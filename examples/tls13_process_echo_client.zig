//! Pure-Zig TLS 1.3 QUIC client for local process interoperability.
//!
//! Usage: quicz-tls13-process-echo-client <server_host> <server_port>

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;

const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };

fn recvTimeout() std.Io.Timeout {
    return .{ .duration = .{
        .clock = .awake,
        .raw = std.Io.Duration.fromMilliseconds(2000),
    } };
}

fn require(condition: bool) !void {
    if (!condition) return error.UnexpectedState;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    const server_host = args.next() orelse return error.MissingArgs;
    const server_port = try std.fmt.parseInt(u16, args.next() orelse return error.MissingArgs, 10);
    const server_address = try std.Io.net.IpAddress.parseIp4(server_host, server_port);
    var local_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var socket = try local_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);

    const alpn = [_][]const u8{"hq-interop"};
    const initial_secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);
    var connection = try Connection.init(allocator, .client, .{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
        .max_datagram_size = 8192,
    });
    defer connection.deinit();
    try connection.setLocalInitialSourceConnectionId(&client_scid);

    var backend = Tls13Backend.initClient(.{
        .alpn = &alpn,
        .server_name = "localhost",
        .skip_cert_verify = true,
    });
    var scratch: [8192]u8 = undefined;
    var receive_buffer: [2048]u8 = undefined;

    _ = try connection.driveCryptoBackendInSpace(.initial, backend.cryptoBackend(), &scratch);
    const client_initial = (try connection.pollProtectedLongCryptoDatagramInSpace(
        .initial,
        1,
        &original_dcid,
        &client_scid,
        &[_]u8{},
        initial_secrets.client,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_initial);
    try socket.send(io, &server_address, client_initial);

    const received_initial = try socket.receiveTimeout(io, &receive_buffer, recvTimeout());
    try connection.processProtectedLongDatagramInSpace(.initial, 2, initial_secrets.server, received_initial.data);
    _ = try connection.driveCryptoBackendInSpace(.initial, backend.cryptoBackend(), &scratch);
    const server_scid = connection.peerInitialSourceConnectionId() orelse return error.MissingPeerConnectionId;

    const received_handshake = try socket.receiveTimeout(io, &receive_buffer, recvTimeout());
    try connection.processProtectedHandshakeDatagramWithInstalledKeys(3, received_handshake.data);
    const handshake_progress = try connection.driveCryptoBackendInSpace(.handshake, backend.cryptoBackend(), &scratch);
    try require(handshake_progress.outbound_bytes > 0);
    try require(handshake_progress.handshake_confirmed);
    const client_finished = (try connection.pollProtectedHandshakeDatagramWithInstalledKeys(
        4,
        server_scid,
        &client_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_finished);
    try socket.send(io, &server_address, client_finished);

    const stream_id = try connection.openStream();
    try connection.sendOnStream(stream_id, "hello", false);
    const stream_packet = (try connection.pollProtectedShortDatagramWithInstalledKeys(5, server_scid)) orelse return error.UnexpectedState;
    defer allocator.free(stream_packet);
    try socket.send(io, &server_address, stream_packet);

    var stream_buffer: [128]u8 = undefined;
    var got_echo = false;
    var received_packets: usize = 0;
    while (received_packets < 4) : (received_packets += 1) {
        const received = socket.receiveTimeout(io, &receive_buffer, recvTimeout()) catch break;
        try connection.processProtectedShortDatagramWithInstalledKeys(
            6 + @as(i64, @intCast(received_packets)),
            client_scid.len,
            received.data,
        );
        if (try connection.recvOnStream(stream_id, &stream_buffer)) |echoed_len| {
            try require(std.mem.eql(u8, stream_buffer[0..echoed_len], "hello"));
            got_echo = true;
            break;
        }
    }
    try require(got_echo);
    std.debug.print("zig_process_client: handshake_done=true echo_bytes=5\n", .{});
}
