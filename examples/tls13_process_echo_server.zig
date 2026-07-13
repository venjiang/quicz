//! One-shot pure-Zig TLS 1.3 QUIC echo server for local process interoperability.
//!
//! Usage: quicz-tls13-process-echo-server <bind_host> <bind_port>
//! The server accepts one loopback test connection, echoes stream 0, then exits.

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };

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
    const bind_host = args.next() orelse return error.MissingArgs;
    const bind_port = try std.fmt.parseInt(u16, args.next() orelse return error.MissingArgs, 10);
    const bind_address = try std.Io.net.IpAddress.parseIp4(bind_host, bind_port);
    var socket = try bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    std.debug.print("zig_process_server: listening={s}:{d}\n", .{ bind_host, bind_port });

    const seed = [_]u8{0x55} ** 32;
    const server_key_pair = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const server_private_key = server_key_pair.secret_key.bytes;
    const certificate_der = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xde, 0xad, 0xbe, 0xef };
    const alpn = [_][]const u8{"hq-interop"};
    var connection = try Connection.init(allocator, .server, .{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
        .max_datagram_size = 8192,
    });
    defer connection.deinit();
    try connection.validatePeerAddress();
    try connection.setLocalInitialSourceConnectionId(&server_scid);

    var backend = Tls13Backend.initServer(.{
        .alpn = &alpn,
        .cert_chain_der = &.{&certificate_der},
        .private_key_bytes = &server_private_key,
        .private_key_algorithm = .ecdsa_p256_sha256,
    });
    var scratch: [8192]u8 = undefined;
    var receive_buffer: [2048]u8 = undefined;

    const received_initial = try socket.receiveTimeout(io, &receive_buffer, recvTimeout());
    const initial_info = try protection.peekProtectedLongPacketInfo(received_initial.data);
    if (initial_info.packet_type != .initial) return error.InvalidPacket;
    const initial_secrets = try protection.deriveInitialSecrets(initial_info.version, initial_info.dcid);
    try connection.processProtectedLongDatagramInSpace(.initial, 1, initial_secrets.client, received_initial.data);
    const client_scid = connection.peerInitialSourceConnectionId() orelse return error.MissingPeerConnectionId;

    const initial_progress = try connection.driveCryptoBackendInSpace(.initial, backend.cryptoBackend(), &scratch);
    try require(initial_progress.handshake_keys_installed);
    const server_initial = (try connection.pollProtectedLongCryptoDatagramInSpace(
        .initial,
        2,
        client_scid,
        &server_scid,
        &[_]u8{},
        initial_secrets.server,
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_initial);
    try socket.send(io, &received_initial.from, server_initial);

    _ = try connection.driveCryptoBackendInSpace(.handshake, backend.cryptoBackend(), &scratch);
    const server_handshake = (try connection.pollProtectedHandshakeDatagramWithInstalledKeys(
        3,
        client_scid,
        &server_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_handshake);
    try socket.send(io, &received_initial.from, server_handshake);

    const received_finished = try socket.receiveTimeout(io, &receive_buffer, recvTimeout());
    try connection.processProtectedHandshakeDatagramWithInstalledKeys(4, received_finished.data);
    const handshake_progress = try connection.driveCryptoBackendInSpace(.handshake, backend.cryptoBackend(), &scratch);
    try require(handshake_progress.handshake_confirmed);
    try require(connection.handshakeConfirmed());

    const received_stream = try socket.receiveTimeout(io, &receive_buffer, recvTimeout());
    try connection.processProtectedShortDatagramWithInstalledKeys(5, server_scid.len, received_stream.data);
    var stream_buffer: [128]u8 = undefined;
    const echoed_len = (try connection.recvOnStream(0, &stream_buffer)) orelse return error.MissingStreamData;
    try require(std.mem.eql(u8, stream_buffer[0..echoed_len], "hello"));
    try connection.sendOnStream(0, stream_buffer[0..echoed_len], false);

    var sent_packets: usize = 0;
    while (sent_packets < 4) : (sent_packets += 1) {
        const packet = (try connection.pollProtectedShortDatagramWithInstalledKeys(
            6 + @as(i64, @intCast(sent_packets)),
            client_scid,
        )) orelse break;
        defer allocator.free(packet);
        try socket.send(io, &received_initial.from, packet);
    }
    try require(sent_packets > 0);

    std.debug.print("zig_process_server: handshake_done=true echo_bytes={d}\n", .{echoed_len});
}
