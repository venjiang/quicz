//! Pure-Zig TLS 1.3 QUIC client for local process interoperability.
//!
//! Usage: quicz-tls13-process-echo-client <server_host> <server_port> [connection_tag]

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const EndpointConnectionLifecycle = quicz.EndpointConnectionLifecycle;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const endpoint = quicz.endpoint;
const protection = quicz.protection;

const original_dcid_base = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const client_scid_base = [_]u8{ 0x21, 0x22, 0x23, 0x24 };

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
    const connection_tag = if (args.next()) |raw_tag|
        try std.fmt.parseInt(u8, raw_tag, 10)
    else
        0;
    var original_dcid = original_dcid_base;
    original_dcid[original_dcid.len - 1] = connection_tag;
    var client_scid = client_scid_base;
    client_scid[client_scid.len - 1] = connection_tag;
    const server_address = try std.Io.net.IpAddress.parseIp4(server_host, server_port);
    var local_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var socket = try local_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    const client_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(local_address.ip4.bytes, local_address.ip4.port),
        .remote = endpoint.Udp4Address.init(server_address.ip4.bytes, server_address.ip4.port),
    };
    const client_handle: u64 = 1;
    var lifecycle = EndpointConnectionLifecycle.init(allocator);
    defer lifecycle.deinit();

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
    try lifecycle.registerConnectionId(client_handle, &client_scid, client_path, .{ .active_migration_disabled = true });

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
    const handshake_route = try lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        client_handle,
        &connection,
        client_path,
        3,
        received_handshake.data,
    );
    try require(handshake_route.connection_id == client_handle);
    const handshake_progress = try lifecycle.driveCryptoBackendInSpaceAndArmConnection(
        client_handle,
        &connection,
        .handshake,
        backend.cryptoBackend(),
        &scratch,
    );
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
    const stream_packet = (try lifecycle.pollProtectedShortDatagramWithInstalledKeys(client_handle, &connection, 5, server_scid)) orelse return error.UnexpectedState;
    defer allocator.free(stream_packet);
    try socket.send(io, &server_address, stream_packet);

    var stream_buffer: [128]u8 = undefined;
    var got_echo = false;
    var received_packets: usize = 0;
    while (received_packets < 4) : (received_packets += 1) {
        const received = socket.receiveTimeout(io, &receive_buffer, recvTimeout()) catch break;
        const stream_route = try lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
            client_handle,
            &connection,
            client_path,
            6 + @as(i64, @intCast(received_packets)),
            received.data,
        );
        try require(stream_route.connection_id == client_handle);
        if (try connection.recvOnStream(stream_id, &stream_buffer)) |echoed_len| {
            try require(std.mem.eql(u8, stream_buffer[0..echoed_len], "hello"));
            got_echo = true;
            break;
        }
    }
    try require(got_echo);

    try connection.closeConnection(0, 0, "process echo complete");
    const close_packet = (try lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        client_handle,
        &connection,
        10,
        server_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(close_packet);
    try socket.send(io, &server_address, close_packet);
    const client_close_deadline = connection.closeDeadlineMillis() orelse return error.UnexpectedState;
    const client_retired = (try lifecycle.checkCloseTimeoutsAndRetireConnection(
        client_handle,
        &connection,
        client_close_deadline,
    )) orelse return error.UnexpectedState;
    try require(client_retired.routes_retired > 0);
    try require(connection.connectionState() == .closed);
    try require(lifecycle.routeCount() == 0);

    std.debug.print("zig_process_client: tag={d} handshake_done=true echo_bytes=5 close_cleanup=true\n", .{connection_tag});
}
