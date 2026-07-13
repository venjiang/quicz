//! One-shot pure-Zig TLS 1.3 QUIC echo server for local process interoperability.
//!
//! Usage: quicz-tls13-process-echo-server <bind_host> <bind_port>
//! The server accepts one loopback test connection, echoes stream 0, then exits.

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const EndpointConnectionLifecycle = quicz.EndpointConnectionLifecycle;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const endpoint = quicz.endpoint;
const quic_packet = quicz.packet;
const protection = quicz.protection;

const server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
const max_initial_datagrams: usize = 4;
// Local test-only P-256 certificate for localhost and 127.0.0.1. Its PEM
// trust anchor is in examples/interop/testdata/quicz-echo-ca.pem so the Go
// and Rust client examples can exercise ordinary certificate validation.
const server_private_key = [_]u8{
    0x5b, 0xbf, 0x4f, 0x5a, 0x48, 0x42, 0x9f, 0x00,
    0x5a, 0x57, 0x09, 0xc3, 0xb4, 0xc1, 0x3a, 0x64,
    0x2e, 0xb1, 0x61, 0xf5, 0x0b, 0xde, 0x64, 0x4b,
    0x3a, 0x38, 0xa6, 0x8f, 0xfa, 0x48, 0xda, 0x51,
};
const certificate_der = [_]u8{
    0x30, 0x82, 0x01, 0xbd, 0x30, 0x82, 0x01, 0x63, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x5d,
    0xd9, 0x11, 0xfc, 0x63, 0x82, 0x9c, 0xf9, 0x73, 0xb0, 0xce, 0xfd, 0x3f, 0xd8, 0xc8, 0xf3, 0x5e,
    0x29, 0x48, 0xd2, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61,
    0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x37, 0x31, 0x33, 0x31,
    0x31, 0x32, 0x34, 0x30, 0x31, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x37, 0x31, 0x30, 0x31, 0x31,
    0x32, 0x34, 0x30, 0x31, 0x5a, 0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06,
    0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
    0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xa8, 0xdc, 0x77, 0x02, 0xf7, 0x11, 0xf5, 0x48, 0xee, 0xe8,
    0x0a, 0x2d, 0x1f, 0x49, 0x60, 0xc9, 0x3f, 0xb3, 0x65, 0x30, 0x40, 0x05, 0x08, 0x6d, 0x89, 0xd9,
    0x04, 0x6c, 0x7b, 0x0c, 0x2d, 0x08, 0xd8, 0xfc, 0x89, 0xc6, 0x3b, 0x44, 0x8c, 0xf2, 0xaa, 0x72,
    0x52, 0x5e, 0x59, 0x27, 0x53, 0x8a, 0xb2, 0x7e, 0x4b, 0x91, 0x1f, 0xc0, 0xa4, 0x55, 0x4a, 0x8d,
    0xb6, 0x05, 0x88, 0xda, 0xd7, 0xe7, 0xa3, 0x81, 0x92, 0x30, 0x81, 0x8f, 0x30, 0x1d, 0x06, 0x03,
    0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xb5, 0xbd, 0x3e, 0xc4, 0x64, 0xc0, 0xcc, 0xd7, 0x01,
    0xfc, 0x3e, 0x48, 0x08, 0x97, 0x11, 0xb0, 0x3c, 0xf1, 0x7b, 0x14, 0x30, 0x1f, 0x06, 0x03, 0x55,
    0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xb5, 0xbd, 0x3e, 0xc4, 0x64, 0xc0, 0xcc, 0xd7,
    0x01, 0xfc, 0x3e, 0x48, 0x08, 0x97, 0x11, 0xb0, 0x3c, 0xf1, 0x7b, 0x14, 0x30, 0x0c, 0x06, 0x03,
    0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d,
    0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d,
    0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x30,
    0x1a, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x13, 0x30, 0x11, 0x82, 0x09, 0x6c, 0x6f, 0x63, 0x61,
    0x6c, 0x68, 0x6f, 0x73, 0x74, 0x87, 0x04, 0x7f, 0x00, 0x00, 0x01, 0x30, 0x0a, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x52, 0x63,
    0xbc, 0xa2, 0x3a, 0x04, 0xa0, 0x48, 0x1a, 0xf2, 0xbe, 0xe5, 0x41, 0xb1, 0x68, 0xe3, 0x08, 0x47,
    0x7c, 0xfd, 0xbf, 0x44, 0x32, 0xa1, 0x14, 0xea, 0x6f, 0x45, 0xe0, 0xf8, 0x6c, 0x85, 0x02, 0x21,
    0x00, 0xc7, 0x26, 0x69, 0xc2, 0xf7, 0x99, 0xad, 0x3b, 0x0f, 0xbe, 0x6f, 0xb0, 0x17, 0x7d, 0xd8,
    0x55, 0xf5, 0x4e, 0xae, 0x60, 0xff, 0x21, 0x4c, 0x9c, 0xac, 0xac, 0xf3, 0x98, 0x2b, 0x4e, 0x1c,
    0x0a,
};

fn recvTimeout() std.Io.Timeout {
    return .{ .duration = .{
        .clock = .awake,
        .raw = std.Io.Duration.fromSeconds(10),
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

    // The endpoint owns acceptance and route registration. Connection and TLS
    // storage remain local to this one-shot process server.
    const server_handle: u64 = 1;
    var lifecycle = EndpointConnectionLifecycle.init(allocator);
    defer lifecycle.deinit();

    const received_initial = try socket.receiveTimeout(io, &receive_buffer, recvTimeout());
    const server_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(bind_address.ip4.bytes, bind_address.ip4.port),
        .remote = endpoint.Udp4Address.init(received_initial.from.ip4.bytes, received_initial.from.ip4.port),
    };
    var endpoint_output: [128]u8 = undefined;
    const initial_accept = switch (try lifecycle.feedDatagram(
        &endpoint_output,
        server_path,
        received_initial.data,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
    )) {
        .accept_initial => |value| value,
        else => return error.InvalidPacket,
    };
    const initial_info = try protection.peekProtectedLongPacketInfo(received_initial.data);
    var original_dcid: [20]u8 = undefined;
    @memcpy(original_dcid[0..initial_info.dcid.len], initial_info.dcid);
    const initial_secrets = try protection.deriveInitialSecrets(initial_info.version, initial_info.dcid);
    const accepted_initial = try lifecycle.processAcceptedProtectedInitialWithCryptoBackendAndPollDatagram(
        server_handle,
        &connection,
        1,
        initial_accept,
        &server_scid,
        received_initial.data,
        .{ .active_migration_disabled = true },
        backend.cryptoBackend(),
        &scratch,
    );
    // The accept metadata borrows the UDP receive buffer, which subsequent
    // receives reuse. Keep the peer CID from Connection-owned state for the
    // later 1-RTT echo destination.
    const client_scid = connection.peerInitialSourceConnectionId() orelse return error.MissingPeerConnectionId;

    // A client may split its ClientHello across Initial packets or retransmit
    // an Initial before the server can emit a response. Keep using Connection's
    // authenticated CRYPTO reassembly until TLS derives Handshake keys, while
    // accepting only the original client's Initial DCID.
    var initial_progress = accepted_initial.backend;
    var initial_datagrams: usize = 1;
    while (!initial_progress.handshake_keys_installed and initial_datagrams < max_initial_datagrams) : (initial_datagrams += 1) {
        const next_initial = try socket.receiveTimeout(io, &receive_buffer, recvTimeout());
        const next_info = try protection.peekProtectedLongPacketInfo(next_initial.data);
        if (next_info.packet_type != .initial) return error.InvalidPacket;
        if (next_info.version != initial_info.version or !std.mem.eql(u8, next_info.dcid, original_dcid[0..initial_info.dcid.len])) {
            return error.InvalidPacket;
        }
        try connection.processProtectedLongDatagramInSpace(.initial, 1, initial_secrets.client, next_initial.data);
        initial_progress = try connection.driveCryptoBackendInSpace(.initial, backend.cryptoBackend(), &scratch);
    }
    try require(initial_progress.handshake_keys_installed);
    const server_initial = accepted_initial.response_datagram orelse return error.UnexpectedState;
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

    // Clients may ACK the server Initial before sending Client Finished. Keep
    // consuming a bounded number of coalesced long-header datagrams until the
    // TLS backend reports completion instead of assuming the next packet is
    // necessarily a Handshake CRYPTO packet.
    var handshake_confirmed = false;
    var handshake_datagrams: usize = 0;
    while (!handshake_confirmed and handshake_datagrams < max_initial_datagrams) : (handshake_datagrams += 1) {
        const received = try socket.receiveTimeout(io, &receive_buffer, recvTimeout());
        const client_route = try lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
            server_handle,
            &connection,
            server_path,
            4 + @as(i64, @intCast(handshake_datagrams)),
            received.data,
        );
        try require(client_route.connection_id == server_handle);
        const handshake_progress = try lifecycle.driveCryptoBackendInSpaceAndArmConnection(
            server_handle,
            &connection,
            .handshake,
            backend.cryptoBackend(),
            &scratch,
        );
        handshake_confirmed = handshake_progress.handshake_confirmed;
    }
    try require(handshake_confirmed);
    try require(connection.handshakeConfirmed());

    var stream_buffer: [128]u8 = undefined;
    var echoed_len: ?usize = null;
    var application_datagrams: usize = 0;
    while (echoed_len == null and application_datagrams < max_initial_datagrams) : (application_datagrams += 1) {
        const received = try socket.receiveTimeout(io, &receive_buffer, recvTimeout());
        const stream_route = try lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
            server_handle,
            &connection,
            server_path,
            5 + @as(i64, @intCast(application_datagrams)),
            received.data,
        );
        try require(stream_route.connection_id == server_handle);
        echoed_len = try connection.recvOnStream(0, &stream_buffer);
    }
    const echo_len = echoed_len orelse return error.MissingStreamData;
    try require(std.mem.eql(u8, stream_buffer[0..echo_len], "hello"));
    try connection.sendOnStream(0, stream_buffer[0..echo_len], false);

    var sent_packets: usize = 0;
    while (sent_packets < 4) : (sent_packets += 1) {
        const packet = (try lifecycle.pollProtectedShortDatagramWithInstalledKeys(
            server_handle,
            &connection,
            6 + @as(i64, @intCast(sent_packets)),
            client_scid,
        )) orelse break;
        defer allocator.free(packet);
        try socket.send(io, &received_initial.from, packet);
    }
    try require(sent_packets > 0);

    const received_close = try socket.receiveTimeout(io, &receive_buffer, recvTimeout());
    const close_route = try lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        server_handle,
        &connection,
        server_path,
        10,
        received_close.data,
    );
    try require(close_route.connection_id == server_handle);
    try require(connection.connectionState() == .draining);
    const server_drain_deadline = connection.closeDeadlineMillis() orelse return error.UnexpectedState;
    const server_retired = (try lifecycle.checkCloseTimeoutsAndRetireConnection(
        server_handle,
        &connection,
        server_drain_deadline,
    )) orelse return error.UnexpectedState;
    try require(server_retired.routes_retired > 0);
    try require(connection.connectionState() == .closed);
    try require(lifecycle.routeCount() == 0);

    std.debug.print("zig_process_server: handshake_done=true echo_bytes={d} close_cleanup=true\n", .{echo_len});
}
