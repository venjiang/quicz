const std = @import("std");
const c = @import("c");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

const ReceivedDatagram = struct {
    path: quicz.endpoint.Udp4Tuple,
    data: []const u8,
};

const FixedWriter = struct {
    buffer: []u8,
    pos: usize = 0,

    pub fn writer(self: *FixedWriter) *FixedWriter {
        return self;
    }

    pub fn writeByte(self: *FixedWriter, byte: u8) !void {
        if (self.pos >= self.buffer.len) return error.NoSpaceLeft;
        self.buffer[self.pos] = byte;
        self.pos += 1;
    }

    pub fn writeAll(self: *FixedWriter, bytes: []const u8) !void {
        if (self.buffer.len - self.pos < bytes.len) return error.NoSpaceLeft;
        @memcpy(self.buffer[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    pub fn getWritten(self: FixedWriter) []const u8 {
        return self.buffer[0..self.pos];
    }
};

const AdapterInitialSocketDelivery = struct {
    crypto_bytes: usize,
    datagram_bytes: usize,
    ack_bytes: usize,
};

const AdapterHandshakeSocketDelivery = struct {
    crypto_bytes: usize,
    datagram_bytes: usize,
    ack_bytes: usize,
};

const AdapterApplicationSocketEcho = struct {
    request_bytes: usize,
    request_datagram_bytes: usize,
    client_pto_deadline_millis: i64,
    client_pto_datagram_bytes: usize,
    client_pto_route: u64,
    server_pto_ack_largest: u64,
    echo_bytes: usize,
    echo_datagram_bytes: usize,
    final_ack_bytes: usize,
    close_datagram_bytes: usize,
    client_inflight_after_echo: usize,
    server_inflight_after_final_ack: usize,
    server_close_error_code: u64,
    client_handshake_confirmed: bool,
    server_handshake_confirmed: bool,
    client_handshake_space_discarded: bool,
    server_handshake_space_discarded: bool,
    client_handshake_keys_present: bool,
    server_handshake_keys_present: bool,
    client_routes_registered: usize,
    server_routes_registered: usize,
    client_routes_after_close_timeout: usize,
    server_routes_after_drain_timeout: usize,
};

const adapter_client_handle: u64 = 501;
const adapter_server_handle: u64 = 511;
const adapter_original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const adapter_client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
const adapter_server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
const adapter_handshake_client_dcid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
const adapter_handshake_client_scid = [_]u8{ 0x91, 0x92, 0x93, 0x94 };
const adapter_handshake_server_dcid = [_]u8{ 0xa5, 0xa6, 0xa7, 0xa8 };
const adapter_handshake_server_scid = [_]u8{ 0xb5, 0xb6, 0xb7, 0xb8 };
const adapter_application_client_dcid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
const adapter_application_server_dcid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };

const AdapterEndpointSocketLoop = struct {
    allocator: std.mem.Allocator,
    threaded: std.Io.Threaded,
    client_socket: std.Io.net.Socket,
    server_socket: std.Io.net.Socket,
    client_lifecycle: quicz.EndpointConnectionLifecycle,
    server_lifecycle: quicz.EndpointConnectionLifecycle,
    client_routes_registered: usize,
    server_routes_registered: usize,

    fn init(allocator: std.mem.Allocator) !AdapterEndpointSocketLoop {
        var threaded = std.Io.Threaded.init(allocator, .{});
        errdefer threaded.deinit();
        const io = threaded.io();

        var client_socket = try bindLoopbackUdp(io);
        errdefer client_socket.close(io);
        var server_socket = try bindLoopbackUdp(io);
        errdefer server_socket.close(io);

        const client_address = try udp4Address(client_socket.address);
        const server_address = try udp4Address(server_socket.address);
        try require(client_address.port != 0);
        try require(server_address.port != 0);
        try require(client_address.port != server_address.port);

        var client_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
        errdefer client_lifecycle.deinit();
        var server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
        errdefer server_lifecycle.deinit();

        const client_path = try udp4Tuple(client_socket.address, server_socket.address);
        const server_path = try udp4Tuple(server_socket.address, client_socket.address);
        try client_lifecycle.registerConnectionId(adapter_client_handle, &adapter_client_scid, client_path, .{
            .active_migration_disabled = true,
        });
        try client_lifecycle.registerConnectionId(adapter_client_handle, &adapter_handshake_client_dcid, client_path, .{
            .active_migration_disabled = true,
        });
        try client_lifecycle.registerConnectionId(adapter_client_handle, &adapter_application_client_dcid, client_path, .{
            .active_migration_disabled = true,
        });
        try server_lifecycle.registerConnectionId(adapter_server_handle, &adapter_original_dcid, server_path, .{
            .active_migration_disabled = true,
        });
        try server_lifecycle.registerConnectionId(adapter_server_handle, &adapter_server_scid, server_path, .{
            .active_migration_disabled = true,
        });
        try server_lifecycle.registerConnectionId(adapter_server_handle, &adapter_handshake_server_dcid, server_path, .{
            .active_migration_disabled = true,
        });
        try server_lifecycle.registerConnectionId(adapter_server_handle, &adapter_application_server_dcid, server_path, .{
            .active_migration_disabled = true,
        });

        return .{
            .allocator = allocator,
            .threaded = threaded,
            .client_socket = client_socket,
            .server_socket = server_socket,
            .client_lifecycle = client_lifecycle,
            .server_lifecycle = server_lifecycle,
            .client_routes_registered = client_lifecycle.routeCount(),
            .server_routes_registered = server_lifecycle.routeCount(),
        };
    }

    fn deinit(self: *AdapterEndpointSocketLoop) void {
        const io = self.threaded.io();
        self.client_lifecycle.deinit();
        self.server_lifecycle.deinit();
        self.client_socket.close(io);
        self.server_socket.close(io);
        self.threaded.deinit();
    }

    fn currentIo(self: *AdapterEndpointSocketLoop) std.Io {
        return self.threaded.io();
    }

    fn receiveAtClient(self: *AdapterEndpointSocketLoop, buf: []u8) !ReceivedDatagram {
        return receiveDatagram(self.currentIo(), &self.client_socket, buf);
    }

    fn receiveAtServer(self: *AdapterEndpointSocketLoop, buf: []u8) !ReceivedDatagram {
        return receiveDatagram(self.currentIo(), &self.server_socket, buf);
    }
};

fn require(condition: bool) ExampleError!void {
    if (!condition) return error.UnexpectedState;
}

fn tlsStatus(status: anytype) quicz.TlsBackendStatus {
    return @enumFromInt(@as(c_int, @intCast(status)));
}

fn cPacketSpace(space: quicz.TlsBackendPacketSpace) c.enum_quicz_tls_backend_packet_space {
    return @intCast(@intFromEnum(space));
}

fn statusIsOk(status: anytype) bool {
    return @as(c_int, @intCast(status)) == c.QUICZ_TLS_BACKEND_OK;
}

fn opensslBackendReceive(
    context: *anyopaque,
    space: quicz.TlsBackendPacketSpace,
    data: [*]const u8,
    data_len: usize,
) callconv(.c) quicz.TlsBackendStatus {
    return tlsStatus(c.quicz_openssl_tls_backend_receive(context, cPacketSpace(space), data, data_len));
}

fn opensslBackendPull(
    context: *anyopaque,
    space: quicz.TlsBackendPacketSpace,
    out: [*]u8,
    out_len: usize,
    written_len: *usize,
) callconv(.c) quicz.TlsBackendStatus {
    return tlsStatus(c.quicz_openssl_tls_backend_pull(context, cPacketSpace(space), out, out_len, written_len));
}

fn opensslBackendSetLocalTransportParameters(
    context: *anyopaque,
    data: [*]const u8,
    data_len: usize,
) callconv(.c) quicz.TlsBackendStatus {
    return tlsStatus(c.quicz_openssl_tls_backend_set_local_transport_parameters(context, data, data_len));
}

fn opensslBackendPullPeerTransportParameters(
    context: *anyopaque,
    out: [*]u8,
    out_len: usize,
    written_len: *usize,
) callconv(.c) quicz.TlsBackendStatus {
    return tlsStatus(c.quicz_openssl_tls_backend_pull_peer_transport_parameters(context, out, out_len, written_len));
}

fn opensslBackendPullHandshakeTrafficSecrets(
    context: *anyopaque,
    out: *quicz.HandshakeTrafficSecrets,
) callconv(.c) quicz.TlsBackendStatus {
    var c_secrets: c.struct_quicz_handshake_traffic_secrets = undefined;
    const status = c.quicz_openssl_tls_backend_pull_handshake_traffic_secrets(context, &c_secrets);
    if (statusIsOk(status)) {
        out.* = .{
            .local = c_secrets.local,
            .peer = c_secrets.peer,
        };
    }
    return tlsStatus(status);
}

fn opensslBackendPullOneRttTrafficSecrets(
    context: *anyopaque,
    out: *quicz.OneRttTrafficSecrets,
) callconv(.c) quicz.TlsBackendStatus {
    var c_secrets: c.struct_quicz_one_rtt_traffic_secrets = undefined;
    const status = c.quicz_openssl_tls_backend_pull_1rtt_traffic_secrets(context, &c_secrets);
    if (statusIsOk(status)) {
        out.* = .{
            .local = c_secrets.local,
            .peer = c_secrets.peer,
        };
    }
    return tlsStatus(status);
}

fn fixedWriter(buffer: []u8) FixedWriter {
    return .{ .buffer = buffer };
}

fn receiveTimeout() std.Io.Timeout {
    return .{
        .duration = .{
            .clock = .awake,
            .raw = std.Io.Duration.fromMilliseconds(500),
        },
    };
}

fn bindLoopbackUdp(io: std.Io) !std.Io.net.Socket {
    var address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    return address.bind(io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
}

fn udp4Address(address: std.Io.net.IpAddress) ExampleError!quicz.endpoint.Udp4Address {
    return switch (address) {
        .ip4 => |ip4| quicz.endpoint.Udp4Address.init(ip4.bytes, ip4.port),
        else => error.UnexpectedState,
    };
}

fn udp4Tuple(local: std.Io.net.IpAddress, remote: std.Io.net.IpAddress) !quicz.endpoint.Udp4Tuple {
    return .{
        .local = try udp4Address(local),
        .remote = try udp4Address(remote),
    };
}

fn receiveDatagram(
    io: std.Io,
    socket: *std.Io.net.Socket,
    buf: []u8,
) !ReceivedDatagram {
    const received = try socket.receiveTimeout(io, buf, receiveTimeout());
    return .{
        .path = try udp4Tuple(socket.address, received.from),
        .data = received.data,
    };
}

fn copyOpenSslServerCrypto(level: usize, out: []u8) ExampleError![]const u8 {
    var written_len: usize = 0;
    const copied = c.quicz_openssl_pair_transcript_copy_server_crypto(
        @intCast(level),
        out.ptr,
        out.len,
        &written_len,
    );
    try require(copied == 1);
    return out[0..written_len];
}

fn copyOpenSslClientPeerTransportParameters(out: []u8) ExampleError![]const u8 {
    var written_len: usize = 0;
    const copied = c.quicz_openssl_pair_transcript_copy_client_peer_transport_parameters(
        out.ptr,
        out.len,
        &written_len,
    );
    try require(copied == 1);
    return out[0..written_len];
}

fn copyOpenSslClientSecret(
    level: usize,
    direction: usize,
) ExampleError![quicz.protection.traffic_secret_len]u8 {
    var secret: [quicz.protection.traffic_secret_len]u8 = undefined;
    var written_len: usize = 0;
    const copied = c.quicz_openssl_pair_transcript_copy_client_secret(
        @intCast(level),
        @intCast(direction),
        &secret,
        secret.len,
        &written_len,
    );
    try require(copied == 1);
    try require(written_len == secret.len);
    return secret;
}

fn copyOpenSslServerSecret(
    level: usize,
    direction: usize,
) ExampleError![quicz.protection.traffic_secret_len]u8 {
    var secret: [quicz.protection.traffic_secret_len]u8 = undefined;
    var written_len: usize = 0;
    const copied = c.quicz_openssl_pair_transcript_copy_server_secret(
        @intCast(level),
        @intCast(direction),
        &secret,
        secret.len,
        &written_len,
    );
    try require(copied == 1);
    try require(written_len == secret.len);
    return secret;
}

const EncodedTranscriptTransportParameters = struct {
    client: []const u8,
    server: []const u8,
};

fn encodeTranscriptTransportParameters(
    allocator: std.mem.Allocator,
    client_out: []u8,
    server_out: []u8,
) !EncodedTranscriptTransportParameters {
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &adapter_original_dcid);

    var client = try quicz.Connection.init(allocator, .client, .{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
        .max_datagram_size = 8192,
    });
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
        .max_datagram_size = 8192,
    });
    defer server.deinit();

    try client.sendCryptoInSpace(.initial, "quicz adapter transcript client tp seed");
    const client_initial = (try client.pollProtectedLongCryptoDatagramInSpace(
        .initial,
        1,
        &adapter_original_dcid,
        &adapter_client_scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_initial);
    try server.recordPeerAddressBytesReceived(client_initial.len);
    try server.processProtectedLongDatagramInSpace(.initial, 2, secrets.client, client_initial);

    try server.sendPingInSpace(.initial);
    const server_initial = (try server.pollProtectedLongDatagram(
        3,
        &adapter_client_scid,
        &adapter_server_scid,
        &[_]u8{},
        .{ .initial = secrets.server },
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_initial);

    const client_local_scid = client.localInitialSourceConnectionId() orelse return error.UnexpectedState;
    const server_original_dcid = server.originalDestinationConnectionId() orelse return error.UnexpectedState;
    const server_local_scid = server.localInitialSourceConnectionId() orelse return error.UnexpectedState;
    try require(std.mem.eql(u8, client_local_scid, &adapter_client_scid));
    try require(std.mem.eql(u8, server_original_dcid, &adapter_original_dcid));
    try require(std.mem.eql(u8, server_local_scid, &adapter_server_scid));

    return .{
        .client = try client.encodeLocalTransportParameters(client_out),
        .server = try server.encodeLocalTransportParameters(server_out),
    };
}

fn verifyAdapterInitialSocketDelivery(
    loop: *AdapterEndpointSocketLoop,
    client: *quicz.Connection,
    server: *quicz.Connection,
    expected_crypto_len: usize,
) !AdapterInitialSocketDelivery {
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &adapter_original_dcid);

    const client_datagram = (try loop.client_lifecycle.pollProtectedLongDatagram(
        adapter_client_handle,
        client,
        10,
        &adapter_original_dcid,
        &adapter_client_scid,
        &[_]u8{},
        .{ .initial = secrets.client },
    )) orelse return error.UnexpectedState;
    defer loop.allocator.free(client_datagram);
    try require(client_datagram.len >= 1200);
    try loop.client_socket.send(loop.currentIo(), &loop.server_socket.address, client_datagram);

    var server_receive_buf: [9000]u8 = undefined;
    var client_receive_buf: [9000]u8 = undefined;
    const client_received = try loop.receiveAtServer(&server_receive_buf);
    const client_route = try loop.server_lifecycle.processRoutedProtectedInitialDatagram(
        adapter_server_handle,
        server,
        client_received.path,
        11,
        &adapter_original_dcid,
        client_received.data,
    );
    try require(client_route.connection_id == adapter_server_handle);
    try require(std.mem.eql(u8, client_route.destination_connection_id.asSlice(), &adapter_original_dcid));
    try require(server.pendingAckLargest(.initial) == 0);

    var crypto_buf: [8192]u8 = undefined;
    const crypto_len = (try server.recvCryptoInSpace(.initial, &crypto_buf)) orelse return error.UnexpectedState;
    try require(crypto_len == expected_crypto_len);
    try require((try server.recvCryptoInSpace(.initial, &crypto_buf)) == null);

    const server_ack = (try loop.server_lifecycle.pollProtectedLongDatagram(
        adapter_server_handle,
        server,
        12,
        &adapter_client_scid,
        &adapter_server_scid,
        &[_]u8{},
        .{ .initial = secrets.server },
    )) orelse return error.UnexpectedState;
    defer loop.allocator.free(server_ack);
    try require(server_ack.len > 0);
    try loop.server_socket.send(loop.currentIo(), &loop.client_socket.address, server_ack);

    const ack_received = try loop.receiveAtClient(&client_receive_buf);
    const ack_route = try loop.client_lifecycle.processRoutedProtectedInitialDatagram(
        adapter_client_handle,
        client,
        ack_received.path,
        13,
        &adapter_original_dcid,
        ack_received.data,
    );
    try require(ack_route.connection_id == adapter_client_handle);
    try require(std.mem.eql(u8, ack_route.destination_connection_id.asSlice(), &adapter_client_scid));
    try require(client.bytesInFlight(.initial) == 0);

    return .{
        .crypto_bytes = crypto_len,
        .datagram_bytes = client_datagram.len,
        .ack_bytes = server_ack.len,
    };
}

fn verifyAdapterHandshakeSocketDelivery(
    loop: *AdapterEndpointSocketLoop,
    client: *quicz.Connection,
    server: *quicz.Connection,
    server_local_secret: [quicz.protection.traffic_secret_len]u8,
    server_peer_secret: [quicz.protection.traffic_secret_len]u8,
    inbound_crypto: []const u8,
) !AdapterHandshakeSocketDelivery {
    try server.installHandshakeTrafficSecrets(.{
        .local = server_local_secret,
        .peer = server_peer_secret,
    });
    try require(server.hasHandshakeProtectionKeys());

    try server.sendCryptoInSpace(.handshake, inbound_crypto);
    const server_datagram = (try loop.server_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        adapter_server_handle,
        server,
        20,
        &adapter_handshake_client_dcid,
        &adapter_handshake_server_scid,
    )) orelse return error.UnexpectedState;
    defer loop.allocator.free(server_datagram);
    try require(server_datagram.len > 0);
    try loop.server_socket.send(loop.currentIo(), &loop.client_socket.address, server_datagram);

    var client_receive_buf: [1500]u8 = undefined;
    var server_receive_buf: [1500]u8 = undefined;
    const server_received = try loop.receiveAtClient(&client_receive_buf);
    const server_route = try loop.client_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        adapter_client_handle,
        client,
        server_received.path,
        21,
        server_received.data,
    );
    try require(server_route.connection_id == adapter_client_handle);
    try require(std.mem.eql(u8, server_route.destination_connection_id.asSlice(), &adapter_handshake_client_dcid));
    try require(client.pendingAckLargest(.handshake) == 0);

    const client_ack = (try loop.client_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        adapter_client_handle,
        client,
        22,
        &adapter_handshake_server_dcid,
        &adapter_handshake_client_scid,
    )) orelse return error.UnexpectedState;
    defer loop.allocator.free(client_ack);
    try require(client_ack.len > 0);
    try loop.client_socket.send(loop.currentIo(), &loop.server_socket.address, client_ack);

    const ack_received = try loop.receiveAtServer(&server_receive_buf);
    const ack_route = try loop.server_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        adapter_server_handle,
        server,
        ack_received.path,
        23,
        ack_received.data,
    );
    try require(ack_route.connection_id == adapter_server_handle);
    try require(std.mem.eql(u8, ack_route.destination_connection_id.asSlice(), &adapter_handshake_server_dcid));
    try require(server.bytesInFlight(.handshake) == 0);

    return .{
        .crypto_bytes = inbound_crypto.len,
        .datagram_bytes = server_datagram.len,
        .ack_bytes = client_ack.len,
    };
}

fn verifyAdapterApplicationSocketEcho(
    loop: *AdapterEndpointSocketLoop,
    client: *quicz.Connection,
    server: *quicz.Connection,
) !AdapterApplicationSocketEcho {
    const request = "adapter openssl one-rtt echo";
    try require(client.handshakeConfirmed());
    try require(server.handshakeConfirmed());
    try require(client.packetNumberSpaceDiscarded(.handshake));
    try require(server.packetNumberSpaceDiscarded(.handshake));
    try require(!client.hasHandshakeProtectionKeys());
    try require(!server.hasHandshakeProtectionKeys());

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, request, true);
    const request_datagram = (try loop.client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        adapter_client_handle,
        client,
        30,
        &adapter_application_server_dcid,
    )) orelse return error.UnexpectedState;
    defer loop.allocator.free(request_datagram);
    try require(request_datagram.len > 0);
    try require(loop.client_lifecycle.recoveryTimerCount() == 1);
    const client_stream_timer = loop.client_lifecycle.earliestRecoveryDeadline() orelse return error.UnexpectedState;
    try require(client_stream_timer.connection_id == adapter_client_handle);
    try require(client_stream_timer.timer.space == .application);
    try require(client_stream_timer.timer.kind == .pto);
    try loop.client_socket.send(loop.currentIo(), &loop.server_socket.address, request_datagram);

    var server_receive_buf: [1500]u8 = undefined;
    var client_receive_buf: [1500]u8 = undefined;
    const request_received = try loop.receiveAtServer(&server_receive_buf);
    const request_route = try loop.server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        adapter_server_handle,
        server,
        request_received.path,
        31,
        request_received.data,
    );
    try require(request_route.connection_id == adapter_server_handle);
    try require(std.mem.eql(u8, request_route.destination_connection_id.asSlice(), &adapter_application_server_dcid));
    try require(server.pendingAckLargest(.application) == 0);

    var read_buf: [128]u8 = undefined;
    const request_len = (try server.recvOnStream(stream_id, &read_buf)) orelse return error.UnexpectedState;
    try require(request_len == request.len);
    try require(std.mem.eql(u8, read_buf[0..request_len], request));

    const client_pto_result = try loop.client_lifecycle.serviceRecoveryTimerAndPollProtectedShortDatagramWithInstalledKeys(
        adapter_client_handle,
        client,
        client_stream_timer.timer.deadline_millis,
        &adapter_application_server_dcid,
    );
    const client_pto_serviced = client_pto_result.serviced orelse return error.UnexpectedState;
    try require(client_pto_serviced.connection_id == adapter_client_handle);
    try require(client_pto_serviced.timer.space == .application);
    try require(client_pto_serviced.timer.kind == .pto);
    const client_pto_probe = client_pto_result.datagram orelse return error.UnexpectedState;
    defer loop.allocator.free(client_pto_probe);
    try require(client_pto_probe.len > 0);
    try require(loop.client_lifecycle.recoveryTimerCount() == 1);
    try loop.client_socket.send(loop.currentIo(), &loop.server_socket.address, client_pto_probe);

    const pto_received = try loop.receiveAtServer(&server_receive_buf);
    const pto_route = try loop.server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        adapter_server_handle,
        server,
        pto_received.path,
        client_stream_timer.timer.deadline_millis + 1,
        pto_received.data,
    );
    try require(pto_route.connection_id == adapter_server_handle);
    try require(std.mem.eql(u8, pto_route.destination_connection_id.asSlice(), &adapter_application_server_dcid));
    const server_pto_ack_largest = server.pendingAckLargest(.application) orelse return error.UnexpectedState;
    try require(server_pto_ack_largest > 0);
    try require((try server.recvOnStream(stream_id, &read_buf)) == null);

    try server.sendOnStream(stream_id, read_buf[0..request_len], true);
    var echo_packet_count: usize = 0;
    var echo_datagram_bytes: usize = 0;
    var echo_len_or_null: ?usize = null;
    while (echo_packet_count < 4 and echo_len_or_null == null) : (echo_packet_count += 1) {
        const echo_datagram = (try loop.server_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
            adapter_server_handle,
            server,
            32 + @as(i64, @intCast(echo_packet_count)),
            &adapter_application_client_dcid,
        )) orelse return error.UnexpectedState;
        defer loop.allocator.free(echo_datagram);
        echo_datagram_bytes += echo_datagram.len;
        try loop.server_socket.send(loop.currentIo(), &loop.client_socket.address, echo_datagram);

        const echo_received = try loop.receiveAtClient(&client_receive_buf);
        const echo_route = try loop.client_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
            adapter_client_handle,
            client,
            echo_received.path,
            40 + @as(i64, @intCast(echo_packet_count)),
            echo_received.data,
        );
        try require(echo_route.connection_id == adapter_client_handle);
        try require(std.mem.eql(u8, echo_route.destination_connection_id.asSlice(), &adapter_application_client_dcid));
        echo_len_or_null = try client.recvOnStream(stream_id, &read_buf);
    }

    const echo_len = echo_len_or_null orelse return error.UnexpectedState;
    try require(echo_len == request_len);
    try require(std.mem.eql(u8, read_buf[0..echo_len], request));
    const client_inflight_after_echo = client.bytesInFlight(.application);
    try require(client_inflight_after_echo == 0);
    try require(client.pendingAckLargest(.application) != null);

    const final_ack = (try loop.client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        adapter_client_handle,
        client,
        50,
        &adapter_application_server_dcid,
    )) orelse return error.UnexpectedState;
    defer loop.allocator.free(final_ack);
    try require(final_ack.len > 0);
    try loop.client_socket.send(loop.currentIo(), &loop.server_socket.address, final_ack);

    const ack_received = try loop.receiveAtServer(&server_receive_buf);
    const ack_route = try loop.server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        adapter_server_handle,
        server,
        ack_received.path,
        51,
        ack_received.data,
    );
    try require(ack_route.connection_id == adapter_server_handle);
    try require(std.mem.eql(u8, ack_route.destination_connection_id.asSlice(), &adapter_application_server_dcid));
    const server_inflight_after_final_ack = server.bytesInFlight(.application);
    try require(server_inflight_after_final_ack == 0);

    try client.closeConnection(0, @intFromEnum(quicz.frame.FrameType.stream), "adapter close");
    try require(client.connectionState() == .closing);
    const close_datagram = (try loop.client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        adapter_client_handle,
        client,
        60,
        &adapter_application_server_dcid,
    )) orelse return error.UnexpectedState;
    defer loop.allocator.free(close_datagram);
    const client_close_deadline = client.closeDeadlineMillis() orelse return error.UnexpectedState;
    try require(client_close_deadline > 60);
    try loop.client_socket.send(loop.currentIo(), &loop.server_socket.address, close_datagram);

    const close_received = try loop.receiveAtServer(&server_receive_buf);
    const close_route = try loop.server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        adapter_server_handle,
        server,
        close_received.path,
        61,
        close_received.data,
    );
    try require(close_route.connection_id == adapter_server_handle);
    try require(std.mem.eql(u8, close_route.destination_connection_id.asSlice(), &adapter_application_server_dcid));
    try require(server.connectionState() == .draining);
    const server_drain_deadline = server.closeDeadlineMillis() orelse return error.UnexpectedState;
    try require(server_drain_deadline > 61);
    const server_close_error_code = switch (server.peerClose() orelse return error.UnexpectedState) {
        .connection => |close| blk: {
            try require(close.error_code == 0);
            try require(close.frame_type == @intFromEnum(quicz.frame.FrameType.stream));
            try require(std.mem.eql(u8, close.reason_phrase, "adapter close"));
            break :blk close.error_code;
        },
        else => return error.UnexpectedState,
    };

    const client_retired = (try loop.client_lifecycle.checkCloseTimeoutsAndRetireConnection(
        adapter_client_handle,
        client,
        client_close_deadline,
    )) orelse return error.UnexpectedState;
    try require(client_retired.routes_retired == loop.client_routes_registered);
    try require(client.connectionState() == .closed);
    const client_routes_after_close_timeout = loop.client_lifecycle.routeCount();
    try require(client_routes_after_close_timeout == 0);

    const server_retired = (try loop.server_lifecycle.checkCloseTimeoutsAndRetireConnection(
        adapter_server_handle,
        server,
        server_drain_deadline,
    )) orelse return error.UnexpectedState;
    try require(server_retired.routes_retired == loop.server_routes_registered);
    try require(server.connectionState() == .closed);
    const server_routes_after_drain_timeout = loop.server_lifecycle.routeCount();
    try require(server_routes_after_drain_timeout == 0);

    return .{
        .request_bytes = request_len,
        .request_datagram_bytes = request_datagram.len,
        .client_pto_deadline_millis = client_stream_timer.timer.deadline_millis,
        .client_pto_datagram_bytes = client_pto_probe.len,
        .client_pto_route = pto_route.connection_id,
        .server_pto_ack_largest = server_pto_ack_largest,
        .echo_bytes = echo_len,
        .echo_datagram_bytes = echo_datagram_bytes,
        .final_ack_bytes = final_ack.len,
        .close_datagram_bytes = close_datagram.len,
        .client_inflight_after_echo = client_inflight_after_echo,
        .server_inflight_after_final_ack = server_inflight_after_final_ack,
        .server_close_error_code = server_close_error_code,
        .client_handshake_confirmed = client.handshakeConfirmed(),
        .server_handshake_confirmed = server.handshakeConfirmed(),
        .client_handshake_space_discarded = client.packetNumberSpaceDiscarded(.handshake),
        .server_handshake_space_discarded = server.packetNumberSpaceDiscarded(.handshake),
        .client_handshake_keys_present = client.hasHandshakeProtectionKeys(),
        .server_handshake_keys_present = server.hasHandshakeProtectionKeys(),
        .client_routes_registered = loop.client_routes_registered,
        .server_routes_registered = loop.server_routes_registered,
        .client_routes_after_close_timeout = client_routes_after_close_timeout,
        .server_routes_after_drain_timeout = server_routes_after_drain_timeout,
    };
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var transcript_client_local_transport_parameter_buf: [512]u8 = undefined;
    var transcript_server_local_transport_parameter_buf: [512]u8 = undefined;
    const transcript_local_transport_parameters = try encodeTranscriptTransportParameters(
        allocator,
        &transcript_client_local_transport_parameter_buf,
        &transcript_server_local_transport_parameter_buf,
    );
    try require(c.quicz_openssl_pair_transcript_configure_transport_parameters(
        transcript_local_transport_parameters.client.ptr,
        transcript_local_transport_parameters.client.len,
        transcript_local_transport_parameters.server.ptr,
        transcript_local_transport_parameters.server.len,
    ) == 1);

    const transcript = c.quicz_openssl_pair_transcript_run();
    try require(transcript.initialized == 1);
    try require(transcript.client_done == 1);
    try require(transcript.server_done == 1);
    try require(transcript.client_alert_callbacks == 0);
    try require(transcript.server_alert_callbacks == 0);
    try require(transcript.client_last_ssl_error == 0);
    try require(transcript.server_last_ssl_error == 0);
    try require(transcript.client_yield_secret_callbacks >= 4);
    try require(transcript.server_yield_secret_callbacks >= 4);
    try require(transcript.client_got_transport_params_callbacks == 1);
    try require(transcript.server_got_transport_params_callbacks == 1);
    try require(transcript.client_peer_transport_parameters_len > 0);
    try require(transcript.server_peer_transport_parameters_len > 0);
    try require(transcript.client_peer_transport_parameters_len == transcript_local_transport_parameters.server.len);
    try require(transcript.server_peer_transport_parameters_len == transcript_local_transport_parameters.client.len);
    try require(transcript.client_keylog_callbacks > 0);
    try require(transcript.server_keylog_callbacks > 0);
    try require(transcript.client_keylog_bytes > @as(usize, @intCast(transcript.client_keylog_callbacks)));
    try require(transcript.server_keylog_bytes > @as(usize, @intCast(transcript.server_keylog_callbacks)));
    try require(transcript.server_out_level_bytes[2] > 0);

    const openssl_context = c.quicz_openssl_tls_backend_new() orelse return error.OutOfMemory;
    defer c.quicz_openssl_tls_backend_free(openssl_context);

    var tls_backend = quicz.TlsBackend{
        .context = openssl_context,
        .receive = opensslBackendReceive,
        .pull = opensslBackendPull,
        .set_local_transport_parameters = opensslBackendSetLocalTransportParameters,
        .pull_peer_transport_parameters = opensslBackendPullPeerTransportParameters,
        .pull_handshake_traffic_secrets = opensslBackendPullHandshakeTrafficSecrets,
        .pull_1rtt_traffic_secrets = opensslBackendPullOneRttTrafficSecrets,
    };

    var connection = try quicz.Connection.init(allocator, .client, .{
        .initial_max_data = 4096,
        .initial_max_stream_data = 1024,
        .max_datagram_size = 8192,
    });
    defer connection.deinit();

    var peer = try quicz.Connection.init(allocator, .server, .{
        .initial_max_data = 4096,
        .initial_max_stream_data = 1024,
        .initial_max_streams_bidi = 4,
        .max_datagram_size = 8192,
    });
    defer peer.deinit();
    try peer.validatePeerAddress();

    var endpoint_loop = try AdapterEndpointSocketLoop.init(allocator);
    defer endpoint_loop.deinit();

    var scratch: [4096]u8 = undefined;
    const initial_progress = try connection.driveCryptoBackendInSpace(
        .initial,
        tls_backend.cryptoBackend(),
        &scratch,
    );

    try require(c.quicz_openssl_tls_backend_callbacks_set(openssl_context) == 1);
    try require(c.quicz_openssl_tls_backend_ssl_is_quic_after_callbacks(openssl_context) == 0);
    try require(c.quicz_openssl_tls_backend_local_transport_parameters_set(openssl_context) == 1);
    try require(c.quicz_openssl_tls_backend_local_transport_parameters_len(openssl_context) == initial_progress.local_transport_parameters_bytes);
    try require(c.quicz_openssl_tls_backend_handshake_drive_calls(openssl_context) > 0);
    try require(c.quicz_openssl_tls_backend_generated_crypto_len(openssl_context) > 0);
    try require(initial_progress.inbound_bytes == 0);
    try require(initial_progress.outbound_chunks == 1);
    try require(initial_progress.outbound_bytes == c.quicz_openssl_tls_backend_generated_crypto_len(openssl_context));
    try require(!initial_progress.peer_transport_parameters_applied);
    try require(!initial_progress.handshake_keys_installed);
    try require(!initial_progress.handshake_confirmed);
    const adapter_initial_socket = try verifyAdapterInitialSocketDelivery(
        &endpoint_loop,
        &connection,
        &peer,
        initial_progress.outbound_bytes,
    );
    const initial_recv_callbacks = c.quicz_openssl_tls_backend_inbound_crypto_recv_callbacks(openssl_context);
    const initial_release_callbacks = c.quicz_openssl_tls_backend_inbound_crypto_release_callbacks(openssl_context);

    var peer_transport_parameter_buf: [512]u8 = undefined;
    const peer_transport_parameters = try copyOpenSslClientPeerTransportParameters(&peer_transport_parameter_buf);
    try require(peer_transport_parameters.len == transcript.client_peer_transport_parameters_len);
    try require(std.mem.eql(u8, peer_transport_parameters, transcript_local_transport_parameters.server));
    var parsed_transcript_peer_transport_parameters = try quicz.transport_parameters.parse(
        peer_transport_parameters,
        allocator,
    );
    defer parsed_transcript_peer_transport_parameters.deinit(allocator);
    const transcript_peer_original_dcid = parsed_transcript_peer_transport_parameters.original_destination_connection_id orelse
        return error.UnexpectedState;
    const transcript_peer_initial_scid = parsed_transcript_peer_transport_parameters.initial_source_connection_id orelse
        return error.UnexpectedState;
    try require(std.mem.eql(u8, transcript_peer_original_dcid, &adapter_original_dcid));
    try require(std.mem.eql(u8, transcript_peer_initial_scid, &adapter_server_scid));
    try require(parsed_transcript_peer_transport_parameters.initial_max_data == 8192);
    try require(parsed_transcript_peer_transport_parameters.initial_max_stream_data_bidi_local == 2048);
    try require(parsed_transcript_peer_transport_parameters.initial_max_stream_data_bidi_remote == 2048);
    try require(parsed_transcript_peer_transport_parameters.initial_max_streams_bidi == 8);
    try require(statusIsOk(c.quicz_openssl_tls_backend_debug_got_transport_parameters(
        openssl_context,
        peer_transport_parameters.ptr,
        peer_transport_parameters.len,
    )));

    const client_handshake_local = try copyOpenSslClientSecret(2, 1);
    const client_handshake_peer = try copyOpenSslClientSecret(2, 0);
    const server_handshake_local = try copyOpenSslServerSecret(2, 1);
    const server_handshake_peer = try copyOpenSslServerSecret(2, 0);
    try require(std.mem.eql(u8, &client_handshake_local, &server_handshake_peer));
    try require(std.mem.eql(u8, &server_handshake_local, &client_handshake_peer));

    try require(statusIsOk(c.quicz_openssl_tls_backend_debug_yield_handshake_secret(
        openssl_context,
        1,
        &client_handshake_local,
        client_handshake_local.len,
    )));
    try require(statusIsOk(c.quicz_openssl_tls_backend_debug_yield_handshake_secret(
        openssl_context,
        0,
        &client_handshake_peer,
        client_handshake_peer.len,
    )));

    const handshake_key_progress = try connection.driveCryptoBackendInSpace(
        .handshake,
        tls_backend.cryptoBackend(),
        &scratch,
    );
    try require(c.quicz_openssl_tls_backend_peer_transport_parameters_len(openssl_context) == peer_transport_parameters.len);
    try require(c.quicz_openssl_tls_backend_got_transport_params_callbacks(openssl_context) == 1);
    try require(c.quicz_openssl_tls_backend_yield_secret_callbacks(openssl_context) == 2);
    try require(handshake_key_progress.peer_transport_parameters_applied);
    try require(handshake_key_progress.peer_transport_parameters_bytes == peer_transport_parameters.len);
    try require(handshake_key_progress.handshake_keys_installed);
    try require(handshake_key_progress.inbound_bytes == 0);
    try require(handshake_key_progress.outbound_chunks == 0);
    try require(!handshake_key_progress.handshake_confirmed);
    try require(connection.hasHandshakeProtectionKeys());

    var inbound_crypto_buf: [8192]u8 = undefined;
    const inbound_crypto = try copyOpenSslServerCrypto(2, &inbound_crypto_buf);
    try require(inbound_crypto.len == transcript.server_out_level_bytes[2]);
    const adapter_handshake_socket = try verifyAdapterHandshakeSocketDelivery(
        &endpoint_loop,
        &connection,
        &peer,
        server_handshake_local,
        server_handshake_peer,
        inbound_crypto,
    );

    const handshake_progress = try connection.driveCryptoBackendInSpace(
        .handshake,
        tls_backend.cryptoBackend(),
        &scratch,
    );

    try require(c.quicz_openssl_tls_backend_received_crypto_len(openssl_context) == inbound_crypto.len);
    try require(c.quicz_openssl_tls_backend_peer_transport_parameters_len(openssl_context) == peer_transport_parameters.len);
    try require(c.quicz_openssl_tls_backend_got_transport_params_callbacks(openssl_context) == 1);
    try require(c.quicz_openssl_tls_backend_yield_secret_callbacks(openssl_context) == 2);
    try require(c.quicz_openssl_tls_backend_pending_inbound_crypto_len(openssl_context) == inbound_crypto.len);
    try require(!handshake_progress.peer_transport_parameters_applied);
    try require(handshake_progress.peer_transport_parameters_bytes == 0);
    try require(!handshake_progress.handshake_keys_installed);
    try require(handshake_progress.inbound_bytes == inbound_crypto.len);
    try require(handshake_progress.outbound_chunks == 0);
    try require(!handshake_progress.handshake_confirmed);
    try require(connection.hasHandshakeProtectionKeys());

    const client_application_local = try copyOpenSslClientSecret(3, 1);
    const client_application_peer = try copyOpenSslClientSecret(3, 0);
    const server_application_local = try copyOpenSslServerSecret(3, 1);
    const server_application_peer = try copyOpenSslServerSecret(3, 0);
    try require(std.mem.eql(u8, &client_application_local, &server_application_peer));
    try require(std.mem.eql(u8, &server_application_local, &client_application_peer));

    try require(statusIsOk(c.quicz_openssl_tls_backend_debug_yield_application_secret(
        openssl_context,
        1,
        &client_application_local,
        client_application_local.len,
    )));
    try require(statusIsOk(c.quicz_openssl_tls_backend_debug_yield_application_secret(
        openssl_context,
        0,
        &client_application_peer,
        client_application_peer.len,
    )));

    const application_progress = try connection.driveCryptoBackendInSpace(
        .application,
        tls_backend.cryptoBackend(),
        &scratch,
    );
    try require(c.quicz_openssl_tls_backend_yield_secret_callbacks(openssl_context) == 4);
    try require(application_progress.one_rtt_keys_installed);
    try require(!application_progress.peer_transport_parameters_applied);
    try require(!application_progress.handshake_keys_installed);
    try require(!application_progress.zero_rtt_keys_installed);
    try require(application_progress.inbound_bytes == 0);
    try require(application_progress.outbound_chunks == 0);
    try require(!application_progress.handshake_confirmed);
    try require(connection.hasOneRttProtectionKeys());

    try peer.installOneRttTrafficSecrets(.{
        .local = server_application_local,
        .peer = server_application_peer,
    });
    try require(connection.hasHandshakeProtectionKeys());
    try require(peer.hasHandshakeProtectionKeys());
    try connection.confirmHandshake();
    try peer.confirmHandshake();
    try connection.discardPacketNumberSpace(.handshake);
    try peer.discardPacketNumberSpace(.handshake);
    try require(connection.handshakeConfirmed());
    try require(peer.handshakeConfirmed());
    try require(connection.packetNumberSpaceDiscarded(.handshake));
    try require(peer.packetNumberSpaceDiscarded(.handshake));
    try require(!connection.hasHandshakeProtectionKeys());
    try require(!peer.hasHandshakeProtectionKeys());
    try require(peer.hasOneRttProtectionKeys());
    const adapter_application_socket = try verifyAdapterApplicationSocketEcho(
        &endpoint_loop,
        &connection,
        &peer,
    );

    try require(statusIsOk(c.quicz_openssl_tls_backend_debug_consume_inbound_once(openssl_context)));
    try require(c.quicz_openssl_tls_backend_inbound_crypto_recv_callbacks(openssl_context) == initial_recv_callbacks + 1);
    try require(c.quicz_openssl_tls_backend_inbound_crypto_release_callbacks(openssl_context) == initial_release_callbacks + 1);
    try require(c.quicz_openssl_tls_backend_pending_inbound_crypto_len(openssl_context) == 0);
    try require(c.quicz_openssl_tls_backend_released_inbound_crypto_len(openssl_context) == inbound_crypto.len);

    std.debug.print(
        "[tls-openssl-backend-adapter] callbacks={} ssl_is_quic={} local_tp_bytes={} initial_outbound_bytes={} generated_crypto_bytes={} adapter_initial_socket={}/{}/{} handshake_drive_calls={} last_ssl_error={} peer_tp_bytes={} got_tp_callbacks={} yield_secret_callbacks={} transcript_handshake_bytes={} adapter_handshake_socket={}/{}/{} handshake_inbound_bytes={} inbound_recv_callbacks={} inbound_release_callbacks={} inbound_released_bytes={} handshake_outbound_chunks={} handshake_keys={} one_rtt_keys={} adapter_application_socket={}/{}/{}/{}/{}/{}/{} backend_confirmed={}\n",
        .{
            c.quicz_openssl_tls_backend_callbacks_set(openssl_context),
            c.quicz_openssl_tls_backend_ssl_is_quic_after_callbacks(openssl_context),
            initial_progress.local_transport_parameters_bytes,
            initial_progress.outbound_bytes,
            c.quicz_openssl_tls_backend_generated_crypto_len(openssl_context),
            adapter_initial_socket.crypto_bytes,
            adapter_initial_socket.datagram_bytes,
            adapter_initial_socket.ack_bytes,
            c.quicz_openssl_tls_backend_handshake_drive_calls(openssl_context),
            c.quicz_openssl_tls_backend_last_ssl_error(openssl_context),
            handshake_key_progress.peer_transport_parameters_bytes,
            c.quicz_openssl_tls_backend_got_transport_params_callbacks(openssl_context),
            c.quicz_openssl_tls_backend_yield_secret_callbacks(openssl_context),
            transcript.server_out_level_bytes[2],
            adapter_handshake_socket.crypto_bytes,
            adapter_handshake_socket.datagram_bytes,
            adapter_handshake_socket.ack_bytes,
            handshake_progress.inbound_bytes,
            c.quicz_openssl_tls_backend_inbound_crypto_recv_callbacks(openssl_context),
            c.quicz_openssl_tls_backend_inbound_crypto_release_callbacks(openssl_context),
            c.quicz_openssl_tls_backend_released_inbound_crypto_len(openssl_context),
            handshake_progress.outbound_chunks,
            handshake_key_progress.handshake_keys_installed,
            application_progress.one_rtt_keys_installed,
            adapter_application_socket.request_bytes,
            adapter_application_socket.request_datagram_bytes,
            adapter_application_socket.echo_bytes,
            adapter_application_socket.echo_datagram_bytes,
            adapter_application_socket.final_ack_bytes,
            adapter_application_socket.client_inflight_after_echo,
            adapter_application_socket.server_inflight_after_final_ack,
            application_progress.handshake_confirmed,
        },
    );
    std.debug.print(
        "[tls-openssl-backend-adapter] transcript_keylog={}/{}/{}/{} transcript_tp={} adapter_keylog={}/{} adapter_pto={}/{}/{}/{} adapter_key_discard={}/{}/{}/{}/{}/{} adapter_endpoint_routes={}/{}/{}/{} adapter_close_cleanup={}/{}\n",
        .{
            transcript.client_keylog_callbacks,
            transcript.server_keylog_callbacks,
            transcript.client_keylog_bytes,
            transcript.server_keylog_bytes,
            transcript.client_peer_transport_parameters_len,
            c.quicz_openssl_tls_backend_keylog_callbacks(openssl_context),
            c.quicz_openssl_tls_backend_keylog_bytes(openssl_context),
            adapter_application_socket.client_pto_deadline_millis,
            adapter_application_socket.client_pto_datagram_bytes,
            adapter_application_socket.client_pto_route,
            adapter_application_socket.server_pto_ack_largest,
            adapter_application_socket.client_handshake_confirmed,
            adapter_application_socket.server_handshake_confirmed,
            adapter_application_socket.client_handshake_space_discarded,
            adapter_application_socket.server_handshake_space_discarded,
            adapter_application_socket.client_handshake_keys_present,
            adapter_application_socket.server_handshake_keys_present,
            adapter_application_socket.client_routes_registered,
            adapter_application_socket.server_routes_registered,
            adapter_application_socket.client_routes_after_close_timeout,
            adapter_application_socket.server_routes_after_drain_timeout,
            adapter_application_socket.close_datagram_bytes,
            adapter_application_socket.server_close_error_code,
        },
    );
}
