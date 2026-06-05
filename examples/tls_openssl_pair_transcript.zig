const std = @import("std");
const c = @import("c");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

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

const ReceivedDatagram = struct {
    data: []const u8,
    path: quicz.endpoint.Udp4Tuple,
};

const transcript_original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const transcript_client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
const transcript_server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };

fn require(condition: bool) ExampleError!void {
    if (!condition) return error.UnexpectedState;
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
        .ip6 => error.UnexpectedState,
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
    receive_buf: []u8,
) !ReceivedDatagram {
    const received = try socket.receiveTimeout(io, receive_buf, receiveTimeout());
    return .{
        .data = received.data,
        .path = try udp4Tuple(socket.address, received.from),
    };
}

fn packetNumberSpaceForOpenSslLevel(level: usize) ?quicz.PacketNumberSpace {
    return switch (level) {
        0 => .initial,
        2 => .handshake,
        3 => .application,
        else => null,
    };
}

fn copyOpenSslCrypto(is_client: bool, level: usize, out: []u8) ExampleError![]const u8 {
    var written_len: usize = 0;
    const copied = if (is_client)
        c.quicz_openssl_pair_transcript_copy_client_crypto(
            @intCast(level),
            out.ptr,
            out.len,
            &written_len,
        )
    else
        c.quicz_openssl_pair_transcript_copy_server_crypto(
            @intCast(level),
            out.ptr,
            out.len,
            &written_len,
        );
    try require(copied == 1);
    return out[0..written_len];
}

fn copyOpenSslPeerTransportParameters(is_client: bool, out: []u8) ExampleError![]const u8 {
    var written_len: usize = 0;
    const copied = if (is_client)
        c.quicz_openssl_pair_transcript_copy_client_peer_transport_parameters(
            out.ptr,
            out.len,
            &written_len,
        )
    else
        c.quicz_openssl_pair_transcript_copy_server_peer_transport_parameters(
            out.ptr,
            out.len,
            &written_len,
        );
    try require(copied == 1);
    return out[0..written_len];
}

fn copyOpenSslSecret(
    is_client: bool,
    level: usize,
    direction: usize,
) ExampleError![quicz.protection.traffic_secret_len]u8 {
    var secret: [quicz.protection.traffic_secret_len]u8 = undefined;
    var written_len: usize = 0;
    const copied = if (is_client)
        c.quicz_openssl_pair_transcript_copy_client_secret(
            @intCast(level),
            @intCast(direction),
            &secret,
            secret.len,
            &written_len,
        )
    else
        c.quicz_openssl_pair_transcript_copy_server_secret(
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

fn copyManualOpenSslCrypto(
    context: *anyopaque,
    is_client: bool,
    level: usize,
    out: []u8,
) ExampleError![]const u8 {
    var written_len: usize = 0;
    const copied = c.quicz_openssl_pair_transcript_context_copy_pending_crypto(
        context,
        if (is_client) 1 else 0,
        @intCast(level),
        out.ptr,
        out.len,
        &written_len,
    );
    try require(copied == 1);
    return out[0..written_len];
}

fn copyManualOpenSslSecret(
    context: *anyopaque,
    is_client: bool,
    level: usize,
    direction: usize,
) ExampleError![quicz.protection.traffic_secret_len]u8 {
    var secret: [quicz.protection.traffic_secret_len]u8 = undefined;
    var written_len: usize = 0;
    const copied = c.quicz_openssl_pair_transcript_context_copy_secret(
        context,
        if (is_client) 1 else 0,
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

fn provideManualOpenSslCrypto(
    context: *anyopaque,
    is_client: bool,
    level: usize,
    data: []const u8,
) ExampleError!void {
    try require(c.quicz_openssl_pair_transcript_context_provide_crypto(
        context,
        if (is_client) 1 else 0,
        @intCast(level),
        data.ptr,
        data.len,
    ) == 1);
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
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &transcript_original_dcid);

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

    try client.sendCryptoInSpace(.initial, "quicz transcript client tp seed");
    const client_initial = (try client.pollProtectedLongCryptoDatagramInSpace(
        .initial,
        1,
        &transcript_original_dcid,
        &transcript_client_scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_initial);
    try server.recordPeerAddressBytesReceived(client_initial.len);
    try server.processProtectedLongDatagramInSpace(.initial, 2, secrets.client, client_initial);

    try server.sendPingInSpace(.initial);
    const server_initial = (try server.pollProtectedLongDatagram(
        3,
        &transcript_client_scid,
        &transcript_server_scid,
        &[_]u8{},
        .{ .initial = secrets.server },
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_initial);

    const client_local_scid = client.localInitialSourceConnectionId() orelse return error.UnexpectedState;
    const server_original_dcid = server.originalDestinationConnectionId() orelse return error.UnexpectedState;
    const server_local_scid = server.localInitialSourceConnectionId() orelse return error.UnexpectedState;
    try require(std.mem.eql(u8, client_local_scid, &transcript_client_scid));
    try require(std.mem.eql(u8, server_original_dcid, &transcript_original_dcid));
    try require(std.mem.eql(u8, server_local_scid, &transcript_server_scid));

    return .{
        .client = try client.encodeLocalTransportParameters(client_out),
        .server = try server.encodeLocalTransportParameters(server_out),
    };
}

fn injectCryptoFrame(
    receiver: *quicz.Connection,
    space: quicz.PacketNumberSpace,
    data: []const u8,
) !void {
    var raw: [8192]u8 = undefined;
    var writer = fixedWriter(&raw);
    try quicz.frame.encodeFrame(writer.writer(), .{ .crypto = .{
        .offset = 0,
        .data = data,
    } });
    try receiver.processDatagramInSpace(space, 0, writer.getWritten());
}

fn verifyCryptoDelivery(
    sender_is_client: bool,
    level: usize,
    expected_len: usize,
    receiver: *quicz.Connection,
) !usize {
    var crypto_bytes: [8192]u8 = undefined;
    const copied = try copyOpenSslCrypto(sender_is_client, level, &crypto_bytes);
    try require(copied.len == expected_len);
    if (copied.len == 0) return 0;

    const space = packetNumberSpaceForOpenSslLevel(level) orelse return error.UnexpectedState;
    try injectCryptoFrame(receiver, space, copied);

    var read_buf: [8192]u8 = undefined;
    const read_len = (try receiver.recvCryptoInSpace(space, &read_buf)) orelse return error.UnexpectedState;
    try require(read_len == copied.len);
    try require(std.mem.eql(u8, read_buf[0..read_len], copied));
    try require((try receiver.recvCryptoInSpace(space, &read_buf)) == null);
    return read_len;
}

const ProtectedInitialDelivery = struct {
    crypto_bytes: usize,
    datagram_bytes: usize,
};

const SocketInitialDelivery = struct {
    client_crypto_bytes: usize,
    client_datagram_bytes: usize,
    server_crypto_bytes: usize,
    server_datagram_bytes: usize,
    client_ack_bytes: usize,
};

const ManualSocketTranscriptDelivery = struct {
    client_initial_crypto_bytes: usize,
    client_initial_datagram_bytes: usize,
    server_initial_crypto_bytes: usize,
    server_initial_datagram_bytes: usize,
    client_handshake_crypto_bytes: usize,
    client_handshake_datagram_bytes: usize,
    server_handshake_crypto_bytes: usize,
    server_handshake_datagram_bytes: usize,
    request_bytes: usize,
    request_datagram_bytes: usize,
    echo_bytes: usize,
    echo_datagram_bytes: usize,
    final_ack_bytes: usize,
    close_datagram_bytes: usize,
    server_close_error_code: u64,
    client_handshake_space_discarded: bool,
    server_handshake_space_discarded: bool,
    client_handshake_keys_present: bool,
    server_handshake_keys_present: bool,
    client_routes_after_close_timeout: usize,
    server_routes_after_drain_timeout: usize,
};

const ProtectedHandshakeDelivery = struct {
    client_crypto_bytes: usize,
    client_datagram_bytes: usize,
    server_crypto_bytes: usize,
    server_datagram_bytes: usize,
};

const SocketHandshakeDelivery = struct {
    client_crypto_bytes: usize,
    client_datagram_bytes: usize,
    client_ack_bytes: usize,
    server_crypto_bytes: usize,
    server_datagram_bytes: usize,
    server_ack_bytes: usize,
};

const ProtectedApplicationDelivery = struct {
    request_bytes: usize,
    request_datagram_bytes: usize,
    response_bytes: usize,
    response_datagram_bytes: usize,
};

const SocketApplicationEcho = struct {
    request_bytes: usize,
    request_datagram_bytes: usize,
    echo_bytes: usize,
    echo_datagram_bytes: usize,
    echo_packets: usize,
};

fn verifyProtectedInitialCryptoDelivery(expected_len: usize) !ProtectedInitialDelivery {
    var client_initial_crypto: [8192]u8 = undefined;
    const copied = try copyOpenSslCrypto(true, 0, &client_initial_crypto);
    try require(copied.len == expected_len);
    try require(copied.len > 0);

    const allocator = std.heap.page_allocator;
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var protected_client = try quicz.Connection.init(allocator, .client, .{
        .max_datagram_size = 8192,
    });
    defer protected_client.deinit();
    var protected_server = try quicz.Connection.init(allocator, .server, .{
        .max_datagram_size = 8192,
    });
    defer protected_server.deinit();

    try protected_client.sendCryptoInSpace(.initial, copied);
    const protected = (try protected_client.pollProtectedLongCryptoDatagramInSpace(
        .initial,
        0,
        &original_dcid,
        &client_scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.UnexpectedState;
    defer allocator.free(protected);
    try require(protected.len >= 1200);
    try require(protected_client.sentPacketCount(.initial) == 1);

    try protected_server.processProtectedLongDatagramInSpace(.initial, 1, secrets.client, protected);
    var read_buf: [8192]u8 = undefined;
    const read_len = (try protected_server.recvCryptoInSpace(.initial, &read_buf)) orelse return error.UnexpectedState;
    try require(read_len == copied.len);
    try require(std.mem.eql(u8, read_buf[0..read_len], copied));
    try require((try protected_server.recvCryptoInSpace(.initial, &read_buf)) == null);
    try require(protected_server.nextPeerPacketNumber(.initial) == 1);
    try require(protected_server.pendingAckLargest(.initial) == 0);

    return .{
        .crypto_bytes = read_len,
        .datagram_bytes = protected.len,
    };
}

fn verifySocketBackedInitialCryptoDelivery(
    expected_client_len: usize,
    expected_server_len: usize,
) !SocketInitialDelivery {
    var client_initial_crypto: [8192]u8 = undefined;
    var server_initial_crypto: [8192]u8 = undefined;
    const copied_client = try copyOpenSslCrypto(true, 0, &client_initial_crypto);
    const copied_server = try copyOpenSslCrypto(false, 0, &server_initial_crypto);
    try require(copied_client.len == expected_client_len);
    try require(copied_server.len == expected_server_len);
    try require(copied_client.len > 0);
    try require(copied_server.len > 0);

    const allocator = std.heap.page_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_socket = try bindLoopbackUdp(io);
    defer client_socket.close(io);
    var server_socket = try bindLoopbackUdp(io);
    defer server_socket.close(io);

    const client_address = try udp4Address(client_socket.address);
    const server_address = try udp4Address(server_socket.address);
    try require(client_address.port != 0);
    try require(server_address.port != 0);
    try require(client_address.port != server_address.port);

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
    const server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const client_handle: u64 = 101;
    const server_handle: u64 = 111;
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try quicz.Connection.init(allocator, .client, .{
        .max_datagram_size = 8192,
    });
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{
        .max_datagram_size = 8192,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    var client_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer client_lifecycle.deinit();
    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer server_lifecycle.deinit();

    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    const server_path = try udp4Tuple(server_socket.address, client_socket.address);
    try client_lifecycle.registerConnectionId(client_handle, &client_scid, client_path, .{
        .active_migration_disabled = true,
    });
    try server_lifecycle.registerConnectionId(server_handle, &original_dcid, server_path, .{
        .active_migration_disabled = true,
    });
    try server_lifecycle.registerConnectionId(server_handle, &server_scid, server_path, .{
        .active_migration_disabled = true,
    });

    try client.sendCryptoInSpace(.initial, copied_client);
    const client_datagram = (try client_lifecycle.pollProtectedLongDatagram(
        client_handle,
        &client,
        80,
        &original_dcid,
        &client_scid,
        &[_]u8{},
        .{ .initial = secrets.client },
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_datagram);
    try client_socket.send(io, &server_socket.address, client_datagram);

    var server_receive_buf: [9000]u8 = undefined;
    var client_receive_buf: [9000]u8 = undefined;
    const client_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const client_route = try server_lifecycle.processRoutedProtectedInitialDatagram(
        server_handle,
        &server,
        client_received.path,
        81,
        &original_dcid,
        client_received.data,
    );
    try require(client_route.connection_id == server_handle);
    try require(std.mem.eql(u8, client_route.destination_connection_id.asSlice(), &original_dcid));
    try require(server.pendingAckLargest(.initial) == 0);

    var read_buf: [8192]u8 = undefined;
    const client_read_len = (try server.recvCryptoInSpace(.initial, &read_buf)) orelse return error.UnexpectedState;
    try require(client_read_len == copied_client.len);
    try require(std.mem.eql(u8, read_buf[0..client_read_len], copied_client));
    try require((try server.recvCryptoInSpace(.initial, &read_buf)) == null);

    try server.sendCryptoInSpace(.initial, copied_server);
    const server_datagram = (try server_lifecycle.pollProtectedLongDatagram(
        server_handle,
        &server,
        82,
        &client_scid,
        &server_scid,
        &[_]u8{},
        .{ .initial = secrets.server },
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_datagram);
    try server_socket.send(io, &client_socket.address, server_datagram);

    const server_received = try receiveDatagram(io, &client_socket, &client_receive_buf);
    const server_route = try client_lifecycle.processRoutedProtectedInitialDatagram(
        client_handle,
        &client,
        server_received.path,
        83,
        &original_dcid,
        server_received.data,
    );
    try require(server_route.connection_id == client_handle);
    try require(std.mem.eql(u8, server_route.destination_connection_id.asSlice(), &client_scid));

    const server_read_len = (try client.recvCryptoInSpace(.initial, &read_buf)) orelse return error.UnexpectedState;
    try require(server_read_len == copied_server.len);
    try require(std.mem.eql(u8, read_buf[0..server_read_len], copied_server));
    try require((try client.recvCryptoInSpace(.initial, &read_buf)) == null);
    try require(client.pendingAckLargest(.initial) == 0);

    const client_ack = (try client_lifecycle.pollProtectedLongDatagram(
        client_handle,
        &client,
        84,
        &server_scid,
        &client_scid,
        &[_]u8{},
        .{ .initial = secrets.client },
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_ack);
    try client_socket.send(io, &server_socket.address, client_ack);

    const client_ack_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const client_ack_route = try server_lifecycle.processRoutedProtectedInitialDatagram(
        server_handle,
        &server,
        client_ack_received.path,
        85,
        &original_dcid,
        client_ack_received.data,
    );
    try require(client_ack_route.connection_id == server_handle);
    try require(std.mem.eql(u8, client_ack_route.destination_connection_id.asSlice(), &server_scid));
    try require(server.bytesInFlight(.initial) == 0);

    return .{
        .client_crypto_bytes = client_read_len,
        .client_datagram_bytes = client_datagram.len,
        .server_crypto_bytes = server_read_len,
        .server_datagram_bytes = server_datagram.len,
        .client_ack_bytes = client_ack.len,
    };
}

fn verifyManualSocketTranscriptDelivery() !ManualSocketTranscriptDelivery {
    const context = c.quicz_openssl_pair_transcript_context_new() orelse return error.UnexpectedState;
    defer c.quicz_openssl_pair_transcript_context_free(context);

    try require(c.quicz_openssl_pair_transcript_context_drive(context, 1) == 1);
    var client_initial_crypto: [8192]u8 = undefined;
    const copied_client = try copyManualOpenSslCrypto(context, true, 0, &client_initial_crypto);
    try require(copied_client.len > 0);

    const allocator = std.heap.page_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_socket = try bindLoopbackUdp(io);
    defer client_socket.close(io);
    var server_socket = try bindLoopbackUdp(io);
    defer server_socket.close(io);

    const client_address = try udp4Address(client_socket.address);
    const server_address = try udp4Address(server_socket.address);
    try require(client_address.port != 0);
    try require(server_address.port != 0);
    try require(client_address.port != server_address.port);

    const original_dcid = transcript_original_dcid;
    const client_scid = transcript_client_scid;
    const server_scid = transcript_server_scid;
    const client_handle: u64 = 121;
    const server_handle: u64 = 131;
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try quicz.Connection.init(allocator, .client, .{
        .initial_max_data = 4096,
        .initial_max_stream_data = 1024,
        .initial_max_streams_bidi = 4,
        .max_datagram_size = 8192,
    });
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{
        .initial_max_data = 4096,
        .initial_max_stream_data = 1024,
        .initial_max_streams_bidi = 4,
        .max_datagram_size = 8192,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    var client_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer client_lifecycle.deinit();
    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer server_lifecycle.deinit();

    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    const server_path = try udp4Tuple(server_socket.address, client_socket.address);
    try client_lifecycle.registerConnectionId(client_handle, &client_scid, client_path, .{
        .active_migration_disabled = true,
    });
    try server_lifecycle.registerConnectionId(server_handle, &original_dcid, server_path, .{
        .active_migration_disabled = true,
    });
    try server_lifecycle.registerConnectionId(server_handle, &server_scid, server_path, .{
        .active_migration_disabled = true,
    });

    try client.sendCryptoInSpace(.initial, copied_client);
    const client_datagram = (try client_lifecycle.pollProtectedLongDatagram(
        client_handle,
        &client,
        90,
        &original_dcid,
        &client_scid,
        &[_]u8{},
        .{ .initial = secrets.client },
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_datagram);
    try client_socket.send(io, &server_socket.address, client_datagram);

    var server_receive_buf: [9000]u8 = undefined;
    var client_receive_buf: [9000]u8 = undefined;
    const client_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const client_route = try server_lifecycle.processRoutedProtectedInitialDatagram(
        server_handle,
        &server,
        client_received.path,
        91,
        &original_dcid,
        client_received.data,
    );
    try require(client_route.connection_id == server_handle);
    try require(std.mem.eql(u8, client_route.destination_connection_id.asSlice(), &original_dcid));

    var read_buf: [8192]u8 = undefined;
    const client_read_len = (try server.recvCryptoInSpace(.initial, &read_buf)) orelse return error.UnexpectedState;
    try require(client_read_len == copied_client.len);
    try require(std.mem.eql(u8, read_buf[0..client_read_len], copied_client));
    try provideManualOpenSslCrypto(context, false, 0, read_buf[0..client_read_len]);

    try require(c.quicz_openssl_pair_transcript_context_drive(context, 0) == 1);
    var server_initial_crypto: [8192]u8 = undefined;
    const copied_server = try copyManualOpenSslCrypto(context, false, 0, &server_initial_crypto);
    try require(copied_server.len > 0);

    try server.sendCryptoInSpace(.initial, copied_server);
    const server_datagram = (try server_lifecycle.pollProtectedLongDatagram(
        server_handle,
        &server,
        92,
        &client_scid,
        &server_scid,
        &[_]u8{},
        .{ .initial = secrets.server },
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_datagram);
    try server_socket.send(io, &client_socket.address, server_datagram);

    const server_received = try receiveDatagram(io, &client_socket, &client_receive_buf);
    const server_route = try client_lifecycle.processRoutedProtectedInitialDatagram(
        client_handle,
        &client,
        server_received.path,
        93,
        &original_dcid,
        server_received.data,
    );
    try require(server_route.connection_id == client_handle);
    try require(std.mem.eql(u8, server_route.destination_connection_id.asSlice(), &client_scid));

    const server_read_len = (try client.recvCryptoInSpace(.initial, &read_buf)) orelse return error.UnexpectedState;
    try require(server_read_len == copied_server.len);
    try require(std.mem.eql(u8, read_buf[0..server_read_len], copied_server));
    try provideManualOpenSslCrypto(context, true, 0, read_buf[0..server_read_len]);

    try require(c.quicz_openssl_pair_transcript_context_drive(context, 1) == 1);

    const client_local = try copyManualOpenSslSecret(context, true, 2, 1);
    const client_peer = try copyManualOpenSslSecret(context, true, 2, 0);
    const server_local = try copyManualOpenSslSecret(context, false, 2, 1);
    const server_peer = try copyManualOpenSslSecret(context, false, 2, 0);
    try require(std.mem.eql(u8, &client_local, &server_peer));
    try require(std.mem.eql(u8, &server_local, &client_peer));

    try client.installHandshakeTrafficSecrets(.{
        .local = client_local,
        .peer = client_peer,
    });
    try server.installHandshakeTrafficSecrets(.{
        .local = server_local,
        .peer = server_peer,
    });
    try require(client.hasHandshakeProtectionKeys());
    try require(server.hasHandshakeProtectionKeys());

    var server_handshake_crypto: [8192]u8 = undefined;
    const copied_server_handshake = try copyManualOpenSslCrypto(context, false, 2, &server_handshake_crypto);
    try require(copied_server_handshake.len > 0);

    try server.sendCryptoInSpace(.handshake, copied_server_handshake);
    const server_handshake_datagram = (try server_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        server_handle,
        &server,
        94,
        &client_scid,
        &server_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_handshake_datagram);
    try server_socket.send(io, &client_socket.address, server_handshake_datagram);

    const server_handshake_received = try receiveDatagram(io, &client_socket, &client_receive_buf);
    const server_handshake_route = try client_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        client_handle,
        &client,
        server_handshake_received.path,
        95,
        server_handshake_received.data,
    );
    try require(server_handshake_route.connection_id == client_handle);
    try require(std.mem.eql(u8, server_handshake_route.destination_connection_id.asSlice(), &client_scid));

    const server_handshake_read_len = (try client.recvCryptoInSpace(.handshake, &read_buf)) orelse
        return error.UnexpectedState;
    try require(server_handshake_read_len == copied_server_handshake.len);
    try require(std.mem.eql(u8, read_buf[0..server_handshake_read_len], copied_server_handshake));
    try provideManualOpenSslCrypto(context, true, 2, read_buf[0..server_handshake_read_len]);

    try require(c.quicz_openssl_pair_transcript_context_drive(context, 1) == 1);
    var client_handshake_crypto: [8192]u8 = undefined;
    const copied_client_handshake = try copyManualOpenSslCrypto(context, true, 2, &client_handshake_crypto);
    try require(copied_client_handshake.len > 0);

    try client.sendCryptoInSpace(.handshake, copied_client_handshake);
    const client_handshake_datagram = (try client_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        client_handle,
        &client,
        96,
        &server_scid,
        &client_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_handshake_datagram);
    try client_socket.send(io, &server_socket.address, client_handshake_datagram);

    const client_handshake_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const client_handshake_route = try server_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        server_handle,
        &server,
        client_handshake_received.path,
        97,
        client_handshake_received.data,
    );
    try require(client_handshake_route.connection_id == server_handle);
    try require(std.mem.eql(u8, client_handshake_route.destination_connection_id.asSlice(), &server_scid));

    const client_handshake_read_len = (try server.recvCryptoInSpace(.handshake, &read_buf)) orelse
        return error.UnexpectedState;
    try require(client_handshake_read_len == copied_client_handshake.len);
    try require(std.mem.eql(u8, read_buf[0..client_handshake_read_len], copied_client_handshake));
    try provideManualOpenSslCrypto(context, false, 2, read_buf[0..client_handshake_read_len]);

    try require(c.quicz_openssl_pair_transcript_context_drive(context, 0) == 1);
    const manual_result = c.quicz_openssl_pair_transcript_context_result(context);
    try require(manual_result.initialized == 1);
    try require(manual_result.client_done == 1);
    try require(manual_result.server_done == 1);
    try require(manual_result.server_got_transport_params_callbacks == 1);
    try require(manual_result.server_peer_transport_parameters_len > 0);
    try require(manual_result.client_alert_callbacks == 0);
    try require(manual_result.server_alert_callbacks == 0);

    const client_one_rtt_local = try copyManualOpenSslSecret(context, true, 3, 1);
    const client_one_rtt_peer = try copyManualOpenSslSecret(context, true, 3, 0);
    const server_one_rtt_local = try copyManualOpenSslSecret(context, false, 3, 1);
    const server_one_rtt_peer = try copyManualOpenSslSecret(context, false, 3, 0);
    try require(std.mem.eql(u8, &client_one_rtt_local, &server_one_rtt_peer));
    try require(std.mem.eql(u8, &server_one_rtt_local, &client_one_rtt_peer));

    try client.installOneRttTrafficSecrets(.{
        .local = client_one_rtt_local,
        .peer = client_one_rtt_peer,
    });
    try server.installOneRttTrafficSecrets(.{
        .local = server_one_rtt_local,
        .peer = server_one_rtt_peer,
    });
    try client.confirmHandshake();
    try server.confirmHandshake();
    try require(client.hasOneRttProtectionKeys());
    try require(server.hasOneRttProtectionKeys());

    const stream_id = try client.openStream();
    const request = "manual openssl udp one-rtt echo";
    try client.sendOnStream(stream_id, request, true);
    const request_datagram = (try client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        client_handle,
        &client,
        98,
        &server_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(request_datagram);
    try client_socket.send(io, &server_socket.address, request_datagram);

    const request_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const request_route = try server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        server_handle,
        &server,
        request_received.path,
        99,
        request_received.data,
    );
    try require(request_route.connection_id == server_handle);
    try require(std.mem.eql(u8, request_route.destination_connection_id.asSlice(), &server_scid));

    var stream_buf: [128]u8 = undefined;
    const request_len = (try server.recvOnStream(stream_id, &stream_buf)) orelse return error.UnexpectedState;
    const request_payload = stream_buf[0..request_len];
    try require(std.mem.eql(u8, request_payload, request));

    try server.sendOnStream(stream_id, request_payload, true);
    var echo_packet_count: usize = 0;
    var echo_datagram_bytes: usize = 0;
    var echo_len_or_null: ?usize = null;
    while (echo_packet_count < 4 and echo_len_or_null == null) : (echo_packet_count += 1) {
        const echo_datagram = (try server_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
            server_handle,
            &server,
            100 + @as(i64, @intCast(echo_packet_count)),
            &client_scid,
        )) orelse return error.UnexpectedState;
        defer allocator.free(echo_datagram);
        echo_datagram_bytes += echo_datagram.len;
        try server_socket.send(io, &client_socket.address, echo_datagram);

        const echo_received = try receiveDatagram(io, &client_socket, &client_receive_buf);
        const echo_route = try client_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
            client_handle,
            &client,
            echo_received.path,
            110 + @as(i64, @intCast(echo_packet_count)),
            echo_received.data,
        );
        try require(echo_route.connection_id == client_handle);
        try require(std.mem.eql(u8, echo_route.destination_connection_id.asSlice(), &client_scid));
        echo_len_or_null = try client.recvOnStream(stream_id, &stream_buf);
    }
    const echo_len = echo_len_or_null orelse return error.UnexpectedState;
    const echo_payload = stream_buf[0..echo_len];
    try require(std.mem.eql(u8, echo_payload, request_payload));

    const final_ack = (try client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        client_handle,
        &client,
        120,
        &server_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(final_ack);
    try client_socket.send(io, &server_socket.address, final_ack);

    const ack_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const ack_route = try server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        server_handle,
        &server,
        ack_received.path,
        121,
        ack_received.data,
    );
    try require(ack_route.connection_id == server_handle);
    try require(std.mem.eql(u8, ack_route.destination_connection_id.asSlice(), &server_scid));
    try require(server.bytesInFlight(.application) == 0);

    try client.discardPacketNumberSpace(.handshake);
    try server.discardPacketNumberSpace(.handshake);
    try require(client.packetNumberSpaceDiscarded(.handshake));
    try require(server.packetNumberSpaceDiscarded(.handshake));
    try require(!client.hasHandshakeProtectionKeys());
    try require(!server.hasHandshakeProtectionKeys());

    try client.closeConnection(0, @intFromEnum(quicz.frame.FrameType.stream), "manual close");
    try require(client.connectionState() == .closing);
    const close_datagram = (try client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        client_handle,
        &client,
        130,
        &server_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(close_datagram);
    const client_close_deadline = client.closeDeadlineMillis() orelse return error.UnexpectedState;
    try require(client_close_deadline > 130);
    try client_socket.send(io, &server_socket.address, close_datagram);

    const close_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const close_route = try server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        server_handle,
        &server,
        close_received.path,
        131,
        close_received.data,
    );
    try require(close_route.connection_id == server_handle);
    try require(std.mem.eql(u8, close_route.destination_connection_id.asSlice(), &server_scid));
    try require(server.connectionState() == .draining);
    const server_drain_deadline = server.closeDeadlineMillis() orelse return error.UnexpectedState;
    try require(server_drain_deadline > 131);
    const server_close_error_code = switch (server.peerClose() orelse return error.UnexpectedState) {
        .connection => |close| blk: {
            try require(close.error_code == 0);
            try require(close.frame_type == @intFromEnum(quicz.frame.FrameType.stream));
            try require(std.mem.eql(u8, close.reason_phrase, "manual close"));
            break :blk close.error_code;
        },
        else => return error.UnexpectedState,
    };

    const client_retired = (try client_lifecycle.checkCloseTimeoutsAndRetireConnection(
        client_handle,
        &client,
        client_close_deadline,
    )) orelse return error.UnexpectedState;
    try require(client_retired.routes_retired == 1);
    try require(client.connectionState() == .closed);
    const client_routes_after_close_timeout = client_lifecycle.routeCount();
    try require(client_routes_after_close_timeout == 0);

    const server_retired = (try server_lifecycle.checkCloseTimeoutsAndRetireConnection(
        server_handle,
        &server,
        server_drain_deadline,
    )) orelse return error.UnexpectedState;
    try require(server_retired.routes_retired == 2);
    try require(server.connectionState() == .closed);
    const server_routes_after_drain_timeout = server_lifecycle.routeCount();
    try require(server_routes_after_drain_timeout == 0);

    return .{
        .client_initial_crypto_bytes = client_read_len,
        .client_initial_datagram_bytes = client_datagram.len,
        .server_initial_crypto_bytes = server_read_len,
        .server_initial_datagram_bytes = server_datagram.len,
        .client_handshake_crypto_bytes = client_handshake_read_len,
        .client_handshake_datagram_bytes = client_handshake_datagram.len,
        .server_handshake_crypto_bytes = server_handshake_read_len,
        .server_handshake_datagram_bytes = server_handshake_datagram.len,
        .request_bytes = request_len,
        .request_datagram_bytes = request_datagram.len,
        .echo_bytes = echo_len,
        .echo_datagram_bytes = echo_datagram_bytes,
        .final_ack_bytes = final_ack.len,
        .close_datagram_bytes = close_datagram.len,
        .server_close_error_code = server_close_error_code,
        .client_handshake_space_discarded = client.packetNumberSpaceDiscarded(.handshake),
        .server_handshake_space_discarded = server.packetNumberSpaceDiscarded(.handshake),
        .client_handshake_keys_present = client.hasHandshakeProtectionKeys(),
        .server_handshake_keys_present = server.hasHandshakeProtectionKeys(),
        .client_routes_after_close_timeout = client_routes_after_close_timeout,
        .server_routes_after_drain_timeout = server_routes_after_drain_timeout,
    };
}

fn verifyProtectedHandshakeCryptoDelivery(
    expected_client_len: usize,
    expected_server_len: usize,
) !ProtectedHandshakeDelivery {
    var client_handshake_crypto: [8192]u8 = undefined;
    var server_handshake_crypto: [8192]u8 = undefined;
    const copied_client = try copyOpenSslCrypto(true, 2, &client_handshake_crypto);
    const copied_server = try copyOpenSslCrypto(false, 2, &server_handshake_crypto);
    try require(copied_client.len == expected_client_len);
    try require(copied_server.len == expected_server_len);
    try require(copied_client.len > 0);
    try require(copied_server.len > 0);

    const client_local = try copyOpenSslSecret(true, 2, 1);
    const client_peer = try copyOpenSslSecret(true, 2, 0);
    const server_local = try copyOpenSslSecret(false, 2, 1);
    const server_peer = try copyOpenSslSecret(false, 2, 0);
    try require(std.mem.eql(u8, &client_local, &server_peer));
    try require(std.mem.eql(u8, &server_local, &client_peer));

    const allocator = std.heap.page_allocator;
    const client_dcid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    const client_scid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
    const server_dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const server_scid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };

    var protected_client = try quicz.Connection.init(allocator, .client, .{
        .max_datagram_size = 8192,
    });
    defer protected_client.deinit();
    var protected_server = try quicz.Connection.init(allocator, .server, .{
        .max_datagram_size = 8192,
    });
    defer protected_server.deinit();
    try protected_server.validatePeerAddress();

    try protected_client.installHandshakeTrafficSecrets(.{
        .local = client_local,
        .peer = client_peer,
    });
    try protected_server.installHandshakeTrafficSecrets(.{
        .local = server_local,
        .peer = server_peer,
    });
    try require(protected_client.hasHandshakeProtectionKeys());
    try require(protected_server.hasHandshakeProtectionKeys());

    try protected_client.sendCryptoInSpace(.handshake, copied_client);
    const protected_client_handshake = (try protected_client.pollProtectedHandshakeDatagramWithInstalledKeys(
        10,
        &server_dcid,
        &client_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(protected_client_handshake);
    try require(protected_client.sentPacketCount(.handshake) == 1);
    try protected_server.processProtectedHandshakeDatagramWithInstalledKeys(11, protected_client_handshake);

    var read_buf: [8192]u8 = undefined;
    const client_read_len = (try protected_server.recvCryptoInSpace(.handshake, &read_buf)) orelse return error.UnexpectedState;
    try require(client_read_len == copied_client.len);
    try require(std.mem.eql(u8, read_buf[0..client_read_len], copied_client));
    try require((try protected_server.recvCryptoInSpace(.handshake, &read_buf)) == null);
    try require(protected_server.nextPeerPacketNumber(.handshake) == 1);
    try require(protected_server.pendingAckLargest(.handshake) == 0);

    try protected_server.sendCryptoInSpace(.handshake, copied_server);
    const protected_server_handshake = (try protected_server.pollProtectedHandshakeDatagramWithInstalledKeys(
        12,
        &client_dcid,
        &server_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(protected_server_handshake);
    try require(protected_server.sentPacketCount(.handshake) == 1);
    try protected_client.processProtectedHandshakeDatagramWithInstalledKeys(13, protected_server_handshake);

    const server_read_len = (try protected_client.recvCryptoInSpace(.handshake, &read_buf)) orelse return error.UnexpectedState;
    try require(server_read_len == copied_server.len);
    try require(std.mem.eql(u8, read_buf[0..server_read_len], copied_server));
    try require((try protected_client.recvCryptoInSpace(.handshake, &read_buf)) == null);
    try require(protected_client.nextPeerPacketNumber(.handshake) == 1);
    try require(protected_client.pendingAckLargest(.handshake) == 0);

    return .{
        .client_crypto_bytes = client_read_len,
        .client_datagram_bytes = protected_client_handshake.len,
        .server_crypto_bytes = server_read_len,
        .server_datagram_bytes = protected_server_handshake.len,
    };
}

fn verifySocketBackedHandshakeCryptoDelivery(
    expected_client_len: usize,
    expected_server_len: usize,
) !SocketHandshakeDelivery {
    var client_handshake_crypto: [8192]u8 = undefined;
    var server_handshake_crypto: [8192]u8 = undefined;
    const copied_client = try copyOpenSslCrypto(true, 2, &client_handshake_crypto);
    const copied_server = try copyOpenSslCrypto(false, 2, &server_handshake_crypto);
    try require(copied_client.len == expected_client_len);
    try require(copied_server.len == expected_server_len);
    try require(copied_client.len > 0);
    try require(copied_server.len > 0);

    const client_local = try copyOpenSslSecret(true, 2, 1);
    const client_peer = try copyOpenSslSecret(true, 2, 0);
    const server_local = try copyOpenSslSecret(false, 2, 1);
    const server_peer = try copyOpenSslSecret(false, 2, 0);
    try require(std.mem.eql(u8, &client_local, &server_peer));
    try require(std.mem.eql(u8, &server_local, &client_peer));

    const allocator = std.heap.page_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_socket = try bindLoopbackUdp(io);
    defer client_socket.close(io);
    var server_socket = try bindLoopbackUdp(io);
    defer server_socket.close(io);

    const client_address = try udp4Address(client_socket.address);
    const server_address = try udp4Address(server_socket.address);
    try require(client_address.port != 0);
    try require(server_address.port != 0);
    try require(client_address.port != server_address.port);

    const client_dcid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const client_scid = [_]u8{ 0x91, 0x92, 0x93, 0x94 };
    const server_dcid = [_]u8{ 0xa5, 0xa6, 0xa7, 0xa8 };
    const server_scid = [_]u8{ 0xb5, 0xb6, 0xb7, 0xb8 };
    const client_handle: u64 = 81;
    const server_handle: u64 = 91;

    var client = try quicz.Connection.init(allocator, .client, .{
        .max_datagram_size = 8192,
    });
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{
        .max_datagram_size = 8192,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    try client.installHandshakeTrafficSecrets(.{
        .local = client_local,
        .peer = client_peer,
    });
    try server.installHandshakeTrafficSecrets(.{
        .local = server_local,
        .peer = server_peer,
    });
    try require(client.hasHandshakeProtectionKeys());
    try require(server.hasHandshakeProtectionKeys());

    var client_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer client_lifecycle.deinit();
    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer server_lifecycle.deinit();

    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    const server_path = try udp4Tuple(server_socket.address, client_socket.address);
    try client_lifecycle.registerConnectionId(client_handle, &client_dcid, client_path, .{
        .active_migration_disabled = true,
    });
    try server_lifecycle.registerConnectionId(server_handle, &server_dcid, server_path, .{
        .active_migration_disabled = true,
    });

    try client.sendCryptoInSpace(.handshake, copied_client);
    const client_datagram = (try client_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        client_handle,
        &client,
        70,
        &server_dcid,
        &client_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_datagram);
    try client_socket.send(io, &server_socket.address, client_datagram);

    var server_receive_buf: [1500]u8 = undefined;
    var client_receive_buf: [1500]u8 = undefined;
    const client_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const client_route = try server_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        server_handle,
        &server,
        client_received.path,
        71,
        client_received.data,
    );
    try require(client_route.connection_id == server_handle);
    try require(std.mem.eql(u8, client_route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.pendingAckLargest(.handshake) == 0);

    var read_buf: [8192]u8 = undefined;
    const client_read_len = (try server.recvCryptoInSpace(.handshake, &read_buf)) orelse return error.UnexpectedState;
    try require(client_read_len == copied_client.len);
    try require(std.mem.eql(u8, read_buf[0..client_read_len], copied_client));
    try require((try server.recvCryptoInSpace(.handshake, &read_buf)) == null);

    const server_ack = (try server_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        server_handle,
        &server,
        72,
        &client_dcid,
        &server_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_ack);
    try server_socket.send(io, &client_socket.address, server_ack);

    const server_ack_received = try receiveDatagram(io, &client_socket, &client_receive_buf);
    const server_ack_route = try client_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        client_handle,
        &client,
        server_ack_received.path,
        73,
        server_ack_received.data,
    );
    try require(server_ack_route.connection_id == client_handle);
    try require(std.mem.eql(u8, server_ack_route.destination_connection_id.asSlice(), &client_dcid));
    try require(client.bytesInFlight(.handshake) == 0);

    try server.sendCryptoInSpace(.handshake, copied_server);
    const server_datagram = (try server_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        server_handle,
        &server,
        74,
        &client_dcid,
        &server_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_datagram);
    try server_socket.send(io, &client_socket.address, server_datagram);

    const server_received = try receiveDatagram(io, &client_socket, &client_receive_buf);
    const server_route = try client_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        client_handle,
        &client,
        server_received.path,
        75,
        server_received.data,
    );
    try require(server_route.connection_id == client_handle);
    try require(std.mem.eql(u8, server_route.destination_connection_id.asSlice(), &client_dcid));
    try require(client.pendingAckLargest(.handshake) == 1);

    const server_read_len = (try client.recvCryptoInSpace(.handshake, &read_buf)) orelse return error.UnexpectedState;
    try require(server_read_len == copied_server.len);
    try require(std.mem.eql(u8, read_buf[0..server_read_len], copied_server));
    try require((try client.recvCryptoInSpace(.handshake, &read_buf)) == null);

    const client_ack = (try client_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        client_handle,
        &client,
        76,
        &server_dcid,
        &client_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_ack);
    try client_socket.send(io, &server_socket.address, client_ack);

    const client_ack_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const client_ack_route = try server_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        server_handle,
        &server,
        client_ack_received.path,
        77,
        client_ack_received.data,
    );
    try require(client_ack_route.connection_id == server_handle);
    try require(std.mem.eql(u8, client_ack_route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.bytesInFlight(.handshake) == 0);
    try require(client_lifecycle.recoveryTimerCount() == 0);
    try require(server_lifecycle.recoveryTimerCount() == 0);

    return .{
        .client_crypto_bytes = client_read_len,
        .client_datagram_bytes = client_datagram.len,
        .client_ack_bytes = server_ack.len,
        .server_crypto_bytes = server_read_len,
        .server_datagram_bytes = server_datagram.len,
        .server_ack_bytes = client_ack.len,
    };
}

fn verifyProtectedApplicationStreamDelivery() !ProtectedApplicationDelivery {
    const client_local = try copyOpenSslSecret(true, 3, 1);
    const client_peer = try copyOpenSslSecret(true, 3, 0);
    const server_local = try copyOpenSslSecret(false, 3, 1);
    const server_peer = try copyOpenSslSecret(false, 3, 0);
    try require(std.mem.eql(u8, &client_local, &server_peer));
    try require(std.mem.eql(u8, &server_local, &client_peer));

    const allocator = std.heap.page_allocator;
    const client_dcid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    const server_dcid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    const request = "openssl one-rtt stream request";
    const response = "openssl one-rtt stream response";

    var protected_client = try quicz.Connection.init(allocator, .client, .{
        .initial_max_data = 4096,
        .initial_max_stream_data = 1024,
        .initial_max_streams_bidi = 4,
        .max_datagram_size = 8192,
    });
    defer protected_client.deinit();
    var protected_server = try quicz.Connection.init(allocator, .server, .{
        .initial_max_data = 4096,
        .initial_max_stream_data = 1024,
        .initial_max_streams_bidi = 4,
        .max_datagram_size = 8192,
    });
    defer protected_server.deinit();
    try protected_server.validatePeerAddress();

    try protected_client.installOneRttTrafficSecrets(.{
        .local = client_local,
        .peer = client_peer,
    });
    try protected_server.installOneRttTrafficSecrets(.{
        .local = server_local,
        .peer = server_peer,
    });
    try require(protected_client.hasOneRttProtectionKeys());
    try require(protected_server.hasOneRttProtectionKeys());

    const stream_id = try protected_client.openStream();
    try protected_client.sendOnStream(stream_id, request, false);
    const protected_request = (try protected_client.pollProtectedShortDatagramWithInstalledKeys(
        20,
        &server_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(protected_request);
    try require(protected_client.sentPacketCount(.application) == 1);
    try protected_server.processProtectedShortDatagramWithInstalledKeys(21, server_dcid.len, protected_request);

    var read_buf: [128]u8 = undefined;
    const request_len = (try protected_server.recvOnStream(stream_id, &read_buf)) orelse return error.UnexpectedState;
    try require(request_len == request.len);
    try require(std.mem.eql(u8, read_buf[0..request_len], request));
    try require(protected_server.nextPeerPacketNumber(.application) == 1);
    try require(protected_server.pendingAckLargest(.application) == 0);

    try protected_server.sendOnStream(stream_id, response, false);
    var response_datagram_bytes: usize = 0;
    var response_len: ?usize = null;
    for (0..4) |packet_index| {
        const protected_response = (try protected_server.pollProtectedShortDatagramWithInstalledKeys(
            22 + @as(i64, @intCast(packet_index)),
            &client_dcid,
        )) orelse return error.UnexpectedState;
        response_datagram_bytes += protected_response.len;
        try protected_client.processProtectedShortDatagramWithInstalledKeys(
            30 + @as(i64, @intCast(packet_index)),
            client_dcid.len,
            protected_response,
        );
        allocator.free(protected_response);
        if ((try protected_client.recvOnStream(stream_id, &read_buf))) |read_len| {
            response_len = read_len;
            break;
        }
    }
    try require(protected_server.sentPacketCount(.application) >= 1);
    const confirmed_response_len = response_len orelse return error.UnexpectedState;
    try require(confirmed_response_len == response.len);
    try require(std.mem.eql(u8, read_buf[0..confirmed_response_len], response));
    try require(protected_client.nextPeerPacketNumber(.application) >= 1);
    try require(protected_client.pendingAckLargest(.application) != null);

    return .{
        .request_bytes = request_len,
        .request_datagram_bytes = protected_request.len,
        .response_bytes = confirmed_response_len,
        .response_datagram_bytes = response_datagram_bytes,
    };
}

fn verifySocketBackedApplicationEchoDelivery() !SocketApplicationEcho {
    const client_local = try copyOpenSslSecret(true, 3, 1);
    const client_peer = try copyOpenSslSecret(true, 3, 0);
    const server_local = try copyOpenSslSecret(false, 3, 1);
    const server_peer = try copyOpenSslSecret(false, 3, 0);
    try require(std.mem.eql(u8, &client_local, &server_peer));
    try require(std.mem.eql(u8, &server_local, &client_peer));

    const allocator = std.heap.page_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_socket = try bindLoopbackUdp(io);
    defer client_socket.close(io);
    var server_socket = try bindLoopbackUdp(io);
    defer server_socket.close(io);

    const client_address = try udp4Address(client_socket.address);
    const server_address = try udp4Address(server_socket.address);
    try require(client_address.port != 0);
    try require(server_address.port != 0);
    try require(client_address.port != server_address.port);

    const client_dcid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const server_dcid = [_]u8{ 0xf1, 0xf2, 0xf3, 0xf4 };
    const client_handle: u64 = 61;
    const server_handle: u64 = 71;

    var client = try quicz.Connection.init(allocator, .client, .{
        .initial_max_data = 4096,
        .initial_max_stream_data = 1024,
        .initial_max_streams_bidi = 4,
        .max_datagram_size = 8192,
    });
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{
        .initial_max_data = 4096,
        .initial_max_stream_data = 1024,
        .initial_max_streams_bidi = 4,
        .max_datagram_size = 8192,
    });
    defer server.deinit();

    try client.installOneRttTrafficSecrets(.{
        .local = client_local,
        .peer = client_peer,
    });
    try server.installOneRttTrafficSecrets(.{
        .local = server_local,
        .peer = server_peer,
    });
    try client.confirmHandshake();
    try server.confirmHandshake();
    try server.validatePeerAddress();
    try require(client.hasOneRttProtectionKeys());
    try require(server.hasOneRttProtectionKeys());

    var client_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer client_lifecycle.deinit();
    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer server_lifecycle.deinit();

    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    const server_path = try udp4Tuple(server_socket.address, client_socket.address);
    try client_lifecycle.registerConnectionId(client_handle, &client_dcid, client_path, .{
        .active_migration_disabled = true,
    });
    try server_lifecycle.registerConnectionId(server_handle, &server_dcid, server_path, .{
        .active_migration_disabled = true,
    });

    const stream_id = try client.openStream();
    const request = "openssl udp one-rtt echo";
    try client.sendOnStream(stream_id, request, true);
    const request_datagram = (try client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        client_handle,
        &client,
        40,
        &server_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(request_datagram);
    try client_socket.send(io, &server_socket.address, request_datagram);

    var server_receive_buf: [1500]u8 = undefined;
    var client_receive_buf: [1500]u8 = undefined;
    const request_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const request_route = try server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        server_handle,
        &server,
        request_received.path,
        41,
        request_received.data,
    );
    try require(request_route.connection_id == server_handle);
    try require(std.mem.eql(u8, request_route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.pendingAckLargest(.application) == 0);

    var read_buf: [128]u8 = undefined;
    const request_len = (try server.recvOnStream(stream_id, &read_buf)) orelse return error.UnexpectedState;
    const request_payload = read_buf[0..request_len];
    try require(std.mem.eql(u8, request_payload, request));

    try server.sendOnStream(stream_id, request_payload, true);
    var echo_packet_count: usize = 0;
    var echo_datagram_bytes: usize = 0;
    var echo_len_or_null: ?usize = null;
    while (echo_packet_count < 4 and echo_len_or_null == null) : (echo_packet_count += 1) {
        const echo_datagram = (try server_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
            server_handle,
            &server,
            42 + @as(i64, @intCast(echo_packet_count)),
            &client_dcid,
        )) orelse return error.UnexpectedState;
        defer allocator.free(echo_datagram);
        echo_datagram_bytes += echo_datagram.len;
        try server_socket.send(io, &client_socket.address, echo_datagram);

        const echo_received = try receiveDatagram(io, &client_socket, &client_receive_buf);
        const echo_route = try client_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
            client_handle,
            &client,
            echo_received.path,
            50 + @as(i64, @intCast(echo_packet_count)),
            echo_received.data,
        );
        try require(echo_route.connection_id == client_handle);
        try require(std.mem.eql(u8, echo_route.destination_connection_id.asSlice(), &client_dcid));
        echo_len_or_null = try client.recvOnStream(stream_id, &read_buf);
    }

    const echo_len = echo_len_or_null orelse return error.UnexpectedState;
    const echo_payload = read_buf[0..echo_len];
    try require(std.mem.eql(u8, echo_payload, request_payload));
    try require(client.bytesInFlight(.application) == 0);
    try require(client.pendingAckLargest(.application) != null);

    const final_ack = (try client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        client_handle,
        &client,
        60,
        &server_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(final_ack);
    try client_socket.send(io, &server_socket.address, final_ack);

    const ack_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const ack_route = try server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        server_handle,
        &server,
        ack_received.path,
        61,
        ack_received.data,
    );
    try require(ack_route.connection_id == server_handle);
    try require(std.mem.eql(u8, ack_route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.bytesInFlight(.application) == 0);

    return .{
        .request_bytes = request_len,
        .request_datagram_bytes = request_datagram.len,
        .echo_bytes = echo_len,
        .echo_datagram_bytes = echo_datagram_bytes,
        .echo_packets = echo_packet_count,
    };
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var client_local_transport_parameter_buf: [512]u8 = undefined;
    var server_local_transport_parameter_buf: [512]u8 = undefined;
    const local_transport_parameters = try encodeTranscriptTransportParameters(
        allocator,
        &client_local_transport_parameter_buf,
        &server_local_transport_parameter_buf,
    );
    try require(c.quicz_openssl_pair_transcript_configure_transport_parameters(
        local_transport_parameters.client.ptr,
        local_transport_parameters.client.len,
        local_transport_parameters.server.ptr,
        local_transport_parameters.server.len,
    ) == 1);

    const result = c.quicz_openssl_pair_transcript_run();

    try require(result.initialized == 1);
    try require(result.client_done == 1);
    try require(result.server_done == 1);
    try require(result.client_last_ssl_error == 0);
    try require(result.server_last_ssl_error == 0);
    try require(result.client_alert_callbacks == 0);
    try require(result.server_alert_callbacks == 0);
    try require(result.client_yield_secret_callbacks >= 4);
    try require(result.server_yield_secret_callbacks >= 4);
    try require(result.client_got_transport_params_callbacks == 1);
    try require(result.server_got_transport_params_callbacks == 1);
    try require(result.client_peer_transport_parameters_len > 0);
    try require(result.server_peer_transport_parameters_len > 0);
    try require(result.client_keylog_callbacks > 0);
    try require(result.server_keylog_callbacks > 0);
    try require(result.client_keylog_bytes > @as(usize, @intCast(result.client_keylog_callbacks)));
    try require(result.server_keylog_bytes > @as(usize, @intCast(result.server_keylog_callbacks)));
    try require(result.client_send_callbacks > 0);
    try require(result.server_send_callbacks > 0);
    try require(result.client_recv_callbacks > 0);
    try require(result.server_recv_callbacks > 0);
    try require(result.client_release_callbacks > 0);
    try require(result.server_release_callbacks > 0);
    try require(result.client_read_level == 3);
    try require(result.server_read_level == 3);
    try require(result.client_write_level == 3);
    try require(result.server_write_level == 3);
    try require(result.client_out_level_bytes[1] == 0);
    try require(result.server_out_level_bytes[1] == 0);
    try require(result.client_out_level_bytes[0] > 0);
    try require(result.server_out_level_bytes[0] > 0);
    try require(result.server_out_level_bytes[2] > 0);
    try require(result.server_out_level_bytes[3] > 0);
    try require(result.error_queue_code == 0);

    var client_peer_transport_parameter_buf: [512]u8 = undefined;
    var server_peer_transport_parameter_buf: [512]u8 = undefined;
    const client_peer_transport_parameters = try copyOpenSslPeerTransportParameters(
        true,
        &client_peer_transport_parameter_buf,
    );
    const server_peer_transport_parameters = try copyOpenSslPeerTransportParameters(
        false,
        &server_peer_transport_parameter_buf,
    );
    try require(client_peer_transport_parameters.len == result.client_peer_transport_parameters_len);
    try require(server_peer_transport_parameters.len == result.server_peer_transport_parameters_len);
    try require(client_peer_transport_parameters.len == local_transport_parameters.server.len);
    try require(server_peer_transport_parameters.len == local_transport_parameters.client.len);
    try require(std.mem.eql(u8, client_peer_transport_parameters, local_transport_parameters.server));
    try require(std.mem.eql(u8, server_peer_transport_parameters, local_transport_parameters.client));
    var parsed_client_peer_transport_parameters = try quicz.transport_parameters.parse(
        client_peer_transport_parameters,
        allocator,
    );
    defer parsed_client_peer_transport_parameters.deinit(allocator);
    var parsed_server_peer_transport_parameters = try quicz.transport_parameters.parse(
        server_peer_transport_parameters,
        allocator,
    );
    defer parsed_server_peer_transport_parameters.deinit(allocator);
    const client_peer_original_dcid = parsed_client_peer_transport_parameters.original_destination_connection_id orelse
        return error.UnexpectedState;
    const client_peer_initial_scid = parsed_client_peer_transport_parameters.initial_source_connection_id orelse
        return error.UnexpectedState;
    const server_peer_initial_scid = parsed_server_peer_transport_parameters.initial_source_connection_id orelse
        return error.UnexpectedState;
    try require(parsed_server_peer_transport_parameters.original_destination_connection_id == null);
    try require(std.mem.eql(u8, client_peer_original_dcid, &transcript_original_dcid));
    try require(std.mem.eql(u8, client_peer_initial_scid, &transcript_server_scid));
    try require(std.mem.eql(u8, server_peer_initial_scid, &transcript_client_scid));
    try require(parsed_client_peer_transport_parameters.initial_max_data == 8192);
    try require(parsed_client_peer_transport_parameters.initial_max_stream_data_bidi_local == 2048);
    try require(parsed_client_peer_transport_parameters.initial_max_stream_data_bidi_remote == 2048);
    try require(parsed_client_peer_transport_parameters.initial_max_streams_bidi == 8);
    try require(parsed_server_peer_transport_parameters.initial_max_data == 8192);
    try require(parsed_server_peer_transport_parameters.initial_max_stream_data_bidi_local == 2048);
    try require(parsed_server_peer_transport_parameters.initial_max_stream_data_bidi_remote == 2048);
    try require(parsed_server_peer_transport_parameters.initial_max_streams_bidi == 8);

    var client_connection = try quicz.Connection.init(allocator, .client, .{
        .max_datagram_size = 8192,
    });
    defer client_connection.deinit();
    var server_connection = try quicz.Connection.init(allocator, .server, .{
        .max_datagram_size = 8192,
    });
    defer server_connection.deinit();

    const client_initial_bytes = try verifyCryptoDelivery(
        true,
        0,
        result.client_out_level_bytes[0],
        &server_connection,
    );
    const server_initial_bytes = try verifyCryptoDelivery(
        false,
        0,
        result.server_out_level_bytes[0],
        &client_connection,
    );
    const client_handshake_bytes = try verifyCryptoDelivery(
        true,
        2,
        result.client_out_level_bytes[2],
        &server_connection,
    );
    const server_handshake_bytes = try verifyCryptoDelivery(
        false,
        2,
        result.server_out_level_bytes[2],
        &client_connection,
    );
    const client_application_bytes = try verifyCryptoDelivery(
        true,
        3,
        result.client_out_level_bytes[3],
        &server_connection,
    );
    const server_application_bytes = try verifyCryptoDelivery(
        false,
        3,
        result.server_out_level_bytes[3],
        &client_connection,
    );
    const protected_initial = try verifyProtectedInitialCryptoDelivery(result.client_out_level_bytes[0]);
    const socket_initial = try verifySocketBackedInitialCryptoDelivery(
        result.client_out_level_bytes[0],
        result.server_out_level_bytes[0],
    );
    const manual_socket_transcript = try verifyManualSocketTranscriptDelivery();
    const protected_handshake = try verifyProtectedHandshakeCryptoDelivery(
        result.client_out_level_bytes[2],
        result.server_out_level_bytes[2],
    );
    const socket_handshake = try verifySocketBackedHandshakeCryptoDelivery(
        result.client_out_level_bytes[2],
        result.server_out_level_bytes[2],
    );
    const protected_application = try verifyProtectedApplicationStreamDelivery();
    const socket_echo = try verifySocketBackedApplicationEchoDelivery();

    std.debug.print(
        "[tls-openssl-pair-transcript] initialized={} client_done={} server_done={} client_send={} server_send={} client_recv={} server_recv={} client_release={} server_release={} client_yield={} server_yield={} client_tp_callbacks={} server_tp_callbacks={} peer_tp_bytes={}/{} client_levels={}/{}/{}/{} server_levels={}/{}/{}/{}",
        .{
            result.initialized,
            result.client_done,
            result.server_done,
            result.client_send_callbacks,
            result.server_send_callbacks,
            result.client_recv_callbacks,
            result.server_recv_callbacks,
            result.client_release_callbacks,
            result.server_release_callbacks,
            result.client_yield_secret_callbacks,
            result.server_yield_secret_callbacks,
            result.client_got_transport_params_callbacks,
            result.server_got_transport_params_callbacks,
            client_peer_transport_parameters.len,
            server_peer_transport_parameters.len,
            result.client_out_level_bytes[0],
            result.client_out_level_bytes[1],
            result.client_out_level_bytes[2],
            result.client_out_level_bytes[3],
            result.server_out_level_bytes[0],
            result.server_out_level_bytes[1],
            result.server_out_level_bytes[2],
            result.server_out_level_bytes[3],
        },
    );
    std.debug.print(
        " keylog={}/{}/{}/{}",
        .{
            result.client_keylog_callbacks,
            result.server_keylog_callbacks,
            result.client_keylog_bytes,
            result.server_keylog_bytes,
        },
    );
    std.debug.print(
        " quicz_delivery={}/{}/{}/{}/{}/{} protected_initial={}/{} socket_initial={}/{}/{}/{}/{}",
        .{
            client_initial_bytes,
            server_initial_bytes,
            client_handshake_bytes,
            server_handshake_bytes,
            client_application_bytes,
            server_application_bytes,
            protected_initial.crypto_bytes,
            protected_initial.datagram_bytes,
            socket_initial.client_crypto_bytes,
            socket_initial.client_datagram_bytes,
            socket_initial.server_crypto_bytes,
            socket_initial.server_datagram_bytes,
            socket_initial.client_ack_bytes,
        },
    );
    std.debug.print(
        " manual_socket_transcript={}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{} manual_socket_cleanup={}/{}/{}/{}/{}/{}/{}/{}",
        .{
            manual_socket_transcript.client_initial_crypto_bytes,
            manual_socket_transcript.client_initial_datagram_bytes,
            manual_socket_transcript.server_initial_crypto_bytes,
            manual_socket_transcript.server_initial_datagram_bytes,
            manual_socket_transcript.client_handshake_crypto_bytes,
            manual_socket_transcript.client_handshake_datagram_bytes,
            manual_socket_transcript.server_handshake_crypto_bytes,
            manual_socket_transcript.server_handshake_datagram_bytes,
            manual_socket_transcript.request_bytes,
            manual_socket_transcript.request_datagram_bytes,
            manual_socket_transcript.echo_bytes,
            manual_socket_transcript.echo_datagram_bytes,
            manual_socket_transcript.final_ack_bytes,
            manual_socket_transcript.close_datagram_bytes,
            manual_socket_transcript.server_close_error_code,
            manual_socket_transcript.client_handshake_space_discarded,
            manual_socket_transcript.server_handshake_space_discarded,
            manual_socket_transcript.client_handshake_keys_present,
            manual_socket_transcript.server_handshake_keys_present,
            manual_socket_transcript.client_routes_after_close_timeout,
            manual_socket_transcript.server_routes_after_drain_timeout,
        },
    );
    std.debug.print(
        " protected_handshake={}/{}/{}/{} socket_handshake={}/{}/{}/{}/{}/{} protected_application={}/{}/{}/{} socket_echo={}/{}/{}/{}/{}",
        .{
            protected_handshake.client_crypto_bytes,
            protected_handshake.client_datagram_bytes,
            protected_handshake.server_crypto_bytes,
            protected_handshake.server_datagram_bytes,
            socket_handshake.client_crypto_bytes,
            socket_handshake.client_datagram_bytes,
            socket_handshake.client_ack_bytes,
            socket_handshake.server_crypto_bytes,
            socket_handshake.server_datagram_bytes,
            socket_handshake.server_ack_bytes,
            protected_application.request_bytes,
            protected_application.request_datagram_bytes,
            protected_application.response_bytes,
            protected_application.response_datagram_bytes,
            socket_echo.request_bytes,
            socket_echo.request_datagram_bytes,
            socket_echo.echo_bytes,
            socket_echo.echo_datagram_bytes,
            socket_echo.echo_packets,
        },
    );
    std.debug.print(
        " iterations={} alerts={}/{} errors={}/{}\n",
        .{
            result.drive_iterations,
            result.client_alert_callbacks,
            result.server_alert_callbacks,
            result.client_last_ssl_error,
            result.server_last_ssl_error,
        },
    );
}
