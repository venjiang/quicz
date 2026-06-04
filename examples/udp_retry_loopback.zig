const std = @import("std");
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

fn fixedWriter(buffer: []u8) FixedWriter {
    return .{ .buffer = buffer };
}

fn require(condition: bool) ExampleError!void {
    if (!condition) return error.UnexpectedState;
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

fn buildInitialDatagram(
    out: []u8,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
    payload: []const u8,
) ![]const u8 {
    var writer = fixedWriter(out);
    try quicz.packet.encodeLongPacket(writer.writer(), .{
        .header = .{
            .version = .v1,
            .dcid = dcid,
            .scid = scid,
            .packet_type = .initial,
            .token = token,
            .packet_number = 0,
            .payload_length = 0,
        },
        .payload = payload,
    });
    return writer.getWritten();
}

fn readCryptoRequired(
    conn: *quicz.Connection,
    space: quicz.PacketNumberSpace,
    out: []u8,
) ![]const u8 {
    const len = (try conn.recvCryptoInSpace(space, out)) orelse return error.UnexpectedState;
    return out[0..len];
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_socket = try bindLoopbackUdp(io);
    defer client_socket.close(io);
    var server_socket = try bindLoopbackUdp(io);
    defer server_socket.close(io);

    const client_local = try udp4Address(client_socket.address);
    const server_local = try udp4Address(server_socket.address);
    try require(client_local.port != 0);
    try require(server_local.port != 0);
    try require(client_local.port != server_local.port);

    var client = try quicz.Connection.init(allocator, .client, .{});
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{});
    defer server.deinit();

    var client_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer client_lifecycle.deinit();
    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer server_lifecycle.deinit();

    const token_secret: quicz.address_validation_token.Secret = [_]u8{0x5d} ** quicz.address_validation_token.secret_len;
    const token_nonce: quicz.address_validation_token.Nonce = [_]u8{0xa7} ** quicz.address_validation_token.nonce_len;
    var token_policy = quicz.endpoint.AddressValidationPolicy.init(allocator, token_secret, .{
        .max_previous_secrets = 1,
        .max_replay_entries = 8,
    });
    defer token_policy.deinit();

    const supported_versions = [_]quicz.packet.Version{ .v1, .v2 };
    const reset_prefix = [_]u8{ 0x40, 0x33, 0x22, 0x11, 0xaa, 0xbb, 0xcc, 0xdd };
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_initial_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const retry_scid = [_]u8{ 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const connection_handle: u64 = 61;

    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    _ = try client_lifecycle.registerClientInitialSourceConnectionId(connection_handle, &client_initial_scid, client_path, .{
        .active_migration_disabled = true,
    });

    var first_initial_raw: [128]u8 = undefined;
    const first_initial = try buildInitialDatagram(
        &first_initial_raw,
        &original_dcid,
        &client_initial_scid,
        &.{},
        &[_]u8{0x01},
    );
    try client_socket.send(io, &server_socket.address, first_initial);

    var server_receive_buf: [1500]u8 = undefined;
    var client_receive_buf: [1500]u8 = undefined;
    const first_received = try server_socket.receiveTimeout(io, &server_receive_buf, receiveTimeout());
    const first_path = try udp4Tuple(server_socket.address, first_received.from);

    var action_buf: [256]u8 = undefined;
    const first_action = try server_lifecycle.handleDatagramWithVersionNegotiation(
        &action_buf,
        first_path,
        first_received.data,
        &reset_prefix,
        &supported_versions,
    );
    const first_accept = switch (first_action) {
        .accept_initial => |accept| accept,
        else => return error.UnexpectedState,
    };
    try require(first_accept.version == .v1);
    try require(first_accept.token.len == 0);
    try require(std.mem.eql(u8, first_accept.original_destination_connection_id, &original_dcid));
    try require(std.mem.eql(u8, first_accept.source_connection_id, &client_initial_scid));

    const retry_token = try token_policy.issueTokenForPath(
        allocator,
        .retry,
        0,
        60_000,
        first_path,
        token_nonce,
    );
    defer allocator.free(retry_token);

    const retry_datagram = try server.issueRetryDatagram(
        1,
        first_accept.original_destination_connection_id,
        first_accept.source_connection_id,
        &retry_scid,
        retry_token,
    );
    defer allocator.free(retry_datagram);
    try require(server.pendingRetryTokenCount() == 1);

    try server_lifecycle.registerConnectionId(connection_handle, first_accept.original_destination_connection_id, first_path, .{
        .active_migration_disabled = true,
    });
    const switched = try server_lifecycle.switchInitialDestinationConnectionIdAfterRetry(
        first_accept.original_destination_connection_id,
        &retry_scid,
        first_path,
    );
    try require(switched.connection_id == connection_handle);
    try require(std.mem.eql(u8, switched.destination_connection_id.asSlice(), &retry_scid));

    try server_socket.send(io, &first_received.from, retry_datagram);
    const retry_received = try client_socket.receiveTimeout(io, &client_receive_buf, receiveTimeout());
    const retry_path = try udp4Tuple(client_socket.address, retry_received.from);
    const retry_route = try client_lifecycle.routeDatagram(retry_path, retry_received.data);
    try require(retry_route.connection_id == connection_handle);
    try require(std.mem.eql(u8, retry_route.destination_connection_id.asSlice(), &client_initial_scid));

    try client.processRetryDatagram(2, &original_dcid, retry_received.data);
    try require(std.mem.eql(u8, client.latestRetryToken() orelse return error.UnexpectedState, retry_token));
    try require(std.mem.eql(u8, client.retrySourceConnectionId() orelse return error.UnexpectedState, &retry_scid));

    const retry_secrets = try quicz.protection.deriveInitialSecrets(.v1, &retry_scid);
    try client.sendCryptoInSpace(.initial, "client after retry");
    const retry_initial = (try client.pollInitialProtectedDatagram(
        3,
        &retry_scid,
        &client_initial_scid,
        &.{},
        retry_secrets.client,
    )) orelse return error.UnexpectedState;
    defer allocator.free(retry_initial);
    try require(retry_initial.len >= 1200);
    try client_socket.send(io, &server_socket.address, retry_initial);

    const retry_initial_received = try server_socket.receiveTimeout(io, &server_receive_buf, receiveTimeout());
    const retry_initial_path = try udp4Tuple(server_socket.address, retry_initial_received.from);
    const retry_initial_result = try server_lifecycle.processRetryValidatedProtectedInitialDatagram(
        &token_policy,
        connection_handle,
        &server,
        4,
        retry_initial_path,
        retry_initial_received.data,
        &supported_versions,
    );
    const retry_accept = retry_initial_result.initial_accept;
    try require(retry_accept.version == .v1);
    try require(std.mem.eql(u8, retry_accept.original_destination_connection_id, &retry_scid));
    try require(std.mem.eql(u8, retry_accept.source_connection_id, &client_initial_scid));
    try require(std.mem.eql(u8, retry_accept.token, retry_token));
    try require(retry_initial_result.route.connection_id == connection_handle);
    try require(retry_initial_result.token_validation.validation.originating_version == .v1);
    try require(server.peerAddressValidated());
    try require(server.pendingRetryTokenCount() == 0);

    var replay_rejected = false;
    if (token_policy.validateTokenForPath(.retry, 5, retry_initial_path, retry_accept.token)) |_| {
        return error.UnexpectedState;
    } else |err| {
        switch (err) {
            error.TokenReplay => replay_rejected = true,
            else => return err,
        }
    }
    try require(replay_rejected);

    try require(std.mem.eql(u8, retry_initial_result.route.destination_connection_id.asSlice(), &retry_scid));
    var server_crypto_buf: [64]u8 = undefined;
    const server_received_crypto = try readCryptoRequired(&server, .initial, &server_crypto_buf);
    try require(std.mem.eql(u8, server_received_crypto, "client after retry"));

    try server_lifecycle.registerConnectionId(connection_handle, &server_scid, retry_initial_path, .{
        .sequence_number = 0,
        .active_migration_disabled = true,
    });
    try server.sendCryptoInSpace(.initial, "server accepted retry");
    const server_initial = (try server.pollInitialProtectedDatagram(
        7,
        &client_initial_scid,
        &server_scid,
        &.{},
        retry_secrets.server,
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_initial);
    try server_socket.send(io, &retry_initial_received.from, server_initial);

    const server_initial_received = try client_socket.receiveTimeout(io, &client_receive_buf, receiveTimeout());
    const server_initial_path = try udp4Tuple(client_socket.address, server_initial_received.from);
    const client_initial_route = try client_lifecycle.processRoutedProtectedInitialDatagram(
        connection_handle,
        &client,
        server_initial_path,
        8,
        &retry_scid,
        server_initial_received.data,
    );
    try require(client_initial_route.connection_id == connection_handle);
    try require(std.mem.eql(u8, client_initial_route.destination_connection_id.asSlice(), &client_initial_scid));
    var client_crypto_buf: [64]u8 = undefined;
    const client_received_crypto = try readCryptoRequired(&client, .initial, &client_crypto_buf);
    try require(std.mem.eql(u8, client_received_crypto, "server accepted retry"));

    var server_transport_parameter_buf: [256]u8 = undefined;
    const server_transport_parameter_bytes = try server.encodeLocalTransportParameters(&server_transport_parameter_buf);
    try client.applyPeerTransportParameterBytes(server_transport_parameter_bytes);
    var client_transport_parameter_buf: [256]u8 = undefined;
    const client_transport_parameter_bytes = try client.encodeLocalTransportParameters(&client_transport_parameter_buf);
    try server.applyPeerTransportParameterBytes(client_transport_parameter_bytes);

    std.debug.print("[udp-retry] client_port={} server_port={} first_bytes={} retry_bytes={} retry_initial_bytes={} server_initial_bytes={} switched_route={} token_len={} replay_rejected={} address_validated={} server_tp_bytes={} client_tp_bytes={} client_tp_retry=true\n", .{
        client_local.port,
        server_local.port,
        first_initial.len,
        retry_datagram.len,
        retry_initial.len,
        server_initial.len,
        retry_initial_result.route.connection_id,
        retry_accept.token.len,
        replay_rejected,
        server.peerAddressValidated(),
        server_transport_parameter_bytes.len,
        client_transport_parameter_bytes.len,
    });
}
