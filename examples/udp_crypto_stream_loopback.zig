const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

const ReceivedDatagram = struct {
    data: []const u8,
    path: quicz.endpoint.Udp4Tuple,
};

const ScriptedCryptoBackend = struct {
    inbound: [128]u8 = undefined,
    inbound_len: usize = 0,
    expected_inbound: []const u8,
    outbound: []const u8,
    outbound_offset: usize = 0,
    wait_for_expected_inbound: bool = false,
    local_transport_parameters: [256]u8 = undefined,
    local_transport_parameters_len: usize = 0,
    peer_transport_parameters: []const u8,
    peer_transport_parameters_sent: bool = false,
    handshake_traffic_secrets: quicz.HandshakeTrafficSecrets,
    handshake_traffic_secrets_sent: bool = false,

    fn backend(self: *ScriptedCryptoBackend) quicz.CryptoBackend {
        return .{
            .context = self,
            .receive = receive,
            .pull = pull,
            .set_local_transport_parameters = setLocalTransportParameters,
            .pull_peer_transport_parameters = pullPeerTransportParameters,
            .pull_handshake_traffic_secrets = pullHandshakeTrafficSecrets,
        };
    }

    fn inboundMatches(self: *const ScriptedCryptoBackend) bool {
        return std.mem.eql(u8, self.inbound[0..self.inbound_len], self.expected_inbound);
    }

    fn receive(context: *anyopaque, space: quicz.PacketNumberSpace, data: []const u8) quicz.Error!void {
        const self: *ScriptedCryptoBackend = @ptrCast(@alignCast(context));
        if (space != .handshake) return error.CryptoError;
        if (self.inbound.len - self.inbound_len < data.len) return error.BufferTooSmall;
        @memcpy(self.inbound[self.inbound_len..][0..data.len], data);
        self.inbound_len += data.len;
    }

    fn pull(context: *anyopaque, space: quicz.PacketNumberSpace, out_buf: []u8) quicz.Error!?[]const u8 {
        const self: *ScriptedCryptoBackend = @ptrCast(@alignCast(context));
        if (space != .handshake) return null;
        if (self.wait_for_expected_inbound and !self.inboundMatches()) return null;
        if (self.outbound_offset >= self.outbound.len) return null;
        const n = @min(out_buf.len, self.outbound.len - self.outbound_offset);
        @memcpy(out_buf[0..n], self.outbound[self.outbound_offset..][0..n]);
        self.outbound_offset += n;
        return out_buf[0..n];
    }

    fn setLocalTransportParameters(context: *anyopaque, data: []const u8) quicz.Error!void {
        const self: *ScriptedCryptoBackend = @ptrCast(@alignCast(context));
        if (data.len > self.local_transport_parameters.len) return error.BufferTooSmall;
        @memcpy(self.local_transport_parameters[0..data.len], data);
        self.local_transport_parameters_len = data.len;
    }

    fn pullPeerTransportParameters(context: *anyopaque, out_buf: []u8) quicz.Error!?[]const u8 {
        const self: *ScriptedCryptoBackend = @ptrCast(@alignCast(context));
        if (self.peer_transport_parameters_sent) return null;
        if (out_buf.len < self.peer_transport_parameters.len) return error.BufferTooSmall;
        @memcpy(out_buf[0..self.peer_transport_parameters.len], self.peer_transport_parameters);
        self.peer_transport_parameters_sent = true;
        return out_buf[0..self.peer_transport_parameters.len];
    }

    fn pullHandshakeTrafficSecrets(context: *anyopaque) quicz.Error!?quicz.HandshakeTrafficSecrets {
        const self: *ScriptedCryptoBackend = @ptrCast(@alignCast(context));
        if (self.handshake_traffic_secrets_sent) return null;
        self.handshake_traffic_secrets_sent = true;
        return self.handshake_traffic_secrets;
    }
};

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

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const client_handle: u64 = 41;
    const server_handle: u64 = 51;
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try quicz.Connection.init(allocator, .client, .{
        .initial_max_data = 12_345,
        .max_datagram_size = 1300,
        .ack_delay_exponent = 4,
        .max_ack_delay_ms = 44,
    });
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{
        .initial_max_data = 54_321,
        .max_datagram_size = 1400,
        .ack_delay_exponent = 5,
        .max_ack_delay_ms = 33,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    var client_peer_transport_parameters_buf: [256]u8 = undefined;
    const client_peer_transport_parameters = try server.encodeLocalTransportParameters(
        &client_peer_transport_parameters_buf,
    );
    var server_peer_transport_parameters_buf: [256]u8 = undefined;
    const server_peer_transport_parameters = try client.encodeLocalTransportParameters(
        &server_peer_transport_parameters_buf,
    );

    var client_backend = ScriptedCryptoBackend{
        .expected_inbound = "server tls flight",
        .outbound = "client tls flight",
        .peer_transport_parameters = client_peer_transport_parameters,
        .handshake_traffic_secrets = .{
            .local = secrets.client.secret,
            .peer = secrets.server.secret,
        },
    };
    var server_backend = ScriptedCryptoBackend{
        .expected_inbound = "client tls flight",
        .outbound = "server tls flight",
        .wait_for_expected_inbound = true,
        .peer_transport_parameters = server_peer_transport_parameters,
        .handshake_traffic_secrets = .{
            .local = secrets.server.secret,
            .peer = secrets.client.secret,
        },
    };
    var scratch: [256]u8 = undefined;
    const client_setup = try client.driveCryptoBackendInSpace(.handshake, client_backend.backend(), &scratch);
    const server_setup = try server.driveCryptoBackendInSpace(.handshake, server_backend.backend(), &scratch);

    try require(client_setup.handshake_keys_installed);
    try require(client_setup.outbound_bytes == "client tls flight".len);
    try require(client_setup.peer_transport_parameters_applied);
    try require(client_backend.local_transport_parameters_len > 0);
    try require(server_setup.handshake_keys_installed);
    try require(server_setup.outbound_bytes == 0);
    try require(server_setup.peer_transport_parameters_applied);
    try require(server_backend.local_transport_parameters_len > 0);
    try require(client.hasHandshakeProtectionKeys());
    try require(server.hasHandshakeProtectionKeys());
    try require(client.peer_max_data == 54_321);
    try require(server.peer_max_data == 12_345);
    try require(client.peer_ack_delay_exponent == 5);
    try require(server.peer_ack_delay_exponent == 4);
    try require(client.peer_max_udp_payload_size == 1400);
    try require(server.peer_max_udp_payload_size == 1300);

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

    const client_flight = (try client_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        client_handle,
        &client,
        0,
        &server_dcid,
        &client_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_flight);
    try client_socket.send(io, &server_socket.address, client_flight);

    var server_receive_buf: [1500]u8 = undefined;
    var client_receive_buf: [1500]u8 = undefined;
    const client_flight_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const server_client_flight_route = try server_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        server_handle,
        &server,
        client_flight_received.path,
        1,
        client_flight_received.data,
    );
    try require(server_client_flight_route.connection_id == server_handle);
    try require(std.mem.eql(u8, server_client_flight_route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.pendingAckLargest(.handshake) == 0);

    const server_progress = try server.driveCryptoBackendInSpace(.handshake, server_backend.backend(), &scratch);
    try require(server_progress.inbound_bytes == "client tls flight".len);
    try require(server_progress.outbound_bytes == "server tls flight".len);
    try require(server_backend.inboundMatches());

    const server_flight = (try server_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        server_handle,
        &server,
        2,
        &client_dcid,
        &server_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_flight);
    try require(server.pendingAckLargest(.handshake) == 0);
    try server_socket.send(io, &client_socket.address, server_flight);

    const server_ack_for_client_flight = (try server_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        server_handle,
        &server,
        3,
        &client_dcid,
        &server_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_ack_for_client_flight);
    try require(server.pendingAckLargest(.handshake) == null);
    try server_socket.send(io, &client_socket.address, server_ack_for_client_flight);

    const server_flight_received = try receiveDatagram(io, &client_socket, &client_receive_buf);
    const client_server_flight_route = try client_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        client_handle,
        &client,
        server_flight_received.path,
        4,
        server_flight_received.data,
    );
    try require(client_server_flight_route.connection_id == client_handle);
    try require(std.mem.eql(u8, client_server_flight_route.destination_connection_id.asSlice(), &client_dcid));
    try require(client.pendingAckLargest(.handshake) == 0);

    const server_ack_received = try receiveDatagram(io, &client_socket, &client_receive_buf);
    const client_ack_for_client_flight_route = try client_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        client_handle,
        &client,
        server_ack_received.path,
        5,
        server_ack_received.data,
    );
    try require(client_ack_for_client_flight_route.connection_id == client_handle);
    try require(std.mem.eql(u8, client_ack_for_client_flight_route.destination_connection_id.asSlice(), &client_dcid));
    try require(client.bytesInFlight(.handshake) == 0);

    const client_progress = try client.driveCryptoBackendInSpace(.handshake, client_backend.backend(), &scratch);
    try require(client_progress.inbound_bytes == "server tls flight".len);
    try require(client_progress.outbound_bytes == 0);
    try require(client_backend.inboundMatches());

    const client_ack = (try client_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        client_handle,
        &client,
        6,
        &server_dcid,
        &client_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_ack);
    try require(client.pendingAckLargest(.handshake) == null);
    try client_socket.send(io, &server_socket.address, client_ack);

    const client_ack_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const server_ack_route = try server_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        server_handle,
        &server,
        client_ack_received.path,
        7,
        client_ack_received.data,
    );
    try require(server_ack_route.connection_id == server_handle);
    try require(std.mem.eql(u8, server_ack_route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.bytesInFlight(.handshake) == 0);
    try require(client_lifecycle.recoveryTimerCount() == 0);
    try require(server_lifecycle.recoveryTimerCount() == 0);

    std.debug.print("[udp-crypto-stream] client_port={} server_port={} client_flight_bytes={} server_flight_bytes={} server_ack_bytes={} client_ack_bytes={} client_inbound={} server_inbound={} client_peer_max_data={} server_peer_max_data={} client_tps={} server_tps={} timers={}/{}\n", .{
        client_local.port,
        server_local.port,
        client_flight.len,
        server_flight.len,
        server_ack_for_client_flight.len,
        client_ack.len,
        client_progress.inbound_bytes,
        server_progress.inbound_bytes,
        client.peer_max_data,
        server.peer_max_data,
        client_backend.local_transport_parameters_len,
        server_backend.local_transport_parameters_len,
        client_lifecycle.recoveryTimerCount(),
        server_lifecycle.recoveryTimerCount(),
    });
}
