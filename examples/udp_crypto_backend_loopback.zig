const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

const ReceivedDatagram = struct {
    data: []const u8,
    path: quicz.endpoint.Udp4Tuple,
};

const OneRttBackend = struct {
    secrets: quicz.OneRttTrafficSecrets,
    sent: bool = false,
    confirmed: bool = true,

    fn backend(self: *OneRttBackend) quicz.CryptoBackend {
        return .{
            .context = self,
            .receive = receive,
            .pull = pull,
            .pull_1rtt_traffic_secrets = pullOneRttTrafficSecrets,
            .handshake_confirmed = handshakeConfirmed,
        };
    }

    fn receive(_: *anyopaque, _: quicz.PacketNumberSpace, _: []const u8) quicz.Error!void {}

    fn pull(_: *anyopaque, _: quicz.PacketNumberSpace, _: []u8) quicz.Error!?[]const u8 {
        return null;
    }

    fn pullOneRttTrafficSecrets(context: *anyopaque) quicz.Error!?quicz.OneRttTrafficSecrets {
        const self: *OneRttBackend = @ptrCast(@alignCast(context));
        if (self.sent) return null;
        self.sent = true;
        return self.secrets;
    }

    fn handshakeConfirmed(context: *anyopaque) bool {
        const self: *OneRttBackend = @ptrCast(@alignCast(context));
        return self.confirmed;
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

    var client = try quicz.Connection.init(allocator, .client, .{});
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    var client_backend = OneRttBackend{ .secrets = .{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    } };
    var server_backend = OneRttBackend{ .secrets = .{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    } };
    var scratch: [8]u8 = undefined;
    const client_progress = try client.driveCryptoBackendInSpace(.handshake, client_backend.backend(), &scratch);
    const server_progress = try server.driveCryptoBackendInSpace(.handshake, server_backend.backend(), &scratch);
    try require(client_progress.one_rtt_keys_installed);
    try require(server_progress.one_rtt_keys_installed);
    try require(client_progress.handshake_confirmed);
    try require(server_progress.handshake_confirmed);
    try require(client.handshakeConfirmed());
    try require(server.handshakeConfirmed());
    try require(client.hasOneRttProtectionKeys());
    try require(server.hasOneRttProtectionKeys());
    try require(client.packetNumberSpaceDiscarded(.handshake));
    try require(server.packetNumberSpaceDiscarded(.handshake));

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
    try client.sendOnStream(stream_id, "udp backend one rtt", true);
    const stream_datagram = (try client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        client_handle,
        &client,
        0,
        &server_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(stream_datagram);
    try require(client_lifecycle.recoveryTimerCount() == 1);
    const client_stream_timer = client_lifecycle.earliestRecoveryDeadline() orelse return error.UnexpectedState;
    try require(client_stream_timer.connection_id == client_handle);
    try require(client_stream_timer.timer.space == .application);
    try require(client_stream_timer.timer.kind == .pto);
    try client_socket.send(io, &server_socket.address, stream_datagram);

    var server_receive_buf: [1500]u8 = undefined;
    var client_receive_buf: [1500]u8 = undefined;
    const stream_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const stream_route = try server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        server_handle,
        &server,
        stream_received.path,
        1,
        stream_received.data,
    );
    try require(stream_route.connection_id == server_handle);
    try require(std.mem.eql(u8, stream_route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.pendingAckLargest(.application) == 0);

    var stream_buf: [64]u8 = undefined;
    const stream_len = (try server.recvOnStream(stream_id, &stream_buf)) orelse return error.UnexpectedState;
    const stream_payload = stream_buf[0..stream_len];
    try require(std.mem.eql(u8, stream_payload, "udp backend one rtt"));

    const client_pto_result = try client_lifecycle.serviceRecoveryTimerAndPollProtectedShortDatagramWithInstalledKeys(
        client_handle,
        &client,
        client_stream_timer.timer.deadline_millis,
        &server_dcid,
    );
    const client_pto_serviced = client_pto_result.serviced orelse return error.UnexpectedState;
    try require(client_pto_serviced.connection_id == client_handle);
    try require(client_pto_serviced.timer.space == .application);
    try require(client_pto_serviced.timer.kind == .pto);
    const client_pto_probe = client_pto_result.datagram orelse return error.UnexpectedState;
    defer allocator.free(client_pto_probe);
    try require(client.sentPacketCount(.application) == 2);
    try require(client_lifecycle.recoveryTimerCount() == 1);
    try client_socket.send(io, &server_socket.address, client_pto_probe);

    const pto_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const pto_route = try server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        server_handle,
        &server,
        pto_received.path,
        client_stream_timer.timer.deadline_millis + 1,
        pto_received.data,
    );
    try require(pto_route.connection_id == server_handle);
    try require(std.mem.eql(u8, pto_route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.pendingAckLargest(.application) == 1);
    try require((try server.recvOnStream(stream_id, &stream_buf)) == null);

    try server.sendOnStream(stream_id, stream_payload, true);
    var echo_datagram_count: usize = 0;
    var echo_bytes: usize = 0;
    var echo_len_or_null: ?usize = null;
    while (echo_datagram_count < 3 and echo_len_or_null == null) : (echo_datagram_count += 1) {
        const echo_datagram = (try server_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
            server_handle,
            &server,
            2 + @as(i64, @intCast(echo_datagram_count)),
            &client_dcid,
        )) orelse return error.UnexpectedState;
        defer allocator.free(echo_datagram);
        echo_bytes += echo_datagram.len;
        try server_socket.send(io, &client_socket.address, echo_datagram);

        const echo_received = try receiveDatagram(io, &client_socket, &client_receive_buf);
        const echo_route = try client_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
            client_handle,
            &client,
            echo_received.path,
            5 + @as(i64, @intCast(echo_datagram_count)),
            echo_received.data,
        );
        try require(echo_route.connection_id == client_handle);
        try require(std.mem.eql(u8, echo_route.destination_connection_id.asSlice(), &client_dcid));
        echo_len_or_null = try client.recvOnStream(stream_id, &stream_buf);
    }
    try require(client.bytesInFlight(.application) == 0);
    const client_inflight_after_echo = client.bytesInFlight(.application);

    const echo_len = echo_len_or_null orelse return error.UnexpectedState;
    const echo_payload = stream_buf[0..echo_len];
    try require(std.mem.eql(u8, echo_payload, stream_payload));
    const echo_ack_largest = client.pendingAckLargest(.application) orelse return error.UnexpectedState;
    try server_lifecycle.armRecoveryTimerFromConnection(server_handle, &server);
    const server_echo_timer = server_lifecycle.earliestRecoveryDeadline() orelse return error.UnexpectedState;
    try require(server_echo_timer.connection_id == server_handle);
    try require(server_echo_timer.timer.space == .application);
    try require(server_echo_timer.timer.kind == .pto);
    const server_echo_deadline = server_echo_timer.timer.deadline_millis;

    const server_pto_result = try server_lifecycle.serviceRecoveryTimerAndPollProtectedShortDatagramWithInstalledKeys(
        server_handle,
        &server,
        server_echo_deadline,
        &client_dcid,
    );
    const server_pto_serviced = server_pto_result.serviced orelse return error.UnexpectedState;
    try require(server_pto_serviced.connection_id == server_handle);
    try require(server_pto_serviced.timer.space == .application);
    try require(server_pto_serviced.timer.kind == .pto);
    const server_pto_probe = server_pto_result.datagram orelse return error.UnexpectedState;
    defer allocator.free(server_pto_probe);
    try require(server_lifecycle.recoveryTimerCount() == 1);
    try server_socket.send(io, &client_socket.address, server_pto_probe);

    const server_pto_received = try receiveDatagram(io, &client_socket, &client_receive_buf);
    const server_pto_route = try client_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        client_handle,
        &client,
        server_pto_received.path,
        server_echo_deadline + 1,
        server_pto_received.data,
    );
    try require(server_pto_route.connection_id == client_handle);
    try require(std.mem.eql(u8, server_pto_route.destination_connection_id.asSlice(), &client_dcid));
    const echo_pto_ack_largest = client.pendingAckLargest(.application).?;
    try require(echo_pto_ack_largest > echo_ack_largest);
    try require((try client.recvOnStream(stream_id, &stream_buf)) == null);

    const final_ack = (try client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        client_handle,
        &client,
        8,
        &server_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(final_ack);
    try require(client.pendingAckLargest(.application) == null);
    try client_socket.send(io, &server_socket.address, final_ack);

    const final_ack_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const final_ack_route = try server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        server_handle,
        &server,
        final_ack_received.path,
        9,
        final_ack_received.data,
    );
    try require(final_ack_route.connection_id == server_handle);
    try require(std.mem.eql(u8, final_ack_route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.bytesInFlight(.application) == 0);
    try require(client_lifecycle.recoveryTimerCount() == 1);
    try require(server_lifecycle.recoveryTimerCount() == 0);

    std.debug.print("[udp-crypto-backend] client_port={} server_port={} stream_bytes={} client_timer_deadline={} client_pto_bytes={} client_pto_route={} echo_packets={} echo_bytes={} echo_timer_deadline={} server_pto_bytes={} server_pto_route={} echo_ack_largest={} echo_pto_ack_largest={} final_ack_bytes={} received=\"{s}\" echo=\"{s}\" client_backend_keys={} server_backend_keys={} confirmed={} client_inflight_after_echo={} server_inflight={} client_timers={} server_timers={}\n", .{
        client_local.port,
        server_local.port,
        stream_datagram.len,
        client_stream_timer.timer.deadline_millis,
        client_pto_probe.len,
        pto_route.connection_id,
        echo_datagram_count,
        echo_bytes,
        server_echo_deadline,
        server_pto_probe.len,
        server_pto_route.connection_id,
        echo_ack_largest,
        echo_pto_ack_largest,
        final_ack.len,
        stream_payload,
        echo_payload,
        client_progress.one_rtt_keys_installed,
        server_progress.one_rtt_keys_installed,
        client.handshakeConfirmed() and server.handshakeConfirmed(),
        client_inflight_after_echo,
        server.bytesInFlight(.application),
        client_lifecycle.recoveryTimerCount(),
        server_lifecycle.recoveryTimerCount(),
    });
}
