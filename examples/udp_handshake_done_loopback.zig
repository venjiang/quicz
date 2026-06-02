const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

const ReceivedDatagram = struct {
    data: []const u8,
    path: quicz.endpoint.Udp4Tuple,
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

    try client.installHandshakeTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });
    try server.installHandshakeTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try client.installOneRttTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });
    try server.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try server.validatePeerAddress();
    try require(client.hasHandshakeProtectionKeys());
    try require(server.hasHandshakeProtectionKeys());
    try require(client.hasOneRttProtectionKeys());
    try require(server.hasOneRttProtectionKeys());
    try require(!client.handshakeConfirmed());

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

    try server.sendHandshakeDone();
    try require(server.handshakeConfirmed());
    try require(server.handshakeState() == .confirmed);
    try require(server.connectionState() == .active);
    try require(server.packetNumberSpaceDiscarded(.handshake));
    try require(!server.hasHandshakeProtectionKeys());
    const server_handshake_keys_discarded = !server.hasHandshakeProtectionKeys();

    const done_datagram = (try server_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        server_handle,
        &server,
        0,
        &client_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(done_datagram);
    try require(server.sentPacketCount(.application) == 1);
    try server_socket.send(io, &client_socket.address, done_datagram);

    var server_receive_buf: [1500]u8 = undefined;
    var client_receive_buf: [1500]u8 = undefined;
    const done_received = try receiveDatagram(io, &client_socket, &client_receive_buf);
    const done_route = try client_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        client_handle,
        &client,
        done_received.path,
        1,
        done_received.data,
    );
    try require(done_route.connection_id == client_handle);
    try require(std.mem.eql(u8, done_route.destination_connection_id.asSlice(), &client_dcid));
    try require(client.handshakeConfirmed());
    try require(client.handshakeState() == .confirmed);
    try require(client.connectionState() == .active);
    try require(client.packetNumberSpaceDiscarded(.handshake));
    try require(!client.hasHandshakeProtectionKeys());
    try require(client.pendingAckLargest(.application) == 0);
    const client_ack_largest = client.pendingAckLargest(.application).?;

    const ack_datagram = (try client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        client_handle,
        &client,
        2,
        &server_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(ack_datagram);
    const client_ack_cleared = client.pendingAckLargest(.application) == null;
    try require(client_ack_cleared);
    try client_socket.send(io, &server_socket.address, ack_datagram);

    const ack_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const ack_route = try server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        server_handle,
        &server,
        ack_received.path,
        3,
        ack_received.data,
    );
    try require(ack_route.connection_id == server_handle);
    try require(std.mem.eql(u8, ack_route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.bytesInFlight(.application) == 0);
    try require(server_lifecycle.recoveryTimerCount() == 0);

    std.debug.print("[udp-handshake-done] client_port={} server_port={} done_bytes={} ack_bytes={} server_confirmed={} server_handshake_state={s} server_connection_state={s} server_handshake_keys_discarded={} client_confirmed={} client_handshake_state={s} client_connection_state={s} client_handshake_keys={} client_ack_largest={} client_ack_cleared={} server_inflight={} server_timers={}\n", .{
        client_local.port,
        server_local.port,
        done_datagram.len,
        ack_datagram.len,
        server.handshakeConfirmed(),
        @tagName(server.handshakeState()),
        @tagName(server.connectionState()),
        server_handshake_keys_discarded,
        client.handshakeConfirmed(),
        @tagName(client.handshakeState()),
        @tagName(client.connectionState()),
        client.hasHandshakeProtectionKeys(),
        client_ack_largest,
        client_ack_cleared,
        server.bytesInFlight(.application),
        server_lifecycle.recoveryTimerCount(),
    });
}
