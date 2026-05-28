const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

const ReceivedRoute = struct {
    data: []const u8,
    route: quicz.endpoint.RouteResult,
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

fn receiveRoute(
    io: std.Io,
    lifecycle: *const quicz.EndpointConnectionLifecycle,
    socket: *std.Io.net.Socket,
    receive_buf: []u8,
) !ReceivedRoute {
    const received = try socket.receiveTimeout(io, receive_buf, receiveTimeout());
    const path = try udp4Tuple(socket.address, received.from);
    return .{
        .data = received.data,
        .route = try lifecycle.routeDatagram(path, received.data),
    };
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_socket = try bindLoopbackUdp(io);
    defer client_socket.close(io);
    var migrated_client_socket = try bindLoopbackUdp(io);
    defer migrated_client_socket.close(io);
    var server_socket = try bindLoopbackUdp(io);
    defer server_socket.close(io);

    const client_local = try udp4Address(client_socket.address);
    const migrated_client_local = try udp4Address(migrated_client_socket.address);
    const server_local = try udp4Address(server_socket.address);
    try require(client_local.port != 0);
    try require(migrated_client_local.port != 0);
    try require(server_local.port != 0);
    try require(client_local.port != server_local.port);
    try require(client_local.port != migrated_client_local.port);

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try quicz.QuicConnection.init(allocator, .client, .{ .enable_spin_bit = true });
    defer client.deinit();
    var server = try quicz.QuicConnection.init(allocator, .server, .{ .enable_spin_bit = true });
    defer server.deinit();
    try server.validatePeerAddress();
    try client.confirmHandshake();
    try server.confirmHandshake();

    var client_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer client_lifecycle.deinit();
    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer server_lifecycle.deinit();

    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    const migrated_client_path = try udp4Tuple(migrated_client_socket.address, server_socket.address);
    const server_path = try udp4Tuple(server_socket.address, client_socket.address);
    const migrated_server_path = try udp4Tuple(server_socket.address, migrated_client_socket.address);
    try client_lifecycle.registerConnectionId(41, &client_dcid, client_path, .{});
    try server_lifecycle.registerConnectionId(51, &server_dcid, server_path, .{});

    var server_receive_buf: [1500]u8 = undefined;
    var client_receive_buf: [1500]u8 = undefined;

    try require(!client.nextOutgoingSpinBit());
    try client.sendPing();
    const first_ping = (try client.pollProtectedShortDatagram(0, &server_dcid, secrets.client)) orelse return error.UnexpectedState;
    defer allocator.free(first_ping);
    const first_spin = try quicz.protection.peekShortPacketSpinBit(first_ping);
    try require(!first_spin);
    try client_socket.send(io, &server_socket.address, first_ping);

    const first_received = try receiveRoute(io, &server_lifecycle, &server_socket, &server_receive_buf);
    try require(first_received.route.connection_id == 51);
    try require(std.mem.eql(u8, first_received.route.destination_connection_id.asSlice(), &server_dcid));
    try server.processProtectedShortDatagram(1, secrets.client, server_dcid.len, first_received.data);
    try require(!server.nextOutgoingSpinBit());

    const first_ack = (try server.pollProtectedShortDatagram(2, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer allocator.free(first_ack);
    const first_ack_spin = try quicz.protection.peekShortPacketSpinBit(first_ack);
    try require(!first_ack_spin);
    try server_socket.send(io, &client_socket.address, first_ack);

    const first_ack_received = try receiveRoute(io, &client_lifecycle, &client_socket, &client_receive_buf);
    try require(first_ack_received.route.connection_id == 41);
    try require(std.mem.eql(u8, first_ack_received.route.destination_connection_id.asSlice(), &client_dcid));
    try client.processProtectedShortDatagram(3, secrets.server, client_dcid.len, first_ack_received.data);
    try require(client.nextOutgoingSpinBit());
    try require(client.bytesInFlight(.application) == 0);

    try client.sendPing();
    const second_ping = (try client.pollProtectedShortDatagram(4, &server_dcid, secrets.client)) orelse return error.UnexpectedState;
    defer allocator.free(second_ping);
    const second_spin = try quicz.protection.peekShortPacketSpinBit(second_ping);
    try require(second_spin);
    try migrated_client_socket.send(io, &server_socket.address, second_ping);

    const second_received = try receiveRoute(io, &server_lifecycle, &server_socket, &server_receive_buf);
    try require(second_received.route.connection_id == 51);
    try require(second_received.route.path_changed);
    try require(std.mem.eql(u8, second_received.route.destination_connection_id.asSlice(), &server_dcid));
    try server.processProtectedShortDatagram(5, secrets.client, server_dcid.len, second_received.data);
    try require(server.nextOutgoingSpinBit());
    const server_spin_before_reset = server.nextOutgoingSpinBit();

    const updated_server_route = try server_lifecycle.updateRoutePathAndResetSpinBit(&server_dcid, server_path, migrated_server_path, &server);
    try require(updated_server_route.connection_id == 51);
    try require(!updated_server_route.path_changed);
    try require(!server.nextOutgoingSpinBit());
    const updated_client_route = try client_lifecycle.updateRoutePathAndResetSpinBit(&client_dcid, client_path, migrated_client_path, &client);
    try require(updated_client_route.connection_id == 41);
    try require(!updated_client_route.path_changed);

    const second_ack = (try server.pollProtectedShortDatagram(6, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer allocator.free(second_ack);
    const second_ack_spin = try quicz.protection.peekShortPacketSpinBit(second_ack);
    try require(!second_ack_spin);
    try server_socket.send(io, &migrated_client_socket.address, second_ack);

    const second_ack_received = try receiveRoute(io, &client_lifecycle, &migrated_client_socket, &client_receive_buf);
    try require(second_ack_received.route.connection_id == 41);
    try require(!second_ack_received.route.path_changed);
    try require(std.mem.eql(u8, second_ack_received.route.destination_connection_id.asSlice(), &client_dcid));
    try client.processProtectedShortDatagram(7, secrets.server, client_dcid.len, second_ack_received.data);
    try require(client.bytesInFlight(.application) == 0);

    std.debug.print("[udp-spin] client_port={} migrated_client_port={} server_port={} first_ping={} first_ack={} second_ping={} second_ack={} first_spin={} first_ack_spin={} second_spin={} path_changed={} server_spin_before_reset={} second_ack_spin={} server_reset={} client_inflight={}\n", .{
        client_local.port,
        migrated_client_local.port,
        server_local.port,
        first_ping.len,
        first_ack.len,
        second_ping.len,
        second_ack.len,
        first_spin,
        first_ack_spin,
        second_spin,
        second_received.route.path_changed,
        server_spin_before_reset,
        second_ack_spin,
        server.nextOutgoingSpinBit(),
        client.bytesInFlight(.application),
    });
}
