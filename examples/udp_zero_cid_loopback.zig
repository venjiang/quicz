const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

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

fn expectUnknownRoute(lifecycle: *const quicz.EndpointConnectionLifecycle, path: quicz.endpoint.Udp4Tuple, datagram: []const u8) !void {
    if (lifecycle.routeDatagram(path, datagram)) |_| {
        return error.UnexpectedState;
    } else |err| switch (err) {
        error.UnknownConnectionId => {},
        else => return err,
    }
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client0_socket = try bindLoopbackUdp(io);
    defer client0_socket.close(io);
    var client1_socket = try bindLoopbackUdp(io);
    defer client1_socket.close(io);
    var client2_socket = try bindLoopbackUdp(io);
    defer client2_socket.close(io);
    var server_socket = try bindLoopbackUdp(io);
    defer server_socket.close(io);

    const client0_local = try udp4Address(client0_socket.address);
    const client1_local = try udp4Address(client1_socket.address);
    const client2_local = try udp4Address(client2_socket.address);
    const server_local = try udp4Address(server_socket.address);
    try require(client0_local.port != 0);
    try require(client1_local.port != 0);
    try require(client2_local.port != 0);
    try require(server_local.port != 0);
    try require(client0_local.port != client1_local.port);
    try require(client0_local.port != client2_local.port);
    try require(client1_local.port != client2_local.port);

    var lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer lifecycle.deinit();

    const empty_cid = [_]u8{};
    const path0 = try udp4Tuple(server_socket.address, client0_socket.address);
    const path1 = try udp4Tuple(server_socket.address, client1_socket.address);
    const path2 = try udp4Tuple(server_socket.address, client2_socket.address);
    try lifecycle.registerConnectionId(101, &empty_cid, path0, .{});
    try lifecycle.registerConnectionId(102, &empty_cid, path1, .{});
    try require(lifecycle.routeCount() == 2);

    const short_datagram = [_]u8{ 0x40, 0x01, 0x02, 0x03 };
    try client0_socket.send(io, &server_socket.address, &short_datagram);
    var server_receive_buf: [1500]u8 = undefined;
    const first_received = try server_socket.receiveTimeout(io, &server_receive_buf, receiveTimeout());
    const first_path = try udp4Tuple(server_socket.address, first_received.from);
    const first_route = try lifecycle.routeDatagram(first_path, first_received.data);
    try require(first_route.connection_id == 101);
    try require(first_route.destination_connection_id.asSlice().len == 0);
    try require(!first_route.path_changed);

    try client1_socket.send(io, &server_socket.address, &short_datagram);
    const second_received = try server_socket.receiveTimeout(io, &server_receive_buf, receiveTimeout());
    const second_path = try udp4Tuple(server_socket.address, second_received.from);
    const second_route = try lifecycle.routeDatagram(second_path, second_received.data);
    try require(second_route.connection_id == 102);
    try require(second_route.destination_connection_id.asSlice().len == 0);
    try require(!second_route.path_changed);

    const long_zero_dcid = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0x00 };
    try client0_socket.send(io, &server_socket.address, &long_zero_dcid);
    const long_received = try server_socket.receiveTimeout(io, &server_receive_buf, receiveTimeout());
    const long_path = try udp4Tuple(server_socket.address, long_received.from);
    const long_route = try lifecycle.routeDatagram(long_path, long_received.data);
    try require(long_route.connection_id == 101);
    try require(long_route.destination_connection_id.asSlice().len == 0);

    try require(try lifecycle.retireConnectionIdOnPath(&empty_cid, path0));
    try require(lifecycle.routeCount() == 1);
    try expectUnknownRoute(&lifecycle, path0, &short_datagram);
    try require((try lifecycle.routeDatagram(path1, &short_datagram)).connection_id == 102);

    const updated_route = try lifecycle.updateRoutePath(&empty_cid, path1, path2);
    try require(updated_route.connection_id == 102);
    try require(!updated_route.path_changed);
    try expectUnknownRoute(&lifecycle, path1, &short_datagram);

    try client2_socket.send(io, &server_socket.address, &short_datagram);
    const updated_received = try server_socket.receiveTimeout(io, &server_receive_buf, receiveTimeout());
    const updated_path = try udp4Tuple(server_socket.address, updated_received.from);
    const confirmed_route = try lifecycle.routeDatagram(updated_path, updated_received.data);
    try require(confirmed_route.connection_id == 102);
    try require(!confirmed_route.path_changed);

    std.debug.print("[udp-zero-cid] client0_port={} client1_port={} client2_port={} server_port={} route0={} route1={} long_route={} retired0=true updated_route={} confirmed_route={}\n", .{
        client0_local.port,
        client1_local.port,
        client2_local.port,
        server_local.port,
        first_route.connection_id,
        second_route.connection_id,
        long_route.connection_id,
        updated_route.connection_id,
        confirmed_route.connection_id,
    });
}
