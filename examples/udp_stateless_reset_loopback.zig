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

    var lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer lifecycle.deinit();

    const cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const path = try udp4Tuple(server_socket.address, client_socket.address);
    try lifecycle.registerConnectionId(7, &cid, path, .{ .stateless_reset_token = token });
    const trigger = [_]u8{
        0x40, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    };

    try client_socket.send(io, &server_socket.address, &trigger);

    var server_receive_buf: [1500]u8 = undefined;
    const active_received = try server_socket.receiveTimeout(io, &server_receive_buf, receiveTimeout());
    const active_path = try udp4Tuple(server_socket.address, active_received.from);
    var active_out: [64]u8 = undefined;
    const active_action = try lifecycle.handleDatagram(
        &active_out,
        active_path,
        active_received.data,
        &[_]u8{ 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde },
    );
    switch (active_action) {
        .routed => |route| {
            try require(route.connection_id == 7);
            try require(std.mem.eql(u8, route.destination_connection_id.asSlice(), &cid));
        },
        else => return error.UnexpectedState,
    }

    const retired = lifecycle.retireConnection(7);
    try require(retired.routes_retired == 1);
    try require(!retired.recovery_timer_disarmed);
    try require(lifecycle.routeCount() == 0);
    try require(lifecycle.statelessResetTokenCount() == 1);

    try client_socket.send(io, &server_socket.address, &trigger);

    const received = try server_socket.receiveTimeout(io, &server_receive_buf, receiveTimeout());
    const received_path = try udp4Tuple(server_socket.address, received.from);
    var reset_out: [64]u8 = undefined;
    const action = try lifecycle.handleDatagram(
        &reset_out,
        received_path,
        received.data,
        &[_]u8{ 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde },
    );
    const reset = switch (action) {
        .stateless_reset => |datagram| datagram,
        else => return error.UnexpectedState,
    };
    try require(reset.len < received.data.len);
    try server_socket.send(io, &received.from, reset);

    var client_receive_buf: [1500]u8 = undefined;
    const reset_received = try client_socket.receiveTimeout(io, &client_receive_buf, receiveTimeout());
    try require(quicz.packet.matchesStatelessReset(reset_received.data, token));

    std.debug.print("[udp-reset] client_port={} server_port={} active_routed=true trigger_bytes={} reset_bytes={} matched=true\n", .{
        client_local.port,
        server_local.port,
        trigger.len,
        reset_received.data.len,
    });
}
