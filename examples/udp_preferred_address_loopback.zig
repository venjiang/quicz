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

fn expectActiveMigrationDisabled(lifecycle: *const quicz.EndpointConnectionLifecycle, path: quicz.endpoint.Udp4Tuple, datagram: []const u8) !void {
    if (lifecycle.routeDatagram(path, datagram)) |_| {
        return error.UnexpectedState;
    } else |err| switch (err) {
        error.ActiveMigrationDisabled => {},
        else => return err,
    }
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
    var preferred_server_socket = try bindLoopbackUdp(io);
    defer preferred_server_socket.close(io);
    var stray_server_socket = try bindLoopbackUdp(io);
    defer stray_server_socket.close(io);

    const client_local = try udp4Address(client_socket.address);
    const server_local = try udp4Address(server_socket.address);
    const preferred_server_local = try udp4Address(preferred_server_socket.address);
    const stray_server_local = try udp4Address(stray_server_socket.address);
    try require(client_local.port != 0);
    try require(server_local.port != 0);
    try require(preferred_server_local.port != 0);
    try require(stray_server_local.port != 0);
    try require(server_local.port != preferred_server_local.port);
    try require(server_local.port != stray_server_local.port);
    try require(preferred_server_local.port != stray_server_local.port);

    var lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer lifecycle.deinit();

    const current_cid = [_]u8{ 0x30, 0x31, 0x32, 0x33 };
    const preferred_cid = [_]u8{ 0x34, 0x35, 0x36, 0x37 };
    const preferred_token = [_]u8{ 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53 };
    const connection_handle: u64 = 91;
    const current_path = try udp4Tuple(client_socket.address, server_socket.address);
    const preferred_path = try udp4Tuple(client_socket.address, preferred_server_socket.address);
    const stray_path = try udp4Tuple(client_socket.address, stray_server_socket.address);
    try lifecycle.registerConnectionId(connection_handle, &current_cid, current_path, .{
        .active_migration_disabled = true,
    });

    const current_datagram = [_]u8{ 0x40, 0x30, 0x31, 0x32, 0x33, 0x01 };
    try server_socket.send(io, &client_socket.address, &current_datagram);
    var client_receive_buf: [1500]u8 = undefined;
    const current_received = try client_socket.receiveTimeout(io, &client_receive_buf, receiveTimeout());
    const current_received_path = try udp4Tuple(client_socket.address, current_received.from);
    const current_route = try lifecycle.routeDatagram(current_received_path, current_received.data);
    try require(current_route.connection_id == connection_handle);
    try require(std.mem.eql(u8, current_route.destination_connection_id.asSlice(), &current_cid));
    try require(!current_route.path_changed);

    const preferred_route = try lifecycle.commitPreferredAddressMigration(
        &current_cid,
        current_path,
        &preferred_cid,
        preferred_path,
        preferred_token,
    );
    try require(preferred_route.connection_id == connection_handle);
    try require(std.mem.eql(u8, preferred_route.destination_connection_id.asSlice(), &preferred_cid));
    try require(!preferred_route.path_changed);
    try expectUnknownRoute(&lifecycle, current_path, &current_datagram);

    const preferred_datagram = [_]u8{
        0x40, 0x34, 0x35, 0x36, 0x37, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    };
    try preferred_server_socket.send(io, &client_socket.address, &preferred_datagram);
    const preferred_received = try client_socket.receiveTimeout(io, &client_receive_buf, receiveTimeout());
    const preferred_received_path = try udp4Tuple(client_socket.address, preferred_received.from);
    const confirmed_route = try lifecycle.routeDatagram(preferred_received_path, preferred_received.data);
    try require(confirmed_route.connection_id == connection_handle);
    try require(std.mem.eql(u8, confirmed_route.destination_connection_id.asSlice(), &preferred_cid));
    try require(!confirmed_route.path_changed);

    try expectActiveMigrationDisabled(&lifecycle, stray_path, &preferred_datagram);
    try require((try lifecycle.statelessResetTokenForDatagram(preferred_path, &preferred_datagram)) == null);
    const retired = lifecycle.retireConnection(connection_handle);
    try require(retired.routes_retired == 1);
    try require(!retired.recovery_timer_disarmed);
    const reset_token = (try lifecycle.statelessResetTokenForDatagram(preferred_path, &preferred_datagram)) orelse return error.UnexpectedState;
    try require(std.mem.eql(u8, &reset_token, &preferred_token));

    std.debug.print("[udp-preferred] client_port={} old_server_port={} preferred_server_port={} stray_server_port={} current_route={} preferred_route={} confirmed_route={} active_migration_disabled=true reset_token_retained=true\n", .{
        client_local.port,
        server_local.port,
        preferred_server_local.port,
        stray_server_local.port,
        current_route.connection_id,
        preferred_route.connection_id,
        confirmed_route.connection_id,
    });
}
