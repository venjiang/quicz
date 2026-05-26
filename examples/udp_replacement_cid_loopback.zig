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

fn receiveRoute(
    io: std.Io,
    router: *const quicz.endpoint.EndpointRouter,
    server_socket: *std.Io.net.Socket,
    receive_buf: []u8,
) !struct { path: quicz.endpoint.Udp4Tuple, route: quicz.endpoint.RouteResult } {
    const received = try server_socket.receiveTimeout(io, receive_buf, receiveTimeout());
    const received_path = try udp4Tuple(server_socket.address, received.from);
    return .{
        .path = received_path,
        .route = try router.routeDatagram(received_path, received.data),
    };
}

fn receiveRetiredToken(
    io: std.Io,
    router: *const quicz.endpoint.EndpointRouter,
    server_socket: *std.Io.net.Socket,
    receive_buf: []u8,
) ![quicz.packet.stateless_reset_token_len]u8 {
    const received = try server_socket.receiveTimeout(io, receive_buf, receiveTimeout());
    const received_path = try udp4Tuple(server_socket.address, received.from);
    if (router.routeDatagram(received_path, received.data)) |_| {
        return error.UnexpectedState;
    } else |err| switch (err) {
        error.UnknownConnectionId => {},
        else => return err,
    }
    return (try router.statelessResetTokenForDatagram(received_path, received.data)) orelse error.UnexpectedState;
}

fn expectActiveMigrationDisabled(router: *const quicz.endpoint.EndpointRouter, path: quicz.endpoint.Udp4Tuple, datagram: []const u8) !void {
    if (router.routeDatagram(path, datagram)) |_| {
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
    var other_client_socket = try bindLoopbackUdp(io);
    defer other_client_socket.close(io);
    var server_socket = try bindLoopbackUdp(io);
    defer server_socket.close(io);

    const client_local = try udp4Address(client_socket.address);
    const other_client_local = try udp4Address(other_client_socket.address);
    const server_local = try udp4Address(server_socket.address);
    try require(client_local.port != 0);
    try require(other_client_local.port != 0);
    try require(server_local.port != 0);
    try require(client_local.port != other_client_local.port);
    try require(client_local.port != server_local.port);
    try require(other_client_local.port != server_local.port);

    var router = quicz.endpoint.EndpointRouter.init(allocator);
    defer router.deinit();

    const connection_handle: u64 = 111;
    const cid0 = [_]u8{ 0x60, 0x61, 0x62, 0x63 };
    const cid1 = [_]u8{ 0x70, 0x71, 0x72, 0x73 };
    const cid2 = [_]u8{ 0x80, 0x81, 0x82, 0x83 };
    const token0 = [_]u8{0x20} ** quicz.packet.stateless_reset_token_len;
    const token1 = [_]u8{0x21} ** quicz.packet.stateless_reset_token_len;
    const token2 = [_]u8{0x22} ** quicz.packet.stateless_reset_token_len;
    const path = try udp4Tuple(server_socket.address, client_socket.address);

    const datagram0 = [_]u8{ 0x40, 0x60, 0x61, 0x62, 0x63, 0x01 };
    const datagram1 = [_]u8{ 0x40, 0x70, 0x71, 0x72, 0x73, 0x01 };
    const datagram2 = [_]u8{ 0x40, 0x80, 0x81, 0x82, 0x83, 0x01 };

    try router.registerConnectionId(connection_handle, &cid0, path, .{
        .sequence_number = 0,
        .active_migration_disabled = true,
        .stateless_reset_token = token0,
    });

    try client_socket.send(io, &server_socket.address, &datagram0);
    var server_receive_buf: [1500]u8 = undefined;
    const initial = try receiveRoute(io, &router, &server_socket, &server_receive_buf);
    try require(initial.route.connection_id == connection_handle);
    try require(initial.route.sequence_number.? == 0);
    try require(std.mem.eql(u8, initial.route.destination_connection_id.asSlice(), &cid0));

    const replacement1 = try router.registerReplacementConnectionId(connection_handle, &cid1, path, 1, 1, .{
        .active_migration_disabled = true,
        .stateless_reset_token = token1,
    });
    try require(replacement1.sequence_number == 1);
    try require(replacement1.retire_prior_to == 1);
    try require(replacement1.retired_count == 1);

    try client_socket.send(io, &server_socket.address, &datagram0);
    const retired0_token = try receiveRetiredToken(io, &router, &server_socket, &server_receive_buf);
    try require(std.mem.eql(u8, &retired0_token, &token0));

    try client_socket.send(io, &server_socket.address, &datagram1);
    const route1 = try receiveRoute(io, &router, &server_socket, &server_receive_buf);
    try require(route1.route.connection_id == connection_handle);
    try require(route1.route.sequence_number.? == 1);
    try require(std.mem.eql(u8, route1.route.destination_connection_id.asSlice(), &cid1));
    try require((try router.statelessResetTokenForDatagram(route1.path, &datagram1)) == null);

    if (router.registerReplacementConnectionId(connection_handle, &cid2, path, 1, 2, .{ .stateless_reset_token = token2 })) |_| {
        return error.UnexpectedState;
    } else |err| switch (err) {
        error.InvalidConnectionIdSequence => {},
        else => return err,
    }

    const replacement2 = try router.registerReplacementConnectionId(connection_handle, &cid2, path, 2, 2, .{
        .active_migration_disabled = true,
        .stateless_reset_token = token2,
    });
    try require(replacement2.sequence_number == 2);
    try require(replacement2.retire_prior_to == 2);
    try require(replacement2.retired_count == 1);

    try client_socket.send(io, &server_socket.address, &datagram1);
    const retired1_token = try receiveRetiredToken(io, &router, &server_socket, &server_receive_buf);
    try require(std.mem.eql(u8, &retired1_token, &token1));

    try client_socket.send(io, &server_socket.address, &datagram2);
    const route2 = try receiveRoute(io, &router, &server_socket, &server_receive_buf);
    try require(route2.route.connection_id == connection_handle);
    try require(route2.route.sequence_number.? == 2);
    try require(std.mem.eql(u8, route2.route.destination_connection_id.asSlice(), &cid2));

    const other_path = try udp4Tuple(server_socket.address, other_client_socket.address);
    try expectActiveMigrationDisabled(&router, other_path, &datagram2);

    std.debug.print("[udp-replacement-cid] client_port={} other_client_port={} server_port={} initial_seq={} replacement1_retired={} replacement2_retired={} active_seq={} retired0_token=true retired1_token=true migration_disabled=true\n", .{
        client_local.port,
        other_client_local.port,
        server_local.port,
        initial.route.sequence_number.?,
        replacement1.retired_count,
        replacement2.retired_count,
        route2.route.sequence_number.?,
    });
}
