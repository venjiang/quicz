const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

fn require(condition: bool) ExampleError!void {
    if (!condition) return error.UnexpectedState;
}

fn requireInvalidRoutePacket(result: anyerror!quicz.endpoint.RouteResult) !void {
    _ = result catch |err| {
        if (err == error.InvalidPacket) return;
        return err;
    };
    return error.UnexpectedState;
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

fn runProtectedAutoClose(
    allocator: std.mem.Allocator,
    io: std.Io,
    client_socket: *std.Io.net.Socket,
    server_socket: *std.Io.net.Socket,
) !void {
    const original_dcid = [_]u8{ 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };
    const client_dcid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const server_dcid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const connection_handle: u64 = 72;
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try quicz.Connection.init(allocator, .client, .{});
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    var client_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer client_lifecycle.deinit();
    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer server_lifecycle.deinit();

    const client_path = try udp4Tuple(client_socket.*.address, server_socket.*.address);
    const server_path = try udp4Tuple(server_socket.*.address, client_socket.*.address);
    try client_lifecycle.registerConnectionId(connection_handle, &client_dcid, client_path, .{});
    try server_lifecycle.registerConnectionId(connection_handle, &server_dcid, server_path, .{});

    const unknown_frame = [_]u8{ 0x1f, 0, 0, 0 };
    const invalid_short = try quicz.protection.protectShortPacketAes128(allocator, .{
        .dcid = &server_dcid,
        .spin_bit = false,
        .key_phase = false,
        .packet_number = 0,
    }, try quicz.packet.encodePacketNumberForHeader(0, null), secrets.client, &unknown_frame);
    defer allocator.free(invalid_short);

    try client_socket.*.send(io, &server_socket.*.address, invalid_short);

    var server_receive_buf: [1500]u8 = undefined;
    const invalid_received = try server_socket.*.receiveTimeout(io, &server_receive_buf, receiveTimeout());
    const invalid_path = try udp4Tuple(server_socket.*.address, invalid_received.from);
    try requireInvalidRoutePacket(server_lifecycle.processRoutedProtectedShortDatagramOrClose(
        connection_handle,
        &server,
        invalid_path,
        30,
        secrets.client,
        invalid_received.data,
    ));
    try require(server.connectionState() == .closing);

    const close_packet = (try server_lifecycle.pollProtectedShortDatagram(connection_handle, &server, 31, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer allocator.free(close_packet);
    try server_socket.*.send(io, &invalid_received.from, close_packet);

    var client_receive_buf: [1500]u8 = undefined;
    const close_received = try client_socket.*.receiveTimeout(io, &client_receive_buf, receiveTimeout());
    const close_path = try udp4Tuple(client_socket.*.address, close_received.from);
    const close_route = try client_lifecycle.processRoutedProtectedShortDatagram(
        connection_handle,
        &client,
        close_path,
        32,
        secrets.server,
        close_received.data,
    );
    try require(close_route.connection_id == connection_handle);
    try require(std.mem.eql(u8, close_route.destination_connection_id.asSlice(), &client_dcid));
    try require(client.connectionState() == .draining);

    switch (client.peerClose() orelse return error.UnexpectedState) {
        .connection => |close| {
            try require(close.error_code == quicz.transport_error.codeValue(.frame_encoding_error));
            try require(close.frame_type == 0x1f);
            try require(std.mem.eql(u8, close.reason_phrase, "frame encoding"));
            std.debug.print("[udp-close] auto_close invalid_bytes={} close_bytes={} error={} frame_type={} server_state={s} client_state={s}\n", .{
                invalid_received.data.len,
                close_received.data.len,
                close.error_code,
                close.frame_type,
                @tagName(server.connectionState()),
                @tagName(client.connectionState()),
            });
        },
        else => return error.UnexpectedState,
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

    const client_local = try udp4Address(client_socket.address);
    const server_local = try udp4Address(server_socket.address);
    try require(client_local.port != 0);
    try require(server_local.port != 0);
    try require(client_local.port != server_local.port);

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const reset_token = [_]u8{ 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f };
    const reset_prefix = [_]u8{ 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde };
    const connection_handle: u64 = 71;
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    try runProtectedAutoClose(allocator, io, &client_socket, &server_socket);

    var client = try quicz.Connection.init(allocator, .client, .{});
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    var client_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer client_lifecycle.deinit();
    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer server_lifecycle.deinit();

    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    const server_path = try udp4Tuple(server_socket.address, client_socket.address);
    try client_lifecycle.registerConnectionId(connection_handle, &client_dcid, client_path, .{});
    try require(client_lifecycle.routeCount() == 1);
    try server_lifecycle.registerConnectionId(connection_handle, &server_dcid, server_path, .{
        .stateless_reset_token = reset_token,
    });
    try require(server_lifecycle.routeCount() == 1);
    try require(server_lifecycle.statelessResetTokenCount() == 1);

    try client.closeConnection(0, @intFromEnum(quicz.frame.FrameType.stream), "udp close");
    const close_packet = (try client.pollProtectedShortDatagram(1, &server_dcid, secrets.client)) orelse return error.UnexpectedState;
    defer allocator.free(close_packet);
    try client_socket.send(io, &server_socket.address, close_packet);

    var server_receive_buf: [1500]u8 = undefined;
    const close_received = try server_socket.receiveTimeout(io, &server_receive_buf, receiveTimeout());
    const close_path = try udp4Tuple(server_socket.address, close_received.from);
    const close_route = try server_lifecycle.processRoutedProtectedShortDatagram(
        connection_handle,
        &server,
        close_path,
        2,
        secrets.client,
        close_received.data,
    );
    try require(close_route.connection_id == connection_handle);
    try require(std.mem.eql(u8, close_route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.connectionState() == .draining);
    switch (server.peerClose() orelse return error.UnexpectedState) {
        .connection => |close| {
            try require(close.error_code == 0);
            try require(std.mem.eql(u8, close.reason_phrase, "udp close"));
        },
        else => return error.UnexpectedState,
    }

    const retired = server_lifecycle.retireConnection(connection_handle);
    try require(retired.routes_retired == 1);
    try require(!retired.recovery_timer_disarmed);
    try require(server_lifecycle.routeCount() == 0);
    try require(server_lifecycle.statelessResetTokenCount() == 1);

    const stray_packet = [_]u8{
        0x40, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    };
    try client_socket.send(io, &server_socket.address, &stray_packet);

    const stray_received = try server_socket.receiveTimeout(io, &server_receive_buf, receiveTimeout());
    const stray_path = try udp4Tuple(server_socket.address, stray_received.from);
    var reset_out: [64]u8 = undefined;
    const action = try server_lifecycle.handleDatagram(
        &reset_out,
        stray_path,
        stray_received.data,
        &reset_prefix,
    );
    const reset = switch (action) {
        .stateless_reset => |datagram| datagram,
        else => return error.UnexpectedState,
    };
    try require(reset.len < stray_received.data.len);
    try server_socket.send(io, &stray_received.from, reset);

    var client_receive_buf: [1500]u8 = undefined;
    const reset_received = try client_socket.receiveTimeout(io, &client_receive_buf, receiveTimeout());
    try require(quicz.packet.matchesStatelessReset(reset_received.data, reset_token));

    std.debug.print("[udp-close] client_port={} server_port={} close_bytes={} retired_routes={} reset_bytes={} matched=true server_state={s}\n", .{
        client_local.port,
        server_local.port,
        close_packet.len,
        retired.routes_retired,
        reset_received.data.len,
        @tagName(server.connectionState()),
    });
}
