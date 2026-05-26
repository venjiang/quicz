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

fn expectFlowControlBlocked(result: anytype) !void {
    _ = result catch |err| {
        if (err == error.FlowControlBlocked) return;
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

fn receiveRoute(
    io: std.Io,
    router: *const quicz.endpoint.EndpointRouter,
    socket: *std.Io.net.Socket,
    receive_buf: []u8,
) !ReceivedRoute {
    const received = try socket.receiveTimeout(io, receive_buf, receiveTimeout());
    const path = try udp4Tuple(socket.address, received.from);
    return .{
        .data = received.data,
        .route = try router.routeDatagram(path, received.data),
    };
}

fn sendClientPacket(
    io: std.Io,
    allocator: std.mem.Allocator,
    client: *quicz.QuicConnection,
    server_router: *const quicz.endpoint.EndpointRouter,
    client_socket: *std.Io.net.Socket,
    server_socket: *std.Io.net.Socket,
    now_millis: i64,
    server_dcid: []const u8,
    keys: quicz.protection.Aes128PacketProtectionKeys,
    receive_buf: []u8,
) ![]const u8 {
    const packet = (try client.pollProtectedShortDatagram(now_millis, server_dcid, keys)) orelse return error.UnexpectedState;
    defer allocator.free(packet);
    try client_socket.send(io, &server_socket.address, packet);

    const received = try receiveRoute(io, server_router, server_socket, receive_buf);
    try require(std.mem.eql(u8, received.route.destination_connection_id.asSlice(), server_dcid));
    return received.data;
}

fn sendServerPacket(
    io: std.Io,
    allocator: std.mem.Allocator,
    server: *quicz.QuicConnection,
    client_router: *const quicz.endpoint.EndpointRouter,
    server_socket: *std.Io.net.Socket,
    client_socket: *std.Io.net.Socket,
    now_millis: i64,
    client_dcid: []const u8,
    keys: quicz.protection.Aes128PacketProtectionKeys,
    receive_buf: []u8,
) ![]const u8 {
    const packet = (try server.pollProtectedShortDatagram(now_millis, client_dcid, keys)) orelse return error.UnexpectedState;
    defer allocator.free(packet);
    try server_socket.send(io, &client_socket.address, packet);

    const received = try receiveRoute(io, client_router, client_socket, receive_buf);
    try require(std.mem.eql(u8, received.route.destination_connection_id.asSlice(), client_dcid));
    return received.data;
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
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try quicz.QuicConnection.init(allocator, .client, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 5,
    });
    defer client.deinit();
    var server = try quicz.QuicConnection.init(allocator, .server, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 5,
    });
    defer server.deinit();
    try server.validatePeerAddress();
    try client.confirmHandshake();
    try server.confirmHandshake();

    var client_router = quicz.endpoint.EndpointRouter.init(allocator);
    defer client_router.deinit();
    var server_router = quicz.endpoint.EndpointRouter.init(allocator);
    defer server_router.deinit();

    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    const server_path = try udp4Tuple(server_socket.address, client_socket.address);
    try client_router.registerConnectionId(41, &client_dcid, client_path, .{
        .active_migration_disabled = true,
    });
    try server_router.registerConnectionId(51, &server_dcid, server_path, .{
        .active_migration_disabled = true,
    });

    var server_receive_buf: [1500 + 8]u8 = undefined;
    var client_receive_buf: [1500 + 8]u8 = undefined;
    var read_buf: [8]u8 = undefined;

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello", false);
    const stream_packet = try sendClientPacket(
        io,
        allocator,
        &client,
        &server_router,
        &client_socket,
        &server_socket,
        0,
        &server_dcid,
        secrets.client,
        &server_receive_buf,
    );
    try server.processProtectedShortDatagram(1, secrets.client, server_dcid.len, stream_packet);

    try expectFlowControlBlocked(client.sendOnStream(stream_id, "!", false));
    const blocked_packet = try sendClientPacket(
        io,
        allocator,
        &client,
        &server_router,
        &client_socket,
        &server_socket,
        2,
        &server_dcid,
        secrets.client,
        &server_receive_buf,
    );
    try server.processProtectedShortDatagram(3, secrets.client, server_dcid.len, blocked_packet);
    try require(server.peerStreamDataBlockedLimit(stream_id) == 5);

    const first_len = (try server.recvOnStream(stream_id, &read_buf)) orelse return error.UnexpectedState;
    try require(std.mem.eql(u8, read_buf[0..first_len], "hello"));

    const max_data_packet = try sendServerPacket(
        io,
        allocator,
        &server,
        &client_router,
        &server_socket,
        &client_socket,
        4,
        &client_dcid,
        secrets.server,
        &client_receive_buf,
    );
    try client.processProtectedShortDatagram(5, secrets.server, client_dcid.len, max_data_packet);

    const max_stream_packet = try sendServerPacket(
        io,
        allocator,
        &server,
        &client_router,
        &server_socket,
        &client_socket,
        6,
        &client_dcid,
        secrets.server,
        &client_receive_buf,
    );
    try client.processProtectedShortDatagram(7, secrets.server, client_dcid.len, max_stream_packet);

    try client.sendOnStream(stream_id, "!", true);
    const resumed_packet = try sendClientPacket(
        io,
        allocator,
        &client,
        &server_router,
        &client_socket,
        &server_socket,
        8,
        &server_dcid,
        secrets.client,
        &server_receive_buf,
    );
    try server.processProtectedShortDatagram(9, secrets.client, server_dcid.len, resumed_packet);

    const resumed_len = (try server.recvOnStream(stream_id, &read_buf)) orelse return error.UnexpectedState;
    try require(std.mem.eql(u8, read_buf[0..resumed_len], "!"));

    const final_ack = try sendServerPacket(
        io,
        allocator,
        &server,
        &client_router,
        &server_socket,
        &client_socket,
        10,
        &client_dcid,
        secrets.server,
        &client_receive_buf,
    );
    try client.processProtectedShortDatagram(11, secrets.server, client_dcid.len, final_ack);
    try require(client.bytesInFlight(.application) == 0);

    std.debug.print("[udp-flow] client_port={} server_port={} stream={} stream_packet={} blocked_packet={} max_data_packet={} max_stream_packet={} resumed_packet={} final_ack={} peer_blocked={} client_inflight={}\n", .{
        client_local.port,
        server_local.port,
        stream_id,
        stream_packet.len,
        blocked_packet.len,
        max_data_packet.len,
        max_stream_packet.len,
        resumed_packet.len,
        final_ack.len,
        server.peerStreamDataBlockedLimit(stream_id).?,
        client.bytesInFlight(.application),
    });
}
