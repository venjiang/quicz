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

    var old_client_socket = try bindLoopbackUdp(io);
    defer old_client_socket.close(io);
    var new_client_socket = try bindLoopbackUdp(io);
    defer new_client_socket.close(io);
    var server_socket = try bindLoopbackUdp(io);
    defer server_socket.close(io);

    const old_client_local = try udp4Address(old_client_socket.address);
    const new_client_local = try udp4Address(new_client_socket.address);
    const server_local = try udp4Address(server_socket.address);
    try require(old_client_local.port != 0);
    try require(new_client_local.port != 0);
    try require(server_local.port != 0);
    try require(old_client_local.port != new_client_local.port);
    try require(old_client_local.port != server_local.port);
    try require(new_client_local.port != server_local.port);

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const challenge_data = [_]u8{ 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb };
    const connection_handle: u64 = 81;
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var server = try quicz.QuicConnection.init(allocator, .server, .{});
    defer server.deinit();
    var client = try quicz.QuicConnection.init(allocator, .client, .{});
    defer client.deinit();
    try server.validatePeerAddress();

    var server_router = quicz.endpoint.EndpointRouter.init(allocator);
    defer server_router.deinit();

    const old_path = try udp4Tuple(server_socket.address, old_client_socket.address);
    try server_router.registerConnectionId(connection_handle, &server_dcid, old_path, .{});

    try server.sendPathChallenge(challenge_data);
    const challenge_packet = (try server.pollProtectedShortDatagram(
        1,
        &client_dcid,
        secrets.server,
    )) orelse return error.UnexpectedState;
    defer allocator.free(challenge_packet);
    try require(server.pendingPathChallengeCount() == 0);
    try require(server.outstandingPathChallengeCount() == 1);
    try server_socket.send(io, &new_client_socket.address, challenge_packet);

    var client_receive_buf: [1500]u8 = undefined;
    const challenge_received = try new_client_socket.receiveTimeout(io, &client_receive_buf, receiveTimeout());
    try client.processProtectedShortDatagram(2, secrets.server, client_dcid.len, challenge_received.data);
    try require(client.pendingAckLargest(.application) == 0);

    const response_packet = (try client.pollProtectedShortDatagram(
        3,
        &server_dcid,
        secrets.client,
    )) orelse return error.UnexpectedState;
    defer allocator.free(response_packet);
    try new_client_socket.send(io, &server_socket.address, response_packet);

    var server_receive_buf: [1500]u8 = undefined;
    const response_received = try server_socket.receiveTimeout(io, &server_receive_buf, receiveTimeout());
    const response_path = try udp4Tuple(server_socket.address, response_received.from);
    const migrated_route = try server_router.routeDatagram(response_path, response_received.data);
    try require(migrated_route.connection_id == connection_handle);
    try require(migrated_route.path_changed);
    try require(std.mem.eql(u8, migrated_route.destination_connection_id.asSlice(), &server_dcid));

    try server.processProtectedShortDatagram(4, secrets.client, server_dcid.len, response_received.data);
    try require(server.outstandingPathChallengeCount() == 0);
    try require(server.bytesInFlight(.application) == 0);
    try require(server.pendingAckLargest(.application) == 0);

    const updated_route = try server_router.updateRoutePath(&server_dcid, old_path, response_path);
    try require(updated_route.connection_id == connection_handle);
    try require(!updated_route.path_changed);

    const confirmed_route = try server_router.routeDatagram(response_path, response_received.data);
    try require(confirmed_route.connection_id == connection_handle);
    try require(!confirmed_route.path_changed);

    std.debug.print("[udp-path] old_client_port={} new_client_port={} server_port={} challenge_bytes={} response_bytes={} path_changed={} endpoint_updated={} server_inflight={}\n", .{
        old_client_local.port,
        new_client_local.port,
        server_local.port,
        challenge_packet.len,
        response_received.data.len,
        migrated_route.path_changed,
        !confirmed_route.path_changed,
        server.bytesInFlight(.application),
    });
}
