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

fn readCryptoRequired(
    conn: *quicz.Connection,
    space: quicz.PacketNumberSpace,
    out: []u8,
) ![]const u8 {
    const len = (try conn.recvCryptoInSpace(space, out)) orelse return error.UnexpectedState;
    return out[0..len];
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
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const reset_prefix = [_]u8{ 0x40, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26 };
    const supported_versions = [_]quicz.packet.Version{ .v1, .v2 };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try quicz.Connection.init(allocator, .client, .{});
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{});
    defer server.deinit();

    var client_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer client_lifecycle.deinit();
    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer server_lifecycle.deinit();

    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    _ = try client_lifecycle.registerClientInitialSourceConnectionId(41, &client_scid, client_path, .{
        .active_migration_disabled = true,
    });

    try client.sendCryptoInSpace(.initial, "udp protected client initial");
    const client_initial = (try client.pollInitialProtectedDatagram(
        0,
        &original_dcid,
        &client_scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_initial);
    try require(client_initial.len >= 1200);
    try client_socket.send(io, &server_socket.address, client_initial);

    var server_receive_buf: [1500]u8 = undefined;
    var client_receive_buf: [1500]u8 = undefined;

    const client_initial_received = try server_socket.receiveTimeout(io, &server_receive_buf, receiveTimeout());
    const server_path = try udp4Tuple(server_socket.address, client_initial_received.from);
    var action_buf: [256]u8 = undefined;
    const accept_action = try server_lifecycle.handleDatagramWithVersionNegotiation(
        &action_buf,
        server_path,
        client_initial_received.data,
        &reset_prefix,
        &supported_versions,
    );
    const initial_accept = switch (accept_action) {
        .accept_initial => |accept| accept,
        else => return error.UnexpectedState,
    };
    try require(std.mem.eql(u8, initial_accept.original_destination_connection_id, &original_dcid));
    try require(std.mem.eql(u8, initial_accept.source_connection_id, &client_scid));
    const accepted_response = try server_lifecycle.processAcceptedProtectedInitialResponseDatagram(
        51,
        &server,
        1,
        initial_accept,
        &server_scid,
        client_initial_received.data,
        .{ .active_migration_disabled = true },
        "udp protected server initial",
    );
    defer allocator.free(accepted_response.response_datagram);
    const accepted = accepted_response.accepted_initial.accepted_routes;
    try require(accepted_response.accepted_initial.processed_packets == 1);
    try require(accepted.server_source_route.connection_id == 51);

    try server.validatePeerAddress();
    var server_initial_crypto_buf: [128]u8 = undefined;
    const server_received_initial = try readCryptoRequired(&server, .initial, &server_initial_crypto_buf);
    try require(std.mem.eql(u8, server_received_initial, "udp protected client initial"));
    const server_initial = accepted_response.response_datagram;
    try server_socket.send(io, &client_initial_received.from, server_initial);

    const server_initial_received = try client_socket.receiveTimeout(io, &client_receive_buf, receiveTimeout());
    const server_initial_path = try udp4Tuple(client_socket.address, server_initial_received.from);
    const client_initial_route = try client_lifecycle.routeDatagram(server_initial_path, server_initial_received.data);
    try require(client_initial_route.connection_id == 41);
    try require(std.mem.eql(u8, client_initial_route.destination_connection_id.asSlice(), &client_scid));

    try client.processInitialProtectedDatagram(3, secrets.server, server_initial_received.data);
    var client_initial_crypto_buf: [128]u8 = undefined;
    const client_received_initial = try readCryptoRequired(&client, .initial, &client_initial_crypto_buf);
    try require(std.mem.eql(u8, client_received_initial, "udp protected server initial"));

    try client.confirmHandshake();
    try server.confirmHandshake();

    try client.sendPing();
    const one_rtt_ping = (try client.pollProtectedShortDatagram(
        4,
        &server_scid,
        secrets.client,
    )) orelse return error.UnexpectedState;
    defer allocator.free(one_rtt_ping);
    try client_socket.send(io, &server_socket.address, one_rtt_ping);

    const one_rtt_ping_received = try server_socket.receiveTimeout(io, &server_receive_buf, receiveTimeout());
    const ping_path = try udp4Tuple(server_socket.address, one_rtt_ping_received.from);
    const server_short_route = try server_lifecycle.routeDatagram(ping_path, one_rtt_ping_received.data);
    try require(server_short_route.connection_id == 51);
    try require(std.mem.eql(u8, server_short_route.destination_connection_id.asSlice(), &server_scid));
    try server.processProtectedShortDatagram(5, secrets.client, server_scid.len, one_rtt_ping_received.data);
    try require(server.pendingAckLargest(.application) == 0);

    const one_rtt_ack = (try server.pollProtectedShortDatagram(
        6,
        &client_scid,
        secrets.server,
    )) orelse return error.UnexpectedState;
    defer allocator.free(one_rtt_ack);
    try server_socket.send(io, &one_rtt_ping_received.from, one_rtt_ack);

    const one_rtt_ack_received = try client_socket.receiveTimeout(io, &client_receive_buf, receiveTimeout());
    const ack_path = try udp4Tuple(client_socket.address, one_rtt_ack_received.from);
    const client_short_route = try client_lifecycle.routeDatagram(ack_path, one_rtt_ack_received.data);
    try require(client_short_route.connection_id == 41);
    try require(std.mem.eql(u8, client_short_route.destination_connection_id.asSlice(), &client_scid));
    try client.processProtectedShortDatagram(7, secrets.server, client_scid.len, one_rtt_ack_received.data);
    try require(client.bytesInFlight(.application) == 0);

    std.debug.print("[udp-protected] client_port={} server_port={} initial_client_bytes={} initial_server_bytes={} ping_bytes={} ack_bytes={} server_route={} client_route={} client_inflight={}\n", .{
        client_local.port,
        server_local.port,
        client_initial.len,
        server_initial.len,
        one_rtt_ping.len,
        one_rtt_ack.len,
        server_short_route.connection_id,
        client_short_route.connection_id,
        client.bytesInFlight(.application),
    });
}
