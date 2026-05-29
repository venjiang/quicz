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
    const path = try udp4Tuple(socket.address, received.from);
    return .{
        .data = received.data,
        .path = path,
    };
}

fn expectInvalidSecondUpdate(conn: *quicz.Connection) !void {
    if (conn.initiateOneRttKeyUpdate()) |_| {
        return error.UnexpectedState;
    } else |err| switch (err) {
        error.InvalidPacket => {},
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

    const client_local = try udp4Address(client_socket.address);
    const server_local = try udp4Address(server_socket.address);
    try require(client_local.port != 0);
    try require(server_local.port != 0);
    try require(client_local.port != server_local.port);

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try quicz.Connection.init(allocator, .client, .{});
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    try client.installOneRttTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });
    try server.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try client.confirmHandshake();
    try server.confirmHandshake();

    var client_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer client_lifecycle.deinit();
    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer server_lifecycle.deinit();

    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    const server_path = try udp4Tuple(server_socket.address, client_socket.address);
    try client_lifecycle.registerConnectionId(41, &client_dcid, client_path, .{
        .active_migration_disabled = true,
    });
    try server_lifecycle.registerConnectionId(51, &server_dcid, server_path, .{
        .active_migration_disabled = true,
    });

    try client.initiateOneRttKeyUpdate();
    try require(client.localOneRttKeyPhase().?);
    try expectInvalidSecondUpdate(&client);

    try client.sendPing();
    const key_update_ping = (try client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        41,
        &client,
        0,
        &server_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(key_update_ping);
    const ping_key_phase = try quicz.protection.peekShortPacketKeyPhaseAes128(secrets.client.hp, key_update_ping, server_dcid.len);
    try require(ping_key_phase);
    try client_socket.send(io, &server_socket.address, key_update_ping);

    var server_receive_buf: [1500]u8 = undefined;
    var client_receive_buf: [1500]u8 = undefined;

    const ping_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const ping_route = try server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        51,
        &server,
        ping_received.path,
        1,
        ping_received.data,
    );
    try require(ping_route.connection_id == 51);
    try require(std.mem.eql(u8, ping_route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.peerOneRttKeyPhase().?);
    try require(server.pendingAckLargest(.application) == 0);

    const ack = (try server_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        51,
        &server,
        2,
        &client_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(ack);
    const ack_key_phase = try quicz.protection.peekShortPacketKeyPhaseAes128(secrets.server.hp, ack, client_dcid.len);
    try require(!ack_key_phase);
    try server_socket.send(io, &client_socket.address, ack);

    const ack_received = try receiveDatagram(io, &client_socket, &client_receive_buf);
    const ack_route = try client_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        41,
        &client,
        ack_received.path,
        3,
        ack_received.data,
    );
    try require(ack_route.connection_id == 41);
    try require(std.mem.eql(u8, ack_route.destination_connection_id.asSlice(), &client_dcid));
    try require(client.bytesInFlight(.application) == 0);

    try client.initiateOneRttKeyUpdate();
    try require(client.localOneRttKeyPhase().? == false);

    std.debug.print("[udp-key-update] client_port={} server_port={} ping_bytes={} ack_bytes={} ping_key_phase={} ack_key_phase={} server_peer_phase={} client_next_phase={} client_inflight={}\n", .{
        client_local.port,
        server_local.port,
        key_update_ping.len,
        ack.len,
        ping_key_phase,
        ack_key_phase,
        server.peerOneRttKeyPhase().?,
        client.localOneRttKeyPhase().?,
        client.bytesInFlight(.application),
    });
}
