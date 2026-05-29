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
    return .{
        .data = received.data,
        .path = try udp4Tuple(socket.address, received.from),
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
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const client_handle: u64 = 41;
    const server_handle: u64 = 51;
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try quicz.Connection.init(allocator, .client, .{});
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{});
    defer server.deinit();

    try client.installHandshakeTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });
    try server.installHandshakeTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try require(client.hasHandshakeProtectionKeys());
    try require(server.hasHandshakeProtectionKeys());
    try server.validatePeerAddress();

    var client_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer client_lifecycle.deinit();
    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer server_lifecycle.deinit();

    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    const server_path = try udp4Tuple(server_socket.address, client_socket.address);
    try client_lifecycle.registerConnectionId(client_handle, &client_dcid, client_path, .{
        .active_migration_disabled = true,
    });
    try server_lifecycle.registerConnectionId(server_handle, &server_dcid, server_path, .{
        .active_migration_disabled = true,
    });

    try server.sendCryptoInSpace(.handshake, "server handshake keys");
    const server_handshake = (try server_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        server_handle,
        &server,
        0,
        &client_dcid,
        &server_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_handshake);
    try require(server.sentPacketCount(.handshake) == 1);
    try server_socket.send(io, &client_socket.address, server_handshake);

    var server_receive_buf: [1500]u8 = undefined;
    var client_receive_buf: [1500]u8 = undefined;
    const server_handshake_received = try receiveDatagram(io, &client_socket, &client_receive_buf);
    const client_handshake_route = try client_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        client_handle,
        &client,
        server_handshake_received.path,
        1,
        server_handshake_received.data,
    );
    try require(client_handshake_route.connection_id == client_handle);
    try require(std.mem.eql(u8, client_handshake_route.destination_connection_id.asSlice(), &client_dcid));
    try require(client.pendingAckLargest(.handshake) == 0);
    try require(client.nextPeerPacketNumber(.handshake) == 1);

    var client_crypto_buf: [64]u8 = undefined;
    const client_received_crypto = try readCryptoRequired(&client, .handshake, &client_crypto_buf);
    try require(std.mem.eql(u8, client_received_crypto, "server handshake keys"));

    const client_ack = (try client_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        client_handle,
        &client,
        2,
        &server_dcid,
        &client_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_ack);
    try require(client.pendingAckLargest(.handshake) == null);
    try client_socket.send(io, &server_socket.address, client_ack);

    const client_ack_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const server_ack_route = try server_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        server_handle,
        &server,
        client_ack_received.path,
        3,
        client_ack_received.data,
    );
    try require(server_ack_route.connection_id == server_handle);
    try require(std.mem.eql(u8, server_ack_route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.sentPacketCount(.handshake) == 0);
    try require(server.bytesInFlight(.handshake) == 0);

    try client.sendCryptoInSpace(.handshake, "client handshake keys");
    const client_handshake = (try client_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        client_handle,
        &client,
        4,
        &server_dcid,
        &client_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_handshake);
    try require(client.sentPacketCount(.handshake) == 1);
    try client_socket.send(io, &server_socket.address, client_handshake);

    const client_handshake_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const server_handshake_route = try server_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        server_handle,
        &server,
        client_handshake_received.path,
        5,
        client_handshake_received.data,
    );
    try require(server_handshake_route.connection_id == server_handle);
    try require(std.mem.eql(u8, server_handshake_route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.pendingAckLargest(.handshake) == 1);
    try require(server.nextPeerPacketNumber(.handshake) == 2);

    var server_crypto_buf: [64]u8 = undefined;
    const server_received_crypto = try readCryptoRequired(&server, .handshake, &server_crypto_buf);
    try require(std.mem.eql(u8, server_received_crypto, "client handshake keys"));

    const server_ack = (try server_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        server_handle,
        &server,
        6,
        &client_dcid,
        &server_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_ack);
    try require(server.pendingAckLargest(.handshake) == null);
    try server_socket.send(io, &client_socket.address, server_ack);

    const server_ack_received = try receiveDatagram(io, &client_socket, &client_receive_buf);
    const client_ack_route = try client_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        client_handle,
        &client,
        server_ack_received.path,
        7,
        server_ack_received.data,
    );
    try require(client_ack_route.connection_id == client_handle);
    try require(std.mem.eql(u8, client_ack_route.destination_connection_id.asSlice(), &client_dcid));
    try require(client.bytesInFlight(.handshake) == 0);
    try require(client_lifecycle.recoveryTimerCount() == 0);
    try require(server_lifecycle.recoveryTimerCount() == 0);

    std.debug.print("[udp-handshake-keys] client_port={} server_port={} server_crypto_bytes={} client_ack_bytes={} client_crypto_bytes={} server_ack_bytes={} client_received=\"{s}\" server_received=\"{s}\" client_inflight={} server_inflight={}\n", .{
        client_local.port,
        server_local.port,
        server_handshake.len,
        client_ack.len,
        client_handshake.len,
        server_ack.len,
        client_received_crypto,
        server_received_crypto,
        client.bytesInFlight(.handshake),
        server.bytesInFlight(.handshake),
    });
}
