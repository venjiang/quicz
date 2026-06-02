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

fn sendClientPacket(
    io: std.Io,
    allocator: std.mem.Allocator,
    client: *quicz.Connection,
    server_lifecycle: *quicz.EndpointConnectionLifecycle,
    server: *quicz.Connection,
    client_socket: *std.Io.net.Socket,
    server_socket: *std.Io.net.Socket,
    now_millis: i64,
    server_dcid: []const u8,
    keys: quicz.protection.Aes128PacketProtectionKeys,
    receive_buf: []u8,
) !usize {
    const packet = (try client.pollProtectedShortDatagram(now_millis, server_dcid, keys)) orelse return error.UnexpectedState;
    defer allocator.free(packet);
    try client_socket.send(io, &server_socket.address, packet);

    const received = try receiveDatagram(io, server_socket, receive_buf);
    const route = try server_lifecycle.processRoutedProtectedShortDatagram(
        51,
        server,
        received.path,
        now_millis + 1,
        keys,
        received.data,
    );
    try require(route.connection_id == 51);
    try require(std.mem.eql(u8, route.destination_connection_id.asSlice(), server_dcid));
    return received.data.len;
}

fn sendServerPacket(
    io: std.Io,
    allocator: std.mem.Allocator,
    server: *quicz.Connection,
    client_lifecycle: *quicz.EndpointConnectionLifecycle,
    client: *quicz.Connection,
    server_socket: *std.Io.net.Socket,
    client_socket: *std.Io.net.Socket,
    now_millis: i64,
    client_dcid: []const u8,
    keys: quicz.protection.Aes128PacketProtectionKeys,
    receive_buf: []u8,
) !usize {
    const packet = (try server.pollProtectedShortDatagram(now_millis, client_dcid, keys)) orelse return error.UnexpectedState;
    defer allocator.free(packet);
    try server_socket.send(io, &client_socket.address, packet);

    const received = try receiveDatagram(io, client_socket, receive_buf);
    const route = try client_lifecycle.processRoutedProtectedShortDatagram(
        41,
        client,
        received.path,
        now_millis + 1,
        keys,
        received.data,
    );
    try require(route.connection_id == 41);
    try require(std.mem.eql(u8, route.destination_connection_id.asSlice(), client_dcid));
    return received.data.len;
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

    var client = try quicz.Connection.init(allocator, .client, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 5,
    });
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 5,
    });
    defer server.deinit();
    try server.validatePeerAddress();
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

    var server_receive_buf: [1500 + 8]u8 = undefined;
    var client_receive_buf: [1500 + 8]u8 = undefined;
    var read_buf: [8]u8 = undefined;

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello", false);
    const stream_packet = try sendClientPacket(
        io,
        allocator,
        &client,
        &server_lifecycle,
        &server,
        &client_socket,
        &server_socket,
        0,
        &server_dcid,
        secrets.client,
        &server_receive_buf,
    );

    try expectFlowControlBlocked(client.sendOnStream(stream_id, "!", false));
    const blocked_packet = try sendClientPacket(
        io,
        allocator,
        &client,
        &server_lifecycle,
        &server,
        &client_socket,
        &server_socket,
        2,
        &server_dcid,
        secrets.client,
        &server_receive_buf,
    );
    try require(server.peerStreamDataBlockedLimit(stream_id) == 5);

    const first_len = (try server.recvOnStream(stream_id, &read_buf)) orelse return error.UnexpectedState;
    try require(std.mem.eql(u8, read_buf[0..first_len], "hello"));

    const max_data_packet = try sendServerPacket(
        io,
        allocator,
        &server,
        &client_lifecycle,
        &client,
        &server_socket,
        &client_socket,
        4,
        &client_dcid,
        secrets.server,
        &client_receive_buf,
    );

    const max_stream_packet = try sendServerPacket(
        io,
        allocator,
        &server,
        &client_lifecycle,
        &client,
        &server_socket,
        &client_socket,
        6,
        &client_dcid,
        secrets.server,
        &client_receive_buf,
    );

    try client.sendOnStream(stream_id, "!", true);
    const resumed_packet = try sendClientPacket(
        io,
        allocator,
        &client,
        &server_lifecycle,
        &server,
        &client_socket,
        &server_socket,
        8,
        &server_dcid,
        secrets.client,
        &server_receive_buf,
    );

    const resumed_len = (try server.recvOnStream(stream_id, &read_buf)) orelse return error.UnexpectedState;
    try require(std.mem.eql(u8, read_buf[0..resumed_len], "!"));
    const final_size = (try server.recvStreamFinalSize(stream_id)) orelse return error.UnexpectedState;
    try require(final_size == 6);
    try require(try server.recvStreamFinished(stream_id));

    const final_ack = try sendServerPacket(
        io,
        allocator,
        &server,
        &client_lifecycle,
        &client,
        &server_socket,
        &client_socket,
        10,
        &client_dcid,
        secrets.server,
        &client_receive_buf,
    );
    try require(client.bytesInFlight(.application) == 0);

    std.debug.print("[udp-flow] client_port={} server_port={} stream={} stream_packet={} blocked_packet={} max_data_packet={} max_stream_packet={} resumed_packet={} final_ack={} peer_blocked={} final_size={} finished={} client_inflight={}\n", .{
        client_local.port,
        server_local.port,
        stream_id,
        stream_packet,
        blocked_packet,
        max_data_packet,
        max_stream_packet,
        resumed_packet,
        final_ack,
        server.peerStreamDataBlockedLimit(stream_id).?,
        final_size,
        try server.recvStreamFinished(stream_id),
        client.bytesInFlight(.application),
    });
}
