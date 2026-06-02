const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

const ReceivedRoute = struct {
    path: quicz.endpoint.Udp4Tuple,
    data: []const u8,
    route: quicz.endpoint.RouteResult,
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

fn receiveRoute(
    io: std.Io,
    lifecycle: *const quicz.EndpointConnectionLifecycle,
    socket: *std.Io.net.Socket,
    receive_buf: []u8,
) !ReceivedRoute {
    const received = try socket.receiveTimeout(io, receive_buf, receiveTimeout());
    const path = try udp4Tuple(socket.address, received.from);
    return .{
        .path = path,
        .data = received.data,
        .route = try lifecycle.routeDatagram(path, received.data),
    };
}

fn receiveProtectedShortDatagram(
    io: std.Io,
    lifecycle: *quicz.EndpointConnectionLifecycle,
    connection_id: u64,
    connection: *quicz.Connection,
    socket: *std.Io.net.Socket,
    receive_buf: []u8,
    now_millis: i64,
    keys: quicz.protection.Aes128PacketProtectionKeys,
) !ReceivedRoute {
    const received = try socket.receiveTimeout(io, receive_buf, receiveTimeout());
    const path = try udp4Tuple(socket.address, received.from);
    return .{
        .path = path,
        .data = received.data,
        .route = try lifecycle.processRoutedProtectedShortDatagram(
            connection_id,
            connection,
            path,
            now_millis,
            keys,
            received.data,
        ),
    };
}

fn receiveRetiredToken(
    io: std.Io,
    lifecycle: *const quicz.EndpointConnectionLifecycle,
    socket: *std.Io.net.Socket,
    receive_buf: []u8,
) ![quicz.packet.stateless_reset_token_len]u8 {
    const received = try socket.receiveTimeout(io, receive_buf, receiveTimeout());
    const path = try udp4Tuple(socket.address, received.from);
    if (lifecycle.routeDatagram(path, received.data)) |_| {
        return error.UnexpectedState;
    } else |err| switch (err) {
        error.UnknownConnectionId => {},
        else => return err,
    }
    return (try lifecycle.statelessResetTokenForDatagram(path, received.data)) orelse error.UnexpectedState;
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
    const cid0 = [_]u8{ 0xc0, 0xff, 0xee, 0x00 };
    const cid1 = [_]u8{ 0xc0, 0xff, 0xee, 0x01 };
    const token0 = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const token1 = [_]u8{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
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

    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    const server_path = try udp4Tuple(server_socket.address, client_socket.address);
    try client_lifecycle.registerConnectionId(41, &client_dcid, client_path, .{
        .active_migration_disabled = true,
    });
    try server_lifecycle.registerConnectionId(51, &server_dcid, server_path, .{
        .active_migration_disabled = true,
    });

    const issued0 = try server_lifecycle.issueConnectionIdRoute(51, &server, &cid0, server_path, token0, 0, .{
        .active_migration_disabled = true,
    });
    const sequence0 = issued0.sequence_number;
    try require(issued0.retired_count == 0);

    const new0 = (try server.pollProtectedShortDatagram(0, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer allocator.free(new0);
    try server_socket.send(io, &client_socket.address, new0);

    var client_receive_buf: [1500]u8 = undefined;
    var server_receive_buf: [1500]u8 = undefined;
    const new0_received = try receiveProtectedShortDatagram(
        io,
        &client_lifecycle,
        41,
        &client,
        &client_socket,
        &client_receive_buf,
        1,
        secrets.server,
    );
    try require(new0_received.route.connection_id == 41);
    try require(std.mem.eql(u8, new0_received.route.destination_connection_id.asSlice(), &client_dcid));
    try require(client.pendingAckLargest(.application) == 0);

    const ack0 = (try client.pollProtectedShortDatagram(2, &server_dcid, secrets.client)) orelse return error.UnexpectedState;
    defer allocator.free(ack0);
    try client_socket.send(io, &server_socket.address, ack0);

    const ack0_received = try receiveProtectedShortDatagram(
        io,
        &server_lifecycle,
        51,
        &server,
        &server_socket,
        &server_receive_buf,
        3,
        secrets.client,
    );
    try require(ack0_received.route.connection_id == 51);
    try require(std.mem.eql(u8, ack0_received.route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.bytesInFlight(.application) == 0);

    const cid0_probe = [_]u8{ 0x40, 0xc0, 0xff, 0xee, 0x00, 0x01 };
    try client_socket.send(io, &server_socket.address, &cid0_probe);
    const cid0_probe_received = try receiveRoute(io, &server_lifecycle, &server_socket, &server_receive_buf);
    try require(cid0_probe_received.route.connection_id == 51);
    try require(cid0_probe_received.route.sequence_number.? == sequence0);

    const replacement = try server_lifecycle.issueConnectionIdRoute(51, &server, &cid1, server_path, token1, 1, .{
        .active_migration_disabled = true,
    });
    const sequence1 = replacement.sequence_number;
    try require(replacement.sequence_number == sequence1);
    try require(replacement.retire_prior_to == 1);
    try require(replacement.retired_count == 1);

    const new1 = (try server.pollProtectedShortDatagram(4, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer allocator.free(new1);
    try server_socket.send(io, &client_socket.address, new1);

    const new1_received = try receiveProtectedShortDatagram(
        io,
        &client_lifecycle,
        41,
        &client,
        &client_socket,
        &client_receive_buf,
        5,
        secrets.server,
    );
    try require(new1_received.route.connection_id == 41);
    try require(client.pendingAckLargest(.application) == 1);

    try client_socket.send(io, &server_socket.address, &cid0_probe);
    const retired_token0 = try receiveRetiredToken(io, &server_lifecycle, &server_socket, &server_receive_buf);
    try require(std.mem.eql(u8, &retired_token0, &token0));

    const retire = (try client.pollProtectedShortDatagram(6, &cid1, secrets.client)) orelse return error.UnexpectedState;
    defer allocator.free(retire);
    try require(client.pendingAckLargest(.application) == null);
    try client_socket.send(io, &server_socket.address, retire);

    const retire_received = try receiveProtectedShortDatagram(
        io,
        &server_lifecycle,
        51,
        &server,
        &server_socket,
        &server_receive_buf,
        7,
        secrets.client,
    );
    try require(retire_received.route.connection_id == 51);
    try require(retire_received.route.sequence_number.? == sequence1);
    try require(std.mem.eql(u8, retire_received.route.destination_connection_id.asSlice(), &cid1));
    try require(server.localConnectionIdCount() == 1);
    try require(server.pendingAckLargest(.application) == 1);

    const cid1_probe = [_]u8{ 0x40, 0xc0, 0xff, 0xee, 0x01, 0x01 };
    try require((try server_lifecycle.statelessResetTokenForDatagram(server_path, &cid1_probe)) == null);
    try client_socket.send(io, &server_socket.address, &cid1_probe);
    const cid1_probe_received = try receiveRoute(io, &server_lifecycle, &server_socket, &server_receive_buf);
    try require(cid1_probe_received.route.connection_id == 51);
    try require(cid1_probe_received.route.sequence_number.? == sequence1);
    try require(std.mem.eql(u8, cid1_probe_received.route.destination_connection_id.asSlice(), &cid1));

    const ack1 = (try server.pollProtectedShortDatagram(8, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer allocator.free(ack1);
    try server_socket.send(io, &client_socket.address, ack1);

    const ack1_received = try receiveProtectedShortDatagram(
        io,
        &client_lifecycle,
        41,
        &client,
        &client_socket,
        &client_receive_buf,
        9,
        secrets.server,
    );
    try require(ack1_received.route.connection_id == 41);
    try require(client.bytesInFlight(.application) == 0);

    std.debug.print("[udp-connection-ids] client_port={} server_port={} new0_bytes={} new1_bytes={} retire_bytes={} route0_seq={} active_seq={} active_probe_seq={} local_active={} retired0_token=true client_inflight={}\n", .{
        client_local.port,
        server_local.port,
        new0.len,
        new1.len,
        retire.len,
        sequence0,
        retire_received.route.sequence_number.?,
        cid1_probe_received.route.sequence_number.?,
        server.localConnectionIdCount(),
        client.bytesInFlight(.application),
    });
}
