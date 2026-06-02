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

fn expectError(expected: anyerror, result: anytype) !void {
    _ = result catch |err| {
        if (err == expected) return;
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
    return .{
        .data = received.data,
        .path = try udp4Tuple(socket.address, received.from),
    };
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
    const rejecting_handle: u64 = 61;
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try quicz.Connection.init(allocator, .client, .{});
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{});
    defer server.deinit();
    var rejecting_server = try quicz.Connection.init(allocator, .server, .{});
    defer rejecting_server.deinit();

    try client.installZeroRttTrafficSecrets(.{ .local = secrets.client.secret });
    try server.installZeroRttTrafficSecrets(.{ .peer = secrets.client.secret });
    try rejecting_server.installZeroRttTrafficSecrets(.{ .peer = secrets.client.secret });
    try require(client.hasLocalZeroRttProtectionKey());
    try require(server.hasPeerZeroRttProtectionKey());
    try require(rejecting_server.hasPeerZeroRttProtectionKey());
    try server.acceptZeroRtt();

    var client_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer client_lifecycle.deinit();
    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer server_lifecycle.deinit();
    var rejecting_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer rejecting_lifecycle.deinit();

    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    const server_path = try udp4Tuple(server_socket.address, client_socket.address);
    try client_lifecycle.registerConnectionId(client_handle, &client_dcid, client_path, .{
        .active_migration_disabled = true,
    });
    try server_lifecycle.registerConnectionId(server_handle, &server_dcid, server_path, .{
        .active_migration_disabled = true,
    });
    try rejecting_lifecycle.registerConnectionId(rejecting_handle, &server_dcid, server_path, .{
        .active_migration_disabled = true,
    });

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "udp early data", true);
    const early = (try client_lifecycle.pollProtectedZeroRttDatagramWithInstalledKeys(
        client_handle,
        &client,
        0,
        &server_dcid,
        &client_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(early);

    try expectError(
        error.InvalidPacket,
        rejecting_lifecycle.processRoutedProtectedZeroRttDatagramWithInstalledKeys(
            rejecting_handle,
            &rejecting_server,
            server_path,
            1,
            early,
        ),
    );
    try require(rejecting_server.nextPeerPacketNumber(.application) == 0);
    try require(rejecting_server.pendingAckLargest(.application) == null);

    try client_socket.send(io, &server_socket.address, early);

    var server_receive_buf: [1500]u8 = undefined;
    var client_receive_buf: [1500]u8 = undefined;
    const early_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const early_route = try server_lifecycle.processRoutedProtectedZeroRttDatagramWithInstalledKeys(
        server_handle,
        &server,
        early_received.path,
        2,
        early_received.data,
    );
    try require(early_route.connection_id == server_handle);
    try require(std.mem.eql(u8, early_route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.pendingAckLargest(.application) == 0);
    try require(server.nextPeerPacketNumber(.application) == 1);
    const server_accepted_early_packet = server.nextPeerPacketNumber(.application) == 1;
    const server_early_ack_largest = server.pendingAckLargest(.application).?;

    var read_buf: [32]u8 = undefined;
    const read_len = (try server.recvOnStream(stream_id, &read_buf)) orelse return error.UnexpectedState;
    try require(std.mem.eql(u8, read_buf[0..read_len], "udp early data"));
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
    try require(!client.hasLocalZeroRttProtectionKey());
    const client_zero_keys_discarded = !client.hasLocalZeroRttProtectionKey();
    try require(server.hasPeerZeroRttProtectionKey());
    const server_zero_keys_before_1rtt = server.hasPeerZeroRttProtectionKey();

    const ack = (try server_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        server_handle,
        &server,
        3,
        &client_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(ack);
    try server_socket.send(io, &client_socket.address, ack);

    const ack_received = try receiveDatagram(io, &client_socket, &client_receive_buf);
    const ack_route = try client_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        client_handle,
        &client,
        ack_received.path,
        4,
        ack_received.data,
    );
    try require(ack_route.connection_id == client_handle);
    try require(std.mem.eql(u8, ack_route.destination_connection_id.asSlice(), &client_dcid));
    try require(client.bytesInFlight(.application) == 0);
    const post_ack_inflight = client.bytesInFlight(.application);
    try require(client_lifecycle.recoveryTimerCount() == 0);

    try client.sendPing();
    const one_rtt_ping = (try client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        client_handle,
        &client,
        5,
        &server_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(one_rtt_ping);
    try client_socket.send(io, &server_socket.address, one_rtt_ping);

    const ping_received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const ping_route = try server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        server_handle,
        &server,
        ping_received.path,
        6,
        ping_received.data,
    );
    try require(ping_route.connection_id == server_handle);
    try require(std.mem.eql(u8, ping_route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.pendingAckLargest(.application) == 1);
    try require(!server.hasPeerZeroRttProtectionKey());

    std.debug.print("[udp-zero-rtt] client_port={} server_port={} early_bytes={} ack_bytes={} ping_bytes={} stream_id={} received=\"{s}\" post_ack_inflight={} rejected_before_accept={} accepted_after_accept={} server_early_ack_largest={} client_zero_keys_discarded={} server_zero_keys_before_1rtt={} server_zero_keys_discarded={}\n", .{
        client_local.port,
        server_local.port,
        early.len,
        ack.len,
        one_rtt_ping.len,
        stream_id,
        read_buf[0..read_len],
        post_ack_inflight,
        rejecting_server.nextPeerPacketNumber(.application) == 0,
        server_accepted_early_packet,
        server_early_ack_largest,
        client_zero_keys_discarded,
        server_zero_keys_before_1rtt,
        !server.hasPeerZeroRttProtectionKey(),
    });
}
