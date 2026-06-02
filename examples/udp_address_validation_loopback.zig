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

fn reversePath(path: quicz.endpoint.Udp4Tuple) quicz.endpoint.Udp4Tuple {
    return .{
        .local = path.remote,
        .remote = path.local,
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
    const connection_handle: u64 = 91;
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);
    const token_secret: quicz.address_validation_token.Secret = [_]u8{0x5c} ** quicz.address_validation_token.secret_len;
    const rotated_token_secret: quicz.address_validation_token.Secret = [_]u8{0x6d} ** quicz.address_validation_token.secret_len;
    const token_nonce: quicz.address_validation_token.Nonce = [_]u8{0x5a} ** quicz.address_validation_token.nonce_len;
    const v2_token_nonce: quicz.address_validation_token.Nonce = [_]u8{0x6b} ** quicz.address_validation_token.nonce_len;

    var server = try quicz.Connection.init(allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();
    var client = try quicz.Connection.init(allocator, .client, .{});
    defer client.deinit();

    var client_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer client_lifecycle.deinit();

    const server_path = try udp4Tuple(server_socket.address, client_socket.address);
    const client_receive_path = reversePath(server_path);
    try client_lifecycle.registerConnectionId(connection_handle, &client_dcid, client_receive_path, .{});

    var token_policy = quicz.endpoint.AddressValidationPolicy.init(allocator, token_secret, .{
        .max_previous_secrets = 1,
        .max_replay_entries = 8,
    });
    defer token_policy.deinit();

    try server.sendHandshakeDone();
    try require(server.packetNumberSpaceDiscarded(.handshake));
    const address_token = try token_policy.issueTokenForPath(
        allocator,
        .new_token,
        10,
        60_000,
        server_path,
        token_nonce,
    );
    defer allocator.free(address_token);
    try server.issueNewToken(address_token);
    try token_policy.rotateSecret(rotated_token_secret);
    try require(token_policy.previousSecretCount() == 1);

    const handshake_done = (try server.pollProtectedShortDatagram(11, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer allocator.free(handshake_done);
    try server_socket.send(io, &client_socket.address, handshake_done);

    var client_receive_buf: [1500]u8 = undefined;
    const handshake_received = try client_socket.receiveTimeout(io, &client_receive_buf, receiveTimeout());
    const handshake_path = try udp4Tuple(client_socket.address, handshake_received.from);
    const handshake_route = try client_lifecycle.processRoutedProtectedShortDatagram(
        connection_handle,
        &client,
        handshake_path,
        12,
        secrets.server,
        handshake_received.data,
    );
    try require(handshake_route.connection_id == connection_handle);
    try require(std.mem.eql(u8, handshake_route.destination_connection_id.asSlice(), &client_dcid));
    try require(client.handshakeConfirmed());

    const new_token = (try server.pollProtectedShortDatagram(13, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer allocator.free(new_token);
    try server_socket.send(io, &client_socket.address, new_token);

    const token_received = try client_socket.receiveTimeout(io, &client_receive_buf, receiveTimeout());
    const token_path = try udp4Tuple(client_socket.address, token_received.from);
    const token_route = try client_lifecycle.processRoutedProtectedShortDatagram(
        connection_handle,
        &client,
        token_path,
        14,
        secrets.server,
        token_received.data,
    );
    try require(token_route.connection_id == connection_handle);
    try require(std.mem.eql(u8, token_route.destination_connection_id.asSlice(), &client_dcid));
    const stored_token = client.latestNewToken() orelse return error.UnexpectedState;

    const changed_client_port = if (client_local.port == std.math.maxInt(u16)) @as(u16, 1) else client_local.port + 1;
    const changed_path = quicz.endpoint.Udp4Tuple{
        .local = server_path.local,
        .remote = quicz.endpoint.Udp4Address.init(client_local.octets, changed_client_port),
    };
    if (token_policy.validateTokenForPath(.new_token, 15, changed_path, stored_token)) |_| {
        return error.UnexpectedState;
    } else |err| switch (err) {
        error.InvalidToken => {},
        else => return err,
    }

    const validation = try token_policy.validateTokenForPath(.new_token, 16, server_path, stored_token);
    try require(validation.originating_version == .v1);
    var secret_set = try token_policy.exportSecretSet(allocator);
    defer secret_set.deinit(allocator);
    var replay_snapshot = try token_policy.exportReplayFilter(allocator);
    defer replay_snapshot.deinit(allocator);
    var restored_policy = try quicz.endpoint.AddressValidationPolicy.initWithSecretSetAndReplayFilter(allocator, secret_set, replay_snapshot, .{
        .max_previous_secrets = 1,
        .max_replay_entries = 8,
    });
    defer restored_policy.deinit();
    try require(restored_policy.replayFilterEntryCount() == 1);

    var future_server = try quicz.Connection.init(allocator, .server, .{});
    defer future_server.deinit();
    try future_server.sendPing();
    var future_out: [16]u8 = undefined;
    try require((try future_server.pollTx(17, &future_out)) == null);
    try future_server.validatePeerAddress();
    const future_ping = (try future_server.pollTx(18, &future_out)) orelse return error.UnexpectedState;

    var replay_rejected = false;
    if (restored_policy.validateTokenForPath(.new_token, 19, server_path, stored_token)) |_| {
        return error.UnexpectedState;
    } else |err| switch (err) {
        error.TokenReplay => replay_rejected = true,
        else => return err,
    }
    try require(replay_rejected);

    const v2_token = try token_policy.issueTokenForPathForVersion(
        allocator,
        .new_token,
        .v2,
        20,
        60_000,
        server_path,
        v2_token_nonce,
    );
    defer allocator.free(v2_token);
    var version_rejected = false;
    if (token_policy.validateTokenForPathForVersion(.new_token, .v1, 21, server_path, v2_token)) |_| {
        return error.UnexpectedState;
    } else |err| switch (err) {
        error.InvalidToken => version_rejected = true,
        else => return err,
    }
    try require(version_rejected);
    const v2_validation = try token_policy.validateTokenForPathForVersion(.new_token, .v2, 22, server_path, v2_token);
    try require(v2_validation.originating_version == .v2);

    std.debug.print("[udp-address] client_port={} server_port={} handshake_bytes={} token_bytes={} stored_token_len={} route={} future_ping_bytes={} previous_secrets={} replay_entries={} replay_rejected={} version_rejected={} v2_validated={}\n", .{
        client_local.port,
        server_local.port,
        handshake_done.len,
        new_token.len,
        stored_token.len,
        token_route.connection_id,
        future_ping.len,
        secret_set.previous_secrets.len,
        replay_snapshot.fingerprints.len,
        replay_rejected,
        version_rejected,
        v2_validation.originating_version == .v2,
    });
}
