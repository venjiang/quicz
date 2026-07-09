//! TLS-owned path validation over loopback UDP (RFC 9000 §8.2).
//!
//! 在 TLS-owned UDP 路径上验证 path validation：用 Tls13Backend 完成真实
//! TLS 1.3 握手安装 1-RTT keys，client 从新 socket 发 1-RTT PING 触发
//! server 检测路径变化（NAT 重绑定模拟），server 发 PATH_CHALLENGE 到新
//! 路径，client 回 PATH_RESPONSE，server 验证后手动 commit lifecycle
//! route path update（路径迁移）。
//!
//! 组合参考：
//!   - tls13_udp_loopback.zig / tls13_stateless_reset_loopback.zig（Tls13Backend 握手）
//!   - udp_path_validation_loopback.zig（mock-key path validation + route commit）
//!
//! Core 缺口：lifecycle 没有提供 installed-key + 自动 path update commit
//! 的组合函数。`processRoutedProtectedShortDatagramWithInstalledKeys` /
//! `...OrClose` 只返回 `RouteResult`（含 path_changed），不调用
//! `updateRoutePathFromValidatedDatagramAndResetSpinBit`。本 example 手动
//! 复刻 mock-key `processRoutedProtectedShortDatagramAndUpdatePathOrClose`
//! 的 commit 逻辑：当 `outstandingPathChallengeCount()` 在收到
//! PATH_RESPONSE 后减少时，手动调用
//! `updateRoutePathFromValidatedDatagramAndResetSpinBit` 提交路径迁移。

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const endpoint = quicz.endpoint;

const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
const server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
// PATH_CHALLENGE 携带的 8 字节随机数据（demo 用固定值）。
const challenge_data = [_]u8{ 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb };
const server_handle: u64 = 2;

fn require(condition: bool) !void {
    if (!condition) return error.UnexpectedState;
}

fn recvTimeout() std.Io.Timeout {
    return .{ .duration = .{
        .clock = .awake,
        .raw = std.Io.Duration.fromMilliseconds(2000),
    } };
}

fn udp4Tuple(local: std.Io.net.IpAddress, remote: std.Io.net.IpAddress) !endpoint.Udp4Tuple {
    const local_ip4 = switch (local) {
        .ip4 => |ip4| ip4,
        .ip6 => return error.UnexpectedState,
    };
    const remote_ip4 = switch (remote) {
        .ip4 => |ip4| ip4,
        .ip6 => return error.UnexpectedState,
    };
    return .{
        .local = endpoint.Udp4Address.init(local_ip4.bytes, local_ip4.port),
        .remote = endpoint.Udp4Address.init(remote_ip4.bytes, remote_ip4.port),
    };
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // 两个 client socket：old_client_socket 用于握手，new_client_socket 用于
    // 触发路径迁移（模拟 NAT 重绑定：同一 connection，不同源端口）。
    var old_client_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var old_client_socket = try old_client_address.bind(io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer old_client_socket.close(io);
    var new_client_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var new_client_socket = try new_client_address.bind(io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer new_client_socket.close(io);
    var server_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var server_socket = try server_address.bind(io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer server_socket.close(io);

    const seed = [_]u8{0x55} ** 32;
    const server_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const server_priv = server_kp.secret_key.bytes;
    const cert_der = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    const alpn = [_][]const u8{"hq-interop"};
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try Connection.init(allocator, .client, .{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
        .active_connection_id_limit = 4,
        .max_datagram_size = 8192,
    });
    defer client.deinit();
    var server = try Connection.init(allocator, .server, .{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
        .active_connection_id_limit = 4,
        .max_datagram_size = 8192,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    var client_backend = Tls13Backend.initClient(.{
        .alpn = &alpn,
        .server_name = "example.com",
        .skip_cert_verify = true,
    });
    var server_backend = Tls13Backend.initServer(.{
        .alpn = &alpn,
        .cert_chain_der = &.{&cert_der},
        .private_key_bytes = &server_priv,
        .private_key_algorithm = .ecdsa_p256_sha256,
    });

    var scratch: [8192]u8 = undefined;
    var recv_buf: [2048]u8 = undefined;

    try client.setLocalInitialSourceConnectionId(&client_scid);
    try server.setLocalInitialSourceConnectionId(&server_scid);

    // === TLS 1.3 握手（参考 tls13_udp_loopback.zig），用 old_client_socket ===

    // 1. Client -> ClientHello over UDP.
    _ = try client.driveCryptoBackendInSpace(.initial, client_backend.cryptoBackend(), &scratch);
    const client_dgram = (try client.pollProtectedLongCryptoDatagramInSpace(
        .initial,
        40,
        &original_dcid,
        &client_scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_dgram);
    try old_client_socket.send(io, &server_socket.address, client_dgram);

    // 2. Server receives, processes, drives initial -> handshake keys.
    const recv1 = try server_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try server.processProtectedLongDatagramInSpace(.initial, 41, secrets.client, recv1.data);
    const server_init_prog = try server.driveCryptoBackendInSpace(.initial, server_backend.cryptoBackend(), &scratch);
    try require(server_init_prog.handshake_keys_installed);

    // 3. Server -> ServerHello (Initial) + EE/Cert/CV/Finished (Handshake) over UDP.
    const server_init_dgram = (try server.pollProtectedLongCryptoDatagramInSpace(
        .initial,
        42,
        &client_scid,
        &server_scid,
        &[_]u8{},
        secrets.server,
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_init_dgram);
    try server_socket.send(io, &old_client_socket.address, server_init_dgram);

    _ = try server.driveCryptoBackendInSpace(.handshake, server_backend.cryptoBackend(), &scratch);
    const server_hs_dgram = (try server.pollProtectedHandshakeDatagramWithInstalledKeys(
        43,
        &client_scid,
        &server_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_hs_dgram);
    try server_socket.send(io, &old_client_socket.address, server_hs_dgram);

    // 4. Client receives ServerHello, drives initial (install handshake keys).
    const recv2 = try old_client_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try client.processProtectedLongDatagramInSpace(.initial, 44, secrets.server, recv2.data);
    _ = try client.driveCryptoBackendInSpace(.initial, client_backend.cryptoBackend(), &scratch);

    // 5. Client receives Handshake flight, drives handshake -> client Finished.
    const recv3 = try old_client_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try client.processProtectedHandshakeDatagramWithInstalledKeys(45, recv3.data);
    const client_hs_prog = try client.driveCryptoBackendInSpace(.handshake, client_backend.cryptoBackend(), &scratch);
    try require(client_hs_prog.outbound_bytes > 0);
    const client_hs_dgram = (try client.pollProtectedHandshakeDatagramWithInstalledKeys(
        46,
        &server_scid,
        &client_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_hs_dgram);
    try old_client_socket.send(io, &server_socket.address, client_hs_dgram);

    // 6. Server receives client Finished -> handshake confirmed, 1-RTT keys installed.
    const recv4 = try server_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try server.processProtectedHandshakeDatagramWithInstalledKeys(47, recv4.data);
    const server_hs_drive = try server.driveCryptoBackendInSpace(.handshake, server_backend.cryptoBackend(), &scratch);
    try require(server_hs_drive.handshake_confirmed);
    try require(server.handshakeConfirmed());

    // === 握手完成，1-RTT keys 已安装 ===

    // === 在 server 侧注册 lifecycle CID 路由 ===
    // old_path = server_socket <-> old_client_socket（握手期间使用的路径）。
    // 注册 server_scid（client 发包的 DCID = server 的 SCID）到 old_path。
    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer server_lifecycle.deinit();
    const old_path = try udp4Tuple(server_socket.address, old_client_socket.address);
    try server_lifecycle.registerConnectionId(server_handle, &server_scid, old_path, .{});
    try require(server_lifecycle.routeCount() == 1);

    // === 路径迁移触发：client 从 new_client_socket 发 1-RTT PING 到 server ===
    // 模拟 NAT 重绑定：同一 connection，client 源端口变化，server 检测到新路径。
    try client.sendPing();
    const ping_dgram = (try client.pollProtectedShortDatagramWithInstalledKeys(
        48,
        &server_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(ping_dgram);
    try new_client_socket.send(io, &server_socket.address, ping_dgram);

    // === server 处理 PING，检测 path_changed ===
    const recv_ping = try server_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    const new_path = try udp4Tuple(server_socket.address, recv_ping.from);
    // 验证新路径与旧路径不同（remote 端口变了）。
    try require(old_path.remote.port != new_path.remote.port);

    // installed-key 路径处理：只返回 RouteResult（含 path_changed），不 commit。
    const ping_route = try server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeysOrClose(
        server_handle,
        &server,
        new_path,
        49,
        recv_ping.data,
    );
    try require(ping_route.connection_id == server_handle);
    try require(ping_route.path_changed); // 检测到路径变化
    try require(std.mem.eql(u8, ping_route.destination_connection_id.asSlice(), &server_scid));

    // === server 发送 PATH_CHALLENGE 到新路径（RFC 9000 §8.2.1）===
    try server.sendPathChallenge(challenge_data);
    try require(server.pendingPathChallengeCount() == 1);
    try require(server.outstandingPathChallengeCount() == 0); // poll 前未发送

    // poll 出 PATH_CHALLENGE datagram（可能含 ACK，循环发送所有 pending）。
    // 发送到 new_client_socket（新路径）。
    var challenge_sent = false;
    {
        var pn: i64 = 50;
        while (pn < 54) : (pn += 1) {
            const dgram = (try server.pollProtectedShortDatagramWithInstalledKeys(pn, &client_scid)) orelse break;
            defer allocator.free(dgram);
            try server_socket.send(io, &recv_ping.from, dgram);
            challenge_sent = true;
        }
    }
    try require(challenge_sent);
    try require(server.pendingPathChallengeCount() == 0); // 已 poll 出
    try require(server.outstandingPathChallengeCount() == 1); // 待 PATH_RESPONSE

    // === client 从 new_client_socket 收 PATH_CHALLENGE，处理（自动排队 PATH_RESPONSE）===
    const recv_challenge = try new_client_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try client.processProtectedShortDatagramWithInstalledKeys(51, client_scid.len, recv_challenge.data);

    // === client poll PATH_RESPONSE，从 new_client_socket 发回 server ===
    // 可能含 ACK，循环发送所有 pending。
    var response_sent = false;
    {
        var pn: i64 = 52;
        while (pn < 56) : (pn += 1) {
            const dgram = (try client.pollProtectedShortDatagramWithInstalledKeys(pn, &server_scid)) orelse break;
            defer allocator.free(dgram);
            try new_client_socket.send(io, &server_socket.address, dgram);
            response_sent = true;
        }
    }
    try require(response_sent);

    // === server 收 PATH_RESPONSE，验证路径，手动 commit route path update ===
    // installed-key 路径无自动 commit 封装，手动复刻 mock-key
    // processRoutedProtectedShortDatagramAndUpdatePathOrClose 的 commit 逻辑：
    // 检查 outstandingPathChallengeCount 在处理前后是否减少（PATH_RESPONSE
    // 消耗了 outstanding PATH_CHALLENGE），若是则调用
    // updateRoutePathFromValidatedDatagramAndResetSpinBit 提交路径迁移。
    var response_path: endpoint.Udp4Tuple = undefined;
    var response_route: endpoint.RouteResult = undefined;
    var outstanding_before: usize = 0;
    var outstanding_after: usize = 0;
    var response_bytes: usize = 0;
    var path_validated = false;
    {
        var pn: i64 = 53;
        while (pn < 60) : (pn += 1) {
            const recv = server_socket.receiveTimeout(io, &recv_buf, recvTimeout()) catch break;
            const path = try udp4Tuple(server_socket.address, recv.from);
            outstanding_before = server.outstandingPathChallengeCount();
            const route = try server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeysOrClose(
                server_handle,
                &server,
                path,
                pn,
                recv.data,
            );
            outstanding_after = server.outstandingPathChallengeCount();
            if (outstanding_after < outstanding_before) {
                // PATH_RESPONSE 被处理，outstanding PATH_CHALLENGE 消耗。
                response_path = path;
                response_route = route;
                response_bytes = recv.data.len;
                path_validated = true;
                break;
            }
        }
    }
    try require(path_validated);
    try require(outstanding_before == 1);
    try require(outstanding_after == 0);
    try require(response_route.connection_id == server_handle);
    try require(response_route.path_changed);
    try require(std.mem.eql(u8, response_route.destination_connection_id.asSlice(), &server_scid));

    // 手动 commit route path update（模拟 mock-key 版的自动 commit）。
    // 这将 lifecycle route 从 old_path 迁移到 new_path，并重置 spin-bit。
    const updated_route = try server_lifecycle.updateRoutePathFromValidatedDatagramAndResetSpinBit(
        response_route.destination_connection_id.asSlice(),
        response_path,
        &server,
    );
    try require(updated_route.connection_id == server_handle);

    // 验证 route 已迁移：新路径成为当前路径，routeDatagram 不再报 path_changed。
    // 用 ping_dgram（DCID=server_scid）在新路径上路由，确认 path_changed=false。
    const confirmed_route = try server_lifecycle.routeDatagram(response_path, ping_dgram);
    try require(confirmed_route.connection_id == server_handle);
    try require(!confirmed_route.path_changed); // 新路径已成为当前路径

    std.debug.print("tls13_path_validation_loopback: handshake + PATH_CHALLENGE/RESPONSE exchange + route commit OK\n", .{});
    std.debug.print("  old_client_port={} new_client_port={} server_port={}\n", .{
        old_path.remote.port,
        new_path.remote.port,
        old_path.local.port,
    });
    std.debug.print("  ping_path_changed={} challenge_bytes={} response_bytes={}\n", .{
        ping_route.path_changed,
        recv_challenge.data.len,
        response_bytes,
    });
    std.debug.print("  outstanding_before={} outstanding_after={} route_committed={}\n", .{
        outstanding_before,
        outstanding_after,
        !confirmed_route.path_changed,
    });
}
