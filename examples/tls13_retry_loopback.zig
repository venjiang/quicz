//! TLS-owned Retry over loopback UDP (RFC 9000 §8.1.2 地址验证).
//!
//! 在 TLS-owned UDP 路径上验证 Retry 地址验证交换：用 Tls13Backend 产生
//! 真实 ClientHello Initial，server 用 issueRetryDatagram 发 Retry（含
//! retry_token + retry_scid），client 用 processRetryDatagram 处理 Retry
//! 并记录 retry_scid + token，server 用 validateRetryToken 验证 token
//! 通过并标记 peerAddressValidated。EndpointConnectionLifecycle 注册
//! CID 路由 + switchInitialDestinationConnectionIdAfterRetry 完成端点级
//! DCID 切换（RFC 9000 §8.1.2 / §17.2.5）。
//!
//! 覆盖范围（闭合 docs §94 "Retry on TLS-owned UDP" 端点级缺口的可闭合部分）：
//!   - 真实 Tls13Backend ClientHello Initial over UDP（driveCryptoBackendInSpace
//!     + pollProtectedLongCryptoDatagramInSpace，用 deriveInitialSecrets
//!     (original_dcid) 的 client 初始密钥保护）
//!   - server issueRetryDatagram -> Retry 包 over UDP（retry_token +
//!     retry_scid，Retry Integrity Tag 由 original_dcid 计算）
//!   - EndpointConnectionLifecycle registerConnectionId +
//!     switchInitialDestinationConnectionIdAfterRetry（端点级 DCID 切换）
//!   - client routeDatagram + processRetryDatagram（记录 retry_scid +
//!     retry_token，自动注入后续 Initial token 字段）
//!   - server validateRetryToken -> peerAddressValidated（一次性消费 token）
//!   - retry_secrets 重派生演示（deriveInitialSecrets(retry_scid)，RFC 9000
//!     要求 Retry 后用 retry_scid 作为 DCID 重派生 initial secrets）
//!
//! 未覆盖（core API 缺口，已报告，不在此 example 实现）：
//!   Retry 后重发 ClientHello Initial + 完整 TLS 握手完成。当前 Connection
//!   没有"为 Retry 重置 Initial crypto send offset 到 0 且不 discard 该
//!   space"的公共 API（discardPacketNumberSpaceState 会 discard，不可用；
//!   packetNumberSpace 是私有 fn，外部够不到 crypto_send_offset 指针）。
//!   Tls13Backend 也没有"重新产出 ClientHello 字节"的接口（client_hello_built
//!   单向置位，hs.step() 在 client_wait_server_hello 无数据返回 wait_for_data）。
//!   首次 poll commit 后 ClientHello CRYPTO 字节已从 crypto_send_queue 移除
//!   并释放，crypto_send_offset 前进到 client_hello_len，无法重发。参考
//!   connection.zig:69505 测试同样只覆盖到 processRetryDatagram。补齐需新增
//!   Connection.resetInitialCryptoSendForRetry() 或 Tls13Backend.retryReceived()
//!   重新产出 ClientHello。
//!
//! 组合参考：
//!   - tls13_path_validation_loopback.zig（Tls13Backend 握手 + lifecycle UDP 模板）
//!   - udp_retry_loopback.zig（mock-key Retry + lifecycle switch 流程）
//!   - connection.zig:69505 测试（Tls13Backend Retry connection 级 API 序列）

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const endpoint = quicz.endpoint;

// 常量与 connection.zig:69505 测试一致（RFC 9000 §17.2.5 Retry 场景）。
const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
const server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
const retry_scid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
// Retry 携带的地址验证 token（demo 用固定 opaque bytes）。
const token: []const u8 = "retry-token-for-client-address";
const server_handle: u64 = 2;
const client_handle: u64 = 3;

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

    // === UDP socket setup（参考 tls13_path_validation_loopback.zig）===
    var client_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var client_socket = try client_address.bind(io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer client_socket.close(io);
    var server_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var server_socket = try server_address.bind(io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer server_socket.close(io);

    // === TLS 握手 setup（参考 tls13_path_validation_loopback.zig）===
    const seed = [_]u8{0x55} ** 32;
    const server_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const server_priv = server_kp.secret_key.bytes;
    const cert_der = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    const alpn = [_][]const u8{"hq-interop"};
    // 首份 Initial 用 original_dcid 派生的 initial secrets 保护。
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
    // server 进入"要求地址验证"状态：握手前必须先通过 Retry 验证对端地址。
    try server.validatePeerAddress();

    var client_backend = Tls13Backend.initClient(.{
        .alpn = &alpn,
        .server_name = "example.com",
        .skip_cert_verify = true,
    });
    // server backend 在 Retry 场景不 drive（server 发 Retry 而非 ServerHello）。
    // 保留构造以展示完整 setup；重发 + 握手完成需 core API 缺口补齐后启用。
    var server_backend = Tls13Backend.initServer(.{
        .alpn = &alpn,
        .cert_chain_der = &.{&cert_der},
        .private_key_bytes = &server_priv,
        .private_key_algorithm = .ecdsa_p256_sha256,
    });
    _ = &server_backend;

    var scratch: [8192]u8 = undefined;
    var recv_buf: [2048]u8 = undefined;

    try client.setLocalInitialSourceConnectionId(&client_scid);
    try server.setLocalInitialSourceConnectionId(&server_scid);

    // === EndpointConnectionLifecycle setup（参考 udp_retry_loopback.zig）===
    var client_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer client_lifecycle.deinit();
    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer server_lifecycle.deinit();

    const client_path = try udp4Tuple(client_socket.address, server_socket.address);

    // 注册 client initial SCID 路由（client 发包的 SCID = client_scid）。
    _ = try client_lifecycle.registerClientInitialSourceConnectionId(client_handle, &client_scid, client_path, .{
        .active_migration_disabled = true,
    });

    // === 步骤 1: client driveCryptoBackendInSpace + poll 发 ClientHello Initial ===
    // Tls13Backend 产生真实 ClientHello，用 secrets.client（基于 original_dcid）保护。
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
    try require(client_dgram.len > 0);
    try client_socket.send(io, &server_socket.address, client_dgram);

    // === 步骤 2: server UDP recv 收 ClientHello（不 process，因要发 Retry）===
    // issueRetryDatagram 要求 next_peer_packet_number==0，所以 server 不能
    // processProtectedLongDatagramInSpace（那会前进 next_peer_packet_number）。
    // server 仅从 UDP 包源地址学习 client 路径。
    const recv1 = try server_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    const server_path = try udp4Tuple(server_socket.address, recv1.from);
    try require(server_path.remote.port == client_path.local.port);

    // === 步骤 3: server lifecycle register original_dcid + switch 到 retry_scid ===
    // 注册 original_dcid（client 首份 Initial 的 DCID）到 server 路由。
    try server_lifecycle.registerConnectionId(server_handle, &original_dcid, server_path, .{
        .active_migration_disabled = true,
    });
    try require(server_lifecycle.routeCount() == 1);

    // === 步骤 4: server issueRetryDatagram 发 Retry（含 retry_token + retry_scid）===
    // Retry 包的 DCID=client_scid（client 的 SCID），SCID=retry_scid（server
    // 的新 SCID），token=retry_token。Retry Integrity Tag 用 original_dcid 计算。
    const retry_dgram = try server.issueRetryDatagram(
        41,
        &original_dcid,
        &client_scid,
        &retry_scid,
        token,
    );
    defer allocator.free(retry_dgram);
    try require(retry_dgram.len > 0);
    try require(server.pendingRetryTokenCount() == 1);
    try require(std.mem.eql(u8, server.retrySourceConnectionId().?, &retry_scid));
    try require(std.mem.eql(u8, server.originalDestinationConnectionId().?, &original_dcid));

    // 端点级 DCID 切换：original_dcid -> retry_scid（RFC 9000 §8.1.2）。
    const switched = try server_lifecycle.switchInitialDestinationConnectionIdAfterRetry(
        &original_dcid,
        &retry_scid,
        server_path,
    );
    try require(switched.connection_id == server_handle);
    try require(std.mem.eql(u8, switched.destination_connection_id.asSlice(), &retry_scid));

    // server UDP send Retry 给 client。
    try server_socket.send(io, &recv1.from, retry_dgram);

    // === 步骤 5: client UDP recv Retry + routeDatagram + processRetryDatagram ===
    const recv2 = try client_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    const retry_path = try udp4Tuple(client_socket.address, recv2.from);
    // lifecycle 路由：Retry 包 DCID=client_scid，路由到 client connection。
    const retry_route = try client_lifecycle.routeDatagram(retry_path, recv2.data);
    try require(retry_route.connection_id == client_handle);

    // processRetryDatagram 验证 Retry Integrity Tag（用 original_dcid），
    // 记录 retry_token + retry_source_connection_id。后续 Initial 包的 token
    // 字段会由 initialTokenForPacket 自动注入 retry_token。
    try client.processRetryDatagram(42, &original_dcid, recv2.data);
    try require(std.mem.eql(u8, client.retrySourceConnectionId().?, &retry_scid));
    try require(std.mem.eql(u8, client.latestRetryToken().?, token));

    // === 步骤 6: server validateRetryToken -> peerAddressValidated ===
    // 一次性消费 pending Retry token，标记 peer 地址已验证，解除 anti-amplification。
    try server.validateRetryToken(client.latestRetryToken().?);
    try require(server.peerAddressValidated());
    try require(server.pendingRetryTokenCount() == 0);

    // === 步骤 7: retry_secrets 重派生演示（RFC 9000 §17.2.5.1）===
    // Retry 后 client 重发 Initial 时 DCID 改为 retry_scid，initial secrets
    // 必须用 retry_scid 重新派生（salt = v1 initial salt，IKM = retry_scid）。
    // 此处演示重派生成功；实际重发 Initial 需 core API 缺口补齐（见顶部注释）。
    const retry_secrets = try protection.deriveInitialSecrets(.v1, &retry_scid);
    _ = retry_secrets;

    std.debug.print("tls13_retry_loopback: ClientHello Initial + Retry exchange + token validation OK\n", .{});
    std.debug.print("  client_port={} server_port={}\n", .{
        client_path.local.port,
        server_path.local.port,
    });
    std.debug.print("  client_hello_bytes={} retry_bytes={}\n", .{
        client_dgram.len,
        retry_dgram.len,
    });
    std.debug.print("  retry_scid_matched={} token_matched={} retry_token_validated={}\n", .{
        std.mem.eql(u8, client.retrySourceConnectionId().?, &retry_scid),
        std.mem.eql(u8, client.latestRetryToken().?, token),
        server.peerAddressValidated(),
    });
    std.debug.print("  pending_retry_tokens={} address_validated={} dcid_switched={}\n", .{
        server.pendingRetryTokenCount(),
        server.peerAddressValidated(),
        std.mem.eql(u8, switched.destination_connection_id.asSlice(), &retry_scid),
    });
}
