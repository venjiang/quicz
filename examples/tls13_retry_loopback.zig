//! TLS-owned Retry 完整闭环 over loopback UDP（RFC 9000 §8.1.2 地址验证 +
//! §17.2.5 Retry 后重发 + RFC 8446 TLS 1.3 握手完成 + 1-RTT 数据交换）。
//!
//! 在 TLS-owned UDP 路径上闭合 Retry 全流程：用 Tls13Backend 产生真实
//! ClientHello Initial，server 用 issueRetryDatagram 发 Retry（含 retry_token +
//! retry_scid），client 用 processRetryDatagram 处理 Retry 并记录 retry_scid +
//! token，server 用 validateRetryToken 验证 token 通过并标记
//! peerAddressValidated。随后 client 用 Tls13Backend.retryReceived() 重新缓存
//! ClientHello + Connection.resetInitialCryptoSendForRetry() 重置 Initial crypto
//! send state，用 retry_scid 作为 DCID + retry_secrets（deriveInitialSecrets
//! (retry_scid)）重发 ClientHello Initial。server 收重发 Initial，继续 TLS 握手
//! （ServerHello + EE/Cert/CV/Finished），client 产 client Finished，server
//! confirmHandshake + 发 HANDSHAKE_DONE，client 收到后 handshake_confirmed。
//! 最后 1-RTT PING/PONG 交换验证应用数据通道。
//!
//! 覆盖范围（闭合 docs §94 "Retry on TLS-owned UDP" 端点级缺口）：
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
//!   - retry_secrets 重派生（deriveInitialSecrets(retry_scid)，RFC 9000
//!     §17.2.5.1 要求 Retry 后用 retry_scid 作为 DCID 重派生 initial secrets）
//!   - **Tls13Backend.retryReceived() 重新缓存 ClientHello 到 out_initial**
//!   - **Connection.resetInitialCryptoSendForRetry() 重置 Initial 发送侧状态**
//!     （crypto_send_offset/packet_number/sent_packets/recovery 归零，不 discard）
//!   - **client 重发 ClientHello Initial（retry_scid DCID + retry_secrets.client）**
//!   - **server 收重发 Initial（retry_secrets.client 解密）+ TLS 握手交换**
//!     （ServerHello/Cert/CV/Finished + installHandshakeTrafficSecrets +
//!     confirmHandshake + installOneRttTrafficSecrets）
//!   - **1-RTT PING/PONG 数据交换**（sendPing + pollProtectedShortDatagram
//!     WithInstalledKeys + processProtectedShortDatagramWithInstalledKeys）
//!
//! 组合参考：
//!   - tls13_path_validation_loopback.zig（Tls13Backend 握手 + lifecycle UDP 模板）
//!   - udp_retry_loopback.zig（mock-key Retry + lifecycle switch 流程）
//!   - connection.zig Retry 完整闭环测试（Tls13Backend + Connection: Retry then
//!     resend ClientHello and complete handshake on TLS-owned path）

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const endpoint = quicz.endpoint;

// 常量与 connection.zig Retry 测试一致（RFC 9000 §17.2.5 Retry 场景）。
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

    // === 步骤 7: retry_secrets 重派生（RFC 9000 §17.2.5.1）===
    // Retry 后 client 重发 Initial 时 DCID 改为 retry_scid，initial secrets
    // 必须用 retry_scid 重新派生（salt = v1 initial salt，IKM = retry_scid）。
    const retry_secrets = try protection.deriveInitialSecrets(.v1, &retry_scid);

    // === 步骤 8: client 重发 ClientHello Initial（retry_scid DCID + retry_secrets）===
    // Tls13Backend.retryReceived() 把缓存的 ClientHello 字节重新放回 out_initial
    // bucket（不触发 hs 状态机重新 build，避免 transcript 错乱）。
    // Connection.resetInitialCryptoSendForRetry() 重置 Initial 发送侧状态
    // （crypto_send_offset/packet_number/sent_packets/recovery 归零，不 discard）。
    // 然后 driveCryptoBackendInSpace(.initial) 重新 pull ClientHello 入队，
    // pollProtectedLongCryptoDatagramInSpace 用 retry_scid 作为 DCID +
    // retry_secrets.client 保护重发。token 字段由 initialTokenForPacket 自动
    // 注入 retry_token（token 参数传空切片）。
    client_backend.retryReceived();
    try client.resetInitialCryptoSendForRetry();
    _ = try client.driveCryptoBackendInSpace(.initial, client_backend.cryptoBackend(), &scratch);
    const retry_ch_dgram = (try client.pollProtectedLongCryptoDatagramInSpace(
        .initial,
        43,
        &retry_scid,
        &client_scid,
        &[_]u8{},
        retry_secrets.client,
    )) orelse return error.UnexpectedState;
    defer allocator.free(retry_ch_dgram);
    try require(retry_ch_dgram.len > 0);
    try client_socket.send(io, &server_socket.address, retry_ch_dgram);

    // === 步骤 9: server UDP recv 重发 Initial + driveCryptoBackendInSpace 产 ServerHello ===
    // server 用 retry_secrets.client（client initial keys）解密重发的 ClientHello。
    const recv3 = try server_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try server.processProtectedLongDatagramInSpace(.initial, 44, retry_secrets.client, recv3.data);
    _ = try server.driveCryptoBackendInSpace(.initial, server_backend.cryptoBackend(), &scratch);

    // server -> ServerHello (Initial, retry_secrets.server) + Handshake flight。
    const sh_dgram = (try server.pollProtectedLongCryptoDatagramInSpace(
        .initial,
        45,
        &client_scid,
        &server_scid,
        &[_]u8{},
        retry_secrets.server,
    )) orelse return error.UnexpectedState;
    defer allocator.free(sh_dgram);
    try server_socket.send(io, &client_socket.address, sh_dgram);

    _ = try server.driveCryptoBackendInSpace(.handshake, server_backend.cryptoBackend(), &scratch);
    const shs_dgram = (try server.pollProtectedHandshakeDatagramWithInstalledKeys(
        46,
        &client_scid,
        &server_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(shs_dgram);
    try server_socket.send(io, &client_socket.address, shs_dgram);

    // === 步骤 10: client UDP recv ServerHello + Handshake flight -> client Finished ===
    // client 用 retry_secrets.server（server initial keys）解密 ServerHello。
    const recv4 = try client_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try client.processProtectedLongDatagramInSpace(.initial, 47, retry_secrets.server, recv4.data);
    _ = try client.driveCryptoBackendInSpace(.initial, client_backend.cryptoBackend(), &scratch);

    const recv5 = try client_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try client.processProtectedHandshakeDatagramWithInstalledKeys(48, recv5.data);
    _ = try client.driveCryptoBackendInSpace(.handshake, client_backend.cryptoBackend(), &scratch);
    const cf_dgram = (try client.pollProtectedHandshakeDatagramWithInstalledKeys(
        49,
        &server_scid,
        &client_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(cf_dgram);
    try client_socket.send(io, &server_socket.address, cf_dgram);

    // === 步骤 11: server UDP recv client Finished -> handshake confirmed + 1-RTT keys ===
    const recv6 = try server_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try server.processProtectedHandshakeDatagramWithInstalledKeys(50, recv6.data);
    _ = try server.driveCryptoBackendInSpace(.handshake, server_backend.cryptoBackend(), &scratch);
    try require(server.handshakeConfirmed());

    // === 步骤 12: server 发 HANDSHAKE_DONE over 1-RTT ===
    try server.sendHandshakeDone();
    const hd_dgram = (try server.pollProtectedShortDatagramWithInstalledKeys(51, &client_scid)) orelse return error.UnexpectedState;
    defer allocator.free(hd_dgram);
    try server_socket.send(io, &client_socket.address, hd_dgram);

    // === 步骤 13: client UDP recv HANDSHAKE_DONE -> handshake confirmed ===
    const recv7 = try client_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try client.processProtectedShortDatagramWithInstalledKeys(52, client_scid.len, recv7.data);
    try require(client.handshakeConfirmed());

    // === 步骤 14: 1-RTT PING/PONG 数据交换 ===
    try client.sendPing();
    const ping_dgram = (try client.pollProtectedShortDatagramWithInstalledKeys(53, &server_scid)) orelse return error.UnexpectedState;
    defer allocator.free(ping_dgram);
    try client_socket.send(io, &server_socket.address, ping_dgram);

    const recv8 = try server_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try server.processProtectedShortDatagramWithInstalledKeys(54, server_scid.len, recv8.data);
    try require(server.peerAddressValidated());

    std.debug.print("tls13_retry_loopback: Retry -> resend ClientHello -> handshake done -> 1-RTT OK\n", .{});
    std.debug.print("  client_port={} server_port={}\n", .{
        client_path.local.port,
        server_path.local.port,
    });
    std.debug.print("  first_ch_bytes={} retry_dgram_bytes={} resent_ch_bytes={}\n", .{
        client_dgram.len,
        retry_dgram.len,
        retry_ch_dgram.len,
    });
    std.debug.print("  retry_scid_matched={} token_matched={} retry_token_validated={}\n", .{
        std.mem.eql(u8, client.retrySourceConnectionId().?, &retry_scid),
        std.mem.eql(u8, client.latestRetryToken().?, token),
        server.peerAddressValidated(),
    });
    std.debug.print("  dcid_switched={} client_hello_resent={}\n", .{
        std.mem.eql(u8, switched.destination_connection_id.asSlice(), &retry_scid),
        retry_ch_dgram.len > 0,
    });
    std.debug.print("  handshake_done={} one_rtt_acked={}\n", .{
        client.handshakeConfirmed() and server.handshakeConfirmed(),
        server.peerAddressValidated(),
    });
}
