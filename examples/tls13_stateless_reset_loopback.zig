//! TLS-owned stateless reset over loopback UDP.
//!
//! 在 TLS-owned UDP 路径上验证 stateless reset：用 Tls13Backend 完成真实
//! TLS 1.3 握手安装 1-RTT keys，server 通过 NEW_CONNECTION_ID 颁发带
//! stateless_reset_token 的新 CID，client 用该 CID 发 1-RTT short-header 包，
//! server 的 EndpointConnectionLifecycle（连接状态已退役，仅保留 token 路由）
//! 回 stateless reset packet，client 用 matchesStatelessReset 识别。
//!
//! 组合参考：
//!   - tls13_udp_loopback.zig（Tls13Backend 握手 + 1-RTT over UDP）
//!   - udp_stateless_reset_loopback.zig（lifecycle registerConnectionId +
//!     handleDatagram -> stateless_reset）
//!   - tls13_lifecycle_loopback.zig（server.issueConnectionId 颁发 NEW_CONNECTION_ID）

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const packet = quicz.packet;
const endpoint = quicz.endpoint;

const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
const server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };

// NEW_CONNECTION_ID 颁发的新 CID + stateless reset token。
// 假设：真实实现中 server endpoint 会自动将 issueConnectionId 颁发的 token
// 注册到 router 的 stateless_reset_token 表。此处显式注册到 lifecycle 以
// 模拟该绑定（与 udp_stateless_reset_loopback.zig 一致）。
const new_cid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
const srt = [_]u8{0xEE} ** 16;
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

    const server_path = try udp4Tuple(server_socket.address, client_socket.address);

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

    // === TLS 1.3 握手（参考 tls13_udp_loopback.zig）===

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
    try client_socket.send(io, &server_socket.address, client_dgram);

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
    try server_socket.send(io, &client_socket.address, server_init_dgram);

    _ = try server.driveCryptoBackendInSpace(.handshake, server_backend.cryptoBackend(), &scratch);
    const server_hs_dgram = (try server.pollProtectedHandshakeDatagramWithInstalledKeys(
        43,
        &client_scid,
        &server_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_hs_dgram);
    try server_socket.send(io, &client_socket.address, server_hs_dgram);

    // 4. Client receives ServerHello, drives initial (install handshake keys).
    const recv2 = try client_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try client.processProtectedLongDatagramInSpace(.initial, 44, secrets.server, recv2.data);
    _ = try client.driveCryptoBackendInSpace(.initial, client_backend.cryptoBackend(), &scratch);

    // 5. Client receives Handshake flight, drives handshake -> client Finished.
    const recv3 = try client_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try client.processProtectedHandshakeDatagramWithInstalledKeys(45, recv3.data);
    const client_hs_prog = try client.driveCryptoBackendInSpace(.handshake, client_backend.cryptoBackend(), &scratch);
    try require(client_hs_prog.outbound_bytes > 0);
    const client_hs_dgram = (try client.pollProtectedHandshakeDatagramWithInstalledKeys(
        46,
        &server_scid,
        &client_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_hs_dgram);
    try client_socket.send(io, &server_socket.address, client_hs_dgram);

    // 6. Server receives client Finished -> handshake confirmed, 1-RTT keys installed.
    const recv4 = try server_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try server.processProtectedHandshakeDatagramWithInstalledKeys(47, recv4.data);
    const server_hs_drive = try server.driveCryptoBackendInSpace(.handshake, server_backend.cryptoBackend(), &scratch);
    try require(server_hs_drive.handshake_confirmed);
    try require(server.handshakeConfirmed());

    // === 握手完成，1-RTT keys 已安装 ===

    // 7. Server 通过 NEW_CONNECTION_ID 颁发带 stateless_reset_token 的新 CID。
    //    issueConnectionId 将帧入队，下一次 pollProtectedShortDatagram 会包含它。
    const issued_seq = try server.issueConnectionId(&new_cid, srt, 0);
    try require(issued_seq == 0);

    // Server 轮询 1-RTT 数据报（含 NEW_CONNECTION_ID 帧），发送给 client。
    // 可能产生多个数据报（ACK + NEW_CONNECTION_ID），全部发送。
    var cid_sent = false;
    {
        var pn: i64 = 50;
        while (pn < 54) : (pn += 1) {
            const dgram = (try server.pollProtectedShortDatagramWithInstalledKeys(pn, &client_scid)) orelse break;
            defer allocator.free(dgram);
            try server_socket.send(io, &client_socket.address, dgram);
            cid_sent = true;
        }
    }
    try require(cid_sent);

    // 8. Client 接收并处理含 NEW_CONNECTION_ID 的 1-RTT 数据报，学习 (new_cid, srt)。
    //    active_connection_ids 会存储 peer 颁发的 CID + token（供 detectStatelessReset）。
    var client_rx_pn: i64 = 60;
    while (true) {
        const recv = client_socket.receiveTimeout(io, &recv_buf, recvTimeout()) catch break;
        try client.processProtectedShortDatagramWithInstalledKeys(client_rx_pn, client_scid.len, recv.data);
        client_rx_pn += 1;
    }

    // === 在 server 侧注册 lifecycle CID + stateless_reset_token 路由 ===

    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer server_lifecycle.deinit();
    try server_lifecycle.registerConnectionId(server_handle, &new_cid, server_path, .{ .stateless_reset_token = srt });
    try require(server_lifecycle.routeCount() == 1);
    try require(server_lifecycle.statelessResetTokenCount() == 1);

    // 9. 模拟 server 状态丢失：退役连接路由，但保留 stateless_reset_token。
    //    retireConnection 移除路由但保留 token 表（RFC 9000 §10.3）。
    //    之后收到 DCID=new_cid 的包将无法路由，但 router 找到 token -> stateless_reset。
    const retired = server_lifecycle.retireConnection(server_handle);
    try require(retired.routes_retired == 1);
    try require(server_lifecycle.routeCount() == 0);
    try require(server_lifecycle.statelessResetTokenCount() == 1);

    // === Stateless reset 验证 ===

    // 10. Client 用 new_cid 作为 DCID 发 1-RTT short-header 包到 server。
    //     包含 STREAM "stateless-reset-probe" 确保数据报长度满足
    //     min_stateless_reset_datagram_len（reset 必须短于触发包）。
    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "stateless-reset-probe", false);
    const probe_dgram = (try client.pollProtectedShortDatagramWithInstalledKeys(
        client_rx_pn,
        &new_cid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(probe_dgram);
    try require(probe_dgram.len > packet.min_stateless_reset_datagram_len);
    try client_socket.send(io, &server_socket.address, probe_dgram);

    // 11. Server 接收触发包，lifecycle handleDatagram 因无路由但找到 token
    //     -> 返回 .stateless_reset。
    const recv_probe = try server_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    const reset_path = try udp4Tuple(server_socket.address, recv_probe.from);
    var reset_out: [64]u8 = undefined;
    // unpredictable_prefix 必须 >= 5 字节且 reset_len < 触发包长度。
    // 首字节 0x40 = short header 标记，使 reset 包看起来像 1-RTT 短包头。
    const unpredictable_prefix = [_]u8{ 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde };
    const action = try server_lifecycle.handleDatagram(
        &reset_out,
        reset_path,
        recv_probe.data,
        &unpredictable_prefix,
    );
    const reset = switch (action) {
        .stateless_reset => |datagram| datagram,
        else => return error.UnexpectedState,
    };
    try require(reset.len < recv_probe.data.len);
    try server_socket.send(io, &recv_probe.from, reset);

    // 12. Client 接收 stateless reset packet，用 matchesStatelessReset 识别。
    var client_receive_buf: [1500]u8 = undefined;
    const reset_received = try client_socket.receiveTimeout(io, &client_receive_buf, recvTimeout());
    try require(packet.matchesStatelessReset(reset_received.data, srt));

    // 进一步验证：client 通过 NEW_CONNECTION_ID 学到的 token 也能匹配
    // （detectStatelessReset 遍历 active_connection_ids，返回 sequence number）。
    const detected_seq = client.detectStatelessReset(reset_received.data);
    try require(detected_seq != null);
    try require(detected_seq.? == 0);

    std.debug.print("tls13_stateless_reset_loopback: handshake + NEW_CONNECTION_ID + stateless_reset matched=true detected_seq={} probe_bytes={} reset_bytes={}\n", .{
        detected_seq.?,
        probe_dgram.len,
        reset_received.data.len,
    });
}
