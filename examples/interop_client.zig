//! QUIC-Interop-Runner 风格的 interop client（M7 外部互通起步）。
//!
//! 命令行：interop_client <server_host> <server_port> [TESTCASE]
//!   TESTCASE 从参数或 TESTCASE 环境变量取（默认 handshake）
//!   SSLKEYLOGFILE 环境变量：若设置，握手后写 NSS key log（client + server）
//!
//! 本地自测：main 在同进程内起内置 server（绑 server_host:server_port），
//! client 用真 UDP loopback socket 连它，按 TESTCASE 驱动。无需外部 QUIC
//! server，agent 可在 sandbox 自验 handshake / transfer / retry。
//!
//! 已支持 TESTCASE：
//!   handshake - 完成 TLS 1.3 握手，验证 1-RTT keys install + handshake done
//!   transfer  - 握手后开 bidirectional stream，发数据，收 echo 响应
//!   retry     - server 触发 Retry，client 处理重发 + 握手完成
//!
//! 模板参考：examples/tls13_udp_loopback.zig（握手 + STREAM echo）、
//! examples/tls13_retry_loopback.zig（Retry 闭环）。endel/quic-zig 的
//! apps/interop_client.zig 仅作架构参考，未复制代码。

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

// 常量与 tls13_udp_loopback / tls13_retry_loopback 一致，便于对照。
const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
const server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
const retry_scid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
const retry_token: []const u8 = "retry-token-for-client-address";

const Testcase = enum {
    handshake,
    transfer,
    retry,
    unsupported,
};

fn parseTestcase(name: []const u8) Testcase {
    if (std.mem.eql(u8, name, "handshake")) return .handshake;
    if (std.mem.eql(u8, name, "transfer")) return .transfer;
    if (std.mem.eql(u8, name, "retry")) return .retry;
    return .unsupported;
}

fn recvTimeout() std.Io.Timeout {
    return .{ .duration = .{
        .clock = .awake,
        .raw = std.Io.Duration.fromMilliseconds(2000),
    } };
}

fn require(condition: bool) !void {
    if (!condition) return error.UnexpectedState;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    // ─── 解析命令行：interop_client <server_host> <server_port> [TESTCASE] ───
    var args_iter = std.process.Args.Iterator.init(init.minimal.args);
    _ = args_iter.next(); // 跳过程序名
    const server_host = args_iter.next() orelse {
        std.debug.print("usage: interop_client <server_host> <server_port> [TESTCASE]\n", .{});
        return error.MissingArgs;
    };
    const server_port_str = args_iter.next() orelse {
        std.debug.print("usage: interop_client <server_host> <server_port> [TESTCASE]\n", .{});
        return error.MissingArgs;
    };
    const server_port = try std.fmt.parseInt(u16, server_port_str, 10);
    const testcase_arg = args_iter.next();

    // TESTCASE：参数优先，否则读 TESTCASE 环境变量，默认 handshake
    const testcase_name = blk: {
        if (testcase_arg) |t| break :blk t;
        if (init.environ_map.get("TESTCASE")) |t| break :blk t;
        break :blk "handshake";
    };
    const testcase = parseTestcase(testcase_name);
    if (testcase == .unsupported) {
        std.debug.print("unsupported TESTCASE: {s}\n", .{testcase_name});
        return error.UnsupportedTestcase;
    }

    // SSLKEYLOGFILE：若设置，握手后写 key log（路径需为绝对路径）
    const keylog_path = init.environ_map.get("SSLKEYLOGFILE");

    // ─── 起 UDP loopback socket：server 绑 server_host:server_port ───
    const server_addr = try std.Io.net.IpAddress.parseIp4(server_host, server_port);
    var server_socket = try server_addr.bind(io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer server_socket.close(io);
    var client_addr = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var client_socket = try client_addr.bind(io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer client_socket.close(io);

    // ─── 创建 Connection + Tls13Backend（client + server） ───
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
        .max_datagram_size = 8192,
    });
    defer client.deinit();
    var server = try Connection.init(allocator, .server, .{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
        .max_datagram_size = 8192,
    });
    defer server.deinit();
    // 标记 server 已验证 peer 地址（跳过 Retry，解除放大限制，可直发 ServerHello）。
    // retry TESTCASE 在 runRetry 内会显式 issueRetryDatagram，此处设置不影响。
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

    switch (testcase) {
        .retry => try runRetry(
            allocator,
            &client,
            &server,
            &client_socket,
            &server_socket,
            io,
            &client_backend,
            &server_backend,
            &scratch,
            &recv_buf,
            secrets,
        ),
        .handshake, .transfer => try runHandshakeTransfer(
            allocator,
            &client,
            &server,
            &client_socket,
            &server_socket,
            io,
            &client_backend,
            &server_backend,
            &scratch,
            &recv_buf,
            secrets,
            testcase,
        ),
        .unsupported => unreachable,
    }

    // ─── SSLKEYLOGFILE：写 NSS key log（client + server secrets） ───
    if (keylog_path) |path| {
        var kbuf: [4096]u8 = undefined;
        var kw = std.Io.Writer.fixed(&kbuf);
        try client_backend.writeKeylog(&kw);
        try server_backend.writeKeylog(&kw);
        const file = std.Io.Dir.createFileAbsolute(io, path, .{}) catch |err| {
            std.debug.print("SSLKEYLOGFILE: 无法写入 {s}: {s}\n", .{ path, @errorName(err) });
            return;
        };
        defer file.close(io);
        try file.writeStreamingAll(io, kw.buffered());
        std.debug.print("sslkeylog: wrote {d} bytes to {s}\n", .{ kw.buffered().len, path });
    }
}

/// handshake + transfer：共享 TLS 1.3 握手，transfer 额外做 STREAM echo。
fn runHandshakeTransfer(
    allocator: std.mem.Allocator,
    client: *Connection,
    server: *Connection,
    client_socket: anytype,
    server_socket: anytype,
    io: std.Io,
    client_backend: *Tls13Backend,
    server_backend: *Tls13Backend,
    scratch: []u8,
    recv_buf: []u8,
    secrets: protection.InitialSecrets,
    testcase: Testcase,
) !void {
    // 1. Client -> ClientHello over UDP。
    _ = try client.driveCryptoBackendInSpace(.initial, client_backend.cryptoBackend(), scratch);
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

    // 2. Server receives, processes, drives initial -> handshake + 1-RTT keys。
    const recv1 = try server_socket.receiveTimeout(io, recv_buf, recvTimeout());
    try server.processProtectedLongDatagramInSpace(.initial, 41, secrets.client, recv1.data);
    const server_init_prog = try server.driveCryptoBackendInSpace(.initial, server_backend.cryptoBackend(), scratch);
    try require(server_init_prog.handshake_keys_installed);

    // 3. Server -> ServerHello (Initial) + EE/Cert/CV/Finished (Handshake)。
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

    _ = try server.driveCryptoBackendInSpace(.handshake, server_backend.cryptoBackend(), scratch);
    const server_hs_dgram = (try server.pollProtectedHandshakeDatagramWithInstalledKeys(
        43,
        &client_scid,
        &server_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_hs_dgram);
    try server_socket.send(io, &client_socket.address, server_hs_dgram);

    // 4. Client receives ServerHello, drives initial (install handshake keys)。
    const recv2 = try client_socket.receiveTimeout(io, recv_buf, recvTimeout());
    try client.processProtectedLongDatagramInSpace(.initial, 44, secrets.server, recv2.data);
    _ = try client.driveCryptoBackendInSpace(.initial, client_backend.cryptoBackend(), scratch);

    // 5. Client receives Handshake flight, drives handshake -> client Finished。
    const recv3 = try client_socket.receiveTimeout(io, recv_buf, recvTimeout());
    try client.processProtectedHandshakeDatagramWithInstalledKeys(45, recv3.data);
    const client_hs_prog = try client.driveCryptoBackendInSpace(.handshake, client_backend.cryptoBackend(), scratch);
    try require(client_hs_prog.outbound_bytes > 0);
    const client_hs_dgram = (try client.pollProtectedHandshakeDatagramWithInstalledKeys(
        46,
        &server_scid,
        &client_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_hs_dgram);
    try client_socket.send(io, &server_socket.address, client_hs_dgram);

    // 6. Server receives client Finished -> handshake confirmed。
    const recv4 = try server_socket.receiveTimeout(io, recv_buf, recvTimeout());
    try server.processProtectedHandshakeDatagramWithInstalledKeys(47, recv4.data);
    const server_hs_drive = try server.driveCryptoBackendInSpace(.handshake, server_backend.cryptoBackend(), scratch);
    try require(server_hs_drive.handshake_confirmed);
    try require(server.handshakeConfirmed());

    if (testcase == .handshake) {
        std.debug.print("handshake_done=true\n", .{});
        return;
    }

    // ─── transfer：握手后开 bidirectional stream，发数据，收 echo ───
    const payload = "quicz-interop-transfer-payload";
    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, payload, false);
    const req_dgram = (try client.pollProtectedShortDatagramWithInstalledKeys(48, &server_scid)) orelse return error.UnexpectedState;
    defer allocator.free(req_dgram);
    try client_socket.send(io, &server_socket.address, req_dgram);

    // Server receives, reads stream, echoes back（可能先发 ACK-only 再发 STREAM）。
    const recv5 = try server_socket.receiveTimeout(io, recv_buf, recvTimeout());
    try server.processProtectedShortDatagramWithInstalledKeys(49, server_scid.len, recv5.data);
    var stream_buf: [256]u8 = undefined;
    const n = (try server.recvOnStream(stream_id, &stream_buf)) orelse return error.UnexpectedState;
    try require(std.mem.eql(u8, stream_buf[0..n], payload));
    try server.sendOnStream(stream_id, stream_buf[0..n], false);
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const dgram = (try server.pollProtectedShortDatagramWithInstalledKeys(50 + @as(i64, @intCast(i)), &client_scid)) orelse break;
        defer allocator.free(dgram);
        try server_socket.send(io, &client_socket.address, dgram);
    }

    // Client receives echo（消费最多 4 个 datagram）。
    var got_echo = false;
    var echo_len: usize = 0;
    var j: usize = 0;
    while (j < 4) : (j += 1) {
        const r = client_socket.receiveTimeout(io, recv_buf, recvTimeout()) catch break;
        try client.processProtectedShortDatagramWithInstalledKeys(54 + @as(i64, @intCast(j)), client_scid.len, r.data);
        if ((try client.recvOnStream(stream_id, &stream_buf)) != null) {
            got_echo = true;
            echo_len = n;
            break;
        }
    }
    try require(got_echo);
    try require(std.mem.eql(u8, stream_buf[0..echo_len], payload));
    std.debug.print("transfer_bytes={d}\n", .{echo_len});
}

/// retry：server 触发 Retry，client 处理重发 + 握手完成。
fn runRetry(
    allocator: std.mem.Allocator,
    client: *Connection,
    server: *Connection,
    client_socket: anytype,
    server_socket: anytype,
    io: std.Io,
    client_backend: *Tls13Backend,
    server_backend: *Tls13Backend,
    scratch: []u8,
    recv_buf: []u8,
    secrets: protection.InitialSecrets,
) !void {
    // server 进入"要求地址验证"状态，握手前必须先通过 Retry 验证。
    try server.validatePeerAddress();

    // 1. Client -> ClientHello Initial（DCID=original_dcid, secrets.client）。
    _ = try client.driveCryptoBackendInSpace(.initial, client_backend.cryptoBackend(), scratch);
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

    // 2. Server 收首份 Initial（**不 process**，避免 next_peer_packet_number 前进
    //    导致 issueRetryDatagram 失败），直接发 Retry。
    const recv1 = try server_socket.receiveTimeout(io, recv_buf, recvTimeout());
    const retry_dgram = try server.issueRetryDatagram(
        41,
        &original_dcid,
        &client_scid,
        &retry_scid,
        retry_token,
    );
    defer allocator.free(retry_dgram);
    try require(server.pendingRetryTokenCount() == 1);
    try require(std.mem.eql(u8, server.retrySourceConnectionId().?, &retry_scid));
    try server_socket.send(io, &recv1.from, retry_dgram);

    // 3. Client 收 Retry，processRetryDatagram 验证 Integrity Tag + 记录 retry_scid/token。
    const recv2 = try client_socket.receiveTimeout(io, recv_buf, recvTimeout());
    try client.processRetryDatagram(42, &original_dcid, recv2.data);
    try require(std.mem.eql(u8, client.retrySourceConnectionId().?, &retry_scid));
    try require(std.mem.eql(u8, client.latestRetryToken().?, retry_token));

    // 4. Server validateRetryToken -> peerAddressValidated（一次性消费 token）。
    try server.validateRetryToken(client.latestRetryToken().?);
    try require(server.peerAddressValidated());

    // 5. retry_secrets 重派生（RFC 9000 §17.2.5.1：DCID 改为 retry_scid）。
    const retry_secrets = try protection.deriveInitialSecrets(.v1, &retry_scid);

    // 6. Client 重发 ClientHello Initial（retryReceived -> reset -> drive -> poll）。
    //    token 字段由 initialTokenForPacket 自动注入 retry_token，故传空切片。
    client_backend.retryReceived();
    try client.resetInitialCryptoSendForRetry();
    _ = try client.driveCryptoBackendInSpace(.initial, client_backend.cryptoBackend(), scratch);
    const retry_ch_dgram = (try client.pollProtectedLongCryptoDatagramInSpace(
        .initial,
        43,
        &retry_scid,
        &client_scid,
        &[_]u8{},
        retry_secrets.client,
    )) orelse return error.UnexpectedState;
    defer allocator.free(retry_ch_dgram);
    try client_socket.send(io, &server_socket.address, retry_ch_dgram);

    // 7. Server 收重发 Initial（retry_secrets.client 解密）-> 产 ServerHello + Handshake flight。
    const recv3 = try server_socket.receiveTimeout(io, recv_buf, recvTimeout());
    try server.processProtectedLongDatagramInSpace(.initial, 44, retry_secrets.client, recv3.data);
    _ = try server.driveCryptoBackendInSpace(.initial, server_backend.cryptoBackend(), scratch);
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

    _ = try server.driveCryptoBackendInSpace(.handshake, server_backend.cryptoBackend(), scratch);
    const shs_dgram = (try server.pollProtectedHandshakeDatagramWithInstalledKeys(
        46,
        &client_scid,
        &server_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(shs_dgram);
    try server_socket.send(io, &client_socket.address, shs_dgram);

    // 8. Client 收 ServerHello（retry_secrets.server 解密）+ Handshake flight -> client Finished。
    const recv4 = try client_socket.receiveTimeout(io, recv_buf, recvTimeout());
    try client.processProtectedLongDatagramInSpace(.initial, 47, retry_secrets.server, recv4.data);
    _ = try client.driveCryptoBackendInSpace(.initial, client_backend.cryptoBackend(), scratch);

    const recv5 = try client_socket.receiveTimeout(io, recv_buf, recvTimeout());
    try client.processProtectedHandshakeDatagramWithInstalledKeys(48, recv5.data);
    _ = try client.driveCryptoBackendInSpace(.handshake, client_backend.cryptoBackend(), scratch);
    const cf_dgram = (try client.pollProtectedHandshakeDatagramWithInstalledKeys(
        49,
        &server_scid,
        &client_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(cf_dgram);
    try client_socket.send(io, &server_socket.address, cf_dgram);

    // 9. Server 收 client Finished -> handshake confirmed。
    const recv6 = try server_socket.receiveTimeout(io, recv_buf, recvTimeout());
    try server.processProtectedHandshakeDatagramWithInstalledKeys(50, recv6.data);
    _ = try server.driveCryptoBackendInSpace(.handshake, server_backend.cryptoBackend(), scratch);
    try require(server.handshakeConfirmed());

    // 10. Server 发 HANDSHAKE_DONE over 1-RTT。
    try server.sendHandshakeDone();
    const hd_dgram = (try server.pollProtectedShortDatagramWithInstalledKeys(51, &client_scid)) orelse return error.UnexpectedState;
    defer allocator.free(hd_dgram);
    try server_socket.send(io, &client_socket.address, hd_dgram);

    // 11. Client 收 HANDSHAKE_DONE -> handshake confirmed。
    const recv7 = try client_socket.receiveTimeout(io, recv_buf, recvTimeout());
    try client.processProtectedShortDatagramWithInstalledKeys(52, client_scid.len, recv7.data);
    try require(client.handshakeConfirmed());

    std.debug.print("retry_completed=true\n", .{});
}
