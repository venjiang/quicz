//! 事件驱动 interop loopback：EndpointConnectionLifecycle deadline 驱动收发循环。
//!
//! 升级 examples/interop_client.zig 的同步交替驱动为单线程事件循环：每端按
//! nextDeadline 等待 socket readable 或超时，收包按 header form 分发到
//! Initial/Handshake/1-RTT 路由路径，超时走 processDueDeadlineAndPollDatagram
//! 触发 loss/PTO 重传。为真实外部 QUIC server 互通铺路。
//!
//! 与 interop_client.zig（同步交替、固定步骤）对照：本 example 每端内部是
//! deadline 驱动事件循环，能处理 PTO 超时恢复，逼近真实网络行为。
//!
//! 命令行：interop_event_loopback [TESTCASE]
//!   TESTCASE: handshake（默认）/ transfer / loss
//!
//! 场景（本地 loopback 自测）：
//!   handshake - 事件循环驱动 TLS 1.3 握手到两端 handshakeConfirmed
//!   transfer  - 握手后开 bidirectional stream，发数据收 echo
//!   loss      - transfer 中 server 延迟回 ACK（模拟处理延迟/ACK 丢失），
//!               client PTO deadline 触发 probe，probe 被 server 处理后
//!               server 回 ACK + echo，最终 transfer 成功（同步交替驱动做不到）

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EndpointConnectionLifecycle = quicz.EndpointConnectionLifecycle;
const EndpointConnectionDeadline = quicz.EndpointConnectionDeadline;
const Udp4Tuple = quicz.endpoint.Udp4Tuple;
const Udp4Address = quicz.endpoint.Udp4Address;

// 常量与 tls13_lifecycle_loopback / interop_client 一致，便于对照。
const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
const server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
const client_handle: u64 = 1;
const server_handle: u64 = 2;

const Testcase = enum { handshake, transfer, loss };

fn parseTestcase(name: []const u8) Testcase {
    if (std.mem.eql(u8, name, "handshake")) return .handshake;
    if (std.mem.eql(u8, name, "transfer")) return .transfer;
    if (std.mem.eql(u8, name, "loss")) return .loss;
    return .handshake;
}

fn require(condition: bool) !void {
    if (!condition) return error.UnexpectedState;
}

fn udp4Address(address: std.Io.net.IpAddress) !Udp4Address {
    return switch (address) {
        .ip4 => |ip4| Udp4Address.init(ip4.bytes, ip4.port),
        else => error.UnexpectedState,
    };
}

fn udp4Tuple(local: std.Io.net.IpAddress, remote: std.Io.net.IpAddress) !Udp4Tuple {
    return .{
        .local = try udp4Address(local),
        .remote = try udp4Address(remote),
    };
}

/// socket 短轮询超时：loopback 包即时送达，5ms 足够区分"有包"与"无包"。
/// 无包时事件循环靠 nextDeadline 推进虚拟时钟，不依赖真实等待。
fn shortTimeout() std.Io.Timeout {
    return .{ .duration = .{
        .clock = .awake,
        .raw = std.Io.Duration.fromMilliseconds(5),
    } };
}

/// 一端的事件循环状态。client/server 各一份。
const Endpoint = struct {
    lifecycle: *EndpointConnectionLifecycle,
    conn: *Connection,
    backend: *Tls13Backend,
    allocator: std.mem.Allocator,
    socket: *std.Io.net.Socket,
    peer_socket: *std.Io.net.Socket,
    path: Udp4Tuple,
    handle: u64,
    is_client: bool,
    /// 发包目标 DCID（对端 SCID）与本端 SCID。
    dcid: []const u8,
    scid: []const u8,
    /// 抑制 driveAndPoll：收包后只 processRecv，不发 ACK/echo。
    /// loss 场景用此模拟 ACK 丢失/处理延迟，使对端 PTO 触发。
    suppress_drive: bool = false,
};

/// 按 header form 分发收包到 Initial/Handshake/1-RTT 路由路径。
///
/// long header 用 peekProtectedLongPacketInfo 判断 packet_type；short header
/// 走 1-RTT installed-key 路径。所有路径容错：解密/路由失败时丢弃包（模拟
/// 真实网络对坏包的丢弃行为），不中断事件循环。
fn processRecv(ep: *Endpoint, data: []const u8, now: i64) void {
    if (data.len == 0) return;
    if ((data[0] & 0x80) != 0) {
        const info = protection.peekProtectedLongPacketInfo(data) catch return;
        switch (info.packet_type) {
            .initial => _ = ep.lifecycle.processRoutedProtectedInitialDatagram(
                ep.handle,
                ep.conn,
                ep.path,
                now,
                &original_dcid,
                data,
            ) catch return,
            .handshake => _ = ep.lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
                ep.handle,
                ep.conn,
                ep.path,
                now,
                data,
            ) catch return,
            .zero_rtt => return,
            .retry => return,
        }
    } else {
        _ = ep.lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
            ep.handle,
            ep.conn,
            ep.path,
            now,
            data,
        ) catch return;
    }
}

/// 驱动 TLS crypto + poll 三种空间输出，按 RFC 9001 顺序与 space 生命周期：
///   - Initial space 未 discard：drive initial -> poll Initial(SH/ACK)
///   - 有 Handshake keys 且 space 未 discard：drive handshake（产 flight/Finished）
///   - poll Handshake 输出
///   - server confirmed 发 HANDSHAKE_DONE
///   - poll 1-RTT 输出
///
/// drive initial 后立即 poll Initial，避免 drive handshake 触发 Initial space
/// discard 后 poll Initial 失败。space discarded 时跳过对应 drive/poll。
fn driveAndPoll(ep: *Endpoint, io: std.Io, now: i64, secrets: protection.InitialSecrets, scratch: []u8) !void {
    const init_key = if (ep.is_client) secrets.client else secrets.server;

    if (!ep.conn.handshakeConfirmed()) {
        // drive initial + poll Initial（space 未 discard 时）。
        if (!ep.conn.packetNumberSpaceDiscarded(.initial)) {
            _ = ep.lifecycle.driveCryptoBackendInSpaceAndArmConnection(
                ep.handle,
                ep.conn,
                .initial,
                ep.backend.cryptoBackend(),
                scratch,
            ) catch {};
            var i: usize = 0;
            while (i < 4) : (i += 1) {
                const dg = (ep.lifecycle.pollProtectedLongDatagram(
                    ep.handle,
                    ep.conn,
                    now,
                    ep.dcid,
                    ep.scid,
                    &[_]u8{},
                    .{ .initial = init_key },
                ) catch null) orelse break;
                defer ep.allocator.free(dg);
                try ep.socket.send(io, &ep.peer_socket.address, dg);
            }
        }
        // drive handshake（有 handshake keys 且 space 未 discard 时）。
        if (ep.conn.hasHandshakeProtectionKeys() and !ep.conn.packetNumberSpaceDiscarded(.handshake)) {
            _ = ep.lifecycle.driveCryptoBackendInSpaceAndArmConnection(
                ep.handle,
                ep.conn,
                .handshake,
                ep.backend.cryptoBackend(),
                scratch,
            ) catch {};
        }
    }

    // poll Handshake 输出（server flight / client Finished）。
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const dg = (ep.lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
            ep.handle,
            ep.conn,
            now,
            ep.dcid,
            ep.scid,
        ) catch null) orelse break;
        defer ep.allocator.free(dg);
        try ep.socket.send(io, &ep.peer_socket.address, dg);
    }

    // server 握手确认后发 HANDSHAKE_DONE（client 收到后才能 confirmed）。
    if (!ep.is_client and ep.conn.handshakeConfirmed()) {
        ep.conn.sendHandshakeDone() catch {};
    }

    // 触发 loss detection（packet/time-threshold loss 重传 STREAM 等）。
    _ = ep.conn.serviceLossDetectionTimer(now) catch {};

    // poll 1-RTT 输出（HANDSHAKE_DONE / ACK / STREAM / PTO probe / 重传）。
    i = 0;
    while (i < 4) : (i += 1) {
        const dg = (ep.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
            ep.handle,
            ep.conn,
            now,
            ep.dcid,
        ) catch null) orelse break;
        defer ep.allocator.free(dg);
        try ep.socket.send(io, &ep.peer_socket.address, dg);
    }
}

/// 处理到期 deadline（idle/close/recovery），poll loss/PTO probe 并发送。
///
/// `processDueDeadlineAndPollDatagram` 在 deadline 未到期时返回 null；到期时
/// 运行 pending work（含 serviceRecoveryTimer）并 poll probe datagram。返回
/// true 表示有进展（deadline 已服务），caller 据此决定是否推进虚拟时钟。
fn processDueDeadline(ep: *Endpoint, io: std.Io, now: i64, pto_fired: *bool) bool {
    const result = (ep.lifecycle.processDueDeadlineAndPollDatagram(
        ep.handle,
        ep.conn,
        now,
        ep.dcid,
        ep.scid,
    ) catch null) orelse return false;
    if (result.pending_work.recovery_serviced != null) pto_fired.* = true;
    if (result.datagram) |dg| {
        defer ep.allocator.free(dg);
        ep.socket.send(io, &ep.peer_socket.address, dg) catch {};
    }
    return true;
}

/// 取两端 nextDeadline 中较早者（用于无进展时推进虚拟时钟）。
fn earliestDeadline(
    client: *Endpoint,
    server: *Endpoint,
) ?EndpointConnectionDeadline {
    const cd = client.lifecycle.nextDeadline(client.handle, client.conn);
    const sd = server.lifecycle.nextDeadline(server.handle, server.conn);
    if (cd) |c| {
        if (sd) |s| return if (c.deadline_millis < s.deadline_millis) c else s;
        return c;
    }
    return sd;
}

/// 单步事件循环：两端各尝试收包 + driveAndPoll，再处理到期 deadline。
///
/// 无进展时推进虚拟时钟 now 到 earliestDeadline，使下一轮 processDueDeadline
/// 能触发。这是超循环的一轮，caller 在循环中调用并检查完成条件。
fn stepEventLoop(
    io: std.Io,
    client: *Endpoint,
    server: *Endpoint,
    now: *i64,
    secrets: protection.InitialSecrets,
    scratch: []u8,
    recv_buf: []u8,
    pto_fired: *bool,
) !void {
    var progressed = false;

    // 1. 两端各尝试收包（短 timeout 轮询，有包则处理 + drive + poll + send）。
    //    suppress_drive 时只 processRecv，不发 ACK/echo（模拟 ACK 丢失）。
    for ([_]*Endpoint{ client, server }) |ep| {
        const recv = ep.socket.receiveTimeout(io, recv_buf, shortTimeout()) catch null;
        if (recv) |r| {
            processRecv(ep, r.data, now.*);
            if (!ep.suppress_drive) {
                try driveAndPoll(ep, io, now.*, secrets, scratch);
            }
            progressed = true;
        }
    }

    // 2. 两端各处理到期 deadline（loss/PTO/idle/close）。
    for ([_]*Endpoint{ client, server }) |ep| {
        if (processDueDeadline(ep, io, now.*, pto_fired)) progressed = true;
    }

    // 3. 无进展时推进虚拟时钟到 next deadline（加速 PTO 触发，不依赖真实等待）。
    //    限制推进幅度，避免 idle/close deadline 的 i64 max 溢出。
    if (!progressed) {
        if (earliestDeadline(client, server)) |d| {
            const target = @min(d.deadline_millis, now.* + 100000);
            now.* = @max(now.*, target);
        }
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    // 解析命令行：interop_event_loopback [TESTCASE]
    var args_iter = std.process.Args.Iterator.init(init.minimal.args);
    _ = args_iter.next(); // 跳过程序名
    const testcase_name = args_iter.next() orelse "handshake";
    const testcase = parseTestcase(testcase_name);

    // ─── 起 UDP loopback socket（两端各绑 loopback:0，OS 分配端口） ───
    var client_addr = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var client_socket = try client_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);
    var server_addr = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var server_socket = try server_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    const server_path = try udp4Tuple(server_socket.address, client_socket.address);

    // ─── crypto material + Initial secrets ───
    const seed = [_]u8{0x55} ** 32;
    const server_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const server_priv = server_kp.secret_key.bytes;
    const cert_der = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    const alpn = [_][]const u8{"hq-interop"};
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    // ─── Connection + Tls13Backend（client + server） ───
    // initial_rtt_ms=100 使 PTO deadline 可预测（约 300ms），事件循环能快速推进触发。
    var client = try Connection.init(allocator, .client, .{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
        .initial_rtt_ms = 100,
        .max_datagram_size = 8192,
    });
    defer client.deinit();
    var server = try Connection.init(allocator, .server, .{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
        .initial_rtt_ms = 100,
        .max_datagram_size = 8192,
    });
    defer server.deinit();
    // server 已验证 peer 地址（跳过 Retry，解除放大限制）。
    try server.validatePeerAddress();
    try client.setLocalInitialSourceConnectionId(&client_scid);
    try server.setLocalInitialSourceConnectionId(&server_scid);

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

    // ─── EndpointConnectionLifecycle + CID 路由注册 ───
    // client 注册 client_scid；server 注册 original_dcid（client Initial DCID）
    // 和 server_scid，使两端收包都能路由到对应 handle。
    var client_lifecycle = EndpointConnectionLifecycle.init(allocator);
    defer client_lifecycle.deinit();
    var server_lifecycle = EndpointConnectionLifecycle.init(allocator);
    defer server_lifecycle.deinit();
    try client_lifecycle.registerConnectionId(client_handle, &client_scid, client_path, .{
        .active_migration_disabled = true,
    });
    try server_lifecycle.registerConnectionId(server_handle, &original_dcid, server_path, .{
        .active_migration_disabled = true,
    });
    try server_lifecycle.registerConnectionId(server_handle, &server_scid, server_path, .{
        .active_migration_disabled = true,
    });

    var client_ep = Endpoint{
        .lifecycle = &client_lifecycle,
        .conn = &client,
        .backend = &client_backend,
        .allocator = allocator,
        .socket = &client_socket,
        .peer_socket = &server_socket,
        .path = client_path,
        .handle = client_handle,
        .is_client = true,
        .dcid = &server_scid,
        .scid = &client_scid,
    };
    var server_ep = Endpoint{
        .lifecycle = &server_lifecycle,
        .conn = &server,
        .backend = &server_backend,
        .allocator = allocator,
        .socket = &server_socket,
        .peer_socket = &client_socket,
        .path = server_path,
        .handle = server_handle,
        .is_client = false,
        .dcid = &client_scid,
        .scid = &server_scid,
    };

    var scratch: [8192]u8 = undefined;
    var recv_buf: [2048]u8 = undefined;
    var now: i64 = 1000;
    var pto_fired = false;

    // ─── 启动：client drive initial -> poll ClientHello -> send ───
    // 事件循环前先把第一个 ClientHello 投递到 server，触发握手交互。
    _ = try client_lifecycle.driveCryptoBackendInSpaceAndArmConnection(
        client_handle,
        &client,
        .initial,
        client_backend.cryptoBackend(),
        &scratch,
    );
    const ch_dg = (try client_lifecycle.pollProtectedLongDatagram(
        client_handle,
        &client,
        now,
        &original_dcid,
        &client_scid,
        &[_]u8{},
        .{ .initial = secrets.client },
    )) orelse return error.UnexpectedState;
    defer allocator.free(ch_dg);
    try client_socket.send(io, &server_socket.address, ch_dg);

    // ─── handshake 事件循环：驱动到两端 handshakeConfirmed ───
    {
        var iters: usize = 0;
        while (iters < 500) : (iters += 1) {
            if (client.handshakeConfirmed() and server.handshakeConfirmed()) break;
            try stepEventLoop(io, &client_ep, &server_ep, &now, secrets, &scratch, &recv_buf, &pto_fired);
        }
        try require(client.handshakeConfirmed());
        try require(server.handshakeConfirmed());
    }

    if (testcase == .handshake) {
        std.debug.print("handshake_done=true\n", .{});
        return;
    }

    // ─── transfer / loss：开 bidirectional stream，发数据，收 echo ───
    const payload = "quicz-interop-event-loop-payload";
    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, payload, false);
    // poll + send client 的 STREAM datagram。
    try driveAndPoll(&client_ep, io, now, secrets, &scratch);

    // loss 场景：server suppress_drive，收到 STREAM 后不回 ACK/echo。
    // client 收不到 ACK -> PTO deadline 触发 -> 发 probe -> server 恢复 drive。
    // 这模拟 ACK 丢失/处理延迟场景下的 PTO 恢复（同步交替驱动做不到）。
    if (testcase == .loss) {
        server_ep.suppress_drive = true;
    }

    var got_echo = false;
    var echo_len: usize = 0;
    var stream_buf: [256]u8 = undefined;
    {
        var iters: usize = 0;
        while (iters < 2000) : (iters += 1) {
            if (got_echo) break;
            try stepEventLoop(io, &client_ep, &server_ep, &now, secrets, &scratch, &recv_buf, &pto_fired);
            // PTO 触发后恢复 server drive，发 ACK + echo。
            if (testcase == .loss and pto_fired and server_ep.suppress_drive) {
                server_ep.suppress_drive = false;
                try driveAndPoll(&server_ep, io, now, secrets, &scratch);
            }
            // server 收到 STREAM 后 echo 回 client（suppress 期间不 echo）。
            if (!server_ep.suppress_drive) {
                if ((try server.recvOnStream(stream_id, &stream_buf))) |n| {
                    try server.sendOnStream(stream_id, stream_buf[0..n], false);
                    try driveAndPoll(&server_ep, io, now, secrets, &scratch);
                }
            }
            // client 收 echo。
            if ((try client.recvOnStream(stream_id, &stream_buf))) |n| {
                got_echo = true;
                echo_len = n;
            }
        }
    }
    try require(got_echo);
    try require(std.mem.eql(u8, stream_buf[0..echo_len], payload));

    if (testcase == .loss) {
        std.debug.print("transfer_bytes={d} pto_recovered={}\n", .{ echo_len, pto_fired });
    } else {
        std.debug.print("transfer_bytes={d}\n", .{echo_len});
    }
}
