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
//!   TESTCASE: handshake（默认）/ transfer / loss / congestion / persistent / key-update / path / stream-control / stream-limit
//!
//! 场景（本地 loopback 自测）：
//!   handshake - 事件循环驱动 TLS 1.3 握手到两端 handshakeConfirmed
//!   transfer  - 握手后开 bidirectional stream，发数据收 echo
//!   loss      - 丢弃首个 client 1-RTT STREAM 数据报，client PTO/retransmission
//!               后的 packet-number gap 由 server 接收并 ACK，最终 transfer 成功
//!   congestion - 丢弃首个 ack-eliciting 1-RTT PING，交付后续三个 PING，
//!                用真实 sparse ACK 触发 client NewReno packet-threshold 降窗
//!   persistent - 建立 RTT sample 后丢弃三个跨 persistent-congestion duration 的
//!                PING，仅交付第四个，用真实 ACK 将 client cwnd 降到 minimum
//!   key-update - TLS-owned 1-RTT 两次 key phase 轮转，首轮 ACK 解锁下一轮，
//!                endpoint key-discard deadline 到期后拒绝旧 key 重放包
//!   path      - TLS-owned 1-RTT PATH_CHALLENGE/PATH_RESPONSE 经新 UDP tuple
//!                验证后，由 server endpoint lifecycle 提交路由迁移
//!   stream-control - TLS-backed endpoint lifecycle 经真实 UDP 发送
//!                    RESET_STREAM，并完成 STOP_SENDING 到 RESET_STREAM 的往返
//!   stream-limit - TLS-backed endpoint lifecycle 经真实 UDP 完成双向流额度
//!                  释放与 MAX_STREAMS_BIDI 更新

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
const max_key_update_datagrams: usize = 64;

const Testcase = enum { handshake, transfer, loss, congestion, persistent, key_update, path, stream_control, stream_limit };

fn parseTestcase(name: []const u8) Testcase {
    if (std.mem.eql(u8, name, "handshake")) return .handshake;
    if (std.mem.eql(u8, name, "transfer")) return .transfer;
    if (std.mem.eql(u8, name, "loss")) return .loss;
    if (std.mem.eql(u8, name, "congestion")) return .congestion;
    if (std.mem.eql(u8, name, "persistent")) return .persistent;
    if (std.mem.eql(u8, name, "key-update")) return .key_update;
    if (std.mem.eql(u8, name, "path")) return .path;
    if (std.mem.eql(u8, name, "stream-control")) return .stream_control;
    if (std.mem.eql(u8, name, "stream-limit")) return .stream_limit;
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
    /// 丢弃下一份会增加 in-flight bytes 的 1-RTT 数据报。ACK-only 包不会
    /// 满足此条件，因此受控 loss 始终针对可被 NewReno 确认的包。
    drop_next_ack_eliciting_one_rtt_datagram: bool = false,
    /// 受控 persistent-congestion 场景中需要丢弃的 ack-eliciting 1-RTT 包数。
    drop_ack_eliciting_one_rtt_datagrams: usize = 0,
    dropped_application_packet_number: ?u64 = null,
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

/// 轮询一份受保护 1-RTT 数据报；除非当前受控丢包场景消费它，否则立即发送。
/// 此路径刻意不 service recovery timer，调用方可为 persistent-loss 包赋予确定时间。
fn pollOneRttAndSend(ep: *Endpoint, io: std.Io, now: i64) !bool {
    const packet_number = ep.conn.nextPacketNumber(.application);
    const in_flight_before = ep.conn.bytesInFlight(.application);
    const dg = (ep.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        ep.handle,
        ep.conn,
        now,
        ep.dcid,
    ) catch null) orelse return false;
    defer ep.allocator.free(dg);

    const ack_eliciting = ep.conn.bytesInFlight(.application) > in_flight_before;
    if (ack_eliciting and (ep.drop_next_ack_eliciting_one_rtt_datagram or ep.drop_ack_eliciting_one_rtt_datagrams != 0)) {
        ep.drop_next_ack_eliciting_one_rtt_datagram = false;
        if (ep.drop_ack_eliciting_one_rtt_datagrams != 0) ep.drop_ack_eliciting_one_rtt_datagrams -= 1;
        if (ep.dropped_application_packet_number == null) ep.dropped_application_packet_number = packet_number;
        return true;
    }

    try ep.socket.send(io, &ep.peer_socket.address, dg);
    return true;
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
        if (!try pollOneRttAndSend(ep, io, now)) break;
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
    for ([_]*Endpoint{ client, server }) |ep| {
        const recv = ep.socket.receiveTimeout(io, recv_buf, shortTimeout()) catch null;
        if (recv) |r| {
            processRecv(ep, r.data, now.*);
            try driveAndPoll(ep, io, now.*, secrets, scratch);
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

/// Drain already-ready control/retransmission output without advancing the
/// virtual clock. Key-update probes call this before changing phase so their
/// first protected packet is not hidden behind pre-existing handshake output.
fn drainReadyOutput(
    io: std.Io,
    client: *Endpoint,
    server: *Endpoint,
    now: i64,
    secrets: protection.InitialSecrets,
    scratch: []u8,
    recv_buf: []u8,
) !void {
    var round: usize = 0;
    while (round < 64) : (round += 1) {
        try driveAndPoll(client, io, now, secrets, scratch);
        try driveAndPoll(server, io, now, secrets, scratch);
        var received_any = false;
        for ([_]*Endpoint{ client, server }) |ep| {
            const received = ep.socket.receiveTimeout(io, recv_buf, shortTimeout()) catch null;
            if (received) |datagram| {
                processRecv(ep, datagram.data, now);
                received_any = true;
            }
        }
        if (!received_any) return;
    }
    return error.UnexpectedState;
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
    var migrated_client_addr = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var migrated_client_socket = try migrated_client_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer migrated_client_socket.close(io);

    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    const server_path = try udp4Tuple(server_socket.address, client_socket.address);
    const migrated_client_path = try udp4Tuple(migrated_client_socket.address, server_socket.address);
    const migrated_server_path = try udp4Tuple(server_socket.address, migrated_client_socket.address);

    // ─── crypto material + Initial secrets ───
    const seed = [_]u8{0x55} ** 32;
    const server_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const server_priv = server_kp.secret_key.bytes;
    const cert_der = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    const alpn = [_][]const u8{"hq-interop"};
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    // ─── Connection + Tls13Backend（client + server） ───
    // initial_rtt_ms=100 使 PTO deadline 可预测（约 300ms），事件循环能快速推进触发。
    const initial_max_streams_bidi: u64 = if (testcase == .stream_limit) 1 else 8;
    var client = try Connection.init(allocator, .client, .{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = initial_max_streams_bidi,
        .initial_rtt_ms = 100,
        // Keep the RFC 9002 minimum window below the initial window so the
        // congestion testcases can observe a genuine RFC 9002 reduction.
        .max_datagram_size = 1200,
    });
    defer client.deinit();
    var server = try Connection.init(allocator, .server, .{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = initial_max_streams_bidi,
        .initial_rtt_ms = 100,
        .max_datagram_size = 1200,
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
        .active_migration_disabled = testcase != .path,
    });
    try server_lifecycle.registerConnectionId(server_handle, &original_dcid, server_path, .{
        .active_migration_disabled = testcase != .path,
    });
    try server_lifecycle.registerConnectionId(server_handle, &server_scid, server_path, .{
        .active_migration_disabled = testcase != .path,
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

    if (testcase == .congestion) {
        // Keep the controlled loss exchange separate from handshake traffic.
        now += 1;
        const initial_cwnd = client.congestionWindow(.application);
        try require(initial_cwnd > 0);

        // Queue four independently ack-eliciting packets. The first is dropped
        // after polling, while the other three traverse the real UDP sockets.
        // Process all three at the server before it polls one sparse ACK. This
        // removes ACK scheduling as a variable: its largest acknowledged packet
        // is exactly three ahead of the dropped packet.
        const first_ping_packet_number = client.nextPacketNumber(.application);
        for (0..4) |_| try client.sendPing();
        client_ep.drop_next_ack_eliciting_one_rtt_datagram = true;
        try driveAndPoll(&client_ep, io, now, secrets, &scratch);

        const dropped_packet_number = client_ep.dropped_application_packet_number orelse return error.UnexpectedState;
        try require(dropped_packet_number == first_ping_packet_number);

        var delivered_pings: usize = 0;
        while (delivered_pings < 3) : (delivered_pings += 1) {
            const received = try server_socket.receiveTimeout(io, &recv_buf, shortTimeout());
            processRecv(&server_ep, received.data, now);
        }
        try require(server.pendingAckLargest(.application) == first_ping_packet_number + 3);
        try require(server.nextPeerPacketNumber(.application) == first_ping_packet_number + 4);
        try driveAndPoll(&server_ep, io, now, secrets, &scratch);

        // A completed handshake can leave a valid control packet in the client
        // socket. Drain the bounded server output and require the sparse ACK to
        // retire the three delivered PINGs before inspecting NewReno state.
        var received_server_packets: usize = 0;
        while (received_server_packets < 4 and client.sentPacketCount(.application) > 1) : (received_server_packets += 1) {
            const datagram = try client_socket.receiveTimeout(io, &recv_buf, shortTimeout());
            const route = try client_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
                client_handle,
                &client,
                client_path,
                now,
                datagram.data,
            );
            try require(route.connection_id == client_handle);
        }
        // The sparse ACK both confirms packets 1..3 and classifies packet 0 as
        // packet-threshold lost, so all four tracking records are retired.
        try require(client.sentPacketCount(.application) == 0);

        std.debug.print("newreno_trace dropped_packet={d} received_server_packets={d} sent_packets={d} in_flight={d} cwnd_before={d} cwnd_after={d}\n", .{
            dropped_packet_number,
            received_server_packets,
            client.sentPacketCount(.application),
            client.bytesInFlight(.application),
            initial_cwnd,
            client.congestionWindow(.application),
        });
        try require(client.congestionWindow(.application) < initial_cwnd);
        try require(client.bytesInFlight(.application) == 0);
        std.debug.print("newreno_loss=true dropped_packet={d} cwnd_before={d} cwnd_after={d}\n", .{
            dropped_packet_number,
            initial_cwnd,
            client.congestionWindow(.application),
        });
        return;
    }

    if (testcase == .persistent) {
        // Establish an RTT sample before candidate-loss packets. RFC 9002 only
        // considers packets sent after this sample for persistent congestion.
        now += 10;
        try client.sendPing();
        try require(try pollOneRttAndSend(&client_ep, io, now));
        const rtt_ping = try server_socket.receiveTimeout(io, &recv_buf, shortTimeout());
        processRecv(&server_ep, rtt_ping.data, now);
        try require(server.pendingAckLargest(.application) == 0);

        now += 100;
        try driveAndPoll(&server_ep, io, now, secrets, &scratch);
        var rtt_ack_packets: usize = 0;
        while (rtt_ack_packets < 4 and client.sentPacketCount(.application) != 0) : (rtt_ack_packets += 1) {
            const datagram = try client_socket.receiveTimeout(io, &recv_buf, shortTimeout());
            const route = try client_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
                client_handle,
                &client,
                client_path,
                now,
                datagram.data,
            );
            try require(route.connection_id == client_handle);
        }
        try require(client.sentPacketCount(.application) == 0);

        const first_lost_packet_number = client.nextPacketNumber(.application);
        const persistent_duration = client.recovery_state.persistentCongestionDurationMs();
        const send_times = [_]i64{ now + 10, now + 1000, now + 1100, now + 1200 };
        const initial_cwnd = client.congestionWindow(.application);
        client_ep.drop_ack_eliciting_one_rtt_datagrams = 3;
        for (send_times) |send_time| {
            try client.sendPing();
            try require(try pollOneRttAndSend(&client_ep, io, send_time));
        }
        try require(client_ep.dropped_application_packet_number == first_lost_packet_number);

        const final_ping = try server_socket.receiveTimeout(io, &recv_buf, shortTimeout());
        processRecv(&server_ep, final_ping.data, send_times[3]);
        try require(server.pendingAckLargest(.application) == first_lost_packet_number + 3);
        try require(server.nextPeerPacketNumber(.application) == first_lost_packet_number + 4);

        now = send_times[3] + 100;
        try driveAndPoll(&server_ep, io, now, secrets, &scratch);
        var persistent_ack_packets: usize = 0;
        while (persistent_ack_packets < 4 and client.sentPacketCount(.application) != 0) : (persistent_ack_packets += 1) {
            const datagram = try client_socket.receiveTimeout(io, &recv_buf, shortTimeout());
            const route = try client_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
                client_handle,
                &client,
                client_path,
                now,
                datagram.data,
            );
            try require(route.connection_id == client_handle);
        }

        const minimum_cwnd = quicz.recovery.minimumCongestionWindow(1200);
        try require(client.sentPacketCount(.application) == 0);
        try require(client.bytesInFlight(.application) == 0);
        try require(client.congestionWindow(.application) == minimum_cwnd);
        try require(client.congestionWindow(.application) < initial_cwnd);
        std.debug.print("persistent_congestion=true first_lost_packet={d} duration_ms={d} rtt_ack_packets={d} persistent_ack_packets={d} cwnd_before={d} cwnd_after={d}\n", .{
            first_lost_packet_number,
            persistent_duration,
            rtt_ack_packets,
            persistent_ack_packets,
            initial_cwnd,
            client.congestionWindow(.application),
        });
        return;
    }

    if (testcase == .key_update) {
        // Handshake confirmation can leave an ACK or HANDSHAKE_DONE control
        // packet queued. Deliver that bounded residual output before switching
        // phase, so the retained datagram below is unambiguously the update
        // PING rather than pre-update traffic.
        try drainReadyOutput(io, &client_ep, &server_ep, now, secrets, &scratch, &recv_buf);

        // The first update must be acknowledged before the local sender may
        // rotate again. Keep its protected packet so the server can later
        // prove that its expired previous generation rejects an old replay.
        const initial_key_phase = client.localOneRttKeyPhase() orelse return error.UnexpectedState;
        now += 1;
        try client.initiateOneRttKeyUpdate();
        try require(client.localOneRttKeyPhase().? != initial_key_phase);
        try require(client.pendingOneRttKeyUpdateAckThreshold() != null);
        try client.sendPing();
        var stale_first_update: ?[]u8 = null;
        defer if (stale_first_update) |datagram| allocator.free(datagram);
        var first_update_packets: usize = 0;
        while (first_update_packets < max_key_update_datagrams) : (first_update_packets += 1) {
            const outgoing = (try client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                client_handle,
                &client,
                now,
                &server_scid,
            )) orelse return error.UnexpectedState;
            defer allocator.free(outgoing);
            try client_socket.send(io, &server_socket.address, outgoing);

            const received = try server_socket.receiveTimeout(io, &recv_buf, shortTimeout());
            _ = server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
                server_handle,
                &server,
                server_path,
                now,
                received.data,
            ) catch |err| switch (err) {
                error.InvalidPacket => continue,
                else => return err,
            };
            if ((server.peerOneRttKeyUpdateCount() orelse return error.UnexpectedState) == 1) {
                stale_first_update = try allocator.dupe(u8, outgoing);
                break;
            }
        }
        const stale_first_update_datagram = stale_first_update orelse return error.UnexpectedState;
        try require((server.peerOneRttKeyUpdateCount() orelse return error.UnexpectedState) == 1);

        var first_ack_packets: usize = 0;
        while (client.pendingOneRttKeyUpdateAckThreshold() != null and first_ack_packets < max_key_update_datagrams) : (first_ack_packets += 1) {
            const outgoing = (try server_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                server_handle,
                &server,
                now + 1,
                &client_scid,
            )) orelse return error.UnexpectedState;
            defer allocator.free(outgoing);
            try server_socket.send(io, &client_socket.address, outgoing);

            const received = try client_socket.receiveTimeout(io, &recv_buf, shortTimeout());
            _ = client_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
                client_handle,
                &client,
                client_path,
                now + 1,
                received.data,
            ) catch |err| switch (err) {
                error.InvalidPacket => continue,
                else => return err,
            };
        }
        try require(client.pendingOneRttKeyUpdateAckThreshold() == null);

        try drainReadyOutput(io, &client_ep, &server_ep, now + 1, secrets, &scratch, &recv_buf);

        // A second live TLS-owned update flips back to key phase zero and
        // leaves generation one as the server's retained previous key.
        now += 2;
        try client.initiateOneRttKeyUpdate();
        try require(client.localOneRttKeyPhase().? == initial_key_phase);
        try client.sendPing();
        var second_update_packets: usize = 0;
        while ((server.peerOneRttKeyUpdateCount() orelse return error.UnexpectedState) < 2 and second_update_packets < max_key_update_datagrams) : (second_update_packets += 1) {
            const outgoing = (try client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                client_handle,
                &client,
                now,
                &server_scid,
            )) orelse return error.UnexpectedState;
            defer allocator.free(outgoing);
            try client_socket.send(io, &server_socket.address, outgoing);

            const received = try server_socket.receiveTimeout(io, &recv_buf, shortTimeout());
            _ = server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
                server_handle,
                &server,
                server_path,
                now,
                received.data,
            ) catch |err| switch (err) {
                error.InvalidPacket => continue,
                else => return err,
            };
        }
        try require((server.peerOneRttKeyUpdateCount() orelse return error.UnexpectedState) == 2);
        try require(server.peerOneRttRetainsKeyGeneration(1).?);

        const key_discard_deadline = server.oneRttKeyDiscardDeadlineMillis() orelse return error.UnexpectedState;
        const endpoint_deadline = server_lifecycle.nextDeadline(server_handle, &server) orelse return error.UnexpectedState;
        try require(endpoint_deadline.kind == .key_discard);
        try require(endpoint_deadline.deadline_millis == key_discard_deadline);
        now = key_discard_deadline;
        const discard_result = (try server_lifecycle.processDueDeadlineAndPollDatagram(
            server_handle,
            &server,
            now,
            &client_scid,
            &server_scid,
        )) orelse return error.UnexpectedState;
        try require(discard_result.deadline.kind == .key_discard);
        try require(discard_result.datagram == null);
        try require(!server.peerOneRttRetainsKeyGeneration(1).?);

        // The server must reject the first-update packet after its retained
        // peer generation has expired, before duplicate packet-number handling
        // could otherwise hide the obsolete protection key.
        try client_socket.send(io, &server_socket.address, stale_first_update_datagram);
        const stale_received = try server_socket.receiveTimeout(io, &recv_buf, shortTimeout());
        const stale_rejected = if (server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
            server_handle,
            &server,
            server_path,
            now,
            stale_received.data,
        )) |_| false else |err| switch (err) {
            error.InvalidPacket => true,
            else => return err,
        };
        try require(stale_rejected);

        std.debug.print("tls_key_update=true first_ack_gate_cleared=true second_update_count={d} discard_deadline={d} stale_rejected={}\n", .{
            server.peerOneRttKeyUpdateCount().?,
            key_discard_deadline,
            stale_rejected,
        });
        return;
    }

    if (testcase == .path) {
        // Clear handshake ACK/HANDSHAKE_DONE output so the next client packet
        // on the new tuple is exactly the PATH_RESPONSE below.
        try drainReadyOutput(io, &client_ep, &server_ep, now, secrets, &scratch, &recv_buf);
        now += 1;

        // A locally initiated migration changes the client's inbound tuple
        // before it receives the server's challenge. The server remains on the
        // old route until authenticated PATH_RESPONSE consumes its challenge.
        try require(migrated_client_socket.address.getPort() != client_socket.address.getPort());
        const client_route = try client_lifecycle.updateRoutePathAndResetSpinBit(
            &client_scid,
            client_path,
            migrated_client_path,
            &client,
        );
        try require(!client_route.path_changed);

        const challenge_data = [_]u8{ 0x73, 0x9d, 0x11, 0x56, 0xca, 0xfe, 0x80, 0x01 };
        try server.sendPathChallenge(challenge_data);
        const challenge = (try server_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
            server_handle,
            &server,
            now,
            &client_scid,
        )) orelse return error.UnexpectedState;
        defer allocator.free(challenge);
        try require(server.outstandingPathChallengeCount() == 1);
        try server_socket.send(io, &migrated_client_socket.address, challenge);

        const challenge_received = try migrated_client_socket.receiveTimeout(io, &recv_buf, shortTimeout());
        const client_result = try client_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeysOrClose(
            client_handle,
            &client,
            migrated_client_path,
            now,
            challenge_received.data,
        );
        try require(!client_result.path_changed);

        const response = (try client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
            client_handle,
            &client,
            now + 1,
            &server_scid,
        )) orelse return error.UnexpectedState;
        defer allocator.free(response);
        try migrated_client_socket.send(io, &server_socket.address, response);

        const response_received = try server_socket.receiveTimeout(io, &recv_buf, shortTimeout());
        const server_result = try server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAndUpdatePathOrClose(
            server_handle,
            &server,
            migrated_server_path,
            now + 1,
            response_received.data,
        );
        try require(server_result.route.path_changed);
        const updated_route = server_result.updated_route orelse return error.UnexpectedState;
        try require(!updated_route.path_changed);
        try require(server.outstandingPathChallengeCount() == 0);
        try require(!(try server_lifecycle.routeDatagram(migrated_server_path, response_received.data)).path_changed);

        std.debug.print("tls_path_validation=true old_client_port={} new_client_port={} server_route_updated=true\n", .{
            client_socket.address.getPort(),
            migrated_client_socket.address.getPort(),
        });
        return;
    }

    if (testcase == .stream_control) {
        // Ensure each asserted datagram belongs to the control exchange rather
        // than residual handshake ACK or HANDSHAKE_DONE output.
        try drainReadyOutput(io, &client_ep, &server_ep, now, secrets, &scratch, &recv_buf);
        now += 1;

        // A client-initiated unidirectional stream is send-only at the client
        // and receive-only at the server. RESET_STREAM must cross the protected
        // UDP/lifecycle path and create the peer receive reset state.
        const reset_stream_id = try client.openUniStream();
        try client.resetStream(reset_stream_id, 41);
        const reset_datagram = (try client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
            client_handle,
            &client,
            now,
            &server_scid,
        )) orelse return error.UnexpectedState;
        defer allocator.free(reset_datagram);
        try client_socket.send(io, &server_socket.address, reset_datagram);
        const reset_received = try server_socket.receiveTimeout(io, &recv_buf, shortTimeout());
        const reset_route = try server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
            server_handle,
            &server,
            server_path,
            now,
            reset_received.data,
        );
        try require(reset_route.connection_id == server_handle);
        const reset_state = (try server.streamState(reset_stream_id)) orelse return error.UnexpectedState;
        try require(reset_state.receive == .reset_received);
        try require(reset_state.receive_reset_error_code.? == 41);

        // The server asks the client to stop a live bidirectional send side.
        // The client must emit the matching RESET_STREAM, which the server
        // receives through the same protected endpoint path.
        const stop_stream_id = try client.openStream();
        try client.sendOnStream(stop_stream_id, "stop", false);
        const stream_datagram = (try client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
            client_handle,
            &client,
            now + 1,
            &server_scid,
        )) orelse return error.UnexpectedState;
        defer allocator.free(stream_datagram);
        try client_socket.send(io, &server_socket.address, stream_datagram);
        const stream_received = try server_socket.receiveTimeout(io, &recv_buf, shortTimeout());
        _ = try server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
            server_handle,
            &server,
            server_path,
            now + 1,
            stream_received.data,
        );
        const received_stream = (try server.streamState(stop_stream_id)) orelse return error.UnexpectedState;
        try require(received_stream.receive == .receiving);
        try require(received_stream.receive_buffered.? == 4);

        try server.stopSending(stop_stream_id, 42);
        const stop_datagram = (try server_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
            server_handle,
            &server,
            now + 2,
            &client_scid,
        )) orelse return error.UnexpectedState;
        defer allocator.free(stop_datagram);
        try server_socket.send(io, &client_socket.address, stop_datagram);
        const stop_received = try client_socket.receiveTimeout(io, &recv_buf, shortTimeout());
        _ = try client_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
            client_handle,
            &client,
            client_path,
            now + 2,
            stop_received.data,
        );
        const stopped_client_stream = (try client.streamState(stop_stream_id)) orelse return error.UnexpectedState;
        try require(stopped_client_stream.send == .reset_sent);

        const reset_response = (try client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
            client_handle,
            &client,
            now + 3,
            &server_scid,
        )) orelse return error.UnexpectedState;
        defer allocator.free(reset_response);
        try client_socket.send(io, &server_socket.address, reset_response);
        const reset_response_received = try server_socket.receiveTimeout(io, &recv_buf, shortTimeout());
        _ = try server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
            server_handle,
            &server,
            server_path,
            now + 3,
            reset_response_received.data,
        );
        const stopped_server_stream = (try server.streamState(stop_stream_id)) orelse return error.UnexpectedState;
        try require(stopped_server_stream.receive == .reset_received);
        try require(stopped_server_stream.receive_reset_error_code.? == 42);

        std.debug.print("tls_stream_control=true reset_error=41 stop_error=42\n", .{});
        return;
    }

    if (testcase == .stream_limit) {
        // Keep the flow-control exchange separate from residual handshake ACK
        // and HANDSHAKE_DONE packets, then prove the peer's advertised limit
        // is initially exhausted.
        try drainReadyOutput(io, &client_ep, &server_ep, now, secrets, &scratch, &recv_buf);
        now += 1;
        const first_stream = try client.openStream();
        try require(first_stream == 0);
        const limit_blocked = if (client.openStream()) |_| false else |err| switch (err) {
            error.FlowControlBlocked => true,
            else => return err,
        };
        try require(limit_blocked);
        try client.sendOnStream(first_stream, "limit", true);
        try driveAndPoll(&client_ep, io, now, secrets, &scratch);

        var request_received = false;
        var stream_buf: [16]u8 = undefined;
        var request_round: usize = 0;
        while (!request_received and request_round < 32) : (request_round += 1) {
            try stepEventLoop(io, &client_ep, &server_ep, &now, secrets, &scratch, &recv_buf, &pto_fired);
            if ((try server.recvOnStream(first_stream, &stream_buf))) |n| {
                try require(std.mem.eql(u8, stream_buf[0..n], "limit"));
                request_received = try server.recvStreamFinished(first_stream);
            }
        }
        try require(request_received);

        // Reading the peer FIN releases one receive-side stream credit. The
        // server emits that MAX_STREAMS_BIDI update as a protected 1-RTT UDP
        // datagram, after which the client can allocate stream ID 4.
        try driveAndPoll(&server_ep, io, now, secrets, &scratch);
        var next_stream: ?u64 = null;
        var release_round: usize = 0;
        while (next_stream == null and release_round < 32) : (release_round += 1) {
            const received = client_socket.receiveTimeout(io, &recv_buf, shortTimeout()) catch continue;
            processRecv(&client_ep, received.data, now);
            next_stream = client.openStream() catch |err| switch (err) {
                error.FlowControlBlocked => null,
                else => return err,
            };
        }
        try require(next_stream.? == 4);
        std.debug.print("tls_stream_limit=true released_stream=4\n", .{});
        return;
    }

    // ─── transfer / loss：开 bidirectional stream，双向 FIN 后收 echo ───
    const payload = "quicz-interop-event-loop-payload";
    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, payload, true);
    if (testcase == .loss) {
        client_ep.drop_next_ack_eliciting_one_rtt_datagram = true;
    }
    // poll + send client 的 STREAM datagram；loss 场景会实际丢弃第一份。
    try driveAndPoll(&client_ep, io, now, secrets, &scratch);

    var got_echo = false;
    var got_echo_fin = false;
    var got_request = false;
    var sent_echo = false;
    var echo_len: usize = 0;
    var stream_buf: [256]u8 = undefined;
    {
        var iters: usize = 0;
        while (iters < 2000) : (iters += 1) {
            if (got_echo_fin) break;
            try stepEventLoop(io, &client_ep, &server_ep, &now, secrets, &scratch, &recv_buf, &pto_fired);
            // server 在完整消费请求 FIN 后才用 FIN 回显。
            if (!got_request) {
                if ((try server.recvOnStream(stream_id, &stream_buf))) |n| {
                    try require(std.mem.eql(u8, stream_buf[0..n], payload));
                    got_request = true;
                }
            }
            if (got_request and !sent_echo and try server.recvStreamFinished(stream_id)) {
                try server.sendOnStream(stream_id, payload, true);
                try driveAndPoll(&server_ep, io, now, secrets, &scratch);
                sent_echo = true;
            }
            // client 收 echo，并确认对端 FIN 已被完整消费。
            if ((try client.recvOnStream(stream_id, &stream_buf))) |n| {
                got_echo = true;
                echo_len = n;
            }
            if (got_echo and try client.recvStreamFinished(stream_id)) {
                got_echo_fin = true;
            }
        }
    }
    try require(got_echo);
    try require(got_echo_fin);
    try require(std.mem.eql(u8, stream_buf[0..echo_len], payload));

    if (testcase == .loss) {
        std.debug.print("transfer_bytes={d} pto_recovered={}\n", .{ echo_len, pto_fired });
    } else {
        std.debug.print("transfer_bytes={d}\n", .{echo_len});
    }
}
