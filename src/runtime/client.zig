//! quicz I/O runtime — async streaming client (std.Io event-driven model).
//!
//! Mirrors the server runtime: a recv task blocks on the UDP socket and
//! queues datagrams; the drive task owns the client endpoint exclusively,
//! routes datagrams, delivers stream data to per-stream queues, services
//! lifecycle deadlines, and parks on a futex word bumped by every wakeup
//! source (std.Build.WebServer update_id pattern). Callers block on
//! semaphores instead of polling.

const std = @import("std");
const builtin = @import("builtin");
const quicz = @import("../lib.zig");

const endpoint = quicz.endpoint;
const quic_packet = quicz.packet;

const log = std.log.scoped(.quicz_runtime);

test "client runtime answers an authenticated probe after socket handoff" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var peer = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer peer.close(io);
    var client = try Client.init(std.testing.allocator, io, .{
        .server_port = peer.address.ip4.port,
        .alpn = &.{},
        .insecure_skip_verify = true,
    });
    defer client.deinit();
    const key: quicz.connectivity.punch_wire.Key = @splat(0x42);
    const attempt_id: quicz.connectivity.punch_wire.AttemptId = @splat(0x11);
    try client.retainPunchResponder(try .init(
        key,
        attempt_id,
        @splat(0xa1),
        peer.address,
        @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds),
        500,
    ));
    const probe = quicz.connectivity.punch_wire.encode(key, .{
        .kind = .probe,
        .attempt_id = attempt_id,
        .nonce = @splat(0xb2),
    });
    const delayed_ack = quicz.connectivity.punch_wire.encode(key, .{
        .kind = .acknowledgement,
        .attempt_id = attempt_id,
        .nonce = @splat(0xa1),
    });
    try client.startTasks();
    const destination = std.Io.net.IpAddress{ .ip4 = .loopback(client.localPort()) };
    try peer.send(io, &destination, &delayed_ack);
    try peer.send(io, &destination, &probe);
    var buffer: [128]u8 = undefined;
    const received = try peer.receiveTimeout(io, &buffer, .{ .duration = .{
        .clock = .awake,
        .raw = .fromMilliseconds(500),
    } });
    try std.testing.expectEqual(
        quicz.connectivity.punch_wire.Kind.acknowledgement,
        (try quicz.connectivity.punch_wire.decode(key, received.data)).kind,
    );
}

test "closing client answers a peer retransmission with one close packet" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const protection = quicz.protection;
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var peer = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer peer.close(io);
    var client = try Client.init(allocator, io, .{ .server_port = peer.address.ip4.port, .alpn = &.{}, .insecure_skip_verify = true });
    defer client.deinit();
    const server_cid: [8]u8 = @splat(0xa1);
    const client_cid = client.client.transport.local_source_connection_id;
    const secrets = try protection.deriveInitialSecrets(.v1, &server_cid);
    const conn = &client.client.transport.connection;
    try conn.setLocalInitialSourceConnectionId(&client_cid);
    try conn.setPeerInitialSourceConnectionId(&server_cid);
    try conn.installOneRttTrafficSecrets(.{ .local = secrets.client.secret, .peer = secrets.server.secret });
    try conn.confirmHandshake();
    client.handshake_state.store(Client.handshake_confirmed, .release);
    client.close();
    client.processCloseRequest();
    var incoming: [1500]u8 = undefined;
    const timeout: std.Io.Timeout = .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(100) } };
    _ = try peer.receiveTimeout(io, &incoming, timeout);
    const retransmission = try protection.protectShortPacketAes128(allocator, .{
        .dcid = &client_cid,
        .key_phase = false,
        .packet_number = 0,
    }, .{ .len = 4, .truncated_packet_number = 0 }, secrets.server, &.{ 1, 0, 0 });
    defer allocator.free(retransmission);
    client.processDatagram(peer.address, retransmission);
    const received = try peer.receiveTimeout(io, &incoming, timeout);
    var decoded = try protection.unprotectShortPacketAes128(allocator, secrets.client, received.data, server_cid.len, 1);
    defer protection.deinitProtectedShortPacket(&decoded, allocator);
    var close_frame = try quicz.frame.decodeFrameSlice(decoded.packet.plaintext, allocator);
    defer quicz.frame.deinitFrame(&close_frame.frame, allocator);
    switch (close_frame.frame) {
        .application_close => {},
        else => return error.TestUnexpectedResult,
    }
    client.processDatagram(peer.address, retransmission);
    _ = try peer.receiveTimeout(io, &incoming, timeout);
    client.processDatagram(peer.address, retransmission);
    try std.testing.expectError(error.Timeout, peer.receiveTimeout(io, &incoming, timeout));
}

test "waitClosed observes terminal timers and allows timeout and cancellation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var peer = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer peer.close(io);
    var client = try Client.init(allocator, io, .{ .server_port = peer.address.ip4.port, .alpn = &.{}, .insecure_skip_verify = true });
    defer client.deinit();
    try std.testing.expectError(error.InvalidTimeout, client.waitClosed(0));
    try std.testing.expectError(error.ClientNotStarted, client.waitClosed(1));
    const server_cid: [8]u8 = @splat(0xa1);
    const conn = &client.client.transport.connection;
    try conn.setLocalInitialSourceConnectionId(&client.client.transport.local_source_connection_id);
    try conn.setPeerInitialSourceConnectionId(&server_cid);
    try conn.installOneRttTrafficSecrets(.{ .local = @splat(1), .peer = @splat(2) });
    try conn.confirmHandshake();
    conn.recovery_state.smoothed_rtt_ns = std.time.ns_per_ms;
    conn.recovery_state.rttvar_ns = 0;
    conn.recovery_state.max_ack_delay_ns = 0;
    client.handshake_state.store(Client.handshake_confirmed, .release);
    try client.startTasks();
    try std.testing.expectError(error.ConnectionTimedOut, client.waitClosed(1));
    const Waiter = struct {
        client: *Client,
        ready: std.Io.Event = .unset,
        failure: ?anyerror = null,

        fn run(self: *@This()) std.Io.Cancelable!void {
            self.ready.set(self.client.io);
            self.client.waitClosed(1000) catch |err| {
                self.failure = err;
            };
        }
    };
    var waiter = Waiter{ .client = &client };
    var waiting = try io.concurrent(Waiter.run, .{&waiter});
    try waiter.ready.wait(io);
    try waiting.cancel(io);
    try std.testing.expectEqual(@as(?anyerror, error.Canceled), waiter.failure);
    try std.testing.expect(!client.protocol_closed.isSet());
    client.close();
    try client.waitClosed(1000);
    try std.testing.expect(client.protocol_closed.isSet());
}

/// Receive-buffer / datagram-pool size (UDP payload allowance).
const max_datagram_size: usize = 8192;
/// Outbound QUIC packet size cap (standard MTU). Sending jumbo datagrams
/// (up to the receive allowance) inflates RTT samples and triggers
/// congestion on loopback, so packets are capped at the MTU while the
/// receive path keeps the larger allowance.
/// Outbound QUIC packet size cap (standard MTU). Sending jumbo datagrams
/// (up to the receive allowance) inflates RTT samples and triggers a
/// congestion / pacer feedback loop on loopback after sustained transfer
/// (see goal.md 256-stream bug), so packets are capped at the MTU while
/// the receive path keeps the larger allowance. Loopback benchmarks that
/// want jumbo packets can raise this (4096 is a safe middle ground).
const send_mtu: usize = 1350;

const queued_datagram_pool_size = 16;

/// Reusable receive buffers: the recv task takes a buffer from the pool
/// instead of allocating per datagram, and the drive task returns it. Falls
/// back to the allocator when the pool is exhausted. `release` matches by
/// pointer, so a partial slice of a pooled buffer is returned correctly.
const DatagramPool = struct {
    buffers: [queued_datagram_pool_size][]u8 = undefined,
    free: [queued_datagram_pool_size]bool = @splat(true),
    mutex: std.atomic.Mutex = .unlocked,

    fn init(allocator: std.mem.Allocator) DatagramPool {
        var pool: DatagramPool = .{};
        for (&pool.buffers) |*b| b.* = allocator.alloc(u8, max_datagram_size) catch &.{};
        return pool;
    }

    fn deinit(self: *DatagramPool, allocator: std.mem.Allocator) void {
        for (self.buffers) |b| {
            if (b.len != 0) allocator.free(b);
        }
    }

    fn take(self: *DatagramPool) ?[]u8 {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        defer self.mutex.unlock();
        for (&self.free, 0..) |*f, i| {
            if (f.*) {
                f.* = false;
                return self.buffers[i];
            }
        }
        return null;
    }

    fn release(self: *DatagramPool, buffer: []u8) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        defer self.mutex.unlock();
        for (&self.free, 0..) |*f, i| {
            if (self.buffers[i].ptr == buffer.ptr) {
                f.* = true;
                return;
            }
        }
    }
};

/// Datagram received by the recv task, waiting for the drive task.
const QueuedDatagram = struct {
    from: std.Io.net.IpAddress,
    /// Owned copy; the drive task frees it after processing.
    data: []u8,
    /// True when `data` is a pooled buffer (returned to the pool, not freed).
    pooled: bool = false,
};

/// Per-stream receive buffer (single connection, client-opened streams).
const StreamRecvState = struct {
    id: u64,
    queue: std.ArrayList(u8) = .empty,
    /// First unread byte; avoids shifting the queue on every read.
    read_offset: usize = 0,
    /// Peer FIN received and all stream bytes delivered to the queue.
    eof: bool = false,
};

/// One caller send, parked in the request slot until the drive task runs it.
/// The caller blocks until done, so `data` may stay a borrowed slice.
const SendRequest = struct {
    data: []const u8,
    fin: bool,
    /// Stream id assigned by the drive task; null on failure.
    result: ?u64 = null,
};

/// One caller send on an already-open stream, parked until the drive task runs
/// it. The caller blocks until done, so `data` may stay a borrowed slice.
const SendOnStreamRequest = struct {
    stream_id: u64,
    data: []const u8,
    fin: bool,
    ok: bool = false,
};

/// One caller key update request, parked until the drive task runs it.
const KeyUpdateRequest = struct {
    ok: bool = false,
};

/// One caller stream-open request (bidirectional or unidirectional), parked
/// until the drive task opens the stream on the transport.
const OpenStreamRequest = struct {
    uni: bool,
    /// Stream id assigned by the drive task; null on failure.
    result: ?u64 = null,
};

test "pacing client wait observes budget readiness without new traffic" {
    // This query reads only the initialized transport connection and keepalive deadline.
    // No socket or runtime task participates in this controlled-clock test.
    var client: Client = undefined;
    client.client.transport.connection = try quicz.Connection.init(std.testing.allocator, .client, .{ .max_datagram_size = 1200 });
    defer client.client.transport.connection.deinit();
    client.next_keepalive_nanos = 10 * std.time.ns_per_s;
    const conn = &client.client.transport.connection;
    try conn.confirmHandshake();
    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "paced payload", false);
    conn.recovery_state.min_rtt_ns = 100 * std.time.ns_per_ms;
    conn.recovery_state.smoothed_rtt_ns = 100 * std.time.ns_per_ms;
    conn.recovery_state.congestion_window = 12_000;
    conn.tx_pacer.budget = 0;
    conn.tx_pacer.last_sent_ns = 0;
    const dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &dcid);
    try std.testing.expect(try conn.pollProtectedShortDatagram(0, &dcid, secrets.client) == null);

    const timeout = client.nextDriveTimeout();
    const ready_at: i64 = switch (timeout) {
        .deadline => |deadline| @intCast(deadline.raw.nanoseconds),
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(i64, 8 * std.time.ns_per_ms), ready_at);
    client.next_keepalive_nanos = std.time.ns_per_ms;
    const earlier = client.nextDriveTimeout();
    try std.testing.expectEqual(@as(i96, std.time.ns_per_ms), earlier.deadline.raw.nanoseconds);
    client.next_keepalive_nanos = 10 * std.time.ns_per_s;
    try std.testing.expect(try conn.pollProtectedShortDatagram(ready_at - 1, &dcid, secrets.client) == null);
    const datagram = (try conn.pollProtectedShortDatagram(ready_at, &dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(datagram);
    try std.testing.expectEqual(@as(?i64, null), conn.pacingDeadline());
}

pub const Client = ClientForTuple(endpoint.Udp4Tuple);
/// Native IPv6 client with an explicitly bound source socket.
pub const IPv6Client = ClientForTuple(endpoint.Udp6Tuple);

/// Build the shared streaming client for one UDP address family.
pub fn ClientForTuple(comptime Path: type) type {
    return ClientForTupleWithDatagramLimit(Path, if (Path == endpoint.Udp6Tuple) 1200 else @intCast(send_mtu));
}

/// Build a client with a smaller UDP payload limit without changing Config.
/// The limit must be at least 1200 and cannot exceed this family's default.
pub fn ClientForTupleWithDatagramLimit(comptime Path: type, comptime datagram_limit: u16) type {
    const Family = @import("udp_address.zig").ForTuple(Path);
    const TlsEndpoint = @import("../quic/tls13_client_endpoint.zig").Tls13ClientEndpointForTuple(Path);
    const default_datagram_limit = if (Path == endpoint.Udp6Tuple) 1200 else send_mtu;
    if (datagram_limit < 1200 or datagram_limit > default_datagram_limit)
        @compileError("UDP payload limit must be between 1200 and the address family's default");
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        io: std.Io,
        socket: std.Io.net.Socket,
        client: TlsEndpoint,
        server_address: std.Io.net.IpAddress,
        keepalive_interval_nanos: i64,
        /// Drive-task only. Null until handshake confirmation.
        next_keepalive_nanos: ?i64 = null,
        punch_responder: ?quicz.connectivity.punch_responder.PunchResponder = null,
        scratch: [8192]u8 = undefined,

        drive_group: std.Io.Group = .init,
        started: bool = false,
        stopping: bool = false,

        /// Futex word bumped by every drive wakeup source (recv task, senders,
        /// connect/close requests, stop); the drive task parks on it with an
        /// absolute deadline (std.Build.WebServer update_id pattern).
        wake_id: std.atomic.Value(u32) = .init(0),
        queue_mutex: std.atomic.Mutex = .unlocked,
        /// Datagrams received by the recv task, consumed FIFO by the drive task.
        datagram_queue: std.ArrayList(QueuedDatagram) = .empty,
        datagram_read_offset: usize = 0,
        /// Reusable receive buffers, avoiding a per-datagram allocation.
        datagram_pool: DatagramPool,

        /// Handshake coordination: the drive task runs the handshake; callers
        /// wait on handshake_complete for the terminal state.
        handshake_state: std.atomic.Value(u8) = .init(0),
        handshake_complete: std.Io.Event = .unset,
        connect_requested: bool = false,
        close_requested: bool = false,
        /// Drive-task only.
        handshake_started: bool = false,
        /// Drive-task only: a local APPLICATION_CLOSE has been issued; a later
        /// closing/closed state is expected and not surfaced as an error.
        close_initiated: bool = false,

        /// Send request slot (one in flight; the caller blocks until done).
        send_mutex: std.atomic.Mutex = .unlocked,
        send_request: ?*SendRequest = null,
        send_done_sem: std.Io.Semaphore = .{ .permits = 0 },

        /// Send-on-existing-stream request slot (one in flight; caller blocks).
        send_on_mutex: std.atomic.Mutex = .unlocked,
        send_on_request: ?*SendOnStreamRequest = null,
        send_on_done_sem: std.Io.Semaphore = .{ .permits = 0 },

        /// Key update request slot (one in flight; the caller blocks until done).
        key_update_mutex: std.atomic.Mutex = .unlocked,
        key_update_request: ?*KeyUpdateRequest = null,
        key_update_done_sem: std.Io.Semaphore = .{ .permits = 0 },

        /// Stream-open request slot (one in flight; the caller blocks until done).
        open_mutex: std.atomic.Mutex = .unlocked,
        open_request: ?*OpenStreamRequest = null,
        open_done_sem: std.Io.Semaphore = .{ .permits = 0 },

        /// Per-stream receive state, protected by state_mutex.
        state_mutex: std.atomic.Mutex = .unlocked,
        recv_streams: std.ArrayList(StreamRecvState) = .empty,
        /// Streams this client opened; the drive task delivers their data.
        open_streams: std.ArrayList(u64) = .empty,
        data_sem: std.Io.Semaphore = .{ .permits = 0 },
        /// Drive-observed connection close; a blocked receive() cannot learn
        /// about the close from stream data or EOF, so it checks this flag.
        conn_closing_or_closed: bool = false,
        protocol_closed: std.Io.Event = .unset,
        closing_datagrams_received: u32 = 0,
        /// Packet-processing error that failed the handshake, if any. Surfaces the
        /// original error to `connect()` instead of a generic HandshakeFailed.
        handshake_error: ?anyerror = null,
        /// When HTTP/3 is layered on this client, the drive task also polls
        /// server-initiated unidirectional streams (control / QPACK). Off by
        /// default so the plain echo path keeps polling only streams it opened.
        h3_mode: bool = false,
        /// Total UDP datagrams received by the recv task since init. Zero after a
        /// failed handshake means nothing ever arrived on the UDP path.
        udp_datagrams_received: usize = 0,

        const handshake_pending: u8 = 0;
        const handshake_confirmed: u8 = 1;
        const handshake_failed: u8 = 2;

        pub const Config = if (Path == endpoint.Udp4Tuple) IPv4Config else IPv6Config;

        pub fn init(allocator: std.mem.Allocator, io: std.Io, config: Config) !Self {
            var client_address: std.Io.net.IpAddress = if (Path == endpoint.Udp4Tuple)
                .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } }
            else
                .{ .ip6 = config.bind_addr orelse return error.ExplicitIPv6LocalAddressRequired };
            const socket = try client_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
            errdefer socket.close(io);
            return initWithSocket(allocator, io, socket, config);
        }

        /// Create a client from an already-bound UDP socket of this address family. On success the
        /// client owns and closes the socket; on failure ownership stays with the
        /// caller. This lets connectivity discovery and QUIC share one NAT mapping.
        pub fn initWithSocket(
            allocator: std.mem.Allocator,
            io: std.Io,
            socket: std.Io.net.Socket,
            config: Config,
        ) !Self {
            const local_address = Family.fromIp(socket.address) orelse return error.UnsupportedClientSocketFamily;
            if (Path == endpoint.Udp6Tuple and std.mem.allEqual(u8, &local_address.octets, 0))
                return error.ExplicitIPv6LocalAddressRequired;
            enlargeSocketReceiveBuffer(socket.handle);
            const remote_address = if (Path == endpoint.Udp4Tuple)
                endpoint.Udp4Address.init(config.server_host, config.server_port)
            else
                endpoint.Udp6Address.init(config.server_host, config.server_port, config.server_scope_id);
            const server_address = Family.toIp(remote_address);
            const client_path = Path{ .local = local_address, .remote = remote_address };
            var original_dcid: [8]u8 = undefined;
            var client_scid: [8]u8 = undefined;
            io.randomSecure(&original_dcid) catch io.random(&original_dcid);
            io.randomSecure(&client_scid) catch io.random(&client_scid);
            const now = std.Io.Clock.real.now(io);
            const tls_config = quicz.tls13.TlsConfig{
                .alpn = config.alpn,
                .server_name = config.server_name,
                .skip_cert_verify = config.insecure_skip_verify or config.ca_bundle == null,
                .now_sec = now.toSeconds(),
                .ca_bundle = config.ca_bundle,
                .prefer_chacha20 = config.prefer_chacha20,
            };
            const available_versions: []const quic_packet.Version = switch (config.version) {
                .v2 => &[_]quic_packet.Version{ .v1, .v2 },
                else => &[_]quic_packet.Version{.v1},
            };
            const client = try TlsEndpoint.init(
                allocator,
                1,
                client_path,
                .{ .active_migration_disabled = config.active_migration_disabled },
                .{
                    .initial_max_data = 10_485_760,
                    .initial_max_stream_data = 10_485_760,
                    .initial_max_streams_bidi = 128,
                    .initial_max_streams_uni = 128,
                    .max_datagram_size = datagram_limit,
                    .chosen_version = config.version,
                    .available_versions = available_versions,
                },
                tls_config,
                original_dcid,
                client_scid,
            );
            return .{
                .allocator = allocator,
                .io = io,
                .socket = socket,
                .client = client,
                .server_address = server_address,
                .keepalive_interval_nanos = @as(i64, config.keepalive_interval_ms) * std.time.ns_per_ms,
                .datagram_pool = DatagramPool.init(allocator),
            };
        }

        pub fn localPort(self: *const Self) u16 {
            return switch (self.socket.address) {
                .ip4 => |address| address.port,
                .ip6 => |address| address.port,
            };
        }

        /// Retain authenticated probe handling in the QUIC receive loop after
        /// connectivity validation hands this socket to the runtime.
        pub fn retainPunchResponder(
            self: *Self,
            responder: quicz.connectivity.punch_responder.PunchResponder,
        ) !void {
            if (self.started) return error.ClientAlreadyStarted;
            if (self.punch_responder) |*existing| existing.deinit();
            self.punch_responder = responder;
        }

        /// Run STUN before the QUIC tasks start, reusing the exact UDP socket and
        /// local port that will carry the later connection.
        pub fn discoverReflexiveAddress(
            self: *Self,
            stun_server: std.Io.net.IpAddress,
            config: quicz.connectivity.stun_transaction.Config,
        ) !quicz.connectivity.stun.MappedAddress {
            if (self.started) return error.ClientAlreadyStarted;
            return quicz.connectivity.stun_transaction.discover(
                self.io,
                &self.socket,
                stun_server,
                config,
            );
        }

        /// Cancel workers and destroy owned state immediately.
        /// Call close and waitClosed first when the protocol closing period must finish.
        pub fn deinit(self: *Self) void {
            if (self.started) {
                @atomicStore(bool, &self.stopping, true, .release);
                self.notifyDrive(self.io);
                // Hosted callers can mask SIGIO. Wake the blocking UDP receiver
                // locally instead of relying on a signal to interrupt recvmsg.
                // Keep the descriptor alive until every worker has exited.
                var wake_address = self.socket.address;
                switch (wake_address) {
                    .ip4 => |*address| {
                        if (std.mem.allEqual(u8, &address.bytes, 0)) address.bytes = .{ 127, 0, 0, 1 };
                    },
                    .ip6 => |*address| {
                        if (std.mem.allEqual(u8, &address.bytes, 0)) address.bytes = @as([15]u8, @splat(0)) ++ .{1};
                    },
                }
                {
                    const previous_protection = self.io.swapCancelProtection(.blocked);
                    defer _ = self.io.swapCancelProtection(previous_protection);
                    self.socket.send(self.io, &wake_address, &.{}) catch {};
                }
                self.drive_group.cancel(self.io);
                self.drive_group.await(self.io) catch {};
                self.started = false;
            }
            for (self.datagram_queue.items[self.datagram_read_offset..]) |qd| {
                if (qd.pooled) self.datagram_pool.release(qd.data) else self.allocator.free(qd.data);
            }
            self.datagram_queue.deinit(self.allocator);
            self.datagram_pool.deinit(self.allocator);
            for (self.recv_streams.items) |*s| s.queue.deinit(self.allocator);
            self.recv_streams.deinit(self.allocator);
            self.open_streams.deinit(self.allocator);
            if (self.punch_responder) |*responder| responder.deinit();
            self.punch_responder = null;
            self.client.deinit();
            self.socket.close(self.io);
        }

        /// Raise SO_RCVBUF so server echo bursts do not overflow the kernel
        /// receive buffer between client drains.
        fn enlargeSocketReceiveBuffer(handle: std.Io.net.Socket.Handle) void {
            const size: u32 = 4 * 1024 * 1024;
            std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&size)) catch {};
            const snd: u32 = 8 * 1024 * 1024;
            std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&snd)) catch {};
        }

        /// Queue APPLICATION_CLOSE without waiting. The driver answers peer packets during closing.
        /// Use waitClosed before deinit to retain the protocol closing period.
        pub fn close(self: *Self) void {
            @atomicStore(bool, &self.close_requested, true, .release);
            self.notifyDrive(self.io);
        }

        /// Wait for the protocol closing/draining period to finish, without destroying this client.
        /// Timeout or cancellation leaves the driver running. Completion does not prove peer receipt.
        pub fn waitClosed(self: *Self, timeout_ms: u32) !void {
            if (timeout_ms == 0) return error.InvalidTimeout;
            if (!self.started) return error.ClientNotStarted;
            const deadline = std.Io.Timestamp.now(self.io, .awake).addDuration(.fromMilliseconds(timeout_ms));
            while (!self.protocol_closed.isSet()) {
                self.protocol_closed.waitTimeout(self.io, .{ .deadline = .{ .clock = .awake, .raw = deadline } }) catch |err| switch (err) {
                    error.Timeout => {
                        if (!self.protocol_closed.isSet() and std.Io.Timestamp.now(self.io, .awake).nanoseconds >= deadline.nanoseconds)
                            return error.ConnectionTimedOut;
                    },
                    else => return err,
                };
            }
        }

        /// Whether any caller request or queued datagram still waits for the
        /// drive task. Checked after the park snapshot to close the window
        /// between request processing and the snapshot (see drive()).
        fn hasPendingWork(self: *Self) bool {
            if (@atomicLoad(bool, &self.close_requested, .acquire)) return true;
            if (@atomicLoad(bool, &self.connect_requested, .acquire) and !self.handshake_started) return true;
            while (!self.send_mutex.tryLock()) std.atomic.spinLoopHint();
            const send_pending = self.send_request != null;
            self.send_mutex.unlock();
            if (send_pending) return true;
            while (!self.send_on_mutex.tryLock()) std.atomic.spinLoopHint();
            const send_on_pending = self.send_on_request != null;
            self.send_on_mutex.unlock();
            if (send_on_pending) return true;
            while (!self.open_mutex.tryLock()) std.atomic.spinLoopHint();
            const open_pending = self.open_request != null;
            self.open_mutex.unlock();
            if (open_pending) return true;
            while (!self.key_update_mutex.tryLock()) std.atomic.spinLoopHint();
            const key_update_pending = self.key_update_request != null;
            self.key_update_mutex.unlock();
            if (key_update_pending) return true;
            while (!self.queue_mutex.tryLock()) std.atomic.spinLoopHint();
            const datagrams_queued = self.datagram_read_offset < self.datagram_queue.items.len;
            self.queue_mutex.unlock();
            return datagrams_queued;
        }

        fn nowNanos(self: *const Self) i64 {
            return @intCast(std.Io.Timestamp.now(self.io, .awake).nanoseconds);
        }

        /// Wake the drive task: bump the futex word, then wake the waiter.
        /// std.Build.WebServer uses the same pattern (notifyUpdate/update_id).
        fn notifyDrive(self: *Self, io: std.Io) void {
            _ = self.wake_id.rmw(.Add, 1, .release);
            io.futexWake(u32, &self.wake_id.raw, 1);
        }

        /// Spawn the recv and drive tasks (idempotent).
        fn startTasks(self: *Self) !void {
            if (self.started) return;
            try self.drive_group.concurrent(self.io, Self.recvTask, .{self});
            self.drive_group.concurrent(self.io, Self.drive, .{self}) catch |err| {
                @atomicStore(bool, &self.stopping, true, .release);
                self.drive_group.cancel(self.io);
                self.drive_group.await(self.io) catch {};
                return err;
            };
            self.started = true;
        }

        /// Drive the TLS 1.3 handshake to completion. Blocks until the drive
        /// task confirms the handshake or the connection closes first.
        pub fn connect(self: *Self) !void {
            return self.connectUntil(null);
        }

        /// Wait on this client's handshake event, without a separate timer task.
        /// Expiration leaves the original driver owned by this client; callers may
        /// wait again or destroy the client. No work retains the caller's stack.
        pub fn connectWithTimeout(self: *Self, timeout_ms: u32) !void {
            if (timeout_ms == 0) return error.InvalidTimeout;
            const deadline = std.Io.Timestamp.now(self.io, .awake).addDuration(.fromMilliseconds(timeout_ms));
            return self.connectUntil(deadline);
        }

        fn connectUntil(self: *Self, deadline: ?std.Io.Timestamp) !void {
            try self.startTasks();
            if (self.handshake_state.load(.acquire) == handshake_confirmed) return;
            @atomicStore(bool, &self.connect_requested, true, .release);
            self.notifyDrive(self.io);
            if (deadline) |end| {
                while (!self.handshake_complete.isSet()) {
                    self.handshake_complete.waitTimeout(self.io, .{ .deadline = .{ .clock = .awake, .raw = end } }) catch |err| switch (err) {
                        error.Timeout => {
                            if (!self.handshake_complete.isSet() and std.Io.Timestamp.now(self.io, .awake).nanoseconds >= end.nanoseconds)
                                return error.ConnectionTimedOut;
                        },
                        error.Canceled => return error.HandshakeFailed,
                    };
                }
            } else {
                self.handshake_complete.wait(self.io) catch return error.HandshakeFailed;
            }
            if (self.handshake_state.load(.acquire) != handshake_confirmed) {
                return self.handshake_error orelse error.HandshakeFailed;
            }
        }

        /// Read the error published by the handshake driver. The caller must
        /// retain this client's lifetime while reading the diagnostic.
        pub fn handshakeError(self: *const Self) ?anyerror {
            if (self.handshake_state.load(.acquire) != handshake_failed) return null;
            return self.handshake_error orelse error.HandshakeFailed;
        }

        /// Return how many UDP datagrams arrived since init. Lets diagnostics
        /// distinguish "UDP path unreachable" from "UDP works but the QUIC or TLS
        /// handshake failed" after a failed connect().
        pub fn datagramsReceived(self: *const Self) usize {
            return self.udp_datagrams_received;
        }

        /// Configure application-space PING keepalive before the runtime starts.
        /// Zero disables keepalive. The drive task remains the sole endpoint owner.
        pub fn setKeepaliveInterval(self: *Self, interval_ms: u32) !void {
            if (self.started) return error.ClientAlreadyStarted;
            self.keepalive_interval_nanos = @as(i64, interval_ms) * std.time.ns_per_ms;
            self.next_keepalive_nanos = null;
        }

        /// Send `data` on a new bidirectional stream; returns the stream id.
        /// The drive task runs the request (the endpoint is drive-task only).
        pub fn send(self: *Self, data: []const u8, fin: bool) !u64 {
            try self.startTasks();
            var req: SendRequest = .{ .data = data, .fin = fin };
            while (true) {
                while (!self.send_mutex.tryLock()) std.atomic.spinLoopHint();
                if (self.send_request == null) break;
                self.send_mutex.unlock();
                std.atomic.spinLoopHint();
            }
            self.send_request = &req;
            self.send_mutex.unlock();
            self.notifyDrive(self.io);
            self.send_done_sem.waitUncancelable(self.io);
            return req.result orelse error.StreamSendFailed;
        }

        /// Send `data` on an already-open stream (e.g. an HTTP/3 control or QPACK
        /// stream). The drive task runs the send; the caller blocks until done.
        pub fn sendOnStream(self: *Self, stream_id: u64, data: []const u8, fin: bool) !void {
            try self.startTasks();
            var req: SendOnStreamRequest = .{ .stream_id = stream_id, .data = data, .fin = fin };
            while (true) {
                while (!self.send_on_mutex.tryLock()) std.atomic.spinLoopHint();
                if (self.send_on_request == null) break;
                self.send_on_mutex.unlock();
                std.atomic.spinLoopHint();
            }
            self.send_on_request = &req;
            self.send_on_mutex.unlock();
            self.notifyDrive(self.io);
            self.send_on_done_sem.waitUncancelable(self.io);
            if (!req.ok) return error.StreamSendFailed;
        }

        /// Open a new bidirectional stream (without sending anything yet); the
        /// drive task performs the open and returns the stream id.
        pub fn openStream(self: *Self) !u64 {
            return self.openStreamInternal(false);
        }

        /// Open a client-initiated unidirectional stream (without sending data);
        /// used by HTTP/3 for the control and QPACK encoder/decoder streams.
        pub fn openUniStream(self: *Self) !u64 {
            return self.openStreamInternal(true);
        }

        /// Switch the drive task into HTTP/3 mode: server-initiated unidirectional
        /// streams are polled so their control / QPACK bytes reach the stream
        /// queues. Call before sending HTTP/3 requests.
        pub fn enableH3(self: *Self) void {
            self.h3_mode = true;
        }

        fn openStreamInternal(self: *Self, uni: bool) !u64 {
            try self.startTasks();
            var req: OpenStreamRequest = .{ .uni = uni };
            while (true) {
                while (!self.open_mutex.tryLock()) std.atomic.spinLoopHint();
                if (self.open_request == null) break;
                self.open_mutex.unlock();
                std.atomic.spinLoopHint();
            }
            self.open_request = &req;
            self.open_mutex.unlock();
            self.notifyDrive(self.io);
            self.open_done_sem.waitUncancelable(self.io);
            return req.result orelse error.StreamOpenFailed;
        }

        /// Initiate a 1-RTT key update (RFC 9001 §6). The drive task advances the
        /// connection's send key phase; the next outgoing packet carries the new
        /// keys and the flipped key phase bit. Requires a confirmed handshake and
        /// no key update already awaiting confirmation.
        pub fn initiateKeyUpdate(self: *Self) !void {
            try self.startTasks();
            var req: KeyUpdateRequest = .{};
            while (true) {
                while (!self.key_update_mutex.tryLock()) std.atomic.spinLoopHint();
                if (self.key_update_request == null) break;
                self.key_update_mutex.unlock();
                std.atomic.spinLoopHint();
            }
            self.key_update_request = &req;
            self.key_update_mutex.unlock();
            self.notifyDrive(self.io);
            self.key_update_done_sem.waitUncancelable(self.io);
            if (!req.ok) return error.KeyUpdateRejected;
        }

        /// Receive data on `stream_id` into `buf`. Blocks until data arrives;
        /// returns bytes read, 0 at EOF (peer FIN fully consumed).
        pub fn receive(self: *Self, stream_id: u64, buf: []u8) !usize {
            const io = self.io;
            while (true) {
                if (@atomicLoad(bool, &self.stopping, .acquire)) return error.Canceled;
                while (!self.state_mutex.tryLock()) std.atomic.spinLoopHint();
                var found: ?*StreamRecvState = null;
                for (self.recv_streams.items) |*s| {
                    if (s.id == stream_id) {
                        found = s;
                        break;
                    }
                }
                if (found) |s| {
                    const available = s.queue.items[s.read_offset..];
                    if (available.len > 0) {
                        const n = @min(buf.len, available.len);
                        @memcpy(buf[0..n], available[0..n]);
                        s.read_offset += n;
                        if (s.read_offset == s.queue.items.len) {
                            s.queue.clearRetainingCapacity();
                            s.read_offset = 0;
                        }
                        self.state_mutex.unlock();
                        return n;
                    }
                    if (s.eof) {
                        self.state_mutex.unlock();
                        return 0;
                    }
                }
                // No data and no EOF: a closing/closed connection will never
                // deliver more on this stream.
                if (@atomicLoad(bool, &self.conn_closing_or_closed, .acquire)) {
                    return error.ConnectionClosed;
                }
                self.state_mutex.unlock();
                self.data_sem.wait(io) catch return error.Canceled;
            }
        }

        /// Non-blocking receive for one stream. Returns `null` when the stream has
        /// no data right now, `0` at EOF, otherwise the number of bytes copied.
        pub fn tryReceiveStreamData(self: *Self, stream_id: u64, buf: []u8) !?usize {
            if (@atomicLoad(bool, &self.stopping, .acquire)) return error.Canceled;
            while (!self.state_mutex.tryLock()) std.atomic.spinLoopHint();
            var result: ?usize = null;
            for (self.recv_streams.items) |*s| {
                if (s.id != stream_id) continue;
                const available = s.queue.items[s.read_offset..];
                if (available.len > 0) {
                    const n = @min(buf.len, available.len);
                    @memcpy(buf[0..n], available[0..n]);
                    s.read_offset += n;
                    if (s.read_offset == s.queue.items.len) {
                        s.queue.clearRetainingCapacity();
                        s.read_offset = 0;
                    }
                    result = n;
                } else if (s.eof) {
                    result = 0;
                }
                break;
            }
            self.state_mutex.unlock();
            return result;
        }

        /// Snapshot the stream ids currently receiving data into `out`; returns
        /// the count written (HTTP/3 control / QPACK / response streams).
        pub fn streamIds(self: *Self, out: []u64) usize {
            var count: usize = 0;
            while (!self.state_mutex.tryLock()) std.atomic.spinLoopHint();
            for (self.recv_streams.items) |*s| {
                if (count >= out.len) break;
                out[count] = s.id;
                count += 1;
            }
            self.state_mutex.unlock();
            return count;
        }

        /// Park until any stream has new data / EOF, a new stream arrives, or the
        /// connection closes. The HTTP/3 client driver uses this between
        /// non-blocking drains.
        pub fn waitStreamActivity(self: *Self) !void {
            while (true) {
                if (@atomicLoad(bool, &self.stopping, .acquire)) return error.Canceled;
                while (!self.state_mutex.tryLock()) std.atomic.spinLoopHint();
                var has_activity = false;
                for (self.recv_streams.items) |*s| {
                    if (s.queue.items.len > s.read_offset or s.eof) {
                        has_activity = true;
                        break;
                    }
                }
                if (has_activity) {
                    self.state_mutex.unlock();
                    return;
                }
                if (@atomicLoad(bool, &self.conn_closing_or_closed, .acquire)) {
                    self.state_mutex.unlock();
                    return error.ConnectionClosed;
                }
                self.state_mutex.unlock();
                self.data_sem.wait(self.io) catch return error.Canceled;
            }
        }

        /// Full echo session (connect + send + receive-to-EOF); returns true when
        /// the echoed bytes match the payload. Suitable for running as a std.Io
        /// async task via Group.concurrent.
        pub fn runEchoSession(self: *Self, payload: []const u8) !bool {
            try self.connect();
            const stream_id = try self.send(payload, true);
            var echo_buf: [4096]u8 = undefined;
            var total: usize = 0;
            while (total < payload.len) {
                const n = try self.receive(stream_id, &echo_buf);
                if (n == 0) break;
                if (total + n > payload.len) return false;
                if (!std.mem.eql(u8, echo_buf[0..n], payload[total .. total + n])) return false;
                total += n;
            }
            return total == payload.len;
        }

        /// Receive datagrams into the queue and wake the drive task. Mirrors the
        /// official WebServer accept task: block on the socket, hand work off.
        fn recvTask(self: *Self) std.Io.Cancelable!void {
            const io = self.io;
            const allocator = self.allocator;
            var recv_buf: [max_datagram_size]u8 = undefined;
            while (!@atomicLoad(bool, &self.stopping, .acquire)) {
                const received = self.socket.receiveTimeout(io, &recv_buf, .none) catch |err| switch (err) {
                    error.Canceled => return,
                    else => {
                        if (@atomicLoad(bool, &self.stopping, .acquire)) return;
                        log.debug("client recv task: receive: {}", .{err});
                        continue;
                    },
                };
                if (@atomicLoad(bool, &self.stopping, .acquire)) return;
                self.udp_datagrams_received += 1;
                const pooled_buf = self.datagram_pool.take();
                const copy = if (pooled_buf) |pb| blk: {
                    @memcpy(pb[0..received.data.len], received.data);
                    break :blk pb[0..received.data.len];
                } else allocator.dupe(u8, received.data) catch continue;
                while (!self.queue_mutex.tryLock()) std.atomic.spinLoopHint();
                self.datagram_queue.append(allocator, .{
                    .from = received.from,
                    .data = copy,
                    .pooled = pooled_buf != null,
                }) catch {
                    self.queue_mutex.unlock();
                    if (pooled_buf != null) self.datagram_pool.release(copy) else allocator.free(copy);
                    continue;
                };
                self.queue_mutex.unlock();
                self.notifyDrive(io);
            }
        }

        /// The client driving task body: run requested handshake/close/send work,
        /// drain outgoing, process queued datagrams, service due deadlines, then
        /// park on the wakeup futex until the next event or lifecycle deadline.
        fn drive(self: *Self) std.Io.Cancelable!void {
            const allocator = self.allocator;
            const io = self.io;
            defer self.failPendingSendRequest();
            defer self.failPendingSendOnStreamRequest();
            defer self.failPendingOpenStreamRequest();
            defer self.failPendingKeyUpdateRequest();
            while (!@atomicLoad(bool, &self.stopping, .acquire)) {
                self.beginHandshakeOnce();
                self.processCloseRequest();
                self.processSendRequest();
                self.processSendOnStreamRequest();
                self.processOpenStreamRequest();
                self.processKeyUpdateRequest();
                self.serviceKeepalive();
                self.drainOutgoing();
                self.drainQueuedDatagrams();
                self.serviceDueDeadlines();
                self.checkHandshakeProgress();
                self.checkConnectionClose();
                // Park until a datagram arrives, a request is queued, stop() runs,
                // or the next lifecycle deadline comes due. The snapshot is taken
                // after draining, pairing with notifyDrive's bump: a notifier that
                // already ran changed wake_id, so the wait returns immediately.
                const snapshot = self.wake_id.load(.acquire);
                const timeout = self.nextDriveTimeout();
                // Re-check stopping after the snapshot: a deinit/stop that ran
                // before the snapshot already bumped wake_id (and its futexWake
                // may have had no waiter yet), and one that runs after the
                // snapshot changes wake_id so the compare cannot match. Without
                // this check the drive could park forever past a stop request.
                if (@atomicLoad(bool, &self.stopping, .acquire)) break;
                // Re-check for work parked between this iteration's request
                // processing and the snapshot: its notifyDrive bump is already
                // captured by the snapshot, so the park below would hold the
                // request until the park timeout (up to the idle deadline, tens
                // of seconds). A request arriving after this check bumps wake_id
                // past the snapshot, so the park still returns immediately.
                if (self.hasPendingWork()) continue;
                io.futexWaitTimeout(u32, &self.wake_id.raw, snapshot, timeout) catch return;
            }
            _ = allocator;
        }

        /// Begin the handshake once connect() has been requested.
        fn beginHandshakeOnce(self: *Self) void {
            if (self.handshake_started) return;
            if (!@atomicLoad(bool, &self.connect_requested, .acquire)) return;
            self.handshake_started = true;
            const begin = self.client.beginWithRoutePath(self.nowNanos(), &self.scratch) catch |err| {
                log.err("client: begin handshake: {}", .{err});
                self.handshake_state.store(handshake_failed, .release);
                self.handshake_complete.set(self.io);
                return;
            };
            self.socket.send(self.io, &self.server_address, begin.datagram) catch {};
            self.allocator.free(begin.datagram);
        }

        /// Emit the APPLICATION_CLOSE frame once close() has been requested.
        fn processCloseRequest(self: *Self) void {
            if (!@atomicLoad(bool, &self.close_requested, .acquire)) return;
            @atomicStore(bool, &self.close_requested, false, .release);
            self.close_initiated = true;
            const closed = self.client.closeApplicationWithRoutePath(0, "session complete", self.nowNanos()) catch |err| {
                log.debug("client: close preparation: {}", .{err});
                return;
            };
            if (closed) |o| {
                self.socket.send(self.io, &self.server_address, o.datagram) catch |err| {
                    log.debug("client: close send: {}", .{err});
                };
                self.allocator.free(o.datagram);
            }
        }

        /// Queue one application-space PING when the configured keepalive
        /// deadline expires. The drive task remains the sole endpoint owner.
        fn serviceKeepalive(self: *Self) void {
            if (self.keepalive_interval_nanos == 0 or
                self.handshake_state.load(.acquire) != handshake_confirmed or
                self.client.transport.connection.isClosingOrClosed())
            {
                self.next_keepalive_nanos = null;
                return;
            }
            const now = self.nowNanos();
            const deadline = self.next_keepalive_nanos orelse {
                self.next_keepalive_nanos = keepaliveDeadlineAfter(now, self.keepalive_interval_nanos);
                return;
            };
            if (now < deadline) return;
            self.client.transport.connection.sendPing() catch {
                self.next_keepalive_nanos = null;
                return;
            };
            self.next_keepalive_nanos = keepaliveDeadlineAfter(now, self.keepalive_interval_nanos);
        }

        fn nextDriveTimeout(self: *const Self) std.Io.Timeout {
            var deadline_nanos: ?i64 = if (self.client.nextDeadline()) |deadline|
                deadline.deadline()
            else
                null;
            if (self.client.transport.connection.pacingDeadline()) |pacing_deadline| {
                if (deadline_nanos == null or pacing_deadline < deadline_nanos.?) {
                    deadline_nanos = pacing_deadline;
                }
            }
            if (self.next_keepalive_nanos) |keepalive_deadline| {
                if (deadline_nanos == null or keepalive_deadline < deadline_nanos.?) {
                    deadline_nanos = keepalive_deadline;
                }
            }
            return if (deadline_nanos) |deadline|
                .{ .deadline = .{ .raw = .{ .nanoseconds = deadline }, .clock = .awake } }
            else
                .none;
        }

        fn keepaliveDeadlineAfter(now_nanos: i64, interval_nanos: i64) i64 {
            return std.math.add(i64, now_nanos, interval_nanos) catch std.math.maxInt(i64);
        }

        /// Run the parked send request: open a stream and queue the data.
        fn processSendRequest(self: *Self) void {
            while (!self.send_mutex.tryLock()) std.atomic.spinLoopHint();
            const req = self.send_request orelse {
                self.send_mutex.unlock();
                return;
            };
            self.send_request = null;
            self.send_mutex.unlock();

            process: {
                const stream_id = self.client.openStream() catch |err| {
                    log.err("client: open stream: {}", .{err});
                    break :process;
                };
                const outbound = self.client.sendStreamWithRoutePath(stream_id, req.data, req.fin, self.nowNanos()) catch |err| {
                    log.err("client: send on stream {d}: {}", .{ stream_id, err });
                    break :process;
                };
                if (outbound) |o| {
                    self.socket.send(self.io, &self.server_address, o.datagram) catch {};
                    self.allocator.free(o.datagram);
                }
                while (!self.state_mutex.tryLock()) std.atomic.spinLoopHint();
                self.open_streams.append(self.allocator, stream_id) catch {};
                self.state_mutex.unlock();
                req.result = stream_id;
            }
            self.send_done_sem.post(self.io);
        }

        /// Complete a parked send request as failed (drive task shutdown path).
        fn failPendingSendRequest(self: *Self) void {
            while (!self.send_mutex.tryLock()) std.atomic.spinLoopHint();
            const req = self.send_request;
            self.send_request = null;
            self.send_mutex.unlock();
            if (req) |r| {
                r.result = null;
                self.send_done_sem.post(self.io);
            }
        }

        /// Run the parked send-on-existing-stream request (drive task only).
        fn processSendOnStreamRequest(self: *Self) void {
            while (!self.send_on_mutex.tryLock()) std.atomic.spinLoopHint();
            const req = self.send_on_request orelse {
                self.send_on_mutex.unlock();
                return;
            };
            self.send_on_request = null;
            self.send_on_mutex.unlock();

            const outbound = self.client.sendStreamWithRoutePath(req.stream_id, req.data, req.fin, self.nowNanos()) catch |err| {
                log.err("client: send on stream {d}: {}", .{ req.stream_id, err });
                req.ok = false;
                self.send_on_done_sem.post(self.io);
                return;
            };
            if (outbound) |o| {
                self.socket.send(self.io, &self.server_address, o.datagram) catch {};
                self.allocator.free(o.datagram);
            }
            req.ok = true;
            self.send_on_done_sem.post(self.io);
        }

        /// Complete a parked send-on-existing-stream request as failed (drive
        /// task shutdown path).
        fn failPendingSendOnStreamRequest(self: *Self) void {
            while (!self.send_on_mutex.tryLock()) std.atomic.spinLoopHint();
            const req = self.send_on_request;
            self.send_on_request = null;
            self.send_on_mutex.unlock();
            if (req) |r| {
                r.ok = false;
                self.send_on_done_sem.post(self.io);
            }
        }

        /// Run the parked stream-open request on the endpoint (drive task only).
        /// The opened stream is registered in `open_streams` so inbound data on it
        /// is delivered to the stream queues.
        fn processOpenStreamRequest(self: *Self) void {
            while (!self.open_mutex.tryLock()) std.atomic.spinLoopHint();
            const req = self.open_request orelse {
                self.open_mutex.unlock();
                return;
            };
            self.open_request = null;
            self.open_mutex.unlock();

            process: {
                const stream_id = if (req.uni)
                    self.client.openUniStream() catch |err| {
                        log.err("client: open uni stream: {}", .{err});
                        break :process;
                    }
                else
                    self.client.openStream() catch |err| {
                        log.err("client: open stream: {}", .{err});
                        break :process;
                    };
                while (!self.state_mutex.tryLock()) std.atomic.spinLoopHint();
                self.open_streams.append(self.allocator, stream_id) catch {};
                self.state_mutex.unlock();
                req.result = stream_id;
            }
            self.open_done_sem.post(self.io);
        }

        /// Complete a parked stream-open request as failed (drive task shutdown).
        fn failPendingOpenStreamRequest(self: *Self) void {
            while (!self.open_mutex.tryLock()) std.atomic.spinLoopHint();
            const req = self.open_request;
            self.open_request = null;
            self.open_mutex.unlock();
            if (req) |r| {
                r.result = null;
                self.open_done_sem.post(self.io);
            }
        }

        /// Run the parked key update request on the endpoint (drive task only).
        fn processKeyUpdateRequest(self: *Self) void {
            while (!self.key_update_mutex.tryLock()) std.atomic.spinLoopHint();
            const req = self.key_update_request orelse {
                self.key_update_mutex.unlock();
                return;
            };
            self.key_update_request = null;
            self.key_update_mutex.unlock();

            self.client.transport.connection.initiateOneRttKeyUpdate() catch |err| {
                log.err("client: initiate key update: {}", .{err});
                self.key_update_done_sem.post(self.io);
                return;
            };
            req.ok = true;
            self.key_update_done_sem.post(self.io);
        }

        /// Complete a parked key update request as failed (drive shutdown path).
        fn failPendingKeyUpdateRequest(self: *Self) void {
            while (!self.key_update_mutex.tryLock()) std.atomic.spinLoopHint();
            const req = self.key_update_request;
            self.key_update_request = null;
            self.key_update_mutex.unlock();
            if (req != null) self.key_update_done_sem.post(self.io);
        }

        /// Drain bounded application output. Closing sends one initial packet,
        /// then uses incoming-packet backoff instead of filling batches with duplicates.
        fn drainOutgoing(self: *Self) void {
            const conn = &self.client.transport.connection;
            if (conn.isClosingOrClosed()) {
                if (conn.connectionState() == .closing and conn.closeDeadline() == null) self.sendClosePacket();
                return;
            }
            var out: [16]TlsEndpoint.ApplicationDatagramPathResult = undefined;
            var iterations: usize = 0;
            while (iterations < 16) : (iterations += 1) {
                const drained = self.client.drainApplicationDatagramsWithRoutePath(self.nowNanos(), &out) catch return;
                if (drained.datagrams_written == 0) return;
                // All drained datagrams go to the server address; batch them so
                // Linux sendmmsg amortizes the syscall (std.Io.Threaded netSend).
                var msgs: [16]std.Io.net.OutgoingMessage = undefined;
                for (out[0..drained.datagrams_written], 0..) |o, i| {
                    msgs[i] = .{ .address = &self.server_address, .data_ptr = o.datagram.ptr, .data_len = o.datagram.len };
                }
                if (builtin.os.tag == .linux) {
                    self.socket.sendMany(self.io, msgs[0..drained.datagrams_written], .{}) catch {};
                } else {
                    for (msgs[0..drained.datagrams_written]) |m| {
                        self.socket.send(self.io, &self.server_address, m.data_ptr[0..m.data_len]) catch {};
                    }
                }
                for (out[0..drained.datagrams_written]) |o| {
                    self.allocator.free(o.datagram);
                }
            }
        }

        fn sendClosePacket(self: *Self) void {
            if (self.client.transport.connection.connectionState() != .closing) return;
            const outgoing = self.client.pollApplicationDatagramWithRoutePath(self.nowNanos()) catch |err| {
                if (err != error.ConnectionClosed) log.debug("client: close response poll: {}", .{err});
                return;
            };
            if (outgoing) |packet| {
                defer self.allocator.free(packet.datagram);
                self.socket.send(self.io, &self.server_address, packet.datagram) catch |err|
                    log.debug("client: close response send: {}", .{err});
            }
        }

        fn respondWhileClosing(self: *Self) void {
            if (self.client.transport.connection.connectionState() != .closing) return;
            self.closing_datagrams_received +|= 1;
            if (std.math.isPowerOfTwo(self.closing_datagrams_received)) self.sendClosePacket();
        }

        /// Process every queued datagram in FIFO order and free its buffer.
        fn drainQueuedDatagrams(self: *Self) void {
            while (true) {
                while (!self.queue_mutex.tryLock()) std.atomic.spinLoopHint();
                if (self.datagram_read_offset >= self.datagram_queue.items.len) {
                    self.datagram_queue.clearRetainingCapacity();
                    self.datagram_read_offset = 0;
                    self.queue_mutex.unlock();
                    return;
                }
                const qd = self.datagram_queue.items[self.datagram_read_offset];
                self.datagram_read_offset += 1;
                self.queue_mutex.unlock();
                self.processDatagram(qd.from, qd.data);
                if (qd.pooled) self.datagram_pool.release(qd.data) else self.allocator.free(qd.data);
            }
        }

        /// Route one datagram through the client endpoint, send the TLS outbound
        /// it returns, deliver stream data, and drain the responses (ACKs).
        fn processDatagram(self: *Self, from: std.Io.net.IpAddress, data: []const u8) void {
            // Datagram size is not authenticated (RFC 9000 section 14).
            // Discard size violations without failing the handshake.
            if (data.len == 0 or data.len > self.client.transport.connection.config.max_datagram_size) return;
            if (self.punch_responder) |responder| {
                switch (responder.handle(from, self.nowNanos(), data)) {
                    .not_punch => {},
                    .consumed => return,
                    .acknowledgement => |acknowledgement| {
                        var destination = from;
                        self.socket.send(self.io, &destination, &acknowledgement) catch {};
                        return;
                    },
                }
            }
            // Discovery can leave unrelated UDP replies on this socket. They
            // cannot fail a pending handshake; IPv4 migration remains available
            // after confirmation. Retained authenticated punches were handled above.
            if (Path == endpoint.Udp6Tuple or self.handshake_state.load(.acquire) != handshake_confirmed) {
                const peer = Family.fromIp(from) orelse return;
                if (!peer.eql(self.client.path.remote)) return;
            }
            const result = (self.client.receiveWithRoutePathOrDiscard(self.nowNanos(), &self.scratch, data) catch |err| {
                if (err == error.ConnectionClosed and self.close_initiated) {
                    self.respondWhileClosing();
                    self.checkConnectionClose();
                    return;
                }
                if (err == error.CryptoError and self.handshake_state.load(.acquire) == handshake_pending) {
                    log.warn("client: handshake rejected ({d} bytes): {}", .{ data.len, err });
                } else {
                    log.err("client: receive ({d} bytes): {}", .{ data.len, err });
                    if (data.len > 0) {
                        const head = data[0..@min(data.len, 48)];
                        log.err("client: datagram head: {x}", .{head});
                    }
                }
                self.recordHandshakeError(err);
                self.drainOutgoing();
                return;
            }) orelse return;
            if (result.outbound_initial) |o| {
                self.socket.send(self.io, &self.server_address, o.datagram) catch {};
                self.allocator.free(o.datagram);
            }
            if (result.outbound_handshake) |o| {
                self.socket.send(self.io, &self.server_address, o.datagram) catch {};
                self.allocator.free(o.datagram);
            }
            if (self.client.transport.connection.connectionState() == .closing) {
                self.respondWhileClosing();
                self.checkConnectionClose();
                return;
            }
            self.deliverStreamData();
            self.drainOutgoing();
        }

        /// Publish receive failures after admission and discarded-space filtering.
        fn recordHandshakeError(self: *Self, err: anyerror) void {
            if (self.handshake_state.load(.acquire) != handshake_pending) return;
            if (!self.handshake_started) return;
            self.handshake_error = err;
            self.handshake_state.store(handshake_failed, .release);
            self.handshake_complete.set(self.io);
        }

        /// Push received bytes of every open stream into its queue and surface
        /// EOF once the peer FIN is fully consumed. Server-initiated
        /// unidirectional streams (odd ids, HTTP/3 control / QPACK) are polled in
        /// addition to the streams this client opened, so their ordered bytes land
        /// in the same per-stream queues as response data.
        fn deliverStreamData(self: *Self) void {
            while (!self.state_mutex.tryLock()) std.atomic.spinLoopHint();
            var pushed = false;
            var buf: [4096]u8 = undefined;
            for (self.open_streams.items) |sid| {
                self.deliverStreamBytes(sid, &buf, &pushed);
            }
            if (self.h3_mode) {
                // HTTP/3 servers only open unidirectional streams toward the
                // client: ids 1, 3, 5, ... (server bidi is not used by H3).
                var server_sid: u64 = 1;
                while (server_sid < 1024) : (server_sid += 2) {
                    self.deliverStreamBytes(server_sid, &buf, &pushed);
                }
            }
            self.state_mutex.unlock();
            if (pushed) self.data_sem.post(self.io);
        }

        fn deliverStreamBytes(self: *Self, sid: u64, buf: *[4096]u8, pushed: *bool) void {
            while (true) {
                const n = self.client.recvStream(sid, buf) catch break;
                const len = n orelse break;
                if (len == 0) break;
                var idx: ?usize = null;
                for (self.recv_streams.items, 0..) |s, i| {
                    if (s.id == sid) {
                        idx = i;
                        break;
                    }
                }
                if (idx == null) {
                    self.recv_streams.append(self.allocator, .{ .id = sid }) catch break;
                    idx = self.recv_streams.items.len - 1;
                }
                self.recv_streams.items[idx.?].queue.appendSlice(self.allocator, buf[0..len]) catch break;
                pushed.* = true;
            }
            if (self.client.streamFinished(sid) catch false) {
                var idx: ?usize = null;
                for (self.recv_streams.items, 0..) |s, i| {
                    if (s.id == sid) {
                        idx = i;
                        break;
                    }
                }
                if (idx == null) {
                    self.recv_streams.append(self.allocator, .{ .id = sid }) catch return;
                    idx = self.recv_streams.items.len - 1;
                }
                if (!self.recv_streams.items[idx.?].eof) {
                    self.recv_streams.items[idx.?].eof = true;
                    pushed.* = true;
                }
            }
        }

        /// Service lifecycle deadlines that came due and send the datagrams they
        /// produce (PTO retransmits, closing packets). Bounded per pass.
        fn serviceDueDeadlines(self: *Self) void {
            var passes: usize = 0;
            while (passes < 8) : (passes += 1) {
                var out: [16]TlsEndpoint.ApplicationDatagramPathResult = undefined;
                const due = self.client.serviceDueDeadlineAndDrainDatagramsWithRoutePath(self.nowNanos(), &out) catch |err| {
                    log.debug("client: due deadline processing: {}", .{err});
                    return;
                };
                const result = due orelse return;
                for (out[0..result.drain.datagrams_written]) |o| {
                    self.socket.send(self.io, &self.server_address, o.datagram) catch {};
                    self.allocator.free(o.datagram);
                }
            }
        }

        /// Surface the terminal handshake state to waiting callers.
        fn checkHandshakeProgress(self: *Self) void {
            if (self.handshake_state.load(.acquire) != handshake_pending) return;
            if (!self.handshake_started) return;
            if (self.client.handshakeConfirmed()) {
                self.handshake_state.store(handshake_confirmed, .release);
                if (self.keepalive_interval_nanos != 0) {
                    self.next_keepalive_nanos = keepaliveDeadlineAfter(self.nowNanos(), self.keepalive_interval_nanos);
                }
                self.handshake_complete.set(self.io);
                return;
            }
            // A connection closing before confirmation can never complete the
            // handshake (server rejection, close frame, expired timers).
            if (self.client.transport.connection.isClosingOrClosed()) {
                self.handshake_state.store(handshake_failed, .release);
                self.handshake_complete.set(self.io);
            }
        }

        /// Surface a closing/closed connection to a blocked receive(): wake the
        /// stream waiters once, so they observe error.ConnectionClosed.
        fn checkConnectionClose(self: *Self) void {
            if (self.client.transport.connection.connectionState() == .closed) self.protocol_closed.set(self.io);
            if (@atomicLoad(bool, &self.conn_closing_or_closed, .acquire)) return;
            if (!self.client.transport.connection.isClosingOrClosed()) return;
            @atomicStore(bool, &self.conn_closing_or_closed, true, .release);
            const conn = self.client.transport.connection;
            if (self.close_initiated or conn.peer_close != null) {
                log.debug("client: connection closing: {} peer_close={}", .{ conn.connectionState(), conn.peer_close != null });
            } else {
                log.err("client: connection entered closing/closed state: {} peer_close={} pending_close={}", .{
                    conn.connectionState(),
                    conn.peer_close != null,
                    conn.pending_close != null,
                });
            }
            self.data_sem.post(self.io);
        }
    };
}

test "runtime client datagram limits preserve legacy configuration and defaults" {
    const LimitedClient = ClientForTupleWithDatagramLimit(endpoint.Udp4Tuple, 1200);
    try std.testing.expect(Client == ClientForTuple(endpoint.Udp4Tuple));
    try std.testing.expect(IPv6Client == ClientForTupleWithDatagramLimit(endpoint.Udp6Tuple, 1200));
    try std.testing.expect(LimitedClient.Config == Client.Config);
    try std.testing.expectEqual(@as(usize, 10), @typeInfo(Client.Config).@"struct".field_names.len);
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    const peer = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer peer.close(io);
    const config: Client.Config = .{ .server_port = peer.address.getPort(), .alpn = &.{} };
    var legacy = try Client.init(std.testing.allocator, io, config);
    defer legacy.deinit();
    var limited = try LimitedClient.init(std.testing.allocator, io, config);
    defer limited.deinit();
    const address6 = std.Io.net.IpAddress{ .ip6 = .loopback(0) };
    const peer6 = try address6.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer peer6.close(io);
    var ipv6 = try IPv6Client.init(std.testing.allocator, io, .{
        .server_port = peer6.address.getPort(),
        .bind_addr = .loopback(0),
        .alpn = &.{},
    });
    defer ipv6.deinit();
    try std.testing.expectEqual(@as(u16, 1350), legacy.client.transport.connection.config.max_datagram_size);
    try std.testing.expectEqual(@as(u64, 1350), legacy.client.transport.connection.localTransportParameters().max_udp_payload_size);
    try std.testing.expectEqual(@as(u16, 1200), limited.client.transport.connection.config.max_datagram_size);
    try std.testing.expectEqual(@as(u64, 1200), limited.client.transport.connection.localTransportParameters().max_udp_payload_size);
    try std.testing.expectEqual(@as(u16, 1200), ipv6.client.transport.connection.config.max_datagram_size);
    try std.testing.expectEqual(@as(u64, 1200), ipv6.client.transport.connection.localTransportParameters().max_udp_payload_size);
}

test "runtime client discards oversized datagrams without failing a pending handshake" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const protection = quicz.protection;
    const server_cid: [8]u8 = @splat(0xa1);
    const secrets = try protection.deriveInitialSecrets(.v1, &server_cid);
    var plaintext: [1472 - 1 - 8 - 4 - 16]u8 = @splat(0);
    plaintext[0] = 1;
    inline for (.{ Client, ClientForTupleWithDatagramLimit(endpoint.Udp4Tuple, 1200), IPv6Client }) |Runtime| {
        var client = try Runtime.init(allocator, io, if (Runtime == IPv6Client)
            .{ .server_port = 4433, .bind_addr = .loopback(0), .alpn = &.{} }
        else
            .{ .server_port = 4433, .alpn = &.{} });
        defer client.deinit();
        const client_cid = client.client.transport.local_source_connection_id;
        const conn = &client.client.transport.connection;
        try conn.setLocalInitialSourceConnectionId(&client_cid);
        try conn.setPeerInitialSourceConnectionId(&server_cid);
        try conn.installOneRttTrafficSecrets(.{ .local = secrets.client.secret, .peer = secrets.server.secret });
        client.handshake_started = true;
        const datagram = try protection.protectShortPacketAes128(allocator, .{
            .dcid = &client_cid,
            .key_phase = false,
            .packet_number = 0,
        }, .{ .len = 4, .truncated_packet_number = 0 }, secrets.server, &plaintext);
        defer allocator.free(datagram);
        try std.testing.expectEqual(@as(usize, 1472), datagram.len);
        client.processDatagram(client.server_address, datagram);
        client.processDatagram(client.server_address, &.{});
        try std.testing.expectEqual(Runtime.handshake_pending, client.handshake_state.load(.acquire));
        try std.testing.expect(!client.handshake_complete.isSet());
        try std.testing.expect(client.handshakeError() == null);
        try std.testing.expectEqual(quicz.ConnectionState.active, conn.connectionState());
    }
}

const IPv4Config = struct {
    server_host: [4]u8 = .{ 127, 0, 0, 1 },
    server_port: u16,
    server_name: []const u8 = "localhost",
    alpn: []const []const u8,
    /// CA bundle for server certificate verification. Caller owns it; must
    /// outlive the Client. Null = skip verification (insecure).
    ca_bundle: ?*const std.crypto.Certificate.Bundle = null,
    /// Skip certificate verification (testing only).
    insecure_skip_verify: bool = false,
    /// QUIC version for the Initial handshake (RFC 9369 v2 = 0x6b3343cf).
    version: quic_packet.Version = .v1,
    /// Offer TLS_CHACHA20_POLY1305_SHA256 in the ClientHello.
    prefer_chacha20: bool = false,
    /// Preserve the existing default for callers that do not need network
    /// migration. Connectivity owners opt in after validating new paths.
    active_migration_disabled: bool = true,
    /// Send an ack-eliciting PING at this interval after handshake.
    /// Zero disables keepalive.
    keepalive_interval_ms: u32 = 0,
};

const IPv6Config = struct {
    server_host: [16]u8 = std.Io.net.Ip6Address.loopback(0).bytes,
    server_port: u16,
    server_scope_id: u32 = 0,
    /// Explicit local IPv6 address. Discovery owners retain source selection.
    bind_addr: ?std.Io.net.Ip6Address = null,
    server_name: []const u8 = "localhost",
    alpn: []const []const u8,
    /// CA bundle for server certificate verification. Caller owns it; must
    /// outlive the Client. Null = skip verification (insecure).
    ca_bundle: ?*const std.crypto.Certificate.Bundle = null,
    /// Skip certificate verification (testing only).
    insecure_skip_verify: bool = false,
    /// QUIC version for the Initial handshake (RFC 9369 v2 = 0x6b3343cf).
    version: quic_packet.Version = .v1,
    /// Offer TLS_CHACHA20_POLY1305_SHA256 in the ClientHello.
    prefer_chacha20: bool = false,
    /// Preserve the existing default for callers that do not need network
    /// migration. Connectivity owners opt in after validating new paths.
    active_migration_disabled: bool = true,
    /// Send an ack-eliciting PING at this interval after handshake.
    /// Zero disables keepalive.
    keepalive_interval_ms: u32 = 0,
};
