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

const Tls13ClientEndpoint = quicz.Tls13ClientEndpoint;
const endpoint = quicz.endpoint;
const quic_packet = quicz.packet;

const log = std.log.scoped(.quicz_runtime);

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
    free: [queued_datagram_pool_size]bool = .{true} ** queued_datagram_pool_size,
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

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    socket: std.Io.net.Socket,
    client: Tls13ClientEndpoint,
    server_address: std.Io.net.IpAddress,
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
    /// wait on handshake_sem for the terminal state.
    handshake_state: std.atomic.Value(u8) = .init(0),
    handshake_sem: std.Io.Semaphore = .{ .permits = 0 },
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

    pub const Config = struct {
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
    };

    pub fn init(allocator: std.mem.Allocator, io: std.Io, config: Config) !Client {
        var client_address = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } };
        const socket = try client_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
        enlargeSocketReceiveBuffer(socket.handle);
        const server_address = std.Io.net.IpAddress{ .ip4 = .{ .bytes = config.server_host, .port = config.server_port } };
        const client_path = endpoint.Udp4Tuple{
            .local = endpoint.Udp4Address.init(socket.address.ip4.bytes, socket.address.ip4.port),
            .remote = endpoint.Udp4Address.init(config.server_host, config.server_port),
        };
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
            .client_ca_bundle = config.ca_bundle,
            .prefer_chacha20 = config.prefer_chacha20,
        };
        const available_versions: []const quic_packet.Version = switch (config.version) {
            .v2 => &[_]quic_packet.Version{ .v1, .v2 },
            else => &[_]quic_packet.Version{.v1},
        };
        const client = try Tls13ClientEndpoint.init(
            allocator,
            1,
            client_path,
            .{ .active_migration_disabled = true },
            .{
                .initial_max_data = 10_485_760,
                .initial_max_stream_data = 10_485_760,
                .initial_max_streams_bidi = 128,
                .initial_max_streams_uni = 128,
                .max_datagram_size = send_mtu,
                .chosen_version = config.version,
                .available_versions = available_versions,
            },
            tls_config,
            original_dcid,
            client_scid,
        );
        return .{ .allocator = allocator, .io = io, .socket = socket, .client = client, .server_address = server_address, .datagram_pool = DatagramPool.init(allocator) };
    }

    pub fn deinit(self: *Client) void {
        if (self.started) {
            @atomicStore(bool, &self.stopping, true, .release);
            self.notifyDrive(self.io);
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

    /// Gracefully close the connection with an APPLICATION_CLOSE; the drive
    /// task emits the close frame and any PTO retransmit while it runs.
    pub fn close(self: *Client) void {
        @atomicStore(bool, &self.close_requested, true, .release);
        self.notifyDrive(self.io);
    }

    /// Whether any caller request or queued datagram still waits for the
    /// drive task. Checked after the park snapshot to close the window
    /// between request processing and the snapshot (see drive()).
    fn hasPendingWork(self: *Client) bool {
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

    fn nowNanos(self: *const Client) i64 {
        return @intCast(std.Io.Timestamp.now(self.io, .awake).nanoseconds);
    }

    /// Wake the drive task: bump the futex word, then wake the waiter.
    /// std.Build.WebServer uses the same pattern (notifyUpdate/update_id).
    fn notifyDrive(self: *Client, io: std.Io) void {
        _ = self.wake_id.rmw(.Add, 1, .release);
        io.futexWake(u32, &self.wake_id.raw, 1);
    }

    /// Spawn the recv and drive tasks (idempotent).
    fn startTasks(self: *Client) !void {
        if (self.started) return;
        try self.drive_group.concurrent(self.io, Client.recvTask, .{self});
        self.drive_group.concurrent(self.io, Client.drive, .{self}) catch |err| {
            @atomicStore(bool, &self.stopping, true, .release);
            self.drive_group.cancel(self.io);
            self.drive_group.await(self.io) catch {};
            return err;
        };
        self.started = true;
    }

    /// Drive the TLS 1.3 handshake to completion. Blocks until the drive
    /// task confirms the handshake or the connection closes first.
    pub fn connect(self: *Client) !void {
        try self.startTasks();
        if (self.handshake_state.load(.acquire) == handshake_confirmed) return;
        @atomicStore(bool, &self.connect_requested, true, .release);
        self.notifyDrive(self.io);
        self.handshake_sem.wait(self.io) catch return error.HandshakeFailed;
        if (self.handshake_state.load(.acquire) != handshake_confirmed) {
            return self.handshake_error orelse error.HandshakeFailed;
        }
    }

    /// Return how many UDP datagrams arrived since init. Lets diagnostics
    /// distinguish "UDP path unreachable" from "UDP works but the QUIC or TLS
    /// handshake failed" after a failed connect().
    pub fn datagramsReceived(self: *const Client) usize {
        return self.udp_datagrams_received;
    }

    /// Send `data` on a new bidirectional stream; returns the stream id.
    /// The drive task runs the request (the endpoint is drive-task only).
    pub fn send(self: *Client, data: []const u8, fin: bool) !u64 {
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
    pub fn sendOnStream(self: *Client, stream_id: u64, data: []const u8, fin: bool) !void {
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
    pub fn openStream(self: *Client) !u64 {
        return self.openStreamInternal(false);
    }

    /// Open a client-initiated unidirectional stream (without sending data);
    /// used by HTTP/3 for the control and QPACK encoder/decoder streams.
    pub fn openUniStream(self: *Client) !u64 {
        return self.openStreamInternal(true);
    }

    /// Switch the drive task into HTTP/3 mode: server-initiated unidirectional
    /// streams are polled so their control / QPACK bytes reach the stream
    /// queues. Call before sending HTTP/3 requests.
    pub fn enableH3(self: *Client) void {
        self.h3_mode = true;
    }

    fn openStreamInternal(self: *Client, uni: bool) !u64 {
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
    pub fn initiateKeyUpdate(self: *Client) !void {
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
    pub fn receive(self: *Client, stream_id: u64, buf: []u8) !usize {
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
    pub fn tryReceiveStreamData(self: *Client, stream_id: u64, buf: []u8) !?usize {
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
    pub fn streamIds(self: *Client, out: []u64) usize {
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
    pub fn waitStreamActivity(self: *Client) !void {
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
    pub fn runEchoSession(self: *Client, payload: []const u8) !bool {
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
    fn recvTask(self: *Client) std.Io.Cancelable!void {
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
            self.udp_datagrams_received += 1;
            const pooled_buf = self.datagram_pool.take();
            const copy = if (pooled_buf) |pb| blk: {
                @memcpy(pb[0..received.data.len], received.data);
                break :blk pb[0..received.data.len];
            } else allocator.dupe(u8, received.data) catch continue;
            while (!self.queue_mutex.tryLock()) std.atomic.spinLoopHint();
            self.datagram_queue.append(allocator, .{ .data = copy, .pooled = pooled_buf != null }) catch {
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
    fn drive(self: *Client) std.Io.Cancelable!void {
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
            self.drainOutgoing();
            self.drainQueuedDatagrams();
            self.checkHandshakeProgress();
            self.checkConnectionClose();
            self.serviceDueDeadlines();
            // Park until a datagram arrives, a request is queued, stop() runs,
            // or the next lifecycle deadline comes due. The snapshot is taken
            // after draining, pairing with notifyDrive's bump: a notifier that
            // already ran changed wake_id, so the wait returns immediately.
            const snapshot = self.wake_id.load(.acquire);
            const timeout: std.Io.Timeout = if (self.client.nextDeadline()) |d|
                .{ .deadline = .{ .raw = .{ .nanoseconds = d.deadline() }, .clock = .awake } }
            else
                .none;
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
    fn beginHandshakeOnce(self: *Client) void {
        if (self.handshake_started) return;
        if (!@atomicLoad(bool, &self.connect_requested, .acquire)) return;
        self.handshake_started = true;
        const begin = self.client.beginWithRoutePath(self.nowNanos(), &self.scratch) catch |err| {
            log.err("client: begin handshake: {}", .{err});
            self.handshake_state.store(handshake_failed, .release);
            self.handshake_sem.post(self.io);
            return;
        };
        self.socket.send(self.io, &self.server_address, begin.datagram) catch {};
        self.allocator.free(begin.datagram);
    }

    /// Emit the APPLICATION_CLOSE frame once close() has been requested.
    fn processCloseRequest(self: *Client) void {
        if (!@atomicLoad(bool, &self.close_requested, .acquire)) return;
        @atomicStore(bool, &self.close_requested, false, .release);
        self.close_initiated = true;
        const closed = self.client.closeApplicationWithRoutePath(0, "session complete", self.nowNanos()) catch return;
        if (closed) |o| {
            self.socket.send(self.io, &self.server_address, o.datagram) catch {};
            self.allocator.free(o.datagram);
        }
    }

    /// Run the parked send request: open a stream and queue the data.
    fn processSendRequest(self: *Client) void {
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
    fn failPendingSendRequest(self: *Client) void {
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
    fn processSendOnStreamRequest(self: *Client) void {
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
    fn failPendingSendOnStreamRequest(self: *Client) void {
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
    fn processOpenStreamRequest(self: *Client) void {
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
    fn failPendingOpenStreamRequest(self: *Client) void {
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
    fn processKeyUpdateRequest(self: *Client) void {
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
    fn failPendingKeyUpdateRequest(self: *Client) void {
        while (!self.key_update_mutex.tryLock()) std.atomic.spinLoopHint();
        const req = self.key_update_request;
        self.key_update_request = null;
        self.key_update_mutex.unlock();
        if (req != null) self.key_update_done_sem.post(self.io);
    }

    /// Drain pending outgoing datagrams to the server. Bounded: the server
    /// endpoint can keep producing closing-frame retransmits, and an unbounded
    /// loop here wedges the drive task so it never reaches the main loop's
    /// `stopping` check (and group.cancel cannot interrupt a non-blocking
    /// busy-spin). The remainder is picked up on the next drive iteration,
    /// mirroring the server runtime's single-pass drain.
    fn drainOutgoing(self: *Client) void {
        var out: [16]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
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

    /// Process every queued datagram in FIFO order and free its buffer.
    fn drainQueuedDatagrams(self: *Client) void {
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
            self.processDatagram(qd.data);
            if (qd.pooled) self.datagram_pool.release(qd.data) else self.allocator.free(qd.data);
        }
    }

    /// Route one datagram through the client endpoint, send the TLS outbound
    /// it returns, deliver stream data, and drain the responses (ACKs).
    fn processDatagram(self: *Client, data: []const u8) void {
        const result = self.client.receiveWithRoutePath(self.nowNanos(), &self.scratch, data) catch |err| {
            log.err("client: receive ({d} bytes): {}", .{ data.len, err });
            if (data.len > 0) {
                const head = data[0..@min(data.len, 48)];
                log.err("client: datagram head: {x}", .{head});
            }
            self.recordHandshakeError(err);
            return;
        };
        if (result.outbound_initial) |o| {
            self.socket.send(self.io, &self.server_address, o.datagram) catch {};
            self.allocator.free(o.datagram);
        }
        if (result.outbound_handshake) |o| {
            self.socket.send(self.io, &self.server_address, o.datagram) catch {};
            self.allocator.free(o.datagram);
        }
        self.deliverStreamData();
        self.drainOutgoing();
    }

    /// Fail a pending handshake with the packet-processing error that made it
    /// unrecoverable. Without this, an invalid/undecryptable server response
    /// is only logged and `connect()` keeps retrying until an external timeout.
    fn recordHandshakeError(self: *Client, err: anyerror) void {
        if (self.handshake_state.load(.acquire) != handshake_pending) return;
        if (!self.handshake_started) return;
        self.handshake_error = err;
        self.handshake_state.store(handshake_failed, .release);
        self.handshake_sem.post(self.io);
    }

    /// Push received bytes of every open stream into its queue and surface
    /// EOF once the peer FIN is fully consumed. Server-initiated
    /// unidirectional streams (odd ids, HTTP/3 control / QPACK) are polled in
    /// addition to the streams this client opened, so their ordered bytes land
    /// in the same per-stream queues as response data.
    fn deliverStreamData(self: *Client) void {
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

    fn deliverStreamBytes(self: *Client, sid: u64, buf: *[4096]u8, pushed: *bool) void {
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
    fn serviceDueDeadlines(self: *Client) void {
        var passes: usize = 0;
        while (passes < 8) : (passes += 1) {
            var out: [16]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
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
    fn checkHandshakeProgress(self: *Client) void {
        if (self.handshake_state.load(.acquire) != handshake_pending) return;
        if (!self.handshake_started) return;
        if (self.client.handshakeConfirmed()) {
            self.handshake_state.store(handshake_confirmed, .release);
            self.handshake_sem.post(self.io);
            return;
        }
        // A connection closing before confirmation can never complete the
        // handshake (server rejection, close frame, expired timers).
        if (self.client.transport.connection.isClosingOrClosed()) {
            self.handshake_state.store(handshake_failed, .release);
            self.handshake_sem.post(self.io);
        }
    }

    /// Surface a closing/closed connection to a blocked receive(): wake the
    /// stream waiters once, so they observe error.ConnectionClosed.
    fn checkConnectionClose(self: *Client) void {
        if (@atomicLoad(bool, &self.conn_closing_or_closed, .acquire)) return;
        if (!self.client.transport.connection.isClosingOrClosed()) return;
        @atomicStore(bool, &self.conn_closing_or_closed, true, .release);
        const conn = self.client.transport.connection;
        if (self.close_initiated and conn.peer_close == null) {
            log.debug("client: connection closing after close request: {}", .{conn.connectionState()});
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
