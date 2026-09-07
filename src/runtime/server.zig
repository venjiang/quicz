//! quicz I/O runtime — async streaming server (multi-connection).
//!
//! std.http model: accept loop spawns per-connection handler tasks.
//! A recv task blocks on the UDP socket and queues datagrams; the drive
//! task routes them to connections and services lifecycle deadlines.
//! The drive parks on a futex word (std.Build.WebServer update_id pattern)
//! bumped by every wakeup source, waiting until the next lifecycle deadline.
//! Handlers block on std.Io.Semaphore wakeups.

const std = @import("std");
const builtin = @import("builtin");
const quicz = @import("../lib.zig");
const h3_proto = @import("../h3/server.zig");
const runtime_h3 = @import("h3_server.zig");

const log = std.log.scoped(.quicz_runtime);

const Connection = quicz.Connection;
const Tls13ServerTransport = quicz.Tls13ServerTransport;
const endpoint = quicz.endpoint;
const quic_packet = quicz.packet;

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

const ServerRecord = struct {
    handle: u64,
    transport: Tls13ServerTransport,
    retry_validated: bool = false,

    fn connectionRef(self: *@This()) *Connection {
        return self.transport.connectionRef();
    }
    fn cryptoBackend(self: *@This()) quicz.CryptoBackend {
        return self.transport.cryptoBackend();
    }
    fn destinationConnectionId(self: *const @This()) []const u8 {
        return self.transport.connection.peerDestinationConnectionId() orelse
            self.transport.peerInitialSourceConnectionId();
    }
    fn sourceConnectionId(self: *const @This()) []const u8 {
        return self.transport.localInitialSourceConnectionId();
    }
    fn initialDestinationConnectionId(self: *const @This()) []const u8 {
        return if (self.retry_validated)
            self.transport.localInitialSourceConnectionId()
        else
            self.transport.originalDestinationConnectionId();
    }
    fn markRetryValidated(self: *@This()) void {
        self.retry_validated = true;
    }
    fn deinit(self: *@This()) void {
        self.transport.deinit();
    }
};

const ServerEndpoint = quicz.Tls13ServerEndpoint(
    ServerRecord,
    ServerRecord.connectionRef,
    ServerRecord.cryptoBackend,
    ServerRecord.destinationConnectionId,
    ServerRecord.sourceConnectionId,
    ServerRecord.initialDestinationConnectionId,
    ServerRecord.markRetryValidated,
    ServerRecord.deinit,
);

/// Datagram received by the recv task, waiting for the drive task.
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

const QueuedDatagram = struct {
    from: std.Io.net.IpAddress,
    /// Owned copy; the drive task frees it after processing.
    data: []u8,
    /// True when `data` is a pooled buffer (returned to the pool, not freed).
    pooled: bool = false,
};

/// Per-stream receive buffer within a connection.
const StreamRecvState = struct {
    id: u64,
    queue: std.ArrayList(u8) = .empty,
    /// First unread byte; avoids shifting the queue on every read.
    read_offset: usize = 0,
    /// Peer FIN received and all stream bytes delivered to the queue.
    eof: bool = false,
};

/// Per-stream send buffer within a connection.
const StreamSendState = struct {
    id: u64,
    queue: std.ArrayList(u8) = .empty,
    fin: bool = false,
};

/// A queued STOP_SENDING request (stream id + application error code).
const StopSendingReq = struct {
    id: u64,
    code: u64,
};

/// Per-connection server state.
const ConnState = struct {
    conn: *Connection,
    handle: u64,
    peer: std.Io.net.IpAddress,
    mutex: std.atomic.Mutex = .unlocked,
    recv_streams: std.ArrayList(StreamRecvState) = .empty,
    pending_streams: std.ArrayList(u64) = .empty,
    send_streams: std.ArrayList(StreamSendState) = .empty,
    /// Queued STOP_SENDING requests (stream id + error code), drained by the
    /// drive task.
    stop_sendings: std.ArrayList(StopSendingReq) = .empty,
    /// True while the handler has queued an openUniStream request the drive
    /// task has not served yet.
    uni_open_requested: bool = false,
    /// Result of the most recent openUniStream request (set by the drive task
    /// before posting uni_open_sem).
    next_uni_stream: u64 = 0,
    /// Posted by the drive task once an openUniStream request is served.
    uni_open_sem: std.Io.Semaphore = .{ .permits = 0 },
    /// Posted by the drive task when stream data or EOF arrives.
    data_sem: std.Io.Semaphore = .{ .permits = 0 },
    /// Set by releaseConnection; the drive task reclaims the state once
    /// the connection is closed and the handler is done with it
    /// (single-owner reclamation; s2n-quic uses a handle refcount here,
    /// which only pays off when one connection has several handlers).
    handler_done: bool = false,
    /// Cached `conn.isClosingOrClosed()`, refreshed by the drive task while
    /// the endpoint record is alive. The endpoint reclaims records of closed
    /// connections during deadline queries; after that the connection pointer
    /// must not be dereferenced, so reclamation relies on this cache.
    closing_or_closed: bool = false,
    /// Set while this connection has queued send data the drive task has
    /// not flushed yet; used to coalesce drive wakeups in sendStreamData.
    send_pending: bool = false,

    fn deinit(self: *ConnState, alloc: std.mem.Allocator) void {
        for (self.recv_streams.items) |*s| s.queue.deinit(alloc);
        self.recv_streams.deinit(alloc);
        self.pending_streams.deinit(alloc);
        for (self.send_streams.items) |*s| s.queue.deinit(alloc);
        self.send_streams.deinit(alloc);
        self.stop_sendings.deinit(alloc);
    }
};

/// Async streaming QUIC server (multi-connection, std.http model).
pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    socket: std.Io.net.Socket,
    server_ep: ServerEndpoint,
    next_handle: u64 = 1,
    alpn: []const []const u8,
    cert_der: []const u8,
    private_key: []const u8,
    prefer_chacha20: bool = false,

    mutex: std.atomic.Mutex = .unlocked,
    conns: std.AutoHashMap(u64, *ConnState),
    pending_accept: std.ArrayList(u64) = .empty,
    /// Posted by the drive task when a new connection is accepted.
    accept_sem: std.Io.Semaphore = .{ .permits = 0 },
    /// Futex word bumped by every drive wakeup source (recv task, senders,
    /// stop); the drive task parks on it with an absolute deadline
    /// (std.Build.WebServer update_id pattern).
    wake_id: std.atomic.Value(u32) = .init(0),
    queue_mutex: std.atomic.Mutex = .unlocked,
    /// Datagrams received by the recv task, consumed FIFO by the drive task.
    datagram_queue: std.ArrayList(QueuedDatagram),
    datagram_read_offset: usize = 0,
    /// Reusable receive buffers, avoiding a per-datagram allocation.
    datagram_pool: DatagramPool,
    drive_group: std.Io.Group = .init,
    started: bool = false,
    stopping: bool = false,
    /// Set by serveH3 before handlers spawn; read by h3ServeHandler.
    h3_request_handler: ?h3_proto.RequestHandler = null,
    h3_qpack_max_table_capacity: u64 = 4096,
    h3_qpack_blocked_streams: u64 = 8,

    pub const Config = struct {
        port: u16,
        alpn: []const []const u8,
        cert_der: []const u8,
        private_key: []const u8,
        prefer_chacha20: bool = false,
        /// IPv4 address to bind. Defaults to loopback (127.0.0.1); set to
        /// `.{0,0,0,0}` to listen on all interfaces (cross-host benchmarks).
        bind_addr: ?[4]u8 = null,
        /// Maximum concurrent connections accepted by this server. The
        /// endpoint pre-allocates routing and scratch state for this many
        /// connections, so set it to your expected peak + headroom.
        max_connections: usize = 4096,
    };

    pub fn init(allocator: std.mem.Allocator, io: std.Io, config: Config) !Server {
        const local_ip = if (config.bind_addr) |ip| ip else [_]u8{ 127, 0, 0, 1 };
        var address = std.Io.net.IpAddress{ .ip4 = .{ .bytes = local_ip, .port = config.port } };
        const socket = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
        enlargeSocketReceiveBuffer(socket.handle);
        const server_ep = try ServerEndpoint.initWithCapacity(allocator, config.max_connections, .{
            .max_routes = config.max_connections,
            .max_stateless_reset_tokens = config.max_connections,
        });
        return .{
            .allocator = allocator,
            .io = io,
            .socket = socket,
            .server_ep = server_ep,
            .alpn = config.alpn,
            .cert_der = config.cert_der,
            .private_key = config.private_key,
            .prefer_chacha20 = config.prefer_chacha20,
            .conns = std.AutoHashMap(u64, *ConnState).init(allocator),
            .datagram_queue = .empty,
            .datagram_pool = DatagramPool.init(allocator),
        };
    }

    pub fn start(self: *Server) !void {
        if (self.started) return;
        try self.drive_group.concurrent(self.io, Server.recvTask, .{self});
        self.drive_group.concurrent(self.io, Server.drive, .{self}) catch |err| {
            @atomicStore(bool, &self.stopping, true, .release);
            self.drive_group.cancel(self.io);
            self.drive_group.await(self.io) catch {};
            return err;
        };
        self.started = true;
    }

    pub fn localPort(self: *const Server) u16 {
        return switch (self.socket.address) {
            .ip4 => |address| address.port,
            .ip6 => |address| address.port,
        };
    }

    /// Signal the drive task and all accept/receive loops to stop.
    pub fn stop(self: *Server) void {
        @atomicStore(bool, &self.stopping, true, .release);
        // Wake a blocked accept loop so it observes `stopping`.
        self.accept_sem.post(self.io);
        // Wake the parked drive task.
        self.notifyDrive(self.io);
    }

    /// Aggregate metrics across all active connections (for a monitoring
    /// endpoint pooled over the lifetime of the server). Reads are lock-serialized
    /// with the drive task's conns traversal; per-connection stats are best-effort
    /// snapshots that may straddle an in-flight update.
    pub const Metrics = struct {
        active_connections: usize,
        stream_bytes_sent: u64,
        stream_bytes_received: u64,
        total_bytes_in_flight: usize,
        smoothed_rtt_us: u64,
        rttvar_us: u64,
        congestion_window: usize,
        packets_lost: u64,
        packets_retransmitted: u64,
    };

    /// Return an aggregate metrics snapshot across all live connections.
    pub fn metricsSnapshot(self: *Server) Metrics {
        var m: Metrics = .{
            .active_connections = 0,
            .stream_bytes_sent = 0,
            .stream_bytes_received = 0,
            .total_bytes_in_flight = 0,
            .smoothed_rtt_us = 0,
            .rttvar_us = 0,
            .congestion_window = 0,
            .packets_lost = 0,
            .packets_retransmitted = 0,
        };
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        var it = self.conns.valueIterator();
        while (it.next()) |csp| {
            const st = csp.*;
            if (st.conn.isClosingOrClosed()) continue;
            const cs = st.conn.connectionStats();
            m.active_connections += 1;
            m.stream_bytes_sent += cs.stream_bytes_sent;
            m.stream_bytes_received += cs.stream_bytes_received;
            m.total_bytes_in_flight += cs.total_bytes_in_flight;
            m.smoothed_rtt_us += cs.smoothed_rtt_us;
            m.rttvar_us += cs.rttvar_us;
            m.congestion_window += cs.congestion_window;
            m.packets_lost += cs.packets_lost;
            m.packets_retransmitted += cs.packets_retransmitted;
        }
        self.mutex.unlock();
        return m;
    }

    /// Start the server (if not already started) and spawn the serve task,
    /// which accepts connections and runs one handler task per connection
    /// (std.Build.WebServer serve pattern). The runtime releases each
    /// connection when its handler returns; deinit cancels the serve task
    /// and every handler task.
    pub fn serve(self: *Server, handler: HandlerFn) !void {
        try self.start();
        try self.drive_group.concurrent(self.io, Server.serveLoop, .{ self, handler });
        log.info("quicz server listening on {f}/", .{self.socket.address});
    }

    /// HTTP/3 QPACK dynamic-table options (RFC 9204).
    pub const H3ServeOptions = struct {
        qpack_max_table_capacity: u64 = 4096,
        qpack_blocked_streams: u64 = 8,
    };

    /// Serve HTTP/3 on this transport server: every accepted connection is
    /// driven by the runtime H3 driver with `handler` as the request handler.
    /// The transport (socket, endpoint, connection lifecycle) stays owned by
    /// this `Server`; only the application protocol is wired here.
    pub fn serveH3(self: *Server, options: H3ServeOptions, handler: h3_proto.RequestHandler) !void {
        self.h3_request_handler = handler;
        self.h3_qpack_max_table_capacity = options.qpack_max_table_capacity;
        self.h3_qpack_blocked_streams = options.qpack_blocked_streams;
        try self.serve(h3ServeHandler);
    }

    /// Per-connection handler backing serveH3: one runtime H3 driver per
    /// connection, exactly the layering recommended for production.
    fn h3ServeHandler(conn: ServerConnection) std.Io.Cancelable!void {
        const srv = conn.server;
        const handler = srv.h3_request_handler orelse return;
        var driver = runtime_h3.H3Server.init(
            srv.allocator,
            srv,
            conn.id,
            handler,
            srv.h3_qpack_max_table_capacity,
            srv.h3_qpack_blocked_streams,
        );
        defer driver.deinit();
        try driver.run();
    }

    /// Serve task body: accept loop plus per-connection handler tasks
    /// (std.Build.WebServer.serve pattern: per-conn group.concurrent,
    /// defer group.cancel for cleanup).
    fn serveLoop(self: *Server, handler: HandlerFn) std.Io.Cancelable!void {
        const io = self.io;
        var group: std.Io.Group = .init;
        defer group.cancel(io);
        while (true) {
            const conn = try self.accept();
            group.concurrent(io, handlerTask, .{ self, conn, handler }) catch |err| {
                log.err("unable to spawn connection handler: {}", .{err});
                self.releaseConnection(conn.id);
                continue;
            };
        }
    }

    /// Handler task wrapper: releases the connection reference when the
    /// handler finishes so the drive task can reclaim the state.
    fn handlerTask(self: *Server, conn: ServerConnection, handler: HandlerFn) std.Io.Cancelable!void {
        defer self.releaseConnection(conn.id);
        handler(conn) catch |err| {
            if (err != error.Canceled) log.err("connection {d} handler failed: {}", .{ conn.id, err });
        };
    }

    pub fn deinit(self: *Server) void {
        if (self.started) {
            self.stop();
            self.drive_group.cancel(self.io);
            self.drive_group.await(self.io) catch {};
            self.started = false;
        }
        var it = self.conns.valueIterator();
        while (it.next()) |cs| {
            cs.*.deinit(self.allocator);
            self.allocator.destroy(cs.*);
        }
        self.conns.deinit();
        self.pending_accept.deinit(self.allocator);
        for (self.datagram_queue.items[self.datagram_read_offset..]) |qd| {
            if (qd.pooled) self.datagram_pool.release(qd.data) else self.allocator.free(qd.data);
        }
        self.datagram_queue.deinit(self.allocator);
        self.datagram_pool.deinit(self.allocator);
        self.server_ep.deinit();
        self.socket.close(self.io);
    }

    /// Mark the handler done with a connection. Call once per connection
    /// when the handler finishes; the drive task frees the state once the
    /// connection is also closed (single-owner reclamation).
    pub fn releaseConnection(self: *Server, conn_id: u64) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        if (self.conns.get(conn_id)) |cs| {
            cs.handler_done = true;
        }
        self.mutex.unlock();
    }

    /// Raise SO_RCVBUF so client bursts do not overflow the kernel receive
    /// buffer before the drive task drains it; loss recovery still covers
    /// any residual drops.
    fn enlargeSocketReceiveBuffer(handle: std.Io.net.Socket.Handle) void {
        const size: u32 = 4 * 1024 * 1024;
        std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&size)) catch {};
    }

    fn nowNanos(self: *const Server) i64 {
        return @intCast(std.Io.Timestamp.now(self.io, .awake).nanoseconds);
    }

    /// Drain queued stream sends and emit outgoing datagrams.
    fn drainOutgoing(self: *Server, io: std.Io, allocator: std.mem.Allocator) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        var closed_handles: [64]u64 = undefined;
        var closed_count: usize = 0;
        var cit = self.conns.valueIterator();
        while (cit.next()) |csp| {
            const st = csp.*;
            // The endpoint reclaims records of closed connections during
            // deadline queries; only dereference the connection while its
            // record is alive. The cached close state keeps this ConnState
            // reclaimable after the record is gone.
            const record_alive = self.server_ep.records.get(st.handle) != null;
            const closing_now = if (record_alive) st.conn.isClosingOrClosed() else true;
            const closing_prev = @atomicRmw(bool, &st.closing_or_closed, .Xchg, closing_now, .acq_rel);
            if (closing_now and !closing_prev) {
                // A blocked handler cannot learn about the close from stream
                // data or EOF; wake it so it observes error.ConnectionClosed.
                st.data_sem.post(io);
            }
            if (closing_now and st.handler_done) {
                if (closed_count < closed_handles.len) {
                    closed_handles[closed_count] = st.handle;
                    closed_count += 1;
                }
                continue;
            }
            if (!record_alive) continue;
            while (!st.mutex.tryLock()) std.atomic.spinLoopHint();
            var flow_blocked = false;
            for (st.send_streams.items) |*sq| {
                if (sq.queue.items.len > 0 or sq.fin) {
                    st.conn.sendOnStream(sq.id, sq.queue.items, sq.fin) catch |err| {
                        if (err == error.FlowControlBlocked) {
                            // Keep the queued bytes and retry once the peer
                            // grants fresh MAX_STREAM_DATA credit (an inbound
                            // datagram wakes the drive loop, which drains again).
                            flow_blocked = true;
                            break;
                        }
                        sq.queue.clearRetainingCapacity();
                        sq.fin = false;
                        break;
                    };
                    sq.queue.clearRetainingCapacity();
                    sq.fin = false;
                }
            }
            for (st.stop_sendings.items) |req| {
                st.conn.stopSending(req.id, req.code) catch {};
            }
            st.stop_sendings.clearRetainingCapacity();
            if (st.uni_open_requested) {
                st.next_uni_stream = st.conn.openUniStream() catch 0;
                st.uni_open_requested = false;
                st.uni_open_sem.post(self.io);
            }
            if (!flow_blocked) st.send_pending = false;
            st.mutex.unlock();
        }
        for (closed_handles[0..closed_count]) |h| {
            if (self.conns.fetchRemove(h)) |kv| {
                kv.value.deinit(allocator);
                allocator.destroy(kv.value);
                log.info("connection {d} closed: state reclaimed", .{h});
            }
        }
        self.mutex.unlock();
        var out: [16]ServerEndpoint.DatagramPathResult = undefined;
        const drained = self.server_ep.drainDatagramsAcrossRecordsWithRoutePathWithScratch(self.nowNanos(), .application, &out);
        // Batch the drained datagrams: Linux sendmmsg amortizes the syscall
        // across the batch (std.Io.Threaded netSend); macOS has no sendmmsg
        // and its batching path is slower, so fall back to per-datagram sends.
        var addrs: [16]std.Io.net.IpAddress = undefined;
        var msgs: [16]std.Io.net.OutgoingMessage = undefined;
        for (out[0..drained.datagrams_written], 0..) |o, i| {
            addrs[i] = .{ .ip4 = .{ .bytes = o.path.remote.octets, .port = o.path.remote.port } };
            msgs[i] = .{ .address = &addrs[i], .data_ptr = o.datagram.ptr, .data_len = o.datagram.len };
        }
        if (builtin.os.tag == .linux) {
            self.socket.sendMany(io, msgs[0..drained.datagrams_written], .{}) catch {};
        } else {
            for (msgs[0..drained.datagrams_written]) |m| {
                self.socket.send(io, m.address, m.data_ptr[0..m.data_len]) catch {};
            }
        }
        for (out[0..drained.datagrams_written]) |o| {
            allocator.free(o.datagram);
        }
    }

    /// Wake the drive task: bump the futex word, then wake the waiter.
    /// std.Build.WebServer uses the same pattern (notifyUpdate/update_id).
    fn notifyDrive(self: *Server, io: std.Io) void {
        _ = self.wake_id.rmw(.Add, 1, .release);
        io.futexWake(u32, &self.wake_id.raw, 1);
    }

    /// Receive datagrams into the queue and wake the drive task. Mirrors the
    /// official WebServer accept task: block on the socket, hand work off.
    fn recvTask(self: *Server) std.Io.Cancelable!void {
        const io = self.io;
        const allocator = self.allocator;
        var recv_buf: [max_datagram_size]u8 = undefined;
        while (!@atomicLoad(bool, &self.stopping, .acquire)) {
            const received = self.socket.receiveTimeout(io, &recv_buf, .none) catch |err| switch (err) {
                error.Canceled => return,
                else => {
                    if (@atomicLoad(bool, &self.stopping, .acquire)) return;
                    log.debug("recv task: receive: {}", .{err});
                    continue;
                },
            };
            const pooled_buf = self.datagram_pool.take();
            const copy = if (pooled_buf) |pb| blk: {
                @memcpy(pb[0..received.data.len], received.data);
                break :blk pb[0..received.data.len];
            } else allocator.dupe(u8, received.data) catch continue;
            while (!self.queue_mutex.tryLock()) std.atomic.spinLoopHint();
            self.datagram_queue.append(allocator, .{ .from = received.from, .data = copy, .pooled = pooled_buf != null }) catch {
                self.queue_mutex.unlock();
                if (pooled_buf != null) self.datagram_pool.release(copy) else allocator.free(copy);
                continue;
            };
            self.queue_mutex.unlock();
            self.notifyDrive(io);
        }
    }

    /// Process every queued datagram in FIFO order and free its buffer.
    fn drainQueuedDatagrams(self: *Server, io: std.Io, allocator: std.mem.Allocator) void {
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
            self.processDatagram(io, allocator, qd.from, qd.data);
            if (qd.pooled) self.datagram_pool.release(qd.data) else allocator.free(qd.data);
        }
    }

    /// Route one datagram through the endpoint (accept or routed step) and
    /// deliver stream data to per-connection queues.
    fn processDatagram(self: *Server, io: std.Io, allocator: std.mem.Allocator, from: std.Io.net.IpAddress, data: []const u8) void {
        const from_addr = endpoint.Udp4Address.init(from.ip4.bytes, from.ip4.port);
        const local_addr = endpoint.Udp4Address.init(self.socket.address.ip4.bytes, self.socket.address.ip4.port);
        const path = endpoint.Udp4Tuple{ .local = local_addr, .remote = from_addr };
        const now = self.nowNanos();

        var initial_out: [4]quicz.endpoint_types.EndpointPolledDatagramResult = undefined;
        var handshake_out: [4]quicz.endpoint_types.EndpointPolledDatagramResult = undefined;
        var installed_out: [16]ServerEndpoint.DatagramPathResult = undefined;
        var pending_out: [16]ServerEndpoint.DatagramPathResult = undefined;
        var scratch: [8192]u8 = undefined;

        const action = self.server_ep.feedDatagram(&scratch, path, data, &[_]u8{}, &[_]quic_packet.Version{ .v1, .v2 }) catch |e| {
            log.err("drive: feedDatagram ({d} bytes): {}", .{ data.len, e });
            return;
        };
        var dest = std.Io.net.IpAddress{ .ip4 = .{ .bytes = from_addr.octets, .port = from_addr.port } };

        switch (action) {
            .accept_initial => |initial_accept| {
                const handle = self.next_handle;
                self.next_handle += 1;
                var server_scid: [8]u8 = undefined;
                io.randomSecure(&server_scid) catch {};
                const record = allocator.create(ServerRecord) catch |e| {
                    log.err("drive: allocate ServerRecord: {}", .{e});
                    return;
                };
                const cert_chain = [_][]const u8{self.cert_der};
                record.* = .{
                    .handle = handle,
                    .transport = Tls13ServerTransport.init(allocator, .{
                        .initial_max_data = 10_485_760,
                        .initial_max_stream_data = 10_485_760,
                        .initial_max_streams_bidi = 128,
                        .initial_max_streams_uni = 128,
                        .max_datagram_size = send_mtu,
                        .max_idle_timeout_ms = 30000,
                    }, .{
                        .alpn = self.alpn,
                        .cert_chain_der = &cert_chain,
                        .private_key_bytes = self.private_key,
                        .private_key_algorithm = .ecdsa_p256_sha256,
                        .prefer_chacha20 = self.prefer_chacha20,
                    }) catch |e| {
                        log.err("drive: Tls13ServerTransport.init: {}", .{e});
                        allocator.destroy(record);
                        return;
                    },
                };
                record.transport.connection.validatePeerAddress() catch |e| {
                    log.err("drive: validatePeerAddress: {}", .{e});
                };
                record.transport.setLocalInitialSourceConnectionId(&server_scid) catch |e| {
                    log.err("drive: setLocalInitialSourceConnectionId: {}", .{e});
                };
                const initial_info = quicz.protection.peekProtectedLongPacketInfo(data) catch |e| {
                    log.err("drive: peekProtectedLongPacketInfo: {}", .{e});
                    record.transport.deinit();
                    allocator.destroy(record);
                    return;
                };
                record.transport.setOriginalDestinationConnectionId(initial_info.dcid) catch |e| {
                    log.err("drive: setOriginalDestinationConnectionId: {}", .{e});
                };
                const accepted = self.server_ep.acceptInitialRecord(handle, record, now, initial_accept, &server_scid, data, .{}, &scratch, &initial_out, &handshake_out) catch |e| {
                    log.err("drive: acceptInitialRecord: {}", .{e});
                    record.transport.deinit();
                    allocator.destroy(record);
                    return;
                };
                const cs = allocator.create(ConnState) catch |e| {
                    log.err("drive: allocate ConnState: {}", .{e});
                    return;
                };
                cs.* = .{ .conn = record.transport.connectionRef(), .handle = handle, .peer = dest };
                while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
                self.conns.put(handle, cs) catch {};
                self.pending_accept.append(allocator, handle) catch {};
                self.mutex.unlock();
                self.accept_sem.post(io);
                log.info("drive: accepted conn {d}: initial_out={d} handshake={}", .{ handle, accepted.initial.drain.datagrams_written, accepted.handshake != null });
                for (initial_out[0..accepted.initial.drain.datagrams_written]) |o| {
                    self.socket.send(io, &dest, o.datagram) catch |e| log.err("drive: send initial response: {}", .{e});
                    allocator.free(o.datagram);
                }
                if (accepted.handshake) |hs| {
                    for (handshake_out[0..hs.drain.datagrams_written]) |o| {
                        self.socket.send(io, &dest, o.datagram) catch {};
                        allocator.free(o.datagram);
                    }
                }
            },
            .routed => {
                // RFC 9000 §12.2: a datagram may coalesce long-header and
                // short-header packets.  When the first long-header packet
                // doesn't fill the datagram and the trailing byte is a short
                // header, re-queue the trailing 1-RTT bytes for the next
                // drive iteration and process only the long-header portion.
                var effective_data = data;
                if (data.len > 1 and (data[0] & 0x80) != 0) {
                    const pi = quicz.protection.peekProtectedLongPacketInfo(data) catch null;
                    if (pi) |pi_val| {
                        // Only split Handshake-first coalesced datagrams with
                        // a trailing short-header (1-RTT) packet.  Initial-first
                        // coalesced datagrams are handled by the endpoint's
                        // processInitialWithHandshakeKeys path; padding (0x00)
                        // is excluded by the fixed-bit check.
                        if (pi_val.packet_type == .handshake and
                            pi_val.len > 0 and pi_val.len < data.len and
                            (data[pi_val.len] & 0x80) == 0 and
                            (data[pi_val.len] & 0x40) != 0)
                        {
                            const trailing = data[pi_val.len..];
                            const tc = allocator.dupe(u8, trailing) catch null;
                            if (tc) |copy| {
                                while (!self.queue_mutex.tryLock()) std.atomic.spinLoopHint();
                                self.datagram_queue.append(allocator, .{ .from = dest, .data = copy }) catch {
                                    allocator.free(copy);
                                };
                                self.queue_mutex.unlock();
                                effective_data = data[0..pi_val.len];
                            }
                        }
                    }
                }
                // Detect packet type from first byte to select the correct key space.
                const space: quicz.endpoint_types.EndpointInstalledKeyDatagramSpace = blk: {
                    if (effective_data.len == 0) break :blk .application;
                    if (effective_data[0] & 0x80 != 0) {
                        break :blk switch ((effective_data[0] >> 4) & 0x03) {
                            2 => .handshake,
                            else => .application,
                        };
                    }
                    break :blk .application;
                };
                const step = self.server_ep.receiveDatagramStepWithRoutePath(
                    allocator,
                    path,
                    now,
                    effective_data,
                    &[_]u8{},
                    &[_]quic_packet.Version{ .v1, .v2 },
                    .{ .space = space, .out = &scratch, .unpredictable_prefix = &[_]u8{}, .supported_versions = &[_]quic_packet.Version{ .v1, .v2 } },
                    &scratch,
                    &[_]u8{},
                    &initial_out,
                    &handshake_out,
                    &installed_out,
                    space,
                    &pending_out,
                ) catch |e| {
                    log.err("drive: receiveDatagramStep ({d} bytes, first 0x{x:0>2}): {}", .{ effective_data.len, effective_data[0], e });
                    return;
                };
                switch (step.process) {
                    .routed => |routed| switch (routed) {
                        .installed_key => |ik| {
                            for (installed_out[0..ik.drain.datagrams_written]) |o| {
                                self.socket.send(io, &dest, o.datagram) catch {};
                                allocator.free(o.datagram);
                            }
                            // Deliver received stream data to per-connection
                            // queues via the endpoint's own records: the
                            // routed connection is the record's connection.
                            while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
                            var rit = self.server_ep.records.records.valueIterator();
                            while (rit.next()) |recp| {
                                const rec = recp.*;
                                const conn = rec.transport.connectionRef();
                                const handle = rec.handle;
                                const st = self.conns.get(handle) orelse continue;
                                var stream_buf: [4096]u8 = undefined;
                                var sid: u64 = 0;
                                var pushed = false;
                                // Poll every client-initiated stream (even sid):
                                // bidirectional (0,4,8,...) and unidirectional
                                // (2,6,10,...). Server-initiated (odd) sids are
                                // send-only here and skipped.
                                while (sid < 1024) : (sid += 1) {
                                    if ((sid & 1) != 0) continue;
                                    while (true) {
                                        const n = conn.recvOnStream(sid, &stream_buf) catch break;
                                        const len = n orelse break;
                                        if (len == 0) break;
                                        while (!st.mutex.tryLock()) std.atomic.spinLoopHint();
                                        var idx: ?usize = null;
                                        for (st.recv_streams.items, 0..) |s, i| {
                                            if (s.id == sid) {
                                                idx = i;
                                                break;
                                            }
                                        }
                                        if (idx == null) {
                                            st.recv_streams.append(allocator, .{ .id = sid }) catch {};
                                            idx = st.recv_streams.items.len - 1;
                                            st.pending_streams.append(allocator, sid) catch {};
                                        }
                                        st.recv_streams.items[idx.?].queue.appendSlice(allocator, stream_buf[0..len]) catch {};
                                        pushed = true;
                                        st.mutex.unlock();
                                    }
                                    // FIN received and all bytes drained from the
                                    // connection: surface EOF on the stream queue.
                                    if (conn.recvStreamFinished(sid) catch false) {
                                        while (!st.mutex.tryLock()) std.atomic.spinLoopHint();
                                        var eof_idx: ?usize = null;
                                        for (st.recv_streams.items, 0..) |s, i| {
                                            if (s.id == sid) {
                                                eof_idx = i;
                                                break;
                                            }
                                        }
                                        if (eof_idx == null) {
                                            st.recv_streams.append(allocator, .{ .id = sid }) catch {};
                                            eof_idx = st.recv_streams.items.len - 1;
                                            st.pending_streams.append(allocator, sid) catch {};
                                        }
                                        st.recv_streams.items[eof_idx.?].eof = true;
                                        pushed = true;
                                        st.mutex.unlock();
                                    }
                                }
                                if (pushed) st.data_sem.post(io);
                            }
                            self.mutex.unlock();
                            self.drainOutgoing(io, allocator);
                        },
                        // Long-header packets on an accepted connection:
                        // Initial-space CRYPTO continuations (ClientHello
                        // spanning several Initials, e.g. post-quantum key
                        // shares) and Handshake-space packets. Send the
                        // drained Initial/Handshake responses.
                        .long => |long_result| {
                            switch (long_result) {
                                .packet => |pkt| switch (pkt) {
                                    .initial => |ip| {
                                        for (initial_out[0..ip.initial.backend.backend.drain.datagrams_written]) |o| {
                                            self.socket.send(io, &dest, o.datagram) catch |e| log.err("drive: send long initial response: {}", .{e});
                                            allocator.free(o.datagram);
                                        }
                                        if (ip.handshake) |hs| {
                                            for (handshake_out[0..hs.backend.drain.datagrams_written]) |o| {
                                                self.socket.send(io, &dest, o.datagram) catch |e| log.err("drive: send long handshake response: {}", .{e});
                                                allocator.free(o.datagram);
                                            }
                                        }
                                    },
                                    .handshake => |hs| {
                                        for (handshake_out[0..hs.backend.backend.drain.datagrams_written]) |o| {
                                            self.socket.send(io, &dest, o.datagram) catch |e| log.err("drive: send routed handshake response: {}", .{e});
                                            allocator.free(o.datagram);
                                        }
                                    },
                                },
                                .coalesced_initial_handshake => |ch| {
                                    for (handshake_out[0..ch.backend.backend.drain.datagrams_written]) |o| {
                                        self.socket.send(io, &dest, o.datagram) catch |e| log.err("drive: send coalesced response: {}", .{e});
                                        allocator.free(o.datagram);
                                    }
                                },
                            }
                            self.drainOutgoing(io, allocator);
                        },
                    },
                    else => {},
                }
                for (pending_out[0..step.pending_drain.datagrams_written]) |o| {
                    self.socket.send(io, &dest, o.datagram) catch {};
                    allocator.free(o.datagram);
                }
            },
            else => {},
        }
    }

    /// Service lifecycle deadlines that came due and send the datagrams they
    /// produce (PTO retransmits, closing/draining packets). Bounded per pass;
    /// remaining work is picked up on the next drive iteration.
    fn serviceDueDeadlines(self: *Server, io: std.Io, allocator: std.mem.Allocator) void {
        var passes: usize = 0;
        while (passes < 8) : (passes += 1) {
            var out: [16]ServerEndpoint.DatagramPathResult = undefined;
            const due = self.server_ep.processDueDeadlineAndDrainDatagramsWithRoutePathWithScratch(self.nowNanos(), &out) catch |e| {
                log.debug("drive: due deadline processing: {}", .{e});
                return;
            };
            const result = due orelse return;
            for (out[0..result.drain.datagrams_written]) |o| {
                var dest = std.Io.net.IpAddress{ .ip4 = .{ .bytes = o.path.remote.octets, .port = o.path.remote.port } };
                self.socket.send(io, &dest, o.datagram) catch {};
                allocator.free(o.datagram);
            }
        }
    }

    /// Whether a handler-queued send or a recv-task datagram still waits for
    /// the drive task. Checked after the park snapshot to close the window
    /// between draining and the snapshot (see drive()).
    fn hasPendingWork(self: *Server) bool {
        while (!self.queue_mutex.tryLock()) std.atomic.spinLoopHint();
        const datagrams_queued = self.datagram_read_offset < self.datagram_queue.items.len;
        self.queue_mutex.unlock();
        if (datagrams_queued) return true;
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        var send_pending = false;
        var it = self.conns.valueIterator();
        while (it.next()) |csp| {
            if (csp.*.send_pending) {
                send_pending = true;
                break;
            }
        }
        self.mutex.unlock();
        return send_pending;
    }

    /// The connection driving task body: drain sends, process queued
    /// datagrams, service due deadlines, then park on the wakeup futex until
    /// the next event or lifecycle deadline.
    pub fn drive(self: *Server) std.Io.Cancelable!void {
        const allocator = self.allocator;
        const io = self.io;
        while (!@atomicLoad(bool, &self.stopping, .acquire)) {
            self.drainOutgoing(io, allocator);
            self.drainQueuedDatagrams(io, allocator);
            self.serviceDueDeadlines(io, allocator);
            // Park until a datagram arrives, a handler queues a send, stop()
            // runs, or the next lifecycle deadline comes due. The snapshot is
            // taken after draining, pairing with notifyDrive's bump: a
            // notifier that already ran changed wake_id, so the wait returns
            // immediately (std.Build.WebServer futexWaitTimeout pattern).
            const snapshot = self.wake_id.load(.acquire);
            // Re-check stopping after the snapshot: a stop() that ran before
            // the snapshot already bumped wake_id (and its futexWake may have
            // had no waiter yet), and one that runs after the snapshot
            // changes wake_id so the compare cannot match. Without this
            // check the drive could park forever past a stop request.
            if (@atomicLoad(bool, &self.stopping, .acquire)) break;
            // Re-check for work parked between this iteration's draining and
            // the snapshot: its notifyDrive bump is already captured by the
            // snapshot, so the park below would hold the work until the park
            // timeout (up to the idle deadline). Work arriving after this
            // check bumps wake_id past the snapshot, so the park still
            // returns immediately.
            if (self.hasPendingWork()) continue;
            const timeout: std.Io.Timeout = timeout: {
                const deadline = self.server_ep.nextDeadlineWithScratch() catch break :timeout .none;
                const d = deadline orelse break :timeout .none;
                break :timeout .{ .deadline = .{ .raw = .{ .nanoseconds = d.deadline_nanos }, .clock = .awake } };
            };
            io.futexWaitTimeout(u32, &self.wake_id.raw, snapshot, timeout) catch return;
        }
    }

    /// Accept the next new connection (polls with std.time.sleep).
    pub fn accept(self: *Server) !ServerConnection {
        while (true) {
            if (@atomicLoad(bool, &self.stopping, .acquire)) return error.Canceled;
            while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
            if (self.pending_accept.items.len > 0) {
                const id = self.pending_accept.orderedRemove(0);
                self.mutex.unlock();
                return .{ .server = self, .id = id };
            }
            self.mutex.unlock();
            self.accept_sem.wait(self.io) catch return error.Canceled;
        }
    }

    /// Accept the next stream with pending data on a connection.
    pub fn acceptStreamId(self: *Server, conn_id: u64) !u64 {
        while (true) {
            if (@atomicLoad(bool, &self.stopping, .acquire)) return error.Canceled;
            while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
            const cs = self.conns.get(conn_id) orelse {
                self.mutex.unlock();
                return error.NoConnection;
            };
            while (!cs.mutex.tryLock()) std.atomic.spinLoopHint();
            if (cs.pending_streams.items.len > 0) {
                const sid = cs.pending_streams.orderedRemove(0);
                cs.mutex.unlock();
                self.mutex.unlock();
                return sid;
            }
            if (@atomicLoad(bool, &cs.closing_or_closed, .acquire)) {
                cs.mutex.unlock();
                self.mutex.unlock();
                return error.ConnectionClosed;
            }
            cs.mutex.unlock();
            self.mutex.unlock();
            cs.data_sem.wait(self.io) catch return error.Canceled;
        }
    }

    /// Receive stream data for one stream (polls its per-stream queue).
    pub fn receiveStreamData(self: *Server, conn_id: u64, sid: u64, buf: []u8) !usize {
        while (true) {
            if (@atomicLoad(bool, &self.stopping, .acquire)) return error.Canceled;
            while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
            const cs = self.conns.get(conn_id) orelse {
                self.mutex.unlock();
                return error.NoConnection;
            };
            while (!cs.mutex.tryLock()) std.atomic.spinLoopHint();
            for (cs.recv_streams.items) |*s| {
                if (s.id != sid) continue;
                const available = s.queue.items[s.read_offset..];
                if (available.len > 0) {
                    const n = @min(buf.len, available.len);
                    @memcpy(buf[0..n], available[0..n]);
                    s.read_offset += n;
                    if (s.read_offset == s.queue.items.len) {
                        s.queue.clearRetainingCapacity();
                        s.read_offset = 0;
                    }
                    cs.mutex.unlock();
                    self.mutex.unlock();
                    return n;
                }
                if (s.eof) {
                    cs.mutex.unlock();
                    self.mutex.unlock();
                    return 0;
                }
                break;
            }
            // No data and no FIN: a closing/closed connection will never
            // deliver more on this stream.
            if (@atomicLoad(bool, &cs.closing_or_closed, .acquire)) {
                cs.mutex.unlock();
                self.mutex.unlock();
                return error.ConnectionClosed;
            }
            cs.mutex.unlock();
            self.mutex.unlock();
            cs.data_sem.wait(self.io) catch return error.Canceled;
        }
    }

    /// Non-blocking accept: pops one queued stream id, or returns `null` when
    /// none is pending. The HTTP/3 driver drains this queue so per-stream
    /// registrations do not accumulate, then parks on `waitStreamActivity`.
    pub fn tryAcceptStreamId(self: *Server, conn_id: u64) !?u64 {
        if (@atomicLoad(bool, &self.stopping, .acquire)) return error.Canceled;
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        const cs = self.conns.get(conn_id) orelse {
            self.mutex.unlock();
            return error.NoConnection;
        };
        while (!cs.mutex.tryLock()) std.atomic.spinLoopHint();
        if (cs.pending_streams.items.len > 0) {
            const sid = cs.pending_streams.orderedRemove(0);
            cs.mutex.unlock();
            self.mutex.unlock();
            return sid;
        }
        if (@atomicLoad(bool, &cs.closing_or_closed, .acquire)) {
            cs.mutex.unlock();
            self.mutex.unlock();
            return error.ConnectionClosed;
        }
        cs.mutex.unlock();
        self.mutex.unlock();
        return null;
    }

    /// Non-blocking receive for one stream. Returns `null` when the stream has
    /// no data right now, `0` at EOF, otherwise the number of bytes copied.
    /// Unlike `receiveStreamData` this never parks, so a caller that drives
    /// several streams (e.g. the HTTP/3 layer) can interleave them and park
    /// once on `waitStreamActivity`.
    pub fn tryReceiveStreamData(self: *Server, conn_id: u64, sid: u64, buf: []u8) !?usize {
        if (@atomicLoad(bool, &self.stopping, .acquire)) return error.Canceled;
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        const cs = self.conns.get(conn_id) orelse {
            self.mutex.unlock();
            return error.NoConnection;
        };
        while (!cs.mutex.tryLock()) std.atomic.spinLoopHint();
        var result: ?usize = null;
        for (cs.recv_streams.items) |*s| {
            if (s.id != sid) continue;
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
        cs.mutex.unlock();
        self.mutex.unlock();
        return result;
    }

    /// Snapshot the stream ids currently receiving data on a connection into
    /// `out`; returns the count written. Used by drivers that need to poll
    /// every active stream (HTTP/3 control / QPACK / request streams).
    pub fn connStreamIds(self: *Server, conn_id: u64, out: []u64) usize {
        var count: usize = 0;
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        const cs = self.conns.get(conn_id) orelse {
            self.mutex.unlock();
            return 0;
        };
        while (!cs.mutex.tryLock()) std.atomic.spinLoopHint();
        for (cs.recv_streams.items) |*s| {
            if (count >= out.len) break;
            out[count] = s.id;
            count += 1;
        }
        cs.mutex.unlock();
        self.mutex.unlock();
        return count;
    }

    /// Park until any stream on a connection has new data / EOF, a new stream
    /// arrives, or the connection closes. The HTTP/3 driver uses this between
    /// non-blocking drains instead of blocking on one stream.
    pub fn waitStreamActivity(self: *Server, conn_id: u64) !void {
        while (true) {
            if (@atomicLoad(bool, &self.stopping, .acquire)) return error.Canceled;
            while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
            const cs = self.conns.get(conn_id) orelse {
                self.mutex.unlock();
                return error.NoConnection;
            };
            while (!cs.mutex.tryLock()) std.atomic.spinLoopHint();
            var has_activity = false;
            for (cs.recv_streams.items) |*s| {
                if (s.queue.items.len > s.read_offset or s.eof) {
                    has_activity = true;
                    break;
                }
            }
            if (cs.pending_streams.items.len > 0) has_activity = true;
            if (has_activity) {
                cs.mutex.unlock();
                self.mutex.unlock();
                return;
            }
            if (@atomicLoad(bool, &cs.closing_or_closed, .acquire)) {
                cs.mutex.unlock();
                self.mutex.unlock();
                return error.ConnectionClosed;
            }
            cs.mutex.unlock();
            self.mutex.unlock();
            cs.data_sem.wait(self.io) catch return error.Canceled;
        }
    }

    /// Queue stream data to send (drive task drains and sends).
    pub fn sendStreamData(self: *Server, conn_id: u64, stream_id: u64, data: []const u8, fin: bool) !void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        const cs = self.conns.get(conn_id) orelse {
            self.mutex.unlock();
            return error.NoConnection;
        };
        while (!cs.mutex.tryLock()) std.atomic.spinLoopHint();
        var idx: ?usize = null;
        for (cs.send_streams.items, 0..) |s, i| {
            if (s.id == stream_id) {
                idx = i;
                break;
            }
        }
        if (idx == null) {
            cs.send_streams.append(self.allocator, .{ .id = stream_id }) catch {};
            idx = cs.send_streams.items.len - 1;
        }
        cs.send_streams.items[idx.?].queue.appendSlice(self.allocator, data) catch {};
        if (fin) cs.send_streams.items[idx.?].fin = true;
        const notify = !cs.send_pending;
        cs.send_pending = true;
        cs.mutex.unlock();
        self.mutex.unlock();
        if (notify) self.notifyDrive(self.io);
    }

    /// Queue a STOP_SENDING (RFC 9000 §3.5) for one stream; the drive task
    /// sends it to the peer. Blocks the handler until the drive task drains it.
    pub fn stopSendingRequest(self: *Server, conn_id: u64, stream_id: u64, code: u64) !void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        const cs = self.conns.get(conn_id) orelse {
            self.mutex.unlock();
            return error.NoConnection;
        };
        while (!cs.mutex.tryLock()) std.atomic.spinLoopHint();
        cs.stop_sendings.append(self.allocator, .{ .id = stream_id, .code = code }) catch {};
        const notify = !cs.send_pending;
        cs.send_pending = true;
        cs.mutex.unlock();
        self.mutex.unlock();
        if (notify) self.notifyDrive(self.io);
    }

    /// Open a server-initiated unidirectional stream. The drive task performs
    /// the actual open (the transport is single-threaded) and posts a result;
    /// this blocks the handler until the stream id is known.
    pub fn openUniStreamRequest(self: *Server, conn_id: u64) !u64 {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        const cs = self.conns.get(conn_id) orelse {
            self.mutex.unlock();
            return error.NoConnection;
        };
        while (!cs.mutex.tryLock()) std.atomic.spinLoopHint();
        cs.uni_open_requested = true;
        const notify = !cs.send_pending;
        cs.send_pending = true;
        cs.mutex.unlock();
        self.mutex.unlock();
        if (notify) self.notifyDrive(self.io);
        cs.uni_open_sem.wait(self.io) catch return error.Canceled;
        return cs.next_uni_stream;
    }
};

/// Per-connection handler callback (std.http model): serves one
/// connection; `error.Canceled` terminates it during shutdown.
pub const HandlerFn = *const fn (ServerConnection) std.Io.Cancelable!void;

/// A server-side connection handle.
pub const ServerConnection = struct {
    server: *Server,
    id: u64,

    pub fn acceptStream(self: *ServerConnection) !Stream {
        const sid = try self.server.acceptStreamId(self.id);
        return .{ .server = self.server, .conn_id = self.id, .id = sid };
    }

    /// Open a server-initiated unidirectional stream (RFC 9000 §2.1).
    pub fn openUniStream(self: *ServerConnection) !Stream {
        const sid = try self.server.openUniStreamRequest(self.id);
        return .{ .server = self.server, .conn_id = self.id, .id = sid };
    }
};

/// A stream handle on a server connection (bidirectional or unidirectional;
/// local or peer-initiated). `acceptStream` may return a peer (client)
/// unidirectional stream; `openUniStream` creates a server one.
pub const Stream = struct {
    server: *Server,
    conn_id: u64,
    id: u64,

    /// True for a unidirectional stream (RFC 9000 §2.1 bit 1 set).
    pub fn isUni(self: Stream) bool {
        return (self.id & 2) != 0;
    }
    /// True if the client initiated the stream (RFC 9000 §2.1 bit 0 clear).
    pub fn isClientInitiated(self: Stream) bool {
        return (self.id & 1) == 0;
    }

    /// Read queued stream bytes. Returns 0 at EOF: the peer FIN arrived
    /// and every stream byte was already consumed.
    pub fn receive(self: *Stream, buf: []u8) !usize {
        return self.server.receiveStreamData(self.conn_id, self.id, buf);
    }
    pub fn send(self: *Stream, data: []const u8, fin: bool) !void {
        return self.server.sendStreamData(self.conn_id, self.id, data, fin);
    }
    /// Ask the peer to STOP_SENDING this stream with `code` (RFC 9000 §3.5).
    pub fn stopSending(self: *Stream, code: u64) !void {
        return self.server.stopSendingRequest(self.conn_id, self.id, code);
    }
};
