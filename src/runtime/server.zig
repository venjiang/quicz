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
const StunBinding = @import("stun_binding.zig").Binding;

const log = std.log.scoped(.quicz_runtime);

fn registerValidatedHandoff(coordinator: *quicz.connectivity.shared_punch_coordinator.SharedPunchCoordinator, remote: std.Io.net.IpAddress, attempt_id: quicz.connectivity.punch_wire.AttemptId) !void {
    const wire = quicz.connectivity.punch_wire;
    const key: wire.Key = @splat(0x42);
    const local_nonce: wire.Nonce = @splat(0xa1);
    try coordinator.register(remote, try .init(key, attempt_id, local_nonce, .{}), 0);
    try std.testing.expect(std.meta.activeTag(coordinator.next(0)) == .probe);
    const probe = wire.encode(key, .{ .kind = .probe, .attempt_id = attempt_id, .nonce = @splat(0xb1) });
    try std.testing.expect(std.meta.activeTag(coordinator.receive(remote, 1, &probe)) == .acknowledgement);
    const acknowledgement = wire.encode(key, .{ .kind = .acknowledgement, .attempt_id = attempt_id, .nonce = local_nonce });
    try std.testing.expectEqual(quicz.connectivity.shared_punch_coordinator.Event{ .validated = attempt_id }, coordinator.receive(remote, 2, &acknowledgement));
}

fn checkPunchHandoffGate(comptime Runtime: type) !void {
    const io = std.testing.io;
    const remote: std.Io.net.IpAddress = if (Runtime == Server) .{ .ip4 = .loopback(4444) } else .{ .ip6 = .loopback(4444) };
    var coordinator = try quicz.connectivity.shared_punch_coordinator.SharedPunchCoordinator.init(std.testing.allocator, 1);
    defer coordinator.deinit();
    var responders = try quicz.connectivity.punch_responder.PunchResponderRegistry.init(std.testing.allocator, 1);
    defer responders.deinit();
    var gate: std.atomic.Mutex = .unlocked;
    var server = try Runtime.init(std.testing.allocator, io, .{
        .port = 0,
        .alpn = &.{},
        .cert_der = &.{},
        .private_key = &.{},
        .max_connections = 1,
        .shared_punch_coordinator = &coordinator,
        .punch_responder_registry = &responders,
    });
    defer server.deinit();
    try server.attachPunchHandoffMutex(&gate);
    try std.testing.expectError(error.PunchHandoffMutexAlreadyAttached, server.attachPunchHandoffMutex(&gate));
    const first_id: quicz.connectivity.punch_wire.AttemptId = @splat(0x11);
    try registerValidatedHandoff(&coordinator, remote, first_id);
    const Worker = struct {
        server: *Runtime,
        entered: std.Io.Event = .unset,
        finished: std.Io.Event = .unset,
        fn run(self: *@This()) void {
            self.entered.set(std.testing.io);
            self.server.retainSharedResponder(@splat(0x11));
            self.finished.set(std.testing.io);
        }
    };
    var worker: Worker = .{ .server = &server };
    while (!gate.tryLock()) std.atomic.spinLoopHint();
    var gate_held = true;
    defer if (gate_held) gate.unlock();
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer {
        if (gate_held) {
            gate.unlock();
            gate_held = false;
        }
        if (!joined) thread.join();
    }
    try worker.entered.wait(io);
    const crossed_gate = if (worker.finished.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(100) } }))
        true
    else |err| switch (err) {
        error.Timeout => false,
        else => return err,
    };
    const cleanup_removed_attempt = coordinator.remove(first_id);
    const cleanup_removed_responder = responders.remove(first_id);
    gate.unlock();
    gate_held = false;
    thread.join();
    joined = true;
    std.debug.print("handoff gate: ipv6={} crossed={} cleanup_attempt={} cleanup_responder={}\n", .{ Runtime == IPv6Server, crossed_gate, cleanup_removed_attempt, cleanup_removed_responder });
    try std.testing.expect(!crossed_gate);
    try std.testing.expect(cleanup_removed_attempt);
    try std.testing.expect(!cleanup_removed_responder);
    try std.testing.expectEqual(@as(u32, 0), responders.responders.count());

    // The opposite ordering installs a responder before cleanup removes it.
    // Repeating at capacity one proves that neither registry retains a slot.
    for ([_]u8{ 0x22, 0x33 }) |tag| {
        const attempt_id: quicz.connectivity.punch_wire.AttemptId = @splat(tag);
        try registerValidatedHandoff(&coordinator, remote, attempt_id);
        server.retainSharedResponder(attempt_id);
        while (!gate.tryLock()) std.atomic.spinLoopHint();
        const attempt_removed = coordinator.remove(attempt_id);
        const responder_removed = responders.remove(attempt_id);
        gate.unlock();
        try std.testing.expect(!attempt_removed);
        try std.testing.expect(responder_removed);
        try std.testing.expectEqual(@as(u32, 0), responders.responders.count());
    }
    try server.start();
    try std.testing.expectError(error.ServerAlreadyStarted, server.attachPunchHandoffMutex(&gate));
}

test "IPv4 responder handoff cannot cross owner cleanup gate" {
    try checkPunchHandoffGate(Server);
}

test "IPv6 responder handoff cannot cross owner cleanup gate" {
    try checkPunchHandoffGate(IPv6Server);
}

test "IPv6 runtime accepts a socket handoff while the legacy runtime retains its family guard" {
    const pem = @embedFile("../quic/testdata/quicz-echo-ca.pem");
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    const encoded_start = (std.mem.indexOf(u8, pem, begin_marker) orelse return error.TestUnexpectedResult) + begin_marker.len;
    const encoded_end = std.mem.indexOfPos(u8, pem, encoded_start, end_marker) orelse return error.TestUnexpectedResult;
    const encoded = std.mem.trim(u8, pem[encoded_start..encoded_end], " \t\r\n");
    var cert_der: [512]u8 = undefined;
    const cert_len = try std.base64.standard.decoderWithIgnore("\r\n").decode(&cert_der, encoded);
    // Match the existing mutual-TLS loopback certificate and P-256 identity.
    const private_key = [_]u8{
        0x5b, 0xbf, 0x4f, 0x5a, 0x48, 0x42, 0x9f, 0x00,
        0x5a, 0x57, 0x09, 0xc3, 0xb4, 0xc1, 0x3a, 0x64,
        0x2e, 0xb1, 0x61, 0xf5, 0x0b, 0xde, 0x64, 0x4b,
        0x3a, 0x38, 0xa6, 0x8f, 0xfa, 0x48, 0xda, 0x51,
    };

    const io = std.testing.io;
    const address = std.Io.net.IpAddress{ .ip6 = .loopback(0) };
    const socket = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    try std.testing.expectError(error.UnsupportedServerSocketFamily, Server.initWithSocket(std.testing.allocator, io, socket, .{
        .port = socket.address.getPort(),
        .alpn = &.{"hq-interop"},
        .cert_der = cert_der[0..cert_len],
        .private_key = &private_key,
        .max_connections = 1,
    }));
    var server = IPv6Server.initWithSocket(std.testing.allocator, io, socket, .{
        .port = socket.address.getPort(),
        .alpn = &.{"hq-interop"},
        .cert_der = cert_der[0..cert_len],
        .private_key = &private_key,
        .max_connections = 1,
    }) catch |err| {
        socket.close(io);
        return err;
    };
    defer server.deinit();

    try std.testing.expect(std.meta.activeTag(server.socket.address) == .ip6);
    try std.testing.expectEqualSlices(u8, &address.ip6.bytes, &server.socket.address.ip6.bytes);
    try std.testing.expectEqual(socket.address.getPort(), server.localPort());
}

test "running server refreshes STUN through its single UDP receiver" {
    const io = std.testing.io;
    const local = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var stun_socket = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer stun_socket.close(io);
    var server = try Server.init(std.testing.allocator, io, .{
        .port = 0,
        .alpn = &.{},
        .cert_der = &.{},
        .private_key = &.{},
        .max_connections = 1,
    });
    defer server.deinit();
    try server.start();
    const bound_port = server.localPort();
    const Responder = struct {
        fn run(socket: *std.Io.net.Socket, expected_port: u16) !void {
            var old_response: ?[32]u8 = null;
            for ([_]u16{ 41001, 41002 }) |mapped_port| {
                var bytes: [64]u8 = undefined;
                const received = try socket.receiveTimeout(std.testing.io, &bytes, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
                try std.testing.expectEqual(expected_port, received.from.getPort());
                const id = try quicz.connectivity.stun.decodeBindingRequest(received.data);
                var target = received.from;
                if (old_response) |old| try socket.send(std.testing.io, &target, &old);
                const response = quicz.connectivity.stun.encodeBindingSuccessIpv4(id, .{ 192, 0, 2, 1 }, mapped_port);
                try socket.send(std.testing.io, &target, &response);
                old_response = response;
            }
        }
    };
    var responder = try io.concurrent(Responder.run, .{ &stun_socket, bound_port });
    defer responder.cancel(io) catch {};
    for ([_]u16{ 41001, 41002 }) |expected_port| {
        const mapped = try server.discoverReflexiveAddress(stun_socket.address, .{ .timeout_ms = 100, .max_attempts = 1 });
        try std.testing.expectEqual(expected_port, mapped.ipv4.port);
        try std.testing.expectEqual(bound_port, server.localPort());
    }
    try responder.await(io);
}

test "running server STUN cancellation preserves socket and rejects foreign responses" {
    const io = std.testing.io;
    const local = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var stun_socket = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer stun_socket.close(io);
    const foreign = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer foreign.close(io);
    var server = try Server.init(std.testing.allocator, io, .{
        .port = 0,
        .alpn = &.{},
        .cert_der = &.{},
        .private_key = &.{},
        .max_connections = 1,
    });
    defer server.deinit();
    try server.start();
    const port = server.localPort();
    var first = try io.concurrent(Server.discoverReflexiveAddress, .{ &server, stun_socket.address, quicz.connectivity.stun_transaction.Config{ .timeout_ms = 500, .max_attempts = 1 } });
    defer _ = first.cancel(io) catch {};
    var bytes: [64]u8 = undefined;
    const received = try stun_socket.receiveTimeout(io, &bytes, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    const old_id = try quicz.connectivity.stun.decodeBindingRequest(received.data);
    try std.testing.expectError(error.Canceled, first.cancel(io));
    var second = try io.concurrent(Server.discoverReflexiveAddress, .{ &server, stun_socket.address, quicz.connectivity.stun_transaction.Config{ .timeout_ms = 100, .max_attempts = 1 } });
    defer _ = second.cancel(io) catch {};
    const next = try stun_socket.receiveTimeout(io, &bytes, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    const id = try quicz.connectivity.stun.decodeBindingRequest(next.data);
    var target = next.from;
    try std.testing.expectEqual(port, target.getPort());
    const wrong = quicz.connectivity.stun.encodeBindingSuccessIpv4(old_id, .{ 192, 0, 2, 1 }, 41001);
    try stun_socket.send(io, &target, &wrong);
    const forged = quicz.connectivity.stun.encodeBindingSuccessIpv4(id, .{ 192, 0, 2, 1 }, 41002);
    try foreign.send(io, &target, &forged);
    try std.testing.expectError(error.StunUnavailable, second.await(io));
    var third = try io.concurrent(Server.discoverReflexiveAddress, .{ &server, stun_socket.address, quicz.connectivity.stun_transaction.Config{ .timeout_ms = 100, .max_attempts = 1 } });
    defer _ = third.cancel(io) catch {};
    const last = try stun_socket.receiveTimeout(io, &bytes, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    const last_id = try quicz.connectivity.stun.decodeBindingRequest(last.data);
    const response = quicz.connectivity.stun.encodeBindingSuccessIpv4(last_id, .{ 192, 0, 2, 1 }, 41003);
    try stun_socket.send(io, &target, &response);
    try std.testing.expectEqual(@as(u16, 41003), (try third.await(io)).ipv4.port);
}

test "server runtime answers an authenticated probe after socket handoff" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var peer = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer peer.close(io);
    const key: quicz.connectivity.punch_wire.Key = .{0x42} ** 32;
    const attempt_id: quicz.connectivity.punch_wire.AttemptId = .{0x11} ** 16;
    const responder = try quicz.connectivity.punch_responder.PunchResponder.init(
        key,
        attempt_id,
        .{0xb2} ** 16,
        peer.address,
        @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds),
        500,
    );
    var server = try Server.init(std.testing.allocator, io, .{
        .port = 0,
        .alpn = &.{},
        .cert_der = &.{},
        .private_key = &.{},
        .max_connections = 1,
        .punch_responder = responder,
    });
    defer server.deinit();
    const probe = quicz.connectivity.punch_wire.encode(key, .{
        .kind = .probe,
        .attempt_id = attempt_id,
        .nonce = .{0xa1} ** 16,
    });
    const delayed_ack = quicz.connectivity.punch_wire.encode(key, .{
        .kind = .acknowledgement,
        .attempt_id = attempt_id,
        .nonce = .{0xb2} ** 16,
    });
    try server.start();
    try peer.send(io, &server.socket.address, &delayed_ack);
    try peer.send(io, &server.socket.address, &probe);
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

test "server runtime isolates authenticated probes for concurrent attempts" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var first_peer = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer first_peer.close(io);
    var second_peer = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer second_peer.close(io);
    var responders = try quicz.connectivity.punch_responder.PunchResponderRegistry.init(std.testing.allocator, 2);
    defer responders.deinit();
    const now: i64 = @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds);
    try responders.register(try .init(.{0x41} ** 32, .{0x11} ** 16, .{0xa1} ** 16, first_peer.address, now, 5_000));
    try responders.register(try .init(.{0x42} ** 32, .{0x22} ** 16, .{0xa2} ** 16, second_peer.address, now, 5_000));
    var server = try Server.init(std.testing.allocator, io, .{
        .port = 0,
        .alpn = &.{},
        .cert_der = &.{},
        .private_key = &.{},
        .max_connections = 2,
        .punch_responder_registry = &responders,
    });
    defer server.deinit();
    try server.start();
    const first_probe = quicz.connectivity.punch_wire.encode(.{0x41} ** 32, .{
        .kind = .probe,
        .attempt_id = .{0x11} ** 16,
        .nonce = .{0xb1} ** 16,
    });
    const second_probe = quicz.connectivity.punch_wire.encode(.{0x42} ** 32, .{
        .kind = .probe,
        .attempt_id = .{0x22} ** 16,
        .nonce = .{0xb2} ** 16,
    });
    try first_peer.send(io, &server.socket.address, &first_probe);
    try second_peer.send(io, &server.socket.address, &second_probe);
    var first_buffer: [128]u8 = undefined;
    var second_buffer: [128]u8 = undefined;
    const first_ack = try first_peer.receiveTimeout(io, &first_buffer, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(500) } });
    const second_ack = try second_peer.receiveTimeout(io, &second_buffer, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(500) } });
    const first_message = try quicz.connectivity.punch_wire.decode(.{0x41} ** 32, first_ack.data);
    const second_message = try quicz.connectivity.punch_wire.decode(.{0x42} ** 32, second_ack.data);
    try std.testing.expectEqual(@as([16]u8, @splat(0x11)), first_message.attempt_id);
    try std.testing.expectEqual(@as([16]u8, @splat(0x22)), second_message.attempt_id);
    try std.testing.expect(responders.remove(.{0x11} ** 16));
    try first_peer.send(io, &server.socket.address, &first_probe);
    try std.testing.expectError(error.Timeout, first_peer.receiveTimeout(io, &first_buffer, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(100) } }));
}

const Connection = quicz.Connection;
const Tls13ServerTransport = quicz.Tls13ServerTransport;
const endpoint = quicz.endpoint;
const quic_packet = quicz.packet;
/// Aggregate capacity that multiple address-family listeners can borrow.
pub const ConnectionAdmission = @import("connection_admission.zig").ConnectionAdmission;

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
/// One accepted connection routes the client's original destination CID, the
/// server CID, and bounded replacement CIDs used during rotation/migration.
const route_slots_per_connection: usize = 4;

const ServerRecord = struct {
    handle: u64,
    transport: Tls13ServerTransport,
    retry_validated: bool = false,
    admission: ?*ConnectionAdmission = null,

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
        if (self.admission) |admission| admission.release();
    }
};

fn ServerEndpointForTuple(comptime Path: type) type {
    return @import("../quic/tls13_server_endpoint.zig").Tls13ServerEndpointForTuple(
        Path,
        ServerRecord,
        ServerRecord.connectionRef,
        ServerRecord.cryptoBackend,
        ServerRecord.destinationConnectionId,
        ServerRecord.sourceConnectionId,
        ServerRecord.initialDestinationConnectionId,
        ServerRecord.markRetryValidated,
        ServerRecord.deinit,
    );
}

/// Datagram received by the recv task, waiting for the drive task.
const queued_datagram_pool_size = 16;
/// Return to deadlines and connection-state publication after this many inputs.
const receive_batch_size = 64;

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
    /// Set by a handler; the drive task alone changes the QUIC connection.
    close_requested: bool = false,
    close_error_code: u64 = 0,
    /// Published by the drive task after its final endpoint operation. Endpoint
    /// retirement can destroy the borrowed connection before this runtime state;
    /// handlers therefore observe closure through this cache alone.
    closing_or_closed: bool = false,
    /// Set while this connection has queued send data the drive task has
    /// not flushed yet; used to coalesce drive wakeups in sendStreamData.
    send_pending: bool = false,
    send_flush_id: std.atomic.Value(u32) = .init(0),

    fn deinit(self: *ConnState, alloc: std.mem.Allocator) void {
        for (self.recv_streams.items) |*s| s.queue.deinit(alloc);
        self.recv_streams.deinit(alloc);
        self.pending_streams.deinit(alloc);
        for (self.send_streams.items) |*s| s.queue.deinit(alloc);
        self.send_streams.deinit(alloc);
        self.stop_sendings.deinit(alloc);
    }
};

test "connection drain releases every concurrent stream flush" {
    const FlushWaiters = struct {
        var waiting: std.atomic.Value(u32) = .init(0);
        var completed: std.atomic.Value(u32) = .init(0);
        var underlying_wait: @FieldType(std.Io.VTable, "futexWait") = undefined;

        fn wait(context: ?*anyopaque, ptr: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
            _ = waiting.fetchAdd(1, .release);
            return underlying_wait(context, ptr, expected, timeout);
        }

        fn flush(stream: Stream) std.Io.Cancelable!void {
            var mutable_stream = stream;
            mutable_stream.flush() catch return;
            _ = completed.fetchAdd(1, .release);
        }
    };
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var vtable = io.vtable.*;
    FlushWaiters.waiting.store(0, .monotonic);
    FlushWaiters.completed.store(0, .monotonic);
    FlushWaiters.underlying_wait = vtable.futexWait;
    vtable.futexWait = FlushWaiters.wait;
    var server = try Server.init(std.testing.allocator, .{ .userdata = io.userdata, .vtable = &vtable }, .{
        .port = 0,
        .alpn = &.{},
        .cert_der = &.{},
        .private_key = &.{},
        .max_connections = 1,
    });
    defer server.deinit();
    const record = try std.testing.allocator.create(ServerRecord);
    {
        errdefer std.testing.allocator.destroy(record);
        record.* = .{ .handle = 1, .transport = try Tls13ServerTransport.init(std.testing.allocator, .{}, .{}) };
        errdefer record.deinit();
        try server.server_ep.records.adopt(1, record);
    }
    const connection = try std.testing.allocator.create(ConnState);
    connection.* = .{ .handle = 1, .conn = record.connectionRef(), .peer = server.socket.address, .send_pending = true };
    {
        errdefer std.testing.allocator.destroy(connection);
        try server.conns.put(1, connection);
    }
    const stream_ids = [_]u64{ try connection.conn.openStream(), try connection.conn.openStream() };
    connection.conn.peer_max_data = 0;
    for (stream_ids) |stream_id| try server.sendStreamData(1, stream_id, "flush", true);

    var pending: std.Io.Group = .init;
    defer pending.cancel(io);
    for (stream_ids) |stream_id| {
        try pending.concurrent(io, FlushWaiters.flush, .{Stream{ .server = &server, .conn_id = 1, .id = stream_id }});
    }
    const started = std.Io.Timestamp.now(io, .awake);
    while (FlushWaiters.waiting.load(.acquire) < 2 and
        started.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds() < 500)
    {
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(@as(u32, 2), FlushWaiters.waiting.load(.acquire));
    // Let both registered calls park before emitting the sole drain event.
    try io.sleep(.fromMilliseconds(20), .awake);
    server.drainOutgoing(server.io, std.testing.allocator);
    try std.testing.expect(connection.send_pending);
    try std.testing.expectEqual(@as(u32, 0), connection.send_flush_id.load(.acquire));
    try std.testing.expectEqual(@as(u32, 0), FlushWaiters.completed.load(.acquire));
    // Restored connection credit lets the next drain consume both queues.
    connection.conn.peer_max_data = 1024;
    server.drainOutgoing(server.io, std.testing.allocator);
    const drained = std.Io.Timestamp.now(io, .awake);
    while (FlushWaiters.completed.load(.acquire) < 2 and
        drained.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds() < 300)
    {
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(@as(u32, 2), FlushWaiters.completed.load(.acquire));
    try pending.await(io);
    try std.testing.expect(!connection.send_pending);
    for (connection.send_streams.items) |stream| {
        try std.testing.expectEqual(@as(usize, 0), stream.queue.items.len);
        try std.testing.expect(!stream.fin);
    }
    try server.flushStreamData(1);
}

fn metricsSnapshotAfterEndpointRetirement(
    comptime Runtime: type,
    comptime retirement: enum { deadline_query, due_deadline },
) !void {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var server = try Runtime.init(allocator, io, .{
        .port = 0,
        .alpn = &.{},
        .cert_der = &.{},
        .private_key = &.{},
        .max_connections = 1,
    });
    defer server.deinit();
    const record = try allocator.create(ServerRecord);
    {
        errdefer allocator.destroy(record);
        record.* = .{ .handle = 1, .transport = try Tls13ServerTransport.init(allocator, .{}, .{}) };
        errdefer record.deinit();
        try server.server_ep.records.adopt(1, record);
    }
    const connection = try allocator.create(ConnState);
    connection.* = .{ .handle = 1, .conn = record.connectionRef(), .peer = server.socket.address };
    {
        errdefer allocator.destroy(connection);
        try server.conns.put(1, connection);
    }
    try connection.conn.validatePeerAddress();
    try connection.conn.confirmHandshake();
    const stream_id = try connection.conn.openStream();
    try server.sendStreamData(1, stream_id, "metrics", true);
    server.drainOutgoing(io, allocator);
    _ = try server.server_ep.nextDeadlineWithScratch();
    server.publishConnectionState();
    try std.testing.expectEqual(@as(usize, 1), server.metricsSnapshot().active_connections);
    try std.testing.expectEqual(@as(u64, 7), server.metricsSnapshot().stream_bytes_sent);

    try connection.conn.closeApplication(0, "");
    var scratch: [send_mtu]u8 = undefined;
    _ = (try connection.conn.pollTx(0, &scratch)) orelse return error.TestUnexpectedResult;
    const deadline = connection.conn.closeDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), server.server_ep.records.count());
    switch (retirement) {
        .deadline_query => {
            try std.testing.expectError(error.ConnectionClosed, connection.conn.pollTx(deadline, &scratch));
            try std.testing.expectEqual(.closed, connection.conn.connectionState());
            // The real deadline query destroys an already-closed owned record.
            _ = try server.server_ep.nextDeadlineWithScratch();
        },
        .due_deadline => {
            // The real due-deadline path closes and destroys its owned record.
            const due = (try server.server_ep.processDueDeadlineAndDrainDatagramsWithRoutePathWithScratch(deadline, &.{})) orelse
                return error.TestUnexpectedResult;
            try std.testing.expect(due.pending_work.close_retired != null);
            try std.testing.expectEqual(@as(usize, 0), due.drain.datagrams_written);
            _ = try server.server_ep.nextDeadlineWithScratch();
        },
    }
    try std.testing.expectEqual(@as(usize, 0), server.server_ep.records.count());
    try std.testing.expect(server.conns.get(1) == connection);
    try std.testing.expect(!connection.handler_done);
    try std.testing.expect(!connection.closing_or_closed);

    // No object is poisoned or reused. A snapshot must not dereference the
    // connection pointer after its actual endpoint-owned record was destroyed.
    // Values remain from the last publication until the drive publishes again.
    try std.testing.expectEqual(@as(usize, 1), server.metricsSnapshot().active_connections);
    connection.send_pending = true;
    server.publishConnectionState();
    const snapshot = server.metricsSnapshot();
    try std.testing.expectEqual(@as(usize, 0), snapshot.active_connections);
    try std.testing.expectEqual(@as(u64, 0), snapshot.stream_bytes_sent);
    try std.testing.expect(connection.closing_or_closed);
    try std.testing.expectEqual(@as(usize, 1), connection.data_sem.permits);
    try server.waitConnectionClosed(1);
    try connection.data_sem.wait(io);
    try std.testing.expectEqual(@as(usize, 0), connection.data_sem.permits);
    server.publishConnectionState();
    try std.testing.expectEqual(@as(usize, 0), connection.data_sem.permits);
    // Retired sends remain pending rather than claiming a successful flush,
    // but cannot keep the drive task spinning without executable work.
    try std.testing.expect(connection.send_pending);
    try std.testing.expect(!server.hasPendingWork());
    try std.testing.expect(server.conns.get(1) == connection);
    server.releaseConnection(1);
    try std.testing.expect(server.hasPendingWork());
    server.publishConnectionState();
    try std.testing.expectEqual(@as(usize, 0), server.conns.count());
    try std.testing.expect(!server.hasPendingWork());
}

test "metrics snapshot survives IPv6 endpoint record retirement before handler release" {
    try metricsSnapshotAfterEndpointRetirement(IPv6Server, .deadline_query);
}

test "metrics snapshot survives IPv4 endpoint record retirement before handler release" {
    try metricsSnapshotAfterEndpointRetirement(Server, .deadline_query);
}

test "metrics snapshot publishes IPv4 due-deadline closure before parking" {
    try metricsSnapshotAfterEndpointRetirement(Server, .due_deadline);
}

test "metrics snapshot publishes IPv6 due-deadline closure before parking" {
    try metricsSnapshotAfterEndpointRetirement(IPv6Server, .due_deadline);
}

test "metrics snapshot publication schedules every retired state beyond one reclaim batch" {
    inline for (.{ Server, IPv6Server }) |Runtime| {
        const allocator = std.testing.allocator;
        const io = std.testing.io;
        var server = try Runtime.init(allocator, io, .{
            .port = 0,
            .alpn = &.{},
            .cert_der = &.{},
            .private_key = &.{},
            .max_connections = 65,
        });
        defer server.deinit();
        for (0..65) |index| {
            const handle = index + 1;
            const record = try allocator.create(ServerRecord);
            {
                errdefer allocator.destroy(record);
                record.* = .{ .handle = handle, .transport = try Tls13ServerTransport.init(allocator, .{}, .{}) };
                errdefer record.deinit();
                const conn = record.connectionRef();
                try conn.validatePeerAddress();
                try conn.confirmHandshake();
                try conn.closeApplication(0, "");
                var scratch: [send_mtu]u8 = undefined;
                _ = (try conn.pollTx(0, &scratch)) orelse return error.TestUnexpectedResult;
                const deadline = conn.closeDeadline() orelse return error.TestUnexpectedResult;
                try std.testing.expectError(error.ConnectionClosed, conn.pollTx(deadline, &scratch));
                try server.server_ep.records.adopt(handle, record);
            }
            const connection = try allocator.create(ConnState);
            errdefer allocator.destroy(connection);
            connection.* = .{
                .handle = handle,
                .conn = record.connectionRef(),
                .peer = server.socket.address,
                .handler_done = true,
            };
            try server.conns.put(handle, connection);
        }
        _ = try server.server_ep.nextDeadlineWithScratch();
        try std.testing.expectEqual(@as(usize, 0), server.server_ep.records.count());
        server.publishConnectionState();
        try std.testing.expectEqual(@as(usize, 1), server.conns.count());
        try std.testing.expect(server.hasPendingWork());
        try std.testing.expectEqual(@as(usize, 0), server.metricsSnapshot().active_connections);
        server.publishConnectionState();
        try std.testing.expectEqual(@as(usize, 0), server.conns.count());
        try std.testing.expect(!server.hasPendingWork());
    }
}

fn metricsSnapshotDuringSustainedReceive(comptime Runtime: type) !void {
    const allocator = std.testing.allocator;
    const base_io = std.testing.io;
    const protection = quicz.protection;
    const Path = if (Runtime == Server) endpoint.Udp4Tuple else endpoint.Udp6Tuple;
    const Family = @import("udp_address.zig").ForTuple(Path);
    const peer_secret: [protection.traffic_secret_len]u8 = @splat(0x51);
    const local_secret: [protection.traffic_secret_len]u8 = @splat(0x52);
    const peer_bind: std.Io.net.IpAddress = if (Runtime == Server) .{ .ip4 = .loopback(0) } else .{ .ip6 = .loopback(0) };
    const closing_peer = try peer_bind.bind(base_io, .{ .mode = .dgram, .protocol = .udp });
    defer closing_peer.close(base_io);
    const busy_peer_socket = try peer_bind.bind(base_io, .{ .mode = .dgram, .protocol = .udp });
    defer busy_peer_socket.close(base_io);
    const Harness = struct {
        var active: ?*@This() = null;
        const maximum_packets = 4096;
        server: *Runtime,
        closing: *ConnState,
        peer: std.Io.net.IpAddress,
        destination_cid: [8]u8,
        underlying_now: @FieldType(std.Io.VTable, "now"),
        underlying_wait: @FieldType(std.Io.VTable, "futexWait"),
        produced: usize = 0,
        closure_observed_after: ?usize = null,
        received_close: bool = false,
        failure: ?anyerror = null,
        enabled: bool = false,
        in_now: bool = false,

        fn observe(self: *@This()) void {
            if (self.server.server_ep.records.get(1)) |record| {
                if (record.connectionRef().isClosingOrClosed()) self.received_close = true;
            }
            if (self.closing.closing_or_closed and self.closure_observed_after == null)
                self.closure_observed_after = self.produced;
        }

        fn enqueue(self: *@This()) !void {
            const packet_number = self.produced;
            // Every added packet has valid AEAD, a fresh packet number, and a
            // routed PING frame. This is sustained useful input, not a UDP flood.
            const datagram = try protection.protectShortPacketAes128(allocator, .{
                .dcid = &self.destination_cid,
                .spin_bit = false,
                .key_phase = false,
                .packet_number = packet_number,
            }, .{ .len = 4, .truncated_packet_number = @intCast(packet_number) }, protection.deriveAes128PacketProtectionKeys(peer_secret), &.{0x01});
            errdefer allocator.free(datagram);
            try self.server.datagram_queue.append(allocator, .{ .from = self.peer, .data = datagram });
            self.produced += 1;
        }

        fn now(context: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
            const self = active.?;
            if (self.enabled and !self.in_now) {
                self.in_now = true;
                defer self.in_now = false;
                self.observe();
                if (self.closure_observed_after == null and self.produced < maximum_packets)
                    self.enqueue() catch |err| {
                        self.failure = err;
                    };
            }
            return self.underlying_now(context, clock);
        }

        fn wait(context: ?*anyopaque, ptr: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
            const self = active.?;
            if (ptr == &self.server.wake_id.raw) {
                self.observe();
                return error.Canceled;
            }
            return self.underlying_wait(context, ptr, expected, timeout);
        }
    };
    var vtable = base_io.vtable.*;
    var server = try Runtime.init(allocator, .{ .userdata = base_io.userdata, .vtable = &vtable }, .{
        .port = 0,
        .alpn = &.{},
        .cert_der = &.{},
        .private_key = &.{},
        .max_connections = 2,
    });
    defer server.deinit();
    var closing: *ConnState = undefined;
    var busy_peer: std.Io.net.IpAddress = undefined;
    var busy_cid: [8]u8 = undefined;
    for (1..3) |handle| {
        const tag: u8 = @intCast(handle);
        const cid: [8]u8 = @splat(tag);
        const peer_cid: [8]u8 = @splat(tag + 0x10);
        const peer = if (handle == 1) closing_peer.address else busy_peer_socket.address;
        const record = try allocator.create(ServerRecord);
        {
            errdefer allocator.destroy(record);
            record.* = .{ .handle = handle, .transport = try Tls13ServerTransport.init(allocator, .{}, .{}) };
            errdefer record.deinit();
            try record.transport.setOriginalDestinationConnectionId(&cid);
            try record.transport.setLocalInitialSourceConnectionId(&cid);
            try record.transport.setPeerInitialSourceConnectionId(&peer_cid);
            try record.connectionRef().installOneRttTrafficSecrets(.{ .local = local_secret, .peer = peer_secret });
            try record.connectionRef().validatePeerAddress();
            try record.connectionRef().confirmHandshake();
            try server.server_ep.records.adopt(handle, record);
        }
        const path = Path{ .local = Family.fromIp(server.socket.address).?, .remote = Family.fromIp(peer).? };
        try server.server_ep.lifecycle.registerConnectionId(handle, &cid, path, .{});
        const state = try allocator.create(ConnState);
        state.* = .{ .handle = handle, .conn = record.connectionRef(), .peer = peer };
        {
            errdefer allocator.destroy(state);
            try server.conns.put(handle, state);
        }
        if (handle == 1) {
            closing = state;
            // A real protected APPLICATION_CLOSE, with no test-side mutation
            // of either the connection's close state or its published cache.
            const datagram = try protection.protectShortPacketAes128(allocator, .{
                .dcid = &cid,
                .spin_bit = false,
                .key_phase = false,
                .packet_number = 0,
            }, .{ .len = 4, .truncated_packet_number = 0 }, protection.deriveAes128PacketProtectionKeys(peer_secret), &.{ 0x1d, 0x00, 0x00 });
            errdefer allocator.free(datagram);
            try server.datagram_queue.append(allocator, .{ .from = peer, .data = datagram });
        } else {
            busy_peer = peer;
            busy_cid = cid;
        }
    }
    server.publishConnectionState();
    try std.testing.expectEqual(@as(usize, 2), server.metricsSnapshot().active_connections);
    var harness: Harness = .{
        .server = &server,
        .closing = closing,
        .peer = busy_peer,
        .destination_cid = busy_cid,
        .underlying_now = vtable.now,
        .underlying_wait = vtable.futexWait,
    };
    Harness.active = &harness;
    defer {
        vtable.now = harness.underlying_now;
        vtable.futexWait = harness.underlying_wait;
        Harness.active = null;
    }
    vtable.now = Harness.now;
    vtable.futexWait = Harness.wait;
    harness.enabled = true;
    try server.drive();
    harness.enabled = false;
    try std.testing.expectEqual(@as(?anyerror, null), harness.failure);
    try std.testing.expect(harness.received_close);
    const publication = harness.closure_observed_after orelse return error.TestUnexpectedResult;
    const busy = server.server_ep.records.get(2) orelse return error.TestUnexpectedResult;
    try std.testing.expect(harness.produced > 0);
    try std.testing.expectEqual(@as(u64, @intCast(harness.produced)), busy.connectionRef().next_peer_packet_number);
    // The cap only prevents an unbounded red test. Correct code publishes
    // closure while the deterministic packet producer can still supply input.
    try std.testing.expect(publication < Harness.maximum_packets);
    try std.testing.expectEqual(@as(usize, 1), server.metricsSnapshot().active_connections);
    try std.testing.expect(closing.closing_or_closed);
    try std.testing.expectEqual(@as(usize, 1), closing.data_sem.permits);
    try server.waitConnectionClosed(1);
}

test "metrics snapshot publishes IPv4 closure during sustained valid receive" {
    try metricsSnapshotDuringSustainedReceive(Server);
}

test "metrics snapshot publishes IPv6 closure during sustained valid receive" {
    try metricsSnapshotDuringSustainedReceive(IPv6Server);
}

fn enqueueReceiveTestDatagram(server: anytype, marker: u8, pooled: bool) !void {
    const allocator = std.testing.allocator;
    const buffer = if (pooled)
        (server.datagram_pool.take() orelse return error.TestUnexpectedResult)[0..2]
    else
        try allocator.alloc(u8, 2);
    errdefer if (pooled) server.datagram_pool.release(buffer) else allocator.free(buffer);
    // A cleared QUIC fixed bit is discarded without a route or a response.
    buffer[0] = 0;
    buffer[1] = marker;
    while (!server.queue_mutex.tryLock()) std.atomic.spinLoopHint();
    defer server.queue_mutex.unlock();
    try server.datagram_queue.append(allocator, .{ .from = server.socket.address, .data = buffer, .pooled = pooled });
}

test "metrics snapshot receive batches preserve FIFO compaction and buffer ownership" {
    inline for (.{ Server, IPv6Server }) |Runtime| {
        for ([_]usize{ 0, 64, 129 }) |queued| {
            const allocator = std.testing.allocator;
            const io = std.testing.io;
            var server = try Runtime.init(allocator, io, .{
                .port = 0,
                .alpn = &.{},
                .cert_der = &.{},
                .private_key = &.{},
                .max_connections = 1,
            });
            defer server.deinit();
            for (0..queued) |index| try enqueueReceiveTestDatagram(&server, @intCast(index), index < queued_datagram_pool_size);
            server.drainQueuedDatagrams(io, allocator);
            for (server.datagram_pool.free) |available| try std.testing.expect(available);
            if (queued <= 64) {
                try std.testing.expectEqual(@as(usize, 0), server.datagram_queue.items.len);
                try std.testing.expectEqual(@as(usize, 0), server.datagram_read_offset);
                try std.testing.expect(!server.hasPendingWork());
                continue;
            }
            // The first prefix is smaller than the live suffix; no copy yet.
            try std.testing.expectEqual(@as(usize, 64), server.datagram_read_offset);
            try std.testing.expectEqual(@as(usize, 129), server.datagram_queue.items.len);
            for (server.datagram_queue.items[server.datagram_read_offset..], 64..) |datagram, marker|
                try std.testing.expectEqual(@as(u8, @intCast(marker)), datagram.data[1]);
            try std.testing.expect(server.hasPendingWork());
            // Reuse a released pool buffer while unread heap buffers remain.
            // A later pass must not release a consumed descriptor a second time.
            const held = server.datagram_pool.take() orelse return error.TestUnexpectedResult;
            defer server.datagram_pool.release(held);
            server.drainQueuedDatagrams(io, allocator);
            try std.testing.expectEqual(@as(usize, 0), server.datagram_read_offset);
            try std.testing.expectEqual(@as(usize, 1), server.datagram_queue.items.len);
            try std.testing.expectEqual(@as(u8, 128), server.datagram_queue.items[0].data[1]);
            try std.testing.expect(server.hasPendingWork());
            server.drainQueuedDatagrams(io, allocator);
            try std.testing.expectEqual(@as(usize, 0), server.datagram_queue.items.len);
            try std.testing.expectEqual(@as(usize, 0), server.datagram_read_offset);
            try std.testing.expect(!server.datagram_pool.free[0]);
            try std.testing.expect(!server.hasPendingWork());
        }
    }
}

test "metrics snapshot receive batches retain appends during processing and stop with an owned suffix" {
    inline for (.{ Server, IPv6Server }) |Runtime| {
        const Harness = struct {
            var active: ?*@This() = null;
            server: *Runtime,
            underlying_now: @FieldType(std.Io.VTable, "now"),
            stop_first: bool,
            enabled: bool = false,
            markers: [65]u8 = undefined,
            seen: usize = 0,
            failure: ?anyerror = null,

            fn now(context: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
                const self = active.?;
                if (self.enabled) {
                    const datagram = self.server.datagram_queue.items[self.server.datagram_read_offset - 1];
                    if (self.seen < self.markers.len) self.markers[self.seen] = datagram.data[1] else self.failure = error.TestUnexpectedResult;
                    self.seen += 1;
                    if (self.seen == 1) {
                        if (self.stop_first) {
                            self.server.stop();
                        } else {
                            enqueueReceiveTestDatagram(self.server, 64, false) catch |err| {
                                self.failure = err;
                            };
                        }
                    }
                }
                return self.underlying_now(context, clock);
            }
        };
        for ([_]bool{ false, true }) |stop_first| {
            const allocator = std.testing.allocator;
            const base_io = std.testing.io;
            var vtable = base_io.vtable.*;
            const io: std.Io = .{ .userdata = base_io.userdata, .vtable = &vtable };
            var server = try Runtime.init(allocator, io, .{
                .port = 0,
                .alpn = &.{},
                .cert_der = &.{},
                .private_key = &.{},
                .max_connections = 1,
            });
            defer server.deinit();
            for (0..64) |index| try enqueueReceiveTestDatagram(&server, @intCast(index), index < queued_datagram_pool_size);
            var harness: Harness = .{ .server = &server, .underlying_now = vtable.now, .stop_first = stop_first };
            Harness.active = &harness;
            defer {
                vtable.now = harness.underlying_now;
                Harness.active = null;
            }
            vtable.now = Harness.now;
            harness.enabled = true;
            server.drainQueuedDatagrams(io, allocator);
            harness.enabled = false;
            try std.testing.expectEqual(@as(?anyerror, null), harness.failure);
            if (stop_first) {
                try std.testing.expectEqual(@as(usize, 1), harness.seen);
                try std.testing.expectEqual(@as(usize, 1), server.datagram_read_offset);
                try std.testing.expectEqual(@as(usize, 64), server.datagram_queue.items.len);
                try std.testing.expect(server.datagram_pool.free[0]);
                try std.testing.expect(!server.datagram_pool.free[1]);
                // deinit retains ownership of every unread buffer, including
                // the pool entries not selected before stop.
            } else {
                try std.testing.expectEqual(@as(usize, 64), harness.seen);
                try std.testing.expectEqual(@as(usize, 0), server.datagram_read_offset);
                try std.testing.expectEqual(@as(usize, 1), server.datagram_queue.items.len);
                try std.testing.expectEqual(@as(u8, 64), server.datagram_queue.items[0].data[1]);
                harness.enabled = true;
                server.drainQueuedDatagrams(io, allocator);
                harness.enabled = false;
                try std.testing.expectEqual(@as(usize, 65), harness.seen);
                for (harness.markers, 0..) |marker, index| try std.testing.expectEqual(@as(u8, @intCast(index)), marker);
                try std.testing.expectEqual(@as(usize, 0), server.datagram_queue.items.len);
                try std.testing.expectEqual(@as(usize, 0), server.datagram_read_offset);
            }
        }
    }
}

test "metrics snapshot receive batches honor pure cancellation before draining the next suffix" {
    inline for (.{ Server, IPv6Server }) |Runtime| {
        const Harness = struct {
            var active: ?*@This() = null;
            underlying_check: @FieldType(std.Io.VTable, "checkCancel"),
            checks: usize = 0,

            fn check(context: ?*anyopaque) std.Io.Cancelable!void {
                const self = active.?;
                self.checks += 1;
                if (self.checks == 2) return error.Canceled;
                return self.underlying_check(context);
            }
        };
        const allocator = std.testing.allocator;
        const base_io = std.testing.io;
        var vtable = base_io.vtable.*;
        const io: std.Io = .{ .userdata = base_io.userdata, .vtable = &vtable };
        var server = try Runtime.init(allocator, io, .{
            .port = 0,
            .alpn = &.{},
            .cert_der = &.{},
            .private_key = &.{},
            .max_connections = 1,
        });
        defer server.deinit();
        for (0..129) |index| try enqueueReceiveTestDatagram(&server, @intCast(index), index < queued_datagram_pool_size);
        var harness: Harness = .{ .underlying_check = vtable.checkCancel };
        Harness.active = &harness;
        defer {
            vtable.checkCancel = harness.underlying_check;
            Harness.active = null;
        }
        vtable.checkCancel = Harness.check;
        try std.testing.expectError(error.Canceled, server.drive());
        try std.testing.expectEqual(@as(usize, 2), harness.checks);
        try std.testing.expect(!server.stopping);
        try std.testing.expectEqual(@as(usize, 64), server.datagram_read_offset);
        try std.testing.expectEqual(@as(usize, 129), server.datagram_queue.items.len);
        try std.testing.expect(server.hasPendingWork());
        for (server.datagram_pool.free) |available| try std.testing.expect(available);
    }
}

/// Async streaming QUIC server (multi-connection, std.http model).
pub const Server = ServerForTuple(endpoint.Udp4Tuple);
/// Native IPv6 server with an explicitly bound source socket.
pub const IPv6Server = ServerForTuple(endpoint.Udp6Tuple);

/// Build the shared streaming server and handles for one UDP address family.
pub fn ServerForTuple(comptime Path: type) type {
    const Family = @import("udp_address.zig").ForTuple(Path);
    const RuntimeEndpoint = ServerEndpointForTuple(Path);
    const datagram_mtu = if (Path == endpoint.Udp6Tuple) 1200 else send_mtu;
    return struct {
        const ServerSelf = @This();
        pub const HandlerFn = *const fn (ServerSelf.ServerConnection) std.Io.Cancelable!void;

        allocator: std.mem.Allocator,
        io: std.Io,
        socket: std.Io.net.Socket,
        server_ep: RuntimeEndpoint,
        /// Borrowed until deinit completes. Each record holds one reservation.
        connection_admission: ?*ConnectionAdmission = null,
        next_handle: u64 = 1,
        alpn: []const []const u8,
        cert_der: []const u8,
        private_key: []const u8,
        private_key_algorithm: quicz.tls13.PrivateKeyAlgorithm,
        prefer_chacha20: bool = false,
        max_idle_timeout_ms: u64 = 30_000,
        punch_responder: ?quicz.connectivity.punch_responder.PunchResponder = null,
        /// Optional externally-owned dynamic responders for attempts sharing this
        /// UDP socket. The caller must keep the registry alive until deinit.
        punch_responder_registry: ?*quicz.connectivity.punch_responder.PunchResponderRegistry = null,
        /// Borrowed active-punch coordinator for this shared socket.
        shared_punch_coordinator: ?*quicz.connectivity.shared_punch_coordinator.SharedPunchCoordinator = null,
        shared_punch_failure_handler: ?*const fn (quicz.connectivity.shared_punch_coordinator.Failure) void = null,
        punch_handoff_mutex: ?*std.atomic.Mutex = null,
        stun_binding: StunBinding = .{},

        mutex: std.atomic.Mutex = .unlocked,
        conns: std.AutoHashMap(u64, *ConnState),
        /// Owned values from the latest drive publication; readers never borrow
        /// an endpoint record or its connection.
        cached_metrics: Metrics = .{
            .active_connections = 0,
            .stream_bytes_sent = 0,
            .stream_bytes_received = 0,
            .total_bytes_in_flight = 0,
            .smoothed_rtt_us = 0,
            .rttvar_us = 0,
            .congestion_window = 0,
            .packets_lost = 0,
            .packets_retransmitted = 0,
        },
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

        pub const Config = if (Path == endpoint.Udp4Tuple) IPv4Config else IPv6Config;

        pub fn init(allocator: std.mem.Allocator, io: std.Io, config: Config) !ServerSelf {
            var address: std.Io.net.IpAddress = if (Path == endpoint.Udp4Tuple)
                .{ .ip4 = .{ .bytes = config.bind_addr orelse .{ 127, 0, 0, 1 }, .port = config.port } }
            else
                .{ .ip6 = .{
                    .bytes = config.bind_addr orelse std.Io.net.Ip6Address.loopback(0).bytes,
                    .port = config.port,
                    .interface = .{ .index = config.bind_scope_id },
                } };
            const socket = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
            errdefer socket.close(io);
            return initWithSocket(allocator, io, socket, config);
        }

        /// Create a server from an already-bound UDP socket of this address family. On success the
        /// server owns and closes the socket; on failure ownership stays with the
        /// caller. Connectivity checks can therefore open the NAT mapping before
        /// QUIC starts without changing the server port.
        pub fn initWithSocket(
            allocator: std.mem.Allocator,
            io: std.Io,
            socket: std.Io.net.Socket,
            config: Config,
        ) !ServerSelf {
            const bound_address = Family.fromIp(socket.address) orelse return error.UnsupportedServerSocketFamily;
            if (Path == endpoint.Udp6Tuple and std.mem.allEqual(u8, &bound_address.octets, 0))
                return error.ExplicitIPv6LocalAddressRequired;
            enlargeSocketReceiveBuffer(socket.handle);
            const route_capacity = std.math.mul(
                usize,
                config.max_connections,
                route_slots_per_connection,
            ) catch std.math.maxInt(usize);
            const server_ep = try RuntimeEndpoint.initWithCapacity(allocator, config.max_connections, .{
                .max_routes = route_capacity,
                .max_stateless_reset_tokens = route_capacity,
            });
            return .{
                .allocator = allocator,
                .io = io,
                .socket = socket,
                .server_ep = server_ep,
                .alpn = config.alpn,
                .cert_der = config.cert_der,
                .private_key = config.private_key,
                .private_key_algorithm = config.private_key_algorithm,
                .prefer_chacha20 = config.prefer_chacha20,
                .max_idle_timeout_ms = config.max_idle_timeout_ms,
                .punch_responder = config.punch_responder,
                .punch_responder_registry = config.punch_responder_registry,
                .shared_punch_coordinator = config.shared_punch_coordinator,
                .shared_punch_failure_handler = config.shared_punch_failure_handler,
                .conns = std.AutoHashMap(u64, *ConnState).init(allocator),
                .datagram_queue = .empty,
                .datagram_pool = DatagramPool.init(allocator),
            };
        }

        /// Attach one shared pending/active limit before any records are admitted.
        /// The caller owns the limit and must keep it alive through deinit.
        pub fn attachConnectionAdmission(self: *ServerSelf, admission: *ConnectionAdmission) !void {
            if (self.started or self.server_ep.records.count() != 0) return error.ServerAlreadyStarted;
            if (self.connection_admission != null) return error.ConnectionAdmissionAlreadyAttached;
            self.connection_admission = admission;
        }

        /// Serialize validated-punch handoff with the owner's attempt cleanup.
        /// Attach before start and keep the mutex alive until deinit returns.
        /// Do not hold this mutex while deinit waits for the runtime tasks.
        pub fn attachPunchHandoffMutex(self: *ServerSelf, gate: *std.atomic.Mutex) !void {
            if (self.started or self.server_ep.records.count() != 0) return error.ServerAlreadyStarted;
            if (self.punch_handoff_mutex != null) return error.PunchHandoffMutexAlreadyAttached;
            self.punch_handoff_mutex = gate;
        }

        pub fn start(self: *ServerSelf) !void {
            if (self.started) return;
            try self.drive_group.concurrent(self.io, ServerSelf.recvTask, .{self});
            self.drive_group.concurrent(self.io, ServerSelf.drive, .{self}) catch |err| {
                @atomicStore(bool, &self.stopping, true, .release);
                self.drive_group.cancel(self.io);
                self.drive_group.await(self.io) catch {};
                return err;
            };
            self.started = true;
        }

        pub fn localPort(self: *const ServerSelf) u16 {
            return switch (self.socket.address) {
                .ip4 => |address| address.port,
                .ip6 => |address| address.port,
            };
        }

        /// Refresh this socket's mapping while the normal runtime remains its
        /// only receiver. STUN cancellation does not interrupt active QUIC streams.
        pub fn discoverReflexiveAddress(self: *ServerSelf, server: std.Io.net.IpAddress, config: quicz.connectivity.stun_transaction.Config) !quicz.connectivity.stun.MappedAddress {
            if (!self.started) return error.ServerNotStarted;
            return self.stun_binding.discover(self.io, &self.socket, server, config);
        }

        /// Wake the drive loop after an externally-owned shared punch coordinator
        /// registers or removes an attempt.
        pub fn wake(self: *ServerSelf) void {
            self.notifyDrive(self.io);
        }

        /// Signal the drive task and all accept/receive loops to stop.
        pub fn stop(self: *ServerSelf) void {
            self.stun_binding.stop(self.io);
            @atomicStore(bool, &self.stopping, true, .release);
            // Wake a blocked accept loop so it observes `stopping`.
            self.accept_sem.post(self.io);
            // Wake the parked drive task.
            self.notifyDrive(self.io);
        }

        /// Aggregate metrics across active connections at the latest drive
        /// publication. Later endpoint changes appear in the next publication.
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

        /// Return the latest drive-owned aggregate without borrowing a connection.
        pub fn metricsSnapshot(self: *ServerSelf) Metrics {
            while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
            defer self.mutex.unlock();
            return self.cached_metrics;
        }

        /// Publish after every endpoint operation in this drive iteration,
        /// including deadline selection, which may destroy closed records.
        fn publishConnectionState(self: *ServerSelf) void {
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
            defer self.mutex.unlock();
            var closed_handles: [64]u64 = undefined;
            var closed_count: usize = 0;
            var it = self.conns.valueIterator();
            while (it.next()) |csp| {
                const st = csp.*;
                const record = self.server_ep.records.get(st.handle);
                const closing_now = if (record) |live| live.connectionRef().isClosingOrClosed() else true;
                const closing_prev = @atomicRmw(bool, &st.closing_or_closed, .Xchg, closing_now, .acq_rel);
                if (closing_now and !closing_prev) st.data_sem.post(self.io);
                if (closing_now) {
                    if (st.handler_done and closed_count < closed_handles.len) {
                        closed_handles[closed_count] = st.handle;
                        closed_count += 1;
                    }
                    continue;
                }
                const cs = record.?.connectionRef().connectionStats();
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
            for (closed_handles[0..closed_count]) |handle| {
                if (self.conns.fetchRemove(handle)) |removed| {
                    removed.value.deinit(self.allocator);
                    self.allocator.destroy(removed.value);
                    log.info("connection {d} closed: state reclaimed", .{handle});
                }
            }
            self.cached_metrics = m;
        }

        /// Start the server (if not already started) and spawn the serve task,
        /// which accepts connections and runs one handler task per connection
        /// (std.Build.WebServer serve pattern). The runtime releases each
        /// connection when its handler returns; deinit cancels the serve task
        /// and every handler task.
        pub fn serve(self: *ServerSelf, handler: ServerSelf.HandlerFn) !void {
            try self.start();
            try self.drive_group.concurrent(self.io, ServerSelf.serveLoop, .{ self, handler });
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
        /// this `ServerSelf`; only the application protocol is wired here.
        pub fn serveH3(self: *ServerSelf, options: H3ServeOptions, handler: h3_proto.RequestHandler) !void {
            if (Path != endpoint.Udp4Tuple) @compileError("IPv6 HTTP/3 is outside this runtime entry point");
            self.h3_request_handler = handler;
            self.h3_qpack_max_table_capacity = options.qpack_max_table_capacity;
            self.h3_qpack_blocked_streams = options.qpack_blocked_streams;
            try self.serve(h3ServeHandler);
        }

        /// Per-connection handler backing serveH3: one runtime H3 driver per
        /// connection, exactly the layering recommended for production.
        fn h3ServeHandler(conn: ServerSelf.ServerConnection) std.Io.Cancelable!void {
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
        fn serveLoop(self: *ServerSelf, handler: ServerSelf.HandlerFn) std.Io.Cancelable!void {
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
        fn handlerTask(self: *ServerSelf, conn: ServerSelf.ServerConnection, handler: ServerSelf.HandlerFn) std.Io.Cancelable!void {
            defer self.releaseConnection(conn.id);
            handler(conn) catch |err| {
                if (err != error.Canceled) log.err("connection {d} handler failed: {}", .{ conn.id, err });
            };
        }

        pub fn deinit(self: *ServerSelf) void {
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
            if (self.punch_responder) |*responder| responder.deinit();
            self.punch_responder = null;
            self.server_ep.deinit();
            self.socket.close(self.io);
        }

        /// Mark the handler done with a connection. Call once per connection
        /// when the handler finishes; the drive task frees the state once the
        /// connection is also closed (single-owner reclamation).
        pub fn releaseConnection(self: *ServerSelf, conn_id: u64) void {
            while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
            if (self.conns.get(conn_id)) |cs| {
                cs.handler_done = true;
            }
            self.mutex.unlock();
            self.notifyDrive(self.io);
        }

        /// Ask the drive task to close one connection without stopping the server.
        /// Safe to call after a handler's stream bridge fails; repeated requests
        /// and already-closed connections are ignored.
        pub fn closeConnection(self: *ServerSelf, conn_id: u64, application_error_code: u64) void {
            while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
            if (self.conns.get(conn_id)) |cs| {
                cs.close_requested = true;
                cs.close_error_code = application_error_code;
            }
            self.mutex.unlock();
            self.notifyDrive(self.io);
        }

        /// Raise SO_RCVBUF so client bursts do not overflow the kernel receive
        /// buffer before the drive task drains it; loss recovery still covers
        /// any residual drops.
        fn enlargeSocketReceiveBuffer(handle: std.Io.net.Socket.Handle) void {
            const size: u32 = 4 * 1024 * 1024;
            std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&size)) catch {};
        }

        fn nowNanos(self: *const ServerSelf) i64 {
            return @intCast(std.Io.Timestamp.now(self.io, .awake).nanoseconds);
        }

        /// Drain queued stream sends and emit outgoing datagrams.
        fn drainOutgoing(self: *ServerSelf, io: std.Io, allocator: std.mem.Allocator) void {
            while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
            var cit = self.conns.valueIterator();
            while (cit.next()) |csp| {
                const st = csp.*;
                // The endpoint reclaims records of closed connections during
                // deadline queries; only dereference the connection while its
                // record is alive. Runtime closure is published after the final
                // endpoint operation rather than from this outgoing pass.
                const record_alive = self.server_ep.records.get(st.handle) != null;
                if (st.close_requested) {
                    st.close_requested = false;
                    if (record_alive and !st.conn.isClosingOrClosed()) {
                        st.conn.closeApplication(st.close_error_code, "") catch |err|
                            log.err("connection {d} close failed: {}", .{ st.handle, err });
                    }
                }
                const closing_now = if (record_alive) st.conn.isClosingOrClosed() else true;
                if (closing_now and st.handler_done) continue;
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
                if (!flow_blocked and st.send_pending) {
                    st.send_pending = false;
                    _ = st.send_flush_id.rmw(.Add, 1, .release);
                    // Every stream flush waits on this connection-wide drain.
                    self.io.futexWake(u32, &st.send_flush_id.raw, std.math.maxInt(u32));
                }
                st.mutex.unlock();
            }
            self.mutex.unlock();
            var out: [16]RuntimeEndpoint.DatagramPathResult = undefined;
            const drained = self.server_ep.drainDatagramsAcrossRecordsWithRoutePathWithScratch(self.nowNanos(), .application, &out);
            // Batch the drained datagrams: Linux sendmmsg amortizes the syscall
            // across the batch (std.Io.Threaded netSend); macOS has no sendmmsg
            // and its batching path is slower, so fall back to per-datagram sends.
            var addrs: [16]std.Io.net.IpAddress = undefined;
            var msgs: [16]std.Io.net.OutgoingMessage = undefined;
            for (out[0..drained.datagrams_written], 0..) |o, i| {
                addrs[i] = Family.toIp(o.path.remote);
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
        fn notifyDrive(self: *ServerSelf, io: std.Io) void {
            _ = self.wake_id.rmw(.Add, 1, .release);
            io.futexWake(u32, &self.wake_id.raw, 1);
        }

        /// Receive datagrams into the queue and wake the drive task. Mirrors the
        /// official WebServer accept task: block on the socket, hand work off.
        fn recvTask(self: *ServerSelf) std.Io.Cancelable!void {
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

        /// Process one finite FIFO batch so timers and publication cannot starve.
        fn drainQueuedDatagrams(self: *ServerSelf, io: std.Io, allocator: std.mem.Allocator) void {
            var processed: usize = 0;
            while (processed < receive_batch_size) : (processed += 1) {
                if (@atomicLoad(bool, &self.stopping, .acquire)) return;
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
            while (!self.queue_mutex.tryLock()) std.atomic.spinLoopHint();
            defer self.queue_mutex.unlock();
            const consumed = self.datagram_read_offset;
            const remaining = self.datagram_queue.items.len - consumed;
            if (remaining == 0) {
                self.datagram_queue.clearRetainingCapacity();
                self.datagram_read_offset = 0;
            } else if (consumed >= remaining) {
                // Moving descriptors transfers their queue ownership; buffers
                // remain live. Copy only when its cost is paid by consumed input.
                std.mem.copyForwards(QueuedDatagram, self.datagram_queue.items[0..remaining], self.datagram_queue.items[consumed..]);
                self.datagram_queue.shrinkRetainingCapacity(remaining);
                self.datagram_read_offset = 0;
            }
        }

        fn drainSharedPunches(self: *ServerSelf, io: std.Io) void {
            const coordinator = self.shared_punch_coordinator orelse return;
            const now_ms: u64 = @intCast(@max(0, @divFloor(self.nowNanos(), 1_000_000)));
            while (true) switch (coordinator.next(now_ms)) {
                .probe => |outbound| {
                    var destination = outbound.destination;
                    self.socket.send(io, &destination, &outbound.packet) catch {};
                },
                .failed => |failure| {
                    if (self.shared_punch_failure_handler) |handler| handler(failure);
                    _ = coordinator.remove(failure.attempt_id);
                },
                .validated => |attempt_id| self.retainSharedResponder(attempt_id),
                else => return,
            };
        }

        fn retainSharedResponder(self: *ServerSelf, attempt_id: quicz.connectivity.punch_wire.AttemptId) void {
            const coordinator = self.shared_punch_coordinator orelse return;
            const handoff_mutex = self.punch_handoff_mutex;
            if (handoff_mutex) |gate| while (!gate.tryLock()) std.atomic.spinLoopHint();
            defer if (handoff_mutex) |gate| gate.unlock();
            var attempt = coordinator.takeValidated(attempt_id) catch return;
            defer attempt.deinit();
            if (self.punch_responder_registry) |responders| {
                const lifetime_ms = std.math.mul(u32, attempt.punch.config.maximum_retry_ms, 2) catch return;
                responders.register(quicz.connectivity.punch_responder.PunchResponder.init(
                    attempt.punch.key,
                    attempt.punch.attempt_id,
                    attempt.punch.local_nonce,
                    attempt.remote,
                    self.nowNanos(),
                    lifetime_ms,
                ) catch return) catch {};
            }
        }

        /// Route one datagram through the endpoint (accept or routed step) and
        /// deliver stream data to per-connection queues.
        fn processDatagram(self: *ServerSelf, io: std.Io, allocator: std.mem.Allocator, from: std.Io.net.IpAddress, data: []const u8) void {
            if (self.stun_binding.receive(io, from, data)) return;
            if (self.shared_punch_coordinator) |coordinator| {
                const now_ms: u64 = @intCast(@max(0, @divFloor(self.nowNanos(), 1_000_000)));
                switch (coordinator.receive(from, now_ms, data)) {
                    .idle => {},
                    .acknowledgement => |outbound| {
                        var destination = outbound.destination;
                        self.socket.send(io, &destination, &outbound.packet) catch {};
                        return;
                    },
                    .validated => |attempt_id| {
                        self.retainSharedResponder(attempt_id);
                        return;
                    },
                    .probe, .failed => return,
                }
            }
            if (self.punch_responder_registry) |responders| {
                switch (responders.handle(from, self.nowNanos(), data)) {
                    .not_punch => {},
                    .consumed => return,
                    .acknowledgement => |acknowledgement| {
                        var destination = from;
                        self.socket.send(io, &destination, &acknowledgement) catch {};
                        return;
                    },
                }
            } else if (self.punch_responder) |responder| {
                switch (responder.handle(from, self.nowNanos(), data)) {
                    .not_punch => {},
                    .consumed => return,
                    .acknowledgement => |acknowledgement| {
                        var destination = from;
                        self.socket.send(io, &destination, &acknowledgement) catch {};
                        return;
                    },
                }
            }
            const from_addr = Family.fromIp(from) orelse return;
            const local_addr = Family.fromIp(self.socket.address) orelse return;
            const path = Path{ .local = local_addr, .remote = from_addr };
            const now = self.nowNanos();

            var initial_out: [4]quicz.endpoint_types.EndpointPolledDatagramResult = undefined;
            var handshake_out: [4]quicz.endpoint_types.EndpointPolledDatagramResult = undefined;
            var installed_out: [16]RuntimeEndpoint.DatagramPathResult = undefined;
            var pending_out: [16]RuntimeEndpoint.DatagramPathResult = undefined;
            var scratch: [8192]u8 = undefined;

            const action = self.server_ep.feedDatagram(&scratch, path, data, &[_]u8{}, &[_]quic_packet.Version{ .v1, .v2 }) catch |e| {
                log.err("drive: feedDatagram ({d} bytes): {}", .{ data.len, e });
                return;
            };
            var dest = Family.toIp(from_addr);

            switch (action) {
                .accept_initial => |initial_accept| {
                    if (self.connection_admission) |admission| if (!admission.tryAcquire()) return;
                    var runtime_owns_reservation = true;
                    defer if (runtime_owns_reservation) {
                        if (self.connection_admission) |admission| admission.release();
                    };
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
                        .admission = self.connection_admission,
                        .transport = Tls13ServerTransport.init(allocator, .{
                            .initial_max_data = 10_485_760,
                            .initial_max_stream_data = 10_485_760,
                            .initial_max_streams_bidi = 128,
                            .initial_max_streams_uni = 128,
                            .max_datagram_size = datagram_mtu,
                            .disable_active_migration = Path == endpoint.Udp6Tuple,
                            .max_idle_timeout_ms = self.max_idle_timeout_ms,
                        }, .{
                            .alpn = self.alpn,
                            .cert_chain_der = &cert_chain,
                            .private_key_bytes = self.private_key,
                            .private_key_algorithm = self.private_key_algorithm,
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
                    runtime_owns_reservation = false;
                    record.transport.setOriginalDestinationConnectionId(initial_info.dcid) catch |e| {
                        log.err("drive: setOriginalDestinationConnectionId: {}", .{e});
                    };
                    const accepted = self.server_ep.acceptOwnedInitialRecord(handle, record, now, initial_accept, &server_scid, data, .{ .active_migration_disabled = Path == endpoint.Udp6Tuple }, &scratch, &initial_out, &handshake_out) catch |e| {
                        log.err("drive: acceptOwnedInitialRecord: {}", .{e});
                        return;
                    };
                    defer {
                        for (initial_out[0..accepted.initial.drain.datagrams_written]) |outbound| allocator.free(outbound.datagram);
                        if (accepted.handshake) |handshake| {
                            for (handshake_out[0..handshake.drain.datagrams_written]) |outbound| allocator.free(outbound.datagram);
                        }
                    }
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
                    }
                    if (accepted.handshake) |hs| {
                        for (handshake_out[0..hs.drain.datagrams_written]) |o| {
                            self.socket.send(io, &dest, o.datagram) catch {};
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
                                    // (2,6,10,...). ServerSelf-initiated (odd) sids are
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
        fn serviceDueDeadlines(self: *ServerSelf, io: std.Io, allocator: std.mem.Allocator) void {
            var passes: usize = 0;
            while (passes < 8) : (passes += 1) {
                var out: [16]RuntimeEndpoint.DatagramPathResult = undefined;
                const due = self.server_ep.processDueDeadlineAndDrainDatagramsWithRoutePathWithScratch(self.nowNanos(), &out) catch |e| {
                    log.debug("drive: due deadline processing: {}", .{e});
                    return;
                };
                const result = due orelse return;
                for (out[0..result.drain.datagrams_written]) |o| {
                    var dest = Family.toIp(o.path.remote);
                    self.socket.send(io, &dest, o.datagram) catch {};
                    allocator.free(o.datagram);
                }
            }
        }

        /// Whether a handler-queued send or a recv-task datagram still waits for
        /// the drive task. Checked after the park snapshot to close the window
        /// between draining and the snapshot (see drive()).
        fn hasPendingWork(self: *ServerSelf) bool {
            if (self.shared_punch_coordinator) |coordinator| {
                const now_ms: u64 = @intCast(@max(0, @divFloor(self.nowNanos(), 1_000_000)));
                if (coordinator.nextDeadlineMs()) |deadline| if (deadline <= now_ms) return true;
            }
            while (!self.queue_mutex.tryLock()) std.atomic.spinLoopHint();
            const datagrams_queued = self.datagram_read_offset < self.datagram_queue.items.len;
            self.queue_mutex.unlock();
            if (datagrams_queued) return true;
            while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
            var pending = false;
            var it = self.conns.valueIterator();
            while (it.next()) |csp| {
                const closing = @atomicLoad(bool, &csp.*.closing_or_closed, .acquire);
                if ((!closing and (csp.*.send_pending or csp.*.close_requested)) or
                    (csp.*.handler_done and closing))
                {
                    pending = true;
                    break;
                }
            }
            self.mutex.unlock();
            return pending;
        }

        /// The connection driving task body: drain sends, process queued
        /// datagrams, service due deadlines, then park on the wakeup futex until
        /// the next event or lifecycle deadline.
        pub fn drive(self: *ServerSelf) std.Io.Cancelable!void {
            const allocator = self.allocator;
            const io = self.io;
            while (!@atomicLoad(bool, &self.stopping, .acquire)) {
                try io.checkCancel();
                self.drainOutgoing(io, allocator);
                self.drainQueuedDatagrams(io, allocator);
                self.drainSharedPunches(io);
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
                const timeout: std.Io.Timeout = timeout: {
                    var deadline_nanos: ?i64 = null;
                    if (self.server_ep.nextDeadlineWithScratch() catch null) |deadline| deadline_nanos = deadline.deadline_nanos;
                    if (self.shared_punch_coordinator) |coordinator| if (coordinator.nextDeadlineMs()) |deadline_ms| {
                        const nanos = std.math.mul(u64, deadline_ms, 1_000_000) catch std.math.maxInt(u64);
                        const punch_nanos: i64 = @intCast(@min(nanos, std.math.maxInt(i64)));
                        if (deadline_nanos == null or punch_nanos < deadline_nanos.?) deadline_nanos = punch_nanos;
                    };
                    break :timeout if (deadline_nanos) |deadline| .{ .deadline = .{ .raw = .{ .nanoseconds = deadline }, .clock = .awake } } else .none;
                };
                self.publishConnectionState();
                // Re-check work whose notifyDrive bump was captured by the
                // snapshot. Publication may also wake a handler that releases
                // its state; work arriving later changes wake_id before parking.
                if (self.hasPendingWork()) continue;
                io.futexWaitTimeout(u32, &self.wake_id.raw, snapshot, timeout) catch return;
            }
        }

        /// Accept the next new connection (polls with std.time.sleep).
        pub fn accept(self: *ServerSelf) !ServerSelf.ServerConnection {
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
        pub fn acceptStreamId(self: *ServerSelf, conn_id: u64) !u64 {
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
        pub fn receiveStreamData(self: *ServerSelf, conn_id: u64, sid: u64, buf: []u8) !usize {
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
        pub fn tryAcceptStreamId(self: *ServerSelf, conn_id: u64) !?u64 {
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
        pub fn tryReceiveStreamData(self: *ServerSelf, conn_id: u64, sid: u64, buf: []u8) !?usize {
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
        pub fn connStreamIds(self: *ServerSelf, conn_id: u64, out: []u64) usize {
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
        pub fn waitStreamActivity(self: *ServerSelf, conn_id: u64) !void {
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

        /// Wait until the peer closes this connection or the transport reaches a
        /// terminal state. Handlers use this to keep the UDP socket alive after
        /// their final stream FIN has been flushed.
        pub fn waitConnectionClosed(self: *ServerSelf, conn_id: u64) !void {
            while (true) {
                if (@atomicLoad(bool, &self.stopping, .acquire)) return error.Canceled;
                while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
                const cs = self.conns.get(conn_id) orelse {
                    self.mutex.unlock();
                    return;
                };
                while (!cs.mutex.tryLock()) std.atomic.spinLoopHint();
                const closed = @atomicLoad(bool, &cs.closing_or_closed, .acquire);
                cs.mutex.unlock();
                self.mutex.unlock();
                if (closed) return;
                cs.data_sem.wait(self.io) catch return error.Canceled;
            }
        }

        /// Queue stream data to send (drive task drains and sends).
        pub fn sendStreamData(self: *ServerSelf, conn_id: u64, stream_id: u64, data: []const u8, fin: bool) !void {
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

        /// Wait until the drive task has consumed all currently queued stream
        /// bytes and FIN markers for this connection.
        pub fn flushStreamData(self: *ServerSelf, conn_id: u64) !void {
            while (true) {
                while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
                const cs = self.conns.get(conn_id) orelse {
                    self.mutex.unlock();
                    return error.NoConnection;
                };
                const snapshot = cs.send_flush_id.load(.acquire);
                while (!cs.mutex.tryLock()) std.atomic.spinLoopHint();
                const pending = cs.send_pending;
                cs.mutex.unlock();
                self.mutex.unlock();
                if (!pending) return;
                self.io.futexWait(u32, &cs.send_flush_id.raw, snapshot) catch return error.Canceled;
            }
        }

        /// Queue a STOP_SENDING (RFC 9000 §3.5) for one stream; the drive task
        /// sends it to the peer. Blocks the handler until the drive task drains it.
        pub fn stopSendingRequest(self: *ServerSelf, conn_id: u64, stream_id: u64, code: u64) !void {
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
        pub fn openUniStreamRequest(self: *ServerSelf, conn_id: u64) !u64 {
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

        pub const ServerConnection = struct {
            server: *ServerSelf,
            id: u64,

            pub fn acceptStream(self: *ServerSelf.ServerConnection) !ServerSelf.Stream {
                const sid = try self.server.acceptStreamId(self.id);
                return .{ .server = self.server, .conn_id = self.id, .id = sid };
            }

            /// Open a server-initiated unidirectional stream (RFC 9000 §2.1).
            pub fn openUniStream(self: *ServerSelf.ServerConnection) !ServerSelf.Stream {
                const sid = try self.server.openUniStreamRequest(self.id);
                return .{ .server = self.server, .conn_id = self.id, .id = sid };
            }

            pub fn waitClosed(self: *ServerSelf.ServerConnection) !void {
                return self.server.waitConnectionClosed(self.id);
            }
        };

        pub const Stream = struct {
            server: *ServerSelf,
            conn_id: u64,
            id: u64,

            /// True for a unidirectional stream (RFC 9000 §2.1 bit 1 set).
            pub fn isUni(self: ServerSelf.Stream) bool {
                return (self.id & 2) != 0;
            }
            /// True if the client initiated the stream (RFC 9000 §2.1 bit 0 clear).
            pub fn isClientInitiated(self: ServerSelf.Stream) bool {
                return (self.id & 1) == 0;
            }

            /// Read queued stream bytes. Returns 0 at EOF: the peer FIN arrived
            /// and every stream byte was already consumed.
            pub fn receive(self: *ServerSelf.Stream, buf: []u8) !usize {
                return self.server.receiveStreamData(self.conn_id, self.id, buf);
            }
            pub fn send(self: *ServerSelf.Stream, data: []const u8, fin: bool) !void {
                return self.server.sendStreamData(self.conn_id, self.id, data, fin);
            }
            pub fn flush(self: *ServerSelf.Stream) !void {
                return self.server.flushStreamData(self.conn_id);
            }
            /// Ask the peer to STOP_SENDING this stream with `code` (RFC 9000 §3.5).
            pub fn stopSending(self: *ServerSelf.Stream, code: u64) !void {
                return self.server.stopSendingRequest(self.conn_id, self.id, code);
            }
        };
    };
}

/// Per-connection handler callback (std.http model): serves one
/// connection; `error.Canceled` terminates it during shutdown.
pub const HandlerFn = Server.HandlerFn;

/// A server-side connection handle.
pub const ServerConnection = Server.ServerConnection;

/// A stream handle on a server connection (bidirectional or unidirectional;
/// local or peer-initiated). `acceptStream` may return a peer (client)
/// unidirectional stream; `openUniStream` creates a server one.
pub const Stream = Server.Stream;

const IPv4Config = struct {
    port: u16,
    alpn: []const []const u8,
    cert_der: []const u8,
    private_key: []const u8,
    private_key_algorithm: quicz.tls13.PrivateKeyAlgorithm = .ecdsa_p256_sha256,
    prefer_chacha20: bool = false,
    /// Maximum connection idle time advertised to peers. Production
    /// defaults to 30 seconds; focused runtime tests may lower it.
    max_idle_timeout_ms: u64 = 30_000,
    /// IPv4 address to bind. Defaults to loopback (127.0.0.1); set to
    /// `.{0,0,0,0}` to listen on all interfaces (cross-host benchmarks).
    bind_addr: ?[4]u8 = null,
    /// Maximum concurrent connections accepted by this server. The
    /// endpoint pre-allocates routing and scratch state for this many
    /// connections, so set it to your expected peak + headroom.
    max_connections: usize = 4096,
    /// Optional authenticated probe handler retained after this runtime
    /// takes ownership of a connectivity-validated UDP socket.
    punch_responder: ?quicz.connectivity.punch_responder.PunchResponder = null,
    /// Dynamic attempt responders for a Host-level shared endpoint. This
    /// registry is borrowed, never cleared or deinitialized by Server.
    punch_responder_registry: ?*quicz.connectivity.punch_responder.PunchResponderRegistry = null,
    shared_punch_coordinator: ?*quicz.connectivity.shared_punch_coordinator.SharedPunchCoordinator = null,
    shared_punch_failure_handler: ?*const fn (quicz.connectivity.shared_punch_coordinator.Failure) void = null,
};

const IPv6Config = struct {
    port: u16,
    alpn: []const []const u8,
    cert_der: []const u8,
    private_key: []const u8,
    private_key_algorithm: quicz.tls13.PrivateKeyAlgorithm = .ecdsa_p256_sha256,
    prefer_chacha20: bool = false,
    /// Maximum connection idle time advertised to peers. Production
    /// defaults to 30 seconds; focused runtime tests may lower it.
    max_idle_timeout_ms: u64 = 30_000,
    /// Explicit local IPv6 address. Defaults to loopback (::1).
    bind_addr: ?[16]u8 = null,
    bind_scope_id: u32 = 0,
    /// Maximum concurrent connections accepted by this server. The
    /// endpoint pre-allocates routing and scratch state for this many
    /// connections, so set it to your expected peak + headroom.
    max_connections: usize = 4096,
    /// Optional authenticated probe handler retained after this runtime
    /// takes ownership of a connectivity-validated UDP socket.
    punch_responder: ?quicz.connectivity.punch_responder.PunchResponder = null,
    /// Dynamic attempt responders for a Host-level shared endpoint. This
    /// registry is borrowed, never cleared or deinitialized by Server.
    punch_responder_registry: ?*quicz.connectivity.punch_responder.PunchResponderRegistry = null,
    shared_punch_coordinator: ?*quicz.connectivity.shared_punch_coordinator.SharedPunchCoordinator = null,
    shared_punch_failure_handler: ?*const fn (quicz.connectivity.shared_punch_coordinator.Failure) void = null,
};
