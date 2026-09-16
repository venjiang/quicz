//! Socket driver for one authenticated candidate-pair check.

const std = @import("std");
const punch_attempt = @import("punch_attempt.zig");

/// Borrow the socket until probing and bounded ACK service finish. After local
/// validation, service peer retries for two maximum retry intervals (2 s by
/// default). Peers must use compatible retry policies. Repeated traffic never
/// extends this deadline; callers must not run a second receiver concurrently.
pub fn run(
    io: std.Io,
    socket: std.Io.net.Socket,
    remote: std.Io.net.IpAddress,
    attempt: *punch_attempt.PunchAttempt,
) !void {
    return runInternal(io, socket, remote, attempt, true);
}

/// Return immediately after local validation. The caller must transfer a
/// `PunchResponder` into the QUIC runtime that takes ownership of this socket.
pub fn runUntilValidated(
    io: std.Io,
    socket: std.Io.net.Socket,
    remote: std.Io.net.IpAddress,
    attempt: *punch_attempt.PunchAttempt,
) !void {
    return runInternal(io, socket, remote, attempt, false);
}

fn runInternal(
    io: std.Io,
    socket: std.Io.net.Socket,
    remote: std.Io.net.IpAddress,
    attempt: *punch_attempt.PunchAttempt,
    service_after_validation: bool,
) !void {
    const started = std.Io.Timestamp.now(io, .awake);
    var receive_buffer: [256]u8 = undefined;
    var destination = remote;
    var finishing_deadline_ms: ?u64 = null;

    while (attempt.state != .failed) {
        const now_ms = elapsedMilliseconds(started, std.Io.Timestamp.now(io, .awake));
        if (attempt.state == .validated) {
            if (!service_after_validation) break;
            // Our ACK may have been lost even though our own probe succeeded.
            // Keep answering retries without reopening the validated state.
            if (finishing_deadline_ms == null) {
                finishing_deadline_ms = std.math.add(u64, now_ms, 2 * @as(u64, attempt.config.maximum_retry_ms)) catch std.math.maxInt(u64);
            }
            if (now_ms >= finishing_deadline_ms.?) break;
        } else {
            if (attempt.nextProbe(now_ms)) |probe| {
                try socket.send(io, &destination, &probe);
                attempt.diagnostics.probe_sends +|= 1;
            }
            if (attempt.state == .failed) break;
        }

        const deadline = std.Io.Clock.Timestamp{
            .raw = started.addDuration(std.Io.Duration.fromMilliseconds(@intCast(@min(
                finishing_deadline_ms orelse attempt.next_probe_ms,
                std.math.maxInt(i64),
            )))),
            .clock = .awake,
        };
        const received = socket.receiveTimeout(io, &receive_buffer, .{ .deadline = deadline }) catch |err| switch (err) {
            error.Timeout => continue,
            error.MessageOversize => {
                attempt.diagnostics.oversized_received +|= 1;
                continue;
            },
            else => return err,
        };
        attempt.diagnostics.datagrams_received +|= 1;
        if (!sameAddress(received.from, remote)) {
            attempt.diagnostics.source_rejected +|= 1;
            continue;
        }
        const result = attempt.receive(received.data) catch continue;
        if (result.acknowledgement) |acknowledgement| {
            try socket.send(io, &destination, &acknowledgement);
            attempt.diagnostics.acknowledgement_sends +|= 1;
        }
    }

    if (attempt.state != .validated) return error.PunchFailed;
}

fn elapsedMilliseconds(started: std.Io.Timestamp, now: std.Io.Timestamp) u64 {
    const elapsed = started.durationTo(now).toMilliseconds();
    return if (elapsed <= 0) 0 else @intCast(elapsed);
}

fn sameAddress(lhs: std.Io.net.IpAddress, rhs: std.Io.net.IpAddress) bool {
    return switch (lhs) {
        .ip4 => |left| switch (rhs) {
            .ip4 => |right| left.port == right.port and std.mem.eql(u8, &left.bytes, &right.bytes),
            .ip6 => false,
        },
        .ip6 => |left| switch (rhs) {
            .ip4 => false,
            .ip6 => |right| left.port == right.port and std.mem.eql(u8, &left.bytes, &right.bytes),
        },
    };
}

test "elapsed milliseconds is monotonic and clamps negative input" {
    const started = std.Io.Timestamp{ .nanoseconds = 1_000_000 };
    const later = std.Io.Timestamp{ .nanoseconds = 3_500_000 };
    const earlier = std.Io.Timestamp{ .nanoseconds = 500_000 };
    try std.testing.expectEqual(@as(u64, 2), elapsedMilliseconds(started, later));
    try std.testing.expectEqual(@as(u64, 0), elapsedMilliseconds(started, earlier));
}

const TestRun = struct {
    io: std.Io,
    socket: std.Io.net.Socket,
    remote: std.Io.net.IpAddress,
    attempt: *punch_attempt.PunchAttempt,
    failure: ?anyerror = null,
    finished: std.atomic.Value(bool) = .init(false),

    fn start(self: *TestRun) std.Io.Cancelable!void {
        run(self.io, self.socket, self.remote, self.attempt) catch |err| {
            self.failure = err;
        };
        self.finished.store(true, .release);
    }
};

fn runFast(context: *TestRun) std.Io.Cancelable!void {
    runUntilValidated(context.io, context.socket, context.remote, context.attempt) catch |err| {
        context.failure = err;
    };
    context.finished.store(true, .release);
}

test "runtime handoff returns promptly after mutual validation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    const first_socket = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer first_socket.close(io);
    const second_socket = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer second_socket.close(io);
    var first_attempt = try punch_attempt.PunchAttempt.init(.{0x42} ** 32, .{0x11} ** 16, .{0xa1} ** 16, .{});
    var second_attempt = try punch_attempt.PunchAttempt.init(.{0x42} ** 32, .{0x11} ** 16, .{0xb2} ** 16, .{});
    var first = TestRun{ .io = io, .socket = first_socket, .remote = second_socket.address, .attempt = &first_attempt };
    var second = TestRun{ .io = io, .socket = second_socket, .remote = first_socket.address, .attempt = &second_attempt };
    const started = std.Io.Timestamp.now(io, .awake);
    var tasks: std.Io.Group = .init;
    defer tasks.cancel(io);
    try tasks.concurrent(io, runFast, .{&first});
    try tasks.concurrent(io, runFast, .{&second});
    try tasks.await(io);

    try std.testing.expectEqual(@as(?anyerror, null), first.failure);
    try std.testing.expectEqual(@as(?anyerror, null), second.failure);
    try std.testing.expect(first_attempt.diagnostics.probe_sends > 0);
    try std.testing.expect(first_attempt.diagnostics.acknowledgement_sends > 0);
    try std.testing.expect(first_attempt.diagnostics.datagrams_received >= 2);
    try std.testing.expectEqual(@as(u32, 0), first_attempt.diagnostics.source_rejected);
    try std.testing.expect(elapsedMilliseconds(started, std.Io.Timestamp.now(io, .awake)) < 500);
}

test "punch diagnostics distinguish silent peer from wrong source" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    const local = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer local.close(io);
    const peer = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer peer.close(io);
    const stranger = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer stranger.close(io);
    for ([_]bool{ false, true }) |wrong_source| {
        var attempt = try punch_attempt.PunchAttempt.init(@splat(0x42), @splat(0x11), @splat(0xa1), .{
            .initial_retry_ms = 200,
            .maximum_retry_ms = 200,
            .max_attempts = 1,
        });
        var context = TestRun{ .io = io, .socket = local, .remote = peer.address, .attempt = &attempt };
        var tasks: std.Io.Group = .init;
        defer tasks.cancel(io);
        try tasks.concurrent(io, runFast, .{&context});
        var buffer: [256]u8 = undefined;
        _ = try peer.receiveTimeout(io, &buffer, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
        if (wrong_source) {
            var other = try punch_attempt.PunchAttempt.init(@splat(0x42), @splat(0x11), @splat(0xb2), .{});
            try stranger.send(io, &local.address, &other.nextProbe(0).?);
        }
        try tasks.await(io);
        try std.testing.expectEqual(@as(?anyerror, error.PunchFailed), context.failure);
        try std.testing.expectEqual(@as(u32, 1), attempt.diagnostics.probe_sends);
        try std.testing.expectEqual(@as(u32, @intFromBool(wrong_source)), attempt.diagnostics.datagrams_received);
        try std.testing.expectEqual(@as(u32, @intFromBool(wrong_source)), attempt.diagnostics.source_rejected);
        try std.testing.expectEqual(@as(u32, 0), attempt.diagnostics.packets_checked);
        try std.testing.expect(!attempt.peer_probe_received and !attempt.local_probe_acknowledged);
    }
}

test "validated driver acknowledges a retransmit after its first ACK is lost" {
    const wire = @import("punch_wire.zig");
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    const local = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer local.close(io);
    const peer = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer peer.close(io);
    const config = punch_attempt.Config{ .initial_retry_ms = 30, .maximum_retry_ms = 60 };
    var attempt = try punch_attempt.PunchAttempt.init(.{0x42} ** 32, .{0x11} ** 16, .{0xa1} ** 16, config);
    var peer_attempt = try punch_attempt.PunchAttempt.init(.{0x42} ** 32, .{0x11} ** 16, .{0xb2} ** 16, config);
    var task = TestRun{ .io = io, .socket = local, .remote = peer.address, .attempt = &attempt };
    var pending: std.Io.Group = .init;
    defer pending.cancel(io);
    try pending.concurrent(io, TestRun.start, .{&task});
    var buffer: [256]u8 = undefined;
    const timeout = std.Io.Timeout{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(300) } };
    const probe = try peer.receiveTimeout(io, &buffer, timeout);
    const local_ack = (try peer_attempt.receive(probe.data)).acknowledgement.?;
    const peer_probe = peer_attempt.nextProbe(0).?;
    try peer.send(io, &local.address, &peer_probe);
    const lost_ack = try peer.receiveTimeout(io, &buffer, timeout);
    try std.testing.expectEqual(wire.Kind.acknowledgement, (try wire.decode(attempt.key, lost_ack.data)).kind);
    // Drop this ACK, then validate the local side only.
    try peer.send(io, &local.address, &local_ack);
    try io.sleep(.fromMilliseconds(30), .awake);
    try peer.send(io, &local.address, &peer_attempt.nextProbe(30).?);
    const retry_ack = try peer.receiveTimeout(io, &buffer, timeout);
    _ = try peer_attempt.receive(retry_ack.data);
    try std.testing.expectEqual(punch_attempt.State.validated, peer_attempt.state);
    // Repeated peer traffic must not extend the finishing deadline.
    const finishing_started = std.Io.Timestamp.now(io, .awake);
    while (!task.finished.load(.acquire) and
        elapsedMilliseconds(finishing_started, std.Io.Timestamp.now(io, .awake)) < 400)
    {
        try peer.send(io, &local.address, &peer_probe);
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    try std.testing.expect(task.finished.load(.acquire));
    try pending.await(io);
    try std.testing.expectEqual(@as(?anyerror, null), task.failure);
    try std.testing.expectEqual(punch_attempt.State.validated, attempt.state);
}

test "driver propagates cancellation without waiting for probe retry" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    const local = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer local.close(io);
    const peer = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer peer.close(io);
    var attempt = try punch_attempt.PunchAttempt.init(.{0x42} ** 32, .{0x11} ** 16, .{0xa1} ** 16, .{
        .initial_retry_ms = 500,
        .maximum_retry_ms = 500,
        .max_attempts = 1,
    });
    var task = TestRun{ .io = io, .socket = local, .remote = peer.address, .attempt = &attempt };
    var pending: std.Io.Group = .init;
    defer pending.cancel(io);
    try pending.concurrent(io, TestRun.start, .{&task});
    var buffer: [256]u8 = undefined;
    _ = try peer.receiveTimeout(io, &buffer, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(300) } });
    const started = std.Io.Timestamp.now(io, .awake);
    pending.cancel(io);
    try std.testing.expectEqual(@as(?anyerror, error.Canceled), task.failure);
    try std.testing.expect(elapsedMilliseconds(started, std.Io.Timestamp.now(io, .awake)) < 250);
}
