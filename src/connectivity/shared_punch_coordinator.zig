//! Concurrent authenticated punch state for one caller-owned UDP socket.
//!
//! The coordinator never reads or writes a socket itself. Its owner calls
//! `next` until idle, sends returned packets, and feeds every received packet
//! back through `receive`. That preserves one socket reader while keeping
//! attempt keys, remotes, deadlines and completion isolated.

const std = @import("std");
const wire = @import("punch_wire.zig");
const punch_attempt = @import("punch_attempt.zig");

pub const Error = error{
    InvalidCapacity,
    AttemptAlreadyRegistered,
    CapacityExceeded,
    AttemptNotValidated,
};

pub const RegisteredAttempt = struct {
    remote: std.Io.net.IpAddress,
    punch: punch_attempt.PunchAttempt,
    started_ms: u64,
    failure_reported: bool = false,

    pub fn deinit(self: *RegisteredAttempt) void {
        std.crypto.secureZero(u8, &self.punch.key);
        @memset(&self.punch.attempt_id, 0);
        @memset(&self.punch.local_nonce, 0);
        self.* = undefined;
    }
};

pub const Outbound = struct {
    attempt_id: wire.AttemptId,
    destination: std.Io.net.IpAddress,
    packet: [wire.packet_length]u8,
};

pub const Event = union(enum) {
    idle,
    probe: Outbound,
    acknowledgement: Outbound,
    validated: wire.AttemptId,
    failed: wire.AttemptId,
};

pub const SharedPunchCoordinator = struct {
    allocator: std.mem.Allocator,
    maximum: usize,
    mutex: std.atomic.Mutex = .unlocked,
    attempts: std.AutoHashMap(wire.AttemptId, RegisteredAttempt),

    pub fn init(allocator: std.mem.Allocator, maximum: usize) Error!SharedPunchCoordinator {
        if (maximum == 0) return error.InvalidCapacity;
        return .{
            .allocator = allocator,
            .maximum = maximum,
            .attempts = std.AutoHashMap(wire.AttemptId, RegisteredAttempt).init(allocator),
        };
    }

    /// Takes ownership of the punch attempt on success and clears it on error.
    pub fn register(
        coordinator: *SharedPunchCoordinator,
        remote: std.Io.net.IpAddress,
        punch_value: punch_attempt.PunchAttempt,
        started_ms: u64,
    ) !void {
        var punch = punch_value;
        coordinator.lock();
        defer coordinator.mutex.unlock();
        if (remote.getPort() == 0) {
            clearPunch(&punch);
            return error.InvalidEndpoint;
        }
        if (coordinator.attempts.contains(punch.attempt_id)) {
            clearPunch(&punch);
            return error.AttemptAlreadyRegistered;
        }
        if (coordinator.attempts.count() >= coordinator.maximum) {
            clearPunch(&punch);
            return error.CapacityExceeded;
        }
        coordinator.attempts.put(punch.attempt_id, .{ .remote = remote, .punch = punch, .started_ms = started_ms }) catch |err| {
            clearPunch(&punch);
            return err;
        };
    }

    /// Produces one due probe or one failure notification. Call repeatedly at
    /// the same timestamp until idle before sleeping until the next deadline.
    pub fn next(coordinator: *SharedPunchCoordinator, now_ms: u64) Event {
        coordinator.lock();
        defer coordinator.mutex.unlock();
        var iterator = coordinator.attempts.valueIterator();
        while (iterator.next()) |attempt| {
            const elapsed = now_ms -| attempt.started_ms;
            if (attempt.punch.nextProbe(elapsed)) |packet| {
                attempt.punch.diagnostics.probe_sends +|= 1;
                return .{ .probe = .{
                    .attempt_id = attempt.punch.attempt_id,
                    .destination = attempt.remote,
                    .packet = packet,
                } };
            }
            if (attempt.punch.state == .failed and !attempt.failure_reported) {
                attempt.failure_reported = true;
                return .{ .failed = attempt.punch.attempt_id };
            }
        }
        return .idle;
    }

    /// Absolute awake-clock deadline for the next probe or failure transition.
    pub fn nextDeadlineMs(coordinator: *SharedPunchCoordinator) ?u64 {
        coordinator.lock();
        defer coordinator.mutex.unlock();
        var iterator = coordinator.attempts.valueIterator();
        var earliest: ?u64 = null;
        while (iterator.next()) |attempt| {
            if (attempt.punch.state != .probing) continue;
            const deadline = std.math.add(u64, attempt.started_ms, attempt.punch.next_probe_ms) catch std.math.maxInt(u64);
            if (earliest == null or deadline < earliest.?) earliest = deadline;
        }
        return earliest;
    }

    /// Consumes only packets for a registered, authenticated attempt from its
    /// nominated remote. Unrecognized traffic remains available to QUIC.
    pub fn receive(
        coordinator: *SharedPunchCoordinator,
        from: std.Io.net.IpAddress,
        now_ms: u64,
        packet: []const u8,
    ) Event {
        coordinator.lock();
        defer coordinator.mutex.unlock();
        const attempt_id = wire.routingAttemptId(packet) catch return .idle;
        const attempt = coordinator.attempts.getPtr(attempt_id) orelse return .idle;
        if (!sameAddress(from, attempt.remote)) {
            attempt.punch.diagnostics.source_rejected +|= 1;
            return .idle;
        }
        attempt.punch.diagnostics.datagrams_received +|= 1;
        const result = attempt.punch.receive(packet) catch return .idle;
        if (result.acknowledgement) |acknowledgement| {
            attempt.punch.diagnostics.acknowledgement_sends +|= 1;
            return .{ .acknowledgement = .{
                .attempt_id = attempt_id,
                .destination = attempt.remote,
                .packet = acknowledgement,
            } };
        }
        if (result.became_validated) return .{ .validated = attempt_id };
        _ = now_ms;
        return .idle;
    }

    /// Transfers a verified attempt to a QUIC runtime or a late responder.
    pub fn takeValidated(coordinator: *SharedPunchCoordinator, attempt_id: wire.AttemptId) Error!RegisteredAttempt {
        coordinator.lock();
        defer coordinator.mutex.unlock();
        const entry = coordinator.attempts.getPtr(attempt_id) orelse return error.AttemptNotValidated;
        if (entry.punch.state != .validated) return error.AttemptNotValidated;
        return coordinator.attempts.fetchRemove(attempt_id).?.value;
    }

    pub fn remove(coordinator: *SharedPunchCoordinator, attempt_id: wire.AttemptId) bool {
        coordinator.lock();
        defer coordinator.mutex.unlock();
        if (coordinator.attempts.fetchRemove(attempt_id)) |entry| {
            var attempt = entry.value;
            attempt.deinit();
            return true;
        }
        return false;
    }

    pub fn deinit(coordinator: *SharedPunchCoordinator) void {
        coordinator.lock();
        var iterator = coordinator.attempts.valueIterator();
        while (iterator.next()) |attempt| attempt.deinit();
        coordinator.attempts.deinit();
        coordinator.mutex.unlock();
        coordinator.* = undefined;
    }

    fn lock(coordinator: *SharedPunchCoordinator) void {
        while (!coordinator.mutex.tryLock()) std.atomic.spinLoopHint();
    }
};

fn clearPunch(punch: *punch_attempt.PunchAttempt) void {
    std.crypto.secureZero(u8, &punch.key);
    @memset(&punch.attempt_id, 0);
    @memset(&punch.local_nonce, 0);
}

fn sameAddress(left: std.Io.net.IpAddress, right: std.Io.net.IpAddress) bool {
    return switch (left) {
        .ip4 => |value| switch (right) {
            .ip4 => |other| value.port == other.port and std.mem.eql(u8, &value.bytes, &other.bytes),
            .ip6 => false,
        },
        .ip6 => |value| switch (right) {
            .ip4 => false,
            .ip6 => |other| value.port == other.port and std.mem.eql(u8, &value.bytes, &other.bytes),
        },
    };
}

test "shared coordinator isolates concurrent attempts on one receive loop" {
    const first_remote = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 4_001 } };
    const second_remote = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 2 }, .port = 4_002 } };
    var coordinator = try SharedPunchCoordinator.init(std.testing.allocator, 2);
    defer coordinator.deinit();
    try coordinator.register(first_remote, try .init(.{0x41} ** 32, .{0x11} ** 16, .{0xa1} ** 16, .{}), 0);
    try coordinator.register(second_remote, try .init(.{0x42} ** 32, .{0x22} ** 16, .{0xa2} ** 16, .{}), 0);

    const first_probe = switch (coordinator.next(0)) {
        .probe => |outbound| outbound,
        else => return error.ExpectedProbe,
    };
    const second_probe = switch (coordinator.next(0)) {
        .probe => |outbound| outbound,
        else => return error.ExpectedProbe,
    };
    try std.testing.expect(!std.mem.eql(u8, &first_probe.attempt_id, &second_probe.attempt_id));

    const first_remote_probe = wire.encode(.{0x41} ** 32, .{ .kind = .probe, .attempt_id = .{0x11} ** 16, .nonce = .{0xb1} ** 16 });
    const second_remote_probe = wire.encode(.{0x42} ** 32, .{ .kind = .probe, .attempt_id = .{0x22} ** 16, .nonce = .{0xb2} ** 16 });
    const first_ack = switch (coordinator.receive(first_remote, 1, &first_remote_probe)) {
        .acknowledgement => |outbound| outbound,
        else => return error.ExpectedAcknowledgement,
    };
    const second_ack = switch (coordinator.receive(second_remote, 1, &second_remote_probe)) {
        .acknowledgement => |outbound| outbound,
        else => return error.ExpectedAcknowledgement,
    };
    try std.testing.expectEqual(@as([16]u8, @splat(0x11)), (try wire.decode(.{0x41} ** 32, &first_ack.packet)).attempt_id);
    try std.testing.expectEqual(@as([16]u8, @splat(0x22)), (try wire.decode(.{0x42} ** 32, &second_ack.packet)).attempt_id);

    const first_acknowledgement = wire.encode(.{0x41} ** 32, .{ .kind = .acknowledgement, .attempt_id = .{0x11} ** 16, .nonce = .{0xa1} ** 16 });
    const second_acknowledgement = wire.encode(.{0x42} ** 32, .{ .kind = .acknowledgement, .attempt_id = .{0x22} ** 16, .nonce = .{0xa2} ** 16 });
    try std.testing.expectEqual(Event{ .validated = .{0x11} ** 16 }, coordinator.receive(first_remote, 2, &first_acknowledgement));
    try std.testing.expectEqual(Event{ .validated = .{0x22} ** 16 }, coordinator.receive(second_remote, 2, &second_acknowledgement));
    var first = try coordinator.takeValidated(.{0x11} ** 16);
    defer first.deinit();
    var second = try coordinator.takeValidated(.{0x22} ** 16);
    defer second.deinit();
    try std.testing.expectEqual(first_remote, first.remote);
    try std.testing.expectEqual(second_remote, second.remote);
}

test "shared coordinator rejects wrong source and cancellation does not cross attempts" {
    const remote = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 4_001 } };
    const other = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 2 }, .port = 4_002 } };
    var coordinator = try SharedPunchCoordinator.init(std.testing.allocator, 2);
    defer coordinator.deinit();
    try coordinator.register(remote, try .init(.{0x41} ** 32, .{0x11} ** 16, .{0xa1} ** 16, .{}), 0);
    try coordinator.register(other, try .init(.{0x42} ** 32, .{0x22} ** 16, .{0xa2} ** 16, .{}), 0);
    const first_probe = wire.encode(.{0x41} ** 32, .{ .kind = .probe, .attempt_id = .{0x11} ** 16, .nonce = .{0xb1} ** 16 });
    try std.testing.expectEqual(Event.idle, coordinator.receive(other, 1, &first_probe));
    try std.testing.expect(coordinator.remove(.{0x11} ** 16));
    const second_probe = wire.encode(.{0x42} ** 32, .{ .kind = .probe, .attempt_id = .{0x22} ** 16, .nonce = .{0xb2} ** 16 });
    try std.testing.expect(coordinator.receive(other, 1, &second_probe) != .idle);
}

test "shared coordinator exposes absolute probe deadlines" {
    const remote = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 4_001 } };
    var coordinator = try SharedPunchCoordinator.init(std.testing.allocator, 1);
    defer coordinator.deinit();
    try coordinator.register(remote, try .init(.{0x41} ** 32, .{0x11} ** 16, .{0xa1} ** 16, .{
        .initial_retry_ms = 100,
        .maximum_retry_ms = 200,
        .max_attempts = 2,
    }), 1_000);
    try std.testing.expectEqual(@as(?u64, 1_000), coordinator.nextDeadlineMs());
    try std.testing.expect(coordinator.next(1_000) == .probe);
    try std.testing.expectEqual(@as(?u64, 1_100), coordinator.nextDeadlineMs());
    try std.testing.expect(coordinator.next(1_100) == .probe);
    try std.testing.expectEqual(@as(?u64, 1_300), coordinator.nextDeadlineMs());
    try std.testing.expect(coordinator.next(1_300) == .failed);
}
