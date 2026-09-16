//! Bounded, idempotent UDP hole-punch attempt state machine.

const std = @import("std");
const wire = @import("punch_wire.zig");

pub const State = enum {
    probing,
    validated,
    failed,
};

pub const Config = struct {
    initial_retry_ms: u32 = 100,
    maximum_retry_ms: u32 = 1_000,
    max_attempts: u8 = 5,
};

pub const ReceiveResult = struct {
    acknowledgement: ?[wire.packet_length]u8 = null,
    became_validated: bool = false,
};

/// Bounded observations for one attempt. Counters never affect validation or
/// retry decisions and retain no endpoints, packet bodies, nonces or keys.
/// Socket-level fields are populated by punch_driver; receive() records checks.
pub const Diagnostics = struct {
    probe_sends: u32 = 0,
    acknowledgement_sends: u32 = 0,
    datagrams_received: u32 = 0,
    source_rejected: u32 = 0,
    oversized_received: u32 = 0,
    packets_checked: u32 = 0,
    malformed_rejected: u32 = 0,
    authentication_rejected: u32 = 0,
    attempt_rejected: u32 = 0,
    nonce_rejected: u32 = 0,
};

pub const PunchAttempt = struct {
    key: wire.Key,
    attempt_id: wire.AttemptId,
    local_nonce: wire.Nonce,
    config: Config,
    state: State = .probing,
    probes_sent: u8 = 0,
    next_probe_ms: u64 = 0,
    peer_probe_received: bool = false,
    local_probe_acknowledged: bool = false,
    diagnostics: Diagnostics = .{},

    pub fn init(
        key: wire.Key,
        attempt_id: wire.AttemptId,
        local_nonce: wire.Nonce,
        config: Config,
    ) !PunchAttempt {
        if (config.initial_retry_ms == 0 or
            config.maximum_retry_ms < config.initial_retry_ms or
            config.max_attempts == 0 or
            config.max_attempts > 5) return error.InvalidPunchConfig;
        return .{
            .key = key,
            .attempt_id = attempt_id,
            .local_nonce = local_nonce,
            .config = config,
        };
    }

    /// Return the next probe when due. Call `advance` even when this returns
    /// null so an exhausted attempt can transition to failed.
    pub fn nextProbe(self: *PunchAttempt, now_ms: u64) ?[wire.packet_length]u8 {
        self.advance(now_ms);
        if (self.state != .probing or self.probes_sent >= self.config.max_attempts) return null;
        if (self.probes_sent > 0 and now_ms < self.next_probe_ms) return null;

        self.probes_sent += 1;
        self.next_probe_ms = std.math.add(u64, now_ms, self.retryDelayMs()) catch std.math.maxInt(u64);
        return wire.encode(self.key, .{
            .kind = .probe,
            .attempt_id = self.attempt_id,
            .nonce = self.local_nonce,
        });
    }

    pub fn receive(self: *PunchAttempt, packet: []const u8) !ReceiveResult {
        if (self.state == .failed) return error.PunchAttemptFailed;
        self.diagnostics.packets_checked +|= 1;
        const message = wire.decode(self.key, packet) catch |err| {
            if (err == error.AuthenticationFailed) {
                self.diagnostics.authentication_rejected +|= 1;
            } else {
                self.diagnostics.malformed_rejected +|= 1;
            }
            return err;
        };
        if (!std.mem.eql(u8, &message.attempt_id, &self.attempt_id)) {
            self.diagnostics.attempt_rejected +|= 1;
            return error.AttemptMismatch;
        }

        var result = ReceiveResult{};
        switch (message.kind) {
            .probe => {
                // A reflected local probe proves no participation by the peer.
                if (std.mem.eql(u8, &message.nonce, &self.local_nonce)) {
                    self.diagnostics.nonce_rejected +|= 1;
                    return error.NonceMismatch;
                }
                self.peer_probe_received = true;
                result.acknowledgement = try wire.acknowledgement(self.key, message);
            },
            .acknowledgement => {
                if (self.probes_sent == 0 or !std.mem.eql(u8, &message.nonce, &self.local_nonce)) {
                    self.diagnostics.nonce_rejected +|= 1;
                    return error.NonceMismatch;
                }
                self.local_probe_acknowledged = true;
            },
        }
        if (self.state == .probing and self.peer_probe_received and self.local_probe_acknowledged) {
            self.state = .validated;
            result.became_validated = true;
        }
        return result;
    }

    pub fn advance(self: *PunchAttempt, now_ms: u64) void {
        if (self.state != .probing) return;
        if (self.probes_sent == self.config.max_attempts and now_ms >= self.next_probe_ms) {
            self.state = .failed;
        }
    }

    fn retryDelayMs(self: *const PunchAttempt) u32 {
        const shift: u5 = @intCast(@min(self.probes_sent - 1, 15));
        const scaled = std.math.shlExact(u32, self.config.initial_retry_ms, shift) catch self.config.maximum_retry_ms;
        return @min(scaled, self.config.maximum_retry_ms);
    }
};

test "punch diagnostics separate rejected proofs without changing validation" {
    const key: wire.Key = @splat(0x42);
    const id: wire.AttemptId = @splat(0x11);
    const local_nonce: wire.Nonce = @splat(0xa1);
    const peer_nonce: wire.Nonce = @splat(0xb2);
    var attempt = try PunchAttempt.init(key, id, local_nonce, .{});
    _ = attempt.nextProbe(0);
    const wrong_mac = wire.encode(@splat(0x43), .{ .kind = .probe, .attempt_id = id, .nonce = peer_nonce });
    const wrong_attempt = wire.encode(key, .{ .kind = .probe, .attempt_id = @splat(0x12), .nonce = peer_nonce });
    const wrong_nonce = wire.encode(key, .{ .kind = .acknowledgement, .attempt_id = id, .nonce = peer_nonce });
    try std.testing.expectError(error.AuthenticationFailed, attempt.receive(&wrong_mac));
    try std.testing.expectError(error.AttemptMismatch, attempt.receive(&wrong_attempt));
    try std.testing.expectError(error.NonceMismatch, attempt.receive(&wrong_nonce));
    try std.testing.expectError(error.InvalidPacketLength, attempt.receive("invalid"));
    try std.testing.expectEqual(State.probing, attempt.state);
    try std.testing.expect(!attempt.peer_probe_received and !attempt.local_probe_acknowledged);
    try std.testing.expectEqual(@as(u32, 4), attempt.diagnostics.packets_checked);
    try std.testing.expectEqual(@as(u32, 1), attempt.diagnostics.authentication_rejected);
    try std.testing.expectEqual(@as(u32, 1), attempt.diagnostics.attempt_rejected);
    try std.testing.expectEqual(@as(u32, 1), attempt.diagnostics.nonce_rejected);
    try std.testing.expectEqual(@as(u32, 1), attempt.diagnostics.malformed_rejected);
    const peer_probe = wire.encode(key, .{ .kind = .probe, .attempt_id = id, .nonce = peer_nonce });
    try std.testing.expect((try attempt.receive(&peer_probe)).acknowledgement != null);
    const acknowledgement = wire.encode(key, .{ .kind = .acknowledgement, .attempt_id = id, .nonce = local_nonce });
    try std.testing.expect((try attempt.receive(&acknowledgement)).became_validated);
    try std.testing.expectEqual(@as(u32, 6), attempt.diagnostics.packets_checked);
}

test "both authenticated directions are required before validation" {
    const key: wire.Key = .{0x42} ** 32;
    const attempt_id: wire.AttemptId = .{0x11} ** 16;
    var app = try PunchAttempt.init(key, attempt_id, .{0xa1} ** 16, .{});
    var host = try PunchAttempt.init(key, attempt_id, .{0xb2} ** 16, .{});
    const app_probe = app.nextProbe(0).?;
    const host_probe = host.nextProbe(0).?;

    const host_result = try host.receive(&app_probe);
    const app_result = try app.receive(&host_probe);
    try std.testing.expect(!host_result.became_validated);
    try std.testing.expect(!app_result.became_validated);
    try std.testing.expectEqual(State.probing, app.state);
    try std.testing.expectEqual(State.probing, host.state);

    try std.testing.expect((try app.receive(&host_result.acknowledgement.?)).became_validated);
    try std.testing.expect((try host.receive(&app_result.acknowledgement.?)).became_validated);
    try std.testing.expectEqual(State.validated, app.state);
    try std.testing.expectEqual(State.validated, host.state);
}

test "retry schedule is bounded to five attempts" {
    var attempt = try PunchAttempt.init(
        .{0x42} ** 32,
        .{0x11} ** 16,
        .{0xa1} ** 16,
        .{ .initial_retry_ms = 100, .maximum_retry_ms = 250, .max_attempts = 5 },
    );
    try std.testing.expect(attempt.nextProbe(0) != null);
    try std.testing.expect(attempt.nextProbe(99) == null);
    try std.testing.expect(attempt.nextProbe(100) != null);
    try std.testing.expect(attempt.nextProbe(299) == null);
    try std.testing.expect(attempt.nextProbe(300) != null);
    try std.testing.expect(attempt.nextProbe(550) != null);
    try std.testing.expect(attempt.nextProbe(800) != null);
    try std.testing.expect(attempt.nextProbe(1_049) == null);
    attempt.advance(1_050);
    try std.testing.expectEqual(State.failed, attempt.state);
    try std.testing.expect(attempt.nextProbe(2_000) == null);
}

test "old attempt and wrong acknowledgement nonce are rejected" {
    const key: wire.Key = .{0x42} ** 32;
    var attempt = try PunchAttempt.init(key, .{0x11} ** 16, .{0xa1} ** 16, .{});
    _ = attempt.nextProbe(0).?;
    const old_attempt = wire.encode(key, .{
        .kind = .probe,
        .attempt_id = .{0x10} ** 16,
        .nonce = .{0xb2} ** 16,
    });
    try std.testing.expectError(error.AttemptMismatch, attempt.receive(&old_attempt));
    const wrong_ack = wire.encode(key, .{
        .kind = .acknowledgement,
        .attempt_id = .{0x11} ** 16,
        .nonce = .{0xff} ** 16,
    });
    try std.testing.expectError(error.NonceMismatch, attempt.receive(&wrong_ack));
}

test "probe retransmission remains idempotent" {
    const key: wire.Key = .{0x42} ** 32;
    var app = try PunchAttempt.init(key, .{0x11} ** 16, .{0xa1} ** 16, .{});
    var host = try PunchAttempt.init(key, .{0x11} ** 16, .{0xb2} ** 16, .{});
    const first = app.nextProbe(0).?;
    const second = app.nextProbe(100).?;
    const first_ack = (try host.receive(&first)).acknowledgement.?;
    const second_ack = (try host.receive(&second)).acknowledgement.?;
    try std.testing.expectEqualSlices(u8, &first_ack, &second_ack);
}

test "reflected local probe cannot authenticate a peer" {
    var attempt = try PunchAttempt.init(.{0x42} ** 32, .{0x11} ** 16, .{0xa1} ** 16, .{});
    const probe = attempt.nextProbe(0).?;
    try std.testing.expectError(error.NonceMismatch, attempt.receive(&probe));
    try std.testing.expect(!attempt.peer_probe_received);
    try std.testing.expect(!attempt.local_probe_acknowledged);
    try std.testing.expectEqual(State.probing, attempt.state);
}
