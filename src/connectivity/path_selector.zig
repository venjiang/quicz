//! Connectivity-path selection above the QUIC transport.
//!
//! A selector belongs to one logical managed connection. It does not own
//! application sessions and never interprets application payloads.

const std = @import("std");

pub const PathKind = enum {
    direct,
    relay_datagram,
    relay_stream,
};

pub const PathStatus = enum {
    probing,
    validated,
    failed,
};

pub const PathCandidate = struct {
    id: u64,
    kind: PathKind,
    status: PathStatus = .probing,
    smoothed_rtt_ms: ?u32 = null,
};

pub const PathChange = union(enum) {
    unchanged,
    selected: u64,
    migrated: struct {
        previous: u64,
        current: u64,
    },
    unavailable,
};

pub const Config = struct {
    /// Avoid migration for small RTT fluctuations on an otherwise healthy path.
    minimum_improvement_ms: u32 = 10,
};

pub const PathSelector = struct {
    allocator: std.mem.Allocator,
    config: Config,
    candidates: std.ArrayList(PathCandidate) = .empty,
    selected_id: ?u64 = null,

    pub fn init(allocator: std.mem.Allocator, config: Config) PathSelector {
        return .{ .allocator = allocator, .config = config };
    }

    pub fn deinit(self: *PathSelector) void {
        self.candidates.deinit(self.allocator);
    }

    pub fn addCandidate(self: *PathSelector, id: u64, kind: PathKind) !void {
        if (self.find(id) != null) return error.DuplicatePath;
        try self.candidates.append(self.allocator, .{ .id = id, .kind = kind });
    }

    pub fn recordValidated(self: *PathSelector, id: u64, smoothed_rtt_ms: u32) !PathChange {
        const candidate = self.find(id) orelse return error.UnknownPath;
        candidate.status = .validated;
        candidate.smoothed_rtt_ms = smoothed_rtt_ms;
        return self.reconcile();
    }

    pub fn recordFailed(self: *PathSelector, id: u64) !PathChange {
        const candidate = self.find(id) orelse return error.UnknownPath;
        candidate.status = .failed;
        candidate.smoothed_rtt_ms = null;
        return self.reconcile();
    }

    pub fn selected(self: *const PathSelector) ?PathCandidate {
        const selected_id = self.selected_id orelse return null;
        for (self.candidates.items) |candidate| {
            if (candidate.id == selected_id) return candidate;
        }
        return null;
    }

    fn find(self: *PathSelector, id: u64) ?*PathCandidate {
        for (self.candidates.items) |*candidate| {
            if (candidate.id == id) return candidate;
        }
        return null;
    }

    fn reconcile(self: *PathSelector) PathChange {
        const current = self.selected();
        const best = self.bestValidated() orelse {
            self.selected_id = null;
            return if (current == null) .unchanged else .unavailable;
        };

        if (current) |active| {
            if (active.status == .validated and active.smoothed_rtt_ms != null) {
                if (active.id == best.id or !isMeaningfullyBetter(best, active, self.config.minimum_improvement_ms)) {
                    return .unchanged;
                }
            }
            self.selected_id = best.id;
            return .{ .migrated = .{ .previous = active.id, .current = best.id } };
        }

        self.selected_id = best.id;
        return .{ .selected = best.id };
    }

    fn bestValidated(self: *const PathSelector) ?PathCandidate {
        var best: ?PathCandidate = null;
        for (self.candidates.items) |candidate| {
            if (candidate.status != .validated or candidate.smoothed_rtt_ms == null) continue;
            if (best == null or ranksBefore(candidate, best.?)) best = candidate;
        }
        return best;
    }
};

fn isMeaningfullyBetter(candidate: PathCandidate, current: PathCandidate, minimum_improvement_ms: u32) bool {
    const candidate_rtt = candidate.smoothed_rtt_ms.?;
    const current_rtt = current.smoothed_rtt_ms.?;
    if (candidate_rtt >= current_rtt) return false;
    if (current_rtt - candidate_rtt > minimum_improvement_ms) return true;
    return current_rtt - candidate_rtt == minimum_improvement_ms and kindRank(candidate.kind) < kindRank(current.kind);
}

fn ranksBefore(lhs: PathCandidate, rhs: PathCandidate) bool {
    const lhs_rtt = lhs.smoothed_rtt_ms.?;
    const rhs_rtt = rhs.smoothed_rtt_ms.?;
    if (lhs_rtt != rhs_rtt) return lhs_rtt < rhs_rtt;
    return kindRank(lhs.kind) < kindRank(rhs.kind);
}

fn kindRank(kind: PathKind) u8 {
    return switch (kind) {
        .direct => 0,
        .relay_datagram => 1,
        .relay_stream => 2,
    };
}

test "relay can serve immediately and later migrate to a faster direct path" {
    var selector = PathSelector.init(std.testing.allocator, .{});
    defer selector.deinit();
    try selector.addCandidate(1, .relay_stream);
    try selector.addCandidate(2, .direct);

    try std.testing.expectEqual(PathChange{ .selected = 1 }, try selector.recordValidated(1, 120));
    try std.testing.expectEqual(
        PathChange{ .migrated = .{ .previous = 1, .current = 2 } },
        try selector.recordValidated(2, 35),
    );
    try std.testing.expectEqual(@as(u64, 2), selector.selected().?.id);
}

test "failed direct probing does not disturb a validated relay path" {
    var selector = PathSelector.init(std.testing.allocator, .{});
    defer selector.deinit();
    try selector.addCandidate(1, .relay_stream);
    try selector.addCandidate(2, .direct);

    _ = try selector.recordValidated(1, 80);
    try std.testing.expectEqual(PathChange.unchanged, try selector.recordFailed(2));
    try std.testing.expectEqual(@as(u64, 1), selector.selected().?.id);
}

test "RTT hysteresis prevents path flapping" {
    var selector = PathSelector.init(std.testing.allocator, .{ .minimum_improvement_ms = 10 });
    defer selector.deinit();
    try selector.addCandidate(1, .relay_datagram);
    try selector.addCandidate(2, .direct);

    _ = try selector.recordValidated(1, 50);
    try std.testing.expectEqual(PathChange.unchanged, try selector.recordValidated(2, 45));
    try std.testing.expectEqual(@as(u64, 1), selector.selected().?.id);
}

test "failed active path falls back without waiting for probing candidates" {
    var selector = PathSelector.init(std.testing.allocator, .{});
    defer selector.deinit();
    try selector.addCandidate(1, .direct);
    try selector.addCandidate(2, .relay_stream);
    try selector.addCandidate(3, .direct);

    _ = try selector.recordValidated(1, 30);
    _ = try selector.recordValidated(2, 100);
    try std.testing.expectEqual(
        PathChange{ .migrated = .{ .previous = 1, .current = 2 } },
        try selector.recordFailed(1),
    );
    try std.testing.expectEqual(@as(u64, 2), selector.selected().?.id);
}

test "selector reports unavailable only after the active path fails" {
    var selector = PathSelector.init(std.testing.allocator, .{});
    defer selector.deinit();
    try selector.addCandidate(1, .direct);

    try std.testing.expectEqual(PathChange.unchanged, try selector.recordFailed(1));
    try selector.addCandidate(2, .relay_stream);
    _ = try selector.recordValidated(2, 90);
    try std.testing.expectEqual(PathChange.unavailable, try selector.recordFailed(2));
    try std.testing.expect(selector.selected() == null);
}

test "candidate identifiers are unique within one selector" {
    var selector = PathSelector.init(std.testing.allocator, .{});
    defer selector.deinit();
    try selector.addCandidate(7, .direct);
    try std.testing.expectError(error.DuplicatePath, selector.addCandidate(7, .relay_stream));
}
