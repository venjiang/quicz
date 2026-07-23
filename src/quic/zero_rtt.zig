//! 0-RTT session resumption flow (RFC 9001 §4.6).
//!
//! Implements the complete 0-RTT flow: session ticket storage,
//! PSK-based handshake resumption, 0-RTT data sending, and
//! replay protection.

const std = @import("std");
const session_cache = @import("session_cache.zig");
const tls13 = @import("../tls/tls13.zig");

/// 0-RTT resumption state for a client connection.
pub const ZeroRttState = enum {
    /// No resumption attempted.
    none,
    /// PSK offered in ClientHello, waiting for server acceptance.
    offered,
    /// Server accepted 0-RTT, early data can be sent.
    accepted,
    /// Server rejected 0-RTT, fall back to full handshake.
    rejected,
};

/// 0-RTT replay protection using a monotonic timestamp.
pub const ReplayProtection = struct {
    /// Last accepted 0-RTT timestamp per server.
    last_timestamps: std.ArrayList(struct { server_id: []const u8, timestamp: i64 }) = .empty,
    allocator: std.mem.Allocator,
    /// Maximum clock skew tolerance in seconds.
    max_clock_skew_sec: i64 = 10,

    pub fn init(allocator: std.mem.Allocator) ReplayProtection {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ReplayProtection) void {
        for (self.last_timestamps.items) |entry| {
            self.allocator.free(entry.server_id);
        }
        self.last_timestamps.deinit(self.allocator);
    }

    /// Check if a 0-RTT attempt is a replay.
    /// Returns true if the attempt is valid (not a replay).
    pub fn validateAttempt(self: *ReplayProtection, server_id: []const u8, now_sec: i64) !bool {
        for (self.last_timestamps.items) |*entry| {
            if (std.mem.eql(u8, entry.server_id, server_id)) {
                // Reject if timestamp is not strictly increasing
                if (now_sec <= entry.timestamp) return false;
                // Reject if clock skew is too large
                if (now_sec - entry.timestamp > self.max_clock_skew_sec * 100) return false;
                entry.timestamp = now_sec;
                return true;
            }
        }
        // First attempt for this server
        const id = try self.allocator.dupe(u8, server_id);
        try self.last_timestamps.append(self.allocator, .{
            .server_id = id,
            .timestamp = now_sec,
        });
        return true;
    }
};

/// 0-RTT resumption manager: coordinates session cache, PSK derivation,
/// and replay protection.
pub const ResumptionManager = struct {
    cache: session_cache.SessionCache,
    replay: ReplayProtection,
    state: ZeroRttState = .none,
    /// PSK for the current resumption attempt.
    current_psk: ?[32]u8 = null,
    /// Whether 0-RTT data has been sent.
    early_data_sent: bool = false,

    pub fn init(allocator: std.mem.Allocator) ResumptionManager {
        return .{
            .cache = session_cache.SessionCache.init(allocator),
            .replay = ReplayProtection.init(allocator),
        };
    }

    pub fn deinit(self: *ResumptionManager) void {
        self.cache.deinit();
        self.replay.deinit();
    }

    /// Attempt 0-RTT resumption for a server.
    /// Returns the PSK if a valid session ticket exists.
    pub fn attemptResumption(self: *ResumptionManager, server_id: []const u8, now_sec: i64) ?[32]u8 {
        const ticket = self.cache.retrieve(server_id, now_sec) orelse {
            self.state = .none;
            return null;
        };
        if (!ticket.allows_early_data) {
            self.state = .none;
            return null;
        }
        // Check replay protection
        const valid = self.replay.validateAttempt(server_id, now_sec) catch {
            self.state = .none;
            return null;
        };
        if (!valid) {
            self.state = .rejected;
            return null;
        }
        self.state = .offered;
        self.current_psk = ticket.psk;
        return ticket.psk;
    }

    /// Record server acceptance of 0-RTT.
    pub fn onServerAccepted(self: *ResumptionManager) void {
        if (self.state == .offered) {
            self.state = .accepted;
        }
    }

    /// Record server rejection of 0-RTT.
    pub fn onServerRejected(self: *ResumptionManager) void {
        self.state = .rejected;
        self.current_psk = null;
    }

    /// Whether 0-RTT data can be sent.
    pub fn canSendEarlyData(self: *const ResumptionManager) bool {
        return self.state == .offered or self.state == .accepted;
    }

    /// Mark early data as sent.
    pub fn markEarlyDataSent(self: *ResumptionManager) void {
        self.early_data_sent = true;
    }
};

test "ResumptionManager full 0-RTT flow" {
    var mgr = ResumptionManager.init(std.testing.allocator);
    defer mgr.deinit();

    // Store a session ticket
    const server_id = try std.testing.allocator.dupe(u8, "example.com:443");
    const nonce = try std.testing.allocator.dupe(u8, "nonce1");
    try mgr.cache.store(.{
        .server_id = server_id,
        .psk = [_]u8{0xaa} ** 32,
        .lifetime_sec = 3600,
        .age_add = 123,
        .nonce = nonce,
        .allows_early_data = true,
        .created_at_sec = 1000,
    });

    // Attempt resumption
    const psk = mgr.attemptResumption("example.com:443", 1001);
    try std.testing.expect(psk != null);
    try std.testing.expectEqual(ZeroRttState.offered, mgr.state);
    try std.testing.expect(mgr.canSendEarlyData());

    // Server accepts
    mgr.onServerAccepted();
    try std.testing.expectEqual(ZeroRttState.accepted, mgr.state);
    try std.testing.expect(mgr.canSendEarlyData());

    // Send early data
    mgr.markEarlyDataSent();
    try std.testing.expect(mgr.early_data_sent);
}

test "ResumptionManager no ticket" {
    var mgr = ResumptionManager.init(std.testing.allocator);
    defer mgr.deinit();

    const psk = mgr.attemptResumption("unknown.com:443", 1000);
    try std.testing.expect(psk == null);
    try std.testing.expectEqual(ZeroRttState.none, mgr.state);
    try std.testing.expect(!mgr.canSendEarlyData());
}

test "ResumptionManager server rejects" {
    var mgr = ResumptionManager.init(std.testing.allocator);
    defer mgr.deinit();

    const server_id = try std.testing.allocator.dupe(u8, "example.com:443");
    const nonce = try std.testing.allocator.dupe(u8, "nonce2");
    try mgr.cache.store(.{
        .server_id = server_id,
        .psk = [_]u8{0xbb} ** 32,
        .lifetime_sec = 3600,
        .age_add = 0,
        .nonce = nonce,
        .allows_early_data = true,
        .created_at_sec = 1000,
    });

    _ = mgr.attemptResumption("example.com:443", 1001);
    try std.testing.expectEqual(ZeroRttState.offered, mgr.state);

    mgr.onServerRejected();
    try std.testing.expectEqual(ZeroRttState.rejected, mgr.state);
    try std.testing.expect(!mgr.canSendEarlyData());
}

test "ReplayProtection rejects replay" {
    var rp = ReplayProtection.init(std.testing.allocator);
    defer rp.deinit();

    // First attempt: valid
    try std.testing.expect(try rp.validateAttempt("server1", 1000));
    // Same timestamp: replay
    try std.testing.expect(!try rp.validateAttempt("server1", 1000));
    // Earlier timestamp: replay
    try std.testing.expect(!try rp.validateAttempt("server1", 999));
    // Later timestamp: valid
    try std.testing.expect(try rp.validateAttempt("server1", 1001));
}

test "ResumptionManager ticket without early data" {
    var mgr = ResumptionManager.init(std.testing.allocator);
    defer mgr.deinit();

    const server_id = try std.testing.allocator.dupe(u8, "noearly.com:443");
    const nonce = try std.testing.allocator.dupe(u8, "nonce3");
    try mgr.cache.store(.{
        .server_id = server_id,
        .psk = [_]u8{0xcc} ** 32,
        .lifetime_sec = 3600,
        .age_add = 0,
        .nonce = nonce,
        .allows_early_data = false,
        .created_at_sec = 1000,
    });

    const psk = mgr.attemptResumption("noearly.com:443", 1001);
    try std.testing.expect(psk == null);
    try std.testing.expectEqual(ZeroRttState.none, mgr.state);
}
