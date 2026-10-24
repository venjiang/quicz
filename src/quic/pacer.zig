//! Token bucket pacer (RFC 9002 §7.7, learned from industry implementations).
//!
//! Gates packet emission to spread transmission over time, preventing
//! burst-induced loss on low-RTT paths. Budget replenishes at
//! pacing_rate = congestion_window / smoothed_rtt × 1.25.
//! Max burst = 10 packets (allows initial window to send immediately).
//!
//! All timestamps and RTT values are in nanoseconds for loopback precision.

const std = @import("std");

/// Maximum number of packets that can be sent in a single burst.
pub const max_burst_packets: usize = 10;

/// Token bucket pacer for QUIC packet transmission.
pub const Pacer = struct {
    /// Available send budget in bytes.
    budget: usize = 0,
    /// Timestamp (ns) of last packet send.
    last_sent_ns: ?i64 = null,
    /// Maximum datagram size in bytes.
    max_datagram_size: usize,

    pub fn init(max_datagram_size: usize) Pacer {
        var p = Pacer{
            .max_datagram_size = max_datagram_size,
        };
        p.budget = p.maxBurstSize();
        return p;
    }

    /// Maximum burst size in bytes (10 packets).
    pub fn maxBurstSize(self: *const Pacer) usize {
        return max_burst_packets * self.max_datagram_size;
    }

    /// Get current send budget in bytes, replenished since last send.
    ///
    /// Replenishment formula (all in nanoseconds):
    ///   added = cwnd × 5 × delta_ns / (srtt_ns × 4)
    /// This equals pacing_rate (cwnd/srtt × 1.25) × delta_time.
    pub fn budgetAt(self: *const Pacer, now_ns: i64, cwnd: usize, smoothed_rtt_ns: u64) usize {
        // No RTT sample yet: no pacing, allow full burst.
        if (smoothed_rtt_ns == 0) return self.maxBurstSize();
        const last = self.last_sent_ns orelse return self.maxBurstSize();
        const delta_ns: u64 = if (now_ns > last) @intCast(now_ns - last) else 0;
        if (delta_ns == 0) return self.budget;

        // added = cwnd * 1.25 * delta_ns / srtt_ns = cwnd * 5 * delta_ns / (srtt_ns * 4)
        const numerator: u128 = @as(u128, cwnd) * 5 * delta_ns;
        const denominator: u128 = @as(u128, smoothed_rtt_ns) * 4;
        const added: usize = @intCast(@min(numerator / denominator, std.math.maxInt(usize)));

        const new_budget = std.math.add(usize, self.budget, added) catch std.math.maxInt(usize);
        return @min(self.maxBurstSize(), new_budget);
    }

    /// Check if a packet of the given size can be sent now.
    pub fn canSend(self: *const Pacer, now_ns: i64, packet_size: usize, cwnd: usize, smoothed_rtt_ns: u64) bool {
        return self.budgetAt(now_ns, cwnd, smoothed_rtt_ns) >= packet_size;
    }

    /// Return the first representable time when this packet has enough budget.
    /// This query does not consume tokens. Null means no pacing wait is needed
    /// or the supplied clock/rate cannot represent a future send time.
    pub fn nextSendTime(self: *const Pacer, now_ns: i64, packet_size: usize, cwnd: usize, smoothed_rtt_ns: u64) ?i64 {
        if (cwnd == 0 or smoothed_rtt_ns == 0 or packet_size > self.maxBurstSize() or
            self.canSend(now_ns, packet_size, cwnd, smoothed_rtt_ns)) return null;
        const last = self.last_sent_ns orelse return null;
        const missing = packet_size - self.budget;
        const numerator = @as(u128, missing) * smoothed_rtt_ns * 4;
        const denominator = @as(u128, cwnd) * 5;
        const wait_ns = numerator / denominator + @intFromBool(numerator % denominator != 0);
        if (wait_ns > std.math.maxInt(i64)) return null;
        const deadline = std.math.add(i64, last, @intCast(wait_ns)) catch return null;
        return if (deadline > now_ns) deadline else null;
    }

    /// Record that a packet was sent, deducting from budget.
    pub fn onPacketSent(self: *Pacer, now_ns: i64, packet_size: usize, cwnd: usize, smoothed_rtt_ns: u64) void {
        const current_budget = self.budgetAt(now_ns, cwnd, smoothed_rtt_ns);
        self.budget = if (packet_size >= current_budget) 0 else current_budget - packet_size;
        self.last_sent_ns = now_ns;
    }

    /// Reset pacer state (e.g., after persistent congestion).
    pub fn reset(self: *Pacer) void {
        self.budget = self.maxBurstSize();
        self.last_sent_ns = null;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "pacer initial budget allows max burst" {
    var p = Pacer.init(1200);
    try std.testing.expectEqual(@as(usize, 12000), p.budget);
    // srtt=1ms=1_000_000ns
    try std.testing.expect(p.canSend(0, 1200, 43200, 1_000_000));
}

test "pacer deducts budget on send" {
    var p = Pacer.init(1200);
    p.onPacketSent(0, 1200, 43200, 1_000_000);
    try std.testing.expectEqual(@as(usize, 10800), p.budget); // 12000 - 1200
}

test "pacer budget replenishes over time" {
    var p = Pacer.init(1200);
    // Drain budget
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        p.onPacketSent(0, 1200, 43200, 1_000_000);
    }
    try std.testing.expectEqual(@as(usize, 0), p.budget);

    // After 100ms=100_000_000ns with cwnd=43200, srtt=100ms=100_000_000ns:
    // added = 43200 * 5 * 100_000_000 / (100_000_000 * 4) = 54000, capped at 12000
    const budget = p.budgetAt(100_000_000, 43200, 100_000_000);
    try std.testing.expectEqual(@as(usize, 12000), budget); // capped at max burst
}

test "pacer blocks send when budget exhausted" {
    var p = Pacer.init(1200);
    // Drain all budget at time 0
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        p.onPacketSent(0, 1200, 43200, 1_000_000);
    }
    // At time 0, no replenishment, can't send
    try std.testing.expect(!p.canSend(0, 1200, 43200, 1_000_000));
    // srtt=100ms=100_000_000ns, rate = 43200*5/(100_000_000*4) bytes/ns
    // After 1ms=1_000_000ns: added = 43200*5*1_000_000/(100_000_000*4) = 540 bytes < 1200
    try std.testing.expect(!p.canSend(1_000_000, 1200, 43200, 100_000_000));
    // After 3ms=3_000_000ns: added = 43200*5*3_000_000/(100_000_000*4) = 1620 >= 1200
    try std.testing.expect(p.canSend(3_000_000, 1200, 43200, 100_000_000));
}

test "pacer zero RTT means no pacing" {
    var p = Pacer.init(1200);
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        p.onPacketSent(0, 1200, 43200, 0);
    }
    // With RTT=0, budget always full (no pacing estimate yet)
    try std.testing.expect(p.canSend(0, 1200, 43200, 0));
}

test "pacer loopback precision (1us RTT)" {
    var p = Pacer.init(1200);
    const srtt_ns: u64 = 1000; // 1 μs loopback RTT
    // Drain budget
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        p.onPacketSent(0, 1200, 43200, srtt_ns);
    }
    try std.testing.expectEqual(@as(usize, 0), p.budget);
    // After 1μs with cwnd=43200, srtt=1000ns:
    // added = 43200 * 5 * 1000 / (1000 * 4) = 54000, capped at 12000
    const budget = p.budgetAt(1000, 43200, srtt_ns);
    try std.testing.expectEqual(@as(usize, 12000), budget);
    try std.testing.expect(p.canSend(1000, 1200, 43200, srtt_ns));
}

test "pacer reset restores full burst" {
    var p = Pacer.init(1200);
    p.onPacketSent(0, 1200, 43200, 1_000_000);
    p.reset();
    try std.testing.expectEqual(@as(usize, 12000), p.budget);
    try std.testing.expect(p.last_sent_ns == null);
}

test "pacing send time rounds upward without changing token state" {
    var p = Pacer.init(1200);
    p.budget = 1000;
    p.last_sent_ns = 0;
    const before = p;
    const deadline = p.nextSendTime(200_000, 1200, 43_200, 100_000_000) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(i64, 370_371), deadline);
    try std.testing.expect(!p.canSend(deadline - 1, 1200, 43_200, 100_000_000));
    try std.testing.expect(p.canSend(deadline, 1200, 43_200, 100_000_000));
    try std.testing.expectEqualDeep(before, p);
    try std.testing.expectEqual(@as(?i64, null), p.nextSendTime(deadline, 1200, 43_200, 100_000_000));
}

test "pacing send time rejects absent waits and unrepresentable clocks" {
    var p = Pacer.init(1200);
    try std.testing.expectEqual(@as(?i64, null), p.nextSendTime(0, 1200, 12_000, 100_000_000));
    p.budget = 0;
    p.last_sent_ns = 0;
    try std.testing.expectEqual(@as(?i64, null), p.nextSendTime(0, 1200, 0, 100_000_000));
    try std.testing.expectEqual(@as(?i64, null), p.nextSendTime(0, 1200, 12_000, 0));
    try std.testing.expectEqual(@as(?i64, null), p.nextSendTime(0, p.maxBurstSize() + 1, 12_000, 100_000_000));
    try std.testing.expectEqual(@as(?i64, null), p.nextSendTime(0, 1200, 1, std.math.maxInt(u64)));
    p.last_sent_ns = std.math.maxInt(i64) - 1;
    try std.testing.expectEqual(@as(?i64, null), p.nextSendTime(p.last_sent_ns.?, 1, 3, 7));
}
