const std = @import("std");

pub const timer_granularity_ms: u64 = 1;
pub const time_threshold_numerator: u64 = 9;
pub const time_threshold_denominator: u64 = 8;
pub const persistent_congestion_threshold: u64 = 3;

fn saturatingAddU64(a: u64, b: u64) u64 {
    return std.math.add(u64, a, b) catch std.math.maxInt(u64);
}

fn saturatingMulU64(a: u64, b: u64) u64 {
    return std.math.mul(u64, a, b) catch std.math.maxInt(u64);
}

fn saturatingMulUsize(a: usize, b: usize) usize {
    return std.math.mul(usize, a, b) catch std.math.maxInt(usize);
}

fn saturatingCeilMulDivU64(value: u64, numerator: u64, denominator: u64) u64 {
    const product = saturatingMulU64(value, numerator);
    if (product == std.math.maxInt(u64)) return product;
    const rounded = saturatingAddU64(product, denominator - 1);
    return rounded / denominator;
}

/// Configuration for the simplified loss recovery and congestion state.
pub const Config = struct {
    max_datagram_size: u16,
    initial_rtt_ms: u32,
    max_ack_delay_ms: u32 = 25,
};

/// Minimal RFC 9002-inspired recovery state.
///
/// This tracks RTT estimates, PTO backoff, bytes in flight, and a NewReno-like
/// congestion window. Packet number spaces and sent-packet metadata are not
/// modeled yet; callers supply byte counts when packets are sent, acked, or lost.
pub const Recovery = struct {
    max_datagram_size: usize,
    max_ack_delay_ms: u64,
    latest_rtt_ms: ?u64 = null,
    min_rtt_ms: ?u64 = null,
    smoothed_rtt_ms: u64,
    rttvar_ms: u64,
    pto_count: u8 = 0,
    bytes_in_flight: usize = 0,
    congestion_window: usize,
    /// Bytes acknowledged while in congestion avoidance but not yet converted
    /// into a full max-datagram-sized congestion-window increase.
    congestion_avoidance_bytes_acked: usize = 0,
    congestion_recovery_start_time_millis: ?i64 = null,
    ssthresh: usize = std.math.maxInt(usize),

    /// Initialize recovery state with RFC 9002-style initial RTT and window.
    pub fn init(config: Config) Recovery {
        const initial_rtt = @as(u64, config.initial_rtt_ms);
        const max_datagram_size = @as(usize, config.max_datagram_size);
        return .{
            .max_datagram_size = max_datagram_size,
            .max_ack_delay_ms = config.max_ack_delay_ms,
            .smoothed_rtt_ms = initial_rtt,
            .rttvar_ms = initial_rtt / 2,
            .congestion_window = initialCongestionWindow(max_datagram_size),
        };
    }

    /// Return true when sending `bytes` would fit inside the congestion window.
    pub fn canSend(self: Recovery, bytes: usize) bool {
        const after_send = std.math.add(usize, self.bytes_in_flight, bytes) catch return false;
        return after_send <= self.congestion_window;
    }

    /// Record bytes for a sent ack-eliciting packet.
    pub fn onPacketSent(self: *Recovery, bytes: usize) void {
        self.bytes_in_flight = std.math.add(usize, self.bytes_in_flight, bytes) catch std.math.maxInt(usize);
    }

    /// Record an acknowledged packet and update RTT/congestion state.
    pub fn onPacketAcked(
        self: *Recovery,
        bytes: usize,
        sent_time_millis: i64,
        latest_rtt_ms: u64,
        ack_delay_ms: u64,
    ) void {
        self.onPacketAckedWithUtilization(bytes, sent_time_millis, latest_rtt_ms, ack_delay_ms, true);
    }

    /// Record an acknowledged packet, with explicit congestion-window utilization.
    ///
    /// RFC 9002 does not grow `congestion_window` when the sender is
    /// application- or flow-control-limited. Callers that can observe whether
    /// the window was utilized before processing the ACK pass that fact here;
    /// RTT, PTO, and bytes-in-flight accounting still update either way.
    pub fn onPacketAckedWithUtilization(
        self: *Recovery,
        bytes: usize,
        sent_time_millis: i64,
        latest_rtt_ms: u64,
        ack_delay_ms: u64,
        congestion_window_utilized: bool,
    ) void {
        self.removeBytesInFlight(bytes);
        self.updateRtt(latest_rtt_ms, ack_delay_ms);
        self.pto_count = 0;
        if (!congestion_window_utilized) return;
        if (self.inCongestionRecovery(sent_time_millis)) return;

        if (self.congestion_window < self.ssthresh) {
            self.congestion_window = std.math.add(usize, self.congestion_window, bytes) catch std.math.maxInt(usize);
            self.congestion_avoidance_bytes_acked = 0;
            return;
        }
        if (self.congestion_window == 0) {
            self.congestion_window = @max(bytes, minimumCongestionWindow(self.max_datagram_size));
            self.congestion_avoidance_bytes_acked = 0;
            return;
        }

        self.growCongestionAvoidance(bytes);
    }

    /// Record packet loss and start a congestion recovery period if needed.
    pub fn onPacketLost(self: *Recovery, bytes: usize, lost_packet_sent_time_millis: i64, now_millis: i64) void {
        self.removeBytesInFlight(bytes);
        self.onCongestionEvent(lost_packet_sent_time_millis, now_millis);
    }

    /// Enter NewReno congestion recovery for a loss or ECN-CE congestion event.
    ///
    /// The caller is responsible for bytes-in-flight accounting. Loss removes
    /// packet bytes before calling this; ECN-CE marks an acknowledged packet as
    /// a congestion signal without treating that packet as lost.
    pub fn onCongestionEvent(self: *Recovery, sent_time_millis: i64, now_millis: i64) void {
        if (self.inCongestionRecovery(sent_time_millis)) return;
        self.congestion_recovery_start_time_millis = now_millis;
        self.congestion_avoidance_bytes_acked = 0;
        self.ssthresh = self.congestion_window / 2;
        self.congestion_window = @max(self.ssthresh, minimumCongestionWindow(self.max_datagram_size));
    }

    /// Return whether a congestion signal for `sent_time_millis` would start a
    /// new recovery period rather than being suppressed by the current one.
    pub fn wouldStartCongestionRecovery(self: Recovery, sent_time_millis: i64) bool {
        return !self.inCongestionRecovery(sent_time_millis);
    }

    /// Mark one PTO expiration and apply exponential backoff to future PTOs.
    pub fn onPtoExpired(self: *Recovery) void {
        if (self.pto_count != std.math.maxInt(u8)) {
            self.pto_count += 1;
        }
    }

    /// Current Probe Timeout in milliseconds.
    pub fn ptoMs(self: Recovery) u64 {
        return self.backedOffPtoMs(true);
    }

    /// Current Initial/Handshake Probe Timeout in milliseconds.
    ///
    /// RFC 9002 sets `max_ack_delay` to zero for Initial and Handshake packet
    /// number spaces because those acknowledgments are not intentionally
    /// delayed.
    pub fn ptoMsWithoutMaxAckDelay(self: Recovery) u64 {
        return self.backedOffPtoMs(false);
    }

    fn basePtoMs(self: Recovery, include_max_ack_delay: bool) u64 {
        const variance_delay = @max(saturatingMulU64(4, self.rttvar_ms), timer_granularity_ms);
        const ack_delay = if (include_max_ack_delay) self.max_ack_delay_ms else 0;
        return saturatingAddU64(saturatingAddU64(self.smoothed_rtt_ms, variance_delay), ack_delay);
    }

    fn backedOffPtoMs(self: Recovery, include_max_ack_delay: bool) u64 {
        var timeout = self.basePtoMs(include_max_ack_delay);

        var count = self.pto_count;
        while (count != 0) : (count -= 1) {
            timeout = std.math.mul(u64, timeout, 2) catch return std.math.maxInt(u64);
        }
        return timeout;
    }

    /// Persistent congestion duration from RFC 9002 Section 7.6.1.
    pub fn persistentCongestionDurationMs(self: Recovery) u64 {
        return std.math.mul(u64, self.basePtoMs(true), persistent_congestion_threshold) catch std.math.maxInt(u64);
    }

    /// Apply the persistent congestion response by reducing cwnd to kMinimumWindow.
    pub fn onPersistentCongestion(self: *Recovery) void {
        self.congestion_window = minimumCongestionWindow(self.max_datagram_size);
        self.congestion_avoidance_bytes_acked = 0;
        self.congestion_recovery_start_time_millis = null;
    }

    fn inCongestionRecovery(self: Recovery, sent_time_millis: i64) bool {
        const recovery_start = self.congestion_recovery_start_time_millis orelse return false;
        return sent_time_millis <= recovery_start;
    }

    fn removeBytesInFlight(self: *Recovery, bytes: usize) void {
        self.bytes_in_flight = if (bytes >= self.bytes_in_flight) 0 else self.bytes_in_flight - bytes;
    }

    fn growCongestionAvoidance(self: *Recovery, bytes: usize) void {
        self.congestion_avoidance_bytes_acked =
            std.math.add(usize, self.congestion_avoidance_bytes_acked, bytes) catch std.math.maxInt(usize);

        while (self.congestion_avoidance_bytes_acked >= self.congestion_window) {
            const window_before_growth = self.congestion_window;
            self.congestion_avoidance_bytes_acked -= window_before_growth;
            self.congestion_window =
                std.math.add(usize, self.congestion_window, self.max_datagram_size) catch std.math.maxInt(usize);
            if (self.congestion_window == std.math.maxInt(usize)) {
                self.congestion_avoidance_bytes_acked = 0;
                return;
            }
        }
    }

    fn updateRtt(self: *Recovery, latest_rtt_ms: u64, ack_delay_ms: u64) void {
        const had_rtt_sample = self.latest_rtt_ms != null;
        self.latest_rtt_ms = latest_rtt_ms;
        self.min_rtt_ms = if (self.min_rtt_ms) |min_rtt| @min(min_rtt, latest_rtt_ms) else latest_rtt_ms;

        const min_rtt = self.min_rtt_ms.?;
        const adjusted_rtt = if (latest_rtt_ms > saturatingAddU64(min_rtt, ack_delay_ms))
            latest_rtt_ms - ack_delay_ms
        else
            latest_rtt_ms;

        if (!had_rtt_sample) {
            self.smoothed_rtt_ms = adjusted_rtt;
            self.rttvar_ms = adjusted_rtt / 2;
            return;
        }

        const rtt_delta = if (self.smoothed_rtt_ms > adjusted_rtt)
            self.smoothed_rtt_ms - adjusted_rtt
        else
            adjusted_rtt - self.smoothed_rtt_ms;

        self.rttvar_ms = saturatingAddU64(saturatingMulU64(3, self.rttvar_ms), rtt_delta) / 4;
        self.smoothed_rtt_ms = saturatingAddU64(saturatingMulU64(7, self.smoothed_rtt_ms), adjusted_rtt) / 8;
    }
};

/// Compute the RFC 9002 initial congestion window in bytes.
pub fn initialCongestionWindow(max_datagram_size: usize) usize {
    return @min(saturatingMulUsize(10, max_datagram_size), @max(saturatingMulUsize(2, max_datagram_size), 14720));
}

/// Compute the minimum congestion window in bytes.
pub fn minimumCongestionWindow(max_datagram_size: usize) usize {
    return saturatingMulUsize(2, max_datagram_size);
}

/// Compute the RFC 9002 time-threshold loss delay in milliseconds.
///
/// The current connection skeleton uses this for ACK-driven time-threshold
/// loss detection. A future endpoint timer will use the same delay to arm the
/// loss detection timer.
pub fn timeThresholdLossDelayMs(latest_rtt_ms: ?u64, smoothed_rtt_ms: u64) u64 {
    const rtt_basis = if (latest_rtt_ms) |latest_rtt| @max(latest_rtt, smoothed_rtt_ms) else smoothed_rtt_ms;
    const loss_delay = saturatingCeilMulDivU64(rtt_basis, time_threshold_numerator, time_threshold_denominator);
    return @max(loss_delay, timer_granularity_ms);
}

test "initial and minimum congestion windows follow RFC 9002 bounds" {
    try std.testing.expectEqual(@as(usize, 13500), initialCongestionWindow(1350));
    try std.testing.expectEqual(@as(usize, 2400), minimumCongestionWindow(1200));
}

test "time threshold loss delay follows RFC 9002 multiplier and granularity" {
    try std.testing.expectEqual(@as(u64, 375), timeThresholdLossDelayMs(null, 333));
    try std.testing.expectEqual(@as(u64, 452), timeThresholdLossDelayMs(401, 333));
    try std.testing.expectEqual(@as(u64, 1), timeThresholdLossDelayMs(0, 0));
    try std.testing.expectEqual(std.math.maxInt(u64), timeThresholdLossDelayMs(std.math.maxInt(u64), 1));
}

test "sent acked and lost packets update bytes in flight and congestion window" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ms = 333 });
    const initial_window = recovery.congestion_window;

    try std.testing.expect(recovery.canSend(1200));
    recovery.onPacketSent(1200);
    try std.testing.expectEqual(@as(usize, 1200), recovery.bytes_in_flight);

    recovery.onPacketAcked(1200, 0, 100, 0);
    try std.testing.expectEqual(@as(usize, 0), recovery.bytes_in_flight);
    try std.testing.expect(recovery.congestion_window > initial_window);
    try std.testing.expectEqual(@as(u8, 0), recovery.pto_count);

    recovery.onPacketSent(2400);
    recovery.onPacketLost(2400, 100, 200);
    try std.testing.expectEqual(@as(usize, 0), recovery.bytes_in_flight);
    try std.testing.expect(recovery.congestion_window >= minimumCongestionWindow(1200));
}

test "NewReno slow start grows congestion window by acked bytes" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ms = 100 });
    const initial_window = recovery.congestion_window;

    recovery.onPacketSent(1200);
    recovery.onPacketAcked(1200, 0, 100, 0);

    try std.testing.expectEqual(@as(usize, 0), recovery.bytes_in_flight);
    try std.testing.expectEqual(initial_window + 1200, recovery.congestion_window);
    try std.testing.expectEqual(std.math.maxInt(usize), recovery.ssthresh);
}

test "NewReno congestion avoidance grows by byte-counted cwnd credit" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ms = 100 });
    recovery.congestion_window = 12_000;
    recovery.ssthresh = 12_000;

    var acked_packets: usize = 0;
    while (acked_packets < 9) : (acked_packets += 1) {
        recovery.onPacketSent(1200);
        recovery.onPacketAcked(1200, @as(i64, @intCast(acked_packets)), 100, 0);
    }

    try std.testing.expectEqual(@as(usize, 0), recovery.bytes_in_flight);
    try std.testing.expectEqual(@as(usize, 10_800), recovery.congestion_avoidance_bytes_acked);
    try std.testing.expectEqual(@as(usize, 12_000), recovery.congestion_window);

    recovery.onPacketSent(1200);
    recovery.onPacketAcked(1200, 10, 100, 0);

    try std.testing.expectEqual(@as(usize, 0), recovery.congestion_avoidance_bytes_acked);
    try std.testing.expectEqual(@as(usize, 13_200), recovery.congestion_window);
}

test "NewReno congestion avoidance consumes multiple cwnd credits from batched ACKs" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ms = 100 });
    recovery.congestion_window = 12_000;
    recovery.ssthresh = 12_000;

    recovery.onPacketSent(25_200);
    recovery.onPacketAcked(25_200, 0, 100, 0);

    try std.testing.expectEqual(@as(usize, 0), recovery.bytes_in_flight);
    try std.testing.expectEqual(@as(usize, 0), recovery.congestion_avoidance_bytes_acked);
    try std.testing.expectEqual(@as(usize, 14_400), recovery.congestion_window);
}

test "underutilized ACK updates recovery accounting without growing congestion window" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ms = 100 });
    const initial_window = recovery.congestion_window;

    recovery.onPacketSent(1200);
    recovery.onPtoExpired();
    recovery.onPacketAckedWithUtilization(1200, 0, 80, 0, false);

    try std.testing.expectEqual(@as(usize, 0), recovery.bytes_in_flight);
    try std.testing.expectEqual(@as(u8, 0), recovery.pto_count);
    try std.testing.expectEqual(@as(?u64, 80), recovery.latest_rtt_ms);
    try std.testing.expectEqual(@as(u64, 80), recovery.smoothed_rtt_ms);
    try std.testing.expectEqual(initial_window, recovery.congestion_window);
}

test "pto uses rtt variance and exponential backoff" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ms = 100, .max_ack_delay_ms = 25 });

    try std.testing.expectEqual(@as(u64, 325), recovery.ptoMs());
    try std.testing.expectEqual(@as(u64, 300), recovery.ptoMsWithoutMaxAckDelay());
    recovery.onPtoExpired();
    try std.testing.expectEqual(@as(u64, 650), recovery.ptoMs());
    try std.testing.expectEqual(@as(u64, 600), recovery.ptoMsWithoutMaxAckDelay());

    recovery.onPacketAcked(0, 0, 80, 0);
    try std.testing.expectEqual(@as(u8, 0), recovery.pto_count);
    try std.testing.expect(recovery.ptoMs() < 650);
}

test "congestion recovery period avoids repeated loss reduction and ACK growth" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ms = 100 });
    const initial_window = recovery.congestion_window;

    recovery.onPacketSent(3600);
    try std.testing.expect(recovery.wouldStartCongestionRecovery(10));
    recovery.onPacketLost(1200, 10, 100);
    const recovery_window = recovery.congestion_window;
    try std.testing.expect(recovery_window < initial_window);
    try std.testing.expectEqual(@as(?i64, 100), recovery.congestion_recovery_start_time_millis);
    try std.testing.expect(!recovery.wouldStartCongestionRecovery(10));
    try std.testing.expect(!recovery.wouldStartCongestionRecovery(20));

    recovery.onPacketLost(1200, 20, 110);
    try std.testing.expectEqual(recovery_window, recovery.congestion_window);

    recovery.onPacketAcked(1200, 50, 100, 0);
    try std.testing.expectEqual(recovery_window, recovery.congestion_window);

    recovery.onPacketSent(1200);
    recovery.onPacketAcked(1200, 150, 100, 0);
    try std.testing.expectEqual(recovery_window, recovery.congestion_window);
    try std.testing.expectEqual(@as(usize, 1200), recovery.congestion_avoidance_bytes_acked);

    var acked_after_recovery: usize = 1;
    while (acked_after_recovery < 5) : (acked_after_recovery += 1) {
        recovery.onPacketSent(1200);
        recovery.onPacketAcked(1200, @as(i64, @intCast(150 + acked_after_recovery)), 100, 0);
    }
    try std.testing.expect(recovery.congestion_window > recovery_window);
    try std.testing.expectEqual(@as(usize, 0), recovery.congestion_avoidance_bytes_acked);
}

test "NewReno congestion event clamps cwnd without clamping ssthresh" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ms = 100 });
    recovery.congestion_window = 3_000;

    recovery.onCongestionEvent(10, 100);

    try std.testing.expectEqual(@as(usize, 1_500), recovery.ssthresh);
    try std.testing.expectEqual(minimumCongestionWindow(1200), recovery.congestion_window);
}

test "ECN congestion event enters recovery without removing bytes in flight" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ms = 100 });
    const initial_window = recovery.congestion_window;

    recovery.onPacketSent(2400);
    recovery.onCongestionEvent(10, 100);
    const recovery_window = recovery.congestion_window;
    try std.testing.expect(recovery_window < initial_window);
    try std.testing.expectEqual(recovery_window, recovery.ssthresh);
    try std.testing.expectEqual(@as(usize, 2400), recovery.bytes_in_flight);
    try std.testing.expectEqual(@as(?i64, 100), recovery.congestion_recovery_start_time_millis);

    recovery.onCongestionEvent(20, 110);
    try std.testing.expectEqual(recovery_window, recovery.congestion_window);

    recovery.onPacketAcked(1200, 50, 100, 0);
    try std.testing.expectEqual(@as(usize, 1200), recovery.bytes_in_flight);
    try std.testing.expectEqual(recovery_window, recovery.congestion_window);
}

test "persistent congestion duration and response follow RFC 9002 bounds" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ms = 100, .max_ack_delay_ms = 25 });

    try std.testing.expectEqual(@as(u64, 975), recovery.persistentCongestionDurationMs());
    recovery.onPtoExpired();
    recovery.onPtoExpired();
    try std.testing.expectEqual(@as(u64, 1300), recovery.ptoMs());
    try std.testing.expectEqual(@as(u64, 975), recovery.persistentCongestionDurationMs());

    recovery.congestion_window = 12_000;
    recovery.ssthresh = 6_000;
    recovery.congestion_recovery_start_time_millis = 42;
    recovery.onPersistentCongestion();
    try std.testing.expectEqual(minimumCongestionWindow(1200), recovery.congestion_window);
    try std.testing.expectEqual(@as(usize, 6_000), recovery.ssthresh);
    try std.testing.expectEqual(@as(?i64, null), recovery.congestion_recovery_start_time_millis);
}

test "recovery arithmetic saturates at numeric extremes" {
    try std.testing.expectEqual(std.math.maxInt(usize), initialCongestionWindow(std.math.maxInt(usize)));
    try std.testing.expectEqual(std.math.maxInt(usize), minimumCongestionWindow(std.math.maxInt(usize)));

    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ms = 100 });
    recovery.smoothed_rtt_ms = std.math.maxInt(u64);
    recovery.rttvar_ms = std.math.maxInt(u64);
    try std.testing.expectEqual(std.math.maxInt(u64), recovery.ptoMs());

    recovery.max_datagram_size = std.math.maxInt(usize);
    recovery.congestion_window = 1;
    recovery.ssthresh = 0;
    recovery.onPacketAcked(1, 0, std.math.maxInt(u64), std.math.maxInt(u64));
    try std.testing.expectEqual(std.math.maxInt(usize), recovery.congestion_window);
    try std.testing.expectEqual(@as(usize, 0), recovery.congestion_avoidance_bytes_acked);
}
