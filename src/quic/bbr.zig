//! BBR congestion control (BBRv1).
//!
//! Implements the BBR algorithm which uses bottleneck bandwidth (BtlBw)
//! and round-trip propagation time (RTprop) measurements to set pacing
//! rate and congestion window, rather than relying on loss signals.
//!
//! Reference: "BBR: Congestion-Based Congestion Control" (Cardwell et al.)

const std = @import("std");

/// BBR state machine phases.
pub const BbrPhase = enum {
    /// Exponential growth to find BtlBw.
    startup,
    /// Drain excess packets queued during startup.
    drain,
    /// Steady-state probing for bandwidth.
    probe_bw,
    /// Periodically drain to measure RTprop.
    probe_rtt,
};

/// BBR congestion control state.
pub const BbrState = struct {
    /// Current phase.
    phase: BbrPhase = .startup,
    /// Estimated bottleneck bandwidth (bytes/sec).
    btl_bw: u64 = 0,
    /// Estimated round-trip propagation time (ms).
    rt_prop_ms: i64 = std.math.maxInt(i64),
    /// Maximum delivered bytes at last RTprop update.
    rt_prop_stamp_ms: i64 = 0,
    /// Whether RTprop has been measured.
    rt_prop_valid: bool = false,
    /// Current pacing rate (bytes/sec).
    pacing_rate: u64 = 0,
    /// Current congestion window (bytes).
    cwnd: usize = 0,
    /// Bytes delivered so far (for bandwidth sampling).
    delivered: u64 = 0,
    /// Timestamp of last delivery sample (ms).
    delivered_stamp_ms: i64 = 0,
    /// Bytes in flight at last delivery sample.
    bytes_in_flight_at_sample: u64 = 0,
    /// Whether a bandwidth sample is being taken.
    sample_is_app_limited: bool = false,
    /// Round trip count for startup completion.
    round_count: u64 = 0,
    /// Delivered at start of current round.
    round_start_delivered: u64 = 0,
    /// Whether we've filled the pipe (startup complete).
    filled_pipe: bool = false,
    /// BtlBw at last round for startup growth check.
    last_round_btl_bw: u64 = 0,
    /// Number of rounds without significant BtlBw growth.
    bw_growth_streak: u64 = 0,
    /// ProbeBW cycle index (0-7).
    probe_bw_cycle_index: u32 = 0,
    /// Timestamp of last ProbeBW cycle advance.
    probe_bw_cycle_stamp_ms: i64 = 0,
    /// Full cwnd (before loss adjustments).
    full_cwnd: usize = 0,
    /// Whether we're in a loss recovery epoch.
    in_loss_recovery: bool = false,
    /// Packets delivered during current recovery epoch.
    recovery_delivered: u64 = 0,

    /// BBR constants.
    const startup_gain: f64 = 2.89; // 2/ln(2)
    const drain_gain: f64 = 1.0 / 2.89;
    const probe_bw_gain: f64 = 1.0;
    const probe_rtt_cwnd_fraction: f64 = 0.5;
    const rt_prop_filter_len_ms: i64 = 10_000; // 10 seconds
    const startup_bw_growth_threshold: f64 = 1.25; // 25% growth
    const min_cwnd_segments: usize = 4;

    /// Pacing gains for ProbeBW cycle [1.25, 0.75, 1, 1, 1, 1, 1, 1].
    const probe_bw_gains = [_]f64{ 1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0 };

    /// Initialize BBR with initial parameters.
    pub fn init(initial_cwnd: usize, max_datagram_size: usize, now_ms: i64) BbrState {
        _ = max_datagram_size;
        return .{
            .cwnd = initial_cwnd,
            .full_cwnd = initial_cwnd,
            .pacing_rate = @intFromFloat(@as(f64, @floatFromInt(initial_cwnd)) * 2.89),
            .rt_prop_stamp_ms = now_ms,
            .delivered_stamp_ms = now_ms,
            .probe_bw_cycle_stamp_ms = now_ms,
            .round_start_delivered = 0,
        };
    }

    /// Update BBR state when a packet is sent.
    pub fn onPacketSent(self: *BbrState, bytes_in_flight: u64) void {
        if (bytes_in_flight == 0) {
            self.sample_is_app_limited = true;
        }
    }

    /// Update BBR state when a packet is ACKed.
    pub fn onPacketAcked(
        self: *BbrState,
        bytes_acked: u64,
        rtt_ms: i64,
        now_ms: i64,
        bytes_in_flight: u64,
        max_datagram_size: usize,
    ) void {
        // Update delivered count
        self.delivered += bytes_acked;

        // Update RTprop estimate
        if (rtt_ms < self.rt_prop_ms) {
            self.rt_prop_ms = rtt_ms;
            self.rt_prop_stamp_ms = now_ms;
            self.rt_prop_valid = true;
        }

        // Check if RTprop filter has expired
        if (now_ms - self.rt_prop_stamp_ms > rt_prop_filter_len_ms) {
            self.rt_prop_ms = rtt_ms;
            self.rt_prop_stamp_ms = now_ms;
        }

        // Update bandwidth estimate
        self.updateBandwidthSample(bytes_acked, now_ms, bytes_in_flight);

        // Check round trip completion
        if (self.delivered >= self.round_start_delivered + bytes_acked) {
            self.round_count += 1;
            self.round_start_delivered = self.delivered;
        }

        // Update state machine
        switch (self.phase) {
            .startup => self.updateStartup(max_datagram_size),
            .drain => self.updateDrain(max_datagram_size),
            .probe_bw => self.updateProbeBw(now_ms, max_datagram_size),
            .probe_rtt => self.updateProbeRtt(now_ms, max_datagram_size),
        }

        // Update pacing rate and cwnd
        self.updatePacingRate(max_datagram_size);
        self.updateCwnd(max_datagram_size);
    }

    /// Handle packet loss.
    pub fn onPacketLost(self: *BbrState, now_ms: i64, max_datagram_size: usize) void {
        _ = now_ms;
        _ = max_datagram_size;
        // BBR doesn't halve cwnd on loss like Reno/CUBIC.
        // It relies on BtlBw and RTprop to set cwnd.
        // Mark loss recovery epoch.
        if (!self.in_loss_recovery) {
            self.in_loss_recovery = true;
            self.recovery_delivered = self.delivered;
        }
    }

    /// End loss recovery epoch.
    pub fn endLossRecovery(self: *BbrState) void {
        self.in_loss_recovery = false;
    }

    /// Get the current pacing rate in bytes/sec.
    pub fn currentPacingRate(self: *const BbrState) u64 {
        return self.pacing_rate;
    }

    /// Get the current congestion window in bytes.
    pub fn currentCwnd(self: *const BbrState) usize {
        return self.cwnd;
    }

    fn updateBandwidthSample(self: *BbrState, bytes_acked: u64, now_ms: i64, bytes_in_flight: u64) void {
        if (self.sample_is_app_limited) {
            self.sample_is_app_limited = false;
            return;
        }

        const elapsed_ms = now_ms - self.delivered_stamp_ms;
        if (elapsed_ms <= 0) return;

        // Bandwidth sample: bytes_acked / elapsed_time
        const bw_sample = bytes_acked * 1000 / @as(u64, @intCast(elapsed_ms));

        if (bw_sample > self.btl_bw) {
            self.btl_bw = bw_sample;
        }

        self.delivered_stamp_ms = now_ms;
        self.bytes_in_flight_at_sample = bytes_in_flight;
    }

    fn updateStartup(self: *BbrState, max_datagram_size: usize) void {
        _ = max_datagram_size;
        // Check if BtlBw has stopped growing significantly
        if (self.btl_bw > 0 and self.last_round_btl_bw > 0) {
            const growth: f64 = @as(f64, @floatFromInt(self.btl_bw)) / @as(f64, @floatFromInt(self.last_round_btl_bw));
            if (growth < startup_bw_growth_threshold) {
                self.bw_growth_streak += 1;
                if (self.bw_growth_streak >= 3) {
                    self.filled_pipe = true;
                    self.phase = .drain;
                    return;
                }
            } else {
                self.bw_growth_streak = 0;
            }
        }
        self.last_round_btl_bw = self.btl_bw;
    }

    fn updateDrain(self: *BbrState, max_datagram_size: usize) void {
        // Drain until bytes_in_flight <= BDP
        const bdp = self.estimateBdp(max_datagram_size);
        if (self.bytes_in_flight_at_sample <= bdp) {
            self.phase = .probe_bw;
            self.probe_bw_cycle_index = 0;
        }
    }

    fn updateProbeBw(self: *BbrState, now_ms: i64, max_datagram_size: usize) void {
        _ = max_datagram_size;
        // Advance cycle every RTprop
        const cycle_duration = if (self.rt_prop_valid) self.rt_prop_ms else 100;
        if (now_ms - self.probe_bw_cycle_stamp_ms > cycle_duration) {
            self.probe_bw_cycle_index = (self.probe_bw_cycle_index + 1) % 8;
            self.probe_bw_cycle_stamp_ms = now_ms;
        }

        // Check if we should enter ProbeRTT
        if (self.rt_prop_valid and now_ms - self.rt_prop_stamp_ms > rt_prop_filter_len_ms) {
            self.phase = .probe_rtt;
        }
    }

    fn updateProbeRtt(self: *BbrState, now_ms: i64, max_datagram_size: usize) void {
        _ = max_datagram_size;
        // Stay in ProbeRTT for 200ms
        if (now_ms - self.rt_prop_stamp_ms > 200) {
            self.phase = .probe_bw;
            self.probe_bw_cycle_index = 0;
            self.probe_bw_cycle_stamp_ms = now_ms;
        }
    }

    fn estimateBdp(self: *const BbrState, max_datagram_size: usize) u64 {
        if (!self.rt_prop_valid or self.btl_bw == 0) {
            return @intCast(@max(self.cwnd, min_cwnd_segments * max_datagram_size));
        }
        // BDP = BtlBw * RTprop
        const rt_prop_sec: f64 = @as(f64, @floatFromInt(self.rt_prop_ms)) / 1000.0;
        const bdp: f64 = @as(f64, @floatFromInt(self.btl_bw)) * rt_prop_sec;
        return @intFromFloat(bdp);
    }

    fn currentGain(self: *const BbrState) f64 {
        return switch (self.phase) {
            .startup => startup_gain,
            .drain => drain_gain,
            .probe_bw => probe_bw_gains[self.probe_bw_cycle_index],
            .probe_rtt => 1.0,
        };
    }

    fn updatePacingRate(self: *BbrState, max_datagram_size: usize) void {
        _ = max_datagram_size;
        if (self.btl_bw == 0) return;
        const gain = self.currentGain();
        const rate: f64 = @as(f64, @floatFromInt(self.btl_bw)) * gain;
        self.pacing_rate = @intFromFloat(rate);
    }

    fn updateCwnd(self: *BbrState, max_datagram_size: usize) void {
        const bdp = self.estimateBdp(max_datagram_size);
        const gain = self.currentGain();

        if (self.phase == .probe_rtt) {
            // Reduce cwnd to probe RTprop
            const probe_rtt_cwnd: f64 = @as(f64, @floatFromInt(bdp)) * probe_rtt_cwnd_fraction;
            const min_cwnd = min_cwnd_segments * max_datagram_size;
            self.cwnd = @max(@as(usize, @intFromFloat(probe_rtt_cwnd)), min_cwnd);
        } else {
            const target: f64 = @as(f64, @floatFromInt(bdp)) * gain;
            const min_cwnd = min_cwnd_segments * max_datagram_size;
            self.cwnd = @max(@as(usize, @intFromFloat(target)), min_cwnd);
        }
        self.full_cwnd = self.cwnd;
    }
};

test "BBR init sets startup phase" {
    const bbr = BbrState.init(12000, 1200, 0);
    try std.testing.expectEqual(BbrPhase.startup, bbr.phase);
    try std.testing.expectEqual(@as(usize, 12000), bbr.cwnd);
    try std.testing.expect(bbr.pacing_rate > 0);
}

test "BBR startup grows BtlBw estimate" {
    var bbr = BbrState.init(12000, 1200, 0);

    // Simulate ACKs with increasing bandwidth
    var i: i64 = 0;
    while (i < 10) : (i += 1) {
        bbr.onPacketAcked(1200, 50, i * 10, 12000 - @as(u64, @intCast(i)) * 1200, 1200);
    }

    try std.testing.expect(bbr.btl_bw > 0);
    try std.testing.expect(bbr.rt_prop_valid);
    try std.testing.expectEqual(@as(i64, 50), bbr.rt_prop_ms);
}

test "BBR transitions from startup to drain" {
    var bbr = BbrState.init(12000, 1200, 0);

    // Simulate many rounds with stable bandwidth (no growth)
    var i: i64 = 0;
    while (i < 50) : (i += 1) {
        bbr.onPacketAcked(1200, 50, i * 100, 6000, 1200);
        // Force round completion
        bbr.round_start_delivered = 0;
    }

    // After enough rounds without growth, should leave startup
    try std.testing.expect(bbr.phase != .startup or bbr.filled_pipe);
}

test "BBR pacing rate tracks BtlBw" {
    var bbr = BbrState.init(12000, 1200, 0);

    // Simulate ACKs
    bbr.onPacketAcked(12000, 50, 100, 0, 1200);

    try std.testing.expect(bbr.pacing_rate > 0);
    try std.testing.expect(bbr.btl_bw > 0);
}

test "BBR cwnd respects minimum" {
    var bbr = BbrState.init(4800, 1200, 0);

    // Simulate very low bandwidth
    bbr.onPacketAcked(100, 500, 1000, 0, 1200);

    // cwnd should be at least 4 * max_datagram_size
    try std.testing.expect(bbr.cwnd >= 4 * 1200);
}

test "BBR loss does not halve cwnd" {
    var bbr = BbrState.init(12000, 1200, 0);

    // Establish some state
    bbr.onPacketAcked(12000, 50, 100, 0, 1200);
    const cwnd_before = bbr.cwnd;

    // Loss event
    bbr.onPacketLost(200, 1200);

    // BBR should not drastically reduce cwnd on loss
    try std.testing.expect(bbr.cwnd >= cwnd_before / 2);
}

test "BBR ProbeRTT reduces cwnd" {
    var bbr = BbrState.init(12000, 1200, 0);

    // Establish state
    bbr.onPacketAcked(12000, 50, 100, 0, 1200);
    bbr.phase = .probe_rtt;
    bbr.rt_prop_valid = true;
    bbr.rt_prop_ms = 50;
    bbr.btl_bw = 240000; // 240 KB/s

    // Update cwnd in ProbeRTT
    bbr.updateCwnd(1200);

    // ProbeRTT cwnd should be reduced
    const bdp: usize = @intFromFloat(@as(f64, @floatFromInt(bbr.btl_bw)) * 0.05);
    try std.testing.expect(bbr.cwnd <= bdp + 4 * 1200);
}
