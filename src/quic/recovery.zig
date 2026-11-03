const std = @import("std");
const cubic_module = @import("cubic.zig");
const connection_config = @import("connection_config.zig");
const hystart_module = @import("hybrid_slow_start.zig");
const duration = @import("../time/duration.zig");
pub const ns_per_us = duration.ns_per_us;
pub const ns_per_ms = duration.ns_per_ms;
pub const ns_per_s = duration.ns_per_s;

pub const timer_granularity_ns: u64 = @intCast(duration.ns_per_ms); // kGranularity = 1ms (RFC 9002)

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
    initial_rtt_ns: u64,
    max_ack_delay_ns: u64 = 25_000_000, // 25ms
    congestion_algorithm: connection_config.CongestionAlgorithm = .new_reno,
    /// PTO jitter percentage (0–50). Adds ±percentage random jitter to the
    /// base PTO to prevent synchronized timeouts across connections.
    /// Default 0 keeps deterministic behaviour for tests.
    pto_jitter_percentage: u8 = 0,
};

/// Congestion controller state machine (RFC 9002 §7.3).
///
/// - `slow_start`: cwnd grows by acked bytes (or HyStart++ increment).
/// - `recovery`: cwnd was reduced; ALL congestion events blocked until
///   an ACK confirms a packet sent after the cutback (PN-based exit).
/// - `congestion_avoidance`: cwnd grows by CUBIC/NewReno formula.
pub const CongestionState = enum {
    slow_start,
    recovery,
    congestion_avoidance,
};

/// Minimal RFC 9002-inspired recovery state.
///
/// This tracks RTT estimates, PTO backoff, bytes in flight, and a NewReno-like
/// congestion window. Packet number spaces and sent-packet metadata are not
/// modeled yet; callers supply byte counts when packets are sent, acked, or lost.
pub const Recovery = struct {
    max_datagram_size: usize,
    max_ack_delay_ns: u64,
    latest_rtt_ns: ?u64 = null,
    min_rtt_ns: ?u64 = null,
    smoothed_rtt_ns: u64,
    rttvar_ns: u64,
    pto_count: u8 = 0,
    bytes_in_flight: usize = 0,
    congestion_window: usize,
    /// Bytes acknowledged while in congestion avoidance but not yet converted
    /// into a full max-datagram-sized congestion-window increase.
    congestion_avoidance_bytes_acked: usize = 0,
    /// Explicit congestion state machine (RFC 9002 §7.3).
    congestion_state: CongestionState = .slow_start,
    congestion_recovery_start_time_nanos: ?i64 = null,
    /// Set when entering recovery; cleared after one packet is sent (fast retransmission).
    fast_retransmission_required: bool = false,
    /// Largest packet number sent (updated by Connection on each send).
    largest_sent_packet_number: u64 = 0,
    /// Largest sent PN at the last cwnd cutback (RFC 6582 recovery).
    largest_sent_at_last_cutback: ?u64 = null,
    /// Largest acknowledged packet number (updated by Connection on each ACK).
    /// Used for packet-number-based recovery detection (RFC 6582).
    largest_acked_packet_number: ?u64 = null,
    /// Cumulative number of packets declared lost (diagnostics/metrics).
    packets_lost: u64 = 0,
    /// Cumulative number of retransmitted packets (diagnostics/metrics).
    packets_retransmitted: u64 = 0,
    ssthresh: usize = std.math.maxInt(usize),
    congestion_algorithm: connection_config.CongestionAlgorithm = .new_reno,
    cubic: cubic_module.CubicState = .{},
    /// HyStart++ slow start controller. Monitors RTT increases to exit
    /// slow start before overshooting available bandwidth.
    hystart: hystart_module.HybridSlowStart,
    /// Timestamp of the most recently sent ack-eliciting packet (millis).
    /// Set by Connection on each send; used by HyStart++ for RTT round detection.
    last_sent_time_nanos: i64 = 0,
    /// PTO jitter percentage (0–50). 0 = deterministic (test default).
    pto_jitter_percentage: u8 = 0,
    /// PRNG for PTO jitter. Seeded from init; deterministic seed keeps
    /// unit-test reproducibility when jitter is enabled explicitly.
    prng: std.Random.DefaultPrng = std.Random.DefaultPrng.init(0),

    /// Initialize recovery state with RFC 9002-style initial RTT and window.
    pub fn init(config: Config) Recovery {
        const initial_rtt = @as(u64, config.initial_rtt_ns);
        const max_datagram_size = @as(usize, config.max_datagram_size);
        return .{
            .max_datagram_size = max_datagram_size,
            .max_ack_delay_ns = config.max_ack_delay_ns,
            .smoothed_rtt_ns = initial_rtt,
            .rttvar_ns = initial_rtt / 2,
            .congestion_window = initialCongestionWindow(max_datagram_size),
            .congestion_algorithm = config.congestion_algorithm,
            .pto_jitter_percentage = config.pto_jitter_percentage,
            .hystart = hystart_module.HybridSlowStart.init(config.max_datagram_size),
        };
    }

    /// Return true when sending `bytes` would fit inside the congestion window.
    pub fn canSend(self: Recovery, bytes: usize) bool {
        const after_send = std.math.add(usize, self.bytes_in_flight, bytes) catch return false;
        return after_send <= self.congestion_window;
    }

    /// Reset path estimates while preserving packet accounting and diagnostics.
    pub fn resetPath(self: *Recovery, initial_rtt_ns: u64, max_datagram_size: u16) void {
        const previous = self.*;
        self.* = init(.{
            .max_datagram_size = max_datagram_size,
            .initial_rtt_ns = initial_rtt_ns,
            .max_ack_delay_ns = previous.max_ack_delay_ns,
            .congestion_algorithm = previous.congestion_algorithm,
            .pto_jitter_percentage = previous.pto_jitter_percentage,
        });
        self.bytes_in_flight = previous.bytes_in_flight;
        self.packets_lost = previous.packets_lost;
        self.packets_retransmitted = previous.packets_retransmitted;
        self.largest_sent_packet_number = previous.largest_sent_packet_number;
        self.largest_acked_packet_number = previous.largest_acked_packet_number;
        self.last_sent_time_nanos = previous.last_sent_time_nanos;
        self.prng = previous.prng;
    }

    /// Release acknowledged previous-path bytes without training this path.
    pub fn onPreviousPathAck(self: *Recovery, bytes: usize) void {
        self.removeBytesInFlight(bytes);
        self.pto_count = 0;
    }

    /// Preserve loss accounting without a congestion event on this path.
    pub fn onPreviousPathLoss(self: *Recovery, bytes: usize) void {
        self.packets_lost +%= 1;
        self.removeBytesInFlight(bytes);
    }

    /// Return the remaining congestion-window budget for ack-eliciting bytes.
    pub fn availableCongestionWindow(self: Recovery) usize {
        if (self.bytes_in_flight >= self.congestion_window) return 0;
        return self.congestion_window - self.bytes_in_flight;
    }

    /// True when the congestion window is sufficiently utilized to allow growth.
    ///
    /// Matches the production QUIC stack approach:
    /// - Congestion limited (bytes_in_flight >= cwnd): always utilized.
    /// - Slow start: utilized when at least half the window is in flight.
    /// - Congestion avoidance: utilized unless available window exceeds
    ///   3 × max_datagram_size (kMaxBurstBytes from Chromium).
    pub fn isCongestionWindowUtilized(self: Recovery) bool {
        if (self.bytes_in_flight >= self.congestion_window) return true;
        if (self.inSlowStart()) {
            return self.bytes_in_flight >= self.congestion_window / 2;
        }
        const available = self.congestion_window - self.bytes_in_flight;
        return available <= self.max_datagram_size * 3;
    }

    /// Record bytes for a sent ack-eliciting packet.
    pub fn onPacketSent(self: *Recovery, bytes: usize) void {
        self.bytes_in_flight = std.math.add(usize, self.bytes_in_flight, bytes) catch std.math.maxInt(usize);
    }

    /// Update the largest acknowledged packet number (called by Connection
    /// when processing ACK frames). Enables packet-number-based recovery
    /// detection: recovery ends when largestAckedPN > largestSentAtLastCutback.
    pub fn notifyLargestAcked(self: *Recovery, pn: u64) void {
        if (self.largest_acked_packet_number) |cur| {
            if (pn > cur) self.largest_acked_packet_number = pn;
        } else {
            self.largest_acked_packet_number = pn;
        }
        // Recovery ends when ACK confirms a packet sent
        // after the cutback. Transition to congestion avoidance.
        if (self.congestion_state == .recovery) {
            if (self.largest_sent_at_last_cutback) |cutback| {
                if (self.largest_acked_packet_number.? > cutback) {
                    self.congestion_state = .congestion_avoidance;
                }
            }
        }
    }

    /// Packet-number-based recovery check (RFC 6582).
    /// True when the largest ACKed packet was sent before or at the last
    /// cwnd cutback, meaning we are still in the recovery period.
    pub fn inRecoveryByPacketNumber(self: Recovery) bool {
        const acked = self.largest_acked_packet_number orelse return false;
        const cutback = self.largest_sent_at_last_cutback orelse return false;
        return acked <= cutback;
    }

    /// Record an acknowledged packet and update RTT/congestion state.
    pub fn onPacketAcked(
        self: *Recovery,
        bytes: usize,
        sent_time_nanos: i64,
        latest_rtt_ns: u64,
        ack_delay_ns: u64,
    ) void {
        self.onPacketAckedWithUtilization(bytes, sent_time_nanos, latest_rtt_ns, ack_delay_ns, true);
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
        sent_time_nanos: i64,
        latest_rtt_ns: u64,
        ack_delay_ns: u64,
        congestion_window_utilized: bool,
    ) void {
        self.removeBytesInFlight(bytes);
        self.updateRtt(latest_rtt_ns, ack_delay_ns);
        // Feed HyStart++ with RTT samples during slow start
        if (self.inSlowStart()) {
            self.hystart.onRttUpdate(
                @floatFromInt(self.congestion_window),
                sent_time_nanos,
                self.last_sent_time_nanos,
                latest_rtt_ns,
            );
        }
        self.onAckedBytesForCongestion(bytes, sent_time_nanos, congestion_window_utilized);
    }

    /// Record acknowledged bytes without taking an RTT sample.
    ///
    /// RFC 9002 only permits an RTT sample when the largest acknowledged packet
    /// carried by the ACK frame is newly acknowledged. ACKs that only newly
    /// acknowledge lower ranges still clear bytes in flight, reset PTO backoff,
    /// and feed congestion control, but must not update RTT estimates.
    pub fn onPacketAckedWithoutRttSample(
        self: *Recovery,
        bytes: usize,
        sent_time_nanos: i64,
        congestion_window_utilized: bool,
    ) void {
        self.removeBytesInFlight(bytes);
        self.onAckedBytesForCongestion(bytes, sent_time_nanos, congestion_window_utilized);
    }

    fn onAckedBytesForCongestion(
        self: *Recovery,
        bytes: usize,
        sent_time_nanos: i64,
        congestion_window_utilized: bool,
    ) void {
        self.pto_count = 0;
        if (!congestion_window_utilized) {
            // RFC 8312 §5.8: signal app-limited to CUBIC epoch.
            if (self.congestion_algorithm == .cubic) {
                self.cubic.onAppLimited(sent_time_nanos);
            }
            // Slow start must not grow when the window is underutilized.
            // Congestion avoidance still grows:
            // the app-limited signal only adjusts the CUBIC epoch timing.
            if (self.congestion_state != .congestion_avoidance) return;
        }
        // No cwnd growth during recovery. Recovery ends when
        // an ACK arrives for a packet sent after the recovery started.
        if (self.congestion_state == .recovery) {
            if (self.inCongestionRecovery(sent_time_nanos)) return;
            // Packet sent after recovery start → exit recovery.
            self.congestion_state = .congestion_avoidance;
        }

        if (self.inSlowStart()) {
            // HyStart++ may reduce growth rate during CSS phase
            const increment = self.hystart.cwndIncrement(bytes);
            const inc_usize: usize = @intFromFloat(@ceil(increment));
            self.congestion_window = std.math.add(usize, self.congestion_window, inc_usize) catch std.math.maxInt(usize);
            self.congestion_avoidance_bytes_acked = 0;
            return;
        }
        if (self.congestion_window == 0) {
            self.congestion_window = @max(bytes, minimumCongestionWindow(self.max_datagram_size));
            self.congestion_avoidance_bytes_acked = 0;
            return;
        }

        self.growCongestionAvoidance(bytes, sent_time_nanos);
    }

    /// Record packet loss and start a congestion recovery period if needed.
    pub fn onPacketLost(self: *Recovery, bytes: usize, lost_packet_sent_time_nanos: i64, now_nanos: i64) void {
        self.onPacketLostWithNumber(bytes, lost_packet_sent_time_nanos, now_nanos, null);
    }

    pub fn onPacketLostWithNumber(self: *Recovery, bytes: usize, lost_packet_sent_time_nanos: i64, now_nanos: i64, lost_pn: ?u64) void {
        self.packets_lost +%= 1;
        self.removeBytesInFlight(bytes);
        self.onCongestionEventWithPacketNumber(lost_packet_sent_time_nanos, now_nanos, lost_pn);
    }

    /// A packet was retransmitted (resend of a lost/timed-out packet).
    pub fn recordRetransmission(self: *Recovery) void {
        self.packets_retransmitted +%= 1;
    }

    /// Enter NewReno congestion recovery for a loss or ECN-CE congestion event.
    ///
    /// The caller is responsible for bytes-in-flight accounting. Loss removes
    /// packet bytes before calling this; ECN-CE marks an acknowledged packet as
    /// a congestion signal without treating that packet as lost.
    pub fn onCongestionEvent(self: *Recovery, sent_time_nanos: i64, now_nanos: i64) void {
        self.onCongestionEventWithPacketNumber(sent_time_nanos, now_nanos, null);
    }

    /// Packet-number-based congestion event (RFC 6582).
    /// Losses for packets sent before the last cutback are a single event (RFC 6582).
    pub fn onCongestionEventWithPacketNumber(self: *Recovery, sent_time_nanos: i64, now_nanos: i64, lost_packet_number: ?u64) void {
        // Once in recovery, block ALL congestion events (RFC 9002 §7.3.2).
        if (self.congestion_state == .recovery) return;
        // Fallback for connections without state tracking (tests).
        if (lost_packet_number) |pn| {
            if (self.largest_sent_at_last_cutback) |last_cut| {
                if (pn <= last_cut) return;
            }
        } else {
            if (self.inCongestionRecovery(sent_time_nanos)) return;
        }
        self.congestion_state = .recovery;
        self.congestion_recovery_start_time_nanos = now_nanos;
        self.fast_retransmission_required = true;
        self.largest_sent_at_last_cutback = self.largest_sent_packet_number;
        self.congestion_avoidance_bytes_acked = 0;
        switch (self.congestion_algorithm) {
            .new_reno => {
                self.ssthresh = self.congestion_window / 2;
                self.congestion_window = @max(self.ssthresh, minimumCongestionWindow(self.max_datagram_size));
                self.hystart.onCongestionEvent(@floatFromInt(self.ssthresh));
            },
            .cubic => {
                self.congestion_window = self.cubic.onCongestionEvent(
                    self.congestion_window,
                    self.max_datagram_size,
                    now_nanos,
                );
                self.ssthresh = self.congestion_window;
                self.hystart.onCongestionEvent(@floatFromInt(self.ssthresh));
            },
        }
    }

    /// Return whether a congestion signal for `sent_time_nanos` would start a
    /// new recovery period rather than being suppressed by the current one.
    pub fn wouldStartCongestionRecovery(self: Recovery, sent_time_nanos: i64) bool {
        return !self.inCongestionRecovery(sent_time_nanos);
    }

    /// Mark one PTO expiration and apply exponential backoff to future PTOs.
    pub fn onPtoExpired(self: *Recovery) void {
        if (self.pto_count != std.math.maxInt(u8)) {
            self.pto_count += 1;
        }
    }

    /// Current Probe Timeout in nanoseconds.
    pub fn ptoNs(self: *Recovery) u64 {
        return self.backedOffPtoNs(true);
    }

    /// Apply a changed maximum datagram size to congestion-control math.
    ///
    /// RFC 9002 uses the sender's current maximum datagram size for the
    /// initial window, minimum window, and congestion-avoidance growth. When
    /// the size decreases during handshake setup, the congestion window is
    /// reset to the recalculated initial window for the new size. When the
    /// size grows, an already-reduced window is raised to the new minimum.
    pub fn updateMaxDatagramSize(self: *Recovery, new_max_datagram_size: usize) void {
        const previous = self.max_datagram_size;
        if (previous == new_max_datagram_size) return;

        self.max_datagram_size = new_max_datagram_size;
        if (new_max_datagram_size < previous) {
            self.congestion_window = initialCongestionWindow(new_max_datagram_size);
            self.congestion_avoidance_bytes_acked = 0;
            return;
        }

        const minimum_window = minimumCongestionWindow(new_max_datagram_size);
        if (self.congestion_window < minimum_window) {
            self.congestion_window = minimum_window;
            self.congestion_avoidance_bytes_acked = 0;
        }
    }

    /// Current Initial/Handshake Probe Timeout in milliseconds.
    ///
    /// RFC 9002 sets `max_ack_delay` to zero for Initial and Handshake packet
    /// number spaces because those acknowledgments are not intentionally
    /// delayed.
    pub fn ptoNsWithoutMaxAckDelay(self: *Recovery) u64 {
        return self.backedOffPtoNs(false);
    }

    fn basePtoNs(self: Recovery, include_max_ack_delay: bool) u64 {
        const variance_delay = @max(saturatingMulU64(4, self.rttvar_ns), timer_granularity_ns);
        const ack_delay = if (include_max_ack_delay) self.max_ack_delay_ns else 0;
        return saturatingAddU64(saturatingAddU64(self.smoothed_rtt_ns, variance_delay), ack_delay);
    }

    fn backedOffPtoNs(self: *Recovery, include_max_ack_delay: bool) u64 {
        var timeout = self.basePtoWithJitterNs(include_max_ack_delay);
        var count = self.pto_count;
        while (count != 0) : (count -= 1) {
            timeout = saturatingMulU64(timeout, 2);
        }
        return timeout;
    }

    /// Base PTO with optional random jitter (RFC 9002 §A.8 recommendation).
    ///
    /// Jitter range is ±pto_jitter_percentage of the base PTO, matching the
    /// approach used by production QUIC stacks to decorrelate timeout storms.
    fn basePtoWithJitterNs(self: *Recovery, include_max_ack_delay: bool) u64 {
        const base = self.basePtoNs(include_max_ack_delay);
        const pct = self.pto_jitter_percentage;
        if (pct == 0) return base;

        const max_jitter = base * @as(u64, @min(pct, 50)) / 100;
        if (max_jitter == 0) return base;

        // Random value in [0, 2*max_jitter], then shift to [-max_jitter, +max_jitter].
        const range = 2 * max_jitter;
        const rand_val = self.prng.random().intRangeAtMost(u64, 0, range);
        const rand_signed: i64 = @intCast(rand_val);
        const max_signed: i64 = @intCast(max_jitter);
        const jitter: i64 = rand_signed - max_signed;

        const base_signed: i64 = @intCast(base);
        const result: i64 = base_signed + jitter;
        const gran_signed: i64 = @intCast(timer_granularity_ns);
        const clamped: u64 = if (result < gran_signed)
            timer_granularity_ns
        else
            @intCast(result);
        return clamped;
    }

    /// Persistent congestion duration from RFC 9002 Section 7.6.1.
    pub fn persistentCongestionDuration(self: Recovery) u64 {
        return std.math.mul(u64, self.basePtoNs(true), persistent_congestion_threshold) catch std.math.maxInt(u64);
    }

    /// Initial/Handshake persistent congestion duration from RFC 9002.
    ///
    /// Initial and Handshake packet number spaces use a zero max_ack_delay for
    /// PTO, so their persistent-congestion period must use the same base PTO.
    pub fn persistentCongestionDurationWithoutMaxAckDelay(self: Recovery) u64 {
        return std.math.mul(u64, self.basePtoNs(false), persistent_congestion_threshold) catch std.math.maxInt(u64);
    }

    /// Apply the persistent congestion response by reducing cwnd to kMinimumWindow.
    pub fn onPersistentCongestion(self: *Recovery) void {
        self.congestion_window = minimumCongestionWindow(self.max_datagram_size);
        self.congestion_state = .slow_start;
        self.congestion_avoidance_bytes_acked = 0;
        self.congestion_recovery_start_time_nanos = null;
        self.fast_retransmission_required = false;
    }

    /// Apply the persistent congestion response and refresh min_rtt when the
    /// same ACK produced the newest RTT sample.
    pub fn onPersistentCongestionWithRttSample(self: *Recovery, latest_rtt_ns: ?u64) void {
        self.onPersistentCongestion();
        if (latest_rtt_ns) |latest| {
            self.min_rtt_ns = latest;
        }
    }

    /// True when the sender is in slow start (cwnd below both ssthresh and
    /// the HyStart++ threshold).
    pub fn inSlowStart(self: Recovery) bool {
        if (self.congestion_state == .slow_start) {
            if (self.congestion_window >= self.ssthresh) return false;
            if (self.hystart.thresholdFound()) {
                return @as(f32, @floatFromInt(self.congestion_window)) < self.hystart.threshold;
            }
            return true;
        }
        return false;
    }

    fn inCongestionRecovery(self: Recovery, sent_time_nanos: i64) bool {
        const recovery_start = self.congestion_recovery_start_time_nanos orelse return false;
        return sent_time_nanos <= recovery_start;
    }

    fn removeBytesInFlight(self: *Recovery, bytes: usize) void {
        self.bytes_in_flight = if (bytes >= self.bytes_in_flight) 0 else self.bytes_in_flight - bytes;
    }

    fn growCongestionAvoidance(self: *Recovery, bytes: usize, now_nanos: i64) void {
        switch (self.congestion_algorithm) {
            .new_reno => self.growCongestionAvoidanceNewReno(bytes),
            .cubic => self.growCongestionAvoidanceCubic(bytes, now_nanos),
        }
    }

    fn growCongestionAvoidanceNewReno(self: *Recovery, bytes: usize) void {
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

    fn growCongestionAvoidanceCubic(self: *Recovery, bytes: usize, now_nanos: i64) void {
        const epoch_start = self.congestion_recovery_start_time_nanos orelse return;
        const mds_f: f64 = @floatFromInt(self.max_datagram_size);
        const cwnd_f: f64 = @floatFromInt(self.congestion_window);
        const rtt_sec: f64 = @as(f64, @floatFromInt(self.smoothed_rtt_ns)) / @as(f64, @floatFromInt(duration.ns_per_s));
        const t_sec: f64 = @as(f64, @floatFromInt(now_nanos - epoch_start)) / @as(f64, @floatFromInt(duration.ns_per_s));

        // Limit increase to half the acked bytes (Linux CUBIC behavior).
        const max_cwnd = cwnd_f + @as(f64, @floatFromInt(bytes)) / 2.0;

        // RFC 9438 §4.1-4.2: compare W_cubic(t) with W_est(t).
        const w_cubic = self.cubic.wCubicSegments(t_sec);
        const w_est = self.cubic.wEst(t_sec, rtt_sec);

        if (w_cubic < w_est) {
            // TCP-friendly region (RFC 9438 §4.2): set cwnd to W_est directly.
            const w_est_bytes: usize = @intFromFloat(w_est * mds_f);
            self.congestion_window = @min(w_est_bytes, @as(usize, @intFromFloat(max_cwnd)));
            return;
        }

        // Concave/Convex region (RFC 9438 §4.3-4.4):
        // target = W_cubic(t + RTT), per-ACK increment = (target - cwnd) / cwnd * mds.
        const w_cubic_target = self.cubic.wCubicSegments(t_sec + rtt_sec);
        const target_bytes = w_cubic_target * mds_f;
        if (cwnd_f >= target_bytes) return;
        const rate = (target_bytes - cwnd_f) / cwnd_f;
        const increment = rate * mds_f;
        const inc_usize: usize = @intFromFloat(@max(increment, 1.0));
        self.congestion_window = @min(
            self.congestion_window + inc_usize,
            @as(usize, @intFromFloat(max_cwnd)),
        );
    }

    /// Minimum trackable RTT (1ms). Prevents zero-RTT samples from collapsing
    /// the estimator on loopback paths (1ms granularity per RFC 9002 kGranularity).
    pub const min_trackable_rtt_ns: u64 = 1_000; // 1μs minimum trackable RTT

    pub fn updateRtt(self: *Recovery, latest_rtt_ns: u64, ack_delay_ns: u64) void {
        const clamped_rtt = @max(latest_rtt_ns, min_trackable_rtt_ns);
        const had_rtt_sample = self.latest_rtt_ns != null;
        self.latest_rtt_ns = clamped_rtt;
        self.min_rtt_ns = if (self.min_rtt_ns) |min_rtt| @min(min_rtt, clamped_rtt) else clamped_rtt;

        const min_rtt = self.min_rtt_ns.?;
        const adjusted_rtt = if (clamped_rtt > saturatingAddU64(min_rtt, ack_delay_ns))
            clamped_rtt - ack_delay_ns
        else
            clamped_rtt;

        if (!had_rtt_sample) {
            self.smoothed_rtt_ns = adjusted_rtt;
            self.rttvar_ns = adjusted_rtt / 2;
            return;
        }

        const rtt_delta = if (self.smoothed_rtt_ns > adjusted_rtt)
            self.smoothed_rtt_ns - adjusted_rtt
        else
            adjusted_rtt - self.smoothed_rtt_ns;

        self.rttvar_ns = saturatingAddU64(saturatingMulU64(3, self.rttvar_ns), rtt_delta) / 4;
        self.smoothed_rtt_ns = saturatingAddU64(saturatingMulU64(7, self.smoothed_rtt_ns), adjusted_rtt) / 8;
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
pub fn timeThresholdLossDelayNs(latest_rtt_ns: ?u64, smoothed_rtt_ns: u64) u64 {
    const rtt_basis = if (latest_rtt_ns) |latest_rtt| @max(latest_rtt, smoothed_rtt_ns) else smoothed_rtt_ns;
    const loss_delay = saturatingCeilMulDivU64(rtt_basis, time_threshold_numerator, time_threshold_denominator);
    return @max(loss_delay, timer_granularity_ns);
}

test "initial and minimum congestion windows follow RFC 9002 bounds" {
    try std.testing.expectEqual(@as(usize, 13500), initialCongestionWindow(1350));
    try std.testing.expectEqual(@as(usize, 2400), minimumCongestionWindow(1200));

    // RFC 9002 §4.1 clamps the initial window to 14720 bytes once
    // 10 * max_datagram_size exceeds it.
    try std.testing.expectEqual(@as(usize, 14720), initialCongestionWindow(1472));
    try std.testing.expectEqual(@as(usize, 14720), initialCongestionWindow(1500));
}

test "time threshold loss delay follows RFC 9002 multiplier and granularity" {
    try std.testing.expectEqual(@as(u64, 374_625_000), timeThresholdLossDelayNs(null, 333_000_000));
    try std.testing.expectEqual(@as(u64, 451_125_000), timeThresholdLossDelayNs(401_000_000, 333_000_000));
    try std.testing.expectEqual(@as(u64, 1_000_000), timeThresholdLossDelayNs(0, 0));
    try std.testing.expectEqual(std.math.maxInt(u64), timeThresholdLossDelayNs(std.math.maxInt(u64), 1));
}

test "sent acked and lost packets update bytes in flight and congestion window" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 333 });
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

test "available congestion window saturates at zero" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 100 });
    recovery.congestion_window = 3600;

    try std.testing.expectEqual(@as(usize, 3600), recovery.availableCongestionWindow());
    recovery.onPacketSent(1200);
    try std.testing.expectEqual(@as(usize, 2400), recovery.availableCongestionWindow());
    recovery.onPacketSent(3000);
    try std.testing.expectEqual(@as(usize, 0), recovery.availableCongestionWindow());
}

test "sent packet accounting saturates bytes in flight" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 100 });
    recovery.bytes_in_flight = std.math.maxInt(usize) - 5;

    recovery.onPacketSent(10);
    try std.testing.expectEqual(std.math.maxInt(usize), recovery.bytes_in_flight);
    try std.testing.expect(!recovery.canSend(1));
    try std.testing.expectEqual(@as(usize, 0), recovery.availableCongestionWindow());

    recovery.onPacketAckedWithoutRttSample(std.math.maxInt(usize), 0, false);
    try std.testing.expectEqual(@as(usize, 0), recovery.bytes_in_flight);
}

test "NewReno slow start grows congestion window by acked bytes" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 100 });
    const initial_window = recovery.congestion_window;

    recovery.onPacketSent(1200);
    recovery.onPacketAcked(1200, 0, 100, 0);

    try std.testing.expectEqual(@as(usize, 0), recovery.bytes_in_flight);
    try std.testing.expectEqual(initial_window + 1200, recovery.congestion_window);
    try std.testing.expectEqual(std.math.maxInt(usize), recovery.ssthresh);
}

test "NewReno congestion avoidance grows by byte-counted cwnd credit" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 100 });
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
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 100 });
    recovery.congestion_window = 12_000;
    recovery.ssthresh = 12_000;

    recovery.onPacketSent(25_200);
    recovery.onPacketAcked(25_200, 0, 100, 0);

    try std.testing.expectEqual(@as(usize, 0), recovery.bytes_in_flight);
    try std.testing.expectEqual(@as(usize, 0), recovery.congestion_avoidance_bytes_acked);
    try std.testing.expectEqual(@as(usize, 14_400), recovery.congestion_window);
}

test "max datagram size update resets cwnd on decrease and preserves cwnd on increase" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1400, .initial_rtt_ns = 100 });
    try std.testing.expectEqual(@as(usize, 14_000), recovery.congestion_window);

    recovery.congestion_window = 20_000;
    recovery.ssthresh = 12_000;
    recovery.congestion_avoidance_bytes_acked = 7_000;
    recovery.updateMaxDatagramSize(1200);
    try std.testing.expectEqual(@as(usize, 1200), recovery.max_datagram_size);
    try std.testing.expectEqual(@as(usize, 12_000), recovery.congestion_window);
    try std.testing.expectEqual(@as(usize, 12_000), recovery.ssthresh);
    try std.testing.expectEqual(@as(usize, 0), recovery.congestion_avoidance_bytes_acked);
    try std.testing.expectEqual(@as(usize, 2400), minimumCongestionWindow(recovery.max_datagram_size));

    recovery.congestion_window = 12_600;
    recovery.congestion_avoidance_bytes_acked = 600;
    recovery.updateMaxDatagramSize(1300);
    try std.testing.expectEqual(@as(usize, 1300), recovery.max_datagram_size);
    try std.testing.expectEqual(@as(usize, 12_600), recovery.congestion_window);
    try std.testing.expectEqual(@as(usize, 600), recovery.congestion_avoidance_bytes_acked);

    recovery.congestion_window = 2000;
    recovery.congestion_avoidance_bytes_acked = 700;
    recovery.updateMaxDatagramSize(1500);
    try std.testing.expectEqual(@as(usize, 1500), recovery.max_datagram_size);
    try std.testing.expectEqual(@as(usize, 3000), recovery.congestion_window);
    try std.testing.expectEqual(@as(usize, 0), recovery.congestion_avoidance_bytes_acked);
}

test "underutilized ACK updates recovery accounting without growing congestion window" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 100_000_000 });
    const initial_window = recovery.congestion_window;

    recovery.onPacketSent(1200);
    recovery.onPtoExpired();
    recovery.onPacketAckedWithUtilization(1200, 0, 80_000_000, 0, false);

    try std.testing.expectEqual(@as(usize, 0), recovery.bytes_in_flight);
    try std.testing.expectEqual(@as(u8, 0), recovery.pto_count);
    try std.testing.expectEqual(@as(?u64, 80_000_000), recovery.latest_rtt_ns);
    try std.testing.expectEqual(@as(u64, 80_000_000), recovery.smoothed_rtt_ns);
    try std.testing.expectEqual(initial_window, recovery.congestion_window);
}

test "ACK accounting can skip RTT sample while resetting PTO" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 100 });
    const initial_window = recovery.congestion_window;

    recovery.onPacketSent(1200);
    recovery.onPtoExpired();
    recovery.onPacketAckedWithoutRttSample(1200, 0, false);

    try std.testing.expectEqual(@as(usize, 0), recovery.bytes_in_flight);
    try std.testing.expectEqual(@as(u8, 0), recovery.pto_count);
    try std.testing.expectEqual(@as(?u64, null), recovery.latest_rtt_ns);
    try std.testing.expectEqual(@as(u64, 100), recovery.smoothed_rtt_ns);
    try std.testing.expectEqual(initial_window, recovery.congestion_window);
}

test "ACK delay does not reduce adjusted RTT below min RTT" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 100_000_000 });

    recovery.onPacketSent(1200);
    recovery.onPacketAcked(1200, 0, 100_000_000, 0);
    try std.testing.expectEqual(@as(?u64, 100_000_000), recovery.min_rtt_ns);
    try std.testing.expectEqual(@as(u64, 100_000_000), recovery.smoothed_rtt_ns);
    try std.testing.expectEqual(@as(u64, 50_000_000), recovery.rttvar_ns);

    recovery.onPacketSent(1200);
    recovery.onPacketAcked(1200, 1, 110_000_000, 20_000_000);
    try std.testing.expectEqual(@as(?u64, 100_000_000), recovery.min_rtt_ns);
    try std.testing.expectEqual(@as(?u64, 110_000_000), recovery.latest_rtt_ns);
    try std.testing.expectEqual(@as(u64, 101_250_000), recovery.smoothed_rtt_ns);
    try std.testing.expectEqual(@as(u64, 40_000_000), recovery.rttvar_ns);

    recovery.onPacketSent(1200);
    recovery.onPacketAcked(1200, 2, 150_000_000, 20_000_000);
    try std.testing.expectEqual(@as(?u64, 100_000_000), recovery.min_rtt_ns);
    try std.testing.expectEqual(@as(?u64, 150_000_000), recovery.latest_rtt_ns);
    try std.testing.expectEqual(@as(u64, 104_843_750), recovery.smoothed_rtt_ns);
    try std.testing.expectEqual(@as(u64, 37_187_500), recovery.rttvar_ns);
}

test "pto uses rtt variance and exponential backoff" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 100_000_000, .max_ack_delay_ns = 25_000_000 });

    try std.testing.expectEqual(@as(u64, 325_000_000), recovery.ptoNs());
    try std.testing.expectEqual(@as(u64, 300_000_000), recovery.ptoNsWithoutMaxAckDelay());
    recovery.onPtoExpired();
    try std.testing.expectEqual(@as(u64, 650_000_000), recovery.ptoNs());
    try std.testing.expectEqual(@as(u64, 600_000_000), recovery.ptoNsWithoutMaxAckDelay());

    recovery.onPacketAcked(0, 0, 80_000_000, 0);
    try std.testing.expectEqual(@as(u8, 0), recovery.pto_count);
    try std.testing.expect(recovery.ptoNs() < 650_000_000);
}

test "pto expiration count saturates before overflowing" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 100 });
    recovery.pto_count = std.math.maxInt(u8) - 1;

    recovery.onPtoExpired();
    try std.testing.expectEqual(std.math.maxInt(u8), recovery.pto_count);
    try std.testing.expectEqual(std.math.maxInt(u64), recovery.ptoNs());

    recovery.onPtoExpired();
    try std.testing.expectEqual(std.math.maxInt(u8), recovery.pto_count);
    try std.testing.expectEqual(std.math.maxInt(u64), recovery.ptoNsWithoutMaxAckDelay());
}

test "pto jitter stays within configured percentage bounds" {
    var recovery = Recovery.init(.{
        .max_datagram_size = 1200,
        .initial_rtt_ns = 100_000_000, // 100ms
        .pto_jitter_percentage = 25,
    });
    // base PTO = smoothed_rtt + 4*rttvar + max_ack_delay
    //          = 100ms + 4*50ms + 25ms = 325ms
    const base_pto: u64 = 325_000_000;
    const max_jitter = base_pto * 25 / 100; // 81.25ms

    var seen_above = false;
    var seen_below = false;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        const pto = recovery.ptoNs();
        // Must be within [base - max_jitter, base + max_jitter]
        try std.testing.expect(pto >= base_pto - max_jitter);
        try std.testing.expect(pto <= base_pto + max_jitter);
        if (pto > base_pto) seen_above = true;
        if (pto < base_pto) seen_below = true;
    }
    // With 200 samples and 25% jitter, both sides should appear
    try std.testing.expect(seen_above);
    try std.testing.expect(seen_below);
}

test "pto jitter zero percentage is deterministic" {
    var recovery = Recovery.init(.{
        .max_datagram_size = 1200,
        .initial_rtt_ns = 100_000_000,
        .pto_jitter_percentage = 0,
    });
    const pto1 = recovery.ptoNs();
    const pto2 = recovery.ptoNs();
    try std.testing.expectEqual(pto1, pto2);
    try std.testing.expectEqual(@as(u64, 325_000_000), pto1);
}

test "congestion recovery period avoids repeated loss reduction and ACK growth" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 100 });
    const initial_window = recovery.congestion_window;

    recovery.onPacketSent(3600);
    try std.testing.expect(recovery.wouldStartCongestionRecovery(10));
    recovery.onPacketLost(1200, 10, 100);
    const recovery_window = recovery.congestion_window;
    try std.testing.expect(recovery_window < initial_window);
    try std.testing.expectEqual(@as(?i64, 100), recovery.congestion_recovery_start_time_nanos);
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

test "ACK inside NewReno recovery updates accounting without congestion growth" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 100_000_000 });
    recovery.congestion_window = 12_000;
    recovery.ssthresh = 12_000;
    recovery.congestion_avoidance_bytes_acked = 600;
    recovery.onPacketSent(12_000);
    recovery.onPtoExpired();

    recovery.onCongestionEvent(20, 100);
    const recovery_window = recovery.congestion_window;
    try std.testing.expectEqual(@as(usize, 6_000), recovery_window);
    try std.testing.expectEqual(@as(usize, 0), recovery.congestion_avoidance_bytes_acked);
    try std.testing.expectEqual(@as(u8, 1), recovery.pto_count);

    recovery.onPacketAcked(1200, 100, 80_000_000, 0);
    try std.testing.expectEqual(@as(usize, 10_800), recovery.bytes_in_flight);
    try std.testing.expectEqual(@as(u8, 0), recovery.pto_count);
    try std.testing.expectEqual(@as(?u64, 80_000_000), recovery.latest_rtt_ns);
    try std.testing.expectEqual(@as(u64, 80_000_000), recovery.smoothed_rtt_ns);
    try std.testing.expectEqual(recovery_window, recovery.congestion_window);
    try std.testing.expectEqual(@as(usize, 0), recovery.congestion_avoidance_bytes_acked);

    recovery.onPacketAcked(6_000, 101, 80_000_000, 0);
    try std.testing.expectEqual(@as(usize, 4_800), recovery.bytes_in_flight);
    try std.testing.expectEqual(recovery_window + 1200, recovery.congestion_window);
    try std.testing.expectEqual(@as(usize, 0), recovery.congestion_avoidance_bytes_acked);
}

test "NewReno congestion event clamps cwnd without clamping ssthresh" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 100 });
    recovery.congestion_window = 3_000;

    recovery.onCongestionEvent(10, 100);

    try std.testing.expectEqual(@as(usize, 1_500), recovery.ssthresh);
    try std.testing.expectEqual(minimumCongestionWindow(1200), recovery.congestion_window);
}

test "ECN congestion event enters recovery without removing bytes in flight" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 100 });
    const initial_window = recovery.congestion_window;

    recovery.onPacketSent(2400);
    recovery.onCongestionEvent(10, 100);
    const recovery_window = recovery.congestion_window;
    try std.testing.expect(recovery_window < initial_window);
    try std.testing.expectEqual(recovery_window, recovery.ssthresh);
    try std.testing.expectEqual(@as(usize, 2400), recovery.bytes_in_flight);
    try std.testing.expectEqual(@as(?i64, 100), recovery.congestion_recovery_start_time_nanos);

    recovery.onCongestionEvent(20, 110);
    try std.testing.expectEqual(recovery_window, recovery.congestion_window);

    recovery.onPacketAcked(1200, 50, 100, 0);
    try std.testing.expectEqual(@as(usize, 1200), recovery.bytes_in_flight);
    try std.testing.expectEqual(recovery_window, recovery.congestion_window);
}

test "persistent congestion duration and response follow RFC 9002 bounds" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 100_000_000, .max_ack_delay_ns = 25_000_000 });

    try std.testing.expectEqual(@as(u64, 975_000_000), recovery.persistentCongestionDuration());
    try std.testing.expectEqual(@as(u64, 900_000_000), recovery.persistentCongestionDurationWithoutMaxAckDelay());
    recovery.onPtoExpired();
    recovery.onPtoExpired();
    try std.testing.expectEqual(@as(u64, 1_300_000_000), recovery.ptoNs());
    try std.testing.expectEqual(@as(u64, 975_000_000), recovery.persistentCongestionDuration());
    try std.testing.expectEqual(@as(u64, 900_000_000), recovery.persistentCongestionDurationWithoutMaxAckDelay());

    recovery.congestion_window = 12_000;
    recovery.ssthresh = 6_000;
    recovery.congestion_recovery_start_time_nanos = 42;
    recovery.onPersistentCongestion();
    try std.testing.expectEqual(minimumCongestionWindow(1200), recovery.congestion_window);
    try std.testing.expectEqual(@as(usize, 6_000), recovery.ssthresh);
    try std.testing.expectEqual(@as(?i64, null), recovery.congestion_recovery_start_time_nanos);
    try std.testing.expect(recovery.wouldStartCongestionRecovery(43));

    recovery.congestion_avoidance_bytes_acked = 600;
    recovery.onCongestionEvent(43, 50);
    try std.testing.expectEqual(@as(?i64, 50), recovery.congestion_recovery_start_time_nanos);
    try std.testing.expectEqual(@as(usize, 0), recovery.congestion_avoidance_bytes_acked);
    try std.testing.expectEqual(minimumCongestionWindow(1200), recovery.congestion_window);
    try std.testing.expectEqual(@as(usize, 1200), recovery.ssthresh);
}

test "persistent congestion refreshes min RTT from newest sample when present" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 100_000_000 });

    recovery.onPacketSent(1200);
    recovery.onPacketAcked(1200, 0, 50_000_000, 0);
    try std.testing.expectEqual(@as(?u64, 50_000_000), recovery.min_rtt_ns);
    try std.testing.expectEqual(@as(?u64, 50_000_000), recovery.latest_rtt_ns);

    recovery.onPacketSent(1200);
    recovery.onPacketAcked(1200, 100, 500_000_000, 0);
    try std.testing.expectEqual(@as(?u64, 50_000_000), recovery.min_rtt_ns);
    try std.testing.expectEqual(@as(?u64, 500_000_000), recovery.latest_rtt_ns);

    recovery.onPersistentCongestionWithRttSample(recovery.latest_rtt_ns);
    try std.testing.expectEqual(@as(?u64, 500_000_000), recovery.min_rtt_ns);
    try std.testing.expectEqual(minimumCongestionWindow(1200), recovery.congestion_window);
}

test "recovery arithmetic saturates at numeric extremes" {
    try std.testing.expectEqual(std.math.maxInt(usize), initialCongestionWindow(std.math.maxInt(usize)));
    try std.testing.expectEqual(std.math.maxInt(usize), minimumCongestionWindow(std.math.maxInt(usize)));

    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 100 });
    recovery.smoothed_rtt_ns = std.math.maxInt(u64);
    recovery.rttvar_ns = std.math.maxInt(u64);
    try std.testing.expectEqual(std.math.maxInt(u64), recovery.ptoNs());

    recovery.max_datagram_size = std.math.maxInt(usize);
    recovery.congestion_window = 1;
    recovery.ssthresh = 0;
    recovery.onPacketAcked(1, 0, std.math.maxInt(u64), std.math.maxInt(u64));
    try std.testing.expectEqual(std.math.maxInt(usize), recovery.congestion_window);
    try std.testing.expectEqual(@as(usize, 0), recovery.congestion_avoidance_bytes_acked);
}

test "CUBIC congestion control through Recovery interface" {
    var r = Recovery.init(.{
        .max_datagram_size = 1200,
        .initial_rtt_ns = 100000000,
        .congestion_algorithm = .cubic,
    });

    const initial_cwnd = r.congestion_window;
    try std.testing.expect(initial_cwnd > 0);

    // Simulate sending packets
    r.onPacketSent(1200);
    r.onPacketSent(1200);
    try std.testing.expectEqual(@as(usize, 2400), r.bytes_in_flight);

    // Simulate loss — CUBIC should reduce window by beta (0.7)
    r.onPacketLost(1200, 50, 100);
    try std.testing.expectEqual(@as(usize, 1200), r.bytes_in_flight);
    try std.testing.expect(r.congestion_window < initial_cwnd);
    try std.testing.expect(r.congestion_recovery_start_time_nanos != null);

    // CUBIC state should be set
    try std.testing.expect(r.cubic.w_max > 0);
    try std.testing.expect(r.cubic.epoch_start_nanos != null);
}

test "NewReno still works when selected" {
    var r = Recovery.init(.{
        .max_datagram_size = 1200,
        .initial_rtt_ns = 100000000,
        .congestion_algorithm = .new_reno,
    });

    const initial_cwnd = r.congestion_window;
    r.onPacketSent(1200);
    r.onPacketLost(1200, 50, 100);

    // NewReno halves the window
    try std.testing.expectEqual(initial_cwnd / 2, r.ssthresh);
    try std.testing.expect(r.congestion_window >= r.ssthresh);
}

test "PN-based recovery blocks then allows growth after cutback ACK" {
    var r = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 100_000_000, .congestion_algorithm = .cubic });
    r.largest_sent_packet_number = 100;
    r.onPacketSent(12000);
    const cwnd_before = r.congestion_window;

    // Loss at PN 50 → cutback, largest_sent_at_last_cutback = 100
    r.onPacketLostWithNumber(1200, 1_000_000_000, 2_000_000_000, 50);
    try std.testing.expect(r.congestion_window < cwnd_before);
    try std.testing.expectEqual(@as(?u64, 100), r.largest_sent_at_last_cutback);

    // ACK for PN 90 (before cutback) → still in recovery, no growth
    r.notifyLargestAcked(90);
    try std.testing.expect(r.inRecoveryByPacketNumber());
    const cwnd_in_recovery = r.congestion_window;
    r.onPacketAckedWithUtilization(1200, 1_500_000_000, 100_000_000, 0, true);
    try std.testing.expectEqual(cwnd_in_recovery, r.congestion_window);

    // ACK for PN 101 (after cutback) → recovery ends, growth resumes
    r.notifyLargestAcked(101);
    try std.testing.expect(!r.inRecoveryByPacketNumber());
    r.onPacketAckedWithUtilization(1200, 5_000_000_000, 100_000_000, 0, true);
    try std.testing.expect(r.congestion_window > cwnd_in_recovery);
}

test "path reset preserves accounting and excludes old-path ACK and loss training" {
    var state = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ns = 333_000_000 });
    state.bytes_in_flight = 200;
    state.last_sent_time_nanos = 10;
    state.congestion_window = 120_000;
    state.smoothed_rtt_ns = 10_000_000;
    state.resetPath(333_000_000, 1200);
    const initial_window = state.congestion_window;
    state.onPreviousPathAck(100);
    try std.testing.expectEqual(@as(usize, 100), state.bytes_in_flight);
    try std.testing.expect(state.min_rtt_ns == null);
    try std.testing.expectEqual(@as(u64, 333_000_000), state.smoothed_rtt_ns);
    try std.testing.expectEqual(initial_window, state.congestion_window);
    state.onPreviousPathLoss(100);
    try std.testing.expectEqual(@as(usize, 0), state.bytes_in_flight);
    try std.testing.expectEqual(initial_window, state.congestion_window);
    state.bytes_in_flight = 100;
    state.onPacketAcked(100, 20, 30_000_000, 0);
    try std.testing.expectEqual(@as(u64, 30_000_000), state.smoothed_rtt_ns);
    try std.testing.expect(state.congestion_window > initial_window);
}
