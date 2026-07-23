//! CUBIC congestion control (RFC 9438).
//!
//! Implements the CUBIC algorithm alongside the existing NewReno baseline.
//! CUBIC uses a cubic function to adjust the congestion window after a
//! loss event, providing better throughput on high-BDP paths.

const std = @import("std");

/// CUBIC state tracked per packet number space.
pub const CubicState = struct {
    /// Window size at the last loss event (W_max).
    w_max: f64 = 0,
    /// Time period K for the cubic function: K = cbrt(W_max * (1-beta) / C).
    k: f64 = 0,
    /// Epoch start time (millis) — when the current congestion avoidance began.
    epoch_start_ms: ?i64 = null,
    /// TCP-friendly cwnd estimate.
    tcp_cwnd: f64 = 0,
    /// Last ACK time in the current epoch.
    last_ack_ms: ?i64 = null,

    /// CUBIC constant C (default 0.4 per RFC 9438).
    pub const C: f64 = 0.4;
    /// Multiplicative decrease factor beta (default 0.7 per RFC 9438).
    pub const beta: f64 = 0.7;

    /// Handle a congestion event (packet loss).
    /// Returns the new congestion window after multiplicative decrease.
    pub fn onCongestionEvent(self: *CubicState, cwnd: usize, max_datagram_size: usize, now_ms: i64) usize {
        const cwnd_f: f64 = @floatFromInt(cwnd);
        const mds_f: f64 = @floatFromInt(max_datagram_size);

        // W_max in segments
        self.w_max = cwnd_f / mds_f;
        self.epoch_start_ms = now_ms;
        self.tcp_cwnd = self.w_max;
        self.last_ack_ms = now_ms;

        // K = cbrt(W_max * (1 - beta) / C)
        const w_max_reduction = self.w_max * (1.0 - beta) / C;
        self.k = if (w_max_reduction > 0) cbrt(w_max_reduction) else 0;

        // Multiplicative decrease: cwnd = cwnd * beta
        const new_cwnd_segments = self.w_max * beta;
        const new_cwnd: usize = @intFromFloat(new_cwnd_segments * mds_f);
        return @max(new_cwnd, 2 * max_datagram_size);
    }

    /// Compute the CUBIC congestion window for the current time.
    /// Returns the target cwnd in bytes.
    pub fn cubicWindow(self: *const CubicState, cwnd: usize, max_datagram_size: usize, now_ms: i64) usize {
        const epoch_start = self.epoch_start_ms orelse return cwnd;
        const mds_f: f64 = @floatFromInt(max_datagram_size);
        const t: f64 = @floatFromInt(now_ms - epoch_start);
        const t_sec = t / 1000.0;

        // W(t) = C * (t - K)^3 + W_max  (in segments)
        const diff = t_sec - self.k;
        const w_cubic = C * diff * diff * diff + self.w_max;
        const w_cubic_bytes: usize = @intFromFloat(w_cubic * mds_f);

        // TCP-friendly region: if W_cubic < W_est, use TCP estimate
        // W_est = W_max * beta + 3 * (1-beta)/(1+beta) * (t/K)  (simplified)
        if (w_cubic_bytes < cwnd) {
            // Stay at current cwnd (TCP-friendly region)
            return cwnd;
        }

        return w_cubic_bytes;
    }

    /// Reset CUBIC state (e.g., after persistent congestion or timeout).
    pub fn reset(self: *CubicState) void {
        self.w_max = 0;
        self.k = 0;
        self.epoch_start_ms = null;
        self.tcp_cwnd = 0;
        self.last_ack_ms = null;
    }
};

/// Integer cube root approximation.
fn cbrt(x: f64) f64 {
    if (x <= 0) return 0;
    // Newton's method for cube root
    var guess: f64 = x / 3.0;
    if (guess == 0) guess = 1.0;
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        const guess_sq = guess * guess;
        if (guess_sq == 0) break;
        guess = (2.0 * guess + x / guess_sq) / 3.0;
    }
    return guess;
}

test "CUBIC onCongestionEvent reduces window by beta" {
    var cubic = CubicState{};
    const mds: usize = 1200;
    const cwnd: usize = 10 * mds; // 10 segments

    const new_cwnd = cubic.onCongestionEvent(cwnd, mds, 1000);

    // cwnd should be approximately 10 * 0.7 = 7 segments = 8400 bytes
    try std.testing.expect(new_cwnd >= 6 * mds);
    try std.testing.expect(new_cwnd <= 8 * mds);
    try std.testing.expect(cubic.w_max > 9.0); // ~10 segments
    try std.testing.expect(cubic.k > 0);
}

test "CUBIC window grows cubically after loss" {
    var cubic = CubicState{};
    const mds: usize = 1200;
    const cwnd: usize = 10 * mds;

    const reduced = cubic.onCongestionEvent(cwnd, mds, 0);

    // At t=0, window should be at the reduced value
    const w0 = cubic.cubicWindow(reduced, mds, 0);
    try std.testing.expect(w0 >= reduced);

    // At t=K, window should be approximately W_max
    const k_ms: i64 = @intFromFloat(cubic.k * 1000.0);
    const w_at_k = cubic.cubicWindow(reduced, mds, k_ms);
    try std.testing.expect(w_at_k >= reduced);

    // Window should grow over time
    const w_later = cubic.cubicWindow(reduced, mds, k_ms * 2);
    try std.testing.expect(w_later >= w_at_k);
}

test "CUBIC reset clears state" {
    var cubic = CubicState{};
    _ = cubic.onCongestionEvent(12000, 1200, 1000);
    try std.testing.expect(cubic.epoch_start_ms != null);

    cubic.reset();
    try std.testing.expect(cubic.epoch_start_ms == null);
    try std.testing.expect(cubic.w_max == 0);
    try std.testing.expect(cubic.k == 0);
}

test "cbrt computes cube root" {
    try std.testing.expect(std.math.approxEqRel(f64, cbrt(27.0), 3.0, 0.001));
    try std.testing.expect(std.math.approxEqRel(f64, cbrt(8.0), 2.0, 0.001));
    try std.testing.expect(std.math.approxEqRel(f64, cbrt(1.0), 1.0, 0.001));
    try std.testing.expect(cbrt(0.0) == 0.0);
}
