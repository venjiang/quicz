const std = @import("std");

const timer_granularity_ms = 1;

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
    pub fn onPacketAcked(self: *Recovery, bytes: usize, latest_rtt_ms: u64, ack_delay_ms: u64) void {
        self.removeBytesInFlight(bytes);
        self.updateRtt(latest_rtt_ms, ack_delay_ms);
        self.pto_count = 0;

        if (self.congestion_window < self.ssthresh) {
            self.congestion_window = std.math.add(usize, self.congestion_window, bytes) catch std.math.maxInt(usize);
            return;
        }

        const increase = @max(@as(usize, 1), (self.max_datagram_size * bytes) / self.congestion_window);
        self.congestion_window = std.math.add(usize, self.congestion_window, increase) catch std.math.maxInt(usize);
    }

    /// Record packet loss and reduce the congestion window to at least 2 packets.
    pub fn onPacketLost(self: *Recovery, bytes: usize) void {
        self.removeBytesInFlight(bytes);
        self.ssthresh = @max(self.congestion_window / 2, minimumCongestionWindow(self.max_datagram_size));
        self.congestion_window = self.ssthresh;
    }

    /// Mark one PTO expiration and apply exponential backoff to future PTOs.
    pub fn onPtoExpired(self: *Recovery) void {
        if (self.pto_count != std.math.maxInt(u8)) {
            self.pto_count += 1;
        }
    }

    /// Current Probe Timeout in milliseconds.
    pub fn ptoMs(self: Recovery) u64 {
        const variance_delay = @max(4 * self.rttvar_ms, timer_granularity_ms);
        var timeout = self.smoothed_rtt_ms + variance_delay + self.max_ack_delay_ms;

        var count = self.pto_count;
        while (count != 0) : (count -= 1) {
            timeout = std.math.mul(u64, timeout, 2) catch return std.math.maxInt(u64);
        }
        return timeout;
    }

    fn removeBytesInFlight(self: *Recovery, bytes: usize) void {
        self.bytes_in_flight = if (bytes >= self.bytes_in_flight) 0 else self.bytes_in_flight - bytes;
    }

    fn updateRtt(self: *Recovery, latest_rtt_ms: u64, ack_delay_ms: u64) void {
        const had_rtt_sample = self.latest_rtt_ms != null;
        self.latest_rtt_ms = latest_rtt_ms;
        self.min_rtt_ms = if (self.min_rtt_ms) |min_rtt| @min(min_rtt, latest_rtt_ms) else latest_rtt_ms;

        const min_rtt = self.min_rtt_ms.?;
        const adjusted_rtt = if (latest_rtt_ms > min_rtt + ack_delay_ms)
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

        self.rttvar_ms = (3 * self.rttvar_ms + rtt_delta) / 4;
        self.smoothed_rtt_ms = (7 * self.smoothed_rtt_ms + adjusted_rtt) / 8;
    }
};

/// Compute the RFC 9002 initial congestion window in bytes.
pub fn initialCongestionWindow(max_datagram_size: usize) usize {
    return @min(10 * max_datagram_size, @max(2 * max_datagram_size, 14720));
}

/// Compute the minimum congestion window in bytes.
pub fn minimumCongestionWindow(max_datagram_size: usize) usize {
    return 2 * max_datagram_size;
}

test "initial and minimum congestion windows follow RFC 9002 bounds" {
    try std.testing.expectEqual(@as(usize, 13500), initialCongestionWindow(1350));
    try std.testing.expectEqual(@as(usize, 2400), minimumCongestionWindow(1200));
}

test "sent acked and lost packets update bytes in flight and congestion window" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ms = 333 });
    const initial_window = recovery.congestion_window;

    try std.testing.expect(recovery.canSend(1200));
    recovery.onPacketSent(1200);
    try std.testing.expectEqual(@as(usize, 1200), recovery.bytes_in_flight);

    recovery.onPacketAcked(1200, 100, 0);
    try std.testing.expectEqual(@as(usize, 0), recovery.bytes_in_flight);
    try std.testing.expect(recovery.congestion_window > initial_window);
    try std.testing.expectEqual(@as(u8, 0), recovery.pto_count);

    recovery.onPacketSent(2400);
    recovery.onPacketLost(2400);
    try std.testing.expectEqual(@as(usize, 0), recovery.bytes_in_flight);
    try std.testing.expect(recovery.congestion_window >= minimumCongestionWindow(1200));
}

test "pto uses rtt variance and exponential backoff" {
    var recovery = Recovery.init(.{ .max_datagram_size = 1200, .initial_rtt_ms = 100, .max_ack_delay_ms = 25 });

    try std.testing.expectEqual(@as(u64, 325), recovery.ptoMs());
    recovery.onPtoExpired();
    try std.testing.expectEqual(@as(u64, 650), recovery.ptoMs());

    recovery.onPacketAcked(0, 80, 0);
    try std.testing.expectEqual(@as(u8, 0), recovery.pto_count);
    try std.testing.expect(recovery.ptoMs() < 650);
}
