//! QUIC connection metrics and error tracking.
//!
//! Provides counters and gauges for observability:
//! packets sent/received/lost, bytes transferred, RTT, and error counts.

const std = @import("std");

/// Connection-level metrics counters.
pub const ConnectionMetrics = struct {
    /// Total packets sent.
    packets_sent: u64 = 0,
    /// Total packets received.
    packets_received: u64 = 0,
    /// Total packets lost (detected by recovery).
    packets_lost: u64 = 0,
    /// Total bytes sent (payload only).
    bytes_sent: u64 = 0,
    /// Total bytes received (payload only).
    bytes_received: u64 = 0,
    /// Total streams opened.
    streams_opened: u64 = 0,
    /// Total streams completed (FIN received).
    streams_completed: u64 = 0,
    /// Total DATAGRAM frames sent.
    datagrams_sent: u64 = 0,
    /// Total DATAGRAM frames received.
    datagrams_received: u64 = 0,
    /// Current smoothed RTT (ms).
    smoothed_rtt_ms: u64 = 0,
    /// Minimum RTT observed (ms).
    min_rtt_ms: u64 = 0,
    /// Current congestion window (bytes).
    congestion_window: usize = 0,
    /// Current bytes in flight.
    bytes_in_flight: usize = 0,
    /// Handshake duration (ms), set once.
    handshake_duration_ms: ?u64 = null,
    /// Connection start timestamp (ms).
    start_ms: i64 = 0,

    /// Record a packet sent.
    pub fn recordPacketSent(self: *ConnectionMetrics, payload_len: usize) void {
        self.packets_sent += 1;
        self.bytes_sent += payload_len;
    }

    /// Record a packet received.
    pub fn recordPacketReceived(self: *ConnectionMetrics, payload_len: usize) void {
        self.packets_received += 1;
        self.bytes_received += payload_len;
    }

    /// Record a packet lost.
    pub fn recordPacketLost(self: *ConnectionMetrics) void {
        self.packets_lost += 1;
    }

    /// Record a stream opened.
    pub fn recordStreamOpened(self: *ConnectionMetrics) void {
        self.streams_opened += 1;
    }

    /// Record a stream completed.
    pub fn recordStreamCompleted(self: *ConnectionMetrics) void {
        self.streams_completed += 1;
    }

    /// Record a datagram sent.
    pub fn recordDatagramSent(self: *ConnectionMetrics) void {
        self.datagrams_sent += 1;
    }

    /// Record a datagram received.
    pub fn recordDatagramReceived(self: *ConnectionMetrics) void {
        self.datagrams_received += 1;
    }

    /// Update RTT metrics.
    pub fn updateRtt(self: *ConnectionMetrics, smoothed_ms: u64, min_ms: u64) void {
        self.smoothed_rtt_ms = smoothed_ms;
        self.min_rtt_ms = min_ms;
    }

    /// Update congestion state.
    pub fn updateCongestion(self: *ConnectionMetrics, cwnd: usize, bif: usize) void {
        self.congestion_window = cwnd;
        self.bytes_in_flight = bif;
    }

    /// Packet loss rate as a fraction (0.0 to 1.0).
    pub fn lossRate(self: *const ConnectionMetrics) f64 {
        const total = self.packets_sent;
        if (total == 0) return 0.0;
        return @as(f64, @floatFromInt(self.packets_lost)) / @as(f64, @floatFromInt(total));
    }

    /// Connection duration in milliseconds.
    pub fn durationMs(self: *const ConnectionMetrics, now_ms: i64) i64 {
        return now_ms - self.start_ms;
    }
};

/// Error tracking for a connection.
pub const ErrorTracker = struct {
    /// Total errors by category.
    transport_errors: u64 = 0,
    crypto_errors: u64 = 0,
    flow_control_errors: u64 = 0,
    protocol_errors: u64 = 0,
    /// Last error code (0 = none).
    last_error_code: u64 = 0,
    /// Last error timestamp (ms).
    last_error_ms: ?i64 = null,

    /// Record a transport error.
    pub fn recordTransportError(self: *ErrorTracker, code: u64, now_ms: i64) void {
        self.transport_errors += 1;
        self.last_error_code = code;
        self.last_error_ms = now_ms;
    }

    /// Record a crypto/TLS error.
    pub fn recordCryptoError(self: *ErrorTracker, code: u64, now_ms: i64) void {
        self.crypto_errors += 1;
        self.last_error_code = code;
        self.last_error_ms = now_ms;
    }

    /// Record a flow control error.
    pub fn recordFlowControlError(self: *ErrorTracker, code: u64, now_ms: i64) void {
        self.flow_control_errors += 1;
        self.last_error_code = code;
        self.last_error_ms = now_ms;
    }

    /// Record a protocol violation.
    pub fn recordProtocolError(self: *ErrorTracker, code: u64, now_ms: i64) void {
        self.protocol_errors += 1;
        self.last_error_code = code;
        self.last_error_ms = now_ms;
    }

    /// Total errors across all categories.
    pub fn totalErrors(self: *const ErrorTracker) u64 {
        return self.transport_errors + self.crypto_errors + self.flow_control_errors + self.protocol_errors;
    }
};

test "ConnectionMetrics packet tracking" {
    var m = ConnectionMetrics{};
    m.recordPacketSent(1200);
    m.recordPacketSent(800);
    m.recordPacketReceived(1200);
    m.recordPacketLost();

    try std.testing.expectEqual(@as(u64, 2), m.packets_sent);
    try std.testing.expectEqual(@as(u64, 2000), m.bytes_sent);
    try std.testing.expectEqual(@as(u64, 1), m.packets_received);
    try std.testing.expectEqual(@as(u64, 1), m.packets_lost);
    try std.testing.expectEqual(@as(f64, 0.5), m.lossRate());
}

test "ConnectionMetrics stream and datagram tracking" {
    var m = ConnectionMetrics{};
    m.recordStreamOpened();
    m.recordStreamOpened();
    m.recordStreamCompleted();
    m.recordDatagramSent();
    m.recordDatagramReceived();

    try std.testing.expectEqual(@as(u64, 2), m.streams_opened);
    try std.testing.expectEqual(@as(u64, 1), m.streams_completed);
    try std.testing.expectEqual(@as(u64, 1), m.datagrams_sent);
    try std.testing.expectEqual(@as(u64, 1), m.datagrams_received);
}

test "ConnectionMetrics RTT and congestion" {
    var m = ConnectionMetrics{};
    m.updateRtt(50, 30);
    m.updateCongestion(14400, 7200);

    try std.testing.expectEqual(@as(u64, 50), m.smoothed_rtt_ms);
    try std.testing.expectEqual(@as(u64, 30), m.min_rtt_ms);
    try std.testing.expectEqual(@as(usize, 14400), m.congestion_window);
    try std.testing.expectEqual(@as(usize, 7200), m.bytes_in_flight);
}

test "ConnectionMetrics duration" {
    var m = ConnectionMetrics{ .start_ms = 1000 };
    try std.testing.expectEqual(@as(i64, 5000), m.durationMs(6000));
}

test "ErrorTracker categorization" {
    var tracker = ErrorTracker{};
    tracker.recordTransportError(0x04, 100);
    tracker.recordCryptoError(0x012a, 200);
    tracker.recordFlowControlError(0x08, 300);
    tracker.recordProtocolError(0x0a, 400);

    try std.testing.expectEqual(@as(u64, 4), tracker.totalErrors());
    try std.testing.expectEqual(@as(u64, 1), tracker.transport_errors);
    try std.testing.expectEqual(@as(u64, 1), tracker.crypto_errors);
    try std.testing.expectEqual(@as(u64, 1), tracker.flow_control_errors);
    try std.testing.expectEqual(@as(u64, 1), tracker.protocol_errors);
    try std.testing.expectEqual(@as(u64, 0x0a), tracker.last_error_code);
    try std.testing.expectEqual(@as(?i64, 400), tracker.last_error_ms);
}

test "ErrorTracker empty state" {
    const tracker = ErrorTracker{};
    try std.testing.expectEqual(@as(u64, 0), tracker.totalErrors());
    try std.testing.expectEqual(@as(u64, 0), tracker.last_error_code);
    try std.testing.expect(tracker.last_error_ms == null);
}
