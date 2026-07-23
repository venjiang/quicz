//! DPLPMTUD — Datagram Packetization Layer PMTU Discovery (RFC 8899).
//!
//! Implements QUIC Path MTU Discovery per RFC 9000 Section 14.
//! Probes with increasingly large UDP payloads to discover the
//! effective path MTU without relying on ICMP.

const std = @import("std");

/// QUIC minimum UDP payload size (RFC 9000 §14).
pub const QUIC_MIN_MTU: usize = 1200;

/// Default probe sizes for DPLPMTUD (RFC 8899 §5.1).
pub const DEFAULT_PROBE_SIZES = [_]usize{ 1200, 1350, 1500, 2000, 4000, 8000 };

/// DPLPMTUD state machine.
pub const PmtuProbe = struct {
    /// Current effective MTU (confirmed by ACK).
    effective_mtu: usize = QUIC_MIN_MTU,
    /// Index into probe_sizes for the next probe to attempt.
    probe_index: usize = 0,
    /// Whether a probe is currently in flight.
    probe_in_flight: bool = false,
    /// Number of consecutive probe failures at the current size.
    probe_failures: u8 = 0,
    /// Maximum consecutive failures before giving up on a probe size.
    max_probe_failures: u8 = 3,
    /// Probe sizes to try.
    probe_sizes: []const usize = &DEFAULT_PROBE_SIZES,
    /// Whether PMTU discovery is complete (no more sizes to probe).
    discovery_complete: bool = false,

    /// Return the next probe size to attempt, or null if discovery is complete.
    pub fn nextProbeSize(self: *PmtuProbe) ?usize {
        if (self.discovery_complete) return null;
        // Skip probe sizes that are not larger than the current effective MTU.
        while (self.probe_index < self.probe_sizes.len and
            self.probe_sizes[self.probe_index] <= self.effective_mtu)
        {
            self.probe_index += 1;
        }
        if (self.probe_index >= self.probe_sizes.len) {
            self.discovery_complete = true;
            return null;
        }
        return self.probe_sizes[self.probe_index];
    }

    /// Start a probe at the next size. Returns the probe size, or null if done.
    pub fn startProbe(self: *PmtuProbe) ?usize {
        const size = self.nextProbeSize() orelse {
            self.discovery_complete = true;
            return null;
        };
        self.probe_in_flight = true;
        return size;
    }

    /// Record that the current probe was acknowledged (success).
    /// Increases the effective MTU to the probe size.
    pub fn onProbeAcked(self: *PmtuProbe) void {
        if (!self.probe_in_flight) return;
        if (self.probe_index < self.probe_sizes.len) {
            self.effective_mtu = self.probe_sizes[self.probe_index];
        }
        self.probe_in_flight = false;
        self.probe_failures = 0;
        self.probe_index += 1;
        if (self.probe_index >= self.probe_sizes.len) {
            self.discovery_complete = true;
        }
    }

    /// Record that the current probe was lost (failure).
    /// After max_probe_failures, skips to the next smaller probe or completes.
    pub fn onProbeLost(self: *PmtuProbe) void {
        if (!self.probe_in_flight) return;
        self.probe_failures += 1;
        if (self.probe_failures >= self.max_probe_failures) {
            // Give up on this size and stop probing larger sizes.
            self.probe_in_flight = false;
            self.discovery_complete = true;
        }
        // Otherwise, retry the same probe size.
    }

    /// Reset the probe state (e.g., after path migration).
    pub fn reset(self: *PmtuProbe) void {
        self.effective_mtu = QUIC_MIN_MTU;
        self.probe_index = 0;
        self.probe_in_flight = false;
        self.probe_failures = 0;
        self.discovery_complete = false;
    }
};

test "PmtuProbe starts at QUIC minimum MTU" {
    const probe = PmtuProbe{};
    try std.testing.expectEqual(QUIC_MIN_MTU, probe.effective_mtu);
    try std.testing.expect(!probe.discovery_complete);
}

test "PmtuProbe discovers larger MTU through successful probes" {
    var probe = PmtuProbe{};

    // First probe: 1350 (index 1, since 1200 <= effective_mtu)
    const size1 = probe.startProbe();
    try std.testing.expect(size1 != null);
    try std.testing.expectEqual(@as(usize, 1350), size1.?);

    // ACK the probe
    probe.onProbeAcked();
    try std.testing.expectEqual(@as(usize, 1350), probe.effective_mtu);

    // Next probe: 1500
    const size2 = probe.startProbe();
    try std.testing.expect(size2 != null);
    try std.testing.expectEqual(@as(usize, 1500), size2.?);

    probe.onProbeAcked();
    try std.testing.expectEqual(@as(usize, 1500), probe.effective_mtu);
}

test "PmtuProbe stops after repeated failures" {
    var probe = PmtuProbe{};
    probe.max_probe_failures = 2;

    _ = probe.startProbe();
    probe.onProbeLost();
    try std.testing.expect(!probe.discovery_complete);

    probe.onProbeLost();
    try std.testing.expect(probe.discovery_complete);
    try std.testing.expectEqual(QUIC_MIN_MTU, probe.effective_mtu);
}

test "PmtuProbe reset restores initial state" {
    var probe = PmtuProbe{};
    _ = probe.startProbe();
    probe.onProbeAcked();
    try std.testing.expect(probe.effective_mtu > QUIC_MIN_MTU);

    probe.reset();
    try std.testing.expectEqual(QUIC_MIN_MTU, probe.effective_mtu);
    try std.testing.expect(!probe.discovery_complete);
    try std.testing.expectEqual(@as(usize, 0), probe.probe_index);
}

test "PmtuProbe completes when all sizes exhausted" {
    var probe = PmtuProbe{};
    probe.probe_sizes = &[_]usize{ 1200, 1350 };

    // 1200 <= effective_mtu, skip to 1350
    const size = probe.startProbe();
    try std.testing.expectEqual(@as(usize, 1350), size.?);
    probe.onProbeAcked();
    try std.testing.expect(probe.discovery_complete);
    try std.testing.expect(probe.nextProbeSize() == null);
}
