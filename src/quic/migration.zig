//! Connection migration production flow (RFC 9000 §9).
//!
//! Handles NAT rebinding detection, path validation production flow,
//! and anti-amplification limits for server-side migration.

const std = @import("std");

/// Anti-amplification state for server-side migration (RFC 9000 §8.1).
/// Servers must not send more than 3x the received bytes on an
/// unvalidated path.
pub const AntiAmplification = struct {
    /// Bytes received from the peer on the current path.
    bytes_received: usize = 0,
    /// Bytes sent to the peer on the current path.
    bytes_sent: usize = 0,
    /// Amplification limit factor (default 3x per RFC 9000).
    limit_factor: usize = 3,

    /// Record received bytes.
    pub fn onReceived(self: *AntiAmplification, bytes: usize) void {
        self.bytes_received += bytes;
    }

    /// Record sent bytes.
    pub fn onSent(self: *AntiAmplification, bytes: usize) void {
        self.bytes_sent += bytes;
    }

    /// Return the maximum bytes that can be sent on the unvalidated path.
    pub fn sendBudget(self: *const AntiAmplification) usize {
        const limit = self.bytes_received * self.limit_factor;
        if (self.bytes_sent >= limit) return 0;
        return limit - self.bytes_sent;
    }

    /// Whether the server is amplification-limited.
    /// Not limited if no data has been received yet (initial state).
    pub fn isLimited(self: *const AntiAmplification) bool {
        if (self.bytes_received == 0) return false;
        return self.sendBudget() == 0;
    }

    /// Whether the path is validated (no amplification limit).
    pub fn isPathValidated(self: *const AntiAmplification) bool {
        return self.bytes_received > 0 and self.bytes_sent <= self.bytes_received;
    }

    /// Reset state for a new path.
    pub fn reset(self: *AntiAmplification) void {
        self.bytes_received = 0;
        self.bytes_sent = 0;
    }
};

/// NAT rebinding detector.
pub const NatRebindingDetector = struct {
    /// Last seen peer address (opaque bytes).
    last_peer_addr: ?[]const u8 = null,
    /// Number of rebinding events detected.
    rebinding_count: usize = 0,

    /// Check if the peer address has changed (NAT rebinding).
    /// Returns true if a rebinding was detected.
    pub fn checkPeerAddress(self: *NatRebindingDetector, new_addr: []const u8) bool {
        if (self.last_peer_addr) |last| {
            if (!std.mem.eql(u8, last, new_addr)) {
                self.rebinding_count += 1;
                self.last_peer_addr = new_addr;
                return true;
            }
            return false;
        }
        self.last_peer_addr = new_addr;
        return false;
    }
};

/// Path validation state machine (RFC 9000 §8.2).
pub const PathValidation = enum {
    /// No validation in progress.
    idle,
    /// PATH_CHALLENGE sent, waiting for PATH_RESPONSE.
    challenge_sent,
    /// PATH_RESPONSE received, path validated.
    validated,
    /// Validation failed (timeout or invalid response).
    failed,
};

/// Migration manager: coordinates NAT rebinding, path validation,
/// and anti-amplification for connection migration.
pub const MigrationManager = struct {
    anti_amplification: AntiAmplification = .{},
    nat_detector: NatRebindingDetector = .{},
    validation_state: PathValidation = .idle,
    /// Number of PATH_CHALLENGE retransmissions.
    challenge_retries: u8 = 0,
    /// Maximum PATH_CHALLENGE retries before declaring failure.
    max_challenge_retries: u8 = 3,

    /// Handle a received datagram: check for NAT rebinding.
    /// On rebinding, resets amplification state for the new path.
    pub fn onDatagramReceived(self: *MigrationManager, peer_addr: []const u8, bytes: usize) bool {
        const rebound = self.nat_detector.checkPeerAddress(peer_addr);
        if (rebound) {
            self.anti_amplification.reset();
        }
        self.anti_amplification.onReceived(bytes);
        return rebound;
    }

    /// Handle a sent datagram: track amplification.
    pub fn onDatagramSent(self: *MigrationManager, bytes: usize) void {
        self.anti_amplification.onSent(bytes);
    }

    /// Start path validation after NAT rebinding.
    /// Resets sent bytes but keeps received bytes for amplification tracking.
    pub fn startValidation(self: *MigrationManager) void {
        self.validation_state = .challenge_sent;
        self.challenge_retries = 0;
        self.anti_amplification.bytes_sent = 0;
    }

    /// Record PATH_RESPONSE received.
    pub fn onPathResponse(self: *MigrationManager) void {
        if (self.validation_state == .challenge_sent) {
            self.validation_state = .validated;
        }
    }

    /// Record PATH_CHALLENGE timeout.
    pub fn onChallengeTimeout(self: *MigrationManager) void {
        self.challenge_retries += 1;
        if (self.challenge_retries >= self.max_challenge_retries) {
            self.validation_state = .failed;
        }
    }

    /// Whether the current path is validated and safe to send.
    pub fn canSend(self: *const MigrationManager) bool {
        return switch (self.validation_state) {
            .idle, .validated => true,
            .challenge_sent => !self.anti_amplification.isLimited(),
            .failed => false,
        };
    }
};

test "AntiAmplification 3x limit" {
    var aa = AntiAmplification{};
    aa.onReceived(1000);
    try std.testing.expectEqual(@as(usize, 3000), aa.sendBudget());
    try std.testing.expect(!aa.isLimited());

    aa.onSent(2000);
    try std.testing.expectEqual(@as(usize, 1000), aa.sendBudget());

    aa.onSent(1000);
    try std.testing.expect(aa.isLimited());
    try std.testing.expectEqual(@as(usize, 0), aa.sendBudget());
}

test "AntiAmplification reset" {
    var aa = AntiAmplification{};
    aa.onReceived(1000);
    aa.onSent(3000);
    try std.testing.expect(aa.isLimited());

    aa.reset();
    try std.testing.expect(!aa.isLimited());
    try std.testing.expectEqual(@as(usize, 0), aa.bytes_received);
}

test "NatRebindingDetector detects address change" {
    var detector = NatRebindingDetector{};
    try std.testing.expect(!detector.checkPeerAddress("192.168.1.1:443"));
    try std.testing.expect(!detector.checkPeerAddress("192.168.1.1:443"));
    try std.testing.expect(detector.checkPeerAddress("10.0.0.1:5555"));
    try std.testing.expectEqual(@as(usize, 1), detector.rebinding_count);
    try std.testing.expect(!detector.checkPeerAddress("10.0.0.1:5555"));
}

test "MigrationManager full flow" {
    var mm = MigrationManager{};

    // Initial datagrams
    _ = mm.onDatagramReceived("addr1", 1200);
    mm.onDatagramSent(1200);
    try std.testing.expect(mm.canSend());

    // NAT rebinding detected
    const rebound = mm.onDatagramReceived("addr2", 1200);
    try std.testing.expect(rebound);

    // Start validation
    mm.startValidation();
    try std.testing.expectEqual(PathValidation.challenge_sent, mm.validation_state);

    // Amplification limit applies during validation
    mm.onDatagramSent(3600); // 3x 1200 received
    try std.testing.expect(!mm.canSend());

    // PATH_RESPONSE received
    mm.onPathResponse();
    try std.testing.expectEqual(PathValidation.validated, mm.validation_state);
    try std.testing.expect(mm.canSend());
}

test "MigrationManager challenge timeout" {
    var mm = MigrationManager{};
    mm.startValidation();

    mm.onChallengeTimeout();
    try std.testing.expectEqual(PathValidation.challenge_sent, mm.validation_state);
    mm.onChallengeTimeout();
    mm.onChallengeTimeout();
    try std.testing.expectEqual(PathValidation.failed, mm.validation_state);
    try std.testing.expect(!mm.canSend());
}
