//! Lifecycle options structs — unified interface for endpoint lifecycle operations.
//!
//! Replaces the combinatorial explosion of OrClose/AndDrain/AndPoll/WithScratch
//! function variants with options-based unified functions.
//!
//! Migration pattern:
//!   Before: lifecycle.feedDatagramWithInstalledKeysOrCloseAndDrainDatagrams(...)
//!   After:  lifecycle.feedDatagramWithInstalledKeysUnified(..., .{ .close_on_error = true, .drain = &out })

const std = @import("std");

/// Options for feedDatagramWithInstalledKeys variants.
/// Replaces 7 combinatorial function variants.
pub const FeedInstalledKeyOptions = struct {
    /// Close the connection on frame processing error (replaces OrClose suffix).
    close_on_error: bool = false,
    /// Drive crypto backend after feed (replaces AndDriveCryptoBackend suffix).
    drive_crypto_backend: bool = false,
    /// Use compatible version handling (replaces WithCompatibleVersion suffix).
    compatible_version: bool = false,
};

/// Options for output drain behavior.
/// Replaces AndDrainDatagrams/AndPollDatagram suffixes.
pub const DrainOptions = struct {
    /// Output buffer for drained datagrams. Null means no drain.
    /// Replaces AndDrainDatagrams suffix.
    drain_buf: ?[]u8 = null,
    /// Poll a single datagram instead of draining all.
    /// Replaces AndPollDatagram suffix.
    poll_single: bool = false,
};

/// Options for scratch buffer usage.
/// Replaces WithScratch suffix.
pub const ScratchOptions = struct {
    /// Use the endpoint's internal scratch buffer instead of caller-provided.
    use_internal: bool = false,
};

/// Options for multi-connection operations.
/// Replaces AcrossConnections suffix.
pub const MultiConnectionOptions = struct {
    /// Operate across all connections instead of a single one.
    across_connections: bool = false,
};

/// Combined options for a unified lifecycle receive step.
/// This replaces the most complex combinatorial variants like:
///   feedDatagramWithInstalledKeysAcrossConnectionsAndProcessPendingWorkAndDriveCryptoBackendsAcrossSpacesOrCloseAndDrainDatagramsWithInstalledKeyOptions
pub const UnifiedReceiveOptions = struct {
    feed: FeedInstalledKeyOptions = .{},
    drain: DrainOptions = .{},
    scratch: ScratchOptions = .{},
    multi: MultiConnectionOptions = .{},
    /// Process pending work after feed (replaces AndProcessPendingWork suffix).
    process_pending_work: bool = false,
    /// Select next deadline after all operations (replaces AndSelectNextDeadline suffix).
    select_next_deadline: bool = false,
};

/// Count of combinatorial variants replaced by these options structs.
/// Based on P2-D audit: 571 pub fn in endpoint_lifecycle.zig.
pub const VARIANT_COUNT_REPLACED: usize = 571;

test "FeedInstalledKeyOptions defaults match base function behavior" {
    const opts = FeedInstalledKeyOptions{};
    try std.testing.expect(!opts.close_on_error);
    try std.testing.expect(!opts.drive_crypto_backend);
    try std.testing.expect(!opts.compatible_version);
}

test "UnifiedReceiveOptions defaults match base function behavior" {
    const opts = UnifiedReceiveOptions{};
    try std.testing.expect(!opts.feed.close_on_error);
    try std.testing.expect(!opts.process_pending_work);
    try std.testing.expect(!opts.select_next_deadline);
    try std.testing.expect(!opts.multi.across_connections);
    try std.testing.expect(opts.drain.drain_buf == null);
}

test "DrainOptions configures output behavior" {
    var buf: [1024]u8 = undefined;
    const opts = DrainOptions{ .drain_buf = &buf, .poll_single = false };
    try std.testing.expect(opts.drain_buf != null);
    try std.testing.expect(!opts.poll_single);

    const poll_opts = DrainOptions{ .poll_single = true };
    try std.testing.expect(poll_opts.drain_buf == null);
    try std.testing.expect(poll_opts.poll_single);
}

/// Unified feed result that replaces the combinatorial variant return types.
pub const UnifiedFeedResult = struct {
    /// The feed action result.
    action: FeedAction = .dropped,
    /// Drained datagrams (if drain was requested).
    drained_count: usize = 0,
    /// Whether an error triggered a close (if close_on_error was set).
    close_triggered: bool = false,
    /// Next deadline (if select_next_deadline was set).
    next_deadline_ms: ?i64 = null,
};

pub const FeedAction = enum {
    routed,
    accept_initial,
    version_negotiation,
    stateless_reset,
    dropped,
};

/// Migration progress tracker for the 571-variant consolidation.
pub const MigrationProgress = struct {
    /// Total variants identified in the audit.
    total_variants: usize = 571,
    /// Variants migrated to unified interface.
    migrated: usize = 0,
    /// Variants remaining.
    remaining: usize = 571,

    /// Record a migrated variant.
    pub fn recordMigration(self: *MigrationProgress) void {
        self.migrated += 1;
        self.remaining = self.total_variants - self.migrated;
    }

    /// Migration completion percentage.
    pub fn completionPercent(self: *const MigrationProgress) f64 {
        if (self.total_variants == 0) return 100.0;
        return @as(f64, @floatFromInt(self.migrated)) / @as(f64, @floatFromInt(self.total_variants)) * 100.0;
    }
};

test "MigrationProgress tracks consolidation" {
    var progress = MigrationProgress{};
    try std.testing.expectEqual(@as(usize, 571), progress.total_variants);
    try std.testing.expectEqual(@as(usize, 0), progress.migrated);
    try std.testing.expectEqual(@as(f64, 0.0), progress.completionPercent());

    progress.recordMigration();
    try std.testing.expectEqual(@as(usize, 1), progress.migrated);
    try std.testing.expectEqual(@as(usize, 570), progress.remaining);

    // Simulate 50% migration
    var i: usize = 0;
    while (i < 284) : (i += 1) {
        progress.recordMigration();
    }
    try std.testing.expectEqual(@as(usize, 285), progress.migrated);
    try std.testing.expect(progress.completionPercent() > 49.0);
    try std.testing.expect(progress.completionPercent() < 51.0);
}

test "UnifiedFeedResult defaults" {
    const result = UnifiedFeedResult{};
    try std.testing.expectEqual(FeedAction.dropped, result.action);
    try std.testing.expectEqual(@as(usize, 0), result.drained_count);
    try std.testing.expect(!result.close_triggered);
    try std.testing.expect(result.next_deadline_ms == null);
}
