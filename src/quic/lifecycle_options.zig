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
