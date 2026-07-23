//! Multipath QUIC path management (draft-ietf-quic-multipath).
//!
//! Implements per-connection multipath state: path identifiers,
//! path status tracking, and per-path RTT/congestion state.

const std = @import("std");

/// Path status per draft-ietf-quic-multipath §3.
pub const PathStatus = enum {
    /// Path is available for sending.
    available,
    /// Path is on standby (backup).
    standby,
    /// Path has been abandoned.
    abandoned,
};

/// Per-path state tracked by the multipath manager.
pub const PathState = struct {
    /// Unique path identifier (64-bit).
    path_id: u64,
    /// Current path status.
    status: PathStatus = .available,
    /// Whether the path has been validated (PATH_CHALLENGE/RESPONSE).
    validated: bool = false,
    /// Smoothed RTT for this path (milliseconds).
    smoothed_rtt_ms: u64 = 333,
    /// Minimum RTT observed on this path.
    min_rtt_ms: ?u64 = null,
    /// Bytes in flight on this path.
    bytes_in_flight: usize = 0,
    /// Congestion window for this path.
    congestion_window: usize = 14720,
    /// Whether this is the primary path.
    is_primary: bool = false,
};

/// Multipath manager: tracks all paths for a connection.
pub const MultipathManager = struct {
    paths: std.ArrayList(PathState) = .empty,
    allocator: std.mem.Allocator,
    next_path_id: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) MultipathManager {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *MultipathManager) void {
        self.paths.deinit(self.allocator);
    }

    /// Add a new path and return its path ID.
    pub fn addPath(self: *MultipathManager) !u64 {
        const path_id = self.next_path_id;
        self.next_path_id += 1;
        try self.paths.append(self.allocator, .{
            .path_id = path_id,
            .is_primary = self.paths.items.len == 0,
        });
        return path_id;
    }

    /// Get a path by its ID.
    pub fn getPath(self: *const MultipathManager, path_id: u64) ?*PathState {
        for (self.paths.items) |*path| {
            if (path.path_id == path_id) return path;
        }
        return null;
    }

    /// Abandon a path (PATH_ABANDON).
    pub fn abandonPath(self: *MultipathManager, path_id: u64) !void {
        const path = self.getPath(path_id) orelse return error.UnknownPath;
        path.status = .abandoned;
    }

    /// Set a path's status (PATH_STATUS).
    pub fn setPathStatus(self: *MultipathManager, path_id: u64, status: PathStatus) !void {
        const path = self.getPath(path_id) orelse return error.UnknownPath;
        if (path.status == .abandoned) return error.PathAbandoned;
        path.status = status;
    }

    /// Mark a path as validated after PATH_CHALLENGE/RESPONSE.
    pub fn validatePath(self: *MultipathManager, path_id: u64) !void {
        const path = self.getPath(path_id) orelse return error.UnknownPath;
        path.validated = true;
    }

    /// Return the number of active (non-abandoned) paths.
    pub fn activePathCount(self: *const MultipathManager) usize {
        var count: usize = 0;
        for (self.paths.items) |path| {
            if (path.status != .abandoned) count += 1;
        }
        return count;
    }

    /// Return the primary path, if any.
    pub fn primaryPath(self: *const MultipathManager) ?*const PathState {
        for (self.paths.items) |*path| {
            if (path.is_primary and path.status != .abandoned) return path;
        }
        return null;
    }

    /// Select the best available path for sending (lowest RTT among available).
    pub fn selectSendPath(self: *const MultipathManager) ?*const PathState {
        var best: ?*const PathState = null;
        for (self.paths.items) |*path| {
            if (path.status != .available) continue;
            if (best == null or path.smoothed_rtt_ms < best.?.smoothed_rtt_ms) {
                best = path;
            }
        }
        return best;
    }
};

test "MultipathManager add and get paths" {
    var mp = MultipathManager.init(std.testing.allocator);
    defer mp.deinit();

    const id0 = try mp.addPath();
    const id1 = try mp.addPath();
    try std.testing.expectEqual(@as(u64, 0), id0);
    try std.testing.expectEqual(@as(u64, 1), id1);
    try std.testing.expectEqual(@as(usize, 2), mp.activePathCount());

    const path0 = mp.getPath(id0).?;
    try std.testing.expect(path0.is_primary);
    const path1 = mp.getPath(id1).?;
    try std.testing.expect(!path1.is_primary);
}

test "MultipathManager abandon path" {
    var mp = MultipathManager.init(std.testing.allocator);
    defer mp.deinit();

    const id0 = try mp.addPath();
    _ = try mp.addPath();
    try std.testing.expectEqual(@as(usize, 2), mp.activePathCount());

    try mp.abandonPath(id0);
    try std.testing.expectEqual(@as(usize, 1), mp.activePathCount());
    try std.testing.expectEqual(PathStatus.abandoned, mp.getPath(id0).?.status);
}

test "MultipathManager path status transitions" {
    var mp = MultipathManager.init(std.testing.allocator);
    defer mp.deinit();

    const id = try mp.addPath();
    try mp.setPathStatus(id, .standby);
    try std.testing.expectEqual(PathStatus.standby, mp.getPath(id).?.status);

    try mp.setPathStatus(id, .available);
    try std.testing.expectEqual(PathStatus.available, mp.getPath(id).?.status);

    try mp.abandonPath(id);
    try std.testing.expectError(error.PathAbandoned, mp.setPathStatus(id, .available));
}

test "MultipathManager validate path" {
    var mp = MultipathManager.init(std.testing.allocator);
    defer mp.deinit();

    const id = try mp.addPath();
    try std.testing.expect(!mp.getPath(id).?.validated);
    try mp.validatePath(id);
    try std.testing.expect(mp.getPath(id).?.validated);
}

test "MultipathManager select best send path" {
    var mp = MultipathManager.init(std.testing.allocator);
    defer mp.deinit();

    const id0 = try mp.addPath();
    const id1 = try mp.addPath();

    mp.getPath(id0).?.smoothed_rtt_ms = 100;
    mp.getPath(id1).?.smoothed_rtt_ms = 50;

    const best = mp.selectSendPath().?;
    try std.testing.expectEqual(id1, best.path_id);

    // Abandon the best path, should fall back to id0
    try mp.abandonPath(id1);
    const fallback = mp.selectSendPath().?;
    try std.testing.expectEqual(id0, fallback.path_id);
}

test "MultipathManager primary path" {
    var mp = MultipathManager.init(std.testing.allocator);
    defer mp.deinit();

    const id0 = try mp.addPath();
    _ = try mp.addPath();

    try std.testing.expectEqual(id0, mp.primaryPath().?.path_id);

    try mp.abandonPath(id0);
    try std.testing.expect(mp.primaryPath() == null);
}
