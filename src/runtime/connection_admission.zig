//! Aggregate pending and active connection capacity shared by UDP listeners.

const std = @import("std");

/// Borrowed by servers. Keep this value stable until every server's deinit returns.
pub const ConnectionAdmission = struct {
    maximum: usize,
    in_use: std.atomic.Value(usize) = .init(0),

    /// Create an empty connection budget. Zero disables new admissions.
    pub fn init(maximum: usize) ConnectionAdmission {
        return .{ .maximum = maximum };
    }

    /// Reserve one slot before allocating connection state.
    pub fn tryAcquire(self: *ConnectionAdmission) bool {
        var current = self.in_use.load(.acquire);
        while (current < self.maximum) {
            current = self.in_use.cmpxchgWeak(current, current + 1, .acq_rel, .acquire) orelse return true;
        }
        return false;
    }

    /// Release exactly one reservation after its connection state is destroyed.
    pub fn release(self: *ConnectionAdmission) void {
        const previous = self.in_use.fetchSub(1, .acq_rel);
        std.debug.assert(previous != 0);
    }

    /// Count reservations held by pending and active connection records.
    pub fn inUse(self: *const ConnectionAdmission) usize {
        return self.in_use.load(.acquire);
    }
};
