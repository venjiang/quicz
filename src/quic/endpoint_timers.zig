const std = @import("std");

const endpoint_types = @import("endpoint_types.zig");
const transport_types = @import("transport_types.zig");

const Error = transport_types.Error;
const LossDetectionTimerDeadline = transport_types.LossDetectionTimerDeadline;
const EndpointLossDetectionTimerDeadline = endpoint_types.EndpointLossDetectionTimerDeadline;

/// Endpoint/event-loop owner for QUIC loss detection timer scheduling.
///
/// This helper does not own connection objects and performs no socket I/O.
/// Call `armFromConnection()` after packet send, ACK processing, key discard, or
/// timer service to mirror the connection's current aggregate recovery timer.
/// `earliestDeadline()` returns the next connection handle to wake, and
/// `serviceConnection()` dispatches the due timer through the connection helper
/// before refreshing endpoint scheduling state.
pub const EndpointLossDetectionTimers = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(EndpointLossDetectionTimerDeadline) = .empty,

    /// Create an empty endpoint recovery timer owner.
    pub fn init(allocator: std.mem.Allocator) EndpointLossDetectionTimers {
        return .{ .allocator = allocator };
    }

    /// Release all endpoint timer storage.
    pub fn deinit(self: *EndpointLossDetectionTimers) void {
        self.entries.deinit(self.allocator);
    }

    /// Return the number of connection timers currently armed by the endpoint.
    pub fn count(self: *const EndpointLossDetectionTimers) usize {
        return self.entries.items.len;
    }

    /// Mirror one connection's current aggregate loss/PTO timer.
    ///
    /// If the connection has no armed recovery timer, any existing endpoint
    /// entry for `connection_id` is removed. Otherwise the existing entry is
    /// updated or a new entry is appended.
    pub fn armFromConnection(
        self: *EndpointLossDetectionTimers,
        connection_id: u64,
        connection: anytype,
    ) Error!void {
        try self.update(connection_id, connection.lossDetectionTimerDeadlineMillis());
    }

    /// Remove one connection timer from endpoint scheduling state.
    pub fn disarmConnection(self: *EndpointLossDetectionTimers, connection_id: u64) bool {
        const index = self.findIndex(connection_id) orelse return false;
        _ = self.entries.orderedRemove(index);
        return true;
    }

    /// Return the earliest connection-level recovery timer known to the endpoint.
    pub fn earliestDeadline(self: *const EndpointLossDetectionTimers) ?EndpointLossDetectionTimerDeadline {
        if (self.entries.items.len == 0) return null;
        var earliest = self.entries.items[0];
        for (self.entries.items[1..]) |entry| {
            if (entry.timer.deadline_millis < earliest.timer.deadline_millis) {
                earliest = entry;
            }
        }
        return earliest;
    }

    /// Return one connection handle's recovery timer snapshot, if armed.
    pub fn deadlineForConnection(self: *const EndpointLossDetectionTimers, connection_id: u64) ?EndpointLossDetectionTimerDeadline {
        const index = self.findIndex(connection_id) orelse return null;
        return self.entries.items[index];
    }

    /// Service one connection's due loss detection timer and refresh scheduling.
    ///
    /// This is the endpoint event-loop bridge for a caller-owned connection
    /// selected by `earliestDeadline()`. It is safe to call before the deadline:
    /// the connection helper is a no-op and the endpoint entry is refreshed from
    /// the connection's current timer. A connection with no remaining timer is
    /// disarmed.
    pub fn serviceConnection(
        self: *EndpointLossDetectionTimers,
        connection_id: u64,
        connection: anytype,
        now_millis: i64,
    ) Error!?EndpointLossDetectionTimerDeadline {
        const serviced = try connection.serviceLossDetectionTimer(now_millis);
        try self.armFromConnection(connection_id, connection);
        const timer = serviced orelse return null;
        return .{
            .connection_id = connection_id,
            .timer = timer,
        };
    }

    /// Set or clear a connection timer from an already computed deadline.
    pub fn update(
        self: *EndpointLossDetectionTimers,
        connection_id: u64,
        timer: ?LossDetectionTimerDeadline,
    ) Error!void {
        const index = self.findIndex(connection_id);
        if (timer) |deadline| {
            const entry = EndpointLossDetectionTimerDeadline{
                .connection_id = connection_id,
                .timer = deadline,
            };
            if (index) |existing| {
                self.entries.items[existing] = entry;
            } else {
                self.entries.append(self.allocator, entry) catch return error.OutOfMemory;
            }
        } else if (index) |existing| {
            _ = self.entries.orderedRemove(existing);
        }
    }

    fn findIndex(self: *const EndpointLossDetectionTimers, connection_id: u64) ?usize {
        for (self.entries.items, 0..) |entry, index| {
            if (entry.connection_id == connection_id) return index;
        }
        return null;
    }
};
