//! QUIC session cache for 0-RTT resumption (RFC 9001 §4.6).
//!
//! Stores NewSessionTicket data from previous connections to enable
//! 0-RTT data sending on subsequent connections to the same server.

const std = @import("std");

/// A cached session ticket for 0-RTT resumption.
pub const SessionTicket = struct {
    /// Server identity (e.g., "example.com:443").
    server_id: []const u8,
    /// PSK derived from the resumption master secret.
    psk: [32]u8,
    /// Ticket lifetime in seconds.
    lifetime_sec: u32,
    /// Ticket age add (obfuscation value).
    age_add: u32,
    /// Ticket nonce.
    nonce: []const u8,
    /// Whether the server indicated 0-RTT support.
    allows_early_data: bool,
    /// Transport parameters to remember for 0-RTT.
    remembered_max_data: u64 = 0,
    remembered_max_stream_data: u64 = 0,
    remembered_max_streams_bidi: u64 = 0,
    remembered_max_streams_uni: u64 = 0,
    /// Creation timestamp (seconds since epoch).
    created_at_sec: i64,
};

/// Session cache: stores and retrieves session tickets.
pub const SessionCache = struct {
    tickets: std.ArrayList(SessionTicket) = .empty,
    allocator: std.mem.Allocator,
    max_entries: usize = 16,

    pub fn init(allocator: std.mem.Allocator) SessionCache {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *SessionCache) void {
        for (self.tickets.items) |*ticket| {
            self.allocator.free(ticket.server_id);
            self.allocator.free(ticket.nonce);
        }
        self.tickets.deinit(self.allocator);
    }

    /// Store a session ticket. Evicts oldest if at capacity.
    pub fn store(self: *SessionCache, ticket: SessionTicket) !void {
        // Duplicate server_id: replace existing
        for (self.tickets.items, 0..) |*existing, i| {
            if (std.mem.eql(u8, existing.server_id, ticket.server_id)) {
                self.allocator.free(existing.server_id);
                self.allocator.free(existing.nonce);
                self.tickets.items[i] = ticket;
                return;
            }
        }
        // Evict oldest if at capacity
        if (self.tickets.items.len >= self.max_entries) {
            const oldest = self.tickets.orderedRemove(0);
            self.allocator.free(oldest.server_id);
            self.allocator.free(oldest.nonce);
        }
        try self.tickets.append(self.allocator, ticket);
    }

    /// Retrieve a valid session ticket for the given server.
    /// Returns null if no valid ticket exists or the ticket has expired.
    pub fn retrieve(self: *const SessionCache, server_id: []const u8, now_sec: i64) ?*const SessionTicket {
        for (self.tickets.items) |*ticket| {
            if (!std.mem.eql(u8, ticket.server_id, server_id)) continue;
            // Check expiry
            const elapsed: i64 = now_sec - ticket.created_at_sec;
            if (elapsed < 0 or elapsed > @as(i64, ticket.lifetime_sec)) continue;
            return ticket;
        }
        return null;
    }

    /// Return the number of cached tickets.
    pub fn count(self: *const SessionCache) usize {
        return self.tickets.items.len;
    }

    /// Remove expired tickets.
    pub fn pruneExpired(self: *SessionCache, now_sec: i64) void {
        var i: usize = 0;
        while (i < self.tickets.items.len) {
            const ticket = &self.tickets.items[i];
            const elapsed: i64 = now_sec - ticket.created_at_sec;
            if (elapsed < 0 or elapsed > @as(i64, ticket.lifetime_sec)) {
                self.allocator.free(ticket.server_id);
                self.allocator.free(ticket.nonce);
                _ = self.tickets.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }
};

test "SessionCache store and retrieve" {
    var cache = SessionCache.init(std.testing.allocator);
    defer cache.deinit();

    const server_id = try std.testing.allocator.dupe(u8, "example.com:443");
    const nonce = try std.testing.allocator.dupe(u8, "nonce1");
    try cache.store(.{
        .server_id = server_id,
        .psk = [_]u8{1} ** 32,
        .lifetime_sec = 3600,
        .age_add = 12345,
        .nonce = nonce,
        .allows_early_data = true,
        .created_at_sec = 1000,
    });

    try std.testing.expectEqual(@as(usize, 1), cache.count());

    const ticket = cache.retrieve("example.com:443", 1000);
    try std.testing.expect(ticket != null);
    try std.testing.expect(ticket.?.allows_early_data);
    try std.testing.expectEqual(@as(u32, 12345), ticket.?.age_add);

    // Not found for different server
    try std.testing.expect(cache.retrieve("other.com:443", 1000) == null);
}

test "SessionCache ticket expiry" {
    var cache = SessionCache.init(std.testing.allocator);
    defer cache.deinit();

    const server_id = try std.testing.allocator.dupe(u8, "example.com:443");
    const nonce = try std.testing.allocator.dupe(u8, "nonce2");
    try cache.store(.{
        .server_id = server_id,
        .psk = [_]u8{2} ** 32,
        .lifetime_sec = 100,
        .age_add = 0,
        .nonce = nonce,
        .allows_early_data = false,
        .created_at_sec = 1000,
    });

    // Valid at t=1050
    try std.testing.expect(cache.retrieve("example.com:443", 1050) != null);
    // Expired at t=1200 (1000 + 100 = 1100)
    try std.testing.expect(cache.retrieve("example.com:443", 1200) == null);
}

test "SessionCache prune expired" {
    var cache = SessionCache.init(std.testing.allocator);
    defer cache.deinit();

    const id1 = try std.testing.allocator.dupe(u8, "a.com:443");
    const n1 = try std.testing.allocator.dupe(u8, "n1");
    try cache.store(.{
        .server_id = id1,
        .psk = [_]u8{1} ** 32,
        .lifetime_sec = 100,
        .age_add = 0,
        .nonce = n1,
        .allows_early_data = false,
        .created_at_sec = 1000,
    });

    const id2 = try std.testing.allocator.dupe(u8, "b.com:443");
    const n2 = try std.testing.allocator.dupe(u8, "n2");
    try cache.store(.{
        .server_id = id2,
        .psk = [_]u8{2} ** 32,
        .lifetime_sec = 3600,
        .age_add = 0,
        .nonce = n2,
        .allows_early_data = true,
        .created_at_sec = 1000,
    });

    try std.testing.expectEqual(@as(usize, 2), cache.count());
    cache.pruneExpired(1200); // a.com expired, b.com still valid
    try std.testing.expectEqual(@as(usize, 1), cache.count());
    try std.testing.expect(cache.retrieve("b.com:443", 1200) != null);
}

test "SessionCache duplicate server_id replaces" {
    var cache = SessionCache.init(std.testing.allocator);
    defer cache.deinit();

    const id1 = try std.testing.allocator.dupe(u8, "example.com:443");
    const n1 = try std.testing.allocator.dupe(u8, "old");
    try cache.store(.{
        .server_id = id1,
        .psk = [_]u8{1} ** 32,
        .lifetime_sec = 100,
        .age_add = 111,
        .nonce = n1,
        .allows_early_data = false,
        .created_at_sec = 1000,
    });

    const id2 = try std.testing.allocator.dupe(u8, "example.com:443");
    const n2 = try std.testing.allocator.dupe(u8, "new");
    try cache.store(.{
        .server_id = id2,
        .psk = [_]u8{2} ** 32,
        .lifetime_sec = 200,
        .age_add = 222,
        .nonce = n2,
        .allows_early_data = true,
        .created_at_sec = 2000,
    });

    try std.testing.expectEqual(@as(usize, 1), cache.count());
    const ticket = cache.retrieve("example.com:443", 2000).?;
    try std.testing.expectEqual(@as(u32, 222), ticket.age_add);
    try std.testing.expect(ticket.allows_early_data);
}
