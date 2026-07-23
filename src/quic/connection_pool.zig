//! QUIC connection pool for client-side connection reuse.
//!
//! Manages a pool of idle QUIC connections keyed by destination,
//! reducing handshake overhead for repeated requests to the same peer.

const std = @import("std");
const connection_module = @import("connection.zig");

const Connection = connection_module.Connection;

/// A pooled connection entry with metadata.
pub const PooledConnection = struct {
    conn: *Connection,
    /// Destination key (e.g., "host:port").
    dest_key: []const u8,
    /// When this connection was returned to the pool (ms).
    pooled_at_ms: i64,
    /// Number of times this connection has been reused.
    reuse_count: u64 = 0,
};

/// Connection pool configuration.
pub const PoolConfig = struct {
    /// Maximum idle connections per destination.
    max_idle_per_dest: usize = 4,
    /// Maximum total idle connections.
    max_idle_total: usize = 16,
    /// Idle timeout in milliseconds.
    idle_timeout_ms: i64 = 30_000,
};

/// A client-side QUIC connection pool.
pub const ConnectionPool = struct {
    allocator: std.mem.Allocator,
    config: PoolConfig,
    /// Idle connections available for reuse.
    idle: std.ArrayList(PooledConnection),
    /// Total connections created by this pool.
    total_created: u64 = 0,
    /// Total reuse hits.
    total_reused: u64 = 0,
    /// Total misses (new connection needed).
    total_misses: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, config: PoolConfig) ConnectionPool {
        return .{
            .allocator = allocator,
            .config = config,
            .idle = .empty,
        };
    }

    pub fn deinit(self: *ConnectionPool) void {
        for (self.idle.items) |entry| {
            entry.conn.deinit();
            self.allocator.destroy(entry.conn);
            self.allocator.free(entry.dest_key);
        }
        self.idle.deinit(self.allocator);
    }

    /// Try to get an idle connection for the given destination.
    /// Returns null if no idle connection is available.
    pub fn acquire(self: *ConnectionPool, dest_key: []const u8, now_ms: i64) ?*Connection {
        // Find and remove the first matching idle connection
        var i: usize = 0;
        while (i < self.idle.items.len) {
            const entry = &self.idle.items[i];
            // Check idle timeout
            if (now_ms - entry.pooled_at_ms > self.config.idle_timeout_ms) {
                // Expired — remove and destroy
                const expired = self.idle.orderedRemove(i);
                expired.conn.deinit();
                self.allocator.destroy(expired.conn);
                self.allocator.free(expired.dest_key);
                continue;
            }
            if (std.mem.eql(u8, entry.dest_key, dest_key)) {
                const pooled = self.idle.orderedRemove(i);
                self.allocator.free(pooled.dest_key);
                self.total_reused += 1;
                // Note: reuse_count is on the pooled entry, but we return the conn
                return pooled.conn;
            }
            i += 1;
        }
        self.total_misses += 1;
        return null;
    }

    /// Return a connection to the pool for future reuse.
    pub fn release(self: *ConnectionPool, conn: *Connection, dest_key: []const u8, now_ms: i64) !void {
        // Check per-dest limit
        var dest_count: usize = 0;
        for (self.idle.items) |entry| {
            if (std.mem.eql(u8, entry.dest_key, dest_key)) dest_count += 1;
        }
        if (dest_count >= self.config.max_idle_per_dest) {
            // Over limit — destroy instead of pooling
            conn.deinit();
            self.allocator.destroy(conn);
            return;
        }

        // Check total limit
        if (self.idle.items.len >= self.config.max_idle_total) {
            // Evict oldest
            if (self.idle.items.len > 0) {
                const evicted = self.idle.orderedRemove(0);
                evicted.conn.deinit();
                self.allocator.destroy(evicted.conn);
                self.allocator.free(evicted.dest_key);
            }
        }

        const owned_key = try self.allocator.dupe(u8, dest_key);
        errdefer self.allocator.free(owned_key);

        try self.idle.append(self.allocator, .{
            .conn = conn,
            .dest_key = owned_key,
            .pooled_at_ms = now_ms,
        });
    }

    /// Number of idle connections in the pool.
    pub fn idleCount(self: *const ConnectionPool) usize {
        return self.idle.items.len;
    }

    /// Number of idle connections for a specific destination.
    pub fn idleCountForDest(self: *const ConnectionPool, dest_key: []const u8) usize {
        var count: usize = 0;
        for (self.idle.items) |entry| {
            if (std.mem.eql(u8, entry.dest_key, dest_key)) count += 1;
        }
        return count;
    }

    /// Pool hit rate as a fraction (0.0 to 1.0).
    pub fn hitRate(self: *const ConnectionPool) f64 {
        const total = self.total_reused + self.total_misses;
        if (total == 0) return 0.0;
        return @as(f64, @floatFromInt(self.total_reused)) / @as(f64, @floatFromInt(total));
    }
};

test "ConnectionPool acquire returns null when empty" {
    var pool = ConnectionPool.init(std.testing.allocator, .{});
    defer pool.deinit();

    try std.testing.expect(pool.acquire("example.com:443", 0) == null);
    try std.testing.expectEqual(@as(u64, 1), pool.total_misses);
}

test "ConnectionPool release and acquire roundtrip" {
    var pool = ConnectionPool.init(std.testing.allocator, .{});
    defer pool.deinit();

    // Create a connection to pool
    var conn = try std.testing.allocator.create(Connection);
    conn.* = try Connection.init(std.testing.allocator, .client, .{});
    try conn.confirmHandshake();

    // Release to pool
    try pool.release(conn, "example.com:443", 1000);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCountForDest("example.com:443"));

    // Acquire from pool
    const acquired = pool.acquire("example.com:443", 2000);
    try std.testing.expect(acquired != null);
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    try std.testing.expectEqual(@as(u64, 1), pool.total_reused);

    // Clean up acquired connection
    acquired.?.deinit();
    std.testing.allocator.destroy(acquired.?);
}

test "ConnectionPool respects per-dest limit" {
    var pool = ConnectionPool.init(std.testing.allocator, .{
        .max_idle_per_dest = 2,
    });
    defer pool.deinit();

    // Create 3 connections for the same dest
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        var conn = try std.testing.allocator.create(Connection);
        conn.* = try Connection.init(std.testing.allocator, .client, .{});
        try conn.confirmHandshake();
        try pool.release(conn, "example.com:443", @intCast(i));
    }

    // Only 2 should be pooled (3rd was destroyed due to limit)
    try std.testing.expectEqual(@as(usize, 2), pool.idleCountForDest("example.com:443"));
}

test "ConnectionPool evicts expired connections" {
    var pool = ConnectionPool.init(std.testing.allocator, .{
        .idle_timeout_ms = 1000,
    });
    defer pool.deinit();

    var conn = try std.testing.allocator.create(Connection);
    conn.* = try Connection.init(std.testing.allocator, .client, .{});
    try conn.confirmHandshake();

    try pool.release(conn, "example.com:443", 0);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());

    // Acquire after timeout — should return null and evict
    const acquired = pool.acquire("example.com:443", 2000);
    try std.testing.expect(acquired == null);
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
}

test "ConnectionPool hit rate tracking" {
    var pool = ConnectionPool.init(std.testing.allocator, .{});
    defer pool.deinit();

    // Miss
    _ = pool.acquire("a.com:443", 0);
    try std.testing.expectEqual(@as(f64, 0.0), pool.hitRate());

    // Create and release
    var conn = try std.testing.allocator.create(Connection);
    conn.* = try Connection.init(std.testing.allocator, .client, .{});
    try conn.confirmHandshake();
    try pool.release(conn, "a.com:443", 100);

    // Hit
    const acquired = pool.acquire("a.com:443", 200);
    try std.testing.expect(acquired != null);
    try std.testing.expectEqual(@as(f64, 0.5), pool.hitRate());

    acquired.?.deinit();
    std.testing.allocator.destroy(acquired.?);
}
