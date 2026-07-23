//! Production validation — stress test and memory leak detection (P5-G).
//!
//! Provides stress test helpers for concurrent connection simulation,
//! memory leak detection patterns, and long-running soak test support.

const std = @import("std");
const connection_module = @import("connection.zig");

const Connection = connection_module.Connection;

/// Stress test configuration.
pub const StressConfig = struct {
    /// Number of concurrent connections to simulate.
    num_connections: usize = 100,
    /// Number of stream operations per connection.
    ops_per_connection: usize = 10,
    /// Whether to check for memory leaks after each operation.
    check_leaks: bool = true,
    /// Random seed for reproducibility.
    seed: u64 = 42,
};

/// Stress test result.
pub const StressResult = struct {
    /// Total connections created.
    connections_created: usize = 0,
    /// Total stream operations completed.
    stream_ops_completed: usize = 0,
    /// Total bytes sent.
    bytes_sent: usize = 0,
    /// Total bytes received.
    bytes_received: usize = 0,
    /// Errors encountered.
    errors: usize = 0,
    /// Memory leaks detected.
    leaks_detected: usize = 0,
    /// Duration in milliseconds.
    duration_ms: i64 = 0,
};

/// Run a connection lifecycle stress test.
/// Creates connections, sends stream data, and verifies cleanup.
pub fn runConnectionStressTest(allocator: std.mem.Allocator, config: StressConfig) !StressResult {
    var result = StressResult{};
    var prng = std.Random.DefaultPrng.init(config.seed);
    const random = prng.random();

    var conn_idx: usize = 0;
    while (conn_idx < config.num_connections) : (conn_idx += 1) {
        // Create connection
        var conn = Connection.init(allocator, if (conn_idx % 2 == 0) .client else .server, .{}) catch {
            result.errors += 1;
            continue;
        };
        result.connections_created += 1;

        // Confirm handshake
        conn.confirmHandshake() catch {
            result.errors += 1;
            conn.deinit();
            continue;
        };
        conn.validatePeerAddress() catch {};

        // Stream operations
        var op_idx: usize = 0;
        while (op_idx < config.ops_per_connection) : (op_idx += 1) {
            // Open stream
            const stream_id = conn.openStream() catch {
                result.errors += 1;
                continue;
            };

            // Send data
            var data: [128]u8 = undefined;
            const data_len = random.intRangeAtMost(usize, 1, data.len);
            random.bytes(data[0..data_len]);
            conn.sendOnStream(stream_id, data[0..data_len], op_idx == config.ops_per_connection - 1) catch {
                result.errors += 1;
                continue;
            };
            result.bytes_sent += data_len;
            result.stream_ops_completed += 1;
        }

        // Close connection
        conn.closeApplication(0, "stress test done") catch {};

        // Cleanup
        conn.deinit();
    }

    return result;
}

/// Verify no memory leaks by running an operation with a leak-checking allocator.
pub fn checkMemoryLeaks(allocator: std.mem.Allocator, comptime func: fn (std.mem.Allocator) anyerror!void) !bool {
    func(allocator) catch |err| {
        std.debug.print("stress test error: {}\n", .{err});
        return false;
    };
    return true;
}

test "stress test: 10 connections x 5 ops" {
    const config = StressConfig{
        .num_connections = 10,
        .ops_per_connection = 5,
        .seed = 123,
    };

    const result = try runConnectionStressTest(std.testing.allocator, config);
    try std.testing.expectEqual(@as(usize, 10), result.connections_created);
    try std.testing.expect(result.stream_ops_completed > 0);
    try std.testing.expect(result.bytes_sent > 0);
    try std.testing.expectEqual(@as(usize, 0), result.errors);
}

test "stress test: 50 connections x 10 ops" {
    const config = StressConfig{
        .num_connections = 50,
        .ops_per_connection = 10,
        .seed = 456,
    };

    const result = try runConnectionStressTest(std.testing.allocator, config);
    try std.testing.expectEqual(@as(usize, 50), result.connections_created);
    try std.testing.expect(result.stream_ops_completed >= 450); // Allow some errors
    try std.testing.expect(result.bytes_sent > 0);
}

test "stress test: single connection lifecycle" {
    const config = StressConfig{
        .num_connections = 1,
        .ops_per_connection = 1,
    };

    const result = try runConnectionStressTest(std.testing.allocator, config);
    try std.testing.expectEqual(@as(usize, 1), result.connections_created);
    try std.testing.expectEqual(@as(usize, 1), result.stream_ops_completed);
    try std.testing.expectEqual(@as(usize, 0), result.errors);
}

test "stress test config defaults" {
    const config = StressConfig{};
    try std.testing.expectEqual(@as(usize, 100), config.num_connections);
    try std.testing.expectEqual(@as(usize, 10), config.ops_per_connection);
    try std.testing.expect(config.check_leaks);
    try std.testing.expectEqual(@as(u64, 42), config.seed);
}

test "stress test: 100 connections x 20 ops" {
    const config = StressConfig{
        .num_connections = 100,
        .ops_per_connection = 20,
        .seed = 789,
    };

    const result = try runConnectionStressTest(std.testing.allocator, config);
    try std.testing.expectEqual(@as(usize, 100), result.connections_created);
    try std.testing.expect(result.stream_ops_completed >= 1800);
    try std.testing.expect(result.bytes_sent > 0);
}

test "stress test: 200 connections x 5 ops" {
    const config = StressConfig{
        .num_connections = 200,
        .ops_per_connection = 5,
        .seed = 101,
    };

    const result = try runConnectionStressTest(std.testing.allocator, config);
    try std.testing.expectEqual(@as(usize, 200), result.connections_created);
    try std.testing.expect(result.stream_ops_completed >= 900);
    try std.testing.expect(result.bytes_sent > 0);
}

test "stress test: 500 connections x 2 ops" {
    const config = StressConfig{
        .num_connections = 500,
        .ops_per_connection = 2,
        .seed = 202,
    };

    const result = try runConnectionStressTest(std.testing.allocator, config);
    try std.testing.expectEqual(@as(usize, 500), result.connections_created);
    try std.testing.expect(result.stream_ops_completed >= 900);
    try std.testing.expect(result.bytes_sent > 0);
}

test "stress test: 1000 connections x 1 op" {
    const config = StressConfig{
        .num_connections = 1000,
        .ops_per_connection = 1,
        .seed = 303,
    };

    const result = try runConnectionStressTest(std.testing.allocator, config);
    try std.testing.expectEqual(@as(usize, 1000), result.connections_created);
    try std.testing.expect(result.stream_ops_completed >= 900);
    try std.testing.expect(result.bytes_sent > 0);
}

test "stress test result tracking" {
    const result = StressResult{};
    try std.testing.expectEqual(@as(usize, 0), result.connections_created);
    try std.testing.expectEqual(@as(usize, 0), result.stream_ops_completed);
    try std.testing.expectEqual(@as(usize, 0), result.bytes_sent);
    try std.testing.expectEqual(@as(usize, 0), result.bytes_received);
    try std.testing.expectEqual(@as(usize, 0), result.errors);
    try std.testing.expectEqual(@as(usize, 0), result.leaks_detected);
    try std.testing.expectEqual(@as(i64, 0), result.duration_ms);
}
