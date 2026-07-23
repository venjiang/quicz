//! QUIC Datagram extension (RFC 9221) tests.
//!
//! Verifies DATAGRAM frame send/receive, size limits,
//! and that datagram loss does not block stream delivery.

const std = @import("std");
const connection_module = @import("connection.zig");

const Connection = connection_module.Connection;

test "RFC 9221: sendDatagram queues payload" {
    var conn = try Connection.init(std.testing.allocator, .client, .{
        .max_datagram_frame_size = 1200,
    });
    defer conn.deinit();
    try conn.confirmHandshake();

    try conn.sendDatagram("hello datagram");
    try std.testing.expectEqual(@as(usize, 1), conn.pending_datagrams.items.len);
    try std.testing.expectEqualStrings("hello datagram", conn.pending_datagrams.items[0]);
}

test "RFC 9221: sendDatagram rejects when not advertised" {
    var conn = try Connection.init(std.testing.allocator, .client, .{
        .max_datagram_frame_size = 0,
    });
    defer conn.deinit();
    try conn.confirmHandshake();

    try std.testing.expectError(error.InvalidPacket, conn.sendDatagram("data"));
}

test "RFC 9221: sendDatagram rejects oversized payload" {
    var conn = try Connection.init(std.testing.allocator, .client, .{
        .max_datagram_frame_size = 100,
    });
    defer conn.deinit();
    try conn.confirmHandshake();

    var big: [200]u8 = undefined;
    @memset(&big, 0x42);
    try std.testing.expectError(error.InvalidPacket, conn.sendDatagram(&big));
}

test "RFC 9221: recvDatagram returns null when empty" {
    var conn = try Connection.init(std.testing.allocator, .client, .{
        .max_datagram_frame_size = 1200,
    });
    defer conn.deinit();
    try conn.confirmHandshake();

    var buf: [1200]u8 = undefined;
    const result = try conn.recvDatagram(&buf);
    try std.testing.expect(result == null);
}

test "RFC 9221: multiple datagrams queued and drained in order" {
    var conn = try Connection.init(std.testing.allocator, .client, .{
        .max_datagram_frame_size = 1200,
    });
    defer conn.deinit();
    try conn.confirmHandshake();

    try conn.sendDatagram("first");
    try conn.sendDatagram("second");
    try conn.sendDatagram("third");

    try std.testing.expectEqual(@as(usize, 3), conn.pending_datagrams.items.len);
    try std.testing.expectEqualStrings("first", conn.pending_datagrams.items[0]);
    try std.testing.expectEqualStrings("second", conn.pending_datagrams.items[1]);
    try std.testing.expectEqualStrings("third", conn.pending_datagrams.items[2]);
}

test "RFC 9221: datagram does not block stream delivery" {
    var conn = try Connection.init(std.testing.allocator, .client, .{
        .max_datagram_frame_size = 1200,
    });
    defer conn.deinit();
    try conn.confirmHandshake();

    // Send datagram
    try conn.sendDatagram("unreliable data");

    // Stream should still work independently
    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "reliable stream data", true);

    const state = try conn.streamState(stream_id);
    try std.testing.expect(state != null);

    // Datagram is still queued
    try std.testing.expectEqual(@as(usize, 1), conn.pending_datagrams.items.len);
}


test "RFC 9221: datagram at max size accepted" {
    var conn = try Connection.init(std.testing.allocator, .client, .{
        .max_datagram_frame_size = 100,
    });
    defer conn.deinit();
    try conn.confirmHandshake();

    var exact: [100]u8 = undefined;
    @memset(&exact, 0xAB);
    try conn.sendDatagram(&exact);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_datagrams.items.len);
    try std.testing.expectEqual(@as(usize, 100), conn.pending_datagrams.items[0].len);
}
