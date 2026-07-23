//! HTTP/3 connection and stream management (RFC 9114 §4-6).
//!
//! Manages HTTP/3 unidirectional control streams, request/response
//! stream lifecycle, and GOAWAY signaling.

const std = @import("std");
const h3_frame = @import("frame.zig");

/// HTTP/3 error codes (RFC 9114 §8.1).
pub const ErrorCode = enum(u64) {
    no_error = 0x0100,
    general_protocol_error = 0x0101,
    internal_error = 0x0102,
    stream_creation_error = 0x0103,
    closed_critical_stream = 0x0104,
    frame_unexpected = 0x0105,
    frame_error = 0x0106,
    excessive_load = 0x0107,
    id_error = 0x0108,
    settings_error = 0x0109,
    missing_settings = 0x010a,
    request_rejected = 0x010b,
    request_cancelled = 0x010c,
    request_incomplete = 0x010d,
    message_error = 0x010e,
    connect_error = 0x010f,
    version_fallback = 0x0110,
    _,
};

/// HTTP/3 stream state.
pub const StreamState = enum {
    /// Stream created, waiting for HEADERS.
    open,
    /// HEADERS sent/received, waiting for DATA.
    headers_done,
    /// DATA being transferred.
    data_transfer,
    /// Response/request complete.
    complete,
    /// Stream reset or abandoned.
    reset,
};

/// An HTTP/3 request/response stream.
pub const H3Stream = struct {
    /// QUIC stream ID.
    stream_id: u64,
    /// Current stream state.
    state: StreamState = .open,
    /// Whether this is a request (client-initiated) or response (server-initiated).
    is_request: bool,
    /// Request method (for requests).
    method: ?[]const u8 = null,
    /// Request path (for requests).
    path: ?[]const u8 = null,
    /// Response status code (for responses).
    status_code: ?u16 = null,
    /// Bytes of body data transferred.
    body_bytes: usize = 0,
    /// Whether the body has a known length.
    body_complete: bool = false,
};

/// HTTP/3 connection state.
pub const H3Connection = struct {
    /// Whether SETTINGS have been exchanged.
    settings_sent: bool = false,
    settings_received: bool = false,
    /// Whether GOAWAY has been sent/received.
    goaway_sent: bool = false,
    goaway_received: bool = false,
    /// Last stream ID in GOAWAY.
    goaway_stream_id: ?u64 = null,
    /// Active request/response streams.
    streams: std.ArrayList(H3Stream) = .empty,
    allocator: std.mem.Allocator,
    /// Next request stream ID (client-side, bidi = 0, 4, 8, ...).
    next_request_stream_id: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) H3Connection {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *H3Connection) void {
        self.streams.deinit(self.allocator);
    }

    /// Open a new request stream (client-side).
    pub fn openRequestStream(self: *H3Connection) !u64 {
        const stream_id = self.next_request_stream_id;
        self.next_request_stream_id += 4; // Client-initiated bidi: 0, 4, 8, ...
        try self.streams.append(self.allocator, .{
            .stream_id = stream_id,
            .is_request = true,
        });
        return stream_id;
    }

    /// Get a stream by ID.
    pub fn getStream(self: *H3Connection, stream_id: u64) ?*H3Stream {
        for (self.streams.items) |*stream| {
            if (stream.stream_id == stream_id) return stream;
        }
        return null;
    }

    /// Mark SETTINGS as sent.
    pub fn markSettingsSent(self: *H3Connection) void {
        self.settings_sent = true;
    }

    /// Mark SETTINGS as received.
    pub fn markSettingsReceived(self: *H3Connection) void {
        self.settings_received = true;
    }

    /// Whether the connection is ready for requests (SETTINGS exchanged).
    pub fn isReady(self: *const H3Connection) bool {
        return self.settings_sent and self.settings_received;
    }

    /// Initiate GOAWAY.
    pub fn sendGoaway(self: *H3Connection, last_stream_id: u64) void {
        self.goaway_sent = true;
        self.goaway_stream_id = last_stream_id;
    }

    /// Return the number of active (non-complete, non-reset) streams.
    pub fn activeStreamCount(self: *const H3Connection) usize {
        var count: usize = 0;
        for (self.streams.items) |stream| {
            if (stream.state != .complete and stream.state != .reset) count += 1;
        }
        return count;
    }

    /// Encode a SETTINGS frame payload.
    pub fn encodeSettings(out: []u8, max_field_section_size: u64) !usize {
        var pos: usize = 0;
        // Setting: max_field_section_size (0x06)
        out[pos] = 0x06;
        pos += 1;
        pos += try encodeVarIntToBuf(out[pos..], max_field_section_size);
        return pos;
    }
};

fn encodeVarIntToBuf(out: []u8, value: u64) !usize {
    if (value <= 63) {
        out[0] = @intCast(value);
        return 1;
    } else if (value <= 16383) {
        out[0] = @intCast(0x40 | (value >> 8));
        out[1] = @intCast(value & 0xff);
        return 2;
    } else if (value <= 1073741823) {
        out[0] = @intCast(0x80 | (value >> 24));
        out[1] = @intCast((value >> 16) & 0xff);
        out[2] = @intCast((value >> 8) & 0xff);
        out[3] = @intCast(value & 0xff);
        return 4;
    } else {
        return error.ValueTooLarge;
    }
}

test "H3Connection open request streams" {
    var conn = H3Connection.init(std.testing.allocator);
    defer conn.deinit();

    const id0 = try conn.openRequestStream();
    const id1 = try conn.openRequestStream();
    try std.testing.expectEqual(@as(u64, 0), id0);
    try std.testing.expectEqual(@as(u64, 4), id1);
    try std.testing.expectEqual(@as(usize, 2), conn.activeStreamCount());

    const stream = conn.getStream(id0).?;
    try std.testing.expect(stream.is_request);
    try std.testing.expectEqual(StreamState.open, stream.state);
}

test "H3Connection settings exchange" {
    var conn = H3Connection.init(std.testing.allocator);
    defer conn.deinit();

    try std.testing.expect(!conn.isReady());
    conn.markSettingsSent();
    try std.testing.expect(!conn.isReady());
    conn.markSettingsReceived();
    try std.testing.expect(conn.isReady());
}

test "H3Connection GOAWAY" {
    var conn = H3Connection.init(std.testing.allocator);
    defer conn.deinit();

    try std.testing.expect(!conn.goaway_sent);
    conn.sendGoaway(8);
    try std.testing.expect(conn.goaway_sent);
    try std.testing.expectEqual(@as(?u64, 8), conn.goaway_stream_id);
}

test "H3Connection encode SETTINGS" {
    var buf: [64]u8 = undefined;
    const len = try H3Connection.encodeSettings(&buf, 8192);
    try std.testing.expect(len > 0);
    // First byte: setting ID 0x06
    try std.testing.expectEqual(@as(u8, 0x06), buf[0]);
}

test "H3 error codes" {
    try std.testing.expectEqual(@as(u64, 0x0100), @intFromEnum(ErrorCode.no_error));
    try std.testing.expectEqual(@as(u64, 0x0101), @intFromEnum(ErrorCode.general_protocol_error));
    try std.testing.expectEqual(@as(u64, 0x010c), @intFromEnum(ErrorCode.request_cancelled));
}
