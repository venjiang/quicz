//! WebTransport over HTTP/3 (draft-ietf-webtrans-http3).
//!
//! Implements WebTransport session establishment, bidirectional
//! streams, and datagrams over an HTTP/3 connection.

const std = @import("std");
const h3_frame = @import("frame.zig");
const h3_connection = @import("connection.zig");

/// WebTransport session state.
pub const WtSession = struct {
    /// Whether the session has been established (CONNECT accepted).
    established: bool = false,
    /// The QUIC stream ID of the CONNECT request stream.
    connect_stream_id: ?u64 = null,
    /// Session ID (from CONNECT response).
    session_id: ?u64 = null,
    /// Active WebTransport bidi streams.
    bidi_streams: std.ArrayList(WtStream) = .empty,
    /// Active WebTransport uni streams.
    uni_streams: std.ArrayList(WtStream) = .empty,
    /// Datagrams received.
    datagrams_received: u64 = 0,
    /// Datagrams sent.
    datagrams_sent: u64 = 0,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) WtSession {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *WtSession) void {
        self.bidi_streams.deinit(self.allocator);
        self.uni_streams.deinit(self.allocator);
    }

    /// Establish a WebTransport session (client-side CONNECT).
    pub fn establish(self: *WtSession, connect_stream_id: u64) void {
        self.established = true;
        self.connect_stream_id = connect_stream_id;
        self.session_id = connect_stream_id;
    }

    /// Open a WebTransport bidirectional stream.
    pub fn openBidiStream(self: *WtSession, stream_id: u64) !void {
        try self.bidi_streams.append(self.allocator, .{
            .stream_id = stream_id,
            .is_bidi = true,
        });
    }

    /// Open a WebTransport unidirectional stream.
    pub fn openUniStream(self: *WtSession, stream_id: u64) !void {
        try self.uni_streams.append(self.allocator, .{
            .stream_id = stream_id,
            .is_bidi = false,
        });
    }

    /// Get a bidi stream by ID.
    pub fn getBidiStream(self: *WtSession, stream_id: u64) ?*WtStream {
        for (self.bidi_streams.items) |*s| {
            if (s.stream_id == stream_id) return s;
        }
        return null;
    }

    /// Record a datagram sent.
    pub fn recordDatagramSent(self: *WtSession) void {
        self.datagrams_sent += 1;
    }

    /// Record a datagram received.
    pub fn recordDatagramReceived(self: *WtSession) void {
        self.datagrams_received += 1;
    }

    /// Close the session.
    pub fn close(self: *WtSession) void {
        self.established = false;
        for (self.bidi_streams.items) |*s| s.state = .closed;
        for (self.uni_streams.items) |*s| s.state = .closed;
    }
};

/// A WebTransport stream (bidi or uni).
pub const WtStream = struct {
    stream_id: u64,
    is_bidi: bool,
    state: WtStreamState = .open,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
};

/// WebTransport stream state.
pub const WtStreamState = enum {
    open,
    /// FIN sent but not yet acknowledged.
    fin_sent,
    /// FIN received.
    fin_received,
    /// Both directions closed.
    closed,
    /// Reset sent or received.
    reset,
};

/// Encode a WebTransport CONNECT request as H3 HEADERS.
/// Uses the extended CONNECT method with :protocol = webtransport.
pub fn encodeConnectRequest(out: []u8, authority: []const u8, path: []const u8) !usize {
    const qpack = @import("qpack.zig");

    const fields = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = authority },
        .{ .name = ":path", .value = path },
    };

    var header_buf: [4096]u8 = undefined;
    const header_len = try qpack.encodeHeaderBlock(&header_buf, &fields);

    // Write HEADERS frame
    var pos: usize = 0;
    out[pos] = 0x01; // HEADERS frame type
    pos += 1;
    // Length varint
    if (header_len <= 63) {
        out[pos] = @intCast(header_len);
        pos += 1;
    } else if (header_len <= 16383) {
        out[pos] = @intCast(0x40 | (header_len >> 8));
        out[pos + 1] = @intCast(header_len & 0xff);
        pos += 2;
    } else {
        return error.HeaderTooLarge;
    }
    @memcpy(out[pos .. pos + header_len], header_buf[0..header_len]);
    pos += header_len;

    return pos;
}

test "WebTransport session lifecycle" {
    var session = WtSession.init(std.testing.allocator);
    defer session.deinit();

    try std.testing.expect(!session.established);

    // Establish session
    session.establish(0);
    try std.testing.expect(session.established);
    try std.testing.expectEqual(@as(?u64, 0), session.session_id);

    // Open bidi streams
    try session.openBidiStream(4);
    try session.openBidiStream(8);
    try std.testing.expectEqual(@as(usize, 2), session.bidi_streams.items.len);

    // Get stream
    const stream = session.getBidiStream(4);
    try std.testing.expect(stream != null);
    try std.testing.expect(stream.?.is_bidi);
    try std.testing.expectEqual(WtStreamState.open, stream.?.state);

    // Datagrams
    session.recordDatagramSent();
    session.recordDatagramSent();
    session.recordDatagramReceived();
    try std.testing.expectEqual(@as(u64, 2), session.datagrams_sent);
    try std.testing.expectEqual(@as(u64, 1), session.datagrams_received);

    // Close session
    session.close();
    try std.testing.expect(!session.established);
    try std.testing.expectEqual(WtStreamState.closed, session.bidi_streams.items[0].state);
}

test "WebTransport uni streams" {
    var session = WtSession.init(std.testing.allocator);
    defer session.deinit();

    session.establish(0);
    try session.openUniStream(3);
    try session.openUniStream(7);

    try std.testing.expectEqual(@as(usize, 2), session.uni_streams.items.len);
    try std.testing.expect(!session.uni_streams.items[0].is_bidi);
}

test "WebTransport CONNECT request encoding" {
    var buf: [4096]u8 = undefined;
    const len = try encodeConnectRequest(&buf, "example.com", "/wt");

    try std.testing.expect(len > 0);
    // First byte should be HEADERS frame type (0x01)
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);
}

test "WebTransport stream state transitions" {
    var stream = WtStream{
        .stream_id = 4,
        .is_bidi = true,
    };

    try std.testing.expectEqual(WtStreamState.open, stream.state);

    stream.state = .fin_sent;
    try std.testing.expectEqual(WtStreamState.fin_sent, stream.state);

    stream.state = .closed;
    try std.testing.expectEqual(WtStreamState.closed, stream.state);
}
