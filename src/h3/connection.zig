//! HTTP/3 connection and stream management (RFC 9114 §4-6).
//!
//! Manages HTTP/3 unidirectional control streams, request/response
//! stream lifecycle, and GOAWAY signaling.

const std = @import("std");
const h3_frame = @import("frame.zig");
const qpack = @import("qpack.zig");
const h3_limits = @import("limits.zig");

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

/// Valid state transitions for HTTP/3 streams (RFC 9114 §4.1).
pub fn isValidTransition(from: StreamState, to: StreamState) bool {
    return switch (from) {
        .open => to == .headers_done or to == .reset,
        .headers_done => to == .data_transfer or to == .complete or to == .reset,
        .data_transfer => to == .complete or to == .reset,
        .complete => false,
        .reset => false,
    };
}

/// HTTP/3 SETTINGS parameters (RFC 9114 §7.2.4.1).
pub const Settings = struct {
    max_field_section_size: u64 = 16384,
    qpack_max_table_capacity: u64 = 0,
    qpack_blocked_streams: u64 = 0,
    enable_connect_protocol: u64 = 0,
    h3_datagram: u64 = 0,

    /// Encode SETTINGS as a frame payload (key-value varint pairs).
    pub fn encodePayload(self: *const Settings, out: []u8) !usize {
        var pos: usize = 0;
        // Only encode non-default values to minimize wire size
        if (self.max_field_section_size != 16384) {
            pos += try encodeSettingPair(out[pos..], 0x06, self.max_field_section_size);
        }
        if (self.qpack_max_table_capacity != 0) {
            pos += try encodeSettingPair(out[pos..], 0x01, self.qpack_max_table_capacity);
        }
        if (self.qpack_blocked_streams != 0) {
            pos += try encodeSettingPair(out[pos..], 0x07, self.qpack_blocked_streams);
        }
        if (self.enable_connect_protocol != 0) {
            pos += try encodeSettingPair(out[pos..], 0x08, self.enable_connect_protocol);
        }
        if (self.h3_datagram != 0) {
            pos += try encodeSettingPair(out[pos..], 0x33, self.h3_datagram);
        }
        return pos;
    }

    /// Decode SETTINGS from a frame payload.
    pub fn decodePayload(data: []const u8) !Settings {
        var settings = Settings{};
        var pos: usize = 0;
        var param_count: usize = 0;
        while (pos < data.len) {
            param_count += 1;
            // Cap total SETTINGS parameters (RFC 9114 §7.2.4.1) to bound decode work.
            try h3_limits.validateSettingsCount(param_count);
            const id_result = try decodeVarIntFromSlice(data, pos);
            pos = id_result.end;
            const val_result = try decodeVarIntFromSlice(data, pos);
            pos = val_result.end;
            switch (id_result.value) {
                0x06 => settings.max_field_section_size = val_result.value,
                0x01 => settings.qpack_max_table_capacity = val_result.value,
                0x07 => settings.qpack_blocked_streams = val_result.value,
                0x08 => settings.enable_connect_protocol = val_result.value,
                0x33 => settings.h3_datagram = val_result.value,
                else => {}, // Ignore unknown settings (RFC 9114 §7.2.4.1)
            }
        }
        return settings;
    }
};

/// Encode a single setting key-value pair as varints.
fn encodeSettingPair(out: []u8, key: u64, value: u64) !usize {
    var pos: usize = 0;
    pos += try encodeVarIntToSlice(out[pos..], key);
    pos += try encodeVarIntToSlice(out[pos..], value);
    return pos;
}

/// Encode a QUIC varint into a slice, return bytes written.
fn encodeVarIntToSlice(out: []u8, value: u64) !usize {
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
        out[0] = @intCast(0xc0 | (value >> 56));
        out[1] = @intCast((value >> 48) & 0xff);
        out[2] = @intCast((value >> 40) & 0xff);
        out[3] = @intCast((value >> 32) & 0xff);
        out[4] = @intCast((value >> 24) & 0xff);
        out[5] = @intCast((value >> 16) & 0xff);
        out[6] = @intCast((value >> 8) & 0xff);
        out[7] = @intCast(value & 0xff);
        return 8;
    }
}

/// Decode a QUIC varint from a slice at given position.
fn decodeVarIntFromSlice(data: []const u8, start: usize) !struct { value: u64, end: usize } {
    if (start >= data.len) return error.IncompleteFrame;
    const first = data[start];
    const prefix = first >> 6;
    const len: usize = @as(usize, 1) << @intCast(prefix);
    if (start + len > data.len) return error.IncompleteFrame;
    var value: u64 = first & 0x3f;
    for (1..len) |i| {
        value = (value << 8) | data[start + i];
    }
    return .{ .value = value, .end = start + len };
}

/// Control stream state (RFC 9114 §6.2.1).
pub const ControlStreamState = enum {
    /// Not yet opened.
    idle,
    /// Stream type byte sent, waiting for SETTINGS.
    type_sent,
    /// SETTINGS sent on this control stream.
    settings_sent,
    /// Peer's control stream received and SETTINGS decoded.
    peer_settings_received,
    /// GOAWAY sent.
    goaway_sent,
    /// Closed.
    closed,
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

    /// Transition to a new state with validation.
    pub fn transition(self: *H3Stream, new_state: StreamState) !void {
        if (!isValidTransition(self.state, new_state)) {
            return error.InvalidStateTransition;
        }
        self.state = new_state;
    }
};

/// HTTP/3 connection state.
pub const H3Connection = struct {
    /// Whether SETTINGS have been exchanged.
    settings_sent: bool = false,
    settings_received: bool = false,
    /// Local and peer settings.
    local_settings: Settings = .{},
    peer_settings: Settings = .{},
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
    /// Control stream state.
    control_state: ControlStreamState = .idle,
    /// QPACK encoder stream ID (local).
    qpack_encoder_stream_id: ?u64 = null,
    /// QPACK decoder stream ID (local).
    qpack_decoder_stream_id: ?u64 = null,
    /// Peer QPACK encoder stream ID.
    peer_qpack_encoder_stream_id: ?u64 = null,
    /// Peer QPACK decoder stream ID.
    peer_qpack_decoder_stream_id: ?u64 = null,

    pub fn init(allocator: std.mem.Allocator) H3Connection {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *H3Connection) void {
        self.streams.deinit(self.allocator);
    }

    /// Open a new request stream (client-side).
    pub fn openRequestStream(self: *H3Connection) !u64 {
        if (self.goaway_sent or self.goaway_received) return error.ConnectionClosing;
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

    /// Mark SETTINGS as sent with the given settings.
    pub fn markSettingsSent(self: *H3Connection, settings: Settings) void {
        self.settings_sent = true;
        self.local_settings = settings;
        self.control_state = .settings_sent;
    }

    /// Mark SETTINGS as received with the decoded peer settings.
    pub fn markSettingsReceived(self: *H3Connection, settings: Settings) void {
        self.settings_received = true;
        self.peer_settings = settings;
        self.control_state = .peer_settings_received;
    }

    /// Whether the connection is ready for requests (SETTINGS exchanged).
    pub fn isReady(self: *const H3Connection) bool {
        return self.settings_sent and self.settings_received;
    }

    /// Initiate GOAWAY.
    pub fn sendGoaway(self: *H3Connection, last_stream_id: u64) void {
        self.goaway_sent = true;
        self.goaway_stream_id = last_stream_id;
        self.control_state = .goaway_sent;
    }

    /// Handle received GOAWAY.
    pub fn receiveGoaway(self: *H3Connection, last_stream_id: u64) void {
        self.goaway_received = true;
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

    /// Encode a GOAWAY frame payload (stream ID as varint).
    pub fn encodeGoawayPayload(out: []u8, stream_id: u64) !usize {
        return encodeVarIntToSlice(out, stream_id);
    }

    /// Decode a GOAWAY frame payload.
    pub fn decodeGoawayPayload(data: []const u8) !u64 {
        const result = try decodeVarIntFromSlice(data, 0);
        return result.value;
    }

    /// Assign QPACK encoder stream ID.
    pub fn setQpackEncoderStream(self: *H3Connection, stream_id: u64) void {
        self.qpack_encoder_stream_id = stream_id;
    }

    /// Assign QPACK decoder stream ID.
    pub fn setQpackDecoderStream(self: *H3Connection, stream_id: u64) void {
        self.qpack_decoder_stream_id = stream_id;
    }

    /// Assign peer QPACK encoder stream ID.
    pub fn setPeerQpackEncoderStream(self: *H3Connection, stream_id: u64) void {
        self.peer_qpack_encoder_stream_id = stream_id;
    }

    /// Assign peer QPACK decoder stream ID.
    pub fn setPeerQpackDecoderStream(self: *H3Connection, stream_id: u64) void {
        self.peer_qpack_decoder_stream_id = stream_id;
    }

    /// Remove completed/reset streams to free memory.
    pub fn pruneFinishedStreams(self: *H3Connection) void {
        var i: usize = 0;
        while (i < self.streams.items.len) {
            const state = self.streams.items[i].state;
            if (state == .complete or state == .reset) {
                _ = self.streams.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }
};

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
    conn.markSettingsSent(.{});
    try std.testing.expect(!conn.isReady());
    conn.markSettingsReceived(.{});
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

test "H3 error codes" {
    try std.testing.expectEqual(@as(u64, 0x0100), @backingInt(ErrorCode.no_error));
    try std.testing.expectEqual(@as(u64, 0x0101), @backingInt(ErrorCode.general_protocol_error));
    try std.testing.expectEqual(@as(u64, 0x010c), @backingInt(ErrorCode.request_cancelled));
}

test "Settings encode/decode roundtrip" {
    const settings = Settings{
        .max_field_section_size = 65536,
        .qpack_max_table_capacity = 4096,
        .qpack_blocked_streams = 16,
        .enable_connect_protocol = 1,
        .h3_datagram = 1,
    };

    var buf: [128]u8 = undefined;
    const len = try settings.encodePayload(&buf);
    try std.testing.expect(len > 0);

    const decoded = try Settings.decodePayload(buf[0..len]);
    try std.testing.expectEqual(@as(u64, 65536), decoded.max_field_section_size);
    try std.testing.expectEqual(@as(u64, 4096), decoded.qpack_max_table_capacity);
    try std.testing.expectEqual(@as(u64, 16), decoded.qpack_blocked_streams);
    try std.testing.expectEqual(@as(u64, 1), decoded.enable_connect_protocol);
    try std.testing.expectEqual(@as(u64, 1), decoded.h3_datagram);
}

test "Settings default values not encoded" {
    const settings = Settings{};
    var buf: [128]u8 = undefined;
    const len = try settings.encodePayload(&buf);
    // All defaults: nothing encoded
    try std.testing.expectEqual(@as(usize, 0), len);
}

test "Settings decode ignores unknown IDs" {
    // Manually encode: unknown_id=0xFF value=42, then max_field_section_size=8192
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    buf[pos] = 0x40 | 0x00; // 2-byte varint prefix for 0xFF
    buf[pos + 1] = 0xff;
    pos += 2;
    buf[pos] = 42; // value
    pos += 1;
    buf[pos] = 0x06; // max_field_section_size
    pos += 1;
    buf[pos] = 0x40 | 0x20; // 8192 = 0x2000, 2-byte varint
    buf[pos + 1] = 0x00;
    pos += 2;

    const decoded = try Settings.decodePayload(buf[0..pos]);
    try std.testing.expectEqual(@as(u64, 8192), decoded.max_field_section_size);
}

test "Settings decode rejects oversized parameter count" {
    // 33 sequential settings (one more than max_settings_params=32), each a
    // known ID with a 1-byte value. The decoder must reject on the 33rd.
    var buf: [128]u8 = undefined;
    var pos: usize = 0;
    var i: usize = 0;
    while (i < 33) : (i += 1) {
        buf[pos] = 0x06; // max_field_section_size
        pos += 1;
        buf[pos] = 1; // value
        pos += 1;
    }
    try std.testing.expectError(error.TooManySettings, Settings.decodePayload(buf[0..pos]));
}

test "GOAWAY payload encode/decode" {
    var buf: [16]u8 = undefined;
    const len = try H3Connection.encodeGoawayPayload(&buf, 12);
    const decoded = try H3Connection.decodeGoawayPayload(buf[0..len]);
    try std.testing.expectEqual(@as(u64, 12), decoded);
}

test "GOAWAY payload large stream ID" {
    var buf: [16]u8 = undefined;
    const len = try H3Connection.encodeGoawayPayload(&buf, 1073741824);
    const decoded = try H3Connection.decodeGoawayPayload(buf[0..len]);
    try std.testing.expectEqual(@as(u64, 1073741824), decoded);
}

test "H3Stream valid state transitions" {
    try std.testing.expect(isValidTransition(.open, .headers_done));
    try std.testing.expect(isValidTransition(.open, .reset));
    try std.testing.expect(!isValidTransition(.open, .complete));
    try std.testing.expect(!isValidTransition(.open, .data_transfer));
    try std.testing.expect(isValidTransition(.headers_done, .data_transfer));
    try std.testing.expect(isValidTransition(.headers_done, .complete));
    try std.testing.expect(isValidTransition(.data_transfer, .complete));
    try std.testing.expect(!isValidTransition(.complete, .reset));
    try std.testing.expect(!isValidTransition(.reset, .open));
}

test "H3Stream transition validation" {
    var stream = H3Stream{ .stream_id = 0, .is_request = true };
    try stream.transition(.headers_done);
    try std.testing.expectEqual(StreamState.headers_done, stream.state);
    try stream.transition(.data_transfer);
    try std.testing.expectEqual(StreamState.data_transfer, stream.state);
    try stream.transition(.complete);
    try std.testing.expectEqual(StreamState.complete, stream.state);
    // Cannot transition from complete
    try std.testing.expectError(error.InvalidStateTransition, stream.transition(.reset));
}

test "H3Connection pruneFinishedStreams" {
    var conn = H3Connection.init(std.testing.allocator);
    defer conn.deinit();

    _ = try conn.openRequestStream(); // id=0
    _ = try conn.openRequestStream(); // id=4
    _ = try conn.openRequestStream(); // id=8
    try std.testing.expectEqual(@as(usize, 3), conn.streams.items.len);

    conn.getStream(0).?.state = .complete;
    conn.getStream(8).?.state = .reset;
    conn.pruneFinishedStreams();

    try std.testing.expectEqual(@as(usize, 1), conn.streams.items.len);
    try std.testing.expectEqual(@as(u64, 4), conn.streams.items[0].stream_id);
}

test "H3Connection GOAWAY blocks new streams" {
    var conn = H3Connection.init(std.testing.allocator);
    defer conn.deinit();

    _ = try conn.openRequestStream();
    conn.sendGoaway(0);
    try std.testing.expectError(error.ConnectionClosing, conn.openRequestStream());
}

test "H3Connection QPACK stream assignment" {
    var conn = H3Connection.init(std.testing.allocator);
    defer conn.deinit();

    conn.setQpackEncoderStream(2);
    conn.setQpackDecoderStream(6);
    conn.setPeerQpackEncoderStream(3);
    conn.setPeerQpackDecoderStream(7);

    try std.testing.expectEqual(@as(?u64, 2), conn.qpack_encoder_stream_id);
    try std.testing.expectEqual(@as(?u64, 6), conn.qpack_decoder_stream_id);
    try std.testing.expectEqual(@as(?u64, 3), conn.peer_qpack_encoder_stream_id);
    try std.testing.expectEqual(@as(?u64, 7), conn.peer_qpack_decoder_stream_id);
}

test "H3Connection control stream state progression" {
    var conn = H3Connection.init(std.testing.allocator);
    defer conn.deinit();

    try std.testing.expectEqual(ControlStreamState.idle, conn.control_state);
    conn.markSettingsSent(.{});
    try std.testing.expectEqual(ControlStreamState.settings_sent, conn.control_state);
    conn.markSettingsReceived(.{});
    try std.testing.expectEqual(ControlStreamState.peer_settings_received, conn.control_state);
    conn.sendGoaway(0);
    try std.testing.expectEqual(ControlStreamState.goaway_sent, conn.control_state);
}
