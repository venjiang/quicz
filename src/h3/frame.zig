//! HTTP/3 frame codec (RFC 9114).
//!
//! Implements HTTP/3 frame type identification, encode, and decode.
//! QPACK compression is stubbed for future implementation.

const std = @import("std");
const buffer = @import("../quic/buffer.zig");

/// HTTP/3 frame types (RFC 9114 §7.2).
pub const FrameType = enum(u64) {
    data = 0x00,
    headers = 0x01,
    cancel_push = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    goaway = 0x07,
    max_push_id = 0x0d,
    _,
};

/// HTTP/3 unidirectional stream types (RFC 9114 §6.2).
pub const StreamType = enum(u64) {
    control = 0x00,
    push = 0x01,
    qpack_encoder = 0x02,
    qpack_decoder = 0x03,
    _,
};

/// HTTP/3 SETTINGS identifiers (RFC 9114 §7.2.4.1).
pub const SettingId = enum(u64) {
    max_field_section_size = 0x06,
    qpack_max_table_capacity = 0x01,
    qpack_blocked_streams = 0x07,
    enable_connect_protocol = 0x08,
    h3_datagram = 0x33,
    _,
};

/// An HTTP/3 frame: type + length + payload.
pub const Frame = struct {
    frame_type: u64,
    payload: []const u8,
};

/// Encode an HTTP/3 frame (type varint + length varint + payload).
pub fn encodeFrame(writer: anytype, frame: Frame) !void {
    try encodeVarInt(writer, frame.frame_type);
    try encodeVarInt(writer, frame.payload.len);
    try writer.writeAll(frame.payload);
}

/// Decode an HTTP/3 frame from a byte slice.
/// Returns the frame and the number of bytes consumed.
pub fn decodeFrame(data: []const u8) !struct { frame: Frame, consumed: usize } {
    const type_result = try decodeVarInt(data);
    const len_result = try decodeVarInt(data[type_result.consumed..]);
    const header_len = type_result.consumed + len_result.consumed;
    const payload_len: usize = @intCast(len_result.value);
    if (header_len + payload_len > data.len) return error.IncompleteFrame;
    return .{
        .frame = .{
            .frame_type = type_result.value,
            .payload = data[header_len .. header_len + payload_len],
        },
        .consumed = header_len + payload_len,
    };
}

/// Encode a QUIC-style varint (RFC 9000 §16).
fn encodeVarInt(writer: anytype, value: u64) !void {
    if (value <= 63) {
        try writer.writeByte(@intCast(value));
    } else if (value <= 16383) {
        try writer.writeByte(@intCast(0x40 | (value >> 8)));
        try writer.writeByte(@intCast(value & 0xff));
    } else if (value <= 1073741823) {
        try writer.writeByte(@intCast(0x80 | (value >> 24)));
        try writer.writeByte(@intCast((value >> 16) & 0xff));
        try writer.writeByte(@intCast((value >> 8) & 0xff));
        try writer.writeByte(@intCast(value & 0xff));
    } else {
        try writer.writeByte(@intCast(0xc0 | (value >> 56)));
        try writer.writeByte(@intCast((value >> 48) & 0xff));
        try writer.writeByte(@intCast((value >> 40) & 0xff));
        try writer.writeByte(@intCast((value >> 32) & 0xff));
        try writer.writeByte(@intCast((value >> 24) & 0xff));
        try writer.writeByte(@intCast((value >> 16) & 0xff));
        try writer.writeByte(@intCast((value >> 8) & 0xff));
        try writer.writeByte(@intCast(value & 0xff));
    }
}

/// Decode a QUIC-style varint from a byte slice.
fn decodeVarInt(data: []const u8) !struct { value: u64, consumed: usize } {
    if (data.len == 0) return error.IncompleteFrame;
    const first = data[0];
    const prefix = first >> 6;
    const len: usize = @as(usize, 1) << @intCast(prefix);
    if (data.len < len) return error.IncompleteFrame;
    var value: u64 = first & 0x3f;
    for (1..len) |i| {
        value = (value << 8) | data[i];
    }
    return .{ .value = value, .consumed = len };
}

/// Return the wire length of an HTTP/3 frame.
pub fn frameWireLen(frame_type: u64, payload_len: usize) usize {
    return varIntLen(frame_type) + varIntLen(payload_len) + payload_len;
}

fn varIntLen(value: u64) usize {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    return 8;
}

test "HTTP/3 DATA frame encode/decode roundtrip" {
    var buf: [256]u8 = undefined;
    var out = buffer.fixedWriter(&buf);
    const payload = "hello http3";
    try encodeFrame(out.writer(), .{ .frame_type = @intFromEnum(FrameType.data), .payload = payload });

    const written = out.getWritten();
    const result = try decodeFrame(written);
    try std.testing.expectEqual(@as(u64, 0x00), result.frame.frame_type);
    try std.testing.expectEqualStrings(payload, result.frame.payload);
    try std.testing.expectEqual(written.len, result.consumed);
}

test "HTTP/3 HEADERS frame encode/decode roundtrip" {
    var buf: [256]u8 = undefined;
    var out = buffer.fixedWriter(&buf);
    const payload = "qpack-encoded-headers";
    try encodeFrame(out.writer(), .{ .frame_type = @intFromEnum(FrameType.headers), .payload = payload });

    const written = out.getWritten();
    const result = try decodeFrame(written);
    try std.testing.expectEqual(@as(u64, 0x01), result.frame.frame_type);
    try std.testing.expectEqualStrings(payload, result.frame.payload);
}

test "HTTP/3 SETTINGS frame encode/decode roundtrip" {
    var buf: [256]u8 = undefined;
    var out = buffer.fixedWriter(&buf);
    // SETTINGS payload: max_field_section_size=8192
    var settings_payload: [16]u8 = undefined;
    var sout = buffer.fixedWriter(&settings_payload);
    try encodeVarInt(sout.writer(), @intFromEnum(SettingId.max_field_section_size));
    try encodeVarInt(sout.writer(), 8192);
    const sp = sout.getWritten();

    try encodeFrame(out.writer(), .{ .frame_type = @intFromEnum(FrameType.settings), .payload = sp });

    const written = out.getWritten();
    const result = try decodeFrame(written);
    try std.testing.expectEqual(@as(u64, 0x04), result.frame.frame_type);
    try std.testing.expectEqual(sp.len, result.frame.payload.len);
}

test "HTTP/3 frame wire length calculation" {
    // DATA frame with 100-byte payload: type(1) + len(2) + 100 = 103
    try std.testing.expectEqual(@as(usize, 103), frameWireLen(0x00, 100));
    // SETTINGS frame with 200-byte payload: type(1) + len(2) + 200 = 203
    try std.testing.expectEqual(@as(usize, 203), frameWireLen(0x04, 200));
}

test "HTTP/3 decode incomplete frame returns error" {
    const data = [_]u8{ 0x00, 0x0a, 0x01, 0x02 }; // type=0, len=10, but only 2 bytes payload
    try std.testing.expectError(error.IncompleteFrame, decodeFrame(&data));
}

test "HTTP/3 stream type values" {
    try std.testing.expectEqual(@as(u64, 0x00), @intFromEnum(StreamType.control));
    try std.testing.expectEqual(@as(u64, 0x01), @intFromEnum(StreamType.push));
    try std.testing.expectEqual(@as(u64, 0x02), @intFromEnum(StreamType.qpack_encoder));
    try std.testing.expectEqual(@as(u64, 0x03), @intFromEnum(StreamType.qpack_decoder));
}
