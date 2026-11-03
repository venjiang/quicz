//! HTTP/3 frame codec (RFC 9114).
//!
//! Implements HTTP/3 frame type identification, encode, and decode.
//! QPACK header compression lives in qpack.zig (RFC 9204).

const std = @import("std");
const buffer = @import("../quic/buffer.zig");
const limits = @import("limits.zig");

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

/// Return whether `frame_type` is a reserved GREASE type (RFC 9114 §7.2.8):
/// `0x1f * N + 0x21` for a non-negative integer N.
pub fn isGreaseFrameType(frame_type: u64) bool {
    if (frame_type < 0x21) return false;
    return (frame_type - 0x21) % 0x1f == 0;
}

/// Return whether a frame may be skipped while scanning a request/response
/// stream for its initial HEADERS frame. GREASE frames and unknown extension
/// frame types carry no request/response semantics and must be ignored by
/// receivers (RFC 9114 §7.2.8 and §9); known frame types are not skippable
/// here, so e.g. DATA before HEADERS still fails as a protocol error.
pub fn isIgnorableHeaderPrefixFrame(frame_type: u64) bool {
    if (isGreaseFrameType(frame_type)) return true;
    return switch (frame_type) {
        @backingInt(FrameType.data),
        @backingInt(FrameType.headers),
        @backingInt(FrameType.cancel_push),
        @backingInt(FrameType.settings),
        @backingInt(FrameType.push_promise),
        @backingInt(FrameType.goaway),
        @backingInt(FrameType.max_push_id),
        => false,
        else => true,
    };
}

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
    // Reject oversize frames on the declared length first (RFC 9114 §4.6): a
    // receiver that buffers/reserves by the declared length must not be made
    // to allocate for an attacker-inflated frame.
    try limits.validateFrameSize(payload_len);
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
    try encodeFrame(out.writer(), .{ .frame_type = @backingInt(FrameType.data), .payload = payload });

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
    try encodeFrame(out.writer(), .{ .frame_type = @backingInt(FrameType.headers), .payload = payload });

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
    try encodeVarInt(sout.writer(), @backingInt(SettingId.max_field_section_size));
    try encodeVarInt(sout.writer(), 8192);
    const sp = sout.getWritten();

    try encodeFrame(out.writer(), .{ .frame_type = @backingInt(FrameType.settings), .payload = sp });

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

test "HTTP/3 oversized frame payload is rejected" {
    // Declared payload length exceeds max_frame_payload_size (16 MiB); the
    // buffer need not actually contain that many bytes — the cap triggers on
    // the declared length before any downstream allocation.
    var data: [9]u8 = undefined;
    data[0] = 0x00; // DATA frame
    data[1] = 0xC0; // 8-byte varint length prefix
    @memset(data[2..9], 0xff); // length = 2^62 - 1
    try std.testing.expectError(error.FrameTooLarge, decodeFrame(&data));
}

test "HTTP/3 stream type values" {
    try std.testing.expectEqual(@as(u64, 0x00), @backingInt(StreamType.control));
    try std.testing.expectEqual(@as(u64, 0x01), @backingInt(StreamType.push));
    try std.testing.expectEqual(@as(u64, 0x02), @backingInt(StreamType.qpack_encoder));
    try std.testing.expectEqual(@as(u64, 0x03), @backingInt(StreamType.qpack_decoder));
}
