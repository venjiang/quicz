const std = @import("std");
const buffer = @import("buffer.zig");
const packet = @import("packet.zig");

/// Basic subset of QUIC frames (RFC 9000 Section 19).
pub const FrameType = enum(u8) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02, // simplified, omitting ECN variants for now
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    stream = 0x08, // 0x08-0x0f STREAM* variants
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams_bidi = 0x12,
    max_streams_uni = 0x13,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked_bidi = 0x16,
    streams_blocked_uni = 0x17,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close = 0x1c,
    application_close = 0x1d,
};

pub const StreamFrame = struct {
    stream_id: u64,
    offset: u64,
    fin: bool,
    data: []const u8,
};

pub const CryptoFrame = struct {
    offset: u64,
    data: []const u8,
};

pub const PaddingFrame = struct { len: usize };

/// ACK frame for the minimal codec. Additional ACK ranges are intentionally not
/// modeled yet; decoding rejects frames whose ACK range count is non-zero.
pub const AckFrame = struct {
    largest_acknowledged: u64,
    ack_delay: u64,
    first_ack_range: u64,
};

pub const ResetStreamFrame = struct {
    stream_id: u64,
    application_error_code: u64,
    final_size: u64,
};

pub const StopSendingFrame = struct {
    stream_id: u64,
    application_error_code: u64,
};

pub const MaxDataFrame = struct {
    maximum_data: u64,
};

pub const MaxStreamDataFrame = struct {
    stream_id: u64,
    maximum_stream_data: u64,
};

pub const MaxStreamsBidiFrame = struct {
    maximum_streams: u64,
};

pub const MaxStreamsUniFrame = struct {
    maximum_streams: u64,
};

pub const ConnectionCloseFrame = struct {
    error_code: u64,
    frame_type: u64,
    reason_phrase: []const u8,
};

pub const ApplicationCloseFrame = struct {
    error_code: u64,
    reason_phrase: []const u8,
};

/// A simplified union of a few important frame types.
pub const Frame = union(enum) {
    padding: PaddingFrame,
    ping: void,
    ack: AckFrame,
    reset_stream: ResetStreamFrame,
    stop_sending: StopSendingFrame,
    stream: StreamFrame,
    crypto: CryptoFrame,
    max_data: MaxDataFrame,
    max_stream_data: MaxStreamDataFrame,
    max_streams_bidi: MaxStreamsBidiFrame,
    max_streams_uni: MaxStreamsUniFrame,
    connection_close: ConnectionCloseFrame,
    application_close: ApplicationCloseFrame,
};

pub const FrameError = error{
    UnsupportedFrameType,
    UnsupportedAckRangeCount,
    InvalidPaddingLength,
    InvalidFrameLength,
};

/// A decoded frame plus the number of payload bytes consumed. If `frame` owns
/// buffers, callers release it with `deinitFrame`.
pub const DecodedFrame = struct {
    frame: Frame,
    len: usize,
};

fn varIntToUsize(value: u64) FrameError!usize {
    return std.math.cast(usize, value) orelse error.InvalidFrameLength;
}

/// Release any buffers owned by a decoded frame.
pub fn deinitFrame(frame: *Frame, allocator: std.mem.Allocator) void {
    switch (frame.*) {
        .stream => |stream| allocator.free(stream.data),
        .crypto => |crypto| allocator.free(crypto.data),
        .connection_close => |close| allocator.free(close.reason_phrase),
        .application_close => |close| allocator.free(close.reason_phrase),
        else => {},
    }
}

/// Encode one minimal QUIC frame to `writer`.
pub fn encodeFrame(writer: anytype, frame: Frame) !void {
    switch (frame) {
        .padding => |padding| {
            if (padding.len == 0) return error.InvalidPaddingLength;
            var i: usize = 0;
            while (i < padding.len) : (i += 1) {
                try writer.writeByte(@intFromEnum(FrameType.padding));
            }
        },
        .ping => {
            try writer.writeByte(@intFromEnum(FrameType.ping));
        },
        .ack => |ack| {
            try writer.writeByte(@intFromEnum(FrameType.ack));
            try packet.encodeVarInt(writer, ack.largest_acknowledged);
            try packet.encodeVarInt(writer, ack.ack_delay);
            try packet.encodeVarInt(writer, 0); // ack range count
            try packet.encodeVarInt(writer, ack.first_ack_range);
        },
        .reset_stream => |reset| {
            try writer.writeByte(@intFromEnum(FrameType.reset_stream));
            try packet.encodeVarInt(writer, reset.stream_id);
            try packet.encodeVarInt(writer, reset.application_error_code);
            try packet.encodeVarInt(writer, reset.final_size);
        },
        .stop_sending => |stop_sending| {
            try writer.writeByte(@intFromEnum(FrameType.stop_sending));
            try packet.encodeVarInt(writer, stop_sending.stream_id);
            try packet.encodeVarInt(writer, stop_sending.application_error_code);
        },
        .stream => |stream| {
            var frame_type: u8 = @intFromEnum(FrameType.stream);
            if (stream.offset != 0) {
                frame_type |= 0x04; // OFF bit
            }
            frame_type |= 0x02; // LEN bit: always set in this simplified codec
            if (stream.fin) {
                frame_type |= 0x01; // FIN bit
            }

            try writer.writeByte(frame_type);
            try packet.encodeVarInt(writer, stream.stream_id);
            if (stream.offset != 0) {
                try packet.encodeVarInt(writer, stream.offset);
            }
            try packet.encodeVarInt(writer, stream.data.len);
            try writer.writeAll(stream.data);
        },
        .crypto => |crypto| {
            try writer.writeByte(@intFromEnum(FrameType.crypto));
            try packet.encodeVarInt(writer, crypto.offset);
            try packet.encodeVarInt(writer, crypto.data.len);
            try writer.writeAll(crypto.data);
        },
        .max_data => |max_data| {
            try writer.writeByte(@intFromEnum(FrameType.max_data));
            try packet.encodeVarInt(writer, max_data.maximum_data);
        },
        .max_stream_data => |max_stream_data| {
            try writer.writeByte(@intFromEnum(FrameType.max_stream_data));
            try packet.encodeVarInt(writer, max_stream_data.stream_id);
            try packet.encodeVarInt(writer, max_stream_data.maximum_stream_data);
        },
        .max_streams_bidi => |max_streams| {
            try writer.writeByte(@intFromEnum(FrameType.max_streams_bidi));
            try packet.encodeVarInt(writer, max_streams.maximum_streams);
        },
        .max_streams_uni => |max_streams| {
            try writer.writeByte(@intFromEnum(FrameType.max_streams_uni));
            try packet.encodeVarInt(writer, max_streams.maximum_streams);
        },
        .connection_close => |close| {
            try writer.writeByte(@intFromEnum(FrameType.connection_close));
            try packet.encodeVarInt(writer, close.error_code);
            try packet.encodeVarInt(writer, close.frame_type);
            try packet.encodeVarInt(writer, close.reason_phrase.len);
            try writer.writeAll(close.reason_phrase);
        },
        .application_close => |close| {
            try writer.writeByte(@intFromEnum(FrameType.application_close));
            try packet.encodeVarInt(writer, close.error_code);
            try packet.encodeVarInt(writer, close.reason_phrase.len);
            try writer.writeAll(close.reason_phrase);
        },
    }
}

/// Decode the first frame in `data`, returning both the frame and byte count.
/// This helper can aggregate consecutive PADDING bytes because it has packet
/// payload boundaries, unlike the streaming reader API.
pub fn decodeFrameSlice(data: []const u8, allocator: std.mem.Allocator) !DecodedFrame {
    if (data.len == 0) return error.EndOfStream;

    if (data[0] == @intFromEnum(FrameType.padding)) {
        var len: usize = 0;
        while (len < data.len and data[len] == @intFromEnum(FrameType.padding)) : (len += 1) {}
        return .{ .frame = .{ .padding = .{ .len = len } }, .len = len };
    }

    var in = buffer.fixedReader(data);
    const decoded = try decodeFrame(in.reader(), allocator);
    return .{ .frame = decoded, .len = in.pos };
}

/// Decode one minimal QUIC frame from `reader`.
pub fn decodeFrame(reader: anytype, allocator: std.mem.Allocator) !Frame {
    const frame_type = try reader.readByte();

    if (frame_type == @intFromEnum(FrameType.padding)) {
        return .{ .padding = .{ .len = 1 } };
    }

    if (frame_type == @intFromEnum(FrameType.ping)) {
        return .{ .ping = {} };
    }

    if (frame_type == @intFromEnum(FrameType.ack)) {
        const largest_acknowledged = (try packet.decodeVarInt(reader)).value;
        const ack_delay = (try packet.decodeVarInt(reader)).value;
        const ack_range_count = (try packet.decodeVarInt(reader)).value;
        if (ack_range_count != 0) return error.UnsupportedAckRangeCount;
        const first_ack_range = (try packet.decodeVarInt(reader)).value;

        return .{ .ack = .{
            .largest_acknowledged = largest_acknowledged,
            .ack_delay = ack_delay,
            .first_ack_range = first_ack_range,
        } };
    }

    if (frame_type == @intFromEnum(FrameType.reset_stream)) {
        const stream_id = (try packet.decodeVarInt(reader)).value;
        const application_error_code = (try packet.decodeVarInt(reader)).value;
        const final_size = (try packet.decodeVarInt(reader)).value;

        return .{ .reset_stream = .{
            .stream_id = stream_id,
            .application_error_code = application_error_code,
            .final_size = final_size,
        } };
    }

    if (frame_type == @intFromEnum(FrameType.stop_sending)) {
        const stream_id = (try packet.decodeVarInt(reader)).value;
        const application_error_code = (try packet.decodeVarInt(reader)).value;

        return .{ .stop_sending = .{
            .stream_id = stream_id,
            .application_error_code = application_error_code,
        } };
    }

    if (frame_type == @intFromEnum(FrameType.crypto)) {
        const offset = (try packet.decodeVarInt(reader)).value;
        const data_len = (try packet.decodeVarInt(reader)).value;
        const len_usize = try varIntToUsize(data_len);

        const data = try allocator.alloc(u8, len_usize);
        errdefer allocator.free(data);
        try reader.readNoEof(data);

        return .{ .crypto = .{
            .offset = offset,
            .data = data,
        } };
    }

    if (frame_type == @intFromEnum(FrameType.max_data)) {
        const maximum_data = (try packet.decodeVarInt(reader)).value;
        return .{ .max_data = .{ .maximum_data = maximum_data } };
    }

    if (frame_type == @intFromEnum(FrameType.max_stream_data)) {
        const stream_id = (try packet.decodeVarInt(reader)).value;
        const maximum_stream_data = (try packet.decodeVarInt(reader)).value;

        return .{ .max_stream_data = .{
            .stream_id = stream_id,
            .maximum_stream_data = maximum_stream_data,
        } };
    }

    if (frame_type == @intFromEnum(FrameType.max_streams_bidi)) {
        const maximum_streams = (try packet.decodeVarInt(reader)).value;
        return .{ .max_streams_bidi = .{ .maximum_streams = maximum_streams } };
    }

    if (frame_type == @intFromEnum(FrameType.max_streams_uni)) {
        const maximum_streams = (try packet.decodeVarInt(reader)).value;
        return .{ .max_streams_uni = .{ .maximum_streams = maximum_streams } };
    }

    if ((frame_type & 0b1111_1000) == @intFromEnum(FrameType.stream)) {
        const has_off = (frame_type & 0x04) != 0;
        const has_len = (frame_type & 0x02) != 0;
        const fin = (frame_type & 0x01) != 0;

        const stream_id = (try packet.decodeVarInt(reader)).value;

        var offset: u64 = 0;
        if (has_off) {
            offset = (try packet.decodeVarInt(reader)).value;
        }

        if (!has_len) {
            return error.InvalidFrameLength;
        }

        const data_len = (try packet.decodeVarInt(reader)).value;
        const len_usize = try varIntToUsize(data_len);

        const data = try allocator.alloc(u8, len_usize);
        errdefer allocator.free(data);
        try reader.readNoEof(data);

        return .{ .stream = .{
            .stream_id = stream_id,
            .offset = offset,
            .fin = fin,
            .data = data,
        } };
    }

    if (frame_type == @intFromEnum(FrameType.connection_close)) {
        const error_code = (try packet.decodeVarInt(reader)).value;
        const triggering_frame_type = (try packet.decodeVarInt(reader)).value;
        const reason_len = (try packet.decodeVarInt(reader)).value;
        const len_usize = try varIntToUsize(reason_len);

        const reason_phrase = try allocator.alloc(u8, len_usize);
        errdefer allocator.free(reason_phrase);
        try reader.readNoEof(reason_phrase);

        return .{ .connection_close = .{
            .error_code = error_code,
            .frame_type = triggering_frame_type,
            .reason_phrase = reason_phrase,
        } };
    }

    if (frame_type == @intFromEnum(FrameType.application_close)) {
        const error_code = (try packet.decodeVarInt(reader)).value;
        const reason_len = (try packet.decodeVarInt(reader)).value;
        const len_usize = try varIntToUsize(reason_len);

        const reason_phrase = try allocator.alloc(u8, len_usize);
        errdefer allocator.free(reason_phrase);
        try reader.readNoEof(reason_phrase);

        return .{ .application_close = .{
            .error_code = error_code,
            .reason_phrase = reason_phrase,
        } };
    }

    return error.UnsupportedFrameType;
}

test "encode/decode stream frame roundtrip" {
    var buf: [256]u8 = undefined;
    var out = buffer.fixedWriter(&buf);

    const input = Frame{ .stream = .{
        .stream_id = 7,
        .offset = 1024,
        .fin = true,
        .data = "hello",
    } };
    try encodeFrame(out.writer(), input);

    const encoded = out.getWritten();
    var in = buffer.fixedReader(encoded);
    var parsed = try decodeFrame(in.reader(), std.testing.allocator);
    defer deinitFrame(&parsed, std.testing.allocator);

    switch (parsed) {
        .stream => |frame| {
            try std.testing.expectEqual(@as(u64, 7), frame.stream_id);
            try std.testing.expectEqual(@as(u64, 1024), frame.offset);
            try std.testing.expect(frame.fin);
            try std.testing.expectEqualStrings("hello", frame.data);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "decodeFrameSlice aggregates consecutive padding" {
    const wire = [_]u8{
        @intFromEnum(FrameType.padding),
        @intFromEnum(FrameType.padding),
        @intFromEnum(FrameType.padding),
        @intFromEnum(FrameType.ping),
    };

    const padding = try decodeFrameSlice(&wire, std.testing.allocator);
    switch (padding.frame) {
        .padding => |frame| {
            try std.testing.expectEqual(@as(usize, 3), frame.len);
            try std.testing.expectEqual(@as(usize, 3), padding.len);
        },
        else => return error.TestUnexpectedResult,
    }

    const ping = try decodeFrameSlice(wire[padding.len..], std.testing.allocator);
    switch (ping.frame) {
        .ping => try std.testing.expectEqual(@as(usize, 1), ping.len),
        else => return error.TestUnexpectedResult,
    }
}

test "encode/decode crypto frame roundtrip" {
    var buf: [256]u8 = undefined;
    var out = buffer.fixedWriter(&buf);

    const input = Frame{ .crypto = .{
        .offset = 4096,
        .data = "crypto-bytes",
    } };
    try encodeFrame(out.writer(), input);

    const encoded = out.getWritten();
    var in = buffer.fixedReader(encoded);
    var parsed = try decodeFrame(in.reader(), std.testing.allocator);
    defer deinitFrame(&parsed, std.testing.allocator);

    switch (parsed) {
        .crypto => |frame| {
            try std.testing.expectEqual(@as(u64, 4096), frame.offset);
            try std.testing.expectEqualStrings("crypto-bytes", frame.data);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "encode/decode ack frame roundtrip" {
    var buf: [128]u8 = undefined;
    var out = buffer.fixedWriter(&buf);

    const input = Frame{ .ack = .{
        .largest_acknowledged = 12345,
        .ack_delay = 42,
        .first_ack_range = 7,
    } };
    try encodeFrame(out.writer(), input);

    const encoded = out.getWritten();
    var in = buffer.fixedReader(encoded);
    const parsed = try decodeFrame(in.reader(), std.testing.allocator);

    switch (parsed) {
        .ack => |frame| {
            try std.testing.expectEqual(@as(u64, 12345), frame.largest_acknowledged);
            try std.testing.expectEqual(@as(u64, 42), frame.ack_delay);
            try std.testing.expectEqual(@as(u64, 7), frame.first_ack_range);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "decode ack frame rejects additional ranges for minimal codec" {
    const wire = [_]u8{
        @intFromEnum(FrameType.ack),
        0x01, // largest acknowledged
        0x00, // ack delay
        0x01, // one additional ACK range
        0x01, // first ACK range
    };

    var in = buffer.fixedReader(&wire);
    try std.testing.expectError(error.UnsupportedAckRangeCount, decodeFrame(in.reader(), std.testing.allocator));
}

test "encode/decode reset_stream frame roundtrip" {
    var buf: [128]u8 = undefined;
    var out = buffer.fixedWriter(&buf);

    const input = Frame{ .reset_stream = .{
        .stream_id = 9,
        .application_error_code = 0x15,
        .final_size = 2048,
    } };
    try encodeFrame(out.writer(), input);

    const encoded = out.getWritten();
    var in = buffer.fixedReader(encoded);
    const parsed = try decodeFrame(in.reader(), std.testing.allocator);

    switch (parsed) {
        .reset_stream => |frame| {
            try std.testing.expectEqual(@as(u64, 9), frame.stream_id);
            try std.testing.expectEqual(@as(u64, 0x15), frame.application_error_code);
            try std.testing.expectEqual(@as(u64, 2048), frame.final_size);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "encode/decode max_data frame roundtrip" {
    var buf: [64]u8 = undefined;
    var out = buffer.fixedWriter(&buf);

    const input = Frame{ .max_data = .{
        .maximum_data = 1_000_000,
    } };
    try encodeFrame(out.writer(), input);

    const encoded = out.getWritten();
    var in = buffer.fixedReader(encoded);
    const parsed = try decodeFrame(in.reader(), std.testing.allocator);

    switch (parsed) {
        .max_data => |frame| {
            try std.testing.expectEqual(@as(u64, 1_000_000), frame.maximum_data);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "encode/decode stop_sending frame roundtrip" {
    var buf: [128]u8 = undefined;
    var out = buffer.fixedWriter(&buf);

    const input = Frame{ .stop_sending = .{
        .stream_id = 9,
        .application_error_code = 0x2a,
    } };
    try encodeFrame(out.writer(), input);

    const encoded = out.getWritten();
    var in = buffer.fixedReader(encoded);
    const parsed = try decodeFrame(in.reader(), std.testing.allocator);

    switch (parsed) {
        .stop_sending => |frame| {
            try std.testing.expectEqual(@as(u64, 9), frame.stream_id);
            try std.testing.expectEqual(@as(u64, 0x2a), frame.application_error_code);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "encode/decode max_stream_data frame roundtrip" {
    var buf: [128]u8 = undefined;
    var out = buffer.fixedWriter(&buf);

    const input = Frame{ .max_stream_data = .{
        .stream_id = 5,
        .maximum_stream_data = 65_535,
    } };
    try encodeFrame(out.writer(), input);

    const encoded = out.getWritten();
    var in = buffer.fixedReader(encoded);
    const parsed = try decodeFrame(in.reader(), std.testing.allocator);

    switch (parsed) {
        .max_stream_data => |frame| {
            try std.testing.expectEqual(@as(u64, 5), frame.stream_id);
            try std.testing.expectEqual(@as(u64, 65_535), frame.maximum_stream_data);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "encode/decode max_streams_bidi frame roundtrip" {
    var buf: [64]u8 = undefined;
    var out = buffer.fixedWriter(&buf);

    const input = Frame{ .max_streams_bidi = .{
        .maximum_streams = 24,
    } };
    try encodeFrame(out.writer(), input);

    const encoded = out.getWritten();
    var in = buffer.fixedReader(encoded);
    const parsed = try decodeFrame(in.reader(), std.testing.allocator);

    switch (parsed) {
        .max_streams_bidi => |frame| {
            try std.testing.expectEqual(@as(u64, 24), frame.maximum_streams);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "encode/decode max_streams_uni frame roundtrip" {
    var buf: [64]u8 = undefined;
    var out = buffer.fixedWriter(&buf);

    const input = Frame{ .max_streams_uni = .{
        .maximum_streams = 40,
    } };
    try encodeFrame(out.writer(), input);

    const encoded = out.getWritten();
    var in = buffer.fixedReader(encoded);
    const parsed = try decodeFrame(in.reader(), std.testing.allocator);

    switch (parsed) {
        .max_streams_uni => |frame| {
            try std.testing.expectEqual(@as(u64, 40), frame.maximum_streams);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "stream frame without LEN bit fails" {
    const wire = [_]u8{
        0x08,
        0x01,
    };

    var in = buffer.fixedReader(&wire);
    try std.testing.expectError(error.InvalidFrameLength, decodeFrame(in.reader(), std.testing.allocator));
}

test "stream frame with truncated payload fails" {
    const wire = [_]u8{
        0x0a, // STREAM with LEN bit
        0x01, // stream id
        0x03, // declared length
        0xaa, 0xbb, // truncated data
    };

    var in = buffer.fixedReader(&wire);
    try std.testing.expectError(error.EndOfStream, decodeFrame(in.reader(), std.testing.allocator));
}

test "encode/decode connection_close frame roundtrip" {
    var buf: [256]u8 = undefined;
    var out = buffer.fixedWriter(&buf);

    const input = Frame{ .connection_close = .{
        .error_code = 0x0a,
        .frame_type = @intFromEnum(FrameType.stream),
        .reason_phrase = "flow control violation",
    } };
    try encodeFrame(out.writer(), input);

    const encoded = out.getWritten();
    var in = buffer.fixedReader(encoded);
    var parsed = try decodeFrame(in.reader(), std.testing.allocator);
    defer deinitFrame(&parsed, std.testing.allocator);

    switch (parsed) {
        .connection_close => |frame| {
            try std.testing.expectEqual(@as(u64, 0x0a), frame.error_code);
            try std.testing.expectEqual(@as(u64, @intFromEnum(FrameType.stream)), frame.frame_type);
            try std.testing.expectEqualStrings("flow control violation", frame.reason_phrase);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "encode/decode application_close frame roundtrip" {
    var buf: [256]u8 = undefined;
    var out = buffer.fixedWriter(&buf);

    const input = Frame{ .application_close = .{
        .error_code = 0x1337,
        .reason_phrase = "app shutdown",
    } };
    try encodeFrame(out.writer(), input);

    const encoded = out.getWritten();
    var in = buffer.fixedReader(encoded);
    var parsed = try decodeFrame(in.reader(), std.testing.allocator);
    defer deinitFrame(&parsed, std.testing.allocator);

    switch (parsed) {
        .application_close => |frame| {
            try std.testing.expectEqual(@as(u64, 0x1337), frame.error_code);
            try std.testing.expectEqualStrings("app shutdown", frame.reason_phrase);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "connection close with truncated reason fails" {
    const wire = [_]u8{
        @intFromEnum(FrameType.connection_close),
        0x01, // error code
        @intFromEnum(FrameType.stream),
        0x04, // reason length
        'n',
        'o',
    };

    var in = buffer.fixedReader(&wire);
    try std.testing.expectError(error.EndOfStream, decodeFrame(in.reader(), std.testing.allocator));
}
