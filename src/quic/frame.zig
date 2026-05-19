const std = @import("std");
const buffer = @import("buffer.zig");
const packet = @import("packet.zig");

const max_quic_varint: u64 = (@as(u64, 1) << 62) - 1;
const max_stream_count: u64 = @as(u64, 1) << 60;

/// Basic subset of QUIC frames (RFC 9000 Section 19).
pub const FrameType = enum(u8) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    ack_ecn = 0x03,
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
    handshake_done = 0x1e,
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

/// NEW_TOKEN frame carrying an address validation token for future connections.
pub const NewTokenFrame = struct {
    /// Opaque token bytes. QUIC NEW_TOKEN frames require a non-empty token.
    token: []const u8,
};

/// One additional ACK range after `first_ack_range`.
///
/// `gap` is the encoded count of missing packets between ranges, and
/// `ack_range` is the encoded length of the acknowledged range.
pub const AckRange = struct {
    gap: u64,
    ack_range: u64,
};

/// ACK frame model. `ranges` contains additional ranges ordered from largest to
/// smallest packet numbers, matching the QUIC ACK frame wire order.
pub const AckFrame = struct {
    largest_acknowledged: u64,
    ack_delay: u64,
    first_ack_range: u64,
    ranges: []const AckRange = &[_]AckRange{},
};

/// ECN counters carried by an ACK_ECN frame.
pub const EcnCounts = struct {
    ect0_count: u64,
    ect1_count: u64,
    ecn_ce_count: u64,
};

/// ACK_ECN frame model: an ACK frame plus ECN validation counters.
pub const AckEcnFrame = struct {
    ack: AckFrame,
    ecn_counts: EcnCounts,
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

/// DATA_BLOCKED frame reporting the connection data limit that blocked sending.
pub const DataBlockedFrame = struct {
    maximum_data: u64,
};

/// STREAM_DATA_BLOCKED frame reporting the stream data limit that blocked sending.
pub const StreamDataBlockedFrame = struct {
    stream_id: u64,
    maximum_stream_data: u64,
};

/// STREAMS_BLOCKED frame for bidirectional stream-count credit exhaustion.
pub const StreamsBlockedBidiFrame = struct {
    maximum_streams: u64,
};

/// STREAMS_BLOCKED frame for unidirectional stream-count credit exhaustion.
pub const StreamsBlockedUniFrame = struct {
    maximum_streams: u64,
};

/// NEW_CONNECTION_ID frame advertising a replacement connection ID.
pub const NewConnectionIdFrame = struct {
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: []const u8,
    stateless_reset_token: [16]u8,
};

/// RETIRE_CONNECTION_ID frame asking the peer to retire a connection ID.
pub const RetireConnectionIdFrame = struct {
    sequence_number: u64,
};

/// PATH_CHALLENGE frame carrying 8 bytes of path validation data.
pub const PathChallengeFrame = struct {
    data: [8]u8,
};

/// PATH_RESPONSE frame echoing 8 bytes from a received path challenge.
pub const PathResponseFrame = struct {
    data: [8]u8,
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
    ack_ecn: AckEcnFrame,
    reset_stream: ResetStreamFrame,
    stop_sending: StopSendingFrame,
    new_token: NewTokenFrame,
    stream: StreamFrame,
    crypto: CryptoFrame,
    max_data: MaxDataFrame,
    max_stream_data: MaxStreamDataFrame,
    max_streams_bidi: MaxStreamsBidiFrame,
    max_streams_uni: MaxStreamsUniFrame,
    data_blocked: DataBlockedFrame,
    stream_data_blocked: StreamDataBlockedFrame,
    streams_blocked_bidi: StreamsBlockedBidiFrame,
    streams_blocked_uni: StreamsBlockedUniFrame,
    new_connection_id: NewConnectionIdFrame,
    retire_connection_id: RetireConnectionIdFrame,
    path_challenge: PathChallengeFrame,
    path_response: PathResponseFrame,
    connection_close: ConnectionCloseFrame,
    application_close: ApplicationCloseFrame,
    handshake_done: void,
};

pub const FrameError = error{
    UnsupportedFrameType,
    InvalidAckRange,
    InvalidPaddingLength,
    InvalidConnectionIdLength,
    InvalidFrameLength,
    InvalidFrameValue,
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

fn readerHasRemainingLen(comptime Reader: type) bool {
    return switch (@typeInfo(Reader)) {
        .pointer => |pointer| @hasDecl(pointer.child, "remainingLen"),
        else => @hasDecl(Reader, "remainingLen"),
    };
}

fn validateAckRangeCountFitsReader(reader: anytype, range_count: usize) FrameError!void {
    if (comptime readerHasRemainingLen(@TypeOf(reader))) {
        const min_range_bytes = std.math.mul(usize, range_count, 2) catch return error.InvalidFrameLength;
        if (min_range_bytes > reader.remainingLen()) return error.InvalidFrameLength;
    }
}

fn validateConnectionIdLen(len: usize) FrameError!void {
    if (len == 0 or len > 20) return error.InvalidConnectionIdLength;
}

fn validateNewConnectionIdFrame(new_connection_id: NewConnectionIdFrame) FrameError!void {
    try validateConnectionIdLen(new_connection_id.connection_id.len);
    if (new_connection_id.retire_prior_to > new_connection_id.sequence_number) {
        return error.InvalidFrameValue;
    }
}

fn validateNewTokenFrame(new_token: NewTokenFrame) FrameError!void {
    if (new_token.token.len == 0) return error.InvalidFrameValue;
}

fn validateStreamCount(maximum_streams: u64) FrameError!void {
    if (maximum_streams > max_stream_count) return error.InvalidFrameValue;
}

fn validateFrameEndOffset(offset: u64, data_len: u64) FrameError!void {
    const end_offset = std.math.add(u64, offset, data_len) catch return error.InvalidFrameValue;
    if (end_offset > max_quic_varint) return error.InvalidFrameValue;
}

fn validateFrameSliceEndOffset(offset: u64, data: []const u8) FrameError!void {
    const data_len = std.math.cast(u64, data.len) orelse return error.InvalidFrameLength;
    try validateFrameEndOffset(offset, data_len);
}

fn validateFrameEndOffsetFromLen(offset: u64, data_len: usize) FrameError!void {
    const data_len_u64 = std.math.cast(u64, data_len) orelse return error.InvalidFrameLength;
    try validateFrameEndOffset(offset, data_len_u64);
}

/// Release any buffers owned by a decoded frame.
pub fn deinitFrame(frame: *Frame, allocator: std.mem.Allocator) void {
    switch (frame.*) {
        .ack => |ack| deinitAckFrame(ack, allocator),
        .ack_ecn => |ack_ecn| deinitAckFrame(ack_ecn.ack, allocator),
        .stream => |stream| allocator.free(stream.data),
        .crypto => |crypto| allocator.free(crypto.data),
        .new_token => |new_token| allocator.free(new_token.token),
        .new_connection_id => |new_connection_id| allocator.free(new_connection_id.connection_id),
        .connection_close => |close| allocator.free(close.reason_phrase),
        .application_close => |close| allocator.free(close.reason_phrase),
        else => {},
    }
}

fn validateAckFrame(ack: AckFrame) FrameError!void {
    if (ack.first_ack_range > ack.largest_acknowledged) return error.InvalidAckRange;

    var smallest = ack.largest_acknowledged - ack.first_ack_range;
    for (ack.ranges) |range| {
        const skipped = std.math.add(u64, range.gap, 2) catch return error.InvalidAckRange;
        if (smallest < skipped) return error.InvalidAckRange;
        const range_largest = smallest - skipped;
        if (range.ack_range > range_largest) return error.InvalidAckRange;
        smallest = range_largest - range.ack_range;
    }
}

fn deinitAckFrame(ack: AckFrame, allocator: std.mem.Allocator) void {
    if (ack.ranges.len != 0) allocator.free(ack.ranges);
}

fn encodeAckFrameFields(writer: anytype, ack: AckFrame) !void {
    try validateAckFrame(ack);

    try packet.encodeVarInt(writer, ack.largest_acknowledged);
    try packet.encodeVarInt(writer, ack.ack_delay);
    try packet.encodeVarInt(writer, ack.ranges.len);
    try packet.encodeVarInt(writer, ack.first_ack_range);
    for (ack.ranges) |range| {
        try packet.encodeVarInt(writer, range.gap);
        try packet.encodeVarInt(writer, range.ack_range);
    }
}

fn decodeAckFrameFields(reader: anytype, allocator: std.mem.Allocator) !AckFrame {
    const largest_acknowledged = (try packet.decodeVarInt(reader)).value;
    const ack_delay = (try packet.decodeVarInt(reader)).value;
    const ack_range_count = (try packet.decodeVarInt(reader)).value;
    const first_ack_range = (try packet.decodeVarInt(reader)).value;

    const range_count = try varIntToUsize(ack_range_count);
    try validateAckRangeCountFitsReader(reader, range_count);
    const ranges = try allocator.alloc(AckRange, range_count);
    errdefer if (ranges.len != 0) allocator.free(ranges);

    for (ranges) |*range| {
        range.* = .{
            .gap = (try packet.decodeVarInt(reader)).value,
            .ack_range = (try packet.decodeVarInt(reader)).value,
        };
    }

    const ack = AckFrame{
        .largest_acknowledged = largest_acknowledged,
        .ack_delay = ack_delay,
        .first_ack_range = first_ack_range,
        .ranges = ranges,
    };
    try validateAckFrame(ack);

    return ack;
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
            try encodeAckFrameFields(writer, ack);
        },
        .ack_ecn => |ack_ecn| {
            try writer.writeByte(@intFromEnum(FrameType.ack_ecn));
            try encodeAckFrameFields(writer, ack_ecn.ack);
            try packet.encodeVarInt(writer, ack_ecn.ecn_counts.ect0_count);
            try packet.encodeVarInt(writer, ack_ecn.ecn_counts.ect1_count);
            try packet.encodeVarInt(writer, ack_ecn.ecn_counts.ecn_ce_count);
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
        .new_token => |new_token| {
            try validateNewTokenFrame(new_token);

            try writer.writeByte(@intFromEnum(FrameType.new_token));
            try packet.encodeVarInt(writer, new_token.token.len);
            try writer.writeAll(new_token.token);
        },
        .stream => |stream| {
            try validateFrameSliceEndOffset(stream.offset, stream.data);

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
            try validateFrameSliceEndOffset(crypto.offset, crypto.data);

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
            try validateStreamCount(max_streams.maximum_streams);
            try writer.writeByte(@intFromEnum(FrameType.max_streams_bidi));
            try packet.encodeVarInt(writer, max_streams.maximum_streams);
        },
        .max_streams_uni => |max_streams| {
            try validateStreamCount(max_streams.maximum_streams);
            try writer.writeByte(@intFromEnum(FrameType.max_streams_uni));
            try packet.encodeVarInt(writer, max_streams.maximum_streams);
        },
        .data_blocked => |data_blocked| {
            try writer.writeByte(@intFromEnum(FrameType.data_blocked));
            try packet.encodeVarInt(writer, data_blocked.maximum_data);
        },
        .stream_data_blocked => |stream_data_blocked| {
            try writer.writeByte(@intFromEnum(FrameType.stream_data_blocked));
            try packet.encodeVarInt(writer, stream_data_blocked.stream_id);
            try packet.encodeVarInt(writer, stream_data_blocked.maximum_stream_data);
        },
        .streams_blocked_bidi => |streams_blocked| {
            try validateStreamCount(streams_blocked.maximum_streams);
            try writer.writeByte(@intFromEnum(FrameType.streams_blocked_bidi));
            try packet.encodeVarInt(writer, streams_blocked.maximum_streams);
        },
        .streams_blocked_uni => |streams_blocked| {
            try validateStreamCount(streams_blocked.maximum_streams);
            try writer.writeByte(@intFromEnum(FrameType.streams_blocked_uni));
            try packet.encodeVarInt(writer, streams_blocked.maximum_streams);
        },
        .new_connection_id => |new_connection_id| {
            try validateNewConnectionIdFrame(new_connection_id);

            try writer.writeByte(@intFromEnum(FrameType.new_connection_id));
            try packet.encodeVarInt(writer, new_connection_id.sequence_number);
            try packet.encodeVarInt(writer, new_connection_id.retire_prior_to);
            try writer.writeByte(@as(u8, @intCast(new_connection_id.connection_id.len)));
            try writer.writeAll(new_connection_id.connection_id);
            try writer.writeAll(&new_connection_id.stateless_reset_token);
        },
        .retire_connection_id => |retire_connection_id| {
            try writer.writeByte(@intFromEnum(FrameType.retire_connection_id));
            try packet.encodeVarInt(writer, retire_connection_id.sequence_number);
        },
        .path_challenge => |path_challenge| {
            try writer.writeByte(@intFromEnum(FrameType.path_challenge));
            try writer.writeAll(&path_challenge.data);
        },
        .path_response => |path_response| {
            try writer.writeByte(@intFromEnum(FrameType.path_response));
            try writer.writeAll(&path_response.data);
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
        .handshake_done => {
            try writer.writeByte(@intFromEnum(FrameType.handshake_done));
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

/// Decode one minimal QUIC frame from `reader`. STREAM frames without a Length
/// field require a reader that exposes `remainingLen()` so the decoder can
/// consume the rest of the packet payload.
pub fn decodeFrame(reader: anytype, allocator: std.mem.Allocator) !Frame {
    const frame_type = try reader.readByte();

    if (frame_type == @intFromEnum(FrameType.padding)) {
        return .{ .padding = .{ .len = 1 } };
    }

    if (frame_type == @intFromEnum(FrameType.ping)) {
        return .{ .ping = {} };
    }

    if (frame_type == @intFromEnum(FrameType.ack) or frame_type == @intFromEnum(FrameType.ack_ecn)) {
        const ack = try decodeAckFrameFields(reader, allocator);
        errdefer deinitAckFrame(ack, allocator);

        if (frame_type == @intFromEnum(FrameType.ack_ecn)) {
            return .{ .ack_ecn = .{
                .ack = ack,
                .ecn_counts = .{
                    .ect0_count = (try packet.decodeVarInt(reader)).value,
                    .ect1_count = (try packet.decodeVarInt(reader)).value,
                    .ecn_ce_count = (try packet.decodeVarInt(reader)).value,
                },
            } };
        }
        return .{ .ack = ack };
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

    if (frame_type == @intFromEnum(FrameType.new_token)) {
        const token_len = (try packet.decodeVarInt(reader)).value;
        const len_usize = try varIntToUsize(token_len);
        if (len_usize == 0) return error.InvalidFrameValue;
        const token = try buffer.readOwnedBytes(reader, allocator, len_usize);

        return .{ .new_token = .{ .token = token } };
    }

    if (frame_type == @intFromEnum(FrameType.crypto)) {
        const offset = (try packet.decodeVarInt(reader)).value;
        const data_len = (try packet.decodeVarInt(reader)).value;
        try validateFrameEndOffset(offset, data_len);
        const len_usize = try varIntToUsize(data_len);

        const data = try buffer.readOwnedBytes(reader, allocator, len_usize);

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
        try validateStreamCount(maximum_streams);
        return .{ .max_streams_bidi = .{ .maximum_streams = maximum_streams } };
    }

    if (frame_type == @intFromEnum(FrameType.max_streams_uni)) {
        const maximum_streams = (try packet.decodeVarInt(reader)).value;
        try validateStreamCount(maximum_streams);
        return .{ .max_streams_uni = .{ .maximum_streams = maximum_streams } };
    }

    if (frame_type == @intFromEnum(FrameType.data_blocked)) {
        const maximum_data = (try packet.decodeVarInt(reader)).value;
        return .{ .data_blocked = .{ .maximum_data = maximum_data } };
    }

    if (frame_type == @intFromEnum(FrameType.stream_data_blocked)) {
        const stream_id = (try packet.decodeVarInt(reader)).value;
        const maximum_stream_data = (try packet.decodeVarInt(reader)).value;
        return .{ .stream_data_blocked = .{
            .stream_id = stream_id,
            .maximum_stream_data = maximum_stream_data,
        } };
    }

    if (frame_type == @intFromEnum(FrameType.streams_blocked_bidi)) {
        const maximum_streams = (try packet.decodeVarInt(reader)).value;
        try validateStreamCount(maximum_streams);
        return .{ .streams_blocked_bidi = .{ .maximum_streams = maximum_streams } };
    }

    if (frame_type == @intFromEnum(FrameType.streams_blocked_uni)) {
        const maximum_streams = (try packet.decodeVarInt(reader)).value;
        try validateStreamCount(maximum_streams);
        return .{ .streams_blocked_uni = .{ .maximum_streams = maximum_streams } };
    }

    if (frame_type == @intFromEnum(FrameType.new_connection_id)) {
        const sequence_number = (try packet.decodeVarInt(reader)).value;
        const retire_prior_to = (try packet.decodeVarInt(reader)).value;
        const connection_id_len = try reader.readByte();
        try validateConnectionIdLen(connection_id_len);
        if (retire_prior_to > sequence_number) return error.InvalidFrameValue;

        const connection_id = try buffer.readOwnedBytes(reader, allocator, connection_id_len);
        errdefer allocator.free(connection_id);

        var stateless_reset_token: [16]u8 = undefined;
        try reader.readNoEof(&stateless_reset_token);

        const new_connection_id = NewConnectionIdFrame{
            .sequence_number = sequence_number,
            .retire_prior_to = retire_prior_to,
            .connection_id = connection_id,
            .stateless_reset_token = stateless_reset_token,
        };

        return .{ .new_connection_id = new_connection_id };
    }

    if (frame_type == @intFromEnum(FrameType.retire_connection_id)) {
        const sequence_number = (try packet.decodeVarInt(reader)).value;
        return .{ .retire_connection_id = .{ .sequence_number = sequence_number } };
    }

    if (frame_type == @intFromEnum(FrameType.path_challenge)) {
        var data: [8]u8 = undefined;
        try reader.readNoEof(&data);
        return .{ .path_challenge = .{ .data = data } };
    }

    if (frame_type == @intFromEnum(FrameType.path_response)) {
        var data: [8]u8 = undefined;
        try reader.readNoEof(&data);
        return .{ .path_response = .{ .data = data } };
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

        const len_usize = if (has_len) blk: {
            const data_len = (try packet.decodeVarInt(reader)).value;
            try validateFrameEndOffset(offset, data_len);
            break :blk try varIntToUsize(data_len);
        } else blk: {
            if (comptime readerHasRemainingLen(@TypeOf(reader))) {
                const data_len = reader.remainingLen();
                try validateFrameEndOffsetFromLen(offset, data_len);
                break :blk data_len;
            }
            return error.InvalidFrameLength;
        };

        const data = try buffer.readOwnedBytes(reader, allocator, len_usize);

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

        const reason_phrase = try buffer.readOwnedBytes(reader, allocator, len_usize);

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

        const reason_phrase = try buffer.readOwnedBytes(reader, allocator, len_usize);

        return .{ .application_close = .{
            .error_code = error_code,
            .reason_phrase = reason_phrase,
        } };
    }

    if (frame_type == @intFromEnum(FrameType.handshake_done)) {
        return .{ .handshake_done = {} };
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

test "stream and crypto frames reject end offsets above varint maximum" {
    var encode_buf: [64]u8 = undefined;
    var encode_out = buffer.fixedWriter(&encode_buf);
    try std.testing.expectError(error.InvalidFrameValue, encodeFrame(encode_out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = max_quic_varint,
        .fin = false,
        .data = "x",
    } }));

    encode_out = buffer.fixedWriter(&encode_buf);
    try std.testing.expectError(error.InvalidFrameValue, encodeFrame(encode_out.writer(), .{ .crypto = .{
        .offset = max_quic_varint,
        .data = "x",
    } }));

    var stream_wire: [32]u8 = undefined;
    var stream_out = buffer.fixedWriter(&stream_wire);
    try stream_out.writeByte(0x0e); // STREAM with OFF and LEN bits
    try packet.encodeVarInt(stream_out.writer(), 0);
    try packet.encodeVarInt(stream_out.writer(), max_quic_varint);
    try packet.encodeVarInt(stream_out.writer(), 1);
    try stream_out.writeByte('x');
    var stream_in = buffer.fixedReader(stream_out.getWritten());
    try std.testing.expectError(error.InvalidFrameValue, decodeFrame(stream_in.reader(), std.testing.allocator));

    var crypto_wire: [32]u8 = undefined;
    var crypto_out = buffer.fixedWriter(&crypto_wire);
    try crypto_out.writeByte(@intFromEnum(FrameType.crypto));
    try packet.encodeVarInt(crypto_out.writer(), max_quic_varint);
    try packet.encodeVarInt(crypto_out.writer(), 1);
    try crypto_out.writeByte('x');
    var crypto_in = buffer.fixedReader(crypto_out.getWritten());
    try std.testing.expectError(error.InvalidFrameValue, decodeFrame(crypto_in.reader(), std.testing.allocator));
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
    var parsed = try decodeFrame(in.reader(), std.testing.allocator);
    defer deinitFrame(&parsed, std.testing.allocator);

    switch (parsed) {
        .ack => |frame| {
            try std.testing.expectEqual(@as(u64, 12345), frame.largest_acknowledged);
            try std.testing.expectEqual(@as(u64, 42), frame.ack_delay);
            try std.testing.expectEqual(@as(u64, 7), frame.first_ack_range);
            try std.testing.expectEqual(@as(usize, 0), frame.ranges.len);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "encode/decode ack frame with additional ranges" {
    const ranges = [_]AckRange{
        .{ .gap = 1, .ack_range = 1 },
    };

    var buf: [128]u8 = undefined;
    var out = buffer.fixedWriter(&buf);
    try encodeFrame(out.writer(), .{ .ack = .{
        .largest_acknowledged = 10,
        .ack_delay = 3,
        .first_ack_range = 2,
        .ranges = &ranges,
    } });

    var in = buffer.fixedReader(out.getWritten());
    var parsed = try decodeFrame(in.reader(), std.testing.allocator);
    defer deinitFrame(&parsed, std.testing.allocator);

    switch (parsed) {
        .ack => |frame| {
            try std.testing.expectEqual(@as(u64, 10), frame.largest_acknowledged);
            try std.testing.expectEqual(@as(u64, 3), frame.ack_delay);
            try std.testing.expectEqual(@as(u64, 2), frame.first_ack_range);
            try std.testing.expectEqual(@as(usize, 1), frame.ranges.len);
            try std.testing.expectEqual(@as(u64, 1), frame.ranges[0].gap);
            try std.testing.expectEqual(@as(u64, 1), frame.ranges[0].ack_range);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "encode/decode ack_ecn frame roundtrip" {
    const ranges = [_]AckRange{
        .{ .gap = 0, .ack_range = 1 },
    };

    var buf: [128]u8 = undefined;
    var out = buffer.fixedWriter(&buf);
    try encodeFrame(out.writer(), .{ .ack_ecn = .{
        .ack = .{
            .largest_acknowledged = 8,
            .ack_delay = 2,
            .first_ack_range = 0,
            .ranges = &ranges,
        },
        .ecn_counts = .{
            .ect0_count = 11,
            .ect1_count = 12,
            .ecn_ce_count = 13,
        },
    } });

    var in = buffer.fixedReader(out.getWritten());
    var parsed = try decodeFrame(in.reader(), std.testing.allocator);
    defer deinitFrame(&parsed, std.testing.allocator);

    switch (parsed) {
        .ack_ecn => |frame| {
            try std.testing.expectEqual(@as(u64, 8), frame.ack.largest_acknowledged);
            try std.testing.expectEqual(@as(u64, 2), frame.ack.ack_delay);
            try std.testing.expectEqual(@as(u64, 0), frame.ack.first_ack_range);
            try std.testing.expectEqual(@as(usize, 1), frame.ack.ranges.len);
            try std.testing.expectEqual(@as(u64, 0), frame.ack.ranges[0].gap);
            try std.testing.expectEqual(@as(u64, 1), frame.ack.ranges[0].ack_range);
            try std.testing.expectEqual(@as(u64, 11), frame.ecn_counts.ect0_count);
            try std.testing.expectEqual(@as(u64, 12), frame.ecn_counts.ect1_count);
            try std.testing.expectEqual(@as(u64, 13), frame.ecn_counts.ecn_ce_count);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "ack_ecn with truncated ecn counts frees decoded ranges" {
    const wire = [_]u8{
        @intFromEnum(FrameType.ack_ecn),
        0x08, // largest acknowledged
        0x00, // ack delay
        0x01, // one additional ACK range
        0x00, // first ACK range
        0x00, // gap
        0x00, // ack range
        0x01, // ECT(0), missing ECT(1) and CE counts
    };

    var in = buffer.fixedReader(&wire);
    try std.testing.expectError(error.EndOfStream, decodeFrame(in.reader(), std.testing.allocator));
}

test "ack frame additional ranges must not underflow packet numbers" {
    const ranges = [_]AckRange{
        .{ .gap = 0, .ack_range = 0 },
    };

    var out_buf: [16]u8 = undefined;
    var out = buffer.fixedWriter(&out_buf);
    try std.testing.expectError(error.InvalidAckRange, encodeFrame(out.writer(), .{ .ack = .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    } }));

    const wire = [_]u8{
        @intFromEnum(FrameType.ack),
        0x00, // largest acknowledged
        0x00, // ack delay
        0x01, // one additional ACK range
        0x00, // first ACK range
        0x00, // gap underflows below packet number 0
        0x00, // ack range
    };

    var in = buffer.fixedReader(&wire);
    try std.testing.expectError(error.InvalidAckRange, decodeFrame(in.reader(), std.testing.allocator));
}

test "ack frame range count must fit remaining payload before allocation" {
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const wire = [_]u8{
        @intFromEnum(FrameType.ack),
        0x00, // largest acknowledged
        0x00, // ack delay
        0x01, // one additional ACK range
        0x00, // first ACK range
    };

    try std.testing.expectError(
        error.InvalidFrameLength,
        decodeFrameSlice(&wire, failing_allocator.allocator()),
    );
}

test "ack frame first range cannot exceed largest acknowledged" {
    var out_buf: [16]u8 = undefined;
    var out = buffer.fixedWriter(&out_buf);
    try std.testing.expectError(error.InvalidAckRange, encodeFrame(out.writer(), .{ .ack = .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 1,
    } }));

    const wire = [_]u8{
        @intFromEnum(FrameType.ack),
        0x00, // largest acknowledged
        0x00, // ack delay
        0x00, // no additional ACK ranges
        0x01, // first ACK range larger than largest acknowledged
    };

    var in = buffer.fixedReader(&wire);
    try std.testing.expectError(error.InvalidAckRange, decodeFrame(in.reader(), std.testing.allocator));
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

test "encode/decode new_token frame roundtrip" {
    var buf: [128]u8 = undefined;
    var out = buffer.fixedWriter(&buf);

    const input = Frame{ .new_token = .{
        .token = "future-address-token",
    } };
    try encodeFrame(out.writer(), input);

    const encoded = out.getWritten();
    var in = buffer.fixedReader(encoded);
    var parsed = try decodeFrame(in.reader(), std.testing.allocator);
    defer deinitFrame(&parsed, std.testing.allocator);

    switch (parsed) {
        .new_token => |frame| try std.testing.expectEqualStrings("future-address-token", frame.token),
        else => return error.TestUnexpectedResult,
    }
}

test "new_token frame rejects empty token" {
    var buf: [8]u8 = undefined;
    var out = buffer.fixedWriter(&buf);
    try std.testing.expectError(error.InvalidFrameValue, encodeFrame(out.writer(), .{ .new_token = .{ .token = "" } }));

    const wire = [_]u8{
        @intFromEnum(FrameType.new_token),
        0x00, // invalid empty token length
    };
    var in = buffer.fixedReader(&wire);
    try std.testing.expectError(error.InvalidFrameValue, decodeFrame(in.reader(), std.testing.allocator));
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

test "stream count frames reject values above max stream count" {
    var encode_buf: [16]u8 = undefined;
    var encode_out = buffer.fixedWriter(&encode_buf);
    try std.testing.expectError(error.InvalidFrameValue, encodeFrame(encode_out.writer(), .{
        .max_streams_bidi = .{ .maximum_streams = max_stream_count + 1 },
    }));

    encode_out = buffer.fixedWriter(&encode_buf);
    try std.testing.expectError(error.InvalidFrameValue, encodeFrame(encode_out.writer(), .{
        .streams_blocked_uni = .{ .maximum_streams = max_stream_count + 1 },
    }));

    var max_streams_wire: [16]u8 = undefined;
    var max_streams_out = buffer.fixedWriter(&max_streams_wire);
    try max_streams_out.writeByte(@intFromEnum(FrameType.max_streams_uni));
    try packet.encodeVarInt(max_streams_out.writer(), max_stream_count + 1);
    var max_streams_in = buffer.fixedReader(max_streams_out.getWritten());
    try std.testing.expectError(error.InvalidFrameValue, decodeFrame(max_streams_in.reader(), std.testing.allocator));

    var streams_blocked_wire: [16]u8 = undefined;
    var streams_blocked_out = buffer.fixedWriter(&streams_blocked_wire);
    try streams_blocked_out.writeByte(@intFromEnum(FrameType.streams_blocked_bidi));
    try packet.encodeVarInt(streams_blocked_out.writer(), max_stream_count + 1);
    var streams_blocked_in = buffer.fixedReader(streams_blocked_out.getWritten());
    try std.testing.expectError(error.InvalidFrameValue, decodeFrame(streams_blocked_in.reader(), std.testing.allocator));
}

test "encode/decode blocked flow-control frames roundtrip" {
    var data_buf: [64]u8 = undefined;
    var data_out = buffer.fixedWriter(&data_buf);
    try encodeFrame(data_out.writer(), .{ .data_blocked = .{ .maximum_data = 4096 } });

    var data_in = buffer.fixedReader(data_out.getWritten());
    const data_blocked = try decodeFrame(data_in.reader(), std.testing.allocator);
    switch (data_blocked) {
        .data_blocked => |frame| try std.testing.expectEqual(@as(u64, 4096), frame.maximum_data),
        else => return error.TestUnexpectedResult,
    }

    var stream_buf: [64]u8 = undefined;
    var stream_out = buffer.fixedWriter(&stream_buf);
    try encodeFrame(stream_out.writer(), .{ .stream_data_blocked = .{
        .stream_id = 5,
        .maximum_stream_data = 2048,
    } });

    var stream_in = buffer.fixedReader(stream_out.getWritten());
    const stream_blocked = try decodeFrame(stream_in.reader(), std.testing.allocator);
    switch (stream_blocked) {
        .stream_data_blocked => |frame| {
            try std.testing.expectEqual(@as(u64, 5), frame.stream_id);
            try std.testing.expectEqual(@as(u64, 2048), frame.maximum_stream_data);
        },
        else => return error.TestUnexpectedResult,
    }

    var bidi_buf: [64]u8 = undefined;
    var bidi_out = buffer.fixedWriter(&bidi_buf);
    try encodeFrame(bidi_out.writer(), .{ .streams_blocked_bidi = .{ .maximum_streams = 3 } });

    var bidi_in = buffer.fixedReader(bidi_out.getWritten());
    const bidi_blocked = try decodeFrame(bidi_in.reader(), std.testing.allocator);
    switch (bidi_blocked) {
        .streams_blocked_bidi => |frame| try std.testing.expectEqual(@as(u64, 3), frame.maximum_streams),
        else => return error.TestUnexpectedResult,
    }

    var uni_buf: [64]u8 = undefined;
    var uni_out = buffer.fixedWriter(&uni_buf);
    try encodeFrame(uni_out.writer(), .{ .streams_blocked_uni = .{ .maximum_streams = 4 } });

    var uni_in = buffer.fixedReader(uni_out.getWritten());
    const uni_blocked = try decodeFrame(uni_in.reader(), std.testing.allocator);
    switch (uni_blocked) {
        .streams_blocked_uni => |frame| try std.testing.expectEqual(@as(u64, 4), frame.maximum_streams),
        else => return error.TestUnexpectedResult,
    }
}

test "encode/decode path validation frames roundtrip" {
    const payload = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };

    var challenge_buf: [16]u8 = undefined;
    var challenge_out = buffer.fixedWriter(&challenge_buf);
    try encodeFrame(challenge_out.writer(), .{ .path_challenge = .{ .data = payload } });

    var challenge_in = buffer.fixedReader(challenge_out.getWritten());
    const challenge = try decodeFrame(challenge_in.reader(), std.testing.allocator);
    switch (challenge) {
        .path_challenge => |frame| try std.testing.expectEqualSlices(u8, &payload, &frame.data),
        else => return error.TestUnexpectedResult,
    }

    var response_buf: [16]u8 = undefined;
    var response_out = buffer.fixedWriter(&response_buf);
    try encodeFrame(response_out.writer(), .{ .path_response = .{ .data = payload } });

    var response_in = buffer.fixedReader(response_out.getWritten());
    const response = try decodeFrame(response_in.reader(), std.testing.allocator);
    switch (response) {
        .path_response => |frame| try std.testing.expectEqualSlices(u8, &payload, &frame.data),
        else => return error.TestUnexpectedResult,
    }
}

test "encode/decode connection id management frames roundtrip" {
    const cid = [_]u8{ 0xca, 0xfe, 0xba, 0xbe };
    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

    var new_cid_buf: [64]u8 = undefined;
    var new_cid_out = buffer.fixedWriter(&new_cid_buf);
    try encodeFrame(new_cid_out.writer(), .{ .new_connection_id = .{
        .sequence_number = 7,
        .retire_prior_to = 3,
        .connection_id = &cid,
        .stateless_reset_token = token,
    } });

    var new_cid_in = buffer.fixedReader(new_cid_out.getWritten());
    var new_cid = try decodeFrame(new_cid_in.reader(), std.testing.allocator);
    defer deinitFrame(&new_cid, std.testing.allocator);
    switch (new_cid) {
        .new_connection_id => |frame| {
            try std.testing.expectEqual(@as(u64, 7), frame.sequence_number);
            try std.testing.expectEqual(@as(u64, 3), frame.retire_prior_to);
            try std.testing.expectEqualSlices(u8, &cid, frame.connection_id);
            try std.testing.expectEqualSlices(u8, &token, &frame.stateless_reset_token);
        },
        else => return error.TestUnexpectedResult,
    }

    var retire_buf: [16]u8 = undefined;
    var retire_out = buffer.fixedWriter(&retire_buf);
    try encodeFrame(retire_out.writer(), .{ .retire_connection_id = .{ .sequence_number = 7 } });

    var retire_in = buffer.fixedReader(retire_out.getWritten());
    const retire = try decodeFrame(retire_in.reader(), std.testing.allocator);
    switch (retire) {
        .retire_connection_id => |frame| try std.testing.expectEqual(@as(u64, 7), frame.sequence_number),
        else => return error.TestUnexpectedResult,
    }
}

test "new_connection_id validates cid length retire order and token length" {
    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

    var out_buf: [64]u8 = undefined;
    var out = buffer.fixedWriter(&out_buf);
    try std.testing.expectError(error.InvalidConnectionIdLength, encodeFrame(out.writer(), .{
        .new_connection_id = .{
            .sequence_number = 1,
            .retire_prior_to = 0,
            .connection_id = &[_]u8{},
            .stateless_reset_token = token,
        },
    }));

    out = buffer.fixedWriter(&out_buf);
    try std.testing.expectError(error.InvalidFrameValue, encodeFrame(out.writer(), .{
        .new_connection_id = .{
            .sequence_number = 1,
            .retire_prior_to = 2,
            .connection_id = &[_]u8{0xaa},
            .stateless_reset_token = token,
        },
    }));

    const zero_len_wire = [_]u8{
        @intFromEnum(FrameType.new_connection_id),
        0x01, // sequence number
        0x00, // retire prior to
        0x00, // invalid connection id length
    };
    var zero_len_in = buffer.fixedReader(&zero_len_wire);
    try std.testing.expectError(error.InvalidConnectionIdLength, decodeFrame(zero_len_in.reader(), std.testing.allocator));

    const bad_retire_wire = [_]u8{
        @intFromEnum(FrameType.new_connection_id),
        0x01, // sequence number
        0x02, // retire prior to exceeds sequence number
        0x01, // connection id length
        0xaa, // connection id
    } ++ token;
    var bad_retire_in = buffer.fixedReader(&bad_retire_wire);
    try std.testing.expectError(error.InvalidFrameValue, decodeFrame(bad_retire_in.reader(), std.testing.allocator));

    const truncated_token_wire = [_]u8{
        @intFromEnum(FrameType.new_connection_id),
        0x01, // sequence number
        0x00, // retire prior to
        0x01, // connection id length
        0xaa, // connection id
        0x00, 0x01, // truncated stateless reset token
    };
    var truncated_token_in = buffer.fixedReader(&truncated_token_wire);
    try std.testing.expectError(error.EndOfStream, decodeFrame(truncated_token_in.reader(), std.testing.allocator));
}

test "stream frame without LEN bit consumes remaining payload" {
    const wire = [_]u8{
        0x08, // STREAM without LEN bit
        0x01, // stream id
        'h',
        'i',
    };

    var in = buffer.fixedReader(&wire);
    var parsed = try decodeFrame(in.reader(), std.testing.allocator);
    defer deinitFrame(&parsed, std.testing.allocator);

    switch (parsed) {
        .stream => |frame| {
            try std.testing.expectEqual(@as(u64, 1), frame.stream_id);
            try std.testing.expectEqual(@as(u64, 0), frame.offset);
            try std.testing.expect(!frame.fin);
            try std.testing.expectEqualStrings("hi", frame.data);
            try std.testing.expectEqual(wire.len, in.pos);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "stream frame without LEN bit needs payload boundary" {
    const StreamingReader = struct {
        data: []const u8,
        pos: usize = 0,

        pub fn reader(self: *@This()) *@This() {
            return self;
        }

        pub fn readByte(self: *@This()) !u8 {
            if (self.pos >= self.data.len) return error.EndOfStream;
            const value = self.data[self.pos];
            self.pos += 1;
            return value;
        }

        pub fn readNoEof(self: *@This(), out: []u8) !void {
            if (self.data.len - self.pos < out.len) return error.EndOfStream;
            @memcpy(out, self.data[self.pos..][0..out.len]);
            self.pos += out.len;
        }
    };

    const wire = [_]u8{
        0x08, // STREAM without LEN bit
        0x01, // stream id
        'h',
    };

    var in = StreamingReader{ .data = &wire };
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

test "decodeFrameSlice rejects truncated payload before allocating" {
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const wire = [_]u8{
        0x0a, // STREAM with LEN bit
        0x00, // stream id
        0x40, 0x40, // declared length 64, no payload bytes left
    };

    try std.testing.expectError(error.EndOfStream, decodeFrameSlice(&wire, failing_allocator.allocator()));
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

test "encode/decode handshake_done frame roundtrip" {
    var buf: [8]u8 = undefined;
    var out = buffer.fixedWriter(&buf);

    try encodeFrame(out.writer(), .{ .handshake_done = {} });

    var in = buffer.fixedReader(out.getWritten());
    const parsed = try decodeFrame(in.reader(), std.testing.allocator);
    switch (parsed) {
        .handshake_done => {},
        else => return error.TestUnexpectedResult,
    }
}
