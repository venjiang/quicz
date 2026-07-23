const std = @import("std");

const connection_state = @import("connection_state.zig");
const frame = @import("frame.zig");
const packet = @import("packet.zig");
const protection = @import("protection.zig");
const protocol_limits = @import("protocol_limits.zig");
const transport_types = @import("transport_types.zig");

const Error = transport_types.Error;
const LocalConnectionId = connection_state.LocalConnectionId;
const PendingBlockedFrame = connection_state.PendingBlockedFrame;
const PendingCloseFrame = connection_state.PendingCloseFrame;
const PendingMaxFrame = connection_state.PendingMaxFrame;
const max_connection_id_len = protocol_limits.max_connection_id_len;
const max_quic_varint = protocol_limits.max_quic_varint;
const max_stream_count = protocol_limits.max_stream_count;

pub fn quicVarIntWireLen(value: u64) Error!usize {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    if (value <= max_quic_varint) return 8;
    return error.InvalidPacket;
}

fn quicFrameVarIntWireLen(value: u64) Error!usize {
    if (value > max_quic_varint) return error.InvalidPacket;
    return quicVarIntWireLen(value);
}

pub fn protectedLongDatagramWireLen(
    header: packet.LongHeader,
    packet_number_len: u8,
    plaintext_len: usize,
) Error!usize {
    if (packet_number_len == 0 or packet_number_len > 4) return error.InvalidPacket;
    if (header.dcid.len > max_connection_id_len or header.scid.len > max_connection_id_len) return error.InvalidPacket;
    if (@intFromEnum(header.version) == 0) return error.InvalidPacket;
    if (header.packet_type == .retry) return error.InvalidPacket;
    if (header.packet_type != .initial and header.token.len != 0) return error.InvalidPacket;
    const protected_payload_len = std.math.add(usize, plaintext_len, protection.aead_tag_len) catch return error.BufferTooSmall;
    const protected_payload_len_u64 = std.math.cast(u64, protected_payload_len) orelse return error.BufferTooSmall;
    const wire_length = std.math.add(u64, protected_payload_len_u64, packet_number_len) catch return error.BufferTooSmall;
    if (wire_length > max_quic_varint) return error.BufferTooSmall;

    var header_len: usize = 1 + 4 + 1 + header.dcid.len + 1 + header.scid.len;
    if (header.packet_type == .initial) {
        const token_len_u64 = std.math.cast(u64, header.token.len) orelse return error.BufferTooSmall;
        if (token_len_u64 > max_quic_varint) return error.InvalidPacket;
        header_len = try addDatagramWireLen(header_len, try quicVarIntWireLen(token_len_u64));
        header_len = try addDatagramWireLen(header_len, header.token.len);
    }
    header_len = try addDatagramWireLen(header_len, try quicVarIntWireLen(wire_length));
    header_len = try addDatagramWireLen(header_len, packet_number_len);
    return try addDatagramWireLen(header_len, protected_payload_len);
}

pub fn protectedLongPlaintextLenForMinDatagram(
    header: packet.LongHeader,
    packet_number_len: u8,
    plaintext_len: usize,
    min_datagram_len: usize,
) Error!usize {
    if (min_datagram_len == 0) return plaintext_len;
    var expanded_len = plaintext_len;
    while (try protectedLongDatagramWireLen(header, packet_number_len, expanded_len) < min_datagram_len) {
        const current_len = try protectedLongDatagramWireLen(header, packet_number_len, expanded_len);
        expanded_len = try addDatagramWireLen(expanded_len, min_datagram_len - current_len);
    }
    return expanded_len;
}

pub fn protectedShortDatagramWireLen(
    dcid_len: usize,
    packet_number_len: u8,
    plaintext_len: usize,
) Error!usize {
    if (packet_number_len == 0 or packet_number_len > 4) return error.InvalidPacket;
    if (dcid_len > max_connection_id_len) return error.InvalidPacket;
    const protected_payload_len = std.math.add(usize, plaintext_len, protection.aead_tag_len) catch return error.BufferTooSmall;
    var len: usize = 1;
    len = try addDatagramWireLen(len, dcid_len);
    len = try addDatagramWireLen(len, packet_number_len);
    return try addDatagramWireLen(len, protected_payload_len);
}

pub fn protectedShortPlaintextLenForMinDatagram(
    dcid_len: usize,
    packet_number_len: u8,
    plaintext_len: usize,
    min_datagram_len: usize,
) Error!usize {
    if (min_datagram_len == 0) return plaintext_len;
    var expanded_len = plaintext_len;
    while (try protectedShortDatagramWireLen(dcid_len, packet_number_len, expanded_len) < min_datagram_len) {
        const current_len = try protectedShortDatagramWireLen(dcid_len, packet_number_len, expanded_len);
        expanded_len = try addDatagramWireLen(expanded_len, min_datagram_len - current_len);
    }
    return expanded_len;
}

pub fn addWireLen(current: usize, extra: usize) Error!usize {
    return std.math.add(usize, current, extra) catch return error.Internal;
}

fn addDatagramWireLen(current: usize, extra: usize) Error!usize {
    return std.math.add(usize, current, extra) catch return error.BufferTooSmall;
}

pub fn streamFrameWireLen(stream_id: u64, offset: u64, data_len: usize) Error!usize {
    if (stream_id > max_quic_varint) return error.InvalidPacket;
    try validateFrameDataRange(offset, data_len);

    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(stream_id));
    if (offset != 0) {
        len = try addWireLen(len, try quicVarIntWireLen(offset));
    }
    len = try addWireLen(len, try quicVarIntWireLen(std.math.cast(u64, data_len) orelse return error.Internal));
    return addWireLen(len, data_len);
}

pub fn cryptoFrameWireLen(offset: u64, data_len: usize) Error!usize {
    try validateFrameDataRange(offset, data_len);

    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(offset));
    len = try addWireLen(len, try quicVarIntWireLen(std.math.cast(u64, data_len) orelse return error.Internal));
    return addWireLen(len, data_len);
}

fn validateFrameDataRange(offset: u64, data_len: usize) Error!void {
    if (offset > max_quic_varint) return error.InvalidPacket;
    const data_len_u64 = std.math.cast(u64, data_len) orelse return error.InvalidPacket;
    if (data_len_u64 > max_quic_varint) return error.InvalidPacket;
    const end_offset = std.math.add(u64, offset, data_len_u64) catch return error.InvalidPacket;
    if (end_offset > max_quic_varint) return error.InvalidPacket;
}

pub fn maxStreamFrameDataLen(stream_id: u64, offset: u64, remaining: usize, max_datagram_size: usize) Error!usize {
    if (try streamFrameWireLen(stream_id, offset, 0) > max_datagram_size) return error.BufferTooSmall;
    if (remaining == 0) return 0;

    var best: usize = 0;
    var low: usize = 1;
    const end_offset_budget = std.math.cast(usize, max_quic_varint - offset) orelse std.math.maxInt(usize);
    var high: usize = @min(remaining, max_datagram_size, end_offset_budget);
    while (low <= high) {
        const mid = low + (high - low) / 2;
        const encoded_len = try streamFrameWireLen(stream_id, offset, mid);
        if (encoded_len <= max_datagram_size) {
            best = mid;
            if (mid == std.math.maxInt(usize)) break;
            low = mid + 1;
        } else {
            if (mid == 0) break;
            high = mid - 1;
        }
    }

    if (best == 0) return error.BufferTooSmall;
    return best;
}

pub fn maxCryptoFrameDataLen(offset: u64, remaining: usize, max_datagram_size: usize) Error!usize {
    if (try cryptoFrameWireLen(offset, 0) > max_datagram_size) return error.BufferTooSmall;
    if (remaining == 0) return 0;

    var best: usize = 0;
    var low: usize = 1;
    const end_offset_budget = std.math.cast(usize, max_quic_varint - offset) orelse std.math.maxInt(usize);
    var high: usize = @min(remaining, max_datagram_size, end_offset_budget);
    while (low <= high) {
        const mid = low + (high - low) / 2;
        const encoded_len = try cryptoFrameWireLen(offset, mid);
        if (encoded_len <= max_datagram_size) {
            best = mid;
            if (mid == std.math.maxInt(usize)) break;
            low = mid + 1;
        } else {
            if (mid == 0) break;
            high = mid - 1;
        }
    }

    if (best == 0) return error.BufferTooSmall;
    return best;
}

/// RFC 9221 DATAGRAM with length (0x31): type + varint len + data.
pub fn datagramFrameWireLen(data_len: usize) Error!usize {
    const type_len: usize = 1;
    const len_field = packet.varIntLen(data_len);
    return type_len + len_field + data_len;
}

pub fn ackFrameWireLen(ack: frame.AckFrame) Error!usize {
    try validateAckFrameWireRange(ack);

    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicFrameVarIntWireLen(ack.largest_acknowledged));
    len = try addWireLen(len, try quicFrameVarIntWireLen(ack.ack_delay));
    len = try addWireLen(len, try quicFrameVarIntWireLen(std.math.cast(u64, ack.ranges.len) orelse return error.InvalidPacket));
    len = try addWireLen(len, try quicFrameVarIntWireLen(ack.first_ack_range));
    for (ack.ranges) |range| {
        len = try addWireLen(len, try quicFrameVarIntWireLen(range.gap));
        len = try addWireLen(len, try quicFrameVarIntWireLen(range.ack_range));
    }
    return len;
}

fn validateAckFrameWireRange(ack: frame.AckFrame) Error!void {
    if (ack.first_ack_range > ack.largest_acknowledged) return error.InvalidPacket;

    var smallest = ack.largest_acknowledged - ack.first_ack_range;
    for (ack.ranges) |range| {
        const skipped = std.math.add(u64, range.gap, 2) catch return error.InvalidPacket;
        if (smallest < skipped) return error.InvalidPacket;
        const range_largest = smallest - skipped;
        if (range.ack_range > range_largest) return error.InvalidPacket;
        smallest = range_largest - range.ack_range;
    }
}

pub fn pathResponseFrameWireLen() usize {
    return 9; // frame type + 8-byte path validation data
}

pub fn pathChallengeFrameWireLen() usize {
    return 9; // frame type + 8-byte path validation data
}

pub fn pingFrameWireLen() usize {
    return 1; // frame type only
}

pub fn resetStreamFrameWireLen(reset: frame.ResetStreamFrame) Error!usize {
    if (reset.stream_id > max_quic_varint or reset.application_error_code > max_quic_varint or reset.final_size > max_quic_varint) {
        return error.InvalidPacket;
    }

    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(reset.stream_id));
    len = try addWireLen(len, try quicVarIntWireLen(reset.application_error_code));
    return addWireLen(len, try quicVarIntWireLen(reset.final_size));
}

pub fn stopSendingFrameWireLen(stop_sending: frame.StopSendingFrame) Error!usize {
    if (stop_sending.stream_id > max_quic_varint or stop_sending.application_error_code > max_quic_varint) {
        return error.InvalidPacket;
    }

    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(stop_sending.stream_id));
    return addWireLen(len, try quicVarIntWireLen(stop_sending.application_error_code));
}

pub fn retireConnectionIdFrameWireLen(sequence_number: u64) Error!usize {
    const len: usize = 1; // frame type
    return addWireLen(len, try quicFrameVarIntWireLen(sequence_number));
}

pub fn newConnectionIdFrameWireLen(local_id: LocalConnectionId) Error!usize {
    if (local_id.connection_id.len == 0 or local_id.connection_id.len > max_connection_id_len) return error.InvalidPacket;
    if (local_id.sequence_number > max_quic_varint or local_id.retire_prior_to > max_quic_varint) return error.InvalidPacket;
    if (local_id.retire_prior_to > local_id.sequence_number) return error.InvalidPacket;

    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicFrameVarIntWireLen(local_id.sequence_number));
    len = try addWireLen(len, try quicFrameVarIntWireLen(local_id.retire_prior_to));
    len = try addWireLen(len, 1); // connection ID length
    len = try addWireLen(len, local_id.connection_id.len);
    return addWireLen(len, local_id.stateless_reset_token.len);
}

pub fn newTokenFrameWireLen(token: []const u8) Error!usize {
    if (token.len == 0) return error.InvalidPacket;
    const token_len = std.math.cast(u64, token.len) orelse return error.BufferTooSmall;
    if (token_len > max_quic_varint) return error.InvalidPacket;

    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(token_len));
    return addWireLen(len, token.len);
}

pub fn handshakeDoneFrameWireLen() usize {
    return 1; // frame type only
}

pub fn closeReasonLenWireLen(reason_len: usize) Error!usize {
    const value = std.math.cast(u64, reason_len) orelse return error.BufferTooSmall;
    if (value > max_quic_varint) return error.InvalidPacket;
    return quicVarIntWireLen(value);
}

pub fn connectionCloseFrameWireLen(close: frame.ConnectionCloseFrame) Error!usize {
    if (close.error_code > max_quic_varint or close.frame_type > max_quic_varint) return error.InvalidPacket;

    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(close.error_code));
    len = try addWireLen(len, try quicVarIntWireLen(close.frame_type));
    len = try addWireLen(len, try closeReasonLenWireLen(close.reason_phrase.len));
    return addWireLen(len, close.reason_phrase.len);
}

pub fn applicationCloseFrameWireLen(close: frame.ApplicationCloseFrame) Error!usize {
    if (close.error_code > max_quic_varint) return error.InvalidPacket;

    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(close.error_code));
    len = try addWireLen(len, try closeReasonLenWireLen(close.reason_phrase.len));
    return addWireLen(len, close.reason_phrase.len);
}

pub fn closeFrameWireLen(close: PendingCloseFrame) Error!usize {
    return switch (close) {
        .connection => |connection| connectionCloseFrameWireLen(connection),
        .application => |application| applicationCloseFrameWireLen(application),
    };
}

pub fn blockedFrameWireLen(blocked: PendingBlockedFrame) Error!usize {
    var len: usize = 1; // frame type
    switch (blocked) {
        .data => |data| {
            return addWireLen(len, try quicFrameVarIntWireLen(data.maximum_data));
        },
        .stream_data => |stream_data| {
            len = try addWireLen(len, try quicFrameVarIntWireLen(stream_data.stream_id));
            return addWireLen(len, try quicFrameVarIntWireLen(stream_data.maximum_stream_data));
        },
        .streams_bidi => |streams| {
            try validateStreamCountWireLen(streams.maximum_streams);
            return addWireLen(len, try quicFrameVarIntWireLen(streams.maximum_streams));
        },
        .streams_uni => |streams| {
            try validateStreamCountWireLen(streams.maximum_streams);
            return addWireLen(len, try quicFrameVarIntWireLen(streams.maximum_streams));
        },
    }
}

pub fn maxFrameWireLen(max_frame: PendingMaxFrame) Error!usize {
    var len: usize = 1; // frame type
    switch (max_frame) {
        .data => |data| {
            return addWireLen(len, try quicFrameVarIntWireLen(data.maximum_data));
        },
        .stream_data => |stream_data| {
            len = try addWireLen(len, try quicFrameVarIntWireLen(stream_data.stream_id));
            return addWireLen(len, try quicFrameVarIntWireLen(stream_data.maximum_stream_data));
        },
        .streams_bidi => |streams| {
            try validateStreamCountWireLen(streams.maximum_streams);
            return addWireLen(len, try quicFrameVarIntWireLen(streams.maximum_streams));
        },
        .streams_uni => |streams| {
            try validateStreamCountWireLen(streams.maximum_streams);
            return addWireLen(len, try quicFrameVarIntWireLen(streams.maximum_streams));
        },
    }
}

fn validateStreamCountWireLen(maximum_streams: u64) Error!void {
    if (maximum_streams > max_stream_count) return error.InvalidPacket;
}

test "varint wire length boundaries" {
    try std.testing.expectEqual(@as(usize, 1), try quicVarIntWireLen(63));
    try std.testing.expectEqual(@as(usize, 2), try quicVarIntWireLen(64));
    try std.testing.expectEqual(@as(usize, 2), try quicVarIntWireLen(16383));
    try std.testing.expectEqual(@as(usize, 4), try quicVarIntWireLen(16384));
    try std.testing.expectEqual(@as(usize, 4), try quicVarIntWireLen(1073741823));
    try std.testing.expectEqual(@as(usize, 8), try quicVarIntWireLen(1073741824));
    try std.testing.expectEqual(@as(usize, 8), try quicVarIntWireLen(max_quic_varint));
    try std.testing.expectError(error.InvalidPacket, quicVarIntWireLen(max_quic_varint + 1));
}

test "protected datagram minimum plaintext length expands to target" {
    const header = packet.LongHeader{
        .packet_type = .initial,
        .version = .v1,
        .dcid = "destination",
        .scid = "source",
        .token = "",
        .packet_number = 0,
        .payload_length = 0,
    };

    const plaintext_len = try protectedLongPlaintextLenForMinDatagram(header, 2, 10, 1200);
    try std.testing.expect((try protectedLongDatagramWireLen(header, 2, plaintext_len)) >= 1200);

    const short_plaintext_len = try protectedShortPlaintextLenForMinDatagram(8, 2, 10, 1200);
    try std.testing.expect((try protectedShortDatagramWireLen(8, 2, short_plaintext_len)) >= 1200);
}

test "protected datagram wire length rejects invalid packet number lengths" {
    const header = packet.LongHeader{
        .packet_type = .handshake,
        .version = .v1,
        .dcid = "destination",
        .scid = "source",
        .token = "",
        .packet_number = 0,
        .payload_length = 0,
    };

    try std.testing.expectError(error.InvalidPacket, protectedLongDatagramWireLen(header, 0, 0));
    try std.testing.expectError(error.InvalidPacket, protectedLongDatagramWireLen(header, 5, 0));
    try std.testing.expectError(error.InvalidPacket, protectedShortDatagramWireLen(8, 0, 0));
    try std.testing.expectError(error.InvalidPacket, protectedShortDatagramWireLen(8, 5, 0));
}

test "protected datagram wire length rejects invalid packet envelopes" {
    var too_long_cid = [_]u8{0} ** (max_connection_id_len + 1);
    const header = packet.LongHeader{
        .packet_type = .handshake,
        .version = .v1,
        .dcid = "destination",
        .scid = "source",
        .token = "",
        .packet_number = 0,
        .payload_length = 0,
    };

    var invalid = header;
    invalid.dcid = &too_long_cid;
    try std.testing.expectError(error.InvalidPacket, protectedLongDatagramWireLen(invalid, 2, 0));

    invalid = header;
    invalid.scid = &too_long_cid;
    try std.testing.expectError(error.InvalidPacket, protectedLongDatagramWireLen(invalid, 2, 0));

    invalid = header;
    invalid.version = @enumFromInt(0);
    try std.testing.expectError(error.InvalidPacket, protectedLongDatagramWireLen(invalid, 2, 0));

    invalid = header;
    invalid.packet_type = .retry;
    try std.testing.expectError(error.InvalidPacket, protectedLongDatagramWireLen(invalid, 2, 0));

    invalid = header;
    invalid.token = "unexpected";
    try std.testing.expectError(error.InvalidPacket, protectedLongDatagramWireLen(invalid, 2, 0));

    const oversized_token_len = std.math.cast(usize, max_quic_varint + 1) orelse return error.SkipZigTest;
    const oversized_token: []const u8 = @as([*]const u8, @ptrFromInt(1))[0..oversized_token_len];
    invalid = header;
    invalid.packet_type = .initial;
    invalid.token = oversized_token;
    try std.testing.expectError(error.InvalidPacket, protectedLongDatagramWireLen(invalid, 2, 0));

    try std.testing.expectError(error.InvalidPacket, protectedShortDatagramWireLen(max_connection_id_len + 1, 2, 0));
}

test "protected long datagram wire length rejects payload overflow" {
    const header = packet.LongHeader{
        .packet_type = .handshake,
        .version = .v1,
        .dcid = "destination",
        .scid = "source",
        .token = "",
        .packet_number = 0,
        .payload_length = 0,
    };

    try std.testing.expectError(
        error.BufferTooSmall,
        protectedLongDatagramWireLen(header, 4, std.math.maxInt(usize)),
    );
    try std.testing.expectError(
        error.BufferTooSmall,
        protectedLongDatagramWireLen(header, 4, max_quic_varint),
    );
}

test "protected short datagram wire length rejects payload overflow" {
    try std.testing.expectError(
        error.BufferTooSmall,
        protectedShortDatagramWireLen(8, 4, std.math.maxInt(usize)),
    );
    try std.testing.expectError(
        error.BufferTooSmall,
        protectedShortDatagramWireLen(8, 4, std.math.maxInt(usize) - protection.aead_tag_len),
    );
}

test "max frame data length respects varint boundary expansion" {
    try std.testing.expectEqual(@as(usize, 3), try maxStreamFrameDataLen(0, 0, 100, 6));
    try std.testing.expectEqual(@as(usize, 63), try maxStreamFrameDataLen(0, 0, 100, 67));
    try std.testing.expectEqual(@as(usize, 64), try maxStreamFrameDataLen(0, 0, 100, 68));
    try std.testing.expectError(error.BufferTooSmall, maxStreamFrameDataLen(0, 0, 100, 2));

    try std.testing.expectEqual(@as(usize, 3), try maxCryptoFrameDataLen(0, 100, 6));
    try std.testing.expectEqual(@as(usize, 63), try maxCryptoFrameDataLen(0, 100, 67));
    try std.testing.expectEqual(@as(usize, 64), try maxCryptoFrameDataLen(0, 100, 68));
    try std.testing.expectError(error.BufferTooSmall, maxCryptoFrameDataLen(0, 100, 2));
}

test "stream and crypto wire length reject unsendable data ranges" {
    try std.testing.expectError(error.InvalidPacket, streamFrameWireLen(max_quic_varint + 1, 0, 0));
    try std.testing.expectError(error.InvalidPacket, streamFrameWireLen(0, max_quic_varint + 1, 0));
    try std.testing.expectError(error.InvalidPacket, streamFrameWireLen(0, max_quic_varint, 1));
    try std.testing.expectError(error.InvalidPacket, streamFrameWireLen(0, 1, std.math.maxInt(usize)));

    try std.testing.expectError(error.InvalidPacket, cryptoFrameWireLen(max_quic_varint + 1, 0));
    try std.testing.expectError(error.InvalidPacket, cryptoFrameWireLen(max_quic_varint, 1));
    try std.testing.expectError(error.InvalidPacket, cryptoFrameWireLen(1, std.math.maxInt(usize)));
}

test "control frame wire length rejects oversized QUIC varints as invalid packets" {
    try std.testing.expectError(error.InvalidPacket, retireConnectionIdFrameWireLen(max_quic_varint + 1));
    try std.testing.expectError(error.InvalidPacket, blockedFrameWireLen(.{ .data = .{ .maximum_data = max_quic_varint + 1 } }));
    try std.testing.expectError(error.InvalidPacket, blockedFrameWireLen(.{ .stream_data = .{
        .stream_id = max_quic_varint + 1,
        .maximum_stream_data = 0,
    } }));
    try std.testing.expectError(error.InvalidPacket, blockedFrameWireLen(.{ .stream_data = .{
        .stream_id = 0,
        .maximum_stream_data = max_quic_varint + 1,
    } }));
    try std.testing.expectError(error.InvalidPacket, blockedFrameWireLen(.{ .streams_bidi = .{ .maximum_streams = max_quic_varint + 1 } }));
    try std.testing.expectError(error.InvalidPacket, blockedFrameWireLen(.{ .streams_uni = .{ .maximum_streams = max_quic_varint + 1 } }));

    try std.testing.expectError(error.InvalidPacket, maxFrameWireLen(.{ .data = .{ .maximum_data = max_quic_varint + 1 } }));
    try std.testing.expectError(error.InvalidPacket, maxFrameWireLen(.{ .stream_data = .{
        .stream_id = max_quic_varint + 1,
        .maximum_stream_data = 0,
    } }));
    try std.testing.expectError(error.InvalidPacket, maxFrameWireLen(.{ .stream_data = .{
        .stream_id = 0,
        .maximum_stream_data = max_quic_varint + 1,
    } }));
    try std.testing.expectError(error.InvalidPacket, maxFrameWireLen(.{ .streams_bidi = .{ .maximum_streams = max_quic_varint + 1 } }));
    try std.testing.expectError(error.InvalidPacket, maxFrameWireLen(.{ .streams_uni = .{ .maximum_streams = max_quic_varint + 1 } }));
}

test "stream count wire length rejects values above the stream count limit" {
    try std.testing.expectError(error.InvalidPacket, blockedFrameWireLen(.{ .streams_bidi = .{ .maximum_streams = max_stream_count + 1 } }));
    try std.testing.expectError(error.InvalidPacket, blockedFrameWireLen(.{ .streams_uni = .{ .maximum_streams = max_stream_count + 1 } }));
    try std.testing.expectError(error.InvalidPacket, maxFrameWireLen(.{ .streams_bidi = .{ .maximum_streams = max_stream_count + 1 } }));
    try std.testing.expectError(error.InvalidPacket, maxFrameWireLen(.{ .streams_uni = .{ .maximum_streams = max_stream_count + 1 } }));
}

test "new connection id wire length rejects invalid local ids" {
    var cid = [_]u8{1};
    const token = [_]u8{0} ** 16;
    try std.testing.expectError(error.InvalidPacket, newConnectionIdFrameWireLen(.{
        .sequence_number = max_quic_varint + 1,
        .retire_prior_to = 0,
        .connection_id = &cid,
        .stateless_reset_token = token,
    }));
    try std.testing.expectError(error.InvalidPacket, newConnectionIdFrameWireLen(.{
        .sequence_number = max_quic_varint,
        .retire_prior_to = max_quic_varint + 1,
        .connection_id = &cid,
        .stateless_reset_token = token,
    }));
    try std.testing.expectError(error.InvalidPacket, newConnectionIdFrameWireLen(.{
        .sequence_number = 0,
        .retire_prior_to = 1,
        .connection_id = &cid,
        .stateless_reset_token = token,
    }));
    try std.testing.expectError(error.InvalidPacket, newConnectionIdFrameWireLen(.{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = &[_]u8{},
        .stateless_reset_token = token,
    }));
}

test "close reason wire length rejects oversized QUIC varints as invalid packets" {
    try std.testing.expectError(error.InvalidPacket, closeReasonLenWireLen(max_quic_varint + 1));
}

test "ack wire length rejects invalid ACK ranges and oversized varints" {
    try std.testing.expectError(error.InvalidPacket, ackFrameWireLen(.{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 2,
        .ranges = &[_]frame.AckRange{},
    }));

    const invalid_ranges = [_]frame.AckRange{.{ .gap = 0, .ack_range = 0 }};
    try std.testing.expectError(error.InvalidPacket, ackFrameWireLen(.{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &invalid_ranges,
    }));

    try std.testing.expectError(error.InvalidPacket, ackFrameWireLen(.{
        .largest_acknowledged = max_quic_varint + 1,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &[_]frame.AckRange{},
    }));
    try std.testing.expectError(error.InvalidPacket, ackFrameWireLen(.{
        .largest_acknowledged = 0,
        .ack_delay = max_quic_varint + 1,
        .first_ack_range = 0,
        .ranges = &[_]frame.AckRange{},
    }));
    try std.testing.expectError(error.InvalidPacket, ackFrameWireLen(.{
        .largest_acknowledged = max_quic_varint + 1,
        .ack_delay = 0,
        .first_ack_range = max_quic_varint + 1,
        .ranges = &[_]frame.AckRange{},
    }));

    const oversized_range = [_]frame.AckRange{.{ .gap = max_quic_varint + 1, .ack_range = 0 }};
    try std.testing.expectError(error.InvalidPacket, ackFrameWireLen(.{
        .largest_acknowledged = 10,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &oversized_range,
    }));

    const oversized_ack_range = [_]frame.AckRange{.{ .gap = 0, .ack_range = max_quic_varint + 1 }};
    try std.testing.expectError(error.InvalidPacket, ackFrameWireLen(.{
        .largest_acknowledged = max_quic_varint + 1,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &oversized_ack_range,
    }));
}

test "max frame data length ignores unsendable remaining bytes" {
    try std.testing.expectEqual(@as(usize, 63), try maxStreamFrameDataLen(0, 0, std.math.maxInt(usize), 67));
    try std.testing.expectEqual(@as(usize, 63), try maxCryptoFrameDataLen(0, std.math.maxInt(usize), 67));
}

test "max frame data length respects the QUIC end offset limit" {
    try std.testing.expectEqual(@as(usize, 1), try maxStreamFrameDataLen(0, max_quic_varint - 1, 10, 64));
    try std.testing.expectEqual(@as(usize, 1), try maxCryptoFrameDataLen(max_quic_varint - 1, 10, 64));
    try std.testing.expectError(error.BufferTooSmall, maxStreamFrameDataLen(0, max_quic_varint, 10, 64));
    try std.testing.expectError(error.BufferTooSmall, maxCryptoFrameDataLen(max_quic_varint, 10, 64));
}
