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

pub fn quicVarIntWireLen(value: u64) Error!usize {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    if (value <= max_quic_varint) return 8;
    return error.Internal;
}

pub fn protectedLongDatagramWireLen(
    header: packet.LongHeader,
    packet_number_len: u8,
    plaintext_len: usize,
) Error!usize {
    if (packet_number_len == 0 or packet_number_len > 4) return error.InvalidPacket;
    const protected_payload_len = std.math.add(usize, plaintext_len, protection.aead_tag_len) catch return error.BufferTooSmall;
    const protected_payload_len_u64 = std.math.cast(u64, protected_payload_len) orelse return error.BufferTooSmall;
    const wire_length = std.math.add(u64, protected_payload_len_u64, packet_number_len) catch return error.BufferTooSmall;

    var header_len: usize = 1 + 4 + 1 + header.dcid.len + 1 + header.scid.len;
    if (header.packet_type == .initial) {
        const token_len_u64 = std.math.cast(u64, header.token.len) orelse return error.BufferTooSmall;
        header_len = try addWireLen(header_len, try quicVarIntWireLen(token_len_u64));
        header_len = try addWireLen(header_len, header.token.len);
    }
    header_len = try addWireLen(header_len, try quicVarIntWireLen(wire_length));
    header_len = try addWireLen(header_len, packet_number_len);
    return try addWireLen(header_len, protected_payload_len);
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
        expanded_len = try addWireLen(expanded_len, min_datagram_len - current_len);
    }
    return expanded_len;
}

pub fn protectedShortDatagramWireLen(
    dcid_len: usize,
    packet_number_len: u8,
    plaintext_len: usize,
) Error!usize {
    if (packet_number_len == 0 or packet_number_len > 4) return error.InvalidPacket;
    var len: usize = 1;
    len = try addWireLen(len, dcid_len);
    len = try addWireLen(len, packet_number_len);
    len = try addWireLen(len, plaintext_len);
    len = try addWireLen(len, protection.aead_tag_len);
    return len;
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
        expanded_len = try addWireLen(expanded_len, min_datagram_len - current_len);
    }
    return expanded_len;
}

pub fn addWireLen(current: usize, extra: usize) Error!usize {
    return std.math.add(usize, current, extra) catch return error.Internal;
}

pub fn streamFrameWireLen(stream_id: u64, offset: u64, data_len: usize) Error!usize {
    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(stream_id));
    if (offset != 0) {
        len = try addWireLen(len, try quicVarIntWireLen(offset));
    }
    len = try addWireLen(len, try quicVarIntWireLen(std.math.cast(u64, data_len) orelse return error.Internal));
    return addWireLen(len, data_len);
}

pub fn cryptoFrameWireLen(offset: u64, data_len: usize) Error!usize {
    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(offset));
    len = try addWireLen(len, try quicVarIntWireLen(std.math.cast(u64, data_len) orelse return error.Internal));
    return addWireLen(len, data_len);
}

pub fn maxStreamFrameDataLen(stream_id: u64, offset: u64, remaining: usize, max_datagram_size: usize) Error!usize {
    if (try streamFrameWireLen(stream_id, offset, 0) > max_datagram_size) return error.BufferTooSmall;
    if (remaining == 0) return 0;

    var best: usize = 0;
    var low: usize = 1;
    var high: usize = remaining;
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
    var high: usize = remaining;
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

pub fn ackFrameWireLen(ack: frame.AckFrame) Error!usize {
    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(ack.largest_acknowledged));
    len = try addWireLen(len, try quicVarIntWireLen(ack.ack_delay));
    len = try addWireLen(len, try quicVarIntWireLen(std.math.cast(u64, ack.ranges.len) orelse return error.Internal));
    len = try addWireLen(len, try quicVarIntWireLen(ack.first_ack_range));
    for (ack.ranges) |range| {
        len = try addWireLen(len, try quicVarIntWireLen(range.gap));
        len = try addWireLen(len, try quicVarIntWireLen(range.ack_range));
    }
    return len;
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
    return addWireLen(len, try quicVarIntWireLen(sequence_number));
}

pub fn newConnectionIdFrameWireLen(local_id: LocalConnectionId) Error!usize {
    if (local_id.connection_id.len == 0 or local_id.connection_id.len > max_connection_id_len) return error.InvalidPacket;
    if (local_id.retire_prior_to > local_id.sequence_number) return error.InvalidPacket;

    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(local_id.sequence_number));
    len = try addWireLen(len, try quicVarIntWireLen(local_id.retire_prior_to));
    len = try addWireLen(len, 1); // connection ID length
    len = try addWireLen(len, local_id.connection_id.len);
    return addWireLen(len, local_id.stateless_reset_token.len);
}

pub fn newTokenFrameWireLen(token: []const u8) Error!usize {
    if (token.len == 0) return error.InvalidPacket;
    const token_len = std.math.cast(u64, token.len) orelse return error.BufferTooSmall;
    if (token_len > max_quic_varint) return error.BufferTooSmall;

    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(token_len));
    return addWireLen(len, token.len);
}

pub fn handshakeDoneFrameWireLen() usize {
    return 1; // frame type only
}

pub fn closeReasonLenWireLen(reason_len: usize) Error!usize {
    const value = std.math.cast(u64, reason_len) orelse return error.BufferTooSmall;
    if (value > max_quic_varint) return error.BufferTooSmall;
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
            return addWireLen(len, try quicVarIntWireLen(data.maximum_data));
        },
        .stream_data => |stream_data| {
            len = try addWireLen(len, try quicVarIntWireLen(stream_data.stream_id));
            return addWireLen(len, try quicVarIntWireLen(stream_data.maximum_stream_data));
        },
        .streams_bidi => |streams| {
            return addWireLen(len, try quicVarIntWireLen(streams.maximum_streams));
        },
        .streams_uni => |streams| {
            return addWireLen(len, try quicVarIntWireLen(streams.maximum_streams));
        },
    }
}

pub fn maxFrameWireLen(max_frame: PendingMaxFrame) Error!usize {
    var len: usize = 1; // frame type
    switch (max_frame) {
        .data => |data| {
            return addWireLen(len, try quicVarIntWireLen(data.maximum_data));
        },
        .stream_data => |stream_data| {
            len = try addWireLen(len, try quicVarIntWireLen(stream_data.stream_id));
            return addWireLen(len, try quicVarIntWireLen(stream_data.maximum_stream_data));
        },
        .streams_bidi => |streams| {
            return addWireLen(len, try quicVarIntWireLen(streams.maximum_streams));
        },
        .streams_uni => |streams| {
            return addWireLen(len, try quicVarIntWireLen(streams.maximum_streams));
        },
    }
}

test "varint wire length boundaries" {
    try std.testing.expectEqual(@as(usize, 1), try quicVarIntWireLen(63));
    try std.testing.expectEqual(@as(usize, 2), try quicVarIntWireLen(64));
    try std.testing.expectEqual(@as(usize, 2), try quicVarIntWireLen(16383));
    try std.testing.expectEqual(@as(usize, 4), try quicVarIntWireLen(16384));
    try std.testing.expectEqual(@as(usize, 4), try quicVarIntWireLen(1073741823));
    try std.testing.expectEqual(@as(usize, 8), try quicVarIntWireLen(1073741824));
    try std.testing.expectEqual(@as(usize, 8), try quicVarIntWireLen(max_quic_varint));
    try std.testing.expectError(error.Internal, quicVarIntWireLen(max_quic_varint + 1));
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
