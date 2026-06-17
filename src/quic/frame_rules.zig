const std = @import("std");

const frame = @import("frame.zig");
const packet_context = @import("packet_context.zig");
const transport_error = @import("transport_error.zig");
const transport_types = @import("transport_types.zig");

const FramePacketType = packet_context.FramePacketType;
const PacketNumberSpace = transport_types.PacketNumberSpace;

pub fn ackFrameRangesAreValid(ack: frame.AckFrame) bool {
    if (ack.first_ack_range > ack.largest_acknowledged) return false;

    var range_largest = ack.largest_acknowledged;
    var range_smallest = range_largest - ack.first_ack_range;
    for (ack.ranges) |range| {
        const skipped = std.math.add(u64, range.gap, 2) catch return false;
        if (range_smallest < skipped) return false;
        range_largest = range_smallest - skipped;
        if (range.ack_range > range_largest) return false;
        range_smallest = range_largest - range.ack_range;
    }

    return true;
}

pub fn ackFrameContains(ack: frame.AckFrame, packet_number: u64) bool {
    if (ack.first_ack_range > ack.largest_acknowledged) return false;

    var range_largest = ack.largest_acknowledged;
    var range_smallest = range_largest - ack.first_ack_range;
    if (packet_number >= range_smallest and packet_number <= range_largest) return true;

    for (ack.ranges) |range| {
        const skipped = std.math.add(u64, range.gap, 2) catch return false;
        if (range_smallest < skipped) return false;
        range_largest = range_smallest - skipped;
        if (range.ack_range > range_largest) return false;
        range_smallest = range_largest - range.ack_range;
        if (packet_number >= range_smallest and packet_number <= range_largest) return true;
    }

    return false;
}

pub fn frameIsAckEliciting(decoded: frame.Frame) bool {
    return switch (decoded) {
        .padding, .ack, .ack_ecn, .connection_close, .application_close => false,
        else => true,
    };
}

pub fn frameAllowedInPacketNumberSpace(decoded: frame.Frame, space: PacketNumberSpace) bool {
    return frameAllowedInFramePacketType(decoded, defaultFramePacketTypeForSpace(space));
}

/// Classify a decoded frame that is not permitted in an RFC 9000 packet type.
///
/// The frame codec handles malformed or unknown frame types separately via
/// `transport_error.frameDecodeErrorCode()`. This helper covers frames that are
/// syntactically valid but appear in the wrong Initial, Handshake, 0-RTT, or
/// 1-RTT packet context.
pub fn framePacketTypeErrorCode(decoded: frame.Frame, packet_type: FramePacketType) ?transport_error.TransportErrorCode {
    if (frameAllowedInFramePacketType(decoded, packet_type)) return null;
    return .protocol_violation;
}

pub fn defaultFramePacketTypeForSpace(space: PacketNumberSpace) FramePacketType {
    return switch (space) {
        .initial => .initial,
        .handshake => .handshake,
        .application => .one_rtt,
    };
}

pub fn packetNumberSpaceForFramePacketType(packet_type: FramePacketType) PacketNumberSpace {
    return switch (packet_type) {
        .initial => .initial,
        .handshake => .handshake,
        .zero_rtt, .one_rtt => .application,
    };
}

pub fn frameAllowedInFramePacketType(decoded: frame.Frame, packet_type: FramePacketType) bool {
    return switch (packet_type) {
        .initial, .handshake => switch (decoded) {
            .padding, .ping, .ack, .ack_ecn, .crypto, .connection_close => true,
            else => false,
        },
        // RFC 9000 Table 3 marks RETIRE_CONNECTION_ID as a 0/1-RTT frame, but
        // Section 12.5 permits treating it as a 0-RTT protocol violation.
        .zero_rtt => switch (decoded) {
            .padding,
            .ping,
            .reset_stream,
            .stop_sending,
            .stream,
            .max_data,
            .max_stream_data,
            .max_streams_bidi,
            .max_streams_uni,
            .data_blocked,
            .stream_data_blocked,
            .streams_blocked_bidi,
            .streams_blocked_uni,
            .new_connection_id,
            .path_challenge,
            .connection_close,
            .application_close,
            => true,
            else => false,
        },
        .one_rtt => true,
    };
}

test "ack range rules validate and locate packet numbers" {
    const ranges = [_]frame.AckRange{
        .{ .gap = 0, .ack_range = 1 },
    };
    const ack = frame.AckFrame{
        .largest_acknowledged = 10,
        .ack_delay = 0,
        .first_ack_range = 2,
        .ranges = &ranges,
    };

    try std.testing.expect(ackFrameRangesAreValid(ack));
    try std.testing.expect(ackFrameContains(ack, 10));
    try std.testing.expect(ackFrameContains(ack, 8));
    try std.testing.expect(!ackFrameContains(ack, 7));
    try std.testing.expect(ackFrameContains(ack, 6));
    try std.testing.expect(ackFrameContains(ack, 5));
    try std.testing.expect(!ackFrameContains(ack, 4));
}

test "packet type frame rules preserve RFC 9000 restrictions" {
    const stream_frame = frame.Frame{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "",
    } };
    const crypto_frame = frame.Frame{ .crypto = .{
        .offset = 0,
        .data = "",
    } };
    const ack_frame = frame.Frame{ .ack = .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    } };

    try std.testing.expect(frameAllowedInFramePacketType(.ping, .initial));
    try std.testing.expect(!frameAllowedInFramePacketType(stream_frame, .initial));
    try std.testing.expect(frameAllowedInFramePacketType(stream_frame, .zero_rtt));
    try std.testing.expect(!frameAllowedInFramePacketType(ack_frame, .zero_rtt));
    try std.testing.expect(frameAllowedInFramePacketType(ack_frame, .one_rtt));
    try std.testing.expectEqual(@as(?transport_error.TransportErrorCode, .protocol_violation), framePacketTypeErrorCode(stream_frame, .handshake));
    try std.testing.expectEqual(@as(?transport_error.TransportErrorCode, null), framePacketTypeErrorCode(crypto_frame, .handshake));
}
