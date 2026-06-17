const std = @import("std");

const protocol_limits = @import("protocol_limits.zig");
const transport_types = @import("transport_types.zig");

const ConnectionSide = transport_types.ConnectionSide;
const max_quic_varint = protocol_limits.max_quic_varint;

pub fn isBidirectional(stream_id: u64) bool {
    return (stream_id & 0x02) == 0;
}

pub fn isLocalInitiator(side: ConnectionSide, stream_id: u64) bool {
    const initiator: ConnectionSide = if ((stream_id & 0x01) == 0) .client else .server;
    return initiator == side;
}

pub fn isLocalBidirectional(side: ConnectionSide, stream_id: u64) bool {
    return isBidirectional(stream_id) and isLocalInitiator(side, stream_id);
}

pub fn isLocalUnidirectional(side: ConnectionSide, stream_id: u64) bool {
    return !isBidirectional(stream_id) and isLocalInitiator(side, stream_id);
}

pub fn countForId(stream_id: u64) u64 {
    return stream_id / 4 + 1;
}

pub fn endOffset(offset: u64, data_len: usize) ?u64 {
    const len = std.math.cast(u64, data_len) orelse return null;
    const end = std.math.add(u64, offset, len) catch return null;
    if (end > max_quic_varint) return null;
    return end;
}

pub fn rangesOverlap(a_offset: u64, a_len: usize, b_offset: u64, b_len: usize) bool {
    const a_end = endOffset(a_offset, a_len) orelse return true;
    const b_end = endOffset(b_offset, b_len) orelse return true;
    return a_offset < b_end and b_offset < a_end;
}

test "stream ID role and direction helpers follow QUIC low-bit encoding" {
    try std.testing.expect(isLocalBidirectional(.client, 0));
    try std.testing.expect(isLocalBidirectional(.server, 1));
    try std.testing.expect(isLocalUnidirectional(.client, 2));
    try std.testing.expect(isLocalUnidirectional(.server, 3));
    try std.testing.expect(!isLocalBidirectional(.client, 1));
    try std.testing.expect(!isLocalUnidirectional(.server, 2));
    try std.testing.expectEqual(@as(u64, 2), countForId(4));
}

test "stream offsets reject overflow and QUIC varint overflow" {
    try std.testing.expectEqual(@as(?u64, 10), endOffset(7, 3));
    try std.testing.expectEqual(@as(?u64, max_quic_varint), endOffset(max_quic_varint - 1, 1));
    try std.testing.expectEqual(@as(?u64, null), endOffset(max_quic_varint, 1));
    try std.testing.expectEqual(@as(?u64, null), endOffset(std.math.maxInt(u64), 1));
}

test "stream range overlap treats invalid ranges as overlapping" {
    try std.testing.expect(!rangesOverlap(0, 3, 3, 2));
    try std.testing.expect(rangesOverlap(0, 4, 3, 2));
    try std.testing.expect(rangesOverlap(max_quic_varint, 2, 0, 1));
}
