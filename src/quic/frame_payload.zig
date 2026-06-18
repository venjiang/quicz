const std = @import("std");

const buffer = @import("buffer.zig");
const packet = @import("packet.zig");

pub fn rawFrameTypeValue(data: []const u8) u64 {
    var in = buffer.fixedReader(data);
    return (packet.decodeVarInt(in.reader()) catch return 0).value;
}

test "rawFrameTypeValue decodes frame type varint" {
    try std.testing.expectEqual(@as(u64, 0x1c), rawFrameTypeValue(&.{0x1c}));
}

test "rawFrameTypeValue returns zero for malformed varint" {
    try std.testing.expectEqual(@as(u64, 0), rawFrameTypeValue(&.{0xff}));
}
