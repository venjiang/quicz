const std = @import("std");

const buffer = @import("buffer.zig");
const frame = @import("frame.zig");
const frame_rules = @import("frame_rules.zig");
const packet = @import("packet.zig");
const packet_context = @import("packet_context.zig");
const transport_error = @import("transport_error.zig");
const transport_types = @import("transport_types.zig");

const Error = transport_types.Error;
const FramePacketType = packet_context.FramePacketType;

pub fn rawFrameTypeValue(data: []const u8) u64 {
    var in = buffer.fixedReader(data);
    return (packet.decodeVarInt(in.reader()) catch return 0).value;
}

pub const CloseError = struct {
    code: transport_error.TransportErrorCode,
    frame_type: u64,
    reason_phrase: []const u8,
};

pub fn classifyCloseError(
    packet_type: FramePacketType,
    datagram: []const u8,
    allocator: std.mem.Allocator,
) Error!?CloseError {
    var offset: usize = 0;
    while (offset < datagram.len) {
        const frame_type_value = rawFrameTypeValue(datagram[offset..]);
        var decoded = frame.decodeFrameSlice(datagram[offset..], allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                if (transport_error.frameDecodeErrorCode(err)) |code| {
                    return .{
                        .code = code,
                        .frame_type = frame_type_value,
                        .reason_phrase = "frame encoding",
                    };
                }
                return null;
            },
        };

        if (decoded.len == 0) {
            frame.deinitFrame(&decoded.frame, allocator);
            return .{
                .code = .frame_encoding_error,
                .frame_type = frame_type_value,
                .reason_phrase = "frame encoding",
            };
        }

        const close_code = frame_rules.framePacketTypeErrorCode(decoded.frame, packet_type);
        frame.deinitFrame(&decoded.frame, allocator);
        if (close_code) |code| {
            return .{
                .code = code,
                .frame_type = frame_type_value,
                .reason_phrase = "packet type",
            };
        }

        offset += decoded.len;
    }
    return null;
}

test "rawFrameTypeValue decodes frame type varint" {
    try std.testing.expectEqual(@as(u64, 0x1c), rawFrameTypeValue(&.{0x1c}));
}

test "rawFrameTypeValue returns zero for malformed varint" {
    try std.testing.expectEqual(@as(u64, 0), rawFrameTypeValue(&.{0xff}));
}

test "classifyCloseError reports packet type violations" {
    const invalid_zero_rtt_ack = [_]u8{ 0x02, 0, 0, 0, 0 };
    const close = (try classifyCloseError(.zero_rtt, &invalid_zero_rtt_ack, std.testing.allocator)).?;
    try std.testing.expectEqual(transport_error.TransportErrorCode.protocol_violation, close.code);
    try std.testing.expectEqual(@as(u64, 0x02), close.frame_type);
    try std.testing.expectEqualStrings("packet type", close.reason_phrase);
}
