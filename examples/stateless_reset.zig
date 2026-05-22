const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

const FixedWriter = struct {
    buffer: []u8,
    pos: usize = 0,

    pub fn writer(self: *FixedWriter) *FixedWriter {
        return self;
    }

    pub fn writeByte(self: *FixedWriter, byte: u8) !void {
        if (self.pos >= self.buffer.len) return error.NoSpaceLeft;
        self.buffer[self.pos] = byte;
        self.pos += 1;
    }

    pub fn writeAll(self: *FixedWriter, bytes: []const u8) !void {
        if (self.buffer.len - self.pos < bytes.len) return error.NoSpaceLeft;
        @memcpy(self.buffer[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    pub fn getWritten(self: FixedWriter) []const u8 {
        return self.buffer[0..self.pos];
    }
};

fn fixedWriter(buffer: []u8) FixedWriter {
    return .{ .buffer = buffer };
}

fn require(condition: bool) !void {
    if (!condition) return error.UnexpectedState;
}

pub fn main() !void {
    var conn = try quicz.QuicConnection.init(std.heap.page_allocator, .client, .{});
    defer conn.deinit();

    const cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    var frame_raw: [64]u8 = undefined;
    var frame_out = fixedWriter(&frame_raw);
    try quicz.frame.encodeFrame(frame_out.writer(), .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = &cid,
        .stateless_reset_token = token,
    } });
    try conn.processDatagram(0, frame_out.getWritten());

    var reset_raw: [quicz.packet.min_stateless_reset_datagram_len]u8 = undefined;
    var reset_out = fixedWriter(&reset_raw);
    try quicz.packet.encodeStatelessReset(reset_out.writer(), &[_]u8{ 0x40, 0xaa, 0xbb, 0xcc, 0xdd }, token);
    try require(conn.detectStatelessReset(reset_out.getWritten()) == 0);

    const other = [_]u8{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    reset_out = fixedWriter(&reset_raw);
    try quicz.packet.encodeStatelessReset(reset_out.writer(), &[_]u8{ 0x40, 0xaa, 0xbb, 0xcc, 0xdd }, other);
    try require(conn.detectStatelessReset(reset_out.getWritten()) == null);

    std.debug.print("[reset] matched peer stateless reset token for sequence=0\n", .{});
    std.debug.print("[reset] false token rejected\n", .{});
}
