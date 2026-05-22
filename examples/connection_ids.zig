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

fn expectNewConnectionId(payload: []const u8, allocator: std.mem.Allocator, expected_sequence: u64, expected_cid: []const u8) !void {
    var offset: usize = 0;
    while (offset < payload.len) {
        var decoded = try quicz.frame.decodeFrameSlice(payload[offset..], allocator);
        defer quicz.frame.deinitFrame(&decoded.frame, allocator);
        if (decoded.len == 0) return error.UnexpectedState;

        switch (decoded.frame) {
            .new_connection_id => |new_id| {
                try require(new_id.sequence_number == expected_sequence);
                try require(std.mem.eql(u8, new_id.connection_id, expected_cid));
                return;
            },
            else => {},
        }

        offset += decoded.len;
    }

    return error.UnexpectedState;
}

fn retireConnectionId(conn: *quicz.QuicConnection, sequence_number: u64) !void {
    var raw: [16]u8 = undefined;
    var out = fixedWriter(&raw);
    try quicz.frame.encodeFrame(out.writer(), .{ .retire_connection_id = .{ .sequence_number = sequence_number } });
    try conn.processDatagram(10, out.getWritten());
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var conn = try quicz.QuicConnection.init(allocator, .server, .{});
    defer conn.deinit();
    try conn.validatePeerAddress();

    const token0 = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const cid0 = [_]u8{ 0xc0, 0xff, 0xee, 0x00 };
    const sequence0 = try conn.issueConnectionId(&cid0, token0, 0);
    try require(sequence0 == 0);
    try require(conn.pendingNewConnectionIdCount() == 1);

    var tx: [64]u8 = undefined;
    const payload0 = (try conn.pollTx(0, &tx)) orelse return error.UnexpectedState;
    try expectNewConnectionId(payload0, allocator, sequence0, &cid0);
    std.debug.print("[cid] issued sequence={} pending={}\n", .{ sequence0, conn.pendingNewConnectionIdCount() });

    try retireConnectionId(&conn, sequence0);
    try require(conn.localConnectionIdCount() == 0);
    std.debug.print("[cid] retired sequence={} active_local={}\n", .{ sequence0, conn.localConnectionIdCount() });

    const token1 = [_]u8{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    const cid1 = [_]u8{ 0xc0, 0xff, 0xee, 0x01 };
    const sequence1 = try conn.issueConnectionId(&cid1, token1, 1);
    const payload1 = (try conn.pollTx(20, &tx)) orelse return error.UnexpectedState;
    try expectNewConnectionId(payload1, allocator, sequence1, &cid1);
    std.debug.print("[cid] replacement sequence={} retire_prior_to=1\n", .{sequence1});
}
