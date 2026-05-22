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

fn expectPathChallenge(payload: []const u8, allocator: std.mem.Allocator, expected: [8]u8) !void {
    var decoded = try quicz.frame.decodeFrameSlice(payload, allocator);
    defer quicz.frame.deinitFrame(&decoded.frame, allocator);
    switch (decoded.frame) {
        .path_challenge => |challenge| try require(std.mem.eql(u8, &challenge.data, &expected)),
        else => return error.UnexpectedState,
    }
}

fn encodePathResponse(buffer: []u8, data: [8]u8) ![]const u8 {
    var out = fixedWriter(buffer);
    try quicz.frame.encodeFrame(out.writer(), .{ .path_response = .{ .data = data } });
    return out.getWritten();
}

fn retryThenSucceed(allocator: std.mem.Allocator) !void {
    var conn = try quicz.QuicConnection.init(allocator, .client, .{});
    defer conn.deinit();

    const challenge_data = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };
    try conn.sendPathChallenge(challenge_data);

    var tx: [64]u8 = undefined;
    const first = (try conn.pollTx(0, &tx)) orelse return error.UnexpectedState;
    try expectPathChallenge(first, allocator, challenge_data);
    try require(conn.pendingPathChallengeCount() == 0);
    try require(conn.outstandingPathChallengeCount() == 1);

    try conn.checkPathValidationTimeouts(10_000);
    try require(conn.pendingPathChallengeCount() == 1);
    try require(conn.outstandingPathChallengeCount() == 0);
    try require(conn.failedPathValidationCount() == 0);

    const retry = (try conn.pollTx(10_000, &tx)) orelse return error.UnexpectedState;
    try expectPathChallenge(retry, allocator, challenge_data);
    try require(conn.pendingPathChallengeCount() == 0);
    try require(conn.outstandingPathChallengeCount() == 1);

    var response_raw: [16]u8 = undefined;
    const response = try encodePathResponse(&response_raw, challenge_data);
    try conn.processDatagram(10_010, response);
    try require(conn.outstandingPathChallengeCount() == 0);
    try require(conn.failedPathValidationCount() == 0);

    std.debug.print("[path] timeout queued retry and matching PATH_RESPONSE validated\n", .{});
}

fn retryThenFail(allocator: std.mem.Allocator) !void {
    var conn = try quicz.QuicConnection.init(allocator, .client, .{});
    defer conn.deinit();

    const challenge_data = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 };
    try conn.sendPathChallenge(challenge_data);

    var tx: [64]u8 = undefined;
    _ = (try conn.pollTx(0, &tx)) orelse return error.UnexpectedState;

    try conn.checkPathValidationTimeouts(10_000);
    _ = (try conn.pollTx(10_000, &tx)) orelse return error.UnexpectedState;

    try conn.checkPathValidationTimeouts(20_000);
    _ = (try conn.pollTx(20_000, &tx)) orelse return error.UnexpectedState;

    try conn.checkPathValidationTimeouts(30_000);
    try require(conn.pendingPathChallengeCount() == 0);
    try require(conn.outstandingPathChallengeCount() == 0);
    try require(conn.failedPathValidationCount() == 1);

    std.debug.print("[path] retry budget exhausted failed_validations={}\n", .{conn.failedPathValidationCount()});
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    try retryThenSucceed(allocator);
    try retryThenFail(allocator);
}
