//! Fuzz harness for QUIC frame codec, packet parser, and transport parameters.
//!
//! Run with: zig build run-fuzz
//! Or standalone: zig build-exe fuzz.zig && ./fuzz

const std = @import("std");
const quicz = @import("quicz");
const frame = quicz.frame;
const packet = quicz.packet;

/// Fuzz target: decode arbitrary bytes as a QUIC frame.
pub fn fuzzFrameDecode(data: []const u8) void {
    if (data.len == 0) return;
    var decoded = frame.decodeFrameSlice(data, std.heap.page_allocator) catch return;
    frame.deinitFrame(&decoded.frame, std.heap.page_allocator);
}

/// Fuzz target: parse arbitrary bytes as a QUIC long header.
pub fn fuzzLongHeaderParse(data: []const u8) void {
    if (data.len == 0) return;
    _ = packet.parseLongHeader(data) catch return;
}

/// Fuzz target: parse arbitrary bytes as a QUIC varint.
pub fn fuzzVarintDecode(data: []const u8) void {
    if (data.len == 0) return;
    var reader = std.io.fixedBufferStream(data).reader();
    _ = packet.decodeVarInt(reader) catch return;
}

/// Simple coverage-guided fuzz loop for testing.
pub fn main() !void {
    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();

    var buf: [4096]u8 = undefined;
    var i: usize = 0;
    const iterations: usize = 100_000;

    while (i < iterations) : (i += 1) {
        const len = random.intRangeAtMost(usize, 1, buf.len);
        random.bytes(buf[0..len]);

        fuzzFrameDecode(buf[0..len]);
        fuzzLongHeaderParse(buf[0..len]);
        fuzzVarintDecode(buf[0..len]);

        if (i % 10_000 == 0) {
            std.debug.print("fuzz progress: {d}/{d}\n", .{ i, iterations });
        }
    }

    std.debug.print("fuzz complete: {d} iterations, no crashes\n", .{iterations});
}

test "fuzz frame decode with random data does not crash" {
    var prng = std.Random.DefaultPrng.init(123);
    const random = prng.random();
    var buf: [512]u8 = undefined;

    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const len = random.intRangeAtMost(usize, 1, buf.len);
        random.bytes(buf[0..len]);
        fuzzFrameDecode(buf[0..len]);
    }
}

test "fuzz long header parse with random data does not crash" {
    var prng = std.Random.DefaultPrng.init(456);
    const random = prng.random();
    var buf: [512]u8 = undefined;

    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const len = random.intRangeAtMost(usize, 1, buf.len);
        random.bytes(buf[0..len]);
        fuzzLongHeaderParse(buf[0..len]);
    }
}

test "fuzz varint decode with random data does not crash" {
    var prng = std.Random.DefaultPrng.init(789);
    const random = prng.random();
    var buf: [64]u8 = undefined;

    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const len = random.intRangeAtMost(usize, 1, buf.len);
        random.bytes(buf[0..len]);
        fuzzVarintDecode(buf[0..len]);
    }
}
