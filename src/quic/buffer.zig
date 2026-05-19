const std = @import("std");

/// Fixed in-memory reader used by packet/frame codecs in tests and payload
/// parsing. It intentionally exposes only the small reader surface needed here.
pub const FixedReader = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn reader(self: *FixedReader) *FixedReader {
        return self;
    }

    pub fn readByte(self: *FixedReader) !u8 {
        if (self.pos >= self.data.len) return error.EndOfStream;
        const value = self.data[self.pos];
        self.pos += 1;
        return value;
    }

    pub fn readNoEof(self: *FixedReader, out: []u8) !void {
        if (self.data.len - self.pos < out.len) return error.EndOfStream;
        @memcpy(out, self.data[self.pos..][0..out.len]);
        self.pos += out.len;
    }

    pub fn remainingLen(self: FixedReader) usize {
        return self.data.len - self.pos;
    }
};

/// Fixed in-memory writer used by packet/frame codecs. It returns
/// `error.NoSpaceLeft` without growing the caller-provided buffer.
pub const FixedWriter = struct {
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

    pub fn getWritten(self: FixedWriter) []u8 {
        return self.buffer[0..self.pos];
    }
};

/// Create a fixed reader over `data`.
pub fn fixedReader(data: []const u8) FixedReader {
    return .{ .data = data };
}

fn readerHasRemainingLen(comptime Reader: type) bool {
    return switch (@typeInfo(Reader)) {
        .pointer => |pointer| @hasDecl(pointer.child, "remainingLen"),
        else => @hasDecl(Reader, "remainingLen"),
    };
}

/// Read exactly `len` bytes into an owned buffer. Readers that expose
/// `remainingLen()` can reject truncated lengths before allocating.
pub fn readOwnedBytes(reader: anytype, allocator: std.mem.Allocator, len: usize) ![]u8 {
    if (comptime readerHasRemainingLen(@TypeOf(reader))) {
        if (len > reader.remainingLen()) return error.EndOfStream;
    }

    const data = try allocator.alloc(u8, len);
    errdefer allocator.free(data);
    try reader.readNoEof(data);
    return data;
}

/// Create a fixed writer over caller-owned `buffer`.
pub fn fixedWriter(buffer: []u8) FixedWriter {
    return .{ .buffer = buffer };
}

test "fixed reader and writer roundtrip bytes" {
    var raw: [4]u8 = undefined;
    var writer = fixedWriter(&raw);

    try writer.writeByte(0xaa);
    try writer.writeAll(&[_]u8{ 0xbb, 0xcc });
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb, 0xcc }, writer.getWritten());

    var reader = fixedReader(writer.getWritten());
    try std.testing.expectEqual(@as(u8, 0xaa), try reader.readByte());

    var tail: [2]u8 = undefined;
    try reader.readNoEof(&tail);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xbb, 0xcc }, &tail);
    try std.testing.expectError(error.EndOfStream, reader.readByte());
}
