const std = @import("std");

/// QUIC version values (v1 + v2)
pub const Version = enum(u32) {
    v1 = 0x00000001,
    v2 = 0x6b3343cf, // RFC 9369

    _,
};

pub const PacketType = enum(u2) {
    initial = 0b00,
    zero_rtt = 0b01,
    handshake = 0b10,
    retry = 0b11,
};

pub const HeaderForm = enum { long, short };

pub const LongHeader = struct {
    version: Version,
    dcid: []const u8,
    scid: []const u8,
    packet_type: PacketType,
    token: []const u8, // Initial: token, others: empty
    packet_number: u64, // decoded PN
};

pub const ShortHeader = struct {
    dcid: []const u8,
    key_phase: bool,
    packet_number: u64,
};

pub const ParsedHeader = union(HeaderForm) {
    long: LongHeader,
    short: ShortHeader,
};

/// Encode a QUIC variable-length integer (RFC 9000 Section 16).
pub fn encodeVarInt(writer: anytype, value: u64) !void {
    if (value <= 63) {
        try writer.writeByte(@as(u8, @intCast(value))); // 00xx xxxx
    } else if (value <= 16383) {
        var tmp: [2]u8 = undefined;
        tmp[0] = 0b01_00_0000 | @as(u8, @intCast(value >> 8));
        tmp[1] = @as(u8, @intCast(value & 0xff));
        try writer.writeAll(&tmp);
    } else if (value <= 1073741823) {
        var tmp: [4]u8 = undefined;
        tmp[0] = 0b10_00_0000 | @as(u8, @intCast(value >> 24));
        tmp[1] = @as(u8, @intCast((value >> 16) & 0xff));
        tmp[2] = @as(u8, @intCast((value >> 8) & 0xff));
        tmp[3] = @as(u8, @intCast(value & 0xff));
        try writer.writeAll(&tmp);
    } else {
        var tmp: [8]u8 = undefined;
        tmp[0] = 0b11_00_0000 | @as(u8, @intCast(value >> 56));
        tmp[1] = @as(u8, @intCast((value >> 48) & 0xff));
        tmp[2] = @as(u8, @intCast((value >> 40) & 0xff));
        tmp[3] = @as(u8, @intCast((value >> 32) & 0xff));
        tmp[4] = @as(u8, @intCast((value >> 24) & 0xff));
        tmp[5] = @as(u8, @intCast((value >> 16) & 0xff));
        tmp[6] = @as(u8, @intCast((value >> 8) & 0xff));
        tmp[7] = @as(u8, @intCast(value & 0xff));
        try writer.writeAll(&tmp);
    }
}

/// Decode a QUIC variable-length integer, returning (value, bytes_consumed).
pub fn decodeVarInt(reader: anytype) !struct { value: u64, len: usize } {
    const first = try reader.readByte();
    const prefix = first >> 6;

    return switch (prefix) {
        0 => .{ .value = first & 0x3f, .len = 1 },
        1 => blk: {
            var buf: [1]u8 = undefined;
            try reader.readNoEof(&buf);
            const value = (@as(u64, first & 0x3f) << 8) | buf[0];
            break :blk .{ .value = value, .len = 2 };
        },
        2 => blk: {
            var buf: [3]u8 = undefined;
            try reader.readNoEof(&buf);
            const value = (@as(u64, first & 0x3f) << 24) | (@as(u64, buf[0]) << 16) | (@as(u64, buf[1]) << 8) | buf[2];
            break :blk .{ .value = value, .len = 4 };
        },
        3 => blk: {
            var buf: [7]u8 = undefined;
            try reader.readNoEof(&buf);
            var value: u64 = first & 0x3f;
            value = (value << 8) | buf[0];
            value = (value << 8) | buf[1];
            value = (value << 8) | buf[2];
            value = (value << 8) | buf[3];
            value = (value << 8) | buf[4];
            value = (value << 8) | buf[5];
            value = (value << 8) | buf[6];
            break :blk .{ .value = value, .len = 8 };
        },
        else => unreachable,
    };
}

/// Parse the first byte and distinguish long vs short header.
pub fn parseHeaderForm(first_byte: u8) HeaderForm {
    return if ((first_byte & 0x80) != 0) .long else .short;
}

/// Stub: encode a long header into the given writer.
/// TODO: implement according to RFC 9000 Section 17.2.
pub fn encodeLongHeader(writer: anytype, header: LongHeader) !void {
    _ = writer;
    _ = header;
    @panic("encodeLongHeader: TODO");
}

/// Stub: parse a long header from the given reader.
/// TODO: implement according to RFC 9000 Section 17.2.
pub fn parseLongHeader(reader: anytype) !LongHeader {
    _ = reader;
    @panic("parseLongHeader: TODO");
}

/// Stub: encode a short header into the given writer.
/// TODO: implement according to RFC 9000 Section 17.3.
pub fn encodeShortHeader(writer: anytype, header: ShortHeader) !void {
    _ = writer;
    _ = header;
    @panic("encodeShortHeader: TODO");
}

/// Stub: parse a short header from the given reader.
/// TODO: implement according to RFC 9000 Section 17.3.
pub fn parseShortHeader(reader: anytype) !ShortHeader {
    _ = reader;
    @panic("parseShortHeader: TODO");
}

test "encodeVarInt emits expected bytes at size boundaries" {
    const Case = struct {
        value: u64,
        expected: []const u8,
    };

    const cases = [_]Case{
        .{ .value = 0, .expected = &[_]u8{0x00} },
        .{ .value = 63, .expected = &[_]u8{0x3f} },
        .{ .value = 64, .expected = &[_]u8{ 0x40, 0x40 } },
        .{ .value = 16383, .expected = &[_]u8{ 0x7f, 0xff } },
        .{ .value = 16384, .expected = &[_]u8{ 0x80, 0x00, 0x40, 0x00 } },
        .{ .value = 1073741823, .expected = &[_]u8{ 0xbf, 0xff, 0xff, 0xff } },
        .{ .value = 1073741824, .expected = &[_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 } },
        .{ .value = 4611686018427387903, .expected = &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
    };

    for (cases) |c| {
        var out: [8]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&out);
        try encodeVarInt(fbs.writer(), c.value);

        const written = fbs.getWritten();
        try std.testing.expectEqual(c.expected.len, written.len);
        try std.testing.expectEqualSlices(u8, c.expected, written);
    }
}

test "decodeVarInt parses expected values and lengths" {
    const Case = struct {
        encoded: []const u8,
        expected_value: u64,
        expected_len: usize,
    };

    const cases = [_]Case{
        .{ .encoded = &[_]u8{0x00}, .expected_value = 0, .expected_len = 1 },
        .{ .encoded = &[_]u8{0x3f}, .expected_value = 63, .expected_len = 1 },
        .{ .encoded = &[_]u8{ 0x40, 0x40 }, .expected_value = 64, .expected_len = 2 },
        .{ .encoded = &[_]u8{ 0x7f, 0xff }, .expected_value = 16383, .expected_len = 2 },
        .{ .encoded = &[_]u8{ 0x80, 0x00, 0x40, 0x00 }, .expected_value = 16384, .expected_len = 4 },
        .{ .encoded = &[_]u8{ 0xbf, 0xff, 0xff, 0xff }, .expected_value = 1073741823, .expected_len = 4 },
        .{ .encoded = &[_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 }, .expected_value = 1073741824, .expected_len = 8 },
        .{ .encoded = &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, .expected_value = 4611686018427387903, .expected_len = 8 },
    };

    for (cases) |c| {
        var fbs = std.io.fixedBufferStream(c.encoded);
        const decoded = try decodeVarInt(fbs.reader());

        try std.testing.expectEqual(c.expected_value, decoded.value);
        try std.testing.expectEqual(c.expected_len, decoded.len);
        try std.testing.expectEqual(c.encoded.len, fbs.pos);
    }
}

test "decodeVarInt fails on truncated inputs" {
    const cases = [_][]const u8{
        &[_]u8{0x40},
        &[_]u8{ 0x80, 0x00 },
        &[_]u8{ 0xc0, 0x00, 0x00, 0x00 },
    };

    for (cases) |encoded| {
        var fbs = std.io.fixedBufferStream(encoded);
        try std.testing.expectError(error.EndOfStream, decodeVarInt(fbs.reader()));
    }
}

test "encodeVarInt and decodeVarInt roundtrip representative values" {
    const values = [_]u64{
        0,
        1,
        37,
        63,
        64,
        15293,
        16383,
        16384,
        999999,
        1073741823,
        1073741824,
        4611686018427387903,
    };

    for (values) |value| {
        var out: [8]u8 = undefined;
        var writer_fbs = std.io.fixedBufferStream(&out);
        try encodeVarInt(writer_fbs.writer(), value);

        const encoded = writer_fbs.getWritten();
        var reader_fbs = std.io.fixedBufferStream(encoded);
        const decoded = try decodeVarInt(reader_fbs.reader());

        try std.testing.expectEqual(value, decoded.value);
        try std.testing.expectEqual(encoded.len, decoded.len);
    }
}

test "encodeVarInt boundary values requested" {
    const Case = struct {
        value: u64,
        expected: []const u8,
    };

    const cases = [_]Case{
        .{ .value = 63, .expected = &[_]u8{0x3f} },
        .{ .value = 64, .expected = &[_]u8{ 0x40, 0x40 } },
        .{ .value = 16383, .expected = &[_]u8{ 0x7f, 0xff } },
        .{ .value = 16384, .expected = &[_]u8{ 0x80, 0x00, 0x40, 0x00 } },
        .{ .value = 1073741823, .expected = &[_]u8{ 0xbf, 0xff, 0xff, 0xff } },
        .{ .value = 1073741824, .expected = &[_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 } },
    };

    for (cases) |c| {
        var out: [8]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&out);
        try encodeVarInt(fbs.writer(), c.value);

        const written = fbs.getWritten();
        try std.testing.expectEqual(c.expected.len, written.len);
        try std.testing.expectEqualSlices(u8, c.expected, written);
    }
}

test "decodeVarInt boundary values requested" {
    const Case = struct {
        encoded: []const u8,
        expected_value: u64,
        expected_len: usize,
    };

    const cases = [_]Case{
        .{ .encoded = &[_]u8{0x3f}, .expected_value = 63, .expected_len = 1 },
        .{ .encoded = &[_]u8{ 0x40, 0x40 }, .expected_value = 64, .expected_len = 2 },
        .{ .encoded = &[_]u8{ 0x7f, 0xff }, .expected_value = 16383, .expected_len = 2 },
        .{ .encoded = &[_]u8{ 0x80, 0x00, 0x40, 0x00 }, .expected_value = 16384, .expected_len = 4 },
        .{ .encoded = &[_]u8{ 0xbf, 0xff, 0xff, 0xff }, .expected_value = 1073741823, .expected_len = 4 },
        .{ .encoded = &[_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 }, .expected_value = 1073741824, .expected_len = 8 },
    };

    for (cases) |c| {
        var fbs = std.io.fixedBufferStream(c.encoded);
        const decoded = try decodeVarInt(fbs.reader());

        try std.testing.expectEqual(c.expected_value, decoded.value);
        try std.testing.expectEqual(c.expected_len, decoded.len);
        try std.testing.expectEqual(c.encoded.len, fbs.pos);
    }
}
