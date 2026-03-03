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

pub const PacketError = error{
    InvalidHeaderForm,
    InvalidFixedBit,
    InvalidConnectionIdLength,
    InvalidPacketNumber,
    UnexpectedToken,
    InvalidLength,
};

fn packetNumberLen(packet_number: u64) PacketError!u2 {
    if (packet_number <= 0xff) return 1;
    if (packet_number <= 0xffff) return 2;
    if (packet_number <= 0xffffff) return 3;
    if (packet_number <= 0xffffffff) return 4;
    return error.InvalidPacketNumber;
}

fn encodePacketNumber(writer: anytype, packet_number: u64, pn_len: u2) !void {
    var buf: [4]u8 = undefined;
    const pn_len_usize: usize = pn_len;

    var i: usize = 0;
    while (i < pn_len_usize) : (i += 1) {
        const shift = @as(u6, @intCast((pn_len_usize - 1 - i) * 8));
        buf[i] = @as(u8, @intCast((packet_number >> shift) & 0xff));
    }

    try writer.writeAll(buf[0..pn_len_usize]);
}

fn decodePacketNumber(reader: anytype, pn_len: u2) !u64 {
    var value: u64 = 0;
    var i: usize = 0;
    while (i < pn_len) : (i += 1) {
        value = (value << 8) | try reader.readByte();
    }
    return value;
}

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

pub fn encodeLongHeader(writer: anytype, header: LongHeader) !void {
    if (header.dcid.len > 20 or header.scid.len > 20) {
        return error.InvalidConnectionIdLength;
    }
    if (header.packet_type != .initial and header.token.len != 0) {
        return error.UnexpectedToken;
    }

    const pn_len = try packetNumberLen(header.packet_number);

    var first_byte: u8 = 0;
    first_byte |= 0x80; // Header Form = long
    first_byte |= 0x40; // Fixed Bit
    first_byte |= @as(u8, @intCast(@intFromEnum(header.packet_type))) << 4;
    first_byte |= @as(u8, pn_len - 1);

    try writer.writeByte(first_byte);

    const version = @as(u32, @intFromEnum(header.version));
    var version_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &version_buf, version, .big);
    try writer.writeAll(&version_buf);

    try writer.writeByte(@as(u8, @intCast(header.dcid.len)));
    try writer.writeAll(header.dcid);

    try writer.writeByte(@as(u8, @intCast(header.scid.len)));
    try writer.writeAll(header.scid);

    if (header.packet_type == .initial) {
        try encodeVarInt(writer, header.token.len);
        try writer.writeAll(header.token);
    }

    // Simplified: encode payload length as packet number length only.
    try encodeVarInt(writer, pn_len);
    try encodePacketNumber(writer, header.packet_number, pn_len);
}

pub fn parseLongHeader(reader: anytype) !LongHeader {
    const first_byte = try reader.readByte();
    if ((first_byte & 0x80) == 0) return error.InvalidHeaderForm;
    if ((first_byte & 0x40) == 0) return error.InvalidFixedBit;

    const packet_type: PacketType = @enumFromInt(@as(u2, @intCast((first_byte >> 4) & 0x03)));
    const pn_len: u2 = @as(u2, @intCast(first_byte & 0x03)) + 1;

    var version_buf: [4]u8 = undefined;
    try reader.readNoEof(&version_buf);
    const version: Version = @enumFromInt(std.mem.readInt(u32, &version_buf, .big));

    const dcid_len = try reader.readByte();
    if (dcid_len > 20) return error.InvalidConnectionIdLength;
    const dcid = try std.heap.page_allocator.alloc(u8, dcid_len);
    try reader.readNoEof(dcid);

    const scid_len = try reader.readByte();
    if (scid_len > 20) return error.InvalidConnectionIdLength;
    const scid = try std.heap.page_allocator.alloc(u8, scid_len);
    try reader.readNoEof(scid);

    var token: []const u8 = &[_]u8{};
    if (packet_type == .initial) {
        const token_len_varint = try decodeVarInt(reader);
        const token_len = token_len_varint.value;
        token = try std.heap.page_allocator.alloc(u8, token_len);
        try reader.readNoEof(@constCast(token));
    }

    const length_varint = try decodeVarInt(reader);
    if (length_varint.value < pn_len) return error.InvalidLength;

    const packet_number = try decodePacketNumber(reader, pn_len);

    return .{
        .version = version,
        .dcid = dcid,
        .scid = scid,
        .packet_type = packet_type,
        .token = token,
        .packet_number = packet_number,
    };
}

pub fn encodeShortHeader(writer: anytype, header: ShortHeader) !void {
    if (header.dcid.len > 20) {
        return error.InvalidConnectionIdLength;
    }

    const pn_len = try packetNumberLen(header.packet_number);

    var first_byte: u8 = 0;
    first_byte |= 0x40; // Fixed Bit
    if (header.key_phase) first_byte |= 0x04;
    first_byte |= @as(u8, pn_len - 1);

    try writer.writeByte(first_byte);

    // Simplified encoding: prefix short-header DCID with length.
    try writer.writeByte(@as(u8, @intCast(header.dcid.len)));
    try writer.writeAll(header.dcid);
    try encodePacketNumber(writer, header.packet_number, pn_len);
}

pub fn parseShortHeader(reader: anytype) !ShortHeader {
    const first_byte = try reader.readByte();
    if ((first_byte & 0x80) != 0) return error.InvalidHeaderForm;
    if ((first_byte & 0x40) == 0) return error.InvalidFixedBit;

    const key_phase = (first_byte & 0x04) != 0;
    const pn_len: u2 = @as(u2, @intCast(first_byte & 0x03)) + 1;

    const dcid_len = try reader.readByte();
    if (dcid_len > 20) return error.InvalidConnectionIdLength;
    const dcid = try std.heap.page_allocator.alloc(u8, dcid_len);
    try reader.readNoEof(dcid);

    const packet_number = try decodePacketNumber(reader, pn_len);

    return .{
        .dcid = dcid,
        .key_phase = key_phase,
        .packet_number = packet_number,
    };
}

test "encode/parse long header roundtrip" {
    var out: [256]u8 = undefined;
    var writer_fbs = std.io.fixedBufferStream(&out);

    const input = LongHeader{
        .version = .v1,
        .dcid = &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd },
        .scid = &[_]u8{ 0x11, 0x22, 0x33, 0x44 },
        .packet_type = .initial,
        .token = &[_]u8{ 0xde, 0xad },
        .packet_number = 0x1234,
    };

    try encodeLongHeader(writer_fbs.writer(), input);

    const encoded = writer_fbs.getWritten();
    var reader_fbs = std.io.fixedBufferStream(encoded);
    const parsed = try parseLongHeader(reader_fbs.reader());

    try std.testing.expectEqual(input.version, parsed.version);
    try std.testing.expectEqual(input.packet_type, parsed.packet_type);
    try std.testing.expectEqual(input.packet_number, parsed.packet_number);
    try std.testing.expectEqualSlices(u8, input.dcid, parsed.dcid);
    try std.testing.expectEqualSlices(u8, input.scid, parsed.scid);
    try std.testing.expectEqualSlices(u8, input.token, parsed.token);
}

test "encode/parse short header roundtrip" {
    var out: [256]u8 = undefined;
    var writer_fbs = std.io.fixedBufferStream(&out);

    const input = ShortHeader{
        .dcid = &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
        .key_phase = true,
        .packet_number = 0x010203,
    };

    try encodeShortHeader(writer_fbs.writer(), input);

    const encoded = writer_fbs.getWritten();
    var reader_fbs = std.io.fixedBufferStream(encoded);
    const parsed = try parseShortHeader(reader_fbs.reader());

    try std.testing.expectEqual(input.key_phase, parsed.key_phase);
    try std.testing.expectEqual(input.packet_number, parsed.packet_number);
    try std.testing.expectEqualSlices(u8, input.dcid, parsed.dcid);
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
