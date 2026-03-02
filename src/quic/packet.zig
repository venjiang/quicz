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
            const value = (@as(u64, first & 0x3f) << 24)
                | (@as(u64, buf[0]) << 16)
                | (@as(u64, buf[1]) << 8)
                | buf[2];
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
