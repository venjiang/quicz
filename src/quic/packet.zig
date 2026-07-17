const std = @import("std");
const buffer = @import("buffer.zig");

/// QUIC version values (v1 + v2)
pub const Version = enum(u32) {
    v1 = 0x00000001,
    v2 = 0x6b3343cf, // RFC 9369

    _,
};

/// Return whether a version number is reserved for QUIC version greasing.
///
/// RFC 9000 reserves every version matching 0x?a?a?a?a so endpoints can
/// advertise or send unsupported versions without those values ever becoming
/// real protocol versions.
pub fn isReservedVersion(version: Version) bool {
    return (@intFromEnum(version) & 0x0f0f0f0f) == 0x0a0a0a0a;
}

pub const PacketType = enum(u2) {
    initial = 0b00,
    zero_rtt = 0b01,
    handshake = 0b10,
    retry = 0b11,
};

pub const HeaderForm = enum { long, short };

pub const stateless_reset_token_len: usize = 16;
pub const min_stateless_reset_datagram_len: usize = stateless_reset_token_len + 5;
pub const max_packet_number: u64 = (@as(u64, 1) << 62) - 1;
const max_quic_varint = max_packet_number;

/// RFC 9000 packet number encoding decision for a packet header.
///
/// `len` is the selected 1..4 byte wire length. `truncated_packet_number` is
/// the low-order packet number value to place on the wire using that length.
pub const PacketNumberEncoding = struct {
    len: u8,
    truncated_packet_number: u32,
};

/// Parsed QUIC long header fields. The `payload_length` is the wire length
/// after the packet number, while QUIC's length field also includes the packet
/// number bytes.
pub const LongHeader = struct {
    version: Version,
    dcid: []const u8,
    scid: []const u8,
    packet_type: PacketType,
    token: []const u8, // Initial: token, others: empty
    /// Full packet number for encoders and reconstructed parsers.
    ///
    /// `parseLongHeader()` without an expected packet number exposes the
    /// truncated wire value here. Use `parseLongHeaderWithExpectedPacketNumber()`
    /// when the next expected packet number for the space is known.
    packet_number: u64,
    payload_length: u64,
};

/// Parsed QUIC short header fields. The destination CID length is connection
/// context and must be supplied by callers when decoding.
pub const ShortHeader = struct {
    dcid: []const u8,
    /// RFC 9000 1-RTT latency spin bit from byte 0 mask 0x20.
    ///
    /// This codec only preserves the header bit. Endpoint policy for enabling,
    /// disabling, and updating spin values belongs to connection/path state.
    spin_bit: bool = false,
    key_phase: bool,
    /// Full packet number for encoders and reconstructed parsers.
    ///
    /// `parseShortHeader()` without an expected packet number exposes the
    /// truncated wire value here. Use `parseShortHeaderWithExpectedPacketNumber()`
    /// when the next expected packet number for the space is known.
    packet_number: u64,
};

/// RFC 8999 Version Negotiation packet fields.
///
/// Version Negotiation packets are version independent and do not carry a
/// length field, so they are parsed from a complete UDP datagram slice rather
/// than a streaming reader.
pub const VersionNegotiationPacket = struct {
    dcid: []const u8,
    scid: []const u8,
    versions: []const Version,
};

/// RFC 9000 Retry packet fields.
///
/// Retry packets do not contain packet numbers. The integrity tag is parsed and
/// serialized as a 16-byte field; RFC 9001 Retry Integrity Tag validation is
/// implemented in the packet-protection layer.
pub const RetryPacket = struct {
    version: Version,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
    integrity_tag: [16]u8,
};

/// RFC 9000 long-header packet with opaque payload bytes.
///
/// Packet protection is deliberately outside this codec layer. `payload`
/// represents the bytes after the encoded packet number, and the QUIC Length
/// field is derived from `payload.len` during serialization.
pub const LongPacket = struct {
    header: LongHeader,
    payload: []const u8,
};

/// RFC 9000 short-header packet with opaque payload bytes.
///
/// Short headers do not carry a payload length. The parser consumes the
/// remaining datagram bytes as payload after the destination CID and encoded
/// packet number. Packet protection stays outside this codec layer.
pub const ShortPacket = struct {
    header: ShortHeader,
    payload: []const u8,
};

/// A decoded long-header packet and the number of datagram bytes consumed.
///
/// `len` lets callers parse coalesced long-header packets from a single UDP
/// datagram while leaving any following bytes for the next packet parser.
pub const DecodedLongPacket = struct {
    packet: LongPacket,
    len: usize,
};

pub const ParsedHeader = union(HeaderForm) {
    long: LongHeader,
    short: ShortHeader,
};

pub const PacketError = error{
    InvalidHeaderForm,
    InvalidFixedBit,
    InvalidReservedBits,
    InvalidConnectionIdLength,
    InvalidPacketNumber,
    UnsupportedPacketType,
    UnexpectedToken,
    InvalidLength,
    InvalidVarInt,
    InvalidVersionNegotiation,
    InvalidVersionList,
    InvalidRetryPacket,
};

/// Return the long-header wire type bits for a packet type and QUIC version.
///
/// QUIC v2 deliberately changes these bits from QUIC v1. Unknown versions keep
/// the v1 mapping so existing version-independent codec callers preserve their
/// previous behavior until a version-specific profile is added.
pub fn longHeaderPacketTypeBits(version: Version, packet_type: PacketType) u2 {
    return switch (version) {
        .v2 => switch (packet_type) {
            .initial => 0b01,
            .zero_rtt => 0b10,
            .handshake => 0b11,
            .retry => 0b00,
        },
        else => @intFromEnum(packet_type),
    };
}

/// Interpret long-header wire type bits for a QUIC version.
pub fn longHeaderPacketTypeFromBits(version: Version, bits: u2) PacketType {
    return switch (version) {
        .v2 => switch (bits) {
            0b00 => .retry,
            0b01 => .initial,
            0b10 => .zero_rtt,
            0b11 => .handshake,
        },
        else => @enumFromInt(bits),
    };
}

fn packetNumberLen(packet_number: u64) PacketError!u8 {
    if (packet_number <= 0xff) return 1;
    if (packet_number <= 0xffff) return 2;
    if (packet_number <= 0xffffff) return 3;
    if (packet_number <= 0xffffffff) return 4;
    return error.InvalidPacketNumber;
}

fn packetNumberEncodingLenForUnacked(num_unacked_packets: u64) PacketError!u8 {
    if (num_unacked_packets == 0) return error.InvalidPacketNumber;
    if (num_unacked_packets <= (@as(u64, 1) << 7)) return 1;
    if (num_unacked_packets <= (@as(u64, 1) << 15)) return 2;
    if (num_unacked_packets <= (@as(u64, 1) << 23)) return 3;
    if (num_unacked_packets <= (@as(u64, 1) << 31)) return 4;
    return error.InvalidPacketNumber;
}

/// Select a truncated packet number encoding for an outgoing packet header.
///
/// This follows RFC 9000 Appendix A.2: choose enough low-order bytes so the
/// encoded range is at least one bit larger than the number of outstanding
/// packet numbers since the largest acknowledged packet. Before receiving any
/// ACK in the packet number space, pass `null` so the full current packet
/// number is covered by the selected 1..4 byte encoding.
pub fn encodePacketNumberForHeader(
    packet_number: u64,
    largest_acked: ?u64,
) PacketError!PacketNumberEncoding {
    if (packet_number > max_packet_number) return error.InvalidPacketNumber;

    const num_unacked_packets = if (largest_acked) |largest| blk: {
        if (largest > max_packet_number or packet_number <= largest) return error.InvalidPacketNumber;
        break :blk packet_number - largest;
    } else blk: {
        break :blk std.math.add(u64, packet_number, 1) catch return error.InvalidPacketNumber;
    };
    const len = try packetNumberEncodingLenForUnacked(num_unacked_packets);
    const bits = @as(u6, @intCast(@as(u16, len) * 8));
    const mask = (@as(u64, 1) << bits) - 1;
    return .{
        .len = len,
        .truncated_packet_number = @as(u32, @intCast(packet_number & mask)),
    };
}

fn encodePacketNumber(writer: anytype, packet_number: u64, pn_len: u8) !void {
    var buf: [4]u8 = undefined;
    const pn_len_usize: usize = pn_len;

    var i: usize = 0;
    while (i < pn_len_usize) : (i += 1) {
        const shift = @as(u6, @intCast((pn_len_usize - 1 - i) * 8));
        buf[i] = @as(u8, @intCast((packet_number >> shift) & 0xff));
    }

    try writer.writeAll(buf[0..pn_len_usize]);
}

fn validatePacketNumberEncoding(encoding: PacketNumberEncoding) PacketError!void {
    if (encoding.len == 0 or encoding.len > 4) return error.InvalidPacketNumber;
    const bits = @as(u6, @intCast(@as(u16, encoding.len) * 8));
    const mask = (@as(u64, 1) << bits) - 1;
    if (@as(u64, encoding.truncated_packet_number) > mask) return error.InvalidPacketNumber;
}

fn validatePacketNumberEncodingMatches(packet_number: u64, encoding: PacketNumberEncoding) PacketError!void {
    if (packet_number > max_packet_number) return error.InvalidPacketNumber;
    try validatePacketNumberEncoding(encoding);
    const bits = @as(u6, @intCast(@as(u16, encoding.len) * 8));
    const mask = (@as(u64, 1) << bits) - 1;
    if (@as(u64, encoding.truncated_packet_number) != (packet_number & mask)) return error.InvalidPacketNumber;
}

fn decodePacketNumber(reader: anytype, pn_len: u8) !u64 {
    var value: u64 = 0;
    var i: usize = 0;
    while (i < pn_len) : (i += 1) {
        value = (value << 8) | try reader.readByte();
    }
    return value;
}

/// Reconstruct a full packet number from a truncated wire packet number.
///
/// `expected_packet_number` is the next packet number expected in the matching
/// packet number space. `pn_len` is the encoded packet number length in bytes.
pub fn reconstructPacketNumber(expected_packet_number: u64, truncated_packet_number: u64, pn_len: u8) PacketError!u64 {
    if (pn_len == 0 or pn_len > 4) return error.InvalidPacketNumber;
    if (expected_packet_number > max_packet_number + 1) return error.InvalidPacketNumber;

    const pn_nbits = @as(u6, @intCast(@as(u16, pn_len) * 8));
    const pn_window = @as(u64, 1) << pn_nbits;
    const pn_half_window = pn_window / 2;
    const pn_mask = pn_window - 1;
    if (truncated_packet_number > pn_mask) return error.InvalidPacketNumber;

    const candidate = (expected_packet_number & ~pn_mask) | truncated_packet_number;
    const candidate_plus_half = std.math.add(u64, candidate, pn_half_window) catch std.math.maxInt(u64);
    var decoded: u64 = undefined;
    if (candidate_plus_half <= expected_packet_number) {
        decoded = std.math.add(u64, candidate, pn_window) catch return error.InvalidPacketNumber;
    } else {
        const expected_plus_half = std.math.add(u64, expected_packet_number, pn_half_window) catch std.math.maxInt(u64);
        decoded = if (candidate > expected_plus_half and candidate >= pn_window)
            candidate - pn_window
        else
            candidate;
    }

    if (decoded > max_packet_number) return error.InvalidPacketNumber;
    return decoded;
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
    } else if (value <= 4611686018427387903) {
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
    } else {
        return error.InvalidVarInt;
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

/// Release connection-id and token buffers owned by a parsed long header.
pub fn deinitLongHeader(header: *LongHeader, allocator: std.mem.Allocator) void {
    allocator.free(header.dcid);
    allocator.free(header.scid);
    if (header.token.len != 0) {
        allocator.free(header.token);
    }
}

/// Release the destination connection-id buffer owned by a parsed short header.
pub fn deinitShortHeader(header: *ShortHeader, allocator: std.mem.Allocator) void {
    allocator.free(header.dcid);
}

/// Release buffers owned by a parsed Version Negotiation packet.
pub fn deinitVersionNegotiationPacket(packet: *VersionNegotiationPacket, allocator: std.mem.Allocator) void {
    allocator.free(packet.dcid);
    allocator.free(packet.scid);
    allocator.free(packet.versions);
}

/// Release buffers owned by a parsed Retry packet.
pub fn deinitRetryPacket(packet: *RetryPacket, allocator: std.mem.Allocator) void {
    allocator.free(packet.dcid);
    allocator.free(packet.scid);
    allocator.free(packet.token);
}

/// Release buffers owned by a decoded long-header packet.
pub fn deinitLongPacket(packet: *LongPacket, allocator: std.mem.Allocator) void {
    deinitLongHeader(&packet.header, allocator);
    if (packet.payload.len != 0) {
        allocator.free(packet.payload);
    }
}

/// Release buffers owned by a parsed short-header packet.
pub fn deinitShortPacket(packet: *ShortPacket, allocator: std.mem.Allocator) void {
    deinitShortHeader(&packet.header, allocator);
    if (packet.payload.len != 0) {
        allocator.free(packet.payload);
    }
}

fn validateVersionNegotiationCidLen(len: usize) PacketError!void {
    if (len > std.math.maxInt(u8)) return error.InvalidConnectionIdLength;
}

fn validateVersionNegotiationVersion(version: Version) PacketError!void {
    if (@intFromEnum(version) == 0) return error.InvalidVersionList;
}

fn validateVersionedPacketVersion(version: Version) PacketError!void {
    if (@intFromEnum(version) == 0) return error.InvalidVersionNegotiation;
}

fn validateLengthVarInt(value: u64) PacketError!void {
    if (value > max_quic_varint) return error.InvalidLength;
}

fn validateLongHeaderCidLen(len: usize) PacketError!void {
    if (len > 20) return error.InvalidConnectionIdLength;
}

/// Serialize a minimal QUIC long header. Payload bytes are not written here;
/// `payload_length` records the bytes expected after the packet number.
pub fn encodeLongHeader(writer: anytype, header: LongHeader) !void {
    const pn_len = try packetNumberLen(header.packet_number);
    try encodeLongHeaderWithPacketNumberEncoding(writer, header, .{
        .len = pn_len,
        .truncated_packet_number = @as(u32, @intCast(header.packet_number)),
    });
}

/// Serialize a long header using an explicit truncated packet number encoding.
///
/// This lets callers use `encodePacketNumberForHeader()` to choose the RFC 9000
/// wire packet-number length from packet-space ACK state while retaining the
/// full packet number in `header.packet_number`.
pub fn encodeLongHeaderWithPacketNumberEncoding(
    writer: anytype,
    header: LongHeader,
    packet_number_encoding: PacketNumberEncoding,
) !void {
    try validateLongHeaderCidLen(header.dcid.len);
    try validateLongHeaderCidLen(header.scid.len);
    try validateVersionedPacketVersion(header.version);
    if (header.packet_type == .retry) {
        return error.UnsupportedPacketType;
    }
    if (header.packet_type != .initial and header.token.len != 0) {
        return error.UnexpectedToken;
    }
    try validatePacketNumberEncodingMatches(header.packet_number, packet_number_encoding);

    const wire_length = std.math.add(u64, header.payload_length, packet_number_encoding.len) catch return error.InvalidLength;
    try validateLengthVarInt(wire_length);
    if (header.packet_type == .initial) {
        const token_len = std.math.cast(u64, header.token.len) orelse return error.InvalidLength;
        try validateLengthVarInt(token_len);
    }

    var first_byte: u8 = 0;
    first_byte |= 0x80; // Header Form = long
    first_byte |= 0x40; // Fixed Bit
    first_byte |= @as(u8, @intCast(longHeaderPacketTypeBits(header.version, header.packet_type))) << 4;
    first_byte |= @as(u8, @intCast(packet_number_encoding.len - 1));

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

    try encodeVarInt(writer, wire_length);
    try encodePacketNumber(writer, packet_number_encoding.truncated_packet_number, packet_number_encoding.len);
}

/// Parse a minimal QUIC long header and allocate copied CID/token slices using
/// `allocator`; callers must release the result with `deinitLongHeader`.
pub fn parseLongHeader(reader: anytype, allocator: std.mem.Allocator) !LongHeader {
    return parseLongHeaderInternal(reader, allocator, null);
}

/// Parse a long header and reconstruct the full packet number for the space.
pub fn parseLongHeaderWithExpectedPacketNumber(
    reader: anytype,
    allocator: std.mem.Allocator,
    expected_packet_number: u64,
) !LongHeader {
    return parseLongHeaderInternal(reader, allocator, expected_packet_number);
}

fn parseLongHeaderInternal(
    reader: anytype,
    allocator: std.mem.Allocator,
    expected_packet_number: ?u64,
) !LongHeader {
    const first_byte = try reader.readByte();
    if ((first_byte & 0x80) == 0) return error.InvalidHeaderForm;
    if ((first_byte & 0x40) == 0) return error.InvalidFixedBit;
    if ((first_byte & 0x0c) != 0) return error.InvalidReservedBits;

    const pn_len: u8 = @as(u8, @intCast(first_byte & 0x03)) + 1;
    const packet_type_bits: u2 = @intCast((first_byte >> 4) & 0x03);

    var version_buf: [4]u8 = undefined;
    try reader.readNoEof(&version_buf);
    const version: Version = @enumFromInt(std.mem.readInt(u32, &version_buf, .big));
    try validateVersionedPacketVersion(version);
    const packet_type = longHeaderPacketTypeFromBits(version, packet_type_bits);
    if (packet_type == .retry) return error.UnsupportedPacketType;

    const dcid_len = try reader.readByte();
    if (dcid_len > 20) return error.InvalidConnectionIdLength;
    const dcid = try allocator.alloc(u8, dcid_len);
    errdefer allocator.free(dcid);
    try reader.readNoEof(dcid);

    const scid_len = try reader.readByte();
    if (scid_len > 20) return error.InvalidConnectionIdLength;
    const scid = try allocator.alloc(u8, scid_len);
    errdefer allocator.free(scid);
    try reader.readNoEof(scid);

    var token: []const u8 = &[_]u8{};
    errdefer if (token.len != 0) allocator.free(token);
    if (packet_type == .initial) {
        const token_len_varint = try decodeVarInt(reader);
        const token_len = std.math.cast(usize, token_len_varint.value) orelse return error.InvalidLength;
        if (token_len != 0) {
            token = try buffer.readOwnedBytes(reader, allocator, token_len);
        }
    }

    const length_varint = try decodeVarInt(reader);
    if (length_varint.value < pn_len) return error.InvalidLength;
    const payload_length = length_varint.value - pn_len;

    const truncated_packet_number = try decodePacketNumber(reader, pn_len);
    const packet_number = if (expected_packet_number) |expected|
        try reconstructPacketNumber(expected, truncated_packet_number, pn_len)
    else
        truncated_packet_number;

    return .{
        .version = version,
        .dcid = dcid,
        .scid = scid,
        .packet_type = packet_type,
        .token = token,
        .packet_number = packet_number,
        .payload_length = payload_length,
    };
}

/// Serialize one QUIC long-header packet with opaque payload bytes.
pub fn encodeLongPacket(writer: anytype, packet: LongPacket) !void {
    const payload_length = std.math.cast(u64, packet.payload.len) orelse return error.InvalidLength;
    var header = packet.header;
    header.payload_length = payload_length;
    try encodeLongHeader(writer, header);
    try writer.writeAll(packet.payload);
}

/// Serialize one long-header packet with an explicit truncated packet number.
pub fn encodeLongPacketWithPacketNumberEncoding(
    writer: anytype,
    packet: LongPacket,
    packet_number_encoding: PacketNumberEncoding,
) !void {
    const payload_length = std.math.cast(u64, packet.payload.len) orelse return error.InvalidLength;
    var header = packet.header;
    header.payload_length = payload_length;
    try encodeLongHeaderWithPacketNumberEncoding(writer, header, packet_number_encoding);
    try writer.writeAll(packet.payload);
}

/// Parse one QUIC long-header packet from a datagram.
///
/// The returned `len` covers exactly the header plus payload declared by the
/// QUIC Length field. Extra trailing bytes are left untouched so callers can
/// continue parsing coalesced packets.
pub fn parseLongPacket(data: []const u8, allocator: std.mem.Allocator) !DecodedLongPacket {
    return parseLongPacketInternal(data, allocator, null);
}

/// Parse one long-header packet and reconstruct the full packet number.
pub fn parseLongPacketWithExpectedPacketNumber(
    data: []const u8,
    allocator: std.mem.Allocator,
    expected_packet_number: u64,
) !DecodedLongPacket {
    return parseLongPacketInternal(data, allocator, expected_packet_number);
}

fn parseLongPacketInternal(
    data: []const u8,
    allocator: std.mem.Allocator,
    expected_packet_number: ?u64,
) !DecodedLongPacket {
    var reader_fbs = buffer.fixedReader(data);
    var header = try parseLongHeaderInternal(reader_fbs.reader(), allocator, expected_packet_number);
    errdefer deinitLongHeader(&header, allocator);

    const payload_len = std.math.cast(usize, header.payload_length) orelse return error.InvalidLength;
    if (payload_len > reader_fbs.remainingLen()) return error.InvalidLength;

    const payload = if (payload_len == 0)
        &[_]u8{}
    else
        try buffer.readOwnedBytes(reader_fbs.reader(), allocator, payload_len);
    errdefer if (payload.len != 0) allocator.free(payload);

    return .{
        .packet = .{
            .header = header,
            .payload = payload,
        },
        .len = reader_fbs.pos,
    };
}

/// Serialize a minimal QUIC short header using the supplied destination CID.
pub fn encodeShortHeader(writer: anytype, header: ShortHeader) !void {
    const pn_len = try packetNumberLen(header.packet_number);
    try encodeShortHeaderWithPacketNumberEncoding(writer, header, .{
        .len = pn_len,
        .truncated_packet_number = @as(u32, @intCast(header.packet_number)),
    });
}

/// Serialize a short header using an explicit truncated packet number encoding.
pub fn encodeShortHeaderWithPacketNumberEncoding(
    writer: anytype,
    header: ShortHeader,
    packet_number_encoding: PacketNumberEncoding,
) !void {
    if (header.dcid.len > 20) {
        return error.InvalidConnectionIdLength;
    }
    try validatePacketNumberEncodingMatches(header.packet_number, packet_number_encoding);

    var first_byte: u8 = 0;
    first_byte |= 0x40; // Fixed Bit
    if (header.spin_bit) first_byte |= 0x20;
    if (header.key_phase) first_byte |= 0x04;
    first_byte |= @as(u8, @intCast(packet_number_encoding.len - 1));

    try writer.writeByte(first_byte);
    try writer.writeAll(header.dcid);
    try encodePacketNumber(writer, packet_number_encoding.truncated_packet_number, packet_number_encoding.len);
}

/// Parse a minimal QUIC short header. `dcid_len` comes from connection context,
/// because short headers do not carry a destination CID length on the wire.
pub fn parseShortHeader(reader: anytype, allocator: std.mem.Allocator, dcid_len: usize) !ShortHeader {
    return parseShortHeaderInternal(reader, allocator, dcid_len, null);
}

/// Parse a short header and reconstruct the full packet number for the space.
pub fn parseShortHeaderWithExpectedPacketNumber(
    reader: anytype,
    allocator: std.mem.Allocator,
    dcid_len: usize,
    expected_packet_number: u64,
) !ShortHeader {
    return parseShortHeaderInternal(reader, allocator, dcid_len, expected_packet_number);
}

fn parseShortHeaderInternal(
    reader: anytype,
    allocator: std.mem.Allocator,
    dcid_len: usize,
    expected_packet_number: ?u64,
) !ShortHeader {
    const first_byte = try reader.readByte();
    if ((first_byte & 0x80) != 0) return error.InvalidHeaderForm;
    if ((first_byte & 0x40) == 0) return error.InvalidFixedBit;
    if ((first_byte & 0x18) != 0) return error.InvalidReservedBits;

    const spin_bit = (first_byte & 0x20) != 0;
    const key_phase = (first_byte & 0x04) != 0;
    const pn_len: u8 = @as(u8, @intCast(first_byte & 0x03)) + 1;

    if (dcid_len > 20) return error.InvalidConnectionIdLength;
    const dcid = try allocator.alloc(u8, dcid_len);
    errdefer allocator.free(dcid);
    try reader.readNoEof(dcid);

    const truncated_packet_number = try decodePacketNumber(reader, pn_len);
    const packet_number = if (expected_packet_number) |expected|
        try reconstructPacketNumber(expected, truncated_packet_number, pn_len)
    else
        truncated_packet_number;

    return .{
        .dcid = dcid,
        .spin_bit = spin_bit,
        .key_phase = key_phase,
        .packet_number = packet_number,
    };
}

/// Serialize one QUIC short-header packet with opaque payload bytes.
pub fn encodeShortPacket(writer: anytype, packet: ShortPacket) !void {
    try encodeShortHeader(writer, packet.header);
    try writer.writeAll(packet.payload);
}

/// Serialize one short-header packet with an explicit truncated packet number.
pub fn encodeShortPacketWithPacketNumberEncoding(
    writer: anytype,
    packet: ShortPacket,
    packet_number_encoding: PacketNumberEncoding,
) !void {
    try encodeShortHeaderWithPacketNumberEncoding(writer, packet.header, packet_number_encoding);
    try writer.writeAll(packet.payload);
}

/// Parse one QUIC short-header packet from a complete datagram.
///
/// Short headers do not encode payload length, so the decoded payload is every
/// byte left after the destination CID and packet number.
pub fn parseShortPacket(
    data: []const u8,
    allocator: std.mem.Allocator,
    dcid_len: usize,
) !ShortPacket {
    return parseShortPacketInternal(data, allocator, dcid_len, null);
}

/// Parse one short-header packet and reconstruct the full packet number.
pub fn parseShortPacketWithExpectedPacketNumber(
    data: []const u8,
    allocator: std.mem.Allocator,
    dcid_len: usize,
    expected_packet_number: u64,
) !ShortPacket {
    return parseShortPacketInternal(data, allocator, dcid_len, expected_packet_number);
}

fn parseShortPacketInternal(
    data: []const u8,
    allocator: std.mem.Allocator,
    dcid_len: usize,
    expected_packet_number: ?u64,
) !ShortPacket {
    var reader_fbs = buffer.fixedReader(data);
    var header = try parseShortHeaderInternal(reader_fbs.reader(), allocator, dcid_len, expected_packet_number);
    errdefer deinitShortHeader(&header, allocator);

    const payload_len = reader_fbs.remainingLen();
    const payload = if (payload_len == 0)
        &[_]u8{}
    else
        try buffer.readOwnedBytes(reader_fbs.reader(), allocator, payload_len);
    errdefer if (payload.len != 0) allocator.free(payload);

    return .{
        .header = header,
        .payload = payload,
    };
}

/// Serialize an RFC 8999 Version Negotiation packet.
///
/// The encoder sets the high bit to indicate a long header and sets the next
/// bit so the packet resembles a QUIC packet with the fixed bit set. Receivers
/// must ignore all 7 version-specific bits after the high bit.
pub fn encodeVersionNegotiationPacket(writer: anytype, packet: VersionNegotiationPacket) !void {
    try validateVersionNegotiationCidLen(packet.dcid.len);
    try validateVersionNegotiationCidLen(packet.scid.len);
    if (packet.versions.len == 0) return error.InvalidVersionList;
    for (packet.versions) |version_value| {
        try validateVersionNegotiationVersion(version_value);
    }

    try writer.writeByte(0xc0); // Header Form = long; remaining bits are unused.
    try writer.writeAll(&[_]u8{ 0x00, 0x00, 0x00, 0x00 }); // Version = 0.

    try writer.writeByte(@as(u8, @intCast(packet.dcid.len)));
    try writer.writeAll(packet.dcid);

    try writer.writeByte(@as(u8, @intCast(packet.scid.len)));
    try writer.writeAll(packet.scid);

    for (packet.versions) |version_value| {
        const raw_version = @as(u32, @intFromEnum(version_value));
        var version_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &version_buf, raw_version, .big);
        try writer.writeAll(&version_buf);
    }
}

/// Parse an RFC 8999 Version Negotiation packet from a complete datagram.
///
/// Empty or truncated supported-version lists are rejected so callers can
/// ignore invalid packets without partially initialized state.
pub fn parseVersionNegotiationPacket(data: []const u8, allocator: std.mem.Allocator) !VersionNegotiationPacket {
    var reader_fbs = buffer.fixedReader(data);
    const reader = reader_fbs.reader();

    const first_byte = try reader.readByte();
    if ((first_byte & 0x80) == 0) return error.InvalidHeaderForm;

    var version_buf: [4]u8 = undefined;
    try reader.readNoEof(&version_buf);
    if (std.mem.readInt(u32, &version_buf, .big) != 0) return error.InvalidVersionNegotiation;

    const dcid_len = try reader.readByte();
    const dcid = try buffer.readOwnedBytes(reader, allocator, dcid_len);
    errdefer allocator.free(dcid);

    const scid_len = try reader.readByte();
    const scid = try buffer.readOwnedBytes(reader, allocator, scid_len);
    errdefer allocator.free(scid);

    const versions_len = reader.remainingLen();
    if (versions_len == 0 or versions_len % 4 != 0) return error.InvalidVersionList;

    const versions = try allocator.alloc(Version, versions_len / 4);
    errdefer allocator.free(versions);

    for (versions) |*version_value| {
        try reader.readNoEof(&version_buf);
        version_value.* = @enumFromInt(std.mem.readInt(u32, &version_buf, .big));
        try validateVersionNegotiationVersion(version_value.*);
    }

    return .{
        .dcid = dcid,
        .scid = scid,
        .versions = versions,
    };
}

/// Serialize an RFC 9000 Retry packet.
///
/// The encoder sets the unused bits to zero. Receivers must ignore those bits
/// because servers can set them to arbitrary values.
pub fn encodeRetryPacket(writer: anytype, retry: RetryPacket) !void {
    try validateLongHeaderCidLen(retry.dcid.len);
    try validateLongHeaderCidLen(retry.scid.len);
    try validateVersionedPacketVersion(retry.version);
    if (retry.token.len == 0) return error.InvalidRetryPacket;

    const type_bits = longHeaderPacketTypeBits(retry.version, .retry);
    try writer.writeByte(0x80 | 0x40 | (@as(u8, @intCast(type_bits)) << 4)); // Long + fixed + Retry + zero unused bits.

    const raw_version = @as(u32, @intFromEnum(retry.version));
    var version_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &version_buf, raw_version, .big);
    try writer.writeAll(&version_buf);

    try writer.writeByte(@intCast(retry.dcid.len));
    try writer.writeAll(retry.dcid);

    try writer.writeByte(@intCast(retry.scid.len));
    try writer.writeAll(retry.scid);

    try writer.writeAll(retry.token);
    try writer.writeAll(&retry.integrity_tag);
}

/// Parse an RFC 9000 Retry packet from a complete datagram.
pub fn parseRetryPacket(data: []const u8, allocator: std.mem.Allocator) !RetryPacket {
    var reader_fbs = buffer.fixedReader(data);
    const reader = reader_fbs.reader();

    const first_byte = try reader.readByte();
    if ((first_byte & 0x80) == 0) return error.InvalidHeaderForm;
    if ((first_byte & 0x40) == 0) return error.InvalidFixedBit;
    const packet_type_bits: u2 = @intCast((first_byte >> 4) & 0x03);

    var version_buf: [4]u8 = undefined;
    try reader.readNoEof(&version_buf);
    const version: Version = @enumFromInt(std.mem.readInt(u32, &version_buf, .big));
    try validateVersionedPacketVersion(version);
    const packet_type = longHeaderPacketTypeFromBits(version, packet_type_bits);
    if (packet_type != .retry) return error.InvalidRetryPacket;

    const dcid_len = try reader.readByte();
    try validateLongHeaderCidLen(dcid_len);
    const dcid = try buffer.readOwnedBytes(reader, allocator, dcid_len);
    errdefer allocator.free(dcid);

    const scid_len = try reader.readByte();
    try validateLongHeaderCidLen(scid_len);
    const scid = try buffer.readOwnedBytes(reader, allocator, scid_len);
    errdefer allocator.free(scid);

    if (reader.remainingLen() <= 16) return error.InvalidRetryPacket;
    const token_len = reader.remainingLen() - 16;
    const token = try buffer.readOwnedBytes(reader, allocator, token_len);
    errdefer allocator.free(token);

    var integrity_tag: [16]u8 = undefined;
    try reader.readNoEof(&integrity_tag);

    return .{
        .version = version,
        .dcid = dcid,
        .scid = scid,
        .token = token,
        .integrity_tag = integrity_tag,
    };
}

/// Return the trailing stateless reset token candidate from a datagram.
///
/// A stateless reset is only recognizable by comparing the final 16 bytes with
/// a token already associated with a connection ID. Packets shorter than the
/// RFC 9000 minimum stateless reset size cannot be resets.
pub fn statelessResetTokenCandidate(datagram: []const u8) ?[stateless_reset_token_len]u8 {
    if (datagram.len < min_stateless_reset_datagram_len) return null;
    var token: [stateless_reset_token_len]u8 = undefined;
    @memcpy(&token, datagram[datagram.len - stateless_reset_token_len ..]);
    return token;
}

pub fn matchesStatelessReset(datagram: []const u8, expected_token: [stateless_reset_token_len]u8) bool {
    const candidate = statelessResetTokenCandidate(datagram) orelse return false;
    return std.crypto.timing_safe.eql([stateless_reset_token_len]u8, candidate, expected_token);
}

/// Serialize a stateless reset datagram with caller-provided unpredictable bytes.
pub fn encodeStatelessReset(writer: anytype, unpredictable_prefix: []const u8, token: [stateless_reset_token_len]u8) !void {
    if (unpredictable_prefix.len < min_stateless_reset_datagram_len - stateless_reset_token_len) {
        return error.InvalidLength;
    }
    try writer.writeAll(unpredictable_prefix);
    try writer.writeAll(&token);
}

test "encode/parse long header roundtrip" {
    var out: [256]u8 = undefined;
    var writer_fbs = buffer.fixedWriter(&out);

    const input = LongHeader{
        .version = .v1,
        .dcid = &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd },
        .scid = &[_]u8{ 0x11, 0x22, 0x33, 0x44 },
        .packet_type = .initial,
        .token = &[_]u8{ 0xde, 0xad },
        .packet_number = 0x1234,
        .payload_length = 10,
    };

    try encodeLongHeader(writer_fbs.writer(), input);

    const encoded = writer_fbs.getWritten();
    var reader_fbs = buffer.fixedReader(encoded);
    var parsed = try parseLongHeader(reader_fbs.reader(), std.testing.allocator);
    defer deinitLongHeader(&parsed, std.testing.allocator);

    try std.testing.expectEqual(input.version, parsed.version);
    try std.testing.expectEqual(input.packet_type, parsed.packet_type);
    try std.testing.expectEqual(input.packet_number, parsed.packet_number);
    try std.testing.expectEqual(input.payload_length, parsed.payload_length);
    try std.testing.expectEqualSlices(u8, input.dcid, parsed.dcid);
    try std.testing.expectEqualSlices(u8, input.scid, parsed.scid);
    try std.testing.expectEqualSlices(u8, input.token, parsed.token);
}

test "encode/parse QUIC v2 long header packet type bits" {
    const cases = [_]struct {
        packet_type: PacketType,
        expected_first_byte: u8,
        token: []const u8,
    }{
        .{ .packet_type = .initial, .expected_first_byte = 0xd0, .token = &[_]u8{0xaa} },
        .{ .packet_type = .zero_rtt, .expected_first_byte = 0xe0, .token = &[_]u8{} },
        .{ .packet_type = .handshake, .expected_first_byte = 0xf0, .token = &[_]u8{} },
    };

    for (cases) |case| {
        const input = LongHeader{
            .version = .v2,
            .dcid = &[_]u8{ 0xaa, 0xbb },
            .scid = &[_]u8{ 0x11, 0x22 },
            .packet_type = case.packet_type,
            .token = case.token,
            .packet_number = 0,
            .payload_length = 1,
        };

        var raw: [64]u8 = undefined;
        var out = buffer.fixedWriter(&raw);
        try encodeLongHeader(out.writer(), input);
        try std.testing.expectEqual(case.expected_first_byte, out.getWritten()[0]);

        var in = buffer.fixedReader(out.getWritten());
        var parsed = try parseLongHeader(in.reader(), std.testing.allocator);
        defer deinitLongHeader(&parsed, std.testing.allocator);

        try std.testing.expectEqual(Version.v2, parsed.version);
        try std.testing.expectEqual(case.packet_type, parsed.packet_type);
        try std.testing.expectEqualSlices(u8, case.token, parsed.token);
    }
}

test "encode/parse long packet roundtrip derives payload length" {
    const input = LongPacket{
        .header = .{
            .version = .v1,
            .dcid = &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd },
            .scid = &[_]u8{ 0x11, 0x22 },
            .packet_type = .initial,
            .token = &[_]u8{ 0xde, 0xad },
            .packet_number = 0x1234,
            .payload_length = 999,
        },
        .payload = &[_]u8{ 0x06, 0x00, 0x00, 0x42 },
    };

    var raw: [256]u8 = undefined;
    var out = buffer.fixedWriter(&raw);
    try encodeLongPacket(out.writer(), input);

    var parsed = try parseLongPacket(out.getWritten(), std.testing.allocator);
    defer deinitLongPacket(&parsed.packet, std.testing.allocator);

    try std.testing.expectEqual(out.getWritten().len, parsed.len);
    try std.testing.expectEqual(input.header.version, parsed.packet.header.version);
    try std.testing.expectEqual(input.header.packet_type, parsed.packet.header.packet_type);
    try std.testing.expectEqual(input.header.packet_number, parsed.packet.header.packet_number);
    try std.testing.expectEqual(@as(u64, input.payload.len), parsed.packet.header.payload_length);
    try std.testing.expectEqualSlices(u8, input.header.dcid, parsed.packet.header.dcid);
    try std.testing.expectEqualSlices(u8, input.header.scid, parsed.packet.header.scid);
    try std.testing.expectEqualSlices(u8, input.header.token, parsed.packet.header.token);
    try std.testing.expectEqualSlices(u8, input.payload, parsed.packet.payload);
}

test "long header reconstructs packet number from explicit wire encoding" {
    const full_packet_number: u64 = 0xa82f9b32;
    const expected_packet_number: u64 = 0xa82f30eb;
    const encoding = PacketNumberEncoding{
        .len = 2,
        .truncated_packet_number = 0x9b32,
    };

    const input = LongHeader{
        .version = .v1,
        .dcid = &[_]u8{ 0xaa, 0xbb },
        .scid = &[_]u8{ 0x11, 0x22 },
        .packet_type = .handshake,
        .token = &[_]u8{},
        .packet_number = full_packet_number,
        .payload_length = 0,
    };

    var raw: [64]u8 = undefined;
    var out = buffer.fixedWriter(&raw);
    try encodeLongHeaderWithPacketNumberEncoding(out.writer(), input, encoding);

    try std.testing.expectEqual(@as(u8, 0xe1), out.getWritten()[0]);

    var in = buffer.fixedReader(out.getWritten());
    var parsed = try parseLongHeaderWithExpectedPacketNumber(
        in.reader(),
        std.testing.allocator,
        expected_packet_number,
    );
    defer deinitLongHeader(&parsed, std.testing.allocator);

    try std.testing.expectEqual(full_packet_number, parsed.packet_number);
    try std.testing.expectEqual(@as(u64, 0), parsed.payload_length);
}

test "long packet explicit packet number encoding reconstructs coalesced packet" {
    const full_packet_number: u64 = 0xa82f9b32;
    const expected_packet_number: u64 = 0xa82f30eb;
    const encoding = try encodePacketNumberForHeader(full_packet_number, 0xa82f30ea);
    const input = LongPacket{
        .header = .{
            .version = .v1,
            .dcid = &[_]u8{0xaa},
            .scid = &[_]u8{0xbb},
            .packet_type = .initial,
            .token = &[_]u8{0xcc},
            .packet_number = full_packet_number,
            .payload_length = 0,
        },
        .payload = &[_]u8{ 0x01, 0x02 },
    };

    var raw: [96]u8 = undefined;
    var out = buffer.fixedWriter(&raw);
    try encodeLongPacketWithPacketNumberEncoding(out.writer(), input, encoding);
    const packet_len = out.getWritten().len;
    try out.writeAll(&[_]u8{ 0xde, 0xad });

    var parsed = try parseLongPacketWithExpectedPacketNumber(
        out.getWritten(),
        std.testing.allocator,
        expected_packet_number,
    );
    defer deinitLongPacket(&parsed.packet, std.testing.allocator);

    try std.testing.expectEqual(packet_len, parsed.len);
    try std.testing.expectEqual(full_packet_number, parsed.packet.header.packet_number);
    try std.testing.expectEqualSlices(u8, input.payload, parsed.packet.payload);
}

test "explicit packet number encoding validates low bits and length" {
    const header = LongHeader{
        .version = .v1,
        .dcid = &[_]u8{0xaa},
        .scid = &[_]u8{0xbb},
        .packet_type = .handshake,
        .token = &[_]u8{},
        .packet_number = 0x1234,
        .payload_length = 0,
    };

    var raw: [64]u8 = undefined;
    var out = buffer.fixedWriter(&raw);
    try std.testing.expectError(error.InvalidPacketNumber, encodeLongHeaderWithPacketNumberEncoding(out.writer(), header, .{
        .len = 1,
        .truncated_packet_number = 0x35,
    }));
    try std.testing.expectError(error.InvalidPacketNumber, encodeLongHeaderWithPacketNumberEncoding(out.writer(), header, .{
        .len = 0,
        .truncated_packet_number = 0,
    }));
}

test "parseLongPacket returns consumed length for coalesced long packets" {
    const first = LongPacket{
        .header = .{
            .version = .v1,
            .dcid = &[_]u8{0xaa},
            .scid = &[_]u8{0x11},
            .packet_type = .initial,
            .token = &[_]u8{},
            .packet_number = 1,
            .payload_length = 0,
        },
        .payload = &[_]u8{0x01},
    };
    const second = LongPacket{
        .header = .{
            .version = .v1,
            .dcid = &[_]u8{0xbb},
            .scid = &[_]u8{0x22},
            .packet_type = .handshake,
            .token = &[_]u8{},
            .packet_number = 2,
            .payload_length = 0,
        },
        .payload = &[_]u8{ 0x02, 0x03 },
    };

    var raw: [128]u8 = undefined;
    var out = buffer.fixedWriter(&raw);
    try encodeLongPacket(out.writer(), first);
    const first_len = out.getWritten().len;
    try encodeLongPacket(out.writer(), second);

    var parsed_first = try parseLongPacket(out.getWritten(), std.testing.allocator);
    defer deinitLongPacket(&parsed_first.packet, std.testing.allocator);
    try std.testing.expectEqual(first_len, parsed_first.len);
    try std.testing.expectEqual(PacketType.initial, parsed_first.packet.header.packet_type);
    try std.testing.expectEqualSlices(u8, first.payload, parsed_first.packet.payload);

    var parsed_second = try parseLongPacket(out.getWritten()[parsed_first.len..], std.testing.allocator);
    defer deinitLongPacket(&parsed_second.packet, std.testing.allocator);
    try std.testing.expectEqual(PacketType.handshake, parsed_second.packet.header.packet_type);
    try std.testing.expectEqualSlices(u8, second.payload, parsed_second.packet.payload);
}

test "encode/parse short header roundtrip" {
    var out: [256]u8 = undefined;
    var writer_fbs = buffer.fixedWriter(&out);

    const input = ShortHeader{
        .dcid = &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
        .spin_bit = true,
        .key_phase = true,
        .packet_number = 0x010203,
    };

    try encodeShortHeader(writer_fbs.writer(), input);

    const encoded = writer_fbs.getWritten();
    try std.testing.expectEqual(@as(usize, 10), encoded.len);
    try std.testing.expectEqual(@as(u8, 0x66), encoded[0]);
    var reader_fbs = buffer.fixedReader(encoded);
    var parsed = try parseShortHeader(reader_fbs.reader(), std.testing.allocator, input.dcid.len);
    defer deinitShortHeader(&parsed, std.testing.allocator);

    try std.testing.expectEqual(input.spin_bit, parsed.spin_bit);
    try std.testing.expectEqual(input.key_phase, parsed.key_phase);
    try std.testing.expectEqual(input.packet_number, parsed.packet_number);
    try std.testing.expectEqualSlices(u8, input.dcid, parsed.dcid);
}

test "short header reconstructs packet number from explicit wire encoding" {
    const full_packet_number: u64 = 0xa82f9b32;
    const expected_packet_number: u64 = 0xa82f30eb;
    const encoding = PacketNumberEncoding{
        .len = 2,
        .truncated_packet_number = 0x9b32,
    };
    const input = ShortHeader{
        .dcid = &[_]u8{ 0xde, 0xad, 0xbe, 0xef },
        .spin_bit = true,
        .key_phase = true,
        .packet_number = full_packet_number,
    };

    var raw: [32]u8 = undefined;
    var out = buffer.fixedWriter(&raw);
    try encodeShortHeaderWithPacketNumberEncoding(out.writer(), input, encoding);

    try std.testing.expectEqual(@as(u8, 0x65), out.getWritten()[0]);

    var in = buffer.fixedReader(out.getWritten());
    var parsed = try parseShortHeaderWithExpectedPacketNumber(
        in.reader(),
        std.testing.allocator,
        input.dcid.len,
        expected_packet_number,
    );
    defer deinitShortHeader(&parsed, std.testing.allocator);

    try std.testing.expectEqual(input.spin_bit, parsed.spin_bit);
    try std.testing.expectEqual(input.key_phase, parsed.key_phase);
    try std.testing.expectEqual(full_packet_number, parsed.packet_number);
    try std.testing.expectEqualSlices(u8, input.dcid, parsed.dcid);
}

test "encode/parse short packet roundtrip consumes remaining payload" {
    const input = ShortPacket{
        .header = .{
            .dcid = &[_]u8{ 0xde, 0xad, 0xbe, 0xef },
            .key_phase = false,
            .packet_number = 0x123,
        },
        .payload = &[_]u8{ 0x40, 0x41, 0x42 },
    };

    var raw: [64]u8 = undefined;
    var out = buffer.fixedWriter(&raw);
    try encodeShortPacket(out.writer(), input);

    var parsed = try parseShortPacket(out.getWritten(), std.testing.allocator, input.header.dcid.len);
    defer deinitShortPacket(&parsed, std.testing.allocator);

    try std.testing.expectEqual(input.header.key_phase, parsed.header.key_phase);
    try std.testing.expectEqual(input.header.packet_number, parsed.header.packet_number);
    try std.testing.expectEqualSlices(u8, input.header.dcid, parsed.header.dcid);
    try std.testing.expectEqualSlices(u8, input.payload, parsed.payload);
}

test "short packet explicit packet number encoding reconstructs full packet number" {
    const full_packet_number: u64 = 0xa82f9b32;
    const expected_packet_number: u64 = 0xa82f30eb;
    const encoding = PacketNumberEncoding{
        .len = 2,
        .truncated_packet_number = 0x9b32,
    };
    const input = ShortPacket{
        .header = .{
            .dcid = &[_]u8{ 0xca, 0xfe },
            .spin_bit = true,
            .key_phase = true,
            .packet_number = full_packet_number,
        },
        .payload = &[_]u8{ 0x01, 0x02, 0x03 },
    };

    var raw: [64]u8 = undefined;
    var out = buffer.fixedWriter(&raw);
    try encodeShortPacketWithPacketNumberEncoding(out.writer(), input, encoding);

    var parsed = try parseShortPacketWithExpectedPacketNumber(
        out.getWritten(),
        std.testing.allocator,
        input.header.dcid.len,
        expected_packet_number,
    );
    defer deinitShortPacket(&parsed, std.testing.allocator);

    try std.testing.expectEqual(input.header.spin_bit, parsed.header.spin_bit);
    try std.testing.expectEqual(input.header.key_phase, parsed.header.key_phase);
    try std.testing.expectEqual(full_packet_number, parsed.header.packet_number);
    try std.testing.expectEqualSlices(u8, input.header.dcid, parsed.header.dcid);
    try std.testing.expectEqualSlices(u8, input.payload, parsed.payload);
}

test "parseShortPacket preserves payload allocation failures" {
    const input = ShortPacket{
        .header = .{
            .dcid = &[_]u8{0xaa},
            .key_phase = false,
            .packet_number = 1,
        },
        .payload = &[_]u8{0xbb},
    };

    var raw: [16]u8 = undefined;
    var out = buffer.fixedWriter(&raw);
    try encodeShortPacket(out.writer(), input);

    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
    try std.testing.expectError(
        error.OutOfMemory,
        parseShortPacket(out.getWritten(), failing_allocator.allocator(), input.header.dcid.len),
    );
}

test "encode/parse version negotiation packet roundtrip with long connection ids" {
    var dcid: [21]u8 = undefined;
    for (&dcid, 0..) |*byte, i| byte.* = @as(u8, @intCast(i));

    var scid: [22]u8 = undefined;
    for (&scid, 0..) |*byte, i| byte.* = @as(u8, @intCast(0x80 + i));

    const versions = [_]Version{ .v1, .v2 };
    const input = VersionNegotiationPacket{
        .dcid = &dcid,
        .scid = &scid,
        .versions = &versions,
    };

    var out: [128]u8 = undefined;
    var writer_fbs = buffer.fixedWriter(&out);
    try encodeVersionNegotiationPacket(writer_fbs.writer(), input);

    const encoded = writer_fbs.getWritten();
    try std.testing.expectEqual(@as(u8, 0xc0), encoded[0]);

    var parsed = try parseVersionNegotiationPacket(encoded, std.testing.allocator);
    defer deinitVersionNegotiationPacket(&parsed, std.testing.allocator);

    try std.testing.expectEqualSlices(u8, input.dcid, parsed.dcid);
    try std.testing.expectEqualSlices(u8, input.scid, parsed.scid);
    try std.testing.expectEqualSlices(Version, input.versions, parsed.versions);
}

test "reserved version helper matches QUIC greasing pattern" {
    try std.testing.expect(isReservedVersion(@enumFromInt(0x0a0a0a0a)));
    try std.testing.expect(isReservedVersion(@enumFromInt(0x1a2a3a4a)));
    try std.testing.expect(isReservedVersion(@enumFromInt(0xfafafafa)));
    try std.testing.expect(!isReservedVersion(Version.v1));
    try std.testing.expect(!isReservedVersion(Version.v2));
    try std.testing.expect(!isReservedVersion(@enumFromInt(0x00000000)));
    try std.testing.expect(!isReservedVersion(@enumFromInt(0xfaceb00c)));
}

test "version negotiation parser ignores unused first-byte bits" {
    const wire = [_]u8{
        0x80, // Header Form = long; unused bits all zero and fixed bit absent.
        0x00, 0x00, 0x00, 0x00, // Version Negotiation
        0x01, 0xaa, // DCID
        0x01, 0xbb, // SCID
        0x00, 0x00, 0x00, 0x01, // QUIC v1
    };

    var parsed = try parseVersionNegotiationPacket(&wire, std.testing.allocator);
    defer deinitVersionNegotiationPacket(&parsed, std.testing.allocator);

    try std.testing.expectEqualSlices(u8, &[_]u8{0xaa}, parsed.dcid);
    try std.testing.expectEqualSlices(u8, &[_]u8{0xbb}, parsed.scid);
    try std.testing.expectEqual(@as(usize, 1), parsed.versions.len);
    try std.testing.expectEqual(Version.v1, parsed.versions[0]);
}

test "version negotiation packet rejects empty and truncated version lists" {
    const empty_versions = [_]u8{
        0x80,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };
    try std.testing.expectError(error.InvalidVersionList, parseVersionNegotiationPacket(&empty_versions, std.testing.allocator));

    const truncated_version = [_]u8{
        0x80,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };
    try std.testing.expectError(error.InvalidVersionList, parseVersionNegotiationPacket(&truncated_version, std.testing.allocator));
}

test "version negotiation packet rejects zero supported versions" {
    const zero_supported_version = [_]u8{
        0x80,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0xaa,
        0x01,
        0xbb,
        0x00,
        0x00,
        0x00,
        0x00,
    };
    try std.testing.expectError(error.InvalidVersionList, parseVersionNegotiationPacket(&zero_supported_version, std.testing.allocator));

    var raw: [32]u8 = undefined;
    var writer = buffer.fixedWriter(&raw);
    const zero_versions = [_]Version{@enumFromInt(0)};
    try std.testing.expectError(error.InvalidVersionList, encodeVersionNegotiationPacket(writer.writer(), .{
        .dcid = &[_]u8{0xaa},
        .scid = &[_]u8{0xbb},
        .versions = &zero_versions,
    }));
}

test "version negotiation packet validates header form and version field" {
    const short_form = [_]u8{
        0x00,
    };
    try std.testing.expectError(error.InvalidHeaderForm, parseVersionNegotiationPacket(&short_form, std.testing.allocator));

    const non_zero_version = [_]u8{
        0x80,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
    };
    try std.testing.expectError(error.InvalidVersionNegotiation, parseVersionNegotiationPacket(&non_zero_version, std.testing.allocator));
}

test "version negotiation packet preserves allocation failures" {
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const wire = [_]u8{
        0x80,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0xaa,
        0x01,
        0xbb,
        0x00,
        0x00,
        0x00,
        0x01,
    };

    try std.testing.expectError(error.OutOfMemory, parseVersionNegotiationPacket(&wire, failing_allocator.allocator()));
}

test "encode/parse retry packet roundtrip" {
    const input = RetryPacket{
        .version = .v1,
        .dcid = &[_]u8{ 0xaa, 0xbb },
        .scid = &[_]u8{ 0x11, 0x22, 0x33 },
        .token = &[_]u8{ 0xde, 0xad, 0xbe, 0xef },
        .integrity_tag = .{
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f,
        },
    };

    var out: [64]u8 = undefined;
    var writer_fbs = buffer.fixedWriter(&out);
    try encodeRetryPacket(writer_fbs.writer(), input);

    const encoded = writer_fbs.getWritten();
    try std.testing.expectEqual(@as(u8, 0xf0), encoded[0]);

    var parsed = try parseRetryPacket(encoded, std.testing.allocator);
    defer deinitRetryPacket(&parsed, std.testing.allocator);

    try std.testing.expectEqual(input.version, parsed.version);
    try std.testing.expectEqualSlices(u8, input.dcid, parsed.dcid);
    try std.testing.expectEqualSlices(u8, input.scid, parsed.scid);
    try std.testing.expectEqualSlices(u8, input.token, parsed.token);
    try std.testing.expectEqualSlices(u8, &input.integrity_tag, &parsed.integrity_tag);
}

test "encode/parse QUIC v2 retry packet type bits" {
    const input = RetryPacket{
        .version = .v2,
        .dcid = &[_]u8{ 0xaa, 0xbb },
        .scid = &[_]u8{ 0x11, 0x22 },
        .token = &[_]u8{ 0xde, 0xad },
        .integrity_tag = .{
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f,
        },
    };

    var raw: [64]u8 = undefined;
    var out = buffer.fixedWriter(&raw);
    try encodeRetryPacket(out.writer(), input);
    try std.testing.expectEqual(@as(u8, 0xc0), out.getWritten()[0]);

    var parsed = try parseRetryPacket(out.getWritten(), std.testing.allocator);
    defer deinitRetryPacket(&parsed, std.testing.allocator);

    try std.testing.expectEqual(Version.v2, parsed.version);
    try std.testing.expectEqualSlices(u8, input.dcid, parsed.dcid);
    try std.testing.expectEqualSlices(u8, input.scid, parsed.scid);
    try std.testing.expectEqualSlices(u8, input.token, parsed.token);
    try std.testing.expectEqualSlices(u8, &input.integrity_tag, &parsed.integrity_tag);
}

test "retry parser ignores unused bits" {
    const wire = [_]u8{
        0xff, // Long + fixed + retry + unused bits set.
        0x00,
        0x00,
        0x00,
        0x01,
        0x01,
        0xaa,
        0x01,
        0xbb,
        0xcc,
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
    };

    var parsed = try parseRetryPacket(&wire, std.testing.allocator);
    defer deinitRetryPacket(&parsed, std.testing.allocator);

    try std.testing.expectEqual(Version.v1, parsed.version);
    try std.testing.expectEqualSlices(u8, &[_]u8{0xcc}, parsed.token);

    const v2_wire = [_]u8{
        0xcf, // Long + fixed + v2 retry + unused bits set.
        0x6b,
        0x33,
        0x43,
        0xcf,
        0x01,
        0xaa,
        0x01,
        0xbb,
        0xcc,
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
    };
    var parsed_v2 = try parseRetryPacket(&v2_wire, std.testing.allocator);
    defer deinitRetryPacket(&parsed_v2, std.testing.allocator);

    try std.testing.expectEqual(Version.v2, parsed_v2.version);
    try std.testing.expectEqualSlices(u8, &[_]u8{0xcc}, parsed_v2.token);
}

test "stateless reset helpers encode and match trailing token" {
    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const prefix = [_]u8{ 0x40, 0xaa, 0xbb, 0xcc, 0xdd };

    var raw: [min_stateless_reset_datagram_len]u8 = undefined;
    var out = buffer.fixedWriter(&raw);
    try encodeStatelessReset(out.writer(), &prefix, token);

    const datagram = out.getWritten();
    try std.testing.expectEqual(@as(usize, min_stateless_reset_datagram_len), datagram.len);
    try std.testing.expect(matchesStatelessReset(datagram, token));
    try std.testing.expectEqualSlices(u8, &token, &statelessResetTokenCandidate(datagram).?);
}

test "stateless reset helpers reject short datagrams and false tokens" {
    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const other = [_]u8{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    const too_short = [_]u8{ 0x40, 0xaa, 0xbb, 0xcc };

    try std.testing.expectEqual(@as(?[stateless_reset_token_len]u8, null), statelessResetTokenCandidate(&too_short));
    try std.testing.expect(!matchesStatelessReset(&too_short, token));

    var raw: [min_stateless_reset_datagram_len]u8 = undefined;
    var out = buffer.fixedWriter(&raw);
    try encodeStatelessReset(out.writer(), &[_]u8{ 0x40, 0xaa, 0xbb, 0xcc, 0xdd }, token);
    try std.testing.expect(!matchesStatelessReset(out.getWritten(), other));
    try std.testing.expectError(error.InvalidLength, encodeStatelessReset(out.writer(), &[_]u8{ 0x40, 0xaa }, token));
}

test "retry packet rejects empty token and invalid header fields" {
    const empty_token = [_]u8{
        0xf0,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
    };
    try std.testing.expectError(error.InvalidRetryPacket, parseRetryPacket(&empty_token, std.testing.allocator));

    const short_form = [_]u8{0x70};
    try std.testing.expectError(error.InvalidHeaderForm, parseRetryPacket(&short_form, std.testing.allocator));

    const missing_fixed = [_]u8{0xb0};
    try std.testing.expectError(error.InvalidFixedBit, parseRetryPacket(&missing_fixed, std.testing.allocator));

    const initial_type = [_]u8{
        0xc0,
        0x00,
        0x00,
        0x00,
        0x01,
    };
    try std.testing.expectError(error.InvalidRetryPacket, parseRetryPacket(&initial_type, std.testing.allocator));
}

test "retry packet validates connection id lengths and allocation failures" {
    const too_long_dcid = [_]u8{
        0xf0,
        0x00,
        0x00,
        0x00,
        0x01,
        0x15,
    };
    try std.testing.expectError(error.InvalidConnectionIdLength, parseRetryPacket(&too_long_dcid, std.testing.allocator));

    const input = RetryPacket{
        .version = .v1,
        .dcid = &[_]u8{0xaa},
        .scid = &[_]u8{0xbb},
        .token = &[_]u8{0xcc},
        .integrity_tag = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    };

    var raw: [32]u8 = undefined;
    var writer = buffer.fixedWriter(&raw);
    try encodeRetryPacket(writer.writer(), input);

    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, parseRetryPacket(writer.getWritten(), failing_allocator.allocator()));
}

test "retry packet rejects zero version" {
    const input = RetryPacket{
        .version = @enumFromInt(0),
        .dcid = &[_]u8{0xaa},
        .scid = &[_]u8{0xbb},
        .token = &[_]u8{0xcc},
        .integrity_tag = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    };

    var raw: [32]u8 = undefined;
    var writer = buffer.fixedWriter(&raw);
    try std.testing.expectError(error.InvalidVersionNegotiation, encodeRetryPacket(writer.writer(), input));

    const wire = [_]u8{
        0xf0, // long + fixed + v1-style retry bits
        0x00,
        0x00,
        0x00,
        0x00,
    };
    try std.testing.expectError(error.InvalidVersionNegotiation, parseRetryPacket(&wire, std.testing.allocator));
}

test "reconstructPacketNumber follows RFC 9000 sample" {
    const largest_authenticated = 0xa82f30ea;
    const expected_packet_number = largest_authenticated + 1;

    try std.testing.expectEqual(
        @as(u64, 0xa82f9b32),
        try reconstructPacketNumber(expected_packet_number, 0x9b32, 2),
    );
}

test "encodePacketNumberForHeader follows RFC 9000 sample" {
    const largest_acked = 0xabe8b3;

    const two_byte = try encodePacketNumberForHeader(0xac5c02, largest_acked);
    try std.testing.expectEqual(@as(u8, 2), two_byte.len);
    try std.testing.expectEqual(@as(u32, 0x5c02), two_byte.truncated_packet_number);

    const three_byte = try encodePacketNumberForHeader(0xace8fe, largest_acked);
    try std.testing.expectEqual(@as(u8, 3), three_byte.len);
    try std.testing.expectEqual(@as(u32, 0xace8fe), three_byte.truncated_packet_number);
}

test "encodePacketNumberForHeader handles no-ack boundaries" {
    const one_byte = try encodePacketNumberForHeader(0x7f, null);
    try std.testing.expectEqual(@as(u8, 1), one_byte.len);
    try std.testing.expectEqual(@as(u32, 0x7f), one_byte.truncated_packet_number);

    const two_byte = try encodePacketNumberForHeader(0x80, null);
    try std.testing.expectEqual(@as(u8, 2), two_byte.len);
    try std.testing.expectEqual(@as(u32, 0x80), two_byte.truncated_packet_number);

    const four_byte = try encodePacketNumberForHeader((@as(u64, 1) << 31) - 1, null);
    try std.testing.expectEqual(@as(u8, 4), four_byte.len);
    try std.testing.expectEqual(@as(u32, 0x7fffffff), four_byte.truncated_packet_number);
}

test "encodePacketNumberForHeader validates packet number range and ack state" {
    try std.testing.expectError(error.InvalidPacketNumber, encodePacketNumberForHeader(max_packet_number + 1, null));
    try std.testing.expectError(error.InvalidPacketNumber, encodePacketNumberForHeader(10, 10));
    try std.testing.expectError(error.InvalidPacketNumber, encodePacketNumberForHeader(10, 11));
    try std.testing.expectError(error.InvalidPacketNumber, encodePacketNumberForHeader((@as(u64, 1) << 31), null));
}

test "reconstructPacketNumber selects closest packet number window" {
    try std.testing.expectEqual(@as(u64, 0xff), try reconstructPacketNumber(0x100, 0xff, 1));
    try std.testing.expectEqual(@as(u64, 0x200), try reconstructPacketNumber(0x180, 0x00, 1));
    try std.testing.expectEqual(@as(u64, 0x1f0), try reconstructPacketNumber(0x250, 0xf0, 1));
}

test "reconstructPacketNumber validates packet number length and truncated value" {
    try std.testing.expectError(error.InvalidPacketNumber, reconstructPacketNumber(0, 0, 0));
    try std.testing.expectError(error.InvalidPacketNumber, reconstructPacketNumber(0, 0, 5));
    try std.testing.expectError(error.InvalidPacketNumber, reconstructPacketNumber(0, 0x100, 1));
}

test "reconstructPacketNumber enforces QUIC packet number limit" {
    try std.testing.expectEqual(
        max_packet_number,
        try reconstructPacketNumber(max_packet_number + 1, 0xffffffff, 4),
    );
    try std.testing.expectError(error.InvalidPacketNumber, reconstructPacketNumber(max_packet_number + 2, 0, 1));
    try std.testing.expectError(error.InvalidPacketNumber, reconstructPacketNumber(max_packet_number, 0, 1));
}

test "parse long header rejects length shorter than packet number" {
    const wire = [_]u8{
        0xc1, // long + fixed + initial + 2-byte packet number
        0x00, 0x00, 0x00, 0x01, // QUIC v1
        0x00, // DCID len
        0x00, // SCID len
        0x00, // token len
        0x01, // length shorter than the 2-byte packet number
    };

    var in = buffer.fixedReader(&wire);
    try std.testing.expectError(error.InvalidLength, parseLongHeader(in.reader(), std.testing.allocator));
}

test "long header rejects non-zero reserved bits" {
    const wire = [_]u8{
        0xcc, // long + fixed + initial + reserved bits set
    };

    var in = buffer.fixedReader(&wire);
    try std.testing.expectError(error.InvalidReservedBits, parseLongHeader(in.reader(), std.testing.allocator));
}

test "versioned long headers reject zero version" {
    const input = LongHeader{
        .version = @enumFromInt(0),
        .dcid = &[_]u8{0xaa},
        .scid = &[_]u8{0xbb},
        .packet_type = .initial,
        .token = &[_]u8{},
        .packet_number = 0,
        .payload_length = 0,
    };

    var raw: [32]u8 = undefined;
    var writer = buffer.fixedWriter(&raw);
    try std.testing.expectError(error.InvalidVersionNegotiation, encodeLongHeader(writer.writer(), input));

    const wire = [_]u8{
        0xc0, // long + fixed + initial
        0x00,
        0x00,
        0x00,
        0x00,
    };
    var in = buffer.fixedReader(&wire);
    try std.testing.expectError(error.InvalidVersionNegotiation, parseLongHeader(in.reader(), std.testing.allocator));
}

test "long header rejects oversized length varints before writing" {
    var raw: [64]u8 = undefined;
    var writer = buffer.fixedWriter(&raw);

    const oversized_payload = LongHeader{
        .version = .v1,
        .dcid = &[_]u8{0xaa},
        .scid = &[_]u8{0xbb},
        .packet_type = .handshake,
        .token = &[_]u8{},
        .packet_number = 0,
        .payload_length = max_quic_varint,
    };
    try std.testing.expectError(error.InvalidLength, encodeLongHeader(writer.writer(), oversized_payload));
    try std.testing.expectEqual(@as(usize, 0), writer.getWritten().len);

    const oversized_token_len = std.math.cast(usize, max_quic_varint + 1) orelse return error.SkipZigTest;
    const oversized_token: []const u8 = @as([*]const u8, @ptrFromInt(1))[0..oversized_token_len];
    const oversized_initial_token = LongHeader{
        .version = .v1,
        .dcid = &[_]u8{0xaa},
        .scid = &[_]u8{0xbb},
        .packet_type = .initial,
        .token = oversized_token,
        .packet_number = 0,
        .payload_length = 0,
    };

    writer = buffer.fixedWriter(&raw);
    try std.testing.expectError(error.InvalidLength, encodeLongHeader(writer.writer(), oversized_initial_token));
    try std.testing.expectEqual(@as(usize, 0), writer.getWritten().len);
}

test "retry long header is outside the minimal codec" {
    var out: [64]u8 = undefined;
    var writer_fbs = buffer.fixedWriter(&out);

    const retry = LongHeader{
        .version = .v1,
        .dcid = &[_]u8{0xaa},
        .scid = &[_]u8{0xbb},
        .packet_type = .retry,
        .token = &[_]u8{},
        .packet_number = 0,
        .payload_length = 0,
    };
    try std.testing.expectError(error.UnsupportedPacketType, encodeLongHeader(writer_fbs.writer(), retry));

    const wire = [_]u8{
        0xf0, // long + fixed + v1 retry
        0x00,
        0x00,
        0x00,
        0x01,
    };
    var in = buffer.fixedReader(&wire);
    try std.testing.expectError(error.UnsupportedPacketType, parseLongHeader(in.reader(), std.testing.allocator));

    const v2_wire = [_]u8{
        0xc0, // long + fixed + v2 retry
        0x6b,
        0x33,
        0x43,
        0xcf,
    };
    var v2_in = buffer.fixedReader(&v2_wire);
    try std.testing.expectError(error.UnsupportedPacketType, parseLongHeader(v2_in.reader(), std.testing.allocator));
}

test "parse long header frees token when trailing length is invalid" {
    const wire = [_]u8{
        0xc1, // long + fixed + initial + 2-byte packet number
        0x00, 0x00, 0x00, 0x01, // QUIC v1
        0x00, // DCID len
        0x00, // SCID len
        0x01, // token len
        0xaa, // token
        0x01, // length shorter than the 2-byte packet number
    };

    var in = buffer.fixedReader(&wire);
    try std.testing.expectError(error.InvalidLength, parseLongHeader(in.reader(), std.testing.allocator));
}

test "parseLongPacket rejects truncated payload length" {
    const input = LongHeader{
        .version = .v1,
        .dcid = &[_]u8{0xaa},
        .scid = &[_]u8{0xbb},
        .packet_type = .handshake,
        .token = &[_]u8{},
        .packet_number = 1,
        .payload_length = 3,
    };

    var raw: [64]u8 = undefined;
    var out = buffer.fixedWriter(&raw);
    try encodeLongHeader(out.writer(), input);
    try out.writeByte(0x01);

    try std.testing.expectError(error.InvalidLength, parseLongPacket(out.getWritten(), std.testing.allocator));
}

test "parseLongPacket preserves payload allocation failures" {
    const input = LongPacket{
        .header = .{
            .version = .v1,
            .dcid = &[_]u8{0xaa},
            .scid = &[_]u8{0xbb},
            .packet_type = .handshake,
            .token = &[_]u8{},
            .packet_number = 1,
            .payload_length = 0,
        },
        .payload = &[_]u8{ 0x01, 0x02, 0x03 },
    };

    var raw: [64]u8 = undefined;
    var out = buffer.fixedWriter(&raw);
    try encodeLongPacket(out.writer(), input);

    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 2 });
    try std.testing.expectError(error.OutOfMemory, parseLongPacket(out.getWritten(), failing_allocator.allocator()));
}

test "parse long header rejects truncated token before allocating" {
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 2 });
    const wire = [_]u8{
        0xc0, // long + fixed + initial + 1-byte packet number
        0x00, 0x00, 0x00, 0x01, // QUIC v1
        0x01, // DCID len
        0xaa, // DCID
        0x01, // SCID len
        0xbb, // SCID
        0x40, 0x40, // token len 64, no token bytes left
    };

    var in = buffer.fixedReader(&wire);
    try std.testing.expectError(error.EndOfStream, parseLongHeader(in.reader(), failing_allocator.allocator()));
}

test "parse short header rejects invalid caller dcid length" {
    const wire = [_]u8{0x40};

    var in = buffer.fixedReader(&wire);
    try std.testing.expectError(error.InvalidConnectionIdLength, parseShortHeader(in.reader(), std.testing.allocator, 21));
}

test "short header rejects non-zero reserved bits" {
    const wire = [_]u8{
        0x58, // short + fixed + reserved bits set
    };

    var in = buffer.fixedReader(&wire);
    try std.testing.expectError(error.InvalidReservedBits, parseShortHeader(in.reader(), std.testing.allocator, 0));
}

test "encodeVarInt rejects values outside QUIC range" {
    var out: [8]u8 = undefined;
    var fbs = buffer.fixedWriter(&out);

    try std.testing.expectError(error.InvalidVarInt, encodeVarInt(fbs.writer(), 4611686018427387904));
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
        var fbs = buffer.fixedWriter(&out);
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
        var fbs = buffer.fixedReader(c.encoded);
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
        var fbs = buffer.fixedReader(encoded);
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
        var writer_fbs = buffer.fixedWriter(&out);
        try encodeVarInt(writer_fbs.writer(), value);

        const encoded = writer_fbs.getWritten();
        var reader_fbs = buffer.fixedReader(encoded);
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
        var fbs = buffer.fixedWriter(&out);
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
        var fbs = buffer.fixedReader(c.encoded);
        const decoded = try decodeVarInt(fbs.reader());

        try std.testing.expectEqual(c.expected_value, decoded.value);
        try std.testing.expectEqual(c.expected_len, decoded.len);
        try std.testing.expectEqual(c.encoded.len, fbs.pos);
    }
}
