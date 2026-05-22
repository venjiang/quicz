const std = @import("std");
const buffer = @import("buffer.zig");
const packet = @import("packet.zig");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

const max_connection_id_len = 20;

/// RFC 9001 QUIC v1 Initial salt.
pub const initial_salt_v1 = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

pub const initial_secret_len = HkdfSha256.prk_length;
pub const aes_128_key_len = 16;
pub const iv_len = 12;
pub const aes_128_hp_key_len = 16;
pub const aead_tag_len = Aes128Gcm.tag_length;
pub const header_protection_sample_len = 16;
pub const header_protection_mask_len = 5;

/// RFC 9001 fixed key used only for Retry Integrity Tag generation.
pub const retry_integrity_key = [_]u8{
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};

/// RFC 9001 fixed nonce used only for Retry Integrity Tag generation.
pub const retry_integrity_nonce = [_]u8{
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
};

pub const ProtectionError = error{
    UnsupportedVersion,
    InvalidConnectionIdLength,
    InvalidPacketNumber,
    InvalidPacketNumberLength,
    InvalidPayloadLength,
    AuthenticationFailed,
};

/// Packet protection material derived from one QUIC packet protection secret.
pub const Aes128PacketProtectionKeys = struct {
    /// Packet protection secret for one endpoint direction.
    secret: [initial_secret_len]u8,
    /// AEAD_AES_128_GCM packet protection key.
    key: [aes_128_key_len]u8,
    /// Per-direction packet protection IV.
    iv: [iv_len]u8,
    /// AES header protection key.
    hp: [aes_128_hp_key_len]u8,
};

/// RFC 9001 Initial packet protection keys for both endpoint directions.
pub const InitialSecrets = struct {
    /// HKDF-Extract output shared by both Initial directions.
    initial_secret: [initial_secret_len]u8,
    /// Keys used by clients to protect Initial packets.
    client: Aes128PacketProtectionKeys,
    /// Keys used by servers to protect Initial packets.
    server: Aes128PacketProtectionKeys,
};

/// Long-header packet opened after QUIC packet protection is removed.
pub const OpenedLongPacket = struct {
    /// Unprotected long-header fields. `payload_length` preserves the protected
    /// wire payload length, including the AEAD authentication tag.
    header: packet.LongHeader,
    /// Decrypted QUIC packet payload bytes.
    plaintext: []const u8,
};

/// Opened long-header packet plus the number of datagram bytes consumed.
pub const DecodedProtectedLongPacket = struct {
    packet: OpenedLongPacket,
    len: usize,
};

/// Derive RFC 9001 QUIC v1 Initial packet protection keys.
///
/// `client_initial_dcid` is the Destination Connection ID from the first client
/// Initial packet. QUIC v2 uses a different salt and is intentionally rejected
/// until v2 support is in scope.
pub fn deriveInitialSecrets(
    version: packet.Version,
    client_initial_dcid: []const u8,
) ProtectionError!InitialSecrets {
    if (client_initial_dcid.len > max_connection_id_len) return error.InvalidConnectionIdLength;
    const salt = switch (version) {
        .v1 => &initial_salt_v1,
        else => return error.UnsupportedVersion,
    };

    const initial_secret = HkdfSha256.extract(salt, client_initial_dcid);
    const client_secret = hkdfExpandLabel(initial_secret, "client in", initial_secret_len);
    const server_secret = hkdfExpandLabel(initial_secret, "server in", initial_secret_len);

    return .{
        .initial_secret = initial_secret,
        .client = deriveAes128PacketProtectionKeys(client_secret),
        .server = deriveAes128PacketProtectionKeys(server_secret),
    };
}

/// Produce the RFC 9001 AES-based header protection mask.
///
/// AES-GCM QUIC cipher suites use AES-ECB over a 16-byte ciphertext sample and
/// consume the first five mask bytes for the first header byte and packet number.
pub fn aes128HeaderProtectionMask(
    hp_key: [aes_128_hp_key_len]u8,
    sample: [header_protection_sample_len]u8,
) [header_protection_mask_len]u8 {
    const aes = std.crypto.core.aes.Aes128.initEnc(hp_key);
    var block: [header_protection_sample_len]u8 = undefined;
    aes.encrypt(&block, &sample);
    return block[0..header_protection_mask_len].*;
}

/// Apply or remove a QUIC header protection mask in place.
///
/// Header protection is XOR-based, so applying the same mask twice restores the
/// original first byte and encoded packet number bytes.
pub fn applyHeaderProtectionMask(
    header_form: packet.HeaderForm,
    first_byte: *u8,
    packet_number_bytes: []u8,
    mask: [header_protection_mask_len]u8,
) ProtectionError!void {
    if (packet_number_bytes.len == 0 or packet_number_bytes.len > 4) return error.InvalidPacketNumberLength;
    const first_byte_mask: u8 = switch (header_form) {
        .long => 0x0f,
        .short => 0x1f,
    };
    first_byte.* ^= mask[0] & first_byte_mask;
    for (packet_number_bytes, 0..) |*byte, i| {
        byte.* ^= mask[i + 1];
    }
}

/// Build the RFC 9001 AEAD nonce from a packet protection IV and packet number.
pub fn packetProtectionNonce(iv: [iv_len]u8, packet_number: u64) ProtectionError![iv_len]u8 {
    if (packet_number > packet.max_packet_number) return error.InvalidPacketNumber;
    var nonce = iv;
    var packet_number_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &packet_number_bytes, packet_number, .big);
    for (packet_number_bytes, 0..) |byte, i| {
        nonce[iv_len - packet_number_bytes.len + i] ^= byte;
    }
    return nonce;
}

/// Protect a QUIC packet payload with AEAD_AES_128_GCM.
///
/// `associated_data` is the unprotected QUIC header through the encoded packet
/// number. Header protection is applied separately after this step.
pub fn protectAes128Payload(
    keys: Aes128PacketProtectionKeys,
    packet_number: u64,
    associated_data: []const u8,
    plaintext: []const u8,
    ciphertext: []u8,
    tag: *[aead_tag_len]u8,
) ProtectionError!void {
    if (ciphertext.len != plaintext.len) return error.InvalidPayloadLength;
    const nonce = try packetProtectionNonce(keys.iv, packet_number);
    Aes128Gcm.encrypt(ciphertext, tag, plaintext, associated_data, nonce, keys.key);
}

/// Remove AEAD_AES_128_GCM protection from a QUIC packet payload.
pub fn unprotectAes128Payload(
    keys: Aes128PacketProtectionKeys,
    packet_number: u64,
    associated_data: []const u8,
    ciphertext: []const u8,
    tag: [aead_tag_len]u8,
    plaintext: []u8,
) ProtectionError!void {
    if (plaintext.len != ciphertext.len) return error.InvalidPayloadLength;
    const nonce = try packetProtectionNonce(keys.iv, packet_number);
    Aes128Gcm.decrypt(plaintext, ciphertext, tag, associated_data, nonce, keys.key) catch return error.AuthenticationFailed;
}

/// Compute the RFC 9001 Retry Integrity Tag for a transmitted Retry packet.
///
/// `retry_without_integrity_tag` is the exact Retry packet bytes as sent on the
/// wire, excluding the final 16-byte Retry Integrity Tag. The Original
/// Destination Connection ID comes from the client Initial packet that caused
/// this Retry and is prepended only in the Retry pseudo-packet.
pub fn retryIntegrityTag(
    allocator: std.mem.Allocator,
    original_destination_connection_id: []const u8,
    retry_without_integrity_tag: []const u8,
) ![aead_tag_len]u8 {
    if (original_destination_connection_id.len > max_connection_id_len) return error.InvalidConnectionIdLength;
    const pseudo_len = 1 + original_destination_connection_id.len + retry_without_integrity_tag.len;
    const pseudo_packet = try allocator.alloc(u8, pseudo_len);
    defer allocator.free(pseudo_packet);

    pseudo_packet[0] = @intCast(original_destination_connection_id.len);
    @memcpy(pseudo_packet[1..][0..original_destination_connection_id.len], original_destination_connection_id);
    @memcpy(pseudo_packet[1 + original_destination_connection_id.len ..], retry_without_integrity_tag);

    var ciphertext: [0]u8 = .{};
    const plaintext: [0]u8 = .{};
    var tag: [aead_tag_len]u8 = undefined;
    Aes128Gcm.encrypt(&ciphertext, &tag, &plaintext, pseudo_packet, retry_integrity_nonce, retry_integrity_key);
    return tag;
}

/// Verify the final 16 bytes of a Retry packet as the RFC 9001 Integrity Tag.
pub fn verifyRetryIntegrityTag(
    allocator: std.mem.Allocator,
    original_destination_connection_id: []const u8,
    retry_datagram: []const u8,
) !bool {
    if (retry_datagram.len <= aead_tag_len) return error.InvalidPayloadLength;
    const tag_offset = retry_datagram.len - aead_tag_len;
    const computed = try retryIntegrityTag(allocator, original_destination_connection_id, retry_datagram[0..tag_offset]);

    var received: [aead_tag_len]u8 = undefined;
    @memcpy(&received, retry_datagram[tag_offset..]);
    return std.crypto.timing_safe.eql([aead_tag_len]u8, computed, received);
}

/// Release buffers owned by a decoded protected long-header packet.
pub fn deinitProtectedLongPacket(decoded: *DecodedProtectedLongPacket, allocator: std.mem.Allocator) void {
    packet.deinitLongHeader(&decoded.packet.header, allocator);
    if (decoded.packet.plaintext.len != 0) {
        allocator.free(decoded.packet.plaintext);
    }
}

/// Serialize and protect one QUIC long-header packet with AEAD_AES_128_GCM.
///
/// The returned datagram contains the long header, protected payload, AEAD tag,
/// and header protection. Callers own the returned slice and must free it.
pub fn protectLongPacketAes128(
    allocator: std.mem.Allocator,
    header: packet.LongHeader,
    packet_number_encoding: packet.PacketNumberEncoding,
    keys: Aes128PacketProtectionKeys,
    plaintext: []const u8,
) ![]u8 {
    const protected_payload_len = std.math.add(usize, plaintext.len, aead_tag_len) catch return error.InvalidPayloadLength;
    const protected_payload_len_u64 = std.math.cast(u64, protected_payload_len) orelse return error.InvalidPayloadLength;
    const wire_length = std.math.add(u64, protected_payload_len_u64, @as(u64, packet_number_encoding.len)) catch return error.InvalidPayloadLength;

    const header_len = try longHeaderLen(header, packet_number_encoding.len, wire_length);
    const pn_offset = header_len - packet_number_encoding.len;
    const total_len = std.math.add(usize, header_len, protected_payload_len) catch return error.InvalidPayloadLength;
    try validateHeaderProtectionSample(total_len, pn_offset);

    var protected_header = header;
    protected_header.payload_length = protected_payload_len_u64;

    const datagram = try allocator.alloc(u8, total_len);
    errdefer allocator.free(datagram);

    var writer = buffer.fixedWriter(datagram[0..header_len]);
    try packet.encodeLongHeaderWithPacketNumberEncoding(writer.writer(), protected_header, packet_number_encoding);
    std.debug.assert(writer.getWritten().len == header_len);

    const ciphertext = datagram[header_len..][0..plaintext.len];
    var tag: [aead_tag_len]u8 = undefined;
    try protectAes128Payload(keys, header.packet_number, datagram[0..header_len], plaintext, ciphertext, &tag);
    @memcpy(datagram[header_len + plaintext.len ..][0..aead_tag_len], &tag);

    var sample: [header_protection_sample_len]u8 = undefined;
    @memcpy(&sample, datagram[pn_offset + 4 ..][0..header_protection_sample_len]);
    const mask = aes128HeaderProtectionMask(keys.hp, sample);
    try applyHeaderProtectionMask(.long, &datagram[0], datagram[pn_offset..header_len], mask);

    return datagram;
}

/// Remove protection from one AEAD_AES_128_GCM long-header packet.
///
/// `expected_packet_number` is the next packet number expected in the decoded
/// packet number space and is used to reconstruct the full packet number.
pub fn unprotectLongPacketAes128(
    allocator: std.mem.Allocator,
    keys: Aes128PacketProtectionKeys,
    datagram: []const u8,
    expected_packet_number: u64,
) !DecodedProtectedLongPacket {
    const prefix = try parseProtectedLongPrefix(datagram);
    const packet_end = try protectedLongPacketEnd(prefix);
    if (packet_end > datagram.len) return error.InvalidPayloadLength;
    try validateHeaderProtectionSample(packet_end, prefix.pn_offset);

    var sample: [header_protection_sample_len]u8 = undefined;
    @memcpy(&sample, datagram[prefix.pn_offset + 4 ..][0..header_protection_sample_len]);
    const mask = aes128HeaderProtectionMask(keys.hp, sample);

    const first_byte = datagram[0] ^ (mask[0] & 0x0f);
    const pn_len: u8 = @as(u8, @intCast(first_byte & 0x03)) + 1;
    if (prefix.length < @as(u64, pn_len) + @as(u64, aead_tag_len)) return error.InvalidPayloadLength;

    const payload_start = prefix.pn_offset + @as(usize, pn_len);
    const ciphertext_end = packet_end - aead_tag_len;
    if (payload_start > ciphertext_end) return error.InvalidPayloadLength;

    const aad = try allocator.alloc(u8, payload_start);
    defer allocator.free(aad);
    @memcpy(aad, datagram[0..payload_start]);
    try applyHeaderProtectionMask(.long, &aad[0], aad[prefix.pn_offset..payload_start], mask);
    std.debug.assert(aad[0] == first_byte);

    const packet_number = try decodeUnmaskedPacketNumber(expected_packet_number, aad[prefix.pn_offset..payload_start]);

    var tag: [aead_tag_len]u8 = undefined;
    @memcpy(&tag, datagram[ciphertext_end..packet_end]);

    const ciphertext = datagram[payload_start..ciphertext_end];
    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);

    try unprotectAes128Payload(keys, packet_number, aad, ciphertext, tag, plaintext);

    const dcid = try copyOwned(allocator, prefix.dcid);
    errdefer if (dcid.len != 0) allocator.free(dcid);
    const scid = try copyOwned(allocator, prefix.scid);
    errdefer if (scid.len != 0) allocator.free(scid);
    const token = try copyOwned(allocator, prefix.token);
    errdefer if (token.len != 0) allocator.free(token);

    return .{
        .packet = .{
            .header = .{
                .version = prefix.version,
                .dcid = dcid,
                .scid = scid,
                .packet_type = prefix.packet_type,
                .token = token,
                .packet_number = packet_number,
                .payload_length = prefix.length - @as(u64, pn_len),
            },
            .plaintext = plaintext,
        },
        .len = packet_end,
    };
}

fn deriveAes128PacketProtectionKeys(secret: [initial_secret_len]u8) Aes128PacketProtectionKeys {
    return .{
        .secret = secret,
        .key = hkdfExpandLabel(secret, "quic key", aes_128_key_len),
        .iv = hkdfExpandLabel(secret, "quic iv", iv_len),
        .hp = hkdfExpandLabel(secret, "quic hp", aes_128_hp_key_len),
    };
}

const ProtectedLongPrefix = struct {
    version: packet.Version,
    dcid: []const u8,
    scid: []const u8,
    packet_type: packet.PacketType,
    token: []const u8,
    length: u64,
    pn_offset: usize,
};

fn varIntLen(value: u64) ProtectionError!usize {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    if (value <= 4611686018427387903) return 8;
    return error.InvalidPayloadLength;
}

fn longHeaderLen(header: packet.LongHeader, pn_len: u8, wire_length: u64) !usize {
    if (pn_len == 0 or pn_len > 4) return error.InvalidPacketNumberLength;
    const token_len = if (header.packet_type == .initial) header.token.len else 0;
    var len: usize = 1 + 4 + 1 + header.dcid.len + 1 + header.scid.len;
    if (header.packet_type == .initial) {
        const token_len_u64 = std.math.cast(u64, token_len) orelse return error.InvalidPayloadLength;
        len += try varIntLen(token_len_u64);
        len += token_len;
    }
    len += try varIntLen(wire_length);
    len += pn_len;
    return len;
}

fn validateHeaderProtectionSample(packet_len: usize, pn_offset: usize) ProtectionError!void {
    const sample_offset = std.math.add(usize, pn_offset, 4) catch return error.InvalidPayloadLength;
    const sample_end = std.math.add(usize, sample_offset, header_protection_sample_len) catch return error.InvalidPayloadLength;
    if (sample_end > packet_len) return error.InvalidPayloadLength;
}

fn parseProtectedLongPrefix(datagram: []const u8) !ProtectedLongPrefix {
    var reader = buffer.fixedReader(datagram);

    const first_byte = try reader.readByte();
    if ((first_byte & 0x80) == 0) return error.InvalidHeaderForm;
    if ((first_byte & 0x40) == 0) return error.InvalidFixedBit;

    const packet_type: packet.PacketType = @enumFromInt(@as(u2, @intCast((first_byte >> 4) & 0x03)));
    if (packet_type == .retry) return error.UnsupportedPacketType;

    var version_buf: [4]u8 = undefined;
    try reader.readNoEof(&version_buf);
    const version: packet.Version = @enumFromInt(std.mem.readInt(u32, &version_buf, .big));

    const dcid_len = try reader.readByte();
    if (dcid_len > 20) return error.InvalidConnectionIdLength;
    const dcid = try readBorrowedBytes(&reader, dcid_len);

    const scid_len = try reader.readByte();
    if (scid_len > 20) return error.InvalidConnectionIdLength;
    const scid = try readBorrowedBytes(&reader, scid_len);

    var token: []const u8 = &[_]u8{};
    if (packet_type == .initial) {
        const token_len_varint = try packet.decodeVarInt(reader.reader());
        const token_len = std.math.cast(usize, token_len_varint.value) orelse return error.InvalidPayloadLength;
        token = try readBorrowedBytes(&reader, token_len);
    }

    const length_varint = try packet.decodeVarInt(reader.reader());
    return .{
        .version = version,
        .dcid = dcid,
        .scid = scid,
        .packet_type = packet_type,
        .token = token,
        .length = length_varint.value,
        .pn_offset = reader.pos,
    };
}

fn readBorrowedBytes(reader: *buffer.FixedReader, len: usize) ![]const u8 {
    if (len > reader.remainingLen()) return error.InvalidPayloadLength;
    const start = reader.pos;
    reader.pos += len;
    return reader.data[start..reader.pos];
}

fn protectedLongPacketEnd(prefix: ProtectedLongPrefix) ProtectionError!usize {
    const pn_offset_u64 = std.math.cast(u64, prefix.pn_offset) orelse return error.InvalidPayloadLength;
    const end_u64 = std.math.add(u64, pn_offset_u64, prefix.length) catch return error.InvalidPayloadLength;
    return std.math.cast(usize, end_u64) orelse return error.InvalidPayloadLength;
}

fn decodeUnmaskedPacketNumber(expected_packet_number: u64, packet_number_bytes: []const u8) !u64 {
    if (packet_number_bytes.len == 0 or packet_number_bytes.len > 4) return error.InvalidPacketNumberLength;
    var truncated: u64 = 0;
    for (packet_number_bytes) |byte| {
        truncated = (truncated << 8) | byte;
    }
    return packet.reconstructPacketNumber(expected_packet_number, truncated, @intCast(packet_number_bytes.len));
}

fn copyOwned(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    if (data.len == 0) return &[_]u8{};
    const owned = try allocator.alloc(u8, data.len);
    @memcpy(owned, data);
    return owned;
}

fn hkdfExpandLabel(
    secret: [initial_secret_len]u8,
    label: []const u8,
    comptime len: usize,
) [len]u8 {
    return std.crypto.tls.hkdfExpandLabel(HkdfSha256, secret, label, "", len);
}

fn expectHex(expected_hex: []const u8, actual: []const u8) !void {
    var expected: [64]u8 = undefined;
    const decoded = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqualSlices(u8, decoded, actual);
}

test "deriveInitialSecrets matches RFC 9001 Appendix A.1 vectors" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try deriveInitialSecrets(.v1, &dcid);

    try expectHex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44", &secrets.initial_secret);

    try expectHex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea", &secrets.client.secret);
    try expectHex("1f369613dd76d5467730efcbe3b1a22d", &secrets.client.key);
    try expectHex("fa044b2f42a3fd3b46fb255c", &secrets.client.iv);
    try expectHex("9f50449e04a0e810283a1e9933adedd2", &secrets.client.hp);

    try expectHex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b", &secrets.server.secret);
    try expectHex("cf3a5331653c364c88f0f379b6067e37", &secrets.server.key);
    try expectHex("0ac1493ca1905853b0bba03e", &secrets.server.iv);
    try expectHex("c206b8d9b9f0f37644430b490eeaa314", &secrets.server.hp);
}

test "deriveInitialSecrets rejects unsupported versions and invalid CID length" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    try std.testing.expectError(error.UnsupportedVersion, deriveInitialSecrets(.v2, &dcid));

    const long_dcid = [_]u8{0xaa} ** 21;
    try std.testing.expectError(error.InvalidConnectionIdLength, deriveInitialSecrets(.v1, &long_dcid));
}

test "AES header protection mask matches RFC 9001 Appendix A.2 sample" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try deriveInitialSecrets(.v1, &dcid);

    var sample: [header_protection_sample_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sample, "d1b1c98dd7689fb8ec11d242b123dc9b");
    const mask = aes128HeaderProtectionMask(secrets.client.hp, sample);
    try expectHex("437b9aec36", &mask);

    var first_byte: u8 = 0xc3;
    var packet_number = [_]u8{ 0x00, 0x00, 0x00, 0x02 };
    try applyHeaderProtectionMask(.long, &first_byte, &packet_number, mask);

    try std.testing.expectEqual(@as(u8, 0xc0), first_byte);
    try expectHex("7b9aec34", &packet_number);

    try applyHeaderProtectionMask(.long, &first_byte, &packet_number, mask);
    try std.testing.expectEqual(@as(u8, 0xc3), first_byte);
    try expectHex("00000002", &packet_number);
}

test "applyHeaderProtectionMask validates packet number length and short header mask bits" {
    const mask = [_]u8{ 0xff, 0x01, 0x02, 0x03, 0x04 };

    var first_byte: u8 = 0x40;
    var empty_packet_number = [_]u8{};
    try std.testing.expectError(error.InvalidPacketNumberLength, applyHeaderProtectionMask(.short, &first_byte, &empty_packet_number, mask));

    var long_packet_number = [_]u8{ 0, 1, 2, 3, 4 };
    try std.testing.expectError(error.InvalidPacketNumberLength, applyHeaderProtectionMask(.short, &first_byte, &long_packet_number, mask));

    var short_first: u8 = 0x41;
    var packet_number = [_]u8{ 0xaa, 0xbb };
    try applyHeaderProtectionMask(.short, &short_first, &packet_number, mask);
    try std.testing.expectEqual(@as(u8, 0x5e), short_first);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xab, 0xb9 }, &packet_number);
}

test "packetProtectionNonce XORs packet number into IV" {
    const iv = [_]u8{ 0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c };
    const nonce = try packetProtectionNonce(iv, 2);
    try expectHex("fa044b2f42a3fd3b46fb255e", &nonce);
    try std.testing.expectError(error.InvalidPacketNumber, packetProtectionNonce(iv, packet.max_packet_number + 1));
}

test "protectAes128Payload matches RFC 9001 Appendix A.3 server Initial" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try deriveInitialSecrets(.v1, &dcid);

    const aad_hex = "c1000000010008f067a5502a4262b50040750001";
    var associated_data: [aad_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&associated_data, aad_hex);

    const plaintext_hex =
        "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739" ++
        "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94" ++
        "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00" ++
        "020304";
    var plaintext: [plaintext_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&plaintext, plaintext_hex);

    const protected_payload_hex =
        "5a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb3" ++
        "8cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9" ++
        "c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f" ++
        "58891850abbdca3d20398c276456cbc42158407dd074ee";
    var expected_protected_payload: [protected_payload_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_protected_payload, protected_payload_hex);

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [aead_tag_len]u8 = undefined;
    try protectAes128Payload(secrets.server, 1, &associated_data, &plaintext, &ciphertext, &tag);

    var protected_payload: [plaintext.len + aead_tag_len]u8 = undefined;
    @memcpy(protected_payload[0..ciphertext.len], &ciphertext);
    @memcpy(protected_payload[ciphertext.len..], &tag);
    try std.testing.expectEqualSlices(u8, &expected_protected_payload, &protected_payload);

    var opened: [plaintext.len]u8 = undefined;
    try unprotectAes128Payload(secrets.server, 1, &associated_data, &ciphertext, tag, &opened);
    try std.testing.expectEqualSlices(u8, &plaintext, &opened);

    tag[0] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, unprotectAes128Payload(secrets.server, 1, &associated_data, &ciphertext, tag, &opened));
}

test "protectLongPacketAes128 matches RFC 9001 Appendix A.3 server Initial" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try deriveInitialSecrets(.v1, &dcid);
    const server_scid = [_]u8{ 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 };

    const plaintext_hex =
        "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739" ++
        "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94" ++
        "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00" ++
        "020304";
    var plaintext: [plaintext_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&plaintext, plaintext_hex);

    const expected_packet_hex =
        "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a" ++
        "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3" ++
        "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84" ++
        "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4" ++
        "2158407dd074ee";
    var expected_packet: [expected_packet_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_packet, expected_packet_hex);

    const header = packet.LongHeader{
        .version = .v1,
        .dcid = &[_]u8{},
        .scid = &server_scid,
        .packet_type = .initial,
        .token = &[_]u8{},
        .packet_number = 1,
        .payload_length = 0,
    };
    const protected = try protectLongPacketAes128(std.testing.allocator, header, .{
        .len = 2,
        .truncated_packet_number = 1,
    }, secrets.server, &plaintext);
    defer std.testing.allocator.free(protected);
    try std.testing.expectEqualSlices(u8, &expected_packet, protected);

    var opened = try unprotectLongPacketAes128(std.testing.allocator, secrets.server, protected, 0);
    defer deinitProtectedLongPacket(&opened, std.testing.allocator);
    try std.testing.expectEqual(@as(usize, expected_packet.len), opened.len);
    try std.testing.expectEqual(packet.Version.v1, opened.packet.header.version);
    try std.testing.expectEqual(packet.PacketType.initial, opened.packet.header.packet_type);
    try std.testing.expectEqual(@as(u64, 1), opened.packet.header.packet_number);
    try std.testing.expectEqual(@as(u64, plaintext.len + aead_tag_len), opened.packet.header.payload_length);
    try std.testing.expectEqualSlices(u8, &[_]u8{}, opened.packet.header.dcid);
    try std.testing.expectEqualSlices(u8, &server_scid, opened.packet.header.scid);
    try std.testing.expectEqualSlices(u8, &plaintext, opened.packet.plaintext);

    var tampered = expected_packet;
    tampered[tampered.len - 1] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, unprotectLongPacketAes128(std.testing.allocator, secrets.server, &tampered, 0));
}

test "protectLongPacketAes128 rejects packets without a header protection sample" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try deriveInitialSecrets(.v1, &dcid);
    const plaintext = [_]u8{ 0x06, 0x00 };
    const header = packet.LongHeader{
        .version = .v1,
        .dcid = &dcid,
        .scid = &[_]u8{},
        .packet_type = .initial,
        .token = &[_]u8{},
        .packet_number = 0,
        .payload_length = 0,
    };
    try std.testing.expectError(error.InvalidPayloadLength, protectLongPacketAes128(std.testing.allocator, header, .{
        .len = 1,
        .truncated_packet_number = 0,
    }, secrets.client, &plaintext));
}

test "retryIntegrityTag matches RFC 9001 Appendix A.4 Retry packet" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const retry_hex =
        "ff000000010008f067a5502a4262b5746f6b656e" ++
        "04a265ba2eff4d829058fb3f0f2496ba";
    var retry_packet: [retry_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&retry_packet, retry_hex);

    const tag_offset = retry_packet.len - aead_tag_len;
    const tag = try retryIntegrityTag(std.testing.allocator, &original_dcid, retry_packet[0..tag_offset]);
    try expectHex("04a265ba2eff4d829058fb3f0f2496ba", &tag);
    try std.testing.expect(try verifyRetryIntegrityTag(std.testing.allocator, &original_dcid, &retry_packet));

    var tampered = retry_packet;
    tampered[1] ^= 0x01;
    try std.testing.expect(!try verifyRetryIntegrityTag(std.testing.allocator, &original_dcid, &tampered));
}

test "retry integrity validates input bounds" {
    const long_original_dcid = [_]u8{0xaa} ** 21;
    const retry_without_tag = [_]u8{ 0xff, 0x00 };
    try std.testing.expectError(error.InvalidConnectionIdLength, retryIntegrityTag(std.testing.allocator, &long_original_dcid, &retry_without_tag));

    const original_dcid = [_]u8{0x83};
    const too_short_retry = [_]u8{0xff} ** aead_tag_len;
    try std.testing.expectError(error.InvalidPayloadLength, verifyRetryIntegrityTag(std.testing.allocator, &original_dcid, &too_short_retry));
}

test "payload protection validates buffer lengths" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try deriveInitialSecrets(.v1, &dcid);
    const associated_data = [_]u8{0xc0};
    const plaintext = [_]u8{0x06};
    var empty_ciphertext = [_]u8{};
    var tag: [aead_tag_len]u8 = [_]u8{0} ** aead_tag_len;
    try std.testing.expectError(error.InvalidPayloadLength, protectAes128Payload(secrets.client, 0, &associated_data, &plaintext, &empty_ciphertext, &tag));

    const ciphertext = [_]u8{0x00};
    var empty_plaintext = [_]u8{};
    try std.testing.expectError(error.InvalidPayloadLength, unprotectAes128Payload(secrets.client, 0, &associated_data, &ciphertext, tag, &empty_plaintext));
}
