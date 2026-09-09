//! Minimal RFC 8489 STUN Binding codec for connectivity discovery.
//!
//! This module only creates unauthenticated Binding requests and parses the
//! XOR-MAPPED-ADDRESS from matching success responses. ICE credentials,
//! MESSAGE-INTEGRITY, retransmission, and socket ownership belong to the
//! higher connectivity transaction layer.

const std = @import("std");

pub const TransactionId = [12]u8;

pub const MappedAddress = union(enum) {
    ipv4: struct {
        address: [4]u8,
        port: u16,
    },
    ipv6: struct {
        address: [16]u8,
        port: u16,
    },
};

const header_length = 20;
const binding_request: u16 = 0x0001;
const binding_success: u16 = 0x0101;
const magic_cookie: u32 = 0x2112a442;
const xor_mapped_address: u16 = 0x0020;
const ipv4_family: u8 = 0x01;
const ipv6_family: u8 = 0x02;
const cookie_bytes = [4]u8{ 0x21, 0x12, 0xa4, 0x42 };

pub fn encodeBindingRequest(transaction_id: TransactionId) [header_length]u8 {
    var message = [_]u8{0} ** header_length;
    writeU16(message[0..2], binding_request);
    writeU16(message[2..4], 0);
    writeU32(message[4..8], magic_cookie);
    @memcpy(message[8..20], &transaction_id);
    return message;
}

pub fn decodeBindingRequest(message: []const u8) !TransactionId {
    if (message.len != header_length) return error.InvalidMessageLength;
    if (message[0] & 0xc0 != 0) return error.NotStun;
    if (readU16(message[0..2]) != binding_request) return error.UnexpectedMessageType;
    if (readU16(message[2..4]) != 0) return error.InvalidMessageLength;
    if (readU32(message[4..8]) != magic_cookie) return error.InvalidMagicCookie;
    var transaction_id: TransactionId = undefined;
    @memcpy(&transaction_id, message[8..20]);
    return transaction_id;
}

pub fn encodeBindingSuccessIpv4(
    transaction_id: TransactionId,
    address: [4]u8,
    port: u16,
) [32]u8 {
    var message = [_]u8{0} ** 32;
    writeU16(message[0..2], binding_success);
    writeU16(message[2..4], 12);
    writeU32(message[4..8], magic_cookie);
    @memcpy(message[8..20], &transaction_id);
    writeU16(message[20..22], xor_mapped_address);
    writeU16(message[22..24], 8);
    message[25] = ipv4_family;
    writeU16(message[26..28], port ^ @as(u16, @truncate(magic_cookie >> 16)));
    for (message[28..32], address, cookie_bytes) |*encoded, plain, mask| {
        encoded.* = plain ^ mask;
    }
    return message;
}

pub fn decodeBindingSuccess(message: []const u8, expected_transaction_id: TransactionId) !MappedAddress {
    if (message.len < header_length) return error.TruncatedHeader;
    if (message[0] & 0xc0 != 0) return error.NotStun;
    if (readU16(message[0..2]) != binding_success) return error.UnexpectedMessageType;
    if (readU32(message[4..8]) != magic_cookie) return error.InvalidMagicCookie;
    if (!std.mem.eql(u8, message[8..20], &expected_transaction_id)) return error.TransactionMismatch;

    const attributes_length = readU16(message[2..4]);
    if (attributes_length % 4 != 0) return error.InvalidMessageLength;
    const total_length = std.math.add(usize, header_length, attributes_length) catch return error.InvalidMessageLength;
    if (message.len != total_length) return error.InvalidMessageLength;

    var offset: usize = header_length;
    while (offset < message.len) {
        if (message.len - offset < 4) return error.TruncatedAttribute;
        const attribute_type = readU16(message[offset .. offset + 2]);
        const attribute_length = readU16(message[offset + 2 .. offset + 4]);
        const value_start = offset + 4;
        const value_end = std.math.add(usize, value_start, attribute_length) catch return error.TruncatedAttribute;
        if (value_end > message.len) return error.TruncatedAttribute;

        if (attribute_type == xor_mapped_address) {
            return decodeXorMappedAddress(message[value_start..value_end], expected_transaction_id);
        }

        const padded_length = std.mem.alignForward(usize, attribute_length, 4);
        offset = std.math.add(usize, value_start, padded_length) catch return error.TruncatedAttribute;
        if (offset > message.len) return error.TruncatedAttribute;
    }
    return error.MissingXorMappedAddress;
}

fn decodeXorMappedAddress(value: []const u8, transaction_id: TransactionId) !MappedAddress {
    if (value.len < 4 or value[0] != 0) return error.InvalidMappedAddress;
    const port = readU16(value[2..4]) ^ @as(u16, @truncate(magic_cookie >> 16));
    return switch (value[1]) {
        ipv4_family => blk: {
            if (value.len != 8) return error.InvalidMappedAddress;
            var address: [4]u8 = undefined;
            for (&address, value[4..8], cookie_bytes) |*decoded, encoded, mask| {
                decoded.* = encoded ^ mask;
            }
            break :blk .{ .ipv4 = .{ .address = address, .port = port } };
        },
        ipv6_family => blk: {
            if (value.len != 20) return error.InvalidMappedAddress;
            var mask: [16]u8 = undefined;
            @memcpy(mask[0..4], &cookie_bytes);
            @memcpy(mask[4..16], &transaction_id);
            var address: [16]u8 = undefined;
            for (&address, value[4..20], mask) |*decoded, encoded, mask_byte| {
                decoded.* = encoded ^ mask_byte;
            }
            break :blk .{ .ipv6 = .{ .address = address, .port = port } };
        },
        else => error.UnsupportedAddressFamily,
    };
}

fn readU16(bytes: []const u8) u16 {
    return (@as(u16, bytes[0]) << 8) | bytes[1];
}

fn readU32(bytes: []const u8) u32 {
    return (@as(u32, bytes[0]) << 24) |
        (@as(u32, bytes[1]) << 16) |
        (@as(u32, bytes[2]) << 8) |
        bytes[3];
}

fn writeU16(bytes: []u8, value: u16) void {
    bytes[0] = @truncate(value >> 8);
    bytes[1] = @truncate(value);
}

fn writeU32(bytes: []u8, value: u32) void {
    bytes[0] = @truncate(value >> 24);
    bytes[1] = @truncate(value >> 16);
    bytes[2] = @truncate(value >> 8);
    bytes[3] = @truncate(value);
}

test "encodes RFC 8489 binding request header" {
    const transaction_id = TransactionId{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    const expected = [20]u8{
        0x00, 0x01, 0x00, 0x00,
        0x21, 0x12, 0xa4, 0x42,
        1,    2,    3,    4,
        5,    6,    7,    8,
        9,    10,   11,   12,
    };
    try std.testing.expectEqualSlices(u8, &expected, &encodeBindingRequest(transaction_id));
    try std.testing.expectEqual(transaction_id, try decodeBindingRequest(&expected));
}

test "decodes IPv4 XOR-MAPPED-ADDRESS from matching binding success" {
    const transaction_id = TransactionId{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    const response = encodeBindingSuccessIpv4(transaction_id, .{ 192, 0, 2, 1 }, 0x8055);

    const mapped = try decodeBindingSuccess(&response, transaction_id);
    try std.testing.expectEqual(MappedAddress{ .ipv4 = .{
        .address = .{ 192, 0, 2, 1 },
        .port = 0x8055,
    } }, mapped);
}

test "decodes IPv6 XOR-MAPPED-ADDRESS" {
    const transaction_id = TransactionId{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    const address = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    var response = [_]u8{0} ** 44;
    writeU16(response[0..2], binding_success);
    writeU16(response[2..4], 24);
    writeU32(response[4..8], magic_cookie);
    @memcpy(response[8..20], &transaction_id);
    writeU16(response[20..22], xor_mapped_address);
    writeU16(response[22..24], 20);
    response[25] = ipv6_family;
    writeU16(response[26..28], 443 ^ @as(u16, @truncate(magic_cookie >> 16)));
    var mask: [16]u8 = undefined;
    @memcpy(mask[0..4], &cookie_bytes);
    @memcpy(mask[4..16], &transaction_id);
    for (response[28..44], address, mask) |*encoded, plain, mask_byte| encoded.* = plain ^ mask_byte;

    const mapped = try decodeBindingSuccess(&response, transaction_id);
    try std.testing.expectEqual(MappedAddress{ .ipv6 = .{ .address = address, .port = 443 } }, mapped);
}

test "rejects mismatched transaction and malformed attributes" {
    const transaction_id = TransactionId{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    var response = [_]u8{0} ** 24;
    writeU16(response[0..2], binding_success);
    writeU16(response[2..4], 4);
    writeU32(response[4..8], magic_cookie);
    @memcpy(response[8..20], &transaction_id);
    writeU16(response[20..22], xor_mapped_address);
    writeU16(response[22..24], 8);

    var wrong_transaction = transaction_id;
    wrong_transaction[0] ^= 0xff;
    try std.testing.expectError(error.TransactionMismatch, decodeBindingSuccess(&response, wrong_transaction));
    try std.testing.expectError(error.TruncatedAttribute, decodeBindingSuccess(&response, transaction_id));
}
