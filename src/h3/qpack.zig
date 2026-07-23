//! QPACK header compression (RFC 9204) — minimal implementation.
//!
//! Implements the QPACK static table and basic header field
//! encoding/decoding for HTTP/3 header blocks.

const std = @import("std");

/// QPACK static table entry (RFC 9204 Appendix A).
pub const StaticEntry = struct {
    name: []const u8,
    value: []const u8,
};

/// QPACK static table (subset of RFC 9204 Appendix A).
pub const static_table = [_]StaticEntry{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":path", .value = "/" },
    .{ .name = "age", .value = "0" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-length", .value = "0" },
    .{ .name = "content-type", .value = "" },
    .{ .name = ":method", .value = "CONNECT" },
    .{ .name = ":method", .value = "DELETE" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "HEAD" },
    .{ .name = ":method", .value = "OPTIONS" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":method", .value = "PUT" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "103" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "503" },
    .{ .name = "accept", .value = "*/*" },
    .{ .name = "accept", .value = "application/dns-message" },
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" },
    .{ .name = "accept-ranges", .value = "bytes" },
    .{ .name = "access-control-allow-headers", .value = "cache-control" },
    .{ .name = "cache-control", .value = "max-age=0" },
    .{ .name = "cache-control", .value = "max-age=2592000" },
    .{ .name = "cache-control", .value = "max-age=604800" },
    .{ .name = "cache-control", .value = "no-cache" },
    .{ .name = "cache-control", .value = "no-store" },
};

/// An HTTP header field.
pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
};

/// Find a static table index for an exact name+value match.
pub fn findStaticIndex(name: []const u8, value: []const u8) ?u64 {
    for (static_table, 0..) |entry, i| {
        if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) {
            return @intCast(i);
        }
    }
    return null;
}

/// Find a static table index for a name-only match.
pub fn findStaticNameIndex(name: []const u8) ?u64 {
    for (static_table, 0..) |entry, i| {
        if (std.mem.eql(u8, entry.name, name)) {
            return @intCast(i);
        }
    }
    return null;
}

/// Encode a header block (sequence of header fields) into a caller-provided buffer.
/// Uses indexed representation for static table matches, literal otherwise.
/// Returns the number of bytes written.
pub fn encodeHeaderBlock(out: []u8, fields: []const HeaderField) !usize {
    var pos: usize = 0;

    // Required Insert Count = 0 (no dynamic table)
    out[pos] = 0x00;
    pos += 1;
    // Delta Base = 0
    out[pos] = 0x00;
    pos += 1;

    for (fields) |field| {
        if (findStaticIndex(field.name, field.value)) |idx| {
            // Indexed Field Line (static): 1TXXXXXX, T=1 for static
            out[pos] = @intCast(0xc0 | idx);
            pos += 1;
        } else if (findStaticNameIndex(field.name)) |name_idx| {
            // Literal with Name Reference (static): 01NTXXXX
            out[pos] = @intCast(0x50 | name_idx);
            pos += 1;
            pos = try encodeStringToBuf(out, pos, field.value);
        } else {
            // Literal without Name Reference: 001NXXXX
            out[pos] = 0x20;
            pos += 1;
            pos = try encodeStringToBuf(out, pos, field.name);
            pos = try encodeStringToBuf(out, pos, field.value);
        }
    }

    return pos;
}

/// Encode a length-prefixed string into a buffer (no Huffman for simplicity).
fn encodeStringToBuf(out: []u8, pos: usize, s: []const u8) !usize {
    var p = pos;
    if (s.len < 128) {
        out[p] = @intCast(s.len);
        p += 1;
    } else {
        out[p] = 0x7f;
        p += 1;
        var remaining = s.len - 127;
        while (remaining >= 128) : (remaining -= 128) {
            out[p] = 0x80 | 127;
            p += 1;
        }
        out[p] = @intCast(remaining);
        p += 1;
    }
    @memcpy(out[p .. p + s.len], s);
    p += s.len;
    return p;
}

test "QPACK static table lookup" {
    // :method GET = index 8
    try std.testing.expectEqual(@as(?u64, 8), findStaticIndex(":method", "GET"));
    // :status 200 = index 16
    try std.testing.expectEqual(@as(?u64, 16), findStaticIndex(":status", "200"));
    // :scheme https = index 14
    try std.testing.expectEqual(@as(?u64, 14), findStaticIndex(":scheme", "https"));
    // :path / = index 1
    try std.testing.expectEqual(@as(?u64, 1), findStaticIndex(":path", "/"));
    // Unknown
    try std.testing.expect(findStaticIndex("x-custom", "value") == null);
}

test "QPACK static name lookup" {
    try std.testing.expectEqual(@as(?u64, 6), findStaticNameIndex(":method"));
    try std.testing.expectEqual(@as(?u64, 0), findStaticNameIndex(":authority"));
    try std.testing.expect(findStaticNameIndex("x-custom") == null);
}

test "QPACK encode header block with static entries" {
    const fields = [_]HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    };

    var encoded: [256]u8 = undefined;
    const len = try encodeHeaderBlock(&encoded, &fields);

    // First 2 bytes: Required Insert Count (0) + Delta Base (0)
    try std.testing.expectEqual(@as(u8, 0x00), encoded[0]);
    try std.testing.expectEqual(@as(u8, 0x00), encoded[1]);
    // :method GET = 0xc0 | 8 = 0xc8
    try std.testing.expectEqual(@as(u8, 0xc8), encoded[2]);
    // :path / = 0xc0 | 1 = 0xc1
    try std.testing.expectEqual(@as(u8, 0xc1), encoded[3]);
    // :scheme https = 0xc0 | 14 = 0xce
    try std.testing.expectEqual(@as(u8, 0xce), encoded[4]);
    // :authority with literal value (name ref index 0): 0x50 | 0 = 0x50
    try std.testing.expectEqual(@as(u8, 0x50), encoded[5]);
    try std.testing.expect(len > 6);
}

test "QPACK encode header block with custom headers" {
    const fields = [_]HeaderField{
        .{ .name = "x-custom-header", .value = "custom-value" },
    };

    var encoded: [256]u8 = undefined;
    const len = try encodeHeaderBlock(&encoded, &fields);

    // Literal without name reference: 0x20
    try std.testing.expectEqual(@as(u8, 0x20), encoded[2]);
    try std.testing.expect(len > 3);
}

/// Decode a QPACK header block into header fields.
/// Returns the number of fields written to `out_fields`.
pub fn decodeHeaderBlock(data: []const u8, out_fields: []HeaderField) !usize {
    if (data.len < 2) return error.InvalidHeaderBlock;

    // Skip Required Insert Count (1 byte) and Delta Base (1 byte)
    var pos: usize = 2;
    var count: usize = 0;

    while (pos < data.len) {
        if (count >= out_fields.len) return error.TooManyFields;
        const first = data[pos];

        if (first & 0x80 != 0) {
            // Indexed Field Line: 1TXXXXXX
            const is_static = (first & 0x40) != 0;
            const index: u64 = first & 0x3f;
            if (!is_static) return error.DynamicTableUnsupported;
            if (index >= static_table.len) return error.InvalidStaticIndex;
            out_fields[count] = .{
                .name = static_table[index].name,
                .value = static_table[index].value,
            };
            count += 1;
            pos += 1;
        } else if (first & 0x40 != 0) {
            // Literal with Name Reference: 01NTXXXX
            const is_static = (first & 0x10) != 0;
            const name_index: u64 = first & 0x0f;
            if (!is_static) return error.DynamicTableUnsupported;
            if (name_index >= static_table.len) return error.InvalidStaticIndex;
            pos += 1;
            const value_result = try decodeString(data, pos);
            out_fields[count] = .{
                .name = static_table[name_index].name,
                .value = value_result.value,
            };
            count += 1;
            pos = value_result.end;
        } else if (first & 0x20 != 0) {
            // Literal without Name Reference: 001NXXXX
            pos += 1;
            const name_result = try decodeString(data, pos);
            const value_result = try decodeString(data, name_result.end);
            out_fields[count] = .{
                .name = name_result.value,
                .value = value_result.value,
            };
            count += 1;
            pos = value_result.end;
        } else {
            return error.UnsupportedRepresentation;
        }
    }

    return count;
}

fn decodeString(data: []const u8, start: usize) !struct { value: []const u8, end: usize } {
    if (start >= data.len) return error.IncompleteString;
    const first = data[start];
    // No Huffman support: H bit (0x80) must be 0
    if (first & 0x80 != 0) return error.HuffmanNotSupported;
    const len: usize = first & 0x7f;
    const value_start = start + 1;
    if (value_start + len > data.len) return error.IncompleteString;
    return .{
        .value = data[value_start .. value_start + len],
        .end = value_start + len,
    };
}

test "QPACK decode header block with static entries" {
    // Encode then decode
    const fields = [_]HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
    };

    var encoded: [256]u8 = undefined;
    const enc_len = try encodeHeaderBlock(&encoded, &fields);

    var decoded: [16]HeaderField = undefined;
    const dec_count = try decodeHeaderBlock(encoded[0..enc_len], &decoded);

    try std.testing.expectEqual(@as(usize, 3), dec_count);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
    try std.testing.expectEqualStrings(":path", decoded[1].name);
    try std.testing.expectEqualStrings("/", decoded[1].value);
    try std.testing.expectEqualStrings(":scheme", decoded[2].name);
    try std.testing.expectEqualStrings("https", decoded[2].value);
}

test "QPACK decode header block with literal value" {
    const fields = [_]HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":authority", .value = "example.com" },
    };

    var encoded: [256]u8 = undefined;
    const enc_len = try encodeHeaderBlock(&encoded, &fields);

    var decoded: [16]HeaderField = undefined;
    const dec_count = try decodeHeaderBlock(encoded[0..enc_len], &decoded);

    try std.testing.expectEqual(@as(usize, 2), dec_count);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
    try std.testing.expectEqualStrings(":authority", decoded[1].name);
    try std.testing.expectEqualStrings("example.com", decoded[1].value);
}

test "QPACK decode header block with custom headers" {
    const fields = [_]HeaderField{
        .{ .name = "x-custom", .value = "custom-value" },
    };

    var encoded: [256]u8 = undefined;
    const enc_len = try encodeHeaderBlock(&encoded, &fields);

    var decoded: [16]HeaderField = undefined;
    const dec_count = try decodeHeaderBlock(encoded[0..enc_len], &decoded);

    try std.testing.expectEqual(@as(usize, 1), dec_count);
    try std.testing.expectEqualStrings("x-custom", decoded[0].name);
    try std.testing.expectEqualStrings("custom-value", decoded[0].value);
}

test "QPACK decode :status 200" {
    const fields = [_]HeaderField{
        .{ .name = ":status", .value = "200" },
    };

    var encoded: [256]u8 = undefined;
    const enc_len = try encodeHeaderBlock(&encoded, &fields);

    var decoded: [16]HeaderField = undefined;
    const dec_count = try decodeHeaderBlock(encoded[0..enc_len], &decoded);

    try std.testing.expectEqual(@as(usize, 1), dec_count);
    try std.testing.expectEqualStrings(":status", decoded[0].name);
    try std.testing.expectEqualStrings("200", decoded[0].value);
}
