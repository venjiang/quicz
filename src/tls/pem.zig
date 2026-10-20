//! PEM (RFC 7468) decoding helpers for TLS credentials.
//!
//! The TLS stack consumes DER certificates and raw key scalars; this module
//! bridges the common on-disk formats:
//! - "CERTIFICATE" blocks (single or chain)
//! - "EC PRIVATE KEY" (SEC1 / RFC 5915) P-256 private keys
//! - "PRIVATE KEY" (PKCS#8 / RFC 5208) wrapping a P-256 EC private key
//!
//! Private-key parsing walks the DER structure (SEQUENCE/INTEGER/OCTET
//! STRING/OID) instead of pattern-matching byte sequences, so unrelated
//! fields (public key, parameters) cannot confuse it.

const std = @import("std");

pub const Error = error{
    InvalidPem,
    InvalidDer,
    UnsupportedKey,
    PemBlockTooLarge,
};

const oid_ec_public_key = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

/// Decode the first PEM block with the given label (e.g. "CERTIFICATE")
/// into `der_buf`, returning the DER slice.
pub fn decodeBlock(pem_text: []const u8, label: []const u8, der_buf: []u8) Error![]u8 {
    var search_from: usize = 0;
    while (true) {
        const begin = std.mem.indexOfPos(u8, pem_text, search_from, "-----BEGIN ") orelse return error.InvalidPem;
        const label_start = begin + "-----BEGIN ".len;
        const label_end = std.mem.indexOfPos(u8, pem_text, label_start, "-----") orelse return error.InvalidPem;
        const found_label = pem_text[label_start..label_end];
        const encoded_start = label_end + "-----".len;
        if (!std.mem.eql(u8, found_label, label)) {
            search_from = encoded_start;
            continue;
        }
        var end_marker_buf: [80]u8 = undefined;
        const end_marker = std.fmt.bufPrint(&end_marker_buf, "-----END {s}-----", .{label}) catch return error.InvalidPem;
        const encoded_end = std.mem.indexOfPos(u8, pem_text, encoded_start, end_marker) orelse return error.InvalidPem;
        const encoded = std.mem.trim(u8, pem_text[encoded_start..encoded_end], " \t\r\n");
        const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
        const der_len = decoder.decode(der_buf, encoded) catch return error.InvalidPem;
        return der_buf[0..der_len];
    }
}

/// Decode every "CERTIFICATE" block in order (leaf first per PEM convention).
/// `der_buf` backs all returned slices; `out` receives one entry per block.
pub fn decodeCertificateChain(pem_text: []const u8, der_buf: []u8, out: [][]u8) Error![][]u8 {
    var count: usize = 0;
    var used: usize = 0;
    var search_from: usize = 0;
    while (std.mem.indexOfPos(u8, pem_text, search_from, "-----BEGIN CERTIFICATE-----")) |begin| {
        if (count == out.len) return error.PemBlockTooLarge;
        const encoded_start = begin + "-----BEGIN CERTIFICATE-----".len;
        const encoded_end = std.mem.indexOfPos(u8, pem_text, encoded_start, "-----END CERTIFICATE-----") orelse return error.InvalidPem;
        const encoded = std.mem.trim(u8, pem_text[encoded_start..encoded_end], " \t\r\n");
        const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
        const der_len = decoder.decode(der_buf[used..], encoded) catch return error.InvalidPem;
        out[count] = der_buf[used .. used + der_len];
        used += der_len;
        count += 1;
        search_from = encoded_end + "-----END CERTIFICATE-----".len;
    }
    if (count == 0) return error.InvalidPem;
    return out[0..count];
}

/// A parsed DER TLV element.
const Tlv = struct {
    tag: u8,
    content: []const u8,
    rest: []const u8,
};

fn readTlv(data: []const u8) Error!Tlv {
    if (data.len < 2) return error.InvalidDer;
    const tag = data[0];
    var len: usize = data[1];
    var content_start: usize = 2;
    if (len & 0x80 != 0) {
        const len_bytes = len & 0x7F;
        if (len_bytes == 0 or len_bytes > 4 or data.len < 2 + len_bytes) return error.InvalidDer;
        len = 0;
        for (data[2 .. 2 + len_bytes]) |b| len = (len << 8) | b;
        content_start = 2 + len_bytes;
    }
    if (data.len < content_start + len) return error.InvalidDer;
    return .{
        .tag = tag,
        .content = data[content_start .. content_start + len],
        .rest = data[content_start + len ..],
    };
}

fn expectTlv(data: []const u8, tag: u8) Error!Tlv {
    const tlv = try readTlv(data);
    if (tlv.tag != tag) return error.InvalidDer;
    return tlv;
}

/// Parse a SEC1 (RFC 5915) ECPrivateKey DER structure and return the private
/// scalar. Accepts 32-byte (P-256) scalars only.
fn parseSec1PrivateKey(der: []const u8) Error![32]u8 {
    const seq = try expectTlv(der, 0x30);
    const version = try expectTlv(seq.content, 0x02);
    if (version.content.len != 1 or version.content[0] != 1) return error.InvalidDer;
    const octets = try expectTlv(version.rest, 0x04);
    if (octets.content.len != 32) return error.UnsupportedKey;
    var key: [32]u8 = undefined;
    @memcpy(&key, octets.content);
    return key;
}

/// Parse a PKCS#8 (RFC 5208) PrivateKeyInfo DER structure. Only
/// id-ecPublicKey + prime256v1 is accepted; anything else (RSA, P-384,
/// Ed25519, ...) is `error.UnsupportedKey`.
fn parsePkcs8PrivateKey(der: []const u8) Error![32]u8 {
    const seq = try expectTlv(der, 0x30);
    const version = try expectTlv(seq.content, 0x02);
    if (version.content.len != 1 or version.content[0] > 1) return error.InvalidDer;
    const algor = try expectTlv(version.rest, 0x30);
    const key_oid = try expectTlv(algor.content, 0x06);
    if (!std.mem.eql(u8, key_oid.content, &oid_ec_public_key)) return error.UnsupportedKey;
    const curve_oid = try expectTlv(key_oid.rest, 0x06);
    if (!std.mem.eql(u8, curve_oid.content, &oid_prime256v1)) return error.UnsupportedKey;
    const inner = try expectTlv(algor.rest, 0x04);
    return parseSec1PrivateKey(inner.content);
}

/// Parse a PEM private key file ("EC PRIVATE KEY" SEC1 or "PRIVATE KEY"
/// PKCS#8) and return the raw 32-byte P-256 scalar.
pub fn parsePrivateKeyP256(pem_text: []const u8, der_buf: []u8) Error![32]u8 {
    if (decodeBlock(pem_text, "EC PRIVATE KEY", der_buf)) |der| {
        return parseSec1PrivateKey(der);
    } else |_| {}
    const der = try decodeBlock(pem_text, "PRIVATE KEY", der_buf);
    return parsePkcs8PrivateKey(der);
}

// ─── Tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

fn derAppendLen(out: *std.ArrayList(u8), allocator: std.mem.Allocator, len: usize) !void {
    if (len < 0x80) {
        try out.append(allocator, @intCast(len));
    } else if (len <= 0xFF) {
        try out.appendSlice(allocator, &.{ 0x81, @intCast(len) });
    } else {
        try out.appendSlice(allocator, &.{ 0x82, @intCast(len >> 8), @intCast(len & 0xFF) });
    }
}

fn derAppendTlv(out: *std.ArrayList(u8), allocator: std.mem.Allocator, tag: u8, content: []const u8) !void {
    try out.append(allocator, tag);
    try derAppendLen(out, allocator, content.len);
    try out.appendSlice(allocator, content);
}

fn derWrapSeq(allocator: std.mem.Allocator, content: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try derAppendTlv(&out, allocator, 0x30, content);
    return out.toOwnedSlice(allocator);
}

/// Build SEC1 ECPrivateKey DER for a raw 32-byte scalar.
fn buildSec1Der(allocator: std.mem.Allocator, scalar: [32]u8) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try derAppendTlv(&body, allocator, 0x02, &.{1});
    try derAppendTlv(&body, allocator, 0x04, &scalar);
    return derWrapSeq(allocator, body.items);
}

/// Build PKCS#8 PrivateKeyInfo DER wrapping a SEC1 P-256 key.
fn buildPkcs8Der(allocator: std.mem.Allocator, scalar: [32]u8) ![]u8 {
    var algor_body: std.ArrayList(u8) = .empty;
    defer algor_body.deinit(allocator);
    try derAppendTlv(&algor_body, allocator, 0x06, &oid_ec_public_key);
    try derAppendTlv(&algor_body, allocator, 0x06, &oid_prime256v1);
    const algor = try derWrapSeq(allocator, algor_body.items);
    defer allocator.free(algor);

    const sec1 = try buildSec1Der(allocator, scalar);
    defer allocator.free(sec1);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try derAppendTlv(&body, allocator, 0x02, &.{0});
    try body.appendSlice(allocator, algor);
    try derAppendTlv(&body, allocator, 0x04, sec1);
    return derWrapSeq(allocator, body.items);
}

fn pemEncode(allocator: std.mem.Allocator, label: []const u8, der: []const u8) ![]u8 {
    const b64_len = std.base64.standard.Encoder.calcSize(der.len);
    const b64 = try allocator.alloc(u8, b64_len);
    defer allocator.free(b64);
    _ = std.base64.standard.Encoder.encode(b64, der);
    return std.fmt.allocPrint(allocator, "-----BEGIN {s}-----\n{s}\n-----END {s}-----\n", .{ label, b64, label });
}

fn testScalar() [32]u8 {
    // Deterministic scalar; not secret, test-only.
    var scalar: [32]u8 = undefined;
    for (&scalar, 0..) |*b, i| b.* = @intCast(i + 1);
    return scalar;
}

test "parses SEC1 EC PRIVATE KEY PEM" {
    const allocator = testing.allocator;
    const scalar = testScalar();
    const der = try buildSec1Der(allocator, scalar);
    defer allocator.free(der);
    const pem = try pemEncode(allocator, "EC PRIVATE KEY", der);
    defer allocator.free(pem);

    var der_buf: [256]u8 = undefined;
    const key = try parsePrivateKeyP256(pem, &der_buf);
    try testing.expectEqualSlices(u8, &scalar, &key);
}

test "parses PKCS#8 PRIVATE KEY PEM" {
    const allocator = testing.allocator;
    const scalar = testScalar();
    const der = try buildPkcs8Der(allocator, scalar);
    defer allocator.free(der);
    const pem = try pemEncode(allocator, "PRIVATE KEY", der);
    defer allocator.free(pem);

    var der_buf: [512]u8 = undefined;
    const key = try parsePrivateKeyP256(pem, &der_buf);
    try testing.expectEqualSlices(u8, &scalar, &key);
}

test "parses key generated by std.crypto (SEC1 shape round trip)" {
    // Ensure a real P-256 secret key survives our SEC1 encode/parse path.
    const kp = EcdsaP256.KeyPair.generate(testing.io);
    const scalar = kp.secret_key.toBytes();
    const allocator = testing.allocator;
    const der = try buildSec1Der(allocator, scalar);
    defer allocator.free(der);
    const pem = try pemEncode(allocator, "EC PRIVATE KEY", der);
    defer allocator.free(pem);

    var der_buf: [256]u8 = undefined;
    const key = try parsePrivateKeyP256(pem, &der_buf);
    try testing.expectEqualSlices(u8, &scalar, &key);
}

test "rejects non-P-256 PKCS#8 (RSA OID)" {
    const allocator = testing.allocator;
    // rsaEncryption OID 1.2.840.113549.1.1.1 + NULL params + bogus key octets.
    const rsa_oid = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
    var algor_body: std.ArrayList(u8) = .empty;
    defer algor_body.deinit(allocator);
    try derAppendTlv(&algor_body, allocator, 0x06, &rsa_oid);
    try derAppendTlv(&algor_body, allocator, 0x05, &.{});
    const algor = try derWrapSeq(allocator, algor_body.items);
    defer allocator.free(algor);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try derAppendTlv(&body, allocator, 0x02, &.{0});
    try body.appendSlice(allocator, algor);
    try derAppendTlv(&body, allocator, 0x04, &.{ 0x30, 0x00 });
    const der = try derWrapSeq(allocator, body.items);
    defer allocator.free(der);
    const pem = try pemEncode(allocator, "PRIVATE KEY", der);
    defer allocator.free(pem);

    var der_buf: [512]u8 = undefined;
    try testing.expectError(error.UnsupportedKey, parsePrivateKeyP256(pem, &der_buf));
}

test "rejects non-32-byte SEC1 scalar (P-384 shape)" {
    const allocator = testing.allocator;
    var scalar48: [48]u8 = undefined;
    @memset(&scalar48, 0xAA);
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try derAppendTlv(&body, allocator, 0x02, &.{1});
    try derAppendTlv(&body, allocator, 0x04, &scalar48);
    const der = try derWrapSeq(allocator, body.items);
    defer allocator.free(der);
    const pem = try pemEncode(allocator, "EC PRIVATE KEY", der);
    defer allocator.free(pem);

    var der_buf: [256]u8 = undefined;
    try testing.expectError(error.UnsupportedKey, parsePrivateKeyP256(pem, &der_buf));
}

test "rejects garbage PEM" {
    var der_buf: [256]u8 = undefined;
    try testing.expectError(error.InvalidPem, parsePrivateKeyP256("not a pem file", &der_buf));
    try testing.expectError(error.InvalidPem, decodeBlock("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----", "CERTIFICATE", &der_buf));
}

test "decodes certificate chain in order" {
    const allocator = testing.allocator;
    const leaf_der = "fake-leaf-der";
    const inter_der = "fake-intermediate-der";
    const leaf_pem = try pemEncode(allocator, "CERTIFICATE", leaf_der);
    defer allocator.free(leaf_pem);
    const inter_pem = try pemEncode(allocator, "CERTIFICATE", inter_der);
    defer allocator.free(inter_pem);
    const pem = try std.fmt.allocPrint(allocator, "{s}{s}", .{ leaf_pem, inter_pem });
    defer allocator.free(pem);

    var der_buf: [1024]u8 = undefined;
    var chain: [4][]u8 = undefined;
    const certs = try decodeCertificateChain(pem, &der_buf, &chain);
    try testing.expectEqual(@as(usize, 2), certs.len);
    try testing.expectEqualSlices(u8, leaf_der, certs[0]);
    try testing.expectEqualSlices(u8, inter_der, certs[1]);
}

test "decodeBlock skips blocks with other labels" {
    const allocator = testing.allocator;
    const key_pem = try pemEncode(allocator, "EC PRIVATE KEY", "keyder");
    defer allocator.free(key_pem);
    const cert_pem = try pemEncode(allocator, "CERTIFICATE", "certder");
    defer allocator.free(cert_pem);
    const pem = try std.fmt.allocPrint(allocator, "{s}{s}", .{ key_pem, cert_pem });
    defer allocator.free(pem);

    var der_buf: [128]u8 = undefined;
    const der = try decodeBlock(pem, "CERTIFICATE", &der_buf);
    try testing.expectEqualSlices(u8, "certder", der);
}
