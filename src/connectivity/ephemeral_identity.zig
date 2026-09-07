//! Short-lived TLS identity for an authenticated connectivity attempt.

const std = @import("std");

const Ed25519 = std.crypto.sign.Ed25519;

pub const server_name = "mons-p2p";
pub const default_lifetime_seconds: u64 = 15 * 60;

pub const Identity = struct {
    certificate_der: []u8,
    private_key_seed: [Ed25519.KeyPair.seed_length]u8,
    expires_at_seconds: u64,

    pub fn deinit(self: *Identity, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, &self.private_key_seed);
        allocator.free(self.certificate_der);
        self.* = undefined;
    }
};

pub fn generate(
    allocator: std.mem.Allocator,
    io: std.Io,
    now_seconds: u64,
) !Identity {
    var serial: [16]u8 = undefined;
    io.random(&serial);
    serial[0] &= 0x7f;
    if (serial[0] == 0) serial[0] = 1;
    var key_pair = Ed25519.KeyPair.generate(io);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair.secret_key));
    return generateFromKeyPair(allocator, &key_pair, serial, now_seconds, default_lifetime_seconds);
}

fn generateFromKeyPair(
    allocator: std.mem.Allocator,
    key_pair: *const Ed25519.KeyPair,
    serial: [16]u8,
    now_seconds: u64,
    lifetime_seconds: u64,
) !Identity {
    if (lifetime_seconds == 0) return error.InvalidLifetime;
    const expires_at = std.math.add(u64, now_seconds, lifetime_seconds) catch return error.InvalidLifetime;
    const not_before = now_seconds -| 60;

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const version = try element(arena, 0x02, &.{2});
    const explicit_version = try element(arena, 0xa0, version);
    const serial_number = try element(arena, 0x02, &serial);
    const signature_algorithm = try algorithmIdentifier(arena);
    const name = try commonName(arena);
    const validity = try validitySequence(arena, not_before, expires_at);
    const public_key_info = try subjectPublicKeyInfo(arena, key_pair.public_key.toBytes());
    const tbs_content = try concatenate(arena, &.{
        explicit_version,
        serial_number,
        signature_algorithm,
        name,
        validity,
        name,
        public_key_info,
    });
    const tbs_certificate = try element(arena, 0x30, tbs_content);
    const signature = try key_pair.sign(tbs_certificate, null);
    const signature_bytes = signature.toBytes();
    var signature_value_content: [1 + Ed25519.Signature.encoded_length]u8 = undefined;
    signature_value_content[0] = 0;
    @memcpy(signature_value_content[1..], &signature_bytes);
    const signature_value = try element(arena, 0x03, &signature_value_content);
    const certificate_content = try concatenate(arena, &.{
        tbs_certificate,
        signature_algorithm,
        signature_value,
    });
    const certificate = try element(arena, 0x30, certificate_content);

    return .{
        .certificate_der = try allocator.dupe(u8, certificate),
        .private_key_seed = key_pair.secret_key.seed(),
        .expires_at_seconds = expires_at,
    };
}

fn algorithmIdentifier(allocator: std.mem.Allocator) ![]u8 {
    const oid = try element(allocator, 0x06, &.{ 0x2b, 0x65, 0x70 });
    return element(allocator, 0x30, oid);
}

fn commonName(allocator: std.mem.Allocator) ![]u8 {
    const oid = try element(allocator, 0x06, &.{ 0x55, 0x04, 0x03 });
    const value = try element(allocator, 0x0c, server_name);
    const attribute_content = try concatenate(allocator, &.{ oid, value });
    const attribute = try element(allocator, 0x30, attribute_content);
    const relative_name = try element(allocator, 0x31, attribute);
    return element(allocator, 0x30, relative_name);
}

fn validitySequence(
    allocator: std.mem.Allocator,
    not_before_seconds: u64,
    not_after_seconds: u64,
) ![]u8 {
    const not_before_text = try generalizedTime(not_before_seconds);
    const not_after_text = try generalizedTime(not_after_seconds);
    const not_before = try element(allocator, 0x18, &not_before_text);
    const not_after = try element(allocator, 0x18, &not_after_text);
    const content = try concatenate(allocator, &.{ not_before, not_after });
    return element(allocator, 0x30, content);
}

fn subjectPublicKeyInfo(
    allocator: std.mem.Allocator,
    public_key: [Ed25519.PublicKey.encoded_length]u8,
) ![]u8 {
    const algorithm = try algorithmIdentifier(allocator);
    var public_key_content: [1 + Ed25519.PublicKey.encoded_length]u8 = undefined;
    public_key_content[0] = 0;
    @memcpy(public_key_content[1..], &public_key);
    const bit_string = try element(allocator, 0x03, &public_key_content);
    const content = try concatenate(allocator, &.{ algorithm, bit_string });
    return element(allocator, 0x30, content);
}

fn generalizedTime(seconds: u64) ![15]u8 {
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = seconds };
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    if (year_day.year > 9_999) return error.InvalidTimestamp;
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch_seconds.getDaySeconds();
    var output: [15]u8 = undefined;
    writeFourDigits(output[0..4], year_day.year);
    writeTwoDigits(output[4..6], month_day.month.numeric());
    writeTwoDigits(output[6..8], month_day.day_index + 1);
    writeTwoDigits(output[8..10], day_seconds.getHoursIntoDay());
    writeTwoDigits(output[10..12], day_seconds.getMinutesIntoHour());
    writeTwoDigits(output[12..14], day_seconds.getSecondsIntoMinute());
    output[14] = 'Z';
    return output;
}

fn writeFourDigits(output: []u8, value: u16) void {
    output[0] = @intCast('0' + @mod(@divTrunc(value, 1_000), 10));
    output[1] = @intCast('0' + @mod(@divTrunc(value, 100), 10));
    output[2] = @intCast('0' + @mod(@divTrunc(value, 10), 10));
    output[3] = @intCast('0' + @mod(value, 10));
}

fn writeTwoDigits(output: []u8, value: anytype) void {
    const numeric: u16 = @intCast(value);
    output[0] = '0' + @as(u8, @intCast(@mod(@divTrunc(numeric, 10), 10)));
    output[1] = '0' + @as(u8, @intCast(@mod(numeric, 10)));
}

fn concatenate(allocator: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    var length: usize = 0;
    for (parts) |part| length = try std.math.add(usize, length, part.len);
    const output = try allocator.alloc(u8, length);
    var offset: usize = 0;
    for (parts) |part| {
        @memcpy(output[offset .. offset + part.len], part);
        offset += part.len;
    }
    return output;
}

fn element(allocator: std.mem.Allocator, tag: u8, content: []const u8) ![]u8 {
    const length_octets: usize = if (content.len < 128) 1 else if (content.len <= 0xff) 2 else 3;
    if (content.len > 0xffff) return error.ElementTooLarge;
    const output = try allocator.alloc(u8, 1 + length_octets + content.len);
    output[0] = tag;
    switch (length_octets) {
        1 => output[1] = @intCast(content.len),
        2 => {
            output[1] = 0x81;
            output[2] = @intCast(content.len);
        },
        3 => {
            output[1] = 0x82;
            std.mem.writeInt(u16, output[2..4], @intCast(content.len), .big);
        },
        else => unreachable,
    }
    @memcpy(output[1 + length_octets ..], content);
    return output;
}

test "ephemeral identity is a valid self-signed Host certificate" {
    var key_pair = try Ed25519.KeyPair.generateDeterministic(.{0x42} ** Ed25519.KeyPair.seed_length);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair.secret_key));
    var identity = try generateFromKeyPair(
        std.testing.allocator,
        &key_pair,
        .{0x21} ** 16,
        1_800_000_000,
        600,
    );
    defer identity.deinit(std.testing.allocator);

    const certificate = std.crypto.Certificate{ .buffer = identity.certificate_der, .index = 0 };
    const parsed = try certificate.parse();
    try std.testing.expectEqualStrings(server_name, parsed.commonName());
    try parsed.verify(parsed, 1_800_000_000);
    try parsed.verifyHostName(server_name);

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, identity.certificate_der);
    try bundle.parseCert(std.testing.allocator, 0, 1_800_000_000);
    try bundle.verify(parsed, 1_800_000_000);
    try std.testing.expectError(
        error.CertificateExpired,
        bundle.verify(parsed, @intCast(identity.expires_at_seconds + 1)),
    );
}
