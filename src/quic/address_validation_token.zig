const std = @import("std");
const packet = @import("packet.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const secret_len = HmacSha256.key_length;
pub const nonce_len = 16;
pub const mac_len = HmacSha256.mac_length;
pub const fingerprint_len = mac_len;

const magic = "qcz-av2";
const version_len = 4;
const token_body_len = magic.len + 1 + version_len + 8 + 8 + nonce_len;
const token_len = token_body_len + mac_len;

/// Server-owned key used to authenticate address-validation tokens.
pub const Secret = [secret_len]u8;

/// Per-token entropy. Callers should use unpredictable bytes in production.
pub const Nonce = [nonce_len]u8;

/// Stable replay-cache key derived from an authenticated token's MAC.
pub const Fingerprint = [fingerprint_len]u8;

/// Owned snapshot of replay-filter fingerprints for external persistence.
///
/// The snapshot stores only token MAC fingerprints, preserving replay
/// rejection state without carrying token plaintext or endpoint secrets.
pub const ReplayFilterSnapshot = struct {
    /// Fingerprints in oldest-to-newest eviction order.
    fingerprints: []Fingerprint,

    /// Release the owned fingerprint snapshot.
    pub fn deinit(self: *ReplayFilterSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.fingerprints);
        self.fingerprints = &.{};
    }
};

/// Address-validation token source from RFC 9000 Section 8.1.1.
pub const Kind = enum(u8) {
    retry = 0,
    new_token = 1,
};

/// Input for creating an authenticated address-validation token.
pub const Context = struct {
    kind: Kind,
    /// QUIC version that originally caused this token to be issued.
    originating_version: packet.Version = .v1,
    issued_millis: i64,
    lifetime_millis: u64,
    peer_address: []const u8,
    nonce: Nonce,
};

/// Parsed and authenticated token metadata.
pub const Validation = struct {
    kind: Kind,
    originating_version: packet.Version,
    issued_millis: i64,
    lifetime_millis: u64,
    nonce: Nonce,
};

pub const Error = error{
    InvalidToken,
    TokenReplay,
    TokenExpired,
    TokenNotYetValid,
    OutOfMemory,
};

/// Endpoint-owned bounded replay filter for validated address tokens.
///
/// The filter stores token MAC fingerprints only. Call `rememberValidated()`
/// after `validate()` succeeds; the filter performs only structural token
/// checks and does not authenticate the token by itself.
pub const ReplayFilter = struct {
    allocator: std.mem.Allocator,
    max_entries: usize,
    fingerprints: std.ArrayList(Fingerprint) = .empty,

    /// Create a replay filter that keeps at most `max_entries` recent tokens.
    pub fn init(allocator: std.mem.Allocator, max_entries: usize) ReplayFilter {
        return .{
            .allocator = allocator,
            .max_entries = max_entries,
        };
    }

    /// Create a replay filter from an externally persisted snapshot.
    ///
    /// If the snapshot is larger than `max_entries`, the newest fingerprints at
    /// the end of the snapshot are retained so eviction order remains stable.
    pub fn initWithSnapshot(
        allocator: std.mem.Allocator,
        max_entries: usize,
        snapshot: ReplayFilterSnapshot,
    ) Error!ReplayFilter {
        var filter = ReplayFilter.init(allocator, max_entries);
        errdefer filter.deinit();

        const retained = retainedSnapshotFingerprints(snapshot.fingerprints, max_entries);
        filter.fingerprints.appendSlice(allocator, retained) catch return error.OutOfMemory;
        return filter;
    }

    /// Release replay-filter storage.
    pub fn deinit(self: *ReplayFilter) void {
        self.fingerprints.deinit(self.allocator);
    }

    /// Return the number of stored replay fingerprints.
    pub fn entryCount(self: *const ReplayFilter) usize {
        return self.fingerprints.items.len;
    }

    /// Export replay fingerprints for external storage or worker distribution.
    pub fn exportSnapshot(self: *const ReplayFilter, allocator: std.mem.Allocator) Error!ReplayFilterSnapshot {
        const fingerprints = allocator.alloc(Fingerprint, self.fingerprints.items.len) catch return error.OutOfMemory;
        @memcpy(fingerprints, self.fingerprints.items);
        return .{ .fingerprints = fingerprints };
    }

    /// Return whether a token fingerprint is already recorded.
    pub fn contains(self: *const ReplayFilter, encoded: []const u8) Error!bool {
        const token_fingerprint = try fingerprint(encoded);
        return self.containsFingerprint(token_fingerprint);
    }

    /// Record a token that has already passed `validate()`.
    ///
    /// Duplicate tokens return `error.TokenReplay`. When the bounded filter is
    /// full, the oldest fingerprint is evicted before the new one is recorded.
    pub fn rememberValidated(self: *ReplayFilter, encoded: []const u8) Error!void {
        if (self.max_entries == 0) return error.InvalidToken;

        const token_fingerprint = try fingerprint(encoded);
        if (self.containsFingerprint(token_fingerprint)) return error.TokenReplay;

        self.fingerprints.ensureUnusedCapacity(self.allocator, 1) catch return error.OutOfMemory;
        if (self.fingerprints.items.len == self.max_entries) {
            _ = self.fingerprints.orderedRemove(0);
        }
        self.fingerprints.appendAssumeCapacity(token_fingerprint);
    }

    fn containsFingerprint(self: *const ReplayFilter, token_fingerprint: Fingerprint) bool {
        for (self.fingerprints.items) |existing| {
            if (std.crypto.timing_safe.eql(Fingerprint, existing, token_fingerprint)) return true;
        }
        return false;
    }
};

fn retainedSnapshotFingerprints(fingerprints: []const Fingerprint, max_entries: usize) []const Fingerprint {
    if (fingerprints.len > max_entries) {
        return fingerprints[fingerprints.len - max_entries ..];
    }
    return fingerprints;
}

/// Encode a server-authenticated token bound to `peer_address`.
///
/// The peer address is included in the HMAC input but not serialized into the
/// token, so NEW_TOKEN values can be address-bound without exposing address
/// material to observers.
pub fn encode(allocator: std.mem.Allocator, secret: Secret, context: Context) Error![]u8 {
    try validateContext(context);

    const encoded = allocator.alloc(u8, token_len) catch return error.OutOfMemory;
    errdefer allocator.free(encoded);

    @memcpy(encoded[0..magic.len], magic);
    var offset: usize = magic.len;
    encoded[offset] = @intFromEnum(context.kind);
    offset += 1;
    std.mem.writeInt(u32, encoded[offset..][0..version_len], @intFromEnum(context.originating_version), .big);
    offset += version_len;
    std.mem.writeInt(u64, encoded[offset..][0..8], @intCast(context.issued_millis), .big);
    offset += 8;
    std.mem.writeInt(u64, encoded[offset..][0..8], context.lifetime_millis, .big);
    offset += 8;
    @memcpy(encoded[offset..][0..nonce_len], &context.nonce);
    offset += nonce_len;
    std.debug.assert(offset == token_body_len);

    const tag = tokenMac(secret, encoded[0..token_body_len], context.peer_address);
    @memcpy(encoded[token_body_len..][0..mac_len], &tag);
    return encoded;
}

/// Authenticate and validate a token for `peer_address` and `expected_kind`.
pub fn validate(
    secret: Secret,
    expected_kind: Kind,
    now_millis: i64,
    peer_address: []const u8,
    encoded: []const u8,
) Error!Validation {
    return validateForVersion(secret, expected_kind, .v1, now_millis, peer_address, encoded);
}

/// Authenticate and validate a token for an expected originating QUIC version.
pub fn validateForVersion(
    secret: Secret,
    expected_kind: Kind,
    expected_originating_version: packet.Version,
    now_millis: i64,
    peer_address: []const u8,
    encoded: []const u8,
) Error!Validation {
    if (now_millis < 0 or peer_address.len == 0 or peer_address.len > std.math.maxInt(u16)) {
        return error.InvalidToken;
    }
    try validateEnvelope(encoded);

    var offset: usize = magic.len;
    const kind = std.enums.fromInt(Kind, encoded[offset]) orelse return error.InvalidToken;
    offset += 1;
    if (kind != expected_kind) return error.InvalidToken;

    const originating_version: packet.Version = @enumFromInt(std.mem.readInt(u32, encoded[offset..][0..version_len], .big));
    offset += version_len;
    if (@intFromEnum(originating_version) != @intFromEnum(expected_originating_version)) return error.InvalidToken;

    const issued_u64 = std.mem.readInt(u64, encoded[offset..][0..8], .big);
    if (issued_u64 > @as(u64, @intCast(std.math.maxInt(i64)))) return error.InvalidToken;
    const issued_millis: i64 = @intCast(issued_u64);
    offset += 8;

    const lifetime_millis = std.mem.readInt(u64, encoded[offset..][0..8], .big);
    if (lifetime_millis == 0) return error.InvalidToken;
    offset += 8;

    const nonce = encoded[offset..][0..nonce_len].*;
    offset += nonce_len;
    std.debug.assert(offset == token_body_len);

    const expected_tag = tokenMac(secret, encoded[0..token_body_len], peer_address);
    const received_tag = encoded[token_body_len..][0..mac_len].*;
    if (!std.crypto.timing_safe.eql([mac_len]u8, expected_tag, received_tag)) {
        return error.InvalidToken;
    }

    if (now_millis < issued_millis) return error.TokenNotYetValid;
    const expires_at = expiresAtMillis(issued_millis, lifetime_millis) orelse return error.InvalidToken;
    if (now_millis > expires_at) return error.TokenExpired;

    return .{
        .kind = kind,
        .originating_version = originating_version,
        .issued_millis = issued_millis,
        .lifetime_millis = lifetime_millis,
        .nonce = nonce,
    };
}

/// Authenticate and validate a token against a caller-ordered set of secrets.
///
/// This helper supports endpoint secret rotation when tokens issued with an
/// older secret must remain valid until their encoded lifetime expires. The
/// first validating secret wins; if a secret authenticates an expired or
/// not-yet-valid token, that temporal error is preserved instead of being
/// collapsed into `InvalidToken`.
pub fn validateAnySecret(
    secrets: []const Secret,
    expected_kind: Kind,
    now_millis: i64,
    peer_address: []const u8,
    encoded: []const u8,
) Error!Validation {
    return validateAnySecretForVersion(secrets, expected_kind, .v1, now_millis, peer_address, encoded);
}

/// Authenticate and validate a token for a QUIC version against rotated secrets.
pub fn validateAnySecretForVersion(
    secrets: []const Secret,
    expected_kind: Kind,
    expected_originating_version: packet.Version,
    now_millis: i64,
    peer_address: []const u8,
    encoded: []const u8,
) Error!Validation {
    if (secrets.len == 0) return error.InvalidToken;

    var authenticated_error: ?Error = null;
    for (secrets) |secret| {
        if (validateForVersion(secret, expected_kind, expected_originating_version, now_millis, peer_address, encoded)) |validation| {
            return validation;
        } else |err| switch (err) {
            error.InvalidToken => {},
            error.TokenExpired, error.TokenNotYetValid => if (authenticated_error == null) {
                authenticated_error = err;
            },
            error.TokenReplay, error.OutOfMemory => return err,
        }
    }

    if (authenticated_error) |err| return err;
    return error.InvalidToken;
}

/// Validate a token against rotated secrets and record it in a replay filter.
///
/// The token is remembered only after authentication, address binding, kind and
/// lifetime checks all pass. Duplicate fingerprints return `TokenReplay`.
pub fn validateAnySecretAndRemember(
    secrets: []const Secret,
    expected_kind: Kind,
    now_millis: i64,
    peer_address: []const u8,
    encoded: []const u8,
    replay_filter: *ReplayFilter,
) Error!Validation {
    return validateAnySecretAndRememberForVersion(secrets, expected_kind, .v1, now_millis, peer_address, encoded, replay_filter);
}

/// Validate a version-bound token against rotated secrets and remember it.
pub fn validateAnySecretAndRememberForVersion(
    secrets: []const Secret,
    expected_kind: Kind,
    expected_originating_version: packet.Version,
    now_millis: i64,
    peer_address: []const u8,
    encoded: []const u8,
    replay_filter: *ReplayFilter,
) Error!Validation {
    const validation = try validateAnySecretForVersion(secrets, expected_kind, expected_originating_version, now_millis, peer_address, encoded);
    try replay_filter.rememberValidated(encoded);
    return validation;
}

/// Return the replay-filter fingerprint for a structurally valid token.
pub fn fingerprint(encoded: []const u8) Error!Fingerprint {
    try validateEnvelope(encoded);
    return encoded[token_body_len..][0..fingerprint_len].*;
}

fn validateEnvelope(encoded: []const u8) Error!void {
    if (encoded.len != token_len or !std.mem.eql(u8, encoded[0..magic.len], magic)) {
        return error.InvalidToken;
    }
    _ = std.enums.fromInt(Kind, encoded[magic.len]) orelse return error.InvalidToken;

    const issued_offset = magic.len + 1 + version_len;
    const issued_u64 = std.mem.readInt(u64, encoded[issued_offset..][0..8], .big);
    if (issued_u64 > @as(u64, @intCast(std.math.maxInt(i64)))) return error.InvalidToken;

    const lifetime_offset = issued_offset + 8;
    const lifetime_millis = std.mem.readInt(u64, encoded[lifetime_offset..][0..8], .big);
    if (lifetime_millis == 0) return error.InvalidToken;
}

fn validateContext(context: Context) Error!void {
    if (context.issued_millis < 0 or context.lifetime_millis == 0) return error.InvalidToken;
    if (context.peer_address.len == 0 or context.peer_address.len > std.math.maxInt(u16)) {
        return error.InvalidToken;
    }
    _ = expiresAtMillis(context.issued_millis, context.lifetime_millis) orelse return error.InvalidToken;
}

fn expiresAtMillis(issued_millis: i64, lifetime_millis: u64) ?i64 {
    if (issued_millis < 0) return null;
    const max_lifetime: u64 = @intCast(std.math.maxInt(i64) - issued_millis);
    if (lifetime_millis > max_lifetime) return null;
    return issued_millis + @as(i64, @intCast(lifetime_millis));
}

fn tokenMac(secret: Secret, body: []const u8, peer_address: []const u8) [mac_len]u8 {
    var address_len: [2]u8 = undefined;
    std.debug.assert(peer_address.len <= std.math.maxInt(u16));
    std.mem.writeInt(u16, &address_len, @intCast(peer_address.len), .big);

    var hmac = HmacSha256.init(&secret);
    hmac.update(body);
    hmac.update(&address_len);
    hmac.update(peer_address);
    var tag: [mac_len]u8 = undefined;
    hmac.final(&tag);
    return tag;
}

test "address validation token validates kind, lifetime, and address binding" {
    const secret: Secret = [_]u8{0x42} ** secret_len;
    const nonce: Nonce = [_]u8{0x99} ** nonce_len;
    const peer_address = "203.0.113.7:4433";

    const encoded = try encode(std.testing.allocator, secret, .{
        .kind = .retry,
        .issued_millis = 1_000,
        .lifetime_millis = 5_000,
        .peer_address = peer_address,
        .nonce = nonce,
    });
    defer std.testing.allocator.free(encoded);

    try std.testing.expectEqual(@as(usize, token_len), encoded.len);
    const validation = try validate(secret, .retry, 1_100, peer_address, encoded);
    try std.testing.expectEqual(Kind.retry, validation.kind);
    try std.testing.expectEqual(packet.Version.v1, validation.originating_version);
    try std.testing.expectEqual(@as(i64, 1_000), validation.issued_millis);
    try std.testing.expectEqual(@as(u64, 5_000), validation.lifetime_millis);
    try std.testing.expectEqualSlices(u8, &nonce, &validation.nonce);

    try std.testing.expectError(error.InvalidToken, validate(secret, .new_token, 1_100, peer_address, encoded));
    try std.testing.expectError(error.InvalidToken, validate(secret, .retry, 1_100, "203.0.113.8:4433", encoded));
    try std.testing.expectError(error.TokenNotYetValid, validate(secret, .retry, 999, peer_address, encoded));
    try std.testing.expectError(error.TokenExpired, validate(secret, .retry, 6_001, peer_address, encoded));
}

test "address validation token binds originating QUIC version" {
    const secret: Secret = [_]u8{0x63} ** secret_len;
    const nonce: Nonce = [_]u8{0x36} ** nonce_len;
    const peer_address = "203.0.113.63:4433";

    const encoded = try encode(std.testing.allocator, secret, .{
        .kind = .new_token,
        .originating_version = .v2,
        .issued_millis = 1_000,
        .lifetime_millis = 5_000,
        .peer_address = peer_address,
        .nonce = nonce,
    });
    defer std.testing.allocator.free(encoded);

    try std.testing.expectError(
        error.InvalidToken,
        validateForVersion(secret, .new_token, .v1, 1_100, peer_address, encoded),
    );

    const validation = try validateForVersion(secret, .new_token, .v2, 1_100, peer_address, encoded);
    try std.testing.expectEqual(packet.Version.v2, validation.originating_version);
    try std.testing.expectEqual(Kind.new_token, validation.kind);

    const secrets = [_]Secret{secret};
    const rotated_validation = try validateAnySecretForVersion(&secrets, .new_token, .v2, 1_100, peer_address, encoded);
    try std.testing.expectEqual(packet.Version.v2, rotated_validation.originating_version);
}

test "address validation token validates against rotated secrets" {
    const old_secret: Secret = [_]u8{0x11} ** secret_len;
    const current_secret: Secret = [_]u8{0x22} ** secret_len;
    const nonce: Nonce = [_]u8{0x44} ** nonce_len;
    const peer_address = "203.0.113.71:4433";

    const encoded = try encode(std.testing.allocator, old_secret, .{
        .kind = .new_token,
        .issued_millis = 1_000,
        .lifetime_millis = 5_000,
        .peer_address = peer_address,
        .nonce = nonce,
    });
    defer std.testing.allocator.free(encoded);

    const rotated = [_]Secret{ current_secret, old_secret };
    const validation = try validateAnySecret(&rotated, .new_token, 1_100, peer_address, encoded);
    try std.testing.expectEqual(Kind.new_token, validation.kind);
    try std.testing.expectEqual(@as(i64, 1_000), validation.issued_millis);

    const current_only = [_]Secret{current_secret};
    try std.testing.expectError(error.InvalidToken, validateAnySecret(&current_only, .new_token, 1_100, peer_address, encoded));
    try std.testing.expectError(error.InvalidToken, validateAnySecret(&[_]Secret{}, .new_token, 1_100, peer_address, encoded));
    try std.testing.expectError(error.TokenExpired, validateAnySecret(&rotated, .new_token, 6_001, peer_address, encoded));
}

test "address validation token validates and records replay fingerprints" {
    const secret: Secret = [_]u8{0x62} ** secret_len;
    const nonce: Nonce = [_]u8{0x26} ** nonce_len;
    const peer_address = "198.51.100.62:4433";
    const secrets = [_]Secret{secret};
    var replay_filter = ReplayFilter.init(std.testing.allocator, 4);
    defer replay_filter.deinit();

    const encoded = try encode(std.testing.allocator, secret, .{
        .kind = .retry,
        .issued_millis = 200,
        .lifetime_millis = 1_000,
        .peer_address = peer_address,
        .nonce = nonce,
    });
    defer std.testing.allocator.free(encoded);

    const validation = try validateAnySecretAndRemember(&secrets, .retry, 250, peer_address, encoded, &replay_filter);
    try std.testing.expectEqual(Kind.retry, validation.kind);
    try std.testing.expect(try replay_filter.contains(encoded));
    try std.testing.expectError(
        error.TokenReplay,
        validateAnySecretAndRemember(&secrets, .retry, 260, peer_address, encoded, &replay_filter),
    );
}

test "address validation token rejects tampering and invalid inputs" {
    const secret: Secret = [_]u8{0x33} ** secret_len;
    const nonce: Nonce = [_]u8{0x77} ** nonce_len;
    const peer_address = "198.51.100.4:4433";

    const encoded = try encode(std.testing.allocator, secret, .{
        .kind = .new_token,
        .issued_millis = 10,
        .lifetime_millis = 90,
        .peer_address = peer_address,
        .nonce = nonce,
    });
    defer std.testing.allocator.free(encoded);

    const tampered = try std.testing.allocator.dupe(u8, encoded);
    defer std.testing.allocator.free(tampered);
    tampered[magic.len + 1] ^= 0x01;
    try std.testing.expectError(error.InvalidToken, validate(secret, .new_token, 20, peer_address, tampered));

    try std.testing.expectError(error.InvalidToken, encode(std.testing.allocator, secret, .{
        .kind = .retry,
        .issued_millis = -1,
        .lifetime_millis = 10,
        .peer_address = peer_address,
        .nonce = nonce,
    }));
    try std.testing.expectError(error.InvalidToken, encode(std.testing.allocator, secret, .{
        .kind = .retry,
        .issued_millis = 0,
        .lifetime_millis = 0,
        .peer_address = peer_address,
        .nonce = nonce,
    }));
    try std.testing.expectError(error.InvalidToken, encode(std.testing.allocator, secret, .{
        .kind = .retry,
        .issued_millis = 0,
        .lifetime_millis = 10,
        .peer_address = "",
        .nonce = nonce,
    }));
}

test "address validation token reports allocation failure" {
    const secret: Secret = [_]u8{0x55} ** secret_len;
    const nonce: Nonce = [_]u8{0x11} ** nonce_len;
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });

    try std.testing.expectError(error.OutOfMemory, encode(failing_allocator.allocator(), secret, .{
        .kind = .retry,
        .issued_millis = 0,
        .lifetime_millis = 10,
        .peer_address = "192.0.2.10:4433",
        .nonce = nonce,
    }));
}

test "address validation replay filter rejects duplicate token fingerprints" {
    const secret: Secret = [_]u8{0x24} ** secret_len;
    const nonce: Nonce = [_]u8{0x12} ** nonce_len;
    const peer_address = "203.0.113.30:4433";
    var replay_filter = ReplayFilter.init(std.testing.allocator, 4);
    defer replay_filter.deinit();

    const encoded = try encode(std.testing.allocator, secret, .{
        .kind = .new_token,
        .issued_millis = 100,
        .lifetime_millis = 1_000,
        .peer_address = peer_address,
        .nonce = nonce,
    });
    defer std.testing.allocator.free(encoded);

    _ = try validate(secret, .new_token, 200, peer_address, encoded);
    try std.testing.expect(!try replay_filter.contains(encoded));
    try replay_filter.rememberValidated(encoded);
    try std.testing.expect(try replay_filter.contains(encoded));
    try std.testing.expectError(error.TokenReplay, replay_filter.rememberValidated(encoded));
}

test "address validation replay filter rejects invalid token shape" {
    var replay_filter = ReplayFilter.init(std.testing.allocator, 4);
    defer replay_filter.deinit();

    try std.testing.expectError(error.InvalidToken, replay_filter.rememberValidated("invalid-token"));
    try std.testing.expectError(error.InvalidToken, replay_filter.contains("invalid-token"));
}

test "address validation replay filter evicts oldest fingerprint at capacity" {
    const secret: Secret = [_]u8{0x44} ** secret_len;
    const peer_address = "198.51.100.44:4433";
    const nonce_a: Nonce = [_]u8{0x01} ** nonce_len;
    const nonce_b: Nonce = [_]u8{0x02} ** nonce_len;
    const nonce_c: Nonce = [_]u8{0x03} ** nonce_len;
    var replay_filter = ReplayFilter.init(std.testing.allocator, 2);
    defer replay_filter.deinit();

    const token_a = try encode(std.testing.allocator, secret, .{
        .kind = .new_token,
        .issued_millis = 1,
        .lifetime_millis = 1_000,
        .peer_address = peer_address,
        .nonce = nonce_a,
    });
    defer std.testing.allocator.free(token_a);
    const token_b = try encode(std.testing.allocator, secret, .{
        .kind = .new_token,
        .issued_millis = 2,
        .lifetime_millis = 1_000,
        .peer_address = peer_address,
        .nonce = nonce_b,
    });
    defer std.testing.allocator.free(token_b);
    const token_c = try encode(std.testing.allocator, secret, .{
        .kind = .new_token,
        .issued_millis = 3,
        .lifetime_millis = 1_000,
        .peer_address = peer_address,
        .nonce = nonce_c,
    });
    defer std.testing.allocator.free(token_c);

    _ = try validate(secret, .new_token, 10, peer_address, token_a);
    _ = try validate(secret, .new_token, 10, peer_address, token_b);
    _ = try validate(secret, .new_token, 10, peer_address, token_c);

    try replay_filter.rememberValidated(token_a);
    try replay_filter.rememberValidated(token_b);
    try replay_filter.rememberValidated(token_c);

    try std.testing.expect(!try replay_filter.contains(token_a));
    try std.testing.expect(try replay_filter.contains(token_b));
    try std.testing.expect(try replay_filter.contains(token_c));
}

test "address validation replay filter exports and restores fingerprint snapshots" {
    const secret: Secret = [_]u8{0x81} ** secret_len;
    const peer_address = "198.51.100.81:4433";
    const nonce_a: Nonce = [_]u8{0x0a} ** nonce_len;
    const nonce_b: Nonce = [_]u8{0x0b} ** nonce_len;
    var replay_filter = ReplayFilter.init(std.testing.allocator, 4);
    defer replay_filter.deinit();

    const token_a = try encode(std.testing.allocator, secret, .{
        .kind = .new_token,
        .issued_millis = 1,
        .lifetime_millis = 1_000,
        .peer_address = peer_address,
        .nonce = nonce_a,
    });
    defer std.testing.allocator.free(token_a);
    const token_b = try encode(std.testing.allocator, secret, .{
        .kind = .new_token,
        .issued_millis = 2,
        .lifetime_millis = 1_000,
        .peer_address = peer_address,
        .nonce = nonce_b,
    });
    defer std.testing.allocator.free(token_b);

    try replay_filter.rememberValidated(token_a);
    try replay_filter.rememberValidated(token_b);
    var snapshot = try replay_filter.exportSnapshot(std.testing.allocator);
    defer snapshot.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), snapshot.fingerprints.len);

    var restored = try ReplayFilter.initWithSnapshot(std.testing.allocator, 4, snapshot);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 2), restored.entryCount());
    try std.testing.expect(try restored.contains(token_a));
    try std.testing.expect(try restored.contains(token_b));
    try std.testing.expectError(error.TokenReplay, restored.rememberValidated(token_a));

    var trimmed = try ReplayFilter.initWithSnapshot(std.testing.allocator, 1, snapshot);
    defer trimmed.deinit();
    try std.testing.expectEqual(@as(usize, 1), trimmed.entryCount());
    try std.testing.expect(!try trimmed.contains(token_a));
    try std.testing.expect(try trimmed.contains(token_b));
}
