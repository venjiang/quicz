const std = @import("std");
const crypto = std.crypto;

const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const Sha256 = crypto.hash.sha2.Sha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const X25519 = crypto.dh.X25519;

const secret_len: usize = 32;
const key_len: usize = 16;
const iv_len: usize = 12;
const hp_len: usize = 16;

/// SHA-256 transcript hash for TLS 1.3 handshake messages (RFC 8446 §4.4.1).
pub const TranscriptHash = struct {
    state: Sha256,

    pub fn init() TranscriptHash {
        return .{ .state = Sha256.init(.{}) };
    }

    pub fn update(self: *TranscriptHash, msg: []const u8) void {
        self.state.update(msg);
    }

    pub fn current(self: *const TranscriptHash) [32]u8 {
        var copy = self.state;
        return copy.finalResult();
    }
};

/// TLS 1.3 key schedule (RFC 8446 §7.1).
pub const KeySchedule = struct {
    early_secret: [secret_len]u8,
    handshake_secret: [secret_len]u8 = undefined,
    master_secret: [secret_len]u8 = undefined,

    client_handshake_traffic_secret: [secret_len]u8 = undefined,
    server_handshake_traffic_secret: [secret_len]u8 = undefined,
    client_app_traffic_secret: [secret_len]u8 = undefined,
    server_app_traffic_secret: [secret_len]u8 = undefined,

    handshake_secret_derived: bool = false,
    app_secret_derived: bool = false,

    /// Initialize with no PSK (early_secret = HKDF-Extract(0, 0)).
    pub fn init() KeySchedule {
        const zeros = [_]u8{0} ** secret_len;
        return .{
            .early_secret = HkdfSha256.extract(&zeros, &zeros),
        };
    }

    /// Initialize with a PSK (early_secret = HKDF-Extract(0, PSK)).
    pub fn initWithPsk(psk: [secret_len]u8) KeySchedule {
        const salt = [_]u8{0} ** secret_len;
        return .{
            .early_secret = HkdfSha256.extract(&salt, &psk),
        };
    }

    /// Derive handshake traffic secrets from the ECDHE shared secret and
    /// the transcript hash up to the ServerHello (RFC 8446 §7.1).
    pub fn deriveHandshakeSecrets(
        self: *KeySchedule,
        shared_secret: []const u8,
        transcript_hash: [32]u8,
    ) void {
        var empty_hash: [32]u8 = undefined;
        Sha256.hash(&.{}, &empty_hash, .{});
        const derived_secret = expandLabel(self.early_secret, "derived", &empty_hash, secret_len);
        self.handshake_secret = HkdfSha256.extract(&derived_secret, shared_secret);
        self.client_handshake_traffic_secret = expandLabel(
            self.handshake_secret,
            "c hs traffic",
            &transcript_hash,
            secret_len,
        );
        self.server_handshake_traffic_secret = expandLabel(
            self.handshake_secret,
            "s hs traffic",
            &transcript_hash,
            secret_len,
        );
        self.handshake_secret_derived = true;
    }

    /// Derive application traffic secrets from the transcript hash up to the
    /// server Finished (RFC 8446 §7.1).
    pub fn deriveAppSecrets(self: *KeySchedule, transcript_hash: [32]u8) void {
        var empty_hash: [32]u8 = undefined;
        Sha256.hash(&.{}, &empty_hash, .{});
        const derived_secret = expandLabel(self.handshake_secret, "derived", &empty_hash, secret_len);
        const zeros = [_]u8{0} ** secret_len;
        self.master_secret = HkdfSha256.extract(&derived_secret, &zeros);
        self.client_app_traffic_secret = expandLabel(
            self.master_secret,
            "c ap traffic",
            &transcript_hash,
            secret_len,
        );
        self.server_app_traffic_secret = expandLabel(
            self.master_secret,
            "s ap traffic",
            &transcript_hash,
            secret_len,
        );
        self.app_secret_derived = true;
    }

    /// Derive QUIC packet protection keys from a traffic secret (RFC 9001 §5.1).
    pub fn deriveQuicKeys(
        traffic_secret: [secret_len]u8,
    ) struct { key: [key_len]u8, iv: [iv_len]u8, hp: [hp_len]u8 } {
        return .{
            .key = expandLabel(traffic_secret, "quic key", &.{}, key_len),
            .iv = expandLabel(traffic_secret, "quic iv", &.{}, iv_len),
            .hp = expandLabel(traffic_secret, "quic hp", &.{}, hp_len),
        };
    }

    /// Compute the Finished verify_data (RFC 8446 §4.4.4).
    pub fn computeFinishedVerifyData(
        base_key: [secret_len]u8,
        transcript_hash: [32]u8,
    ) [32]u8 {
        const finished_key = expandLabel(base_key, "finished", &.{}, secret_len);
        var out: [32]u8 = undefined;
        HmacSha256.create(&out, &transcript_hash, &finished_key);
        return out;
    }
};

/// QUIC encryption level (maps to packet number spaces).
pub const EncryptionLevel = enum(u8) {
    initial = 0,
    early_data,
    handshake,
    application,
};

/// Action returned by the TLS handshake state machine step.
pub const Action = union(enum) {
    send_data: SendData,
    install_keys: InstallKeys,
    wait_for_data,
    complete,
    _continue,
};

pub const SendData = struct {
    level: EncryptionLevel,
    data: []const u8,
};

pub const QuicKeys = struct {
    key: [key_len]u8,
    iv: [iv_len]u8,
    hp: [hp_len]u8,
};

pub const InstallKeys = struct {
    level: EncryptionLevel,
    open: QuicKeys,
    seal: QuicKeys,
};

/// Configuration for a TLS 1.3 handshake.
pub const TlsConfig = struct {
    alpn: []const []const u8 = &.{},
    server_name: ?[]const u8 = null,
    cert_chain_der: []const []const u8 = &.{},
    private_key_bytes: ?[]const u8 = null,
    skip_cert_verify: bool = true,
};

/// TLS handshake error set.
pub const HandshakeError = error{
    UnexpectedMessage,
    DecodeError,
    BadCertificate,
    BadCertificateVerify,
    BadFinished,
    InternalError,
    KeyScheduleError,
    NoKeyShare,
    UnsupportedVersion,
    NoApplicationProtocol,
    MissingExtension,
};

// ─── Internal helpers ───────────────────────────────────────────────

fn expandLabel(
    secret: [secret_len]u8,
    label: []const u8,
    context: []const u8,
    comptime len: usize,
) [len]u8 {
    return std.crypto.tls.hkdfExpandLabel(HkdfSha256, secret, label, context, len);
}

fn readU16(buf: []const u8) u16 {
    return std.mem.readInt(u16, buf[0..2], .big);
}

// ─── Tests ──────────────────────────────────────────────────────────

test "KeySchedule init is deterministic and differs from PSK" {
    const ks = KeySchedule.init();
    const ks2 = KeySchedule.init();
    try std.testing.expectEqualSlices(u8, &ks.early_secret, &ks2.early_secret);

    const psk = [_]u8{0xab} ** secret_len;
    const ks_psk = KeySchedule.initWithPsk(psk);
    try std.testing.expect(!std.mem.eql(u8, &ks.early_secret, &ks_psk.early_secret));
}

test "KeySchedule deriveQuicKeys produces correct lengths" {
    const traffic_secret = [_]u8{0xab} ** secret_len;
    const keys = KeySchedule.deriveQuicKeys(traffic_secret);
    try std.testing.expectEqual(key_len, keys.key.len);
    try std.testing.expectEqual(iv_len, keys.iv.len);
    try std.testing.expectEqual(hp_len, keys.hp.len);
}

test "KeySchedule deriveQuicKeys is deterministic" {
    const traffic_secret = [_]u8{0xcd} ** secret_len;
    const keys1 = KeySchedule.deriveQuicKeys(traffic_secret);
    const keys2 = KeySchedule.deriveQuicKeys(traffic_secret);
    try std.testing.expectEqualSlices(u8, &keys1.key, &keys2.key);
    try std.testing.expectEqualSlices(u8, &keys1.iv, &keys2.iv);
    try std.testing.expectEqualSlices(u8, &keys1.hp, &keys2.hp);
}

test "KeySchedule deriveQuicKeys differs for different secrets" {
    const secret_a = [_]u8{0x01} ** secret_len;
    const secret_b = [_]u8{0x02} ** secret_len;
    const keys_a = KeySchedule.deriveQuicKeys(secret_a);
    const keys_b = KeySchedule.deriveQuicKeys(secret_b);
    try std.testing.expect(!std.mem.eql(u8, &keys_a.key, &keys_b.key));
    try std.testing.expect(!std.mem.eql(u8, &keys_a.iv, &keys_b.iv));
}

test "KeySchedule computeFinishedVerifyData produces 32 bytes" {
    const base_key = [_]u8{0xef} ** secret_len;
    const transcript = [_]u8{0x12} ** 32;
    const verify_data = KeySchedule.computeFinishedVerifyData(base_key, transcript);
    try std.testing.expectEqual(@as(usize, 32), verify_data.len);
}

test "TranscriptHash is empty hash on init" {
    const th = TranscriptHash.init();
    const hash = th.current();
    // SHA-256 of empty string
    const expected = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "TranscriptHash update changes hash" {
    var th = TranscriptHash.init();
    const empty_hash = th.current();
    th.update("ClientHello");
    const updated_hash = th.current();
    try std.testing.expect(!std.mem.eql(u8, &empty_hash, &updated_hash));
}

test "TranscriptHash snapshot does not consume state" {
    var th = TranscriptHash.init();
    th.update("message1");
    const snapshot = th.current();
    th.update("message2");
    const final_hash = th.current();
    try std.testing.expect(!std.mem.eql(u8, &snapshot, &final_hash));
}

test "KeySchedule handshake secrets differ for client and server" {
    const ks = KeySchedule.init();
    var ks_copy = ks;
    const shared_secret = [_]u8{0x42} ** 32;
    const transcript = [_]u8{0x00} ** 32;
    ks_copy.deriveHandshakeSecrets(&shared_secret, transcript);
    try std.testing.expect(ks_copy.handshake_secret_derived);
    try std.testing.expect(!std.mem.eql(
        u8,
        &ks_copy.client_handshake_traffic_secret,
        &ks_copy.server_handshake_traffic_secret,
    ));
}
