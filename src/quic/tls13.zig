const std = @import("std");
const crypto = std.crypto;
const builtin = @import("builtin");

const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const Sha256 = crypto.hash.sha2.Sha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const X25519 = crypto.dh.X25519;
const Certificate = crypto.Certificate;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const Ed25519 = crypto.sign.Ed25519;
const SignatureScheme = crypto.tls.SignatureScheme;

pub const secret_len: usize = 32;
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

    /// Derive the resumption master secret (RFC 8446 §7.1). Used to derive
    /// PSK values for session resumption and 0-RTT early data.
    pub fn deriveResumptionMasterSecret(self: *const KeySchedule, transcript_hash: [32]u8) [secret_len]u8 {
        return expandLabel(self.master_secret, "res master", &transcript_hash, secret_len);
    }

    /// Derive a PSK from the resumption master secret and a NewSessionTicket
    /// nonce (RFC 8446 §8.1). The resulting PSK seeds `initWithPsk` for a
    /// resumed session that can send 0-RTT early data.
    pub fn derivePskFromTicket(resumption_master_secret: [secret_len]u8, ticket_nonce: []const u8) [secret_len]u8 {
        return expandLabel(resumption_master_secret, "resumption", ticket_nonce, secret_len);
    }

    /// Derive the client early traffic secret for 0-RTT early data
    /// (RFC 8446 §7.1). Requires a PSK-based early secret (`initWithPsk`);
    /// with a no-PSK schedule the result is not useful for 0-RTT.
    pub fn deriveEarlyTrafficSecret(self: *const KeySchedule, transcript_hash: [32]u8) [secret_len]u8 {
        return expandLabel(self.early_secret, "c e traffic", &transcript_hash, secret_len);
    }

    /// Derive the resumption binder key for the PSK binder in a
    /// pre_shared_key extension (RFC 8446 §7.1). Requires a PSK-based
    /// early secret; feeds `computeFinishedVerifyData` to produce the
    /// binder HMAC over the ClientHello transcript truncated at the binder.
    pub fn deriveBinderKey(self: *const KeySchedule) [secret_len]u8 {
        return expandLabel(self.early_secret, "res binder", &.{}, secret_len);
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

/// Signature algorithm used by the server's CertificateVerify (matches the
/// private key in `TlsConfig.private_key_bytes`).
pub const PrivateKeyAlgorithm = enum {
    ecdsa_p256_sha256,
    ed25519,
};

/// Configuration for a TLS 1.3 handshake.
pub const TlsConfig = struct {
    alpn: []const []const u8 = &.{},
    server_name: ?[]const u8 = null,
    cert_chain_der: []const []const u8 = &.{},
    /// Raw private key (32 bytes): P-256 scalar or Ed25519 seed.
    private_key_bytes: ?[]const u8 = null,
    private_key_algorithm: PrivateKeyAlgorithm = .ecdsa_p256_sha256,
    skip_cert_verify: bool = true,
    /// Optional wall-clock seconds since epoch for certificate validity-period
    /// checks. When null, validity is not checked.
    now_sec: ?i64 = null,
    /// Optional CA bundle for chain-to-trust-anchor verification. Requires
    /// `now_sec` to be set as well.
    ca_bundle: ?*const Certificate.Bundle = null,
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
    UnrecognizedName,
    UnsupportedSignatureAlgorithm,
    UnsupportedPskKeyExchangeMode,
};

// ─── CertificateVerify signature verification ───────────────────────

/// Verify a TLS 1.3 CertificateVerify signature against a public key
/// (RFC 8446 §4.4.3). `signed_content` is the already-assembled buffer of
/// 64 space bytes + "TLS 1.3, server CertificateVerify" + 0x00 + transcript
/// hash. The signature scheme must match the certificate's public-key
/// algorithm category; a mismatch is rejected as `BadCertificateVerify`.
fn verifyCertificateVerifySignature(
    pub_key: []const u8,
    pub_key_algo: Certificate.AlgorithmCategory,
    scheme: u16,
    sig: []const u8,
    signed_content: []const u8,
) HandshakeError!void {
    const s: SignatureScheme = @enumFromInt(scheme);
    switch (s) {
        .ecdsa_secp256r1_sha256 => {
            if (pub_key_algo != .X9_62_id_ecPublicKey) return error.BadCertificateVerify;
            const esig = EcdsaP256Sha256.Signature.fromDer(sig) catch return error.BadCertificateVerify;
            const pk = EcdsaP256Sha256.PublicKey.fromSec1(pub_key) catch return error.BadCertificateVerify;
            esig.verify(signed_content, pk) catch return error.BadCertificateVerify;
        },
        .ed25519 => {
            if (pub_key_algo != .curveEd25519) return error.BadCertificateVerify;
            if (sig.len != Ed25519.Signature.encoded_length) return error.BadCertificateVerify;
            if (pub_key.len != Ed25519.PublicKey.encoded_length) return error.BadCertificateVerify;
            const esig = Ed25519.Signature.fromBytes(sig[0..Ed25519.Signature.encoded_length].*);
            const pk = Ed25519.PublicKey.fromBytes(pub_key[0..Ed25519.PublicKey.encoded_length].*) catch return error.BadCertificateVerify;
            esig.verify(signed_content, pk) catch return error.BadCertificateVerify;
        },
        .rsa_pss_rsae_sha256 => {
            if (pub_key_algo != .rsaEncryption) return error.BadCertificateVerify;
            verifyRsaPssSha256(pub_key, sig, signed_content) catch return error.BadCertificateVerify;
        },
        else => return error.BadCertificateVerify,
    }
}

/// Verify an RSA-PSS-SHA256 signature (RFC 8017) over `msg` with a DER-encoded
/// RSA public key. The modulus length must be one of the supported TLS sizes.
fn verifyRsaPssSha256(pub_key_der: []const u8, sig: []const u8, msg: []const u8) HandshakeError!void {
    const rsa = Certificate.rsa;
    const comp = rsa.PublicKey.parseDer(pub_key_der) catch return error.BadCertificateVerify;
    switch (comp.modulus.len) {
        inline 128, 256, 384, 512 => |ml| {
            if (sig.len != ml) return error.BadCertificateVerify;
            const key = rsa.PublicKey.fromBytes(comp.exponent, comp.modulus) catch return error.BadCertificateVerify;
            const s = rsa.PSSSignature.fromBytes(ml, sig[0..ml]);
            rsa.PSSSignature.verify(ml, s, msg, key, Sha256) catch return error.BadCertificateVerify;
        },
        else => return error.BadCertificateVerify,
    }
}

/// Fill `buf` with cryptographically secure random bytes from the OS.
pub fn secureRandomBytes(buf: []u8) void {
    switch (builtin.os.tag) {
        .macos,
        .ios,
        .maccatalyst,
        .tvos,
        .watchos,
        .visionos,
        .freebsd,
        .netbsd,
        .openbsd,
        .dragonfly,
        .illumos,
        .serenity,
        => std.c.arc4random_buf(buf.ptr, buf.len),
        .linux => _ = std.c.getrandom(buf.ptr, buf.len, 0),
        else => @compileError("secureRandomBytes: unsupported OS"),
    }
}

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

fn readU32(buf: []const u8) u32 {
    return std.mem.readInt(u32, buf[0..4], .big);
}

/// Parsed NewSessionTicket handshake message (RFC 8446 §4.6.1).
pub const NewSessionTicket = struct {
    ticket_lifetime: u32,
    ticket_age_add: u32,
    ticket_nonce: []const u8,
    ticket: []const u8,
};

/// Parse a NewSessionTicket handshake message (RFC 8446 §4.6.1). The
/// `ticket_nonce` feeds `KeySchedule.derivePskFromTicket` to produce the
/// resumption PSK. Slices reference `msg` and remain valid while it does.
pub fn parseNewSessionTicket(msg: []const u8) HandshakeError!NewSessionTicket {
    if (msg.len < 4 or msg[0] != @intFromEnum(HandshakeType.new_session_ticket)) return error.UnexpectedMessage;
    const body_len = (@as(usize, msg[1]) << 16) |
        (@as(usize, msg[2]) << 8) |
        @as(usize, msg[3]);
    if (body_len != msg.len - 4) return error.DecodeError;

    var pos: usize = 4;
    if (pos + 4 > msg.len) return error.DecodeError;
    const ticket_lifetime = readU32(msg[pos..]);
    pos += 4;
    if (pos + 4 > msg.len) return error.DecodeError;
    const ticket_age_add = readU32(msg[pos..]);
    pos += 4;
    if (pos + 1 > msg.len) return error.DecodeError;
    const nonce_len = msg[pos];
    pos += 1;
    if (pos + nonce_len > msg.len) return error.DecodeError;
    const ticket_nonce = msg[pos .. pos + nonce_len];
    pos += nonce_len;
    if (pos + 2 > msg.len) return error.DecodeError;
    const ticket_len = readU16(msg[pos..]);
    pos += 2;
    if (ticket_len == 0) return error.DecodeError;
    if (pos + ticket_len > msg.len) return error.DecodeError;
    const ticket = msg[pos .. pos + ticket_len];
    pos += ticket_len;
    if (pos + 2 > msg.len) return error.DecodeError;
    const extensions_len = readU16(msg[pos..]);
    pos += 2;
    if (pos + extensions_len != msg.len) return error.DecodeError;
    return .{
        .ticket_lifetime = ticket_lifetime,
        .ticket_age_add = ticket_age_add,
        .ticket_nonce = ticket_nonce,
        .ticket = ticket,
    };
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

test "KeySchedule deriveResumptionMasterSecret is deterministic and distinct" {
    var ks = KeySchedule.init();
    const shared_secret = [_]u8{0x01} ** 32;
    const transcript = [_]u8{0x02} ** 32;
    ks.deriveHandshakeSecrets(&shared_secret, transcript);
    ks.deriveAppSecrets(transcript);
    const rms1 = ks.deriveResumptionMasterSecret(transcript);
    const rms2 = ks.deriveResumptionMasterSecret(transcript);
    try std.testing.expectEqual(@as(usize, secret_len), rms1.len);
    try std.testing.expectEqualSlices(u8, &rms1, &rms2);
    // Resumption master secret must differ from the app traffic secrets.
    try std.testing.expect(!std.mem.eql(u8, &rms1, &ks.client_app_traffic_secret));
    try std.testing.expect(!std.mem.eql(u8, &rms1, &ks.server_app_traffic_secret));
}

test "KeySchedule derivePskFromTicket is deterministic and nonce-dependent" {
    var ks = KeySchedule.init();
    const shared_secret = [_]u8{0x01} ** 32;
    const transcript = [_]u8{0x02} ** 32;
    ks.deriveHandshakeSecrets(&shared_secret, transcript);
    ks.deriveAppSecrets(transcript);
    const rms = ks.deriveResumptionMasterSecret(transcript);
    const nonce_a = [_]u8{0x03} ** 16;
    const nonce_b = [_]u8{0x04} ** 16;
    const psk_a1 = KeySchedule.derivePskFromTicket(rms, &nonce_a);
    const psk_a2 = KeySchedule.derivePskFromTicket(rms, &nonce_a);
    const psk_b = KeySchedule.derivePskFromTicket(rms, &nonce_b);
    try std.testing.expectEqual(@as(usize, secret_len), psk_a1.len);
    try std.testing.expectEqualSlices(u8, &psk_a1, &psk_a2);
    // Different ticket nonces yield different PSKs.
    try std.testing.expect(!std.mem.eql(u8, &psk_a1, &psk_b));
    // PSK differs from the resumption master secret.
    try std.testing.expect(!std.mem.eql(u8, &psk_a1, &rms));
}

test "parseNewSessionTicket parses fields" {
    const msg = [_]u8{
        0x04, 0x00, 0x00, 0x13, // type=new_session_ticket, length=19
        0x00, 0x00, 0x0e, 0x10, // ticket_lifetime=3600
        0x00, 0x00, 0x00, 0x01, // ticket_age_add=1
        0x02, 0xaa, 0xbb, // nonce_len=2, nonce=0xaabb
        0x00, 0x04, 0xcc, 0xdd, 0xee, 0xff, // ticket_len=4, ticket=0xccddeeff
        0x00, 0x00, // extensions_len=0
    };
    const nst = try parseNewSessionTicket(&msg);
    try std.testing.expectEqual(@as(u32, 3600), nst.ticket_lifetime);
    try std.testing.expectEqual(@as(u32, 1), nst.ticket_age_add);
    try std.testing.expectEqual(@as(usize, 2), nst.ticket_nonce.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb }, nst.ticket_nonce);
    try std.testing.expectEqual(@as(usize, 4), nst.ticket.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xcc, 0xdd, 0xee, 0xff }, nst.ticket);
}

test "parseNewSessionTicket rejects wrong type and truncation" {
    const wrong_type = [_]u8{ 0x01, 0x00, 0x00, 0x00 };
    try std.testing.expectError(error.UnexpectedMessage, parseNewSessionTicket(&wrong_type));
    const truncated = [_]u8{ 0x04, 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expectError(error.DecodeError, parseNewSessionTicket(&truncated));
}

test "parseNewSessionTicket rejects invalid vector boundaries" {
    const missing_extensions = [_]u8{
        0x04, 0x00, 0x00, 0x11,
        0x00, 0x00, 0x0e, 0x10,
        0x00, 0x00, 0x00, 0x01,
        0x02, 0xaa, 0xbb, 0x00,
        0x04, 0xcc, 0xdd, 0xee,
        0xff,
    };
    try std.testing.expectError(error.DecodeError, parseNewSessionTicket(&missing_extensions));

    const trailing_after_extensions = [_]u8{
        0x04, 0x00, 0x00, 0x14,
        0x00, 0x00, 0x0e, 0x10,
        0x00, 0x00, 0x00, 0x01,
        0x02, 0xaa, 0xbb, 0x00,
        0x04, 0xcc, 0xdd, 0xee,
        0xff, 0x00, 0x00, 0x00,
    };
    try std.testing.expectError(error.DecodeError, parseNewSessionTicket(&trailing_after_extensions));

    const header_length_mismatch = [_]u8{
        0x04, 0x00, 0x00, 0x12,
        0x00, 0x00, 0x0e, 0x10,
        0x00, 0x00, 0x00, 0x01,
        0x02, 0xaa, 0xbb, 0x00,
        0x04, 0xcc, 0xdd, 0xee,
        0xff, 0x00, 0x00,
    };
    try std.testing.expectError(error.DecodeError, parseNewSessionTicket(&header_length_mismatch));

    const empty_ticket = [_]u8{
        0x04, 0x00, 0x00, 0x0d,
        0x00, 0x00, 0x0e, 0x10,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00,
    };
    try std.testing.expectError(error.DecodeError, parseNewSessionTicket(&empty_ticket));
}

test "Tls13Handshake clientProcessNewSessionTicket derives and stores PSK" {
    const alpn = [_][]const u8{"hq-interop"};
    const tp = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var hs = Tls13Handshake.initClient(.{
        .alpn = &alpn,
        .server_name = "example.com",
    }, &tp);
    // Drive the key schedule to application secrets and mark connected so
    // the post-handshake path is reachable.
    const shared_secret = [_]u8{0x01} ** 32;
    hs.key_schedule.deriveHandshakeSecrets(&shared_secret, hs.transcript.current());
    hs.key_schedule.deriveAppSecrets(hs.transcript.current());
    hs.state = .connected;

    const nst_msg = [_]u8{
        0x04, 0x00, 0x00, 0x13, // type=new_session_ticket, length=19
        0x00, 0x00, 0x0e, 0x10, // ticket_lifetime=3600
        0x00, 0x00, 0x00, 0x01, // ticket_age_add=1
        0x02, 0xaa, 0xbb, // nonce_len=2, nonce=0xaabb
        0x00, 0x04, 0xcc, 0xdd, 0xee, 0xff, // ticket_len=4, ticket
        0x00, 0x00, // extensions_len=0
    };
    try hs.clientProcessNewSessionTicket(&nst_msg);
    try std.testing.expect(hs.resumption_psk != null);
}

test "Tls13Handshake clientProcessPostHandshake drains NewSessionTicket from input buffer" {
    const alpn = [_][]const u8{"hq-interop"};
    const tp = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var hs = Tls13Handshake.initClient(.{
        .alpn = &alpn,
        .server_name = "example.com",
    }, &tp);
    const shared_secret = [_]u8{0x01} ** 32;
    hs.key_schedule.deriveHandshakeSecrets(&shared_secret, hs.transcript.current());
    hs.key_schedule.deriveAppSecrets(hs.transcript.current());
    hs.state = .connected;

    const nst_msg = [_]u8{
        0x04, 0x00, 0x00, 0x13, // type=new_session_ticket, length=19
        0x00, 0x00, 0x0e, 0x10, // ticket_lifetime=3600
        0x00, 0x00, 0x00, 0x01, // ticket_age_add=1
        0x02, 0xaa, 0xbb, // nonce_len=2, nonce=0xaabb
        0x00, 0x04, 0xcc, 0xdd, 0xee, 0xff, // ticket_len=4, ticket
        0x00, 0x00, // extensions_len=0
    };
    hs.provideData(&nst_msg);
    try std.testing.expect(hs.resumption_psk == null);
    try hs.clientProcessPostHandshake();
    try std.testing.expect(hs.resumption_psk != null);
}

test "resumption PSK round-trips through initWithPsk" {
    var ks = KeySchedule.init();
    const shared_secret = [_]u8{0x01} ** 32;
    const transcript = [_]u8{0x02} ** 32;
    ks.deriveHandshakeSecrets(&shared_secret, transcript);
    ks.deriveAppSecrets(transcript);
    const rms = ks.deriveResumptionMasterSecret(transcript);
    const nonce = [_]u8{0x03} ** 16;
    const psk = KeySchedule.derivePskFromTicket(rms, &nonce);

    // A resumed session seeds the key schedule with the PSK.
    const resumed = KeySchedule.initWithPsk(psk);
    const zeros = [_]u8{0} ** secret_len;
    const expected_early = HkdfSha256.extract(&zeros, &psk);
    try std.testing.expectEqualSlices(u8, &expected_early, &resumed.early_secret);
    // The resumed early secret must differ from a fresh (no-PSK) early secret.
    const fresh = KeySchedule.init();
    try std.testing.expect(!std.mem.eql(u8, &resumed.early_secret, &fresh.early_secret));
}

test "KeySchedule deriveEarlyTrafficSecret is deterministic and PSK-dependent" {
    const psk = [_]u8{0xab} ** secret_len;
    const ks = KeySchedule.initWithPsk(psk);
    const transcript = [_]u8{0x02} ** 32;
    const early1 = ks.deriveEarlyTrafficSecret(transcript);
    const early2 = ks.deriveEarlyTrafficSecret(transcript);
    try std.testing.expectEqualSlices(u8, &early1, &early2);
    // Different PSK yields a different early traffic secret.
    const psk2 = [_]u8{0xcd} ** secret_len;
    const ks2 = KeySchedule.initWithPsk(psk2);
    const early3 = ks2.deriveEarlyTrafficSecret(transcript);
    try std.testing.expect(!std.mem.eql(u8, &early1, &early3));
}

test "Tls13Handshake initClientWithPsk seeds PSK and sets has_psk" {
    const alpn = [_][]const u8{"hq-interop"};
    const tp = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const psk = [_]u8{0xab} ** secret_len;
    const hs = Tls13Handshake.initClientWithPsk(.{
        .alpn = &alpn,
        .server_name = "example.com",
    }, &tp, psk);
    try std.testing.expect(hs.has_psk);
    // early_secret = HKDF-Extract(0, psk)
    const zeros = [_]u8{0} ** secret_len;
    const expected_early = HkdfSha256.extract(&zeros, &psk);
    try std.testing.expectEqualSlices(u8, &expected_early, &hs.key_schedule.early_secret);
    // has_psk is false for a regular initClient.
    const hs2 = Tls13Handshake.initClient(.{ .alpn = &alpn, .server_name = "example.com" }, &tp);
    try std.testing.expect(!hs2.has_psk);
}

test "KeySchedule deriveBinderKey is deterministic and PSK-dependent" {
    const psk = [_]u8{0xab} ** secret_len;
    const ks = KeySchedule.initWithPsk(psk);
    const binder1 = ks.deriveBinderKey();
    const binder2 = ks.deriveBinderKey();
    try std.testing.expectEqualSlices(u8, &binder1, &binder2);
    // Different PSK yields a different binder key.
    const psk2 = [_]u8{0xcd} ** secret_len;
    const ks2 = KeySchedule.initWithPsk(psk2);
    const binder3 = ks2.deriveBinderKey();
    try std.testing.expect(!std.mem.eql(u8, &binder1, &binder3));
    // Binder key differs from the early traffic secret.
    const transcript = [_]u8{0x02} ** 32;
    const early = ks.deriveEarlyTrafficSecret(transcript);
    try std.testing.expect(!std.mem.eql(u8, &binder1, &early));
}

test "Tls13Handshake clientProcessNewSessionTicket stores session ticket" {
    const alpn = [_][]const u8{"hq-interop"};
    const tp = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var hs = Tls13Handshake.initClient(.{
        .alpn = &alpn,
        .server_name = "example.com",
    }, &tp);
    const shared_secret = [_]u8{0x01} ** 32;
    hs.key_schedule.deriveHandshakeSecrets(&shared_secret, hs.transcript.current());
    hs.key_schedule.deriveAppSecrets(hs.transcript.current());
    hs.state = .connected;

    const nst_msg = [_]u8{
        0x04, 0x00, 0x00, 0x13,
        0x00, 0x00, 0x0e, 0x10,
        0x00, 0x00, 0x00, 0x01,
        0x02, 0xaa, 0xbb, 0x00,
        0x04, 0xcc, 0xdd, 0xee,
        0xff, 0x00, 0x00,
    };
    try hs.clientProcessNewSessionTicket(&nst_msg);
    try std.testing.expectEqual(@as(usize, 4), hs.session_ticket_len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xcc, 0xdd, 0xee, 0xff }, hs.session_ticket[0..4]);
}

test "Tls13Handshake clientProcessNewSessionTicket rejects oversized session ticket" {
    const alpn = [_][]const u8{"hq-interop"};
    const tp = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var hs = Tls13Handshake.initClient(.{
        .alpn = &alpn,
        .server_name = "example.com",
    }, &tp);
    const shared_secret = [_]u8{0x01} ** 32;
    hs.key_schedule.deriveHandshakeSecrets(&shared_secret, hs.transcript.current());
    hs.key_schedule.deriveAppSecrets(hs.transcript.current());
    hs.state = .connected;

    const oversized_ticket_len = 4097;
    const body_len = 4 + 4 + 1 + 2 + oversized_ticket_len + 2;
    var nst_msg: [4 + body_len]u8 = undefined;
    nst_msg[0] = @intFromEnum(HandshakeType.new_session_ticket);
    nst_msg[1] = @intCast((body_len >> 16) & 0xff);
    nst_msg[2] = @intCast((body_len >> 8) & 0xff);
    nst_msg[3] = @intCast(body_len & 0xff);
    var pos: usize = 4;
    writeU32(nst_msg[pos..], 3600);
    pos += 4;
    writeU32(nst_msg[pos..], 1);
    pos += 4;
    nst_msg[pos] = 0;
    pos += 1;
    writeU16(nst_msg[pos..], oversized_ticket_len);
    pos += 2;
    @memset(nst_msg[pos..][0..oversized_ticket_len], 0xcc);
    pos += oversized_ticket_len;
    writeU16(nst_msg[pos..], 0);
    pos += 2;
    try std.testing.expectEqual(nst_msg.len, pos);

    try std.testing.expectError(error.DecodeError, hs.clientProcessNewSessionTicket(&nst_msg));
}

test "PSK binder computes via computeFinishedVerifyData over binder key" {
    const psk = [_]u8{0xab} ** secret_len;
    const ks = KeySchedule.initWithPsk(psk);
    const binder_key = ks.deriveBinderKey();
    const transcript = [_]u8{0x02} ** 32;
    const binder = KeySchedule.computeFinishedVerifyData(binder_key, transcript);
    try std.testing.expectEqual(@as(usize, 32), binder.len);
    // Deterministic.
    const binder2 = KeySchedule.computeFinishedVerifyData(binder_key, transcript);
    try std.testing.expectEqualSlices(u8, &binder, &binder2);
    // Different transcript yields a different binder.
    const transcript2 = [_]u8{0x03} ** 32;
    const binder3 = KeySchedule.computeFinishedVerifyData(binder_key, transcript2);
    try std.testing.expect(!std.mem.eql(u8, &binder, &binder3));
}

test "Tls13Handshake ClientHello includes pre_shared_key when has_psk" {
    const alpn = [_][]const u8{"hq-interop"};
    const tp = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const psk = [_]u8{0xab} ** secret_len;
    var hs = Tls13Handshake.initClientWithPsk(.{
        .alpn = &alpn,
        .server_name = "example.com",
    }, &tp, psk);
    // Provide a session ticket so pre_shared_key is emitted.
    const ticket = [_]u8{ 0xcc, 0xdd, 0xee, 0xff };
    @memcpy(hs.session_ticket[0..ticket.len], &ticket);
    hs.session_ticket_len = ticket.len;

    const action = try hs.step();
    try std.testing.expect(action == .send_data);
    const data = action.send_data.data;
    // ClientHello type
    try std.testing.expectEqual(@as(u8, 1), data[0]);
    // Find pre_shared_key extension (0x0029) in the data.
    var found_psk = false;
    var i: usize = 0;
    while (i + 4 < data.len) : (i += 1) {
        if (data[i] == 0x00 and data[i + 1] == 0x29) {
            found_psk = true;
            break;
        }
    }
    try std.testing.expect(found_psk);
    // early_data extension (0x002A) must also be present (empty, signals 0-RTT).
    var found_early_data = false;
    i = 0;
    while (i + 4 < data.len) : (i += 1) {
        if (data[i] == 0x00 and data[i + 1] == 0x2A) {
            found_early_data = true;
            break;
        }
    }
    try std.testing.expect(found_early_data);
}

test "Tls13Handshake client rejects ClientHello PSK output overflow" {
    var long_name: [12250]u8 = undefined;
    @memset(&long_name, 'a');
    const psk = [_]u8{0xab} ** secret_len;
    var hs = Tls13Handshake.initClientWithPsk(.{
        .server_name = &long_name,
    }, &[_]u8{}, psk);
    @memset(&hs.session_ticket, 0xcc);
    hs.session_ticket_len = hs.session_ticket.len;

    try std.testing.expectError(error.DecodeError, hs.step());
}

test "Tls13Handshake server parses client pre_shared_key and early_data extensions" {
    const alpn = [_][]const u8{"hq-interop"};
    const tp = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const psk = [_]u8{0xab} ** secret_len;
    var client = Tls13Handshake.initClientWithPsk(.{
        .alpn = &alpn,
        .server_name = "example.com",
    }, &tp, psk);
    const ticket = [_]u8{ 0xcc, 0xdd, 0xee, 0xff };
    @memcpy(client.session_ticket[0..ticket.len], &ticket);
    client.session_ticket_len = ticket.len;

    // Build the ClientHello (with pre_shared_key + early_data).
    const action = try client.step();
    try std.testing.expect(action == .send_data);
    const client_hello = action.send_data.data;

    // Server receives the ClientHello and parses its extensions.
    var server = Tls13Handshake.initServer(.{
        .alpn = &alpn,
    }, &tp);
    server.provideData(client_hello);
    _ = try server.step();

    // Server recorded the 0-RTT offer and parsed the first identity + binder.
    try std.testing.expect(server.peer_offered_psk);
    try std.testing.expect(server.peer_offered_early_data);
    try std.testing.expectEqual(@as(usize, ticket.len), server.peer_psk_identity_len);
    try std.testing.expectEqualSlices(u8, &ticket, server.peer_psk_identity[0..server.peer_psk_identity_len]);
    // The binder is 32 bytes computed by the client over the truncated
    // ClientHello transcript; it must be non-zero (not the placeholder).
    var binder_is_zero = true;
    for (server.peer_psk_binder) |b| {
        if (b != 0) {
            binder_is_zero = false;
            break;
        }
    }
    try std.testing.expect(!binder_is_zero);
}

test "Tls13Handshake initServerWithPsk derives matching client early traffic secret" {
    const alpn = [_][]const u8{"hq-interop"};
    const tp = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const psk = [_]u8{0xab} ** secret_len;

    var client = Tls13Handshake.initClientWithPsk(.{
        .alpn = &alpn,
        .server_name = "example.com",
    }, &tp, psk);
    const ticket = [_]u8{ 0xcc, 0xdd, 0xee, 0xff };
    @memcpy(client.session_ticket[0..ticket.len], &ticket);
    client.session_ticket_len = ticket.len;
    const action = try client.step();
    const client_hello = action.send_data.data;

    var server = Tls13Handshake.initServerWithPsk(.{
        .alpn = &alpn,
    }, &tp, psk);
    try std.testing.expect(server.server_psk != null);
    try std.testing.expect(!server.server_early_traffic_secret_derived);
    server.provideData(client_hello);
    _ = try server.step();

    // After parsing the ClientHello, the server has derived the client
    // early traffic secret over the (shared) ClientHello transcript.
    try std.testing.expect(server.server_early_traffic_secret_derived);
    // The binder verifies against the matching PSK.
    try std.testing.expect(server.peer_psk_binder_valid);

    // Same PSK -> same early secret.
    try std.testing.expectEqualSlices(u8, &client.key_schedule.early_secret, &server.key_schedule.early_secret);

    // Recompute the expected secret directly from the ClientHello bytes the
    // client sent: same PSK (early secret) + same ClientHello transcript.
    var expected_ks = KeySchedule.initWithPsk(psk);
    var expected_th = TranscriptHash.init();
    expected_th.update(client_hello);
    const expected = expected_ks.deriveEarlyTrafficSecret(expected_th.current());
    try std.testing.expectEqualSlices(u8, &expected, &server.server_early_traffic_secret);

    // The server's peer (receive) 0-RTT secret must equal the client's
    // local (send) early traffic secret: same PSK -> same early secret,
    // same ClientHello -> same transcript hash.
    const client_early = client.key_schedule.deriveEarlyTrafficSecret(client.transcript.current());
    try std.testing.expectEqualSlices(u8, &client_early, &server.server_early_traffic_secret);
}

test "Tls13Handshake server rejects mismatched PSK binder" {
    const alpn = [_][]const u8{"hq-interop"};
    const tp = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const client_psk = [_]u8{0xab} ** secret_len;
    const server_psk = [_]u8{0xcd} ** secret_len;

    var client = Tls13Handshake.initClientWithPsk(.{
        .alpn = &alpn,
        .server_name = "example.com",
    }, &tp, client_psk);
    const ticket = [_]u8{ 0xcc, 0xdd, 0xee, 0xff };
    @memcpy(client.session_ticket[0..ticket.len], &ticket);
    client.session_ticket_len = ticket.len;
    const action = try client.step();
    const client_hello = action.send_data.data;

    // Server is configured with a different PSK: the binder_key derived
    // from it will not match the one the client used.
    var server = Tls13Handshake.initServerWithPsk(.{
        .alpn = &alpn,
    }, &tp, server_psk);
    server.provideData(client_hello);
    _ = try server.step();

    // Binder verification fails and the early traffic secret is NOT derived.
    try std.testing.expect(!server.peer_psk_binder_valid);
    try std.testing.expect(!server.server_early_traffic_secret_derived);
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

// ─── TLS 1.3 constants ──────────────────────────────────────────────

const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_verify = 15,
    finished = 20,
};

const ExtType = enum(u16) {
    server_name = 0x0000,
    supported_groups = 0x000A,
    signature_algorithms = 0x000D,
    alpn = 0x0010,
    pre_shared_key = 0x0029,
    psk_key_exchange_modes = 0x002D,
    early_data = 0x002A,
    supported_versions = 0x002B,
    key_share = 0x0033,
    quic_transport_parameters = 0x0039,
};

const cipher_aes_128_gcm_sha256: u16 = 0x1301;
const group_x25519: u16 = 0x001D;
const legacy_version_tls_1_2: u16 = 0x0303;
const version_tls_1_3: u16 = 0x0304;
const hello_retry_request_random = [_]u8{
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
    0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

const sig_ecdsa_secp256r1_sha256: u16 = 0x0403;
const sig_ed25519: u16 = 0x0807;
const sig_rsa_pss_rsae_sha256: u16 = 0x0804;

fn signatureSchemeForPrivateKeyAlgorithm(algorithm: PrivateKeyAlgorithm) u16 {
    return switch (algorithm) {
        .ecdsa_p256_sha256 => sig_ecdsa_secp256r1_sha256,
        .ed25519 => sig_ed25519,
    };
}

fn clientHelloKnownExtensionBit(ext_type: u16) ?u4 {
    return switch (ext_type) {
        @intFromEnum(ExtType.server_name) => 0,
        @intFromEnum(ExtType.supported_groups) => 1,
        @intFromEnum(ExtType.signature_algorithms) => 2,
        @intFromEnum(ExtType.alpn) => 3,
        @intFromEnum(ExtType.pre_shared_key) => 4,
        @intFromEnum(ExtType.early_data) => 5,
        @intFromEnum(ExtType.psk_key_exchange_modes) => 6,
        @intFromEnum(ExtType.supported_versions) => 7,
        @intFromEnum(ExtType.key_share) => 8,
        @intFromEnum(ExtType.quic_transport_parameters) => 9,
        else => null,
    };
}

fn serverHelloKnownExtensionBit(ext_type: u16) ?u4 {
    return switch (ext_type) {
        @intFromEnum(ExtType.supported_versions) => 0,
        @intFromEnum(ExtType.key_share) => 1,
        else => null,
    };
}

fn encryptedExtensionsKnownExtensionBit(ext_type: u16) ?u4 {
    return switch (ext_type) {
        @intFromEnum(ExtType.alpn) => 0,
        @intFromEnum(ExtType.quic_transport_parameters) => 1,
        else => null,
    };
}

// ─── Write helpers ───────────────────────────────────────────────────

fn writeU16(buf: []u8, val: u16) void {
    std.mem.writeInt(u16, buf[0..2], val, .big);
}

fn writeU32(buf: []u8, val: u32) void {
    std.mem.writeInt(u32, buf[0..4], val, .big);
}

fn writeExtHeader(buf: []u8, pos: usize, ext_type: u16, ext_len: usize) usize {
    writeU16(buf[pos..], ext_type);
    writeU16(buf[pos + 2 ..], @intCast(ext_len));
    return pos + 4;
}

// ─── Handshake state machine ─────────────────────────────────────────

const HandshakeState = enum {
    client_start,
    client_wait_server_hello,
    client_wait_encrypted_extensions,
    client_wait_certificate,
    client_wait_certificate_verify,
    client_wait_finished,
    client_send_finished,
    server_wait_client_hello,
    server_send_server_hello,
    server_send_encrypted_extensions,
    server_send_certificate,
    server_send_certificate_verify,
    server_send_finished,
    server_wait_client_finished,
    connected,
};

/// Pure Zig TLS 1.3 handshake state machine for QUIC (RFC 8446 + RFC 9001).
pub const Tls13Handshake = struct {
    state: HandshakeState,
    is_server: bool,
    transcript: TranscriptHash,
    key_schedule: KeySchedule,
    config: TlsConfig,

    // X25519 key exchange
    x25519_secret: [32]u8 = undefined,
    x25519_public: [32]u8 = undefined,
    peer_x25519_public: [32]u8 = undefined,

    // Output buffer (ClientHello / server flights)
    out_buf: [16384]u8 = undefined,
    out_len: usize = 0,

    // Input buffer (incoming handshake messages)
    in_buf: [16384]u8 = undefined,
    in_len: usize = 0,
    in_offset: usize = 0,

    // Client random (for SSLKEYLOGFILE and ServerHello matching)
    client_random: [32]u8 = undefined,
    // Server random (server side only; written into ServerHello)
    server_random: [32]u8 = undefined,

    // Negotiated ALPN
    negotiated_alpn: [256]u8 = undefined,
    negotiated_alpn_len: usize = 0,

    // Server-side: SNI host_name offered by the client.
    client_sni: [256]u8 = undefined,
    client_sni_len: usize = 0,

    // Pending key installation flags
    pending_install_handshake: bool = false,
    pending_install_app: bool = false,

    // Pre-encoded QUIC transport parameters
    tp_encoded: [1024]u8 = undefined,
    tp_encoded_len: usize = 0,
    local_tp_too_large: bool = false,

    // Peer QUIC transport parameters (parsed from EncryptedExtensions)
    peer_tp: [1024]u8 = undefined,
    peer_tp_len: usize = 0,

    // Server certificate (first in chain, DER) — verified via verifyServerCertificate
    server_cert: [4096]u8 = undefined,
    server_cert_len: usize = 0,

    // CertificateVerify signature — verified via verifyCertificateVerify
    cert_verify_scheme: u16 = 0,
    cert_verify_sig: [1024]u8 = undefined,
    cert_verify_sig_len: usize = 0,

    // Resumption PSK derived from a post-handshake NewSessionTicket (client
    // side). Seeds `KeySchedule.initWithPsk` for a future resumed session.
    resumption_psk: ?[secret_len]u8 = null,

    // True when the client was initialized with a resumption PSK, enabling
    // 0-RTT early data in the ClientHello.
    has_psk: bool = false,

    // Session ticket from a post-handshake NewSessionTicket (client side).
    // Carried in the pre_shared_key extension of a resumed ClientHello.
    session_ticket: [4096]u8 = undefined,
    session_ticket_len: usize = 0,

    // Server-side: a PSK configured out-of-band (extern_psk or a restored
    // resumption_psk) used to accept a resumed client's 0-RTT. When present,
    // the server seeds `KeySchedule.initWithPsk` so it can derive the same
    // client early traffic secret the client used to protect early data.
    server_psk: ?[secret_len]u8 = null,

    // Server-side: the client early traffic secret derived over the
    // ClientHello transcript once a matching PSK is in place. This is the
    // peer (receive) 0-RTT secret for the server.
    server_early_traffic_secret: [secret_len]u8 = undefined,
    server_early_traffic_secret_derived: bool = false,

    // Server-side: the psk_identity offered by the client in its
    // pre_shared_key extension (parsed but not yet validated against a
    // ticket store). `peer_offered_psk` is set whenever the extension is
    // present; `peer_offered_early_data` tracks the early_data extension.
    peer_psk_identity: [4096]u8 = undefined,
    peer_psk_identity_len: usize = 0,
    peer_psk_binder: [32]u8 = undefined,
    peer_offered_psk: bool = false,
    peer_offered_early_data: bool = false,

    // Server-side: the byte offset of the client's psk_binder within the
    // ClientHello handshake message (used to recompute the truncated
    // transcript hash for binder verification), and the verification result.
    peer_psk_binder_msg_offset: usize = 0,
    peer_psk_binder_valid: bool = false,

    // Server-side: whether a post-handshake NewSessionTicket has been emitted
    // for this connection (one-shot, so pump does not regenerate it).
    nst_sent: bool = false,

    /// Initialize as a TLS 1.3 client.
    pub fn initClient(config: TlsConfig, transport_params: []const u8) Tls13Handshake {
        var self: Tls13Handshake = undefined;
        self.state = .client_start;
        self.is_server = false;
        self.transcript = TranscriptHash.init();
        self.key_schedule = KeySchedule.init();
        self.config = config;
        self.out_len = 0;
        self.in_len = 0;
        self.in_offset = 0;
        self.pending_install_handshake = false;
        self.pending_install_app = false;
        self.negotiated_alpn_len = 0;
        self.client_sni_len = 0;
        self.peer_tp_len = 0;
        self.server_cert_len = 0;
        self.cert_verify_scheme = 0;
        self.cert_verify_sig_len = 0;
        self.resumption_psk = null;
        self.has_psk = false;
        self.session_ticket_len = 0;
        self.server_psk = null;
        self.peer_psk_identity_len = 0;
        self.peer_offered_psk = false;
        self.peer_offered_early_data = false;
        self.server_early_traffic_secret_derived = false;
        self.peer_psk_binder_valid = false;
        self.nst_sent = false;

        // Copy pre-encoded transport parameters. Oversized local bytes cannot
        // be represented without changing the wire value, so defer failure to
        // the message-building step instead of truncating.
        self.local_tp_too_large = transport_params.len > self.tp_encoded.len;
        const tp_len = if (self.local_tp_too_large) 0 else transport_params.len;
        @memcpy(self.tp_encoded[0..tp_len], transport_params[0..tp_len]);
        self.tp_encoded_len = tp_len;

        // Generate X25519 key pair
        secureRandomBytes(&self.x25519_secret);
        self.x25519_public = X25519.recoverPublicKey(self.x25519_secret) catch blk: {
            secureRandomBytes(&self.x25519_secret);
            break :blk X25519.recoverPublicKey(self.x25519_secret) catch unreachable;
        };

        return self;
    }

    /// Initialize as a TLS 1.3 client with a resumption PSK (RFC 8446 §7.1
    /// + §8.1). The PSK seeds the key schedule via `initWithPsk` and enables
    /// 0-RTT early data. The caller obtains the PSK from a prior session's
    /// `resumptionPsk` (client side, after a NewSessionTicket).
    pub fn initClientWithPsk(config: TlsConfig, transport_params: []const u8, psk: [secret_len]u8) Tls13Handshake {
        var self = initClient(config, transport_params);
        self.key_schedule = KeySchedule.initWithPsk(psk);
        self.has_psk = true;
        return self;
    }

    /// Initialize as a TLS 1.3 server. `transport_params` is the server's
    /// pre-encoded QUIC transport parameters to carry in EncryptedExtensions.
    pub fn initServer(config: TlsConfig, transport_params: []const u8) Tls13Handshake {
        var self: Tls13Handshake = undefined;
        self.state = .server_wait_client_hello;
        self.is_server = true;
        self.transcript = TranscriptHash.init();
        self.key_schedule = KeySchedule.init();
        self.config = config;
        self.out_len = 0;
        self.in_len = 0;
        self.in_offset = 0;
        self.pending_install_handshake = false;
        self.pending_install_app = false;
        self.negotiated_alpn_len = 0;
        self.client_sni_len = 0;
        self.peer_tp_len = 0;
        self.server_cert_len = 0;
        self.cert_verify_scheme = 0;
        self.cert_verify_sig_len = 0;
        self.resumption_psk = null;
        self.has_psk = false;
        self.session_ticket_len = 0;
        self.server_psk = null;
        self.peer_psk_identity_len = 0;
        self.peer_offered_psk = false;
        self.peer_offered_early_data = false;
        self.server_early_traffic_secret_derived = false;
        self.peer_psk_binder_valid = false;
        self.nst_sent = false;

        // Copy pre-encoded transport parameters (sent in EncryptedExtensions).
        // Oversized local bytes cannot be represented without changing the
        // wire value, so defer failure to the message-building step.
        self.local_tp_too_large = transport_params.len > self.tp_encoded.len;
        const tp_len = if (self.local_tp_too_large) 0 else transport_params.len;
        @memcpy(self.tp_encoded[0..tp_len], transport_params[0..tp_len]);
        self.tp_encoded_len = tp_len;

        // Generate X25519 key pair
        secureRandomBytes(&self.x25519_secret);
        self.x25519_public = X25519.recoverPublicKey(self.x25519_secret) catch blk: {
            secureRandomBytes(&self.x25519_secret);
            break :blk X25519.recoverPublicKey(self.x25519_secret) catch unreachable;
        };

        return self;
    }

    /// Initialize as a TLS 1.3 server configured with a PSK for accepting a
    /// resumed client's 0-RTT early data. The PSK must match the one the
    /// client used (extern_psk or a restored resumption_psk); the server
    /// derives the client early traffic secret from it once the ClientHello
    /// arrives.
    pub fn initServerWithPsk(config: TlsConfig, transport_params: []const u8, psk: [secret_len]u8) Tls13Handshake {
        var self = initServer(config, transport_params);
        self.server_psk = psk;
        self.key_schedule = KeySchedule.initWithPsk(psk);
        return self;
    }

    pub fn provideData(self: *Tls13Handshake, data: []const u8) void {
        if (self.in_offset > 0 and self.in_len - self.in_offset + data.len > self.in_buf.len) {
            const remaining = self.in_len - self.in_offset;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.in_buf[0..remaining], self.in_buf[self.in_offset..self.in_len]);
            }
            self.in_len = remaining;
            self.in_offset = 0;
        }
        const copy_len = @min(data.len, self.in_buf.len - self.in_len);
        @memcpy(self.in_buf[self.in_len..][0..copy_len], data[0..copy_len]);
        self.in_len += copy_len;
    }

    /// Read one handshake message from the input buffer.
    /// Returns null if not enough data is available.
    fn readHandshakeMsg(self: *Tls13Handshake) ?[]const u8 {
        const available = self.in_len - self.in_offset;
        if (available < 4) return null;
        const msg_len = (@as(usize, self.in_buf[self.in_offset + 1]) << 16) |
            (@as(usize, self.in_buf[self.in_offset + 2]) << 8) |
            @as(usize, self.in_buf[self.in_offset + 3]);
        const total = 4 + msg_len;
        if (available < total) return null;
        const msg = self.in_buf[self.in_offset..][0..total];
        self.in_offset += total;
        return msg;
    }

    /// Step the handshake state machine. Returns an action for the caller.
    pub fn step(self: *Tls13Handshake) HandshakeError!Action {
        if (self.pending_install_handshake) {
            self.pending_install_handshake = false;
            // Local = this endpoint's write secret; peer = remote's write secret.
            const local = KeySchedule.deriveQuicKeys(if (self.is_server)
                self.key_schedule.server_handshake_traffic_secret
            else
                self.key_schedule.client_handshake_traffic_secret);
            const peer = KeySchedule.deriveQuicKeys(if (self.is_server)
                self.key_schedule.client_handshake_traffic_secret
            else
                self.key_schedule.server_handshake_traffic_secret);
            return Action{ .install_keys = .{
                .level = .handshake,
                .open = .{ .key = peer.key, .iv = peer.iv, .hp = peer.hp },
                .seal = .{ .key = local.key, .iv = local.iv, .hp = local.hp },
            } };
        }
        if (self.pending_install_app) {
            self.pending_install_app = false;
            const local = KeySchedule.deriveQuicKeys(if (self.is_server)
                self.key_schedule.server_app_traffic_secret
            else
                self.key_schedule.client_app_traffic_secret);
            const peer = KeySchedule.deriveQuicKeys(if (self.is_server)
                self.key_schedule.client_app_traffic_secret
            else
                self.key_schedule.server_app_traffic_secret);
            return Action{ .install_keys = .{
                .level = .application,
                .open = .{ .key = peer.key, .iv = peer.iv, .hp = peer.hp },
                .seal = .{ .key = local.key, .iv = local.iv, .hp = local.hp },
            } };
        }

        switch (self.state) {
            .client_start => return self.clientBuildHello(),
            .client_wait_server_hello => return self.clientProcessServerHello(),
            .client_wait_encrypted_extensions => return self.clientProcessEncryptedExtensions(),
            .client_wait_certificate => return self.clientProcessCertificate(),
            .client_wait_certificate_verify => return self.clientProcessCertificateVerify(),
            .client_wait_finished => return self.clientProcessServerFinished(),
            .client_send_finished => return self.clientSendFinished(),
            .server_wait_client_hello => return self.serverProcessClientHello(),
            .server_send_server_hello => return self.serverBuildServerHello(),
            .server_send_encrypted_extensions => return self.serverBuildEncryptedExtensions(),
            .server_send_certificate => return self.serverBuildCertificate(),
            .server_send_certificate_verify => return self.serverBuildCertificateVerify(),
            .server_send_finished => return self.serverBuildFinished(),
            .server_wait_client_finished => return self.serverProcessClientFinished(),
            .connected => return .complete,
        }
    }

    pub fn isComplete(self: *const Tls13Handshake) bool {
        return self.state == .connected;
    }

    /// Process a post-handshake NewSessionTicket message (client side, after
    /// the handshake is complete). Derives the resumption PSK from the
    /// resumption master secret and the ticket nonce, and stores it for a
    /// future resumed session that can send 0-RTT early data
    /// (RFC 8446 §4.6.1 + §7.1 + §8.1).
    pub fn clientProcessNewSessionTicket(self: *Tls13Handshake, msg: []const u8) HandshakeError!void {
        if (self.is_server) return error.UnexpectedMessage;
        if (self.state != .connected) return error.UnexpectedMessage;
        const nst = try parseNewSessionTicket(msg);
        const rms = self.key_schedule.deriveResumptionMasterSecret(self.transcript.current());
        self.resumption_psk = KeySchedule.derivePskFromTicket(rms, nst.ticket_nonce);
        if (nst.ticket.len > self.session_ticket.len) return error.DecodeError;
        const ticket_len = nst.ticket.len;
        @memcpy(self.session_ticket[0..ticket_len], nst.ticket[0..ticket_len]);
        self.session_ticket_len = ticket_len;
    }

    /// Process buffered post-handshake messages (client side, after the
    /// handshake is complete). Currently handles NewSessionTicket to derive
    /// and store the resumption PSK; other post-handshake messages are
    /// ignored. Drains complete messages from the input buffer.
    pub fn clientProcessPostHandshake(self: *Tls13Handshake) HandshakeError!void {
        if (self.is_server) return;
        if (self.state != .connected) return;
        while (self.readHandshakeMsg()) |msg| {
            if (msg.len > 0 and msg[0] == @intFromEnum(HandshakeType.new_session_ticket)) {
                try self.clientProcessNewSessionTicket(msg);
            }
        }
    }

    /// Build a ClientHello message with ALPN, SNI, key_share, and QUIC
    /// transport parameters extensions (RFC 8446 §4.1.2 + RFC 9001 §8).
    fn clientBuildHello(self: *Tls13Handshake) HandshakeError!Action {
        if (self.local_tp_too_large) return error.DecodeError;
        secureRandomBytes(&self.client_random);

        const buf = &self.out_buf;
        var pos: usize = 4; // reserve type + 3-byte length

        // legacy_version = 0x0303
        buf[pos] = 0x03;
        buf[pos + 1] = 0x03;
        pos += 2;

        // random
        @memcpy(buf[pos..][0..32], &self.client_random);
        pos += 32;

        // session_id: empty (RFC 9001 §4.1 — QUIC uses empty session ID)
        buf[pos] = 0;
        pos += 1;

        // cipher_suites: TLS_AES_128_GCM_SHA256 only
        writeU16(buf[pos..], 2);
        pos += 2;
        writeU16(buf[pos..], cipher_aes_128_gcm_sha256);
        pos += 2;

        // compression_methods: null
        buf[pos] = 1;
        pos += 1;
        buf[pos] = 0;
        pos += 1;

        // ─── Extensions ───────────────────────────────────────────
        const ext_start = pos;
        pos += 2; // extensions length placeholder

        // supported_versions (TLS 1.3)
        pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.supported_versions), 3);
        buf[pos] = 2;
        pos += 1;
        writeU16(buf[pos..], version_tls_1_3);
        pos += 2;

        // key_share (X25519)
        const share_len = 2 + 2 + 32; // group + len + key
        pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.key_share), 2 + share_len);
        writeU16(buf[pos..], @intCast(share_len));
        pos += 2;
        writeU16(buf[pos..], group_x25519);
        pos += 2;
        writeU16(buf[pos..], 32);
        pos += 2;
        @memcpy(buf[pos..][0..32], &self.x25519_public);
        pos += 32;

        // signature_algorithms
        pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.signature_algorithms), 2 + 6);
        writeU16(buf[pos..], 6);
        pos += 2;
        writeU16(buf[pos..], sig_ecdsa_secp256r1_sha256);
        pos += 2;
        writeU16(buf[pos..], sig_ed25519);
        pos += 2;
        writeU16(buf[pos..], sig_rsa_pss_rsae_sha256);
        pos += 2;

        // supported_groups
        pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.supported_groups), 2 + 2);
        writeU16(buf[pos..], 2);
        pos += 2;
        writeU16(buf[pos..], group_x25519);
        pos += 2;

        // SNI (server_name)
        if (self.config.server_name) |sni| {
            if (sni.len == 0 or sni.len > std.math.maxInt(u16) - 5) return error.DecodeError;
            const sni_ext_len = 2 + 1 + 2 + sni.len;
            if (pos + 4 + sni_ext_len > buf.len) return error.DecodeError;
            pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.server_name), sni_ext_len);
            writeU16(buf[pos..], @intCast(1 + 2 + sni.len));
            pos += 2;
            buf[pos] = 0; // host_name type
            pos += 1;
            writeU16(buf[pos..], @intCast(sni.len));
            pos += 2;
            @memcpy(buf[pos..][0..sni.len], sni);
            pos += sni.len;
        }

        // ALPN
        if (self.config.alpn.len > 0) {
            var alpn_total: usize = 0;
            for (self.config.alpn) |proto| {
                if (proto.len == 0 or proto.len > std.math.maxInt(u8)) return error.DecodeError;
                alpn_total = std.math.add(usize, alpn_total, 1 + proto.len) catch return error.DecodeError;
                if (alpn_total > std.math.maxInt(u16) - 2) return error.DecodeError;
            }
            if (pos + 4 + 2 + alpn_total > buf.len) return error.DecodeError;
            pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.alpn), 2 + alpn_total);
            writeU16(buf[pos..], @intCast(alpn_total));
            pos += 2;
            for (self.config.alpn) |proto| {
                buf[pos] = @intCast(proto.len);
                pos += 1;
                @memcpy(buf[pos..][0..proto.len], proto);
                pos += proto.len;
            }
        }

        // QUIC transport parameters
        if (self.tp_encoded_len > 0) {
            if (pos + 4 + self.tp_encoded_len > buf.len) return error.DecodeError;
            pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.quic_transport_parameters), self.tp_encoded_len);
            @memcpy(buf[pos..][0..self.tp_encoded_len], self.tp_encoded[0..self.tp_encoded_len]);
            pos += self.tp_encoded_len;
        }

        // psk_key_exchange_modes
        if (pos + 4 + 2 > buf.len) return error.DecodeError;
        pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.psk_key_exchange_modes), 2);
        buf[pos] = 1;
        pos += 1;
        buf[pos] = 0x01; // psk_dhe_ke
        pos += 1;

        // early_data (RFC 8446 §4.2.10) -- empty extension signals 0-RTT
        // intent. Must precede pre_shared_key.
        if (self.has_psk) {
            if (pos + 4 > buf.len) return error.DecodeError;
            pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.early_data), 0);
        }

        // pre_shared_key (MUST be last; RFC 8446 §4.2.11) when a resumption
        // PSK + ticket are available. The binder is computed over the
        // ClientHello transcript truncated at the binder list.
        if (self.has_psk and self.session_ticket_len > 0) {
            const ticket_len = self.session_ticket_len;
            if (ticket_len > self.session_ticket.len) return error.DecodeError;
            const identity_len = std.math.add(usize, 2 + 4, ticket_len) catch return error.DecodeError;
            const identities_len = identity_len;
            const binder_len: usize = 32;
            const binders_len = 1 + binder_len;
            const psk_ext_data_len = 2 + identities_len + 2 + binders_len;
            if (psk_ext_data_len > std.math.maxInt(u16)) return error.DecodeError;
            if (pos + 4 + psk_ext_data_len > buf.len) return error.DecodeError;
            pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.pre_shared_key), psk_ext_data_len);
            // identities
            writeU16(buf[pos..], @intCast(identities_len));
            pos += 2;
            writeU16(buf[pos..], @intCast(ticket_len));
            pos += 2;
            @memcpy(buf[pos..][0..ticket_len], self.session_ticket[0..ticket_len]);
            pos += ticket_len;
            // obfuscated_ticket_age: 0 (no timing for this skeleton)
            buf[pos] = 0;
            buf[pos + 1] = 0;
            buf[pos + 2] = 0;
            buf[pos + 3] = 0;
            pos += 4;
            // binders
            writeU16(buf[pos..], @intCast(binders_len));
            pos += 2;
            buf[pos] = @intCast(binder_len);
            pos += 1;
            const binder_offset = pos;
            @memset(buf[pos..][0..binder_len], 0);
            pos += binder_len;

            // Fill in extensions length + handshake header BEFORE the
            // transcript update, so the binder is computed over the real
            // header/lengths (matching what the server hashes).
            self.out_len = pos;
            const ext_len = pos - ext_start - 2;
            writeU16(buf[ext_start..], @intCast(ext_len));
            const msg_len = pos - 4;
            buf[0] = @intFromEnum(HandshakeType.client_hello);
            buf[1] = @intCast((msg_len >> 16) & 0xFF);
            buf[2] = @intCast((msg_len >> 8) & 0xFF);
            buf[3] = @intCast(msg_len & 0xFF);

            // Binder = computeFinishedVerifyData(binder_key, transcript hash
            // truncated at the binder list, i.e. up to and including the
            // binder_len byte, excluding the binder bytes).
            self.transcript.update(buf[0..binder_offset]);
            const th = self.transcript.current();
            const binder_key = self.key_schedule.deriveBinderKey();
            const binder = KeySchedule.computeFinishedVerifyData(binder_key, th);
            @memcpy(buf[binder_offset..][0..binder_len], &binder);
            self.transcript.update(buf[binder_offset..][0..binder_len]);

            self.state = .client_wait_server_hello;
            return Action{ .send_data = .{
                .level = .initial,
                .data = self.out_buf[0..self.out_len],
            } };
        }

        // Fill in extensions length
        const ext_len = pos - ext_start - 2;
        writeU16(buf[ext_start..], @intCast(ext_len));

        // Fill in handshake header: type + 3-byte length
        const msg_len = pos - 4;
        buf[0] = @intFromEnum(HandshakeType.client_hello);
        buf[1] = @intCast((msg_len >> 16) & 0xFF);
        buf[2] = @intCast((msg_len >> 8) & 0xFF);
        buf[3] = @intCast(msg_len & 0xFF);

        self.out_len = pos;
        self.transcript.update(buf[0..pos]);
        self.state = .client_wait_server_hello;

        return Action{ .send_data = .{
            .level = .initial,
            .data = self.out_buf[0..self.out_len],
        } };
    }

    /// Parse a ServerHello, complete the X25519 key exchange, and derive
    /// handshake traffic secrets (RFC 8446 §4.1.3 + §7.1).
    fn clientProcessServerHello(self: *Tls13Handshake) HandshakeError!Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;
        if (msg.len < 4 or msg[0] != @intFromEnum(HandshakeType.server_hello)) return error.UnexpectedMessage;

        var pos: usize = 4;
        // legacy_version (0x0303)
        if (pos + 2 > msg.len) return error.DecodeError;
        if (readU16(msg[pos..]) != legacy_version_tls_1_2) return error.UnsupportedVersion;
        pos += 2;
        // random (32 bytes). HelloRetryRequest reuses ServerHello with a
        // fixed random sentinel; this minimal QUIC TLS path has no HRR state
        // machine yet, so reject before transcript/key-schedule progress.
        if (pos + 32 > msg.len) return error.DecodeError;
        if (std.mem.eql(u8, msg[pos..][0..32], &hello_retry_request_random)) return error.DecodeError;
        pos += 32;
        // legacy_session_id_echo
        if (pos + 1 > msg.len) return error.DecodeError;
        const sid_len = msg[pos];
        pos += 1;
        if (sid_len != 0) return error.DecodeError;
        if (pos + sid_len > msg.len) return error.DecodeError;
        pos += sid_len;
        // cipher_suite (must be TLS_AES_128_GCM_SHA256)
        if (pos + 2 > msg.len) return error.DecodeError;
        if (readU16(msg[pos..]) != cipher_aes_128_gcm_sha256) return error.DecodeError;
        pos += 2;
        // legacy_compression_method (null)
        if (pos + 1 > msg.len) return error.DecodeError;
        if (msg[pos] != 0) return error.DecodeError;
        pos += 1;
        // extensions
        if (pos + 2 > msg.len) return error.DecodeError;
        const ext_total = readU16(msg[pos..]);
        pos += 2;
        if (pos + ext_total != msg.len) return error.DecodeError;
        const ext_end = pos + ext_total;

        var have_version = false;
        var have_key_share = false;
        var seen_known_extensions: u16 = 0;
        while (pos < ext_end) {
            if (pos + 4 > ext_end) return error.DecodeError;
            const et = readU16(msg[pos..]);
            const el = readU16(msg[pos + 2 ..]);
            pos += 4;
            if (pos + el > ext_end) return error.DecodeError;
            const ext = msg[pos .. pos + el];
            pos += el;
            if (serverHelloKnownExtensionBit(et)) |bit| {
                const mask = @as(u16, 1) << bit;
                if (seen_known_extensions & mask != 0) return error.DecodeError;
                seen_known_extensions |= mask;
            }
            switch (et) {
                @intFromEnum(ExtType.supported_versions) => {
                    if (el != 2) return error.DecodeError;
                    if (readU16(ext[0..2]) != version_tls_1_3) return error.UnsupportedVersion;
                    have_version = true;
                },
                @intFromEnum(ExtType.key_share) => {
                    // ServerHello key_share: 2-byte group + 2-byte key length + key
                    if (el < 4) return error.DecodeError;
                    if (readU16(ext[0..2]) != group_x25519) return error.NoKeyShare;
                    const klen = readU16(ext[2..4]);
                    if (klen != 32 or el != 4 + 32) return error.DecodeError;
                    @memcpy(&self.peer_x25519_public, ext[4..36]);
                    have_key_share = true;
                },
                else => {}, // ignore unrecognized extensions
            }
        }

        if (!have_version) return error.MissingExtension;
        if (!have_key_share) return error.NoKeyShare;

        // ECDHE shared secret: client secret × server public.
        const shared = X25519.scalarmult(self.x25519_secret, self.peer_x25519_public) catch return error.InternalError;

        // The transcript includes ServerHello before deriving handshake secrets.
        self.transcript.update(msg);
        self.key_schedule.deriveHandshakeSecrets(&shared, self.transcript.current());

        self.pending_install_handshake = true;
        self.state = .client_wait_encrypted_extensions;
        return ._continue;
    }

    /// Parse EncryptedExtensions and capture the negotiated ALPN and peer
    /// QUIC transport parameters (RFC 8446 §4.3.1 + RFC 9001 §8).
    fn clientProcessEncryptedExtensions(self: *Tls13Handshake) HandshakeError!Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;
        if (msg.len < 4 or msg[0] != @intFromEnum(HandshakeType.encrypted_extensions)) return error.UnexpectedMessage;

        var pos: usize = 4;
        if (pos + 2 > msg.len) return error.DecodeError;
        const ext_total = readU16(msg[pos..]);
        pos += 2;
        if (pos + ext_total != msg.len) return error.DecodeError;
        const ext_end = pos + ext_total;

        var have_alpn = false;
        var seen_known_extensions: u16 = 0;
        while (pos < ext_end) {
            if (pos + 4 > ext_end) return error.DecodeError;
            const et = readU16(msg[pos..]);
            const el = readU16(msg[pos + 2 ..]);
            pos += 4;
            if (pos + el > ext_end) return error.DecodeError;
            const ext = msg[pos .. pos + el];
            pos += el;
            if (encryptedExtensionsKnownExtensionBit(et)) |bit| {
                const mask = @as(u16, 1) << bit;
                if (seen_known_extensions & mask != 0) return error.DecodeError;
                seen_known_extensions |= mask;
            }
            switch (et) {
                @intFromEnum(ExtType.alpn) => {
                    // ALPN: 2-byte list length + (1-byte proto length + proto)
                    if (el < 3) return error.DecodeError;
                    const list_len = readU16(ext[0..2]);
                    if (list_len + 2 != el) return error.DecodeError;
                    const proto_len = ext[2];
                    if (proto_len == 0 or proto_len + 3 != el) return error.DecodeError;
                    const proto = ext[3 .. 3 + proto_len];
                    var offered = self.config.alpn.len == 0;
                    for (self.config.alpn) |candidate| {
                        if (std.mem.eql(u8, proto, candidate)) {
                            offered = true;
                            break;
                        }
                    }
                    if (!offered) return error.NoApplicationProtocol;
                    self.negotiated_alpn_len = @min(proto_len, self.negotiated_alpn.len);
                    @memcpy(self.negotiated_alpn[0..self.negotiated_alpn_len], proto[0..self.negotiated_alpn_len]);
                    have_alpn = true;
                },
                @intFromEnum(ExtType.quic_transport_parameters) => {
                    if (el > self.peer_tp.len) return error.DecodeError;
                    self.peer_tp_len = el;
                    @memcpy(self.peer_tp[0..self.peer_tp_len], ext);
                },
                else => {}, // ignore unrecognized extensions
            }
        }

        if (self.config.alpn.len > 0 and !have_alpn) return error.NoApplicationProtocol;

        self.transcript.update(msg);
        self.state = .client_wait_certificate;
        return ._continue;
    }

    /// Parse the server Certificate message and retain its leaf certificate
    /// for CertificateVerify (RFC 8446 §4.4.2).
    fn clientProcessCertificate(self: *Tls13Handshake) HandshakeError!Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;
        if (msg.len < 4 or msg[0] != @intFromEnum(HandshakeType.certificate)) return error.UnexpectedMessage;

        var pos: usize = 4;
        // certificate_request_context (1-byte length + data)
        if (pos + 1 > msg.len) return error.DecodeError;
        const ctx_len = msg[pos];
        pos += 1;
        if (ctx_len != 0) return error.DecodeError;
        if (pos + ctx_len > msg.len) return error.DecodeError;
        pos += ctx_len;
        // certificate_list (3-byte length + entries)
        if (pos + 3 > msg.len) return error.DecodeError;
        const list_len = (@as(usize, msg[pos]) << 16) |
            (@as(usize, msg[pos + 1]) << 8) |
            @as(usize, msg[pos + 2]);
        pos += 3;
        const list_end = std.math.add(usize, pos, list_len) catch return error.DecodeError;
        if (list_end != msg.len) return error.DecodeError;
        const leaf_der = try nextCertificateEntry(msg, &pos, list_end);
        if (leaf_der.len > self.server_cert.len) return error.BadCertificate;
        self.server_cert_len = leaf_der.len;
        @memcpy(self.server_cert[0..self.server_cert_len], leaf_der);

        const chain_start = pos;
        while (pos < list_end) {
            _ = try nextCertificateEntry(msg, &pos, list_end);
        }

        // CertificateVerify uses the retained leaf. Chain validation consumes
        // the remaining leaf-to-issuer entries while their message bytes live.
        if (!self.config.skip_cert_verify) {
            try self.verifyServerCertificateChain(msg, chain_start, list_end);
        }

        self.transcript.update(msg);
        self.state = .client_wait_certificate_verify;
        return ._continue;
    }

    /// Verify a retained leaf certificate with no peer-supplied intermediates.
    ///
    /// This preserves the public direct-anchor check for callers that provide
    /// a leaf out of band. Handshake processing uses the complete received
    /// certificate_list through `verifyServerCertificateChain` instead.
    pub fn verifyServerCertificate(self: *Tls13Handshake) HandshakeError!void {
        return self.verifyServerCertificateChain(&.{}, 0, 0);
    }

    /// Verify the retained leaf, peer-supplied issuers, and configured trust
    /// bundle. Each supplied edge validates issuer name, validity, and
    /// signature; the final supplied certificate is then verified by the
    /// bundle. Without a bundle, preserve hostname-only and optional leaf-time
    /// verification for existing callers.
    fn verifyServerCertificateChain(
        self: *Tls13Handshake,
        certificate_message: []const u8,
        chain_pos: usize,
        chain_end: usize,
    ) HandshakeError!void {
        const cert: Certificate = .{
            .buffer = self.server_cert[0..self.server_cert_len],
            .index = 0,
        };
        const parsed = cert.parse() catch return error.BadCertificate;

        // Hostname (SNI) check against SAN/CN (RFC 6125).
        if (self.config.server_name) |host| {
            parsed.verifyHostName(host) catch return error.BadCertificate;
        }

        if (self.config.ca_bundle) |bundle| {
            const now = self.config.now_sec orelse return error.BadCertificate;
            var subject = parsed;
            var pos = chain_pos;
            while (pos < chain_end) {
                const issuer_der = try nextCertificateEntry(certificate_message, &pos, chain_end);
                const issuer = (Certificate{ .buffer = issuer_der, .index = 0 }).parse() catch return error.BadCertificate;
                subject.verify(issuer, now) catch return error.BadCertificate;
                subject = issuer;
            }
            bundle.verify(subject, now) catch return error.BadCertificate;
            return;
        }

        // Preserve validity-only behavior when no trust anchor is configured.
        if (self.config.now_sec) |now| {
            const not_before = @as(i64, @intCast(parsed.validity.not_before));
            const not_after = @as(i64, @intCast(parsed.validity.not_after));
            if (now < not_before or now > not_after) return error.BadCertificate;
        }
    }

    /// Read one TLS CertificateEntry and advance `pos` past its DER bytes and
    /// per-entry extensions. The caller supplies the enclosing certificate_list
    /// end so malformed lengths cannot reach the next handshake message.
    fn nextCertificateEntry(
        certificate_message: []const u8,
        pos: *usize,
        list_end: usize,
    ) HandshakeError![]const u8 {
        if (list_end > certificate_message.len or pos.* > list_end or list_end - pos.* < 3) return error.DecodeError;
        const cert_len = (@as(usize, certificate_message[pos.*]) << 16) |
            (@as(usize, certificate_message[pos.* + 1]) << 8) |
            @as(usize, certificate_message[pos.* + 2]);
        pos.* += 3;
        if (cert_len > list_end - pos.*) return error.DecodeError;
        const cert_der = certificate_message[pos.* .. pos.* + cert_len];
        pos.* += cert_len;
        if (list_end - pos.* < 2) return error.DecodeError;
        const extensions_len = readU16(certificate_message[pos.*..]);
        pos.* += 2;
        if (extensions_len > list_end - pos.*) return error.DecodeError;
        pos.* += extensions_len;
        return cert_der;
    }

    /// Parse CertificateVerify and store the signature, then (when
    /// verification is enabled) verify it against the server certificate's
    /// public key (RFC 8446 §4.4.3).
    fn clientProcessCertificateVerify(self: *Tls13Handshake) HandshakeError!Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;
        if (msg.len < 4 or msg[0] != @intFromEnum(HandshakeType.certificate_verify)) return error.UnexpectedMessage;

        var pos: usize = 4;
        // signature_scheme (2 bytes)
        if (pos + 2 > msg.len) return error.DecodeError;
        self.cert_verify_scheme = readU16(msg[pos..]);
        pos += 2;
        // signature (2-byte length + data)
        if (pos + 2 > msg.len) return error.DecodeError;
        const sig_len = readU16(msg[pos..]);
        pos += 2;
        if (pos + sig_len > msg.len) return error.DecodeError;
        if (pos + sig_len != msg.len) return error.DecodeError;
        if (sig_len > self.cert_verify_sig.len) return error.DecodeError;
        self.cert_verify_sig_len = sig_len;
        @memcpy(self.cert_verify_sig[0..self.cert_verify_sig_len], msg[pos .. pos + sig_len]);

        // The signature covers the transcript up to (not including) this
        // message, so snapshot before updating the transcript.
        if (!self.config.skip_cert_verify) {
            try self.verifyCertificateVerify(self.transcript.current());
        }

        self.transcript.update(msg);
        self.state = .client_wait_finished;
        return ._continue;
    }

    /// Verify the stored CertificateVerify signature against the server
    /// certificate's public key, using the transcript hash up to the
    /// Certificate message (RFC 8446 §4.4.3).
    fn verifyCertificateVerify(self: *Tls13Handshake, transcript_hash: [32]u8) HandshakeError!void {
        const cert: Certificate = .{
            .buffer = self.server_cert[0..self.server_cert_len],
            .index = 0,
        };
        const parsed = cert.parse() catch return error.BadCertificate;
        const pub_key = parsed.pubKey();
        const pub_key_algo: Certificate.AlgorithmCategory = parsed.pub_key_algo;

        // Signed content: 0x20 × 64 + context string + 0x00 + transcript hash.
        const label = "TLS 1.3, server CertificateVerify";
        var signed: [64 + label.len + 1 + 32]u8 = undefined;
        @memset(signed[0..64], 0x20);
        @memcpy(signed[64..][0..label.len], label);
        signed[64 + label.len] = 0x00;
        @memcpy(signed[64 + label.len + 1 ..][0..32], &transcript_hash);

        try verifyCertificateVerifySignature(
            pub_key,
            pub_key_algo,
            self.cert_verify_scheme,
            self.cert_verify_sig[0..self.cert_verify_sig_len],
            &signed,
        );
    }

    /// Verify the server Finished message against the transcript hash and
    /// server handshake traffic secret (RFC 8446 §4.4.4).
    fn clientProcessServerFinished(self: *Tls13Handshake) HandshakeError!Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;
        if (msg.len < 4 or msg[0] != @intFromEnum(HandshakeType.finished)) return error.UnexpectedMessage;

        const verify_data = msg[4..];
        if (verify_data.len != 32) return error.BadFinished; // SHA-256 → 32 bytes

        // verify_data covers the transcript up to (not including) Finished.
        const expected = KeySchedule.computeFinishedVerifyData(
            self.key_schedule.server_handshake_traffic_secret,
            self.transcript.current(),
        );
        var received: [32]u8 = undefined;
        @memcpy(&received, verify_data[0..32]);
        if (!std.crypto.timing_safe.eql([32]u8, expected, received)) return error.BadFinished;

        // The transcript now includes server Finished for app secrets and the
        // client Finished derived in the next step.
        self.transcript.update(msg);
        self.state = .client_send_finished;
        return ._continue;
    }

    /// Build the client Finished message, derive application traffic
    /// secrets, and arm the pending application key installation
    /// (RFC 8446 §4.4.4 + §7.1).
    ///
    /// At this point the transcript covers every handshake message up to and
    /// including the server Finished. Both the application secrets and the
    /// client's own verify_data are derived from that same transcript hash —
    /// the client Finished covers all messages up to (not including) itself.
    fn clientSendFinished(self: *Tls13Handshake) HandshakeError!Action {
        const th = self.transcript.current();

        // Application secrets derive from the transcript up to server Finished.
        self.key_schedule.deriveAppSecrets(th);

        // Client verify_data uses the client handshake traffic secret over the
        // same transcript hash.
        const verify_data = KeySchedule.computeFinishedVerifyData(
            self.key_schedule.client_handshake_traffic_secret,
            th,
        );

        // Finished message: type + 3-byte length + 32-byte verify_data.
        const buf = &self.out_buf;
        buf[0] = @intFromEnum(HandshakeType.finished);
        const msg_len: usize = 32;
        buf[1] = @intCast((msg_len >> 16) & 0xFF);
        buf[2] = @intCast((msg_len >> 8) & 0xFF);
        buf[3] = @intCast(msg_len & 0xFF);
        @memcpy(buf[4..36], &verify_data);

        // The client Finished is appended to the transcript for completeness;
        // it is the last handshake message in TLS 1.3.
        self.transcript.update(buf[0..36]);
        self.pending_install_app = true;
        self.state = .connected;

        // Sent at the Handshake level — 1-RTT application data follows once the
        // caller installs the pending application keys.
        return Action{ .send_data = .{
            .level = .handshake,
            .data = self.out_buf[0..36],
        } };
    }

    // ─── Server-side state handlers ──────────────────────────────────

    /// Parse a ClientHello: extract the X25519 key share, select ALPN, capture
    /// peer QUIC transport parameters, and update the transcript
    /// (RFC 8446 §4.1.2 + RFC 9001 §8).
    fn serverProcessClientHello(self: *Tls13Handshake) HandshakeError!Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;
        if (msg.len < 4 or msg[0] != @intFromEnum(HandshakeType.client_hello)) return error.UnexpectedMessage;

        const body = msg[4..];
        if (body.len < 2 + 32 + 1) return error.DecodeError;
        var pos: usize = 0;
        if (readU16(body[pos..]) != legacy_version_tls_1_2) return error.UnsupportedVersion;
        pos += 2; // legacy_version
        pos += 32; // random
        // legacy_session_id (QUIC does not use TLS compatibility mode)
        if (pos >= body.len) return error.DecodeError;
        const sid_len = body[pos];
        pos += 1;
        if (sid_len != 0) return error.DecodeError;
        if (pos + sid_len > body.len) return error.DecodeError;
        pos += sid_len;
        // cipher_suites — require TLS_AES_128_GCM_SHA256
        if (pos + 2 > body.len) return error.DecodeError;
        const cs_len = readU16(body[pos..]);
        pos += 2;
        if (cs_len == 0 or cs_len % 2 != 0) return error.DecodeError;
        if (pos + cs_len > body.len) return error.DecodeError;
        var cs_found = false;
        {
            var cs_pos: usize = 0;
            while (cs_pos + 2 <= cs_len) : (cs_pos += 2) {
                if (readU16(body[pos + cs_pos ..]) == cipher_aes_128_gcm_sha256) {
                    cs_found = true;
                    break;
                }
            }
        }
        if (!cs_found) return error.UnsupportedVersion;
        pos += cs_len;
        // compression_methods
        if (pos >= body.len) return error.DecodeError;
        const cm_len = body[pos];
        pos += 1;
        if (cm_len != 1) return error.DecodeError;
        if (pos + cm_len > body.len) return error.DecodeError;
        if (body[pos] != 0) return error.DecodeError;
        pos += cm_len;
        // extensions
        if (pos + 2 > body.len) return error.DecodeError;
        const ext_total = readU16(body[pos..]);
        pos += 2;
        if (pos + ext_total != body.len) return error.DecodeError;
        const ext_end = pos + ext_total;

        var have_key_share = false;
        var have_version = false;
        var have_server_name = false;
        var have_supported_groups = false;
        var have_signature_algorithms = false;
        var have_psk_key_exchange_modes = false;
        var client_supports_x25519 = false;
        var client_supports_server_sig = false;
        var client_supports_psk_dhe_ke = false;
        var seen_known_extensions: u16 = 0;
        const server_sig_scheme = signatureSchemeForPrivateKeyAlgorithm(self.config.private_key_algorithm);
        while (pos < ext_end) {
            if (pos + 4 > ext_end) return error.DecodeError;
            const et = readU16(body[pos..]);
            const el = readU16(body[pos + 2 ..]);
            pos += 4;
            if (pos + el > ext_end) return error.DecodeError;
            const ext = body[pos .. pos + el];
            pos += el;
            if (clientHelloKnownExtensionBit(et)) |bit| {
                const mask = @as(u16, 1) << bit;
                if (seen_known_extensions & mask != 0) return error.DecodeError;
                seen_known_extensions |= mask;
            }
            switch (et) {
                @intFromEnum(ExtType.supported_versions) => {
                    // ClientHello: 1-byte list length + 2-byte versions.
                    if (el < 3) return error.DecodeError;
                    const versions_len = ext[0];
                    if (versions_len == 0 or 1 + versions_len != el or versions_len % 2 != 0) {
                        return error.DecodeError;
                    }
                    var vp: usize = 1;
                    while (vp + 2 <= el) : (vp += 2) {
                        if (readU16(ext[vp..]) == version_tls_1_3) {
                            have_version = true;
                            break;
                        }
                    }
                },
                @intFromEnum(ExtType.key_share) => {
                    // client_shares_len(2) + [group(2) + key_len(2) + key]
                    if (el < 2) return error.DecodeError;
                    const shares_len = readU16(ext[0..2]);
                    if (shares_len == 0 or 2 + shares_len != el) return error.DecodeError;
                    var sp: usize = 2; // skip client_shares_len
                    while (sp + 4 <= el) {
                        const group = readU16(ext[sp..]);
                        const klen = readU16(ext[sp + 2 ..]);
                        sp += 4;
                        if (sp + klen > el) return error.DecodeError;
                        if (group == group_x25519 and klen == 32 and sp + 32 <= el) {
                            @memcpy(&self.peer_x25519_public, ext[sp..][0..32]);
                            have_key_share = true;
                        }
                        sp += klen;
                    }
                    if (sp != el) return error.DecodeError;
                },
                @intFromEnum(ExtType.alpn) => {
                    if (el < 2) return error.DecodeError;
                    const list_len = readU16(ext[0..2]);
                    if (list_len == 0 or 2 + list_len != el) return error.DecodeError;
                    var ap: usize = 2;
                    while (ap < el) {
                        if (ap + 1 > el) return error.DecodeError;
                        const plen = ext[ap];
                        ap += 1;
                        if (plen == 0 or ap + plen > el) return error.DecodeError;
                        const proto = ext[ap .. ap + plen];
                        for (self.config.alpn) |our| {
                            if (std.mem.eql(u8, proto, our)) {
                                self.negotiated_alpn_len = @min(plen, self.negotiated_alpn.len);
                                @memcpy(
                                    self.negotiated_alpn[0..self.negotiated_alpn_len],
                                    proto[0..self.negotiated_alpn_len],
                                );
                                break;
                            }
                        }
                        ap += plen;
                    }
                },
                @intFromEnum(ExtType.supported_groups) => {
                    if (el < 2) return error.DecodeError;
                    const groups_len = readU16(ext[0..2]);
                    if (groups_len == 0 or 2 + groups_len != el or groups_len % 2 != 0) {
                        return error.DecodeError;
                    }
                    have_supported_groups = true;
                    var gp: usize = 2;
                    while (gp + 2 <= el) : (gp += 2) {
                        if (readU16(ext[gp..]) == group_x25519) {
                            client_supports_x25519 = true;
                        }
                    }
                },
                @intFromEnum(ExtType.signature_algorithms) => {
                    if (el < 2) return error.DecodeError;
                    const schemes_len = readU16(ext[0..2]);
                    if (schemes_len == 0 or 2 + schemes_len != el or schemes_len % 2 != 0) {
                        return error.DecodeError;
                    }
                    have_signature_algorithms = true;
                    var sp: usize = 2;
                    while (sp + 2 <= el) : (sp += 2) {
                        if (readU16(ext[sp..]) == server_sig_scheme) {
                            client_supports_server_sig = true;
                        }
                    }
                },
                @intFromEnum(ExtType.server_name) => {
                    if (el < 2) return error.DecodeError;
                    const list_len = readU16(ext[0..2]);
                    if (list_len == 0 or 2 + list_len != el) return error.DecodeError;
                    var sp: usize = 2;
                    var saw_host_name = false;
                    while (sp < el) {
                        if (sp + 3 > el) return error.DecodeError;
                        const name_type = ext[sp];
                        const name_len = readU16(ext[sp + 1 ..]);
                        sp += 3;
                        if (name_len == 0 or sp + name_len > el) return error.DecodeError;
                        const offered_name = ext[sp .. sp + name_len];
                        sp += name_len;
                        if (name_type == 0) {
                            if (saw_host_name) return error.DecodeError;
                            saw_host_name = true;
                            have_server_name = true;
                            if (offered_name.len > self.client_sni.len) return error.DecodeError;
                            @memcpy(self.client_sni[0..offered_name.len], offered_name);
                            self.client_sni_len = offered_name.len;
                            if (self.config.server_name) |expected_name| {
                                if (!std.ascii.eqlIgnoreCase(offered_name, expected_name)) {
                                    return error.UnrecognizedName;
                                }
                            }
                        }
                    }
                },
                @intFromEnum(ExtType.quic_transport_parameters) => {
                    if (el > self.peer_tp.len) return error.DecodeError;
                    self.peer_tp_len = el;
                    @memcpy(self.peer_tp[0..self.peer_tp_len], ext);
                },
                @intFromEnum(ExtType.psk_key_exchange_modes) => {
                    if (el < 2) return error.DecodeError;
                    const modes_len = ext[0];
                    if (modes_len == 0 or 1 + modes_len != el) return error.DecodeError;
                    have_psk_key_exchange_modes = true;
                    var mp: usize = 1;
                    while (mp < el) : (mp += 1) {
                        if (ext[mp] == 0x01) {
                            client_supports_psk_dhe_ke = true;
                        }
                    }
                },
                @intFromEnum(ExtType.early_data) => {
                    // Empty extension (RFC 8446 §4.2.10): the client signals
                    // 0-RTT intent. The server only records the offer here;
                    // acceptance is gated on a matching PSK and policy.
                    if (el != 0) return error.DecodeError;
                    self.peer_offered_early_data = true;
                },
                @intFromEnum(ExtType.pre_shared_key) => {
                    // RFC 8446 §4.2.11. Must be the last extension; parse the
                    // first offered identity + binder. identities<7..2^16-1>
                    // then binders<33..2^16-1>.
                    if (pos != ext_end) return error.DecodeError;
                    self.peer_offered_psk = true;
                    var pp: usize = 0;
                    if (pp + 2 > el) return error.DecodeError;
                    const identities_len = readU16(ext[pp..]);
                    pp += 2;
                    if (pp + identities_len > el) return error.DecodeError;
                    if (identities_len < 7) return error.DecodeError;
                    const identities_end = pp + identities_len;
                    var identity_count: usize = 0;
                    while (pp < identities_end) {
                        if (pp + 2 > identities_end) return error.DecodeError;
                        const identity_len = readU16(ext[pp..]);
                        pp += 2;
                        if (identity_len == 0) return error.DecodeError;
                        if (pp + identity_len + 4 > identities_end) return error.DecodeError;
                        if (identity_count == 0) {
                            if (identity_len > self.peer_psk_identity.len) return error.DecodeError;
                            @memcpy(self.peer_psk_identity[0..identity_len], ext[pp..][0..identity_len]);
                            self.peer_psk_identity_len = identity_len;
                        }
                        pp += identity_len;
                        pp += 4; // obfuscated_ticket_age
                        identity_count += 1;
                    }
                    if (pp != identities_end or identity_count == 0) return error.DecodeError;
                    if (pp + 2 > el) return error.DecodeError;
                    const binders_len = readU16(ext[pp..]);
                    pp += 2;
                    if (binders_len < 33) return error.DecodeError;
                    if (pp + binders_len != el) return error.DecodeError;
                    const binders_end = pp + binders_len;
                    var binder_count: usize = 0;
                    while (pp < binders_end) {
                        if (pp + 1 > binders_end) return error.DecodeError;
                        const binder_len = ext[pp];
                        pp += 1;
                        if (binder_len < 32 or pp + binder_len > binders_end) {
                            return error.DecodeError;
                        }
                        if (binder_count == 0) {
                            if (binder_len != self.peer_psk_binder.len) return error.DecodeError;
                            @memcpy(&self.peer_psk_binder, ext[pp..][0..binder_len]);
                            // Record the binder's offset within the ClientHello
                            // message so the truncated transcript hash can be
                            // recomputed for verification. `ext` starts at body
                            // offset (pos - el); binder starts at ext offset pp.
                            self.peer_psk_binder_msg_offset = 4 + (pos - el) + pp;
                        }
                        pp += binder_len;
                        binder_count += 1;
                    }
                    if (pp != binders_end or binder_count != identity_count) return error.DecodeError;
                },
                else => {}, // ignore unrecognized extensions
            }
        }

        if (!have_version) return error.UnsupportedVersion;
        if (!have_key_share) return error.NoKeyShare;
        if (have_supported_groups and !client_supports_x25519) return error.NoKeyShare;
        if (self.config.cert_chain_der.len > 0 and !have_signature_algorithms) return error.MissingExtension;
        if (have_signature_algorithms and !client_supports_server_sig) return error.UnsupportedSignatureAlgorithm;
        if (self.config.alpn.len > 0 and self.negotiated_alpn_len == 0) return error.NoApplicationProtocol;
        if (self.config.server_name != null and !have_server_name) return error.UnrecognizedName;
        if (self.peer_offered_early_data and !self.peer_offered_psk) return error.DecodeError;
        if (self.peer_offered_psk and !have_psk_key_exchange_modes) return error.MissingExtension;
        if (self.peer_offered_psk and !client_supports_psk_dhe_ke) return error.UnsupportedPskKeyExchangeMode;

        // Update the transcript. When the client offered a PSK, split the
        // update at the binder so the truncated transcript hash can be used
        // to verify the binder (RFC 8446 §4.2.11).
        if (self.peer_offered_psk) {
            const binder_offset = self.peer_psk_binder_msg_offset;
            self.transcript.update(msg[0..binder_offset]);
            const truncated_hash = self.transcript.current();
            self.transcript.update(msg[binder_offset..]);
            // If the server holds a PSK, verify the binder and, on success,
            // derive the client early traffic secret over the (now complete)
            // ClientHello transcript so 0-RTT can be opened.
            if (self.server_psk != null) {
                const binder_key = self.key_schedule.deriveBinderKey();
                const expected = KeySchedule.computeFinishedVerifyData(binder_key, truncated_hash);
                self.peer_psk_binder_valid = std.crypto.timing_safe.eql(
                    [32]u8,
                    expected,
                    self.peer_psk_binder,
                );
                if (self.peer_psk_binder_valid) {
                    self.server_early_traffic_secret = self.key_schedule.deriveEarlyTrafficSecret(self.transcript.current());
                    self.server_early_traffic_secret_derived = true;
                }
            }
        } else {
            self.transcript.update(msg);
        }
        self.state = .server_send_server_hello;
        return ._continue;
    }

    /// Build a ServerHello, complete the X25519 key exchange, and derive
    /// handshake traffic secrets (RFC 8446 §4.1.3 + §7.1).
    fn serverBuildServerHello(self: *Tls13Handshake) HandshakeError!Action {
        secureRandomBytes(&self.server_random);

        const buf = &self.out_buf;
        var pos: usize = 4;
        // legacy_version 0x0303
        buf[pos] = 0x03;
        buf[pos + 1] = 0x03;
        pos += 2;
        // random
        @memcpy(buf[pos..][0..32], &self.server_random);
        pos += 32;
        // legacy_session_id echo: empty (QUIC)
        buf[pos] = 0;
        pos += 1;
        // cipher_suite
        writeU16(buf[pos..], cipher_aes_128_gcm_sha256);
        pos += 2;
        // legacy_compression_method: null
        buf[pos] = 0;
        pos += 1;
        // extensions
        const ext_start = pos;
        pos += 2;
        // supported_versions (server picks one)
        pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.supported_versions), 2);
        writeU16(buf[pos..], version_tls_1_3);
        pos += 2;
        // key_share (server: group + 2-byte key length + key)
        pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.key_share), 2 + 2 + 32);
        writeU16(buf[pos..], group_x25519);
        pos += 2;
        writeU16(buf[pos..], 32);
        pos += 2;
        @memcpy(buf[pos..][0..32], &self.x25519_public);
        pos += 32;
        const ext_len = pos - ext_start - 2;
        writeU16(buf[ext_start..], @intCast(ext_len));
        const msg_len = pos - 4;
        buf[0] = @intFromEnum(HandshakeType.server_hello);
        buf[1] = @intCast((msg_len >> 16) & 0xFF);
        buf[2] = @intCast((msg_len >> 8) & 0xFF);
        buf[3] = @intCast(msg_len & 0xFF);

        self.transcript.update(buf[0..pos]);

        // ECDHE shared secret: server secret × client public.
        const shared = X25519.scalarmult(self.x25519_secret, self.peer_x25519_public) catch return error.InternalError;
        self.key_schedule.deriveHandshakeSecrets(&shared, self.transcript.current());

        self.pending_install_handshake = true;
        self.state = .server_send_encrypted_extensions;
        return Action{ .send_data = .{
            .level = .initial,
            .data = self.out_buf[0..pos],
        } };
    }

    /// Build EncryptedExtensions carrying the negotiated ALPN and the server's
    /// QUIC transport parameters (RFC 8446 §4.3.1 + RFC 9001 §8).
    fn serverBuildEncryptedExtensions(self: *Tls13Handshake) HandshakeError!Action {
        if (self.local_tp_too_large) return error.DecodeError;
        const alpn = self.negotiated_alpn[0..self.negotiated_alpn_len];
        const tp = self.tp_encoded[0..self.tp_encoded_len];
        if (alpn.len > std.math.maxInt(u8)) return error.DecodeError;
        const alpn_ext_len = if (alpn.len > 0) 4 + 2 + 1 + alpn.len else 0;
        const tp_ext_len = if (tp.len > 0) 4 + tp.len else 0;
        const ee_len = std.math.add(usize, 4 + 2, alpn_ext_len) catch return error.DecodeError;
        const total_len = std.math.add(usize, ee_len, tp_ext_len) catch return error.DecodeError;
        if (total_len > self.out_buf.len) return error.DecodeError;
        const len = buildEncryptedExtensions(&self.out_buf, alpn, tp);
        self.transcript.update(self.out_buf[0..len]);
        self.state = .server_send_certificate;
        return Action{ .send_data = .{
            .level = .handshake,
            .data = self.out_buf[0..len],
        } };
    }

    /// Build the Certificate message from the configured leaf-first chain
    /// (RFC 8446 §4.4.2).
    fn serverBuildCertificate(self: *Tls13Handshake) HandshakeError!Action {
        if (self.config.cert_chain_der.len == 0) return error.BadCertificate;
        const len = buildCertificateChain(&self.out_buf, self.config.cert_chain_der) orelse return error.BadCertificate;
        self.transcript.update(self.out_buf[0..len]);
        self.state = .server_send_certificate_verify;
        return Action{ .send_data = .{
            .level = .handshake,
            .data = self.out_buf[0..len],
        } };
    }

    /// Build CertificateVerify, signing the transcript hash up to the
    /// Certificate with the configured private key (RFC 8446 §4.4.3).
    fn serverBuildCertificateVerify(self: *Tls13Handshake) HandshakeError!Action {
        const private_key = self.config.private_key_bytes orelse return error.BadCertificate;
        const th = self.transcript.current();

        // Signed content: 0x20 × 64 + context string + 0x00 + transcript hash.
        const label = "TLS 1.3, server CertificateVerify";
        var sign_content: [64 + label.len + 1 + 32]u8 = undefined;
        @memset(sign_content[0..64], 0x20);
        @memcpy(sign_content[64..][0..label.len], label);
        sign_content[64 + label.len] = 0x00;
        @memcpy(sign_content[64 + label.len + 1 ..][0..32], &th);

        var sig_storage: [128]u8 = undefined;
        var sig_len: usize = 0;
        const sig_scheme: u16 = switch (self.config.private_key_algorithm) {
            .ecdsa_p256_sha256 => blk: {
                if (private_key.len != 32) return error.InternalError;
                var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
                const sk = EcdsaP256Sha256.SecretKey.fromBytes(private_key[0..32].*) catch return error.InternalError;
                const kp = EcdsaP256Sha256.KeyPair.fromSecretKey(sk) catch return error.InternalError;
                const sig = kp.sign(&sign_content, null) catch return error.InternalError;
                const der = sig.toDer(&der_buf);
                sig_len = der.len;
                @memcpy(sig_storage[0..sig_len], der);
                break :blk sig_ecdsa_secp256r1_sha256;
            },
            .ed25519 => blk: {
                if (private_key.len != 32) return error.InternalError;
                const kp = Ed25519.KeyPair.generateDeterministic(private_key[0..32].*) catch return error.InternalError;
                const sig = kp.sign(&sign_content, null) catch return error.InternalError;
                const bytes = sig.toBytes();
                sig_len = bytes.len;
                @memcpy(sig_storage[0..sig_len], &bytes);
                break :blk sig_ed25519;
            },
        };

        const buf = &self.out_buf;
        var pos: usize = 4;
        writeU16(buf[pos..], sig_scheme);
        pos += 2;
        writeU16(buf[pos..], @intCast(sig_len));
        pos += 2;
        @memcpy(buf[pos..][0..sig_len], sig_storage[0..sig_len]);
        pos += sig_len;
        const body_len: u24 = @intCast(pos - 4);
        buf[0] = @intFromEnum(HandshakeType.certificate_verify);
        buf[1] = @intCast(body_len >> 16);
        buf[2] = @intCast((body_len >> 8) & 0xff);
        buf[3] = @intCast(body_len & 0xff);

        self.transcript.update(buf[0..pos]);
        self.state = .server_send_finished;
        return Action{ .send_data = .{
            .level = .handshake,
            .data = self.out_buf[0..pos],
        } };
    }

    /// Build the server Finished message and derive application traffic
    /// secrets (RFC 8446 §4.4.4 + §7.1).
    fn serverBuildFinished(self: *Tls13Handshake) HandshakeError!Action {
        // verify_data covers the transcript up to (not including) Finished.
        const verify_data = KeySchedule.computeFinishedVerifyData(
            self.key_schedule.server_handshake_traffic_secret,
            self.transcript.current(),
        );
        const len = buildFinished(&self.out_buf, verify_data);
        self.transcript.update(self.out_buf[0..len]);

        // Application secrets derive from the transcript up to server Finished.
        self.key_schedule.deriveAppSecrets(self.transcript.current());
        self.pending_install_app = true;
        self.state = .server_wait_client_finished;
        return Action{ .send_data = .{
            .level = .handshake,
            .data = self.out_buf[0..len],
        } };
    }

    /// Verify the client Finished message against the transcript hash and
    /// client handshake traffic secret (RFC 8446 §4.4.4).
    fn serverProcessClientFinished(self: *Tls13Handshake) HandshakeError!Action {
        const msg = self.readHandshakeMsg() orelse return .wait_for_data;
        if (msg.len < 4 or msg[0] != @intFromEnum(HandshakeType.finished)) return error.UnexpectedMessage;

        const verify_data = msg[4..];
        if (verify_data.len != 32) return error.BadFinished; // SHA-256 → 32 bytes

        // client Finished covers the transcript up to (not including) itself,
        // i.e. through the server Finished.
        const expected = KeySchedule.computeFinishedVerifyData(
            self.key_schedule.client_handshake_traffic_secret,
            self.transcript.current(),
        );
        var received: [32]u8 = undefined;
        @memcpy(&received, verify_data[0..32]);
        if (!std.crypto.timing_safe.eql([32]u8, expected, received)) return error.BadFinished;

        self.transcript.update(msg);
        self.state = .connected;
        return ._continue;
    }

    /// Build a post-handshake NewSessionTicket (RFC 8446 §4.6.1) so the
    /// client can derive a resumption PSK and reuse it for 0-RTT in a future
    /// connection. The ticket is an opaque blob here (a real implementation
    /// encrypts the resumption master secret or derived PSK into it); the
    /// client only stores it as the psk_identity for the next ClientHello.
    /// The PSK itself is derived by both ends from
    /// resumption_master_secret + ticket_nonce, so the server need not ship
    /// the secret in the clear.
    pub fn serverBuildNewSessionTicket(self: *Tls13Handshake) HandshakeError!Action {
        const rms = self.key_schedule.deriveResumptionMasterSecret(self.transcript.current());

        // 16-byte ticket nonce; the PSK derived from it is available to the
        // server (e.g. for a ticket store) via derivePskFromTicket.
        var nonce: [16]u8 = undefined;
        secureRandomBytes(&nonce);
        _ = KeySchedule.derivePskFromTicket(rms, &nonce);

        const buf = &self.out_buf;
        var pos: usize = 4; // reserve type + 3-byte length
        // ticket_lifetime = 3600 (1 hour)
        writeU32(buf[pos..], 3600);
        pos += 4;
        // ticket_age_add = 0 (skeleton: no obfuscated age timing)
        writeU32(buf[pos..], 0);
        pos += 4;
        // ticket_nonce<0..255>
        buf[pos] = @intCast(nonce.len);
        pos += 1;
        @memcpy(buf[pos..][0..nonce.len], &nonce);
        pos += nonce.len;
        // ticket<1..2^16-1>: carry the nonce as the opaque identity.
        writeU16(buf[pos..], @intCast(nonce.len));
        pos += 2;
        @memcpy(buf[pos..][0..nonce.len], &nonce);
        pos += nonce.len;
        // extensions<0..2^16-2>: empty
        writeU16(buf[pos..], 0);
        pos += 2;

        const msg_len = pos - 4;
        buf[0] = @intFromEnum(HandshakeType.new_session_ticket);
        buf[1] = @intCast((msg_len >> 16) & 0xFF);
        buf[2] = @intCast((msg_len >> 8) & 0xFF);
        buf[3] = @intCast(msg_len & 0xFF);

        self.out_len = pos;
        self.nst_sent = true;
        return Action{ .send_data = .{
            .level = .application,
            .data = self.out_buf[0..self.out_len],
        } };
    }
};

// ─── Tests for ClientHello ───────────────────────────────────────────

test "Tls13Handshake client builds ClientHello with ALPN and key_share" {
    const alpn = [_][]const u8{"hq-interop"};
    const tp = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var hs = Tls13Handshake.initClient(.{
        .alpn = &alpn,
        .server_name = "example.com",
    }, &tp);

    const action = try hs.step();
    try std.testing.expect(action == .send_data);
    const data = action.send_data.data;
    try std.testing.expect(data.len > 100);
    try std.testing.expectEqual(@as(u8, 1), data[0]); // ClientHello type

    // Verify it contains ALPN extension (0x0010)
    var found_alpn = false;
    var i: usize = 0;
    while (i + 4 < data.len) : (i += 1) {
        if (data[i] == 0x00 and data[i + 1] == 0x10) {
            found_alpn = true;
            break;
        }
    }
    try std.testing.expect(found_alpn);

    // Verify it contains SNI extension (0x0000) with "example.com"
    var found_sni = false;
    i = 0;
    while (i + 4 < data.len) : (i += 1) {
        if (data[i] == 0x00 and data[i + 1] == 0x00 and i > 40) {
            found_sni = true;
            break;
        }
    }
    try std.testing.expect(found_sni);

    // Next step should wait for data (ServerHello)
    const next = try hs.step();
    try std.testing.expect(next == .wait_for_data);
}

test "Tls13Handshake client builds ClientHello with transport parameters" {
    const tp = [_]u8{ 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA };
    var hs = Tls13Handshake.initClient(.{}, &tp);

    const action = try hs.step();
    const data = action.send_data.data;

    // Verify it contains quic_transport_parameters extension (0x0039)
    var found_tp = false;
    var i: usize = 0;
    while (i + 4 < data.len) : (i += 1) {
        if (data[i] == 0x00 and data[i + 1] == 0x39) {
            found_tp = true;
            break;
        }
    }
    try std.testing.expect(found_tp);
}

test "Tls13Handshake client rejects empty local SNI" {
    var hs = Tls13Handshake.initClient(.{
        .server_name = "",
    }, &[_]u8{});

    try std.testing.expectError(error.DecodeError, hs.step());
}

test "Tls13Handshake client rejects oversized local SNI" {
    var long_name: [16384]u8 = undefined;
    @memset(&long_name, 'a');
    var hs = Tls13Handshake.initClient(.{
        .server_name = &long_name,
    }, &[_]u8{});

    try std.testing.expectError(error.DecodeError, hs.step());
}

test "Tls13Handshake client rejects oversized local ALPN protocol name" {
    const long_proto = "a" ** 256;
    const alpn = [_][]const u8{long_proto};
    var hs = Tls13Handshake.initClient(.{
        .alpn = &alpn,
    }, &[_]u8{});

    try std.testing.expectError(error.DecodeError, hs.step());
}

test "Tls13Handshake client rejects empty local ALPN protocol name" {
    const alpn = [_][]const u8{""};
    var hs = Tls13Handshake.initClient(.{
        .alpn = &alpn,
    }, &[_]u8{});

    try std.testing.expectError(error.DecodeError, hs.step());
}

test "Tls13Handshake client rejects oversized local transport parameters" {
    var tp: [1025]u8 = undefined;
    @memset(&tp, 0xaa);
    var hs = Tls13Handshake.initClient(.{}, &tp);

    try std.testing.expectError(error.DecodeError, hs.step());
}

test "Tls13Handshake isComplete is false before handshake" {
    var hs = Tls13Handshake.initClient(.{}, &[_]u8{});
    try std.testing.expect(!hs.isComplete());
    _ = try hs.step();
    try std.testing.expect(!hs.isComplete());
}

// ─── Tests for ServerHello processing ────────────────────────────────

/// Build a minimal ServerHello into `buf`. `cipher`, `include_version`, and
/// `include_key_share` let failure-injection tests omit or corrupt fields.
/// Returns the total number of bytes written.
pub fn buildServerHello(
    buf: []u8,
    server_public: [32]u8,
    cipher: u16,
    include_version: bool,
    include_key_share: bool,
) usize {
    var p: usize = 0;
    buf[p] = @intFromEnum(HandshakeType.server_hello);
    p += 1;
    p += 3; // length placeholder
    // legacy_version 0x0303
    buf[p] = 0x03;
    buf[p + 1] = 0x03;
    p += 2;
    // random (fixed value for deterministic tests)
    @memset(buf[p..][0..32], 0xAA);
    p += 32;
    // legacy_session_id_echo: empty
    buf[p] = 0;
    p += 1;
    // cipher_suite
    writeU16(buf[p..], cipher);
    p += 2;
    // legacy_compression_method: null
    buf[p] = 0;
    p += 1;
    // extensions
    const ext_start = p;
    p += 2;
    if (include_version) {
        p = writeExtHeader(buf, p, @intFromEnum(ExtType.supported_versions), 2);
        writeU16(buf[p..], version_tls_1_3);
        p += 2;
    }
    if (include_key_share) {
        p = writeExtHeader(buf, p, @intFromEnum(ExtType.key_share), 2 + 2 + 32);
        writeU16(buf[p..], group_x25519);
        p += 2;
        writeU16(buf[p..], 32);
        p += 2;
        @memcpy(buf[p..][0..32], &server_public);
        p += 32;
    }
    const ext_len = p - ext_start - 2;
    writeU16(buf[ext_start..], @intCast(ext_len));
    const msg_len = p - 4;
    buf[1] = @intCast((msg_len >> 16) & 0xFF);
    buf[2] = @intCast((msg_len >> 8) & 0xFF);
    buf[3] = @intCast(msg_len & 0xFF);
    return p;
}

fn appendDuplicateServerHelloExtension(buf: []u8, msg_len: usize, ext_type: u16) ![]u8 {
    if (msg_len < 4 + 2 + 32 + 1 + 2 + 1 + 2) return error.TestUnexpectedResult;
    var pos: usize = 4 + 2 + 32;
    const sid_len = buf[pos];
    pos += 1;
    if (pos + sid_len + 2 + 1 + 2 > msg_len) return error.TestUnexpectedResult;
    pos += sid_len;
    pos += 2; // cipher_suite
    pos += 1; // legacy_compression_method
    const extensions_len_offset = pos;
    const extensions_len = readU16(buf[pos..]);
    pos += 2;
    if (pos + extensions_len > msg_len) return error.TestUnexpectedResult;
    const ext_end = pos + extensions_len;

    while (pos < ext_end) {
        if (pos + 4 > ext_end) return error.TestUnexpectedResult;
        const header_offset = pos;
        const current_type = readU16(buf[pos..]);
        const current_len = readU16(buf[pos + 2 ..]);
        pos += 4;
        if (pos + current_len > ext_end) return error.TestUnexpectedResult;
        if (current_type == ext_type) {
            const duplicate_len = 4 + current_len;
            if (msg_len + duplicate_len > buf.len) return error.TestUnexpectedResult;
            std.mem.copyForwards(u8, buf[msg_len..][0..duplicate_len], buf[header_offset..][0..duplicate_len]);
            const new_body_len = msg_len - 4 + duplicate_len;
            buf[1] = @as(u8, @intCast(new_body_len >> 16));
            buf[2] = @as(u8, @intCast((new_body_len >> 8) & 0xFF));
            buf[3] = @as(u8, @intCast(new_body_len & 0xFF));
            writeU16(
                buf[extensions_len_offset..][0..2],
                @as(u16, @intCast(extensions_len + duplicate_len)),
            );
            return buf[0 .. msg_len + duplicate_len];
        }
        pos += current_len;
    }
    return error.TestUnexpectedResult;
}

fn extendServerHelloExtensionBody(buf: []u8, msg_len: usize, ext_type: u16, extra: []const u8) ![]u8 {
    if (extra.len == 0 or extra.len > std.math.maxInt(u16)) return error.TestUnexpectedResult;
    if (msg_len < 4 + 2 + 32 + 1 + 2 + 1 + 2) return error.TestUnexpectedResult;
    var pos: usize = 4 + 2 + 32;
    const sid_len = buf[pos];
    pos += 1;
    if (pos + sid_len + 2 + 1 + 2 > msg_len) return error.TestUnexpectedResult;
    pos += sid_len;
    pos += 2; // cipher_suite
    pos += 1; // legacy_compression_method
    const extensions_len_offset = pos;
    const extensions_len = readU16(buf[pos..]);
    pos += 2;
    if (pos + extensions_len > msg_len) return error.TestUnexpectedResult;
    const ext_end = pos + extensions_len;

    while (pos < ext_end) {
        if (pos + 4 > ext_end) return error.TestUnexpectedResult;
        const header_offset = pos;
        const current_type = readU16(buf[pos..]);
        const current_len = readU16(buf[pos + 2 ..]);
        pos += 4;
        if (pos + current_len > ext_end) return error.TestUnexpectedResult;
        if (current_type == ext_type) {
            if (current_len + extra.len > std.math.maxInt(u16)) return error.TestUnexpectedResult;
            if (msg_len + extra.len > buf.len) return error.TestUnexpectedResult;
            const insert_offset = pos + current_len;
            std.mem.copyBackwards(
                u8,
                buf[insert_offset + extra.len .. msg_len + extra.len],
                buf[insert_offset..msg_len],
            );
            @memcpy(buf[insert_offset..][0..extra.len], extra);
            writeU16(buf[header_offset + 2 ..][0..2], @as(u16, @intCast(current_len + extra.len)));
            const new_body_len = msg_len - 4 + extra.len;
            buf[1] = @as(u8, @intCast(new_body_len >> 16));
            buf[2] = @as(u8, @intCast((new_body_len >> 8) & 0xFF));
            buf[3] = @as(u8, @intCast(new_body_len & 0xFF));
            writeU16(
                buf[extensions_len_offset..][0..2],
                @as(u16, @intCast(extensions_len + extra.len)),
            );
            return buf[0 .. msg_len + extra.len];
        }
        pos += current_len;
    }
    return error.TestUnexpectedResult;
}

test "Tls13Handshake client processes ServerHello and installs handshake keys" {
    const alpn = [_][]const u8{"hq-interop"};
    var hs = Tls13Handshake.initClient(.{
        .alpn = &alpn,
        .server_name = "example.com",
    }, &[_]u8{ 0x01, 0x02 });

    // Produce the ClientHello first so the transcript matches.
    const ch_action = try hs.step();
    try std.testing.expect(std.meta.activeTag(ch_action) == .send_data);
    const client_hello = ch_action.send_data.data;

    // Server X25519 key pair.
    var server_secret: [32]u8 = undefined;
    secureRandomBytes(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);

    var sh_buf: [128]u8 = undefined;
    const sh_len = buildServerHello(&sh_buf, server_public, cipher_aes_128_gcm_sha256, true, true);
    const server_hello = sh_buf[0..sh_len];

    hs.provideData(server_hello);

    // First step parses ServerHello and derives handshake secrets.
    const cont = try hs.step();
    try std.testing.expect(std.meta.activeTag(cont) == ._continue);

    // Next step emits the pending install_keys(handshake) action.
    const install = try hs.step();
    try std.testing.expect(std.meta.activeTag(install) == .install_keys);
    try std.testing.expectEqual(EncryptionLevel.handshake, install.install_keys.level);

    // Rebuild the keys manually from the same transcript and shared secret.
    var th = TranscriptHash.init();
    th.update(client_hello);
    th.update(server_hello);
    const shared = try X25519.scalarmult(hs.x25519_secret, server_public);
    var ks = KeySchedule.init();
    ks.deriveHandshakeSecrets(&shared, th.current());
    const expected_seal = KeySchedule.deriveQuicKeys(ks.client_handshake_traffic_secret);
    const expected_open = KeySchedule.deriveQuicKeys(ks.server_handshake_traffic_secret);

    // Client seals with the client handshake secret, opens with the server's.
    try std.testing.expectEqualSlices(u8, &expected_seal.key, &install.install_keys.seal.key);
    try std.testing.expectEqualSlices(u8, &expected_seal.iv, &install.install_keys.seal.iv);
    try std.testing.expectEqualSlices(u8, &expected_seal.hp, &install.install_keys.seal.hp);
    try std.testing.expectEqualSlices(u8, &expected_open.key, &install.install_keys.open.key);
    try std.testing.expectEqualSlices(u8, &expected_open.iv, &install.install_keys.open.iv);
    try std.testing.expectEqualSlices(u8, &expected_open.hp, &install.install_keys.open.hp);
}

test "Tls13Handshake client rejects ServerHello with wrong cipher suite" {
    var hs = Tls13Handshake.initClient(.{}, &[_]u8{});
    _ = try hs.step();

    var server_secret: [32]u8 = undefined;
    secureRandomBytes(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);

    var sh_buf: [128]u8 = undefined;
    const sh_len = buildServerHello(&sh_buf, server_public, 0x1302, true, true);
    hs.provideData(sh_buf[0..sh_len]);

    try std.testing.expectError(error.DecodeError, hs.step());
}

test "Tls13Handshake client rejects duplicate known ServerHello extensions" {
    var hs = Tls13Handshake.initClient(.{}, &[_]u8{});
    _ = try hs.step();

    var server_secret: [32]u8 = undefined;
    secureRandomBytes(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);

    var sh_buf: [160]u8 = undefined;
    const base_len = buildServerHello(&sh_buf, server_public, cipher_aes_128_gcm_sha256, true, true);
    const server_hello = try appendDuplicateServerHelloExtension(
        &sh_buf,
        base_len,
        @intFromEnum(ExtType.supported_versions),
    );
    hs.provideData(server_hello);

    try std.testing.expectError(error.DecodeError, hs.step());
}

test "Tls13Handshake client rejects malformed ServerHello supported_versions length" {
    var hs = Tls13Handshake.initClient(.{}, &[_]u8{});
    _ = try hs.step();

    var server_secret: [32]u8 = undefined;
    secureRandomBytes(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);

    var sh_buf: [160]u8 = undefined;
    const base_len = buildServerHello(&sh_buf, server_public, cipher_aes_128_gcm_sha256, true, true);
    const server_hello = try extendServerHelloExtensionBody(
        &sh_buf,
        base_len,
        @intFromEnum(ExtType.supported_versions),
        &[_]u8{0x00},
    );
    hs.provideData(server_hello);

    try std.testing.expectError(error.DecodeError, hs.step());
}

test "Tls13Handshake client rejects unsupported HelloRetryRequest sentinel" {
    var hs = Tls13Handshake.initClient(.{}, &[_]u8{});
    _ = try hs.step();

    var server_secret: [32]u8 = undefined;
    secureRandomBytes(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);

    var sh_buf: [128]u8 = undefined;
    const sh_len = buildServerHello(&sh_buf, server_public, cipher_aes_128_gcm_sha256, true, true);
    @memcpy(sh_buf[4 + 2 ..][0..32], &hello_retry_request_random);
    hs.provideData(sh_buf[0..sh_len]);

    try std.testing.expectError(error.DecodeError, hs.step());
}

test "Tls13Handshake client rejects trailing bytes after ServerHello extensions" {
    var hs = Tls13Handshake.initClient(.{}, &[_]u8{});
    _ = try hs.step();

    var server_secret: [32]u8 = undefined;
    secureRandomBytes(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);

    var sh_buf: [160]u8 = undefined;
    const base_len = buildServerHello(&sh_buf, server_public, cipher_aes_128_gcm_sha256, true, true);
    const server_hello = try appendTrailingHandshakeByte(&sh_buf, base_len, 0xaa);
    hs.provideData(server_hello);

    try std.testing.expectError(error.DecodeError, hs.step());
}

test "Tls13Handshake client rejects ServerHello invalid legacy_version" {
    var hs = Tls13Handshake.initClient(.{}, &[_]u8{});
    _ = try hs.step();

    var server_secret: [32]u8 = undefined;
    secureRandomBytes(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);

    var sh_buf: [128]u8 = undefined;
    const sh_len = buildServerHello(&sh_buf, server_public, cipher_aes_128_gcm_sha256, true, true);
    writeU16(sh_buf[4..][0..2], 0x0301);
    hs.provideData(sh_buf[0..sh_len]);

    try std.testing.expectError(error.UnsupportedVersion, hs.step());
}

test "Tls13Handshake client rejects non-empty ServerHello legacy_session_id_echo" {
    var hs = Tls13Handshake.initClient(.{}, &[_]u8{});
    _ = try hs.step();

    var server_secret: [32]u8 = undefined;
    secureRandomBytes(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);

    var sh_buf: [128]u8 = undefined;
    const sh_len = buildServerHello(&sh_buf, server_public, cipher_aes_128_gcm_sha256, true, true);
    const sid_len_offset = 4 + 2 + 32;
    const insert_offset = sid_len_offset + 1;
    std.mem.copyBackwards(u8, sh_buf[insert_offset + 1 .. sh_len + 1], sh_buf[insert_offset..sh_len]);
    sh_buf[sid_len_offset] = 1;
    sh_buf[insert_offset] = 0xaa;
    const new_body_len = sh_len + 1 - 4;
    sh_buf[1] = @intCast((new_body_len >> 16) & 0xFF);
    sh_buf[2] = @intCast((new_body_len >> 8) & 0xFF);
    sh_buf[3] = @intCast(new_body_len & 0xFF);
    hs.provideData(sh_buf[0 .. sh_len + 1]);

    try std.testing.expectError(error.DecodeError, hs.step());
}

test "Tls13Handshake client rejects non-null ServerHello compression method" {
    var hs = Tls13Handshake.initClient(.{}, &[_]u8{});
    _ = try hs.step();

    var server_secret: [32]u8 = undefined;
    secureRandomBytes(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);

    var sh_buf: [128]u8 = undefined;
    const sh_len = buildServerHello(&sh_buf, server_public, cipher_aes_128_gcm_sha256, true, true);
    const compression_method_offset = 4 + 2 + 32 + 1 + 2;
    sh_buf[compression_method_offset] = 1;
    hs.provideData(sh_buf[0..sh_len]);

    try std.testing.expectError(error.DecodeError, hs.step());
}

test "Tls13Handshake client rejects ServerHello missing supported_versions" {
    var hs = Tls13Handshake.initClient(.{}, &[_]u8{});
    _ = try hs.step();

    var server_secret: [32]u8 = undefined;
    secureRandomBytes(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);

    var sh_buf: [128]u8 = undefined;
    const sh_len = buildServerHello(&sh_buf, server_public, cipher_aes_128_gcm_sha256, false, true);
    hs.provideData(sh_buf[0..sh_len]);

    try std.testing.expectError(error.MissingExtension, hs.step());
}

test "Tls13Handshake client rejects ServerHello missing key_share" {
    var hs = Tls13Handshake.initClient(.{}, &[_]u8{});
    _ = try hs.step();

    var server_secret: [32]u8 = undefined;
    secureRandomBytes(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);

    var sh_buf: [128]u8 = undefined;
    const sh_len = buildServerHello(&sh_buf, server_public, cipher_aes_128_gcm_sha256, true, false);
    hs.provideData(sh_buf[0..sh_len]);

    try std.testing.expectError(error.NoKeyShare, hs.step());
}

// ─── Tests for client handshake completion ───────────────────────────

/// Build a minimal EncryptedExtensions carrying an optional ALPN protocol
/// and an optional opaque QUIC transport parameters blob.
pub fn buildEncryptedExtensions(buf: []u8, alpn: []const u8, peer_tp: []const u8) usize {
    var p: usize = 0;
    buf[p] = @intFromEnum(HandshakeType.encrypted_extensions);
    p += 1;
    p += 3; // length placeholder
    const ext_start = p;
    p += 2; // extensions length placeholder
    if (alpn.len > 0) {
        const alpn_ext_len = 2 + 1 + alpn.len;
        p = writeExtHeader(buf, p, @intFromEnum(ExtType.alpn), alpn_ext_len);
        writeU16(buf[p..], @intCast(1 + alpn.len));
        p += 2;
        buf[p] = @intCast(alpn.len);
        p += 1;
        @memcpy(buf[p..][0..alpn.len], alpn);
        p += alpn.len;
    }
    if (peer_tp.len > 0) {
        p = writeExtHeader(buf, p, @intFromEnum(ExtType.quic_transport_parameters), peer_tp.len);
        @memcpy(buf[p..][0..peer_tp.len], peer_tp);
        p += peer_tp.len;
    }
    const ext_len = p - ext_start - 2;
    writeU16(buf[ext_start..], @intCast(ext_len));
    const msg_len = p - 4;
    buf[1] = @intCast((msg_len >> 16) & 0xFF);
    buf[2] = @intCast((msg_len >> 8) & 0xFF);
    buf[3] = @intCast(msg_len & 0xFF);
    return p;
}

fn appendDuplicateEncryptedExtensionsExtension(buf: []u8, msg_len: usize, ext_type: u16) ![]u8 {
    if (msg_len < 6 or buf[0] != @intFromEnum(HandshakeType.encrypted_extensions)) {
        return error.TestUnexpectedResult;
    }
    var pos: usize = 4;
    const extensions_len_offset = pos;
    const extensions_len = readU16(buf[pos..]);
    pos += 2;
    if (pos + extensions_len > msg_len) return error.TestUnexpectedResult;
    const ext_end = pos + extensions_len;

    while (pos < ext_end) {
        if (pos + 4 > ext_end) return error.TestUnexpectedResult;
        const header_offset = pos;
        const current_type = readU16(buf[pos..]);
        const current_len = readU16(buf[pos + 2 ..]);
        pos += 4;
        if (pos + current_len > ext_end) return error.TestUnexpectedResult;
        if (current_type == ext_type) {
            const duplicate_len = 4 + current_len;
            if (msg_len + duplicate_len > buf.len) return error.TestUnexpectedResult;
            std.mem.copyForwards(u8, buf[msg_len..][0..duplicate_len], buf[header_offset..][0..duplicate_len]);
            const new_body_len = msg_len - 4 + duplicate_len;
            buf[1] = @as(u8, @intCast(new_body_len >> 16));
            buf[2] = @as(u8, @intCast((new_body_len >> 8) & 0xFF));
            buf[3] = @as(u8, @intCast(new_body_len & 0xFF));
            writeU16(
                buf[extensions_len_offset..][0..2],
                @as(u16, @intCast(extensions_len + duplicate_len)),
            );
            return buf[0 .. msg_len + duplicate_len];
        }
        pos += current_len;
    }
    return error.TestUnexpectedResult;
}

/// Build a Certificate message carrying a leaf-first DER certificate chain.
///
/// Every entry is emitted with empty per-certificate extensions. `null` means
/// the chain is empty, an entry exceeds the TLS 24-bit vector limit, or the
/// output buffer cannot hold the complete message.
pub fn buildCertificateChain(buf: []u8, cert_chain_der: []const []const u8) ?usize {
    if (cert_chain_der.len == 0 or buf.len < 8) return null;

    var p: usize = 0;
    buf[p] = @intFromEnum(HandshakeType.certificate);
    p += 1;
    p += 3; // handshake message length placeholder
    buf[p] = 0; // certificate_request_context: empty
    p += 1;
    const list_start = p;
    p += 3; // certificate_list length placeholder

    for (cert_chain_der) |cert_der| {
        if (cert_der.len > 0xFF_FF_FF) return null;
        const entry_len = std.math.add(usize, cert_der.len, 5) catch return null;
        const next = std.math.add(usize, p, entry_len) catch return null;
        if (next > buf.len) return null;

        buf[p] = @truncate(cert_der.len >> 16);
        buf[p + 1] = @truncate(cert_der.len >> 8);
        buf[p + 2] = @truncate(cert_der.len);
        p += 3;
        @memcpy(buf[p..][0..cert_der.len], cert_der);
        p += cert_der.len;
        writeU16(buf[p..], 0); // certificate-entry extensions
        p += 2;
    }

    const list_len = p - (list_start + 3);
    if (list_len > 0xFF_FF_FF) return null;
    buf[list_start] = @truncate(list_len >> 16);
    buf[list_start + 1] = @truncate(list_len >> 8);
    buf[list_start + 2] = @truncate(list_len);

    const message_len = p - 4;
    if (message_len > 0xFF_FF_FF) return null;
    buf[1] = @truncate(message_len >> 16);
    buf[2] = @truncate(message_len >> 8);
    buf[3] = @truncate(message_len);
    return p;
}

/// Build a Certificate message carrying a single DER certificate.
pub fn buildCertificate(buf: []u8, cert_der: []const u8) usize {
    return buildCertificateChain(buf, &.{cert_der}).?;
}

test "buildCertificateChain encodes every configured certificate" {
    const leaf = [_]u8{ 0x01, 0x02 };
    const issuer = [_]u8{ 0xa0, 0xb1, 0xc2 };
    var buf: [64]u8 = undefined;
    const len = buildCertificateChain(&buf, &.{ &leaf, &issuer }) orelse return error.TestUnexpectedResult;

    const expected = [_]u8{
        @intFromEnum(HandshakeType.certificate), 0, 0,    19,
        0,                                       0, 0,    15,
        0,                                       0, 2,    0x01,
        0x02,                                    0, 0,    0,
        0,                                       3, 0xa0, 0xb1,
        0xc2,                                    0, 0,
    };
    try std.testing.expectEqual(expected.len, len);
    try std.testing.expectEqualSlices(u8, &expected, buf[0..len]);
}

test "buildCertificateChain rejects empty and oversized output" {
    var empty_buf: [8]u8 = undefined;
    try std.testing.expect(buildCertificateChain(&empty_buf, &.{}) == null);

    const leaf = [_]u8{0x01};
    var too_small: [8]u8 = undefined;
    try std.testing.expect(buildCertificateChain(&too_small, &.{&leaf}) == null);
}

test "buildCertificateChain writes multi-byte vector lengths" {
    const leaf = [_]u8{0xaa} ** 300;
    var buf: [400]u8 = undefined;
    const len = buildCertificateChain(&buf, &.{&leaf}) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqual(@as(usize, 313), len);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 53 }, buf[1..4]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 49 }, buf[5..8]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 44 }, buf[8..11]);
}

test "Tls13Handshake validates supplied certificate entries to a trust anchor" {
    const pem = @embedFile("testdata/quicz-echo-ca.pem");
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    const begin = std.mem.indexOf(u8, pem, begin_marker) orelse return error.TestUnexpectedResult;
    const encoded_start = begin + begin_marker.len;
    const encoded_end = std.mem.indexOfPos(u8, pem, encoded_start, end_marker) orelse return error.TestUnexpectedResult;
    const encoded = std.mem.trim(u8, pem[encoded_start..encoded_end], " \t\r\n");
    var der_storage: [512]u8 = undefined;
    const decoder = std.base64.standard.decoderWithIgnore("\r\n");
    const der_len = try decoder.decode(&der_storage, encoded);
    const der = der_storage[0..der_len];

    const now_sec: i64 = 1_800_000_000;
    var bundle = Certificate.Bundle.empty;
    defer bundle.deinit(std.testing.allocator);
    try bundle.bytes.appendSlice(std.testing.allocator, der);
    try bundle.parseCert(std.testing.allocator, 0, now_sec);

    var certificate_message: [2048]u8 = undefined;
    const certificate_len = buildCertificateChain(&certificate_message, &.{ der, der }) orelse return error.TestUnexpectedResult;
    var handshake = Tls13Handshake.initClient(.{
        .server_name = "localhost",
        .skip_cert_verify = false,
        .now_sec = now_sec,
        .ca_bundle = &bundle,
    }, &.{});
    handshake.provideData(certificate_message[0..certificate_len]);
    try std.testing.expect(std.meta.activeTag(try handshake.clientProcessCertificate()) == ._continue);
    try std.testing.expectEqualSlices(u8, der, handshake.server_cert[0..handshake.server_cert_len]);
}

test "nextCertificateEntry rejects truncated extensions" {
    const malformed = [_]u8{ 0, 0, 1, 0xaa, 0 };
    var pos: usize = 0;
    try std.testing.expectError(error.DecodeError, Tls13Handshake.nextCertificateEntry(&malformed, &pos, malformed.len));
}

test "Tls13Handshake rejects malformed certificate chains when verification is skipped" {
    const malformed = [_]u8{
        @intFromEnum(HandshakeType.certificate), 0, 0, 9,
        0,                                       0, 0, 5,
        0,                                       0, 1, 0xaa,
        0,
    };
    var handshake = Tls13Handshake.initClient(.{}, &.{});
    handshake.provideData(&malformed);
    try std.testing.expectError(error.DecodeError, handshake.clientProcessCertificate());
}

test "Tls13Handshake rejects non-empty server Certificate request context" {
    const cert_der = [_]u8{0x30};
    var certificate_message: [64]u8 = undefined;
    const certificate_len = buildCertificate(&certificate_message, &cert_der);
    const context_offset = 4;
    const insert_offset = context_offset + 1;
    std.mem.copyBackwards(
        u8,
        certificate_message[insert_offset + 1 .. certificate_len + 1],
        certificate_message[insert_offset..certificate_len],
    );
    certificate_message[context_offset] = 1;
    certificate_message[insert_offset] = 0xaa;
    const new_body_len = certificate_len + 1 - 4;
    certificate_message[1] = @intCast((new_body_len >> 16) & 0xFF);
    certificate_message[2] = @intCast((new_body_len >> 8) & 0xFF);
    certificate_message[3] = @intCast(new_body_len & 0xFF);

    var handshake = Tls13Handshake.initClient(.{ .skip_cert_verify = true }, &[_]u8{});
    handshake.state = .client_wait_certificate;
    handshake.provideData(certificate_message[0 .. certificate_len + 1]);

    try std.testing.expectError(error.DecodeError, handshake.clientProcessCertificate());
}

/// Build a CertificateVerify message with a signature scheme and signature.
pub fn buildCertificateVerify(buf: []u8, scheme: u16, sig: []const u8) usize {
    var p: usize = 0;
    buf[p] = @intFromEnum(HandshakeType.certificate_verify);
    p += 1;
    p += 3; // length placeholder
    writeU16(buf[p..], scheme);
    p += 2;
    writeU16(buf[p..], @intCast(sig.len));
    p += 2;
    @memcpy(buf[p..][0..sig.len], sig);
    p += sig.len;
    const msg_len = p - 4;
    buf[1] = @intCast((msg_len >> 16) & 0xFF);
    buf[2] = @intCast((msg_len >> 8) & 0xFF);
    buf[3] = @intCast(msg_len & 0xFF);
    return p;
}

/// Build a Finished message carrying 32 bytes of verify_data.
pub fn buildFinished(buf: []u8, verify_data: [32]u8) usize {
    buf[0] = @intFromEnum(HandshakeType.finished);
    const msg_len: usize = 32;
    buf[1] = @intCast((msg_len >> 16) & 0xFF);
    buf[2] = @intCast((msg_len >> 8) & 0xFF);
    buf[3] = @intCast(msg_len & 0xFF);
    @memcpy(buf[4..36], &verify_data);
    return 36;
}

test "Tls13Handshake client completes full handshake and installs application keys" {
    const alpn_proto = "hq-interop";
    const alpn = [_][]const u8{alpn_proto};
    const peer_tp = [_]u8{ 0xAB, 0xCD, 0xEF };
    var hs = Tls13Handshake.initClient(.{
        .alpn = &alpn,
        .server_name = "example.com",
    }, &[_]u8{ 0x01, 0x02 });

    // 1. ClientHello
    const ch_action = try hs.step();
    try std.testing.expect(std.meta.activeTag(ch_action) == .send_data);
    const client_hello = ch_action.send_data.data;

    // Server X25519 key pair + shared secret.
    var server_secret: [32]u8 = undefined;
    secureRandomBytes(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);
    const shared = try X25519.scalarmult(hs.x25519_secret, server_public);

    // Independent transcript + key schedule to predict verify_data and keys.
    var th = TranscriptHash.init();
    th.update(client_hello);
    var ks = KeySchedule.init();

    // 2. ServerHello
    var sh_buf: [128]u8 = undefined;
    const sh_len = buildServerHello(&sh_buf, server_public, cipher_aes_128_gcm_sha256, true, true);
    const server_hello = sh_buf[0..sh_len];
    hs.provideData(server_hello);
    th.update(server_hello);
    ks.deriveHandshakeSecrets(&shared, th.current());

    try std.testing.expect(std.meta.activeTag(try hs.step()) == ._continue);
    const hs_install = try hs.step();
    try std.testing.expectEqual(EncryptionLevel.handshake, hs_install.install_keys.level);

    // 3. EncryptedExtensions (ALPN + peer transport params)
    var ee_buf: [256]u8 = undefined;
    const ee_len = buildEncryptedExtensions(&ee_buf, alpn_proto, &peer_tp);
    const ee = ee_buf[0..ee_len];
    hs.provideData(ee);
    th.update(ee);
    try std.testing.expect(std.meta.activeTag(try hs.step()) == ._continue);

    // 4. Certificate
    const cert_der = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    var cert_buf: [512]u8 = undefined;
    const cert_len = buildCertificate(&cert_buf, &cert_der);
    const cert = cert_buf[0..cert_len];
    hs.provideData(cert);
    th.update(cert);
    try std.testing.expect(std.meta.activeTag(try hs.step()) == ._continue);

    // 5. CertificateVerify
    const sig_scheme: u16 = 0x0807; // ed25519
    const sig_bytes = [_]u8{0x42} ** 64;
    var cv_buf: [256]u8 = undefined;
    const cv_len = buildCertificateVerify(&cv_buf, sig_scheme, &sig_bytes);
    const cv = cv_buf[0..cv_len];
    hs.provideData(cv);
    th.update(cv);
    try std.testing.expect(std.meta.activeTag(try hs.step()) == ._continue);

    // Captured peer state along the way.
    try std.testing.expectEqualStrings(alpn_proto, hs.negotiated_alpn[0..hs.negotiated_alpn_len]);
    try std.testing.expectEqualSlices(u8, &peer_tp, hs.peer_tp[0..hs.peer_tp_len]);
    try std.testing.expectEqualSlices(u8, &cert_der, hs.server_cert[0..hs.server_cert_len]);
    try std.testing.expectEqual(sig_scheme, hs.cert_verify_scheme);
    try std.testing.expectEqualSlices(u8, &sig_bytes, hs.cert_verify_sig[0..hs.cert_verify_sig_len]);

    // 6. Server Finished (correct verify_data over transcript up to CV).
    const server_verify = KeySchedule.computeFinishedVerifyData(
        ks.server_handshake_traffic_secret,
        th.current(),
    );
    var sf_buf: [64]u8 = undefined;
    const sf_len = buildFinished(&sf_buf, server_verify);
    const server_finished = sf_buf[0..sf_len];
    hs.provideData(server_finished);
    th.update(server_finished); // app secrets derive from here
    try std.testing.expect(std.meta.activeTag(try hs.step()) == ._continue);

    // 7. Client sends its Finished at the Handshake level.
    const cf_action = try hs.step();
    try std.testing.expect(std.meta.activeTag(cf_action) == .send_data);
    try std.testing.expectEqual(EncryptionLevel.handshake, cf_action.send_data.level);
    const client_finished = cf_action.send_data.data;
    try std.testing.expectEqual(@as(usize, 36), client_finished.len);

    // Client verify_data uses the client handshake secret over the transcript
    // up to (not including) the client Finished — i.e. through server Finished.
    const expected_cf = KeySchedule.computeFinishedVerifyData(
        ks.client_handshake_traffic_secret,
        th.current(),
    );
    try std.testing.expectEqualSlices(u8, &expected_cf, client_finished[4..36]);

    // 8. Application keys are installed next.
    const app_install = try hs.step();
    try std.testing.expectEqual(EncryptionLevel.application, app_install.install_keys.level);
    ks.deriveAppSecrets(th.current());
    const expected_seal = KeySchedule.deriveQuicKeys(ks.client_app_traffic_secret);
    const expected_open = KeySchedule.deriveQuicKeys(ks.server_app_traffic_secret);
    try std.testing.expectEqualSlices(u8, &expected_seal.key, &app_install.install_keys.seal.key);
    try std.testing.expectEqualSlices(u8, &expected_seal.iv, &app_install.install_keys.seal.iv);
    try std.testing.expectEqualSlices(u8, &expected_seal.hp, &app_install.install_keys.seal.hp);
    try std.testing.expectEqualSlices(u8, &expected_open.key, &app_install.install_keys.open.key);
    try std.testing.expectEqualSlices(u8, &expected_open.iv, &app_install.install_keys.open.iv);
    try std.testing.expectEqualSlices(u8, &expected_open.hp, &app_install.install_keys.open.hp);

    // 9. Handshake complete.
    try std.testing.expect(std.meta.activeTag(try hs.step()) == .complete);
    try std.testing.expect(hs.isComplete());
}

test "Tls13Handshake client rejects unoffered server ALPN" {
    const alpn = [_][]const u8{"hq-interop"};
    var hs = Tls13Handshake.initClient(.{
        .alpn = &alpn,
        .server_name = "example.com",
    }, &[_]u8{});

    _ = try hs.step();

    var server_secret: [32]u8 = undefined;
    secureRandomBytes(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);
    var sh_buf: [128]u8 = undefined;
    hs.provideData(sh_buf[0..buildServerHello(&sh_buf, server_public, cipher_aes_128_gcm_sha256, true, true)]);
    _ = try hs.step();
    _ = try hs.step();

    var ee_buf: [256]u8 = undefined;
    hs.provideData(ee_buf[0..buildEncryptedExtensions(&ee_buf, "other-proto", &[_]u8{})]);
    try std.testing.expectError(error.NoApplicationProtocol, hs.step());
}

test "Tls13Handshake client rejects missing ALPN selection when offered" {
    const alpn = [_][]const u8{"hq-interop"};
    var hs = Tls13Handshake.initClient(.{
        .alpn = &alpn,
        .server_name = "example.com",
    }, &[_]u8{});

    _ = try hs.step();

    var server_secret: [32]u8 = undefined;
    secureRandomBytes(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);
    var sh_buf: [128]u8 = undefined;
    hs.provideData(sh_buf[0..buildServerHello(&sh_buf, server_public, cipher_aes_128_gcm_sha256, true, true)]);
    _ = try hs.step();
    _ = try hs.step();

    var ee_buf: [256]u8 = undefined;
    hs.provideData(ee_buf[0..buildEncryptedExtensions(&ee_buf, "", &[_]u8{})]);
    try std.testing.expectError(error.NoApplicationProtocol, hs.step());
}

test "Tls13Handshake client rejects duplicate known EncryptedExtensions extensions" {
    var hs = Tls13Handshake.initClient(.{}, &[_]u8{});
    _ = try hs.step();

    var server_secret: [32]u8 = undefined;
    secureRandomBytes(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);
    var sh_buf: [128]u8 = undefined;
    hs.provideData(sh_buf[0..buildServerHello(&sh_buf, server_public, cipher_aes_128_gcm_sha256, true, true)]);
    _ = try hs.step();
    _ = try hs.step();

    var ee_buf: [256]u8 = undefined;
    const base_len = buildEncryptedExtensions(&ee_buf, "", &[_]u8{ 0x01, 0x02, 0x03 });
    const encrypted_extensions = try appendDuplicateEncryptedExtensionsExtension(
        &ee_buf,
        base_len,
        @intFromEnum(ExtType.quic_transport_parameters),
    );
    hs.provideData(encrypted_extensions);
    try std.testing.expectError(error.DecodeError, hs.step());
}

test "Tls13Handshake client rejects oversized EncryptedExtensions transport parameters" {
    var hs = Tls13Handshake.initClient(.{}, &[_]u8{});
    _ = try hs.step();

    var peer_tp: [1025]u8 = undefined;
    @memset(&peer_tp, 0xaa);
    var ee_buf: [2048]u8 = undefined;
    const ee_len = buildEncryptedExtensions(&ee_buf, "", &peer_tp);
    hs.provideData(ee_buf[0..ee_len]);

    try std.testing.expectError(error.DecodeError, hs.clientProcessEncryptedExtensions());
}

test "Tls13Handshake server rejects oversized local transport parameters" {
    var tp: [1025]u8 = undefined;
    @memset(&tp, 0xaa);
    var hs = Tls13Handshake.initServer(.{}, &tp);

    try std.testing.expectError(error.DecodeError, hs.serverBuildEncryptedExtensions());
}

test "Tls13Handshake server rejects oversized EncryptedExtensions ALPN output" {
    var hs = Tls13Handshake.initServer(.{}, &[_]u8{});
    @memset(&hs.negotiated_alpn, 'a');
    hs.negotiated_alpn_len = hs.negotiated_alpn.len;

    try std.testing.expectError(error.DecodeError, hs.serverBuildEncryptedExtensions());
}

test "Tls13Handshake client rejects trailing bytes after EncryptedExtensions extensions" {
    var hs = Tls13Handshake.initClient(.{}, &[_]u8{});
    _ = try hs.step();

    var server_secret: [32]u8 = undefined;
    secureRandomBytes(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);
    var sh_buf: [128]u8 = undefined;
    hs.provideData(sh_buf[0..buildServerHello(&sh_buf, server_public, cipher_aes_128_gcm_sha256, true, true)]);
    _ = try hs.step();
    _ = try hs.step();

    var ee_buf: [256]u8 = undefined;
    const base_len = buildEncryptedExtensions(&ee_buf, "", &[_]u8{});
    const encrypted_extensions = try appendTrailingHandshakeByte(&ee_buf, base_len, 0xaa);
    hs.provideData(encrypted_extensions);
    try std.testing.expectError(error.DecodeError, hs.step());
}

test "Tls13Handshake client rejects server Finished with wrong verify_data" {
    var hs = Tls13Handshake.initClient(.{}, &[_]u8{});
    _ = try hs.step(); // ClientHello

    var server_secret: [32]u8 = undefined;
    secureRandomBytes(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);
    var sh_buf: [128]u8 = undefined;
    hs.provideData(sh_buf[0..buildServerHello(&sh_buf, server_public, cipher_aes_128_gcm_sha256, true, true)]);
    _ = try hs.step(); // _continue
    _ = try hs.step(); // install_keys(handshake)

    var buf: [512]u8 = undefined;
    hs.provideData(buf[0..buildEncryptedExtensions(&buf, "", &[_]u8{})]);
    _ = try hs.step();
    hs.provideData(buf[0..buildCertificate(&buf, &[_]u8{0x30})]);
    _ = try hs.step();
    hs.provideData(buf[0..buildCertificateVerify(&buf, 0x0807, &[_]u8{0x01})]);
    _ = try hs.step();

    // Wrong verify_data (all zeros) — must not match the real one.
    const bad: [32]u8 = [_]u8{0} ** 32;
    var fin_buf: [64]u8 = undefined;
    hs.provideData(fin_buf[0..buildFinished(&fin_buf, bad)]);
    try std.testing.expectError(error.BadFinished, hs.step());
}

test "Tls13Handshake client rejects CertificateVerify with trailing bytes" {
    var cv_buf: [64]u8 = undefined;
    const base_len = buildCertificateVerify(&cv_buf, 0x0807, &[_]u8{0x01});
    cv_buf[base_len] = 0xaa;
    const new_body_len = base_len + 1 - 4;
    cv_buf[1] = @intCast((new_body_len >> 16) & 0xFF);
    cv_buf[2] = @intCast((new_body_len >> 8) & 0xFF);
    cv_buf[3] = @intCast(new_body_len & 0xFF);

    var handshake = Tls13Handshake.initClient(.{ .skip_cert_verify = true }, &[_]u8{});
    handshake.state = .client_wait_certificate_verify;
    handshake.provideData(cv_buf[0 .. base_len + 1]);

    try std.testing.expectError(error.DecodeError, handshake.clientProcessCertificateVerify());
}

test "Tls13Handshake client rejects oversized CertificateVerify signature" {
    const oversized_sig = [_]u8{0xaa} ** 1025;
    var cv_buf: [1100]u8 = undefined;
    const cv_len = buildCertificateVerify(&cv_buf, 0x0807, &oversized_sig);

    var handshake = Tls13Handshake.initClient(.{ .skip_cert_verify = true }, &[_]u8{});
    handshake.state = .client_wait_certificate_verify;
    handshake.provideData(cv_buf[0..cv_len]);

    try std.testing.expectError(error.DecodeError, handshake.clientProcessCertificateVerify());
}

// ─── Tests for CertificateVerify signature verification ─────────────

/// Build the TLS 1.3 server CertificateVerify signed content over a fixed
/// transcript hash for use in signature tests.
pub fn certVerifySignedContent(transcript_hash: [32]u8) [130]u8 {
    const label = "TLS 1.3, server CertificateVerify";
    var signed: [64 + label.len + 1 + 32]u8 = undefined;
    @memset(signed[0..64], 0x20);
    @memcpy(signed[64..][0..label.len], label);
    signed[64 + label.len] = 0x00;
    @memcpy(signed[64 + label.len + 1 ..][0..32], &transcript_hash);
    return signed;
}

test "verifyCertificateVerifySignature accepts a valid ECDSA P-256 signature" {
    const seed = [_]u8{0x11} ** 32;
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const pub_key = kp.public_key.toUncompressedSec1();

    const th: [32]u8 = [_]u8{0xAB} ** 32;
    const signed = certVerifySignedContent(th);

    const sig = try kp.sign(&signed, null);
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);

    try verifyCertificateVerifySignature(&pub_key, .X9_62_id_ecPublicKey, 0x0403, der, &signed);
}

test "verifyCertificateVerifySignature rejects a tampered ECDSA P-256 signature" {
    const seed = [_]u8{0x11} ** 32;
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const pub_key = kp.public_key.toUncompressedSec1();

    const th: [32]u8 = [_]u8{0xAB} ** 32;
    const signed = certVerifySignedContent(th);

    const sig = try kp.sign(&signed, null);
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);
    // Flip a byte in the DER signature.
    var tampered = der_buf;
    tampered[0] ^= 0xFF;
    const tampered_der = tampered[0..der.len];

    try std.testing.expectError(
        error.BadCertificateVerify,
        verifyCertificateVerifySignature(&pub_key, .X9_62_id_ecPublicKey, 0x0403, tampered_der, &signed),
    );
}

test "verifyCertificateVerifySignature accepts a valid Ed25519 signature" {
    const seed = [_]u8{0x22} ** 32;
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const pub_key = kp.public_key.toBytes();

    const th: [32]u8 = [_]u8{0xCD} ** 32;
    const signed = certVerifySignedContent(th);

    const sig = try kp.sign(&signed, null);
    const sig_bytes = sig.toBytes();

    try verifyCertificateVerifySignature(&pub_key, .curveEd25519, 0x0807, &sig_bytes, &signed);
}

test "verifyCertificateVerifySignature rejects a tampered Ed25519 signature" {
    const seed = [_]u8{0x22} ** 32;
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const pub_key = kp.public_key.toBytes();

    const th: [32]u8 = [_]u8{0xCD} ** 32;
    const signed = certVerifySignedContent(th);

    const sig = try kp.sign(&signed, null);
    var sig_bytes = sig.toBytes();
    sig_bytes[0] ^= 0xFF;

    try std.testing.expectError(
        error.BadCertificateVerify,
        verifyCertificateVerifySignature(&pub_key, .curveEd25519, 0x0807, &sig_bytes, &signed),
    );
}

test "verifyCertificateVerifySignature rejects a scheme/key-algorithm mismatch" {
    // Ed25519 public key + signature, but the scheme claims ECDSA P-256.
    const seed = [_]u8{0x22} ** 32;
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const pub_key = kp.public_key.toBytes();
    const sig = try kp.sign("any message", null);
    const sig_bytes = sig.toBytes();

    try std.testing.expectError(
        error.BadCertificateVerify,
        verifyCertificateVerifySignature(&pub_key, .curveEd25519, 0x0403, &sig_bytes, "any message"),
    );
}

test "verifyCertificateVerifySignature rejects an unsupported scheme" {
    try std.testing.expectError(
        error.BadCertificateVerify,
        verifyCertificateVerifySignature(&[_]u8{}, .curveEd25519, 0x0000, &[_]u8{}, "msg"),
    );
}

// ─── Tests for server-side handshake + loopback ──────────────────────

const ClientHelloExtension = struct {
    header_offset: usize,
    body_offset: usize,
    body_len: usize,
    extensions_len_offset: usize,
};

fn clientHelloExtension(msg: []const u8, ext_type: u16) !ClientHelloExtension {
    if (msg.len < 4 or msg[0] != @intFromEnum(HandshakeType.client_hello)) return error.TestUnexpectedResult;
    const body = msg[4..];
    var pos: usize = 0;
    if (body.len < 2 + 32 + 1) return error.TestUnexpectedResult;
    pos += 2 + 32;
    const sid_len = body[pos];
    pos += 1;
    if (pos + sid_len > body.len) return error.TestUnexpectedResult;
    pos += sid_len;
    if (pos + 2 > body.len) return error.TestUnexpectedResult;
    const cipher_suites_len = readU16(body[pos..]);
    pos += 2;
    if (pos + cipher_suites_len > body.len) return error.TestUnexpectedResult;
    pos += cipher_suites_len;
    if (pos >= body.len) return error.TestUnexpectedResult;
    const compression_methods_len = body[pos];
    pos += 1;
    if (pos + compression_methods_len > body.len) return error.TestUnexpectedResult;
    pos += compression_methods_len;
    if (pos + 2 > body.len) return error.TestUnexpectedResult;
    const extensions_len_offset = 4 + pos;
    const extensions_len = readU16(body[pos..]);
    pos += 2;
    if (pos + extensions_len > body.len) return error.TestUnexpectedResult;
    const ext_end = pos + extensions_len;
    while (pos < ext_end) {
        if (pos + 4 > ext_end) return error.TestUnexpectedResult;
        const header_offset = 4 + pos;
        const current_type = readU16(body[pos..]);
        const current_len = readU16(body[pos + 2 ..]);
        pos += 4;
        if (pos + current_len > ext_end) return error.TestUnexpectedResult;
        if (current_type == ext_type) {
            return .{
                .header_offset = header_offset,
                .body_offset = 4 + pos,
                .body_len = current_len,
                .extensions_len_offset = extensions_len_offset,
            };
        }
        pos += current_len;
    }
    return error.TestUnexpectedResult;
}

fn clientHelloBytes(config: TlsConfig, out: []u8) ![]u8 {
    var client = Tls13Handshake.initClient(config, &[_]u8{});
    const action = try client.step();
    if (std.meta.activeTag(action) != .send_data) return error.TestUnexpectedResult;
    if (action.send_data.data.len > out.len) return error.TestUnexpectedResult;
    @memcpy(out[0..action.send_data.data.len], action.send_data.data);
    return out[0..action.send_data.data.len];
}

fn clientHelloPskBytes(config: TlsConfig, psk: [secret_len]u8, out: []u8) ![]u8 {
    var client = Tls13Handshake.initClientWithPsk(config, &[_]u8{}, psk);
    const ticket = [_]u8{ 0xcc, 0xdd, 0xee, 0xff };
    @memcpy(client.session_ticket[0..ticket.len], &ticket);
    client.session_ticket_len = ticket.len;
    const action = try client.step();
    if (std.meta.activeTag(action) != .send_data) return error.TestUnexpectedResult;
    if (action.send_data.data.len > out.len) return error.TestUnexpectedResult;
    @memcpy(out[0..action.send_data.data.len], action.send_data.data);
    return out[0..action.send_data.data.len];
}

fn setClientHelloBodyLen(buf: []u8, new_body_len: usize) !void {
    if (new_body_len > 0xFF_FF_FF) return error.TestUnexpectedResult;
    buf[1] = @as(u8, @intCast(new_body_len >> 16));
    buf[2] = @as(u8, @intCast((new_body_len >> 8) & 0xFF));
    buf[3] = @as(u8, @intCast(new_body_len & 0xFF));
}

fn appendTrailingHandshakeByte(buf: []u8, msg_len: usize, byte: u8) ![]u8 {
    if (msg_len < 4 or msg_len + 1 > buf.len) return error.TestUnexpectedResult;
    buf[msg_len] = byte;
    try setClientHelloBodyLen(buf, msg_len + 1 - 4);
    return buf[0 .. msg_len + 1];
}

fn appendDuplicateClientHelloExtension(buf: []u8, msg_len: usize, ext_type: u16) ![]u8 {
    const msg = buf[0..msg_len];
    const ext = try clientHelloExtension(msg, ext_type);
    const duplicate_len = 4 + ext.body_len;
    if (msg_len + duplicate_len > buf.len) return error.TestUnexpectedResult;

    const old_body_len = msg_len - 4;
    const new_body_len = old_body_len + duplicate_len;

    std.mem.copyForwards(
        u8,
        buf[msg_len..][0..duplicate_len],
        buf[ext.header_offset..][0..duplicate_len],
    );
    try setClientHelloBodyLen(buf, new_body_len);

    const old_extensions_len = readU16(buf[ext.extensions_len_offset..]);
    const new_extensions_len = old_extensions_len + duplicate_len;
    writeU16(buf[ext.extensions_len_offset..][0..2], @as(u16, @intCast(new_extensions_len)));
    return buf[0 .. msg_len + duplicate_len];
}

fn appendClientHelloRawExtension(buf: []u8, msg_len: usize, ext_type: u16, payload: []const u8) ![]u8 {
    if (payload.len > std.math.maxInt(u16)) return error.TestUnexpectedResult;
    const duplicate_len = 4 + payload.len;
    if (msg_len + duplicate_len > buf.len) return error.TestUnexpectedResult;
    const ext = try clientHelloExtension(buf[0..msg_len], @intFromEnum(ExtType.supported_versions));

    writeU16(buf[msg_len..][0..2], ext_type);
    writeU16(buf[msg_len + 2 ..][0..2], @as(u16, @intCast(payload.len)));
    @memcpy(buf[msg_len + 4 ..][0..payload.len], payload);
    try setClientHelloBodyLen(buf, msg_len - 4 + duplicate_len);

    const old_extensions_len = readU16(buf[ext.extensions_len_offset..]);
    const new_extensions_len = old_extensions_len + duplicate_len;
    writeU16(buf[ext.extensions_len_offset..][0..2], @as(u16, @intCast(new_extensions_len)));
    return buf[0 .. msg_len + duplicate_len];
}

fn extendClientHelloExtensionBody(buf: []u8, msg_len: usize, ext_type: u16, extra: []const u8) ![]u8 {
    if (extra.len == 0 or extra.len > std.math.maxInt(u16)) return error.TestUnexpectedResult;
    const ext = try clientHelloExtension(buf[0..msg_len], ext_type);
    if (ext.body_len + extra.len > std.math.maxInt(u16)) return error.TestUnexpectedResult;
    if (msg_len + extra.len > buf.len) return error.TestUnexpectedResult;

    std.mem.copyBackwards(
        u8,
        buf[ext.body_offset + extra.len ..][0 .. msg_len - ext.body_offset],
        buf[ext.body_offset..msg_len],
    );
    @memcpy(buf[ext.body_offset..][0..extra.len], extra);
    writeU16(buf[ext.header_offset + 2 ..][0..2], @as(u16, @intCast(ext.body_len + extra.len)));
    try setClientHelloBodyLen(buf, msg_len - 4 + extra.len);

    const old_extensions_len = readU16(buf[ext.extensions_len_offset..]);
    const new_extensions_len = old_extensions_len + extra.len;
    writeU16(buf[ext.extensions_len_offset..][0..2], @as(u16, @intCast(new_extensions_len)));
    return buf[0 .. msg_len + extra.len];
}

test "Tls13Handshake server rejects duplicate known ClientHello extensions" {
    var hello_buf: [1024]u8 = undefined;
    const base_hello = try clientHelloBytes(.{}, &hello_buf);
    const hello = try appendDuplicateClientHelloExtension(&hello_buf, base_hello.len, @intFromEnum(ExtType.supported_versions));

    var server = Tls13Handshake.initServer(.{}, &[_]u8{});
    server.provideData(hello);
    try std.testing.expectError(error.DecodeError, server.step());
}

test "Tls13Handshake server rejects trailing bytes after ClientHello extensions" {
    var hello_buf: [1024]u8 = undefined;
    const base_hello = try clientHelloBytes(.{}, &hello_buf);
    const hello = try appendTrailingHandshakeByte(&hello_buf, base_hello.len, 0xaa);

    var server = Tls13Handshake.initServer(.{}, &[_]u8{});
    server.provideData(hello);
    try std.testing.expectError(error.DecodeError, server.step());
}

test "Tls13Handshake server rejects non-empty ClientHello early_data extension" {
    const psk = [_]u8{0xab} ** secret_len;
    var hello_buf: [1024]u8 = undefined;
    const base_hello = try clientHelloPskBytes(.{}, psk, &hello_buf);
    const hello = try extendClientHelloExtensionBody(
        &hello_buf,
        base_hello.len,
        @intFromEnum(ExtType.early_data),
        &[_]u8{0x00},
    );

    var server = Tls13Handshake.initServerWithPsk(.{}, &[_]u8{}, psk);
    server.provideData(hello);
    try std.testing.expectError(error.DecodeError, server.step());
}

test "Tls13Handshake server rejects ClientHello pre_shared_key before trailing extension" {
    const psk = [_]u8{0xab} ** secret_len;
    var hello_buf: [1024]u8 = undefined;
    const base_hello = try clientHelloPskBytes(.{}, psk, &hello_buf);
    const hello = try appendClientHelloRawExtension(&hello_buf, base_hello.len, 0xaaaa, &[_]u8{});

    var server = Tls13Handshake.initServerWithPsk(.{}, &[_]u8{}, psk);
    server.provideData(hello);
    try std.testing.expectError(error.DecodeError, server.step());
}

test "Tls13Handshake server rejects pre_shared_key without psk_key_exchange_modes" {
    const psk = [_]u8{0xab} ** secret_len;
    var hello_buf: [1024]u8 = undefined;
    const hello = try clientHelloPskBytes(.{}, psk, &hello_buf);
    const modes = try clientHelloExtension(hello, @intFromEnum(ExtType.psk_key_exchange_modes));
    writeU16(hello[modes.header_offset..][0..2], 0xaaaa);

    var server = Tls13Handshake.initServerWithPsk(.{}, &[_]u8{}, psk);
    server.provideData(hello);
    try std.testing.expectError(error.MissingExtension, server.step());
}

test "Tls13Handshake server rejects pre_shared_key without psk_dhe_ke mode" {
    const psk = [_]u8{0xab} ** secret_len;
    var hello_buf: [1024]u8 = undefined;
    const hello = try clientHelloPskBytes(.{}, psk, &hello_buf);
    const modes = try clientHelloExtension(hello, @intFromEnum(ExtType.psk_key_exchange_modes));
    hello[modes.body_offset + 1] = 0x00;

    var server = Tls13Handshake.initServerWithPsk(.{}, &[_]u8{}, psk);
    server.provideData(hello);
    try std.testing.expectError(error.UnsupportedPskKeyExchangeMode, server.step());
}

test "Tls13Handshake server rejects early_data without pre_shared_key" {
    var hello_buf: [1024]u8 = undefined;
    const base_hello = try clientHelloBytes(.{}, &hello_buf);
    const hello = try appendClientHelloRawExtension(
        &hello_buf,
        base_hello.len,
        @intFromEnum(ExtType.early_data),
        &[_]u8{},
    );

    var server = Tls13Handshake.initServer(.{}, &[_]u8{});
    server.provideData(hello);
    try std.testing.expectError(error.DecodeError, server.step());
}

test "Tls13Handshake server rejects malformed ClientHello PSK identity vector" {
    const psk = [_]u8{0xab} ** secret_len;
    var hello_buf: [1024]u8 = undefined;
    const hello = try clientHelloPskBytes(.{}, psk, &hello_buf);
    const psk_ext = try clientHelloExtension(hello, @intFromEnum(ExtType.pre_shared_key));
    writeU16(hello[psk_ext.body_offset + 2 ..][0..2], 0);

    var server = Tls13Handshake.initServerWithPsk(.{}, &[_]u8{}, psk);
    server.provideData(hello);
    try std.testing.expectError(error.DecodeError, server.step());
}

test "Tls13Handshake server rejects oversized ClientHello PSK identity" {
    const psk = [_]u8{0xab} ** secret_len;
    var hello_buf: [8192]u8 = undefined;
    const base_hello = try clientHelloPskBytes(.{}, psk, &hello_buf);
    const psk_ext = try clientHelloExtension(base_hello, @intFromEnum(ExtType.pre_shared_key));

    const identity_len_offset = psk_ext.body_offset + 2;
    const identity_len = readU16(hello_buf[identity_len_offset..]);
    const probe_server = Tls13Handshake.initServer(.{}, &[_]u8{});
    const oversized_len = probe_server.peer_psk_identity.len + 1;
    const extra_len = oversized_len - identity_len;
    if (base_hello.len + extra_len > hello_buf.len) return error.TestUnexpectedResult;
    const insert_offset = identity_len_offset + 2 + identity_len;
    std.mem.copyBackwards(
        u8,
        hello_buf[insert_offset + extra_len .. base_hello.len + extra_len],
        hello_buf[insert_offset..base_hello.len],
    );
    @memset(hello_buf[insert_offset..][0..extra_len], 0xee);

    writeU16(hello_buf[identity_len_offset..][0..2], @as(u16, @intCast(identity_len + extra_len)));
    const identities_len = readU16(hello_buf[psk_ext.body_offset..]);
    writeU16(hello_buf[psk_ext.body_offset..][0..2], @as(u16, @intCast(identities_len + extra_len)));
    writeU16(hello_buf[psk_ext.header_offset + 2 ..][0..2], @as(u16, @intCast(psk_ext.body_len + extra_len)));
    try setClientHelloBodyLen(&hello_buf, base_hello.len - 4 + extra_len);
    const extensions_len = readU16(hello_buf[psk_ext.extensions_len_offset..]);
    writeU16(hello_buf[psk_ext.extensions_len_offset..][0..2], @as(u16, @intCast(extensions_len + extra_len)));
    const hello = hello_buf[0 .. base_hello.len + extra_len];

    var server = Tls13Handshake.initServerWithPsk(.{}, &[_]u8{}, psk);
    server.provideData(hello);
    try std.testing.expectError(error.DecodeError, server.step());
}

test "Tls13Handshake server rejects mismatched PSK identity and binder counts" {
    const psk = [_]u8{0xab} ** secret_len;
    var hello_buf: [1024]u8 = undefined;
    const base_hello = try clientHelloPskBytes(.{}, psk, &hello_buf);
    const psk_ext = try clientHelloExtension(base_hello, @intFromEnum(ExtType.pre_shared_key));

    const identities_len = readU16(hello_buf[psk_ext.body_offset..]);
    const second_identity = [_]u8{
        0x00, 0x01, 0xaa,
        0x00, 0x00, 0x00,
        0x00,
    };
    const insert_offset = psk_ext.body_offset + 2 + identities_len;
    std.mem.copyBackwards(
        u8,
        hello_buf[insert_offset + second_identity.len .. base_hello.len + second_identity.len],
        hello_buf[insert_offset..base_hello.len],
    );
    @memcpy(hello_buf[insert_offset..][0..second_identity.len], &second_identity);

    writeU16(hello_buf[psk_ext.body_offset..][0..2], @as(u16, @intCast(identities_len + second_identity.len)));
    writeU16(hello_buf[psk_ext.header_offset + 2 ..][0..2], @as(u16, @intCast(psk_ext.body_len + second_identity.len)));
    try setClientHelloBodyLen(&hello_buf, base_hello.len - 4 + second_identity.len);
    const extensions_len = readU16(hello_buf[psk_ext.extensions_len_offset..]);
    writeU16(hello_buf[psk_ext.extensions_len_offset..][0..2], @as(u16, @intCast(extensions_len + second_identity.len)));
    const hello = hello_buf[0 .. base_hello.len + second_identity.len];

    var server = Tls13Handshake.initServerWithPsk(.{}, &[_]u8{}, psk);
    server.provideData(hello);
    try std.testing.expectError(error.DecodeError, server.step());
}

test "Tls13Handshake server rejects trailing ClientHello PSK binder bytes" {
    const psk = [_]u8{0xab} ** secret_len;
    var hello_buf: [1024]u8 = undefined;
    const base_hello = try clientHelloPskBytes(.{}, psk, &hello_buf);
    const psk_ext = try clientHelloExtension(base_hello, @intFromEnum(ExtType.pre_shared_key));

    const insert_offset = psk_ext.body_offset + psk_ext.body_len;
    std.mem.copyBackwards(u8, hello_buf[insert_offset + 1 .. base_hello.len + 1], hello_buf[insert_offset..base_hello.len]);
    hello_buf[insert_offset] = 0x00;
    writeU16(hello_buf[psk_ext.header_offset + 2 ..][0..2], @as(u16, @intCast(psk_ext.body_len + 1)));
    try setClientHelloBodyLen(&hello_buf, base_hello.len - 4 + 1);
    const extensions_len = readU16(hello_buf[psk_ext.extensions_len_offset..]);
    writeU16(hello_buf[psk_ext.extensions_len_offset..][0..2], @as(u16, @intCast(extensions_len + 1)));
    const hello = hello_buf[0 .. base_hello.len + 1];

    var server = Tls13Handshake.initServerWithPsk(.{}, &[_]u8{}, psk);
    server.provideData(hello);
    try std.testing.expectError(error.DecodeError, server.step());
}

test "Tls13Handshake server rejects oversized ClientHello transport parameters" {
    var hello_buf: [2048]u8 = undefined;
    const base_hello = try clientHelloBytes(.{}, &hello_buf);
    var peer_tp: [1025]u8 = undefined;
    @memset(&peer_tp, 0xaa);
    const hello = try appendClientHelloRawExtension(
        &hello_buf,
        base_hello.len,
        @intFromEnum(ExtType.quic_transport_parameters),
        &peer_tp,
    );

    var server = Tls13Handshake.initServer(.{}, &[_]u8{});
    server.provideData(hello);
    try std.testing.expectError(error.DecodeError, server.step());
}

test "Tls13Handshake server rejects invalid ClientHello legacy_version" {
    var hello_buf: [1024]u8 = undefined;
    const hello = try clientHelloBytes(.{}, &hello_buf);
    writeU16(hello[4..][0..2], 0x0301);

    var server = Tls13Handshake.initServer(.{}, &[_]u8{});
    server.provideData(hello);
    try std.testing.expectError(error.UnsupportedVersion, server.step());
}

test "Tls13Handshake server rejects non-empty ClientHello legacy_session_id" {
    var hello_buf: [1024]u8 = undefined;
    const base_hello = try clientHelloBytes(.{}, &hello_buf);
    const session_id_len_offset = 4 + 2 + 32;
    const insert_offset = session_id_len_offset + 1;
    std.mem.copyBackwards(
        u8,
        hello_buf[insert_offset + 1 .. base_hello.len + 1],
        hello_buf[insert_offset..base_hello.len],
    );
    hello_buf[session_id_len_offset] = 1;
    hello_buf[insert_offset] = 0xaa;
    try setClientHelloBodyLen(&hello_buf, base_hello.len + 1 - 4);
    const hello = hello_buf[0 .. base_hello.len + 1];

    var server = Tls13Handshake.initServer(.{}, &[_]u8{});
    server.provideData(hello);
    try std.testing.expectError(error.DecodeError, server.step());
}

test "Tls13Handshake server rejects malformed ClientHello cipher_suites length" {
    var hello_buf: [1024]u8 = undefined;
    const hello = try clientHelloBytes(.{}, &hello_buf);
    const body = hello[4..];
    const session_id_len_offset = 2 + 32;
    const cipher_suites_len_offset = 4 + session_id_len_offset + 1 + body[session_id_len_offset];
    writeU16(hello[cipher_suites_len_offset..][0..2], 1);

    var server = Tls13Handshake.initServer(.{}, &[_]u8{});
    server.provideData(hello);
    try std.testing.expectError(error.DecodeError, server.step());
}

test "Tls13Handshake server rejects empty ClientHello compression_methods" {
    var hello_buf: [1024]u8 = undefined;
    const hello = try clientHelloBytes(.{}, &hello_buf);
    const body = hello[4..];
    const session_id_len_offset = 2 + 32;
    const cipher_suites_len_offset = 4 + session_id_len_offset + 1 + body[session_id_len_offset];
    const compression_methods_len_offset = cipher_suites_len_offset + 2 + readU16(hello[cipher_suites_len_offset..]);
    hello[compression_methods_len_offset] = 0;

    var server = Tls13Handshake.initServer(.{}, &[_]u8{});
    server.provideData(hello);
    try std.testing.expectError(error.DecodeError, server.step());
}

test "Tls13Handshake server rejects non-null ClientHello compression method" {
    var hello_buf: [1024]u8 = undefined;
    const hello = try clientHelloBytes(.{}, &hello_buf);
    const body = hello[4..];
    const session_id_len_offset = 2 + 32;
    const cipher_suites_len_offset = 4 + session_id_len_offset + 1 + body[session_id_len_offset];
    const compression_methods_len_offset = cipher_suites_len_offset + 2 + readU16(hello[cipher_suites_len_offset..]);
    hello[compression_methods_len_offset + 1] = 1;

    var server = Tls13Handshake.initServer(.{}, &[_]u8{});
    server.provideData(hello);
    try std.testing.expectError(error.DecodeError, server.step());
}

test "Tls13Handshake server rejects ClientHello supported_groups without X25519" {
    var hello_buf: [1024]u8 = undefined;
    const hello = try clientHelloBytes(.{}, &hello_buf);
    const groups = try clientHelloExtension(hello, @intFromEnum(ExtType.supported_groups));
    writeU16(hello[groups.body_offset + 2 ..][0..2], 0x0017);

    var server = Tls13Handshake.initServer(.{}, &[_]u8{});
    server.provideData(hello);
    try std.testing.expectError(error.NoKeyShare, server.step());
}

test "Tls13Handshake server rejects missing signature_algorithms when sending a certificate" {
    var hello_buf: [1024]u8 = undefined;
    const hello = try clientHelloBytes(.{}, &hello_buf);
    const sig_algs = try clientHelloExtension(hello, @intFromEnum(ExtType.signature_algorithms));
    writeU16(hello[sig_algs.header_offset..][0..2], 0xaaaa);

    const cert_der = [_]u8{ 0x30, 0x03, 0x01 };
    var server = Tls13Handshake.initServer(.{
        .cert_chain_der = &.{&cert_der},
    }, &[_]u8{});
    server.provideData(hello);
    try std.testing.expectError(error.MissingExtension, server.step());
}

test "Tls13Handshake server rejects unsupported CertificateVerify signature scheme" {
    var hello_buf: [1024]u8 = undefined;
    const hello = try clientHelloBytes(.{}, &hello_buf);
    const sig_algs = try clientHelloExtension(hello, @intFromEnum(ExtType.signature_algorithms));
    writeU16(hello[sig_algs.body_offset + 2 ..][0..2], 0x0805);
    writeU16(hello[sig_algs.body_offset + 4 ..][0..2], 0x0806);
    writeU16(hello[sig_algs.body_offset + 6 ..][0..2], sig_rsa_pss_rsae_sha256);

    const cert_der = [_]u8{ 0x30, 0x03, 0x01 };
    var server = Tls13Handshake.initServer(.{
        .cert_chain_der = &.{&cert_der},
        .private_key_algorithm = .ecdsa_p256_sha256,
    }, &[_]u8{});
    server.provideData(hello);
    try std.testing.expectError(error.UnsupportedSignatureAlgorithm, server.step());
}

test "Tls13Handshake server rejects malformed ClientHello supported_versions length" {
    var hello_buf: [1024]u8 = undefined;
    const hello = try clientHelloBytes(.{}, &hello_buf);
    const versions = try clientHelloExtension(hello, @intFromEnum(ExtType.supported_versions));
    hello[versions.body_offset] = 3;

    var server = Tls13Handshake.initServer(.{}, &[_]u8{});
    server.provideData(hello);
    try std.testing.expectError(error.DecodeError, server.step());
}

test "Tls13Handshake server rejects malformed ClientHello key_share length" {
    var hello_buf: [1024]u8 = undefined;
    const hello = try clientHelloBytes(.{}, &hello_buf);
    const key_share = try clientHelloExtension(hello, @intFromEnum(ExtType.key_share));
    writeU16(hello[key_share.body_offset..][0..2], @as(u16, @intCast(key_share.body_len - 3)));

    var server = Tls13Handshake.initServer(.{}, &[_]u8{});
    server.provideData(hello);
    try std.testing.expectError(error.DecodeError, server.step());
}

test "Tls13Handshake server rejects malformed ClientHello ALPN length" {
    const alpn = [_][]const u8{"hq-interop"};
    var hello_buf: [1024]u8 = undefined;
    const hello = try clientHelloBytes(.{ .alpn = &alpn }, &hello_buf);
    const alpn_ext = try clientHelloExtension(hello, @intFromEnum(ExtType.alpn));
    writeU16(hello[alpn_ext.body_offset..][0..2], @as(u16, @intCast(alpn_ext.body_len - 1)));

    var server = Tls13Handshake.initServer(.{}, &[_]u8{});
    server.provideData(hello);
    try std.testing.expectError(error.DecodeError, server.step());
}

test "Tls13Handshake server accepts matching ClientHello SNI" {
    var client = Tls13Handshake.initClient(.{
        .server_name = "Example.COM",
    }, &[_]u8{});
    var server = Tls13Handshake.initServer(.{
        .server_name = "example.com",
    }, &[_]u8{});

    const client_hello_action = try client.step();
    try std.testing.expect(std.meta.activeTag(client_hello_action) == .send_data);

    server.provideData(client_hello_action.send_data.data);
    try std.testing.expect(std.meta.activeTag(try server.step()) == ._continue);
    try std.testing.expectEqualStrings("Example.COM", server.client_sni[0..server.client_sni_len]);
}

test "Tls13Handshake server rejects oversized ClientHello SNI host_name" {
    const long_name = "a" ** 257;
    var client = Tls13Handshake.initClient(.{
        .server_name = long_name,
    }, &[_]u8{});
    var server = Tls13Handshake.initServer(.{}, &[_]u8{});

    const client_hello_action = try client.step();
    try std.testing.expect(std.meta.activeTag(client_hello_action) == .send_data);

    server.provideData(client_hello_action.send_data.data);
    try std.testing.expectError(error.DecodeError, server.step());
}

test "Tls13Handshake server rejects missing ClientHello SNI when configured" {
    var client = Tls13Handshake.initClient(.{}, &[_]u8{});
    var server = Tls13Handshake.initServer(.{
        .server_name = "example.com",
    }, &[_]u8{});

    const client_hello_action = try client.step();
    try std.testing.expect(std.meta.activeTag(client_hello_action) == .send_data);

    server.provideData(client_hello_action.send_data.data);
    try std.testing.expectError(error.UnrecognizedName, server.step());
}

test "Tls13Handshake server rejects mismatched ClientHello SNI when configured" {
    var client = Tls13Handshake.initClient(.{
        .server_name = "other.example",
    }, &[_]u8{});
    var server = Tls13Handshake.initServer(.{
        .server_name = "example.com",
    }, &[_]u8{});

    const client_hello_action = try client.step();
    try std.testing.expect(std.meta.activeTag(client_hello_action) == .send_data);

    server.provideData(client_hello_action.send_data.data);
    try std.testing.expectError(error.UnrecognizedName, server.step());
}

test "Tls13Handshake client↔server loopback completes with matching secrets" {
    // Server ECDSA P-256 key pair (real private key for CertificateVerify).
    const seed = [_]u8{0x55} ** 32;
    const server_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const server_priv = server_kp.secret_key.bytes; // 32-byte P-256 scalar

    const alpn = [_][]const u8{"hq-interop"};
    const client_tp = [_]u8{ 0x01, 0x02, 0x03 };
    const server_tp = [_]u8{ 0xAA, 0xBB };
    const cert_der = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };

    var client = Tls13Handshake.initClient(.{
        .alpn = &alpn,
        .server_name = "example.com",
        .skip_cert_verify = true, // leaf cert is a dummy DER
    }, &client_tp);
    var server = Tls13Handshake.initServer(.{
        .alpn = &alpn,
        .cert_chain_der = &.{&cert_der},
        .private_key_bytes = &server_priv,
        .private_key_algorithm = .ecdsa_p256_sha256,
    }, &server_tp);

    // 1. Client emits ClientHello.
    const ch_action = try client.step();
    try std.testing.expect(std.meta.activeTag(ch_action) == .send_data);
    try std.testing.expectEqual(EncryptionLevel.initial, ch_action.send_data.level);
    const client_hello = ch_action.send_data.data;

    // 2. Server consumes ClientHello; collect ServerHello (initial) +
    //    EE/Certificate/CertificateVerify/Finished (handshake).
    server.provideData(client_hello);
    var srv_initial: [512]u8 = undefined;
    var srv_initial_len: usize = 0;
    var srv_hs: [4096]u8 = undefined;
    var srv_hs_len: usize = 0;
    var srv_hs_keys = false;
    var srv_app_keys = false;
    while (true) {
        const a = try server.step();
        switch (a) {
            .send_data => |sd| {
                if (sd.level == .initial) {
                    @memcpy(srv_initial[srv_initial_len..][0..sd.data.len], sd.data);
                    srv_initial_len += sd.data.len;
                } else {
                    @memcpy(srv_hs[srv_hs_len..][0..sd.data.len], sd.data);
                    srv_hs_len += sd.data.len;
                }
            },
            .install_keys => |ik| {
                if (ik.level == .handshake) srv_hs_keys = true;
                if (ik.level == .application) srv_app_keys = true;
            },
            .wait_for_data, .complete => break,
            ._continue => continue,
        }
    }
    try std.testing.expect(srv_initial_len > 0); // ServerHello
    try std.testing.expect(srv_hs_len > 0); // EE+Cert+CV+Finished
    try std.testing.expect(srv_hs_keys);
    try std.testing.expect(srv_app_keys);

    // 3. Client consumes ServerHello + handshake flight; emits client Finished.
    client.provideData(srv_initial[0..srv_initial_len]);
    client.provideData(srv_hs[0..srv_hs_len]);
    var cli_fin: [256]u8 = undefined;
    var cli_fin_len: usize = 0;
    var cli_hs_keys = false;
    var cli_app_keys = false;
    while (true) {
        const a = try client.step();
        switch (a) {
            .send_data => |sd| {
                @memcpy(cli_fin[cli_fin_len..][0..sd.data.len], sd.data);
                cli_fin_len += sd.data.len;
            },
            .install_keys => |ik| {
                if (ik.level == .handshake) cli_hs_keys = true;
                if (ik.level == .application) cli_app_keys = true;
            },
            .wait_for_data, .complete => break,
            ._continue => continue,
        }
    }
    try std.testing.expect(cli_hs_keys);
    try std.testing.expect(cli_app_keys);
    try std.testing.expectEqual(@as(usize, 36), cli_fin_len); // client Finished

    // 4. Server consumes client Finished → connected.
    server.provideData(cli_fin[0..cli_fin_len]);
    try std.testing.expect(std.meta.activeTag(try server.step()) == ._continue);
    try std.testing.expect(server.isComplete());

    // 5. Both complete; traffic secrets match (shared schedule).
    try std.testing.expect(client.isComplete());
    try std.testing.expectEqualSlices(u8, &client.key_schedule.client_handshake_traffic_secret, &server.key_schedule.client_handshake_traffic_secret);
    try std.testing.expectEqualSlices(u8, &client.key_schedule.server_handshake_traffic_secret, &server.key_schedule.server_handshake_traffic_secret);
    try std.testing.expectEqualSlices(u8, &client.key_schedule.client_app_traffic_secret, &server.key_schedule.client_app_traffic_secret);
    try std.testing.expectEqualSlices(u8, &client.key_schedule.server_app_traffic_secret, &server.key_schedule.server_app_traffic_secret);

    // 6. ALPN negotiated on both sides.
    try std.testing.expectEqualStrings("hq-interop", client.negotiated_alpn[0..client.negotiated_alpn_len]);
    try std.testing.expectEqualStrings("hq-interop", server.negotiated_alpn[0..server.negotiated_alpn_len]);

    // 7. Peer transport parameters crossed over.
    try std.testing.expectEqualSlices(u8, &server_tp, client.peer_tp[0..client.peer_tp_len]);
    try std.testing.expectEqualSlices(u8, &client_tp, server.peer_tp[0..server.peer_tp_len]);
}

// ─── Tests for certificate validity-period verification ─────────────

test "verifyServerCertificate surfaces unparseable certificates as BadCertificate" {
    const cert_der = @embedFile("testdata/test_leaf.der");
    var hs = Tls13Handshake.initClient(.{
        .skip_cert_verify = false,
        .now_sec = 0,
    }, &[_]u8{});
    @memcpy(hs.server_cert[0..cert_der.len], cert_der);
    hs.server_cert_len = cert_der.len;
    // test_leaf.der carries OIDs std.crypto.Certificate does not recognize;
    // verifyServerCertificate must surface parse failure as BadCertificate
    // rather than leaking the inner error.
    try std.testing.expectError(error.BadCertificate, hs.verifyServerCertificate());
}
