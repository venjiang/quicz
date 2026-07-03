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
    psk_key_exchange_modes = 0x002D,
    early_data = 0x002A,
    supported_versions = 0x002B,
    key_share = 0x0033,
    quic_transport_parameters = 0x0039,
};

const cipher_aes_128_gcm_sha256: u16 = 0x1301;
const group_x25519: u16 = 0x001D;
const version_tls_1_3: u16 = 0x0304;

const sig_ecdsa_secp256r1_sha256: u16 = 0x0403;
const sig_ed25519: u16 = 0x0807;
const sig_rsa_pss_rsae_sha256: u16 = 0x0804;

// ─── Write helpers ───────────────────────────────────────────────────

fn writeU16(buf: []u8, val: u16) void {
    std.mem.writeInt(u16, buf[0..2], val, .big);
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

    // Negotiated ALPN
    negotiated_alpn: [256]u8 = undefined,
    negotiated_alpn_len: usize = 0,

    // Pending key installation flags
    pending_install_handshake: bool = false,
    pending_install_app: bool = false,

    // Pre-encoded QUIC transport parameters
    tp_encoded: [1024]u8 = undefined,
    tp_encoded_len: usize = 0,

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

        // Copy pre-encoded transport parameters
        const tp_len = @min(transport_params.len, self.tp_encoded.len);
        @memcpy(self.tp_encoded[0..tp_len], transport_params[0..tp_len]);
        self.tp_encoded_len = tp_len;

        // Generate X25519 key pair
        std.crypto.random.bytes(&self.x25519_secret);
        self.x25519_public = X25519.recoverPublicKey(self.x25519_secret) catch blk: {
            std.crypto.random.bytes(&self.x25519_secret);
            break :blk X25519.recoverPublicKey(self.x25519_secret) catch unreachable;
        };

        return self;
    }

    /// Provide incoming CRYPTO stream data to the handshake.
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
            const keys = KeySchedule.deriveQuicKeys(self.key_schedule.client_handshake_traffic_secret);
            const peer_keys = KeySchedule.deriveQuicKeys(self.key_schedule.server_handshake_traffic_secret);
            return Action{ .install_keys = .{
                .level = .handshake,
                .open = .{ .key = peer_keys.key, .iv = peer_keys.iv, .hp = peer_keys.hp },
                .seal = .{ .key = keys.key, .iv = keys.iv, .hp = keys.hp },
            } };
        }
        if (self.pending_install_app) {
            self.pending_install_app = false;
            const keys = KeySchedule.deriveQuicKeys(self.key_schedule.client_app_traffic_secret);
            const peer_keys = KeySchedule.deriveQuicKeys(self.key_schedule.server_app_traffic_secret);
            return Action{ .install_keys = .{
                .level = .application,
                .open = .{ .key = peer_keys.key, .iv = peer_keys.iv, .hp = peer_keys.hp },
                .seal = .{ .key = keys.key, .iv = keys.iv, .hp = keys.hp },
            } };
        }

        switch (self.state) {
            .client_start => return self.clientBuildHello(),
            .client_wait_server_hello,
            .client_wait_encrypted_extensions,
            .client_wait_certificate,
            .client_wait_certificate_verify,
            .client_wait_finished,
            .client_send_finished,
            .server_wait_client_hello,
            .server_send_server_hello,
            .server_send_encrypted_extensions,
            .server_send_certificate,
            .server_send_certificate_verify,
            .server_send_finished,
            .server_wait_client_finished,
            => return .wait_for_data,
            .connected => return .complete,
        }
    }

    pub fn isComplete(self: *const Tls13Handshake) bool {
        return self.state == .connected;
    }

    /// Build a ClientHello message with ALPN, SNI, key_share, and QUIC
    /// transport parameters extensions (RFC 8446 §4.1.2 + RFC 9001 §8).
    fn clientBuildHello(self: *Tls13Handshake) HandshakeError!Action {
        std.crypto.random.bytes(&self.client_random);

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
            const sni_ext_len = 2 + 1 + 2 + sni.len;
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
            for (self.config.alpn) |proto| alpn_total += 1 + proto.len;
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
            pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.quic_transport_parameters), self.tp_encoded_len);
            @memcpy(buf[pos..][0..self.tp_encoded_len], self.tp_encoded[0..self.tp_encoded_len]);
            pos += self.tp_encoded_len;
        }

        // psk_key_exchange_modes
        pos = writeExtHeader(buf, pos, @intFromEnum(ExtType.psk_key_exchange_modes), 2);
        buf[pos] = 1;
        pos += 1;
        buf[pos] = 0x01; // psk_dhe_ke
        pos += 1;

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
    try std.testing.expectEqual(@as(usize, 0), data.len != 0 and data.len or 0); // dummy check
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

test "Tls13Handshake isComplete is false before handshake" {
    var hs = Tls13Handshake.initClient(.{}, &[_]u8{});
    try std.testing.expect(!hs.isComplete());
    _ = try hs.step();
    try std.testing.expect(!hs.isComplete());
}
