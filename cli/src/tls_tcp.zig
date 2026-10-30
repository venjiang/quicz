//! TLS 1.3 server over TCP (RFC 8446) for the quicz CLI.
//!
//! The QUIC code path carries TLS handshake messages in CRYPTO frames and
//! derives RFC 9001 packet-protection keys, so it cannot serve a browser over
//! TCP. This module reuses the standard key schedule (`quicz.tls13.KeySchedule`)
//! but adds the TLS record layer and `tls13 key`/`tls13 iv` derivation that
//! plain HTTPS needs.
//!
//! Supported: TLS_AES_128_GCM_SHA256, X25519, ECDSA P-256 certificates.

const std = @import("std");
const crypto = std.crypto;
const quicz = @import("quicz");

const tls13 = quicz.tls13;

const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const Sha256 = crypto.hash.sha2.Sha256;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const X25519 = crypto.dh.X25519;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;

const key_len: usize = 16;
const iv_len: usize = 12;
const tag_len: usize = 16;
const record_max: usize = 16384;

const ContentType = struct {
    const change_cipher_spec: u8 = 20;
    const alert: u8 = 21;
    const handshake: u8 = 22;
    const application_data: u8 = 23;
};

test "write fragments application data into bounded TLS records" {
    const payload: [record_max * 2 + 17]u8 = @splat(0x42);
    var ciphertext: [payload.len + 3 * (5 + tag_len + 1)]u8 = undefined;
    var out = std.Io.Writer.fixed(&ciphertext);
    var in = std.Io.Reader.fixed(&.{});
    var stream: TlsStream = .{
        .in = &in,
        .out = &out,
        .write_key = @splat(1),
        .write_iv = @splat(2),
        .read_key = @splat(3),
        .read_iv = @splat(4),
    };
    try stream.write(&payload);
    var records = std.Io.Reader.fixed(out.buffered());
    var record_buf: [record_max + 256]u8 = undefined;
    var plain: [record_max + 1]u8 = undefined;
    var sequence: u64 = 0;
    var offset: usize = 0;
    while (offset < payload.len) {
        const record = try readRecord(&records, &record_buf);
        const decoded = try openRecord(record.payload, &plain, stream.write_key, stream.write_iv, &sequence);
        try std.testing.expectEqual(ContentType.application_data, decoded.content_type);
        try std.testing.expect(decoded.data.len <= record_max);
        try std.testing.expectEqualSlices(u8, payload[offset..][0..decoded.data.len], decoded.data);
        offset += decoded.data.len;
    }
    try std.testing.expectEqual(@as(u64, 3), sequence);
    try std.testing.expectEqual(sequence, stream.write_seq);
}

test "read accepts encrypted close notify as EOF" {
    var ciphertext: [64]u8 = undefined;
    const secret: [16]u8 = @splat(1);
    const iv: [12]u8 = @splat(2);
    var sequence: u64 = 0;
    const len = sealRecord(&ciphertext, ContentType.alert, &.{ 1, 0 }, secret, iv, &sequence);
    var in = std.Io.Reader.fixed(ciphertext[0..len]);
    var out = std.Io.Writer.fixed(&.{});
    var stream: TlsStream = .{
        .in = &in,
        .out = &out,
        .write_key = secret,
        .write_iv = iv,
        .read_key = secret,
        .read_iv = iv,
    };
    var plaintext: [32]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try stream.read(&plaintext));
    try std.testing.expectEqual(@as(usize, 0), try stream.read(&plaintext));
    try std.testing.expect(!stream.write_closed);
}

const HandshakeType = struct {
    const client_hello: u8 = 1;
    const server_hello: u8 = 2;
    const encrypted_extensions: u8 = 8;
    const certificate: u8 = 11;
    const certificate_verify: u8 = 15;
    const finished: u8 = 20;
};

const ExtType = struct {
    const supported_versions: u16 = 43;
    const key_share: u16 = 51;
    const alpn: u16 = 16;
};

const version_tls_1_3: u16 = 0x0304;
const group_x25519: u16 = 0x001d;
const cipher_aes_128_gcm_sha256: u16 = 0x1301;
const sig_ecdsa_p256_sha256: u16 = 0x0403;

pub const Config = struct {
    cert_der: []const u8,
    private_key: *const [32]u8,
    alpn: []const []const u8 = &.{"http/1.1"},
};

fn readU16(buf: []const u8) u16 {
    return std.mem.readInt(u16, buf[0..2], .big);
}

fn writeU16(buf: []u8, value: u16) void {
    std.mem.writeInt(u16, buf[0..2], value, .big);
}

fn deriveTlsKey(traffic_secret: [32]u8) [16]u8 {
    return std.crypto.tls.hkdfExpandLabel(HkdfSha256, traffic_secret, "key", &.{}, key_len);
}

fn deriveTlsIv(traffic_secret: [32]u8) [12]u8 {
    return std.crypto.tls.hkdfExpandLabel(HkdfSha256, traffic_secret, "iv", &.{}, iv_len);
}

fn nonceFor(iv: [12]u8, seq: u64) [12]u8 {
    var nonce = iv;
    var seq_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_be, seq, .big);
    for (0..8) |i| nonce[4 + i] ^= seq_be[i];
    return nonce;
}

fn writeRecordHeader(out: []u8, content_type: u8, len: usize) void {
    out[0] = content_type;
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = @intCast((len >> 8) & 0xff);
    out[4] = @intCast(len & 0xff);
}

/// Encrypt one TLS record. `out` must hold `5 + payload.len + tag_len + 1`.
/// The encrypted outer content type is always application_data (RFC 8446 §5.2).
fn sealRecord(
    out: []u8,
    inner_content_type: u8,
    payload: []const u8,
    key: [16]u8,
    iv: [12]u8,
    seq: *u64,
) usize {
    const plaintext_len = payload.len + 1;
    const cipher_len = plaintext_len + tag_len;
    writeRecordHeader(out, ContentType.application_data, cipher_len);
    var aad: [5]u8 = undefined;
    writeRecordHeader(&aad, ContentType.application_data, cipher_len);

    @memcpy(out[5..][0..payload.len], payload);
    out[5 + payload.len] = inner_content_type;
    var tag: [tag_len]u8 = undefined;
    Aes128Gcm.encrypt(
        out[5 .. 5 + plaintext_len],
        &tag,
        out[5 .. 5 + plaintext_len],
        &aad,
        nonceFor(iv, seq.*),
        key,
    );
    @memcpy(out[5 + plaintext_len .. 5 + cipher_len], &tag);
    seq.* += 1;
    return 5 + cipher_len;
}

const Decrypted = struct {
    content_type: u8,
    data: []const u8,
};

/// Decrypt one TLS record payload. `out` must hold `payload.len - tag_len` bytes.
fn openRecord(
    payload: []const u8,
    out: []u8,
    key: [16]u8,
    iv: [12]u8,
    seq: *u64,
) !Decrypted {
    if (payload.len < tag_len + 1) return error.DecryptionFailed;
    const cipher_len = payload.len;
    const plaintext_len = cipher_len - tag_len;
    // The limit includes content type and padding (RFC 8446 section 5.4).
    if (plaintext_len > record_max + 1) return error.RecordOversize;
    var aad: [5]u8 = undefined;
    writeRecordHeader(&aad, ContentType.application_data, cipher_len);
    var tag: [tag_len]u8 = undefined;
    @memcpy(&tag, payload[plaintext_len..]);
    Aes128Gcm.decrypt(
        out[0..plaintext_len],
        payload[0..plaintext_len],
        tag,
        &aad,
        nonceFor(iv, seq.*),
        key,
    ) catch return error.DecryptionFailed;
    seq.* += 1;

    // Inner content type is the last non-zero byte; trailing zero bytes are
    // padding (RFC 8446 §5.4).
    var inner_len = plaintext_len;
    while (inner_len > 0 and out[inner_len - 1] == 0) inner_len -= 1;
    if (inner_len == 0) return error.DecryptionFailed;
    const content_type = out[inner_len - 1];
    return .{ .content_type = content_type, .data = out[0 .. inner_len - 1] };
}

fn readN(in: *std.Io.Reader, buf: []u8) !void {
    try in.readSliceAll(buf);
}

const Record = struct {
    content_type: u8,
    payload: []const u8,
};

/// Read one TLS record (header + payload) into `buf`.
fn readRecord(in: *std.Io.Reader, buf: []u8) !Record {
    var header: [5]u8 = undefined;
    try readN(in, &header);
    const len = (@as(usize, header[3]) << 8) | header[4];
    if (len > buf.len) return error.RecordOversize;
    try readN(in, buf[0..len]);
    return .{ .content_type = header[0], .payload = buf[0..len] };
}

fn sendRecord(out: *std.Io.Writer, content_type: u8, payload: []const u8) !void {
    var header: [5]u8 = undefined;
    writeRecordHeader(&header, content_type, payload.len);
    try out.writeAll(&header);
    try out.writeAll(payload);
    try out.flush();
}

const ClientHelloInfo = struct {
    session_id: []const u8,
    key_share: ?[32]u8,
    tls13_supported: bool,
    alpn_list: ?[]const u8,
};

fn findExtension(msg: []const u8, ext_type: u16) ?[]const u8 {
    if (msg.len < 4) return null;
    const body_len = (@as(usize, msg[1]) << 16) |
        (@as(usize, msg[2]) << 8) |
        @as(usize, msg[3]);
    if (body_len != msg.len - 4) return null;

    var pos: usize = 4;
    if (pos + 32 + 1 > msg.len) return null;
    pos += 2 + 32; // legacy_version + random
    if (pos + 1 > msg.len) return null;
    const sid_len = msg[pos];
    pos += 1;
    if (pos + sid_len > msg.len) return null;
    pos += sid_len;
    if (pos + 2 > msg.len) return null;
    const cipher_len = readU16(msg[pos..]);
    pos += 2 + cipher_len;
    if (pos + 1 > msg.len) return null;
    const comp_len = msg[pos];
    pos += 1 + comp_len;
    if (pos + 2 > msg.len) return null;
    const ext_len = readU16(msg[pos..]);
    pos += 2;
    const ext_end = pos + ext_len;
    if (ext_end > msg.len) return null;

    while (pos + 4 <= ext_end) {
        const current_type = readU16(msg[pos..]);
        const current_len = readU16(msg[pos + 2 ..]);
        pos += 4;
        if (pos + current_len > ext_end) return null;
        if (current_type == ext_type) return msg[pos .. pos + current_len];
        pos += current_len;
    }
    return null;
}

fn parseClientHello(msg: []const u8) !ClientHelloInfo {
    if (msg.len < 4 or msg[0] != HandshakeType.client_hello) return error.UnexpectedMessage;
    var pos: usize = 4;
    if (pos + 2 + 32 + 1 > msg.len) return error.DecodeError;
    pos += 2 + 32; // legacy_version + random
    const sid_len = msg[pos];
    pos += 1;
    if (pos + sid_len > msg.len) return error.DecodeError;
    const session_id = msg[pos .. pos + sid_len];
    pos += sid_len;
    if (pos + 2 > msg.len) return error.DecodeError;
    const cipher_len = readU16(msg[pos..]);
    pos += 2 + cipher_len;
    if (pos + 1 > msg.len) return error.DecodeError;
    pos += 1 + msg[pos];
    if (pos + 2 > msg.len) return error.DecodeError;
    const ext_len = readU16(msg[pos..]);
    pos += 2;
    if (pos + ext_len > msg.len) return error.DecodeError;
    const extensions = msg[pos .. pos + ext_len];

    var key_share: ?[32]u8 = null;
    var tls13_supported = false;
    if (findExtension(msg, ExtType.supported_versions)) |data| {
        // ClientHello uses a one-byte vector length for supported_versions.
        if (data.len >= 3 and data[0] + 1 == data.len) {
            var i: usize = 1;
            while (i + 2 <= data.len) : (i += 2) {
                if (readU16(data[i..]) == version_tls_1_3) tls13_supported = true;
            }
        }
    }
    if (findExtension(msg, ExtType.key_share)) |data| {
        if (data.len >= 2) {
            const list_len = readU16(data[0..2]);
            var i: usize = 2;
            const list_end = 2 + list_len;
            while (i + 4 <= list_end and i + 4 <= data.len) {
                const group = readU16(data[i..]);
                const klen = readU16(data[i + 2 ..]);
                if (group == group_x25519 and klen == 32 and i + 4 + 32 <= data.len) {
                    key_share = data[i + 4 ..][0..32].*;
                    break;
                }
                i += 4 + klen;
            }
        }
    }
    const alpn_list = findExtension(msg, ExtType.alpn);
    _ = extensions;
    return .{
        .session_id = session_id,
        .key_share = key_share,
        .tls13_supported = tls13_supported,
        .alpn_list = alpn_list,
    };
}

fn buildServerHello(
    buf: []u8,
    server_random: [32]u8,
    server_public: [32]u8,
    session_id: []const u8,
) usize {
    var p: usize = 0;
    buf[p] = HandshakeType.server_hello;
    p += 1;
    p += 3; // length placeholder
    buf[p] = 0x03;
    buf[p + 1] = 0x03;
    p += 2;
    @memcpy(buf[p..][0..32], &server_random);
    p += 32;
    buf[p] = @intCast(session_id.len);
    p += 1;
    @memcpy(buf[p..][0..session_id.len], session_id);
    p += session_id.len;
    writeU16(buf[p..], cipher_aes_128_gcm_sha256);
    p += 2;
    buf[p] = 0;
    p += 1;
    const ext_start = p;
    p += 2;
    p = writeExtHeader(buf, p, ExtType.supported_versions, 2);
    writeU16(buf[p..], version_tls_1_3);
    p += 2;
    p = writeExtHeader(buf, p, ExtType.key_share, 2 + 2 + 32);
    writeU16(buf[p..], group_x25519);
    p += 2;
    writeU16(buf[p..], 32);
    p += 2;
    @memcpy(buf[p..][0..32], &server_public);
    p += 32;
    const ext_len = p - ext_start - 2;
    writeU16(buf[ext_start..], @intCast(ext_len));
    const msg_len = p - 4;
    buf[1] = @intCast((msg_len >> 16) & 0xff);
    buf[2] = @intCast((msg_len >> 8) & 0xff);
    buf[3] = @intCast(msg_len & 0xff);
    return p;
}

fn writeExtHeader(buf: []u8, pos: usize, ext_type: u16, len: usize) usize {
    writeU16(buf[pos..], ext_type);
    writeU16(buf[pos + 2 ..], @intCast(len));
    return pos + 4;
}

fn buildEncryptedExtensions(buf: []u8, alpn: ?[]const u8) usize {
    var p: usize = 0;
    buf[p] = HandshakeType.encrypted_extensions;
    p += 1;
    p += 3; // length placeholder
    const ext_start = p;
    p += 2; // extensions length placeholder
    if (alpn) |proto| {
        p = writeExtHeader(buf, p, ExtType.alpn, 2 + 1 + proto.len);
        writeU16(buf[p..], @intCast(1 + proto.len));
        p += 2;
        buf[p] = @intCast(proto.len);
        p += 1;
        @memcpy(buf[p..][0..proto.len], proto);
        p += proto.len;
    }
    const ext_len = p - ext_start - 2;
    writeU16(buf[ext_start..], @intCast(ext_len));
    const msg_len = p - 4;
    buf[1] = @intCast((msg_len >> 16) & 0xff);
    buf[2] = @intCast((msg_len >> 8) & 0xff);
    buf[3] = @intCast(msg_len & 0xff);
    return p;
}

fn negotiateAlpn(offered: []const u8, config_alpn: []const []const u8) ?[]const u8 {
    if (offered.len < 2) return null;
    const list_len = readU16(offered[0..2]);
    var i: usize = 2;
    const list_end = 2 + list_len;
    if (list_end > offered.len) return null;
    while (i < list_end) {
        const proto_len = offered[i];
        i += 1;
        if (i + proto_len > list_end) return null;
        const proto = offered[i .. i + proto_len];
        for (config_alpn) |wanted| {
            if (std.mem.eql(u8, proto, wanted)) return proto;
        }
        i += proto_len;
    }
    return null;
}

pub const TlsStream = struct {
    in: *std.Io.Reader,
    out: *std.Io.Writer,
    write_key: [16]u8,
    write_iv: [12]u8,
    write_seq: u64 = 0,
    // Record or I/O failure also terminates output, without a graceful alert.
    write_closed: bool = false,
    read_key: [16]u8,
    read_iv: [12]u8,
    read_seq: u64 = 0,
    read_closed: bool = false,
    dec_buf: [record_max + 256]u8 = undefined,
    dec_start: usize = 0,
    dec_end: usize = 0,

    pub fn handshake(in: *std.Io.Reader, out: *std.Io.Writer, config: Config) !TlsStream {
        var transcript = tls13.TranscriptHash.init();
        var recv_buf: [record_max]u8 = undefined;

        // 1. ClientHello (plaintext handshake record).
        const ch_rec = try readRecord(in, &recv_buf);
        if (ch_rec.content_type != ContentType.handshake) return error.UnexpectedMessage;
        const ch_msg = ch_rec.payload;
        const ch = try parseClientHello(ch_msg);
        if (!ch.tls13_supported) return error.UnsupportedVersion;
        const client_key = ch.key_share orelse return error.NoKeyShare;
        transcript.update(ch_msg);

        // 2. X25519 key exchange.
        var x25519_secret: [32]u8 = undefined;
        tls13.secureRandomBytes(&x25519_secret);
        const x25519_public = X25519.recoverPublicKey(x25519_secret);
        const shared_secret = try X25519.scalarmult(x25519_secret, client_key);

        // 3. ServerHello (plaintext).
        var sh_buf: [512]u8 = undefined;
        var server_random: [32]u8 = undefined;
        tls13.secureRandomBytes(&server_random);
        const sh_msg_len = buildServerHello(&sh_buf, server_random, x25519_public, ch.session_id);
        const sh_msg = sh_buf[0..sh_msg_len];
        transcript.update(sh_msg);
        try sendRecord(out, ContentType.handshake, sh_msg);
        try sendRecord(out, ContentType.change_cipher_spec, &[_]u8{1});

        // 4. Derive handshake traffic secrets and record keys.
        var ks = tls13.KeySchedule.init();
        const transcript_after_sh = transcript.current();
        ks.deriveHandshakeSecrets(&shared_secret, transcript_after_sh);
        const server_hs_key = deriveTlsKey(ks.server_handshake_traffic_secret);
        const server_hs_iv = deriveTlsIv(ks.server_handshake_traffic_secret);
        const client_hs_key = deriveTlsKey(ks.client_handshake_traffic_secret);
        const client_hs_iv = deriveTlsIv(ks.client_handshake_traffic_secret);

        var server_hs_seq: u64 = 0;

        // 5. EncryptedExtensions (no QUIC transport parameters over TCP).
        const negotiated_alpn = if (ch.alpn_list) |offered|
            negotiateAlpn(offered, config.alpn)
        else
            null;
        var ee_buf: [256]u8 = undefined;
        const ee_len = buildEncryptedExtensions(&ee_buf, negotiated_alpn);
        const ee_msg = ee_buf[0..ee_len];
        transcript.update(ee_msg);
        var rec: [record_max + 128]u8 = undefined;
        const ee_rec_len = sealRecord(&rec, ContentType.handshake, ee_msg, server_hs_key, server_hs_iv, &server_hs_seq);
        try out.writeAll(rec[0..ee_rec_len]);
        try out.flush();

        // 6. Certificate.
        var cert_buf: [record_max]u8 = undefined;
        const cert_len = tls13.buildCertificate(&cert_buf, config.cert_der);
        const cert_msg = cert_buf[0..cert_len];
        transcript.update(cert_msg);
        const cert_rec_len = sealRecord(&rec, ContentType.handshake, cert_msg, server_hs_key, server_hs_iv, &server_hs_seq);
        try out.writeAll(rec[0..cert_rec_len]);
        try out.flush();

        // 7. CertificateVerify (ECDSA P-256).
        var cv_buf: [512]u8 = undefined;
        const signed_content = tls13.certVerifySignedContent(transcript.current());
        const sk = try EcdsaP256Sha256.SecretKey.fromBytes(config.private_key.*);
        const kp = try EcdsaP256Sha256.KeyPair.fromSecretKey(sk);
        var noise: [EcdsaP256Sha256.noise_length]u8 = undefined;
        tls13.secureRandomBytes(&noise);
        const ecdsa_sig = try EcdsaP256Sha256.KeyPair.sign(kp, &signed_content, noise);
        var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
        const der_sig = ecdsa_sig.toDer(&der_buf);
        const cv_len = tls13.buildCertificateVerify(&cv_buf, sig_ecdsa_p256_sha256, der_sig);
        const cv_msg = cv_buf[0..cv_len];
        transcript.update(cv_msg);
        const cv_rec_len = sealRecord(&rec, ContentType.handshake, cv_msg, server_hs_key, server_hs_iv, &server_hs_seq);
        try out.writeAll(rec[0..cv_rec_len]);
        try out.flush();

        // 8. Finished + derive application secrets.
        const server_finished_vd = tls13.KeySchedule.computeFinishedVerifyData(
            ks.server_handshake_traffic_secret,
            transcript.current(),
        );
        var fin_msg: [36]u8 = undefined;
        fin_msg[0] = HandshakeType.finished;
        fin_msg[1] = 0;
        fin_msg[2] = 0;
        fin_msg[3] = 32;
        @memcpy(fin_msg[4..36], &server_finished_vd);
        transcript.update(&fin_msg);
        const transcript_after_sf = transcript.current();
        ks.deriveAppSecrets(transcript_after_sf);
        const fin_rec_len = sealRecord(&rec, ContentType.handshake, &fin_msg, server_hs_key, server_hs_iv, &server_hs_seq);
        try out.writeAll(rec[0..fin_rec_len]);
        try out.flush();

        // 9. Client Finished (encrypted in an application_data record).
        var client_hs_seq: u64 = 0;
        var client_finished_ok = false;
        var dec_buf2: [record_max]u8 = undefined;
        while (!client_finished_ok) {
            const crec = try readRecord(in, &recv_buf);
            if (crec.content_type == ContentType.change_cipher_spec) continue;
            if (crec.content_type != ContentType.application_data) return error.UnexpectedMessage;
            const dec = try openRecord(crec.payload, &dec_buf2, client_hs_key, client_hs_iv, &client_hs_seq);
            if (dec.content_type != ContentType.handshake) return error.UnexpectedMessage;
            if (dec.data.len < 4 or dec.data[0] != HandshakeType.finished) return error.UnexpectedMessage;
            if (dec.data.len < 36) return error.BadFinished;
            const expected_vd = tls13.KeySchedule.computeFinishedVerifyData(
                ks.client_handshake_traffic_secret,
                transcript.current(),
            );
            if (!crypto.timing_safe.eql([32]u8, dec.data[4..36].*, expected_vd)) return error.BadFinished;
            transcript.update(dec.data);
            client_finished_ok = true;
        }

        const app_write_key = deriveTlsKey(ks.server_app_traffic_secret);
        const app_write_iv = deriveTlsIv(ks.server_app_traffic_secret);
        const app_read_key = deriveTlsKey(ks.client_app_traffic_secret);
        const app_read_iv = deriveTlsIv(ks.client_app_traffic_secret);

        return .{
            .in = in,
            .out = out,
            .write_key = app_write_key,
            .write_iv = app_write_iv,
            .read_key = app_read_key,
            .read_iv = app_read_iv,
        };
    }

    /// Read decrypted application data. Peer close_notify returns 0.
    /// Record and I/O errors terminate output and propagate unchanged.
    pub fn read(self: *TlsStream, buf: []u8) !usize {
        if (self.read_closed) return 0;
        errdefer self.write_closed = true;
        if (self.dec_start < self.dec_end) {
            const available = self.dec_end - self.dec_start;
            const n = @min(available, buf.len);
            @memcpy(buf[0..n], self.dec_buf[self.dec_start .. self.dec_start + n]);
            self.dec_start += n;
            return n;
        }

        var header: [5]u8 = undefined;
        try readN(self.in, &header);
        const len = (@as(usize, header[3]) << 8) | header[4];
        if (len > self.dec_buf.len) return error.RecordOversize;
        try readN(self.in, self.dec_buf[0..len]);
        if (header[0] == ContentType.application_data) {
            var plain: [record_max + 1]u8 = undefined;
            const dec = try openRecord(self.dec_buf[0..len], &plain, self.read_key, self.read_iv, &self.read_seq);
            if (dec.content_type == ContentType.alert) {
                if (dec.data.len != 2 or dec.data[1] != 0) return error.TlsAlert;
                self.read_closed = true;
                return 0;
            }
            if (dec.content_type != ContentType.application_data) return error.UnexpectedMessage;
            const n = @min(dec.data.len, buf.len);
            @memcpy(buf[0..n], dec.data[0..n]);
            if (n < dec.data.len) {
                @memcpy(self.dec_buf[0 .. dec.data.len - n], dec.data[n..]);
                self.dec_start = 0;
                self.dec_end = dec.data.len - n;
            }
            return n;
        }
        if (header[0] == ContentType.alert) {
            return error.TlsAlert;
        }
        return error.UnexpectedMessage;
    }

    /// Write bounded application records. I/O errors terminate output.
    pub fn write(self: *TlsStream, data: []const u8) !void {
        if (self.write_closed) return error.StreamClosed;
        errdefer self.write_closed = true;
        var rec: [record_max + 64]u8 = undefined;
        var offset: usize = 0;
        while (offset < data.len) {
            const count = @min(record_max, data.len - offset);
            const n = sealRecord(&rec, ContentType.application_data, data[offset..][0..count], self.write_key, self.write_iv, &self.write_seq);
            try self.out.writeAll(rec[0..n]);
            offset += count;
        }
        try self.out.flush();
    }

    /// Send close_notify unless output already ended or failed. Repeated calls do not send another alert.
    pub fn end(self: *TlsStream) !void {
        if (self.write_closed) return;
        self.write_closed = true;
        var rec: [64]u8 = undefined;
        const n = sealRecord(&rec, ContentType.alert, &.{ 1, 0 }, self.write_key, self.write_iv, &self.write_seq);
        try self.out.writeAll(rec[0..n]);
        try self.out.flush();
    }
};

test "read accepts a full sized application record" {
    const payload: [record_max]u8 = @splat(0x42);
    var ciphertext: [record_max + 64]u8 = undefined;
    const secret: [16]u8 = @splat(1);
    const iv: [12]u8 = @splat(2);
    var sequence: u64 = 0;
    const len = sealRecord(&ciphertext, ContentType.application_data, &payload, secret, iv, &sequence);
    var in = std.Io.Reader.fixed(ciphertext[0..len]);
    var out = std.Io.Writer.fixed(&.{});
    var stream: TlsStream = .{ .in = &in, .out = &out, .write_key = secret, .write_iv = iv, .read_key = secret, .read_iv = iv };
    var plaintext: [record_max]u8 = undefined;
    try std.testing.expectEqual(record_max, try stream.read(&plaintext));
    try std.testing.expectEqualSlices(u8, &payload, &plaintext);
}

test "read accepts padding within the TLSInnerPlaintext limit" {
    const content_len = record_max - 239;
    var padded: [record_max]u8 = @splat(0);
    @memset(padded[0..content_len], 0x42);
    padded[content_len] = ContentType.application_data;
    var ciphertext: [record_max + 256 + 5]u8 = undefined;
    const secret: [16]u8 = @splat(1);
    const iv: [12]u8 = @splat(2);
    var sequence: u64 = 0;
    // The embedded type precedes padding, including the final zero from sealRecord.
    const len = sealRecord(&ciphertext, 0, &padded, secret, iv, &sequence);
    var in = std.Io.Reader.fixed(ciphertext[0..len]);
    var out = std.Io.Writer.fixed(&.{});
    var stream: TlsStream = .{ .in = &in, .out = &out, .write_key = secret, .write_iv = iv, .read_key = secret, .read_iv = iv };
    var plaintext: [record_max]u8 = undefined;
    try std.testing.expectEqual(content_len, try stream.read(&plaintext));
    try std.testing.expect(std.mem.allEqual(u8, plaintext[0..content_len], 0x42));
}

test "read rejects a TLSInnerPlaintext that exceeds the limit through padding" {
    var padded: [record_max + 239]u8 = @splat(0);
    @memset(padded[0..record_max], 0x42);
    padded[record_max] = ContentType.application_data;
    var ciphertext: [record_max + 256 + 5]u8 = undefined;
    const secret: [16]u8 = @splat(1);
    const iv: [12]u8 = @splat(2);
    var sequence: u64 = 0;
    const len = sealRecord(&ciphertext, 0, &padded, secret, iv, &sequence);
    var in = std.Io.Reader.fixed(ciphertext[0..len]);
    var out = std.Io.Writer.fixed(&.{});
    var stream: TlsStream = .{ .in = &in, .out = &out, .write_key = secret, .write_iv = iv, .read_key = secret, .read_iv = iv };
    var plaintext: [record_max]u8 = undefined;
    try std.testing.expectError(error.RecordOversize, stream.read(&plaintext));
    try stream.end();
    try std.testing.expectEqual(@as(u64, 0), stream.write_seq);
    try std.testing.expectError(error.StreamClosed, stream.write("late"));
}

test "fatal read errors suppress close notify and later writes" {
    const Failure = enum { authentication, record_size, alert, content_type, truncated };
    for (std.enums.values(Failure)) |failure| {
        var ciphertext: [128]u8 = undefined;
        const secret: [16]u8 = @splat(1);
        const iv: [12]u8 = @splat(2);
        var sequence: u64 = 0;
        var len: usize = 0;
        const expected: anyerror = switch (failure) {
            .authentication => blk: {
                len = sealRecord(&ciphertext, ContentType.application_data, "request", secret, iv, &sequence);
                ciphertext[len - 1] ^= 1;
                break :blk error.DecryptionFailed;
            },
            .record_size => blk: {
                writeRecordHeader(&ciphertext, ContentType.application_data, record_max + 257);
                len = 5;
                break :blk error.RecordOversize;
            },
            .alert => blk: {
                len = sealRecord(&ciphertext, ContentType.alert, &.{ 2, 20 }, secret, iv, &sequence);
                break :blk error.TlsAlert;
            },
            .content_type => blk: {
                len = sealRecord(&ciphertext, ContentType.handshake, &.{1}, secret, iv, &sequence);
                break :blk error.UnexpectedMessage;
            },
            .truncated => blk: {
                ciphertext[0] = ContentType.application_data;
                len = 1;
                break :blk error.EndOfStream;
            },
        };
        var in = std.Io.Reader.fixed(ciphertext[0..len]);
        var reply: [128]u8 = undefined;
        var out = std.Io.Writer.fixed(&reply);
        var stream: TlsStream = .{ .in = &in, .out = &out, .write_key = secret, .write_iv = iv, .read_key = secret, .read_iv = iv };
        var plaintext: [128]u8 = undefined;
        try std.testing.expectError(expected, stream.read(&plaintext));
        try std.testing.expect(stream.write_closed);
        try stream.end();
        try stream.end();
        try std.testing.expectEqual(@as(usize, 0), out.end);
        try std.testing.expectEqual(@as(u64, 0), stream.write_seq);
        try std.testing.expectError(error.StreamClosed, stream.write("late"));
    }
}

test "failed application write or flush suppresses close notify and output retries" {
    const Sink = struct {
        writer: std.Io.Writer = .{ .buffer = &.{}, .vtable = &.{ .drain = drain } },
        calls: usize = 0,

        fn drain(writer: *std.Io.Writer, _: []const []const u8, _: usize) std.Io.Writer.Error!usize {
            const self: *@This() = @alignCast(@fieldParentPtr("writer", writer));
            self.calls += 1;
            return error.WriteFailed;
        }
    };
    for ([_]bool{ false, true }) |buffered| {
        var in = std.Io.Reader.fixed(&.{});
        var sink: Sink = .{};
        var ciphertext: [128]u8 = undefined;
        if (buffered) sink.writer.buffer = &ciphertext;
        var stream: TlsStream = .{
            .in = &in,
            .out = &sink.writer,
            .write_key = @splat(1),
            .write_iv = @splat(2),
            .read_key = @splat(3),
            .read_iv = @splat(4),
        };
        try std.testing.expectError(error.WriteFailed, stream.write("response"));
        try std.testing.expect(stream.write_closed);
        try std.testing.expectEqual(@as(usize, 1), sink.calls);
        const sequence_after_failure = stream.write_seq;
        try stream.end();
        try stream.end();
        try std.testing.expectEqual(@as(usize, 1), sink.calls);
        try std.testing.expectEqual(sequence_after_failure, stream.write_seq);
        try std.testing.expectError(error.StreamClosed, stream.write("late"));
        try std.testing.expectEqual(@as(usize, 1), sink.calls);
    }
}

test "end sends one encrypted close notify and rejects further writes" {
    var ciphertext: [64]u8 = undefined;
    var in = std.Io.Reader.fixed(&.{});
    var out = std.Io.Writer.fixed(&ciphertext);
    var stream: TlsStream = .{
        .in = &in,
        .out = &out,
        .write_key = @splat(1),
        .write_iv = @splat(2),
        .read_key = @splat(3),
        .read_iv = @splat(4),
    };
    try stream.end();
    const length = out.end;
    try stream.end();
    try std.testing.expectEqual(length, out.end);
    try std.testing.expectEqual(@as(u64, 1), stream.write_seq);
    try std.testing.expectError(error.StreamClosed, stream.write("late"));
    var sequence: u64 = 0;
    var plaintext: [32]u8 = undefined;
    const decoded = try openRecord(out.buffered()[5..], &plaintext, stream.write_key, stream.write_iv, &sequence);
    try std.testing.expectEqual(ContentType.alert, decoded.content_type);
    try std.testing.expectEqualSlices(u8, &.{ 1, 0 }, decoded.data);
}

test "failed end remains write closed without retrying the alert" {
    var in = std.Io.Reader.fixed(&.{});
    var out = std.Io.Writer.fixed(&.{});
    var stream: TlsStream = .{
        .in = &in,
        .out = &out,
        .write_key = @splat(1),
        .write_iv = @splat(2),
        .read_key = @splat(3),
        .read_iv = @splat(4),
    };
    try std.testing.expectError(error.WriteFailed, stream.end());
    try std.testing.expectError(error.StreamClosed, stream.write("late"));
    try stream.end();
    try std.testing.expectEqual(@as(u64, 1), stream.write_seq);
}
