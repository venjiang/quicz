//! TLS 1.3 client over TCP (RFC 8446) for the quicz CLI.
//!
//! Reuses `quicz.tls13` primitives (KeySchedule, TranscriptHash, certificate
//! verification) and follows the same `in`/`out` interface pattern as the
//! server-side `tls_tcp.zig`.

const std = @import("std");
const crypto = std.crypto;
const quicz = @import("quicz");

const tls13 = quicz.tls13;

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

const HandshakeType = struct {
    const client_hello: u8 = 1;
    const server_hello: u8 = 2;
    const encrypted_extensions: u8 = 8;
    const certificate: u8 = 11;
    const certificate_verify: u8 = 15;
    const finished: u8 = 20;
};

const ExtType = struct {
    const server_name: u16 = 0;
    const supported_groups: u16 = 10;
    const supported_versions: u16 = 43;
    const key_share: u16 = 51;
    const alpn: u16 = 16;
    const signature_algorithms: u16 = 13;
};

const version_tls_1_3: u16 = 0x0304;
const group_x25519: u16 = 0x001d;
const cipher_aes_128_gcm_sha256: u16 = 0x1301;
const sig_ecdsa_p256_sha256: u16 = 0x0403;
const sig_rsa_pss_rsae_sha256: u16 = 0x0804;

// ---- record layer (shared with tls_tcp.zig) --------------------------

fn readU16(buf: []const u8) u16 { return std.mem.readInt(u16, buf[0..2], .big); }
fn readU24(buf: []const u8) u24 { return @as(u24, buf[0]) << 16 | @as(u24, buf[1]) << 8 | @as(u24, buf[2]); }
fn writeU16(buf: []u8, value: u16) void { std.mem.writeInt(u16, buf[0..2], value, .big); }

fn writeRecordHeader(out: []u8, content_type: u8, len: usize) void {
    out[0] = content_type;
    out[1] = 0x03; out[2] = 0x03;
    out[3] = @intCast((len >> 8) & 0xff);
    out[4] = @intCast(len & 0xff);
}

fn deriveTlsKey(secret: [32]u8) [16]u8 {
    return std.crypto.tls.hkdfExpandLabel(crypto.kdf.hkdf.HkdfSha256, secret, "key", &.{}, key_len);
}
fn deriveTlsIv(secret: [32]u8) [12]u8 {
    return std.crypto.tls.hkdfExpandLabel(crypto.kdf.hkdf.HkdfSha256, secret, "iv", &.{}, iv_len);
}

fn nonceFor(iv: [12]u8, seq: u64) [12]u8 {
    var nonce = iv;
    var seq_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_be, seq, .big);
    for (0..8) |i| nonce[4 + i] ^= seq_be[i];
    return nonce;
}

fn sealRecord(out: []u8, inner_ct: u8, payload: []const u8, key: [16]u8, iv: [12]u8, seq: *u64) usize {
    const pt_len = payload.len + 1;
    const ct_len = pt_len + tag_len;
    writeRecordHeader(out, ContentType.application_data, ct_len);
    var aad: [5]u8 = undefined;
    writeRecordHeader(&aad, ContentType.application_data, ct_len);
    @memcpy(out[5..][0..payload.len], payload);
    out[5 + payload.len] = inner_ct;
    var tag: [tag_len]u8 = undefined;
    Aes128Gcm.encrypt(out[5..][0..pt_len], &tag, out[5..][0..pt_len], &aad, nonceFor(iv, seq.*), key);
    @memcpy(out[5 + pt_len .. 5 + ct_len], &tag);
    seq.* += 1;
    return 5 + ct_len;
}

const Decrypted = struct { content_type: u8, data: []const u8 };

fn openRecord(payload: []const u8, out: []u8, key: [16]u8, iv: [12]u8, seq: *u64) !Decrypted {
    if (payload.len < tag_len + 1) return error.TlsDecryptFailed;
    const ct_len = payload.len;
    const pt_len = ct_len - tag_len;
    var aad: [5]u8 = undefined;
    writeRecordHeader(&aad, ContentType.application_data, ct_len);
    var tag: [tag_len]u8 = undefined;
    @memcpy(&tag, payload[pt_len..]);
    Aes128Gcm.decrypt(out[0..pt_len], payload[0..pt_len], tag, &aad, nonceFor(iv, seq.*), key) catch return error.TlsDecryptFailed;
    seq.* += 1;
    var inner_len = pt_len;
    while (inner_len > 0 and out[inner_len - 1] == 0) inner_len -= 1;
    if (inner_len == 0) return error.TlsDecryptFailed;
    return .{ .content_type = out[inner_len - 1], .data = out[0 .. inner_len - 1] };
}

fn readN(in: *std.Io.Reader, buf: []u8) !void { try in.readSliceAll(buf); }

const Record = struct { content_type: u8, payload: []const u8 };

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

// ---- client hello ---------------------------------------------------

fn writeExtTlv(buf: []u8, pos: usize, ext_type: u16, len: usize) usize {
    writeU16(buf[pos..], ext_type);
    writeU16(buf[pos + 2 ..], @intCast(len));
    return pos + 4;
}

fn buildClientHello(buf: []u8, client_random: [32]u8, client_public: [32]u8, server_name: []const u8) usize {
    var p: usize = 0;
    buf[p] = HandshakeType.client_hello; p += 1; p += 3;
    buf[p] = 0x03; buf[p + 1] = 0x03; p += 2;
    @memcpy(buf[p..][0..32], &client_random); p += 32;
    buf[p] = 0; p += 1; // session_id
    writeU16(buf[p..], 2); p += 2; writeU16(buf[p..], cipher_aes_128_gcm_sha256); p += 2;
    buf[p] = 1; p += 1; buf[p] = 0; p += 1; // compression
    const ext_start = p; p += 2;

    p = writeExtTlv(buf, p, ExtType.supported_versions, 3);
    buf[p] = 2; p += 1; writeU16(buf[p..], version_tls_1_3); p += 2;

    p = writeExtTlv(buf, p, ExtType.key_share, 2 + 2 + 2 + 32);
    writeU16(buf[p..], 2 + 2 + 32); p += 2; writeU16(buf[p..], group_x25519); p += 2;
    writeU16(buf[p..], 32); p += 2; @memcpy(buf[p..][0..32], &client_public); p += 32;

    p = writeExtTlv(buf, p, ExtType.signature_algorithms, 2 + 2 + 2);
    writeU16(buf[p..], 4); p += 2; writeU16(buf[p..], sig_ecdsa_p256_sha256); p += 2;
    writeU16(buf[p..], sig_rsa_pss_rsae_sha256); p += 2;

    const sni_ext_len: usize = 2 + 1 + 2 + server_name.len;
    p = writeExtTlv(buf, p, ExtType.server_name, sni_ext_len);
    writeU16(buf[p..], @intCast(1 + 2 + server_name.len)); p += 2;
    buf[p] = 0; p += 1; writeU16(buf[p..], @intCast(server_name.len)); p += 2;
    @memcpy(buf[p..][0..server_name.len], server_name); p += server_name.len;

    const alpn_ext_len: usize = 2 + 1 + "http/1.1".len;
    p = writeExtTlv(buf, p, ExtType.alpn, alpn_ext_len);
    writeU16(buf[p..], @intCast(1 + "http/1.1".len)); p += 2;
    buf[p] = @intCast("http/1.1".len); p += 1;
    @memcpy(buf[p..][0.."http/1.1".len], "http/1.1"); p += "http/1.1".len;

    const ext_len = p - ext_start - 2;
    writeU16(buf[ext_start..], @intCast(ext_len));
    const msg_len = p - 4;
    buf[1] = @intCast((msg_len >> 16) & 0xff);
    buf[2] = @intCast((msg_len >> 8) & 0xff);
    buf[3] = @intCast(msg_len & 0xff);
    return p;
}

// ---- server hello parsing -------------------------------------------

const ServerHelloInfo = struct { server_random: [32]u8, server_public: [32]u8 };

fn parseServerHello(msg: []const u8) !ServerHelloInfo {
    if (msg.len < 4 or msg[0] != HandshakeType.server_hello) return error.TlsUnexpectedMessage;
    var pos: usize = 4;
    if (pos + 2 + 32 > msg.len) return error.TlsDecodeError;
    const server_random = msg[pos + 2 ..][0..32].*;
    pos += 2 + 32;
    if (pos + 1 > msg.len) return error.TlsDecodeError;
    pos += 1 + msg[pos]; // session_id
    if (pos + 2 > msg.len) return error.TlsDecodeError;
    pos += 2; // cipher_suite
    if (pos + 1 > msg.len) return error.TlsDecodeError;
    pos += 1; // compression
    if (pos + 2 > msg.len) return error.TlsDecodeError;
    const ext_len = readU16(msg[pos..]); pos += 2;
    const ext_end = pos + ext_len;
    if (ext_end > msg.len) return error.TlsDecodeError;

    var key_share: ?[32]u8 = null;
    while (pos + 4 <= ext_end) {
        const etype = readU16(msg[pos..]); const elen = readU16(msg[pos + 2 ..]); pos += 4;
        if (pos + elen > ext_end) return error.TlsDecodeError;
        if (etype == ExtType.key_share and elen >= 4) {
            if (readU16(msg[pos..]) == group_x25519 and readU16(msg[pos + 2 ..]) == 32 and pos + 4 + 32 <= ext_end)
                key_share = msg[pos + 4 ..][0..32].*;
        }
        pos += elen;
    }
    return .{ .server_random = server_random, .server_public = key_share orelse return error.TlsNoKeyShare };
}

// ---- handshake helpers -----------------------------------------------

fn readHandshakeMessage(in: *std.Io.Reader, buf: []u8, key: [16]u8, iv: [12]u8, seq: *u64) ![]const u8 {
    var recv_buf: [record_max]u8 = undefined;
    while (true) {
        const rec = try readRecord(in, &recv_buf);
        if (rec.content_type == ContentType.change_cipher_spec) continue;
        if (rec.content_type != ContentType.application_data) return error.TlsUnexpectedMessage;
        const dec = try openRecord(rec.payload, buf, key, iv, seq);
        if (dec.content_type != ContentType.handshake) return error.TlsUnexpectedMessage;
        return dec.data;
    }
}

fn checkHandshakeType(msg: []const u8, expected: u8) !void {
    if (msg.len < 4 or msg[0] != expected) return error.TlsUnexpectedMessage;
}

fn readHandshakeBody(msg: []const u8) []const u8 { return msg[4..]; }

// ---- public API -----------------------------------------------------

pub const Config = struct {
    server_name: []const u8,
    insecure: bool = false,
    ca_bundle: ?*std.crypto.Certificate.Bundle = null,
};

pub const TlsClientStream = struct {
    in: *std.Io.Reader,
    out: *std.Io.Writer,
    write_key: [16]u8,
    write_iv: [12]u8,
    write_seq: u64 = 0,
    read_key: [16]u8,
    read_iv: [12]u8,
    read_seq: u64 = 0,
    dec_buf: [record_max + 256]u8 = undefined,
    dec_start: usize = 0,
    dec_end: usize = 0,

    /// Perform a client-side TLS 1.3 handshake over the given reader/writer.
    /// `now` is the current Unix timestamp for certificate verification.
    pub fn handshake(in: *std.Io.Reader, out: *std.Io.Writer, cfg: Config, now: i64) !TlsClientStream {
        var transcript = tls13.TranscriptHash.init();
        var recv_buf: [record_max]u8 = undefined;

        // X25519 key exchange.
        var x25519_secret: [32]u8 = undefined;
        tls13.secureRandomBytes(&x25519_secret);
        const x25519_public = try X25519.recoverPublicKey(x25519_secret);

        // Build and send ClientHello.
        var ch_buf: [1024]u8 = undefined;
        var client_random: [32]u8 = undefined;
        tls13.secureRandomBytes(&client_random);
        const ch_len = buildClientHello(&ch_buf, client_random, x25519_public, cfg.server_name);
        const ch_msg = ch_buf[0..ch_len];
        transcript.update(ch_msg);

        // Read ServerHello (plaintext).
        const sh_rec = readRecord(in, &recv_buf) catch {
            std.log.err("tls_client: failed to read ServerHello", .{});
            return error.TlsHandshakeFailed;
        };
        if (sh_rec.content_type == ContentType.alert) {
            if (sh_rec.payload.len >= 2) {
            }
            return error.TlsHandshakeFailed;
        }
        if (sh_rec.content_type != ContentType.handshake) {
            std.log.err("tls_client: expected handshake record, got type={d}", .{sh_rec.content_type});
            return error.TlsUnexpectedMessage;
        }
        const sh = parseServerHello(sh_rec.payload) catch {

        // Compute shared secret and derive handshake keys.
        const shared_secret = try X25519.scalarmult(x25519_secret, sh.server_public);
        var ks = tls13.KeySchedule.init();
        ks.deriveHandshakeSecrets(&shared_secret, transcript.current());
        const client_hs_key = deriveTlsKey(ks.client_handshake_traffic_secret);
        const client_hs_iv = deriveTlsIv(ks.client_handshake_traffic_secret);
        const server_hs_key = deriveTlsKey(ks.server_handshake_traffic_secret);
        const server_hs_iv = deriveTlsIv(ks.server_handshake_traffic_secret);
        var server_hs_seq: u64 = 0;
        var client_hs_seq: u64 = 0;

        // Read EncryptedExtensions.
        var dec_buf: [record_max]u8 = undefined;
        const ee_msg = readHandshakeMessage(in, &dec_buf, server_hs_key, server_hs_iv, &server_hs_seq) catch {
            std.log.err("tls_client: failed to read EncryptedExtensions", .{});
            return error.TlsHandshakeFailed;
        };
        checkHandshakeType(ee_msg, HandshakeType.encrypted_extensions) catch {

        // Read Certificate.
        const cert_msg = readHandshakeMessage(in, &dec_buf, server_hs_key, server_hs_iv, &server_hs_seq) catch {
            std.log.err("tls_client: failed to read Certificate", .{});
            return error.TlsHandshakeFailed;
        };
        checkHandshakeType(cert_msg, HandshakeType.certificate) catch {

        // Read CertificateVerify.
        const cv_msg = readHandshakeMessage(in, &dec_buf, server_hs_key, server_hs_iv, &server_hs_seq) catch {
            std.log.err("tls_client: failed to read CertificateVerify", .{});
            return error.TlsHandshakeFailed;
        };
        checkHandshakeType(cv_msg, HandshakeType.certificate_verify) catch {
        if (cv_body.len < 4) return error.TlsDecodeError;
        _ = readU16(cv_body[0..2]); // sig_scheme
        _ = readU16(cv_body[2..4]); // sig_len

        // Extract leaf certificate DER for verification.
        const cert_body = readHandshakeBody(cert_msg);
        if (cert_body.len < 1) return error.TlsDecodeError;
        const ctx_len = cert_body[0];
        var cp: usize = 1 + ctx_len;
        if (cp + 3 > cert_body.len) return error.TlsDecodeError;
        const cert_list_len = readU24(cert_body[cp..]); cp += 3;
        const cert_list_end = cp + cert_list_len;
        if (cert_list_end > cert_body.len) return error.TlsDecodeError;
        if (cp + 3 > cert_list_end) return error.TlsNoCertificate;
        const leaf_der_len = readU24(cert_body[cp..]); cp += 3;
        if (cp + leaf_der_len > cert_list_end) return error.TlsDecodeError;
        const leaf_der = cert_body[cp .. cp + leaf_der_len];

        if (!cfg.insecure) {
            // Verify certificate chain against the CA bundle.
            if (cfg.ca_bundle) |bundle| {
                const leaf_cert: std.crypto.Certificate = .{ .buffer = leaf_der, .index = 0 };
                const leaf_parsed = std.crypto.Certificate.parse(leaf_cert) catch return error.TlsBadCertificate;
                bundle.verify(leaf_parsed, now) catch return error.TlsBadCertificate;
            }
        }
        transcript.update(cv_msg);

        // Read Server Finished.
        const sf_msg = readHandshakeMessage(in, &dec_buf, server_hs_key, server_hs_iv, &server_hs_seq) catch {
            std.log.err("tls_client: failed to read Server Finished", .{});
            return error.TlsHandshakeFailed;
        };
        checkHandshakeType(sf_msg, HandshakeType.finished) catch {
            std.log.err("tls_client: expected Finished, got type={d}", .{sf_msg[0]});
            return error.TlsHandshakeFailed;
        };
        if (sf_msg.len < 36) return error.TlsBadFinished;
        const expected_vd = tls13.KeySchedule.computeFinishedVerifyData(ks.server_handshake_traffic_secret, transcript.current());
        if (!crypto.timing_safe.eql([32]u8, sf_msg[4..36].*, expected_vd)) return error.TlsBadFinished;
        transcript.update(sf_msg);

        // Derive application secrets.
        ks.deriveAppSecrets(transcript.current());

        // Send Client Finished.
        const client_finished_vd = tls13.KeySchedule.computeFinishedVerifyData(ks.client_handshake_traffic_secret, transcript.current());
        var fin_msg: [36]u8 = undefined;
        fin_msg[0] = HandshakeType.finished;
        fin_msg[1] = 0; fin_msg[2] = 0; fin_msg[3] = 32;
        @memcpy(fin_msg[4..36], &client_finished_vd);
        transcript.update(&fin_msg);
        var rec: [record_max + 64]u8 = undefined;
        const fin_rec_len = sealRecord(&rec, ContentType.handshake, &fin_msg, client_hs_key, client_hs_iv, &client_hs_seq);
        try out.writeAll(rec[0..fin_rec_len]);
        try out.flush();

        return .{
            .in = in, .out = out,
            .write_key = deriveTlsKey(ks.client_app_traffic_secret),
            .write_iv = deriveTlsIv(ks.client_app_traffic_secret),
            .read_key = deriveTlsKey(ks.server_app_traffic_secret),
            .read_iv = deriveTlsIv(ks.server_app_traffic_secret),
        };
    }

    /// Read decrypted application data. Returns 0 on EOF.
    pub fn read(self: *TlsClientStream, buf: []u8) !usize {
        if (self.dec_start < self.dec_end) {
            const n = @min(self.dec_end - self.dec_start, buf.len);
            @memcpy(buf[0..n], self.dec_buf[self.dec_start .. self.dec_start + n]);
            self.dec_start += n;
            return n;
        }
        var header: [5]u8 = undefined;
        readN(self.in, &header) catch |e| {
            if (e == error.EndOfStream) return 0;
            return e;
        };
        const len = (@as(usize, header[3]) << 8) | header[4];
        if (len > self.dec_buf.len) return error.RecordOversize;
        try readN(self.in, self.dec_buf[0..len]);
        if (header[0] == ContentType.application_data) {
            var plain: [record_max]u8 = undefined;
            const dec = try openRecord(self.dec_buf[0..len], &plain, self.read_key, self.read_iv, &self.read_seq);
            if (dec.content_type != ContentType.application_data) return error.TlsUnexpectedMessage;
            const n = @min(dec.data.len, buf.len);
            @memcpy(buf[0..n], dec.data[0..n]);
            if (n < dec.data.len) {
                @memcpy(self.dec_buf[0 .. dec.data.len - n], dec.data[n..]);
                self.dec_start = 0;
                self.dec_end = dec.data.len - n;
            }
            return n;
        }
        if (header[0] == ContentType.alert) return error.TlsAlert;
        return error.TlsUnexpectedMessage;
    }

    /// Write application data (encrypted as a TLS record).
    pub fn write(self: *TlsClientStream, data: []const u8) !void {
        var rec: [record_max + 64]u8 = undefined;
        const n = sealRecord(&rec, ContentType.application_data, data, self.write_key, self.write_iv, &self.write_seq);
        try self.out.writeAll(rec[0..n]);
        try self.out.flush();
    }
};
