//! Pure-Zig adapter that wraps a `Tls13Handshake` into the connection-facing
//! `CryptoBackend` interface.
//!
//! The connection drives TLS over QUIC CRYPTO byte streams: it feeds inbound
//! CRYPTO bytes via `receive`, pulls outbound CRYPTO bytes via `pull`, pulls
//! traffic secrets once they are available, and probes `handshake_confirmed`.
//! This adapter translates that pull-based interface onto the push-based
//! `Tls13Handshake.step()` state machine, buffering `send_data` actions per
//! packet number space and exposing traffic secrets directly from the key
//! schedule (the connection derives packet-protection keys from the secret).

const std = @import("std");
const tls13 = @import("tls13.zig");
const transport_types = @import("transport_types.zig");
const protection = @import("protection.zig");
const crypto_types = @import("crypto_types.zig");

const Error = transport_types.Error;
const PacketNumberSpace = transport_types.PacketNumberSpace;
const CryptoBackend = crypto_types.CryptoBackend;
const HandshakeTrafficSecrets = crypto_types.HandshakeTrafficSecrets;
const OneRttTrafficSecrets = crypto_types.OneRttTrafficSecrets;
const ZeroRttTrafficSecrets = crypto_types.ZeroRttTrafficSecrets;
const Tls13Handshake = tls13.Tls13Handshake;
const TlsConfig = tls13.TlsConfig;
const EncryptionLevel = tls13.EncryptionLevel;

/// Per-space outbound buffer. `Tls13Handshake.step()` emits one `send_data`
/// action at a time; this buffer accumulates them so the connection can drain
/// a space across multiple `pull` calls.
const OutBucket = struct {
    buf: [max_out]u8 = undefined,
    len: usize = 0,
    offset: usize = 0,

    fn pending(self: *const OutBucket) usize {
        return self.len - self.offset;
    }

    fn append(self: *OutBucket, data: []const u8) void {
        const room = self.buf.len - self.len;
        const n = @min(data.len, room);
        @memcpy(self.buf[self.len..][0..n], data[0..n]);
        self.len += n;
    }

    /// Copy as many pending bytes as fit in `out`, advancing the offset.
    /// Returns the slice of `out` that was filled.
    fn drain(self: *OutBucket, out: []u8) []const u8 {
        const n = @min(self.pending(), out.len);
        if (n > 0) @memcpy(out[0..n], self.buf[self.offset..][0..n]);
        self.offset += n;
        if (self.offset >= self.len) {
            self.len = 0;
            self.offset = 0;
        }
        return out[0..n];
    }
};

const max_out: usize = 32768;

/// A `Tls13Handshake` exposed as a `CryptoBackend`. The connection never owns
/// this value; the caller holds it (stack or long-lived struct) for as long as
/// the connection drives it.
pub const Tls13Backend = struct {
    hs: Tls13Handshake,

    out_initial: OutBucket = .{},
    out_handshake: OutBucket = .{},
    out_app: OutBucket = .{},

    /// Set once the ClientHello has been emitted, after which
    /// `set_local_transport_parameters` is ignored (the transport parameters
    /// are baked into the ClientHello transcript).
    client_hello_built: bool = false,

    /// One-shot delivery flags — each pull hook returns its payload at most once.
    handshake_secrets_sent: bool = false,
    one_rtt_secrets_sent: bool = false,
    peer_tp_sent: bool = false,
    alpn_sent: bool = false,
    early_traffic_secret_sent: bool = false,

    /// Observability counters (never key material). Useful for interop
    /// debugging: how many CRYPTO bytes flowed in/out, how many drive errors.
    inbound_bytes: usize = 0,
    outbound_bytes: usize = 0,
    drive_errors: usize = 0,

    /// Initialize as a TLS 1.3 client. Transport parameters are supplied by
    /// the connection via `set_local_transport_parameters` before the
    /// ClientHello is pulled; pass them there rather than to `initClient`.
    pub fn initClient(config: TlsConfig) Tls13Backend {
        return .{ .hs = Tls13Handshake.initClient(config, &[_]u8{}) };
    }

    /// Initialize as a TLS 1.3 client with a resumption PSK for 0-RTT.
    pub fn initClientWithPsk(config: TlsConfig, psk: [tls13.secret_len]u8) Tls13Backend {
        return .{ .hs = Tls13Handshake.initClientWithPsk(config, &[_]u8{}, psk) };
    }

    /// Initialize as a TLS 1.3 server. Transport parameters are supplied by
    /// the connection via `set_local_transport_parameters` before the
    /// ServerHello flight is pulled.
    pub fn initServer(config: TlsConfig) Tls13Backend {
        return .{ .hs = Tls13Handshake.initServer(config, &[_]u8{}) };
    }

    /// Return a `CryptoBackend` value whose callbacks drive this backend.
    /// The value is only valid while `self` is stable.
    pub fn cryptoBackend(self: *Tls13Backend) CryptoBackend {
        return .{
            .context = self,
            .receive = receive,
            .pull = pull,
            .set_local_transport_parameters = setLocalTransportParameters,
            .pull_peer_transport_parameters = pullPeerTransportParameters,
            .pull_handshake_traffic_secrets = pullHandshakeTrafficSecrets,
            .pull_zero_rtt_traffic_secrets = pullZeroRttTrafficSecrets,
            .pull_1rtt_traffic_secrets = pullOneRttTrafficSecrets,
            .pull_negotiated_alpn = pullNegotiatedAlpn,
            .handshake_confirmed = handshakeConfirmed,
        };
    }

    // ─── Callbacks ───────────────────────────────────────────────────

    fn receive(context: *anyopaque, space: PacketNumberSpace, data: []const u8) Error!void {
        _ = space; // Tls13Handshake parses by message type; QUIC orders across spaces.
        const self: *Tls13Backend = @ptrCast(@alignCast(context));
        self.inbound_bytes += data.len;
        self.hs.provideData(data);
        self.pump() catch {
            self.drive_errors += 1;
            return error.CryptoError;
        };
    }

    fn pull(context: *anyopaque, space: PacketNumberSpace, out_buf: []u8) Error!?[]const u8 {
        const self: *Tls13Backend = @ptrCast(@alignCast(context));
        const bucket = self.bucketForSpace(space);
        if (bucket.pending() == 0) {
            // Nothing buffered: advance the state machine, which may produce
            // data for this or another space.
            self.pump() catch {
                self.drive_errors += 1;
                return error.CryptoError;
            };
            if (bucket.pending() == 0) return null;
        }
        const out = bucket.drain(out_buf);
        if (out.len == 0) return null;
        self.outbound_bytes += out.len;
        return out;
    }

    fn setLocalTransportParameters(context: *anyopaque, data: []const u8) Error!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(context));
        // Idempotent: once the ClientHello is built the transport parameters
        // are fixed in the transcript.
        if (self.client_hello_built) return;
        const n = @min(data.len, self.hs.tp_encoded.len);
        @memcpy(self.hs.tp_encoded[0..n], data[0..n]);
        self.hs.tp_encoded_len = n;
    }

    fn pullPeerTransportParameters(context: *anyopaque, out_buf: []u8) Error!?[]const u8 {
        const self: *Tls13Backend = @ptrCast(@alignCast(context));
        if (self.peer_tp_sent or self.hs.peer_tp_len == 0) return null;
        const n = @min(self.hs.peer_tp_len, out_buf.len);
        @memcpy(out_buf[0..n], self.hs.peer_tp[0..n]);
        self.peer_tp_sent = true;
        return out_buf[0..n];
    }

    fn pullHandshakeTrafficSecrets(context: *anyopaque) Error!?HandshakeTrafficSecrets {
        const self: *Tls13Backend = @ptrCast(@alignCast(context));
        if (!self.hs.key_schedule.handshake_secret_derived or self.handshake_secrets_sent) return null;
        self.handshake_secrets_sent = true;
        // `local` is this endpoint's write secret; `peer` is the remote's.
        if (self.hs.is_server) {
            return .{
                .local = self.hs.key_schedule.server_handshake_traffic_secret,
                .peer = self.hs.key_schedule.client_handshake_traffic_secret,
            };
        }
        return .{
            .local = self.hs.key_schedule.client_handshake_traffic_secret,
            .peer = self.hs.key_schedule.server_handshake_traffic_secret,
        };
    }

    fn pullOneRttTrafficSecrets(context: *anyopaque) Error!?OneRttTrafficSecrets {
        const self: *Tls13Backend = @ptrCast(@alignCast(context));
        if (!self.hs.key_schedule.app_secret_derived or self.one_rtt_secrets_sent) return null;
        self.one_rtt_secrets_sent = true;
        if (self.hs.is_server) {
            return .{
                .local = self.hs.key_schedule.server_app_traffic_secret,
                .peer = self.hs.key_schedule.client_app_traffic_secret,
            };
        }
        return .{
            .local = self.hs.key_schedule.client_app_traffic_secret,
            .peer = self.hs.key_schedule.server_app_traffic_secret,
        };
    }

    fn pullNegotiatedAlpn(context: *anyopaque, out_buf: []u8) Error!?[]const u8 {
        const self: *Tls13Backend = @ptrCast(@alignCast(context));
        if (self.alpn_sent or self.hs.negotiated_alpn_len == 0) return null;
        const n = @min(self.hs.negotiated_alpn_len, out_buf.len);
        @memcpy(out_buf[0..n], self.hs.negotiated_alpn[0..n]);
        self.alpn_sent = true;
        return out_buf[0..n];
    }

    fn handshakeConfirmed(context: *anyopaque) bool {
        const self: *Tls13Backend = @ptrCast(@alignCast(context));
        return self.hs.isComplete();
    }

    fn pullZeroRttTrafficSecrets(context: *anyopaque) Error!?ZeroRttTrafficSecrets {
        const self: *Tls13Backend = @ptrCast(@alignCast(context));
        // Client: derive the early traffic secret from the PSK-based early
        // secret and the ClientHello transcript; expose as the local write
        // secret so the connection can install 0-RTT keys.
        const early = self.pullEarlyTrafficSecret() orelse return null;
        return .{ .local = early, .peer = null };
    }

    /// Return the resumption PSK derived from a post-handshake
    /// NewSessionTicket, or null if none has been received. The PSK seeds
    /// `Tls13Handshake.initWithPsk` for a future resumed session with 0-RTT.
    pub fn resumptionPsk(self: *const Tls13Backend) ?[tls13.secret_len]u8 {
        return self.hs.resumption_psk;
    }

    /// Return the client early traffic secret for 0-RTT, or null when the
    /// client has no PSK or the ClientHello has not been built yet. The
    /// secret protects 0-RTT early data; the caller derives packet-protection
    /// keys via `protection.deriveAes128PacketProtectionKeys`. One-shot.
    pub fn pullEarlyTrafficSecret(self: *Tls13Backend) ?[tls13.secret_len]u8 {
        if (!self.hs.has_psk or self.early_traffic_secret_sent or !self.client_hello_built) return null;
        self.early_traffic_secret_sent = true;
        return self.hs.key_schedule.deriveEarlyTrafficSecret(self.hs.transcript.current());
    }

    /// Write TLS 1.3 secrets in NSS key-log format to `writer` for
    /// SSLKEYLOGFILE / Wireshark debugging. Call after handshake secrets are
    /// available. Never prints private key material — only derived traffic
    /// secrets.
    pub fn writeKeylog(self: *Tls13Backend, writer: *std.Io.Writer) !void {
        const hs = &self.hs;
        const cr = &hs.client_random;
        if (hs.key_schedule.handshake_secret_derived) {
            try writer.print("SERVER_HANDSHAKE_TRAFFIC_SECRET {x} {x}\n", .{ cr.*, hs.key_schedule.server_handshake_traffic_secret });
            try writer.print("CLIENT_HANDSHAKE_TRAFFIC_SECRET {x} {x}\n", .{ cr.*, hs.key_schedule.client_handshake_traffic_secret });
        }
        if (hs.key_schedule.app_secret_derived) {
            try writer.print("SERVER_TRAFFIC_SECRET_0 {x} {x}\n", .{ cr.*, hs.key_schedule.server_app_traffic_secret });
            try writer.print("CLIENT_TRAFFIC_SECRET_0 {x} {x}\n", .{ cr.*, hs.key_schedule.client_app_traffic_secret });
        }
    }

    // ─── Internal helpers ────────────────────────────────────────────

    /// Advance the state machine until it blocks (wait_for_data / complete),
    /// buffering every `send_data` action into the matching space bucket.
    fn pump(self: *Tls13Backend) tls13.HandshakeError!void {
        while (true) {
            const action = try self.hs.step();
            switch (action) {
                .send_data => |sd| {
                    if (!self.client_hello_built and sd.level == .initial) self.client_hello_built = true;
                    self.bucketForLevel(sd.level).append(sd.data);
                },
                .install_keys => {},
                .wait_for_data => return,
                .complete => {
                    // After the handshake completes, a client may receive
                    // post-handshake NewSessionTicket messages in Application
                    // CRYPTO; drain them to derive the resumption PSK.
                    if (!self.hs.is_server) {
                        try self.hs.clientProcessPostHandshake();
                    }
                    return;
                },
                ._continue => continue,
            }
        }
    }

    fn bucketForLevel(self: *Tls13Backend, level: EncryptionLevel) *OutBucket {
        return switch (level) {
            .initial => &self.out_initial,
            .handshake => &self.out_handshake,
            .application, .early_data => &self.out_app,
        };
    }

    fn bucketForSpace(self: *Tls13Backend, space: PacketNumberSpace) *OutBucket {
        return switch (space) {
            .initial => &self.out_initial,
            .handshake => &self.out_handshake,
            .application => &self.out_app,
        };
    }
};

// ─── Tests ───────────────────────────────────────────────────────────

const X25519 = std.crypto.dh.X25519;
const testing = std.testing;

test "Tls13Backend resumptionPsk returns stored PSK" {
    var backend = Tls13Backend.initClient(.{
        .alpn = &.{},
        .server_name = "example.com",
    });
    try std.testing.expect(backend.resumptionPsk() == null);
    backend.hs.resumption_psk = [_]u8{0x01} ** tls13.secret_len;
    const psk = backend.resumptionPsk().?;
    try std.testing.expectEqual(@as(usize, tls13.secret_len), psk.len);
    try std.testing.expectEqual(@as(u8, 0x01), psk[0]);
}

test "Tls13Backend pullEarlyTrafficSecret returns 0-RTT secret after ClientHello" {
    var backend = Tls13Backend.initClientWithPsk(.{
        .alpn = &.{},
        .server_name = "example.com",
    }, [_]u8{0xab} ** tls13.secret_len);
    // Before the ClientHello is built, no early secret.
    try std.testing.expect(backend.pullEarlyTrafficSecret() == null);
    // Drive the ClientHello via the CryptoBackend pull hook (triggers pump).
    var cb = backend.cryptoBackend();
    var out_buf: [4096]u8 = undefined;
    _ = cb.pull(cb.context, .initial, &out_buf) catch {};
    // After the ClientHello is built, the early traffic secret is available.
    const early = backend.pullEarlyTrafficSecret() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, tls13.secret_len), early.len);
    // One-shot: a second pull returns null.
    try std.testing.expect(backend.pullEarlyTrafficSecret() == null);
}

test "Tls13Backend drives a full client handshake through CryptoBackend hooks" {
    const alpn_proto = "hq-interop";
    const alpn = [_][]const u8{alpn_proto};
    const local_tp = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const peer_tp = [_]u8{ 0xAB, 0xCD, 0xEF };

    var backend = Tls13Backend.initClient(.{
        .alpn = &alpn,
        .server_name = "example.com",
    });
    var cb = backend.cryptoBackend();

    // Connection feeds local transport parameters before pulling ClientHello.
    _ = try cb.setLocalTransportParameters(&local_tp);

    // pull(initial) → ClientHello.
    var scratch: [4096]u8 = undefined;
    const ch_opt = try cb.pull(cb.context, .initial, &scratch);
    try testing.expect(ch_opt != null);
    var client_hello: [4096]u8 = undefined;
    const client_hello_len = ch_opt.?.len;
    @memcpy(client_hello[0..client_hello_len], ch_opt.?);
    const client_hello_bytes = client_hello[0..client_hello_len];

    // Server X25519 key pair + shared secret (replicated to predict secrets).
    var server_secret: [32]u8 = undefined;
    tls13.secureRandomBytes(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);
    const shared = try X25519.scalarmult(backend.hs.x25519_secret, server_public);

    var th = tls13.TranscriptHash.init();
    th.update(client_hello_bytes);
    var ks = tls13.KeySchedule.init();

    // ServerHello (initial space).
    var sh_buf: [128]u8 = undefined;
    const sh_len = tls13.buildServerHello(&sh_buf, server_public, 0x1301, true, true);
    const server_hello = sh_buf[0..sh_len];
    try cb.receive(cb.context, .initial, server_hello);
    th.update(server_hello);
    ks.deriveHandshakeSecrets(&shared, th.current());

    // Handshake traffic secrets are available after ServerHello is processed.
    const hs_secrets = (try cb.pullHandshakeTrafficSecrets()) orelse return error.TestExpectedSecrets;
    try testing.expectEqualSlices(u8, &ks.client_handshake_traffic_secret, &hs_secrets.local);
    try testing.expectEqualSlices(u8, &ks.server_handshake_traffic_secret, &hs_secrets.peer);
    // Second pull returns null (one-shot delivery).
    try testing.expect((try cb.pullHandshakeTrafficSecrets()) == null);

    // Build the handshake-space server flight: EE + Certificate + CV + Finished.
    var ee_buf: [256]u8 = undefined;
    const ee_len = tls13.buildEncryptedExtensions(&ee_buf, alpn_proto, &peer_tp);
    const ee = ee_buf[0..ee_len];

    const cert_der = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    var cert_buf: [512]u8 = undefined;
    const cert_len = tls13.buildCertificate(&cert_buf, &cert_der);
    const cert = cert_buf[0..cert_len];

    // CertificateVerify uses a dummy signature; verification is skipped by
    // default (skip_cert_verify = true), so the signature need not be real.
    const sig_bytes = [_]u8{0x42} ** 64;
    var cv_buf: [256]u8 = undefined;
    const cv_len = tls13.buildCertificateVerify(&cv_buf, 0x0807, &sig_bytes);
    const cv = cv_buf[0..cv_len];

    th.update(ee);
    th.update(cert);
    th.update(cv);
    const server_verify = tls13.KeySchedule.computeFinishedVerifyData(
        ks.server_handshake_traffic_secret,
        th.current(),
    );
    var sf_buf: [64]u8 = undefined;
    const sf_len = tls13.buildFinished(&sf_buf, server_verify);
    const server_finished = sf_buf[0..sf_len];

    // Concatenate the handshake-space flight and feed it in one receive call.
    var flight: [1024]u8 = undefined;
    var fl: usize = 0;
    @memcpy(flight[fl..][0..ee.len], ee);
    fl += ee.len;
    @memcpy(flight[fl..][0..cert.len], cert);
    fl += cert.len;
    @memcpy(flight[fl..][0..cv.len], cv);
    fl += cv.len;
    @memcpy(flight[fl..][0..server_finished.len], server_finished);
    fl += server_finished.len;
    try cb.receive(cb.context, .handshake, flight[0..fl]);

    // The client now emits its Finished in the handshake space.
    const cf_opt = try cb.pull(cb.context, .handshake, &scratch);
    try testing.expect(cf_opt != null);
    try testing.expectEqual(@as(usize, 36), cf_opt.?.len);

    // Application traffic secrets are available after the client Finished.
    th.update(server_finished);
    const app_secrets = (try cb.pullOneRttTrafficSecrets()) orelse return error.TestExpectedAppSecrets;
    ks.deriveAppSecrets(th.current());
    try testing.expectEqualSlices(u8, &ks.client_app_traffic_secret, &app_secrets.local);
    try testing.expectEqualSlices(u8, &ks.server_app_traffic_secret, &app_secrets.peer);

    // Peer transport parameters + negotiated ALPN.
    const ptp = (try cb.pullPeerTransportParameters(&scratch)) orelse return error.TestExpectedPeerTp;
    try testing.expectEqualSlices(u8, &peer_tp, ptp);
    const alpn_result = (try cb.pullNegotiatedAlpn(&scratch)) orelse return error.TestExpectedAlpn;
    try testing.expectEqualStrings(alpn_proto, alpn_result);

    // Handshake is complete.
    try testing.expect(cb.isHandshakeConfirmed());

    // No more outbound data in any space.
    try testing.expect((try cb.pull(cb.context, .initial, &scratch)) == null);
    try testing.expect((try cb.pull(cb.context, .handshake, &scratch)) == null);
    try testing.expect((try cb.pull(cb.context, .application, &scratch)) == null);
}

test "Tls13Backend set_local_transport_parameters is ignored after ClientHello is built" {
    var backend = Tls13Backend.initClient(.{});
    var cb = backend.cryptoBackend();

    const first_tp = [_]u8{ 0xAA, 0xBB };
    _ = try cb.setLocalTransportParameters(&first_tp);
    try testing.expectEqual(@as(usize, 2), backend.hs.tp_encoded_len);

    // Pull the ClientHello, which bakes the transport parameters in.
    var scratch: [4096]u8 = undefined;
    _ = try cb.pull(cb.context, .initial, &scratch);
    try testing.expect(backend.client_hello_built);

    // A later call must not overwrite the baked parameters.
    const second_tp = [_]u8{ 0xCC, 0xDD, 0xEE };
    _ = try cb.setLocalTransportParameters(&second_tp);
    try testing.expectEqual(@as(usize, 2), backend.hs.tp_encoded_len);
    try testing.expectEqual(@as(u8, 0xAA), backend.hs.tp_encoded[0]);
}
