//! Pure-Zig TLS 1.3 backend driving two `Connection`s through a complete
//! handshake over in-memory datagram exchange (no UDP sockets, no OpenSSL).
//!
//! Mirrors the drive rhythm of `tls_openssl_backend_adapter.zig` but the
//! `CryptoBackend` is `quicz.tls13_backend.Tls13Backend`, so CRYPTO bytes and
//! traffic secrets are produced by the in-tree TLS 1.3 implementation.

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const TlsConfig = quicz.tls13.TlsConfig;
const PrivateKeyAlgorithm = quicz.tls13.PrivateKeyAlgorithm;
const protection = quicz.protection;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
const server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };

fn require(condition: bool) !void {
    if (!condition) return error.UnexpectedState;
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Server ECDSA P-256 key pair (real private key for CertificateVerify).
    const seed = [_]u8{0x55} ** 32;
    const server_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const server_priv = server_kp.secret_key.bytes;
    const cert_der = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    const alpn = [_][]const u8{"hq-interop"};

    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try Connection.init(allocator, .client, .{
        .max_datagram_size = 8192,
    });
    defer client.deinit();
    var server = try Connection.init(allocator, .server, .{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
        .max_datagram_size = 8192,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    var client_backend = Tls13Backend.initClient(.{
        .alpn = &alpn,
        .server_name = "example.com",
        .skip_cert_verify = true,
    });
    var server_backend = Tls13Backend.initServer(.{
        .alpn = &alpn,
        .cert_chain_der = &.{&cert_der},
        .private_key_bytes = &server_priv,
        .private_key_algorithm = .ecdsa_p256_sha256,
    });

    var scratch: [8192]u8 = undefined;

    // Set the client's Initial Source Connection ID before the first drive so
    // the backend-produced ClientHello carries it in its transport parameters.
    try client.setLocalInitialSourceConnectionId(&client_scid);

    // 1. Client drive initial → produces ClientHello CRYPTO.
    const client_initial_progress = try client.driveCryptoBackendInSpace(
        .initial,
        client_backend.cryptoBackend(),
        &scratch,
    );
    try require(client_initial_progress.outbound_bytes > 0);

    // 2. Client packs the ClientHello into a protected Initial datagram.
    const client_datagram = (try client.pollProtectedLongCryptoDatagramInSpace(
        .initial,
        40,
        &original_dcid,
        &client_scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_datagram);
    try require(client_datagram.len >= 1200);

    // 3. Server receives and decrypts the Initial datagram, then drives the
    //    backend to consume the ClientHello and produce the ServerHello flight.
    try server.processProtectedLongDatagramInSpace(.initial, 41, secrets.client, client_datagram);
    const server_initial_progress = try server.driveCryptoBackendInSpace(
        .initial,
        server_backend.cryptoBackend(),
        &scratch,
    );
    try require(server_initial_progress.inbound_bytes > 0);
    try require(server_initial_progress.handshake_keys_installed);

    std.debug.print(
        "client_initial_outbound={d} server_initial_inbound={d} handshake_keys={}\n",
        .{
            client_initial_progress.outbound_bytes,
            server_initial_progress.inbound_bytes,
            server_initial_progress.handshake_keys_installed,
        },
    );

    std.debug.print("tls13_backend_loopback: initial flight exchange OK\n", .{});
}
