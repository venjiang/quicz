//! Pure-Zig TLS 1.3 handshake over real loopback UDP sockets (no OpenSSL).
//!
//! Lifts `tls13_backend_loopback.zig` onto UDP: two `Connection`s each driven
//! by a `Tls13Backend` exchange protected datagrams over loopback UDP sockets
//! until the handshake is confirmed. STREAM echo + full lifecycle (ACK/PTO/
//! close) are tracked as the remaining M4 work.

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
const server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };

fn require(condition: bool) !void {
    if (!condition) return error.UnexpectedState;
}

fn recvTimeout() std.Io.Timeout {
    return .{ .duration = .{
        .clock = .awake,
        .raw = std.Io.Duration.fromMilliseconds(2000),
    } };
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var client_socket = try client_address.bind(io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer client_socket.close(io);
    var server_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var server_socket = try server_address.bind(io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
    defer server_socket.close(io);

    const seed = [_]u8{0x55} ** 32;
    const server_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const server_priv = server_kp.secret_key.bytes;
    const cert_der = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    const alpn = [_][]const u8{"hq-interop"};
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try Connection.init(allocator, .client, .{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
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
    var recv_buf: [2048]u8 = undefined;

    try client.setLocalInitialSourceConnectionId(&client_scid);
    try server.setLocalInitialSourceConnectionId(&server_scid);

    // 1. Client → ClientHello over UDP.
    _ = try client.driveCryptoBackendInSpace(.initial, client_backend.cryptoBackend(), &scratch);
    const client_dgram = (try client.pollProtectedLongCryptoDatagramInSpace(
        .initial, 40, &original_dcid, &client_scid, &[_]u8{}, secrets.client,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_dgram);
    try client_socket.send(io, &server_socket.address, client_dgram);

    // 2. Server receives, processes, drives initial → handshake + 1-RTT keys.
    const recv1 = try server_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try server.processProtectedLongDatagramInSpace(.initial, 41, secrets.client, recv1.data);
    const server_init_prog = try server.driveCryptoBackendInSpace(.initial, server_backend.cryptoBackend(), &scratch);
    try require(server_init_prog.handshake_keys_installed);

    // 3. Server → ServerHello (Initial) + EE/Cert/CV/Finished (Handshake) over UDP.
    const server_init_dgram = (try server.pollProtectedLongCryptoDatagramInSpace(
        .initial, 42, &client_scid, &server_scid, &[_]u8{}, secrets.server,
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_init_dgram);
    try server_socket.send(io, &client_socket.address, server_init_dgram);

    _ = try server.driveCryptoBackendInSpace(.handshake, server_backend.cryptoBackend(), &scratch);
    const server_hs_dgram = (try server.pollProtectedHandshakeDatagramWithInstalledKeys(
        43, &client_scid, &server_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_hs_dgram);
    try server_socket.send(io, &client_socket.address, server_hs_dgram);

    // 4. Client receives ServerHello, drives initial (install handshake keys).
    const recv2 = try client_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try client.processProtectedLongDatagramInSpace(.initial, 44, secrets.server, recv2.data);
    _ = try client.driveCryptoBackendInSpace(.initial, client_backend.cryptoBackend(), &scratch);

    // 5. Client receives Handshake flight, drives handshake → client Finished.
    const recv3 = try client_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try client.processProtectedHandshakeDatagramWithInstalledKeys(45, recv3.data);
    const client_hs_prog = try client.driveCryptoBackendInSpace(.handshake, client_backend.cryptoBackend(), &scratch);
    try require(client_hs_prog.outbound_bytes > 0);
    const client_hs_dgram = (try client.pollProtectedHandshakeDatagramWithInstalledKeys(
        46, &server_scid, &client_scid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_hs_dgram);
    try client_socket.send(io, &server_socket.address, client_hs_dgram);

    // 6. Server receives client Finished → handshake confirmed.
    const recv4 = try server_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try server.processProtectedHandshakeDatagramWithInstalledKeys(47, recv4.data);
    const server_hs_drive = try server.driveCryptoBackendInSpace(.handshake, server_backend.cryptoBackend(), &scratch);
    try require(server_hs_drive.handshake_confirmed);
    try require(server.handshakeConfirmed());

    // 7. Client opens a bidirectional stream and sends "hello" over 1-RTT.
    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello", false);
    const req_dgram = (try client.pollProtectedShortDatagramWithInstalledKeys(48, &server_scid)) orelse return error.UnexpectedState;
    defer allocator.free(req_dgram);
    try client_socket.send(io, &server_socket.address, req_dgram);

    // 8. Server receives, reads the stream, echoes back.
    const recv5 = try server_socket.receiveTimeout(io, &recv_buf, recvTimeout());
    try server.processProtectedShortDatagramWithInstalledKeys(49, server_scid.len, recv5.data);
    var stream_buf: [128]u8 = undefined;
    const n = (try server.recvOnStream(stream_id, &stream_buf)) orelse return error.UnexpectedState;
    try require(std.mem.eql(u8, stream_buf[0..n], "hello"));
    try server.sendOnStream(stream_id, "hello", false);
    // Server may emit an ACK-only datagram first, then the STREAM datagram.
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const dgram = (try server.pollProtectedShortDatagramWithInstalledKeys(50 + @as(i64, @intCast(i)), &client_scid)) orelse break;
        defer allocator.free(dgram);
        try server_socket.send(io, &client_socket.address, dgram);
    }

    // 9. Client receives the echo (consume up to two datagrams).
    var got_echo = false;
    var j: usize = 0;
    while (j < 4) : (j += 1) {
        const r = client_socket.receiveTimeout(io, &recv_buf, recvTimeout()) catch break;
        try client.processProtectedShortDatagramWithInstalledKeys(51 + @as(i64, @intCast(j)), client_scid.len, r.data);
        if ((try client.recvOnStream(stream_id, &stream_buf)) != null) {
            got_echo = true;
            break;
        }
    }
    try require(got_echo);
    try require(std.mem.eql(u8, stream_buf[0..5], "hello"));

    std.debug.print("tls13_udp_loopback: handshake + STREAM echo over UDP OK, confirmed={}\n", .{server.handshakeConfirmed()});
}
