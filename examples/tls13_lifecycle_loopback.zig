//! Pure-Zig TLS 1.3 over loopback UDP with `EndpointConnectionLifecycle`
//! ownership — the M5/M6 foundation that `tls13_udp_loopback.zig` (Connection-
//! direct) does not cover. Mirrors `tls_openssl_backend_adapter.zig`
//! `AdapterEndpointSocketLoop` but with `Tls13Backend`.

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
const server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
const client_handle: u64 = 1;
const server_handle: u64 = 2;

fn require(condition: bool) !void {
    if (!condition) return error.UnexpectedState;
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var client_socket = try client_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer client_socket.close(io);
    var server_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var server_socket = try server_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer server_socket.close(io);

    const client_path = quicz.endpoint.Udp4Tuple{
        .local = quicz.endpoint.Udp4Address.init(client_address.ip4.bytes, client_address.ip4.port),
        .remote = quicz.endpoint.Udp4Address.init(server_address.ip4.bytes, server_address.ip4.port),
    };
    const server_path = quicz.endpoint.Udp4Tuple{
        .local = quicz.endpoint.Udp4Address.init(server_address.ip4.bytes, server_address.ip4.port),
        .remote = quicz.endpoint.Udp4Address.init(client_address.ip4.bytes, client_address.ip4.port),
    };

    var client_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer client_lifecycle.deinit();
    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer server_lifecycle.deinit();
    try client_lifecycle.registerConnectionId(client_handle, &client_scid, client_path, .{ .active_migration_disabled = true });
    try server_lifecycle.registerConnectionId(server_handle, &original_dcid, server_path, .{ .active_migration_disabled = true });
    try server_lifecycle.registerConnectionId(server_handle, &server_scid, server_path, .{ .active_migration_disabled = true });

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
    try client.setLocalInitialSourceConnectionId(&client_scid);
    try server.setLocalInitialSourceConnectionId(&server_scid);

    var client_backend = Tls13Backend.initClient(.{ .alpn = &alpn, .server_name = "example.com", .skip_cert_verify = true });
    var server_backend = Tls13Backend.initServer(.{
        .alpn = &alpn,
        .cert_chain_der = &.{&cert_der},
        .private_key_bytes = &server_priv,
        .private_key_algorithm = .ecdsa_p256_sha256,
    });

    var scratch: [8192]u8 = undefined;

    // Client drive initial via lifecycle (arms connection + produces ClientHello).
    const client_progress = try client_lifecycle.driveCryptoBackendInSpaceAndArmConnection(
        client_handle,
        &client,
        .initial,
        client_backend.cryptoBackend(),
        &scratch,
    );
    try require(client_progress.outbound_bytes > 0);

    const client_dgram = (try client_lifecycle.pollProtectedLongDatagram(
        client_handle,
        &client,
        10,
        &original_dcid,
        &client_scid,
        &[_]u8{},
        .{ .initial = secrets.client },
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_dgram);
    try client_socket.send(io, &server_socket.address, client_dgram);

    // Server receives via routed lifecycle processing.
    var recv_buf: [9000]u8 = undefined;
    const recv1 = try server_socket.receiveTimeout(io, &recv_buf, .{ .duration = .{
        .clock = .awake,
        .raw = std.Io.Duration.fromMilliseconds(2000),
    } });
    const route = try server_lifecycle.processRoutedProtectedInitialDatagram(
        server_handle,
        &server,
        server_path,
        11,
        &original_dcid,
        recv1.data,
    );
    try require(route.connection_id == server_handle);

    const server_progress = try server_lifecycle.driveCryptoBackendInSpaceAndArmConnection(
        server_handle,
        &server,
        .initial,
        server_backend.cryptoBackend(),
        &scratch,
    );
    try require(server_progress.handshake_keys_installed);

    // Server polls its Initial datagram (ServerHello) and sends to client.
    const server_initial_dgram = (try server_lifecycle.pollProtectedLongDatagram(
        server_handle,
        &server,
        12,
        &client_scid,
        &server_scid,
        &[_]u8{},
        .{ .initial = secrets.server },
    )) orelse return error.UnexpectedState;
    defer allocator.free(server_initial_dgram);
    try server_socket.send(io, &client_socket.address, server_initial_dgram);

    // Client receives ServerHello via routed lifecycle processing.
    const recv2 = try client_socket.receiveTimeout(io, &recv_buf, .{ .duration = .{
        .clock = .awake,
        .raw = std.Io.Duration.fromMilliseconds(2000),
    } });
    _ = try client_lifecycle.processRoutedProtectedInitialDatagram(
        client_handle,
        &client,
        client_path,
        13,
        &original_dcid,
        recv2.data,
    );
    const client_drive2 = try client_lifecycle.driveCryptoBackendInSpaceAndArmConnection(
        client_handle,
        &client,
        .initial,
        client_backend.cryptoBackend(),
        &scratch,
    );
    try require(client_drive2.handshake_keys_installed);

    std.debug.print("tls13_lifecycle_loopback: lifecycle initial exchange OK, server_initial={d} client_hs_keys={}\n", .{ server_initial_dgram.len, client_drive2.handshake_keys_installed });
}
