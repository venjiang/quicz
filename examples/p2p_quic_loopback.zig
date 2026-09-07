//! Simulates rendezvous candidate exchange, authenticated bidirectional UDP
//! probing, and verified QUIC stream traffic on the same two sockets.

const std = @import("std");
const quicz = @import("quicz");
const test_certs = @import("test_certs.zig");

const Client = quicz.runtime.client.Client;
const Server = quicz.runtime.server.Server;
const ServerConnection = quicz.runtime.server.ServerConnection;
const punch = quicz.connectivity.punch_wire;

fn echoHandler(connection: ServerConnection) std.Io.Cancelable!void {
    var mutable_connection = connection;
    var stream = mutable_connection.acceptStream() catch return;
    var buffer: [256]u8 = undefined;
    const received = stream.receive(&buffer) catch return;
    stream.send(buffer[0..received], true) catch {};
}

fn receivePunch(
    io: std.Io,
    socket: std.Io.net.Socket,
    key: punch.Key,
) !punch.Message {
    var buffer: [256]u8 = undefined;
    const received = try socket.receiveTimeout(io, &buffer, .{ .duration = .{
        .clock = .awake,
        .raw = std.Io.Duration.fromMilliseconds(1_000),
    } });
    return punch.decode(key, received.data);
}

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var app_bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    const app_socket = try app_bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    var app_socket_transferred = false;
    defer if (!app_socket_transferred) app_socket.close(io);
    var host_bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    const host_socket = try host_bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    var host_socket_transferred = false;
    defer if (!host_socket_transferred) host_socket.close(io);

    const app_port = app_socket.address.ip4.port;
    const host_port = host_socket.address.ip4.port;
    var app_candidate = app_socket.address;
    var host_candidate = host_socket.address;
    const attempt_id: punch.AttemptId = .{0x11} ** 16;
    const key: punch.Key = .{0x42} ** 32;
    const app_nonce: punch.Nonce = .{0xa1} ** 16;
    const host_nonce: punch.Nonce = .{0xb2} ** 16;
    const app_probe = punch.encode(key, .{ .kind = .probe, .attempt_id = attempt_id, .nonce = app_nonce });
    const host_probe = punch.encode(key, .{ .kind = .probe, .attempt_id = attempt_id, .nonce = host_nonce });

    // Both peers send before either receives, matching simultaneous outbound
    // probing through stateful firewalls and NATs.
    try app_socket.send(io, &host_candidate, &app_probe);
    try host_socket.send(io, &app_candidate, &host_probe);
    const received_by_host = try receivePunch(io, host_socket, key);
    const received_by_app = try receivePunch(io, app_socket, key);
    if (received_by_host.kind != .probe or received_by_app.kind != .probe) return error.ExpectedProbe;
    if (!std.mem.eql(u8, &received_by_host.attempt_id, &attempt_id) or
        !std.mem.eql(u8, &received_by_app.attempt_id, &attempt_id)) return error.AttemptMismatch;

    const host_ack = try punch.acknowledgement(key, received_by_host);
    const app_ack = try punch.acknowledgement(key, received_by_app);
    try host_socket.send(io, &app_candidate, &host_ack);
    try app_socket.send(io, &host_candidate, &app_ack);
    const app_confirmation = try receivePunch(io, app_socket, key);
    const host_confirmation = try receivePunch(io, host_socket, key);
    if (app_confirmation.kind != .acknowledgement or
        !std.mem.eql(u8, &app_confirmation.nonce, &app_nonce)) return error.AppPathNotValidated;
    if (host_confirmation.kind != .acknowledgement or
        !std.mem.eql(u8, &host_confirmation.nonce, &host_nonce)) return error.HostPathNotValidated;

    const alpn = [_][]const u8{"quicz-p2p-spike"};
    var server = try Server.initWithSocket(allocator, io, host_socket, .{
        .port = host_port,
        .alpn = &alpn,
        .cert_der = &test_certs.cert_der,
        .private_key = &test_certs.private_key,
    });
    host_socket_transferred = true;
    defer server.deinit();
    try server.serve(&echoHandler);

    const ca_pem = @embedFile("interop/testdata/quicz-echo-ca.pem");
    var ca_der_buffer: [1024]u8 = undefined;
    const ca_der = try quicz.tls_pem.decodeBlock(ca_pem, "CERTIFICATE", &ca_der_buffer);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.bytes.appendSlice(allocator, ca_der);
    try ca_bundle.parseCert(allocator, 0, std.Io.Clock.real.now(io).toSeconds());

    var client = try Client.initWithSocket(allocator, io, app_socket, .{
        .server_port = host_port,
        .server_name = "localhost",
        .alpn = &alpn,
        .ca_bundle = &ca_bundle,
        .active_migration_disabled = false,
    });
    app_socket_transferred = true;
    defer client.deinit();
    const payload = "authenticated P2P QUIC stream";
    if (!try client.runEchoSession(payload)) return error.EchoMismatch;
    if (client.localPort() != app_port or server.localPort() != host_port) return error.PortChanged;

    std.debug.print(
        "P2P QUIC: app={d} host={d} probe=authenticated tls=verified echo=ok\n",
        .{ app_port, host_port },
    );
}
