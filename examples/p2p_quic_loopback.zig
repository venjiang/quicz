//! Simulates rendezvous candidate exchange, authenticated bidirectional UDP
//! probing, and verified QUIC stream traffic on the same two sockets.

const std = @import("std");
const quicz = @import("quicz");
const test_certs = @import("test_certs.zig");

const Client = quicz.runtime.client.Client;
const Server = quicz.runtime.server.Server;
const ServerConnection = quicz.runtime.server.ServerConnection;
const punch_wire = quicz.connectivity.punch_wire;
const PunchAttempt = quicz.connectivity.punch_attempt.PunchAttempt;
const PunchState = quicz.connectivity.punch_attempt.State;

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
    key: punch_wire.Key,
) ![punch_wire.packet_length]u8 {
    var buffer: [256]u8 = undefined;
    const received = try socket.receiveTimeout(io, &buffer, .{ .duration = .{
        .clock = .awake,
        .raw = std.Io.Duration.fromMilliseconds(1_000),
    } });
    _ = try punch_wire.decode(key, received.data);
    if (received.data.len != punch_wire.packet_length) return error.InvalidPunchPacket;
    var packet: [punch_wire.packet_length]u8 = undefined;
    @memcpy(&packet, received.data);
    return packet;
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
    const attempt_id: punch_wire.AttemptId = .{0x11} ** 16;
    const key: punch_wire.Key = .{0x42} ** 32;
    var app_attempt = try PunchAttempt.init(key, attempt_id, .{0xa1} ** 16, .{});
    var host_attempt = try PunchAttempt.init(key, attempt_id, .{0xb2} ** 16, .{});
    const punch_started = std.Io.Timestamp.now(io, .awake);
    const app_probe = app_attempt.nextProbe(0).?;
    const host_probe = host_attempt.nextProbe(0).?;

    // Both peers send before either receives, matching simultaneous outbound
    // probing through stateful firewalls and NATs.
    try app_socket.send(io, &host_candidate, &app_probe);
    try host_socket.send(io, &app_candidate, &host_probe);
    const received_by_host = try receivePunch(io, host_socket, key);
    const received_by_app = try receivePunch(io, app_socket, key);
    const host_result = try host_attempt.receive(&received_by_host);
    const app_result = try app_attempt.receive(&received_by_app);
    try host_socket.send(io, &app_candidate, &host_result.acknowledgement.?);
    try app_socket.send(io, &host_candidate, &app_result.acknowledgement.?);
    const app_confirmation = try receivePunch(io, app_socket, key);
    const host_confirmation = try receivePunch(io, host_socket, key);
    _ = try app_attempt.receive(&app_confirmation);
    _ = try host_attempt.receive(&host_confirmation);
    if (app_attempt.state != PunchState.validated) return error.AppPathNotValidated;
    if (host_attempt.state != PunchState.validated) return error.HostPathNotValidated;
    const punch_finished = std.Io.Timestamp.now(io, .awake);

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
    const echo_started = std.Io.Timestamp.now(io, .awake);
    if (!try client.runEchoSession(payload)) return error.EchoMismatch;
    const echo_finished = std.Io.Timestamp.now(io, .awake);
    if (client.localPort() != app_port or server.localPort() != host_port) return error.PortChanged;

    std.debug.print(
        "P2P QUIC: app={d} host={d} probe_us={d} handshake_echo_us={d} tls=verified echo=ok\n",
        .{
            app_port,
            host_port,
            @divTrunc(punch_started.durationTo(punch_finished).nanoseconds, 1_000),
            @divTrunc(echo_started.durationTo(echo_finished).nanoseconds, 1_000),
        },
    );
}
