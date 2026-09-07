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
const punch_driver = quicz.connectivity.punch_driver;

fn echoHandler(connection: ServerConnection) std.Io.Cancelable!void {
    var mutable_connection = connection;
    var stream = mutable_connection.acceptStream() catch return;
    var buffer: [256]u8 = undefined;
    const received = stream.receive(&buffer) catch return;
    stream.send(buffer[0..received], true) catch {};
}

const PunchContext = struct {
    io: std.Io,
    socket: std.Io.net.Socket,
    remote: std.Io.net.IpAddress,
    attempt: *PunchAttempt,
    failure: *?anyerror,
};

fn runPunch(context: PunchContext) std.Io.Cancelable!void {
    punch_driver.run(context.io, context.socket, context.remote, context.attempt) catch |err| {
        context.failure.* = err;
    };
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
    const app_candidate = app_socket.address;
    const host_candidate = host_socket.address;
    const attempt_id: punch_wire.AttemptId = .{0x11} ** 16;
    const key: punch_wire.Key = .{0x42} ** 32;
    var app_attempt = try PunchAttempt.init(key, attempt_id, .{0xa1} ** 16, .{});
    var host_attempt = try PunchAttempt.init(key, attempt_id, .{0xb2} ** 16, .{});
    const punch_started = std.Io.Timestamp.now(io, .awake);
    var app_failure: ?anyerror = null;
    var host_failure: ?anyerror = null;
    var punch_group: std.Io.Group = .init;
    try punch_group.concurrent(io, runPunch, .{PunchContext{
        .io = io,
        .socket = app_socket,
        .remote = host_candidate,
        .attempt = &app_attempt,
        .failure = &app_failure,
    }});
    try punch_group.concurrent(io, runPunch, .{PunchContext{
        .io = io,
        .socket = host_socket,
        .remote = app_candidate,
        .attempt = &host_attempt,
        .failure = &host_failure,
    }});
    punch_group.await(io) catch {};
    if (app_failure) |err| return err;
    if (host_failure) |err| return err;
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
