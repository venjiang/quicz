//! Simulates rendezvous candidate exchange, authenticated bidirectional UDP
//! probing, and verified QUIC stream traffic on the same two sockets.

const std = @import("std");
const quicz = @import("quicz");

const Client = quicz.runtime.client.Client;
const Server = quicz.runtime.server.Server;
const ServerConnection = quicz.runtime.server.ServerConnection;
const punch_wire = quicz.connectivity.punch_wire;
const PunchAttempt = quicz.connectivity.punch_attempt.PunchAttempt;
const PunchState = quicz.connectivity.punch_attempt.State;
const punch_driver = quicz.connectivity.punch_driver;
const benchmark_rounds = 100;

fn echoHandler(connection: ServerConnection) std.Io.Cancelable!void {
    var mutable_connection = connection;
    var stream = mutable_connection.acceptStream() catch return;
    var buffer: [256]u8 = undefined;
    while (true) {
        const received = stream.receive(&buffer) catch return;
        if (received == 0) {
            stream.send(&.{}, true) catch {};
            return;
        }
        stream.send(buffer[0..received], false) catch return;
    }
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

    const now_seconds: u64 = @intCast(std.Io.Clock.real.now(io).toSeconds());
    var identity = try quicz.connectivity.ephemeral_identity.generate(allocator, io, now_seconds);
    defer identity.deinit(allocator);
    const alpn = [_][]const u8{"quicz-p2p-spike"};
    var server = try Server.initWithSocket(allocator, io, host_socket, .{
        .port = host_port,
        .alpn = &alpn,
        .cert_der = identity.certificate_der,
        .private_key = &identity.private_key_seed,
        .private_key_algorithm = .ed25519,
        .max_connections = 1,
    });
    host_socket_transferred = true;
    defer server.deinit();
    try server.serve(&echoHandler);

    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.bytes.appendSlice(allocator, identity.certificate_der);
    try ca_bundle.parseCert(allocator, 0, std.Io.Clock.real.now(io).toSeconds());

    var client = try Client.initWithSocket(allocator, io, app_socket, .{
        .server_port = host_port,
        .server_name = quicz.connectivity.ephemeral_identity.server_name,
        .alpn = &alpn,
        .ca_bundle = &ca_bundle,
        .active_migration_disabled = false,
    });
    app_socket_transferred = true;
    defer client.deinit();
    const handshake_started = std.Io.Timestamp.now(io, .awake);
    try client.connect();
    const handshake_finished = std.Io.Timestamp.now(io, .awake);
    const stream_id = try client.openStream();
    var roundtrip_microseconds: [benchmark_rounds]u64 = undefined;
    for (0..benchmark_rounds) |round| {
        var payload: [8]u8 = undefined;
        std.mem.writeInt(u64, &payload, round, .big);
        const round_started = std.Io.Timestamp.now(io, .awake);
        try client.sendOnStream(stream_id, &payload, round + 1 == benchmark_rounds);
        var response: [8]u8 = undefined;
        const received = try client.receive(stream_id, &response);
        const round_finished = std.Io.Timestamp.now(io, .awake);
        if (received != response.len or !std.mem.eql(u8, &payload, &response)) return error.EchoMismatch;
        roundtrip_microseconds[round] = @intCast(@divTrunc(
            round_started.durationTo(round_finished).nanoseconds,
            1_000,
        ));
    }
    if (client.localPort() != app_port or server.localPort() != host_port) return error.PortChanged;
    std.mem.sort(u64, &roundtrip_microseconds, {}, std.sort.asc(u64));

    std.debug.print(
        "P2P QUIC: rounds={d} app={d} host={d} probe_us={d} handshake_us={d} rtt_us_p50={d} rtt_us_p95={d} rtt_us_p99={d} tls=verified\n",
        .{
            benchmark_rounds,
            app_port,
            host_port,
            @divTrunc(punch_started.durationTo(punch_finished).nanoseconds, 1_000),
            @divTrunc(handshake_started.durationTo(handshake_finished).nanoseconds, 1_000),
            roundtrip_microseconds[49],
            roundtrip_microseconds[94],
            roundtrip_microseconds[98],
        },
    );
}
