//! Multi-client concurrent connection benchmark on the production runtime.
//!
//! One `runtime.Server` (std.Io.Threaded) serves `NUM_CLIENTS` concurrent
//! `runtime.Client` connections. Measures:
//!   - per-client handshake time (wall clock, concurrent)
//!   - aggregate echo throughput (each client sends a payload and reads it back)
//!
//! Usage: zig build run-multi-client-bench
//!   (NUM_CLIENTS is fixed at comptime; edit below to change.)

const std = @import("std");
const test_certs = @import("test_certs.zig");
const quicz = @import("quicz");
const Server = quicz.runtime.server.Server;
const ServerConnection = quicz.runtime.server.ServerConnection;
const Client = quicz.runtime.client.Client;

const port: u16 = 4437;
const num_clients: usize = 8;
const echo_payload_len: usize = 64 * 1024;
const alpn = [_][]const u8{"hq-interop"};

const Result = struct {
    connect_ms: u64 = 0,
    throughput_mbps: f64 = 0,
    ok: bool = false,
};

/// Remote server address for the client tasks (loopback by default; set to a
/// peer container's IP in cross-host mode).
var g_server_host: [4]u8 = .{ 127, 0, 0, 1 };

fn parseIpv4(s: []const u8) ![4]u8 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| {
        if (i >= 4) return error.BadAddress;
        out[i] = try std.fmt.parseInt(u8, part, 10);
        i += 1;
    }
    if (i != 4) return error.BadAddress;
    return out;
}

/// Server echo handler: one per connection (server.serve model); read the full
/// stream to EOF and echo every chunk back.
fn echoHandler(conn: ServerConnection) std.Io.Cancelable!void {
    var c = conn;
    var stream = c.acceptStream() catch return;
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = stream.receive(&buf) catch return;
        if (n == 0) break;
        stream.send(buf[0..n], false) catch return;
    }
}

fn clientTask(io: std.Io, idx: usize, results: []Result) std.Io.Cancelable!void {
    var client = Client.init(std.heap.c_allocator, io, .{
        .server_host = g_server_host,
        .server_port = port,
        .server_name = "localhost",
        .alpn = &alpn,
        .insecure_skip_verify = true,
    }) catch {
        results[idx].ok = false;
        return;
    };
    defer client.deinit();

    const t0 = std.Io.Timestamp.now(io, .awake);
    client.connect() catch {
        results[idx].ok = false;
        return;
    };
    const t1 = std.Io.Timestamp.now(io, .awake);
    results[idx].connect_ms = @intCast(std.Io.Duration.toMilliseconds(t0.durationTo(t1)));

    // Echo a payload and read it all back.
    var payload = std.heap.c_allocator.alloc(u8, echo_payload_len) catch return;
    _ = &payload;
    defer std.heap.c_allocator.free(payload);
    @memset(payload, @intCast('A' + @mod(idx, 26)));
    const sid = client.send(payload, false) catch {
        results[idx].ok = false;
        return;
    };

    var rbuf: [65536]u8 = undefined;
    var received: usize = 0;
    while (received < payload.len) {
        const n = client.receive(sid, &rbuf) catch break;
        if (n == 0) break;
        received += n;
    }
    const t2 = std.Io.Timestamp.now(io, .awake);
    const seconds = @as(f64, @floatFromInt(std.Io.Duration.toNanoseconds(t1.durationTo(t2)))) / 1e9;
    results[idx].throughput_mbps = @as(f64, @floatFromInt(received)) * 8.0 / 1e6 / seconds;
    results[idx].ok = received == payload.len;
}

fn runClients(io: std.Io, host: [4]u8) !void {
    g_server_host = host;
    var results: [num_clients]Result = @splat(Result{});
    var group: std.Io.Group = .init;
    for (0..num_clients) |i| {
        try group.concurrent(io, clientTask, .{ io, i, &results });
    }
    try group.await(io);

    var total_ok: usize = 0;
    var sum_connect: u64 = 0;
    var sum_mbps: f64 = 0;
    for (results, 0..) |r, i| {
        if (r.ok) total_ok += 1;
        sum_connect += r.connect_ms;
        sum_mbps += r.throughput_mbps;
        std.debug.print("  client {d}: connect={d} ms  {d:.1} Mbit/s\n", .{ i, r.connect_ms, r.throughput_mbps });
    }
    std.debug.print(
        "multi-client bench: ok={d}/{d} avg_connect={d} ms  aggregate={d:.1} Mbit/s (host={}.{}.{}.{})\n",
        .{ total_ok, num_clients, sum_connect / num_clients, sum_mbps, host[0], host[1], host[2], host[3] },
    );
    if (total_ok != num_clients) return error.BenchFailed;
}

/// Modes:
///   (no args)   — loopback: server + N clients in one process
///   server      — server only, listening on 0.0.0.0 (run in a server container)
///   client HOST — N clients connecting to HOST (run in a client container)
pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var it = std.process.Args.Iterator.init(init.minimal.args);
    var mode: enum { loopback, server, client } = .loopback;
    var remote_host: [4]u8 = .{ 127, 0, 0, 1 };
    var idx: usize = 0;
    while (it.next()) |a| {
        if (idx == 1) {
            if (std.mem.eql(u8, a, "server")) {
                mode = .server;
            } else if (std.mem.eql(u8, a, "client")) {
                mode = .client;
            }
        } else if (idx == 2 and mode == .client) {
            remote_host = parseIpv4(a) catch remote_host;
        }
        idx += 1;
    }

    if (mode == .server) {
        var server = try Server.init(std.heap.c_allocator, io, .{
            .port = port,
            .alpn = &alpn,
            .cert_der = &test_certs.cert_der,
            .private_key = &test_certs.private_key,
            .bind_addr = .{ 0, 0, 0, 0 },
        });
        defer server.deinit();
        try server.serve(&echoHandler);
        std.debug.print("multi-client bench: server on 0.0.0.0:{d}\n", .{port});
        server.drive_group.await(io) catch {};
        return;
    }

    if (mode == .client) {
        std.debug.print("multi-client bench: client, {d} concurrent to {}.{}.{}.{}:{d}\n", .{
            num_clients, remote_host[0], remote_host[1], remote_host[2], remote_host[3], port,
        });
        try runClients(io, remote_host);
        return;
    }

    // Loopback: server + clients in one process.
    var server = try Server.init(std.heap.c_allocator, io, .{
        .port = port,
        .alpn = &alpn,
        .cert_der = &test_certs.cert_der,
        .private_key = &test_certs.private_key,
    });
    defer server.deinit();
    try server.serve(&echoHandler);
    std.debug.print("multi-client bench: server on 127.0.0.1:{d}, clients={d}\n", .{ port, num_clients });
    try runClients(io, .{ 127, 0, 0, 1 });
    server.stop();
}
