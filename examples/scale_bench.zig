//! Connection-scale benchmark on the production runtime.
//!
//! One `runtime.Server` (std.Io.Threaded) serves `NUM_CLIENTS` concurrent
//! connections. Each client performs a real TLS 1.3 handshake and a short
//! echo, then disconnects. Measures:
//!   - connection-establishment rate (concurrent handshakes through the
//!     single server drive task)
//!   - success / failure counts
//!
//! The benchmark uses optimized protocol code and a checked debug allocator.
//!   zig build run-scale-bench

const std = @import("std");
const test_certs = @import("test_certs.zig");
const quicz = @import("quicz");
const Server = quicz.runtime.server.Server;
const ServerConnection = quicz.runtime.server.ServerConnection;
const Client = quicz.runtime.client.Client;

const port: u16 = 4439;
const num_clients: usize = 500;
const echo_payload_len: usize = 1024;
const alpn = [_][]const u8{"hq-interop"};

const Result = struct {
    ok: bool = false,
    connect_ms: u64 = 0,
    stage: enum { init, connect, send, receive, done } = .init,
    failure: ?anyerror = null,
};

fn echoHandler(conn: ServerConnection) std.Io.Cancelable!void {
    var c = conn;
    while (true) {
        var stream = c.acceptStream() catch return;
        var buf: [65536]u8 = undefined;
        while (true) {
            const n = stream.receive(&buf) catch return;
            if (n == 0) break;
            stream.send(buf[0..n], false) catch return;
        }
    }
}

fn clientTask(io: std.Io, allocator: std.mem.Allocator, idx: usize, results: []Result) std.Io.Cancelable!void {
    var client = Client.init(allocator, io, .{
        .server_host = .{ 127, 0, 0, 1 },
        .server_port = port,
        .server_name = "localhost",
        .alpn = &alpn,
        .insecure_skip_verify = true,
    }) catch |err| {
        results[idx].failure = err;
        return;
    };
    defer client.deinit();

    const t0 = std.Io.Timestamp.now(io, .awake);
    results[idx].stage = .connect;
    client.connect() catch |err| {
        results[idx].failure = err;
        return;
    };
    const t1 = std.Io.Timestamp.now(io, .awake);
    results[idx].connect_ms = @intCast(std.Io.Duration.toMilliseconds(t0.durationTo(t1)));

    results[idx].stage = .send;
    const payload = allocator.alloc(u8, echo_payload_len) catch |err| {
        results[idx].failure = err;
        return;
    };
    defer allocator.free(payload);
    @memset(payload, @intCast('A' + @mod(idx, 26)));
    results[idx].stage = .send;
    const sid = client.send(payload, false) catch |err| {
        results[idx].failure = err;
        return;
    };
    results[idx].stage = .receive;
    var rbuf: [4096]u8 = undefined;
    var received: usize = 0;
    while (received < payload.len) {
        const n = client.receive(sid, &rbuf) catch |err| {
            results[idx].failure = err;
            return;
        };
        if (n == 0) break;
        if (n > payload.len - received or !std.mem.eql(u8, payload[received..][0..n], rbuf[0..n])) {
            results[idx].failure = error.EchoMismatch;
            return;
        }
        received += n;
    }
    results[idx].ok = received == payload.len;
    results[idx].stage = .done;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var gpa: std.heap.DebugAllocator(.{ .safety = true, .stack_trace_frames = 6 }) = .init;
    const allocator = gpa.allocator();

    var server = try Server.init(allocator, io, .{
        .port = port,
        .alpn = &alpn,
        .cert_der = &test_certs.cert_der,
        .private_key = &test_certs.private_key,
    });
    try server.serve(&echoHandler);

    const t0 = std.Io.Timestamp.now(io, .awake);
    var results: [num_clients]Result = @splat(Result{});
    var group: std.Io.Group = .init;
    for (0..num_clients) |i| {
        try group.concurrent(io, clientTask, .{ io, allocator, i, &results });
    }
    try group.await(io);
    const t1 = std.Io.Timestamp.now(io, .awake);

    server.stop();
    server.deinit();

    var ok_count: usize = 0;
    var total_connect_ms: u64 = 0;
    for (results, 0..) |r, index| {
        if (r.ok) ok_count += 1;
        if (!r.ok) std.debug.print("scale client {d}: stage={s} failure={s}\n", .{ index, @tagName(r.stage), if (r.failure) |err| @errorName(err) else "EchoMismatch" });
        total_connect_ms += r.connect_ms;
    }
    const seconds: f64 = @as(f64, @floatFromInt(std.Io.Duration.toMilliseconds(t0.durationTo(t1)))) / 1000.0;
    const rate: f64 = @as(f64, @floatFromInt(num_clients)) / seconds;
    std.debug.print("scale bench: clients={d} ok={d}/{d} total={d:.3}s rate={d:.0} conn/s avg_connect={d} ms\n", .{
        num_clients,                                                           ok_count, num_clients, seconds, rate,
        if (num_clients == 0) 0 else @divTrunc(total_connect_ms, num_clients),
    });

    const check = gpa.deinit();
    if (check != .ok) return error.MemoryLeak;
    if (ok_count != num_clients) return error.ScaleFailed;
}
