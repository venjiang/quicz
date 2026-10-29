//! Connection-scale benchmark on the production runtime.
//!
//! One `runtime.Server` (std.Io.Threaded) serves `NUM_CLIENTS` concurrent
//! connections. Each client performs a real TLS 1.3 handshake and a short
//! echo, then disconnects. Measures:
//!   - connection-establishment rate (concurrent handshakes through the
//!     single server drive task)
//!   - success / failure counts
//!
//! Run with a Debug build to also leak-check the whole run:
//!   zig build run-scale-bench                      # Debug, leak-checked
//!   zig build run-scale-bench -Doptimize=ReleaseFast

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
    }) catch return;
    defer client.deinit();

    const t0 = std.Io.Timestamp.now(io, .awake);
    client.connect() catch return;
    const t1 = std.Io.Timestamp.now(io, .awake);
    results[idx].connect_ms = @intCast(std.Io.Duration.toMilliseconds(t0.durationTo(t1)));

    const payload = allocator.alloc(u8, echo_payload_len) catch return;
    defer allocator.free(payload);
    @memset(payload, @intCast('A' + @mod(idx, 26)));
    const sid = client.send(payload, false) catch return;
    var rbuf: [4096]u8 = undefined;
    var received: usize = 0;
    while (received < payload.len) {
        const n = client.receive(sid, &rbuf) catch return;
        if (n == 0) break;
        received += n;
    }
    results[idx].ok = received == payload.len;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
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
    for (results) |r| {
        if (r.ok) ok_count += 1;
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
