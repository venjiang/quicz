//! Long-run stability benchmark on the production runtime.
//!
//! One process, one `runtime.Server` (std.Io.Threaded) serving `NUM_CLIENTS`
//! concurrent connections. Each client repeatedly opens streams and echoes a
//! payload for `DURATION_MS` (steady-state transfer), then disconnects. All
//! allocations go through a `DebugAllocator`; a clean `gpa.deinit()` at the
//! end proves no leaks across the whole run, and the per-client stats expose
//! transfer volume / errors / throughput over the sustained window.
//!
//! Run with a Debug build (leak checking) or ReleaseFast (throughput):
//!   zig build run-stability-bench                  # Debug, leak-checked
//!   zig build run-stability-bench -Doptimize=ReleaseFast

const std = @import("std");
const test_certs = @import("test_certs.zig");
const quicz = @import("quicz");
const Server = quicz.runtime.server.Server;
const ServerConnection = quicz.runtime.server.ServerConnection;
const Client = quicz.runtime.client.Client;

const port: u16 = 4438;
const num_clients: usize = 4;
const payload_len: usize = 256 * 1024;
const duration_ms: u64 = 30_000;
/// Overridden by the first CLI argument (ms); default 30 s.
var g_run_duration_ms: u64 = duration_ms;
const alpn = [_][]const u8{"hq-interop"};

const Stats = struct {
    transfer_bytes: u64 = 0,
    errors: u64 = 0,
    ok: bool = false,
};

/// Server echo handler: one per connection (server.serve model); read the full
/// stream to EOF and echo every chunk back.
fn echoHandler(conn: ServerConnection) std.Io.Cancelable!void {
    var c = conn;
    // Serve every stream on this connection until it closes.
    while (true) {
        var stream = c.acceptStream() catch return;
        var buf: [65536]u8 = undefined;
        while (true) {
            const n = stream.receive(&buf) catch break;
            if (n == 0) {
                // Client sent FIN; echo-terminate so the client stream fully
                // completes and releases its stream slot.
                stream.send(&.{}, true) catch break;
                break;
            }
            stream.send(buf[0..n], false) catch break;
        }
    }
}

fn clientSession(io: std.Io, allocator: std.mem.Allocator, idx: usize, stats: []Stats) std.Io.Cancelable!void {
    var client = Client.init(allocator, io, .{
        .server_port = port,
        .server_name = "localhost",
        .alpn = &alpn,
        .insecure_skip_verify = true,
    }) catch {
        stats[idx].errors += 1;
        return;
    };
    _ = &client;
    defer client.deinit();

    client.connect() catch {
        stats[idx].errors += 1;
        return;
    };

    var payload = allocator.alloc(u8, payload_len) catch return;
    _ = &payload;
    defer allocator.free(payload);
    @memset(payload, @intCast('A' + @mod(idx, 26)));

    const t0 = std.Io.Timestamp.now(io, .awake);
    var transferred: u64 = 0;
    var errors: u64 = 0;
    while (true) {
        const now = std.Io.Timestamp.now(io, .awake);
        if (now.nanoseconds - t0.nanoseconds >= @as(i96, @intCast(g_run_duration_ms)) * 1_000_000) break;

        const sid = client.send(payload, true) catch {
            errors += 1;
            break;
        };
        var received: usize = 0;
        var rbuf: [65536]u8 = undefined;
        while (received < payload.len) {
            const n = client.receive(sid, &rbuf) catch break;
            if (n == 0) break;
            received += n;
        }
        if (received == payload.len) {
            // Consume the FIN so the stream completes and frees its slot.
            _ = client.receive(sid, &rbuf) catch {};
            transferred += payload.len;
        } else {
            errors += 1;
        }
    }
    stats[idx] = .{ .transfer_bytes = transferred, .errors = errors, .ok = true };
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    const allocator = gpa.allocator();

    // Optional first argument overrides the run duration in milliseconds
    // (default 30 s; use e.g. 3600000 for a one-hour soak).
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next(); // program name
    g_run_duration_ms = if (args.next()) |arg|
        std.fmt.parseInt(u64, arg, 10) catch duration_ms
    else
        duration_ms;

    var server = try Server.init(allocator, io, .{
        .port = port,
        .alpn = &alpn,
        .cert_der = &test_certs.cert_der,
        .private_key = &test_certs.private_key,
    });
    var server_deinited = false;
    errdefer if (!server_deinited) server.deinit();
    try server.serve(&echoHandler);
    std.debug.print("stability bench: server on 127.0.0.1:{d}, clients={d}, duration={d} ms\n", .{ port, num_clients, g_run_duration_ms });

    var stats: [num_clients]Stats = @splat(Stats{});
    var group: std.Io.Group = .init;
    for (0..num_clients) |i| {
        try group.concurrent(io, clientSession, .{ io, allocator, i, &stats });
    }
    try group.await(io);

    server.stop();
    const m = server.metricsSnapshot();
    std.debug.print("stability bench: metrics conns={d} sent={d}B recv={d}B loss={d} rt={d} srtt={d}us cwnd={d}B\n", .{ m.active_connections, m.stream_bytes_sent, m.stream_bytes_received, m.packets_lost, m.packets_retransmitted, m.smoothed_rtt_us, m.congestion_window });
    server.deinit();
    server_deinited = true;

    var total_bytes: u64 = 0;
    var total_errors: u64 = 0;
    var all_ok = true;
    for (stats, 0..) |s, i| {
        total_bytes += s.transfer_bytes;
        total_errors += s.errors;
        if (!s.ok or s.errors > 0) all_ok = false;
        std.debug.print("  client {d}: {d} bytes  {d} errors\n", .{ i, s.transfer_bytes, s.errors });
    }
    const seconds: f64 = @as(f64, @floatFromInt(g_run_duration_ms)) / 1000.0;
    std.debug.print(
        "stability bench: ok={} bytes={d} errors={d}  aggregate={d:.1} Mbit/s\n",
        .{ all_ok, total_bytes, total_errors, @as(f64, @floatFromInt(total_bytes)) * 8.0 / 1e6 / seconds },
    );

    // Leak check: any allocation not freed by server/client deinit is reported.
    const check = gpa.deinit();
    if (check != .ok) return error.MemoryLeak;
    if (!all_ok) return error.StabilityFailed;
}
