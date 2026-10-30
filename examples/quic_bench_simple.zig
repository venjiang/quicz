//! Simple single-threaded QUIC benchmark — no UDP sockets, measures raw QUIC processing.
//!
//! Usage: zig build run-quic-bench-simple

const std = @import("std");
const builtin = @import("builtin");
const quicz = @import("quicz");

const MachTimebaseInfo = extern struct { numer: u32, denom: u32 };
extern fn mach_timebase_info(info: *MachTimebaseInfo) i32;

var tb: MachTimebaseInfo = undefined;
var tb_init: bool = false;
var t0: u64 = 0;

fn nanoTime() u64 {
    if (comptime builtin.os.tag == .macos) {
        if (!tb_init) {
            _ = mach_timebase_info(&tb);
            t0 = std.c.mach_absolute_time();
            tb_init = true;
        }
        return (std.c.mach_absolute_time() - t0) * tb.numer / tb.denom;
    } else {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
        return @intCast(@as(i128, ts.sec) * 1_000_000_000 + ts.nsec);
    }
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    std.debug.print("=== quicz Simple Benchmark (single-thread, in-memory) ===\n\n", .{});

    const original_dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };

    var client = try quicz.Connection.init(allocator, .client, .{
        .initial_max_data = 256 * 1024 * 1024,
        .initial_max_stream_data = 256 * 1024 * 1024,
        .congestion_algorithm = .cubic,
    });
    var server = try quicz.Connection.init(allocator, .server, .{
        .initial_max_data = 256 * 1024 * 1024,
        .initial_max_stream_data = 256 * 1024 * 1024,
    });

    try client.installOneRttTrafficSecrets(.{ .local = secrets.client.secret, .peer = secrets.server.secret });
    try server.installOneRttTrafficSecrets(.{ .local = secrets.server.secret, .peer = secrets.client.secret });
    try client.confirmHandshake();
    try server.confirmHandshake();
    try server.validatePeerAddress();

    // --- Benchmark 1: Stream throughput (in-memory, no UDP) ---
    {
        std.debug.print("  --- Stream Upload (16 MB, in-memory) ---\n", .{});
        const transfer_size: usize = 16 * 1024 * 1024;
        const stream_id = try client.openStream();
        var payload: [1200]u8 = undefined;
        @memset(&payload, 'X');
        var read_buf: [65536]u8 = undefined;

        var total_sent: usize = 0;
        var total_received: usize = 0;
        var pn: usize = 0;
        _ = nanoTime(); // init timer

        const start = nanoTime();

        while (total_received < transfer_size) {
            // Client: queue + send
            var fed: usize = 0;
            while (total_sent < transfer_size and fed < 64) : (fed += 1) {
                const chunk = @min(payload.len, transfer_size - total_sent);
                const fin = total_sent + chunk >= transfer_size;
                client.sendOnStream(stream_id, payload[0..chunk], fin) catch break;
                total_sent += chunk;
            }

            // Client: poll datagrams → feed to server
            while (true) {
                const dg = client.pollProtectedShortDatagramWithInstalledKeys(
                    @intCast(nanoTime()),
                    &server_dcid,
                ) catch break orelse break;
                defer allocator.free(dg);
                pn += 1;
                _ = server.processProtectedShortDatagramWithInstalledKeys(
                    @intCast(nanoTime()),
                    client_dcid.len,
                    dg,
                ) catch {};
            }

            // Server: read stream data
            while (true) {
                const n = server.recvOnStream(stream_id, &read_buf) catch break orelse break;
                if (n == 0) break;
                total_received += n;
            }

            // Server: send ACKs → feed to client
            while (true) {
                const ack = server.pollProtectedShortDatagramWithInstalledKeys(
                    @intCast(nanoTime()),
                    &client_dcid,
                ) catch break orelse break;
                defer allocator.free(ack);
                _ = client.processProtectedShortDatagramWithInstalledKeys(
                    @intCast(nanoTime()),
                    server_dcid.len,
                    ack,
                ) catch {};
            }
        }

        const elapsed = nanoTime() - start;
        const seconds = @as(f64, @floatFromInt(elapsed)) / 1e9;
        const gbps = @as(f64, @floatFromInt(total_received)) / 1e9 / seconds;

        std.debug.print("  {s:20} {d:.2} GB/s  ({d} MB in {d:.3} ms, {d} pkts)\n", .{
            "Stream Upload",
            gbps,
            total_received / (1024 * 1024),
            @as(f64, @floatFromInt(elapsed)) / 1e6,
            pn,
        });
        std.debug.print("  {s:20} cwnd={d} KB\n\n", .{
            "Stats",
            client.recovery_state.congestion_window / 1024,
        });
    }

    // --- Benchmark 2: Echo latency ---
    {
        std.debug.print("  --- Echo Latency (1 KB roundtrip, in-memory) ---\n", .{});
        const echo_iters: usize = 5000;
        var echo_payload: [1024]u8 = undefined;
        @memset(&echo_payload, 'E');
        var echo_read: [2048]u8 = undefined;

        const echo_stream = try client.openStream();
        var latencies: [echo_iters]u64 = undefined;
        var echo_pn: i64 = 100000;

        for (0..echo_iters) |iter| {
            const t_start = nanoTime();

            // Client sends
            try client.sendOnStream(echo_stream, &echo_payload, false);
            while (true) {
                const dg = client.pollProtectedShortDatagramWithInstalledKeys(
                    @intCast(nanoTime()),
                    &server_dcid,
                ) catch break orelse break;
                defer allocator.free(dg);
                echo_pn += 1;
                _ = server.processProtectedShortDatagramWithInstalledKeys(
                    @intCast(nanoTime()),
                    client_dcid.len,
                    dg,
                ) catch {};
            }

            // Server reads + echoes
            _ = server.recvOnStream(echo_stream, &echo_read) catch {};
            try server.sendOnStream(echo_stream, &echo_payload, false);
            while (true) {
                const dg = server.pollProtectedShortDatagramWithInstalledKeys(
                    @intCast(nanoTime()),
                    &client_dcid,
                ) catch break orelse break;
                defer allocator.free(dg);
                echo_pn += 1;
                _ = client.processProtectedShortDatagramWithInstalledKeys(
                    @intCast(nanoTime()),
                    server_dcid.len,
                    dg,
                ) catch {};
            }

            // Client reads echo
            _ = client.recvOnStream(echo_stream, &echo_read) catch {};

            latencies[iter] = nanoTime() - t_start;
        }

        // Sort for percentiles
        std.mem.sort(u64, &latencies, {}, comptime std.sort.asc(u64));

        std.debug.print("  P50   = {d:.1} us\n", .{@as(f64, @floatFromInt(latencies[echo_iters * 50 / 100])) / 1000.0});
        std.debug.print("  P99   = {d:.1} us\n", .{@as(f64, @floatFromInt(latencies[echo_iters * 99 / 100])) / 1000.0});
        std.debug.print("  P99.9 = {d:.1} us\n", .{@as(f64, @floatFromInt(latencies[echo_iters * 999 / 1000])) / 1000.0});
    }

    // --- Benchmark 3: Multi-stream throughput ---
    {
        std.debug.print("  --- Multi-stream Upload (4 streams x 4 MB, in-memory) ---\n", .{});
        const num_streams: usize = 4;
        const per_stream: usize = 4 * 1024 * 1024;
        var ms_ids: [num_streams]u64 = undefined;
        for (0..num_streams) |si| {
            ms_ids[si] = try client.openStream();
        }
        var ms_payload: [1200]u8 = undefined;
        @memset(&ms_payload, 'M');
        var ms_read: [65536]u8 = undefined;
        var ms_queued: [num_streams]usize = @splat(0);
        var ms_total_recv: usize = 0;
        const ms_target = per_stream * num_streams;

        const ms_start = nanoTime();
        while (ms_total_recv < ms_target) {
            for (0..num_streams) |si| {
                var fed: usize = 0;
                while (ms_queued[si] < per_stream and fed < 16) : (fed += 1) {
                    const ch = @min(ms_payload.len, per_stream - ms_queued[si]);
                    const fin = ms_queued[si] + ch >= per_stream;
                    client.sendOnStream(ms_ids[si], ms_payload[0..ch], fin) catch break;
                    ms_queued[si] += ch;
                }
            }
            while (true) {
                const dg = client.pollProtectedShortDatagramWithInstalledKeys(
                    @intCast(nanoTime()),
                    &server_dcid,
                ) catch break orelse break;
                defer allocator.free(dg);
                _ = server.processProtectedShortDatagramWithInstalledKeys(
                    @intCast(nanoTime()),
                    client_dcid.len,
                    dg,
                ) catch {};
            }
            for (0..num_streams) |si| {
                while (true) {
                    const n = server.recvOnStream(ms_ids[si], &ms_read) catch break orelse break;
                    if (n == 0) break;
                    ms_total_recv += n;
                }
            }
            while (true) {
                const ack = server.pollProtectedShortDatagramWithInstalledKeys(
                    @intCast(nanoTime()),
                    &client_dcid,
                ) catch break orelse break;
                defer allocator.free(ack);
                _ = client.processProtectedShortDatagramWithInstalledKeys(
                    @intCast(nanoTime()),
                    server_dcid.len,
                    ack,
                ) catch {};
            }
        }
        const ms_elapsed = nanoTime() - ms_start;
        const ms_seconds = @as(f64, @floatFromInt(ms_elapsed)) / 1e9;
        const ms_gbps = @as(f64, @floatFromInt(ms_total_recv)) / 1e9 / ms_seconds;
        std.debug.print("  {s:20} {d:.2} GB/s  ({d} MB in {d:.3} ms)\n", .{
            "4-stream aggregate",
            ms_gbps,
            ms_total_recv / (1024 * 1024),
            @as(f64, @floatFromInt(ms_elapsed)) / 1e6,
        });
    }

    std.debug.print("\n  Done.\n", .{});
}
