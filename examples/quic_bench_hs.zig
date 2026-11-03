//! quicz benchmark with a REAL TLS 1.3 handshake (RFC 9000 §7 / RFC 9001 §4).
//!
//! The installed-keys bypass (quic_bench.zig) skips the handshake and therefore the
//! transport-parameter exchange (RFC 9000 §7.4); fresh bypass connections misbehave
//! across repeated transfers. This bench does a real handshake (pattern from
//! examples/interop_client.zig) for every measurement, and measures throughput with the
//! Multi-iteration model: N self-contained iterations, end-to-end, report mean/stddev.
const std = @import("std");
const builtin = @import("builtin");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
const server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };

const max_datagram_size: usize = 8900;
const stream_chunk_size: usize = max_datagram_size - 128;
const transfer_size: usize = 64 * 1024 * 1024;
const bench_iters: usize = 5;

fn nanoTime() u64 {
    if (comptime builtin.os.tag == .macos) {
        const MachTimebaseInfo = extern struct { numer: u32, denom: u32 };
        const mt = struct {
            extern fn mach_timebase_info(info: *MachTimebaseInfo) i32;
            extern fn mach_absolute_time() u64;
            var tb: MachTimebaseInfo = undefined;
            var inited: bool = false;
            var t0: u64 = 0;
        };
        if (!mt.inited) {
            _ = mt.mach_timebase_info(&mt.tb);
            mt.t0 = mt.mach_absolute_time();
            mt.inited = true;
        }
        return (mt.mach_absolute_time() - mt.t0) * mt.tb.numer / mt.tb.denom;
    } else {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
        return @intCast(@as(i128, ts.sec) * 1_000_000_000 + ts.nsec);
    }
}

fn bindLoopback(io: std.Io) !std.Io.net.Socket {
    var address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    return address.bind(io, .{ .mode = .dgram, .protocol = .udp });
}

fn hsRecvTimeout() std.Io.Timeout {
    return .{ .duration = .{ .clock = .awake, .raw = std.Io.Duration.fromMilliseconds(2000) } };
}

fn doHandshake(
    allocator: std.mem.Allocator,
    client: *Connection,
    server: *Connection,
    client_socket: *std.Io.net.Socket,
    server_socket: *std.Io.net.Socket,
    io: std.Io,
    client_backend: *Tls13Backend,
    server_backend: *Tls13Backend,
    scratch: []u8,
    recv_buf: []u8,
    secrets: protection.InitialSecrets,
) !void {
    _ = try client.driveCryptoBackendInSpace(.initial, client_backend.cryptoBackend(), scratch);
    const ch = (try client.pollProtectedLongCryptoDatagramInSpace(.initial, 40, &original_dcid, &client_scid, &[_]u8{}, secrets.client)) orelse return error.UnexpectedState;
    defer allocator.free(ch);
    try client_socket.send(io, &server_socket.address, ch);

    const r1 = try server_socket.receiveTimeout(io, recv_buf, hsRecvTimeout());
    try server.processProtectedLongDatagramInSpace(.initial, 41, secrets.client, r1.data);
    const s_prog = try server.driveCryptoBackendInSpace(.initial, server_backend.cryptoBackend(), scratch);
    if (!s_prog.handshake_keys_installed) return error.UnexpectedState;

    const sh = (try server.pollProtectedLongCryptoDatagramInSpace(.initial, 42, &client_scid, &server_scid, &[_]u8{}, secrets.server)) orelse return error.UnexpectedState;
    defer allocator.free(sh);
    try server_socket.send(io, &client_socket.address, sh);
    _ = try server.driveCryptoBackendInSpace(.handshake, server_backend.cryptoBackend(), scratch);
    const sf = (try server.pollProtectedHandshakeDatagramWithInstalledKeys(43, &client_scid, &server_scid)) orelse return error.UnexpectedState;
    defer allocator.free(sf);
    try server_socket.send(io, &client_socket.address, sf);

    const r2 = try client_socket.receiveTimeout(io, recv_buf, hsRecvTimeout());
    try client.processProtectedLongDatagramInSpace(.initial, 44, secrets.server, r2.data);
    _ = try client.driveCryptoBackendInSpace(.initial, client_backend.cryptoBackend(), scratch);

    const r3 = try client_socket.receiveTimeout(io, recv_buf, hsRecvTimeout());
    try client.processProtectedHandshakeDatagramWithInstalledKeys(45, r3.data);
    const c_prog = try client.driveCryptoBackendInSpace(.handshake, client_backend.cryptoBackend(), scratch);
    if (c_prog.outbound_bytes == 0) return error.UnexpectedState;
    const cf = (try client.pollProtectedHandshakeDatagramWithInstalledKeys(46, &server_scid, &client_scid)) orelse return error.UnexpectedState;
    defer allocator.free(cf);
    try client_socket.send(io, &server_socket.address, cf);

    const r4 = try server_socket.receiveTimeout(io, recv_buf, hsRecvTimeout());
    try server.processProtectedHandshakeDatagramWithInstalledKeys(47, r4.data);
    const s_drive = try server.driveCryptoBackendInSpace(.handshake, server_backend.cryptoBackend(), scratch);
    if (!s_drive.handshake_confirmed) return error.UnexpectedState;
}

const BenchBackends = struct {
    client: *Connection,
    server: *Connection,
    client_backend: *Tls13Backend,
    server_backend: *Tls13Backend,
    secrets: protection.InitialSecrets,
};

/// Create fresh client/server connections + TLS backends and run a real handshake.
/// Caller owns the returned connections (call deinit) and the sockets it passed in.
fn setupHandshakenPair(
    allocator: std.mem.Allocator,
    io: std.Io,
    client_socket: *std.Io.net.Socket,
    server_socket: *std.Io.net.Socket,
    scratch: []u8,
    hs_buf: []u8,
) !BenchBackends {
    const seed = @as([32]u8, @splat(0x55));
    const server_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const server_priv = server_kp.secret_key.bytes;
    const cert_der = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    const alpn = [_][]const u8{"bench"};
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    const client = try allocator.create(Connection);
    client.* = try Connection.init(allocator, .client, .{
        .initial_max_data = 256 * 1024 * 1024,
        .initial_max_stream_data = 256 * 1024 * 1024,
        .initial_max_streams_bidi = 64,
        .congestion_algorithm = .cubic,
        .max_datagram_size = max_datagram_size,
    });
    const server = try allocator.create(Connection);
    server.* = try Connection.init(allocator, .server, .{
        .initial_max_data = 256 * 1024 * 1024,
        .initial_max_stream_data = 256 * 1024 * 1024,
        .initial_max_streams_bidi = 64,
        .max_datagram_size = max_datagram_size,
    });
    try server.validatePeerAddress();

    const client_backend = try allocator.create(Tls13Backend);
    client_backend.* = Tls13Backend.initClient(.{ .alpn = &alpn, .server_name = "example.com", .skip_cert_verify = true });
    const server_backend = try allocator.create(Tls13Backend);
    server_backend.* = Tls13Backend.initServer(.{ .alpn = &alpn, .cert_chain_der = &.{&cert_der}, .private_key_bytes = &server_priv, .private_key_algorithm = .ecdsa_p256_sha256 });

    try client.setLocalInitialSourceConnectionId(&client_scid);
    try server.setLocalInitialSourceConnectionId(&server_scid);

    try doHandshake(allocator, client, server, client_socket, server_socket, io, client_backend, server_backend, scratch, hs_buf, secrets);
    return .{ .client = client, .server = server, .client_backend = client_backend, .server_backend = server_backend, .secrets = secrets };
}

const SrvCtx = struct {
    socket: *std.Io.net.Socket,
    io: std.Io,
    server: *Connection,
    done: *std.atomic.Value(bool),
    bytes_received: *std.atomic.Value(usize),
    client_addr: std.Io.net.IpAddress,
    num_streams: usize,
};

/// Server transfer thread: receives 1-RTT datagrams, reads client-initiated bidi
/// streams (0,4,...,4*(num_streams-1)), ACKs.
fn serverTransferThread(ctx: *SrvCtx) void {
    var recv_buf: [9000]u8 = undefined;
    var read_buf: [65536]u8 = undefined;
    var have_client_addr = false;
    while (!ctx.done.load(.acquire)) {
        var received_any = false;
        while (true) {
            const received = ctx.socket.receiveTimeout(ctx.io, &recv_buf, .{ .duration = .{ .clock = .awake, .raw = std.Io.Duration.fromMicroseconds(100) } }) catch break;
            if (!have_client_addr) {
                ctx.client_addr = received.from;
                have_client_addr = true;
            }
            _ = ctx.server.processProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), client_scid.len, received.data) catch {};
            received_any = true;
        }
        if (!received_any) continue;
        var si: usize = 0;
        while (si < ctx.num_streams) : (si += 1) {
            while (true) {
                const n = ctx.server.recvOnStream(@intCast(si * 4), &read_buf) catch break orelse break;
                if (n == 0) break;
                _ = ctx.bytes_received.fetchAdd(n, .monotonic);
            }
        }
        if (have_client_addr) {
            while (true) {
                const ack_dg = ctx.server.pollProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), &client_scid) catch break orelse break;
                defer ctx.server.allocator.free(ack_dg);
                ctx.socket.send(ctx.io, &ctx.client_addr, ack_dg) catch break;
            }
        }
    }
}

const LossCtx = struct {
    socket: *std.Io.net.Socket,
    io: std.Io,
    server: *Connection,
    done: *std.atomic.Value(bool),
    bytes_received: *std.atomic.Value(usize),
    client_addr: std.Io.net.IpAddress,
    drop_pct: usize,
    rtt_us: u64,
    rng_state: *u64,
};

/// Server thread with simulated random loss (xorshift PRNG) and optional RTT delay.
fn serverLossThread(ctx: *LossCtx) void {
    var recv_buf: [9000]u8 = undefined;
    var read_buf: [65536]u8 = undefined;
    var have_client_addr = false;
    while (!ctx.done.load(.acquire)) {
        var received_any = false;
        while (true) {
            const received = ctx.socket.receiveTimeout(ctx.io, &recv_buf, .{ .duration = .{ .clock = .awake, .raw = std.Io.Duration.fromMicroseconds(100) } }) catch break;
            if (!have_client_addr) {
                ctx.client_addr = received.from;
                have_client_addr = true;
            }
            ctx.rng_state.* ^= ctx.rng_state.* << 13;
            ctx.rng_state.* ^= ctx.rng_state.* >> 7;
            ctx.rng_state.* ^= ctx.rng_state.* << 17;
            if (ctx.rng_state.* % 100 < ctx.drop_pct) continue;
            if (ctx.rtt_us > 0) {
                const deadline = nanoTime() + ctx.rtt_us * 500;
                while (nanoTime() < deadline) {}
            }
            _ = ctx.server.processProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), client_scid.len, received.data) catch {};
            received_any = true;
        }
        if (!received_any) continue;
        while (true) {
            const n = ctx.server.recvOnStream(0, &read_buf) catch break orelse break;
            if (n == 0) break;
            _ = ctx.bytes_received.fetchAdd(n, .monotonic);
        }
        if (have_client_addr) {
            while (true) {
                const ack_dg = ctx.server.pollProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), &client_scid) catch break orelse break;
                defer ctx.server.allocator.free(ack_dg);
                ctx.socket.send(ctx.io, &ctx.client_addr, ack_dg) catch break;
            }
        }
    }
}

fn runTransfer(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *Connection,
    client_socket: *std.Io.net.Socket,
    server_addr: *const std.Io.net.IpAddress,
    bytes_received: *std.atomic.Value(usize),
    stream_id: u64,
    size: usize,
) f64 {
    var payload: [stream_chunk_size]u8 = undefined;
    @memset(&payload, 'X');
    var recv_buf: [9000]u8 = undefined;
    var total_queued: usize = 0;
    const start_ns = nanoTime();
    while (total_queued < size) {
        var fed: usize = 0;
        while (total_queued < size and fed < 256) : (fed += 1) {
            const chunk = @min(payload.len, size - total_queued);
            const fin = total_queued + chunk >= size;
            client.sendOnStream(stream_id, payload[0..chunk], fin) catch break;
            total_queued += chunk;
        }
        while (true) {
            const dg = client.pollProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), &server_scid) catch break orelse break;
            defer allocator.free(dg);
            client_socket.send(io, server_addr, dg) catch break;
        }
        while (true) {
            const ack = client_socket.receiveTimeout(io, &recv_buf, .{ .duration = .{ .clock = .awake, .raw = std.Io.Duration.fromMicroseconds(100) } }) catch break;
            _ = client.processProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), server_scid.len, ack.data) catch {};
        }
        // RFC 9002 §6.2: service the loss detection timer so delayed/lost ACKs
        // trigger PTO retransmission instead of stalling the transfer.
        _ = client.serviceLossDetectionTimer(@intCast(nanoTime())) catch {};
    }
    var wait: usize = 0;
    while (bytes_received.load(.monotonic) < size and wait < 10_000_000) : (wait += 1) {
        while (true) {
            const dg = client.pollProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), &server_scid) catch break orelse break;
            defer allocator.free(dg);
            client_socket.send(io, server_addr, dg) catch break;
        }
        while (true) {
            const ack = client_socket.receiveTimeout(io, &recv_buf, .{ .duration = .{ .clock = .awake, .raw = std.Io.Duration.fromMicroseconds(100) } }) catch break;
            _ = client.processProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), server_scid.len, ack.data) catch {};
        }
        _ = client.serviceLossDetectionTimer(@intCast(nanoTime())) catch {};
    }
    const elapsed = nanoTime() - start_ns;
    const seconds = @as(f64, @floatFromInt(elapsed)) / 1_000_000_000.0;
    return @as(f64, @floatFromInt(size)) / (1024.0 * 1024.0) / seconds;
}

fn measureSingleStream(allocator: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("\n  --- Single-Stream Throughput (real handshake) ---\n", .{});
    var tp_samples: [bench_iters]f64 = undefined;
    var it: usize = 0;
    while (it < bench_iters) : (it += 1) {
        var client_socket = try bindLoopback(io);
        defer client_socket.close(io);
        var server_socket = try bindLoopback(io);
        defer server_socket.close(io);
        const server_addr = server_socket.address;
        var scratch: [16384]u8 = undefined;
        var hs_buf: [16384]u8 = undefined;
        const pair = try setupHandshakenPair(allocator, io, &client_socket, &server_socket, &scratch, &hs_buf);
        defer {
            pair.client.deinit();
            pair.server.deinit();
            allocator.destroy(pair.client);
            allocator.destroy(pair.server);
            allocator.destroy(pair.client_backend);
            allocator.destroy(pair.server_backend);
        }
        var done = std.atomic.Value(bool).init(false);
        var bytes_received = std.atomic.Value(usize).init(0);
        var srv_ctx = SrvCtx{ .socket = &server_socket, .io = io, .server = pair.server, .done = &done, .bytes_received = &bytes_received, .client_addr = client_socket.address, .num_streams = 1 };
        const srv_thread = try std.Thread.spawn(.{}, serverTransferThread, .{&srv_ctx});
        const stream_id = try pair.client.openStream();
        const tp = runTransfer(allocator, io, pair.client, &client_socket, &server_addr, &bytes_received, stream_id, transfer_size);
        done.store(true, .release);
        srv_thread.join();
        tp_samples[it] = tp;
        std.debug.print("  [iter {d}] {d:.2} MB/s\n", .{ it, tp_samples[it] });
    }
    var mean: f64 = 0;
    for (tp_samples) |s| mean += s;
    mean /= @as(f64, @floatFromInt(bench_iters));
    var var_acc: f64 = 0;
    for (tp_samples) |s| {
        const d = s - mean;
        var_acc += d * d;
    }
    const stddev = @sqrt(var_acc / @as(f64, @floatFromInt(bench_iters)));
    std.debug.print("  {s:20} {d:.2} MB/s  (stddev {d:.1}%, {d} iters x {d} MB)\n", .{ "Stream Upload", mean, stddev * 100.0 / mean, bench_iters, transfer_size / (1024 * 1024) });
}

fn measureEcho(allocator: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("\n  --- Echo Latency (1 KB roundtrip, real handshake) ---\n", .{});
    var client_socket = try bindLoopback(io);
    defer client_socket.close(io);
    var server_socket = try bindLoopback(io);
    defer server_socket.close(io);
    const server_addr = server_socket.address;
    var scratch: [16384]u8 = undefined;
    var hs_buf: [16384]u8 = undefined;
    const pair = try setupHandshakenPair(allocator, io, &client_socket, &server_socket, &scratch, &hs_buf);
    defer {
        pair.client.deinit();
        pair.server.deinit();
        allocator.destroy(pair.client);
        allocator.destroy(pair.server);
        allocator.destroy(pair.client_backend);
        allocator.destroy(pair.server_backend);
    }
    const echo_iters: usize = 5000;
    var echo_payload: [1024]u8 = undefined;
    @memset(&echo_payload, 'E');
    var echo_rb: [9000]u8 = undefined;
    var echo_read: [2048]u8 = undefined;
    const echo_stream = try pair.client.openStream();
    var latencies: [echo_iters]u64 = undefined;
    for (0..echo_iters) |iter| {
        const t0 = nanoTime();
        try pair.client.sendOnStream(echo_stream, &echo_payload, false);
        if (try pair.client.pollProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), &server_scid)) |dg| {
            defer allocator.free(dg);
            try client_socket.send(io, &server_addr, dg);
        }
        const srv_r = server_socket.receiveTimeout(io, &echo_rb, .{ .duration = .{ .clock = .awake, .raw = std.Io.Duration.fromMilliseconds(5) } }) catch continue;
        _ = pair.server.processProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), client_scid.len, srv_r.data) catch continue;
        _ = pair.server.recvOnStream(echo_stream, &echo_read) catch {};
        try pair.server.sendOnStream(echo_stream, &echo_payload, false);
        if (try pair.server.pollProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), &client_scid)) |dg| {
            defer allocator.free(dg);
            try server_socket.send(io, &client_socket.address, dg);
        }
        const cli_r = client_socket.receiveTimeout(io, &echo_rb, .{ .duration = .{ .clock = .awake, .raw = std.Io.Duration.fromMilliseconds(5) } }) catch continue;
        _ = pair.client.processProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), server_scid.len, cli_r.data) catch {};
        _ = pair.client.recvOnStream(echo_stream, &echo_read) catch {};
        latencies[iter] = nanoTime() - t0;
    }
    std.mem.sort(u64, &latencies, {}, std.sort.asc(u64));
    std.debug.print("  {s:20} P50={d:.1}us  P99={d:.1}us  P99.9={d:.1}us  ({d} iters)\n", .{
        "Echo Latency",
        @as(f64, @floatFromInt(latencies[echo_iters * 50 / 100])) / 1000.0,
        @as(f64, @floatFromInt(latencies[echo_iters * 99 / 100])) / 1000.0,
        @as(f64, @floatFromInt(latencies[echo_iters * 999 / 1000])) / 1000.0,
        echo_iters,
    });
}

fn measureMultiStream(allocator: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("\n  --- Multi-Stream Throughput (4 streams, real handshake) ---\n", .{});
    const num_streams: usize = 4;
    const ms_size: usize = 64 * 1024 * 1024;
    const per_stream: usize = ms_size / num_streams;
    var tp_samples: [bench_iters]f64 = undefined;
    var it: usize = 0;
    while (it < bench_iters) : (it += 1) {
        var client_socket = try bindLoopback(io);
        defer client_socket.close(io);
        var server_socket = try bindLoopback(io);
        defer server_socket.close(io);
        const server_addr = server_socket.address;
        var scratch: [16384]u8 = undefined;
        var hs_buf: [16384]u8 = undefined;
        const pair = try setupHandshakenPair(allocator, io, &client_socket, &server_socket, &scratch, &hs_buf);
        defer {
            pair.client.deinit();
            pair.server.deinit();
            allocator.destroy(pair.client);
            allocator.destroy(pair.server);
            allocator.destroy(pair.client_backend);
            allocator.destroy(pair.server_backend);
        }
        var done = std.atomic.Value(bool).init(false);
        var bytes_received = std.atomic.Value(usize).init(0);
        var srv_ctx = SrvCtx{ .socket = &server_socket, .io = io, .server = pair.server, .done = &done, .bytes_received = &bytes_received, .client_addr = client_socket.address, .num_streams = num_streams };
        const srv_thread = try std.Thread.spawn(.{}, serverTransferThread, .{&srv_ctx});

        var ids: [num_streams]u64 = undefined;
        for (0..num_streams) |si| ids[si] = try pair.client.openStream();
        var payload: [stream_chunk_size]u8 = undefined;
        @memset(&payload, 'M');
        var recv_buf: [9000]u8 = undefined;
        var queued: [num_streams]usize = .{ 0, 0, 0, 0 };
        var total_q: usize = 0;
        const t0 = nanoTime();
        while (total_q < ms_size) {
            for (0..num_streams) |si| {
                if (queued[si] >= per_stream) continue;
                var f: usize = 0;
                while (queued[si] < per_stream and f < 64) : (f += 1) {
                    const ch = @min(payload.len, per_stream - queued[si]);
                    pair.client.sendOnStream(ids[si], payload[0..ch], queued[si] + ch >= per_stream) catch break;
                    queued[si] += ch;
                    total_q += ch;
                }
            }
            while (true) {
                const dg = pair.client.pollProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), &server_scid) catch break orelse break;
                defer allocator.free(dg);
                client_socket.send(io, &server_addr, dg) catch break;
            }
            while (true) {
                const a = client_socket.receiveTimeout(io, &recv_buf, .{ .duration = .{ .clock = .awake, .raw = std.Io.Duration.fromMicroseconds(100) } }) catch break;
                _ = pair.client.processProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), server_scid.len, a.data) catch {};
            }
        }
        var w: usize = 0;
        while (bytes_received.load(.monotonic) < ms_size and w < 5_000_000) : (w += 1) {
            while (true) {
                const dg = pair.client.pollProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), &server_scid) catch break orelse break;
                defer allocator.free(dg);
                client_socket.send(io, &server_addr, dg) catch break;
            }
            while (true) {
                const a = client_socket.receiveTimeout(io, &recv_buf, .{ .duration = .{ .clock = .awake, .raw = std.Io.Duration.fromMicroseconds(100) } }) catch break;
                _ = pair.client.processProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), server_scid.len, a.data) catch {};
            }
        }
        const elapsed = nanoTime() - t0;
        done.store(true, .release);
        srv_thread.join();
        const seconds = @as(f64, @floatFromInt(elapsed)) / 1_000_000_000.0;
        tp_samples[it] = @as(f64, @floatFromInt(ms_size)) / (1024.0 * 1024.0) / seconds;
        std.debug.print("  [iter {d}] {d:.2} MB/s\n", .{ it, tp_samples[it] });
    }
    var mean: f64 = 0;
    for (tp_samples) |s| mean += s;
    mean /= @as(f64, @floatFromInt(bench_iters));
    var var_acc: f64 = 0;
    for (tp_samples) |s| {
        const d = s - mean;
        var_acc += d * d;
    }
    const stddev = @sqrt(var_acc / @as(f64, @floatFromInt(bench_iters)));
    std.debug.print("  {s:20} {d:.2} MB/s  (stddev {d:.1}%, {d} iters x {d} MB, {d} streams)\n", .{ "Multi-Stream (4x)", mean, stddev * 100.0 / mean, bench_iters, ms_size / (1024 * 1024), num_streams });
}

fn measureLoss(allocator: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("\n  --- Loss Recovery (real handshake, simulated loss) ---\n", .{});
    const loss_rates = [_]struct { pct: usize, rtt_us: u64, label: []const u8 }{
        .{ .pct = 1, .rtt_us = 0, .label = "1% loss (loopback)" },
        .{ .pct = 5, .rtt_us = 0, .label = "5% loss (loopback)" },
        .{ .pct = 1, .rtt_us = 100, .label = "1% loss (100us RTT)" },
        .{ .pct = 5, .rtt_us = 100, .label = "5% loss (100us RTT)" },
    };
    const loss_transfer: usize = 4 * 1024 * 1024;
    var rng_state: u64 = 0x12345678;
    for (loss_rates) |lr| {
        var client_socket = try bindLoopback(io);
        defer client_socket.close(io);
        var server_socket = try bindLoopback(io);
        defer server_socket.close(io);
        const server_addr = server_socket.address;
        var scratch: [16384]u8 = undefined;
        var hs_buf: [16384]u8 = undefined;
        const pair = try setupHandshakenPair(allocator, io, &client_socket, &server_socket, &scratch, &hs_buf);
        defer {
            pair.client.deinit();
            pair.server.deinit();
            allocator.destroy(pair.client);
            allocator.destroy(pair.server);
            allocator.destroy(pair.client_backend);
            allocator.destroy(pair.server_backend);
        }
        var done = std.atomic.Value(bool).init(false);
        var bytes_received = std.atomic.Value(usize).init(0);
        var loss_ctx = LossCtx{ .socket = &server_socket, .io = io, .server = pair.server, .done = &done, .bytes_received = &bytes_received, .client_addr = client_socket.address, .drop_pct = lr.pct, .rtt_us = lr.rtt_us, .rng_state = &rng_state };
        const loss_thr = try std.Thread.spawn(.{}, serverLossThread, .{&loss_ctx});
        const stream_id = try pair.client.openStream();
        const mbps = runTransfer(allocator, io, pair.client, &client_socket, &server_addr, &bytes_received, stream_id, loss_transfer);
        done.store(true, .release);
        loss_thr.join();
        std.debug.print("  {s:22} {d:.2} MB/s  ({d} MB)\n", .{ lr.label, mbps, loss_transfer / (1024 * 1024) });
    }
}

/// One real handshake on fresh stack connections; returns elapsed nanoseconds.
fn measureOneHandshakeNs(allocator: std.mem.Allocator, io: std.Io) !u64 {
    var client_socket = try bindLoopback(io);
    defer client_socket.close(io);
    var server_socket = try bindLoopback(io);
    defer server_socket.close(io);

    const seed = @as([32]u8, @splat(0x55));
    const server_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const server_priv = server_kp.secret_key.bytes;
    const cert_der = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    const alpn = [_][]const u8{"bench"};
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try Connection.init(allocator, .client, .{
        .initial_max_data = 256 * 1024 * 1024,
        .initial_max_stream_data = 256 * 1024 * 1024,
        .initial_max_streams_bidi = 64,
        .congestion_algorithm = .cubic,
        .max_datagram_size = max_datagram_size,
    });
    defer client.deinit();
    var server = try Connection.init(allocator, .server, .{
        .initial_max_data = 256 * 1024 * 1024,
        .initial_max_stream_data = 256 * 1024 * 1024,
        .initial_max_streams_bidi = 64,
        .max_datagram_size = max_datagram_size,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    var client_backend = Tls13Backend.initClient(.{ .alpn = &alpn, .server_name = "example.com", .skip_cert_verify = true });
    var server_backend = Tls13Backend.initServer(.{ .alpn = &alpn, .cert_chain_der = &.{&cert_der}, .private_key_bytes = &server_priv, .private_key_algorithm = .ecdsa_p256_sha256 });

    var scratch: [16384]u8 = undefined;
    var hs_buf: [16384]u8 = undefined;
    try client.setLocalInitialSourceConnectionId(&client_scid);
    try server.setLocalInitialSourceConnectionId(&server_scid);

    const t0 = nanoTime();
    try doHandshake(allocator, &client, &server, &client_socket, &server_socket, io, &client_backend, &server_backend, &scratch, &hs_buf, secrets);
    return nanoTime() - t0;
}

fn measureHandshakeLatency(allocator: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("\n  --- Handshake Latency (real TLS 1.3) ---\n", .{});
    const iters: usize = 200;
    var latencies: [iters]u64 = undefined;
    for (0..iters) |i| latencies[i] = try measureOneHandshakeNs(allocator, io);
    std.mem.sort(u64, &latencies, {}, std.sort.asc(u64));
    std.debug.print("  {s:20} P50={d:.1}us  P99={d:.1}us  ({d} iters)\n", .{
        "Handshake Latency",
        @as(f64, @floatFromInt(latencies[iters * 50 / 100])) / 1000.0,
        @as(f64, @floatFromInt(latencies[iters * 99 / 100])) / 1000.0,
        iters,
    });
}

fn measureHandshakeRate(allocator: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("\n  --- Handshake Throughput (new connections/s) ---\n", .{});
    const iters: usize = 100;
    const t0 = nanoTime();
    var i: usize = 0;
    while (i < iters) : (i += 1) _ = try measureOneHandshakeNs(allocator, io);
    const elapsed = nanoTime() - t0;
    const seconds = @as(f64, @floatFromInt(elapsed)) / 1_000_000_000.0;
    std.debug.print("  {s:20} {d:.1} conn/s  ({d} handshakes in {d:.3} s)\n", .{
        "Handshake Rate",
        @as(f64, @floatFromInt(iters)) / seconds,
        iters,
        seconds,
    });
}

fn measureStreamChurn(allocator: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("\n  --- Stream Churn (open rate, real handshake) ---\n", .{});
    var client_socket = try bindLoopback(io);
    defer client_socket.close(io);
    var server_socket = try bindLoopback(io);
    defer server_socket.close(io);

    const seed = @as([32]u8, @splat(0x55));
    const server_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const server_priv = server_kp.secret_key.bytes;
    const cert_der = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    const alpn = [_][]const u8{"bench"};
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try Connection.init(allocator, .client, .{
        .initial_max_data = 256 * 1024 * 1024,
        .initial_max_stream_data = 256 * 1024 * 1024,
        .initial_max_streams_bidi = 1_048_576,
        .congestion_algorithm = .cubic,
        .max_datagram_size = max_datagram_size,
    });
    defer client.deinit();
    var server = try Connection.init(allocator, .server, .{
        .initial_max_data = 256 * 1024 * 1024,
        .initial_max_stream_data = 256 * 1024 * 1024,
        .initial_max_streams_bidi = 1_048_576,
        .max_datagram_size = max_datagram_size,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    var client_backend = Tls13Backend.initClient(.{ .alpn = &alpn, .server_name = "example.com", .skip_cert_verify = true });
    var server_backend = Tls13Backend.initServer(.{ .alpn = &alpn, .cert_chain_der = &.{&cert_der}, .private_key_bytes = &server_priv, .private_key_algorithm = .ecdsa_p256_sha256 });

    var scratch: [16384]u8 = undefined;
    var hs_buf: [16384]u8 = undefined;
    try client.setLocalInitialSourceConnectionId(&client_scid);
    try server.setLocalInitialSourceConnectionId(&server_scid);
    try doHandshake(allocator, &client, &server, &client_socket, &server_socket, io, &client_backend, &server_backend, &scratch, &hs_buf, secrets);

    const iters: usize = 100_000;
    const t0 = nanoTime();
    var i: usize = 0;
    while (i < iters) : (i += 1) {
        const stream_id = client.openStream() catch break;
        _ = stream_id;
    }
    const elapsed = nanoTime() - t0;
    const seconds = @as(f64, @floatFromInt(elapsed)) / 1_000_000_000.0;
    std.debug.print("  {s:20} {d:.0} streams/s  ({d} opened in {d:.3} s)\n", .{
        "Stream Open Rate",
        @as(f64, @floatFromInt(i)) / seconds,
        i,
        seconds,
    });
}

/// Server thread that drains received DATAGRAM frames (RFC 9221) and counts bytes.
fn serverDatagramThread(ctx: *SrvCtx) void {
    var recv_buf: [9000]u8 = undefined;
    var read_buf: [9000]u8 = undefined;
    var have_client_addr = false;
    while (!ctx.done.load(.acquire)) {
        var received_any = false;
        while (true) {
            const received = ctx.socket.receiveTimeout(ctx.io, &recv_buf, .{ .duration = .{ .clock = .awake, .raw = std.Io.Duration.fromMicroseconds(100) } }) catch break;
            if (!have_client_addr) {
                ctx.client_addr = received.from;
                have_client_addr = true;
            }
            _ = ctx.server.processProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), client_scid.len, received.data) catch {};
            received_any = true;
        }
        if (!received_any) continue;
        while (true) {
            const n = ctx.server.recvDatagram(&read_buf) catch break orelse break;
            if (n == 0) break;
            _ = ctx.bytes_received.fetchAdd(n, .monotonic);
        }
        if (have_client_addr) {
            while (true) {
                const ack_dg = ctx.server.pollProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), &client_scid) catch break orelse break;
                defer ctx.server.allocator.free(ack_dg);
                ctx.socket.send(ctx.io, &ctx.client_addr, ack_dg) catch break;
            }
        }
    }
}

/// DATAGRAM (RFC 9221) throughput over a real handshake. max_datagram_frame_size is
/// negotiated via the transport parameter during the handshake.
fn measureDatagram(allocator: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("\n  --- DATAGRAM Throughput (RFC 9221, real handshake) ---\n", .{});
    const dgram_payload: usize = 1200;
    const total_bytes: usize = 4 * 1024 * 1024;

    var client_socket = try bindLoopback(io);
    defer client_socket.close(io);
    var server_socket = try bindLoopback(io);
    defer server_socket.close(io);
    const server_addr = server_socket.address;

    const seed = @as([32]u8, @splat(0x55));
    const server_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const server_priv = server_kp.secret_key.bytes;
    const cert_der = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    const alpn = [_][]const u8{"bench"};
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try Connection.init(allocator, .client, .{
        .initial_max_data = 256 * 1024 * 1024,
        .initial_max_stream_data = 256 * 1024 * 1024,
        .initial_max_streams_bidi = 64,
        .congestion_algorithm = .cubic,
        .max_datagram_size = max_datagram_size,
        .max_datagram_frame_size = max_datagram_size,
    });
    defer client.deinit();
    var server = try Connection.init(allocator, .server, .{
        .initial_max_data = 256 * 1024 * 1024,
        .initial_max_stream_data = 256 * 1024 * 1024,
        .initial_max_streams_bidi = 64,
        .max_datagram_size = max_datagram_size,
        .max_datagram_frame_size = max_datagram_size,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    var client_backend = Tls13Backend.initClient(.{ .alpn = &alpn, .server_name = "example.com", .skip_cert_verify = true });
    var server_backend = Tls13Backend.initServer(.{ .alpn = &alpn, .cert_chain_der = &.{&cert_der}, .private_key_bytes = &server_priv, .private_key_algorithm = .ecdsa_p256_sha256 });

    var scratch: [16384]u8 = undefined;
    var hs_buf: [16384]u8 = undefined;
    try client.setLocalInitialSourceConnectionId(&client_scid);
    try server.setLocalInitialSourceConnectionId(&server_scid);
    try doHandshake(allocator, &client, &server, &client_socket, &server_socket, io, &client_backend, &server_backend, &scratch, &hs_buf, secrets);

    var done = std.atomic.Value(bool).init(false);
    var bytes_received = std.atomic.Value(usize).init(0);
    var srv_ctx = SrvCtx{ .socket = &server_socket, .io = io, .server = &server, .done = &done, .bytes_received = &bytes_received, .client_addr = client_socket.address, .num_streams = 1 };
    const srv_thread = try std.Thread.spawn(.{}, serverDatagramThread, .{&srv_ctx});

    var payload: [dgram_payload]u8 = undefined;
    @memset(&payload, 'D');
    var recv_buf: [9000]u8 = undefined;
    var sent: usize = 0;
    const t0 = nanoTime();
    while (sent < total_bytes) {
        var burst: usize = 0;
        while (sent < total_bytes and burst < 64) : (burst += 1) {
            client.sendDatagram(&payload) catch break;
            sent += dgram_payload;
        }
        while (true) {
            const dg = client.pollProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), &server_scid) catch break orelse break;
            defer allocator.free(dg);
            client_socket.send(io, &server_addr, dg) catch break;
        }
        while (true) {
            const ack = client_socket.receiveTimeout(io, &recv_buf, .{ .duration = .{ .clock = .awake, .raw = std.Io.Duration.fromMicroseconds(100) } }) catch break;
            _ = client.processProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), server_scid.len, ack.data) catch {};
        }
    }
    var wait: usize = 0;
    while (bytes_received.load(.monotonic) < total_bytes and wait < 5_000_000) : (wait += 1) {
        while (true) {
            const dg = client.pollProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), &server_scid) catch break orelse break;
            defer allocator.free(dg);
            client_socket.send(io, &server_addr, dg) catch break;
        }
        while (true) {
            const ack = client_socket.receiveTimeout(io, &recv_buf, .{ .duration = .{ .clock = .awake, .raw = std.Io.Duration.fromMicroseconds(100) } }) catch break;
            _ = client.processProtectedShortDatagramWithInstalledKeys(@intCast(nanoTime()), server_scid.len, ack.data) catch {};
        }
    }
    const elapsed = nanoTime() - t0;
    done.store(true, .release);
    srv_thread.join();
    const recv = bytes_received.load(.monotonic);
    const seconds = @as(f64, @floatFromInt(elapsed)) / 1_000_000_000.0;
    std.debug.print("  {s:20} {d:.2} MB/s  ({d} B payload, recv {d}/{d} bytes)\n", .{
        "DATAGRAM (RFC 9221)",
        @as(f64, @floatFromInt(recv)) / (1024.0 * 1024.0) / seconds,
        dgram_payload,
        recv,
        total_bytes,
    });
}

const WorkerCtx = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    bytes_out: *std.atomic.Value(usize),
};

/// One connection transfer as a std.Io concurrent task (returns Cancelable!void).
/// Used to test whether std.Io's async multiplexing (Group.concurrent on a shared
/// std.Io thread pool) changes aggregate throughput vs thread-per-connection.
fn asyncTransferTask(ctx: WorkerCtx) std.Io.Cancelable!void {
    const allocator = ctx.allocator;
    const io = ctx.io;
    var client_socket = bindLoopback(io) catch return;
    defer client_socket.close(io);
    var server_socket = bindLoopback(io) catch return;
    defer server_socket.close(io);
    const server_addr = server_socket.address;

    const seed = @as([32]u8, @splat(0x55));
    const server_kp = EcdsaP256Sha256.KeyPair.generateDeterministic(seed) catch return;
    const server_priv = server_kp.secret_key.bytes;
    const cert_der = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    const alpn = [_][]const u8{"bench"};
    const secrets = protection.deriveInitialSecrets(.v1, &original_dcid) catch return;

    var client = Connection.init(allocator, .client, .{
        .initial_max_data = 256 * 1024 * 1024,
        .initial_max_stream_data = 256 * 1024 * 1024,
        .initial_max_streams_bidi = 64,
        .congestion_algorithm = .cubic,
        .max_datagram_size = max_datagram_size,
    }) catch return;
    var server = Connection.init(allocator, .server, .{
        .initial_max_data = 256 * 1024 * 1024,
        .initial_max_stream_data = 256 * 1024 * 1024,
        .initial_max_streams_bidi = 64,
        .max_datagram_size = max_datagram_size,
    }) catch return;
    server.validatePeerAddress() catch return;

    var client_backend = Tls13Backend.initClient(.{ .alpn = &alpn, .server_name = "example.com", .skip_cert_verify = true });
    var server_backend = Tls13Backend.initServer(.{ .alpn = &alpn, .cert_chain_der = &.{&cert_der}, .private_key_bytes = &server_priv, .private_key_algorithm = .ecdsa_p256_sha256 });

    var scratch: [16384]u8 = undefined;
    var hs_buf: [16384]u8 = undefined;
    client.setLocalInitialSourceConnectionId(&client_scid) catch return;
    server.setLocalInitialSourceConnectionId(&server_scid) catch return;
    doHandshake(allocator, &client, &server, &client_socket, &server_socket, io, &client_backend, &server_backend, &scratch, &hs_buf, secrets) catch return;

    var done = std.atomic.Value(bool).init(false);
    var bytes_received = std.atomic.Value(usize).init(0);
    var srv_ctx = SrvCtx{ .socket = &server_socket, .io = io, .server = &server, .done = &done, .bytes_received = &bytes_received, .client_addr = client_socket.address, .num_streams = 1 };
    const srv_thread = std.Thread.spawn(.{}, serverTransferThread, .{&srv_ctx}) catch return;
    const stream_id = client.openStream() catch return;
    _ = runTransfer(allocator, io, &client, &client_socket, &server_addr, &bytes_received, stream_id, transfer_size);
    done.store(true, .release);
    srv_thread.join();
    ctx.bytes_out.store(bytes_received.load(.monotonic), .monotonic);
    client.deinit();
    server.deinit();
}

/// Concurrent connections via std.Io Group.concurrent on ONE shared std.Io
/// (async multiplexing model), to compare against thread-per-connection.
fn measureConcurrentAsync(allocator: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("\n  --- Concurrent via std.Io Group.concurrent (shared std.Io) ---\n", .{});
    const num_conns: usize = 4;
    var arenas: [num_conns]*std.heap.ArenaAllocator = undefined;
    var byte_counts: [num_conns]std.atomic.Value(usize) = undefined;
    for (0..num_conns) |i| byte_counts[i] = std.atomic.Value(usize).init(0);

    var group: std.Io.Group = .init;
    const t0 = nanoTime();
    for (0..num_conns) |i| {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        arenas[i] = arena;
        const ctx = WorkerCtx{ .io = io, .allocator = arena.allocator(), .bytes_out = &byte_counts[i] };
        group.concurrent(io, asyncTransferTask, .{ctx}) catch {};
    }
    group.await(io) catch {};
    var total_bytes: usize = 0;
    for (0..num_conns) |i| {
        total_bytes += byte_counts[i].load(.monotonic);
        arenas[i].deinit();
        allocator.destroy(arenas[i]);
    }
    const elapsed = nanoTime() - t0;
    const seconds = @as(f64, @floatFromInt(elapsed)) / 1_000_000_000.0;
    std.debug.print("  {s:20} {d:.2} MB/s  ({d} conns via Group.concurrent in {d:.3} s)\n", .{
        "Async (shared Io)",
        @as(f64, @floatFromInt(total_bytes)) / (1024.0 * 1024.0) / seconds,
        num_conns,
        seconds,
    });
}

/// One connection (real handshake + 16 MB transfer) run on its own thread, for
/// the concurrent-connection scaling test. std.Io.Threaded is multi-threaded, so
/// independent connections on separate threads can run in parallel.
fn workerFn(ctx: WorkerCtx) void {
    const allocator = ctx.allocator;
    // Per-connection std.Io (each worker owns its own I/O context)
    // to test whether the shared std.Io serializes concurrent connections.
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var client_socket = bindLoopback(io) catch return;
    defer client_socket.close(io);
    var server_socket = bindLoopback(io) catch return;
    defer server_socket.close(io);
    const server_addr = server_socket.address;

    const seed = @as([32]u8, @splat(0x55));
    const server_kp = EcdsaP256Sha256.KeyPair.generateDeterministic(seed) catch return;
    const server_priv = server_kp.secret_key.bytes;
    const cert_der = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF };
    const alpn = [_][]const u8{"bench"};
    const secrets = protection.deriveInitialSecrets(.v1, &original_dcid) catch return;

    var client = Connection.init(allocator, .client, .{
        .initial_max_data = 256 * 1024 * 1024,
        .initial_max_stream_data = 256 * 1024 * 1024,
        .initial_max_streams_bidi = 64,
        .congestion_algorithm = .cubic,
        .max_datagram_size = max_datagram_size,
    }) catch return;
    var server = Connection.init(allocator, .server, .{
        .initial_max_data = 256 * 1024 * 1024,
        .initial_max_stream_data = 256 * 1024 * 1024,
        .initial_max_streams_bidi = 64,
        .max_datagram_size = max_datagram_size,
    }) catch return;
    server.validatePeerAddress() catch return;

    var client_backend = Tls13Backend.initClient(.{ .alpn = &alpn, .server_name = "example.com", .skip_cert_verify = true });
    var server_backend = Tls13Backend.initServer(.{ .alpn = &alpn, .cert_chain_der = &.{&cert_der}, .private_key_bytes = &server_priv, .private_key_algorithm = .ecdsa_p256_sha256 });

    var scratch: [16384]u8 = undefined;
    var hs_buf: [16384]u8 = undefined;
    client.setLocalInitialSourceConnectionId(&client_scid) catch return;
    server.setLocalInitialSourceConnectionId(&server_scid) catch return;
    doHandshake(allocator, &client, &server, &client_socket, &server_socket, io, &client_backend, &server_backend, &scratch, &hs_buf, secrets) catch return;

    var done = std.atomic.Value(bool).init(false);
    var bytes_received = std.atomic.Value(usize).init(0);
    var srv_ctx = SrvCtx{ .socket = &server_socket, .io = io, .server = &server, .done = &done, .bytes_received = &bytes_received, .client_addr = client_socket.address, .num_streams = 1 };
    const srv_thread = std.Thread.spawn(.{}, serverTransferThread, .{&srv_ctx}) catch return;
    const stream_id = client.openStream() catch return;
    _ = runTransfer(allocator, io, &client, &client_socket, &server_addr, &bytes_received, stream_id, transfer_size);
    done.store(true, .release);
    srv_thread.join();
    ctx.bytes_out.store(bytes_received.load(.monotonic), .monotonic);
    client.deinit();
    server.deinit();
}

/// Concurrent connection scaling: N connections each run on their own thread
/// (own arena + server thread), started together. Measures aggregate throughput
/// to see how quicz scales with multiple threads (std.Io.Threaded is multi-threaded).
fn measureConcurrentConnections(allocator: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("\n  --- Concurrent Connection Scaling (N threads) ---\n", .{});
    const num_conns: usize = 4;
    var arenas: [num_conns]*std.heap.ArenaAllocator = undefined;
    var byte_counts: [num_conns]std.atomic.Value(usize) = undefined;
    var threads: [num_conns]std.Thread = undefined;
    for (0..num_conns) |i| byte_counts[i] = std.atomic.Value(usize).init(0);

    const t0 = nanoTime();
    for (0..num_conns) |i| {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        arenas[i] = arena;
        const ctx = WorkerCtx{ .io = io, .allocator = arena.allocator(), .bytes_out = &byte_counts[i] };
        threads[i] = try std.Thread.spawn(.{ .allocator = allocator }, workerFn, .{ctx});
    }
    var total_bytes: usize = 0;
    for (0..num_conns) |i| {
        threads[i].join();
        total_bytes += byte_counts[i].load(.monotonic);
        arenas[i].deinit();
        allocator.destroy(arenas[i]);
    }
    const elapsed = nanoTime() - t0;
    const seconds = @as(f64, @floatFromInt(elapsed)) / 1_000_000_000.0;
    std.debug.print("  {s:20} {d:.2} MB/s  ({d} concurrent conns x {d} MB in {d:.3} s)\n", .{
        "Aggregate (4 conns)",
        @as(f64, @floatFromInt(total_bytes)) / (1024.0 * 1024.0) / seconds,
        num_conns,
        transfer_size / (1024 * 1024),
        seconds,
    });
}

/// Server thread that drains received DATAGRAM frames (RFC 9221) and counts bytes.
pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    std.debug.print("=== quicz Benchmark (REAL handshake, RFC 9000/9001) ===\n", .{});
    std.debug.print("Datagram: {d} B | CUBIC | throughput iters: {d}\n", .{ max_datagram_size, bench_iters });

    try measureSingleStream(allocator, io);
    try measureEcho(allocator, io);
    try measureMultiStream(allocator, io);
    try measureLoss(allocator, io);
    try measureHandshakeLatency(allocator, io);
    try measureHandshakeRate(allocator, io);
    try measureStreamChurn(allocator, io);
    try measureConcurrentConnections(allocator, io);
    try measureConcurrentAsync(allocator, io);
    try measureDatagram(allocator, io);

    std.debug.print("\n=== Benchmark complete ===\n", .{});
}
