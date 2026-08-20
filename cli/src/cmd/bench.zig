//! `quicz bench` subcommand: QUIC handshake latency + stream throughput
//! benchmark against a peer running `quicz echo --server`.

const std = @import("std");
const quicz = @import("quicz");
const common = @import("../common.zig");

const nextArg = common.nextArg;
const Client = common.Client;
const alpn_hq = common.alpn_hq;
const runWithTimeout = common.runWithTimeout;
const TimedWork = common.TimedWork;
const resolveHost = common.resolveHost;

pub fn run(allocator: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !void {
    try cmdBench(allocator, io, args);
}

// ---------------------------------------------------------------- bench

const BenchJob = struct {
    allocator: std.mem.Allocator,
    ip: [4]u8,
    host: []const u8,
    port: u16,
    size: usize,
};

fn benchJob(io: std.Io, ctx: *anyopaque) anyerror!void {
    const job: *const BenchJob = @ptrCast(@alignCast(ctx));
    var client = try Client.init(job.allocator, io, .{
        .server_host = job.ip,
        .server_port = job.port,
        .server_name = job.host,
        .alpn = &alpn_hq,
        .insecure_skip_verify = true,
    });
    defer client.deinit();

    const t0 = std.Io.Timestamp.now(io, .awake);
    try client.connect();
    const t1 = std.Io.Timestamp.now(io, .awake);

    const payload = try job.allocator.alloc(u8, job.size);
    defer job.allocator.free(payload);
    @memset(payload, 'x');
    const sid = try client.send(payload, true);

    var rbuf: [65536]u8 = undefined;
    var received: usize = 0;
    while (received < job.size) {
        const n = try client.receive(sid, &rbuf);
        if (n == 0) break;
        received += n;
    }
    const t2 = std.Io.Timestamp.now(io, .awake);

    const connect_ms = std.Io.Duration.toMilliseconds(t0.durationTo(t1));
    const seconds = @as(f64, @floatFromInt(std.Io.Duration.toNanoseconds(t1.durationTo(t2)))) / 1e9;
    const mbps = @as(f64, @floatFromInt(received)) * 8.0 / 1e6 / seconds;
    std.debug.print("connect={d} ms size={d} B received={d} B time={d:.3} s rate={d:.1} Mbit/s\n", .{
        connect_ms,
        job.size,
        received,
        seconds,
        mbps,
    });
    if (received != job.size) return error.BenchFailed;
}

fn cmdBench(allocator: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !void {
    var host: ?[]const u8 = null;
    var port: ?u16 = null;
    var size: usize = 64 * 1024;
    var timeout_ms: u64 = 10000;

    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--size")) {
            size = try std.fmt.parseInt(usize, try nextArg(args), 10);
        } else if (std.mem.eql(u8, a, "--timeout-ms")) {
            timeout_ms = try std.fmt.parseInt(u64, try nextArg(args), 10);
        } else if (host == null) {
            host = a;
        } else if (port == null) {
            port = try std.fmt.parseInt(u16, a, 10);
        } else {
            return error.TooManyArgs;
        }
    }
    const hp = host orelse return error.MissingHost;
    const cp = port orelse return error.MissingPort;
    if (size == 0 or size > 256 * 1024 * 1024) return error.BadSize;

    const ip = try resolveHost(io, hp, cp);
    var job: BenchJob = .{
        .allocator = allocator,
        .ip = ip,
        .host = hp,
        .port = cp,
        .size = size,
    };
    try runWithTimeout(io, timeout_ms, benchJob, &job);
}
