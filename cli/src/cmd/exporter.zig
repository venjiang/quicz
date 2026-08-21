//! `quicz exporter` subcommand: expose repeated `quicz probe` results as a
//! Prometheus HTTP `/metrics` endpoint.

const std = @import("std");
const common = @import("../common.zig");
const probe = @import("probe.zig");

const nextArg = common.nextArg;
const parseIpv4 = common.parseIpv4;
const ResolveOverride = common.ResolveOverride;
const parseResolveSpec = common.parseResolveSpec;

const default_port: u16 = 9633;
const default_interval_ms: u64 = 60_000;
const max_target_len: usize = 1024;
var g_allocator: ?std.mem.Allocator = null;
var g_io: ?std.Io = null;

pub fn run(allocator: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !void {
    try cmdExporter(allocator, io, args);
}

const ExporterConfig = struct {
    targets: []const []const u8,
    probe_options: probe.ProbeOptions,
    interval_ms: u64,
};

const ExporterCache = struct {
    results: []probe.ProbeResult,
    lock: std.Io.RwLock = .init,

    fn init(allocator: std.mem.Allocator, count: usize) !ExporterCache {
        const results = try allocator.alloc(probe.ProbeResult, count);
        for (results) |*result| result.* = probe.emptyProbeResult("");
        return .{ .results = results };
    }

    fn deinit(self: *const ExporterCache, allocator: std.mem.Allocator) void {
        for (self.results) |result| probe.deinitProbeResult(allocator, &result);
        allocator.free(self.results);
    }
};

fn appendNormalizedTarget(allocator: std.mem.Allocator, targets: *std.ArrayList([]const u8), raw: []const u8) !void {
    var target_buf: [max_target_len]u8 = undefined;
    const target = probe.normalizeProbeTarget(raw, &target_buf) orelse {
        std.debug.print("exporter: unsupported target '{s}' (only https:// is supported)\n", .{raw});
        return error.UnsupportedTarget;
    };
    for (targets.items) |existing| {
        if (std.mem.eql(u8, existing, target)) return error.DuplicateTarget;
    }
    const owned = try allocator.dupe(u8, target);
    errdefer allocator.free(owned);
    try targets.append(allocator, owned);
}

fn cmdExporter(allocator: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !void {
    var bind: [4]u8 = .{ 127, 0, 0, 1 };
    var port: u16 = default_port;
    var interval_ms: u64 = default_interval_ms;
    var targets: std.ArrayList([]const u8) = .empty;
    defer {
        for (targets.items) |target| allocator.free(target);
        targets.deinit(allocator);
    }
    var resolves: std.ArrayList(ResolveOverride) = .empty;
    defer resolves.deinit(allocator);
    var probe_options = probe.ProbeOptions{ .target = "" };
    g_allocator = allocator;
    g_io = io;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--target")) {
            appendNormalizedTarget(allocator, &targets, try nextArg(args)) catch |err| switch (err) {
                error.DuplicateTarget => {
                    std.debug.print("exporter: duplicate target\n", .{});
                    return err;
                },
                else => return err,
            };
        } else if (std.mem.eql(u8, arg, "--bind")) {
            bind = try parseIpv4(try nextArg(args));
        } else if (std.mem.eql(u8, arg, "--port")) {
            port = try std.fmt.parseInt(u16, try nextArg(args), 10);
        } else if (std.mem.eql(u8, arg, "--interval")) {
            const seconds = try std.fmt.parseInt(u64, try nextArg(args), 10);
            if (seconds < 1) {
                std.debug.print("exporter: --interval must be at least 1 second\n", .{});
                return error.InvalidInterval;
            }
            interval_ms = try std.math.mul(u64, seconds, 1000);
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
            common.g_verbose = true;
        } else if (std.mem.eql(u8, arg, "-k") or std.mem.eql(u8, arg, "--insecure")) {
            probe_options.insecure = true;
        } else if (std.mem.eql(u8, arg, "--ca")) {
            probe_options.ca_path = try nextArg(args);
        } else if (std.mem.eql(u8, arg, "--resolve")) {
            try resolves.append(allocator, try parseResolveSpec(try nextArg(args)));
        } else if (std.mem.eql(u8, arg, "--connect-timeout")) {
            const seconds = try std.fmt.parseInt(u64, try nextArg(args), 10);
            probe_options.connect_timeout_ms = try std.math.mul(u64, seconds, 1000);
        } else if (std.mem.eql(u8, arg, "--max-time")) {
            const seconds = try std.fmt.parseInt(u64, try nextArg(args), 10);
            probe_options.timeout_ms = try std.math.mul(u64, seconds, 1000);
        } else if (std.mem.eql(u8, arg, "-A") or std.mem.eql(u8, arg, "--user-agent")) {
            probe_options.user_agent = try nextArg(args);
        } else if (std.mem.eql(u8, arg, "--no-alt-svc")) {
            probe_options.check_alt_svc = false;
        } else {
            std.debug.print("exporter: unknown option: {s}\n", .{arg});
            return error.UnknownOption;
        }
    }
    if (targets.items.len == 0) {
        std.debug.print("exporter: at least one --target is required\n", .{});
        return error.MissingTarget;
    }
    probe_options.resolve = resolves.items;

    const config = ExporterConfig{
        .targets = targets.items,
        .probe_options = probe_options,
        .interval_ms = interval_ms,
    };
    var cache = try ExporterCache.init(allocator, targets.items.len);
    defer cache.deinit(allocator);
    try refreshCache(io, &cache, &config);

    var address = std.Io.net.IpAddress{ .ip4 = .{ .bytes = bind, .port = port } };
    var server = address.listen(io, .{ .reuse_address = true }) catch |err| {
        std.debug.print("exporter: failed to listen on {d}.{d}.{d}.{d}:{d}: {s}\n", .{
            bind[0], bind[1], bind[2], bind[3], port, @errorName(err),
        });
        return err;
    };
    defer server.deinit(io);

    std.debug.print("quicz exporter: http://{d}.{d}.{d}.{d}:{d}/metrics | targets={d} interval={d}s\n", .{
        bind[0], bind[1], bind[2], bind[3], port, targets.items.len, interval_ms / 1000,
    });
    var group: std.Io.Group = .init;
    defer group.cancel(io);
    group.concurrent(io, probeLoop, .{ &cache, &config }) catch |err| {
        std.debug.print("exporter: probe loop failed to start: {s}\n", .{@errorName(err)});
        return err;
    };
    try serveExporter(io, &server, &cache, &group);
}

fn serveExporter(io: std.Io, server: *std.Io.net.Server, cache: *ExporterCache, group: *std.Io.Group) std.Io.Cancelable!void {
    while (true) {
        var stream = server.accept(io) catch |err| switch (err) {
            error.Canceled => |canceled| return canceled,
            else => {
                std.debug.print("exporter: accept failed: {s}\n", .{@errorName(err)});
                return;
            },
        };
        group.concurrent(io, handleConnection, .{ stream, cache }) catch |err| {
            std.debug.print("exporter: connection handler failed to start: {s}\n", .{@errorName(err)});
            stream.close(io);
        };
    }
}

fn handleConnection(stream: std.Io.net.Stream, cache: *ExporterCache) void {
    const io = g_io orelse return;
    defer stream.close(io);

    var request_buf: [8192]u8 = undefined;
    const request_len = readRequestHead(io, stream, &request_buf) orelse return;
    const request = request_buf[0..request_len];
    const request_target = metricsRequestTarget(request) orelse {
        sendHttpResponse(io, stream, 404, "Not Found", "text/plain; charset=utf-8", "not found\n", false) catch {};
        return;
    };

    const allocator = g_allocator orelse return;
    const body = buildMetrics(allocator, io, cache) catch {
        sendHttpResponse(io, stream, 500, "Internal Server Error", "text/plain; charset=utf-8", "probe failed\n", request_target.head_only) catch {};
        return;
    };
    defer allocator.free(body);
    sendHttpResponse(
        io,
        stream,
        200,
        "OK",
        "text/plain; version=0.0.4; charset=utf-8",
        body,
        request_target.head_only,
    ) catch {};
}

const RequestTarget = struct {
    path: []const u8,
    head_only: bool,
};

fn metricsRequestTarget(request: []const u8) ?RequestTarget {
    const line_end = std.mem.indexOf(u8, request, "\r\n") orelse return null;
    var parts = std.mem.splitScalar(u8, request[0..line_end], ' ');
    const method = parts.next() orelse return null;
    const path = parts.next() orelse return null;
    const version = parts.next() orelse return null;
    if (parts.next() != null) return null;
    if (!std.mem.eql(u8, version, "HTTP/1.1") and !std.mem.eql(u8, version, "HTTP/1.0")) return null;
    if (!std.mem.eql(u8, path, "/metrics")) return null;
    if (std.mem.eql(u8, method, "GET")) return .{ .path = path, .head_only = false };
    if (std.mem.eql(u8, method, "HEAD")) return .{ .path = path, .head_only = true };
    return null;
}

fn readRequestHead(io: std.Io, stream: std.Io.net.Stream, buf: []u8) ?usize {
    var len: usize = 0;
    while (len < buf.len) {
        if (std.mem.indexOf(u8, buf[0..len], "\r\n\r\n")) |_| return len;
        const message = stream.socket.receiveTimeout(
            io,
            buf[len..],
            .{ .duration = .{
                .raw = std.Io.Duration.fromMilliseconds(5000),
                .clock = .awake,
            } },
        ) catch return null;
        const data_len = message.data.len;
        if (data_len == 0) return null;
        len += data_len;
    }
    return null;
}

fn probeLoop(cache: *ExporterCache, config: *const ExporterConfig) void {
    const io = g_io orelse return;
    while (true) {
        const duration_ms = std.math.cast(i64, config.interval_ms) orelse return;
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(duration_ms), .awake) catch |err| switch (err) {
            error.Canceled => return,
        };
        refreshCache(io, cache, config) catch {};
    }
}

fn refreshCache(io: std.Io, cache: *ExporterCache, config: *const ExporterConfig) !void {
    const allocator = g_allocator orelse return error.MissingAllocator;
    for (config.targets, 0..) |target, target_index| {
        var options = config.probe_options;
        options.target = target;
        const result = try probe.runProbeOnce(allocator, io, options);
        if (cache.lock.lock(io)) |_| {
            probe.deinitProbeResult(allocator, &cache.results[target_index]);
            cache.results[target_index] = result;
            cache.lock.unlock(io);
        } else |_| {
            probe.deinitProbeResult(allocator, &result);
            return;
        }
    }
}

fn buildMetrics(allocator: std.mem.Allocator, io: std.Io, cache: *ExporterCache) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    var metric_buf: [16384]u8 = undefined;

    cache.lock.lockShared(io) catch return error.LockFailed;
    defer cache.lock.unlockShared(io);

    for (cache.results, 0..) |result, target_index| {
        const metrics = try probe.formatProbePrometheus(result, &metric_buf);
        if (target_index == 0) {
            try body.appendSlice(allocator, metrics);
        } else {
            try appendMetricSamples(allocator, &body, metrics);
        }
    }
    return body.toOwnedSlice(allocator);
}

fn appendMetricSamples(allocator: std.mem.Allocator, body: *std.ArrayList(u8), metrics: []const u8) !void {
    var lines = std.mem.splitScalar(u8, metrics, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "# ")) continue;
        try body.appendSlice(allocator, line);
        try body.append(allocator, '\n');
    }
}

fn sendHttpResponse(
    io: std.Io,
    stream: std.Io.net.Stream,
    status: u16,
    reason: []const u8,
    content_type: []const u8,
    body: []const u8,
    head_only: bool,
) !void {
    var send_buf: [8192]u8 = undefined;
    var writer = stream.writer(io, &send_buf);
    try writer.interface.print(
        "HTTP/1.1 {d} {s}\r\ncontent-type: {s}\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n",
        .{ status, reason, content_type, body.len },
    );
    if (!head_only and body.len > 0) try writer.interface.writeAll(body);
    try writer.interface.flush();
}

test "exporter strips duplicate metric metadata" {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(std.testing.allocator);
    try body.appendSlice(std.testing.allocator, "# HELP metric one\n# TYPE metric gauge\nmetric{target=\"one\"} 1\n");
    try appendMetricSamples(std.testing.allocator, &body, "# HELP metric one\n# TYPE metric gauge\nmetric{target=\"two\"} 0\n");
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, body.items, "# HELP metric one\n"));
    try std.testing.expect(std.mem.indexOf(u8, body.items, "metric{target=\"one\"} 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, body.items, "metric{target=\"two\"} 0") != null);
}

test "exporter accepts only GET or HEAD metrics requests" {
    const get = metricsRequestTarget("GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").?;
    try std.testing.expectEqualStrings("/metrics", get.path);
    try std.testing.expect(!get.head_only);
    const head = metricsRequestTarget("HEAD /metrics HTTP/1.1\r\n\r\n").?;
    try std.testing.expect(head.head_only);
    try std.testing.expect(metricsRequestTarget("POST /metrics HTTP/1.1\r\n\r\n") == null);
    try std.testing.expect(metricsRequestTarget("GET /other HTTP/1.1\r\n\r\n") == null);
}
