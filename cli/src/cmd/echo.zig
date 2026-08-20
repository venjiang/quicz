//! `quicz echo` subcommand: raw QUIC stream echo server/client for
//! interop verification.

const std = @import("std");
const quicz = @import("quicz");
const common = @import("../common.zig");

const nextArg = common.nextArg;
const parseIpv4 = common.parseIpv4;
const Server = common.Server;
const ServerConnection = common.ServerConnection;
const Client = common.Client;
const alpn_hq = common.alpn_hq;
const loadCertKey = common.loadCertKey;
const runWithTimeout = common.runWithTimeout;
const TimedWork = common.TimedWork;
const resolveHost = common.resolveHost;

pub fn run(allocator: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !void {
    try cmdEcho(allocator, io, args);
}

// ---------------------------------------------------------------- echo

fn echoHandler(conn: ServerConnection) std.Io.Cancelable!void {
    var c = conn;
    var buf: [65536]u8 = undefined;
    while (true) {
        var stream = c.acceptStream() catch return;
        if (stream.isUni()) {
            while (true) {
                const n = stream.receive(&buf) catch break;
                if (n == 0) break;
            }
            continue;
        }
        while (true) {
            const n = stream.receive(&buf) catch break;
            if (n == 0) break;
            stream.send(buf[0..n], false) catch break;
        }
        stream.send(&.{}, true) catch {};
    }
}

fn cmdEcho(allocator: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !void {
    var server_mode = false;
    var client_mode = false;
    var port: u16 = 4433;
    var bind: ?[4]u8 = null;
    var payload: []const u8 = "hello quicz cli";
    var cert_pem: ?[]const u8 = null;
    var key_pem: ?[]const u8 = null;
    var ca_pem: ?[]const u8 = null;
    var host: ?[]const u8 = null;
    var client_port: ?u16 = null;
    var timeout_ms: u64 = 10000;

    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--server")) {
            server_mode = true;
        } else if (std.mem.eql(u8, a, "--client")) {
            client_mode = true;
        } else if (std.mem.eql(u8, a, "--port")) {
            port = try std.fmt.parseInt(u16, try nextArg(args), 10);
        } else if (std.mem.eql(u8, a, "--bind")) {
            bind = try parseIpv4(try nextArg(args));
        } else if (std.mem.eql(u8, a, "--data")) {
            payload = try nextArg(args);
        } else if (std.mem.eql(u8, a, "--cert")) {
            cert_pem = try nextArg(args);
        } else if (std.mem.eql(u8, a, "--key")) {
            key_pem = try nextArg(args);
        } else if (std.mem.eql(u8, a, "--ca")) {
            ca_pem = try nextArg(args);
        } else if (std.mem.eql(u8, a, "--timeout-ms")) {
            timeout_ms = try std.fmt.parseInt(u64, try nextArg(args), 10);
        } else if (host == null) {
            host = a;
        } else if (client_port == null) {
            client_port = try std.fmt.parseInt(u16, a, 10);
        } else {
            return error.TooManyArgs;
        }
    }

    if (server_mode == client_mode) return error.AmbiguousMode;
    if (server_mode) {
        return runEchoServer(allocator, io, port, bind, cert_pem, key_pem);
    }
    const hp = host orelse return error.MissingHost;
    const cp = client_port orelse return error.MissingPort;
    return runEchoClient(allocator, io, hp, cp, payload, ca_pem, timeout_ms);
}

fn runEchoServer(allocator: std.mem.Allocator, io: std.Io, port: u16, bind: ?[4]u8, cert_pem: ?[]const u8, key_pem: ?[]const u8) !void {
    const identity = try loadCertKey(io, cert_pem, key_pem);
    var server = try Server.init(allocator, io, .{
        .port = port,
        .alpn = &alpn_hq,
        .cert_der = identity.cert_der,
        .private_key = &identity.private_key,
        .bind_addr = bind,
    });
    defer server.deinit();
    try server.serve(&echoHandler);
    std.debug.print("quicz echo server on UDP port {d}\n", .{port});
    server.drive_group.await(io) catch {};
}

const EchoClientJob = struct {
    allocator: std.mem.Allocator,
    ip: [4]u8,
    host: []const u8,
    port: u16,
    payload: []const u8,
    ca_bundle: ?*const std.crypto.Certificate.Bundle,
};

fn echoClientJob(io: std.Io, ctx: *anyopaque) anyerror!void {
    const job: *const EchoClientJob = @ptrCast(@alignCast(ctx));
    var client = try Client.init(job.allocator, io, .{
        .server_host = job.ip,
        .server_port = job.port,
        .server_name = job.host,
        .alpn = &alpn_hq,
        .insecure_skip_verify = job.ca_bundle == null,
        .ca_bundle = job.ca_bundle,
    });
    defer client.deinit();

    const t0 = std.Io.Timestamp.now(io, .awake);
    try client.connect();
    const t1 = std.Io.Timestamp.now(io, .awake);
    const ok = try client.runEchoSession(job.payload);
    const connect_ms = std.Io.Duration.toMilliseconds(t0.durationTo(t1));
    if (ok) {
        std.debug.print("echo OK connect={d} ms bytes={d}\n", .{ connect_ms, job.payload.len });
    } else {
        std.debug.print("echo MISMATCH connect={d} ms\n", .{connect_ms});
        return error.EchoMismatch;
    }
}

fn runEchoClient(allocator: std.mem.Allocator, io: std.Io, host: []const u8, port: u16, payload: []const u8, ca_pem: ?[]const u8, timeout_ms: u64) !void {
    const ip = try resolveHost(io, host, port);

    var maybe_bundle: ?std.crypto.Certificate.Bundle = null;
    if (ca_pem) |pem| {
        if (!std.Io.Dir.path.isAbsolute(pem)) return error.CaPathMustBeAbsolute;
        var bundle: std.crypto.Certificate.Bundle = .empty;
        const now = std.Io.Clock.real.now(io);
        try bundle.addCertsFromFilePathAbsolute(allocator, io, now, pem);
        maybe_bundle = bundle;
    }
    defer {
        if (maybe_bundle) |*b| b.deinit(allocator);
    }

    var job: EchoClientJob = .{
        .allocator = allocator,
        .ip = ip,
        .host = host,
        .port = port,
        .payload = payload,
        .ca_bundle = if (maybe_bundle) |*b| b else null,
    };
    try runWithTimeout(io, timeout_ms, echoClientJob, &job);
}
