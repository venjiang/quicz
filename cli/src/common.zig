//! Shared, subcommand-agnostic helpers for the quicz CLI: URL parsing, DNS
//! and CA bootstrap, timeout wrappers, runtime aliases. Kept out of main.zig
//! (which now only dispatches subcommands) and out of cmd/*.zig so each
//! subcommand module stays self-contained without duplicating plumbing.

const std = @import("std");
const quicz = @import("quicz");
const test_certs = @import("test_certs");

pub const Server = quicz.runtime.server.Server;
pub const ServerConnection = quicz.runtime.server.ServerConnection;
pub const Client = quicz.runtime.client.Client;
pub const RuntimeH3Client = quicz.runtime.h3_client.H3Client;

pub const alpn_h3 = [_][]const u8{"h3"};
pub const alpn_hq = [_][]const u8{"hq-interop"};
pub var g_verbose = false;
pub fn nextArg(args: *std.process.Args.Iterator) ![]const u8 {
    return args.next() orelse return error.MissingArgument;
}

pub fn parseIpv4(s: []const u8) ![4]u8 {
    const addr = try std.Io.net.IpAddress.parseIp4(s, 0);
    return addr.ip4.bytes;
}

pub const ResolveOverride = struct {
    host: []const u8,
    port: u16,
    addr: [4]u8,
};

/// Parse a `--resolve HOST:PORT:ADDR` argument (curl-style DNS override).
pub fn parseResolveSpec(spec: []const u8) !ResolveOverride {
    const first_colon = std.mem.indexOfScalar(u8, spec, ':') orelse return error.BadResolveSpec;
    const last_colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return error.BadResolveSpec;
    if (first_colon == last_colon) return error.BadResolveSpec;
    const host = spec[0..first_colon];
    if (host.len == 0) return error.BadResolveSpec;
    const port = try std.fmt.parseInt(u16, spec[first_colon + 1 .. last_colon], 10);
    const addr = try parseIpv4(spec[last_colon + 1 ..]);
    return .{ .host = host, .port = port, .addr = addr };
}

pub fn readFile(io: std.Io, path: []const u8, buf: []u8) ![]u8 {
    const file = try std.Io.Dir.openFile(.cwd(), io, path, .{});
    defer file.close(io);
    const n = try file.readPositionalAll(io, buf, 0);
    return buf[0..n];
}

/// Read a whole file into an allocator-owned buffer.
pub fn readFileAll(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    const file = try std.Io.Dir.openFile(.cwd(), io, path, .{});
    defer file.close(io);
    const len = try file.length(io);
    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);
    const n = try file.readPositionalAll(io, buf, 0);
    return buf[0..n];
}

/// Write an HTTP/3 status line and non-pseudo headers to a file.
const system_ca_bundle_paths = [_][]const u8{
    "/etc/ssl/cert.pem", // macOS, Debian/Ubuntu
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt", // RHEL/Fedora
    "/etc/ssl/ca-bundle.pem", // SUSE / others
};

pub fn loadSystemCaBundle(allocator: std.mem.Allocator, io: std.Io) !std.crypto.Certificate.Bundle {
    const now = std.Io.Clock.real.now(io);
    for (system_ca_bundle_paths) |path| {
        var bundle: std.crypto.Certificate.Bundle = .empty;
        bundle.addCertsFromFilePathAbsolute(allocator, io, now, path) catch continue;
        if (bundle.bytes.items.len > 0) return bundle;
        bundle.deinit(allocator);
    }
    return error.SystemCaBundleNotFound;
}

/// Lowercase a header name so `-H 'Content-Type: ...'` behaves like curl
/// (HTTP field names must be lowercase; RFC 9110 §5.1).
pub const TimedWork = struct {
    done: std.atomic.Value(bool) = .init(false),
    result: ?anyerror = null,
};

pub fn timedSession(io: std.Io, timed: *TimedWork, work: *const fn (io: std.Io, ctx: *anyopaque) anyerror!void, ctx: *anyopaque) void {
    work(io, ctx) catch |e| {
        timed.result = e;
        timed.done.store(true, .release);
        return;
    };
    timed.result = null;
    timed.done.store(true, .release);
}

pub fn timedWatchdog(io: std.Io, session: *std.Io.Future(void), timed: *TimedWork, timeout_ms: u64) void {
    const tick_ms: u64 = 100;
    var waited: u64 = 0;
    while (waited < timeout_ms) {
        if (timed.done.load(.acquire)) return;
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(tick_ms), .awake) catch return;
        waited += tick_ms;
    }
    if (!timed.done.load(.acquire)) {
        session.cancel(io);
    }
}

pub fn mapTimedResult(r: anyerror) anyerror {
    return if (r == error.Canceled) error.Timeout else r;
}

pub fn runWithTimeout(io: std.Io, timeout_ms: u64, work: *const fn (io: std.Io, ctx: *anyopaque) anyerror!void, ctx: *anyopaque) !void {
    var timed: TimedWork = .{};
    var session = io.async(timedSession, .{ io, &timed, work, ctx });
    var watchdog = io.async(timedWatchdog, .{ io, &session, &timed, timeout_ms });
    _ = watchdog.await(io);
    _ = session.await(io);
    if (timed.result) |r| return mapTimedResult(r);
    return;
}

pub const ConnectCtx = struct { client: *Client };

pub fn connectWork(_: std.Io, ctx: *anyopaque) anyerror!void {
    const c: *ConnectCtx = @ptrCast(@alignCast(ctx));
    try c.client.connect();
}

/// Bound only the QUIC handshake with `--connect-timeout-ms`; the enclosing
/// `--timeout-ms` still caps the whole request.
pub fn connectWithTimeout(io: std.Io, timeout_ms: u64, client: *Client) !void {
    var ctx = ConnectCtx{ .client = client };
    try runWithTimeout(io, timeout_ms, connectWork, &ctx);
}

/// Resolve a host name to an IPv4 address. IPv4 literals and `localhost` are
pub fn resolveHost(io: std.Io, host: []const u8, port: u16) ![4]u8 {
    if (std.mem.eql(u8, host, "localhost")) return .{ 127, 0, 0, 1 };
    if (std.Io.net.IpAddress.parseIp4(host, port)) |addr| {
        return addr.ip4.bytes;
    } else |_| {}

    const name = std.Io.net.HostName.init(host) catch return error.BadHostName;
    var buf: [16]std.Io.net.HostName.LookupResult = undefined;
    var queue: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&buf);
    try std.Io.net.HostName.lookup(name, io, &queue, .{ .port = port });
    while (queue.getOneUncancelable(io)) |item| {
        switch (item) {
            .address => |addr| switch (addr) {
                .ip4 => |ip4| return ip4.bytes,
                else => {},
            },
            .canonical_name => {},
        }
    } else |_| {}
    return error.NoIpv4Address;
}

pub fn resolveHostWithOverrides(io: std.Io, host: []const u8, port: u16, overrides: []const ResolveOverride) ![4]u8 {
    for (overrides) |o| {
        if (o.port == port and std.ascii.eqlIgnoreCase(o.host, host)) return o.addr;
    }
    return resolveHost(io, host, port);
}
pub fn loadCertKey(io: std.Io, cert_pem: ?[]const u8, key_pem: ?[]const u8) !struct { cert_der: []const u8, private_key: [32]u8 } {
    var cert_pem_buf: [64 * 1024]u8 = undefined;
    var cert_der_buf: [8192]u8 = undefined;
    var key_pem_buf: [64 * 1024]u8 = undefined;
    var key_der_buf: [512]u8 = undefined;

    if (cert_pem != null or key_pem != null) {
        if (cert_pem == null or key_pem == null) return error.CertAndKeyRequired;
        const cert_pem_data = try readFile(io, cert_pem.?, &cert_pem_buf);
        const cert_der = try quicz.tls_pem.decodeBlock(cert_pem_data, "CERTIFICATE", &cert_der_buf);
        const key_pem_data = try readFile(io, key_pem.?, &key_pem_buf);
        const private_key = try quicz.tls_pem.parsePrivateKeyP256(key_pem_data, &key_der_buf);
        return .{ .cert_der = cert_der, .private_key = private_key };
    }
    return .{ .cert_der = &test_certs.cert_der, .private_key = test_certs.private_key };
}

// ---------------------------------------------------------------- h3 client

pub const H3Target = struct {
    host: []const u8,
    port: u16,
    path: []const u8,
};

pub fn parseH3Url(url: []const u8) !H3Target {
    const prefix = "https://";
    if (!std.mem.startsWith(u8, url, prefix)) return error.HttpsOnly;
    const rest = url[prefix.len..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const authority = rest[0..slash];
    const path = if (slash < rest.len) rest[slash..] else "/";
    if (std.mem.indexOfScalar(u8, authority, '[') != null) return error.Ipv6NotSupported;

    const colon = std.mem.lastIndexOfScalar(u8, authority, ':');
    const host = if (colon) |c| authority[0..c] else authority;
    if (host.len == 0) return error.BadUrl;
    const port: u16 = if (colon) |c| try std.fmt.parseInt(u16, authority[c + 1 ..], 10) else 443;
    return .{ .host = host, .port = port, .path = path };
}

pub const max_cli_response_body_size: usize = 256 * 1024 * 1024;

test "parse h3 url" {
    const t = try parseH3Url("https://example.com:8443/path?q=1");
    try std.testing.expectEqualStrings("example.com", t.host);
    try std.testing.expectEqual(@as(u16, 8443), t.port);
    try std.testing.expectEqualStrings("/path?q=1", t.path);

    const t2 = try parseH3Url("https://127.0.0.1/");
    try std.testing.expectEqual(@as(u16, 443), t2.port);
    try std.testing.expectEqualStrings("/", t2.path);

    try std.testing.expectError(error.HttpsOnly, parseH3Url("http://x/"));
}

test "parse ipv4" {
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, try parseIpv4("127.0.0.1"));
    try std.testing.expectError(error.InvalidCharacter, parseIpv4("not-an-ip"));
}

test "parse resolve spec" {
    const o = try parseResolveSpec("example.com:443:127.0.0.1");
    try std.testing.expectEqualStrings("example.com", o.host);
    try std.testing.expectEqual(@as(u16, 443), o.port);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, o.addr);
    try std.testing.expectError(error.BadResolveSpec, parseResolveSpec("example.com:443"));
    try std.testing.expectError(error.BadResolveSpec, parseResolveSpec(":443:127.0.0.1"));
}
