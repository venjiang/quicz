//! `quicz h3` subcommand: curl-style HTTP/3 request client.

const std = @import("std");
const quicz = @import("quicz");
const common = @import("../common.zig");
const cookies = @import("../cookies.zig");

// Shared helpers re-exported for readability inside this module.
const nextArg = common.nextArg;
const parseIpv4 = common.parseIpv4;
const ResolveOverride = common.ResolveOverride;
const parseResolveSpec = common.parseResolveSpec;
const readFile = common.readFile;
const readFileAll = common.readFileAll;
const loadSystemCaBundle = common.loadSystemCaBundle;
const TimedWork = common.TimedWork;
const runWithTimeout = common.runWithTimeout;
const ConnectCtx = common.ConnectCtx;
const connectWithTimeout = common.connectWithTimeout;
const resolveHost = common.resolveHost;
const resolveHostWithOverrides = common.resolveHostWithOverrides;
const loadCertKey = common.loadCertKey;
const H3Target = common.H3Target;
const parseH3Url = common.parseH3Url;
const max_cli_response_body_size = common.max_cli_response_body_size;
const Client = common.Client;
const RuntimeH3Client = common.RuntimeH3Client;
const Server = common.Server;
const ServerConnection = common.ServerConnection;
const alpn_h3 = common.alpn_h3;
const alpn_hq = common.alpn_hq;


pub fn run(allocator: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !void {
    try cmdH3(allocator, io, args);
}

fn writeHeadersToFile(io: std.Io, path: []const u8, status: u16, headers: []const quicz.qpack.HeaderField) !void {
    const file = try std.Io.Dir.createFile(.cwd(), io, path, .{});
    defer file.close(io);
    var buf: [32]u8 = undefined;
    const status_line = std.fmt.bufPrint(&buf, "HTTP/3 {d}\n", .{status}) catch "HTTP/3 ?\n";
    try file.writeStreamingAll(io, status_line);
    for (headers) |h| {
        if (h.name.len > 0 and h.name[0] == ':') continue;
        try file.writeStreamingAll(io, h.name);
        try file.writeStreamingAll(io, ": ");
        try file.writeStreamingAll(io, h.value);
        try file.writeStreamingAll(io, "\n");
    }
}

/// Candidate system CA bundle paths, checked in order; the first file that
/// yields at least one certificate wins.
fn lowercaseName(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const out = try allocator.dupe(u8, name);
    for (out) |*c| c.* = std.ascii.toLower(c.*);
    return out;
}

const H3Job = struct {
    allocator: std.mem.Allocator,
    url: []const u8,
    method: []const u8,
    body: ?[]const u8,
    headers: []const quicz.qpack.HeaderField,
    insecure: bool,
    ca_bundle: ?*const std.crypto.Certificate.Bundle,
    output_path: ?[]const u8,
    include_headers: bool,
    follow_redirects: bool,
    max_redirects: usize,
    silent: bool,
    fail_on_http_error: bool,
    dump_headers_path: ?[]const u8,
    resolve: []const ResolveOverride,
    connect_timeout_ms: ?u64,
    write_out: ?[]const u8,
    max_filesize: ?usize,
    cookie_jar: ?*cookies.CookieJar,
};

fn isRedirectStatus(status: u16) bool {
    return switch (status) {
        301, 302, 303, 307, 308 => true,
        else => false,
    };
}

fn findHeader(headers: []const quicz.qpack.HeaderField, name: []const u8) ?[]const u8 {
    for (headers) |h| {
        if (std.mem.eql(u8, h.name, name)) return h.value;
    }
    return null;
}

/// Apply curl-like defaults for the h3 subcommand: `-d` implies POST plus the
/// form content type, and every request carries a user-agent (overridable with
/// `-A`, replacing any `-H user-agent:` header).
fn applyH3Defaults(
    allocator: std.mem.Allocator,
    method: *[]const u8,
    method_explicit: bool,
    data_given: bool,
    headers: *std.ArrayList(quicz.qpack.HeaderField),
    user_agent: ?[]const u8,
    upload: bool,
) !void {
    if (data_given and !method_explicit and std.mem.eql(u8, method.*, "GET")) method.* = "POST";
    if (data_given and findHeader(headers.items, "content-type") == null) {
        const name = try lowercaseName(allocator, "content-type");
        const content_type = if (upload) "application/octet-stream" else "application/x-www-form-urlencoded";
        headers.append(allocator, .{ .name = name, .value = content_type }) catch |e| {
            allocator.free(name);
            return e;
        };
    }
    const effective_user_agent = user_agent orelse "quicz/0.1.0";
    var i: usize = 0;
    while (i < headers.items.len) {
        if (std.mem.eql(u8, headers.items[i].name, "user-agent")) {
            allocator.free(headers.items[i].name);
            _ = headers.orderedRemove(i);
        } else {
            i += 1;
        }
    }
    const ua_name = try lowercaseName(allocator, "user-agent");
    headers.append(allocator, .{ .name = ua_name, .value = effective_user_agent }) catch |e| {
        allocator.free(ua_name);
        return e;
    };
}

/// Replace any existing header with `name`, then append the new value.
/// Header values are borrowed and must outlive the request.
fn setHeader(
    allocator: std.mem.Allocator,
    headers: *std.ArrayList(quicz.qpack.HeaderField),
    name: []const u8,
    value: []const u8,
) !void {
    var i: usize = 0;
    while (i < headers.items.len) {
        if (std.mem.eql(u8, headers.items[i].name, name)) {
            allocator.free(headers.items[i].name);
            _ = headers.orderedRemove(i);
        } else {
            i += 1;
        }
    }
    const name_owned = try lowercaseName(allocator, name);
    headers.append(allocator, .{ .name = name_owned, .value = value }) catch |e| {
        allocator.free(name_owned);
        return e;
    };
}

/// Render a `-u user:pass` value as an `Authorization: Basic ...` header value.
fn buildBasicAuth(userpass: []const u8, buf: []u8) ![]const u8 {
    const enc = std.base64.standard.Encoder;
    const b64_len = enc.calcSize(userpass.len);
    if (b64_len + 6 > buf.len) return error.AuthTooLong;
    @memcpy(buf[0..6], "Basic ");
    _ = enc.encode(buf[6 .. 6 + b64_len], userpass);
    return buf[0 .. 6 + b64_len];
}

const WriteOutVars = struct {
    http_code: u16,
    url_effective: []const u8,
    time_total_ms: u64,
    time_connect_ms: u64,
    size_download: usize,
    num_redirects: usize,
};

/// Render a curl-style `-w` format with `%{var}` placeholders to stdout.
/// Variables are integer milliseconds unless noted.
fn writeOutVars(io: std.Io, format: []const u8, vars: WriteOutVars) !void {
    var out: [1024]u8 = undefined;
    var pos: usize = 0;
    var i: usize = 0;
    var scratch: [64]u8 = undefined;
    while (i < format.len) {
        if (pos >= out.len) break;
        if (format[i] == '%' and i + 1 < format.len and format[i + 1] == '{') {
            const close = std.mem.indexOfScalarPos(u8, format, i + 2, '}') orelse {
                out[pos] = format[i];
                pos += 1;
                i += 1;
                continue;
            };
            const name = format[i + 2 .. close];
            var rendered: []const u8 = "";
            if (std.mem.eql(u8, name, "http_code")) {
                rendered = std.fmt.bufPrint(&scratch, "{d}", .{vars.http_code}) catch "";
            } else if (std.mem.eql(u8, name, "url_effective")) {
                rendered = vars.url_effective;
            } else if (std.mem.eql(u8, name, "time_total_ms")) {
                rendered = std.fmt.bufPrint(&scratch, "{d}", .{vars.time_total_ms}) catch "";
            } else if (std.mem.eql(u8, name, "time_connect_ms")) {
                rendered = std.fmt.bufPrint(&scratch, "{d}", .{vars.time_connect_ms}) catch "";
            } else if (std.mem.eql(u8, name, "size_download")) {
                rendered = std.fmt.bufPrint(&scratch, "{d}", .{vars.size_download}) catch "";
            } else if (std.mem.eql(u8, name, "num_redirects")) {
                rendered = std.fmt.bufPrint(&scratch, "{d}", .{vars.num_redirects}) catch "";
            }
            if (pos + rendered.len > out.len) break;
            @memcpy(out[pos .. pos + rendered.len], rendered);
            pos += rendered.len;
            i = close + 1;
        } else {
            if (format[i] == '\\' and i + 1 < format.len) {
                const esc = switch (format[i + 1]) {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    '\\' => '\\',
                    else => format[i + 1],
                };
                out[pos] = esc;
                pos += 1;
                i += 2;
            } else {
                out[pos] = format[i];
                pos += 1;
                i += 1;
            }
        }
    }
    try std.Io.File.stdout().writeStreamingAll(io, out[0..pos]);
}

/// Resolve a `Location` header against the current URL. Returns an
/// allocator-owned string; supports absolute https URLs, root-relative paths,
/// and path-relative targets.
fn resolveLocation(allocator: std.mem.Allocator, current_url: []const u8, location: []const u8) ![]const u8 {
    const loc = std.mem.trim(u8, location, " \t");
    if (loc.len == 0) return error.BadRedirectLocation;
    if (std.mem.startsWith(u8, loc, "https://")) return allocator.dupe(u8, loc);
    if (std.mem.indexOf(u8, loc, "://") != null) return error.NonHttpsRedirect;
    const base = try parseH3Url(current_url);
    if (std.mem.startsWith(u8, loc, "/")) {
        return resolvedTarget(allocator, base, "", loc);
    }
    var dir: []const u8 = "/";
    if (std.mem.lastIndexOfScalar(u8, base.path, '/')) |slash| {
        if (slash > 0) dir = base.path[0 .. slash + 1];
    }
    return resolvedTarget(allocator, base, dir, loc);
}

/// Rebuild an https URL from a target, omitting the default port 443.
fn resolvedTarget(allocator: std.mem.Allocator, target: H3Target, dir: []const u8, loc: []const u8) ![]const u8 {
    if (target.port == 443) {
        return std.fmt.allocPrint(allocator, "https://{s}{s}{s}", .{ target.host, dir, loc });
    }
    return std.fmt.allocPrint(allocator, "https://{s}:{d}{s}{s}", .{ target.host, target.port, dir, loc });
}

fn sameOrigin(host_a: []const u8, port_a: u16, host_b: []const u8, port_b: u16) bool {
    return port_a == port_b and std.mem.eql(u8, host_a, host_b);
}

fn appendQuery(allocator: std.mem.Allocator, url: []const u8, query: []const u8) ![]u8 {
    if (std.mem.indexOfScalar(u8, url, '?') != null) {
        return std.fmt.allocPrint(allocator, "{s}&{s}", .{ url, query });
    }
    return std.fmt.allocPrint(allocator, "{s}?{s}", .{ url, query });
}

/// Unix seconds from the real-time clock, used for cookie expiry handling.
fn unixNow(io: std.Io) i64 {
    return std.Io.Timestamp.now(io, .real).toSeconds();
}

fn h3Job(io: std.Io, ctx: *anyopaque) anyerror!void {
    const job: *const H3Job = @ptrCast(@alignCast(ctx));
    const t0 = std.Io.Timestamp.now(io, .awake);
    // Function-scoped so it runs after the request (including redirect hops)
    // complete; an if-scoped defer would fire before the request starts.
    defer if (job.cookie_jar) |jar| jar.save(io) catch |e| {
        if (!job.silent) std.debug.print("h3: cookie jar save failed: {s}\n", .{@errorName(e)});
    };

    var current_url = job.url;
    var current_url_owned = false;
    defer if (current_url_owned) job.allocator.free(current_url);
    var redirects_left: usize = job.max_redirects;
    var redirect_count: usize = 0;

    // Connection reused across same-origin redirects to avoid re-handshaking.
    var client: ?Client = null;
    var h3cli: ?RuntimeH3Client = null;
    var connected_host: ?[]const u8 = null;
    var connected_host_owned = false;
    var connected_port: u16 = 0;
    var connect_ms: i64 = 0;
    defer {
        if (h3cli) |*h| h.deinit();
        if (client) |*c| c.deinit();
        if (connected_host_owned) {
            if (connected_host) |host| job.allocator.free(host);
        }
    }

    while (true) {
        const parsed = try parseH3Url(current_url);

        const origin_changed = connected_host == null or
            !sameOrigin(connected_host.?, connected_port, parsed.host, parsed.port);
        if (origin_changed) {
            if (h3cli) |*h| h.deinit();
            if (client) |*c| c.deinit();
            if (connected_host_owned) {
                if (connected_host) |host| job.allocator.free(host);
            }
            h3cli = null;
            client = null;
            connected_host = null;
            connected_host_owned = false;

            const new_host = try job.allocator.dupe(u8, parsed.host);
            errdefer job.allocator.free(new_host);

            const ip = try resolveHostWithOverrides(io, parsed.host, parsed.port, job.resolve);
            if (common.g_verbose) {
                std.debug.print("* resolve {s} -> {d}.{d}.{d}.{d}\n", .{ parsed.host, ip[0], ip[1], ip[2], ip[3] });
            }
            // Initialise directly into the optional payload so the drive task
            // started by `connect()` keeps pointing at a stable address.
            client = try Client.init(job.allocator, io, .{
                .server_host = ip,
                .server_port = parsed.port,
                .server_name = parsed.host,
                .alpn = &alpn_h3,
                .insecure_skip_verify = job.insecure or job.ca_bundle == null,
                .ca_bundle = job.ca_bundle,
            });
            errdefer {
                if (client) |*c| {
                    c.deinit();
                    client = null;
                }
            }
            const c0 = std.Io.Timestamp.now(io, .awake);
            if (job.connect_timeout_ms) |ms| {
                try connectWithTimeout(io, ms, &client.?);
            } else {
                try client.?.connect();
            }
            const c1 = std.Io.Timestamp.now(io, .awake);
            connect_ms = std.Io.Duration.toMilliseconds(c0.durationTo(c1));
            if (common.g_verbose) {
                std.debug.print("* Connected to {s} ({d}.{d}.{d}.{d}) port {d}\n", .{ parsed.host, ip[0], ip[1], ip[2], ip[3], parsed.port });
            }

            // Initialise directly into the optional payload: `run()` points
            // the adapter's ctx at the H3 client itself, so it must not move.
            h3cli = RuntimeH3Client.init(job.allocator, &client.?, 4096, 8);
            errdefer {
                if (h3cli) |*h| {
                    h.deinit();
                    h3cli = null;
                }
            }
            try h3cli.?.run();
            // A diagnostic client should fetch bodies larger than the library's
            // 1 MiB default response cap.
            h3cli.?.h3.max_response_body_size = max_cli_response_body_size;

            connected_host = new_host;
            connected_host_owned = true;
            connected_port = parsed.port;
        }

        var cookie_hdr_buf: ?[]u8 = null;
        defer if (cookie_hdr_buf) |b| job.allocator.free(b);
        var hop_headers: ?[]quicz.qpack.HeaderField = null;
        defer if (hop_headers) |hh| job.allocator.free(hh);
        const headers_for_request = blk: {
            if (job.cookie_jar) |jar| {
                if (try jar.headerFor(job.allocator, unixNow(io), parsed.host, parsed.path)) |cookie_hdr| {
                    cookie_hdr_buf = cookie_hdr;
                    const all = try job.allocator.alloc(quicz.qpack.HeaderField, job.headers.len + 1);
                    hop_headers = all;
                    @memcpy(all[0..job.headers.len], job.headers);
                    all[job.headers.len] = .{ .name = "cookie", .value = cookie_hdr };
                    break :blk all;
                }
            }
            break :blk job.headers;
        };
        const request = quicz.h3_request.Request{
            .method = job.method,
            .path = parsed.path,
            .scheme = "https",
            .authority = parsed.host,
            .extra_headers = headers_for_request,
            .body = job.body,
        };
        const sid = try h3cli.?.sendRequest(request);
        if (common.g_verbose) std.debug.print("> {s} {s} HTTP/3\n", .{ job.method, parsed.path });
        const response = try h3cli.?.receiveResponse(sid);

        if (job.max_filesize) |limit| {
            if (response.body) |b| {
                if (b.len > limit) return error.MaxFilesizeExceeded;
            }
        }

        if (job.cookie_jar) |jar| {
            const now = unixNow(io);
            for (response.headers) |h| {
                if (std.mem.eql(u8, h.name, "set-cookie")) {
                    jar.addSetCookie(job.allocator, now, parsed.host, h.value) catch {};
                }
            }
        }

        if (job.follow_redirects and isRedirectStatus(response.status)) {
            if (findHeader(response.headers, "location")) |location| {
                if (redirects_left == 0) return error.TooManyRedirects;
                const next_url = try resolveLocation(job.allocator, current_url, location);
                if (common.g_verbose) std.debug.print("* redirect: {s}\n", .{next_url});
                if (current_url_owned) job.allocator.free(current_url);
                current_url = next_url;
                current_url_owned = true;
                redirects_left -= 1;
                redirect_count += 1;
                continue;
            }
        }

        if (job.fail_on_http_error and response.status >= 400) {
            std.debug.print("HTTP/3 {d}\n", .{response.status});
            return error.HttpError;
        }

        if (job.dump_headers_path) |dump_path| {
            try writeHeadersToFile(io, dump_path, response.status, response.headers);
        }

        if (job.include_headers) {
            std.debug.print("HTTP/3 {d}\n", .{response.status});
            for (response.headers) |h| {
                // Skip QPACK pseudo-headers; the status line already shows them.
                if (h.name.len > 0 and h.name[0] == ':') continue;
                std.debug.print("{s}: {s}\n", .{ h.name, h.value });
            }
        } else {
            std.debug.print("HTTP/3 {d}\n", .{response.status});
        }

        if (job.output_path) |path| {
            if (std.mem.eql(u8, path, "-")) {
                if (response.body) |payload| try std.Io.File.stdout().writeStreamingAll(io, payload);
            } else {
                const file = try std.Io.Dir.createFile(.cwd(), io, path, .{});
                defer file.close(io);
                if (response.body) |payload| try file.writeStreamingAll(io, payload);
            }
        } else if (response.body) |payload| {
            try std.Io.File.stdout().writeStreamingAll(io, payload);
        }

        if (job.follow_redirects and !std.mem.eql(u8, current_url, job.url)) {
            std.debug.print("final URL: {s}\n", .{current_url});
        }

        if (job.write_out) |fmt| {
            const t1 = std.Io.Timestamp.now(io, .awake);
            try writeOutVars(io, fmt, .{
                .http_code = response.status,
                .url_effective = current_url,
                .time_total_ms = @intCast(@max(std.Io.Duration.toMilliseconds(t0.durationTo(t1)), 0)),
                .time_connect_ms = @intCast(@max(connect_ms, 0)),
                .size_download = if (response.body) |b| b.len else 0,
                .num_redirects = redirect_count,
            });
        } else if (!job.silent) {
            const stats = h3cli.?.client.client.transport.connection.connectionStats();
            std.debug.print("connect={d} ms srtt={d} us loss={d} retrans={d} sent={d} received={d}\n", .{
                connect_ms,
                stats.smoothed_rtt_us,
                stats.packets_lost,
                stats.packets_retransmitted,
                stats.stream_bytes_sent,
                stats.stream_bytes_received,
            });
        }
        return;
    }
}

fn cmdH3(allocator: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !void {
    var url = try nextArg(args);
    var owned_url: ?[]u8 = null;
    defer if (owned_url) |u| allocator.free(u);
    var insecure = false;
    var method: []const u8 = "GET";
    var body: ?[]const u8 = null;
    var timeout_ms: u64 = 10000;
    var method_explicit = false;
    var headers = std.ArrayList(quicz.qpack.HeaderField).empty;
    defer headers.deinit(allocator);
    defer {
        for (headers.items) |h| allocator.free(h.name);
    }
    var ca_pem: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var dump_headers_path: ?[]const u8 = null;
    var include_headers = false;
    var follow_redirects = false;
    var max_redirects: usize = 10;
    var silent = false;
    var fail_on_http_error = false;
    var owned_body: ?[]u8 = null;
    defer if (owned_body) |b| allocator.free(b);
    var data_given = false;
    var get_mode = false;
    var user_agent: ?[]const u8 = null;
    var upload_given = false;
    var write_out: ?[]const u8 = null;
    var max_filesize: ?usize = null;
    var auth_buf: [128]u8 = undefined;
    var connect_timeout_ms: ?u64 = null;
    var resolves = std.ArrayList(ResolveOverride).empty;
    defer resolves.deinit(allocator);
    var cookie_jar: ?cookies.CookieJar = null;
    defer if (cookie_jar) |*cj| cj.deinit();

    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "-k")) {
            insecure = true;
        } else if (std.mem.eql(u8, a, "-G") or std.mem.eql(u8, a, "--get")) {
            get_mode = true;
        } else if (std.mem.eql(u8, a, "-v") or std.mem.eql(u8, a, "--verbose")) {
            common.g_verbose = true;
        } else if (std.mem.eql(u8, a, "-f") or std.mem.eql(u8, a, "--fail")) {
            fail_on_http_error = true;
        } else if (std.mem.eql(u8, a, "-s") or std.mem.eql(u8, a, "--silent")) {
            silent = true;
        } else if (std.mem.eql(u8, a, "-I") or std.mem.eql(u8, a, "--head")) {
            method = "HEAD";
            method_explicit = true;
            include_headers = true;
        } else if (std.mem.eql(u8, a, "-i") or std.mem.eql(u8, a, "--include")) {
            include_headers = true;
        } else if (std.mem.eql(u8, a, "-L") or std.mem.eql(u8, a, "--location")) {
            follow_redirects = true;
        } else if (std.mem.eql(u8, a, "-D") or std.mem.eql(u8, a, "--dump-header")) {
            dump_headers_path = try nextArg(args);
        } else if (std.mem.eql(u8, a, "--max-redirects")) {
            max_redirects = try std.fmt.parseInt(usize, try nextArg(args), 10);
        } else if (std.mem.eql(u8, a, "--max-filesize")) {
            max_filesize = try std.fmt.parseInt(usize, try nextArg(args), 10);
        } else if (std.mem.eql(u8, a, "-o") or std.mem.eql(u8, a, "--output")) {
            output_path = try nextArg(args);
        } else if (std.mem.eql(u8, a, "-X")) {
            method = try nextArg(args);
            method_explicit = true;
        } else if (std.mem.eql(u8, a, "-d") or std.mem.eql(u8, a, "--data")) {
            const raw = try nextArg(args);
            data_given = true;
            if (raw.len > 0 and raw[0] == '@') {
                const buf = try readFileAll(allocator, io, raw[1..]);
                owned_body = buf;
                body = buf;
            } else {
                body = raw;
            }
        } else if (std.mem.eql(u8, a, "-T") or std.mem.eql(u8, a, "--upload-file")) {
            const file_path = try nextArg(args);
            const buf = try readFileAll(allocator, io, file_path);
            owned_body = buf;
            body = buf;
            method = "PUT";
            method_explicit = true;
            data_given = true;
            upload_given = true;
        } else if (std.mem.eql(u8, a, "-A") or std.mem.eql(u8, a, "--user-agent")) {
            user_agent = try nextArg(args);
        } else if (std.mem.eql(u8, a, "-u") or std.mem.eql(u8, a, "--user")) {
            const value = try buildBasicAuth(try nextArg(args), &auth_buf);
            try setHeader(allocator, &headers, "authorization", value);
        } else if (std.mem.eql(u8, a, "-e") or std.mem.eql(u8, a, "--referer")) {
            try setHeader(allocator, &headers, "referer", try nextArg(args));
        } else if (std.mem.eql(u8, a, "-b") or std.mem.eql(u8, a, "--cookie")) {
            const value = try nextArg(args);
            if (value.len > 0 and value[0] == '@') {
                if (cookie_jar == null) cookie_jar = cookies.CookieJar.init(allocator);
                try cookie_jar.?.loadFromFile(io, value[1..]);
            } else {
                try setHeader(allocator, &headers, "cookie", value);
            }
        } else if (std.mem.eql(u8, a, "-c") or std.mem.eql(u8, a, "--cookie-jar")) {
            const jar_path = try nextArg(args);
            if (cookie_jar == null) cookie_jar = cookies.CookieJar.init(allocator);
            cookie_jar.?.save_path = jar_path;
        } else if (std.mem.eql(u8, a, "-w") or std.mem.eql(u8, a, "--write-out")) {
            write_out = try nextArg(args);
        } else if (std.mem.eql(u8, a, "--resolve")) {
            const override = try parseResolveSpec(try nextArg(args));
            try resolves.append(allocator, override);
        } else if (std.mem.eql(u8, a, "--connect-timeout-ms")) {
            connect_timeout_ms = try std.fmt.parseInt(u64, try nextArg(args), 10);
        } else if (std.mem.eql(u8, a, "--connect-timeout")) {
            const secs = try std.fmt.parseInt(u64, try nextArg(args), 10);
            connect_timeout_ms = try std.math.mul(u64, secs, 1000);
        } else if (std.mem.eql(u8, a, "--timeout-ms")) {
            timeout_ms = try std.fmt.parseInt(u64, try nextArg(args), 10);
        } else if (std.mem.eql(u8, a, "--max-time")) {
            const secs = try std.fmt.parseInt(u64, try nextArg(args), 10);
            timeout_ms = try std.math.mul(u64, secs, 1000);
        } else if (std.mem.eql(u8, a, "-H")) {
            const hv = try nextArg(args);
            const colon = std.mem.indexOfScalar(u8, hv, ':') orelse return error.InvalidHeader;
            const name = std.mem.trim(u8, hv[0..colon], " \t");
            const value = std.mem.trim(u8, hv[colon + 1 ..], " \t");
            if (name.len == 0) return error.InvalidHeader;
            const lower_name = try lowercaseName(allocator, name);
            try headers.append(allocator, .{ .name = lower_name, .value = value });
        } else if (std.mem.eql(u8, a, "--ca")) {
            ca_pem = try nextArg(args);
        } else {
            std.debug.print("h3: unknown option: {s}\n", .{a});
            return error.UnknownOption;
        }
    }

    if (get_mode) {
        // `-G` turns `--data` into a URL query and keeps the method GET.
        method = "GET";
        method_explicit = true;
        if (body) |query| {
            const combined = try appendQuery(allocator, url, query);
            owned_url = combined;
            url = combined;
            body = null;
            data_given = false;
        }
    }

    try applyH3Defaults(allocator, &method, method_explicit, data_given, &headers, user_agent, upload_given);

    var maybe_bundle: ?std.crypto.Certificate.Bundle = null;
    if (ca_pem) |pem| {
        if (!std.Io.Dir.path.isAbsolute(pem)) return error.CaPathMustBeAbsolute;
        var bundle: std.crypto.Certificate.Bundle = .empty;
        const now = std.Io.Clock.real.now(io);
        try bundle.addCertsFromFilePathAbsolute(allocator, io, now, pem);
        maybe_bundle = bundle;
    } else if (!insecure) {
        // Verify against the system CA bundle by default; `-k` opts out.
        maybe_bundle = loadSystemCaBundle(allocator, io) catch |err| blk: {
            std.debug.print("h3: system CA bundle unavailable ({s}); certificate verification disabled\n", .{@errorName(err)});
            break :blk null;
        };
    }
    defer {
        if (maybe_bundle) |*b| b.deinit(allocator);
    }

    var job: H3Job = .{
        .allocator = allocator,
        .url = url,
        .method = method,
        .body = body,
        .headers = headers.items,
        .insecure = insecure,
        .ca_bundle = if (maybe_bundle) |*b| b else null,
        .output_path = output_path,
        .include_headers = include_headers,
        .follow_redirects = follow_redirects,
        .max_redirects = max_redirects,
        .silent = silent,
        .fail_on_http_error = fail_on_http_error,
        .dump_headers_path = dump_headers_path,
        .resolve = resolves.items,
        .connect_timeout_ms = connect_timeout_ms,
        .write_out = write_out,
        .max_filesize = max_filesize,
        .cookie_jar = if (cookie_jar) |*cj| cj else null,
    };
    try runWithTimeout(io, timeout_ms, h3Job, &job);
}

test "append query" {
    const allocator = std.testing.allocator;
    const a = try appendQuery(allocator, "https://x/", "a=1");
    defer allocator.free(a);
    try std.testing.expectEqualStrings("https://x/?a=1", a);
    const b = try appendQuery(allocator, "https://x/?q=1", "a=1");
    defer allocator.free(b);
    try std.testing.expectEqualStrings("https://x/?q=1&a=1", b);
}

test "apply h3 defaults" {
    const allocator = std.testing.allocator;
    var headers = std.ArrayList(quicz.qpack.HeaderField).empty;
    defer {
        for (headers.items) |h| allocator.free(h.name);
        headers.deinit(allocator);
    }

    var method: []const u8 = "GET";
    try applyH3Defaults(allocator, &method, false, true, &headers, null, false);
    try std.testing.expectEqualStrings("POST", method);
    try std.testing.expectEqualStrings("application/x-www-form-urlencoded", findHeader(headers.items, "content-type").?);
    try std.testing.expectEqualStrings("quicz/0.1.0", findHeader(headers.items, "user-agent").?);

    // A user-supplied content-type survives; -A replaces any -H user-agent.
    for (headers.items) |h| allocator.free(h.name);
    headers.clearRetainingCapacity();
    const content_type_name = try lowercaseName(allocator, "Content-Type");
    try headers.append(allocator, .{ .name = content_type_name, .value = "application/json" });
    const legacy_ua_name = try lowercaseName(allocator, "User-Agent");
    try headers.append(allocator, .{ .name = legacy_ua_name, .value = "legacy" });
    var m2: []const u8 = "GET";
    try applyH3Defaults(allocator, &m2, false, true, &headers, "my-agent/1.0", false);
    try std.testing.expectEqualStrings("application/json", findHeader(headers.items, "content-type").?);
    try std.testing.expectEqualStrings("my-agent/1.0", findHeader(headers.items, "user-agent").?);
    var ua_count: usize = 0;
    for (headers.items) |h| {
        if (std.mem.eql(u8, h.name, "user-agent")) ua_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), ua_count);

    // An explicit -X GET is not overridden by -d.
    for (headers.items) |h| allocator.free(h.name);
    headers.clearRetainingCapacity();
    var m3: []const u8 = "GET";
    try applyH3Defaults(allocator, &m3, true, true, &headers, null, false);
    try std.testing.expectEqualStrings("GET", m3);
}

test "basic auth and setHeader" {
    const allocator = std.testing.allocator;
    var buf: [128]u8 = undefined;
    const auth = try buildBasicAuth("user:pass", &buf);
    try std.testing.expectEqualStrings("Basic dXNlcjpwYXNz", auth);

    var headers = std.ArrayList(quicz.qpack.HeaderField).empty;
    defer {
        for (headers.items) |h| allocator.free(h.name);
        headers.deinit(allocator);
    }
    try setHeader(allocator, &headers, "authorization", auth);
    try setHeader(allocator, &headers, "authorization", "Basic ABC");
    try std.testing.expectEqualStrings("Basic ABC", findHeader(headers.items, "authorization").?);
    var count: usize = 0;
    for (headers.items) |h| {
        if (std.mem.eql(u8, h.name, "authorization")) count += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), count);
}

test "upload implies octet-stream content type" {
    const allocator = std.testing.allocator;
    var headers = std.ArrayList(quicz.qpack.HeaderField).empty;
    defer {
        for (headers.items) |h| allocator.free(h.name);
        headers.deinit(allocator);
    }
    var method: []const u8 = "PUT";
    try applyH3Defaults(allocator, &method, true, true, &headers, null, true);
    try std.testing.expectEqualStrings("application/octet-stream", findHeader(headers.items, "content-type").?);
}

test "lowercase header name" {
    const out = try lowercaseName(std.testing.allocator, "Content-Type");
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("content-type", out);
}

test "redirect helpers" {
    try std.testing.expect(isRedirectStatus(301));
    try std.testing.expect(isRedirectStatus(308));
    try std.testing.expect(!isRedirectStatus(200));

    try std.testing.expect(sameOrigin("a.com", 443, "a.com", 443));
    try std.testing.expect(!sameOrigin("a.com", 8443, "a.com", 443));
    try std.testing.expect(!sameOrigin("a.com", 443, "b.com", 443));

    const headers = [_]quicz.qpack.HeaderField{
        .{ .name = "content-type", .value = "text/plain" },
        .{ .name = "location", .value = "/new" },
    };
    try std.testing.expectEqualStrings("/new", findHeader(&headers, "location").?);
    try std.testing.expect(findHeader(&headers, "server") == null);
}

test "resolve redirect location" {
    const allocator = std.testing.allocator;
    const abs = try resolveLocation(allocator, "https://a.com/x", "https://b.com/y");
    defer allocator.free(abs);
    try std.testing.expectEqualStrings("https://b.com/y", abs);

    const root = try resolveLocation(allocator, "https://a.com:8443/x", "/new");
    defer allocator.free(root);
    try std.testing.expectEqualStrings("https://a.com:8443/new", root);

    const rel = try resolveLocation(allocator, "https://a.com/a/b", "../c");
    defer allocator.free(rel);
    try std.testing.expectEqualStrings("https://a.com/a/../c", rel);

    try std.testing.expectError(error.NonHttpsRedirect, resolveLocation(allocator, "https://a.com/", "http://b.com/x"));
}
