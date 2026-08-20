//! quicz CLI - daily QUIC / HTTP/3 development tool.
//!
//! Subcommands:
//!   quicz h3 <url> [-k] [-G] [-v] [-i] [-I] [-L] [-s] [-f] [-o FILE] [-D FILE] [--max-redirects N] [--max-filesize BYTES] [-X METHOD] [-A UA] [-u USER:PASS] [-e URL] [-b COOKIE|@FILE] [-c FILE] [-T FILE] [-w FORMAT] [-H NAME:VALUE]... [-d BODY] [--data @FILE] [--resolve HOST:PORT:ADDR] [--ca PEM] [--connect-timeout SECS] [--max-time SECS]
//!   quicz probe <url> [--json|--prometheus|--nagios] [-k] [--ca PEM] [--resolve HOST:PORT:ADDR] [--connect-timeout SECS] [--max-time SECS] [-A UA]
//!   quicz serve [--dir DIR] [--index FILE] [--port N] [--bind IP] [--cert PEM] [--key PEM]
//!   quicz echo --server [--port N] [--bind IP] [--cert PEM] [--key PEM]
//!   quicz echo --client HOST PORT [--data BODY] [--ca PEM]
//!   quicz bench HOST PORT [--size BYTES]
//!
//! The H3 / echo / bench clients accept IPv4 literals, `localhost`, or
//! resolvable host names. `--ca` requires an absolute PEM path.

const std = @import("std");
const test_certs = @import("test_certs");
const quicz = @import("quicz");
const tls_tcp = @import("tls_tcp.zig");
const cookies = @import("cookies.zig");

const common = @import("common.zig");
// Force cmd modules into the test compilation graph so their unit tests run
// (Zig 0.16 only collects tests from imported modules that are referenced).
comptime {
    _ = @import("cmd/h3.zig");
    _ = @import("cmd/probe.zig");
}
const h3 = @import("cmd/h3.zig");
const probe = @import("cmd/probe.zig");
// Re-exported shared helpers so in-file callers keep working while the
// subcommands migrate one by one into cmd/*.zig modules.
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

pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = cliLog,
};

/// The CLI reports its own status and metrics via `std.debug.print`; swallow
/// the library's internal runtime logs so a successful request stays clean
/// even when the peer retransmits a packet the client cannot yet decrypt.
/// `-v` re-enables those runtime logs for connection debugging.

fn cliLog(
    comptime message_level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    if (common.g_verbose) std.log.defaultLog(message_level, scope, format, args);
}

const max_file_size: usize = 32 * 1024 * 1024;

/// Shared serve state. The H3 request handler is a plain function pointer, so
/// the CLI keeps the process Io, allocator, root directory, and server in
/// globals. Each connection driver owns its H3 state; the handler only borrows
/// these for file I/O.
var g_server: ?*Server = null;
var g_io: std.Io = undefined;
var g_allocator: std.mem.Allocator = undefined;
var g_root_dir: std.Io.Dir = undefined;
var g_index_name: []const u8 = "index.html";
var g_metrics_buf: [512]u8 = undefined;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    const sub = args.next() orelse {
        printUsage();
        return;
    };

    if (std.mem.eql(u8, sub, "h3")) return h3.run(allocator, io, &args);
    if (std.mem.eql(u8, sub, "probe")) return probe.run(allocator, io, &args);
    if (std.mem.eql(u8, sub, "serve")) return cmdServe(allocator, io, &args);
    if (std.mem.eql(u8, sub, "echo")) return cmdEcho(allocator, io, &args);
    if (std.mem.eql(u8, sub, "bench")) return cmdBench(allocator, io, &args);
    if (std.mem.eql(u8, sub, "help") or std.mem.eql(u8, sub, "--help") or std.mem.eql(u8, sub, "-h")) {
        printUsage();
        return;
    }
    std.debug.print("unknown subcommand: {s}\n\n", .{sub});
    printUsage();
}

fn printUsage() void {
    std.debug.print(
        \\quicz - QUIC / HTTP/3 development tool
        \\
        \\Usage:
        \\  quicz h3 <url> [-k] [-G] [-v] [-i] [-I] [-L] [-s] [-f] [-o FILE] [-D FILE] [--max-redirects N] [--max-filesize BYTES] [-X METHOD] [-A UA] [-u USER:PASS] [-e URL] [-b COOKIE|@FILE] [-c FILE] [-T FILE] [-w FORMAT] [-H NAME:VALUE]... [-d BODY] [--data @FILE] [--resolve HOST:PORT:ADDR] [--ca PEM] [--connect-timeout SECS] [--max-time SECS]
        \\  quicz probe <url> [--json] [-k] [--ca PEM] [--resolve HOST:PORT:ADDR] [--connect-timeout SECS] [--max-time SECS] [-A UA]
        \\                                     (scheme-less URLs are treated as https://; other schemes are rejected)
        \\  quicz serve [--dir DIR] [--index FILE] [--port N] [--bind IP] [--cert PEM] [--key PEM]
        \\  quicz echo --server [--port N] [--bind IP] [--cert PEM] [--key PEM]
        \\  quicz echo --client HOST PORT [--data BODY] [--ca PEM] [--timeout-ms MS]
        \\  quicz bench HOST PORT [--size BYTES] [--timeout-ms MS]
        \\
    , .{});
}

// ---------------------------------------------------------------- h3 server

fn sanitizeRelPath(path: []const u8) ![]const u8 {
    if (path.len == 0 or path[0] != '/') return error.BadPath;
    var it = std.mem.splitScalar(u8, path[1..], '/');
    while (it.next()) |seg| {
        if (std.mem.eql(u8, seg, "..")) return error.BadPath;
    }
    return path[1..];
}

fn contentTypeFor(path: []const u8) []const u8 {
    const ext = std.fs.path.extension(path);
    if (std.mem.eql(u8, ext, ".html") or std.mem.eql(u8, ext, ".htm")) return "text/html; charset=utf-8";
    if (std.mem.eql(u8, ext, ".css")) return "text/css; charset=utf-8";
    if (std.mem.eql(u8, ext, ".js")) return "application/javascript";
    if (std.mem.eql(u8, ext, ".json")) return "application/json";
    if (std.mem.eql(u8, ext, ".txt")) return "text/plain; charset=utf-8";
    if (std.mem.eql(u8, ext, ".md")) return "text/markdown";
    if (std.mem.eql(u8, ext, ".wasm")) return "application/wasm";
    if (std.mem.eql(u8, ext, ".png")) return "image/png";
    if (std.mem.eql(u8, ext, ".jpg") or std.mem.eql(u8, ext, ".jpeg")) return "image/jpeg";
    if (std.mem.eql(u8, ext, ".gif")) return "image/gif";
    if (std.mem.eql(u8, ext, ".svg")) return "image/svg+xml";
    if (std.mem.eql(u8, ext, ".ico")) return "image/x-icon";
    if (std.mem.eql(u8, ext, ".pdf")) return "application/pdf";
    if (std.mem.eql(u8, ext, ".mp4")) return "video/mp4";
    if (std.mem.eql(u8, ext, ".webm")) return "video/webm";
    if (std.mem.eql(u8, ext, ".mp3")) return "audio/mpeg";
    if (std.mem.eql(u8, ext, ".zip")) return "application/zip";
    return "application/octet-stream";
}

/// Response body that owns a heap buffer and releases it after the H3 server
/// finishes pumping (or cancels) the stream.
const OwnedBody = struct {
    allocator: std.mem.Allocator,
    data: []u8,
    /// Extra response headers. The H3 response borrows this slice, so it must
    /// outlive the handler return; owned here and freed with the body.
    headers: []quicz.qpack.HeaderField,
    offset: usize = 0,

    fn allData(self: *OwnedBody) []const u8 {
        return self.data[self.offset..];
    }
};

fn ownedBodyNext(ctx: *anyopaque, buf: []u8) anyerror!?usize {
    const state: *OwnedBody = @ptrCast(@alignCast(ctx));
    if (state.offset >= state.data.len) return null;
    const n = @min(state.data.len - state.offset, buf.len);
    @memcpy(buf[0..n], state.data[state.offset .. state.offset + n]);
    state.offset += n;
    return n;
}

fn ownedBodyDeinit(ctx: *anyopaque) void {
    const state: *OwnedBody = @ptrCast(@alignCast(ctx));
    const allocator = state.allocator;
    allocator.free(state.headers);
    allocator.free(state.data);
    allocator.destroy(state);
}

fn ownedResponse(status: u16, content_type: []const u8, data: []u8) quicz.h3_request.Response {
    const allocator = g_allocator;
    const state = allocator.create(OwnedBody) catch return .{ .status = 500, .body = "out of memory" };
    const headers = allocator.alloc(quicz.qpack.HeaderField, 1) catch return .{ .status = 500, .body = "out of memory" };
    headers[0] = .{ .name = "content-type", .value = content_type };
    state.* = .{ .allocator = allocator, .data = data, .headers = headers };
    return .{
        .status = status,
        .extra_headers = headers,
        .body_stream = .{ .ctx = state, .next_fn = ownedBodyNext, .deinit_fn = ownedBodyDeinit },
    };
}

fn headResponse(status: u16, content_type: []const u8) quicz.h3_request.Response {
    const allocator = g_allocator;
    const state = allocator.create(OwnedBody) catch return .{ .status = 500, .body = "out of memory" };
    const headers = allocator.alloc(quicz.qpack.HeaderField, 1) catch {
        allocator.destroy(state);
        return .{ .status = 500, .body = "out of memory" };
    };
    const data = allocator.alloc(u8, 0) catch {
        allocator.free(headers);
        allocator.destroy(state);
        return .{ .status = 500, .body = "out of memory" };
    };
    headers[0] = .{ .name = "content-type", .value = content_type };
    state.* = .{ .allocator = allocator, .data = data, .headers = headers };
    return .{
        .status = status,
        .extra_headers = headers,
        .body_stream = .{ .ctx = state, .next_fn = ownedBodyNext, .deinit_fn = ownedBodyDeinit },
    };
}

fn readFileBody(rel: []const u8) ![]u8 {
    const file = try g_root_dir.openFile(g_io, rel, .{});
    defer file.close(g_io);
    const len = try file.length(g_io);
    if (len > max_file_size) return error.FileTooLarge;
    const buf = try g_allocator.alloc(u8, @intCast(len));
    errdefer g_allocator.free(buf);
    const n = try file.readPositionalAll(g_io, buf, 0);
    return buf[0..n];
}

fn directoryListingResponse(rel: []const u8) quicz.h3_request.Response {
    var prefix_buf: [4096]u8 = undefined;
    const prefix: []const u8 = if (rel.len == 0) "/" else blk: {
        const trimmed = if (rel[rel.len - 1] == '/') rel[0 .. rel.len - 1] else rel;
        const written = std.fmt.bufPrint(&prefix_buf, "/{s}/", .{trimmed}) catch return .{ .status = 500, .body = "server error" };
        break :blk written;
    };
    var dir_owned = false;
    const dir = if (rel.len == 0) g_root_dir else blk: {
        const d = g_root_dir.openDir(g_io, rel, .{ .iterate = true }) catch return .{ .status = 500, .body = "server error" };
        dir_owned = true;
        break :blk d;
    };
    defer if (dir_owned) dir.close(g_io);
    var out = std.ArrayList(u8).empty;
    defer out.deinit(g_allocator);
    out.appendSlice(g_allocator, "<!doctype html><html><head><meta charset=\"utf-8\"><title>quicz serve</title></head><body><h1>quicz serve</h1><ul>") catch return .{ .status = 500, .body = "server error" };
    var it = std.Io.Dir.iterate(dir);
    while (true) {
        const maybe_entry = it.next(g_io) catch return .{ .status = 500, .body = "server error" };
        const entry = maybe_entry orelse break;
        out.appendSlice(g_allocator, "<li><a href=\"") catch return .{ .status = 500, .body = "server error" };
        out.appendSlice(g_allocator, prefix) catch return .{ .status = 500, .body = "server error" };
        out.appendSlice(g_allocator, entry.name) catch return .{ .status = 500, .body = "server error" };
        out.appendSlice(g_allocator, "\">") catch return .{ .status = 500, .body = "server error" };
        out.appendSlice(g_allocator, entry.name) catch return .{ .status = 500, .body = "server error" };
        out.appendSlice(g_allocator, if (entry.kind == .directory) "/</a></li>" else "</a></li>") catch return .{ .status = 500, .body = "server error" };
    }
    out.appendSlice(g_allocator, "</ul></body></html>") catch return .{ .status = 500, .body = "server error" };
    const data = out.toOwnedSlice(g_allocator) catch return .{ .status = 500, .body = "server error" };
    return ownedResponse(200, "text/html; charset=utf-8", data);
}

/// Serve a directory: its `--index` file when present, otherwise a listing.
fn serveDirectory(rel: []const u8, is_head: bool) ?quicz.h3_request.Response {
    const dir = g_root_dir.openDir(g_io, rel, .{ .iterate = true }) catch return null;
    defer dir.close(g_io);

    const file = dir.openFile(g_io, g_index_name, .{}) catch null;
    if (file) |f| {
        defer f.close(g_io);
        const len = f.length(g_io) catch return .{ .status = 500, .body = "server error" };
        if (len > max_file_size) return .{ .status = 413, .body = "file too large" };
        const data = g_allocator.alloc(u8, @intCast(len)) catch return .{ .status = 500, .body = "server error" };
        errdefer g_allocator.free(data);
        const n = f.readPositionalAll(g_io, data, 0) catch return .{ .status = 500, .body = "server error" };
        const body = data[0..n];
        if (is_head) {
            g_allocator.free(data);
            return headResponse(200, contentTypeFor(g_index_name));
        }
        return ownedResponse(200, contentTypeFor(g_index_name), body);
    }

    if (is_head) return headResponse(200, "text/html; charset=utf-8");
    return directoryListingResponse(rel);
}

/// HTTP/3 request echo: returns the method, path, authority, and body the
/// client sent, so any H3 client can inspect its request on the wire.
fn echoResponse(req: quicz.h3_request.DecodedRequest, is_head: bool) quicz.h3_request.Response {
    if (is_head) return headResponse(200, "text/plain; charset=utf-8");
    var out = std.ArrayList(u8).empty;
    defer out.deinit(g_allocator);
    out.appendSlice(g_allocator, "method: ") catch return .{ .status = 500, .body = "server error" };
    out.appendSlice(g_allocator, req.method) catch return .{ .status = 500, .body = "server error" };
    out.appendSlice(g_allocator, "\npath: ") catch return .{ .status = 500, .body = "server error" };
    out.appendSlice(g_allocator, req.path) catch return .{ .status = 500, .body = "server error" };
    if (req.authority) |authority| {
        out.appendSlice(g_allocator, "\nauthority: ") catch return .{ .status = 500, .body = "server error" };
        out.appendSlice(g_allocator, authority) catch return .{ .status = 500, .body = "server error" };
    }
    if (req.body) |body| {
        out.appendSlice(g_allocator, "\nbody: ") catch return .{ .status = 500, .body = "server error" };
        out.appendSlice(g_allocator, body) catch return .{ .status = 500, .body = "server error" };
    }
    const data = out.toOwnedSlice(g_allocator) catch return .{ .status = 500, .body = "server error" };
    return ownedResponse(200, "text/plain; charset=utf-8", data);
}

fn serveHandler(req: quicz.h3_request.DecodedRequest) quicz.h3_request.Response {
    const is_head = std.mem.eql(u8, req.method, "HEAD");
    const req_path = if (std.mem.indexOfScalar(u8, req.path, '?')) |q| req.path[0..q] else req.path;
    if (std.mem.eql(u8, req_path, "/echo")) return echoResponse(req, is_head);
    if (!std.mem.eql(u8, req.method, "GET") and !is_head) {
        return .{ .status = 405, .extra_headers = &.{.{ .name = "allow", .value = "GET, HEAD" }}, .body = "method not allowed" };
    }

    if (std.mem.eql(u8, req_path, "/metrics")) {
        if (g_server) |srv| {
            const m = srv.metricsSnapshot();
            const body = std.fmt.bufPrint(&g_metrics_buf, "connections={d}\nsent={d}\nreceived={d}\nin_flight={d}\nsrtt_us={d}\nloss={d}\nretransmitted={d}\n", .{
                m.active_connections,
                m.stream_bytes_sent,
                m.stream_bytes_received,
                m.total_bytes_in_flight,
                m.smoothed_rtt_us,
                m.packets_lost,
                m.packets_retransmitted,
            }) catch "metrics error";
            if (is_head) return headResponse(200, "text/plain");
            return .{ .status = 200, .extra_headers = &.{.{ .name = "content-type", .value = "text/plain" }}, .body = body };
        }
        return .{ .status = 503, .body = "server not ready" };
    }

    const rel = sanitizeRelPath(req_path) catch return .{ .status = 400, .body = "bad request" };
    const primary = if (rel.len == 0) g_index_name else rel;
    if (readFileBody(primary)) |data| {
        if (is_head) {
            g_allocator.free(data);
            return headResponse(200, contentTypeFor(primary));
        }
        return ownedResponse(200, contentTypeFor(primary), data);
    } else |e| switch (e) {
        error.FileTooLarge => return .{ .status = 413, .body = "file too large" },
        else => {
            if (rel.len == 0) {
                if (is_head) return headResponse(200, "text/html; charset=utf-8");
                return directoryListingResponse("");
            }
            return serveDirectory(rel, is_head) orelse .{ .status = 404, .body = "not found" };
        },
    }
}

/// HTTP/1.1 fallback server so browsers can open the same static content over
/// TCP while the QUIC listener keeps serving HTTP/3. Mirrors how real H3 sites
/// expose both listeners and let browsers upgrade via Alt-Svc.
fn serveHttp11(tcp_server: *std.Io.net.Server, port: u16, tls_config: tls_tcp.Config) std.Io.Cancelable!void {
    const io = g_io;
    var group: std.Io.Group = .init;
    defer group.cancel(io);
    while (true) {
        var stream = tcp_server.accept(io) catch |err| switch (err) {
            error.Canceled => |e| return e,
            else => {
                std.debug.print("serve: HTTP/1.1 accept failed: {s}\n", .{@errorName(err)});
                return;
            },
        };
        group.concurrent(io, handleHttp11Connection, .{ stream, port, tls_config }) catch |err| {
            std.debug.print("serve: HTTP/1.1 handler spawn failed: {s}\n", .{@errorName(err)});
            stream.close(io);
            continue;
        };
    }
}

fn handleHttp11Connection(stream: std.Io.net.Stream, port: u16, tls_config: tls_tcp.Config) void {
    const io = g_io;
    defer {
        var copy = stream;
        copy.close(io);
    }
    var send_buffer: [65536]u8 = undefined;
    var recv_buffer: [65536]u8 = undefined;
    var connection_reader = stream.reader(io, &recv_buffer);
    var connection_writer = stream.writer(io, &send_buffer);
    var tls_stream = tls_tcp.TlsStream.handshake(&connection_reader.interface, &connection_writer.interface, tls_config) catch |err| {
        std.debug.print("serve: TLS handshake failed: {s}\n", .{@errorName(err)});
        return;
    };
    handleHttp11Tls(&tls_stream, port);
}

/// Read one HTTP/1.1 request head over the TLS stream and respond, then close
/// when the client asks to. GET/HEAD responses keep the connection alive so a
/// browser can fetch the page's CSS/JS/images without a fresh TLS handshake.
fn handleHttp11Tls(tls_stream: *tls_tcp.TlsStream, port: u16) void {
    var req_buf: [16384]u8 = undefined;
    var req_len: usize = 0;
    while (true) {
        var head_end: ?usize = null;
        while (head_end == null) {
            if (req_len >= req_buf.len) return;
            const n = tls_stream.read(req_buf[req_len..]) catch return;
            if (n == 0) return;
            req_len += n;
            head_end = std.mem.indexOf(u8, req_buf[0..req_len], "\r\n\r\n");
        }
        const keep_alive = handleHttp11Request(tls_stream, req_buf[0..head_end.?], port) catch |err| {
            if (common.g_verbose) std.debug.print("serve: HTTP/1.1 request failed: {s}\n", .{@errorName(err)});
            return;
        };
        const consumed = head_end.? + 4;
        std.mem.copyForwards(u8, req_buf[0 .. req_len - consumed], req_buf[consumed..req_len]);
        req_len -= consumed;
        if (!keep_alive) return;
    }
}

fn connectionWantsClose(head: []const u8) bool {
    var it = std.mem.splitScalar(u8, head, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, "\r");
        if (std.ascii.startsWithIgnoreCase(line, "connection:")) {
            const value = std.mem.trim(u8, line["connection:".len..], " \t");
            return std.ascii.indexOfIgnoreCase(value, "close") != null;
        }
    }
    return false;
}

fn handleHttp11Request(tls_stream: *tls_tcp.TlsStream, head: []const u8, port: u16) !bool {
    const line_end = std.mem.indexOfScalar(u8, head, '\r') orelse return error.BadRequest;
    const request_line = head[0..line_end];
    var sp1 = std.mem.indexOfScalar(u8, request_line, ' ') orelse return error.BadRequest;
    const method = request_line[0..sp1];
    const after_method = request_line[sp1 + 1 ..];
    sp1 = std.mem.indexOfScalar(u8, after_method, ' ') orelse return error.BadRequest;
    const target = after_method[0..sp1];
    if (!std.mem.eql(u8, method, "GET") and !std.mem.eql(u8, method, "HEAD")) {
        try sendHttp11Response(tls_stream, 405, &.{.{ .name = "allow", .value = "GET, HEAD" }}, "method not allowed", port, false, false);
        return false;
    }
    const path = if (std.mem.indexOfScalar(u8, target, '?')) |q| target[0..q] else target;
    const decoded = quicz.h3_request.DecodedRequest{
        .method = method,
        .path = path,
        .scheme = "https",
        .authority = null,
        .body = null,
    };
    const h3resp = serveHandler(decoded);
    defer if (h3resp.body_stream) |bs| bs.deinit();

    var body: []const u8 = "";
    if (h3resp.body) |b| {
        body = b;
    } else if (h3resp.body_stream) |bs| {
        const state: *OwnedBody = @ptrCast(@alignCast(bs.ctx));
        body = state.allData();
    }
    const head_only = std.mem.eql(u8, method, "HEAD");
    const keep_alive = !connectionWantsClose(head);
    try sendHttp11Response(tls_stream, h3resp.status, h3resp.extra_headers, body, port, head_only, keep_alive);
    return keep_alive;
}

fn sendHttp11Response(
    tls_stream: *tls_tcp.TlsStream,
    status_code: u16,
    extra_headers: []const quicz.qpack.HeaderField,
    body: []const u8,
    port: u16,
    head_only: bool,
    keep_alive: bool,
) !void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    const status: std.http.Status = @enumFromInt(@as(u10, @intCast(status_code)));
    const phrase = status.phrase() orelse "Unknown";
    try w.print("HTTP/1.1 {d} {s}\r\n", .{ status_code, phrase });
    for (extra_headers) |h| {
        try w.print("{s}: {s}\r\n", .{ h.name, h.value });
    }
    try w.print("content-length: {d}\r\n", .{body.len});
    try w.print("alt-svc: h3=\":{d}\"; ma=86400\r\n", .{port});
    try w.print("connection: {s}\r\n\r\n", .{if (keep_alive) "keep-alive" else "close"});
    try tls_stream.write(buf[0..w.end]);
    if (!head_only and body.len > 0) try tls_stream.write(body);
}

fn cmdServe(allocator: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !void {
    var dir_path: []const u8 = ".";
    var port: u16 = 4433;
    var bind: ?[4]u8 = null;
    var cert_pem: ?[]const u8 = null;
    var key_pem: ?[]const u8 = null;

    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--dir")) {
            dir_path = try nextArg(args);
        } else if (std.mem.eql(u8, a, "--index")) {
            g_index_name = try nextArg(args);
        } else if (std.mem.eql(u8, a, "--port")) {
            port = try std.fmt.parseInt(u16, try nextArg(args), 10);
        } else if (std.mem.eql(u8, a, "--bind")) {
            bind = try parseIpv4(try nextArg(args));
        } else if (std.mem.eql(u8, a, "--cert")) {
            cert_pem = try nextArg(args);
        } else if (std.mem.eql(u8, a, "--key")) {
            key_pem = try nextArg(args);
        } else {
            std.debug.print("serve: unknown option: {s}\n", .{a});
            return error.UnknownOption;
        }
    }

    g_allocator = allocator;
    g_io = io;
    g_root_dir = try std.Io.Dir.openDir(.cwd(), io, dir_path, .{ .iterate = true });

    const identity = try loadCertKey(io, cert_pem, key_pem);

    var server = try Server.init(allocator, io, .{
        .port = port,
        .alpn = &alpn_h3,
        .cert_der = identity.cert_der,
        .private_key = &identity.private_key,
        .bind_addr = bind,
    });
    defer server.deinit();
    g_server = &server;

    const ip = bind orelse [_]u8{ 127, 0, 0, 1 };
    var tcp_address = std.Io.net.IpAddress{ .ip4 = .{ .bytes = ip, .port = port } };
    var tcp_server = tcp_address.listen(io, .{ .reuse_address = true }) catch |err| {
        std.debug.print("serve: failed to listen on TCP {d}: {s}\n", .{ port, @errorName(err) });
        return err;
    };
    defer tcp_server.deinit(io);
    const tls_config = tls_tcp.Config{
        .cert_der = identity.cert_der,
        .private_key = &identity.private_key,
        .alpn = &.{"http/1.1"},
    };
    var tcp_serve_task = io.concurrent(serveHttp11, .{ &tcp_server, port, tls_config }) catch |err| {
        std.debug.print("serve: failed to start HTTP/1.1 serve loop: {s}\n", .{@errorName(err)});
        return err;
    };
    defer tcp_serve_task.cancel(io) catch {};

    try server.serveH3(.{}, serveHandler);
    std.debug.print("quicz serve: https://127.0.0.1:{d}/ (browser) | HTTP/3 https://127.0.0.1:{d}/ (quicz h3 -k) | dir={s}\n", .{ port, port, dir_path });
    server.drive_group.await(io) catch {};
    tcp_serve_task.await(io) catch {};
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

test "sanitize rel path rejects traversal" {
    try std.testing.expectEqualStrings("a/b", try sanitizeRelPath("/a/b"));
    try std.testing.expectError(error.BadPath, sanitizeRelPath("/a/../b"));
    try std.testing.expectError(error.BadPath, sanitizeRelPath("a/b"));
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

test "cookie jar module" {
    _ = @import("cookies.zig");
}
