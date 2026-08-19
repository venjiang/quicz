//! Cookie-jar demo HTTP/3 server.
//!
//! Usage:
//!   zig build run-h3-cookie-server
//!
//! Listens on 127.0.0.1:4434 with ALPN "h3", exercising request-header
//! retention (`DecodedRequest.headers`) plus Set-Cookie / redirect behavior
//! for the CLI cookie jar (`quicz h3 -b @jar -c jar -L`):
//!
//!   /set      -> 200 + Set-Cookie: sid=abc123; Path=/; Max-Age=3600
//!   /redirect -> 302 + Set-Cookie: hops=1; Path=/; Max-Age=3600
//!                + Location: /echo
//!   /echo     -> 200 echoing the received Cookie request header

const std = @import("std");
const test_certs = @import("test_certs.zig");
const quicz = @import("quicz");

const Server = quicz.runtime.server.Server;

const bind_port: u16 = 4434;
const alpn = [_][]const u8{"h3"};
const allocator = std.heap.c_allocator;

var g_echo_buf: [512]u8 = undefined;

fn findCookieHeader(headers: []const quicz.qpack.HeaderField) ?[]const u8 {
    for (headers) |h| {
        if (h.name.len == 6 and std.ascii.eqlIgnoreCase(h.name, "cookie")) return h.value;
    }
    return null;
}

fn handleRequest(req: quicz.h3_request.DecodedRequest) quicz.h3_request.Response {
    std.debug.print("REQ {s} {s} nheaders={d}\n", .{ req.method, req.path, req.headers.len });
    for (req.headers) |h| std.debug.print("  hdr {s}: {s}\n", .{ h.name, h.value });
    if (std.mem.eql(u8, req.method, "GET") and std.mem.eql(u8, req.path, "/set")) {
        return .{
            .status = 200,
            .extra_headers = &.{
                .{ .name = "content-type", .value = "text/plain" },
                .{ .name = "set-cookie", .value = "sid=abc123; Path=/; Max-Age=3600" },
            },
            .body = "set-ok",
        };
    }
    if (std.mem.eql(u8, req.method, "GET") and std.mem.eql(u8, req.path, "/redirect")) {
        return .{
            .status = 302,
            .extra_headers = &.{
                .{ .name = "location", .value = "/echo" },
                .{ .name = "set-cookie", .value = "hops=1; Path=/; Max-Age=3600" },
            },
            .body = "",
        };
    }
    if (std.mem.eql(u8, req.method, "GET") and std.mem.eql(u8, req.path, "/echo")) {
        const cookie = findCookieHeader(req.headers) orelse "";
        const body = std.fmt.bufPrint(&g_echo_buf, "cookie={s}\n", .{cookie}) catch "cookie buffer overflow";
        return .{
            .status = 200,
            .extra_headers = &.{.{ .name = "content-type", .value = "text/plain" }},
            .body = body,
        };
    }
    if (!std.mem.eql(u8, req.method, "GET")) return .{ .status = 405, .body = "method not allowed" };
    return .{ .status = 404, .body = "not found" };
}

pub fn main() !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.init(allocator, io, .{
        .port = bind_port,
        .alpn = &alpn,
        .cert_der = &test_certs.cert_der,
        .private_key = &test_certs.private_key,
    });
    defer server.deinit();
    try server.serveH3(.{}, handleRequest);
    std.debug.print("quicz H3 cookie server: https://127.0.0.1:{d} (ALPN h3)\n", .{bind_port});

    server.drive_group.await(io) catch {};
}
