//! quicz CLI - daily QUIC / HTTP/3 development tool.
//!
//! Subcommands:
//!   quicz h3 <url> [-k] [-G] [-v] [-i] [-I] [-L] [-s] [-f] [-o FILE] [-D FILE] [--max-redirects N] [--max-filesize BYTES] [-X METHOD] [-A UA] [-u USER:PASS] [-e URL] [-b COOKIE|@FILE] [-c FILE] [-T FILE] [-w FORMAT] [-H NAME:VALUE]... [-d BODY] [--data @FILE] [--resolve HOST:PORT:ADDR] [--ca PEM] [--connect-timeout SECS] [--max-time SECS]
//!   quicz probe <url> [--json|--prometheus|--nagios] [-k] [--ca PEM] [--resolve HOST:PORT:ADDR] [--connect-timeout SECS] [--max-time SECS] [-A UA]
//!   quicz exporter --target URL [--target URL]... [--bind IP] [--port N]
//!   quicz serve [--dir DIR] [--index FILE] [--port N] [--bind IP] [--cert PEM] [--key PEM]
//!   quicz echo --server [--port N] [--bind IP] [--cert PEM] [--key PEM]
//!   quicz echo --client HOST PORT [--data BODY] [--ca PEM]
//!   quicz bench HOST PORT [--size BYTES]
//!
//! The H3 / echo / bench clients accept IPv4 literals, `localhost`, or
//! resolvable host names. `--ca` requires an absolute PEM path.

const std = @import("std");

const common = @import("common.zig");
// Force cmd modules into the test compilation graph so their unit tests run
// (Zig 0.16 only collects tests from imported modules that are referenced).
comptime {
    _ = @import("cmd/h3.zig");
    _ = @import("cmd/probe.zig");
    _ = @import("cmd/exporter.zig");
    _ = @import("cmd/serve.zig");
    _ = @import("cmd/echo.zig");
    _ = @import("cmd/bench.zig");
    _ = @import("cookies.zig");
    _ = @import("svcb.zig");
}
const h3 = @import("cmd/h3.zig");
const probe = @import("cmd/probe.zig");
const exporter = @import("cmd/exporter.zig");
const serve = @import("cmd/serve.zig");
const echo = @import("cmd/echo.zig");
const bench = @import("cmd/bench.zig");

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
    if (std.mem.eql(u8, sub, "exporter")) return exporter.run(allocator, io, &args);
    if (std.mem.eql(u8, sub, "serve")) return serve.run(allocator, io, &args);
    if (std.mem.eql(u8, sub, "echo")) return echo.run(allocator, io, &args);
    if (std.mem.eql(u8, sub, "bench")) return bench.run(allocator, io, &args);
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
        \\  quicz exporter --target URL [--target URL]... [--bind IP] [--port N]
        \\  quicz serve [--dir DIR] [--index FILE] [--port N] [--bind IP] [--cert PEM] [--key PEM]
        \\  quicz echo --server [--port N] [--bind IP] [--cert PEM] [--key PEM]
        \\  quicz echo --client HOST PORT [--data BODY] [--ca PEM] [--timeout-ms MS]
        \\  quicz bench HOST PORT [--size BYTES] [--timeout-ms MS]
        \\
    , .{});
}
