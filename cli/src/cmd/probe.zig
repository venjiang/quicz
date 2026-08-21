//! `quicz probe` subcommand: HTTP/3/QUIC service health check with
//! pass/fail verdict and single-stage failure attribution.

const std = @import("std");
const quicz = @import("quicz");
const common = @import("../common.zig");
const svcb = @import("../svcb.zig");

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
    try cmdProbe(allocator, io, args);
}

// ---------------------------------------------------------------- probe

/// Normalize the probe target URL. Returns the URL unchanged when it already
/// has the `https://` scheme, prefixes `https://` for scheme-less inputs
/// (curl-like convenience), and returns null for any explicit non-https
/// scheme (http://, ftp://, ...) so the caller can report a usage error
/// instead of silently rewriting an explicit scheme.
pub fn normalizeProbeTarget(raw: []const u8, buf: []u8) ?[]const u8 {
    if (std.mem.startsWith(u8, raw, "https://")) return raw;
    if (std.mem.indexOf(u8, raw, "://") != null) return null;
    return std.fmt.bufPrint(buf, "https://{s}", .{raw}) catch return null;
}

/// HTTP/3/QUIC service health probe (`quicz probe <url>`). Follows the
/// `quicz.md` product plan: report DNS, UDP reachability, QUIC/TLS handshake,
/// ALPN and an HTTP/3 request, and attribute failures to a single stage.
const ProbeStage = enum {
    invalid_url,
    dns_resolve_failed,
    udp_timeout,
    quic_handshake_failed,
    tls_cert_failed,
    http3_request_failed,
    probe_timeout,
};

pub const ProbeResult = struct {
    target: []const u8,
    dns_ok: bool,
    resolved_ip: ?[4]u8,
    udp_reachable: bool,
    quic_handshake_success: bool,
    alpn: ?[]const u8,
    http3_request_success: bool,
    http_status: ?u16,
    alt_svc_h3: ?bool = null,
    alt_svc_value: ?[]const u8 = null,
    fallback_reachable: ?bool = null,
    fallback_http_version: ?[]const u8 = null,
    fallback_http_status: ?u16 = null,
    fallback_detected: ?bool = null,
    svcb_query_ok: bool = false,
    svcb_h3: bool = false,
    svcb_priority: ?u16 = null,
    svcb_target: ?[]const u8 = null,
    svcb_alpn: ?[]const u8 = null,
    svcb_port: ?u16 = null,
    failure_stage: ?ProbeStage,
    handshake_ms: u64,
    request_ms: u64,

    fn isOk(self: *const ProbeResult) bool {
        return self.failure_stage == null;
    }
};

pub const ProbeOptions = struct {
    target: []const u8,
    insecure: bool = false,
    ca_path: ?[]const u8 = null,
    resolve: []const ResolveOverride = &.{},
    connect_timeout_ms: ?u64 = null,
    timeout_ms: u64 = 10000,
    user_agent: []const u8 = "quicz-probe/0.1",
    check_alt_svc: bool = true,
};

const ProbeStageName = enum { invalid_url, dns_resolve_failed, udp_timeout, quic_handshake_failed, tls_cert_failed, http3_request_failed, probe_timeout };

fn probeStageName(stage: ProbeStage) []const u8 {
    return switch (stage) {
        .invalid_url => "invalid_url",
        .dns_resolve_failed => "dns_resolve_failed",
        .udp_timeout => "udp_timeout",
        .quic_handshake_failed => "quic_handshake_failed",
        .tls_cert_failed => "tls_cert_failed",
        .http3_request_failed => "http3_request_failed",
        .probe_timeout => "probe_timeout",
    };
}

fn completeProbe(
    allocator: std.mem.Allocator,
    io: std.Io,
    result: *ProbeResult,
    opts: ProbeOptions,
    ip: [4]u8,
    parsed_host: []const u8,
    parsed_port: u16,
    parsed_path: []const u8,
    ca_bundle: ?*std.crypto.Certificate.Bundle,
) ProbeResult {
    if (opts.check_alt_svc) {
        checkAltSvc(allocator, io, result, opts, ip, parsed_host, parsed_port, parsed_path, ca_bundle) catch {};
    }
    if (result.fallback_reachable) |reachable| {
        result.fallback_detected = reachable and result.failure_stage != null;
    }
    return result.*;
}

pub fn deinitProbeResult(allocator: std.mem.Allocator, result: *const ProbeResult) void {
    if (result.alt_svc_value) |value| allocator.free(value);
    if (result.svcb_target) |value| allocator.free(value);
    if (result.svcb_alpn) |value| allocator.free(value);
}

fn writeJsonString(out: *std.Io.Writer, value: []const u8) !void {
    try out.writeByte('"');
    for (value) |char| {
        switch (char) {
            '"' => try out.writeAll("\\\""),
            '\\' => try out.writeAll("\\\\"),
            '\n' => try out.writeAll("\\n"),
            '\r' => try out.writeAll("\\r"),
            '\t' => try out.writeAll("\\t"),
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f, 0x7f => try out.print("\\u{x:0>4}", .{char}),
            else => try out.writeByte(char),
        }
    }
    try out.writeByte('"');
}

fn altSvcOffersH3(value: []const u8) bool {
    var entries = std.mem.splitScalar(u8, value, ',');
    while (entries.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t");
        const parameter_start = std.mem.indexOfAny(u8, entry, ";=") orelse entry.len;
        const protocol = entry[0..parameter_start];
        if (std.mem.eql(u8, protocol, "h3") or std.mem.startsWith(u8, protocol, "h3-")) return true;
    }
    return false;
}

/// Map a QUIC connect() failure to a probe failure stage.
fn stageForConnectError(e: anyerror) ProbeStage {
    return switch (e) {
        // Nothing answered on UDP: the connect deadline (runWithTimeout maps
        // Canceled -> Timeout), an unroutable destination, or an ICMP port/
        // network unreachable echoed back (ConnectionRefused).
        error.Timeout, error.Canceled, error.NetworkUnreachable, error.HostUnreachable, error.ConnectionRefused => .udp_timeout,
        // Pure-Zig TLS 1.3 surfaces handshake failures (certificate
        // verification included) as CryptoError.
        error.CryptoError => .tls_cert_failed,
        else => .quic_handshake_failed,
    };
}

/// Render the probe result as a text report.
fn renderProbeText(result: ProbeResult) void {
    std.debug.print("probe {s}\n", .{result.target});
    std.debug.print("  dns:           {s}\n", .{if (result.dns_ok) "ok" else "fail"});
    if (result.resolved_ip) |ip| {
        std.debug.print("  resolved_ip:   {d}.{d}.{d}.{d}\n", .{ ip[0], ip[1], ip[2], ip[3] });
    }
    if (result.svcb_query_ok) {
        std.debug.print("  svcb_h3:       {s}\n", .{if (result.svcb_h3) "yes" else "no"});
        if (result.svcb_alpn) |alpn| std.debug.print("  svcb_alpn:     {s}\n", .{alpn});
        if (result.svcb_port) |port| std.debug.print("  svcb_port:     {d}\n", .{port});
    }
    std.debug.print("  udp_reachable: {s}\n", .{if (result.udp_reachable) "ok" else "fail"});
    std.debug.print("  handshake:     {s}\n", .{if (result.quic_handshake_success) "ok" else "fail"});
    std.debug.print("  alpn:          {s}\n", .{result.alpn orelse "none"});
    std.debug.print("  http3_request: {s}\n", .{if (result.http3_request_success) "ok" else "fail"});
    if (result.http_status) |code| {
        std.debug.print("  http_status:   {d}\n", .{code});
    }
    if (result.alt_svc_h3) |found| {
        std.debug.print("  alt_svc_h3:    {s}\n", .{if (found) "yes" else "no"});
        if (result.alt_svc_value) |v| {
            std.debug.print("  alt_svc_value: {s}\n", .{v});
        }
    }
    if (result.fallback_reachable) |reachable| {
        std.debug.print("  fallback:      {s}\n", .{if (reachable) "ok" else "fail"});
        if (result.fallback_detected) |detected| {
            std.debug.print("  fallback_used: {s}\n", .{if (detected) "yes" else "no"});
        }
    }
    if (result.failure_stage) |stage| {
        std.debug.print("  failure_stage: {s}\n", .{probeStageName(stage)});
        std.debug.print("  verdict:       fail\n", .{});
    } else {
        std.debug.print("  verdict:       pass\n", .{});
    }
}

/// Render the probe result as JSON. Header values are attacker-influenced, so
/// every emitted string is escaped even when normal values are plain ASCII.
fn formatProbeJson(result: ProbeResult, buf: []u8) ![]const u8 {
    var w = std.Io.Writer.fixed(buf);
    try w.writeAll("{\n  \"target\": ");
    try writeJsonString(&w, result.target);
    try w.writeAll(",\n  \"dns_ok\": ");
    try w.writeAll(if (result.dns_ok) "true" else "false");
    try w.writeAll(",\n  \"resolved_ip\": ");
    if (result.resolved_ip) |ip| {
        try w.print("\"{d}.{d}.{d}.{d}\"", .{ ip[0], ip[1], ip[2], ip[3] });
    } else {
        try w.writeAll("null");
    }
    try w.writeAll(",\n  \"udp_reachable\": ");
    try w.writeAll(if (result.udp_reachable) "true" else "false");
    try w.writeAll(",\n  \"quic_handshake_success\": ");
    try w.writeAll(if (result.quic_handshake_success) "true" else "false");
    try w.writeAll(",\n  \"alpn\": ");
    if (result.alpn) |a| {
        try writeJsonString(&w, a);
    } else {
        try w.writeAll("null");
    }
    try w.writeAll(",\n  \"http3_request_success\": ");
    try w.writeAll(if (result.http3_request_success) "true" else "false");
    try w.writeAll(",\n  \"http_status\": ");
    if (result.http_status) |code| {
        try w.print("{d}", .{code});
    } else {
        try w.writeAll("null");
    }
    try w.writeAll(",\n  \"alt_svc_h3\": ");
    if (result.alt_svc_h3) |found| {
        try w.writeAll(if (found) "true" else "false");
    } else {
        try w.writeAll("null");
    }
    try w.writeAll(",\n  \"alt_svc_value\": ");
    if (result.alt_svc_value) |v| {
        try writeJsonString(&w, v);
    } else {
        try w.writeAll("null");
    }
    try w.writeAll(",\n  \"fallback_reachable\": ");
    if (result.fallback_reachable) |r| {
        try w.writeAll(if (r) "true" else "false");
    } else {
        try w.writeAll("null");
    }
    try w.writeAll(",\n  \"fallback_http_version\": ");
    if (result.fallback_http_version) |v| {
        try writeJsonString(&w, v);
    } else {
        try w.writeAll("null");
    }
    try w.writeAll(",\n  \"fallback_http_status\": ");
    if (result.fallback_http_status) |s| {
        try w.print("{d}", .{s});
    } else {
        try w.writeAll("null");
    }
    try w.writeAll(",\n  \"fallback_detected\": ");
    if (result.fallback_detected) |detected| {
        try w.writeAll(if (detected) "true" else "false");
    } else {
        try w.writeAll("null");
    }
    try w.writeAll(",\n  \"svcb_query_ok\": ");
    try w.writeAll(if (result.svcb_query_ok) "true" else "false");
    try w.writeAll(",\n  \"svcb_h3\": ");
    try w.writeAll(if (result.svcb_h3) "true" else "false");
    try w.writeAll(",\n  \"svcb_alpn\": ");
    if (result.svcb_alpn) |v| {
        try writeJsonString(&w, v);
    } else {
        try w.writeAll("null");
    }
    try w.writeAll(",\n  \"svcb_port\": ");
    if (result.svcb_port) |p| {
        try w.print("{d}", .{p});
    } else {
        try w.writeAll("null");
    }
    try w.writeAll(",\n  \"failure_stage\": ");
    if (result.failure_stage) |stage| {
        try w.print("\"{s}\"", .{probeStageName(stage)});
    } else {
        try w.writeAll("null");
    }
    try w.print(",\n  \"handshake_ms\": {d},\n  \"request_ms\": {d}\n}}\n", .{ result.handshake_ms, result.request_ms });
    return w.buffered();
}

fn renderProbeJson(result: ProbeResult) void {
    var buf: [2048]u8 = undefined;
    const json = formatProbeJson(result, &buf) catch return;
    std.debug.print("{s}", .{json});
}

/// Escape a Prometheus label value (`\`, `"`, newline). URL targets are
/// plain ASCII in practice, but exporters must not emit invalid exposition.
fn escapePromLabel(out: []u8, pos: *usize, value: []const u8) !void {
    for (value) |ch| {
        switch (ch) {
            '\\' => {
                if (pos.* + 2 > out.len) return error.NoSpaceLeft;
                out[pos.*] = '\\';
                out[pos.* + 1] = '\\';
                pos.* += 2;
            },
            '"' => {
                if (pos.* + 2 > out.len) return error.NoSpaceLeft;
                out[pos.*] = '\\';
                out[pos.* + 1] = '"';
                pos.* += 2;
            },
            '\n' => {
                if (pos.* + 2 > out.len) return error.NoSpaceLeft;
                out[pos.*] = '\\';
                out[pos.* + 1] = 'n';
                pos.* += 2;
            },
            else => {
                if (pos.* + 1 > out.len) return error.NoSpaceLeft;
                out[pos.*] = ch;
                pos.* += 1;
            },
        }
    }
}

/// Render the probe result in Prometheus text exposition format. Metric
/// names follow the `quicz.md` product plan (quic_*); a scrape of a failed
/// probe carries the failure stage as a label for alerting.
pub fn formatProbePrometheus(result: ProbeResult, buf: []u8) ![]const u8 {
    var pos: usize = 0;
    const put = struct {
        fn w(out: []u8, p: *usize, s: []const u8) !void {
            if (p.* + s.len > out.len) return error.NoSpaceLeft;
            @memcpy(out[p.*..][0..s.len], s);
            p.* += s.len;
        }
    }.w;

    var esc: [2048]u8 = undefined;
    var epos: usize = 0;
    try escapePromLabel(&esc, &epos, result.target);
    const tgt = esc[0..epos];

    try put(buf, &pos, "# HELP quic_probe_success Whether the HTTP/3/QUIC probe passed all checks.\n");
    try put(buf, &pos, "# TYPE quic_probe_success gauge\n");
    try put(buf, &pos, "quic_probe_success{target=\"");
    try put(buf, &pos, tgt);
    try put(buf, &pos, "\"} ");
    pos += (try std.fmt.bufPrint(buf[pos..], "{d}", .{@as(u8, if (result.isOk()) 1 else 0)})).len;
    try put(buf, &pos, "\n");

    try put(buf, &pos, "quic_udp_reachable{target=\"");
    try put(buf, &pos, tgt);
    try put(buf, &pos, "\"} ");
    pos += (try std.fmt.bufPrint(buf[pos..], "{d}", .{@as(u8, if (result.udp_reachable) 1 else 0)})).len;
    try put(buf, &pos, "\n");

    try put(buf, &pos, "quic_handshake_success{target=\"");
    try put(buf, &pos, tgt);
    try put(buf, &pos, "\"} ");
    pos += (try std.fmt.bufPrint(buf[pos..], "{d}", .{@as(u8, if (result.quic_handshake_success) 1 else 0)})).len;
    try put(buf, &pos, "\n");

    try put(buf, &pos, "quic_alpn_h3_success{target=\"");
    try put(buf, &pos, tgt);
    try put(buf, &pos, "\"} ");
    pos += (try std.fmt.bufPrint(buf[pos..], "{d}", .{@as(u8, if (std.mem.eql(u8, result.alpn orelse "", "h3")) 1 else 0)})).len;
    try put(buf, &pos, "\n");

    try put(buf, &pos, "quic_http3_request_success{target=\"");
    try put(buf, &pos, tgt);
    try put(buf, &pos, "\"} ");
    pos += (try std.fmt.bufPrint(buf[pos..], "{d}", .{@as(u8, if (result.http3_request_success) 1 else 0)})).len;
    try put(buf, &pos, "\n");

    if (result.failure_stage) |stage| {
        const stage_name = probeStageName(stage);
        var esc_stage_buf: [64]u8 = undefined;
        var s_pos: usize = 0;
        try escapePromLabel(&esc_stage_buf, &s_pos, stage_name);
        try put(buf, &pos, "quic_failure_stage{target=\"");
        try put(buf, &pos, tgt);
        try put(buf, &pos, "\",stage=\"");
        try put(buf, &pos, esc_stage_buf[0..s_pos]);
        try put(buf, &pos, "\"} 1\n");
    }

    pos += (try std.fmt.bufPrint(buf[pos..], "quic_handshake_duration_seconds{{target=\"{s}\"}} {d:.3}\n", .{ tgt, @as(f64, @floatFromInt(result.handshake_ms)) / 1000.0 })).len;
    pos += (try std.fmt.bufPrint(buf[pos..], "quic_request_duration_seconds{{target=\"{s}\"}} {d:.3}\n", .{ tgt, @as(f64, @floatFromInt(result.request_ms)) / 1000.0 })).len;

    if (result.alt_svc_h3) |found| {
        try put(buf, &pos, "quic_alt_svc_h3{target=\"");
        try put(buf, &pos, tgt);
        try put(buf, &pos, "\"} ");
        pos += (try std.fmt.bufPrint(buf[pos..], "{d}", .{@as(u8, if (found) 1 else 0)})).len;
        try put(buf, &pos, "\n");
    }

    if (result.fallback_reachable) |reachable| {
        try put(buf, &pos, "quic_fallback_reachable{target=\"");
        try put(buf, &pos, tgt);
        try put(buf, &pos, "\"} ");
        pos += (try std.fmt.bufPrint(buf[pos..], "{d}", .{@as(u8, if (reachable) 1 else 0)})).len;
        try put(buf, &pos, "\n");
    }

    if (result.fallback_detected) |detected| {
        try put(buf, &pos, "quic_fallback_detected{target=\"");
        try put(buf, &pos, tgt);
        try put(buf, &pos, "\"} ");
        pos += (try std.fmt.bufPrint(buf[pos..], "{d}", .{@as(u8, if (detected) 1 else 0)})).len;
        try put(buf, &pos, "\n");
    }

    if (result.svcb_query_ok) {
        try put(buf, &pos, "quic_svcb_h3{target=\"");
        try put(buf, &pos, tgt);
        try put(buf, &pos, "\"} ");
        pos += (try std.fmt.bufPrint(buf[pos..], "{d}", .{@as(u8, if (result.svcb_h3) 1 else 0)})).len;
        try put(buf, &pos, "\n");
    }

    return buf[0..pos];
}

fn renderProbePrometheus(result: ProbeResult) void {
    var buf: [4096]u8 = undefined;
    const out = formatProbePrometheus(result, &buf) catch return;
    std.debug.print("{s}", .{out});
}

/// Nagios/Icinga plugin output: one status line plus pipe-separated perfdata.
/// Nagios exit conventions are applied by the caller (0 OK, 2 CRITICAL,
/// 3 UNKNOWN); see `check_quic` in the quicz.md plan.
fn formatProbeNagios(result: ProbeResult, buf: []u8) ![]const u8 {
    var w = std.Io.Writer.fixed(buf);
    if (result.isOk()) {
        try w.print("QUIC-H3 OK - {s} handshake={d:.3}s request={d:.3}s", .{
            result.target,
            @as(f64, @floatFromInt(result.handshake_ms)) / 1000.0,
            @as(f64, @floatFromInt(result.request_ms)) / 1000.0,
        });
        if (result.alt_svc_h3) |found| {
            try w.print(" alt_svc_h3={s}", .{if (found) "yes" else "no"});
        }
        if (result.svcb_query_ok) {
            try w.print(" svcb_h3={s}", .{if (result.svcb_h3) "yes" else "no"});
        }
        if (result.fallback_reachable) |r| {
            try w.print(" fallback={s}", .{if (r) "ok" else "fail"});
        }
        try w.print(" | quic_probe_success=1 quic_handshake_duration_seconds={d:.3} quic_request_duration_seconds={d:.3}\n", .{
            @as(f64, @floatFromInt(result.handshake_ms)) / 1000.0,
            @as(f64, @floatFromInt(result.request_ms)) / 1000.0,
        });
    } else {
        const stage = if (result.failure_stage) |s_| probeStageName(s_) else "unknown";
        try w.print("QUIC-H3 CRITICAL - {s} failure_stage={s}", .{
            result.target, stage,
        });
        if (result.fallback_reachable) |reachable| {
            try w.print(" fallback={s}", .{if (reachable) "ok" else "fail"});
        }
        if (result.svcb_query_ok) {
            try w.print(" svcb_h3={s}", .{if (result.svcb_h3) "yes" else "no"});
        }
        if (result.fallback_detected) |detected| {
            try w.print(" fallback_detected={s}", .{if (detected) "yes" else "no"});
        }
        try w.writeAll(" | quic_probe_success=0");
        if (result.fallback_detected) |detected| {
            try w.print(" quic_fallback_detected={d}", .{@as(u8, if (detected) 1 else 0)});
        }
        try w.writeAll("\n");
    }
    return w.buffered();
}

fn renderProbeNagios(result: ProbeResult) void {
    var buf: [2048]u8 = undefined;
    const out = formatProbeNagios(result, &buf) catch return;
    std.debug.print("{s}", .{out});
}

const ProbeWork = struct {
    allocator: std.mem.Allocator,
    opts: ProbeOptions,
    result: ProbeResult = undefined,
};

pub fn emptyProbeResult(target: []const u8) ProbeResult {
    return .{
        .target = target,
        .dns_ok = false,
        .resolved_ip = null,
        .udp_reachable = false,
        .quic_handshake_success = false,
        .alpn = null,
        .http3_request_success = false,
        .http_status = null,
        .failure_stage = .invalid_url,
        .handshake_ms = 0,
        .request_ms = 0,
    };
}

/// Run one probe under its configured whole-probe timeout. This is the
/// reusable entry point for command wrappers such as the exporter.
pub fn runProbeOnce(allocator: std.mem.Allocator, io: std.Io, opts: ProbeOptions) !ProbeResult {
    var work = ProbeWork{
        .allocator = allocator,
        .opts = opts,
        .result = emptyProbeResult(opts.target),
    };
    runWithTimeout(io, opts.timeout_ms, probeWork, &work) catch |err| {
        if (err == error.Timeout) {
            work.result.failure_stage = .probe_timeout;
            return work.result;
        }
        return err;
    };
    return work.result;
}

fn probeWork(io: std.Io, ctx: *anyopaque) anyerror!void {
    const work: *ProbeWork = @ptrCast(@alignCast(ctx));
    work.result = try runProbe(work.allocator, io, work.opts);
}

/// Run the probe. Returns a fully-populated `ProbeResult` even on failure so
/// the caller can attribute the failure to a stage; only internal errors
/// (allocation, IO setup) propagate.
fn runProbe(allocator: std.mem.Allocator, io: std.Io, opts: ProbeOptions) !ProbeResult {
    var result = ProbeResult{
        .target = opts.target,
        .dns_ok = false,
        .resolved_ip = null,
        .udp_reachable = false,
        .quic_handshake_success = false,
        .alpn = null,
        .http3_request_success = false,
        .http_status = null,
        .alt_svc_h3 = null,
        .alt_svc_value = null,
        .fallback_reachable = null,
        .fallback_http_version = null,
        .fallback_http_status = null,
        .failure_stage = .invalid_url,
        .handshake_ms = 0,
        .request_ms = 0,
    };

    const parsed = parseH3Url(opts.target) catch |e| {
        if (common.g_verbose) std.debug.print("* probe parse URL error: {s}\n", .{@errorName(e)});
        return result;
    };
    const parsed_host = parsed.host;
    const parsed_port = parsed.port;

    const ip = resolveHostWithOverrides(io, parsed.host, parsed.port, opts.resolve) catch {
        result.failure_stage = .dns_resolve_failed;
        return result;
    };
    result.dns_ok = true;
    result.resolved_ip = ip;

    const svcb_info = svcb.queryHttpsSvc(allocator, io, parsed_host);
    defer svcb_info.deinit(allocator);
    result.svcb_query_ok = svcb_info.query_ok;
    result.svcb_h3 = svcb_info.h3;
    result.svcb_priority = svcb_info.priority;
    result.svcb_target = if (svcb_info.target) |target| allocator.dupe(u8, target) catch null else null;
    result.svcb_alpn = if (svcb_info.alpn) |alpn| allocator.dupe(u8, alpn) catch null else null;
    result.svcb_port = svcb_info.port;

    var maybe_bundle: ?std.crypto.Certificate.Bundle = null;
    if (opts.ca_path) |pem| {
        if (!std.Io.Dir.path.isAbsolute(pem)) return error.CaPathMustBeAbsolute;
        var bundle: std.crypto.Certificate.Bundle = .empty;
        const now = std.Io.Clock.real.now(io);
        try bundle.addCertsFromFilePathAbsolute(allocator, io, now, pem);
        maybe_bundle = bundle;
    } else if (!opts.insecure) {
        maybe_bundle = loadSystemCaBundle(allocator, io) catch null;
    }
    defer {
        if (maybe_bundle) |*b| b.deinit(allocator);
    }
    const fallback_ca_bundle: ?*std.crypto.Certificate.Bundle = if (maybe_bundle) |*b| b else null;

    var client: ?Client = null;
    var h3cli: ?RuntimeH3Client = null;
    defer if (client) |*c| c.deinit();
    defer if (h3cli) |*h| h.deinit();

    const c0 = std.Io.Timestamp.now(io, .awake);
    const connected: bool = blk: {
        client = Client.init(allocator, io, .{
            .server_host = ip,
            .server_port = parsed.port,
            .server_name = parsed.host,
            .alpn = &alpn_h3,
            .insecure_skip_verify = opts.insecure or maybe_bundle == null,
            .ca_bundle = if (maybe_bundle) |*b| b else null,
        }) catch |e| {
            result.failure_stage = stageForConnectError(e);
            break :blk false;
        };
        const connect_result: anyerror!void = if (opts.connect_timeout_ms) |ms|
            connectWithTimeout(io, ms, &client.?)
        else
            client.?.connect();
        connect_result catch |e| {
            if (common.g_verbose) std.debug.print("* probe connect error: {s}\n", .{@errorName(e)});
            // Zero datagrams received means the UDP path is dead (blackholed,
            // firewalled, or ICMP-refused); anything else means UDP works and
            // the failure is in QUIC or TLS.
            if (client.?.datagramsReceived() == 0) {
                result.failure_stage = .udp_timeout;
            } else {
                result.failure_stage = stageForConnectError(e);
            }
            break :blk false;
        };
        break :blk true;
    };
    const c1 = std.Io.Timestamp.now(io, .awake);
    result.handshake_ms = @intCast(std.Io.Duration.toMilliseconds(c0.durationTo(c1)));
    if (!connected) {
        result.udp_reachable = switch (result.failure_stage.?) {
            .udp_timeout => false,
            else => true,
        };
        return completeProbe(allocator, io, &result, opts, ip, parsed_host, parsed_port, parsed.path, fallback_ca_bundle);
    }
    result.udp_reachable = true;
    result.quic_handshake_success = true;
    result.alpn = "h3";

    h3cli = RuntimeH3Client.init(allocator, &client.?, 4096, 8);
    h3cli.?.run() catch {
        result.failure_stage = .http3_request_failed;
        return completeProbe(allocator, io, &result, opts, ip, parsed_host, parsed_port, parsed.path, fallback_ca_bundle);
    };
    h3cli.?.h3.max_response_body_size = max_cli_response_body_size;

    const request = quicz.h3_request.Request{
        .method = "GET",
        .path = parsed.path,
        .scheme = "https",
        .authority = parsed.host,
        .extra_headers = &.{.{ .name = "user-agent", .value = opts.user_agent }},
        .body = null,
    };
    const t0 = std.Io.Timestamp.now(io, .awake);
    const sid = h3cli.?.sendRequest(request) catch {
        result.failure_stage = .http3_request_failed;
        return completeProbe(allocator, io, &result, opts, ip, parsed_host, parsed_port, parsed.path, fallback_ca_bundle);
    };
    const response = h3cli.?.receiveResponse(sid) catch {
        result.failure_stage = .http3_request_failed;
        return completeProbe(allocator, io, &result, opts, ip, parsed_host, parsed_port, parsed.path, fallback_ca_bundle);
    };
    const t1 = std.Io.Timestamp.now(io, .awake);
    result.request_ms = @intCast(std.Io.Duration.toMilliseconds(t0.durationTo(t1)));
    result.http3_request_success = true;
    result.http_status = response.status;
    result.failure_stage = null;

    return completeProbe(allocator, io, &result, opts, ip, parsed_host, parsed_port, parsed.path, fallback_ca_bundle);
}

fn cmdProbe(allocator: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !void {
    const raw = try nextArg(args);
    var target_buf: [4096]u8 = undefined;
    const target = normalizeProbeTarget(raw, &target_buf) orelse {
        std.debug.print("probe: unsupported URL '{s}' (only https:// is supported)\n", .{raw});
        std.process.exit(2);
    };
    var opts = ProbeOptions{ .target = target };
    var output: enum { text, json, prometheus, nagios } = .text;
    var resolves = std.ArrayList(ResolveOverride).empty;
    defer resolves.deinit(allocator);
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--json")) {
            output = .json;
        } else if (std.mem.eql(u8, a, "--prometheus")) {
            output = .prometheus;
        } else if (std.mem.eql(u8, a, "--nagios")) {
            output = .nagios;
        } else if (std.mem.eql(u8, a, "-v") or std.mem.eql(u8, a, "--verbose")) {
            common.g_verbose = true;
        } else if (std.mem.eql(u8, a, "-k") or std.mem.eql(u8, a, "--insecure")) {
            opts.insecure = true;
        } else if (std.mem.eql(u8, a, "--ca")) {
            opts.ca_path = try nextArg(args);
        } else if (std.mem.eql(u8, a, "--resolve")) {
            const override = try parseResolveSpec(try nextArg(args));
            try resolves.append(allocator, override);
        } else if (std.mem.eql(u8, a, "--connect-timeout")) {
            const secs = try std.fmt.parseInt(u64, try nextArg(args), 10);
            opts.connect_timeout_ms = try std.math.mul(u64, secs, 1000);
        } else if (std.mem.eql(u8, a, "--max-time")) {
            const secs = try std.fmt.parseInt(u64, try nextArg(args), 10);
            opts.timeout_ms = try std.math.mul(u64, secs, 1000);
        } else if (std.mem.eql(u8, a, "-A") or std.mem.eql(u8, a, "--user-agent")) {
            opts.user_agent = try nextArg(args);
        } else if (std.mem.eql(u8, a, "--no-alt-svc")) {
            opts.check_alt_svc = false;
        } else {
            std.debug.print("probe: unknown option: {s}\n", .{a});
            return error.UnknownOption;
        }
    }
    opts.resolve = resolves.items;

    var work = ProbeWork{ .allocator = allocator, .opts = opts };
    try runWithTimeout(io, opts.timeout_ms, probeWork, &work);
    switch (output) {
        .json => renderProbeJson(work.result),
        .prometheus => renderProbePrometheus(work.result),
        .nagios => renderProbeNagios(work.result),
        .text => renderProbeText(work.result),
    }
    deinitProbeResult(allocator, &work.result);
    if (output == .nagios) {
        // Nagios plugin exit codes: 0 OK, 2 CRITICAL, 3 UNKNOWN.
        if (!work.result.isOk()) std.process.exit(2);
        return;
    }
    if (!work.result.isOk()) std.process.exit(1);
}

/// Perform a best-effort Alt-Svc check via TCP+TLS.  This is supplementary —
/// failures here do not affect the probe pass/fail verdict.
fn checkAltSvc(
    allocator: std.mem.Allocator,
    io: std.Io,
    result: *ProbeResult,
    opts: ProbeOptions,
    ip: [4]u8,
    parsed_host: []const u8,
    parsed_port: u16,
    parsed_path: []const u8,
    ca_bundle: ?*std.crypto.Certificate.Bundle,
) !void {
    result.alt_svc_h3 = false;
    result.alt_svc_value = null;

    // TCP connect to the resolved IP.
    const addr = std.Io.net.IpAddress{ .ip4 = .{ .bytes = ip, .port = parsed_port } };
    const tcp = addr.connect(io, .{ .mode = .stream }) catch {
        if (common.g_verbose) std.debug.print("* alt-svc: TCP connect failed\n", .{});
        return;
    };
    defer tcp.close(io);

    if (common.g_verbose) std.debug.print("* alt-svc: TCP connected to {d}.{d}.{d}.{d}:{d}\n", .{ ip[0], ip[1], ip[2], ip[3], parsed_port });

    const tls_buffer_len = std.crypto.tls.Client.min_buffer_len;
    var socket_recv_buf: [tls_buffer_len]u8 = undefined;
    var socket_send_buf: [tls_buffer_len]u8 = undefined;
    var tls_recv_buf: [tls_buffer_len]u8 = undefined;
    var tls_send_buf: [tls_buffer_len]u8 = undefined;
    var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
    var ca_lock: std.Io.RwLock = .init;
    io.random(&entropy);
    var reader = tcp.reader(io, &socket_recv_buf);
    var writer = tcp.writer(io, &socket_send_buf);

    const verify_certificate = !opts.insecure and ca_bundle != null;
    var tls = std.crypto.tls.Client.init(&reader.interface, &writer.interface, .{
        .host = if (verify_certificate)
            .{ .explicit = parsed_host }
        else
            .{ .no_verification = {} },
        .ca = if (verify_certificate)
            .{ .bundle = .{
                .gpa = allocator,
                .io = io,
                .lock = &ca_lock,
                .bundle = ca_bundle.?,
            } }
        else
            .{ .no_verification = {} },
        .write_buffer = &tls_send_buf,
        .read_buffer = &tls_recv_buf,
        .entropy = &entropy,
        .realtime_now = std.Io.Clock.real.now(io),
        .allow_truncation_attacks = true,
    }) catch |err| {
        if (common.g_verbose) std.debug.print("* alt-svc: TLS handshake failed: {s}\n", .{@errorName(err)});
        return;
    };
    defer {
        tls.end() catch {};
        writer.interface.flush() catch {};
    }

    // HTTP/1.1 GET request.
    var req_buf: [4096]u8 = undefined;
    const req = try std.fmt.bufPrint(&req_buf, "GET {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: {s}\r\nConnection: close\r\n\r\n", .{ parsed_path, parsed_host, opts.user_agent });
    tls.writer.writeAll(req) catch {
        if (common.g_verbose) std.debug.print("* alt-svc: HTTP request write failed\n", .{});
        return;
    };
    tls.writer.flush() catch {
        if (common.g_verbose) std.debug.print("* alt-svc: HTTP request flush failed\n", .{});
        return;
    };
    writer.interface.flush() catch {
        if (common.g_verbose) std.debug.print("* alt-svc: TCP request flush failed\n", .{});
        return;
    };

    // Read response headers.
    var resp_buf: [65536]u8 = undefined;
    var resp_len: usize = 0;
    var header_end: ?usize = null;
    while (header_end == null) {
        if (resp_len >= resp_buf.len) break;
        const n = tls.reader.readSliceShort(resp_buf[resp_len..]) catch |err| {
            if (common.g_verbose) std.debug.print("* alt-svc: HTTP response read failed: {s}\n", .{@errorName(err)});
            break;
        };
        if (n == 0) break;
        resp_len += n;
        header_end = std.mem.indexOf(u8, resp_buf[0..resp_len], "\r\n\r\n");
    }
    const headers = if (header_end) |end| resp_buf[0..end] else blk: {
        if (resp_len > 0) break :blk resp_buf[0..resp_len];
        return;
    };

    // Fallback is reachable (TCP+TLS+HTTP succeeded).
    result.fallback_reachable = true;

    // Parse HTTP status line for version and status code.
    if (std.mem.indexOfScalar(u8, headers, '\n')) |_| {
        var line_it = std.mem.splitScalar(u8, headers, '\n');
        if (line_it.next()) |status_line_raw| {
            const status_line = std.mem.trim(u8, status_line_raw, "\r");
            // The ClientHello offers only http/1.1, so the static token is
            // sufficient and avoids owning a short-lived heap copy.
            result.fallback_http_version = "HTTP/1.1";
            if (std.mem.indexOfScalar(u8, status_line, ' ')) |sp1| {
                const rest = std.mem.trim(u8, status_line[sp1..], " ");
                if (std.mem.indexOfScalar(u8, rest, ' ')) |sp2| {
                    result.fallback_http_status = try std.fmt.parseInt(u16, rest[0..sp2], 10);
                } else {
                    result.fallback_http_status = try std.fmt.parseInt(u16, rest, 10);
                }
            }
        }
    }

    // Parse Alt-Svc header.
    var it = std.mem.splitScalar(u8, headers, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, "\r");
        if (std.ascii.startsWithIgnoreCase(line, "alt-svc:")) {
            const value = std.mem.trim(u8, line["alt-svc:".len..], " \t");
            result.alt_svc_value = if (result.alt_svc_value) |previous| merged: {
                const merged = try std.fmt.allocPrint(allocator, "{s}, {s}", .{ previous, value });
                allocator.free(previous);
                break :merged merged;
            } else try allocator.dupe(u8, value);
            result.alt_svc_h3 = altSvcOffersH3(value) or result.alt_svc_h3.?;
        }
    }
}

test "probe nagios rendering" {
    var buf: [2048]u8 = undefined;
    const ok = try formatProbeNagios(.{
        .target = "https://example.com",
        .dns_ok = true,
        .resolved_ip = .{ 127, 0, 0, 1 },
        .udp_reachable = true,
        .quic_handshake_success = true,
        .alpn = "h3",
        .http3_request_success = true,
        .http_status = 200,
        .failure_stage = null,
        .handshake_ms = 107,
        .request_ms = 15,
    }, &buf);
    try std.testing.expect(std.mem.indexOf(u8, ok, "QUIC-H3 OK - https://example.com handshake=0.107s request=0.015s") != null);
    try std.testing.expect(std.mem.indexOf(u8, ok, "quic_probe_success=1") != null);

    const fail = try formatProbeNagios(.{
        .target = "https://192.0.2.1",
        .dns_ok = true,
        .resolved_ip = .{ 192, 0, 2, 1 },
        .udp_reachable = false,
        .quic_handshake_success = false,
        .alpn = null,
        .http3_request_success = false,
        .http_status = null,
        .failure_stage = .udp_timeout,
        .handshake_ms = 2052,
        .request_ms = 0,
    }, &buf);
    try std.testing.expect(std.mem.indexOf(u8, fail, "QUIC-H3 CRITICAL - https://192.0.2.1 failure_stage=udp_timeout") != null);
    try std.testing.expect(std.mem.indexOf(u8, fail, "quic_probe_success=0") != null);

    const fallback = try formatProbeNagios(.{
        .target = "https://example.com",
        .dns_ok = true,
        .resolved_ip = .{ 127, 0, 0, 1 },
        .udp_reachable = true,
        .quic_handshake_success = false,
        .alpn = null,
        .http3_request_success = false,
        .http_status = null,
        .fallback_reachable = true,
        .fallback_http_version = "HTTP/1.1",
        .fallback_http_status = 200,
        .fallback_detected = true,
        .failure_stage = .quic_handshake_failed,
        .handshake_ms = 20,
        .request_ms = 0,
    }, &buf);
    try std.testing.expect(std.mem.indexOf(u8, fallback, "fallback=ok fallback_detected=yes") != null);
    try std.testing.expect(std.mem.indexOf(u8, fallback, "quic_fallback_detected=1") != null);
}

test "probe prometheus rendering" {
    var buf: [4096]u8 = undefined;
    const out = try formatProbePrometheus(.{
        .target = "https://example.com/x",
        .dns_ok = true,
        .resolved_ip = .{ 127, 0, 0, 1 },
        .udp_reachable = false,
        .quic_handshake_success = false,
        .alpn = null,
        .http3_request_success = false,
        .http_status = null,
        .alt_svc_h3 = true,
        .fallback_reachable = true,
        .fallback_detected = false,
        .svcb_query_ok = true,
        .svcb_h3 = true,
        .svcb_alpn = "h3",
        .svcb_port = 443,
        .failure_stage = .udp_timeout,
        .handshake_ms = 2004,
        .request_ms = 0,
    }, &buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "quic_probe_success{target=\"https://example.com/x\"} 0") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "quic_udp_reachable{target=\"https://example.com/x\"} 0") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "quic_failure_stage{target=\"https://example.com/x\",stage=\"udp_timeout\"} 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "quic_handshake_duration_seconds{target=\"https://example.com/x\"} 2.004") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "quic_request_duration_seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "quic_alt_svc_h3{target=\"https://example.com/x\"} 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "quic_fallback_reachable{target=\"https://example.com/x\"} 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "quic_fallback_detected{target=\"https://example.com/x\"} 0") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "quic_svcb_h3{target=\"https://example.com/x\"} 1") != null);
}

test "probe target normalization" {
    var buf: [4096]u8 = undefined;
    try std.testing.expectEqualStrings("https://example.com", normalizeProbeTarget("https://example.com", &buf).?);
    try std.testing.expectEqualStrings("https://example.com", normalizeProbeTarget("example.com", &buf).?);
    try std.testing.expectEqualStrings("https://host:8443/x", normalizeProbeTarget("host:8443/x", &buf).?);
    try std.testing.expect(normalizeProbeTarget("http://example.com", &buf) == null);
    try std.testing.expect(normalizeProbeTarget("ftp://example.com", &buf) == null);
    try std.testing.expect(normalizeProbeTarget("ws://example.com", &buf) == null);
}

test "probe stage names" {
    try std.testing.expectEqualSlices(u8, "udp_timeout", probeStageName(.udp_timeout));
    try std.testing.expectEqualSlices(u8, "tls_cert_failed", probeStageName(.tls_cert_failed));
    try std.testing.expectEqualSlices(u8, "http3_request_failed", probeStageName(.http3_request_failed));
}

test "probe connect error stage mapping" {
    try std.testing.expectEqual(ProbeStage.udp_timeout, stageForConnectError(error.Timeout));
    try std.testing.expectEqual(ProbeStage.udp_timeout, stageForConnectError(error.Canceled));
    try std.testing.expectEqual(ProbeStage.udp_timeout, stageForConnectError(error.NetworkUnreachable));
    try std.testing.expectEqual(ProbeStage.udp_timeout, stageForConnectError(error.ConnectionRefused));
    try std.testing.expectEqual(ProbeStage.tls_cert_failed, stageForConnectError(error.CryptoError));
    try std.testing.expectEqual(ProbeStage.quic_handshake_failed, stageForConnectError(error.HandshakeFailed));
    try std.testing.expectEqual(ProbeStage.quic_handshake_failed, stageForConnectError(error.InvalidPacket));
}

test "probe json rendering" {
    var buf: [2048]u8 = undefined;
    const json = try formatProbeJson(.{
        .target = "https://example.com/path",
        .dns_ok = true,
        .resolved_ip = .{ 127, 0, 0, 1 },
        .udp_reachable = true,
        .quic_handshake_success = true,
        .alpn = "h3",
        .http3_request_success = true,
        .http_status = 200,
        .failure_stage = null,
        .handshake_ms = 12,
        .request_ms = 34,
    }, &buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"target\": \"https://example.com/path\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"resolved_ip\": \"127.0.0.1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failure_stage\": null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"http_status\": 200") != null);
}

test "probe json escapes alt-svc and renders fallback" {
    var buf: [2048]u8 = undefined;
    const json = try formatProbeJson(.{
        .target = "https://example.com/path",
        .dns_ok = true,
        .resolved_ip = .{ 127, 0, 0, 1 },
        .udp_reachable = false,
        .quic_handshake_success = false,
        .alpn = null,
        .http3_request_success = false,
        .http_status = null,
        .alt_svc_h3 = true,
        .alt_svc_value = "h3=\":443\"; ma=86400",
        .fallback_reachable = true,
        .fallback_http_version = "HTTP/1.1",
        .fallback_http_status = 200,
        .fallback_detected = true,
        .failure_stage = .quic_handshake_failed,
        .handshake_ms = 20,
        .request_ms = 0,
    }, &buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"alt_svc_value\": \"h3=") != null);
    const escaped_quote = std.mem.indexOf(u8, json, "h3=").? + 3;
    try std.testing.expectEqual(@as(u8, '\\'), json[escaped_quote]);
    try std.testing.expectEqual(@as(u8, '"'), json[escaped_quote + 1]);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"fallback_reachable\": true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"fallback_detected\": true") != null);
}

test "probe alt-svc protocol parsing" {
    try std.testing.expect(altSvcOffersH3("h3=\":443\"; ma=86400"));
    try std.testing.expect(altSvcOffersH3("h2=\":443\", h3-29=\":443\""));
    try std.testing.expect(!altSvcOffersH3("h2=\":443\", h3x=\":443\""));
}

test "probe invalid url stage" {
    var buf: [2048]u8 = undefined;
    const json = try formatProbeJson(.{
        .target = "not-a-url",
        .dns_ok = false,
        .resolved_ip = null,
        .udp_reachable = false,
        .quic_handshake_success = false,
        .alpn = null,
        .http3_request_success = false,
        .http_status = null,
        .alt_svc_h3 = null,
        .alt_svc_value = null,
        .fallback_reachable = null,
        .fallback_http_version = null,
        .fallback_http_status = null,
        .failure_stage = .invalid_url,
        .handshake_ms = 0,
        .request_ms = 0,
    }, &buf);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failure_stage\": \"invalid_url\"") != null);
}
