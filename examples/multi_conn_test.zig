//! quicz I/O runtime — multi-connection test (std.http model).
//!
//! Follows std.http.Server's design: an accept loop spawns an independent
//! handler task per connection; each handler processes its connection without
//! blocking the accept loop or other connections.
const std = @import("std");
const test_certs = @import("test_certs.zig");
const quicz = @import("quicz");
const Server = quicz.runtime.server.Server;
const ServerConnection = quicz.runtime.server.ServerConnection;
const Client = quicz.runtime.client.Client;
const port: u16 = 4455;
const num_conns: usize = 3;
const streams_per_conn: usize = 2;
const stream_payload_len: usize = 512 * 1024;

const alpn = [_][]const u8{"hq-interop"};

/// Per-connection handler (std.http model): handles one connection's echo,
/// runs as its own task so it never blocks the accept loop or other conns.
fn handleConnection(conn: ServerConnection) std.Io.Cancelable!void {
    // std.http per-connection handler: read request data, write response.
    var c = conn;
    std.debug.print("[handler {d}] waiting for {d} streams...\n", .{ c.id, streams_per_conn });
    var si: usize = 0;
    while (si < streams_per_conn) : (si += 1) {
        var stream = c.acceptStream() catch |e| {
            std.debug.print("[handler {d}] acceptStream err {}\n", .{ c.id, e });
            return;
        };
        var buf: [65536]u8 = undefined;
        var total: usize = 0;
        while (true) {
            const n = stream.receive(&buf) catch break;
            if (n == 0) break; // EOF: peer FIN received and drained.
            stream.send(buf[0..n], false) catch break;
            total += n;
        }
        stream.send(&.{}, true) catch {}; // FIN the echoed stream.
        std.debug.print("[handler {d}] stream {d} echoed {d} bytes\n", .{ c.id, stream.id, total });
    }
}

/// Abrupt-close session: open a stream, send partial data WITHOUT a FIN,
/// then close the connection. The server handler must wake up with
/// error.ConnectionClosed instead of blocking on the stream forever.
fn abruptSession(allocator: std.mem.Allocator, io: std.Io) std.Io.Cancelable!void {
    runAbruptSession(allocator, io) catch |e| {
        std.debug.print("[client abrupt] session FAILED: {}\n", .{e});
    };
}

fn runAbruptSession(allocator: std.mem.Allocator, io: std.Io) !void {
    var client = try Client.init(allocator, io, .{ .server_port = port, .server_name = "localhost", .alpn = &alpn });
    defer client.deinit();
    try client.connect();
    var payload: [1024]u8 = undefined;
    @memset(&payload, 'Y');
    _ = try client.send(&payload, false);
    client.close();
    try client.waitClosed(10_000);
    std.debug.print("[client abrupt] closed connection without FIN\n", .{});
}

/// Concurrent-task wrapper: run one echo session, record failure in
/// `failed` (transport errors do not fit the Cancelable error set).
fn clientSession(allocator: std.mem.Allocator, io: std.Io, ci: usize, failed: *bool) std.Io.Cancelable!void {
    runClientSession(allocator, io, ci) catch |e| {
        std.debug.print("[client {d}] session FAILED: {}\n", .{ ci, e });
        @atomicStore(bool, failed, true, .release);
    };
}

/// One full client echo session; all sessions run concurrently.
fn runClientSession(allocator: std.mem.Allocator, io: std.Io, ci: usize) !void {
    std.debug.print("[client {d}] init+connect...\n", .{ci});
    var client = try Client.init(allocator, io, .{ .server_port = port, .server_name = "localhost", .alpn = &alpn });
    defer client.deinit();
    try client.connect();
    std.debug.print("[client {d}] connected\n", .{ci});
    const payload = try allocator.alloc(u8, stream_payload_len);
    defer allocator.free(payload);
    @memset(payload, 'X');
    var stream_ids: [streams_per_conn]u64 = undefined;
    for (0..streams_per_conn) |si| {
        stream_ids[si] = try client.send(payload, true);
    }
    var recv_buf: [65536]u8 = undefined;
    for (stream_ids) |sid| {
        var total: usize = 0;
        var got_eof = false;
        while (!got_eof) {
            const n = try client.receive(sid, &recv_buf);
            if (n == 0) {
                got_eof = true;
            } else {
                total += n;
            }
        }
        std.debug.print("[client {d}] stream {d} received {d}/{d} bytes eof={}\n", .{ ci, sid, total, payload.len, got_eof });
        if (total != payload.len) return error.EchoMismatch;
    }
    client.close();
    try client.waitClosed(10_000);
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.init(allocator, io, .{ .port = port, .alpn = &alpn, .cert_der = &test_certs.cert_der, .private_key = &test_certs.private_key });
    defer server.deinit();
    try server.serve(&handleConnection);
    std.debug.print("server on 127.0.0.1:{d} (std.http per-connection handler model)\n", .{port});
    var session_failed: bool = false;
    var client_group: std.Io.Group = .init;
    for (0..num_conns) |ci| {
        try client_group.concurrent(io, clientSession, .{ allocator, io, ci, &session_failed });
    }
    try client_group.concurrent(io, abruptSession, .{ allocator, io });
    try client_group.await(io);
    if (@atomicLoad(bool, &session_failed, .acquire)) return error.EchoMismatch;
    // Give the drive task a few loops to observe the closes and reclaim
    // connection state, then assert nothing leaked.
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(300), .awake) catch {};
    while (!server.mutex.tryLock()) std.atomic.spinLoopHint();
    const live = server.conns.count();
    server.mutex.unlock();
    std.debug.print("[server] live connections after reap window: {d}\n", .{live});
    if (live != 0) return error.ConnectionLeak;
    std.debug.print("multi-connection test done\n", .{});
    server.stop();
}
