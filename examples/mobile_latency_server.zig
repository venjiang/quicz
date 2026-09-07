//! QUIC echo server for iOS feasibility and latency measurements.

const std = @import("std");
const quicz = @import("quicz");
const test_certs = @import("test_certs.zig");

const Server = quicz.runtime.server.Server;
const ServerConnection = quicz.runtime.server.ServerConnection;
const alpn = [_][]const u8{"quicz-mobile-latency-v1"};

fn echoHandler(connection: ServerConnection) std.Io.Cancelable!void {
    var mutable_connection = connection;
    while (true) {
        var stream = mutable_connection.acceptStream() catch return;
        var buffer: [4096]u8 = undefined;
        while (true) {
            const received = stream.receive(&buffer) catch return;
            if (received == 0) {
                stream.send(&.{}, true) catch {};
                break;
            }
            stream.send(buffer[0..received], false) catch return;
        }
    }
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len > 2) return error.InvalidArguments;
    const port = if (args.len == 2)
        std.fmt.parseInt(u16, args[1], 10) catch return error.InvalidArguments
    else
        4433;

    var threaded = std.Io.Threaded.init(init.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.init(init.gpa, io, .{
        .port = port,
        .alpn = &alpn,
        .cert_der = &test_certs.cert_der,
        .private_key = &test_certs.private_key,
        .bind_addr = .{ 0, 0, 0, 0 },
        .max_connections = 8,
    });
    defer server.deinit();
    try server.serve(&echoHandler);

    var stdout_buffer: [256]u8 = undefined;
    var stdout = std.Io.File.Writer.init(.stdout(), io, &stdout_buffer);
    try stdout.interface.print(
        "quicz mobile latency server: udp=0.0.0.0:{d} alpn=quicz-mobile-latency-v1\n",
        .{port},
    );
    try stdout.interface.flush();
    server.drive_group.await(io) catch {};
}
