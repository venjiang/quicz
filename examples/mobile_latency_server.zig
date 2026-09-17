//! QUIC echo server for iOS feasibility and latency measurements.

const std = @import("std");
const quicz = @import("quicz");
const test_certs = @import("test_certs.zig");

const Server = quicz.runtime.server.Server;
const ServerConnection = quicz.runtime.server.ServerConnection;
const PunchAttempt = quicz.connectivity.punch_attempt.PunchAttempt;
const punch_driver = quicz.connectivity.punch_driver;
const alpn = [_][]const u8{"quicz-mobile-latency-v1"};
const benchmark_key: quicz.connectivity.punch_wire.Key = .{0x42} ** 32;
const benchmark_attempt_id: quicz.connectivity.punch_wire.AttemptId = .{0x11} ** 16;
const benchmark_host_nonce: quicz.connectivity.punch_wire.Nonce = .{0xb2} ** 16;

fn acceptAuthenticatedPunch(io: std.Io, socket: std.Io.net.Socket) !void {
    var attempt = try PunchAttempt.init(
        benchmark_key,
        benchmark_attempt_id,
        benchmark_host_nonce,
        .{},
    );
    const deadline = std.Io.Clock.Timestamp{
        .clock = .awake,
        .raw = std.Io.Timestamp.now(io, .awake).addDuration(std.Io.Duration.fromSeconds(300)),
    };
    var receive_buffer: [256]u8 = undefined;
    while (true) {
        const received = try socket.receiveTimeout(io, &receive_buffer, .{ .deadline = deadline });
        const result = attempt.receive(received.data) catch continue;
        const acknowledgement = result.acknowledgement orelse continue;
        var remote = received.from;
        try socket.send(io, &remote, &acknowledgement);
        try punch_driver.run(io, socket, remote, &attempt);
        return;
    }
}

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
    if (args.len > 3) return error.InvalidArguments;
    const port = if (args.len >= 2)
        std.fmt.parseInt(u16, args[1], 10) catch return error.InvalidArguments
    else
        4433;
    const accept_punch = if (args.len == 3)
        std.mem.eql(u8, args[2], "passive-punch")
    else
        false;
    if (args.len == 3 and !accept_punch) return error.InvalidArguments;

    var threaded = std.Io.Threaded.init(init.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var bind_address = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } };
    const socket = try bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    var socket_transferred = false;
    defer if (!socket_transferred) socket.close(io);

    if (accept_punch) try acceptAuthenticatedPunch(io, socket);

    var server = try Server.initWithSocket(init.gpa, io, socket, .{
        .port = port,
        .alpn = &alpn,
        .cert_der = &test_certs.cert_der,
        .private_key = &test_certs.private_key,
        .max_connections = 8,
    });
    socket_transferred = true;
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
