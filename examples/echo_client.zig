const std = @import("std");
const quicz = @import("quicz");

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    var stdout = std.io.getStdOut().writer();

    const addr = try std.net.Address.parseIp4("127.0.0.1", 4443);

    var sock = try std.net.DatagramSocket.createIpv4();
    defer sock.deinit();

    try sock.connect(addr);

    var conn = try quicz.QuicConnection.init(gpa, .client, .{});
    defer conn.deinit();

    const now = std.time.milliTimestamp();

    var out_buf: [2048]u8 = undefined;
    if (try conn.pollTx(now, &out_buf)) |tx| {
        _ = try sock.send(tx);
    }

    const stream_id = try conn.openStream();
    try stdout.print("Opened stream {d}\n", .{stream_id});

    const msg = "hello from quicz client";
    try conn.sendOnStream(stream_id, msg[0..], true);

    if (try conn.pollTx(std.time.milliTimestamp(), &out_buf)) |tx2| {
        _ = try sock.send(tx2);
    }

    var recv_buf: [2048]u8 = undefined;
    const n = try sock.receive(&recv_buf);
    try conn.processDatagram(std.time.milliTimestamp(), recv_buf[0..n]);

    var app_buf: [1024]u8 = undefined;
    if (try conn.recvOnStream(stream_id, &app_buf)) |len| {
        try stdout.print("Got echo: {s}\n", .{app_buf[0..len]});
    } else {
        try stdout.print("No app data yet\n", .{});
    }
}
