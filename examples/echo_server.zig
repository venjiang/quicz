const std = @import("std");
const quicz = @import("quicz");

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    var stdout = std.io.getStdOut().writer();

    try stdout.print("quicz echo server listening on 0.0.0.0:4443\n", .{});

    var sock = try std.net.DatagramSocket.createIpv4();
    defer sock.deinit();

    try sock.bind(.{
        .address = try std.net.Address.parseIp4("0.0.0.0", 4443),
    });

    var conn = try quicz.QuicConnection.init(gpa, .server, .{});
    defer conn.deinit();

    var buf: [2048]u8 = undefined;

    while (true) {
        var src_addr: std.net.Address = undefined;
        const n = try sock.receiveFrom(&src_addr, &buf);
        const now = std.time.milliTimestamp();

        try conn.processDatagram(now, buf[0..n]);

        while (true) {
            var out_buf: [2048]u8 = undefined;
            const maybe_tx = try conn.pollTx(now, &out_buf);
            if (maybe_tx) |tx| {
                _ = try sock.sendTo(tx, src_addr);
            } else break;
        }

        var app_buf: [1024]u8 = undefined;
        if (try conn.recvOnStream(0, &app_buf)) |len| {
            try conn.sendOnStream(0, app_buf[0..len], false);
        }
    }
}
