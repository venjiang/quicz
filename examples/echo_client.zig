const std = @import("std");
const quicz = @import("quicz");

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    var conn = try quicz.Connection.init(gpa, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "hello from quicz client", true);

    var datagram: [128]u8 = undefined;
    if (try conn.pollTx(0, &datagram)) |payload| {
        std.debug.print("[client] stream={} queued {} payload bytes\n", .{ stream_id, payload.len });
    }
}
