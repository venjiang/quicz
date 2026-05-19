const std = @import("std");
const quicz = @import("quicz");

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    var client = try quicz.QuicConnection.init(gpa, .client, .{});
    defer client.deinit();
    var server = try quicz.QuicConnection.init(gpa, .server, .{});
    defer server.deinit();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello from quicz client", true);

    var datagram: [128]u8 = undefined;
    try server.processDatagram(0, (try client.pollTx(0, &datagram)).?);

    var recv_buf: [128]u8 = undefined;
    const recv_len = (try server.recvOnStream(stream_id, &recv_buf)).?;
    const received = recv_buf[0..recv_len];
    std.debug.print("[server] received: {s}\n", .{received});

    try server.sendOnStream(stream_id, received, true);
    try client.processDatagram(0, (try server.pollTx(0, &datagram)).?);

    const echo_len = (try client.recvOnStream(stream_id, &recv_buf)).?;
    std.debug.print("[server] echoed: {s}\n", .{recv_buf[0..echo_len]});
}
