const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

fn requireError(expected: anyerror, result: anyerror!?usize) !void {
    _ = result catch |err| {
        if (err == expected) return;
        return err;
    };
    return error.UnexpectedState;
}

fn pollRequired(conn: *quicz.QuicConnection, out: []u8) ![]const u8 {
    return (try conn.pollTx(0, out)) orelse error.UnexpectedState;
}

fn expectIdle(conn: *quicz.QuicConnection, out: []u8) !void {
    if ((try conn.pollTx(1, out)) != null) return error.UnexpectedState;
}

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    var client = try quicz.QuicConnection.init(gpa, .client, .{});
    defer client.deinit();
    var server = try quicz.QuicConnection.init(gpa, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello", false);
    try client.resetStream(stream_id, 7);

    var datagram: [128]u8 = undefined;
    const client_reset = try pollRequired(&client, &datagram);
    try server.processDatagram(0, client_reset);

    var recv_buf: [16]u8 = undefined;
    try requireError(error.StreamClosed, server.recvOnStream(stream_id, &recv_buf));
    std.debug.print("[stream-reset] client reset stream={} final_size={?}\n", .{
        stream_id,
        try server.recvStreamFinalSize(stream_id),
    });

    try expectIdle(&client, &datagram);
    std.debug.print("[stream-reset] unsent STREAM data dropped after reset\n", .{});

    try server.resetStream(stream_id, 9);
    const server_reset = try pollRequired(&server, &datagram);
    try client.processDatagram(1, server_reset);
    std.debug.print("[stream-reset] server reset reply side stream={} final_size={?}\n", .{
        stream_id,
        try client.recvStreamFinalSize(stream_id),
    });
}
