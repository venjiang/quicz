const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

fn pollRequired(conn: *quicz.QuicConnection, out: []u8) ![]const u8 {
    return (try conn.pollTx(0, out)) orelse error.UnexpectedState;
}

fn requireError(expected: anyerror, result: anyerror!?usize) !void {
    _ = result catch |err| {
        if (err == expected) return;
        return err;
    };
    return error.UnexpectedState;
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

    var datagram: [128]u8 = undefined;
    try server.processDatagram(0, try pollRequired(&client, &datagram));
    try server.stopSending(stream_id, 23);

    const stop_payload = try pollRequired(&server, &datagram);
    try client.processDatagram(1, stop_payload);
    std.debug.print("[stop] receiver requested stop stream={} error=23\n", .{stream_id});

    const reset_payload = try pollRequired(&client, &datagram);
    try server.processDatagram(2, reset_payload);

    var recv_buf: [16]u8 = undefined;
    try requireError(error.StreamClosed, server.recvOnStream(stream_id, &recv_buf));
    std.debug.print("[stop] sender answered with RESET_STREAM final_size={?}\n", .{
        try server.recvStreamFinalSize(stream_id),
    });
}
