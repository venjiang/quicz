const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

fn relayUntilStreamData(
    sender: *quicz.QuicConnection,
    receiver: *quicz.QuicConnection,
    stream_id: u64,
    out: []u8,
) ![]const u8 {
    var datagram: [128]u8 = undefined;
    var attempts: usize = 0;
    while (attempts < 8) : (attempts += 1) {
        if (try receiver.recvOnStream(stream_id, out)) |len| return out[0..len];
        const payload = (try sender.pollTx(0, &datagram)) orelse return error.UnexpectedState;
        try receiver.processDatagram(0, payload);
    }
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
    try client.sendOnStream(stream_id, "hello from quicz client", true);

    var recv_buf: [128]u8 = undefined;
    const received = try relayUntilStreamData(&client, &server, stream_id, &recv_buf);
    std.debug.print("[server] received: {s}\n", .{received});

    try server.sendOnStream(stream_id, received, true);

    const echoed = try relayUntilStreamData(&server, &client, stream_id, &recv_buf);
    std.debug.print("[client] echoed: {s}\n", .{echoed});
}
