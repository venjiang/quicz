const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

fn requireError(expected: anyerror, result: anyerror!void) !void {
    result catch |err| {
        if (err == expected) return;
        return err;
    };
    return error.UnexpectedState;
}

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

    const client_stream = try client.openUniStream();
    try client.sendOnStream(client_stream, "client telemetry", true);

    var recv_buf: [64]u8 = undefined;
    var datagram: [128]u8 = undefined;
    const client_payload = (try client.pollTx(0, &datagram)) orelse return error.UnexpectedState;
    try server.processDatagram(0, client_payload);
    try server.processDatagram(1, client_payload);
    const client_data_len = (try server.recvOnStream(client_stream, &recv_buf)) orelse return error.UnexpectedState;
    std.debug.print("[uni] client->server stream={} data={s} duplicate_ignored=true finished={}\n", .{
        client_stream,
        recv_buf[0..client_data_len],
        try server.recvStreamFinished(client_stream),
    });

    try requireError(error.InvalidStream, server.sendOnStream(client_stream, "reply-not-allowed", true));
    std.debug.print("[uni] server rejected reply on receive-only stream={}\n", .{client_stream});

    var down_client = try quicz.QuicConnection.init(gpa, .client, .{});
    defer down_client.deinit();
    var down_server = try quicz.QuicConnection.init(gpa, .server, .{});
    defer down_server.deinit();
    try down_server.validatePeerAddress();

    const server_stream = try down_server.openUniStream();
    try down_server.sendOnStream(server_stream, "server event", true);

    const server_data = try relayUntilStreamData(&down_server, &down_client, server_stream, &recv_buf);
    std.debug.print("[uni] server->client stream={} data={s} final_size={?} finished={}\n", .{
        server_stream,
        server_data,
        try down_client.recvStreamFinalSize(server_stream),
        try down_client.recvStreamFinished(server_stream),
    });
}
