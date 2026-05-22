const std = @import("std");
const quicz = @import("quicz");

fn pollRequired(
    conn: *quicz.QuicConnection,
    space: quicz.PacketNumberSpace,
    now_millis: i64,
    out: []u8,
) ![]u8 {
    return (try conn.pollTxInSpace(space, now_millis, out)) orelse error.UnexpectedState;
}

fn readCryptoRequired(
    conn: *quicz.QuicConnection,
    space: quicz.PacketNumberSpace,
    out: []u8,
) ![]const u8 {
    const len = (try conn.recvCryptoInSpace(space, out)) orelse return error.UnexpectedState;
    return out[0..len];
}

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    var client = try quicz.QuicConnection.init(gpa, .client, .{});
    defer client.deinit();
    var server = try quicz.QuicConnection.init(gpa, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    var datagram: [128]u8 = undefined;
    var crypto_buf: [128]u8 = undefined;

    try client.sendCryptoInSpace(.initial, "client initial flight");
    const initial_payload = try pollRequired(&client, .initial, 0, &datagram);
    try server.processDatagramInSpace(.initial, 1, initial_payload);
    const initial_bytes = try readCryptoRequired(&server, .initial, &crypto_buf);
    std.debug.print("[crypto] initial recv={s} pending_ack={?}\n", .{
        initial_bytes,
        server.pendingAckLargest(.initial),
    });

    const initial_ack = try pollRequired(&server, .initial, 2, &datagram);
    try client.processDatagramInSpace(.initial, 3, initial_ack);
    std.debug.print("[crypto] initial acked sent_packets={}\n", .{client.sentPacketCount(.initial)});

    try server.sendCryptoInSpace(.handshake, "server handshake flight");
    const handshake_payload = try pollRequired(&server, .handshake, 4, &datagram);
    try client.processDatagramInSpace(.handshake, 5, handshake_payload);
    const handshake_bytes = try readCryptoRequired(&client, .handshake, &crypto_buf);
    std.debug.print("[crypto] handshake recv={s} pending_ack={?}\n", .{
        handshake_bytes,
        client.pendingAckLargest(.handshake),
    });

    try client.confirmHandshake();
    std.debug.print("[crypto] client handshake_confirmed={}\n", .{client.handshakeConfirmed()});
}
