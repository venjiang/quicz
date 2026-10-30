const std = @import("std");
const Connection = @import("connection.zig").Connection;

/// Deliver the server's queued HANDSHAKE_DONE before testing application traffic.
pub fn confirmClient(client: *Connection, server: *Connection, client_scid: []const u8, now_nanos: i64) !void {
    try std.testing.expect(!client.handshakeConfirmed());
    try std.testing.expect(server.handshakeConfirmed());
    const datagram = (try server.pollProtectedShortDatagramWithInstalledKeys(now_nanos, client_scid)) orelse return error.TestUnexpectedResult;
    defer server.allocator.free(datagram);
    try client.processProtectedShortDatagramWithInstalledKeys(now_nanos + 1, client_scid.len, datagram);
    try std.testing.expect(client.handshakeConfirmed());
}
