const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{AddressValidationExampleFailed};

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var server = try quicz.QuicConnection.init(allocator, .server, .{});
    defer server.deinit();

    try server.sendPing();
    var out_buf: [32]u8 = undefined;
    if (try server.pollTx(0, &out_buf) != null) return error.AddressValidationExampleFailed;
    if (server.pending_ping_count != 1) return error.AddressValidationExampleFailed;

    std.debug.print("[address] unvalidated server blocked before received bytes\n", .{});

    try server.recordPeerAddressBytesReceived(1);
    const ping_payload = (try server.pollTx(1, &out_buf)) orelse return error.AddressValidationExampleFailed;
    if (ping_payload.len != 1) return error.AddressValidationExampleFailed;
    const remaining = server.antiAmplificationLimitRemaining() orelse return error.AddressValidationExampleFailed;

    std.debug.print("[address] recorded=1 sent={} remaining={}\n", .{ ping_payload.len, remaining });

    try server.sendCryptoInSpace(.handshake, "x");
    if (try server.pollTxInSpace(.handshake, 2, &out_buf) != null) return error.AddressValidationExampleFailed;

    try server.validatePeerAddress();
    const crypto_payload = (try server.pollTxInSpace(.handshake, 3, &out_buf)) orelse return error.AddressValidationExampleFailed;
    if (server.antiAmplificationLimitRemaining() != null) return error.AddressValidationExampleFailed;

    std.debug.print("[address] validation lifted limit crypto_bytes={}\n", .{crypto_payload.len});
}
