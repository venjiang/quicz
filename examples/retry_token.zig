const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{RetryTokenExampleFailed};

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var server = try quicz.QuicConnection.init(allocator, .server, .{});
    defer server.deinit();

    const retry_token = "retry-token-for-client-address";
    try server.issueRetryToken(retry_token);

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const retry = quicz.packet.RetryPacket{
        .version = .v1,
        .dcid = &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd },
        .scid = &[_]u8{ 0x10, 0x20, 0x30, 0x40 },
        .token = retry_token,
        .integrity_tag = [_]u8{0} ** quicz.protection.aead_tag_len,
    };

    const retry_datagram = try quicz.protection.encodeRetryPacketWithIntegrity(allocator, &original_dcid, retry);
    defer allocator.free(retry_datagram);
    const retry_integrity_valid = try quicz.protection.verifyRetryIntegrityTag(allocator, &original_dcid, retry_datagram);
    if (!retry_integrity_valid) return error.RetryTokenExampleFailed;

    var parsed = try quicz.protection.parseRetryPacketWithIntegrity(allocator, &original_dcid, retry_datagram);
    defer quicz.packet.deinitRetryPacket(&parsed, allocator);

    try server.sendPing();
    var tx: [16]u8 = undefined;
    if (try server.pollTx(0, &tx) != null) return error.RetryTokenExampleFailed;

    try server.validateRetryToken(parsed.token);
    const payload = (try server.pollTx(1, &tx)) orelse return error.RetryTokenExampleFailed;
    if (!server.peerAddressValidated() or server.pendingRetryTokenCount() != 0) return error.RetryTokenExampleFailed;

    server.validateRetryToken(parsed.token) catch |err| {
        if (err != error.InvalidPacket) return err;
    };

    std.debug.print(
        "[retry] token_len={} integrity={} address_validated={} ping_bytes={}\n",
        .{ parsed.token.len, retry_integrity_valid, server.peerAddressValidated(), payload.len },
    );
    std.debug.print("[retry] consumed token is not reusable\n", .{});
}
