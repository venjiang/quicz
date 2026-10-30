const std = @import("std");
const Connection = @import("connection.zig").Connection;
const protection = @import("protection.zig");

test "expired receive keys do not reappear after an authenticated packet" {
    const allocator = std.testing.allocator;
    const cid = [_]u8{ 1, 2, 3, 4 };
    const secrets = try protection.deriveInitialSecrets(.v1, &cid);
    const current = protection.nextAes128PacketProtectionKeys(secrets.client);
    for ([_]bool{ false, true }) |caller_owned| {
        var server = try Connection.init(allocator, .server, .{});
        defer server.deinit();
        try server.validatePeerAddress();
        try server.confirmHandshake();
        try server.installOneRttTrafficSecrets(.{ .local = secrets.server.secret, .peer = secrets.client.secret });
        var state = server.peer_one_rtt_key_phase_state.?;
        var now: i64 = 1;
        for (0..2) |number| {
            const datagram = try protection.protectShortPacketAes128(allocator, .{
                .dcid = &cid,
                .key_phase = true,
                .packet_number = number,
            }, .{ .len = 4, .truncated_packet_number = @intCast(number) }, current, &.{ 1, 0, 0 });
            defer allocator.free(datagram);
            if (caller_owned) {
                try server.processProtectedShortDatagramWithKeyPhaseState(now, &state, cid.len, datagram);
            } else {
                try server.processProtectedShortDatagramWithInstalledKeys(now, cid.len, datagram);
                state = server.peer_one_rtt_key_phase_state.?;
            }
            if (number == 0) {
                try std.testing.expect(state.retainsKeyGeneration(0));
                now = state.previousDiscardDeadline() orelse return error.TestUnexpectedResult;
            }
        }
        try std.testing.expect(!state.retainsKeyGeneration(0));
        try std.testing.expectEqual(@as(u64, 2), server.nextPeerPacketNumber(.application));
    }
}
