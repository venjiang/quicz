const std = @import("std");
const Connection = @import("connection.zig").Connection;
const frame = @import("frame.zig");
const ms = std.time.ns_per_ms;

fn expectHandshakeDone(payload: []const u8) !void {
    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .handshake_done => {},
        else => return error.TestUnexpectedResult,
    }
}

test "HANDSHAKE_DONE PTO retransmits until any copy is acknowledged" {
    var server = try Connection.init(std.testing.allocator, .server, .{ .initial_rtt_ns = 100 * ms });
    defer server.deinit();
    try server.validatePeerAddress();
    try server.sendHandshakeDone();
    var out: [64]u8 = undefined;
    try expectHandshakeDone((try server.pollTx(0, &out)) orelse return error.TestUnexpectedResult);
    const deadline = server.ptoDeadline(.application) orelse return error.TestUnexpectedResult;
    _ = try server.serviceLossDetectionTimer(deadline);
    try expectHandshakeDone((try server.pollTx(deadline + 1, &out)) orelse return error.TestUnexpectedResult);
    const retry_at = server.ptoDeadline(.application) orelse return error.TestUnexpectedResult;
    _ = try server.serviceLossDetectionTimer(retry_at);
    try std.testing.expect(server.pending_handshake_done);

    try std.testing.expectError(error.InvalidPacket, server.receiveAckInSpace(.application, retry_at + 1, .{
        .largest_acknowledged = 2,
        .ack_delay = 0,
        .first_ack_range = 0,
    }));
    try std.testing.expect(server.pending_handshake_done);

    try server.receiveAckInSpace(.application, retry_at + 2, .{ .largest_acknowledged = 1, .ack_delay = 0, .first_ack_range = 0 });
    try std.testing.expect(!server.pending_handshake_done);
    try std.testing.expect((try server.pollTx(retry_at + 3, &out)) == null);
}

test "HANDSHAKE_DONE is requeued by packet and time threshold loss" {
    for ([_]bool{ false, true }) |time_threshold| {
        var server = try Connection.init(std.testing.allocator, .server, .{ .initial_rtt_ns = 100 * ms });
        defer server.deinit();
        try server.validatePeerAddress();
        try server.sendHandshakeDone();
        var out: [64]u8 = undefined;
        _ = (try server.pollTx(0, &out)) orelse return error.TestUnexpectedResult;
        const pings: usize = if (time_threshold) 1 else 3;
        for (0..pings) |index| {
            try server.sendPing();
            _ = (try server.pollTx(@as(i64, @intCast(index + 1)) * ms, &out)) orelse return error.TestUnexpectedResult;
        }
        const ack_at: i64 = if (time_threshold) 101 * ms else 4 * ms;
        try server.receiveAckInSpace(.application, ack_at, .{ .largest_acknowledged = pings, .ack_delay = 0, .first_ack_range = 0 });
        var resend_at = ack_at + 1;
        if (time_threshold) {
            try std.testing.expect(!server.pending_handshake_done);
            const loss = server.lossDetectionTimerDeadline() orelse return error.TestUnexpectedResult;
            try std.testing.expect(loss.kind == .loss_time);
            _ = try server.serviceLossDetectionTimer(loss.deadline_nanos);
            resend_at = loss.deadline_nanos + 1;
        }
        try std.testing.expect(server.pending_handshake_done);
        try expectHandshakeDone((try server.pollTx(resend_at, &out)) orelse return error.TestUnexpectedResult);
    }
}
