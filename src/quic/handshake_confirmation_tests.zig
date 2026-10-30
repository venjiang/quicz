const std = @import("std");
const Connection = @import("connection.zig").Connection;
const frame = @import("frame.zig");
const protection = @import("protection.zig");
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

fn expectNoHandshakeDone(payload: []const u8) !void {
    var offset: usize = 0;
    while (offset < payload.len) {
        var decoded = try frame.decodeFrameSlice(payload[offset..], std.testing.allocator);
        defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
        try std.testing.expect(std.meta.activeTag(decoded.frame) != .handshake_done);
        offset += decoded.len;
    }
}

test "HANDSHAKE_DONE late ACK cancels retransmission after packet or time loss" {
    const allocator = std.testing.allocator;
    const cid = [_]u8{ 1, 2, 3, 4 };
    const secrets = try protection.deriveInitialSecrets(.v1, &cid);
    for ([_]bool{ false, true }) |protected| {
        for ([_]bool{ false, true }) |time_threshold| {
            for ([_]bool{ false, true }) |cumulative_ack| {
                var server = try Connection.init(allocator, .server, .{ .initial_rtt_ns = 100 * ms });
                defer server.deinit();
                try server.validatePeerAddress();
                try server.sendHandshakeDone();
                if (protected) try server.installOneRttTrafficSecrets(.{ .local = secrets.server.secret, .peer = secrets.client.secret });
                var out: [64]u8 = undefined;
                const first = (if (protected)
                    try server.pollProtectedShortDatagramWithInstalledKeys(0, &cid)
                else
                    try server.pollTx(0, &out)) orelse return error.TestUnexpectedResult;
                if (protected) allocator.free(first);
                try std.testing.expect(server.sent_packets.items[0].handshake_done);
                const pings: usize = if (time_threshold) 1 else 3;
                for (0..pings) |index| {
                    try server.sendPing();
                    const now = @as(i64, @intCast(index + 1)) * ms;
                    const ping = (if (protected)
                        try server.pollProtectedShortDatagramWithInstalledKeys(now, &cid)
                    else
                        try server.pollTx(now, &out)) orelse return error.TestUnexpectedResult;
                    if (protected) allocator.free(ping);
                }
                var now: i64 = if (time_threshold) 101 * ms else 4 * ms;
                try server.receiveAckInSpace(.application, now, .{ .largest_acknowledged = pings, .ack_delay = 0, .first_ack_range = 0 });
                if (time_threshold) {
                    try std.testing.expect(!server.pending_handshake_done);
                    now = (server.lossDetectionTimerDeadline() orelse return error.TestUnexpectedResult).deadline_nanos;
                    _ = try server.serviceLossDetectionTimer(now);
                }
                try std.testing.expect(server.pending_handshake_done);
                now += 1;
                const ack: frame.AckFrame = if (!cumulative_ack)
                    .{ .largest_acknowledged = 0, .ack_delay = 0, .first_ack_range = 0 }
                else if (time_threshold)
                    .{ .largest_acknowledged = 1, .ack_delay = 0, .first_ack_range = 1 }
                else
                    .{ .largest_acknowledged = 3, .ack_delay = 0, .first_ack_range = 0, .ranges = &.{.{ .gap = 1, .ack_range = 0 }} };
                try server.receiveAckInSpace(.application, now, ack);
                try std.testing.expect(server.handshake_done_acked);
                try std.testing.expect(!server.pending_handshake_done);
                const next_number = server.next_packet_number;
                const next = if (protected)
                    try server.pollProtectedShortDatagramWithInstalledKeys(now + 1, &cid)
                else
                    try server.pollTx(now + 1, &out);
                if (next) |bytes| {
                    if (protected) {
                        defer allocator.free(bytes);
                        var decoded = try protection.unprotectShortPacketAes128(allocator, secrets.server, bytes, cid.len, next_number);
                        defer protection.deinitProtectedShortPacket(&decoded, allocator);
                        try expectNoHandshakeDone(decoded.packet.plaintext);
                    } else try expectNoHandshakeDone(bytes);
                }
            }
        }
    }
}

fn loseHandshakeDone(server: *Connection, sent_at: i64) !u64 {
    const packet_number = server.next_packet_number;
    var out: [64]u8 = undefined;
    try expectHandshakeDone((try server.pollTx(sent_at, &out)) orelse return error.TestUnexpectedResult);
    for (0..3) |index| {
        try server.sendPing();
        _ = (try server.pollTx(sent_at + @as(i64, @intCast(index + 1)) * ms, &out)) orelse return error.TestUnexpectedResult;
    }
    try server.receiveAckInSpace(.application, sent_at + 4 * ms, .{ .largest_acknowledged = packet_number + 3, .ack_delay = 0, .first_ack_range = 0 });
    try std.testing.expect(server.pending_handshake_done);
    return packet_number;
}

test "HANDSHAKE_DONE late ACK preserves validation and in-flight accounting" {
    var server = try Connection.init(std.testing.allocator, .server, .{ .initial_rtt_ns = 100 * ms });
    defer server.deinit();
    try server.validatePeerAddress();
    _ = try server.recordPacketSentInSpace(.initial, 0, 100);
    try server.sendHandshakeDone();
    const lost_number = try loseHandshakeDone(&server, 0);
    try std.testing.expectEqual(@as(usize, 1), server.lost_handshake_done_count);
    try std.testing.expectError(error.InvalidPacket, server.receiveAckInSpace(.application, 5 * ms, .{
        .largest_acknowledged = server.next_packet_number,
        .ack_delay = 0,
        .first_ack_range = server.next_packet_number,
    }));
    try std.testing.expectError(error.InvalidPacket, server.receiveAckInSpace(.application, 5 * ms, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &.{.{ .gap = 1, .ack_range = 1 }},
    }));
    try server.receiveAckInSpace(.initial, 5 * ms, .{ .largest_acknowledged = lost_number, .ack_delay = 0, .first_ack_range = 0 });
    try server.receiveAckInSpace(.application, 6 * ms, .{ .largest_acknowledged = lost_number + 1, .ack_delay = 0, .first_ack_range = 0 });
    try std.testing.expect(!server.handshake_done_acked);
    try std.testing.expect(server.pending_handshake_done);
    try std.testing.expectEqual(@as(usize, 1), server.lost_handshake_done_count);

    var out: [64]u8 = undefined;
    try expectHandshakeDone((try server.pollTx(7 * ms, &out)) orelse return error.TestUnexpectedResult);
    const first_deadline = server.lossDetectionTimerDeadline() orelse return error.TestUnexpectedResult;
    if (first_deadline.kind == .loss_time) _ = try server.serviceLossDetectionTimer(first_deadline.deadline_nanos);
    const pto = server.ptoDeadline(.application) orelse return error.TestUnexpectedResult;
    _ = try server.serviceLossDetectionTimer(pto);
    try std.testing.expect(server.pending_handshake_done);
    const in_flight = server.bytesInFlight(.application);
    const cwnd = server.recovery_state.congestion_window;
    const smoothed_rtt = server.recovery_state.smoothed_rtt_ns;
    try std.testing.expect(in_flight > 0);
    try server.receiveAckInSpace(.application, pto + 1, .{ .largest_acknowledged = lost_number, .ack_delay = 0, .first_ack_range = 0 });
    try std.testing.expect(server.handshake_done_acked);
    try std.testing.expect(!server.pending_handshake_done);
    try std.testing.expectEqual(@as(usize, 0), server.lost_handshake_done_count);
    try std.testing.expectEqual(in_flight, server.bytesInFlight(.application));
    try std.testing.expectEqual(cwnd, server.recovery_state.congestion_window);
    try std.testing.expectEqual(smoothed_rtt, server.recovery_state.smoothed_rtt_ns);
    for (0..3) |index| {
        try server.sendPing();
        _ = (try server.pollTx(pto + @as(i64, @intCast(index + 2)) * ms, &out)) orelse return error.TestUnexpectedResult;
    }
    try server.receiveAckInSpace(.application, pto + 5 * ms, .{ .largest_acknowledged = server.next_packet_number - 1, .ack_delay = 0, .first_ack_range = 0 });
    try std.testing.expect(!server.pending_handshake_done);
    try std.testing.expectEqual(@as(usize, 0), server.lost_handshake_done_count);
    if (try server.pollTx(pto + 6 * ms, &out)) |payload| try expectNoHandshakeDone(payload);
}

test "HANDSHAKE_DONE lost history is bounded and clears on retained or in-flight ACK" {
    for ([_]bool{ false, true }) |ack_in_flight| {
        var server = try Connection.init(std.testing.allocator, .server, .{ .initial_rtt_ns = 100 * ms });
        defer server.deinit();
        try server.validatePeerAddress();
        try server.sendHandshakeDone();
        const capacity = server.lost_handshake_done_packet_numbers.len;
        var first_lost: u64 = 0;
        var last_lost: u64 = 0;
        for (0..capacity + 1) |index| {
            last_lost = try loseHandshakeDone(&server, @as(i64, @intCast(index)) * 5 * ms);
            if (index == 0) first_lost = last_lost;
        }
        try std.testing.expectEqual(capacity, server.lost_handshake_done_count);
        try std.testing.expect(server.lost_handshake_done_packet_numbers[0] > first_lost);
        var now = @as(i64, @intCast(capacity + 1)) * 5 * ms;
        try server.receiveAckInSpace(.application, now, .{ .largest_acknowledged = first_lost, .ack_delay = 0, .first_ack_range = 0 });
        try std.testing.expect(!server.handshake_done_acked);
        try std.testing.expect(server.pending_handshake_done);
        var number_to_ack = last_lost;
        if (ack_in_flight) {
            var out: [64]u8 = undefined;
            number_to_ack = server.next_packet_number;
            now += ms;
            try expectHandshakeDone((try server.pollTx(now, &out)) orelse return error.TestUnexpectedResult);
        }
        try server.receiveAckInSpace(.application, now + ms, .{ .largest_acknowledged = number_to_ack, .ack_delay = 0, .first_ack_range = 0 });
        try std.testing.expect(server.handshake_done_acked);
        try std.testing.expect(!server.pending_handshake_done);
        try std.testing.expectEqual(@as(usize, 0), server.lost_handshake_done_count);
    }
}

test "HANDSHAKE_DONE late ACK wins over another copy lost in the same ACK" {
    var server = try Connection.init(std.testing.allocator, .server, .{ .initial_rtt_ns = 100 * ms });
    defer server.deinit();
    try server.validatePeerAddress();
    try server.sendHandshakeDone();
    const lost_number = try loseHandshakeDone(&server, 0);
    var out: [64]u8 = undefined;
    try expectHandshakeDone((try server.pollTx(5 * ms, &out)) orelse return error.TestUnexpectedResult);
    for (0..3) |index| {
        try server.sendPing();
        _ = (try server.pollTx(@as(i64, @intCast(index + 6)) * ms, &out)) orelse return error.TestUnexpectedResult;
    }
    const largest = server.next_packet_number - 1;
    try server.receiveAckInSpace(.application, 9 * ms, .{
        .largest_acknowledged = largest,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &.{.{ .gap = largest - lost_number - 2, .ack_range = 0 }},
    });
    try std.testing.expect(server.handshake_done_acked);
    try std.testing.expect(!server.pending_handshake_done);
    try std.testing.expectEqual(@as(usize, 0), server.lost_handshake_done_count);
    if (try server.pollTx(10 * ms, &out)) |payload| try expectNoHandshakeDone(payload);
}
