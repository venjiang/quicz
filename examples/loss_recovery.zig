const std = @import("std");
const quicz = @import("quicz");

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var packet_threshold = try quicz.QuicConnection.init(allocator, .client, .{});
    defer packet_threshold.deinit();

    _ = try packet_threshold.recordPacketSentInSpace(.application, 10, 100);
    _ = try packet_threshold.recordPacketSentInSpace(.application, 11, 100);
    _ = try packet_threshold.recordPacketSentInSpace(.application, 12, 100);
    _ = try packet_threshold.recordPacketSentInSpace(.application, 13, 100);

    try packet_threshold.receiveAckInSpace(.application, 70, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    if (packet_threshold.sentPacketCount(.application) != 2) return error.LossRecoveryExampleFailed;
    if (packet_threshold.bytesInFlight(.application) != 200) return error.LossRecoveryExampleFailed;
    std.debug.print(
        "[loss] packet-threshold loss removed one packet; remaining={d} bytes_in_flight={d}\n",
        .{ packet_threshold.sentPacketCount(.application), packet_threshold.bytesInFlight(.application) },
    );

    var time_threshold = try quicz.QuicConnection.init(allocator, .client, .{});
    defer time_threshold.deinit();

    _ = try time_threshold.recordPacketSentInSpace(.application, 300, 100);
    _ = try time_threshold.recordPacketSentInSpace(.application, 500, 100);

    try time_threshold.receiveAckInSpace(.application, 600, .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    const timer = time_threshold.lossDetectionTimerDeadlineMillis() orelse return error.LossRecoveryExampleFailed;
    if (timer.space != .application) return error.LossRecoveryExampleFailed;
    if (timer.kind != .loss_time) return error.LossRecoveryExampleFailed;
    const deadline = timer.deadline_millis;
    if (time_threshold.sentPacketCount(.application) != 1) return error.LossRecoveryExampleFailed;
    const serviced = (try time_threshold.serviceLossDetectionTimer(deadline)) orelse return error.LossRecoveryExampleFailed;
    if (serviced.space != .application) return error.LossRecoveryExampleFailed;
    if (serviced.kind != .loss_time) return error.LossRecoveryExampleFailed;

    if (time_threshold.sentPacketCount(.application) != 0) return error.LossRecoveryExampleFailed;
    if (time_threshold.bytesInFlight(.application) != 0) return error.LossRecoveryExampleFailed;
    std.debug.print(
        "[loss] time-threshold deadline={d} removed older packet; remaining={d} bytes_in_flight={d}\n",
        .{ deadline, time_threshold.sentPacketCount(.application), time_threshold.bytesInFlight(.application) },
    );

    var newreno = try quicz.QuicConnection.init(allocator, .client, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer newreno.deinit();

    const initial_cwnd = newreno.congestionWindow(.application);
    _ = try newreno.recordPacketSentInSpace(.application, 0, 1200);
    try newreno.receiveAckInSpace(.application, 100, .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    const slow_start_cwnd = newreno.congestionWindow(.application);
    if (slow_start_cwnd != initial_cwnd + 1200) return error.LossRecoveryExampleFailed;

    newreno.recovery_state.ssthresh = slow_start_cwnd;
    _ = try newreno.recordPacketSentInSpace(.application, 120, 1200);
    const avoidance_before = newreno.congestionWindow(.application);
    const avoidance_increase = @max(@as(usize, 1), (1200 * 1200) / avoidance_before);
    try newreno.receiveAckInSpace(.application, 220, .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    const avoidance_cwnd = newreno.congestionWindow(.application);
    if (avoidance_cwnd != avoidance_before + avoidance_increase) return error.LossRecoveryExampleFailed;
    if (newreno.bytesInFlight(.application) != 0) return error.LossRecoveryExampleFailed;
    std.debug.print(
        "[loss] NewReno slow_start_cwnd={d} congestion_avoidance_cwnd={d} avoidance_increase={d}\n",
        .{ slow_start_cwnd, avoidance_cwnd, avoidance_increase },
    );

    var persistent = try quicz.QuicConnection.init(allocator, .client, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer persistent.deinit();

    _ = try persistent.recordPacketSentInSpace(.application, 0, 100);
    try persistent.receiveAckInSpace(.application, 100, .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    _ = try persistent.recordPacketSentInSpace(.application, 10, 100);
    _ = try persistent.recordPacketSentInSpace(.application, 1000, 100);
    _ = try persistent.recordPacketSentInSpace(.application, 1100, 100);
    _ = try persistent.recordPacketSentInSpace(.application, 1200, 100);
    try persistent.receiveAckInSpace(.application, 1300, .{
        .largest_acknowledged = 4,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    if (persistent.congestionWindow(.application) != quicz.recovery.minimumCongestionWindow(1200)) {
        return error.LossRecoveryExampleFailed;
    }
    std.debug.print(
        "[loss] persistent congestion reduced cwnd={d}\n",
        .{persistent.congestionWindow(.application)},
    );

    var recovery_period = try quicz.QuicConnection.init(allocator, .client, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer recovery_period.deinit();
    var packet_number: u64 = 0;
    while (packet_number < 8) : (packet_number += 1) {
        _ = try recovery_period.recordPacketSentInSpace(.application, @as(i64, @intCast(packet_number + 1)) * 10, 100);
    }
    try recovery_period.receiveAckInSpace(.application, 100, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    const recovery_window = recovery_period.congestionWindow(.application);
    try recovery_period.receiveAckInSpace(.application, 120, .{
        .largest_acknowledged = 7,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    if (recovery_period.congestionWindow(.application) != recovery_window) {
        return error.LossRecoveryExampleFailed;
    }
    std.debug.print(
        "[loss] recovery period suppressed repeated cwnd reduction cwnd={d}\n",
        .{recovery_window},
    );

    var ack_delay = try quicz.QuicConnection.init(allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer ack_delay.deinit();
    try ack_delay.applyPeerTransportParameters(.{
        .max_ack_delay = 10,
        .ack_delay_exponent = 3,
    });

    _ = try ack_delay.recordPacketSentInSpace(.application, 0, 100);
    try ack_delay.receiveAckInSpace(.application, 100, .{
        .largest_acknowledged = 0,
        .ack_delay = 20,
        .first_ack_range = 0,
    });
    _ = try ack_delay.recordPacketSentInSpace(.application, 100, 100);
    try ack_delay.receiveAckInSpace(.application, 220, .{
        .largest_acknowledged = 1,
        .ack_delay = 20,
        .first_ack_range = 0,
    });
    if (ack_delay.smoothedRttMillis(.application) != 102) return error.LossRecoveryExampleFailed;

    _ = try ack_delay.recordPacketSentInSpace(.application, 220, 100);
    try ack_delay.confirmHandshake();
    try ack_delay.receiveAckInSpace(.application, 340, .{
        .largest_acknowledged = 2,
        .ack_delay = 20,
        .first_ack_range = 0,
    });
    if (ack_delay.smoothedRttMillis(.application) != 103) return error.LossRecoveryExampleFailed;
    std.debug.print(
        "[loss] post-handshake ACK delay capped smoothed_rtt_ms={d}\n",
        .{ack_delay.smoothedRttMillis(.application)},
    );
}
