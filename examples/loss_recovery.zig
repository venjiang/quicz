const std = @import("std");
const quicz = @import("quicz");

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var packet_threshold = try quicz.Connection.init(allocator, .client, .{});
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

    var invalid_ack = try quicz.Connection.init(allocator, .client, .{});
    defer invalid_ack.deinit();
    _ = try invalid_ack.recordPacketSentInSpace(.application, 10, 100);
    _ = try invalid_ack.recordPacketSentInSpace(.application, 20, 100);
    const invalid_ack_ranges = [_]quicz.frame.AckRange{
        .{ .gap = 0, .ack_range = 0 },
    };
    invalid_ack.receiveAckInSpace(.application, 60, .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &invalid_ack_ranges,
    }) catch |err| switch (err) {
        error.InvalidPacket => {},
        else => return err,
    };
    if (invalid_ack.sentPacketCount(.application) != 2) return error.LossRecoveryExampleFailed;
    if (invalid_ack.bytesInFlight(.application) != 200) return error.LossRecoveryExampleFailed;
    std.debug.print(
        "[loss] invalid ACK range rejected; remaining={d} bytes_in_flight={d}\n",
        .{ invalid_ack.sentPacketCount(.application), invalid_ack.bytesInFlight(.application) },
    );

    var time_threshold = try quicz.Connection.init(allocator, .client, .{});
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

    var newreno = try quicz.Connection.init(allocator, .client, .{
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
    const underutilized_cwnd = newreno.congestionWindow(.application);
    if (underutilized_cwnd != initial_cwnd) return error.LossRecoveryExampleFailed;

    var slow_start_sent: usize = 0;
    while (slow_start_sent < 10) : (slow_start_sent += 1) {
        _ = try newreno.recordPacketSentInSpace(.application, @as(i64, @intCast(slow_start_sent + 1)), 1200);
    }
    try newreno.receiveAckInSpace(.application, 110, .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    const slow_start_cwnd = newreno.congestionWindow(.application);
    if (slow_start_cwnd != initial_cwnd + 1200) return error.LossRecoveryExampleFailed;

    newreno.recovery_state.ssthresh = slow_start_cwnd;
    while (newreno.bytesInFlight(.application) < newreno.congestionWindow(.application)) {
        _ = try newreno.recordPacketSentInSpace(.application, 120, 1200);
    }
    const avoidance_before = newreno.congestionWindow(.application);
    try newreno.receiveAckInSpace(.application, 220, .{
        .largest_acknowledged = 2,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    const avoidance_credit_cwnd = newreno.congestionWindow(.application);
    if (avoidance_credit_cwnd != avoidance_before) return error.LossRecoveryExampleFailed;
    if (newreno.recovery_state.congestion_avoidance_bytes_acked != 1200) return error.LossRecoveryExampleFailed;

    _ = try newreno.recordPacketSentInSpace(.application, 230, 1200);
    if (newreno.bytesInFlight(.application) != avoidance_before) return error.LossRecoveryExampleFailed;
    try newreno.receiveAckInSpace(.application, 240, .{
        .largest_acknowledged = 12,
        .ack_delay = 0,
        .first_ack_range = 9,
    });
    const avoidance_cwnd = newreno.congestionWindow(.application);
    if (avoidance_cwnd != avoidance_before + 1200) return error.LossRecoveryExampleFailed;
    if (newreno.recovery_state.congestion_avoidance_bytes_acked != 0) return error.LossRecoveryExampleFailed;
    if (newreno.bytesInFlight(.application) != 1200) return error.LossRecoveryExampleFailed;
    std.debug.print(
        "[loss] NewReno underutilized_cwnd={d} slow_start_cwnd={d} congestion_avoidance_credit_cwnd={d} congestion_avoidance_cwnd={d} avoidance_increase={d}\n",
        .{ underutilized_cwnd, slow_start_cwnd, avoidance_credit_cwnd, avoidance_cwnd, avoidance_cwnd - avoidance_before },
    );

    var batched_avoidance = quicz.recovery.Recovery.init(.{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    batched_avoidance.congestion_window = 12_000;
    batched_avoidance.ssthresh = 12_000;
    batched_avoidance.onPacketSent(25_200);
    batched_avoidance.onPacketAcked(25_200, 0, 100, 0);
    if (batched_avoidance.congestion_window != 14_400) return error.LossRecoveryExampleFailed;
    if (batched_avoidance.congestion_avoidance_bytes_acked != 0) return error.LossRecoveryExampleFailed;
    std.debug.print(
        "[loss] NewReno batched_avoidance_cwnd={d} batched_credit={d}\n",
        .{ batched_avoidance.congestion_window, batched_avoidance.congestion_avoidance_bytes_acked },
    );

    var newreno_clamp = try quicz.Connection.init(allocator, .client, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer newreno_clamp.deinit();
    newreno_clamp.recovery_state.congestion_window = 3_000;
    var clamp_packet_number: u64 = 0;
    while (clamp_packet_number < 4) : (clamp_packet_number += 1) {
        _ = try newreno_clamp.recordPacketSentInSpace(.application, @as(i64, @intCast(clamp_packet_number + 1)) * 10, 100);
    }
    try newreno_clamp.receiveAckInSpace(.application, 100, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    const minimum_cwnd = quicz.recovery.minimumCongestionWindow(1200);
    if (newreno_clamp.congestionWindow(.application) != minimum_cwnd) return error.LossRecoveryExampleFailed;
    if (newreno_clamp.recovery_state.ssthresh != 1_500) return error.LossRecoveryExampleFailed;
    std.debug.print(
        "[loss] NewReno min clamp cwnd={d} ssthresh={d}\n",
        .{ newreno_clamp.congestionWindow(.application), newreno_clamp.recovery_state.ssthresh },
    );

    var persistent = try quicz.Connection.init(allocator, .client, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer persistent.deinit();

    _ = try persistent.recordPacketSentInSpace(.application, 0, 100);
    try persistent.receiveAckInSpace(.application, 50, .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    if (persistent.recovery_state.min_rtt_ms != 50) return error.LossRecoveryExampleFailed;
    persistent.recovery_state.onPtoExpired();
    persistent.recovery_state.onPtoExpired();
    const persistent_duration = persistent.recovery_state.persistentCongestionDurationMs();
    _ = try persistent.recordPacketSentInSpace(.application, 100, 100);
    _ = try persistent.recordPacketSentInSpace(.application, 1000, 100);
    _ = try persistent.recordPacketSentInSpace(.application, 1100, 100);
    _ = try persistent.recordPacketSentInSpace(.application, 1200, 100);
    try persistent.receiveAckInSpace(.application, 1700, .{
        .largest_acknowledged = 4,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    if (persistent.congestionWindow(.application) != quicz.recovery.minimumCongestionWindow(1200)) {
        return error.LossRecoveryExampleFailed;
    }
    const refreshed_min_rtt = persistent.recovery_state.min_rtt_ms orelse return error.LossRecoveryExampleFailed;
    if (refreshed_min_rtt != 500) return error.LossRecoveryExampleFailed;
    const persistent_recovery_cleared = persistent.recovery_state.congestion_recovery_start_time_millis == null;
    if (!persistent_recovery_cleared) return error.LossRecoveryExampleFailed;
    if (!persistent.recovery_state.wouldStartCongestionRecovery(1800)) return error.LossRecoveryExampleFailed;
    persistent.recovery_state.congestion_avoidance_bytes_acked = 600;
    persistent.recovery_state.onCongestionEvent(1800, 1900);
    const persistent_reentry_start = persistent.recovery_state.congestion_recovery_start_time_millis orelse return error.LossRecoveryExampleFailed;
    if (persistent_reentry_start != 1900) return error.LossRecoveryExampleFailed;
    if (persistent.recovery_state.congestion_avoidance_bytes_acked != 0) return error.LossRecoveryExampleFailed;
    std.debug.print(
        "[loss] persistent congestion duration={d} reduced_cwnd={d} refreshed_min_rtt={d} recovery_cleared={} reentry_start={d}\n",
        .{
            persistent_duration,
            persistent.congestionWindow(.application),
            refreshed_min_rtt,
            persistent_recovery_cleared,
            persistent_reentry_start,
        },
    );

    var non_contiguous_persistent = try quicz.Connection.init(allocator, .client, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer non_contiguous_persistent.deinit();

    _ = try non_contiguous_persistent.recordPacketSentInSpace(.application, 0, 100);
    try non_contiguous_persistent.receiveAckInSpace(.application, 100, .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    _ = try non_contiguous_persistent.recordPacketSentInSpace(.application, 10, 100);
    _ = try non_contiguous_persistent.recordPacketSentInSpace(.application, 1000, 100);
    _ = try non_contiguous_persistent.recordPacketSentInSpace(.application, 1100, 100);
    _ = try non_contiguous_persistent.recordPacketSentInSpace(.application, 1200, 100);
    _ = try non_contiguous_persistent.recordPacketSentInSpace(.application, 1300, 100);
    const non_contiguous_ack_ranges = [_]quicz.frame.AckRange{
        .{ .gap = 0, .ack_range = 0 },
    };
    try non_contiguous_persistent.receiveAckInSpace(.application, 1400, .{
        .largest_acknowledged = 5,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &non_contiguous_ack_ranges,
    });
    if (non_contiguous_persistent.congestionWindow(.application) <= quicz.recovery.minimumCongestionWindow(1200)) {
        return error.LossRecoveryExampleFailed;
    }
    std.debug.print(
        "[loss] non_contiguous_persistent suppressed cwnd={d} minimum={d}\n",
        .{ non_contiguous_persistent.congestionWindow(.application), quicz.recovery.minimumCongestionWindow(1200) },
    );

    var recovery_period = try quicz.Connection.init(allocator, .client, .{
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

    var recovery_ack_accounting = quicz.recovery.Recovery.init(.{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    recovery_ack_accounting.congestion_window = 12_000;
    recovery_ack_accounting.ssthresh = 12_000;
    recovery_ack_accounting.congestion_avoidance_bytes_acked = 600;
    recovery_ack_accounting.onPacketSent(12_000);
    recovery_ack_accounting.onPtoExpired();
    recovery_ack_accounting.onCongestionEvent(20, 100);
    const recovery_ack_cwnd = recovery_ack_accounting.congestion_window;
    recovery_ack_accounting.onPacketAcked(1200, 100, 80, 0);
    if (recovery_ack_accounting.congestion_window != recovery_ack_cwnd) return error.LossRecoveryExampleFailed;
    if (recovery_ack_accounting.congestion_avoidance_bytes_acked != 0) return error.LossRecoveryExampleFailed;
    if (recovery_ack_accounting.bytes_in_flight != 10_800) return error.LossRecoveryExampleFailed;
    if (recovery_ack_accounting.pto_count != 0) return error.LossRecoveryExampleFailed;
    const recovery_ack_latest_rtt = recovery_ack_accounting.latest_rtt_ms orelse return error.LossRecoveryExampleFailed;
    if (recovery_ack_latest_rtt != 80) return error.LossRecoveryExampleFailed;
    std.debug.print(
        "[loss] recovery ACK accounting cwnd={d} latest_rtt={d} inflight={d} credit={d}\n",
        .{
            recovery_ack_accounting.congestion_window,
            recovery_ack_latest_rtt,
            recovery_ack_accounting.bytes_in_flight,
            recovery_ack_accounting.congestion_avoidance_bytes_acked,
        },
    );

    var congestion_probe = try quicz.Connection.init(allocator, .client, .{
        .max_datagram_size = 1350,
        .initial_rtt_ms = 100,
    });
    defer congestion_probe.deinit();
    const probe_stream_id = try congestion_probe.openStream();
    var probe_chunk: [1200]u8 = undefined;
    @memset(&probe_chunk, 'p');
    var probe_buf: [1400]u8 = undefined;
    var probe_sent: usize = 0;
    while (probe_sent < 8) : (probe_sent += 1) {
        try congestion_probe.sendOnStream(probe_stream_id, &probe_chunk, false);
        _ = (try congestion_probe.pollTx(@as(i64, @intCast(probe_sent + 1)) * 10, &probe_buf)) orelse return error.LossRecoveryExampleFailed;
    }
    const minimum_probe_cwnd = quicz.recovery.minimumCongestionWindow(congestion_probe.recovery_state.max_datagram_size);
    congestion_probe.recovery_state.congestion_window = minimum_probe_cwnd;
    try congestion_probe.receiveAckInSpace(.application, 90, .{
        .largest_acknowledged = 5,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    if (congestion_probe.bytesInFlight(.application) < congestion_probe.congestionWindow(.application)) {
        return error.LossRecoveryExampleFailed;
    }
    if (congestion_probe.recovery_state.canSend(1)) return error.LossRecoveryExampleFailed;
    const probe_payload = (try congestion_probe.pollTx(100, &probe_buf)) orelse return error.LossRecoveryExampleFailed;
    if (congestion_probe.bytesInFlight(.application) <= congestion_probe.congestionWindow(.application)) {
        return error.LossRecoveryExampleFailed;
    }
    std.debug.print(
        "[loss] congestion probe retransmit bytes={d} cwnd={d} inflight={d}\n",
        .{ probe_payload.len, congestion_probe.congestionWindow(.application), congestion_probe.bytesInFlight(.application) },
    );

    var ce_probe = try quicz.Connection.init(allocator, .client, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer ce_probe.deinit();
    const ce_probe_stream_id = try ce_probe.openStream();
    try ce_probe.sendOnStream(ce_probe_stream_id, "ce congestion probe", false);
    ce_probe.recovery_state.congestion_window = 36_000;
    var ce_packet_number: usize = 0;
    while (ce_packet_number < 30) : (ce_packet_number += 1) {
        _ = try ce_probe.recordEcnPacketSentInSpace(
            .application,
            @as(i64, @intCast(ce_packet_number + 1)) * 10,
            1200,
            .ect0,
        );
    }
    var ce_probe_buf: [1400]u8 = undefined;
    if (try ce_probe.pollTx(350, &ce_probe_buf) != null) return error.LossRecoveryExampleFailed;
    try ce_probe.receiveAckEcnInSpace(.application, 360, .{
        .ack = .{
            .largest_acknowledged = 0,
            .ack_delay = 0,
            .first_ack_range = 0,
        },
        .ecn_counts = .{
            .ect0_count = 0,
            .ect1_count = 0,
            .ecn_ce_count = 1,
        },
    });
    if (ce_probe.ecnValidationState(.application) != .capable) return error.LossRecoveryExampleFailed;
    if (ce_probe.ecnCounts(.application).ecn_ce_count != 1) return error.LossRecoveryExampleFailed;
    if (ce_probe.congestion_probe_count != 1) return error.LossRecoveryExampleFailed;
    if (ce_probe.recovery_state.canSend(1)) return error.LossRecoveryExampleFailed;
    const ce_probe_payload = (try ce_probe.pollTx(370, &ce_probe_buf)) orelse return error.LossRecoveryExampleFailed;
    if (ce_probe.congestion_probe_count != 0) return error.LossRecoveryExampleFailed;
    std.debug.print(
        "[loss] CE congestion probe bytes={d} ce_count={d} cwnd={d} inflight={d}\n",
        .{
            ce_probe_payload.len,
            ce_probe.ecnCounts(.application).ecn_ce_count,
            ce_probe.congestionWindow(.application),
            ce_probe.bytesInFlight(.application),
        },
    );

    var rtt_sampling = try quicz.Connection.init(allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer rtt_sampling.deinit();
    _ = try rtt_sampling.recordPacketSentInSpace(.application, 90, 100);
    _ = try rtt_sampling.recordPacketSentInSpace(.application, 100, 100);
    _ = try rtt_sampling.recordPacketSentInSpace(.application, 110, 100);
    try rtt_sampling.receiveAckInSpace(.application, 200, .{
        .largest_acknowledged = 2,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    const baseline_latest_rtt = rtt_sampling.recovery_state.latest_rtt_ms orelse return error.LossRecoveryExampleFailed;
    const baseline_smoothed_rtt = rtt_sampling.smoothedRttMillis(.application);
    const lower_ack_ranges = [_]quicz.frame.AckRange{
        .{ .gap = 0, .ack_range = 0 },
    };
    rtt_sampling.recovery_state.onPtoExpired();
    try rtt_sampling.receiveAckInSpace(.application, 201, .{
        .largest_acknowledged = 2,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &lower_ack_ranges,
    });
    if (rtt_sampling.sentPacketCount(.application) != 1) return error.LossRecoveryExampleFailed;
    if (rtt_sampling.bytesInFlight(.application) != 100) return error.LossRecoveryExampleFailed;
    if (rtt_sampling.recovery_state.pto_count != 0) return error.LossRecoveryExampleFailed;
    const lower_ack_latest_rtt = rtt_sampling.recovery_state.latest_rtt_ms orelse return error.LossRecoveryExampleFailed;
    if (lower_ack_latest_rtt != baseline_latest_rtt) return error.LossRecoveryExampleFailed;
    if (rtt_sampling.smoothedRttMillis(.application) != baseline_smoothed_rtt) return error.LossRecoveryExampleFailed;
    std.debug.print(
        "[loss] old-largest ACK preserved RTT latest={d} smoothed={d} remaining={d}\n",
        .{ baseline_latest_rtt, baseline_smoothed_rtt, rtt_sampling.sentPacketCount(.application) },
    );

    var cross_space_gate = try quicz.Connection.init(allocator, .server, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer cross_space_gate.deinit();
    try cross_space_gate.validatePeerAddress();
    _ = try cross_space_gate.recordPacketSentInSpace(.initial, 0, 6000);
    _ = try cross_space_gate.recordPacketSentInSpace(.handshake, 1, 6000);
    const blocked_total_inflight = cross_space_gate.totalBytesInFlight();
    const blocked_stream_id = try cross_space_gate.openStream();
    try cross_space_gate.sendOnStream(blocked_stream_id, "blocked", false);
    var gate_buf: [128]u8 = undefined;
    if (try cross_space_gate.pollTx(10, &gate_buf) != null) return error.LossRecoveryExampleFailed;
    try cross_space_gate.receiveAckInSpace(.initial, 20, .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    const unblocked_total_inflight = cross_space_gate.totalBytesInFlight();
    const gate_payload = (try cross_space_gate.pollTx(30, &gate_buf)) orelse return error.LossRecoveryExampleFailed;
    var gate_decoded = try quicz.frame.decodeFrameSlice(gate_payload, allocator);
    defer quicz.frame.deinitFrame(&gate_decoded.frame, allocator);
    switch (gate_decoded.frame) {
        .stream => |stream_frame| {
            if (stream_frame.stream_id != blocked_stream_id) return error.LossRecoveryExampleFailed;
            if (!std.mem.eql(u8, stream_frame.data, "blocked")) return error.LossRecoveryExampleFailed;
        },
        else => return error.LossRecoveryExampleFailed,
    }
    std.debug.print(
        "[loss] cross-space congestion gate blocked_inflight={d} unblocked_inflight={d} app_packets={d}\n",
        .{ blocked_total_inflight, unblocked_total_inflight, cross_space_gate.sentPacketCount(.application) },
    );

    var ack_delay = try quicz.Connection.init(allocator, .client, .{
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
