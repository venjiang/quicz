const std = @import("std");
const quicz = @import("quicz");

fn packetContainsCrypto(
    allocator: std.mem.Allocator,
    packet: []const u8,
    keys: quicz.protection.Aes128PacketProtectionKeys,
    dcid_len: usize,
    expected_packet_number: u64,
    expected_data: []const u8,
) !bool {
    var opened = try quicz.protection.unprotectShortPacketAes128(
        allocator,
        keys,
        packet,
        dcid_len,
        expected_packet_number,
    );
    defer quicz.protection.deinitProtectedShortPacket(&opened, allocator);

    var offset: usize = 0;
    while (offset < opened.packet.plaintext.len) {
        var decoded = try quicz.frame.decodeFrameSlice(opened.packet.plaintext[offset..], allocator);
        defer quicz.frame.deinitFrame(&decoded.frame, allocator);
        if (decoded.len == 0) return error.PtoRecoveryExampleFailed;
        offset += decoded.len;

        switch (decoded.frame) {
            .crypto => |crypto| return crypto.offset == 0 and std.mem.eql(u8, crypto.data, expected_data),
            else => {},
        }
    }
    return false;
}

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var pre_confirm = try quicz.QuicConnection.init(allocator, .client, .{ .initial_rtt_ms = 100 });
    defer pre_confirm.deinit();
    _ = try pre_confirm.recordPacketSentInSpace(.application, 10, 100);
    if (pre_confirm.ptoDeadlineMillis(.application) != null) return error.PtoRecoveryExampleFailed;
    if (pre_confirm.lossDetectionTimerDeadlineMillis() != null) return error.PtoRecoveryExampleFailed;
    try pre_confirm.checkPtoTimeouts(10_000);
    if (pre_confirm.pending_ping_count != 0) return error.PtoRecoveryExampleFailed;
    if (pre_confirm.recovery_state.pto_count != 0) return error.PtoRecoveryExampleFailed;
    try pre_confirm.confirmHandshake();
    const pre_confirm_deadline = pre_confirm.ptoDeadlineMillis(.application) orelse return error.PtoRecoveryExampleFailed;
    std.debug.print(
        "[pto] application PTO gated until handshake confirmed deadline={d}\n",
        .{pre_confirm_deadline},
    );

    var conn = try quicz.QuicConnection.init(allocator, .client, .{ .initial_rtt_ms = 100 });
    defer conn.deinit();
    try conn.confirmHandshake();

    _ = try conn.recordPacketSentInSpace(.application, 10, 100);
    const timer = conn.lossDetectionTimerDeadlineMillis() orelse return error.PtoRecoveryExampleFailed;
    if (timer.space != .application) return error.PtoRecoveryExampleFailed;
    if (timer.kind != .pto) return error.PtoRecoveryExampleFailed;
    const deadline = timer.deadline_millis;
    conn.recovery_state.congestion_window = conn.bytesInFlight(.application);
    if (conn.recovery_state.canSend(1)) return error.PtoRecoveryExampleFailed;

    if ((try conn.serviceLossDetectionTimer(deadline - 1)) != null) return error.PtoRecoveryExampleFailed;
    if (conn.ptoDeadlineMillis(.application) != deadline) return error.PtoRecoveryExampleFailed;

    const serviced = (try conn.serviceLossDetectionTimer(deadline)) orelse return error.PtoRecoveryExampleFailed;
    if (serviced.space != .application) return error.PtoRecoveryExampleFailed;
    if (serviced.kind != .pto) return error.PtoRecoveryExampleFailed;
    if (conn.ptoDeadlineMillis(.application) == null) return error.PtoRecoveryExampleFailed;
    if (conn.pto_probe_count != 1) return error.PtoRecoveryExampleFailed;

    var out_buf: [32]u8 = undefined;
    const payload = (try conn.pollTx(deadline + 1, &out_buf)) orelse return error.PtoRecoveryExampleFailed;
    if (conn.pto_probe_count != 0) return error.PtoRecoveryExampleFailed;
    if (conn.bytesInFlight(.application) <= conn.congestionWindow(.application)) return error.PtoRecoveryExampleFailed;
    var decoded = try quicz.frame.decodeFrameSlice(payload, allocator);
    defer quicz.frame.deinitFrame(&decoded.frame, allocator);

    switch (decoded.frame) {
        .ping => {},
        else => return error.PtoRecoveryExampleFailed,
    }

    std.debug.print(
        "[pto] deadline={d} queued and emitted PTO PING bytes={d} cwnd={d} inflight={d}\n",
        .{ deadline, payload.len, conn.congestionWindow(.application), conn.bytesInFlight(.application) },
    );

    var stream_probe = try quicz.QuicConnection.init(allocator, .client, .{ .initial_rtt_ms = 100 });
    defer stream_probe.deinit();
    try stream_probe.confirmHandshake();
    const stream_id = try stream_probe.openStream();
    try stream_probe.sendOnStream(stream_id, "old", false);
    _ = (try stream_probe.pollTx(10, &out_buf)) orelse return error.PtoRecoveryExampleFailed;
    try stream_probe.sendOnStream(stream_id, "new", false);
    const stream_probe_deadline = stream_probe.ptoDeadlineMillis(.application) orelse return error.PtoRecoveryExampleFailed;
    try stream_probe.checkPtoTimeouts(stream_probe_deadline);

    const stream_probe_payload = (try stream_probe.pollTx(stream_probe_deadline + 1, &out_buf)) orelse return error.PtoRecoveryExampleFailed;
    var stream_probe_decoded = try quicz.frame.decodeFrameSlice(stream_probe_payload, allocator);
    defer quicz.frame.deinitFrame(&stream_probe_decoded.frame, allocator);
    switch (stream_probe_decoded.frame) {
        .stream => |stream_frame| {
            if (stream_frame.stream_id != stream_id) return error.PtoRecoveryExampleFailed;
            if (stream_frame.offset != 3) return error.PtoRecoveryExampleFailed;
            if (!std.mem.eql(u8, stream_frame.data, "new")) return error.PtoRecoveryExampleFailed;
        },
        else => return error.PtoRecoveryExampleFailed,
    }

    std.debug.print(
        "[pto] queued STREAM data used as PTO probe bytes={d}\n",
        .{stream_probe_payload.len},
    );

    var retransmit_probe = try quicz.QuicConnection.init(allocator, .client, .{ .initial_rtt_ms = 100 });
    defer retransmit_probe.deinit();
    try retransmit_probe.confirmHandshake();
    const retransmit_stream_id = try retransmit_probe.openStream();
    try retransmit_probe.sendOnStream(retransmit_stream_id, "old", false);
    _ = (try retransmit_probe.pollTx(10, &out_buf)) orelse return error.PtoRecoveryExampleFailed;
    const retransmit_deadline = retransmit_probe.ptoDeadlineMillis(.application) orelse return error.PtoRecoveryExampleFailed;
    try retransmit_probe.checkPtoTimeouts(retransmit_deadline);

    const retransmit_payload = (try retransmit_probe.pollTx(retransmit_deadline + 1, &out_buf)) orelse return error.PtoRecoveryExampleFailed;
    var retransmit_decoded = try quicz.frame.decodeFrameSlice(retransmit_payload, allocator);
    defer quicz.frame.deinitFrame(&retransmit_decoded.frame, allocator);
    switch (retransmit_decoded.frame) {
        .stream => |stream_frame| {
            if (stream_frame.stream_id != retransmit_stream_id) return error.PtoRecoveryExampleFailed;
            if (stream_frame.offset != 0) return error.PtoRecoveryExampleFailed;
            if (!std.mem.eql(u8, stream_frame.data, "old")) return error.PtoRecoveryExampleFailed;
        },
        else => return error.PtoRecoveryExampleFailed,
    }

    std.debug.print(
        "[pto] in-flight STREAM data used as PTO probe bytes={d}\n",
        .{retransmit_payload.len},
    );

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var crypto_probe = try quicz.QuicConnection.init(allocator, .client, .{ .initial_rtt_ms = 100 });
    defer crypto_probe.deinit();
    try crypto_probe.confirmHandshake();
    try crypto_probe.sendCrypto("pto protected crypto");
    const first_crypto = (try crypto_probe.pollProtectedShortDatagram(
        10,
        &server_dcid,
        secrets.client,
    )) orelse return error.PtoRecoveryExampleFailed;
    defer allocator.free(first_crypto);

    const crypto_deadline = crypto_probe.ptoDeadlineMillis(.application) orelse return error.PtoRecoveryExampleFailed;
    try crypto_probe.checkPtoTimeouts(crypto_deadline);
    if (crypto_probe.pending_ping_count != 0) return error.PtoRecoveryExampleFailed;

    const crypto_payload = (try crypto_probe.pollProtectedShortDatagram(
        crypto_deadline + 1,
        &server_dcid,
        secrets.client,
    )) orelse return error.PtoRecoveryExampleFailed;
    defer allocator.free(crypto_payload);
    if (!try packetContainsCrypto(
        allocator,
        crypto_payload,
        secrets.client,
        server_dcid.len,
        1,
        "pto protected crypto",
    )) return error.PtoRecoveryExampleFailed;

    std.debug.print(
        "[pto] in-flight protected CRYPTO data used as PTO probe bytes={d}\n",
        .{crypto_payload.len},
    );

    var handshake_rtt = try quicz.QuicConnection.init(allocator, .client, .{ .initial_rtt_ms = 100 });
    defer handshake_rtt.deinit();
    _ = try handshake_rtt.recordPacketSentInSpace(.handshake, 0, 100);
    try handshake_rtt.receiveAckInSpace(.handshake, 100, .{
        .largest_acknowledged = 0,
        .ack_delay = 1,
        .first_ack_range = 0,
    });
    _ = try handshake_rtt.recordPacketSentInSpace(.handshake, 100, 100);
    try handshake_rtt.receiveAckInSpace(.handshake, 220, .{
        .largest_acknowledged = 1,
        .ack_delay = 1,
        .first_ack_range = 0,
    });
    if (handshake_rtt.smoothedRttMillis(.handshake) != 102) return error.PtoRecoveryExampleFailed;

    std.debug.print(
        "[pto] handshake ACK delay ignored for RTT smoothed={d}\n",
        .{handshake_rtt.smoothedRttMillis(.handshake)},
    );

    var shared_rtt = try quicz.QuicConnection.init(allocator, .server, .{ .initial_rtt_ms = 100 });
    defer shared_rtt.deinit();
    try shared_rtt.validatePeerAddress();

    _ = try shared_rtt.recordPacketSentInSpace(.initial, 0, 100);
    _ = try shared_rtt.recordPacketSentInSpace(.handshake, 10, 100);
    try shared_rtt.receiveAckInSpace(.initial, 50, .{
        .largest_acknowledged = 0,
        .ack_delay = 5,
        .first_ack_range = 0,
    });
    const shared_handshake_deadline = shared_rtt.ptoDeadlineMillis(.handshake) orelse return error.PtoRecoveryExampleFailed;
    if (shared_rtt.smoothedRttMillis(.handshake) != 50) return error.PtoRecoveryExampleFailed;
    if (shared_rtt.smoothedRttMillis(.application) != 50) return error.PtoRecoveryExampleFailed;
    if (shared_handshake_deadline != 160) return error.PtoRecoveryExampleFailed;

    std.debug.print(
        "[pto] RTT shared across spaces initial_smoothed={d} handshake_deadline={d} application_smoothed={d}\n",
        .{
            shared_rtt.smoothedRttMillis(.initial),
            shared_handshake_deadline,
            shared_rtt.smoothedRttMillis(.application),
        },
    );

    var spaces = try quicz.QuicConnection.init(allocator, .server, .{ .initial_rtt_ms = 100 });
    defer spaces.deinit();
    try spaces.validatePeerAddress();

    _ = try spaces.recordPacketSentInSpace(.initial, 10, 100);
    _ = try spaces.recordPacketSentInSpace(.handshake, 20, 100);

    const initial_deadline = spaces.ptoDeadlineMillis(.initial) orelse return error.PtoRecoveryExampleFailed;
    const handshake_deadline = spaces.ptoDeadlineMillis(.handshake) orelse return error.PtoRecoveryExampleFailed;
    if (initial_deadline != 310) return error.PtoRecoveryExampleFailed;
    if (handshake_deadline != 320) return error.PtoRecoveryExampleFailed;
    const spaces_timer = spaces.lossDetectionTimerDeadlineMillis() orelse return error.PtoRecoveryExampleFailed;
    if (spaces_timer.space != .initial) return error.PtoRecoveryExampleFailed;
    if (spaces_timer.kind != .pto) return error.PtoRecoveryExampleFailed;
    if (spaces_timer.deadline_millis != initial_deadline) return error.PtoRecoveryExampleFailed;

    const initial_serviced = (try spaces.serviceLossDetectionTimer(initial_deadline)) orelse return error.PtoRecoveryExampleFailed;
    if (initial_serviced.space != .initial) return error.PtoRecoveryExampleFailed;
    if (initial_serviced.kind != .pto) return error.PtoRecoveryExampleFailed;
    if (spaces.ptoDeadlineMillis(.handshake) != handshake_deadline) return error.PtoRecoveryExampleFailed;

    const initial_payload = (try spaces.pollTxInSpace(.initial, initial_deadline + 1, &out_buf)) orelse return error.PtoRecoveryExampleFailed;
    var initial_decoded = try quicz.frame.decodeFrameSlice(initial_payload, allocator);
    defer quicz.frame.deinitFrame(&initial_decoded.frame, allocator);
    switch (initial_decoded.frame) {
        .ping => {},
        else => return error.PtoRecoveryExampleFailed,
    }

    const handshake_payload = (try spaces.pollTxInSpace(.handshake, initial_deadline + 1, &out_buf)) orelse return error.PtoRecoveryExampleFailed;
    var handshake_decoded = try quicz.frame.decodeFrameSlice(handshake_payload, allocator);
    defer quicz.frame.deinitFrame(&handshake_decoded.frame, allocator);
    switch (handshake_decoded.frame) {
        .ping => {},
        else => return error.PtoRecoveryExampleFailed,
    }

    std.debug.print(
        "[pto] spaces initial_deadline={d} handshake_deadline={d} initial_probe={d} handshake_peer_probe={d}\n",
        .{ initial_deadline, handshake_deadline, initial_payload.len, handshake_payload.len },
    );
}
