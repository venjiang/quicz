const std = @import("std");
const quicz = @import("quicz");

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var conn = try quicz.QuicConnection.init(allocator, .client, .{ .initial_rtt_ms = 100 });
    defer conn.deinit();

    _ = try conn.recordPacketSentInSpace(.application, 10, 100);
    const deadline = conn.ptoDeadlineMillis(.application) orelse return error.PtoRecoveryExampleFailed;

    try conn.checkPtoTimeouts(deadline - 1);
    if (conn.ptoDeadlineMillis(.application) != deadline) return error.PtoRecoveryExampleFailed;

    try conn.checkPtoTimeouts(deadline);
    if (conn.ptoDeadlineMillis(.application) == null) return error.PtoRecoveryExampleFailed;

    var out_buf: [32]u8 = undefined;
    const payload = (try conn.pollTx(deadline + 1, &out_buf)) orelse return error.PtoRecoveryExampleFailed;
    var decoded = try quicz.frame.decodeFrameSlice(payload, allocator);
    defer quicz.frame.deinitFrame(&decoded.frame, allocator);

    switch (decoded.frame) {
        .ping => {},
        else => return error.PtoRecoveryExampleFailed,
    }

    std.debug.print(
        "[pto] deadline={d} queued and emitted PTO PING bytes={d}\n",
        .{ deadline, payload.len },
    );

    var stream_probe = try quicz.QuicConnection.init(allocator, .client, .{ .initial_rtt_ms = 100 });
    defer stream_probe.deinit();
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

    var spaces = try quicz.QuicConnection.init(allocator, .server, .{ .initial_rtt_ms = 100 });
    defer spaces.deinit();
    try spaces.validatePeerAddress();

    _ = try spaces.recordPacketSentInSpace(.initial, 10, 100);
    _ = try spaces.recordPacketSentInSpace(.handshake, 20, 100);

    try spaces.checkPtoTimeouts(335);
    const initial_payload = (try spaces.pollTxInSpace(.initial, 336, &out_buf)) orelse return error.PtoRecoveryExampleFailed;
    var initial_decoded = try quicz.frame.decodeFrameSlice(initial_payload, allocator);
    defer quicz.frame.deinitFrame(&initial_decoded.frame, allocator);
    switch (initial_decoded.frame) {
        .ping => {},
        else => return error.PtoRecoveryExampleFailed,
    }

    try spaces.checkPtoTimeouts(345);
    const handshake_payload = (try spaces.pollTxInSpace(.handshake, 346, &out_buf)) orelse return error.PtoRecoveryExampleFailed;
    var handshake_decoded = try quicz.frame.decodeFrameSlice(handshake_payload, allocator);
    defer quicz.frame.deinitFrame(&handshake_decoded.frame, allocator);
    switch (handshake_decoded.frame) {
        .ping => {},
        else => return error.PtoRecoveryExampleFailed,
    }

    std.debug.print(
        "[pto] spaces initial_probe={d} handshake_probe={d}\n",
        .{ initial_payload.len, handshake_payload.len },
    );
}
