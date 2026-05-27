const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{EndpointRecoveryTimerExampleFailed};

fn require(condition: bool) ExampleError!void {
    if (!condition) return error.EndpointRecoveryTimerExampleFailed;
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var timers = quicz.EndpointLossDetectionTimers.init(allocator);
    defer timers.deinit();

    const pto_connection_id: u64 = 1001;
    const loss_connection_id: u64 = 2002;

    var pto_conn = try quicz.QuicConnection.init(allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer pto_conn.deinit();
    var loss_conn = try quicz.QuicConnection.init(allocator, .client, .{});
    defer loss_conn.deinit();

    _ = try pto_conn.recordPacketSentInSpace(.application, 10, 100);

    _ = try loss_conn.recordPacketSentInSpace(.application, 300, 100);
    _ = try loss_conn.recordPacketSentInSpace(.application, 500, 100);
    try loss_conn.receiveAckInSpace(.application, 600, .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    try timers.armFromConnection(pto_connection_id, &pto_conn);
    try timers.armFromConnection(loss_connection_id, &loss_conn);
    try require(timers.count() == 2);

    const first = timers.earliestDeadline() orelse return error.EndpointRecoveryTimerExampleFailed;
    try require(first.connection_id == pto_connection_id);
    try require(first.timer.kind == .pto);
    try require((try timers.serviceConnection(
        pto_connection_id,
        &pto_conn,
        first.timer.deadline_millis - 1,
    )) == null);
    try require(pto_conn.pending_ping_count == 0);

    const pto_serviced = (try timers.serviceConnection(
        pto_connection_id,
        &pto_conn,
        first.timer.deadline_millis,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    try require(pto_serviced.connection_id == pto_connection_id);
    try require(pto_serviced.timer.kind == .pto);
    try require(pto_conn.pending_ping_count == 1);

    try pto_conn.receiveAckInSpace(.application, pto_serviced.timer.deadline_millis + 1, .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    try timers.armFromConnection(pto_connection_id, &pto_conn);
    try require(timers.count() == 1);

    const second = timers.earliestDeadline() orelse return error.EndpointRecoveryTimerExampleFailed;
    try require(second.connection_id == loss_connection_id);
    try require(second.timer.kind == .loss_time);

    const loss_serviced = (try timers.serviceConnection(
        loss_connection_id,
        &loss_conn,
        second.timer.deadline_millis,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    try require(loss_serviced.connection_id == loss_connection_id);
    try require(loss_serviced.timer.kind == .loss_time);
    try require(loss_conn.sentPacketCount(.application) == 0);
    try require(loss_conn.bytesInFlight(.application) == 0);
    try require(timers.count() == 0);

    std.debug.print("[endpoint-timers] first_connection={} first_kind={s} first_deadline={} second_connection={} second_kind={s} second_deadline={} pto_ping={} loss_remaining={} timers_remaining={}\n", .{
        first.connection_id,
        @tagName(first.timer.kind),
        first.timer.deadline_millis,
        second.connection_id,
        @tagName(second.timer.kind),
        second.timer.deadline_millis,
        pto_conn.pending_ping_count,
        loss_conn.sentPacketCount(.application),
        timers.count(),
    });
}
