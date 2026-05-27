const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{EndpointRecoveryTimerExampleFailed};

fn require(condition: bool) ExampleError!void {
    if (!condition) return error.EndpointRecoveryTimerExampleFailed;
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var endpoint_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer endpoint_lifecycle.deinit();

    const pto_connection_id: u64 = 1001;
    const loss_connection_id: u64 = 2002;
    const pto_cid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const loss_cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const path = quicz.endpoint.Udp4Tuple{
        .local = quicz.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = quicz.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 50_000),
    };

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

    try endpoint_lifecycle.registerConnectionId(pto_connection_id, &pto_cid, path, .{
        .sequence_number = 0,
    });
    try endpoint_lifecycle.registerConnectionId(loss_connection_id, &loss_cid, path, .{
        .sequence_number = 1,
    });
    try endpoint_lifecycle.armRecoveryTimerFromConnection(pto_connection_id, &pto_conn);
    try endpoint_lifecycle.armRecoveryTimerFromConnection(loss_connection_id, &loss_conn);
    try require(endpoint_lifecycle.routeCount() == 2);
    try require(endpoint_lifecycle.recoveryTimerCount() == 2);

    const first = endpoint_lifecycle.earliestRecoveryDeadline() orelse return error.EndpointRecoveryTimerExampleFailed;
    try require(first.connection_id == pto_connection_id);
    try require(first.timer.kind == .pto);
    try require((try endpoint_lifecycle.serviceRecoveryTimer(
        pto_connection_id,
        &pto_conn,
        first.timer.deadline_millis - 1,
    )) == null);
    try require(pto_conn.pending_ping_count == 0);

    const pto_serviced = (try endpoint_lifecycle.serviceRecoveryTimer(
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
    try endpoint_lifecycle.armRecoveryTimerFromConnection(pto_connection_id, &pto_conn);
    try require(endpoint_lifecycle.recoveryTimerCount() == 1);

    const second = endpoint_lifecycle.earliestRecoveryDeadline() orelse return error.EndpointRecoveryTimerExampleFailed;
    try require(second.connection_id == loss_connection_id);
    try require(second.timer.kind == .loss_time);

    const loss_serviced = (try endpoint_lifecycle.serviceRecoveryTimer(
        loss_connection_id,
        &loss_conn,
        second.timer.deadline_millis,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    try require(loss_serviced.connection_id == loss_connection_id);
    try require(loss_serviced.timer.kind == .loss_time);
    try require(loss_conn.sentPacketCount(.application) == 0);
    try require(loss_conn.bytesInFlight(.application) == 0);
    try require(endpoint_lifecycle.recoveryTimerCount() == 0);

    const pto_retired = endpoint_lifecycle.retireConnection(pto_connection_id);
    try require(pto_retired.routes_retired == 1);
    try require(!pto_retired.recovery_timer_disarmed);
    const loss_retired = endpoint_lifecycle.retireConnection(loss_connection_id);
    try require(loss_retired.routes_retired == 1);
    try require(!loss_retired.recovery_timer_disarmed);
    try require(endpoint_lifecycle.routeCount() == 0);

    std.debug.print("[endpoint-timers] first_connection={} first_kind={s} first_deadline={} second_connection={} second_kind={s} second_deadline={} pto_ping={} loss_remaining={} timers_remaining={} routes_remaining={}\n", .{
        first.connection_id,
        @tagName(first.timer.kind),
        first.timer.deadline_millis,
        second.connection_id,
        @tagName(second.timer.kind),
        second.timer.deadline_millis,
        pto_conn.pending_ping_count,
        loss_conn.sentPacketCount(.application),
        endpoint_lifecycle.recoveryTimerCount(),
        endpoint_lifecycle.routeCount(),
    });
}
