const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{IdleTimeoutExampleFailed};

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var conn = try quicz.Connection.init(allocator, .client, .{
        .max_idle_timeout_ms = 100,
    });
    defer conn.deinit();

    try conn.applyPeerTransportParameters(.{
        .max_idle_timeout = 80,
    });
    if (conn.effectiveIdleTimeoutMillis() != 80) return error.IdleTimeoutExampleFailed;

    try conn.sendPing();
    var tx: [16]u8 = undefined;
    const ping_payload = (try conn.pollTx(10, &tx)) orelse return error.IdleTimeoutExampleFailed;
    if (ping_payload.len != 1) return error.IdleTimeoutExampleFailed;

    const deadline = conn.idleTimeoutDeadlineMillis() orelse return error.IdleTimeoutExampleFailed;
    try conn.checkIdleTimeouts(deadline - 1);
    if (conn.connectionState() != .active) return error.IdleTimeoutExampleFailed;

    conn.checkIdleTimeouts(deadline) catch |err| {
        if (err != error.ConnectionClosed) return err;
    };
    if (conn.connectionState() != .closed) return error.IdleTimeoutExampleFailed;

    var lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer lifecycle.deinit();

    var endpoint_conn = try quicz.Connection.init(allocator, .client, .{
        .initial_rtt_ms = 100,
        .max_idle_timeout_ms = 40,
    });
    defer endpoint_conn.deinit();
    try endpoint_conn.confirmHandshake();

    const endpoint_connection_id: u64 = 44;
    const endpoint_cid = [_]u8{ 0x44, 0x44, 0x44, 0x44 };
    const path = quicz.endpoint.Udp4Tuple{
        .local = quicz.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = quicz.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 50_000),
    };
    try lifecycle.registerConnectionId(endpoint_connection_id, &endpoint_cid, path, .{
        .sequence_number = 0,
    });

    try endpoint_conn.sendPing();
    var endpoint_tx: [16]u8 = undefined;
    const endpoint_ping = (try endpoint_conn.pollTx(20, &endpoint_tx)) orelse return error.IdleTimeoutExampleFailed;
    if (endpoint_ping.len != 1) return error.IdleTimeoutExampleFailed;
    try lifecycle.armRecoveryTimerFromConnection(endpoint_connection_id, &endpoint_conn);
    if (lifecycle.routeCount() != 1 or lifecycle.recoveryTimerCount() != 1) return error.IdleTimeoutExampleFailed;

    const endpoint_deadline = endpoint_conn.idleTimeoutDeadlineMillis() orelse return error.IdleTimeoutExampleFailed;
    if ((try lifecycle.checkIdleTimeoutsAndRetireConnection(endpoint_connection_id, &endpoint_conn, endpoint_deadline - 1)) != null) {
        return error.IdleTimeoutExampleFailed;
    }
    if (lifecycle.routeCount() != 1 or lifecycle.recoveryTimerCount() != 1) return error.IdleTimeoutExampleFailed;

    const retired = (try lifecycle.checkIdleTimeoutsAndRetireConnection(endpoint_connection_id, &endpoint_conn, endpoint_deadline)) orelse return error.IdleTimeoutExampleFailed;
    if (retired.routes_retired != 1 or !retired.recovery_timer_disarmed) return error.IdleTimeoutExampleFailed;
    if (endpoint_conn.connectionState() != .closed) return error.IdleTimeoutExampleFailed;
    if (lifecycle.routeCount() != 0 or lifecycle.recoveryTimerCount() != 0) return error.IdleTimeoutExampleFailed;

    std.debug.print(
        "[idle] effective_timeout_ms={} deadline={} state={s} endpoint_routes_retired={} endpoint_timer_disarmed={}\n",
        .{
            conn.effectiveIdleTimeoutMillis().?,
            deadline,
            @tagName(conn.connectionState()),
            retired.routes_retired,
            retired.recovery_timer_disarmed,
        },
    );
}
