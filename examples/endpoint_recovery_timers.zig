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

    var protected_client_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer protected_client_lifecycle.deinit();
    var protected_server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer protected_server_lifecycle.deinit();

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const server_dcid = [_]u8{ 0x91, 0x92, 0x93, 0x94 };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);
    const client_addr = quicz.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 50_000);
    const server_addr = quicz.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433);
    const server_receive_path = quicz.endpoint.Udp4Tuple{
        .local = server_addr,
        .remote = client_addr,
    };
    const client_receive_path = quicz.endpoint.Udp4Tuple{
        .local = client_addr,
        .remote = server_addr,
    };
    const protected_client_id: u64 = 3003;
    const protected_server_id: u64 = 4004;

    var protected_client = try quicz.QuicConnection.init(allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer protected_client.deinit();
    var protected_server = try quicz.QuicConnection.init(allocator, .server, .{
        .initial_rtt_ms = 100,
    });
    defer protected_server.deinit();
    try protected_server.validatePeerAddress();
    try protected_client.installOneRttTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });
    try protected_server.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });

    try protected_client_lifecycle.registerConnectionId(protected_client_id, &client_dcid, client_receive_path, .{
        .sequence_number = 0,
    });
    try protected_server_lifecycle.registerConnectionId(protected_server_id, &server_dcid, server_receive_path, .{
        .sequence_number = 0,
    });
    try protected_server_lifecycle.registerConnectionId(protected_server_id, &original_dcid, server_receive_path, .{
        .sequence_number = 1,
    });

    try protected_client.sendCryptoInSpace(.initial, "lifecycle initial");
    const long_initial = (try protected_client_lifecycle.pollProtectedLongDatagram(
        protected_client_id,
        &protected_client,
        8,
        &original_dcid,
        &client_dcid,
        &[_]u8{},
        .{ .initial = secrets.client },
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(long_initial);
    try require(protected_client_lifecycle.recoveryTimerCount() == 1);

    const long_initial_route = try protected_server_lifecycle.routeDatagram(server_receive_path, long_initial);
    try require(long_initial_route.connection_id == protected_server_id);
    try require(try protected_server_lifecycle.processProtectedLongDatagram(
        long_initial_route.connection_id,
        &protected_server,
        9,
        .{ .initial = secrets.client },
        long_initial,
    ) == 1);
    try require(protected_server.pendingAckLargest(.initial) == 0);

    const long_ack = (try protected_server_lifecycle.pollProtectedLongDatagram(
        protected_server_id,
        &protected_server,
        10,
        &client_dcid,
        &server_dcid,
        &[_]u8{},
        .{ .initial = secrets.server },
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(long_ack);
    try require(protected_server_lifecycle.recoveryTimerCount() == 0);

    const long_ack_route = try protected_client_lifecycle.routeDatagram(client_receive_path, long_ack);
    try require(long_ack_route.connection_id == protected_client_id);
    try require(try protected_client_lifecycle.processProtectedLongDatagram(
        long_ack_route.connection_id,
        &protected_client,
        11,
        .{ .initial = secrets.server },
        long_ack,
    ) == 1);
    try require(protected_client.bytesInFlight(.initial) == 0);
    try require(protected_client_lifecycle.recoveryTimerCount() == 0);

    try protected_client.sendPing();
    const ping = (try protected_client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        protected_client_id,
        &protected_client,
        10,
        &server_dcid,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(ping);
    try require(protected_client_lifecycle.recoveryTimerCount() == 1);

    const ping_route = try protected_server_lifecycle.routeDatagram(server_receive_path, ping);
    try require(ping_route.connection_id == protected_server_id);
    try protected_server_lifecycle.processProtectedShortDatagramWithInstalledKeys(
        ping_route.connection_id,
        &protected_server,
        11,
        server_dcid.len,
        ping,
    );
    try require(protected_server.pendingAckLargest(.application) == 0);

    const ack = (try protected_server_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        protected_server_id,
        &protected_server,
        12,
        &client_dcid,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(ack);
    try require(protected_server_lifecycle.recoveryTimerCount() == 0);

    const ack_route = try protected_client_lifecycle.routeDatagram(client_receive_path, ack);
    try require(ack_route.connection_id == protected_client_id);
    try protected_client_lifecycle.processProtectedShortDatagramWithInstalledKeys(
        ack_route.connection_id,
        &protected_client,
        13,
        client_dcid.len,
        ack,
    );
    try require(protected_client.bytesInFlight(.application) == 0);
    const protected_timers_remaining = protected_client_lifecycle.recoveryTimerCount() + protected_server_lifecycle.recoveryTimerCount();

    std.debug.print("[endpoint-timers] first_connection={} first_kind={s} first_deadline={} second_connection={} second_kind={s} second_deadline={} pto_ping={} loss_remaining={} timers_remaining={} routes_remaining={} protected_bytes={} protected_timers={}\n", .{
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
        long_initial.len + long_ack.len + ping.len + ack.len,
        protected_timers_remaining,
    });
}
