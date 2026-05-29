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
    const closing_connection_id: u64 = 2502;
    const pto_cid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const loss_cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const closing_cid = [_]u8{ 0x25, 0x02, 0x25, 0x02 };
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

    var closing_conn = try quicz.QuicConnection.init(allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer closing_conn.deinit();
    try endpoint_lifecycle.registerConnectionId(closing_connection_id, &closing_cid, path, .{
        .sequence_number = 2,
    });
    _ = try closing_conn.recordPacketSentInSpace(.application, 42, 100);
    try endpoint_lifecycle.armRecoveryTimerFromConnection(closing_connection_id, &closing_conn);
    try require(endpoint_lifecycle.recoveryTimerCount() == 1);
    try closing_conn.closeConnection(0, @intFromEnum(quicz.frame.FrameType.stream), "done");
    try endpoint_lifecycle.armRecoveryTimerFromConnection(closing_connection_id, &closing_conn);
    const closing_disarmed = endpoint_lifecycle.recoveryTimerCount() == 0 and closing_conn.lossDetectionTimerDeadlineMillis() == null;
    try require(closing_disarmed);
    const closing_retired = endpoint_lifecycle.retireConnection(closing_connection_id);
    try require(closing_retired.routes_retired == 1);
    try require(!closing_retired.recovery_timer_disarmed);
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
    try protected_client.installHandshakeTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });
    try protected_server.installHandshakeTrafficSecrets(.{
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

    try protected_server.sendCryptoInSpace(.handshake, "caller handshake");
    const caller_handshake = (try protected_server_lifecycle.pollProtectedLongCryptoDatagramInSpace(
        protected_server_id,
        &protected_server,
        .handshake,
        12,
        &client_dcid,
        &server_dcid,
        &[_]u8{},
        secrets.server,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(caller_handshake);
    try require(protected_server_lifecycle.recoveryTimerCount() == 1);

    const caller_handshake_route = try protected_client_lifecycle.routeDatagram(client_receive_path, caller_handshake);
    try require(caller_handshake_route.connection_id == protected_client_id);
    try protected_client_lifecycle.processProtectedLongDatagramInSpace(
        caller_handshake_route.connection_id,
        &protected_client,
        .handshake,
        13,
        secrets.server,
        caller_handshake,
    );
    try require(protected_client.pendingAckLargest(.handshake) == 0);

    const caller_handshake_ack = (try protected_client_lifecycle.pollProtectedLongDatagram(
        protected_client_id,
        &protected_client,
        14,
        &server_dcid,
        &client_dcid,
        &[_]u8{},
        .{ .handshake = secrets.client },
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(caller_handshake_ack);
    try require(protected_client_lifecycle.recoveryTimerCount() == 0);

    const caller_handshake_ack_route = try protected_server_lifecycle.routeDatagram(server_receive_path, caller_handshake_ack);
    try require(caller_handshake_ack_route.connection_id == protected_server_id);
    try protected_server_lifecycle.processProtectedLongDatagramInSpace(
        caller_handshake_ack_route.connection_id,
        &protected_server,
        .handshake,
        15,
        secrets.client,
        caller_handshake_ack,
    );
    try require(protected_server.bytesInFlight(.handshake) == 0);
    try require(protected_server_lifecycle.recoveryTimerCount() == 0);

    try protected_server.sendCryptoInSpace(.handshake, "installed handshake");
    const installed_handshake = (try protected_server_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        protected_server_id,
        &protected_server,
        16,
        &client_dcid,
        &server_dcid,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(installed_handshake);
    try require(protected_server_lifecycle.recoveryTimerCount() == 1);

    const installed_handshake_route = try protected_client_lifecycle.routeDatagram(client_receive_path, installed_handshake);
    try require(installed_handshake_route.connection_id == protected_client_id);
    try protected_client_lifecycle.processProtectedHandshakeDatagramWithInstalledKeys(
        installed_handshake_route.connection_id,
        &protected_client,
        17,
        installed_handshake,
    );
    try require(protected_client.pendingAckLargest(.handshake) == 1);

    const installed_handshake_ack = (try protected_client_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        protected_client_id,
        &protected_client,
        18,
        &server_dcid,
        &client_dcid,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(installed_handshake_ack);
    try require(protected_client_lifecycle.recoveryTimerCount() == 0);

    const installed_handshake_ack_route = try protected_server_lifecycle.routeDatagram(server_receive_path, installed_handshake_ack);
    try require(installed_handshake_ack_route.connection_id == protected_server_id);
    try protected_server_lifecycle.processProtectedHandshakeDatagramWithInstalledKeys(
        installed_handshake_ack_route.connection_id,
        &protected_server,
        19,
        installed_handshake_ack,
    );
    try require(protected_server.bytesInFlight(.handshake) == 0);
    try require(protected_server_lifecycle.recoveryTimerCount() == 0);

    const caller_early_stream_id = try protected_client.openStream();
    try protected_client.sendOnStream(caller_early_stream_id, "caller early", true);
    const caller_zero = (try protected_client_lifecycle.pollProtectedZeroRttDatagram(
        protected_client_id,
        &protected_client,
        20,
        &server_dcid,
        &client_dcid,
        secrets.client,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(caller_zero);
    try require(protected_client_lifecycle.recoveryTimerCount() == 1);

    const caller_zero_route = try protected_server_lifecycle.routeDatagram(server_receive_path, caller_zero);
    try require(caller_zero_route.connection_id == protected_server_id);
    try protected_server_lifecycle.processProtectedZeroRttDatagram(
        caller_zero_route.connection_id,
        &protected_server,
        21,
        secrets.client,
        caller_zero,
    );
    try require(protected_server.pendingAckLargest(.application) == 0);
    try require(protected_server_lifecycle.recoveryTimerCount() == 0);

    const caller_zero_ack = (try protected_server_lifecycle.pollProtectedShortDatagram(
        protected_server_id,
        &protected_server,
        22,
        &client_dcid,
        secrets.server,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(caller_zero_ack);
    try require(protected_server_lifecycle.recoveryTimerCount() == 0);

    const caller_zero_ack_route = try protected_client_lifecycle.routeDatagram(client_receive_path, caller_zero_ack);
    try require(caller_zero_ack_route.connection_id == protected_client_id);
    try protected_client_lifecycle.processProtectedShortDatagram(
        caller_zero_ack_route.connection_id,
        &protected_client,
        23,
        secrets.server,
        client_dcid.len,
        caller_zero_ack,
    );
    try require(protected_client.bytesInFlight(.application) == 0);
    try require(protected_client_lifecycle.recoveryTimerCount() == 0);

    try protected_client.installZeroRttTrafficSecrets(.{
        .local = secrets.client.secret,
    });
    try protected_server.installZeroRttTrafficSecrets(.{
        .peer = secrets.client.secret,
    });
    try protected_server.acceptZeroRtt();
    const early_stream_id = try protected_client.openStream();
    try protected_client.sendOnStream(early_stream_id, "installed early", true);
    const installed_zero = (try protected_client_lifecycle.pollProtectedZeroRttDatagramWithInstalledKeys(
        protected_client_id,
        &protected_client,
        24,
        &server_dcid,
        &client_dcid,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(installed_zero);
    try require(protected_client_lifecycle.recoveryTimerCount() == 1);

    const installed_zero_route = try protected_server_lifecycle.routeDatagram(server_receive_path, installed_zero);
    try require(installed_zero_route.connection_id == protected_server_id);
    try protected_server_lifecycle.processProtectedZeroRttDatagramWithInstalledKeys(
        installed_zero_route.connection_id,
        &protected_server,
        25,
        installed_zero,
    );
    try require(protected_server.pendingAckLargest(.application) == 1);
    try require(protected_server_lifecycle.recoveryTimerCount() == 0);

    try protected_client.sendPing();
    const caller_short = (try protected_client_lifecycle.pollProtectedShortDatagram(
        protected_client_id,
        &protected_client,
        26,
        &server_dcid,
        secrets.client,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(caller_short);
    try require(protected_client_lifecycle.recoveryTimerCount() == 1);

    const caller_short_route = try protected_server_lifecycle.routeDatagram(server_receive_path, caller_short);
    try require(caller_short_route.connection_id == protected_server_id);
    try protected_server_lifecycle.processProtectedShortDatagram(
        caller_short_route.connection_id,
        &protected_server,
        27,
        secrets.client,
        server_dcid.len,
        caller_short,
    );
    try require(protected_server.pendingAckLargest(.application) == 2);

    const caller_short_ack = (try protected_server_lifecycle.pollProtectedShortDatagram(
        protected_server_id,
        &protected_server,
        28,
        &client_dcid,
        secrets.server,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(caller_short_ack);
    try require(protected_server_lifecycle.recoveryTimerCount() == 0);

    const caller_short_ack_route = try protected_client_lifecycle.routeDatagram(client_receive_path, caller_short_ack);
    try require(caller_short_ack_route.connection_id == protected_client_id);
    try protected_client_lifecycle.processProtectedShortDatagram(
        caller_short_ack_route.connection_id,
        &protected_client,
        29,
        secrets.server,
        client_dcid.len,
        caller_short_ack,
    );
    try require(protected_client.bytesInFlight(.application) == 0);
    try require(protected_client_lifecycle.recoveryTimerCount() == 0);

    try protected_client.installOneRttTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });
    try protected_server.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });

    try protected_client.sendPing();
    const ping = (try protected_client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        protected_client_id,
        &protected_client,
        30,
        &server_dcid,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(ping);
    try require(protected_client_lifecycle.recoveryTimerCount() == 1);

    const ping_route = try protected_server_lifecycle.routeDatagram(server_receive_path, ping);
    try require(ping_route.connection_id == protected_server_id);
    try protected_server_lifecycle.processProtectedShortDatagramWithInstalledKeys(
        ping_route.connection_id,
        &protected_server,
        31,
        server_dcid.len,
        ping,
    );
    try require(protected_server.pendingAckLargest(.application) == 3);

    const ack = (try protected_server_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        protected_server_id,
        &protected_server,
        32,
        &client_dcid,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(ack);
    try require(protected_server_lifecycle.recoveryTimerCount() == 0);

    const ack_route = try protected_client_lifecycle.routeDatagram(client_receive_path, ack);
    try require(ack_route.connection_id == protected_client_id);
    try protected_client_lifecycle.processProtectedShortDatagramWithInstalledKeys(
        ack_route.connection_id,
        &protected_client,
        33,
        client_dcid.len,
        ack,
    );
    try require(protected_client.bytesInFlight(.application) == 0);

    const explicit_next_client_keys = quicz.protection.nextAes128PacketProtectionKeys(secrets.client);
    const explicit_next_server_keys = quicz.protection.nextAes128PacketProtectionKeys(secrets.server);
    try protected_client.sendPing();
    const explicit_key_phase_ping = (try protected_client_lifecycle.pollProtectedShortDatagramWithKeyPhase(
        protected_client_id,
        &protected_client,
        34,
        &server_dcid,
        explicit_next_client_keys,
        true,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(explicit_key_phase_ping);
    try require(protected_client_lifecycle.recoveryTimerCount() == 1);

    const explicit_key_phase_ping_route = try protected_server_lifecycle.routeDatagram(server_receive_path, explicit_key_phase_ping);
    try require(explicit_key_phase_ping_route.connection_id == protected_server_id);
    try protected_server_lifecycle.processProtectedShortDatagramWithKeyUpdate(
        explicit_key_phase_ping_route.connection_id,
        &protected_server,
        35,
        .{
            .current = secrets.client,
            .next = explicit_next_client_keys,
            .current_key_phase = false,
        },
        server_dcid.len,
        explicit_key_phase_ping,
    );
    try require(protected_server.pendingAckLargest(.application) == 4);

    const explicit_key_phase_ack = (try protected_server_lifecycle.pollProtectedShortDatagramWithKeyPhase(
        protected_server_id,
        &protected_server,
        36,
        &client_dcid,
        secrets.server,
        false,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(explicit_key_phase_ack);
    try require(protected_server_lifecycle.recoveryTimerCount() == 0);

    const explicit_key_phase_ack_route = try protected_client_lifecycle.routeDatagram(client_receive_path, explicit_key_phase_ack);
    try require(explicit_key_phase_ack_route.connection_id == protected_client_id);
    try protected_client_lifecycle.processProtectedShortDatagramWithKeyUpdate(
        explicit_key_phase_ack_route.connection_id,
        &protected_client,
        37,
        .{
            .current = secrets.server,
            .next = explicit_next_server_keys,
            .current_key_phase = false,
        },
        client_dcid.len,
        explicit_key_phase_ack,
    );
    try require(protected_client.bytesInFlight(.application) == 0);

    var key_phase_client_send_state = quicz.protection.Aes128KeyPhaseState.init(secrets.client, false);
    var key_phase_server_recv_state = quicz.protection.Aes128KeyPhaseState.init(secrets.client, false);
    var key_phase_server_send_state = quicz.protection.Aes128KeyPhaseState.init(secrets.server, false);
    var key_phase_client_recv_state = quicz.protection.Aes128KeyPhaseState.init(secrets.server, false);
    key_phase_client_send_state.initiateKeyUpdate();

    try protected_client.sendPing();
    const key_phase_ping = (try protected_client_lifecycle.pollProtectedShortDatagramWithKeyPhaseState(
        protected_client_id,
        &protected_client,
        38,
        &server_dcid,
        &key_phase_client_send_state,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(key_phase_ping);
    try require(protected_client_lifecycle.recoveryTimerCount() == 1);

    const key_phase_ping_route = try protected_server_lifecycle.routeDatagram(server_receive_path, key_phase_ping);
    try require(key_phase_ping_route.connection_id == protected_server_id);
    try protected_server_lifecycle.processProtectedShortDatagramWithKeyPhaseState(
        key_phase_ping_route.connection_id,
        &protected_server,
        39,
        &key_phase_server_recv_state,
        server_dcid.len,
        key_phase_ping,
    );
    try require(key_phase_server_recv_state.currentKeyPhase());
    try require(protected_server.pendingAckLargest(.application) == 5);

    const key_phase_ack = (try protected_server_lifecycle.pollProtectedShortDatagramWithKeyPhaseState(
        protected_server_id,
        &protected_server,
        40,
        &client_dcid,
        &key_phase_server_send_state,
    )) orelse return error.EndpointRecoveryTimerExampleFailed;
    defer allocator.free(key_phase_ack);
    try require(protected_server_lifecycle.recoveryTimerCount() == 0);

    const key_phase_ack_route = try protected_client_lifecycle.routeDatagram(client_receive_path, key_phase_ack);
    try require(key_phase_ack_route.connection_id == protected_client_id);
    try protected_client_lifecycle.processProtectedShortDatagramWithKeyPhaseState(
        key_phase_ack_route.connection_id,
        &protected_client,
        41,
        &key_phase_client_recv_state,
        client_dcid.len,
        key_phase_ack,
    );
    try require(!key_phase_client_recv_state.currentKeyPhase());
    try require(protected_client.bytesInFlight(.application) == 0);
    const protected_timers_remaining = protected_client_lifecycle.recoveryTimerCount() + protected_server_lifecycle.recoveryTimerCount();

    std.debug.print("[endpoint-timers] first_connection={} first_kind={s} first_deadline={} second_connection={} second_kind={s} second_deadline={} pto_ping={} loss_remaining={} close_disarmed={} timers_remaining={} routes_remaining={} protected_bytes={} protected_timers={}\n", .{
        first.connection_id,
        @tagName(first.timer.kind),
        first.timer.deadline_millis,
        second.connection_id,
        @tagName(second.timer.kind),
        second.timer.deadline_millis,
        pto_conn.pending_ping_count,
        loss_conn.sentPacketCount(.application),
        closing_disarmed,
        endpoint_lifecycle.recoveryTimerCount(),
        endpoint_lifecycle.routeCount(),
        long_initial.len + long_ack.len + caller_handshake.len + caller_handshake_ack.len + installed_handshake.len + installed_handshake_ack.len + caller_zero.len + caller_zero_ack.len + installed_zero.len + caller_short.len + caller_short_ack.len + ping.len + ack.len + explicit_key_phase_ping.len + explicit_key_phase_ack.len + key_phase_ping.len + key_phase_ack.len,
        protected_timers_remaining,
    });
}
