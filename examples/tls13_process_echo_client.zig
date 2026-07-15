//! Pure-Zig TLS 1.3 QUIC client for local process interoperability.
//!
//! Usage: quicz-tls13-process-echo-client <server_host> <server_port> [connection_tag] [close|idle|loss] [none|retry]

const std = @import("std");
const quicz = @import("quicz");

const EndpointConnectionLifecycle = quicz.EndpointConnectionLifecycle;
const endpoint = quicz.endpoint;

const original_dcid_base = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const client_scid_base = [_]u8{ 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };
const echo_payloads = [_][]const u8{ "hello", "world" };
const echo_total_bytes: usize = 10;
const client_max_datagram_size: usize = 8192;

fn recvTimeout() std.Io.Timeout {
    return .{ .duration = .{
        .clock = .awake,
        .raw = std.Io.Duration.fromMilliseconds(2000),
    } };
}

fn recvTimeoutForDeadline(io: std.Io, deadline_millis: ?i64) std.Io.Timeout {
    const now_millis = std.Io.Clock.awake.now(io).toMilliseconds();
    const timeout_millis = if (deadline_millis) |deadline|
        @max(@as(i64, 0), deadline - now_millis)
    else
        2_000;
    return .{ .duration = .{
        .clock = .awake,
        .raw = std.Io.Duration.fromMilliseconds(timeout_millis),
    } };
}

fn nowMillis(io: std.Io) i64 {
    return std.Io.Clock.awake.now(io).toMilliseconds();
}

fn require(condition: bool) !void {
    if (!condition) return error.UnexpectedState;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    const server_host = args.next() orelse return error.MissingArgs;
    const server_port = try std.fmt.parseInt(u16, args.next() orelse return error.MissingArgs, 10);
    const connection_tag = if (args.next()) |raw_tag|
        try std.fmt.parseInt(u8, raw_tag, 10)
    else
        0;
    const completion_mode = args.next() orelse "close";
    const leave_idle = std.mem.eql(u8, completion_mode, "idle");
    const drop_initial_responses = std.mem.eql(u8, completion_mode, "loss");
    if (!leave_idle and !drop_initial_responses and !std.mem.eql(u8, completion_mode, "close")) return error.InvalidCompletionMode;
    const retry_mode = args.next() orelse "none";
    const expect_retry = std.mem.eql(u8, retry_mode, "retry");
    if (!expect_retry and !std.mem.eql(u8, retry_mode, "none")) return error.InvalidRetryMode;

    var original_dcid = original_dcid_base;
    original_dcid[original_dcid.len - 1] = connection_tag;
    var client_scid = client_scid_base;
    client_scid[client_scid.len - 1] = connection_tag;
    const server_address = try std.Io.net.IpAddress.parseIp4(server_host, server_port);
    var local_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var socket = try local_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    const client_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(local_address.ip4.bytes, local_address.ip4.port),
        .remote = endpoint.Udp4Address.init(server_address.ip4.bytes, server_address.ip4.port),
    };
    const client_handle: u64 = 1;
    var lifecycle = EndpointConnectionLifecycle.init(allocator);
    defer lifecycle.deinit();

    const alpn = [_][]const u8{"hq-interop"};
    var transport = try quicz.Tls13ClientTransport.init(allocator, .{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
        .max_datagram_size = client_max_datagram_size,
    }, .{
        .alpn = &alpn,
        .server_name = "localhost",
        .skip_cert_verify = true,
    }, original_dcid, client_scid);
    defer transport.deinit();
    try lifecycle.registerConnectionId(client_handle, &client_scid, client_path, .{ .active_migration_disabled = true });

    var scratch: [8192]u8 = undefined;
    var receive_buffer: [client_max_datagram_size]u8 = undefined;

    const client_initial = try transport.begin(nowMillis(io), &scratch);
    defer allocator.free(client_initial);
    try socket.send(io, &server_address, client_initial);
    try lifecycle.armRecoveryTimerFromConnection(client_handle, &transport.connection);

    var received_handshake_datagrams: usize = 0;
    var retry_received = false;
    var sent_finished = false;
    while (received_handshake_datagrams < 8 and !transport.handshakeConfirmed()) : (received_handshake_datagrams += 1) {
        const received = try socket.receiveTimeout(io, &receive_buffer, recvTimeout());
        const route = try lifecycle.routeDatagram(client_path, received.data);
        try require(route.connection_id == client_handle);
        const progress = try transport.receive(nowMillis(io), &scratch, received.data);
        try lifecycle.armRecoveryTimerFromConnection(client_handle, &transport.connection);
        if (progress.retry_received) {
            if (!expect_retry or retry_received) return error.UnexpectedRetry;
            retry_received = true;
        }
        if (progress.outbound_initial) |retry_initial| {
            defer allocator.free(retry_initial);
            try socket.send(io, &server_address, retry_initial);
        }
        if (progress.outbound_handshake) |client_finished| {
            defer allocator.free(client_finished);
            try socket.send(io, &server_address, client_finished);
            sent_finished = true;
        }
    }
    if (expect_retry != retry_received) return error.MissingRetry;
    try require(sent_finished);
    try require(transport.handshakeConfirmed());

    var stream_ids: [echo_payloads.len]u64 = undefined;
    for (echo_payloads, 0..) |payload, index| {
        stream_ids[index] = try transport.openStream();
        try transport.sendStream(stream_ids[index], payload, true);
    }
    var sent_application_packets: usize = 0;
    while (sent_application_packets < 4) : (sent_application_packets += 1) {
        const stream_packet = (try transport.pollApplicationDatagram(nowMillis(io))) orelse break;
        defer allocator.free(stream_packet);
        try socket.send(io, &server_address, stream_packet);
        try lifecycle.armRecoveryTimerFromConnection(client_handle, &transport.connection);
    }
    try require(sent_application_packets > 0);

    var stream_buffer: [128]u8 = undefined;
    var got_echo: [echo_payloads.len]bool = .{ false, false };
    var got_echo_fin: [echo_payloads.len]bool = .{ false, false };
    var dropped_responses: usize = 0;
    var received_packets: usize = 0;
    var recovery_timer_services: usize = 0;
    while (received_packets < 16 and recovery_timer_services < 4) {
        const next_deadline = if (transport.nextDeadline()) |deadline|
            deadline.deadlineMillis()
        else
            null;
        const received = socket.receiveTimeout(io, &receive_buffer, recvTimeoutForDeadline(io, next_deadline)) catch |err| switch (err) {
            error.Timeout => {
                const serviced = (try transport.serviceDueDeadline(nowMillis(io))) orelse continue;
                switch (serviced) {
                    .recovery => {
                        recovery_timer_services += 1;
                        var retransmission_count: usize = 0;
                        while (retransmission_count < 4) : (retransmission_count += 1) {
                            const retransmission = (try transport.pollApplicationDatagram(nowMillis(io))) orelse break;
                            defer allocator.free(retransmission);
                            try socket.send(io, &server_address, retransmission);
                        }
                    },
                    .idle_timeout, .close_timeout => return error.ConnectionClosed,
                    .key_discard => continue,
                }
                continue;
            },
            else => return err,
        };
        if (drop_initial_responses and dropped_responses < 4) {
            dropped_responses += 1;
            continue;
        }
        const route = try lifecycle.routeDatagram(client_path, received.data);
        try require(route.connection_id == client_handle);
        const progress = try transport.receive(nowMillis(io), &scratch, received.data);
        try lifecycle.armRecoveryTimerFromConnection(client_handle, &transport.connection);
        if (progress.outbound_handshake) |client_finished| {
            defer allocator.free(client_finished);
            try socket.send(io, &server_address, client_finished);
        }
        if (!progress.application_processed) continue;
        received_packets += 1;
        inline for (stream_ids, echo_payloads, 0..) |stream_id, payload, index| {
            if (try transport.recvStream(stream_id, &stream_buffer)) |echoed_len| {
                try require(std.mem.eql(u8, stream_buffer[0..echoed_len], payload));
                got_echo[index] = true;
            }
            if (got_echo[index] and try transport.streamFinished(stream_id)) {
                got_echo_fin[index] = true;
            }
        }
        if (std.mem.allEqual(bool, &got_echo_fin, true)) break;
    }
    try require(std.mem.allEqual(bool, &got_echo, true));
    try require(std.mem.allEqual(bool, &got_echo_fin, true));
    if (drop_initial_responses) try require(dropped_responses == 4);

    if (leave_idle) {
        std.debug.print("zig_process_client: tag={d} handshake_done=true echo_streams=2 echo_bytes={d} idle_peer=true\n", .{ connection_tag, echo_total_bytes });
        return;
    }

    try transport.connection.closeConnection(0, 0, "process echo complete");
    const close_packet = (try transport.pollApplicationDatagram(nowMillis(io))) orelse return error.UnexpectedState;
    defer allocator.free(close_packet);
    try socket.send(io, &server_address, close_packet);
    const client_close_deadline = transport.connection.closeDeadlineMillis() orelse return error.UnexpectedState;
    const client_retired = (try lifecycle.checkCloseTimeoutsAndRetireConnection(
        client_handle,
        &transport.connection,
        client_close_deadline,
    )) orelse return error.UnexpectedState;
    try require(client_retired.routes_retired > 0);
    try require(transport.connection.connectionState() == .closed);
    try require(lifecycle.routeCount() == 0);

    if (drop_initial_responses) {
        if (expect_retry) {
            std.debug.print("zig_process_client: tag={d} handshake_done=true echo_streams=2 echo_bytes={d} pto_recovered=true retry_validated=true close_cleanup=true\n", .{ connection_tag, echo_total_bytes });
        } else {
            std.debug.print("zig_process_client: tag={d} handshake_done=true echo_streams=2 echo_bytes={d} pto_recovered=true close_cleanup=true\n", .{ connection_tag, echo_total_bytes });
        }
    } else if (expect_retry) {
        std.debug.print("zig_process_client: tag={d} handshake_done=true echo_streams=2 echo_bytes={d} retry_validated=true close_cleanup=true\n", .{ connection_tag, echo_total_bytes });
    } else {
        std.debug.print("zig_process_client: tag={d} handshake_done=true echo_streams=2 echo_bytes={d} close_cleanup=true\n", .{ connection_tag, echo_total_bytes });
    }
}
