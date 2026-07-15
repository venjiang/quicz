//! Client-only QUIC interoperability echo against an independent server.
//!
//! Usage: quicz-interop-external-client <server_ip> <server_port> <ca_pem> [server_name] [version-negotiation]
//! `ca_pem` must be an absolute path. The client always verifies the server
//! certificate and requires the `hq-interop` ALPN selected by the peer. After
//! the TLS handshake, it sends FIN-terminated `hello` and `world` on separate
//! bidirectional streams and requires both matching echoes. The optional
//! `version-negotiation` mode first offers v2, requires a v1-only peer's
//! Version Negotiation packet, then starts a fresh v1 connection attempt.

const std = @import("std");
const quicz = @import("quicz");

const echo_payloads = [_][]const u8{ "hello", "world" };
const echo_total_bytes: usize = 10;

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
    const server_ip = args.next() orelse return error.MissingArgs;
    const server_port = try std.fmt.parseInt(u16, args.next() orelse return error.MissingArgs, 10);
    const ca_pem = args.next() orelse return error.MissingArgs;
    const server_name = args.next() orelse "localhost";
    const require_version_negotiation = if (args.next()) |mode|
        std.mem.eql(u8, mode, "version-negotiation")
    else
        false;
    if (args.next() != null) return error.InvalidArgs;
    if (!std.Io.Dir.path.isAbsolute(ca_pem)) return error.CaPathMustBeAbsolute;

    const server_address = try std.Io.net.IpAddress.parseIp4(server_ip, server_port);
    var local_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var socket = try local_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    const client_path = quicz.endpoint.Udp4Tuple{
        .local = quicz.endpoint.Udp4Address.init(local_address.ip4.bytes, local_address.ip4.port),
        .remote = quicz.endpoint.Udp4Address.init(server_address.ip4.bytes, server_address.ip4.port),
    };
    const client_handle: u64 = 1;

    var original_dcid: [8]u8 = undefined;
    quicz.tls13.secureRandomBytes(&original_dcid);
    var client_scid: [8]u8 = undefined;
    quicz.tls13.secureRandomBytes(&client_scid);

    const now = std.Io.Clock.real.now(io);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(allocator, io, now, ca_pem);

    const alpn = [_][]const u8{"hq-interop"};
    const available_versions = [_]quicz.packet.Version{ .v2, .v1 };
    const tls_config = quicz.tls13.TlsConfig{
        .alpn = &alpn,
        .server_name = server_name,
        .skip_cert_verify = false,
        .now_sec = now.toSeconds(),
        .ca_bundle = &ca_bundle,
    };
    const initial_connection_config: quicz.Config = .{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
        .max_datagram_size = 8192,
        .chosen_version = if (require_version_negotiation) .v2 else .v1,
        .available_versions = if (require_version_negotiation) &available_versions else &[_]quicz.packet.Version{.v1},
    };
    var client_endpoint = try quicz.Tls13ClientEndpoint.init(
        allocator,
        client_handle,
        client_path,
        .{ .active_migration_disabled = true },
        initial_connection_config,
        tls_config,
        original_dcid,
        client_scid,
    );
    defer client_endpoint.deinit();
    var scratch: [8192]u8 = undefined;
    var receive_buffer: [8192]u8 = undefined;

    const client_initial = try client_endpoint.begin(nowMillis(io), &scratch);
    defer allocator.free(client_initial);
    try socket.send(io, &server_address, client_initial);

    var sent_finished = false;
    var version_negotiated = false;
    var datagrams_received: usize = 0;
    while (datagrams_received < 8 and !client_endpoint.handshakeConfirmed()) : (datagrams_received += 1) {
        const received = try socket.receiveTimeout(io, &receive_buffer, recvTimeout());
        const received_result = try client_endpoint.receive(nowMillis(io), &scratch, received.data);
        try require(received_result.route.connection_id == client_handle);
        const progress = received_result.transport;
        if (progress.version_negotiation_selected_version) |selected_version| {
            if (!require_version_negotiation or selected_version != .v1 or version_negotiated) return error.UnexpectedVersionNegotiation;
            const followup_config = try client_endpoint.versionNegotiationFollowupConfig();
            const followup_endpoint = blk: {
                var candidate = try quicz.Tls13ClientEndpoint.init(
                    allocator,
                    client_handle,
                    client_path,
                    .{ .active_migration_disabled = true },
                    followup_config,
                    tls_config,
                    new_dcid: {
                        var dcid: [8]u8 = undefined;
                        quicz.tls13.secureRandomBytes(&dcid);
                        break :new_dcid dcid;
                    },
                    new_scid: {
                        var scid: [8]u8 = undefined;
                        quicz.tls13.secureRandomBytes(&scid);
                        break :new_scid scid;
                    },
                );
                errdefer candidate.deinit();
                const followup_initial = try candidate.begin(nowMillis(io), &scratch);
                defer allocator.free(followup_initial);
                try socket.send(io, &server_address, followup_initial);
                break :blk candidate;
            };
            client_endpoint.deinit();
            client_endpoint = followup_endpoint;
            version_negotiated = true;
            continue;
        }
        if (progress.outbound_initial) |retry_initial| {
            defer allocator.free(retry_initial);
            try socket.send(io, &server_address, retry_initial);
            continue;
        }
        if (progress.outbound_handshake) |client_finished| {
            defer allocator.free(client_finished);
            try socket.send(io, &server_address, client_finished);
            sent_finished = true;
        }
    }

    if (require_version_negotiation and !version_negotiated) return error.MissingVersionNegotiation;
    if (!sent_finished or !client_endpoint.handshakeConfirmed()) return error.HandshakeNotConfirmed;

    // The independent peer must parse both protected 1-RTT STREAMs and finish
    // each matching response. This is intentionally not a local-only contract.
    var stream_ids: [echo_payloads.len]u64 = undefined;
    for (echo_payloads, 0..) |payload, index| {
        stream_ids[index] = try client_endpoint.openStream();
        try client_endpoint.sendStream(stream_ids[index], payload, true);
    }
    var sent_application_datagrams: usize = 0;
    while (sent_application_datagrams < 8) : (sent_application_datagrams += 1) {
        const datagram = (try client_endpoint.pollApplicationDatagram(nowMillis(io))) orelse break;
        defer allocator.free(datagram);
        try socket.send(io, &server_address, datagram);
    }

    var stream_buffer: [128]u8 = undefined;
    var received_application_datagrams: usize = 0;
    var recovery_timer_services: usize = 0;
    var got_echo: [echo_payloads.len]bool = .{ false, false };
    var got_echo_fin: [echo_payloads.len]bool = .{ false, false };
    var pto_recovered = false;
    while (received_application_datagrams < 16 and recovery_timer_services < 4) {
        const next_deadline = if (client_endpoint.nextDeadline()) |deadline|
            deadline.deadlineMillis()
        else
            null;
        const received = socket.receiveTimeout(io, &receive_buffer, recvTimeoutForDeadline(io, next_deadline)) catch |err| switch (err) {
            error.Timeout => {
                const serviced = (try client_endpoint.serviceDueDeadline(nowMillis(io))) orelse continue;
                switch (serviced) {
                    .recovery => |recovery| {
                        recovery_timer_services += 1;
                        if (recovery.kind == .pto) pto_recovered = true;

                        var retransmission_count: usize = 0;
                        while (retransmission_count < 4) : (retransmission_count += 1) {
                            const retransmission = (try client_endpoint.pollApplicationDatagram(nowMillis(io))) orelse break;
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
        const received_result = try client_endpoint.receive(nowMillis(io), &scratch, received.data);
        try require(received_result.route.connection_id == client_handle);
        const progress = received_result.transport;
        if (progress.outbound_handshake) |client_finished| {
            defer allocator.free(client_finished);
            try socket.send(io, &server_address, client_finished);
        }
        // Server Initial/Handshake retransmissions can arrive while the
        // application STREAM is lost. They do not acknowledge 1-RTT data and
        // must not consume the bounded application receive budget before PTO.
        if (!progress.application_processed) continue;
        received_application_datagrams += 1;
        inline for (stream_ids, echo_payloads, 0..) |stream_id, payload, index| {
            if (try client_endpoint.recvStream(stream_id, &stream_buffer)) |echoed_len| {
                try require(std.mem.eql(u8, stream_buffer[0..echoed_len], payload));
                got_echo[index] = true;
            }
            if (got_echo[index] and try client_endpoint.streamFinished(stream_id)) {
                got_echo_fin[index] = true;
            }
        }
        if (std.mem.allEqual(bool, &got_echo_fin, true)) break;
    }
    if (!std.mem.allEqual(bool, &got_echo, true)) return error.MissingStreamEcho;
    if (!std.mem.allEqual(bool, &got_echo_fin, true)) return error.MissingStreamFin;
    std.debug.print("external_handshake_done=true certificate_verified=true alpn=hq-interop echo_streams=2 echo_bytes={d} pto_recovered={} version_negotiation={}\n", .{ echo_total_bytes, pto_recovered, version_negotiated });
}
