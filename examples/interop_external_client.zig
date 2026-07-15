//! Client-only QUIC interoperability echo against an independent server.
//!
//! Usage: quicz-interop-external-client <server_ip> <server_port> <ca_pem> [server_name]
//! `ca_pem` must be an absolute path. The client always verifies the server
//! certificate and requires the `hq-interop` ALPN selected by the peer. After
//! the TLS handshake, it sends FIN-terminated `hello` and `world` on separate
//! bidirectional streams and requires both matching echoes.

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
    if (args.next() != null) return error.InvalidArgs;
    if (!std.Io.Dir.path.isAbsolute(ca_pem)) return error.CaPathMustBeAbsolute;

    const server_address = try std.Io.net.IpAddress.parseIp4(server_ip, server_port);
    var local_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var socket = try local_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);

    var original_dcid: [8]u8 = undefined;
    quicz.tls13.secureRandomBytes(&original_dcid);
    var client_scid: [8]u8 = undefined;
    quicz.tls13.secureRandomBytes(&client_scid);

    const now = std.Io.Clock.real.now(io);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(allocator, io, now, ca_pem);

    const alpn = [_][]const u8{"hq-interop"};
    var transport = try quicz.Tls13ClientTransport.init(
        allocator,
        .{
            .initial_max_data = 8192,
            .initial_max_stream_data = 2048,
            .initial_max_streams_bidi = 8,
            .max_datagram_size = 8192,
        },
        .{
            .alpn = &alpn,
            .server_name = server_name,
            .skip_cert_verify = false,
            .now_sec = now.toSeconds(),
            .ca_bundle = &ca_bundle,
        },
        original_dcid,
        client_scid,
    );
    defer transport.deinit();
    var scratch: [8192]u8 = undefined;
    var receive_buffer: [8192]u8 = undefined;

    const client_initial = try transport.begin(nowMillis(io), &scratch);
    defer allocator.free(client_initial);
    try socket.send(io, &server_address, client_initial);

    var sent_finished = false;
    var datagrams_received: usize = 0;
    while (datagrams_received < 8 and !transport.handshakeConfirmed()) : (datagrams_received += 1) {
        const received = try socket.receiveTimeout(io, &receive_buffer, recvTimeout());
        const progress = try transport.receive(nowMillis(io), &scratch, received.data);
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

    if (!sent_finished or !transport.handshakeConfirmed()) return error.HandshakeNotConfirmed;

    // The independent peer must parse both protected 1-RTT STREAMs and finish
    // each matching response. This is intentionally not a local-only contract.
    var stream_ids: [echo_payloads.len]u64 = undefined;
    for (echo_payloads, 0..) |payload, index| {
        stream_ids[index] = try transport.openStream();
        try transport.sendStream(stream_ids[index], payload, true);
    }
    var sent_application_datagrams: usize = 0;
    while (sent_application_datagrams < 8) : (sent_application_datagrams += 1) {
        const datagram = (try transport.pollApplicationDatagram(nowMillis(io))) orelse break;
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
        const next_recovery_deadline = if (transport.lossDetectionTimerDeadlineMillis()) |deadline|
            deadline.deadline_millis
        else
            null;
        const received = socket.receiveTimeout(io, &receive_buffer, recvTimeoutForDeadline(io, next_recovery_deadline)) catch |err| switch (err) {
            error.Timeout => {
                const serviced = (try transport.serviceLossDetectionTimer(nowMillis(io))) orelse continue;
                recovery_timer_services += 1;
                if (serviced.kind == .pto) pto_recovered = true;

                var retransmission_count: usize = 0;
                while (retransmission_count < 4) : (retransmission_count += 1) {
                    const retransmission = (try transport.pollApplicationDatagram(nowMillis(io))) orelse break;
                    defer allocator.free(retransmission);
                    try socket.send(io, &server_address, retransmission);
                }
                continue;
            },
            else => return err,
        };
        const progress = try transport.receive(nowMillis(io), &scratch, received.data);
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
    if (!std.mem.allEqual(bool, &got_echo, true)) return error.MissingStreamEcho;
    if (!std.mem.allEqual(bool, &got_echo_fin, true)) return error.MissingStreamFin;
    std.debug.print("external_handshake_done=true certificate_verified=true alpn=hq-interop echo_streams=2 echo_bytes={d} pto_recovered={}\n", .{ echo_total_bytes, pto_recovered });
}
