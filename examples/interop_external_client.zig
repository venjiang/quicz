//! Client-only QUIC interoperability echo against an independent server.
//!
//! Usage: quicz-interop-external-client <server_ip> <server_port> <ca_pem> [server_name]
//! `ca_pem` must be an absolute path. The client always verifies the server
//! certificate and requires the `hq-interop` ALPN selected by the peer. After
//! the TLS handshake, it sends a FIN-terminated `hello` on one bidirectional
//! stream and requires the matching echo.

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;

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

/// Some peers pad a server Initial UDP datagram to 1200 bytes after the encoded
/// long packet. This is neither a QUIC long nor short packet, so discard only
/// an all-zero tail at this UDP integration boundary.
fn isZeroOnlyDatagramPadding(datagram_tail: []const u8) bool {
    return datagram_tail.len > 0 and std.mem.allEqual(u8, datagram_tail, 0);
}

fn require(condition: bool) !void {
    if (!condition) return error.UnexpectedState;
}

fn isRetryDatagram(datagram: []const u8) bool {
    if (datagram.len < 5 or (datagram[0] & 0x80) == 0 or (datagram[0] & 0x40) == 0) return false;
    const version: quicz.packet.Version = @enumFromInt(std.mem.readInt(u32, datagram[1..5], .big));
    const type_bits: u2 = @intCast((datagram[0] >> 4) & 0x03);
    return quicz.packet.longHeaderPacketTypeFromBits(version, type_bits) == .retry;
}

fn processServerLongDatagram(
    connection: *Connection,
    backend: *Tls13Backend,
    scratch: []u8,
    initial_keys: protection.Aes128PacketProtectionKeys,
    now_millis: i64,
    datagram: []const u8,
) !usize {
    var offset: usize = 0;
    while (offset < datagram.len and (datagram[offset] & 0x80) != 0) {
        const info = try protection.peekProtectedLongPacketInfo(datagram[offset..]);
        const packet_end = std.math.add(usize, offset, info.len) catch return error.InvalidPacket;
        if (packet_end > datagram.len) return error.InvalidPacket;
        const packet = datagram[offset..packet_end];
        switch (info.packet_type) {
            .initial => {
                try connection.processProtectedLongDatagramInSpace(.initial, now_millis, initial_keys, packet);
                _ = try connection.driveCryptoBackendInSpace(.initial, backend.cryptoBackend(), scratch);
            },
            .handshake => {
                try connection.processProtectedHandshakeDatagramWithInstalledKeys(now_millis, packet);
                _ = try connection.driveCryptoBackendInSpace(.handshake, backend.cryptoBackend(), scratch);
            },
            .zero_rtt, .retry => return error.UnsupportedPacketType,
        }
        offset = packet_end;
    }
    return offset;
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
    const initial_secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);
    var connection = try Connection.init(allocator, .client, .{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
        .max_datagram_size = 8192,
    });
    defer connection.deinit();
    try connection.setLocalInitialSourceConnectionId(&client_scid);

    var backend = Tls13Backend.initClient(.{
        .alpn = &alpn,
        .server_name = server_name,
        .skip_cert_verify = false,
        .now_sec = now.toSeconds(),
        .ca_bundle = &ca_bundle,
    });
    var scratch: [8192]u8 = undefined;
    var receive_buffer: [8192]u8 = undefined;

    _ = try connection.driveCryptoBackendInSpace(.initial, backend.cryptoBackend(), &scratch);
    const client_initial = (try connection.pollProtectedLongCryptoDatagramInSpace(
        .initial,
        nowMillis(io),
        &original_dcid,
        &client_scid,
        &[_]u8{},
        initial_secrets.client,
    )) orelse return error.UnexpectedState;
    defer allocator.free(client_initial);
    try socket.send(io, &server_address, client_initial);

    var sent_finished = false;
    var received_retry = false;
    var server_initial_keys = initial_secrets.server;
    var datagrams_received: usize = 0;
    while (datagrams_received < 8 and !connection.handshakeConfirmed()) : (datagrams_received += 1) {
        const received = try socket.receiveTimeout(io, &receive_buffer, recvTimeout());
        const now_millis = nowMillis(io);
        if (isRetryDatagram(received.data)) {
            if (received_retry) return error.DuplicateRetry;
            try connection.processRetryDatagram(now_millis, &original_dcid, received.data);
            const retry_scid = connection.retrySourceConnectionId() orelse return error.MissingPeerConnectionId;
            const retry_secrets = try protection.deriveInitialSecrets(.v1, retry_scid);
            backend.retryReceived();
            try connection.resetInitialCryptoSendForRetry();
            _ = try connection.driveCryptoBackendInSpace(.initial, backend.cryptoBackend(), &scratch);
            const retry_initial = (try connection.pollProtectedLongCryptoDatagramInSpace(
                .initial,
                now_millis,
                retry_scid,
                &client_scid,
                &[_]u8{},
                retry_secrets.client,
            )) orelse return error.UnexpectedState;
            defer allocator.free(retry_initial);
            try socket.send(io, &server_address, retry_initial);
            received_retry = true;
            server_initial_keys = retry_secrets.server;
            continue;
        }
        if ((received.data[0] & 0x80) != 0) {
            const long_packet_bytes = try processServerLongDatagram(
                &connection,
                &backend,
                &scratch,
                server_initial_keys,
                now_millis,
                received.data,
            );
            if (long_packet_bytes < received.data.len) {
                const datagram_tail = received.data[long_packet_bytes..];
                if (!isZeroOnlyDatagramPadding(datagram_tail)) {
                    try connection.processProtectedShortDatagramWithInstalledKeys(
                        now_millis,
                        client_scid.len,
                        datagram_tail,
                    );
                }
            }
            if (!sent_finished) {
                const server_scid = connection.peerInitialSourceConnectionId() orelse return error.MissingPeerConnectionId;
                if (try connection.pollProtectedHandshakeDatagramWithInstalledKeys(nowMillis(io), server_scid, &client_scid)) |client_finished| {
                    defer allocator.free(client_finished);
                    try socket.send(io, &server_address, client_finished);
                    sent_finished = true;
                }
            }
        } else {
            try connection.processProtectedShortDatagramWithInstalledKeys(now_millis, client_scid.len, received.data);
        }
    }

    if (!sent_finished or !connection.handshakeConfirmed()) return error.HandshakeNotConfirmed;

    // The independent echo peer reads a request until FIN, then writes the
    // same bytes back on this bidirectional stream. Do not use a local-only
    // stream contract here: the peer must parse the protected 1-RTT packet.
    const peer_connection_id = connection.peerInitialSourceConnectionId() orelse return error.MissingPeerConnectionId;
    const stream_id = try connection.openStream();
    try connection.sendOnStream(stream_id, "hello", true);
    var sent_application_datagrams: usize = 0;
    while (sent_application_datagrams < 4) : (sent_application_datagrams += 1) {
        const datagram = (try connection.pollProtectedShortDatagramWithInstalledKeys(
            nowMillis(io),
            peer_connection_id,
        )) orelse break;
        defer allocator.free(datagram);
        try socket.send(io, &server_address, datagram);
    }

    var stream_buffer: [128]u8 = undefined;
    var received_application_datagrams: usize = 0;
    var recovery_timer_services: usize = 0;
    var got_echo = false;
    var got_echo_fin = false;
    var pto_recovered = false;
    while (received_application_datagrams < 8 and recovery_timer_services < 4) {
        const next_recovery_deadline = if (connection.lossDetectionTimerDeadlineMillis()) |deadline|
            deadline.deadline_millis
        else
            null;
        const received = socket.receiveTimeout(io, &receive_buffer, recvTimeoutForDeadline(io, next_recovery_deadline)) catch |err| switch (err) {
            error.Timeout => {
                const serviced = (try connection.serviceLossDetectionTimer(nowMillis(io))) orelse continue;
                recovery_timer_services += 1;
                if (serviced.kind == .pto) pto_recovered = true;

                var retransmission_count: usize = 0;
                while (retransmission_count < 4) : (retransmission_count += 1) {
                    const retransmission = (try connection.pollProtectedShortDatagramWithInstalledKeys(
                        nowMillis(io),
                        peer_connection_id,
                    )) orelse break;
                    defer allocator.free(retransmission);
                    try socket.send(io, &server_address, retransmission);
                }
                continue;
            },
            else => return err,
        };
        const now_millis = nowMillis(io);
        var processed_application_datagram = false;
        if ((received.data[0] & 0x80) != 0) {
            const long_packet_bytes = try processServerLongDatagram(
                &connection,
                &backend,
                &scratch,
                server_initial_keys,
                now_millis,
                received.data,
            );
            if (long_packet_bytes < received.data.len) {
                const datagram_tail = received.data[long_packet_bytes..];
                if (!isZeroOnlyDatagramPadding(datagram_tail)) {
                    try connection.processProtectedShortDatagramWithInstalledKeys(
                        now_millis,
                        client_scid.len,
                        datagram_tail,
                    );
                    processed_application_datagram = true;
                }
            }
        } else {
            try connection.processProtectedShortDatagramWithInstalledKeys(
                now_millis,
                client_scid.len,
                received.data,
            );
            processed_application_datagram = true;
        }
        // Server Initial/Handshake retransmissions can arrive while the
        // application STREAM is lost. They do not acknowledge 1-RTT data and
        // must not consume the bounded application receive budget before PTO.
        if (!processed_application_datagram) continue;
        received_application_datagrams += 1;
        if (try connection.recvOnStream(stream_id, &stream_buffer)) |echoed_len| {
            try require(std.mem.eql(u8, stream_buffer[0..echoed_len], "hello"));
            got_echo = true;
        }
        if (got_echo and try connection.recvStreamFinished(stream_id)) {
            got_echo_fin = true;
            break;
        }
    }
    if (!got_echo) return error.MissingStreamEcho;
    if (!got_echo_fin) return error.MissingStreamFin;
    std.debug.print("external_handshake_done=true certificate_verified=true alpn=hq-interop echo_bytes=5 pto_recovered={}\n", .{pto_recovered});
}

test "zero-only datagram padding is isolated from a short packet" {
    try std.testing.expect(isZeroOnlyDatagramPadding(&[_]u8{ 0, 0, 0 }));
    try std.testing.expect(!isZeroOnlyDatagramPadding(&[_]u8{}));
    try std.testing.expect(!isZeroOnlyDatagramPadding(&[_]u8{ 0x40, 0 }));
}

test "Retry detector accepts only a v1 Retry header" {
    const retry = [_]u8{ 0xf0, 0, 0, 0, 1 };
    const initial = [_]u8{ 0xc0, 0, 0, 0, 1 };
    try std.testing.expect(isRetryDatagram(&retry));
    try std.testing.expect(!isRetryDatagram(&initial));
    try std.testing.expect(!isRetryDatagram(&[_]u8{ 0xf0, 0, 0, 0 }));
}
