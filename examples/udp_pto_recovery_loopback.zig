const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

const ReceivedDatagram = struct {
    data: []const u8,
    path: quicz.endpoint.Udp4Tuple,
};

fn require(condition: bool) ExampleError!void {
    if (!condition) return error.UnexpectedState;
}

fn receiveTimeout() std.Io.Timeout {
    return .{
        .duration = .{
            .clock = .awake,
            .raw = std.Io.Duration.fromMilliseconds(500),
        },
    };
}

fn bindLoopbackUdp(io: std.Io) !std.Io.net.Socket {
    var address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    return address.bind(io, .{
        .mode = .dgram,
        .protocol = .udp,
    });
}

fn udp4Address(address: std.Io.net.IpAddress) ExampleError!quicz.endpoint.Udp4Address {
    return switch (address) {
        .ip4 => |ip4| quicz.endpoint.Udp4Address.init(ip4.bytes, ip4.port),
        .ip6 => error.UnexpectedState,
    };
}

fn udp4Tuple(local: std.Io.net.IpAddress, remote: std.Io.net.IpAddress) !quicz.endpoint.Udp4Tuple {
    return .{
        .local = try udp4Address(local),
        .remote = try udp4Address(remote),
    };
}

fn receiveDatagram(
    io: std.Io,
    socket: *std.Io.net.Socket,
    receive_buf: []u8,
) !ReceivedDatagram {
    const received = try socket.receiveTimeout(io, receive_buf, receiveTimeout());
    const path = try udp4Tuple(socket.address, received.from);
    return .{
        .data = received.data,
        .path = path,
    };
}

fn sendClientPacket(
    io: std.Io,
    client_socket: *std.Io.net.Socket,
    server_socket: *std.Io.net.Socket,
    server_lifecycle: *quicz.EndpointConnectionLifecycle,
    server: *quicz.Connection,
    packet: []const u8,
    now_millis: i64,
    server_dcid: []const u8,
    receive_buf: []u8,
    keys: quicz.protection.Aes128PacketProtectionKeys,
) !void {
    try client_socket.send(io, &server_socket.address, packet);

    const received = try receiveDatagram(io, server_socket, receive_buf);
    const route = try server_lifecycle.processRoutedProtectedShortDatagram(
        51,
        server,
        received.path,
        now_millis,
        keys,
        received.data,
    );
    try require(route.connection_id == 51);
    try require(std.mem.eql(u8, route.destination_connection_id.asSlice(), server_dcid));
}

fn sendServerPacket(
    io: std.Io,
    server_socket: *std.Io.net.Socket,
    client_socket: *std.Io.net.Socket,
    client_lifecycle: *quicz.EndpointConnectionLifecycle,
    client: *quicz.Connection,
    packet: []const u8,
    now_millis: i64,
    client_dcid: []const u8,
    receive_buf: []u8,
    keys: quicz.protection.Aes128PacketProtectionKeys,
) !void {
    try server_socket.send(io, &client_socket.address, packet);

    const received = try receiveDatagram(io, client_socket, receive_buf);
    const route = try client_lifecycle.processRoutedProtectedShortDatagram(
        41,
        client,
        received.path,
        now_millis,
        keys,
        received.data,
    );
    try require(route.connection_id == 41);
    try require(std.mem.eql(u8, route.destination_connection_id.asSlice(), client_dcid));
}

fn packetContainsStream(
    allocator: std.mem.Allocator,
    packet: []const u8,
    keys: quicz.protection.Aes128PacketProtectionKeys,
    dcid_len: usize,
    expected_packet_number: u64,
    stream_id: u64,
    expected_offset: u64,
    expected_data: []const u8,
) !bool {
    var opened = try quicz.protection.unprotectShortPacketAes128(
        allocator,
        keys,
        packet,
        dcid_len,
        expected_packet_number,
    );
    defer quicz.protection.deinitProtectedShortPacket(&opened, allocator);

    var offset: usize = 0;
    while (offset < opened.packet.plaintext.len) {
        var decoded = try quicz.frame.decodeFrameSlice(opened.packet.plaintext[offset..], allocator);
        defer quicz.frame.deinitFrame(&decoded.frame, allocator);
        if (decoded.len == 0) return error.UnexpectedState;
        offset += decoded.len;

        switch (decoded.frame) {
            .stream => |stream| {
                return stream.stream_id == stream_id and
                    stream.offset == expected_offset and
                    std.mem.eql(u8, stream.data, expected_data);
            },
            else => {},
        }
    }
    return false;
}

fn packetContainsCrypto(
    allocator: std.mem.Allocator,
    packet: []const u8,
    keys: quicz.protection.Aes128PacketProtectionKeys,
    dcid_len: usize,
    expected_packet_number: u64,
    expected_data: []const u8,
) !bool {
    var opened = try quicz.protection.unprotectShortPacketAes128(
        allocator,
        keys,
        packet,
        dcid_len,
        expected_packet_number,
    );
    defer quicz.protection.deinitProtectedShortPacket(&opened, allocator);

    var offset: usize = 0;
    while (offset < opened.packet.plaintext.len) {
        var decoded = try quicz.frame.decodeFrameSlice(opened.packet.plaintext[offset..], allocator);
        defer quicz.frame.deinitFrame(&decoded.frame, allocator);
        if (decoded.len == 0) return error.UnexpectedState;
        offset += decoded.len;

        switch (decoded.frame) {
            .crypto => |crypto| {
                return crypto.offset == 0 and std.mem.eql(u8, crypto.data, expected_data);
            },
            else => {},
        }
    }
    return false;
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const client_connection_id: u64 = 41;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_socket = try bindLoopbackUdp(io);
    defer client_socket.close(io);
    var server_socket = try bindLoopbackUdp(io);
    defer server_socket.close(io);

    const client_local = try udp4Address(client_socket.address);
    const server_local = try udp4Address(server_socket.address);
    try require(client_local.port != 0);
    try require(server_local.port != 0);
    try require(client_local.port != server_local.port);

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try quicz.Connection.init(allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{
        .initial_rtt_ms = 100,
    });
    defer server.deinit();
    try server.validatePeerAddress();
    try client.confirmHandshake();
    try server.confirmHandshake();

    var client_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer client_lifecycle.deinit();
    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(allocator);
    defer server_lifecycle.deinit();

    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    const server_path = try udp4Tuple(server_socket.address, client_socket.address);
    try client_lifecycle.registerConnectionId(41, &client_dcid, client_path, .{
        .active_migration_disabled = true,
    });
    try server_lifecycle.registerConnectionId(51, &server_dcid, server_path, .{
        .active_migration_disabled = true,
    });

    var server_receive_buf: [1500]u8 = undefined;
    var client_receive_buf: [1500]u8 = undefined;

    try client.sendPing();
    const first_ping = (try client.pollProtectedShortDatagram(10, &server_dcid, secrets.client)) orelse return error.UnexpectedState;
    defer allocator.free(first_ping);
    try sendClientPacket(
        io,
        &client_socket,
        &server_socket,
        &server_lifecycle,
        &server,
        first_ping,
        11,
        &server_dcid,
        &server_receive_buf,
        secrets.client,
    );
    try require(server.pendingAckLargest(.application) == 0);

    try client_lifecycle.armRecoveryTimerFromConnection(client_connection_id, &client);
    const ping_timer = client_lifecycle.earliestRecoveryDeadline() orelse return error.UnexpectedState;
    try require(ping_timer.connection_id == client_connection_id);
    try require(ping_timer.timer.space == .application);
    try require(ping_timer.timer.kind == .pto);
    const ping_deadline = ping_timer.timer.deadline_millis;
    try require((try client_lifecycle.serviceRecoveryTimer(client_connection_id, &client, ping_deadline - 1)) == null);
    try require(client.sentPacketCount(.application) == 1);
    try require(client_lifecycle.recoveryTimerCount() == 1);

    const ping_probe_result = try client_lifecycle.serviceRecoveryTimerAndPollProtectedShortDatagram(
        client_connection_id,
        &client,
        ping_deadline,
        &server_dcid,
        secrets.client,
    );
    const ping_serviced = ping_probe_result.serviced orelse return error.UnexpectedState;
    try require(ping_serviced.connection_id == client_connection_id);
    try require(ping_serviced.timer.space == .application);
    try require(ping_serviced.timer.kind == .pto);
    const pto_ping = ping_probe_result.datagram orelse return error.UnexpectedState;
    defer allocator.free(pto_ping);
    try require(client.sentPacketCount(.application) == 2);
    try require(client_lifecycle.recoveryTimerCount() == 1);
    try sendClientPacket(
        io,
        &client_socket,
        &server_socket,
        &server_lifecycle,
        &server,
        pto_ping,
        ping_deadline + 2,
        &server_dcid,
        &server_receive_buf,
        secrets.client,
    );
    try require(server.pendingAckLargest(.application) == 1);

    const ping_ack = (try server.pollProtectedShortDatagram(ping_deadline + 3, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer allocator.free(ping_ack);
    try sendServerPacket(
        io,
        &server_socket,
        &client_socket,
        &client_lifecycle,
        &client,
        ping_ack,
        ping_deadline + 4,
        &client_dcid,
        &client_receive_buf,
        secrets.server,
    );
    try require(client.sentPacketCount(.application) == 0);
    try require(client.bytesInFlight(.application) == 0);
    try require(client.ptoDeadlineMillis(.application) == null);
    try client_lifecycle.armRecoveryTimerFromConnection(client_connection_id, &client);
    try require(client_lifecycle.recoveryTimerCount() == 0);

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "old", false);
    const first_stream = (try client.pollProtectedShortDatagram(1000, &server_dcid, secrets.client)) orelse return error.UnexpectedState;
    defer allocator.free(first_stream);
    try sendClientPacket(
        io,
        &client_socket,
        &server_socket,
        &server_lifecycle,
        &server,
        first_stream,
        1001,
        &server_dcid,
        &server_receive_buf,
        secrets.client,
    );

    try client.sendOnStream(stream_id, "new", true);
    try client_lifecycle.armRecoveryTimerFromConnection(client_connection_id, &client);
    const stream_timer = client_lifecycle.earliestRecoveryDeadline() orelse return error.UnexpectedState;
    try require(stream_timer.connection_id == client_connection_id);
    try require(stream_timer.timer.space == .application);
    try require(stream_timer.timer.kind == .pto);
    const stream_deadline = stream_timer.timer.deadline_millis;
    const stream_probe_result = try client_lifecycle.serviceRecoveryTimerAndPollProtectedShortDatagram(
        client_connection_id,
        &client,
        stream_deadline,
        &server_dcid,
        secrets.client,
    );
    const stream_serviced = stream_probe_result.serviced orelse return error.UnexpectedState;
    try require(stream_serviced.connection_id == client_connection_id);
    try require(stream_serviced.timer.space == .application);
    try require(stream_serviced.timer.kind == .pto);
    const stream_probe = stream_probe_result.datagram orelse return error.UnexpectedState;
    defer allocator.free(stream_probe);
    try require(client.sentPacketCount(.application) == 2);
    try require(client_lifecycle.recoveryTimerCount() == 1);
    try sendClientPacket(
        io,
        &client_socket,
        &server_socket,
        &server_lifecycle,
        &server,
        stream_probe,
        stream_deadline + 2,
        &server_dcid,
        &server_receive_buf,
        secrets.client,
    );
    try require(server.pendingAckLargest(.application) == 3);

    var stream_read_buf: [16]u8 = undefined;
    const stream_read_len = (try server.recvOnStream(stream_id, &stream_read_buf)) orelse return error.UnexpectedState;
    try require(std.mem.eql(u8, stream_read_buf[0..stream_read_len], "oldnew"));

    const stream_ack = (try server.pollProtectedShortDatagram(stream_deadline + 3, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer allocator.free(stream_ack);
    try sendServerPacket(
        io,
        &server_socket,
        &client_socket,
        &client_lifecycle,
        &client,
        stream_ack,
        stream_deadline + 4,
        &client_dcid,
        &client_receive_buf,
        secrets.server,
    );
    try require(client.sentPacketCount(.application) == 0);
    try require(client.bytesInFlight(.application) == 0);
    try require(client.ptoDeadlineMillis(.application) == null);
    try client_lifecycle.armRecoveryTimerFromConnection(client_connection_id, &client);
    try require(client_lifecycle.recoveryTimerCount() == 0);

    const retransmit_stream_id = try client.openStream();
    try client.sendOnStream(retransmit_stream_id, "again", false);
    const first_retransmit_stream = (try client.pollProtectedShortDatagram(2000, &server_dcid, secrets.client)) orelse return error.UnexpectedState;
    defer allocator.free(first_retransmit_stream);
    try sendClientPacket(
        io,
        &client_socket,
        &server_socket,
        &server_lifecycle,
        &server,
        first_retransmit_stream,
        2001,
        &server_dcid,
        &server_receive_buf,
        secrets.client,
    );

    var retransmit_read_buf: [16]u8 = undefined;
    const retransmit_read_len = (try server.recvOnStream(retransmit_stream_id, &retransmit_read_buf)) orelse return error.UnexpectedState;
    try require(std.mem.eql(u8, retransmit_read_buf[0..retransmit_read_len], "again"));

    try client_lifecycle.armRecoveryTimerFromConnection(client_connection_id, &client);
    const retransmit_timer = client_lifecycle.earliestRecoveryDeadline() orelse return error.UnexpectedState;
    try require(retransmit_timer.connection_id == client_connection_id);
    try require(retransmit_timer.timer.space == .application);
    try require(retransmit_timer.timer.kind == .pto);
    const retransmit_deadline = retransmit_timer.timer.deadline_millis;
    const retransmit_probe_result = try client_lifecycle.serviceRecoveryTimerAndPollProtectedShortDatagram(
        client_connection_id,
        &client,
        retransmit_deadline,
        &server_dcid,
        secrets.client,
    );
    const retransmit_serviced = retransmit_probe_result.serviced orelse return error.UnexpectedState;
    try require(retransmit_serviced.connection_id == client_connection_id);
    try require(retransmit_serviced.timer.space == .application);
    try require(retransmit_serviced.timer.kind == .pto);
    const retransmit_probe = retransmit_probe_result.datagram orelse return error.UnexpectedState;
    defer allocator.free(retransmit_probe);
    try require(client.sentPacketCount(.application) == 2);
    try require(client_lifecycle.recoveryTimerCount() == 1);
    try require(try packetContainsStream(
        allocator,
        retransmit_probe,
        secrets.client,
        server_dcid.len,
        5,
        retransmit_stream_id,
        0,
        "again",
    ));
    try sendClientPacket(
        io,
        &client_socket,
        &server_socket,
        &server_lifecycle,
        &server,
        retransmit_probe,
        retransmit_deadline + 2,
        &server_dcid,
        &server_receive_buf,
        secrets.client,
    );
    try require((try server.recvOnStream(retransmit_stream_id, &retransmit_read_buf)) == null);

    const retransmit_ack = (try server.pollProtectedShortDatagram(retransmit_deadline + 3, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer allocator.free(retransmit_ack);
    try sendServerPacket(
        io,
        &server_socket,
        &client_socket,
        &client_lifecycle,
        &client,
        retransmit_ack,
        retransmit_deadline + 4,
        &client_dcid,
        &client_receive_buf,
        secrets.server,
    );
    try require(client.sentPacketCount(.application) == 0);
    try require(client.bytesInFlight(.application) == 0);
    try require(client.ptoDeadlineMillis(.application) == null);
    try client_lifecycle.armRecoveryTimerFromConnection(client_connection_id, &client);
    try require(client_lifecycle.recoveryTimerCount() == 0);

    try client.sendCrypto("udp crypto");
    const first_crypto = (try client.pollProtectedShortDatagram(3000, &server_dcid, secrets.client)) orelse return error.UnexpectedState;
    defer allocator.free(first_crypto);
    try sendClientPacket(
        io,
        &client_socket,
        &server_socket,
        &server_lifecycle,
        &server,
        first_crypto,
        3001,
        &server_dcid,
        &server_receive_buf,
        secrets.client,
    );
    var crypto_read_buf: [16]u8 = undefined;
    const crypto_read_len = (try server.recvCrypto(&crypto_read_buf)) orelse return error.UnexpectedState;
    try require(std.mem.eql(u8, crypto_read_buf[0..crypto_read_len], "udp crypto"));

    try client_lifecycle.armRecoveryTimerFromConnection(client_connection_id, &client);
    const crypto_timer = client_lifecycle.earliestRecoveryDeadline() orelse return error.UnexpectedState;
    try require(crypto_timer.connection_id == client_connection_id);
    try require(crypto_timer.timer.space == .application);
    try require(crypto_timer.timer.kind == .pto);
    const crypto_deadline = crypto_timer.timer.deadline_millis;
    const crypto_probe_result = try client_lifecycle.serviceRecoveryTimerAndPollProtectedShortDatagram(
        client_connection_id,
        &client,
        crypto_deadline,
        &server_dcid,
        secrets.client,
    );
    const crypto_serviced = crypto_probe_result.serviced orelse return error.UnexpectedState;
    try require(crypto_serviced.connection_id == client_connection_id);
    try require(crypto_serviced.timer.space == .application);
    try require(crypto_serviced.timer.kind == .pto);
    const crypto_probe = crypto_probe_result.datagram orelse return error.UnexpectedState;
    defer allocator.free(crypto_probe);
    try require(client.sentPacketCount(.application) == 2);
    try require(client_lifecycle.recoveryTimerCount() == 1);
    try require(try packetContainsCrypto(
        allocator,
        crypto_probe,
        secrets.client,
        server_dcid.len,
        7,
        "udp crypto",
    ));
    try sendClientPacket(
        io,
        &client_socket,
        &server_socket,
        &server_lifecycle,
        &server,
        crypto_probe,
        crypto_deadline + 2,
        &server_dcid,
        &server_receive_buf,
        secrets.client,
    );
    try require((try server.recvCrypto(&crypto_read_buf)) == null);

    const crypto_ack = (try server.pollProtectedShortDatagram(crypto_deadline + 3, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer allocator.free(crypto_ack);
    try sendServerPacket(
        io,
        &server_socket,
        &client_socket,
        &client_lifecycle,
        &client,
        crypto_ack,
        crypto_deadline + 4,
        &client_dcid,
        &client_receive_buf,
        secrets.server,
    );
    try require(client.sentPacketCount(.application) == 0);
    try require(client.bytesInFlight(.application) == 0);
    try require(client.ptoDeadlineMillis(.application) == null);
    try client_lifecycle.armRecoveryTimerFromConnection(client_connection_id, &client);
    try require(client_lifecycle.recoveryTimerCount() == 0);

    std.debug.print("[udp-pto] client_port={} server_port={} ping_deadline={} pto_ping_bytes={} stream_deadline={} stream_probe_bytes={} retransmit_deadline={} retransmit_probe_bytes={} crypto_deadline={} crypto_probe_bytes={} received=\"{s}\" retransmitted=\"{s}\" crypto=\"{s}\" client_inflight={} timers_remaining={}\n", .{
        client_local.port,
        server_local.port,
        ping_deadline,
        pto_ping.len,
        stream_deadline,
        stream_probe.len,
        retransmit_deadline,
        retransmit_probe.len,
        crypto_deadline,
        crypto_probe.len,
        stream_read_buf[0..stream_read_len],
        retransmit_read_buf[0..retransmit_read_len],
        crypto_read_buf[0..crypto_read_len],
        client.bytesInFlight(.application),
        client_lifecycle.recoveryTimerCount(),
    });
}
