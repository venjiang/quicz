const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };

const FixedWriter = struct {
    buffer: []u8,
    pos: usize = 0,

    pub fn writer(self: *FixedWriter) *FixedWriter {
        return self;
    }

    pub fn writeByte(self: *FixedWriter, byte: u8) !void {
        if (self.pos >= self.buffer.len) return error.NoSpaceLeft;
        self.buffer[self.pos] = byte;
        self.pos += 1;
    }

    pub fn writeAll(self: *FixedWriter, bytes: []const u8) !void {
        if (self.buffer.len - self.pos < bytes.len) return error.NoSpaceLeft;
        @memcpy(self.buffer[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    pub fn getWritten(self: FixedWriter) []const u8 {
        return self.buffer[0..self.pos];
    }
};

const ReceivedDatagram = struct {
    data: []const u8,
    path: quicz.endpoint.Udp4Tuple,
};

const RecoveryPeriodResult = struct {
    client_port: u16,
    server_port: u16,
    first_recovery_window: usize,
    second_recovery_window: usize,
    repeated_loss_suppressed: bool,
    remaining_packets: usize,
};

const PersistentCongestionResult = struct {
    client_port: u16,
    server_port: u16,
    minimum_window: usize,
    final_window: usize,
    reduced_to_minimum: bool,
    remaining_packets: usize,
    bytes_in_flight: usize,
};

const CeProbeResult = struct {
    client_port: u16,
    server_port: u16,
    probe_bytes: usize,
    ce_count: u64,
    congestion_window: usize,
    bytes_in_flight: usize,
    route: u64,
};

fn fixedWriter(buffer: []u8) FixedWriter {
    return .{ .buffer = buffer };
}

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

fn protectShortPacket(
    allocator: std.mem.Allocator,
    dcid: []const u8,
    packet_number: u64,
    keys: quicz.protection.Aes128PacketProtectionKeys,
    plaintext: []const u8,
) ![]u8 {
    const packet_number_encoding = try quicz.packet.encodePacketNumberForHeader(packet_number, null);
    return quicz.protection.protectShortPacketAes128(
        allocator,
        .{
            .dcid = dcid,
            .spin_bit = false,
            .key_phase = false,
            .packet_number = packet_number,
        },
        packet_number_encoding,
        keys,
        plaintext,
    );
}

fn prepareLoopbackPair(
    client_socket: *std.Io.net.Socket,
    server_socket: *std.Io.net.Socket,
    client_lifecycle: *quicz.EndpointConnectionLifecycle,
    server_lifecycle: *quicz.EndpointConnectionLifecycle,
) !void {
    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    const server_path = try udp4Tuple(server_socket.address, client_socket.address);
    try client_lifecycle.registerConnectionId(41, &client_dcid, client_path, .{
        .active_migration_disabled = true,
    });
    try server_lifecycle.registerConnectionId(51, &server_dcid, server_path, .{
        .active_migration_disabled = true,
    });
}

fn sendClientPing(
    allocator: std.mem.Allocator,
    io: std.Io,
    client_socket: *std.Io.net.Socket,
    server_socket: *std.Io.net.Socket,
    server_lifecycle: *quicz.EndpointConnectionLifecycle,
    client: *quicz.Connection,
    server: *quicz.Connection,
    now_millis: i64,
    receive_buf: []u8,
    keys: quicz.protection.Aes128PacketProtectionKeys,
) !usize {
    try client.sendPing();
    const packet = (try client.pollProtectedShortDatagram(now_millis, &server_dcid, keys)) orelse return error.UnexpectedState;
    defer allocator.free(packet);

    try client_socket.send(io, &server_socket.address, packet);
    const received = try receiveDatagram(io, server_socket, receive_buf);
    const route = try server_lifecycle.processRoutedProtectedShortDatagram(
        51,
        server,
        received.path,
        now_millis + 1,
        keys,
        received.data,
    );
    try require(route.connection_id == 51);
    try require(std.mem.eql(u8, route.destination_connection_id.asSlice(), &server_dcid));
    return packet.len;
}

fn sendServerAck(
    allocator: std.mem.Allocator,
    io: std.Io,
    server_socket: *std.Io.net.Socket,
    client_socket: *std.Io.net.Socket,
    client_lifecycle: *quicz.EndpointConnectionLifecycle,
    client: *quicz.Connection,
    now_millis: i64,
    server_packet_number: u64,
    ack: quicz.frame.AckFrame,
    receive_buf: []u8,
    keys: quicz.protection.Aes128PacketProtectionKeys,
) !usize {
    var payload: [64]u8 = undefined;
    var out = fixedWriter(&payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .ack = ack });

    const packet = try protectShortPacket(
        allocator,
        &client_dcid,
        server_packet_number,
        keys,
        out.getWritten(),
    );
    defer allocator.free(packet);

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
    try require(std.mem.eql(u8, route.destination_connection_id.asSlice(), &client_dcid));
    return packet.len;
}

fn sendServerAckEcn(
    allocator: std.mem.Allocator,
    io: std.Io,
    server_socket: *std.Io.net.Socket,
    client_socket: *std.Io.net.Socket,
    client_lifecycle: *quicz.EndpointConnectionLifecycle,
    client: *quicz.Connection,
    now_millis: i64,
    server_packet_number: u64,
    ack_ecn: quicz.frame.AckEcnFrame,
    receive_buf: []u8,
    keys: quicz.protection.Aes128PacketProtectionKeys,
) !usize {
    var payload: [64]u8 = undefined;
    var out = fixedWriter(&payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .ack_ecn = ack_ecn });

    const packet = try protectShortPacket(
        allocator,
        &client_dcid,
        server_packet_number,
        keys,
        out.getWritten(),
    );
    defer allocator.free(packet);

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
    try require(std.mem.eql(u8, route.destination_connection_id.asSlice(), &client_dcid));
    return packet.len;
}

fn runRecoveryPeriodPhase(allocator: std.mem.Allocator, io: std.Io) !RecoveryPeriodResult {
    var client_socket = try bindLoopbackUdp(io);
    defer client_socket.close(io);
    var server_socket = try bindLoopbackUdp(io);
    defer server_socket.close(io);

    const client_local = try udp4Address(client_socket.address);
    const server_local = try udp4Address(server_socket.address);
    try require(client_local.port != 0);
    try require(server_local.port != 0);
    try require(client_local.port != server_local.port);

    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try quicz.Connection.init(allocator, .client, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{
        .max_datagram_size = 1200,
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
    try prepareLoopbackPair(&client_socket, &server_socket, &client_lifecycle, &server_lifecycle);

    var server_receive_buf: [1500]u8 = undefined;
    var client_receive_buf: [1500]u8 = undefined;

    var packet_number: u64 = 0;
    while (packet_number < 8) : (packet_number += 1) {
        const now_millis = @as(i64, @intCast(packet_number + 1)) * 10;
        _ = try sendClientPing(allocator, io, &client_socket, &server_socket, &server_lifecycle, &client, &server, now_millis, &server_receive_buf, secrets.client);
    }
    try require(client.sentPacketCount(.application) == 8);
    try require(server.pendingAckLargest(.application) == 7);

    _ = try sendServerAck(allocator, io, &server_socket, &client_socket, &client_lifecycle, &client, 100, 0, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    }, &client_receive_buf, secrets.server);
    const first_recovery_window = client.congestionWindow(.application);
    try require(client.sentPacketCount(.application) == 6);

    _ = try sendServerAck(allocator, io, &server_socket, &client_socket, &client_lifecycle, &client, 120, 1, .{
        .largest_acknowledged = 7,
        .ack_delay = 0,
        .first_ack_range = 0,
    }, &client_receive_buf, secrets.server);
    const second_recovery_window = client.congestionWindow(.application);
    try require(second_recovery_window == first_recovery_window);

    return .{
        .client_port = client_local.port,
        .server_port = server_local.port,
        .first_recovery_window = first_recovery_window,
        .second_recovery_window = second_recovery_window,
        .repeated_loss_suppressed = second_recovery_window == first_recovery_window,
        .remaining_packets = client.sentPacketCount(.application),
    };
}

fn runPersistentCongestionPhase(allocator: std.mem.Allocator, io: std.Io) !PersistentCongestionResult {
    var client_socket = try bindLoopbackUdp(io);
    defer client_socket.close(io);
    var server_socket = try bindLoopbackUdp(io);
    defer server_socket.close(io);

    const client_local = try udp4Address(client_socket.address);
    const server_local = try udp4Address(server_socket.address);
    try require(client_local.port != 0);
    try require(server_local.port != 0);
    try require(client_local.port != server_local.port);

    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try quicz.Connection.init(allocator, .client, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{
        .max_datagram_size = 1200,
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
    try prepareLoopbackPair(&client_socket, &server_socket, &client_lifecycle, &server_lifecycle);

    var server_receive_buf: [1500]u8 = undefined;
    var client_receive_buf: [1500]u8 = undefined;

    _ = try sendClientPing(allocator, io, &client_socket, &server_socket, &server_lifecycle, &client, &server, 0, &server_receive_buf, secrets.client);
    _ = try sendServerAck(allocator, io, &server_socket, &client_socket, &client_lifecycle, &client, 100, 0, .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    }, &client_receive_buf, secrets.server);
    try require(client.sentPacketCount(.application) == 0);

    _ = try sendClientPing(allocator, io, &client_socket, &server_socket, &server_lifecycle, &client, &server, 10, &server_receive_buf, secrets.client);
    _ = try sendClientPing(allocator, io, &client_socket, &server_socket, &server_lifecycle, &client, &server, 1000, &server_receive_buf, secrets.client);
    _ = try sendClientPing(allocator, io, &client_socket, &server_socket, &server_lifecycle, &client, &server, 1100, &server_receive_buf, secrets.client);
    _ = try sendClientPing(allocator, io, &client_socket, &server_socket, &server_lifecycle, &client, &server, 1200, &server_receive_buf, secrets.client);
    try require(client.sentPacketCount(.application) == 4);

    _ = try sendServerAck(allocator, io, &server_socket, &client_socket, &client_lifecycle, &client, 1300, 1, .{
        .largest_acknowledged = 4,
        .ack_delay = 0,
        .first_ack_range = 0,
    }, &client_receive_buf, secrets.server);

    const minimum_window = quicz.recovery.minimumCongestionWindow(1200);
    try require(client.congestionWindow(.application) == minimum_window);
    try require(client.sentPacketCount(.application) == 0);
    try require(client.bytesInFlight(.application) == 0);

    return .{
        .client_port = client_local.port,
        .server_port = server_local.port,
        .minimum_window = minimum_window,
        .final_window = client.congestionWindow(.application),
        .reduced_to_minimum = client.congestionWindow(.application) == minimum_window,
        .remaining_packets = client.sentPacketCount(.application),
        .bytes_in_flight = client.bytesInFlight(.application),
    };
}

fn runCeProbePhase(allocator: std.mem.Allocator, io: std.Io) !CeProbeResult {
    var client_socket = try bindLoopbackUdp(io);
    defer client_socket.close(io);
    var server_socket = try bindLoopbackUdp(io);
    defer server_socket.close(io);

    const client_local = try udp4Address(client_socket.address);
    const server_local = try udp4Address(server_socket.address);
    try require(client_local.port != 0);
    try require(server_local.port != 0);
    try require(client_local.port != server_local.port);

    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try quicz.Connection.init(allocator, .client, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{
        .max_datagram_size = 1200,
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
    try prepareLoopbackPair(&client_socket, &server_socket, &client_lifecycle, &server_lifecycle);

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "udp ce congestion probe", false);
    client.recovery_state.congestion_window = 36_000;

    var client_receive_buf: [1500]u8 = undefined;
    var server_receive_buf: [1500]u8 = undefined;
    var ping_payload = [_]u8{@intFromEnum(quicz.frame.FrameType.padding)} ** 1178;
    ping_payload[0] = @intFromEnum(quicz.frame.FrameType.ping);
    var packet_number: usize = 0;
    while (packet_number < 30) : (packet_number += 1) {
        const packet = try protectShortPacket(
            allocator,
            &server_dcid,
            @intCast(packet_number),
            secrets.client,
            &ping_payload,
        );
        defer allocator.free(packet);
        _ = try client.recordEcnPacketSentInSpace(
            .application,
            @as(i64, @intCast(packet_number + 1)) * 10,
            packet.len,
            .ect0,
        );

        try client_socket.send(io, &server_socket.address, packet);
        const received = try receiveDatagram(io, &server_socket, &server_receive_buf);
        const route = try server_lifecycle.processRoutedProtectedShortDatagram(
            51,
            &server,
            received.path,
            @as(i64, @intCast(packet_number + 1)) * 10 + 1,
            secrets.client,
            received.data,
        );
        try require(route.connection_id == 51);
        try require(std.mem.eql(u8, route.destination_connection_id.asSlice(), &server_dcid));
    }
    client.recovery_state.congestion_window = client.bytesInFlight(.application);

    const pre_ce = try client_lifecycle.pollProtectedShortDatagram(
        41,
        &client,
        350,
        &server_dcid,
        secrets.client,
    );
    try require(pre_ce == null);

    _ = try sendServerAckEcn(allocator, io, &server_socket, &client_socket, &client_lifecycle, &client, 360, 0, .{
        .ack = .{
            .largest_acknowledged = 0,
            .ack_delay = 0,
            .first_ack_range = 0,
        },
        .ecn_counts = .{
            .ect0_count = 0,
            .ect1_count = 0,
            .ecn_ce_count = 1,
        },
    }, &client_receive_buf, secrets.server);

    try require(client.ecnValidationState(.application) == .capable);
    try require(client.ecnCounts(.application).ecn_ce_count == 1);
    try require(client.congestion_probe_count == 1);
    try require(!client.recovery_state.canSend(1));

    const probe = (try client_lifecycle.pollProtectedShortDatagram(
        41,
        &client,
        370,
        &server_dcid,
        secrets.client,
    )) orelse return error.UnexpectedState;
    defer allocator.free(probe);
    try require(client.congestion_probe_count == 0);

    try client_socket.send(io, &server_socket.address, probe);
    const received = try receiveDatagram(io, &server_socket, &server_receive_buf);
    const route = try server_lifecycle.processRoutedProtectedShortDatagram(
        51,
        &server,
        received.path,
        371,
        secrets.client,
        received.data,
    );
    try require(route.connection_id == 51);
    try require(std.mem.eql(u8, route.destination_connection_id.asSlice(), &server_dcid));

    var stream_buf: [64]u8 = undefined;
    const stream_len = (try server.recvOnStream(stream_id, &stream_buf)) orelse return error.UnexpectedState;
    try require(std.mem.eql(u8, stream_buf[0..stream_len], "udp ce congestion probe"));
    try require(client.bytesInFlight(.application) > client.congestionWindow(.application));

    return .{
        .client_port = client_local.port,
        .server_port = server_local.port,
        .probe_bytes = probe.len,
        .ce_count = client.ecnCounts(.application).ecn_ce_count,
        .congestion_window = client.congestionWindow(.application),
        .bytes_in_flight = client.bytesInFlight(.application),
        .route = route.connection_id,
    };
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const recovery_period = try runRecoveryPeriodPhase(allocator, io);
    const persistent_congestion = try runPersistentCongestionPhase(allocator, io);
    const ce_probe = try runCeProbePhase(allocator, io);

    std.debug.print("[udp-congestion] recovery_client_port={} recovery_server_port={} recovery_cwnd={} repeated_loss_cwnd={} repeated_loss_suppressed={} recovery_remaining={} persistent_client_port={} persistent_server_port={} minimum_cwnd={} persistent_cwnd={} persistent_minimum={} persistent_remaining={} persistent_inflight={} ce_client_port={} ce_server_port={} ce_probe_bytes={} ce_count={} ce_cwnd={} ce_inflight={} ce_route={}\n", .{
        recovery_period.client_port,
        recovery_period.server_port,
        recovery_period.first_recovery_window,
        recovery_period.second_recovery_window,
        recovery_period.repeated_loss_suppressed,
        recovery_period.remaining_packets,
        persistent_congestion.client_port,
        persistent_congestion.server_port,
        persistent_congestion.minimum_window,
        persistent_congestion.final_window,
        persistent_congestion.reduced_to_minimum,
        persistent_congestion.remaining_packets,
        persistent_congestion.bytes_in_flight,
        ce_probe.client_port,
        ce_probe.server_port,
        ce_probe.probe_bytes,
        ce_probe.ce_count,
        ce_probe.congestion_window,
        ce_probe.bytes_in_flight,
        ce_probe.route,
    });
}
