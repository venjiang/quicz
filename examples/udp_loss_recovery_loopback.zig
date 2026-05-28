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

const ReceivedRoute = struct {
    data: []const u8,
    route: quicz.endpoint.RouteResult,
};

const PacketThresholdResult = struct {
    client_port: u16,
    server_port: u16,
    remaining_packets: usize,
    bytes_in_flight: usize,
    ack_bytes: usize,
};

const TimeThresholdResult = struct {
    client_port: u16,
    server_port: u16,
    deadline_millis: i64,
    remaining_before_deadline: usize,
    remaining_after_deadline: usize,
    bytes_after_deadline: usize,
    ack_bytes: usize,
    timers_after_deadline: usize,
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

fn receiveRoute(
    io: std.Io,
    lifecycle: *const quicz.EndpointConnectionLifecycle,
    socket: *std.Io.net.Socket,
    receive_buf: []u8,
) !ReceivedRoute {
    const received = try socket.receiveTimeout(io, receive_buf, receiveTimeout());
    const path = try udp4Tuple(socket.address, received.from);
    return .{
        .data = received.data,
        .route = try lifecycle.routeDatagram(path, received.data),
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
    server_lifecycle: *const quicz.EndpointConnectionLifecycle,
    client: *quicz.QuicConnection,
    server: *quicz.QuicConnection,
    now_millis: i64,
    receive_buf: []u8,
    keys: quicz.protection.Aes128PacketProtectionKeys,
) !usize {
    try client.sendPing();
    const packet = (try client.pollProtectedShortDatagram(now_millis, &server_dcid, keys)) orelse return error.UnexpectedState;
    defer allocator.free(packet);

    try client_socket.send(io, &server_socket.address, packet);
    const received = try receiveRoute(io, server_lifecycle, server_socket, receive_buf);
    try require(received.route.connection_id == 51);
    try require(std.mem.eql(u8, received.route.destination_connection_id.asSlice(), &server_dcid));
    try server.processProtectedShortDatagram(now_millis + 1, keys, server_dcid.len, received.data);
    return packet.len;
}

fn sendServerAck(
    allocator: std.mem.Allocator,
    io: std.Io,
    server_socket: *std.Io.net.Socket,
    client_socket: *std.Io.net.Socket,
    client_lifecycle: *const quicz.EndpointConnectionLifecycle,
    client: *quicz.QuicConnection,
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
    const received = try receiveRoute(io, client_lifecycle, client_socket, receive_buf);
    try require(received.route.connection_id == 41);
    try require(std.mem.eql(u8, received.route.destination_connection_id.asSlice(), &client_dcid));
    try client.processProtectedShortDatagram(now_millis, keys, client_dcid.len, received.data);
    return packet.len;
}

fn runPacketThresholdPhase(allocator: std.mem.Allocator, io: std.Io) !PacketThresholdResult {
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

    var client = try quicz.QuicConnection.init(allocator, .client, .{});
    defer client.deinit();
    var server = try quicz.QuicConnection.init(allocator, .server, .{});
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

    var packet_lengths: [4]usize = undefined;
    packet_lengths[0] = try sendClientPing(allocator, io, &client_socket, &server_socket, &server_lifecycle, &client, &server, 10, &server_receive_buf, secrets.client);
    packet_lengths[1] = try sendClientPing(allocator, io, &client_socket, &server_socket, &server_lifecycle, &client, &server, 11, &server_receive_buf, secrets.client);
    packet_lengths[2] = try sendClientPing(allocator, io, &client_socket, &server_socket, &server_lifecycle, &client, &server, 12, &server_receive_buf, secrets.client);
    packet_lengths[3] = try sendClientPing(allocator, io, &client_socket, &server_socket, &server_lifecycle, &client, &server, 13, &server_receive_buf, secrets.client);
    try require(client.sentPacketCount(.application) == 4);
    try require(server.pendingAckLargest(.application) == 3);

    const ack_bytes = try sendServerAck(allocator, io, &server_socket, &client_socket, &client_lifecycle, &client, 70, 0, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    }, &client_receive_buf, secrets.server);

    const expected_remaining_bytes = packet_lengths[1] + packet_lengths[2];
    try require(client.sentPacketCount(.application) == 2);
    try require(client.bytesInFlight(.application) == expected_remaining_bytes);

    return .{
        .client_port = client_local.port,
        .server_port = server_local.port,
        .remaining_packets = client.sentPacketCount(.application),
        .bytes_in_flight = client.bytesInFlight(.application),
        .ack_bytes = ack_bytes,
    };
}

fn runTimeThresholdPhase(allocator: std.mem.Allocator, io: std.Io) !TimeThresholdResult {
    const client_connection_id: u64 = 41;

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

    var client = try quicz.QuicConnection.init(allocator, .client, .{});
    defer client.deinit();
    var server = try quicz.QuicConnection.init(allocator, .server, .{});
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

    const first_packet_len = try sendClientPing(allocator, io, &client_socket, &server_socket, &server_lifecycle, &client, &server, 300, &server_receive_buf, secrets.client);
    _ = try sendClientPing(allocator, io, &client_socket, &server_socket, &server_lifecycle, &client, &server, 500, &server_receive_buf, secrets.client);
    try require(client.sentPacketCount(.application) == 2);
    try require(server.pendingAckLargest(.application) == 1);

    const ack_bytes = try sendServerAck(allocator, io, &server_socket, &client_socket, &client_lifecycle, &client, 600, 0, .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    }, &client_receive_buf, secrets.server);

    try client_lifecycle.armRecoveryTimerFromConnection(client_connection_id, &client);
    const timer = client_lifecycle.earliestRecoveryDeadline() orelse return error.UnexpectedState;
    try require(timer.connection_id == client_connection_id);
    try require(timer.timer.space == .application);
    try require(timer.timer.kind == .loss_time);
    const deadline = timer.timer.deadline_millis;
    try require(client.sentPacketCount(.application) == 1);
    try require(client.bytesInFlight(.application) == first_packet_len);

    try require((try client_lifecycle.serviceRecoveryTimer(client_connection_id, &client, deadline - 1)) == null);
    const remaining_before_deadline = client.sentPacketCount(.application);
    try require(remaining_before_deadline == 1);
    try require(client.bytesInFlight(.application) == first_packet_len);
    try require(client_lifecycle.recoveryTimerCount() == 1);

    const serviced = (try client_lifecycle.serviceRecoveryTimer(client_connection_id, &client, deadline)) orelse return error.UnexpectedState;
    try require(serviced.connection_id == client_connection_id);
    try require(serviced.timer.space == .application);
    try require(serviced.timer.kind == .loss_time);
    try require(client.sentPacketCount(.application) == 0);
    try require(client.bytesInFlight(.application) == 0);
    try require(client_lifecycle.recoveryTimerCount() == 0);

    return .{
        .client_port = client_local.port,
        .server_port = server_local.port,
        .deadline_millis = deadline,
        .remaining_before_deadline = remaining_before_deadline,
        .remaining_after_deadline = client.sentPacketCount(.application),
        .bytes_after_deadline = client.bytesInFlight(.application),
        .ack_bytes = ack_bytes,
        .timers_after_deadline = client_lifecycle.recoveryTimerCount(),
    };
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const packet_threshold = try runPacketThresholdPhase(allocator, io);
    const time_threshold = try runTimeThresholdPhase(allocator, io);

    std.debug.print("[udp-loss] packet_client_port={} packet_server_port={} packet_remaining={} packet_inflight={} packet_ack_bytes={} time_client_port={} time_server_port={} time_deadline={} time_before_deadline={} time_remaining={} time_inflight={} time_ack_bytes={} time_timers={}\n", .{
        packet_threshold.client_port,
        packet_threshold.server_port,
        packet_threshold.remaining_packets,
        packet_threshold.bytes_in_flight,
        packet_threshold.ack_bytes,
        time_threshold.client_port,
        time_threshold.server_port,
        time_threshold.deadline_millis,
        time_threshold.remaining_before_deadline,
        time_threshold.remaining_after_deadline,
        time_threshold.bytes_after_deadline,
        time_threshold.ack_bytes,
        time_threshold.timers_after_deadline,
    });
}
