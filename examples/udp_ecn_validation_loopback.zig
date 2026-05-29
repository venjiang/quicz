const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

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

fn receiveProtectedShortDatagram(
    io: std.Io,
    lifecycle: *quicz.EndpointConnectionLifecycle,
    connection_id: u64,
    connection: *quicz.Connection,
    socket: *std.Io.net.Socket,
    receive_buf: []u8,
    now_millis: i64,
    keys: quicz.protection.Aes128PacketProtectionKeys,
) !quicz.endpoint.RouteResult {
    const received = try socket.receiveTimeout(io, receive_buf, receiveTimeout());
    const path = try udp4Tuple(socket.address, received.from);
    return try lifecycle.processRoutedProtectedShortDatagram(
        connection_id,
        connection,
        path,
        now_millis,
        keys,
        received.data,
    );
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

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var client_socket = try bindLoopbackUdp(io);
    defer client_socket.close(io);
    var server_socket = try bindLoopbackUdp(io);
    defer server_socket.close(io);
    var migrated_server_socket = try bindLoopbackUdp(io);
    defer migrated_server_socket.close(io);

    const client_local = try udp4Address(client_socket.address);
    const server_local = try udp4Address(server_socket.address);
    const migrated_local = try udp4Address(migrated_server_socket.address);
    try require(client_local.port != 0);
    try require(server_local.port != 0);
    try require(migrated_local.port != 0);
    try require(client_local.port != server_local.port);
    try require(server_local.port != migrated_local.port);

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try quicz.Connection.init(allocator, .client, .{});
    defer client.deinit();
    var server = try quicz.Connection.init(allocator, .server, .{});
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
    const migrated_path = try udp4Tuple(client_socket.address, migrated_server_socket.address);
    try client_lifecycle.registerConnectionId(41, &client_dcid, client_path, .{
        .active_migration_disabled = true,
    });
    try server_lifecycle.registerConnectionId(51, &server_dcid, server_path, .{
        .active_migration_disabled = true,
    });

    var server_receive_buf: [1500]u8 = undefined;
    var client_receive_buf: [1500]u8 = undefined;

    const ping_payload = [_]u8{
        @intFromEnum(quicz.frame.FrameType.ping),
        @intFromEnum(quicz.frame.FrameType.padding),
        @intFromEnum(quicz.frame.FrameType.padding),
    };
    const ecn_ping = try protectShortPacket(allocator, &server_dcid, 0, secrets.client, &ping_payload);
    defer allocator.free(ecn_ping);
    try require(try client.recordEcnPacketSentInSpace(.application, 0, ecn_ping.len, .ect0) == 0);
    try client_socket.send(io, &server_socket.address, ecn_ping);

    const ping_route = try receiveProtectedShortDatagram(
        io,
        &server_lifecycle,
        51,
        &server,
        &server_socket,
        &server_receive_buf,
        1,
        secrets.client,
    );
    try require(ping_route.connection_id == 51);
    try require(std.mem.eql(u8, ping_route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.pendingAckLargest(.application) == 0);

    var ack_ecn_payload: [64]u8 = undefined;
    var ack_ecn_out = fixedWriter(&ack_ecn_payload);
    try quicz.frame.encodeFrame(ack_ecn_out.writer(), .{ .ack_ecn = .{
        .ack = .{
            .largest_acknowledged = 0,
            .ack_delay = 0,
            .first_ack_range = 0,
        },
        .ecn_counts = .{
            .ect0_count = 1,
            .ect1_count = 0,
            .ecn_ce_count = 0,
        },
    } });
    const ack_ecn = try protectShortPacket(allocator, &client_dcid, 0, secrets.server, ack_ecn_out.getWritten());
    defer allocator.free(ack_ecn);
    try server_socket.send(io, &client_socket.address, ack_ecn);

    const ack_ecn_route = try receiveProtectedShortDatagram(
        io,
        &client_lifecycle,
        41,
        &client,
        &client_socket,
        &client_receive_buf,
        2,
        secrets.server,
    );
    try require(ack_ecn_route.connection_id == 41);
    try require(std.mem.eql(u8, ack_ecn_route.destination_connection_id.asSlice(), &client_dcid));

    try require(client.bytesInFlight(.application) == 0);
    try require(client.sentPacketCount(.application) == 0);
    try require(client.ecnValidationState(.application) == .capable);
    try require(client.ecnCounts(.application).ect0_count == 1);
    const no_ce_cwnd = client.congestionWindow(.application);

    const ce_ping = try protectShortPacket(allocator, &server_dcid, 1, secrets.client, &ping_payload);
    defer allocator.free(ce_ping);
    try require(try client.recordEcnPacketSentInSpace(.application, 10, ce_ping.len, .ect0) == 1);
    try client_socket.send(io, &server_socket.address, ce_ping);

    const ce_ping_route = try receiveProtectedShortDatagram(
        io,
        &server_lifecycle,
        51,
        &server,
        &server_socket,
        &server_receive_buf,
        11,
        secrets.client,
    );
    try require(ce_ping_route.connection_id == 51);
    try require(std.mem.eql(u8, ce_ping_route.destination_connection_id.asSlice(), &server_dcid));
    try require(server.pendingAckLargest(.application) == 1);

    var ce_ack_payload: [64]u8 = undefined;
    var ce_ack_out = fixedWriter(&ce_ack_payload);
    try quicz.frame.encodeFrame(ce_ack_out.writer(), .{ .ack_ecn = .{
        .ack = .{
            .largest_acknowledged = 1,
            .ack_delay = 0,
            .first_ack_range = 0,
        },
        .ecn_counts = .{
            .ect0_count = 1,
            .ect1_count = 0,
            .ecn_ce_count = 1,
        },
    } });
    const ce_ack = try protectShortPacket(allocator, &client_dcid, 1, secrets.server, ce_ack_out.getWritten());
    defer allocator.free(ce_ack);
    try server_socket.send(io, &client_socket.address, ce_ack);

    const ce_ack_route = try receiveProtectedShortDatagram(
        io,
        &client_lifecycle,
        41,
        &client,
        &client_socket,
        &client_receive_buf,
        12,
        secrets.server,
    );
    try require(ce_ack_route.connection_id == 41);
    try require(std.mem.eql(u8, ce_ack_route.destination_connection_id.asSlice(), &client_dcid));

    const ce_cwnd = client.congestionWindow(.application);
    try require(client.bytesInFlight(.application) == 0);
    try require(client.sentPacketCount(.application) == 0);
    try require(client.ecnValidationState(.application) == .capable);
    try require(client.ecnCounts(.application).ecn_ce_count == 1);
    try require(ce_cwnd == @max(no_ce_cwnd / 2, quicz.recovery.minimumCongestionWindow(1350)));

    const refreshed_ecn_state = try client_lifecycle.refreshEcnPathStateFromConnection(client_path, &client, .application);
    try require(refreshed_ecn_state == .capable);
    try require(client_lifecycle.ecnPathState(client_path) == .capable);
    try require(client_lifecycle.ecnPathState(migrated_path) == .unknown);
    try require(client_lifecycle.mayUseEctOnPath(migrated_path));

    std.debug.print("[udp-ecn] client_port={} server_port={} migrated_port={} ping_bytes={} ack_ecn_bytes={} ce_ping_bytes={} ce_ack_bytes={} client_ecn={s} path_ecn={s} migrated_ecn={s} ect0_count={} ce_count={} no_ce_cwnd={} ce_cwnd={} client_inflight={}\n", .{
        client_local.port,
        server_local.port,
        migrated_local.port,
        ecn_ping.len,
        ack_ecn.len,
        ce_ping.len,
        ce_ack.len,
        @tagName(client.ecnValidationState(.application)),
        @tagName(client_lifecycle.ecnPathState(client_path)),
        @tagName(client_lifecycle.ecnPathState(migrated_path)),
        client.ecnCounts(.application).ect0_count,
        client.ecnCounts(.application).ecn_ce_count,
        no_ce_cwnd,
        ce_cwnd,
        client.bytesInFlight(.application),
    });
}
