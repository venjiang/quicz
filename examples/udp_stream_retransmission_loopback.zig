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
    router: *const quicz.endpoint.EndpointRouter,
    socket: *std.Io.net.Socket,
    receive_buf: []u8,
) !ReceivedRoute {
    const received = try socket.receiveTimeout(io, receive_buf, receiveTimeout());
    const path = try udp4Tuple(socket.address, received.from);
    return .{
        .data = received.data,
        .route = try router.routeDatagram(path, received.data),
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
    client_router: *quicz.endpoint.EndpointRouter,
    server_router: *quicz.endpoint.EndpointRouter,
) !void {
    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    const server_path = try udp4Tuple(server_socket.address, client_socket.address);
    try client_router.registerConnectionId(41, &client_dcid, client_path, .{
        .active_migration_disabled = true,
    });
    try server_router.registerConnectionId(51, &server_dcid, server_path, .{
        .active_migration_disabled = true,
    });
}

fn sendClientPacket(
    io: std.Io,
    client_socket: *std.Io.net.Socket,
    server_socket: *std.Io.net.Socket,
    server_router: *const quicz.endpoint.EndpointRouter,
    server: *quicz.QuicConnection,
    now_millis: i64,
    packet: []const u8,
    receive_buf: []u8,
    keys: quicz.protection.Aes128PacketProtectionKeys,
) !void {
    try client_socket.send(io, &server_socket.address, packet);
    const received = try receiveRoute(io, server_router, server_socket, receive_buf);
    try require(received.route.connection_id == 51);
    try require(std.mem.eql(u8, received.route.destination_connection_id.asSlice(), &server_dcid));
    try server.processProtectedShortDatagram(now_millis, keys, server_dcid.len, received.data);
}

fn sendServerAck(
    allocator: std.mem.Allocator,
    io: std.Io,
    server_socket: *std.Io.net.Socket,
    client_socket: *std.Io.net.Socket,
    client_router: *const quicz.endpoint.EndpointRouter,
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
    const received = try receiveRoute(io, client_router, client_socket, receive_buf);
    try require(received.route.connection_id == 41);
    try require(std.mem.eql(u8, received.route.destination_connection_id.asSlice(), &client_dcid));
    try client.processProtectedShortDatagram(now_millis, keys, client_dcid.len, received.data);
    return packet.len;
}

fn retransmitContainsStream(
    allocator: std.mem.Allocator,
    packet: []const u8,
    keys: quicz.protection.Aes128PacketProtectionKeys,
    expected_packet_number: u64,
    stream_id: u64,
    expected_data: []const u8,
) !bool {
    var opened = try quicz.protection.unprotectShortPacketAes128(
        allocator,
        keys,
        packet,
        server_dcid.len,
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
                    stream.offset == 0 and
                    std.mem.eql(u8, stream.data, expected_data);
            },
            else => {},
        }
    }
    return false;
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

    var client_router = quicz.endpoint.EndpointRouter.init(allocator);
    defer client_router.deinit();
    var server_router = quicz.endpoint.EndpointRouter.init(allocator);
    defer server_router.deinit();
    try prepareLoopbackPair(&client_socket, &server_socket, &client_router, &server_router);

    var server_receive_buf: [1500]u8 = undefined;
    var client_receive_buf: [1500]u8 = undefined;

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "lost", false);
    const stream_packet = (try client.pollProtectedShortDatagram(10, &server_dcid, secrets.client)) orelse return error.UnexpectedState;
    defer allocator.free(stream_packet);
    try sendClientPacket(io, &client_socket, &server_socket, &server_router, &server, 11, stream_packet, &server_receive_buf, secrets.client);

    var read_buf: [16]u8 = undefined;
    const read_len = (try server.recvOnStream(stream_id, &read_buf)) orelse return error.UnexpectedState;
    try require(std.mem.eql(u8, read_buf[0..read_len], "lost"));
    try require((try server.recvOnStream(stream_id, &read_buf)) == null);

    var ping_count: usize = 0;
    while (ping_count < 3) : (ping_count += 1) {
        try client.sendPing();
        const ping_packet = (try client.pollProtectedShortDatagram(20 + @as(i64, @intCast(ping_count)), &server_dcid, secrets.client)) orelse return error.UnexpectedState;
        defer allocator.free(ping_packet);
        try sendClientPacket(
            io,
            &client_socket,
            &server_socket,
            &server_router,
            &server,
            30 + @as(i64, @intCast(ping_count)),
            ping_packet,
            &server_receive_buf,
            secrets.client,
        );
    }
    try require(client.sentPacketCount(.application) == 4);
    try require(server.pendingAckLargest(.application) == 3);

    const sparse_ack_bytes = try sendServerAck(allocator, io, &server_socket, &client_socket, &client_router, &client, 70, 0, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    }, &client_receive_buf, secrets.server);

    try require(client.sentPacketCount(.application) == 2);
    const retransmit_packet = (try client.pollProtectedShortDatagram(80, &server_dcid, secrets.client)) orelse return error.UnexpectedState;
    defer allocator.free(retransmit_packet);
    try require(try retransmitContainsStream(allocator, retransmit_packet, secrets.client, 4, stream_id, "lost"));

    try sendClientPacket(io, &client_socket, &server_socket, &server_router, &server, 81, retransmit_packet, &server_receive_buf, secrets.client);
    try require((try server.recvOnStream(stream_id, &read_buf)) == null);

    const final_ack_bytes = try sendServerAck(allocator, io, &server_socket, &client_socket, &client_router, &client, 90, 1, .{
        .largest_acknowledged = 4,
        .ack_delay = 0,
        .first_ack_range = 4,
    }, &client_receive_buf, secrets.server);

    try require(client.sentPacketCount(.application) == 0);
    try require(client.bytesInFlight(.application) == 0);

    std.debug.print("[udp-stream-retransmission] client_port={} server_port={} sparse_ack_bytes={} retransmit_bytes={} final_ack_bytes={} final_inflight={}\n", .{
        client_local.port,
        server_local.port,
        sparse_ack_bytes,
        retransmit_packet.len,
        final_ack_bytes,
        client.bytesInFlight(.application),
    });
}
