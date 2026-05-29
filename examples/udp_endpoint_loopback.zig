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

fn buildInitialDatagram(
    out: []u8,
    version: quicz.packet.Version,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
    payload: []const u8,
) ![]const u8 {
    var writer = fixedWriter(out);
    try quicz.packet.encodeLongPacket(writer.writer(), .{
        .header = .{
            .version = version,
            .dcid = dcid,
            .scid = scid,
            .packet_type = .initial,
            .token = token,
            .packet_number = 0,
            .payload_length = 0,
        },
        .payload = payload,
    });
    return writer.getWritten();
}

pub fn main() !void {
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
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

    var client_lifecycle = quicz.EndpointConnectionLifecycle.init(std.heap.page_allocator);
    defer client_lifecycle.deinit();
    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(std.heap.page_allocator);
    defer server_lifecycle.deinit();

    const supported_versions = [_]quicz.packet.Version{ .v1, .v2 };
    const reset_prefix = [_]u8{ 0x40, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x99 };

    const unsupported_version: quicz.packet.Version = @enumFromInt(0xfa_ce_b0_0c);
    const client_versions = [_]quicz.packet.Version{ .v2, .v1, unsupported_version };
    const original_dcid = [_]u8{ 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88 };
    const client_initial_scid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };

    var unsupported_initial_raw: [64]u8 = undefined;
    const unsupported_initial = try buildInitialDatagram(
        &unsupported_initial_raw,
        unsupported_version,
        &original_dcid,
        &client_initial_scid,
        &.{},
        &[_]u8{0x01},
    );

    try client_socket.send(io, &server_socket.address, unsupported_initial);

    var server_receive_buf: [1500]u8 = undefined;
    const unsupported_received = try server_socket.receiveTimeout(io, &server_receive_buf, receiveTimeout());
    const unsupported_path = try udp4Tuple(server_socket.address, unsupported_received.from);

    var response_out: [256]u8 = undefined;
    const version_negotiation_action = try server_lifecycle.handleDatagramWithVersionNegotiation(
        &response_out,
        unsupported_path,
        unsupported_received.data,
        &reset_prefix,
        &supported_versions,
    );
    const version_negotiation = switch (version_negotiation_action) {
        .version_negotiation => |response| response,
        else => return error.UnexpectedState,
    };
    try server_socket.send(io, &unsupported_received.from, version_negotiation);

    var client_receive_buf: [1500]u8 = undefined;
    const version_negotiation_received = try client_socket.receiveTimeout(io, &client_receive_buf, receiveTimeout());
    var parsed_version_negotiation = try quicz.packet.parseVersionNegotiationPacket(
        version_negotiation_received.data,
        std.heap.page_allocator,
    );
    defer quicz.packet.deinitVersionNegotiationPacket(&parsed_version_negotiation, std.heap.page_allocator);
    try require(std.mem.eql(u8, parsed_version_negotiation.dcid, &client_initial_scid));
    try require(std.mem.eql(u8, parsed_version_negotiation.scid, &original_dcid));
    try require(parsed_version_negotiation.versions.len == supported_versions.len);

    var version_negotiation_client = try quicz.Connection.init(std.heap.page_allocator, .client, .{
        .chosen_version = unsupported_version,
        .available_versions = &client_versions,
    });
    defer version_negotiation_client.deinit();
    const selected_version = (try version_negotiation_client.processVersionNegotiationDatagram(
        0,
        &original_dcid,
        &client_initial_scid,
        version_negotiation_received.data,
    )) orelse return error.UnexpectedState;
    try require(selected_version == .v2);
    try require(version_negotiation_client.versionNegotiationSelectedVersion() == .v2);

    const client_path = try udp4Tuple(client_socket.address, server_socket.address);
    _ = try client_lifecycle.registerClientInitialSourceConnectionId(31, &client_initial_scid, client_path, .{
        .active_migration_disabled = true,
    });
    try require(client_lifecycle.routeCount() == 1);

    const initial_token = [_]u8{ 0xa1, 0xa2 };
    var supported_initial_raw: [64]u8 = undefined;
    const supported_initial = try buildInitialDatagram(
        &supported_initial_raw,
        .v1,
        &original_dcid,
        &client_initial_scid,
        &initial_token,
        &[_]u8{ 0x02, 0x00, 0xff },
    );
    try client_socket.send(io, &server_socket.address, supported_initial);

    const supported_received = try server_socket.receiveTimeout(io, &server_receive_buf, receiveTimeout());
    const supported_path = try udp4Tuple(server_socket.address, supported_received.from);
    const accept_action = try server_lifecycle.handleDatagramWithVersionNegotiation(
        &response_out,
        supported_path,
        supported_received.data,
        &reset_prefix,
        &supported_versions,
    );

    const server_initial_scid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const server_reset_token = [_]u8{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    const accepted_route = switch (accept_action) {
        .accept_initial => |accept| blk: {
            try require(accept.version == .v1);
            try require(std.mem.eql(u8, accept.original_destination_connection_id, &original_dcid));
            try require(std.mem.eql(u8, accept.source_connection_id, &client_initial_scid));
            try require(std.mem.eql(u8, accept.token, &initial_token));
            break :blk try server_lifecycle.registerAcceptedInitialConnectionIds(21, accept, &server_initial_scid, .{
                .active_migration_disabled = true,
                .stateless_reset_token = server_reset_token,
            });
        },
        else => return error.UnexpectedState,
    };
    try require(accepted_route.original_destination_route.connection_id == 21);
    try require(accepted_route.server_source_route.connection_id == 21);
    try require(server_lifecycle.routeCount() == 2);

    var server_initial_raw: [64]u8 = undefined;
    const server_initial = try buildInitialDatagram(
        &server_initial_raw,
        .v1,
        &client_initial_scid,
        &server_initial_scid,
        &.{},
        &[_]u8{ 0x06, 0x00 },
    );
    try server_socket.send(io, &supported_received.from, server_initial);

    const server_initial_received = try client_socket.receiveTimeout(io, &client_receive_buf, receiveTimeout());
    const server_initial_path = try udp4Tuple(client_socket.address, server_initial_received.from);
    const client_route = try client_lifecycle.routeDatagram(server_initial_path, server_initial_received.data);
    try require(client_route.connection_id == 31);
    try require(std.mem.eql(u8, client_route.destination_connection_id.asSlice(), &client_initial_scid));

    const short_followup = [_]u8{ 0x40, 0xb1, 0xb2, 0xb3, 0xb4, 0x01 };
    try client_socket.send(io, &server_socket.address, &short_followup);
    const short_received = try server_socket.receiveTimeout(io, &server_receive_buf, receiveTimeout());
    const short_path = try udp4Tuple(server_socket.address, short_received.from);
    const server_route = try server_lifecycle.routeDatagram(short_path, short_received.data);
    try require(server_route.connection_id == 21);
    try require(std.mem.eql(u8, server_route.destination_connection_id.asSlice(), &server_initial_scid));

    std.debug.print("[udp-endpoint] client_port={} server_port={} vn_versions={} vn_selected=0x{x} accepted={} client_route={} server_route={} response_bytes={}\n", .{
        client_local.port,
        server_local.port,
        parsed_version_negotiation.versions.len,
        @intFromEnum(selected_version),
        accepted_route.server_source_route.connection_id,
        client_route.connection_id,
        server_route.connection_id,
        version_negotiation.len,
    });
}
