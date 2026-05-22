const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedRoundtrip};

const FixedReader = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn reader(self: *FixedReader) *FixedReader {
        return self;
    }

    pub fn readByte(self: *FixedReader) !u8 {
        if (self.pos >= self.data.len) return error.EndOfStream;
        const value = self.data[self.pos];
        self.pos += 1;
        return value;
    }

    pub fn readNoEof(self: *FixedReader, out: []u8) !void {
        if (self.data.len - self.pos < out.len) return error.EndOfStream;
        @memcpy(out, self.data[self.pos..][0..out.len]);
        self.pos += out.len;
    }

    pub fn remainingLen(self: FixedReader) usize {
        return self.data.len - self.pos;
    }
};

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

fn fixedReader(data: []const u8) FixedReader {
    return .{ .data = data };
}

fn fixedWriter(buffer: []u8) FixedWriter {
    return .{ .buffer = buffer };
}

fn require(condition: bool) ExampleError!void {
    if (!condition) return error.UnexpectedRoundtrip;
}

fn varintRoundtrip() !void {
    var raw: [8]u8 = undefined;
    var writer = fixedWriter(&raw);

    try quicz.packet.encodeVarInt(writer.writer(), 15_293);

    var reader = fixedReader(writer.getWritten());
    const decoded = try quicz.packet.decodeVarInt(reader.reader());
    try require(decoded.value == 15_293);
    try require(decoded.len == writer.getWritten().len);

    std.debug.print("[codec] varint value={} bytes={}\n", .{ decoded.value, decoded.len });
}

fn shortPacketRoundtrip(allocator: std.mem.Allocator) !void {
    const dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const packet_number: u64 = 0xa82f9b32;
    const expected_packet_number: u64 = 0xa82f30eb;
    const packet_number_encoding = quicz.packet.PacketNumberEncoding{
        .len = 2,
        .truncated_packet_number = 0x9b32,
    };
    const input = quicz.packet.ShortPacket{
        .header = .{
            .dcid = &dcid,
            .spin_bit = true,
            .key_phase = true,
            .packet_number = packet_number,
        },
        .payload = &[_]u8{ 0x06, 0x00, 0x01 },
    };

    var raw: [32]u8 = undefined;
    var writer = fixedWriter(&raw);
    try quicz.packet.encodeShortPacketWithPacketNumberEncoding(writer.writer(), input, packet_number_encoding);

    var parsed = try quicz.packet.parseShortPacketWithExpectedPacketNumber(
        writer.getWritten(),
        allocator,
        dcid.len,
        expected_packet_number,
    );
    defer quicz.packet.deinitShortPacket(&parsed, allocator);

    try require(std.mem.eql(u8, parsed.header.dcid, &dcid));
    try require(parsed.header.spin_bit == input.header.spin_bit);
    try require(parsed.header.key_phase == input.header.key_phase);
    try require(parsed.header.packet_number == input.header.packet_number);
    try require(std.mem.eql(u8, parsed.payload, input.payload));

    std.debug.print("[codec] short packet dcid_len={} spin={} packet_number=0x{x} payload_bytes={}\n", .{
        parsed.header.dcid.len,
        parsed.header.spin_bit,
        parsed.header.packet_number,
        parsed.payload.len,
    });
}

fn longPacketRoundtrip(allocator: std.mem.Allocator) !void {
    const initial_packet_number: u64 = 0xa82f9b32;
    const expected_initial_packet_number: u64 = 0xa82f30eb;
    const initial_packet_number_encoding = quicz.packet.PacketNumberEncoding{
        .len = 2,
        .truncated_packet_number = 0x9b32,
    };
    const initial = quicz.packet.LongPacket{
        .header = .{
            .version = .v1,
            .dcid = &[_]u8{ 0xca, 0xfe },
            .scid = &[_]u8{ 0xba, 0xbe },
            .packet_type = .initial,
            .token = &[_]u8{0x01},
            .packet_number = initial_packet_number,
            .payload_length = 0,
        },
        .payload = &[_]u8{ 0x06, 0x00 },
    };
    const handshake = quicz.packet.LongPacket{
        .header = .{
            .version = .v1,
            .dcid = &[_]u8{ 0xca, 0xfe },
            .scid = &[_]u8{ 0xba, 0xbe },
            .packet_type = .handshake,
            .token = &[_]u8{},
            .packet_number = 2,
            .payload_length = 0,
        },
        .payload = &[_]u8{ 0x06, 0x01, 0x02 },
    };

    var raw: [128]u8 = undefined;
    var writer = fixedWriter(&raw);
    try quicz.packet.encodeLongPacketWithPacketNumberEncoding(
        writer.writer(),
        initial,
        initial_packet_number_encoding,
    );
    const first_len = writer.getWritten().len;
    try quicz.packet.encodeLongPacket(writer.writer(), handshake);

    var parsed_initial = try quicz.packet.parseLongPacketWithExpectedPacketNumber(
        writer.getWritten(),
        allocator,
        expected_initial_packet_number,
    );
    defer quicz.packet.deinitLongPacket(&parsed_initial.packet, allocator);
    try require(parsed_initial.len == first_len);
    try require(parsed_initial.packet.header.packet_type == .initial);
    try require(parsed_initial.packet.header.packet_number == initial_packet_number);
    try require(parsed_initial.packet.header.payload_length == initial.payload.len);
    try require(std.mem.eql(u8, parsed_initial.packet.payload, initial.payload));

    var parsed_handshake = try quicz.packet.parseLongPacket(writer.getWritten()[parsed_initial.len..], allocator);
    defer quicz.packet.deinitLongPacket(&parsed_handshake.packet, allocator);
    try require(parsed_handshake.packet.header.packet_type == .handshake);
    try require(parsed_handshake.packet.header.payload_length == handshake.payload.len);
    try require(std.mem.eql(u8, parsed_handshake.packet.payload, handshake.payload));

    std.debug.print("[codec] long packets first={s} pn=0x{x} second={s} payload_bytes={}\n", .{
        @tagName(parsed_initial.packet.header.packet_type),
        parsed_initial.packet.header.packet_number,
        @tagName(parsed_handshake.packet.header.packet_type),
        parsed_initial.packet.payload.len + parsed_handshake.packet.payload.len,
    });
}

fn packetNumberEncodingExample() !void {
    const encoded = try quicz.packet.encodePacketNumberForHeader(0xac5c02, 0xabe8b3);
    try require(encoded.len == 2);
    try require(encoded.truncated_packet_number == 0x5c02);

    std.debug.print("[codec] packet number truncated=0x{x} bytes={}\n", .{
        encoded.truncated_packet_number,
        encoded.len,
    });
}

fn versionNegotiationRoundtrip(allocator: std.mem.Allocator) !void {
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const scid = [_]u8{ 0x0a, 0x0b, 0x0c, 0x0d };
    const versions = [_]quicz.packet.Version{ .v1, .v2 };
    const input = quicz.packet.VersionNegotiationPacket{
        .dcid = &dcid,
        .scid = &scid,
        .versions = &versions,
    };

    var raw: [64]u8 = undefined;
    var writer = fixedWriter(&raw);
    try quicz.packet.encodeVersionNegotiationPacket(writer.writer(), input);

    var parsed = try quicz.packet.parseVersionNegotiationPacket(writer.getWritten(), allocator);
    defer quicz.packet.deinitVersionNegotiationPacket(&parsed, allocator);

    try require(std.mem.eql(u8, parsed.dcid, &dcid));
    try require(std.mem.eql(u8, parsed.scid, &scid));
    try require(parsed.versions.len == versions.len);
    try require(parsed.versions[0] == .v1);
    try require(parsed.versions[1] == .v2);

    std.debug.print("[codec] version negotiation versions={}\n", .{parsed.versions.len});
}

fn streamFrameRoundtrip(allocator: std.mem.Allocator) !void {
    const input = quicz.frame.Frame{
        .stream = .{
            .stream_id = 0,
            .offset = 0,
            .fin = true,
            .data = "ping",
        },
    };

    var raw: [32]u8 = undefined;
    var writer = fixedWriter(&raw);
    try quicz.frame.encodeFrame(writer.writer(), input);

    var decoded = try quicz.frame.decodeFrameSlice(writer.getWritten(), allocator);
    defer quicz.frame.deinitFrame(&decoded.frame, allocator);

    try require(decoded.len == writer.getWritten().len);
    switch (decoded.frame) {
        .stream => |stream| {
            try require(stream.stream_id == 0);
            try require(stream.offset == 0);
            try require(stream.fin);
            try require(std.mem.eql(u8, stream.data, "ping"));
            std.debug.print("[codec] stream frame stream_id={} data_len={} fin={}\n", .{
                stream.stream_id,
                stream.data.len,
                stream.fin,
            });
        },
        else => return error.UnexpectedRoundtrip,
    }
}

fn transportParametersRoundtrip(allocator: std.mem.Allocator) !void {
    const initial_source_connection_id = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const input = quicz.transport_parameters.TransportParameters{
        .initial_max_data = 65_536,
        .initial_max_stream_data_bidi_local = 32_768,
        .initial_max_streams_bidi = 16,
        .initial_source_connection_id = &initial_source_connection_id,
    };

    var raw: [128]u8 = undefined;
    var writer = fixedWriter(&raw);
    try quicz.transport_parameters.encode(writer.writer(), input);

    var parsed = try quicz.transport_parameters.parse(writer.getWritten(), allocator);
    defer parsed.deinit(allocator);

    try require(parsed.initial_max_data == input.initial_max_data);
    try require(parsed.initial_max_stream_data_bidi_local == input.initial_max_stream_data_bidi_local);
    try require(parsed.initial_max_streams_bidi == input.initial_max_streams_bidi);
    try require(parsed.initial_source_connection_id != null);
    try require(std.mem.eql(u8, parsed.initial_source_connection_id.?, &initial_source_connection_id));

    std.debug.print("[codec] transport parameters max_data={} max_streams_bidi={}\n", .{
        parsed.initial_max_data,
        parsed.initial_max_streams_bidi,
    });
}

fn connectionTransportParameters(allocator: std.mem.Allocator) !void {
    const reset_token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

    var client = try quicz.QuicConnection.init(allocator, .client, .{
        .max_datagram_size = 1400,
        .disable_active_migration = true,
        .stateless_reset_token = reset_token,
        .initial_max_data = 4096,
        .initial_max_stream_data = 1024,
        .initial_max_streams_bidi = 4,
        .initial_max_streams_uni = 2,
    });
    defer client.deinit();

    const local = client.localTransportParameters();
    try require(local.max_udp_payload_size == 1400);
    try require(local.disable_active_migration);
    try require(local.stateless_reset_token == null);
    try require(local.initial_max_data == 4096);
    try require(local.initial_max_stream_data_bidi_remote == 1024);
    try require(local.initial_max_streams_bidi == 4);

    var server = try quicz.QuicConnection.init(allocator, .server, .{
        .stateless_reset_token = reset_token,
    });
    defer server.deinit();
    const server_local = server.localTransportParameters();
    const server_reset_token = server_local.stateless_reset_token orelse return error.UnexpectedRoundtrip;
    try require(std.mem.eql(u8, &server_reset_token, &reset_token));

    try client.applyPeerTransportParameters(.{
        .stateless_reset_token = reset_token,
        .max_udp_payload_size = 1200,
        .initial_max_data = 2048,
        .initial_max_stream_data_bidi_remote = 512,
        .initial_max_stream_data_uni = 256,
        .initial_max_streams_bidi = 1,
        .initial_max_streams_uni = 1,
        .disable_active_migration = true,
    });
    try require(client.peerActiveMigrationDisabled());
    const peer_reset_token = client.peerStatelessResetToken() orelse return error.UnexpectedRoundtrip;
    try require(std.mem.eql(u8, &peer_reset_token, &reset_token));

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello", true);
    if (client.openStream()) |_| {
        return error.UnexpectedRoundtrip;
    } else |err| {
        if (err != error.FlowControlBlocked) return err;
    }

    std.debug.print("[codec] connection transport params local_max_data={} migration_disabled={} reset_token={} server_reset_token={}\n", .{
        local.initial_max_data,
        client.peerActiveMigrationDisabled(),
        peer_reset_token.len,
        server_reset_token.len,
    });
}

fn transportErrorMapping() !void {
    const tls_alert: u8 = 42;
    const code = quicz.transport_error.cryptoErrorCode(tls_alert);
    const decoded_alert = quicz.transport_error.cryptoErrorAlert(code);

    try require(quicz.transport_error.isKnownCode(@intFromEnum(quicz.transport_error.TransportErrorCode.protocol_violation)));
    try require(quicz.transport_error.isCryptoErrorCode(code));
    try require(decoded_alert != null);
    try require(decoded_alert.? == tls_alert);

    std.debug.print("[codec] transport error tls_alert={} code=0x{x}\n", .{ tls_alert, code });
}

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    try varintRoundtrip();
    try shortPacketRoundtrip(gpa);
    try longPacketRoundtrip(gpa);
    try packetNumberEncodingExample();
    try versionNegotiationRoundtrip(gpa);
    try streamFrameRoundtrip(gpa);
    try transportParametersRoundtrip(gpa);
    try connectionTransportParameters(gpa);
    try transportErrorMapping();
}
