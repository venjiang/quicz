const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{TransportParameterExampleFailed};

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

fn require(condition: bool) !void {
    if (!condition) return error.TransportParameterExampleFailed;
}

fn requireError(expected: anyerror, result: anytype) !void {
    _ = result catch |err| {
        if (err == expected) return;
        return err;
    };
    return error.TransportParameterExampleFailed;
}

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    const reset_token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const preferred_cid = [_]u8{ 0xc1, 0xd1, 0xe1, 0xf1 };
    const preferred = try quicz.PreferredAddress.init(
        .{ 192, 0, 2, 7 },
        4433,
        .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7 },
        4434,
        &preferred_cid,
        reset_token,
    );

    var client = try quicz.Connection.init(allocator, .client, .{
        .max_idle_timeout_ms = 300,
        .ack_delay_exponent = 4,
        .max_ack_delay_ms = 33,
        .initial_max_data = 256,
        .initial_max_stream_data = 64,
        .initial_max_streams_bidi = 2,
    });
    defer client.deinit();

    var server = try quicz.Connection.init(allocator, .server, .{
        .max_datagram_size = 1200,
        .max_idle_timeout_ms = 200,
        .ack_delay_exponent = 5,
        .max_ack_delay_ms = 40,
        .disable_active_migration = true,
        .stateless_reset_token = reset_token,
        .preferred_address = preferred,
        .initial_max_data = 128,
        .initial_max_stream_data = 32,
        .initial_max_streams_bidi = 1,
    });
    defer server.deinit();

    var client_extension: [512]u8 = undefined;
    const client_bytes = try client.encodeLocalTransportParameters(&client_extension);
    var greased_client_extension: [640]u8 = undefined;
    var greased_client_writer = fixedWriter(&greased_client_extension);
    try quicz.transport_parameters.encodeReservedParameter(greased_client_writer.writer(), 27, "grease");
    try greased_client_writer.writeAll(client_bytes);
    const greased_client_bytes = greased_client_writer.getWritten();
    try require(quicz.transport_parameters.isReservedParameterId(27));

    var parsed_client = try quicz.transport_parameters.parse(greased_client_bytes, allocator);
    defer parsed_client.deinit(allocator);
    try require(parsed_client.stateless_reset_token == null);
    try require(parsed_client.preferred_address == null);
    try require(parsed_client.ack_delay_exponent == 4);
    try server.applyPeerTransportParameterBytes(greased_client_bytes);

    var server_extension: [512]u8 = undefined;
    const server_bytes = try server.encodeLocalTransportParameters(&server_extension);
    var parsed_server = try quicz.transport_parameters.parse(server_bytes, allocator);
    defer parsed_server.deinit(allocator);
    try require(parsed_server.stateless_reset_token != null);
    try require(parsed_server.preferred_address != null);
    try require(parsed_server.disable_active_migration);
    try client.applyPeerTransportParameterBytes(server_bytes);

    try require(client.effectiveIdleTimeoutMillis() == 200);
    try require(client.recovery_state.max_datagram_size == 1200);
    try require(client.congestionWindow(.application) == quicz.recovery.initialCongestionWindow(1200));
    try require(client.peerActiveMigrationDisabled());
    const stored_token = client.peerStatelessResetToken() orelse return error.TransportParameterExampleFailed;
    try require(std.mem.eql(u8, &stored_token, &reset_token));
    const stored_preferred = client.peerPreferredAddress() orelse return error.TransportParameterExampleFailed;
    try require(std.mem.eql(u8, stored_preferred.connectionId(), &preferred_cid));

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "01234567890123456789012345678901", false);
    try requireError(error.FlowControlBlocked, client.sendOnStream(stream_id, "x", false));

    var invalid_client_extension: [64]u8 = undefined;
    var invalid_writer = fixedWriter(&invalid_client_extension);
    try quicz.transport_parameters.encode(invalid_writer.writer(), .{
        .stateless_reset_token = reset_token,
    });
    try requireError(error.InvalidPacket, server.applyPeerTransportParameterBytes(invalid_writer.getWritten()));

    var auto_close_server = try quicz.Connection.init(allocator, .server, .{});
    defer auto_close_server.deinit();
    try auto_close_server.validatePeerAddress();
    try requireError(
        error.InvalidPacket,
        auto_close_server.applyPeerTransportParameterBytesOrClose(invalid_writer.getWritten()),
    );

    var close_payload_buf: [96]u8 = undefined;
    const close_payload = (try auto_close_server.pollTx(0, &close_payload_buf)) orelse return error.TransportParameterExampleFailed;
    var decoded_close = try quicz.frame.decodeFrameSlice(close_payload, allocator);
    defer quicz.frame.deinitFrame(&decoded_close.frame, allocator);
    var close_error_code: u64 = 0;
    var close_frame_type: u64 = 0;
    switch (decoded_close.frame) {
        .connection_close => |close| {
            close_error_code = close.error_code;
            close_frame_type = close.frame_type;
            try require(close_error_code == quicz.transport_error.codeValue(.transport_parameter_error));
            try require(close_frame_type == @intFromEnum(quicz.frame.FrameType.crypto));
        },
        else => return error.TransportParameterExampleFailed,
    }

    std.debug.print(
        "[transport-parameters] client_bytes={} server_bytes={} effective_idle_ms={} recovery_mds={} recovery_cwnd={} preferred_cid_len={} reserved_ignored=true stream_limit_blocked=true invalid_client_server_only_rejected=true auto_close_code={} auto_close_frame_type={}\n",
        .{
            greased_client_bytes.len,
            server_bytes.len,
            client.effectiveIdleTimeoutMillis().?,
            client.recovery_state.max_datagram_size,
            client.congestionWindow(.application),
            stored_preferred.connectionId().len,
            close_error_code,
            close_frame_type,
        },
    );
}
