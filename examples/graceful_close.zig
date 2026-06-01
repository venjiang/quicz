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

fn requireError(expected: anyerror, result: anyerror!void) !void {
    result catch |err| {
        if (err == expected) return;
        return err;
    };
    return error.UnexpectedState;
}

fn requireUsizeError(expected: anyerror, result: anyerror!usize) !void {
    _ = result catch |err| {
        if (err == expected) return;
        return err;
    };
    return error.UnexpectedState;
}

fn requireRouteError(expected: anyerror, result: anyerror!quicz.endpoint.RouteResult) !void {
    _ = result catch |err| {
        if (err == expected) return;
        return err;
    };
    return error.UnexpectedState;
}

fn pollRequired(conn: *quicz.Connection, out: []u8) ![]const u8 {
    return (try conn.pollTx(0, out)) orelse error.UnexpectedState;
}

fn requirePollError(expected: anyerror, result: anyerror!?[]u8) !void {
    _ = result catch |err| {
        if (err == expected) return;
        return err;
    };
    return error.UnexpectedState;
}

fn printConnectionClose(gpa: std.mem.Allocator, payload: []const u8) !void {
    var decoded = try quicz.frame.decodeFrameSlice(payload, gpa);
    defer quicz.frame.deinitFrame(&decoded.frame, gpa);
    if (decoded.len != payload.len) return error.UnexpectedState;

    switch (decoded.frame) {
        .connection_close => |close| {
            std.debug.print(
                "[close] connection close error={} frame_type={} reason={s}\n",
                .{ close.error_code, close.frame_type, close.reason_phrase },
            );
        },
        else => return error.UnexpectedState,
    }
}

fn printApplicationClose(gpa: std.mem.Allocator, payload: []const u8) !void {
    var decoded = try quicz.frame.decodeFrameSlice(payload, gpa);
    defer quicz.frame.deinitFrame(&decoded.frame, gpa);
    if (decoded.len != payload.len) return error.UnexpectedState;

    switch (decoded.frame) {
        .application_close => |close| {
            std.debug.print(
                "[close] application close error={} reason={s}\n",
                .{ close.error_code, close.reason_phrase },
            );
        },
        else => return error.UnexpectedState,
    }
}

fn printPeerClose(prefix: []const u8, close: quicz.PeerClose) void {
    switch (close) {
        .connection => |connection| {
            std.debug.print(
                "[close] {s} peer transport close error={} frame_type={} reason={s}\n",
                .{ prefix, connection.error_code, connection.frame_type, connection.reason_phrase },
            );
        },
        .application => |application| {
            std.debug.print(
                "[close] {s} peer application close error={} reason={s}\n",
                .{ prefix, application.error_code, application.reason_phrase },
            );
        },
    }
}

fn framePayloadAutoCloseExample(gpa: std.mem.Allocator) !void {
    var default_server = try quicz.Connection.init(gpa, .server, .{});
    defer default_server.deinit();
    try default_server.validatePeerAddress();

    const unknown_payload = [_]u8{0x1f};
    try requireError(
        error.InvalidPacket,
        default_server.processDatagramOrClose(0, &unknown_payload),
    );
    var close_payload_buf: [64]u8 = undefined;
    const default_close = try pollRequired(&default_server, &close_payload_buf);
    try printConnectionClose(gpa, default_close);
    std.debug.print(
        "[close] default auto close state={s} after unknown frame\n",
        .{@tagName(default_server.connectionState())},
    );

    var ack_range_server = try quicz.Connection.init(gpa, .server, .{});
    defer ack_range_server.deinit();
    try ack_range_server.validatePeerAddress();

    const invalid_ack_range_payload = [_]u8{
        @intFromEnum(quicz.frame.FrameType.ack),
        0x00, // largest acknowledged
        0x00, // ack delay
        0x00, // no additional ACK ranges
        0x01, // first ACK range larger than largest acknowledged
    };
    try requireError(
        error.InvalidPacket,
        ack_range_server.processDatagramOrClose(0, &invalid_ack_range_payload),
    );
    const ack_range_close = try pollRequired(&ack_range_server, &close_payload_buf);
    try printConnectionClose(gpa, ack_range_close);
    std.debug.print(
        "[close] default auto close state={s} after invalid ACK range\n",
        .{@tagName(ack_range_server.connectionState())},
    );

    var ack_ecn_range_server = try quicz.Connection.init(gpa, .server, .{});
    defer ack_ecn_range_server.deinit();
    try ack_ecn_range_server.validatePeerAddress();

    const invalid_ack_ecn_range_payload = [_]u8{
        @intFromEnum(quicz.frame.FrameType.ack_ecn),
        0x00, // largest acknowledged
        0x00, // ack delay
        0x00, // no additional ACK ranges
        0x01, // first ACK range larger than largest acknowledged
    };
    try requireError(
        error.InvalidPacket,
        ack_ecn_range_server.processDatagramOrClose(0, &invalid_ack_ecn_range_payload),
    );
    const ack_ecn_range_close = try pollRequired(&ack_ecn_range_server, &close_payload_buf);
    try printConnectionClose(gpa, ack_ecn_range_close);
    std.debug.print(
        "[close] default auto close state={s} after invalid ACK_ECN range\n",
        .{@tagName(ack_ecn_range_server.connectionState())},
    );

    var streams_blocked_bidi_server = try quicz.Connection.init(gpa, .server, .{});
    defer streams_blocked_bidi_server.deinit();
    try streams_blocked_bidi_server.validatePeerAddress();

    var invalid_streams_blocked_bidi: [16]u8 = undefined;
    var streams_blocked_bidi_out = fixedWriter(&invalid_streams_blocked_bidi);
    try streams_blocked_bidi_out.writer().writeByte(@intFromEnum(quicz.frame.FrameType.streams_blocked_bidi));
    try quicz.packet.encodeVarInt(streams_blocked_bidi_out.writer(), (@as(u64, 1) << 60) + 1);
    try requireError(
        error.InvalidPacket,
        streams_blocked_bidi_server.processDatagramOrClose(0, streams_blocked_bidi_out.getWritten()),
    );
    const streams_blocked_bidi_close = try pollRequired(&streams_blocked_bidi_server, &close_payload_buf);
    try printConnectionClose(gpa, streams_blocked_bidi_close);
    std.debug.print(
        "[close] default auto close state={s} after invalid STREAMS_BLOCKED_BIDI limit\n",
        .{@tagName(streams_blocked_bidi_server.connectionState())},
    );

    var streams_blocked_uni_server = try quicz.Connection.init(gpa, .server, .{});
    defer streams_blocked_uni_server.deinit();
    try streams_blocked_uni_server.validatePeerAddress();

    var invalid_streams_blocked_uni: [16]u8 = undefined;
    var streams_blocked_uni_out = fixedWriter(&invalid_streams_blocked_uni);
    try streams_blocked_uni_out.writer().writeByte(@intFromEnum(quicz.frame.FrameType.streams_blocked_uni));
    try quicz.packet.encodeVarInt(streams_blocked_uni_out.writer(), (@as(u64, 1) << 60) + 1);
    try requireError(
        error.InvalidPacket,
        streams_blocked_uni_server.processDatagramOrClose(0, streams_blocked_uni_out.getWritten()),
    );
    const streams_blocked_uni_close = try pollRequired(&streams_blocked_uni_server, &close_payload_buf);
    try printConnectionClose(gpa, streams_blocked_uni_close);
    std.debug.print(
        "[close] default auto close state={s} after invalid STREAMS_BLOCKED_UNI limit\n",
        .{@tagName(streams_blocked_uni_server.connectionState())},
    );

    var initial_server = try quicz.Connection.init(gpa, .server, .{});
    defer initial_server.deinit();
    try initial_server.validatePeerAddress();

    const handshake_done = [_]u8{@intFromEnum(quicz.frame.FrameType.handshake_done)};
    try requireError(
        error.InvalidPacket,
        initial_server.processDatagramInSpaceOrClose(.initial, 0, &handshake_done),
    );
    const initial_close = try pollRequired(&initial_server, &close_payload_buf);
    try printConnectionClose(gpa, initial_close);
    std.debug.print(
        "[close] initial auto close state={s} after forbidden HANDSHAKE_DONE\n",
        .{@tagName(initial_server.connectionState())},
    );
}

fn packetTypeAutoCloseExample(gpa: std.mem.Allocator) !void {
    var server = try quicz.Connection.init(gpa, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    const ack_payload = [_]u8{
        @intFromEnum(quicz.frame.FrameType.ack),
        0,
        0,
        0,
        0,
    };

    try requireError(
        error.InvalidPacket,
        server.processDatagramForPacketTypeOrClose(.zero_rtt, 0, &ack_payload),
    );

    var close_payload_buf: [64]u8 = undefined;
    const close_payload = try pollRequired(&server, &close_payload_buf);
    try printConnectionClose(gpa, close_payload);
    std.debug.print(
        "[close] auto close state={s} after invalid 0-RTT ACK\n",
        .{@tagName(server.connectionState())},
    );

    var ack_ecn_server = try quicz.Connection.init(gpa, .server, .{});
    defer ack_ecn_server.deinit();
    try ack_ecn_server.validatePeerAddress();

    var ack_ecn_payload_buf: [32]u8 = undefined;
    var ack_ecn_out = fixedWriter(&ack_ecn_payload_buf);
    try quicz.frame.encodeFrame(ack_ecn_out.writer(), .{ .ack_ecn = .{
        .ack = .{
            .largest_acknowledged = 0,
            .ack_delay = 0,
            .first_ack_range = 0,
        },
        .ecn_counts = .{
            .ect0_count = 0,
            .ect1_count = 0,
            .ecn_ce_count = 0,
        },
    } });

    try requireError(
        error.InvalidPacket,
        ack_ecn_server.processDatagramForPacketTypeOrClose(.zero_rtt, 0, ack_ecn_out.getWritten()),
    );

    const ack_ecn_close_payload = try pollRequired(&ack_ecn_server, &close_payload_buf);
    try printConnectionClose(gpa, ack_ecn_close_payload);
    std.debug.print(
        "[close] auto close state={s} after invalid 0-RTT ACK_ECN\n",
        .{@tagName(ack_ecn_server.connectionState())},
    );
}

fn semanticFrameAutoCloseExample(gpa: std.mem.Allocator) !void {
    var server = try quicz.Connection.init(gpa, .server, .{
        .initial_max_data = 16,
        .initial_max_stream_data = 0,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    var stream_payload: [32]u8 = undefined;
    var out = fixedWriter(&stream_payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "x",
    } });

    try requireError(
        error.InvalidPacket,
        server.processDatagramOrClose(0, out.getWritten()),
    );

    var close_payload_buf: [64]u8 = undefined;
    const close_payload = try pollRequired(&server, &close_payload_buf);
    var decoded = try quicz.frame.decodeFrameSlice(close_payload, gpa);
    defer quicz.frame.deinitFrame(&decoded.frame, gpa);
    if (decoded.len != close_payload.len) return error.UnexpectedState;

    switch (decoded.frame) {
        .connection_close => |close| {
            if (close.error_code != quicz.transport_error.codeValue(.flow_control_error)) return error.UnexpectedState;
            std.debug.print(
                "[close] semantic auto close error={} frame_type={} reason={s} state={s}\n",
                .{ close.error_code, close.frame_type, close.reason_phrase, @tagName(server.connectionState()) },
            );
        },
        else => return error.UnexpectedState,
    }

    var ack_client = try quicz.Connection.init(gpa, .client, .{});
    defer ack_client.deinit();
    const ack_stream_id = try ack_client.openStream();
    try ack_client.sendOnStream(ack_stream_id, "hello", false);
    var sent_payload_buf: [128]u8 = undefined;
    _ = try pollRequired(&ack_client, &sent_payload_buf);

    var ack_payload: [32]u8 = undefined;
    out = fixedWriter(&ack_payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .ack = .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    } });
    try requireError(
        error.InvalidPacket,
        ack_client.processDatagramOrClose(60, out.getWritten()),
    );

    var ack_close_buf: [64]u8 = undefined;
    const ack_close_payload = try pollRequired(&ack_client, &ack_close_buf);
    var ack_close = try quicz.frame.decodeFrameSlice(ack_close_payload, gpa);
    defer quicz.frame.deinitFrame(&ack_close.frame, gpa);
    if (ack_close.len != ack_close_payload.len) return error.UnexpectedState;

    switch (ack_close.frame) {
        .connection_close => |close| {
            if (close.error_code != quicz.transport_error.codeValue(.protocol_violation)) return error.UnexpectedState;
            std.debug.print(
                "[close] semantic ack auto close error={} frame_type={} reason={s} state={s}\n",
                .{ close.error_code, close.frame_type, close.reason_phrase, @tagName(ack_client.connectionState()) },
            );
        },
        else => return error.UnexpectedState,
    }

    var ack_ecn_client = try quicz.Connection.init(gpa, .client, .{});
    defer ack_ecn_client.deinit();
    const ack_ecn_stream_id = try ack_ecn_client.openStream();
    try ack_ecn_client.sendOnStream(ack_ecn_stream_id, "hello", false);
    var ack_ecn_sent_payload_buf: [128]u8 = undefined;
    _ = try pollRequired(&ack_ecn_client, &ack_ecn_sent_payload_buf);

    var ack_ecn_payload: [32]u8 = undefined;
    out = fixedWriter(&ack_ecn_payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .ack_ecn = .{
        .ack = .{
            .largest_acknowledged = 1,
            .ack_delay = 0,
            .first_ack_range = 0,
        },
        .ecn_counts = .{
            .ect0_count = 0,
            .ect1_count = 0,
            .ecn_ce_count = 0,
        },
    } });
    try requireError(
        error.InvalidPacket,
        ack_ecn_client.processDatagramOrClose(60, out.getWritten()),
    );

    var ack_ecn_close_buf: [64]u8 = undefined;
    const ack_ecn_close_payload = try pollRequired(&ack_ecn_client, &ack_ecn_close_buf);
    var ack_ecn_close = try quicz.frame.decodeFrameSlice(ack_ecn_close_payload, gpa);
    defer quicz.frame.deinitFrame(&ack_ecn_close.frame, gpa);
    if (ack_ecn_close.len != ack_ecn_close_payload.len) return error.UnexpectedState;

    switch (ack_ecn_close.frame) {
        .connection_close => |close| {
            if (close.error_code != quicz.transport_error.codeValue(.protocol_violation)) return error.UnexpectedState;
            std.debug.print(
                "[close] semantic ack-ecn auto close error={} frame_type={} reason={s} state={s}\n",
                .{ close.error_code, close.frame_type, close.reason_phrase, @tagName(ack_ecn_client.connectionState()) },
            );
        },
        else => return error.UnexpectedState,
    }

    var stop_server = try quicz.Connection.init(gpa, .server, .{});
    defer stop_server.deinit();
    try stop_server.validatePeerAddress();

    var stop_payload: [32]u8 = undefined;
    out = fixedWriter(&stop_payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .stop_sending = .{
        .stream_id = 2,
        .application_error_code = 1,
    } });
    try requireError(
        error.InvalidPacket,
        stop_server.processDatagramOrClose(0, out.getWritten()),
    );

    var stop_close_buf: [64]u8 = undefined;
    const stop_close_payload = try pollRequired(&stop_server, &stop_close_buf);
    try printConnectionClose(gpa, stop_close_payload);
    std.debug.print(
        "[close] semantic stop-sending auto close state={s}\n",
        .{@tagName(stop_server.connectionState())},
    );

    var max_stream_data_server = try quicz.Connection.init(gpa, .server, .{});
    defer max_stream_data_server.deinit();
    try max_stream_data_server.validatePeerAddress();

    var max_stream_data_payload: [32]u8 = undefined;
    out = fixedWriter(&max_stream_data_payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .max_stream_data = .{
        .stream_id = 2,
        .maximum_stream_data = 32,
    } });
    try requireError(
        error.InvalidPacket,
        max_stream_data_server.processDatagramOrClose(0, out.getWritten()),
    );

    var max_stream_data_close_buf: [64]u8 = undefined;
    const max_stream_data_close_payload = try pollRequired(&max_stream_data_server, &max_stream_data_close_buf);
    try printConnectionClose(gpa, max_stream_data_close_payload);
    std.debug.print(
        "[close] semantic max-stream-data auto close state={s}\n",
        .{@tagName(max_stream_data_server.connectionState())},
    );

    var blocked_server = try quicz.Connection.init(gpa, .server, .{
        .initial_max_streams_bidi = 0,
    });
    defer blocked_server.deinit();
    try blocked_server.validatePeerAddress();

    var blocked_payload: [32]u8 = undefined;
    out = fixedWriter(&blocked_payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .stream_data_blocked = .{
        .stream_id = 0,
        .maximum_stream_data = 0,
    } });
    try requireError(
        error.InvalidPacket,
        blocked_server.processDatagramOrClose(0, out.getWritten()),
    );

    var blocked_close_buf: [64]u8 = undefined;
    const blocked_close_payload = try pollRequired(&blocked_server, &blocked_close_buf);
    try printConnectionClose(gpa, blocked_close_payload);
    std.debug.print(
        "[close] semantic stream-data-blocked auto close state={s}\n",
        .{@tagName(blocked_server.connectionState())},
    );

    var conflict_server = try quicz.Connection.init(gpa, .server, .{});
    defer conflict_server.deinit();
    try conflict_server.validatePeerAddress();

    var conflict_payload: [64]u8 = undefined;
    out = fixedWriter(&conflict_payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "hello",
    } });
    try conflict_server.processDatagram(0, out.getWritten());

    out = fixedWriter(&conflict_payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 3,
        .fin = false,
        .data = "xx",
    } });
    try requireError(
        error.InvalidPacket,
        conflict_server.processDatagramOrClose(1, out.getWritten()),
    );

    var conflict_close_buf: [64]u8 = undefined;
    const conflict_close_payload = try pollRequired(&conflict_server, &conflict_close_buf);
    var conflict_close = try quicz.frame.decodeFrameSlice(conflict_close_payload, gpa);
    defer quicz.frame.deinitFrame(&conflict_close.frame, gpa);
    if (conflict_close.len != conflict_close_payload.len) return error.UnexpectedState;

    switch (conflict_close.frame) {
        .connection_close => |close| {
            if (close.error_code != quicz.transport_error.codeValue(.protocol_violation)) return error.UnexpectedState;
            std.debug.print(
                "[close] semantic stream-conflict auto close error={} frame_type={} reason={s} state={s}\n",
                .{ close.error_code, close.frame_type, close.reason_phrase, @tagName(conflict_server.connectionState()) },
            );
        },
        else => return error.UnexpectedState,
    }

    var path_server = try quicz.Connection.init(gpa, .server, .{});
    defer path_server.deinit();
    try path_server.validatePeerAddress();

    var path_response_payload: [16]u8 = undefined;
    out = fixedWriter(&path_response_payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .path_response = .{ .data = [_]u8{ 7, 6, 5, 4, 3, 2, 1, 0 } } });

    try requireError(
        error.InvalidPacket,
        path_server.processDatagramOrClose(0, out.getWritten()),
    );

    var path_close_payload_buf: [64]u8 = undefined;
    const path_close_payload = try pollRequired(&path_server, &path_close_payload_buf);
    var path_close = try quicz.frame.decodeFrameSlice(path_close_payload, gpa);
    defer quicz.frame.deinitFrame(&path_close.frame, gpa);
    if (path_close.len != path_close_payload.len) return error.UnexpectedState;

    switch (path_close.frame) {
        .connection_close => |close| {
            if (close.error_code != quicz.transport_error.codeValue(.protocol_violation)) return error.UnexpectedState;
            std.debug.print(
                "[close] semantic path-response auto close error={} frame_type={} reason={s} state={s}\n",
                .{ close.error_code, close.frame_type, close.reason_phrase, @tagName(path_server.connectionState()) },
            );
        },
        else => return error.UnexpectedState,
    }

    var token_server = try quicz.Connection.init(gpa, .server, .{});
    defer token_server.deinit();
    try token_server.validatePeerAddress();

    var new_token_payload: [32]u8 = undefined;
    out = fixedWriter(&new_token_payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .new_token = .{ .token = "future" } });

    try requireError(
        error.InvalidPacket,
        token_server.processDatagramOrClose(0, out.getWritten()),
    );

    var token_close_buf: [64]u8 = undefined;
    const token_close_payload = try pollRequired(&token_server, &token_close_buf);
    var token_close = try quicz.frame.decodeFrameSlice(token_close_payload, gpa);
    defer quicz.frame.deinitFrame(&token_close.frame, gpa);
    if (token_close.len != token_close_payload.len) return error.UnexpectedState;

    switch (token_close.frame) {
        .connection_close => |close| {
            if (close.error_code != quicz.transport_error.codeValue(.protocol_violation)) return error.UnexpectedState;
            std.debug.print(
                "[close] semantic role auto close error={} frame_type={} reason={s} state={s}\n",
                .{ close.error_code, close.frame_type, close.reason_phrase, @tagName(token_server.connectionState()) },
            );
        },
        else => return error.UnexpectedState,
    }

    var handshake_done_server = try quicz.Connection.init(gpa, .server, .{});
    defer handshake_done_server.deinit();
    try handshake_done_server.validatePeerAddress();

    const handshake_done_payload = [_]u8{@intFromEnum(quicz.frame.FrameType.handshake_done)};
    try requireError(
        error.InvalidPacket,
        handshake_done_server.processDatagramOrClose(0, &handshake_done_payload),
    );

    var handshake_done_close_buf: [64]u8 = undefined;
    const handshake_done_close_payload = try pollRequired(&handshake_done_server, &handshake_done_close_buf);
    var handshake_done_close = try quicz.frame.decodeFrameSlice(handshake_done_close_payload, gpa);
    defer quicz.frame.deinitFrame(&handshake_done_close.frame, gpa);
    if (handshake_done_close.len != handshake_done_close_payload.len) return error.UnexpectedState;

    switch (handshake_done_close.frame) {
        .connection_close => |close| {
            if (close.error_code != quicz.transport_error.codeValue(.protocol_violation)) return error.UnexpectedState;
            std.debug.print(
                "[close] semantic handshake-done auto close error={} frame_type={} reason={s} state={s}\n",
                .{ close.error_code, close.frame_type, close.reason_phrase, @tagName(handshake_done_server.connectionState()) },
            );
        },
        else => return error.UnexpectedState,
    }

    var cid_client = try quicz.Connection.init(gpa, .client, .{});
    defer cid_client.deinit();

    const cid0 = [_]u8{ 0xc0, 0, 0, 0 };
    const cid1 = [_]u8{ 0xc0, 0, 0, 1 };
    const cid2 = [_]u8{ 0xc0, 0, 0, 2 };
    const token0 = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const token1 = [_]u8{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    const token2 = [_]u8{0xa5} ** quicz.packet.stateless_reset_token_len;

    var cid_payload: [96]u8 = undefined;
    out = fixedWriter(&cid_payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = &cid0,
        .stateless_reset_token = token0,
    } });
    try cid_client.processDatagram(0, out.getWritten());

    out = fixedWriter(&cid_payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = &cid1,
        .stateless_reset_token = token1,
    } });
    try cid_client.processDatagram(1, out.getWritten());

    out = fixedWriter(&cid_payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 2,
        .retire_prior_to = 0,
        .connection_id = &cid2,
        .stateless_reset_token = token2,
    } });
    try requireError(
        error.InvalidPacket,
        cid_client.processDatagramOrClose(2, out.getWritten()),
    );

    var cid_close_buf: [64]u8 = undefined;
    const cid_close_payload = try pollRequired(&cid_client, &cid_close_buf);
    var cid_close = try quicz.frame.decodeFrameSlice(cid_close_payload, gpa);
    defer quicz.frame.deinitFrame(&cid_close.frame, gpa);
    if (cid_close.len != cid_close_payload.len) return error.UnexpectedState;

    switch (cid_close.frame) {
        .connection_close => |close| {
            if (close.error_code != quicz.transport_error.codeValue(.connection_id_limit_error)) return error.UnexpectedState;
            std.debug.print(
                "[close] semantic connection-id-limit auto close error={} frame_type={} reason={s} state={s}\n",
                .{ close.error_code, close.frame_type, close.reason_phrase, @tagName(cid_client.connectionState()) },
            );
        },
        else => return error.UnexpectedState,
    }

    var cid_reuse_client = try quicz.Connection.init(gpa, .client, .{});
    defer cid_reuse_client.deinit();

    const reuse_cid0 = [_]u8{ 0xd0, 0, 0, 0 };
    const reuse_cid1 = [_]u8{ 0xd0, 0, 0, 1 };
    const reuse_token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

    out = fixedWriter(&cid_payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = &reuse_cid0,
        .stateless_reset_token = reuse_token,
    } });
    try cid_reuse_client.processDatagram(0, out.getWritten());

    out = fixedWriter(&cid_payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = &reuse_cid1,
        .stateless_reset_token = reuse_token,
    } });
    try requireError(
        error.InvalidPacket,
        cid_reuse_client.processDatagramOrClose(1, out.getWritten()),
    );

    var cid_reuse_close_buf: [64]u8 = undefined;
    const cid_reuse_close_payload = try pollRequired(&cid_reuse_client, &cid_reuse_close_buf);
    var cid_reuse_close = try quicz.frame.decodeFrameSlice(cid_reuse_close_payload, gpa);
    defer quicz.frame.deinitFrame(&cid_reuse_close.frame, gpa);
    if (cid_reuse_close.len != cid_reuse_close_payload.len) return error.UnexpectedState;

    switch (cid_reuse_close.frame) {
        .connection_close => |close| {
            if (close.error_code != quicz.transport_error.codeValue(.protocol_violation)) return error.UnexpectedState;
            std.debug.print(
                "[close] semantic reset-token-reuse auto close error={} frame_type={} reason={s} state={s}\n",
                .{ close.error_code, close.frame_type, close.reason_phrase, @tagName(cid_reuse_client.connectionState()) },
            );
        },
        else => return error.UnexpectedState,
    }

    var retire_server = try quicz.Connection.init(gpa, .server, .{});
    defer retire_server.deinit();
    try retire_server.validatePeerAddress();

    var retire_payload: [16]u8 = undefined;
    out = fixedWriter(&retire_payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .retire_connection_id = .{ .sequence_number = 99 } });

    try requireError(
        error.InvalidPacket,
        retire_server.processDatagramOrClose(0, out.getWritten()),
    );

    var retire_close_buf: [64]u8 = undefined;
    const retire_close_payload = try pollRequired(&retire_server, &retire_close_buf);
    var retire_close = try quicz.frame.decodeFrameSlice(retire_close_payload, gpa);
    defer quicz.frame.deinitFrame(&retire_close.frame, gpa);
    if (retire_close.len != retire_close_payload.len) return error.UnexpectedState;

    switch (retire_close.frame) {
        .connection_close => |close| {
            if (close.error_code != quicz.transport_error.codeValue(.protocol_violation)) return error.UnexpectedState;
            std.debug.print(
                "[close] semantic retire-cid auto close error={} frame_type={} reason={s} state={s}\n",
                .{ close.error_code, close.frame_type, close.reason_phrase, @tagName(retire_server.connectionState()) },
            );
        },
        else => return error.UnexpectedState,
    }
}

fn protectedShortCloseExample(gpa: std.mem.Allocator) !void {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try quicz.Connection.init(gpa, .client, .{});
    defer client.deinit();
    var server = try quicz.Connection.init(gpa, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    try client.closeConnection(0, @intFromEnum(quicz.frame.FrameType.stream), "protected done");
    const protected_close = (try client.pollProtectedShortDatagram(0, &server_dcid, secrets.client)) orelse return error.UnexpectedState;
    defer gpa.free(protected_close);
    try server.processProtectedShortDatagram(1, secrets.client, server_dcid.len, protected_close);
    printPeerClose("protected receiver", server.peerClose() orelse return error.UnexpectedState);
    const protected_next_peer = server.nextPeerPacketNumber(.application);
    const invalid_protected = [_]u8{0xff};
    try server.processProtectedShortDatagram(2, secrets.client, server_dcid.len, &invalid_protected);
    if (server.nextPeerPacketNumber(.application) != protected_next_peer) return error.UnexpectedState;

    const retransmit = (try client.pollProtectedShortDatagram(3, &server_dcid, secrets.client)) orelse return error.UnexpectedState;
    defer gpa.free(retransmit);

    std.debug.print(
        "[close] protected close bytes={} retransmit={} sender={s} receiver={s} discarded_next_peer={}\n",
        .{
            protected_close.len,
            retransmit.len,
            @tagName(client.connectionState()),
            @tagName(server.connectionState()),
            protected_next_peer,
        },
    );

    var app_server = try quicz.Connection.init(gpa, .server, .{});
    defer app_server.deinit();
    try app_server.validatePeerAddress();
    var app_client = try quicz.Connection.init(gpa, .client, .{});
    defer app_client.deinit();

    try app_server.closeApplication(42, "protected app done");
    const protected_app_close = (try app_server.pollProtectedShortDatagram(4, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer gpa.free(protected_app_close);
    try app_client.processProtectedShortDatagram(5, secrets.server, client_dcid.len, protected_app_close);
    printPeerClose("protected app receiver", app_client.peerClose() orelse return error.UnexpectedState);
    std.debug.print(
        "[close] protected application close bytes={} receiver={s}\n",
        .{ protected_app_close.len, @tagName(app_client.connectionState()) },
    );
}

fn protectedLongCloseExample(gpa: std.mem.Allocator) !void {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var initial_client = try quicz.Connection.init(gpa, .client, .{});
    defer initial_client.deinit();
    var initial_server = try quicz.Connection.init(gpa, .server, .{});
    defer initial_server.deinit();

    try initial_client.closeConnection(
        quicz.transport_error.codeValue(.no_error),
        @intFromEnum(quicz.frame.FrameType.crypto),
        "protected initial close",
    );
    const initial_close = (try initial_client.pollProtectedLongDatagram(
        6,
        &original_dcid,
        &client_scid,
        &[_]u8{},
        .{ .initial = secrets.client },
    )) orelse return error.UnexpectedState;
    defer gpa.free(initial_close);
    if (initial_close.len < 1200) return error.UnexpectedState;
    if (try initial_server.processProtectedLongDatagram(7, .{ .initial = secrets.client }, initial_close) != 1) return error.UnexpectedState;
    printPeerClose("protected initial receiver", initial_server.peerClose() orelse return error.UnexpectedState);
    std.debug.print(
        "[close] protected long initial close bytes={} sender={s} receiver={s}\n",
        .{
            initial_close.len,
            @tagName(initial_client.connectionState()),
            @tagName(initial_server.connectionState()),
        },
    );

    var handshake_server = try quicz.Connection.init(gpa, .server, .{});
    defer handshake_server.deinit();
    try handshake_server.validatePeerAddress();
    var handshake_client = try quicz.Connection.init(gpa, .client, .{});
    defer handshake_client.deinit();

    try handshake_server.closeConnection(
        quicz.transport_error.codeValue(.internal_error),
        @intFromEnum(quicz.frame.FrameType.crypto),
        "protected handshake close",
    );
    const handshake_close = (try handshake_server.pollProtectedLongDatagram(
        8,
        &client_scid,
        &server_scid,
        &[_]u8{},
        .{ .handshake = secrets.server },
    )) orelse return error.UnexpectedState;
    defer gpa.free(handshake_close);
    if (try handshake_client.processProtectedLongDatagram(9, .{ .handshake = secrets.server }, handshake_close) != 1) return error.UnexpectedState;
    printPeerClose("protected handshake receiver", handshake_client.peerClose() orelse return error.UnexpectedState);
    std.debug.print(
        "[close] protected long handshake close bytes={} sender={s} receiver={s}\n",
        .{
            handshake_close.len,
            @tagName(handshake_server.connectionState()),
            @tagName(handshake_client.connectionState()),
        },
    );
}

fn protectedReceiveAutoCloseExample(gpa: std.mem.Allocator) !void {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    var initial_plaintext: [1200]u8 = undefined;
    @memset(&initial_plaintext, 0);
    initial_plaintext[0] = @intFromEnum(quicz.frame.FrameType.handshake_done);

    const invalid_initial = try quicz.protection.protectLongPacketAes128(gpa, .{
        .version = .v1,
        .dcid = &original_dcid,
        .scid = &client_scid,
        .packet_type = .initial,
        .token = &[_]u8{},
        .packet_number = 0,
        .payload_length = 0,
    }, try quicz.packet.encodePacketNumberForHeader(0, null), secrets.client, &initial_plaintext);
    defer gpa.free(invalid_initial);
    if (invalid_initial.len < 1200) return error.UnexpectedState;

    var initial_client = try quicz.Connection.init(gpa, .client, .{});
    defer initial_client.deinit();
    var initial_server = try quicz.Connection.init(gpa, .server, .{});
    defer initial_server.deinit();
    try initial_server.validatePeerAddress();

    try requireUsizeError(
        error.InvalidPacket,
        initial_server.processProtectedLongDatagramOrClose(10, .{ .initial = secrets.client }, invalid_initial),
    );
    const initial_close = (try initial_server.pollProtectedLongDatagram(
        11,
        &client_scid,
        &server_scid,
        &[_]u8{},
        .{ .initial = secrets.server },
    )) orelse return error.UnexpectedState;
    defer gpa.free(initial_close);
    if (try initial_client.processProtectedLongDatagram(12, .{ .initial = secrets.server }, initial_close) != 1) {
        return error.UnexpectedState;
    }
    printPeerClose("protected initial auto-close receiver", initial_client.peerClose() orelse return error.UnexpectedState);
    std.debug.print(
        "[close] protected initial auto close bytes={} sender={s} receiver={s}\n",
        .{
            initial_close.len,
            @tagName(initial_server.connectionState()),
            @tagName(initial_client.connectionState()),
        },
    );

    const unknown_frame = [_]u8{ 0x1f, 0, 0, 0 };
    const invalid_short = try quicz.protection.protectShortPacketAes128(gpa, .{
        .dcid = &server_dcid,
        .spin_bit = false,
        .key_phase = false,
        .packet_number = 0,
    }, try quicz.packet.encodePacketNumberForHeader(0, null), secrets.client, &unknown_frame);
    defer gpa.free(invalid_short);

    var short_client = try quicz.Connection.init(gpa, .client, .{});
    defer short_client.deinit();
    var short_server = try quicz.Connection.init(gpa, .server, .{});
    defer short_server.deinit();
    try short_server.validatePeerAddress();

    try requireError(
        error.InvalidPacket,
        short_server.processProtectedShortDatagramOrClose(13, secrets.client, server_dcid.len, invalid_short),
    );
    const short_close = (try short_server.pollProtectedShortDatagram(14, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer gpa.free(short_close);
    try short_client.processProtectedShortDatagram(15, secrets.server, client_dcid.len, short_close);
    printPeerClose("protected short auto-close receiver", short_client.peerClose() orelse return error.UnexpectedState);
    std.debug.print(
        "[close] protected short auto close bytes={} sender={s} receiver={s}\n",
        .{
            short_close.len,
            @tagName(short_server.connectionState()),
            @tagName(short_client.connectionState()),
        },
    );
}

fn protectedClosedStateDiscardExample(gpa: std.mem.Allocator) !void {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);
    const invalid_protected = [_]u8{0xff};

    var closing = try quicz.Connection.init(gpa, .client, .{});
    defer closing.deinit();

    try closing.closeConnection(0, @intFromEnum(quicz.frame.FrameType.stream), "closing discard");
    const closing_initial_next = closing.nextPeerPacketNumber(.initial);
    const closing_application_next = closing.nextPeerPacketNumber(.application);
    if (try closing.processProtectedLongDatagramOrClose(19, .{
        .initial = secrets.server,
        .zero_rtt = secrets.server,
    }, &invalid_protected) != 0) return error.UnexpectedState;
    try closing.processProtectedZeroRttDatagramOrClose(20, secrets.server, &invalid_protected);
    if (closing.nextPeerPacketNumber(.initial) != closing_initial_next) return error.UnexpectedState;
    if (closing.nextPeerPacketNumber(.application) != closing_application_next) return error.UnexpectedState;
    std.debug.print(
        "[close] protected long/0-rtt closing discard initial_next={} application_next={} state={s}\n",
        .{
            closing_initial_next,
            closing_application_next,
            @tagName(closing.connectionState()),
        },
    );

    var close_payload: [64]u8 = undefined;
    var out = fixedWriter(&close_payload);
    try quicz.frame.encodeFrame(out.writer(), .{ .application_close = .{
        .error_code = 0,
        .reason_phrase = "drain discard",
    } });

    var draining = try quicz.Connection.init(gpa, .server, .{});
    defer draining.deinit();
    try draining.processDatagram(21, out.getWritten());
    const draining_initial_next = draining.nextPeerPacketNumber(.initial);
    const draining_application_next = draining.nextPeerPacketNumber(.application);
    if (try draining.processProtectedLongDatagramOrClose(22, .{
        .initial = secrets.client,
        .zero_rtt = secrets.client,
    }, &invalid_protected) != 0) return error.UnexpectedState;
    try draining.processProtectedZeroRttDatagramOrClose(23, secrets.client, &invalid_protected);
    if (draining.nextPeerPacketNumber(.initial) != draining_initial_next) return error.UnexpectedState;
    if (draining.nextPeerPacketNumber(.application) != draining_application_next) return error.UnexpectedState;
    std.debug.print(
        "[close] protected long/0-rtt draining discard initial_next={} application_next={} state={s}\n",
        .{
            draining_initial_next,
            draining_application_next,
            @tagName(draining.connectionState()),
        },
    );
}

fn lifecycleProtectedReceiveAutoCloseExample(gpa: std.mem.Allocator) !void {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);

    const client_addr = quicz.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 50_000);
    const server_addr = quicz.endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433);
    const server_receive_path = quicz.endpoint.Udp4Tuple{
        .local = server_addr,
        .remote = client_addr,
    };

    var lifecycle = quicz.EndpointConnectionLifecycle.init(gpa);
    defer lifecycle.deinit();
    const connection_id: u64 = 7;
    try lifecycle.registerConnectionId(connection_id, &server_dcid, server_receive_path, .{
        .sequence_number = 0,
    });

    const unknown_frame = [_]u8{ 0x1f, 0, 0, 0 };
    const invalid_short = try quicz.protection.protectShortPacketAes128(gpa, .{
        .dcid = &server_dcid,
        .spin_bit = false,
        .key_phase = false,
        .packet_number = 0,
    }, try quicz.packet.encodePacketNumberForHeader(0, null), secrets.client, &unknown_frame);
    defer gpa.free(invalid_short);

    var client = try quicz.Connection.init(gpa, .client, .{});
    defer client.deinit();
    var server = try quicz.Connection.init(gpa, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    try requireRouteError(
        error.InvalidPacket,
        lifecycle.processRoutedProtectedShortDatagramOrClose(
            connection_id,
            &server,
            server_receive_path,
            16,
            secrets.client,
            invalid_short,
        ),
    );
    const close_packet = (try lifecycle.pollProtectedShortDatagram(connection_id, &server, 17, &client_dcid, secrets.server)) orelse return error.UnexpectedState;
    defer gpa.free(close_packet);
    try client.processProtectedShortDatagram(18, secrets.server, client_dcid.len, close_packet);
    printPeerClose("lifecycle protected auto-close receiver", client.peerClose() orelse return error.UnexpectedState);
    std.debug.print(
        "[close] lifecycle protected short auto close bytes={} routes={} sender={s} receiver={s}\n",
        .{
            close_packet.len,
            lifecycle.routeCount(),
            @tagName(server.connectionState()),
            @tagName(client.connectionState()),
        },
    );
}

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    var client = try quicz.Connection.init(gpa, .client, .{});
    defer client.deinit();
    var server = try quicz.Connection.init(gpa, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    try client.closeConnection(0, @intFromEnum(quicz.frame.FrameType.stream), "done");
    var datagram: [128]u8 = undefined;
    const connection_close = try pollRequired(&client, &datagram);
    try printConnectionClose(gpa, connection_close);
    std.debug.print(
        "[close] sender state={s} deadline_ms={}\n",
        .{ @tagName(client.connectionState()), client.closeDeadlineMillis().? },
    );
    try server.processDatagram(0, connection_close);
    printPeerClose("receiver", server.peerClose() orelse return error.UnexpectedState);
    const receiver_next_peer = server.nextPeerPacketNumber(.application);
    const invalid_payload = [_]u8{0xff};
    try server.processDatagram(1, &invalid_payload);
    if (server.nextPeerPacketNumber(.application) != receiver_next_peer) return error.UnexpectedState;
    try requireError(error.ConnectionClosed, server.sendPing());
    std.debug.print(
        "[close] receiver state={s} rejected send after CONNECTION_CLOSE discarded_next_peer={}\n",
        .{ @tagName(server.connectionState()), receiver_next_peer },
    );

    const retransmitted_close = (try client.pollTx(1, &datagram)) orelse return error.UnexpectedState;
    try printConnectionClose(gpa, retransmitted_close);
    std.debug.print(
        "[close] sender retransmitted close while state={s}\n",
        .{@tagName(client.connectionState())},
    );

    try requirePollError(error.ConnectionClosed, client.pollTx(client.closeDeadlineMillis().?, &datagram));
    std.debug.print("[close] sender expired state={s}\n", .{@tagName(client.connectionState())});

    var app_server = try quicz.Connection.init(gpa, .server, .{});
    defer app_server.deinit();
    try app_server.validatePeerAddress();
    var app_client = try quicz.Connection.init(gpa, .client, .{});
    defer app_client.deinit();

    try app_server.closeApplication(42, "app done");
    const application_close = try pollRequired(&app_server, &datagram);
    try printApplicationClose(gpa, application_close);
    try app_client.processDatagram(0, application_close);
    printPeerClose("application receiver", app_client.peerClose() orelse return error.UnexpectedState);
    try requireError(error.ConnectionClosed, app_client.sendPing());
    std.debug.print("[close] application receiver state={s}\n", .{@tagName(app_client.connectionState())});

    try framePayloadAutoCloseExample(gpa);
    try packetTypeAutoCloseExample(gpa);
    try semanticFrameAutoCloseExample(gpa);
    try protectedShortCloseExample(gpa);
    try protectedLongCloseExample(gpa);
    try protectedReceiveAutoCloseExample(gpa);
    try protectedClosedStateDiscardExample(gpa);
    try lifecycleProtectedReceiveAutoCloseExample(gpa);
}
