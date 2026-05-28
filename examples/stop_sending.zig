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

fn pollRequired(conn: *quicz.QuicConnection, out: []u8) ![]const u8 {
    return (try conn.pollTx(0, out)) orelse error.UnexpectedState;
}

fn requireError(expected: anyerror, result: anytype) !void {
    _ = result catch |err| {
        if (err == expected) return;
        return err;
    };
    return error.UnexpectedState;
}

fn expectAckOnly(allocator: std.mem.Allocator, payload: []const u8) !void {
    var decoded = try quicz.frame.decodeFrameSlice(payload, allocator);
    defer quicz.frame.deinitFrame(&decoded.frame, allocator);
    switch (decoded.frame) {
        .ack => {},
        else => return error.UnexpectedState,
    }
    if (decoded.len != payload.len) return error.UnexpectedState;
}

fn expectAckThenReset(
    allocator: std.mem.Allocator,
    payload: []const u8,
    stream_id: u64,
    application_error_code: u64,
    final_size: u64,
) !void {
    var ack = try quicz.frame.decodeFrameSlice(payload, allocator);
    defer quicz.frame.deinitFrame(&ack.frame, allocator);
    switch (ack.frame) {
        .ack => {},
        else => return error.UnexpectedState,
    }

    var reset = try quicz.frame.decodeFrameSlice(payload[ack.len..], allocator);
    defer quicz.frame.deinitFrame(&reset.frame, allocator);
    switch (reset.frame) {
        .reset_stream => |reset_frame| {
            if (reset_frame.stream_id != stream_id) return error.UnexpectedState;
            if (reset_frame.application_error_code != application_error_code) return error.UnexpectedState;
            if (reset_frame.final_size != final_size) return error.UnexpectedState;
        },
        else => return error.UnexpectedState,
    }
    if (payload.len != ack.len + reset.len) return error.UnexpectedState;
}

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    var client = try quicz.QuicConnection.init(gpa, .client, .{});
    defer client.deinit();
    var server = try quicz.QuicConnection.init(gpa, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello", false);

    var datagram: [128]u8 = undefined;
    try server.processDatagram(0, try pollRequired(&client, &datagram));
    try server.stopSending(stream_id, 23);

    const stop_payload = try pollRequired(&server, &datagram);
    try client.processDatagram(1, stop_payload);
    std.debug.print("[stop] receiver requested stop stream={} error=23\n", .{stream_id});

    const reset_payload = try pollRequired(&client, &datagram);
    try server.processDatagram(2, reset_payload);

    var recv_buf: [16]u8 = undefined;
    try requireError(error.StreamClosed, server.recvOnStream(stream_id, &recv_buf));
    std.debug.print("[stop] sender answered with RESET_STREAM final_size={?}\n", .{
        try server.recvStreamFinalSize(stream_id),
    });

    var racing_client = try quicz.QuicConnection.init(gpa, .client, .{});
    defer racing_client.deinit();
    var racing_server = try quicz.QuicConnection.init(gpa, .server, .{});
    defer racing_server.deinit();
    try racing_server.validatePeerAddress();

    const racing_stream = try racing_client.openStream();
    try racing_client.sendOnStream(racing_stream, "racing", false);
    try racing_server.processDatagram(3, try pollRequired(&racing_client, &datagram));
    try racing_server.stopSending(racing_stream, 25);
    try racing_client.resetStream(racing_stream, 25);
    try racing_server.processDatagram(4, try pollRequired(&racing_client, &datagram));

    const ack_only = try pollRequired(&racing_server, &datagram);
    try expectAckOnly(gpa, ack_only);
    std.debug.print("[stop] queued STOP_SENDING dropped after RESET_STREAM stream={}\n", .{racing_stream});

    var done_client = try quicz.QuicConnection.init(gpa, .client, .{});
    defer done_client.deinit();
    var done_server = try quicz.QuicConnection.init(gpa, .server, .{});
    defer done_server.deinit();
    try done_server.validatePeerAddress();

    const done_stream = try done_client.openStream();
    try done_client.sendOnStream(done_stream, "done", true);
    try done_server.processDatagram(5, try pollRequired(&done_client, &datagram));
    try requireError(error.StreamClosed, done_server.stopSending(done_stream, 24));
    std.debug.print("[stop] receiver skipped STOP_SENDING after final data stream={}\n", .{done_stream});

    var early_client = try quicz.QuicConnection.init(gpa, .client, .{});
    defer early_client.deinit();
    var early_server = try quicz.QuicConnection.init(gpa, .server, .{});
    defer early_server.deinit();
    try early_server.validatePeerAddress();

    _ = try early_client.openStream();
    _ = try early_client.openStream();
    const early_stream = try early_client.openStream();
    try early_client.stopSending(early_stream, 26);
    try early_server.processDatagram(6, try pollRequired(&early_client, &datagram));
    try early_client.processDatagram(7, try pollRequired(&early_server, &datagram));
    try early_client.sendOnStream(early_stream, "still open", true);
    try early_server.processDatagram(8, try pollRequired(&early_client, &datagram));

    const early_len = (try early_server.recvOnStream(early_stream, &recv_buf)) orelse return error.UnexpectedState;
    if (!std.mem.eql(u8, recv_buf[0..early_len], "still open")) return error.UnexpectedState;
    std.debug.print("[stop] STOP_SENDING before STREAM opened stream={} and lower streams, reset reply side, and left receive side open\n", .{early_stream});

    var lost_client = try quicz.QuicConnection.init(gpa, .client, .{});
    defer lost_client.deinit();

    const lost_stream = try lost_client.openStream();
    try lost_client.sendOnStream(lost_stream, "lost", false);
    _ = try pollRequired(&lost_client, &datagram);
    try lost_client.sendPing();
    _ = try pollRequired(&lost_client, &datagram);
    try lost_client.sendPing();
    _ = try pollRequired(&lost_client, &datagram);
    try lost_client.sendPing();
    _ = try pollRequired(&lost_client, &datagram);

    var stop_buf: [16]u8 = undefined;
    var stop_out = fixedWriter(&stop_buf);
    try quicz.frame.encodeFrame(stop_out.writer(), .{ .stop_sending = .{
        .stream_id = lost_stream,
        .application_error_code = 27,
    } });
    try lost_client.processDatagram(9, stop_out.getWritten());
    try lost_client.receiveAckInSpace(.application, 10, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    const suppressed_reset = try pollRequired(&lost_client, &datagram);
    try expectAckThenReset(gpa, suppressed_reset, lost_stream, 27, 4);
    if ((try lost_client.pollTx(11, &datagram)) != null) return error.UnexpectedState;
    std.debug.print("[stop] RESET_STREAM suppressed ACK-loss STREAM retransmission stream={}\n", .{lost_stream});
}
