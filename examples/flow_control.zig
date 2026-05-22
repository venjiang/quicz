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

fn requireError(expected: anyerror, result: anytype) !void {
    _ = result catch |err| {
        if (err == expected) return;
        return err;
    };
    return error.UnexpectedState;
}

fn applyFrame(conn: *quicz.QuicConnection, frame_value: quicz.frame.Frame) !void {
    var raw: [32]u8 = undefined;
    var writer = fixedWriter(&raw);
    try quicz.frame.encodeFrame(writer.writer(), frame_value);
    try conn.processDatagram(0, writer.getWritten());
}

fn expectDataBlocked(conn: *quicz.QuicConnection, gpa: std.mem.Allocator, expected_max: u64) !void {
    var raw: [64]u8 = undefined;
    const payload = (try conn.pollTx(0, &raw)) orelse return error.UnexpectedState;
    var decoded = try quicz.frame.decodeFrameSlice(payload, gpa);
    defer quicz.frame.deinitFrame(&decoded.frame, gpa);

    switch (decoded.frame) {
        .data_blocked => |blocked| {
            if (blocked.maximum_data != expected_max) return error.UnexpectedState;
        },
        else => return error.UnexpectedState,
    }
}

fn expectStreamDataBlocked(conn: *quicz.QuicConnection, gpa: std.mem.Allocator, expected_stream: u64, expected_max: u64) !void {
    var raw: [64]u8 = undefined;
    const payload = (try conn.pollTx(0, &raw)) orelse return error.UnexpectedState;
    var decoded = try quicz.frame.decodeFrameSlice(payload, gpa);
    defer quicz.frame.deinitFrame(&decoded.frame, gpa);

    switch (decoded.frame) {
        .stream_data_blocked => |blocked| {
            if (blocked.stream_id != expected_stream or blocked.maximum_stream_data != expected_max) {
                return error.UnexpectedState;
            }
        },
        else => return error.UnexpectedState,
    }
}

fn expectStreamsBlockedBidi(conn: *quicz.QuicConnection, gpa: std.mem.Allocator, expected_max: u64) !void {
    var raw: [64]u8 = undefined;
    const payload = (try conn.pollTx(0, &raw)) orelse return error.UnexpectedState;
    var decoded = try quicz.frame.decodeFrameSlice(payload, gpa);
    defer quicz.frame.deinitFrame(&decoded.frame, gpa);

    switch (decoded.frame) {
        .streams_blocked_bidi => |blocked| {
            if (blocked.maximum_streams != expected_max) return error.UnexpectedState;
        },
        else => return error.UnexpectedState,
    }
}

fn expectMaxDataPayload(gpa: std.mem.Allocator, payload: []const u8, expected_max: u64) !void {
    var first = try quicz.frame.decodeFrameSlice(payload, gpa);
    defer quicz.frame.deinitFrame(&first.frame, gpa);

    const offset = switch (first.frame) {
        .ack => first.len,
        .max_data => |max_data| blk: {
            if (first.len != payload.len) return error.UnexpectedState;
            if (max_data.maximum_data != expected_max) return error.UnexpectedState;
            break :blk payload.len;
        },
        else => return error.UnexpectedState,
    };
    if (offset == payload.len) return;

    var second = try quicz.frame.decodeFrameSlice(payload[offset..], gpa);
    defer quicz.frame.deinitFrame(&second.frame, gpa);
    if (second.len != payload.len - offset) return error.UnexpectedState;
    switch (second.frame) {
        .max_data => |max_data| {
            if (max_data.maximum_data != expected_max) return error.UnexpectedState;
        },
        else => return error.UnexpectedState,
    }
}

fn expectMaxStreamDataPayload(
    gpa: std.mem.Allocator,
    payload: []const u8,
    expected_stream: u64,
    expected_max: u64,
) !void {
    var offset: usize = 0;
    while (offset < payload.len) {
        var decoded = try quicz.frame.decodeFrameSlice(payload[offset..], gpa);
        const decoded_len = decoded.len;
        switch (decoded.frame) {
            .max_stream_data => |max_stream_data| {
                quicz.frame.deinitFrame(&decoded.frame, gpa);
                if (decoded_len == 0) return error.UnexpectedState;
                if (max_stream_data.stream_id != expected_stream or max_stream_data.maximum_stream_data != expected_max) {
                    return error.UnexpectedState;
                }
                return;
            },
            else => quicz.frame.deinitFrame(&decoded.frame, gpa),
        }
        if (decoded_len == 0) return error.UnexpectedState;
        offset += decoded_len;
    }
    return error.UnexpectedState;
}

fn expectMaxStreamsBidiPayload(gpa: std.mem.Allocator, payload: []const u8, expected_max: u64) !void {
    const found = try payloadHasMaxStreamsBidi(gpa, payload, expected_max);
    if (!found) return error.UnexpectedState;
}

fn expectMaxDataFrom(conn: *quicz.QuicConnection, gpa: std.mem.Allocator, expected_max: u64) !void {
    var raw: [128]u8 = undefined;
    const payload = (try conn.pollTx(0, &raw)) orelse return error.UnexpectedState;
    try expectMaxDataPayload(gpa, payload, expected_max);
}

fn expectMaxStreamDataFrom(
    conn: *quicz.QuicConnection,
    gpa: std.mem.Allocator,
    expected_stream: u64,
    expected_max: u64,
) !void {
    var raw: [128]u8 = undefined;
    const payload = (try conn.pollTx(0, &raw)) orelse return error.UnexpectedState;
    try expectMaxStreamDataPayload(gpa, payload, expected_stream, expected_max);
}

fn expectMaxStreamsBidiFrom(conn: *quicz.QuicConnection, gpa: std.mem.Allocator, expected_max: u64) !void {
    var raw: [128]u8 = undefined;
    const payload = (try conn.pollTx(0, &raw)) orelse return error.UnexpectedState;
    try expectMaxStreamsBidiPayload(gpa, payload, expected_max);
}

fn expectPeerBlockedRefresh(
    conn: *quicz.QuicConnection,
    gpa: std.mem.Allocator,
    frame_value: quicz.frame.Frame,
    expected: quicz.frame.Frame,
) !void {
    try applyFrame(conn, frame_value);
    switch (expected) {
        .max_data => |max_data| try expectMaxDataFrom(conn, gpa, max_data.maximum_data),
        .max_stream_data => |max_stream_data| try expectMaxStreamDataFrom(
            conn,
            gpa,
            max_stream_data.stream_id,
            max_stream_data.maximum_stream_data,
        ),
        .max_streams_bidi => |max_streams| try expectMaxStreamsBidiFrom(conn, gpa, max_streams.maximum_streams),
        else => return error.UnexpectedState,
    }
}

fn payloadHasMaxStreamsBidi(gpa: std.mem.Allocator, payload: []const u8, expected_max: u64) !bool {
    var offset: usize = 0;
    while (offset < payload.len) {
        var decoded = try quicz.frame.decodeFrameSlice(payload[offset..], gpa);
        const decoded_len = decoded.len;
        switch (decoded.frame) {
            .max_streams_bidi => |max_streams| {
                quicz.frame.deinitFrame(&decoded.frame, gpa);
                if (max_streams.maximum_streams != expected_max) return error.UnexpectedState;
                return true;
            },
            else => quicz.frame.deinitFrame(&decoded.frame, gpa),
        }
        if (decoded_len == 0) return error.UnexpectedState;
        offset += decoded_len;
    }
    return false;
}

fn relayUntilMaxStreamsBidi(
    sender: *quicz.QuicConnection,
    receiver: *quicz.QuicConnection,
    gpa: std.mem.Allocator,
    expected_max: u64,
) !void {
    var raw: [128]u8 = undefined;
    var poll_count: usize = 0;
    while (poll_count < 4) : (poll_count += 1) {
        const payload = (try sender.pollTx(0, &raw)) orelse break;
        const found = try payloadHasMaxStreamsBidi(gpa, payload, expected_max);
        try receiver.processDatagram(0, payload);
        if (found) return;
    }
    return error.UnexpectedState;
}

fn connectionCreditExample(gpa: std.mem.Allocator) !void {
    var conn = try quicz.QuicConnection.init(gpa, .client, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 16,
    });
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "hello", false);
    try requireError(error.FlowControlBlocked, conn.sendOnStream(stream_id, "!", false));
    try expectDataBlocked(&conn, gpa, 5);

    try applyFrame(&conn, .{ .max_data = .{ .maximum_data = 6 } });
    try conn.sendOnStream(stream_id, "!", true);

    std.debug.print("[flow] DATA_BLOCKED reported maximum_data=5\n", .{});
    std.debug.print("[flow] connection credit unblocked stream={} total_bytes=6\n", .{stream_id});
}

fn streamCreditExample(gpa: std.mem.Allocator) !void {
    var conn = try quicz.QuicConnection.init(gpa, .client, .{
        .initial_max_data = 16,
        .initial_max_stream_data = 5,
    });
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "hello", false);
    try requireError(error.FlowControlBlocked, conn.sendOnStream(stream_id, "!", false));
    try expectStreamDataBlocked(&conn, gpa, stream_id, 5);

    try applyFrame(&conn, .{ .max_stream_data = .{
        .stream_id = stream_id,
        .maximum_stream_data = 6,
    } });
    try conn.sendOnStream(stream_id, "!", true);

    std.debug.print("[flow] STREAM_DATA_BLOCKED reported stream={} maximum_stream_data=5\n", .{stream_id});
    std.debug.print("[flow] stream credit unblocked stream={} stream_bytes=6\n", .{stream_id});
}

fn streamCountExample(gpa: std.mem.Allocator) !void {
    var conn = try quicz.QuicConnection.init(gpa, .client, .{
        .initial_max_streams_bidi = 1,
    });
    defer conn.deinit();

    _ = try conn.openStream();
    if (conn.openStream()) |_| {
        return error.UnexpectedState;
    } else |err| {
        if (err != error.FlowControlBlocked) return err;
    }
    try expectStreamsBlockedBidi(&conn, gpa, 1);

    try applyFrame(&conn, .{ .max_streams_bidi = .{ .maximum_streams = 2 } });
    const stream_id = try conn.openStream();

    std.debug.print("[flow] STREAMS_BLOCKED_BIDI reported maximum_streams=1\n", .{});
    std.debug.print("[flow] stream-count credit opened stream={}\n", .{stream_id});
}

fn receiveCreditExample(gpa: std.mem.Allocator) !void {
    var client = try quicz.QuicConnection.init(gpa, .client, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 5,
    });
    defer client.deinit();
    var server = try quicz.QuicConnection.init(gpa, .server, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 5,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello", false);

    var raw: [128]u8 = undefined;
    const stream_payload = (try client.pollTx(0, &raw)) orelse return error.UnexpectedState;
    try server.processDatagram(0, stream_payload);
    try requireError(error.FlowControlBlocked, client.sendOnStream(stream_id, "!", false));

    var read_buf: [8]u8 = undefined;
    const n = (try server.recvOnStream(stream_id, &read_buf)) orelse return error.UnexpectedState;
    if (!std.mem.eql(u8, read_buf[0..n], "hello")) return error.UnexpectedState;

    const max_data_payload = (try server.pollTx(0, &raw)) orelse return error.UnexpectedState;
    try expectMaxDataPayload(gpa, max_data_payload, 10);
    try client.processDatagram(0, max_data_payload);

    const max_stream_payload = (try server.pollTx(0, &raw)) orelse return error.UnexpectedState;
    try expectMaxStreamDataPayload(gpa, max_stream_payload, stream_id, 10);
    try client.processDatagram(0, max_stream_payload);

    try client.sendOnStream(stream_id, "!", true);

    std.debug.print("[flow] recv consumed stream={} and advertised MAX_DATA/MAX_STREAM_DATA=10\n", .{stream_id});
    std.debug.print("[flow] sender used refreshed receive credit stream={} total_bytes=6\n", .{stream_id});
}

fn peerBlockedRefreshExample(gpa: std.mem.Allocator) !void {
    var client = try quicz.QuicConnection.init(gpa, .client, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 5,
    });
    defer client.deinit();
    var server = try quicz.QuicConnection.init(gpa, .server, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 5,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello", false);

    var raw: [128]u8 = undefined;
    const stream_payload = (try client.pollTx(0, &raw)) orelse return error.UnexpectedState;
    try server.processDatagram(0, stream_payload);

    var read_buf: [8]u8 = undefined;
    const n = (try server.recvOnStream(stream_id, &read_buf)) orelse return error.UnexpectedState;
    if (!std.mem.eql(u8, read_buf[0..n], "hello")) return error.UnexpectedState;

    try expectMaxDataFrom(&server, gpa, 10);
    try expectMaxStreamDataFrom(&server, gpa, stream_id, 10);

    try expectPeerBlockedRefresh(&server, gpa, .{ .data_blocked = .{ .maximum_data = 5 } }, .{
        .max_data = .{ .maximum_data = 10 },
    });
    try expectPeerBlockedRefresh(&server, gpa, .{ .stream_data_blocked = .{
        .stream_id = stream_id,
        .maximum_stream_data = 5,
    } }, .{
        .max_stream_data = .{
            .stream_id = stream_id,
            .maximum_stream_data = 10,
        },
    });

    var stream_count = try quicz.QuicConnection.init(gpa, .client, .{
        .initial_max_streams_bidi = 4,
    });
    defer stream_count.deinit();
    try expectPeerBlockedRefresh(&stream_count, gpa, .{ .streams_blocked_bidi = .{ .maximum_streams = 1 } }, .{
        .max_streams_bidi = .{ .maximum_streams = 4 },
    });

    std.debug.print("[flow] peer BLOCKED re-advertised MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS\n", .{});
}

fn receiveStreamCountCreditExample(gpa: std.mem.Allocator) !void {
    var client = try quicz.QuicConnection.init(gpa, .client, .{
        .initial_max_data = 16,
        .initial_max_stream_data = 16,
        .initial_max_streams_bidi = 1,
    });
    defer client.deinit();
    var server = try quicz.QuicConnection.init(gpa, .server, .{
        .initial_max_data = 16,
        .initial_max_stream_data = 16,
        .initial_max_streams_bidi = 1,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    const first_stream = try client.openStream();
    try client.sendOnStream(first_stream, "done", true);

    var raw: [128]u8 = undefined;
    const stream_payload = (try client.pollTx(0, &raw)) orelse return error.UnexpectedState;
    try server.processDatagram(0, stream_payload);
    try requireError(error.FlowControlBlocked, client.openStream());

    var read_buf: [4]u8 = undefined;
    const n = (try server.recvOnStream(first_stream, &read_buf)) orelse return error.UnexpectedState;
    if (!std.mem.eql(u8, read_buf[0..n], "done")) return error.UnexpectedState;

    try relayUntilMaxStreamsBidi(&server, &client, gpa, 2);
    const next_stream = try client.openStream();

    std.debug.print("[flow] recv finished peer stream={} and advertised MAX_STREAMS_BIDI=2\n", .{first_stream});
    std.debug.print("[flow] sender opened next bidirectional stream={}\n", .{next_stream});
}

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    try connectionCreditExample(gpa);
    try streamCreditExample(gpa);
    try streamCountExample(gpa);
    try receiveCreditExample(gpa);
    try peerBlockedRefreshExample(gpa);
    try receiveStreamCountCreditExample(gpa);
}
