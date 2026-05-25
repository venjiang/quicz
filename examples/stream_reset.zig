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

fn requireError(expected: anyerror, result: anyerror!?usize) !void {
    _ = result catch |err| {
        if (err == expected) return;
        return err;
    };
    return error.UnexpectedState;
}

fn pollRequired(conn: *quicz.QuicConnection, out: []u8) ![]const u8 {
    return (try conn.pollTx(0, out)) orelse error.UnexpectedState;
}

fn expectIdle(conn: *quicz.QuicConnection, out: []u8) !void {
    if ((try conn.pollTx(1, out)) != null) return error.UnexpectedState;
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
    try client.resetStream(stream_id, 7);

    var datagram: [128]u8 = undefined;
    const client_reset = try pollRequired(&client, &datagram);
    try server.processDatagram(0, client_reset);

    var recv_buf: [16]u8 = undefined;
    try requireError(error.StreamClosed, server.recvOnStream(stream_id, &recv_buf));
    std.debug.print("[stream-reset] client reset stream={} final_size={?}\n", .{
        stream_id,
        try server.recvStreamFinalSize(stream_id),
    });

    try expectIdle(&client, &datagram);
    std.debug.print("[stream-reset] unsent STREAM data dropped after reset\n", .{});

    try server.resetStream(stream_id, 9);
    const server_reset = try pollRequired(&server, &datagram);
    try client.processDatagram(1, server_reset);
    std.debug.print("[stream-reset] server reset reply side stream={} final_size={?}\n", .{
        stream_id,
        try client.recvStreamFinalSize(stream_id),
    });

    var late_stream_raw: [64]u8 = undefined;
    var late_stream_out = fixedWriter(&late_stream_raw);
    try quicz.frame.encodeFrame(late_stream_out.writer(), .{ .stream = .{
        .stream_id = stream_id,
        .offset = 0,
        .fin = true,
        .data = "hello",
    } });
    try server.processDatagram(1, late_stream_out.getWritten());
    try requireError(error.StreamClosed, server.recvOnStream(stream_id, &recv_buf));
    std.debug.print("[stream-reset] late STREAM within reset final size was ignored\n", .{});

    var gap_server = try quicz.QuicConnection.init(gpa, .server, .{
        .initial_max_data = 6,
        .initial_max_stream_data = 10,
    });
    defer gap_server.deinit();

    var fin_gap_raw: [64]u8 = undefined;
    var fin_gap_out = fixedWriter(&fin_gap_raw);
    try quicz.frame.encodeFrame(fin_gap_out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 5,
        .fin = true,
        .data = "!",
    } });
    try gap_server.processDatagram(0, fin_gap_out.getWritten());

    var reset_gap_raw: [64]u8 = undefined;
    var reset_gap_out = fixedWriter(&reset_gap_raw);
    try quicz.frame.encodeFrame(reset_gap_out.writer(), .{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = 8,
        .final_size = 6,
    } });
    try gap_server.processDatagram(1, reset_gap_out.getWritten());
    try requireError(error.StreamClosed, gap_server.recvOnStream(0, &recv_buf));
    std.debug.print("[stream-reset] reset after FIN gaps aborted receive side final_size={?}\n", .{
        try gap_server.recvStreamFinalSize(0),
    });

    var limited_client = try quicz.QuicConnection.init(gpa, .client, .{
        .initial_max_streams_bidi = 1,
    });
    defer limited_client.deinit();
    var limited_server = try quicz.QuicConnection.init(gpa, .server, .{
        .initial_max_streams_bidi = 1,
    });
    defer limited_server.deinit();
    try limited_server.validatePeerAddress();

    const limited_stream = try limited_client.openStream();
    try limited_client.resetStream(limited_stream, 10);
    try limited_server.processDatagram(0, try pollRequired(&limited_client, &datagram));
    try requireError(error.StreamClosed, limited_server.recvOnStream(limited_stream, &recv_buf));
    try limited_client.processDatagram(1, try pollRequired(&limited_server, &datagram));
    const next_stream = try limited_client.openStream();
    std.debug.print("[stream-reset] reset released receive stream-count next_stream={}\n", .{
        next_stream,
    });
}
