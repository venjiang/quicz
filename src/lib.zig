const std = @import("std");

pub const packet = @import("quic/packet.zig");
pub const frame = @import("quic/frame.zig");
pub const recovery = @import("quic/recovery.zig");
const buffer = @import("quic/buffer.zig");

const max_quic_varint = 4611686018427387903;

/// Public error set returned by the experimental connection API.
pub const Error = error{
    ConnectionClosed,
    InvalidPacket,
    CryptoError,
    Internal,
    OutOfMemory,
    BufferTooSmall,
    StreamClosed,
    InvalidStream,
};

/// Runtime configuration for a `QuicConnection`.
pub const Config = struct {
    max_datagram_size: u16 = 1350,
    initial_rtt_ms: u32 = 333,
};

/// Endpoint role. It determines the locally initiated bidirectional stream IDs.
pub const ConnectionSide = enum { client, server };

const PendingStreamFrame = struct {
    stream_id: u64,
    offset: u64,
    fin: bool,
    data: []u8,
};

fn quicVarIntWireLen(value: u64) Error!usize {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    if (value <= max_quic_varint) return 8;
    return error.Internal;
}

fn addWireLen(current: usize, extra: usize) Error!usize {
    return std.math.add(usize, current, extra) catch return error.Internal;
}

fn streamFrameWireLen(stream_id: u64, offset: u64, data_len: usize) Error!usize {
    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(stream_id));
    if (offset != 0) {
        len = try addWireLen(len, try quicVarIntWireLen(offset));
    }
    len = try addWireLen(len, try quicVarIntWireLen(std.math.cast(u64, data_len) orelse return error.Internal));
    return addWireLen(len, data_len);
}

fn streamEndOffset(offset: u64, data_len: usize) ?u64 {
    const len = std.math.cast(u64, data_len) orelse return null;
    const end = std.math.add(u64, offset, len) catch return null;
    if (end > max_quic_varint) return null;
    return end;
}

const SendStreamState = struct {
    stream_id: u64,
    next_offset: u64 = 0,
    fin_sent: bool = false,
};

const RecvStreamState = struct {
    stream_id: u64,
    data: std.ArrayList(u8) = .empty,
    read_offset: usize = 0,
    final_size: ?u64 = null,

    fn deinit(self: *RecvStreamState, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
    }
};

const RecvStreamSnapshot = struct {
    data_len: usize,
    read_offset: usize,
    final_size: ?u64,
};

/// Experimental QUIC connection handle.
///
/// The current implementation only moves unencrypted frame payload bytes through
/// the public API. Packet protection, TLS, ACK processing, and network I/O are
/// intentionally outside this first connection skeleton.
pub const QuicConnection = struct {
    allocator: std.mem.Allocator,
    config: Config,
    side: ConnectionSide,
    next_stream_id: u64,
    recovery_state: recovery.Recovery,
    send_queue: std.ArrayList(PendingStreamFrame),
    send_streams: std.ArrayList(SendStreamState),
    recv_streams: std.ArrayList(RecvStreamState),

    /// Create a connection with empty send and receive state.
    pub fn init(
        allocator: std.mem.Allocator,
        side: ConnectionSide,
        config: Config,
    ) !QuicConnection {
        return QuicConnection{
            .allocator = allocator,
            .config = config,
            .side = side,
            .next_stream_id = switch (side) {
                .client => 0,
                .server => 1,
            },
            .recovery_state = recovery.Recovery.init(.{
                .max_datagram_size = config.max_datagram_size,
                .initial_rtt_ms = config.initial_rtt_ms,
            }),
            .send_queue = .empty,
            .send_streams = .empty,
            .recv_streams = .empty,
        };
    }

    /// Release all buffers owned by this connection.
    pub fn deinit(self: *QuicConnection) void {
        for (self.send_queue.items) |pending| {
            self.allocator.free(pending.data);
        }
        self.send_queue.deinit(self.allocator);
        self.send_streams.deinit(self.allocator);
        for (self.recv_streams.items) |*stream| {
            stream.deinit(self.allocator);
        }
        self.recv_streams.deinit(self.allocator);
    }

    /// Process one unencrypted packet payload containing one or more QUIC frames.
    pub fn processDatagram(
        self: *QuicConnection,
        now_millis: i64,
        datagram: []const u8,
    ) Error!void {
        _ = now_millis;

        if (datagram.len == 0 or datagram.len > self.config.max_datagram_size) return error.InvalidPacket;

        const recv_stream_count = self.recv_streams.items.len;
        const recv_snapshots = self.allocator.alloc(RecvStreamSnapshot, recv_stream_count) catch return error.OutOfMemory;
        defer self.allocator.free(recv_snapshots);
        for (self.recv_streams.items, recv_snapshots) |stream, *snapshot| {
            snapshot.* = .{
                .data_len = stream.data.items.len,
                .read_offset = stream.read_offset,
                .final_size = stream.final_size,
            };
        }
        errdefer self.rollbackRecvStreams(recv_stream_count, recv_snapshots);

        var offset: usize = 0;
        while (offset < datagram.len) {
            var decoded = frame.decodeFrameSlice(datagram[offset..], self.allocator) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidPacket,
            };
            defer frame.deinitFrame(&decoded.frame, self.allocator);

            if (decoded.len == 0) return error.InvalidPacket;

            switch (decoded.frame) {
                .stream => |stream_frame| try self.receiveStreamFrame(stream_frame),
                else => {},
            }

            offset += decoded.len;
        }
    }

    /// Return the next unencrypted packet payload to send, or null if idle.
    pub fn pollTx(
        self: *QuicConnection,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        _ = now_millis;

        if (self.send_queue.items.len == 0) return null;

        const pending = self.send_queue.items[0];
        const encoded_len = try streamFrameWireLen(pending.stream_id, pending.offset, pending.data.len);
        if (encoded_len > self.config.max_datagram_size) return error.BufferTooSmall;
        if (!self.recovery_state.canSend(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;

        var writable = out_buf;
        if (writable.len > self.config.max_datagram_size) {
            writable = writable[0..self.config.max_datagram_size];
        }

        var out = buffer.fixedWriter(writable);
        frame.encodeFrame(out.writer(), .{ .stream = .{
            .stream_id = pending.stream_id,
            .offset = pending.offset,
            .fin = pending.fin,
            .data = pending.data,
        } }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const written = out.getWritten();
        std.debug.assert(written.len == encoded_len);

        const removed = self.send_queue.orderedRemove(0);
        self.allocator.free(removed.data);
        self.recovery_state.onPacketSent(written.len);
        return written;
    }

    /// Open a locally initiated bidirectional stream and return its QUIC stream ID.
    pub fn openStream(self: *QuicConnection) Error!u64 {
        const stream_id = self.next_stream_id;
        if (stream_id > max_quic_varint) return error.InvalidStream;

        const next_stream_id = std.math.add(u64, stream_id, 4) catch return error.Internal;

        self.send_streams.append(self.allocator, .{ .stream_id = stream_id }) catch return error.OutOfMemory;
        self.next_stream_id = next_stream_id;
        return stream_id;
    }

    /// Queue data for a stream. The data is copied and emitted by `pollTx`.
    pub fn sendOnStream(
        self: *QuicConnection,
        stream_id: u64,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (stream_id > max_quic_varint) return error.InvalidStream;

        const existing_state = self.findSendStream(stream_id);
        if (existing_state) |state| {
            if (state.fin_sent) return error.StreamClosed;
        }

        const offset = if (existing_state) |state| state.next_offset else 0;
        const next_offset = streamEndOffset(offset, data.len) orelse return error.InvalidStream;
        const encoded_len = try streamFrameWireLen(stream_id, offset, data.len);
        if (encoded_len > self.config.max_datagram_size) return error.BufferTooSmall;

        const owned = self.allocator.alloc(u8, data.len) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned);
        @memcpy(owned, data);

        var appended_send_state = false;
        errdefer if (appended_send_state) {
            _ = self.send_streams.orderedRemove(self.send_streams.items.len - 1);
        };

        const state = existing_state orelse blk: {
            self.send_streams.append(self.allocator, .{ .stream_id = stream_id }) catch return error.OutOfMemory;
            appended_send_state = true;
            break :blk &self.send_streams.items[self.send_streams.items.len - 1];
        };

        self.send_queue.append(self.allocator, .{
            .stream_id = stream_id,
            .offset = offset,
            .fin = fin,
            .data = owned,
        }) catch return error.OutOfMemory;

        state.next_offset = next_offset;
        if (fin) state.fin_sent = true;
    }

    /// Read queued data for a stream. Returns null when no data is available.
    pub fn recvOnStream(
        self: *QuicConnection,
        stream_id: u64,
        buf: []u8,
    ) Error!?usize {
        const stream_state = self.findRecvStream(stream_id) orelse return null;
        if (stream_state.read_offset >= stream_state.data.items.len) return null;

        const available = stream_state.data.items[stream_state.read_offset..];
        const n = @min(buf.len, available.len);
        @memcpy(buf[0..n], available[0..n]);
        stream_state.read_offset += n;
        return n;
    }

    fn findSendStream(self: *QuicConnection, stream_id: u64) ?*SendStreamState {
        for (self.send_streams.items) |*stream| {
            if (stream.stream_id == stream_id) return stream;
        }
        return null;
    }

    fn findRecvStream(self: *QuicConnection, stream_id: u64) ?*RecvStreamState {
        for (self.recv_streams.items) |*stream| {
            if (stream.stream_id == stream_id) return stream;
        }
        return null;
    }

    fn rollbackRecvStreams(
        self: *QuicConnection,
        original_len: usize,
        snapshots: []const RecvStreamSnapshot,
    ) void {
        while (self.recv_streams.items.len > original_len) {
            var removed = self.recv_streams.orderedRemove(self.recv_streams.items.len - 1);
            removed.deinit(self.allocator);
        }

        for (snapshots, 0..) |snapshot, i| {
            var stream = &self.recv_streams.items[i];
            stream.data.items.len = snapshot.data_len;
            stream.read_offset = snapshot.read_offset;
            stream.final_size = snapshot.final_size;
        }
    }

    fn receiveStreamFrame(self: *QuicConnection, stream_frame: frame.StreamFrame) Error!void {
        if (stream_frame.stream_id > max_quic_varint) return error.InvalidStream;

        const existing_state = self.findRecvStream(stream_frame.stream_id);
        if (existing_state) |stream_state| {
            if (stream_state.final_size != null) return error.InvalidPacket;
        }

        const expected_offset = if (existing_state) |stream_state|
            std.math.cast(u64, stream_state.data.items.len) orelse return error.Internal
        else
            0;
        if (stream_frame.offset != expected_offset) {
            return error.InvalidPacket;
        }

        const end_offset = streamEndOffset(stream_frame.offset, stream_frame.data.len) orelse return error.InvalidPacket;

        var appended_recv_state = false;
        errdefer if (appended_recv_state) {
            var removed = self.recv_streams.orderedRemove(self.recv_streams.items.len - 1);
            removed.deinit(self.allocator);
        };

        const stream_state = existing_state orelse blk: {
            self.recv_streams.append(self.allocator, .{ .stream_id = stream_frame.stream_id }) catch return error.OutOfMemory;
            appended_recv_state = true;
            break :blk &self.recv_streams.items[self.recv_streams.items.len - 1];
        };

        stream_state.data.appendSlice(self.allocator, stream_frame.data) catch return error.OutOfMemory;
        if (stream_frame.fin) {
            stream_state.final_size = end_offset;
        }
    }
};

test "openStream allocates client and server bidirectional stream ids" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try std.testing.expectEqual(@as(u64, 0), try client.openStream());
    try std.testing.expectEqual(@as(u64, 4), try client.openStream());
    try std.testing.expectEqual(@as(u64, 1), try server.openStream());
    try std.testing.expectEqual(@as(u64, 5), try server.openStream());
}

test "sendOnStream and pollTx emit stream frame payloads" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "hello", true);

    var out_buf: [128]u8 = undefined;
    const payload = (try conn.pollTx(0, &out_buf)).?;
    try std.testing.expectEqual(payload.len, conn.recovery_state.bytes_in_flight);

    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);

    switch (decoded.frame) {
        .stream => |stream_frame| {
            try std.testing.expectEqual(stream_id, stream_frame.stream_id);
            try std.testing.expectEqual(@as(u64, 0), stream_frame.offset);
            try std.testing.expect(stream_frame.fin);
            try std.testing.expectEqualStrings("hello", stream_frame.data);
        },
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqual(@as(?[]u8, null), try conn.pollTx(0, &out_buf));
}

test "processDatagram and recvOnStream move stream data" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello ", false);
    try client.sendOnStream(stream_id, "world", true);

    var datagram: [128]u8 = undefined;
    try server.processDatagram(0, (try client.pollTx(0, &datagram)).?);
    try server.processDatagram(0, (try client.pollTx(0, &datagram)).?);

    var read_buf: [32]u8 = undefined;
    const n = (try server.recvOnStream(stream_id, &read_buf)).?;
    try std.testing.expectEqualStrings("hello world", read_buf[0..n]);
    try std.testing.expectEqual(@as(?usize, null), try server.recvOnStream(stream_id, &read_buf));
}

test "pollTx returns null when congestion window is full" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "hello", false);

    conn.recovery_state.congestion_window = 0;

    var out_buf: [128]u8 = undefined;
    try std.testing.expectEqual(@as(?[]u8, null), try conn.pollTx(0, &out_buf));

    conn.recovery_state.congestion_window = 128;
    const payload = (try conn.pollTx(0, &out_buf)).?;
    try std.testing.expect(payload.len > 0);
}

test "pollTx checks congestion before writing output buffer" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "hello", false);

    conn.recovery_state.congestion_window = 0;

    var tiny = [_]u8{0xaa};
    try std.testing.expectEqual(@as(?[]u8, null), try conn.pollTx(0, &tiny));
    try std.testing.expectEqual(@as(u8, 0xaa), tiny[0]);
}

test "pollTx keeps queued frame when output buffer is too small" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "hello", false);

    var tiny: [2]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, conn.pollTx(0, &tiny));

    var out_buf: [128]u8 = undefined;
    const payload = (try conn.pollTx(0, &out_buf)).?;
    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);

    switch (decoded.frame) {
        .stream => |stream_frame| try std.testing.expectEqualStrings("hello", stream_frame.data),
        else => return error.TestUnexpectedResult,
    }
}

test "sendOnStream rejects unsendable stream frames before mutating state" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{ .max_datagram_size = 8 });
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try std.testing.expectError(error.BufferTooSmall, conn.sendOnStream(stream_id, "too large", false));

    var out_buf: [32]u8 = undefined;
    try std.testing.expectEqual(@as(?[]u8, null), try conn.pollTx(0, &out_buf));

    try conn.sendOnStream(stream_id, "x", true);
    const payload = (try conn.pollTx(0, &out_buf)).?;
    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);

    switch (decoded.frame) {
        .stream => |stream_frame| {
            try std.testing.expectEqual(@as(u64, 0), stream_frame.offset);
            try std.testing.expect(stream_frame.fin);
            try std.testing.expectEqualStrings("x", stream_frame.data);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "sendOnStream does not create state for oversized new streams" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{ .max_datagram_size = 8 });
    defer conn.deinit();

    try std.testing.expectError(error.BufferTooSmall, conn.sendOnStream(4, "too large", false));
    try std.testing.expectEqual(@as(usize, 0), conn.send_streams.items.len);
}

test "processDatagram preserves out of memory from frame decoding" {
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var conn = try QuicConnection.init(failing_allocator.allocator(), .server, .{});
    defer conn.deinit();

    const wire = [_]u8{
        0x0a, // STREAM with LEN bit
        0x00, // stream id
        0x01, // data length
        'x',
    };

    try std.testing.expectError(error.OutOfMemory, conn.processDatagram(0, &wire));
}

test "processDatagram rejects payloads larger than configured datagram size" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{ .max_datagram_size = 3 });
    defer conn.deinit();

    const wire = [_]u8{
        0x0a, // STREAM with LEN bit
        0x00, // stream id
        0x01, // data length
        'x',
    };

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, &wire));
}

test "processDatagram rejects empty payloads" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, &[_]u8{}));
}

test "processDatagram accepts stream frame without length field" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    const wire = [_]u8{
        0x08, // STREAM without LEN bit
        0x00, // stream id
        'o',
        'k',
    };

    try conn.processDatagram(0, &wire);

    var read_buf: [8]u8 = undefined;
    const n = (try conn.recvOnStream(0, &read_buf)).?;
    try std.testing.expectEqualStrings("ok", read_buf[0..n]);
}

test "processDatagram rolls back stream state when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "x",
    } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items.len);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "a",
    } });
    try conn.processDatagram(0, out.getWritten());

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 1,
        .fin = true,
        .data = "b",
    } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 1), conn.recv_streams.items.len);
    try std.testing.expectEqualStrings("a", conn.recv_streams.items[0].data.items);
    try std.testing.expectEqual(@as(?u64, null), conn.recv_streams.items[0].final_size);
}

test "processDatagram does not create state for out-of-order new streams" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 1,
        .fin = false,
        .data = "x",
    } });

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items.len);
}

test "receive stream rejects data after final size" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = true,
        .data = "hello",
    } });
    try conn.processDatagram(0, out.getWritten());

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 5,
        .fin = false,
        .data = "!",
    } });
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
}

test "receive stream rejects end offset beyond QUIC varint range" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = max_quic_varint,
        .fin = true,
        .data = "x",
    } });

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
}

test "stream ids must fit QUIC varint range" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    try std.testing.expectError(error.InvalidStream, conn.sendOnStream(max_quic_varint + 1, "x", false));

    conn.next_stream_id = max_quic_varint + 1;
    try std.testing.expectError(error.InvalidStream, conn.openStream());
}
