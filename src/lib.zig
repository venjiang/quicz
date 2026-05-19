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
    FlowControlBlocked,
    StreamClosed,
    InvalidStream,
};

/// Runtime configuration for a `QuicConnection`.
pub const Config = struct {
    /// Maximum frame payload bytes accepted or emitted by the in-memory API.
    max_datagram_size: u16 = 1350,
    /// Initial RTT estimate used by recovery before the first ACK sample.
    initial_rtt_ms: u32 = 333,
    /// Initial connection-level stream data limit in both send and receive directions.
    initial_max_data: u64 = 65_536,
    /// Initial per-stream data limit in both send and receive directions.
    initial_max_stream_data: u64 = 65_536,
};

/// Endpoint role. It determines the locally initiated bidirectional stream IDs.
pub const ConnectionSide = enum { client, server };

const PendingStreamFrame = struct {
    stream_id: u64,
    offset: u64,
    fin: bool,
    data: []u8,
};

const SentPacket = struct {
    packet_number: u64,
    sent_time_millis: i64,
    bytes: usize,
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

fn ackFrameWireLen(ack: frame.AckFrame) Error!usize {
    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(ack.largest_acknowledged));
    len = try addWireLen(len, try quicVarIntWireLen(ack.ack_delay));
    len = try addWireLen(len, try quicVarIntWireLen(std.math.cast(u64, ack.ranges.len) orelse return error.Internal));
    len = try addWireLen(len, try quicVarIntWireLen(ack.first_ack_range));
    for (ack.ranges) |range| {
        len = try addWireLen(len, try quicVarIntWireLen(range.gap));
        len = try addWireLen(len, try quicVarIntWireLen(range.ack_range));
    }
    return len;
}

fn streamEndOffset(offset: u64, data_len: usize) ?u64 {
    const len = std.math.cast(u64, data_len) orelse return null;
    const end = std.math.add(u64, offset, len) catch return null;
    if (end > max_quic_varint) return null;
    return end;
}

fn elapsedMillis(sent_time_millis: i64, now_millis: i64) u64 {
    if (now_millis <= sent_time_millis) return 0;
    const delta = std.math.sub(i64, now_millis, sent_time_millis) catch return std.math.maxInt(u64);
    return @intCast(delta);
}

fn ackFrameContains(ack: frame.AckFrame, packet_number: u64) bool {
    if (ack.first_ack_range > ack.largest_acknowledged) return false;

    var range_largest = ack.largest_acknowledged;
    var range_smallest = range_largest - ack.first_ack_range;
    if (packet_number >= range_smallest and packet_number <= range_largest) return true;

    for (ack.ranges) |range| {
        const skipped = std.math.add(u64, range.gap, 2) catch return false;
        if (range_smallest < skipped) return false;
        range_largest = range_smallest - skipped;
        if (range.ack_range > range_largest) return false;
        range_smallest = range_largest - range.ack_range;
        if (packet_number >= range_smallest and packet_number <= range_largest) return true;
    }

    return false;
}

fn frameIsAckEliciting(decoded: frame.Frame) bool {
    return switch (decoded) {
        .padding, .ack, .connection_close, .application_close => false,
        else => true,
    };
}

const SendStreamState = struct {
    stream_id: u64,
    next_offset: u64 = 0,
    max_data: u64,
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
/// the public API. Packet protection, TLS, and network I/O are intentionally
/// outside this connection skeleton.
pub const QuicConnection = struct {
    allocator: std.mem.Allocator,
    config: Config,
    side: ConnectionSide,
    next_stream_id: u64,
    next_packet_number: u64,
    next_peer_packet_number: u64,
    pending_ack_largest: ?u64,
    peer_max_data: u64,
    peer_initial_max_stream_data: u64,
    sent_stream_data_bytes: u64,
    recv_max_data: u64,
    recv_max_stream_data: u64,
    recv_data_bytes: u64,
    recovery_state: recovery.Recovery,
    sent_packets: std.ArrayList(SentPacket),
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
            .next_packet_number = 0,
            .next_peer_packet_number = 0,
            .pending_ack_largest = null,
            .peer_max_data = config.initial_max_data,
            .peer_initial_max_stream_data = config.initial_max_stream_data,
            .sent_stream_data_bytes = 0,
            .recv_max_data = config.initial_max_data,
            .recv_max_stream_data = config.initial_max_stream_data,
            .recv_data_bytes = 0,
            .recovery_state = recovery.Recovery.init(.{
                .max_datagram_size = config.max_datagram_size,
                .initial_rtt_ms = config.initial_rtt_ms,
            }),
            .sent_packets = .empty,
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
        self.sent_packets.deinit(self.allocator);
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
        if (datagram.len == 0 or datagram.len > self.config.max_datagram_size) return error.InvalidPacket;

        const recovery_snapshot = self.recovery_state;
        const sent_packet_count = self.sent_packets.items.len;
        const sent_packet_snapshots = self.allocator.alloc(SentPacket, sent_packet_count) catch return error.OutOfMemory;
        defer self.allocator.free(sent_packet_snapshots);
        @memcpy(sent_packet_snapshots, self.sent_packets.items);

        const next_peer_packet_number_snapshot = self.next_peer_packet_number;
        const pending_ack_largest_snapshot = self.pending_ack_largest;
        const peer_max_data_snapshot = self.peer_max_data;
        const send_stream_count = self.send_streams.items.len;
        const send_stream_snapshots = self.allocator.alloc(SendStreamState, send_stream_count) catch return error.OutOfMemory;
        defer self.allocator.free(send_stream_snapshots);
        @memcpy(send_stream_snapshots, self.send_streams.items);

        const recv_data_bytes_snapshot = self.recv_data_bytes;
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
        errdefer {
            self.rollbackRecvStreams(recv_stream_count, recv_snapshots);
            self.recv_data_bytes = recv_data_bytes_snapshot;
            self.rollbackSendStreams(send_stream_count, send_stream_snapshots);
            self.peer_max_data = peer_max_data_snapshot;
            self.next_peer_packet_number = next_peer_packet_number_snapshot;
            self.pending_ack_largest = pending_ack_largest_snapshot;
            self.rollbackSentPackets(sent_packet_count, sent_packet_snapshots);
            self.recovery_state = recovery_snapshot;
        }

        var ack_eliciting = false;
        var offset: usize = 0;
        while (offset < datagram.len) {
            var decoded = frame.decodeFrameSlice(datagram[offset..], self.allocator) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidPacket,
            };
            defer frame.deinitFrame(&decoded.frame, self.allocator);

            if (decoded.len == 0) return error.InvalidPacket;

            if (frameIsAckEliciting(decoded.frame)) {
                ack_eliciting = true;
            }

            switch (decoded.frame) {
                .ack => |ack| self.receiveAckFrame(now_millis, ack),
                .max_data => |max_data| self.receiveMaxDataFrame(max_data),
                .max_stream_data => |max_stream_data| self.receiveMaxStreamDataFrame(max_stream_data),
                .stream => |stream_frame| try self.receiveStreamFrame(stream_frame),
                else => {},
            }

            offset += decoded.len;
        }

        if (ack_eliciting) {
            try self.queueAckForReceivedPacket();
        }
    }

    /// Return the next unencrypted packet payload to send, or null if idle.
    pub fn pollTx(
        self: *QuicConnection,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        const ack_to_send = self.pendingAckFrame();
        if (self.send_queue.items.len == 0) {
            if (ack_to_send) |ack| {
                return try self.pollAckOnly(ack, out_buf);
            }
            return null;
        }

        const pending = self.send_queue.items[0];
        const stream_encoded_len = try streamFrameWireLen(pending.stream_id, pending.offset, pending.data.len);
        if (stream_encoded_len > self.config.max_datagram_size) return error.BufferTooSmall;

        var encoded_len = stream_encoded_len;
        var include_ack = false;
        if (ack_to_send) |ack| {
            const ack_encoded_len = try ackFrameWireLen(ack);
            const coalesced_len = try addWireLen(ack_encoded_len, stream_encoded_len);
            if (coalesced_len <= self.config.max_datagram_size and out_buf.len >= coalesced_len and self.recovery_state.canSend(coalesced_len)) {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= self.config.max_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.recovery_state.canSend(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        var appended_sent_packet = false;
        errdefer if (appended_sent_packet) {
            self.sent_packets.items.len -= 1;
        };

        const packet_number = self.next_packet_number;
        self.sent_packets.append(self.allocator, .{
            .packet_number = packet_number,
            .sent_time_millis = now_millis,
            .bytes = encoded_len,
        }) catch return error.OutOfMemory;
        appended_sent_packet = true;

        var out = buffer.fixedWriter(out_buf[0..encoded_len]);
        if (include_ack) {
            frame.encodeFrame(out.writer(), .{ .ack = ack_to_send.? }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }
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
        if (include_ack) self.pending_ack_largest = null;
        self.next_packet_number = std.math.add(u64, packet_number, 1) catch return error.Internal;
        self.recovery_state.onPacketSent(written.len);
        return written;
    }

    /// Open a locally initiated bidirectional stream and return its QUIC stream ID.
    pub fn openStream(self: *QuicConnection) Error!u64 {
        const stream_id = self.next_stream_id;
        if (stream_id > max_quic_varint) return error.InvalidStream;

        const next_stream_id = std.math.add(u64, stream_id, 4) catch return error.Internal;

        self.send_streams.append(self.allocator, .{
            .stream_id = stream_id,
            .max_data = self.peer_initial_max_stream_data,
        }) catch return error.OutOfMemory;
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
        const stream_max_data = if (existing_state) |state| state.max_data else self.peer_initial_max_stream_data;
        if (next_offset > stream_max_data) return error.FlowControlBlocked;

        const next_sent_total = streamEndOffset(self.sent_stream_data_bytes, data.len) orelse return error.InvalidStream;
        if (next_sent_total > self.peer_max_data) return error.FlowControlBlocked;

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
            self.send_streams.append(self.allocator, .{
                .stream_id = stream_id,
                .max_data = self.peer_initial_max_stream_data,
            }) catch return error.OutOfMemory;
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
        self.sent_stream_data_bytes = next_sent_total;
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

    fn rollbackSendStreams(
        self: *QuicConnection,
        original_len: usize,
        snapshots: []const SendStreamState,
    ) void {
        self.send_streams.items.len = original_len;
        @memcpy(self.send_streams.items[0..original_len], snapshots);
    }

    fn rollbackSentPackets(
        self: *QuicConnection,
        original_len: usize,
        snapshots: []const SentPacket,
    ) void {
        self.sent_packets.items.len = original_len;
        @memcpy(self.sent_packets.items[0..original_len], snapshots);
    }

    fn receiveAckFrame(self: *QuicConnection, now_millis: i64, ack: frame.AckFrame) void {
        var acked_bytes: usize = 0;
        var largest_acked_packet: ?SentPacket = null;

        var i: usize = 0;
        while (i < self.sent_packets.items.len) {
            if (!ackFrameContains(ack, self.sent_packets.items[i].packet_number)) {
                i += 1;
                continue;
            }

            const removed = self.sent_packets.orderedRemove(i);
            acked_bytes = std.math.add(usize, acked_bytes, removed.bytes) catch std.math.maxInt(usize);
            if (largest_acked_packet == null or removed.packet_number > largest_acked_packet.?.packet_number) {
                largest_acked_packet = removed;
            }
        }

        if (acked_bytes == 0) return;

        const rtt_packet = largest_acked_packet.?;
        self.recovery_state.onPacketAcked(
            acked_bytes,
            elapsedMillis(rtt_packet.sent_time_millis, now_millis),
            ack.ack_delay,
        );
    }

    fn pendingAckFrame(self: QuicConnection) ?frame.AckFrame {
        const largest = self.pending_ack_largest orelse return null;
        return .{
            .largest_acknowledged = largest,
            .ack_delay = 0,
            .first_ack_range = largest,
        };
    }

    fn pollAckOnly(
        self: *QuicConnection,
        ack: frame.AckFrame,
        out_buf: []u8,
    ) Error![]u8 {
        const encoded_len = try ackFrameWireLen(ack);
        if (encoded_len > self.config.max_datagram_size) return error.BufferTooSmall;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;

        var out = buffer.fixedWriter(out_buf[0..encoded_len]);
        frame.encodeFrame(out.writer(), .{ .ack = ack }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        self.pending_ack_largest = null;
        return out.getWritten();
    }

    fn queueAckForReceivedPacket(self: *QuicConnection) Error!void {
        if (self.next_peer_packet_number > max_quic_varint) return error.InvalidPacket;

        const packet_number = self.next_peer_packet_number;
        self.pending_ack_largest = if (self.pending_ack_largest) |largest| @max(largest, packet_number) else packet_number;
        self.next_peer_packet_number = std.math.add(u64, packet_number, 1) catch return error.Internal;
    }

    fn receiveMaxDataFrame(self: *QuicConnection, max_data: frame.MaxDataFrame) void {
        self.peer_max_data = @max(self.peer_max_data, max_data.maximum_data);
    }

    fn receiveMaxStreamDataFrame(self: *QuicConnection, max_stream_data: frame.MaxStreamDataFrame) void {
        const stream_state = self.findSendStream(max_stream_data.stream_id) orelse return;
        stream_state.max_data = @max(stream_state.max_data, max_stream_data.maximum_stream_data);
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
        if (end_offset > self.recv_max_stream_data) return error.InvalidPacket;

        const next_recv_total = streamEndOffset(self.recv_data_bytes, stream_frame.data.len) orelse return error.InvalidPacket;
        if (next_recv_total > self.recv_max_data) return error.InvalidPacket;

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
        self.recv_data_bytes = next_recv_total;
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

test "pollTx records sent packets for ACK-driven recovery" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "hello", false);

    var out_buf: [128]u8 = undefined;
    const payload = (try conn.pollTx(10, &out_buf)).?;

    try std.testing.expectEqual(@as(usize, 1), conn.sent_packets.items.len);
    try std.testing.expectEqual(@as(u64, 0), conn.sent_packets.items[0].packet_number);
    try std.testing.expectEqual(@as(i64, 10), conn.sent_packets.items[0].sent_time_millis);
    try std.testing.expectEqual(payload.len, conn.sent_packets.items[0].bytes);
    try std.testing.expectEqual(@as(u64, 1), conn.next_packet_number);
}

test "processDatagram ACK updates recovery and removes sent packets" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "hello", false);

    var out_buf: [128]u8 = undefined;
    const payload = (try conn.pollTx(10, &out_buf)).?;
    try std.testing.expectEqual(payload.len, conn.recovery_state.bytes_in_flight);

    var ack_buf: [32]u8 = undefined;
    var ack_out = buffer.fixedWriter(&ack_buf);
    try frame.encodeFrame(ack_out.writer(), .{ .ack = .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    } });

    try conn.processDatagram(60, ack_out.getWritten());

    try std.testing.expectEqual(@as(usize, 0), conn.sent_packets.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.recovery_state.bytes_in_flight);
    try std.testing.expectEqual(@as(?u64, 50), conn.recovery_state.latest_rtt_ms);
}

test "processDatagram queues ACK for ack-eliciting payloads" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello", false);

    var datagram: [128]u8 = undefined;
    const stream_payload = (try client.pollTx(10, &datagram)).?;
    try server.processDatagram(20, stream_payload);

    var ack_buf: [32]u8 = undefined;
    const ack_payload = (try server.pollTx(30, &ack_buf)).?;
    try std.testing.expectEqual(@as(usize, 0), server.sent_packets.items.len);
    try std.testing.expectEqual(@as(usize, 0), server.recovery_state.bytes_in_flight);

    var decoded = try frame.decodeFrameSlice(ack_payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .ack => |ack| {
            try std.testing.expectEqual(@as(u64, 0), ack.largest_acknowledged);
            try std.testing.expectEqual(@as(u64, 0), ack.first_ack_range);
        },
        else => return error.TestUnexpectedResult,
    }

    try client.processDatagram(60, ack_payload);
    try std.testing.expectEqual(@as(usize, 0), client.sent_packets.items.len);
    try std.testing.expectEqual(@as(usize, 0), client.recovery_state.bytes_in_flight);
    try std.testing.expectEqual(@as(?u64, 50), client.recovery_state.latest_rtt_ms);
    try std.testing.expectEqual(@as(?[]u8, null), try client.pollTx(70, &datagram));
}

test "pollTx coalesces pending ACK with queued STREAM payload" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello", true);

    var datagram: [128]u8 = undefined;
    try server.processDatagram(20, (try client.pollTx(10, &datagram)).?);

    try server.sendOnStream(stream_id, "echo", true);
    const coalesced = (try server.pollTx(30, &datagram)).?;
    try std.testing.expectEqual(@as(usize, 1), server.sent_packets.items.len);
    try std.testing.expectEqual(coalesced.len, server.sent_packets.items[0].bytes);

    var first = try frame.decodeFrameSlice(coalesced, std.testing.allocator);
    defer frame.deinitFrame(&first.frame, std.testing.allocator);
    switch (first.frame) {
        .ack => |ack| try std.testing.expectEqual(@as(u64, 0), ack.largest_acknowledged),
        else => return error.TestUnexpectedResult,
    }

    var second = try frame.decodeFrameSlice(coalesced[first.len..], std.testing.allocator);
    defer frame.deinitFrame(&second.frame, std.testing.allocator);
    switch (second.frame) {
        .stream => |stream_frame| {
            try std.testing.expectEqual(stream_id, stream_frame.stream_id);
            try std.testing.expect(stream_frame.fin);
            try std.testing.expectEqualStrings("echo", stream_frame.data);
        },
        else => return error.TestUnexpectedResult,
    }

    try client.processDatagram(40, coalesced);
    try std.testing.expectEqual(@as(usize, 0), client.sent_packets.items.len);

    var recv_buf: [16]u8 = undefined;
    const recv_len = (try client.recvOnStream(stream_id, &recv_buf)).?;
    try std.testing.expectEqualStrings("echo", recv_buf[0..recv_len]);

    const ack_back = (try client.pollTx(50, &datagram)).?;
    try server.processDatagram(60, ack_back);
    try std.testing.expectEqual(@as(usize, 0), server.sent_packets.items.len);
}

test "pollTx keeps queued STREAM when pending ACK cannot fit output buffer" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello", false);

    var datagram: [128]u8 = undefined;
    try server.processDatagram(20, (try client.pollTx(10, &datagram)).?);
    try server.sendOnStream(stream_id, "echo", false);

    var tiny = [_]u8{0xaa};
    try std.testing.expectError(error.BufferTooSmall, server.pollTx(30, &tiny));
    try std.testing.expectEqual(@as(u8, 0xaa), tiny[0]);
    try std.testing.expectEqual(@as(?u64, 0), server.pending_ack_largest);
    try std.testing.expectEqual(@as(usize, 1), server.send_queue.items.len);

    const coalesced = (try server.pollTx(40, &datagram)).?;
    var decoded = try frame.decodeFrameSlice(coalesced, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .ack => |ack| try std.testing.expectEqual(@as(u64, 0), ack.largest_acknowledged),
        else => return error.TestUnexpectedResult,
    }
}

test "ACK ranges keep unacknowledged sent packets in flight" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "a", false);
    try conn.sendOnStream(stream_id, "b", false);
    try conn.sendOnStream(stream_id, "c", false);

    var out_buf: [128]u8 = undefined;
    _ = (try conn.pollTx(10, &out_buf)).?;
    const unacked_payload = (try conn.pollTx(20, &out_buf)).?;
    _ = (try conn.pollTx(30, &out_buf)).?;
    try std.testing.expectEqual(@as(usize, 3), conn.sent_packets.items.len);

    const ranges = [_]frame.AckRange{
        .{ .gap = 0, .ack_range = 0 },
    };
    var ack_buf: [32]u8 = undefined;
    var ack_out = buffer.fixedWriter(&ack_buf);
    try frame.encodeFrame(ack_out.writer(), .{ .ack = .{
        .largest_acknowledged = 2,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    } });

    try conn.processDatagram(60, ack_out.getWritten());

    try std.testing.expectEqual(@as(usize, 1), conn.sent_packets.items.len);
    try std.testing.expectEqual(@as(u64, 1), conn.sent_packets.items[0].packet_number);
    try std.testing.expectEqual(unacked_payload.len, conn.recovery_state.bytes_in_flight);
}

test "processDatagram rolls back ACK recovery state when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "hello", false);

    var out_buf: [128]u8 = undefined;
    const payload = (try conn.pollTx(10, &out_buf)).?;

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .ack = .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(60, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 1), conn.sent_packets.items.len);
    try std.testing.expectEqual(@as(u64, 0), conn.sent_packets.items[0].packet_number);
    try std.testing.expectEqual(payload.len, conn.recovery_state.bytes_in_flight);
    try std.testing.expectEqual(@as(?u64, null), conn.recovery_state.latest_rtt_ms);
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

test "sendOnStream enforces connection flow control until MAX_DATA" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 10,
    });
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "12345", false);
    try std.testing.expectError(error.FlowControlBlocked, conn.sendOnStream(stream_id, "x", false));
    try std.testing.expectEqual(@as(u64, 5), conn.sent_stream_data_bytes);
    try std.testing.expectEqual(@as(usize, 1), conn.send_queue.items.len);

    var update_buf: [16]u8 = undefined;
    var update_out = buffer.fixedWriter(&update_buf);
    try frame.encodeFrame(update_out.writer(), .{ .max_data = .{ .maximum_data = 6 } });
    try conn.processDatagram(0, update_out.getWritten());

    try conn.sendOnStream(stream_id, "x", false);
    try std.testing.expectEqual(@as(u64, 6), conn.sent_stream_data_bytes);
    try std.testing.expectEqual(@as(usize, 2), conn.send_queue.items.len);
}

test "sendOnStream enforces stream flow control until MAX_STREAM_DATA" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 10,
        .initial_max_stream_data = 5,
    });
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "12345", false);
    try std.testing.expectError(error.FlowControlBlocked, conn.sendOnStream(stream_id, "x", false));
    try std.testing.expectEqual(@as(u64, 5), conn.findSendStream(stream_id).?.next_offset);

    var update_buf: [32]u8 = undefined;
    var update_out = buffer.fixedWriter(&update_buf);
    try frame.encodeFrame(update_out.writer(), .{ .max_stream_data = .{
        .stream_id = stream_id,
        .maximum_stream_data = 6,
    } });
    try conn.processDatagram(0, update_out.getWritten());

    try conn.sendOnStream(stream_id, "x", false);

    var out_buf: [128]u8 = undefined;
    _ = (try conn.pollTx(0, &out_buf)).?;
    const payload = (try conn.pollTx(0, &out_buf)).?;
    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);

    switch (decoded.frame) {
        .stream => |stream_frame| {
            try std.testing.expectEqual(@as(u64, 5), stream_frame.offset);
            try std.testing.expectEqualStrings("x", stream_frame.data);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "sendOnStream does not create state for flow-control blocked new streams" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 100,
        .initial_max_stream_data = 1,
    });
    defer conn.deinit();

    try std.testing.expectError(error.FlowControlBlocked, conn.sendOnStream(4, "xx", false));
    try std.testing.expectEqual(@as(usize, 0), conn.send_streams.items.len);
    try std.testing.expectEqual(@as(u64, 0), conn.sent_stream_data_bytes);
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

test "processDatagram enforces receive stream flow control" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{
        .initial_max_data = 100,
        .initial_max_stream_data = 5,
    });
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "123456",
    } });

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items.len);
    try std.testing.expectEqual(@as(u64, 0), conn.recv_data_bytes);
}

test "processDatagram enforces receive connection flow control" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 5,
    });
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "12345",
    } });
    try conn.processDatagram(0, out.getWritten());
    try std.testing.expectEqual(@as(u64, 5), conn.recv_data_bytes);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 4,
        .offset = 0,
        .fin = false,
        .data = "x",
    } });

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 1), conn.recv_streams.items.len);
    try std.testing.expectEqual(@as(u64, 5), conn.recv_data_bytes);
}

test "processDatagram rolls back flow-control updates when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 10,
    });
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "12345", false);
    try std.testing.expectError(error.FlowControlBlocked, conn.sendOnStream(stream_id, "x", false));

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .max_data = .{ .maximum_data = 6 } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(u64, 5), conn.peer_max_data);
    try std.testing.expectError(error.FlowControlBlocked, conn.sendOnStream(stream_id, "x", false));
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
