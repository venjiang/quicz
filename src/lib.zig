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
    /// Initial bidirectional stream-count limit in both send and receive directions.
    initial_max_streams_bidi: u64 = 64,
    /// Initial unidirectional stream-count limit in both send and receive directions.
    initial_max_streams_uni: u64 = 64,
};

/// Endpoint role. It determines the locally initiated stream IDs.
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

fn maxStreamFrameDataLen(stream_id: u64, offset: u64, remaining: usize, max_datagram_size: usize) Error!usize {
    if (try streamFrameWireLen(stream_id, offset, 0) > max_datagram_size) return error.BufferTooSmall;
    if (remaining == 0) return 0;

    var best: usize = 0;
    var low: usize = 1;
    var high: usize = remaining;
    while (low <= high) {
        const mid = low + (high - low) / 2;
        const encoded_len = try streamFrameWireLen(stream_id, offset, mid);
        if (encoded_len <= max_datagram_size) {
            best = mid;
            if (mid == std.math.maxInt(usize)) break;
            low = mid + 1;
        } else {
            if (mid == 0) break;
            high = mid - 1;
        }
    }

    if (best == 0) return error.BufferTooSmall;
    return best;
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

fn pathResponseFrameWireLen() usize {
    return 9; // frame type + 8-byte path validation data
}

fn resetStreamFrameWireLen(reset: frame.ResetStreamFrame) Error!usize {
    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(reset.stream_id));
    len = try addWireLen(len, try quicVarIntWireLen(reset.application_error_code));
    return addWireLen(len, try quicVarIntWireLen(reset.final_size));
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
        .padding, .ack, .ack_ecn, .connection_close, .application_close => false,
        else => true,
    };
}

fn isBidirectionalStream(stream_id: u64) bool {
    return (stream_id & 0x02) == 0;
}

fn isLocalStreamInitiator(side: ConnectionSide, stream_id: u64) bool {
    const initiator: ConnectionSide = if ((stream_id & 0x01) == 0) .client else .server;
    return initiator == side;
}

fn isLocalBidirectionalStream(side: ConnectionSide, stream_id: u64) bool {
    return isBidirectionalStream(stream_id) and isLocalStreamInitiator(side, stream_id);
}

fn isLocalUnidirectionalStream(side: ConnectionSide, stream_id: u64) bool {
    return !isBidirectionalStream(stream_id) and isLocalStreamInitiator(side, stream_id);
}

fn streamCountForId(stream_id: u64) u64 {
    return stream_id / 4 + 1;
}

const SendStreamState = struct {
    stream_id: u64,
    next_offset: u64 = 0,
    max_data: u64,
    fin_sent: bool = false,
    reset_sent: bool = false,
};

const RecvStreamState = struct {
    stream_id: u64,
    data: std.ArrayList(u8) = .empty,
    read_offset: usize = 0,
    final_size: ?u64 = null,
    reset_error_code: ?u64 = null,

    fn deinit(self: *RecvStreamState, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
    }
};

const RecvStreamSnapshot = struct {
    data_len: usize,
    read_offset: usize,
    final_size: ?u64,
    reset_error_code: ?u64,
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
    next_uni_stream_id: u64,
    next_packet_number: u64,
    next_peer_packet_number: u64,
    pending_ack_largest: ?u64,
    pending_path_responses: std.ArrayList([8]u8),
    peer_max_data: u64,
    peer_initial_max_stream_data: u64,
    peer_max_streams_bidi: u64,
    peer_max_streams_uni: u64,
    opened_bidi_streams: u64,
    opened_uni_streams: u64,
    sent_stream_data_bytes: u64,
    recv_max_data: u64,
    recv_max_stream_data: u64,
    recv_max_streams_bidi: u64,
    recv_max_streams_uni: u64,
    recv_data_bytes: u64,
    recovery_state: recovery.Recovery,
    sent_packets: std.ArrayList(SentPacket),
    send_queue: std.ArrayList(PendingStreamFrame),
    pending_reset_streams: std.ArrayList(frame.ResetStreamFrame),
    send_streams: std.ArrayList(SendStreamState),
    recv_streams: std.ArrayList(RecvStreamState),
    closed: bool,

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
            .next_uni_stream_id = switch (side) {
                .client => 2,
                .server => 3,
            },
            .next_packet_number = 0,
            .next_peer_packet_number = 0,
            .pending_ack_largest = null,
            .pending_path_responses = .empty,
            .peer_max_data = config.initial_max_data,
            .peer_initial_max_stream_data = config.initial_max_stream_data,
            .peer_max_streams_bidi = config.initial_max_streams_bidi,
            .peer_max_streams_uni = config.initial_max_streams_uni,
            .opened_bidi_streams = 0,
            .opened_uni_streams = 0,
            .sent_stream_data_bytes = 0,
            .recv_max_data = config.initial_max_data,
            .recv_max_stream_data = config.initial_max_stream_data,
            .recv_max_streams_bidi = config.initial_max_streams_bidi,
            .recv_max_streams_uni = config.initial_max_streams_uni,
            .recv_data_bytes = 0,
            .recovery_state = recovery.Recovery.init(.{
                .max_datagram_size = config.max_datagram_size,
                .initial_rtt_ms = config.initial_rtt_ms,
            }),
            .sent_packets = .empty,
            .send_queue = .empty,
            .pending_reset_streams = .empty,
            .send_streams = .empty,
            .recv_streams = .empty,
            .closed = false,
        };
    }

    /// Release all buffers owned by this connection.
    pub fn deinit(self: *QuicConnection) void {
        for (self.send_queue.items) |pending| {
            self.allocator.free(pending.data);
        }
        self.sent_packets.deinit(self.allocator);
        self.pending_path_responses.deinit(self.allocator);
        self.send_queue.deinit(self.allocator);
        self.pending_reset_streams.deinit(self.allocator);
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
        if (self.closed) return error.ConnectionClosed;
        if (datagram.len == 0 or datagram.len > self.config.max_datagram_size) return error.InvalidPacket;

        const recovery_snapshot = self.recovery_state;
        const sent_packet_count = self.sent_packets.items.len;
        const sent_packet_snapshots = self.allocator.alloc(SentPacket, sent_packet_count) catch return error.OutOfMemory;
        defer self.allocator.free(sent_packet_snapshots);
        @memcpy(sent_packet_snapshots, self.sent_packets.items);

        const next_peer_packet_number_snapshot = self.next_peer_packet_number;
        const pending_ack_largest_snapshot = self.pending_ack_largest;
        const pending_path_response_count = self.pending_path_responses.items.len;
        const pending_reset_stream_count = self.pending_reset_streams.items.len;
        const peer_max_data_snapshot = self.peer_max_data;
        const peer_max_streams_bidi_snapshot = self.peer_max_streams_bidi;
        const peer_max_streams_uni_snapshot = self.peer_max_streams_uni;
        const closed_snapshot = self.closed;
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
                .reset_error_code = stream.reset_error_code,
            };
        }
        errdefer {
            self.rollbackRecvStreams(recv_stream_count, recv_snapshots);
            self.recv_data_bytes = recv_data_bytes_snapshot;
            self.rollbackSendStreams(send_stream_count, send_stream_snapshots);
            self.peer_max_streams_uni = peer_max_streams_uni_snapshot;
            self.peer_max_streams_bidi = peer_max_streams_bidi_snapshot;
            self.peer_max_data = peer_max_data_snapshot;
            self.next_peer_packet_number = next_peer_packet_number_snapshot;
            self.pending_ack_largest = pending_ack_largest_snapshot;
            self.pending_path_responses.items.len = pending_path_response_count;
            self.pending_reset_streams.items.len = pending_reset_stream_count;
            self.closed = closed_snapshot;
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
                .ack => |ack| try self.receiveAckFrame(now_millis, ack),
                .ack_ecn => |ack_ecn| try self.receiveAckFrame(now_millis, ack_ecn.ack),
                .max_data => |max_data| self.receiveMaxDataFrame(max_data),
                .max_stream_data => |max_stream_data| self.receiveMaxStreamDataFrame(max_stream_data),
                .max_streams_bidi => |max_streams| self.receiveMaxStreamsBidiFrame(max_streams),
                .max_streams_uni => |max_streams| self.receiveMaxStreamsUniFrame(max_streams),
                .path_challenge => |path_challenge| try self.receivePathChallengeFrame(path_challenge),
                .stop_sending => |stop_sending| try self.receiveStopSendingFrame(stop_sending),
                .reset_stream => |reset_stream| try self.receiveResetStreamFrame(reset_stream),
                .stream => |stream_frame| try self.receiveStreamFrame(stream_frame),
                .handshake_done => if (self.side == .server) return error.InvalidPacket,
                .connection_close, .application_close => self.closed = true,
                else => {},
            }

            offset += decoded.len;
        }

        if (ack_eliciting and !self.closed) {
            try self.queueAckForReceivedPacket();
        }
    }

    /// Return the next unencrypted packet payload to send, or null if idle.
    pub fn pollTx(
        self: *QuicConnection,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        if (self.closed) return error.ConnectionClosed;

        const ack_to_send = self.pendingAckFrame();
        if (self.pending_path_responses.items.len != 0) {
            return try self.pollPathResponse(ack_to_send, now_millis, out_buf);
        }
        if (self.pending_reset_streams.items.len != 0) {
            return try self.pollResetStream(ack_to_send, now_millis, out_buf);
        }

        self.dropResetClosedStreamFrames();

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
        if (self.closed) return error.ConnectionClosed;

        const stream_id = self.next_stream_id;
        if (stream_id > max_quic_varint) return error.InvalidStream;

        const next_stream_id = std.math.add(u64, stream_id, 4) catch return error.Internal;
        if (self.opened_bidi_streams >= self.peer_max_streams_bidi) return error.FlowControlBlocked;

        self.send_streams.append(self.allocator, .{
            .stream_id = stream_id,
            .max_data = self.peer_initial_max_stream_data,
        }) catch return error.OutOfMemory;
        self.next_stream_id = next_stream_id;
        self.opened_bidi_streams = std.math.add(u64, self.opened_bidi_streams, 1) catch return error.Internal;
        return stream_id;
    }

    /// Open a locally initiated unidirectional stream and return its QUIC stream ID.
    pub fn openUniStream(self: *QuicConnection) Error!u64 {
        if (self.closed) return error.ConnectionClosed;

        const stream_id = self.next_uni_stream_id;
        if (stream_id > max_quic_varint) return error.InvalidStream;

        const next_stream_id = std.math.add(u64, stream_id, 4) catch return error.Internal;
        if (self.opened_uni_streams >= self.peer_max_streams_uni) return error.FlowControlBlocked;

        self.send_streams.append(self.allocator, .{
            .stream_id = stream_id,
            .max_data = self.peer_initial_max_stream_data,
        }) catch return error.OutOfMemory;
        self.next_uni_stream_id = next_stream_id;
        self.opened_uni_streams = std.math.add(u64, self.opened_uni_streams, 1) catch return error.Internal;
        return stream_id;
    }

    /// Queue data for a stream. The data is copied and emitted by `pollTx`.
    pub fn sendOnStream(
        self: *QuicConnection,
        stream_id: u64,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (self.closed) return error.ConnectionClosed;
        if (stream_id > max_quic_varint) return error.InvalidStream;
        if (!isBidirectionalStream(stream_id) and !isLocalUnidirectionalStream(self.side, stream_id)) {
            return error.InvalidStream;
        }

        const existing_state = self.findSendStream(stream_id);
        if (existing_state) |state| {
            if (state.fin_sent) return error.StreamClosed;
        } else if (isLocalBidirectionalStream(self.side, stream_id) or isLocalUnidirectionalStream(self.side, stream_id)) {
            return error.InvalidStream;
        } else if (self.findRecvStream(stream_id) == null) {
            return error.InvalidStream;
        }

        const offset = if (existing_state) |state| state.next_offset else 0;
        const next_offset = streamEndOffset(offset, data.len) orelse return error.InvalidStream;
        const stream_max_data = if (existing_state) |state| state.max_data else self.peer_initial_max_stream_data;
        if (next_offset > stream_max_data) return error.FlowControlBlocked;

        const next_sent_total = streamEndOffset(self.sent_stream_data_bytes, data.len) orelse return error.InvalidStream;
        if (next_sent_total > self.peer_max_data) return error.FlowControlBlocked;

        _ = try maxStreamFrameDataLen(stream_id, offset, data.len, self.config.max_datagram_size);

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

        const send_queue_snapshot = self.send_queue.items.len;
        errdefer self.rollbackSendQueue(send_queue_snapshot);

        if (data.len == 0) {
            try self.queueStreamFrame(stream_id, offset, data, fin);
        } else {
            var consumed: usize = 0;
            var frame_offset = offset;
            while (consumed < data.len) {
                const chunk_len = try maxStreamFrameDataLen(
                    stream_id,
                    frame_offset,
                    data.len - consumed,
                    self.config.max_datagram_size,
                );
                const next_consumed = consumed + chunk_len;
                try self.queueStreamFrame(
                    stream_id,
                    frame_offset,
                    data[consumed..next_consumed],
                    fin and next_consumed == data.len,
                );
                frame_offset = streamEndOffset(frame_offset, chunk_len) orelse return error.Internal;
                consumed = next_consumed;
            }
        }

        state.next_offset = next_offset;
        if (fin) state.fin_sent = true;
        self.sent_stream_data_bytes = next_sent_total;
    }

    /// Read queued data for a stream. Returns null when no data is available,
    /// or `StreamClosed` when the peer reset the receive side.
    pub fn recvOnStream(
        self: *QuicConnection,
        stream_id: u64,
        buf: []u8,
    ) Error!?usize {
        if (self.closed) return error.ConnectionClosed;
        if (stream_id > max_quic_varint) return error.InvalidStream;
        if (!isBidirectionalStream(stream_id) and isLocalStreamInitiator(self.side, stream_id)) {
            return error.InvalidStream;
        }

        const stream_state = self.findRecvStream(stream_id) orelse return null;
        if (stream_state.reset_error_code != null) return error.StreamClosed;
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

    fn queueStreamFrame(
        self: *QuicConnection,
        stream_id: u64,
        offset: u64,
        data: []const u8,
        fin: bool,
    ) Error!void {
        const owned = self.allocator.alloc(u8, data.len) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned);
        @memcpy(owned, data);

        self.send_queue.append(self.allocator, .{
            .stream_id = stream_id,
            .offset = offset,
            .fin = fin,
            .data = owned,
        }) catch return error.OutOfMemory;
    }

    fn rollbackSendQueue(self: *QuicConnection, original_len: usize) void {
        while (self.send_queue.items.len > original_len) {
            const removed = self.send_queue.orderedRemove(self.send_queue.items.len - 1);
            self.allocator.free(removed.data);
        }
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
            stream.reset_error_code = snapshot.reset_error_code;
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

    fn receiveAckFrame(self: *QuicConnection, now_millis: i64, ack: frame.AckFrame) Error!void {
        if (ack.largest_acknowledged >= self.next_packet_number) return error.InvalidPacket;

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

    fn pollPathResponse(
        self: *QuicConnection,
        ack_to_send: ?frame.AckFrame,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        const response_encoded_len = pathResponseFrameWireLen();
        if (response_encoded_len > self.config.max_datagram_size) return error.BufferTooSmall;

        var encoded_len = response_encoded_len;
        var include_ack = false;
        if (ack_to_send) |ack| {
            const ack_encoded_len = try ackFrameWireLen(ack);
            const coalesced_len = try addWireLen(ack_encoded_len, response_encoded_len);
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

        const response_data = self.pending_path_responses.items[0];
        var out = buffer.fixedWriter(out_buf[0..encoded_len]);
        if (include_ack) {
            frame.encodeFrame(out.writer(), .{ .ack = ack_to_send.? }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }
        frame.encodeFrame(out.writer(), .{ .path_response = .{ .data = response_data } }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const written = out.getWritten();
        std.debug.assert(written.len == encoded_len);

        _ = self.pending_path_responses.orderedRemove(0);
        if (include_ack) self.pending_ack_largest = null;
        self.next_packet_number = std.math.add(u64, packet_number, 1) catch return error.Internal;
        self.recovery_state.onPacketSent(written.len);
        return written;
    }

    fn pollResetStream(
        self: *QuicConnection,
        ack_to_send: ?frame.AckFrame,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        const reset = self.pending_reset_streams.items[0];
        const reset_encoded_len = try resetStreamFrameWireLen(reset);
        if (reset_encoded_len > self.config.max_datagram_size) return error.BufferTooSmall;

        var encoded_len = reset_encoded_len;
        var include_ack = false;
        if (ack_to_send) |ack| {
            const ack_encoded_len = try ackFrameWireLen(ack);
            const coalesced_len = try addWireLen(ack_encoded_len, reset_encoded_len);
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
        frame.encodeFrame(out.writer(), .{ .reset_stream = reset }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const written = out.getWritten();
        std.debug.assert(written.len == encoded_len);

        _ = self.pending_reset_streams.orderedRemove(0);
        if (include_ack) self.pending_ack_largest = null;
        self.next_packet_number = std.math.add(u64, packet_number, 1) catch return error.Internal;
        self.recovery_state.onPacketSent(written.len);
        return written;
    }

    fn dropResetClosedStreamFrames(self: *QuicConnection) void {
        var i: usize = 0;
        while (i < self.send_queue.items.len) {
            const pending = self.send_queue.items[i];
            const stream_state = self.findSendStream(pending.stream_id) orelse {
                i += 1;
                continue;
            };
            if (!stream_state.reset_sent) {
                i += 1;
                continue;
            }

            const removed = self.send_queue.orderedRemove(i);
            self.allocator.free(removed.data);
        }
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

    fn receiveMaxStreamsBidiFrame(self: *QuicConnection, max_streams: frame.MaxStreamsBidiFrame) void {
        self.peer_max_streams_bidi = @max(self.peer_max_streams_bidi, max_streams.maximum_streams);
    }

    fn receiveMaxStreamsUniFrame(self: *QuicConnection, max_streams: frame.MaxStreamsUniFrame) void {
        self.peer_max_streams_uni = @max(self.peer_max_streams_uni, max_streams.maximum_streams);
    }

    fn receivePathChallengeFrame(self: *QuicConnection, path_challenge: frame.PathChallengeFrame) Error!void {
        self.pending_path_responses.append(self.allocator, path_challenge.data) catch return error.OutOfMemory;
    }

    fn receiveStopSendingFrame(self: *QuicConnection, stop_sending: frame.StopSendingFrame) Error!void {
        if (stop_sending.stream_id > max_quic_varint) return error.InvalidStream;

        if (!isBidirectionalStream(stop_sending.stream_id)) {
            if (!isLocalStreamInitiator(self.side, stop_sending.stream_id)) return error.InvalidPacket;
            const stream_state = self.findSendStream(stop_sending.stream_id) orelse return error.InvalidPacket;
            try self.queueResetStreamForStopSending(stream_state, stop_sending.application_error_code);
            return;
        }

        if (isLocalStreamInitiator(self.side, stop_sending.stream_id)) {
            const stream_state = self.findSendStream(stop_sending.stream_id) orelse return error.InvalidPacket;
            try self.queueResetStreamForStopSending(stream_state, stop_sending.application_error_code);
            return;
        }

        if (streamCountForId(stop_sending.stream_id) > self.recv_max_streams_bidi) return error.InvalidPacket;

        const existing_state = self.findSendStream(stop_sending.stream_id);
        var appended_send_state = false;
        errdefer if (appended_send_state) {
            _ = self.send_streams.orderedRemove(self.send_streams.items.len - 1);
        };

        const stream_state = existing_state orelse blk: {
            self.send_streams.append(self.allocator, .{
                .stream_id = stop_sending.stream_id,
                .max_data = self.peer_initial_max_stream_data,
            }) catch return error.OutOfMemory;
            appended_send_state = true;
            break :blk &self.send_streams.items[self.send_streams.items.len - 1];
        };
        try self.queueResetStreamForStopSending(stream_state, stop_sending.application_error_code);
    }

    fn queueResetStreamForStopSending(
        self: *QuicConnection,
        stream_state: *SendStreamState,
        application_error_code: u64,
    ) Error!void {
        if (stream_state.reset_sent) return;

        self.pending_reset_streams.append(self.allocator, .{
            .stream_id = stream_state.stream_id,
            .application_error_code = application_error_code,
            .final_size = stream_state.next_offset,
        }) catch return error.OutOfMemory;
        stream_state.fin_sent = true;
        stream_state.reset_sent = true;
    }

    fn validateIncomingStreamCount(self: *QuicConnection, stream_id: u64) Error!void {
        if (isLocalBidirectionalStream(self.side, stream_id)) {
            if (self.findSendStream(stream_id) == null) return error.InvalidPacket;
            return;
        }
        if (isBidirectionalStream(stream_id)) {
            if (streamCountForId(stream_id) > self.recv_max_streams_bidi) return error.InvalidPacket;
            return;
        }
        if (isLocalStreamInitiator(self.side, stream_id)) return error.InvalidPacket;
        if (streamCountForId(stream_id) > self.recv_max_streams_uni) return error.InvalidPacket;
    }

    fn receiveResetStreamFrame(self: *QuicConnection, reset: frame.ResetStreamFrame) Error!void {
        if (reset.stream_id > max_quic_varint) return error.InvalidStream;
        try self.validateIncomingStreamCount(reset.stream_id);
        if (reset.final_size > self.recv_max_stream_data) return error.InvalidPacket;

        const existing_state = self.findRecvStream(reset.stream_id);
        var appended_recv_state = false;
        errdefer if (appended_recv_state) {
            var removed = self.recv_streams.orderedRemove(self.recv_streams.items.len - 1);
            removed.deinit(self.allocator);
        };

        const stream_state = existing_state orelse blk: {
            self.recv_streams.append(self.allocator, .{ .stream_id = reset.stream_id }) catch return error.OutOfMemory;
            appended_recv_state = true;
            break :blk &self.recv_streams.items[self.recv_streams.items.len - 1];
        };

        const current_size = std.math.cast(u64, stream_state.data.items.len) orelse return error.Internal;
        if (reset.final_size < current_size) return error.InvalidPacket;
        if (stream_state.final_size) |final_size| {
            if (final_size != reset.final_size) return error.InvalidPacket;
            return;
        }

        const delta = reset.final_size - current_size;
        const next_recv_total = std.math.add(u64, self.recv_data_bytes, delta) catch return error.InvalidPacket;
        if (next_recv_total > self.recv_max_data) return error.InvalidPacket;

        self.recv_data_bytes = next_recv_total;
        stream_state.final_size = reset.final_size;
        stream_state.reset_error_code = reset.application_error_code;
    }

    fn receiveStreamFrame(self: *QuicConnection, stream_frame: frame.StreamFrame) Error!void {
        if (stream_frame.stream_id > max_quic_varint) return error.InvalidStream;
        try self.validateIncomingStreamCount(stream_frame.stream_id);

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

test "openStream enforces peer bidirectional stream limit until MAX_STREAMS_BIDI" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{ .initial_max_streams_bidi = 1 });
    defer conn.deinit();

    try std.testing.expectEqual(@as(u64, 0), try conn.openStream());
    try std.testing.expectError(error.FlowControlBlocked, conn.openStream());
    try std.testing.expectEqual(@as(u64, 1), conn.opened_bidi_streams);
    try std.testing.expectEqual(@as(usize, 1), conn.send_streams.items.len);

    var update_buf: [16]u8 = undefined;
    var update_out = buffer.fixedWriter(&update_buf);
    try frame.encodeFrame(update_out.writer(), .{ .max_streams_bidi = .{ .maximum_streams = 2 } });
    try conn.processDatagram(0, update_out.getWritten());

    try std.testing.expectEqual(@as(u64, 4), try conn.openStream());
    try std.testing.expectEqual(@as(u64, 2), conn.opened_bidi_streams);
}

test "openUniStream allocates unidirectional stream ids and enforces MAX_STREAMS_UNI" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{ .initial_max_streams_uni = 1 });
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try std.testing.expectEqual(@as(u64, 2), try client.openUniStream());
    try std.testing.expectError(error.FlowControlBlocked, client.openUniStream());
    try std.testing.expectEqual(@as(u64, 1), client.opened_uni_streams);
    try std.testing.expectEqual(@as(usize, 1), client.send_streams.items.len);
    try std.testing.expectEqual(@as(u64, 3), try server.openUniStream());

    var update_buf: [16]u8 = undefined;
    var update_out = buffer.fixedWriter(&update_buf);
    try frame.encodeFrame(update_out.writer(), .{ .max_streams_uni = .{ .maximum_streams = 2 } });
    try client.processDatagram(0, update_out.getWritten());

    try std.testing.expectEqual(@as(u64, 6), try client.openUniStream());
    try std.testing.expectEqual(@as(u64, 2), client.opened_uni_streams);
}

test "sendOnStream requires openStream for new local bidirectional streams" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    try std.testing.expectError(error.InvalidStream, conn.sendOnStream(0, "x", false));
    try std.testing.expectEqual(@as(usize, 0), conn.send_streams.items.len);
    try std.testing.expectEqual(@as(u64, 0), conn.opened_bidi_streams);

    const stream_id = try conn.openStream();
    try std.testing.expectEqual(@as(u64, 0), stream_id);
    try conn.sendOnStream(stream_id, "x", false);
    try std.testing.expectEqual(@as(u64, 1), conn.opened_bidi_streams);
}

test "sendOnStream requires opened local unidirectional streams" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try std.testing.expectError(error.InvalidStream, client.sendOnStream(2, "x", false));
    try std.testing.expectError(error.InvalidStream, client.sendOnStream(3, "x", false));
    try std.testing.expectError(error.InvalidStream, server.sendOnStream(2, "x", false));
    try std.testing.expectError(error.InvalidStream, server.sendOnStream(3, "x", false));
    try std.testing.expectEqual(@as(usize, 0), client.send_streams.items.len);
    try std.testing.expectEqual(@as(usize, 0), server.send_streams.items.len);
}

test "sendOnStream and pollTx emit opened local unidirectional stream frames" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openUniStream();
    try conn.sendOnStream(stream_id, "uni", true);

    var out_buf: [128]u8 = undefined;
    const payload = (try conn.pollTx(0, &out_buf)).?;

    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);

    switch (decoded.frame) {
        .stream => |stream_frame| {
            try std.testing.expectEqual(@as(u64, 2), stream_frame.stream_id);
            try std.testing.expectEqualStrings("uni", stream_frame.data);
            try std.testing.expect(stream_frame.fin);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "sendOnStream requires observed peer bidirectional streams" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    try std.testing.expectError(error.InvalidStream, conn.sendOnStream(1, "reply", false));

    var datagram: [16]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 1,
        .offset = 0,
        .fin = false,
        .data = "",
    } });
    try conn.processDatagram(0, out.getWritten());

    try conn.sendOnStream(1, "reply", false);
    try std.testing.expectEqual(@as(usize, 1), conn.send_streams.items.len);
}

test "processDatagram rolls back MAX_STREAMS_BIDI updates when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{ .initial_max_streams_bidi = 1 });
    defer conn.deinit();

    try std.testing.expectEqual(@as(u64, 0), try conn.openStream());
    try std.testing.expectError(error.FlowControlBlocked, conn.openStream());

    var datagram: [16]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .max_streams_bidi = .{ .maximum_streams = 2 } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(u64, 1), conn.peer_max_streams_bidi);
    try std.testing.expectError(error.FlowControlBlocked, conn.openStream());
}

test "processDatagram rolls back MAX_STREAMS_UNI updates when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{ .initial_max_streams_uni = 1 });
    defer conn.deinit();

    try std.testing.expectEqual(@as(u64, 2), try conn.openUniStream());
    try std.testing.expectError(error.FlowControlBlocked, conn.openUniStream());

    var datagram: [16]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .max_streams_uni = .{ .maximum_streams = 2 } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(u64, 1), conn.peer_max_streams_uni);
    try std.testing.expectError(error.FlowControlBlocked, conn.openUniStream());
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

test "sendOnStream fragments stream data by max datagram size" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{ .max_datagram_size = 10 });
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "abcdefghijklmnop", true);

    const Expected = struct {
        offset: u64,
        data: []const u8,
        fin: bool,
    };
    const expected = [_]Expected{
        .{ .offset = 0, .data = "abcdefg", .fin = false },
        .{ .offset = 7, .data = "hijklm", .fin = false },
        .{ .offset = 13, .data = "nop", .fin = true },
    };

    var out_buf: [10]u8 = undefined;
    for (expected) |want| {
        const payload = (try conn.pollTx(0, &out_buf)).?;
        try std.testing.expect(payload.len <= out_buf.len);

        var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
        defer frame.deinitFrame(&decoded.frame, std.testing.allocator);

        switch (decoded.frame) {
            .stream => |stream_frame| {
                try std.testing.expectEqual(stream_id, stream_frame.stream_id);
                try std.testing.expectEqual(want.offset, stream_frame.offset);
                try std.testing.expectEqual(want.fin, stream_frame.fin);
                try std.testing.expectEqualStrings(want.data, stream_frame.data);
            },
            else => return error.TestUnexpectedResult,
        }
    }

    try std.testing.expectEqual(@as(?[]u8, null), try conn.pollTx(0, &out_buf));
    try std.testing.expectEqual(@as(u64, 16), conn.findSendStream(stream_id).?.next_offset);
    try std.testing.expect(conn.findSendStream(stream_id).?.fin_sent);
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

test "processDatagram ACK_ECN updates recovery without queuing ACK" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "hello", false);

    var out_buf: [128]u8 = undefined;
    const payload = (try conn.pollTx(10, &out_buf)).?;
    try std.testing.expectEqual(payload.len, conn.recovery_state.bytes_in_flight);

    var ack_buf: [32]u8 = undefined;
    var ack_out = buffer.fixedWriter(&ack_buf);
    try frame.encodeFrame(ack_out.writer(), .{ .ack_ecn = .{
        .ack = .{
            .largest_acknowledged = 0,
            .ack_delay = 0,
            .first_ack_range = 0,
        },
        .ecn_counts = .{
            .ect0_count = 1,
            .ect1_count = 0,
            .ecn_ce_count = 0,
        },
    } });

    try conn.processDatagram(60, ack_out.getWritten());

    try std.testing.expectEqual(@as(usize, 0), conn.sent_packets.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.recovery_state.bytes_in_flight);
    try std.testing.expectEqual(@as(?u64, 50), conn.recovery_state.latest_rtt_ms);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
}

test "processDatagram rejects ACK for packet number never sent" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "hello", false);

    var out_buf: [128]u8 = undefined;
    const payload = (try conn.pollTx(10, &out_buf)).?;
    try std.testing.expectEqual(@as(u64, 1), conn.next_packet_number);

    var ack_buf: [32]u8 = undefined;
    var ack_out = buffer.fixedWriter(&ack_buf);
    try frame.encodeFrame(ack_out.writer(), .{ .ack = .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    } });

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(60, ack_out.getWritten()));
    try std.testing.expectEqual(@as(usize, 1), conn.sent_packets.items.len);
    try std.testing.expectEqual(@as(u64, 0), conn.sent_packets.items[0].packet_number);
    try std.testing.expectEqual(payload.len, conn.recovery_state.bytes_in_flight);
    try std.testing.expectEqual(@as(?u64, null), conn.recovery_state.latest_rtt_ms);
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

test "PATH_CHALLENGE queues PATH_RESPONSE with pending ACK" {
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    const challenge_data = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0, 1, 2, 3 };
    var challenge_buf: [16]u8 = undefined;
    var challenge_out = buffer.fixedWriter(&challenge_buf);
    try frame.encodeFrame(challenge_out.writer(), .{ .path_challenge = .{ .data = challenge_data } });

    try server.processDatagram(20, challenge_out.getWritten());
    try std.testing.expectEqual(@as(usize, 1), server.pending_path_responses.items.len);
    try std.testing.expectEqual(@as(?u64, 0), server.pending_ack_largest);

    var out_buf: [64]u8 = undefined;
    const response_payload = (try server.pollTx(30, &out_buf)).?;
    try std.testing.expectEqual(@as(usize, 1), server.sent_packets.items.len);
    try std.testing.expectEqual(@as(usize, 0), server.pending_path_responses.items.len);
    try std.testing.expectEqual(@as(?u64, null), server.pending_ack_largest);

    var ack = try frame.decodeFrameSlice(response_payload, std.testing.allocator);
    defer frame.deinitFrame(&ack.frame, std.testing.allocator);
    switch (ack.frame) {
        .ack => |ack_frame| try std.testing.expectEqual(@as(u64, 0), ack_frame.largest_acknowledged),
        else => return error.TestUnexpectedResult,
    }

    var response = try frame.decodeFrameSlice(response_payload[ack.len..], std.testing.allocator);
    defer frame.deinitFrame(&response.frame, std.testing.allocator);
    switch (response.frame) {
        .path_response => |path_response| try std.testing.expectEqualSlices(u8, &challenge_data, &path_response.data),
        else => return error.TestUnexpectedResult,
    }
}

test "processDatagram rolls back PATH_RESPONSE state when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .path_challenge = .{ .data = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 } } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_path_responses.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 0), conn.next_peer_packet_number);

    var out_buf: [64]u8 = undefined;
    try std.testing.expectEqual(@as(?[]u8, null), try conn.pollTx(0, &out_buf));
}

test "STOP_SENDING queues RESET_STREAM and drops unsent stream data" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "hello", false);

    var stop_buf: [16]u8 = undefined;
    var stop_out = buffer.fixedWriter(&stop_buf);
    try frame.encodeFrame(stop_out.writer(), .{ .stop_sending = .{
        .stream_id = stream_id,
        .application_error_code = 7,
    } });
    try conn.processDatagram(10, stop_out.getWritten());

    try std.testing.expect(conn.findSendStream(stream_id).?.reset_sent);
    try std.testing.expectError(error.StreamClosed, conn.sendOnStream(stream_id, "again", false));
    try std.testing.expectEqual(@as(usize, 1), conn.pending_reset_streams.items.len);

    var out_buf: [64]u8 = undefined;
    const reset_payload = (try conn.pollTx(20, &out_buf)).?;

    var ack = try frame.decodeFrameSlice(reset_payload, std.testing.allocator);
    defer frame.deinitFrame(&ack.frame, std.testing.allocator);
    switch (ack.frame) {
        .ack => |ack_frame| try std.testing.expectEqual(@as(u64, 0), ack_frame.largest_acknowledged),
        else => return error.TestUnexpectedResult,
    }

    var reset = try frame.decodeFrameSlice(reset_payload[ack.len..], std.testing.allocator);
    defer frame.deinitFrame(&reset.frame, std.testing.allocator);
    switch (reset.frame) {
        .reset_stream => |reset_frame| {
            try std.testing.expectEqual(stream_id, reset_frame.stream_id);
            try std.testing.expectEqual(@as(u64, 7), reset_frame.application_error_code);
            try std.testing.expectEqual(@as(u64, 5), reset_frame.final_size);
        },
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqual(@as(usize, 1), conn.send_queue.items.len);
    try std.testing.expectEqual(@as(?[]u8, null), try conn.pollTx(30, &out_buf));
    try std.testing.expectEqual(@as(usize, 0), conn.send_queue.items.len);
}

test "STOP_SENDING on peer bidirectional stream prevents later reply" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var stop_buf: [16]u8 = undefined;
    var stop_out = buffer.fixedWriter(&stop_buf);
    try frame.encodeFrame(stop_out.writer(), .{ .stop_sending = .{
        .stream_id = 0,
        .application_error_code = 9,
    } });
    try conn.processDatagram(0, stop_out.getWritten());

    try std.testing.expectError(error.StreamClosed, conn.sendOnStream(0, "reply", false));

    var out_buf: [64]u8 = undefined;
    const reset_payload = (try conn.pollTx(0, &out_buf)).?;
    var ack = try frame.decodeFrameSlice(reset_payload, std.testing.allocator);
    defer frame.deinitFrame(&ack.frame, std.testing.allocator);
    switch (ack.frame) {
        .ack => |ack_frame| try std.testing.expectEqual(@as(u64, 0), ack_frame.largest_acknowledged),
        else => return error.TestUnexpectedResult,
    }

    var reset = try frame.decodeFrameSlice(reset_payload[ack.len..], std.testing.allocator);
    defer frame.deinitFrame(&reset.frame, std.testing.allocator);
    switch (reset.frame) {
        .reset_stream => |reset_frame| {
            try std.testing.expectEqual(@as(u64, 0), reset_frame.stream_id);
            try std.testing.expectEqual(@as(u64, 9), reset_frame.application_error_code);
            try std.testing.expectEqual(@as(u64, 0), reset_frame.final_size);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "STOP_SENDING rolls back reset state when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stop_sending = .{
        .stream_id = stream_id,
        .application_error_code = 1,
    } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expect(!conn.findSendStream(stream_id).?.reset_sent);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_reset_streams.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 0), conn.next_peer_packet_number);

    try conn.sendOnStream(stream_id, "ok", false);
}

test "STOP_SENDING validates stream direction and count before queuing reset" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{
        .initial_max_streams_bidi = 1,
        .initial_max_streams_uni = 1,
    });
    defer conn.deinit();

    var datagram: [16]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stop_sending = .{
        .stream_id = 2,
        .application_error_code = 1,
    } });

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_reset_streams.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.send_streams.items.len);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stop_sending = .{
        .stream_id = 4,
        .application_error_code = 1,
    } });

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_reset_streams.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.send_streams.items.len);
}

test "duplicate STOP_SENDING does not queue duplicate RESET_STREAM" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    var stop_buf: [16]u8 = undefined;
    var stop_out = buffer.fixedWriter(&stop_buf);
    try frame.encodeFrame(stop_out.writer(), .{ .stop_sending = .{
        .stream_id = stream_id,
        .application_error_code = 1,
    } });

    try conn.processDatagram(0, stop_out.getWritten());
    try conn.processDatagram(1, stop_out.getWritten());
    try std.testing.expectEqual(@as(usize, 1), conn.pending_reset_streams.items.len);
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

test "RESET_STREAM closes receive stream and accounts final size once" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 10,
    });
    defer conn.deinit();

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = 42,
        .final_size = 5,
    } });
    try conn.processDatagram(0, out.getWritten());
    try std.testing.expectEqual(@as(u64, 5), conn.recv_data_bytes);
    try std.testing.expectEqual(@as(?u64, 42), conn.recv_streams.items[0].reset_error_code);

    var read_buf: [8]u8 = undefined;
    try std.testing.expectError(error.StreamClosed, conn.recvOnStream(0, &read_buf));

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = 99,
        .final_size = 5,
    } });
    try conn.processDatagram(0, out.getWritten());
    try std.testing.expectEqual(@as(u64, 5), conn.recv_data_bytes);
    try std.testing.expectEqual(@as(?u64, 42), conn.recv_streams.items[0].reset_error_code);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 4,
        .offset = 0,
        .fin = false,
        .data = "x",
    } });
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
}

test "RESET_STREAM rejects inconsistent final size and rolls back state" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "abc",
    } });
    try conn.processDatagram(0, out.getWritten());

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = 1,
        .final_size = 2,
    } });
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(u64, 3), conn.recv_data_bytes);
    try std.testing.expectEqual(@as(?u64, null), conn.recv_streams.items[0].reset_error_code);

    var read_buf: [8]u8 = undefined;
    const n = (try conn.recvOnStream(0, &read_buf)).?;
    try std.testing.expectEqualStrings("abc", read_buf[0..n]);
}

test "RESET_STREAM after FIN with same final size keeps received data readable" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = true,
        .data = "abc",
    } });
    try conn.processDatagram(0, out.getWritten());

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = 1,
        .final_size = 3,
    } });
    try conn.processDatagram(0, out.getWritten());
    try std.testing.expectEqual(@as(?u64, null), conn.recv_streams.items[0].reset_error_code);

    var read_buf: [8]u8 = undefined;
    const n = (try conn.recvOnStream(0, &read_buf)).?;
    try std.testing.expectEqualStrings("abc", read_buf[0..n]);
    try std.testing.expectEqual(@as(?usize, null), try conn.recvOnStream(0, &read_buf));
}

test "RESET_STREAM flow-control violation does not create receive state" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{
        .initial_max_data = 2,
        .initial_max_stream_data = 10,
    });
    defer conn.deinit();

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = 1,
        .final_size = 3,
    } });

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(u64, 0), conn.recv_data_bytes);
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items.len);
}

test "processDatagram enforces inbound bidirectional stream count for STREAM" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{ .initial_max_streams_bidi = 1 });
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 4,
        .offset = 0,
        .fin = false,
        .data = "x",
    } });

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items.len);
    try std.testing.expectEqual(@as(u64, 0), conn.recv_data_bytes);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "ok",
    } });
    try conn.processDatagram(0, out.getWritten());
    try std.testing.expectEqual(@as(usize, 1), conn.recv_streams.items.len);
}

test "processDatagram enforces inbound bidirectional stream count for RESET_STREAM" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{ .initial_max_streams_bidi = 1 });
    defer conn.deinit();

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .reset_stream = .{
        .stream_id = 4,
        .application_error_code = 1,
        .final_size = 0,
    } });

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items.len);
    try std.testing.expectEqual(@as(u64, 0), conn.recv_data_bytes);
}

test "processDatagram enforces inbound unidirectional stream count" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{ .initial_max_streams_uni = 1 });
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 6,
        .offset = 0,
        .fin = false,
        .data = "x",
    } });

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items.len);
    try std.testing.expectEqual(@as(u64, 0), conn.recv_data_bytes);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 2,
        .offset = 0,
        .fin = false,
        .data = "ok",
    } });
    try conn.processDatagram(0, out.getWritten());
    try std.testing.expectEqual(@as(usize, 1), conn.recv_streams.items.len);
}

test "processDatagram rejects local bidirectional streams that were not opened" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "x",
    } });
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items.len);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = 1,
        .final_size = 0,
    } });
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items.len);

    _ = try conn.openStream();
    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "ok",
    } });
    try conn.processDatagram(0, out.getWritten());
    try std.testing.expectEqual(@as(usize, 1), conn.recv_streams.items.len);
}

test "processDatagram accepts peer unidirectional stream receive state" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 2,
        .offset = 0,
        .fin = false,
        .data = "x",
    } });
    try conn.processDatagram(0, out.getWritten());
    try std.testing.expectEqual(@as(usize, 1), conn.recv_streams.items.len);

    var read_buf: [8]u8 = undefined;
    const n = (try conn.recvOnStream(2, &read_buf)).?;
    try std.testing.expectEqualStrings("x", read_buf[0..n]);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .reset_stream = .{
        .stream_id = 6,
        .application_error_code = 1,
        .final_size = 1,
    } });
    try conn.processDatagram(0, out.getWritten());
    try std.testing.expectEqual(@as(usize, 2), conn.recv_streams.items.len);
    try std.testing.expectEqual(@as(?u64, 1), conn.findRecvStream(6).?.reset_error_code);
}

test "processDatagram rejects local unidirectional stream receive state" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    _ = try conn.openUniStream();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 3,
        .offset = 0,
        .fin = false,
        .data = "x",
    } });
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items.len);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .reset_stream = .{
        .stream_id = 3,
        .application_error_code = 1,
        .final_size = 0,
    } });
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items.len);
}

test "recvOnStream rejects locally initiated unidirectional streams" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openUniStream();

    var read_buf: [8]u8 = undefined;
    try std.testing.expectError(error.InvalidStream, conn.recvOnStream(stream_id, &read_buf));
}

test "client accepts HANDSHAKE_DONE and queues ACK" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const payload = [_]u8{@intFromEnum(frame.FrameType.handshake_done)};
    try conn.processDatagram(0, &payload);

    try std.testing.expectEqual(@as(?u64, 0), conn.pending_ack_largest);

    var out_buf: [16]u8 = undefined;
    const ack_payload = (try conn.pollTx(0, &out_buf)).?;
    var decoded = try frame.decodeFrameSlice(ack_payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);

    switch (decoded.frame) {
        .ack => |ack| try std.testing.expectEqual(@as(u64, 0), ack.largest_acknowledged),
        else => return error.TestUnexpectedResult,
    }
}

test "server rejects HANDSHAKE_DONE from peer" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    const payload = [_]u8{@intFromEnum(frame.FrameType.handshake_done)};
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, &payload));
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 0), conn.next_peer_packet_number);

    var out_buf: [16]u8 = undefined;
    try std.testing.expectEqual(@as(?[]u8, null), try conn.pollTx(0, &out_buf));
}

test "connection close frame closes public connection API" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var close_buf: [64]u8 = undefined;
    var close_out = buffer.fixedWriter(&close_buf);
    try frame.encodeFrame(close_out.writer(), .{ .connection_close = .{
        .error_code = 0,
        .frame_type = @intFromEnum(frame.FrameType.stream),
        .reason_phrase = "done",
    } });

    try conn.processDatagram(0, close_out.getWritten());
    try std.testing.expect(conn.closed);

    var out_buf: [32]u8 = undefined;
    try std.testing.expectError(error.ConnectionClosed, conn.pollTx(0, &out_buf));
    try std.testing.expectError(error.ConnectionClosed, conn.openStream());
    try std.testing.expectError(error.ConnectionClosed, conn.openUniStream());
    try std.testing.expectError(error.ConnectionClosed, conn.sendOnStream(0, "x", false));

    var recv_buf: [8]u8 = undefined;
    try std.testing.expectError(error.ConnectionClosed, conn.recvOnStream(0, &recv_buf));

    const ping = [_]u8{@intFromEnum(frame.FrameType.ping)};
    try std.testing.expectError(error.ConnectionClosed, conn.processDatagram(0, &ping));
}

test "invalid payload rolls back connection close state" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .application_close = .{
        .error_code = 0,
        .reason_phrase = "bad tail",
    } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expect(!conn.closed);
    try std.testing.expectEqual(@as(u64, 1), try conn.openStream());
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
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{ .max_datagram_size = 3 });
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try std.testing.expectError(error.BufferTooSmall, conn.sendOnStream(stream_id, "too large", false));

    var out_buf: [32]u8 = undefined;
    try std.testing.expectEqual(@as(?[]u8, null), try conn.pollTx(0, &out_buf));

    try conn.sendOnStream(stream_id, "", true);
    const payload = (try conn.pollTx(0, &out_buf)).?;
    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);

    switch (decoded.frame) {
        .stream => |stream_frame| {
            try std.testing.expectEqual(@as(u64, 0), stream_frame.offset);
            try std.testing.expect(stream_frame.fin);
            try std.testing.expectEqualStrings("", stream_frame.data);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "sendOnStream does not create state for oversized new streams" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{ .max_datagram_size = 3 });
    defer conn.deinit();

    var datagram: [8]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 1,
        .offset = 0,
        .fin = false,
        .data = "",
    } });
    try conn.processDatagram(0, out.getWritten());

    try std.testing.expectError(error.BufferTooSmall, conn.sendOnStream(1, "too large", false));
    try std.testing.expectEqual(@as(usize, 0), conn.send_streams.items.len);
}

test "sendOnStream rolls back partial fragmentation when later offsets cannot fit" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{ .max_datagram_size = 4 });
    defer conn.deinit();

    var datagram: [8]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 1,
        .offset = 0,
        .fin = false,
        .data = "",
    } });
    try conn.processDatagram(0, out.getWritten());

    try std.testing.expectError(error.BufferTooSmall, conn.sendOnStream(1, "ab", false));
    try std.testing.expectEqual(@as(usize, 0), conn.send_streams.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.send_queue.items.len);
    try std.testing.expectEqual(@as(u64, 0), conn.sent_stream_data_bytes);
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

    var datagram: [8]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 1,
        .offset = 0,
        .fin = false,
        .data = "",
    } });
    try conn.processDatagram(0, out.getWritten());

    try std.testing.expectError(error.FlowControlBlocked, conn.sendOnStream(1, "xx", false));
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

test "processDatagram rejects truncated ACK ranges before allocation" {
    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var conn = try QuicConnection.init(failing_allocator.allocator(), .server, .{});
    defer conn.deinit();

    const wire = [_]u8{
        @intFromEnum(frame.FrameType.ack),
        0x00, // largest acknowledged
        0x00, // ack delay
        0x01, // one additional ACK range
        0x00, // first ACK range
    };

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, &wire));
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

    conn.next_uni_stream_id = max_quic_varint + 1;
    try std.testing.expectError(error.InvalidStream, conn.openUniStream());
}
