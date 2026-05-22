const std = @import("std");

pub const packet = @import("quic/packet.zig");
pub const frame = @import("quic/frame.zig");
pub const recovery = @import("quic/recovery.zig");
pub const protection = @import("quic/protection.zig");
pub const transport_error = @import("quic/transport_error.zig");
pub const transport_parameters = @import("quic/transport_parameters.zig");
const buffer = @import("quic/buffer.zig");

test {
    _ = protection;
    _ = transport_error;
    _ = transport_parameters;
}

const max_quic_varint = 4611686018427387903;
const max_stream_count = @as(u64, 1) << 60;
const max_connection_id_len = 20;
const min_active_connection_id_limit = 2;
const default_max_stored_new_tokens: usize = 4;
const close_state_pto_multiplier: u64 = 3;
const max_path_challenge_transmissions: u8 = 3;
const packet_threshold_loss_gap: u64 = 3;
const anti_amplification_multiplier: usize = 3;

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
    /// Local max_idle_timeout transport parameter in milliseconds. Zero disables the local side.
    max_idle_timeout_ms: u64 = 0,
    /// Advertise that this endpoint does not support active connection migration.
    disable_active_migration: bool = false,
    /// Optional server stateless_reset_token transport parameter for the handshake CID.
    ///
    /// QUIC clients must not send this parameter, so client connections ignore
    /// this value when exporting local transport parameters.
    stateless_reset_token: ?[packet.stateless_reset_token_len]u8 = null,
    /// Initial connection-level stream data limit in both send and receive directions.
    initial_max_data: u64 = 65_536,
    /// Initial per-stream data limit in both send and receive directions.
    initial_max_stream_data: u64 = 65_536,
    /// Initial bidirectional stream-count limit in both send and receive directions. Maximum is 2^60.
    initial_max_streams_bidi: u64 = 64,
    /// Initial unidirectional stream-count limit in both send and receive directions. Maximum is 2^60.
    initial_max_streams_uni: u64 = 64,
    /// Maximum active peer-issued connection IDs tracked by the connection skeleton.
    active_connection_id_limit: u64 = min_active_connection_id_limit,
    /// Maximum NEW_TOKEN values retained by client connections. A value of 0 discards tokens.
    max_stored_new_tokens: usize = default_max_stored_new_tokens,
};

/// Endpoint role. It determines the locally initiated stream IDs.
pub const ConnectionSide = enum { client, server };

/// Modeled connection lifecycle for the experimental frame-payload API.
pub const ConnectionState = enum {
    /// Normal send and receive APIs are available.
    active,
    /// A local CONNECTION_CLOSE has been queued or sent; only close transmission remains.
    closing,
    /// A peer CONNECTION_CLOSE was received; packets are discarded until the drain timer ends.
    draining,
    /// Close/drain state has expired and the connection state can be discarded.
    closed,
};

/// QUIC packet number spaces from RFC 9000 Section 12.3.
pub const PacketNumberSpace = enum {
    /// Initial packets and ACKs for Initial packets.
    initial,
    /// Handshake packets and ACKs for Handshake packets.
    handshake,
    /// 0-RTT and 1-RTT application data packets.
    application,
};

/// QUIC packet type context used for frame-payload validation.
///
/// 0-RTT and 1-RTT share the application data packet number space, but RFC 9000
/// still restricts which frame types can appear in 0-RTT packets.
pub const FramePacketType = enum {
    /// Initial long-header packet payload.
    initial,
    /// 0-RTT long-header packet payload.
    zero_rtt,
    /// Handshake long-header packet payload.
    handshake,
    /// 1-RTT short-header packet payload.
    one_rtt,
};

/// Modeled ECN codepoint used for packets recorded by the frame-payload API.
pub const EcnCodepoint = enum {
    /// Packet was not sent with an ECN-Capable Transport marking.
    not_ect,
    /// Packet was modeled as sent with ECT(0).
    ect0,
    /// Packet was modeled as sent with ECT(1).
    ect1,
};

/// Per-packet-number-space result of RFC 9000 ECN validation.
pub const EcnValidationState = enum {
    /// No ACK_ECN counter has validated this space yet.
    unknown,
    /// ACK_ECN counters have validated at least one increasing largest ACK.
    capable,
    /// ECN validation failed; future packetization should stop setting ECT.
    failed,
};

const PendingStreamFrame = struct {
    stream_id: u64,
    offset: u64,
    fin: bool,
    data: []u8,
};

const PendingCryptoFrame = struct {
    offset: u64,
    data: []u8,
};

const PendingRecvStreamFrame = struct {
    offset: u64,
    data: []u8,
};

const PendingBlockedFrame = union(enum) {
    data: frame.DataBlockedFrame,
    stream_data: frame.StreamDataBlockedFrame,
    streams_bidi: frame.StreamsBlockedBidiFrame,
    streams_uni: frame.StreamsBlockedUniFrame,
};

const PendingMaxFrame = union(enum) {
    data: frame.MaxDataFrame,
    stream_data: frame.MaxStreamDataFrame,
    streams_bidi: frame.MaxStreamsBidiFrame,
    streams_uni: frame.MaxStreamsUniFrame,
};

const PendingCloseFrame = union(enum) {
    connection: frame.ConnectionCloseFrame,
    application: frame.ApplicationCloseFrame,
};

const PendingPathChallenge = struct {
    data: [8]u8,
    transmissions: u8 = 0,
};

const OutstandingPathChallenge = struct {
    data: [8]u8,
    sent_time_millis: i64,
    transmissions: u8,
};

const SentPacket = struct {
    packet_number: u64,
    sent_time_millis: i64,
    bytes: usize,
    ecn_codepoint: EcnCodepoint = .not_ect,
};

const LossDetectionResult = struct {
    lost_bytes: usize = 0,
    pc_candidate_count: usize = 0,
    pc_first_packet_number: u64 = 0,
    pc_last_packet_number: u64 = 0,
    pc_first_sent_time_millis: i64 = 0,
    pc_last_sent_time_millis: i64 = 0,
    pc_contiguous_packet_numbers: bool = true,
    largest_lost_sent_time_millis: ?i64 = null,

    fn recordLostPacket(self: *LossDetectionResult, sent_packet: SentPacket, first_rtt_sample_sent_time_millis: ?i64) void {
        self.lost_bytes = std.math.add(usize, self.lost_bytes, sent_packet.bytes) catch std.math.maxInt(usize);
        self.largest_lost_sent_time_millis = if (self.largest_lost_sent_time_millis) |current|
            @max(current, sent_packet.sent_time_millis)
        else
            sent_packet.sent_time_millis;

        const first_rtt_sent_time = first_rtt_sample_sent_time_millis orelse return;
        if (sent_packet.sent_time_millis <= first_rtt_sent_time) return;

        if (self.pc_candidate_count == 0) {
            self.pc_first_packet_number = sent_packet.packet_number;
            self.pc_last_packet_number = sent_packet.packet_number;
            self.pc_first_sent_time_millis = sent_packet.sent_time_millis;
            self.pc_last_sent_time_millis = sent_packet.sent_time_millis;
        } else {
            if (sent_packet.packet_number != saturatingAddU64(self.pc_last_packet_number, 1)) {
                self.pc_contiguous_packet_numbers = false;
            }
            self.pc_last_packet_number = sent_packet.packet_number;
            self.pc_last_sent_time_millis = sent_packet.sent_time_millis;
        }
        self.pc_candidate_count += 1;
    }

    fn persistentCongestionEstablished(self: LossDetectionResult, recovery_state: recovery.Recovery) bool {
        if (self.pc_candidate_count < 2 or !self.pc_contiguous_packet_numbers) return false;
        return elapsedMillis(self.pc_first_sent_time_millis, self.pc_last_sent_time_millis) >=
            recovery_state.persistentCongestionDurationMs();
    }
};

const PacketNumberSpaceState = struct {
    discarded: bool = false,
    next_packet_number: u64 = 0,
    next_peer_packet_number: u64 = 0,
    pending_ack_largest: ?u64 = null,
    largest_acknowledged: ?u64 = null,
    first_rtt_sample_sent_time_millis: ?i64 = null,
    loss_deadline_millis: ?i64 = null,
    recovery_state: recovery.Recovery,
    sent_packets: std.ArrayList(SentPacket) = .empty,
    pending_ping_count: usize = 0,
    crypto_send_offset: u64 = 0,
    crypto_recv_buffer: std.ArrayList(u8) = .empty,
    crypto_read_offset: usize = 0,
    crypto_send_queue: std.ArrayList(PendingCryptoFrame) = .empty,
    ecn_sent_ect0: u64 = 0,
    ecn_sent_ect1: u64 = 0,
    ecn_largest_acknowledged: ?u64 = null,
    ecn_counts: frame.EcnCounts = zeroEcnCounts(),
    ecn_validation_state: EcnValidationState = .unknown,

    fn init(config: Config) PacketNumberSpaceState {
        return .{
            .recovery_state = recovery.Recovery.init(.{
                .max_datagram_size = config.max_datagram_size,
                .initial_rtt_ms = config.initial_rtt_ms,
            }),
        };
    }

    fn deinit(self: *PacketNumberSpaceState, allocator: std.mem.Allocator) void {
        for (self.crypto_send_queue.items) |pending| {
            allocator.free(pending.data);
        }
        self.crypto_recv_buffer.deinit(allocator);
        self.crypto_send_queue.deinit(allocator);
        self.sent_packets.deinit(allocator);
    }
};

const PacketNumberSpaceView = struct {
    discarded: *bool,
    next_packet_number: *u64,
    next_peer_packet_number: *u64,
    pending_ack_largest: *?u64,
    largest_acknowledged: *?u64,
    first_rtt_sample_sent_time_millis: *?i64,
    loss_deadline_millis: *?i64,
    recovery_state: *recovery.Recovery,
    sent_packets: *std.ArrayList(SentPacket),
    pending_ping_count: *usize,
    crypto_send_offset: *u64,
    crypto_recv_buffer: *std.ArrayList(u8),
    crypto_read_offset: *usize,
    crypto_send_queue: *std.ArrayList(PendingCryptoFrame),
    ecn_sent_ect0: *u64,
    ecn_sent_ect1: *u64,
    ecn_largest_acknowledged: *?u64,
    ecn_counts: *frame.EcnCounts,
    ecn_validation_state: *EcnValidationState,
};

const ActiveConnectionId = struct {
    sequence_number: u64,
    connection_id: []u8,
    stateless_reset_token: [16]u8,
    retired: bool = false,
};

const ActiveConnectionIdSnapshot = struct {
    retired: bool,
};

const LocalConnectionId = struct {
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: []u8,
    stateless_reset_token: [16]u8,
    sent: bool = false,
    retired: bool = false,
};

const LocalConnectionIdSnapshot = struct {
    retired: bool,
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

fn saturatingMulU64(a: u64, b: u64) u64 {
    return std.math.mul(u64, a, b) catch std.math.maxInt(u64);
}

fn saturatingAddMillis(now_millis: i64, duration_millis: u64) i64 {
    const duration_i64 = std.math.cast(i64, duration_millis) orelse return std.math.maxInt(i64);
    return std.math.add(i64, now_millis, duration_i64) catch std.math.maxInt(i64);
}

fn ptoDeadlineFor(sent_packets: []const SentPacket, recovery_state: recovery.Recovery) ?i64 {
    var latest_sent_time: ?i64 = null;
    for (sent_packets) |sent_packet| {
        latest_sent_time = if (latest_sent_time) |current|
            @max(current, sent_packet.sent_time_millis)
        else
            sent_packet.sent_time_millis;
    }
    const sent_time = latest_sent_time orelse return null;
    return saturatingAddMillis(sent_time, recovery_state.ptoMs());
}

fn zeroEcnCounts() frame.EcnCounts {
    return .{
        .ect0_count = 0,
        .ect1_count = 0,
        .ecn_ce_count = 0,
    };
}

fn saturatingAddU64(a: u64, b: u64) u64 {
    return std.math.add(u64, a, b) catch std.math.maxInt(u64);
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

fn cryptoFrameWireLen(offset: u64, data_len: usize) Error!usize {
    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(offset));
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

fn maxCryptoFrameDataLen(offset: u64, remaining: usize, max_datagram_size: usize) Error!usize {
    if (try cryptoFrameWireLen(offset, 0) > max_datagram_size) return error.BufferTooSmall;
    if (remaining == 0) return 0;

    var best: usize = 0;
    var low: usize = 1;
    var high: usize = remaining;
    while (low <= high) {
        const mid = low + (high - low) / 2;
        const encoded_len = try cryptoFrameWireLen(offset, mid);
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

fn pathChallengeFrameWireLen() usize {
    return 9; // frame type + 8-byte path validation data
}

fn pingFrameWireLen() usize {
    return 1; // frame type only
}

fn resetStreamFrameWireLen(reset: frame.ResetStreamFrame) Error!usize {
    if (reset.stream_id > max_quic_varint or reset.application_error_code > max_quic_varint or reset.final_size > max_quic_varint) {
        return error.InvalidPacket;
    }

    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(reset.stream_id));
    len = try addWireLen(len, try quicVarIntWireLen(reset.application_error_code));
    return addWireLen(len, try quicVarIntWireLen(reset.final_size));
}

fn stopSendingFrameWireLen(stop_sending: frame.StopSendingFrame) Error!usize {
    if (stop_sending.stream_id > max_quic_varint or stop_sending.application_error_code > max_quic_varint) {
        return error.InvalidPacket;
    }

    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(stop_sending.stream_id));
    return addWireLen(len, try quicVarIntWireLen(stop_sending.application_error_code));
}

fn retireConnectionIdFrameWireLen(sequence_number: u64) Error!usize {
    const len: usize = 1; // frame type
    return addWireLen(len, try quicVarIntWireLen(sequence_number));
}

fn newConnectionIdFrameWireLen(local_id: LocalConnectionId) Error!usize {
    if (local_id.connection_id.len == 0 or local_id.connection_id.len > max_connection_id_len) return error.InvalidPacket;
    if (local_id.retire_prior_to > local_id.sequence_number) return error.InvalidPacket;

    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(local_id.sequence_number));
    len = try addWireLen(len, try quicVarIntWireLen(local_id.retire_prior_to));
    len = try addWireLen(len, 1); // connection ID length
    len = try addWireLen(len, local_id.connection_id.len);
    return addWireLen(len, local_id.stateless_reset_token.len);
}

fn closeReasonLenWireLen(reason_len: usize) Error!usize {
    const value = std.math.cast(u64, reason_len) orelse return error.BufferTooSmall;
    if (value > max_quic_varint) return error.BufferTooSmall;
    return quicVarIntWireLen(value);
}

fn connectionCloseFrameWireLen(close: frame.ConnectionCloseFrame) Error!usize {
    if (close.error_code > max_quic_varint or close.frame_type > max_quic_varint) return error.InvalidPacket;

    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(close.error_code));
    len = try addWireLen(len, try quicVarIntWireLen(close.frame_type));
    len = try addWireLen(len, try closeReasonLenWireLen(close.reason_phrase.len));
    return addWireLen(len, close.reason_phrase.len);
}

fn applicationCloseFrameWireLen(close: frame.ApplicationCloseFrame) Error!usize {
    if (close.error_code > max_quic_varint) return error.InvalidPacket;

    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(close.error_code));
    len = try addWireLen(len, try closeReasonLenWireLen(close.reason_phrase.len));
    return addWireLen(len, close.reason_phrase.len);
}

fn closeFrameWireLen(close: PendingCloseFrame) Error!usize {
    return switch (close) {
        .connection => |connection| connectionCloseFrameWireLen(connection),
        .application => |application| applicationCloseFrameWireLen(application),
    };
}

fn blockedFrameWireLen(blocked: PendingBlockedFrame) Error!usize {
    var len: usize = 1; // frame type
    switch (blocked) {
        .data => |data| {
            return addWireLen(len, try quicVarIntWireLen(data.maximum_data));
        },
        .stream_data => |stream_data| {
            len = try addWireLen(len, try quicVarIntWireLen(stream_data.stream_id));
            return addWireLen(len, try quicVarIntWireLen(stream_data.maximum_stream_data));
        },
        .streams_bidi => |streams| {
            return addWireLen(len, try quicVarIntWireLen(streams.maximum_streams));
        },
        .streams_uni => |streams| {
            return addWireLen(len, try quicVarIntWireLen(streams.maximum_streams));
        },
    }
}

fn maxFrameWireLen(max_frame: PendingMaxFrame) Error!usize {
    var len: usize = 1; // frame type
    switch (max_frame) {
        .data => |data| {
            return addWireLen(len, try quicVarIntWireLen(data.maximum_data));
        },
        .stream_data => |stream_data| {
            len = try addWireLen(len, try quicVarIntWireLen(stream_data.stream_id));
            return addWireLen(len, try quicVarIntWireLen(stream_data.maximum_stream_data));
        },
        .streams_bidi => |streams| {
            return addWireLen(len, try quicVarIntWireLen(streams.maximum_streams));
        },
        .streams_uni => |streams| {
            return addWireLen(len, try quicVarIntWireLen(streams.maximum_streams));
        },
    }
}

fn deinitPendingCloseFrame(close: *PendingCloseFrame, allocator: std.mem.Allocator) void {
    switch (close.*) {
        .connection => |connection| allocator.free(connection.reason_phrase),
        .application => |application| allocator.free(application.reason_phrase),
    }
}

fn streamEndOffset(offset: u64, data_len: usize) ?u64 {
    const len = std.math.cast(u64, data_len) orelse return null;
    const end = std.math.add(u64, offset, len) catch return null;
    if (end > max_quic_varint) return null;
    return end;
}

fn streamRangesOverlap(a_offset: u64, a_len: usize, b_offset: u64, b_len: usize) bool {
    const a_end = streamEndOffset(a_offset, a_len) orelse return true;
    const b_end = streamEndOffset(b_offset, b_len) orelse return true;
    return a_offset < b_end and b_offset < a_end;
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

fn frameAllowedInPacketNumberSpace(decoded: frame.Frame, space: PacketNumberSpace) bool {
    return frameAllowedInFramePacketType(decoded, defaultFramePacketTypeForSpace(space));
}

fn defaultFramePacketTypeForSpace(space: PacketNumberSpace) FramePacketType {
    return switch (space) {
        .initial => .initial,
        .handshake => .handshake,
        .application => .one_rtt,
    };
}

fn packetNumberSpaceForFramePacketType(packet_type: FramePacketType) PacketNumberSpace {
    return switch (packet_type) {
        .initial => .initial,
        .handshake => .handshake,
        .zero_rtt, .one_rtt => .application,
    };
}

fn frameAllowedInFramePacketType(decoded: frame.Frame, packet_type: FramePacketType) bool {
    return switch (packet_type) {
        .initial, .handshake => switch (decoded) {
            .padding, .ping, .ack, .ack_ecn, .crypto, .connection_close => true,
            else => false,
        },
        .zero_rtt => switch (decoded) {
            .padding,
            .ping,
            .reset_stream,
            .stop_sending,
            .stream,
            .max_data,
            .max_stream_data,
            .max_streams_bidi,
            .max_streams_uni,
            .data_blocked,
            .stream_data_blocked,
            .streams_blocked_bidi,
            .streams_blocked_uni,
            .new_connection_id,
            .path_challenge,
            .connection_close,
            .application_close,
            => true,
            else => false,
        },
        .one_rtt => true,
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
    max_data: u64,
    data: std.ArrayList(u8) = .empty,
    pending: std.ArrayList(PendingRecvStreamFrame) = .empty,
    read_offset: usize = 0,
    final_size: ?u64 = null,
    reset_error_code: ?u64 = null,
    stop_sending_sent: bool = false,
    stream_count_credit_released: bool = false,

    fn deinit(self: *RecvStreamState, allocator: std.mem.Allocator) void {
        for (self.pending.items) |pending| {
            allocator.free(pending.data);
        }
        self.pending.deinit(allocator);
        self.data.deinit(allocator);
    }
};

const RecvStreamSnapshot = struct {
    max_data: u64,
    data_len: usize,
    pending_count: usize,
    read_offset: usize,
    final_size: ?u64,
    reset_error_code: ?u64,
    stop_sending_sent: bool,
    stream_count_credit_released: bool,
};

const PeerStreamDataBlockedState = struct {
    stream_id: u64,
    maximum_stream_data: u64,
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
    peer_address_validated: bool,
    peer_address_bytes_received: usize,
    peer_address_bytes_sent: usize,
    peer_max_idle_timeout_ms: u64,
    peer_disable_active_migration: bool,
    peer_stateless_reset_token: ?[packet.stateless_reset_token_len]u8,
    last_packet_activity_millis: ?i64,
    next_stream_id: u64,
    next_uni_stream_id: u64,
    initial_packet_space: PacketNumberSpaceState,
    handshake_packet_space: PacketNumberSpaceState,
    next_packet_number: u64,
    application_packet_space_discarded: bool,
    next_peer_packet_number: u64,
    pending_ack_largest: ?u64,
    pending_path_responses: std.ArrayList([8]u8),
    pending_path_challenges: std.ArrayList(PendingPathChallenge),
    outstanding_path_challenges: std.ArrayList(OutstandingPathChallenge),
    failed_path_validations: usize,
    active_connection_ids: std.ArrayList(ActiveConnectionId),
    local_connection_ids: std.ArrayList(LocalConnectionId),
    next_local_connection_id_sequence: u64,
    peer_active_connection_id_limit: u64,
    pending_retire_connection_ids: std.ArrayList(u64),
    stored_new_tokens: std.ArrayList([]u8),
    retry_tokens: std.ArrayList([]u8),
    pending_blocked_frames: std.ArrayList(PendingBlockedFrame),
    pending_max_frames: std.ArrayList(PendingMaxFrame),
    pending_ping_count: usize,
    peer_max_udp_payload_size: usize,
    peer_max_data: u64,
    peer_initial_max_stream_data_bidi_local: u64,
    peer_initial_max_stream_data_bidi_remote: u64,
    peer_initial_max_stream_data_uni: u64,
    peer_max_streams_bidi: u64,
    peer_max_streams_uni: u64,
    peer_ack_delay_exponent: u64,
    opened_bidi_streams: u64,
    opened_uni_streams: u64,
    sent_stream_data_bytes: u64,
    recv_max_data: u64,
    recv_max_stream_data: u64,
    recv_max_streams_bidi: u64,
    recv_max_streams_uni: u64,
    recv_data_bytes: u64,
    peer_data_blocked_limit: ?u64,
    peer_stream_data_blocked_limits: std.ArrayList(PeerStreamDataBlockedState),
    peer_streams_blocked_bidi_limit: ?u64,
    peer_streams_blocked_uni_limit: ?u64,
    recovery_state: recovery.Recovery,
    sent_packets: std.ArrayList(SentPacket),
    largest_acknowledged: ?u64,
    first_rtt_sample_sent_time_millis: ?i64,
    loss_deadline_millis: ?i64,
    ecn_sent_ect0: u64,
    ecn_sent_ect1: u64,
    ecn_largest_acknowledged: ?u64,
    ecn_counts: frame.EcnCounts,
    ecn_validation_state: EcnValidationState,
    crypto_send_offset: u64,
    crypto_recv_buffer: std.ArrayList(u8),
    crypto_read_offset: usize,
    crypto_send_queue: std.ArrayList(PendingCryptoFrame),
    send_queue: std.ArrayList(PendingStreamFrame),
    pending_reset_streams: std.ArrayList(frame.ResetStreamFrame),
    pending_stop_sending: std.ArrayList(frame.StopSendingFrame),
    send_streams: std.ArrayList(SendStreamState),
    recv_streams: std.ArrayList(RecvStreamState),
    handshake_confirmed: bool,
    pending_close: ?PendingCloseFrame,
    state: ConnectionState,
    close_deadline_millis: ?i64,
    closed: bool,

    /// Create a connection with empty send and receive state.
    pub fn init(
        allocator: std.mem.Allocator,
        side: ConnectionSide,
        config: Config,
    ) !QuicConnection {
        if (config.initial_max_streams_bidi > max_stream_count or config.initial_max_streams_uni > max_stream_count) {
            return error.InvalidStream;
        }
        if (config.active_connection_id_limit < min_active_connection_id_limit) {
            return error.InvalidPacket;
        }

        return QuicConnection{
            .allocator = allocator,
            .config = config,
            .side = side,
            .peer_address_validated = side == .client,
            .peer_address_bytes_received = 0,
            .peer_address_bytes_sent = 0,
            .peer_max_idle_timeout_ms = 0,
            .peer_disable_active_migration = false,
            .peer_stateless_reset_token = null,
            .last_packet_activity_millis = null,
            .next_stream_id = switch (side) {
                .client => 0,
                .server => 1,
            },
            .next_uni_stream_id = switch (side) {
                .client => 2,
                .server => 3,
            },
            .initial_packet_space = PacketNumberSpaceState.init(config),
            .handshake_packet_space = PacketNumberSpaceState.init(config),
            .next_packet_number = 0,
            .application_packet_space_discarded = false,
            .next_peer_packet_number = 0,
            .pending_ack_largest = null,
            .pending_path_responses = .empty,
            .pending_path_challenges = .empty,
            .outstanding_path_challenges = .empty,
            .failed_path_validations = 0,
            .active_connection_ids = .empty,
            .local_connection_ids = .empty,
            .next_local_connection_id_sequence = 0,
            .peer_active_connection_id_limit = min_active_connection_id_limit,
            .pending_retire_connection_ids = .empty,
            .stored_new_tokens = .empty,
            .retry_tokens = .empty,
            .pending_blocked_frames = .empty,
            .pending_max_frames = .empty,
            .pending_ping_count = 0,
            .peer_max_udp_payload_size = config.max_datagram_size,
            .peer_max_data = config.initial_max_data,
            .peer_initial_max_stream_data_bidi_local = config.initial_max_stream_data,
            .peer_initial_max_stream_data_bidi_remote = config.initial_max_stream_data,
            .peer_initial_max_stream_data_uni = config.initial_max_stream_data,
            .peer_max_streams_bidi = config.initial_max_streams_bidi,
            .peer_max_streams_uni = config.initial_max_streams_uni,
            .peer_ack_delay_exponent = 3,
            .opened_bidi_streams = 0,
            .opened_uni_streams = 0,
            .sent_stream_data_bytes = 0,
            .recv_max_data = config.initial_max_data,
            .recv_max_stream_data = config.initial_max_stream_data,
            .recv_max_streams_bidi = config.initial_max_streams_bidi,
            .recv_max_streams_uni = config.initial_max_streams_uni,
            .recv_data_bytes = 0,
            .peer_data_blocked_limit = null,
            .peer_stream_data_blocked_limits = .empty,
            .peer_streams_blocked_bidi_limit = null,
            .peer_streams_blocked_uni_limit = null,
            .recovery_state = recovery.Recovery.init(.{
                .max_datagram_size = config.max_datagram_size,
                .initial_rtt_ms = config.initial_rtt_ms,
            }),
            .sent_packets = .empty,
            .largest_acknowledged = null,
            .first_rtt_sample_sent_time_millis = null,
            .loss_deadline_millis = null,
            .ecn_sent_ect0 = 0,
            .ecn_sent_ect1 = 0,
            .ecn_largest_acknowledged = null,
            .ecn_counts = zeroEcnCounts(),
            .ecn_validation_state = .unknown,
            .crypto_send_offset = 0,
            .crypto_recv_buffer = .empty,
            .crypto_read_offset = 0,
            .crypto_send_queue = .empty,
            .send_queue = .empty,
            .pending_reset_streams = .empty,
            .pending_stop_sending = .empty,
            .send_streams = .empty,
            .recv_streams = .empty,
            .handshake_confirmed = false,
            .pending_close = null,
            .state = .active,
            .close_deadline_millis = null,
            .closed = false,
        };
    }

    /// Release all buffers owned by this connection.
    pub fn deinit(self: *QuicConnection) void {
        self.initial_packet_space.deinit(self.allocator);
        self.handshake_packet_space.deinit(self.allocator);
        for (self.crypto_send_queue.items) |pending| {
            self.allocator.free(pending.data);
        }
        for (self.send_queue.items) |pending| {
            self.allocator.free(pending.data);
        }
        self.sent_packets.deinit(self.allocator);
        self.pending_path_responses.deinit(self.allocator);
        self.pending_path_challenges.deinit(self.allocator);
        self.outstanding_path_challenges.deinit(self.allocator);
        for (self.active_connection_ids.items) |active_id| {
            self.allocator.free(active_id.connection_id);
        }
        self.active_connection_ids.deinit(self.allocator);
        for (self.local_connection_ids.items) |local_id| {
            self.allocator.free(local_id.connection_id);
        }
        self.local_connection_ids.deinit(self.allocator);
        self.pending_retire_connection_ids.deinit(self.allocator);
        for (self.stored_new_tokens.items) |token| {
            self.allocator.free(token);
        }
        self.stored_new_tokens.deinit(self.allocator);
        for (self.retry_tokens.items) |token| {
            self.allocator.free(token);
        }
        self.retry_tokens.deinit(self.allocator);
        self.pending_blocked_frames.deinit(self.allocator);
        self.pending_max_frames.deinit(self.allocator);
        self.peer_stream_data_blocked_limits.deinit(self.allocator);
        self.crypto_recv_buffer.deinit(self.allocator);
        self.crypto_send_queue.deinit(self.allocator);
        self.send_queue.deinit(self.allocator);
        self.pending_reset_streams.deinit(self.allocator);
        self.pending_stop_sending.deinit(self.allocator);
        self.send_streams.deinit(self.allocator);
        for (self.recv_streams.items) |*stream| {
            stream.deinit(self.allocator);
        }
        self.clearPendingCloseFrame();
        self.recv_streams.deinit(self.allocator);
    }

    /// Return the current modeled connection lifecycle state.
    pub fn connectionState(self: QuicConnection) ConnectionState {
        return self.state;
    }

    /// Return the close/drain deadline in milliseconds, or null when no timer is active.
    pub fn closeDeadlineMillis(self: QuicConnection) ?i64 {
        return self.close_deadline_millis;
    }

    /// Return the effective max idle timeout in milliseconds, or null when disabled.
    ///
    /// RFC 9000 uses the shorter non-zero timeout advertised by either endpoint.
    /// A zero value from one side means that side has no preference; both zero
    /// disables idle timeout handling in this frame-payload model.
    pub fn effectiveIdleTimeoutMillis(self: QuicConnection) ?u64 {
        const local = self.config.max_idle_timeout_ms;
        const peer = self.peer_max_idle_timeout_ms;
        if (local == 0 and peer == 0) return null;
        if (local == 0) return peer;
        if (peer == 0) return local;
        return @min(local, peer);
    }

    /// Return the current idle timeout deadline, or null when the timer is inactive.
    pub fn idleTimeoutDeadlineMillis(self: QuicConnection) ?i64 {
        const idle_timeout = self.effectiveIdleTimeoutMillis() orelse return null;
        const last_activity = self.last_packet_activity_millis orelse return null;
        return saturatingAddMillis(last_activity, idle_timeout);
    }

    /// Return whether the peer disabled active connection migration.
    ///
    /// Endpoint routing does not exist yet, so this currently records the peer
    /// transport parameter for later migration-policy enforcement.
    pub fn peerActiveMigrationDisabled(self: QuicConnection) bool {
        return self.peer_disable_active_migration;
    }

    /// Return the peer stateless reset token from transport parameters, if any.
    ///
    /// RFC 9000 permits this as a server transport parameter. The existing
    /// `detectStatelessReset()` API still reports NEW_CONNECTION_ID sequence
    /// numbers only; this getter lets a future packet endpoint bind the
    /// handshake CID token without changing that API's return meaning.
    pub fn peerStatelessResetToken(self: QuicConnection) ?[packet.stateless_reset_token_len]u8 {
        return self.peer_stateless_reset_token;
    }

    /// Return whether the peer address is considered validated for send limits.
    ///
    /// Clients are initialized as validated because RFC 9000 anti-amplification
    /// limits apply to servers before they validate the client's address.
    pub fn peerAddressValidated(self: QuicConnection) bool {
        return self.peer_address_validated;
    }

    /// Record received datagram bytes for the modeled server anti-amplification budget.
    ///
    /// This explicit hook is used until UDP packet I/O exists. It increases the
    /// amount an unvalidated server address may send to three times the recorded
    /// received bytes. Validated peers and clients do not need this budget.
    pub fn recordPeerAddressBytesReceived(self: *QuicConnection, bytes: usize) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (!self.isAntiAmplificationLimited()) return;
        self.peer_address_bytes_received = std.math.add(usize, self.peer_address_bytes_received, bytes) catch std.math.maxInt(usize);
    }

    /// Mark the peer address as validated and lift the modeled anti-amplification limit.
    ///
    /// Future TLS, Retry-token, or path-validation integrations can call this
    /// after proving that the peer receives packets at its claimed address.
    pub fn validatePeerAddress(self: *QuicConnection) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        self.peer_address_validated = true;
    }

    /// Return remaining server anti-amplification bytes, or null when unrestricted.
    pub fn antiAmplificationLimitRemaining(self: QuicConnection) ?usize {
        if (!self.isAntiAmplificationLimited()) return null;
        const limit = std.math.mul(usize, self.peer_address_bytes_received, anti_amplification_multiplier) catch std.math.maxInt(usize);
        if (self.peer_address_bytes_sent >= limit) return 0;
        return limit - self.peer_address_bytes_sent;
    }

    /// Return the next packet number for a packet number space.
    pub fn nextPacketNumber(self: QuicConnection, space: PacketNumberSpace) u64 {
        return switch (space) {
            .initial => self.initial_packet_space.next_packet_number,
            .handshake => self.handshake_packet_space.next_packet_number,
            .application => self.next_packet_number,
        };
    }

    /// Return the next peer packet number modeled for receive-side ACK generation.
    pub fn nextPeerPacketNumber(self: QuicConnection, space: PacketNumberSpace) u64 {
        return switch (space) {
            .initial => self.initial_packet_space.next_peer_packet_number,
            .handshake => self.handshake_packet_space.next_peer_packet_number,
            .application => self.next_peer_packet_number,
        };
    }

    /// Return the largest packet number awaiting ACK emission in a packet number space.
    pub fn pendingAckLargest(self: QuicConnection, space: PacketNumberSpace) ?u64 {
        return switch (space) {
            .initial => self.initial_packet_space.pending_ack_largest,
            .handshake => self.handshake_packet_space.pending_ack_largest,
            .application => self.pending_ack_largest,
        };
    }

    /// Return whether a packet number space has been discarded.
    pub fn packetNumberSpaceDiscarded(self: QuicConnection, space: PacketNumberSpace) bool {
        return switch (space) {
            .initial => self.initial_packet_space.discarded,
            .handshake => self.handshake_packet_space.discarded,
            .application => self.application_packet_space_discarded,
        };
    }

    /// Return the count of sent packets tracked for ACK-driven recovery in one space.
    pub fn sentPacketCount(self: QuicConnection, space: PacketNumberSpace) usize {
        return switch (space) {
            .initial => self.initial_packet_space.sent_packets.items.len,
            .handshake => self.handshake_packet_space.sent_packets.items.len,
            .application => self.sent_packets.items.len,
        };
    }

    /// Return bytes in flight for one packet number space.
    pub fn bytesInFlight(self: QuicConnection, space: PacketNumberSpace) usize {
        return switch (space) {
            .initial => self.initial_packet_space.recovery_state.bytes_in_flight,
            .handshake => self.handshake_packet_space.recovery_state.bytes_in_flight,
            .application => self.recovery_state.bytes_in_flight,
        };
    }

    /// Return the congestion window for one packet number space's recovery state.
    pub fn congestionWindow(self: QuicConnection, space: PacketNumberSpace) usize {
        return switch (space) {
            .initial => self.initial_packet_space.recovery_state.congestion_window,
            .handshake => self.handshake_packet_space.recovery_state.congestion_window,
            .application => self.recovery_state.congestion_window,
        };
    }

    /// Return the current smoothed RTT estimate for one packet number space.
    pub fn smoothedRttMillis(self: QuicConnection, space: PacketNumberSpace) u64 {
        return switch (space) {
            .initial => self.initial_packet_space.recovery_state.smoothed_rtt_ms,
            .handshake => self.handshake_packet_space.recovery_state.smoothed_rtt_ms,
            .application => self.recovery_state.smoothed_rtt_ms,
        };
    }

    /// Return the current time-threshold loss deadline for one packet number space.
    pub fn lossDetectionDeadlineMillis(self: QuicConnection, space: PacketNumberSpace) ?i64 {
        return switch (space) {
            .initial => self.initial_packet_space.loss_deadline_millis,
            .handshake => self.handshake_packet_space.loss_deadline_millis,
            .application => self.loss_deadline_millis,
        };
    }

    /// Return the modeled PTO deadline for one packet number space.
    ///
    /// This uses the latest ack-eliciting packet tracked in the selected space
    /// and the current simplified PTO duration. ACK-only payloads are not
    /// tracked in `sent_packets`, so they do not arm PTO.
    pub fn ptoDeadlineMillis(self: QuicConnection, space: PacketNumberSpace) ?i64 {
        return switch (space) {
            .initial => ptoDeadlineFor(self.initial_packet_space.sent_packets.items, self.initial_packet_space.recovery_state),
            .handshake => ptoDeadlineFor(self.handshake_packet_space.sent_packets.items, self.handshake_packet_space.recovery_state),
            .application => ptoDeadlineFor(self.sent_packets.items, self.recovery_state),
        };
    }

    /// Return the current ECN validation state for one packet number space.
    pub fn ecnValidationState(self: QuicConnection, space: PacketNumberSpace) EcnValidationState {
        return switch (space) {
            .initial => self.initial_packet_space.ecn_validation_state,
            .handshake => self.handshake_packet_space.ecn_validation_state,
            .application => self.ecn_validation_state,
        };
    }

    /// Return the latest validated ACK_ECN counters for one packet number space.
    pub fn ecnCounts(self: QuicConnection, space: PacketNumberSpace) frame.EcnCounts {
        return switch (space) {
            .initial => self.initial_packet_space.ecn_counts,
            .handshake => self.handshake_packet_space.ecn_counts,
            .application => self.ecn_counts,
        };
    }

    /// Return queued PATH_CHALLENGE frames that have not been transmitted yet.
    pub fn pendingPathChallengeCount(self: QuicConnection) usize {
        return self.pending_path_challenges.items.len;
    }

    /// Return transmitted PATH_CHALLENGE frames awaiting a matching PATH_RESPONSE.
    pub fn outstandingPathChallengeCount(self: QuicConnection) usize {
        return self.outstanding_path_challenges.items.len;
    }

    /// Return PATH_CHALLENGE validations that exhausted the retry budget.
    pub fn failedPathValidationCount(self: QuicConnection) usize {
        return self.failed_path_validations;
    }

    /// Return whether the modeled QUIC handshake is confirmed.
    pub fn handshakeConfirmed(self: QuicConnection) bool {
        return self.handshake_confirmed;
    }

    /// Return the peer-issued CID sequence whose stateless reset token matches.
    ///
    /// This is a read-only detector for future UDP packet handling. The
    /// frame-payload API does not automatically close the connection because it
    /// does not yet receive protected packets.
    pub fn detectStatelessReset(self: QuicConnection, datagram: []const u8) ?u64 {
        for (self.active_connection_ids.items) |active_id| {
            if (active_id.retired) continue;
            if (packet.matchesStatelessReset(datagram, active_id.stateless_reset_token)) {
                return active_id.sequence_number;
            }
        }
        return null;
    }

    /// Return Retry tokens issued by this server and still accepted once.
    pub fn pendingRetryTokenCount(self: QuicConnection) usize {
        return self.retry_tokens.items.len;
    }

    /// Register an opaque Retry token that a server will accept once.
    ///
    /// The token bytes are copied into connection-owned memory. This is a
    /// deterministic model for tests and examples until endpoint-level token
    /// encryption, expiration, and address binding exist.
    pub fn issueRetryToken(self: *QuicConnection, token: []const u8) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.side != .server or token.len == 0) return error.InvalidPacket;
        for (self.retry_tokens.items) |existing| {
            if (std.mem.eql(u8, existing, token)) return error.InvalidPacket;
        }

        const owned_token = self.allocator.alloc(u8, token.len) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned_token);
        @memcpy(owned_token, token);
        self.retry_tokens.append(self.allocator, owned_token) catch return error.OutOfMemory;
    }

    /// Consume a matching Retry token and mark the peer address validated.
    ///
    /// The current frame-payload model treats Retry token validation as an
    /// explicit server-only address-validation hook. A valid token is consumed
    /// exactly once and lifts the server anti-amplification limit.
    pub fn validateRetryToken(self: *QuicConnection, token: []const u8) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.side != .server or token.len == 0) return error.InvalidPacket;

        for (self.retry_tokens.items, 0..) |existing, i| {
            if (!std.mem.eql(u8, existing, token)) continue;
            const removed = self.retry_tokens.orderedRemove(i);
            self.allocator.free(removed);
            self.peer_address_validated = true;
            return;
        }

        return error.InvalidPacket;
    }

    /// Return locally issued connection IDs that the peer has not retired.
    pub fn localConnectionIdCount(self: QuicConnection) u64 {
        var count: u64 = 0;
        for (self.local_connection_ids.items) |local_id| {
            if (!local_id.retired) count += 1;
        }
        return count;
    }

    /// Return locally issued NEW_CONNECTION_ID frames still waiting to be sent.
    pub fn pendingNewConnectionIdCount(self: QuicConnection) usize {
        var count: usize = 0;
        for (self.local_connection_ids.items) |local_id| {
            if (!local_id.sent and !local_id.retired) count += 1;
        }
        return count;
    }

    /// Queue a locally issued connection ID for transmission in NEW_CONNECTION_ID.
    ///
    /// The connection ID is copied and owned by the connection. `retire_prior_to`
    /// is encoded into the outgoing frame but local retirement is only recorded
    /// after the peer sends RETIRE_CONNECTION_ID.
    pub fn issueConnectionId(
        self: *QuicConnection,
        connection_id: []const u8,
        stateless_reset_token: [16]u8,
        retire_prior_to: u64,
    ) Error!u64 {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (connection_id.len == 0 or connection_id.len > max_connection_id_len) return error.InvalidPacket;
        if (self.next_local_connection_id_sequence > max_quic_varint) return error.Internal;
        if (retire_prior_to > self.next_local_connection_id_sequence) return error.InvalidPacket;
        if (self.localConnectionIdCount() >= self.peer_active_connection_id_limit) return error.InvalidPacket;
        if (self.localConnectionIdValueExists(connection_id)) return error.InvalidPacket;

        const sequence_number = self.next_local_connection_id_sequence;
        const owned_connection_id = self.allocator.alloc(u8, connection_id.len) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned_connection_id);
        @memcpy(owned_connection_id, connection_id);

        self.local_connection_ids.append(self.allocator, .{
            .sequence_number = sequence_number,
            .retire_prior_to = retire_prior_to,
            .connection_id = owned_connection_id,
            .stateless_reset_token = stateless_reset_token,
        }) catch return error.OutOfMemory;
        self.next_local_connection_id_sequence = std.math.add(u64, sequence_number, 1) catch return error.Internal;
        return sequence_number;
    }

    /// Move timed-out PATH_CHALLENGE probes back to the send queue or mark them failed.
    ///
    /// Timeout uses the current simplified PTO. Endpoint path identity is not
    /// modeled until the UDP routing layer exists, so this only retries the
    /// frame-payload validation data already tracked by the connection.
    pub fn checkPathValidationTimeouts(self: *QuicConnection, now_millis: i64) Error!void {
        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        try self.expirePathChallenges(now_millis);
    }

    /// Apply due time-threshold loss detection in all packet number spaces.
    ///
    /// This deterministic timer hook is part of the frame-payload recovery
    /// skeleton. It does not send PTO probes yet; it only removes packets whose
    /// RFC 9002 time-threshold loss deadline has expired.
    pub fn checkLossDetectionTimeouts(self: *QuicConnection, now_millis: i64) Error!void {
        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        self.expireLossDetectionTimeouts(now_millis);
    }

    /// Queue PTO PING probes when simplified PTO deadlines expire.
    ///
    /// This is a deterministic hook for the current frame-payload model. It
    /// queues one PING in every non-discarded packet number space whose PTO is
    /// due. It does not yet retransmit data frames; if no packet is in flight,
    /// it is a no-op.
    pub fn checkPtoTimeouts(self: *QuicConnection, now_millis: i64) Error!void {
        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        self.expireLossDetectionTimeouts(now_millis);
        try self.checkPtoTimeoutInSpace(.initial, now_millis);
        try self.checkPtoTimeoutInSpace(.handshake, now_millis);
        try self.checkPtoTimeoutInSpace(.application, now_millis);
    }

    /// Apply the modeled QUIC idle timeout under a controlled clock.
    pub fn checkIdleTimeouts(self: *QuicConnection, now_millis: i64) Error!void {
        self.expireIdleState(now_millis);
        if (self.state == .closed) return error.ConnectionClosed;
    }

    /// Mark the modeled handshake as confirmed.
    ///
    /// TLS integration is not wired yet, so this explicit hook lets tests and
    /// future TLS adapters enable post-handshake recovery behavior such as the
    /// RFC 9002 peer `max_ack_delay` cap.
    pub fn confirmHandshake(self: *QuicConnection) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        self.handshake_confirmed = true;
    }

    /// Discard Initial or Handshake packet-number-space recovery state.
    ///
    /// This models the QUIC key-discard side effect before packet protection is
    /// implemented. Application data shares the 0-RTT/1-RTT packet number space
    /// and is never discarded through this API.
    pub fn discardPacketNumberSpace(self: *QuicConnection, space: PacketNumberSpace) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (space == .application) return error.InvalidPacket;

        var packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return;

        packet_space.discarded.* = true;
        packet_space.pending_ack_largest.* = null;
        packet_space.largest_acknowledged.* = null;
        packet_space.first_rtt_sample_sent_time_millis.* = null;
        packet_space.loss_deadline_millis.* = null;
        packet_space.sent_packets.items.len = 0;
        packet_space.pending_ping_count.* = 0;
        self.rollbackCryptoSendQueue(packet_space.crypto_send_queue, 0);
        packet_space.crypto_send_offset.* = 0;
        packet_space.crypto_recv_buffer.items.len = 0;
        packet_space.crypto_read_offset.* = 0;
        packet_space.recovery_state.bytes_in_flight = 0;
        packet_space.recovery_state.pto_count = 0;
    }

    /// Record a modeled ack-eliciting packet in the selected packet number space.
    ///
    /// This low-level helper backs tests and future packetization work until
    /// protected packets are produced by the connection itself.
    pub fn recordPacketSentInSpace(
        self: *QuicConnection,
        space: PacketNumberSpace,
        now_millis: i64,
        bytes: usize,
    ) Error!u64 {
        return self.recordPacketSentInSpaceWithEcn(space, now_millis, bytes, .not_ect);
    }

    /// Record a modeled ECT-marked packet in the selected packet number space.
    ///
    /// This helper exists for deterministic ECN validation tests and future
    /// packetization. Real IP-header ECN marking is outside the frame-payload
    /// API, so callers must only use `ect0` or `ect1` when they have modeled
    /// that send-side marking explicitly.
    pub fn recordEcnPacketSentInSpace(
        self: *QuicConnection,
        space: PacketNumberSpace,
        now_millis: i64,
        bytes: usize,
        codepoint: EcnCodepoint,
    ) Error!u64 {
        if (codepoint == .not_ect) return error.InvalidPacket;
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.ecn_validation_state.* == .failed) return error.InvalidPacket;
        return self.recordPacketSentInSpaceWithEcn(space, now_millis, bytes, codepoint);
    }

    fn recordPacketSentInSpaceWithEcn(
        self: *QuicConnection,
        space: PacketNumberSpace,
        now_millis: i64,
        bytes: usize,
        codepoint: EcnCodepoint,
    ) Error!u64 {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        var packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;
        if (packet_space.next_packet_number.* > max_quic_varint) return error.Internal;
        if (!packet_space.recovery_state.canSend(bytes)) return error.FlowControlBlocked;
        if (!self.canSendToPeerAddress(bytes)) return error.FlowControlBlocked;

        const packet_number = packet_space.next_packet_number.*;
        packet_space.sent_packets.append(self.allocator, .{
            .packet_number = packet_number,
            .sent_time_millis = now_millis,
            .bytes = bytes,
            .ecn_codepoint = codepoint,
        }) catch return error.OutOfMemory;
        errdefer _ = packet_space.sent_packets.orderedRemove(packet_space.sent_packets.items.len - 1);

        packet_space.next_packet_number.* = std.math.add(u64, packet_number, 1) catch return error.Internal;
        switch (codepoint) {
            .not_ect => {},
            .ect0 => packet_space.ecn_sent_ect0.* += 1,
            .ect1 => packet_space.ecn_sent_ect1.* += 1,
        }
        packet_space.recovery_state.onPacketSent(bytes);
        self.recordPeerAddressBytesSent(bytes);
        self.recordPacketActivity(now_millis);
        return packet_number;
    }

    /// Process one ACK frame in the selected packet number space.
    pub fn receiveAckInSpace(
        self: *QuicConnection,
        space: PacketNumberSpace,
        now_millis: i64,
        ack: frame.AckFrame,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        try self.receiveAckFrame(space, now_millis, ack, null);
    }

    /// Process one ACK_ECN frame in the selected packet number space.
    pub fn receiveAckEcnInSpace(
        self: *QuicConnection,
        space: PacketNumberSpace,
        now_millis: i64,
        ack_ecn: frame.AckEcnFrame,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        try self.receiveAckFrame(space, now_millis, ack_ecn.ack, ack_ecn.ecn_counts);
    }

    /// Queue an ACK for the next received packet number in the selected space.
    pub fn queueAckForReceivedPacketInSpace(self: *QuicConnection, space: PacketNumberSpace) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        try self.queueAckForReceivedPacket(space);
    }

    /// Queue one ack-eliciting PING in a selected packet number space.
    pub fn sendPingInSpace(self: *QuicConnection, space: PacketNumberSpace) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        try self.queuePingInSpace(space);
    }

    /// Build the local RFC 9000 transport parameters advertised during handshake.
    ///
    /// The current skeleton maps idle timeout, receive limits, ACK timing,
    /// local datagram sizing, active migration policy, and optional server
    /// stateless reset token into typed parameters. Connection ID values and
    /// server-only Retry/original-destination fields are left for the future
    /// packet layer.
    pub fn localTransportParameters(self: QuicConnection) transport_parameters.TransportParameters {
        var params = transport_parameters.TransportParameters{
            .max_idle_timeout = self.config.max_idle_timeout_ms,
            .initial_max_data = self.recv_max_data,
            .initial_max_stream_data_bidi_local = self.recv_max_stream_data,
            .initial_max_stream_data_bidi_remote = self.recv_max_stream_data,
            .initial_max_stream_data_uni = self.recv_max_stream_data,
            .initial_max_streams_bidi = self.recv_max_streams_bidi,
            .initial_max_streams_uni = self.recv_max_streams_uni,
            .max_ack_delay = self.recovery_state.max_ack_delay_ms,
            .disable_active_migration = self.config.disable_active_migration,
            .active_connection_id_limit = self.config.active_connection_id_limit,
        };
        if (self.side == .server) {
            params.stateless_reset_token = self.config.stateless_reset_token;
        }
        if (self.config.max_datagram_size >= 1200) {
            params.max_udp_payload_size = self.config.max_datagram_size;
        }
        return params;
    }

    /// Apply peer RFC 9000 transport parameters after handshake parsing.
    ///
    /// This updates the send-side flow-control, stream-count, ACK timing, idle
    /// timeout, connection ID, and datagram-size limits used by the in-memory
    /// connection model. It should be called before application writes for the
    /// connection; later MAX_* frames can still increase limits.
    pub fn applyPeerTransportParameters(
        self: *QuicConnection,
        params: transport_parameters.TransportParameters,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        try self.validatePeerTransportParameters(params);

        self.peer_max_udp_payload_size = std.math.cast(usize, params.max_udp_payload_size) orelse std.math.maxInt(usize);
        self.peer_max_data = params.initial_max_data;
        self.peer_initial_max_stream_data_bidi_local = params.initial_max_stream_data_bidi_local;
        self.peer_initial_max_stream_data_bidi_remote = params.initial_max_stream_data_bidi_remote;
        self.peer_initial_max_stream_data_uni = params.initial_max_stream_data_uni;
        self.peer_max_streams_bidi = params.initial_max_streams_bidi;
        self.peer_max_streams_uni = params.initial_max_streams_uni;
        self.peer_ack_delay_exponent = params.ack_delay_exponent;
        self.peer_max_idle_timeout_ms = params.max_idle_timeout;
        self.peer_disable_active_migration = params.disable_active_migration;
        self.peer_stateless_reset_token = params.stateless_reset_token;
        self.peer_active_connection_id_limit = params.active_connection_id_limit;
        self.recovery_state.max_ack_delay_ms = params.max_ack_delay;

        for (self.send_streams.items) |*stream| {
            stream.max_data = self.initialPeerStreamDataLimit(stream.stream_id);
        }
    }

    fn validateConnectionIdParameter(cid: ?[]const u8) Error!void {
        if (cid) |value| {
            if (value.len > max_connection_id_len) return error.InvalidPacket;
        }
    }

    fn validatePeerTransportParameters(
        self: QuicConnection,
        params: transport_parameters.TransportParameters,
    ) Error!void {
        if (self.side == .server) {
            if (params.original_destination_connection_id != null or
                params.stateless_reset_token != null or
                params.preferred_address != null or
                params.retry_source_connection_id != null)
            {
                return error.InvalidPacket;
            }
        }

        if (params.max_udp_payload_size < 1200) return error.InvalidPacket;
        if (params.initial_max_streams_bidi > max_stream_count or params.initial_max_streams_uni > max_stream_count) {
            return error.InvalidPacket;
        }
        if (params.ack_delay_exponent > 20) return error.InvalidPacket;
        if (params.max_ack_delay >= (@as(u64, 1) << 14)) return error.InvalidPacket;
        if (params.active_connection_id_limit < min_active_connection_id_limit) return error.InvalidPacket;
        try validateConnectionIdParameter(params.original_destination_connection_id);
        try validateConnectionIdParameter(params.initial_source_connection_id);
        try validateConnectionIdParameter(params.retry_source_connection_id);
        if (params.preferred_address) |preferred| {
            if (preferred.connection_id.len == 0 or preferred.connection_id.len > max_connection_id_len) {
                return error.InvalidPacket;
            }
        }
    }

    fn closeStateTimeoutMillis(self: QuicConnection) u64 {
        return saturatingMulU64(close_state_pto_multiplier, self.recovery_state.ptoMs());
    }

    fn closeStateDeadlineMillis(self: QuicConnection, now_millis: i64) i64 {
        return saturatingAddMillis(now_millis, self.closeStateTimeoutMillis());
    }

    fn clearPendingCloseFrame(self: *QuicConnection) void {
        if (self.pending_close) |*pending_close| {
            deinitPendingCloseFrame(pending_close, self.allocator);
            self.pending_close = null;
        }
    }

    fn enterClosingState(self: *QuicConnection, now_millis: i64) void {
        self.state = .closing;
        self.close_deadline_millis = self.closeStateDeadlineMillis(now_millis);
        self.closed = true;
    }

    fn enterDrainingState(self: *QuicConnection, now_millis: i64) void {
        self.state = .draining;
        self.close_deadline_millis = self.closeStateDeadlineMillis(now_millis);
        self.closed = true;
    }

    fn expireCloseState(self: *QuicConnection, now_millis: i64) void {
        if (self.state != .closing and self.state != .draining) return;
        const deadline = self.close_deadline_millis orelse return;
        if (now_millis < deadline) return;

        self.state = .closed;
        self.close_deadline_millis = null;
        self.closed = true;
        self.clearPendingCloseFrame();
    }

    fn expireIdleState(self: *QuicConnection, now_millis: i64) void {
        if (self.state != .active) return;
        if (self.pending_close != null) return;
        const deadline = self.idleTimeoutDeadlineMillis() orelse return;
        if (now_millis < deadline) return;

        self.state = .closed;
        self.close_deadline_millis = null;
        self.closed = true;
        self.clearPendingCloseFrame();
    }

    fn recordPacketActivity(self: *QuicConnection, now_millis: i64) void {
        if (self.effectiveIdleTimeoutMillis() == null) return;
        self.last_packet_activity_millis = now_millis;
    }

    fn isClosingOrClosed(self: QuicConnection) bool {
        return self.state != .active or self.pending_close != null or self.closed;
    }

    fn maxTxDatagramSize(self: QuicConnection) usize {
        return @min(@as(usize, self.config.max_datagram_size), self.peer_max_udp_payload_size);
    }

    fn isAntiAmplificationLimited(self: QuicConnection) bool {
        return self.side == .server and !self.peer_address_validated;
    }

    fn canSendToPeerAddress(self: QuicConnection, bytes: usize) bool {
        const remaining = self.antiAmplificationLimitRemaining() orelse return true;
        return bytes <= remaining;
    }

    fn recordPeerAddressBytesSent(self: *QuicConnection, bytes: usize) void {
        if (!self.isAntiAmplificationLimited()) return;
        self.peer_address_bytes_sent = std.math.add(usize, self.peer_address_bytes_sent, bytes) catch std.math.maxInt(usize);
    }

    fn initialPeerStreamDataLimit(self: QuicConnection, stream_id: u64) u64 {
        if (!isBidirectionalStream(stream_id)) return self.peer_initial_max_stream_data_uni;
        if (isLocalStreamInitiator(self.side, stream_id)) return self.peer_initial_max_stream_data_bidi_remote;
        return self.peer_initial_max_stream_data_bidi_local;
    }

    fn scaledPeerAckDelay(self: QuicConnection, ack_delay: u64) u64 {
        const multiplier = std.math.shl(u64, 1, self.peer_ack_delay_exponent);
        return saturatingMulU64(ack_delay, multiplier);
    }

    fn ackDelayForRtt(self: QuicConnection, space: PacketNumberSpace, ack_delay: u64) u64 {
        if (space == .initial) return 0;
        const scaled_ack_delay = self.scaledPeerAckDelay(ack_delay);
        if (!self.handshake_confirmed) return scaled_ack_delay;
        return @min(scaled_ack_delay, self.recovery_state.max_ack_delay_ms);
    }

    fn packetNumberSpace(self: *QuicConnection, space: PacketNumberSpace) PacketNumberSpaceView {
        return switch (space) {
            .initial => .{
                .discarded = &self.initial_packet_space.discarded,
                .next_packet_number = &self.initial_packet_space.next_packet_number,
                .next_peer_packet_number = &self.initial_packet_space.next_peer_packet_number,
                .pending_ack_largest = &self.initial_packet_space.pending_ack_largest,
                .largest_acknowledged = &self.initial_packet_space.largest_acknowledged,
                .first_rtt_sample_sent_time_millis = &self.initial_packet_space.first_rtt_sample_sent_time_millis,
                .loss_deadline_millis = &self.initial_packet_space.loss_deadline_millis,
                .recovery_state = &self.initial_packet_space.recovery_state,
                .sent_packets = &self.initial_packet_space.sent_packets,
                .pending_ping_count = &self.initial_packet_space.pending_ping_count,
                .crypto_send_offset = &self.initial_packet_space.crypto_send_offset,
                .crypto_recv_buffer = &self.initial_packet_space.crypto_recv_buffer,
                .crypto_read_offset = &self.initial_packet_space.crypto_read_offset,
                .crypto_send_queue = &self.initial_packet_space.crypto_send_queue,
                .ecn_sent_ect0 = &self.initial_packet_space.ecn_sent_ect0,
                .ecn_sent_ect1 = &self.initial_packet_space.ecn_sent_ect1,
                .ecn_largest_acknowledged = &self.initial_packet_space.ecn_largest_acknowledged,
                .ecn_counts = &self.initial_packet_space.ecn_counts,
                .ecn_validation_state = &self.initial_packet_space.ecn_validation_state,
            },
            .handshake => .{
                .discarded = &self.handshake_packet_space.discarded,
                .next_packet_number = &self.handshake_packet_space.next_packet_number,
                .next_peer_packet_number = &self.handshake_packet_space.next_peer_packet_number,
                .pending_ack_largest = &self.handshake_packet_space.pending_ack_largest,
                .largest_acknowledged = &self.handshake_packet_space.largest_acknowledged,
                .first_rtt_sample_sent_time_millis = &self.handshake_packet_space.first_rtt_sample_sent_time_millis,
                .loss_deadline_millis = &self.handshake_packet_space.loss_deadline_millis,
                .recovery_state = &self.handshake_packet_space.recovery_state,
                .sent_packets = &self.handshake_packet_space.sent_packets,
                .pending_ping_count = &self.handshake_packet_space.pending_ping_count,
                .crypto_send_offset = &self.handshake_packet_space.crypto_send_offset,
                .crypto_recv_buffer = &self.handshake_packet_space.crypto_recv_buffer,
                .crypto_read_offset = &self.handshake_packet_space.crypto_read_offset,
                .crypto_send_queue = &self.handshake_packet_space.crypto_send_queue,
                .ecn_sent_ect0 = &self.handshake_packet_space.ecn_sent_ect0,
                .ecn_sent_ect1 = &self.handshake_packet_space.ecn_sent_ect1,
                .ecn_largest_acknowledged = &self.handshake_packet_space.ecn_largest_acknowledged,
                .ecn_counts = &self.handshake_packet_space.ecn_counts,
                .ecn_validation_state = &self.handshake_packet_space.ecn_validation_state,
            },
            .application => .{
                .discarded = &self.application_packet_space_discarded,
                .next_packet_number = &self.next_packet_number,
                .next_peer_packet_number = &self.next_peer_packet_number,
                .pending_ack_largest = &self.pending_ack_largest,
                .largest_acknowledged = &self.largest_acknowledged,
                .first_rtt_sample_sent_time_millis = &self.first_rtt_sample_sent_time_millis,
                .loss_deadline_millis = &self.loss_deadline_millis,
                .recovery_state = &self.recovery_state,
                .sent_packets = &self.sent_packets,
                .pending_ping_count = &self.pending_ping_count,
                .crypto_send_offset = &self.crypto_send_offset,
                .crypto_recv_buffer = &self.crypto_recv_buffer,
                .crypto_read_offset = &self.crypto_read_offset,
                .crypto_send_queue = &self.crypto_send_queue,
                .ecn_sent_ect0 = &self.ecn_sent_ect0,
                .ecn_sent_ect1 = &self.ecn_sent_ect1,
                .ecn_largest_acknowledged = &self.ecn_largest_acknowledged,
                .ecn_counts = &self.ecn_counts,
                .ecn_validation_state = &self.ecn_validation_state,
            },
        };
    }

    /// Process one unencrypted packet payload containing one or more QUIC frames.
    pub fn processDatagram(
        self: *QuicConnection,
        now_millis: i64,
        datagram: []const u8,
    ) Error!void {
        try self.processDatagramInSpace(.application, now_millis, datagram);
    }

    /// Process one frame-payload datagram in a selected packet number space.
    ///
    /// This keeps ACK generation and ACK processing isolated between Initial,
    /// Handshake, and Application spaces while the repository still lacks
    /// protected QUIC packetization.
    pub fn processDatagramInSpace(
        self: *QuicConnection,
        space: PacketNumberSpace,
        now_millis: i64,
        datagram: []const u8,
    ) Error!void {
        try self.processDatagramInSpaceWithPacketType(
            space,
            defaultFramePacketTypeForSpace(space),
            now_millis,
            datagram,
        );
    }

    /// Remove Initial packet protection and process the decrypted frame payload.
    ///
    /// This is the first protected-packet bridge for the connection skeleton. It
    /// accepts exactly one QUIC v1 Initial long packet, decrypts it with caller
    /// supplied Initial keys, requires the packet number to match the next
    /// expected Initial packet number, then routes the plaintext through the
    /// existing Initial packet number space frame handler. Coalesced packets,
    /// Retry, Handshake, 0-RTT, and 1-RTT protection remain endpoint work.
    pub fn processInitialProtectedDatagram(
        self: *QuicConnection,
        now_millis: i64,
        keys: protection.Aes128PacketProtectionKeys,
        datagram: []const u8,
    ) Error!void {
        const expected_packet_number = self.nextPeerPacketNumber(.initial);
        var decoded = protection.unprotectLongPacketAes128(
            self.allocator,
            keys,
            datagram,
            expected_packet_number,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidPacket,
        };
        defer protection.deinitProtectedLongPacket(&decoded, self.allocator);

        if (decoded.len != datagram.len) return error.InvalidPacket;
        if (decoded.packet.header.version != .v1 or decoded.packet.header.packet_type != .initial) {
            return error.InvalidPacket;
        }
        if (decoded.packet.header.packet_number != expected_packet_number) return error.InvalidPacket;

        try self.processDatagramInSpaceWithPacketType(
            .initial,
            .initial,
            now_millis,
            decoded.packet.plaintext,
        );
    }

    /// Return the next protected Initial CRYPTO datagram, or null if idle.
    ///
    /// The returned datagram is allocated with the connection allocator and must
    /// be freed by the caller. This bridges the Initial CRYPTO send queue to the
    /// RFC 9001 long-packet protection helper while preserving packet-number,
    /// sent-packet, recovery, anti-amplification, and idle-timeout accounting.
    /// ACK-only, PING-only, coalesced packets, Retry, Handshake, 0-RTT, and
    /// 1-RTT protected transmit remain endpoint work.
    pub fn pollInitialProtectedDatagram(
        self: *QuicConnection,
        now_millis: i64,
        dcid: []const u8,
        scid: []const u8,
        token: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
    ) Error!?[]u8 {
        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;

        var packet_space = self.packetNumberSpace(.initial);
        if (packet_space.discarded.*) return error.InvalidPacket;
        if (packet_space.crypto_send_queue.items.len == 0) return null;
        if (packet_space.next_packet_number.* > max_quic_varint) return error.Internal;

        const pending = packet_space.crypto_send_queue.items[0];
        const crypto_encoded_len = try cryptoFrameWireLen(pending.offset, pending.data.len);
        const packet_number = packet_space.next_packet_number.*;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            packet_space.largest_acknowledged.*,
        ) catch return error.Internal;

        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const plaintext_len = @max(crypto_encoded_len, min_payload_len);
        if (plaintext_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        frame.encodeFrame(plaintext_out.writer(), .{ .crypto = .{
            .offset = pending.offset,
            .data = pending.data,
        } }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const datagram = protection.protectLongPacketAes128(self.allocator, .{
            .version = .v1,
            .dcid = dcid,
            .scid = scid,
            .packet_type = .initial,
            .token = token,
            .packet_number = packet_number,
            .payload_length = 0,
        }, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        if (datagram.len > self.maxTxDatagramSize()) {
            self.allocator.free(datagram);
            return error.BufferTooSmall;
        }
        if (!packet_space.recovery_state.canSend(datagram.len) or !self.canSendToPeerAddress(datagram.len)) {
            self.allocator.free(datagram);
            return null;
        }

        packet_space.sent_packets.append(self.allocator, .{
            .packet_number = packet_number,
            .sent_time_millis = now_millis,
            .bytes = datagram.len,
        }) catch return error.OutOfMemory;
        errdefer _ = packet_space.sent_packets.orderedRemove(packet_space.sent_packets.items.len - 1);

        const removed = packet_space.crypto_send_queue.orderedRemove(0);
        self.allocator.free(removed.data);
        packet_space.next_packet_number.* = std.math.add(u64, packet_number, 1) catch return error.Internal;
        packet_space.recovery_state.onPacketSent(datagram.len);
        self.recordPeerAddressBytesSent(datagram.len);
        self.recordPacketActivity(now_millis);
        return datagram;
    }

    /// Process one frame-payload datagram using RFC 9000 packet-type frame rules.
    ///
    /// 0-RTT and 1-RTT both use the Application packet number space, but 0-RTT
    /// rejects frames that are only valid after the handshake has progressed.
    pub fn processDatagramForPacketType(
        self: *QuicConnection,
        packet_type: FramePacketType,
        now_millis: i64,
        datagram: []const u8,
    ) Error!void {
        try self.processDatagramInSpaceWithPacketType(
            packetNumberSpaceForFramePacketType(packet_type),
            packet_type,
            now_millis,
            datagram,
        );
    }

    fn processDatagramInSpaceWithPacketType(
        self: *QuicConnection,
        space: PacketNumberSpace,
        packet_type: FramePacketType,
        now_millis: i64,
        datagram: []const u8,
    ) Error!void {
        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (datagram.len == 0 or datagram.len > self.config.max_datagram_size) return error.InvalidPacket;

        var packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;
        const recovery_snapshot = packet_space.recovery_state.*;
        const sent_packet_count = packet_space.sent_packets.items.len;
        const sent_packet_snapshots = self.allocator.alloc(SentPacket, sent_packet_count) catch return error.OutOfMemory;
        defer self.allocator.free(sent_packet_snapshots);
        @memcpy(sent_packet_snapshots, packet_space.sent_packets.items);
        const largest_acknowledged_snapshot = packet_space.largest_acknowledged.*;
        const first_rtt_sample_sent_time_snapshot = packet_space.first_rtt_sample_sent_time_millis.*;
        const loss_deadline_millis_snapshot = packet_space.loss_deadline_millis.*;
        const ecn_sent_ect0_snapshot = packet_space.ecn_sent_ect0.*;
        const ecn_sent_ect1_snapshot = packet_space.ecn_sent_ect1.*;
        const ecn_largest_acknowledged_snapshot = packet_space.ecn_largest_acknowledged.*;
        const ecn_counts_snapshot = packet_space.ecn_counts.*;
        const ecn_validation_state_snapshot = packet_space.ecn_validation_state.*;

        const next_peer_packet_number_snapshot = packet_space.next_peer_packet_number.*;
        const pending_ack_largest_snapshot = packet_space.pending_ack_largest.*;
        const pending_path_response_count = self.pending_path_responses.items.len;
        const outstanding_path_challenge_count = self.outstanding_path_challenges.items.len;
        const outstanding_path_challenge_snapshots = self.allocator.alloc(OutstandingPathChallenge, outstanding_path_challenge_count) catch return error.OutOfMemory;
        defer self.allocator.free(outstanding_path_challenge_snapshots);
        @memcpy(outstanding_path_challenge_snapshots, self.outstanding_path_challenges.items);
        const active_connection_id_count = self.active_connection_ids.items.len;
        const active_connection_id_snapshots = self.allocator.alloc(ActiveConnectionIdSnapshot, active_connection_id_count) catch return error.OutOfMemory;
        defer self.allocator.free(active_connection_id_snapshots);
        for (self.active_connection_ids.items, active_connection_id_snapshots) |active_id, *snapshot| {
            snapshot.* = .{ .retired = active_id.retired };
        }
        const local_connection_id_count = self.local_connection_ids.items.len;
        const local_connection_id_snapshots = self.allocator.alloc(LocalConnectionIdSnapshot, local_connection_id_count) catch return error.OutOfMemory;
        defer self.allocator.free(local_connection_id_snapshots);
        for (self.local_connection_ids.items, local_connection_id_snapshots) |local_id, *snapshot| {
            snapshot.* = .{ .retired = local_id.retired };
        }
        const pending_retire_connection_id_count = self.pending_retire_connection_ids.items.len;
        const stored_new_token_count = self.stored_new_tokens.items.len;
        const pending_reset_stream_count = self.pending_reset_streams.items.len;
        const pending_max_frame_count = self.pending_max_frames.items.len;
        const peer_max_data_snapshot = self.peer_max_data;
        const peer_max_udp_payload_size_snapshot = self.peer_max_udp_payload_size;
        const peer_initial_max_stream_data_bidi_local_snapshot = self.peer_initial_max_stream_data_bidi_local;
        const peer_initial_max_stream_data_bidi_remote_snapshot = self.peer_initial_max_stream_data_bidi_remote;
        const peer_initial_max_stream_data_uni_snapshot = self.peer_initial_max_stream_data_uni;
        const peer_max_streams_bidi_snapshot = self.peer_max_streams_bidi;
        const peer_max_streams_uni_snapshot = self.peer_max_streams_uni;
        const peer_ack_delay_exponent_snapshot = self.peer_ack_delay_exponent;
        const peer_data_blocked_limit_snapshot = self.peer_data_blocked_limit;
        const peer_streams_blocked_bidi_limit_snapshot = self.peer_streams_blocked_bidi_limit;
        const peer_streams_blocked_uni_limit_snapshot = self.peer_streams_blocked_uni_limit;
        const peer_stream_data_blocked_count = self.peer_stream_data_blocked_limits.items.len;
        const peer_stream_data_blocked_snapshots = self.allocator.alloc(PeerStreamDataBlockedState, peer_stream_data_blocked_count) catch return error.OutOfMemory;
        defer self.allocator.free(peer_stream_data_blocked_snapshots);
        @memcpy(peer_stream_data_blocked_snapshots, self.peer_stream_data_blocked_limits.items);
        const handshake_confirmed_snapshot = self.handshake_confirmed;
        const closed_snapshot = self.closed;
        const state_snapshot = self.state;
        const close_deadline_millis_snapshot = self.close_deadline_millis;
        const crypto_recv_buffer_len_snapshot = packet_space.crypto_recv_buffer.items.len;
        const crypto_read_offset_snapshot = packet_space.crypto_read_offset.*;
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
                .max_data = stream.max_data,
                .data_len = stream.data.items.len,
                .pending_count = stream.pending.items.len,
                .read_offset = stream.read_offset,
                .final_size = stream.final_size,
                .reset_error_code = stream.reset_error_code,
                .stop_sending_sent = stream.stop_sending_sent,
                .stream_count_credit_released = stream.stream_count_credit_released,
            };
        }
        errdefer {
            self.rollbackRecvStreams(recv_stream_count, recv_snapshots);
            self.recv_data_bytes = recv_data_bytes_snapshot;
            self.rollbackSendStreams(send_stream_count, send_stream_snapshots);
            self.peer_max_streams_uni = peer_max_streams_uni_snapshot;
            self.peer_max_streams_bidi = peer_max_streams_bidi_snapshot;
            self.peer_max_data = peer_max_data_snapshot;
            self.peer_max_udp_payload_size = peer_max_udp_payload_size_snapshot;
            self.peer_initial_max_stream_data_bidi_local = peer_initial_max_stream_data_bidi_local_snapshot;
            self.peer_initial_max_stream_data_bidi_remote = peer_initial_max_stream_data_bidi_remote_snapshot;
            self.peer_initial_max_stream_data_uni = peer_initial_max_stream_data_uni_snapshot;
            self.peer_ack_delay_exponent = peer_ack_delay_exponent_snapshot;
            self.peer_data_blocked_limit = peer_data_blocked_limit_snapshot;
            self.peer_streams_blocked_bidi_limit = peer_streams_blocked_bidi_limit_snapshot;
            self.peer_streams_blocked_uni_limit = peer_streams_blocked_uni_limit_snapshot;
            self.rollbackPeerStreamDataBlockedLimits(peer_stream_data_blocked_count, peer_stream_data_blocked_snapshots);
            self.handshake_confirmed = handshake_confirmed_snapshot;
            packet_space = self.packetNumberSpace(space);
            packet_space.next_peer_packet_number.* = next_peer_packet_number_snapshot;
            packet_space.pending_ack_largest.* = pending_ack_largest_snapshot;
            self.pending_path_responses.items.len = pending_path_response_count;
            self.outstanding_path_challenges.items.len = outstanding_path_challenge_count;
            @memcpy(self.outstanding_path_challenges.items[0..outstanding_path_challenge_count], outstanding_path_challenge_snapshots);
            self.rollbackActiveConnectionIds(active_connection_id_count, active_connection_id_snapshots);
            self.rollbackLocalConnectionIds(local_connection_id_count, local_connection_id_snapshots);
            self.pending_retire_connection_ids.items.len = pending_retire_connection_id_count;
            self.rollbackStoredNewTokens(stored_new_token_count);
            self.pending_reset_streams.items.len = pending_reset_stream_count;
            self.pending_max_frames.items.len = pending_max_frame_count;
            self.closed = closed_snapshot;
            self.state = state_snapshot;
            self.close_deadline_millis = close_deadline_millis_snapshot;
            packet_space.crypto_recv_buffer.items.len = crypto_recv_buffer_len_snapshot;
            packet_space.crypto_read_offset.* = crypto_read_offset_snapshot;
            self.rollbackSentPackets(packet_space.sent_packets, sent_packet_count, sent_packet_snapshots);
            packet_space.largest_acknowledged.* = largest_acknowledged_snapshot;
            packet_space.first_rtt_sample_sent_time_millis.* = first_rtt_sample_sent_time_snapshot;
            packet_space.loss_deadline_millis.* = loss_deadline_millis_snapshot;
            packet_space.ecn_sent_ect0.* = ecn_sent_ect0_snapshot;
            packet_space.ecn_sent_ect1.* = ecn_sent_ect1_snapshot;
            packet_space.ecn_largest_acknowledged.* = ecn_largest_acknowledged_snapshot;
            packet_space.ecn_counts.* = ecn_counts_snapshot;
            packet_space.ecn_validation_state.* = ecn_validation_state_snapshot;
            packet_space.recovery_state.* = recovery_snapshot;
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
            if (!frameAllowedInFramePacketType(decoded.frame, packet_type)) return error.InvalidPacket;

            if (frameIsAckEliciting(decoded.frame)) {
                ack_eliciting = true;
            }

            switch (decoded.frame) {
                .ack => |ack| try self.receiveAckFrame(space, now_millis, ack, null),
                .ack_ecn => |ack_ecn| try self.receiveAckFrame(space, now_millis, ack_ecn.ack, ack_ecn.ecn_counts),
                .max_data => |max_data| self.receiveMaxDataFrame(max_data),
                .max_stream_data => |max_stream_data| try self.receiveMaxStreamDataFrame(max_stream_data),
                .max_streams_bidi => |max_streams| self.receiveMaxStreamsBidiFrame(max_streams),
                .max_streams_uni => |max_streams| self.receiveMaxStreamsUniFrame(max_streams),
                .data_blocked => |data_blocked| try self.receiveDataBlockedFrame(data_blocked),
                .stream_data_blocked => |stream_data_blocked| try self.receiveStreamDataBlockedFrame(stream_data_blocked),
                .streams_blocked_bidi => |streams_blocked| try self.receiveStreamsBlockedBidiFrame(streams_blocked),
                .streams_blocked_uni => |streams_blocked| try self.receiveStreamsBlockedUniFrame(streams_blocked),
                .path_challenge => |path_challenge| try self.receivePathChallengeFrame(path_challenge),
                .path_response => |path_response| try self.receivePathResponseFrame(path_response),
                .stop_sending => |stop_sending| try self.receiveStopSendingFrame(stop_sending),
                .reset_stream => |reset_stream| try self.receiveResetStreamFrame(reset_stream),
                .crypto => |crypto| try self.receiveCryptoFrame(space, crypto),
                .stream => |stream_frame| try self.receiveStreamFrame(stream_frame),
                .new_connection_id => |new_connection_id| try self.receiveNewConnectionIdFrame(new_connection_id),
                .retire_connection_id => |retire_connection_id| try self.receiveRetireConnectionIdFrame(retire_connection_id),
                .new_token => |new_token| try self.receiveNewTokenFrame(new_token),
                .handshake_done => try self.receiveHandshakeDoneFrame(),
                .connection_close, .application_close => self.enterDrainingState(now_millis),
                else => {},
            }

            offset += decoded.len;
        }

        if (ack_eliciting and !self.closed) {
            try self.queueAckForReceivedPacket(space);
        }
        try self.drainPendingRecvStreams();
        self.recordPacketActivity(now_millis);
    }

    /// Return the next frame-payload datagram for a selected packet number space.
    ///
    /// Initial and Handshake spaces currently emit ACK-only, PING, or CRYPTO payloads.
    /// Application space delegates to `pollTx()` and can emit the broader
    /// frame-payload skeleton used by the examples.
    pub fn pollTxInSpace(
        self: *QuicConnection,
        space: PacketNumberSpace,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        if (space == .application) return self.pollTx(now_millis, out_buf);

        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;

        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;

        const ack_to_send = self.pendingAckFrame(space);
        if (packet_space.crypto_send_queue.items.len != 0) {
            return try self.pollCryptoFrame(space, ack_to_send, now_millis, out_buf);
        }
        if (packet_space.pending_ping_count.* != 0) {
            return try self.pollPingFrameInSpace(space, ack_to_send, now_millis, out_buf);
        }
        if (ack_to_send) |ack| {
            return try self.pollAckOnlyInSpace(space, ack, now_millis, out_buf);
        }
        return null;
    }

    /// Return the next unencrypted packet payload to send, or null if idle.
    pub fn pollTx(
        self: *QuicConnection,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
        if (self.pending_close != null) return try self.pollCloseFrame(now_millis, out_buf);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        try self.expirePathChallenges(now_millis);

        const ack_to_send = self.pendingAckFrame(.application);
        if (self.pending_path_responses.items.len != 0) {
            return try self.pollPathResponse(ack_to_send, now_millis, out_buf);
        }
        if (self.pending_reset_streams.items.len != 0) {
            return try self.pollResetStream(ack_to_send, now_millis, out_buf);
        }
        if (self.pending_stop_sending.items.len != 0) {
            return try self.pollStopSending(ack_to_send, now_millis, out_buf);
        }
        if (self.pending_retire_connection_ids.items.len != 0) {
            return try self.pollRetireConnectionId(ack_to_send, now_millis, out_buf);
        }
        if (self.pendingNewConnectionIdCount() != 0) {
            return try self.pollNewConnectionId(ack_to_send, now_millis, out_buf);
        }
        if (self.pending_path_challenges.items.len != 0) {
            return try self.pollPathChallenge(ack_to_send, now_millis, out_buf);
        }
        self.dropObsoleteMaxFrames();
        if (self.pending_max_frames.items.len != 0) {
            return try self.pollMaxFrame(ack_to_send, now_millis, out_buf);
        }
        self.dropObsoleteBlockedFrames();
        if (self.pending_blocked_frames.items.len != 0) {
            return try self.pollBlockedFrame(ack_to_send, now_millis, out_buf);
        }
        if (self.crypto_send_queue.items.len != 0) {
            return try self.pollCryptoFrame(.application, ack_to_send, now_millis, out_buf);
        }
        if (self.pending_ping_count != 0) {
            return try self.pollPingFrame(ack_to_send, now_millis, out_buf);
        }

        self.dropResetClosedStreamFrames();

        if (self.send_queue.items.len == 0) {
            if (ack_to_send) |ack| {
                return try self.pollAckOnly(ack, now_millis, out_buf);
            }
            return null;
        }

        const pending = self.send_queue.items[0];
        const stream_encoded_len = try streamFrameWireLen(pending.stream_id, pending.offset, pending.data.len);
        const max_tx_datagram_size = self.maxTxDatagramSize();
        if (stream_encoded_len > max_tx_datagram_size) return error.BufferTooSmall;

        var encoded_len = stream_encoded_len;
        var include_ack = false;
        if (ack_to_send) |ack| {
            const ack_encoded_len = try ackFrameWireLen(ack);
            const coalesced_len = try addWireLen(ack_encoded_len, stream_encoded_len);
            if (coalesced_len <= max_tx_datagram_size and out_buf.len >= coalesced_len and
                self.recovery_state.canSend(coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_millis, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.recovery_state.canSend(encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
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
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_millis);
        return written;
    }

    /// Queue a transport CONNECTION_CLOSE frame for the next `pollTx()` call.
    ///
    /// The reason phrase is copied into connection-owned memory. While queued,
    /// regular public send/receive APIs return `ConnectionClosed`; `pollTx()`
    /// remains available to emit the close frame and then mark the connection closed.
    pub fn closeConnection(
        self: *QuicConnection,
        error_code: u64,
        frame_type: u64,
        reason_phrase: []const u8,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;

        const close = frame.ConnectionCloseFrame{
            .error_code = error_code,
            .frame_type = frame_type,
            .reason_phrase = reason_phrase,
        };
        const encoded_len = try connectionCloseFrameWireLen(close);
        if (encoded_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const owned_reason = self.allocator.alloc(u8, reason_phrase.len) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned_reason);
        @memcpy(owned_reason, reason_phrase);

        self.pending_close = .{ .connection = .{
            .error_code = error_code,
            .frame_type = frame_type,
            .reason_phrase = owned_reason,
        } };
        self.state = .closing;
        self.close_deadline_millis = null;
    }

    /// Queue an application CONNECTION_CLOSE frame for the next `pollTx()` call.
    ///
    /// The reason phrase is copied into connection-owned memory. This closes the
    /// same public API surface as transport close; only the emitted frame type
    /// and error-code namespace differ.
    pub fn closeApplication(
        self: *QuicConnection,
        error_code: u64,
        reason_phrase: []const u8,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;

        const close = frame.ApplicationCloseFrame{
            .error_code = error_code,
            .reason_phrase = reason_phrase,
        };
        const encoded_len = try applicationCloseFrameWireLen(close);
        if (encoded_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const owned_reason = self.allocator.alloc(u8, reason_phrase.len) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned_reason);
        @memcpy(owned_reason, reason_phrase);

        self.pending_close = .{ .application = .{
            .error_code = error_code,
            .reason_phrase = owned_reason,
        } };
        self.state = .closing;
        self.close_deadline_millis = null;
    }

    /// Open a locally initiated bidirectional stream and return its QUIC stream ID.
    pub fn openStream(self: *QuicConnection) Error!u64 {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;

        const stream_id = self.next_stream_id;
        if (stream_id > max_quic_varint) return error.InvalidStream;

        const next_stream_id = std.math.add(u64, stream_id, 4) catch return error.Internal;
        if (self.opened_bidi_streams >= self.peer_max_streams_bidi) {
            try self.queueStreamsBlockedBidiFrame(self.peer_max_streams_bidi);
            return error.FlowControlBlocked;
        }

        self.send_streams.append(self.allocator, .{
            .stream_id = stream_id,
            .max_data = self.initialPeerStreamDataLimit(stream_id),
        }) catch return error.OutOfMemory;
        self.next_stream_id = next_stream_id;
        self.opened_bidi_streams = std.math.add(u64, self.opened_bidi_streams, 1) catch return error.Internal;
        return stream_id;
    }

    /// Open a locally initiated unidirectional stream and return its QUIC stream ID.
    pub fn openUniStream(self: *QuicConnection) Error!u64 {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;

        const stream_id = self.next_uni_stream_id;
        if (stream_id > max_quic_varint) return error.InvalidStream;

        const next_stream_id = std.math.add(u64, stream_id, 4) catch return error.Internal;
        if (self.opened_uni_streams >= self.peer_max_streams_uni) {
            try self.queueStreamsBlockedUniFrame(self.peer_max_streams_uni);
            return error.FlowControlBlocked;
        }

        self.send_streams.append(self.allocator, .{
            .stream_id = stream_id,
            .max_data = self.initialPeerStreamDataLimit(stream_id),
        }) catch return error.OutOfMemory;
        self.next_uni_stream_id = next_stream_id;
        self.opened_uni_streams = std.math.add(u64, self.opened_uni_streams, 1) catch return error.Internal;
        return stream_id;
    }

    /// Queue CRYPTO data for transmission on the default Application-space byte stream.
    ///
    /// The data is copied, split to fit `max_datagram_size`, and emitted as
    /// CRYPTO frames by `pollTx`. Empty inputs are ignored because CRYPTO has no
    /// FIN signal and carries only byte-stream progress in this skeleton.
    pub fn sendCrypto(self: *QuicConnection, data: []const u8) Error!void {
        try self.sendCryptoInSpace(.application, data);
    }

    /// Queue CRYPTO data in a selected packet number space.
    ///
    /// QUIC uses separate CRYPTO byte streams for each encryption level. This
    /// frame-payload hook lets tests and future TLS adapters exercise that
    /// separation before protected packet handling exists.
    pub fn sendCryptoInSpace(
        self: *QuicConnection,
        space: PacketNumberSpace,
        data: []const u8,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (data.len == 0) return;

        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;

        const offset = packet_space.crypto_send_offset.*;
        const next_offset = streamEndOffset(offset, data.len) orelse return error.CryptoError;
        const max_tx_datagram_size = self.maxTxDatagramSize();
        _ = try maxCryptoFrameDataLen(offset, data.len, max_tx_datagram_size);

        const queue_snapshot = packet_space.crypto_send_queue.items.len;
        errdefer self.rollbackCryptoSendQueue(packet_space.crypto_send_queue, queue_snapshot);

        var consumed: usize = 0;
        var frame_offset = offset;
        while (consumed < data.len) {
            const chunk_len = try maxCryptoFrameDataLen(
                frame_offset,
                data.len - consumed,
                max_tx_datagram_size,
            );
            const next_consumed = consumed + chunk_len;
            try self.queueCryptoFrame(packet_space.crypto_send_queue, frame_offset, data[consumed..next_consumed]);
            frame_offset = streamEndOffset(frame_offset, chunk_len) orelse return error.Internal;
            consumed = next_consumed;
        }

        packet_space.crypto_send_offset.* = next_offset;
    }

    /// Queue data for a stream. The data is copied and emitted by `pollTx`.
    pub fn sendOnStream(
        self: *QuicConnection,
        stream_id: u64,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
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
        const stream_max_data = if (existing_state) |state| state.max_data else self.initialPeerStreamDataLimit(stream_id);
        if (next_offset > stream_max_data) {
            try self.queueStreamDataBlockedFrame(stream_id, stream_max_data);
            return error.FlowControlBlocked;
        }

        const next_sent_total = streamEndOffset(self.sent_stream_data_bytes, data.len) orelse return error.InvalidStream;
        if (next_sent_total > self.peer_max_data) {
            try self.queueDataBlockedFrame(self.peer_max_data);
            return error.FlowControlBlocked;
        }

        const max_tx_datagram_size = self.maxTxDatagramSize();
        _ = try maxStreamFrameDataLen(stream_id, offset, data.len, max_tx_datagram_size);

        var appended_send_state = false;
        errdefer if (appended_send_state) {
            _ = self.send_streams.orderedRemove(self.send_streams.items.len - 1);
        };

        const state = existing_state orelse blk: {
            self.send_streams.append(self.allocator, .{
                .stream_id = stream_id,
                .max_data = self.initialPeerStreamDataLimit(stream_id),
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
                    max_tx_datagram_size,
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

    /// Abort the send side of an opened stream and queue a RESET_STREAM frame.
    ///
    /// The current send offset becomes the RESET_STREAM final size. This API is
    /// valid for streams where this endpoint has a send side: opened local
    /// bidirectional/unidirectional streams and observed peer bidirectional
    /// streams. Peer-initiated unidirectional streams are receive-only here.
    pub fn resetStream(
        self: *QuicConnection,
        stream_id: u64,
        application_error_code: u64,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (stream_id > max_quic_varint) return error.InvalidStream;
        if (application_error_code > max_quic_varint) return error.InvalidPacket;
        if (!isBidirectionalStream(stream_id) and !isLocalUnidirectionalStream(self.side, stream_id)) {
            return error.InvalidStream;
        }

        if (self.findSendStream(stream_id)) |stream_state| {
            try self.queueResetStream(stream_state, application_error_code);
            return;
        }

        if (isLocalBidirectionalStream(self.side, stream_id) or isLocalUnidirectionalStream(self.side, stream_id)) {
            return error.InvalidStream;
        }
        if (self.findRecvStream(stream_id) == null) return error.InvalidStream;

        var appended_send_state = false;
        errdefer if (appended_send_state) {
            _ = self.send_streams.orderedRemove(self.send_streams.items.len - 1);
        };

        self.send_streams.append(self.allocator, .{
            .stream_id = stream_id,
            .max_data = self.initialPeerStreamDataLimit(stream_id),
        }) catch return error.OutOfMemory;
        appended_send_state = true;

        try self.queueResetStream(&self.send_streams.items[self.send_streams.items.len - 1], application_error_code);
    }

    /// Ask the peer to stop sending on a receive-capable stream.
    ///
    /// This queues one STOP_SENDING frame for an opened local bidirectional
    /// stream or an observed peer-initiated receive stream. Locally initiated
    /// unidirectional streams are send-only here and are rejected.
    pub fn stopSending(
        self: *QuicConnection,
        stream_id: u64,
        application_error_code: u64,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (stream_id > max_quic_varint) return error.InvalidStream;
        if (application_error_code > max_quic_varint) return error.InvalidPacket;
        if (!isBidirectionalStream(stream_id) and isLocalStreamInitiator(self.side, stream_id)) {
            return error.InvalidStream;
        }

        const existing_state = self.findRecvStream(stream_id);
        if (existing_state) |stream_state| {
            try self.queueStopSending(stream_state, application_error_code);
            return;
        }

        if (!isLocalBidirectionalStream(self.side, stream_id)) return error.InvalidStream;
        if (self.findSendStream(stream_id) == null) return error.InvalidStream;

        var appended_recv_state = false;
        errdefer if (appended_recv_state) {
            var removed = self.recv_streams.orderedRemove(self.recv_streams.items.len - 1);
            removed.deinit(self.allocator);
        };

        self.recv_streams.append(self.allocator, .{
            .stream_id = stream_id,
            .max_data = self.recv_max_stream_data,
        }) catch return error.OutOfMemory;
        appended_recv_state = true;

        try self.queueStopSending(&self.recv_streams.items[self.recv_streams.items.len - 1], application_error_code);
    }

    /// Queue one ack-eliciting PING frame for transmission by `pollTx`.
    ///
    /// The PING has no payload and does not consume stream or connection flow
    /// control credit. It is still congestion controlled once emitted.
    pub fn sendPing(self: *QuicConnection) Error!void {
        try self.sendPingInSpace(.application);
    }

    /// Queue one PATH_CHALLENGE frame and track it until a matching PATH_RESPONSE arrives.
    pub fn sendPathChallenge(self: *QuicConnection, data: [8]u8) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        self.pending_path_challenges.append(self.allocator, .{ .data = data }) catch return error.OutOfMemory;
    }

    /// Return the newest stored NEW_TOKEN value, or null when no token is available.
    ///
    /// Tokens are opaque address-validation data owned by the connection. The
    /// returned slice remains valid until `deinit()` or until the connection
    /// state is otherwise mutated by future token-storage changes.
    pub fn latestNewToken(self: QuicConnection) ?[]const u8 {
        if (self.stored_new_tokens.items.len == 0) return null;
        return self.stored_new_tokens.items[self.stored_new_tokens.items.len - 1];
    }

    /// Return the largest DATA_BLOCKED limit reported by the peer.
    pub fn peerDataBlockedLimit(self: QuicConnection) ?u64 {
        return self.peer_data_blocked_limit;
    }

    /// Return the largest STREAM_DATA_BLOCKED limit reported by the peer for one stream.
    pub fn peerStreamDataBlockedLimit(self: QuicConnection, stream_id: u64) ?u64 {
        for (self.peer_stream_data_blocked_limits.items) |blocked| {
            if (blocked.stream_id == stream_id) return blocked.maximum_stream_data;
        }
        return null;
    }

    /// Return the largest STREAMS_BLOCKED_BIDI limit reported by the peer.
    pub fn peerStreamsBlockedBidiLimit(self: QuicConnection) ?u64 {
        return self.peer_streams_blocked_bidi_limit;
    }

    /// Return the largest STREAMS_BLOCKED_UNI limit reported by the peer.
    pub fn peerStreamsBlockedUniLimit(self: QuicConnection) ?u64 {
        return self.peer_streams_blocked_uni_limit;
    }

    /// Read received CRYPTO bytes from the default Application-space byte stream.
    ///
    /// Returns null when no unread CRYPTO bytes are available. This wrapper
    /// keeps the original default Application-space behavior.
    pub fn recvCrypto(self: *QuicConnection, buf: []u8) Error!?usize {
        return self.recvCryptoInSpace(.application, buf);
    }

    /// Read received CRYPTO bytes from a selected packet number space.
    ///
    /// Returns null when no unread bytes are available in that space. Initial,
    /// Handshake, and Application CRYPTO offsets are intentionally independent.
    pub fn recvCryptoInSpace(
        self: *QuicConnection,
        space: PacketNumberSpace,
        buf: []u8,
    ) Error!?usize {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;
        if (packet_space.crypto_read_offset.* >= packet_space.crypto_recv_buffer.items.len) return null;

        const available = packet_space.crypto_recv_buffer.items[packet_space.crypto_read_offset.*..];
        const n = @min(buf.len, available.len);
        @memcpy(buf[0..n], available[0..n]);
        packet_space.crypto_read_offset.* += n;
        return n;
    }

    /// Read queued data for a stream. Returns null when no data is available,
    /// or `StreamClosed` when the peer reset the receive side.
    pub fn recvOnStream(
        self: *QuicConnection,
        stream_id: u64,
        buf: []u8,
    ) Error!?usize {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (stream_id > max_quic_varint) return error.InvalidStream;
        if (!isBidirectionalStream(stream_id) and isLocalStreamInitiator(self.side, stream_id)) {
            return error.InvalidStream;
        }

        const stream_state = self.findRecvStream(stream_id) orelse return null;
        if (stream_state.reset_error_code != null) return error.StreamClosed;
        if (stream_state.read_offset >= stream_state.data.items.len) {
            try self.queueReceiveFlowControlCredit(stream_state, 0);
            return null;
        }

        const available = stream_state.data.items[stream_state.read_offset..];
        const n = @min(buf.len, available.len);
        try self.queueReceiveFlowControlCredit(stream_state, n);
        @memcpy(buf[0..n], available[0..n]);
        stream_state.read_offset += n;
        return n;
    }

    /// Return the final size learned from a STREAM FIN or RESET_STREAM.
    ///
    /// Null means the receive side has not observed a final size yet. Locally
    /// initiated unidirectional stream IDs are invalid on the receive API.
    pub fn recvStreamFinalSize(self: QuicConnection, stream_id: u64) Error!?u64 {
        if (stream_id > max_quic_varint) return error.InvalidStream;
        if (!isBidirectionalStream(stream_id) and isLocalStreamInitiator(self.side, stream_id)) {
            return error.InvalidStream;
        }

        for (self.recv_streams.items) |stream| {
            if (stream.stream_id == stream_id) return stream.final_size;
        }
        return null;
    }

    /// Return whether the receive side has consumed all bytes through FIN.
    ///
    /// A RESET_STREAM final size is intentionally not treated as successful FIN
    /// completion; callers still receive `StreamClosed` from `recvOnStream()`.
    pub fn recvStreamFinished(self: QuicConnection, stream_id: u64) Error!bool {
        if (stream_id > max_quic_varint) return error.InvalidStream;
        if (!isBidirectionalStream(stream_id) and isLocalStreamInitiator(self.side, stream_id)) {
            return error.InvalidStream;
        }

        for (self.recv_streams.items) |stream| {
            if (stream.stream_id != stream_id) continue;
            if (stream.reset_error_code != null) return false;
            const final_size = stream.final_size orelse return false;
            const final_size_usize = std.math.cast(usize, final_size) orelse return false;
            if (stream.data.items.len < final_size_usize) return false;
            return stream.read_offset >= final_size_usize;
        }
        return false;
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

    fn queueCryptoFrame(
        self: *QuicConnection,
        queue: *std.ArrayList(PendingCryptoFrame),
        offset: u64,
        data: []const u8,
    ) Error!void {
        const owned = self.allocator.alloc(u8, data.len) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned);
        @memcpy(owned, data);

        queue.append(self.allocator, .{
            .offset = offset,
            .data = owned,
        }) catch return error.OutOfMemory;
    }

    fn queueDataBlockedFrame(self: *QuicConnection, maximum_data: u64) Error!void {
        for (self.pending_blocked_frames.items) |pending| {
            switch (pending) {
                .data => |data| if (data.maximum_data == maximum_data) return,
                else => {},
            }
        }
        self.pending_blocked_frames.append(self.allocator, .{ .data = .{ .maximum_data = maximum_data } }) catch return error.OutOfMemory;
    }

    fn queueStreamDataBlockedFrame(self: *QuicConnection, stream_id: u64, maximum_stream_data: u64) Error!void {
        for (self.pending_blocked_frames.items) |pending| {
            switch (pending) {
                .stream_data => |stream_data| if (stream_data.stream_id == stream_id and stream_data.maximum_stream_data == maximum_stream_data) return,
                else => {},
            }
        }
        self.pending_blocked_frames.append(self.allocator, .{ .stream_data = .{
            .stream_id = stream_id,
            .maximum_stream_data = maximum_stream_data,
        } }) catch return error.OutOfMemory;
    }

    fn queueStreamsBlockedBidiFrame(self: *QuicConnection, maximum_streams: u64) Error!void {
        for (self.pending_blocked_frames.items) |pending| {
            switch (pending) {
                .streams_bidi => |streams| if (streams.maximum_streams == maximum_streams) return,
                else => {},
            }
        }
        self.pending_blocked_frames.append(self.allocator, .{ .streams_bidi = .{ .maximum_streams = maximum_streams } }) catch return error.OutOfMemory;
    }

    fn queueStreamsBlockedUniFrame(self: *QuicConnection, maximum_streams: u64) Error!void {
        for (self.pending_blocked_frames.items) |pending| {
            switch (pending) {
                .streams_uni => |streams| if (streams.maximum_streams == maximum_streams) return,
                else => {},
            }
        }
        self.pending_blocked_frames.append(self.allocator, .{ .streams_uni = .{ .maximum_streams = maximum_streams } }) catch return error.OutOfMemory;
    }

    fn queueMaxDataFrame(self: *QuicConnection, maximum_data: u64) Error!void {
        for (self.pending_max_frames.items) |pending| {
            switch (pending) {
                .data => |data| if (data.maximum_data == maximum_data) return,
                else => {},
            }
        }
        self.pending_max_frames.append(self.allocator, .{ .data = .{ .maximum_data = maximum_data } }) catch return error.OutOfMemory;
    }

    fn queueMaxStreamDataFrame(
        self: *QuicConnection,
        stream_id: u64,
        maximum_stream_data: u64,
    ) Error!void {
        for (self.pending_max_frames.items) |pending| {
            switch (pending) {
                .stream_data => |stream_data| if (stream_data.stream_id == stream_id and stream_data.maximum_stream_data == maximum_stream_data) return,
                else => {},
            }
        }
        self.pending_max_frames.append(self.allocator, .{ .stream_data = .{
            .stream_id = stream_id,
            .maximum_stream_data = maximum_stream_data,
        } }) catch return error.OutOfMemory;
    }

    fn queueMaxStreamsBidiFrame(self: *QuicConnection, maximum_streams: u64) Error!void {
        if (maximum_streams > max_stream_count) return error.InvalidStream;
        for (self.pending_max_frames.items) |pending| {
            switch (pending) {
                .streams_bidi => |streams| if (streams.maximum_streams == maximum_streams) return,
                else => {},
            }
        }
        self.pending_max_frames.append(self.allocator, .{ .streams_bidi = .{ .maximum_streams = maximum_streams } }) catch return error.OutOfMemory;
    }

    fn queueMaxStreamsUniFrame(self: *QuicConnection, maximum_streams: u64) Error!void {
        if (maximum_streams > max_stream_count) return error.InvalidStream;
        for (self.pending_max_frames.items) |pending| {
            switch (pending) {
                .streams_uni => |streams| if (streams.maximum_streams == maximum_streams) return,
                else => {},
            }
        }
        self.pending_max_frames.append(self.allocator, .{ .streams_uni = .{ .maximum_streams = maximum_streams } }) catch return error.OutOfMemory;
    }

    fn queueReceiveStreamCountCredit(
        self: *QuicConnection,
        stream_state: *RecvStreamState,
        consumed_len: usize,
    ) Error!void {
        if (stream_state.stream_count_credit_released) return;
        if (stream_state.reset_error_code != null) return;
        const final_size = stream_state.final_size orelse return;
        const final_size_usize = std.math.cast(usize, final_size) orelse return error.Internal;
        if (stream_state.data.items.len < final_size_usize) return;
        const new_read_offset = std.math.add(usize, stream_state.read_offset, consumed_len) catch return error.Internal;
        if (new_read_offset < final_size_usize) return;
        if (isLocalStreamInitiator(self.side, stream_state.stream_id)) return;

        if (isBidirectionalStream(stream_state.stream_id)) {
            const next_limit = std.math.add(u64, self.recv_max_streams_bidi, 1) catch return error.InvalidStream;
            const max_frame = PendingMaxFrame{ .streams_bidi = .{ .maximum_streams = next_limit } };
            if (try maxFrameWireLen(max_frame) > self.maxTxDatagramSize()) return error.BufferTooSmall;
            try self.queueMaxStreamsBidiFrame(next_limit);
            self.recv_max_streams_bidi = next_limit;
        } else {
            const next_limit = std.math.add(u64, self.recv_max_streams_uni, 1) catch return error.InvalidStream;
            const max_frame = PendingMaxFrame{ .streams_uni = .{ .maximum_streams = next_limit } };
            if (try maxFrameWireLen(max_frame) > self.maxTxDatagramSize()) return error.BufferTooSmall;
            try self.queueMaxStreamsUniFrame(next_limit);
            self.recv_max_streams_uni = next_limit;
        }
        stream_state.stream_count_credit_released = true;
    }

    fn queueReceiveFlowControlCredit(
        self: *QuicConnection,
        stream_state: *RecvStreamState,
        consumed_len: usize,
    ) Error!void {
        if (consumed_len == 0) {
            try self.queueReceiveStreamCountCredit(stream_state, 0);
            return;
        }

        const pending_max_count = self.pending_max_frames.items.len;
        const recv_max_data_snapshot = self.recv_max_data;
        const recv_max_streams_bidi_snapshot = self.recv_max_streams_bidi;
        const recv_max_streams_uni_snapshot = self.recv_max_streams_uni;
        const stream_max_data_snapshot = stream_state.max_data;
        const stream_count_credit_released_snapshot = stream_state.stream_count_credit_released;
        errdefer {
            self.pending_max_frames.items.len = pending_max_count;
            self.recv_max_data = recv_max_data_snapshot;
            self.recv_max_streams_bidi = recv_max_streams_bidi_snapshot;
            self.recv_max_streams_uni = recv_max_streams_uni_snapshot;
            stream_state.max_data = stream_max_data_snapshot;
            stream_state.stream_count_credit_released = stream_count_credit_released_snapshot;
        }

        const consumed = std.math.cast(u64, consumed_len) orelse return error.Internal;
        const next_connection_limit = std.math.add(u64, self.recv_max_data, consumed) catch return error.Internal;
        const next_stream_limit = std.math.add(u64, stream_state.max_data, consumed) catch return error.Internal;
        if (next_connection_limit > max_quic_varint or next_stream_limit > max_quic_varint) return error.Internal;

        const max_data_frame = PendingMaxFrame{ .data = .{ .maximum_data = next_connection_limit } };
        const max_stream_data_frame = PendingMaxFrame{ .stream_data = .{
            .stream_id = stream_state.stream_id,
            .maximum_stream_data = next_stream_limit,
        } };
        const max_tx_datagram_size = self.maxTxDatagramSize();
        if (try maxFrameWireLen(max_data_frame) > max_tx_datagram_size) return error.BufferTooSmall;
        if (try maxFrameWireLen(max_stream_data_frame) > max_tx_datagram_size) return error.BufferTooSmall;

        try self.queueMaxDataFrame(next_connection_limit);
        try self.queueMaxStreamDataFrame(stream_state.stream_id, next_stream_limit);
        self.recv_max_data = next_connection_limit;
        stream_state.max_data = next_stream_limit;
        try self.queueReceiveStreamCountCredit(stream_state, consumed_len);
    }

    fn rollbackCryptoSendQueue(
        self: *QuicConnection,
        queue: *std.ArrayList(PendingCryptoFrame),
        original_len: usize,
    ) void {
        while (queue.items.len > original_len) {
            const removed = queue.orderedRemove(queue.items.len - 1);
            self.allocator.free(removed.data);
        }
    }

    fn rollbackSendQueue(self: *QuicConnection, original_len: usize) void {
        while (self.send_queue.items.len > original_len) {
            const removed = self.send_queue.orderedRemove(self.send_queue.items.len - 1);
            self.allocator.free(removed.data);
        }
    }

    fn rollbackStoredNewTokens(self: *QuicConnection, original_len: usize) void {
        while (self.stored_new_tokens.items.len > original_len) {
            const removed = self.stored_new_tokens.orderedRemove(self.stored_new_tokens.items.len - 1);
            self.allocator.free(removed);
        }
    }

    fn rollbackPeerStreamDataBlockedLimits(
        self: *QuicConnection,
        original_len: usize,
        snapshots: []const PeerStreamDataBlockedState,
    ) void {
        self.peer_stream_data_blocked_limits.items.len = original_len;
        @memcpy(self.peer_stream_data_blocked_limits.items[0..original_len], snapshots);
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
            while (stream.pending.items.len > snapshot.pending_count) {
                const removed = stream.pending.orderedRemove(stream.pending.items.len - 1);
                self.allocator.free(removed.data);
            }
            stream.max_data = snapshot.max_data;
            stream.data.items.len = snapshot.data_len;
            stream.read_offset = snapshot.read_offset;
            stream.final_size = snapshot.final_size;
            stream.reset_error_code = snapshot.reset_error_code;
            stream.stop_sending_sent = snapshot.stop_sending_sent;
            stream.stream_count_credit_released = snapshot.stream_count_credit_released;
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
        sent_packets: *std.ArrayList(SentPacket),
        original_len: usize,
        snapshots: []const SentPacket,
    ) void {
        _ = self;
        sent_packets.items.len = original_len;
        @memcpy(sent_packets.items[0..original_len], snapshots);
    }

    fn rollbackActiveConnectionIds(
        self: *QuicConnection,
        original_len: usize,
        snapshots: []const ActiveConnectionIdSnapshot,
    ) void {
        while (self.active_connection_ids.items.len > original_len) {
            const removed = self.active_connection_ids.orderedRemove(self.active_connection_ids.items.len - 1);
            self.allocator.free(removed.connection_id);
        }

        for (snapshots, 0..) |snapshot, i| {
            self.active_connection_ids.items[i].retired = snapshot.retired;
        }
    }

    fn streamDataLimitForBlockedFrame(self: *QuicConnection, stream_id: u64) u64 {
        if (self.findSendStream(stream_id)) |stream_state| return stream_state.max_data;
        return self.initialPeerStreamDataLimit(stream_id);
    }

    fn blockedFrameIsObsolete(self: *QuicConnection, blocked_frame: PendingBlockedFrame) bool {
        return switch (blocked_frame) {
            .data => |data| self.peer_max_data > data.maximum_data,
            .stream_data => |stream_data| self.streamDataLimitForBlockedFrame(stream_data.stream_id) > stream_data.maximum_stream_data,
            .streams_bidi => |streams| self.peer_max_streams_bidi > streams.maximum_streams,
            .streams_uni => |streams| self.peer_max_streams_uni > streams.maximum_streams,
        };
    }

    fn dropObsoleteBlockedFrames(self: *QuicConnection) void {
        var i: usize = 0;
        while (i < self.pending_blocked_frames.items.len) {
            if (self.blockedFrameIsObsolete(self.pending_blocked_frames.items[i])) {
                _ = self.pending_blocked_frames.orderedRemove(i);
                continue;
            }
            i += 1;
        }
    }

    fn receiveStreamDataLimitForMaxFrame(self: *QuicConnection, stream_id: u64) u64 {
        if (self.findRecvStream(stream_id)) |stream_state| return stream_state.max_data;
        return self.recv_max_stream_data;
    }

    fn maxFrameIsObsolete(self: *QuicConnection, max_frame: PendingMaxFrame) bool {
        return switch (max_frame) {
            .data => |data| self.recv_max_data > data.maximum_data,
            .stream_data => |stream_data| self.receiveStreamDataLimitForMaxFrame(stream_data.stream_id) > stream_data.maximum_stream_data,
            .streams_bidi => |streams| self.recv_max_streams_bidi > streams.maximum_streams,
            .streams_uni => |streams| self.recv_max_streams_uni > streams.maximum_streams,
        };
    }

    fn dropObsoleteMaxFrames(self: *QuicConnection) void {
        var i: usize = 0;
        while (i < self.pending_max_frames.items.len) {
            if (self.maxFrameIsObsolete(self.pending_max_frames.items[i])) {
                _ = self.pending_max_frames.orderedRemove(i);
                continue;
            }
            i += 1;
        }
    }

    fn receiveAckFrame(
        self: *QuicConnection,
        space: PacketNumberSpace,
        now_millis: i64,
        ack: frame.AckFrame,
        ecn_counts: ?frame.EcnCounts,
    ) Error!void {
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;
        if (ack.largest_acknowledged >= packet_space.next_packet_number.*) return error.InvalidPacket;

        var acked_bytes: usize = 0;
        var largest_acked_packet: ?SentPacket = null;
        var newly_acked_ect0: u64 = 0;
        var newly_acked_ect1: u64 = 0;

        var i: usize = 0;
        while (i < packet_space.sent_packets.items.len) {
            if (!ackFrameContains(ack, packet_space.sent_packets.items[i].packet_number)) {
                i += 1;
                continue;
            }

            const removed = packet_space.sent_packets.orderedRemove(i);
            acked_bytes = std.math.add(usize, acked_bytes, removed.bytes) catch std.math.maxInt(usize);
            if (largest_acked_packet == null or removed.packet_number > largest_acked_packet.?.packet_number) {
                largest_acked_packet = removed;
            }
            switch (removed.ecn_codepoint) {
                .not_ect => {},
                .ect0 => newly_acked_ect0 += 1,
                .ect1 => newly_acked_ect1 += 1,
            }
        }

        self.validateEcnAck(
            packet_space,
            ack.largest_acknowledged,
            newly_acked_ect0,
            newly_acked_ect1,
            ecn_counts,
        );

        const latest_rtt_sample = if (largest_acked_packet) |acked_packet|
            elapsedMillis(acked_packet.sent_time_millis, now_millis)
        else
            null;
        if (latest_rtt_sample != null and packet_space.first_rtt_sample_sent_time_millis.* == null) {
            packet_space.first_rtt_sample_sent_time_millis.* = largest_acked_packet.?.sent_time_millis;
        }
        if (acked_bytes != 0) {
            if (packet_space.largest_acknowledged.*) |previous_largest| {
                packet_space.largest_acknowledged.* = @max(previous_largest, ack.largest_acknowledged);
            } else {
                packet_space.largest_acknowledged.* = ack.largest_acknowledged;
            }
        }

        const loss_result = self.removeAckDrivenLosses(
            packet_space,
            packet_space.largest_acknowledged.* orelse ack.largest_acknowledged,
            latest_rtt_sample,
            now_millis,
        );
        const persistent_congestion_established = loss_result.persistentCongestionEstablished(packet_space.recovery_state.*);
        if (loss_result.lost_bytes != 0) {
            packet_space.recovery_state.onPacketLost(
                loss_result.lost_bytes,
                loss_result.largest_lost_sent_time_millis.?,
                now_millis,
            );
        }

        if (acked_bytes == 0) {
            if (persistent_congestion_established) {
                packet_space.recovery_state.onPersistentCongestion();
            }
            return;
        }

        packet_space.recovery_state.onPacketAcked(
            acked_bytes,
            largest_acked_packet.?.sent_time_millis,
            latest_rtt_sample.?,
            self.ackDelayForRtt(space, ack.ack_delay),
        );
        if (persistent_congestion_established) {
            packet_space.recovery_state.onPersistentCongestion();
        }
    }

    fn validateEcnAck(
        self: *QuicConnection,
        packet_space: PacketNumberSpaceView,
        largest_acknowledged: u64,
        newly_acked_ect0: u64,
        newly_acked_ect1: u64,
        ecn_counts: ?frame.EcnCounts,
    ) void {
        _ = self;
        if (packet_space.ecn_validation_state.* == .failed) return;
        if (packet_space.ecn_largest_acknowledged.*) |previous_largest| {
            if (largest_acknowledged <= previous_largest) return;
        }

        const counts = ecn_counts orelse {
            if (newly_acked_ect0 != 0 or newly_acked_ect1 != 0) {
                packet_space.ecn_validation_state.* = .failed;
            }
            return;
        };

        if (counts.ect0_count > packet_space.ecn_sent_ect0.* or
            counts.ect1_count > packet_space.ecn_sent_ect1.* or
            counts.ecn_ce_count > saturatingAddU64(packet_space.ecn_sent_ect0.*, packet_space.ecn_sent_ect1.*))
        {
            packet_space.ecn_validation_state.* = .failed;
            return;
        }

        const previous = packet_space.ecn_counts.*;
        if (counts.ect0_count < previous.ect0_count or
            counts.ect1_count < previous.ect1_count or
            counts.ecn_ce_count < previous.ecn_ce_count)
        {
            packet_space.ecn_validation_state.* = .failed;
            return;
        }

        const ect0_increase = counts.ect0_count - previous.ect0_count;
        const ect1_increase = counts.ect1_count - previous.ect1_count;
        const ce_increase = counts.ecn_ce_count - previous.ecn_ce_count;
        if (saturatingAddU64(ect0_increase, ce_increase) < newly_acked_ect0 or
            saturatingAddU64(ect1_increase, ce_increase) < newly_acked_ect1)
        {
            packet_space.ecn_validation_state.* = .failed;
            return;
        }

        packet_space.ecn_counts.* = counts;
        packet_space.ecn_largest_acknowledged.* = largest_acknowledged;
        if (packet_space.ecn_validation_state.* == .capable or newly_acked_ect0 != 0 or newly_acked_ect1 != 0) {
            packet_space.ecn_validation_state.* = .capable;
        }
    }

    fn removeAckDrivenLosses(
        self: *QuicConnection,
        packet_space: PacketNumberSpaceView,
        largest_acknowledged: u64,
        latest_rtt_sample_ms: ?u64,
        now_millis: i64,
    ) LossDetectionResult {
        _ = self;
        const loss_delay_ms = recovery.timeThresholdLossDelayMs(
            latest_rtt_sample_ms orelse packet_space.recovery_state.latest_rtt_ms,
            packet_space.recovery_state.smoothed_rtt_ms,
        );
        packet_space.loss_deadline_millis.* = null;
        var result: LossDetectionResult = .{};
        var i: usize = 0;
        while (i < packet_space.sent_packets.items.len) {
            const sent_packet = packet_space.sent_packets.items[i];
            if (sent_packet.packet_number > largest_acknowledged) {
                i += 1;
                continue;
            }
            const packet_threshold_lost = largest_acknowledged >=
                saturatingAddU64(sent_packet.packet_number, packet_threshold_loss_gap);
            const time_threshold_lost = saturatingAddMillis(sent_packet.sent_time_millis, loss_delay_ms) <= now_millis;
            if (!packet_threshold_lost and !time_threshold_lost) {
                const deadline = saturatingAddMillis(sent_packet.sent_time_millis, loss_delay_ms);
                packet_space.loss_deadline_millis.* = if (packet_space.loss_deadline_millis.*) |current|
                    @min(current, deadline)
                else
                    deadline;
                i += 1;
                continue;
            }

            const removed = packet_space.sent_packets.orderedRemove(i);
            result.recordLostPacket(removed, packet_space.first_rtt_sample_sent_time_millis.*);
        }
        return result;
    }

    fn expireLossDetectionTimeouts(self: *QuicConnection, now_millis: i64) void {
        self.expireLossDetectionTimeoutInSpace(.initial, now_millis);
        self.expireLossDetectionTimeoutInSpace(.handshake, now_millis);
        self.expireLossDetectionTimeoutInSpace(.application, now_millis);
    }

    fn expireLossDetectionTimeoutInSpace(self: *QuicConnection, space: PacketNumberSpace, now_millis: i64) void {
        const packet_space = self.packetNumberSpace(space);
        const deadline = packet_space.loss_deadline_millis.* orelse return;
        if (deadline > now_millis) return;
        const largest_acknowledged = packet_space.largest_acknowledged.* orelse {
            packet_space.loss_deadline_millis.* = null;
            return;
        };
        const loss_result = self.removeAckDrivenLosses(packet_space, largest_acknowledged, null, now_millis);
        if (loss_result.lost_bytes != 0) {
            packet_space.recovery_state.onPacketLost(
                loss_result.lost_bytes,
                loss_result.largest_lost_sent_time_millis.?,
                now_millis,
            );
            if (loss_result.persistentCongestionEstablished(packet_space.recovery_state.*)) {
                packet_space.recovery_state.onPersistentCongestion();
            }
        }
    }

    fn checkPtoTimeoutInSpace(self: *QuicConnection, space: PacketNumberSpace, now_millis: i64) Error!void {
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return;
        const deadline = self.ptoDeadlineMillis(space) orelse return;
        if (deadline > now_millis) return;
        try self.queuePingInSpace(space);
        packet_space.recovery_state.onPtoExpired();
    }

    fn pendingAckFrame(self: QuicConnection, space: PacketNumberSpace) ?frame.AckFrame {
        const largest = self.pendingAckLargest(space) orelse return null;
        return .{
            .largest_acknowledged = largest,
            .ack_delay = 0,
            .first_ack_range = largest,
        };
    }

    fn queuePingInSpace(self: *QuicConnection, space: PacketNumberSpace) Error!void {
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;
        packet_space.pending_ping_count.* = std.math.add(usize, packet_space.pending_ping_count.*, 1) catch return error.Internal;
    }

    fn expirePathChallenges(self: *QuicConnection, now_millis: i64) Error!void {
        if (self.outstanding_path_challenges.items.len == 0) return;

        const retry_after_ms = self.recovery_state.ptoMs();
        var retry_count: usize = 0;
        for (self.outstanding_path_challenges.items) |challenge| {
            if (elapsedMillis(challenge.sent_time_millis, now_millis) < retry_after_ms) continue;
            if (challenge.transmissions < max_path_challenge_transmissions) retry_count += 1;
        }
        if (retry_count != 0) {
            self.pending_path_challenges.ensureUnusedCapacity(self.allocator, retry_count) catch return error.OutOfMemory;
        }

        var i: usize = 0;
        while (i < self.outstanding_path_challenges.items.len) {
            const challenge = self.outstanding_path_challenges.items[i];
            if (elapsedMillis(challenge.sent_time_millis, now_millis) < retry_after_ms) {
                i += 1;
                continue;
            }

            if (challenge.transmissions >= max_path_challenge_transmissions) {
                _ = self.outstanding_path_challenges.orderedRemove(i);
                self.failed_path_validations = std.math.add(usize, self.failed_path_validations, 1) catch std.math.maxInt(usize);
                continue;
            }

            self.pending_path_challenges.appendAssumeCapacity(.{
                .data = challenge.data,
                .transmissions = challenge.transmissions,
            });
            _ = self.outstanding_path_challenges.orderedRemove(i);
        }
    }

    fn pollCloseFrame(
        self: *QuicConnection,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        const close = self.pending_close orelse return null;
        const encoded_len = try closeFrameWireLen(close);
        if (encoded_len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        if (!self.canSendToPeerAddress(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;

        var out = buffer.fixedWriter(out_buf[0..encoded_len]);
        switch (close) {
            .connection => |connection| frame.encodeFrame(out.writer(), .{ .connection_close = connection }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
            .application => |application| frame.encodeFrame(out.writer(), .{ .application_close = application }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
        }

        const written = out.getWritten();
        std.debug.assert(written.len == encoded_len);

        if (!self.closed) self.enterClosingState(now_millis);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_millis);
        return written;
    }

    fn pollAckOnly(
        self: *QuicConnection,
        ack: frame.AckFrame,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        return self.pollAckOnlyInSpace(.application, ack, now_millis, out_buf);
    }

    fn pollAckOnlyInSpace(
        self: *QuicConnection,
        space: PacketNumberSpace,
        ack: frame.AckFrame,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        const encoded_len = try ackFrameWireLen(ack);
        if (encoded_len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        if (!self.canSendToPeerAddress(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;

        var out = buffer.fixedWriter(out_buf[0..encoded_len]);
        frame.encodeFrame(out.writer(), .{ .ack = ack }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const packet_space = self.packetNumberSpace(space);
        packet_space.pending_ack_largest.* = null;
        const written = out.getWritten();
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_millis);
        return written;
    }

    fn pollPathResponse(
        self: *QuicConnection,
        ack_to_send: ?frame.AckFrame,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        const response_encoded_len = pathResponseFrameWireLen();
        const max_tx_datagram_size = self.maxTxDatagramSize();
        if (response_encoded_len > max_tx_datagram_size) return error.BufferTooSmall;

        var encoded_len = response_encoded_len;
        var include_ack = false;
        if (ack_to_send) |ack| {
            const ack_encoded_len = try ackFrameWireLen(ack);
            const coalesced_len = try addWireLen(ack_encoded_len, response_encoded_len);
            if (coalesced_len <= max_tx_datagram_size and out_buf.len >= coalesced_len and
                self.recovery_state.canSend(coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_millis, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.recovery_state.canSend(encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
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
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_millis);
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
        const max_tx_datagram_size = self.maxTxDatagramSize();
        if (reset_encoded_len > max_tx_datagram_size) return error.BufferTooSmall;

        var encoded_len = reset_encoded_len;
        var include_ack = false;
        if (ack_to_send) |ack| {
            const ack_encoded_len = try ackFrameWireLen(ack);
            const coalesced_len = try addWireLen(ack_encoded_len, reset_encoded_len);
            if (coalesced_len <= max_tx_datagram_size and out_buf.len >= coalesced_len and
                self.recovery_state.canSend(coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_millis, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.recovery_state.canSend(encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
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
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_millis);
        return written;
    }

    fn pollStopSending(
        self: *QuicConnection,
        ack_to_send: ?frame.AckFrame,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        const stop_sending = self.pending_stop_sending.items[0];
        const stop_encoded_len = try stopSendingFrameWireLen(stop_sending);
        const max_tx_datagram_size = self.maxTxDatagramSize();
        if (stop_encoded_len > max_tx_datagram_size) return error.BufferTooSmall;

        var encoded_len = stop_encoded_len;
        var include_ack = false;
        if (ack_to_send) |ack| {
            const ack_encoded_len = try ackFrameWireLen(ack);
            const coalesced_len = try addWireLen(ack_encoded_len, stop_encoded_len);
            if (coalesced_len <= max_tx_datagram_size and out_buf.len >= coalesced_len and
                self.recovery_state.canSend(coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_millis, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.recovery_state.canSend(encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
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
        frame.encodeFrame(out.writer(), .{ .stop_sending = stop_sending }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const written = out.getWritten();
        std.debug.assert(written.len == encoded_len);

        _ = self.pending_stop_sending.orderedRemove(0);
        if (include_ack) self.pending_ack_largest = null;
        self.next_packet_number = std.math.add(u64, packet_number, 1) catch return error.Internal;
        self.recovery_state.onPacketSent(written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_millis);
        return written;
    }

    fn pollRetireConnectionId(
        self: *QuicConnection,
        ack_to_send: ?frame.AckFrame,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        const sequence_number = self.pending_retire_connection_ids.items[0];
        const retire_encoded_len = try retireConnectionIdFrameWireLen(sequence_number);
        const max_tx_datagram_size = self.maxTxDatagramSize();
        if (retire_encoded_len > max_tx_datagram_size) return error.BufferTooSmall;

        var encoded_len = retire_encoded_len;
        var include_ack = false;
        if (ack_to_send) |ack| {
            const ack_encoded_len = try ackFrameWireLen(ack);
            const coalesced_len = try addWireLen(ack_encoded_len, retire_encoded_len);
            if (coalesced_len <= max_tx_datagram_size and out_buf.len >= coalesced_len and
                self.recovery_state.canSend(coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_millis, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.recovery_state.canSend(encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
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
        frame.encodeFrame(out.writer(), .{ .retire_connection_id = .{ .sequence_number = sequence_number } }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const written = out.getWritten();
        std.debug.assert(written.len == encoded_len);

        _ = self.pending_retire_connection_ids.orderedRemove(0);
        if (include_ack) self.pending_ack_largest = null;
        self.next_packet_number = std.math.add(u64, packet_number, 1) catch return error.Internal;
        self.recovery_state.onPacketSent(written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_millis);
        return written;
    }

    fn pollNewConnectionId(
        self: *QuicConnection,
        ack_to_send: ?frame.AckFrame,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        const local_index = self.nextUnsentLocalConnectionIdIndex() orelse return null;
        const local_id = self.local_connection_ids.items[local_index];
        const new_connection_id_encoded_len = try newConnectionIdFrameWireLen(local_id);
        const max_tx_datagram_size = self.maxTxDatagramSize();
        if (new_connection_id_encoded_len > max_tx_datagram_size) return error.BufferTooSmall;

        var encoded_len = new_connection_id_encoded_len;
        var include_ack = false;
        if (ack_to_send) |ack| {
            const ack_encoded_len = try ackFrameWireLen(ack);
            const coalesced_len = try addWireLen(ack_encoded_len, new_connection_id_encoded_len);
            if (coalesced_len <= max_tx_datagram_size and out_buf.len >= coalesced_len and
                self.recovery_state.canSend(coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_millis, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.recovery_state.canSend(encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
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
        frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
            .sequence_number = local_id.sequence_number,
            .retire_prior_to = local_id.retire_prior_to,
            .connection_id = local_id.connection_id,
            .stateless_reset_token = local_id.stateless_reset_token,
        } }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const written = out.getWritten();
        std.debug.assert(written.len == encoded_len);

        self.local_connection_ids.items[local_index].sent = true;
        if (include_ack) self.pending_ack_largest = null;
        self.next_packet_number = std.math.add(u64, packet_number, 1) catch return error.Internal;
        self.recovery_state.onPacketSent(written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_millis);
        return written;
    }

    fn pollPingFrame(
        self: *QuicConnection,
        ack_to_send: ?frame.AckFrame,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        return self.pollPingFrameInSpace(.application, ack_to_send, now_millis, out_buf);
    }

    fn pollPingFrameInSpace(
        self: *QuicConnection,
        space: PacketNumberSpace,
        ack_to_send: ?frame.AckFrame,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        var packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;

        const ping_encoded_len = pingFrameWireLen();
        const max_tx_datagram_size = self.maxTxDatagramSize();
        if (ping_encoded_len > max_tx_datagram_size) return error.BufferTooSmall;

        var encoded_len = ping_encoded_len;
        var include_ack = false;
        if (ack_to_send) |ack| {
            const ack_encoded_len = try ackFrameWireLen(ack);
            const coalesced_len = try addWireLen(ack_encoded_len, ping_encoded_len);
            if (coalesced_len <= max_tx_datagram_size and out_buf.len >= coalesced_len and
                packet_space.recovery_state.canSend(coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnlyInSpace(space, ack, now_millis, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!packet_space.recovery_state.canSend(encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;
        if (packet_space.next_packet_number.* > max_quic_varint) return error.Internal;

        var appended_sent_packet = false;
        errdefer if (appended_sent_packet) {
            packet_space.sent_packets.items.len -= 1;
        };

        const packet_number = packet_space.next_packet_number.*;
        packet_space.sent_packets.append(self.allocator, .{
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
        frame.encodeFrame(out.writer(), .{ .ping = {} }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const written = out.getWritten();
        std.debug.assert(written.len == encoded_len);

        packet_space.pending_ping_count.* -= 1;
        if (include_ack) packet_space.pending_ack_largest.* = null;
        packet_space.next_packet_number.* = std.math.add(u64, packet_number, 1) catch return error.Internal;
        packet_space.recovery_state.onPacketSent(written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_millis);
        return written;
    }

    fn pollPathChallenge(
        self: *QuicConnection,
        ack_to_send: ?frame.AckFrame,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        const challenge_encoded_len = pathChallengeFrameWireLen();
        const max_tx_datagram_size = self.maxTxDatagramSize();
        if (challenge_encoded_len > max_tx_datagram_size) return error.BufferTooSmall;

        var encoded_len = challenge_encoded_len;
        var include_ack = false;
        if (ack_to_send) |ack| {
            const ack_encoded_len = try ackFrameWireLen(ack);
            const coalesced_len = try addWireLen(ack_encoded_len, challenge_encoded_len);
            if (coalesced_len <= max_tx_datagram_size and out_buf.len >= coalesced_len and
                self.recovery_state.canSend(coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_millis, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.recovery_state.canSend(encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        var appended_sent_packet = false;
        var appended_outstanding_challenge = false;
        errdefer {
            if (appended_outstanding_challenge) {
                self.outstanding_path_challenges.items.len -= 1;
            }
            if (appended_sent_packet) {
                self.sent_packets.items.len -= 1;
            }
        }

        const packet_number = self.next_packet_number;
        self.sent_packets.append(self.allocator, .{
            .packet_number = packet_number,
            .sent_time_millis = now_millis,
            .bytes = encoded_len,
        }) catch return error.OutOfMemory;
        appended_sent_packet = true;

        const pending_challenge = self.pending_path_challenges.items[0];
        const challenge_data = pending_challenge.data;
        var out = buffer.fixedWriter(out_buf[0..encoded_len]);
        if (include_ack) {
            frame.encodeFrame(out.writer(), .{ .ack = ack_to_send.? }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }
        frame.encodeFrame(out.writer(), .{ .path_challenge = .{ .data = challenge_data } }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const transmissions = std.math.add(u8, pending_challenge.transmissions, 1) catch max_path_challenge_transmissions;
        self.outstanding_path_challenges.append(self.allocator, .{
            .data = challenge_data,
            .sent_time_millis = now_millis,
            .transmissions = transmissions,
        }) catch return error.OutOfMemory;
        appended_outstanding_challenge = true;

        const written = out.getWritten();
        std.debug.assert(written.len == encoded_len);

        _ = self.pending_path_challenges.orderedRemove(0);
        if (include_ack) self.pending_ack_largest = null;
        self.next_packet_number = std.math.add(u64, packet_number, 1) catch return error.Internal;
        self.recovery_state.onPacketSent(written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_millis);
        return written;
    }

    fn pollBlockedFrame(
        self: *QuicConnection,
        ack_to_send: ?frame.AckFrame,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        const blocked = self.pending_blocked_frames.items[0];
        const blocked_encoded_len = try blockedFrameWireLen(blocked);
        const max_tx_datagram_size = self.maxTxDatagramSize();
        if (blocked_encoded_len > max_tx_datagram_size) return error.BufferTooSmall;

        var encoded_len = blocked_encoded_len;
        var include_ack = false;
        if (ack_to_send) |ack| {
            const ack_encoded_len = try ackFrameWireLen(ack);
            const coalesced_len = try addWireLen(ack_encoded_len, blocked_encoded_len);
            if (coalesced_len <= max_tx_datagram_size and out_buf.len >= coalesced_len and
                self.recovery_state.canSend(coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_millis, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.recovery_state.canSend(encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
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
        switch (blocked) {
            .data => |data| frame.encodeFrame(out.writer(), .{ .data_blocked = data }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
            .stream_data => |stream_data| frame.encodeFrame(out.writer(), .{ .stream_data_blocked = stream_data }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
            .streams_bidi => |streams| frame.encodeFrame(out.writer(), .{ .streams_blocked_bidi = streams }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
            .streams_uni => |streams| frame.encodeFrame(out.writer(), .{ .streams_blocked_uni = streams }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
        }

        const written = out.getWritten();
        std.debug.assert(written.len == encoded_len);

        _ = self.pending_blocked_frames.orderedRemove(0);
        if (include_ack) self.pending_ack_largest = null;
        self.next_packet_number = std.math.add(u64, packet_number, 1) catch return error.Internal;
        self.recovery_state.onPacketSent(written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_millis);
        return written;
    }

    fn pollMaxFrame(
        self: *QuicConnection,
        ack_to_send: ?frame.AckFrame,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        const max_frame = self.pending_max_frames.items[0];
        const max_encoded_len = try maxFrameWireLen(max_frame);
        const max_tx_datagram_size = self.maxTxDatagramSize();
        if (max_encoded_len > max_tx_datagram_size) return error.BufferTooSmall;

        var encoded_len = max_encoded_len;
        var include_ack = false;
        if (ack_to_send) |ack| {
            const ack_encoded_len = try ackFrameWireLen(ack);
            const coalesced_len = try addWireLen(ack_encoded_len, max_encoded_len);
            if (coalesced_len <= max_tx_datagram_size and out_buf.len >= coalesced_len and
                self.recovery_state.canSend(coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_millis, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.recovery_state.canSend(encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
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
        switch (max_frame) {
            .data => |data| frame.encodeFrame(out.writer(), .{ .max_data = data }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
            .stream_data => |stream_data| frame.encodeFrame(out.writer(), .{ .max_stream_data = stream_data }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
            .streams_bidi => |streams| frame.encodeFrame(out.writer(), .{ .max_streams_bidi = streams }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
            .streams_uni => |streams| frame.encodeFrame(out.writer(), .{ .max_streams_uni = streams }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
        }

        const written = out.getWritten();
        std.debug.assert(written.len == encoded_len);

        _ = self.pending_max_frames.orderedRemove(0);
        if (include_ack) self.pending_ack_largest = null;
        self.next_packet_number = std.math.add(u64, packet_number, 1) catch return error.Internal;
        self.recovery_state.onPacketSent(written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_millis);
        return written;
    }

    fn pollCryptoFrame(
        self: *QuicConnection,
        space: PacketNumberSpace,
        ack_to_send: ?frame.AckFrame,
        now_millis: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        var packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;

        const pending = packet_space.crypto_send_queue.items[0];
        const crypto_encoded_len = try cryptoFrameWireLen(pending.offset, pending.data.len);
        const max_tx_datagram_size = self.maxTxDatagramSize();
        if (crypto_encoded_len > max_tx_datagram_size) return error.BufferTooSmall;

        var encoded_len = crypto_encoded_len;
        var include_ack = false;
        if (ack_to_send) |ack| {
            const ack_encoded_len = try ackFrameWireLen(ack);
            const coalesced_len = try addWireLen(ack_encoded_len, crypto_encoded_len);
            if (coalesced_len <= max_tx_datagram_size and out_buf.len >= coalesced_len and
                packet_space.recovery_state.canSend(coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnlyInSpace(space, ack, now_millis, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!packet_space.recovery_state.canSend(encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;
        if (packet_space.next_packet_number.* > max_quic_varint) return error.Internal;

        var appended_sent_packet = false;
        errdefer if (appended_sent_packet) {
            packet_space.sent_packets.items.len -= 1;
        };

        const packet_number = packet_space.next_packet_number.*;
        packet_space.sent_packets.append(self.allocator, .{
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
        frame.encodeFrame(out.writer(), .{ .crypto = .{
            .offset = pending.offset,
            .data = pending.data,
        } }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const written = out.getWritten();
        std.debug.assert(written.len == encoded_len);

        const removed = packet_space.crypto_send_queue.orderedRemove(0);
        self.allocator.free(removed.data);
        if (include_ack) packet_space.pending_ack_largest.* = null;
        packet_space.next_packet_number.* = std.math.add(u64, packet_number, 1) catch return error.Internal;
        packet_space.recovery_state.onPacketSent(written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_millis);
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

    fn queueAckForReceivedPacket(self: *QuicConnection, space: PacketNumberSpace) Error!void {
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;
        if (packet_space.next_peer_packet_number.* > max_quic_varint) return error.InvalidPacket;

        const packet_number = packet_space.next_peer_packet_number.*;
        packet_space.pending_ack_largest.* = if (packet_space.pending_ack_largest.*) |largest| @max(largest, packet_number) else packet_number;
        packet_space.next_peer_packet_number.* = std.math.add(u64, packet_number, 1) catch return error.Internal;
    }

    fn activeConnectionIdCount(self: QuicConnection) u64 {
        var count: u64 = 0;
        for (self.active_connection_ids.items) |active_id| {
            if (!active_id.retired) count += 1;
        }
        return count;
    }

    fn nextUnsentLocalConnectionIdIndex(self: QuicConnection) ?usize {
        for (self.local_connection_ids.items, 0..) |local_id, i| {
            if (!local_id.sent and !local_id.retired) return i;
        }
        return null;
    }

    fn localConnectionIdValueExists(self: QuicConnection, connection_id: []const u8) bool {
        for (self.local_connection_ids.items) |local_id| {
            if (std.mem.eql(u8, local_id.connection_id, connection_id)) return true;
        }
        return false;
    }

    fn findLocalConnectionId(self: *QuicConnection, sequence_number: u64) ?*LocalConnectionId {
        for (self.local_connection_ids.items) |*local_id| {
            if (local_id.sequence_number == sequence_number) return local_id;
        }
        return null;
    }

    fn rollbackLocalConnectionIds(
        self: *QuicConnection,
        original_len: usize,
        snapshots: []const LocalConnectionIdSnapshot,
    ) void {
        self.local_connection_ids.items.len = original_len;
        for (self.local_connection_ids.items, snapshots[0..original_len]) |*local_id, snapshot| {
            local_id.retired = snapshot.retired;
        }
    }

    fn findActiveConnectionId(self: *QuicConnection, sequence_number: u64) ?*ActiveConnectionId {
        for (self.active_connection_ids.items) |*active_id| {
            if (active_id.sequence_number == sequence_number) return active_id;
        }
        return null;
    }

    fn queueRetireConnectionId(self: *QuicConnection, sequence_number: u64) Error!void {
        for (self.pending_retire_connection_ids.items) |queued_sequence_number| {
            if (queued_sequence_number == sequence_number) return;
        }
        self.pending_retire_connection_ids.append(self.allocator, sequence_number) catch return error.OutOfMemory;
    }

    fn retireConnectionIdsBefore(self: *QuicConnection, retire_prior_to: u64) Error!void {
        for (self.active_connection_ids.items) |*active_id| {
            if (active_id.sequence_number >= retire_prior_to or active_id.retired) continue;
            active_id.retired = true;
            try self.queueRetireConnectionId(active_id.sequence_number);
        }
    }

    fn receiveNewConnectionIdFrame(self: *QuicConnection, new_connection_id: frame.NewConnectionIdFrame) Error!void {
        try self.retireConnectionIdsBefore(new_connection_id.retire_prior_to);

        if (self.findActiveConnectionId(new_connection_id.sequence_number)) |existing| {
            if (!std.mem.eql(u8, existing.connection_id, new_connection_id.connection_id)) return error.InvalidPacket;
            if (!std.mem.eql(u8, &existing.stateless_reset_token, &new_connection_id.stateless_reset_token)) return error.InvalidPacket;
            return;
        }

        if (self.activeConnectionIdCount() >= self.config.active_connection_id_limit) return error.InvalidPacket;

        const owned_connection_id = self.allocator.alloc(u8, new_connection_id.connection_id.len) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned_connection_id);
        @memcpy(owned_connection_id, new_connection_id.connection_id);

        self.active_connection_ids.append(self.allocator, .{
            .sequence_number = new_connection_id.sequence_number,
            .connection_id = owned_connection_id,
            .stateless_reset_token = new_connection_id.stateless_reset_token,
        }) catch return error.OutOfMemory;
    }

    fn receiveRetireConnectionIdFrame(self: *QuicConnection, retire_connection_id: frame.RetireConnectionIdFrame) Error!void {
        const local_id = self.findLocalConnectionId(retire_connection_id.sequence_number) orelse return error.InvalidPacket;
        if (!local_id.sent) return error.InvalidPacket;
        local_id.retired = true;
    }

    fn receiveNewTokenFrame(self: *QuicConnection, new_token: frame.NewTokenFrame) Error!void {
        if (self.side == .server) return error.InvalidPacket;
        if (self.stored_new_tokens.items.len >= self.config.max_stored_new_tokens) return;

        const owned = self.allocator.alloc(u8, new_token.token.len) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned);
        @memcpy(owned, new_token.token);

        self.stored_new_tokens.append(self.allocator, owned) catch return error.OutOfMemory;
    }

    fn receiveHandshakeDoneFrame(self: *QuicConnection) Error!void {
        if (self.side == .server) return error.InvalidPacket;
        self.handshake_confirmed = true;
    }

    fn receiveDataBlockedFrame(self: *QuicConnection, data_blocked: frame.DataBlockedFrame) Error!void {
        self.peer_data_blocked_limit = if (self.peer_data_blocked_limit) |current|
            @max(current, data_blocked.maximum_data)
        else
            data_blocked.maximum_data;
        if (data_blocked.maximum_data < self.recv_max_data) {
            try self.queueMaxDataFrame(self.recv_max_data);
        }
    }

    fn receiveStreamDataBlockedFrame(self: *QuicConnection, stream_data_blocked: frame.StreamDataBlockedFrame) Error!void {
        if (stream_data_blocked.stream_id > max_quic_varint) return error.InvalidStream;

        for (self.peer_stream_data_blocked_limits.items) |*blocked| {
            if (blocked.stream_id != stream_data_blocked.stream_id) continue;
            blocked.maximum_stream_data = @max(blocked.maximum_stream_data, stream_data_blocked.maximum_stream_data);
            if (self.findRecvStream(stream_data_blocked.stream_id)) |stream_state| {
                if (stream_data_blocked.maximum_stream_data < stream_state.max_data) {
                    try self.queueMaxStreamDataFrame(stream_data_blocked.stream_id, stream_state.max_data);
                }
            }
            return;
        }

        self.peer_stream_data_blocked_limits.append(self.allocator, .{
            .stream_id = stream_data_blocked.stream_id,
            .maximum_stream_data = stream_data_blocked.maximum_stream_data,
        }) catch return error.OutOfMemory;
        if (self.findRecvStream(stream_data_blocked.stream_id)) |stream_state| {
            if (stream_data_blocked.maximum_stream_data < stream_state.max_data) {
                try self.queueMaxStreamDataFrame(stream_data_blocked.stream_id, stream_state.max_data);
            }
        }
    }

    fn receiveStreamsBlockedBidiFrame(self: *QuicConnection, streams_blocked: frame.StreamsBlockedBidiFrame) Error!void {
        self.peer_streams_blocked_bidi_limit = if (self.peer_streams_blocked_bidi_limit) |current|
            @max(current, streams_blocked.maximum_streams)
        else
            streams_blocked.maximum_streams;
        if (streams_blocked.maximum_streams < self.recv_max_streams_bidi) {
            try self.queueMaxStreamsBidiFrame(self.recv_max_streams_bidi);
        }
    }

    fn receiveStreamsBlockedUniFrame(self: *QuicConnection, streams_blocked: frame.StreamsBlockedUniFrame) Error!void {
        self.peer_streams_blocked_uni_limit = if (self.peer_streams_blocked_uni_limit) |current|
            @max(current, streams_blocked.maximum_streams)
        else
            streams_blocked.maximum_streams;
        if (streams_blocked.maximum_streams < self.recv_max_streams_uni) {
            try self.queueMaxStreamsUniFrame(self.recv_max_streams_uni);
        }
    }

    fn receiveMaxDataFrame(self: *QuicConnection, max_data: frame.MaxDataFrame) void {
        self.peer_max_data = @max(self.peer_max_data, max_data.maximum_data);
    }

    fn receiveMaxStreamDataFrame(self: *QuicConnection, max_stream_data: frame.MaxStreamDataFrame) Error!void {
        if (max_stream_data.stream_id > max_quic_varint) return error.InvalidStream;

        if (!isBidirectionalStream(max_stream_data.stream_id)) {
            if (!isLocalStreamInitiator(self.side, max_stream_data.stream_id)) return error.InvalidPacket;
            const stream_state = self.findSendStream(max_stream_data.stream_id) orelse return error.InvalidPacket;
            stream_state.max_data = @max(stream_state.max_data, max_stream_data.maximum_stream_data);
            return;
        }

        if (isLocalStreamInitiator(self.side, max_stream_data.stream_id)) {
            const stream_state = self.findSendStream(max_stream_data.stream_id) orelse return error.InvalidPacket;
            stream_state.max_data = @max(stream_state.max_data, max_stream_data.maximum_stream_data);
            return;
        }

        if (streamCountForId(max_stream_data.stream_id) > self.recv_max_streams_bidi) return error.InvalidPacket;
        if (self.findRecvStream(max_stream_data.stream_id) == null) return error.InvalidPacket;

        const existing_state = self.findSendStream(max_stream_data.stream_id);
        const stream_state = existing_state orelse blk: {
            self.send_streams.append(self.allocator, .{
                .stream_id = max_stream_data.stream_id,
                .max_data = self.initialPeerStreamDataLimit(max_stream_data.stream_id),
            }) catch return error.OutOfMemory;
            break :blk &self.send_streams.items[self.send_streams.items.len - 1];
        };
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

    fn receivePathResponseFrame(self: *QuicConnection, path_response: frame.PathResponseFrame) Error!void {
        for (self.outstanding_path_challenges.items, 0..) |challenge, i| {
            if (std.mem.eql(u8, &challenge.data, &path_response.data)) {
                _ = self.outstanding_path_challenges.orderedRemove(i);
                return;
            }
        }

        return error.InvalidPacket;
    }

    fn receiveStopSendingFrame(self: *QuicConnection, stop_sending: frame.StopSendingFrame) Error!void {
        if (stop_sending.stream_id > max_quic_varint) return error.InvalidStream;

        if (!isBidirectionalStream(stop_sending.stream_id)) {
            if (!isLocalStreamInitiator(self.side, stop_sending.stream_id)) return error.InvalidPacket;
            const stream_state = self.findSendStream(stop_sending.stream_id) orelse return error.InvalidPacket;
            try self.queueResetStream(stream_state, stop_sending.application_error_code);
            return;
        }

        if (isLocalStreamInitiator(self.side, stop_sending.stream_id)) {
            const stream_state = self.findSendStream(stop_sending.stream_id) orelse return error.InvalidPacket;
            try self.queueResetStream(stream_state, stop_sending.application_error_code);
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
                .max_data = self.initialPeerStreamDataLimit(stop_sending.stream_id),
            }) catch return error.OutOfMemory;
            appended_send_state = true;
            break :blk &self.send_streams.items[self.send_streams.items.len - 1];
        };
        try self.queueResetStream(stream_state, stop_sending.application_error_code);
    }

    fn queueResetStream(
        self: *QuicConnection,
        stream_state: *SendStreamState,
        application_error_code: u64,
    ) Error!void {
        if (stream_state.reset_sent) return;
        if (application_error_code > max_quic_varint) return error.InvalidPacket;

        self.pending_reset_streams.append(self.allocator, .{
            .stream_id = stream_state.stream_id,
            .application_error_code = application_error_code,
            .final_size = stream_state.next_offset,
        }) catch return error.OutOfMemory;
        stream_state.fin_sent = true;
        stream_state.reset_sent = true;
    }

    fn queueStopSending(
        self: *QuicConnection,
        stream_state: *RecvStreamState,
        application_error_code: u64,
    ) Error!void {
        if (stream_state.reset_error_code != null) return error.StreamClosed;
        if (stream_state.stop_sending_sent) return;
        if (application_error_code > max_quic_varint) return error.InvalidPacket;

        self.pending_stop_sending.append(self.allocator, .{
            .stream_id = stream_state.stream_id,
            .application_error_code = application_error_code,
        }) catch return error.OutOfMemory;
        stream_state.stop_sending_sent = true;
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

    fn receivedStreamByteCount(stream_state: RecvStreamState) Error!u64 {
        var received = std.math.cast(u64, stream_state.data.items.len) orelse return error.Internal;
        for (stream_state.pending.items) |pending| {
            received = std.math.add(u64, received, pending.data.len) catch return error.InvalidPacket;
        }
        return received;
    }

    fn highestReceivedStreamEndOffset(stream_state: RecvStreamState) Error!u64 {
        var highest = std.math.cast(u64, stream_state.data.items.len) orelse return error.Internal;
        for (stream_state.pending.items) |pending| {
            const pending_end = streamEndOffset(pending.offset, pending.data.len) orelse return error.InvalidPacket;
            highest = @max(highest, pending_end);
        }
        return highest;
    }

    fn receiveStreamFrameOverlaps(stream_state: RecvStreamState, offset: u64, data_len: usize) Error!bool {
        if (data_len == 0) return false;

        const contiguous_len = std.math.cast(u64, stream_state.data.items.len) orelse return error.Internal;
        if (offset < contiguous_len) return true;

        for (stream_state.pending.items) |pending| {
            if (streamRangesOverlap(offset, data_len, pending.offset, pending.data.len)) return true;
        }
        return false;
    }

    fn appendPendingRecvStreamFrame(
        self: *QuicConnection,
        stream_state: *RecvStreamState,
        offset: u64,
        data: []const u8,
    ) Error!void {
        const owned = self.allocator.alloc(u8, data.len) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned);
        @memcpy(owned, data);

        stream_state.pending.append(self.allocator, .{
            .offset = offset,
            .data = owned,
        }) catch return error.OutOfMemory;
    }

    fn pendingRecvFrameIndexAt(stream_state: RecvStreamState, offset: u64) ?usize {
        for (stream_state.pending.items, 0..) |pending, i| {
            if (pending.offset == offset) return i;
        }
        return null;
    }

    fn drainPendingRecvStreams(self: *QuicConnection) Error!void {
        for (self.recv_streams.items) |*stream_state| {
            const start_len = stream_state.data.items.len;
            var expected = std.math.cast(u64, start_len) orelse return error.Internal;
            var total_append_len: usize = 0;
            while (pendingRecvFrameIndexAt(stream_state.*, expected)) |pending_index| {
                const pending = stream_state.pending.items[pending_index];
                total_append_len = std.math.add(usize, total_append_len, pending.data.len) catch return error.InvalidPacket;
                expected = streamEndOffset(expected, pending.data.len) orelse return error.InvalidPacket;
            }

            if (total_append_len == 0) continue;
            stream_state.data.ensureUnusedCapacity(self.allocator, total_append_len) catch return error.OutOfMemory;

            expected = std.math.cast(u64, start_len) orelse return error.Internal;
            while (pendingRecvFrameIndexAt(stream_state.*, expected)) |pending_index| {
                const pending = stream_state.pending.items[pending_index];
                stream_state.data.appendSliceAssumeCapacity(pending.data);
                expected = streamEndOffset(expected, pending.data.len) orelse return error.InvalidPacket;

                const removed = stream_state.pending.orderedRemove(pending_index);
                self.allocator.free(removed.data);
            }
        }
    }

    fn receiveResetStreamFrame(self: *QuicConnection, reset: frame.ResetStreamFrame) Error!void {
        if (reset.stream_id > max_quic_varint) return error.InvalidStream;
        try self.validateIncomingStreamCount(reset.stream_id);

        const existing_state = self.findRecvStream(reset.stream_id);
        var appended_recv_state = false;
        errdefer if (appended_recv_state) {
            var removed = self.recv_streams.orderedRemove(self.recv_streams.items.len - 1);
            removed.deinit(self.allocator);
        };

        const stream_state = existing_state orelse blk: {
            self.recv_streams.append(self.allocator, .{
                .stream_id = reset.stream_id,
                .max_data = self.recv_max_stream_data,
            }) catch return error.OutOfMemory;
            appended_recv_state = true;
            break :blk &self.recv_streams.items[self.recv_streams.items.len - 1];
        };

        if (reset.final_size > stream_state.max_data) return error.InvalidPacket;

        const highest_received = try highestReceivedStreamEndOffset(stream_state.*);
        if (reset.final_size < highest_received) return error.InvalidPacket;
        if (stream_state.final_size) |final_size| {
            if (final_size != reset.final_size) return error.InvalidPacket;
            return;
        }

        const received_size = try receivedStreamByteCount(stream_state.*);
        if (reset.final_size < received_size) return error.InvalidPacket;
        const delta = reset.final_size - received_size;
        const next_recv_total = std.math.add(u64, self.recv_data_bytes, delta) catch return error.InvalidPacket;
        if (next_recv_total > self.recv_max_data) return error.InvalidPacket;

        self.recv_data_bytes = next_recv_total;
        stream_state.final_size = reset.final_size;
        stream_state.reset_error_code = reset.application_error_code;
    }

    fn receiveCryptoFrame(
        self: *QuicConnection,
        space: PacketNumberSpace,
        crypto: frame.CryptoFrame,
    ) Error!void {
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;

        const expected_offset = std.math.cast(u64, packet_space.crypto_recv_buffer.items.len) orelse return error.Internal;
        if (crypto.offset != expected_offset) return error.InvalidPacket;
        _ = streamEndOffset(crypto.offset, crypto.data.len) orelse return error.InvalidPacket;

        packet_space.crypto_recv_buffer.appendSlice(self.allocator, crypto.data) catch return error.OutOfMemory;
    }

    fn receiveStreamFrame(self: *QuicConnection, stream_frame: frame.StreamFrame) Error!void {
        if (stream_frame.stream_id > max_quic_varint) return error.InvalidStream;
        try self.validateIncomingStreamCount(stream_frame.stream_id);

        const end_offset = streamEndOffset(stream_frame.offset, stream_frame.data.len) orelse return error.InvalidPacket;
        const next_recv_total = streamEndOffset(self.recv_data_bytes, stream_frame.data.len) orelse return error.InvalidPacket;
        if (next_recv_total > self.recv_max_data) return error.InvalidPacket;

        const existing_state = self.findRecvStream(stream_frame.stream_id);
        const stream_receive_limit = if (existing_state) |stream_state| stream_state.max_data else self.recv_max_stream_data;
        if (end_offset > stream_receive_limit) return error.InvalidPacket;

        if (existing_state) |stream_state| {
            if (stream_state.reset_error_code != null) return error.InvalidPacket;
            if (stream_state.final_size) |final_size| {
                if (end_offset > final_size) return error.InvalidPacket;
                if (stream_frame.fin and end_offset != final_size) return error.InvalidPacket;
            } else if (stream_frame.fin) {
                const highest_received = try highestReceivedStreamEndOffset(stream_state.*);
                if (end_offset < highest_received) return error.InvalidPacket;
            }

            if (try receiveStreamFrameOverlaps(stream_state.*, stream_frame.offset, stream_frame.data.len)) {
                return error.InvalidPacket;
            }
        }

        var appended_recv_state = false;
        errdefer if (appended_recv_state) {
            var removed = self.recv_streams.orderedRemove(self.recv_streams.items.len - 1);
            removed.deinit(self.allocator);
        };

        const stream_state = existing_state orelse blk: {
            self.recv_streams.append(self.allocator, .{
                .stream_id = stream_frame.stream_id,
                .max_data = self.recv_max_stream_data,
            }) catch return error.OutOfMemory;
            appended_recv_state = true;
            break :blk &self.recv_streams.items[self.recv_streams.items.len - 1];
        };

        const contiguous_len = std.math.cast(u64, stream_state.data.items.len) orelse return error.Internal;
        if (stream_frame.data.len != 0) {
            if (stream_frame.offset == contiguous_len) {
                stream_state.data.appendSlice(self.allocator, stream_frame.data) catch return error.OutOfMemory;
            } else {
                try self.appendPendingRecvStreamFrame(stream_state, stream_frame.offset, stream_frame.data);
            }
            self.recv_data_bytes = next_recv_total;
        }
        if (stream_frame.fin) {
            stream_state.final_size = end_offset;
        }
    }
};

const TestMaxStreamsKind = enum { bidi, uni };

const TestMaxFrameExpectation = union(enum) {
    data: u64,
    stream_data: struct {
        stream_id: u64,
        maximum_stream_data: u64,
    },
    streams_bidi: u64,
    streams_uni: u64,
};

fn payloadContainsExpectedMaxFrame(
    payload: []const u8,
    expected: TestMaxFrameExpectation,
) !bool {
    var offset: usize = 0;
    while (offset < payload.len) {
        var decoded = try frame.decodeFrameSlice(payload[offset..], std.testing.allocator);
        const decoded_len = decoded.len;
        defer frame.deinitFrame(&decoded.frame, std.testing.allocator);

        const matched = switch (decoded.frame) {
            .max_data => |max_data| switch (expected) {
                .data => |maximum_data| max_data.maximum_data == maximum_data,
                else => false,
            },
            .max_stream_data => |max_stream_data| switch (expected) {
                .stream_data => |stream_data| max_stream_data.stream_id == stream_data.stream_id and
                    max_stream_data.maximum_stream_data == stream_data.maximum_stream_data,
                else => false,
            },
            .max_streams_bidi => |max_streams| switch (expected) {
                .streams_bidi => |maximum_streams| max_streams.maximum_streams == maximum_streams,
                else => false,
            },
            .max_streams_uni => |max_streams| switch (expected) {
                .streams_uni => |maximum_streams| max_streams.maximum_streams == maximum_streams,
                else => false,
            },
            else => false,
        };
        if (matched) return true;
        if (decoded_len == 0) return error.TestUnexpectedResult;
        offset += decoded_len;
    }
    return false;
}

fn payloadContainsExpectedMaxStreams(
    payload: []const u8,
    kind: TestMaxStreamsKind,
    expected_max: u64,
) !bool {
    var offset: usize = 0;
    while (offset < payload.len) {
        var decoded = try frame.decodeFrameSlice(payload[offset..], std.testing.allocator);
        const decoded_len = decoded.len;
        switch (decoded.frame) {
            .max_streams_bidi => |max_streams| {
                frame.deinitFrame(&decoded.frame, std.testing.allocator);
                if (kind != .bidi) return false;
                try std.testing.expectEqual(expected_max, max_streams.maximum_streams);
                return true;
            },
            .max_streams_uni => |max_streams| {
                frame.deinitFrame(&decoded.frame, std.testing.allocator);
                if (kind != .uni) return false;
                try std.testing.expectEqual(expected_max, max_streams.maximum_streams);
                return true;
            },
            else => frame.deinitFrame(&decoded.frame, std.testing.allocator),
        }
        if (decoded_len == 0) return error.TestUnexpectedResult;
        offset += decoded_len;
    }
    return false;
}

fn pollAndProcessUntilMaxStreams(
    sender: *QuicConnection,
    receiver: *QuicConnection,
    kind: TestMaxStreamsKind,
    expected_max: u64,
) !void {
    var datagram: [128]u8 = undefined;
    var now_millis: i64 = 10;
    var poll_count: usize = 0;
    while (poll_count < 4) : (poll_count += 1) {
        const payload = (try sender.pollTx(now_millis, &datagram)) orelse break;
        const found = try payloadContainsExpectedMaxStreams(payload, kind, expected_max);
        try receiver.processDatagram(now_millis + 1, payload);
        if (found) return;
        now_millis += 10;
    }
    return error.TestUnexpectedResult;
}

fn expectFramePacketTypeRejected(
    packet_type: FramePacketType,
    frame_value: frame.Frame,
) !void {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), frame_value);

    try std.testing.expectError(
        error.InvalidPacket,
        conn.processDatagramForPacketType(packet_type, 0, out.getWritten()),
    );
    const space = packetNumberSpaceForFramePacketType(packet_type);
    try std.testing.expectEqual(@as(?u64, null), conn.pendingAckLargest(space));
    try std.testing.expectEqual(@as(u64, 0), conn.nextPeerPacketNumber(space));
}

test "openStream allocates client and server bidirectional stream ids" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    try std.testing.expectEqual(@as(u64, 0), try client.openStream());
    try std.testing.expectEqual(@as(u64, 4), try client.openStream());
    try std.testing.expectEqual(@as(u64, 1), try server.openStream());
    try std.testing.expectEqual(@as(u64, 5), try server.openStream());
}

test "init validates initial stream count limits" {
    var max_bidi = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_streams_bidi = max_stream_count,
    });
    defer max_bidi.deinit();

    var max_uni = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_streams_uni = max_stream_count,
    });
    defer max_uni.deinit();

    try std.testing.expectError(error.InvalidStream, QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_streams_bidi = max_stream_count + 1,
    }));
    try std.testing.expectError(error.InvalidStream, QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_streams_uni = max_stream_count + 1,
    }));
    try std.testing.expectError(error.InvalidPacket, QuicConnection.init(std.testing.allocator, .client, .{
        .active_connection_id_limit = 1,
    }));
}

test "localTransportParameters exposes configured receive limits" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .max_datagram_size = 1400,
        .max_idle_timeout_ms = 30_000,
        .disable_active_migration = true,
        .initial_max_data = 12_345,
        .initial_max_stream_data = 2345,
        .initial_max_streams_bidi = 12,
        .initial_max_streams_uni = 6,
        .active_connection_id_limit = 4,
    });
    defer conn.deinit();

    const params = conn.localTransportParameters();
    try std.testing.expect(params.stateless_reset_token == null);
    try std.testing.expectEqual(@as(u64, 30_000), params.max_idle_timeout);
    try std.testing.expect(params.disable_active_migration);
    try std.testing.expectEqual(@as(u64, 1400), params.max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, 12_345), params.initial_max_data);
    try std.testing.expectEqual(@as(u64, 2345), params.initial_max_stream_data_bidi_local);
    try std.testing.expectEqual(@as(u64, 2345), params.initial_max_stream_data_bidi_remote);
    try std.testing.expectEqual(@as(u64, 2345), params.initial_max_stream_data_uni);
    try std.testing.expectEqual(@as(u64, 12), params.initial_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 6), params.initial_max_streams_uni);
    try std.testing.expectEqual(@as(u64, 4), params.active_connection_id_limit);
}

test "localTransportParameters advertises server stateless reset token only" {
    const reset_token = [_]u8{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

    var client = try QuicConnection.init(std.testing.allocator, .client, .{
        .stateless_reset_token = reset_token,
    });
    defer client.deinit();
    try std.testing.expect(client.localTransportParameters().stateless_reset_token == null);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{
        .stateless_reset_token = reset_token,
    });
    defer server.deinit();

    const params = server.localTransportParameters();
    const advertised = params.stateless_reset_token orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &reset_token, &advertised);
}

test "applyPeerTransportParameters updates send limits and ACK policy" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_stream_data = 99,
        .initial_max_streams_bidi = 8,
        .initial_max_streams_uni = 8,
    });
    defer conn.deinit();

    const bidi_stream = try conn.openStream();
    try std.testing.expectEqual(@as(u64, 99), conn.send_streams.items[0].max_data);
    const reset_token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

    try conn.applyPeerTransportParameters(.{
        .stateless_reset_token = reset_token,
        .max_udp_payload_size = 1200,
        .initial_max_data = 10,
        .initial_max_stream_data_bidi_local = 7,
        .initial_max_stream_data_bidi_remote = 5,
        .initial_max_stream_data_uni = 9,
        .initial_max_streams_bidi = 1,
        .initial_max_streams_uni = 1,
        .ack_delay_exponent = 4,
        .max_idle_timeout = 250,
        .disable_active_migration = true,
        .max_ack_delay = 50,
    });

    try std.testing.expectEqual(@as(u64, 10), conn.peer_max_data);
    try std.testing.expectEqual(@as(usize, 1200), conn.maxTxDatagramSize());
    try std.testing.expectEqual(@as(u64, 4), conn.peer_ack_delay_exponent);
    try std.testing.expectEqual(@as(u64, 250), conn.peer_max_idle_timeout_ms);
    try std.testing.expectEqual(@as(?u64, 250), conn.effectiveIdleTimeoutMillis());
    try std.testing.expect(conn.peerActiveMigrationDisabled());
    const stored_reset_token = conn.peerStatelessResetToken() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &reset_token, &stored_reset_token);
    try std.testing.expectEqual(@as(u64, 50), conn.recovery_state.max_ack_delay_ms);
    try std.testing.expectEqual(@as(u64, 5), conn.findSendStream(bidi_stream).?.max_data);
    try std.testing.expectError(error.FlowControlBlocked, conn.openStream());

    const uni_stream = try conn.openUniStream();
    try std.testing.expectEqual(@as(u64, 9), conn.findSendStream(uni_stream).?.max_data);
    try std.testing.expectError(error.FlowControlBlocked, conn.openUniStream());
}

test "effectiveIdleTimeoutMillis uses shorter non-zero endpoint value" {
    var local_only = try QuicConnection.init(std.testing.allocator, .client, .{
        .max_idle_timeout_ms = 1000,
    });
    defer local_only.deinit();
    try std.testing.expectEqual(@as(?u64, 1000), local_only.effectiveIdleTimeoutMillis());

    var disabled = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer disabled.deinit();
    try std.testing.expectEqual(@as(?u64, null), disabled.effectiveIdleTimeoutMillis());

    var shorter_peer = try QuicConnection.init(std.testing.allocator, .client, .{
        .max_idle_timeout_ms = 1000,
    });
    defer shorter_peer.deinit();
    try shorter_peer.applyPeerTransportParameters(.{
        .max_idle_timeout = 250,
    });
    try std.testing.expectEqual(@as(?u64, 250), shorter_peer.effectiveIdleTimeoutMillis());

    var shorter_local = try QuicConnection.init(std.testing.allocator, .client, .{
        .max_idle_timeout_ms = 250,
    });
    defer shorter_local.deinit();
    try shorter_local.applyPeerTransportParameters(.{
        .max_idle_timeout = 1000,
    });
    try std.testing.expectEqual(@as(?u64, 250), shorter_local.effectiveIdleTimeoutMillis());
}

test "successful send refreshes idle timeout and timeout closes connection" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .max_idle_timeout_ms = 100,
    });
    defer conn.deinit();

    try conn.sendPing();
    var out_buf: [16]u8 = undefined;
    const payload = (try conn.pollTx(10, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), payload.len);
    try std.testing.expectEqual(@as(?i64, 110), conn.idleTimeoutDeadlineMillis());

    try conn.checkIdleTimeouts(109);
    try std.testing.expectEqual(ConnectionState.active, conn.connectionState());

    try std.testing.expectError(error.ConnectionClosed, conn.checkIdleTimeouts(110));
    try std.testing.expectEqual(ConnectionState.closed, conn.connectionState());
    try std.testing.expectError(error.ConnectionClosed, conn.sendPing());
}

test "successful receive refreshes idle timeout but invalid payload does not" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .max_idle_timeout_ms = 50,
    });
    defer conn.deinit();

    var payload_buf: [8]u8 = undefined;
    var payload_out = buffer.fixedWriter(&payload_buf);
    try frame.encodeFrame(payload_out.writer(), .{ .ping = {} });

    try conn.processDatagram(10, payload_out.getWritten());
    try std.testing.expectEqual(@as(?i64, 60), conn.idleTimeoutDeadlineMillis());
    try std.testing.expectEqual(@as(?u64, 0), conn.pendingAckLargest(.application));

    const invalid_payload = [_]u8{0xff};
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(20, &invalid_payload));
    try std.testing.expectEqual(@as(?i64, 60), conn.idleTimeoutDeadlineMillis());

    try std.testing.expectError(error.ConnectionClosed, conn.pollTx(60, &payload_buf));
    try std.testing.expectEqual(ConnectionState.closed, conn.connectionState());
}

test "applyPeerTransportParameters rejects invalid peer values without mutation" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    try std.testing.expectError(error.InvalidPacket, conn.applyPeerTransportParameters(.{
        .stateless_reset_token = token,
        .initial_max_data = 1,
    }));
    try std.testing.expectEqual(@as(u64, 65_536), conn.peer_max_data);
    try std.testing.expectEqual(@as(u64, 3), conn.peer_ack_delay_exponent);
    try std.testing.expect(conn.peerStatelessResetToken() == null);
    try std.testing.expectEqual(ConnectionState.active, conn.connectionState());
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

test "sendCrypto fragments and pollTx emits crypto frame payloads" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{ .max_datagram_size = 8 });
    defer conn.deinit();

    try conn.sendCrypto("hello world");
    try std.testing.expectEqual(@as(u64, 11), conn.crypto_send_offset);
    try std.testing.expectEqual(@as(usize, 3), conn.crypto_send_queue.items.len);

    const Expected = struct {
        offset: u64,
        data: []const u8,
    };
    const expected = [_]Expected{
        .{ .offset = 0, .data = "hello" },
        .{ .offset = 5, .data = " worl" },
        .{ .offset = 10, .data = "d" },
    };

    var out_buf: [8]u8 = undefined;
    for (expected) |want| {
        const payload = (try conn.pollTx(0, &out_buf)).?;
        try std.testing.expect(payload.len <= out_buf.len);

        var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
        defer frame.deinitFrame(&decoded.frame, std.testing.allocator);

        switch (decoded.frame) {
            .crypto => |crypto| {
                try std.testing.expectEqual(want.offset, crypto.offset);
                try std.testing.expectEqualStrings(want.data, crypto.data);
            },
            else => return error.TestUnexpectedResult,
        }
    }

    try std.testing.expectEqual(@as(usize, 0), conn.crypto_send_queue.items.len);
    try std.testing.expectEqual(@as(?[]u8, null), try conn.pollTx(0, &out_buf));
}

test "processDatagram and recvCrypto move crypto data" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .crypto = .{
        .offset = 0,
        .data = "hello ",
    } });
    try conn.processDatagram(0, out.getWritten());

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .crypto = .{
        .offset = 6,
        .data = "world",
    } });
    try conn.processDatagram(1, out.getWritten());

    try std.testing.expectEqual(@as(?u64, 1), conn.pending_ack_largest);

    var read_buf: [16]u8 = undefined;
    const n = (try conn.recvCrypto(&read_buf)).?;
    try std.testing.expectEqualStrings("hello world", read_buf[0..n]);
    try std.testing.expectEqual(@as(?usize, null), try conn.recvCrypto(&read_buf));
}

test "CRYPTO streams are isolated by packet number space" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    try client.sendCryptoInSpace(.initial, "initial flight");
    try client.sendCryptoInSpace(.handshake, "handshake flight");

    var datagram: [64]u8 = undefined;
    const initial_payload = (try client.pollTxInSpace(.initial, 10, &datagram)) orelse return error.TestUnexpectedResult;
    try server.processDatagramInSpace(.initial, 20, initial_payload);

    const handshake_payload = (try client.pollTxInSpace(.handshake, 30, &datagram)) orelse return error.TestUnexpectedResult;
    try server.processDatagramInSpace(.handshake, 40, handshake_payload);

    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.initial));
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.handshake));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.initial));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.handshake));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));

    var read_buf: [32]u8 = undefined;
    const initial_len = (try server.recvCryptoInSpace(.initial, &read_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("initial flight", read_buf[0..initial_len]);
    const handshake_len = (try server.recvCryptoInSpace(.handshake, &read_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("handshake flight", read_buf[0..handshake_len]);
    try std.testing.expectEqual(@as(?usize, null), try server.recvCryptoInSpace(.application, &read_buf));

    const initial_ack = (try server.pollTxInSpace(.initial, 50, &datagram)) orelse return error.TestUnexpectedResult;
    try client.processDatagramInSpace(.initial, 60, initial_ack);
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.initial));
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.handshake));
}

test "pollTx coalesces pending ACK with queued CRYPTO payload" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello", false);

    var datagram: [128]u8 = undefined;
    try server.processDatagram(20, (try client.pollTx(10, &datagram)).?);
    try server.sendCrypto("hs");

    const coalesced = (try server.pollTx(30, &datagram)).?;
    try std.testing.expectEqual(@as(usize, 1), server.sent_packets.items.len);
    try std.testing.expectEqual(@as(?u64, null), server.pending_ack_largest);

    var first = try frame.decodeFrameSlice(coalesced, std.testing.allocator);
    defer frame.deinitFrame(&first.frame, std.testing.allocator);
    switch (first.frame) {
        .ack => |ack| try std.testing.expectEqual(@as(u64, 0), ack.largest_acknowledged),
        else => return error.TestUnexpectedResult,
    }

    var second = try frame.decodeFrameSlice(coalesced[first.len..], std.testing.allocator);
    defer frame.deinitFrame(&second.frame, std.testing.allocator);
    switch (second.frame) {
        .crypto => |crypto| {
            try std.testing.expectEqual(@as(u64, 0), crypto.offset);
            try std.testing.expectEqualStrings("hs", crypto.data);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "sendPing and pollTx emit ping frame payloads" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    try conn.sendPing();
    try conn.sendPing();
    try std.testing.expectEqual(@as(usize, 2), conn.pending_ping_count);

    var out_buf: [16]u8 = undefined;
    const first_payload = (try conn.pollTx(10, &out_buf)).?;
    try std.testing.expectEqual(@as(usize, 1), conn.pending_ping_count);
    try std.testing.expectEqual(@as(usize, 1), conn.sent_packets.items.len);
    try std.testing.expectEqual(@as(usize, first_payload.len), conn.recovery_state.bytes_in_flight);

    var first = try frame.decodeFrameSlice(first_payload, std.testing.allocator);
    defer frame.deinitFrame(&first.frame, std.testing.allocator);
    switch (first.frame) {
        .ping => {},
        else => return error.TestUnexpectedResult,
    }

    const second_payload = (try conn.pollTx(20, &out_buf)).?;
    try std.testing.expectEqual(@as(usize, 0), conn.pending_ping_count);
    try std.testing.expectEqual(@as(usize, 2), conn.sent_packets.items.len);

    var second = try frame.decodeFrameSlice(second_payload, std.testing.allocator);
    defer frame.deinitFrame(&second.frame, std.testing.allocator);
    switch (second.frame) {
        .ping => {},
        else => return error.TestUnexpectedResult,
    }
}

test "server anti-amplification blocks sends until peer bytes are recorded" {
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try std.testing.expect(!server.peerAddressValidated());
    try std.testing.expectEqual(@as(?usize, 0), server.antiAmplificationLimitRemaining());

    try server.sendPing();
    var out_buf: [16]u8 = undefined;
    try std.testing.expectEqual(@as(?[]u8, null), try server.pollTx(0, &out_buf));
    try std.testing.expectEqual(@as(usize, 1), server.pending_ping_count);

    try server.recordPeerAddressBytesReceived(1);
    try std.testing.expectEqual(@as(?usize, 3), server.antiAmplificationLimitRemaining());

    const payload = (try server.pollTx(1, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), payload.len);
    try std.testing.expectEqual(@as(?usize, 2), server.antiAmplificationLimitRemaining());
    try std.testing.expectEqual(@as(usize, 0), server.pending_ping_count);
}

test "server anti-amplification budget is shared across packet number spaces" {
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try server.recordPeerAddressBytesReceived(1);
    try server.sendPingInSpace(.initial);
    try server.sendPing();

    var out_buf: [32]u8 = undefined;
    const initial_payload = (try server.pollTxInSpace(.initial, 0, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), initial_payload.len);
    try std.testing.expectEqual(@as(?usize, 2), server.antiAmplificationLimitRemaining());

    const app_payload = (try server.pollTx(1, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), app_payload.len);
    try std.testing.expectEqual(@as(?usize, 1), server.antiAmplificationLimitRemaining());

    try server.sendCryptoInSpace(.handshake, "x");
    try std.testing.expectEqual(@as(?[]u8, null), try server.pollTxInSpace(.handshake, 2, &out_buf));
    try std.testing.expectEqual(@as(usize, 1), server.handshake_packet_space.crypto_send_queue.items.len);

    try server.validatePeerAddress();
    try std.testing.expect(server.peerAddressValidated());
    try std.testing.expectEqual(@as(?usize, null), server.antiAmplificationLimitRemaining());

    const crypto_payload = (try server.pollTxInSpace(.handshake, 3, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(crypto_payload.len > 1);
    try std.testing.expectEqual(@as(usize, 0), server.handshake_packet_space.crypto_send_queue.items.len);
}

test "recordPacketSentInSpace respects server anti-amplification budget" {
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try std.testing.expectError(error.FlowControlBlocked, server.recordPacketSentInSpace(.application, 0, 1));

    try server.recordPeerAddressBytesReceived(10);
    try std.testing.expectEqual(@as(u64, 0), try server.recordPacketSentInSpace(.application, 0, 20));
    try std.testing.expectEqual(@as(?usize, 10), server.antiAmplificationLimitRemaining());

    try std.testing.expectError(error.FlowControlBlocked, server.recordPacketSentInSpace(.application, 10, 11));
    try std.testing.expectEqual(@as(usize, 1), server.sentPacketCount(.application));
    try std.testing.expectEqual(@as(?usize, 10), server.antiAmplificationLimitRemaining());
}

test "server Retry token validation consumes token and validates address" {
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try server.issueRetryToken("retry-token");
    try std.testing.expectEqual(@as(usize, 1), server.pendingRetryTokenCount());
    try std.testing.expect(!server.peerAddressValidated());

    try server.sendPing();
    var out_buf: [16]u8 = undefined;
    try std.testing.expectEqual(@as(?[]u8, null), try server.pollTx(0, &out_buf));

    try server.validateRetryToken("retry-token");
    try std.testing.expect(server.peerAddressValidated());
    try std.testing.expectEqual(@as(?usize, null), server.antiAmplificationLimitRemaining());
    try std.testing.expectEqual(@as(usize, 0), server.pendingRetryTokenCount());

    const payload = (try server.pollTx(1, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), payload.len);
    try std.testing.expectError(error.InvalidPacket, server.validateRetryToken("retry-token"));
}

test "Retry token validation rejects invalid tokens without mutation" {
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try std.testing.expectError(error.InvalidPacket, server.issueRetryToken(""));
    try server.issueRetryToken("valid");
    try std.testing.expectError(error.InvalidPacket, server.issueRetryToken("valid"));

    try std.testing.expectError(error.InvalidPacket, server.validateRetryToken(""));
    try std.testing.expectError(error.InvalidPacket, server.validateRetryToken("invalid"));
    try std.testing.expect(!server.peerAddressValidated());
    try std.testing.expectEqual(@as(usize, 1), server.pendingRetryTokenCount());

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try std.testing.expectError(error.InvalidPacket, client.issueRetryToken("server-only"));
    try std.testing.expectError(error.InvalidPacket, client.validateRetryToken("server-only"));
}

test "invalid datagram leaves explicit anti-amplification budget unchanged" {
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try server.recordPeerAddressBytesReceived(2);
    try std.testing.expectEqual(@as(?usize, 6), server.antiAmplificationLimitRemaining());

    const invalid_payload = [_]u8{0xff};
    try std.testing.expectError(error.InvalidPacket, server.processDatagram(0, &invalid_payload));
    try std.testing.expectEqual(@as(?usize, 6), server.antiAmplificationLimitRemaining());
    try std.testing.expectEqual(@as(u64, 0), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));
}

test "pollTx coalesces pending ACK with queued PING payload" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello", false);

    var datagram: [128]u8 = undefined;
    try server.processDatagram(20, (try client.pollTx(10, &datagram)).?);
    try server.sendPing();

    const coalesced = (try server.pollTx(30, &datagram)).?;
    try std.testing.expectEqual(@as(usize, 1), server.sent_packets.items.len);
    try std.testing.expectEqual(@as(usize, 0), server.pending_ping_count);
    try std.testing.expectEqual(@as(?u64, null), server.pending_ack_largest);

    var first = try frame.decodeFrameSlice(coalesced, std.testing.allocator);
    defer frame.deinitFrame(&first.frame, std.testing.allocator);
    switch (first.frame) {
        .ack => |ack| try std.testing.expectEqual(@as(u64, 0), ack.largest_acknowledged),
        else => return error.TestUnexpectedResult,
    }

    var second = try frame.decodeFrameSlice(coalesced[first.len..], std.testing.allocator);
    defer frame.deinitFrame(&second.frame, std.testing.allocator);
    switch (second.frame) {
        .ping => {},
        else => return error.TestUnexpectedResult,
    }
}

test "processDatagram rejects out-of-order crypto data" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [16]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .crypto = .{
        .offset = 1,
        .data = "x",
    } });

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_recv_buffer.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
}

test "processDatagram rolls back crypto data when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .crypto = .{
        .offset = 0,
        .data = "x",
    } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_recv_buffer.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_read_offset);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 0), conn.next_peer_packet_number);
}

test "sendCrypto rejects unsendable crypto frames before mutating state" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{ .max_datagram_size = 2 });
    defer conn.deinit();

    try std.testing.expectError(error.BufferTooSmall, conn.sendCrypto("x"));
    try std.testing.expectEqual(@as(u64, 0), conn.crypto_send_offset);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_send_queue.items.len);

    var out_buf: [16]u8 = undefined;
    try std.testing.expectEqual(@as(?[]u8, null), try conn.pollTx(0, &out_buf));
}

test "sendCrypto rolls back partial fragmentation when later offsets cannot fit" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{ .max_datagram_size = 4 });
    defer conn.deinit();

    const data = [_]u8{'x'} ** 65;
    try std.testing.expectError(error.BufferTooSmall, conn.sendCrypto(&data));
    try std.testing.expectEqual(@as(u64, 0), conn.crypto_send_offset);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_send_queue.items.len);
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

test "ACK delay is ignored for Initial RTT samples" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();

    _ = try conn.recordPacketSentInSpace(.initial, 0, 100);
    try conn.receiveAckInSpace(.initial, 100, .{
        .largest_acknowledged = 0,
        .ack_delay = 1,
        .first_ack_range = 0,
    });
    try std.testing.expectEqual(@as(u64, 100), conn.smoothedRttMillis(.initial));

    _ = try conn.recordPacketSentInSpace(.initial, 100, 100);
    try conn.receiveAckInSpace(.initial, 200, .{
        .largest_acknowledged = 1,
        .ack_delay = 1,
        .first_ack_range = 0,
    });
    try std.testing.expectEqual(@as(u64, 100), conn.smoothedRttMillis(.initial));
}

test "ACK delay is capped by peer max_ack_delay after handshake confirmation" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();
    try conn.applyPeerTransportParameters(.{
        .max_ack_delay = 10,
        .ack_delay_exponent = 3,
    });
    try std.testing.expectEqual(@as(u64, 0), conn.ackDelayForRtt(.initial, 20));
    try std.testing.expectEqual(@as(u64, 160), conn.ackDelayForRtt(.application, 20));

    _ = try conn.recordPacketSentInSpace(.application, 0, 100);
    try conn.receiveAckInSpace(.application, 100, .{
        .largest_acknowledged = 0,
        .ack_delay = 20,
        .first_ack_range = 0,
    });
    try std.testing.expectEqual(@as(u64, 100), conn.smoothedRttMillis(.application));

    _ = try conn.recordPacketSentInSpace(.application, 100, 100);
    try conn.receiveAckInSpace(.application, 220, .{
        .largest_acknowledged = 1,
        .ack_delay = 20,
        .first_ack_range = 0,
    });
    try std.testing.expectEqual(@as(u64, 102), conn.smoothedRttMillis(.application));

    _ = try conn.recordPacketSentInSpace(.application, 220, 100);
    try conn.confirmHandshake();
    try std.testing.expectEqual(@as(u64, 10), conn.ackDelayForRtt(.application, 20));
    try conn.receiveAckInSpace(.application, 340, .{
        .largest_acknowledged = 2,
        .ack_delay = 20,
        .first_ack_range = 0,
    });
    try std.testing.expectEqual(@as(u64, 103), conn.smoothedRttMillis(.application));
}

test "ACK marks packet-threshold losses in the selected packet number space" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    _ = try conn.recordPacketSentInSpace(.application, 10, 100);
    _ = try conn.recordPacketSentInSpace(.application, 11, 100);
    _ = try conn.recordPacketSentInSpace(.application, 12, 100);
    _ = try conn.recordPacketSentInSpace(.application, 13, 100);
    try std.testing.expectEqual(@as(usize, 400), conn.bytesInFlight(.application));

    try conn.receiveAckInSpace(.application, 70, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    try std.testing.expectEqual(@as(usize, 2), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 200), conn.bytesInFlight(.application));
    try std.testing.expectEqual(@as(?u64, 57), conn.recovery_state.latest_rtt_ms);
}

test "ACK marks time-threshold losses in the selected packet number space" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    _ = try conn.recordPacketSentInSpace(.application, 0, 100);
    _ = try conn.recordPacketSentInSpace(.application, 500, 100);
    try std.testing.expectEqual(@as(usize, 200), conn.bytesInFlight(.application));

    try conn.receiveAckInSpace(.application, 900, .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    try std.testing.expectEqual(@as(usize, 0), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), conn.bytesInFlight(.application));
    try std.testing.expectEqual(@as(?u64, 400), conn.recovery_state.latest_rtt_ms);
}

test "ACK keeps earlier packet while time-threshold delay has not elapsed" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    _ = try conn.recordPacketSentInSpace(.application, 300, 100);
    _ = try conn.recordPacketSentInSpace(.application, 500, 100);

    try conn.receiveAckInSpace(.application, 600, .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    try std.testing.expectEqual(@as(usize, 1), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 100), conn.bytesInFlight(.application));
    try std.testing.expectEqual(@as(u64, 0), conn.sent_packets.items[0].packet_number);
    try std.testing.expectEqual(@as(?i64, 675), conn.lossDetectionDeadlineMillis(.application));

    try conn.checkLossDetectionTimeouts(674);
    try std.testing.expectEqual(@as(usize, 1), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 100), conn.bytesInFlight(.application));

    try conn.checkLossDetectionTimeouts(675);
    try std.testing.expectEqual(@as(usize, 0), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), conn.bytesInFlight(.application));
    try std.testing.expectEqual(@as(?i64, null), conn.lossDetectionDeadlineMillis(.application));
}

test "ACK-driven losses establish persistent congestion after prior RTT sample" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();

    _ = try conn.recordPacketSentInSpace(.application, 0, 100);
    try conn.receiveAckInSpace(.application, 100, .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    _ = try conn.recordPacketSentInSpace(.application, 10, 100);
    _ = try conn.recordPacketSentInSpace(.application, 1000, 100);
    _ = try conn.recordPacketSentInSpace(.application, 1100, 100);
    _ = try conn.recordPacketSentInSpace(.application, 1200, 100);

    try conn.receiveAckInSpace(.application, 1300, .{
        .largest_acknowledged = 4,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    try std.testing.expectEqual(@as(usize, 0), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), conn.bytesInFlight(.application));
    try std.testing.expectEqual(recovery.minimumCongestionWindow(1200), conn.congestionWindow(.application));
}

test "ACK-driven losses do not establish persistent congestion before first RTT sample" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();

    _ = try conn.recordPacketSentInSpace(.application, 10, 100);
    _ = try conn.recordPacketSentInSpace(.application, 1000, 100);
    _ = try conn.recordPacketSentInSpace(.application, 1100, 100);
    _ = try conn.recordPacketSentInSpace(.application, 1200, 100);

    try conn.receiveAckInSpace(.application, 1300, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    try std.testing.expectEqual(@as(usize, 0), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), conn.bytesInFlight(.application));
    try std.testing.expect(conn.congestionWindow(.application) > recovery.minimumCongestionWindow(1200));
}

test "ACK losses respect NewReno congestion recovery period" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();

    const initial_window = conn.congestionWindow(.application);
    var packet_number: u64 = 0;
    while (packet_number < 8) : (packet_number += 1) {
        _ = try conn.recordPacketSentInSpace(.application, @as(i64, @intCast(packet_number + 1)) * 10, 100);
    }

    try conn.receiveAckInSpace(.application, 100, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    const recovery_window = conn.congestionWindow(.application);
    try std.testing.expect(recovery_window < initial_window);

    try conn.receiveAckInSpace(.application, 120, .{
        .largest_acknowledged = 7,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    try std.testing.expectEqual(recovery_window, conn.congestionWindow(.application));
}

test "processDatagram rolls back packet-threshold losses when later frame is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();
    try conn.validatePeerAddress();

    _ = try conn.recordPacketSentInSpace(.application, 10, 100);
    _ = try conn.recordPacketSentInSpace(.application, 11, 100);
    _ = try conn.recordPacketSentInSpace(.application, 12, 100);
    _ = try conn.recordPacketSentInSpace(.application, 13, 100);

    var payload_buf: [32]u8 = undefined;
    var payload = buffer.fixedWriter(&payload_buf);
    try frame.encodeFrame(payload.writer(), .{ .ack = .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    } });
    try payload.writer().writeByte(@intFromEnum(frame.FrameType.handshake_done));

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(70, payload.getWritten()));
    try std.testing.expectEqual(@as(usize, 4), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 400), conn.bytesInFlight(.application));
    try std.testing.expectEqual(@as(?u64, null), conn.recovery_state.latest_rtt_ms);
    try std.testing.expectEqual(@as(?i64, null), conn.lossDetectionDeadlineMillis(.application));
}

test "processDatagram rolls back time-threshold losses when later frame is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();
    try conn.validatePeerAddress();

    _ = try conn.recordPacketSentInSpace(.application, 0, 100);
    _ = try conn.recordPacketSentInSpace(.application, 500, 100);

    var payload_buf: [32]u8 = undefined;
    var payload = buffer.fixedWriter(&payload_buf);
    try frame.encodeFrame(payload.writer(), .{ .ack = .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    } });
    try payload.writer().writeByte(@intFromEnum(frame.FrameType.handshake_done));

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(900, payload.getWritten()));
    try std.testing.expectEqual(@as(usize, 2), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 200), conn.bytesInFlight(.application));
    try std.testing.expectEqual(@as(?u64, null), conn.recovery_state.latest_rtt_ms);
    try std.testing.expectEqual(@as(?i64, null), conn.lossDetectionDeadlineMillis(.application));
}

test "processDatagram rolls back persistent congestion when later frame is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();
    try conn.validatePeerAddress();

    _ = try conn.recordPacketSentInSpace(.application, 0, 100);
    try conn.receiveAckInSpace(.application, 100, .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    _ = try conn.recordPacketSentInSpace(.application, 10, 100);
    _ = try conn.recordPacketSentInSpace(.application, 1000, 100);
    _ = try conn.recordPacketSentInSpace(.application, 1100, 100);
    _ = try conn.recordPacketSentInSpace(.application, 1200, 100);
    const congestion_window_before = conn.congestionWindow(.application);

    var payload_buf: [32]u8 = undefined;
    var payload = buffer.fixedWriter(&payload_buf);
    try frame.encodeFrame(payload.writer(), .{ .ack = .{
        .largest_acknowledged = 4,
        .ack_delay = 0,
        .first_ack_range = 0,
    } });
    try payload.writer().writeByte(@intFromEnum(frame.FrameType.handshake_done));

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(1300, payload.getWritten()));
    try std.testing.expectEqual(@as(usize, 4), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 400), conn.bytesInFlight(.application));
    try std.testing.expectEqual(congestion_window_before, conn.congestionWindow(.application));
}

test "checkPtoTimeouts queues application PING and backs off PTO" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();

    _ = try conn.recordPacketSentInSpace(.application, 10, 100);
    try std.testing.expectEqual(@as(?i64, 335), conn.ptoDeadlineMillis(.application));

    try conn.checkPtoTimeouts(334);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 0), conn.recovery_state.pto_count);

    try conn.checkPtoTimeouts(335);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 1), conn.recovery_state.pto_count);

    var out_buf: [32]u8 = undefined;
    const payload = (try conn.pollTx(336, &out_buf)).?;
    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .ping => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 0), conn.pending_ping_count);
    try std.testing.expectEqual(@as(?i64, 986), conn.ptoDeadlineMillis(.application));

    try conn.receiveAckInSpace(.application, 400, .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 1,
    });
    try std.testing.expectEqual(@as(u8, 0), conn.recovery_state.pto_count);
    try std.testing.expectEqual(@as(?i64, null), conn.ptoDeadlineMillis(.application));
}

test "checkPtoTimeouts queues Initial and Handshake PING probes independently" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();

    _ = try conn.recordPacketSentInSpace(.initial, 10, 100);
    _ = try conn.recordPacketSentInSpace(.handshake, 20, 100);

    try std.testing.expectEqual(@as(?i64, 335), conn.ptoDeadlineMillis(.initial));
    try std.testing.expectEqual(@as(?i64, 345), conn.ptoDeadlineMillis(.handshake));

    try conn.checkPtoTimeouts(334);
    try std.testing.expectEqual(@as(usize, 0), conn.initial_packet_space.pending_ping_count);
    try std.testing.expectEqual(@as(usize, 0), conn.handshake_packet_space.pending_ping_count);

    try conn.checkPtoTimeouts(335);
    try std.testing.expectEqual(@as(usize, 1), conn.initial_packet_space.pending_ping_count);
    try std.testing.expectEqual(@as(usize, 0), conn.handshake_packet_space.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 1), conn.initial_packet_space.recovery_state.pto_count);

    var out_buf: [32]u8 = undefined;
    const initial_payload = (try conn.pollTxInSpace(.initial, 336, &out_buf)) orelse return error.TestUnexpectedResult;
    var initial_decoded = try frame.decodeFrameSlice(initial_payload, std.testing.allocator);
    defer frame.deinitFrame(&initial_decoded.frame, std.testing.allocator);
    switch (initial_decoded.frame) {
        .ping => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 0), conn.initial_packet_space.pending_ping_count);

    try conn.checkPtoTimeouts(345);
    try std.testing.expectEqual(@as(usize, 1), conn.handshake_packet_space.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 1), conn.handshake_packet_space.recovery_state.pto_count);

    const handshake_payload = (try conn.pollTxInSpace(.handshake, 346, &out_buf)) orelse return error.TestUnexpectedResult;
    var handshake_decoded = try frame.decodeFrameSlice(handshake_payload, std.testing.allocator);
    defer frame.deinitFrame(&handshake_decoded.frame, std.testing.allocator);
    switch (handshake_decoded.frame) {
        .ping => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 0), conn.handshake_packet_space.pending_ping_count);
}

test "checkPtoTimeouts is no-op when no application packet is in flight" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    try conn.checkPtoTimeouts(10_000);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 0), conn.recovery_state.pto_count);
}

test "packet number spaces isolate ACK recovery state" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    try std.testing.expectEqual(@as(u64, 0), try conn.recordPacketSentInSpace(.initial, 10, 100));
    try std.testing.expectEqual(@as(u64, 0), try conn.recordPacketSentInSpace(.application, 20, 200));

    try std.testing.expectEqual(@as(u64, 1), conn.nextPacketNumber(.initial));
    try std.testing.expectEqual(@as(u64, 0), conn.nextPacketNumber(.handshake));
    try std.testing.expectEqual(@as(u64, 1), conn.nextPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 1), conn.sentPacketCount(.initial));
    try std.testing.expectEqual(@as(usize, 1), conn.sentPacketCount(.application));

    var ack_buf: [32]u8 = undefined;
    var ack_out = buffer.fixedWriter(&ack_buf);
    try frame.encodeFrame(ack_out.writer(), .{ .ack = .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    } });

    try conn.processDatagramInSpace(.initial, 60, ack_out.getWritten());
    try std.testing.expectEqual(@as(usize, 0), conn.sentPacketCount(.initial));
    try std.testing.expectEqual(@as(usize, 1), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), conn.bytesInFlight(.initial));
    try std.testing.expectEqual(@as(usize, 200), conn.bytesInFlight(.application));

    try std.testing.expectError(error.InvalidPacket, conn.processDatagramInSpace(.handshake, 70, ack_out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.sentPacketCount(.initial));
    try std.testing.expectEqual(@as(usize, 1), conn.sentPacketCount(.application));
}

test "discardPacketNumberSpace clears Initial recovery and prevents reuse" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    _ = try conn.recordPacketSentInSpace(.initial, 300, 100);
    _ = try conn.recordPacketSentInSpace(.initial, 500, 100);
    _ = try conn.recordPacketSentInSpace(.application, 10, 200);
    try conn.sendCryptoInSpace(.initial, "queued crypto");
    try conn.receiveAckInSpace(.initial, 600, .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    var crypto_datagram: [32]u8 = undefined;
    var crypto_out = buffer.fixedWriter(&crypto_datagram);
    try frame.encodeFrame(crypto_out.writer(), .{ .crypto = .{
        .offset = 0,
        .data = "rx",
    } });
    try conn.processDatagramInSpace(.initial, 650, crypto_out.getWritten());
    try conn.queueAckForReceivedPacketInSpace(.initial);
    conn.initial_packet_space.recovery_state.pto_count = 2;

    try std.testing.expectEqual(@as(usize, 1), conn.sentPacketCount(.initial));
    try std.testing.expectEqual(@as(u64, 13), conn.initial_packet_space.crypto_send_offset);
    try std.testing.expectEqual(@as(usize, 1), conn.initial_packet_space.crypto_send_queue.items.len);
    try std.testing.expectEqual(@as(usize, 2), conn.initial_packet_space.crypto_recv_buffer.items.len);
    try std.testing.expectEqual(@as(?i64, 675), conn.lossDetectionDeadlineMillis(.initial));
    try std.testing.expectEqual(@as(?u64, 1), conn.pendingAckLargest(.initial));
    try std.testing.expectEqual(@as(usize, 100), conn.bytesInFlight(.initial));

    try conn.discardPacketNumberSpace(.initial);
    try std.testing.expect(conn.packetNumberSpaceDiscarded(.initial));
    try std.testing.expectEqual(@as(usize, 0), conn.sentPacketCount(.initial));
    try std.testing.expectEqual(@as(usize, 0), conn.bytesInFlight(.initial));
    try std.testing.expectEqual(@as(?i64, null), conn.lossDetectionDeadlineMillis(.initial));
    try std.testing.expectEqual(@as(?i64, null), conn.ptoDeadlineMillis(.initial));
    try std.testing.expectEqual(@as(?u64, null), conn.pendingAckLargest(.initial));
    try std.testing.expectEqual(@as(u8, 0), conn.initial_packet_space.recovery_state.pto_count);
    try std.testing.expectEqual(@as(u64, 0), conn.initial_packet_space.crypto_send_offset);
    try std.testing.expectEqual(@as(usize, 0), conn.initial_packet_space.crypto_send_queue.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.initial_packet_space.crypto_recv_buffer.items.len);
    try std.testing.expectEqual(@as(usize, 1), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 200), conn.bytesInFlight(.application));

    try conn.discardPacketNumberSpace(.initial);
    try std.testing.expectError(error.InvalidPacket, conn.recordPacketSentInSpace(.initial, 700, 100));
    try std.testing.expectError(error.InvalidPacket, conn.sendCryptoInSpace(.initial, "x"));
    try std.testing.expectError(error.InvalidPacket, conn.queueAckForReceivedPacketInSpace(.initial));
    const ping = [_]u8{@intFromEnum(frame.FrameType.ping)};
    try std.testing.expectError(error.InvalidPacket, conn.processDatagramInSpace(.initial, 700, &ping));
    try std.testing.expectError(error.InvalidPacket, conn.discardPacketNumberSpace(.application));
}

test "processInitialProtectedDatagram opens Initial packet into Initial space" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const secrets = try protection.deriveInitialSecrets(.v1, &dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try client.sendCryptoInSpace(.initial, "client initial");
    var payload_buf: [128]u8 = undefined;
    const payload = (try client.pollTxInSpace(.initial, 0, &payload_buf)) orelse return error.TestUnexpectedResult;

    const packet_number: u64 = 0;
    const protected = try protection.protectLongPacketAes128(std.testing.allocator, .{
        .version = .v1,
        .dcid = &dcid,
        .scid = &scid,
        .packet_type = .initial,
        .token = &[_]u8{},
        .packet_number = packet_number,
        .payload_length = 0,
    }, try packet.encodePacketNumberForHeader(packet_number, null), secrets.client, payload);
    defer std.testing.allocator.free(protected);

    try server.processInitialProtectedDatagram(1, secrets.client, protected);

    var crypto_buf: [32]u8 = undefined;
    const recv_len = (try server.recvCryptoInSpace(.initial, &crypto_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("client initial", crypto_buf[0..recv_len]);
    try std.testing.expectEqual(@as(u64, 1), server.nextPeerPacketNumber(.initial));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.initial));
}

test "processInitialProtectedDatagram rejects tampered packet without state changes" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const secrets = try protection.deriveInitialSecrets(.v1, &dcid);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    const protected = try protection.protectLongPacketAes128(std.testing.allocator, .{
        .version = .v1,
        .dcid = &dcid,
        .scid = &scid,
        .packet_type = .initial,
        .token = &[_]u8{},
        .packet_number = 0,
        .payload_length = 0,
    }, try packet.encodePacketNumberForHeader(0, null), secrets.client, "plaintext");
    defer std.testing.allocator.free(protected);

    const tampered = try std.testing.allocator.dupe(u8, protected);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;

    try std.testing.expectError(error.InvalidPacket, server.processInitialProtectedDatagram(1, secrets.client, tampered));
    try std.testing.expectEqual(@as(u64, 0), server.nextPeerPacketNumber(.initial));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.initial));
}

test "pollInitialProtectedDatagram emits protected Initial CRYPTO packet" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const secrets = try protection.deriveInitialSecrets(.v1, &dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try client.sendCryptoInSpace(.initial, "client initial");
    const protected = (try client.pollInitialProtectedDatagram(
        0,
        &dcid,
        &scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);

    try std.testing.expectEqual(@as(u64, 1), client.nextPacketNumber(.initial));
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.initial));
    try std.testing.expectEqual(protected.len, client.bytesInFlight(.initial));

    try server.processInitialProtectedDatagram(1, secrets.client, protected);
    var crypto_buf: [32]u8 = undefined;
    const recv_len = (try server.recvCryptoInSpace(.initial, &crypto_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("client initial", crypto_buf[0..recv_len]);
    try std.testing.expectEqual(@as(u64, 1), server.nextPeerPacketNumber(.initial));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.initial));
}

test "pollInitialProtectedDatagram leaves Initial space idle when no CRYPTO is queued" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const secrets = try protection.deriveInitialSecrets(.v1, &dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    try std.testing.expectEqual(@as(?[]u8, null), try client.pollInitialProtectedDatagram(
        0,
        &dcid,
        &scid,
        &[_]u8{},
        secrets.client,
    ));
    try std.testing.expectEqual(@as(u64, 0), client.nextPacketNumber(.initial));
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.initial));
}

test "packet number spaces reject frames forbidden by RFC 9000 packet type rules" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .ping = {} });
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 1,
        .offset = 0,
        .fin = false,
        .data = "x",
    } });

    try std.testing.expectError(error.InvalidPacket, conn.processDatagramInSpace(.initial, 0, out.getWritten()));
    try std.testing.expectEqual(@as(?u64, null), conn.pendingAckLargest(.initial));
    try std.testing.expectEqual(@as(u64, 0), conn.nextPeerPacketNumber(.initial));
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items.len);

    const handshake_done = [_]u8{@intFromEnum(frame.FrameType.handshake_done)};
    try std.testing.expectError(error.InvalidPacket, conn.processDatagramInSpace(.handshake, 1, &handshake_done));
    try std.testing.expect(!conn.handshakeConfirmed());
    try std.testing.expectEqual(@as(?u64, null), conn.pendingAckLargest(.handshake));
    try std.testing.expectEqual(@as(u64, 0), conn.nextPeerPacketNumber(.handshake));

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 1,
        .offset = 0,
        .fin = true,
        .data = "ok",
    } });

    try conn.processDatagramInSpace(.application, 2, out.getWritten());
    try std.testing.expectEqual(@as(?u64, 0), conn.pendingAckLargest(.application));
    try std.testing.expectEqual(@as(u64, 1), conn.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 1), conn.recv_streams.items.len);
}

test "0-RTT packet type shares Application packet number space but filters frames" {
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = true,
        .data = "early",
    } });

    try server.processDatagramForPacketType(.zero_rtt, 0, out.getWritten());
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.application));
    try std.testing.expectEqual(@as(u64, 1), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 1), server.recv_streams.items.len);

    const ping = [_]u8{@intFromEnum(frame.FrameType.ping)};
    try server.processDatagramForPacketType(.one_rtt, 1, &ping);
    try std.testing.expectEqual(@as(?u64, 1), server.pendingAckLargest(.application));
    try std.testing.expectEqual(@as(u64, 2), server.nextPeerPacketNumber(.application));
}

test "0-RTT packet type rejects forbidden frames and rolls back earlier state" {
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    var datagram: [96]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "early",
    } });
    try frame.encodeFrame(out.writer(), .{ .ack = .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    } });

    try std.testing.expectError(
        error.InvalidPacket,
        server.processDatagramForPacketType(.zero_rtt, 0, out.getWritten()),
    );
    try std.testing.expectEqual(@as(usize, 0), server.recv_streams.items.len);
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));
    try std.testing.expectEqual(@as(u64, 0), server.nextPeerPacketNumber(.application));

    try expectFramePacketTypeRejected(.zero_rtt, .{ .crypto = .{ .offset = 0, .data = "tls" } });
    try expectFramePacketTypeRejected(.zero_rtt, .{ .handshake_done = {} });
    try expectFramePacketTypeRejected(.zero_rtt, .{ .new_token = .{ .token = "token" } });
    try expectFramePacketTypeRejected(.zero_rtt, .{ .path_response = .{ .data = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 } } });
    try expectFramePacketTypeRejected(.zero_rtt, .{ .retire_connection_id = .{ .sequence_number = 0 } });
}

test "0-RTT packet type allows reset and stop-sending frames" {
    var reset_server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer reset_server.deinit();

    var reset_raw: [32]u8 = undefined;
    var reset_out = buffer.fixedWriter(&reset_raw);
    try frame.encodeFrame(reset_out.writer(), .{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = 7,
        .final_size = 0,
    } });

    try reset_server.processDatagramForPacketType(.zero_rtt, 0, reset_out.getWritten());
    try std.testing.expectEqual(@as(?u64, 0), reset_server.pendingAckLargest(.application));
    try std.testing.expectEqual(@as(u64, 1), reset_server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 1), reset_server.recv_streams.items.len);
    try std.testing.expectEqual(@as(?u64, 0), reset_server.recv_streams.items[0].final_size);
    try std.testing.expectEqual(@as(?u64, 7), reset_server.recv_streams.items[0].reset_error_code);

    var stop_server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer stop_server.deinit();

    var stop_raw: [32]u8 = undefined;
    var stop_out = buffer.fixedWriter(&stop_raw);
    try frame.encodeFrame(stop_out.writer(), .{ .stop_sending = .{
        .stream_id = 0,
        .application_error_code = 9,
    } });

    try stop_server.processDatagramForPacketType(.zero_rtt, 0, stop_out.getWritten());
    try std.testing.expectEqual(@as(?u64, 0), stop_server.pendingAckLargest(.application));
    try std.testing.expectEqual(@as(u64, 1), stop_server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 1), stop_server.pending_reset_streams.items.len);
    try std.testing.expectEqual(@as(u64, 0), stop_server.pending_reset_streams.items[0].stream_id);
    try std.testing.expectEqual(@as(u64, 9), stop_server.pending_reset_streams.items[0].application_error_code);
}

test "packet number spaces isolate receive-side ACK generation" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    const ping = [_]u8{@intFromEnum(frame.FrameType.ping)};
    try conn.processDatagramInSpace(.initial, 0, &ping);
    try conn.processDatagramInSpace(.handshake, 1, &ping);

    try std.testing.expectEqual(@as(?u64, 0), conn.pendingAckLargest(.initial));
    try std.testing.expectEqual(@as(?u64, 0), conn.pendingAckLargest(.handshake));
    try std.testing.expectEqual(@as(?u64, null), conn.pendingAckLargest(.application));
    try std.testing.expectEqual(@as(u64, 1), conn.nextPeerPacketNumber(.initial));
    try std.testing.expectEqual(@as(u64, 1), conn.nextPeerPacketNumber(.handshake));
    try std.testing.expectEqual(@as(u64, 0), conn.nextPeerPacketNumber(.application));

    try conn.processDatagram(2, &ping);
    try std.testing.expectEqual(@as(?u64, 0), conn.pendingAckLargest(.application));
    try std.testing.expectEqual(@as(u64, 1), conn.nextPeerPacketNumber(.application));
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
            .ect0_count = 0,
            .ect1_count = 0,
            .ecn_ce_count = 0,
        },
    } });

    try conn.processDatagram(60, ack_out.getWritten());

    try std.testing.expectEqual(@as(usize, 0), conn.sent_packets.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.recovery_state.bytes_in_flight);
    try std.testing.expectEqual(@as(?u64, 50), conn.recovery_state.latest_rtt_ms);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
    try std.testing.expectEqual(EcnValidationState.unknown, conn.ecnValidationState(.application));
}

test "ACK_ECN validates ECT0 counters for modeled sent packets" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    try std.testing.expectEqual(@as(u64, 0), try conn.recordEcnPacketSentInSpace(.application, 10, 100, .ect0));
    try std.testing.expectEqual(@as(usize, 100), conn.bytesInFlight(.application));

    try conn.receiveAckEcnInSpace(.application, 60, .{
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
    });

    try std.testing.expectEqual(@as(usize, 0), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), conn.bytesInFlight(.application));
    try std.testing.expectEqual(EcnValidationState.capable, conn.ecnValidationState(.application));
    try std.testing.expectEqual(@as(u64, 1), conn.ecnCounts(.application).ect0_count);
}

test "regular ACK disables ECN validation for newly acknowledged ECT packet" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    _ = try conn.recordEcnPacketSentInSpace(.application, 10, 100, .ect0);

    try conn.receiveAckInSpace(.application, 60, .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    try std.testing.expectEqual(@as(usize, 0), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), conn.bytesInFlight(.application));
    try std.testing.expectEqual(EcnValidationState.failed, conn.ecnValidationState(.application));
}

test "ACK_ECN disables validation when counters do not cover newly acknowledged ECT packets" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    _ = try conn.recordEcnPacketSentInSpace(.application, 10, 100, .ect0);

    try conn.receiveAckEcnInSpace(.application, 60, .{
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
    });

    try std.testing.expectEqual(EcnValidationState.failed, conn.ecnValidationState(.application));
    try std.testing.expectEqual(@as(usize, 0), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), conn.bytesInFlight(.application));
}

test "ACK_ECN disables validation when counters exceed sent ECT totals" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    _ = try conn.recordPacketSentInSpace(.application, 10, 100);

    try conn.receiveAckEcnInSpace(.application, 60, .{
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
    });

    try std.testing.expectEqual(EcnValidationState.failed, conn.ecnValidationState(.application));
}

test "ACK_ECN reordered ACK does not fail validation when largest ack does not increase" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    _ = try conn.recordEcnPacketSentInSpace(.application, 10, 100, .ect0);
    _ = try conn.recordEcnPacketSentInSpace(.application, 20, 100, .ect0);

    try conn.receiveAckEcnInSpace(.application, 70, .{
        .ack = .{
            .largest_acknowledged = 1,
            .ack_delay = 0,
            .first_ack_range = 0,
        },
        .ecn_counts = .{
            .ect0_count = 1,
            .ect1_count = 0,
            .ecn_ce_count = 0,
        },
    });
    try std.testing.expectEqual(EcnValidationState.capable, conn.ecnValidationState(.application));

    try conn.receiveAckEcnInSpace(.application, 80, .{
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
    });

    try std.testing.expectEqual(EcnValidationState.capable, conn.ecnValidationState(.application));
    try std.testing.expectEqual(@as(usize, 0), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), conn.bytesInFlight(.application));
}

test "processDatagram rolls back ECN validation state when later frame is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();
    try conn.validatePeerAddress();

    _ = try conn.recordEcnPacketSentInSpace(.application, 10, 100, .ect0);

    var payload_buf: [64]u8 = undefined;
    var payload = buffer.fixedWriter(&payload_buf);
    try frame.encodeFrame(payload.writer(), .{ .ack_ecn = .{
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
    try payload.writer().writeByte(@intFromEnum(frame.FrameType.handshake_done));

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(60, payload.getWritten()));
    try std.testing.expectEqual(EcnValidationState.unknown, conn.ecnValidationState(.application));
    try std.testing.expectEqual(@as(u64, 0), conn.ecnCounts(.application).ect0_count);
    try std.testing.expectEqual(@as(usize, 1), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 100), conn.bytesInFlight(.application));
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
    try server.validatePeerAddress();

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
    try server.validatePeerAddress();

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

test "processDatagram rejects PATH_RESPONSE without outstanding challenge" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .path_challenge = .{ .data = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 } } });
    try frame.encodeFrame(out.writer(), .{ .path_response = .{ .data = [_]u8{ 7, 6, 5, 4, 3, 2, 1, 0 } } });

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_path_responses.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 0), conn.next_peer_packet_number);
}

test "sendPathChallenge emits challenge and accepts matching PATH_RESPONSE" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const challenge_data = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };
    try conn.sendPathChallenge(challenge_data);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_path_challenges.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.outstanding_path_challenges.items.len);

    var out_buf: [64]u8 = undefined;
    const challenge_payload = (try conn.pollTx(10, &out_buf)).?;
    try std.testing.expectEqual(@as(usize, 0), conn.pending_path_challenges.items.len);
    try std.testing.expectEqual(@as(usize, 1), conn.outstanding_path_challenges.items.len);
    try std.testing.expectEqualSlices(u8, &challenge_data, &conn.outstanding_path_challenges.items[0].data);
    try std.testing.expectEqual(@as(usize, 1), conn.sent_packets.items.len);

    var challenge = try frame.decodeFrameSlice(challenge_payload, std.testing.allocator);
    defer frame.deinitFrame(&challenge.frame, std.testing.allocator);
    switch (challenge.frame) {
        .path_challenge => |path_challenge| try std.testing.expectEqualSlices(u8, &challenge_data, &path_challenge.data),
        else => return error.TestUnexpectedResult,
    }

    var response_buf: [16]u8 = undefined;
    var response_out = buffer.fixedWriter(&response_buf);
    try frame.encodeFrame(response_out.writer(), .{ .path_response = .{ .data = challenge_data } });

    try conn.processDatagram(20, response_out.getWritten());
    try std.testing.expectEqual(@as(usize, 0), conn.outstanding_path_challenges.items.len);
    try std.testing.expectEqual(@as(?u64, 0), conn.pending_ack_largest);

    const ack_payload = (try conn.pollTx(30, &out_buf)).?;
    var ack = try frame.decodeFrameSlice(ack_payload, std.testing.allocator);
    defer frame.deinitFrame(&ack.frame, std.testing.allocator);
    switch (ack.frame) {
        .ack => |ack_frame| try std.testing.expectEqual(@as(u64, 0), ack_frame.largest_acknowledged),
        else => return error.TestUnexpectedResult,
    }
}

test "processDatagram rejects duplicate or mismatched PATH_RESPONSE" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const challenge_data = [_]u8{ 1, 3, 5, 7, 9, 11, 13, 15 };
    try conn.sendPathChallenge(challenge_data);

    var out_buf: [64]u8 = undefined;
    _ = (try conn.pollTx(0, &out_buf)).?;

    var mismatch_buf: [16]u8 = undefined;
    var mismatch_out = buffer.fixedWriter(&mismatch_buf);
    try frame.encodeFrame(mismatch_out.writer(), .{ .path_response = .{ .data = [_]u8{ 15, 13, 11, 9, 7, 5, 3, 1 } } });

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(10, mismatch_out.getWritten()));
    try std.testing.expectEqual(@as(usize, 1), conn.outstanding_path_challenges.items.len);
    try std.testing.expectEqualSlices(u8, &challenge_data, &conn.outstanding_path_challenges.items[0].data);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 0), conn.next_peer_packet_number);

    var response_buf: [16]u8 = undefined;
    var response_out = buffer.fixedWriter(&response_buf);
    try frame.encodeFrame(response_out.writer(), .{ .path_response = .{ .data = challenge_data } });

    try conn.processDatagram(20, response_out.getWritten());
    try std.testing.expectEqual(@as(usize, 0), conn.outstanding_path_challenges.items.len);
    try std.testing.expectEqual(@as(?u64, 0), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 1), conn.next_peer_packet_number);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(30, response_out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.outstanding_path_challenges.items.len);
    try std.testing.expectEqual(@as(?u64, 0), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 1), conn.next_peer_packet_number);
}

test "processDatagram rolls back matched PATH_RESPONSE when later frame is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const challenge_data = [_]u8{ 0, 2, 4, 6, 8, 10, 12, 14 };
    try conn.sendPathChallenge(challenge_data);

    var out_buf: [64]u8 = undefined;
    _ = (try conn.pollTx(0, &out_buf)).?;
    try std.testing.expectEqual(@as(usize, 1), conn.outstanding_path_challenges.items.len);
    try std.testing.expectEqual(@as(i64, 0), conn.outstanding_path_challenges.items[0].sent_time_millis);
    try std.testing.expectEqual(@as(u8, 1), conn.outstanding_path_challenges.items[0].transmissions);

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .path_response = .{ .data = challenge_data } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(10, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 1), conn.outstanding_path_challenges.items.len);
    try std.testing.expectEqualSlices(u8, &challenge_data, &conn.outstanding_path_challenges.items[0].data);
    try std.testing.expectEqual(@as(i64, 0), conn.outstanding_path_challenges.items[0].sent_time_millis);
    try std.testing.expectEqual(@as(u8, 1), conn.outstanding_path_challenges.items[0].transmissions);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 0), conn.next_peer_packet_number);
}

test "path challenge timeout retries then records validation failure" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const challenge_data = [_]u8{ 9, 8, 7, 6, 5, 4, 3, 2 };
    try conn.sendPathChallenge(challenge_data);
    try std.testing.expectEqual(@as(usize, 1), conn.pendingPathChallengeCount());
    try std.testing.expectEqual(@as(usize, 0), conn.outstandingPathChallengeCount());

    var out_buf: [64]u8 = undefined;
    _ = (try conn.pollTx(0, &out_buf)).?;
    try std.testing.expectEqual(@as(usize, 0), conn.pendingPathChallengeCount());
    try std.testing.expectEqual(@as(usize, 1), conn.outstandingPathChallengeCount());
    try std.testing.expectEqual(@as(u8, 1), conn.outstanding_path_challenges.items[0].transmissions);

    try conn.checkPathValidationTimeouts(saturatingAddMillis(0, conn.recovery_state.ptoMs() - 1));
    try std.testing.expectEqual(@as(usize, 0), conn.pendingPathChallengeCount());
    try std.testing.expectEqual(@as(usize, 1), conn.outstandingPathChallengeCount());

    try conn.checkPathValidationTimeouts(saturatingAddMillis(0, conn.recovery_state.ptoMs()));
    try std.testing.expectEqual(@as(usize, 1), conn.pendingPathChallengeCount());
    try std.testing.expectEqual(@as(usize, 0), conn.outstandingPathChallengeCount());
    try std.testing.expectEqual(@as(usize, 0), conn.failedPathValidationCount());

    _ = (try conn.pollTx(1000, &out_buf)).?;
    try std.testing.expectEqual(@as(usize, 0), conn.pendingPathChallengeCount());
    try std.testing.expectEqual(@as(usize, 1), conn.outstandingPathChallengeCount());
    try std.testing.expectEqual(@as(u8, 2), conn.outstanding_path_challenges.items[0].transmissions);
    try std.testing.expectEqualSlices(u8, &challenge_data, &conn.outstanding_path_challenges.items[0].data);

    try conn.checkPathValidationTimeouts(saturatingAddMillis(1000, conn.recovery_state.ptoMs()));
    try std.testing.expectEqual(@as(usize, 1), conn.pendingPathChallengeCount());
    try std.testing.expectEqual(@as(usize, 0), conn.outstandingPathChallengeCount());

    _ = (try conn.pollTx(2000, &out_buf)).?;
    try std.testing.expectEqual(@as(u8, 3), conn.outstanding_path_challenges.items[0].transmissions);

    try conn.checkPathValidationTimeouts(saturatingAddMillis(2000, conn.recovery_state.ptoMs()));
    try std.testing.expectEqual(@as(usize, 0), conn.pendingPathChallengeCount());
    try std.testing.expectEqual(@as(usize, 0), conn.outstandingPathChallengeCount());
    try std.testing.expectEqual(@as(usize, 1), conn.failedPathValidationCount());
}

test "pollTx automatically retries timed-out path challenge" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const challenge_data = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 };
    try conn.sendPathChallenge(challenge_data);

    var out_buf: [64]u8 = undefined;
    _ = (try conn.pollTx(0, &out_buf)).?;
    const retry_at = saturatingAddMillis(0, conn.recovery_state.ptoMs());
    const retry_payload = (try conn.pollTx(retry_at, &out_buf)).?;

    try std.testing.expectEqual(@as(usize, 0), conn.pendingPathChallengeCount());
    try std.testing.expectEqual(@as(usize, 1), conn.outstandingPathChallengeCount());
    try std.testing.expectEqual(@as(u8, 2), conn.outstanding_path_challenges.items[0].transmissions);

    var decoded = try frame.decodeFrameSlice(retry_payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .path_challenge => |path_challenge| try std.testing.expectEqualSlices(u8, &challenge_data, &path_challenge.data),
        else => return error.TestUnexpectedResult,
    }
}

test "issueConnectionId emits NEW_CONNECTION_ID and accepts peer retirement" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();
    try conn.validatePeerAddress();

    const cid = [_]u8{ 0xc0, 0xff, 0xee, 0x01 };
    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    try std.testing.expectEqual(@as(u64, 0), try conn.issueConnectionId(&cid, token, 0));
    try std.testing.expectEqual(@as(u64, 1), conn.localConnectionIdCount());
    try std.testing.expectEqual(@as(usize, 1), conn.pendingNewConnectionIdCount());

    var tx: [64]u8 = undefined;
    const payload = (try conn.pollTx(0, &tx)).?;
    try std.testing.expectEqual(@as(usize, 0), conn.pendingNewConnectionIdCount());
    try std.testing.expect(conn.local_connection_ids.items[0].sent);

    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .new_connection_id => |new_connection_id| {
            try std.testing.expectEqual(@as(u64, 0), new_connection_id.sequence_number);
            try std.testing.expectEqual(@as(u64, 0), new_connection_id.retire_prior_to);
            try std.testing.expectEqualSlices(u8, &cid, new_connection_id.connection_id);
            try std.testing.expectEqualSlices(u8, &token, &new_connection_id.stateless_reset_token);
        },
        else => return error.TestUnexpectedResult,
    }

    var retire_buf: [16]u8 = undefined;
    var retire_out = buffer.fixedWriter(&retire_buf);
    try frame.encodeFrame(retire_out.writer(), .{ .retire_connection_id = .{ .sequence_number = 0 } });

    try conn.processDatagram(10, retire_out.getWritten());
    try std.testing.expectEqual(@as(u64, 0), conn.localConnectionIdCount());
    try std.testing.expect(conn.local_connection_ids.items[0].retired);
    try std.testing.expectEqual(@as(?u64, 0), conn.pending_ack_largest);
}

test "issueConnectionId rejects duplicates and peer active id limit overflow" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const cid0 = [_]u8{ 0, 1, 2, 3 };
    const cid1 = [_]u8{ 4, 5, 6, 7 };
    const cid2 = [_]u8{ 8, 9, 10, 11 };

    try std.testing.expectEqual(@as(u64, 0), try conn.issueConnectionId(&cid0, token, 0));
    try std.testing.expectError(error.InvalidPacket, conn.issueConnectionId(&cid0, token, 0));
    try std.testing.expectEqual(@as(u64, 1), try conn.issueConnectionId(&cid1, token, 0));
    try std.testing.expectError(error.InvalidPacket, conn.issueConnectionId(&cid2, token, 0));
    try std.testing.expectEqual(@as(u64, 2), conn.localConnectionIdCount());
}

test "RETIRE_CONNECTION_ID rejects unknown or unsent local ids" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    try std.testing.expectEqual(@as(u64, 0), try conn.issueConnectionId(&cid, token, 0));

    var retire_buf: [16]u8 = undefined;
    var retire_out = buffer.fixedWriter(&retire_buf);
    try frame.encodeFrame(retire_out.writer(), .{ .retire_connection_id = .{ .sequence_number = 0 } });

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, retire_out.getWritten()));
    try std.testing.expectEqual(@as(u64, 1), conn.localConnectionIdCount());
    try std.testing.expect(!conn.local_connection_ids.items[0].retired);

    retire_out = buffer.fixedWriter(&retire_buf);
    try frame.encodeFrame(retire_out.writer(), .{ .retire_connection_id = .{ .sequence_number = 9 } });
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(1, retire_out.getWritten()));
}

test "RETIRE_CONNECTION_ID rolls back local retirement when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();
    try conn.validatePeerAddress();

    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const cid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    try std.testing.expectEqual(@as(u64, 0), try conn.issueConnectionId(&cid, token, 0));

    var tx: [64]u8 = undefined;
    _ = (try conn.pollTx(0, &tx)).?;
    try std.testing.expect(conn.local_connection_ids.items[0].sent);

    var datagram: [24]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .retire_connection_id = .{ .sequence_number = 0 } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(10, out.getWritten()));
    try std.testing.expectEqual(@as(u64, 1), conn.localConnectionIdCount());
    try std.testing.expect(!conn.local_connection_ids.items[0].retired);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 0), conn.next_peer_packet_number);
}

test "NEW_CONNECTION_ID tracks active peer ids and queues RETIRE_CONNECTION_ID" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const cid0 = [_]u8{ 0xaa, 0xbb, 0xcc, 0x00 };
    const cid1 = [_]u8{ 0xaa, 0xbb, 0xcc, 0x01 };
    const token0 = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const token1 = [_]u8{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

    var datagram: [96]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = &cid0,
        .stateless_reset_token = token0,
    } });
    try conn.processDatagram(10, out.getWritten());
    try std.testing.expectEqual(@as(usize, 1), conn.active_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 1), conn.activeConnectionIdCount());
    try std.testing.expectEqual(@as(usize, 0), conn.pending_retire_connection_ids.items.len);

    var tx: [64]u8 = undefined;
    _ = (try conn.pollTx(20, &tx)).?;

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 1,
        .connection_id = &cid1,
        .stateless_reset_token = token1,
    } });
    try conn.processDatagram(30, out.getWritten());
    try std.testing.expectEqual(@as(usize, 2), conn.active_connection_ids.items.len);
    try std.testing.expect(conn.active_connection_ids.items[0].retired);
    try std.testing.expect(!conn.active_connection_ids.items[1].retired);
    try std.testing.expectEqual(@as(u64, 1), conn.activeConnectionIdCount());
    try std.testing.expectEqual(@as(usize, 1), conn.pending_retire_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 0), conn.pending_retire_connection_ids.items[0]);

    const retire_payload = (try conn.pollTx(40, &tx)).?;
    var ack = try frame.decodeFrameSlice(retire_payload, std.testing.allocator);
    defer frame.deinitFrame(&ack.frame, std.testing.allocator);
    switch (ack.frame) {
        .ack => |ack_frame| try std.testing.expectEqual(@as(u64, 1), ack_frame.largest_acknowledged),
        else => return error.TestUnexpectedResult,
    }

    var retire = try frame.decodeFrameSlice(retire_payload[ack.len..], std.testing.allocator);
    defer frame.deinitFrame(&retire.frame, std.testing.allocator);
    switch (retire.frame) {
        .retire_connection_id => |retire_frame| try std.testing.expectEqual(@as(u64, 0), retire_frame.sequence_number),
        else => return error.TestUnexpectedResult,
    }
}

test "NEW_CONNECTION_ID enforces active id limit and duplicate consistency" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const cid0 = [_]u8{ 0xc0, 0, 0, 0 };
    const cid1 = [_]u8{ 0xc0, 0, 0, 1 };
    const cid2 = [_]u8{ 0xc0, 0, 0, 2 };
    const cid0_mismatch = [_]u8{ 0xee, 0, 0, 0 };

    var datagram: [96]u8 = undefined;
    var tx: [64]u8 = undefined;

    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = &cid0,
        .stateless_reset_token = token,
    } });
    try conn.processDatagram(0, out.getWritten());
    _ = (try conn.pollTx(0, &tx)).?;

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = &cid0,
        .stateless_reset_token = token,
    } });
    try conn.processDatagram(1, out.getWritten());
    try std.testing.expectEqual(@as(usize, 1), conn.active_connection_ids.items.len);
    _ = (try conn.pollTx(1, &tx)).?;

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = &cid0_mismatch,
        .stateless_reset_token = token,
    } });
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(2, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 1), conn.active_connection_ids.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = &cid1,
        .stateless_reset_token = token,
    } });
    try conn.processDatagram(3, out.getWritten());
    _ = (try conn.pollTx(3, &tx)).?;
    try std.testing.expectEqual(@as(u64, 2), conn.activeConnectionIdCount());

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 2,
        .retire_prior_to = 0,
        .connection_id = &cid2,
        .stateless_reset_token = token,
    } });
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(4, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 2), conn.active_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 2), conn.activeConnectionIdCount());
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
}

test "NEW_CONNECTION_ID retire_prior_to rolls back when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const cid0 = [_]u8{ 0xd0, 0, 0, 0 };
    const cid1 = [_]u8{ 0xd0, 0, 0, 1 };

    var datagram: [96]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = &cid0,
        .stateless_reset_token = token,
    } });
    try conn.processDatagram(0, out.getWritten());

    var tx: [64]u8 = undefined;
    _ = (try conn.pollTx(0, &tx)).?;

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 1,
        .connection_id = &cid1,
        .stateless_reset_token = token,
    } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(1, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 1), conn.active_connection_ids.items.len);
    try std.testing.expect(!conn.active_connection_ids.items[0].retired);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_retire_connection_ids.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 1), conn.next_peer_packet_number);
}

test "detectStatelessReset matches active peer-issued reset token" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    var frame_buf: [64]u8 = undefined;
    var frame_out = buffer.fixedWriter(&frame_buf);
    try frame.encodeFrame(frame_out.writer(), .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = &cid,
        .stateless_reset_token = token,
    } });
    try conn.processDatagram(0, frame_out.getWritten());

    var reset_buf: [packet.min_stateless_reset_datagram_len]u8 = undefined;
    var reset_out = buffer.fixedWriter(&reset_buf);
    try packet.encodeStatelessReset(reset_out.writer(), &[_]u8{ 0x40, 0xaa, 0xbb, 0xcc, 0xdd }, token);

    try std.testing.expectEqual(@as(?u64, 0), conn.detectStatelessReset(reset_out.getWritten()));
    try std.testing.expectEqual(@as(?u64, null), conn.detectStatelessReset(reset_out.getWritten()[0..4]));

    const other = [_]u8{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    reset_out = buffer.fixedWriter(&reset_buf);
    try packet.encodeStatelessReset(reset_out.writer(), &[_]u8{ 0x40, 0xaa, 0xbb, 0xcc, 0xdd }, other);
    try std.testing.expectEqual(@as(?u64, null), conn.detectStatelessReset(reset_out.getWritten()));
}

test "detectStatelessReset ignores retired peer-issued reset tokens" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{ .active_connection_id_limit = 3 });
    defer conn.deinit();

    const cid0 = [_]u8{ 0xaa, 0xbb, 0xcc, 0x00 };
    const cid1 = [_]u8{ 0xaa, 0xbb, 0xcc, 0x01 };
    const token0 = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const token1 = [_]u8{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    var datagram: [96]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = &cid0,
        .stateless_reset_token = token0,
    } });
    try frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 1,
        .connection_id = &cid1,
        .stateless_reset_token = token1,
    } });
    try conn.processDatagram(0, out.getWritten());
    try std.testing.expect(conn.active_connection_ids.items[0].retired);

    var reset_buf: [packet.min_stateless_reset_datagram_len]u8 = undefined;
    var reset_out = buffer.fixedWriter(&reset_buf);
    try packet.encodeStatelessReset(reset_out.writer(), &[_]u8{ 0x40, 0xaa, 0xbb, 0xcc, 0xdd }, token0);
    try std.testing.expectEqual(@as(?u64, null), conn.detectStatelessReset(reset_out.getWritten()));

    reset_out = buffer.fixedWriter(&reset_buf);
    try packet.encodeStatelessReset(reset_out.writer(), &[_]u8{ 0x40, 0xaa, 0xbb, 0xcc, 0xdd }, token1);
    try std.testing.expectEqual(@as(?u64, 1), conn.detectStatelessReset(reset_out.getWritten()));
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

test "resetStream queues RESET_STREAM and drops unsent stream data" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "hello", false);
    try conn.resetStream(stream_id, 7);

    try std.testing.expect(conn.findSendStream(stream_id).?.reset_sent);
    try std.testing.expectError(error.StreamClosed, conn.sendOnStream(stream_id, "again", false));
    try std.testing.expectEqual(@as(usize, 1), conn.pending_reset_streams.items.len);

    var out_buf: [64]u8 = undefined;
    const reset_payload = (try conn.pollTx(20, &out_buf)).?;

    var reset = try frame.decodeFrameSlice(reset_payload, std.testing.allocator);
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

test "resetStream can abort an observed peer bidirectional stream" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();
    try conn.validatePeerAddress();

    var stream_buf: [32]u8 = undefined;
    var stream_out = buffer.fixedWriter(&stream_buf);
    try frame.encodeFrame(stream_out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = "hello",
        .fin = false,
    } });
    try conn.processDatagram(0, stream_out.getWritten());

    try conn.resetStream(0, 9);
    try std.testing.expectError(error.StreamClosed, conn.sendOnStream(0, "reply", false));
    try std.testing.expectEqual(@as(usize, 1), conn.pending_reset_streams.items.len);

    var out_buf: [64]u8 = undefined;
    const reset_payload = (try conn.pollTx(10, &out_buf)).?;

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

test "resetStream validates stream direction, state, and application error code" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    try std.testing.expectError(error.InvalidStream, conn.resetStream(0, 1));
    try std.testing.expectError(error.InvalidStream, conn.resetStream(3, 1));

    const stream_id = try conn.openStream();
    try std.testing.expectError(error.InvalidPacket, conn.resetStream(stream_id, max_quic_varint + 1));
    try std.testing.expect(!conn.findSendStream(stream_id).?.reset_sent);

    const uni_stream_id = try conn.openUniStream();
    try conn.resetStream(uni_stream_id, 2);
    try std.testing.expect(conn.findSendStream(uni_stream_id).?.reset_sent);
}

test "duplicate resetStream does not queue duplicate RESET_STREAM" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.resetStream(stream_id, 1);
    try conn.resetStream(stream_id, 2);

    try std.testing.expectEqual(@as(usize, 1), conn.pending_reset_streams.items.len);
    try std.testing.expectEqual(@as(u64, 1), conn.pending_reset_streams.items[0].application_error_code);
}

test "stopSending queues STOP_SENDING and peer responds with RESET_STREAM" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello", false);

    var datagram: [128]u8 = undefined;
    try server.processDatagram(10, (try client.pollTx(0, &datagram)).?);
    try server.stopSending(stream_id, 11);
    try std.testing.expectEqual(@as(usize, 1), server.pending_stop_sending.items.len);

    const stop_payload = (try server.pollTx(20, &datagram)).?;
    var ack = try frame.decodeFrameSlice(stop_payload, std.testing.allocator);
    defer frame.deinitFrame(&ack.frame, std.testing.allocator);
    switch (ack.frame) {
        .ack => |ack_frame| try std.testing.expectEqual(@as(u64, 0), ack_frame.largest_acknowledged),
        else => return error.TestUnexpectedResult,
    }

    var stop = try frame.decodeFrameSlice(stop_payload[ack.len..], std.testing.allocator);
    defer frame.deinitFrame(&stop.frame, std.testing.allocator);
    switch (stop.frame) {
        .stop_sending => |stop_frame| {
            try std.testing.expectEqual(stream_id, stop_frame.stream_id);
            try std.testing.expectEqual(@as(u64, 11), stop_frame.application_error_code);
        },
        else => return error.TestUnexpectedResult,
    }

    try client.processDatagram(30, stop_payload);
    try std.testing.expect(client.findSendStream(stream_id).?.reset_sent);
    try std.testing.expectError(error.StreamClosed, client.sendOnStream(stream_id, "again", false));

    const reset_payload = (try client.pollTx(40, &datagram)).?;
    var reset_ack = try frame.decodeFrameSlice(reset_payload, std.testing.allocator);
    defer frame.deinitFrame(&reset_ack.frame, std.testing.allocator);
    switch (reset_ack.frame) {
        .ack => |ack_frame| try std.testing.expectEqual(@as(u64, 0), ack_frame.largest_acknowledged),
        else => return error.TestUnexpectedResult,
    }

    var reset = try frame.decodeFrameSlice(reset_payload[reset_ack.len..], std.testing.allocator);
    defer frame.deinitFrame(&reset.frame, std.testing.allocator);
    switch (reset.frame) {
        .reset_stream => |reset_frame| {
            try std.testing.expectEqual(stream_id, reset_frame.stream_id);
            try std.testing.expectEqual(@as(u64, 11), reset_frame.application_error_code);
            try std.testing.expectEqual(@as(u64, 5), reset_frame.final_size);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "stopSending validates receive-side direction and stream state" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    try std.testing.expectError(error.InvalidStream, conn.stopSending(0, 1));
    try std.testing.expectError(error.InvalidStream, conn.stopSending(1, 1));
    try std.testing.expectError(error.InvalidStream, conn.stopSending(3, 1));

    const stream_id = try conn.openStream();
    try std.testing.expectError(error.InvalidPacket, conn.stopSending(stream_id, max_quic_varint + 1));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_stop_sending.items.len);

    try conn.stopSending(stream_id, 2);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_stop_sending.items.len);
    try std.testing.expect(conn.findRecvStream(stream_id).?.stop_sending_sent);

    var out_buf: [32]u8 = undefined;
    const payload = (try conn.pollTx(0, &out_buf)).?;
    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .stop_sending => |stop_frame| {
            try std.testing.expectEqual(stream_id, stop_frame.stream_id);
            try std.testing.expectEqual(@as(u64, 2), stop_frame.application_error_code);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "duplicate stopSending does not queue duplicate STOP_SENDING" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.stopSending(stream_id, 1);
    try conn.stopSending(stream_id, 2);

    try std.testing.expectEqual(@as(usize, 1), conn.pending_stop_sending.items.len);
    try std.testing.expectEqual(@as(u64, 1), conn.pending_stop_sending.items[0].application_error_code);
}

test "stopSending rejects receive stream after RESET_STREAM" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var reset_buf: [16]u8 = undefined;
    var reset_out = buffer.fixedWriter(&reset_buf);
    try frame.encodeFrame(reset_out.writer(), .{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = 7,
        .final_size = 0,
    } });
    try conn.processDatagram(0, reset_out.getWritten());

    try std.testing.expectError(error.StreamClosed, conn.stopSending(0, 1));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_stop_sending.items.len);
}

test "STOP_SENDING on peer bidirectional stream prevents later reply" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();
    try conn.validatePeerAddress();

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
    try server.validatePeerAddress();

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
    try server.validatePeerAddress();

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
    try std.testing.expectEqual(@as(?u64, 5), try conn.recvStreamFinalSize(0));
    try std.testing.expect(!try conn.recvStreamFinished(0));

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
    try std.testing.expectError(error.InvalidStream, conn.recvStreamFinalSize(stream_id));
    try std.testing.expectError(error.InvalidStream, conn.recvStreamFinished(stream_id));
}

test "client accepts HANDSHAKE_DONE and queues ACK" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const payload = [_]u8{@intFromEnum(frame.FrameType.handshake_done)};
    try conn.processDatagram(0, &payload);

    try std.testing.expect(conn.handshakeConfirmed());
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

test "HANDSHAKE_DONE state rolls back when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const payload = [_]u8{
        @intFromEnum(frame.FrameType.handshake_done),
        0xff,
    };
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, &payload));
    try std.testing.expect(!conn.handshakeConfirmed());
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 0), conn.next_peer_packet_number);
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

test "client stores NEW_TOKEN and queues ACK" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    var token_buf: [32]u8 = undefined;
    var token_out = buffer.fixedWriter(&token_buf);
    try frame.encodeFrame(token_out.writer(), .{ .new_token = .{ .token = "future" } });

    try conn.processDatagram(0, token_out.getWritten());
    try std.testing.expectEqual(@as(?u64, 0), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(usize, 1), conn.stored_new_tokens.items.len);
    try std.testing.expectEqualStrings("future", conn.latestNewToken().?);

    var out_buf: [16]u8 = undefined;
    const ack_payload = (try conn.pollTx(0, &out_buf)).?;
    var decoded = try frame.decodeFrameSlice(ack_payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);

    switch (decoded.frame) {
        .ack => |ack| try std.testing.expectEqual(@as(u64, 0), ack.largest_acknowledged),
        else => return error.TestUnexpectedResult,
    }
}

test "client stores NEW_TOKEN values up to configured limit" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{ .max_stored_new_tokens = 2 });
    defer conn.deinit();

    var token_buf: [64]u8 = undefined;
    var token_out = buffer.fixedWriter(&token_buf);
    try frame.encodeFrame(token_out.writer(), .{ .new_token = .{ .token = "one" } });
    try conn.processDatagram(0, token_out.getWritten());

    token_out = buffer.fixedWriter(&token_buf);
    try frame.encodeFrame(token_out.writer(), .{ .new_token = .{ .token = "two" } });
    try conn.processDatagram(1, token_out.getWritten());

    token_out = buffer.fixedWriter(&token_buf);
    try frame.encodeFrame(token_out.writer(), .{ .new_token = .{ .token = "three" } });
    try conn.processDatagram(2, token_out.getWritten());

    try std.testing.expectEqual(@as(usize, 2), conn.stored_new_tokens.items.len);
    try std.testing.expectEqualStrings("one", conn.stored_new_tokens.items[0]);
    try std.testing.expectEqualStrings("two", conn.latestNewToken().?);
}

test "server rejects NEW_TOKEN from peer" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var token_buf: [32]u8 = undefined;
    var token_out = buffer.fixedWriter(&token_buf);
    try frame.encodeFrame(token_out.writer(), .{ .new_token = .{ .token = "future" } });

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, token_out.getWritten()));
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 0), conn.next_peer_packet_number);
    try std.testing.expectEqual(@as(usize, 0), conn.stored_new_tokens.items.len);

    var out_buf: [16]u8 = undefined;
    try std.testing.expectEqual(@as(?[]u8, null), try conn.pollTx(0, &out_buf));
}

test "NEW_TOKEN storage rolls back when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    var token_buf: [64]u8 = undefined;
    var token_out = buffer.fixedWriter(&token_buf);
    try frame.encodeFrame(token_out.writer(), .{ .new_token = .{ .token = "stable" } });
    try conn.processDatagram(0, token_out.getWritten());
    try std.testing.expectEqualStrings("stable", conn.latestNewToken().?);

    token_out = buffer.fixedWriter(&token_buf);
    try frame.encodeFrame(token_out.writer(), .{ .new_token = .{ .token = "rollback" } });
    try token_out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(1, token_out.getWritten()));
    try std.testing.expectEqual(@as(usize, 1), conn.stored_new_tokens.items.len);
    try std.testing.expectEqualStrings("stable", conn.latestNewToken().?);
    try std.testing.expectEqual(@as(?u64, 0), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 1), conn.next_peer_packet_number);
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
    try std.testing.expectEqual(ConnectionState.draining, conn.connectionState());
    try std.testing.expect(conn.closeDeadlineMillis().? > 0);

    var out_buf: [32]u8 = undefined;
    try std.testing.expectError(error.ConnectionClosed, conn.pollTx(0, &out_buf));
    try std.testing.expectError(error.ConnectionClosed, conn.openStream());
    try std.testing.expectError(error.ConnectionClosed, conn.openUniStream());
    try std.testing.expectError(error.ConnectionClosed, conn.closeConnection(0, 0, ""));
    try std.testing.expectError(error.ConnectionClosed, conn.closeApplication(0, ""));
    try std.testing.expectError(error.ConnectionClosed, conn.sendPing());
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
    try std.testing.expectEqual(ConnectionState.active, conn.connectionState());
    try std.testing.expectEqual(@as(?i64, null), conn.closeDeadlineMillis());
    try std.testing.expectEqual(@as(u64, 1), try conn.openStream());
}

test "closeConnection queues CONNECTION_CLOSE and closes after pollTx" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    try conn.closeConnection(0, @intFromEnum(frame.FrameType.stream), "done");
    try std.testing.expect(!conn.closed);
    try std.testing.expectEqual(ConnectionState.closing, conn.connectionState());
    try std.testing.expectEqual(@as(?i64, null), conn.closeDeadlineMillis());
    try std.testing.expectError(error.ConnectionClosed, conn.sendPing());

    const ping = [_]u8{@intFromEnum(frame.FrameType.ping)};
    try std.testing.expectError(error.ConnectionClosed, conn.processDatagram(0, &ping));

    var out_buf: [64]u8 = undefined;
    const payload = (try conn.pollTx(0, &out_buf)).?;
    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);

    switch (decoded.frame) {
        .connection_close => |close| {
            try std.testing.expectEqual(@as(u64, 0), close.error_code);
            try std.testing.expectEqual(@as(u64, @intFromEnum(frame.FrameType.stream)), close.frame_type);
            try std.testing.expectEqualStrings("done", close.reason_phrase);
        },
        else => return error.InvalidPacket,
    }

    try std.testing.expect(conn.closed);
    try std.testing.expectEqual(ConnectionState.closing, conn.connectionState());
    try std.testing.expect(conn.closeDeadlineMillis().? > 0);

    const retransmit = (try conn.pollTx(1, &out_buf)).?;
    var retransmitted = try frame.decodeFrameSlice(retransmit, std.testing.allocator);
    defer frame.deinitFrame(&retransmitted.frame, std.testing.allocator);
    switch (retransmitted.frame) {
        .connection_close => |close| {
            try std.testing.expectEqual(@as(u64, 0), close.error_code);
            try std.testing.expectEqual(@as(u64, @intFromEnum(frame.FrameType.stream)), close.frame_type);
            try std.testing.expectEqualStrings("done", close.reason_phrase);
        },
        else => return error.InvalidPacket,
    }
}

test "closeApplication queues APPLICATION_CLOSE and closes after pollTx" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();
    try conn.validatePeerAddress();

    try conn.closeApplication(42, "app done");

    var out_buf: [64]u8 = undefined;
    const payload = (try conn.pollTx(0, &out_buf)).?;
    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);

    switch (decoded.frame) {
        .application_close => |close| {
            try std.testing.expectEqual(@as(u64, 42), close.error_code);
            try std.testing.expectEqualStrings("app done", close.reason_phrase);
        },
        else => return error.InvalidPacket,
    }

    try std.testing.expect(conn.closed);
    try std.testing.expectEqual(ConnectionState.closing, conn.connectionState());
    try std.testing.expectError(error.ConnectionClosed, conn.openStream());

    const retransmit = (try conn.pollTx(1, &out_buf)).?;
    var retransmitted = try frame.decodeFrameSlice(retransmit, std.testing.allocator);
    defer frame.deinitFrame(&retransmitted.frame, std.testing.allocator);
    switch (retransmitted.frame) {
        .application_close => |close| {
            try std.testing.expectEqual(@as(u64, 42), close.error_code);
            try std.testing.expectEqualStrings("app done", close.reason_phrase);
        },
        else => return error.InvalidPacket,
    }
}

test "local closing state expires after close timeout" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{ .initial_rtt_ms = 100 });
    defer conn.deinit();

    try conn.closeConnection(0, @intFromEnum(frame.FrameType.ping), "bye");

    var out_buf: [64]u8 = undefined;
    _ = (try conn.pollTx(10, &out_buf)).?;
    const deadline = conn.closeDeadlineMillis().?;
    try std.testing.expectEqual(ConnectionState.closing, conn.connectionState());
    try std.testing.expect(deadline > 10);

    const retransmit = (try conn.pollTx(deadline - 1, &out_buf)).?;
    var decoded = try frame.decodeFrameSlice(retransmit, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .connection_close => |close| try std.testing.expectEqualStrings("bye", close.reason_phrase),
        else => return error.InvalidPacket,
    }
    try std.testing.expectEqual(ConnectionState.closing, conn.connectionState());

    try std.testing.expectError(error.ConnectionClosed, conn.pollTx(deadline, &out_buf));
    try std.testing.expectEqual(ConnectionState.closed, conn.connectionState());
    try std.testing.expectEqual(@as(?i64, null), conn.closeDeadlineMillis());
    try std.testing.expect(conn.pending_close == null);
}

test "remote close enters draining state until close timeout expires" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{ .initial_rtt_ms = 100 });
    defer conn.deinit();

    var close_buf: [64]u8 = undefined;
    var close_out = buffer.fixedWriter(&close_buf);
    try frame.encodeFrame(close_out.writer(), .{ .application_close = .{
        .error_code = 0,
        .reason_phrase = "remote",
    } });

    try conn.processDatagram(20, close_out.getWritten());
    const deadline = conn.closeDeadlineMillis().?;
    try std.testing.expect(conn.closed);
    try std.testing.expectEqual(ConnectionState.draining, conn.connectionState());
    try std.testing.expect(deadline > 20);

    const ping = [_]u8{@intFromEnum(frame.FrameType.ping)};
    try std.testing.expectError(error.ConnectionClosed, conn.processDatagram(deadline - 1, &ping));
    try std.testing.expectEqual(ConnectionState.draining, conn.connectionState());

    try std.testing.expectError(error.ConnectionClosed, conn.processDatagram(deadline, &ping));
    try std.testing.expectEqual(ConnectionState.closed, conn.connectionState());
    try std.testing.expectEqual(@as(?i64, null), conn.closeDeadlineMillis());
}

test "local close validates size before mutating connection state" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{ .max_datagram_size = 5 });
    defer conn.deinit();

    try std.testing.expectError(
        error.BufferTooSmall,
        conn.closeConnection(0, @intFromEnum(frame.FrameType.stream), "too-long"),
    );
    try std.testing.expect(!conn.closed);
    try std.testing.expect(conn.pending_close == null);
    try std.testing.expectEqual(ConnectionState.active, conn.connectionState());

    try conn.sendPing();
    var out_buf: [8]u8 = undefined;
    const payload = (try conn.pollTx(0, &out_buf)).?;
    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);

    switch (decoded.frame) {
        .ping => {},
        else => return error.InvalidPacket,
    }
}

test "local close rejects invalid varint values before mutating connection state" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    try std.testing.expectError(error.InvalidPacket, conn.closeConnection(max_quic_varint + 1, 0, ""));
    try std.testing.expectError(error.InvalidPacket, conn.closeApplication(max_quic_varint + 1, ""));
    try std.testing.expect(!conn.closed);
    try std.testing.expect(conn.pending_close == null);
    try std.testing.expectEqual(ConnectionState.active, conn.connectionState());
    try std.testing.expectEqual(@as(u64, 0), try conn.openStream());
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

test "sendOnStream queues DATA_BLOCKED when connection flow control blocks" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 10,
    });
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "12345", false);
    try std.testing.expectError(error.FlowControlBlocked, conn.sendOnStream(stream_id, "x", false));
    try std.testing.expectEqual(@as(usize, 1), conn.pending_blocked_frames.items.len);

    var out_buf: [64]u8 = undefined;
    const payload = (try conn.pollTx(0, &out_buf)).?;
    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);

    switch (decoded.frame) {
        .data_blocked => |blocked| try std.testing.expectEqual(@as(u64, 5), blocked.maximum_data),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 0), conn.pending_blocked_frames.items.len);
    try std.testing.expectEqual(@as(usize, 1), conn.send_queue.items.len);
}

test "obsolete DATA_BLOCKED is dropped after MAX_DATA update" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 10,
    });
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "12345", false);
    try std.testing.expectError(error.FlowControlBlocked, conn.sendOnStream(stream_id, "x", false));

    var update_buf: [16]u8 = undefined;
    var update_out = buffer.fixedWriter(&update_buf);
    try frame.encodeFrame(update_out.writer(), .{ .max_data = .{ .maximum_data = 6 } });
    try conn.processDatagram(0, update_out.getWritten());

    try conn.sendOnStream(stream_id, "x", false);

    var out_buf: [128]u8 = undefined;
    const payload = (try conn.pollTx(0, &out_buf)).?;
    var first = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&first.frame, std.testing.allocator);

    const stream_offset = switch (first.frame) {
        .ack => first.len,
        .stream => @as(usize, 0),
        else => return error.TestUnexpectedResult,
    };
    var decoded = try frame.decodeFrameSlice(payload[stream_offset..], std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);

    switch (decoded.frame) {
        .stream => |stream_frame| {
            try std.testing.expectEqual(@as(u64, 0), stream_frame.offset);
            try std.testing.expectEqualStrings("12345", stream_frame.data);
        },
        else => return error.TestUnexpectedResult,
    }
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

test "sendOnStream queues STREAM_DATA_BLOCKED when stream flow control blocks" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 10,
        .initial_max_stream_data = 5,
    });
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "12345", false);
    try std.testing.expectError(error.FlowControlBlocked, conn.sendOnStream(stream_id, "x", false));

    var out_buf: [64]u8 = undefined;
    const payload = (try conn.pollTx(0, &out_buf)).?;
    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);

    switch (decoded.frame) {
        .stream_data_blocked => |blocked| {
            try std.testing.expectEqual(stream_id, blocked.stream_id);
            try std.testing.expectEqual(@as(u64, 5), blocked.maximum_stream_data);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "recvOnStream queues MAX_DATA and MAX_STREAM_DATA after consuming bytes" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 5,
    });
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 5,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "12345", false);

    var datagram: [128]u8 = undefined;
    try server.processDatagram(0, (try client.pollTx(0, &datagram)).?);
    try std.testing.expectError(error.FlowControlBlocked, client.sendOnStream(stream_id, "!", false));

    var read_buf: [3]u8 = undefined;
    const n1 = (try server.recvOnStream(stream_id, &read_buf)).?;
    try std.testing.expectEqualStrings("123", read_buf[0..n1]);
    const n2 = (try server.recvOnStream(stream_id, &read_buf)).?;
    try std.testing.expectEqualStrings("45", read_buf[0..n2]);
    try std.testing.expectEqual(@as(u64, 10), server.recv_max_data);
    try std.testing.expectEqual(@as(u64, 10), server.findRecvStream(stream_id).?.max_data);

    const max_data_payload = (try server.pollTx(10, &datagram)).?;
    var ack = try frame.decodeFrameSlice(max_data_payload, std.testing.allocator);
    defer frame.deinitFrame(&ack.frame, std.testing.allocator);
    switch (ack.frame) {
        .ack => |ack_frame| try std.testing.expectEqual(@as(u64, 0), ack_frame.largest_acknowledged),
        else => return error.TestUnexpectedResult,
    }

    var max_data = try frame.decodeFrameSlice(max_data_payload[ack.len..], std.testing.allocator);
    defer frame.deinitFrame(&max_data.frame, std.testing.allocator);
    switch (max_data.frame) {
        .max_data => |max_frame| try std.testing.expectEqual(@as(u64, 10), max_frame.maximum_data),
        else => return error.TestUnexpectedResult,
    }
    try client.processDatagram(20, max_data_payload);

    const max_stream_payload = (try server.pollTx(30, &datagram)).?;
    var max_stream = try frame.decodeFrameSlice(max_stream_payload, std.testing.allocator);
    defer frame.deinitFrame(&max_stream.frame, std.testing.allocator);
    switch (max_stream.frame) {
        .max_stream_data => |max_frame| {
            try std.testing.expectEqual(stream_id, max_frame.stream_id);
            try std.testing.expectEqual(@as(u64, 10), max_frame.maximum_stream_data);
        },
        else => return error.TestUnexpectedResult,
    }
    try client.processDatagram(40, max_stream_payload);

    try client.sendOnStream(stream_id, "!", true);
}

test "recvOnStream queues MAX_STREAMS_BIDI when peer bidirectional stream finishes" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 16,
        .initial_max_stream_data = 16,
        .initial_max_streams_bidi = 1,
    });
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{
        .initial_max_data = 16,
        .initial_max_stream_data = 16,
        .initial_max_streams_bidi = 1,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "done", true);

    var datagram: [128]u8 = undefined;
    try server.processDatagram(0, (try client.pollTx(0, &datagram)).?);
    try std.testing.expectError(error.FlowControlBlocked, client.openStream());

    var read_buf: [4]u8 = undefined;
    const n = (try server.recvOnStream(stream_id, &read_buf)).?;
    try std.testing.expectEqualStrings("done", read_buf[0..n]);
    try std.testing.expect(try server.recvStreamFinished(stream_id));
    try std.testing.expectEqual(@as(u64, 2), server.recv_max_streams_bidi);

    try pollAndProcessUntilMaxStreams(&server, &client, .bidi, 2);
    try std.testing.expectEqual(@as(u64, 4), try client.openStream());

    try std.testing.expectEqual(@as(?usize, null), try server.recvOnStream(stream_id, &read_buf));
    try std.testing.expectEqual(@as(u64, 2), server.recv_max_streams_bidi);
}

test "recvOnStream queues MAX_STREAMS_UNI when zero-length peer unidirectional stream finishes" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_streams_uni = 1,
    });
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{
        .initial_max_streams_uni = 1,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    const stream_id = try client.openUniStream();
    try client.sendOnStream(stream_id, "", true);

    var datagram: [128]u8 = undefined;
    try server.processDatagram(0, (try client.pollTx(0, &datagram)).?);
    try std.testing.expectError(error.FlowControlBlocked, client.openUniStream());

    var read_buf: [1]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try server.recvOnStream(stream_id, &read_buf));
    try std.testing.expect(try server.recvStreamFinished(stream_id));
    try std.testing.expectEqual(@as(u64, 2), server.recv_max_streams_uni);

    try pollAndProcessUntilMaxStreams(&server, &client, .uni, 2);
    try std.testing.expectEqual(@as(u64, 6), try client.openUniStream());

    try std.testing.expectEqual(@as(?usize, null), try server.recvOnStream(stream_id, &read_buf));
    try std.testing.expectEqual(@as(u64, 2), server.recv_max_streams_uni);
}

test "openStream queues STREAMS_BLOCKED frames when stream count blocks" {
    var bidi = try QuicConnection.init(std.testing.allocator, .client, .{ .initial_max_streams_bidi = 1 });
    defer bidi.deinit();

    _ = try bidi.openStream();
    try std.testing.expectError(error.FlowControlBlocked, bidi.openStream());

    var out_buf: [64]u8 = undefined;
    const bidi_payload = (try bidi.pollTx(0, &out_buf)).?;
    var bidi_decoded = try frame.decodeFrameSlice(bidi_payload, std.testing.allocator);
    defer frame.deinitFrame(&bidi_decoded.frame, std.testing.allocator);
    switch (bidi_decoded.frame) {
        .streams_blocked_bidi => |blocked| try std.testing.expectEqual(@as(u64, 1), blocked.maximum_streams),
        else => return error.TestUnexpectedResult,
    }

    var uni = try QuicConnection.init(std.testing.allocator, .client, .{ .initial_max_streams_uni = 1 });
    defer uni.deinit();

    _ = try uni.openUniStream();
    try std.testing.expectError(error.FlowControlBlocked, uni.openUniStream());

    const uni_payload = (try uni.pollTx(0, &out_buf)).?;
    var uni_decoded = try frame.decodeFrameSlice(uni_payload, std.testing.allocator);
    defer frame.deinitFrame(&uni_decoded.frame, std.testing.allocator);
    switch (uni_decoded.frame) {
        .streams_blocked_uni => |blocked| try std.testing.expectEqual(@as(u64, 1), blocked.maximum_streams),
        else => return error.TestUnexpectedResult,
    }
}

test "processDatagram records peer BLOCKED frame limits" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [96]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .data_blocked = .{ .maximum_data = 4096 } });
    try frame.encodeFrame(out.writer(), .{ .stream_data_blocked = .{
        .stream_id = 0,
        .maximum_stream_data = 1024,
    } });
    try frame.encodeFrame(out.writer(), .{ .streams_blocked_bidi = .{ .maximum_streams = 3 } });
    try frame.encodeFrame(out.writer(), .{ .streams_blocked_uni = .{ .maximum_streams = 5 } });

    try conn.processDatagram(0, out.getWritten());

    try std.testing.expectEqual(@as(?u64, 4096), conn.peerDataBlockedLimit());
    try std.testing.expectEqual(@as(?u64, 1024), conn.peerStreamDataBlockedLimit(0));
    try std.testing.expectEqual(@as(?u64, 3), conn.peerStreamsBlockedBidiLimit());
    try std.testing.expectEqual(@as(?u64, 5), conn.peerStreamsBlockedUniLimit());
    try std.testing.expectEqual(@as(?u64, 0), conn.pending_ack_largest);
}

test "peer BLOCKED frame limits keep highest reported value" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [96]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .data_blocked = .{ .maximum_data = 4096 } });
    try frame.encodeFrame(out.writer(), .{ .data_blocked = .{ .maximum_data = 2048 } });
    try frame.encodeFrame(out.writer(), .{ .stream_data_blocked = .{
        .stream_id = 0,
        .maximum_stream_data = 7,
    } });
    try frame.encodeFrame(out.writer(), .{ .stream_data_blocked = .{
        .stream_id = 0,
        .maximum_stream_data = 9,
    } });
    try frame.encodeFrame(out.writer(), .{ .stream_data_blocked = .{
        .stream_id = 4,
        .maximum_stream_data = 11,
    } });
    try frame.encodeFrame(out.writer(), .{ .streams_blocked_bidi = .{ .maximum_streams = 1 } });
    try frame.encodeFrame(out.writer(), .{ .streams_blocked_bidi = .{ .maximum_streams = 2 } });

    try conn.processDatagram(0, out.getWritten());

    try std.testing.expectEqual(@as(?u64, 4096), conn.peerDataBlockedLimit());
    try std.testing.expectEqual(@as(?u64, 9), conn.peerStreamDataBlockedLimit(0));
    try std.testing.expectEqual(@as(?u64, 11), conn.peerStreamDataBlockedLimit(4));
    try std.testing.expectEqual(@as(?u64, null), conn.peerStreamDataBlockedLimit(8));
    try std.testing.expectEqual(@as(?u64, 2), conn.peerStreamsBlockedBidiLimit());
}

test "peer BLOCKED frame state rolls back when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [96]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .data_blocked = .{ .maximum_data = 5 } });
    try frame.encodeFrame(out.writer(), .{ .stream_data_blocked = .{
        .stream_id = 0,
        .maximum_stream_data = 7,
    } });
    try frame.encodeFrame(out.writer(), .{ .streams_blocked_bidi = .{ .maximum_streams = 1 } });
    try conn.processDatagram(0, out.getWritten());

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .data_blocked = .{ .maximum_data = 9 } });
    try frame.encodeFrame(out.writer(), .{ .stream_data_blocked = .{
        .stream_id = 4,
        .maximum_stream_data = 11,
    } });
    try frame.encodeFrame(out.writer(), .{ .streams_blocked_uni = .{ .maximum_streams = 3 } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(1, out.getWritten()));
    try std.testing.expectEqual(@as(?u64, 5), conn.peerDataBlockedLimit());
    try std.testing.expectEqual(@as(?u64, 7), conn.peerStreamDataBlockedLimit(0));
    try std.testing.expectEqual(@as(?u64, null), conn.peerStreamDataBlockedLimit(4));
    try std.testing.expectEqual(@as(?u64, 1), conn.peerStreamsBlockedBidiLimit());
    try std.testing.expectEqual(@as(?u64, null), conn.peerStreamsBlockedUniLimit());
    try std.testing.expectEqual(@as(?u64, 0), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 1), conn.next_peer_packet_number);
}

test "peer DATA_BLOCKED below current receive limit retransmits MAX_DATA" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    conn.recv_max_data = 10;

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .data_blocked = .{ .maximum_data = 5 } });
    try conn.processDatagram(0, out.getWritten());

    try std.testing.expectEqual(@as(?u64, 5), conn.peerDataBlockedLimit());

    var out_buf: [64]u8 = undefined;
    const payload = (try conn.pollTx(0, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(try payloadContainsExpectedMaxFrame(payload, .{ .data = 10 }));
}

test "peer STREAM_DATA_BLOCKED below current receive stream limit retransmits MAX_STREAM_DATA" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_stream_data = 10,
    });
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 1,
        .offset = 0,
        .fin = false,
        .data = "",
    } });
    try conn.processDatagram(0, out.getWritten());

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream_data_blocked = .{
        .stream_id = 1,
        .maximum_stream_data = 5,
    } });
    try conn.processDatagram(1, out.getWritten());

    try std.testing.expectEqual(@as(?u64, 5), conn.peerStreamDataBlockedLimit(1));

    var out_buf: [64]u8 = undefined;
    const payload = (try conn.pollTx(2, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(try payloadContainsExpectedMaxFrame(payload, .{
        .stream_data = .{ .stream_id = 1, .maximum_stream_data = 10 },
    }));
}

test "peer STREAMS_BLOCKED below current receive limits retransmits MAX_STREAMS" {
    var bidi = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_streams_bidi = 4,
    });
    defer bidi.deinit();

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .streams_blocked_bidi = .{ .maximum_streams = 1 } });
    try bidi.processDatagram(0, out.getWritten());

    try std.testing.expectEqual(@as(?u64, 1), bidi.peerStreamsBlockedBidiLimit());

    var out_buf: [64]u8 = undefined;
    const bidi_payload = (try bidi.pollTx(0, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(try payloadContainsExpectedMaxFrame(bidi_payload, .{ .streams_bidi = 4 }));

    var uni = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_streams_uni = 3,
    });
    defer uni.deinit();

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .streams_blocked_uni = .{ .maximum_streams = 1 } });
    try uni.processDatagram(0, out.getWritten());

    try std.testing.expectEqual(@as(?u64, 1), uni.peerStreamsBlockedUniLimit());

    const uni_payload = (try uni.pollTx(0, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(try payloadContainsExpectedMaxFrame(uni_payload, .{ .streams_uni = 3 }));
}

test "peer BLOCKED triggered MAX retransmission rolls back when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    conn.recv_max_data = 10;

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .data_blocked = .{ .maximum_data = 5 } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(?u64, null), conn.peerDataBlockedLimit());
    try std.testing.expectEqual(@as(usize, 0), conn.pending_max_frames.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 0), conn.next_peer_packet_number);
}

test "MAX_STREAM_DATA rejects unopened local and receive-only streams" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    var update_buf: [32]u8 = undefined;
    var update_out = buffer.fixedWriter(&update_buf);
    try frame.encodeFrame(update_out.writer(), .{ .max_stream_data = .{
        .stream_id = 0,
        .maximum_stream_data = 10,
    } });
    try std.testing.expectError(error.InvalidPacket, client.processDatagram(0, update_out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), client.send_streams.items.len);
    try std.testing.expectEqual(@as(?u64, null), client.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 0), client.next_peer_packet_number);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    update_out = buffer.fixedWriter(&update_buf);
    try frame.encodeFrame(update_out.writer(), .{ .max_stream_data = .{
        .stream_id = 2,
        .maximum_stream_data = 10,
    } });
    try std.testing.expectError(error.InvalidPacket, server.processDatagram(0, update_out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), server.send_streams.items.len);
}

test "MAX_STREAM_DATA updates observed peer bidirectional reply credit" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 10,
        .initial_max_stream_data = 1,
    });
    defer conn.deinit();

    var peer_stream_buf: [16]u8 = undefined;
    var peer_stream_out = buffer.fixedWriter(&peer_stream_buf);
    try frame.encodeFrame(peer_stream_out.writer(), .{ .stream = .{
        .stream_id = 1,
        .offset = 0,
        .fin = false,
        .data = "",
    } });
    try conn.processDatagram(0, peer_stream_out.getWritten());

    try std.testing.expectError(error.FlowControlBlocked, conn.sendOnStream(1, "xx", false));
    try std.testing.expectEqual(@as(usize, 0), conn.send_streams.items.len);

    var update_buf: [32]u8 = undefined;
    var update_out = buffer.fixedWriter(&update_buf);
    try frame.encodeFrame(update_out.writer(), .{ .max_stream_data = .{
        .stream_id = 1,
        .maximum_stream_data = 2,
    } });
    try conn.processDatagram(1, update_out.getWritten());

    try std.testing.expectEqual(@as(usize, 1), conn.send_streams.items.len);
    try std.testing.expectEqual(@as(u64, 2), conn.findSendStream(1).?.max_data);
    try conn.sendOnStream(1, "xx", false);
    try std.testing.expectEqual(@as(usize, 1), conn.send_queue.items.len);
}

test "MAX_STREAM_DATA send-state creation rolls back when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    var peer_stream_buf: [16]u8 = undefined;
    var peer_stream_out = buffer.fixedWriter(&peer_stream_buf);
    try frame.encodeFrame(peer_stream_out.writer(), .{ .stream = .{
        .stream_id = 1,
        .offset = 0,
        .fin = false,
        .data = "",
    } });
    try conn.processDatagram(0, peer_stream_out.getWritten());

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .max_stream_data = .{
        .stream_id = 1,
        .maximum_stream_data = 2,
    } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(1, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.send_streams.items.len);
    try std.testing.expectEqual(@as(?u64, 0), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 1), conn.next_peer_packet_number);
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

test "processDatagram buffers and reassembles out-of-order new stream data" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 5,
        .fin = true,
        .data = "!",
    } });

    try conn.processDatagram(0, out.getWritten());
    try std.testing.expectEqual(@as(usize, 1), conn.recv_streams.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items[0].data.items.len);
    try std.testing.expectEqual(@as(usize, 1), conn.recv_streams.items[0].pending.items.len);
    try std.testing.expectEqual(@as(?u64, 6), conn.recv_streams.items[0].final_size);
    try std.testing.expectEqual(@as(?u64, 6), try conn.recvStreamFinalSize(0));
    try std.testing.expect(!try conn.recvStreamFinished(0));
    try std.testing.expectEqual(@as(u64, 1), conn.recv_data_bytes);

    var read_buf: [16]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try conn.recvOnStream(0, &read_buf));

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "hello",
    } });

    try conn.processDatagram(1, out.getWritten());
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items[0].pending.items.len);
    try std.testing.expectEqual(@as(u64, 6), conn.recv_data_bytes);
    try std.testing.expect(!try conn.recvStreamFinished(0));

    const n = (try conn.recvOnStream(0, &read_buf)).?;
    try std.testing.expectEqualStrings("hello!", read_buf[0..n]);
    try std.testing.expect(try conn.recvStreamFinished(0));
    try std.testing.expectEqual(@as(?usize, null), try conn.recvOnStream(0, &read_buf));
}

test "processDatagram rejects overlapping out-of-order stream data" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 2,
        .fin = false,
        .data = "cd",
    } });
    try conn.processDatagram(0, out.getWritten());
    try std.testing.expectEqual(@as(usize, 1), conn.recv_streams.items[0].pending.items.len);
    try std.testing.expectEqual(@as(u64, 2), conn.recv_data_bytes);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 3,
        .fin = false,
        .data = "de",
    } });

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(1, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 1), conn.recv_streams.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items[0].data.items.len);
    try std.testing.expectEqual(@as(usize, 1), conn.recv_streams.items[0].pending.items.len);
    try std.testing.expectEqual(@as(u64, 2), conn.recv_data_bytes);
}

test "processDatagram rolls back out-of-order pending stream data when payload is invalid" {
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
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items.len);
    try std.testing.expectEqual(@as(u64, 0), conn.recv_data_bytes);
}

test "RESET_STREAM accounts final size after out-of-order stream data" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{
        .initial_max_data = 6,
        .initial_max_stream_data = 10,
    });
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 5,
        .fin = false,
        .data = "!",
    } });
    try conn.processDatagram(0, out.getWritten());
    try std.testing.expectEqual(@as(u64, 1), conn.recv_data_bytes);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = 7,
        .final_size = 6,
    } });
    try conn.processDatagram(1, out.getWritten());

    try std.testing.expectEqual(@as(u64, 6), conn.recv_data_bytes);
    try std.testing.expectEqual(@as(?u64, 7), conn.recv_streams.items[0].reset_error_code);

    var read_buf: [8]u8 = undefined;
    try std.testing.expectError(error.StreamClosed, conn.recvOnStream(0, &read_buf));
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
    try out.writeByte(0x0f); // STREAM with OFF, LEN, and FIN bits
    try packet.encodeVarInt(out.writer(), 0);
    try packet.encodeVarInt(out.writer(), max_quic_varint);
    try packet.encodeVarInt(out.writer(), 1);
    try out.writeByte('x');

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
