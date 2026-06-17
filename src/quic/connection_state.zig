const std = @import("std");

const frame = @import("frame.zig");
const packet_context = @import("packet_context.zig");

const EcnCodepoint = packet_context.EcnCodepoint;

/// Result of validating an ACK_ECN frame against sent ECN counters.
pub const EcnAckValidationResult = struct {
    ce_congestion_event: bool = false,
};

/// STREAM frame payload retained for retransmission or rollback.
pub const PendingStreamFrame = struct {
    stream_id: u64,
    offset: u64,
    fin: bool,
    data: []u8,
};

/// CRYPTO frame payload retained for retransmission or rollback.
pub const PendingCryptoFrame = struct {
    offset: u64,
    data: []u8,
};

/// Out-of-order receive-side STREAM payload.
pub const PendingRecvStreamFrame = struct {
    offset: u64,
    data: []u8,
};

/// Queued BLOCKED-family control frame.
pub const PendingBlockedFrame = union(enum) {
    data: frame.DataBlockedFrame,
    stream_data: frame.StreamDataBlockedFrame,
    streams_bidi: frame.StreamsBlockedBidiFrame,
    streams_uni: frame.StreamsBlockedUniFrame,
};

/// Queued MAX-family control frame.
pub const PendingMaxFrame = union(enum) {
    data: frame.MaxDataFrame,
    stream_data: frame.MaxStreamDataFrame,
    streams_bidi: frame.MaxStreamsBidiFrame,
    streams_uni: frame.MaxStreamsUniFrame,
};

/// Queued transport or application close frame.
pub const PendingCloseFrame = union(enum) {
    connection: frame.ConnectionCloseFrame,
    application: frame.ApplicationCloseFrame,
};

/// Rollback snapshot for whether peer close diagnostics existed.
pub const PeerCloseSnapshot = enum { absent, present };

/// Pending PATH_CHALLENGE data awaiting transmission.
pub const PendingPathChallenge = struct {
    data: [8]u8,
    transmissions: u8 = 0,
};

/// PATH_CHALLENGE data sent and awaiting response.
pub const OutstandingPathChallenge = struct {
    data: [8]u8,
    sent_time_millis: i64,
    transmissions: u8,
};

/// Sent packet metadata retained for ACK/loss accounting.
pub const SentPacket = struct {
    packet_number: u64,
    sent_time_millis: i64,
    bytes: usize,
    ecn_codepoint: EcnCodepoint = .not_ect,
    stream_frame: ?PendingStreamFrame = null,
    crypto_frame: ?PendingCryptoFrame = null,
    reset_stream_frame: ?frame.ResetStreamFrame = null,
    stop_sending_frame: ?frame.StopSendingFrame = null,

    pub fn deinit(self: *SentPacket, allocator: std.mem.Allocator) void {
        if (self.stream_frame) |pending| {
            allocator.free(pending.data);
            self.stream_frame = null;
        }
        if (self.crypto_frame) |pending| {
            allocator.free(pending.data);
            self.crypto_frame = null;
        }
    }
};

/// RTT estimator rollback snapshot for one packet number space.
pub const RttEstimateSnapshot = struct {
    first_rtt_sample_sent_time_millis: ?i64,
    latest_rtt_ms: ?u64,
    min_rtt_ms: ?u64,
    smoothed_rtt_ms: u64,
    rttvar_ms: u64,
};

/// PTO backoff rollback snapshot across packet number spaces.
pub const PtoBackoffSnapshot = struct {
    initial: u8,
    handshake: u8,
    application: u8,
};

/// Peer-issued connection ID tracked for routing and stateless reset.
pub const ActiveConnectionId = struct {
    sequence_number: u64,
    connection_id: []u8,
    stateless_reset_token: [16]u8,
    retired: bool = false,
};

/// Rollback snapshot for peer-issued connection ID retirement.
pub const ActiveConnectionIdSnapshot = struct {
    retired: bool,
};

/// Locally issued connection ID tracked until peer retirement.
pub const LocalConnectionId = struct {
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: []u8,
    stateless_reset_token: [16]u8,
    sent: bool = false,
    retired: bool = false,
};

/// Rollback snapshot for locally issued connection ID retirement.
pub const LocalConnectionIdSnapshot = struct {
    retired: bool,
};

pub fn deinitPendingStreamFrameSlice(allocator: std.mem.Allocator, frames: []PendingStreamFrame) void {
    for (frames) |pending| {
        allocator.free(pending.data);
    }
}

pub fn deinitPendingCryptoFrameSlice(allocator: std.mem.Allocator, frames: []PendingCryptoFrame) void {
    for (frames) |pending| {
        allocator.free(pending.data);
    }
}

pub fn deinitSentPacketSlice(allocator: std.mem.Allocator, sent_packets: []SentPacket) void {
    for (sent_packets) |*sent_packet| {
        sent_packet.deinit(allocator);
    }
}

pub fn clearSentPacketList(allocator: std.mem.Allocator, sent_packets: *std.ArrayList(SentPacket)) void {
    deinitSentPacketSlice(allocator, sent_packets.items);
    sent_packets.items.len = 0;
}

pub fn deinitSentPacketList(allocator: std.mem.Allocator, sent_packets: *std.ArrayList(SentPacket)) void {
    clearSentPacketList(allocator, sent_packets);
    sent_packets.deinit(allocator);
}

pub fn deinitPendingCloseFrame(close: *PendingCloseFrame, allocator: std.mem.Allocator) void {
    switch (close.*) {
        .connection => |connection| allocator.free(connection.reason_phrase),
        .application => |application| allocator.free(application.reason_phrase),
    }
}
