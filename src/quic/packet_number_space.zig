const std = @import("std");

const connection_config = @import("connection_config.zig");
const connection_state = @import("connection_state.zig");
const frame = @import("frame.zig");
const packet_context = @import("packet_context.zig");
const recovery = @import("recovery.zig");

const Config = connection_config.Config;
const EcnValidationState = packet_context.EcnValidationState;
const PendingCryptoFrame = connection_state.PendingCryptoFrame;
const SentPacket = connection_state.SentPacket;
const deinitSentPacketList = connection_state.deinitSentPacketList;

/// Mutable state owned by one QUIC packet number space.
pub const State = struct {
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
    pto_probe_count: usize = 0,
    congestion_probe_count: usize = 0,
    crypto_send_offset: u64 = 0,
    crypto_recv_buffer: std.ArrayList(u8) = .empty,
    crypto_read_offset: usize = 0,
    crypto_send_queue: std.ArrayList(PendingCryptoFrame) = .empty,
    crypto_recv_pending: std.ArrayList(PendingCryptoFrame) = .empty,
    ecn_sent_ect0: u64 = 0,
    ecn_sent_ect1: u64 = 0,
    ecn_largest_acknowledged: ?u64 = null,
    ecn_counts: frame.EcnCounts = zeroEcnCounts(),
    ecn_validation_state: EcnValidationState = .unknown,

    pub fn init(config: Config) State {
        return .{
            .recovery_state = recovery.Recovery.init(.{
                .max_datagram_size = config.max_datagram_size,
                .initial_rtt_ms = config.initial_rtt_ms,
                .max_ack_delay_ms = config.max_ack_delay_ms,
            }),
        };
    }

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        for (self.crypto_send_queue.items) |pending| {
            allocator.free(pending.data);
        }
        for (self.crypto_recv_pending.items) |pending| {
            allocator.free(pending.data);
        }
        self.crypto_recv_buffer.deinit(allocator);
        self.crypto_send_queue.deinit(allocator);
        self.crypto_recv_pending.deinit(allocator);
        deinitSentPacketList(allocator, &self.sent_packets);
    }
};

/// Borrowed field view used by connection logic that is generic over a packet number space.
pub const View = struct {
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
    pto_probe_count: *usize,
    congestion_probe_count: *usize,
    crypto_send_offset: *u64,
    crypto_recv_buffer: *std.ArrayList(u8),
    crypto_read_offset: *usize,
    crypto_send_queue: *std.ArrayList(PendingCryptoFrame),
    crypto_recv_pending: *std.ArrayList(PendingCryptoFrame),
    ecn_sent_ect0: *u64,
    ecn_sent_ect1: *u64,
    ecn_largest_acknowledged: *?u64,
    ecn_counts: *frame.EcnCounts,
    ecn_validation_state: *EcnValidationState,
};

pub fn zeroEcnCounts() frame.EcnCounts {
    return .{
        .ect0_count = 0,
        .ect1_count = 0,
        .ecn_ce_count = 0,
    };
}
