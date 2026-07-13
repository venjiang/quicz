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

/// One inclusive received packet-number interval, ordered from largest to
/// smallest when stored in `ReceivedPacketRanges`.
pub const ReceivedPacketRange = struct {
    smallest: u64,
    largest: u64,
};

/// Bounded receive-side packet-number history for one packet number space.
///
/// QUIC receivers need packet-number ranges both to reject duplicate packets
/// before frame side effects and to encode non-contiguous ACK frames. Keeping
/// this fixed-size avoids allowing peer-controlled reordering to allocate
/// unbounded connection memory. When the limit is reached, the oldest range is
/// forgotten; this may cause an old packet to be acknowledged less often but
/// preserves the newest loss/reordering evidence needed for recovery.
pub const ReceivedPacketRanges = struct {
    pub const max_ranges = 32;

    ranges: [max_ranges]ReceivedPacketRange = undefined,
    count: usize = 0,
    ack_ranges: [max_ranges - 1]frame.AckRange = undefined,
    forgotten_through: ?u64 = null,

    /// Return whether this packet number remains in the receive history.
    pub fn contains(self: ReceivedPacketRanges, packet_number: u64) bool {
        for (self.ranges[0..self.count]) |range| {
            if (packet_number > range.largest) continue;
            return packet_number >= range.smallest;
        }
        return false;
    }

    /// Return whether this packet number can be retained without reviving a
    /// range that was deliberately forgotten to bound receive-side memory.
    pub fn canRecord(self: ReceivedPacketRanges, packet_number: u64) bool {
        if (self.forgotten_through) |forgotten| {
            if (packet_number <= forgotten) return false;
        }

        var index: usize = 0;
        while (index < self.count) : (index += 1) {
            const range = self.ranges[index];
            if (packet_number > range.largest) return true;
            if (packet_number >= range.smallest) return false;
            if (range.smallest != 0 and packet_number + 1 == range.smallest) return true;
        }
        return self.count < max_ranges;
    }

    /// Record a newly processed packet number.
    ///
    /// Returns false for duplicates and when an older non-contiguous range is
    /// outside the bounded retention window. New ranges are merged with either
    /// adjacent neighbor, so normal in-order traffic occupies one entry.
    pub fn record(self: *ReceivedPacketRanges, packet_number: u64) bool {
        if (!self.canRecord(packet_number)) return false;

        var index: usize = 0;
        while (index < self.count) : (index += 1) {
            const range = self.ranges[index];
            if (packet_number > range.largest) {
                if (range.largest != std.math.maxInt(u64) and packet_number == range.largest + 1) {
                    self.ranges[index].largest = packet_number;
                    if (index != 0 and self.ranges[index - 1].smallest == packet_number + 1) {
                        self.ranges[index - 1].smallest = self.ranges[index].smallest;
                        self.remove(index);
                    }
                    return true;
                }
                return self.insert(index, .{ .smallest = packet_number, .largest = packet_number });
            }
            if (packet_number >= range.smallest) return false;
            if (range.smallest != 0 and packet_number + 1 == range.smallest) {
                self.ranges[index].smallest = packet_number;
                if (index + 1 < self.count and self.ranges[index + 1].largest + 1 == packet_number) {
                    self.ranges[index].smallest = self.ranges[index + 1].smallest;
                    self.remove(index + 1);
                }
                return true;
            }
        }
        return self.insert(self.count, .{ .smallest = packet_number, .largest = packet_number });
    }

    /// Return the packet number expected by QUIC packet-number reconstruction.
    pub fn nextExpectedPacketNumber(self: ReceivedPacketRanges) u64 {
        if (self.count == 0) return 0;
        const largest = self.ranges[0].largest;
        return if (largest == std.math.maxInt(u64)) largest else largest + 1;
    }

    /// Build the ACK ranges for every retained received packet number.
    pub fn ackFrame(self: *ReceivedPacketRanges) ?frame.AckFrame {
        if (self.count == 0) return null;

        const largest_range = self.ranges[0];
        for (self.ranges[1..self.count], 0..) |range, index| {
            const previous_smallest = self.ranges[index].smallest;
            self.ack_ranges[index] = .{
                .gap = previous_smallest - range.largest - 2,
                .ack_range = range.largest - range.smallest,
            };
        }
        return .{
            .largest_acknowledged = largest_range.largest,
            .ack_delay = 0,
            .first_ack_range = largest_range.largest - largest_range.smallest,
            .ranges = self.ack_ranges[0 .. self.count - 1],
        };
    }

    fn insert(self: *ReceivedPacketRanges, index: usize, range: ReceivedPacketRange) bool {
        if (self.count == max_ranges and index == self.count) return false;
        if (self.count == max_ranges) {
            const forgotten = self.ranges[self.count - 1].largest;
            self.forgotten_through = if (self.forgotten_through) |previous| @max(previous, forgotten) else forgotten;
            self.count -= 1;
        }
        std.mem.copyBackwards(ReceivedPacketRange, self.ranges[index + 1 .. self.count + 1], self.ranges[index..self.count]);
        self.ranges[index] = range;
        self.count += 1;
        return true;
    }

    fn remove(self: *ReceivedPacketRanges, index: usize) void {
        std.mem.copyForwards(ReceivedPacketRange, self.ranges[index .. self.count - 1], self.ranges[index + 1 .. self.count]);
        self.count -= 1;
    }
};

/// Mutable state owned by one QUIC packet number space.
pub const State = struct {
    discarded: bool = false,
    next_packet_number: u64 = 0,
    next_peer_packet_number: u64 = 0,
    pending_ack_largest: ?u64 = null,
    received_packet_ranges: ReceivedPacketRanges = .{},
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
    received_packet_ranges: *ReceivedPacketRanges,
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

test "received packet ranges merge reordered packets and encode ACK gaps" {
    var received = ReceivedPacketRanges{};

    try std.testing.expect(received.record(0));
    try std.testing.expect(received.record(2));
    try std.testing.expect(!received.record(2));
    try std.testing.expectEqual(@as(u64, 3), received.nextExpectedPacketNumber());

    const gapped_ack = received.ackFrame() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 2), gapped_ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 0), gapped_ack.first_ack_range);
    try std.testing.expectEqual(@as(usize, 1), gapped_ack.ranges.len);
    try std.testing.expectEqual(@as(u64, 0), gapped_ack.ranges[0].gap);
    try std.testing.expectEqual(@as(u64, 0), gapped_ack.ranges[0].ack_range);

    try std.testing.expect(received.record(1));
    const contiguous_ack = received.ackFrame() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 2), contiguous_ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 2), contiguous_ack.first_ack_range);
    try std.testing.expectEqual(@as(usize, 0), contiguous_ack.ranges.len);
}

test "received packet ranges reject forgotten packets after bounded eviction" {
    var received = ReceivedPacketRanges{};
    for (0..ReceivedPacketRanges.max_ranges) |index| {
        try std.testing.expect(received.record(@as(u64, @intCast(index * 2 + 1))));
    }

    try std.testing.expect(received.record(100));
    try std.testing.expect(!received.canRecord(1));
    try std.testing.expect(!received.record(1));

    for (64..100) |packet_number| {
        try std.testing.expect(received.record(@as(u64, @intCast(packet_number))));
    }
    try std.testing.expect(received.count < ReceivedPacketRanges.max_ranges);
    try std.testing.expect(!received.canRecord(1));
}
