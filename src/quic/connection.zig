const std = @import("std");
const clock = @import("../time/clock.zig");
const duration_mod = @import("../time/duration.zig");

pub const packet = @import("packet.zig");
pub const frame = @import("frame.zig");
pub const recovery = @import("recovery.zig");
const pacer_module = @import("pacer.zig");
pub const protection = @import("protection.zig");
pub const address_validation_token = @import("address_validation_token.zig");
pub const endpoint = @import("endpoint.zig");
pub const transport_error = @import("transport_error.zig");
pub const transport_parameters = @import("transport_parameters.zig");
const transport_types = @import("transport_types.zig");
const crypto_types = @import("crypto_types.zig");
const tls_backend_module = @import("tls_backend.zig");
pub const tls13 = @import("../tls/tls13.zig");
pub const tls13_backend = @import("tls13_backend.zig");
comptime {
    // Keep tls13 reachable so its tests run under `zig build test`.
    _ = tls13;
    _ = tls13_backend;
}
const endpoint_types = @import("endpoint_types.zig");
const endpoint_timers = @import("endpoint_timers.zig");
const connection_config = @import("connection_config.zig");
const connection_rules = @import("connection_rules.zig");
const connection_version = @import("connection_version.zig");
const connection_state = @import("connection_state.zig");
const packet_number_space = @import("packet_number_space.zig");
const stream_id_rules = @import("stream_id.zig");
const packet_context = @import("packet_context.zig");
const protocol_limits = @import("protocol_limits.zig");
const buffer = @import("buffer.zig");
const wire_len = @import("wire_len.zig");
const multipath_module = @import("multipath.zig");
const qlog_module = @import("../qlog/qlog.zig");
const frame_rules = @import("frame_rules.zig");
const frame_payload_module = @import("frame_payload.zig");

pub const Error = transport_types.Error;
pub const ConnectionSide = transport_types.ConnectionSide;
pub const VersionCompatibility = transport_types.VersionCompatibility;
pub const canConvertFirstFlightVersion = transport_types.canConvertFirstFlightVersion;
pub const selectCompatibleVersion = transport_types.selectCompatibleVersion;
pub const ConnectionState = transport_types.ConnectionState;
pub const PeerClose = transport_types.PeerClose;
pub const HandshakeState = transport_types.HandshakeState;
pub const StreamSendState = transport_types.StreamSendState;
pub const StreamReceiveState = transport_types.StreamReceiveState;
pub const StreamState = transport_types.StreamState;
pub const PacketNumberSpace = transport_types.PacketNumberSpace;
pub const LossDetectionTimerKind = transport_types.LossDetectionTimerKind;
pub const LossDetectionTimerDeadline = transport_types.LossDetectionTimerDeadline;
pub const HandshakeTrafficSecrets = crypto_types.HandshakeTrafficSecrets;
pub const ZeroRttTrafficSecrets = crypto_types.ZeroRttTrafficSecrets;
pub const OneRttTrafficSecrets = crypto_types.OneRttTrafficSecrets;
pub const CryptoBackend = crypto_types.CryptoBackend;
pub const CryptoBackendProgress = crypto_types.CryptoBackendProgress;
const PeerTransportParameterDrivePolicy = crypto_types.PeerTransportParameterDrivePolicy;
pub const TlsBackendStatus = tls_backend_module.TlsBackendStatus;
pub const TlsBackendPacketSpace = tls_backend_module.TlsBackendPacketSpace;
pub const TlsBackendReceiveFn = tls_backend_module.TlsBackendReceiveFn;
pub const TlsBackendPullFn = tls_backend_module.TlsBackendPullFn;
pub const TlsBackendSetBytesFn = tls_backend_module.TlsBackendSetBytesFn;
pub const TlsBackendPullBytesFn = tls_backend_module.TlsBackendPullBytesFn;
pub const TlsBackendPullHandshakeSecretsFn = tls_backend_module.TlsBackendPullHandshakeSecretsFn;
pub const TlsBackendPullZeroRttSecretsFn = tls_backend_module.TlsBackendPullZeroRttSecretsFn;
pub const TlsBackendPullOneRttSecretsFn = tls_backend_module.TlsBackendPullOneRttSecretsFn;
pub const TlsBackendHandshakeConfirmedFn = tls_backend_module.TlsBackendHandshakeConfirmedFn;
pub const TlsBackend = tls_backend_module.TlsBackend;
pub const PreferredAddress = connection_config.PreferredAddress;
pub const Config = connection_config.Config;
pub const EndpointLossDetectionTimerDeadline = endpoint_types.EndpointLossDetectionTimerDeadline;
pub const EndpointLossDetectionTimers = endpoint_timers.EndpointLossDetectionTimers;
pub const EndpointConnectionRetireResult = endpoint_types.EndpointConnectionRetireResult;
pub const EndpointVersionNegotiationResult = endpoint_types.EndpointVersionNegotiationResult;
pub const EndpointVersionNegotiationFollowupResult = endpoint_types.EndpointVersionNegotiationFollowupResult;
pub const EndpointVersionNegotiationError = endpoint_types.EndpointVersionNegotiationError;
pub const EndpointProtectedInitialError = endpoint_types.EndpointProtectedInitialError;
pub const EndpointRetryProtectedInitialError = endpoint_types.EndpointRetryProtectedInitialError;
pub const EndpointProtectedDatagramError = endpoint_types.EndpointProtectedDatagramError;
pub const EndpointAddressValidationError = endpoint_types.EndpointAddressValidationError;
pub const EndpointConnectionIdError = endpoint_types.EndpointConnectionIdError;
pub const EndpointIssuedConnectionIdOptions = endpoint_types.EndpointIssuedConnectionIdOptions;
pub const EndpointIssuedConnectionIdResult = endpoint_types.EndpointIssuedConnectionIdResult;
pub const EndpointAcceptedProtectedInitialResult = endpoint_types.EndpointAcceptedProtectedInitialResult;
pub const EndpointProtectedLongDatagramResult = endpoint_types.EndpointProtectedLongDatagramResult;
pub const EndpointRoutedCryptoBackendDriveProtectedLongDatagramResult = endpoint_types.EndpointRoutedCryptoBackendDriveProtectedLongDatagramResult;
pub const EndpointRoutedCryptoBackendDriveProtectedLongDatagramDrainResult = endpoint_types.EndpointRoutedCryptoBackendDriveProtectedLongDatagramDrainResult;
pub const EndpointRoutedCryptoBackendDriveDatagramResult = endpoint_types.EndpointRoutedCryptoBackendDriveDatagramResult;
pub const EndpointRoutedCryptoBackendDriveDatagramDrainResult = endpoint_types.EndpointRoutedCryptoBackendDriveDatagramDrainResult;
pub const EndpointRoutedCryptoBackendDriveNextDeadlineResult = endpoint_types.EndpointRoutedCryptoBackendDriveNextDeadlineResult;
pub const EndpointRoutedDatagramResult = endpoint_types.EndpointRoutedDatagramResult;
pub const EndpointRoutedDatagramDrainResult = endpoint_types.EndpointRoutedDatagramDrainResult;
pub const EndpointRoutedNextDeadlineResult = endpoint_types.EndpointRoutedNextDeadlineResult;
pub const EndpointPathValidatedShortDatagramResult = endpoint_types.EndpointPathValidatedShortDatagramResult;
pub const EndpointProtectedShortRecoveryPollResult = endpoint_types.EndpointProtectedShortRecoveryPollResult;
pub const EndpointProtectedLongRecoveryPollResult = endpoint_types.EndpointProtectedLongRecoveryPollResult;
pub const EndpointConnectionDeadlineKind = endpoint_types.EndpointConnectionDeadlineKind;
pub const EndpointConnectionDeadline = endpoint_types.EndpointConnectionDeadline;
pub const EndpointInstalledKeyDatagramSpace = endpoint_types.EndpointInstalledKeyDatagramSpace;
pub const EndpointPollInstalledKeyDatagramOptions = endpoint_types.EndpointPollInstalledKeyDatagramOptions;
pub const EndpointFeedInstalledKeyDatagramOptions = endpoint_types.EndpointFeedInstalledKeyDatagramOptions;
pub const EndpointPendingWorkResult = endpoint_types.EndpointPendingWorkResult;
pub const EndpointPendingWorkDatagramResult = endpoint_types.EndpointPendingWorkDatagramResult;
pub const EndpointPendingWorkDatagramDrainResult = endpoint_types.EndpointPendingWorkDatagramDrainResult;
pub const EndpointPendingWorkSweepResult = endpoint_types.EndpointPendingWorkSweepResult;
pub const EndpointPendingWorkNextDeadlineResult = endpoint_types.EndpointPendingWorkNextDeadlineResult;
pub const EndpointPendingWorkSweepDatagramResult = endpoint_types.EndpointPendingWorkSweepDatagramResult;
pub const EndpointPendingWorkSweepDatagramDrainResult = endpoint_types.EndpointPendingWorkSweepDatagramDrainResult;
pub const EndpointPendingWorkCryptoBackendDatagramResult = endpoint_types.EndpointPendingWorkCryptoBackendDatagramResult;
pub const EndpointPendingWorkCryptoBackendDatagramDrainResult = endpoint_types.EndpointPendingWorkCryptoBackendDatagramDrainResult;
pub const EndpointPendingWorkCryptoBackendNextDeadlineResult = endpoint_types.EndpointPendingWorkCryptoBackendNextDeadlineResult;
pub const EndpointCryptoBackendDriveSweepResult = endpoint_types.EndpointCryptoBackendDriveSweepResult;
pub const EndpointCryptoBackendDriveNextDeadlineResult = endpoint_types.EndpointCryptoBackendDriveNextDeadlineResult;
pub const EndpointCryptoBackendDriveDatagramResult = endpoint_types.EndpointCryptoBackendDriveDatagramResult;
pub const EndpointCryptoBackendDriveDatagramDrainResult = endpoint_types.EndpointCryptoBackendDriveDatagramDrainResult;
pub const EndpointCryptoBackendDriveProtectedLongDatagramResult = endpoint_types.EndpointCryptoBackendDriveProtectedLongDatagramResult;
pub const EndpointCryptoBackendDriveProtectedLongDatagramDrainResult = endpoint_types.EndpointCryptoBackendDriveProtectedLongDatagramDrainResult;
pub const EndpointPolledDatagramResult = endpoint_types.EndpointPolledDatagramResult;
pub const EndpointDatagramDrainResult = endpoint_types.EndpointDatagramDrainResult;
pub const EndpointDueWorkDatagramResult = endpoint_types.EndpointDueWorkDatagramResult;
pub const EndpointDueWorkDatagramDrainResult = endpoint_types.EndpointDueWorkDatagramDrainResult;
pub const EndpointDueWorkNextDeadlineResult = endpoint_types.EndpointDueWorkNextDeadlineResult;
pub const EndpointDueWorkCryptoBackendNextDeadlineResult = endpoint_types.EndpointDueWorkCryptoBackendNextDeadlineResult;
pub const EndpointDueWorkCryptoBackendDatagramResult = endpoint_types.EndpointDueWorkCryptoBackendDatagramResult;
pub const EndpointDueWorkCryptoBackendDatagramDrainResult = endpoint_types.EndpointDueWorkCryptoBackendDatagramDrainResult;
pub const EndpointFeedInstalledKeyDatagramResult = endpoint_types.EndpointFeedInstalledKeyDatagramResult;
pub const EndpointFeedInstalledKeyDatagramNextDeadlineResult = endpoint_types.EndpointFeedInstalledKeyDatagramNextDeadlineResult;
pub const EndpointFeedPendingWorkNextDeadlineResult = endpoint_types.EndpointFeedPendingWorkNextDeadlineResult;
pub const EndpointFeedPendingWorkDatagramPollResult = endpoint_types.EndpointFeedPendingWorkDatagramPollResult;
pub const EndpointFeedPendingWorkDatagramDrainResult = endpoint_types.EndpointFeedPendingWorkDatagramDrainResult;
pub const EndpointFeedPendingWorkCryptoBackendNextDeadlineResult = endpoint_types.EndpointFeedPendingWorkCryptoBackendNextDeadlineResult;
pub const EndpointFeedPendingWorkCryptoBackendDatagramResult = endpoint_types.EndpointFeedPendingWorkCryptoBackendDatagramResult;
pub const EndpointFeedPendingWorkCryptoBackendDatagramDrainResult = endpoint_types.EndpointFeedPendingWorkCryptoBackendDatagramDrainResult;
pub const EndpointFeedInstalledKeyDatagramPollResult = endpoint_types.EndpointFeedInstalledKeyDatagramPollResult;
pub const EndpointFeedInstalledKeyDatagramDrainResult = endpoint_types.EndpointFeedInstalledKeyDatagramDrainResult;
pub const EndpointFeedCryptoBackendDriveNextDeadlineResult = endpoint_types.EndpointFeedCryptoBackendDriveNextDeadlineResult;
pub const EndpointFeedCryptoBackendDriveDatagramResult = endpoint_types.EndpointFeedCryptoBackendDriveDatagramResult;
pub const EndpointFeedCryptoBackendDriveDatagramDrainResult = endpoint_types.EndpointFeedCryptoBackendDriveDatagramDrainResult;
pub const EndpointAcceptedProtectedInitialResponseResult = endpoint_types.EndpointAcceptedProtectedInitialResponseResult;
pub const EndpointAcceptedInitialCryptoBackendNextDeadlineResult = endpoint_types.EndpointAcceptedInitialCryptoBackendNextDeadlineResult;
pub const EndpointAcceptedInitialCryptoBackendDatagramResult = endpoint_types.EndpointAcceptedInitialCryptoBackendDatagramResult;
pub const EndpointAcceptedInitialCryptoBackendDatagramDrainResult = endpoint_types.EndpointAcceptedInitialCryptoBackendDatagramDrainResult;
pub const EndpointRetryProtectedInitialResult = endpoint_types.EndpointRetryProtectedInitialResult;
pub const EndpointAddressValidationResult = endpoint_types.EndpointAddressValidationResult;
pub const FramePacketType = packet_context.FramePacketType;
pub const ProtectedLongDatagramKeys = packet_context.ProtectedLongDatagramKeys;
pub const EcnCodepoint = packet_context.EcnCodepoint;
pub const EcnValidationState = packet_context.EcnValidationState;

pub const AckElicitingSendAdmission = connection_rules.AckElicitingSendAdmission;

const max_quic_varint = protocol_limits.max_quic_varint;
const max_stream_count = protocol_limits.max_stream_count;
const max_connection_id_len = protocol_limits.max_connection_id_len;
const min_initial_destination_connection_id_len = protocol_limits.min_initial_destination_connection_id_len;
const min_initial_udp_datagram_len = protocol_limits.min_initial_udp_datagram_len;
const min_active_connection_id_limit = protocol_limits.min_active_connection_id_limit;
const close_state_pto_multiplier = protocol_limits.close_state_pto_multiplier;
const max_path_challenge_transmissions = protocol_limits.max_path_challenge_transmissions;
const packet_threshold_loss_gap = protocol_limits.packet_threshold_loss_gap;
const anti_amplification_multiplier = protocol_limits.anti_amplification_multiplier;

const EcnAckValidationResult = connection_state.EcnAckValidationResult;
const PendingStreamFrame = connection_state.PendingStreamFrame;
const PendingCryptoFrame = connection_state.PendingCryptoFrame;
const PendingRecvStreamFrame = connection_state.PendingRecvStreamFrame;
const PendingBlockedFrame = connection_state.PendingBlockedFrame;
const PendingMaxFrame = connection_state.PendingMaxFrame;
const PendingCloseFrame = connection_state.PendingCloseFrame;
const PeerCloseSnapshot = connection_state.PeerCloseSnapshot;
const PendingPathChallenge = connection_state.PendingPathChallenge;
const OutstandingPathChallenge = connection_state.OutstandingPathChallenge;
const SentPacket = connection_state.SentPacket;
const RttEstimateSnapshot = connection_state.RttEstimateSnapshot;
const PtoBackoffSnapshot = connection_state.PtoBackoffSnapshot;
const PacketNumberSpaceState = packet_number_space.State;
const PacketNumberSpaceView = packet_number_space.View;
const ReceivedPacketRanges = packet_number_space.ReceivedPacketRanges;
const ActiveConnectionId = connection_state.ActiveConnectionId;
const ActiveConnectionIdSnapshot = connection_state.ActiveConnectionIdSnapshot;
const LocalConnectionId = connection_state.LocalConnectionId;
const LocalConnectionIdSnapshot = connection_state.LocalConnectionIdSnapshot;
const deinitPendingStreamFrameSlice = connection_state.deinitPendingStreamFrameSlice;
const deinitPendingCryptoFrameSlice = connection_state.deinitPendingCryptoFrameSlice;
const deinitSentPacketSlice = connection_state.deinitSentPacketSlice;
const clearSentPacketList = connection_state.clearSentPacketList;
const deinitSentPacketList = connection_state.deinitSentPacketList;
const deinitPendingCloseFrame = connection_state.deinitPendingCloseFrame;
const quicVarIntWireLen = wire_len.quicVarIntWireLen;
const protectedLongDatagramWireLen = wire_len.protectedLongDatagramWireLen;
const protectedLongPlaintextLenForMinDatagram = wire_len.protectedLongPlaintextLenForMinDatagram;
const protectedShortDatagramWireLen = wire_len.protectedShortDatagramWireLen;
const protectedShortPlaintextLenForMinDatagram = wire_len.protectedShortPlaintextLenForMinDatagram;
const addWireLen = wire_len.addWireLen;
const streamFrameWireLen = wire_len.streamFrameWireLen;
const cryptoFrameWireLen = wire_len.cryptoFrameWireLen;
const maxStreamFrameDataLen = wire_len.maxStreamFrameDataLen;
const maxCryptoFrameDataLen = wire_len.maxCryptoFrameDataLen;
const ackFrameWireLen = wire_len.ackFrameWireLen;
const pathResponseFrameWireLen = wire_len.pathResponseFrameWireLen;
const pathChallengeFrameWireLen = wire_len.pathChallengeFrameWireLen;
const pingFrameWireLen = wire_len.pingFrameWireLen;
const resetStreamFrameWireLen = wire_len.resetStreamFrameWireLen;
const stopSendingFrameWireLen = wire_len.stopSendingFrameWireLen;
const retireConnectionIdFrameWireLen = wire_len.retireConnectionIdFrameWireLen;
const newConnectionIdFrameWireLen = wire_len.newConnectionIdFrameWireLen;
const newTokenFrameWireLen = wire_len.newTokenFrameWireLen;
const handshakeDoneFrameWireLen = wire_len.handshakeDoneFrameWireLen;
const closeReasonLenWireLen = wire_len.closeReasonLenWireLen;
const connectionCloseFrameWireLen = wire_len.connectionCloseFrameWireLen;
const applicationCloseFrameWireLen = wire_len.applicationCloseFrameWireLen;
const closeFrameWireLen = wire_len.closeFrameWireLen;
const blockedFrameWireLen = wire_len.blockedFrameWireLen;
const maxFrameWireLen = wire_len.maxFrameWireLen;
const ackFrameRangesAreValid = frame_rules.ackFrameRangesAreValid;
const ackFrameContains = frame_rules.ackFrameContains;
const frameIsAckEliciting = frame_rules.frameIsAckEliciting;
const frameAllowedInPacketNumberSpace = frame_rules.frameAllowedInPacketNumberSpace;
const defaultFramePacketTypeForSpace = frame_rules.defaultFramePacketTypeForSpace;
const packetNumberSpaceForFramePacketType = frame_rules.packetNumberSpaceForFramePacketType;
const frameAllowedInFramePacketType = frame_rules.frameAllowedInFramePacketType;
const zeroEcnCounts = packet_number_space.zeroEcnCounts;
const protectedLongDatagramKeysForSpace = packet_context.protectedLongDatagramKeysForSpace;
const streamEndOffset = stream_id_rules.endOffset;
const streamRangesOverlap = stream_id_rules.rangesOverlap;
const isBidirectionalStream = stream_id_rules.isBidirectional;
const isLocalStreamInitiator = stream_id_rules.isLocalInitiator;
const isLocalBidirectionalStream = stream_id_rules.isLocalBidirectional;
const isLocalUnidirectionalStream = stream_id_rules.isLocalUnidirectional;
const streamCountForId = stream_id_rules.countForId;

const PeerTransportParameterValidationError = connection_rules.PeerTransportParameterValidationError;
const peerTransportParameterValidationErrorAsPublic = connection_rules.peerTransportParameterValidationErrorAsPublic;
const statelessResetTokensEqual = connection_rules.statelessResetTokensEqual;
const validateInitialDestinationConnectionIdLength = connection_rules.validateInitialDestinationConnectionIdLength;

const EndpointConnectionView = @import("../lib.zig").EndpointConnectionView;
const EndpointConnectionPollView = @import("../lib.zig").EndpointConnectionPollView;
const EndpointConnectionInstalledKeyPollView = @import("../lib.zig").EndpointConnectionInstalledKeyPollView;
const EndpointConnectionReceiveView = @import("../lib.zig").EndpointConnectionReceiveView;
const EndpointCryptoBackendDriveView = @import("../lib.zig").EndpointCryptoBackendDriveView;
const EndpointVersionNegotiationHandoffResult = @import("../lib.zig").EndpointVersionNegotiationHandoffResult;
const EndpointVersionNegotiationProtectedInitialResult = @import("../lib.zig").EndpointVersionNegotiationProtectedInitialResult;
const EndpointConnectionLifecycle = @import("endpoint_lifecycle.zig").EndpointConnectionLifecycle;

const BuiltProtectedLongPacket = struct {
    space: PacketNumberSpace,
    packet_number: u64,
    datagram: []u8,
    ack_eliciting: bool,
    close_packet: bool = false,
    sent_stream_frame: ?PendingStreamFrame = null,
    queued_stream_remainder: ?PendingStreamFrame = null,
    sent_reset_stream_frame: ?frame.ResetStreamFrame = null,
    sent_stop_sending_frame: ?frame.StopSendingFrame = null,
    local_original_destination_connection_id: [max_connection_id_len]u8 = undefined,
    local_original_destination_connection_id_len: ?u8 = null,
    local_initial_source_connection_id: [max_connection_id_len]u8 = undefined,
    local_initial_source_connection_id_len: ?u8 = null,
    clear_ack: bool = false,
    consume_ping: bool = false,
    consume_crypto: bool = false,
    consume_reset_stream: bool = false,
    consume_stop_sending: bool = false,
    consume_stream: bool = false,

    fn recordLocalOriginalDestinationConnectionId(self: *BuiltProtectedLongPacket, dcid: ?[]const u8) void {
        const value = dcid orelse return;
        std.debug.assert(value.len <= max_connection_id_len);
        @memcpy(self.local_original_destination_connection_id[0..value.len], value);
        self.local_original_destination_connection_id_len = @intCast(value.len);
    }

    fn recordLocalInitialSourceConnectionId(self: *BuiltProtectedLongPacket, scid: ?[]const u8) void {
        const value = scid orelse return;
        std.debug.assert(value.len <= max_connection_id_len);
        @memcpy(self.local_initial_source_connection_id[0..value.len], value);
        self.local_initial_source_connection_id_len = @intCast(value.len);
    }

    fn deinitSidecars(self: *BuiltProtectedLongPacket, allocator: std.mem.Allocator) void {
        if (self.sent_stream_frame) |pending| {
            allocator.free(pending.data);
            self.sent_stream_frame = null;
        }
        if (self.queued_stream_remainder) |pending| {
            allocator.free(pending.data);
            self.queued_stream_remainder = null;
        }
    }
};

const BuiltProtectedShortPacket = struct {
    packet_number: u64,
    datagram: []u8,
    ack_eliciting: bool,
    sent_stream_frame: ?PendingStreamFrame = null,
    queued_stream_remainder: ?PendingStreamFrame = null,
    sent_reset_stream_frame: ?frame.ResetStreamFrame = null,
    sent_stop_sending_frame: ?frame.StopSendingFrame = null,
    clear_ack: bool = false,
    consume_ping: bool = false,
    consume_crypto: bool = false,
    consume_path_response: bool = false,
    consume_path_challenge: bool = false,
    consume_retire_connection_id: bool = false,
    new_connection_id_index: ?usize = null,
    consume_new_token: bool = false,
    consume_handshake_done: bool = false,
    consume_max_frame: bool = false,
    consume_blocked_frame: bool = false,
    consume_reset_stream: bool = false,
    consume_stop_sending: bool = false,
    consume_stream: bool = false,
    close_packet: bool = false,

    fn deinitSidecars(self: *BuiltProtectedShortPacket, allocator: std.mem.Allocator) void {
        if (self.sent_stream_frame) |pending| {
            allocator.free(pending.data);
            self.sent_stream_frame = null;
        }
        if (self.queued_stream_remainder) |pending| {
            allocator.free(pending.data);
            self.queued_stream_remainder = null;
        }
    }
};

const LossDetectionResult = struct {
    lost_bytes: usize = 0,
    pc_candidate_count: usize = 0,
    pc_first_packet_number: u64 = 0,
    pc_last_packet_number: u64 = 0,
    pc_first_sent_time_nanos: i64 = 0,
    pc_last_sent_time_nanos: i64 = 0,
    pc_contiguous_packet_numbers: bool = true,
    largest_lost_sent_time_nanos: ?i64 = null,
    largest_lost_packet_number: ?u64 = null,

    fn recordLostPacket(self: *LossDetectionResult, sent_packet: SentPacket, first_rtt_sample_sent_time_nanos: ?i64) void {
        self.lost_bytes = std.math.add(usize, self.lost_bytes, sent_packet.bytes) catch std.math.maxInt(usize);
        self.largest_lost_sent_time_nanos = if (self.largest_lost_sent_time_nanos) |current|
            @max(current, sent_packet.sent_time_nanos)
        else
            sent_packet.sent_time_nanos;
        self.largest_lost_packet_number = if (self.largest_lost_packet_number) |current|
            @max(current, sent_packet.packet_number)
        else
            sent_packet.packet_number;

        const first_rtt_sent_time = first_rtt_sample_sent_time_nanos orelse return;
        if (sent_packet.sent_time_nanos <= first_rtt_sent_time) return;

        if (self.pc_candidate_count == 0) {
            self.pc_first_packet_number = sent_packet.packet_number;
            self.pc_last_packet_number = sent_packet.packet_number;
            self.pc_first_sent_time_nanos = sent_packet.sent_time_nanos;
            self.pc_last_sent_time_nanos = sent_packet.sent_time_nanos;
        } else {
            if (sent_packet.packet_number != saturatingAddU64(self.pc_last_packet_number, 1)) {
                self.pc_contiguous_packet_numbers = false;
            }
            self.pc_last_packet_number = sent_packet.packet_number;
            self.pc_last_sent_time_nanos = sent_packet.sent_time_nanos;
        }
        self.pc_candidate_count += 1;
    }

    fn persistentCongestionEstablished(
        self: LossDetectionResult,
        space: PacketNumberSpace,
        recovery_state: recovery.Recovery,
    ) bool {
        if (self.pc_candidate_count < 2 or !self.pc_contiguous_packet_numbers) return false;
        const duration_ns = switch (space) {
            .initial, .handshake => recovery_state.persistentCongestionDurationWithoutMaxAckDelay(),
            .application => recovery_state.persistentCongestionDuration(),
        };
        return elapsed(self.pc_first_sent_time_nanos, self.pc_last_sent_time_nanos) >=
            duration_ns;
    }
};

fn saturatingMulU64(a: u64, b: u64) u64 {
    return std.math.mul(u64, a, b) catch std.math.maxInt(u64);
}

pub fn saturatingAdd(now_nanos: i64, duration_nanos: u64) i64 {
    const duration_i64 = std.math.cast(i64, duration_nanos) orelse return std.math.maxInt(i64);
    return std.math.add(i64, now_nanos, duration_i64) catch std.math.maxInt(i64);
}

fn ptoDeadlineFor(
    sent_packets: []const SentPacket,
    recovery_state: recovery.Recovery,
    include_max_ack_delay: bool,
    pto_count: u8,
) ?i64 {
    var latest_sent_time: ?i64 = null;
    for (sent_packets) |sent_packet| {
        latest_sent_time = if (latest_sent_time) |current|
            @max(current, sent_packet.sent_time_nanos)
        else
            sent_packet.sent_time_nanos;
    }
    const sent_time = latest_sent_time orelse return null;
    var deadline_recovery_state = recovery_state;
    deadline_recovery_state.pto_count = pto_count;
    const pto_ns = if (include_max_ack_delay)
        deadline_recovery_state.ptoNs()
    else
        deadline_recovery_state.ptoNsWithoutMaxAckDelay();
    return saturatingAdd(sent_time, pto_ns);
}

fn ptoDeadlineFromStart(
    start_nanos: i64,
    recovery_state: recovery.Recovery,
    include_max_ack_delay: bool,
    pto_count: u8,
) i64 {
    var deadline_recovery_state = recovery_state;
    deadline_recovery_state.pto_count = pto_count;
    const pto_ns = if (include_max_ack_delay)
        deadline_recovery_state.ptoNs()
    else
        deadline_recovery_state.ptoNsWithoutMaxAckDelay();
    return saturatingAdd(start_nanos, pto_ns);
}

fn saturatingAddU64(a: u64, b: u64) u64 {
    return std.math.add(u64, a, b) catch std.math.maxInt(u64);
}

fn cryptoBackendDrivePolicyClosesOnError(policy: PeerTransportParameterDrivePolicy) bool {
    return switch (policy) {
        .strict, .compatible => false,
        .close_on_error, .compatible_close_on_error => true,
    };
}

fn deinitPeerClose(close: *PeerClose, allocator: std.mem.Allocator) void {
    switch (close.*) {
        .connection => |connection| allocator.free(connection.reason_phrase),
        .application => |application| allocator.free(application.reason_phrase),
    }
}

pub fn elapsed(sent_time_nanos: i64, now_nanos: i64) u64 {
    if (now_nanos <= sent_time_nanos) return 0;
    const delta = std.math.sub(i64, now_nanos, sent_time_nanos) catch return std.math.maxInt(u64);
    return @intCast(delta);
}

pub const framePacketTypeErrorCode = frame_rules.framePacketTypeErrorCode;

const FramePayloadCloseError = frame_payload_module.CloseError;
const rawFrameTypeValue = frame_payload_module.rawFrameTypeValue;
const classifyFramePayloadCloseError = frame_payload_module.classifyCloseError;

const ProtectedLongPacketSpace = struct {
    packet_type: packet.PacketType,
    frame_packet_type: FramePacketType,
};

fn protectedLongPacketSpaceFor(space: PacketNumberSpace) ?ProtectedLongPacketSpace {
    return switch (space) {
        .initial => .{ .packet_type = .initial, .frame_packet_type = .initial },
        .handshake => .{ .packet_type = .handshake, .frame_packet_type = .handshake },
        .application => null,
    };
}

const ProtectedLongPacketRoute = struct {
    space: PacketNumberSpace,
    packet_type: packet.PacketType,
    frame_packet_type: FramePacketType,
    keys: protection.Aes128PacketProtectionKeys,
};

fn protectedLongPacketRouteFor(
    keys: ProtectedLongDatagramKeys,
    packet_type: packet.PacketType,
) ?ProtectedLongPacketRoute {
    return switch (packet_type) {
        .initial => if (keys.initial) |initial_keys| .{
            .space = .initial,
            .packet_type = .initial,
            .frame_packet_type = .initial,
            .keys = initial_keys,
        } else null,
        .zero_rtt => if (keys.zero_rtt) |zero_rtt_keys| .{
            .space = .application,
            .packet_type = .zero_rtt,
            .frame_packet_type = .zero_rtt,
            .keys = zero_rtt_keys,
        } else null,
        .handshake => if (keys.handshake) |handshake_keys| .{
            .space = .handshake,
            .packet_type = .handshake,
            .frame_packet_type = .handshake,
            .keys = handshake_keys,
        } else null,
        .retry => null,
    };
}

const SendStreamState = struct {
    stream_id: u64,
    next_offset: u64 = 0,
    max_data: u64,
    fin_sent: bool = false,
    fin_acked: bool = false,
    data_acked: bool = false,
    reset_sent: bool = false,
    reset_acked: bool = false,
};

fn sendStreamClosed(stream_state: *const SendStreamState) bool {
    return stream_state.fin_sent or stream_state.reset_sent;
}

fn publicSendStreamState(stream_state: *const SendStreamState) StreamSendState {
    if (stream_state.reset_acked) return .reset_acked;
    if (stream_state.reset_sent) return .reset_sent;
    if (stream_state.data_acked) return .data_acked;
    if (stream_state.fin_sent) return .data_sent;
    return .ready;
}

fn markSentPacketAckedOnStreams(conn: *Connection, sent_packet: SentPacket) void {
    if (sent_packet.stream_frame) |pending| {
        if (pending.fin) {
            if (conn.findSendStream(pending.stream_id)) |stream_state| {
                stream_state.fin_acked = true;
            }
        }
    }
    if (sent_packet.reset_stream_frame) |reset| {
        if (conn.findSendStream(reset.stream_id)) |stream_state| {
            stream_state.reset_acked = true;
        }
    }
}

fn streamHasQueuedSendData(conn: *const Connection, stream_id: u64) bool {
    for (conn.send_queue.items) |pending| {
        if (pending.stream_id == stream_id) return true;
    }
    return false;
}

fn streamHasOutstandingSendData(conn: *const Connection, stream_id: u64) bool {
    for (conn.sent_packets.items) |sent_packet| {
        if (sent_packet.stream_frame) |pending| {
            if (pending.stream_id == stream_id) return true;
        }
    }
    return false;
}

fn refreshSendDataAckedStates(conn: *Connection) void {
    for (conn.send_streams.items) |*stream_state| {
        if (!stream_state.fin_acked or stream_state.reset_sent) continue;
        stream_state.data_acked = !streamHasQueuedSendData(conn, stream_state.stream_id) and
            !streamHasOutstandingSendData(conn, stream_state.stream_id);
    }
}

fn resetStreamFrameAlreadyAcked(conn: *Connection, reset: frame.ResetStreamFrame) bool {
    const stream_state = conn.findSendStream(reset.stream_id) orelse return false;
    return stream_state.reset_acked;
}

const RecvStreamState = struct {
    stream_id: u64,
    max_data: u64,
    data: std.ArrayList(u8) = .empty,
    pending: std.ArrayList(PendingRecvStreamFrame) = .empty,
    read_offset: usize = 0,
    final_size: ?u64 = null,
    reset_error_code: ?u64 = null,
    data_read_observed: bool = false,
    reset_read_observed: bool = false,
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
    data_read_observed: bool,
    reset_read_observed: bool,
    stop_sending_sent: bool,
    stream_count_credit_released: bool,
};

fn receiveBufferedByteCountForSnapshot(stream_state: *const RecvStreamState) u64 {
    var received = std.math.cast(u64, stream_state.data.items.len) orelse return std.math.maxInt(u64);
    for (stream_state.pending.items) |pending| {
        const pending_len = std.math.cast(u64, pending.data.len) orelse return std.math.maxInt(u64);
        received = saturatingAddU64(received, pending_len);
    }
    return received;
}

fn receiveReadOffsetForSnapshot(stream_state: *const RecvStreamState) u64 {
    return std.math.cast(u64, stream_state.read_offset) orelse std.math.maxInt(u64);
}

fn publicReceiveStreamState(stream_state: *const RecvStreamState) StreamReceiveState {
    if (stream_state.reset_error_code != null) {
        return if (stream_state.reset_read_observed) .reset_read else .reset_received;
    }
    if (stream_state.data_read_observed) return .data_read;

    const final_size = stream_state.final_size orelse return .receiving;
    const final_size_usize = std.math.cast(usize, final_size) orelse return .size_known;
    if (stream_state.data.items.len >= final_size_usize) return .data_received;
    return .size_known;
}

fn markReceiveDataReadIfComplete(stream_state: *RecvStreamState) void {
    if (stream_state.reset_error_code != null) return;
    const final_size = stream_state.final_size orelse return;
    const final_size_usize = std.math.cast(usize, final_size) orelse return;
    if (stream_state.data.items.len >= final_size_usize and stream_state.read_offset >= final_size_usize) {
        stream_state.data_read_observed = true;
    }
}

const PeerStreamDataBlockedState = struct {
    stream_id: u64,
    maximum_stream_data: u64,
};

/// Experimental QUIC connection handle.
///
/// The current implementation only moves unencrypted frame payload bytes through
/// the public API. Packet protection, TLS, and network I/O are intentionally
/// outside this connection skeleton.
/// Aggregate connection health/diagnostics counters for observability.
pub const ConnectionStats = struct {
    /// Application-level stream bytes sent by this endpoint.
    stream_bytes_sent: u64,
    /// Application-level stream bytes received by this endpoint.
    stream_bytes_received: u64,
    /// Total bytes currently in flight (ack-eliciting, application space).
    total_bytes_in_flight: usize,
    /// Smoothed RTT in microseconds (application space).
    smoothed_rtt_us: u64,
    /// RTT variance in microseconds (application space).
    rttvar_us: u64,
    /// Current congestion window in bytes (application space).
    congestion_window: usize,
    /// Cumulative packets declared lost (application space).
    packets_lost: u64,
    /// Cumulative retransmissions (application space).
    packets_retransmitted: u64,
    /// Largest acknowledged packet number (application space).
    largest_acked_packet_number: ?u64,
};

pub const Connection = struct {
    allocator: std.mem.Allocator,
    config: Config,
    /// Optional qlog event writer. Non-null when QLOG_DIR is set.
    qlog_writer: ?*qlog_module.QlogWriter = null,
    side: ConnectionSide,
    peer_address_validated: bool,
    peer_address_bytes_received: usize,
    peer_address_bytes_sent: usize,
    /// Multipath manager (null when multipath is disabled).
    multipath: ?multipath_module.MultipathManager = null,
    peer_max_idle_timeout_ms: u64,
    peer_disable_active_migration: bool,
    peer_stateless_reset_token: ?[packet.stateless_reset_token_len]u8,
    peer_preferred_address: ?PreferredAddress,
    peer_version_information_chosen_version: ?packet.Version,
    peer_version_information_available_versions: ?[]packet.Version,
    last_packet_activity_nanos: ?i64,
    next_stream_id: u64,
    next_uni_stream_id: u64,
    initial_packet_space: PacketNumberSpaceState,
    handshake_packet_space: PacketNumberSpaceState,
    next_packet_number: u64,
    application_packet_space_discarded: bool,
    next_peer_packet_number: u64,
    pending_ack_largest: ?u64,
    received_packet_ranges: ReceivedPacketRanges,
    pending_path_responses: std.ArrayList([8]u8),
    pending_path_challenges: std.ArrayList(PendingPathChallenge),
    outstanding_path_challenges: std.ArrayList(OutstandingPathChallenge),
    failed_path_validations: usize,
    active_connection_ids: std.ArrayList(ActiveConnectionId),
    local_connection_ids: std.ArrayList(LocalConnectionId),
    next_local_connection_id_sequence: u64,
    peer_active_connection_id_limit: u64,
    largest_peer_retire_prior_to: u64,
    pending_retire_connection_ids: std.ArrayList(u64),
    stored_new_tokens: std.ArrayList([]u8),
    pending_new_tokens: std.ArrayList([]u8),
    retry_token: ?[]u8,
    version_negotiation_selected_version: ?packet.Version,
    local_initial_source_connection_id: [max_connection_id_len]u8,
    local_initial_source_connection_id_len: ?u8,
    peer_initial_source_connection_id: ?[]u8,
    original_destination_connection_id: [max_connection_id_len]u8,
    original_destination_connection_id_len: ?u8,
    retry_source_connection_id: ?[]u8,
    retry_tokens: std.ArrayList([]u8),
    pending_blocked_frames: std.ArrayList(PendingBlockedFrame),
    pending_max_frames: std.ArrayList(PendingMaxFrame),
    pending_ping_count: usize,
    pto_probe_count: usize,
    congestion_probe_count: usize,
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
    first_rtt_sample_sent_time_nanos: ?i64,
    loss_deadline_nanos: ?i64,
    anti_deadlock_pto_start_nanos: ?i64,
    ecn_sent_ect0: u64,
    ecn_sent_ect1: u64,
    ecn_largest_acknowledged: ?u64,
    ecn_counts: frame.EcnCounts,
    ecn_validation_state: EcnValidationState,
    crypto_send_offset: u64,
    crypto_recv_buffer: std.ArrayList(u8),
    crypto_read_offset: usize,
    crypto_send_queue: std.ArrayList(PendingCryptoFrame),
    crypto_recv_pending: std.ArrayList(PendingCryptoFrame),
    send_queue: std.ArrayList(PendingStreamFrame),
    /// Token bucket pacer for ack-eliciting packet transmission.
    tx_pacer: pacer_module.Pacer,
    /// Set only when protected packet polling encounters the pacing gate.
    pacing_send_deadline: ?i64 = null,
    /// RFC 9221 outgoing DATAGRAM payloads queued by sendDatagram().
    pending_datagrams: std.ArrayList([]const u8),
    /// RFC 9221 incoming DATAGRAM payloads received from peer.
    received_datagrams: std.ArrayList([]const u8),
    pending_reset_streams: std.ArrayList(frame.ResetStreamFrame),
    pending_stop_sending: std.ArrayList(frame.StopSendingFrame),
    send_streams: std.ArrayList(SendStreamState),
    recv_streams: std.ArrayList(RecvStreamState),
    spin_bit_value: bool,
    local_handshake_keys: ?protection.Aes128PacketProtectionKeys,
    peer_handshake_keys: ?protection.Aes128PacketProtectionKeys,
    local_zero_rtt_keys: ?protection.Aes128PacketProtectionKeys,
    peer_zero_rtt_keys: ?protection.Aes128PacketProtectionKeys,
    peer_zero_rtt_accepted: bool,
    local_one_rtt_key_phase_state: ?protection.Aes128KeyPhaseState,
    peer_one_rtt_key_phase_state: ?protection.Aes128KeyPhaseState,
    local_one_rtt_key_update_ack_threshold: ?u64,
    /// Negotiated TLS cipher suite for Handshake/1-RTT key derivation.
    negotiated_cipher: protection.CipherSuite = .aes_128_gcm,
    handshake_state: HandshakeState,
    handshake_confirmed: bool,
    pending_handshake_done: bool,
    handshake_done_sent: bool,
    peer_close: ?PeerClose,
    pending_close: ?PendingCloseFrame,
    state: ConnectionState,
    close_deadline_nanos: ?i64,
    closed: bool,

    /// Create a connection with empty send and receive state.
    pub fn init(
        allocator: std.mem.Allocator,
        side: ConnectionSide,
        config: Config,
    ) !Connection {
        if (config.initial_max_streams_bidi > max_stream_count or config.initial_max_streams_uni > max_stream_count) {
            return error.InvalidStream;
        }
        if (config.active_connection_id_limit < min_active_connection_id_limit) {
            return error.InvalidPacket;
        }
        if (config.max_datagram_size > transport_parameters.max_udp_payload_size_default) {
            return error.InvalidPacket;
        }
        if (config.max_idle_timeout_ms > max_quic_varint) {
            return error.InvalidPacket;
        }
        if (config.initial_max_data > max_quic_varint or config.initial_max_stream_data > max_quic_varint) {
            return error.InvalidPacket;
        }
        if (config.active_connection_id_limit > max_quic_varint) {
            return error.InvalidPacket;
        }
        if (config.ack_delay_exponent > 20) {
            return error.InvalidPacket;
        }
        if (duration_mod.nanosToMillis(@intCast(config.max_ack_delay_ns)) >= (@as(i64, 1) << 14)) {
            return error.InvalidPacket;
        }
        if (config.max_crypto_buffer_size > max_quic_varint) {
            return error.InvalidPacket;
        }
        if (config.receive_connection_window) |window| {
            if (window > max_quic_varint) return error.InvalidPacket;
        }
        if (config.receive_stream_window) |window| {
            if (window > max_quic_varint) return error.InvalidPacket;
        }
        if (config.receive_stream_count_window) |window| {
            if (window > max_stream_count) return error.InvalidStream;
        }
        if (side == .client and config.preferred_address != null) {
            return error.InvalidPacket;
        }
        try connection_version.validateLocalVersionInformation(side, config);

        var conn = Connection{
            .allocator = allocator,
            .config = config,
            .side = side,
            .peer_address_validated = side == .client,
            .peer_address_bytes_received = 0,
            .peer_address_bytes_sent = 0,
            .peer_max_idle_timeout_ms = 0,
            .peer_disable_active_migration = false,
            .peer_stateless_reset_token = null,
            .peer_preferred_address = null,
            .peer_version_information_chosen_version = null,
            .peer_version_information_available_versions = null,
            .last_packet_activity_nanos = null,
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
            .received_packet_ranges = .{},
            .pending_path_responses = .empty,
            .pending_path_challenges = .empty,
            .outstanding_path_challenges = .empty,
            .failed_path_validations = 0,
            .active_connection_ids = .empty,
            .local_connection_ids = .empty,
            .next_local_connection_id_sequence = 0,
            .peer_active_connection_id_limit = min_active_connection_id_limit,
            .largest_peer_retire_prior_to = 0,
            .pending_retire_connection_ids = .empty,
            .stored_new_tokens = .empty,
            .pending_new_tokens = .empty,
            .retry_token = null,
            .version_negotiation_selected_version = config.version_negotiation_selected_version,
            .local_initial_source_connection_id = undefined,
            .local_initial_source_connection_id_len = null,
            .peer_initial_source_connection_id = null,
            .original_destination_connection_id = undefined,
            .original_destination_connection_id_len = null,
            .retry_source_connection_id = null,
            .retry_tokens = .empty,
            .pending_blocked_frames = .empty,
            .pending_max_frames = .empty,
            .pending_ping_count = 0,
            .pto_probe_count = 0,
            .congestion_probe_count = 0,
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
                .initial_rtt_ns = config.initial_rtt_ns,
                .max_ack_delay_ns = config.max_ack_delay_ns,
                .congestion_algorithm = config.congestion_algorithm,
                .pto_jitter_percentage = config.pto_jitter_percentage,
            }),
            .sent_packets = .empty,
            .largest_acknowledged = null,
            .first_rtt_sample_sent_time_nanos = null,
            .loss_deadline_nanos = null,
            .anti_deadlock_pto_start_nanos = null,
            .ecn_sent_ect0 = 0,
            .ecn_sent_ect1 = 0,
            .ecn_largest_acknowledged = null,
            .ecn_counts = zeroEcnCounts(),
            .ecn_validation_state = .unknown,
            .crypto_send_offset = 0,
            .crypto_recv_buffer = .empty,
            .crypto_read_offset = 0,
            .crypto_send_queue = .empty,
            .crypto_recv_pending = .empty,
            .send_queue = .empty,
            .tx_pacer = pacer_module.Pacer.init(config.max_datagram_size),
            .pending_datagrams = .empty,
            .received_datagrams = .empty,
            .pending_reset_streams = .empty,
            .pending_stop_sending = .empty,
            .send_streams = .empty,
            .recv_streams = .empty,
            .spin_bit_value = false,
            .local_handshake_keys = null,
            .peer_handshake_keys = null,
            .local_zero_rtt_keys = null,
            .peer_zero_rtt_keys = null,
            .peer_zero_rtt_accepted = false,
            .local_one_rtt_key_phase_state = null,
            .peer_one_rtt_key_phase_state = null,
            .local_one_rtt_key_update_ack_threshold = null,
            .handshake_state = .initial,
            .handshake_confirmed = false,
            .pending_handshake_done = false,
            .handshake_done_sent = false,
            .peer_close = null,
            .pending_close = null,
            .state = .active,
            .close_deadline_nanos = null,
            .closed = false,
        };
        if (config.initial_congestion_window_packets) |pkts| {
            conn.recovery_state.congestion_window = pkts * @as(usize, config.max_datagram_size);
        }
        return conn;
    }

    /// Release all buffers owned by this connection.
    pub fn deinit(self: *Connection) void {
        self.initial_packet_space.deinit(self.allocator);
        self.handshake_packet_space.deinit(self.allocator);
        for (self.crypto_send_queue.items) |pending| {
            self.allocator.free(pending.data);
        }
        for (self.crypto_recv_pending.items) |pending| {
            self.allocator.free(pending.data);
        }
        for (self.send_queue.items) |pending| {
            self.allocator.free(pending.data);
        }
        deinitSentPacketList(self.allocator, &self.sent_packets);
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
        for (self.pending_new_tokens.items) |token| {
            self.allocator.free(token);
        }
        self.pending_new_tokens.deinit(self.allocator);
        if (self.retry_token) |token| self.allocator.free(token);
        if (self.peer_initial_source_connection_id) |cid| self.allocator.free(cid);
        if (self.retry_source_connection_id) |cid| self.allocator.free(cid);
        if (self.peer_version_information_available_versions) |versions| self.allocator.free(versions);
        for (self.retry_tokens.items) |token| {
            self.allocator.free(token);
        }
        self.retry_tokens.deinit(self.allocator);
        self.pending_blocked_frames.deinit(self.allocator);
        self.pending_max_frames.deinit(self.allocator);
        self.peer_stream_data_blocked_limits.deinit(self.allocator);
        self.crypto_recv_buffer.deinit(self.allocator);
        self.crypto_send_queue.deinit(self.allocator);
        self.crypto_recv_pending.deinit(self.allocator);
        self.send_queue.deinit(self.allocator);
        for (self.pending_datagrams.items) |d| self.allocator.free(d);
        self.pending_datagrams.deinit(self.allocator);
        for (self.received_datagrams.items) |d| self.allocator.free(d);
        self.received_datagrams.deinit(self.allocator);
        self.pending_reset_streams.deinit(self.allocator);
        self.pending_stop_sending.deinit(self.allocator);
        self.send_streams.deinit(self.allocator);
        for (self.recv_streams.items) |*stream| {
            stream.deinit(self.allocator);
        }
        self.clearPeerClose();
        self.clearPendingCloseFrame();
        self.recv_streams.deinit(self.allocator);
    }

    /// Return the current modeled connection lifecycle state.
    pub fn connectionState(self: Connection) ConnectionState {
        return self.state;
    }

    /// Return the error code of the queued transport/application CONNECTION_CLOSE,
    /// or null when no close is pending. Endpoint loops can observe the close
    /// reason (e.g. KEY_UPDATE_ERROR) without draining the emitted frame.
    pub fn pendingCloseErrorCode(self: Connection) ?u64 {
        const pending = self.pending_close orelse return null;
        return switch (pending) {
            .connection => |c| c.error_code,
            .application => |a| a.error_code,
        };
    }

    /// Return the close/drain deadline in milliseconds, or null when no timer is active.
    pub fn closeDeadline(self: Connection) ?i64 {
        return self.close_deadline_nanos;
    }

    /// Return the peer close frame that moved this connection into draining, if any.
    pub fn peerClose(self: Connection) ?PeerClose {
        return self.peer_close;
    }

    /// Return a read-only stream state snapshot, or null if the stream is unknown.
    ///
    /// The `stream_id` must fit QUIC's variable-length integer space. This API
    /// does not create stream state and does not validate whether an unopened ID
    /// would be legal for this endpoint; it only reports state already observed
    /// or opened by the connection.
    pub fn streamState(self: Connection, stream_id: u64) Error!?StreamState {
        if (stream_id > max_quic_varint) return error.InvalidStream;

        var send_state: ?*const SendStreamState = null;
        for (self.send_streams.items) |*stream| {
            if (stream.stream_id == stream_id) {
                send_state = stream;
                break;
            }
        }

        var recv_state: ?*const RecvStreamState = null;
        for (self.recv_streams.items) |*stream| {
            if (stream.stream_id == stream_id) {
                recv_state = stream;
                break;
            }
        }

        if (send_state == null and recv_state == null) return null;

        return .{
            .stream_id = stream_id,
            .send = if (send_state) |state| publicSendStreamState(state) else .none,
            .receive = if (recv_state) |state| publicReceiveStreamState(state) else .none,
            .send_offset = if (send_state) |state| state.next_offset else null,
            .send_max_data = if (send_state) |state| state.max_data else null,
            .receive_buffered = if (recv_state) |state| receiveBufferedByteCountForSnapshot(state) else null,
            .receive_read_offset = if (recv_state) |state| receiveReadOffsetForSnapshot(state) else null,
            .receive_stop_sending_sent = if (recv_state) |state| state.stop_sending_sent else null,
            .receive_final_size = if (recv_state) |state| state.final_size else null,
            .receive_reset_error_code = if (recv_state) |state| state.reset_error_code else null,
        };
    }

    /// Return the effective max idle timeout in milliseconds, or null when disabled.
    ///
    /// RFC 9000 uses the shorter non-zero timeout advertised by either endpoint.
    /// A zero value from one side means that side has no preference; both zero
    /// disables idle timeout handling in this frame-payload model.
    pub fn effectiveIdleTimeout(self: Connection) ?u64 {
        const local = self.config.max_idle_timeout_ms;
        const peer = self.peer_max_idle_timeout_ms;
        if (local == 0 and peer == 0) return null;
        if (local == 0) return peer;
        if (peer == 0) return local;
        return @min(local, peer);
    }

    /// Return the current idle timeout deadline, or null when the timer is inactive.
    pub fn idleTimeoutDeadline(self: Connection) ?i64 {
        const idle_timeout = self.effectiveIdleTimeout() orelse return null;
        const last_activity = self.last_packet_activity_nanos orelse return null;
        return saturatingAdd(last_activity, @intCast(duration_mod.millisToNanos(@intCast(idle_timeout))));
    }

    /// Return whether the peer disabled active connection migration.
    ///
    /// Endpoint routing does not exist yet, so this currently records the peer
    /// transport parameter for later migration-policy enforcement.
    pub fn peerActiveMigrationDisabled(self: Connection) bool {
        return self.peer_disable_active_migration;
    }

    /// Return the peer stateless reset token from transport parameters, if any.
    ///
    /// RFC 9000 permits this as a server transport parameter. The existing
    /// `detectStatelessReset()` API still reports NEW_CONNECTION_ID sequence
    /// numbers only; this getter lets a future packet endpoint bind the
    /// handshake CID token without changing that API's return meaning.
    pub fn peerStatelessResetToken(self: Connection) ?[packet.stateless_reset_token_len]u8 {
        return self.peer_stateless_reset_token;
    }

    /// Return the server preferred address learned from peer transport parameters.
    ///
    /// The value is copied into connection-owned fixed storage when peer
    /// parameters are applied. The current skeleton only exposes it for future
    /// endpoint migration policy; it does not automatically migrate sockets.
    pub fn peerPreferredAddress(self: Connection) ?PreferredAddress {
        return self.peer_preferred_address;
    }

    /// Return the peer's authenticated Version Information, if applied.
    ///
    /// The returned Available Versions slice is connection-owned and remains
    /// valid until the next peer transport-parameter application or deinit.
    pub fn peerVersionInformation(self: Connection) ?transport_parameters.VersionInformation {
        const chosen_version = self.peer_version_information_chosen_version orelse return null;
        const available_versions = self.peer_version_information_available_versions orelse return null;
        return .{
            .chosen_version = chosen_version,
            .available_versions = available_versions,
        };
    }

    /// Select the server's compatible version from stored peer Version Information.
    ///
    /// This is a read-only convenience around `selectCompatibleVersion()`.
    /// Callers must provide the explicit directional first-flight compatibility
    /// relation; this helper does not assume any non-identity compatibility.
    pub fn selectPeerCompatibleVersion(
        self: Connection,
        compatibilities: []const VersionCompatibility,
    ) Error!?packet.Version {
        if (self.side != .server) return error.InvalidPacket;
        const version_information = self.peerVersionInformation() orelse return null;
        return selectCompatibleVersion(self.config.available_versions, version_information, compatibilities);
    }

    /// Return whether the peer address is considered validated for send limits.
    ///
    /// Clients are initialized as validated because RFC 9000 anti-amplification
    /// limits apply to servers before they validate the client's address.
    pub fn peerAddressValidated(self: Connection) bool {
        return self.peer_address_validated;
    }

    /// Record received datagram bytes for the modeled server anti-amplification budget.
    ///
    /// This explicit hook is used until UDP packet I/O exists. It increases the
    /// amount an unvalidated server address may send to three times the recorded
    /// received bytes. Validated peers and clients do not need this budget.
    pub fn recordPeerAddressBytesReceived(self: *Connection, bytes: usize) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (!self.isAntiAmplificationLimited()) return;
        self.peer_address_bytes_received = std.math.add(usize, self.peer_address_bytes_received, bytes) catch std.math.maxInt(usize);
    }

    /// Record one received datagram and immediately service an expired recovery timer.
    ///
    /// RFC 9002 requires a server that was blocked by anti-amplification limits
    /// to re-arm PTO when a datagram grants new send credit. If that PTO would
    /// already have expired while the server was blocked, this helper services
    /// the aggregate loss detection timer with the supplied controlled clock.
    pub fn recordPeerAddressDatagramReceived(
        self: *Connection,
        now_nanos: i64,
        bytes: usize,
    ) Error!?LossDetectionTimerDeadline {
        const was_at_limit = self.serverAtAntiAmplificationLimit();
        try self.recordPeerAddressBytesReceived(bytes);
        if (!was_at_limit) return null;
        return try self.serviceLossDetectionTimer(now_nanos);
    }

    /// Mark the peer address as validated and lift the modeled anti-amplification limit.
    ///
    /// Future TLS, Retry-token, or path-validation integrations can call this
    /// after proving that the peer receives packets at its claimed address.
    pub fn validatePeerAddress(self: *Connection) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        self.peer_address_validated = true;
    }

    /// Enable multipath support for this connection.
    pub fn enableMultipath(self: *Connection, allocator: std.mem.Allocator) !void {
        if (self.multipath != null) return;
        var mp = multipath_module.MultipathManager.init(allocator);
        _ = try mp.addPath();
        self.multipath = mp;
    }

    /// Whether multipath is enabled.
    pub fn isMultipathEnabled(self: *const Connection) bool {
        return self.multipath != null;
    }

    /// Return the number of active paths (multipath).
    pub fn activePathCount(self: *const Connection) usize {
        return if (self.multipath) |mp| mp.activePathCount() else 1;
    }

    /// Abandon a path (multipath).
    pub fn abandonPath(self: *Connection, path_id: u64) !void {
        if (self.multipath) |*mp| {
            try mp.abandonPath(path_id);
        }
    }

    /// Return remaining server anti-amplification bytes, or null when unrestricted.
    pub fn antiAmplificationLimitRemaining(self: Connection) ?usize {
        if (!self.isAntiAmplificationLimited()) return null;
        const limit = std.math.mul(usize, self.peer_address_bytes_received, anti_amplification_multiplier) catch std.math.maxInt(usize);
        if (self.peer_address_bytes_sent >= limit) return 0;
        return limit - self.peer_address_bytes_sent;
    }

    /// Return the next packet number for a packet number space.
    pub fn nextPacketNumber(self: Connection, space: PacketNumberSpace) u64 {
        return switch (space) {
            .initial => self.initial_packet_space.next_packet_number,
            .handshake => self.handshake_packet_space.next_packet_number,
            .application => self.next_packet_number,
        };
    }

    /// Return the next peer packet number modeled for receive-side ACK generation.
    pub fn nextPeerPacketNumber(self: Connection, space: PacketNumberSpace) u64 {
        return switch (space) {
            .initial => self.initial_packet_space.next_peer_packet_number,
            .handshake => self.handshake_packet_space.next_peer_packet_number,
            .application => self.next_peer_packet_number,
        };
    }

    /// Return the largest packet number awaiting ACK emission in a packet number space.
    pub fn pendingAckLargest(self: Connection, space: PacketNumberSpace) ?u64 {
        return switch (space) {
            .initial => self.initial_packet_space.pending_ack_largest,
            .handshake => self.handshake_packet_space.pending_ack_largest,
            .application => self.pending_ack_largest,
        };
    }

    /// Return whether a packet number space has been discarded.
    pub fn packetNumberSpaceDiscarded(self: Connection, space: PacketNumberSpace) bool {
        return switch (space) {
            .initial => self.initial_packet_space.discarded,
            .handshake => self.handshake_packet_space.discarded,
            .application => self.application_packet_space_discarded,
        };
    }

    /// Return the count of sent packets tracked for ACK-driven recovery in one space.
    pub fn sentPacketCount(self: Connection, space: PacketNumberSpace) usize {
        return switch (space) {
            .initial => self.initial_packet_space.sent_packets.items.len,
            .handshake => self.handshake_packet_space.sent_packets.items.len,
            .application => self.sent_packets.items.len,
        };
    }

    /// Return bytes in flight for one packet number space.
    pub fn bytesInFlight(self: Connection, space: PacketNumberSpace) usize {
        return switch (space) {
            .initial => self.initial_packet_space.recovery_state.bytes_in_flight,
            .handshake => self.handshake_packet_space.recovery_state.bytes_in_flight,
            .application => self.recovery_state.bytes_in_flight,
        };
    }

    /// Return connection-level bytes in flight across all packet number spaces.
    pub fn totalBytesInFlight(self: Connection) usize {
        const initial_and_handshake =
            std.math.add(usize, self.bytesInFlight(.initial), self.bytesInFlight(.handshake)) catch std.math.maxInt(usize);
        return std.math.add(usize, initial_and_handshake, self.bytesInFlight(.application)) catch std.math.maxInt(usize);
    }

    /// Return the congestion window for one packet number space's recovery state.
    pub fn congestionWindow(self: Connection, space: PacketNumberSpace) usize {
        return switch (space) {
            .initial => self.initial_packet_space.recovery_state.congestion_window,
            .handshake => self.handshake_packet_space.recovery_state.congestion_window,
            .application => self.recovery_state.congestion_window,
        };
    }

    /// Return the remaining congestion-window budget for one packet number space.
    ///
    /// The current congestion admission model uses connection-level bytes in
    /// flight against the selected packet number space's congestion window.
    pub fn availableCongestionWindow(self: Connection, space: PacketNumberSpace) usize {
        const window = self.congestionWindow(space);
        const in_flight = self.totalBytesInFlight();
        if (in_flight >= window) return 0;
        return window - in_flight;
    }

    /// Return whether ack-eliciting sends are currently congestion-window limited.
    pub fn congestionWindowFull(self: Connection, space: PacketNumberSpace) bool {
        return self.availableCongestionWindow(space) == 0;
    }

    /// Return the effective ack-eliciting send-admission budget for one space.
    ///
    /// A null result means the connection currently has no send-admission cap
    /// for this space, for example when a PTO or congestion probe may bypass
    /// the congestion window and the peer address is not anti-amplification
    /// limited.
    pub fn availableAckElicitingSendBudget(self: *Connection, space: PacketNumberSpace) ?usize {
        const packet_space = self.packetNumberSpace(space);
        const congestion_budget: ?usize = if (packet_space.pto_probe_count.* != 0 or
            packet_space.congestion_probe_count.* != 0)
            null
        else
            self.availableCongestionWindow(space);
        const peer_budget = self.antiAmplificationLimitRemaining();

        if (congestion_budget) |congestion_remaining| {
            if (peer_budget) |peer_remaining| return @min(congestion_remaining, peer_remaining);
            return congestion_remaining;
        }

        return peer_budget;
    }

    /// Return the first send-admission result for one ack-eliciting payload.
    ///
    /// The ordering matches the commit path: congestion/probe admission is
    /// checked before the peer-address anti-amplification budget.
    pub fn ackElicitingSendAdmission(
        self: *Connection,
        space: PacketNumberSpace,
        bytes: usize,
    ) AckElicitingSendAdmission {
        if (!self.canSendAckElicitingInSpace(space, bytes)) return .congestion_limited;
        if (!self.canSendToPeerAddress(bytes)) return .anti_amplification_limited;
        return .allowed;
    }

    /// Return whether `bytes` can be sent as ack-eliciting payload in one space.
    ///
    /// This mirrors the connection's send admission checks: PTO/congestion
    /// probes may bypass the congestion window, but peer-address
    /// anti-amplification limits still apply.
    pub fn canSendAckEliciting(self: *Connection, space: PacketNumberSpace, bytes: usize) bool {
        return self.ackElicitingSendAdmission(space, bytes) == .allowed;
    }

    /// Return the current smoothed RTT estimate for one packet number space.
    pub fn smoothedRtt(self: Connection, space: PacketNumberSpace) u64 {
        const ns = switch (space) {
            .initial => self.initial_packet_space.recovery_state.smoothed_rtt_ns,
            .handshake => self.handshake_packet_space.recovery_state.smoothed_rtt_ns,
            .application => self.recovery_state.smoothed_rtt_ns,
        };
        return @intCast(duration_mod.nanosToMillis(@intCast(ns)));
    }

    /// Return aggregate connection health/diagnostics counters.
    pub fn connectionStats(self: Connection) ConnectionStats {
        const app = self.recovery_state;
        return .{
            .stream_bytes_sent = self.sent_stream_data_bytes,
            .stream_bytes_received = self.recv_data_bytes,
            .total_bytes_in_flight = self.totalBytesInFlight(),
            .smoothed_rtt_us = @intCast(app.smoothed_rtt_ns / @as(u64, duration_mod.ns_per_us)),
            .rttvar_us = @intCast(app.rttvar_ns / @as(u64, duration_mod.ns_per_us)),
            .congestion_window = app.congestion_window,
            .packets_lost = app.packets_lost,
            .packets_retransmitted = app.packets_retransmitted,
            .largest_acked_packet_number = app.largest_acked_packet_number,
        };
    }

    /// Return the current time-threshold loss deadline for one packet number space.
    pub fn lossDetectionDeadline(self: Connection, space: PacketNumberSpace) ?i64 {
        return switch (space) {
            .initial => self.initial_packet_space.loss_deadline_nanos,
            .handshake => self.handshake_packet_space.loss_deadline_nanos,
            .application => self.loss_deadline_nanos,
        };
    }

    /// Return the modeled PTO deadline for one packet number space.
    ///
    /// This uses the latest ack-eliciting packet tracked in the selected space
    /// and the connection-level PTO backoff count. ACK-only payloads are not
    /// tracked in `sent_packets`, so they do not arm PTO. RFC 9002 forbids
    /// arming Application Data PTO before the handshake is confirmed, and
    /// disarms PTO while an unvalidated server has no anti-amplification credit.
    pub fn ptoDeadline(self: Connection, space: PacketNumberSpace) ?i64 {
        if (!self.ptoAllowedInSpace(space)) return null;
        const pto_count = self.connectionPtoBackoffCount();
        return switch (space) {
            .initial => ptoDeadlineFor(self.initial_packet_space.sent_packets.items, self.initial_packet_space.recovery_state, false, pto_count) orelse
                self.antiDeadlockPtoDeadline(.initial, pto_count),
            .handshake => ptoDeadlineFor(self.handshake_packet_space.sent_packets.items, self.handshake_packet_space.recovery_state, false, pto_count) orelse
                self.antiDeadlockPtoDeadline(.handshake, pto_count),
            .application => ptoDeadlineFor(self.sent_packets.items, self.recovery_state, true, pto_count),
        };
    }

    /// Return the earliest modeled loss detection timer across packet spaces.
    ///
    /// This follows the RFC 9002 scheduling rule used by the simplified
    /// recovery model: any pending loss-time deadline wins over PTO; otherwise
    /// the earliest PTO deadline is returned. The caller can pass the same clock
    /// value to `checkLossDetectionTimeouts()` and `checkPtoTimeouts()` when the
    /// deadline expires.
    pub fn lossDetectionTimerDeadline(self: Connection) ?LossDetectionTimerDeadline {
        if (self.isClosingOrClosed()) return null;

        const spaces = [_]PacketNumberSpace{ .initial, .handshake, .application };

        var loss_deadline: ?LossDetectionTimerDeadline = null;
        for (spaces) |space| {
            const deadline = self.lossDetectionDeadline(space) orelse continue;
            if (loss_deadline == null or deadline < loss_deadline.?.deadline_nanos) {
                loss_deadline = .{
                    .space = space,
                    .kind = .loss_time,
                    .deadline_nanos = deadline,
                };
            }
        }
        if (loss_deadline) |deadline| return deadline;

        var pto_deadline: ?LossDetectionTimerDeadline = null;
        for (spaces) |space| {
            const deadline = self.ptoDeadline(space) orelse continue;
            if (pto_deadline == null or deadline < pto_deadline.?.deadline_nanos) {
                pto_deadline = .{
                    .space = space,
                    .kind = .pto,
                    .deadline_nanos = deadline,
                };
            }
        }
        return pto_deadline;
    }

    /// Service the aggregate modeled QUIC loss detection timer if it is due.
    ///
    /// This is the endpoint/event-loop entry point for the simplified recovery
    /// model. It recomputes the aggregate timer, does nothing before the
    /// deadline, and when due dispatches to loss-time handling before PTO
    /// probing. Loss-time service drains due loss deadlines; PTO service handles
    /// one earliest PTO expiration and advances the connection-level backoff.
    /// The returned value is the earliest timer that caused this service call to run.
    pub fn serviceLossDetectionTimer(self: *Connection, now_nanos: i64) Error!?LossDetectionTimerDeadline {
        const deadline = self.lossDetectionTimerDeadline() orelse return null;
        if (deadline.deadline_nanos > now_nanos) return null;

        switch (deadline.kind) {
            .loss_time => try self.checkLossDetectionTimeouts(now_nanos),
            .pto => try self.checkPtoTimeouts(now_nanos),
        }
        return deadline;
    }

    /// Return the current ECN validation state for one packet number space.
    pub fn ecnValidationState(self: Connection, space: PacketNumberSpace) EcnValidationState {
        return switch (space) {
            .initial => self.initial_packet_space.ecn_validation_state,
            .handshake => self.handshake_packet_space.ecn_validation_state,
            .application => self.ecn_validation_state,
        };
    }

    /// Return the latest validated ACK_ECN counters for one packet number space.
    pub fn ecnCounts(self: Connection, space: PacketNumberSpace) frame.EcnCounts {
        return switch (space) {
            .initial => self.initial_packet_space.ecn_counts,
            .handshake => self.handshake_packet_space.ecn_counts,
            .application => self.ecn_counts,
        };
    }

    /// Return queued PATH_CHALLENGE frames that have not been transmitted yet.
    pub fn pendingPathChallengeCount(self: Connection) usize {
        return self.pending_path_challenges.items.len;
    }

    /// Return transmitted PATH_CHALLENGE frames awaiting a matching PATH_RESPONSE.
    pub fn outstandingPathChallengeCount(self: Connection) usize {
        return self.outstanding_path_challenges.items.len;
    }

    /// Return PATH_CHALLENGE validations that exhausted the retry budget.
    pub fn failedPathValidationCount(self: Connection) usize {
        return self.failed_path_validations;
    }

    /// Return whether the modeled QUIC handshake is confirmed.
    pub fn handshakeConfirmed(self: Connection) bool {
        return self.handshake_confirmed;
    }

    /// Returns true when a fast retransmission should be prioritized.
    ///
    /// Set upon entering congestion recovery; cleared after one packet is sent.
    /// Callers should retransmit lost frames before sending new data.
    pub fn requiresFastRetransmission(self: Connection) bool {
        return self.recovery_state.fast_retransmission_required or
            self.initial_packet_space.recovery_state.fast_retransmission_required or
            self.handshake_packet_space.recovery_state.fast_retransmission_required;
    }

    /// Return the modeled QUIC handshake progress state.
    pub fn handshakeState(self: Connection) HandshakeState {
        return self.handshake_state;
    }

    /// Return the spin bit that the next protected 1-RTT short packet will use.
    ///
    /// When `Config.enable_spin_bit` is false this remains false so the default
    /// packetization behavior stays unchanged.
    pub fn nextOutgoingSpinBit(self: Connection) bool {
        return self.shortHeaderSpinBit();
    }

    /// Reset the modeled spin bit for a newly selected path or destination CID.
    ///
    /// The current connection skeleton is single-path; endpoint routing can call
    /// this hook when a future socket-backed migration commits to a new path.
    pub fn resetSpinBitForPath(self: *Connection) void {
        self.spin_bit_value = false;
    }

    /// Install TLS-produced Handshake traffic secrets into connection-owned state.
    ///
    /// The local secret protects future Handshake long-header packets sent by
    /// this endpoint. The peer secret opens future Handshake long-header packets
    /// received from the remote endpoint. `discardPacketNumberSpace(.handshake)`
    /// discards these installed keys together with Handshake recovery state.
    pub fn installHandshakeTrafficSecrets(
        self: *Connection,
        secrets: HandshakeTrafficSecrets,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.handshake_packet_space.discarded) return error.InvalidPacket;
        self.local_handshake_keys = protection.deriveForCipher(secrets.local, self.config.chosen_version, self.negotiated_cipher);
        self.peer_handshake_keys = protection.deriveForCipher(secrets.peer, self.config.chosen_version, self.negotiated_cipher);
    }

    /// Return whether both local send and peer receive Handshake keys exist.
    pub fn hasHandshakeProtectionKeys(self: Connection) bool {
        return self.local_handshake_keys != null and self.peer_handshake_keys != null;
    }

    /// Install TLS-produced 0-RTT traffic secrets into connection-owned state.
    ///
    /// Clients normally install only `local` so they can emit early data.
    /// Servers normally install only `peer` so they can open client early data.
    /// The server-side peer receive key is not accepted by default; call
    /// `acceptZeroRtt()` after TLS policy accepts early data, or
    /// `rejectZeroRtt()` to discard it.
    pub fn installZeroRttTrafficSecrets(
        self: *Connection,
        secrets: ZeroRttTrafficSecrets,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (secrets.local == null and secrets.peer == null) return error.InvalidPacket;
        if (secrets.local) |local| {
            self.local_zero_rtt_keys = protection.deriveForCipher(local, self.config.chosen_version, self.negotiated_cipher);
        }
        if (secrets.peer) |peer| {
            self.peer_zero_rtt_keys = protection.deriveForCipher(peer, self.config.chosen_version, self.negotiated_cipher);
            self.peer_zero_rtt_accepted = false;
        }
    }

    /// Return whether local 0-RTT send keys are installed.
    pub fn hasLocalZeroRttProtectionKey(self: Connection) bool {
        return self.local_zero_rtt_keys != null;
    }

    /// Return whether peer 0-RTT receive keys are installed.
    pub fn hasPeerZeroRttProtectionKey(self: Connection) bool {
        return self.peer_zero_rtt_keys != null;
    }

    /// Return whether installed peer 0-RTT receive keys are accepted for use.
    pub fn zeroRttAccepted(self: Connection) bool {
        return self.peer_zero_rtt_accepted;
    }

    /// Accept installed peer 0-RTT receive keys after TLS early-data policy.
    ///
    /// This only gates the connection-installed receive helper. Callers that
    /// use `processProtectedZeroRttDatagram()` with explicit keys still own
    /// acceptance and replay policy outside the connection.
    pub fn acceptZeroRtt(self: *Connection) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.peer_zero_rtt_keys == null) return error.InvalidPacket;
        self.peer_zero_rtt_accepted = true;
    }

    /// Reject installed peer 0-RTT receive keys and discard early-data state.
    ///
    /// This models TLS rejecting early data before any installed-key 0-RTT
    /// payload is processed. It does not affect caller-owned explicit-key
    /// packet opening.
    pub fn rejectZeroRtt(self: *Connection) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        self.peer_zero_rtt_keys = null;
        self.peer_zero_rtt_accepted = false;
    }

    /// Discard all installed 0-RTT packet-protection keys.
    ///
    /// This explicit hook models the key-lifecycle cleanup required after
    /// early data is no longer accepted. Clients also discard these keys when
    /// 1-RTT keys are installed; servers discard them after the first accepted
    /// 1-RTT short packet. TLS acceptance/replay policy remains outside this
    /// helper.
    pub fn discardZeroRttProtectionKeys(self: *Connection) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        self.discardZeroRttProtectionKeyState();
    }

    fn discardZeroRttProtectionKeyState(self: *Connection) void {
        self.local_zero_rtt_keys = null;
        self.peer_zero_rtt_keys = null;
        self.peer_zero_rtt_accepted = false;
    }

    /// Install TLS-produced 1-RTT traffic secrets into connection-owned state.
    ///
    /// The local secret protects future short-header packets sent by this
    /// endpoint. The peer secret opens future short-header packets received
    /// from the remote endpoint. Key phase starts at false as required for
    /// initial 1-RTT keys; later updates use `initiateOneRttKeyUpdate()` and
    /// peer key-phase bits. Client connections discard installed 0-RTT keys as
    /// soon as 1-RTT keys are installed.
    pub fn installOneRttTrafficSecrets(
        self: *Connection,
        secrets: OneRttTrafficSecrets,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.side == .client) {
            self.discardZeroRttProtectionKeyState();
        }
        self.local_one_rtt_key_phase_state = protection.Aes128KeyPhaseState.initForVersion(
            protection.deriveForCipher(secrets.local, self.config.chosen_version, self.negotiated_cipher),
            false,
            self.config.chosen_version,
        );
        self.peer_one_rtt_key_phase_state = protection.Aes128KeyPhaseState.initForVersion(
            protection.deriveForCipher(secrets.peer, self.config.chosen_version, self.negotiated_cipher),
            false,
            self.config.chosen_version,
        );
        self.local_one_rtt_key_update_ack_threshold = null;
    }

    /// Return whether both local send and peer receive 1-RTT key states exist.
    pub fn hasOneRttProtectionKeys(self: Connection) bool {
        return self.local_one_rtt_key_phase_state != null and self.peer_one_rtt_key_phase_state != null;
    }

    /// Return the key phase bit used by the next installed-key 1-RTT send.
    pub fn localOneRttKeyPhase(self: Connection) ?bool {
        if (self.local_one_rtt_key_phase_state) |state| return state.currentKeyPhase();
        return null;
    }

    /// Return the active peer key phase for installed-key 1-RTT receive.
    pub fn peerOneRttKeyPhase(self: Connection) ?bool {
        if (self.peer_one_rtt_key_phase_state) |state| return state.currentKeyPhase();
        return null;
    }

    /// Return the number of installed local 1-RTT send key updates applied.
    pub fn localOneRttKeyUpdateCount(self: Connection) ?u64 {
        if (self.local_one_rtt_key_phase_state) |state| return state.keyUpdateCount();
        return null;
    }

    /// Return the number of installed peer 1-RTT receive key updates applied.
    pub fn peerOneRttKeyUpdateCount(self: Connection) ?u64 {
        if (self.peer_one_rtt_key_phase_state) |state| return state.keyUpdateCount();
        return null;
    }

    /// Return whether local 1-RTT send keys still retain `generation`.
    pub fn localOneRttRetainsKeyGeneration(self: Connection, generation: u64) ?bool {
        if (self.local_one_rtt_key_phase_state) |state| return state.retainsKeyGeneration(generation);
        return null;
    }

    /// Return whether peer 1-RTT receive keys still retain `generation`.
    pub fn peerOneRttRetainsKeyGeneration(self: Connection, generation: u64) ?bool {
        if (self.peer_one_rtt_key_phase_state) |state| return state.retainsKeyGeneration(generation);
        return null;
    }

    /// Return the packet-number threshold that must be ACKed before another
    /// local installed-key 1-RTT key update can be initiated.
    ///
    /// Null means no local key update is currently waiting for ACK
    /// confirmation. Endpoint/TLS loops can use this read-only hook to observe
    /// the ACK gate without mutating key-phase state.
    pub fn pendingOneRttKeyUpdateAckThreshold(self: Connection) ?u64 {
        return self.local_one_rtt_key_update_ack_threshold;
    }

    /// Return the earliest deadline for discarding retained 1-RTT keys.
    ///
    /// A QUIC endpoint must keep a previous key generation for one PTO after a
    /// key-phase transition, then stop accepting packets protected with it.
    /// Socket loops use this deadline together with idle, close, and recovery
    /// deadlines so an otherwise idle connection still discards old keys.
    pub fn oneRttKeyDiscardDeadline(self: Connection) ?i64 {
        var deadline: ?i64 = null;
        if (self.local_one_rtt_key_phase_state) |state| {
            if (state.previousDiscardDeadline()) |candidate| deadline = candidate;
        }
        if (self.peer_one_rtt_key_phase_state) |state| {
            if (state.previousDiscardDeadline()) |candidate| {
                if (deadline == null or candidate < deadline.?) deadline = candidate;
            }
        }
        return deadline;
    }

    /// Discard retained 1-RTT generations whose PTO retain window has elapsed.
    pub fn discardExpiredOneRttKeys(self: *Connection, now_nanos: i64) bool {
        var discarded = false;
        if (self.local_one_rtt_key_phase_state) |*state| {
            discarded = state.discardExpiredPrevious(now_nanos) or discarded;
        }
        if (self.peer_one_rtt_key_phase_state) |*state| {
            discarded = state.discardExpiredPrevious(now_nanos) or discarded;
        }
        return discarded;
    }

    /// Advance the installed local 1-RTT send keys before the next packet.
    ///
    /// This models endpoint-owned key update initiation after handshake
    /// confirmation. A second local update is rejected until an Application ACK
    /// covers a packet number sent with the new key phase.
    /// Schedule the retained previous-generation key for discard one PTO after
    /// `now_nanos`, so delayed packets protected with the old key phase can be
    /// opened during the retain window and the old key is dropped afterwards
    /// (RFC 9001 §6.5 / RFC 9002 §6.2).
    fn schedulePreviousKeyDiscard(
        self: *Connection,
        state: *protection.Aes128KeyPhaseState,
        now_nanos: ?i64,
    ) void {
        const now = now_nanos orelse return;
        const deadline = ptoDeadlineFromStart(
            now,
            self.recovery_state,
            false,
            self.recovery_state.pto_count,
        );
        state.schedulePreviousDiscard(deadline);
    }

    pub fn initiateOneRttKeyUpdate(self: *Connection) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (!self.handshake_confirmed) return error.InvalidPacket;
        if (self.local_one_rtt_key_update_ack_threshold != null) return error.InvalidPacket;
        if (self.local_one_rtt_key_phase_state) |*state| {
            state.initiateKeyUpdate();
            self.schedulePreviousKeyDiscard(state, self.last_packet_activity_nanos);
            self.local_one_rtt_key_update_ack_threshold = self.next_packet_number;
            return;
        }
        return error.InvalidPacket;
    }

    fn shortHeaderSpinBit(self: Connection) bool {
        return self.config.enable_spin_bit and self.spin_bit_value;
    }

    fn updateSpinBitAfterReceivedShortPacket(self: *Connection, peer_spin_bit: bool) void {
        if (!self.config.enable_spin_bit) return;
        self.spin_bit_value = switch (self.side) {
            .client => !peer_spin_bit,
            .server => peer_spin_bit,
        };
    }

    /// Return the peer-issued CID sequence whose stateless reset token matches.
    ///
    /// This is a read-only detector for future UDP packet handling. The
    /// frame-payload API does not automatically close the connection because it
    /// does not yet receive protected packets.
    pub fn detectStatelessReset(self: Connection, datagram: []const u8) ?u64 {
        for (self.active_connection_ids.items) |active_id| {
            if (active_id.retired) continue;
            if (packet.matchesStatelessReset(datagram, active_id.stateless_reset_token)) {
                return active_id.sequence_number;
            }
        }
        return null;
    }

    /// Process a stateless reset datagram and enter draining when its trailing
    /// token matches an active peer-issued connection ID.
    ///
    /// A matching reset has no peer close frame or error code. It stops any
    /// pending CONNECTION_CLOSE output and starts the close/draining timeout.
    /// Null means the datagram was too short, used an unknown token, matched
    /// only a retired token, or the connection was already fully closed.
    pub fn processStatelessResetDatagram(self: *Connection, now_nanos: i64, datagram: []const u8) ?u64 {
        self.expireCloseState(now_nanos);
        self.expireIdleState(now_nanos);
        if (self.state == .closed) return null;

        const sequence_number = self.detectStatelessReset(datagram) orelse return null;
        self.clearPendingCloseFrame();
        self.enterDrainingState(now_nanos);
        return sequence_number;
    }

    /// Return Retry tokens issued by this server and still accepted once.
    pub fn pendingRetryTokenCount(self: Connection) usize {
        return self.retry_tokens.items.len;
    }

    /// Return the Retry token most recently accepted by a client connection.
    ///
    /// The returned token is owned by the connection and is used automatically
    /// as the Initial token when protected Initial packetization receives no
    /// explicit token argument. Null means no valid Retry packet has been
    /// processed by this client connection.
    pub fn latestRetryToken(self: Connection) ?[]const u8 {
        return self.retry_token;
    }

    /// Return the Source Connection ID used by this endpoint's first sent Initial.
    ///
    /// This value is captured only after a protected Initial packet is actually
    /// committed to the send path. `localTransportParameters()` exports it as
    /// `initial_source_connection_id` once available.
    pub fn localInitialSourceConnectionId(self: *const Connection) ?[]const u8 {
        const len = self.local_initial_source_connection_id_len orelse return null;
        return self.local_initial_source_connection_id[0..len];
    }

    /// Set this endpoint's Initial Source Connection ID before the first
    /// crypto-backend drive so that `encodeLocalTransportParameters` includes
    /// it in the local transport parameters. Callers that drive a TLS-owned
    /// handshake from the `client_start` state (where the backend produces the
    /// ClientHello) must set this before the first `driveCryptoBackendInSpace`,
    /// since packet polling that would otherwise record it happens after drive.
    pub fn setLocalInitialSourceConnectionId(self: *Connection, scid: []const u8) Error!void {
        if (scid.len > max_connection_id_len) return error.InvalidPacket;
        @memcpy(self.local_initial_source_connection_id[0..scid.len], scid);
        self.local_initial_source_connection_id_len = @intCast(scid.len);
    }

    /// Store the peer's Initial Source Connection ID before packet processing
    /// has captured it, or verify that a repeated binding matches exactly.
    ///
    /// Endpoint-owned Retry paths can authenticate the client SCID before the
    /// protected follow-up Initial is processed. Once set, the value is stable
    /// and is later used for transport-parameter validation and outgoing CID
    /// fallback before the peer issues NEW_CONNECTION_ID.
    pub fn setPeerInitialSourceConnectionId(self: *Connection, scid: []const u8) Error!void {
        if (scid.len > max_connection_id_len) return error.InvalidPacket;
        if (self.peer_initial_source_connection_id) |existing| {
            if (!std.mem.eql(u8, existing, scid)) return error.InvalidPacket;
            return;
        }
        const owned = self.allocator.alloc(u8, scid.len) catch return error.OutOfMemory;
        @memcpy(owned, scid);
        self.peer_initial_source_connection_id = owned;
    }

    /// Return the peer's Initial Source Connection ID observed on its first Initial.
    ///
    /// The value is captured from a successfully opened protected Initial packet
    /// and later authenticated by the peer's `initial_source_connection_id`
    /// transport parameter.
    pub fn peerInitialSourceConnectionId(self: Connection) ?[]const u8 {
        return self.peer_initial_source_connection_id;
    }

    /// Return the peer Connection ID selected for subsequent outgoing packets.
    ///
    /// Once the peer advertises active NEW_CONNECTION_ID values, prefer the
    /// highest non-retired sequence number. Until then, use the authenticated
    /// Initial Source Connection ID captured from the peer's first Initial.
    pub fn peerDestinationConnectionId(self: *const Connection) ?[]const u8 {
        var selected: ?[]const u8 = null;
        var selected_sequence: ?u64 = null;
        for (self.active_connection_ids.items) |active_id| {
            if (active_id.retired) continue;
            if (selected_sequence == null or active_id.sequence_number > selected_sequence.?) {
                selected = active_id.connection_id;
                selected_sequence = active_id.sequence_number;
            }
        }
        return selected orelse self.peer_initial_source_connection_id;
    }

    fn hasZeroLengthLocalInitialSourceConnectionId(self: Connection) bool {
        const len = self.local_initial_source_connection_id_len orelse return false;
        return len == 0;
    }

    fn sendsZeroLengthDestinationConnectionId(self: *const Connection) bool {
        const destination_connection_id = self.peerDestinationConnectionId() orelse return false;
        return destination_connection_id.len == 0;
    }

    /// Return the Original Destination Connection ID remembered for transport parameters.
    ///
    /// Client connections record the DCID used by their first sent Initial and
    /// validate it against the server's `original_destination_connection_id`.
    /// Server connections record the DCID from the first successfully opened
    /// client Initial and export it through `localTransportParameters()`.
    pub fn originalDestinationConnectionId(self: *const Connection) ?[]const u8 {
        const len = self.original_destination_connection_id_len orelse return null;
        return self.original_destination_connection_id[0..len];
    }

    /// Return the Retry Source Connection ID from a validated Retry packet.
    ///
    /// Client connections expose the Retry Source Connection ID from a
    /// validated Retry packet for later server transport-parameter validation.
    /// Server connections expose the Retry Source Connection ID from a Retry
    /// datagram issued through `issueRetryDatagram()`.
    pub fn retrySourceConnectionId(self: Connection) ?[]const u8 {
        return self.retry_source_connection_id;
    }

    /// Return the configured QUIC version for protected packet processing.
    pub fn chosenVersion(self: Connection) packet.Version {
        return self.config.chosen_version;
    }

    /// Set the QUIC version for protected packet processing.
    ///
    /// Server connections adopt the version from an accepted client Initial
    /// so that subsequent Initial/Handshake packet construction and key
    /// derivation use the version the client chose. Must be called before the
    /// first outgoing long-header packet is built.
    pub fn setChosenVersion(self: *Connection, version: packet.Version) void {
        self.config.chosen_version = version;
    }

    /// Return the version selected from a validated Version Negotiation packet.
    ///
    /// The current connection object only records the result. The caller still
    /// owns starting the next incompatible-version connection attempt with the
    /// selected version and carrying authenticated RFC 9368 Version Information.
    pub fn versionNegotiationSelectedVersion(self: Connection) ?packet.Version {
        return self.version_negotiation_selected_version;
    }

    /// Return a config for the client follow-up connection after Version Negotiation.
    ///
    /// RFC 8999 Version Negotiation asks the client to start a new connection
    /// attempt with the selected version. The returned config preserves the
    /// caller's version list while setting both `chosen_version` and
    /// `version_negotiation_selected_version`, so later authenticated RFC 9368
    /// Version Information can validate that the server did not downgrade the
    /// negotiated version.
    pub fn versionNegotiationFollowupConfig(self: Connection) Error!Config {
        if (self.side != .client) return error.InvalidPacket;
        const selected = self.version_negotiation_selected_version orelse return error.InvalidPacket;
        var config = self.config;
        config.chosen_version = selected;
        config.version_negotiation_selected_version = selected;
        return config;
    }

    /// Build and record one server-side QUIC v1 Retry datagram.
    ///
    /// The returned datagram is allocated with the connection allocator and
    /// must be freed by the caller. A successful call registers `token` for
    /// one-time server validation, records the Original Destination Connection
    /// ID and Retry Source Connection ID, and makes both available through
    /// `localTransportParameters()`. Address-bound token generation can be
    /// supplied by `issueAddressValidationToken()`. Endpoint DCID switching
    /// remains endpoint policy.
    pub fn issueRetryDatagram(
        self: *Connection,
        now_nanos: i64,
        original_destination_connection_id: []const u8,
        client_source_connection_id: []const u8,
        retry_source_connection_id: []const u8,
        token: []const u8,
    ) Error![]u8 {
        self.expireIdleState(now_nanos);
        self.expireCloseState(now_nanos);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.side != .server or token.len == 0) return error.InvalidPacket;
        if (self.initial_packet_space.discarded or self.initial_packet_space.next_peer_packet_number != 0) return error.InvalidPacket;
        if (self.original_destination_connection_id_len != null or self.retry_source_connection_id != null) return error.InvalidPacket;
        try self.validateOriginalDestinationConnectionIdForRecord(original_destination_connection_id);
        try validateInitialDestinationConnectionIdLength(original_destination_connection_id);
        if (client_source_connection_id.len > max_connection_id_len or retry_source_connection_id.len > max_connection_id_len) {
            return error.InvalidPacket;
        }

        const retry = packet.RetryPacket{
            .version = self.config.chosen_version,
            .dcid = client_source_connection_id,
            .scid = retry_source_connection_id,
            .token = token,
            .integrity_tag = @as([protection.aead_tag_len]u8, @splat(0)),
        };
        const datagram = protection.encodeRetryPacketWithIntegrity(
            self.allocator,
            original_destination_connection_id,
            retry,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        const owned_retry_scid = self.allocator.alloc(u8, retry_source_connection_id.len) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned_retry_scid);
        @memcpy(owned_retry_scid, retry_source_connection_id);

        try self.issueRetryToken(token);
        self.recordOriginalDestinationConnectionId(original_destination_connection_id);
        self.retry_source_connection_id = owned_retry_scid;
        self.recordPeerAddressBytesSent(datagram.len);
        self.recordPacketActivity(now_nanos);
        return datagram;
    }

    /// Validate and process one client-side Retry datagram for the configured version.
    ///
    /// The Retry Integrity Tag is verified using the Original Destination
    /// Connection ID from the first client Initial. A valid Retry stores the
    /// opaque token for the next Initial packet and records the Retry Source
    /// Connection ID for later transport-parameter checks. This models the
    /// packet-routing step only; token encryption, expiration, address binding,
    /// and endpoint DCID switching remain endpoint policy.
    pub fn processRetryDatagram(
        self: *Connection,
        now_nanos: i64,
        original_destination_connection_id: []const u8,
        datagram: []const u8,
    ) Error!void {
        self.expireIdleState(now_nanos);
        self.expireCloseState(now_nanos);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.side != .client or self.retry_token != null) return error.InvalidPacket;
        if (self.initial_packet_space.discarded) return error.InvalidPacket;
        if (self.initial_packet_space.next_peer_packet_number != 0) return error.InvalidPacket;

        var retry = protection.parseRetryPacketWithIntegrity(
            self.allocator,
            original_destination_connection_id,
            datagram,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidPacket,
        };
        defer packet.deinitRetryPacket(&retry, self.allocator);

        if (@backingInt(retry.version) != @backingInt(self.config.chosen_version)) return error.InvalidPacket;
        try self.validateOriginalDestinationConnectionIdForRecord(original_destination_connection_id);
        if (self.original_destination_connection_id_len == null) {
            try validateInitialDestinationConnectionIdLength(original_destination_connection_id);
        }

        const owned_token = self.allocator.alloc(u8, retry.token.len) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned_token);
        @memcpy(owned_token, retry.token);

        const owned_retry_scid = self.allocator.alloc(u8, retry.scid.len) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned_retry_scid);
        @memcpy(owned_retry_scid, retry.scid);

        self.recordOriginalDestinationConnectionId(original_destination_connection_id);
        self.retry_token = owned_token;
        self.retry_source_connection_id = owned_retry_scid;
        self.recordPacketActivity(now_nanos);
    }

    /// 重置 Initial packet space 的发送侧状态，用于 Retry 后重发 ClientHello。
    ///
    /// 首次 `pollProtectedLongCryptoDatagramInSpace` commit 后 ClientHello CRYPTO
    /// 字节已从 `crypto_send_queue` 移除并释放，`crypto_send_offset` 前进到
    /// ClientHello 末尾，`next_packet_number` 前进到 1，无法重发。本方法重置整个
    /// 发送侧：清空 queue、offset 归零、packet number 归零、清空 sent_packets、
    /// 重置 recovery 计数，让后续 `driveCryptoBackendInSpace(.initial)` 重新 pull
    /// 出 ClientHello（由 `Tls13Backend.retryReceived` 重新缓存）并从 packet number
    /// 0 重新入队发送。
    ///
    /// RFC 9000 §17.2.5.1：Retry 后 client 丢弃 original DCID 派生的 initial keys
    /// 及其发送记录。server 从未 process 首份 ch（`issueRetryDatagram` 要求
    /// `next_peer_packet_number==0`），所以重发用 packet_number=0 与 server 端
    /// `expected_packet_number=0` 匹配，不违反 §21.4 的 packet number 重用禁令
    ///（首份 ch 从未被 server 接受，等同从未发送）。
    ///
    /// 与 `discardPacketNumberSpaceState` 的区别：**不**置 `discarded = true`，
    /// **不**清 recv 侧状态（`crypto_recv_buffer`/`crypto_read_offset`/
    /// `next_peer_packet_number`）、**不**清 initial keys（caller 用 retry_scid
    /// 重新派生的 keys 通过 `pollProtectedLongCryptoDatagramInSpace` 传入）。
    /// 仅 client 侧合法。
    pub fn resetInitialCryptoSendForRetry(self: *Connection) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.side != .client) return error.InvalidPacket;
        if (self.initial_packet_space.discarded) return error.InvalidPacket;
        const packet_space = self.packetNumberSpace(.initial);
        self.rollbackCryptoSendQueue(packet_space.crypto_send_queue, 0);
        packet_space.crypto_send_offset.* = 0;
        clearSentPacketList(self.allocator, packet_space.sent_packets);
        packet_space.next_packet_number.* = 0;
        packet_space.pending_ping_count.* = 0;
        packet_space.pto_probe_count.* = 0;
        packet_space.congestion_probe_count.* = 0;
        packet_space.recovery_state.bytes_in_flight = 0;
        packet_space.recovery_state.pto_count = 0;
    }

    /// Validate and act on one client-side Version Negotiation packet.
    ///
    /// Packets received before this client has sent an Initial, incorrect
    /// connection-ID echoes, packets that include the client's Original
    /// Version, and Version Negotiation received after this client has already
    /// processed another peer packet are ignored by returning null. A valid
    /// packet selects the first server-offered version that appears in this
    /// client's configured `available_versions`, records that this connection
    /// attempt already reacted to Version Negotiation, and returns the selected
    /// version.
    pub fn processVersionNegotiationDatagram(
        self: *Connection,
        now_nanos: i64,
        original_destination_connection_id: []const u8,
        local_initial_source_connection_id: []const u8,
        datagram: []const u8,
    ) Error!?packet.Version {
        self.expireIdleState(now_nanos);
        self.expireCloseState(now_nanos);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.side != .client) return error.InvalidPacket;
        if (original_destination_connection_id.len > max_connection_id_len) return error.InvalidPacket;
        if (local_initial_source_connection_id.len > max_connection_id_len) return error.InvalidPacket;
        if (self.version_negotiation_selected_version != null) return null;
        if (self.initial_packet_space.next_packet_number == 0) return null;
        if (self.retry_source_connection_id != null) return null;
        if (self.initial_packet_space.discarded) return null;
        if (self.initial_packet_space.next_peer_packet_number != 0) return null;
        if (self.handshake_packet_space.discarded) return null;
        if (self.handshake_packet_space.next_peer_packet_number != 0) return null;
        if (self.next_peer_packet_number != 0) return null;

        var negotiation = packet.parseVersionNegotiationPacket(datagram, self.allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidPacket,
        };
        defer packet.deinitVersionNegotiationPacket(&negotiation, self.allocator);

        if (!std.mem.eql(u8, negotiation.dcid, local_initial_source_connection_id)) return null;
        if (!std.mem.eql(u8, negotiation.scid, original_destination_connection_id)) return null;
        if (connection_version.versionListContains(negotiation.versions, self.config.chosen_version)) return null;

        const selected = connection_version.selectMutualVersion(self.config.available_versions, negotiation.versions) orelse return error.InvalidPacket;
        self.version_negotiation_selected_version = selected;
        self.recordPacketActivity(now_nanos);
        return selected;
    }

    /// Create a server-authenticated address-validation token.
    ///
    /// The token is bound to `peer_address`, expires after `lifetime_nanos`,
    /// and is authenticated with `secret`. The peer address is included in the
    /// MAC input but not serialized into the token. Callers pass `.retry`
    /// tokens to `issueRetryDatagram()` and `.new_token` values to
    /// `issueNewToken()`.
    pub fn issueAddressValidationToken(
        self: *Connection,
        secret: address_validation_token.Secret,
        kind: address_validation_token.Kind,
        now_nanos: i64,
        lifetime_nanos: u64,
        peer_address: []const u8,
        nonce: address_validation_token.Nonce,
    ) Error![]u8 {
        return self.issueAddressValidationTokenForVersion(secret, kind, .v1, now_nanos, lifetime_nanos, peer_address, nonce);
    }

    /// Create a server-authenticated token for a specific QUIC version.
    pub fn issueAddressValidationTokenForVersion(
        self: *Connection,
        secret: address_validation_token.Secret,
        kind: address_validation_token.Kind,
        originating_version: packet.Version,
        now_nanos: i64,
        lifetime_nanos: u64,
        peer_address: []const u8,
        nonce: address_validation_token.Nonce,
    ) Error![]u8 {
        self.expireIdleState(now_nanos);
        self.expireCloseState(now_nanos);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.side != .server) return error.InvalidPacket;

        return address_validation_token.encode(self.allocator, secret, .{
            .kind = kind,
            .originating_version = originating_version,
            .issued_nanos = now_nanos,
            .lifetime_nanos = lifetime_nanos,
            .peer_address = peer_address,
            .nonce = nonce,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidPacket,
        };
    }

    /// Validate a server-authenticated address-validation token.
    ///
    /// Retry tokens must also be present in the one-time pending Retry-token
    /// set, so successful validation consumes them. NEW_TOKEN validation is
    /// stateless in the current connection skeleton. Either successful kind
    /// validates the peer address and lifts the modeled anti-amplification
    /// limit.
    pub fn validateAddressValidationToken(
        self: *Connection,
        secret: address_validation_token.Secret,
        expected_kind: address_validation_token.Kind,
        now_nanos: i64,
        peer_address: []const u8,
        token: []const u8,
    ) Error!void {
        try self.validateAddressValidationTokenForVersion(secret, expected_kind, .v1, now_nanos, peer_address, token);
    }

    /// Validate a server-authenticated token for an expected QUIC version.
    pub fn validateAddressValidationTokenForVersion(
        self: *Connection,
        secret: address_validation_token.Secret,
        expected_kind: address_validation_token.Kind,
        expected_originating_version: packet.Version,
        now_nanos: i64,
        peer_address: []const u8,
        token: []const u8,
    ) Error!void {
        const secrets = [_]address_validation_token.Secret{secret};
        try self.validateAddressValidationTokenWithSecretsForVersion(&secrets, expected_kind, expected_originating_version, now_nanos, peer_address, token);
    }

    /// Validate a server-authenticated token against rotated endpoint secrets.
    ///
    /// This has the same connection-side effects as
    /// `validateAddressValidationToken()`: Retry tokens are consumed from the
    /// pending one-time set, NEW_TOKEN values do not require pending state, and
    /// successful validation marks the peer address as validated.
    pub fn validateAddressValidationTokenWithSecrets(
        self: *Connection,
        secrets: []const address_validation_token.Secret,
        expected_kind: address_validation_token.Kind,
        now_nanos: i64,
        peer_address: []const u8,
        token: []const u8,
    ) Error!void {
        try self.validateAddressValidationTokenWithSecretsForVersion(secrets, expected_kind, .v1, now_nanos, peer_address, token);
    }

    /// Validate a version-bound server-authenticated token against rotated secrets.
    pub fn validateAddressValidationTokenWithSecretsForVersion(
        self: *Connection,
        secrets: []const address_validation_token.Secret,
        expected_kind: address_validation_token.Kind,
        expected_originating_version: packet.Version,
        now_nanos: i64,
        peer_address: []const u8,
        token: []const u8,
    ) Error!void {
        self.expireIdleState(now_nanos);
        self.expireCloseState(now_nanos);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.side != .server or token.len == 0) return error.InvalidPacket;

        _ = address_validation_token.validateAnySecretForVersion(secrets, expected_kind, expected_originating_version, now_nanos, peer_address, token) catch return error.InvalidPacket;
        if (expected_kind == .retry and !self.consumePendingRetryToken(token)) {
            return error.InvalidPacket;
        }
        self.peer_address_validated = true;
        self.recordPacketActivity(now_nanos);
    }

    /// Register an opaque Retry token that a server will accept once.
    ///
    /// The token bytes are copied into connection-owned memory. This is a
    /// deterministic model for tests and examples until endpoint-level token
    /// encryption, expiration, and address binding exist.
    pub fn issueRetryToken(self: *Connection, token: []const u8) Error!void {
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
    pub fn validateRetryToken(self: *Connection, token: []const u8) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.side != .server or token.len == 0) return error.InvalidPacket;

        if (self.consumePendingRetryToken(token)) {
            self.peer_address_validated = true;
            return;
        }

        return error.InvalidPacket;
    }

    /// Return locally issued connection IDs that the peer has not retired.
    pub fn localConnectionIdCount(self: Connection) u64 {
        var count: u64 = 0;
        for (self.local_connection_ids.items) |local_id| {
            if (!local_id.retired) count += 1;
        }
        return count;
    }

    fn localConnectionIdCountAfterRetirePriorTo(self: Connection, retire_prior_to: u64) u64 {
        var count: u64 = 0;
        for (self.local_connection_ids.items) |local_id| {
            if (local_id.retired or local_id.sequence_number < retire_prior_to) continue;
            count += 1;
        }
        return count;
    }

    /// Return locally issued NEW_CONNECTION_ID frames still waiting to be sent.
    pub fn pendingNewConnectionIdCount(self: Connection) usize {
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
        self: *Connection,
        connection_id: []const u8,
        stateless_reset_token: [16]u8,
        retire_prior_to: u64,
    ) Error!u64 {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.hasZeroLengthLocalInitialSourceConnectionId()) return error.InvalidPacket;
        if (connection_id.len == 0 or connection_id.len > max_connection_id_len) return error.InvalidPacket;
        if (self.next_local_connection_id_sequence > max_quic_varint) return error.InvalidPacket;
        if (retire_prior_to > self.next_local_connection_id_sequence) return error.InvalidPacket;
        if (self.localConnectionIdCountAfterRetirePriorTo(retire_prior_to) >= self.peer_active_connection_id_limit) return error.InvalidPacket;
        if (self.localConnectionIdValueExists(connection_id)) return error.InvalidPacket;
        if (self.localStatelessResetTokenValueExists(stateless_reset_token)) return error.InvalidPacket;

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
    pub fn checkPathValidationTimeouts(self: *Connection, now_nanos: i64) Error!void {
        self.expireIdleState(now_nanos);
        self.expireCloseState(now_nanos);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        try self.expirePathChallenges(now_nanos);
    }

    /// Apply due time-threshold loss detection in all packet number spaces.
    ///
    /// This deterministic timer hook is part of the frame-payload recovery
    /// skeleton. It does not send PTO probes yet; it only removes packets whose
    /// RFC 9002 time-threshold loss deadline has expired.
    pub fn checkLossDetectionTimeouts(self: *Connection, now_nanos: i64) Error!void {
        self.expireIdleState(now_nanos);
        self.expireCloseState(now_nanos);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        try self.expireLossDetectionTimeouts(now_nanos);
    }

    /// Queue PTO probes when simplified PTO deadlines expire.
    ///
    /// This is a deterministic hook for the current frame-payload model. It
    /// lets already queued ack-eliciting data serve as the probe. If nothing is
    /// queued, it reuses in-flight CRYPTO first, then Application STREAM, before
    /// falling back to a PING. When one space expires, the connection-level PTO
    /// backoff advances and other packet number spaces that still have
    /// in-flight packets also get peer probes.
    pub fn checkPtoTimeouts(self: *Connection, now_nanos: i64) Error!void {
        self.expireIdleState(now_nanos);
        self.expireCloseState(now_nanos);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        // Drop retained previous-generation 1-RTT keys once their post-update
        // retain window expires (RFC 9001 §6.5).
        _ = self.discardExpiredOneRttKeys(now_nanos);
        try self.expireLossDetectionTimeouts(now_nanos);
        const spaces = [_]PacketNumberSpace{ .initial, .handshake, .application };
        var expired_space: ?PacketNumberSpace = null;
        var expired_deadline: ?i64 = null;
        for (spaces) |space| {
            const deadline = self.ptoDeadline(space) orelse continue;
            if (deadline > now_nanos) continue;
            if (expired_deadline == null or deadline < expired_deadline.?) {
                expired_space = space;
                expired_deadline = deadline;
            }
        }
        if (expired_space) |space| {
            try self.checkPtoTimeoutInSpace(space);
            try self.queuePtoPeerSpaceProbes(space);
        }
    }

    /// Apply the modeled QUIC idle timeout under a controlled clock.
    pub fn checkIdleTimeouts(self: *Connection, now_nanos: i64) Error!void {
        self.expireIdleState(now_nanos);
        if (self.state == .closed) return error.ConnectionClosed;
    }

    /// Apply the modeled close/drain timeout under a controlled clock.
    pub fn checkCloseTimeouts(self: *Connection, now_nanos: i64) Error!void {
        self.expireCloseState(now_nanos);
        if (self.state == .closed) return error.ConnectionClosed;
    }

    /// Mark the modeled handshake as confirmed.
    ///
    /// TLS integration is not wired yet, so this explicit hook lets tests and
    /// future TLS adapters enable post-handshake recovery behavior such as the
    /// RFC 9002 peer `max_ack_delay` cap.
    pub fn confirmHandshake(self: *Connection) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        self.handshake_state = .confirmed;
        self.handshake_confirmed = true;
        self.anti_deadlock_pto_start_nanos = null;
        if (self.qlog_writer) |qlog| {
            qlog.emitConnectionState("handshake_confirmed", self.last_packet_activity_nanos orelse 0);
        }
    }

    /// Discard Initial or Handshake packet-number-space recovery state.
    ///
    /// This models the QUIC key-discard side effect before packet protection is
    /// implemented. Application data shares the 0-RTT/1-RTT packet number space
    /// and is never discarded through this API.
    pub fn discardPacketNumberSpace(self: *Connection, space: PacketNumberSpace) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (space == .application) return error.InvalidPacket;
        self.discardPacketNumberSpaceState(space);
    }

    fn discardPacketNumberSpaceState(self: *Connection, space: PacketNumberSpace) void {
        std.debug.assert(space != .application);
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return;

        packet_space.discarded.* = true;
        if (space == .handshake) {
            self.local_handshake_keys = null;
            self.peer_handshake_keys = null;
        }
        packet_space.pending_ack_largest.* = null;
        packet_space.received_packet_ranges.* = .{};
        packet_space.largest_acknowledged.* = null;
        packet_space.first_rtt_sample_sent_time_nanos.* = null;
        packet_space.loss_deadline_nanos.* = null;
        clearSentPacketList(self.allocator, packet_space.sent_packets);
        packet_space.pending_ping_count.* = 0;
        packet_space.pto_probe_count.* = 0;
        packet_space.congestion_probe_count.* = 0;
        self.rollbackCryptoSendQueue(packet_space.crypto_send_queue, 0);
        packet_space.crypto_send_offset.* = 0;
        packet_space.crypto_recv_buffer.items.len = 0;
        packet_space.crypto_read_offset.* = 0;
        self.rollbackCryptoFrameQueue(packet_space.crypto_recv_pending, 0);
        packet_space.recovery_state.bytes_in_flight = 0;
        packet_space.recovery_state.pto_count = 0;
        packet_space.recovery_state.congestion_avoidance_bytes_acked = 0;
        packet_space.ecn_sent_ect0.* = 0;
        packet_space.ecn_sent_ect1.* = 0;
        packet_space.ecn_largest_acknowledged.* = null;
        packet_space.ecn_counts.* = zeroEcnCounts();
        packet_space.ecn_validation_state.* = .unknown;
        self.anti_deadlock_pto_start_nanos = null;
        self.resetConnectionPtoBackoff();
    }

    /// Record a modeled ack-eliciting packet in the selected packet number space.
    ///
    /// This low-level helper backs tests and future packetization work until
    /// protected packets are produced by the connection itself.
    pub fn recordPacketSentInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        now_nanos: i64,
        bytes: usize,
    ) Error!u64 {
        return self.recordPacketSentInSpaceWithEcn(space, now_nanos, bytes, .not_ect);
    }

    /// Record a modeled ECT-marked packet in the selected packet number space.
    ///
    /// This helper exists for deterministic ECN validation tests and future
    /// packetization. Real IP-header ECN marking is outside the frame-payload
    /// API, so callers must only use `ect0` or `ect1` when they have modeled
    /// that send-side marking explicitly.
    pub fn recordEcnPacketSentInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        now_nanos: i64,
        bytes: usize,
        codepoint: EcnCodepoint,
    ) Error!u64 {
        if (codepoint == .not_ect) return error.InvalidPacket;
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.ecn_validation_state.* == .failed) return error.InvalidPacket;
        return self.recordPacketSentInSpaceWithEcn(space, now_nanos, bytes, codepoint);
    }

    fn recordPacketSentInSpaceWithEcn(
        self: *Connection,
        space: PacketNumberSpace,
        now_nanos: i64,
        bytes: usize,
        codepoint: EcnCodepoint,
    ) Error!u64 {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;
        if (packet_space.next_packet_number.* > max_quic_varint) return error.Internal;
        if (self.ackElicitingSendAdmission(space, bytes) != .allowed) return error.FlowControlBlocked;

        const packet_number = packet_space.next_packet_number.*;
        packet_space.sent_packets.append(self.allocator, .{
            .packet_number = packet_number,
            .sent_time_nanos = now_nanos,
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
        self.recordAckElicitingSendInSpace(space, bytes);
        self.recordPeerAddressBytesSent(bytes);
        self.recordPacketActivity(now_nanos);
        self.maybeDiscardInitialAfterHandshakePacketSent(space);
        return packet_number;
    }

    /// Process one ACK frame in the selected packet number space.
    pub fn receiveAckInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        now_nanos: i64,
        ack: frame.AckFrame,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        try self.receiveAckFrame(space, now_nanos, ack, null);
    }

    /// Process one ACK_ECN frame in the selected packet number space.
    pub fn receiveAckEcnInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        now_nanos: i64,
        ack_ecn: frame.AckEcnFrame,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        try self.receiveAckFrame(space, now_nanos, ack_ecn.ack, ack_ecn.ecn_counts);
    }

    /// Queue an ACK for the next expected packet number in the selected space.
    pub fn queueAckForReceivedPacketInSpace(self: *Connection, space: PacketNumberSpace) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        try self.queueAckForReceivedPacket(space, null);
    }

    /// Queue one ack-eliciting PING in a selected packet number space.
    pub fn sendPingInSpace(self: *Connection, space: PacketNumberSpace) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        try self.queuePingInSpace(space);
        self.markHandshakeSpaceUsed(space);
    }

    /// Build the local RFC 9000 transport parameters advertised during handshake.
    ///
    /// The current skeleton maps idle timeout, receive limits, ACK timing,
    /// local datagram sizing, active migration policy, the first sent Initial
    /// Source Connection ID when known, server Original Destination Connection
    /// ID / Retry Source Connection ID when known, RFC 9368 version
    /// information, and optional server stateless reset token into typed
    /// parameters. Stateless reset tokens are advertised only when the server's
    /// Initial Source Connection ID is known and non-empty.
    pub fn localTransportParameters(self: *const Connection) transport_parameters.TransportParameters {
        var params = transport_parameters.TransportParameters{
            .max_idle_timeout = self.config.max_idle_timeout_ms,
            .initial_max_data = self.recv_max_data,
            .initial_max_stream_data_bidi_local = self.recv_max_stream_data,
            .initial_max_stream_data_bidi_remote = self.recv_max_stream_data,
            .initial_max_stream_data_uni = self.recv_max_stream_data,
            .initial_max_streams_bidi = self.recv_max_streams_bidi,
            .initial_max_streams_uni = self.recv_max_streams_uni,
            .ack_delay_exponent = self.config.ack_delay_exponent,
            .max_ack_delay = @intCast(duration_mod.nanosToMillis(@intCast(self.config.max_ack_delay_ns))),
            .disable_active_migration = self.config.disable_active_migration,
            .active_connection_id_limit = self.config.active_connection_id_limit,
            .original_destination_connection_id = if (self.side == .server) self.originalDestinationConnectionId() else null,
            .initial_source_connection_id = self.localInitialSourceConnectionId(),
            .retry_source_connection_id = if (self.side == .server) self.retrySourceConnectionId() else null,
            .version_information = .{
                .chosen_version = self.config.chosen_version,
                .available_versions = self.config.available_versions,
            },
        };
        if (self.side == .server) {
            if (self.localInitialSourceConnectionId()) |initial_scid| {
                if (initial_scid.len != 0) {
                    params.stateless_reset_token = self.config.stateless_reset_token;
                }
            }
            if (self.config.preferred_address) |*preferred| {
                params.preferred_address = preferred.asTransportParameter();
            }
        }
        if (self.config.max_datagram_size >= 1200) {
            params.max_udp_payload_size = self.config.max_datagram_size;
        }
        return params;
    }

    /// Encode local transport parameters as TLS QUIC extension bytes.
    ///
    /// TLS backends carry these bytes in the QUIC transport_parameters
    /// extension. The returned slice aliases `out_buf` and remains valid until
    /// the caller reuses that buffer.
    pub fn encodeLocalTransportParameters(self: *const Connection, out_buf: []u8) Error![]const u8 {
        var out = buffer.fixedWriter(out_buf);
        transport_parameters.encode(out.writer(), self.localTransportParameters()) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        return out.getWritten();
    }

    /// Apply peer RFC 9000 transport parameters after handshake parsing.
    ///
    /// This updates the send-side flow-control, stream-count, ACK timing, idle
    /// timeout, connection ID, and datagram-size limits used by the in-memory
    /// connection model. It should be called before application writes for the
    /// connection; later MAX_* frames can still increase limits.
    pub fn applyPeerTransportParameters(
        self: *Connection,
        params: transport_parameters.TransportParameters,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        self.validatePeerTransportParameters(params) catch |err| switch (err) {
            error.VersionNegotiationError => return error.InvalidPacket,
            else => return peerTransportParameterValidationErrorAsPublic(err),
        };
        try self.applyValidatedPeerTransportParameters(params);
    }

    /// Apply peer parameters while accepting RFC 9368 compatible negotiation.
    ///
    /// This server-only path validates the peer's authenticated Version
    /// Information against explicit directional first-flight compatibility
    /// rules. The selected compatible version must match this connection's
    /// configured `chosen_version`; on success the peer parameters are applied
    /// and the selected version is returned.
    pub fn applyPeerTransportParametersWithCompatibleVersion(
        self: *Connection,
        params: transport_parameters.TransportParameters,
        compatibilities: []const VersionCompatibility,
    ) Error!packet.Version {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        const selected = self.validatePeerTransportParametersWithCompatibleVersion(
            params,
            compatibilities,
        ) catch |err| switch (err) {
            error.VersionNegotiationError => return error.InvalidPacket,
            else => return peerTransportParameterValidationErrorAsPublic(err),
        };
        try self.applyValidatedPeerTransportParameters(params);
        return selected;
    }

    fn applyValidatedPeerTransportParameters(
        self: *Connection,
        params: transport_parameters.TransportParameters,
    ) Error!void {
        const peer_preferred_address = if (params.preferred_address) |preferred|
            try PreferredAddress.fromTransportParameter(preferred)
        else
            null;
        var peer_available_versions: ?[]packet.Version = null;
        if (params.version_information) |version_information| {
            const owned_available_versions = self.allocator.alloc(packet.Version, version_information.available_versions.len) catch return error.OutOfMemory;
            errdefer self.allocator.free(owned_available_versions);
            @memcpy(owned_available_versions, version_information.available_versions);
            peer_available_versions = owned_available_versions;
        }
        errdefer if (peer_available_versions) |versions| self.allocator.free(versions);

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
        self.peer_preferred_address = peer_preferred_address;
        if (self.peer_version_information_available_versions) |old_versions| self.allocator.free(old_versions);
        self.peer_version_information_chosen_version = if (params.version_information) |version_information| version_information.chosen_version else null;
        self.peer_version_information_available_versions = peer_available_versions;
        peer_available_versions = null;
        self.peer_active_connection_id_limit = params.active_connection_id_limit;
        self.recovery_state.max_ack_delay_ns = @intCast(duration_mod.millisToNanos(@intCast(params.max_ack_delay)));
        self.syncRecoveryMaxDatagramSize();

        for (self.send_streams.items) |*stream| {
            stream.max_data = self.initialPeerStreamDataLimit(stream.stream_id);
        }
    }

    /// Parse TLS QUIC extension bytes and apply peer transport parameters.
    ///
    /// Parse errors and semantic validation failures are reported as
    /// `InvalidPacket`. The connection mutates only after the extension parses
    /// and passes the same validation used by `applyPeerTransportParameters()`.
    pub fn applyPeerTransportParameterBytes(
        self: *Connection,
        data: []const u8,
    ) Error!void {
        var params = transport_parameters.parse(data, self.allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidPacket,
        };
        defer params.deinit(self.allocator);
        try self.applyPeerTransportParameters(params);
    }

    /// Parse and apply peer parameters with explicit compatible-version rules.
    pub fn applyPeerTransportParameterBytesWithCompatibleVersion(
        self: *Connection,
        data: []const u8,
        compatibilities: []const VersionCompatibility,
    ) Error!packet.Version {
        var params = transport_parameters.parse(data, self.allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidPacket,
        };
        defer params.deinit(self.allocator);
        return try self.applyPeerTransportParametersWithCompatibleVersion(params, compatibilities);
    }

    /// Apply peer transport-parameter bytes and queue CONNECTION_CLOSE on peer errors.
    ///
    /// The input and success behavior match `applyPeerTransportParameterBytes()`.
    /// When parsing or peer-parameter validation identifies invalid peer
    /// transport parameters, this wrapper queues a transport CONNECTION_CLOSE
    /// with the CRYPTO frame type before returning `InvalidPacket`. Parsed
    /// RFC 9368 version-negotiation failures use `VERSION_NEGOTIATION_ERROR`;
    /// malformed transport parameters and other semantic failures use
    /// `TRANSPORT_PARAMETER_ERROR`.
    pub fn applyPeerTransportParameterBytesOrClose(
        self: *Connection,
        data: []const u8,
    ) Error!void {
        if (self.isClosingOrClosed()) return self.applyPeerTransportParameterBytes(data);

        var params = transport_parameters.parse(data, self.allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                if (transport_error.transportParameterErrorCode(err)) |code| {
                    try self.closeConnection(
                        transport_error.codeValue(code),
                        @backingInt(frame.FrameType.crypto),
                        "transport parameters",
                    );
                    return error.InvalidPacket;
                }
                return error.InvalidPacket;
            },
        };
        defer params.deinit(self.allocator);

        self.validatePeerTransportParameters(params) catch |err| switch (err) {
            error.VersionNegotiationError => {
                try self.closeConnection(
                    transport_error.codeValue(.version_negotiation_error),
                    @backingInt(frame.FrameType.crypto),
                    "version negotiation",
                );
                return error.InvalidPacket;
            },
            error.InvalidPacket => {
                try self.closeConnection(
                    transport_error.codeValue(.transport_parameter_error),
                    @backingInt(frame.FrameType.crypto),
                    "transport parameters",
                );
                return error.InvalidPacket;
            },
            else => return peerTransportParameterValidationErrorAsPublic(err),
        };

        try self.applyValidatedPeerTransportParameters(params);
    }

    /// Apply compatible-version peer parameter bytes and queue close on errors.
    ///
    /// Parsed RFC 9368 version-negotiation failures use
    /// `VERSION_NEGOTIATION_ERROR`; malformed transport parameters and other
    /// semantic failures use `TRANSPORT_PARAMETER_ERROR`.
    pub fn applyPeerTransportParameterBytesWithCompatibleVersionOrClose(
        self: *Connection,
        data: []const u8,
        compatibilities: []const VersionCompatibility,
    ) Error!packet.Version {
        if (self.isClosingOrClosed()) return self.applyPeerTransportParameterBytesWithCompatibleVersion(data, compatibilities);

        var params = transport_parameters.parse(data, self.allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                if (transport_error.transportParameterErrorCode(err)) |code| {
                    try self.closeConnection(
                        transport_error.codeValue(code),
                        @backingInt(frame.FrameType.crypto),
                        "transport parameters",
                    );
                    return error.InvalidPacket;
                }
                return error.InvalidPacket;
            },
        };
        defer params.deinit(self.allocator);

        const selected = self.validatePeerTransportParametersWithCompatibleVersion(
            params,
            compatibilities,
        ) catch |err| switch (err) {
            error.VersionNegotiationError => {
                try self.closeConnection(
                    transport_error.codeValue(.version_negotiation_error),
                    @backingInt(frame.FrameType.crypto),
                    "version negotiation",
                );
                return error.InvalidPacket;
            },
            error.InvalidPacket => {
                try self.closeConnection(
                    transport_error.codeValue(.transport_parameter_error),
                    @backingInt(frame.FrameType.crypto),
                    "transport parameters",
                );
                return error.InvalidPacket;
            },
            else => return peerTransportParameterValidationErrorAsPublic(err),
        };

        try self.applyValidatedPeerTransportParameters(params);
        return selected;
    }

    fn validateConnectionIdParameter(cid: ?[]const u8) Error!void {
        if (cid) |value| {
            if (value.len > max_connection_id_len) return error.InvalidPacket;
        }
    }

    fn validatePeerVersionInformation(
        self: Connection,
        version_information: transport_parameters.VersionInformation,
    ) PeerTransportParameterValidationError!void {
        try validatePeerVersionInformationSyntax(version_information);

        switch (self.side) {
            .server => {
                if (!version_information.containsAvailableVersion(version_information.chosen_version)) {
                    return error.InvalidPacket;
                }
                if (@backingInt(version_information.chosen_version) != @backingInt(self.config.chosen_version)) {
                    return error.VersionNegotiationError;
                }
            },
            .client => {
                if (!connection_version.versionListContains(self.config.available_versions, version_information.chosen_version)) {
                    return error.VersionNegotiationError;
                }
                if (self.version_negotiation_selected_version) |selected| {
                    if (@backingInt(version_information.chosen_version) != @backingInt(selected)) {
                        return error.VersionNegotiationError;
                    }
                    if (version_information.available_versions.len == 0) {
                        return error.VersionNegotiationError;
                    }
                    const preferred = connection_version.selectMutualVersionWithExtra(
                        self.config.available_versions,
                        version_information.available_versions,
                        version_information.chosen_version,
                    ) orelse return error.VersionNegotiationError;
                    if (@backingInt(preferred) != @backingInt(selected)) {
                        return error.VersionNegotiationError;
                    }
                }
            },
        }
    }

    fn validatePeerVersionInformationSyntax(
        version_information: transport_parameters.VersionInformation,
    ) PeerTransportParameterValidationError!void {
        if (connection_version.isZeroVersion(version_information.chosen_version)) return error.InvalidPacket;
        if (packet.isReservedVersion(version_information.chosen_version)) return error.VersionNegotiationError;
        for (version_information.available_versions) |available| {
            if (connection_version.isZeroVersion(available)) return error.InvalidPacket;
        }
    }

    fn validatePeerTransportParameterValues(
        self: Connection,
        params: transport_parameters.TransportParameters,
    ) PeerTransportParameterValidationError!void {
        try validatePeerTransportParameterIntegerBounds(params);
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
        try self.validateInitialSourceConnectionIdParameter(params.initial_source_connection_id);
        try self.validateOriginalDestinationConnectionIdParameter(params.original_destination_connection_id);
        try self.validateRetrySourceConnectionIdParameter(params.retry_source_connection_id);
        if (params.preferred_address) |preferred| {
            _ = try PreferredAddress.fromTransportParameter(preferred);
        }
    }

    fn validatePeerTransportParameterIntegerBounds(params: transport_parameters.TransportParameters) Error!void {
        const integer_values = [_]u64{
            params.max_idle_timeout,
            params.max_udp_payload_size,
            params.initial_max_data,
            params.initial_max_stream_data_bidi_local,
            params.initial_max_stream_data_bidi_remote,
            params.initial_max_stream_data_uni,
            params.initial_max_streams_bidi,
            params.initial_max_streams_uni,
            params.ack_delay_exponent,
            params.max_ack_delay,
            params.active_connection_id_limit,
        };
        for (integer_values) |value| {
            if (value > max_quic_varint) return error.InvalidPacket;
        }
        if (params.max_udp_payload_size > transport_parameters.max_udp_payload_size_default) {
            return error.InvalidPacket;
        }
    }

    fn validatePeerTransportParametersWithCompatibleVersion(
        self: Connection,
        params: transport_parameters.TransportParameters,
        compatibilities: []const VersionCompatibility,
    ) PeerTransportParameterValidationError!packet.Version {
        if (self.side != .server) return error.InvalidPacket;
        try self.validatePeerTransportParameterValues(params);
        const version_information = params.version_information orelse return error.InvalidPacket;
        try validatePeerVersionInformationSyntax(version_information);
        if (!version_information.containsAvailableVersion(version_information.chosen_version)) {
            return error.InvalidPacket;
        }
        const selected = selectCompatibleVersion(
            self.config.available_versions,
            version_information,
            compatibilities,
        ) orelse return error.VersionNegotiationError;
        if (@backingInt(selected) != @backingInt(self.config.chosen_version)) {
            return error.VersionNegotiationError;
        }
        return selected;
    }

    fn validatePeerTransportParameters(
        self: Connection,
        params: transport_parameters.TransportParameters,
    ) PeerTransportParameterValidationError!void {
        try self.validatePeerTransportParameterValues(params);
        if (params.version_information) |version_information| {
            try self.validatePeerVersionInformation(version_information);
        } else if (self.side == .client) {
            if (self.version_negotiation_selected_version) |selected| {
                if (@backingInt(selected) != @backingInt(packet.Version.v1)) return error.VersionNegotiationError;
            }
        }
    }

    fn validateOriginalDestinationConnectionIdParameter(self: Connection, original_destination_connection_id: ?[]const u8) Error!void {
        if (self.side != .client) return;
        if (self.originalDestinationConnectionId()) |expected| {
            const actual = original_destination_connection_id orelse return error.InvalidPacket;
            if (!std.mem.eql(u8, expected, actual)) return error.InvalidPacket;
        } else if (original_destination_connection_id != null) {
            return error.InvalidPacket;
        }
    }

    fn validateInitialSourceConnectionIdParameter(self: Connection, initial_source_connection_id: ?[]const u8) Error!void {
        if (self.peer_initial_source_connection_id) |expected| {
            const actual = initial_source_connection_id orelse return error.InvalidPacket;
            if (!std.mem.eql(u8, expected, actual)) return error.InvalidPacket;
        }
    }

    fn validateRetrySourceConnectionIdParameter(self: Connection, retry_source_connection_id: ?[]const u8) Error!void {
        if (self.side != .client) return;
        if (self.retry_source_connection_id) |expected| {
            const actual = retry_source_connection_id orelse return error.InvalidPacket;
            if (!std.mem.eql(u8, expected, actual)) return error.InvalidPacket;
        } else if (retry_source_connection_id != null) {
            return error.InvalidPacket;
        }
    }

    fn closeStateTimeout(self: Connection) u64 {
        var rs = self.recovery_state;
        return saturatingMulU64(close_state_pto_multiplier, rs.ptoNs());
    }

    fn closeStateDeadline(self: Connection, now_nanos: i64) i64 {
        return saturatingAdd(now_nanos, self.closeStateTimeout());
    }

    fn clearPendingCloseFrame(self: *Connection) void {
        if (self.pending_close) |*pending_close| {
            deinitPendingCloseFrame(pending_close, self.allocator);
            self.pending_close = null;
        }
    }

    fn clearPeerClose(self: *Connection) void {
        if (self.peer_close) |*peer_close| {
            deinitPeerClose(peer_close, self.allocator);
            self.peer_close = null;
        }
    }

    fn enterClosingState(self: *Connection, now_nanos: i64) void {
        self.state = .closing;
        self.close_deadline_nanos = self.closeStateDeadline(now_nanos);
        self.closed = true;
    }

    fn enterDrainingState(self: *Connection, now_nanos: i64) void {
        self.state = .draining;
        self.close_deadline_nanos = self.closeStateDeadline(now_nanos);
        self.closed = true;
    }

    fn receiveConnectionCloseFrame(self: *Connection, now_nanos: i64, close: frame.ConnectionCloseFrame) Error!void {
        if (self.peer_close == null) {
            const owned_reason = self.allocator.alloc(u8, close.reason_phrase.len) catch return error.OutOfMemory;
            errdefer self.allocator.free(owned_reason);
            @memcpy(owned_reason, close.reason_phrase);
            self.peer_close = .{ .connection = .{
                .error_code = close.error_code,
                .frame_type = close.frame_type,
                .reason_phrase = owned_reason,
            } };
        }
        self.enterDrainingState(now_nanos);
    }

    fn receiveApplicationCloseFrame(self: *Connection, now_nanos: i64, close: frame.ApplicationCloseFrame) Error!void {
        if (self.peer_close == null) {
            const owned_reason = self.allocator.alloc(u8, close.reason_phrase.len) catch return error.OutOfMemory;
            errdefer self.allocator.free(owned_reason);
            @memcpy(owned_reason, close.reason_phrase);
            self.peer_close = .{ .application = .{
                .error_code = close.error_code,
                .reason_phrase = owned_reason,
            } };
        }
        self.enterDrainingState(now_nanos);
    }

    fn expireCloseState(self: *Connection, now_nanos: i64) void {
        if (self.state != .closing and self.state != .draining) return;
        const deadline = self.close_deadline_nanos orelse return;
        if (now_nanos < deadline) return;

        self.state = .closed;
        self.close_deadline_nanos = null;
        self.closed = true;
        self.clearPendingCloseFrame();
    }

    fn expireIdleState(self: *Connection, now_nanos: i64) void {
        if (self.state != .active) return;
        if (self.pending_close != null) return;
        const deadline = self.idleTimeoutDeadline() orelse return;
        if (now_nanos < deadline) return;

        self.state = .closed;
        self.close_deadline_nanos = null;
        self.closed = true;
        self.clearPendingCloseFrame();
    }

    fn recordPacketActivity(self: *Connection, now_nanos: i64) void {
        if (self.effectiveIdleTimeout() == null) return;
        self.last_packet_activity_nanos = now_nanos;
    }

    /// Whether the connection is closing, draining, or fully closed.
    pub fn isClosingOrClosed(self: Connection) bool {
        return self.state != .active or self.pending_close != null or self.closed;
    }

    fn prepareInboundDatagramProcessing(self: *Connection, now_nanos: i64) Error!bool {
        self.expireIdleState(now_nanos);
        self.expireCloseState(now_nanos);
        _ = self.discardExpiredOneRttKeys(now_nanos);
        if (self.state == .closing or self.state == .draining) return false;
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        return true;
    }

    pub fn maxTxDatagramSize(self: Connection) usize {
        return @min(@as(usize, self.config.max_datagram_size), self.peer_max_udp_payload_size);
    }

    fn validateReceivedUdpDatagramSize(self: Connection, datagram: []const u8) Error!void {
        if (datagram.len == 0 or datagram.len > self.config.max_datagram_size) return error.InvalidPacket;
    }

    fn syncRecoveryMaxDatagramSize(self: *Connection) void {
        const max_datagram_size = self.maxTxDatagramSize();
        self.initial_packet_space.recovery_state.updateMaxDatagramSize(max_datagram_size);
        self.handshake_packet_space.recovery_state.updateMaxDatagramSize(max_datagram_size);
        self.recovery_state.updateMaxDatagramSize(max_datagram_size);
    }

    fn isAntiAmplificationLimited(self: Connection) bool {
        return self.side == .server and !self.peer_address_validated;
    }

    fn canSendToPeerAddress(self: Connection, bytes: usize) bool {
        const remaining = self.antiAmplificationLimitRemaining() orelse return true;
        return bytes <= remaining;
    }

    fn serverAtAntiAmplificationLimit(self: Connection) bool {
        const remaining = self.antiAmplificationLimitRemaining() orelse return false;
        return remaining == 0;
    }

    pub fn initialTokenForPacket(self: Connection, space: PacketNumberSpace, token: []const u8) []const u8 {
        if (space != .initial or token.len != 0) return token;
        return self.retry_token orelse &[_]u8{};
    }

    fn recordPeerAddressBytesSent(self: *Connection, bytes: usize) void {
        if (!self.isAntiAmplificationLimited()) return;
        self.peer_address_bytes_sent = std.math.add(usize, self.peer_address_bytes_sent, bytes) catch std.math.maxInt(usize);
    }

    fn consumePendingRetryToken(self: *Connection, token: []const u8) bool {
        for (self.retry_tokens.items, 0..) |existing, i| {
            if (!std.mem.eql(u8, existing, token)) continue;
            const removed = self.retry_tokens.orderedRemove(i);
            self.allocator.free(removed);
            return true;
        }
        return false;
    }

    pub fn hasPendingRetryToken(self: *const Connection, token: []const u8) bool {
        for (self.retry_tokens.items) |existing| {
            if (std.mem.eql(u8, existing, token)) return true;
        }
        return false;
    }

    fn initialPeerStreamDataLimit(self: Connection, stream_id: u64) u64 {
        if (!isBidirectionalStream(stream_id)) return self.peer_initial_max_stream_data_uni;
        if (isLocalStreamInitiator(self.side, stream_id)) return self.peer_initial_max_stream_data_bidi_remote;
        return self.peer_initial_max_stream_data_bidi_local;
    }

    fn scaledPeerAckDelay(self: Connection, ack_delay: u64) u64 {
        const multiplier = std.math.shl(u64, 1, self.peer_ack_delay_exponent);
        return saturatingMulU64(ack_delay, multiplier);
    }

    pub fn ackDelayForRtt(self: Connection, space: PacketNumberSpace, ack_delay: u64) u64 {
        if (space == .initial or space == .handshake) return 0;
        const scaled_ack_delay_ns = self.scaledPeerAckDelay(ack_delay) * 1000; // μs→ns
        if (!self.handshake_confirmed) return scaled_ack_delay_ns;
        return @min(scaled_ack_delay_ns, self.recovery_state.max_ack_delay_ns);
    }

    fn rttEstimateSnapshot(self: *Connection, space: PacketNumberSpace) RttEstimateSnapshot {
        const packet_space = self.packetNumberSpace(space);
        return .{
            .first_rtt_sample_sent_time_nanos = packet_space.first_rtt_sample_sent_time_nanos.*,
            .latest_rtt_ns = packet_space.recovery_state.latest_rtt_ns,
            .min_rtt_ns = packet_space.recovery_state.min_rtt_ns,
            .smoothed_rtt_ns = packet_space.recovery_state.smoothed_rtt_ns,
            .rttvar_ns = packet_space.recovery_state.rttvar_ns,
        };
    }

    fn restoreRttEstimateSnapshot(
        self: *Connection,
        space: PacketNumberSpace,
        snapshot: RttEstimateSnapshot,
    ) void {
        const packet_space = self.packetNumberSpace(space);
        packet_space.first_rtt_sample_sent_time_nanos.* = snapshot.first_rtt_sample_sent_time_nanos;
        packet_space.recovery_state.latest_rtt_ns = snapshot.latest_rtt_ns;
        packet_space.recovery_state.min_rtt_ns = snapshot.min_rtt_ns;
        packet_space.recovery_state.smoothed_rtt_ns = snapshot.smoothed_rtt_ns;
        packet_space.recovery_state.rttvar_ns = snapshot.rttvar_ns;
    }

    fn ptoBackoffSnapshot(self: Connection) PtoBackoffSnapshot {
        return .{
            .initial = self.initial_packet_space.recovery_state.pto_count,
            .handshake = self.handshake_packet_space.recovery_state.pto_count,
            .application = self.recovery_state.pto_count,
        };
    }

    fn restorePtoBackoffSnapshot(self: *Connection, snapshot: PtoBackoffSnapshot) void {
        self.initial_packet_space.recovery_state.pto_count = snapshot.initial;
        self.handshake_packet_space.recovery_state.pto_count = snapshot.handshake;
        self.recovery_state.pto_count = snapshot.application;
    }

    fn connectionPtoBackoffCount(self: Connection) u8 {
        var count: u8 = 0;
        if (!self.initial_packet_space.discarded) {
            count = @max(count, self.initial_packet_space.recovery_state.pto_count);
        }
        if (!self.handshake_packet_space.discarded) {
            count = @max(count, self.handshake_packet_space.recovery_state.pto_count);
        }
        if (!self.application_packet_space_discarded) {
            count = @max(count, self.recovery_state.pto_count);
        }
        return count;
    }

    fn setConnectionPtoBackoffCount(self: *Connection, count: u8) void {
        if (!self.initial_packet_space.discarded) {
            self.initial_packet_space.recovery_state.pto_count = count;
        }
        if (!self.handshake_packet_space.discarded) {
            self.handshake_packet_space.recovery_state.pto_count = count;
        }
        if (!self.application_packet_space_discarded) {
            self.recovery_state.pto_count = count;
        }
    }

    fn resetConnectionPtoBackoff(self: *Connection) void {
        self.setConnectionPtoBackoffCount(0);
    }

    fn ackShouldResetPtoBackoff(self: Connection, space: PacketNumberSpace) bool {
        // RFC 9002 keeps the PTO backoff armed for client Initial ACKs because
        // the client cannot treat those ACKs as proof that the server has
        // validated the client's address.
        return !(self.side == .client and space == .initial);
    }

    fn increaseConnectionPtoBackoff(self: *Connection) void {
        const current = self.connectionPtoBackoffCount();
        const next = if (current == std.math.maxInt(u8)) current else current + 1;
        self.setConnectionPtoBackoffCount(next);
    }

    fn rememberFirstRttSampleSentTime(self: *Connection, sent_time_nanos: i64) void {
        const spaces = [_]PacketNumberSpace{ .initial, .handshake, .application };
        for (spaces) |sample_space| {
            const packet_space = self.packetNumberSpace(sample_space);
            if (packet_space.discarded.*) continue;
            if (packet_space.first_rtt_sample_sent_time_nanos.* == null) {
                packet_space.first_rtt_sample_sent_time_nanos.* = sent_time_nanos;
            }
        }
    }

    fn syncRttEstimatesFromSpace(self: *Connection, source_space: PacketNumberSpace) void {
        const source_packet_space = self.packetNumberSpace(source_space);
        const source_recovery = source_packet_space.recovery_state.*;
        const spaces = [_]PacketNumberSpace{ .initial, .handshake, .application };
        for (spaces) |target_space| {
            if (target_space == source_space) continue;
            const target_packet_space = self.packetNumberSpace(target_space);
            if (target_packet_space.discarded.*) continue;
            target_packet_space.recovery_state.latest_rtt_ns = source_recovery.latest_rtt_ns;
            target_packet_space.recovery_state.min_rtt_ns = source_recovery.min_rtt_ns;
            target_packet_space.recovery_state.smoothed_rtt_ns = source_recovery.smoothed_rtt_ns;
            target_packet_space.recovery_state.rttvar_ns = source_recovery.rttvar_ns;
        }
    }

    fn markHandshakeSpaceUsed(self: *Connection, space: PacketNumberSpace) void {
        if (space == .handshake and self.handshake_state == .initial) {
            self.handshake_state = .handshake;
        }
    }

    fn maybeDiscardInitialAfterHandshakePacketSent(self: *Connection, space: PacketNumberSpace) void {
        if (self.side != .client or space != .handshake or self.isClosingOrClosed()) return;
        self.discardPacketNumberSpaceState(.initial);
    }

    fn maybeDiscardInitialAfterHandshakePacketReceived(self: *Connection, space: PacketNumberSpace) void {
        if (self.side != .server or space != .handshake or self.isClosingOrClosed()) return;
        self.discardPacketNumberSpaceState(.initial);
    }

    fn maybeDiscardHandshakeAfterConfirmedCryptoSent(self: *Connection, space: PacketNumberSpace) void {
        if (space != .handshake or !self.handshake_confirmed or self.isClosingOrClosed()) return;

        const packet_space = self.packetNumberSpace(.handshake);
        if (packet_space.discarded.* or packet_space.crypto_send_queue.items.len != 0) return;
        self.discardPacketNumberSpaceState(.handshake);
    }

    fn packetNumberSpace(self: *Connection, space: PacketNumberSpace) PacketNumberSpaceView {
        return switch (space) {
            .initial => .{
                .discarded = &self.initial_packet_space.discarded,
                .next_packet_number = &self.initial_packet_space.next_packet_number,
                .next_peer_packet_number = &self.initial_packet_space.next_peer_packet_number,
                .pending_ack_largest = &self.initial_packet_space.pending_ack_largest,
                .received_packet_ranges = &self.initial_packet_space.received_packet_ranges,
                .largest_acknowledged = &self.initial_packet_space.largest_acknowledged,
                .first_rtt_sample_sent_time_nanos = &self.initial_packet_space.first_rtt_sample_sent_time_nanos,
                .loss_deadline_nanos = &self.initial_packet_space.loss_deadline_nanos,
                .recovery_state = &self.initial_packet_space.recovery_state,
                .sent_packets = &self.initial_packet_space.sent_packets,
                .pending_ping_count = &self.initial_packet_space.pending_ping_count,
                .pto_probe_count = &self.initial_packet_space.pto_probe_count,
                .congestion_probe_count = &self.initial_packet_space.congestion_probe_count,
                .crypto_send_offset = &self.initial_packet_space.crypto_send_offset,
                .crypto_recv_buffer = &self.initial_packet_space.crypto_recv_buffer,
                .crypto_read_offset = &self.initial_packet_space.crypto_read_offset,
                .crypto_send_queue = &self.initial_packet_space.crypto_send_queue,
                .crypto_recv_pending = &self.initial_packet_space.crypto_recv_pending,
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
                .received_packet_ranges = &self.handshake_packet_space.received_packet_ranges,
                .largest_acknowledged = &self.handshake_packet_space.largest_acknowledged,
                .first_rtt_sample_sent_time_nanos = &self.handshake_packet_space.first_rtt_sample_sent_time_nanos,
                .loss_deadline_nanos = &self.handshake_packet_space.loss_deadline_nanos,
                .recovery_state = &self.handshake_packet_space.recovery_state,
                .sent_packets = &self.handshake_packet_space.sent_packets,
                .pending_ping_count = &self.handshake_packet_space.pending_ping_count,
                .pto_probe_count = &self.handshake_packet_space.pto_probe_count,
                .congestion_probe_count = &self.handshake_packet_space.congestion_probe_count,
                .crypto_send_offset = &self.handshake_packet_space.crypto_send_offset,
                .crypto_recv_buffer = &self.handshake_packet_space.crypto_recv_buffer,
                .crypto_read_offset = &self.handshake_packet_space.crypto_read_offset,
                .crypto_send_queue = &self.handshake_packet_space.crypto_send_queue,
                .crypto_recv_pending = &self.handshake_packet_space.crypto_recv_pending,
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
                .received_packet_ranges = &self.received_packet_ranges,
                .largest_acknowledged = &self.largest_acknowledged,
                .first_rtt_sample_sent_time_nanos = &self.first_rtt_sample_sent_time_nanos,
                .loss_deadline_nanos = &self.loss_deadline_nanos,
                .recovery_state = &self.recovery_state,
                .sent_packets = &self.sent_packets,
                .pending_ping_count = &self.pending_ping_count,
                .pto_probe_count = &self.pto_probe_count,
                .congestion_probe_count = &self.congestion_probe_count,
                .crypto_send_offset = &self.crypto_send_offset,
                .crypto_recv_buffer = &self.crypto_recv_buffer,
                .crypto_read_offset = &self.crypto_read_offset,
                .crypto_send_queue = &self.crypto_send_queue,
                .crypto_recv_pending = &self.crypto_recv_pending,
                .ecn_sent_ect0 = &self.ecn_sent_ect0,
                .ecn_sent_ect1 = &self.ecn_sent_ect1,
                .ecn_largest_acknowledged = &self.ecn_largest_acknowledged,
                .ecn_counts = &self.ecn_counts,
                .ecn_validation_state = &self.ecn_validation_state,
            },
        };
    }

    fn canSendAckElicitingInSpace(self: *Connection, space: PacketNumberSpace, bytes: usize) bool {
        const packet_space = self.packetNumberSpace(space);
        const total_in_flight = self.totalBytesInFlight();
        const after_send = std.math.add(usize, total_in_flight, bytes) catch return false;
        return packet_space.pto_probe_count.* != 0 or
            packet_space.congestion_probe_count.* != 0 or
            after_send <= packet_space.recovery_state.congestion_window;
    }

    fn armPtoProbeInSpace(self: *Connection, space: PacketNumberSpace) void {
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.pto_probe_count.* == 0) {
            packet_space.pto_probe_count.* = 1;
        }
    }

    fn armCongestionProbeInSpace(self: *Connection, space: PacketNumberSpace) void {
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.congestion_probe_count.* == 0) {
            packet_space.congestion_probe_count.* = 1;
        }
    }

    fn recordAckElicitingSendInSpace(self: *Connection, space: PacketNumberSpace, bytes: usize) void {
        const packet_space = self.packetNumberSpace(space);
        packet_space.recovery_state.largest_sent_packet_number = self.next_packet_number;
        packet_space.recovery_state.onPacketSent(bytes);
        packet_space.recovery_state.fast_retransmission_required = false;
        packet_space.recovery_state.last_sent_time_nanos = @intCast(clock.nanoTimestamp());
        self.anti_deadlock_pto_start_nanos = null;
        if (packet_space.pto_probe_count.* != 0) {
            packet_space.pto_probe_count.* -= 1;
        }
        if (packet_space.congestion_probe_count.* != 0) {
            packet_space.congestion_probe_count.* -= 1;
        }
    }

    /// Process one unencrypted packet payload containing one or more QUIC frames.
    ///
    /// Closing or draining connections discard the datagram before parsing.
    pub fn processDatagram(
        self: *Connection,
        now_nanos: i64,
        datagram: []const u8,
    ) Error!void {
        try self.processDatagramInSpace(.application, now_nanos, datagram);
    }

    /// Process one unencrypted packet payload and queue CONNECTION_CLOSE on classified peer errors.
    ///
    /// This is the Application-space counterpart to
    /// `processDatagramForPacketTypeOrClose()`. Existing callers that need
    /// pure rollback behavior can continue using `processDatagram()`.
    pub fn processDatagramOrClose(
        self: *Connection,
        now_nanos: i64,
        datagram: []const u8,
    ) Error!void {
        try self.processDatagramInSpaceOrClose(.application, now_nanos, datagram);
    }

    /// Process one frame-payload datagram in a selected packet number space.
    ///
    /// This keeps ACK generation and ACK processing isolated between Initial,
    /// Handshake, and Application spaces while the repository still lacks
    /// protected QUIC packetization. Closing or draining connections discard
    /// the datagram before parsing.
    pub fn processDatagramInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        now_nanos: i64,
        datagram: []const u8,
    ) Error!void {
        try self.processFramesInSpaceNoSnapshot(
            space,
            defaultFramePacketTypeForSpace(space),
            now_nanos,
            datagram,
            null,
        );
    }

    /// Process one selected-space frame-payload datagram and queue CONNECTION_CLOSE on classified peer errors.
    ///
    /// Initial and Handshake spaces use their matching packet-type frame rules.
    /// Application space uses 1-RTT frame rules. Existing callers that need pure
    /// rollback behavior can continue using `processDatagramInSpace()`.
    pub fn processDatagramInSpaceOrClose(
        self: *Connection,
        space: PacketNumberSpace,
        now_nanos: i64,
        datagram: []const u8,
    ) Error!void {
        try self.processDatagramForPacketTypeOrClose(
            defaultFramePacketTypeForSpace(space),
            now_nanos,
            datagram,
        );
    }

    /// Process a UDP datagram containing coalesced protected long-header packets.
    ///
    /// The method currently routes Initial, 0-RTT, and Handshake protected
    /// packets. It first validates that every coalesced packet has
    /// caller-supplied keys and a supported packet type, so missing-key or
    /// unsupported-type failures do not partially mutate connection state. Each
    /// successfully opened packet is then routed through the matching packet
    /// number space. It returns 0 when closing or draining packets are discarded
    /// before parsing. 0-RTT uses Application packet numbers while still
    /// applying 0-RTT frame restrictions. Retry packets are handled separately
    /// by `processRetryDatagram()`. Real TLS transcript ownership and key
    /// discard remain future endpoint/TLS work.
    pub fn processProtectedLongDatagram(
        self: *Connection,
        now_nanos: i64,
        keys: ProtectedLongDatagramKeys,
        datagram: []const u8,
    ) Error!usize {
        return self.processProtectedLongDatagramWithFrameErrorPolicy(now_nanos, keys, datagram, false);
    }

    /// Process coalesced protected long-header packets and queue CONNECTION_CLOSE on frame errors.
    ///
    /// Packet parsing, version/key routing, packet-number validation, and
    /// success behavior match `processProtectedLongDatagram()`. After a packet
    /// authenticates, malformed/unknown frame payloads or frames forbidden for
    /// that long-header packet type queue a transport CONNECTION_CLOSE before
    /// returning `InvalidPacket`.
    pub fn processProtectedLongDatagramOrClose(
        self: *Connection,
        now_nanos: i64,
        keys: ProtectedLongDatagramKeys,
        datagram: []const u8,
    ) Error!usize {
        return self.processProtectedLongDatagramWithFrameErrorPolicy(now_nanos, keys, datagram, true);
    }

    fn processProtectedLongDatagramWithFrameErrorPolicy(
        self: *Connection,
        now_nanos: i64,
        keys: ProtectedLongDatagramKeys,
        datagram: []const u8,
        close_on_frame_payload_error: bool,
    ) Error!usize {
        if (datagram.len == 0) return error.InvalidPacket;
        if (!try self.prepareInboundDatagramProcessing(now_nanos)) return 0;
        try self.validateReceivedUdpDatagramSize(datagram);

        // Validation pass: walk the coalesced packets. RFC 9000 §12.2 lets a
        // receiver discard an unparseable datagram remainder, which stacks use
        // for datagram-level padding after a client Initial (e.g. quiche fills
        // the tail with null bytes), so stop at the first unsupported packet
        // after at least one valid packet instead of rejecting the datagram.
        var offset: usize = 0;
        var packet_count: usize = 0;
        var coalesced_end: usize = 0;
        while (offset < datagram.len) {
            const info = protection.peekProtectedLongPacketInfo(datagram[offset..]) catch {
                if (offset > 0) break;
                return error.InvalidPacket;
            };
            if (@backingInt(info.version) != @backingInt(self.config.chosen_version) or info.len == 0) {
                if (offset > 0) break;
                return error.InvalidPacket;
            }
            const route = protectedLongPacketRouteFor(keys, info.packet_type) orelse {
                if (offset > 0) break;
                return error.InvalidPacket;
            };
            const packet_space = self.packetNumberSpace(route.space);
            if (packet_space.discarded.*) {
                if (offset > 0) break;
                return error.InvalidPacket;
            }
            offset = std.math.add(usize, offset, info.len) catch return error.InvalidPacket;
            packet_count += 1;
            coalesced_end = offset;
        }

        offset = 0;
        var processed_count: usize = 0;
        while (offset < coalesced_end) {
            const info = protection.peekProtectedLongPacketInfo(datagram[offset..]) catch return error.InvalidPacket;
            if (@backingInt(info.version) != @backingInt(self.config.chosen_version) or info.len == 0) return error.InvalidPacket;
            const route = protectedLongPacketRouteFor(keys, info.packet_type) orelse return error.InvalidPacket;
            try self.processProtectedLongDatagramWithRoute(
                route,
                now_nanos,
                datagram.len,
                datagram[offset..][0..info.len],
                close_on_frame_payload_error,
            );
            offset += info.len;
            processed_count += 1;
        }

        std.debug.assert(processed_count == packet_count);
        return processed_count;
    }

    /// Remove long-header packet protection for Initial or Handshake space.
    ///
    /// This accepts exactly one protected long packet for the connection's
    /// configured QUIC version and the selected Initial or Handshake packet
    /// number space, decrypts it with caller-supplied keys, requires the packet
    /// number to match the next expected value for that space, then routes the
    /// plaintext through the matching frame rules.
    /// Closing or draining connections discard the datagram before parsing.
    /// Coalesced packets, 1-RTT protected transmit, real TLS transcript
    /// ownership, key discard, and key update remain endpoint/TLS integration
    /// work.
    pub fn processProtectedLongDatagramInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        now_nanos: i64,
        keys: protection.Aes128PacketProtectionKeys,
        datagram: []const u8,
    ) Error!void {
        try self.processProtectedLongDatagramInSpaceWithFrameErrorPolicy(space, now_nanos, keys, datagram, false);
    }

    /// Remove long-header protection and queue CONNECTION_CLOSE on frame errors.
    ///
    /// This opt-in wrapper preserves `processProtectedLongDatagramInSpace()`
    /// success behavior, but authenticated plaintext frame encoding failures
    /// and packet-type violations queue a transport CONNECTION_CLOSE before
    /// returning `InvalidPacket`.
    pub fn processProtectedLongDatagramInSpaceOrClose(
        self: *Connection,
        space: PacketNumberSpace,
        now_nanos: i64,
        keys: protection.Aes128PacketProtectionKeys,
        datagram: []const u8,
    ) Error!void {
        try self.processProtectedLongDatagramInSpaceWithFrameErrorPolicy(space, now_nanos, keys, datagram, true);
    }

    fn processProtectedLongDatagramInSpaceWithFrameErrorPolicy(
        self: *Connection,
        space: PacketNumberSpace,
        now_nanos: i64,
        keys: protection.Aes128PacketProtectionKeys,
        datagram: []const u8,
        close_on_frame_payload_error: bool,
    ) Error!void {
        if (!try self.prepareInboundDatagramProcessing(now_nanos)) return;
        try self.validateReceivedUdpDatagramSize(datagram);

        const long_space = protectedLongPacketSpaceFor(space) orelse return error.InvalidPacket;
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;

        try self.processProtectedLongDatagramWithRoute(.{
            .space = space,
            .packet_type = long_space.packet_type,
            .frame_packet_type = long_space.frame_packet_type,
            .keys = keys,
        }, now_nanos, datagram.len, datagram, close_on_frame_payload_error);
    }

    /// Remove Handshake long-header protection using installed peer keys.
    ///
    /// Call `installHandshakeTrafficSecrets()` or drive a `CryptoBackend` that
    /// returns Handshake traffic secrets before using this helper. Failed
    /// packets keep the Handshake packet-number space unchanged through the
    /// same rollback boundary as the caller-keyed helper.
    pub fn processProtectedHandshakeDatagramWithInstalledKeys(
        self: *Connection,
        now_nanos: i64,
        datagram: []const u8,
    ) Error!void {
        const keys = self.peer_handshake_keys orelse return error.InvalidPacket;
        try self.processProtectedLongDatagramInSpace(.handshake, now_nanos, keys, datagram);
    }

    /// Process a coalesced Initial and Handshake UDP datagram using caller
    /// Initial keys and the installed peer Handshake keys.
    ///
    /// This keeps the exact UDP datagram length available for RFC 9000 Initial
    /// size validation while `processProtectedLongDatagram()` slices each
    /// authenticated long-header packet at its encoded boundary.
    pub fn processProtectedLongDatagramWithInstalledHandshakeKeys(
        self: *Connection,
        now_nanos: i64,
        initial_keys: protection.Aes128PacketProtectionKeys,
        datagram: []const u8,
    ) Error!usize {
        const handshake_keys = self.peer_handshake_keys orelse return error.InvalidPacket;
        return self.processProtectedLongDatagram(now_nanos, .{
            .initial = initial_keys,
            .handshake = handshake_keys,
        }, datagram);
    }

    /// Remove installed-key Handshake protection and queue CONNECTION_CLOSE on frame errors.
    ///
    /// This keeps the installed-key lookup and success path of
    /// `processProtectedHandshakeDatagramWithInstalledKeys()`, while applying
    /// the close-propagating protected long-packet receive policy after packet
    /// authentication succeeds.
    pub fn processProtectedHandshakeDatagramWithInstalledKeysOrClose(
        self: *Connection,
        now_nanos: i64,
        datagram: []const u8,
    ) Error!void {
        const keys = self.peer_handshake_keys orelse return error.InvalidPacket;
        try self.processProtectedLongDatagramInSpaceOrClose(.handshake, now_nanos, keys, datagram);
    }

    fn processProtectedLongDatagramWithRoute(
        self: *Connection,
        route: ProtectedLongPacketRoute,
        now_nanos: i64,
        udp_datagram_len: usize,
        datagram: []const u8,
        close_on_frame_payload_error: bool,
    ) Error!void {
        const packet_space = self.packetNumberSpace(route.space);
        if (packet_space.discarded.*) return error.InvalidPacket;
        try self.validateIncomingInitialDatagramLen(route.space, udp_datagram_len);

        const expected_packet_number = packet_space.next_peer_packet_number.*;
        var decoded = protection.unprotectLongPacketAes128(
            self.allocator,
            route.keys,
            datagram,
            expected_packet_number,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidPacket,
        };
        defer protection.deinitProtectedLongPacket(&decoded, self.allocator);

        if (decoded.len != datagram.len) return error.InvalidPacket;
        if (@backingInt(decoded.packet.header.version) != @backingInt(self.config.chosen_version) or decoded.packet.header.packet_type != route.packet_type) {
            return error.InvalidPacket;
        }
        // RFC 9000 §13.1: packets with an already-received or below-window
        // packet number are discarded, not treated as a connection error
        // (e.g. a client Initial retransmitted while the server flight was
        // lost).
        if (!packet_space.received_packet_ranges.canRecord(decoded.packet.header.packet_number)) return;

        const pending_original_destination_dcid = if (route.space == .initial and self.side == .server and self.original_destination_connection_id_len == null)
            decoded.packet.header.dcid
        else
            null;
        if (pending_original_destination_dcid) |dcid| {
            try validateInitialDestinationConnectionIdLength(dcid);
        }
        if (route.space == .initial and self.side == .client and decoded.packet.header.token.len != 0) {
            return error.InvalidPacket;
        }
        if (route.space == .initial) {
            if (self.peer_initial_source_connection_id) |expected| {
                if (!std.mem.eql(u8, expected, decoded.packet.header.scid)) return error.InvalidPacket;
            }
        }
        const pending_peer_initial_scid = if (route.space == .initial and self.peer_initial_source_connection_id == null)
            self.allocator.dupe(u8, decoded.packet.header.scid) catch return error.OutOfMemory
        else
            null;
        errdefer if (pending_peer_initial_scid) |cid| self.allocator.free(cid);

        try self.processDatagramInSpaceWithPacketTypeMaybeClose(
            route.space,
            route.frame_packet_type,
            now_nanos,
            decoded.packet.plaintext,
            close_on_frame_payload_error,
            decoded.packet.header.packet_number,
        );
        const packet_space_after = self.packetNumberSpace(route.space);
        _ = try self.recordReceivedPacketNumber(packet_space_after, decoded.packet.header.packet_number);
        if (pending_original_destination_dcid) |cid| {
            self.recordOriginalDestinationConnectionId(cid);
        }
        if (pending_peer_initial_scid) |cid| {
            self.peer_initial_source_connection_id = cid;
        }
    }

    /// Remove 0-RTT long-header packet protection and process the decrypted payload.
    ///
    /// 0-RTT packets share the Application packet number space with 1-RTT, but
    /// this method routes the plaintext through 0-RTT frame restrictions.
    /// Closing or draining connections discard the datagram before parsing. The
    /// caller supplies the 0-RTT traffic keys; TLS secret production, rejection
    /// policy, and replay defenses remain endpoint/TLS integration work.
    pub fn processProtectedZeroRttDatagram(
        self: *Connection,
        now_nanos: i64,
        keys: protection.Aes128PacketProtectionKeys,
        datagram: []const u8,
    ) Error!void {
        try self.processProtectedZeroRttDatagramWithFrameErrorPolicy(now_nanos, keys, datagram, false);
    }

    /// Remove 0-RTT protection and queue CONNECTION_CLOSE on frame errors.
    ///
    /// This opt-in wrapper keeps the packet-number and success behavior of
    /// `processProtectedZeroRttDatagram()`, but authenticated 0-RTT plaintext
    /// frame encoding failures or 0-RTT-forbidden frames queue a transport
    /// CONNECTION_CLOSE before returning `InvalidPacket`.
    pub fn processProtectedZeroRttDatagramOrClose(
        self: *Connection,
        now_nanos: i64,
        keys: protection.Aes128PacketProtectionKeys,
        datagram: []const u8,
    ) Error!void {
        try self.processProtectedZeroRttDatagramWithFrameErrorPolicy(now_nanos, keys, datagram, true);
    }

    fn processProtectedZeroRttDatagramWithFrameErrorPolicy(
        self: *Connection,
        now_nanos: i64,
        keys: protection.Aes128PacketProtectionKeys,
        datagram: []const u8,
        close_on_frame_payload_error: bool,
    ) Error!void {
        if (!try self.prepareInboundDatagramProcessing(now_nanos)) return;
        if (self.side != .server) return error.InvalidPacket;
        try self.validateReceivedUdpDatagramSize(datagram);

        try self.processProtectedLongDatagramWithRoute(.{
            .space = .application,
            .packet_type = .zero_rtt,
            .frame_packet_type = .zero_rtt,
            .keys = keys,
        }, now_nanos, datagram.len, datagram, close_on_frame_payload_error);
    }

    /// Remove 0-RTT long-header protection using installed peer early-data keys.
    ///
    /// Call `installZeroRttTrafficSecrets()` or drive a `CryptoBackend` that
    /// returns a peer 0-RTT secret, then `acceptZeroRtt()` after TLS policy
    /// accepts early data. Replay defense remains caller-owned endpoint/TLS
    /// work.
    pub fn processProtectedZeroRttDatagramWithInstalledKeys(
        self: *Connection,
        now_nanos: i64,
        datagram: []const u8,
    ) Error!void {
        const keys = self.peer_zero_rtt_keys orelse return error.InvalidPacket;
        if (!self.peer_zero_rtt_accepted) return error.InvalidPacket;
        try self.processProtectedZeroRttDatagram(now_nanos, keys, datagram);
    }

    /// Remove installed-key 0-RTT protection and queue CONNECTION_CLOSE on frame errors.
    ///
    /// This keeps installed-key lookup and explicit 0-RTT acceptance unchanged,
    /// while using the close-propagating protected 0-RTT receive policy after
    /// packet authentication succeeds.
    pub fn processProtectedZeroRttDatagramWithInstalledKeysOrClose(
        self: *Connection,
        now_nanos: i64,
        datagram: []const u8,
    ) Error!void {
        const keys = self.peer_zero_rtt_keys orelse return error.InvalidPacket;
        if (!self.peer_zero_rtt_accepted) return error.InvalidPacket;
        try self.processProtectedZeroRttDatagramOrClose(now_nanos, keys, datagram);
    }

    /// Remove Initial packet protection and process the decrypted frame payload.
    ///
    /// This compatibility wrapper routes one protected Initial long packet
    /// through `processProtectedLongDatagramInSpace(.initial, ...)`.
    pub fn processInitialProtectedDatagram(
        self: *Connection,
        now_nanos: i64,
        keys: protection.Aes128PacketProtectionKeys,
        datagram: []const u8,
    ) Error!void {
        try self.processProtectedLongDatagramInSpace(.initial, now_nanos, keys, datagram);
    }

    /// Remove 1-RTT short-header packet protection and process the frame payload.
    ///
    /// This accepts exactly one protected short-header datagram, decrypts it
    /// with caller-supplied keys, requires the packet number to match the next
    /// expected Application packet number, then routes the plaintext through
    /// 1-RTT frame rules. Closing or draining connections discard the datagram
    /// before parsing. Use `processProtectedShortDatagramWithKeyUpdate()`
    /// when the datagram might carry the next key phase. Installed 1-RTT keys
    /// are available through `processProtectedShortDatagramWithInstalledKeys()`;
    /// connection-installed server 0-RTT receive keys are discarded after the
    /// packet authenticates and the Application-frame payload is accepted. Real
    /// TLS transcript ownership, remaining key discard, and endpoint DCID lookup
    /// remain future endpoint/TLS integration work.
    pub fn processProtectedShortDatagram(
        self: *Connection,
        now_nanos: i64,
        keys: protection.Aes128PacketProtectionKeys,
        dcid_len: usize,
        datagram: []const u8,
    ) Error!void {
        try self.processProtectedShortDatagramWithFrameErrorPolicy(now_nanos, keys, dcid_len, datagram, false);
    }

    /// Remove 1-RTT short-header protection and queue CONNECTION_CLOSE on frame errors.
    ///
    /// Packet authentication, packet-number validation, and success behavior
    /// match `processProtectedShortDatagram()`. After authentication succeeds,
    /// malformed/unknown frame payloads queue FRAME_ENCODING_ERROR and
    /// 1-RTT-forbidden frames queue PROTOCOL_VIOLATION before returning
    /// `InvalidPacket`.
    pub fn processProtectedShortDatagramOrClose(
        self: *Connection,
        now_nanos: i64,
        keys: protection.Aes128PacketProtectionKeys,
        dcid_len: usize,
        datagram: []const u8,
    ) Error!void {
        try self.processProtectedShortDatagramWithFrameErrorPolicy(now_nanos, keys, dcid_len, datagram, true);
    }

    fn processProtectedShortDatagramWithFrameErrorPolicy(
        self: *Connection,
        now_nanos: i64,
        keys: protection.Aes128PacketProtectionKeys,
        dcid_len: usize,
        datagram: []const u8,
        close_on_frame_payload_error: bool,
    ) Error!void {
        if (!try self.prepareInboundDatagramProcessing(now_nanos)) return;
        try self.validateReceivedUdpDatagramSize(datagram);

        const packet_space = self.packetNumberSpace(.application);
        if (packet_space.discarded.*) return error.InvalidPacket;

        const expected_packet_number = packet_space.next_peer_packet_number.*;
        var decoded = protection.unprotectShortPacketAes128(
            self.allocator,
            keys,
            datagram,
            dcid_len,
            expected_packet_number,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidPacket,
        };
        defer protection.deinitProtectedShortPacket(&decoded, self.allocator);

        try self.processDecodedProtectedShortDatagram(now_nanos, &decoded, datagram.len, close_on_frame_payload_error);
    }

    /// Remove 1-RTT short-header packet protection with current/next key phases.
    ///
    /// The receiver uses the short-header key phase bit to choose either
    /// `keys.current` or `keys.next`, then applies the same Application-space
    /// packet-number and frame validation as `processProtectedShortDatagram()`.
    /// This is still caller-keyed; use
    /// `processProtectedShortDatagramWithInstalledKeys()` when the connection
    /// owns key-phase state. Successful server-side receive also discards
    /// installed 0-RTT receive keys. Real TLS traffic-secret production remains
    /// future integration work.
    pub fn processProtectedShortDatagramWithKeyUpdate(
        self: *Connection,
        now_nanos: i64,
        keys: protection.ShortPacketKeyUpdateKeys,
        dcid_len: usize,
        datagram: []const u8,
    ) Error!void {
        try self.processProtectedShortDatagramWithKeyUpdateAndFrameErrorPolicy(now_nanos, keys, dcid_len, datagram, false);
    }

    /// Remove 1-RTT protection with current/next keys and queue close on frame errors.
    ///
    /// This preserves `processProtectedShortDatagramWithKeyUpdate()` success
    /// behavior and key selection, but uses the close-propagating receive path
    /// for authenticated plaintext frame payload errors.
    pub fn processProtectedShortDatagramWithKeyUpdateOrClose(
        self: *Connection,
        now_nanos: i64,
        keys: protection.ShortPacketKeyUpdateKeys,
        dcid_len: usize,
        datagram: []const u8,
    ) Error!void {
        try self.processProtectedShortDatagramWithKeyUpdateAndFrameErrorPolicy(now_nanos, keys, dcid_len, datagram, true);
    }

    fn processProtectedShortDatagramWithKeyUpdateAndFrameErrorPolicy(
        self: *Connection,
        now_nanos: i64,
        keys: protection.ShortPacketKeyUpdateKeys,
        dcid_len: usize,
        datagram: []const u8,
        close_on_frame_payload_error: bool,
    ) Error!void {
        if (!try self.prepareInboundDatagramProcessing(now_nanos)) return;
        try self.validateReceivedUdpDatagramSize(datagram);

        const packet_space = self.packetNumberSpace(.application);
        if (packet_space.discarded.*) return error.InvalidPacket;

        const expected_packet_number = packet_space.next_peer_packet_number.*;
        var decoded = protection.unprotectShortPacketAes128WithKeyUpdate(
            self.allocator,
            keys,
            datagram,
            dcid_len,
            expected_packet_number,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidPacket,
        };
        defer protection.deinitProtectedShortPacket(&decoded, self.allocator);

        try self.processDecodedProtectedShortDatagram(now_nanos, &decoded, datagram.len, close_on_frame_payload_error);
    }

    /// Remove 1-RTT short-header packet protection with caller-owned key state.
    ///
    /// The key-phase state supplies current and next receive keys. It advances
    /// only after the packet authenticates and the decrypted frame payload is
    /// accepted, so failed datagrams do not mutate peer key-phase state. Real
    /// TLS traffic-secret production, key-update confirmation, and old-key
    /// discard remain future endpoint/TLS integration work. Successful
    /// server-side receive also discards installed 0-RTT receive keys.
    pub fn processProtectedShortDatagramWithKeyPhaseState(
        self: *Connection,
        now_nanos: i64,
        key_phase_state: *protection.Aes128KeyPhaseState,
        dcid_len: usize,
        datagram: []const u8,
    ) Error!void {
        try self.processProtectedShortDatagramWithKeyPhaseStateAndFrameErrorPolicy(now_nanos, key_phase_state, dcid_len, datagram, false);
    }

    /// Remove 1-RTT protection with caller-owned key state and queue close on frame errors.
    ///
    /// The key-phase state still advances only after packet authentication and
    /// plaintext frame processing succeed. Authenticated frame payload errors
    /// queue a transport CONNECTION_CLOSE and leave the key-phase state
    /// unchanged.
    pub fn processProtectedShortDatagramWithKeyPhaseStateOrClose(
        self: *Connection,
        now_nanos: i64,
        key_phase_state: *protection.Aes128KeyPhaseState,
        dcid_len: usize,
        datagram: []const u8,
    ) Error!void {
        try self.processProtectedShortDatagramWithKeyPhaseStateAndFrameErrorPolicy(now_nanos, key_phase_state, dcid_len, datagram, true);
    }

    fn processProtectedShortDatagramWithKeyPhaseStateAndFrameErrorPolicy(
        self: *Connection,
        now_nanos: i64,
        key_phase_state: *protection.Aes128KeyPhaseState,
        dcid_len: usize,
        datagram: []const u8,
        close_on_frame_payload_error: bool,
    ) Error!void {
        if (!try self.prepareInboundDatagramProcessing(now_nanos)) return;
        try self.validateReceivedUdpDatagramSize(datagram);

        const packet_space = self.packetNumberSpace(.application);
        if (packet_space.discarded.*) return error.InvalidPacket;

        const expected_packet_number = packet_space.next_peer_packet_number.*;
        var decoded = protection.unprotectShortPacketAes128WithKeyUpdate(
            self.allocator,
            key_phase_state.keyUpdateKeys(),
            datagram,
            dcid_len,
            expected_packet_number,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.KeyUpdateError => {
                // The packet's revealed key phase matches a previous
                // generation whose keys were already discarded past the PTO
                // retain window: the peer is protecting packets with keys
                // older than the retained generation (RFC 9001 §6.5). Surface
                // this as a KEY_UPDATE_ERROR transport close.
                self.closeConnection(
                    transport_error.codeValue(.key_update_error),
                    0,
                    "packet protected with discarded key",
                ) catch {};
                return error.InvalidPacket;
            },
            else => return error.InvalidPacket,
        };
        defer protection.deinitProtectedShortPacket(&decoded, self.allocator);

        try self.processDecodedProtectedShortDatagram(now_nanos, &decoded, datagram.len, close_on_frame_payload_error);
        // Only a packet that authenticated against the `next` key generation
        // signals a peer-initiated key update; a delayed packet opened with the
        // retained `previous` key must not advance key-phase state, even though
        // its revealed phase bit also differs from `current` (RFC 9001 §6.5).
        if (decoded.peer_initiated_key_update) {
            if (key_phase_state.updateAfterReceiving(decoded.packet.header.key_phase)) {
                // Retain the old peer receive key for one PTO so delayed packets
                // protected with the previous key phase can still be opened
                // (RFC 9001 §6.5 / RFC 9002 §6.2).
                self.schedulePreviousKeyDiscard(key_phase_state, now_nanos);
                // RFC 9001 §6.2: the responding endpoint MUST update its send
                // keys to the corresponding key phase before acknowledging the
                // packet that carried the new phase. Skip when the local send
                // phase already matches the packet phase: this packet is then
                // the peer's response to a locally initiated update (or a
                // simultaneous initiation), not a fresh peer-initiated update.
                if (self.local_one_rtt_key_phase_state) |*local_state| {
                    if (local_state.currentKeyPhase() != decoded.packet.header.key_phase) {
                        local_state.initiateKeyUpdate();
                        self.schedulePreviousKeyDiscard(local_state, now_nanos);
                    }
                }
            }
        }
    }

    /// Remove 1-RTT short-header protection using installed peer traffic keys.
    ///
    /// The peer key-phase state is owned by the connection and advances only
    /// after authentication and Application-frame processing succeed. Use
    /// `installOneRttTrafficSecrets()` or a `CryptoBackend` traffic-secret
    /// handoff before calling this helper. Server-side successful receive
    /// discards installed 0-RTT receive keys.
    pub fn processProtectedShortDatagramWithInstalledKeys(
        self: *Connection,
        now_nanos: i64,
        dcid_len: usize,
        datagram: []const u8,
    ) Error!void {
        var state = self.peer_one_rtt_key_phase_state orelse return error.InvalidPacket;
        try self.processProtectedShortDatagramWithKeyPhaseState(now_nanos, &state, dcid_len, datagram);
        self.peer_one_rtt_key_phase_state = state;
    }

    /// Remove installed-key 1-RTT protection and queue CONNECTION_CLOSE on frame errors.
    ///
    /// This preserves connection-owned key-phase state semantics, advancing the
    /// installed state only after authenticated plaintext frame processing
    /// succeeds. Classified frame payload errors queue a transport
    /// CONNECTION_CLOSE and leave the installed key state unchanged.
    pub fn processProtectedShortDatagramWithInstalledKeysOrClose(
        self: *Connection,
        now_nanos: i64,
        dcid_len: usize,
        datagram: []const u8,
    ) Error!void {
        var state = self.peer_one_rtt_key_phase_state orelse return error.InvalidPacket;
        try self.processProtectedShortDatagramWithKeyPhaseStateOrClose(now_nanos, &state, dcid_len, datagram);
        self.peer_one_rtt_key_phase_state = state;
    }

    fn processDecodedProtectedShortDatagram(
        self: *Connection,
        now_nanos: i64,
        decoded: *const protection.DecodedProtectedShortPacket,
        datagram_len: usize,
        close_on_frame_payload_error: bool,
    ) Error!void {
        if (decoded.len != datagram_len) return error.InvalidPacket;
        const packet_space = self.packetNumberSpace(.application);
        // Duplicate or below-window 1-RTT packets are discarded per
        // RFC 9000 §13.1, not connection errors.
        if (!packet_space.received_packet_ranges.canRecord(decoded.packet.header.packet_number)) return;
        try self.processDatagramInSpaceWithPacketTypeMaybeClose(
            .application,
            .one_rtt,
            now_nanos,
            decoded.packet.plaintext,
            close_on_frame_payload_error,
            decoded.packet.header.packet_number,
        );
        const packet_space_after = self.packetNumberSpace(.application);
        _ = try self.recordReceivedPacketNumber(packet_space_after, decoded.packet.header.packet_number);
        if (self.side == .server) {
            self.discardZeroRttProtectionKeyState();
        }
        self.updateSpinBitAfterReceivedShortPacket(decoded.packet.header.spin_bit);
    }

    /// Return one protected 1-RTT short-header datagram for Application frames.
    ///
    /// The returned datagram is allocated with the connection allocator and must
    /// be freed by the caller. This currently protects Application-space PING,
    /// CRYPTO, HANDSHAKE_DONE, NEW_TOKEN, NEW_CONNECTION_ID, PATH_CHALLENGE,
    /// PATH_RESPONSE, RETIRE_CONNECTION_ID, MAX_DATA, MAX_STREAM_DATA,
    /// MAX_STREAMS_BIDI/UNI, DATA_BLOCKED, STREAM_DATA_BLOCKED,
    /// STREAMS_BLOCKED_BIDI/UNI, RESET_STREAM, STOP_SENDING,
    /// CONNECTION_CLOSE/APPLICATION_CLOSE, or one queued STREAM with an optional
    /// ACK, or ACK-only state, while preserving packet number, ACK, recovery,
    /// congestion, close-state, and anti-amplification accounting. TLS secret
    /// production, automatic key-phase transitions, and remaining key discard
    /// remain endpoint/TLS integration work.
    pub fn pollProtectedShortDatagram(
        self: *Connection,
        now_nanos: i64,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
    ) Error!?[]u8 {
        return self.pollProtectedShortDatagramWithKeyPhase(now_nanos, dcid, keys, false);
    }

    /// Return one protected 1-RTT short-header datagram with an explicit key phase.
    ///
    /// Callers pass keys matching `key_phase`. This keeps the current
    /// caller-keyed bridge usable for deterministic key-update tests while a
    /// future endpoint/TLS state machine owns key-phase transitions.
    pub fn pollProtectedShortDatagramWithKeyPhase(
        self: *Connection,
        now_nanos: i64,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
    ) Error!?[]u8 {
        self.pacing_send_deadline = null;
        errdefer self.pacing_send_deadline = null;
        self.expireIdleState(now_nanos);
        self.expireCloseState(now_nanos);
        if (self.pending_close != null) {
            return try self.pollProtectedShortCloseDatagram(now_nanos, dcid, keys, key_phase);
        }
        if (self.isClosingOrClosed()) return error.ConnectionClosed;

        // Select control-only output before the general builder can coalesce
        // STREAM data or remove obsolete queued frames.
        var pacing_limited = false;
        if (self.recovery_state.min_rtt_ns != null and
            (self.send_queue.items.len != 0 or self.crypto_send_queue.items.len != 0))
        {
            const cwnd = self.recovery_state.congestion_window;
            const srtt: u64 = self.recovery_state.smoothed_rtt_ns;
            if (!self.tx_pacer.canSend(now_nanos, self.maxTxDatagramSize(), cwnd, srtt)) {
                pacing_limited = true;
                self.pacing_send_deadline = self.tx_pacer.nextSendTime(now_nanos, self.maxTxDatagramSize(), cwnd, srtt);
            }
        }

        var built = if (pacing_limited) limited: {
            if (self.application_packet_space_discarded) return error.InvalidPacket;
            const ack = self.pendingAckFrame(.application);
            if (self.pending_path_responses.items.len != 0) {
                break :limited try self.buildProtectedShortPathResponsePacket(dcid, keys, key_phase, ack);
            }
            if (ack) |pending| {
                break :limited try self.buildProtectedShortControlPacket(dcid, keys, key_phase, try ackFrameWireLen(pending), pending, false);
            }
            return null;
        } else (try self.buildNextProtectedShortPacket(dcid, keys, key_phase)) orelse return null;
        errdefer {
            built.deinitSidecars(self.allocator);
            self.allocator.free(built.datagram);
        }

        if (built.datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        if (if (built.ack_eliciting)
            self.ackElicitingSendAdmission(.application, built.datagram.len) != .allowed
        else
            !self.canSendToPeerAddress(built.datagram.len))
        {
            self.pacing_send_deadline = null;
            built.deinitSidecars(self.allocator);
            self.allocator.free(built.datagram);
            return null;
        }
        if (built.ack_eliciting) {
            self.sent_packets.ensureUnusedCapacity(self.allocator, 1) catch return error.OutOfMemory;
        }
        if (built.consume_path_challenge) {
            self.outstanding_path_challenges.ensureUnusedCapacity(self.allocator, 1) catch return error.OutOfMemory;
        }

        self.commitBuiltProtectedShortPacket(built, now_nanos);
        if (built.ack_eliciting) {
            const cwnd = self.recovery_state.congestion_window;
            const srtt: u64 = self.recovery_state.smoothed_rtt_ns;
            self.tx_pacer.onPacketSent(now_nanos, built.datagram.len, cwnd, srtt);
        }
        if (pacing_limited) {
            self.pacing_send_deadline = self.tx_pacer.nextSendTime(now_nanos, self.maxTxDatagramSize(), self.recovery_state.congestion_window, self.recovery_state.smoothed_rtt_ns);
        }
        return built.datagram;
    }

    /// Return a pacing wakeup recorded by protected polling. Merge this value
    /// with lifecycle deadlines, then poll output again when it becomes due.
    /// This query does not consume packets, frames, or pacing budget.
    pub fn pacingDeadline(self: *const Connection) ?i64 {
        if (self.isClosingOrClosed() or self.pending_close != null or self.application_packet_space_discarded or
            (self.send_queue.items.len == 0 and self.crypto_send_queue.items.len == 0)) return null;
        if (self.pto_probe_count == 0 and self.congestion_probe_count == 0 and
            self.availableCongestionWindow(.application) == 0) return null;
        if (self.antiAmplificationLimitRemaining()) |remaining| if (remaining == 0) return null;
        return self.pacing_send_deadline;
    }

    /// Return one protected 1-RTT short-header datagram using key-phase state.
    ///
    /// This uses the state's current send keys and current key-phase bit. The
    /// caller explicitly initiates updates on the state before polling.
    pub fn pollProtectedShortDatagramWithKeyPhaseState(
        self: *Connection,
        now_nanos: i64,
        dcid: []const u8,
        key_phase_state: *const protection.Aes128KeyPhaseState,
    ) Error!?[]u8 {
        return self.pollProtectedShortDatagramWithKeyPhase(
            now_nanos,
            dcid,
            key_phase_state.currentKeys(),
            key_phase_state.currentKeyPhase(),
        );
    }

    /// Return one protected 1-RTT short-header datagram using installed keys.
    ///
    /// The local key-phase state is owned by the connection. Call
    /// `installOneRttTrafficSecrets()` or drive a `CryptoBackend` that returns
    /// 1-RTT traffic secrets before using this helper.
    pub fn pollProtectedShortDatagramWithInstalledKeys(
        self: *Connection,
        now_nanos: i64,
        dcid: []const u8,
    ) Error!?[]u8 {
        const state = self.local_one_rtt_key_phase_state orelse {
            self.pacing_send_deadline = null;
            return error.InvalidPacket;
        };
        return self.pollProtectedShortDatagramWithKeyPhaseState(now_nanos, dcid, &state);
    }

    fn protectedPathValidationPlaintextLen(
        self: Connection,
        dcid_len: usize,
        packet_number_len: u8,
        plaintext_len: usize,
    ) Error!usize {
        if (self.maxTxDatagramSize() < min_initial_udp_datagram_len) return plaintext_len;
        if (!self.canSendToPeerAddress(min_initial_udp_datagram_len)) return plaintext_len;

        return protectedShortPlaintextLenForMinDatagram(
            dcid_len,
            packet_number_len,
            plaintext_len,
            min_initial_udp_datagram_len,
        );
    }

    fn pollProtectedShortCloseDatagram(
        self: *Connection,
        now_nanos: i64,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
    ) Error!?[]u8 {
        var built = try self.buildProtectedShortClosePacket(dcid, keys, key_phase);
        errdefer {
            built.deinitSidecars(self.allocator);
            self.allocator.free(built.datagram);
        }

        if (built.datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        if (!self.canSendToPeerAddress(built.datagram.len)) {
            built.deinitSidecars(self.allocator);
            self.allocator.free(built.datagram);
            return null;
        }

        self.commitBuiltProtectedShortPacket(built, now_nanos);
        return built.datagram;
    }

    /// Return one protected 0-RTT long-header datagram for early Application frames.
    ///
    /// The returned datagram is allocated with the connection allocator and must
    /// be freed by the caller. This client-side API emits one 0-RTT protected
    /// RESET_STREAM, STOP_SENDING, or STREAM frame from the Application packet
    /// number space without coalescing ACK or CRYPTO frames, because those are
    /// not valid in 0-RTT packets. Callers supply the 0-RTT keys; TLS secret
    /// production, replay defense, and server acceptance policy remain
    /// endpoint/TLS integration work.
    pub fn pollProtectedZeroRttDatagram(
        self: *Connection,
        now_nanos: i64,
        dcid: []const u8,
        scid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
    ) Error!?[]u8 {
        self.expireIdleState(now_nanos);
        self.expireCloseState(now_nanos);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;

        const built = (try self.buildNextProtectedZeroRttPacket(dcid, scid, keys)) orelse return null;
        errdefer self.deinitBuiltProtectedLongPacket(built);

        if (built.datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        if (!self.canSendToPeerAddress(built.datagram.len)) {
            self.deinitBuiltProtectedLongPacket(built);
            return null;
        }
        if (built.ack_eliciting and !self.canSendAckElicitingInSpace(.application, built.datagram.len)) {
            self.deinitBuiltProtectedLongPacket(built);
            return null;
        }

        try self.ensureProtectedLongCommitCapacity(built);
        self.commitBuiltProtectedLongPacket(built, now_nanos);
        return built.datagram;
    }

    /// Return one protected 0-RTT long-header datagram using installed keys.
    ///
    /// This client-side helper emits early STREAM, RESET_STREAM, or STOP_SENDING
    /// data with the connection's installed local 0-RTT keys. TLS 0-RTT
    /// acceptance and replay policy remain endpoint/TLS work.
    pub fn pollProtectedZeroRttDatagramWithInstalledKeys(
        self: *Connection,
        now_nanos: i64,
        dcid: []const u8,
        scid: []const u8,
    ) Error!?[]u8 {
        const keys = self.local_zero_rtt_keys orelse return error.InvalidPacket;
        return self.pollProtectedZeroRttDatagram(now_nanos, dcid, scid, keys);
    }

    /// Return one protected long datagram with queued Initial/0-RTT/Handshake frames.
    ///
    /// The returned datagram is allocated with the connection allocator and must
    /// be freed by the caller. For each Initial/Handshake space, the method can
    /// emit one protected CRYPTO packet, PING packet with an optional ACK,
    /// ACK-only packet, or pending transport `CONNECTION_CLOSE`. When
    /// `keys.zero_rtt` is supplied by a client, it can also emit one 0-RTT
    /// Application STREAM, RESET_STREAM, or STOP_SENDING packet. The method
    /// coalesces eligible long packets into one UDP datagram when the result
    /// fits `max_udp_payload_size`. It prebuilds packets and checks congestion
    /// plus anti-amplification budget before committing packet-number,
    /// sent-packet, recovery, ACK/PING, CRYPTO, close, and 0-RTT queue state.
    /// Endpoint DCID switching, real TLS transcript ownership, key discard, and
    /// key update remain endpoint/TLS integration work.
    pub fn pollProtectedLongDatagram(
        self: *Connection,
        now_nanos: i64,
        dcid: []const u8,
        scid: []const u8,
        initial_token: []const u8,
        keys: ProtectedLongDatagramKeys,
    ) Error!?[]u8 {
        self.expireIdleState(now_nanos);
        self.expireCloseState(now_nanos);

        var initial_packet: ?BuiltProtectedLongPacket = null;
        var zero_rtt_packet: ?BuiltProtectedLongPacket = null;
        var handshake_packet: ?BuiltProtectedLongPacket = null;
        errdefer {
            self.deinitBuiltProtectedLongPacketIfPresent(&initial_packet);
            self.deinitBuiltProtectedLongPacketIfPresent(&zero_rtt_packet);
            self.deinitBuiltProtectedLongPacketIfPresent(&handshake_packet);
        }

        if (self.pending_close != null) {
            if (keys.handshake) |handshake_keys| {
                handshake_packet = try self.buildProtectedLongClosePacketInSpace(
                    .handshake,
                    dcid,
                    scid,
                    &[_]u8{},
                    handshake_keys,
                    0,
                );
            } else if (keys.initial) |initial_keys| {
                initial_packet = try self.buildProtectedLongClosePacketInSpace(
                    .initial,
                    dcid,
                    scid,
                    initial_token,
                    initial_keys,
                    0,
                );
            } else {
                return error.InvalidPacket;
            }
        } else {
            if (self.isClosingOrClosed()) return error.ConnectionClosed;
            if (self.initial_packet_space.crypto_send_queue.items.len != 0 or
                self.initial_packet_space.pending_ping_count != 0 or
                self.initial_packet_space.pending_ack_largest != null)
            {
                // Spaces without caller-provided keys are skipped, not
                // errors: the pending data stays queued for a later drain
                // that holds those keys (RFC 9002 per-space probing).
                if (keys.initial) |initial_keys| {
                    initial_packet = try self.buildNextProtectedLongPacketInSpace(
                        .initial,
                        dcid,
                        scid,
                        initial_token,
                        initial_keys,
                        0,
                    );
                }
            }
            if (keys.zero_rtt) |zero_rtt_keys| {
                if (self.hasPendingProtectedZeroRttFrames()) {
                    zero_rtt_packet = try self.buildNextProtectedZeroRttPacket(
                        dcid,
                        scid,
                        zero_rtt_keys,
                    );
                }
            }
            if (self.handshake_packet_space.crypto_send_queue.items.len != 0 or
                self.handshake_packet_space.pending_ping_count != 0 or
                self.handshake_packet_space.pending_ack_largest != null)
            {
                // Skip when the caller did not provide Handshake keys: a
                // peer-space PTO probe queued by an Initial-space PTO must
                // not fail an Initial-only drain; the re-queued data stays
                // pending until a drain with Handshake keys runs.
                if (keys.handshake) |handshake_keys| {
                    handshake_packet = try self.buildNextProtectedLongPacketInSpace(
                        .handshake,
                        dcid,
                        scid,
                        &[_]u8{},
                        handshake_keys,
                        0,
                    );
                }
            }
        }

        if (initial_packet == null and zero_rtt_packet == null and handshake_packet == null) return null;

        var total_len: usize = 0;
        if (initial_packet) |built| {
            total_len = built.datagram.len;
        }
        if (zero_rtt_packet) |built| {
            const next_total = std.math.add(usize, total_len, built.datagram.len) catch return error.BufferTooSmall;
            if (total_len != 0 and next_total > self.maxTxDatagramSize()) {
                self.deinitBuiltProtectedLongPacketIfPresent(&zero_rtt_packet);
            } else {
                total_len = next_total;
            }
        }
        if (handshake_packet) |built| {
            const next_total = std.math.add(usize, total_len, built.datagram.len) catch return error.BufferTooSmall;
            if (total_len != 0 and next_total > self.maxTxDatagramSize()) {
                self.deinitBuiltProtectedLongPacketIfPresent(&handshake_packet);
            } else {
                total_len = next_total;
            }
        }
        if (initial_packet) |built| {
            const required_initial_datagram_len = self.minimumOutgoingInitialDatagramLen(.initial, built.ack_eliciting);
            if (required_initial_datagram_len != 0 and total_len < required_initial_datagram_len) {
                const initial_was_close = built.close_packet;
                const target_initial_len = try addWireLen(built.datagram.len, required_initial_datagram_len - total_len);
                self.deinitBuiltProtectedLongPacketIfPresent(&initial_packet);
                initial_packet = if (initial_was_close)
                    try self.buildProtectedLongClosePacketInSpace(
                        .initial,
                        dcid,
                        scid,
                        initial_token,
                        keys.initial orelse return error.InvalidPacket,
                        target_initial_len,
                    )
                else
                    try self.buildNextProtectedLongPacketInSpace(
                        .initial,
                        dcid,
                        scid,
                        initial_token,
                        keys.initial orelse return error.InvalidPacket,
                        target_initial_len,
                    );

                total_len = 0;
                if (initial_packet) |expanded_initial| total_len = expanded_initial.datagram.len;
                if (zero_rtt_packet) |zero_rtt| total_len = std.math.add(usize, total_len, zero_rtt.datagram.len) catch return error.BufferTooSmall;
                if (handshake_packet) |handshake| total_len = std.math.add(usize, total_len, handshake.datagram.len) catch return error.BufferTooSmall;

                if (total_len > self.maxTxDatagramSize()) {
                    self.deinitBuiltProtectedLongPacketIfPresent(&zero_rtt_packet);
                    self.deinitBuiltProtectedLongPacketIfPresent(&handshake_packet);
                    self.deinitBuiltProtectedLongPacketIfPresent(&initial_packet);
                    initial_packet = if (initial_was_close)
                        try self.buildProtectedLongClosePacketInSpace(
                            .initial,
                            dcid,
                            scid,
                            initial_token,
                            keys.initial orelse return error.InvalidPacket,
                            required_initial_datagram_len,
                        )
                    else
                        try self.buildNextProtectedLongPacketInSpace(
                            .initial,
                            dcid,
                            scid,
                            initial_token,
                            keys.initial orelse return error.InvalidPacket,
                            required_initial_datagram_len,
                        );
                    total_len = if (initial_packet) |single_initial| single_initial.datagram.len else 0;
                }
            }
        }
        if (total_len == 0) return null;
        if (total_len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        if (!self.canSendToPeerAddress(total_len)) {
            self.deinitBuiltProtectedLongPacketIfPresent(&initial_packet);
            self.deinitBuiltProtectedLongPacketIfPresent(&zero_rtt_packet);
            self.deinitBuiltProtectedLongPacketIfPresent(&handshake_packet);
            return null;
        }
        if (initial_packet) |built| {
            if (built.ack_eliciting and !self.canSendAckElicitingInSpace(built.space, built.datagram.len)) {
                self.deinitBuiltProtectedLongPacketIfPresent(&initial_packet);
                self.deinitBuiltProtectedLongPacketIfPresent(&zero_rtt_packet);
                self.deinitBuiltProtectedLongPacketIfPresent(&handshake_packet);
                return null;
            }
        }
        if (zero_rtt_packet) |built| {
            if (built.ack_eliciting and !self.canSendAckElicitingInSpace(built.space, built.datagram.len)) {
                self.deinitBuiltProtectedLongPacketIfPresent(&initial_packet);
                self.deinitBuiltProtectedLongPacketIfPresent(&zero_rtt_packet);
                self.deinitBuiltProtectedLongPacketIfPresent(&handshake_packet);
                return null;
            }
        }
        if (handshake_packet) |built| {
            if (built.ack_eliciting and !self.canSendAckElicitingInSpace(built.space, built.datagram.len)) {
                self.deinitBuiltProtectedLongPacketIfPresent(&initial_packet);
                self.deinitBuiltProtectedLongPacketIfPresent(&zero_rtt_packet);
                self.deinitBuiltProtectedLongPacketIfPresent(&handshake_packet);
                return null;
            }
        }

        if (initial_packet) |built| try self.ensureProtectedLongCommitCapacity(built);
        if (zero_rtt_packet) |built| try self.ensureProtectedLongCommitCapacity(built);
        if (handshake_packet) |built| try self.ensureProtectedLongCommitCapacity(built);

        const datagram = self.allocator.alloc(u8, total_len) catch return error.OutOfMemory;
        errdefer self.allocator.free(datagram);

        var offset: usize = 0;
        if (initial_packet) |built| {
            @memcpy(datagram[offset..][0..built.datagram.len], built.datagram);
            offset += built.datagram.len;
            self.commitBuiltProtectedLongPacket(built, now_nanos);
            self.allocator.free(built.datagram);
            initial_packet = null;
        }
        if (zero_rtt_packet) |built| {
            @memcpy(datagram[offset..][0..built.datagram.len], built.datagram);
            offset += built.datagram.len;
            self.commitBuiltProtectedLongPacket(built, now_nanos);
            self.allocator.free(built.datagram);
            zero_rtt_packet = null;
        }
        if (handshake_packet) |built| {
            @memcpy(datagram[offset..][0..built.datagram.len], built.datagram);
            offset += built.datagram.len;
            self.commitBuiltProtectedLongPacket(built, now_nanos);
            self.allocator.free(built.datagram);
            handshake_packet = null;
        }
        std.debug.assert(offset == datagram.len);
        return datagram;
    }

    /// Return one protected Handshake long-header datagram using installed keys.
    ///
    /// This emits at most one pending transport `CONNECTION_CLOSE`, Handshake
    /// CRYPTO, PING+ACK, or ACK-only packet from the Handshake packet number
    /// space without requiring the caller to pass packet-protection keys on
    /// every call. Use the caller-keyed `pollProtectedLongDatagram()` when
    /// coalescing Initial and Handshake packets is required.
    pub fn pollProtectedHandshakeDatagramWithInstalledKeys(
        self: *Connection,
        now_nanos: i64,
        dcid: []const u8,
        scid: []const u8,
    ) Error!?[]u8 {
        self.expireIdleState(now_nanos);
        self.expireCloseState(now_nanos);

        const keys = self.local_handshake_keys orelse return error.InvalidPacket;
        if (self.pending_close != null) {
            return try self.pollProtectedLongCloseDatagramInSpace(.handshake, now_nanos, dcid, scid, &[_]u8{}, keys);
        }
        if (self.isClosingOrClosed()) return error.ConnectionClosed;

        const built = (try self.buildNextProtectedLongPacketInSpace(
            .handshake,
            dcid,
            scid,
            &[_]u8{},
            keys,
            0,
        )) orelse return null;
        errdefer self.allocator.free(built.datagram);

        if (built.datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        if (!self.canSendToPeerAddress(built.datagram.len)) {
            self.allocator.free(built.datagram);
            return null;
        }
        if (built.ack_eliciting and !self.canSendAckElicitingInSpace(.handshake, built.datagram.len)) {
            self.allocator.free(built.datagram);
            return null;
        }

        try self.ensureProtectedLongCommitCapacity(built);
        self.commitBuiltProtectedLongPacket(built, now_nanos);
        return built.datagram;
    }

    fn pollProtectedLongCloseDatagramInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        now_nanos: i64,
        dcid: []const u8,
        scid: []const u8,
        token: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
    ) Error!?[]u8 {
        const built = try self.buildProtectedLongClosePacketInSpace(space, dcid, scid, token, keys, 0);
        errdefer self.deinitBuiltProtectedLongPacket(built);

        if (built.datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        if (!self.canSendToPeerAddress(built.datagram.len)) {
            self.deinitBuiltProtectedLongPacket(built);
            return null;
        }

        self.commitBuiltProtectedLongPacket(built, now_nanos);
        return built.datagram;
    }

    /// Return the next protected Initial or Handshake CRYPTO datagram, or null if idle.
    ///
    /// The returned datagram is allocated with the connection allocator and must
    /// be freed by the caller. This compatibility-level API bridges only the
    /// selected Initial or Handshake CRYPTO send queue to the RFC 9001
    /// long-packet protection helper. Use `pollProtectedLongDatagram()` when ACK
    /// or PING protected packets should also be emitted. For Initial packets,
    /// a client-side Retry token accepted through `processRetryDatagram()` is
    /// used when `token` is empty. Real TLS transcript ownership, key discard,
    /// and key update remain endpoint/TLS integration work.
    pub fn pollProtectedLongCryptoDatagramInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        now_nanos: i64,
        dcid: []const u8,
        scid: []const u8,
        token: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
    ) Error!?[]u8 {
        self.expireIdleState(now_nanos);
        self.expireCloseState(now_nanos);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;

        const min_datagram_len = self.minimumOutgoingInitialDatagramLen(space, true);
        const built = (try self.buildProtectedLongCryptoPacketInSpace(space, dcid, scid, token, keys, min_datagram_len)) orelse return null;
        errdefer self.allocator.free(built.datagram);

        if (!self.canSendAckElicitingInSpace(space, built.datagram.len) or !self.canSendToPeerAddress(built.datagram.len)) {
            self.allocator.free(built.datagram);
            return null;
        }

        try self.ensureProtectedLongCommitCapacity(built);
        self.commitBuiltProtectedLongPacket(built, now_nanos);
        return built.datagram;
    }

    /// Return the next protected Initial CRYPTO datagram, or null if idle.
    ///
    /// This compatibility wrapper routes Initial CRYPTO through
    /// `pollProtectedLongCryptoDatagramInSpace(.initial, ...)`.
    pub fn pollInitialProtectedDatagram(
        self: *Connection,
        now_nanos: i64,
        dcid: []const u8,
        scid: []const u8,
        token: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
    ) Error!?[]u8 {
        return self.pollProtectedLongCryptoDatagramInSpace(.initial, now_nanos, dcid, scid, token, keys);
    }

    fn buildProtectedLongClosePacketInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        dcid: []const u8,
        scid: []const u8,
        token: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        min_datagram_len: usize,
    ) Error!BuiltProtectedLongPacket {
        const long_space = protectedLongPacketSpaceFor(space) orelse return error.InvalidPacket;
        if (space != .initial and token.len != 0) return error.InvalidPacket;
        const header_token = self.initialTokenForPacket(space, token);
        try self.validateOutgoingInitialPacketFields(space, dcid, header_token);

        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;
        if (packet_space.next_packet_number.* > max_quic_varint) return error.Internal;

        const close = self.pending_close orelse return error.Internal;
        const connection_close = switch (close) {
            .connection => |connection| connection,
            .application => return error.InvalidPacket,
        };
        const close_frame = frame.Frame{ .connection_close = connection_close };
        if (!frameAllowedInFramePacketType(close_frame, long_space.frame_packet_type)) return error.InvalidPacket;
        const encoded_frame_len = try connectionCloseFrameWireLen(connection_close);

        const packet_number = packet_space.next_packet_number.*;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            packet_space.largest_acknowledged.*,
        ) catch return error.Internal;

        const header = packet.LongHeader{
            .version = self.config.chosen_version,
            .dcid = dcid,
            .scid = scid,
            .packet_type = long_space.packet_type,
            .token = header_token,
            .packet_number = packet_number,
            .payload_length = 0,
        };
        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const plaintext_len = try protectedLongPlaintextLenForMinDatagram(
            header,
            packet_number_encoding.len,
            @max(encoded_frame_len, min_payload_len),
            min_datagram_len,
        );
        if (plaintext_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        frame.encodeFrame(plaintext_out.writer(), close_frame) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const datagram = protection.protectLongPacketAes128(self.allocator, header, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        var built = BuiltProtectedLongPacket{
            .space = space,
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = false,
            .close_packet = true,
        };
        built.recordLocalOriginalDestinationConnectionId(self.localOriginalDestinationConnectionIdForPacket(space, dcid));
        built.recordLocalInitialSourceConnectionId(self.localInitialSourceConnectionIdForPacket(space, scid));
        return built;
    }

    fn buildProtectedLongCryptoPacketInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        dcid: []const u8,
        scid: []const u8,
        token: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        min_datagram_len: usize,
    ) Error!?BuiltProtectedLongPacket {
        const long_space = protectedLongPacketSpaceFor(space) orelse return error.InvalidPacket;
        if (space != .initial and token.len != 0) return error.InvalidPacket;
        const header_token = self.initialTokenForPacket(space, token);
        try self.validateOutgoingInitialPacketFields(space, dcid, header_token);

        const packet_space = self.packetNumberSpace(space);
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

        const header = packet.LongHeader{
            .version = self.config.chosen_version,
            .dcid = dcid,
            .scid = scid,
            .packet_type = long_space.packet_type,
            .token = header_token,
            .packet_number = packet_number,
            .payload_length = 0,
        };
        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const plaintext_len = try protectedLongPlaintextLenForMinDatagram(
            header,
            packet_number_encoding.len,
            @max(crypto_encoded_len, min_payload_len),
            min_datagram_len,
        );
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

        const datagram = protection.protectLongPacketAes128(self.allocator, header, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        var built = BuiltProtectedLongPacket{
            .space = space,
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = true,
            .consume_crypto = true,
        };
        built.recordLocalOriginalDestinationConnectionId(self.localOriginalDestinationConnectionIdForPacket(space, dcid));
        built.recordLocalInitialSourceConnectionId(self.localInitialSourceConnectionIdForPacket(space, scid));
        return built;
    }

    fn buildNextProtectedLongPacketInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        dcid: []const u8,
        scid: []const u8,
        token: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        min_datagram_len: usize,
    ) Error!?BuiltProtectedLongPacket {
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;
        if (packet_space.crypto_send_queue.items.len != 0) {
            return self.buildProtectedLongCryptoPacketInSpace(space, dcid, scid, token, keys, min_datagram_len);
        }
        const ack_to_send = self.pendingAckFrame(space);
        if (packet_space.pending_ping_count.* != 0) {
            return try self.buildProtectedLongPingPacketInSpace(space, dcid, scid, token, keys, ack_to_send, min_datagram_len);
        }
        if (ack_to_send) |ack| {
            return try self.buildProtectedLongAckOnlyPacketInSpace(space, dcid, scid, token, keys, ack, min_datagram_len);
        }
        return null;
    }

    fn hasPendingProtectedZeroRttFrames(self: *Connection) bool {
        self.dropObsoleteStopSendingFrames();
        return self.pending_reset_streams.items.len != 0 or
            self.pending_stop_sending.items.len != 0 or
            self.send_queue.items.len != 0;
    }

    fn buildNextProtectedZeroRttPacket(
        self: *Connection,
        dcid: []const u8,
        scid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
    ) Error!?BuiltProtectedLongPacket {
        if (self.side != .client) return error.InvalidPacket;
        if (self.application_packet_space_discarded) return error.InvalidPacket;

        self.dropResetClosedStreamFrames();
        if (self.pending_reset_streams.items.len != 0) {
            const reset = self.pending_reset_streams.items[0];
            return try self.buildProtectedZeroRttFramePacket(
                dcid,
                scid,
                keys,
                .{ .reset_stream = reset },
                try resetStreamFrameWireLen(reset),
                .{ .reset_stream = true },
            );
        }
        self.dropObsoleteStopSendingFrames();
        if (self.pending_stop_sending.items.len != 0) {
            const stop_sending = self.pending_stop_sending.items[0];
            return try self.buildProtectedZeroRttFramePacket(
                dcid,
                scid,
                keys,
                .{ .stop_sending = stop_sending },
                try stopSendingFrameWireLen(stop_sending),
                .{ .stop_sending = true },
            );
        }
        if (self.send_queue.items.len != 0) {
            const pending = self.send_queue.items[0];
            return try self.buildProtectedZeroRttFramePacket(
                dcid,
                scid,
                keys,
                .{ .stream = .{
                    .stream_id = pending.stream_id,
                    .offset = pending.offset,
                    .fin = pending.fin,
                    .data = pending.data,
                } },
                try streamFrameWireLen(pending.stream_id, pending.offset, pending.data.len),
                .{ .stream = true },
            );
        }
        return null;
    }

    const ZeroRttConsumeFlags = struct {
        reset_stream: bool = false,
        stop_sending: bool = false,
        stream: bool = false,
    };

    fn buildProtectedZeroRttFramePacket(
        self: *Connection,
        dcid: []const u8,
        scid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        frame_to_send: frame.Frame,
        encoded_frame_len: usize,
        consume: ZeroRttConsumeFlags,
    ) Error!BuiltProtectedLongPacket {
        if (!frameAllowedInFramePacketType(frame_to_send, .zero_rtt)) return error.InvalidPacket;

        const packet_space = self.packetNumberSpace(.application);
        if (packet_space.discarded.*) return error.InvalidPacket;
        if (packet_space.next_packet_number.* > max_quic_varint) return error.Internal;

        const packet_number = packet_space.next_packet_number.*;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            packet_space.largest_acknowledged.*,
        ) catch return error.Internal;

        const header = packet.LongHeader{
            .version = self.config.chosen_version,
            .dcid = dcid,
            .scid = scid,
            .packet_type = .zero_rtt,
            .token = &[_]u8{},
            .packet_number = packet_number,
            .payload_length = 0,
        };
        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        var protected_frame = frame_to_send;
        var protected_frame_len = encoded_frame_len;
        var queued_stream_remainder: ?PendingStreamFrame = null;
        errdefer if (queued_stream_remainder) |remainder| self.allocator.free(remainder.data);
        if (consume.stream) {
            const stream = switch (frame_to_send) {
                .stream => |value| value,
                else => return error.Internal,
            };
            if (stream.data.len != 0) {
                var low: usize = 1;
                var high: usize = stream.data.len;
                var stream_data_len: usize = 0;
                while (low <= high) {
                    const candidate = low + (high - low) / 2;
                    const candidate_frame_len = try streamFrameWireLen(stream.stream_id, stream.offset, candidate);
                    const candidate_plaintext_len = @max(candidate_frame_len, min_payload_len);
                    if (try protectedLongDatagramWireLen(header, packet_number_encoding.len, candidate_plaintext_len) <= self.maxTxDatagramSize()) {
                        stream_data_len = candidate;
                        low = candidate + 1;
                    } else {
                        high = candidate - 1;
                    }
                }
                if (stream_data_len == 0) return error.BufferTooSmall;
                protected_frame = .{ .stream = .{
                    .stream_id = stream.stream_id,
                    .offset = stream.offset,
                    .fin = stream.fin and stream_data_len == stream.data.len,
                    .data = stream.data[0..stream_data_len],
                } };
                protected_frame_len = try streamFrameWireLen(stream.stream_id, stream.offset, stream_data_len);
                if (stream_data_len < stream.data.len) {
                    const remainder_offset = streamEndOffset(stream.offset, stream_data_len) orelse return error.Internal;
                    const remainder_data = self.allocator.dupe(u8, stream.data[stream_data_len..]) catch return error.OutOfMemory;
                    queued_stream_remainder = .{
                        .stream_id = stream.stream_id,
                        .offset = remainder_offset,
                        .fin = stream.fin,
                        .data = remainder_data,
                    };
                }
            }
        }

        const plaintext_len = @max(protected_frame_len, min_payload_len);
        if (try protectedLongDatagramWireLen(header, packet_number_encoding.len, plaintext_len) > self.maxTxDatagramSize()) {
            return error.BufferTooSmall;
        }

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        frame.encodeFrame(plaintext_out.writer(), protected_frame) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const datagram = protection.protectLongPacketAes128(self.allocator, header, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        var sent_stream_frame: ?PendingStreamFrame = null;
        if (consume.stream) {
            const stream = switch (protected_frame) {
                .stream => |stream| stream,
                else => return error.Internal,
            };
            sent_stream_frame = .{
                .stream_id = stream.stream_id,
                .offset = stream.offset,
                .fin = stream.fin,
                .data = self.allocator.dupe(u8, stream.data) catch return error.OutOfMemory,
            };
        }
        errdefer if (sent_stream_frame) |pending| {
            self.allocator.free(pending.data);
        };
        const sent_reset_stream_frame: ?frame.ResetStreamFrame = if (consume.reset_stream)
            switch (protected_frame) {
                .reset_stream => |reset| reset,
                else => return error.Internal,
            }
        else
            null;
        const sent_stop_sending_frame: ?frame.StopSendingFrame = if (consume.stop_sending)
            switch (protected_frame) {
                .stop_sending => |stop_sending| stop_sending,
                else => return error.Internal,
            }
        else
            null;

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        return .{
            .space = .application,
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = frameIsAckEliciting(protected_frame),
            .sent_stream_frame = sent_stream_frame,
            .queued_stream_remainder = queued_stream_remainder,
            .sent_reset_stream_frame = sent_reset_stream_frame,
            .sent_stop_sending_frame = sent_stop_sending_frame,
            .consume_reset_stream = consume.reset_stream,
            .consume_stop_sending = consume.stop_sending,
            .consume_stream = consume.stream,
        };
    }

    fn buildProtectedLongPingPacketInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        dcid: []const u8,
        scid: []const u8,
        token: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        ack_to_send: ?frame.AckFrame,
        min_datagram_len: usize,
    ) Error!BuiltProtectedLongPacket {
        const ack_len = if (ack_to_send) |ack| try ackFrameWireLen(ack) else 0;
        const encoded_len = try addWireLen(ack_len, pingFrameWireLen());
        return try self.buildProtectedLongControlPacketInSpace(
            space,
            dcid,
            scid,
            token,
            keys,
            encoded_len,
            ack_to_send,
            true,
            min_datagram_len,
        );
    }

    fn buildProtectedLongAckOnlyPacketInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        dcid: []const u8,
        scid: []const u8,
        token: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        ack: frame.AckFrame,
        min_datagram_len: usize,
    ) Error!BuiltProtectedLongPacket {
        return try self.buildProtectedLongControlPacketInSpace(
            space,
            dcid,
            scid,
            token,
            keys,
            try ackFrameWireLen(ack),
            ack,
            false,
            min_datagram_len,
        );
    }

    fn buildProtectedLongControlPacketInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        dcid: []const u8,
        scid: []const u8,
        token: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        encoded_frame_len: usize,
        ack_to_send: ?frame.AckFrame,
        include_ping: bool,
        min_datagram_len: usize,
    ) Error!BuiltProtectedLongPacket {
        const long_space = protectedLongPacketSpaceFor(space) orelse return error.InvalidPacket;
        if (space != .initial and token.len != 0) return error.InvalidPacket;
        const header_token = self.initialTokenForPacket(space, token);
        try self.validateOutgoingInitialPacketFields(space, dcid, header_token);

        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;
        if (packet_space.next_packet_number.* > max_quic_varint) return error.Internal;

        const packet_number = packet_space.next_packet_number.*;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            packet_space.largest_acknowledged.*,
        ) catch return error.Internal;

        const header = packet.LongHeader{
            .version = self.config.chosen_version,
            .dcid = dcid,
            .scid = scid,
            .packet_type = long_space.packet_type,
            .token = header_token,
            .packet_number = packet_number,
            .payload_length = 0,
        };
        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const plaintext_len = try protectedLongPlaintextLenForMinDatagram(
            header,
            packet_number_encoding.len,
            @max(encoded_frame_len, min_payload_len),
            min_datagram_len,
        );
        if (plaintext_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        if (ack_to_send) |ack| {
            frame.encodeFrame(plaintext_out.writer(), .{ .ack = ack }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }
        if (include_ping) {
            frame.encodeFrame(plaintext_out.writer(), .{ .ping = {} }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }

        const datagram = protection.protectLongPacketAes128(self.allocator, header, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        var built = BuiltProtectedLongPacket{
            .space = space,
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = include_ping,
            .clear_ack = ack_to_send != null,
            .consume_ping = include_ping,
        };
        built.recordLocalOriginalDestinationConnectionId(self.localOriginalDestinationConnectionIdForPacket(space, dcid));
        built.recordLocalInitialSourceConnectionId(self.localInitialSourceConnectionIdForPacket(space, scid));
        return built;
    }

    fn localOriginalDestinationConnectionIdForPacket(
        self: Connection,
        space: PacketNumberSpace,
        dcid: []const u8,
    ) ?[]const u8 {
        if (self.side != .client or space != .initial or self.original_destination_connection_id_len != null) return null;
        return dcid;
    }

    fn localInitialSourceConnectionIdForPacket(
        self: Connection,
        space: PacketNumberSpace,
        scid: []const u8,
    ) ?[]const u8 {
        if (space != .initial or self.local_initial_source_connection_id_len != null) return null;
        return scid;
    }

    fn validateOutgoingInitialPacketFields(
        self: Connection,
        space: PacketNumberSpace,
        dcid: []const u8,
        token: []const u8,
    ) Error!void {
        if (space != .initial) return;
        if (self.side == .server) {
            if (token.len != 0) return error.InvalidPacket;
            return;
        }
        if (self.originalDestinationConnectionId()) |original_dcid| {
            const expected_dcid = self.peerInitialSourceConnectionId() orelse
                self.retrySourceConnectionId() orelse
                original_dcid;
            if (!std.mem.eql(u8, expected_dcid, dcid)) return error.InvalidPacket;
            return;
        }
        try validateInitialDestinationConnectionIdLength(dcid);
    }

    fn minimumOutgoingInitialDatagramLen(self: Connection, space: PacketNumberSpace, ack_eliciting: bool) usize {
        if (space != .initial) return 0;
        if (self.side == .client or ack_eliciting) return min_initial_udp_datagram_len;
        return 0;
    }

    fn validateIncomingInitialDatagramLen(self: Connection, space: PacketNumberSpace, udp_datagram_len: usize) Error!void {
        if (space == .initial and self.side == .server and udp_datagram_len < min_initial_udp_datagram_len) {
            return error.InvalidPacket;
        }
    }

    fn validateOriginalDestinationConnectionIdForRecord(self: Connection, dcid: []const u8) Error!void {
        if (dcid.len > max_connection_id_len) return error.InvalidPacket;
        if (self.originalDestinationConnectionId()) |existing| {
            if (!std.mem.eql(u8, existing, dcid)) return error.InvalidPacket;
        }
    }

    fn recordOriginalDestinationConnectionId(self: *Connection, dcid: []const u8) void {
        if (self.original_destination_connection_id_len != null) return;
        std.debug.assert(dcid.len <= max_connection_id_len);
        @memcpy(self.original_destination_connection_id[0..dcid.len], dcid);
        self.original_destination_connection_id_len = @intCast(dcid.len);
    }

    fn recordLocalInitialSourceConnectionId(self: *Connection, scid: []const u8) void {
        if (self.local_initial_source_connection_id_len != null) return;
        std.debug.assert(scid.len <= max_connection_id_len);
        @memcpy(self.local_initial_source_connection_id[0..scid.len], scid);
        self.local_initial_source_connection_id_len = @intCast(scid.len);
    }

    fn ensureProtectedLongCommitCapacity(
        self: *Connection,
        built: BuiltProtectedLongPacket,
    ) Error!void {
        if (!built.ack_eliciting) return;
        var packet_space = self.packetNumberSpace(built.space);
        packet_space.sent_packets.ensureUnusedCapacity(self.allocator, 1) catch return error.OutOfMemory;
    }

    fn deinitBuiltProtectedLongPacket(self: *Connection, built: BuiltProtectedLongPacket) void {
        var owned = built;
        owned.deinitSidecars(self.allocator);
        self.allocator.free(owned.datagram);
    }

    fn deinitBuiltProtectedLongPacketIfPresent(
        self: *Connection,
        built: *?BuiltProtectedLongPacket,
    ) void {
        if (built.*) |packet_to_free| {
            self.deinitBuiltProtectedLongPacket(packet_to_free);
            built.* = null;
        }
    }

    fn commitBuiltProtectedLongPacket(
        self: *Connection,
        built: BuiltProtectedLongPacket,
        now_nanos: i64,
    ) void {
        var packet_space = self.packetNumberSpace(built.space);
        var sent_crypto_frame: ?PendingCryptoFrame = null;
        var sent_stream_frame = built.sent_stream_frame;
        var sent_reset_stream_frame = built.sent_reset_stream_frame;
        var sent_stop_sending_frame = built.sent_stop_sending_frame;
        if (built.consume_crypto) {
            sent_crypto_frame = packet_space.crypto_send_queue.orderedRemove(0);
        }

        if (built.ack_eliciting) {
            packet_space.sent_packets.appendAssumeCapacity(.{
                .packet_number = built.packet_number,
                .sent_time_nanos = now_nanos,
                .bytes = built.datagram.len,
                .stream_frame = sent_stream_frame,
                .crypto_frame = sent_crypto_frame,
                .reset_stream_frame = sent_reset_stream_frame,
                .stop_sending_frame = sent_stop_sending_frame,
            });
            sent_stream_frame = null;
            sent_crypto_frame = null;
            sent_reset_stream_frame = null;
            sent_stop_sending_frame = null;
        }
        if (sent_stream_frame) |pending| {
            self.allocator.free(pending.data);
        }
        if (sent_crypto_frame) |pending| {
            self.allocator.free(pending.data);
        }

        if (built.consume_ping) packet_space.pending_ping_count.* -= 1;
        if (built.consume_reset_stream) _ = self.pending_reset_streams.orderedRemove(0);
        if (built.consume_stop_sending) _ = self.pending_stop_sending.orderedRemove(0);
        if (built.consume_stream) {
            const removed = self.send_queue.items[0];
            if (built.queued_stream_remainder) |remainder| {
                self.send_queue.items[0] = remainder;
            } else {
                _ = self.send_queue.orderedRemove(0);
            }
            self.allocator.free(removed.data);
        }
        if (built.clear_ack) packet_space.pending_ack_largest.* = null;
        packet_space.next_packet_number.* = built.packet_number + 1;
        if (built.ack_eliciting) self.recordAckElicitingSendInSpace(built.space, built.datagram.len);
        if (built.close_packet and !self.closed) self.enterClosingState(now_nanos);
        self.recordPeerAddressBytesSent(built.datagram.len);
        self.recordPacketActivity(now_nanos);
        if (built.local_original_destination_connection_id_len) |len| {
            self.recordOriginalDestinationConnectionId(built.local_original_destination_connection_id[0..len]);
        }
        if (built.local_initial_source_connection_id_len) |len| {
            self.recordLocalInitialSourceConnectionId(built.local_initial_source_connection_id[0..len]);
        }
        self.maybeDiscardInitialAfterHandshakePacketSent(built.space);
        self.maybeDiscardHandshakeAfterConfirmedCryptoSent(built.space);
    }

    fn buildNextProtectedShortPacket(
        self: *Connection,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
    ) Error!?BuiltProtectedShortPacket {
        if (self.application_packet_space_discarded) return error.InvalidPacket;
        const ack_to_send = self.pendingAckFrame(.application);
        if (self.pending_path_responses.items.len != 0) {
            return try self.buildProtectedShortPathResponsePacket(dcid, keys, key_phase, ack_to_send);
        }
        if (self.pending_reset_streams.items.len != 0) {
            return try self.buildProtectedShortResetStreamPacket(dcid, keys, key_phase, ack_to_send);
        }
        self.dropObsoleteStopSendingFrames();
        if (self.pending_stop_sending.items.len != 0) {
            return try self.buildProtectedShortStopSendingPacket(dcid, keys, key_phase, ack_to_send);
        }
        if (self.pending_retire_connection_ids.items.len != 0) {
            return try self.buildProtectedShortRetireConnectionIdPacket(dcid, keys, key_phase, ack_to_send);
        }
        if (self.pending_handshake_done) {
            return try self.buildProtectedShortHandshakeDonePacket(dcid, keys, key_phase, ack_to_send);
        }
        if (self.nextUnsentLocalConnectionIdIndex() != null) {
            return try self.buildProtectedShortNewConnectionIdPacket(dcid, keys, key_phase, ack_to_send);
        }
        if (self.pending_new_tokens.items.len != 0) {
            return try self.buildProtectedShortNewTokenPacket(dcid, keys, key_phase, ack_to_send);
        }
        if (self.pending_path_challenges.items.len != 0) {
            return try self.buildProtectedShortPathChallengePacket(dcid, keys, key_phase, ack_to_send);
        }
        self.dropObsoleteMaxFrames();
        if (self.pending_max_frames.items.len != 0) {
            return try self.buildProtectedShortMaxFramePacket(dcid, keys, key_phase, ack_to_send);
        }
        self.dropObsoleteBlockedFrames();
        if (self.pending_blocked_frames.items.len != 0) {
            return try self.buildProtectedShortBlockedFramePacket(dcid, keys, key_phase, ack_to_send);
        }
        if (self.crypto_send_queue.items.len != 0) {
            return try self.buildProtectedShortCryptoPacket(dcid, keys, key_phase, ack_to_send);
        }
        if (self.pending_ping_count != 0) {
            const ack_len = if (ack_to_send) |ack| try ackFrameWireLen(ack) else 0;
            const encoded_len = try addWireLen(ack_len, pingFrameWireLen());
            return try self.buildProtectedShortControlPacket(dcid, keys, key_phase, encoded_len, ack_to_send, true);
        }
        if (self.pending_datagrams.items.len != 0) {
            return try self.buildProtectedShortDatagramFramePacket(dcid, keys, key_phase, ack_to_send);
        }
        self.dropResetClosedStreamFrames();
        if (self.send_queue.items.len != 0) {
            return try self.buildProtectedShortStreamPacket(dcid, keys, key_phase, ack_to_send);
        }
        if (ack_to_send) |ack| {
            return try self.buildProtectedShortControlPacket(
                dcid,
                keys,
                key_phase,
                try ackFrameWireLen(ack),
                ack,
                false,
            );
        }
        return null;
    }

    fn buildProtectedShortClosePacket(
        self: *Connection,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
    ) Error!BuiltProtectedShortPacket {
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        const close = self.pending_close orelse return error.Internal;
        const encoded_frame_len = try closeFrameWireLen(close);

        const packet_number = self.next_packet_number;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            self.largest_acknowledged,
        ) catch return error.Internal;

        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const plaintext_len = @max(encoded_frame_len, min_payload_len);
        if (plaintext_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        switch (close) {
            .connection => |connection| frame.encodeFrame(plaintext_out.writer(), .{ .connection_close = connection }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
            .application => |application| frame.encodeFrame(plaintext_out.writer(), .{ .application_close = application }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
        }

        const datagram = protection.protectShortPacketAes128(self.allocator, .{
            .dcid = dcid,
            .spin_bit = self.shortHeaderSpinBit(),
            .key_phase = key_phase,
            .packet_number = packet_number,
        }, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        return .{
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = false,
            .close_packet = true,
        };
    }

    fn buildProtectedShortPathResponsePacket(
        self: *Connection,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
        ack_to_send: ?frame.AckFrame,
    ) Error!BuiltProtectedShortPacket {
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        const response_data = self.pending_path_responses.items[0];
        const response_encoded_len = pathResponseFrameWireLen();
        var encoded_frame_len = response_encoded_len;
        if (ack_to_send) |ack| {
            encoded_frame_len = try addWireLen(try ackFrameWireLen(ack), response_encoded_len);
        }

        const packet_number = self.next_packet_number;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            self.largest_acknowledged,
        ) catch return error.Internal;

        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const plaintext_len = try self.protectedPathValidationPlaintextLen(
            dcid.len,
            packet_number_encoding.len,
            @max(encoded_frame_len, min_payload_len),
        );
        if (plaintext_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        if (ack_to_send) |ack| {
            frame.encodeFrame(plaintext_out.writer(), .{ .ack = ack }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }
        frame.encodeFrame(plaintext_out.writer(), .{ .path_response = .{ .data = response_data } }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const datagram = protection.protectShortPacketAes128(self.allocator, .{
            .dcid = dcid,
            .spin_bit = self.shortHeaderSpinBit(),
            .key_phase = key_phase,
            .packet_number = packet_number,
        }, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        return .{
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = true,
            .clear_ack = ack_to_send != null,
            .consume_path_response = true,
        };
    }

    fn buildProtectedShortResetStreamPacket(
        self: *Connection,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
        ack_to_send: ?frame.AckFrame,
    ) Error!BuiltProtectedShortPacket {
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        const reset = self.pending_reset_streams.items[0];
        const reset_encoded_len = try resetStreamFrameWireLen(reset);
        var encoded_frame_len = reset_encoded_len;
        if (ack_to_send) |ack| {
            encoded_frame_len = try addWireLen(try ackFrameWireLen(ack), reset_encoded_len);
        }

        const packet_number = self.next_packet_number;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            self.largest_acknowledged,
        ) catch return error.Internal;

        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const plaintext_len = @max(encoded_frame_len, min_payload_len);
        if (plaintext_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        if (ack_to_send) |ack| {
            frame.encodeFrame(plaintext_out.writer(), .{ .ack = ack }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }
        frame.encodeFrame(plaintext_out.writer(), .{ .reset_stream = reset }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const datagram = protection.protectShortPacketAes128(self.allocator, .{
            .dcid = dcid,
            .spin_bit = self.shortHeaderSpinBit(),
            .key_phase = key_phase,
            .packet_number = packet_number,
        }, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        return .{
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = true,
            .sent_reset_stream_frame = reset,
            .clear_ack = ack_to_send != null,
            .consume_reset_stream = true,
        };
    }

    fn buildProtectedShortStopSendingPacket(
        self: *Connection,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
        ack_to_send: ?frame.AckFrame,
    ) Error!BuiltProtectedShortPacket {
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        const stop_sending = self.pending_stop_sending.items[0];
        const stop_encoded_len = try stopSendingFrameWireLen(stop_sending);
        var encoded_frame_len = stop_encoded_len;
        if (ack_to_send) |ack| {
            encoded_frame_len = try addWireLen(try ackFrameWireLen(ack), stop_encoded_len);
        }

        const packet_number = self.next_packet_number;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            self.largest_acknowledged,
        ) catch return error.Internal;

        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const plaintext_len = @max(encoded_frame_len, min_payload_len);
        if (plaintext_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        if (ack_to_send) |ack| {
            frame.encodeFrame(plaintext_out.writer(), .{ .ack = ack }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }
        frame.encodeFrame(plaintext_out.writer(), .{ .stop_sending = stop_sending }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const datagram = protection.protectShortPacketAes128(self.allocator, .{
            .dcid = dcid,
            .spin_bit = self.shortHeaderSpinBit(),
            .key_phase = key_phase,
            .packet_number = packet_number,
        }, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        return .{
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = true,
            .sent_stop_sending_frame = stop_sending,
            .clear_ack = ack_to_send != null,
            .consume_stop_sending = true,
        };
    }

    fn buildProtectedShortRetireConnectionIdPacket(
        self: *Connection,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
        ack_to_send: ?frame.AckFrame,
    ) Error!BuiltProtectedShortPacket {
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        const sequence_number = self.pending_retire_connection_ids.items[0];
        const retire_encoded_len = try retireConnectionIdFrameWireLen(sequence_number);
        var encoded_frame_len = retire_encoded_len;
        if (ack_to_send) |ack| {
            encoded_frame_len = try addWireLen(try ackFrameWireLen(ack), retire_encoded_len);
        }

        const packet_number = self.next_packet_number;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            self.largest_acknowledged,
        ) catch return error.Internal;

        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const plaintext_len = @max(encoded_frame_len, min_payload_len);
        if (plaintext_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        if (ack_to_send) |ack| {
            frame.encodeFrame(plaintext_out.writer(), .{ .ack = ack }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }
        frame.encodeFrame(plaintext_out.writer(), .{ .retire_connection_id = .{ .sequence_number = sequence_number } }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const datagram = protection.protectShortPacketAes128(self.allocator, .{
            .dcid = dcid,
            .spin_bit = self.shortHeaderSpinBit(),
            .key_phase = key_phase,
            .packet_number = packet_number,
        }, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        return .{
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = true,
            .clear_ack = ack_to_send != null,
            .consume_retire_connection_id = true,
        };
    }

    fn buildProtectedShortNewConnectionIdPacket(
        self: *Connection,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
        ack_to_send: ?frame.AckFrame,
    ) Error!BuiltProtectedShortPacket {
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        const local_index = self.nextUnsentLocalConnectionIdIndex() orelse return error.Internal;
        const local_id = self.local_connection_ids.items[local_index];
        const new_connection_id_encoded_len = try newConnectionIdFrameWireLen(local_id);
        var encoded_frame_len = new_connection_id_encoded_len;
        if (ack_to_send) |ack| {
            encoded_frame_len = try addWireLen(try ackFrameWireLen(ack), new_connection_id_encoded_len);
        }

        const packet_number = self.next_packet_number;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            self.largest_acknowledged,
        ) catch return error.Internal;

        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const plaintext_len = @max(encoded_frame_len, min_payload_len);
        if (plaintext_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        if (ack_to_send) |ack| {
            frame.encodeFrame(plaintext_out.writer(), .{ .ack = ack }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }
        frame.encodeFrame(plaintext_out.writer(), .{ .new_connection_id = .{
            .sequence_number = local_id.sequence_number,
            .retire_prior_to = local_id.retire_prior_to,
            .connection_id = local_id.connection_id,
            .stateless_reset_token = local_id.stateless_reset_token,
        } }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const datagram = protection.protectShortPacketAes128(self.allocator, .{
            .dcid = dcid,
            .spin_bit = self.shortHeaderSpinBit(),
            .key_phase = key_phase,
            .packet_number = packet_number,
        }, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        return .{
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = true,
            .clear_ack = ack_to_send != null,
            .new_connection_id_index = local_index,
        };
    }

    fn buildProtectedShortHandshakeDonePacket(
        self: *Connection,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
        ack_to_send: ?frame.AckFrame,
    ) Error!BuiltProtectedShortPacket {
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        const handshake_done_encoded_len = handshakeDoneFrameWireLen();
        var encoded_frame_len = handshake_done_encoded_len;
        if (ack_to_send) |ack| {
            encoded_frame_len = try addWireLen(try ackFrameWireLen(ack), handshake_done_encoded_len);
        }

        const packet_number = self.next_packet_number;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            self.largest_acknowledged,
        ) catch return error.Internal;

        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const plaintext_len = @max(encoded_frame_len, min_payload_len);
        if (plaintext_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        if (ack_to_send) |ack| {
            frame.encodeFrame(plaintext_out.writer(), .{ .ack = ack }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }
        frame.encodeFrame(plaintext_out.writer(), .{ .handshake_done = {} }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const datagram = protection.protectShortPacketAes128(self.allocator, .{
            .dcid = dcid,
            .spin_bit = self.shortHeaderSpinBit(),
            .key_phase = key_phase,
            .packet_number = packet_number,
        }, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        return .{
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = true,
            .clear_ack = ack_to_send != null,
            .consume_handshake_done = true,
        };
    }

    fn buildProtectedShortNewTokenPacket(
        self: *Connection,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
        ack_to_send: ?frame.AckFrame,
    ) Error!BuiltProtectedShortPacket {
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        const token = self.pending_new_tokens.items[0];
        const new_token_encoded_len = try newTokenFrameWireLen(token);
        var encoded_frame_len = new_token_encoded_len;
        if (ack_to_send) |ack| {
            encoded_frame_len = try addWireLen(try ackFrameWireLen(ack), new_token_encoded_len);
        }

        const packet_number = self.next_packet_number;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            self.largest_acknowledged,
        ) catch return error.Internal;

        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const plaintext_len = @max(encoded_frame_len, min_payload_len);
        if (plaintext_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        if (ack_to_send) |ack| {
            frame.encodeFrame(plaintext_out.writer(), .{ .ack = ack }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }
        frame.encodeFrame(plaintext_out.writer(), .{ .new_token = .{ .token = token } }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const datagram = protection.protectShortPacketAes128(self.allocator, .{
            .dcid = dcid,
            .spin_bit = self.shortHeaderSpinBit(),
            .key_phase = key_phase,
            .packet_number = packet_number,
        }, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        return .{
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = true,
            .clear_ack = ack_to_send != null,
            .consume_new_token = true,
        };
    }

    fn buildProtectedShortPathChallengePacket(
        self: *Connection,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
        ack_to_send: ?frame.AckFrame,
    ) Error!BuiltProtectedShortPacket {
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        const pending_challenge = self.pending_path_challenges.items[0];
        const challenge_encoded_len = pathChallengeFrameWireLen();
        var encoded_frame_len = challenge_encoded_len;
        if (ack_to_send) |ack| {
            encoded_frame_len = try addWireLen(try ackFrameWireLen(ack), challenge_encoded_len);
        }

        const packet_number = self.next_packet_number;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            self.largest_acknowledged,
        ) catch return error.Internal;

        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const plaintext_len = try self.protectedPathValidationPlaintextLen(
            dcid.len,
            packet_number_encoding.len,
            @max(encoded_frame_len, min_payload_len),
        );
        if (plaintext_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        if (ack_to_send) |ack| {
            frame.encodeFrame(plaintext_out.writer(), .{ .ack = ack }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }
        frame.encodeFrame(plaintext_out.writer(), .{ .path_challenge = .{ .data = pending_challenge.data } }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const datagram = protection.protectShortPacketAes128(self.allocator, .{
            .dcid = dcid,
            .spin_bit = self.shortHeaderSpinBit(),
            .key_phase = key_phase,
            .packet_number = packet_number,
        }, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        return .{
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = true,
            .clear_ack = ack_to_send != null,
            .consume_path_challenge = true,
        };
    }

    fn buildProtectedShortMaxFramePacket(
        self: *Connection,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
        ack_to_send: ?frame.AckFrame,
    ) Error!BuiltProtectedShortPacket {
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        const max_frame = self.pending_max_frames.items[0];
        const max_encoded_len = try maxFrameWireLen(max_frame);
        var encoded_frame_len = max_encoded_len;
        if (ack_to_send) |ack| {
            encoded_frame_len = try addWireLen(try ackFrameWireLen(ack), max_encoded_len);
        }

        const packet_number = self.next_packet_number;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            self.largest_acknowledged,
        ) catch return error.Internal;

        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const plaintext_len = @max(encoded_frame_len, min_payload_len);
        if (plaintext_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        if (ack_to_send) |ack| {
            frame.encodeFrame(plaintext_out.writer(), .{ .ack = ack }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }
        switch (max_frame) {
            .data => |data| frame.encodeFrame(plaintext_out.writer(), .{ .max_data = data }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
            .stream_data => |stream_data| frame.encodeFrame(plaintext_out.writer(), .{ .max_stream_data = stream_data }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
            .streams_bidi => |streams| frame.encodeFrame(plaintext_out.writer(), .{ .max_streams_bidi = streams }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
            .streams_uni => |streams| frame.encodeFrame(plaintext_out.writer(), .{ .max_streams_uni = streams }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
        }

        const datagram = protection.protectShortPacketAes128(self.allocator, .{
            .dcid = dcid,
            .spin_bit = self.shortHeaderSpinBit(),
            .key_phase = key_phase,
            .packet_number = packet_number,
        }, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        return .{
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = true,
            .clear_ack = ack_to_send != null,
            .consume_max_frame = true,
        };
    }

    fn buildProtectedShortBlockedFramePacket(
        self: *Connection,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
        ack_to_send: ?frame.AckFrame,
    ) Error!BuiltProtectedShortPacket {
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        const blocked = self.pending_blocked_frames.items[0];
        const blocked_encoded_len = try blockedFrameWireLen(blocked);
        var encoded_frame_len = blocked_encoded_len;
        if (ack_to_send) |ack| {
            encoded_frame_len = try addWireLen(try ackFrameWireLen(ack), blocked_encoded_len);
        }

        const packet_number = self.next_packet_number;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            self.largest_acknowledged,
        ) catch return error.Internal;

        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const plaintext_len = @max(encoded_frame_len, min_payload_len);
        if (plaintext_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        if (ack_to_send) |ack| {
            frame.encodeFrame(plaintext_out.writer(), .{ .ack = ack }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }
        switch (blocked) {
            .data => |data| frame.encodeFrame(plaintext_out.writer(), .{ .data_blocked = data }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
            .stream_data => |stream_data| frame.encodeFrame(plaintext_out.writer(), .{ .stream_data_blocked = stream_data }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
            .streams_bidi => |streams| frame.encodeFrame(plaintext_out.writer(), .{ .streams_blocked_bidi = streams }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
            .streams_uni => |streams| frame.encodeFrame(plaintext_out.writer(), .{ .streams_blocked_uni = streams }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            },
        }

        const datagram = protection.protectShortPacketAes128(self.allocator, .{
            .dcid = dcid,
            .spin_bit = self.shortHeaderSpinBit(),
            .key_phase = key_phase,
            .packet_number = packet_number,
        }, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        return .{
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = true,
            .clear_ack = ack_to_send != null,
            .consume_blocked_frame = true,
        };
    }

    fn buildProtectedShortCryptoPacket(
        self: *Connection,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
        ack_to_send: ?frame.AckFrame,
    ) Error!BuiltProtectedShortPacket {
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        const pending = self.crypto_send_queue.items[0];
        const crypto_encoded_len = try cryptoFrameWireLen(pending.offset, pending.data.len);
        var encoded_frame_len = crypto_encoded_len;
        if (ack_to_send) |ack| {
            encoded_frame_len = try addWireLen(try ackFrameWireLen(ack), crypto_encoded_len);
        }

        const packet_number = self.next_packet_number;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            self.largest_acknowledged,
        ) catch return error.Internal;

        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const plaintext_len = @max(encoded_frame_len, min_payload_len);
        if (plaintext_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        if (ack_to_send) |ack| {
            frame.encodeFrame(plaintext_out.writer(), .{ .ack = ack }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }
        frame.encodeFrame(plaintext_out.writer(), .{ .crypto = .{
            .offset = pending.offset,
            .data = pending.data,
        } }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const datagram = protection.protectShortPacketAes128(self.allocator, .{
            .dcid = dcid,
            .spin_bit = self.shortHeaderSpinBit(),
            .key_phase = key_phase,
            .packet_number = packet_number,
        }, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        return .{
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = true,
            .clear_ack = ack_to_send != null,
            .consume_crypto = true,
        };
    }

    /// Build one protected short packet carrying a DATAGRAM frame (RFC 9221).
    ///
    /// Dequeues the first pending DATAGRAM payload and encodes it alongside
    /// an optional ACK frame. DATAGRAM frames are ack-eliciting but not
    /// retransmitted on loss (unreliable by design).
    fn buildProtectedShortDatagramFramePacket(
        self: *Connection,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
        ack_to_send: ?frame.AckFrame,
    ) Error!BuiltProtectedShortPacket {
        if (self.next_packet_number > max_quic_varint) return error.Internal;
        if (self.pending_datagrams.items.len == 0) return error.Internal;

        const packet_number = self.next_packet_number;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            self.largest_acknowledged,
        ) catch return error.Internal;

        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const dgram_data = self.pending_datagrams.items[0];
        const ack_encoded_len = if (ack_to_send) |ack| try ackFrameWireLen(ack) else 0;
        const datagram_frame_len = try wire_len.datagramFrameWireLen(dgram_data.len);
        const encoded_frame_len = try addWireLen(ack_encoded_len, datagram_frame_len);
        const plaintext_len = @max(encoded_frame_len, min_payload_len);

        const empty_datagram_len = try protectedShortDatagramWireLen(dcid.len, packet_number_encoding.len, 0);
        if (empty_datagram_len + plaintext_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        if (ack_to_send) |ack| {
            frame.encodeFrame(plaintext_out.writer(), .{ .ack = ack }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }
        frame.encodeFrame(plaintext_out.writer(), .{ .datagram = .{ .data = dgram_data } }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const datagram = protection.protectShortPacketAes128(self.allocator, .{
            .dcid = dcid,
            .spin_bit = self.shortHeaderSpinBit(),
            .key_phase = key_phase,
            .packet_number = packet_number,
        }, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        // Dequeue the DATAGRAM payload after successful encoding.
        const owned = self.pending_datagrams.orderedRemove(0);
        self.allocator.free(owned);

        return .{
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = true,
            .clear_ack = ack_to_send != null,
            .consume_ping = false,
        };
    }

    fn buildProtectedShortStreamPacket(
        self: *Connection,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
        ack_to_send: ?frame.AckFrame,
    ) Error!BuiltProtectedShortPacket {
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        const packet_number = self.next_packet_number;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            self.largest_acknowledged,
        ) catch return error.Internal;
        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;

        const empty_datagram_len = try protectedShortDatagramWireLen(dcid.len, packet_number_encoding.len, 0);
        const max_datagram_size = self.maxTxDatagramSize();
        if (empty_datagram_len > max_datagram_size) return error.BufferTooSmall;
        const max_plaintext_len = max_datagram_size - empty_datagram_len;

        const ack_encoded_len = if (ack_to_send) |ack| try ackFrameWireLen(ack) else 0;
        const pending = self.send_queue.items[0];
        const stream_budget = std.math.sub(usize, max_plaintext_len, ack_encoded_len) catch {
            if (ack_to_send) |ack| {
                return try self.buildProtectedShortControlPacket(dcid, keys, key_phase, ack_encoded_len, ack, false);
            }
            return error.BufferTooSmall;
        };
        if (try streamFrameWireLen(pending.stream_id, pending.offset, 0) > stream_budget) {
            if (ack_to_send) |ack| {
                return try self.buildProtectedShortControlPacket(dcid, keys, key_phase, ack_encoded_len, ack, false);
            }
            return error.BufferTooSmall;
        }
        const stream_data_len = try maxStreamFrameDataLen(
            pending.stream_id,
            pending.offset,
            pending.data.len,
            stream_budget,
        );
        const stream_encoded_len = try streamFrameWireLen(pending.stream_id, pending.offset, stream_data_len);
        const encoded_frame_len = try addWireLen(ack_encoded_len, stream_encoded_len);
        const plaintext_len = @max(encoded_frame_len, min_payload_len);
        if (try protectedShortDatagramWireLen(dcid.len, packet_number_encoding.len, plaintext_len) > max_datagram_size) {
            return error.BufferTooSmall;
        }

        const header: packet.ShortHeader = .{
            .dcid = dcid,
            .spin_bit = self.shortHeaderSpinBit(),
            .key_phase = key_phase,
            .packet_number = packet_number,
        };
        // empty_datagram_len = header + AEAD tag (0 plaintext), so the header
        // length is that minus the tag; the payload is protected in place.
        const header_len = empty_datagram_len - protection.aead_tag_len;
        const protected_payload_len = plaintext_len + protection.aead_tag_len;
        const datagram_len = try addWireLen(header_len, protected_payload_len);
        const datagram = self.allocator.alloc(u8, datagram_len) catch return error.OutOfMemory;
        errdefer self.allocator.free(datagram);

        var header_writer = buffer.fixedWriter(datagram[0..header_len]);
        packet.encodeShortHeaderWithPacketNumberEncoding(header_writer.writer(), header, packet_number_encoding) catch |err| switch (err) {
            error.InvalidConnectionIdLength => return error.InvalidPacket,
            else => return error.Internal,
        };

        const plaintext = datagram[header_len..][0..plaintext_len];
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        if (ack_to_send) |ack| {
            frame.encodeFrame(plaintext_out.writer(), .{ .ack = ack }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }
        frame.encodeFrame(plaintext_out.writer(), .{ .stream = .{
            .stream_id = pending.stream_id,
            .offset = pending.offset,
            .fin = pending.fin and stream_data_len == pending.data.len,
            .data = pending.data[0..stream_data_len],
        } }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        protection.protectShortPacketAes128InPlace(header, packet_number_encoding, keys, datagram, header_len, plaintext_len) catch |err| switch (err) {
            else => return error.InvalidPacket,
        };

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        const sent_stream_frame = try self.clonePendingStreamFrame(.{
            .stream_id = pending.stream_id,
            .offset = pending.offset,
            .fin = pending.fin and stream_data_len == pending.data.len,
            .data = pending.data[0..stream_data_len],
        });
        errdefer self.allocator.free(sent_stream_frame.data);
        const queued_stream_remainder: ?PendingStreamFrame = if (stream_data_len < pending.data.len) remainder: {
            const remainder_offset = streamEndOffset(pending.offset, stream_data_len) orelse return error.Internal;
            const remainder_data = self.allocator.dupe(u8, pending.data[stream_data_len..]) catch return error.OutOfMemory;
            break :remainder .{
                .stream_id = pending.stream_id,
                .offset = remainder_offset,
                .fin = pending.fin,
                .data = remainder_data,
            };
        } else null;
        errdefer if (queued_stream_remainder) |remainder| self.allocator.free(remainder.data);
        return .{
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = true,
            .sent_stream_frame = sent_stream_frame,
            .queued_stream_remainder = queued_stream_remainder,
            .clear_ack = ack_to_send != null,
            .consume_stream = true,
        };
    }

    fn buildProtectedShortControlPacket(
        self: *Connection,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
        encoded_frame_len: usize,
        ack_to_send: ?frame.AckFrame,
        include_ping: bool,
    ) Error!BuiltProtectedShortPacket {
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        const packet_number = self.next_packet_number;
        const packet_number_encoding = packet.encodePacketNumberForHeader(
            packet_number,
            self.largest_acknowledged,
        ) catch return error.Internal;

        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const plaintext_len = @max(encoded_frame_len, min_payload_len);
        if (plaintext_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        if (ack_to_send) |ack| {
            frame.encodeFrame(plaintext_out.writer(), .{ .ack = ack }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }
        if (include_ping) {
            frame.encodeFrame(plaintext_out.writer(), .{ .ping = {} }) catch |err| switch (err) {
                error.NoSpaceLeft => return error.BufferTooSmall,
                else => return error.Internal,
            };
        }

        const datagram = protection.protectShortPacketAes128(self.allocator, .{
            .dcid = dcid,
            .spin_bit = self.shortHeaderSpinBit(),
            .key_phase = key_phase,
            .packet_number = packet_number,
        }, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        if (datagram.len > self.maxTxDatagramSize()) return error.BufferTooSmall;
        return .{
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = include_ping,
            .clear_ack = ack_to_send != null,
            .consume_ping = include_ping,
        };
    }

    fn commitBuiltProtectedShortPacket(
        self: *Connection,
        built: BuiltProtectedShortPacket,
        now_nanos: i64,
    ) void {
        var sent_crypto_frame: ?PendingCryptoFrame = null;
        if (built.consume_crypto) {
            sent_crypto_frame = self.crypto_send_queue.orderedRemove(0);
        }

        if (built.ack_eliciting) {
            self.sent_packets.appendAssumeCapacity(.{
                .packet_number = built.packet_number,
                .sent_time_nanos = now_nanos,
                .bytes = built.datagram.len,
                .stream_frame = built.sent_stream_frame,
                .crypto_frame = sent_crypto_frame,
                .reset_stream_frame = built.sent_reset_stream_frame,
                .stop_sending_frame = built.sent_stop_sending_frame,
            });
            sent_crypto_frame = null;
        }
        if (sent_crypto_frame) |pending| {
            self.allocator.free(pending.data);
        }

        if (built.consume_ping) self.pending_ping_count -= 1;
        if (built.consume_path_response) _ = self.pending_path_responses.orderedRemove(0);
        if (built.consume_path_challenge) {
            const removed = self.pending_path_challenges.orderedRemove(0);
            const transmissions = std.math.add(u8, removed.transmissions, 1) catch max_path_challenge_transmissions;
            self.outstanding_path_challenges.appendAssumeCapacity(.{
                .data = removed.data,
                .sent_time_nanos = now_nanos,
                .transmissions = transmissions,
            });
        }
        if (built.consume_retire_connection_id) _ = self.pending_retire_connection_ids.orderedRemove(0);
        if (built.new_connection_id_index) |local_index| self.local_connection_ids.items[local_index].sent = true;
        if (built.consume_handshake_done) {
            self.pending_handshake_done = false;
            self.handshake_done_sent = true;
        }
        if (built.consume_new_token) {
            const removed = self.pending_new_tokens.orderedRemove(0);
            self.allocator.free(removed);
        }
        if (built.consume_max_frame) _ = self.pending_max_frames.orderedRemove(0);
        if (built.consume_blocked_frame) _ = self.pending_blocked_frames.orderedRemove(0);
        if (built.consume_reset_stream) _ = self.pending_reset_streams.orderedRemove(0);
        if (built.consume_stop_sending) _ = self.pending_stop_sending.orderedRemove(0);
        if (built.consume_stream) {
            const removed = self.send_queue.items[0];
            if (built.queued_stream_remainder) |remainder| {
                self.send_queue.items[0] = remainder;
            } else {
                _ = self.send_queue.orderedRemove(0);
            }
            self.allocator.free(removed.data);
        }
        if (built.clear_ack) self.pending_ack_largest = null;
        self.next_packet_number = built.packet_number + 1;
        if (built.ack_eliciting) self.recordAckElicitingSendInSpace(.application, built.datagram.len);
        if (built.close_packet and !self.closed) self.enterClosingState(now_nanos);
        self.recordPeerAddressBytesSent(built.datagram.len);
        self.recordPacketActivity(now_nanos);
    }

    /// Process one frame-payload datagram using RFC 9000 packet-type frame rules.
    ///
    /// 0-RTT and 1-RTT both use the Application packet number space, but 0-RTT
    /// rejects frames that are only valid after the handshake has progressed.
    /// Closing or draining connections discard the datagram before parsing.
    pub fn processDatagramForPacketType(
        self: *Connection,
        packet_type: FramePacketType,
        now_nanos: i64,
        datagram: []const u8,
    ) Error!void {
        try self.processFramesInSpaceNoSnapshot(
            packetNumberSpaceForFramePacketType(packet_type),
            packet_type,
            now_nanos,
            datagram,
            null,
        );
    }

    fn semanticCloseError(
        code: transport_error.TransportErrorCode,
        frame_type_value: u64,
        reason_phrase: []const u8,
    ) FramePayloadCloseError {
        return .{
            .code = code,
            .frame_type = frame_type_value,
            .reason_phrase = reason_phrase,
        };
    }

    fn classifyReceiveStreamIdCloseError(self: *Connection, stream_id: u64, frame_type_value: u64) ?FramePayloadCloseError {
        if (stream_id > max_quic_varint) return null;
        if (isLocalBidirectionalStream(self.side, stream_id)) {
            if (self.findSendStream(stream_id) == null) {
                return semanticCloseError(.stream_state_error, frame_type_value, "stream state");
            }
            return null;
        }
        if (isBidirectionalStream(stream_id)) {
            if (streamCountForId(stream_id) > self.recv_max_streams_bidi) {
                return semanticCloseError(.stream_limit_error, frame_type_value, "stream limit");
            }
            return null;
        }
        if (isLocalStreamInitiator(self.side, stream_id)) {
            return semanticCloseError(.stream_state_error, frame_type_value, "stream state");
        }
        if (streamCountForId(stream_id) > self.recv_max_streams_uni) {
            return semanticCloseError(.stream_limit_error, frame_type_value, "stream limit");
        }
        return null;
    }

    fn classifySendControlStreamIdCloseError(self: *Connection, stream_id: u64, frame_type_value: u64) ?FramePayloadCloseError {
        if (stream_id > max_quic_varint) return null;
        if (!isBidirectionalStream(stream_id)) {
            if (!isLocalStreamInitiator(self.side, stream_id)) {
                return semanticCloseError(.stream_state_error, frame_type_value, "stream state");
            }
            if (self.findSendStream(stream_id) == null) {
                return semanticCloseError(.stream_state_error, frame_type_value, "stream state");
            }
            return null;
        }
        if (isLocalStreamInitiator(self.side, stream_id)) {
            if (self.findSendStream(stream_id) == null) {
                return semanticCloseError(.stream_state_error, frame_type_value, "stream state");
            }
            return null;
        }
        if (streamCountForId(stream_id) > self.recv_max_streams_bidi) {
            return semanticCloseError(.stream_limit_error, frame_type_value, "stream limit");
        }
        return null;
    }

    fn classifyStreamFrameProcessingCloseError(
        self: *Connection,
        stream_frame: frame.StreamFrame,
        frame_type_value: u64,
    ) ?FramePayloadCloseError {
        if (self.classifyReceiveStreamIdCloseError(stream_frame.stream_id, frame_type_value)) |close| return close;

        const end_offset = streamEndOffset(stream_frame.offset, stream_frame.data.len) orelse return null;
        const existing_state = self.findRecvStream(stream_frame.stream_id);
        const stream_receive_limit = if (existing_state) |stream_state| stream_state.max_data else self.recv_max_stream_data;
        if (end_offset > stream_receive_limit) {
            return semanticCloseError(.flow_control_error, frame_type_value, "flow control");
        }

        if (existing_state) |stream_state| {
            if (stream_state.final_size) |final_size| {
                if (end_offset > final_size) {
                    return semanticCloseError(.final_size_error, frame_type_value, "final size");
                }
                if (stream_frame.fin and end_offset != final_size) {
                    return semanticCloseError(.final_size_error, frame_type_value, "final size");
                }
                if (streamFrameHasConflictingOverlap(stream_state.*, stream_frame.offset, stream_frame.data) catch return null) {
                    return semanticCloseError(.protocol_violation, frame_type_value, "stream data");
                }
                const final_size_usize = std.math.cast(usize, final_size) orelse return null;
                if (stream_state.data.items.len >= final_size_usize) return null;
                if (stream_state.reset_error_code != null) return null;
            } else if (stream_state.reset_error_code != null) {
                return null;
            } else if (stream_frame.fin) {
                const highest_received = highestReceivedStreamEndOffset(stream_state.*) catch return null;
                if (end_offset < highest_received) {
                    return semanticCloseError(.final_size_error, frame_type_value, "final size");
                }
            }

            if (streamFrameHasConflictingOverlap(stream_state.*, stream_frame.offset, stream_frame.data) catch return null) {
                return semanticCloseError(.protocol_violation, frame_type_value, "stream data");
            }
        }

        const new_frame_data_len = if (existing_state) |stream_state|
            self.collectNewRecvStreamDataSegments(stream_state.*, stream_frame.offset, stream_frame.data, null) catch return null
        else
            stream_frame.data.len;
        const next_recv_total = streamEndOffset(self.recv_data_bytes, new_frame_data_len) orelse return null;
        if (next_recv_total > self.recv_max_data) {
            return semanticCloseError(.flow_control_error, frame_type_value, "flow control");
        }
        return null;
    }

    fn classifyResetStreamFrameProcessingCloseError(
        self: *Connection,
        reset: frame.ResetStreamFrame,
        frame_type_value: u64,
    ) ?FramePayloadCloseError {
        if (self.classifyReceiveStreamIdCloseError(reset.stream_id, frame_type_value)) |close| return close;

        const existing_state = self.findRecvStream(reset.stream_id);
        const stream_receive_limit = if (existing_state) |stream_state| stream_state.max_data else self.recv_max_stream_data;
        if (reset.final_size > stream_receive_limit) {
            return semanticCloseError(.flow_control_error, frame_type_value, "flow control");
        }

        if (existing_state) |stream_state| {
            const highest_received = highestReceivedStreamEndOffset(stream_state.*) catch return null;
            if (reset.final_size < highest_received) {
                return semanticCloseError(.final_size_error, frame_type_value, "final size");
            }
            if (stream_state.final_size) |final_size| {
                if (final_size != reset.final_size) {
                    return semanticCloseError(.final_size_error, frame_type_value, "final size");
                }
                if (stream_state.reset_error_code != null) return null;

                const final_size_usize = std.math.cast(usize, final_size) orelse return null;
                if (stream_state.data.items.len >= final_size_usize) return null;

                const received_size = receivedStreamByteCount(stream_state.*) catch return null;
                if (reset.final_size < received_size) {
                    return semanticCloseError(.final_size_error, frame_type_value, "final size");
                }
                const delta = reset.final_size - received_size;
                const next_recv_total = std.math.add(u64, self.recv_data_bytes, delta) catch return null;
                if (next_recv_total > self.recv_max_data) {
                    return semanticCloseError(.flow_control_error, frame_type_value, "flow control");
                }
                return null;
            }

            const received_size = receivedStreamByteCount(stream_state.*) catch return null;
            if (reset.final_size < received_size) {
                return semanticCloseError(.final_size_error, frame_type_value, "final size");
            }
            const delta = reset.final_size - received_size;
            const next_recv_total = std.math.add(u64, self.recv_data_bytes, delta) catch return null;
            if (next_recv_total > self.recv_max_data) {
                return semanticCloseError(.flow_control_error, frame_type_value, "flow control");
            }
            return null;
        }

        const next_recv_total = std.math.add(u64, self.recv_data_bytes, reset.final_size) catch return null;
        if (next_recv_total > self.recv_max_data) {
            return semanticCloseError(.flow_control_error, frame_type_value, "flow control");
        }
        return null;
    }

    fn classifyCryptoFrameProcessingCloseError(
        self: *Connection,
        packet_type: FramePacketType,
        crypto: frame.CryptoFrame,
        frame_type_value: u64,
    ) ?FramePayloadCloseError {
        const end_offset = streamEndOffset(crypto.offset, crypto.data.len) orelse return null;
        if (end_offset > self.config.max_crypto_buffer_size) {
            return semanticCloseError(.crypto_buffer_exceeded, frame_type_value, "crypto buffer");
        }
        const packet_space = self.packetNumberSpace(packetNumberSpaceForFramePacketType(packet_type));
        if (cryptoFrameHasConflictingOverlap(packet_space, crypto.offset, crypto.data) catch return null) {
            return semanticCloseError(.protocol_violation, frame_type_value, "crypto data");
        }
        return null;
    }

    fn classifyAckFrameProcessingCloseError(
        self: *Connection,
        packet_type: FramePacketType,
        ack: frame.AckFrame,
        frame_type_value: u64,
    ) ?FramePayloadCloseError {
        const packet_space = self.packetNumberSpace(packetNumberSpaceForFramePacketType(packet_type));
        if (packet_space.discarded.*) return null;
        if (ack.largest_acknowledged >= packet_space.next_packet_number.*) {
            return semanticCloseError(.protocol_violation, frame_type_value, "ack");
        }
        return null;
    }

    fn classifyNewConnectionIdFrameProcessingCloseError(
        self: *Connection,
        new_connection_id: frame.NewConnectionIdFrame,
        frame_type_value: u64,
    ) ?FramePayloadCloseError {
        if (self.sendsZeroLengthDestinationConnectionId()) {
            return semanticCloseError(.protocol_violation, frame_type_value, "connection id zero");
        }
        if (self.findActiveConnectionId(new_connection_id.sequence_number)) |existing| {
            if (!std.mem.eql(u8, existing.connection_id, new_connection_id.connection_id)) {
                return semanticCloseError(.protocol_violation, frame_type_value, "connection id sequence");
            }
            if (!statelessResetTokensEqual(existing.stateless_reset_token, new_connection_id.stateless_reset_token)) {
                return semanticCloseError(.protocol_violation, frame_type_value, "reset token mismatch");
            }
            return null;
        }
        if (self.findActiveConnectionIdByValue(new_connection_id.connection_id)) |_| {
            return semanticCloseError(.protocol_violation, frame_type_value, "connection id reuse");
        }
        if (self.activeStatelessResetTokenValueExists(new_connection_id.stateless_reset_token)) {
            return semanticCloseError(.protocol_violation, frame_type_value, "reset token reuse");
        }
        const active_after_retire = self.activeConnectionIdCountAfterRetirePriorTo(new_connection_id.retire_prior_to);
        if (active_after_retire >= self.config.active_connection_id_limit) {
            return semanticCloseError(.connection_id_limit_error, frame_type_value, "connection id limit");
        }
        return null;
    }

    fn classifyRetireConnectionIdFrameProcessingCloseError(
        self: *Connection,
        retire_connection_id: frame.RetireConnectionIdFrame,
        frame_type_value: u64,
    ) ?FramePayloadCloseError {
        if (self.hasZeroLengthLocalInitialSourceConnectionId()) {
            return semanticCloseError(.protocol_violation, frame_type_value, "connection id zero");
        }
        const local_id = self.findLocalConnectionId(retire_connection_id.sequence_number) orelse {
            return semanticCloseError(.protocol_violation, frame_type_value, "retire connection id");
        };
        if (!local_id.sent) {
            return semanticCloseError(.protocol_violation, frame_type_value, "retire connection id");
        }
        return null;
    }

    fn classifyFrameProcessingCloseError(
        self: *Connection,
        packet_type: FramePacketType,
        datagram: []const u8,
    ) Error!?FramePayloadCloseError {
        var offset: usize = 0;
        while (offset < datagram.len) {
            const frame_type_value = rawFrameTypeValue(datagram[offset..]);
            var decoded = frame.decodeFrameSlice(datagram[offset..], self.allocator) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return null,
            };

            if (decoded.len == 0) {
                frame.deinitFrame(&decoded.frame, self.allocator);
                return null;
            }
            if (framePacketTypeErrorCode(decoded.frame, packet_type) != null) {
                frame.deinitFrame(&decoded.frame, self.allocator);
                return null;
            }

            const close = switch (decoded.frame) {
                .ack => |ack| self.classifyAckFrameProcessingCloseError(packet_type, ack, frame_type_value),
                .ack_ecn => |ack_ecn| self.classifyAckFrameProcessingCloseError(packet_type, ack_ecn.ack, frame_type_value),
                .stream => |stream_frame| self.classifyStreamFrameProcessingCloseError(stream_frame, frame_type_value),
                .crypto => |crypto| self.classifyCryptoFrameProcessingCloseError(packet_type, crypto, frame_type_value),
                .reset_stream => |reset| self.classifyResetStreamFrameProcessingCloseError(reset, frame_type_value),
                .stream_data_blocked => |blocked| self.classifyReceiveStreamIdCloseError(blocked.stream_id, frame_type_value),
                .max_stream_data => |max_stream_data| self.classifySendControlStreamIdCloseError(max_stream_data.stream_id, frame_type_value),
                .max_streams_bidi => |max_streams| if (max_streams.maximum_streams > max_stream_count)
                    semanticCloseError(.frame_encoding_error, frame_type_value, "frame encoding")
                else
                    null,
                .max_streams_uni => |max_streams| if (max_streams.maximum_streams > max_stream_count)
                    semanticCloseError(.frame_encoding_error, frame_type_value, "frame encoding")
                else
                    null,
                .stop_sending => |stop_sending| self.classifySendControlStreamIdCloseError(stop_sending.stream_id, frame_type_value),
                .new_token => if (self.side == .server)
                    semanticCloseError(.protocol_violation, frame_type_value, "new token")
                else
                    null,
                .new_connection_id => |new_connection_id| self.classifyNewConnectionIdFrameProcessingCloseError(new_connection_id, frame_type_value),
                .retire_connection_id => |retire_connection_id| self.classifyRetireConnectionIdFrameProcessingCloseError(retire_connection_id, frame_type_value),
                .path_response => |path_response| if (self.pathResponseChallengeIndex(path_response.data) == null)
                    semanticCloseError(.protocol_violation, frame_type_value, "path response")
                else
                    null,
                .handshake_done => if (self.side == .server)
                    semanticCloseError(.protocol_violation, frame_type_value, "handshake done")
                else
                    null,
                else => null,
            };
            const decoded_len = decoded.len;
            frame.deinitFrame(&decoded.frame, self.allocator);
            if (close) |classified| return classified;
            offset += decoded_len;
        }
        return null;
    }

    /// Process one frame-payload datagram and queue CONNECTION_CLOSE on classified peer errors.
    ///
    /// The input and success output match `processDatagramForPacketType()`. On
    /// malformed/unknown frame payloads, frames that are invalid for the
    /// selected packet type, or classified semantic frame-processing failures,
    /// this wrapper queues a transport CONNECTION_CLOSE with the RFC 9000 close
    /// code before returning `InvalidPacket`. Existing callers that need pure
    /// rollback behavior can continue using `processDatagramForPacketType()`.
    pub fn processDatagramForPacketTypeOrClose(
        self: *Connection,
        packet_type: FramePacketType,
        now_nanos: i64,
        datagram: []const u8,
    ) Error!void {
        if (self.isClosingOrClosed() or datagram.len > self.config.max_datagram_size) {
            return self.processDatagramForPacketType(packet_type, now_nanos, datagram);
        }

        if (try classifyFramePayloadCloseError(packet_type, datagram, self.allocator)) |close| {
            try self.closeConnection(
                transport_error.codeValue(close.code),
                close.frame_type,
                close.reason_phrase,
            );
            return error.InvalidPacket;
        }

        self.processDatagramForPacketType(packet_type, now_nanos, datagram) catch |err| {
            switch (err) {
                error.InvalidPacket, error.InvalidStream => {
                    if (try self.classifyFrameProcessingCloseError(packet_type, datagram)) |close| {
                        try self.closeConnection(
                            transport_error.codeValue(close.code),
                            close.frame_type,
                            close.reason_phrase,
                        );
                        return error.InvalidPacket;
                    }
                },
                else => {},
            }
            return err;
        };
    }

    fn processDatagramInSpaceWithPacketTypeMaybeClose(
        self: *Connection,
        space: PacketNumberSpace,
        packet_type: FramePacketType,
        now_nanos: i64,
        datagram: []const u8,
        close_on_frame_payload_error: bool,
        received_packet_number: ?u64,
    ) Error!void {
        if (close_on_frame_payload_error) {
            if (try classifyFramePayloadCloseError(packet_type, datagram, self.allocator)) |close| {
                try self.closeConnection(
                    transport_error.codeValue(close.code),
                    close.frame_type,
                    close.reason_phrase,
                );
                return error.InvalidPacket;
            }

            self.processFramesInSpaceNoSnapshot(space, packet_type, now_nanos, datagram, received_packet_number) catch |err| {
                switch (err) {
                    error.InvalidPacket, error.InvalidStream => {
                        if (try self.classifyFrameProcessingCloseError(packet_type, datagram)) |close| {
                            try self.closeConnection(
                                transport_error.codeValue(close.code),
                                close.frame_type,
                                close.reason_phrase,
                            );
                            return error.InvalidPacket;
                        }
                    },
                    else => {},
                }
                return err;
            };
            return;
        }
        return self.processFramesInSpaceNoSnapshot(space, packet_type, now_nanos, datagram, received_packet_number);
    }

    /// Process decoded frames without transactional snapshot/rollback.
    ///
    /// Used by the close-on-error path where frame errors close the connection
    /// instead of rolling back state. Avoids O(n) sent_packets cloning per
    /// inbound datagram, eliminating the O(n²) throughput bottleneck.
    fn processFramesInSpaceNoSnapshot(
        self: *Connection,
        space: PacketNumberSpace,
        packet_type: FramePacketType,
        now_nanos: i64,
        datagram: []const u8,
        received_packet_number: ?u64,
    ) Error!void {
        if (!try self.prepareInboundDatagramProcessing(now_nanos)) return;
        if (datagram.len == 0 or datagram.len > self.config.max_datagram_size) return error.InvalidPacket;
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;

        var ack_eliciting = false;
        var received_handshake_done = false;
        var offset: usize = 0;
        while (offset < datagram.len) {
            // Borrow STREAM/CRYPTO payloads from the packet plaintext instead of
            // copying them; every handler copies into its own storage before the
            // plaintext is freed, so the borrow is never retained past this loop.
            var decoded = frame.decodeFrameSliceBorrowing(datagram[offset..], self.allocator) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidPacket,
            };
            defer frame.deinitFrameBorrowing(&decoded.frame, self.allocator);

            if (decoded.len == 0) return error.InvalidPacket;
            if (!frameAllowedInFramePacketType(decoded.frame, packet_type)) return error.InvalidPacket;

            if (frameIsAckEliciting(decoded.frame)) {
                ack_eliciting = true;
            }

            switch (decoded.frame) {
                .ack => |ack| try self.receiveAckFrame(space, now_nanos, ack, null),
                .ack_ecn => |ack_ecn| try self.receiveAckFrame(space, now_nanos, ack_ecn.ack, ack_ecn.ecn_counts),
                .max_data => |max_data| self.receiveMaxDataFrame(max_data),
                .max_stream_data => |max_stream_data| try self.receiveMaxStreamDataFrame(max_stream_data),
                .max_streams_bidi => |max_streams| try self.receiveMaxStreamsBidiFrame(max_streams),
                .max_streams_uni => |max_streams| try self.receiveMaxStreamsUniFrame(max_streams),
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
                .handshake_done => {
                    try self.receiveHandshakeDoneFrame();
                    received_handshake_done = true;
                },
                .connection_close => |connection_close| try self.receiveConnectionCloseFrame(now_nanos, connection_close),
                .application_close => |application_close| try self.receiveApplicationCloseFrame(now_nanos, application_close),
                .datagram => |dg| {
                    if (self.config.max_datagram_frame_size > 0) {
                        const owned = self.allocator.alloc(u8, dg.data.len) catch return error.OutOfMemory;
                        @memcpy(owned, dg.data);
                        self.received_datagrams.append(self.allocator, owned) catch {
                            self.allocator.free(owned);
                            return error.OutOfMemory;
                        };
                    }
                },
                else => {},
            }

            offset += decoded.len;
        }

        if (ack_eliciting and !self.closed) {
            try self.queueAckForReceivedPacket(space, received_packet_number);
        }
        self.markHandshakeSpaceUsed(space);
        try self.drainPendingRecvStreams();
        self.recordPacketActivity(now_nanos);
        self.maybeDiscardInitialAfterHandshakePacketReceived(space);
        if (received_handshake_done and !self.isClosingOrClosed()) {
            try self.discardPacketNumberSpace(.handshake);
        }
    }
    /// Return the next frame-payload datagram for a selected packet number space.
    ///
    /// Initial and Handshake spaces currently emit ACK-only, PING, or CRYPTO payloads.
    /// Application space delegates to `pollTx()` and can emit the broader
    /// frame-payload skeleton used by the examples.
    pub fn pollTxInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        now_nanos: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        if (space == .application) return self.pollTx(now_nanos, out_buf);

        self.expireIdleState(now_nanos);
        self.expireCloseState(now_nanos);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;

        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;

        const ack_to_send = self.pendingAckFrame(space);
        if (packet_space.crypto_send_queue.items.len != 0) {
            return try self.pollCryptoFrame(space, ack_to_send, now_nanos, out_buf);
        }
        if (packet_space.pending_ping_count.* != 0) {
            return try self.pollPingFrameInSpace(space, ack_to_send, now_nanos, out_buf);
        }
        if (ack_to_send) |ack| {
            return try self.pollAckOnlyInSpace(space, ack, now_nanos, out_buf);
        }
        return null;
    }

    /// Return the next unencrypted packet payload to send, or null if idle.
    pub fn pollTx(
        self: *Connection,
        now_nanos: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        self.expireIdleState(now_nanos);
        self.expireCloseState(now_nanos);
        if (self.pending_close != null) return try self.pollCloseFrame(now_nanos, out_buf);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        try self.expirePathChallenges(now_nanos);

        const ack_to_send = self.pendingAckFrame(.application);
        if (self.pending_path_responses.items.len != 0) {
            return try self.pollPathResponse(ack_to_send, now_nanos, out_buf);
        }
        if (self.pending_reset_streams.items.len != 0) {
            return try self.pollResetStream(ack_to_send, now_nanos, out_buf);
        }
        self.dropObsoleteStopSendingFrames();
        if (self.pending_stop_sending.items.len != 0) {
            return try self.pollStopSending(ack_to_send, now_nanos, out_buf);
        }
        if (self.pending_retire_connection_ids.items.len != 0) {
            return try self.pollRetireConnectionId(ack_to_send, now_nanos, out_buf);
        }
        if (self.pending_handshake_done) {
            return try self.pollHandshakeDone(ack_to_send, now_nanos, out_buf);
        }
        if (self.pendingNewConnectionIdCount() != 0) {
            return try self.pollNewConnectionId(ack_to_send, now_nanos, out_buf);
        }
        if (self.pending_new_tokens.items.len != 0) {
            return try self.pollNewToken(ack_to_send, now_nanos, out_buf);
        }
        if (self.pending_path_challenges.items.len != 0) {
            return try self.pollPathChallenge(ack_to_send, now_nanos, out_buf);
        }
        self.dropObsoleteMaxFrames();
        if (self.pending_max_frames.items.len != 0) {
            return try self.pollMaxFrame(ack_to_send, now_nanos, out_buf);
        }
        self.dropObsoleteBlockedFrames();
        if (self.pending_blocked_frames.items.len != 0) {
            return try self.pollBlockedFrame(ack_to_send, now_nanos, out_buf);
        }
        if (self.crypto_send_queue.items.len != 0) {
            return try self.pollCryptoFrame(.application, ack_to_send, now_nanos, out_buf);
        }
        if (self.pending_ping_count != 0) {
            return try self.pollPingFrame(ack_to_send, now_nanos, out_buf);
        }
        if (self.pending_datagrams.items.len != 0) {
            return try self.pollDatagramFrame(ack_to_send, now_nanos, out_buf);
        }

        self.dropResetClosedStreamFrames();

        if (self.send_queue.items.len == 0) {
            if (ack_to_send) |ack| {
                return try self.pollAckOnly(ack, now_nanos, out_buf);
            }
            return null;
        }

        const pending = self.send_queue.items[0];
        const max_tx_datagram_size = self.maxTxDatagramSize();
        const ack_encoded_len = if (ack_to_send) |ack| try ackFrameWireLen(ack) else 0;
        var stream_budget = max_tx_datagram_size;
        var include_ack = false;
        if (ack_to_send) |ack| {
            stream_budget = std.math.sub(usize, max_tx_datagram_size, ack_encoded_len) catch {
                return try self.pollAckOnly(ack, now_nanos, out_buf);
            };
            if (try streamFrameWireLen(pending.stream_id, pending.offset, 0) > stream_budget) {
                return try self.pollAckOnly(ack, now_nanos, out_buf);
            }
        }

        const stream_data_len = try maxStreamFrameDataLen(
            pending.stream_id,
            pending.offset,
            pending.data.len,
            stream_budget,
        );
        const stream_encoded_len = try streamFrameWireLen(pending.stream_id, pending.offset, stream_data_len);
        const encoded_len = try addWireLen(if (ack_to_send == null) 0 else ack_encoded_len, stream_encoded_len);
        if (ack_to_send) |ack| {
            if (out_buf.len >= encoded_len and
                self.canSendAckElicitingInSpace(.application, encoded_len) and self.canSendToPeerAddress(encoded_len))
            {
                include_ack = true;
            } else {
                return try self.pollAckOnly(ack, now_nanos, out_buf);
            }
        }
        if (!self.canSendAckElicitingInSpace(.application, encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        const sent_stream_frame = try self.clonePendingStreamFrame(.{
            .stream_id = pending.stream_id,
            .offset = pending.offset,
            .fin = pending.fin and stream_data_len == pending.data.len,
            .data = pending.data[0..stream_data_len],
        });
        var sent_stream_frame_transferred = false;
        errdefer if (!sent_stream_frame_transferred) {
            self.allocator.free(sent_stream_frame.data);
        };
        const queued_stream_remainder: ?PendingStreamFrame = if (stream_data_len < pending.data.len) remainder: {
            const remainder_offset = streamEndOffset(pending.offset, stream_data_len) orelse return error.Internal;
            const remainder_data = self.allocator.dupe(u8, pending.data[stream_data_len..]) catch return error.OutOfMemory;
            break :remainder .{
                .stream_id = pending.stream_id,
                .offset = remainder_offset,
                .fin = pending.fin,
                .data = remainder_data,
            };
        } else null;
        errdefer if (queued_stream_remainder) |remainder| self.allocator.free(remainder.data);

        var appended_sent_packet = false;
        errdefer if (appended_sent_packet) {
            var removed_sent_packet = self.sent_packets.orderedRemove(self.sent_packets.items.len - 1);
            removed_sent_packet.deinit(self.allocator);
        };

        const packet_number = self.next_packet_number;
        self.sent_packets.append(self.allocator, .{
            .packet_number = packet_number,
            .sent_time_nanos = now_nanos,
            .bytes = encoded_len,
            .stream_frame = sent_stream_frame,
        }) catch return error.OutOfMemory;
        sent_stream_frame_transferred = true;
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
            .fin = pending.fin and stream_data_len == pending.data.len,
            .data = pending.data[0..stream_data_len],
        } }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const written = out.getWritten();
        std.debug.assert(written.len == encoded_len);

        const removed = self.send_queue.items[0];
        if (queued_stream_remainder) |remainder| {
            self.send_queue.items[0] = remainder;
        } else {
            _ = self.send_queue.orderedRemove(0);
        }
        self.allocator.free(removed.data);
        if (include_ack) self.pending_ack_largest = null;
        self.next_packet_number = std.math.add(u64, packet_number, 1) catch return error.Internal;
        self.recordAckElicitingSendInSpace(.application, written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_nanos);
        return written;
    }

    /// Queue a transport CONNECTION_CLOSE frame for the next `pollTx()` call.
    ///
    /// The reason phrase is copied into connection-owned memory. While queued,
    /// regular public send/receive APIs return `ConnectionClosed`; `pollTx()`
    /// remains available to emit the close frame and then mark the connection closed.
    pub fn closeConnection(
        self: *Connection,
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
        self.close_deadline_nanos = null;
        if (self.qlog_writer) |qlog| {
            qlog.emitConnectionState("closing", self.last_packet_activity_nanos orelse 0);
        }
    }

    /// Queue an application CONNECTION_CLOSE frame for the next `pollTx()` call.
    ///
    /// The reason phrase is copied into connection-owned memory. This closes the
    /// same public API surface as transport close; only the emitted frame type
    /// and error-code namespace differ.
    pub fn closeApplication(
        self: *Connection,
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
        self.close_deadline_nanos = null;
    }

    /// Open a locally initiated bidirectional stream and return its QUIC stream ID.
    pub fn openStream(self: *Connection) Error!u64 {
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
    pub fn openUniStream(self: *Connection) Error!u64 {
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
    pub fn sendCrypto(self: *Connection, data: []const u8) Error!void {
        try self.sendCryptoInSpace(.application, data);
    }

    /// Queue CRYPTO data in a selected packet number space.
    ///
    /// QUIC uses separate CRYPTO byte streams for each encryption level. This
    /// frame-payload hook lets tests and future TLS adapters exercise that
    /// separation before protected packet handling exists.
    pub fn sendCryptoInSpace(
        self: *Connection,
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
        self.markHandshakeSpaceUsed(space);
    }

    /// Queue data for a stream. The data is copied and emitted by `pollTx`.
    pub fn sendOnStream(
        self: *Connection,
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
            if (sendStreamClosed(state)) return error.StreamClosed;
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

        // Reserve protected short-packet overhead when splitting a STREAM write.
        const datagram_size = self.maxTxDatagramSize();
        const base_datagram_size: usize = if (datagram_size == 0) 1200 else datagram_size;
        const max_tx_datagram_size = if (base_datagram_size > 64) base_datagram_size - 64 else base_datagram_size;
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
        self: *Connection,
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
        self: *Connection,
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

        const stream_state = try self.appendRecvStreamState(stream_id);
        appended_recv_state = true;

        try self.queueStopSending(stream_state, application_error_code);
    }

    /// Queue one ack-eliciting PING frame for transmission by `pollTx`.
    ///
    /// The PING has no payload and does not consume stream or connection flow
    /// control credit. It is still congestion controlled once emitted.
    pub fn sendPing(self: *Connection) Error!void {
        try self.sendPingInSpace(.application);
    }

    /// Queue one PATH_CHALLENGE frame and track it until a matching PATH_RESPONSE arrives.
    pub fn sendPathChallenge(self: *Connection, data: [8]u8) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        self.pending_path_challenges.append(self.allocator, .{ .data = data }) catch return error.OutOfMemory;
    }

    /// Queue the server-only HANDSHAKE_DONE frame for Application/1-RTT transmission.
    ///
    /// This marks the modeled server handshake confirmed, discards Handshake
    /// packet-number-space state and installed Handshake keys, and queues at
    /// most one HANDSHAKE_DONE frame. The frame is consumed only after a
    /// successful `pollTx()` or `pollProtectedShortDatagram()` send commit.
    pub fn sendHandshakeDone(self: *Connection) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.side != .server) return error.InvalidPacket;

        self.handshake_state = .confirmed;
        self.handshake_confirmed = true;
        self.discardPacketNumberSpaceState(.handshake);
        if (self.pending_handshake_done or self.handshake_done_sent) return;
        self.pending_handshake_done = true;
    }

    /// Queue a server-issued NEW_TOKEN frame for Application/1-RTT transmission.
    ///
    /// The opaque token is copied into connection-owned memory. It is consumed
    /// only after a successful `pollTx()` or `pollProtectedShortDatagram()` send
    /// commit; anti-amplification or congestion blocking leaves it queued.
    pub fn issueNewToken(self: *Connection, token: []const u8) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.side != .server) return error.InvalidPacket;

        const encoded_len = try newTokenFrameWireLen(token);
        if (encoded_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const owned_token = self.allocator.alloc(u8, token.len) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned_token);
        @memcpy(owned_token, token);
        self.pending_new_tokens.append(self.allocator, owned_token) catch return error.OutOfMemory;
    }

    /// Return the newest stored NEW_TOKEN value, or null when no token is available.
    ///
    /// Tokens are opaque address-validation data owned by the connection. The
    /// returned slice remains valid until `deinit()` or until the connection
    /// state is otherwise mutated by future token-storage changes.
    pub fn latestNewToken(self: Connection) ?[]const u8 {
        if (self.stored_new_tokens.items.len == 0) return null;
        return self.stored_new_tokens.items[self.stored_new_tokens.items.len - 1];
    }

    /// Return the largest DATA_BLOCKED limit reported by the peer.
    pub fn peerDataBlockedLimit(self: Connection) ?u64 {
        return self.peer_data_blocked_limit;
    }

    /// Return the largest STREAM_DATA_BLOCKED limit reported by the peer for one stream.
    pub fn peerStreamDataBlockedLimit(self: Connection, stream_id: u64) ?u64 {
        for (self.peer_stream_data_blocked_limits.items) |blocked| {
            if (blocked.stream_id == stream_id) return blocked.maximum_stream_data;
        }
        return null;
    }

    /// Return the largest STREAMS_BLOCKED_BIDI limit reported by the peer.
    pub fn peerStreamsBlockedBidiLimit(self: Connection) ?u64 {
        return self.peer_streams_blocked_bidi_limit;
    }

    /// Return the largest STREAMS_BLOCKED_UNI limit reported by the peer.
    pub fn peerStreamsBlockedUniLimit(self: Connection) ?u64 {
        return self.peer_streams_blocked_uni_limit;
    }

    /// Read received CRYPTO bytes from the default Application-space byte stream.
    ///
    /// Returns null when no unread CRYPTO bytes are available. This wrapper
    /// keeps the original default Application-space behavior.
    pub fn recvCrypto(self: *Connection, buf: []u8) Error!?usize {
        return self.recvCryptoInSpace(.application, buf);
    }

    /// Read received CRYPTO bytes from a selected packet number space.
    ///
    /// Returns null when no unread bytes are available in that space. Initial,
    /// Handshake, and Application CRYPTO offsets are intentionally independent.
    pub fn recvCryptoInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        buf: []u8,
    ) Error!?usize {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;
        try self.drainPendingCryptoFrames(space);
        if (packet_space.crypto_read_offset.* >= packet_space.crypto_recv_buffer.items.len) return null;

        const available = packet_space.crypto_recv_buffer.items[packet_space.crypto_read_offset.*..];
        const n = @min(buf.len, available.len);
        @memcpy(buf[0..n], available[0..n]);
        packet_space.crypto_read_offset.* += n;
        return n;
    }

    /// Drive a pluggable TLS/crypto backend for one packet number space.
    ///
    /// This helper gives `backend` the local transport-parameter extension
    /// bytes when requested, delivers contiguous received CRYPTO bytes to
    /// `backend`, applies peer transport-parameter bytes returned by
    /// `backend`, queues backend-produced bytes through `sendCryptoInSpace()`,
    /// and marks the modeled handshake confirmed when the backend reports
    /// completion. If a Handshake-space drive confirms the handshake without
    /// queuing outbound CRYPTO, the Handshake packet number space and installed
    /// Handshake keys are discarded in the same call. `scratch` must be
    /// non-empty and is only used during this call.
    pub fn driveCryptoBackendInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        backend: CryptoBackend,
        scratch: []u8,
    ) Error!CryptoBackendProgress {
        return self.driveCryptoBackendInSpaceWithPeerParameterPolicy(space, backend, scratch, .strict);
    }

    /// Drive a pluggable TLS/crypto backend and queue CONNECTION_CLOSE on peer
    /// transport-parameter errors.
    ///
    /// This preserves the success behavior of `driveCryptoBackendInSpace()`,
    /// but malformed or semantically invalid peer transport-parameter
    /// extension bytes returned by `backend` are handled through
    /// `applyPeerTransportParameterBytesOrClose()`. Backend output is not pulled
    /// after such an error, so the close frame is the next observable send.
    pub fn driveCryptoBackendInSpaceOrClose(
        self: *Connection,
        space: PacketNumberSpace,
        backend: CryptoBackend,
        scratch: []u8,
    ) Error!CryptoBackendProgress {
        return self.driveCryptoBackendInSpaceWithPeerParameterPolicy(space, backend, scratch, .close_on_error);
    }

    /// Drive a crypto backend while accepting explicit compatible version negotiation.
    ///
    /// Peer transport parameters returned by `backend` are applied with
    /// `applyPeerTransportParameterBytesWithCompatibleVersion()`. This is the
    /// server-side backend bridge for RFC 9368 compatible Version Information;
    /// callers must pass every allowed directional first-flight conversion.
    pub fn driveCryptoBackendInSpaceWithCompatibleVersion(
        self: *Connection,
        space: PacketNumberSpace,
        backend: CryptoBackend,
        scratch: []u8,
        compatibilities: []const VersionCompatibility,
    ) Error!CryptoBackendProgress {
        return self.driveCryptoBackendInSpaceWithPeerParameterPolicy(space, backend, scratch, .{ .compatible = compatibilities });
    }

    /// Drive a compatible-version backend and queue CONNECTION_CLOSE on errors.
    ///
    /// Parsed RFC 9368 negotiation failures use `VERSION_NEGOTIATION_ERROR`.
    /// Backend output is not pulled after a peer transport-parameter error.
    pub fn driveCryptoBackendInSpaceWithCompatibleVersionOrClose(
        self: *Connection,
        space: PacketNumberSpace,
        backend: CryptoBackend,
        scratch: []u8,
        compatibilities: []const VersionCompatibility,
    ) Error!CryptoBackendProgress {
        return self.driveCryptoBackendInSpaceWithPeerParameterPolicy(space, backend, scratch, .{ .compatible_close_on_error = compatibilities });
    }

    /// Drive a pluggable TLS/crypto backend across an ordered set of packet
    /// number spaces in one call.
    ///
    /// A live TLS handshake produces CRYPTO output for more than one encryption
    /// level from a single inbound flight: consuming an Initial ClientHello can
    /// emit both Initial and Handshake CRYPTO. `driveCryptoBackendInSpace()`
    /// only pulls one space, so a socket loop had to call it once per level.
    /// This helper feeds inbound CRYPTO for each listed space in order, applies
    /// connection-level peer transport parameters and traffic secrets once, then
    /// pulls backend-produced CRYPTO for each listed space in order. `spaces`
    /// must be ordered from the lowest to the highest encryption level the
    /// caller wants serviced, and `scratch` must be non-empty.
    pub fn driveCryptoBackendAcrossSpaces(
        self: *Connection,
        spaces: []const PacketNumberSpace,
        backend: CryptoBackend,
        scratch: []u8,
    ) Error!CryptoBackendProgress {
        return self.driveCryptoBackendOverSpacesWithPeerParameterPolicy(spaces, backend, scratch, .strict);
    }

    /// Drive a backend across ordered packet number spaces and queue
    /// CONNECTION_CLOSE on peer transport-parameter errors.
    ///
    /// This preserves the success behavior of `driveCryptoBackendAcrossSpaces()`
    /// while routing malformed or semantically invalid peer transport-parameter
    /// extension bytes through `applyPeerTransportParameterBytesOrClose()`.
    pub fn driveCryptoBackendAcrossSpacesOrClose(
        self: *Connection,
        spaces: []const PacketNumberSpace,
        backend: CryptoBackend,
        scratch: []u8,
    ) Error!CryptoBackendProgress {
        return self.driveCryptoBackendOverSpacesWithPeerParameterPolicy(spaces, backend, scratch, .close_on_error);
    }

    /// Drive a backend across ordered packet number spaces while accepting
    /// explicit compatible version negotiation.
    ///
    /// This is the cross-space form of
    /// `driveCryptoBackendInSpaceWithCompatibleVersion()`. It preserves the
    /// same ordered-space backend input/output behavior as
    /// `driveCryptoBackendAcrossSpaces()` while applying peer Version
    /// Information with the caller-provided compatibility table.
    pub fn driveCryptoBackendAcrossSpacesWithCompatibleVersion(
        self: *Connection,
        spaces: []const PacketNumberSpace,
        backend: CryptoBackend,
        scratch: []u8,
        compatibilities: []const VersionCompatibility,
    ) Error!CryptoBackendProgress {
        return self.driveCryptoBackendOverSpacesWithPeerParameterPolicy(
            spaces,
            backend,
            scratch,
            .{ .compatible = compatibilities },
        );
    }

    /// Drive a compatible-version backend across ordered packet number spaces
    /// and queue CONNECTION_CLOSE on negotiation errors.
    ///
    /// This is the cross-space form of
    /// `driveCryptoBackendInSpaceWithCompatibleVersionOrClose()`. Parsed RFC
    /// 9368 negotiation failures use `VERSION_NEGOTIATION_ERROR`, and backend
    /// output is not pulled after a peer transport-parameter error.
    pub fn driveCryptoBackendAcrossSpacesWithCompatibleVersionOrClose(
        self: *Connection,
        spaces: []const PacketNumberSpace,
        backend: CryptoBackend,
        scratch: []u8,
        compatibilities: []const VersionCompatibility,
    ) Error!CryptoBackendProgress {
        return self.driveCryptoBackendOverSpacesWithPeerParameterPolicy(
            spaces,
            backend,
            scratch,
            .{ .compatible_close_on_error = compatibilities },
        );
    }

    fn driveCryptoBackendInSpaceWithPeerParameterPolicy(
        self: *Connection,
        space: PacketNumberSpace,
        backend: CryptoBackend,
        scratch: []u8,
        peer_transport_parameter_policy: PeerTransportParameterDrivePolicy,
    ) Error!CryptoBackendProgress {
        const spaces = [_]PacketNumberSpace{space};
        return self.driveCryptoBackendOverSpacesWithPeerParameterPolicy(
            &spaces,
            backend,
            scratch,
            peer_transport_parameter_policy,
        );
    }

    fn driveCryptoBackendOverSpacesWithPeerParameterPolicy(
        self: *Connection,
        spaces: []const PacketNumberSpace,
        backend: CryptoBackend,
        scratch: []u8,
        peer_transport_parameter_policy: PeerTransportParameterDrivePolicy,
    ) Error!CryptoBackendProgress {
        if (scratch.len == 0) return error.BufferTooSmall;
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        for (spaces) |space| {
            if (self.packetNumberSpace(space).discarded.*) return error.InvalidPacket;
        }

        var progress = CryptoBackendProgress{};

        if (backend.set_local_transport_parameters != null) {
            const local_transport_parameters = try self.encodeLocalTransportParameters(scratch);
            if (try backend.setLocalTransportParameters(local_transport_parameters)) {
                progress.local_transport_parameters_bytes = local_transport_parameters.len;
            }
        }

        for (spaces) |space| {
            while (true) {
                const packet_space = self.packetNumberSpace(space);
                const crypto_read_offset_snapshot = packet_space.crypto_read_offset.*;
                const n = (try self.recvCryptoInSpace(space, scratch)) orelse break;
                if (n == 0) return error.BufferTooSmall;
                backend.receive(backend.context, space, scratch[0..n]) catch |err| {
                    packet_space.crypto_read_offset.* = crypto_read_offset_snapshot;
                    if (err == error.CryptoError and cryptoBackendDrivePolicyClosesOnError(peer_transport_parameter_policy)) {
                        try self.closeConnection(
                            transport_error.cryptoErrorCode(80),
                            @backingInt(frame.FrameType.crypto),
                            "crypto error",
                        );
                        return error.InvalidPacket;
                    }
                    return err;
                };
                progress.inbound_chunks += 1;
                progress.inbound_bytes += n;
            }
        }

        if (try backend.pullPeerTransportParameters(scratch)) |peer_transport_parameters| {
            switch (peer_transport_parameter_policy) {
                .strict => try self.applyPeerTransportParameterBytes(peer_transport_parameters),
                .close_on_error => try self.applyPeerTransportParameterBytesOrClose(peer_transport_parameters),
                .compatible => |compatibilities| progress.peer_compatible_version_selected = try self.applyPeerTransportParameterBytesWithCompatibleVersion(
                    peer_transport_parameters,
                    compatibilities,
                ),
                .compatible_close_on_error => |compatibilities| progress.peer_compatible_version_selected = try self.applyPeerTransportParameterBytesWithCompatibleVersionOrClose(
                    peer_transport_parameters,
                    compatibilities,
                ),
            }
            progress.peer_transport_parameters_bytes = peer_transport_parameters.len;
            progress.peer_transport_parameters_applied = true;
        }

        if (try backend.pullHandshakeTrafficSecrets()) |secrets| {
            if (backend.negotiated_cipher_suite) |fn_ptr| {
                self.negotiated_cipher = switch (fn_ptr(backend.context)) {
                    0x1303 => .chacha20_poly1305,
                    else => .aes_128_gcm,
                };
            }
            try self.installHandshakeTrafficSecrets(secrets);
            progress.handshake_keys_installed = true;
        }

        if (try backend.pullZeroRttTrafficSecrets()) |secrets| {
            try self.installZeroRttTrafficSecrets(secrets);
            // Server-side application policy (RFC 9001 §8): when configured to
            // accept 0-RTT, accept installed peer receive keys automatically so
            // early data is delivered to streams and TLS can signal acceptance
            // in EncryptedExtensions. When disabled (the safe default), keys
            // stay installed but not accepted, so
            // `processProtectedZeroRttDatagramWithInstalledKeys` rejects
            // early-data packets and TLS omits the EncryptedExtensions
            // early_data acceptance signal. Clients only carry `local` 0-RTT
            // secrets and are unaffected by this gate.
            if (secrets.peer != null) {
                const accept_early_data = self.config.accept_zero_rtt;
                if (accept_early_data) try self.acceptZeroRtt();
                _ = try backend.setEarlyDataAccepted(accept_early_data);
            }
            progress.zero_rtt_keys_installed = true;
        }

        if (backend.earlyDataAccepted()) |accepted| {
            progress.zero_rtt_accepted = accepted;
            if (!accepted and self.side == .client and self.local_zero_rtt_keys != null) {
                self.local_zero_rtt_keys = null;
                progress.zero_rtt_keys_discarded = true;
            }
        }

        if (try backend.pullOneRttTrafficSecrets()) |secrets| {
            try self.installOneRttTrafficSecrets(secrets);
            progress.one_rtt_keys_installed = true;
        }

        var handshake_outbound_chunks: usize = 0;
        for (spaces) |space| {
            while (try backend.pull(backend.context, space, scratch)) |outbound| {
                if (outbound.len == 0) break;
                try self.sendCryptoInSpace(space, outbound);
                progress.outbound_chunks += 1;
                progress.outbound_bytes += outbound.len;
                if (space == .handshake) handshake_outbound_chunks += 1;
            }
        }

        const backend_confirmed = backend.isHandshakeConfirmed();
        if (backend_confirmed and !self.handshake_confirmed) {
            try self.confirmHandshake();
        }
        const handshake_no_output_pending = self.handshake_packet_space.crypto_send_queue.items.len == 0;
        if (backend_confirmed and handshake_outbound_chunks == 0 and handshake_no_output_pending) {
            self.discardPacketNumberSpaceState(.handshake);
            progress.handshake_space_discarded = true;
        }
        if (self.handshake_confirmed and backend.pull_negotiated_alpn != null) {
            if (try backend.pullNegotiatedAlpn(scratch)) |alpn| {
                if (alpn.len > 0) progress.application_protocol_negotiated = true;
            }
        }
        progress.handshake_confirmed = self.handshake_confirmed;
        return progress;
    }

    /// Read queued data for a stream. Returns null when no data is available,
    /// or `StreamClosed` when the peer reset the receive side.
    pub fn recvOnStream(
        self: *Connection,
        stream_id: u64,
        buf: []u8,
    ) Error!?usize {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (stream_id > max_quic_varint) return error.InvalidStream;
        if (!isBidirectionalStream(stream_id) and isLocalStreamInitiator(self.side, stream_id)) {
            return error.InvalidStream;
        }

        const stream_state = self.findRecvStream(stream_id) orelse return null;
        if (stream_state.reset_error_code != null) {
            // Partial delivery: if enabled and buffered data remains, deliver it first.
            if (self.config.enable_reset_partial_delivery and
                stream_state.read_offset < stream_state.data.items.len)
            {
                const available = stream_state.data.items[stream_state.read_offset..];
                const n = @min(buf.len, available.len);
                try self.queueReceiveFlowControlCredit(stream_state, n);
                @memcpy(buf[0..n], available[0..n]);
                stream_state.read_offset += n;
                return n;
            }
            try self.queueClosedReceiveStreamCountCredit(stream_state);
            stream_state.reset_read_observed = true;
            return error.StreamClosed;
        }
        if (stream_state.read_offset >= stream_state.data.items.len) {
            try self.queueReceiveFlowControlCredit(stream_state, 0);
            markReceiveDataReadIfComplete(stream_state);
            return null;
        }

        const available = stream_state.data.items[stream_state.read_offset..];
        const n = @min(buf.len, available.len);
        try self.queueReceiveFlowControlCredit(stream_state, n);
        @memcpy(buf[0..n], available[0..n]);
        stream_state.read_offset += n;
        markReceiveDataReadIfComplete(stream_state);
        return n;
    }

    /// Queue an unreliable DATAGRAM frame for sending (RFC 9221).
    ///
    /// The payload is copied into connection-owned memory. Returns
    /// error.InvalidPacket if the peer did not advertise
    /// max_datagram_frame_size or the payload exceeds the advertised limit.
    pub fn sendDatagram(self: *Connection, data: []const u8) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.config.max_datagram_frame_size == 0) return error.InvalidPacket;
        if (data.len > self.config.max_datagram_frame_size) return error.InvalidPacket;
        const owned = self.allocator.alloc(u8, data.len) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned);
        @memcpy(owned, data);
        self.pending_datagrams.append(self.allocator, owned) catch {
            self.allocator.free(owned);
            return error.OutOfMemory;
        };
    }

    /// Read one received DATAGRAM frame payload (RFC 9221).
    ///
    /// Returns null if no datagrams are queued. The payload is copied into
    /// the caller buffer; the internal buffer is freed.
    pub fn recvDatagram(self: *Connection, buf: []u8) Error!?usize {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.received_datagrams.items.len == 0) return null;
        const datagram = self.received_datagrams.orderedRemove(0);
        defer self.allocator.free(datagram);
        const n = @min(buf.len, datagram.len);
        @memcpy(buf[0..n], datagram[0..n]);
        return n;
    }

    /// Return the count of queued outgoing DATAGRAM frames.
    pub fn pendingDatagramCount(self: Connection) usize {
        return self.pending_datagrams.items.len;
    }

    /// Return the count of queued incoming DATAGRAM frames.
    pub fn receivedDatagramCount(self: Connection) usize {
        return self.received_datagrams.items.len;
    }

    /// Return the final size learned from a STREAM FIN or RESET_STREAM.
    ///
    /// Null means the receive side has not observed a final size yet. Locally
    /// initiated unidirectional stream IDs are invalid on the receive API.
    pub fn recvStreamFinalSize(self: Connection, stream_id: u64) Error!?u64 {
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
    pub fn recvStreamFinished(self: Connection, stream_id: u64) Error!bool {
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

    pub fn findSendStream(self: *Connection, stream_id: u64) ?*SendStreamState {
        for (self.send_streams.items) |*stream| {
            if (stream.stream_id == stream_id) return stream;
        }
        return null;
    }

    pub fn findRecvStream(self: *Connection, stream_id: u64) ?*RecvStreamState {
        for (self.recv_streams.items) |*stream| {
            if (stream.stream_id == stream_id) return stream;
        }
        return null;
    }

    fn appendRecvStreamState(self: *Connection, stream_id: u64) Error!*RecvStreamState {
        self.recv_streams.append(self.allocator, .{
            .stream_id = stream_id,
            .max_data = self.recv_max_stream_data,
        }) catch return error.OutOfMemory;
        return &self.recv_streams.items[self.recv_streams.items.len - 1];
    }

    fn ensureRecvStreamState(self: *Connection, stream_id: u64) Error!*RecvStreamState {
        if (self.findRecvStream(stream_id)) |stream_state| return stream_state;

        var next_stream_id = stream_id & 0x03;
        while (true) {
            if (self.findRecvStream(next_stream_id) == null) {
                _ = try self.appendRecvStreamState(next_stream_id);
            }
            if (next_stream_id == stream_id) break;
            next_stream_id = std.math.add(u64, next_stream_id, 4) catch return error.InvalidStream;
        }

        return self.findRecvStream(stream_id) orelse error.Internal;
    }

    fn queueStreamFrame(
        self: *Connection,
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
        self: *Connection,
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

    pub fn queueDataBlockedFrame(self: *Connection, maximum_data: u64) Error!void {
        for (self.pending_blocked_frames.items) |pending| {
            switch (pending) {
                .data => |data| if (data.maximum_data == maximum_data) return,
                else => {},
            }
        }
        self.pending_blocked_frames.append(self.allocator, .{ .data = .{ .maximum_data = maximum_data } }) catch return error.OutOfMemory;
    }

    fn queueStreamDataBlockedFrame(self: *Connection, stream_id: u64, maximum_stream_data: u64) Error!void {
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

    fn queueStreamsBlockedBidiFrame(self: *Connection, maximum_streams: u64) Error!void {
        for (self.pending_blocked_frames.items) |pending| {
            switch (pending) {
                .streams_bidi => |streams| if (streams.maximum_streams == maximum_streams) return,
                else => {},
            }
        }
        self.pending_blocked_frames.append(self.allocator, .{ .streams_bidi = .{ .maximum_streams = maximum_streams } }) catch return error.OutOfMemory;
    }

    fn queueStreamsBlockedUniFrame(self: *Connection, maximum_streams: u64) Error!void {
        for (self.pending_blocked_frames.items) |pending| {
            switch (pending) {
                .streams_uni => |streams| if (streams.maximum_streams == maximum_streams) return,
                else => {},
            }
        }
        self.pending_blocked_frames.append(self.allocator, .{ .streams_uni = .{ .maximum_streams = maximum_streams } }) catch return error.OutOfMemory;
    }

    pub fn queueMaxDataFrame(self: *Connection, maximum_data: u64) Error!void {
        for (self.pending_max_frames.items) |pending| {
            switch (pending) {
                .data => |data| if (data.maximum_data == maximum_data) return,
                else => {},
            }
        }
        self.pending_max_frames.append(self.allocator, .{ .data = .{ .maximum_data = maximum_data } }) catch return error.OutOfMemory;
    }

    fn queueMaxStreamDataFrame(
        self: *Connection,
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

    fn queueMaxStreamsBidiFrame(self: *Connection, maximum_streams: u64) Error!void {
        if (maximum_streams > max_stream_count) return error.InvalidStream;
        for (self.pending_max_frames.items) |pending| {
            switch (pending) {
                .streams_bidi => |streams| if (streams.maximum_streams == maximum_streams) return,
                else => {},
            }
        }
        self.pending_max_frames.append(self.allocator, .{ .streams_bidi = .{ .maximum_streams = maximum_streams } }) catch return error.OutOfMemory;
    }

    fn queueMaxStreamsUniFrame(self: *Connection, maximum_streams: u64) Error!void {
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
        self: *Connection,
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
        try self.queueClosedReceiveStreamCountCredit(stream_state);
    }

    fn queueClosedReceiveStreamCountCredit(
        self: *Connection,
        stream_state: *RecvStreamState,
    ) Error!void {
        if (stream_state.stream_count_credit_released) return;
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

    fn nextReceiveConnectionDataLimit(self: Connection, consumed: u64) Error!u64 {
        var next_limit = std.math.add(u64, self.recv_max_data, consumed) catch return error.Internal;
        if (self.config.receive_connection_window) |window| {
            const target_limit = std.math.add(u64, self.recv_data_bytes, window) catch return error.Internal;
            next_limit = @max(next_limit, target_limit);
        }
        if (next_limit > max_quic_varint) return error.Internal;
        return next_limit;
    }

    fn nextReceiveStreamDataLimit(self: Connection, stream_state: RecvStreamState, consumed: u64) Error!u64 {
        var next_limit = std.math.add(u64, stream_state.max_data, consumed) catch return error.Internal;
        if (self.config.receive_stream_window) |window| {
            const highest_received = try highestReceivedStreamEndOffset(stream_state);
            const target_limit = std.math.add(u64, highest_received, window) catch return error.Internal;
            next_limit = @max(next_limit, target_limit);
        }
        if (next_limit > max_quic_varint) return error.Internal;
        return next_limit;
    }

    fn nextReceiveLimitAfterPeerBlocked(
        current_limit: u64,
        reported_limit: u64,
        maybe_window: ?u64,
    ) ?u64 {
        const window = maybe_window orelse return null;
        const capped_reported = @min(reported_limit, max_quic_varint);
        if (window == 0 or capped_reported < current_limit) return null;
        const capped_window = @min(window, max_quic_varint - capped_reported);
        const target_limit = capped_reported + capped_window;
        if (target_limit <= current_limit) return null;
        return target_limit;
    }

    fn nextReceiveStreamCountLimitAfterPeerBlocked(
        current_limit: u64,
        reported_limit: u64,
        maybe_window: ?u64,
    ) ?u64 {
        const window = maybe_window orelse return null;
        const capped_reported = @min(reported_limit, max_stream_count);
        if (window == 0 or capped_reported < current_limit) return null;
        const capped_window = @min(window, max_stream_count - capped_reported);
        const target_limit = capped_reported + capped_window;
        if (target_limit <= current_limit) return null;
        return target_limit;
    }

    fn queueReceiveFlowControlCredit(
        self: *Connection,
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
        const next_connection_limit = try self.nextReceiveConnectionDataLimit(consumed);
        const next_stream_limit = try self.nextReceiveStreamDataLimit(stream_state.*, consumed);

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
        self: *Connection,
        queue: *std.ArrayList(PendingCryptoFrame),
        original_len: usize,
    ) void {
        self.rollbackCryptoFrameQueue(queue, original_len);
    }

    fn rollbackCryptoFrameQueue(
        self: *Connection,
        queue: *std.ArrayList(PendingCryptoFrame),
        original_len: usize,
    ) void {
        while (queue.items.len > original_len) {
            const removed = queue.orderedRemove(queue.items.len - 1);
            self.allocator.free(removed.data);
        }
    }
    fn rollbackSendQueue(self: *Connection, original_len: usize) void {
        while (self.send_queue.items.len > original_len) {
            const removed = self.send_queue.orderedRemove(self.send_queue.items.len - 1);
            self.allocator.free(removed.data);
        }
    }
    fn clonePendingStreamFrame(self: *Connection, pending: PendingStreamFrame) Error!PendingStreamFrame {
        const data = self.allocator.dupe(u8, pending.data) catch return error.OutOfMemory;
        return .{
            .stream_id = pending.stream_id,
            .offset = pending.offset,
            .fin = pending.fin,
            .data = data,
        };
    }
    fn clonePendingCryptoFrame(self: *Connection, pending: PendingCryptoFrame) Error!PendingCryptoFrame {
        const data = self.allocator.dupe(u8, pending.data) catch return error.OutOfMemory;
        return .{
            .offset = pending.offset,
            .data = data,
        };
    }
    fn cloneSentPacket(self: *Connection, sent_packet: SentPacket) Error!SentPacket {
        var cloned = sent_packet;
        cloned.stream_frame = null;
        cloned.crypto_frame = null;
        errdefer cloned.deinit(self.allocator);
        cloned.stream_frame = if (sent_packet.stream_frame) |pending|
            try self.clonePendingStreamFrame(pending)
        else
            null;
        cloned.crypto_frame = if (sent_packet.crypto_frame) |pending|
            try self.clonePendingCryptoFrame(pending)
        else
            null;
        return cloned;
    }

    fn streamDataBlockedFrameIsObsolete(self: *Connection, stream_data: frame.StreamDataBlockedFrame) bool {
        if (self.findSendStream(stream_data.stream_id)) |stream_state| {
            if (sendStreamClosed(stream_state)) return true;
            return stream_state.max_data > stream_data.maximum_stream_data;
        }
        return self.initialPeerStreamDataLimit(stream_data.stream_id) > stream_data.maximum_stream_data;
    }

    fn blockedFrameIsObsolete(self: *Connection, blocked_frame: PendingBlockedFrame) bool {
        return switch (blocked_frame) {
            .data => |data| self.peer_max_data > data.maximum_data,
            .stream_data => |stream_data| self.streamDataBlockedFrameIsObsolete(stream_data),
            .streams_bidi => |streams| self.peer_max_streams_bidi > streams.maximum_streams,
            .streams_uni => |streams| self.peer_max_streams_uni > streams.maximum_streams,
        };
    }

    fn dropObsoleteBlockedFrames(self: *Connection) void {
        var i: usize = 0;
        while (i < self.pending_blocked_frames.items.len) {
            if (self.blockedFrameIsObsolete(self.pending_blocked_frames.items[i])) {
                _ = self.pending_blocked_frames.orderedRemove(i);
                continue;
            }
            i += 1;
        }
    }

    fn maxStreamDataFrameIsObsolete(self: *Connection, stream_data: frame.MaxStreamDataFrame) bool {
        const stream_state = self.findRecvStream(stream_data.stream_id) orelse {
            return self.recv_max_stream_data > stream_data.maximum_stream_data;
        };
        if (stream_state.final_size != null or stream_state.reset_error_code != null) return true;
        return stream_state.max_data > stream_data.maximum_stream_data;
    }

    fn maxFrameIsObsolete(self: *Connection, max_frame: PendingMaxFrame) bool {
        return switch (max_frame) {
            .data => |data| self.recv_max_data > data.maximum_data,
            .stream_data => |stream_data| self.maxStreamDataFrameIsObsolete(stream_data),
            .streams_bidi => |streams| self.recv_max_streams_bidi > streams.maximum_streams,
            .streams_uni => |streams| self.recv_max_streams_uni > streams.maximum_streams,
        };
    }

    fn dropObsoleteMaxFrames(self: *Connection) void {
        var i: usize = 0;
        while (i < self.pending_max_frames.items.len) {
            if (self.maxFrameIsObsolete(self.pending_max_frames.items[i])) {
                _ = self.pending_max_frames.orderedRemove(i);
                continue;
            }
            i += 1;
        }
    }

    fn stopSendingFrameIsObsolete(self: *Connection, stop_sending: frame.StopSendingFrame) bool {
        const stream_state = self.findRecvStream(stop_sending.stream_id) orelse return true;
        if (stream_state.reset_error_code != null) return true;
        const final_size = stream_state.final_size orelse return false;
        const final_size_usize = std.math.cast(usize, final_size) orelse return false;
        return stream_state.data.items.len >= final_size_usize;
    }

    fn dropObsoleteStopSendingFrames(self: *Connection) void {
        var i: usize = 0;
        while (i < self.pending_stop_sending.items.len) {
            if (self.stopSendingFrameIsObsolete(self.pending_stop_sending.items[i])) {
                _ = self.pending_stop_sending.orderedRemove(i);
                continue;
            }
            i += 1;
        }
    }

    fn receiveAckFrame(
        self: *Connection,
        space: PacketNumberSpace,
        now_nanos: i64,
        ack: frame.AckFrame,
        ecn_counts: ?frame.EcnCounts,
    ) Error!void {
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;
        if (ack.largest_acknowledged >= packet_space.next_packet_number.*) return error.InvalidPacket;
        if (!ackFrameRangesAreValid(ack)) return error.InvalidPacket;

        var acked_bytes: usize = 0;
        var largest_acked_packet: ?SentPacket = null;
        var newly_acked_ect0: u64 = 0;
        var newly_acked_ect1: u64 = 0;
        var local_key_update_acked = false;
        const congestion_window_utilized = packet_space.recovery_state.isCongestionWindowUtilized();

        var i: usize = 0;
        while (i < packet_space.sent_packets.items.len) {
            if (!ackFrameContains(ack, packet_space.sent_packets.items[i].packet_number)) {
                i += 1;
                continue;
            }

            var removed = packet_space.sent_packets.orderedRemove(i);
            acked_bytes = std.math.add(usize, acked_bytes, removed.bytes) catch std.math.maxInt(usize);
            if (space == .application) {
                if (self.local_one_rtt_key_update_ack_threshold) |threshold| {
                    if (removed.packet_number >= threshold) {
                        local_key_update_acked = true;
                    }
                }
            }
            if (largest_acked_packet == null or removed.packet_number > largest_acked_packet.?.packet_number) {
                largest_acked_packet = .{
                    .packet_number = removed.packet_number,
                    .sent_time_nanos = removed.sent_time_nanos,
                    .bytes = removed.bytes,
                    .ecn_codepoint = removed.ecn_codepoint,
                };
            }
            switch (removed.ecn_codepoint) {
                .not_ect => {},
                .ect0 => newly_acked_ect0 += 1,
                .ect1 => newly_acked_ect1 += 1,
            }
            markSentPacketAckedOnStreams(self, removed);
            removed.deinit(self.allocator);
        }

        if (acked_bytes == 0) return;

        const ecn_result = self.validateEcnAck(
            packet_space,
            ack.largest_acknowledged,
            newly_acked_ect0,
            newly_acked_ect1,
            ecn_counts,
        );

        const latest_rtt_sample = if (largest_acked_packet != null and
            largest_acked_packet.?.packet_number == ack.largest_acknowledged)
            elapsed(largest_acked_packet.?.sent_time_nanos, now_nanos)
        else
            null;
        if (latest_rtt_sample) |rtt_sample| {
            _ = rtt_sample;
            self.rememberFirstRttSampleSentTime(largest_acked_packet.?.sent_time_nanos);
        }
        if (acked_bytes != 0) {
            if (packet_space.largest_acknowledged.*) |previous_largest| {
                packet_space.largest_acknowledged.* = @max(previous_largest, ack.largest_acknowledged);
            } else {
                packet_space.largest_acknowledged.* = ack.largest_acknowledged;
            }
        }

        const loss_result = try self.removeAckDrivenLosses(
            packet_space,
            packet_space.largest_acknowledged.* orelse ack.largest_acknowledged,
            latest_rtt_sample,
            now_nanos,
        );
        refreshSendDataAckedStates(self);
        var congestion_probe_needed = false;
        if (ecn_result.ce_congestion_event) {
            if (largest_acked_packet) |acked_packet| {
                congestion_probe_needed = packet_space.recovery_state.wouldStartCongestionRecovery(acked_packet.sent_time_nanos);
                packet_space.recovery_state.onCongestionEvent(acked_packet.sent_time_nanos, now_nanos);
            }
        }
        const persistent_congestion_established = loss_result.persistentCongestionEstablished(space, packet_space.recovery_state.*);
        if (loss_result.lost_bytes != 0) {
            congestion_probe_needed = congestion_probe_needed or
                packet_space.recovery_state.wouldStartCongestionRecovery(loss_result.largest_lost_sent_time_nanos.?);
            packet_space.recovery_state.onPacketLostWithNumber(
                loss_result.lost_bytes,
                loss_result.largest_lost_sent_time_nanos.?,
                now_nanos,
                loss_result.largest_lost_packet_number,
            );
            // A lost packet is requeued for retransmission, so count it here.
            packet_space.recovery_state.recordRetransmission();
        }
        if (congestion_probe_needed) {
            self.armCongestionProbeIfPendingData(space);
        }

        if (local_key_update_acked) {
            self.local_one_rtt_key_update_ack_threshold = null;
        }

        packet_space.recovery_state.notifyLargestAcked(ack.largest_acknowledged);
        const pto_backoff_before_ack = self.ptoBackoffSnapshot();
        if (latest_rtt_sample) |rtt_sample| {
            packet_space.recovery_state.onPacketAckedWithUtilization(
                acked_bytes,
                largest_acked_packet.?.sent_time_nanos,
                rtt_sample,
                self.ackDelayForRtt(space, ack.ack_delay),
                congestion_window_utilized,
            );
            self.syncRttEstimatesFromSpace(space);
        } else {
            packet_space.recovery_state.onPacketAckedWithoutRttSample(
                acked_bytes,
                largest_acked_packet.?.sent_time_nanos,
                congestion_window_utilized,
            );
        }
        if (self.ackShouldResetPtoBackoff(space)) {
            self.resetConnectionPtoBackoff();
        } else {
            self.restorePtoBackoffSnapshot(pto_backoff_before_ack);
        }
        if (persistent_congestion_established) {
            const pc_rtt_sample_ns = latest_rtt_sample;
            packet_space.recovery_state.onPersistentCongestionWithRttSample(pc_rtt_sample_ns);
            if (latest_rtt_sample != null) {
                self.syncRttEstimatesFromSpace(space);
            }
        }
        self.refreshAntiDeadlockPtoTimer(space, now_nanos);
    }

    fn validateEcnAck(
        self: *Connection,
        packet_space: PacketNumberSpaceView,
        largest_acknowledged: u64,
        newly_acked_ect0: u64,
        newly_acked_ect1: u64,
        ecn_counts: ?frame.EcnCounts,
    ) EcnAckValidationResult {
        _ = self;
        if (packet_space.ecn_validation_state.* == .failed) return .{};
        if (packet_space.ecn_largest_acknowledged.*) |previous_largest| {
            if (largest_acknowledged <= previous_largest) return .{};
        }

        const counts = ecn_counts orelse {
            if (newly_acked_ect0 != 0 or newly_acked_ect1 != 0) {
                packet_space.ecn_validation_state.* = .failed;
            }
            return .{};
        };

        if (counts.ect0_count > packet_space.ecn_sent_ect0.* or
            counts.ect1_count > packet_space.ecn_sent_ect1.* or
            counts.ecn_ce_count > saturatingAddU64(packet_space.ecn_sent_ect0.*, packet_space.ecn_sent_ect1.*))
        {
            packet_space.ecn_validation_state.* = .failed;
            return .{};
        }

        const previous = packet_space.ecn_counts.*;
        if (counts.ect0_count < previous.ect0_count or
            counts.ect1_count < previous.ect1_count or
            counts.ecn_ce_count < previous.ecn_ce_count)
        {
            packet_space.ecn_validation_state.* = .failed;
            return .{};
        }

        const ect0_increase = counts.ect0_count - previous.ect0_count;
        const ect1_increase = counts.ect1_count - previous.ect1_count;
        const ce_increase = counts.ecn_ce_count - previous.ecn_ce_count;
        if (saturatingAddU64(ect0_increase, ce_increase) < newly_acked_ect0 or
            saturatingAddU64(ect1_increase, ce_increase) < newly_acked_ect1)
        {
            packet_space.ecn_validation_state.* = .failed;
            return .{};
        }

        packet_space.ecn_counts.* = counts;
        packet_space.ecn_largest_acknowledged.* = largest_acknowledged;
        if (packet_space.ecn_validation_state.* == .capable or newly_acked_ect0 != 0 or newly_acked_ect1 != 0) {
            packet_space.ecn_validation_state.* = .capable;
        }
        return .{ .ce_congestion_event = ce_increase != 0 };
    }

    fn removeAckDrivenLosses(
        self: *Connection,
        packet_space: PacketNumberSpaceView,
        largest_acknowledged: u64,
        latest_rtt_sample_ns: ?u64,
        now_nanos: i64,
    ) Error!LossDetectionResult {
        const loss_delay_ns = recovery.timeThresholdLossDelayNs(
            (latest_rtt_sample_ns orelse 0),
            packet_space.recovery_state.smoothed_rtt_ns,
        );

        var retransmit_frames: std.ArrayList(PendingStreamFrame) = .empty;
        defer {
            deinitPendingStreamFrameSlice(self.allocator, retransmit_frames.items);
            retransmit_frames.deinit(self.allocator);
        }
        var retransmit_crypto_frames: std.ArrayList(PendingCryptoFrame) = .empty;
        defer {
            deinitPendingCryptoFrameSlice(self.allocator, retransmit_crypto_frames.items);
            retransmit_crypto_frames.deinit(self.allocator);
        }
        var retransmit_reset_stream_frames: std.ArrayList(frame.ResetStreamFrame) = .empty;
        defer retransmit_reset_stream_frames.deinit(self.allocator);
        var retransmit_stop_sending_frames: std.ArrayList(frame.StopSendingFrame) = .empty;
        defer retransmit_stop_sending_frames.deinit(self.allocator);

        var next_loss_deadline: ?i64 = null;
        for (packet_space.sent_packets.items) |sent_packet| {
            if (sent_packet.packet_number > largest_acknowledged) continue;
            const packet_threshold_lost = largest_acknowledged >=
                saturatingAddU64(sent_packet.packet_number, packet_threshold_loss_gap);
            const time_threshold_lost = sent_packet.sent_time_nanos + @as(i64, @intCast(loss_delay_ns)) <= now_nanos;
            if (!packet_threshold_lost and !time_threshold_lost) {
                const deadline = sent_packet.sent_time_nanos + @as(i64, @intCast(loss_delay_ns));
                next_loss_deadline = if (next_loss_deadline) |current|
                    @min(current, deadline)
                else
                    deadline;
                continue;
            }

            if (sent_packet.stream_frame) |pending| {
                if (self.findSendStream(pending.stream_id)) |stream_state| {
                    if (stream_state.reset_sent) continue;
                }

                const cloned = try self.clonePendingStreamFrame(pending);
                errdefer self.allocator.free(cloned.data);
                retransmit_frames.append(self.allocator, cloned) catch return error.OutOfMemory;
            }
            if (sent_packet.crypto_frame) |pending| {
                const cloned = try self.clonePendingCryptoFrame(pending);
                errdefer self.allocator.free(cloned.data);
                retransmit_crypto_frames.append(self.allocator, cloned) catch return error.OutOfMemory;
            }
            if (sent_packet.reset_stream_frame) |reset| {
                if (resetStreamFrameAlreadyAcked(self, reset)) continue;
                retransmit_reset_stream_frames.append(self.allocator, reset) catch return error.OutOfMemory;
            }
            if (sent_packet.stop_sending_frame) |stop_sending| {
                retransmit_stop_sending_frames.append(self.allocator, stop_sending) catch return error.OutOfMemory;
            }
        }

        self.send_queue.ensureUnusedCapacity(self.allocator, retransmit_frames.items.len) catch return error.OutOfMemory;
        packet_space.crypto_send_queue.ensureUnusedCapacity(self.allocator, retransmit_crypto_frames.items.len) catch return error.OutOfMemory;
        self.pending_reset_streams.ensureUnusedCapacity(self.allocator, retransmit_reset_stream_frames.items.len) catch return error.OutOfMemory;
        self.pending_stop_sending.ensureUnusedCapacity(self.allocator, retransmit_stop_sending_frames.items.len) catch return error.OutOfMemory;
        packet_space.loss_deadline_nanos.* = next_loss_deadline;
        for (retransmit_reset_stream_frames.items, 0..) |reset, i| {
            self.pending_reset_streams.insertAssumeCapacity(i, reset);
        }
        retransmit_reset_stream_frames.items.len = 0;
        for (retransmit_stop_sending_frames.items, 0..) |stop_sending, i| {
            self.pending_stop_sending.insertAssumeCapacity(i, stop_sending);
        }
        retransmit_stop_sending_frames.items.len = 0;
        for (retransmit_frames.items, 0..) |pending, i| {
            self.send_queue.insertAssumeCapacity(i, pending);
        }
        retransmit_frames.items.len = 0;
        for (retransmit_crypto_frames.items, 0..) |pending, i| {
            packet_space.crypto_send_queue.insertAssumeCapacity(i, pending);
        }
        retransmit_crypto_frames.items.len = 0;

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
            const time_threshold_lost = sent_packet.sent_time_nanos + @as(i64, @intCast(loss_delay_ns)) <= now_nanos;
            if (!packet_threshold_lost and !time_threshold_lost) {
                const deadline = sent_packet.sent_time_nanos + @as(i64, @intCast(loss_delay_ns));
                packet_space.loss_deadline_nanos.* = if (packet_space.loss_deadline_nanos.*) |current|
                    @min(current, deadline)
                else
                    deadline;
                i += 1;
                continue;
            }

            var removed = packet_space.sent_packets.orderedRemove(i);
            result.recordLostPacket(removed, packet_space.first_rtt_sample_sent_time_nanos.*);
            removed.deinit(self.allocator);
        }
        return result;
    }

    fn expireLossDetectionTimeouts(self: *Connection, now_nanos: i64) Error!void {
        try self.expireLossDetectionTimeoutInSpace(.initial, now_nanos);
        try self.expireLossDetectionTimeoutInSpace(.handshake, now_nanos);
        try self.expireLossDetectionTimeoutInSpace(.application, now_nanos);
    }

    fn expireLossDetectionTimeoutInSpace(self: *Connection, space: PacketNumberSpace, now_nanos: i64) Error!void {
        const packet_space = self.packetNumberSpace(space);
        const deadline = packet_space.loss_deadline_nanos.* orelse return;
        if (deadline > now_nanos) return;
        const largest_acknowledged = packet_space.largest_acknowledged.* orelse {
            packet_space.loss_deadline_nanos.* = null;
            return;
        };
        const loss_result = try self.removeAckDrivenLosses(packet_space, largest_acknowledged, null, now_nanos);
        if (loss_result.lost_bytes != 0) {
            const congestion_probe_needed =
                packet_space.recovery_state.wouldStartCongestionRecovery(loss_result.largest_lost_sent_time_nanos.?);
            packet_space.recovery_state.onPacketLostWithNumber(
                loss_result.lost_bytes,
                loss_result.largest_lost_sent_time_nanos.?,
                now_nanos,
                loss_result.largest_lost_packet_number,
            );
            if (congestion_probe_needed) {
                self.armCongestionProbeIfPendingData(space);
            }
            if (loss_result.persistentCongestionEstablished(space, packet_space.recovery_state.*)) {
                packet_space.recovery_state.onPersistentCongestion();
            }
        }
        self.refreshAntiDeadlockPtoTimer(space, now_nanos);
    }

    fn hasPendingAckElicitingDataInSpace(self: *Connection, space: PacketNumberSpace) bool {
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.crypto_send_queue.items.len != 0 or packet_space.pending_ping_count.* != 0) return true;
        if (space != .application) return false;

        if (self.pending_path_responses.items.len != 0 or
            self.pending_reset_streams.items.len != 0 or
            self.pending_retire_connection_ids.items.len != 0 or
            self.pending_handshake_done or
            self.pendingNewConnectionIdCount() != 0 or
            self.pending_new_tokens.items.len != 0 or
            self.pending_path_challenges.items.len != 0)
        {
            return true;
        }

        self.dropObsoleteStopSendingFrames();
        if (self.pending_stop_sending.items.len != 0) return true;
        self.dropObsoleteMaxFrames();
        if (self.pending_max_frames.items.len != 0) return true;
        self.dropObsoleteBlockedFrames();
        if (self.pending_blocked_frames.items.len != 0) return true;
        self.dropResetClosedStreamFrames();
        return self.send_queue.items.len != 0;
    }

    fn hasQueuedAckElicitingDataInSpace(self: *Connection, space: PacketNumberSpace) bool {
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.crypto_send_queue.items.len != 0 or packet_space.pending_ping_count.* != 0) return true;
        if (space != .application) return false;

        return self.pending_path_responses.items.len != 0 or
            self.pending_reset_streams.items.len != 0 or
            self.pending_retire_connection_ids.items.len != 0 or
            self.pending_handshake_done or
            self.pendingNewConnectionIdCount() != 0 or
            self.pending_new_tokens.items.len != 0 or
            self.pending_path_challenges.items.len != 0 or
            self.pending_stop_sending.items.len != 0 or
            self.pending_max_frames.items.len != 0 or
            self.pending_blocked_frames.items.len != 0 or
            self.send_queue.items.len != 0;
    }

    fn hasPendingPtoProbeDataInSpace(self: *Connection, space: PacketNumberSpace) bool {
        return self.hasPendingAckElicitingDataInSpace(space);
    }

    fn armCongestionProbeIfPendingData(self: *Connection, space: PacketNumberSpace) void {
        if (self.hasQueuedAckElicitingDataInSpace(space)) {
            self.armCongestionProbeInSpace(space);
        }
    }

    fn hasQueuedInitialOrHandshakeAckElicitingData(self: Connection, space: PacketNumberSpace) bool {
        return switch (space) {
            .initial => self.initial_packet_space.crypto_send_queue.items.len != 0 or self.initial_packet_space.pending_ping_count != 0,
            .handshake => self.handshake_packet_space.crypto_send_queue.items.len != 0 or self.handshake_packet_space.pending_ping_count != 0,
            .application => false,
        };
    }

    fn antiDeadlockPtoSpace(self: Connection) ?PacketNumberSpace {
        // Anti-deadlock PTO stays armed for a client until the handshake is
        // confirmed. Receiving an ACK validates the peer's address, but the
        // handshake can still stall on later lost server packets; disarming on
        // the first ACK leaves the client with no in-flight data and no timer
        // to drive a retransmit, deadlocking connect() when server packets are
        // lost. See RFC 9002 §6.2.2.1.
        if (self.side == .server) return null;
        if (self.handshake_confirmed) return null;
        if (self.totalBytesInFlight() != 0) return null;

        if (self.local_handshake_keys != null and !self.handshake_packet_space.discarded) {
            if (!self.hasQueuedInitialOrHandshakeAckElicitingData(.handshake)) return .handshake;
            return null;
        }
        if (!self.initial_packet_space.discarded and !self.hasQueuedInitialOrHandshakeAckElicitingData(.initial)) {
            return .initial;
        }
        return null;
    }

    fn antiDeadlockPtoDeadline(self: Connection, space: PacketNumberSpace, pto_count: u8) ?i64 {
        if (self.antiDeadlockPtoSpace() != space) return null;
        const start_nanos = self.anti_deadlock_pto_start_nanos orelse return null;
        const recovery_state = switch (space) {
            .initial => self.initial_packet_space.recovery_state,
            .handshake => self.handshake_packet_space.recovery_state,
            .application => return null,
        };
        return ptoDeadlineFromStart(start_nanos, recovery_state, false, pto_count);
    }

    fn refreshAntiDeadlockPtoTimer(self: *Connection, trigger_space: PacketNumberSpace, now_nanos: i64) void {
        if (self.antiDeadlockPtoSpace() == null) {
            self.anti_deadlock_pto_start_nanos = null;
            return;
        }
        if (trigger_space == .application and self.anti_deadlock_pto_start_nanos == null) return;
        if (self.anti_deadlock_pto_start_nanos == null) {
            self.anti_deadlock_pto_start_nanos = now_nanos;
        }
    }

    fn ptoAllowedInSpace(self: Connection, space: PacketNumberSpace) bool {
        if (self.serverAtAntiAmplificationLimit()) return false;
        return switch (space) {
            .initial, .handshake => true,
            .application => self.handshake_confirmed,
        };
    }

    fn queuePtoProbeInSpace(self: *Connection, space: PacketNumberSpace) Error!void {
        if (!self.ptoAllowedInSpace(space)) return;
        if (self.hasPendingPtoProbeDataInSpace(space)) {
            self.armPtoProbeInSpace(space);
            return;
        }

        const queued_crypto_probe = try self.queuePtoCryptoRetransmission(space);
        const queued_control_probe = if (!queued_crypto_probe)
            try self.queuePtoControlRetransmission(space)
        else
            false;
        const queued_stream_probe = if (!queued_crypto_probe and !queued_control_probe)
            try self.queuePtoStreamRetransmission(space)
        else
            false;
        if (!queued_crypto_probe and !queued_control_probe and !queued_stream_probe) {
            try self.queuePingInSpace(space);
        }
        self.armPtoProbeInSpace(space);
    }

    fn queuePtoPeerSpaceProbes(self: *Connection, expired_space: PacketNumberSpace) Error!void {
        const spaces = [_]PacketNumberSpace{ .initial, .handshake, .application };
        for (spaces) |space| {
            if (space == expired_space) continue;
            if (!self.ptoAllowedInSpace(space)) continue;

            const packet_space = self.packetNumberSpace(space);
            if (packet_space.discarded.* or packet_space.sent_packets.items.len == 0) continue;
            try self.queuePtoProbeInSpace(space);
        }
    }

    fn checkPtoTimeoutInSpace(self: *Connection, space: PacketNumberSpace) Error!void {
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return;
        try self.queuePtoProbeInSpace(space);
        self.increaseConnectionPtoBackoff();
    }

    fn queuePtoCryptoRetransmission(self: *Connection, space: PacketNumberSpace) Error!bool {
        const packet_space = self.packetNumberSpace(space);
        for (packet_space.sent_packets.items) |sent_packet| {
            const pending = sent_packet.crypto_frame orelse continue;
            const cloned = try self.clonePendingCryptoFrame(pending);
            errdefer self.allocator.free(cloned.data);
            packet_space.crypto_send_queue.append(self.allocator, cloned) catch return error.OutOfMemory;
            return true;
        }
        return false;
    }

    fn queuePtoControlRetransmission(self: *Connection, space: PacketNumberSpace) Error!bool {
        if (space != .application) return false;
        const packet_space = self.packetNumberSpace(space);
        for (packet_space.sent_packets.items) |sent_packet| {
            if (sent_packet.reset_stream_frame) |reset| {
                if (resetStreamFrameAlreadyAcked(self, reset)) continue;
                self.pending_reset_streams.append(self.allocator, reset) catch return error.OutOfMemory;
                return true;
            }
            if (sent_packet.stop_sending_frame) |stop_sending| {
                self.pending_stop_sending.append(self.allocator, stop_sending) catch return error.OutOfMemory;
                return true;
            }
        }
        return false;
    }

    fn queuePtoStreamRetransmission(self: *Connection, space: PacketNumberSpace) Error!bool {
        if (space != .application) return false;
        const packet_space = self.packetNumberSpace(space);
        for (packet_space.sent_packets.items) |sent_packet| {
            const pending = sent_packet.stream_frame orelse continue;
            const cloned = try self.clonePendingStreamFrame(pending);
            errdefer self.allocator.free(cloned.data);
            self.send_queue.append(self.allocator, cloned) catch return error.OutOfMemory;
            return true;
        }
        return false;
    }

    fn pendingAckFrame(self: *Connection, space: PacketNumberSpace) ?frame.AckFrame {
        const packet_space = self.packetNumberSpace(space);
        _ = packet_space.pending_ack_largest.* orelse return null;
        return packet_space.received_packet_ranges.ackFrame();
    }

    fn queuePingInSpace(self: *Connection, space: PacketNumberSpace) Error!void {
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;
        packet_space.pending_ping_count.* = std.math.add(usize, packet_space.pending_ping_count.*, 1) catch return error.Internal;
    }

    fn expirePathChallenges(self: *Connection, now_nanos: i64) Error!void {
        if (self.outstanding_path_challenges.items.len == 0) return;

        const retry_after = self.recovery_state.ptoNs();
        var retry_count: usize = 0;
        for (self.outstanding_path_challenges.items) |challenge| {
            if (elapsed(challenge.sent_time_nanos, now_nanos) < retry_after) continue;
            if (challenge.transmissions < max_path_challenge_transmissions) retry_count += 1;
        }
        if (retry_count != 0) {
            self.pending_path_challenges.ensureUnusedCapacity(self.allocator, retry_count) catch return error.OutOfMemory;
        }

        var i: usize = 0;
        while (i < self.outstanding_path_challenges.items.len) {
            const challenge = self.outstanding_path_challenges.items[i];
            if (elapsed(challenge.sent_time_nanos, now_nanos) < retry_after) {
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
        self: *Connection,
        now_nanos: i64,
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

        if (!self.closed) self.enterClosingState(now_nanos);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_nanos);
        return written;
    }

    fn pollAckOnly(
        self: *Connection,
        ack: frame.AckFrame,
        now_nanos: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        return self.pollAckOnlyInSpace(.application, ack, now_nanos, out_buf);
    }

    fn pollAckOnlyInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        ack: frame.AckFrame,
        now_nanos: i64,
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
        self.recordPacketActivity(now_nanos);
        self.maybeDiscardInitialAfterHandshakePacketSent(space);
        return written;
    }

    fn pollPathResponse(
        self: *Connection,
        ack_to_send: ?frame.AckFrame,
        now_nanos: i64,
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
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_nanos, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.canSendAckElicitingInSpace(.application, encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        var appended_sent_packet = false;
        errdefer if (appended_sent_packet) {
            self.sent_packets.items.len -= 1;
        };

        const packet_number = self.next_packet_number;
        self.sent_packets.append(self.allocator, .{
            .packet_number = packet_number,
            .sent_time_nanos = now_nanos,
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
        self.recordAckElicitingSendInSpace(.application, written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_nanos);
        return written;
    }

    fn pollResetStream(
        self: *Connection,
        ack_to_send: ?frame.AckFrame,
        now_nanos: i64,
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
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_nanos, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.canSendAckElicitingInSpace(.application, encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        var appended_sent_packet = false;
        errdefer if (appended_sent_packet) {
            self.sent_packets.items.len -= 1;
        };

        const packet_number = self.next_packet_number;
        self.sent_packets.append(self.allocator, .{
            .packet_number = packet_number,
            .sent_time_nanos = now_nanos,
            .bytes = encoded_len,
            .reset_stream_frame = reset,
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
        self.recordAckElicitingSendInSpace(.application, written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_nanos);
        return written;
    }

    fn pollStopSending(
        self: *Connection,
        ack_to_send: ?frame.AckFrame,
        now_nanos: i64,
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
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_nanos, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.canSendAckElicitingInSpace(.application, encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        var appended_sent_packet = false;
        errdefer if (appended_sent_packet) {
            self.sent_packets.items.len -= 1;
        };

        const packet_number = self.next_packet_number;
        self.sent_packets.append(self.allocator, .{
            .packet_number = packet_number,
            .sent_time_nanos = now_nanos,
            .bytes = encoded_len,
            .stop_sending_frame = stop_sending,
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
        self.recordAckElicitingSendInSpace(.application, written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_nanos);
        return written;
    }

    fn pollRetireConnectionId(
        self: *Connection,
        ack_to_send: ?frame.AckFrame,
        now_nanos: i64,
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
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_nanos, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.canSendAckElicitingInSpace(.application, encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        var appended_sent_packet = false;
        errdefer if (appended_sent_packet) {
            self.sent_packets.items.len -= 1;
        };

        const packet_number = self.next_packet_number;
        self.sent_packets.append(self.allocator, .{
            .packet_number = packet_number,
            .sent_time_nanos = now_nanos,
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
        self.recordAckElicitingSendInSpace(.application, written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_nanos);
        return written;
    }

    fn pollNewConnectionId(
        self: *Connection,
        ack_to_send: ?frame.AckFrame,
        now_nanos: i64,
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
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_nanos, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.canSendAckElicitingInSpace(.application, encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        var appended_sent_packet = false;
        errdefer if (appended_sent_packet) {
            self.sent_packets.items.len -= 1;
        };

        const packet_number = self.next_packet_number;
        self.sent_packets.append(self.allocator, .{
            .packet_number = packet_number,
            .sent_time_nanos = now_nanos,
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
        self.recordAckElicitingSendInSpace(.application, written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_nanos);
        return written;
    }

    fn pollHandshakeDone(
        self: *Connection,
        ack_to_send: ?frame.AckFrame,
        now_nanos: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        const handshake_done_encoded_len = handshakeDoneFrameWireLen();
        const max_tx_datagram_size = self.maxTxDatagramSize();
        if (handshake_done_encoded_len > max_tx_datagram_size) return error.BufferTooSmall;

        var encoded_len = handshake_done_encoded_len;
        var include_ack = false;
        if (ack_to_send) |ack| {
            const ack_encoded_len = try ackFrameWireLen(ack);
            const coalesced_len = try addWireLen(ack_encoded_len, handshake_done_encoded_len);
            if (coalesced_len <= max_tx_datagram_size and out_buf.len >= coalesced_len and
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_nanos, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.canSendAckElicitingInSpace(.application, encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        var appended_sent_packet = false;
        errdefer if (appended_sent_packet) {
            self.sent_packets.items.len -= 1;
        };

        const packet_number = self.next_packet_number;
        self.sent_packets.append(self.allocator, .{
            .packet_number = packet_number,
            .sent_time_nanos = now_nanos,
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
        frame.encodeFrame(out.writer(), .{ .handshake_done = {} }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const written = out.getWritten();
        std.debug.assert(written.len == encoded_len);

        self.pending_handshake_done = false;
        self.handshake_done_sent = true;
        if (include_ack) self.pending_ack_largest = null;
        self.next_packet_number = std.math.add(u64, packet_number, 1) catch return error.Internal;
        self.recordAckElicitingSendInSpace(.application, written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_nanos);
        return written;
    }

    fn pollNewToken(
        self: *Connection,
        ack_to_send: ?frame.AckFrame,
        now_nanos: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        const token = self.pending_new_tokens.items[0];
        const new_token_encoded_len = try newTokenFrameWireLen(token);
        const max_tx_datagram_size = self.maxTxDatagramSize();
        if (new_token_encoded_len > max_tx_datagram_size) return error.BufferTooSmall;

        var encoded_len = new_token_encoded_len;
        var include_ack = false;
        if (ack_to_send) |ack| {
            const ack_encoded_len = try ackFrameWireLen(ack);
            const coalesced_len = try addWireLen(ack_encoded_len, new_token_encoded_len);
            if (coalesced_len <= max_tx_datagram_size and out_buf.len >= coalesced_len and
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_nanos, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.canSendAckElicitingInSpace(.application, encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        var appended_sent_packet = false;
        errdefer if (appended_sent_packet) {
            self.sent_packets.items.len -= 1;
        };

        const packet_number = self.next_packet_number;
        self.sent_packets.append(self.allocator, .{
            .packet_number = packet_number,
            .sent_time_nanos = now_nanos,
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
        frame.encodeFrame(out.writer(), .{ .new_token = .{ .token = token } }) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const written = out.getWritten();
        std.debug.assert(written.len == encoded_len);

        const removed = self.pending_new_tokens.orderedRemove(0);
        self.allocator.free(removed);
        if (include_ack) self.pending_ack_largest = null;
        self.next_packet_number = std.math.add(u64, packet_number, 1) catch return error.Internal;
        self.recordAckElicitingSendInSpace(.application, written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_nanos);
        return written;
    }

    fn pollPingFrame(
        self: *Connection,
        ack_to_send: ?frame.AckFrame,
        now_nanos: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        return self.pollPingFrameInSpace(.application, ack_to_send, now_nanos, out_buf);
    }

    fn pollPingFrameInSpace(
        self: *Connection,
        space: PacketNumberSpace,
        ack_to_send: ?frame.AckFrame,
        now_nanos: i64,
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
                self.canSendAckElicitingInSpace(space, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnlyInSpace(space, ack, now_nanos, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.canSendAckElicitingInSpace(space, encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;
        if (packet_space.next_packet_number.* > max_quic_varint) return error.Internal;

        var appended_sent_packet = false;
        errdefer if (appended_sent_packet) {
            var removed_sent_packet = packet_space.sent_packets.orderedRemove(packet_space.sent_packets.items.len - 1);
            removed_sent_packet.deinit(self.allocator);
        };

        const packet_number = packet_space.next_packet_number.*;
        packet_space.sent_packets.append(self.allocator, .{
            .packet_number = packet_number,
            .sent_time_nanos = now_nanos,
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
        self.recordAckElicitingSendInSpace(space, written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_nanos);
        self.maybeDiscardInitialAfterHandshakePacketSent(space);
        return written;
    }

    fn pollDatagramFrame(
        self: *Connection,
        ack_to_send: ?frame.AckFrame,
        now_nanos: i64,
        out_buf: []u8,
    ) Error!?[]u8 {
        _ = ack_to_send;
        _ = now_nanos;
        const data = self.pending_datagrams.orderedRemove(0);
        defer self.allocator.free(data);
        const encoded_len = wire_len.datagramFrameWireLen(data.len) catch return error.BufferTooSmall;
        if (encoded_len > out_buf.len) return error.BufferTooSmall;
        var out = buffer.fixedWriter(out_buf);
        frame.encodeFrame(out.writer(), .{ .datagram = .{ .data = data } }) catch return error.BufferTooSmall;
        return out.getWritten();
    }

    fn pollPathChallenge(
        self: *Connection,
        ack_to_send: ?frame.AckFrame,
        now_nanos: i64,
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
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_nanos, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.canSendAckElicitingInSpace(.application, encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
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
            .sent_time_nanos = now_nanos,
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
            .sent_time_nanos = now_nanos,
            .transmissions = transmissions,
        }) catch return error.OutOfMemory;
        appended_outstanding_challenge = true;

        const written = out.getWritten();
        std.debug.assert(written.len == encoded_len);

        _ = self.pending_path_challenges.orderedRemove(0);
        if (include_ack) self.pending_ack_largest = null;
        self.next_packet_number = std.math.add(u64, packet_number, 1) catch return error.Internal;
        self.recordAckElicitingSendInSpace(.application, written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_nanos);
        return written;
    }

    fn pollBlockedFrame(
        self: *Connection,
        ack_to_send: ?frame.AckFrame,
        now_nanos: i64,
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
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_nanos, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.canSendAckElicitingInSpace(.application, encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        var appended_sent_packet = false;
        errdefer if (appended_sent_packet) {
            self.sent_packets.items.len -= 1;
        };

        const packet_number = self.next_packet_number;
        self.sent_packets.append(self.allocator, .{
            .packet_number = packet_number,
            .sent_time_nanos = now_nanos,
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
        self.recordAckElicitingSendInSpace(.application, written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_nanos);
        return written;
    }

    fn pollMaxFrame(
        self: *Connection,
        ack_to_send: ?frame.AckFrame,
        now_nanos: i64,
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
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_nanos, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.canSendAckElicitingInSpace(.application, encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        var appended_sent_packet = false;
        errdefer if (appended_sent_packet) {
            self.sent_packets.items.len -= 1;
        };

        const packet_number = self.next_packet_number;
        self.sent_packets.append(self.allocator, .{
            .packet_number = packet_number,
            .sent_time_nanos = now_nanos,
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
        self.recordAckElicitingSendInSpace(.application, written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_nanos);
        return written;
    }

    fn pollCryptoFrame(
        self: *Connection,
        space: PacketNumberSpace,
        ack_to_send: ?frame.AckFrame,
        now_nanos: i64,
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
                self.canSendAckElicitingInSpace(space, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnlyInSpace(space, ack, now_nanos, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.canSendAckElicitingInSpace(space, encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;
        if (packet_space.next_packet_number.* > max_quic_varint) return error.Internal;

        const sent_crypto_frame = try self.clonePendingCryptoFrame(pending);
        var sent_crypto_frame_transferred = false;
        errdefer if (!sent_crypto_frame_transferred) {
            self.allocator.free(sent_crypto_frame.data);
        };

        var appended_sent_packet = false;
        errdefer if (appended_sent_packet) {
            var removed_sent_packet = packet_space.sent_packets.orderedRemove(packet_space.sent_packets.items.len - 1);
            removed_sent_packet.deinit(self.allocator);
        };

        const packet_number = packet_space.next_packet_number.*;
        packet_space.sent_packets.append(self.allocator, .{
            .packet_number = packet_number,
            .sent_time_nanos = now_nanos,
            .bytes = encoded_len,
            .crypto_frame = sent_crypto_frame,
        }) catch return error.OutOfMemory;
        sent_crypto_frame_transferred = true;
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
        self.recordAckElicitingSendInSpace(space, written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_nanos);
        self.maybeDiscardInitialAfterHandshakePacketSent(space);
        self.maybeDiscardHandshakeAfterConfirmedCryptoSent(space);
        return written;
    }

    fn dropResetClosedStreamFrames(self: *Connection) void {
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

    fn queueAckForReceivedPacket(
        self: *Connection,
        space: PacketNumberSpace,
        received_packet_number: ?u64,
    ) Error!void {
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;
        const packet_number = received_packet_number orelse packet_space.next_peer_packet_number.*;
        if (!try self.recordReceivedPacketNumber(packet_space, packet_number)) return;

        packet_space.pending_ack_largest.* = packet_space.received_packet_ranges.ranges[0].largest;
    }

    fn recordReceivedPacketNumber(
        self: *Connection,
        packet_space: PacketNumberSpaceView,
        packet_number: u64,
    ) Error!bool {
        _ = self;
        if (packet_number > max_quic_varint) return error.InvalidPacket;
        const inserted = packet_space.received_packet_ranges.record(packet_number);
        if (inserted) {
            packet_space.next_peer_packet_number.* = packet_space.received_packet_ranges.nextExpectedPacketNumber();
        }
        return inserted;
    }

    pub fn activeConnectionIdCount(self: Connection) u64 {
        var count: u64 = 0;
        for (self.active_connection_ids.items) |active_id| {
            if (!active_id.retired) count += 1;
        }
        return count;
    }

    fn activeConnectionIdCountAfterRetirePriorTo(self: Connection, retire_prior_to: u64) u64 {
        var count: u64 = 0;
        for (self.active_connection_ids.items) |active_id| {
            if (active_id.retired or active_id.sequence_number < retire_prior_to) continue;
            count += 1;
        }
        return count;
    }

    fn nextUnsentLocalConnectionIdIndex(self: Connection) ?usize {
        for (self.local_connection_ids.items, 0..) |local_id, i| {
            if (!local_id.sent and !local_id.retired) return i;
        }
        return null;
    }

    fn localConnectionIdValueExists(self: Connection, connection_id: []const u8) bool {
        for (self.local_connection_ids.items) |local_id| {
            if (std.mem.eql(u8, local_id.connection_id, connection_id)) return true;
        }
        return false;
    }

    fn localStatelessResetTokenValueExists(
        self: Connection,
        stateless_reset_token: [packet.stateless_reset_token_len]u8,
    ) bool {
        for (self.local_connection_ids.items) |local_id| {
            if (statelessResetTokensEqual(local_id.stateless_reset_token, stateless_reset_token)) return true;
        }
        return false;
    }

    fn findLocalConnectionId(self: *Connection, sequence_number: u64) ?*LocalConnectionId {
        for (self.local_connection_ids.items) |*local_id| {
            if (local_id.sequence_number == sequence_number) return local_id;
        }
        return null;
    }
    pub fn rollbackIssuedConnectionIds(
        self: *Connection,
        original_len: usize,
        original_next_sequence: u64,
    ) void {
        std.debug.assert(original_len <= self.local_connection_ids.items.len);
        for (self.local_connection_ids.items[original_len..]) |local_id| {
            self.allocator.free(local_id.connection_id);
        }
        self.local_connection_ids.items.len = original_len;
        self.next_local_connection_id_sequence = original_next_sequence;
    }

    fn findActiveConnectionId(self: *Connection, sequence_number: u64) ?*ActiveConnectionId {
        for (self.active_connection_ids.items) |*active_id| {
            if (active_id.sequence_number == sequence_number) return active_id;
        }
        return null;
    }

    fn findActiveConnectionIdByValue(self: *Connection, connection_id: []const u8) ?*ActiveConnectionId {
        for (self.active_connection_ids.items) |*active_id| {
            if (std.mem.eql(u8, active_id.connection_id, connection_id)) return active_id;
        }
        return null;
    }

    fn activeStatelessResetTokenValueExists(
        self: Connection,
        stateless_reset_token: [packet.stateless_reset_token_len]u8,
    ) bool {
        for (self.active_connection_ids.items) |active_id| {
            if (statelessResetTokensEqual(active_id.stateless_reset_token, stateless_reset_token)) return true;
        }
        return false;
    }

    fn queueRetireConnectionId(self: *Connection, sequence_number: u64) Error!void {
        for (self.pending_retire_connection_ids.items) |queued_sequence_number| {
            if (queued_sequence_number == sequence_number) return;
        }
        self.pending_retire_connection_ids.append(self.allocator, sequence_number) catch return error.OutOfMemory;
    }

    fn retireConnectionIdsBefore(self: *Connection, retire_prior_to: u64) Error!void {
        for (self.active_connection_ids.items) |*active_id| {
            if (active_id.sequence_number >= retire_prior_to or active_id.retired) continue;
            active_id.retired = true;
            try self.queueRetireConnectionId(active_id.sequence_number);
        }
    }

    fn receiveNewConnectionIdFrame(self: *Connection, new_connection_id: frame.NewConnectionIdFrame) Error!void {
        if (self.sendsZeroLengthDestinationConnectionId()) return error.InvalidPacket;
        if (new_connection_id.retire_prior_to > new_connection_id.sequence_number) return error.InvalidPacket;
        self.largest_peer_retire_prior_to = @max(self.largest_peer_retire_prior_to, new_connection_id.retire_prior_to);
        try self.retireConnectionIdsBefore(new_connection_id.retire_prior_to);

        if (self.findActiveConnectionId(new_connection_id.sequence_number)) |existing| {
            if (!std.mem.eql(u8, existing.connection_id, new_connection_id.connection_id)) return error.InvalidPacket;
            if (!statelessResetTokensEqual(existing.stateless_reset_token, new_connection_id.stateless_reset_token)) return error.InvalidPacket;
            return;
        }

        if (new_connection_id.sequence_number < self.largest_peer_retire_prior_to) {
            try self.queueRetireConnectionId(new_connection_id.sequence_number);
            return;
        }

        if (self.findActiveConnectionIdByValue(new_connection_id.connection_id)) |_| return error.InvalidPacket;
        if (self.activeStatelessResetTokenValueExists(new_connection_id.stateless_reset_token)) return error.InvalidPacket;
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

    fn receiveRetireConnectionIdFrame(self: *Connection, retire_connection_id: frame.RetireConnectionIdFrame) Error!void {
        if (self.hasZeroLengthLocalInitialSourceConnectionId()) return error.InvalidPacket;
        const local_id = self.findLocalConnectionId(retire_connection_id.sequence_number) orelse return error.InvalidPacket;
        if (!local_id.sent) return error.InvalidPacket;
        local_id.retired = true;
    }

    fn receiveNewTokenFrame(self: *Connection, new_token: frame.NewTokenFrame) Error!void {
        if (self.side == .server) return error.InvalidPacket;
        if (self.stored_new_tokens.items.len >= self.config.max_stored_new_tokens) return;

        const owned = self.allocator.alloc(u8, new_token.token.len) catch return error.OutOfMemory;
        errdefer self.allocator.free(owned);
        @memcpy(owned, new_token.token);

        self.stored_new_tokens.append(self.allocator, owned) catch return error.OutOfMemory;
    }

    fn receiveHandshakeDoneFrame(self: *Connection) Error!void {
        if (self.side == .server) return error.InvalidPacket;
        self.handshake_state = .confirmed;
        self.handshake_confirmed = true;
    }

    fn receiveDataBlockedFrame(self: *Connection, data_blocked: frame.DataBlockedFrame) Error!void {
        self.peer_data_blocked_limit = if (self.peer_data_blocked_limit) |current|
            @max(current, data_blocked.maximum_data)
        else
            data_blocked.maximum_data;
        if (data_blocked.maximum_data < self.recv_max_data) {
            try self.queueMaxDataFrame(self.recv_max_data);
        } else if (nextReceiveLimitAfterPeerBlocked(
            self.recv_max_data,
            data_blocked.maximum_data,
            self.config.receive_connection_window,
        )) |next_limit| {
            try self.queueMaxDataFrame(next_limit);
            self.recv_max_data = next_limit;
        }
    }

    fn receiveStreamDataBlockedFrame(self: *Connection, stream_data_blocked: frame.StreamDataBlockedFrame) Error!void {
        if (stream_data_blocked.stream_id > max_quic_varint) return error.InvalidStream;
        try self.validateIncomingStreamCount(stream_data_blocked.stream_id);

        const stream_state = try self.ensureRecvStreamState(stream_data_blocked.stream_id);
        if (stream_state.final_size != null) return;

        for (self.peer_stream_data_blocked_limits.items) |*blocked| {
            if (blocked.stream_id != stream_data_blocked.stream_id) continue;
            blocked.maximum_stream_data = @max(blocked.maximum_stream_data, stream_data_blocked.maximum_stream_data);
            if (stream_data_blocked.maximum_stream_data < stream_state.max_data) {
                try self.queueMaxStreamDataFrame(stream_data_blocked.stream_id, stream_state.max_data);
            } else if (nextReceiveLimitAfterPeerBlocked(
                stream_state.max_data,
                stream_data_blocked.maximum_stream_data,
                self.config.receive_stream_window,
            )) |next_limit| {
                try self.queueMaxStreamDataFrame(stream_data_blocked.stream_id, next_limit);
                stream_state.max_data = next_limit;
            }
            return;
        }

        self.peer_stream_data_blocked_limits.append(self.allocator, .{
            .stream_id = stream_data_blocked.stream_id,
            .maximum_stream_data = stream_data_blocked.maximum_stream_data,
        }) catch return error.OutOfMemory;
        if (stream_data_blocked.maximum_stream_data < stream_state.max_data) {
            try self.queueMaxStreamDataFrame(stream_data_blocked.stream_id, stream_state.max_data);
        } else if (nextReceiveLimitAfterPeerBlocked(
            stream_state.max_data,
            stream_data_blocked.maximum_stream_data,
            self.config.receive_stream_window,
        )) |next_limit| {
            try self.queueMaxStreamDataFrame(stream_data_blocked.stream_id, next_limit);
            stream_state.max_data = next_limit;
        }
    }

    fn receiveStreamsBlockedBidiFrame(self: *Connection, streams_blocked: frame.StreamsBlockedBidiFrame) Error!void {
        self.peer_streams_blocked_bidi_limit = if (self.peer_streams_blocked_bidi_limit) |current|
            @max(current, streams_blocked.maximum_streams)
        else
            streams_blocked.maximum_streams;
        if (streams_blocked.maximum_streams < self.recv_max_streams_bidi) {
            try self.queueMaxStreamsBidiFrame(self.recv_max_streams_bidi);
        } else if (nextReceiveStreamCountLimitAfterPeerBlocked(
            self.recv_max_streams_bidi,
            streams_blocked.maximum_streams,
            self.config.receive_stream_count_window,
        )) |next_limit| {
            try self.queueMaxStreamsBidiFrame(next_limit);
            self.recv_max_streams_bidi = next_limit;
        }
    }

    fn receiveStreamsBlockedUniFrame(self: *Connection, streams_blocked: frame.StreamsBlockedUniFrame) Error!void {
        self.peer_streams_blocked_uni_limit = if (self.peer_streams_blocked_uni_limit) |current|
            @max(current, streams_blocked.maximum_streams)
        else
            streams_blocked.maximum_streams;
        if (streams_blocked.maximum_streams < self.recv_max_streams_uni) {
            try self.queueMaxStreamsUniFrame(self.recv_max_streams_uni);
        } else if (nextReceiveStreamCountLimitAfterPeerBlocked(
            self.recv_max_streams_uni,
            streams_blocked.maximum_streams,
            self.config.receive_stream_count_window,
        )) |next_limit| {
            try self.queueMaxStreamsUniFrame(next_limit);
            self.recv_max_streams_uni = next_limit;
        }
    }

    fn receiveMaxDataFrame(self: *Connection, max_data: frame.MaxDataFrame) void {
        self.peer_max_data = @max(self.peer_max_data, max_data.maximum_data);
    }

    fn applyMaxStreamDataToSendStream(stream_state: *SendStreamState, maximum_stream_data: u64) void {
        if (sendStreamClosed(stream_state)) return;
        stream_state.max_data = @max(stream_state.max_data, maximum_stream_data);
    }

    fn receiveMaxStreamDataFrame(self: *Connection, max_stream_data: frame.MaxStreamDataFrame) Error!void {
        if (max_stream_data.stream_id > max_quic_varint) return error.InvalidStream;

        if (!isBidirectionalStream(max_stream_data.stream_id)) {
            if (!isLocalStreamInitiator(self.side, max_stream_data.stream_id)) return error.InvalidPacket;
            const stream_state = self.findSendStream(max_stream_data.stream_id) orelse return error.InvalidPacket;
            applyMaxStreamDataToSendStream(stream_state, max_stream_data.maximum_stream_data);
            return;
        }

        if (isLocalStreamInitiator(self.side, max_stream_data.stream_id)) {
            const stream_state = self.findSendStream(max_stream_data.stream_id) orelse return error.InvalidPacket;
            applyMaxStreamDataToSendStream(stream_state, max_stream_data.maximum_stream_data);
            return;
        }

        if (streamCountForId(max_stream_data.stream_id) > self.recv_max_streams_bidi) return error.InvalidPacket;
        _ = try self.ensureRecvStreamState(max_stream_data.stream_id);

        const existing_state = self.findSendStream(max_stream_data.stream_id);
        var appended_send_state = false;
        errdefer if (appended_send_state) {
            _ = self.send_streams.orderedRemove(self.send_streams.items.len - 1);
        };

        const stream_state = existing_state orelse blk: {
            self.send_streams.append(self.allocator, .{
                .stream_id = max_stream_data.stream_id,
                .max_data = self.initialPeerStreamDataLimit(max_stream_data.stream_id),
            }) catch return error.OutOfMemory;
            appended_send_state = true;
            break :blk &self.send_streams.items[self.send_streams.items.len - 1];
        };
        applyMaxStreamDataToSendStream(stream_state, max_stream_data.maximum_stream_data);
    }

    fn receiveMaxStreamsBidiFrame(self: *Connection, max_streams: frame.MaxStreamsBidiFrame) Error!void {
        if (max_streams.maximum_streams > max_stream_count) return error.InvalidPacket;
        self.peer_max_streams_bidi = @max(self.peer_max_streams_bidi, max_streams.maximum_streams);
    }

    fn receiveMaxStreamsUniFrame(self: *Connection, max_streams: frame.MaxStreamsUniFrame) Error!void {
        if (max_streams.maximum_streams > max_stream_count) return error.InvalidPacket;
        self.peer_max_streams_uni = @max(self.peer_max_streams_uni, max_streams.maximum_streams);
    }

    fn receivePathChallengeFrame(self: *Connection, path_challenge: frame.PathChallengeFrame) Error!void {
        for (self.pending_path_responses.items) |response_data| {
            if (std.mem.eql(u8, &response_data, &path_challenge.data)) return;
        }
        self.pending_path_responses.append(self.allocator, path_challenge.data) catch return error.OutOfMemory;
    }

    fn pathResponseChallengeIndex(self: *Connection, data: [8]u8) ?usize {
        for (self.outstanding_path_challenges.items, 0..) |challenge, i| {
            if (std.mem.eql(u8, &challenge.data, &data)) return i;
        }
        return null;
    }

    fn receivePathResponseFrame(self: *Connection, path_response: frame.PathResponseFrame) Error!void {
        const challenge_index = self.pathResponseChallengeIndex(path_response.data) orelse return error.InvalidPacket;
        _ = self.outstanding_path_challenges.orderedRemove(challenge_index);
    }

    fn receiveStopSendingFrame(self: *Connection, stop_sending: frame.StopSendingFrame) Error!void {
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

        _ = try self.ensureRecvStreamState(stop_sending.stream_id);

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
        self: *Connection,
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
        stream_state.reset_acked = false;
    }

    fn queueStopSending(
        self: *Connection,
        stream_state: *RecvStreamState,
        application_error_code: u64,
    ) Error!void {
        if (stream_state.reset_error_code != null) return error.StreamClosed;
        if (stream_state.stop_sending_sent) return;
        if (application_error_code > max_quic_varint) return error.InvalidPacket;
        if (stream_state.final_size) |final_size| {
            const final_size_usize = std.math.cast(usize, final_size) orelse return error.Internal;
            if (stream_state.data.items.len >= final_size_usize) return error.StreamClosed;
        }

        self.pending_stop_sending.append(self.allocator, .{
            .stream_id = stream_state.stream_id,
            .application_error_code = application_error_code,
        }) catch return error.OutOfMemory;
        stream_state.stop_sending_sent = true;
    }

    fn validateIncomingStreamCount(self: *Connection, stream_id: u64) Error!void {
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

    const ReceiveStreamFrameData = struct {
        offset: u64,
        data: []const u8,
    };

    const PendingRecvOverlap = struct {
        pending: PendingRecvStreamFrame,
        start: u64,
        end: u64,
    };

    fn streamFrameHasConflictingOverlap(
        stream_state: RecvStreamState,
        offset: u64,
        data: []const u8,
    ) Error!bool {
        if (data.len == 0) return false;

        // Only proven byte conflicts are semantic protocol errors here. Overlaps
        // that remain unsupported or ambiguous still fall through to the
        // rollback-only STREAM receive path.
        const end_offset = streamEndOffset(offset, data.len) orelse return error.InvalidPacket;
        const contiguous_len = std.math.cast(u64, stream_state.data.items.len) orelse return error.Internal;
        const contiguous_overlap_start = offset;
        const contiguous_overlap_end = @min(end_offset, contiguous_len);
        if (contiguous_overlap_start < contiguous_overlap_end) {
            const incoming_start = std.math.cast(usize, contiguous_overlap_start - offset) orelse return error.InvalidPacket;
            const existing_start = std.math.cast(usize, contiguous_overlap_start) orelse return error.InvalidPacket;
            const overlap_len = std.math.cast(usize, contiguous_overlap_end - contiguous_overlap_start) orelse return error.InvalidPacket;
            if (!std.mem.eql(
                u8,
                stream_state.data.items[existing_start..][0..overlap_len],
                data[incoming_start..][0..overlap_len],
            )) return true;
        }

        for (stream_state.pending.items) |pending| {
            const pending_end = streamEndOffset(pending.offset, pending.data.len) orelse return error.InvalidPacket;
            const overlap_start = @max(offset, pending.offset);
            const overlap_end = @min(end_offset, pending_end);
            if (overlap_start >= overlap_end) continue;

            const incoming_start = std.math.cast(usize, overlap_start - offset) orelse return error.InvalidPacket;
            const pending_start = std.math.cast(usize, overlap_start - pending.offset) orelse return error.InvalidPacket;
            const overlap_len = std.math.cast(usize, overlap_end - overlap_start) orelse return error.InvalidPacket;
            if (!std.mem.eql(
                u8,
                pending.data[pending_start..][0..overlap_len],
                data[incoming_start..][0..overlap_len],
            )) return true;
        }

        return false;
    }

    fn earliestPendingRecvOverlap(
        stream_state: RecvStreamState,
        start: u64,
        end: u64,
    ) Error!?PendingRecvOverlap {
        var earliest: ?PendingRecvOverlap = null;
        for (stream_state.pending.items) |pending| {
            const pending_end = streamEndOffset(pending.offset, pending.data.len) orelse return error.InvalidPacket;
            const overlap_start = @max(start, pending.offset);
            const overlap_end = @min(end, pending_end);
            if (overlap_start >= overlap_end) continue;
            if (earliest == null or overlap_start < earliest.?.start) {
                earliest = .{
                    .pending = pending,
                    .start = overlap_start,
                    .end = overlap_end,
                };
            }
        }
        return earliest;
    }

    fn collectNewRecvStreamDataSegments(
        self: *Connection,
        stream_state: RecvStreamState,
        offset: u64,
        data: []const u8,
        segments: ?*std.ArrayList(ReceiveStreamFrameData),
    ) Error!usize {
        if (data.len == 0) return 0;

        const contiguous_len = std.math.cast(u64, stream_state.data.items.len) orelse return error.Internal;
        const end_offset = streamEndOffset(offset, data.len) orelse return error.InvalidPacket;
        var cursor = offset;
        var new_byte_count: usize = 0;

        if (cursor < contiguous_len) {
            const duplicate_len_u64 = @min(
                contiguous_len - cursor,
                end_offset - cursor,
            );
            const duplicate_len = std.math.cast(usize, duplicate_len_u64) orelse return error.InvalidPacket;
            const duplicate_start = std.math.cast(usize, cursor) orelse return error.InvalidPacket;
            const duplicate_end = std.math.add(usize, duplicate_start, duplicate_len) catch return error.InvalidPacket;
            const incoming_start = std.math.cast(usize, cursor - offset) orelse return error.InvalidPacket;
            if (!std.mem.eql(u8, stream_state.data.items[duplicate_start..duplicate_end], data[incoming_start..][0..duplicate_len])) {
                return error.InvalidPacket;
            }
            cursor = streamEndOffset(cursor, duplicate_len) orelse return error.InvalidPacket;
            if (cursor == end_offset) return 0;
        }

        while (cursor < end_offset) {
            const overlap = try earliestPendingRecvOverlap(stream_state, cursor, end_offset) orelse {
                const start_index = std.math.cast(usize, cursor - offset) orelse return error.InvalidPacket;
                const segment_len = data.len - start_index;
                if (segments) |out_segments| {
                    out_segments.append(self.allocator, .{
                        .offset = cursor,
                        .data = data[start_index..],
                    }) catch return error.OutOfMemory;
                }
                return std.math.add(usize, new_byte_count, segment_len) catch return error.InvalidPacket;
            };

            if (overlap.start > cursor) {
                const start_index = std.math.cast(usize, cursor - offset) orelse return error.InvalidPacket;
                const segment_len = std.math.cast(usize, overlap.start - cursor) orelse return error.InvalidPacket;
                if (segments) |out_segments| {
                    out_segments.append(self.allocator, .{
                        .offset = cursor,
                        .data = data[start_index..][0..segment_len],
                    }) catch return error.OutOfMemory;
                }
                new_byte_count = std.math.add(usize, new_byte_count, segment_len) catch return error.InvalidPacket;
                cursor = overlap.start;
            }

            const incoming_start = std.math.cast(usize, overlap.start - offset) orelse return error.InvalidPacket;
            const pending_start = std.math.cast(usize, overlap.start - overlap.pending.offset) orelse return error.InvalidPacket;
            const overlap_len = std.math.cast(usize, overlap.end - overlap.start) orelse return error.InvalidPacket;
            if (!std.mem.eql(
                u8,
                data[incoming_start..][0..overlap_len],
                overlap.pending.data[pending_start..][0..overlap_len],
            )) {
                return error.InvalidPacket;
            }
            cursor = overlap.end;
        }

        return new_byte_count;
    }

    fn appendPendingRecvStreamFrame(
        self: *Connection,
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

    fn drainPendingRecvStreams(self: *Connection) Error!void {
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

    fn receiveResetStreamFrame(self: *Connection, reset: frame.ResetStreamFrame) Error!void {
        if (reset.stream_id > max_quic_varint) return error.InvalidStream;
        try self.validateIncomingStreamCount(reset.stream_id);

        const stream_state = try self.ensureRecvStreamState(reset.stream_id);

        if (reset.final_size > stream_state.max_data) return error.InvalidPacket;

        const highest_received = try highestReceivedStreamEndOffset(stream_state.*);
        if (reset.final_size < highest_received) return error.InvalidPacket;
        if (stream_state.final_size) |final_size| {
            if (final_size != reset.final_size) return error.InvalidPacket;
            if (stream_state.reset_error_code != null) return;

            const final_size_usize = std.math.cast(usize, final_size) orelse return error.Internal;
            if (stream_state.data.items.len >= final_size_usize) return;

            const received_size = try receivedStreamByteCount(stream_state.*);
            if (reset.final_size < received_size) return error.InvalidPacket;
            const delta = reset.final_size - received_size;
            const next_recv_total = std.math.add(u64, self.recv_data_bytes, delta) catch return error.InvalidPacket;
            if (next_recv_total > self.recv_max_data) return error.InvalidPacket;

            self.recv_data_bytes = next_recv_total;
            stream_state.reset_error_code = reset.application_error_code;
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

    const ReceiveCryptoFrameData = struct {
        offset: u64,
        data: []const u8,
    };

    const PendingCryptoOverlap = struct {
        pending: PendingCryptoFrame,
        start: u64,
        end: u64,
    };

    fn cryptoFrameHasConflictingOverlap(
        packet_space: PacketNumberSpaceView,
        offset: u64,
        data: []const u8,
    ) Error!bool {
        if (data.len == 0) return false;

        const end_offset = streamEndOffset(offset, data.len) orelse return error.InvalidPacket;
        const contiguous_len = std.math.cast(u64, packet_space.crypto_recv_buffer.items.len) orelse return error.Internal;
        const contiguous_overlap_start = offset;
        const contiguous_overlap_end = @min(end_offset, contiguous_len);
        if (contiguous_overlap_start < contiguous_overlap_end) {
            const incoming_start = std.math.cast(usize, contiguous_overlap_start - offset) orelse return error.InvalidPacket;
            const existing_start = std.math.cast(usize, contiguous_overlap_start) orelse return error.InvalidPacket;
            const overlap_len = std.math.cast(usize, contiguous_overlap_end - contiguous_overlap_start) orelse return error.InvalidPacket;
            if (!std.mem.eql(
                u8,
                packet_space.crypto_recv_buffer.items[existing_start..][0..overlap_len],
                data[incoming_start..][0..overlap_len],
            )) return true;
        }

        for (packet_space.crypto_recv_pending.items) |pending| {
            const pending_end = streamEndOffset(pending.offset, pending.data.len) orelse return error.InvalidPacket;
            const overlap_start = @max(offset, pending.offset);
            const overlap_end = @min(end_offset, pending_end);
            if (overlap_start >= overlap_end) continue;

            const incoming_start = std.math.cast(usize, overlap_start - offset) orelse return error.InvalidPacket;
            const pending_start = std.math.cast(usize, overlap_start - pending.offset) orelse return error.InvalidPacket;
            const overlap_len = std.math.cast(usize, overlap_end - overlap_start) orelse return error.InvalidPacket;
            if (!std.mem.eql(
                u8,
                pending.data[pending_start..][0..overlap_len],
                data[incoming_start..][0..overlap_len],
            )) return true;
        }

        return false;
    }

    fn earliestPendingCryptoOverlap(
        packet_space: PacketNumberSpaceView,
        start: u64,
        end: u64,
    ) Error!?PendingCryptoOverlap {
        var earliest: ?PendingCryptoOverlap = null;
        for (packet_space.crypto_recv_pending.items) |pending| {
            const pending_end = streamEndOffset(pending.offset, pending.data.len) orelse return error.InvalidPacket;
            const overlap_start = @max(start, pending.offset);
            const overlap_end = @min(end, pending_end);
            if (overlap_start >= overlap_end) continue;
            if (earliest == null or overlap_start < earliest.?.start) {
                earliest = .{
                    .pending = pending,
                    .start = overlap_start,
                    .end = overlap_end,
                };
            }
        }
        return earliest;
    }

    fn collectNewCryptoFrameDataSegments(
        self: *Connection,
        packet_space: PacketNumberSpaceView,
        offset: u64,
        data: []const u8,
        segments: ?*std.ArrayList(ReceiveCryptoFrameData),
    ) Error!void {
        if (data.len == 0) return;

        const contiguous_len = std.math.cast(u64, packet_space.crypto_recv_buffer.items.len) orelse return error.Internal;
        const end_offset = streamEndOffset(offset, data.len) orelse return error.InvalidPacket;
        var cursor = offset;

        if (cursor < contiguous_len) {
            const duplicate_len_u64 = @min(
                contiguous_len - cursor,
                end_offset - cursor,
            );
            const duplicate_len = std.math.cast(usize, duplicate_len_u64) orelse return error.InvalidPacket;
            const duplicate_start = std.math.cast(usize, cursor) orelse return error.InvalidPacket;
            const duplicate_end = std.math.add(usize, duplicate_start, duplicate_len) catch return error.InvalidPacket;
            const incoming_start = std.math.cast(usize, cursor - offset) orelse return error.InvalidPacket;
            if (!std.mem.eql(u8, packet_space.crypto_recv_buffer.items[duplicate_start..duplicate_end], data[incoming_start..][0..duplicate_len])) {
                return error.InvalidPacket;
            }
            cursor = streamEndOffset(cursor, duplicate_len) orelse return error.InvalidPacket;
            if (cursor == end_offset) return;
        }

        while (cursor < end_offset) {
            const overlap = try earliestPendingCryptoOverlap(packet_space, cursor, end_offset) orelse {
                const start_index = std.math.cast(usize, cursor - offset) orelse return error.InvalidPacket;
                if (segments) |out_segments| {
                    out_segments.append(self.allocator, .{
                        .offset = cursor,
                        .data = data[start_index..],
                    }) catch return error.OutOfMemory;
                }
                return;
            };

            if (overlap.start > cursor) {
                const start_index = std.math.cast(usize, cursor - offset) orelse return error.InvalidPacket;
                const segment_len = std.math.cast(usize, overlap.start - cursor) orelse return error.InvalidPacket;
                if (segments) |out_segments| {
                    out_segments.append(self.allocator, .{
                        .offset = cursor,
                        .data = data[start_index..][0..segment_len],
                    }) catch return error.OutOfMemory;
                }
                cursor = overlap.start;
            }

            const incoming_start = std.math.cast(usize, overlap.start - offset) orelse return error.InvalidPacket;
            const pending_start = std.math.cast(usize, overlap.start - overlap.pending.offset) orelse return error.InvalidPacket;
            const overlap_len = std.math.cast(usize, overlap.end - overlap.start) orelse return error.InvalidPacket;
            if (!std.mem.eql(
                u8,
                data[incoming_start..][0..overlap_len],
                overlap.pending.data[pending_start..][0..overlap_len],
            )) {
                return error.InvalidPacket;
            }
            cursor = overlap.end;
        }
    }

    fn pendingCryptoFrameIndexAt(packet_space: PacketNumberSpaceView, offset: u64) ?usize {
        for (packet_space.crypto_recv_pending.items, 0..) |pending, i| {
            if (pending.offset == offset) return i;
        }
        return null;
    }

    fn drainPendingCryptoFrames(self: *Connection, space: PacketNumberSpace) Error!void {
        var packet_space = self.packetNumberSpace(space);
        const start_len = packet_space.crypto_recv_buffer.items.len;
        var expected = std.math.cast(u64, start_len) orelse return error.Internal;
        var total_append_len: usize = 0;
        while (pendingCryptoFrameIndexAt(packet_space, expected)) |pending_index| {
            const pending = packet_space.crypto_recv_pending.items[pending_index];
            total_append_len = std.math.add(usize, total_append_len, pending.data.len) catch return error.InvalidPacket;
            expected = streamEndOffset(expected, pending.data.len) orelse return error.InvalidPacket;
        }

        if (total_append_len == 0) return;
        packet_space.crypto_recv_buffer.ensureUnusedCapacity(self.allocator, total_append_len) catch return error.OutOfMemory;

        expected = std.math.cast(u64, start_len) orelse return error.Internal;
        while (pendingCryptoFrameIndexAt(packet_space, expected)) |pending_index| {
            const pending = packet_space.crypto_recv_pending.items[pending_index];
            packet_space.crypto_recv_buffer.appendSliceAssumeCapacity(pending.data);
            expected = streamEndOffset(expected, pending.data.len) orelse return error.InvalidPacket;

            const removed = packet_space.crypto_recv_pending.orderedRemove(pending_index);
            self.allocator.free(removed.data);
        }
    }

    fn receiveCryptoFrame(
        self: *Connection,
        space: PacketNumberSpace,
        crypto: frame.CryptoFrame,
    ) Error!void {
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;

        const end_offset = streamEndOffset(crypto.offset, crypto.data.len) orelse return error.InvalidPacket;
        if (end_offset > self.config.max_crypto_buffer_size) return error.InvalidPacket;
        var new_frame_segments: std.ArrayList(ReceiveCryptoFrameData) = .empty;
        defer new_frame_segments.deinit(self.allocator);
        try self.collectNewCryptoFrameDataSegments(packet_space, crypto.offset, crypto.data, &new_frame_segments);

        for (new_frame_segments.items) |new_frame_data| {
            const contiguous_len = std.math.cast(u64, packet_space.crypto_recv_buffer.items.len) orelse return error.Internal;
            if (new_frame_data.offset == contiguous_len) {
                packet_space.crypto_recv_buffer.appendSlice(self.allocator, new_frame_data.data) catch return error.OutOfMemory;
            } else {
                try self.queueCryptoFrame(packet_space.crypto_recv_pending, new_frame_data.offset, new_frame_data.data);
            }
        }
    }

    fn receiveStreamFrame(self: *Connection, stream_frame: frame.StreamFrame) Error!void {
        if (stream_frame.stream_id > max_quic_varint) return error.InvalidStream;
        try self.validateIncomingStreamCount(stream_frame.stream_id);

        const end_offset = streamEndOffset(stream_frame.offset, stream_frame.data.len) orelse return error.InvalidPacket;
        const existing_state = self.findRecvStream(stream_frame.stream_id);
        const stream_receive_limit = if (existing_state) |stream_state| stream_state.max_data else self.recv_max_stream_data;
        if (end_offset > stream_receive_limit) return error.InvalidPacket;

        if (existing_state) |stream_state| {
            if (stream_state.final_size) |final_size| {
                if (end_offset > final_size) return error.InvalidPacket;
                if (stream_frame.fin and end_offset != final_size) return error.InvalidPacket;
                if (try streamFrameHasConflictingOverlap(stream_state.*, stream_frame.offset, stream_frame.data)) return error.InvalidPacket;
                const final_size_usize = std.math.cast(usize, final_size) orelse return error.Internal;
                if (stream_state.data.items.len >= final_size_usize) return;
                if (stream_state.reset_error_code != null) return;
            } else if (stream_state.reset_error_code != null) {
                return error.Internal;
            } else if (stream_frame.fin) {
                const highest_received = try highestReceivedStreamEndOffset(stream_state.*);
                if (end_offset < highest_received) return error.InvalidPacket;
            }
        }

        const stream_state = if (existing_state) |state| state else try self.ensureRecvStreamState(stream_frame.stream_id);

        var new_frame_segments: std.ArrayList(ReceiveStreamFrameData) = .empty;
        defer new_frame_segments.deinit(self.allocator);
        const new_frame_data_len = try self.collectNewRecvStreamDataSegments(
            stream_state.*,
            stream_frame.offset,
            stream_frame.data,
            &new_frame_segments,
        );
        const next_recv_total = streamEndOffset(self.recv_data_bytes, new_frame_data_len) orelse return error.InvalidPacket;
        if (next_recv_total > self.recv_max_data) return error.InvalidPacket;

        for (new_frame_segments.items) |new_frame_data| {
            const contiguous_len = std.math.cast(u64, stream_state.data.items.len) orelse return error.Internal;
            if (new_frame_data.offset == contiguous_len) {
                stream_state.data.appendSlice(self.allocator, new_frame_data.data) catch return error.OutOfMemory;
            } else {
                try self.appendPendingRecvStreamFrame(stream_state, new_frame_data.offset, new_frame_data.data);
            }
        }
        self.recv_data_bytes = next_recv_total;
        if (stream_frame.fin) {
            stream_state.final_size = end_offset;
        }
    }
};

/// Compatibility alias for callers using the earlier public name.
///
/// New code should use `Connection`; the alias keeps existing examples and
/// downstream experiments source-compatible while the API remains experimental.
pub const QuicConnection = Connection;
