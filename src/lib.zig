const std = @import("std");

pub const packet = @import("quic/packet.zig");
pub const frame = @import("quic/frame.zig");
pub const recovery = @import("quic/recovery.zig");
pub const protection = @import("quic/protection.zig");
pub const address_validation_token = @import("quic/address_validation_token.zig");
pub const endpoint = @import("quic/endpoint.zig");
pub const transport_error = @import("quic/transport_error.zig");
pub const transport_parameters = @import("quic/transport_parameters.zig");
const transport_types = @import("quic/transport_types.zig");
const crypto_types = @import("quic/crypto_types.zig");
const tls_backend_module = @import("quic/tls_backend.zig");
pub const tls13 = @import("quic/tls13.zig");
pub const tls13_backend = @import("quic/tls13_backend.zig");
comptime {
    // Keep tls13 reachable so its tests run under `zig build test`.
    _ = tls13;
    _ = tls13_backend;
}
const endpoint_types = @import("quic/endpoint_types.zig");
const endpoint_timers = @import("quic/endpoint_timers.zig");
const connection_config = @import("quic/connection_config.zig");
const connection_rules = @import("quic/connection_rules.zig");
const connection_version = @import("quic/connection_version.zig");
const connection_state = @import("quic/connection_state.zig");
const packet_number_space = @import("quic/packet_number_space.zig");
const stream_id_rules = @import("quic/stream_id.zig");
const packet_context = @import("quic/packet_context.zig");
const protocol_limits = @import("quic/protocol_limits.zig");
const buffer = @import("quic/buffer.zig");
const wire_len = @import("quic/wire_len.zig");
const frame_rules = @import("quic/frame_rules.zig");
const frame_payload_module = @import("quic/frame_payload.zig");

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

test {
    _ = protection;
    _ = address_validation_token;
    _ = endpoint;
    _ = transport_error;
    _ = transport_parameters;
    _ = transport_types;
    _ = crypto_types;
    _ = tls_backend_module;
    _ = endpoint_types;
    _ = endpoint_timers;
    _ = connection_config;
    _ = connection_rules;
    _ = connection_version;
    _ = connection_state;
    _ = packet_number_space;
    _ = stream_id_rules;
    _ = wire_len;
    _ = frame_rules;
    _ = frame_payload_module;
    _ = connection_module;
    _ = endpoint_lifecycle_module;
}

test "frame payload helper exposes raw frame type value" {
    try std.testing.expectEqual(@as(u64, 0x1c), frame_payload_module.rawFrameTypeValue(&.{0x1c}));
}

test "frame payload helper classifies packet type close error" {
    const invalid_zero_rtt_ack = [_]u8{ 0x02, 0, 0, 0, 0 };
    const close = (try frame_payload_module.classifyCloseError(
        .zero_rtt,
        &invalid_zero_rtt_ack,
        std.testing.allocator,
    )).?;
    try std.testing.expectEqual(transport_error.TransportErrorCode.protocol_violation, close.code);
    try std.testing.expectEqual(@as(u64, 0x02), close.frame_type);
    try std.testing.expectEqualStrings("packet type", close.reason_phrase);
}

/// Endpoint result after accepting Version Negotiation and creating the follow-up connection.
pub const EndpointVersionNegotiationHandoffResult = struct {
    /// Version Negotiation endpoint state changes and follow-up route.
    followup: EndpointVersionNegotiationFollowupResult,
    /// Newly initialized client connection for the selected version.
    ///
    /// The caller owns this connection and must call `deinit()`.
    followup_connection: Connection,
};

/// Endpoint result after accepting Version Negotiation and emitting a follow-up Initial.
pub const EndpointVersionNegotiationProtectedInitialResult = struct {
    /// Endpoint-owned follow-up route and initialized client connection.
    handoff: EndpointVersionNegotiationHandoffResult,
    /// Caller-keyed protected Initial datagram emitted by `handoff.followup_connection`.
    ///
    /// The caller owns these bytes and must free them with the same allocator
    /// used by `handoff.followup_connection`.
    initial_datagram: []u8,
};

/// Caller-owned connection reference used by aggregate endpoint scheduling.
pub const EndpointConnectionView = struct {
    /// Caller-owned connection handle used by endpoint routing and timers.
    connection_id: u64,
    /// Caller-owned connection state. The lifecycle does not take ownership.
    connection: *const Connection,
};

/// Mutable caller-owned connection reference used by socket-loop deadline work.
pub const EndpointConnectionPollView = struct {
    /// Caller-owned connection handle used by endpoint routing and timers.
    connection_id: u64,
    /// Caller-owned connection state. The lifecycle does not take ownership.
    connection: *Connection,
    /// Destination connection ID to use when a due recovery wakeup emits a packet.
    destination_connection_id: []const u8,
    /// Source connection ID for long-header Handshake recovery packets.
    source_connection_id: []const u8 = &.{},
};

/// Mutable caller-owned connection plus explicit installed-key output options.
pub const EndpointConnectionInstalledKeyPollView = struct {
    /// Caller-owned connection handle used by endpoint routing and timers.
    connection_id: u64,
    /// Caller-owned connection state. The lifecycle does not take ownership.
    connection: *Connection,
    /// Installed-key output options to use when this connection's recovery deadline is selected.
    poll_options: EndpointPollInstalledKeyDatagramOptions,
};

/// Mutable caller-owned connection reference used by socket-loop receive dispatch.
pub const EndpointConnectionReceiveView = struct {
    /// Caller-owned connection handle used by endpoint routing and packet receive.
    connection_id: u64,
    /// Caller-owned connection state. The lifecycle does not take ownership.
    connection: *Connection,
};

/// Caller-owned connection/backend pair used by TLS drive sweeps.
pub const EndpointCryptoBackendDriveView = struct {
    /// Caller-owned connection handle used by endpoint timers.
    connection_id: u64,
    /// Caller-owned connection state. The lifecycle does not take ownership.
    connection: *Connection,
    /// TLS/crypto backend associated with `connection`.
    backend: CryptoBackend,
    /// Scratch buffer used for backend pull and transport-parameter bytes.
    scratch: []u8,
};

/// Endpoint-owned routing and recovery-timer lifecycle for connection handles.
///
/// This helper owns the endpoint router, aggregate loss/PTO timer table, and
/// ECN path policy for a socket event loop. It still does not own
/// `Connection` instances or perform socket I/O; callers pass the selected
/// connection into the timer/service paths and use this owner for datagram
/// routing and UDP-path policy decisions.
const endpoint_lifecycle_module = @import("quic/endpoint_lifecycle.zig");
pub const EndpointConnectionLifecycle = endpoint_lifecycle_module.EndpointConnectionLifecycle;

const connection_module = @import("quic/connection.zig");
pub const Connection = connection_module.Connection;
pub const QuicConnection = connection_module.Connection;
pub const framePacketTypeErrorCode = connection_module.framePacketTypeErrorCode;
