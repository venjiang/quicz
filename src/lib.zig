const std = @import("std");

pub const packet = @import("quic/packet.zig");
pub const frame = @import("quic/frame.zig");
pub const recovery = @import("quic/recovery.zig");
pub const pacer = @import("quic/pacer.zig");
pub const duration = @import("time/duration.zig");
pub const protection = @import("quic/protection.zig");
pub const address_validation_token = @import("quic/address_validation_token.zig");
pub const endpoint = @import("quic/endpoint.zig");
pub const runtime = struct {
    pub const server = @import("runtime/server.zig");
    pub const client = @import("runtime/client.zig");
    pub const h3_server = @import("runtime/h3_server.zig");
    pub const h3_client = @import("runtime/h3_client.zig");
};
pub const transport_error = @import("quic/transport_error.zig");
pub const transport_parameters = @import("quic/transport_parameters.zig");
const transport_types = @import("quic/transport_types.zig");
const crypto_types = @import("quic/crypto_types.zig");
const tls_backend_module = @import("quic/tls_backend.zig");
pub const tls13 = @import("tls/tls13.zig");
pub const pq_kex = @import("tls/pq_kex.zig");
pub const tls_pem = @import("tls/pem.zig");
pub const qlog = @import("qlog/qlog.zig");
pub const cubic = @import("quic/cubic.zig");
pub const pmtu = @import("quic/pmtu.zig");
pub const h3 = @import("h3/frame.zig");
pub const qpack = @import("h3/qpack.zig");
pub const h3_connection = @import("h3/connection.zig");
pub const h3_request = @import("h3/request.zig");
pub const h3_server = @import("h3/server.zig");
pub const h3_client = @import("h3/client.zig");
pub const webtransport = @import("h3/webtransport.zig");
pub const h3_limits = @import("h3/limits.zig");
pub const h3_datagram = @import("h3/datagram.zig");
const h3_fuzz_test = @import("h3/fuzz_test.zig");
const h3_integration_test = @import("h3/h3_integration_test.zig");
const quic_v2_test = @import("quic/quic_v2_test.zig");
const interop_coverage_test = @import("quic/interop_coverage_test.zig");
const datagram_ext_test = @import("quic/datagram_ext_test.zig");
pub const multipath = @import("quic/multipath.zig");
pub const lifecycle_options = @import("quic/lifecycle_options.zig");
pub const session_cache = @import("quic/session_cache.zig");
pub const gso = @import("quic/gso.zig");
pub const connection_pool = @import("quic/connection_pool.zig");
pub const metrics = @import("quic/metrics.zig");
pub const fuzz_targets = @import("quic/fuzz_targets.zig");
pub const migration = @import("quic/migration.zig");
pub const connectivity = struct {
    pub const path_selector = @import("connectivity/path_selector.zig");
    pub const stun = @import("connectivity/stun.zig");
    pub const stun_transaction = @import("connectivity/stun_transaction.zig");
    pub const punch_wire = @import("connectivity/punch_wire.zig");
    pub const punch_attempt = @import("connectivity/punch_attempt.zig");
};
const integration_tests = @import("quic/integration_tests.zig");
pub const udp_event_loop = @import("quic/udp_event_loop.zig");
pub const zero_rtt = @import("quic/zero_rtt.zig");
pub const stress_test = @import("quic/stress_test.zig");
pub const tls13_backend = @import("quic/tls13_backend.zig");
comptime {
    // Keep tls13 reachable so its tests run under `zig build test`.
    _ = tls13;
    _ = pq_kex;
    _ = qlog;
    _ = cubic;
    _ = @import("quic/connection_tests.zig");
    _ = @import("quic/tls13_server_endpoint_tests.zig");
    _ = pacer;
    _ = duration;
    _ = pmtu;
    _ = h3;
    _ = qpack;
    _ = h3_connection;
    _ = h3_request;
    _ = h3_server;
    _ = h3_client;
    _ = webtransport;
    _ = h3_limits;
    _ = h3_datagram;
    _ = h3_fuzz_test;
    _ = h3_integration_test;
    _ = quic_v2_test;
    _ = interop_coverage_test;
    _ = datagram_ext_test;
    _ = multipath;
    _ = lifecycle_options;
    _ = session_cache;
    _ = gso;
    _ = connection_pool;
    _ = metrics;
    _ = fuzz_targets;
    _ = migration;
    _ = connectivity.path_selector;
    _ = connectivity.stun;
    _ = connectivity.stun_transaction;
    _ = connectivity.punch_wire;
    _ = connectivity.punch_attempt;
    _ = integration_tests;
    _ = udp_event_loop;
    _ = zero_rtt;
    _ = stress_test;
    _ = tls13_backend;
}
pub const endpoint_types = @import("quic/endpoint_types.zig");
const endpoint_timers = @import("quic/endpoint_timers.zig");
const connection_config = @import("quic/connection_config.zig");
const connection_rules = @import("quic/connection_rules.zig");
const connection_version = @import("quic/connection_version.zig");
const connection_state = @import("quic/connection_state.zig");
const packet_number_space = @import("quic/packet_number_space.zig");
const stream_id_rules = @import("quic/stream_id.zig");
const packet_context = @import("quic/packet_context.zig");
const protocol_limits = @import("quic/protocol_limits.zig");
pub const buffer = @import("quic/buffer.zig");
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
pub const EndpointLossDetectionTimers = endpoint_timers.EndpointLossDetectionTimers;
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
    followup: endpoint_types.EndpointVersionNegotiationFollowupResult,
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
    poll_options: endpoint_types.EndpointPollInstalledKeyDatagramOptions,
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

const endpoint_connection_registry_module = @import("quic/endpoint_connection_registry.zig");
pub const EndpointConnectionRegistry = endpoint_connection_registry_module.EndpointConnectionRegistry;
test {
    _ = endpoint_connection_registry_module;
}

const tls13_client_transport_module = @import("quic/tls13_client_transport.zig");
pub const Tls13ClientTransport = tls13_client_transport_module.Tls13ClientTransport;
test {
    _ = tls13_client_transport_module;
}

const tls13_client_endpoint_module = @import("quic/tls13_client_endpoint.zig");
pub const Tls13ClientEndpoint = tls13_client_endpoint_module.Tls13ClientEndpoint;
test {
    _ = tls13_client_endpoint_module;
}

const tls13_server_transport_module = @import("quic/tls13_server_transport.zig");
pub const Tls13ServerTransport = tls13_server_transport_module.Tls13ServerTransport;
test {
    _ = tls13_server_transport_module;
}

const tls13_server_endpoint_module = @import("quic/tls13_server_endpoint.zig");
pub const Tls13ServerEndpoint = tls13_server_endpoint_module.Tls13ServerEndpoint;
test {
    _ = tls13_server_endpoint_module;
}

const connection_module = @import("quic/connection.zig");
pub const Connection = connection_module.Connection;
pub const QuicConnection = connection_module.Connection;
pub const framePacketTypeErrorCode = connection_module.framePacketTypeErrorCode;
