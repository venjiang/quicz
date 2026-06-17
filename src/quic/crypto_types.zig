const packet = @import("packet.zig");
const protection = @import("protection.zig");

/// TLS-produced Handshake traffic secrets for one QUIC connection.
///
/// `local` is this endpoint's write secret; `peer` is the remote endpoint's
/// write secret used for opening peer Handshake packets. QUIC key update does
/// not apply to Handshake keys.
pub const HandshakeTrafficSecrets = struct {
    /// This endpoint's Handshake write traffic secret.
    local: [protection.traffic_secret_len]u8,
    /// Peer endpoint's Handshake write traffic secret.
    peer: [protection.traffic_secret_len]u8,
};

/// TLS-produced 0-RTT traffic secrets for one QUIC connection.
///
/// 0-RTT packets are only sent by clients. `local` is the optional client write
/// secret for emitting early data, and `peer` is the optional client write
/// secret used by a server to open peer early-data packets.
pub const ZeroRttTrafficSecrets = struct {
    /// Optional local 0-RTT write traffic secret.
    local: ?[protection.traffic_secret_len]u8 = null,
    /// Optional peer 0-RTT write traffic secret.
    peer: ?[protection.traffic_secret_len]u8 = null,
};

/// TLS-produced 1-RTT traffic secrets for one QUIC connection.
///
/// `local` is this endpoint's write secret; `peer` is the remote endpoint's
/// write secret used for opening peer packets. The connection derives packet
/// protection keys and owns the resulting key-phase state.
pub const OneRttTrafficSecrets = struct {
    /// This endpoint's 1-RTT write traffic secret.
    local: [protection.traffic_secret_len]u8,
    /// Peer endpoint's 1-RTT write traffic secret.
    peer: [protection.traffic_secret_len]u8,
};

/// Progress reported by one `driveCryptoBackendInSpace()` call.
pub const CryptoBackendProgress = struct {
    /// Local transport-parameter extension bytes supplied to the backend.
    local_transport_parameters_bytes: usize = 0,
    /// Peer transport-parameter extension bytes pulled from the backend.
    peer_transport_parameters_bytes: usize = 0,
    /// Whether peer transport parameters were applied during this drive step.
    peer_transport_parameters_applied: bool = false,
    /// Compatible QUIC version selected while applying peer Version Information.
    peer_compatible_version_selected: ?packet.Version = null,
    /// Whether Handshake traffic secrets were installed during this drive step.
    handshake_keys_installed: bool = false,
    /// Whether any 0-RTT traffic secret was installed during this drive step.
    zero_rtt_keys_installed: bool = false,
    /// Whether 1-RTT traffic secrets were installed during this drive step.
    one_rtt_keys_installed: bool = false,
    /// Number of inbound CRYPTO chunks delivered to the backend.
    inbound_chunks: usize = 0,
    /// Number of inbound CRYPTO bytes delivered to the backend.
    inbound_bytes: usize = 0,
    /// Number of outbound backend chunks queued as CRYPTO data.
    outbound_chunks: usize = 0,
    /// Number of outbound backend bytes queued as CRYPTO data.
    outbound_bytes: usize = 0,
    /// Whether the connection is handshake-confirmed after the drive step.
    handshake_confirmed: bool = false,
};
