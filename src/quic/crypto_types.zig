const packet = @import("packet.zig");
const protection = @import("protection.zig");
const transport_types = @import("transport_types.zig");

const Error = transport_types.Error;
const PacketNumberSpace = transport_types.PacketNumberSpace;
const VersionCompatibility = transport_types.VersionCompatibility;

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
    /// Whether Handshake packet-space state and keys were discarded during this drive step.
    handshake_space_discarded: bool = false,
    /// Whether any 0-RTT traffic secret was installed during this drive step.
    zero_rtt_keys_installed: bool = false,
    /// Whether installed 0-RTT packet-protection keys were discarded during this drive step.
    zero_rtt_keys_discarded: bool = false,
    /// TLS early-data acceptance observed during this drive step.
    ///
    /// `null` means TLS has not reported an acceptance decision. `true` means
    /// the server accepted offered 0-RTT. `false` means it rejected offered
    /// 0-RTT, so a client must stop sending early data.
    zero_rtt_accepted: ?bool = null,
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
    /// Whether a TLS-negotiated application protocol (ALPN) was confirmed
    /// during this drive step. Only set when the backend exposes an ALPN hook
    /// and the handshake is confirmed. A confirmed handshake with this field
    /// false indicates an RFC 9001 §8.1 no_application_protocol condition.
    application_protocol_negotiated: bool = false,
};

/// Pluggable TLS/crypto backend hook driven by QUIC CRYPTO byte streams.
///
/// The connection owns QUIC packet-number-space buffering and packetization;
/// the backend owns TLS transcript parsing, handshake data production, and
/// handshake-complete decisions. Callback errors abort the current drive step.
pub const CryptoBackend = struct {
    /// Opaque backend state passed to all callbacks.
    context: *anyopaque,
    /// Consume contiguous CRYPTO bytes received in `space`.
    receive: *const fn (context: *anyopaque, space: PacketNumberSpace, data: []const u8) Error!void,
    /// Copy backend-produced CRYPTO bytes for `space` into `out_buf`.
    ///
    /// Return null when no bytes are currently available. Non-empty returned
    /// slices are copied into connection-owned CRYPTO send queues before this
    /// callback is invoked again.
    pull: *const fn (context: *anyopaque, space: PacketNumberSpace, out_buf: []u8) Error!?[]const u8,
    /// Optional hook receiving this endpoint's encoded transport parameters.
    ///
    /// The slice is valid only during the callback; backends that need to hold
    /// it for TLS transcript construction must copy it. The connection may call
    /// this more than once, so backends should treat it as idempotent setup.
    set_local_transport_parameters: ?*const fn (context: *anyopaque, data: []const u8) Error!void = null,
    /// Optional hook returning peer transport-parameter extension bytes.
    ///
    /// Return null until no new peer extension is available. Backends should
    /// return each parsed peer extension at most once because applying
    /// transport parameters resets initial peer limits.
    pull_peer_transport_parameters: ?*const fn (context: *anyopaque, out_buf: []u8) Error!?[]const u8 = null,
    /// Optional hook returning TLS-produced Handshake traffic secrets.
    ///
    /// Return null until secrets are available. The connection derives packet
    /// protection keys for installed-key Handshake long-packet helpers.
    pull_handshake_traffic_secrets: ?*const fn (context: *anyopaque) Error!?HandshakeTrafficSecrets = null,
    /// Optional hook returning TLS-produced 0-RTT traffic secrets.
    ///
    /// Return null until secrets are available. Clients usually return `local`
    /// and servers usually return `peer`.
    pull_zero_rtt_traffic_secrets: ?*const fn (context: *anyopaque) Error!?ZeroRttTrafficSecrets = null,
    /// Optional server-side hook that tells TLS whether the connection policy
    /// accepted offered early data before EncryptedExtensions is emitted.
    set_early_data_accepted: ?*const fn (context: *anyopaque, accepted: bool) Error!void = null,
    /// Optional client-side hook returning the server's EncryptedExtensions
    /// early-data decision. Return null until the decision is known.
    early_data_accepted: ?*const fn (context: *anyopaque) ?bool = null,
    /// Optional hook returning TLS-produced 1-RTT traffic secrets.
    ///
    /// Return null until secrets are available. The connection derives packet
    /// protection keys and installs endpoint-owned key-phase state from the
    /// returned secrets.
    pull_1rtt_traffic_secrets: ?*const fn (context: *anyopaque) Error!?OneRttTrafficSecrets = null,
    /// Optional hook returning the TLS-negotiated ALPN protocol bytes.
    ///
    /// Return null when negotiation has not completed or the backend does not
    /// expose ALPN. Non-empty slices indicate successful negotiation. The
    /// connection checks this after handshake confirmation to satisfy
    /// RFC 9001 §8.1.
    pull_negotiated_alpn: ?*const fn (context: *anyopaque, out_buf: []u8) Error!?[]const u8 = null,
    /// Optional handshake-complete probe. When true, the connection marks the
    /// modeled handshake confirmed after CRYPTO input/output has been driven.
    handshake_confirmed: ?*const fn (context: *anyopaque) bool = null,

    pub fn isHandshakeConfirmed(self: CryptoBackend) bool {
        if (self.handshake_confirmed) |confirmed| return confirmed(self.context);
        return false;
    }

    pub fn setLocalTransportParameters(self: CryptoBackend, data: []const u8) Error!bool {
        const set_local = self.set_local_transport_parameters orelse return false;
        try set_local(self.context, data);
        return true;
    }

    pub fn pullPeerTransportParameters(self: CryptoBackend, out_buf: []u8) Error!?[]const u8 {
        const pull_peer = self.pull_peer_transport_parameters orelse return null;
        return try pull_peer(self.context, out_buf);
    }

    pub fn pullHandshakeTrafficSecrets(self: CryptoBackend) Error!?HandshakeTrafficSecrets {
        const pull_secrets = self.pull_handshake_traffic_secrets orelse return null;
        return try pull_secrets(self.context);
    }

    pub fn pullZeroRttTrafficSecrets(self: CryptoBackend) Error!?ZeroRttTrafficSecrets {
        const pull_secrets = self.pull_zero_rtt_traffic_secrets orelse return null;
        return try pull_secrets(self.context);
    }

    pub fn setEarlyDataAccepted(self: CryptoBackend, accepted: bool) Error!bool {
        const set_accepted = self.set_early_data_accepted orelse return false;
        try set_accepted(self.context, accepted);
        return true;
    }

    pub fn earlyDataAccepted(self: CryptoBackend) ?bool {
        const accepted = self.early_data_accepted orelse return null;
        return accepted(self.context);
    }

    pub fn pullOneRttTrafficSecrets(self: CryptoBackend) Error!?OneRttTrafficSecrets {
        const pull_secrets = self.pull_1rtt_traffic_secrets orelse return null;
        return try pull_secrets(self.context);
    }

    pub fn pullNegotiatedAlpn(self: CryptoBackend, out_buf: []u8) Error!?[]const u8 {
        const pull_alpn = self.pull_negotiated_alpn orelse return null;
        return try pull_alpn(self.context, out_buf);
    }
};

/// Peer transport-parameter handling policy for a crypto-backend drive step.
///
/// `Connection` uses this to decide how peer transport-parameter extension
/// bytes returned by a backend are applied: `strict` and `close_on_error`
/// enforce QUIC v1 parameters, while the compatible variants accept RFC 9368
/// compatible version negotiation using the caller-provided first-flight
/// conversions. The `*_close_on_error` variants queue CONNECTION_CLOSE instead
/// of returning the parameter error to the caller.
pub const PeerTransportParameterDrivePolicy = union(enum) {
    strict,
    close_on_error,
    compatible: []const VersionCompatibility,
    compatible_close_on_error: []const VersionCompatibility,
};
