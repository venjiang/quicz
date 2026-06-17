const packet = @import("packet.zig");
const protocol_limits = @import("protocol_limits.zig");
const transport_parameters = @import("transport_parameters.zig");
const transport_types = @import("transport_types.zig");

const Error = transport_types.Error;

const max_connection_id_len = protocol_limits.max_connection_id_len;
const min_active_connection_id_limit = protocol_limits.min_active_connection_id_limit;
const default_max_stored_new_tokens: usize = 4;
const default_max_crypto_buffer_size: u64 = 1 << 20;
const default_available_versions = [_]packet.Version{.v1};

/// Fixed-storage server preferred-address transport parameter value.
///
/// QUIC servers can advertise this parameter so clients know a preferred
/// address, replacement connection ID, and stateless reset token for future
/// migration. This value owns fixed connection ID storage so connection state
/// never borrows slices from parsed transport parameters.
pub const PreferredAddress = struct {
    /// Preferred IPv4 address.
    ipv4_address: [4]u8,
    /// Preferred IPv4 UDP port.
    ipv4_port: u16,
    /// Preferred IPv6 address.
    ipv6_address: [16]u8,
    /// Preferred IPv6 UDP port.
    ipv6_port: u16,
    /// Fixed storage for the preferred-address connection ID.
    connection_id: [max_connection_id_len]u8 = undefined,
    /// Number of valid bytes in `connection_id`; must be 1..20.
    connection_id_len: u8,
    /// Stateless reset token associated with `connection_id`.
    stateless_reset_token: [packet.stateless_reset_token_len]u8,

    /// Construct a preferred-address value with owned fixed CID storage.
    pub fn init(
        ipv4_address: [4]u8,
        ipv4_port: u16,
        ipv6_address: [16]u8,
        ipv6_port: u16,
        connection_id: []const u8,
        stateless_reset_token: [packet.stateless_reset_token_len]u8,
    ) Error!PreferredAddress {
        if (connection_id.len == 0 or connection_id.len > max_connection_id_len) return error.InvalidPacket;
        var result = PreferredAddress{
            .ipv4_address = ipv4_address,
            .ipv4_port = ipv4_port,
            .ipv6_address = ipv6_address,
            .ipv6_port = ipv6_port,
            .connection_id_len = @intCast(connection_id.len),
            .stateless_reset_token = stateless_reset_token,
        };
        @memcpy(result.connection_id[0..connection_id.len], connection_id);
        return result;
    }

    /// Copy a parsed transport-parameter preferred address into fixed storage.
    pub fn fromTransportParameter(preferred: transport_parameters.PreferredAddress) Error!PreferredAddress {
        return PreferredAddress.init(
            preferred.ipv4_address,
            preferred.ipv4_port,
            preferred.ipv6_address,
            preferred.ipv6_port,
            preferred.connection_id,
            preferred.stateless_reset_token,
        );
    }

    /// Borrow the valid preferred-address connection ID bytes.
    pub fn connectionId(self: *const PreferredAddress) []const u8 {
        return self.connection_id[0..@as(usize, self.connection_id_len)];
    }

    /// Convert to the typed transport-parameter view for encoding/export.
    pub fn asTransportParameter(self: *const PreferredAddress) transport_parameters.PreferredAddress {
        return .{
            .ipv4_address = self.ipv4_address,
            .ipv4_port = self.ipv4_port,
            .ipv6_address = self.ipv6_address,
            .ipv6_port = self.ipv6_port,
            .connection_id = self.connectionId(),
            .stateless_reset_token = self.stateless_reset_token,
        };
    }
};

/// Runtime configuration for a `Connection`.
pub const Config = struct {
    /// Maximum frame payload bytes accepted or emitted by the in-memory API.
    max_datagram_size: u16 = 1350,
    /// Maximum received CRYPTO stream end offset buffered per packet number space.
    ///
    /// Peers that exceed this limit are rejected; close-on-error receive APIs
    /// map that rejection to RFC 9000 `CRYPTO_BUFFER_EXCEEDED`.
    max_crypto_buffer_size: u64 = default_max_crypto_buffer_size,
    /// Initial RTT estimate used by recovery before the first ACK sample.
    initial_rtt_ms: u32 = 333,
    /// Local max_idle_timeout transport parameter in milliseconds. Zero disables the local side.
    max_idle_timeout_ms: u64 = 0,
    /// Local ACK delay exponent transport parameter used for ACK Delay encoding.
    ack_delay_exponent: u8 = 3,
    /// Local max_ack_delay transport parameter in milliseconds.
    max_ack_delay_ms: u32 = 25,
    /// Advertise that this endpoint does not support active connection migration.
    disable_active_migration: bool = false,
    /// Optional server stateless_reset_token transport parameter for the handshake CID.
    ///
    /// QUIC clients must not send this parameter, so client connections ignore
    /// this value when exporting local transport parameters.
    stateless_reset_token: ?[packet.stateless_reset_token_len]u8 = null,
    /// Optional server preferred_address transport parameter.
    ///
    /// Only server connections can advertise this value. Clients store a peer
    /// preferred address through `applyPeerTransportParameters()` instead.
    preferred_address: ?PreferredAddress = null,
    /// Initial connection-level stream data limit in both send and receive directions.
    initial_max_data: u64 = 65_536,
    /// Initial per-stream data limit in both send and receive directions.
    initial_max_stream_data: u64 = 65_536,
    /// Optional target receive connection window after application reads free data.
    ///
    /// When set, receive-side MAX_DATA refresh advertises at least this many
    /// bytes beyond the highest connection-level byte received so far. Null
    /// preserves the fixed-window behavior of replenishing exactly consumed
    /// bytes.
    receive_connection_window: ?u64 = null,
    /// Optional target receive stream window after application reads free data.
    ///
    /// When set, receive-side MAX_STREAM_DATA refresh advertises at least this
    /// many bytes beyond the highest byte received on that stream. Null
    /// preserves the fixed-window behavior of replenishing exactly consumed
    /// bytes.
    receive_stream_window: ?u64 = null,
    /// Optional target stream-count growth when a peer reports current-limit blocking.
    ///
    /// When set, STREAMS_BLOCKED_BIDI/UNI at or above the current receive
    /// stream-count limit grows the matching MAX_STREAMS by this many streams.
    /// Null preserves the existing behavior of only retransmitting stale limits
    /// or refreshing credit after completed peer-initiated streams.
    receive_stream_count_window: ?u64 = null,
    /// Initial bidirectional stream-count limit in both send and receive directions. Maximum is 2^60.
    initial_max_streams_bidi: u64 = 64,
    /// Initial unidirectional stream-count limit in both send and receive directions. Maximum is 2^60.
    initial_max_streams_uni: u64 = 64,
    /// Maximum active peer-issued connection IDs tracked by the connection skeleton.
    active_connection_id_limit: u64 = min_active_connection_id_limit,
    /// QUIC version advertised as this endpoint's chosen version.
    ///
    /// Protected long-packet and Retry helpers use this value for the wire
    /// version and version-specific long-header packet type bits. Short
    /// headers remain version independent. The value is also advertised in
    /// authenticated RFC 9368 version_information transport parameters.
    chosen_version: packet.Version = .v1,
    /// Versions advertised in the RFC 9368 Available Versions list.
    available_versions: []const packet.Version = &default_available_versions,
    /// Version selected after reacting to an RFC 8999 Version Negotiation packet.
    ///
    /// Client follow-up connections set this to enforce RFC 9368 downgrade
    /// validation against the server's authenticated Version Information.
    version_negotiation_selected_version: ?packet.Version = null,
    /// Maximum NEW_TOKEN values retained by client connections. A value of 0 discards tokens.
    max_stored_new_tokens: usize = default_max_stored_new_tokens,
    /// Enable RFC 9000 latency spin-bit signaling in the current single-path model.
    ///
    /// Disabled connections emit a deterministic false spin bit and ignore peer
    /// spin values. Future endpoint path state can reset this value when a new
    /// path or destination CID is selected.
    enable_spin_bit: bool = false,
};
