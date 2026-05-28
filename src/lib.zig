const std = @import("std");

pub const packet = @import("quic/packet.zig");
pub const frame = @import("quic/frame.zig");
pub const recovery = @import("quic/recovery.zig");
pub const protection = @import("quic/protection.zig");
pub const address_validation_token = @import("quic/address_validation_token.zig");
pub const endpoint = @import("quic/endpoint.zig");
pub const transport_error = @import("quic/transport_error.zig");
pub const transport_parameters = @import("quic/transport_parameters.zig");
const buffer = @import("quic/buffer.zig");

test {
    _ = protection;
    _ = address_validation_token;
    _ = endpoint;
    _ = transport_error;
    _ = transport_parameters;
}

const max_quic_varint = 4611686018427387903;
const max_stream_count = @as(u64, 1) << 60;
const max_connection_id_len = 20;
const min_initial_destination_connection_id_len = 8;
const min_initial_udp_datagram_len = 1200;
const min_active_connection_id_limit = 2;
const default_max_stored_new_tokens: usize = 4;
const close_state_pto_multiplier: u64 = 3;
const max_path_challenge_transmissions: u8 = 3;
const packet_threshold_loss_gap: u64 = 3;
const anti_amplification_multiplier: usize = 3;
const default_available_versions = [_]packet.Version{.v1};

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

/// Runtime configuration for a `QuicConnection`.
pub const Config = struct {
    /// Maximum frame payload bytes accepted or emitted by the in-memory API.
    max_datagram_size: u16 = 1350,
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
    /// The connection skeleton still emits QUIC v1 packet headers in most
    /// packetized helpers; this value is currently used for authenticated
    /// RFC 9368 version_information transport-parameter exchange.
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

/// Endpoint role. It determines the locally initiated stream IDs.
pub const ConnectionSide = enum { client, server };

fn isZeroVersion(version: packet.Version) bool {
    return @intFromEnum(version) == 0;
}

fn versionListContains(versions: []const packet.Version, version: packet.Version) bool {
    for (versions) |candidate| {
        if (@intFromEnum(candidate) == @intFromEnum(version)) return true;
    }
    return false;
}

fn statelessResetTokensEqual(
    a: [packet.stateless_reset_token_len]u8,
    b: [packet.stateless_reset_token_len]u8,
) bool {
    return std.crypto.timing_safe.eql([packet.stateless_reset_token_len]u8, a, b);
}

fn selectMutualVersion(preferred_versions: []const packet.Version, offered_versions: []const packet.Version) ?packet.Version {
    for (preferred_versions) |preferred| {
        if (versionListContains(offered_versions, preferred)) return preferred;
    }
    return null;
}

fn selectMutualVersionWithExtra(
    preferred_versions: []const packet.Version,
    offered_versions: []const packet.Version,
    extra_version: packet.Version,
) ?packet.Version {
    for (preferred_versions) |preferred| {
        if (@intFromEnum(preferred) == @intFromEnum(extra_version) or versionListContains(offered_versions, preferred)) {
            return preferred;
        }
    }
    return null;
}

fn validateLocalVersionInformation(side: ConnectionSide, config: Config) Error!void {
    if (isZeroVersion(config.chosen_version)) return error.InvalidPacket;
    for (config.available_versions) |available| {
        if (isZeroVersion(available)) return error.InvalidPacket;
    }
    if (side == .client) {
        if (config.available_versions.len == 0) return error.InvalidPacket;
        if (!versionListContains(config.available_versions, config.chosen_version)) return error.InvalidPacket;
    }
    if (config.version_negotiation_selected_version) |selected| {
        if (side != .client) return error.InvalidPacket;
        if (isZeroVersion(selected)) return error.InvalidPacket;
        if (@intFromEnum(selected) != @intFromEnum(config.chosen_version)) return error.InvalidPacket;
        if (!versionListContains(config.available_versions, selected)) return error.InvalidPacket;
    }
}

fn validateInitialDestinationConnectionIdLength(dcid: []const u8) Error!void {
    if (dcid.len < min_initial_destination_connection_id_len or dcid.len > max_connection_id_len) {
        return error.InvalidPacket;
    }
}

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

/// Transport-layer close information received from the peer.
///
/// The reason phrase slice is owned by the connection and remains valid until
/// `deinit()`. A null `peerClose()` result means no peer close frame has been
/// accepted yet.
pub const PeerClose = union(enum) {
    /// Peer sent a transport CONNECTION_CLOSE frame.
    connection: struct {
        /// QUIC transport error code carried by the peer.
        error_code: u64,
        /// Frame type that triggered the close, or 0 when not frame-specific.
        frame_type: u64,
        /// Peer-provided diagnostic reason phrase.
        reason_phrase: []const u8,
    },
    /// Peer sent an application CONNECTION_CLOSE frame.
    application: struct {
        /// Application error code carried by the peer.
        error_code: u64,
        /// Peer-provided diagnostic reason phrase.
        reason_phrase: []const u8,
    },
};

/// Modeled QUIC handshake progress for the experimental frame-payload API.
pub const HandshakeState = enum {
    /// Only Initial-level state has been observed or queued.
    initial,
    /// Handshake packet number space is active but the handshake is not confirmed.
    handshake,
    /// The handshake has been confirmed by HANDSHAKE_DONE or an external TLS hook.
    confirmed,
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

/// Cause that arms the modeled QUIC loss detection timer.
pub const LossDetectionTimerKind = enum {
    /// Time-threshold loss detection is pending.
    loss_time,
    /// Probe Timeout is pending for ack-eliciting data in flight.
    pto,
};

/// Earliest modeled QUIC loss detection timer deadline.
///
/// `deadline_millis` uses the same caller-controlled millisecond clock passed
/// to send, receive, and recovery APIs. When any packet number space has a
/// loss-time deadline, RFC 9002 gives that timer precedence over PTO.
pub const LossDetectionTimerDeadline = struct {
    /// Packet number space whose timer should be serviced.
    space: PacketNumberSpace,
    /// Timer cause to handle at `deadline_millis`.
    kind: LossDetectionTimerKind,
    /// Absolute deadline in the connection's caller-controlled millisecond clock.
    deadline_millis: i64,
};

/// Endpoint-owned scheduled loss detection timer for one connection handle.
///
/// The endpoint stores the caller's connection handle alongside the connection's
/// current aggregate recovery timer. The `timer` field remains connection-owned
/// recovery state; endpoint code uses this wrapper to choose which connection
/// should be serviced next.
pub const EndpointLossDetectionTimerDeadline = struct {
    /// Caller-owned connection handle used by endpoint routing and event loops.
    connection_id: u64,
    /// Connection-level aggregate loss/PTO timer snapshot.
    timer: LossDetectionTimerDeadline,
};

/// Endpoint/event-loop owner for QUIC loss detection timer scheduling.
///
/// This helper does not own `QuicConnection` objects and performs no socket I/O.
/// Call `armFromConnection()` after packet send, ACK processing, key discard, or
/// timer service to mirror the connection's current aggregate recovery timer.
/// `earliestDeadline()` returns the next connection handle to wake, and
/// `serviceConnection()` dispatches the due timer through the connection helper
/// before refreshing endpoint scheduling state.
pub const EndpointLossDetectionTimers = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(EndpointLossDetectionTimerDeadline) = .empty,

    /// Create an empty endpoint recovery timer owner.
    pub fn init(allocator: std.mem.Allocator) EndpointLossDetectionTimers {
        return .{ .allocator = allocator };
    }

    /// Release all endpoint timer storage.
    pub fn deinit(self: *EndpointLossDetectionTimers) void {
        self.entries.deinit(self.allocator);
    }

    /// Return the number of connection timers currently armed by the endpoint.
    pub fn count(self: *const EndpointLossDetectionTimers) usize {
        return self.entries.items.len;
    }

    /// Mirror one connection's current aggregate loss/PTO timer.
    ///
    /// If the connection has no armed recovery timer, any existing endpoint
    /// entry for `connection_id` is removed. Otherwise the existing entry is
    /// updated or a new entry is appended.
    pub fn armFromConnection(
        self: *EndpointLossDetectionTimers,
        connection_id: u64,
        connection: *const QuicConnection,
    ) Error!void {
        try self.update(connection_id, connection.lossDetectionTimerDeadlineMillis());
    }

    /// Remove one connection timer from endpoint scheduling state.
    pub fn disarmConnection(self: *EndpointLossDetectionTimers, connection_id: u64) bool {
        const index = self.findIndex(connection_id) orelse return false;
        _ = self.entries.orderedRemove(index);
        return true;
    }

    /// Return the earliest connection-level recovery timer known to the endpoint.
    pub fn earliestDeadline(self: *const EndpointLossDetectionTimers) ?EndpointLossDetectionTimerDeadline {
        if (self.entries.items.len == 0) return null;
        var earliest = self.entries.items[0];
        for (self.entries.items[1..]) |entry| {
            if (entry.timer.deadline_millis < earliest.timer.deadline_millis) {
                earliest = entry;
            }
        }
        return earliest;
    }

    /// Service one connection's due loss detection timer and refresh scheduling.
    ///
    /// This is the endpoint event-loop bridge for a caller-owned connection
    /// selected by `earliestDeadline()`. It is safe to call before the deadline:
    /// the connection helper is a no-op and the endpoint entry is refreshed from
    /// the connection's current timer. A connection with no remaining timer is
    /// disarmed.
    pub fn serviceConnection(
        self: *EndpointLossDetectionTimers,
        connection_id: u64,
        connection: *QuicConnection,
        now_millis: i64,
    ) Error!?EndpointLossDetectionTimerDeadline {
        const serviced = try connection.serviceLossDetectionTimer(now_millis);
        try self.armFromConnection(connection_id, connection);
        const timer = serviced orelse return null;
        return .{
            .connection_id = connection_id,
            .timer = timer,
        };
    }

    /// Set or clear a connection timer from an already computed deadline.
    pub fn update(
        self: *EndpointLossDetectionTimers,
        connection_id: u64,
        timer: ?LossDetectionTimerDeadline,
    ) Error!void {
        const index = self.findIndex(connection_id);
        if (timer) |deadline| {
            const entry = EndpointLossDetectionTimerDeadline{
                .connection_id = connection_id,
                .timer = deadline,
            };
            if (index) |existing| {
                self.entries.items[existing] = entry;
            } else {
                self.entries.append(self.allocator, entry) catch return error.OutOfMemory;
            }
        } else if (index) |existing| {
            _ = self.entries.orderedRemove(existing);
        }
    }

    fn findIndex(self: *const EndpointLossDetectionTimers, connection_id: u64) ?usize {
        for (self.entries.items, 0..) |entry, index| {
            if (entry.connection_id == connection_id) return index;
        }
        return null;
    }
};

/// Result of retiring one endpoint connection handle.
pub const EndpointConnectionRetireResult = struct {
    /// Number of active destination-CID routes removed for the connection.
    routes_retired: usize,
    /// Whether an armed loss/PTO timer was removed for the connection.
    recovery_timer_disarmed: bool,
};

/// Endpoint-owned routing and recovery-timer lifecycle for connection handles.
///
/// This helper owns the endpoint router and aggregate loss/PTO timer table for
/// a socket event loop. It still does not own `QuicConnection` instances or
/// perform socket I/O; callers pass the selected connection into the timer
/// service path and use `router` for datagram routing.
pub const EndpointConnectionLifecycle = struct {
    /// Destination-CID router owned by this endpoint lifecycle.
    router: endpoint.EndpointRouter,
    /// Aggregate loss/PTO timers keyed by caller-owned connection handle.
    recovery_timers: EndpointLossDetectionTimers,

    /// Create an endpoint lifecycle owner with empty routes and timers.
    pub fn init(allocator: std.mem.Allocator) EndpointConnectionLifecycle {
        return .{
            .router = endpoint.EndpointRouter.init(allocator),
            .recovery_timers = EndpointLossDetectionTimers.init(allocator),
        };
    }

    /// Release route and timer storage owned by this endpoint lifecycle.
    pub fn deinit(self: *EndpointConnectionLifecycle) void {
        self.recovery_timers.deinit();
        self.router.deinit();
    }

    /// Return the number of active destination-CID routes.
    pub fn routeCount(self: *const EndpointConnectionLifecycle) usize {
        return self.router.routeCount();
    }

    /// Return the number of armed recovery timers.
    pub fn recoveryTimerCount(self: *const EndpointConnectionLifecycle) usize {
        return self.recovery_timers.count();
    }

    /// Register a destination connection ID for a caller-owned connection.
    pub fn registerConnectionId(
        self: *EndpointConnectionLifecycle,
        connection_id: u64,
        destination_connection_id: []const u8,
        path: endpoint.Udp4Tuple,
        options: endpoint.RouteOptions,
    ) endpoint.RouteError!void {
        return self.router.registerConnectionId(connection_id, destination_connection_id, path, options);
    }

    /// Route one received datagram using the owned endpoint routing table.
    pub fn routeDatagram(
        self: *const EndpointConnectionLifecycle,
        path: endpoint.Udp4Tuple,
        datagram: []const u8,
    ) endpoint.RouteError!endpoint.RouteResult {
        return self.router.routeDatagram(path, datagram);
    }

    /// Mirror one connection's current aggregate loss/PTO timer.
    pub fn armRecoveryTimerFromConnection(
        self: *EndpointConnectionLifecycle,
        connection_id: u64,
        connection: *const QuicConnection,
    ) Error!void {
        try self.recovery_timers.armFromConnection(connection_id, connection);
    }

    /// Return the earliest connection-level recovery timer known to the endpoint.
    pub fn earliestRecoveryDeadline(self: *const EndpointConnectionLifecycle) ?EndpointLossDetectionTimerDeadline {
        return self.recovery_timers.earliestDeadline();
    }

    /// Service one connection's due loss/PTO timer and refresh endpoint state.
    pub fn serviceRecoveryTimer(
        self: *EndpointConnectionLifecycle,
        connection_id: u64,
        connection: *QuicConnection,
        now_millis: i64,
    ) Error!?EndpointLossDetectionTimerDeadline {
        return self.recovery_timers.serviceConnection(connection_id, connection, now_millis);
    }

    /// Poll one installed-key protected 1-RTT datagram and refresh recovery scheduling.
    ///
    /// This is the endpoint event-loop bridge for the common "connection owns
    /// packet protection keys, endpoint owns timers" boundary. The returned
    /// datagram remains allocated by `connection` and must be freed by the
    /// caller. If timer refresh fails after a datagram is produced, the helper
    /// frees that datagram before returning the error.
    pub fn pollProtectedShortDatagramWithInstalledKeys(
        self: *EndpointConnectionLifecycle,
        connection_id: u64,
        connection: *QuicConnection,
        now_millis: i64,
        dcid: []const u8,
    ) Error!?[]u8 {
        const datagram = try connection.pollProtectedShortDatagramWithInstalledKeys(now_millis, dcid);
        errdefer if (datagram) |bytes| connection.allocator.free(bytes);
        try self.armRecoveryTimerFromConnection(connection_id, connection);
        return datagram;
    }

    /// Process one installed-key protected 1-RTT datagram and refresh timers.
    ///
    /// ACK processing, loss recovery cleanup, and ACK generation state stay in
    /// the connection. The endpoint lifecycle mirrors the resulting aggregate
    /// loss/PTO timer so socket event loops do not need a separate manual
    /// refresh after every protected receive.
    pub fn processProtectedShortDatagramWithInstalledKeys(
        self: *EndpointConnectionLifecycle,
        connection_id: u64,
        connection: *QuicConnection,
        now_millis: i64,
        dcid_len: usize,
        datagram: []const u8,
    ) Error!void {
        try connection.processProtectedShortDatagramWithInstalledKeys(now_millis, dcid_len, datagram);
        try self.armRecoveryTimerFromConnection(connection_id, connection);
    }

    /// Retire all routes and any armed recovery timer for one connection handle.
    pub fn retireConnection(self: *EndpointConnectionLifecycle, connection_id: u64) EndpointConnectionRetireResult {
        return .{
            .routes_retired = self.router.retireConnectionRoutes(connection_id),
            .recovery_timer_disarmed = self.recovery_timers.disarmConnection(connection_id),
        };
    }
};

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
    /// Optional hook returning TLS-produced 1-RTT traffic secrets.
    ///
    /// Return null until secrets are available. The connection derives packet
    /// protection keys and installs endpoint-owned key-phase state from the
    /// returned secrets.
    pull_1rtt_traffic_secrets: ?*const fn (context: *anyopaque) Error!?OneRttTrafficSecrets = null,
    /// Optional handshake-complete probe. When true, the connection marks the
    /// modeled handshake confirmed after CRYPTO input/output has been driven.
    handshake_confirmed: ?*const fn (context: *anyopaque) bool = null,

    fn isHandshakeConfirmed(self: CryptoBackend) bool {
        if (self.handshake_confirmed) |confirmed| return confirmed(self.context);
        return false;
    }

    fn setLocalTransportParameters(self: CryptoBackend, data: []const u8) Error!bool {
        const set_local = self.set_local_transport_parameters orelse return false;
        try set_local(self.context, data);
        return true;
    }

    fn pullPeerTransportParameters(self: CryptoBackend, out_buf: []u8) Error!?[]const u8 {
        const pull_peer = self.pull_peer_transport_parameters orelse return null;
        return try pull_peer(self.context, out_buf);
    }

    fn pullHandshakeTrafficSecrets(self: CryptoBackend) Error!?HandshakeTrafficSecrets {
        const pull_secrets = self.pull_handshake_traffic_secrets orelse return null;
        return try pull_secrets(self.context);
    }

    fn pullZeroRttTrafficSecrets(self: CryptoBackend) Error!?ZeroRttTrafficSecrets {
        const pull_secrets = self.pull_zero_rtt_traffic_secrets orelse return null;
        return try pull_secrets(self.context);
    }

    fn pullOneRttTrafficSecrets(self: CryptoBackend) Error!?OneRttTrafficSecrets {
        const pull_secrets = self.pull_1rtt_traffic_secrets orelse return null;
        return try pull_secrets(self.context);
    }
};

/// Progress reported by one `driveCryptoBackendInSpace()` call.
pub const CryptoBackendProgress = struct {
    /// Local transport-parameter extension bytes supplied to the backend.
    local_transport_parameters_bytes: usize = 0,
    /// Peer transport-parameter extension bytes pulled from the backend.
    peer_transport_parameters_bytes: usize = 0,
    /// Whether peer transport parameters were applied during this drive step.
    peer_transport_parameters_applied: bool = false,
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

/// Caller-supplied keys for protected long-packet receive routing.
///
/// `initial` is required when a coalesced datagram contains Initial packets.
/// `zero_rtt` is required when it contains 0-RTT packets. `handshake` is
/// required when it contains Handshake packets unless the installed-key
/// Handshake helpers are used. Real TLS transcript ownership and automatic key
/// discard remain future endpoint/TLS work.
pub const ProtectedLongDatagramKeys = struct {
    /// Keys used to open protected Initial long packets.
    initial: ?protection.Aes128PacketProtectionKeys = null,
    /// Keys used to open protected 0-RTT long packets.
    zero_rtt: ?protection.Aes128PacketProtectionKeys = null,
    /// Keys used to open protected Handshake long packets.
    handshake: ?protection.Aes128PacketProtectionKeys = null,
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

const EcnAckValidationResult = struct {
    ce_congestion_event: bool = false,
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

const BuiltProtectedLongPacket = struct {
    space: PacketNumberSpace,
    packet_number: u64,
    datagram: []u8,
    ack_eliciting: bool,
    sent_stream_frame: ?PendingStreamFrame = null,
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
    }
};

const BuiltProtectedShortPacket = struct {
    packet_number: u64,
    datagram: []u8,
    ack_eliciting: bool,
    sent_stream_frame: ?PendingStreamFrame = null,
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
    }
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

const PeerCloseSnapshot = enum { absent, present };

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
    stream_frame: ?PendingStreamFrame = null,
    crypto_frame: ?PendingCryptoFrame = null,
    reset_stream_frame: ?frame.ResetStreamFrame = null,
    stop_sending_frame: ?frame.StopSendingFrame = null,

    fn deinit(self: *SentPacket, allocator: std.mem.Allocator) void {
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

fn deinitPendingStreamFrameSlice(allocator: std.mem.Allocator, frames: []PendingStreamFrame) void {
    for (frames) |pending| {
        allocator.free(pending.data);
    }
}

fn deinitPendingCryptoFrameSlice(allocator: std.mem.Allocator, frames: []PendingCryptoFrame) void {
    for (frames) |pending| {
        allocator.free(pending.data);
    }
}

fn deinitSentPacketSlice(allocator: std.mem.Allocator, sent_packets: []SentPacket) void {
    for (sent_packets) |*sent_packet| {
        sent_packet.deinit(allocator);
    }
}

fn clearSentPacketList(allocator: std.mem.Allocator, sent_packets: *std.ArrayList(SentPacket)) void {
    deinitSentPacketSlice(allocator, sent_packets.items);
    sent_packets.items.len = 0;
}

fn deinitSentPacketList(allocator: std.mem.Allocator, sent_packets: *std.ArrayList(SentPacket)) void {
    clearSentPacketList(allocator, sent_packets);
    sent_packets.deinit(allocator);
}

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
    pto_probe_count: usize = 0,
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

    fn init(config: Config) PacketNumberSpaceState {
        return .{
            .recovery_state = recovery.Recovery.init(.{
                .max_datagram_size = config.max_datagram_size,
                .initial_rtt_ms = config.initial_rtt_ms,
                .max_ack_delay_ms = config.max_ack_delay_ms,
            }),
        };
    }

    fn deinit(self: *PacketNumberSpaceState, allocator: std.mem.Allocator) void {
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
    pto_probe_count: *usize,
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

fn protectedLongDatagramWireLen(
    header: packet.LongHeader,
    packet_number_len: u8,
    plaintext_len: usize,
) Error!usize {
    if (packet_number_len == 0 or packet_number_len > 4) return error.InvalidPacket;
    const protected_payload_len = std.math.add(usize, plaintext_len, protection.aead_tag_len) catch return error.BufferTooSmall;
    const protected_payload_len_u64 = std.math.cast(u64, protected_payload_len) orelse return error.BufferTooSmall;
    const wire_length = std.math.add(u64, protected_payload_len_u64, packet_number_len) catch return error.BufferTooSmall;

    var header_len: usize = 1 + 4 + 1 + header.dcid.len + 1 + header.scid.len;
    if (header.packet_type == .initial) {
        const token_len_u64 = std.math.cast(u64, header.token.len) orelse return error.BufferTooSmall;
        header_len = try addWireLen(header_len, try quicVarIntWireLen(token_len_u64));
        header_len = try addWireLen(header_len, header.token.len);
    }
    header_len = try addWireLen(header_len, try quicVarIntWireLen(wire_length));
    header_len = try addWireLen(header_len, packet_number_len);
    return try addWireLen(header_len, protected_payload_len);
}

fn protectedLongPlaintextLenForMinDatagram(
    header: packet.LongHeader,
    packet_number_len: u8,
    plaintext_len: usize,
    min_datagram_len: usize,
) Error!usize {
    if (min_datagram_len == 0) return plaintext_len;
    var expanded_len = plaintext_len;
    while (try protectedLongDatagramWireLen(header, packet_number_len, expanded_len) < min_datagram_len) {
        const current_len = try protectedLongDatagramWireLen(header, packet_number_len, expanded_len);
        expanded_len = try addWireLen(expanded_len, min_datagram_len - current_len);
    }
    return expanded_len;
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

fn ptoDeadlineFor(
    sent_packets: []const SentPacket,
    recovery_state: recovery.Recovery,
    include_max_ack_delay: bool,
) ?i64 {
    var latest_sent_time: ?i64 = null;
    for (sent_packets) |sent_packet| {
        latest_sent_time = if (latest_sent_time) |current|
            @max(current, sent_packet.sent_time_millis)
        else
            sent_packet.sent_time_millis;
    }
    const sent_time = latest_sent_time orelse return null;
    const pto_ms = if (include_max_ack_delay)
        recovery_state.ptoMs()
    else
        recovery_state.ptoMsWithoutMaxAckDelay();
    return saturatingAddMillis(sent_time, pto_ms);
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

fn newTokenFrameWireLen(token: []const u8) Error!usize {
    if (token.len == 0) return error.InvalidPacket;
    const token_len = std.math.cast(u64, token.len) orelse return error.BufferTooSmall;
    if (token_len > max_quic_varint) return error.BufferTooSmall;

    var len: usize = 1; // frame type
    len = try addWireLen(len, try quicVarIntWireLen(token_len));
    return addWireLen(len, token.len);
}

fn handshakeDoneFrameWireLen() usize {
    return 1; // frame type only
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

fn deinitPeerClose(close: *PeerClose, allocator: std.mem.Allocator) void {
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

fn frameAllowedInFramePacketType(decoded: frame.Frame, packet_type: FramePacketType) bool {
    return switch (packet_type) {
        .initial, .handshake => switch (decoded) {
            .padding, .ping, .ack, .ack_ecn, .crypto, .connection_close => true,
            else => false,
        },
        // RFC 9000 Table 3 marks RETIRE_CONNECTION_ID as a 0/1-RTT frame, but
        // Section 12.5 permits treating it as a 0-RTT protocol violation.
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
    peer_preferred_address: ?PreferredAddress,
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
    crypto_recv_pending: std.ArrayList(PendingCryptoFrame),
    send_queue: std.ArrayList(PendingStreamFrame),
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
    handshake_state: HandshakeState,
    handshake_confirmed: bool,
    pending_handshake_done: bool,
    handshake_done_sent: bool,
    peer_close: ?PeerClose,
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
        if (config.ack_delay_exponent > 20) {
            return error.InvalidPacket;
        }
        if (config.max_ack_delay_ms >= (@as(u32, 1) << 14)) {
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
        try validateLocalVersionInformation(side, config);

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
            .peer_preferred_address = null,
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
                .max_ack_delay_ms = config.max_ack_delay_ms,
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
            .crypto_recv_pending = .empty,
            .send_queue = .empty,
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
    pub fn connectionState(self: QuicConnection) ConnectionState {
        return self.state;
    }

    /// Return the close/drain deadline in milliseconds, or null when no timer is active.
    pub fn closeDeadlineMillis(self: QuicConnection) ?i64 {
        return self.close_deadline_millis;
    }

    /// Return the peer close frame that moved this connection into draining, if any.
    pub fn peerClose(self: QuicConnection) ?PeerClose {
        return self.peer_close;
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

    /// Return the server preferred address learned from peer transport parameters.
    ///
    /// The value is copied into connection-owned fixed storage when peer
    /// parameters are applied. The current skeleton only exposes it for future
    /// endpoint migration policy; it does not automatically migrate sockets.
    pub fn peerPreferredAddress(self: QuicConnection) ?PreferredAddress {
        return self.peer_preferred_address;
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
            .initial => ptoDeadlineFor(self.initial_packet_space.sent_packets.items, self.initial_packet_space.recovery_state, false),
            .handshake => ptoDeadlineFor(self.handshake_packet_space.sent_packets.items, self.handshake_packet_space.recovery_state, false),
            .application => ptoDeadlineFor(self.sent_packets.items, self.recovery_state, true),
        };
    }

    /// Return the earliest modeled loss detection timer across packet spaces.
    ///
    /// This follows the RFC 9002 scheduling rule used by the simplified
    /// recovery model: any pending loss-time deadline wins over PTO; otherwise
    /// the earliest PTO deadline is returned. The caller can pass the same clock
    /// value to `checkLossDetectionTimeouts()` and `checkPtoTimeouts()` when the
    /// deadline expires.
    pub fn lossDetectionTimerDeadlineMillis(self: QuicConnection) ?LossDetectionTimerDeadline {
        const spaces = [_]PacketNumberSpace{ .initial, .handshake, .application };

        var loss_deadline: ?LossDetectionTimerDeadline = null;
        for (spaces) |space| {
            const deadline = self.lossDetectionDeadlineMillis(space) orelse continue;
            if (loss_deadline == null or deadline < loss_deadline.?.deadline_millis) {
                loss_deadline = .{
                    .space = space,
                    .kind = .loss_time,
                    .deadline_millis = deadline,
                };
            }
        }
        if (loss_deadline) |deadline| return deadline;

        var pto_deadline: ?LossDetectionTimerDeadline = null;
        for (spaces) |space| {
            const deadline = self.ptoDeadlineMillis(space) orelse continue;
            if (pto_deadline == null or deadline < pto_deadline.?.deadline_millis) {
                pto_deadline = .{
                    .space = space,
                    .kind = .pto,
                    .deadline_millis = deadline,
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
    /// probing. A late call may service multiple due packet number spaces via
    /// the existing per-space timeout handlers; the returned value is the
    /// earliest timer that caused this service call to run.
    pub fn serviceLossDetectionTimer(self: *QuicConnection, now_millis: i64) Error!?LossDetectionTimerDeadline {
        const deadline = self.lossDetectionTimerDeadlineMillis() orelse return null;
        if (deadline.deadline_millis > now_millis) return null;

        switch (deadline.kind) {
            .loss_time => try self.checkLossDetectionTimeouts(now_millis),
            .pto => try self.checkPtoTimeouts(now_millis),
        }
        return deadline;
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

    /// Return the modeled QUIC handshake progress state.
    pub fn handshakeState(self: QuicConnection) HandshakeState {
        return self.handshake_state;
    }

    /// Return the spin bit that the next protected 1-RTT short packet will use.
    ///
    /// When `Config.enable_spin_bit` is false this remains false so the default
    /// packetization behavior stays unchanged.
    pub fn nextOutgoingSpinBit(self: QuicConnection) bool {
        return self.shortHeaderSpinBit();
    }

    /// Reset the modeled spin bit for a newly selected path or destination CID.
    ///
    /// The current connection skeleton is single-path; endpoint routing can call
    /// this hook when a future socket-backed migration commits to a new path.
    pub fn resetSpinBitForPath(self: *QuicConnection) void {
        self.spin_bit_value = false;
    }

    /// Install TLS-produced Handshake traffic secrets into connection-owned state.
    ///
    /// The local secret protects future Handshake long-header packets sent by
    /// this endpoint. The peer secret opens future Handshake long-header packets
    /// received from the remote endpoint. `discardPacketNumberSpace(.handshake)`
    /// discards these installed keys together with Handshake recovery state.
    pub fn installHandshakeTrafficSecrets(
        self: *QuicConnection,
        secrets: HandshakeTrafficSecrets,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.handshake_packet_space.discarded) return error.InvalidPacket;
        self.local_handshake_keys = protection.deriveAes128PacketProtectionKeys(secrets.local);
        self.peer_handshake_keys = protection.deriveAes128PacketProtectionKeys(secrets.peer);
    }

    /// Return whether both local send and peer receive Handshake keys exist.
    pub fn hasHandshakeProtectionKeys(self: QuicConnection) bool {
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
        self: *QuicConnection,
        secrets: ZeroRttTrafficSecrets,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (secrets.local == null and secrets.peer == null) return error.InvalidPacket;
        if (secrets.local) |local| {
            self.local_zero_rtt_keys = protection.deriveAes128PacketProtectionKeys(local);
        }
        if (secrets.peer) |peer| {
            self.peer_zero_rtt_keys = protection.deriveAes128PacketProtectionKeys(peer);
            self.peer_zero_rtt_accepted = false;
        }
    }

    /// Return whether local 0-RTT send keys are installed.
    pub fn hasLocalZeroRttProtectionKey(self: QuicConnection) bool {
        return self.local_zero_rtt_keys != null;
    }

    /// Return whether peer 0-RTT receive keys are installed.
    pub fn hasPeerZeroRttProtectionKey(self: QuicConnection) bool {
        return self.peer_zero_rtt_keys != null;
    }

    /// Return whether installed peer 0-RTT receive keys are accepted for use.
    pub fn zeroRttAccepted(self: QuicConnection) bool {
        return self.peer_zero_rtt_accepted;
    }

    /// Accept installed peer 0-RTT receive keys after TLS early-data policy.
    ///
    /// This only gates the connection-installed receive helper. Callers that
    /// use `processProtectedZeroRttDatagram()` with explicit keys still own
    /// acceptance and replay policy outside the connection.
    pub fn acceptZeroRtt(self: *QuicConnection) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.peer_zero_rtt_keys == null) return error.InvalidPacket;
        self.peer_zero_rtt_accepted = true;
    }

    /// Reject installed peer 0-RTT receive keys and discard early-data state.
    ///
    /// This models TLS rejecting early data before any installed-key 0-RTT
    /// payload is processed. It does not affect caller-owned explicit-key
    /// packet opening.
    pub fn rejectZeroRtt(self: *QuicConnection) Error!void {
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
    pub fn discardZeroRttProtectionKeys(self: *QuicConnection) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        self.discardZeroRttProtectionKeyState();
    }

    fn discardZeroRttProtectionKeyState(self: *QuicConnection) void {
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
        self: *QuicConnection,
        secrets: OneRttTrafficSecrets,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.side == .client) {
            self.discardZeroRttProtectionKeyState();
        }
        self.local_one_rtt_key_phase_state = protection.Aes128KeyPhaseState.init(
            protection.deriveAes128PacketProtectionKeys(secrets.local),
            false,
        );
        self.peer_one_rtt_key_phase_state = protection.Aes128KeyPhaseState.init(
            protection.deriveAes128PacketProtectionKeys(secrets.peer),
            false,
        );
        self.local_one_rtt_key_update_ack_threshold = null;
    }

    /// Return whether both local send and peer receive 1-RTT key states exist.
    pub fn hasOneRttProtectionKeys(self: QuicConnection) bool {
        return self.local_one_rtt_key_phase_state != null and self.peer_one_rtt_key_phase_state != null;
    }

    /// Return the key phase bit used by the next installed-key 1-RTT send.
    pub fn localOneRttKeyPhase(self: QuicConnection) ?bool {
        if (self.local_one_rtt_key_phase_state) |state| return state.currentKeyPhase();
        return null;
    }

    /// Return the active peer key phase for installed-key 1-RTT receive.
    pub fn peerOneRttKeyPhase(self: QuicConnection) ?bool {
        if (self.peer_one_rtt_key_phase_state) |state| return state.currentKeyPhase();
        return null;
    }

    /// Advance the installed local 1-RTT send keys before the next packet.
    ///
    /// This models endpoint-owned key update initiation after handshake
    /// confirmation. A second local update is rejected until an Application ACK
    /// covers a packet number sent with the new key phase.
    pub fn initiateOneRttKeyUpdate(self: *QuicConnection) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (!self.handshake_confirmed) return error.InvalidPacket;
        if (self.local_one_rtt_key_update_ack_threshold != null) return error.InvalidPacket;
        if (self.local_one_rtt_key_phase_state) |*state| {
            state.initiateKeyUpdate();
            self.local_one_rtt_key_update_ack_threshold = self.next_packet_number;
            return;
        }
        return error.InvalidPacket;
    }

    fn shortHeaderSpinBit(self: QuicConnection) bool {
        return self.config.enable_spin_bit and self.spin_bit_value;
    }

    fn updateSpinBitAfterReceivedShortPacket(self: *QuicConnection, peer_spin_bit: bool) void {
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

    /// Return the Retry token most recently accepted by a client connection.
    ///
    /// The returned token is owned by the connection and is used automatically
    /// as the Initial token when protected Initial packetization receives no
    /// explicit token argument. Null means no valid Retry packet has been
    /// processed by this client connection.
    pub fn latestRetryToken(self: QuicConnection) ?[]const u8 {
        return self.retry_token;
    }

    /// Return the Source Connection ID used by this endpoint's first sent Initial.
    ///
    /// This value is captured only after a protected Initial packet is actually
    /// committed to the send path. `localTransportParameters()` exports it as
    /// `initial_source_connection_id` once available.
    pub fn localInitialSourceConnectionId(self: *const QuicConnection) ?[]const u8 {
        const len = self.local_initial_source_connection_id_len orelse return null;
        return self.local_initial_source_connection_id[0..len];
    }

    /// Return the peer's Initial Source Connection ID observed on its first Initial.
    ///
    /// The value is captured from a successfully opened protected Initial packet
    /// and later authenticated by the peer's `initial_source_connection_id`
    /// transport parameter.
    pub fn peerInitialSourceConnectionId(self: QuicConnection) ?[]const u8 {
        return self.peer_initial_source_connection_id;
    }

    /// Return the Original Destination Connection ID remembered for transport parameters.
    ///
    /// Client connections record the DCID used by their first sent Initial and
    /// validate it against the server's `original_destination_connection_id`.
    /// Server connections record the DCID from the first successfully opened
    /// client Initial and export it through `localTransportParameters()`.
    pub fn originalDestinationConnectionId(self: *const QuicConnection) ?[]const u8 {
        const len = self.original_destination_connection_id_len orelse return null;
        return self.original_destination_connection_id[0..len];
    }

    /// Return the Retry Source Connection ID from a validated Retry packet.
    ///
    /// Client connections expose the Retry Source Connection ID from a
    /// validated Retry packet for later server transport-parameter validation.
    /// Server connections expose the Retry Source Connection ID from a Retry
    /// datagram issued through `issueRetryDatagram()`.
    pub fn retrySourceConnectionId(self: QuicConnection) ?[]const u8 {
        return self.retry_source_connection_id;
    }

    /// Return the version selected from a validated Version Negotiation packet.
    ///
    /// The current connection object only records the result. The caller still
    /// owns starting the next incompatible-version connection attempt with the
    /// selected version and carrying authenticated RFC 9368 Version Information.
    pub fn versionNegotiationSelectedVersion(self: QuicConnection) ?packet.Version {
        return self.version_negotiation_selected_version;
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
        self: *QuicConnection,
        now_millis: i64,
        original_destination_connection_id: []const u8,
        client_source_connection_id: []const u8,
        retry_source_connection_id: []const u8,
        token: []const u8,
    ) Error![]u8 {
        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
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
            .version = .v1,
            .dcid = client_source_connection_id,
            .scid = retry_source_connection_id,
            .token = token,
            .integrity_tag = [_]u8{0} ** protection.aead_tag_len,
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
        self.recordPacketActivity(now_millis);
        return datagram;
    }

    /// Validate and process one client-side QUIC v1 Retry datagram.
    ///
    /// The Retry Integrity Tag is verified using the Original Destination
    /// Connection ID from the first client Initial. A valid Retry stores the
    /// opaque token for the next Initial packet and records the Retry Source
    /// Connection ID for later transport-parameter checks. This models the
    /// packet-routing step only; token encryption, expiration, address binding,
    /// and endpoint DCID switching remain endpoint policy.
    pub fn processRetryDatagram(
        self: *QuicConnection,
        now_millis: i64,
        original_destination_connection_id: []const u8,
        datagram: []const u8,
    ) Error!void {
        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
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

        if (retry.version != .v1) return error.InvalidPacket;
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
        self.recordPacketActivity(now_millis);
    }

    /// Validate and act on one client-side Version Negotiation packet.
    ///
    /// Incorrect connection-ID echoes and packets that include the client's
    /// Original Version are ignored by returning null. A valid packet selects
    /// the first server-offered version that appears in this client's
    /// configured `available_versions`, records that this connection attempt
    /// already reacted to Version Negotiation, and returns the selected version.
    pub fn processVersionNegotiationDatagram(
        self: *QuicConnection,
        now_millis: i64,
        original_destination_connection_id: []const u8,
        local_initial_source_connection_id: []const u8,
        datagram: []const u8,
    ) Error!?packet.Version {
        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.side != .client) return error.InvalidPacket;
        if (self.initial_packet_space.discarded) return error.InvalidPacket;
        if (self.initial_packet_space.next_peer_packet_number != 0) return error.InvalidPacket;
        if (original_destination_connection_id.len > max_connection_id_len) return error.InvalidPacket;
        if (local_initial_source_connection_id.len > max_connection_id_len) return error.InvalidPacket;
        if (self.version_negotiation_selected_version != null) return null;

        var negotiation = packet.parseVersionNegotiationPacket(datagram, self.allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidPacket,
        };
        defer packet.deinitVersionNegotiationPacket(&negotiation, self.allocator);

        if (!std.mem.eql(u8, negotiation.dcid, local_initial_source_connection_id)) return null;
        if (!std.mem.eql(u8, negotiation.scid, original_destination_connection_id)) return null;
        if (versionListContains(negotiation.versions, self.config.chosen_version)) return null;

        const selected = selectMutualVersion(self.config.available_versions, negotiation.versions) orelse return error.InvalidPacket;
        self.version_negotiation_selected_version = selected;
        self.recordPacketActivity(now_millis);
        return selected;
    }

    /// Create a server-authenticated address-validation token.
    ///
    /// The token is bound to `peer_address`, expires after `lifetime_millis`,
    /// and is authenticated with `secret`. The peer address is included in the
    /// MAC input but not serialized into the token. Callers pass `.retry`
    /// tokens to `issueRetryDatagram()` and `.new_token` values to
    /// `issueNewToken()`.
    pub fn issueAddressValidationToken(
        self: *QuicConnection,
        secret: address_validation_token.Secret,
        kind: address_validation_token.Kind,
        now_millis: i64,
        lifetime_millis: u64,
        peer_address: []const u8,
        nonce: address_validation_token.Nonce,
    ) Error![]u8 {
        return self.issueAddressValidationTokenForVersion(secret, kind, .v1, now_millis, lifetime_millis, peer_address, nonce);
    }

    /// Create a server-authenticated token for a specific QUIC version.
    pub fn issueAddressValidationTokenForVersion(
        self: *QuicConnection,
        secret: address_validation_token.Secret,
        kind: address_validation_token.Kind,
        originating_version: packet.Version,
        now_millis: i64,
        lifetime_millis: u64,
        peer_address: []const u8,
        nonce: address_validation_token.Nonce,
    ) Error![]u8 {
        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.side != .server) return error.InvalidPacket;

        return address_validation_token.encode(self.allocator, secret, .{
            .kind = kind,
            .originating_version = originating_version,
            .issued_millis = now_millis,
            .lifetime_millis = lifetime_millis,
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
        self: *QuicConnection,
        secret: address_validation_token.Secret,
        expected_kind: address_validation_token.Kind,
        now_millis: i64,
        peer_address: []const u8,
        token: []const u8,
    ) Error!void {
        try self.validateAddressValidationTokenForVersion(secret, expected_kind, .v1, now_millis, peer_address, token);
    }

    /// Validate a server-authenticated token for an expected QUIC version.
    pub fn validateAddressValidationTokenForVersion(
        self: *QuicConnection,
        secret: address_validation_token.Secret,
        expected_kind: address_validation_token.Kind,
        expected_originating_version: packet.Version,
        now_millis: i64,
        peer_address: []const u8,
        token: []const u8,
    ) Error!void {
        const secrets = [_]address_validation_token.Secret{secret};
        try self.validateAddressValidationTokenWithSecretsForVersion(&secrets, expected_kind, expected_originating_version, now_millis, peer_address, token);
    }

    /// Validate a server-authenticated token against rotated endpoint secrets.
    ///
    /// This has the same connection-side effects as
    /// `validateAddressValidationToken()`: Retry tokens are consumed from the
    /// pending one-time set, NEW_TOKEN values do not require pending state, and
    /// successful validation marks the peer address as validated.
    pub fn validateAddressValidationTokenWithSecrets(
        self: *QuicConnection,
        secrets: []const address_validation_token.Secret,
        expected_kind: address_validation_token.Kind,
        now_millis: i64,
        peer_address: []const u8,
        token: []const u8,
    ) Error!void {
        try self.validateAddressValidationTokenWithSecretsForVersion(secrets, expected_kind, .v1, now_millis, peer_address, token);
    }

    /// Validate a version-bound server-authenticated token against rotated secrets.
    pub fn validateAddressValidationTokenWithSecretsForVersion(
        self: *QuicConnection,
        secrets: []const address_validation_token.Secret,
        expected_kind: address_validation_token.Kind,
        expected_originating_version: packet.Version,
        now_millis: i64,
        peer_address: []const u8,
        token: []const u8,
    ) Error!void {
        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        if (self.side != .server or token.len == 0) return error.InvalidPacket;

        _ = address_validation_token.validateAnySecretForVersion(secrets, expected_kind, expected_originating_version, now_millis, peer_address, token) catch return error.InvalidPacket;
        if (expected_kind == .retry and !self.consumePendingRetryToken(token)) {
            return error.InvalidPacket;
        }
        self.peer_address_validated = true;
        self.recordPacketActivity(now_millis);
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

        if (self.consumePendingRetryToken(token)) {
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
        try self.expireLossDetectionTimeouts(now_millis);
    }

    /// Queue PTO probes when simplified PTO deadlines expire.
    ///
    /// This is a deterministic hook for the current frame-payload model. It
    /// lets already queued ack-eliciting data serve as the probe. If nothing is
    /// queued, it reuses in-flight CRYPTO first, then Application STREAM, before
    /// falling back to a PING. When a space expires, other packet number spaces
    /// that still have in-flight packets also get probes without advancing their
    /// own PTO backoff until their own deadline expires.
    pub fn checkPtoTimeouts(self: *QuicConnection, now_millis: i64) Error!void {
        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        try self.expireLossDetectionTimeouts(now_millis);
        const spaces = [_]PacketNumberSpace{ .initial, .handshake, .application };
        for (spaces) |space| {
            if (try self.checkPtoTimeoutInSpace(space, now_millis)) {
                try self.queuePtoPeerSpaceProbes(space);
            }
        }
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
        self.handshake_state = .confirmed;
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
        self.discardPacketNumberSpaceState(space);
    }

    fn discardPacketNumberSpaceState(self: *QuicConnection, space: PacketNumberSpace) void {
        std.debug.assert(space != .application);
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return;

        packet_space.discarded.* = true;
        if (space == .handshake) {
            self.local_handshake_keys = null;
            self.peer_handshake_keys = null;
        }
        packet_space.pending_ack_largest.* = null;
        packet_space.largest_acknowledged.* = null;
        packet_space.first_rtt_sample_sent_time_millis.* = null;
        packet_space.loss_deadline_millis.* = null;
        clearSentPacketList(self.allocator, packet_space.sent_packets);
        packet_space.pending_ping_count.* = 0;
        packet_space.pto_probe_count.* = 0;
        self.rollbackCryptoSendQueue(packet_space.crypto_send_queue, 0);
        packet_space.crypto_send_offset.* = 0;
        packet_space.crypto_recv_buffer.items.len = 0;
        packet_space.crypto_read_offset.* = 0;
        self.rollbackCryptoFrameQueue(packet_space.crypto_recv_pending, 0);
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
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;
        if (packet_space.next_packet_number.* > max_quic_varint) return error.Internal;
        if (!self.canSendAckElicitingInSpace(space, bytes)) return error.FlowControlBlocked;
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
        self.recordAckElicitingSendInSpace(space, bytes);
        self.recordPeerAddressBytesSent(bytes);
        self.recordPacketActivity(now_millis);
        self.maybeDiscardInitialAfterHandshakePacketSent(space);
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
        self.markHandshakeSpaceUsed(space);
    }

    /// Build the local RFC 9000 transport parameters advertised during handshake.
    ///
    /// The current skeleton maps idle timeout, receive limits, ACK timing,
    /// local datagram sizing, active migration policy, the first sent Initial
    /// Source Connection ID when known, server Original Destination Connection
    /// ID / Retry Source Connection ID when known, RFC 9368 version
    /// information, and optional server stateless reset token into typed
    /// parameters.
    pub fn localTransportParameters(self: *const QuicConnection) transport_parameters.TransportParameters {
        var params = transport_parameters.TransportParameters{
            .max_idle_timeout = self.config.max_idle_timeout_ms,
            .initial_max_data = self.recv_max_data,
            .initial_max_stream_data_bidi_local = self.recv_max_stream_data,
            .initial_max_stream_data_bidi_remote = self.recv_max_stream_data,
            .initial_max_stream_data_uni = self.recv_max_stream_data,
            .initial_max_streams_bidi = self.recv_max_streams_bidi,
            .initial_max_streams_uni = self.recv_max_streams_uni,
            .ack_delay_exponent = self.config.ack_delay_exponent,
            .max_ack_delay = self.config.max_ack_delay_ms,
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
            params.stateless_reset_token = self.config.stateless_reset_token;
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
    pub fn encodeLocalTransportParameters(self: *const QuicConnection, out_buf: []u8) Error![]const u8 {
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
        self: *QuicConnection,
        params: transport_parameters.TransportParameters,
    ) Error!void {
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        try self.validatePeerTransportParameters(params);

        const peer_preferred_address = if (params.preferred_address) |preferred|
            try PreferredAddress.fromTransportParameter(preferred)
        else
            null;

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
        self.peer_active_connection_id_limit = params.active_connection_id_limit;
        self.recovery_state.max_ack_delay_ms = params.max_ack_delay;

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
        self: *QuicConnection,
        data: []const u8,
    ) Error!void {
        var params = transport_parameters.parse(data, self.allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidPacket,
        };
        defer params.deinit(self.allocator);
        try self.applyPeerTransportParameters(params);
    }

    fn validateConnectionIdParameter(cid: ?[]const u8) Error!void {
        if (cid) |value| {
            if (value.len > max_connection_id_len) return error.InvalidPacket;
        }
    }

    fn validatePeerVersionInformation(
        self: QuicConnection,
        version_information: transport_parameters.VersionInformation,
    ) Error!void {
        if (isZeroVersion(version_information.chosen_version)) return error.InvalidPacket;
        for (version_information.available_versions) |available| {
            if (isZeroVersion(available)) return error.InvalidPacket;
        }

        switch (self.side) {
            .server => {
                if (!version_information.containsAvailableVersion(version_information.chosen_version)) {
                    return error.InvalidPacket;
                }
                if (@intFromEnum(version_information.chosen_version) != @intFromEnum(self.config.chosen_version)) {
                    return error.InvalidPacket;
                }
            },
            .client => {
                if (!versionListContains(self.config.available_versions, version_information.chosen_version)) {
                    return error.InvalidPacket;
                }
                if (self.version_negotiation_selected_version) |selected| {
                    if (@intFromEnum(version_information.chosen_version) != @intFromEnum(selected)) {
                        return error.InvalidPacket;
                    }
                    if (version_information.available_versions.len == 0) {
                        return error.InvalidPacket;
                    }
                    const preferred = selectMutualVersionWithExtra(
                        self.config.available_versions,
                        version_information.available_versions,
                        version_information.chosen_version,
                    ) orelse return error.InvalidPacket;
                    if (@intFromEnum(preferred) != @intFromEnum(selected)) {
                        return error.InvalidPacket;
                    }
                }
            },
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
        try self.validateInitialSourceConnectionIdParameter(params.initial_source_connection_id);
        try self.validateOriginalDestinationConnectionIdParameter(params.original_destination_connection_id);
        try self.validateRetrySourceConnectionIdParameter(params.retry_source_connection_id);
        if (params.preferred_address) |preferred| {
            _ = try PreferredAddress.fromTransportParameter(preferred);
        }
        if (params.version_information) |version_information| {
            try self.validatePeerVersionInformation(version_information);
        } else if (self.side == .client) {
            if (self.version_negotiation_selected_version) |selected| {
                if (@intFromEnum(selected) != @intFromEnum(packet.Version.v1)) return error.InvalidPacket;
            }
        }
    }

    fn validateOriginalDestinationConnectionIdParameter(self: QuicConnection, original_destination_connection_id: ?[]const u8) Error!void {
        if (self.side != .client) return;
        if (self.originalDestinationConnectionId()) |expected| {
            const actual = original_destination_connection_id orelse return error.InvalidPacket;
            if (!std.mem.eql(u8, expected, actual)) return error.InvalidPacket;
        } else if (original_destination_connection_id != null) {
            return error.InvalidPacket;
        }
    }

    fn validateInitialSourceConnectionIdParameter(self: QuicConnection, initial_source_connection_id: ?[]const u8) Error!void {
        if (self.peer_initial_source_connection_id) |expected| {
            const actual = initial_source_connection_id orelse return error.InvalidPacket;
            if (!std.mem.eql(u8, expected, actual)) return error.InvalidPacket;
        }
    }

    fn validateRetrySourceConnectionIdParameter(self: QuicConnection, retry_source_connection_id: ?[]const u8) Error!void {
        if (self.side != .client) return;
        if (self.retry_source_connection_id) |expected| {
            const actual = retry_source_connection_id orelse return error.InvalidPacket;
            if (!std.mem.eql(u8, expected, actual)) return error.InvalidPacket;
        } else if (retry_source_connection_id != null) {
            return error.InvalidPacket;
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

    fn clearPeerClose(self: *QuicConnection) void {
        if (self.peer_close) |*peer_close| {
            deinitPeerClose(peer_close, self.allocator);
            self.peer_close = null;
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

    fn receiveConnectionCloseFrame(self: *QuicConnection, now_millis: i64, close: frame.ConnectionCloseFrame) Error!void {
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
        self.enterDrainingState(now_millis);
    }

    fn receiveApplicationCloseFrame(self: *QuicConnection, now_millis: i64, close: frame.ApplicationCloseFrame) Error!void {
        if (self.peer_close == null) {
            const owned_reason = self.allocator.alloc(u8, close.reason_phrase.len) catch return error.OutOfMemory;
            errdefer self.allocator.free(owned_reason);
            @memcpy(owned_reason, close.reason_phrase);
            self.peer_close = .{ .application = .{
                .error_code = close.error_code,
                .reason_phrase = owned_reason,
            } };
        }
        self.enterDrainingState(now_millis);
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

    fn prepareInboundDatagramProcessing(self: *QuicConnection, now_millis: i64) Error!bool {
        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
        if (self.state == .closing or self.state == .draining) return false;
        if (self.isClosingOrClosed()) return error.ConnectionClosed;
        return true;
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

    fn initialTokenForPacket(self: QuicConnection, space: PacketNumberSpace, token: []const u8) []const u8 {
        if (space != .initial or token.len != 0) return token;
        return self.retry_token orelse &[_]u8{};
    }

    fn recordPeerAddressBytesSent(self: *QuicConnection, bytes: usize) void {
        if (!self.isAntiAmplificationLimited()) return;
        self.peer_address_bytes_sent = std.math.add(usize, self.peer_address_bytes_sent, bytes) catch std.math.maxInt(usize);
    }

    fn consumePendingRetryToken(self: *QuicConnection, token: []const u8) bool {
        for (self.retry_tokens.items, 0..) |existing, i| {
            if (!std.mem.eql(u8, existing, token)) continue;
            const removed = self.retry_tokens.orderedRemove(i);
            self.allocator.free(removed);
            return true;
        }
        return false;
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

    fn markHandshakeSpaceUsed(self: *QuicConnection, space: PacketNumberSpace) void {
        if (space == .handshake and self.handshake_state == .initial) {
            self.handshake_state = .handshake;
        }
    }

    fn maybeDiscardInitialAfterHandshakePacketSent(self: *QuicConnection, space: PacketNumberSpace) void {
        if (self.side != .client or space != .handshake or self.isClosingOrClosed()) return;
        self.discardPacketNumberSpaceState(.initial);
    }

    fn maybeDiscardInitialAfterHandshakePacketReceived(self: *QuicConnection, space: PacketNumberSpace) void {
        if (self.side != .server or space != .handshake or self.isClosingOrClosed()) return;
        self.discardPacketNumberSpaceState(.initial);
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
                .pto_probe_count = &self.initial_packet_space.pto_probe_count,
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
                .largest_acknowledged = &self.handshake_packet_space.largest_acknowledged,
                .first_rtt_sample_sent_time_millis = &self.handshake_packet_space.first_rtt_sample_sent_time_millis,
                .loss_deadline_millis = &self.handshake_packet_space.loss_deadline_millis,
                .recovery_state = &self.handshake_packet_space.recovery_state,
                .sent_packets = &self.handshake_packet_space.sent_packets,
                .pending_ping_count = &self.handshake_packet_space.pending_ping_count,
                .pto_probe_count = &self.handshake_packet_space.pto_probe_count,
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
                .largest_acknowledged = &self.largest_acknowledged,
                .first_rtt_sample_sent_time_millis = &self.first_rtt_sample_sent_time_millis,
                .loss_deadline_millis = &self.loss_deadline_millis,
                .recovery_state = &self.recovery_state,
                .sent_packets = &self.sent_packets,
                .pending_ping_count = &self.pending_ping_count,
                .pto_probe_count = &self.pto_probe_count,
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

    fn canSendAckElicitingInSpace(self: *QuicConnection, space: PacketNumberSpace, bytes: usize) bool {
        const packet_space = self.packetNumberSpace(space);
        return packet_space.pto_probe_count.* != 0 or packet_space.recovery_state.canSend(bytes);
    }

    fn armPtoProbeInSpace(self: *QuicConnection, space: PacketNumberSpace) void {
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.pto_probe_count.* == 0) {
            packet_space.pto_probe_count.* = 1;
        }
    }

    fn recordAckElicitingSendInSpace(self: *QuicConnection, space: PacketNumberSpace, bytes: usize) void {
        const packet_space = self.packetNumberSpace(space);
        packet_space.recovery_state.onPacketSent(bytes);
        if (packet_space.pto_probe_count.* != 0) {
            packet_space.pto_probe_count.* -= 1;
        }
    }

    /// Process one unencrypted packet payload containing one or more QUIC frames.
    ///
    /// Closing or draining connections discard the datagram before parsing.
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
    /// protected QUIC packetization. Closing or draining connections discard
    /// the datagram before parsing.
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
        self: *QuicConnection,
        now_millis: i64,
        keys: ProtectedLongDatagramKeys,
        datagram: []const u8,
    ) Error!usize {
        if (datagram.len == 0) return error.InvalidPacket;
        if (!try self.prepareInboundDatagramProcessing(now_millis)) return 0;

        var offset: usize = 0;
        var packet_count: usize = 0;
        while (offset < datagram.len) {
            const info = protection.peekProtectedLongPacketInfo(datagram[offset..]) catch return error.InvalidPacket;
            if (info.version != .v1 or info.len == 0) return error.InvalidPacket;
            const route = protectedLongPacketRouteFor(keys, info.packet_type) orelse return error.InvalidPacket;
            const packet_space = self.packetNumberSpace(route.space);
            if (packet_space.discarded.*) return error.InvalidPacket;
            offset = std.math.add(usize, offset, info.len) catch return error.InvalidPacket;
            packet_count += 1;
        }

        offset = 0;
        var processed_count: usize = 0;
        while (offset < datagram.len) {
            const info = protection.peekProtectedLongPacketInfo(datagram[offset..]) catch return error.InvalidPacket;
            const route = protectedLongPacketRouteFor(keys, info.packet_type) orelse return error.InvalidPacket;
            try self.processProtectedLongDatagramWithRoute(
                route,
                now_millis,
                datagram.len,
                datagram[offset..][0..info.len],
            );
            offset += info.len;
            processed_count += 1;
        }

        std.debug.assert(processed_count == packet_count);
        return processed_count;
    }

    /// Remove long-header packet protection for Initial or Handshake space.
    ///
    /// This accepts exactly one QUIC v1 protected long packet for the selected
    /// Initial or Handshake packet number space, decrypts it with caller-supplied
    /// keys, requires the packet number to match the next expected value for
    /// that space, then routes the plaintext through the matching frame rules.
    /// Closing or draining connections discard the datagram before parsing.
    /// Coalesced packets, 1-RTT protected transmit, real TLS transcript
    /// ownership, key discard, and key update remain endpoint/TLS integration
    /// work.
    pub fn processProtectedLongDatagramInSpace(
        self: *QuicConnection,
        space: PacketNumberSpace,
        now_millis: i64,
        keys: protection.Aes128PacketProtectionKeys,
        datagram: []const u8,
    ) Error!void {
        if (!try self.prepareInboundDatagramProcessing(now_millis)) return;

        const long_space = protectedLongPacketSpaceFor(space) orelse return error.InvalidPacket;
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;

        try self.processProtectedLongDatagramWithRoute(.{
            .space = space,
            .packet_type = long_space.packet_type,
            .frame_packet_type = long_space.frame_packet_type,
            .keys = keys,
        }, now_millis, datagram.len, datagram);
    }

    /// Remove Handshake long-header protection using installed peer keys.
    ///
    /// Call `installHandshakeTrafficSecrets()` or drive a `CryptoBackend` that
    /// returns Handshake traffic secrets before using this helper. Failed
    /// packets keep the Handshake packet-number space unchanged through the
    /// same rollback boundary as the caller-keyed helper.
    pub fn processProtectedHandshakeDatagramWithInstalledKeys(
        self: *QuicConnection,
        now_millis: i64,
        datagram: []const u8,
    ) Error!void {
        const keys = self.peer_handshake_keys orelse return error.InvalidPacket;
        try self.processProtectedLongDatagramInSpace(.handshake, now_millis, keys, datagram);
    }

    fn processProtectedLongDatagramWithRoute(
        self: *QuicConnection,
        route: ProtectedLongPacketRoute,
        now_millis: i64,
        udp_datagram_len: usize,
        datagram: []const u8,
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
        if (decoded.packet.header.version != .v1 or decoded.packet.header.packet_type != route.packet_type) {
            return error.InvalidPacket;
        }
        if (decoded.packet.header.packet_number != expected_packet_number) return error.InvalidPacket;

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
        const pending_peer_initial_scid = if (route.space == .initial and self.peer_initial_source_connection_id == null)
            self.allocator.dupe(u8, decoded.packet.header.scid) catch return error.OutOfMemory
        else
            null;
        errdefer if (pending_peer_initial_scid) |cid| self.allocator.free(cid);

        try self.processDatagramInSpaceWithPacketType(
            route.space,
            route.frame_packet_type,
            now_millis,
            decoded.packet.plaintext,
        );
        const packet_space_after = self.packetNumberSpace(route.space);
        if (packet_space_after.next_peer_packet_number.* == expected_packet_number) {
            packet_space_after.next_peer_packet_number.* = std.math.add(u64, expected_packet_number, 1) catch return error.Internal;
        }
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
        self: *QuicConnection,
        now_millis: i64,
        keys: protection.Aes128PacketProtectionKeys,
        datagram: []const u8,
    ) Error!void {
        if (!try self.prepareInboundDatagramProcessing(now_millis)) return;

        try self.processProtectedLongDatagramWithRoute(.{
            .space = .application,
            .packet_type = .zero_rtt,
            .frame_packet_type = .zero_rtt,
            .keys = keys,
        }, now_millis, datagram.len, datagram);
    }

    /// Remove 0-RTT long-header protection using installed peer early-data keys.
    ///
    /// Call `installZeroRttTrafficSecrets()` or drive a `CryptoBackend` that
    /// returns a peer 0-RTT secret, then `acceptZeroRtt()` after TLS policy
    /// accepts early data. Replay defense remains caller-owned endpoint/TLS
    /// work.
    pub fn processProtectedZeroRttDatagramWithInstalledKeys(
        self: *QuicConnection,
        now_millis: i64,
        datagram: []const u8,
    ) Error!void {
        const keys = self.peer_zero_rtt_keys orelse return error.InvalidPacket;
        if (!self.peer_zero_rtt_accepted) return error.InvalidPacket;
        try self.processProtectedZeroRttDatagram(now_millis, keys, datagram);
    }

    /// Remove Initial packet protection and process the decrypted frame payload.
    ///
    /// This compatibility wrapper routes one protected Initial long packet
    /// through `processProtectedLongDatagramInSpace(.initial, ...)`.
    pub fn processInitialProtectedDatagram(
        self: *QuicConnection,
        now_millis: i64,
        keys: protection.Aes128PacketProtectionKeys,
        datagram: []const u8,
    ) Error!void {
        try self.processProtectedLongDatagramInSpace(.initial, now_millis, keys, datagram);
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
        self: *QuicConnection,
        now_millis: i64,
        keys: protection.Aes128PacketProtectionKeys,
        dcid_len: usize,
        datagram: []const u8,
    ) Error!void {
        if (!try self.prepareInboundDatagramProcessing(now_millis)) return;

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

        try self.processDecodedProtectedShortDatagram(now_millis, &decoded, datagram.len, expected_packet_number);
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
        self: *QuicConnection,
        now_millis: i64,
        keys: protection.ShortPacketKeyUpdateKeys,
        dcid_len: usize,
        datagram: []const u8,
    ) Error!void {
        if (!try self.prepareInboundDatagramProcessing(now_millis)) return;

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

        try self.processDecodedProtectedShortDatagram(now_millis, &decoded, datagram.len, expected_packet_number);
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
        self: *QuicConnection,
        now_millis: i64,
        key_phase_state: *protection.Aes128KeyPhaseState,
        dcid_len: usize,
        datagram: []const u8,
    ) Error!void {
        if (!try self.prepareInboundDatagramProcessing(now_millis)) return;

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
            else => return error.InvalidPacket,
        };
        defer protection.deinitProtectedShortPacket(&decoded, self.allocator);

        try self.processDecodedProtectedShortDatagram(now_millis, &decoded, datagram.len, expected_packet_number);
        _ = key_phase_state.updateAfterReceiving(decoded.packet.header.key_phase);
    }

    /// Remove 1-RTT short-header protection using installed peer traffic keys.
    ///
    /// The peer key-phase state is owned by the connection and advances only
    /// after authentication and Application-frame processing succeed. Use
    /// `installOneRttTrafficSecrets()` or a `CryptoBackend` traffic-secret
    /// handoff before calling this helper. Server-side successful receive
    /// discards installed 0-RTT receive keys.
    pub fn processProtectedShortDatagramWithInstalledKeys(
        self: *QuicConnection,
        now_millis: i64,
        dcid_len: usize,
        datagram: []const u8,
    ) Error!void {
        var state = self.peer_one_rtt_key_phase_state orelse return error.InvalidPacket;
        try self.processProtectedShortDatagramWithKeyPhaseState(now_millis, &state, dcid_len, datagram);
        self.peer_one_rtt_key_phase_state = state;
    }

    fn processDecodedProtectedShortDatagram(
        self: *QuicConnection,
        now_millis: i64,
        decoded: *const protection.DecodedProtectedShortPacket,
        datagram_len: usize,
        expected_packet_number: u64,
    ) Error!void {
        if (decoded.len != datagram_len) return error.InvalidPacket;
        if (decoded.packet.header.packet_number != expected_packet_number) return error.InvalidPacket;
        try self.processDatagramInSpaceWithPacketType(
            .application,
            .one_rtt,
            now_millis,
            decoded.packet.plaintext,
        );
        const packet_space_after = self.packetNumberSpace(.application);
        if (packet_space_after.next_peer_packet_number.* == expected_packet_number) {
            packet_space_after.next_peer_packet_number.* = std.math.add(u64, expected_packet_number, 1) catch return error.Internal;
        }
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
        self: *QuicConnection,
        now_millis: i64,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
    ) Error!?[]u8 {
        return self.pollProtectedShortDatagramWithKeyPhase(now_millis, dcid, keys, false);
    }

    /// Return one protected 1-RTT short-header datagram with an explicit key phase.
    ///
    /// Callers pass keys matching `key_phase`. This keeps the current
    /// caller-keyed bridge usable for deterministic key-update tests while a
    /// future endpoint/TLS state machine owns key-phase transitions.
    pub fn pollProtectedShortDatagramWithKeyPhase(
        self: *QuicConnection,
        now_millis: i64,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
    ) Error!?[]u8 {
        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
        if (self.pending_close != null) {
            return try self.pollProtectedShortCloseDatagram(now_millis, dcid, keys, key_phase);
        }
        if (self.isClosingOrClosed()) return error.ConnectionClosed;

        var built = (try self.buildNextProtectedShortPacket(dcid, keys, key_phase)) orelse return null;
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
        if (built.ack_eliciting and !self.canSendAckElicitingInSpace(.application, built.datagram.len)) {
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

        self.commitBuiltProtectedShortPacket(built, now_millis);
        return built.datagram;
    }

    /// Return one protected 1-RTT short-header datagram using key-phase state.
    ///
    /// This uses the state's current send keys and current key-phase bit. The
    /// caller explicitly initiates updates on the state before polling.
    pub fn pollProtectedShortDatagramWithKeyPhaseState(
        self: *QuicConnection,
        now_millis: i64,
        dcid: []const u8,
        key_phase_state: *const protection.Aes128KeyPhaseState,
    ) Error!?[]u8 {
        return self.pollProtectedShortDatagramWithKeyPhase(
            now_millis,
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
        self: *QuicConnection,
        now_millis: i64,
        dcid: []const u8,
    ) Error!?[]u8 {
        const state = self.local_one_rtt_key_phase_state orelse return error.InvalidPacket;
        return self.pollProtectedShortDatagramWithKeyPhaseState(now_millis, dcid, &state);
    }

    fn pollProtectedShortCloseDatagram(
        self: *QuicConnection,
        now_millis: i64,
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

        self.commitBuiltProtectedShortPacket(built, now_millis);
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
        self: *QuicConnection,
        now_millis: i64,
        dcid: []const u8,
        scid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
    ) Error!?[]u8 {
        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
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
        self.commitBuiltProtectedLongPacket(built, now_millis);
        return built.datagram;
    }

    /// Return one protected 0-RTT long-header datagram using installed keys.
    ///
    /// This client-side helper emits early STREAM, RESET_STREAM, or STOP_SENDING
    /// data with the connection's installed local 0-RTT keys. TLS 0-RTT
    /// acceptance and replay policy remain endpoint/TLS work.
    pub fn pollProtectedZeroRttDatagramWithInstalledKeys(
        self: *QuicConnection,
        now_millis: i64,
        dcid: []const u8,
        scid: []const u8,
    ) Error!?[]u8 {
        const keys = self.local_zero_rtt_keys orelse return error.InvalidPacket;
        return self.pollProtectedZeroRttDatagram(now_millis, dcid, scid, keys);
    }

    /// Return one protected long datagram with queued Initial/0-RTT/Handshake frames.
    ///
    /// The returned datagram is allocated with the connection allocator and must
    /// be freed by the caller. For each Initial/Handshake space, the method can
    /// emit one protected CRYPTO packet, PING packet with an optional ACK, or
    /// ACK-only packet. When `keys.zero_rtt` is supplied by a client, it can
    /// also emit one 0-RTT Application STREAM, RESET_STREAM, or STOP_SENDING
    /// packet. The method coalesces eligible long packets into one UDP datagram
    /// when the result fits `max_udp_payload_size`. It prebuilds packets and
    /// checks congestion plus anti-amplification budget before committing
    /// packet-number, sent-packet, recovery, ACK/PING, CRYPTO, and 0-RTT queue
    /// state. Endpoint DCID switching, real TLS transcript ownership, key
    /// discard, and key update remain endpoint/TLS integration work.
    pub fn pollProtectedLongDatagram(
        self: *QuicConnection,
        now_millis: i64,
        dcid: []const u8,
        scid: []const u8,
        initial_token: []const u8,
        keys: ProtectedLongDatagramKeys,
    ) Error!?[]u8 {
        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;

        var initial_packet: ?BuiltProtectedLongPacket = null;
        var zero_rtt_packet: ?BuiltProtectedLongPacket = null;
        var handshake_packet: ?BuiltProtectedLongPacket = null;
        errdefer {
            self.deinitBuiltProtectedLongPacketIfPresent(&initial_packet);
            self.deinitBuiltProtectedLongPacketIfPresent(&zero_rtt_packet);
            self.deinitBuiltProtectedLongPacketIfPresent(&handshake_packet);
        }

        if (self.initial_packet_space.crypto_send_queue.items.len != 0 or
            self.initial_packet_space.pending_ping_count != 0 or
            self.initial_packet_space.pending_ack_largest != null)
        {
            initial_packet = try self.buildNextProtectedLongPacketInSpace(
                .initial,
                dcid,
                scid,
                initial_token,
                keys.initial orelse return error.InvalidPacket,
                0,
            );
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
            handshake_packet = try self.buildNextProtectedLongPacketInSpace(
                .handshake,
                dcid,
                scid,
                &[_]u8{},
                keys.handshake orelse return error.InvalidPacket,
                0,
            );
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
                const target_initial_len = try addWireLen(built.datagram.len, required_initial_datagram_len - total_len);
                self.deinitBuiltProtectedLongPacketIfPresent(&initial_packet);
                initial_packet = try self.buildNextProtectedLongPacketInSpace(
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
                    initial_packet = try self.buildNextProtectedLongPacketInSpace(
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
            self.commitBuiltProtectedLongPacket(built, now_millis);
            self.allocator.free(built.datagram);
            initial_packet = null;
        }
        if (zero_rtt_packet) |built| {
            @memcpy(datagram[offset..][0..built.datagram.len], built.datagram);
            offset += built.datagram.len;
            self.commitBuiltProtectedLongPacket(built, now_millis);
            self.allocator.free(built.datagram);
            zero_rtt_packet = null;
        }
        if (handshake_packet) |built| {
            @memcpy(datagram[offset..][0..built.datagram.len], built.datagram);
            offset += built.datagram.len;
            self.commitBuiltProtectedLongPacket(built, now_millis);
            self.allocator.free(built.datagram);
            handshake_packet = null;
        }
        std.debug.assert(offset == datagram.len);
        return datagram;
    }

    /// Return one protected Handshake long-header datagram using installed keys.
    ///
    /// This emits at most one Handshake CRYPTO, PING+ACK, or ACK-only packet
    /// from the Handshake packet number space without requiring the caller to
    /// pass packet-protection keys on every call. Use the caller-keyed
    /// `pollProtectedLongDatagram()` when coalescing Initial and Handshake
    /// packets is required.
    pub fn pollProtectedHandshakeDatagramWithInstalledKeys(
        self: *QuicConnection,
        now_millis: i64,
        dcid: []const u8,
        scid: []const u8,
    ) Error!?[]u8 {
        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;

        const keys = self.local_handshake_keys orelse return error.InvalidPacket;
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
        self.commitBuiltProtectedLongPacket(built, now_millis);
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
        self: *QuicConnection,
        space: PacketNumberSpace,
        now_millis: i64,
        dcid: []const u8,
        scid: []const u8,
        token: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
    ) Error!?[]u8 {
        self.expireIdleState(now_millis);
        self.expireCloseState(now_millis);
        if (self.isClosingOrClosed()) return error.ConnectionClosed;

        const min_datagram_len = self.minimumOutgoingInitialDatagramLen(space, true);
        const built = (try self.buildProtectedLongCryptoPacketInSpace(space, dcid, scid, token, keys, min_datagram_len)) orelse return null;
        errdefer self.allocator.free(built.datagram);

        if (!self.canSendAckElicitingInSpace(space, built.datagram.len) or !self.canSendToPeerAddress(built.datagram.len)) {
            self.allocator.free(built.datagram);
            return null;
        }

        try self.ensureProtectedLongCommitCapacity(built);
        self.commitBuiltProtectedLongPacket(built, now_millis);
        return built.datagram;
    }

    /// Return the next protected Initial CRYPTO datagram, or null if idle.
    ///
    /// This compatibility wrapper routes Initial CRYPTO through
    /// `pollProtectedLongCryptoDatagramInSpace(.initial, ...)`.
    pub fn pollInitialProtectedDatagram(
        self: *QuicConnection,
        now_millis: i64,
        dcid: []const u8,
        scid: []const u8,
        token: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
    ) Error!?[]u8 {
        return self.pollProtectedLongCryptoDatagramInSpace(.initial, now_millis, dcid, scid, token, keys);
    }

    fn buildProtectedLongCryptoPacketInSpace(
        self: *QuicConnection,
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
            .version = .v1,
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
        self: *QuicConnection,
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

    fn hasPendingProtectedZeroRttFrames(self: *QuicConnection) bool {
        self.dropObsoleteStopSendingFrames();
        return self.pending_reset_streams.items.len != 0 or
            self.pending_stop_sending.items.len != 0 or
            self.send_queue.items.len != 0;
    }

    fn buildNextProtectedZeroRttPacket(
        self: *QuicConnection,
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
        self: *QuicConnection,
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

        const min_payload_len = if (packet_number_encoding.len >= 4) 0 else 4 - packet_number_encoding.len;
        const plaintext_len = @max(encoded_frame_len, min_payload_len);
        if (plaintext_len > self.maxTxDatagramSize()) return error.BufferTooSmall;

        const plaintext = self.allocator.alloc(u8, plaintext_len) catch return error.OutOfMemory;
        defer self.allocator.free(plaintext);
        @memset(plaintext, 0);

        var plaintext_out = buffer.fixedWriter(plaintext);
        frame.encodeFrame(plaintext_out.writer(), frame_to_send) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.Internal,
        };

        const datagram = protection.protectLongPacketAes128(self.allocator, .{
            .version = .v1,
            .dcid = dcid,
            .scid = scid,
            .packet_type = .zero_rtt,
            .token = &[_]u8{},
            .packet_number = packet_number,
            .payload_length = 0,
        }, packet_number_encoding, keys, plaintext) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidPacket,
        };
        errdefer self.allocator.free(datagram);

        var sent_stream_frame: ?PendingStreamFrame = null;
        if (consume.stream) {
            const stream = switch (frame_to_send) {
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
            switch (frame_to_send) {
                .reset_stream => |reset| reset,
                else => return error.Internal,
            }
        else
            null;
        const sent_stop_sending_frame: ?frame.StopSendingFrame = if (consume.stop_sending)
            switch (frame_to_send) {
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
            .ack_eliciting = frameIsAckEliciting(frame_to_send),
            .sent_stream_frame = sent_stream_frame,
            .sent_reset_stream_frame = sent_reset_stream_frame,
            .sent_stop_sending_frame = sent_stop_sending_frame,
            .consume_reset_stream = consume.reset_stream,
            .consume_stop_sending = consume.stop_sending,
            .consume_stream = consume.stream,
        };
    }

    fn buildProtectedLongPingPacketInSpace(
        self: *QuicConnection,
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
        self: *QuicConnection,
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
        self: *QuicConnection,
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
            .version = .v1,
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
        self: QuicConnection,
        space: PacketNumberSpace,
        dcid: []const u8,
    ) ?[]const u8 {
        if (self.side != .client or space != .initial or self.original_destination_connection_id_len != null) return null;
        return dcid;
    }

    fn localInitialSourceConnectionIdForPacket(
        self: QuicConnection,
        space: PacketNumberSpace,
        scid: []const u8,
    ) ?[]const u8 {
        if (space != .initial or self.local_initial_source_connection_id_len != null) return null;
        return scid;
    }

    fn validateOutgoingInitialPacketFields(
        self: QuicConnection,
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

    fn minimumOutgoingInitialDatagramLen(self: QuicConnection, space: PacketNumberSpace, ack_eliciting: bool) usize {
        if (space != .initial) return 0;
        if (self.side == .client or ack_eliciting) return min_initial_udp_datagram_len;
        return 0;
    }

    fn validateIncomingInitialDatagramLen(self: QuicConnection, space: PacketNumberSpace, udp_datagram_len: usize) Error!void {
        if (space == .initial and self.side == .server and udp_datagram_len < min_initial_udp_datagram_len) {
            return error.InvalidPacket;
        }
    }

    fn validateOriginalDestinationConnectionIdForRecord(self: QuicConnection, dcid: []const u8) Error!void {
        if (dcid.len > max_connection_id_len) return error.InvalidPacket;
        if (self.originalDestinationConnectionId()) |existing| {
            if (!std.mem.eql(u8, existing, dcid)) return error.InvalidPacket;
        }
    }

    fn recordOriginalDestinationConnectionId(self: *QuicConnection, dcid: []const u8) void {
        if (self.original_destination_connection_id_len != null) return;
        std.debug.assert(dcid.len <= max_connection_id_len);
        @memcpy(self.original_destination_connection_id[0..dcid.len], dcid);
        self.original_destination_connection_id_len = @intCast(dcid.len);
    }

    fn recordLocalInitialSourceConnectionId(self: *QuicConnection, scid: []const u8) void {
        if (self.local_initial_source_connection_id_len != null) return;
        std.debug.assert(scid.len <= max_connection_id_len);
        @memcpy(self.local_initial_source_connection_id[0..scid.len], scid);
        self.local_initial_source_connection_id_len = @intCast(scid.len);
    }

    fn ensureProtectedLongCommitCapacity(
        self: *QuicConnection,
        built: BuiltProtectedLongPacket,
    ) Error!void {
        if (!built.ack_eliciting) return;
        var packet_space = self.packetNumberSpace(built.space);
        packet_space.sent_packets.ensureUnusedCapacity(self.allocator, 1) catch return error.OutOfMemory;
    }

    fn deinitBuiltProtectedLongPacket(self: *QuicConnection, built: BuiltProtectedLongPacket) void {
        var owned = built;
        owned.deinitSidecars(self.allocator);
        self.allocator.free(owned.datagram);
    }

    fn deinitBuiltProtectedLongPacketIfPresent(
        self: *QuicConnection,
        built: *?BuiltProtectedLongPacket,
    ) void {
        if (built.*) |packet_to_free| {
            self.deinitBuiltProtectedLongPacket(packet_to_free);
            built.* = null;
        }
    }

    fn commitBuiltProtectedLongPacket(
        self: *QuicConnection,
        built: BuiltProtectedLongPacket,
        now_millis: i64,
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
                .sent_time_millis = now_millis,
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
            const removed = self.send_queue.orderedRemove(0);
            self.allocator.free(removed.data);
        }
        if (built.clear_ack) packet_space.pending_ack_largest.* = null;
        packet_space.next_packet_number.* = built.packet_number + 1;
        if (built.ack_eliciting) self.recordAckElicitingSendInSpace(built.space, built.datagram.len);
        self.recordPeerAddressBytesSent(built.datagram.len);
        self.recordPacketActivity(now_millis);
        if (built.local_original_destination_connection_id_len) |len| {
            self.recordOriginalDestinationConnectionId(built.local_original_destination_connection_id[0..len]);
        }
        if (built.local_initial_source_connection_id_len) |len| {
            self.recordLocalInitialSourceConnectionId(built.local_initial_source_connection_id[0..len]);
        }
        self.maybeDiscardInitialAfterHandshakePacketSent(built.space);
    }

    fn buildNextProtectedShortPacket(
        self: *QuicConnection,
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
        self: *QuicConnection,
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
        self: *QuicConnection,
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
        self: *QuicConnection,
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
            .clear_ack = ack_to_send != null,
            .consume_reset_stream = true,
        };
    }

    fn buildProtectedShortStopSendingPacket(
        self: *QuicConnection,
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
            .clear_ack = ack_to_send != null,
            .consume_stop_sending = true,
        };
    }

    fn buildProtectedShortRetireConnectionIdPacket(
        self: *QuicConnection,
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
        self: *QuicConnection,
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
        self: *QuicConnection,
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
        self: *QuicConnection,
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
        self: *QuicConnection,
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
        self: *QuicConnection,
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
        self: *QuicConnection,
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
        self: *QuicConnection,
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

    fn buildProtectedShortStreamPacket(
        self: *QuicConnection,
        dcid: []const u8,
        keys: protection.Aes128PacketProtectionKeys,
        key_phase: bool,
        ack_to_send: ?frame.AckFrame,
    ) Error!BuiltProtectedShortPacket {
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        const pending = self.send_queue.items[0];
        const stream_encoded_len = try streamFrameWireLen(pending.stream_id, pending.offset, pending.data.len);
        var encoded_frame_len = stream_encoded_len;
        if (ack_to_send) |ack| {
            encoded_frame_len = try addWireLen(try ackFrameWireLen(ack), stream_encoded_len);
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
        frame.encodeFrame(plaintext_out.writer(), .{ .stream = .{
            .stream_id = pending.stream_id,
            .offset = pending.offset,
            .fin = pending.fin,
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
        const sent_stream_frame = try self.clonePendingStreamFrame(pending);
        errdefer self.allocator.free(sent_stream_frame.data);
        return .{
            .packet_number = packet_number,
            .datagram = datagram,
            .ack_eliciting = true,
            .sent_stream_frame = sent_stream_frame,
            .clear_ack = ack_to_send != null,
            .consume_stream = true,
        };
    }

    fn buildProtectedShortControlPacket(
        self: *QuicConnection,
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
        self: *QuicConnection,
        built: BuiltProtectedShortPacket,
        now_millis: i64,
    ) void {
        var sent_crypto_frame: ?PendingCryptoFrame = null;
        if (built.consume_crypto) {
            sent_crypto_frame = self.crypto_send_queue.orderedRemove(0);
        }

        if (built.ack_eliciting) {
            self.sent_packets.appendAssumeCapacity(.{
                .packet_number = built.packet_number,
                .sent_time_millis = now_millis,
                .bytes = built.datagram.len,
                .stream_frame = built.sent_stream_frame,
                .crypto_frame = sent_crypto_frame,
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
                .sent_time_millis = now_millis,
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
            const removed = self.send_queue.orderedRemove(0);
            self.allocator.free(removed.data);
        }
        if (built.clear_ack) self.pending_ack_largest = null;
        self.next_packet_number = built.packet_number + 1;
        if (built.ack_eliciting) self.recordAckElicitingSendInSpace(.application, built.datagram.len);
        if (built.close_packet and !self.closed) self.enterClosingState(now_millis);
        self.recordPeerAddressBytesSent(built.datagram.len);
        self.recordPacketActivity(now_millis);
    }

    /// Process one frame-payload datagram using RFC 9000 packet-type frame rules.
    ///
    /// 0-RTT and 1-RTT both use the Application packet number space, but 0-RTT
    /// rejects frames that are only valid after the handshake has progressed.
    /// Closing or draining connections discard the datagram before parsing.
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
        if (!try self.prepareInboundDatagramProcessing(now_millis)) return;
        if (datagram.len == 0 or datagram.len > self.config.max_datagram_size) return error.InvalidPacket;

        var packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;
        const recovery_snapshot = packet_space.recovery_state.*;
        const sent_packet_snapshots = try self.cloneSentPackets(packet_space.sent_packets.items);
        var sent_packet_snapshots_restored = false;
        defer {
            if (!sent_packet_snapshots_restored) {
                deinitSentPacketSlice(self.allocator, sent_packet_snapshots);
            }
            self.allocator.free(sent_packet_snapshots);
        }
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
        const pending_stop_sending_count = self.pending_stop_sending.items.len;
        const pending_max_frame_count = self.pending_max_frames.items.len;
        const recv_max_data_snapshot = self.recv_max_data;
        const recv_max_streams_bidi_snapshot = self.recv_max_streams_bidi;
        const recv_max_streams_uni_snapshot = self.recv_max_streams_uni;
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
        const handshake_state_snapshot = self.handshake_state;
        const handshake_confirmed_snapshot = self.handshake_confirmed;
        const local_one_rtt_key_update_ack_threshold_snapshot = self.local_one_rtt_key_update_ack_threshold;
        const peer_close_snapshot: PeerCloseSnapshot = if (self.peer_close == null) .absent else .present;
        const closed_snapshot = self.closed;
        const state_snapshot = self.state;
        const close_deadline_millis_snapshot = self.close_deadline_millis;
        const crypto_send_queue_snapshots = try self.clonePendingCryptoFrames(packet_space.crypto_send_queue.items);
        var crypto_send_queue_snapshots_restored = false;
        defer {
            if (!crypto_send_queue_snapshots_restored) {
                deinitPendingCryptoFrameSlice(self.allocator, crypto_send_queue_snapshots);
            }
            self.allocator.free(crypto_send_queue_snapshots);
        }
        const crypto_recv_buffer_len_snapshot = packet_space.crypto_recv_buffer.items.len;
        const crypto_recv_pending_count_snapshot = packet_space.crypto_recv_pending.items.len;
        const crypto_read_offset_snapshot = packet_space.crypto_read_offset.*;
        const send_stream_count = self.send_streams.items.len;
        const send_stream_snapshots = self.allocator.alloc(SendStreamState, send_stream_count) catch return error.OutOfMemory;
        defer self.allocator.free(send_stream_snapshots);
        @memcpy(send_stream_snapshots, self.send_streams.items);
        const send_queue_snapshots = try self.clonePendingStreamFrames(self.send_queue.items);
        var send_queue_snapshots_restored = false;
        defer {
            if (!send_queue_snapshots_restored) {
                deinitPendingStreamFrameSlice(self.allocator, send_queue_snapshots);
            }
            self.allocator.free(send_queue_snapshots);
        }

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
            self.rollbackSendQueueFromSnapshots(send_queue_snapshots);
            send_queue_snapshots_restored = true;
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
            self.handshake_state = handshake_state_snapshot;
            self.handshake_confirmed = handshake_confirmed_snapshot;
            self.local_one_rtt_key_update_ack_threshold = local_one_rtt_key_update_ack_threshold_snapshot;
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
            self.pending_stop_sending.items.len = pending_stop_sending_count;
            self.pending_max_frames.items.len = pending_max_frame_count;
            self.recv_max_data = recv_max_data_snapshot;
            self.recv_max_streams_bidi = recv_max_streams_bidi_snapshot;
            self.recv_max_streams_uni = recv_max_streams_uni_snapshot;
            self.closed = closed_snapshot;
            self.state = state_snapshot;
            self.close_deadline_millis = close_deadline_millis_snapshot;
            if (peer_close_snapshot == .absent) self.clearPeerClose();
            self.rollbackCryptoFrameQueueFromSnapshots(packet_space.crypto_send_queue, crypto_send_queue_snapshots);
            crypto_send_queue_snapshots_restored = true;
            packet_space.crypto_recv_buffer.items.len = crypto_recv_buffer_len_snapshot;
            self.rollbackCryptoFrameQueue(packet_space.crypto_recv_pending, crypto_recv_pending_count_snapshot);
            packet_space.crypto_read_offset.* = crypto_read_offset_snapshot;
            self.rollbackSentPackets(packet_space.sent_packets, sent_packet_snapshots);
            sent_packet_snapshots_restored = true;
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
        var received_handshake_done = false;
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
                .handshake_done => {
                    try self.receiveHandshakeDoneFrame();
                    received_handshake_done = true;
                },
                .connection_close => |connection_close| try self.receiveConnectionCloseFrame(now_millis, connection_close),
                .application_close => |application_close| try self.receiveApplicationCloseFrame(now_millis, application_close),
                else => {},
            }

            offset += decoded.len;
        }

        if (ack_eliciting and !self.closed) {
            try self.queueAckForReceivedPacket(space);
        }
        self.markHandshakeSpaceUsed(space);
        try self.drainPendingRecvStreams();
        self.recordPacketActivity(now_millis);
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
        self.dropObsoleteStopSendingFrames();
        if (self.pending_stop_sending.items.len != 0) {
            return try self.pollStopSending(ack_to_send, now_millis, out_buf);
        }
        if (self.pending_retire_connection_ids.items.len != 0) {
            return try self.pollRetireConnectionId(ack_to_send, now_millis, out_buf);
        }
        if (self.pending_handshake_done) {
            return try self.pollHandshakeDone(ack_to_send, now_millis, out_buf);
        }
        if (self.pendingNewConnectionIdCount() != 0) {
            return try self.pollNewConnectionId(ack_to_send, now_millis, out_buf);
        }
        if (self.pending_new_tokens.items.len != 0) {
            return try self.pollNewToken(ack_to_send, now_millis, out_buf);
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
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_millis, out_buf);
            } else {
                return error.BufferTooSmall;
            }
        }

        if (!self.canSendAckElicitingInSpace(.application, encoded_len) or !self.canSendToPeerAddress(encoded_len)) return null;
        if (out_buf.len < encoded_len) return error.BufferTooSmall;
        if (self.next_packet_number > max_quic_varint) return error.Internal;

        const sent_stream_frame = try self.clonePendingStreamFrame(pending);
        var sent_stream_frame_transferred = false;
        errdefer if (!sent_stream_frame_transferred) {
            self.allocator.free(sent_stream_frame.data);
        };

        var appended_sent_packet = false;
        errdefer if (appended_sent_packet) {
            var removed_sent_packet = self.sent_packets.orderedRemove(self.sent_packets.items.len - 1);
            removed_sent_packet.deinit(self.allocator);
        };

        const packet_number = self.next_packet_number;
        self.sent_packets.append(self.allocator, .{
            .packet_number = packet_number,
            .sent_time_millis = now_millis,
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
        self.recordAckElicitingSendInSpace(.application, written.len);
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
        self.markHandshakeSpaceUsed(space);
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

        const stream_state = try self.appendRecvStreamState(stream_id);
        appended_recv_state = true;

        try self.queueStopSending(stream_state, application_error_code);
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

    /// Queue the server-only HANDSHAKE_DONE frame for Application/1-RTT transmission.
    ///
    /// This marks the modeled server handshake confirmed, discards Handshake
    /// packet-number-space state and installed Handshake keys, and queues at
    /// most one HANDSHAKE_DONE frame. The frame is consumed only after a
    /// successful `pollTx()` or `pollProtectedShortDatagram()` send commit.
    pub fn sendHandshakeDone(self: *QuicConnection) Error!void {
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
    pub fn issueNewToken(self: *QuicConnection, token: []const u8) Error!void {
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
        self: *QuicConnection,
        space: PacketNumberSpace,
        backend: CryptoBackend,
        scratch: []u8,
    ) Error!CryptoBackendProgress {
        if (scratch.len == 0) return error.BufferTooSmall;

        var progress = CryptoBackendProgress{};

        if (backend.set_local_transport_parameters != null) {
            const local_transport_parameters = try self.encodeLocalTransportParameters(scratch);
            if (try backend.setLocalTransportParameters(local_transport_parameters)) {
                progress.local_transport_parameters_bytes = local_transport_parameters.len;
            }
        }

        while (try self.recvCryptoInSpace(space, scratch)) |n| {
            if (n == 0) return error.BufferTooSmall;
            try backend.receive(backend.context, space, scratch[0..n]);
            progress.inbound_chunks += 1;
            progress.inbound_bytes += n;
        }

        if (try backend.pullPeerTransportParameters(scratch)) |peer_transport_parameters| {
            try self.applyPeerTransportParameterBytes(peer_transport_parameters);
            progress.peer_transport_parameters_bytes = peer_transport_parameters.len;
            progress.peer_transport_parameters_applied = true;
        }

        if (try backend.pullHandshakeTrafficSecrets()) |secrets| {
            try self.installHandshakeTrafficSecrets(secrets);
            progress.handshake_keys_installed = true;
        }

        if (try backend.pullZeroRttTrafficSecrets()) |secrets| {
            try self.installZeroRttTrafficSecrets(secrets);
            progress.zero_rtt_keys_installed = true;
        }

        if (try backend.pullOneRttTrafficSecrets()) |secrets| {
            try self.installOneRttTrafficSecrets(secrets);
            progress.one_rtt_keys_installed = true;
        }

        while (try backend.pull(backend.context, space, scratch)) |outbound| {
            if (outbound.len == 0) break;
            try self.sendCryptoInSpace(space, outbound);
            progress.outbound_chunks += 1;
            progress.outbound_bytes += outbound.len;
        }

        const backend_confirmed = backend.isHandshakeConfirmed();
        if (backend_confirmed and !self.handshake_confirmed) {
            try self.confirmHandshake();
        }
        if (backend_confirmed and space == .handshake and progress.outbound_chunks == 0) {
            self.discardPacketNumberSpaceState(.handshake);
        }
        progress.handshake_confirmed = self.handshake_confirmed;
        return progress;
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
        if (stream_state.reset_error_code != null) {
            try self.queueClosedReceiveStreamCountCredit(stream_state);
            return error.StreamClosed;
        }
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

    fn appendRecvStreamState(self: *QuicConnection, stream_id: u64) Error!*RecvStreamState {
        self.recv_streams.append(self.allocator, .{
            .stream_id = stream_id,
            .max_data = self.recv_max_stream_data,
        }) catch return error.OutOfMemory;
        return &self.recv_streams.items[self.recv_streams.items.len - 1];
    }

    fn ensureRecvStreamState(self: *QuicConnection, stream_id: u64) Error!*RecvStreamState {
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
        try self.queueClosedReceiveStreamCountCredit(stream_state);
    }

    fn queueClosedReceiveStreamCountCredit(
        self: *QuicConnection,
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

    fn nextReceiveConnectionDataLimit(self: QuicConnection, consumed: u64) Error!u64 {
        var next_limit = std.math.add(u64, self.recv_max_data, consumed) catch return error.Internal;
        if (self.config.receive_connection_window) |window| {
            const target_limit = std.math.add(u64, self.recv_data_bytes, window) catch return error.Internal;
            next_limit = @max(next_limit, target_limit);
        }
        if (next_limit > max_quic_varint) return error.Internal;
        return next_limit;
    }

    fn nextReceiveStreamDataLimit(self: QuicConnection, stream_state: RecvStreamState, consumed: u64) Error!u64 {
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
        self: *QuicConnection,
        queue: *std.ArrayList(PendingCryptoFrame),
        original_len: usize,
    ) void {
        self.rollbackCryptoFrameQueue(queue, original_len);
    }

    fn rollbackCryptoFrameQueue(
        self: *QuicConnection,
        queue: *std.ArrayList(PendingCryptoFrame),
        original_len: usize,
    ) void {
        while (queue.items.len > original_len) {
            const removed = queue.orderedRemove(queue.items.len - 1);
            self.allocator.free(removed.data);
        }
    }

    fn rollbackCryptoFrameQueueFromSnapshots(
        self: *QuicConnection,
        queue: *std.ArrayList(PendingCryptoFrame),
        snapshots: []const PendingCryptoFrame,
    ) void {
        deinitPendingCryptoFrameSlice(self.allocator, queue.items);
        queue.items.len = snapshots.len;
        @memcpy(queue.items[0..snapshots.len], snapshots);
    }

    fn rollbackSendQueue(self: *QuicConnection, original_len: usize) void {
        while (self.send_queue.items.len > original_len) {
            const removed = self.send_queue.orderedRemove(self.send_queue.items.len - 1);
            self.allocator.free(removed.data);
        }
    }

    fn rollbackSendQueueFromSnapshots(
        self: *QuicConnection,
        snapshots: []const PendingStreamFrame,
    ) void {
        deinitPendingStreamFrameSlice(self.allocator, self.send_queue.items);
        self.send_queue.items.len = snapshots.len;
        @memcpy(self.send_queue.items[0..snapshots.len], snapshots);
    }

    fn clonePendingStreamFrame(self: *QuicConnection, pending: PendingStreamFrame) Error!PendingStreamFrame {
        const data = self.allocator.dupe(u8, pending.data) catch return error.OutOfMemory;
        return .{
            .stream_id = pending.stream_id,
            .offset = pending.offset,
            .fin = pending.fin,
            .data = data,
        };
    }

    fn clonePendingStreamFrames(
        self: *QuicConnection,
        frames: []const PendingStreamFrame,
    ) Error![]PendingStreamFrame {
        const snapshots = self.allocator.alloc(PendingStreamFrame, frames.len) catch return error.OutOfMemory;
        var cloned_count: usize = 0;
        errdefer {
            deinitPendingStreamFrameSlice(self.allocator, snapshots[0..cloned_count]);
            self.allocator.free(snapshots);
        }

        for (frames, 0..) |pending, i| {
            snapshots[i] = try self.clonePendingStreamFrame(pending);
            cloned_count += 1;
        }
        return snapshots;
    }

    fn clonePendingCryptoFrame(self: *QuicConnection, pending: PendingCryptoFrame) Error!PendingCryptoFrame {
        const data = self.allocator.dupe(u8, pending.data) catch return error.OutOfMemory;
        return .{
            .offset = pending.offset,
            .data = data,
        };
    }

    fn clonePendingCryptoFrames(
        self: *QuicConnection,
        frames: []const PendingCryptoFrame,
    ) Error![]PendingCryptoFrame {
        const snapshots = self.allocator.alloc(PendingCryptoFrame, frames.len) catch return error.OutOfMemory;
        var cloned_count: usize = 0;
        errdefer {
            deinitPendingCryptoFrameSlice(self.allocator, snapshots[0..cloned_count]);
            self.allocator.free(snapshots);
        }

        for (frames, 0..) |pending, i| {
            snapshots[i] = try self.clonePendingCryptoFrame(pending);
            cloned_count += 1;
        }
        return snapshots;
    }

    fn cloneSentPacket(self: *QuicConnection, sent_packet: SentPacket) Error!SentPacket {
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

    fn cloneSentPackets(self: *QuicConnection, sent_packets: []const SentPacket) Error![]SentPacket {
        const snapshots = self.allocator.alloc(SentPacket, sent_packets.len) catch return error.OutOfMemory;
        var cloned_count: usize = 0;
        errdefer {
            deinitSentPacketSlice(self.allocator, snapshots[0..cloned_count]);
            self.allocator.free(snapshots);
        }

        for (sent_packets, 0..) |sent_packet, i| {
            snapshots[i] = try self.cloneSentPacket(sent_packet);
            cloned_count += 1;
        }
        return snapshots;
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
        snapshots: []const SentPacket,
    ) void {
        clearSentPacketList(self.allocator, sent_packets);
        sent_packets.items.len = snapshots.len;
        @memcpy(sent_packets.items[0..snapshots.len], snapshots);
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

    fn streamDataBlockedFrameIsObsolete(self: *QuicConnection, stream_data: frame.StreamDataBlockedFrame) bool {
        if (self.findSendStream(stream_data.stream_id)) |stream_state| {
            if (stream_state.reset_sent or stream_state.fin_sent) return true;
            return stream_state.max_data > stream_data.maximum_stream_data;
        }
        return self.initialPeerStreamDataLimit(stream_data.stream_id) > stream_data.maximum_stream_data;
    }

    fn blockedFrameIsObsolete(self: *QuicConnection, blocked_frame: PendingBlockedFrame) bool {
        return switch (blocked_frame) {
            .data => |data| self.peer_max_data > data.maximum_data,
            .stream_data => |stream_data| self.streamDataBlockedFrameIsObsolete(stream_data),
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

    fn maxStreamDataFrameIsObsolete(self: *QuicConnection, stream_data: frame.MaxStreamDataFrame) bool {
        const stream_state = self.findRecvStream(stream_data.stream_id) orelse {
            return self.recv_max_stream_data > stream_data.maximum_stream_data;
        };
        if (stream_state.final_size != null or stream_state.reset_error_code != null) return true;
        return stream_state.max_data > stream_data.maximum_stream_data;
    }

    fn maxFrameIsObsolete(self: *QuicConnection, max_frame: PendingMaxFrame) bool {
        return switch (max_frame) {
            .data => |data| self.recv_max_data > data.maximum_data,
            .stream_data => |stream_data| self.maxStreamDataFrameIsObsolete(stream_data),
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

    fn stopSendingFrameIsObsolete(self: *QuicConnection, stop_sending: frame.StopSendingFrame) bool {
        const stream_state = self.findRecvStream(stop_sending.stream_id) orelse return true;
        if (stream_state.reset_error_code != null) return true;
        const final_size = stream_state.final_size orelse return false;
        const final_size_usize = std.math.cast(usize, final_size) orelse return false;
        return stream_state.data.items.len >= final_size_usize;
    }

    fn dropObsoleteStopSendingFrames(self: *QuicConnection) void {
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
        var local_key_update_acked = false;

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
                    .sent_time_millis = removed.sent_time_millis,
                    .bytes = removed.bytes,
                    .ecn_codepoint = removed.ecn_codepoint,
                };
            }
            switch (removed.ecn_codepoint) {
                .not_ect => {},
                .ect0 => newly_acked_ect0 += 1,
                .ect1 => newly_acked_ect1 += 1,
            }
            removed.deinit(self.allocator);
        }

        const ecn_result = self.validateEcnAck(
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

        const loss_result = try self.removeAckDrivenLosses(
            packet_space,
            packet_space.largest_acknowledged.* orelse ack.largest_acknowledged,
            latest_rtt_sample,
            now_millis,
        );
        if (ecn_result.ce_congestion_event) {
            if (largest_acked_packet) |acked_packet| {
                packet_space.recovery_state.onCongestionEvent(acked_packet.sent_time_millis, now_millis);
            }
        }
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
        if (local_key_update_acked) {
            self.local_one_rtt_key_update_ack_threshold = null;
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
        self: *QuicConnection,
        packet_space: PacketNumberSpaceView,
        largest_acknowledged: u64,
        latest_rtt_sample_ms: ?u64,
        now_millis: i64,
    ) Error!LossDetectionResult {
        const loss_delay_ms = recovery.timeThresholdLossDelayMs(
            latest_rtt_sample_ms orelse packet_space.recovery_state.latest_rtt_ms,
            packet_space.recovery_state.smoothed_rtt_ms,
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
            const time_threshold_lost = saturatingAddMillis(sent_packet.sent_time_millis, loss_delay_ms) <= now_millis;
            if (!packet_threshold_lost and !time_threshold_lost) {
                const deadline = saturatingAddMillis(sent_packet.sent_time_millis, loss_delay_ms);
                next_loss_deadline = if (next_loss_deadline) |current|
                    @min(current, deadline)
                else
                    deadline;
                continue;
            }

            if (sent_packet.stream_frame) |pending| {
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
        packet_space.loss_deadline_millis.* = next_loss_deadline;
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

            var removed = packet_space.sent_packets.orderedRemove(i);
            result.recordLostPacket(removed, packet_space.first_rtt_sample_sent_time_millis.*);
            removed.deinit(self.allocator);
        }
        return result;
    }

    fn expireLossDetectionTimeouts(self: *QuicConnection, now_millis: i64) Error!void {
        try self.expireLossDetectionTimeoutInSpace(.initial, now_millis);
        try self.expireLossDetectionTimeoutInSpace(.handshake, now_millis);
        try self.expireLossDetectionTimeoutInSpace(.application, now_millis);
    }

    fn expireLossDetectionTimeoutInSpace(self: *QuicConnection, space: PacketNumberSpace, now_millis: i64) Error!void {
        const packet_space = self.packetNumberSpace(space);
        const deadline = packet_space.loss_deadline_millis.* orelse return;
        if (deadline > now_millis) return;
        const largest_acknowledged = packet_space.largest_acknowledged.* orelse {
            packet_space.loss_deadline_millis.* = null;
            return;
        };
        const loss_result = try self.removeAckDrivenLosses(packet_space, largest_acknowledged, null, now_millis);
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

    fn hasPendingPtoProbeDataInSpace(self: *QuicConnection, space: PacketNumberSpace) bool {
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

    fn queuePtoProbeInSpace(self: *QuicConnection, space: PacketNumberSpace) Error!void {
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

    fn queuePtoPeerSpaceProbes(self: *QuicConnection, expired_space: PacketNumberSpace) Error!void {
        const spaces = [_]PacketNumberSpace{ .initial, .handshake, .application };
        for (spaces) |space| {
            if (space == expired_space) continue;

            const packet_space = self.packetNumberSpace(space);
            if (packet_space.discarded.* or packet_space.sent_packets.items.len == 0) continue;
            try self.queuePtoProbeInSpace(space);
        }
    }

    fn checkPtoTimeoutInSpace(self: *QuicConnection, space: PacketNumberSpace, now_millis: i64) Error!bool {
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return false;
        const deadline = self.ptoDeadlineMillis(space) orelse return false;
        if (deadline > now_millis) return false;
        try self.queuePtoProbeInSpace(space);
        packet_space.recovery_state.onPtoExpired();
        return true;
    }

    fn queuePtoCryptoRetransmission(self: *QuicConnection, space: PacketNumberSpace) Error!bool {
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

    fn queuePtoControlRetransmission(self: *QuicConnection, space: PacketNumberSpace) Error!bool {
        if (space != .application) return false;
        const packet_space = self.packetNumberSpace(space);
        for (packet_space.sent_packets.items) |sent_packet| {
            if (sent_packet.reset_stream_frame) |reset| {
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

    fn queuePtoStreamRetransmission(self: *QuicConnection, space: PacketNumberSpace) Error!bool {
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
        self.maybeDiscardInitialAfterHandshakePacketSent(space);
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
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_millis, out_buf);
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
        self.recordAckElicitingSendInSpace(.application, written.len);
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
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_millis, out_buf);
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
        self.recordAckElicitingSendInSpace(.application, written.len);
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
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_millis, out_buf);
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
        self.recordAckElicitingSendInSpace(.application, written.len);
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
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_millis, out_buf);
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
        self.recordAckElicitingSendInSpace(.application, written.len);
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
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_millis, out_buf);
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
        self.recordAckElicitingSendInSpace(.application, written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_millis);
        return written;
    }

    fn pollHandshakeDone(
        self: *QuicConnection,
        ack_to_send: ?frame.AckFrame,
        now_millis: i64,
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
                return try self.pollAckOnly(ack, now_millis, out_buf);
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
        self.recordPacketActivity(now_millis);
        return written;
    }

    fn pollNewToken(
        self: *QuicConnection,
        ack_to_send: ?frame.AckFrame,
        now_millis: i64,
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
                return try self.pollAckOnly(ack, now_millis, out_buf);
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
                self.canSendAckElicitingInSpace(space, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnlyInSpace(space, ack, now_millis, out_buf);
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
        self.recordAckElicitingSendInSpace(space, written.len);
        self.recordPeerAddressBytesSent(written.len);
        self.recordPacketActivity(now_millis);
        self.maybeDiscardInitialAfterHandshakePacketSent(space);
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
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_millis, out_buf);
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
        self.recordAckElicitingSendInSpace(.application, written.len);
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
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_millis, out_buf);
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
        self.recordAckElicitingSendInSpace(.application, written.len);
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
                self.canSendAckElicitingInSpace(.application, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnly(ack, now_millis, out_buf);
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
        self.recordAckElicitingSendInSpace(.application, written.len);
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
                self.canSendAckElicitingInSpace(space, coalesced_len) and self.canSendToPeerAddress(coalesced_len))
            {
                encoded_len = coalesced_len;
                include_ack = true;
            } else if (ack_encoded_len <= max_tx_datagram_size and out_buf.len >= ack_encoded_len) {
                return try self.pollAckOnlyInSpace(space, ack, now_millis, out_buf);
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
            .sent_time_millis = now_millis,
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
        self.recordPacketActivity(now_millis);
        self.maybeDiscardInitialAfterHandshakePacketSent(space);
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

    fn localStatelessResetTokenValueExists(
        self: QuicConnection,
        stateless_reset_token: [packet.stateless_reset_token_len]u8,
    ) bool {
        for (self.local_connection_ids.items) |local_id| {
            if (statelessResetTokensEqual(local_id.stateless_reset_token, stateless_reset_token)) return true;
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

    fn activeStatelessResetTokenValueExists(
        self: QuicConnection,
        stateless_reset_token: [packet.stateless_reset_token_len]u8,
    ) bool {
        for (self.active_connection_ids.items) |active_id| {
            if (statelessResetTokensEqual(active_id.stateless_reset_token, stateless_reset_token)) return true;
        }
        return false;
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
            if (!statelessResetTokensEqual(existing.stateless_reset_token, new_connection_id.stateless_reset_token)) return error.InvalidPacket;
            return;
        }

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
        self.handshake_state = .confirmed;
        self.handshake_confirmed = true;
    }

    fn receiveDataBlockedFrame(self: *QuicConnection, data_blocked: frame.DataBlockedFrame) Error!void {
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

    fn receiveStreamDataBlockedFrame(self: *QuicConnection, stream_data_blocked: frame.StreamDataBlockedFrame) Error!void {
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

    fn receiveStreamsBlockedBidiFrame(self: *QuicConnection, streams_blocked: frame.StreamsBlockedBidiFrame) Error!void {
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

    fn receiveStreamsBlockedUniFrame(self: *QuicConnection, streams_blocked: frame.StreamsBlockedUniFrame) Error!void {
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

    fn receiveMaxDataFrame(self: *QuicConnection, max_data: frame.MaxDataFrame) void {
        self.peer_max_data = @max(self.peer_max_data, max_data.maximum_data);
    }

    fn applyMaxStreamDataToSendStream(stream_state: *SendStreamState, maximum_stream_data: u64) void {
        if (stream_state.fin_sent) return;
        stream_state.max_data = @max(stream_state.max_data, maximum_stream_data);
    }

    fn receiveMaxStreamDataFrame(self: *QuicConnection, max_stream_data: frame.MaxStreamDataFrame) Error!void {
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

    const ReceiveStreamFrameData = struct {
        offset: u64,
        data: []const u8,
    };

    fn trimAlreadyReceivedStreamData(
        stream_state: RecvStreamState,
        offset: u64,
        data: []const u8,
    ) Error!ReceiveStreamFrameData {
        if (data.len == 0) return .{ .offset = offset, .data = data };

        const contiguous_len = std.math.cast(u64, stream_state.data.items.len) orelse return error.Internal;
        var new_offset = offset;
        var new_data = data;

        if (new_offset < contiguous_len) {
            const duplicate_len_u64 = @min(
                contiguous_len - new_offset,
                std.math.cast(u64, new_data.len) orelse return error.InvalidPacket,
            );
            const duplicate_len = std.math.cast(usize, duplicate_len_u64) orelse return error.InvalidPacket;
            const duplicate_start = std.math.cast(usize, new_offset) orelse return error.InvalidPacket;
            const duplicate_end = std.math.add(usize, duplicate_start, duplicate_len) catch return error.InvalidPacket;
            if (!std.mem.eql(u8, stream_state.data.items[duplicate_start..duplicate_end], new_data[0..duplicate_len])) {
                return error.InvalidPacket;
            }
            new_offset = streamEndOffset(new_offset, duplicate_len) orelse return error.InvalidPacket;
            new_data = new_data[duplicate_len..];
            if (new_data.len == 0) return .{ .offset = new_offset, .data = new_data };
        }

        for (stream_state.pending.items) |pending| {
            if (!streamRangesOverlap(new_offset, new_data.len, pending.offset, pending.data.len)) continue;
            if (new_offset == pending.offset and new_data.len == pending.data.len and std.mem.eql(u8, new_data, pending.data)) {
                return .{ .offset = new_offset, .data = new_data[0..0] };
            }
            return error.InvalidPacket;
        }
        return .{ .offset = new_offset, .data = new_data };
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

    fn trimAlreadyReceivedCryptoData(
        packet_space: PacketNumberSpaceView,
        offset: u64,
        data: []const u8,
    ) Error!ReceiveCryptoFrameData {
        if (data.len == 0) return .{ .offset = offset, .data = data };

        const contiguous_len = std.math.cast(u64, packet_space.crypto_recv_buffer.items.len) orelse return error.Internal;
        var new_offset = offset;
        var new_data = data;

        if (new_offset < contiguous_len) {
            const duplicate_len_u64 = @min(
                contiguous_len - new_offset,
                std.math.cast(u64, new_data.len) orelse return error.InvalidPacket,
            );
            const duplicate_len = std.math.cast(usize, duplicate_len_u64) orelse return error.InvalidPacket;
            const duplicate_start = std.math.cast(usize, new_offset) orelse return error.InvalidPacket;
            const duplicate_end = std.math.add(usize, duplicate_start, duplicate_len) catch return error.InvalidPacket;
            if (!std.mem.eql(u8, packet_space.crypto_recv_buffer.items[duplicate_start..duplicate_end], new_data[0..duplicate_len])) {
                return error.InvalidPacket;
            }
            new_offset = streamEndOffset(new_offset, duplicate_len) orelse return error.InvalidPacket;
            new_data = new_data[duplicate_len..];
            if (new_data.len == 0) return .{ .offset = new_offset, .data = new_data };
        }

        for (packet_space.crypto_recv_pending.items) |pending| {
            if (!streamRangesOverlap(new_offset, new_data.len, pending.offset, pending.data.len)) continue;
            if (new_offset == pending.offset and new_data.len == pending.data.len and std.mem.eql(u8, new_data, pending.data)) {
                return .{ .offset = new_offset, .data = new_data[0..0] };
            }
            return error.InvalidPacket;
        }
        return .{ .offset = new_offset, .data = new_data };
    }

    fn pendingCryptoFrameIndexAt(packet_space: PacketNumberSpaceView, offset: u64) ?usize {
        for (packet_space.crypto_recv_pending.items, 0..) |pending, i| {
            if (pending.offset == offset) return i;
        }
        return null;
    }

    fn drainPendingCryptoFrames(self: *QuicConnection, space: PacketNumberSpace) Error!void {
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
        self: *QuicConnection,
        space: PacketNumberSpace,
        crypto: frame.CryptoFrame,
    ) Error!void {
        const packet_space = self.packetNumberSpace(space);
        if (packet_space.discarded.*) return error.InvalidPacket;

        _ = streamEndOffset(crypto.offset, crypto.data.len) orelse return error.InvalidPacket;
        const new_frame_data = try trimAlreadyReceivedCryptoData(packet_space, crypto.offset, crypto.data);
        if (new_frame_data.data.len == 0) return;

        const contiguous_len = std.math.cast(u64, packet_space.crypto_recv_buffer.items.len) orelse return error.Internal;
        if (new_frame_data.offset == contiguous_len) {
            packet_space.crypto_recv_buffer.appendSlice(self.allocator, new_frame_data.data) catch return error.OutOfMemory;
        } else {
            try self.queueCryptoFrame(packet_space.crypto_recv_pending, new_frame_data.offset, new_frame_data.data);
        }
    }

    fn receiveStreamFrame(self: *QuicConnection, stream_frame: frame.StreamFrame) Error!void {
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

        const new_frame_data = try trimAlreadyReceivedStreamData(stream_state.*, stream_frame.offset, stream_frame.data);
        const next_recv_total = streamEndOffset(self.recv_data_bytes, new_frame_data.data.len) orelse return error.InvalidPacket;
        if (next_recv_total > self.recv_max_data) return error.InvalidPacket;

        const contiguous_len = std.math.cast(u64, stream_state.data.items.len) orelse return error.Internal;
        if (new_frame_data.data.len != 0) {
            if (new_frame_data.offset == contiguous_len) {
                stream_state.data.appendSlice(self.allocator, new_frame_data.data) catch return error.OutOfMemory;
            } else {
                try self.appendPendingRecvStreamFrame(stream_state, new_frame_data.offset, new_frame_data.data);
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

const TestControlFrameExpectation = union(enum) {
    reset_stream: frame.ResetStreamFrame,
    stop_sending: frame.StopSendingFrame,
};

fn payloadContainsExpectedControlFrame(
    payload: []const u8,
    expected: TestControlFrameExpectation,
) !bool {
    var offset: usize = 0;
    while (offset < payload.len) {
        var decoded = try frame.decodeFrameSlice(payload[offset..], std.testing.allocator);
        const decoded_len = decoded.len;
        defer frame.deinitFrame(&decoded.frame, std.testing.allocator);

        const matched = switch (decoded.frame) {
            .reset_stream => |reset| switch (expected) {
                .reset_stream => |want| reset.stream_id == want.stream_id and
                    reset.application_error_code == want.application_error_code and
                    reset.final_size == want.final_size,
                else => false,
            },
            .stop_sending => |stop_sending| switch (expected) {
                .stop_sending => |want| stop_sending.stream_id == want.stream_id and
                    stop_sending.application_error_code == want.application_error_code,
                else => false,
            },
            .padding => false,
            else => false,
        };
        if (matched) return true;
        if (decoded_len == 0) return error.TestUnexpectedResult;
        offset += decoded_len;
    }
    return false;
}

fn protectedZeroRttContainsControlFrame(
    datagram: []const u8,
    keys: protection.Aes128PacketProtectionKeys,
    expected_packet_number: u64,
    expected: TestControlFrameExpectation,
) !bool {
    var opened = try protection.unprotectLongPacketAes128(
        std.testing.allocator,
        keys,
        datagram,
        expected_packet_number,
    );
    defer protection.deinitProtectedLongPacket(&opened, std.testing.allocator);

    try std.testing.expectEqual(packet.PacketType.zero_rtt, opened.packet.header.packet_type);
    try std.testing.expectEqual(expected_packet_number, opened.packet.header.packet_number);
    return try payloadContainsExpectedControlFrame(opened.packet.plaintext, expected);
}

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
    try std.testing.expectError(error.InvalidPacket, QuicConnection.init(std.testing.allocator, .client, .{
        .ack_delay_exponent = 21,
    }));
    try std.testing.expectError(error.InvalidPacket, QuicConnection.init(std.testing.allocator, .client, .{
        .max_ack_delay_ms = 1 << 14,
    }));
    try std.testing.expectError(error.InvalidStream, QuicConnection.init(std.testing.allocator, .client, .{
        .receive_stream_count_window = max_stream_count + 1,
    }));
}

test "PreferredAddress owns fixed connection ID storage" {
    const reset_token = [_]u8{0xa5} ** packet.stateless_reset_token_len;
    const cid = [_]u8{ 0xc1, 0xc2, 0xc3 };
    const preferred = try PreferredAddress.init(
        .{ 192, 0, 2, 10 },
        4433,
        .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        4434,
        &cid,
        reset_token,
    );

    try std.testing.expectEqualSlices(u8, &cid, preferred.connectionId());
    try std.testing.expectError(error.InvalidPacket, PreferredAddress.init(
        .{ 192, 0, 2, 10 },
        4433,
        .{0} ** 16,
        4434,
        &[_]u8{},
        reset_token,
    ));
}

test "localTransportParameters exposes configured receive limits" {
    const available_versions = [_]packet.Version{ .v2, .v1 };
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .max_datagram_size = 1400,
        .max_idle_timeout_ms = 30_000,
        .disable_active_migration = true,
        .initial_max_data = 12_345,
        .initial_max_stream_data = 2345,
        .initial_max_streams_bidi = 12,
        .initial_max_streams_uni = 6,
        .active_connection_id_limit = 4,
        .available_versions = &available_versions,
    });
    defer conn.deinit();

    const params = conn.localTransportParameters();
    try std.testing.expect(params.stateless_reset_token == null);
    try std.testing.expect(params.original_destination_connection_id == null);
    try std.testing.expect(params.initial_source_connection_id == null);
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
    const version_information = params.version_information orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(packet.Version.v1, version_information.chosen_version);
    try std.testing.expectEqualSlices(packet.Version, &available_versions, version_information.available_versions);
}

test "version_information transport parameter validation follows endpoint role" {
    const v2_first = [_]packet.Version{ .v2, .v1 };
    const v1_only = [_]packet.Version{.v1};

    try std.testing.expectError(error.InvalidPacket, QuicConnection.init(std.testing.allocator, .client, .{
        .chosen_version = @enumFromInt(0),
        .available_versions = &v1_only,
    }));
    try std.testing.expectError(error.InvalidPacket, QuicConnection.init(std.testing.allocator, .client, .{
        .chosen_version = .v1,
        .available_versions = &[_]packet.Version{.v2},
    }));

    var server = try QuicConnection.init(std.testing.allocator, .server, .{
        .chosen_version = .v1,
        .available_versions = &v2_first,
    });
    defer server.deinit();
    try server.applyPeerTransportParameters(.{
        .initial_max_data = 7,
        .version_information = .{
            .chosen_version = .v1,
            .available_versions = &v2_first,
        },
    });
    try std.testing.expectEqual(@as(u64, 7), server.peer_max_data);

    try std.testing.expectError(error.InvalidPacket, server.applyPeerTransportParameters(.{
        .initial_max_data = 8,
        .version_information = .{
            .chosen_version = .v1,
            .available_versions = &[_]packet.Version{.v2},
        },
    }));
    try std.testing.expectEqual(@as(u64, 7), server.peer_max_data);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{
        .available_versions = &v1_only,
    });
    defer client.deinit();
    try std.testing.expectError(error.InvalidPacket, client.applyPeerTransportParameters(.{
        .version_information = .{
            .chosen_version = .v2,
            .available_versions = &v2_first,
        },
    }));
}

test "version_information validates downgrade state after Version Negotiation" {
    const v2_first = [_]packet.Version{ .v2, .v1 };
    const v1_first = [_]packet.Version{ .v1, .v2 };

    try std.testing.expectError(error.InvalidPacket, QuicConnection.init(std.testing.allocator, .server, .{
        .version_negotiation_selected_version = .v1,
    }));
    try std.testing.expectError(error.InvalidPacket, QuicConnection.init(std.testing.allocator, .client, .{
        .chosen_version = .v1,
        .available_versions = &v2_first,
        .version_negotiation_selected_version = .v2,
    }));

    var client = try QuicConnection.init(std.testing.allocator, .client, .{
        .chosen_version = .v2,
        .available_versions = &v2_first,
        .version_negotiation_selected_version = .v2,
    });
    defer client.deinit();

    try client.applyPeerTransportParameters(.{
        .initial_max_data = 11,
        .version_information = .{
            .chosen_version = .v2,
            .available_versions = &v2_first,
        },
    });
    try std.testing.expectEqual(@as(u64, 11), client.peer_max_data);

    try std.testing.expectError(error.InvalidPacket, client.applyPeerTransportParameters(.{
        .initial_max_data = 12,
        .version_information = .{
            .chosen_version = .v1,
            .available_versions = &v1_first,
        },
    }));
    try std.testing.expectError(error.InvalidPacket, client.applyPeerTransportParameters(.{
        .initial_max_data = 13,
        .version_information = .{
            .chosen_version = .v2,
            .available_versions = &[_]packet.Version{},
        },
    }));
    try std.testing.expectEqual(@as(u64, 11), client.peer_max_data);
}

test "version_information rejects downgrade after forged Version Negotiation" {
    const v2_first = [_]packet.Version{ .v2, .v1 };
    const v1_first = [_]packet.Version{ .v1, .v2 };

    var downgraded = try QuicConnection.init(std.testing.allocator, .client, .{
        .chosen_version = .v1,
        .available_versions = &v2_first,
        .version_negotiation_selected_version = .v1,
    });
    defer downgraded.deinit();

    try std.testing.expectError(error.InvalidPacket, downgraded.applyPeerTransportParameters(.{
        .initial_max_data = 10,
        .version_information = .{
            .chosen_version = .v1,
            .available_versions = &v1_first,
        },
    }));
    try std.testing.expectEqual(@as(u64, 65_536), downgraded.peer_max_data);
}

test "missing version_information after Version Negotiation follows v1 exception" {
    const v2_first = [_]packet.Version{ .v2, .v1 };
    const v1_only = [_]packet.Version{.v1};

    var selected_v2 = try QuicConnection.init(std.testing.allocator, .client, .{
        .chosen_version = .v2,
        .available_versions = &v2_first,
        .version_negotiation_selected_version = .v2,
    });
    defer selected_v2.deinit();
    try std.testing.expectError(error.InvalidPacket, selected_v2.applyPeerTransportParameters(.{
        .initial_max_data = 10,
    }));
    try std.testing.expectEqual(@as(u64, 65_536), selected_v2.peer_max_data);

    var selected_v1 = try QuicConnection.init(std.testing.allocator, .client, .{
        .chosen_version = .v1,
        .available_versions = &v1_only,
        .version_negotiation_selected_version = .v1,
    });
    defer selected_v1.deinit();
    try selected_v1.applyPeerTransportParameters(.{
        .initial_max_data = 10,
    });
    try std.testing.expectEqual(@as(u64, 10), selected_v1.peer_max_data);
}

test "localTransportParameters keeps local ACK policy separate from peer recovery policy" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .ack_delay_exponent = 7,
        .max_ack_delay_ms = 15,
    });
    defer conn.deinit();

    const before = conn.localTransportParameters();
    try std.testing.expectEqual(@as(u64, 7), before.ack_delay_exponent);
    try std.testing.expectEqual(@as(u64, 15), before.max_ack_delay);

    try conn.applyPeerTransportParameters(.{
        .ack_delay_exponent = 4,
        .max_ack_delay = 50,
    });
    try std.testing.expectEqual(@as(u64, 4), conn.peer_ack_delay_exponent);
    try std.testing.expectEqual(@as(u64, 50), conn.recovery_state.max_ack_delay_ms);

    const after = conn.localTransportParameters();
    try std.testing.expectEqual(@as(u64, 7), after.ack_delay_exponent);
    try std.testing.expectEqual(@as(u64, 15), after.max_ack_delay);
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

test "localTransportParameters advertises server preferred address only" {
    const reset_token = [_]u8{0x44} ** packet.stateless_reset_token_len;
    const cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const preferred = try PreferredAddress.init(
        .{ 203, 0, 113, 7 },
        8443,
        .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7 },
        8444,
        &cid,
        reset_token,
    );

    try std.testing.expectError(error.InvalidPacket, QuicConnection.init(std.testing.allocator, .client, .{
        .preferred_address = preferred,
    }));

    var server = try QuicConnection.init(std.testing.allocator, .server, .{
        .preferred_address = preferred,
    });
    defer server.deinit();

    const exported = server.localTransportParameters().preferred_address orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &preferred.ipv4_address, &exported.ipv4_address);
    try std.testing.expectEqual(preferred.ipv4_port, exported.ipv4_port);
    try std.testing.expectEqualSlices(u8, preferred.connectionId(), exported.connection_id);
    try std.testing.expectEqualSlices(u8, &reset_token, &exported.stateless_reset_token);
}

test "transport parameter TLS extension bytes roundtrip through connection API" {
    const reset_token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const preferred_cid = [_]u8{ 0xf5, 0xf6, 0xf7, 0xf8 };
    const preferred = try PreferredAddress.init(
        .{ 198, 51, 100, 7 },
        4433,
        .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7 },
        4434,
        &preferred_cid,
        reset_token,
    );

    var server = try QuicConnection.init(std.testing.allocator, .server, .{
        .max_datagram_size = 1300,
        .max_idle_timeout_ms = 250,
        .stateless_reset_token = reset_token,
        .preferred_address = preferred,
        .initial_max_data = 4096,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 3,
        .initial_max_streams_uni = 2,
    });
    defer server.deinit();

    var extension_bytes_buf: [256]u8 = undefined;
    const extension_bytes = try server.encodeLocalTransportParameters(&extension_bytes_buf);
    try std.testing.expect(extension_bytes.len > 0);

    var parsed = try transport_parameters.parse(extension_bytes, std.testing.allocator);
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 4096), parsed.initial_max_data);
    try std.testing.expectEqual(@as(u64, 1300), parsed.max_udp_payload_size);
    try std.testing.expect(parsed.stateless_reset_token != null);
    try std.testing.expect(parsed.preferred_address != null);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try client.applyPeerTransportParameterBytes(extension_bytes);
    try std.testing.expectEqual(@as(u64, 4096), client.peer_max_data);
    try std.testing.expectEqual(@as(usize, 1300), client.maxTxDatagramSize());
    try std.testing.expectEqual(@as(?u64, 250), client.effectiveIdleTimeoutMillis());
    const peer_reset = client.peerStatelessResetToken() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &reset_token, &peer_reset);
    const peer_preferred = client.peerPreferredAddress() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &preferred_cid, peer_preferred.connectionId());

    var too_small: [1]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, server.encodeLocalTransportParameters(&too_small));
}

test "applyPeerTransportParameterBytes rejects malformed or invalid extensions without mutation" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    const malformed = [_]u8{0x04};
    try std.testing.expectError(error.InvalidPacket, conn.applyPeerTransportParameterBytes(&malformed));
    try std.testing.expectEqual(@as(u64, 65_536), conn.peer_max_data);
    try std.testing.expect(conn.peerStatelessResetToken() == null);

    const reset_token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    var server_only_raw: [64]u8 = undefined;
    var server_only_out = buffer.fixedWriter(&server_only_raw);
    try transport_parameters.encode(server_only_out.writer(), .{
        .stateless_reset_token = reset_token,
        .initial_max_data = 7,
    });

    try std.testing.expectError(
        error.InvalidPacket,
        conn.applyPeerTransportParameterBytes(server_only_out.getWritten()),
    );
    try std.testing.expectEqual(@as(u64, 65_536), conn.peer_max_data);
    try std.testing.expect(conn.peerStatelessResetToken() == null);
    try std.testing.expectEqual(ConnectionState.active, conn.connectionState());
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
    const preferred_cid = [_]u8{ 0xf1, 0xf2, 0xf3, 0xf4 };
    const preferred = try PreferredAddress.init(
        .{ 198, 51, 100, 42 },
        4433,
        .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42 },
        4434,
        &preferred_cid,
        reset_token,
    );

    try conn.applyPeerTransportParameters(.{
        .stateless_reset_token = reset_token,
        .preferred_address = preferred.asTransportParameter(),
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
    const stored_preferred = conn.peerPreferredAddress() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &preferred.ipv4_address, &stored_preferred.ipv4_address);
    try std.testing.expectEqual(preferred.ipv4_port, stored_preferred.ipv4_port);
    try std.testing.expectEqualSlices(u8, preferred.connectionId(), stored_preferred.connectionId());
    try std.testing.expectEqualSlices(u8, &reset_token, &stored_preferred.stateless_reset_token);
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
    const preferred = try PreferredAddress.init(.{ 203, 0, 113, 9 }, 4433, .{0} ** 16, 4434, &[_]u8{0xc1}, token);
    try std.testing.expectError(error.InvalidPacket, conn.applyPeerTransportParameters(.{
        .stateless_reset_token = token,
        .initial_max_data = 1,
    }));
    try std.testing.expectError(error.InvalidPacket, conn.applyPeerTransportParameters(.{
        .preferred_address = preferred.asTransportParameter(),
        .initial_max_data = 2,
    }));
    try std.testing.expectEqual(@as(u64, 65_536), conn.peer_max_data);
    try std.testing.expectEqual(@as(u64, 3), conn.peer_ack_delay_exponent);
    try std.testing.expect(conn.peerStatelessResetToken() == null);
    try std.testing.expect(conn.peerPreferredAddress() == null);
    try std.testing.expectEqual(ConnectionState.active, conn.connectionState());
}

test "applyPeerTransportParameters validates retry_source_connection_id" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const retry_scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const other_scid = [_]u8{ 0x99, 0x88, 0x77, 0x66 };
    const retry = packet.RetryPacket{
        .version = .v1,
        .dcid = &client_scid,
        .scid = &retry_scid,
        .token = "retry-token-for-client-address",
        .integrity_tag = [_]u8{0} ** protection.aead_tag_len,
    };
    const retry_datagram = try protection.encodeRetryPacketWithIntegrity(std.testing.allocator, &original_dcid, retry);
    defer std.testing.allocator.free(retry_datagram);

    var no_retry = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer no_retry.deinit();
    try std.testing.expectError(error.InvalidPacket, no_retry.applyPeerTransportParameters(.{
        .retry_source_connection_id = &retry_scid,
        .initial_max_data = 7,
    }));
    try std.testing.expectEqual(@as(u64, 65_536), no_retry.peer_max_data);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try client.processRetryDatagram(10, &original_dcid, retry_datagram);

    try std.testing.expectError(error.InvalidPacket, client.applyPeerTransportParameters(.{
        .original_destination_connection_id = &original_dcid,
        .initial_max_data = 8,
    }));
    try std.testing.expectError(error.InvalidPacket, client.applyPeerTransportParameters(.{
        .original_destination_connection_id = &original_dcid,
        .retry_source_connection_id = &other_scid,
        .initial_max_data = 9,
    }));
    try std.testing.expectError(error.InvalidPacket, client.applyPeerTransportParameters(.{
        .original_destination_connection_id = &other_scid,
        .retry_source_connection_id = &retry_scid,
        .initial_max_data = 9,
    }));
    try std.testing.expectEqual(@as(u64, 65_536), client.peer_max_data);
    try std.testing.expectEqualStrings(&original_dcid, client.originalDestinationConnectionId().?);

    try client.applyPeerTransportParameters(.{
        .original_destination_connection_id = &original_dcid,
        .retry_source_connection_id = &retry_scid,
        .initial_max_data = 10,
    });
    try std.testing.expectEqual(@as(u64, 10), client.peer_max_data);
}

test "issueRetryDatagram records Retry transport parameters and token" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const retry_scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const retry_token = "retry-token-for-client-address";

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    const retry_datagram = try server.issueRetryDatagram(
        10,
        &original_dcid,
        &client_scid,
        &retry_scid,
        retry_token,
    );
    defer std.testing.allocator.free(retry_datagram);

    try std.testing.expect(try protection.verifyRetryIntegrityTag(std.testing.allocator, &original_dcid, retry_datagram));
    try std.testing.expectEqualStrings(&original_dcid, server.originalDestinationConnectionId().?);
    try std.testing.expectEqualStrings(&retry_scid, server.retrySourceConnectionId().?);
    try std.testing.expectEqual(@as(usize, 1), server.pendingRetryTokenCount());
    const server_params = server.localTransportParameters();
    try std.testing.expectEqualStrings(&original_dcid, server_params.original_destination_connection_id.?);
    try std.testing.expectEqualStrings(&retry_scid, server_params.retry_source_connection_id.?);

    try client.processRetryDatagram(11, &original_dcid, retry_datagram);
    try client.applyPeerTransportParameters(server_params);
    try std.testing.expectEqual(@as(u64, 65_536), client.peer_max_data);
    try server.validateRetryToken(client.latestRetryToken().?);
    try std.testing.expect(server.peerAddressValidated());
    try std.testing.expectEqual(@as(usize, 0), server.pendingRetryTokenCount());
}

test "issueRetryDatagram rejects invalid Retry issuance without mutation" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const retry_scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try std.testing.expectError(error.InvalidPacket, client.issueRetryDatagram(
        0,
        &original_dcid,
        &client_scid,
        &retry_scid,
        "token",
    ));

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try std.testing.expectError(error.InvalidPacket, server.issueRetryDatagram(
        1,
        &original_dcid,
        &client_scid,
        &retry_scid,
        "",
    ));
    try std.testing.expect(server.originalDestinationConnectionId() == null);
    try std.testing.expect(server.retrySourceConnectionId() == null);
    try std.testing.expectEqual(@as(usize, 0), server.pendingRetryTokenCount());

    const retry_datagram = try server.issueRetryDatagram(
        2,
        &original_dcid,
        &client_scid,
        &retry_scid,
        "token",
    );
    defer std.testing.allocator.free(retry_datagram);
    try std.testing.expectError(error.InvalidPacket, server.issueRetryDatagram(
        3,
        &original_dcid,
        &client_scid,
        &retry_scid,
        "other-token",
    ));
    try std.testing.expectEqualStrings(&original_dcid, server.originalDestinationConnectionId().?);
    try std.testing.expectEqualStrings(&retry_scid, server.retrySourceConnectionId().?);
    try std.testing.expectEqual(@as(usize, 1), server.pendingRetryTokenCount());
}

test "address-bound Retry token validation consumes token and validates address" {
    const secret: address_validation_token.Secret = [_]u8{0x42} ** address_validation_token.secret_len;
    const nonce: address_validation_token.Nonce = [_]u8{0x19} ** address_validation_token.nonce_len;
    const peer_address = "203.0.113.7:4433";
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const retry_scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    const retry_token = try server.issueAddressValidationToken(
        secret,
        .retry,
        100,
        1_000,
        peer_address,
        nonce,
    );
    defer std.testing.allocator.free(retry_token);

    const retry_datagram = try server.issueRetryDatagram(
        101,
        &original_dcid,
        &client_scid,
        &retry_scid,
        retry_token,
    );
    defer std.testing.allocator.free(retry_datagram);
    try client.processRetryDatagram(102, &original_dcid, retry_datagram);

    try std.testing.expectEqual(@as(usize, 1), server.pendingRetryTokenCount());
    try std.testing.expect(!server.peerAddressValidated());
    try server.validateAddressValidationToken(secret, .retry, 103, peer_address, client.latestRetryToken().?);
    try std.testing.expect(server.peerAddressValidated());
    try std.testing.expectEqual(@as(usize, 0), server.pendingRetryTokenCount());
    try std.testing.expectError(
        error.InvalidPacket,
        server.validateAddressValidationToken(secret, .retry, 104, peer_address, client.latestRetryToken().?),
    );
}

test "address-bound Retry token rejects wrong address or expiration without consuming" {
    const secret: address_validation_token.Secret = [_]u8{0x21} ** address_validation_token.secret_len;
    const nonce: address_validation_token.Nonce = [_]u8{0x84} ** address_validation_token.nonce_len;
    const peer_address = "198.51.100.3:4433";

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    const retry_token = try server.issueAddressValidationToken(
        secret,
        .retry,
        10,
        10,
        peer_address,
        nonce,
    );
    defer std.testing.allocator.free(retry_token);
    try server.issueRetryToken(retry_token);

    try std.testing.expectError(
        error.InvalidPacket,
        server.validateAddressValidationToken(secret, .retry, 11, "198.51.100.4:4433", retry_token),
    );
    try std.testing.expect(!server.peerAddressValidated());
    try std.testing.expectEqual(@as(usize, 1), server.pendingRetryTokenCount());

    try server.validateAddressValidationToken(secret, .retry, 20, peer_address, retry_token);
    try std.testing.expect(server.peerAddressValidated());
    try std.testing.expectEqual(@as(usize, 0), server.pendingRetryTokenCount());

    var expired_server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer expired_server.deinit();
    const expired_token = try expired_server.issueAddressValidationToken(
        secret,
        .retry,
        10,
        10,
        peer_address,
        nonce,
    );
    defer std.testing.allocator.free(expired_token);
    try expired_server.issueRetryToken(expired_token);

    try std.testing.expectError(
        error.InvalidPacket,
        expired_server.validateAddressValidationToken(secret, .retry, 21, peer_address, expired_token),
    );
    try std.testing.expect(!expired_server.peerAddressValidated());
    try std.testing.expectEqual(@as(usize, 1), expired_server.pendingRetryTokenCount());
}

test "address-bound NEW_TOKEN validates peer address without one-time Retry state" {
    const secret: address_validation_token.Secret = [_]u8{0xa5} ** address_validation_token.secret_len;
    const nonce: address_validation_token.Nonce = [_]u8{0x5a} ** address_validation_token.nonce_len;
    const peer_address = "192.0.2.9:4433";

    var issuer = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer issuer.deinit();
    const new_token = try issuer.issueAddressValidationToken(
        secret,
        .new_token,
        1_000,
        60_000,
        peer_address,
        nonce,
    );
    defer std.testing.allocator.free(new_token);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.sendPing();
    var out_buf: [16]u8 = undefined;
    try std.testing.expectEqual(@as(?[]u8, null), try server.pollTx(1_010, &out_buf));

    try server.validateAddressValidationToken(secret, .new_token, 1_020, peer_address, new_token);
    try std.testing.expect(server.peerAddressValidated());
    try std.testing.expectEqual(@as(?usize, null), server.antiAmplificationLimitRemaining());
    const payload = (try server.pollTx(1_021, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), payload.len);

    var other_server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer other_server.deinit();
    try std.testing.expectError(
        error.InvalidPacket,
        other_server.validateAddressValidationToken(secret, .new_token, 1_030, "192.0.2.10:4433", new_token),
    );
    try std.testing.expect(!other_server.peerAddressValidated());
}

test "address-bound NEW_TOKEN validates only for its originating QUIC version" {
    const secret: address_validation_token.Secret = [_]u8{0xb5} ** address_validation_token.secret_len;
    const nonce: address_validation_token.Nonce = [_]u8{0x7a} ** address_validation_token.nonce_len;
    const peer_address = "192.0.2.29:4433";

    var issuer = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer issuer.deinit();
    const new_token = try issuer.issueAddressValidationTokenForVersion(
        secret,
        .new_token,
        .v2,
        1_000,
        60_000,
        peer_address,
        nonce,
    );
    defer std.testing.allocator.free(new_token);

    var v1_server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer v1_server.deinit();
    try std.testing.expectError(
        error.InvalidPacket,
        v1_server.validateAddressValidationTokenForVersion(secret, .new_token, .v1, 1_020, peer_address, new_token),
    );
    try std.testing.expect(!v1_server.peerAddressValidated());

    var v2_server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer v2_server.deinit();
    try v2_server.validateAddressValidationTokenForVersion(secret, .new_token, .v2, 1_020, peer_address, new_token);
    try std.testing.expect(v2_server.peerAddressValidated());
}

test "address-bound NEW_TOKEN validates with rotated secrets" {
    const previous_secret: address_validation_token.Secret = [_]u8{0xa5} ** address_validation_token.secret_len;
    const current_secret: address_validation_token.Secret = [_]u8{0x5c} ** address_validation_token.secret_len;
    const secrets = [_]address_validation_token.Secret{ current_secret, previous_secret };
    const current_only = [_]address_validation_token.Secret{current_secret};
    const nonce: address_validation_token.Nonce = [_]u8{0x5a} ** address_validation_token.nonce_len;
    const peer_address = "192.0.2.19:4433";

    var issuer = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer issuer.deinit();
    const new_token = try issuer.issueAddressValidationToken(
        previous_secret,
        .new_token,
        1_000,
        60_000,
        peer_address,
        nonce,
    );
    defer std.testing.allocator.free(new_token);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validateAddressValidationTokenWithSecrets(&secrets, .new_token, 1_020, peer_address, new_token);
    try std.testing.expect(server.peerAddressValidated());

    var current_only_server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer current_only_server.deinit();
    try std.testing.expectError(
        error.InvalidPacket,
        current_only_server.validateAddressValidationTokenWithSecrets(&current_only, .new_token, 1_020, peer_address, new_token),
    );
    try std.testing.expect(!current_only_server.peerAddressValidated());
}

test "applyPeerTransportParameters validates original_destination_connection_id without Retry" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const other_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try client.sendCryptoInSpace(.initial, "client initial");
    const protected = (try client.pollInitialProtectedDatagram(
        0,
        &dcid,
        &client_scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);
    try std.testing.expectEqualStrings(&dcid, client.originalDestinationConnectionId().?);

    try server.processInitialProtectedDatagram(1, secrets.client, protected);
    const server_params = server.localTransportParameters();
    try std.testing.expectEqualStrings(&dcid, server.originalDestinationConnectionId().?);
    try std.testing.expectEqualStrings(&dcid, server_params.original_destination_connection_id.?);

    try std.testing.expectError(error.InvalidPacket, client.applyPeerTransportParameters(.{
        .initial_max_data = 7,
    }));
    try std.testing.expectError(error.InvalidPacket, client.applyPeerTransportParameters(.{
        .original_destination_connection_id = &other_dcid,
        .initial_max_data = 8,
    }));
    try std.testing.expectEqual(@as(u64, 65_536), client.peer_max_data);

    try client.applyPeerTransportParameters(.{
        .original_destination_connection_id = server_params.original_destination_connection_id,
        .initial_max_data = 9,
    });
    try std.testing.expectEqual(@as(u64, 9), client.peer_max_data);
}

test "applyPeerTransportParameters validates initial_source_connection_id" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const other_scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try client.sendCryptoInSpace(.initial, "client initial");
    const protected = (try client.pollInitialProtectedDatagram(
        0,
        &dcid,
        &client_scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);
    try std.testing.expect(protected.len >= min_initial_udp_datagram_len);

    try server.processInitialProtectedDatagram(1, secrets.client, protected);
    try std.testing.expectEqualStrings(&client_scid, server.peerInitialSourceConnectionId().?);

    try std.testing.expectError(error.InvalidPacket, server.applyPeerTransportParameters(.{
        .initial_max_data = 7,
    }));
    try std.testing.expectError(error.InvalidPacket, server.applyPeerTransportParameters(.{
        .initial_source_connection_id = &other_scid,
        .initial_max_data = 8,
    }));
    try std.testing.expectEqual(@as(u64, 65_536), server.peer_max_data);

    try server.applyPeerTransportParameters(.{
        .initial_source_connection_id = &client_scid,
        .initial_max_data = 9,
    });
    try std.testing.expectEqual(@as(u64, 9), server.peer_max_data);
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

test "processDatagram buffers out-of-order CRYPTO and ignores duplicate pending data" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .crypto = .{
        .offset = 6,
        .data = "world",
    } });
    const pending = try std.testing.allocator.dupe(u8, out.getWritten());
    defer std.testing.allocator.free(pending);
    try conn.processDatagram(0, pending);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_recv_buffer.items.len);
    try std.testing.expectEqual(@as(usize, 1), conn.crypto_recv_pending.items.len);

    try conn.processDatagram(1, pending);
    try std.testing.expectEqual(@as(usize, 1), conn.crypto_recv_pending.items.len);

    var read_buf: [16]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try conn.recvCrypto(&read_buf));

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .crypto = .{
        .offset = 0,
        .data = "hello ",
    } });
    try conn.processDatagram(2, out.getWritten());
    try std.testing.expectEqual(@as(usize, 1), conn.crypto_recv_pending.items.len);

    const n = (try conn.recvCrypto(&read_buf)).?;
    try std.testing.expectEqualStrings("hello world", read_buf[0..n]);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_recv_pending.items.len);
}

test "processDatagram discards duplicate CRYPTO data without appending bytes" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .crypto = .{
        .offset = 0,
        .data = "hello",
    } });
    const original = try std.testing.allocator.dupe(u8, out.getWritten());
    defer std.testing.allocator.free(original);
    try conn.processDatagram(0, original);
    try std.testing.expectEqualStrings("hello", conn.crypto_recv_buffer.items);

    try conn.processDatagram(1, original);
    try std.testing.expectEqualStrings("hello", conn.crypto_recv_buffer.items);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .crypto = .{
        .offset = 3,
        .data = "lo!",
    } });
    try conn.processDatagram(2, out.getWritten());
    try std.testing.expectEqualStrings("hello!", conn.crypto_recv_buffer.items);

    var read_buf: [8]u8 = undefined;
    const n = (try conn.recvCrypto(&read_buf)).?;
    try std.testing.expectEqualStrings("hello!", read_buf[0..n]);
}

test "processDatagram rejects conflicting CRYPTO overlap and rolls back pending data" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .crypto = .{
        .offset = 5,
        .data = "tail",
    } });
    try out.writeByte(0x02); // truncated ACK frame
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_recv_pending.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_recv_buffer.items.len);
    try std.testing.expectEqual(@as(u64, 0), conn.next_peer_packet_number);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .crypto = .{
        .offset = 0,
        .data = "hello",
    } });
    try conn.processDatagram(1, out.getWritten());

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .crypto = .{
        .offset = 3,
        .data = "xx",
    } });
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(2, out.getWritten()));
    try std.testing.expectEqualStrings("hello", conn.crypto_recv_buffer.items);
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
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.initial));

    var read_buf: [32]u8 = undefined;
    const initial_len = (try server.recvCryptoInSpace(.initial, &read_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("initial flight", read_buf[0..initial_len]);

    const initial_ack = (try server.pollTxInSpace(.initial, 25, &datagram)) orelse return error.TestUnexpectedResult;
    try client.processDatagramInSpace(.initial, 26, initial_ack);

    const handshake_payload = (try client.pollTxInSpace(.handshake, 30, &datagram)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(client.packetNumberSpaceDiscarded(.initial));
    try server.processDatagramInSpace(.handshake, 40, handshake_payload);
    try std.testing.expect(server.packetNumberSpaceDiscarded(.initial));

    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.initial));
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.handshake));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.initial));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.handshake));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));

    const handshake_len = (try server.recvCryptoInSpace(.handshake, &read_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("handshake flight", read_buf[0..handshake_len]);
    try std.testing.expectEqual(@as(?usize, null), try server.recvCryptoInSpace(.application, &read_buf));
}

test "driveCryptoBackendInSpace delivers reassembled CRYPTO and queues backend output" {
    const MockBackend = struct {
        inbound: std.ArrayList(u8) = .empty,
        outbound: []const u8,
        outbound_offset: usize = 0,
        last_space: ?PacketNumberSpace = null,
        receive_count: usize = 0,
        confirmed: bool = false,

        fn deinit(self: *@This()) void {
            self.inbound.deinit(std.testing.allocator);
        }

        fn backend(self: *@This()) CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
                .handshake_confirmed = handshakeConfirmed,
            };
        }

        fn receive(context: *anyopaque, space: PacketNumberSpace, data: []const u8) Error!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.last_space = space;
            self.receive_count += 1;
            self.inbound.appendSlice(std.testing.allocator, data) catch return error.OutOfMemory;
            if (space == .handshake and std.mem.eql(u8, self.inbound.items, "client hello")) {
                self.confirmed = true;
            }
        }

        fn pull(context: *anyopaque, space: PacketNumberSpace, out_buf: []u8) Error!?[]const u8 {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (space != .handshake or self.outbound_offset >= self.outbound.len) return null;
            const n = @min(out_buf.len, self.outbound.len - self.outbound_offset);
            @memcpy(out_buf[0..n], self.outbound[self.outbound_offset..][0..n]);
            self.outbound_offset += n;
            return out_buf[0..n];
        }

        fn handshakeConfirmed(context: *anyopaque) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            return self.confirmed;
        }
    };

    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .crypto = .{
        .offset = 6,
        .data = " hello",
    } });
    try conn.processDatagramInSpace(.handshake, 0, out.getWritten());

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .crypto = .{
        .offset = 0,
        .data = "client",
    } });
    try conn.processDatagramInSpace(.handshake, 1, out.getWritten());

    var backend = MockBackend{ .outbound = "server flight" };
    defer backend.deinit();
    var scratch: [5]u8 = undefined;
    const progress = try conn.driveCryptoBackendInSpace(.handshake, backend.backend(), &scratch);

    try std.testing.expectEqual(@as(usize, 3), progress.inbound_chunks);
    try std.testing.expectEqual(@as(usize, 12), progress.inbound_bytes);
    try std.testing.expectEqual(@as(usize, 3), progress.outbound_chunks);
    try std.testing.expectEqual(@as(usize, 13), progress.outbound_bytes);
    try std.testing.expect(progress.handshake_confirmed);
    try std.testing.expectEqual(HandshakeState.confirmed, conn.handshakeState());
    try std.testing.expect(!conn.packetNumberSpaceDiscarded(.handshake));
    try std.testing.expectEqual(PacketNumberSpace.handshake, backend.last_space.?);
    try std.testing.expectEqualStrings("client hello", backend.inbound.items);

    try conn.validatePeerAddress();
    var payload_buf: [64]u8 = undefined;
    var collected: [32]u8 = undefined;
    var collected_len: usize = 0;
    while (try conn.pollTxInSpace(.handshake, 2, &payload_buf)) |payload| {
        var payload_offset: usize = 0;
        while (payload_offset < payload.len) {
            var decoded = try frame.decodeFrameSlice(payload[payload_offset..], std.testing.allocator);
            defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
            switch (decoded.frame) {
                .crypto => |crypto| {
                    @memcpy(collected[collected_len..][0..crypto.data.len], crypto.data);
                    collected_len += crypto.data.len;
                },
                .ack => {},
                else => return error.TestUnexpectedResult,
            }
            payload_offset += decoded.len;
        }
    }
    try std.testing.expectEqualStrings("server flight", collected[0..collected_len]);
}

test "driveCryptoBackendInSpace discards Handshake space when backend confirms without outbound crypto" {
    const ConfirmingBackend = struct {
        inbound: std.ArrayList(u8) = .empty,
        secrets: HandshakeTrafficSecrets,
        secrets_sent: bool = false,
        confirmed: bool = false,

        fn deinit(self: *@This()) void {
            self.inbound.deinit(std.testing.allocator);
        }

        fn backend(self: *@This()) CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
                .pull_handshake_traffic_secrets = pullHandshakeTrafficSecrets,
                .handshake_confirmed = handshakeConfirmed,
            };
        }

        fn receive(context: *anyopaque, space: PacketNumberSpace, data: []const u8) Error!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (space != .handshake) return error.CryptoError;
            self.inbound.appendSlice(std.testing.allocator, data) catch return error.OutOfMemory;
            self.confirmed = std.mem.eql(u8, self.inbound.items, "client finished");
        }

        fn pull(_: *anyopaque, _: PacketNumberSpace, _: []u8) Error!?[]const u8 {
            return null;
        }

        fn pullHandshakeTrafficSecrets(context: *anyopaque) Error!?HandshakeTrafficSecrets {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.secrets_sent) return null;
            self.secrets_sent = true;
            return self.secrets;
        }

        fn handshakeConfirmed(context: *anyopaque) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            return self.confirmed;
        }
    };

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .crypto = .{
        .offset = 0,
        .data = "client finished",
    } });
    try conn.processDatagramInSpace(.handshake, 0, out.getWritten());
    try std.testing.expectEqual(@as(?u64, 0), conn.pendingAckLargest(.handshake));

    var backend = ConfirmingBackend{ .secrets = .{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    } };
    defer backend.deinit();
    var scratch: [32]u8 = undefined;
    const progress = try conn.driveCryptoBackendInSpace(.handshake, backend.backend(), &scratch);

    try std.testing.expect(progress.handshake_confirmed);
    try std.testing.expect(progress.handshake_keys_installed);
    try std.testing.expectEqual(@as(usize, 1), progress.inbound_chunks);
    try std.testing.expectEqual(@as(usize, 0), progress.outbound_chunks);
    try std.testing.expectEqual(HandshakeState.confirmed, conn.handshakeState());
    try std.testing.expect(conn.handshakeConfirmed());
    try std.testing.expect(conn.packetNumberSpaceDiscarded(.handshake));
    try std.testing.expect(!conn.hasHandshakeProtectionKeys());
    try std.testing.expectEqual(@as(?u64, null), conn.pendingAckLargest(.handshake));
    try std.testing.expectError(error.InvalidPacket, conn.sendCryptoInSpace(.handshake, "late"));
    try std.testing.expectError(error.InvalidPacket, conn.installHandshakeTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    }));
}

test "driveCryptoBackendInSpace requires scratch buffer before consuming crypto" {
    const NoopBackend = struct {
        fn receive(_: *anyopaque, _: PacketNumberSpace, _: []const u8) Error!void {}

        fn pull(_: *anyopaque, _: PacketNumberSpace, _: []u8) Error!?[]const u8 {
            return null;
        }
    };

    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .crypto = .{
        .offset = 0,
        .data = "client",
    } });
    try conn.processDatagramInSpace(.handshake, 0, out.getWritten());

    var context: u8 = 0;
    const backend = CryptoBackend{
        .context = &context,
        .receive = NoopBackend.receive,
        .pull = NoopBackend.pull,
    };
    var empty: [0]u8 = .{};
    try std.testing.expectError(error.BufferTooSmall, conn.driveCryptoBackendInSpace(.handshake, backend, &empty));

    var read_buf: [8]u8 = undefined;
    const n = (try conn.recvCryptoInSpace(.handshake, &read_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("client", read_buf[0..n]);
}

test "driveCryptoBackendInSpace exchanges transport parameter bytes with backend" {
    const MockBackend = struct {
        local_transport_parameters: std.ArrayList(u8) = .empty,
        peer_transport_parameters: []const u8,
        peer_sent: bool = false,

        fn deinit(self: *@This()) void {
            self.local_transport_parameters.deinit(std.testing.allocator);
        }

        fn backend(self: *@This()) CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
                .set_local_transport_parameters = setLocalTransportParameters,
                .pull_peer_transport_parameters = pullPeerTransportParameters,
            };
        }

        fn receive(_: *anyopaque, _: PacketNumberSpace, _: []const u8) Error!void {}

        fn pull(_: *anyopaque, _: PacketNumberSpace, _: []u8) Error!?[]const u8 {
            return null;
        }

        fn setLocalTransportParameters(context: *anyopaque, data: []const u8) Error!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.local_transport_parameters.appendSlice(std.testing.allocator, data) catch return error.OutOfMemory;
        }

        fn pullPeerTransportParameters(context: *anyopaque, out_buf: []u8) Error!?[]const u8 {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.peer_sent) return null;
            if (out_buf.len < self.peer_transport_parameters.len) return error.BufferTooSmall;
            @memcpy(out_buf[0..self.peer_transport_parameters.len], self.peer_transport_parameters);
            self.peer_sent = true;
            return out_buf[0..self.peer_transport_parameters.len];
        }
    };

    var peer_params_buf: [160]u8 = undefined;
    var peer_params_out = buffer.fixedWriter(&peer_params_buf);
    try transport_parameters.encode(peer_params_out.writer(), .{
        .max_idle_timeout = 88,
        .max_udp_payload_size = 1400,
        .initial_max_data = 1234,
        .initial_max_stream_data_bidi_local = 55,
        .initial_max_stream_data_bidi_remote = 66,
        .initial_max_stream_data_uni = 77,
        .initial_max_streams_bidi = 4,
        .initial_max_streams_uni = 5,
        .ack_delay_exponent = 5,
        .max_ack_delay = 33,
    });

    var conn = try QuicConnection.init(std.testing.allocator, .server, .{
        .max_datagram_size = 1300,
        .ack_delay_exponent = 4,
        .max_ack_delay_ms = 44,
        .initial_max_data = 999,
    });
    defer conn.deinit();

    var backend = MockBackend{ .peer_transport_parameters = peer_params_out.getWritten() };
    defer backend.deinit();
    var scratch: [256]u8 = undefined;
    const progress = try conn.driveCryptoBackendInSpace(.initial, backend.backend(), &scratch);

    try std.testing.expect(progress.local_transport_parameters_bytes > 0);
    try std.testing.expectEqual(progress.local_transport_parameters_bytes, backend.local_transport_parameters.items.len);
    try std.testing.expectEqual(peer_params_out.getWritten().len, progress.peer_transport_parameters_bytes);
    try std.testing.expect(progress.peer_transport_parameters_applied);

    var parsed_local = try transport_parameters.parse(backend.local_transport_parameters.items, std.testing.allocator);
    defer parsed_local.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 999), parsed_local.initial_max_data);
    try std.testing.expectEqual(@as(u64, 4), parsed_local.ack_delay_exponent);
    try std.testing.expectEqual(@as(u64, 44), parsed_local.max_ack_delay);
    try std.testing.expectEqual(@as(u64, 1300), parsed_local.max_udp_payload_size);

    try std.testing.expectEqual(@as(u64, 1234), conn.peer_max_data);
    try std.testing.expectEqual(@as(u64, 55), conn.peer_initial_max_stream_data_bidi_local);
    try std.testing.expectEqual(@as(u64, 66), conn.peer_initial_max_stream_data_bidi_remote);
    try std.testing.expectEqual(@as(u64, 77), conn.peer_initial_max_stream_data_uni);
    try std.testing.expectEqual(@as(u64, 4), conn.peer_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 5), conn.peer_max_streams_uni);
    try std.testing.expectEqual(@as(u64, 5), conn.peer_ack_delay_exponent);
    try std.testing.expectEqual(@as(u64, 88), conn.peer_max_idle_timeout_ms);
    try std.testing.expectEqual(@as(usize, 1400), conn.peer_max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, 33), conn.recovery_state.max_ack_delay_ms);
}

test "driveCryptoBackendInSpace rejects invalid peer transport parameters before output" {
    const BadBackend = struct {
        output_pulled: bool = false,
        peer_sent: bool = false,

        fn backend(self: *@This()) CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
                .pull_peer_transport_parameters = pullPeerTransportParameters,
            };
        }

        fn receive(_: *anyopaque, _: PacketNumberSpace, _: []const u8) Error!void {}

        fn pull(context: *anyopaque, _: PacketNumberSpace, out_buf: []u8) Error!?[]const u8 {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.output_pulled = true;
            if (out_buf.len == 0) return error.BufferTooSmall;
            out_buf[0] = 0;
            return out_buf[0..1];
        }

        fn pullPeerTransportParameters(context: *anyopaque, out_buf: []u8) Error!?[]const u8 {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.peer_sent) return null;
            if (out_buf.len == 0) return error.BufferTooSmall;
            out_buf[0] = 0x04;
            self.peer_sent = true;
            return out_buf[0..1];
        }
    };

    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    var backend = BadBackend{};
    var scratch: [64]u8 = undefined;
    try std.testing.expectError(error.InvalidPacket, conn.driveCryptoBackendInSpace(.handshake, backend.backend(), &scratch));
    try std.testing.expect(!backend.output_pulled);
    try std.testing.expectEqual(@as(u64, 65_536), conn.peer_max_data);

    try conn.validatePeerAddress();
    var payload_buf: [16]u8 = undefined;
    try std.testing.expectEqual(@as(?[]u8, null), try conn.pollTxInSpace(.handshake, 1, &payload_buf));
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

test "processDatagram buffers out-of-order crypto data" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .crypto = .{
        .offset = 6,
        .data = "world",
    } });

    try conn.processDatagram(0, out.getWritten());
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_recv_buffer.items.len);
    try std.testing.expectEqual(@as(usize, 1), conn.crypto_recv_pending.items.len);
    try std.testing.expectEqual(@as(?u64, 0), conn.pending_ack_largest);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .crypto = .{
        .offset = 0,
        .data = "hello ",
    } });
    try conn.processDatagram(1, out.getWritten());

    var read_buf: [16]u8 = undefined;
    const n = (try conn.recvCrypto(&read_buf)).?;
    try std.testing.expectEqualStrings("hello world", read_buf[0..n]);
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_recv_pending.items.len);
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
    try std.testing.expectEqual(@as(usize, 0), conn.crypto_recv_pending.items.len);
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

test "loss detection timer reports loss-time before PTO across packet spaces" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    _ = try conn.recordPacketSentInSpace(.application, 300, 100);
    _ = try conn.recordPacketSentInSpace(.application, 500, 100);
    _ = try conn.recordPacketSentInSpace(.initial, 10, 100);

    try conn.receiveAckInSpace(.application, 600, .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    const deadline = conn.lossDetectionTimerDeadlineMillis() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(PacketNumberSpace.application, deadline.space);
    try std.testing.expectEqual(LossDetectionTimerKind.loss_time, deadline.kind);
    try std.testing.expectEqual(@as(i64, 675), deadline.deadline_millis);
}

test "loss detection timer reports earliest PTO when no loss time is armed" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();
    try conn.validatePeerAddress();

    _ = try conn.recordPacketSentInSpace(.initial, 10, 100);
    _ = try conn.recordPacketSentInSpace(.handshake, 20, 100);
    _ = try conn.recordPacketSentInSpace(.application, 0, 100);

    const deadline = conn.lossDetectionTimerDeadlineMillis() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(PacketNumberSpace.initial, deadline.space);
    try std.testing.expectEqual(LossDetectionTimerKind.pto, deadline.kind);
    try std.testing.expectEqual(@as(i64, 310), deadline.deadline_millis);
}

test "serviceLossDetectionTimer is no-op before aggregate deadline" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();

    _ = try conn.recordPacketSentInSpace(.application, 10, 100);
    const deadline = conn.lossDetectionTimerDeadlineMillis() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(PacketNumberSpace.application, deadline.space);
    try std.testing.expectEqual(LossDetectionTimerKind.pto, deadline.kind);
    try std.testing.expectEqual(@as(i64, 335), deadline.deadline_millis);

    try std.testing.expectEqual(@as(?LossDetectionTimerDeadline, null), try conn.serviceLossDetectionTimer(334));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 0), conn.recovery_state.pto_count);
}

test "serviceLossDetectionTimer handles loss-time before due PTO probes" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    _ = try conn.recordPacketSentInSpace(.application, 1000, 100);
    _ = try conn.recordPacketSentInSpace(.application, 1200, 100);
    _ = try conn.recordPacketSentInSpace(.initial, 0, 100);

    try conn.receiveAckInSpace(.application, 1300, .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    const serviced = (try conn.serviceLossDetectionTimer(1375)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(PacketNumberSpace.application, serviced.space);
    try std.testing.expectEqual(LossDetectionTimerKind.loss_time, serviced.kind);
    try std.testing.expectEqual(@as(i64, 1375), serviced.deadline_millis);
    try std.testing.expectEqual(@as(usize, 0), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), conn.bytesInFlight(.application));
    try std.testing.expectEqual(@as(usize, 1), conn.sentPacketCount(.initial));
    try std.testing.expectEqual(@as(usize, 0), conn.initial_packet_space.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 0), conn.initial_packet_space.recovery_state.pto_count);
}

test "serviceLossDetectionTimer handles PTO deadline through aggregate timer" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();

    _ = try conn.recordPacketSentInSpace(.application, 10, 100);

    const serviced = (try conn.serviceLossDetectionTimer(335)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(PacketNumberSpace.application, serviced.space);
    try std.testing.expectEqual(LossDetectionTimerKind.pto, serviced.kind);
    try std.testing.expectEqual(@as(i64, 335), serviced.deadline_millis);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 1), conn.recovery_state.pto_count);
}

test "PTO frame-payload probe bypasses congestion window once" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();

    _ = try conn.recordPacketSentInSpace(.application, 10, 100);
    const deadline = conn.lossDetectionTimerDeadlineMillis() orelse return error.TestUnexpectedResult;
    conn.recovery_state.congestion_window = conn.bytesInFlight(.application);

    const serviced = (try conn.serviceLossDetectionTimer(deadline.deadline_millis)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(PacketNumberSpace.application, serviced.space);
    try std.testing.expectEqual(LossDetectionTimerKind.pto, serviced.kind);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_ping_count);
    try std.testing.expectEqual(@as(usize, 1), conn.pto_probe_count);
    try std.testing.expect(!conn.recovery_state.canSend(1));

    var out_buf: [32]u8 = undefined;
    const payload = (try conn.pollTx(deadline.deadline_millis + 1, &out_buf)) orelse return error.TestUnexpectedResult;
    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .ping => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 0), conn.pending_ping_count);
    try std.testing.expectEqual(@as(usize, 0), conn.pto_probe_count);
    try std.testing.expect(conn.bytesInFlight(.application) > conn.congestionWindow(.application));
}

test "EndpointLossDetectionTimers selects and services earliest connection timer" {
    var timers = EndpointLossDetectionTimers.init(std.testing.allocator);
    defer timers.deinit();

    var fast = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer fast.deinit();
    var slow = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 200,
    });
    defer slow.deinit();

    _ = try fast.recordPacketSentInSpace(.application, 10, 100);
    _ = try slow.recordPacketSentInSpace(.application, 20, 100);

    const fast_timer = fast.lossDetectionTimerDeadlineMillis() orelse return error.TestUnexpectedResult;
    const slow_timer = slow.lossDetectionTimerDeadlineMillis() orelse return error.TestUnexpectedResult;
    try std.testing.expect(fast_timer.deadline_millis < slow_timer.deadline_millis);

    try timers.armFromConnection(20, &slow);
    try timers.armFromConnection(10, &fast);
    try std.testing.expectEqual(@as(usize, 2), timers.count());

    const earliest = timers.earliestDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 10), earliest.connection_id);
    try std.testing.expectEqual(PacketNumberSpace.application, earliest.timer.space);
    try std.testing.expectEqual(LossDetectionTimerKind.pto, earliest.timer.kind);
    try std.testing.expectEqual(fast_timer.deadline_millis, earliest.timer.deadline_millis);

    try std.testing.expectEqual(
        @as(?EndpointLossDetectionTimerDeadline, null),
        try timers.serviceConnection(10, &fast, fast_timer.deadline_millis - 1),
    );
    try std.testing.expectEqual(@as(usize, 0), fast.pending_ping_count);
    try std.testing.expectEqual(@as(usize, 2), timers.count());

    const serviced = (try timers.serviceConnection(10, &fast, fast_timer.deadline_millis)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 10), serviced.connection_id);
    try std.testing.expectEqual(PacketNumberSpace.application, serviced.timer.space);
    try std.testing.expectEqual(LossDetectionTimerKind.pto, serviced.timer.kind);
    try std.testing.expectEqual(fast_timer.deadline_millis, serviced.timer.deadline_millis);
    try std.testing.expectEqual(@as(usize, 1), fast.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 1), fast.recovery_state.pto_count);

    try fast.receiveAckInSpace(.application, fast_timer.deadline_millis + 1, .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    });
    try timers.armFromConnection(10, &fast);
    try std.testing.expectEqual(@as(usize, 1), timers.count());

    const remaining = timers.earliestDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 20), remaining.connection_id);
    try std.testing.expectEqual(slow_timer.deadline_millis, remaining.timer.deadline_millis);
}

test "EndpointLossDetectionTimers disarms connection after loss-time service" {
    var timers = EndpointLossDetectionTimers.init(std.testing.allocator);
    defer timers.deinit();

    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    _ = try conn.recordPacketSentInSpace(.application, 300, 100);
    _ = try conn.recordPacketSentInSpace(.application, 500, 100);
    try conn.receiveAckInSpace(.application, 600, .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    const timer = conn.lossDetectionTimerDeadlineMillis() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(PacketNumberSpace.application, timer.space);
    try std.testing.expectEqual(LossDetectionTimerKind.loss_time, timer.kind);
    try timers.armFromConnection(99, &conn);
    try std.testing.expectEqual(@as(usize, 1), timers.count());

    try std.testing.expectEqual(
        @as(?EndpointLossDetectionTimerDeadline, null),
        try timers.serviceConnection(99, &conn, timer.deadline_millis - 1),
    );
    try std.testing.expectEqual(@as(usize, 1), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 1), timers.count());

    const serviced = (try timers.serviceConnection(99, &conn, timer.deadline_millis)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 99), serviced.connection_id);
    try std.testing.expectEqual(PacketNumberSpace.application, serviced.timer.space);
    try std.testing.expectEqual(LossDetectionTimerKind.loss_time, serviced.timer.kind);
    try std.testing.expectEqual(@as(usize, 0), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), conn.bytesInFlight(.application));
    try std.testing.expectEqual(@as(usize, 0), timers.count());
    try std.testing.expectEqual(@as(?EndpointLossDetectionTimerDeadline, null), timers.earliestDeadline());
}

test "EndpointConnectionLifecycle retires routes with recovery timer" {
    var lifecycle = EndpointConnectionLifecycle.init(std.testing.allocator);
    defer lifecycle.deinit();

    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();

    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 50_000),
    };
    const cid0 = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const cid1 = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const short_datagram = [_]u8{ 0x40, 0x10, 0x20, 0x30, 0x40, 0x00 };

    try lifecycle.registerConnectionId(41, &cid0, path, .{ .sequence_number = 0 });
    try lifecycle.registerConnectionId(41, &cid1, path, .{ .sequence_number = 1 });

    const routed = try lifecycle.routeDatagram(path, &short_datagram);
    try std.testing.expectEqual(@as(u64, 41), routed.connection_id);
    try std.testing.expectEqualSlices(u8, &cid0, routed.destination_connection_id.asSlice());
    try std.testing.expectEqual(@as(usize, 2), lifecycle.routeCount());

    _ = try conn.recordPacketSentInSpace(.application, 10, 100);
    try lifecycle.armRecoveryTimerFromConnection(41, &conn);
    const armed = lifecycle.earliestRecoveryDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 41), armed.connection_id);
    try std.testing.expectEqual(LossDetectionTimerKind.pto, armed.timer.kind);
    try std.testing.expectEqual(@as(usize, 1), lifecycle.recoveryTimerCount());

    const retired = lifecycle.retireConnection(41);
    try std.testing.expectEqual(@as(usize, 2), retired.routes_retired);
    try std.testing.expect(retired.recovery_timer_disarmed);
    try std.testing.expectEqual(@as(usize, 0), lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), lifecycle.recoveryTimerCount());
    try std.testing.expectEqual(@as(?EndpointLossDetectionTimerDeadline, null), lifecycle.earliestRecoveryDeadline());
    try std.testing.expectError(error.UnknownConnectionId, lifecycle.routeDatagram(path, &short_datagram));

    const retired_again = lifecycle.retireConnection(41);
    try std.testing.expectEqual(@as(usize, 0), retired_again.routes_retired);
    try std.testing.expect(!retired_again.recovery_timer_disarmed);
}

test "EndpointConnectionLifecycle refreshes installed-key protected short timer lifecycle" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client_lifecycle = EndpointConnectionLifecycle.init(std.testing.allocator);
    defer client_lifecycle.deinit();
    var server_lifecycle = EndpointConnectionLifecycle.init(std.testing.allocator);
    defer server_lifecycle.deinit();

    var client = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{
        .initial_rtt_ms = 100,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    try client.installOneRttTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });
    try server.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });

    const client_addr = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 50_000);
    const server_addr = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433);
    const server_receive_path = endpoint.Udp4Tuple{
        .local = server_addr,
        .remote = client_addr,
    };
    const client_receive_path = endpoint.Udp4Tuple{
        .local = client_addr,
        .remote = server_addr,
    };
    const client_connection_id: u64 = 10;
    const server_connection_id: u64 = 20;

    try client_lifecycle.registerConnectionId(client_connection_id, &client_dcid, client_receive_path, .{
        .sequence_number = 0,
    });
    try server_lifecycle.registerConnectionId(server_connection_id, &server_dcid, server_receive_path, .{
        .sequence_number = 0,
    });

    try client.sendPing();
    const ping = (try client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        client_connection_id,
        &client,
        10,
        &server_dcid,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(ping);
    try std.testing.expectEqual(@as(usize, 1), client_lifecycle.recoveryTimerCount());
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.application));

    const server_route = try server_lifecycle.routeDatagram(server_receive_path, ping);
    try std.testing.expectEqual(server_connection_id, server_route.connection_id);
    try server_lifecycle.processProtectedShortDatagramWithInstalledKeys(
        server_route.connection_id,
        &server,
        11,
        server_dcid.len,
        ping,
    );
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.application));
    try std.testing.expectEqual(@as(usize, 0), server_lifecycle.recoveryTimerCount());

    const ack = (try server_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        server_connection_id,
        &server,
        12,
        &client_dcid,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(ack);
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));
    try std.testing.expectEqual(@as(usize, 0), server_lifecycle.recoveryTimerCount());

    const client_route = try client_lifecycle.routeDatagram(client_receive_path, ack);
    try std.testing.expectEqual(client_connection_id, client_route.connection_id);
    try client_lifecycle.processProtectedShortDatagramWithInstalledKeys(
        client_route.connection_id,
        &client,
        13,
        client_dcid.len,
        ack,
    );
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight(.application));
    try std.testing.expectEqual(@as(usize, 0), client_lifecycle.recoveryTimerCount());
    try std.testing.expectEqual(@as(?EndpointLossDetectionTimerDeadline, null), client_lifecycle.earliestRecoveryDeadline());
}

test "EndpointLossDetectionTimers drives protected short PTO and ACK disarm" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var timers = EndpointLossDetectionTimers.init(std.testing.allocator);
    defer timers.deinit();

    var client = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer client.deinit();

    try client.sendPing();
    const first = (try client.pollProtectedShortDatagram(10, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(first);
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.application));

    try timers.armFromConnection(41, &client);
    const deadline = timers.earliestDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 41), deadline.connection_id);
    try std.testing.expectEqual(PacketNumberSpace.application, deadline.timer.space);
    try std.testing.expectEqual(LossDetectionTimerKind.pto, deadline.timer.kind);
    try std.testing.expectEqual(@as(i64, 335), deadline.timer.deadline_millis);

    try std.testing.expectEqual(
        @as(?EndpointLossDetectionTimerDeadline, null),
        try timers.serviceConnection(41, &client, deadline.timer.deadline_millis - 1),
    );
    try std.testing.expectEqual(@as(usize, 0), client.pending_ping_count);
    try std.testing.expectEqual(@as(usize, 1), timers.count());

    const serviced = (try timers.serviceConnection(41, &client, deadline.timer.deadline_millis)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 41), serviced.connection_id);
    try std.testing.expectEqual(LossDetectionTimerKind.pto, serviced.timer.kind);
    try std.testing.expectEqual(@as(usize, 1), client.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 1), client.recovery_state.pto_count);

    const probe = (try client.pollProtectedShortDatagram(deadline.timer.deadline_millis + 1, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(probe);
    try std.testing.expectEqual(@as(usize, 2), client.sentPacketCount(.application));
    try timers.armFromConnection(41, &client);
    try std.testing.expectEqual(@as(usize, 1), timers.count());

    var ack_payload_buf: [64]u8 = undefined;
    var ack_payload = buffer.fixedWriter(&ack_payload_buf);
    try frame.encodeFrame(ack_payload.writer(), .{ .ack = .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 1,
    } });
    const ack_packet_number_encoding = try packet.encodePacketNumberForHeader(0, null);
    const ack_packet = try protection.protectShortPacketAes128(
        std.testing.allocator,
        .{
            .dcid = &client_dcid,
            .spin_bit = false,
            .key_phase = false,
            .packet_number = 0,
        },
        ack_packet_number_encoding,
        secrets.server,
        ack_payload.getWritten(),
    );
    defer std.testing.allocator.free(ack_packet);

    try client.processProtectedShortDatagram(deadline.timer.deadline_millis + 2, secrets.server, client_dcid.len, ack_packet);
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight(.application));
    try timers.armFromConnection(41, &client);
    try std.testing.expectEqual(@as(usize, 0), timers.count());
    try std.testing.expectEqual(@as(?EndpointLossDetectionTimerDeadline, null), timers.earliestDeadline());
}

test "protected short PTO probe bypasses congestion window once" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer client.deinit();

    try client.sendPing();
    const first = (try client.pollProtectedShortDatagram(10, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(first);
    const deadline = client.lossDetectionTimerDeadlineMillis() orelse return error.TestUnexpectedResult;
    client.recovery_state.congestion_window = client.bytesInFlight(.application);

    const serviced = (try client.serviceLossDetectionTimer(deadline.deadline_millis)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(PacketNumberSpace.application, serviced.space);
    try std.testing.expectEqual(LossDetectionTimerKind.pto, serviced.kind);
    try std.testing.expectEqual(@as(usize, 1), client.pending_ping_count);
    try std.testing.expectEqual(@as(usize, 1), client.pto_probe_count);
    try std.testing.expect(!client.recovery_state.canSend(first.len));

    const probe = (try client.pollProtectedShortDatagram(deadline.deadline_millis + 1, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(probe);
    try std.testing.expectEqual(@as(usize, 2), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.pending_ping_count);
    try std.testing.expectEqual(@as(usize, 0), client.pto_probe_count);
    try std.testing.expect(client.bytesInFlight(.application) > client.congestionWindow(.application));
}

test "EndpointLossDetectionTimers services protected short loss-time retransmission" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var timers = EndpointLossDetectionTimers.init(std.testing.allocator);
    defer timers.deinit();

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    try client.sendCrypto("endpoint timer protected crypto");
    const first = (try client.pollProtectedShortDatagram(300, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(first);

    try client.sendPing();
    const second = (try client.pollProtectedShortDatagram(500, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(second);
    try std.testing.expectEqual(@as(usize, 2), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.crypto_send_queue.items.len);

    try client.receiveAckInSpace(.application, 600, .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    try timers.armFromConnection(42, &client);
    const deadline = timers.earliestDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 42), deadline.connection_id);
    try std.testing.expectEqual(PacketNumberSpace.application, deadline.timer.space);
    try std.testing.expectEqual(LossDetectionTimerKind.loss_time, deadline.timer.kind);
    try std.testing.expectEqual(@as(i64, 675), deadline.timer.deadline_millis);

    const serviced = (try timers.serviceConnection(42, &client, deadline.timer.deadline_millis)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 42), serviced.connection_id);
    try std.testing.expectEqual(LossDetectionTimerKind.loss_time, serviced.timer.kind);
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 1), client.crypto_send_queue.items.len);
    try std.testing.expectEqualStrings("endpoint timer protected crypto", client.crypto_send_queue.items[0].data);
    try std.testing.expectEqual(@as(usize, 0), timers.count());
}

test "loss detection timer expires protected short CRYPTO retransmission" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    try client.sendCrypto("loss-timer protected crypto");
    const first = (try client.pollProtectedShortDatagram(
        300,
        &server_dcid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(first);

    try client.sendPing();
    const second = (try client.pollProtectedShortDatagram(
        500,
        &server_dcid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(second);
    try std.testing.expectEqual(@as(usize, 2), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.crypto_send_queue.items.len);

    try client.receiveAckInSpace(.application, 600, .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    const timer = client.lossDetectionTimerDeadlineMillis() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(PacketNumberSpace.application, timer.space);
    try std.testing.expectEqual(LossDetectionTimerKind.loss_time, timer.kind);
    try std.testing.expectEqual(@as(i64, 675), timer.deadline_millis);
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.crypto_send_queue.items.len);

    try client.checkLossDetectionTimeouts(timer.deadline_millis - 1);
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.crypto_send_queue.items.len);

    try client.checkLossDetectionTimeouts(timer.deadline_millis);
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 1), client.crypto_send_queue.items.len);
    try std.testing.expectEqual(@as(u64, 0), client.crypto_send_queue.items[0].offset);
    try std.testing.expectEqualStrings("loss-timer protected crypto", client.crypto_send_queue.items[0].data);
    try std.testing.expectEqual(@as(?LossDetectionTimerDeadline, null), client.lossDetectionTimerDeadlineMillis());

    const retransmit = (try client.pollProtectedShortDatagram(
        timer.deadline_millis + 1,
        &server_dcid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(retransmit);
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.application));

    var opened = try protection.unprotectShortPacketAes128(
        std.testing.allocator,
        secrets.client,
        retransmit,
        server_dcid.len,
        2,
    );
    defer protection.deinitProtectedShortPacket(&opened, std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 2), opened.packet.header.packet_number);

    var decoded = try frame.decodeFrameSlice(opened.packet.plaintext, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .crypto => |crypto| {
            try std.testing.expectEqual(@as(u64, 0), crypto.offset);
            try std.testing.expectEqualStrings("loss-timer protected crypto", crypto.data);
        },
        else => return error.TestUnexpectedResult,
    }
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

test "ACK-driven persistent congestion duration ignores PTO backoff" {
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
    conn.recovery_state.onPtoExpired();
    conn.recovery_state.onPtoExpired();
    try std.testing.expectEqual(@as(u8, 2), conn.recovery_state.pto_count);
    try std.testing.expectEqual(@as(u64, 975), conn.recovery_state.persistentCongestionDurationMs());

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

test "ACK-driven NewReno loss keeps ssthresh below minimum cwnd clamp" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();

    conn.recovery_state.congestion_window = 3_000;
    var packet_number: u64 = 0;
    while (packet_number < 4) : (packet_number += 1) {
        _ = try conn.recordPacketSentInSpace(.application, @as(i64, @intCast(packet_number + 1)) * 10, 100);
    }

    try conn.receiveAckInSpace(.application, 100, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    try std.testing.expectEqual(recovery.minimumCongestionWindow(1200), conn.congestionWindow(.application));
    try std.testing.expectEqual(@as(usize, 1_500), conn.recovery_state.ssthresh);
}

test "ACK growth follows NewReno slow start then congestion avoidance" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();

    const initial_window = conn.congestionWindow(.application);
    try std.testing.expectEqual(recovery.initialCongestionWindow(1200), initial_window);

    _ = try conn.recordPacketSentInSpace(.application, 0, 1200);
    try conn.receiveAckInSpace(.application, 100, .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    const slow_start_window = conn.congestionWindow(.application);
    try std.testing.expectEqual(initial_window + 1200, slow_start_window);
    try std.testing.expectEqual(@as(usize, 0), conn.bytesInFlight(.application));

    conn.recovery_state.ssthresh = slow_start_window;
    _ = try conn.recordPacketSentInSpace(.application, 120, 1200);
    const avoidance_before = conn.congestionWindow(.application);
    const expected_increase = @max(@as(usize, 1), (1200 * 1200) / avoidance_before);
    try conn.receiveAckInSpace(.application, 220, .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    try std.testing.expectEqual(avoidance_before + expected_increase, conn.congestionWindow(.application));
    try std.testing.expectEqual(@as(usize, 0), conn.bytesInFlight(.application));
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

test "checkPtoTimeouts uses queued STREAM data as application probe before PING" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "old", false);

    var out_buf: [64]u8 = undefined;
    _ = (try conn.pollTx(10, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), conn.sentPacketCount(.application));

    try conn.sendOnStream(stream_id, "new", false);
    const deadline = conn.ptoDeadlineMillis(.application) orelse return error.TestUnexpectedResult;
    try conn.checkPtoTimeouts(deadline);

    try std.testing.expectEqual(@as(usize, 0), conn.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 1), conn.recovery_state.pto_count);
    try std.testing.expectEqual(@as(usize, 1), conn.send_queue.items.len);

    const payload = (try conn.pollTx(deadline + 1, &out_buf)) orelse return error.TestUnexpectedResult;
    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .stream => |stream_frame| {
            try std.testing.expectEqual(stream_id, stream_frame.stream_id);
            try std.testing.expectEqual(@as(u64, 3), stream_frame.offset);
            try std.testing.expectEqualStrings("new", stream_frame.data);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 2), conn.sentPacketCount(.application));
}

test "checkPtoTimeouts retransmits in-flight STREAM data before PING" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "old", false);

    var out_buf: [64]u8 = undefined;
    _ = (try conn.pollTx(10, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), conn.send_queue.items.len);

    const deadline = conn.ptoDeadlineMillis(.application) orelse return error.TestUnexpectedResult;
    try conn.checkPtoTimeouts(deadline);

    try std.testing.expectEqual(@as(usize, 0), conn.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 1), conn.recovery_state.pto_count);
    try std.testing.expectEqual(@as(usize, 1), conn.send_queue.items.len);
    try std.testing.expectEqual(stream_id, conn.send_queue.items[0].stream_id);
    try std.testing.expectEqual(@as(u64, 0), conn.send_queue.items[0].offset);
    try std.testing.expectEqualStrings("old", conn.send_queue.items[0].data);

    const payload = (try conn.pollTx(deadline + 1, &out_buf)) orelse return error.TestUnexpectedResult;
    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .stream => |stream_frame| {
            try std.testing.expectEqual(stream_id, stream_frame.stream_id);
            try std.testing.expectEqual(@as(u64, 0), stream_frame.offset);
            try std.testing.expectEqualStrings("old", stream_frame.data);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 2), conn.sentPacketCount(.application));
}

test "checkPtoTimeouts retransmits protected Initial CRYPTO data before PING" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const secrets = try protection.deriveInitialSecrets(.v1, &dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer client.deinit();

    try client.sendCryptoInSpace(.initial, "pto protected initial");
    const protected = (try client.pollInitialProtectedDatagram(
        10,
        &dcid,
        &scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.initial));
    try std.testing.expectEqual(@as(usize, 0), client.initial_packet_space.crypto_send_queue.items.len);

    const deadline = client.ptoDeadlineMillis(.initial) orelse return error.TestUnexpectedResult;
    try client.checkPtoTimeouts(deadline);
    try std.testing.expectEqual(@as(usize, 0), client.initial_packet_space.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 1), client.initial_packet_space.recovery_state.pto_count);
    try std.testing.expectEqual(@as(usize, 1), client.initial_packet_space.crypto_send_queue.items.len);
    try std.testing.expectEqual(@as(u64, 0), client.initial_packet_space.crypto_send_queue.items[0].offset);
    try std.testing.expectEqualStrings("pto protected initial", client.initial_packet_space.crypto_send_queue.items[0].data);

    const retransmit = (try client.pollInitialProtectedDatagram(
        deadline + 1,
        &dcid,
        &scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(retransmit);
    try std.testing.expectEqual(@as(usize, 2), client.sentPacketCount(.initial));

    var opened = try protection.unprotectLongPacketAes128(std.testing.allocator, secrets.client, retransmit, 1);
    defer protection.deinitProtectedLongPacket(&opened, std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 1), opened.packet.header.packet_number);

    var payload_offset: usize = 0;
    var found_crypto = false;
    while (payload_offset < opened.packet.plaintext.len) {
        var decoded = try frame.decodeFrameSlice(opened.packet.plaintext[payload_offset..], std.testing.allocator);
        defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
        switch (decoded.frame) {
            .crypto => |crypto| {
                try std.testing.expectEqual(@as(u64, 0), crypto.offset);
                try std.testing.expectEqualStrings("pto protected initial", crypto.data);
                found_crypto = true;
            },
            .padding => {},
            else => return error.TestUnexpectedResult,
        }
        payload_offset += decoded.len;
    }
    try std.testing.expect(found_crypto);
}

test "checkPtoTimeouts retransmits protected short CRYPTO data before PING" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer client.deinit();

    try client.sendCrypto("pto protected crypto");
    const protected = (try client.pollProtectedShortDatagram(
        10,
        &server_dcid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.crypto_send_queue.items.len);

    const deadline = client.ptoDeadlineMillis(.application) orelse return error.TestUnexpectedResult;
    try client.checkPtoTimeouts(deadline);
    try std.testing.expectEqual(@as(usize, 0), client.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 1), client.recovery_state.pto_count);
    try std.testing.expectEqual(@as(usize, 1), client.crypto_send_queue.items.len);
    try std.testing.expectEqual(@as(u64, 0), client.crypto_send_queue.items[0].offset);
    try std.testing.expectEqualStrings("pto protected crypto", client.crypto_send_queue.items[0].data);

    const retransmit = (try client.pollProtectedShortDatagram(
        deadline + 1,
        &server_dcid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(retransmit);
    try std.testing.expectEqual(@as(usize, 2), client.sentPacketCount(.application));

    var opened = try protection.unprotectShortPacketAes128(std.testing.allocator, secrets.client, retransmit, server_dcid.len, 1);
    defer protection.deinitProtectedShortPacket(&opened, std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 1), opened.packet.header.packet_number);

    var decoded = try frame.decodeFrameSlice(opened.packet.plaintext, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .crypto => |crypto| {
            try std.testing.expectEqual(@as(u64, 0), crypto.offset);
            try std.testing.expectEqualStrings("pto protected crypto", crypto.data);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "checkPtoTimeouts queues peer-space PTO probes without early backoff" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();
    try conn.validatePeerAddress();

    _ = try conn.recordPacketSentInSpace(.initial, 10, 100);
    _ = try conn.recordPacketSentInSpace(.handshake, 20, 100);

    try std.testing.expectEqual(@as(?i64, 310), conn.ptoDeadlineMillis(.initial));
    try std.testing.expectEqual(@as(?i64, 320), conn.ptoDeadlineMillis(.handshake));

    try conn.checkPtoTimeouts(309);
    try std.testing.expectEqual(@as(usize, 0), conn.initial_packet_space.pending_ping_count);
    try std.testing.expectEqual(@as(usize, 0), conn.handshake_packet_space.pending_ping_count);

    try conn.checkPtoTimeouts(310);
    try std.testing.expectEqual(@as(usize, 1), conn.initial_packet_space.pending_ping_count);
    try std.testing.expectEqual(@as(usize, 1), conn.handshake_packet_space.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 1), conn.initial_packet_space.recovery_state.pto_count);
    try std.testing.expectEqual(@as(u8, 0), conn.handshake_packet_space.recovery_state.pto_count);

    try conn.checkPtoTimeouts(320);
    try std.testing.expectEqual(@as(usize, 1), conn.initial_packet_space.pending_ping_count);
    try std.testing.expectEqual(@as(usize, 1), conn.handshake_packet_space.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 1), conn.initial_packet_space.recovery_state.pto_count);
    try std.testing.expectEqual(@as(u8, 1), conn.handshake_packet_space.recovery_state.pto_count);

    var out_buf: [32]u8 = undefined;
    const initial_payload = (try conn.pollTxInSpace(.initial, 321, &out_buf)) orelse return error.TestUnexpectedResult;
    var initial_decoded = try frame.decodeFrameSlice(initial_payload, std.testing.allocator);
    defer frame.deinitFrame(&initial_decoded.frame, std.testing.allocator);
    switch (initial_decoded.frame) {
        .ping => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 0), conn.initial_packet_space.pending_ping_count);

    const handshake_payload = (try conn.pollTxInSpace(.handshake, 321, &out_buf)) orelse return error.TestUnexpectedResult;
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

test "client Handshake send discards Initial space after successful packet commit" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    _ = try client.recordPacketSentInSpace(.initial, 0, 100);
    try client.sendCryptoInSpace(.initial, "queued initial");
    try client.sendCryptoInSpace(.handshake, "client handshake");

    var tiny: [0]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, client.pollTxInSpace(.handshake, 1, &tiny));
    try std.testing.expect(!client.packetNumberSpaceDiscarded(.initial));
    try std.testing.expectEqual(@as(usize, 1), client.initial_packet_space.crypto_send_queue.items.len);

    var out_buf: [64]u8 = undefined;
    const handshake_payload = (try client.pollTxInSpace(.handshake, 2, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(handshake_payload.len > 0);
    try std.testing.expect(client.packetNumberSpaceDiscarded(.initial));
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.initial));
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight(.initial));
    try std.testing.expectEqual(@as(usize, 0), client.initial_packet_space.crypto_send_queue.items.len);
    try std.testing.expectError(error.InvalidPacket, client.pollTxInSpace(.initial, 3, &out_buf));
}

test "server Handshake receive discards Initial space after valid payload" {
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    const ping = [_]u8{@intFromEnum(frame.FrameType.ping)};
    try server.processDatagramInSpace(.initial, 0, &ping);
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.initial));

    const invalid_handshake = [_]u8{
        @intFromEnum(frame.FrameType.ping),
        0xff,
    };
    try std.testing.expectError(error.InvalidPacket, server.processDatagramInSpace(.handshake, 1, &invalid_handshake));
    try std.testing.expect(!server.packetNumberSpaceDiscarded(.initial));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.initial));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.handshake));

    try server.processDatagramInSpace(.handshake, 2, &ping);
    try std.testing.expect(server.packetNumberSpaceDiscarded(.initial));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.initial));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.handshake));
}

test "protected Handshake packet commits discard Initial at the RFC 9001 boundary" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    _ = try client.recordPacketSentInSpace(.initial, 0, 100);
    try client.sendCryptoInSpace(.initial, "queued initial");
    try client.sendCryptoInSpace(.handshake, "client handshake");
    const protected = (try client.pollProtectedLongCryptoDatagramInSpace(
        .handshake,
        10,
        &server_scid,
        &client_scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);

    try std.testing.expect(client.packetNumberSpaceDiscarded(.initial));
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.initial));
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.handshake));

    const ping = [_]u8{@intFromEnum(frame.FrameType.ping)};
    try server.processDatagramInSpace(.initial, 0, &ping);
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.initial));
    try server.processProtectedLongDatagramInSpace(.handshake, 11, secrets.client, protected);
    try std.testing.expect(server.packetNumberSpaceDiscarded(.initial));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.initial));

    var crypto_buf: [32]u8 = undefined;
    const recv_len = (try server.recvCryptoInSpace(.handshake, &crypto_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("client handshake", crypto_buf[0..recv_len]);
}

test "discardPacketNumberSpace clears installed Handshake protection keys" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    try conn.installHandshakeTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });
    try std.testing.expect(conn.hasHandshakeProtectionKeys());

    try conn.sendCryptoInSpace(.handshake, "handshake");
    try conn.discardPacketNumberSpace(.handshake);
    try std.testing.expect(conn.packetNumberSpaceDiscarded(.handshake));
    try std.testing.expect(!conn.hasHandshakeProtectionKeys());
    try std.testing.expectError(
        error.InvalidPacket,
        conn.pollProtectedHandshakeDatagramWithInstalledKeys(0, &dcid, &scid),
    );
    try std.testing.expectError(
        error.InvalidPacket,
        conn.processProtectedHandshakeDatagramWithInstalledKeys(0, &[_]u8{}),
    );
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
    const protected = (try client.pollInitialProtectedDatagram(
        0,
        &dcid,
        &scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);
    try std.testing.expect(protected.len >= min_initial_udp_datagram_len);

    try server.processInitialProtectedDatagram(1, secrets.client, protected);

    var crypto_buf: [32]u8 = undefined;
    const recv_len = (try server.recvCryptoInSpace(.initial, &crypto_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("client initial", crypto_buf[0..recv_len]);
    try std.testing.expectEqualStrings(&scid, server.peerInitialSourceConnectionId().?);
    try std.testing.expectEqual(@as(u64, 1), server.nextPeerPacketNumber(.initial));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.initial));
}

test "processInitialProtectedDatagram rejects tampered packet without state changes" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const secrets = try protection.deriveInitialSecrets(.v1, &dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try client.sendCryptoInSpace(.initial, "plaintext");
    const protected = (try client.pollInitialProtectedDatagram(
        0,
        &dcid,
        &scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);
    try std.testing.expect(protected.len >= min_initial_udp_datagram_len);

    const tampered = try std.testing.allocator.dupe(u8, protected);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;

    try std.testing.expectError(error.InvalidPacket, server.processInitialProtectedDatagram(1, secrets.client, tampered));
    try std.testing.expectEqual(@as(u64, 0), server.nextPeerPacketNumber(.initial));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.initial));
    try std.testing.expectEqual(@as(?[]const u8, null), server.peerInitialSourceConnectionId());
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
    try std.testing.expect(protected.len >= min_initial_udp_datagram_len);

    try std.testing.expectEqual(@as(u64, 1), client.nextPacketNumber(.initial));
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.initial));
    try std.testing.expectEqual(protected.len, client.bytesInFlight(.initial));
    try std.testing.expectEqualStrings(&dcid, client.originalDestinationConnectionId().?);
    try std.testing.expect(client.localTransportParameters().original_destination_connection_id == null);
    try std.testing.expectEqualStrings(&scid, client.localInitialSourceConnectionId().?);
    try std.testing.expectEqualStrings(&scid, client.localTransportParameters().initial_source_connection_id.?);

    try server.processInitialProtectedDatagram(1, secrets.client, protected);
    try std.testing.expectEqualStrings(&dcid, server.originalDestinationConnectionId().?);
    try std.testing.expectEqualStrings(&dcid, server.localTransportParameters().original_destination_connection_id.?);
    var crypto_buf: [32]u8 = undefined;
    const recv_len = (try server.recvCryptoInSpace(.initial, &crypto_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("client initial", crypto_buf[0..recv_len]);
    try std.testing.expectEqual(@as(u64, 1), server.nextPeerPacketNumber(.initial));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.initial));
}

test "ACK-driven loss requeues protected Initial CRYPTO frame for retransmission" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const secrets = try protection.deriveInitialSecrets(.v1, &dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    try client.sendCryptoInSpace(.initial, "lost protected initial");
    const protected = (try client.pollInitialProtectedDatagram(
        10,
        &dcid,
        &scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.initial));
    try std.testing.expectEqual(@as(usize, 0), client.initial_packet_space.crypto_send_queue.items.len);
    try std.testing.expect(client.initial_packet_space.sent_packets.items[0].crypto_frame != null);

    _ = try client.recordPacketSentInSpace(.initial, 20, 1);
    _ = try client.recordPacketSentInSpace(.initial, 30, 1);
    _ = try client.recordPacketSentInSpace(.initial, 40, 1);
    try client.receiveAckInSpace(.initial, 70, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    try std.testing.expectEqual(@as(usize, 2), client.sentPacketCount(.initial));
    try std.testing.expectEqual(@as(usize, 1), client.initial_packet_space.crypto_send_queue.items.len);
    try std.testing.expectEqual(@as(u64, 0), client.initial_packet_space.crypto_send_queue.items[0].offset);
    try std.testing.expectEqualStrings("lost protected initial", client.initial_packet_space.crypto_send_queue.items[0].data);

    const retransmit = (try client.pollInitialProtectedDatagram(
        80,
        &dcid,
        &scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(retransmit);

    var opened = try protection.unprotectLongPacketAes128(std.testing.allocator, secrets.client, retransmit, 4);
    defer protection.deinitProtectedLongPacket(&opened, std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 4), opened.packet.header.packet_number);

    var payload_offset: usize = 0;
    var found_crypto = false;
    while (payload_offset < opened.packet.plaintext.len) {
        var decoded = try frame.decodeFrameSlice(opened.packet.plaintext[payload_offset..], std.testing.allocator);
        defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
        switch (decoded.frame) {
            .crypto => |crypto| {
                try std.testing.expectEqual(@as(u64, 0), crypto.offset);
                try std.testing.expectEqualStrings("lost protected initial", crypto.data);
                found_crypto = true;
            },
            .padding => {},
            else => return error.TestUnexpectedResult,
        }
        payload_offset += decoded.len;
    }
    try std.testing.expect(found_crypto);
}

test "Initial datagram size follows RFC 9000 minimum rules" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &dcid);

    const small_initial = try protection.protectLongPacketAes128(std.testing.allocator, .{
        .version = .v1,
        .dcid = &dcid,
        .scid = &client_scid,
        .packet_type = .initial,
        .token = &[_]u8{},
        .packet_number = 0,
        .payload_length = 0,
    }, try packet.encodePacketNumberForHeader(0, null), secrets.client, "client initial");
    defer std.testing.allocator.free(small_initial);
    try std.testing.expect(small_initial.len < min_initial_udp_datagram_len);

    var small_server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer small_server.deinit();
    try std.testing.expectError(error.InvalidPacket, small_server.processInitialProtectedDatagram(0, secrets.client, small_initial));
    try std.testing.expectEqual(@as(u64, 0), small_server.nextPeerPacketNumber(.initial));
    try std.testing.expectEqual(@as(?u64, null), small_server.pendingAckLargest(.initial));
    try std.testing.expectEqual(@as(?[]const u8, null), small_server.originalDestinationConnectionId());

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try client.sendCryptoInSpace(.initial, "client initial");
    const padded_client_initial = (try client.pollInitialProtectedDatagram(
        1,
        &dcid,
        &client_scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(padded_client_initial);
    try std.testing.expect(padded_client_initial.len >= min_initial_udp_datagram_len);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.processInitialProtectedDatagram(2, secrets.client, padded_client_initial);
    try std.testing.expectEqualStrings(&dcid, server.originalDestinationConnectionId().?);
    try server.validatePeerAddress();

    try server.sendCryptoInSpace(.initial, "server initial");
    const padded_server_initial = (try server.pollInitialProtectedDatagram(
        3,
        &client_scid,
        &server_scid,
        &[_]u8{},
        secrets.server,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(padded_server_initial);
    try std.testing.expect(padded_server_initial.len >= min_initial_udp_datagram_len);

    var ack_server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer ack_server.deinit();
    try ack_server.validatePeerAddress();
    try ack_server.processInitialProtectedDatagram(4, secrets.client, padded_client_initial);
    const ack_only = (try ack_server.pollProtectedLongDatagram(
        5,
        &client_scid,
        &server_scid,
        &[_]u8{},
        .{ .initial = secrets.server },
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(ack_only);
    try std.testing.expect(ack_only.len < min_initial_udp_datagram_len);
}

test "Initial packetization enforces client DCID length and server empty token" {
    const short_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57 };
    const valid_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try client.sendCryptoInSpace(.initial, "client initial");
    const short_secrets = try protection.deriveInitialSecrets(.v1, &short_dcid);
    try std.testing.expectError(error.InvalidPacket, client.pollInitialProtectedDatagram(
        0,
        &short_dcid,
        &client_scid,
        &[_]u8{},
        short_secrets.client,
    ));
    try std.testing.expectEqual(@as(u64, 0), client.nextPacketNumber(.initial));
    try std.testing.expectEqual(@as(?[]const u8, null), client.originalDestinationConnectionId());

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.sendCryptoInSpace(.initial, "server initial");
    const valid_secrets = try protection.deriveInitialSecrets(.v1, &valid_dcid);
    try std.testing.expectError(error.InvalidPacket, server.pollInitialProtectedDatagram(
        0,
        &client_scid,
        &server_scid,
        "server-token-is-invalid",
        valid_secrets.server,
    ));
    try std.testing.expectEqual(@as(u64, 0), server.nextPacketNumber(.initial));
    try std.testing.expectEqual(@as(?[]const u8, null), server.localInitialSourceConnectionId());

    var follow_client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer follow_client.deinit();
    try follow_client.sendCryptoInSpace(.initial, "client initial");
    const first_initial = (try follow_client.pollInitialProtectedDatagram(
        1,
        &valid_dcid,
        &client_scid,
        &[_]u8{},
        valid_secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(first_initial);

    var follow_server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer follow_server.deinit();
    try follow_server.validatePeerAddress();
    try follow_server.sendCryptoInSpace(.initial, "server initial");
    const server_initial = (try follow_server.pollInitialProtectedDatagram(
        2,
        &client_scid,
        &server_scid,
        &[_]u8{},
        valid_secrets.server,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(server_initial);
    try follow_client.processInitialProtectedDatagram(2, valid_secrets.server, server_initial);
    try std.testing.expectEqualStrings(&server_scid, follow_client.peerInitialSourceConnectionId().?);
    try follow_client.sendPingInSpace(.initial);

    try std.testing.expectError(error.InvalidPacket, follow_client.pollProtectedLongDatagram(
        3,
        &valid_dcid,
        &client_scid,
        &[_]u8{},
        .{ .initial = valid_secrets.client },
    ));
    try std.testing.expectEqual(@as(u64, 1), follow_client.nextPacketNumber(.initial));

    const follow_initial = (try follow_client.pollProtectedLongDatagram(
        4,
        &server_scid,
        &client_scid,
        &[_]u8{},
        .{ .initial = valid_secrets.client },
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(follow_initial);
    var opened_follow_initial = try protection.unprotectLongPacketAes128(
        std.testing.allocator,
        valid_secrets.client,
        follow_initial,
        1,
    );
    defer protection.deinitProtectedLongPacket(&opened_follow_initial, std.testing.allocator);
    try std.testing.expectEqualStrings(&server_scid, opened_follow_initial.packet.header.dcid);
}

test "Initial receive validates first client DCID length and server token direction" {
    const short_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57 };
    const valid_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };

    const short_secrets = try protection.deriveInitialSecrets(.v1, &short_dcid);
    const short_protected = try protection.protectLongPacketAes128(std.testing.allocator, .{
        .version = .v1,
        .dcid = &short_dcid,
        .scid = &client_scid,
        .packet_type = .initial,
        .token = &[_]u8{},
        .packet_number = 0,
        .payload_length = 0,
    }, try packet.encodePacketNumberForHeader(0, null), short_secrets.client, "client initial");
    defer std.testing.allocator.free(short_protected);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try std.testing.expectError(error.InvalidPacket, server.processInitialProtectedDatagram(0, short_secrets.client, short_protected));
    try std.testing.expectEqual(@as(u64, 0), server.nextPeerPacketNumber(.initial));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.initial));
    try std.testing.expectEqual(@as(?[]const u8, null), server.originalDestinationConnectionId());
    try std.testing.expectEqual(@as(?[]const u8, null), server.peerInitialSourceConnectionId());

    const valid_secrets = try protection.deriveInitialSecrets(.v1, &valid_dcid);
    const token_protected = try protection.protectLongPacketAes128(std.testing.allocator, .{
        .version = .v1,
        .dcid = &client_scid,
        .scid = &server_scid,
        .packet_type = .initial,
        .token = "server-token-is-invalid",
        .packet_number = 0,
        .payload_length = 0,
    }, try packet.encodePacketNumberForHeader(0, null), valid_secrets.server, "server initial");
    defer std.testing.allocator.free(token_protected);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try std.testing.expectError(error.InvalidPacket, client.processInitialProtectedDatagram(0, valid_secrets.server, token_protected));
    try std.testing.expectEqual(@as(u64, 0), client.nextPeerPacketNumber(.initial));
    try std.testing.expectEqual(@as(?u64, null), client.pendingAckLargest(.initial));
    try std.testing.expectEqual(@as(?[]const u8, null), client.peerInitialSourceConnectionId());
}

test "processRetryDatagram stores token and Initial packetization reuses it" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const retry_scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const retry_token = "retry-token-for-client-address";
    const retry = packet.RetryPacket{
        .version = .v1,
        .dcid = &client_scid,
        .scid = &retry_scid,
        .token = retry_token,
        .integrity_tag = [_]u8{0} ** protection.aead_tag_len,
    };
    const retry_datagram = try protection.encodeRetryPacketWithIntegrity(std.testing.allocator, &original_dcid, retry);
    defer std.testing.allocator.free(retry_datagram);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    try client.processRetryDatagram(10, &original_dcid, retry_datagram);
    try std.testing.expectEqualStrings(retry_token, client.latestRetryToken().?);
    try std.testing.expectEqualStrings(&original_dcid, client.originalDestinationConnectionId().?);
    try std.testing.expectEqualStrings(&retry_scid, client.retrySourceConnectionId().?);

    const retry_secrets = try protection.deriveInitialSecrets(.v1, &retry_scid);
    try client.sendCryptoInSpace(.initial, "client after retry");
    const protected = (try client.pollInitialProtectedDatagram(
        11,
        &retry_scid,
        &client_scid,
        &[_]u8{},
        retry_secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);

    var opened = try protection.unprotectLongPacketAes128(std.testing.allocator, retry_secrets.client, protected, 0);
    defer protection.deinitProtectedLongPacket(&opened, std.testing.allocator);
    try std.testing.expectEqual(packet.PacketType.initial, opened.packet.header.packet_type);
    try std.testing.expectEqualStrings(retry_token, opened.packet.header.token);
    try std.testing.expectEqualStrings(&retry_scid, opened.packet.header.dcid);
    try std.testing.expectEqualStrings(&client_scid, opened.packet.header.scid);
    try std.testing.expectEqual(@as(u64, 1), client.nextPacketNumber(.initial));
}

test "processRetryDatagram rejects invalid or duplicate Retry without mutation" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const retry_scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const retry_token = "retry-token-for-client-address";
    const retry = packet.RetryPacket{
        .version = .v1,
        .dcid = &client_scid,
        .scid = &retry_scid,
        .token = retry_token,
        .integrity_tag = [_]u8{0} ** protection.aead_tag_len,
    };
    const retry_datagram = try protection.encodeRetryPacketWithIntegrity(std.testing.allocator, &original_dcid, retry);
    defer std.testing.allocator.free(retry_datagram);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try std.testing.expectError(error.InvalidPacket, server.processRetryDatagram(9, &original_dcid, retry_datagram));
    try std.testing.expectEqual(@as(?[]const u8, null), server.latestRetryToken());

    const tampered = try std.testing.allocator.dupe(u8, retry_datagram);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;

    var tampered_client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer tampered_client.deinit();
    try std.testing.expectError(error.InvalidPacket, tampered_client.processRetryDatagram(10, &original_dcid, tampered));
    try std.testing.expectEqual(@as(?[]const u8, null), tampered_client.latestRetryToken());
    try std.testing.expectEqual(@as(?[]const u8, null), tampered_client.originalDestinationConnectionId());
    try std.testing.expectEqual(@as(?[]const u8, null), tampered_client.retrySourceConnectionId());

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try client.processRetryDatagram(11, &original_dcid, retry_datagram);
    try std.testing.expectError(error.InvalidPacket, client.processRetryDatagram(12, &original_dcid, retry_datagram));
    try std.testing.expectEqualStrings(retry_token, client.latestRetryToken().?);
    try std.testing.expectEqualStrings(&retry_scid, client.retrySourceConnectionId().?);
}

test "processVersionNegotiationDatagram selects mutual version once" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const client_versions = [_]packet.Version{ .v2, .v1 };
    const server_versions = [_]packet.Version{.v2};
    var raw: [64]u8 = undefined;
    var out = buffer.fixedWriter(&raw);
    try packet.encodeVersionNegotiationPacket(out.writer(), .{
        .dcid = &client_scid,
        .scid = &original_dcid,
        .versions = &server_versions,
    });

    var client = try QuicConnection.init(std.testing.allocator, .client, .{
        .chosen_version = .v1,
        .available_versions = &client_versions,
    });
    defer client.deinit();

    const selected = (try client.processVersionNegotiationDatagram(
        10,
        &original_dcid,
        &client_scid,
        out.getWritten(),
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(packet.Version.v2, selected);
    try std.testing.expectEqual(packet.Version.v2, client.versionNegotiationSelectedVersion().?);
    try std.testing.expectEqual(@as(?packet.Version, null), try client.processVersionNegotiationDatagram(
        11,
        &original_dcid,
        &client_scid,
        out.getWritten(),
    ));
    try std.testing.expectEqual(packet.Version.v2, client.versionNegotiationSelectedVersion().?);
}

test "processVersionNegotiationDatagram ignores unsafe or mismatched packets" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const other_cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const client_versions = [_]packet.Version{ .v2, .v1 };
    const v1_included = [_]packet.Version{ .v2, .v1 };
    const v2_only = [_]packet.Version{.v2};

    var contains_original_raw: [80]u8 = undefined;
    var contains_original_out = buffer.fixedWriter(&contains_original_raw);
    try packet.encodeVersionNegotiationPacket(contains_original_out.writer(), .{
        .dcid = &client_scid,
        .scid = &original_dcid,
        .versions = &v1_included,
    });

    var wrong_dcid_raw: [80]u8 = undefined;
    var wrong_dcid_out = buffer.fixedWriter(&wrong_dcid_raw);
    try packet.encodeVersionNegotiationPacket(wrong_dcid_out.writer(), .{
        .dcid = &other_cid,
        .scid = &original_dcid,
        .versions = &v2_only,
    });

    var wrong_scid_raw: [80]u8 = undefined;
    var wrong_scid_out = buffer.fixedWriter(&wrong_scid_raw);
    try packet.encodeVersionNegotiationPacket(wrong_scid_out.writer(), .{
        .dcid = &client_scid,
        .scid = &other_cid,
        .versions = &v2_only,
    });

    var client = try QuicConnection.init(std.testing.allocator, .client, .{
        .chosen_version = .v1,
        .available_versions = &client_versions,
    });
    defer client.deinit();

    try std.testing.expectEqual(@as(?packet.Version, null), try client.processVersionNegotiationDatagram(
        10,
        &original_dcid,
        &client_scid,
        contains_original_out.getWritten(),
    ));
    try std.testing.expectEqual(@as(?packet.Version, null), try client.processVersionNegotiationDatagram(
        11,
        &original_dcid,
        &client_scid,
        wrong_dcid_out.getWritten(),
    ));
    try std.testing.expectEqual(@as(?packet.Version, null), try client.processVersionNegotiationDatagram(
        12,
        &original_dcid,
        &client_scid,
        wrong_scid_out.getWritten(),
    ));
    try std.testing.expectEqual(@as(?packet.Version, null), client.versionNegotiationSelectedVersion());
}

test "processVersionNegotiationDatagram rejects no mutual version without mutation" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const client_versions = [_]packet.Version{ .v2, .v1 };
    const server_versions = [_]packet.Version{@enumFromInt(0xface_b00c)};
    var raw: [64]u8 = undefined;
    var out = buffer.fixedWriter(&raw);
    try packet.encodeVersionNegotiationPacket(out.writer(), .{
        .dcid = &client_scid,
        .scid = &original_dcid,
        .versions = &server_versions,
    });

    var client = try QuicConnection.init(std.testing.allocator, .client, .{
        .chosen_version = .v1,
        .available_versions = &client_versions,
    });
    defer client.deinit();

    try std.testing.expectError(error.InvalidPacket, client.processVersionNegotiationDatagram(
        10,
        &original_dcid,
        &client_scid,
        out.getWritten(),
    ));
    try std.testing.expectEqual(@as(?packet.Version, null), client.versionNegotiationSelectedVersion());

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try std.testing.expectError(error.InvalidPacket, server.processVersionNegotiationDatagram(
        10,
        &original_dcid,
        &client_scid,
        out.getWritten(),
    ));
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
    try std.testing.expect(client.localInitialSourceConnectionId() == null);
    try std.testing.expect(client.localTransportParameters().initial_source_connection_id == null);
}

test "protected long datagram bridge emits Handshake CRYPTO packet" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try protection.deriveInitialSecrets(.v1, &dcid);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try server.validatePeerAddress();

    try server.sendCryptoInSpace(.handshake, "server handshake");
    const protected = (try server.pollProtectedLongCryptoDatagramInSpace(
        .handshake,
        10,
        &dcid,
        &scid,
        &[_]u8{},
        secrets.server,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);

    try std.testing.expectEqual(@as(u64, 1), server.nextPacketNumber(.handshake));
    try std.testing.expectEqual(@as(usize, 1), server.sentPacketCount(.handshake));
    try std.testing.expectEqual(protected.len, server.bytesInFlight(.handshake));

    try client.processProtectedLongDatagramInSpace(.handshake, 11, secrets.server, protected);
    var crypto_buf: [32]u8 = undefined;
    const recv_len = (try client.recvCryptoInSpace(.handshake, &crypto_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("server handshake", crypto_buf[0..recv_len]);
    try std.testing.expectEqual(@as(u64, 1), client.nextPeerPacketNumber(.handshake));
    try std.testing.expectEqual(@as(?u64, 0), client.pendingAckLargest(.handshake));
}

test "processProtectedLongDatagram routes coalesced Initial and Handshake packets" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try server.validatePeerAddress();

    try server.sendCryptoInSpace(.initial, "server initial");
    const initial = (try server.pollProtectedLongCryptoDatagramInSpace(
        .initial,
        10,
        &client_scid,
        &server_scid,
        &[_]u8{},
        secrets.server,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(initial);

    try server.sendCryptoInSpace(.handshake, "server handshake");
    const handshake = (try server.pollProtectedLongCryptoDatagramInSpace(
        .handshake,
        11,
        &client_scid,
        &server_scid,
        &[_]u8{},
        secrets.server,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(handshake);

    const coalesced = try std.testing.allocator.alloc(u8, initial.len + handshake.len);
    defer std.testing.allocator.free(coalesced);
    @memcpy(coalesced[0..initial.len], initial);
    @memcpy(coalesced[initial.len..], handshake);

    try std.testing.expectEqual(@as(usize, 2), try client.processProtectedLongDatagram(12, .{
        .initial = secrets.server,
        .handshake = secrets.server,
    }, coalesced));

    var crypto_buf: [32]u8 = undefined;
    const initial_len = (try client.recvCryptoInSpace(.initial, &crypto_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("server initial", crypto_buf[0..initial_len]);
    const handshake_len = (try client.recvCryptoInSpace(.handshake, &crypto_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("server handshake", crypto_buf[0..handshake_len]);
    try std.testing.expectEqual(@as(u64, 1), client.nextPeerPacketNumber(.initial));
    try std.testing.expectEqual(@as(u64, 1), client.nextPeerPacketNumber(.handshake));
    try std.testing.expectEqual(@as(?u64, 0), client.pendingAckLargest(.initial));
    try std.testing.expectEqual(@as(?u64, 0), client.pendingAckLargest(.handshake));
}

test "processProtectedLongDatagram validates coalesced keys before mutation" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try server.validatePeerAddress();

    try server.sendCryptoInSpace(.initial, "server initial");
    const initial = (try server.pollProtectedLongCryptoDatagramInSpace(
        .initial,
        10,
        &client_scid,
        &server_scid,
        &[_]u8{},
        secrets.server,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(initial);

    try server.sendCryptoInSpace(.handshake, "server handshake");
    const handshake = (try server.pollProtectedLongCryptoDatagramInSpace(
        .handshake,
        11,
        &client_scid,
        &server_scid,
        &[_]u8{},
        secrets.server,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(handshake);

    const coalesced = try std.testing.allocator.alloc(u8, initial.len + handshake.len);
    defer std.testing.allocator.free(coalesced);
    @memcpy(coalesced[0..initial.len], initial);
    @memcpy(coalesced[initial.len..], handshake);

    try std.testing.expectError(error.InvalidPacket, client.processProtectedLongDatagram(12, .{
        .initial = secrets.server,
    }, coalesced));

    var crypto_buf: [32]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try client.recvCryptoInSpace(.initial, &crypto_buf));
    try std.testing.expectEqual(@as(?usize, null), try client.recvCryptoInSpace(.handshake, &crypto_buf));
    try std.testing.expectEqual(@as(u64, 0), client.nextPeerPacketNumber(.initial));
    try std.testing.expectEqual(@as(u64, 0), client.nextPeerPacketNumber(.handshake));
    try std.testing.expectEqual(@as(?u64, null), client.pendingAckLargest(.initial));
    try std.testing.expectEqual(@as(?u64, null), client.pendingAckLargest(.handshake));
}

test "pollProtectedLongDatagram coalesces Initial and Handshake CRYPTO packets" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try server.validatePeerAddress();

    try server.sendCryptoInSpace(.initial, "server initial");
    try server.sendCryptoInSpace(.handshake, "server handshake");

    const coalesced = (try server.pollProtectedLongDatagram(
        10,
        &client_scid,
        &server_scid,
        &[_]u8{},
        .{ .initial = secrets.server, .handshake = secrets.server },
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(coalesced);

    const first = try protection.peekProtectedLongPacketInfo(coalesced);
    try std.testing.expectEqual(packet.PacketType.initial, first.packet_type);
    const second = try protection.peekProtectedLongPacketInfo(coalesced[first.len..]);
    try std.testing.expectEqual(packet.PacketType.handshake, second.packet_type);
    try std.testing.expectEqual(coalesced.len, first.len + second.len);
    try std.testing.expectEqual(@as(u64, 1), server.nextPacketNumber(.initial));
    try std.testing.expectEqual(@as(u64, 1), server.nextPacketNumber(.handshake));
    try std.testing.expectEqual(@as(usize, 1), server.sentPacketCount(.initial));
    try std.testing.expectEqual(@as(usize, 1), server.sentPacketCount(.handshake));
    try std.testing.expectEqual(first.len, server.bytesInFlight(.initial));
    try std.testing.expectEqual(second.len, server.bytesInFlight(.handshake));
    try std.testing.expectEqualStrings(&server_scid, server.localInitialSourceConnectionId().?);
    try std.testing.expectEqualStrings(&server_scid, server.localTransportParameters().initial_source_connection_id.?);

    try std.testing.expectEqual(@as(usize, 2), try client.processProtectedLongDatagram(11, .{
        .initial = secrets.server,
        .handshake = secrets.server,
    }, coalesced));

    var crypto_buf: [32]u8 = undefined;
    const initial_len = (try client.recvCryptoInSpace(.initial, &crypto_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("server initial", crypto_buf[0..initial_len]);
    const handshake_len = (try client.recvCryptoInSpace(.handshake, &crypto_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("server handshake", crypto_buf[0..handshake_len]);
}

test "pollProtectedLongDatagram validates keys before send-state mutation" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();
    try server.sendCryptoInSpace(.initial, "server initial");
    try server.sendCryptoInSpace(.handshake, "server handshake");

    try std.testing.expectError(error.InvalidPacket, server.pollProtectedLongDatagram(
        10,
        &client_scid,
        &server_scid,
        &[_]u8{},
        .{ .initial = secrets.server },
    ));
    try std.testing.expectEqual(@as(u64, 0), server.nextPacketNumber(.initial));
    try std.testing.expectEqual(@as(u64, 0), server.nextPacketNumber(.handshake));
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.initial));
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.handshake));

    const coalesced = (try server.pollProtectedLongDatagram(
        11,
        &client_scid,
        &server_scid,
        &[_]u8{},
        .{ .initial = secrets.server, .handshake = secrets.server },
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(coalesced);
    try std.testing.expectEqual(@as(u64, 1), server.nextPacketNumber(.initial));
    try std.testing.expectEqual(@as(u64, 1), server.nextPacketNumber(.handshake));
}

test "pollProtectedZeroRttDatagram emits protected STREAM in Application packet space" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "early data", true);
    const protected = (try client.pollProtectedZeroRttDatagram(
        10,
        &server_scid,
        &client_scid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);

    const info = try protection.peekProtectedLongPacketInfo(protected);
    try std.testing.expectEqual(packet.PacketType.zero_rtt, info.packet_type);
    try std.testing.expectEqual(@as(u64, 1), client.nextPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.send_queue.items.len);

    try std.testing.expectEqual(@as(usize, 1), try server.processProtectedLongDatagram(11, .{
        .zero_rtt = secrets.client,
    }, protected));

    var recv_buf: [32]u8 = undefined;
    const recv_len = (try server.recvOnStream(stream_id, &recv_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("early data", recv_buf[0..recv_len]);
    try std.testing.expectEqual(@as(u64, 1), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.application));
}

test "ACK-driven loss requeues protected 0-RTT STREAM frame for retransmission" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "lost early", true);
    const protected = (try client.pollProtectedZeroRttDatagram(
        10,
        &server_scid,
        &client_scid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);

    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.send_queue.items.len);
    try std.testing.expect(client.sent_packets.items[0].stream_frame != null);

    _ = try client.recordPacketSentInSpace(.application, 20, 1);
    _ = try client.recordPacketSentInSpace(.application, 30, 1);
    _ = try client.recordPacketSentInSpace(.application, 40, 1);
    try client.receiveAckInSpace(.application, 70, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    try std.testing.expectEqual(@as(usize, 2), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 1), client.send_queue.items.len);
    try std.testing.expectEqual(stream_id, client.send_queue.items[0].stream_id);
    try std.testing.expectEqual(@as(u64, 0), client.send_queue.items[0].offset);
    try std.testing.expect(client.send_queue.items[0].fin);
    try std.testing.expectEqualStrings("lost early", client.send_queue.items[0].data);

    const retransmit = (try client.pollProtectedZeroRttDatagram(
        80,
        &server_scid,
        &client_scid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(retransmit);

    var opened = try protection.unprotectLongPacketAes128(std.testing.allocator, secrets.client, retransmit, 4);
    defer protection.deinitProtectedLongPacket(&opened, std.testing.allocator);
    try std.testing.expectEqual(packet.PacketType.zero_rtt, opened.packet.header.packet_type);
    try std.testing.expectEqual(@as(u64, 4), opened.packet.header.packet_number);

    var payload_offset: usize = 0;
    var found_stream = false;
    while (payload_offset < opened.packet.plaintext.len) {
        var decoded = try frame.decodeFrameSlice(opened.packet.plaintext[payload_offset..], std.testing.allocator);
        defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
        switch (decoded.frame) {
            .stream => |stream| {
                try std.testing.expectEqual(stream_id, stream.stream_id);
                try std.testing.expectEqual(@as(u64, 0), stream.offset);
                try std.testing.expect(stream.fin);
                try std.testing.expectEqualStrings("lost early", stream.data);
                found_stream = true;
            },
            .padding => {},
            else => return error.TestUnexpectedResult,
        }
        payload_offset += decoded.len;
    }
    try std.testing.expect(found_stream);
}

test "checkPtoTimeouts retransmits protected 0-RTT STREAM data before PING" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer client.deinit();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "pto early", true);
    const protected = (try client.pollProtectedZeroRttDatagram(
        10,
        &server_scid,
        &client_scid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);

    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.send_queue.items.len);
    try std.testing.expect(client.sent_packets.items[0].stream_frame != null);

    const deadline = client.ptoDeadlineMillis(.application) orelse return error.TestUnexpectedResult;
    try client.checkPtoTimeouts(deadline);
    try std.testing.expectEqual(@as(usize, 0), client.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 1), client.recovery_state.pto_count);
    try std.testing.expectEqual(@as(usize, 1), client.send_queue.items.len);
    try std.testing.expectEqual(stream_id, client.send_queue.items[0].stream_id);
    try std.testing.expectEqual(@as(u64, 0), client.send_queue.items[0].offset);
    try std.testing.expect(client.send_queue.items[0].fin);
    try std.testing.expectEqualStrings("pto early", client.send_queue.items[0].data);

    const retransmit = (try client.pollProtectedZeroRttDatagram(
        deadline + 1,
        &server_scid,
        &client_scid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(retransmit);

    var opened = try protection.unprotectLongPacketAes128(std.testing.allocator, secrets.client, retransmit, 1);
    defer protection.deinitProtectedLongPacket(&opened, std.testing.allocator);
    try std.testing.expectEqual(packet.PacketType.zero_rtt, opened.packet.header.packet_type);
    try std.testing.expectEqual(@as(u64, 1), opened.packet.header.packet_number);

    var payload_offset: usize = 0;
    var found_stream = false;
    while (payload_offset < opened.packet.plaintext.len) {
        var decoded = try frame.decodeFrameSlice(opened.packet.plaintext[payload_offset..], std.testing.allocator);
        defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
        switch (decoded.frame) {
            .stream => |stream| {
                try std.testing.expectEqual(stream_id, stream.stream_id);
                try std.testing.expectEqual(@as(u64, 0), stream.offset);
                try std.testing.expect(stream.fin);
                try std.testing.expectEqualStrings("pto early", stream.data);
                found_stream = true;
            },
            .padding => {},
            else => return error.TestUnexpectedResult,
        }
        payload_offset += decoded.len;
    }
    try std.testing.expect(found_stream);
}

test "ACK-driven loss requeues protected 0-RTT control frames for retransmission" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var reset_client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer reset_client.deinit();

    const reset_stream_id = try reset_client.openStream();
    try reset_client.sendOnStream(reset_stream_id, "hello", false);
    try reset_client.resetStream(reset_stream_id, 7);
    const reset_frame: frame.ResetStreamFrame = .{
        .stream_id = reset_stream_id,
        .application_error_code = 7,
        .final_size = 5,
    };

    const protected_reset = (try reset_client.pollProtectedZeroRttDatagram(
        10,
        &server_scid,
        &client_scid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected_reset);

    try std.testing.expectEqual(@as(usize, 0), reset_client.pending_reset_streams.items.len);
    try std.testing.expect(reset_client.sent_packets.items[0].reset_stream_frame != null);
    try std.testing.expect(try protectedZeroRttContainsControlFrame(
        protected_reset,
        secrets.client,
        0,
        .{ .reset_stream = reset_frame },
    ));

    _ = try reset_client.recordPacketSentInSpace(.application, 20, 1);
    _ = try reset_client.recordPacketSentInSpace(.application, 30, 1);
    _ = try reset_client.recordPacketSentInSpace(.application, 40, 1);
    try reset_client.receiveAckInSpace(.application, 70, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    try std.testing.expectEqual(@as(usize, 1), reset_client.pending_reset_streams.items.len);
    try std.testing.expectEqual(reset_frame.stream_id, reset_client.pending_reset_streams.items[0].stream_id);
    try std.testing.expectEqual(reset_frame.application_error_code, reset_client.pending_reset_streams.items[0].application_error_code);
    try std.testing.expectEqual(reset_frame.final_size, reset_client.pending_reset_streams.items[0].final_size);

    const reset_retransmit = (try reset_client.pollProtectedZeroRttDatagram(
        80,
        &server_scid,
        &client_scid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(reset_retransmit);
    try std.testing.expect(try protectedZeroRttContainsControlFrame(
        reset_retransmit,
        secrets.client,
        4,
        .{ .reset_stream = reset_frame },
    ));

    var stop_client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer stop_client.deinit();

    const stop_stream_id = try stop_client.openStream();
    try stop_client.stopSending(stop_stream_id, 9);
    const stop_frame: frame.StopSendingFrame = .{
        .stream_id = stop_stream_id,
        .application_error_code = 9,
    };

    const protected_stop = (try stop_client.pollProtectedZeroRttDatagram(
        10,
        &server_scid,
        &client_scid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected_stop);

    try std.testing.expectEqual(@as(usize, 0), stop_client.pending_stop_sending.items.len);
    try std.testing.expect(stop_client.sent_packets.items[0].stop_sending_frame != null);
    try std.testing.expect(try protectedZeroRttContainsControlFrame(
        protected_stop,
        secrets.client,
        0,
        .{ .stop_sending = stop_frame },
    ));

    _ = try stop_client.recordPacketSentInSpace(.application, 20, 1);
    _ = try stop_client.recordPacketSentInSpace(.application, 30, 1);
    _ = try stop_client.recordPacketSentInSpace(.application, 40, 1);
    try stop_client.receiveAckInSpace(.application, 70, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    try std.testing.expectEqual(@as(usize, 1), stop_client.pending_stop_sending.items.len);
    try std.testing.expectEqual(stop_frame.stream_id, stop_client.pending_stop_sending.items[0].stream_id);
    try std.testing.expectEqual(stop_frame.application_error_code, stop_client.pending_stop_sending.items[0].application_error_code);

    const stop_retransmit = (try stop_client.pollProtectedZeroRttDatagram(
        80,
        &server_scid,
        &client_scid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(stop_retransmit);
    try std.testing.expect(try protectedZeroRttContainsControlFrame(
        stop_retransmit,
        secrets.client,
        4,
        .{ .stop_sending = stop_frame },
    ));
}

test "checkPtoTimeouts retransmits protected 0-RTT control frames before PING" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var reset_client = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer reset_client.deinit();

    const reset_stream_id = try reset_client.openStream();
    try reset_client.sendOnStream(reset_stream_id, "bye", false);
    try reset_client.resetStream(reset_stream_id, 11);
    const reset_frame: frame.ResetStreamFrame = .{
        .stream_id = reset_stream_id,
        .application_error_code = 11,
        .final_size = 3,
    };

    const protected_reset = (try reset_client.pollProtectedZeroRttDatagram(
        10,
        &server_scid,
        &client_scid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected_reset);

    const reset_deadline = reset_client.ptoDeadlineMillis(.application) orelse return error.TestUnexpectedResult;
    try reset_client.checkPtoTimeouts(reset_deadline);
    try std.testing.expectEqual(@as(usize, 0), reset_client.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 1), reset_client.recovery_state.pto_count);
    try std.testing.expectEqual(@as(usize, 1), reset_client.pending_reset_streams.items.len);

    const reset_retransmit = (try reset_client.pollProtectedZeroRttDatagram(
        reset_deadline + 1,
        &server_scid,
        &client_scid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(reset_retransmit);
    try std.testing.expect(try protectedZeroRttContainsControlFrame(
        reset_retransmit,
        secrets.client,
        1,
        .{ .reset_stream = reset_frame },
    ));

    var stop_client = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_rtt_ms = 100,
    });
    defer stop_client.deinit();

    const stop_stream_id = try stop_client.openStream();
    try stop_client.stopSending(stop_stream_id, 13);
    const stop_frame: frame.StopSendingFrame = .{
        .stream_id = stop_stream_id,
        .application_error_code = 13,
    };

    const protected_stop = (try stop_client.pollProtectedZeroRttDatagram(
        10,
        &server_scid,
        &client_scid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected_stop);

    const stop_deadline = stop_client.ptoDeadlineMillis(.application) orelse return error.TestUnexpectedResult;
    try stop_client.checkPtoTimeouts(stop_deadline);
    try std.testing.expectEqual(@as(usize, 0), stop_client.pending_ping_count);
    try std.testing.expectEqual(@as(u8, 1), stop_client.recovery_state.pto_count);
    try std.testing.expectEqual(@as(usize, 1), stop_client.pending_stop_sending.items.len);

    const stop_retransmit = (try stop_client.pollProtectedZeroRttDatagram(
        stop_deadline + 1,
        &server_scid,
        &client_scid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(stop_retransmit);
    try std.testing.expect(try protectedZeroRttContainsControlFrame(
        stop_retransmit,
        secrets.client,
        1,
        .{ .stop_sending = stop_frame },
    ));
}

test "invalid ACK payload rolls back protected 0-RTT control-frame requeue" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    const stream_id = try client.openStream();
    try client.stopSending(stream_id, 15);
    const protected = (try client.pollProtectedZeroRttDatagram(
        10,
        &server_scid,
        &client_scid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);
    try std.testing.expectEqual(@as(usize, 0), client.pending_stop_sending.items.len);

    _ = try client.recordPacketSentInSpace(.application, 20, 1);
    _ = try client.recordPacketSentInSpace(.application, 30, 1);
    _ = try client.recordPacketSentInSpace(.application, 40, 1);

    var ack_buf: [32]u8 = undefined;
    var ack_out = buffer.fixedWriter(&ack_buf);
    try frame.encodeFrame(ack_out.writer(), .{ .ack = .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    } });
    try ack_out.writeByte(0xff);

    try std.testing.expectError(
        error.InvalidPacket,
        client.processDatagramForPacketType(.one_rtt, 70, ack_out.getWritten()),
    );
    try std.testing.expectEqual(@as(usize, 4), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.pending_stop_sending.items.len);
}

test "driveCryptoBackendInSpace installs zero RTT traffic secrets for long packet exchange" {
    const SecretBackend = struct {
        secrets: ZeroRttTrafficSecrets,
        sent: bool = false,

        fn backend(self: *@This()) CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
                .pull_zero_rtt_traffic_secrets = pullZeroRttTrafficSecrets,
            };
        }

        fn receive(_: *anyopaque, _: PacketNumberSpace, _: []const u8) Error!void {}

        fn pull(_: *anyopaque, _: PacketNumberSpace, _: []u8) Error!?[]const u8 {
            return null;
        }

        fn pullZeroRttTrafficSecrets(context: *anyopaque) Error!?ZeroRttTrafficSecrets {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.sent) return null;
            self.sent = true;
            return self.secrets;
        }
    };

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    var client_backend = SecretBackend{ .secrets = .{ .local = secrets.client.secret } };
    var server_backend = SecretBackend{ .secrets = .{ .peer = secrets.client.secret } };
    var scratch: [8]u8 = undefined;
    const client_progress = try client.driveCryptoBackendInSpace(.initial, client_backend.backend(), &scratch);
    const server_progress = try server.driveCryptoBackendInSpace(.initial, server_backend.backend(), &scratch);
    try std.testing.expect(client_progress.zero_rtt_keys_installed);
    try std.testing.expect(server_progress.zero_rtt_keys_installed);
    try std.testing.expect(client.hasLocalZeroRttProtectionKey());
    try std.testing.expect(!client.hasPeerZeroRttProtectionKey());
    try std.testing.expect(!server.hasLocalZeroRttProtectionKey());
    try std.testing.expect(server.hasPeerZeroRttProtectionKey());
    try std.testing.expect(!server.zeroRttAccepted());

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "installed early", true);
    const protected = (try client.pollProtectedZeroRttDatagramWithInstalledKeys(
        10,
        &server_scid,
        &client_scid,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);

    try std.testing.expectError(
        error.InvalidPacket,
        server.processProtectedZeroRttDatagramWithInstalledKeys(10, protected),
    );
    try std.testing.expectEqual(@as(u64, 0), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));

    try server.acceptZeroRtt();
    try std.testing.expect(server.zeroRttAccepted());

    var tampered = try std.testing.allocator.dupe(u8, protected);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;
    try std.testing.expectError(
        error.InvalidPacket,
        server.processProtectedZeroRttDatagramWithInstalledKeys(11, tampered),
    );
    try std.testing.expectEqual(@as(u64, 0), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));

    try server.processProtectedZeroRttDatagramWithInstalledKeys(12, protected);
    var recv_buf: [32]u8 = undefined;
    const recv_len = (try server.recvOnStream(stream_id, &recv_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("installed early", recv_buf[0..recv_len]);
    try std.testing.expectEqual(@as(u64, 1), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.application));
}

test "discardZeroRttProtectionKeys clears installed early-data keys" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    try conn.installZeroRttTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.client.secret,
    });
    try std.testing.expect(conn.hasLocalZeroRttProtectionKey());
    try std.testing.expect(conn.hasPeerZeroRttProtectionKey());
    try conn.acceptZeroRtt();
    try std.testing.expect(conn.zeroRttAccepted());

    try conn.discardZeroRttProtectionKeys();
    try std.testing.expect(!conn.hasLocalZeroRttProtectionKey());
    try std.testing.expect(!conn.hasPeerZeroRttProtectionKey());
    try std.testing.expect(!conn.zeroRttAccepted());
    try conn.discardZeroRttProtectionKeys();

    try std.testing.expectError(
        error.InvalidPacket,
        conn.pollProtectedZeroRttDatagramWithInstalledKeys(0, &dcid, &scid),
    );
    try std.testing.expectError(
        error.InvalidPacket,
        conn.processProtectedZeroRttDatagramWithInstalledKeys(0, &[_]u8{}),
    );
}

test "installed zero RTT receive requires explicit accept or rejects and discards keys" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try std.testing.expectError(error.InvalidPacket, server.acceptZeroRtt());
    try server.installZeroRttTrafficSecrets(.{ .peer = secrets.client.secret });
    try std.testing.expect(server.hasPeerZeroRttProtectionKey());
    try std.testing.expect(!server.zeroRttAccepted());

    try server.rejectZeroRtt();
    try std.testing.expect(!server.hasPeerZeroRttProtectionKey());
    try std.testing.expect(!server.zeroRttAccepted());
    try std.testing.expectError(error.InvalidPacket, server.acceptZeroRtt());
    try std.testing.expectError(
        error.InvalidPacket,
        server.processProtectedZeroRttDatagramWithInstalledKeys(0, &[_]u8{}),
    );
}

test "installOneRttTrafficSecrets discards client zero RTT keys" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try client.installZeroRttTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });
    try std.testing.expect(client.hasLocalZeroRttProtectionKey());
    try std.testing.expect(client.hasPeerZeroRttProtectionKey());

    try client.installOneRttTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });
    try std.testing.expect(client.hasOneRttProtectionKeys());
    try std.testing.expect(!client.hasLocalZeroRttProtectionKey());
    try std.testing.expect(!client.hasPeerZeroRttProtectionKey());
    try std.testing.expectError(
        error.InvalidPacket,
        client.pollProtectedZeroRttDatagramWithInstalledKeys(0, &dcid, &scid),
    );

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.installZeroRttTrafficSecrets(.{ .peer = secrets.client.secret });
    try server.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try std.testing.expect(server.hasOneRttProtectionKeys());
    try std.testing.expect(server.hasPeerZeroRttProtectionKey());
}

test "server discards zero RTT keys after successful one RTT receive" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try server.installZeroRttTrafficSecrets(.{ .peer = secrets.client.secret });
    try server.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try std.testing.expect(server.hasPeerZeroRttProtectionKey());

    try client.sendPing();
    const protected = (try client.pollProtectedShortDatagram(
        10,
        &server_dcid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);

    var tampered = try std.testing.allocator.dupe(u8, protected);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;
    try std.testing.expectError(
        error.InvalidPacket,
        server.processProtectedShortDatagramWithInstalledKeys(11, server_dcid.len, tampered),
    );
    try std.testing.expect(server.hasPeerZeroRttProtectionKey());
    try std.testing.expectEqual(@as(u64, 0), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));

    try server.processProtectedShortDatagramWithInstalledKeys(12, server_dcid.len, protected);
    try std.testing.expect(!server.hasLocalZeroRttProtectionKey());
    try std.testing.expect(!server.hasPeerZeroRttProtectionKey());
    try std.testing.expectEqual(@as(u64, 1), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.application));
}

test "pollProtectedLongDatagram coalesces Initial and 0-RTT packets with key validation" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try client.sendCryptoInSpace(.initial, "client initial");
    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "early", true);

    const coalesced = (try client.pollProtectedLongDatagram(
        10,
        &original_dcid,
        &client_scid,
        &[_]u8{},
        .{
            .initial = secrets.client,
            .zero_rtt = secrets.client,
        },
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(coalesced);

    const first = try protection.peekProtectedLongPacketInfo(coalesced);
    try std.testing.expectEqual(packet.PacketType.initial, first.packet_type);
    const second = try protection.peekProtectedLongPacketInfo(coalesced[first.len..]);
    try std.testing.expectEqual(packet.PacketType.zero_rtt, second.packet_type);
    try std.testing.expectEqual(coalesced.len, first.len + second.len);
    try std.testing.expectEqual(@as(u64, 1), client.nextPacketNumber(.initial));
    try std.testing.expectEqual(@as(u64, 1), client.nextPacketNumber(.application));

    try std.testing.expectError(error.InvalidPacket, server.processProtectedLongDatagram(11, .{
        .initial = secrets.client,
    }, coalesced));
    var initial_buf: [32]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try server.recvCryptoInSpace(.initial, &initial_buf));
    try std.testing.expectEqual(@as(u64, 0), server.nextPeerPacketNumber(.initial));
    try std.testing.expectEqual(@as(u64, 0), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.initial));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));

    try std.testing.expectEqual(@as(usize, 2), try server.processProtectedLongDatagram(12, .{
        .initial = secrets.client,
        .zero_rtt = secrets.client,
    }, coalesced));

    const initial_len = (try server.recvCryptoInSpace(.initial, &initial_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("client initial", initial_buf[0..initial_len]);
    var stream_buf: [16]u8 = undefined;
    const stream_len = (try server.recvOnStream(stream_id, &stream_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("early", stream_buf[0..stream_len]);
    try std.testing.expectEqual(@as(u64, 1), server.nextPeerPacketNumber(.initial));
    try std.testing.expectEqual(@as(u64, 1), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.initial));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.application));
}

test "processProtectedZeroRttDatagram rejects protected ACK frame" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var plaintext: [16]u8 = undefined;
    @memset(&plaintext, 0);
    var plaintext_out = buffer.fixedWriter(&plaintext);
    try frame.encodeFrame(plaintext_out.writer(), .{ .ack = .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    } });

    const protected = try protection.protectLongPacketAes128(std.testing.allocator, .{
        .version = .v1,
        .dcid = &server_scid,
        .scid = &client_scid,
        .packet_type = .zero_rtt,
        .token = &[_]u8{},
        .packet_number = 0,
        .payload_length = 0,
    }, try packet.encodePacketNumberForHeader(0, null), secrets.client, &plaintext);
    defer std.testing.allocator.free(protected);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try std.testing.expectError(
        error.InvalidPacket,
        server.processProtectedZeroRttDatagram(10, secrets.client, protected),
    );
    try std.testing.expectEqual(@as(u64, 0), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));
}

test "pollProtectedLongDatagram drops obsolete 0-RTT STOP_SENDING" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    const stream_id = try client.openStream();
    try client.stopSending(stream_id, 1);
    try std.testing.expectEqual(@as(usize, 1), client.pending_stop_sending.items.len);

    var reset_buf: [32]u8 = undefined;
    var reset_out = buffer.fixedWriter(&reset_buf);
    try frame.encodeFrame(reset_out.writer(), .{ .reset_stream = .{
        .stream_id = stream_id,
        .application_error_code = 7,
        .final_size = 0,
    } });
    try client.processDatagramForPacketType(.one_rtt, 0, reset_out.getWritten());

    try std.testing.expectEqual(@as(?[]u8, null), try client.pollProtectedLongDatagram(
        1,
        &server_scid,
        &client_scid,
        &[_]u8{},
        .{ .zero_rtt = secrets.client },
    ));
    try std.testing.expectEqual(@as(usize, 0), client.pending_stop_sending.items.len);
    try std.testing.expectEqual(@as(u64, 0), client.nextPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, 0), client.pendingAckLargest(.application));
}

test "processProtectedShortDatagram routes protected 1-RTT payload" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);
    const plaintext = [_]u8{
        @intFromEnum(frame.FrameType.ping),
        @intFromEnum(frame.FrameType.padding),
        @intFromEnum(frame.FrameType.padding),
        @intFromEnum(frame.FrameType.padding),
    };

    const protected = try protection.protectShortPacketAes128(std.testing.allocator, .{
        .dcid = &server_dcid,
        .spin_bit = false,
        .key_phase = false,
        .packet_number = 0,
    }, try packet.encodePacketNumberForHeader(0, null), secrets.client, &plaintext);
    defer std.testing.allocator.free(protected);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try server.processProtectedShortDatagram(10, secrets.client, server_dcid.len, protected);
    try std.testing.expectEqual(@as(u64, 1), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.application));
}

test "processProtectedShortDatagram discards packets while draining" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var close_buf: [64]u8 = undefined;
    var close_out = buffer.fixedWriter(&close_buf);
    try frame.encodeFrame(close_out.writer(), .{ .application_close = .{
        .error_code = 0,
        .reason_phrase = "stop",
    } });
    const close_packet = try protection.protectShortPacketAes128(std.testing.allocator, .{
        .dcid = &server_dcid,
        .spin_bit = false,
        .key_phase = false,
        .packet_number = 0,
    }, try packet.encodePacketNumberForHeader(0, null), secrets.client, close_out.getWritten());
    defer std.testing.allocator.free(close_packet);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try server.processProtectedShortDatagram(10, secrets.client, server_dcid.len, close_packet);
    const next_peer_packet_number = server.nextPeerPacketNumber(.application);
    try std.testing.expect(server.closed);
    try std.testing.expectEqual(ConnectionState.draining, server.connectionState());
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));

    const invalid_protected = [_]u8{0xff};
    try server.processProtectedShortDatagram(11, secrets.client, server_dcid.len, &invalid_protected);
    try std.testing.expectEqual(ConnectionState.draining, server.connectionState());
    try std.testing.expectEqual(next_peer_packet_number, server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));
}

test "protected short datagram spin bit follows enabled single-path policy" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const client_dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{ .enable_spin_bit = true });
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{ .enable_spin_bit = true });
    defer server.deinit();
    try server.validatePeerAddress();

    try std.testing.expect(!client.nextOutgoingSpinBit());
    try client.sendPing();
    const first_client_packet = (try client.pollProtectedShortDatagram(
        10,
        &server_dcid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(first_client_packet);
    try std.testing.expect(!try protection.peekShortPacketSpinBit(first_client_packet));

    try server.processProtectedShortDatagram(11, secrets.client, server_dcid.len, first_client_packet);
    try std.testing.expect(!server.nextOutgoingSpinBit());
    const server_ack = (try server.pollProtectedShortDatagram(
        12,
        &client_dcid,
        secrets.server,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(server_ack);
    try std.testing.expect(!try protection.peekShortPacketSpinBit(server_ack));

    try client.processProtectedShortDatagram(13, secrets.server, client_dcid.len, server_ack);
    try std.testing.expect(client.nextOutgoingSpinBit());
    try client.sendPing();
    const second_client_packet = (try client.pollProtectedShortDatagram(
        14,
        &server_dcid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(second_client_packet);
    try std.testing.expect(try protection.peekShortPacketSpinBit(second_client_packet));

    try server.processProtectedShortDatagram(15, secrets.client, server_dcid.len, second_client_packet);
    try std.testing.expect(server.nextOutgoingSpinBit());
    server.resetSpinBitForPath();
    try std.testing.expect(!server.nextOutgoingSpinBit());
}

test "spin bit disabled and invalid packets do not update modeled state" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);
    const plaintext = [_]u8{
        @intFromEnum(frame.FrameType.ping),
        @intFromEnum(frame.FrameType.padding),
        @intFromEnum(frame.FrameType.padding),
        @intFromEnum(frame.FrameType.padding),
    };
    const protected = try protection.protectShortPacketAes128(std.testing.allocator, .{
        .dcid = &server_dcid,
        .spin_bit = true,
        .key_phase = false,
        .packet_number = 0,
    }, try packet.encodePacketNumberForHeader(0, null), secrets.client, &plaintext);
    defer std.testing.allocator.free(protected);
    try std.testing.expect(try protection.peekShortPacketSpinBit(protected));

    var disabled_server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer disabled_server.deinit();
    try disabled_server.processProtectedShortDatagram(10, secrets.client, server_dcid.len, protected);
    try std.testing.expect(!disabled_server.nextOutgoingSpinBit());

    var enabled_server = try QuicConnection.init(std.testing.allocator, .server, .{ .enable_spin_bit = true });
    defer enabled_server.deinit();
    var tampered = try std.testing.allocator.dupe(u8, protected);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;
    try std.testing.expectError(
        error.InvalidPacket,
        enabled_server.processProtectedShortDatagram(11, secrets.client, server_dcid.len, tampered),
    );
    try std.testing.expect(!enabled_server.nextOutgoingSpinBit());

    try enabled_server.processProtectedShortDatagram(12, secrets.client, server_dcid.len, protected);
    try std.testing.expect(enabled_server.nextOutgoingSpinBit());
}

test "protected short datagram key update selects next key phase" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);
    const next_client_keys = protection.nextAes128PacketProtectionKeys(secrets.client);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try client.sendPing();
    const protected = (try client.pollProtectedShortDatagramWithKeyPhase(
        10,
        &server_dcid,
        next_client_keys,
        true,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);
    try std.testing.expectEqual(@as(u64, 1), client.nextPacketNumber(.application));
    try std.testing.expect(try protection.peekShortPacketKeyPhaseAes128(secrets.client.hp, protected, server_dcid.len));

    var rejecting_server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer rejecting_server.deinit();
    try std.testing.expectError(
        error.InvalidPacket,
        rejecting_server.processProtectedShortDatagram(11, secrets.client, server_dcid.len, protected),
    );
    try std.testing.expectEqual(@as(u64, 0), rejecting_server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, null), rejecting_server.pendingAckLargest(.application));

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.processProtectedShortDatagramWithKeyUpdate(12, .{
        .current = secrets.client,
        .next = next_client_keys,
        .current_key_phase = false,
    }, server_dcid.len, protected);
    try std.testing.expectEqual(@as(u64, 1), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.application));
}

test "protected short datagram key phase state advances after successful receive" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client_send_state = protection.Aes128KeyPhaseState.init(secrets.client, false);
    var server_recv_state = protection.Aes128KeyPhaseState.init(secrets.client, false);
    client_send_state.initiateKeyUpdate();

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try client.sendPing();
    const protected = (try client.pollProtectedShortDatagramWithKeyPhaseState(
        10,
        &server_dcid,
        &client_send_state,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);
    try std.testing.expect(try protection.peekShortPacketKeyPhaseAes128(secrets.client.hp, protected, server_dcid.len));

    var tampered = try std.testing.allocator.dupe(u8, protected);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try std.testing.expectError(
        error.InvalidPacket,
        server.processProtectedShortDatagramWithKeyPhaseState(11, &server_recv_state, server_dcid.len, tampered),
    );
    try std.testing.expect(!server_recv_state.currentKeyPhase());
    try std.testing.expectEqual(@as(u64, 0), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));

    try server.processProtectedShortDatagramWithKeyPhaseState(12, &server_recv_state, server_dcid.len, protected);
    try std.testing.expect(server_recv_state.currentKeyPhase());
    try std.testing.expectEqual(@as(u64, 1), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.application));
}

test "driveCryptoBackendInSpace installs handshake traffic secrets for long packet exchange" {
    const SecretBackend = struct {
        secrets: HandshakeTrafficSecrets,
        sent: bool = false,

        fn backend(self: *@This()) CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
                .pull_handshake_traffic_secrets = pullHandshakeTrafficSecrets,
            };
        }

        fn receive(_: *anyopaque, _: PacketNumberSpace, _: []const u8) Error!void {}

        fn pull(_: *anyopaque, _: PacketNumberSpace, _: []u8) Error!?[]const u8 {
            return null;
        }

        fn pullHandshakeTrafficSecrets(context: *anyopaque) Error!?HandshakeTrafficSecrets {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.sent) return null;
            self.sent = true;
            return self.secrets;
        }
    };

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    var client_backend = SecretBackend{ .secrets = .{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    } };
    var server_backend = SecretBackend{ .secrets = .{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    } };
    var scratch: [8]u8 = undefined;
    const client_progress = try client.driveCryptoBackendInSpace(.handshake, client_backend.backend(), &scratch);
    const server_progress = try server.driveCryptoBackendInSpace(.handshake, server_backend.backend(), &scratch);
    try std.testing.expect(client_progress.handshake_keys_installed);
    try std.testing.expect(server_progress.handshake_keys_installed);
    try std.testing.expect(!client_progress.one_rtt_keys_installed);
    try std.testing.expect(client.hasHandshakeProtectionKeys());
    try std.testing.expect(server.hasHandshakeProtectionKeys());

    try server.sendCryptoInSpace(.handshake, "server handshake");
    const protected = (try server.pollProtectedHandshakeDatagramWithInstalledKeys(
        10,
        &client_scid,
        &server_scid,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);

    var tampered = try std.testing.allocator.dupe(u8, protected);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;
    try std.testing.expectError(
        error.InvalidPacket,
        client.processProtectedHandshakeDatagramWithInstalledKeys(11, tampered),
    );
    try std.testing.expectEqual(@as(u64, 0), client.nextPeerPacketNumber(.handshake));
    try std.testing.expectEqual(@as(?u64, null), client.pendingAckLargest(.handshake));

    try client.processProtectedHandshakeDatagramWithInstalledKeys(12, protected);
    var crypto_buf: [64]u8 = undefined;
    const recv_len = (try client.recvCryptoInSpace(.handshake, &crypto_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("server handshake", crypto_buf[0..recv_len]);
    try std.testing.expectEqual(@as(u64, 1), client.nextPeerPacketNumber(.handshake));
    try std.testing.expectEqual(@as(?u64, 0), client.pendingAckLargest(.handshake));

    const ack = (try client.pollProtectedHandshakeDatagramWithInstalledKeys(
        13,
        &server_scid,
        &client_scid,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(ack);
    try server.processProtectedHandshakeDatagramWithInstalledKeys(14, ack);
    try std.testing.expectEqual(@as(usize, 0), server.bytesInFlight(.handshake));
}

test "driveCryptoBackendInSpace installs one RTT traffic secrets for short packet exchange" {
    const SecretBackend = struct {
        secrets: OneRttTrafficSecrets,
        sent: bool = false,

        fn backend(self: *@This()) CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
                .pull_1rtt_traffic_secrets = pullOneRttTrafficSecrets,
            };
        }

        fn receive(_: *anyopaque, _: PacketNumberSpace, _: []const u8) Error!void {}

        fn pull(_: *anyopaque, _: PacketNumberSpace, _: []u8) Error!?[]const u8 {
            return null;
        }

        fn pullOneRttTrafficSecrets(context: *anyopaque) Error!?OneRttTrafficSecrets {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.sent) return null;
            self.sent = true;
            return self.secrets;
        }
    };

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    var client_backend = SecretBackend{ .secrets = .{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    } };
    var server_backend = SecretBackend{ .secrets = .{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    } };
    var scratch: [8]u8 = undefined;
    const client_progress = try client.driveCryptoBackendInSpace(.handshake, client_backend.backend(), &scratch);
    const server_progress = try server.driveCryptoBackendInSpace(.handshake, server_backend.backend(), &scratch);
    try std.testing.expect(client_progress.one_rtt_keys_installed);
    try std.testing.expect(server_progress.one_rtt_keys_installed);
    try std.testing.expect(client.hasOneRttProtectionKeys());
    try std.testing.expect(server.hasOneRttProtectionKeys());
    try std.testing.expectEqual(@as(?bool, false), client.localOneRttKeyPhase());
    try std.testing.expectEqual(@as(?bool, false), server.peerOneRttKeyPhase());

    try client.sendPing();
    const client_ping = (try client.pollProtectedShortDatagramWithInstalledKeys(
        10,
        &server_dcid,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(client_ping);
    try server.processProtectedShortDatagramWithInstalledKeys(11, server_dcid.len, client_ping);
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.application));

    const server_ack = (try server.pollProtectedShortDatagramWithInstalledKeys(
        12,
        &client_dcid,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(server_ack);
    try client.processProtectedShortDatagramWithInstalledKeys(13, client_dcid.len, server_ack);
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight(.application));
}

test "installed one RTT key phase state advances only after successful receive" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    try client.installOneRttTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });
    try server.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try client.confirmHandshake();
    try server.confirmHandshake();

    try client.initiateOneRttKeyUpdate();
    try std.testing.expectEqual(@as(?bool, true), client.localOneRttKeyPhase());
    try client.sendPing();
    const protected = (try client.pollProtectedShortDatagramWithInstalledKeys(
        10,
        &server_dcid,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);
    try std.testing.expect(try protection.peekShortPacketKeyPhaseAes128(secrets.client.hp, protected, server_dcid.len));

    var tampered = try std.testing.allocator.dupe(u8, protected);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;

    try std.testing.expectError(
        error.InvalidPacket,
        server.processProtectedShortDatagramWithInstalledKeys(11, server_dcid.len, tampered),
    );
    try std.testing.expectEqual(@as(?bool, false), server.peerOneRttKeyPhase());
    try std.testing.expectEqual(@as(u64, 0), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));

    try server.processProtectedShortDatagramWithInstalledKeys(12, server_dcid.len, protected);
    try std.testing.expectEqual(@as(?bool, true), server.peerOneRttKeyPhase());
    try std.testing.expectEqual(@as(u64, 1), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.application));
}

test "installed one RTT key update requires handshake confirmation and ACK before next update" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    try client.installOneRttTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });
    try server.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });

    try std.testing.expectError(error.InvalidPacket, client.initiateOneRttKeyUpdate());
    try client.confirmHandshake();
    try server.confirmHandshake();
    try client.initiateOneRttKeyUpdate();
    try std.testing.expectEqual(@as(?bool, true), client.localOneRttKeyPhase());
    try std.testing.expectError(error.InvalidPacket, client.initiateOneRttKeyUpdate());

    try client.sendPing();
    const ping = (try client.pollProtectedShortDatagramWithInstalledKeys(
        10,
        &server_dcid,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(ping);
    try server.processProtectedShortDatagramWithInstalledKeys(11, server_dcid.len, ping);
    const ack = (try server.pollProtectedShortDatagramWithInstalledKeys(
        12,
        &client_dcid,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(ack);
    try client.processProtectedShortDatagramWithInstalledKeys(13, client_dcid.len, ack);

    try client.initiateOneRttKeyUpdate();
    try std.testing.expectEqual(@as(?bool, false), client.localOneRttKeyPhase());
}

test "installed one RTT key update ACK confirmation rolls back with invalid payload" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try client.installOneRttTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });
    try client.confirmHandshake();
    try client.initiateOneRttKeyUpdate();
    _ = try client.recordPacketSentInSpace(.application, 10, 100);

    var payload: [32]u8 = undefined;
    var out = buffer.fixedWriter(&payload);
    try frame.encodeFrame(out.writer(), .{ .ack = .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    } });
    try out.writeByte(0xff);
    try std.testing.expectError(error.InvalidPacket, client.processDatagramForPacketType(.one_rtt, 20, out.getWritten()));
    try std.testing.expectError(error.InvalidPacket, client.initiateOneRttKeyUpdate());
    try std.testing.expectEqual(@as(usize, 1), client.sent_packets.items.len);

    out = buffer.fixedWriter(&payload);
    try frame.encodeFrame(out.writer(), .{ .ack = .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    } });
    try client.processDatagramForPacketType(.one_rtt, 21, out.getWritten());
    try client.initiateOneRttKeyUpdate();
}

test "processProtectedShortDatagram rejects invalid short packets without mutation" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);
    const plaintext = [_]u8{
        @intFromEnum(frame.FrameType.ping),
        @intFromEnum(frame.FrameType.padding),
        @intFromEnum(frame.FrameType.padding),
        @intFromEnum(frame.FrameType.padding),
    };

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    const wrong_packet_number = try protection.protectShortPacketAes128(std.testing.allocator, .{
        .dcid = &server_dcid,
        .spin_bit = false,
        .key_phase = false,
        .packet_number = 1,
    }, try packet.encodePacketNumberForHeader(1, null), secrets.client, &plaintext);
    defer std.testing.allocator.free(wrong_packet_number);

    try std.testing.expectError(
        error.InvalidPacket,
        server.processProtectedShortDatagram(10, secrets.client, server_dcid.len, wrong_packet_number),
    );
    try std.testing.expectEqual(@as(u64, 0), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));

    const tampered = try protection.protectShortPacketAes128(std.testing.allocator, .{
        .dcid = &server_dcid,
        .spin_bit = false,
        .key_phase = false,
        .packet_number = 0,
    }, try packet.encodePacketNumberForHeader(0, null), secrets.client, &plaintext);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;

    try std.testing.expectError(
        error.InvalidPacket,
        server.processProtectedShortDatagram(11, secrets.client, server_dcid.len, tampered),
    );
    try std.testing.expectEqual(@as(u64, 0), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));
}

test "pollProtectedShortDatagram emits protected PING and ACK-only response" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    try client.sendPing();
    const client_ping = (try client.pollProtectedShortDatagram(10, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(client_ping);
    try std.testing.expectEqual(@as(u64, 1), client.nextPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.application));
    try std.testing.expectEqual(client_ping.len, client.bytesInFlight(.application));

    try server.processProtectedShortDatagram(11, secrets.client, server_dcid.len, client_ping);
    try std.testing.expectEqual(@as(u64, 1), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.application));

    const server_ack = (try server.pollProtectedShortDatagram(12, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(server_ack);
    try std.testing.expectEqual(@as(u64, 1), server.nextPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), server.bytesInFlight(.application));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));

    try client.processProtectedShortDatagram(13, secrets.server, client_dcid.len, server_ack);
    try std.testing.expectEqual(@as(u64, 1), client.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight(.application));
    try std.testing.expectEqual(@as(?u64, null), client.pendingAckLargest(.application));
}

test "pollProtectedShortDatagram emits protected STREAM and ACK response" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello protected", true);

    const client_stream = (try client.pollProtectedShortDatagram(10, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(client_stream);
    try std.testing.expectEqual(@as(u64, 1), client.nextPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.application));
    try std.testing.expectEqual(client_stream.len, client.bytesInFlight(.application));
    try std.testing.expectEqual(@as(?[]u8, null), try client.pollProtectedShortDatagram(11, &server_dcid, secrets.client));

    try server.processProtectedShortDatagram(12, secrets.client, server_dcid.len, client_stream);
    var recv_buf: [32]u8 = undefined;
    const recv_len = (try server.recvOnStream(stream_id, &recv_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("hello protected", recv_buf[0..recv_len]);
    try std.testing.expectEqual(@as(u64, 1), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.application));

    server.pending_max_frames.items.len = 0;
    const server_ack = (try server.pollProtectedShortDatagram(13, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(server_ack);
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), server.bytesInFlight(.application));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));

    try client.processProtectedShortDatagram(14, secrets.server, client_dcid.len, server_ack);
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight(.application));
    try std.testing.expectEqual(@as(?u64, null), client.pendingAckLargest(.application));
}

test "pollProtectedShortDatagram emits protected CRYPTO and ACK response" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    try client.sendCrypto("application crypto");
    const client_crypto = (try client.pollProtectedShortDatagram(10, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(client_crypto);
    try std.testing.expectEqual(@as(u64, 1), client.nextPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.application));
    try std.testing.expectEqual(client_crypto.len, client.bytesInFlight(.application));
    try std.testing.expectEqual(@as(?[]u8, null), try client.pollProtectedShortDatagram(11, &server_dcid, secrets.client));

    try server.processProtectedShortDatagram(12, secrets.client, server_dcid.len, client_crypto);
    var crypto_buf: [32]u8 = undefined;
    const crypto_len = (try server.recvCrypto(&crypto_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("application crypto", crypto_buf[0..crypto_len]);
    try std.testing.expectEqual(@as(u64, 1), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.application));

    const server_ack = (try server.pollProtectedShortDatagram(13, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(server_ack);
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), server.bytesInFlight(.application));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));

    try client.processProtectedShortDatagram(14, secrets.server, client_dcid.len, server_ack);
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight(.application));
    try std.testing.expectEqual(@as(?u64, null), client.pendingAckLargest(.application));
}

test "ACK-driven loss requeues protected short CRYPTO frame for retransmission" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    try client.sendCrypto("lost protected crypto");
    const protected = (try client.pollProtectedShortDatagram(
        10,
        &server_dcid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(protected);
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.crypto_send_queue.items.len);
    try std.testing.expect(client.sent_packets.items[0].crypto_frame != null);

    _ = try client.recordPacketSentInSpace(.application, 20, 1);
    _ = try client.recordPacketSentInSpace(.application, 30, 1);
    _ = try client.recordPacketSentInSpace(.application, 40, 1);
    try client.receiveAckInSpace(.application, 70, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    try std.testing.expectEqual(@as(usize, 2), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 1), client.crypto_send_queue.items.len);
    try std.testing.expectEqual(@as(u64, 0), client.crypto_send_queue.items[0].offset);
    try std.testing.expectEqualStrings("lost protected crypto", client.crypto_send_queue.items[0].data);

    const retransmit = (try client.pollProtectedShortDatagram(
        80,
        &server_dcid,
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(retransmit);

    var opened = try protection.unprotectShortPacketAes128(std.testing.allocator, secrets.client, retransmit, server_dcid.len, 4);
    defer protection.deinitProtectedShortPacket(&opened, std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 4), opened.packet.header.packet_number);

    var decoded = try frame.decodeFrameSlice(opened.packet.plaintext, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .crypto => |crypto| {
            try std.testing.expectEqual(@as(u64, 0), crypto.offset);
            try std.testing.expectEqualStrings("lost protected crypto", crypto.data);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "pollProtectedShortDatagram preserves STREAM when anti-amplification blocks" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    const stream_id = try server.openStream();
    try server.sendOnStream(stream_id, "blocked first", true);

    try std.testing.expectEqual(
        @as(?[]u8, null),
        try server.pollProtectedShortDatagram(10, &client_dcid, secrets.server),
    );
    try std.testing.expectEqual(@as(u64, 0), server.nextPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.application));

    try server.validatePeerAddress();
    const server_stream = (try server.pollProtectedShortDatagram(11, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(server_stream);
    try std.testing.expectEqual(@as(u64, 1), server.nextPacketNumber(.application));
    try std.testing.expectEqual(server_stream.len, server.bytesInFlight(.application));

    try client.processProtectedShortDatagram(12, secrets.server, client_dcid.len, server_stream);
    var recv_buf: [32]u8 = undefined;
    const recv_len = (try client.recvOnStream(stream_id, &recv_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("blocked first", recv_buf[0..recv_len]);
}

test "pollProtectedShortDatagram preserves CRYPTO when anti-amplification blocks" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    try server.sendCrypto("blocked crypto");

    try std.testing.expectEqual(
        @as(?[]u8, null),
        try server.pollProtectedShortDatagram(10, &client_dcid, secrets.server),
    );
    try std.testing.expectEqual(@as(u64, 0), server.nextPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.application));

    try server.validatePeerAddress();
    const server_crypto = (try server.pollProtectedShortDatagram(11, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(server_crypto);
    try std.testing.expectEqual(@as(u64, 1), server.nextPacketNumber(.application));
    try std.testing.expectEqual(server_crypto.len, server.bytesInFlight(.application));

    try client.processProtectedShortDatagram(12, secrets.server, client_dcid.len, server_crypto);
    var crypto_buf: [32]u8 = undefined;
    const crypto_len = (try client.recvCrypto(&crypto_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("blocked crypto", crypto_buf[0..crypto_len]);
}

test "pollProtectedShortDatagram emits protected PATH_CHALLENGE and PATH_RESPONSE" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    const challenge_data = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };
    try client.sendPathChallenge(challenge_data);
    const challenge = (try client.pollProtectedShortDatagram(10, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(challenge);
    try std.testing.expectEqual(@as(usize, 0), client.pending_path_challenges.items.len);
    try std.testing.expectEqual(@as(usize, 1), client.outstanding_path_challenges.items.len);
    try std.testing.expectEqualSlices(u8, &challenge_data, &client.outstanding_path_challenges.items[0].data);
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.application));
    try std.testing.expectEqual(challenge.len, client.bytesInFlight(.application));

    try server.processProtectedShortDatagram(11, secrets.client, server_dcid.len, challenge);
    try std.testing.expectEqual(@as(usize, 1), server.pending_path_responses.items.len);
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.application));

    const response = (try server.pollProtectedShortDatagram(12, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(response);
    try std.testing.expectEqual(@as(usize, 0), server.pending_path_responses.items.len);
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));
    try std.testing.expectEqual(@as(usize, 1), server.sentPacketCount(.application));
    try std.testing.expectEqual(response.len, server.bytesInFlight(.application));

    try client.processProtectedShortDatagram(13, secrets.server, client_dcid.len, response);
    try std.testing.expectEqual(@as(usize, 0), client.outstanding_path_challenges.items.len);
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight(.application));
    try std.testing.expectEqual(@as(?u64, 0), client.pendingAckLargest(.application));

    const ack = (try client.pollProtectedShortDatagram(14, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(ack);
    try std.testing.expectEqual(@as(?u64, null), client.pendingAckLargest(.application));
    try server.processProtectedShortDatagram(15, secrets.client, server_dcid.len, ack);
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), server.bytesInFlight(.application));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));
}

test "endpoint route path update follows protected PATH_RESPONSE validation" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const old_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 50_000),
    };
    const new_path = endpoint.Udp4Tuple{
        .local = old_path.local,
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 50_001),
    };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var router = endpoint.EndpointRouter.init(std.testing.allocator);
    defer router.deinit();
    try router.registerConnectionId(19, &server_dcid, old_path, .{});

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try server.validatePeerAddress();

    const challenge_data = [_]u8{ 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb };
    try server.sendPathChallenge(challenge_data);
    const challenge = (try server.pollProtectedShortDatagram(10, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(challenge);
    try client.processProtectedShortDatagram(11, secrets.server, client_dcid.len, challenge);

    const response = (try client.pollProtectedShortDatagram(12, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(response);
    const migrated_route = try router.routeDatagram(new_path, response);
    try std.testing.expectEqual(@as(u64, 19), migrated_route.connection_id);
    try std.testing.expect(migrated_route.path_changed);

    try server.processProtectedShortDatagram(13, secrets.client, server_dcid.len, response);
    try std.testing.expectEqual(@as(usize, 0), server.outstandingPathChallengeCount());

    const updated = try router.updateRoutePath(&server_dcid, old_path, new_path);
    try std.testing.expectEqual(@as(u64, 19), updated.connection_id);
    try std.testing.expect(!updated.path_changed);

    const confirmed_route = try router.routeDatagram(new_path, response);
    try std.testing.expectEqual(@as(u64, 19), confirmed_route.connection_id);
    try std.testing.expect(!confirmed_route.path_changed);
    try std.testing.expectError(error.PathMismatch, router.updateRoutePath(&server_dcid, old_path, old_path));
}

test "pollProtectedShortDatagram preserves PATH_CHALLENGE when anti-amplification blocks" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    const challenge_data = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 };
    try server.sendPathChallenge(challenge_data);

    try std.testing.expectEqual(
        @as(?[]u8, null),
        try server.pollProtectedShortDatagram(10, &client_dcid, secrets.server),
    );
    try std.testing.expectEqual(@as(u64, 0), server.nextPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 1), server.pending_path_challenges.items.len);
    try std.testing.expectEqual(@as(usize, 0), server.outstanding_path_challenges.items.len);
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.application));

    try server.validatePeerAddress();
    const challenge = (try server.pollProtectedShortDatagram(11, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(challenge);
    try std.testing.expectEqual(@as(usize, 0), server.pending_path_challenges.items.len);
    try std.testing.expectEqual(@as(usize, 1), server.outstanding_path_challenges.items.len);
    try std.testing.expectEqualSlices(u8, &challenge_data, &server.outstanding_path_challenges.items[0].data);
    try std.testing.expectEqual(@as(u64, 1), server.nextPacketNumber(.application));

    try client.processProtectedShortDatagram(12, secrets.server, client_dcid.len, challenge);
    try std.testing.expectEqual(@as(usize, 1), client.pending_path_responses.items.len);
    try std.testing.expectEqual(@as(?u64, 0), client.pendingAckLargest(.application));
}

test "pollProtectedShortDatagram emits protected NEW_CONNECTION_ID and RETIRE_CONNECTION_ID" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    const cid0 = [_]u8{ 0xc0, 0xff, 0xee, 0x00 };
    const cid1 = [_]u8{ 0xc0, 0xff, 0xee, 0x01 };
    const token0 = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const token1 = [_]u8{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

    try std.testing.expectEqual(@as(u64, 0), try server.issueConnectionId(&cid0, token0, 0));
    const new0 = (try server.pollProtectedShortDatagram(10, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(new0);
    try std.testing.expect(server.local_connection_ids.items[0].sent);
    try std.testing.expectEqual(@as(usize, 0), server.pendingNewConnectionIdCount());
    try std.testing.expectEqual(new0.len, server.bytesInFlight(.application));

    try client.processProtectedShortDatagram(11, secrets.server, client_dcid.len, new0);
    try std.testing.expectEqual(@as(usize, 1), client.active_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 1), client.activeConnectionIdCount());
    try std.testing.expectEqual(@as(?u64, 0), client.pendingAckLargest(.application));

    const ack0 = (try client.pollProtectedShortDatagram(12, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(ack0);
    try server.processProtectedShortDatagram(13, secrets.client, server_dcid.len, ack0);
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), server.bytesInFlight(.application));

    try std.testing.expectEqual(@as(u64, 1), try server.issueConnectionId(&cid1, token1, 1));
    const new1 = (try server.pollProtectedShortDatagram(14, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(new1);
    try std.testing.expect(server.local_connection_ids.items[1].sent);
    try client.processProtectedShortDatagram(15, secrets.server, client_dcid.len, new1);
    try std.testing.expectEqual(@as(usize, 2), client.active_connection_ids.items.len);
    try std.testing.expect(client.active_connection_ids.items[0].retired);
    try std.testing.expect(!client.active_connection_ids.items[1].retired);
    try std.testing.expectEqual(@as(usize, 1), client.pending_retire_connection_ids.items.len);
    try std.testing.expectEqual(@as(?u64, 1), client.pendingAckLargest(.application));

    const retire = (try client.pollProtectedShortDatagram(16, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(retire);
    try std.testing.expectEqual(@as(usize, 0), client.pending_retire_connection_ids.items.len);
    try std.testing.expectEqual(@as(?u64, null), client.pendingAckLargest(.application));

    try server.processProtectedShortDatagram(17, secrets.client, server_dcid.len, retire);
    try std.testing.expect(server.local_connection_ids.items[0].retired);
    try std.testing.expectEqual(@as(u64, 1), server.localConnectionIdCount());
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), server.bytesInFlight(.application));
    try std.testing.expectEqual(@as(?u64, 1), server.pendingAckLargest(.application));

    const ack1 = (try server.pollProtectedShortDatagram(18, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(ack1);
    try client.processProtectedShortDatagram(19, secrets.server, client_dcid.len, ack1);
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight(.application));
}

test "pollProtectedShortDatagram preserves NEW_CONNECTION_ID when anti-amplification blocks" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    const cid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    try std.testing.expectEqual(@as(u64, 0), try server.issueConnectionId(&cid, token, 0));

    try std.testing.expectEqual(
        @as(?[]u8, null),
        try server.pollProtectedShortDatagram(10, &client_dcid, secrets.server),
    );
    try std.testing.expectEqual(@as(u64, 0), server.nextPacketNumber(.application));
    try std.testing.expect(!server.local_connection_ids.items[0].sent);
    try std.testing.expectEqual(@as(usize, 1), server.pendingNewConnectionIdCount());
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.application));

    try server.validatePeerAddress();
    const new_id = (try server.pollProtectedShortDatagram(11, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(new_id);
    try std.testing.expect(server.local_connection_ids.items[0].sent);
    try std.testing.expectEqual(@as(u64, 1), server.nextPacketNumber(.application));

    try client.processProtectedShortDatagram(12, secrets.server, client_dcid.len, new_id);
    try std.testing.expectEqual(@as(usize, 1), client.active_connection_ids.items.len);
    try std.testing.expectEqualSlices(u8, &cid, client.active_connection_ids.items[0].connection_id);
}

test "pollProtectedShortDatagram emits protected MAX_DATA and MAX_STREAM_DATA" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

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
    try client.sendOnStream(stream_id, "hello", false);
    const client_stream = (try client.pollProtectedShortDatagram(10, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(client_stream);

    try server.processProtectedShortDatagram(11, secrets.client, server_dcid.len, client_stream);
    var read_buf: [8]u8 = undefined;
    const read_len = (try server.recvOnStream(stream_id, &read_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("hello", read_buf[0..read_len]);
    try std.testing.expectEqual(@as(usize, 2), server.pending_max_frames.items.len);

    const max_data = (try server.pollProtectedShortDatagram(12, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(max_data);
    try std.testing.expectEqual(@as(usize, 1), server.pending_max_frames.items.len);
    try client.processProtectedShortDatagram(13, secrets.server, client_dcid.len, max_data);
    try std.testing.expectEqual(@as(u64, 10), client.peer_max_data);

    const max_stream_data = (try server.pollProtectedShortDatagram(14, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(max_stream_data);
    try std.testing.expectEqual(@as(usize, 0), server.pending_max_frames.items.len);
    try client.processProtectedShortDatagram(15, secrets.server, client_dcid.len, max_stream_data);
    try std.testing.expectEqual(@as(u64, 10), client.findSendStream(stream_id).?.max_data);

    try client.sendOnStream(stream_id, "!", true);
}

test "pollProtectedShortDatagram emits protected BLOCKED frames" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var data_client = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 16,
    });
    defer data_client.deinit();
    var data_server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer data_server.deinit();
    const data_stream = try data_client.openStream();
    try data_client.sendOnStream(data_stream, "hello", false);
    try std.testing.expectError(error.FlowControlBlocked, data_client.sendOnStream(data_stream, "!", false));

    const data_blocked = (try data_client.pollProtectedShortDatagram(10, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(data_blocked);
    try std.testing.expectEqual(@as(usize, 0), data_client.pending_blocked_frames.items.len);
    try data_server.processProtectedShortDatagram(11, secrets.client, server_dcid.len, data_blocked);
    try std.testing.expectEqual(@as(?u64, 5), data_server.peerDataBlockedLimit());

    var stream_client = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 16,
        .initial_max_stream_data = 5,
    });
    defer stream_client.deinit();
    var stream_server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer stream_server.deinit();
    const stream_id = try stream_client.openStream();
    try stream_client.sendOnStream(stream_id, "hello", false);
    try std.testing.expectError(error.FlowControlBlocked, stream_client.sendOnStream(stream_id, "!", false));

    const stream_blocked = (try stream_client.pollProtectedShortDatagram(10, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(stream_blocked);
    try std.testing.expectEqual(@as(usize, 0), stream_client.pending_blocked_frames.items.len);
    try stream_server.processProtectedShortDatagram(11, secrets.client, server_dcid.len, stream_blocked);
    try std.testing.expectEqual(@as(?u64, 5), stream_server.peerStreamDataBlockedLimit(stream_id));

    var bidi_client = try QuicConnection.init(std.testing.allocator, .client, .{ .initial_max_streams_bidi = 1 });
    defer bidi_client.deinit();
    var bidi_server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer bidi_server.deinit();
    _ = try bidi_client.openStream();
    try std.testing.expectError(error.FlowControlBlocked, bidi_client.openStream());

    const bidi_blocked = (try bidi_client.pollProtectedShortDatagram(10, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(bidi_blocked);
    try std.testing.expectEqual(@as(usize, 0), bidi_client.pending_blocked_frames.items.len);
    try bidi_server.processProtectedShortDatagram(11, secrets.client, server_dcid.len, bidi_blocked);
    try std.testing.expectEqual(@as(?u64, 1), bidi_server.peerStreamsBlockedBidiLimit());

    var uni_client = try QuicConnection.init(std.testing.allocator, .client, .{ .initial_max_streams_uni = 1 });
    defer uni_client.deinit();
    var uni_server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer uni_server.deinit();
    _ = try uni_client.openUniStream();
    try std.testing.expectError(error.FlowControlBlocked, uni_client.openUniStream());

    const uni_blocked = (try uni_client.pollProtectedShortDatagram(10, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(uni_blocked);
    try std.testing.expectEqual(@as(usize, 0), uni_client.pending_blocked_frames.items.len);
    try uni_server.processProtectedShortDatagram(11, secrets.client, server_dcid.len, uni_blocked);
    try std.testing.expectEqual(@as(?u64, 1), uni_server.peerStreamsBlockedUniLimit());
}

test "pollProtectedShortDatagram preserves MAX and BLOCKED frames when anti-amplification blocks" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var max_server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer max_server.deinit();
    try max_server.queueMaxDataFrame(max_server.recv_max_data);

    try std.testing.expectEqual(
        @as(?[]u8, null),
        try max_server.pollProtectedShortDatagram(10, &client_dcid, secrets.server),
    );
    try std.testing.expectEqual(@as(usize, 1), max_server.pending_max_frames.items.len);
    try std.testing.expectEqual(@as(u64, 0), max_server.nextPacketNumber(.application));

    try max_server.validatePeerAddress();
    const max_frame = (try max_server.pollProtectedShortDatagram(11, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(max_frame);
    try std.testing.expectEqual(@as(usize, 0), max_server.pending_max_frames.items.len);
    try std.testing.expectEqual(@as(u64, 1), max_server.nextPacketNumber(.application));

    var blocked_server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer blocked_server.deinit();
    try blocked_server.queueDataBlockedFrame(blocked_server.peer_max_data);

    try std.testing.expectEqual(
        @as(?[]u8, null),
        try blocked_server.pollProtectedShortDatagram(10, &client_dcid, secrets.server),
    );
    try std.testing.expectEqual(@as(usize, 1), blocked_server.pending_blocked_frames.items.len);
    try std.testing.expectEqual(@as(u64, 0), blocked_server.nextPacketNumber(.application));

    try blocked_server.validatePeerAddress();
    const blocked_frame = (try blocked_server.pollProtectedShortDatagram(11, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(blocked_frame);
    try std.testing.expectEqual(@as(usize, 0), blocked_server.pending_blocked_frames.items.len);
    try std.testing.expectEqual(@as(u64, 1), blocked_server.nextPacketNumber(.application));
}

test "pollProtectedShortDatagram emits protected RESET_STREAM and ACK response" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello", false);
    try client.resetStream(stream_id, 7);

    const client_reset = (try client.pollProtectedShortDatagram(10, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(client_reset);
    try std.testing.expectEqual(@as(usize, 0), client.pending_reset_streams.items.len);
    try std.testing.expectEqual(@as(usize, 1), client.sentPacketCount(.application));
    try std.testing.expectEqual(client_reset.len, client.bytesInFlight(.application));

    try server.processProtectedShortDatagram(11, secrets.client, server_dcid.len, client_reset);
    var recv_buf: [16]u8 = undefined;
    try std.testing.expectError(error.StreamClosed, server.recvOnStream(stream_id, &recv_buf));
    try std.testing.expectEqual(@as(?u64, 5), try server.recvStreamFinalSize(stream_id));
    try std.testing.expectEqual(@as(?u64, 0), server.pendingAckLargest(.application));

    try std.testing.expectEqual(@as(?[]u8, null), try client.pollProtectedShortDatagram(12, &server_dcid, secrets.client));
    try std.testing.expectEqual(@as(usize, 0), client.send_queue.items.len);

    const server_ack = (try server.pollProtectedShortDatagram(13, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(server_ack);
    try client.processProtectedShortDatagram(14, secrets.server, client_dcid.len, server_ack);
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight(.application));
}

test "pollProtectedShortDatagram emits protected STOP_SENDING and RESET_STREAM response" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello", false);

    const client_stream = (try client.pollProtectedShortDatagram(10, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(client_stream);
    try server.processProtectedShortDatagram(11, secrets.client, server_dcid.len, client_stream);

    try server.stopSending(stream_id, 23);
    const server_stop = (try server.pollProtectedShortDatagram(12, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(server_stop);
    try client.processProtectedShortDatagram(13, secrets.server, client_dcid.len, server_stop);
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 1), client.pending_reset_streams.items.len);

    const client_reset = (try client.pollProtectedShortDatagram(14, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(client_reset);
    try std.testing.expectEqual(@as(usize, 0), client.pending_reset_streams.items.len);
    try std.testing.expectEqual(@as(?u64, null), client.pendingAckLargest(.application));

    try server.processProtectedShortDatagram(15, secrets.client, server_dcid.len, client_reset);
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.application));
    var recv_buf: [16]u8 = undefined;
    try std.testing.expectError(error.StreamClosed, server.recvOnStream(stream_id, &recv_buf));
    try std.testing.expectEqual(@as(?u64, 5), try server.recvStreamFinalSize(stream_id));
    try std.testing.expectEqual(@as(?u64, 1), server.pendingAckLargest(.application));

    const server_ack = (try server.pollProtectedShortDatagram(16, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(server_ack);
    try client.processProtectedShortDatagram(17, secrets.server, client_dcid.len, server_ack);
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight(.application));
}

test "pollProtectedShortDatagram drops obsolete STOP_SENDING after RESET_STREAM" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "hello", false);
    const client_stream = (try client.pollProtectedShortDatagram(10, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(client_stream);
    try server.processProtectedShortDatagram(11, secrets.client, server_dcid.len, client_stream);

    try server.stopSending(stream_id, 23);
    try std.testing.expectEqual(@as(usize, 1), server.pending_stop_sending.items.len);
    try client.resetStream(stream_id, 23);

    const client_reset = (try client.pollProtectedShortDatagram(12, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(client_reset);
    try server.processProtectedShortDatagram(13, secrets.client, server_dcid.len, client_reset);
    try std.testing.expectEqual(@as(usize, 1), server.pending_stop_sending.items.len);

    const server_ack = (try server.pollProtectedShortDatagram(14, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(server_ack);
    try std.testing.expectEqual(@as(usize, 0), server.pending_stop_sending.items.len);
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.application));

    try client.processProtectedShortDatagram(15, secrets.server, client_dcid.len, server_ack);
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight(.application));
}

test "sendHandshakeDone and issueNewToken validate server-only queues" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.installHandshakeTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try server.sendCryptoInSpace(.handshake, "discarded handshake");
    try std.testing.expect(server.hasHandshakeProtectionKeys());

    try std.testing.expectError(error.InvalidPacket, client.sendHandshakeDone());
    try std.testing.expectError(error.InvalidPacket, client.issueNewToken("future"));
    try std.testing.expectError(error.InvalidPacket, server.issueNewToken(""));

    try server.sendHandshakeDone();
    try std.testing.expect(server.handshakeConfirmed());
    try std.testing.expectEqual(HandshakeState.confirmed, server.handshakeState());
    try std.testing.expect(server.packetNumberSpaceDiscarded(.handshake));
    try std.testing.expect(!server.hasHandshakeProtectionKeys());
    try std.testing.expectError(error.InvalidPacket, server.sendCryptoInSpace(.handshake, "late"));
    try std.testing.expectError(error.InvalidPacket, server.installHandshakeTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    }));
    try std.testing.expect(server.pending_handshake_done);
    try server.sendHandshakeDone();
    try std.testing.expect(server.pending_handshake_done);

    try server.issueNewToken("future");
    try std.testing.expectEqual(@as(usize, 1), server.pending_new_tokens.items.len);
}

test "pollProtectedShortDatagram emits protected HANDSHAKE_DONE" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try client.installHandshakeTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });
    try std.testing.expect(client.hasHandshakeProtectionKeys());

    try server.sendHandshakeDone();
    const done_packet = (try server.pollProtectedShortDatagram(10, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(done_packet);
    try std.testing.expect(!server.pending_handshake_done);
    try std.testing.expect(server.handshake_done_sent);
    try std.testing.expectEqual(@as(u64, 1), server.nextPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 1), server.sentPacketCount(.application));
    try std.testing.expectEqual(done_packet.len, server.bytesInFlight(.application));

    try client.processProtectedShortDatagram(11, secrets.server, client_dcid.len, done_packet);
    try std.testing.expect(client.handshakeConfirmed());
    try std.testing.expect(client.packetNumberSpaceDiscarded(.handshake));
    try std.testing.expect(!client.hasHandshakeProtectionKeys());
    try std.testing.expectEqual(@as(?u64, 0), client.pendingAckLargest(.application));

    const ack = (try client.pollProtectedShortDatagram(12, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(ack);
    try server.processProtectedShortDatagram(13, secrets.client, server_dcid.len, ack);
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), server.bytesInFlight(.application));
}

test "pollProtectedShortDatagram emits protected NEW_TOKEN" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    try server.issueNewToken("future-protected");
    const token_packet = (try server.pollProtectedShortDatagram(10, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(token_packet);
    try std.testing.expectEqual(@as(usize, 0), server.pending_new_tokens.items.len);
    try std.testing.expectEqual(@as(u64, 1), server.nextPacketNumber(.application));
    try std.testing.expectEqual(token_packet.len, server.bytesInFlight(.application));

    try client.processProtectedShortDatagram(11, secrets.server, client_dcid.len, token_packet);
    try std.testing.expectEqualStrings("future-protected", client.latestNewToken().?);
    try std.testing.expectEqual(@as(?u64, 0), client.pendingAckLargest(.application));
}

test "pollProtectedShortDatagram preserves HANDSHAKE_DONE and NEW_TOKEN when anti-amplification blocks" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    try server.sendHandshakeDone();
    try server.issueNewToken("blocked-token");

    try std.testing.expectEqual(
        @as(?[]u8, null),
        try server.pollProtectedShortDatagram(10, &client_dcid, secrets.server),
    );
    try std.testing.expect(server.pending_handshake_done);
    try std.testing.expectEqual(@as(usize, 1), server.pending_new_tokens.items.len);
    try std.testing.expectEqual(@as(u64, 0), server.nextPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.application));

    try server.validatePeerAddress();
    const done_packet = (try server.pollProtectedShortDatagram(11, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(done_packet);
    try std.testing.expect(!server.pending_handshake_done);
    try std.testing.expectEqual(@as(usize, 1), server.pending_new_tokens.items.len);
    try client.processProtectedShortDatagram(12, secrets.server, client_dcid.len, done_packet);
    try std.testing.expect(client.handshakeConfirmed());

    const token_packet = (try server.pollProtectedShortDatagram(13, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(token_packet);
    try std.testing.expectEqual(@as(usize, 0), server.pending_new_tokens.items.len);
    try client.processProtectedShortDatagram(13, secrets.server, client_dcid.len, token_packet);
    try std.testing.expectEqualStrings("blocked-token", client.latestNewToken().?);
}

test "pollProtectedShortDatagram emits protected CONNECTION_CLOSE and retransmits" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const server_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{ .initial_rtt_ms = 100 });
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{ .initial_rtt_ms = 100 });
    defer server.deinit();
    try server.validatePeerAddress();

    try client.closeConnection(0, @intFromEnum(frame.FrameType.stream), "done");
    try std.testing.expect(!client.closed);
    try std.testing.expectEqual(ConnectionState.closing, client.connectionState());
    try std.testing.expectEqual(@as(?i64, null), client.closeDeadlineMillis());

    const close_packet = (try client.pollProtectedShortDatagram(10, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(close_packet);
    try std.testing.expect(client.closed);
    try std.testing.expectEqual(ConnectionState.closing, client.connectionState());
    try std.testing.expectEqual(@as(u64, 1), client.nextPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight(.application));
    try std.testing.expect(client.closeDeadlineMillis().? > 10);

    try server.processProtectedShortDatagram(11, secrets.client, server_dcid.len, close_packet);
    try std.testing.expect(server.closed);
    try std.testing.expectEqual(ConnectionState.draining, server.connectionState());
    try std.testing.expectEqual(@as(u64, 1), server.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));
    try std.testing.expectError(error.ConnectionClosed, server.sendPing());

    const retransmit = (try client.pollProtectedShortDatagram(12, &server_dcid, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(retransmit);
    try std.testing.expectEqual(@as(u64, 2), client.nextPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight(.application));

    const deadline = client.closeDeadlineMillis().?;
    try std.testing.expectError(
        error.ConnectionClosed,
        client.pollProtectedShortDatagram(deadline, &server_dcid, secrets.client),
    );
    try std.testing.expectEqual(ConnectionState.closed, client.connectionState());
    try std.testing.expect(client.pending_close == null);
}

test "pollProtectedShortDatagram emits protected APPLICATION_CLOSE" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    try server.closeApplication(42, "app done");
    const close_packet = (try server.pollProtectedShortDatagram(10, &client_dcid, secrets.server)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(close_packet);

    try std.testing.expect(server.closed);
    try std.testing.expectEqual(ConnectionState.closing, server.connectionState());
    try std.testing.expectEqual(@as(u64, 1), server.nextPacketNumber(.application));
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.application));

    try client.processProtectedShortDatagram(11, secrets.server, client_dcid.len, close_packet);
    try std.testing.expect(client.closed);
    try std.testing.expectEqual(ConnectionState.draining, client.connectionState());
    try std.testing.expectEqual(@as(u64, 1), client.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, null), client.pendingAckLargest(.application));
}

test "pollProtectedShortDatagram preserves close frame when anti-amplification blocks" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_dcid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try server.closeConnection(0, @intFromEnum(frame.FrameType.stream), "blocked close");
    try std.testing.expectEqual(
        @as(?[]u8, null),
        try server.pollProtectedShortDatagram(10, &client_dcid, secrets.server),
    );
    try std.testing.expect(!server.closed);
    try std.testing.expectEqual(ConnectionState.closing, server.connectionState());
    try std.testing.expectEqual(@as(?i64, null), server.closeDeadlineMillis());
    try std.testing.expectEqual(@as(u64, 0), server.nextPacketNumber(.application));
    try std.testing.expect(server.pending_close != null);
}

test "pollProtectedLongDatagram emits protected ACK-only without bytes in flight" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    _ = try client.recordPacketSentInSpace(.initial, 0, 100);
    try server.queueAckForReceivedPacketInSpace(.initial);

    const ack_datagram = (try server.pollProtectedLongDatagram(
        10,
        &client_scid,
        &server_scid,
        &[_]u8{},
        .{ .initial = secrets.server },
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(ack_datagram);

    try std.testing.expectEqual(@as(u64, 1), server.nextPacketNumber(.initial));
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.initial));
    try std.testing.expectEqual(@as(usize, 0), server.bytesInFlight(.initial));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.initial));

    try std.testing.expectEqual(@as(usize, 1), try client.processProtectedLongDatagram(11, .{ .initial = secrets.server }, ack_datagram));
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.initial));
    try std.testing.expectEqual(@as(usize, 0), client.bytesInFlight(.initial));
    try std.testing.expectEqual(@as(u64, 1), client.nextPeerPacketNumber(.initial));
    try std.testing.expectEqual(@as(?u64, null), client.pendingAckLargest(.initial));
}

test "pollProtectedLongDatagram emits protected PING with ACK" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try server.validatePeerAddress();

    _ = try client.recordPacketSentInSpace(.handshake, 0, 100);
    try server.queueAckForReceivedPacketInSpace(.handshake);
    try server.sendPingInSpace(.handshake);

    const ping_datagram = (try server.pollProtectedLongDatagram(
        20,
        &client_scid,
        &server_scid,
        &[_]u8{},
        .{ .handshake = secrets.server },
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(ping_datagram);

    try std.testing.expectEqual(@as(u64, 1), server.nextPacketNumber(.handshake));
    try std.testing.expectEqual(@as(usize, 1), server.sentPacketCount(.handshake));
    try std.testing.expectEqual(ping_datagram.len, server.bytesInFlight(.handshake));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.handshake));

    try std.testing.expectEqual(@as(usize, 1), try client.processProtectedLongDatagram(21, .{ .handshake = secrets.server }, ping_datagram));
    try std.testing.expectEqual(@as(usize, 0), client.sentPacketCount(.handshake));
    try std.testing.expectEqual(@as(u64, 1), client.nextPeerPacketNumber(.handshake));
    try std.testing.expectEqual(@as(?u64, 0), client.pendingAckLargest(.handshake));
}

test "protected long datagram bridge rejects mismatched packet type without state changes" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const secrets = try protection.deriveInitialSecrets(.v1, &dcid);

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

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();

    try std.testing.expectError(
        error.InvalidPacket,
        server.processProtectedLongDatagramInSpace(.handshake, 1, secrets.client, protected),
    );
    try std.testing.expectEqual(@as(u64, 0), server.nextPeerPacketNumber(.handshake));
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.handshake));
    var crypto_buf: [32]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try server.recvCryptoInSpace(.handshake, &crypto_buf));
}

test "protected long CRYPTO poll rejects Handshake token without mutation" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const secrets = try protection.deriveInitialSecrets(.v1, &dcid);

    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();
    try server.sendCryptoInSpace(.handshake, "server handshake");

    try std.testing.expectError(
        error.InvalidPacket,
        server.pollProtectedLongCryptoDatagramInSpace(.handshake, 10, &dcid, &scid, "token", secrets.server),
    );
    try std.testing.expectEqual(@as(u64, 0), server.nextPacketNumber(.handshake));
    try std.testing.expectEqual(@as(usize, 0), server.sentPacketCount(.handshake));
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

test "handshakeState tracks Handshake space use and confirmation" {
    var sender = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer sender.deinit();

    try std.testing.expectEqual(HandshakeState.initial, sender.handshakeState());
    try sender.sendCryptoInSpace(.initial, "initial");
    try std.testing.expectEqual(HandshakeState.initial, sender.handshakeState());
    try sender.sendCryptoInSpace(.handshake, "handshake");
    try std.testing.expectEqual(HandshakeState.handshake, sender.handshakeState());
    try std.testing.expect(!sender.handshakeConfirmed());

    try sender.confirmHandshake();
    try std.testing.expectEqual(HandshakeState.confirmed, sender.handshakeState());
    try std.testing.expect(sender.handshakeConfirmed());

    var receiver = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer receiver.deinit();
    const ping = [_]u8{@intFromEnum(frame.FrameType.ping)};
    try receiver.processDatagramInSpace(.handshake, 0, &ping);
    try std.testing.expectEqual(HandshakeState.handshake, receiver.handshakeState());
    try std.testing.expect(!receiver.handshakeConfirmed());
    try std.testing.expectEqual(@as(?u64, 0), receiver.pendingAckLargest(.handshake));

    var rollback = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer rollback.deinit();
    const invalid_payload = [_]u8{
        @intFromEnum(frame.FrameType.ping),
        0xff,
    };
    try std.testing.expectError(error.InvalidPacket, rollback.processDatagramInSpace(.handshake, 0, &invalid_payload));
    try std.testing.expectEqual(HandshakeState.initial, rollback.handshakeState());
    try std.testing.expect(!rollback.handshakeConfirmed());
    try std.testing.expectEqual(@as(?u64, null), rollback.pendingAckLargest(.handshake));
    try std.testing.expectEqual(@as(u64, 0), rollback.nextPeerPacketNumber(.handshake));
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

test "0-RTT rejects RETIRE_CONNECTION_ID before semantic retirement" {
    var server = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer server.deinit();
    try server.validatePeerAddress();

    const cid = [_]u8{ 0xc0, 0xff, 0xee, 0x10 };
    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    try std.testing.expectEqual(@as(u64, 0), try server.issueConnectionId(&cid, token, 0));

    var new_cid_buf: [64]u8 = undefined;
    _ = (try server.pollTx(0, &new_cid_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(server.local_connection_ids.items[0].sent);

    var retire_buf: [16]u8 = undefined;
    var retire_out = buffer.fixedWriter(&retire_buf);
    try frame.encodeFrame(retire_out.writer(), .{ .retire_connection_id = .{ .sequence_number = 0 } });

    try std.testing.expectError(
        error.InvalidPacket,
        server.processDatagramForPacketType(.zero_rtt, 0, retire_out.getWritten()),
    );
    try std.testing.expect(!server.local_connection_ids.items[0].retired);
    try std.testing.expectEqual(@as(?u64, null), server.pendingAckLargest(.application));
    try std.testing.expectEqual(@as(u64, 0), server.nextPeerPacketNumber(.application));
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

    try std.testing.expect(conn.packetNumberSpaceDiscarded(.initial));
    try std.testing.expectEqual(@as(?u64, null), conn.pendingAckLargest(.initial));
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

test "ACK_ECN CE increase enters NewReno recovery" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();

    const initial_window = conn.congestionWindow(.application);
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
            .ecn_ce_count = 1,
        },
    });

    const recovery_window = conn.congestionWindow(.application);
    try std.testing.expectEqual(@as(usize, 0), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), conn.bytesInFlight(.application));
    try std.testing.expectEqual(EcnValidationState.capable, conn.ecnValidationState(.application));
    try std.testing.expectEqual(@as(u64, 1), conn.ecnCounts(.application).ecn_ce_count);
    try std.testing.expectEqual(@max(initial_window / 2, recovery.minimumCongestionWindow(1200)), recovery_window);
    try std.testing.expectEqual(recovery_window, conn.recovery_state.ssthresh);
}

test "ACK_ECN CE increase respects NewReno recovery period" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .max_datagram_size = 1200,
        .initial_rtt_ms = 100,
    });
    defer conn.deinit();

    _ = try conn.recordEcnPacketSentInSpace(.application, 10, 100, .ect0);
    _ = try conn.recordEcnPacketSentInSpace(.application, 20, 100, .ect0);

    try conn.receiveAckEcnInSpace(.application, 60, .{
        .ack = .{
            .largest_acknowledged = 0,
            .ack_delay = 0,
            .first_ack_range = 0,
        },
        .ecn_counts = .{
            .ect0_count = 0,
            .ect1_count = 0,
            .ecn_ce_count = 1,
        },
    });
    const recovery_window = conn.congestionWindow(.application);

    try conn.receiveAckEcnInSpace(.application, 70, .{
        .ack = .{
            .largest_acknowledged = 1,
            .ack_delay = 0,
            .first_ack_range = 0,
        },
        .ecn_counts = .{
            .ect0_count = 0,
            .ect1_count = 0,
            .ecn_ce_count = 2,
        },
    });

    try std.testing.expectEqual(@as(usize, 0), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 0), conn.bytesInFlight(.application));
    try std.testing.expectEqual(EcnValidationState.capable, conn.ecnValidationState(.application));
    try std.testing.expectEqual(@as(u64, 2), conn.ecnCounts(.application).ecn_ce_count);
    try std.testing.expectEqual(recovery_window, conn.congestionWindow(.application));
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

    const congestion_window_before = conn.congestionWindow(.application);
    const ssthresh_before = conn.recovery_state.ssthresh;
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
            .ect0_count = 0,
            .ect1_count = 0,
            .ecn_ce_count = 1,
        },
    } });
    try payload.writer().writeByte(@intFromEnum(frame.FrameType.handshake_done));

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(60, payload.getWritten()));
    try std.testing.expectEqual(EcnValidationState.unknown, conn.ecnValidationState(.application));
    try std.testing.expectEqual(@as(u64, 0), conn.ecnCounts(.application).ect0_count);
    try std.testing.expectEqual(@as(u64, 0), conn.ecnCounts(.application).ecn_ce_count);
    try std.testing.expectEqual(@as(usize, 1), conn.sentPacketCount(.application));
    try std.testing.expectEqual(@as(usize, 100), conn.bytesInFlight(.application));
    try std.testing.expectEqual(congestion_window_before, conn.congestionWindow(.application));
    try std.testing.expectEqual(ssthresh_before, conn.recovery_state.ssthresh);
    try std.testing.expectEqual(@as(?i64, null), conn.recovery_state.congestion_recovery_start_time_millis);
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

test "issueConnectionId rejects duplicate CIDs duplicate reset tokens and peer active id limit overflow" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    const token0 = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const token1 = [_]u8{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    const token2 = [_]u8{0xa5} ** packet.stateless_reset_token_len;
    const cid0 = [_]u8{ 0, 1, 2, 3 };
    const cid1 = [_]u8{ 4, 5, 6, 7 };
    const cid2 = [_]u8{ 8, 9, 10, 11 };

    try std.testing.expectEqual(@as(u64, 0), try conn.issueConnectionId(&cid0, token0, 0));
    try std.testing.expectError(error.InvalidPacket, conn.issueConnectionId(&cid0, token1, 0));
    try std.testing.expectError(error.InvalidPacket, conn.issueConnectionId(&cid1, token0, 0));
    try std.testing.expectEqual(@as(u64, 1), try conn.issueConnectionId(&cid1, token1, 0));
    try std.testing.expectError(error.InvalidPacket, conn.issueConnectionId(&cid2, token2, 0));
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

    const token0 = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const token1 = [_]u8{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    const token2 = [_]u8{0xa5} ** packet.stateless_reset_token_len;
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
        .stateless_reset_token = token0,
    } });
    try conn.processDatagram(0, out.getWritten());
    _ = (try conn.pollTx(0, &tx)).?;

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = &cid0,
        .stateless_reset_token = token0,
    } });
    try conn.processDatagram(1, out.getWritten());
    try std.testing.expectEqual(@as(usize, 1), conn.active_connection_ids.items.len);
    _ = (try conn.pollTx(1, &tx)).?;

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = &cid0_mismatch,
        .stateless_reset_token = token0,
    } });
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(2, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 1), conn.active_connection_ids.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = &cid1,
        .stateless_reset_token = token0,
    } });
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(3, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 1), conn.active_connection_ids.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = &cid1,
        .stateless_reset_token = token1,
    } });
    try conn.processDatagram(4, out.getWritten());
    _ = (try conn.pollTx(3, &tx)).?;
    try std.testing.expectEqual(@as(u64, 2), conn.activeConnectionIdCount());

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 2,
        .retire_prior_to = 0,
        .connection_id = &cid2,
        .stateless_reset_token = token2,
    } });
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(5, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 2), conn.active_connection_ids.items.len);
    try std.testing.expectEqual(@as(u64, 2), conn.activeConnectionIdCount());
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
}

test "NEW_CONNECTION_ID retire_prior_to rolls back when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const token0 = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const token1 = [_]u8{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    const cid0 = [_]u8{ 0xd0, 0, 0, 0 };
    const cid1 = [_]u8{ 0xd0, 0, 0, 1 };

    var datagram: [96]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = &cid0,
        .stateless_reset_token = token0,
    } });
    try conn.processDatagram(0, out.getWritten());

    var tx: [64]u8 = undefined;
    _ = (try conn.pollTx(0, &tx)).?;

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 1,
        .connection_id = &cid1,
        .stateless_reset_token = token1,
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

test "stopSending rejects receive stream after final data is received" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var stream_buf: [32]u8 = undefined;
    var stream_out = buffer.fixedWriter(&stream_buf);
    try frame.encodeFrame(stream_out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = true,
        .data = "done",
    } });
    try conn.processDatagram(0, stream_out.getWritten());

    try std.testing.expectError(error.StreamClosed, conn.stopSending(0, 1));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_stop_sending.items.len);
}

test "stopSending is still valid while final-size stream data has gaps" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var stream_buf: [32]u8 = undefined;
    var stream_out = buffer.fixedWriter(&stream_buf);
    try frame.encodeFrame(stream_out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 4,
        .fin = true,
        .data = "!",
    } });
    try conn.processDatagram(0, stream_out.getWritten());

    try conn.stopSending(0, 1);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_stop_sending.items.len);
}

test "pending STOP_SENDING is dropped after matching RESET_STREAM arrives" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.stopSending(stream_id, 1);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_stop_sending.items.len);

    var reset_buf: [32]u8 = undefined;
    var reset_out = buffer.fixedWriter(&reset_buf);
    try frame.encodeFrame(reset_out.writer(), .{ .reset_stream = .{
        .stream_id = stream_id,
        .application_error_code = 7,
        .final_size = 0,
    } });
    try conn.processDatagram(0, reset_out.getWritten());

    var out_buf: [64]u8 = undefined;
    const payload = (try conn.pollTx(1, &out_buf)) orelse return error.TestUnexpectedResult;
    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .ack => |ack_frame| try std.testing.expectEqual(@as(u64, 0), ack_frame.largest_acknowledged),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(decoded.len, payload.len);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_stop_sending.items.len);
}

test "pending STOP_SENDING is dropped after final data arrives" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.stopSending(stream_id, 1);
    try std.testing.expectEqual(@as(usize, 1), conn.pending_stop_sending.items.len);

    var stream_buf: [32]u8 = undefined;
    var stream_out = buffer.fixedWriter(&stream_buf);
    try frame.encodeFrame(stream_out.writer(), .{ .stream = .{
        .stream_id = stream_id,
        .offset = 0,
        .fin = true,
        .data = "done",
    } });
    try conn.processDatagram(0, stream_out.getWritten());

    var out_buf: [64]u8 = undefined;
    const payload = (try conn.pollTx(1, &out_buf)) orelse return error.TestUnexpectedResult;
    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .ack => |ack_frame| try std.testing.expectEqual(@as(u64, 0), ack_frame.largest_acknowledged),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(decoded.len, payload.len);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_stop_sending.items.len);

    var read_buf: [8]u8 = undefined;
    const n = (try conn.recvOnStream(stream_id, &read_buf)).?;
    try std.testing.expectEqualStrings("done", read_buf[0..n]);
}

test "STOP_SENDING on peer bidirectional stream prevents later reply" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();
    try conn.validatePeerAddress();

    const stream_id: u64 = 8;
    var stop_buf: [16]u8 = undefined;
    var stop_out = buffer.fixedWriter(&stop_buf);
    try frame.encodeFrame(stop_out.writer(), .{ .stop_sending = .{
        .stream_id = stream_id,
        .application_error_code = 9,
    } });
    try conn.processDatagram(0, stop_out.getWritten());

    try std.testing.expect(conn.findRecvStream(0) != null);
    try std.testing.expect(conn.findRecvStream(4) != null);
    try std.testing.expect(conn.findRecvStream(stream_id) != null);
    try std.testing.expectError(error.StreamClosed, conn.sendOnStream(stream_id, "reply", false));

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
            try std.testing.expectEqual(stream_id, reset_frame.stream_id);
            try std.testing.expectEqual(@as(u64, 9), reset_frame.application_error_code);
            try std.testing.expectEqual(@as(u64, 0), reset_frame.final_size);
        },
        else => return error.TestUnexpectedResult,
    }

    var stream_buf: [32]u8 = undefined;
    var stream_out = buffer.fixedWriter(&stream_buf);
    try frame.encodeFrame(stream_out.writer(), .{ .stream = .{
        .stream_id = stream_id,
        .offset = 0,
        .fin = true,
        .data = "done",
    } });
    try conn.processDatagram(1, stream_out.getWritten());

    var read_buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try conn.recvOnStream(0, &read_buf));
    try std.testing.expectEqual(@as(?usize, null), try conn.recvOnStream(4, &read_buf));
    const n = (try conn.recvOnStream(stream_id, &read_buf)).?;
    try std.testing.expectEqualStrings("done", read_buf[0..n]);
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

test "STOP_SENDING rolls back peer bidirectional stream creation when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stop_sending = .{
        .stream_id = 0,
        .application_error_code = 1,
    } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.send_streams.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_reset_streams.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 0), conn.next_peer_packet_number);
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

test "ACK-driven loss requeues STREAM frame for retransmission" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "lost", false);

    var out_buf: [128]u8 = undefined;
    _ = (try conn.pollTx(10, &out_buf)).?;
    try conn.sendPing();
    _ = (try conn.pollTx(20, &out_buf)).?;
    try conn.sendPing();
    _ = (try conn.pollTx(30, &out_buf)).?;
    try conn.sendPing();
    _ = (try conn.pollTx(40, &out_buf)).?;
    try std.testing.expectEqual(@as(usize, 4), conn.sent_packets.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.send_queue.items.len);

    try conn.receiveAckInSpace(.application, 70, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    try std.testing.expectEqual(@as(usize, 2), conn.sent_packets.items.len);
    try std.testing.expectEqual(@as(usize, 1), conn.send_queue.items.len);
    try std.testing.expectEqual(stream_id, conn.send_queue.items[0].stream_id);
    try std.testing.expectEqual(@as(u64, 0), conn.send_queue.items[0].offset);
    try std.testing.expectEqualStrings("lost", conn.send_queue.items[0].data);

    const retransmit_payload = (try conn.pollTx(80, &out_buf)).?;
    var decoded = try frame.decodeFrameSlice(retransmit_payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .stream => |stream| {
            try std.testing.expectEqual(stream_id, stream.stream_id);
            try std.testing.expectEqual(@as(u64, 0), stream.offset);
            try std.testing.expectEqualStrings("lost", stream.data);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "processDatagram rolls back STREAM retransmission requeue when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "lost", false);

    var out_buf: [128]u8 = undefined;
    _ = (try conn.pollTx(10, &out_buf)).?;
    try conn.sendPing();
    _ = (try conn.pollTx(20, &out_buf)).?;
    try conn.sendPing();
    _ = (try conn.pollTx(30, &out_buf)).?;
    try conn.sendPing();
    _ = (try conn.pollTx(40, &out_buf)).?;
    const bytes_in_flight = conn.recovery_state.bytes_in_flight;

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .ack = .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(70, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 4), conn.sent_packets.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.send_queue.items.len);
    try std.testing.expectEqual(bytes_in_flight, conn.recovery_state.bytes_in_flight);
    try std.testing.expectEqual(@as(?u64, null), conn.recovery_state.latest_rtt_ms);
}

test "ACK-driven loss requeues CRYPTO frame for retransmission" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    try conn.sendCryptoInSpace(.handshake, "lost crypto");

    var out_buf: [128]u8 = undefined;
    _ = (try conn.pollTxInSpace(.handshake, 10, &out_buf)).?;
    _ = try conn.recordPacketSentInSpace(.handshake, 20, 1);
    _ = try conn.recordPacketSentInSpace(.handshake, 30, 1);
    _ = try conn.recordPacketSentInSpace(.handshake, 40, 1);
    try std.testing.expectEqual(@as(usize, 4), conn.sentPacketCount(.handshake));
    try std.testing.expectEqual(@as(usize, 0), conn.handshake_packet_space.crypto_send_queue.items.len);

    try conn.receiveAckInSpace(.handshake, 70, .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    });

    try std.testing.expectEqual(@as(usize, 2), conn.sentPacketCount(.handshake));
    try std.testing.expectEqual(@as(usize, 1), conn.handshake_packet_space.crypto_send_queue.items.len);
    try std.testing.expectEqual(@as(u64, 0), conn.handshake_packet_space.crypto_send_queue.items[0].offset);
    try std.testing.expectEqualStrings("lost crypto", conn.handshake_packet_space.crypto_send_queue.items[0].data);

    const retransmit_payload = (try conn.pollTxInSpace(.handshake, 80, &out_buf)).?;
    var decoded = try frame.decodeFrameSlice(retransmit_payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .crypto => |crypto| {
            try std.testing.expectEqual(@as(u64, 0), crypto.offset);
            try std.testing.expectEqualStrings("lost crypto", crypto.data);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "processDatagram rolls back CRYPTO retransmission requeue when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    try conn.sendCryptoInSpace(.handshake, "lost crypto");

    var out_buf: [128]u8 = undefined;
    _ = (try conn.pollTxInSpace(.handshake, 10, &out_buf)).?;
    _ = try conn.recordPacketSentInSpace(.handshake, 20, 1);
    _ = try conn.recordPacketSentInSpace(.handshake, 30, 1);
    _ = try conn.recordPacketSentInSpace(.handshake, 40, 1);
    const bytes_in_flight = conn.bytesInFlight(.handshake);

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .ack = .{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .first_ack_range = 0,
    } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagramInSpace(.handshake, 70, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 4), conn.sentPacketCount(.handshake));
    try std.testing.expectEqual(@as(usize, 0), conn.handshake_packet_space.crypto_send_queue.items.len);
    try std.testing.expectEqual(bytes_in_flight, conn.bytesInFlight(.handshake));
    try std.testing.expectEqual(@as(?u64, null), conn.handshake_packet_space.recovery_state.latest_rtt_ms);
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

test "RESET_STREAM after FIN with gaps aborts receive side and accounts final size" {
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
        .fin = true,
        .data = "!",
    } });
    try conn.processDatagram(0, out.getWritten());
    try std.testing.expectEqual(@as(?u64, 6), conn.recv_streams.items[0].final_size);
    try std.testing.expectEqual(@as(usize, 1), conn.recv_streams.items[0].pending.items.len);
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

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "hello",
    } });
    try conn.processDatagram(2, out.getWritten());
    try std.testing.expectEqual(@as(u64, 6), conn.recv_data_bytes);
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items[0].data.items.len);

    var read_buf: [8]u8 = undefined;
    try std.testing.expectError(error.StreamClosed, conn.recvOnStream(0, &read_buf));
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
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();
    try conn.installHandshakeTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });
    try conn.sendCryptoInSpace(.handshake, "late handshake");
    try std.testing.expect(conn.hasHandshakeProtectionKeys());

    const payload = [_]u8{@intFromEnum(frame.FrameType.handshake_done)};
    try conn.processDatagram(0, &payload);

    try std.testing.expect(conn.handshakeConfirmed());
    try std.testing.expectEqual(HandshakeState.confirmed, conn.handshakeState());
    try std.testing.expectEqual(@as(?u64, 0), conn.pending_ack_largest);
    try std.testing.expect(conn.packetNumberSpaceDiscarded(.handshake));
    try std.testing.expect(!conn.hasHandshakeProtectionKeys());
    try std.testing.expectError(
        error.InvalidPacket,
        conn.pollProtectedHandshakeDatagramWithInstalledKeys(0, &dcid, &scid),
    );

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
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();
    try conn.installHandshakeTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });

    const payload = [_]u8{
        @intFromEnum(frame.FrameType.handshake_done),
        0xff,
    };
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, &payload));
    try std.testing.expect(!conn.handshakeConfirmed());
    try std.testing.expectEqual(HandshakeState.initial, conn.handshakeState());
    try std.testing.expect(!conn.packetNumberSpaceDiscarded(.handshake));
    try std.testing.expect(conn.hasHandshakeProtectionKeys());
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
    const next_peer_packet_number = conn.nextPeerPacketNumber(.application);
    try conn.processDatagram(0, &ping);
    try std.testing.expectEqual(ConnectionState.draining, conn.connectionState());
    try std.testing.expectEqual(next_peer_packet_number, conn.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, null), conn.pendingAckLargest(.application));
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
    try std.testing.expect(conn.peerClose() == null);
    try std.testing.expectEqual(ConnectionState.active, conn.connectionState());
    try std.testing.expectEqual(@as(?i64, null), conn.closeDeadlineMillis());
    try std.testing.expectEqual(@as(u64, 1), try conn.openStream());
}

test "closeConnection queues CONNECTION_CLOSE and closes after pollTx" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    try conn.closeConnection(0, @intFromEnum(frame.FrameType.stream), "done");
    try std.testing.expect(conn.peerClose() == null);
    try std.testing.expect(!conn.closed);
    try std.testing.expectEqual(ConnectionState.closing, conn.connectionState());
    try std.testing.expectEqual(@as(?i64, null), conn.closeDeadlineMillis());
    try std.testing.expectError(error.ConnectionClosed, conn.sendPing());

    const ping = [_]u8{@intFromEnum(frame.FrameType.ping)};
    try conn.processDatagram(0, &ping);
    try std.testing.expect(!conn.closed);
    try std.testing.expect(conn.pending_close != null);
    try std.testing.expectEqual(ConnectionState.closing, conn.connectionState());
    try std.testing.expectEqual(@as(u64, 0), conn.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, null), conn.pendingAckLargest(.application));

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

    const invalid_payload = [_]u8{0xff};
    const next_peer_packet_number = conn.nextPeerPacketNumber(.application);
    try conn.processDatagram(deadline - 1, &invalid_payload);
    try std.testing.expectEqual(ConnectionState.draining, conn.connectionState());
    try std.testing.expectEqual(next_peer_packet_number, conn.nextPeerPacketNumber(.application));
    try std.testing.expectEqual(@as(?u64, null), conn.pendingAckLargest(.application));

    try std.testing.expectError(error.ConnectionClosed, conn.processDatagram(deadline, &invalid_payload));
    try std.testing.expectEqual(ConnectionState.closed, conn.connectionState());
    try std.testing.expectEqual(@as(?i64, null), conn.closeDeadlineMillis());
}

test "remote close exposes peer close diagnostics" {
    var transport = try QuicConnection.init(std.testing.allocator, .server, .{ .initial_rtt_ms = 100 });
    defer transport.deinit();

    var close_buf: [64]u8 = undefined;
    var close_out = buffer.fixedWriter(&close_buf);
    try frame.encodeFrame(close_out.writer(), .{ .connection_close = .{
        .error_code = 0x10c,
        .frame_type = @intFromEnum(frame.FrameType.stream),
        .reason_phrase = "flow error",
    } });

    try transport.processDatagram(20, close_out.getWritten());
    switch (transport.peerClose() orelse return error.TestUnexpectedResult) {
        .connection => |close| {
            try std.testing.expectEqual(@as(u64, 0x10c), close.error_code);
            try std.testing.expectEqual(@as(u64, @intFromEnum(frame.FrameType.stream)), close.frame_type);
            try std.testing.expectEqualStrings("flow error", close.reason_phrase);
        },
        else => return error.TestUnexpectedResult,
    }

    const deadline = transport.closeDeadlineMillis().?;
    const ping = [_]u8{@intFromEnum(frame.FrameType.ping)};
    try std.testing.expectError(error.ConnectionClosed, transport.processDatagram(deadline, &ping));
    try std.testing.expectEqual(ConnectionState.closed, transport.connectionState());
    switch (transport.peerClose() orelse return error.TestUnexpectedResult) {
        .connection => |close| try std.testing.expectEqualStrings("flow error", close.reason_phrase),
        else => return error.TestUnexpectedResult,
    }

    var application = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer application.deinit();

    close_out = buffer.fixedWriter(&close_buf);
    try frame.encodeFrame(close_out.writer(), .{ .application_close = .{
        .error_code = 42,
        .reason_phrase = "app stop",
    } });

    try application.processDatagram(30, close_out.getWritten());
    switch (application.peerClose() orelse return error.TestUnexpectedResult) {
        .application => |close| {
            try std.testing.expectEqual(@as(u64, 42), close.error_code);
            try std.testing.expectEqualStrings("app stop", close.reason_phrase);
        },
        else => return error.TestUnexpectedResult,
    }
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

test "pending STREAM_DATA_BLOCKED is dropped when FIN closes send side before transmit" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 10,
        .initial_max_stream_data = 5,
    });
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "12345", false);
    try std.testing.expectError(error.FlowControlBlocked, conn.sendOnStream(stream_id, "x", false));
    try std.testing.expectEqual(@as(usize, 1), conn.pending_blocked_frames.items.len);

    try conn.sendOnStream(stream_id, "", true);

    var out_buf: [128]u8 = undefined;
    const payload = (try conn.pollTx(0, &out_buf)).?;
    try std.testing.expectEqual(@as(usize, 0), conn.pending_blocked_frames.items.len);

    var decoded = try frame.decodeFrameSlice(payload, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .stream => |stream_frame| {
            try std.testing.expectEqual(stream_id, stream_frame.stream_id);
            try std.testing.expectEqual(@as(u64, 0), stream_frame.offset);
            try std.testing.expectEqualStrings("12345", stream_frame.data);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "pending STREAM_DATA_BLOCKED is dropped when reset closes send side before transmit" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 10,
        .initial_max_stream_data = 5,
    });
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "12345", false);
    try std.testing.expectError(error.FlowControlBlocked, conn.sendOnStream(stream_id, "x", false));
    try std.testing.expectEqual(@as(usize, 1), conn.pending_blocked_frames.items.len);

    try conn.resetStream(stream_id, 7);

    var out_buf: [128]u8 = undefined;
    const reset_payload = (try conn.pollTx(0, &out_buf)).?;
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

    try std.testing.expectEqual(@as(?[]u8, null), try conn.pollTx(1, &out_buf));
    try std.testing.expectEqual(@as(usize, 0), conn.pending_blocked_frames.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.send_queue.items.len);
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

test "pending MAX_STREAM_DATA is dropped when final size becomes known before transmit" {
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

    var read_buf: [8]u8 = undefined;
    const n = (try server.recvOnStream(stream_id, &read_buf)).?;
    try std.testing.expectEqualStrings("12345", read_buf[0..n]);
    try std.testing.expectEqual(@as(u64, 10), server.findRecvStream(stream_id).?.max_data);

    try client.sendOnStream(stream_id, "", true);
    try server.processDatagram(1, (try client.pollTx(1, &datagram)).?);

    const payload = (try server.pollTx(2, &datagram)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(try payloadContainsExpectedMaxFrame(payload, .{ .data = 10 }));
    try std.testing.expect(!try payloadContainsExpectedMaxFrame(payload, .{
        .stream_data = .{ .stream_id = stream_id, .maximum_stream_data = 10 },
    }));
    try std.testing.expectEqual(@as(usize, 0), server.pending_max_frames.items.len);
}

test "pending MAX_STREAM_DATA is dropped when RESET_STREAM arrives before transmit" {
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

    var read_buf: [8]u8 = undefined;
    const n = (try server.recvOnStream(stream_id, &read_buf)).?;
    try std.testing.expectEqualStrings("12345", read_buf[0..n]);
    try std.testing.expectEqual(@as(u64, 10), server.findRecvStream(stream_id).?.max_data);

    try client.resetStream(stream_id, 7);
    try server.processDatagram(1, (try client.pollTx(1, &datagram)).?);

    const payload = (try server.pollTx(2, &datagram)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(try payloadContainsExpectedMaxFrame(payload, .{ .data = 10 }));
    try std.testing.expect(!try payloadContainsExpectedMaxFrame(payload, .{
        .stream_data = .{ .stream_id = stream_id, .maximum_stream_data = 10 },
    }));
    try std.testing.expectEqual(@as(usize, 0), server.pending_max_frames.items.len);
}

test "recvOnStream uses configured target receive windows" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 5,
    });
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{
        .initial_max_data = 5,
        .initial_max_stream_data = 5,
        .receive_connection_window = 10,
        .receive_stream_window = 12,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "12345", false);

    var datagram: [128]u8 = undefined;
    try server.processDatagram(0, (try client.pollTx(0, &datagram)).?);

    var read_buf: [8]u8 = undefined;
    const read_len = (try server.recvOnStream(stream_id, &read_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("12345", read_buf[0..read_len]);
    try std.testing.expectEqual(@as(u64, 15), server.recv_max_data);
    try std.testing.expectEqual(@as(u64, 17), server.findRecvStream(stream_id).?.max_data);

    var saw_max_data = false;
    var saw_max_stream_data = false;
    var polls: usize = 0;
    while (polls < 3 and (!saw_max_data or !saw_max_stream_data)) : (polls += 1) {
        const payload = (try server.pollTx(10 + @as(i64, @intCast(polls)), &datagram)) orelse break;
        saw_max_data = saw_max_data or try payloadContainsExpectedMaxFrame(payload, .{ .data = 15 });
        saw_max_stream_data = saw_max_stream_data or try payloadContainsExpectedMaxFrame(payload, .{
            .stream_data = .{ .stream_id = stream_id, .maximum_stream_data = 17 },
        });
        try client.processDatagram(20 + @as(i64, @intCast(polls)), payload);
    }
    try std.testing.expect(saw_max_data);
    try std.testing.expect(saw_max_stream_data);
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

test "recvOnStream queues MAX_STREAMS_BIDI after peer bidirectional RESET_STREAM is observed" {
    var client = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_streams_bidi = 1,
    });
    defer client.deinit();
    var server = try QuicConnection.init(std.testing.allocator, .server, .{
        .initial_max_streams_bidi = 1,
    });
    defer server.deinit();
    try server.validatePeerAddress();

    const stream_id = try client.openStream();
    try client.resetStream(stream_id, 7);

    var datagram: [128]u8 = undefined;
    try server.processDatagram(0, (try client.pollTx(0, &datagram)).?);
    try std.testing.expectError(error.FlowControlBlocked, client.openStream());

    var read_buf: [1]u8 = undefined;
    try std.testing.expectError(error.StreamClosed, server.recvOnStream(stream_id, &read_buf));
    try std.testing.expectEqual(@as(u64, 2), server.recv_max_streams_bidi);

    try pollAndProcessUntilMaxStreams(&server, &client, .bidi, 2);
    try std.testing.expectEqual(@as(u64, 4), try client.openStream());

    try std.testing.expectError(error.StreamClosed, server.recvOnStream(stream_id, &read_buf));
    try std.testing.expectEqual(@as(u64, 2), server.recv_max_streams_bidi);
}

test "recvOnStream queues MAX_STREAMS_UNI after peer unidirectional RESET_STREAM is observed" {
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
    try client.resetStream(stream_id, 7);

    var datagram: [128]u8 = undefined;
    try server.processDatagram(0, (try client.pollTx(0, &datagram)).?);
    try std.testing.expectError(error.FlowControlBlocked, client.openUniStream());

    var read_buf: [1]u8 = undefined;
    try std.testing.expectError(error.StreamClosed, server.recvOnStream(stream_id, &read_buf));
    try std.testing.expectEqual(@as(u64, 2), server.recv_max_streams_uni);

    try pollAndProcessUntilMaxStreams(&server, &client, .uni, 2);
    try std.testing.expectEqual(@as(u64, 6), try client.openUniStream());

    try std.testing.expectError(error.StreamClosed, server.recvOnStream(stream_id, &read_buf));
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

test "STREAM_DATA_BLOCKED creates receive stream state before STREAM data" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_stream_data = 10,
    });
    defer conn.deinit();

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream_data_blocked = .{
        .stream_id = 1,
        .maximum_stream_data = 5,
    } });
    try conn.processDatagram(0, out.getWritten());

    const stream_state = conn.findRecvStream(1) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 10), stream_state.max_data);
    try std.testing.expectEqual(@as(?u64, 5), conn.peerStreamDataBlockedLimit(1));

    var out_buf: [64]u8 = undefined;
    const payload = (try conn.pollTx(1, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(try payloadContainsExpectedMaxFrame(payload, .{
        .stream_data = .{ .stream_id = 1, .maximum_stream_data = 10 },
    }));
}

test "STREAM_DATA_BLOCKED validates receive-side stream direction and count" {
    var server = try QuicConnection.init(std.testing.allocator, .server, .{ .initial_max_streams_uni = 1 });
    defer server.deinit();

    const local_uni = try server.openUniStream();
    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream_data_blocked = .{
        .stream_id = local_uni,
        .maximum_stream_data = 0,
    } });
    try std.testing.expectError(error.InvalidPacket, server.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(?u64, null), server.peerStreamDataBlockedLimit(local_uni));
    try std.testing.expectEqual(@as(?u64, null), server.pending_ack_largest);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream_data_blocked = .{
        .stream_id = 6,
        .maximum_stream_data = 0,
    } });
    try std.testing.expectError(error.InvalidPacket, server.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(?u64, null), server.peerStreamDataBlockedLimit(6));
    try std.testing.expectEqual(@as(usize, 0), server.recv_streams.items.len);

    var client = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer client.deinit();

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream_data_blocked = .{
        .stream_id = 0,
        .maximum_stream_data = 0,
    } });
    try std.testing.expectError(error.InvalidPacket, client.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(?u64, null), client.peerStreamDataBlockedLimit(0));

    const local_bidi = try client.openStream();
    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream_data_blocked = .{
        .stream_id = local_bidi,
        .maximum_stream_data = 0,
    } });
    try client.processDatagram(0, out.getWritten());
    try std.testing.expect(client.findRecvStream(local_bidi) != null);
    try std.testing.expectEqual(@as(?u64, 0), client.peerStreamDataBlockedLimit(local_bidi));
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
    try std.testing.expectEqual(@as(usize, 1), conn.recv_streams.items.len);

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
    try std.testing.expectEqual(@as(usize, 1), conn.recv_streams.items.len);
    try std.testing.expect(conn.findRecvStream(4) == null);
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

test "peer DATA_BLOCKED at current receive limit waits without configured window" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 5,
    });
    defer conn.deinit();

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .data_blocked = .{ .maximum_data = 5 } });
    try conn.processDatagram(0, out.getWritten());

    try std.testing.expectEqual(@as(?u64, 5), conn.peerDataBlockedLimit());
    try std.testing.expectEqual(@as(u64, 5), conn.recv_max_data);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_max_frames.items.len);
    try std.testing.expectEqual(@as(?u64, 0), conn.pending_ack_largest);
}

test "peer DATA_BLOCKED at receive limit grows configured receive window" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 5,
        .receive_connection_window = 10,
    });
    defer conn.deinit();

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .data_blocked = .{ .maximum_data = 5 } });
    try conn.processDatagram(0, out.getWritten());

    try std.testing.expectEqual(@as(?u64, 5), conn.peerDataBlockedLimit());
    try std.testing.expectEqual(@as(u64, 15), conn.recv_max_data);

    var out_buf: [64]u8 = undefined;
    const payload = (try conn.pollTx(1, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(try payloadContainsExpectedMaxFrame(payload, .{ .data = 15 }));

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .data_blocked = .{ .maximum_data = 5 } });
    try conn.processDatagram(2, out.getWritten());
    try std.testing.expectEqual(@as(u64, 15), conn.recv_max_data);

    const stale_payload = (try conn.pollTx(3, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(try payloadContainsExpectedMaxFrame(stale_payload, .{ .data = 15 }));
}

test "peer STREAM_DATA_BLOCKED at receive limit grows configured receive window" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_stream_data = 5,
        .receive_stream_window = 12,
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
    const stream_state = conn.findRecvStream(1) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 17), stream_state.max_data);

    var out_buf: [64]u8 = undefined;
    const payload = (try conn.pollTx(2, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(try payloadContainsExpectedMaxFrame(payload, .{
        .stream_data = .{ .stream_id = 1, .maximum_stream_data = 17 },
    }));
}

test "peer STREAM_DATA_BLOCKED is discarded after stream final size is known" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{
        .initial_max_stream_data = 5,
        .receive_stream_window = 12,
    });
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 5,
        .fin = true,
        .data = "",
    } });
    try conn.processDatagram(0, out.getWritten());
    try std.testing.expectEqual(@as(?u64, 5), conn.recv_streams.items[0].final_size);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream_data_blocked = .{
        .stream_id = 0,
        .maximum_stream_data = 5,
    } });
    try conn.processDatagram(1, out.getWritten());

    try std.testing.expectEqual(@as(?u64, null), conn.peerStreamDataBlockedLimit(0));
    try std.testing.expectEqual(@as(u64, 5), conn.recv_streams.items[0].max_data);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_max_frames.items.len);
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

test "peer STREAMS_BLOCKED at receive limit waits without configured window" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_streams_bidi = 2,
    });
    defer conn.deinit();

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .streams_blocked_bidi = .{ .maximum_streams = 2 } });
    try conn.processDatagram(0, out.getWritten());

    try std.testing.expectEqual(@as(?u64, 2), conn.peerStreamsBlockedBidiLimit());
    try std.testing.expectEqual(@as(u64, 2), conn.recv_max_streams_bidi);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_max_frames.items.len);
    try std.testing.expectEqual(@as(?u64, 0), conn.pending_ack_largest);
}

test "peer STREAMS_BLOCKED at receive limit grows configured stream-count window" {
    var bidi = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_streams_bidi = 2,
        .receive_stream_count_window = 3,
    });
    defer bidi.deinit();

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .streams_blocked_bidi = .{ .maximum_streams = 2 } });
    try bidi.processDatagram(0, out.getWritten());

    try std.testing.expectEqual(@as(?u64, 2), bidi.peerStreamsBlockedBidiLimit());
    try std.testing.expectEqual(@as(u64, 5), bidi.recv_max_streams_bidi);

    var out_buf: [64]u8 = undefined;
    const bidi_payload = (try bidi.pollTx(1, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(try payloadContainsExpectedMaxFrame(bidi_payload, .{ .streams_bidi = 5 }));

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .streams_blocked_bidi = .{ .maximum_streams = 2 } });
    try bidi.processDatagram(2, out.getWritten());
    try std.testing.expectEqual(@as(u64, 5), bidi.recv_max_streams_bidi);

    const stale_payload = (try bidi.pollTx(3, &out_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(try payloadContainsExpectedMaxFrame(stale_payload, .{ .streams_bidi = 5 }));

    var uni = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_streams_uni = 1,
        .receive_stream_count_window = 2,
    });
    defer uni.deinit();

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .streams_blocked_uni = .{ .maximum_streams = 1 } });
    try uni.processDatagram(0, out.getWritten());

    try std.testing.expectEqual(@as(?u64, 1), uni.peerStreamsBlockedUniLimit());
    try std.testing.expectEqual(@as(u64, 3), uni.recv_max_streams_uni);

    const uni_payload = (try uni.pollTx(1, &out_buf)) orelse return error.TestUnexpectedResult;
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

test "peer STREAMS_BLOCKED stream-count growth rolls back when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_streams_bidi = 2,
        .receive_stream_count_window = 3,
    });
    defer conn.deinit();

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .streams_blocked_bidi = .{ .maximum_streams = 2 } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(?u64, null), conn.peerStreamsBlockedBidiLimit());
    try std.testing.expectEqual(@as(u64, 2), conn.recv_max_streams_bidi);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_max_frames.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 0), conn.next_peer_packet_number);
}

test "peer BLOCKED receive-window growth rolls back when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 5,
        .receive_connection_window = 10,
    });
    defer conn.deinit();

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .data_blocked = .{ .maximum_data = 5 } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(?u64, null), conn.peerDataBlockedLimit());
    try std.testing.expectEqual(@as(u64, 5), conn.recv_max_data);
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

test "MAX_STREAM_DATA opens peer bidirectional stream before STREAM data" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 10,
        .initial_max_stream_data = 1,
        .initial_max_streams_bidi = 3,
    });
    defer conn.deinit();

    const stream_id: u64 = 9;
    var update_buf: [32]u8 = undefined;
    var update_out = buffer.fixedWriter(&update_buf);
    try frame.encodeFrame(update_out.writer(), .{ .max_stream_data = .{
        .stream_id = stream_id,
        .maximum_stream_data = 2,
    } });
    try conn.processDatagram(0, update_out.getWritten());

    try std.testing.expect(conn.findRecvStream(1) != null);
    try std.testing.expect(conn.findRecvStream(5) != null);
    try std.testing.expect(conn.findRecvStream(stream_id) != null);
    try std.testing.expectEqual(@as(usize, 1), conn.send_streams.items.len);
    try std.testing.expectEqual(@as(u64, 2), conn.findSendStream(stream_id).?.max_data);

    try conn.sendOnStream(stream_id, "xx", false);
    try std.testing.expectEqual(@as(usize, 1), conn.send_queue.items.len);
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

test "MAX_STREAM_DATA is ignored after send side sends FIN" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{
        .initial_max_data = 10,
        .initial_max_stream_data = 5,
    });
    defer conn.deinit();

    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "hello", true);
    try std.testing.expect(conn.findSendStream(stream_id).?.fin_sent);

    var update_buf: [32]u8 = undefined;
    var update_out = buffer.fixedWriter(&update_buf);
    try frame.encodeFrame(update_out.writer(), .{ .max_stream_data = .{
        .stream_id = stream_id,
        .maximum_stream_data = 10,
    } });
    try conn.processDatagram(0, update_out.getWritten());

    try std.testing.expectEqual(@as(u64, 5), conn.findSendStream(stream_id).?.max_data);
    try std.testing.expectError(error.StreamClosed, conn.sendOnStream(stream_id, "!", false));
}

test "MAX_STREAM_DATA send-state creation rolls back when payload is invalid" {
    var conn = try QuicConnection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();

    var datagram: [32]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .max_stream_data = .{
        .stream_id = 1,
        .maximum_stream_data = 2,
    } });
    try out.writeByte(0xff);

    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(0, out.getWritten()));
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items.len);
    try std.testing.expectEqual(@as(usize, 0), conn.send_streams.items.len);
    try std.testing.expectEqual(@as(?u64, null), conn.pending_ack_largest);
    try std.testing.expectEqual(@as(u64, 0), conn.next_peer_packet_number);
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

test "STREAM opens lower-numbered peer streams of the same type" {
    var server = try QuicConnection.init(std.testing.allocator, .server, .{
        .initial_max_streams_bidi = 3,
        .initial_max_streams_uni = 3,
    });
    defer server.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 8,
        .offset = 0,
        .fin = false,
        .data = "bidi",
    } });
    try server.processDatagram(0, out.getWritten());

    try std.testing.expect(server.findRecvStream(0) != null);
    try std.testing.expect(server.findRecvStream(4) != null);
    try std.testing.expect(server.findRecvStream(8) != null);

    var read_buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try server.recvOnStream(0, &read_buf));
    try std.testing.expectEqual(@as(?usize, null), try server.recvOnStream(4, &read_buf));
    const n = (try server.recvOnStream(8, &read_buf)).?;
    try std.testing.expectEqualStrings("bidi", read_buf[0..n]);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 10,
        .offset = 0,
        .fin = true,
        .data = "uni",
    } });
    try server.processDatagram(1, out.getWritten());

    try std.testing.expect(server.findRecvStream(2) != null);
    try std.testing.expect(server.findRecvStream(6) != null);
    try std.testing.expect(server.findRecvStream(10) != null);
    try std.testing.expectEqual(@as(?usize, null), try server.recvOnStream(2, &read_buf));
    try std.testing.expectEqual(@as(?usize, null), try server.recvOnStream(6, &read_buf));
    const uni_len = (try server.recvOnStream(10, &read_buf)).?;
    try std.testing.expectEqualStrings("uni", read_buf[0..uni_len]);
}

test "processDatagram discards duplicate STREAM data without growing flow control" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "hello",
    } });
    const original = try std.testing.allocator.dupe(u8, out.getWritten());
    defer std.testing.allocator.free(original);
    try conn.processDatagram(0, original);
    try std.testing.expectEqual(@as(u64, 5), conn.recv_data_bytes);

    try conn.processDatagram(1, original);
    try std.testing.expectEqual(@as(u64, 5), conn.recv_data_bytes);
    try std.testing.expectEqualStrings("hello", conn.recv_streams.items[0].data.items);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 3,
        .fin = false,
        .data = "lo!",
    } });
    try conn.processDatagram(2, out.getWritten());
    try std.testing.expectEqual(@as(u64, 6), conn.recv_data_bytes);

    var read_buf: [8]u8 = undefined;
    const n = (try conn.recvOnStream(0, &read_buf)).?;
    try std.testing.expectEqualStrings("hello!", read_buf[0..n]);
}

test "processDatagram accepts duplicate pending STREAM frame and rejects conflicting overlap" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 5,
        .fin = false,
        .data = "tail",
    } });
    const pending = try std.testing.allocator.dupe(u8, out.getWritten());
    defer std.testing.allocator.free(pending);
    try conn.processDatagram(0, pending);
    try std.testing.expectEqual(@as(u64, 4), conn.recv_data_bytes);
    try std.testing.expectEqual(@as(usize, 1), conn.recv_streams.items[0].pending.items.len);

    try conn.processDatagram(1, pending);
    try std.testing.expectEqual(@as(u64, 4), conn.recv_data_bytes);
    try std.testing.expectEqual(@as(usize, 1), conn.recv_streams.items[0].pending.items.len);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 7,
        .fin = false,
        .data = "xx",
    } });
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(2, out.getWritten()));
    try std.testing.expectEqual(@as(u64, 4), conn.recv_data_bytes);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "head-",
    } });
    try conn.processDatagram(3, out.getWritten());
    try std.testing.expectEqual(@as(u64, 9), conn.recv_data_bytes);

    var read_buf: [16]u8 = undefined;
    const n = (try conn.recvOnStream(0, &read_buf)).?;
    try std.testing.expectEqualStrings("head-tail", read_buf[0..n]);
}

test "processDatagram rejects conflicting duplicate STREAM bytes" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{});
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "hello",
    } });
    try conn.processDatagram(0, out.getWritten());

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 3,
        .fin = false,
        .data = "xx",
    } });
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(1, out.getWritten()));
    try std.testing.expectEqual(@as(u64, 5), conn.recv_data_bytes);
    try std.testing.expectEqualStrings("hello", conn.recv_streams.items[0].data.items);
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

test "receive stream ignores data after RESET_STREAM within final size" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{
        .initial_max_data = 10,
        .initial_max_stream_data = 10,
    });
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = 7,
        .final_size = 5,
    } });
    try conn.processDatagram(0, out.getWritten());
    try std.testing.expectEqual(@as(u64, 5), conn.recv_data_bytes);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "abc",
    } });
    try conn.processDatagram(1, out.getWritten());
    try std.testing.expectEqual(@as(u64, 5), conn.recv_data_bytes);
    try std.testing.expectEqual(@as(usize, 0), conn.recv_streams.items[0].data.items.len);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 5,
        .fin = true,
        .data = "",
    } });
    try conn.processDatagram(2, out.getWritten());
    try std.testing.expectEqual(@as(?u64, 5), conn.recv_streams.items[0].final_size);
    try std.testing.expectEqual(@as(?u64, 7), conn.recv_streams.items[0].reset_error_code);

    var read_buf: [8]u8 = undefined;
    try std.testing.expectError(error.StreamClosed, conn.recvOnStream(0, &read_buf));
}

test "receive stream rejects data after RESET_STREAM that changes final size" {
    var conn = try QuicConnection.init(std.testing.allocator, .server, .{
        .initial_max_data = 10,
        .initial_max_stream_data = 10,
    });
    defer conn.deinit();

    var datagram: [64]u8 = undefined;
    var out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = 7,
        .final_size = 5,
    } });
    try conn.processDatagram(0, out.getWritten());

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 5,
        .fin = false,
        .data = "!",
    } });
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(1, out.getWritten()));
    try std.testing.expectEqual(@as(u64, 5), conn.recv_data_bytes);
    try std.testing.expectEqual(@as(?u64, 5), conn.recv_streams.items[0].final_size);
    try std.testing.expectEqual(@as(?u64, 7), conn.recv_streams.items[0].reset_error_code);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 4,
        .fin = true,
        .data = "",
    } });
    try std.testing.expectError(error.InvalidPacket, conn.processDatagram(1, out.getWritten()));
    try std.testing.expectEqual(@as(u64, 5), conn.recv_data_bytes);
    try std.testing.expectEqual(@as(?u64, 5), conn.recv_streams.items[0].final_size);
    try std.testing.expectEqual(@as(?u64, 7), conn.recv_streams.items[0].reset_error_code);
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

test "receive stream discards late STREAM after all data is received" {
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
    try std.testing.expectEqual(@as(u64, 5), conn.recv_data_bytes);

    out = buffer.fixedWriter(&datagram);
    try frame.encodeFrame(out.writer(), .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "HELLO",
    } });
    try conn.processDatagram(1, out.getWritten());
    try std.testing.expectEqual(@as(u64, 5), conn.recv_data_bytes);
    try std.testing.expectEqualStrings("hello", conn.recv_streams.items[0].data.items);

    var read_buf: [8]u8 = undefined;
    const n = (try conn.recvOnStream(0, &read_buf)).?;
    try std.testing.expectEqualStrings("hello", read_buf[0..n]);
    try std.testing.expect(try conn.recvStreamFinished(0));
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
