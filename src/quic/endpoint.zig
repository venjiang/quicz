const std = @import("std");
const address_validation_token = @import("address_validation_token.zig");
const buffer = @import("buffer.zig");
const packet = @import("packet.zig");

/// Maximum QUIC connection ID length from RFC 9000.
pub const max_connection_id_len: usize = 20;
/// QUIC stateless reset token length.
pub const stateless_reset_token_len: usize = packet.stateless_reset_token_len;
/// Binary IPv4 peer address binding length used by address-validation tokens.
pub const address_validation_peer_binding_len: usize = 6;

/// Errors returned by the in-memory endpoint routing table.
pub const RouteError = error{
    InvalidConnectionIdLength,
    InvalidConnectionIdSequence,
    InvalidDatagram,
    InvalidVersionList,
    InvalidResetSize,
    BufferTooSmall,
    DuplicateConnectionId,
    UnknownConnectionId,
    AmbiguousConnectionId,
    ActiveMigrationDisabled,
    PathMismatch,
    OutOfMemory,
};

/// IPv4 UDP address used by the first endpoint-routing skeleton.
pub const Udp4Address = struct {
    octets: [4]u8,
    port: u16,

    /// Construct an IPv4 UDP address from network-order octets and a port.
    pub fn init(octets: [4]u8, port: u16) Udp4Address {
        return .{ .octets = octets, .port = port };
    }

    /// Return whether both address and UDP port are identical.
    pub fn eql(self: Udp4Address, other: Udp4Address) bool {
        return self.port == other.port and std.mem.eql(u8, &self.octets, &other.octets);
    }

    /// Return the stable binary address binding used for address-validation tokens.
    ///
    /// The binding is IPv4 octets followed by the UDP port in network byte
    /// order. It is intended as the `peer_address` input for
    /// `quicz.address_validation_token`, avoiding text formatting differences
    /// in endpoint policy code.
    pub fn addressValidationBinding(self: Udp4Address) [address_validation_peer_binding_len]u8 {
        var binding: [address_validation_peer_binding_len]u8 = undefined;
        @memcpy(binding[0..4], &self.octets);
        std.mem.writeInt(u16, binding[4..6], self.port, .big);
        return binding;
    }
};

/// Local/remote IPv4 UDP tuple used to route one received datagram.
pub const Udp4Tuple = struct {
    local: Udp4Address,
    remote: Udp4Address,

    /// Return whether local and remote addresses both match.
    pub fn eql(self: Udp4Tuple, other: Udp4Tuple) bool {
        return self.local.eql(other.local) and self.remote.eql(other.remote);
    }

    /// Return the remote peer binding for address-validation tokens.
    ///
    /// QUIC address validation proves reachability of the peer address. The
    /// local socket address remains part of routing policy but is not encoded
    /// into this peer-address token binding.
    pub fn peerAddressValidationBinding(self: Udp4Tuple) [address_validation_peer_binding_len]u8 {
        return self.remote.addressValidationBinding();
    }
};

/// Fixed-storage QUIC connection ID.
pub const ConnectionId = struct {
    bytes: [max_connection_id_len]u8 = undefined,
    len: u8 = 0,

    /// Copy a QUIC connection ID into bounded fixed storage.
    pub fn init(value: []const u8) RouteError!ConnectionId {
        if (value.len > max_connection_id_len) return error.InvalidConnectionIdLength;
        var result = ConnectionId{ .len = @intCast(value.len) };
        @memcpy(result.bytes[0..value.len], value);
        return result;
    }

    /// Borrow the valid connection ID bytes.
    pub fn asSlice(self: *const ConnectionId) []const u8 {
        return self.bytes[0..self.len];
    }

    /// Return whether this connection ID matches a byte slice exactly.
    pub fn eqlSlice(self: *const ConnectionId, value: []const u8) bool {
        return std.mem.eql(u8, self.asSlice(), value);
    }
};

/// Routing policy associated with a destination connection ID.
pub const RouteOptions = struct {
    /// Optional NEW_CONNECTION_ID sequence number for this destination CID.
    sequence_number: ?u64 = null,
    /// Reject packets from a different UDP tuple while active migration is disabled.
    active_migration_disabled: bool = false,
    /// Optional stateless reset token associated with this destination CID.
    stateless_reset_token: ?[stateless_reset_token_len]u8 = null,
};

/// Result of endpoint routing before packet protection is removed.
pub const RouteResult = struct {
    /// Application-owned connection handle associated with the destination CID.
    connection_id: u64,
    /// Optional NEW_CONNECTION_ID sequence number associated with the route.
    sequence_number: ?u64,
    /// Destination connection ID used to select the connection.
    destination_connection_id: ConnectionId,
    /// True when the datagram arrived on a different UDP tuple than the registered path.
    path_changed: bool,
};

/// Endpoint-level information needed to accept a new server-side Initial.
///
/// Slices borrow from the triggering datagram. The destination CID is the
/// client's Original Destination Connection ID; the source CID is the peer CID
/// that a server uses as the destination CID for its first response.
pub const InitialAcceptResult = struct {
    /// UDP path that carried the new Initial.
    path: Udp4Tuple,
    /// QUIC version from the long header.
    version: packet.Version,
    /// Destination Connection ID from the client Initial.
    original_destination_connection_id: []const u8,
    /// Source Connection ID from the client Initial.
    source_connection_id: []const u8,
    /// Initial token, if present.
    token: []const u8,
};

/// Endpoint-level action for one received UDP datagram.
pub const DatagramAction = union(enum) {
    /// Deliver the datagram to a caller-owned connection.
    routed: RouteResult,
    /// Accept this supported-version Initial as a new server-side connection.
    accept_initial: InitialAcceptResult,
    /// Send this Version Negotiation datagram on the same UDP path.
    version_negotiation: []const u8,
    /// Send this stateless reset datagram on the same UDP path.
    stateless_reset: []const u8,
    /// Drop the datagram without a connection delivery or reset response.
    dropped,
};

/// Version-independent long-header connection IDs from the first packet in a datagram.
pub const LongHeaderConnectionIds = struct {
    /// QUIC Version field carried by the long header.
    version: packet.Version,
    /// Destination Connection ID slice borrowed from the datagram.
    dcid: []const u8,
    /// Source Connection ID slice borrowed from the datagram.
    scid: []const u8,
};

/// Options for endpoint-level connection ID replacement registration.
pub const ReplacementRouteOptions = struct {
    /// Reject packets from a different UDP tuple while active migration is disabled.
    active_migration_disabled: bool = false,
    /// Optional stateless reset token associated with the replacement CID.
    stateless_reset_token: ?[stateless_reset_token_len]u8 = null,
};

/// Result of registering a replacement destination connection ID.
pub const ReplacementResult = struct {
    /// NEW_CONNECTION_ID sequence number associated with the replacement CID.
    sequence_number: u64,
    /// Retire Prior To threshold applied after the replacement route was registered.
    retire_prior_to: u64,
    /// Number of older active routes retired by the threshold.
    retired_count: usize,
};

/// Per-path ECN validation state owned by endpoint policy.
pub const EcnPathValidationState = enum {
    /// ECN has not yet been validated on this UDP path.
    unknown,
    /// ACK_ECN counters validated ECN use on this UDP path.
    capable,
    /// ECN validation failed on this UDP path; future packets should not use ECT.
    failed,
};

const EcnPathEntry = struct {
    path: Udp4Tuple,
    state: EcnPathValidationState,
};

/// In-memory endpoint ECN policy keyed by UDP path identity.
///
/// The connection skeleton validates ACK_ECN counters per packet number space.
/// This endpoint helper keeps the resulting ECN decision scoped to a concrete
/// UDP tuple so migration can re-enter validation on the new path without
/// inheriting a failed or capable state from a previous path.
pub const EcnPathPolicy = struct {
    allocator: std.mem.Allocator,
    paths: std.ArrayList(EcnPathEntry) = .empty,

    /// Create an empty endpoint ECN path policy.
    pub fn init(allocator: std.mem.Allocator) EcnPathPolicy {
        return .{ .allocator = allocator };
    }

    /// Release stored path state.
    pub fn deinit(self: *EcnPathPolicy) void {
        self.paths.deinit(self.allocator);
    }

    /// Return the ECN state for a path, or `unknown` when it has not been seen.
    pub fn stateForPath(self: *const EcnPathPolicy, path: Udp4Tuple) EcnPathValidationState {
        const index = self.findPathIndex(path) orelse return .unknown;
        return self.paths.items[index].state;
    }

    /// Return whether endpoint packetization may set an ECT codepoint on this path.
    pub fn mayUseEct(self: *const EcnPathPolicy, path: Udp4Tuple) bool {
        return self.stateForPath(path) != .failed;
    }

    /// Store the current ECN validation state for one UDP path.
    pub fn setStateForPath(
        self: *EcnPathPolicy,
        path: Udp4Tuple,
        state: EcnPathValidationState,
    ) RouteError!void {
        if (self.findPathIndex(path)) |index| {
            self.paths.items[index].state = state;
            return;
        }
        self.paths.append(self.allocator, .{ .path = path, .state = state }) catch return error.OutOfMemory;
    }

    /// Remove stored ECN state for one UDP path.
    pub fn resetPath(self: *EcnPathPolicy, path: Udp4Tuple) bool {
        const index = self.findPathIndex(path) orelse return false;
        _ = self.paths.orderedRemove(index);
        return true;
    }

    fn findPathIndex(self: *const EcnPathPolicy, path: Udp4Tuple) ?usize {
        for (self.paths.items, 0..) |entry, index| {
            if (entry.path.eql(path)) return index;
        }
        return null;
    }
};

const Route = struct {
    connection_id: u64,
    sequence_number: ?u64,
    destination_connection_id: ConnectionId,
    path: Udp4Tuple,
    active_migration_disabled: bool,
};

const StatelessResetRoute = struct {
    destination_connection_id: ConnectionId,
    token: [stateless_reset_token_len]u8,
};

/// Snapshot of address-validation token secrets for external persistence.
///
/// The snapshot contains only secrets. Replay-filter state is exported through
/// `AddressValidationPolicy.exportReplayFilter()` so callers can choose
/// separate storage and retention policies for token secrets and replay state.
pub const AddressValidationSecretSet = struct {
    /// Current secret used to issue new tokens.
    current_secret: address_validation_token.Secret,
    /// Previous secrets retained for validating already-issued tokens.
    previous_secrets: []address_validation_token.Secret,

    /// Release the owned previous-secret snapshot.
    pub fn deinit(self: *AddressValidationSecretSet, allocator: std.mem.Allocator) void {
        allocator.free(self.previous_secrets);
        self.previous_secrets = &.{};
    }
};

/// In-memory endpoint address-validation policy.
///
/// The policy owns the active token secret, a bounded set of previous secrets
/// for rotation, and a replay filter. It can export/import the token secret set
/// and replay-filter fingerprints for external persistence or worker
/// distribution.
pub const AddressValidationPolicy = struct {
    allocator: std.mem.Allocator,
    current_secret: address_validation_token.Secret,
    max_previous_secrets: usize,
    previous_secrets: std.ArrayList(address_validation_token.Secret) = .empty,
    replay_filter: address_validation_token.ReplayFilter,

    /// Create an endpoint token policy with one active secret.
    pub fn init(
        allocator: std.mem.Allocator,
        current_secret: address_validation_token.Secret,
        options: AddressValidationPolicyOptions,
    ) AddressValidationPolicy {
        return .{
            .allocator = allocator,
            .current_secret = current_secret,
            .max_previous_secrets = options.max_previous_secrets,
            .replay_filter = address_validation_token.ReplayFilter.init(allocator, options.max_replay_entries),
        };
    }

    /// Create an endpoint token policy from an externally persisted secret set.
    ///
    /// Previous secrets are copied and trimmed to the configured retention
    /// limit, keeping the newest retained values from the end of the snapshot.
    /// Replay-filter state starts empty; use
    /// `initWithSecretSetAndReplayFilter()` when restoring replay state too.
    pub fn initWithSecretSet(
        allocator: std.mem.Allocator,
        secret_set: AddressValidationSecretSet,
        options: AddressValidationPolicyOptions,
    ) address_validation_token.Error!AddressValidationPolicy {
        var policy = AddressValidationPolicy.init(allocator, secret_set.current_secret, options);
        errdefer policy.deinit();

        const retained = if (secret_set.previous_secrets.len > options.max_previous_secrets)
            secret_set.previous_secrets[secret_set.previous_secrets.len - options.max_previous_secrets ..]
        else
            secret_set.previous_secrets;
        policy.previous_secrets.appendSlice(allocator, retained) catch return error.OutOfMemory;
        return policy;
    }

    /// Create an endpoint token policy from persisted secrets and replay state.
    ///
    /// Replay fingerprints are copied and trimmed to `max_replay_entries`,
    /// keeping newest entries from the end of the snapshot.
    pub fn initWithSecretSetAndReplayFilter(
        allocator: std.mem.Allocator,
        secret_set: AddressValidationSecretSet,
        replay_snapshot: address_validation_token.ReplayFilterSnapshot,
        options: AddressValidationPolicyOptions,
    ) address_validation_token.Error!AddressValidationPolicy {
        var policy = try AddressValidationPolicy.initWithSecretSet(allocator, secret_set, options);
        errdefer policy.deinit();

        var replay_filter = try address_validation_token.ReplayFilter.initWithSnapshot(
            allocator,
            options.max_replay_entries,
            replay_snapshot,
        );
        errdefer replay_filter.deinit();

        policy.replay_filter.deinit();
        policy.replay_filter = replay_filter;
        return policy;
    }

    /// Release endpoint token-policy storage.
    pub fn deinit(self: *AddressValidationPolicy) void {
        self.replay_filter.deinit();
        self.previous_secrets.deinit(self.allocator);
    }

    /// Return the number of retained previous token secrets.
    pub fn previousSecretCount(self: *const AddressValidationPolicy) usize {
        return self.previous_secrets.items.len;
    }

    /// Return the number of retained replay fingerprints.
    pub fn replayFilterEntryCount(self: *const AddressValidationPolicy) usize {
        return self.replay_filter.entryCount();
    }

    /// Export the active and retained previous secrets for external storage.
    pub fn exportSecretSet(self: *const AddressValidationPolicy, allocator: std.mem.Allocator) address_validation_token.Error!AddressValidationSecretSet {
        const previous = allocator.alloc(address_validation_token.Secret, self.previous_secrets.items.len) catch return error.OutOfMemory;
        @memcpy(previous, self.previous_secrets.items);
        return .{
            .current_secret = self.current_secret,
            .previous_secrets = previous,
        };
    }

    /// Export replay fingerprints for external storage or worker distribution.
    pub fn exportReplayFilter(self: *const AddressValidationPolicy, allocator: std.mem.Allocator) address_validation_token.Error!address_validation_token.ReplayFilterSnapshot {
        return self.replay_filter.exportSnapshot(allocator);
    }

    /// Rotate to a new active secret while retaining the previous one.
    ///
    /// Retained previous secrets allow already-issued tokens to validate until
    /// their encoded lifetimes expire. When the configured retention limit is
    /// exceeded, the oldest previous secret is dropped.
    pub fn rotateSecret(
        self: *AddressValidationPolicy,
        new_secret: address_validation_token.Secret,
    ) address_validation_token.Error!void {
        if (std.crypto.timing_safe.eql(address_validation_token.Secret, self.current_secret, new_secret)) return;
        if (self.max_previous_secrets != 0) {
            self.previous_secrets.ensureUnusedCapacity(self.allocator, 1) catch return error.OutOfMemory;
            self.previous_secrets.appendAssumeCapacity(self.current_secret);
            while (self.previous_secrets.items.len > self.max_previous_secrets) {
                _ = self.previous_secrets.orderedRemove(0);
            }
        }
        self.current_secret = new_secret;
    }

    /// Issue an address-validation token bound to a UDP peer path.
    pub fn issueTokenForPath(
        self: *const AddressValidationPolicy,
        allocator: std.mem.Allocator,
        kind: address_validation_token.Kind,
        now_millis: i64,
        lifetime_millis: u64,
        path: Udp4Tuple,
        nonce: address_validation_token.Nonce,
    ) address_validation_token.Error![]u8 {
        return self.issueTokenForPathForVersion(allocator, kind, .v1, now_millis, lifetime_millis, path, nonce);
    }

    /// Issue an address-validation token for a specific originating QUIC version.
    pub fn issueTokenForPathForVersion(
        self: *const AddressValidationPolicy,
        allocator: std.mem.Allocator,
        kind: address_validation_token.Kind,
        originating_version: packet.Version,
        now_millis: i64,
        lifetime_millis: u64,
        path: Udp4Tuple,
        nonce: address_validation_token.Nonce,
    ) address_validation_token.Error![]u8 {
        const binding = path.peerAddressValidationBinding();
        return address_validation_token.encode(allocator, self.current_secret, .{
            .kind = kind,
            .originating_version = originating_version,
            .issued_millis = now_millis,
            .lifetime_millis = lifetime_millis,
            .peer_address = &binding,
            .nonce = nonce,
        });
    }

    /// Validate an address token against this endpoint path and record replay state.
    ///
    /// Successful validation remembers the token fingerprint. A later attempt
    /// to validate the same token returns `error.TokenReplay`.
    pub fn validateTokenForPath(
        self: *AddressValidationPolicy,
        expected_kind: address_validation_token.Kind,
        now_millis: i64,
        path: Udp4Tuple,
        encoded: []const u8,
    ) address_validation_token.Error!address_validation_token.Validation {
        return self.validateTokenForPathForVersion(expected_kind, .v1, now_millis, path, encoded);
    }

    /// Validate a version-bound address token and record replay state.
    pub fn validateTokenForPathForVersion(
        self: *AddressValidationPolicy,
        expected_kind: address_validation_token.Kind,
        expected_originating_version: packet.Version,
        now_millis: i64,
        path: Udp4Tuple,
        encoded: []const u8,
    ) address_validation_token.Error!address_validation_token.Validation {
        const validation = try self.validateTokenForPathWithoutReplayForVersion(
            expected_kind,
            expected_originating_version,
            now_millis,
            path,
            encoded,
        );
        try self.replay_filter.rememberValidated(encoded);
        return validation;
    }

    /// Validate an address token against this endpoint path without recording replay state.
    pub fn validateTokenForPathWithoutReplay(
        self: *const AddressValidationPolicy,
        expected_kind: address_validation_token.Kind,
        now_millis: i64,
        path: Udp4Tuple,
        encoded: []const u8,
    ) address_validation_token.Error!address_validation_token.Validation {
        return self.validateTokenForPathWithoutReplayForVersion(expected_kind, .v1, now_millis, path, encoded);
    }

    /// Validate a version-bound address token without recording replay state.
    pub fn validateTokenForPathWithoutReplayForVersion(
        self: *const AddressValidationPolicy,
        expected_kind: address_validation_token.Kind,
        expected_originating_version: packet.Version,
        now_millis: i64,
        path: Udp4Tuple,
        encoded: []const u8,
    ) address_validation_token.Error!address_validation_token.Validation {
        const binding = path.peerAddressValidationBinding();
        return self.validateTokenForBinding(expected_kind, expected_originating_version, now_millis, &binding, encoded);
    }

    fn validateTokenForBinding(
        self: *const AddressValidationPolicy,
        expected_kind: address_validation_token.Kind,
        expected_originating_version: packet.Version,
        now_millis: i64,
        peer_address: []const u8,
        encoded: []const u8,
    ) address_validation_token.Error!address_validation_token.Validation {
        var authenticated_error: ?address_validation_token.Error = null;
        if (address_validation_token.validateForVersion(self.current_secret, expected_kind, expected_originating_version, now_millis, peer_address, encoded)) |validation| {
            return validation;
        } else |err| switch (err) {
            error.InvalidToken => {},
            error.TokenExpired, error.TokenNotYetValid => if (authenticated_error == null) {
                authenticated_error = err;
            },
            error.TokenReplay, error.OutOfMemory => return err,
        }

        var index = self.previous_secrets.items.len;
        while (index > 0) {
            index -= 1;
            if (address_validation_token.validateForVersion(self.previous_secrets.items[index], expected_kind, expected_originating_version, now_millis, peer_address, encoded)) |validation| {
                return validation;
            } else |err| switch (err) {
                error.InvalidToken => {},
                error.TokenExpired, error.TokenNotYetValid => if (authenticated_error == null) {
                    authenticated_error = err;
                },
                error.TokenReplay, error.OutOfMemory => return err,
            }
        }

        if (authenticated_error) |err| return err;
        return error.InvalidToken;
    }
};

/// Options for `AddressValidationPolicy`.
pub const AddressValidationPolicyOptions = struct {
    /// Number of previous token secrets retained for validation after rotation.
    max_previous_secrets: usize = 1,
    /// Number of validated token fingerprints kept for replay rejection.
    max_replay_entries: usize = 1024,
};

/// In-memory QUIC endpoint routing table.
///
/// This table does not perform socket I/O and does not own `QuicConnection`
/// instances. It maps destination connection IDs to caller-owned connection
/// handles, checks the IPv4 UDP tuple associated with the route, and can route
/// either long-header datagrams with an encoded DCID length or short-header
/// datagrams by matching registered CID prefixes.
pub const EndpointRouter = struct {
    allocator: std.mem.Allocator,
    routes: std.ArrayList(Route) = .empty,
    reset_tokens: std.ArrayList(StatelessResetRoute) = .empty,

    /// Create an empty endpoint routing table.
    pub fn init(allocator: std.mem.Allocator) EndpointRouter {
        return .{ .allocator = allocator };
    }

    /// Release all route storage.
    pub fn deinit(self: *EndpointRouter) void {
        self.reset_tokens.deinit(self.allocator);
        self.routes.deinit(self.allocator);
    }

    /// Return the number of active destination-CID routes.
    pub fn routeCount(self: *const EndpointRouter) usize {
        return self.routes.items.len;
    }

    /// Return the number of destination CIDs with stateless reset tokens.
    pub fn statelessResetTokenCount(self: *const EndpointRouter) usize {
        return self.reset_tokens.items.len;
    }

    /// Register a destination connection ID for a caller-owned connection handle.
    pub fn registerConnectionId(
        self: *EndpointRouter,
        connection_id: u64,
        destination_connection_id: []const u8,
        path: Udp4Tuple,
        options: RouteOptions,
    ) RouteError!void {
        const cid = try ConnectionId.init(destination_connection_id);
        if (cid.len == 0) {
            if (options.sequence_number != null) return error.InvalidConnectionIdLength;
            if (options.stateless_reset_token != null) return error.InvalidConnectionIdLength;
            if (self.findZeroLengthRouteIndex(path) != null) return error.DuplicateConnectionId;
        } else if (self.findRouteIndex(cid) != null) return error.DuplicateConnectionId;
        if (options.sequence_number) |sequence_number| {
            if (self.findRouteSequenceIndex(connection_id, sequence_number) != null) return error.DuplicateConnectionId;
        }
        if (options.stateless_reset_token) |token| {
            try self.ensureStatelessResetTokenAllowed(cid, token);
        }
        self.routes.append(self.allocator, .{
            .connection_id = connection_id,
            .sequence_number = options.sequence_number,
            .destination_connection_id = cid,
            .path = path,
            .active_migration_disabled = options.active_migration_disabled,
        }) catch return error.OutOfMemory;
        errdefer _ = self.routes.orderedRemove(self.routes.items.len - 1);
        if (options.stateless_reset_token) |token| {
            try self.registerStatelessResetTokenForCid(cid, token);
        }
    }

    /// Register a stateless reset token for a destination CID.
    ///
    /// Tokens survive active route retirement so a later packet for the retired
    /// CID can be answered by endpoint policy without owning a connection.
    pub fn registerStatelessResetToken(
        self: *EndpointRouter,
        destination_connection_id: []const u8,
        token: [stateless_reset_token_len]u8,
    ) RouteError!void {
        const cid = try ConnectionId.init(destination_connection_id);
        if (cid.len == 0) return error.InvalidConnectionIdLength;
        try self.ensureStatelessResetTokenAllowed(cid, token);
        try self.registerStatelessResetTokenForCid(cid, token);
    }

    /// Remove a destination connection ID route.
    pub fn retireConnectionId(self: *EndpointRouter, destination_connection_id: []const u8) RouteError!bool {
        const cid = try ConnectionId.init(destination_connection_id);
        if (cid.len == 0) return error.AmbiguousConnectionId;
        const index = self.findRouteIndex(cid) orelse return false;
        _ = self.routes.orderedRemove(index);
        return true;
    }

    /// Remove a destination connection ID route bound to a UDP tuple.
    pub fn retireConnectionIdOnPath(
        self: *EndpointRouter,
        destination_connection_id: []const u8,
        path: Udp4Tuple,
    ) RouteError!bool {
        const cid = try ConnectionId.init(destination_connection_id);
        const index = if (cid.len == 0) self.findZeroLengthRouteIndex(path) else self.findRouteIndex(cid);
        const route_index = index orelse return false;
        _ = self.routes.orderedRemove(route_index);
        return true;
    }

    /// Remove a route by caller-owned connection handle and NEW_CONNECTION_ID sequence number.
    pub fn retireConnectionIdSequence(
        self: *EndpointRouter,
        connection_id: u64,
        sequence_number: u64,
    ) bool {
        const index = self.findRouteSequenceIndex(connection_id, sequence_number) orelse return false;
        _ = self.routes.orderedRemove(index);
        return true;
    }

    /// Remove routes whose sequence number is lower than `retire_prior_to`.
    ///
    /// This mirrors the NEW_CONNECTION_ID Retire Prior To threshold while
    /// leaving stateless reset tokens available for later inactive-CID packets.
    pub fn retireConnectionIdSequencesBefore(
        self: *EndpointRouter,
        connection_id: u64,
        retire_prior_to: u64,
    ) usize {
        var retired: usize = 0;
        var index: usize = 0;
        while (index < self.routes.items.len) {
            const route = self.routes.items[index];
            const sequence_number = route.sequence_number orelse {
                index += 1;
                continue;
            };
            if (route.connection_id != connection_id or sequence_number >= retire_prior_to) {
                index += 1;
                continue;
            }
            _ = self.routes.orderedRemove(index);
            retired += 1;
        }
        return retired;
    }

    /// Register a replacement destination CID and retire older sequence routes.
    ///
    /// This mirrors NEW_CONNECTION_ID replacement semantics at endpoint routing
    /// scope. The replacement route is installed first so the endpoint keeps at
    /// least one active route while applying `retire_prior_to`; the threshold
    /// must not exceed the replacement sequence number.
    pub fn registerReplacementConnectionId(
        self: *EndpointRouter,
        connection_id: u64,
        destination_connection_id: []const u8,
        path: Udp4Tuple,
        sequence_number: u64,
        retire_prior_to: u64,
        options: ReplacementRouteOptions,
    ) RouteError!ReplacementResult {
        if (retire_prior_to > sequence_number) return error.InvalidConnectionIdSequence;
        try self.registerConnectionId(connection_id, destination_connection_id, path, .{
            .sequence_number = sequence_number,
            .active_migration_disabled = options.active_migration_disabled,
            .stateless_reset_token = options.stateless_reset_token,
        });
        return .{
            .sequence_number = sequence_number,
            .retire_prior_to = retire_prior_to,
            .retired_count = self.retireConnectionIdSequencesBefore(connection_id, retire_prior_to),
        };
    }

    /// Replace an Initial route's destination CID with the Retry Source CID.
    ///
    /// After a server sends a Retry packet, the client uses the Retry Source
    /// Connection ID as the Destination Connection ID on the next Initial. This
    /// helper keeps the same caller-owned connection handle and UDP path while
    /// making that route switch explicit in endpoint policy. It is only for
    /// Initial routes, so routes created from NEW_CONNECTION_ID sequence numbers
    /// are rejected.
    pub fn switchInitialDestinationConnectionIdAfterRetry(
        self: *EndpointRouter,
        original_destination_connection_id: []const u8,
        retry_source_connection_id: []const u8,
        path: Udp4Tuple,
    ) RouteError!RouteResult {
        const original_cid = try ConnectionId.init(original_destination_connection_id);
        const retry_cid = try ConnectionId.init(retry_source_connection_id);
        const index = if (original_cid.len == 0)
            self.findZeroLengthRouteIndex(path) orelse return error.UnknownConnectionId
        else
            self.findRouteIndex(original_cid) orelse return error.UnknownConnectionId;
        const route = &self.routes.items[index];
        if (!route.path.eql(path)) return error.PathMismatch;
        if (route.sequence_number != null) return error.InvalidConnectionIdSequence;

        const duplicate_index = if (retry_cid.len == 0) self.findZeroLengthRouteIndex(path) else self.findRouteIndex(retry_cid);
        if (duplicate_index) |existing_index| {
            if (existing_index != index) return error.DuplicateConnectionId;
        }

        route.destination_connection_id = retry_cid;
        return resultForRoute(route.*, path);
    }

    /// Commit a caller-validated migration to a server preferred address.
    ///
    /// The QUIC transport parameter carries a preferred-address connection ID
    /// and stateless reset token. After the caller validates the preferred UDP
    /// path, this helper installs the preferred route for the same
    /// caller-owned connection handle and retires the previous active route.
    /// Socket I/O and path validation remain outside this in-memory policy.
    pub fn commitPreferredAddressMigration(
        self: *EndpointRouter,
        current_destination_connection_id: []const u8,
        current_path: Udp4Tuple,
        preferred_destination_connection_id: []const u8,
        preferred_path: Udp4Tuple,
        preferred_stateless_reset_token: [stateless_reset_token_len]u8,
    ) RouteError!RouteResult {
        const current_cid = try ConnectionId.init(current_destination_connection_id);
        const preferred_cid = try ConnectionId.init(preferred_destination_connection_id);
        if (preferred_cid.len == 0) return error.InvalidConnectionIdLength;

        const current_index = self.findRouteIndexForPath(current_cid, current_path) orelse return error.UnknownConnectionId;
        const current_route = self.routes.items[current_index];
        if (!current_route.path.eql(current_path)) return error.PathMismatch;

        try self.registerConnectionId(current_route.connection_id, preferred_cid.asSlice(), preferred_path, .{
            .active_migration_disabled = current_route.active_migration_disabled,
            .stateless_reset_token = preferred_stateless_reset_token,
        });
        _ = self.routes.orderedRemove(current_index);

        const preferred_index = self.findRouteIndexForPath(preferred_cid, preferred_path) orelse return error.UnknownConnectionId;
        return resultForRoute(self.routes.items[preferred_index], preferred_path);
    }

    /// Move a route to a newly validated UDP tuple.
    ///
    /// The caller is responsible for QUIC path validation and packet-number
    /// ordering. `current_path` must still match the route so a stale validation
    /// result cannot overwrite a newer path update.
    pub fn updateRoutePath(
        self: *EndpointRouter,
        destination_connection_id: []const u8,
        current_path: Udp4Tuple,
        new_path: Udp4Tuple,
    ) RouteError!RouteResult {
        const cid = try ConnectionId.init(destination_connection_id);
        const index = self.findRouteIndexForPath(cid, current_path) orelse return error.UnknownConnectionId;
        const route = &self.routes.items[index];
        if (!route.path.eql(current_path)) return error.PathMismatch;
        if (!route.path.eql(new_path) and route.active_migration_disabled) return error.ActiveMigrationDisabled;
        if (cid.len == 0 and !route.path.eql(new_path)) {
            if (self.findZeroLengthRouteIndex(new_path)) |existing_index| {
                if (existing_index != index) return error.DuplicateConnectionId;
            }
        }
        route.path = new_path;
        return resultForRoute(route.*, new_path);
    }

    /// Return a stateless reset token for a datagram that has no active route on this path.
    ///
    /// Active routes take precedence and return null. Long-header datagrams are
    /// matched by their encoded DCID. Short-header datagrams are matched against
    /// registered reset-token CID prefixes, with ambiguity rejected instead of
    /// guessing.
    pub fn statelessResetTokenForDatagram(
        self: *const EndpointRouter,
        path: Udp4Tuple,
        datagram: []const u8,
    ) RouteError!?[stateless_reset_token_len]u8 {
        if (datagram.len < 1) return error.InvalidDatagram;
        if ((datagram[0] & 0x80) != 0) {
            const dcid = try ConnectionId.init(try peekLongDestinationConnectionId(datagram));
            if (self.findRouteIndexForPath(dcid, path) != null) return null;
            const reset_index = self.findStatelessResetTokenIndex(dcid) orelse return null;
            return self.reset_tokens.items[reset_index].token;
        }

        if (try self.findShortRouteIndex(path, datagram)) |_| return null;
        const reset_index = (try self.findShortStatelessResetTokenIndex(datagram)) orelse return null;
        return self.reset_tokens.items[reset_index].token;
    }

    /// Write a stateless reset datagram for an inactive destination CID.
    ///
    /// The caller supplies unpredictable prefix bytes and owns the output
    /// buffer. Active routes return null, and the generated reset must be
    /// shorter than the triggering datagram so endpoint code cannot create a
    /// reset loop with another endpoint.
    pub fn writeStatelessResetForDatagram(
        self: *const EndpointRouter,
        out: []u8,
        path: Udp4Tuple,
        triggering_datagram: []const u8,
        unpredictable_prefix: []const u8,
    ) RouteError!?[]const u8 {
        const token = (try self.statelessResetTokenForDatagram(path, triggering_datagram)) orelse return null;
        if (unpredictable_prefix.len < packet.min_stateless_reset_datagram_len - stateless_reset_token_len) {
            return error.InvalidResetSize;
        }
        const reset_len = unpredictable_prefix.len + stateless_reset_token_len;
        if (reset_len >= triggering_datagram.len) return error.InvalidResetSize;
        if (out.len < reset_len) return error.BufferTooSmall;

        @memcpy(out[0..unpredictable_prefix.len], unpredictable_prefix);
        @memcpy(out[unpredictable_prefix.len..][0..stateless_reset_token_len], &token);
        return out[0..reset_len];
    }

    /// Decide endpoint receive handling for one UDP datagram.
    ///
    /// Active routes are returned for connection delivery. Unknown CIDs are
    /// answered with a stateless reset only when an inactive-CID token is known;
    /// otherwise the datagram is dropped. Malformed, ambiguous, or policy-
    /// rejected datagrams are surfaced as errors so callers do not accidentally
    /// reset packets that still belong to an active connection.
    pub fn handleDatagram(
        self: *const EndpointRouter,
        out: []u8,
        path: Udp4Tuple,
        datagram: []const u8,
        unpredictable_prefix: []const u8,
    ) RouteError!DatagramAction {
        if (self.routeDatagram(path, datagram)) |route| {
            return .{ .routed = route };
        } else |err| switch (err) {
            error.UnknownConnectionId => {},
            else => return err,
        }

        if (try self.writeStatelessResetForDatagram(out, path, datagram, unpredictable_prefix)) |reset| {
            return .{ .stateless_reset = reset };
        }
        return .dropped;
    }

    /// Decide endpoint receive handling with RFC 8999 Version Negotiation.
    ///
    /// If the datagram starts with a long header whose Version is unsupported,
    /// this writes a Version Negotiation response before route lookup. Short
    /// headers, Version Negotiation packets, and supported versions continue
    /// through normal route/reset/drop handling.
    pub fn handleDatagramWithVersionNegotiation(
        self: *const EndpointRouter,
        out: []u8,
        path: Udp4Tuple,
        datagram: []const u8,
        unpredictable_prefix: []const u8,
        supported_versions: []const packet.Version,
    ) RouteError!DatagramAction {
        if (try writeVersionNegotiationForUnsupportedVersion(out, datagram, supported_versions)) |response| {
            return .{ .version_negotiation = response };
        }
        const action = try self.handleDatagram(out, path, datagram, unpredictable_prefix);
        switch (action) {
            .dropped => {},
            else => return action,
        }
        if (try peekInitialAcceptDatagram(path, datagram, supported_versions)) |accept| {
            return .{ .accept_initial = accept };
        }
        return .dropped;
    }

    /// Route a datagram by peeking the destination connection ID.
    ///
    /// Long headers carry an explicit DCID length. Short headers do not, so the
    /// router matches the datagram against registered CIDs and rejects ambiguous
    /// prefix matches.
    pub fn routeDatagram(
        self: *const EndpointRouter,
        path: Udp4Tuple,
        datagram: []const u8,
    ) RouteError!RouteResult {
        if (datagram.len < 1) return error.InvalidDatagram;
        if ((datagram[0] & 0x80) != 0) {
            return self.routeConnectionId(try peekLongDestinationConnectionId(datagram), path);
        }
        return self.routeShortDatagram(path, datagram);
    }

    /// Route a datagram when the destination connection ID is already known.
    pub fn routeConnectionId(
        self: *const EndpointRouter,
        destination_connection_id: []const u8,
        path: Udp4Tuple,
    ) RouteError!RouteResult {
        const cid = try ConnectionId.init(destination_connection_id);
        const index = self.findRouteIndexForPath(cid, path) orelse return error.UnknownConnectionId;
        return resultForRoute(self.routes.items[index], path);
    }

    fn routeShortDatagram(self: *const EndpointRouter, path: Udp4Tuple, datagram: []const u8) RouteError!RouteResult {
        const index = (try self.findShortRouteIndex(path, datagram)) orelse return error.UnknownConnectionId;
        return resultForRoute(self.routes.items[index], path);
    }

    fn findShortRouteIndex(self: *const EndpointRouter, path: Udp4Tuple, datagram: []const u8) RouteError!?usize {
        var match_index: ?usize = null;
        for (self.routes.items, 0..) |route, index| {
            const cid = route.destination_connection_id.asSlice();
            if (cid.len == 0) {
                if (!route.path.eql(path)) continue;
            } else {
                if (datagram.len < 1 + cid.len) continue;
                if (!std.mem.eql(u8, cid, datagram[1..][0..cid.len])) continue;
            }
            if (match_index != null) return error.AmbiguousConnectionId;
            match_index = index;
        }
        return match_index;
    }

    fn findRouteIndexForPath(self: *const EndpointRouter, cid: ConnectionId, path: Udp4Tuple) ?usize {
        if (cid.len == 0) return self.findZeroLengthRouteIndex(path);
        return self.findRouteIndex(cid);
    }

    fn findRouteIndex(self: *const EndpointRouter, cid: ConnectionId) ?usize {
        for (self.routes.items, 0..) |route, index| {
            if (route.destination_connection_id.eqlSlice(cid.asSlice())) return index;
        }
        return null;
    }

    fn findRouteSequenceIndex(self: *const EndpointRouter, connection_id: u64, sequence_number: u64) ?usize {
        for (self.routes.items, 0..) |route, index| {
            if (route.connection_id != connection_id) continue;
            if (route.sequence_number == null or route.sequence_number.? != sequence_number) continue;
            return index;
        }
        return null;
    }

    fn findZeroLengthRouteIndex(self: *const EndpointRouter, path: Udp4Tuple) ?usize {
        for (self.routes.items, 0..) |route, index| {
            if (route.destination_connection_id.len == 0 and route.path.eql(path)) return index;
        }
        return null;
    }

    fn ensureStatelessResetTokenAllowed(
        self: *const EndpointRouter,
        cid: ConnectionId,
        token: [stateless_reset_token_len]u8,
    ) RouteError!void {
        for (self.reset_tokens.items) |reset_route| {
            const same_cid = reset_route.destination_connection_id.eqlSlice(cid.asSlice());
            const same_token = std.crypto.timing_safe.eql([stateless_reset_token_len]u8, reset_route.token, token);
            if (same_cid and !same_token) return error.DuplicateConnectionId;
            if (!same_cid and same_token) return error.DuplicateConnectionId;
        }
    }

    fn registerStatelessResetTokenForCid(
        self: *EndpointRouter,
        cid: ConnectionId,
        token: [stateless_reset_token_len]u8,
    ) RouteError!void {
        if (self.findStatelessResetTokenIndex(cid) != null) return;
        self.reset_tokens.append(self.allocator, .{
            .destination_connection_id = cid,
            .token = token,
        }) catch return error.OutOfMemory;
    }

    fn findStatelessResetTokenIndex(self: *const EndpointRouter, cid: ConnectionId) ?usize {
        for (self.reset_tokens.items, 0..) |reset_route, index| {
            if (reset_route.destination_connection_id.eqlSlice(cid.asSlice())) return index;
        }
        return null;
    }

    fn findShortStatelessResetTokenIndex(self: *const EndpointRouter, datagram: []const u8) RouteError!?usize {
        var match_index: ?usize = null;
        for (self.reset_tokens.items, 0..) |reset_route, index| {
            const cid = reset_route.destination_connection_id.asSlice();
            if (datagram.len < 1 + cid.len) continue;
            if (!std.mem.eql(u8, cid, datagram[1..][0..cid.len])) continue;
            if (match_index != null) return error.AmbiguousConnectionId;
            match_index = index;
        }
        return match_index;
    }
};

/// Write an RFC 8999 Version Negotiation packet for an unsupported long header.
///
/// Returns `null` for short headers, Version Negotiation packets, or versions
/// already present in `supported_versions`. The response echoes the received
/// Source CID as Destination CID and the received Destination CID as Source CID.
pub fn writeVersionNegotiationForUnsupportedVersion(
    out: []u8,
    datagram: []const u8,
    supported_versions: []const packet.Version,
) RouteError!?[]const u8 {
    if (datagram.len < 1) return error.InvalidDatagram;
    if ((datagram[0] & 0x80) == 0) return null;
    if (supported_versions.len == 0) return error.InvalidVersionList;
    for (supported_versions) |supported| {
        if (@intFromEnum(supported) == 0) return error.InvalidVersionList;
    }

    const ids = try peekLongHeaderConnectionIds(datagram);
    if (@intFromEnum(ids.version) == 0) return null;
    if (versionListContains(supported_versions, ids.version)) return null;

    var writer = buffer.fixedWriter(out);
    packet.encodeVersionNegotiationPacket(writer.writer(), .{
        .dcid = ids.scid,
        .scid = ids.dcid,
        .versions = supported_versions,
    }) catch |err| switch (err) {
        error.NoSpaceLeft => return error.BufferTooSmall,
        error.InvalidVersionList => return error.InvalidVersionList,
        error.InvalidConnectionIdLength => return error.InvalidConnectionIdLength,
        else => return error.InvalidDatagram,
    };
    return writer.getWritten();
}

/// Peek a supported-version client Initial that can create a server connection.
///
/// This helper only classifies complete Initial headers. It does not remove
/// packet protection, validate Retry/address tokens, or mutate route state.
/// Non-Initial long headers, unsupported versions, Version Negotiation packets,
/// and short headers return `null`.
pub fn peekInitialAcceptDatagram(
    path: Udp4Tuple,
    datagram: []const u8,
    supported_versions: []const packet.Version,
) RouteError!?InitialAcceptResult {
    if (datagram.len < 1) return error.InvalidDatagram;
    if ((datagram[0] & 0x80) == 0) return null;
    if (supported_versions.len == 0) return error.InvalidVersionList;
    for (supported_versions) |supported| {
        if (@intFromEnum(supported) == 0) return error.InvalidVersionList;
    }

    var reader = buffer.fixedReader(datagram);
    const first_byte = reader.readByte() catch return error.InvalidDatagram;
    const packet_number_len: usize = @as(usize, first_byte & 0x03) + 1;
    const packet_type_bits: u2 = @intCast((first_byte >> 4) & 0x03);

    var version_buf: [4]u8 = undefined;
    reader.readNoEof(&version_buf) catch return error.InvalidDatagram;
    const version: packet.Version = @enumFromInt(std.mem.readInt(u32, &version_buf, .big));
    if (@intFromEnum(version) == 0) return null;
    if ((first_byte & 0x40) == 0) return error.InvalidDatagram;
    if (!versionListContains(supported_versions, version)) return null;
    if (packet.longHeaderPacketTypeFromBits(version, packet_type_bits) != .initial) return null;

    const dcid_len = reader.readByte() catch return error.InvalidDatagram;
    if (dcid_len > max_connection_id_len) return error.InvalidConnectionIdLength;
    if (reader.remainingLen() < dcid_len) return error.InvalidDatagram;
    const dcid_start = reader.pos;
    reader.pos += dcid_len;

    const scid_len = reader.readByte() catch return error.InvalidDatagram;
    if (scid_len > max_connection_id_len) return error.InvalidConnectionIdLength;
    if (reader.remainingLen() < scid_len) return error.InvalidDatagram;
    const scid_start = reader.pos;
    reader.pos += scid_len;

    const token_len_varint = packet.decodeVarInt(reader.reader()) catch return error.InvalidDatagram;
    const token_len = std.math.cast(usize, token_len_varint.value) orelse return error.InvalidDatagram;
    if (reader.remainingLen() < token_len) return error.InvalidDatagram;
    const token_start = reader.pos;
    reader.pos += token_len;

    const length_varint = packet.decodeVarInt(reader.reader()) catch return error.InvalidDatagram;
    if (length_varint.value < packet_number_len) return error.InvalidDatagram;
    const encoded_packet_len = std.math.cast(usize, length_varint.value) orelse return error.InvalidDatagram;
    if (reader.remainingLen() < encoded_packet_len) return error.InvalidDatagram;

    return .{
        .path = path,
        .version = version,
        .original_destination_connection_id = datagram[dcid_start..][0..dcid_len],
        .source_connection_id = datagram[scid_start..][0..scid_len],
        .token = datagram[token_start..][0..token_len],
    };
}

/// Peek version-independent long-header connection IDs from one UDP datagram.
pub fn peekLongHeaderConnectionIds(datagram: []const u8) RouteError!LongHeaderConnectionIds {
    if (datagram.len < 6) return error.InvalidDatagram;
    if ((datagram[0] & 0x80) == 0) return error.InvalidDatagram;
    const version: packet.Version = @enumFromInt(std.mem.readInt(u32, datagram[1..5], .big));
    const dcid_len = datagram[5];
    const dcid_start: usize = 6;
    const dcid_end = dcid_start + @as(usize, dcid_len);
    if (datagram.len < dcid_end + 1) return error.InvalidDatagram;
    const scid_len = datagram[dcid_end];
    const scid_start = dcid_end + 1;
    const scid_end = scid_start + @as(usize, scid_len);
    if (datagram.len < scid_end) return error.InvalidDatagram;
    return .{
        .version = version,
        .dcid = datagram[dcid_start..dcid_end],
        .scid = datagram[scid_start..scid_end],
    };
}

fn resultForRoute(route: Route, path: Udp4Tuple) RouteError!RouteResult {
    const path_changed = !route.path.eql(path);
    if (path_changed and route.active_migration_disabled) return error.ActiveMigrationDisabled;
    return .{
        .connection_id = route.connection_id,
        .sequence_number = route.sequence_number,
        .destination_connection_id = route.destination_connection_id,
        .path_changed = path_changed,
    };
}

fn peekLongDestinationConnectionId(datagram: []const u8) RouteError![]const u8 {
    if (datagram.len < 6) return error.InvalidDatagram;
    const dcid_len = datagram[5];
    if (dcid_len > max_connection_id_len) return error.InvalidConnectionIdLength;
    const dcid_end = 6 + @as(usize, dcid_len);
    if (datagram.len < dcid_end) return error.InvalidDatagram;
    return datagram[6..dcid_end];
}

fn versionListContains(versions: []const packet.Version, version: packet.Version) bool {
    for (versions) |candidate| {
        if (@intFromEnum(candidate) == @intFromEnum(version)) return true;
    }
    return false;
}

fn testPath(remote_port: u16) Udp4Tuple {
    return testPathWithLocal(4433, remote_port);
}

fn testPathWithLocal(local_port: u16, remote_port: u16) Udp4Tuple {
    return .{
        .local = Udp4Address.init(.{ 127, 0, 0, 1 }, local_port),
        .remote = Udp4Address.init(.{ 127, 0, 0, 1 }, remote_port),
    };
}

test "Udp4Tuple creates remote peer address-validation binding" {
    const secret: address_validation_token.Secret = [_]u8{0x7a} ** address_validation_token.secret_len;
    const nonce: address_validation_token.Nonce = [_]u8{0x51} ** address_validation_token.nonce_len;
    const path = Udp4Tuple{
        .local = Udp4Address.init(.{ 192, 0, 2, 1 }, 4433),
        .remote = Udp4Address.init(.{ 203, 0, 113, 7 }, 50_000),
    };
    const same_peer_other_local = Udp4Tuple{
        .local = Udp4Address.init(.{ 192, 0, 2, 2 }, 4434),
        .remote = Udp4Address.init(.{ 203, 0, 113, 7 }, 50_000),
    };
    const changed_peer_port = Udp4Tuple{
        .local = path.local,
        .remote = Udp4Address.init(.{ 203, 0, 113, 7 }, 50_001),
    };
    const changed_peer_address = Udp4Tuple{
        .local = path.local,
        .remote = Udp4Address.init(.{ 203, 0, 113, 8 }, 50_000),
    };

    const binding = path.peerAddressValidationBinding();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 203, 0, 113, 7, 0xc3, 0x50 }, &binding);
    try std.testing.expectEqualSlices(u8, &binding, &same_peer_other_local.peerAddressValidationBinding());

    const encoded = try address_validation_token.encode(std.testing.allocator, secret, .{
        .kind = .new_token,
        .issued_millis = 1_000,
        .lifetime_millis = 10_000,
        .peer_address = &binding,
        .nonce = nonce,
    });
    defer std.testing.allocator.free(encoded);

    const same_peer_binding = same_peer_other_local.peerAddressValidationBinding();
    const changed_port_binding = changed_peer_port.peerAddressValidationBinding();
    const changed_address_binding = changed_peer_address.peerAddressValidationBinding();

    _ = try address_validation_token.validate(secret, .new_token, 1_100, &same_peer_binding, encoded);
    try std.testing.expectError(
        error.InvalidToken,
        address_validation_token.validate(secret, .new_token, 1_100, &changed_port_binding, encoded),
    );
    try std.testing.expectError(
        error.InvalidToken,
        address_validation_token.validate(secret, .new_token, 1_100, &changed_address_binding, encoded),
    );
}

test "AddressValidationPolicy validates rotated path-bound tokens and rejects replay" {
    const old_secret: address_validation_token.Secret = [_]u8{0xa1} ** address_validation_token.secret_len;
    const current_secret: address_validation_token.Secret = [_]u8{0xb2} ** address_validation_token.secret_len;
    const nonce: address_validation_token.Nonce = [_]u8{0xc3} ** address_validation_token.nonce_len;
    const path = testPath(50_000);
    const changed_path = testPath(50_001);
    var policy = AddressValidationPolicy.init(std.testing.allocator, old_secret, .{
        .max_previous_secrets = 1,
        .max_replay_entries = 4,
    });
    defer policy.deinit();

    const token = try policy.issueTokenForPath(std.testing.allocator, .new_token, 1_000, 10_000, path, nonce);
    defer std.testing.allocator.free(token);
    try policy.rotateSecret(current_secret);

    try std.testing.expectEqual(@as(usize, 1), policy.previousSecretCount());
    try std.testing.expectError(
        error.InvalidToken,
        policy.validateTokenForPath(.new_token, 1_100, changed_path, token),
    );

    const validation = try policy.validateTokenForPath(.new_token, 1_100, path, token);
    try std.testing.expectEqual(address_validation_token.Kind.new_token, validation.kind);
    try std.testing.expectError(
        error.TokenReplay,
        policy.validateTokenForPath(.new_token, 1_200, path, token),
    );
}

test "AddressValidationPolicy rejects tokens from a different QUIC version" {
    const secret: address_validation_token.Secret = [_]u8{0xd1} ** address_validation_token.secret_len;
    const nonce: address_validation_token.Nonce = [_]u8{0xd2} ** address_validation_token.nonce_len;
    const path = testPath(50_000);
    var policy = AddressValidationPolicy.init(std.testing.allocator, secret, .{
        .max_previous_secrets = 1,
        .max_replay_entries = 4,
    });
    defer policy.deinit();

    const token = try policy.issueTokenForPathForVersion(std.testing.allocator, .new_token, .v2, 1_000, 10_000, path, nonce);
    defer std.testing.allocator.free(token);

    try std.testing.expectError(
        error.InvalidToken,
        policy.validateTokenForPathForVersion(.new_token, .v1, 1_100, path, token),
    );
    try std.testing.expectEqual(@as(usize, 0), policy.replayFilterEntryCount());

    const validation = try policy.validateTokenForPathForVersion(.new_token, .v2, 1_100, path, token);
    try std.testing.expectEqual(packet.Version.v2, validation.originating_version);
    try std.testing.expectEqual(address_validation_token.Kind.new_token, validation.kind);
    try std.testing.expectEqual(@as(usize, 1), policy.replayFilterEntryCount());
}

test "AddressValidationPolicy drops oldest retained secret after rotation limit" {
    const old_secret: address_validation_token.Secret = [_]u8{0x01} ** address_validation_token.secret_len;
    const middle_secret: address_validation_token.Secret = [_]u8{0x02} ** address_validation_token.secret_len;
    const current_secret: address_validation_token.Secret = [_]u8{0x03} ** address_validation_token.secret_len;
    const old_nonce: address_validation_token.Nonce = [_]u8{0x11} ** address_validation_token.nonce_len;
    const middle_nonce: address_validation_token.Nonce = [_]u8{0x22} ** address_validation_token.nonce_len;
    const path = testPath(50_000);
    var policy = AddressValidationPolicy.init(std.testing.allocator, old_secret, .{
        .max_previous_secrets = 1,
        .max_replay_entries = 4,
    });
    defer policy.deinit();

    const old_token = try policy.issueTokenForPath(std.testing.allocator, .new_token, 1_000, 10_000, path, old_nonce);
    defer std.testing.allocator.free(old_token);
    try policy.rotateSecret(middle_secret);
    const middle_token = try policy.issueTokenForPath(std.testing.allocator, .new_token, 1_100, 10_000, path, middle_nonce);
    defer std.testing.allocator.free(middle_token);
    try policy.rotateSecret(current_secret);

    try std.testing.expectEqual(@as(usize, 1), policy.previousSecretCount());
    try std.testing.expectError(
        error.InvalidToken,
        policy.validateTokenForPathWithoutReplay(.new_token, 1_200, path, old_token),
    );
    const validation = try policy.validateTokenForPathWithoutReplay(.new_token, 1_200, path, middle_token);
    try std.testing.expectEqual(address_validation_token.Kind.new_token, validation.kind);
}

test "AddressValidationPolicy exports and restores retained token secrets" {
    const old_secret: address_validation_token.Secret = [_]u8{0x31} ** address_validation_token.secret_len;
    const middle_secret: address_validation_token.Secret = [_]u8{0x32} ** address_validation_token.secret_len;
    const current_secret: address_validation_token.Secret = [_]u8{0x33} ** address_validation_token.secret_len;
    const old_nonce: address_validation_token.Nonce = [_]u8{0x41} ** address_validation_token.nonce_len;
    const middle_nonce: address_validation_token.Nonce = [_]u8{0x42} ** address_validation_token.nonce_len;
    const current_nonce: address_validation_token.Nonce = [_]u8{0x43} ** address_validation_token.nonce_len;
    const path = testPath(50_000);
    var policy = AddressValidationPolicy.init(std.testing.allocator, old_secret, .{
        .max_previous_secrets = 2,
        .max_replay_entries = 4,
    });
    defer policy.deinit();

    const old_token = try policy.issueTokenForPath(std.testing.allocator, .new_token, 1_000, 10_000, path, old_nonce);
    defer std.testing.allocator.free(old_token);
    try policy.rotateSecret(middle_secret);
    const middle_token = try policy.issueTokenForPath(std.testing.allocator, .new_token, 1_100, 10_000, path, middle_nonce);
    defer std.testing.allocator.free(middle_token);
    try policy.rotateSecret(current_secret);
    const current_token = try policy.issueTokenForPath(std.testing.allocator, .new_token, 1_200, 10_000, path, current_nonce);
    defer std.testing.allocator.free(current_token);

    var secret_set = try policy.exportSecretSet(std.testing.allocator);
    defer secret_set.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), secret_set.previous_secrets.len);

    var restored = try AddressValidationPolicy.initWithSecretSet(std.testing.allocator, secret_set, .{
        .max_previous_secrets = 2,
        .max_replay_entries = 4,
    });
    defer restored.deinit();
    _ = try restored.validateTokenForPathWithoutReplay(.new_token, 1_300, path, old_token);
    _ = try restored.validateTokenForPathWithoutReplay(.new_token, 1_300, path, middle_token);
    _ = try restored.validateTokenForPathWithoutReplay(.new_token, 1_300, path, current_token);

    var trimmed = try AddressValidationPolicy.initWithSecretSet(std.testing.allocator, secret_set, .{
        .max_previous_secrets = 1,
        .max_replay_entries = 4,
    });
    defer trimmed.deinit();
    try std.testing.expectEqual(@as(usize, 1), trimmed.previousSecretCount());
    try std.testing.expectError(
        error.InvalidToken,
        trimmed.validateTokenForPathWithoutReplay(.new_token, 1_300, path, old_token),
    );
    _ = try trimmed.validateTokenForPathWithoutReplay(.new_token, 1_300, path, middle_token);
}

test "AddressValidationPolicy exports and restores replay filter state" {
    const secret: address_validation_token.Secret = [_]u8{0x61} ** address_validation_token.secret_len;
    const consumed_nonce: address_validation_token.Nonce = [_]u8{0x71} ** address_validation_token.nonce_len;
    const fresh_nonce: address_validation_token.Nonce = [_]u8{0x72} ** address_validation_token.nonce_len;
    const path = testPath(50_000);
    var policy = AddressValidationPolicy.init(std.testing.allocator, secret, .{
        .max_previous_secrets = 1,
        .max_replay_entries = 4,
    });
    defer policy.deinit();

    const consumed_token = try policy.issueTokenForPath(std.testing.allocator, .new_token, 1_000, 10_000, path, consumed_nonce);
    defer std.testing.allocator.free(consumed_token);
    const fresh_token = try policy.issueTokenForPath(std.testing.allocator, .new_token, 1_100, 10_000, path, fresh_nonce);
    defer std.testing.allocator.free(fresh_token);

    _ = try policy.validateTokenForPath(.new_token, 1_200, path, consumed_token);
    var secret_set = try policy.exportSecretSet(std.testing.allocator);
    defer secret_set.deinit(std.testing.allocator);
    var replay_snapshot = try policy.exportReplayFilter(std.testing.allocator);
    defer replay_snapshot.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), replay_snapshot.fingerprints.len);

    var restored = try AddressValidationPolicy.initWithSecretSetAndReplayFilter(std.testing.allocator, secret_set, replay_snapshot, .{
        .max_previous_secrets = 1,
        .max_replay_entries = 4,
    });
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 1), restored.replayFilterEntryCount());
    try std.testing.expectError(
        error.TokenReplay,
        restored.validateTokenForPath(.new_token, 1_300, path, consumed_token),
    );
    _ = try restored.validateTokenForPath(.new_token, 1_300, path, fresh_token);

    var trimmed = try AddressValidationPolicy.initWithSecretSetAndReplayFilter(std.testing.allocator, secret_set, replay_snapshot, .{
        .max_previous_secrets = 1,
        .max_replay_entries = 0,
    });
    defer trimmed.deinit();
    try std.testing.expectEqual(@as(usize, 0), trimmed.replayFilterEntryCount());
    _ = try trimmed.validateTokenForPathWithoutReplay(.new_token, 1_300, path, consumed_token);
}

test "EcnPathPolicy keeps ECN validation state scoped to UDP path identity" {
    const path = testPath(50_000);
    const migrated_path = testPath(50_001);
    var policy = EcnPathPolicy.init(std.testing.allocator);
    defer policy.deinit();

    try std.testing.expectEqual(EcnPathValidationState.unknown, policy.stateForPath(path));
    try std.testing.expect(policy.mayUseEct(path));

    try policy.setStateForPath(path, .capable);
    try std.testing.expectEqual(EcnPathValidationState.capable, policy.stateForPath(path));
    try std.testing.expectEqual(EcnPathValidationState.unknown, policy.stateForPath(migrated_path));
    try std.testing.expect(policy.mayUseEct(migrated_path));

    try policy.setStateForPath(migrated_path, .failed);
    try std.testing.expectEqual(EcnPathValidationState.failed, policy.stateForPath(migrated_path));
    try std.testing.expect(!policy.mayUseEct(migrated_path));
    try std.testing.expectEqual(EcnPathValidationState.capable, policy.stateForPath(path));

    try std.testing.expect(policy.resetPath(migrated_path));
    try std.testing.expectEqual(EcnPathValidationState.unknown, policy.stateForPath(migrated_path));
    try std.testing.expect(!policy.resetPath(migrated_path));
}

test "EndpointRouter routes long and short datagrams by destination CID" {
    const dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const path = testPath(50_000);
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();
    try router.registerConnectionId(7, &dcid, path, .{});

    const long_datagram = [_]u8{
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x04, 0xaa, 0xbb, 0xcc, 0xdd,
        0x00,
    };
    const long_route = try router.routeDatagram(path, &long_datagram);
    try std.testing.expectEqual(@as(u64, 7), long_route.connection_id);
    try std.testing.expect(!long_route.path_changed);
    try std.testing.expectEqualSlices(u8, &dcid, long_route.destination_connection_id.asSlice());

    const short_datagram = [_]u8{ 0x40, 0xaa, 0xbb, 0xcc, 0xdd, 0x01 };
    const short_route = try router.routeDatagram(path, &short_datagram);
    try std.testing.expectEqual(@as(u64, 7), short_route.connection_id);
    try std.testing.expect(!short_route.path_changed);
}

test "Endpoint version negotiation response swaps connection IDs" {
    const supported_versions = [_]packet.Version{ .v1, .v2 };
    const unsupported_version: packet.Version = @enumFromInt(0xface_b00c);
    const datagram = [_]u8{
        0xc0,
        0xfa,
        0xce,
        0xb0,
        0x0c,
        0x02,
        0xaa,
        0xbb,
        0x03,
        0x11,
        0x22,
        0x33,
        0x00,
    };

    const ids = try peekLongHeaderConnectionIds(&datagram);
    try std.testing.expectEqual(unsupported_version, ids.version);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb }, ids.dcid);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x11, 0x22, 0x33 }, ids.scid);

    var response_buf: [64]u8 = undefined;
    const response = (try writeVersionNegotiationForUnsupportedVersion(
        &response_buf,
        &datagram,
        &supported_versions,
    )) orelse return error.TestUnexpectedResult;

    var parsed = try packet.parseVersionNegotiationPacket(response, std.testing.allocator);
    defer packet.deinitVersionNegotiationPacket(&parsed, std.testing.allocator);
    try std.testing.expectEqualSlices(u8, ids.scid, parsed.dcid);
    try std.testing.expectEqualSlices(u8, ids.dcid, parsed.scid);
    try std.testing.expectEqualSlices(packet.Version, &supported_versions, parsed.versions);
}

test "Endpoint version negotiation ignores non-triggering datagrams" {
    const supported_versions = [_]packet.Version{ .v1, .v2 };
    const supported = [_]u8{
        0xc0,
        0x00,
        0x00,
        0x00,
        0x01,
        0x01,
        0xaa,
        0x01,
        0xbb,
        0x00,
    };
    const version_negotiation = [_]u8{
        0x80,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0xaa,
        0x01,
        0xbb,
        0x00,
        0x00,
        0x00,
        0x01,
    };
    const short_header = [_]u8{ 0x40, 0xaa, 0xbb };

    var response_buf: [64]u8 = undefined;
    try std.testing.expectEqual(@as(?[]const u8, null), try writeVersionNegotiationForUnsupportedVersion(
        &response_buf,
        &supported,
        &supported_versions,
    ));
    try std.testing.expectEqual(@as(?[]const u8, null), try writeVersionNegotiationForUnsupportedVersion(
        &response_buf,
        &version_negotiation,
        &supported_versions,
    ));
    try std.testing.expectEqual(@as(?[]const u8, null), try writeVersionNegotiationForUnsupportedVersion(
        &response_buf,
        &short_header,
        &supported_versions,
    ));

    const zero_version = [_]packet.Version{@enumFromInt(0)};
    try std.testing.expectError(
        error.InvalidVersionList,
        writeVersionNegotiationForUnsupportedVersion(&response_buf, &supported, &zero_version),
    );
    try std.testing.expectError(
        error.InvalidVersionList,
        writeVersionNegotiationForUnsupportedVersion(&response_buf, &supported, &[_]packet.Version{}),
    );
}

test "Endpoint handleDatagram can emit version negotiation before route lookup" {
    const supported_versions = [_]packet.Version{ .v1, .v2 };
    const datagram = [_]u8{
        0xc0,
        0xfa,
        0xce,
        0xb0,
        0x0c,
        0x02,
        0xaa,
        0xbb,
        0x03,
        0x11,
        0x22,
        0x33,
        0x00,
    };
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();

    var response_buf: [64]u8 = undefined;
    const action = try router.handleDatagramWithVersionNegotiation(
        &response_buf,
        testPath(50_000),
        &datagram,
        &[_]u8{ 0x55, 0x56, 0x57, 0x58, 0x59 },
        &supported_versions,
    );
    const response = switch (action) {
        .version_negotiation => |response| response,
        else => return error.TestUnexpectedResult,
    };

    var parsed = try packet.parseVersionNegotiationPacket(response, std.testing.allocator);
    defer packet.deinitVersionNegotiationPacket(&parsed, std.testing.allocator);
    try std.testing.expectEqualSlices(packet.Version, &supported_versions, parsed.versions);
}

test "Endpoint handleDatagram classifies supported unknown Initial for server accept" {
    const supported_versions = [_]packet.Version{.v1};
    const path = testPath(50_000);
    const original_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11 };
    const client_scid = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    const token = [_]u8{ 0x99, 0x88, 0x77 };
    const initial = [_]u8{
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x08, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee, 0xff, 0x00, 0x11, 0x04,
        0x12, 0x34, 0x56, 0x78, 0x03,
        0x99, 0x88, 0x77, 0x02, 0x00,
        0xaa,
    };
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();

    const accept = (try peekInitialAcceptDatagram(path, &initial, &supported_versions)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(packet.Version.v1, accept.version);
    try std.testing.expect(accept.path.eql(path));
    try std.testing.expectEqualSlices(u8, &original_dcid, accept.original_destination_connection_id);
    try std.testing.expectEqualSlices(u8, &client_scid, accept.source_connection_id);
    try std.testing.expectEqualSlices(u8, &token, accept.token);

    var out: [64]u8 = undefined;
    const action = try router.handleDatagramWithVersionNegotiation(
        &out,
        path,
        &initial,
        &[_]u8{ 0x55, 0x56, 0x57, 0x58, 0x59 },
        &supported_versions,
    );
    switch (action) {
        .accept_initial => |result| {
            try std.testing.expectEqual(packet.Version.v1, result.version);
            try std.testing.expect(result.path.eql(path));
            try std.testing.expectEqualSlices(u8, &original_dcid, result.original_destination_connection_id);
            try std.testing.expectEqualSlices(u8, &client_scid, result.source_connection_id);
            try std.testing.expectEqualSlices(u8, &token, result.token);
        },
        else => return error.TestUnexpectedResult,
    }

    try router.registerConnectionId(7, &original_dcid, path, .{});
    const routed = try router.handleDatagramWithVersionNegotiation(
        &out,
        path,
        &initial,
        &[_]u8{ 0x55, 0x56, 0x57, 0x58, 0x59 },
        &supported_versions,
    );
    switch (routed) {
        .routed => |route| try std.testing.expectEqual(@as(u64, 7), route.connection_id),
        else => return error.TestUnexpectedResult,
    }
}

test "Endpoint Initial accept ignores non-Initial and rejects malformed Initial headers" {
    const supported_versions = [_]packet.Version{.v1};
    const path = testPath(50_000);
    const short_header = [_]u8{ 0x40, 0xaa, 0xbb };
    const version_negotiation = [_]u8{
        0x80, 0x00, 0x00, 0x00, 0x00,
        0x01, 0xaa, 0x01, 0xbb, 0x00,
        0x00, 0x00, 0x01,
    };
    const handshake = [_]u8{
        0xe0, 0x00, 0x00, 0x00, 0x01,
        0x01, 0xaa, 0x01, 0xbb, 0x02,
        0x00, 0xaa,
    };
    const unsupported_initial = [_]u8{
        0xc0, 0xfa, 0xce, 0xb0, 0x0c,
        0x01, 0xaa, 0x01, 0xbb, 0x00,
        0x02, 0x00, 0xaa,
    };
    const truncated_initial = [_]u8{
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x08, 0xaa, 0xbb,
    };
    const bad_length_initial = [_]u8{
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x01, 0xaa, 0x01, 0xbb, 0x00,
        0x01,
    };

    try std.testing.expect((try peekInitialAcceptDatagram(path, &short_header, &supported_versions)) == null);
    try std.testing.expect((try peekInitialAcceptDatagram(path, &version_negotiation, &supported_versions)) == null);
    try std.testing.expect((try peekInitialAcceptDatagram(path, &handshake, &supported_versions)) == null);
    try std.testing.expect((try peekInitialAcceptDatagram(path, &unsupported_initial, &supported_versions)) == null);
    try std.testing.expectError(error.InvalidDatagram, peekInitialAcceptDatagram(path, &truncated_initial, &supported_versions));
    try std.testing.expectError(error.InvalidDatagram, peekInitialAcceptDatagram(path, &bad_length_initial, &supported_versions));
    try std.testing.expectError(error.InvalidVersionList, peekInitialAcceptDatagram(path, &bad_length_initial, &[_]packet.Version{}));

    const zero_version = [_]packet.Version{@enumFromInt(0)};
    try std.testing.expectError(error.InvalidVersionList, peekInitialAcceptDatagram(path, &bad_length_initial, &zero_version));
}

test "EndpointRouter reports path changes and active migration rejection" {
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const path = testPath(50_000);
    const changed_path = testPath(50_001);
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();

    try router.registerConnectionId(1, &dcid, path, .{});
    const migrated = try router.routeConnectionId(&dcid, changed_path);
    try std.testing.expectEqual(@as(u64, 1), migrated.connection_id);
    try std.testing.expect(migrated.path_changed);

    try std.testing.expect(try router.retireConnectionId(&dcid));
    try router.registerConnectionId(2, &dcid, path, .{ .active_migration_disabled = true });
    try std.testing.expectError(error.ActiveMigrationDisabled, router.routeConnectionId(&dcid, changed_path));
}

test "EndpointRouter switches Initial route to Retry Source Connection ID" {
    const original_dcid = [_]u8{ 0x10, 0x11, 0x12, 0x13 };
    const retry_scid = [_]u8{ 0x20, 0x21, 0x22, 0x23 };
    const duplicate_cid = [_]u8{ 0x30, 0x31, 0x32, 0x33 };
    const sequenced_cid = [_]u8{ 0x40, 0x41, 0x42, 0x43 };
    const path = testPath(50_000);
    const changed_path = testPath(50_001);
    const original_datagram = [_]u8{
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x10, 0x11, 0x12, 0x13,
        0x00,
    };
    const retry_datagram = [_]u8{
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x20, 0x21, 0x22, 0x23,
        0x00,
    };
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();

    try router.registerConnectionId(17, &original_dcid, path, .{});
    try router.registerConnectionId(18, &duplicate_cid, path, .{});
    try router.registerConnectionId(19, &sequenced_cid, path, .{ .sequence_number = 0 });
    try std.testing.expectEqual(@as(u64, 17), (try router.routeDatagram(path, &original_datagram)).connection_id);

    try std.testing.expectError(
        error.DuplicateConnectionId,
        router.switchInitialDestinationConnectionIdAfterRetry(&original_dcid, &duplicate_cid, path),
    );
    try std.testing.expectEqual(@as(u64, 17), (try router.routeDatagram(path, &original_datagram)).connection_id);
    try std.testing.expectError(
        error.PathMismatch,
        router.switchInitialDestinationConnectionIdAfterRetry(&original_dcid, &retry_scid, changed_path),
    );
    try std.testing.expectError(
        error.InvalidConnectionIdSequence,
        router.switchInitialDestinationConnectionIdAfterRetry(&sequenced_cid, &retry_scid, path),
    );

    const switched = try router.switchInitialDestinationConnectionIdAfterRetry(&original_dcid, &retry_scid, path);
    try std.testing.expectEqual(@as(u64, 17), switched.connection_id);
    try std.testing.expectEqual(@as(?u64, null), switched.sequence_number);
    try std.testing.expectEqualSlices(u8, &retry_scid, switched.destination_connection_id.asSlice());
    try std.testing.expectError(error.UnknownConnectionId, router.routeDatagram(path, &original_datagram));
    try std.testing.expectEqual(@as(u64, 17), (try router.routeDatagram(path, &retry_datagram)).connection_id);
}

test "EndpointRouter updates route path after caller validates migration" {
    const dcid = [_]u8{ 0x44, 0x55, 0x66, 0x77 };
    const old_path = testPath(50_000);
    const new_path = testPath(50_001);
    const third_path = testPath(50_002);
    const short_datagram = [_]u8{ 0x40, 0x44, 0x55, 0x66, 0x77, 0x01 };
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();

    try router.registerConnectionId(3, &dcid, old_path, .{});
    const migrated = try router.routeDatagram(new_path, &short_datagram);
    try std.testing.expect(migrated.path_changed);

    const updated = try router.updateRoutePath(&dcid, old_path, new_path);
    try std.testing.expectEqual(@as(u64, 3), updated.connection_id);
    try std.testing.expect(!updated.path_changed);

    const on_new_path = try router.routeDatagram(new_path, &short_datagram);
    try std.testing.expect(!on_new_path.path_changed);
    try std.testing.expectError(error.PathMismatch, router.updateRoutePath(&dcid, old_path, third_path));

    try std.testing.expect(try router.retireConnectionId(&dcid));
    try router.registerConnectionId(4, &dcid, old_path, .{ .active_migration_disabled = true });
    try std.testing.expectError(error.ActiveMigrationDisabled, router.updateRoutePath(&dcid, old_path, new_path));
}

test "EndpointRouter commits caller-validated preferred address migration" {
    const current_cid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    const preferred_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
    const duplicate_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const preferred_token = [_]u8{0x42} ** stateless_reset_token_len;
    const current_path = testPath(50_000);
    const preferred_path = testPathWithLocal(8443, 50_001);
    const third_path = testPathWithLocal(8443, 50_002);
    const current_datagram = [_]u8{ 0x40, 0x51, 0x52, 0x53, 0x54, 0x01 };
    const preferred_datagram = [_]u8{
        0x40, 0x61, 0x62, 0x63, 0x64, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    };
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();

    try router.registerConnectionId(23, &current_cid, current_path, .{ .active_migration_disabled = true });
    try router.registerConnectionId(24, &duplicate_cid, current_path, .{});
    try std.testing.expectError(
        error.DuplicateConnectionId,
        router.commitPreferredAddressMigration(&current_cid, current_path, &duplicate_cid, preferred_path, preferred_token),
    );
    try std.testing.expectEqual(@as(u64, 23), (try router.routeDatagram(current_path, &current_datagram)).connection_id);
    try std.testing.expectError(
        error.PathMismatch,
        router.commitPreferredAddressMigration(&current_cid, preferred_path, &preferred_cid, preferred_path, preferred_token),
    );
    try std.testing.expectError(
        error.InvalidConnectionIdLength,
        router.commitPreferredAddressMigration(&current_cid, current_path, &[_]u8{}, preferred_path, preferred_token),
    );

    const migrated = try router.commitPreferredAddressMigration(&current_cid, current_path, &preferred_cid, preferred_path, preferred_token);
    try std.testing.expectEqual(@as(u64, 23), migrated.connection_id);
    try std.testing.expectEqualSlices(u8, &preferred_cid, migrated.destination_connection_id.asSlice());
    try std.testing.expect(!migrated.path_changed);
    try std.testing.expectError(error.UnknownConnectionId, router.routeDatagram(current_path, &current_datagram));
    try std.testing.expectEqual(@as(u64, 23), (try router.routeDatagram(preferred_path, &preferred_datagram)).connection_id);
    try std.testing.expectError(error.ActiveMigrationDisabled, router.routeDatagram(third_path, &preferred_datagram));
    try std.testing.expectEqual(@as(?[stateless_reset_token_len]u8, null), try router.statelessResetTokenForDatagram(preferred_path, &preferred_datagram));

    try std.testing.expect(try router.retireConnectionId(&preferred_cid));
    const retired_token = (try router.statelessResetTokenForDatagram(preferred_path, &preferred_datagram)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &preferred_token, &retired_token);
}

test "EndpointRouter retires connection ID routes by sequence number" {
    const cid0 = [_]u8{ 0x30, 0x31, 0x32, 0x33 };
    const cid1 = [_]u8{ 0x40, 0x41, 0x42, 0x43 };
    const cid2 = [_]u8{ 0x50, 0x51, 0x52, 0x53 };
    const token0 = [_]u8{0x01} ** stateless_reset_token_len;
    const token1 = [_]u8{0x02} ** stateless_reset_token_len;
    const path = testPath(50_000);
    const datagram0 = [_]u8{ 0x40, 0x30, 0x31, 0x32, 0x33, 0x01 };
    const datagram1 = [_]u8{ 0x40, 0x40, 0x41, 0x42, 0x43, 0x01 };
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();

    try router.registerConnectionId(9, &cid0, path, .{ .sequence_number = 0, .stateless_reset_token = token0 });
    try router.registerConnectionId(9, &cid1, path, .{ .sequence_number = 1, .stateless_reset_token = token1 });
    try std.testing.expectError(error.DuplicateConnectionId, router.registerConnectionId(9, &cid2, path, .{ .sequence_number = 1 }));

    const route1 = try router.routeDatagram(path, &datagram1);
    try std.testing.expectEqual(@as(u64, 9), route1.connection_id);
    try std.testing.expectEqual(@as(?u64, 1), route1.sequence_number);

    try std.testing.expect(router.retireConnectionIdSequence(9, 0));
    try std.testing.expectError(error.UnknownConnectionId, router.routeDatagram(path, &datagram0));
    const retired_token = (try router.statelessResetTokenForDatagram(path, &datagram0)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &token0, &retired_token);
    try std.testing.expectEqual(@as(u64, 9), (try router.routeDatagram(path, &datagram1)).connection_id);
    try std.testing.expect(!router.retireConnectionIdSequence(9, 0));
    try std.testing.expect(!router.retireConnectionIdSequence(10, 1));
}

test "EndpointRouter retires connection ID routes before a sequence threshold" {
    const cid0 = [_]u8{ 0x20, 0x21, 0x22, 0x23 };
    const cid1 = [_]u8{ 0x30, 0x31, 0x32, 0x33 };
    const cid2 = [_]u8{ 0x40, 0x41, 0x42, 0x43 };
    const other_cid = [_]u8{ 0x50, 0x51, 0x52, 0x53 };
    const token0 = [_]u8{0x10} ** stateless_reset_token_len;
    const token1 = [_]u8{0x11} ** stateless_reset_token_len;
    const token2 = [_]u8{0x12} ** stateless_reset_token_len;
    const other_token = [_]u8{0x13} ** stateless_reset_token_len;
    const path = testPath(50_000);
    const datagram0 = [_]u8{ 0x40, 0x20, 0x21, 0x22, 0x23, 0x01 };
    const datagram1 = [_]u8{ 0x40, 0x30, 0x31, 0x32, 0x33, 0x01 };
    const datagram2 = [_]u8{ 0x40, 0x40, 0x41, 0x42, 0x43, 0x01 };
    const other_datagram = [_]u8{ 0x40, 0x50, 0x51, 0x52, 0x53, 0x01 };
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();

    try router.registerConnectionId(9, &cid0, path, .{ .sequence_number = 0, .stateless_reset_token = token0 });
    try router.registerConnectionId(9, &cid1, path, .{ .sequence_number = 1, .stateless_reset_token = token1 });
    try router.registerConnectionId(9, &cid2, path, .{ .sequence_number = 2, .stateless_reset_token = token2 });
    try router.registerConnectionId(10, &other_cid, path, .{ .sequence_number = 0, .stateless_reset_token = other_token });

    try std.testing.expectEqual(@as(usize, 0), router.retireConnectionIdSequencesBefore(9, 0));
    try std.testing.expectEqual(@as(usize, 2), router.retireConnectionIdSequencesBefore(9, 2));
    try std.testing.expectError(error.UnknownConnectionId, router.routeDatagram(path, &datagram0));
    try std.testing.expectError(error.UnknownConnectionId, router.routeDatagram(path, &datagram1));
    try std.testing.expectEqual(@as(u64, 9), (try router.routeDatagram(path, &datagram2)).connection_id);
    try std.testing.expectEqual(@as(u64, 10), (try router.routeDatagram(path, &other_datagram)).connection_id);

    const retired_token0 = (try router.statelessResetTokenForDatagram(path, &datagram0)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &token0, &retired_token0);
    const retired_token1 = (try router.statelessResetTokenForDatagram(path, &datagram1)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &token1, &retired_token1);
    try std.testing.expectEqual(@as(?[stateless_reset_token_len]u8, null), try router.statelessResetTokenForDatagram(path, &datagram2));
    try std.testing.expectEqual(@as(?[stateless_reset_token_len]u8, null), try router.statelessResetTokenForDatagram(path, &other_datagram));
    try std.testing.expectEqual(@as(usize, 0), router.retireConnectionIdSequencesBefore(9, 2));
}

test "EndpointRouter registers replacement connection ID and retires older routes" {
    const cid0 = [_]u8{ 0x60, 0x61, 0x62, 0x63 };
    const cid1 = [_]u8{ 0x70, 0x71, 0x72, 0x73 };
    const cid2 = [_]u8{ 0x80, 0x81, 0x82, 0x83 };
    const token0 = [_]u8{0x20} ** stateless_reset_token_len;
    const token1 = [_]u8{0x21} ** stateless_reset_token_len;
    const token2 = [_]u8{0x22} ** stateless_reset_token_len;
    const path = testPath(50_000);
    const datagram0 = [_]u8{ 0x40, 0x60, 0x61, 0x62, 0x63, 0x01 };
    const datagram1 = [_]u8{ 0x40, 0x70, 0x71, 0x72, 0x73, 0x01 };
    const datagram2 = [_]u8{ 0x40, 0x80, 0x81, 0x82, 0x83, 0x01 };
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();

    try router.registerConnectionId(11, &cid0, path, .{ .sequence_number = 0, .stateless_reset_token = token0 });
    const replacement1 = try router.registerReplacementConnectionId(11, &cid1, path, 1, 1, .{ .stateless_reset_token = token1 });
    try std.testing.expectEqual(@as(u64, 1), replacement1.sequence_number);
    try std.testing.expectEqual(@as(u64, 1), replacement1.retire_prior_to);
    try std.testing.expectEqual(@as(usize, 1), replacement1.retired_count);
    try std.testing.expectError(error.UnknownConnectionId, router.routeDatagram(path, &datagram0));
    const retired_token0 = (try router.statelessResetTokenForDatagram(path, &datagram0)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &token0, &retired_token0);
    try std.testing.expectEqual(@as(?u64, 1), (try router.routeDatagram(path, &datagram1)).sequence_number);

    try std.testing.expectError(
        error.InvalidConnectionIdSequence,
        router.registerReplacementConnectionId(11, &cid2, path, 1, 2, .{ .stateless_reset_token = token2 }),
    );
    try std.testing.expectError(error.UnknownConnectionId, router.routeDatagram(path, &datagram2));

    const replacement2 = try router.registerReplacementConnectionId(11, &cid2, path, 2, 2, .{ .stateless_reset_token = token2 });
    try std.testing.expectEqual(@as(usize, 1), replacement2.retired_count);
    try std.testing.expectError(error.UnknownConnectionId, router.routeDatagram(path, &datagram1));
    try std.testing.expectEqual(@as(?u64, 2), (try router.routeDatagram(path, &datagram2)).sequence_number);
}

test "EndpointRouter exposes stateless reset tokens only for inactive routes" {
    const dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const path = testPath(50_000);
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();

    try router.registerConnectionId(7, &dcid, path, .{ .stateless_reset_token = token });
    const short_datagram = [_]u8{ 0x40, 0xaa, 0xbb, 0xcc, 0xdd, 0x01 };
    try std.testing.expectEqual(@as(?[stateless_reset_token_len]u8, null), try router.statelessResetTokenForDatagram(path, &short_datagram));

    try std.testing.expect(try router.retireConnectionId(&dcid));
    const short_token = (try router.statelessResetTokenForDatagram(path, &short_datagram)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &token, &short_token);

    const long_datagram = [_]u8{
        0xc0, 0x00, 0x00, 0x00, 0x01,
        0x04, 0xaa, 0xbb, 0xcc, 0xdd,
        0x00,
    };
    const long_token = (try router.statelessResetTokenForDatagram(path, &long_datagram)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &token, &long_token);
    try std.testing.expectEqual(@as(usize, 1), router.statelessResetTokenCount());
}

test "EndpointRouter routes zero-length destination CIDs by UDP tuple" {
    const empty_cid = [_]u8{};
    const path0 = testPath(50_000);
    const path1 = testPathWithLocal(4434, 50_001);
    const path2 = testPathWithLocal(4435, 50_002);
    const path3 = testPathWithLocal(4436, 50_003);
    const short_datagram = [_]u8{ 0x40, 0x01, 0x02, 0x03 };
    const long_datagram = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01, 0x00 };
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();

    try router.registerConnectionId(1, &empty_cid, path0, .{});
    try router.registerConnectionId(2, &empty_cid, path1, .{});
    try std.testing.expectError(error.DuplicateConnectionId, router.registerConnectionId(3, &empty_cid, path0, .{}));

    const short_route0 = try router.routeDatagram(path0, &short_datagram);
    try std.testing.expectEqual(@as(u64, 1), short_route0.connection_id);
    try std.testing.expectEqual(@as(usize, 0), short_route0.destination_connection_id.asSlice().len);

    const short_route1 = try router.routeDatagram(path1, &short_datagram);
    try std.testing.expectEqual(@as(u64, 2), short_route1.connection_id);

    const long_route0 = try router.routeDatagram(path0, &long_datagram);
    try std.testing.expectEqual(@as(u64, 1), long_route0.connection_id);
    try std.testing.expectError(error.UnknownConnectionId, router.routeDatagram(path2, &short_datagram));
    try std.testing.expectError(error.AmbiguousConnectionId, router.retireConnectionId(&empty_cid));
    try std.testing.expect(try router.retireConnectionIdOnPath(&empty_cid, path0));
    try std.testing.expectError(error.UnknownConnectionId, router.routeDatagram(path0, &short_datagram));
    try std.testing.expectEqual(@as(u64, 2), (try router.routeDatagram(path1, &short_datagram)).connection_id);

    const zero_updated = try router.updateRoutePath(&empty_cid, path1, path3);
    try std.testing.expectEqual(@as(u64, 2), zero_updated.connection_id);
    try std.testing.expect(!zero_updated.path_changed);
    try std.testing.expectError(error.UnknownConnectionId, router.routeDatagram(path1, &short_datagram));
    try std.testing.expectEqual(@as(u64, 2), (try router.routeDatagram(path3, &short_datagram)).connection_id);
}

test "EndpointRouter rejects stateless reset tokens for zero-length CIDs" {
    const empty_cid = [_]u8{};
    const token = [_]u8{0x11} ** stateless_reset_token_len;
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();

    try std.testing.expectError(
        error.InvalidConnectionIdLength,
        router.registerConnectionId(1, &empty_cid, testPath(50_000), .{ .stateless_reset_token = token }),
    );
    try std.testing.expectError(
        error.InvalidConnectionIdLength,
        router.registerConnectionId(1, &empty_cid, testPath(50_000), .{ .sequence_number = 0 }),
    );
    try std.testing.expectError(
        error.InvalidConnectionIdLength,
        router.registerStatelessResetToken(&empty_cid, token),
    );
}

test "EndpointRouter writes stateless reset datagrams for inactive routes" {
    const dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const token = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const prefix = [_]u8{ 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde };
    const triggering_datagram = [_]u8{
        0x40, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    };
    const path = testPath(50_000);
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();

    try router.registerConnectionId(7, &dcid, path, .{ .stateless_reset_token = token });
    var out: [64]u8 = undefined;
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        try router.writeStatelessResetForDatagram(&out, path, &triggering_datagram, &prefix),
    );

    try std.testing.expect(try router.retireConnectionId(&dcid));
    const reset = (try router.writeStatelessResetForDatagram(&out, path, &triggering_datagram, &prefix)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(prefix.len + stateless_reset_token_len, reset.len);
    try std.testing.expect(reset.len < triggering_datagram.len);
    try std.testing.expectEqualSlices(u8, &prefix, reset[0..prefix.len]);
    try std.testing.expect(packet.matchesStatelessReset(reset, token));
}

test "EndpointRouter handles datagrams as route reset or drop" {
    const active_cid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
    const retired_cid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const reset_token = [_]u8{0x9a} ** stateless_reset_token_len;
    const prefix = [_]u8{ 0x40, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01, 0x02 };
    const active_datagram = [_]u8{ 0x40, 0x21, 0x22, 0x23, 0x24, 0x01 };
    const retired_datagram = [_]u8{
        0x40, 0x31, 0x32, 0x33, 0x34, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    };
    const unknown_datagram = [_]u8{
        0x40, 0x41, 0x42, 0x43, 0x44, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    };
    const path = testPath(50_000);
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();

    try router.registerConnectionId(77, &active_cid, path, .{});
    try router.registerConnectionId(88, &retired_cid, path, .{ .stateless_reset_token = reset_token });
    try std.testing.expect(try router.retireConnectionId(&retired_cid));

    var out: [64]u8 = undefined;
    const active_action = try router.handleDatagram(&out, path, &active_datagram, &prefix);
    switch (active_action) {
        .routed => |route| try std.testing.expectEqual(@as(u64, 77), route.connection_id),
        else => return error.TestUnexpectedResult,
    }

    const reset_action = try router.handleDatagram(&out, path, &retired_datagram, &prefix);
    switch (reset_action) {
        .stateless_reset => |reset| {
            try std.testing.expectEqual(prefix.len + stateless_reset_token_len, reset.len);
            try std.testing.expect(packet.matchesStatelessReset(reset, reset_token));
        },
        else => return error.TestUnexpectedResult,
    }

    const drop_action = try router.handleDatagram(&out, path, &unknown_datagram, &prefix);
    switch (drop_action) {
        .dropped => {},
        else => return error.TestUnexpectedResult,
    }
}

test "EndpointRouter rejects invalid stateless reset datagram sizing" {
    const dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const token = [_]u8{0x11} ** stateless_reset_token_len;
    const prefix = [_]u8{ 0x40, 0x12, 0x34, 0x56, 0x78 };
    const short_prefix = [_]u8{ 0x40, 0x12, 0x34, 0x56 };
    const triggering_datagram = [_]u8{
        0x40, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
    };
    const too_short_trigger = [_]u8{
        0x40, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();

    try router.registerStatelessResetToken(&dcid, token);
    var out: [64]u8 = undefined;
    var small_out: [20]u8 = undefined;
    try std.testing.expectError(
        error.InvalidResetSize,
        router.writeStatelessResetForDatagram(&out, testPath(50_000), &triggering_datagram, &short_prefix),
    );
    try std.testing.expectError(
        error.InvalidResetSize,
        router.writeStatelessResetForDatagram(&out, testPath(50_000), &too_short_trigger, &prefix),
    );
    try std.testing.expectError(
        error.BufferTooSmall,
        router.writeStatelessResetForDatagram(&small_out, testPath(50_000), &triggering_datagram, &prefix),
    );
}

test "EndpointRouter rejects unknown duplicate ambiguous and malformed routes" {
    const path = testPath(50_000);
    const cid0 = [_]u8{0xaa};
    const cid1 = [_]u8{ 0xaa, 0xbb };
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();

    try router.registerConnectionId(1, &cid0, path, .{});
    try std.testing.expectError(error.DuplicateConnectionId, router.registerConnectionId(2, &cid0, path, .{}));
    try router.registerConnectionId(2, &cid1, path, .{});

    try std.testing.expectError(error.UnknownConnectionId, router.routeConnectionId(&[_]u8{0xcc}, path));
    try std.testing.expectError(error.AmbiguousConnectionId, router.routeDatagram(path, &[_]u8{ 0x40, 0xaa, 0xbb, 0x00 }));
    try std.testing.expectError(error.InvalidDatagram, router.routeDatagram(path, &[_]u8{0xc0}));

    var too_long: [max_connection_id_len + 1]u8 = undefined;
    @memset(&too_long, 0);
    try std.testing.expectError(error.InvalidConnectionIdLength, router.registerConnectionId(3, &too_long, path, .{}));
}

test "EndpointRouter rejects ambiguous stateless reset token prefixes" {
    const token0 = [_]u8{0x01} ** stateless_reset_token_len;
    const token1 = [_]u8{0x02} ** stateless_reset_token_len;
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();

    try router.registerStatelessResetToken(&[_]u8{0xaa}, token0);
    try router.registerStatelessResetToken(&[_]u8{ 0xaa, 0xbb }, token1);
    try std.testing.expectError(
        error.AmbiguousConnectionId,
        router.statelessResetTokenForDatagram(testPath(50_000), &[_]u8{ 0x40, 0xaa, 0xbb, 0x00 }),
    );
    try std.testing.expectError(
        error.DuplicateConnectionId,
        router.registerStatelessResetToken(&[_]u8{0xaa}, token1),
    );
    try std.testing.expectEqual(@as(?[stateless_reset_token_len]u8, null), try router.statelessResetTokenForDatagram(testPath(50_000), &[_]u8{ 0x40, 0xcc, 0x00 }));
    try std.testing.expectError(error.InvalidDatagram, router.statelessResetTokenForDatagram(testPath(50_000), &[_]u8{}));
    try std.testing.expectEqual(@as(usize, 2), router.statelessResetTokenCount());
    try std.testing.expectEqual(@as(?usize, null), try router.findShortRouteIndex(testPath(50_000), &[_]u8{ 0x40, 0xaa, 0xbb, 0x00 }));
    try std.testing.expectEqual(@as(usize, 0), router.routeCount());
}

test "EndpointRouter rejects stateless reset token reuse across connection IDs" {
    const cid0 = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3 };
    const cid1 = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3 };
    const cid2 = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const token0 = [_]u8{0x31} ** stateless_reset_token_len;
    const token1 = [_]u8{0x32} ** stateless_reset_token_len;
    const path = testPath(50_000);
    var router = EndpointRouter.init(std.testing.allocator);
    defer router.deinit();

    try router.registerConnectionId(1, &cid0, path, .{ .sequence_number = 0, .stateless_reset_token = token0 });
    try std.testing.expectError(
        error.DuplicateConnectionId,
        router.registerConnectionId(1, &cid1, path, .{ .sequence_number = 1, .stateless_reset_token = token0 }),
    );
    try std.testing.expectEqual(@as(usize, 1), router.routeCount());
    try std.testing.expectEqual(@as(usize, 1), router.statelessResetTokenCount());

    try router.registerStatelessResetToken(&cid1, token1);
    try std.testing.expectError(
        error.DuplicateConnectionId,
        router.registerStatelessResetToken(&cid2, token1),
    );
    try std.testing.expectError(error.UnknownConnectionId, router.routeConnectionId(&cid1, path));
    try std.testing.expectEqual(@as(usize, 2), router.statelessResetTokenCount());
}
