//! Reusable endpoint ownership for TLS 1.3 server connection records.
//!
//! This type owns lifecycle routing/timers and record storage, but deliberately
//! leaves UDP socket I/O, admission policy, and application dispatch with its
//! caller.

const std = @import("std");
const endpoint_types = @import("endpoint_types.zig");
const address_validation_token = @import("address_validation_token.zig");
const buffer = @import("buffer.zig");
const root = @import("../lib.zig");
const connection_module = @import("connection.zig");
const endpoint = @import("endpoint.zig");
const endpoint_connection_registry = @import("endpoint_connection_registry.zig");
const endpoint_lifecycle = @import("endpoint_lifecycle.zig");
const frame = @import("frame.zig");
const quic_packet = @import("packet.zig");
const protection = @import("protection.zig");
const tls13 = @import("../tls/tls13.zig");
const tls13_client_endpoint = @import("tls13_client_endpoint.zig");
const tls13_server_transport = @import("tls13_server_transport.zig");

const Connection = connection_module.Connection;
const Tls13ClientEndpoint = tls13_client_endpoint.Tls13ClientEndpoint;
const Tls13ServerTransport = tls13_server_transport.Tls13ServerTransport;

/// Build an endpoint owner for one caller-defined TLS server record type.
///
/// Records own their transport/backend and application metadata. The endpoint
/// owns their lifetime, CID routing, recovery timers, and path policy.
pub fn Tls13ServerEndpoint(
    comptime Record: type,
    comptime connection_of: *const fn (*Record) *Connection,
    comptime crypto_backend_of: *const fn (*Record) root.CryptoBackend,
    comptime destination_connection_id_of: *const fn (*const Record) []const u8,
    comptime source_connection_id_of: *const fn (*const Record) []const u8,
    comptime initial_destination_connection_id_of: *const fn (*const Record) []const u8,
    comptime mark_retry_validated: *const fn (*Record) void,
    comptime deinit_record: *const fn (*Record) void,
) type {
    return Tls13ServerEndpointForTuple(
        endpoint.Udp4Tuple,
        Record,
        connection_of,
        crypto_backend_of,
        destination_connection_id_of,
        source_connection_id_of,
        initial_destination_connection_id_of,
        mark_retry_validated,
        deinit_record,
    );
}

/// Build a TLS server endpoint owner for one fixed UDP address family.
pub fn Tls13ServerEndpointForTuple(
    comptime Path: type,
    comptime Record: type,
    comptime connection_of: *const fn (*Record) *Connection,
    comptime crypto_backend_of: *const fn (*Record) root.CryptoBackend,
    comptime destination_connection_id_of: *const fn (*const Record) []const u8,
    comptime source_connection_id_of: *const fn (*const Record) []const u8,
    comptime initial_destination_connection_id_of: *const fn (*const Record) []const u8,
    comptime mark_retry_validated: *const fn (*Record) void,
    comptime deinit_record: *const fn (*Record) void,
) type {
    const EndpointConnectionLifecycle = endpoint_lifecycle.EndpointConnectionLifecycleForTuple(Path);
    const PathEndpoint = endpoint.ForTuple(Path);
    const PathTypes = endpoint_types.ForTuple(Path);
    const Registry = endpoint_connection_registry.EndpointConnectionRegistryForTuple(
        Path,
        Record,
        connection_of,
        deinit_record,
    );

    return struct {
        const Self = @This();

        /// Endpoint-owned 1-RTT datagram paired with its committed UDP route.
        pub const OneRttDatagramPathResult = struct {
            datagram: []u8,
            path: Path,
        };

        /// Endpoint-owned protected datagram paired with its committed UDP route.
        pub const DatagramPathResult = struct {
            /// Endpoint-owned connection handle that produced `datagram`.
            connection_id: u64,
            /// Protected datagram emitted by the selected record.
            datagram: []u8,
            /// Current committed UDP tuple for this record's local route CID.
            path: Path,
        };

        /// Endpoint response datagram paired with the UDP tuple it answers.
        pub const DatagramResponsePathResult = struct {
            /// Response datagram written into caller-provided scratch storage.
            datagram: []const u8,
            /// UDP tuple that produced the response.
            path: Path,
        };

        /// Route classification with response datagrams paired to their path.
        pub const DatagramActionPathResult = union(enum) {
            routed: endpoint.RouteResult,
            accept_initial: PathEndpoint.InitialAcceptResult,
            version_negotiation: DatagramResponsePathResult,
            stateless_reset: DatagramResponsePathResult,
            dropped,
        };

        /// Installed-key receive result with any immediate output route.
        pub const InstalledKeyDatagramRoutePollResult = struct {
            /// Receive, path validation, and route-update result when feed succeeded.
            feed: ?PathTypes.EndpointFeedInstalledKeyPathUpdateResult = null,
            /// Feed error returned after the endpoint had selected a record.
            feed_error: ?endpoint_types.EndpointProtectedDatagramError = null,
            /// Peer-issued CID sequence whose stateless reset token matched.
            stateless_reset_sequence_number: ?u64 = null,
            /// Protected output emitted after feed or close-on-error handling.
            datagram: ?DatagramPathResult = null,
            /// Next endpoint-visible deadline after receive processing and optional output.
            next_deadline: ?endpoint_types.EndpointConnectionDeadline = null,
        };

        /// Due-work result with every drained datagram paired to a route.
        pub const DueWorkDatagramPathDrainResult = struct {
            /// Deadline that was due when this pending-work pass started.
            deadline: endpoint_types.EndpointConnectionDeadline,
            /// Pending-work actions applied for the due deadline.
            pending_work: endpoint_types.EndpointPendingWorkResult,
            /// Bounded output drain after a due recovery timer, if any.
            drain: DatagramPathDrainResult,
            /// Next endpoint-visible deadline after due work and output drain.
            next_deadline: ?endpoint_types.EndpointConnectionDeadline = null,
        };

        /// Pending-work sweep result with every drained datagram paired to a route.
        pub const PendingWorkDatagramPathDrainResult = struct {
            /// Pending-work actions applied across endpoint-owned records.
            pending_work: endpoint_types.EndpointPendingWorkSweepResult,
            /// Bounded output drain after pending recovery work, if any.
            drain: DatagramPathDrainResult,
            /// Next endpoint-visible deadline after pending work and output drain.
            next_deadline: ?endpoint_types.EndpointConnectionDeadline = null,
        };

        /// Installed-key receive plus pending-work result with route-bound output drain.
        pub const FeedPendingWorkDatagramPathDrainResult = struct {
            /// Receive classification and processing result.
            feed: PathTypes.EndpointFeedInstalledKeyDatagramResult,
            /// Pending-work actions applied after receive processing.
            pending_work: endpoint_types.EndpointPendingWorkSweepResult,
            /// Bounded output drain after pending recovery work, if any.
            drain: DatagramPathDrainResult,
            /// Next endpoint-visible deadline after receive, pending work, and output drain.
            next_deadline: ?endpoint_types.EndpointConnectionDeadline = null,
        };

        /// Installed-key receive plus pending-work result with one route-bound output poll.
        pub const FeedPendingWorkDatagramPathPollResult = struct {
            /// Receive classification and processing result.
            feed: PathTypes.EndpointFeedInstalledKeyDatagramResult,
            /// Pending-work actions applied after receive processing.
            pending_work: endpoint_types.EndpointPendingWorkSweepResult,
            /// Route preflight error before pending recovery work, if any.
            pending_route_error: ?endpoint.RouteError = null,
            /// Protected output emitted after pending recovery work, if any.
            datagram: ?DatagramPathResult = null,
            /// Next endpoint-visible deadline after receive, pending work, and output poll.
            next_deadline: ?endpoint_types.EndpointConnectionDeadline = null,
        };

        /// Result from draining active-record output with committed route paths.
        pub const DatagramPathDrainResult = struct {
            /// Number of initialized entries written to the caller-provided output slice.
            datagrams_written: usize = 0,
            /// First polling error observed after any earlier entries were written.
            first_error: ?root.Error = null,
            /// First route lookup error observed after any earlier entries were written.
            first_route_error: ?endpoint.RouteError = null,
        };

        /// Explicit close result with bounded route-bound output.
        pub const CloseDatagramPathDrainResult = struct {
            drain: DatagramPathDrainResult = .{},
            next_deadline: ?endpoint_types.EndpointConnectionDeadline = null,
        };

        /// Application stream/control result with bounded route-bound output.
        pub const OneRttControlDatagramPathDrainResult = struct {
            drain: DatagramPathDrainResult = .{},
            next_deadline: ?endpoint_types.EndpointConnectionDeadline = null,
        };

        /// Accepted Initial output paired with the committed UDP route.
        pub const AcceptedInitialDatagramDrainPathResult = struct {
            accepted: PathTypes.EndpointAcceptedInitialCryptoBackendDatagramDrainResult,
            path: Path,
        };

        /// Backend-driven installed-key output paired with the committed route.
        pub const CryptoBackendDatagramDrainPathResult = struct {
            backend: endpoint_types.EndpointCryptoBackendDriveDatagramDrainResult,
            path: Path,
        };

        /// Backend-driven long-header output paired with the committed route.
        pub const ProtectedLongBackendDatagramDrainPathResult = struct {
            backend: endpoint_types.EndpointCryptoBackendDriveProtectedLongDatagramDrainResult,
            path: Path,
        };

        /// Accepted Initial record admission with route-bound output drains.
        pub const InitialRecordAdmissionPathResult = struct {
            initial: AcceptedInitialDatagramDrainPathResult,
            handshake: ?CryptoBackendDatagramDrainPathResult = null,
        };

        /// Capacity drop metadata for a new Initial that was not admitted.
        pub const InitialRecordCapacityDropResult = struct {
            active_connections: usize,
            active_connection_limit: usize,
        };

        /// Capacity-aware accepted Initial admission result.
        pub const InitialRecordAdmissionAttemptPathResult = union(enum) {
            admitted: InitialRecordAdmissionPathResult,
            dropped_capacity: InitialRecordCapacityDropResult,
        };

        /// Routed Initial processing with route-bound output drains.
        pub const InitialProcessPathResult = struct {
            initial: struct {
                route: endpoint.RouteResult,
                backend: ProtectedLongBackendDatagramDrainPathResult,
            },
            handshake: ?CryptoBackendDatagramDrainPathResult = null,
        };

        /// Routed long-header packet dispatch with route-bound output drains.
        pub const LongPacketProcessPathResult = union(enum) {
            initial: InitialProcessPathResult,
            handshake: RoutedBackendDatagramDrainPathResult,
        };

        /// Routed long datagram dispatch with route-bound output drains.
        pub const LongDatagramProcessPathResult = union(enum) {
            packet: LongPacketProcessPathResult,
            coalesced_initial_handshake: RoutedBackendDatagramDrainPathResult,
        };

        /// Routed datagram dispatch with route-bound output.
        pub const RoutedDatagramProcessPathResult = union(enum) {
            long: LongDatagramProcessPathResult,
            installed_key: InstalledKeyDatagramRoutePollResult,
        };

        /// Installed-key receive result with bounded route-bound output drain.
        pub const InstalledKeyDatagramRouteDrainResult = struct {
            /// Receive, path validation, and route-update result when feed succeeded.
            feed: ?PathTypes.EndpointFeedInstalledKeyPathUpdateResult = null,
            /// Feed error returned after the endpoint had selected a record.
            feed_error: ?endpoint_types.EndpointProtectedDatagramError = null,
            /// Peer-issued CID sequence whose stateless reset token matched.
            stateless_reset_sequence_number: ?u64 = null,
            /// Bounded protected output drain after receive or close-on-error handling.
            drain: endpoint_types.EndpointDatagramDrainResult = .{},
            /// Next endpoint-visible deadline after receive processing and bounded output.
            next_deadline: ?endpoint_types.EndpointConnectionDeadline = null,
        };

        /// Routed datagram dispatch with bounded route-bound output drain.
        pub const RoutedDatagramDrainPathResult = union(enum) {
            long: LongDatagramProcessPathResult,
            installed_key: InstalledKeyDatagramRouteDrainResult,
        };

        /// Endpoint classification plus routed datagram processing result.
        pub const DatagramProcessPathResult = union(enum) {
            routed: RoutedDatagramProcessPathResult,
            accept_initial: PathEndpoint.InitialAcceptResult,
            version_negotiation: DatagramResponsePathResult,
            stateless_reset: DatagramResponsePathResult,
            dropped,
        };

        /// Endpoint classification plus routed datagram processing and bounded drain.
        pub const DatagramProcessDrainPathResult = union(enum) {
            routed: RoutedDatagramDrainPathResult,
            accept_initial: PathEndpoint.InitialAcceptResult,
            version_negotiation: DatagramResponsePathResult,
            stateless_reset: DatagramResponsePathResult,
            dropped,
        };

        /// One server socket-loop receive step with route-bound output and pending work.
        pub const DatagramStepPathResult = struct {
            /// Endpoint classification plus routed datagram processing result.
            process: DatagramProcessDrainPathResult,
            /// Pending work swept across endpoint-owned records after receive.
            pending_work: endpoint_types.EndpointPendingWorkSweepResult,
            /// Bounded route-bound output after pending recovery work, if any.
            pending_drain: DatagramPathDrainResult,
            /// Next endpoint-visible deadline after receive, drain, and pending work.
            next_deadline: ?endpoint_types.EndpointConnectionDeadline = null,
        };

        /// One server socket-loop receive step that may admit a new Initial record.
        pub const InitialAdmissionDatagramStepPathResult = struct {
            /// Endpoint classification plus routed datagram processing result.
            process: DatagramProcessDrainPathResult,
            /// Admission result when `process` classified a fresh Initial.
            admission: ?InitialRecordAdmissionAttemptPathResult = null,
            /// Pending work swept across endpoint-owned records after receive.
            pending_work: endpoint_types.EndpointPendingWorkSweepResult,
            /// Bounded route-bound output after pending recovery work, if any.
            pending_drain: DatagramPathDrainResult,
            /// Next endpoint-visible deadline after receive, optional admission, and pending work.
            next_deadline: ?endpoint_types.EndpointConnectionDeadline = null,
        };

        const PendingStepPathResult = struct {
            pending_work: endpoint_types.EndpointPendingWorkSweepResult = .{},
            pending_drain: DatagramPathDrainResult = .{},
            next_deadline: ?endpoint_types.EndpointConnectionDeadline = null,
        };

        /// Routed installed-key backend processing with route-bound output.
        pub const RoutedBackendDatagramDrainPathResult = struct {
            route: endpoint.RouteResult,
            backend: CryptoBackendDatagramDrainPathResult,
        };

        /// Retry follow-up Initial validation with route-bound TLS output.
        pub const RetryInitialProcessPathResult = struct {
            /// Authenticated Retry follow-up metadata and token validation.
            retry: PathTypes.EndpointRetryProtectedInitialResult,
            /// Initial-space TLS backend output after the Retry follow-up.
            initial: ProtectedLongBackendDatagramDrainPathResult,
            /// Handshake-space backend output after Initial installed keys.
            handshake: ?CryptoBackendDatagramDrainPathResult = null,
        };

        lifecycle: EndpointConnectionLifecycle,
        records: Registry,

        fn packetNumberSpace(space: endpoint_types.EndpointInstalledKeyDatagramSpace) root.PacketNumberSpace {
            return switch (space) {
                .handshake => .handshake,
                .zero_rtt, .application => .application,
            };
        }

        fn preflightDueRecoveryRoutes(
            self: *Self,
            now_nanos: i64,
        ) (root.Error || endpoint.RouteError)!void {
            _ = try self.records.removeClosedRecords(&self.lifecycle);
            var iterator = self.records.records.iterator();
            while (iterator.next()) |entry| {
                const connection_id = entry.key_ptr.*;
                const record = entry.value_ptr.*;
                const connection = connection_of(record);
                const deadline = self.lifecycle.nextDeadline(connection_id, connection) orelse continue;
                if (deadline.deadline_nanos > now_nanos) continue;
                if (deadline.kind != .recovery) continue;
                if (deadline.recovery == null) continue;
                _ = try self.currentRecordRoutePath(record);
            }
        }

        fn hasDueRecoveryForInstalledKeySpace(
            self: *const Self,
            now_nanos: i64,
            space: endpoint_types.EndpointInstalledKeyDatagramSpace,
        ) bool {
            const packet_space = packetNumberSpace(space);
            var iterator = self.records.records.iterator();
            while (iterator.next()) |entry| {
                const connection_id = entry.key_ptr.*;
                const record = entry.value_ptr.*;
                const connection = connection_of(record);
                const deadline = self.lifecycle.nextDeadline(connection_id, connection) orelse continue;
                if (deadline.deadline_nanos > now_nanos) continue;
                if (deadline.kind != .recovery) continue;
                const recovery = deadline.recovery orelse continue;
                if (recovery.space == packet_space) return true;
            }
            return false;
        }

        fn currentRecordRoutePath(self: *const Self, record: *const Record) endpoint.RouteError!Path {
            return self.lifecycle.currentRoutePath(source_connection_id_of(record));
        }

        fn classifyRoutePreflightError(err: anyerror) ?endpoint.RouteError {
            return switch (err) {
                error.InvalidConnectionIdLength,
                error.InvalidConnectionIdSequence,
                error.InvalidDatagram,
                error.InvalidVersionList,
                error.InvalidResetSize,
                error.DuplicateConnectionId,
                error.RouteCapacityReached,
                error.StatelessResetTokenCapacityReached,
                error.UnknownConnectionId,
                error.AmbiguousConnectionId,
                error.ActiveMigrationDisabled,
                error.PathMismatch,
                => @errorCast(err),
                else => null,
            };
        }

        fn retireRecordAfterTerminalPendingWork(
            self: *Self,
            connection_id: u64,
            pending_work: endpoint_types.EndpointPendingWorkResult,
        ) root.Error!void {
            if (pending_work.idle_retired == null and pending_work.close_retired == null) return;
            self.records.remove(connection_id) catch return error.Internal;
        }

        /// Create an endpoint with dynamically allocated record and route storage.
        ///
        /// The caller owns admission and resource policy. Use
        /// `initWithCapacity()` when a fixed active-connection limit and
        /// up-front lifecycle storage are required.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .lifecycle = EndpointConnectionLifecycle.init(allocator),
                .records = Registry.init(allocator),
            };
        }

        /// Create an endpoint with bounded record, route, and reset-token storage.
        pub fn initWithCapacity(
            allocator: std.mem.Allocator,
            max_active_connections: usize,
            router_options: endpoint.EndpointRouterOptions,
        ) !Self {
            var lifecycle = EndpointConnectionLifecycle.initWithRouterOptions(allocator, router_options);
            errdefer lifecycle.deinit();
            try lifecycle.router.reserveConfiguredCapacity();
            try lifecycle.recovery_timers.ensureCapacity(max_active_connections);
            return .{
                .lifecycle = lifecycle,
                .records = try Registry.initWithCapacity(allocator, max_active_connections),
            };
        }

        /// Release all active records before lifecycle routing/timer state.
        pub fn deinit(self: *Self) void {
            self.records.deinit();
            self.lifecycle.deinit();
        }

        /// Return the number of endpoint-owned active connection records.
        pub fn activeConnectionCount(self: *const Self) usize {
            return self.records.activeCount();
        }

        /// Return the configured active-connection limit.
        ///
        /// Dynamically sized endpoints report `std.math.maxInt(usize)`.
        pub fn activeConnectionLimit(self: *const Self) usize {
            return self.records.capacityLimit();
        }

        /// Return whether this endpoint can accept one more connection record.
        pub fn hasConnectionCapacity(self: *const Self) bool {
            return self.records.hasActiveCapacity();
        }

        /// Write active endpoint-owned connection handles into caller-owned storage.
        pub fn activeConnectionIds(self: *const Self, out: []u64) root.Error![]u64 {
            return self.records.fillActiveConnectionIds(out);
        }

        /// Classify one UDP datagram through this endpoint's lifecycle owner.
        pub fn feedDatagram(
            self: *const Self,
            out: []u8,
            path: Path,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
        ) endpoint.RouteError!PathEndpoint.DatagramAction {
            return self.lifecycle.feedDatagram(
                out,
                path,
                datagram,
                unpredictable_prefix,
                supported_versions,
            );
        }

        /// Classify one UDP datagram and pair endpoint-generated responses
        /// with the UDP tuple that must receive them.
        pub fn feedDatagramWithResponsePath(
            self: *const Self,
            out: []u8,
            path: Path,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
        ) endpoint.RouteError!DatagramActionPathResult {
            return switch (try self.feedDatagram(
                out,
                path,
                datagram,
                unpredictable_prefix,
                supported_versions,
            )) {
                .routed => |route| .{ .routed = route },
                .accept_initial => |initial| .{ .accept_initial = initial },
                .version_negotiation => |response| .{ .version_negotiation = .{
                    .datagram = response,
                    .path = path,
                } },
                .stateless_reset => |reset| .{ .stateless_reset = .{
                    .datagram = reset,
                    .path = path,
                } },
                .dropped => .dropped,
            };
        }

        /// Resolve one routed datagram without decrypting it.
        pub fn routeDatagram(
            self: *const Self,
            path: Path,
            datagram: []const u8,
        ) endpoint.RouteError!endpoint.RouteResult {
            return self.lifecycle.routeDatagram(path, datagram);
        }

        /// Retire one endpoint-owned record together with all lifecycle state.
        ///
        /// The route/timer retirement is idempotent because deadline processing
        /// can have already retired them before the caller destroys the record.
        pub fn retireRecord(
            self: *Self,
            connection_id: u64,
        ) error{ Internal, UnknownConnectionId }!endpoint_types.EndpointConnectionRetireResult {
            return self.records.retire(&self.lifecycle, connection_id);
        }

        /// Retire lifecycle state and destroy endpoint-owned records that are already closed.
        pub fn reclaimClosedRecords(self: *Self) root.Error!usize {
            return self.records.removeClosedRecords(&self.lifecycle);
        }

        /// Select the earliest deadline across all endpoint-owned records.
        pub fn nextDeadline(
            self: *Self,
            allocator: std.mem.Allocator,
        ) !?endpoint_types.EndpointConnectionDeadline {
            return self.records.nextDeadline(&self.lifecycle, allocator);
        }

        /// Select the earliest deadline across endpoint-owned records without allocating.
        ///
        /// `out` must have room for every active server record. This is the
        /// production socket-loop path for bounded endpoint owners that need
        /// stable wakeup selection without per-iteration heap allocation.
        pub fn nextDeadlineWithStorage(
            self: *Self,
            out: []root.EndpointConnectionView,
        ) root.Error!?endpoint_types.EndpointConnectionDeadline {
            return self.records.nextDeadlineWithStorage(&self.lifecycle, out);
        }

        /// Select the earliest endpoint-owned deadline using registry scratch storage.
        pub fn nextDeadlineWithScratch(self: *Self) root.Error!?endpoint_types.EndpointConnectionDeadline {
            return self.records.nextDeadlineWithScratch(&self.lifecycle);
        }

        /// Sweep all endpoint-owned records, retire closed records, and return
        /// the next endpoint-visible deadline.
        pub fn processPendingWorkAndSelectNextDeadline(
            self: *Self,
            allocator: std.mem.Allocator,
            now_nanos: i64,
        ) root.Error!endpoint_types.EndpointPendingWorkNextDeadlineResult {
            return self.records.processPendingWorkAndSelectNextDeadline(
                &self.lifecycle,
                allocator,
                now_nanos,
            );
        }

        /// Sweep pending work and select the next endpoint-owned deadline using scratch storage.
        pub fn processPendingWorkAndSelectNextDeadlineWithScratch(
            self: *Self,
            now_nanos: i64,
        ) root.Error!endpoint_types.EndpointPendingWorkNextDeadlineResult {
            return self.records.processPendingWorkAndSelectNextDeadlineWithScratch(
                &self.lifecycle,
                now_nanos,
            );
        }

        /// Sweep pending work across endpoint-owned records and drain route-bound output.
        pub fn processPendingWorkAndDrainDatagramsWithRoutePath(
            self: *Self,
            allocator: std.mem.Allocator,
            now_nanos: i64,
            space: endpoint_types.EndpointInstalledKeyDatagramSpace,
            out: []DatagramPathResult,
        ) root.Error!PendingWorkDatagramPathDrainResult {
            self.preflightDueRecoveryRoutes(now_nanos) catch |err| {
                const route_error = classifyRoutePreflightError(err) orelse return @errorCast(err);
                return .{
                    .pending_work = .{},
                    .drain = .{ .first_route_error = route_error },
                    .next_deadline = try self.nextDeadline(allocator),
                };
            };
            if (out.len == 0 and self.hasDueRecoveryForInstalledKeySpace(now_nanos, space)) {
                return .{
                    .pending_work = .{},
                    .drain = .{ .first_error = error.BufferTooSmall },
                    .next_deadline = try self.nextDeadline(allocator),
                };
            }
            const pending_work = try self.records.processPendingWork(
                &self.lifecycle,
                allocator,
                now_nanos,
            );
            const drain = if (pending_work.recovery_serviced_count == 0)
                DatagramPathDrainResult{}
            else
                self.drainDatagramsAcrossRecordsWithRoutePath(
                    allocator,
                    now_nanos,
                    space,
                    out,
                );
            return .{
                .pending_work = pending_work,
                .drain = drain,
                .next_deadline = try self.nextDeadline(allocator),
            };
        }

        /// Sweep pending work and drain route-bound output using registry scratch storage.
        pub fn processPendingWorkAndDrainDatagramsWithRoutePathWithScratch(
            self: *Self,
            now_nanos: i64,
            space: endpoint_types.EndpointInstalledKeyDatagramSpace,
            out: []DatagramPathResult,
        ) root.Error!PendingWorkDatagramPathDrainResult {
            self.preflightDueRecoveryRoutes(now_nanos) catch |err| {
                const route_error = classifyRoutePreflightError(err) orelse return @errorCast(err);
                return .{
                    .pending_work = .{},
                    .drain = .{ .first_route_error = route_error },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                };
            };
            if (out.len == 0 and self.hasDueRecoveryForInstalledKeySpace(now_nanos, space)) {
                return .{
                    .pending_work = .{},
                    .drain = .{ .first_error = error.BufferTooSmall },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                };
            }
            const pending_work = try self.records.processPendingWorkWithScratch(
                &self.lifecycle,
                now_nanos,
            );
            const drain = if (pending_work.recovery_serviced_count == 0)
                DatagramPathDrainResult{}
            else
                self.drainDatagramsAcrossRecordsWithRoutePathWithScratch(
                    now_nanos,
                    space,
                    out,
                );
            return .{
                .pending_work = pending_work,
                .drain = drain,
                .next_deadline = try self.nextDeadlineWithScratch(),
            };
        }

        /// Service the earliest due deadline and drain bounded protected output.
        pub fn processDueDeadlineAndDrainDatagrams(
            self: *Self,
            allocator: std.mem.Allocator,
            now_nanos: i64,
            out: []endpoint_types.EndpointPolledDatagramResult,
        ) root.Error!?endpoint_types.EndpointDueWorkDatagramDrainResult {
            const deadline = (try self.nextDeadline(allocator)) orelse return null;
            if (deadline.deadline_nanos > now_nanos) return null;
            const record = self.records.get(deadline.connection_id) orelse return error.Internal;
            const connection = connection_of(record);
            const source_connection_id = source_connection_id_of(record);

            const pending_drain = if (deadline.installedKeyPollOptions(
                destination_connection_id_of(record),
                source_connection_id,
            )) |options|
                try self.lifecycle.processPendingWorkAndDrainDatagrams(
                    deadline.connection_id,
                    connection,
                    now_nanos,
                    options,
                    out,
                )
            else if (deadline.kind == .recovery and deadline.recovery != null and deadline.recovery.?.space == .initial) pending: {
                if (out.len == 0) return error.BufferTooSmall;
                const pending = try self.lifecycle.processPendingWork(
                    deadline.connection_id,
                    connection,
                    now_nanos,
                );
                const serviced = pending.recovery_serviced orelse break :pending endpoint_types.EndpointPendingWorkDatagramDrainResult{
                    .pending_work = pending,
                    .drain = .{},
                };
                if (serviced.timer.space != .initial) return error.InvalidPacket;
                break :pending endpoint_types.EndpointPendingWorkDatagramDrainResult{
                    .pending_work = pending,
                    .drain = self.drainInitialDatagrams(
                        deadline.connection_id,
                        record,
                        connection,
                        now_nanos,
                        out,
                    ),
                };
            } else endpoint_types.EndpointPendingWorkDatagramDrainResult{
                .pending_work = try self.lifecycle.processPendingWork(
                    deadline.connection_id,
                    connection,
                    now_nanos,
                ),
                .drain = .{},
            };

            try self.retireRecordAfterTerminalPendingWork(deadline.connection_id, pending_drain.pending_work);
            return .{
                .deadline = deadline,
                .pending_work = pending_drain.pending_work,
                .drain = pending_drain.drain,
                .next_deadline = try self.nextDeadline(allocator),
            };
        }

        /// Service the earliest due deadline using registry scratch storage.
        pub fn processDueDeadlineAndDrainDatagramsWithScratch(
            self: *Self,
            now_nanos: i64,
            out: []endpoint_types.EndpointPolledDatagramResult,
        ) root.Error!?endpoint_types.EndpointDueWorkDatagramDrainResult {
            const deadline = (try self.nextDeadlineWithScratch()) orelse return null;
            if (deadline.deadline_nanos > now_nanos) return null;
            const record = self.records.get(deadline.connection_id) orelse return error.Internal;
            const connection = connection_of(record);
            const source_connection_id = source_connection_id_of(record);

            const pending_drain = if (deadline.installedKeyPollOptions(
                destination_connection_id_of(record),
                source_connection_id,
            )) |options|
                try self.lifecycle.processPendingWorkAndDrainDatagrams(
                    deadline.connection_id,
                    connection,
                    now_nanos,
                    options,
                    out,
                )
            else if (deadline.kind == .recovery and deadline.recovery != null and deadline.recovery.?.space == .initial) pending: {
                if (out.len == 0) return error.BufferTooSmall;
                const pending = try self.lifecycle.processPendingWork(
                    deadline.connection_id,
                    connection,
                    now_nanos,
                );
                const serviced = pending.recovery_serviced orelse break :pending endpoint_types.EndpointPendingWorkDatagramDrainResult{
                    .pending_work = pending,
                    .drain = .{},
                };
                if (serviced.timer.space != .initial) return error.InvalidPacket;
                break :pending endpoint_types.EndpointPendingWorkDatagramDrainResult{
                    .pending_work = pending,
                    .drain = self.drainInitialDatagrams(
                        deadline.connection_id,
                        record,
                        connection,
                        now_nanos,
                        out,
                    ),
                };
            } else endpoint_types.EndpointPendingWorkDatagramDrainResult{
                .pending_work = try self.lifecycle.processPendingWork(
                    deadline.connection_id,
                    connection,
                    now_nanos,
                ),
                .drain = .{},
            };

            try self.retireRecordAfterTerminalPendingWork(deadline.connection_id, pending_drain.pending_work);
            return .{
                .deadline = deadline,
                .pending_work = pending_drain.pending_work,
                .drain = pending_drain.drain,
                .next_deadline = try self.nextDeadlineWithScratch(),
            };
        }

        /// Service the earliest due deadline and pair output with route paths.
        ///
        /// This socket-facing form keeps recovery service and packet generation
        /// under the lifecycle owner, while also resolving the current endpoint
        /// route before output is emitted. Each initialized output slot is owned
        /// by the caller and must be freed even when `drain.first_error` is set.
        pub fn processDueDeadlineAndDrainDatagramsWithRoutePath(
            self: *Self,
            allocator: std.mem.Allocator,
            now_nanos: i64,
            out: []DatagramPathResult,
        ) (root.Error || endpoint.RouteError)!?DueWorkDatagramPathDrainResult {
            const deadline = (try self.nextDeadline(allocator)) orelse return null;
            if (deadline.deadline_nanos > now_nanos) return null;
            const record = self.records.get(deadline.connection_id) orelse return error.Internal;
            const connection = connection_of(record);
            const source_connection_id = source_connection_id_of(record);
            const drains_recovery_datagram = deadline.kind == .recovery and deadline.recovery != null and (deadline.installedKeyPollOptions(
                destination_connection_id_of(record),
                source_connection_id,
            ) != null or deadline.recovery.?.space == .initial);
            if (drains_recovery_datagram and out.len == 0) return error.BufferTooSmall;
            const route_path = if (drains_recovery_datagram)
                self.lifecycle.currentRoutePath(source_connection_id) catch |err| {
                    return .{
                        .deadline = deadline,
                        .pending_work = .{},
                        .drain = .{ .first_route_error = err },
                        .next_deadline = try self.nextDeadline(allocator),
                    };
                }
            else
                null;

            const pending_work = if (deadline.installedKeyPollOptions(
                destination_connection_id_of(record),
                source_connection_id,
            )) |options| pending: {
                const pending = try self.lifecycle.processPendingWork(
                    deadline.connection_id,
                    connection,
                    now_nanos,
                );
                const serviced = pending.recovery_serviced orelse break :pending pending;
                if (serviced.timer.space != options.recoveryPacketNumberSpace()) return error.InvalidPacket;
                const drain = self.drainDatagramsWithRoutePath(
                    deadline.connection_id,
                    connection,
                    now_nanos,
                    options,
                    route_path.?,
                    out,
                );
                return .{
                    .deadline = deadline,
                    .pending_work = pending,
                    .drain = .{
                        .datagrams_written = drain.datagrams_written,
                        .first_error = drain.first_error,
                    },
                    .next_deadline = try self.nextDeadline(allocator),
                };
            } else if (deadline.kind == .recovery and deadline.recovery != null and deadline.recovery.?.space == .initial) pending: {
                const pending = try self.lifecycle.processPendingWork(
                    deadline.connection_id,
                    connection,
                    now_nanos,
                );
                const serviced = pending.recovery_serviced orelse break :pending pending;
                if (serviced.timer.space != .initial) return error.InvalidPacket;
                const drain = self.drainInitialDatagramsWithRoutePath(
                    deadline.connection_id,
                    record,
                    connection,
                    now_nanos,
                    route_path.?,
                    out,
                );
                return .{
                    .deadline = deadline,
                    .pending_work = pending,
                    .drain = .{
                        .datagrams_written = drain.datagrams_written,
                        .first_error = drain.first_error,
                    },
                    .next_deadline = try self.nextDeadline(allocator),
                };
            } else try self.lifecycle.processPendingWork(
                deadline.connection_id,
                connection,
                now_nanos,
            );
            try self.retireRecordAfterTerminalPendingWork(deadline.connection_id, pending_work);

            return .{
                .deadline = deadline,
                .pending_work = pending_work,
                .drain = .{},
                .next_deadline = try self.nextDeadline(allocator),
            };
        }

        /// Service the earliest due deadline with route paths using registry scratch storage.
        pub fn processDueDeadlineAndDrainDatagramsWithRoutePathWithScratch(
            self: *Self,
            now_nanos: i64,
            out: []DatagramPathResult,
        ) (root.Error || endpoint.RouteError)!?DueWorkDatagramPathDrainResult {
            const deadline = (try self.nextDeadlineWithScratch()) orelse return null;
            if (deadline.deadline_nanos > now_nanos) return null;
            const record = self.records.get(deadline.connection_id) orelse return error.Internal;
            const connection = connection_of(record);
            const source_connection_id = source_connection_id_of(record);
            const drains_recovery_datagram = deadline.kind == .recovery and deadline.recovery != null and (deadline.installedKeyPollOptions(
                destination_connection_id_of(record),
                source_connection_id,
            ) != null or deadline.recovery.?.space == .initial);
            if (drains_recovery_datagram and out.len == 0) return error.BufferTooSmall;
            const route_path = if (drains_recovery_datagram)
                self.lifecycle.currentRoutePath(source_connection_id) catch |err| {
                    return .{
                        .deadline = deadline,
                        .pending_work = .{},
                        .drain = .{ .first_route_error = err },
                        .next_deadline = try self.nextDeadlineWithScratch(),
                    };
                }
            else
                null;

            const pending_work = if (deadline.installedKeyPollOptions(
                destination_connection_id_of(record),
                source_connection_id,
            )) |options| pending: {
                const pending = try self.lifecycle.processPendingWork(
                    deadline.connection_id,
                    connection,
                    now_nanos,
                );
                const serviced = pending.recovery_serviced orelse break :pending pending;
                if (serviced.timer.space != options.recoveryPacketNumberSpace()) return error.InvalidPacket;
                const drain = self.drainDatagramsWithRoutePath(
                    deadline.connection_id,
                    connection,
                    now_nanos,
                    options,
                    route_path.?,
                    out,
                );
                return .{
                    .deadline = deadline,
                    .pending_work = pending,
                    .drain = .{
                        .datagrams_written = drain.datagrams_written,
                        .first_error = drain.first_error,
                    },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                };
            } else if (deadline.kind == .recovery and deadline.recovery != null and deadline.recovery.?.space == .initial) pending: {
                const pending = try self.lifecycle.processPendingWork(
                    deadline.connection_id,
                    connection,
                    now_nanos,
                );
                const serviced = pending.recovery_serviced orelse break :pending pending;
                if (serviced.timer.space != .initial) return error.InvalidPacket;
                const drain = self.drainInitialDatagramsWithRoutePath(
                    deadline.connection_id,
                    record,
                    connection,
                    now_nanos,
                    route_path.?,
                    out,
                );
                return .{
                    .deadline = deadline,
                    .pending_work = pending,
                    .drain = .{
                        .datagrams_written = drain.datagrams_written,
                        .first_error = drain.first_error,
                    },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                };
            } else try self.lifecycle.processPendingWork(
                deadline.connection_id,
                connection,
                now_nanos,
            );
            try self.retireRecordAfterTerminalPendingWork(deadline.connection_id, pending_work);

            return .{
                .deadline = deadline,
                .pending_work = pending_work,
                .drain = .{},
                .next_deadline = try self.nextDeadlineWithScratch(),
            };
        }

        fn drainInitialDatagramsWithRoutePath(
            self: *Self,
            connection_id: u64,
            record: *const Record,
            connection: *Connection,
            now_nanos: i64,
            path: Path,
            out: []DatagramPathResult,
        ) endpoint_types.EndpointDatagramDrainResult {
            var result = endpoint_types.EndpointDatagramDrainResult{};
            const initial_secrets = protection.deriveInitialSecrets(
                connection.chosenVersion(),
                initial_destination_connection_id_of(record),
            ) catch {
                result.first_error = error.InvalidPacket;
                return result;
            };
            const send_keys = switch (connection.side) {
                .client => initial_secrets.client,
                .server => initial_secrets.server,
            };
            while (result.datagrams_written < out.len) {
                const datagram = connection.pollProtectedLongDatagram(
                    now_nanos,
                    destination_connection_id_of(record),
                    source_connection_id_of(record),
                    &[_]u8{},
                    .{ .initial = send_keys },
                ) catch |err| {
                    result.first_error = err;
                    return result;
                };
                const bytes = datagram orelse break;
                out[result.datagrams_written] = .{
                    .connection_id = connection_id,
                    .datagram = bytes,
                    .path = path,
                };
                result.datagrams_written += 1;
            }
            self.lifecycle.armRecoveryTimerFromConnection(connection_id, connection) catch |err| {
                result.first_error = err;
            };
            return result;
        }

        fn drainInitialDatagrams(
            self: *Self,
            connection_id: u64,
            record: *const Record,
            connection: *Connection,
            now_nanos: i64,
            out: []endpoint_types.EndpointPolledDatagramResult,
        ) endpoint_types.EndpointDatagramDrainResult {
            var result = endpoint_types.EndpointDatagramDrainResult{};
            const initial_secrets = protection.deriveInitialSecrets(
                connection.chosenVersion(),
                initial_destination_connection_id_of(record),
            ) catch {
                result.first_error = error.InvalidPacket;
                return result;
            };
            const send_keys = switch (connection.side) {
                .client => initial_secrets.client,
                .server => initial_secrets.server,
            };
            while (result.datagrams_written < out.len) {
                const datagram = connection.pollProtectedLongDatagram(
                    now_nanos,
                    destination_connection_id_of(record),
                    source_connection_id_of(record),
                    &[_]u8{},
                    .{ .initial = send_keys },
                ) catch |err| {
                    result.first_error = err;
                    return result;
                };
                const bytes = datagram orelse break;
                out[result.datagrams_written] = .{
                    .connection_id = connection_id,
                    .datagram = bytes,
                };
                result.datagrams_written += 1;
            }
            self.lifecycle.armRecoveryTimerFromConnection(connection_id, connection) catch |err| {
                result.first_error = err;
            };
            return result;
        }

        fn drainDatagramsWithRoutePath(
            self: *Self,
            connection_id: u64,
            connection: *Connection,
            now_nanos: i64,
            options: endpoint_types.EndpointPollInstalledKeyDatagramOptions,
            path: Path,
            out: []DatagramPathResult,
        ) endpoint_types.EndpointDatagramDrainResult {
            var result = endpoint_types.EndpointDatagramDrainResult{};
            while (result.datagrams_written < out.len) {
                const datagram = self.lifecycle.pollDatagram(
                    connection_id,
                    connection,
                    now_nanos,
                    options,
                ) catch |err| {
                    result.first_error = err;
                    return result;
                };
                out[result.datagrams_written] = if (datagram) |bytes| .{
                    .connection_id = connection_id,
                    .datagram = bytes,
                    .path = path,
                } else return result;
                result.datagrams_written += 1;
            }
            return result;
        }

        /// Route and process one protected installed-key datagram.
        pub fn feedDatagramWithInstalledKeys(
            self: *Self,
            allocator: std.mem.Allocator,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
        ) endpoint_types.EndpointProtectedDatagramError!PathTypes.EndpointFeedInstalledKeyDatagramResult {
            _ = allocator;
            return self.feedDatagramWithInstalledKeysOwned(
                path,
                now_nanos,
                datagram,
                options,
            );
        }

        fn feedDatagramWithInstalledKeysOwned(
            self: *Self,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
        ) endpoint_types.EndpointProtectedDatagramError!PathTypes.EndpointFeedInstalledKeyDatagramResult {
            const action = try self.lifecycle.feedDatagram(
                options.out,
                path,
                datagram,
                options.unpredictable_prefix,
                options.supported_versions,
            );
            const route = switch (action) {
                .routed => |value| value,
                .accept_initial => |initial| return .{ .accept_initial = initial },
                .version_negotiation => |response| return .{ .version_negotiation = response },
                .stateless_reset => |reset| return .{ .stateless_reset = reset },
                .dropped => return .dropped,
            };
            const record = self.records.get(route.connection_id) orelse return error.Internal;
            return self.lifecycle.feedDatagramWithInstalledKeys(
                route.connection_id,
                connection_of(record),
                path,
                now_nanos,
                datagram,
                options,
            );
        }

        /// Route one installed-key datagram and select the next endpoint-owned deadline using scratch storage.
        pub fn feedDatagramWithInstalledKeysAndSelectNextDeadlineWithScratch(
            self: *Self,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
        ) endpoint_types.EndpointProtectedDatagramError!PathTypes.EndpointFeedInstalledKeyDatagramNextDeadlineResult {
            _ = try self.records.nextDeadlineWithScratch(&self.lifecycle);
            return .{
                .feed = try self.feedDatagramWithInstalledKeysOwned(
                    path,
                    now_nanos,
                    datagram,
                    options,
                ),
                .next_deadline = try self.nextDeadlineWithScratch(),
            };
        }

        /// Route one installed-key datagram, sweep pending work, and select the next deadline using scratch storage.
        pub fn feedDatagramWithInstalledKeysAndProcessPendingWorkAndSelectNextDeadlineWithScratch(
            self: *Self,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
        ) endpoint_types.EndpointProtectedDatagramError!PathTypes.EndpointFeedPendingWorkNextDeadlineResult {
            _ = self.records.receive_view_scratch orelse return error.BufferTooSmall;
            _ = self.records.deadline_view_scratch orelse return error.BufferTooSmall;
            const feed = try self.feedDatagramWithInstalledKeysOwned(
                path,
                now_nanos,
                datagram,
                options,
            );
            const pending_deadline = try self.processPendingWorkAndSelectNextDeadlineWithScratch(now_nanos);
            return .{
                .feed = feed,
                .pending_work = pending_deadline.pending_work,
                .next_deadline = pending_deadline.next_deadline,
            };
        }

        /// Route one installed-key datagram, sweep pending work, and drain route-bound output using scratch storage.
        pub fn feedDatagramWithInstalledKeysAndProcessPendingWorkAndDrainDatagramsWithRoutePathWithScratch(
            self: *Self,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
            space: endpoint_types.EndpointInstalledKeyDatagramSpace,
            out: []DatagramPathResult,
        ) endpoint_types.EndpointProtectedDatagramError!FeedPendingWorkDatagramPathDrainResult {
            _ = self.records.receive_view_scratch orelse return error.BufferTooSmall;
            _ = self.records.deadline_view_scratch orelse return error.BufferTooSmall;
            _ = self.records.poll_view_scratch orelse return error.BufferTooSmall;
            const feed = try self.feedDatagramWithInstalledKeysOwned(
                path,
                now_nanos,
                datagram,
                options,
            );
            const pending_drain = try self.processPendingWorkAndDrainDatagramsWithRoutePathWithScratch(
                now_nanos,
                space,
                out,
            );
            return .{
                .feed = feed,
                .pending_work = pending_drain.pending_work,
                .drain = pending_drain.drain,
                .next_deadline = pending_drain.next_deadline,
            };
        }

        /// Route one installed-key datagram, sweep pending work, and poll one route-bound output using scratch storage.
        pub fn feedDatagramWithInstalledKeysAndProcessPendingWorkAndPollDatagramWithRoutePathWithScratch(
            self: *Self,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
            space: endpoint_types.EndpointInstalledKeyDatagramSpace,
        ) endpoint_types.EndpointProtectedDatagramError!FeedPendingWorkDatagramPathPollResult {
            _ = self.records.receive_view_scratch orelse return error.BufferTooSmall;
            _ = self.records.deadline_view_scratch orelse return error.BufferTooSmall;
            _ = self.records.poll_view_scratch orelse return error.BufferTooSmall;
            const feed = try self.feedDatagramWithInstalledKeysOwned(
                path,
                now_nanos,
                datagram,
                options,
            );
            self.preflightDueRecoveryRoutes(now_nanos) catch |err| {
                const route_error = classifyRoutePreflightError(err) orelse return @errorCast(err);
                return .{
                    .feed = feed,
                    .pending_work = .{},
                    .pending_route_error = route_error,
                    .next_deadline = try self.nextDeadlineWithScratch(),
                };
            };
            const pending_work = try self.records.processPendingWorkWithScratch(
                &self.lifecycle,
                now_nanos,
            );
            const datagram_out = if (pending_work.recovery_serviced_count == 0)
                null
            else
                try self.pollDatagramWithRoutePathWithScratch(
                    now_nanos,
                    space,
                );
            return .{
                .feed = feed,
                .pending_work = pending_work,
                .datagram = datagram_out,
                .next_deadline = try self.nextDeadlineWithScratch(),
            };
        }

        /// Route one installed-key datagram, apply validated path-update
        /// handling on the selected record, and poll one 1-RTT output datagram.
        ///
        /// This keeps the record lookup, path-validation output tuple, and
        /// protected output packet together at the endpoint-owner layer. The
        /// caller still owns UDP I/O and supplies the route-classification
        /// scratch buffer and endpoint entropy through `options`.
        pub fn feedDatagramWithInstalledKeysAndUpdatePathOrCloseAndPollDatagram(
            self: *Self,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
        ) endpoint_types.EndpointProtectedDatagramError!PathTypes.EndpointFeedPathUpdateDatagramPollResult {
            const action = try self.lifecycle.feedDatagram(
                options.out,
                path,
                datagram,
                options.unpredictable_prefix,
                options.supported_versions,
            );
            const route = switch (action) {
                .routed => |value| value,
                .accept_initial => |initial| return .{ .feed = .{ .feed = .{ .accept_initial = initial } } },
                .version_negotiation => |response| return .{ .feed = .{ .feed = .{ .version_negotiation = response } } },
                .stateless_reset => |reset| return .{ .feed = .{ .feed = .{ .stateless_reset = reset } } },
                .dropped => return .{ .feed = .{ .feed = .dropped } },
            };
            const record = self.records.get(route.connection_id) orelse return error.Internal;
            return self.lifecycle.feedDatagramWithInstalledKeysAndUpdatePathOrCloseAndPollDatagram(
                route.connection_id,
                connection_of(record),
                path,
                now_nanos,
                datagram,
                options,
                .{
                    .space = .application,
                    .destination_connection_id = destination_connection_id_of(record),
                },
            );
        }

        /// Route, process, and poll one installed-key datagram with output path.
        ///
        /// Successful receive paths return the feed result plus any immediate
        /// output datagram paired with the selected UDP tuple. If authenticated
        /// frame processing reports `InvalidPacket` after selecting a record,
        /// this helper returns that error as data and polls a queued
        /// CONNECTION_CLOSE on the committed route. Pre-route classification
        /// errors and non-frame processing errors still return through the
        /// function error set.
        pub fn feedInstalledKeyDatagramWithRoutePath(
            self: *Self,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
        ) endpoint_types.EndpointProtectedDatagramError!InstalledKeyDatagramRoutePollResult {
            const action = try self.lifecycle.feedDatagram(
                options.out,
                path,
                datagram,
                options.unpredictable_prefix,
                options.supported_versions,
            );
            const route = switch (action) {
                .routed => |value| value,
                .accept_initial => |initial| return .{
                    .feed = .{ .feed = .{ .accept_initial = initial } },
                    .next_deadline = try self.nextDeadline(self.records.allocator),
                },
                .version_negotiation => |response| return .{
                    .feed = .{ .feed = .{ .version_negotiation = response } },
                    .next_deadline = try self.nextDeadline(self.records.allocator),
                },
                .stateless_reset => |reset| return .{
                    .feed = .{ .feed = .{ .stateless_reset = reset } },
                    .next_deadline = try self.nextDeadline(self.records.allocator),
                },
                .dropped => return .{
                    .feed = .{ .feed = .dropped },
                    .next_deadline = try self.nextDeadline(self.records.allocator),
                },
            };
            const record = self.records.get(route.connection_id) orelse return error.Internal;
            return self.processRoutedInstalledKeyDatagramWithRoutePath(
                route,
                record,
                path,
                now_nanos,
                datagram,
                options,
            );
        }

        /// Route, process, and poll one installed-key datagram using deadline scratch.
        ///
        /// This preserves `feedInstalledKeyDatagramWithRoutePath` semantics for
        /// socket-loop callers that preallocate endpoint deadline views.
        pub fn feedInstalledKeyDatagramWithRoutePathWithScratch(
            self: *Self,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
        ) endpoint_types.EndpointProtectedDatagramError!InstalledKeyDatagramRoutePollResult {
            _ = try self.records.nextDeadlineWithScratch(&self.lifecycle);
            const action = try self.lifecycle.feedDatagram(
                options.out,
                path,
                datagram,
                options.unpredictable_prefix,
                options.supported_versions,
            );
            const route = switch (action) {
                .routed => |value| value,
                .accept_initial => |initial| return .{
                    .feed = .{ .feed = .{ .accept_initial = initial } },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                },
                .version_negotiation => |response| return .{
                    .feed = .{ .feed = .{ .version_negotiation = response } },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                },
                .stateless_reset => |reset| return .{
                    .feed = .{ .feed = .{ .stateless_reset = reset } },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                },
                .dropped => return .{
                    .feed = .{ .feed = .dropped },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                },
            };
            const record = self.records.get(route.connection_id) orelse return error.Internal;
            return self.processRoutedInstalledKeyDatagramWithRoutePathWithScratch(
                route,
                record,
                path,
                now_nanos,
                datagram,
                options,
            );
        }

        fn processRoutedInstalledKeyDatagramWithRoutePath(
            self: *Self,
            route: endpoint.RouteResult,
            record: *Record,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
        ) endpoint_types.EndpointProtectedDatagramError!InstalledKeyDatagramRoutePollResult {
            const connection = connection_of(record);
            const destination_connection_id = destination_connection_id_of(record);
            const route_path = try self.lifecycle.currentRoutePath(route.destination_connection_id.asSlice());
            if (datagram.len != 0 and quic_packet.parseHeaderForm(datagram[0]) == .short) {
                if (connection.processStatelessResetDatagram(now_nanos, datagram)) |sequence_number| {
                    try self.lifecycle.armRecoveryTimerFromConnection(route.connection_id, connection);
                    return .{
                        .feed = .{ .feed = .dropped },
                        .stateless_reset_sequence_number = sequence_number,
                        .next_deadline = try self.nextDeadline(self.records.allocator),
                    };
                }
            }
            const feed = self.lifecycle.feedDatagramWithInstalledKeysAndUpdatePathOrClose(
                route.connection_id,
                connection,
                path,
                now_nanos,
                datagram,
                options,
            ) catch |err| {
                if (err != error.InvalidPacket) return err;
                const close_datagram = if (connection.connectionState() == .closing) try self.lifecycle.pollDatagram(
                    route.connection_id,
                    connection,
                    now_nanos,
                    .{
                        .space = .application,
                        .destination_connection_id = destination_connection_id,
                    },
                ) else null;
                return .{
                    .feed_error = err,
                    .datagram = if (close_datagram) |value| .{
                        .connection_id = route.connection_id,
                        .datagram = value,
                        .path = route_path,
                    } else null,
                    .next_deadline = try self.nextDeadline(self.records.allocator),
                };
            };
            switch (feed.feed) {
                .routed => {},
                else => return .{
                    .feed = feed,
                    .next_deadline = try self.nextDeadline(self.records.allocator),
                },
            }
            const output_path = feed.selected_output_path orelse route_path;
            const polled = try self.lifecycle.pollDatagram(
                route.connection_id,
                connection,
                now_nanos,
                .{
                    .space = .application,
                    .destination_connection_id = destination_connection_id,
                },
            );
            return .{
                .feed = feed,
                .datagram = if (polled) |protected_datagram| .{
                    .connection_id = route.connection_id,
                    .datagram = protected_datagram,
                    .path = output_path,
                } else null,
                .next_deadline = try self.nextDeadline(self.records.allocator),
            };
        }

        fn processRoutedInstalledKeyDatagramWithRoutePathWithScratch(
            self: *Self,
            route: endpoint.RouteResult,
            record: *Record,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
        ) endpoint_types.EndpointProtectedDatagramError!InstalledKeyDatagramRoutePollResult {
            const connection = connection_of(record);
            const destination_connection_id = destination_connection_id_of(record);
            const route_path = try self.lifecycle.currentRoutePath(route.destination_connection_id.asSlice());
            if (datagram.len != 0 and quic_packet.parseHeaderForm(datagram[0]) == .short) {
                if (connection.processStatelessResetDatagram(now_nanos, datagram)) |sequence_number| {
                    try self.lifecycle.armRecoveryTimerFromConnection(route.connection_id, connection);
                    return .{
                        .feed = .{ .feed = .dropped },
                        .stateless_reset_sequence_number = sequence_number,
                        .next_deadline = try self.nextDeadlineWithScratch(),
                    };
                }
            }
            const feed = self.lifecycle.feedDatagramWithInstalledKeysAndUpdatePathOrClose(
                route.connection_id,
                connection,
                path,
                now_nanos,
                datagram,
                options,
            ) catch |err| {
                if (err != error.InvalidPacket) return err;
                const close_datagram = if (connection.connectionState() == .closing) try self.lifecycle.pollDatagram(
                    route.connection_id,
                    connection,
                    now_nanos,
                    .{
                        .space = .application,
                        .destination_connection_id = destination_connection_id,
                    },
                ) else null;
                return .{
                    .feed_error = err,
                    .datagram = if (close_datagram) |value| .{
                        .connection_id = route.connection_id,
                        .datagram = value,
                        .path = route_path,
                    } else null,
                    .next_deadline = try self.nextDeadlineWithScratch(),
                };
            };
            switch (feed.feed) {
                .routed => {},
                else => return .{
                    .feed = feed,
                    .next_deadline = try self.nextDeadlineWithScratch(),
                },
            }
            const output_path = feed.selected_output_path orelse route_path;
            const polled = try self.lifecycle.pollDatagram(
                route.connection_id,
                connection,
                now_nanos,
                .{
                    .space = .application,
                    .destination_connection_id = destination_connection_id,
                },
            );
            return .{
                .feed = feed,
                .datagram = if (polled) |protected_datagram| .{
                    .connection_id = route.connection_id,
                    .datagram = protected_datagram,
                    .path = output_path,
                } else null,
                .next_deadline = try self.nextDeadlineWithScratch(),
            };
        }

        /// Route, process, and drain one installed-key datagram using deadline scratch.
        ///
        /// This is the bounded-output companion to
        /// `feedInstalledKeyDatagramWithRoutePathWithScratch()`.
        pub fn feedInstalledKeyDatagramAndDrainWithRoutePathWithScratch(
            self: *Self,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
            out: []DatagramPathResult,
        ) (endpoint_types.EndpointProtectedDatagramError || endpoint.RouteError)!InstalledKeyDatagramRouteDrainResult {
            _ = try self.records.nextDeadlineWithScratch(&self.lifecycle);
            const action = try self.lifecycle.feedDatagram(
                options.out,
                path,
                datagram,
                options.unpredictable_prefix,
                options.supported_versions,
            );
            const route = switch (action) {
                .routed => |value| value,
                .accept_initial => |initial| return .{
                    .feed = .{ .feed = .{ .accept_initial = initial } },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                },
                .version_negotiation => |response| return .{
                    .feed = .{ .feed = .{ .version_negotiation = response } },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                },
                .stateless_reset => |reset| return .{
                    .feed = .{ .feed = .{ .stateless_reset = reset } },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                },
                .dropped => return .{
                    .feed = .{ .feed = .dropped },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                },
            };
            const record = self.records.get(route.connection_id) orelse return error.Internal;
            return self.processRoutedInstalledKeyDatagramAndDrainWithRoutePathWithScratch(
                route,
                record,
                path,
                now_nanos,
                datagram,
                options,
                out,
            );
        }

        fn processRoutedInstalledKeyDatagramAndDrainWithRoutePath(
            self: *Self,
            route: endpoint.RouteResult,
            record: *Record,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
            out: []DatagramPathResult,
        ) (endpoint_types.EndpointProtectedDatagramError || endpoint.RouteError)!InstalledKeyDatagramRouteDrainResult {
            const connection = connection_of(record);
            const destination_connection_id = destination_connection_id_of(record);
            const route_path = try self.lifecycle.currentRoutePath(route.destination_connection_id.asSlice());
            if (datagram.len != 0 and quic_packet.parseHeaderForm(datagram[0]) == .short) {
                if (connection.processStatelessResetDatagram(now_nanos, datagram)) |sequence_number| {
                    try self.lifecycle.armRecoveryTimerFromConnection(route.connection_id, connection);
                    return .{
                        .feed = .{ .feed = .dropped },
                        .stateless_reset_sequence_number = sequence_number,
                        .next_deadline = try self.nextDeadline(self.records.allocator),
                    };
                }
            }
            const feed = self.lifecycle.feedDatagramWithInstalledKeysAndUpdatePathOrClose(
                route.connection_id,
                connection,
                path,
                now_nanos,
                datagram,
                options,
            ) catch |err| {
                if (err != error.InvalidPacket) return err;
                var result = InstalledKeyDatagramRouteDrainResult{
                    .feed_error = err,
                    .next_deadline = try self.nextDeadline(self.records.allocator),
                };
                if (connection.connectionState() == .closing) {
                    result.drain = if (out.len == 0)
                        .{ .first_error = error.BufferTooSmall }
                    else
                        self.drainDatagramsWithRoutePath(
                            route.connection_id,
                            connection,
                            now_nanos,
                            .{
                                .space = .application,
                                .destination_connection_id = destination_connection_id,
                            },
                            route_path,
                            out,
                        );
                    result.next_deadline = try self.nextDeadline(self.records.allocator);
                }
                return result;
            };
            switch (feed.feed) {
                .routed => {},
                else => return .{
                    .feed = feed,
                    .next_deadline = try self.nextDeadline(self.records.allocator),
                },
            }
            const output_path = feed.selected_output_path orelse route_path;
            if (out.len == 0 and connection.pendingAckLargest(.application) != null) {
                return .{
                    .feed = feed,
                    .drain = .{ .first_error = error.BufferTooSmall },
                    .next_deadline = try self.nextDeadline(self.records.allocator),
                };
            }
            const drain = self.drainDatagramsWithRoutePath(
                route.connection_id,
                connection,
                now_nanos,
                .{
                    .space = .application,
                    .destination_connection_id = destination_connection_id,
                },
                output_path,
                out,
            );
            return .{
                .feed = feed,
                .drain = drain,
                .next_deadline = try self.nextDeadline(self.records.allocator),
            };
        }

        fn processRoutedInstalledKeyDatagramAndDrainWithRoutePathWithScratch(
            self: *Self,
            route: endpoint.RouteResult,
            record: *Record,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
            out: []DatagramPathResult,
        ) (endpoint_types.EndpointProtectedDatagramError || endpoint.RouteError)!InstalledKeyDatagramRouteDrainResult {
            const connection = connection_of(record);
            const destination_connection_id = destination_connection_id_of(record);
            const route_path = try self.lifecycle.currentRoutePath(route.destination_connection_id.asSlice());
            if (datagram.len != 0 and quic_packet.parseHeaderForm(datagram[0]) == .short) {
                if (connection.processStatelessResetDatagram(now_nanos, datagram)) |sequence_number| {
                    try self.lifecycle.armRecoveryTimerFromConnection(route.connection_id, connection);
                    return .{
                        .feed = .{ .feed = .dropped },
                        .stateless_reset_sequence_number = sequence_number,
                        .next_deadline = try self.nextDeadlineWithScratch(),
                    };
                }
            }
            const feed = self.lifecycle.feedDatagramWithInstalledKeysAndUpdatePathOrClose(
                route.connection_id,
                connection,
                path,
                now_nanos,
                datagram,
                options,
            ) catch |err| {
                if (err != error.InvalidPacket) return err;
                var result = InstalledKeyDatagramRouteDrainResult{
                    .feed_error = err,
                    .next_deadline = try self.nextDeadlineWithScratch(),
                };
                if (connection.connectionState() == .closing) {
                    result.drain = if (out.len == 0)
                        .{ .first_error = error.BufferTooSmall }
                    else
                        self.drainDatagramsWithRoutePath(
                            route.connection_id,
                            connection,
                            now_nanos,
                            .{
                                .space = .application,
                                .destination_connection_id = destination_connection_id,
                            },
                            route_path,
                            out,
                        );
                    result.next_deadline = try self.nextDeadlineWithScratch();
                }
                return result;
            };
            switch (feed.feed) {
                .routed => {},
                else => return .{
                    .feed = feed,
                    .next_deadline = try self.nextDeadlineWithScratch(),
                },
            }
            const output_path = feed.selected_output_path orelse route_path;
            if (out.len == 0 and connection.pendingAckLargest(.application) != null) {
                return .{
                    .feed = feed,
                    .drain = .{ .first_error = error.BufferTooSmall },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                };
            }
            const drain = self.drainDatagramsWithRoutePath(
                route.connection_id,
                connection,
                now_nanos,
                .{
                    .space = .application,
                    .destination_connection_id = destination_connection_id,
                },
                output_path,
                out,
            );
            return .{
                .feed = feed,
                .drain = drain,
                .next_deadline = try self.nextDeadlineWithScratch(),
            };
        }

        /// Poll one installed-key 1-RTT datagram from an endpoint-owned record.
        ///
        /// The caller supplies only the selected handle and peer destination CID;
        /// routing, recovery-timer refresh, and the embedded connection remain
        /// owned by this endpoint's record table.
        pub fn pollOneRttDatagram(
            self: *Self,
            connection_id: u64,
            now_nanos: i64,
        ) (root.Error || error{UnknownConnectionId})!?[]u8 {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            return self.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                connection_id,
                connection_of(record),
                now_nanos,
                destination_connection_id_of(record),
            );
        }

        /// Poll one installed-key 1-RTT datagram with its committed UDP route.
        ///
        /// This is the socket-facing variant for endpoint-owned servers after
        /// route migration has been validated and committed. The path is read
        /// from the same route table used for inbound classification.
        pub fn pollOneRttDatagramWithRoutePath(
            self: *Self,
            connection_id: u64,
            now_nanos: i64,
        ) (root.Error || endpoint.RouteError)!?OneRttDatagramPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.lifecycle.currentRoutePath(source_connection_id_of(record));
            const datagram = (try self.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                connection_id,
                connection_of(record),
                now_nanos,
                destination_connection_id_of(record),
            )) orelse return null;
            return .{
                .datagram = datagram,
                .path = path,
            };
        }

        /// Poll the first installed-key datagram across endpoint-owned records.
        pub fn pollDatagramWithRoutePath(
            self: *Self,
            allocator: std.mem.Allocator,
            now_nanos: i64,
            space: endpoint_types.EndpointInstalledKeyDatagramSpace,
        ) (root.Error || endpoint.RouteError)!?DatagramPathResult {
            _ = try self.records.removeClosedRecords(&self.lifecycle);
            if (self.records.poll_view_scratch) |views| {
                return self.pollDatagramAcrossRecordViewsWithRoutePath(
                    try self.records.fillPollViews(views, destination_connection_id_of, source_connection_id_of),
                    now_nanos,
                    space,
                );
            }
            const views = try self.records.pollViews(
                allocator,
                destination_connection_id_of,
                source_connection_id_of,
            );
            defer allocator.free(views);
            return self.pollDatagramAcrossRecordViewsWithRoutePath(
                views,
                now_nanos,
                space,
            );
        }

        /// Poll the first installed-key datagram using registry-owned poll scratch.
        pub fn pollDatagramWithRoutePathWithScratch(
            self: *Self,
            now_nanos: i64,
            space: endpoint_types.EndpointInstalledKeyDatagramSpace,
        ) (root.Error || endpoint.RouteError)!?DatagramPathResult {
            _ = try self.records.removeClosedRecords(&self.lifecycle);
            const views = self.records.poll_view_scratch orelse return error.BufferTooSmall;
            return self.pollDatagramAcrossRecordViewsWithRoutePath(
                try self.records.fillPollViews(views, destination_connection_id_of, source_connection_id_of),
                now_nanos,
                space,
            );
        }

        /// Drain installed-key datagrams across active endpoint-owned records.
        ///
        /// Each initialized output slot owns its datagram. If `first_error` or
        /// `first_route_error` is set, the caller still owns the first
        /// `datagrams_written` entries.
        pub fn drainDatagramsAcrossRecordsWithRoutePath(
            self: *Self,
            allocator: std.mem.Allocator,
            now_nanos: i64,
            space: endpoint_types.EndpointInstalledKeyDatagramSpace,
            out: []DatagramPathResult,
        ) DatagramPathDrainResult {
            var result = DatagramPathDrainResult{};
            while (result.datagrams_written < out.len) {
                const datagram = self.pollDatagramWithRoutePath(
                    allocator,
                    now_nanos,
                    space,
                ) catch |err| {
                    switch (err) {
                        error.InvalidConnectionIdLength,
                        error.InvalidConnectionIdSequence,
                        error.InvalidDatagram,
                        error.InvalidVersionList,
                        error.InvalidResetSize,
                        error.DuplicateConnectionId,
                        error.RouteCapacityReached,
                        error.StatelessResetTokenCapacityReached,
                        error.UnknownConnectionId,
                        error.AmbiguousConnectionId,
                        error.ActiveMigrationDisabled,
                        error.PathMismatch,
                        => result.first_route_error = @errorCast(err),
                        else => result.first_error = @errorCast(err),
                    }
                    return result;
                };
                out[result.datagrams_written] = datagram orelse return result;
                result.datagrams_written += 1;
            }
            return result;
        }

        /// Drain installed-key datagrams using registry-owned poll scratch.
        pub fn drainDatagramsAcrossRecordsWithRoutePathWithScratch(
            self: *Self,
            now_nanos: i64,
            space: endpoint_types.EndpointInstalledKeyDatagramSpace,
            out: []DatagramPathResult,
        ) DatagramPathDrainResult {
            var result = DatagramPathDrainResult{};
            while (result.datagrams_written < out.len) {
                const datagram = self.pollDatagramWithRoutePathWithScratch(
                    now_nanos,
                    space,
                ) catch |err| {
                    switch (err) {
                        error.InvalidConnectionIdLength,
                        error.InvalidConnectionIdSequence,
                        error.InvalidDatagram,
                        error.InvalidVersionList,
                        error.InvalidResetSize,
                        error.DuplicateConnectionId,
                        error.RouteCapacityReached,
                        error.StatelessResetTokenCapacityReached,
                        error.UnknownConnectionId,
                        error.AmbiguousConnectionId,
                        error.ActiveMigrationDisabled,
                        error.PathMismatch,
                        => result.first_route_error = @errorCast(err),
                        else => result.first_error = @errorCast(err),
                    }
                    return result;
                };
                out[result.datagrams_written] = datagram orelse return result;
                result.datagrams_written += 1;
            }
            return result;
        }

        fn pollDatagramAcrossRecordViewsWithRoutePath(
            self: *Self,
            views: []const root.EndpointConnectionPollView,
            now_nanos: i64,
            space: endpoint_types.EndpointInstalledKeyDatagramSpace,
        ) (root.Error || endpoint.RouteError)!?DatagramPathResult {
            if (views.len == 0) {
                self.records.next_poll_index = 0;
                return null;
            }
            const start = self.records.next_poll_index % views.len;
            var offset: usize = 0;
            while (offset < views.len) : (offset += 1) {
                const index = (start + offset) % views.len;
                const view = views[index];
                if (view.connection.connectionState() == .closed) {
                    _ = self.records.retire(&self.lifecycle, view.connection_id) catch return error.Internal;
                    continue;
                }
                const path = try self.lifecycle.currentRoutePath(view.source_connection_id);
                const datagram = self.lifecycle.pollDatagram(
                    view.connection_id,
                    view.connection,
                    now_nanos,
                    .{
                        .space = space,
                        .destination_connection_id = view.destination_connection_id,
                        .source_connection_id = view.source_connection_id,
                    },
                ) catch |err| switch (err) {
                    error.ConnectionClosed => {
                        if (view.connection.connectionState() == .closed) {
                            _ = self.records.retire(&self.lifecycle, view.connection_id) catch return error.Internal;
                        }
                        continue;
                    },
                    else => return err,
                };
                if (datagram) |bytes| {
                    self.records.next_poll_index = (index + 1) % views.len;
                    return .{
                        .connection_id = view.connection_id,
                        .datagram = bytes,
                        .path = path,
                    };
                }
            }
            self.records.next_poll_index = start;
            return null;
        }

        /// Read received bytes from one endpoint-owned server stream.
        pub fn recvStream(
            self: *Self,
            connection_id: u64,
            stream_id: u64,
            out: []u8,
        ) (root.Error || error{UnknownConnectionId})!?usize {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            return connection_of(record).recvOnStream(stream_id, out);
        }

        /// Return whether one endpoint-owned server stream has received FIN.
        pub fn streamFinished(
            self: *const Self,
            connection_id: u64,
            stream_id: u64,
        ) (root.Error || error{UnknownConnectionId})!bool {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            return connection_of(record).recvStreamFinished(stream_id);
        }

        /// Open a server-initiated bidirectional stream on one owned record.
        pub fn openStream(
            self: *Self,
            connection_id: u64,
        ) (root.Error || error{UnknownConnectionId})!u64 {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            return connection_of(record).openStream();
        }

        /// Open a server-initiated unidirectional stream on one owned record.
        pub fn openUniStream(
            self: *Self,
            connection_id: u64,
        ) (root.Error || error{UnknownConnectionId})!u64 {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            return connection_of(record).openUniStream();
        }

        /// Queue FIN-terminated or open stream bytes on one owned record.
        pub fn sendStream(
            self: *Self,
            connection_id: u64,
            stream_id: u64,
            data: []const u8,
            fin: bool,
        ) (root.Error || error{UnknownConnectionId})!void {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            try connection_of(record).sendOnStream(stream_id, data, fin);
        }

        /// Queue stream bytes and poll one datagram with the committed route.
        ///
        /// The route is resolved before mutating stream state, so a missing
        /// endpoint route does not leave application data queued on the record.
        pub fn sendStreamWithRoutePath(
            self: *Self,
            connection_id: u64,
            stream_id: u64,
            data: []const u8,
            fin: bool,
            now_nanos: i64,
        ) (root.Error || endpoint.RouteError)!?OneRttDatagramPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            try connection_of(record).sendOnStream(stream_id, data, fin);
            const datagram = (try self.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                connection_id,
                connection_of(record),
                now_nanos,
                destination_connection_id_of(record),
            )) orelse return null;
            return .{
                .datagram = datagram,
                .path = path,
            };
        }

        /// Queue stream bytes and drain protected datagrams with the committed route.
        ///
        /// The route and output capacity are checked before mutating stream state.
        pub fn sendStreamWithRoutePathAndDrainDatagrams(
            self: *Self,
            allocator: std.mem.Allocator,
            connection_id: u64,
            stream_id: u64,
            data: []const u8,
            fin: bool,
            now_nanos: i64,
            out: []DatagramPathResult,
        ) (root.Error || endpoint.RouteError)!OneRttControlDatagramPathDrainResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            if (out.len == 0) return error.BufferTooSmall;
            const connection = connection_of(record);
            try connection.sendOnStream(stream_id, data, fin);
            const drain = self.drainDatagramsWithRoutePath(
                connection_id,
                connection,
                now_nanos,
                .{
                    .space = .application,
                    .destination_connection_id = destination_connection_id_of(record),
                },
                path,
                out,
            );
            return .{
                .drain = .{
                    .datagrams_written = drain.datagrams_written,
                    .first_error = drain.first_error,
                },
                .next_deadline = try self.nextDeadline(allocator),
            };
        }

        /// Queue stream bytes, drain protected datagrams, and select the next
        /// deadline using registry scratch storage.
        ///
        /// The route, output capacity, and scratch deadline storage are checked
        /// before mutating stream state.
        pub fn sendStreamWithRoutePathAndDrainDatagramsWithScratch(
            self: *Self,
            connection_id: u64,
            stream_id: u64,
            data: []const u8,
            fin: bool,
            now_nanos: i64,
            out: []DatagramPathResult,
        ) (root.Error || endpoint.RouteError)!OneRttControlDatagramPathDrainResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            if (out.len == 0) return error.BufferTooSmall;
            _ = self.records.deadline_view_scratch orelse return error.BufferTooSmall;
            const connection = connection_of(record);
            try connection.sendOnStream(stream_id, data, fin);
            const drain = self.drainDatagramsWithRoutePath(
                connection_id,
                connection,
                now_nanos,
                .{
                    .space = .application,
                    .destination_connection_id = destination_connection_id_of(record),
                },
                path,
                out,
            );
            return .{
                .drain = .{
                    .datagrams_written = drain.datagrams_written,
                    .first_error = drain.first_error,
                },
                .next_deadline = try self.nextDeadlineWithScratch(),
            };
        }

        /// Abort a locally writable stream and queue a RESET_STREAM frame.
        pub fn resetStream(
            self: *Self,
            connection_id: u64,
            stream_id: u64,
            application_error_code: u64,
        ) (root.Error || error{UnknownConnectionId})!void {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            try connection_of(record).resetStream(stream_id, application_error_code);
        }

        /// Queue RESET_STREAM and poll one datagram with the committed route.
        pub fn resetStreamWithRoutePath(
            self: *Self,
            connection_id: u64,
            stream_id: u64,
            application_error_code: u64,
            now_nanos: i64,
        ) (root.Error || endpoint.RouteError)!?OneRttDatagramPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            try connection_of(record).resetStream(stream_id, application_error_code);
            const datagram = (try self.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                connection_id,
                connection_of(record),
                now_nanos,
                destination_connection_id_of(record),
            )) orelse return null;
            return .{
                .datagram = datagram,
                .path = path,
            };
        }

        /// Queue RESET_STREAM and drain protected datagrams with the committed route.
        ///
        /// The route and output capacity are checked before mutating stream state.
        pub fn resetStreamWithRoutePathAndDrainDatagrams(
            self: *Self,
            allocator: std.mem.Allocator,
            connection_id: u64,
            stream_id: u64,
            application_error_code: u64,
            now_nanos: i64,
            out: []DatagramPathResult,
        ) (root.Error || endpoint.RouteError)!OneRttControlDatagramPathDrainResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            if (out.len == 0) return error.BufferTooSmall;
            const connection = connection_of(record);
            try connection.resetStream(stream_id, application_error_code);
            const drain = self.drainDatagramsWithRoutePath(
                connection_id,
                connection,
                now_nanos,
                .{
                    .space = .application,
                    .destination_connection_id = destination_connection_id_of(record),
                },
                path,
                out,
            );
            return .{
                .drain = .{
                    .datagrams_written = drain.datagrams_written,
                    .first_error = drain.first_error,
                },
                .next_deadline = try self.nextDeadline(allocator),
            };
        }

        /// Queue RESET_STREAM, drain protected datagrams, and select the next
        /// deadline using registry scratch storage.
        ///
        /// The route, output capacity, and scratch deadline storage are checked
        /// before mutating stream-control state.
        pub fn resetStreamWithRoutePathAndDrainDatagramsWithScratch(
            self: *Self,
            connection_id: u64,
            stream_id: u64,
            application_error_code: u64,
            now_nanos: i64,
            out: []DatagramPathResult,
        ) (root.Error || endpoint.RouteError)!OneRttControlDatagramPathDrainResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            if (out.len == 0) return error.BufferTooSmall;
            _ = self.records.deadline_view_scratch orelse return error.BufferTooSmall;
            const connection = connection_of(record);
            try connection.resetStream(stream_id, application_error_code);
            const drain = self.drainDatagramsWithRoutePath(
                connection_id,
                connection,
                now_nanos,
                .{
                    .space = .application,
                    .destination_connection_id = destination_connection_id_of(record),
                },
                path,
                out,
            );
            return .{
                .drain = .{
                    .datagrams_written = drain.datagrams_written,
                    .first_error = drain.first_error,
                },
                .next_deadline = try self.nextDeadlineWithScratch(),
            };
        }

        /// Ask the peer to stop sending on a receive-capable stream.
        pub fn stopSending(
            self: *Self,
            connection_id: u64,
            stream_id: u64,
            application_error_code: u64,
        ) (root.Error || error{UnknownConnectionId})!void {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            try connection_of(record).stopSending(stream_id, application_error_code);
        }

        /// Queue STOP_SENDING and poll one datagram with the committed route.
        pub fn stopSendingWithRoutePath(
            self: *Self,
            connection_id: u64,
            stream_id: u64,
            application_error_code: u64,
            now_nanos: i64,
        ) (root.Error || endpoint.RouteError)!?OneRttDatagramPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            try connection_of(record).stopSending(stream_id, application_error_code);
            const datagram = (try self.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                connection_id,
                connection_of(record),
                now_nanos,
                destination_connection_id_of(record),
            )) orelse return null;
            return .{
                .datagram = datagram,
                .path = path,
            };
        }

        /// Queue STOP_SENDING and drain protected datagrams with the committed route.
        ///
        /// The route and output capacity are checked before mutating stream state.
        pub fn stopSendingWithRoutePathAndDrainDatagrams(
            self: *Self,
            allocator: std.mem.Allocator,
            connection_id: u64,
            stream_id: u64,
            application_error_code: u64,
            now_nanos: i64,
            out: []DatagramPathResult,
        ) (root.Error || endpoint.RouteError)!OneRttControlDatagramPathDrainResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            if (out.len == 0) return error.BufferTooSmall;
            const connection = connection_of(record);
            try connection.stopSending(stream_id, application_error_code);
            const drain = self.drainDatagramsWithRoutePath(
                connection_id,
                connection,
                now_nanos,
                .{
                    .space = .application,
                    .destination_connection_id = destination_connection_id_of(record),
                },
                path,
                out,
            );
            return .{
                .drain = .{
                    .datagrams_written = drain.datagrams_written,
                    .first_error = drain.first_error,
                },
                .next_deadline = try self.nextDeadline(allocator),
            };
        }

        /// Queue STOP_SENDING, drain protected datagrams, and select the next
        /// deadline using registry scratch storage.
        ///
        /// The route, output capacity, and scratch deadline storage are checked
        /// before mutating stream-control state.
        pub fn stopSendingWithRoutePathAndDrainDatagramsWithScratch(
            self: *Self,
            connection_id: u64,
            stream_id: u64,
            application_error_code: u64,
            now_nanos: i64,
            out: []DatagramPathResult,
        ) (root.Error || endpoint.RouteError)!OneRttControlDatagramPathDrainResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            if (out.len == 0) return error.BufferTooSmall;
            _ = self.records.deadline_view_scratch orelse return error.BufferTooSmall;
            const connection = connection_of(record);
            try connection.stopSending(stream_id, application_error_code);
            const drain = self.drainDatagramsWithRoutePath(
                connection_id,
                connection,
                now_nanos,
                .{
                    .space = .application,
                    .destination_connection_id = destination_connection_id_of(record),
                },
                path,
                out,
            );
            return .{
                .drain = .{
                    .datagrams_written = drain.datagrams_written,
                    .first_error = drain.first_error,
                },
                .next_deadline = try self.nextDeadlineWithScratch(),
            };
        }

        /// Queue a transport CONNECTION_CLOSE and return it with the route.
        pub fn closeWithRoutePath(
            self: *Self,
            connection_id: u64,
            error_code: u64,
            frame_type: u64,
            reason_phrase: []const u8,
            now_nanos: i64,
        ) (root.Error || endpoint.RouteError)!?OneRttDatagramPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            try connection_of(record).closeConnection(error_code, frame_type, reason_phrase);
            const datagram = (try self.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                connection_id,
                connection_of(record),
                now_nanos,
                destination_connection_id_of(record),
            )) orelse return null;
            return .{
                .datagram = datagram,
                .path = path,
            };
        }

        /// Queue an APPLICATION_CLOSE and return it with the route.
        pub fn closeApplicationWithRoutePath(
            self: *Self,
            connection_id: u64,
            error_code: u64,
            reason_phrase: []const u8,
            now_nanos: i64,
        ) (root.Error || endpoint.RouteError)!?OneRttDatagramPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            try connection_of(record).closeApplication(error_code, reason_phrase);
            const datagram = (try self.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                connection_id,
                connection_of(record),
                now_nanos,
                destination_connection_id_of(record),
            )) orelse return null;
            return .{
                .datagram = datagram,
                .path = path,
            };
        }

        /// Queue a transport CONNECTION_CLOSE and drain route-bound output.
        pub fn closeWithRoutePathAndDrainDatagrams(
            self: *Self,
            allocator: std.mem.Allocator,
            connection_id: u64,
            error_code: u64,
            frame_type: u64,
            reason_phrase: []const u8,
            now_nanos: i64,
            out: []DatagramPathResult,
        ) (root.Error || endpoint.RouteError)!CloseDatagramPathDrainResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            if (out.len == 0) return error.BufferTooSmall;
            const connection = connection_of(record);
            try connection.closeConnection(error_code, frame_type, reason_phrase);
            const drain = self.drainDatagramsWithRoutePath(
                connection_id,
                connection,
                now_nanos,
                .{
                    .space = .application,
                    .destination_connection_id = destination_connection_id_of(record),
                },
                path,
                out,
            );
            return .{
                .drain = .{
                    .datagrams_written = drain.datagrams_written,
                    .first_error = drain.first_error,
                },
                .next_deadline = try self.nextDeadline(allocator),
            };
        }

        /// Queue an APPLICATION_CLOSE and drain route-bound output.
        pub fn closeApplicationWithRoutePathAndDrainDatagrams(
            self: *Self,
            allocator: std.mem.Allocator,
            connection_id: u64,
            error_code: u64,
            reason_phrase: []const u8,
            now_nanos: i64,
            out: []DatagramPathResult,
        ) (root.Error || endpoint.RouteError)!CloseDatagramPathDrainResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            if (out.len == 0) return error.BufferTooSmall;
            const connection = connection_of(record);
            try connection.closeApplication(error_code, reason_phrase);
            const drain = self.drainDatagramsWithRoutePath(
                connection_id,
                connection,
                now_nanos,
                .{
                    .space = .application,
                    .destination_connection_id = destination_connection_id_of(record),
                },
                path,
                out,
            );
            return .{
                .drain = .{
                    .datagrams_written = drain.datagrams_written,
                    .first_error = drain.first_error,
                },
                .next_deadline = try self.nextDeadline(allocator),
            };
        }

        /// Queue a transport CONNECTION_CLOSE, drain route-bound output, and select the next deadline using scratch storage.
        pub fn closeWithRoutePathAndDrainDatagramsWithScratch(
            self: *Self,
            connection_id: u64,
            error_code: u64,
            frame_type: u64,
            reason_phrase: []const u8,
            now_nanos: i64,
            out: []DatagramPathResult,
        ) (root.Error || endpoint.RouteError)!CloseDatagramPathDrainResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            if (out.len == 0) return error.BufferTooSmall;
            _ = self.records.deadline_view_scratch orelse return error.BufferTooSmall;
            const connection = connection_of(record);
            try connection.closeConnection(error_code, frame_type, reason_phrase);
            const drain = self.drainDatagramsWithRoutePath(
                connection_id,
                connection,
                now_nanos,
                .{
                    .space = .application,
                    .destination_connection_id = destination_connection_id_of(record),
                },
                path,
                out,
            );
            return .{
                .drain = .{
                    .datagrams_written = drain.datagrams_written,
                    .first_error = drain.first_error,
                },
                .next_deadline = try self.nextDeadlineWithScratch(),
            };
        }

        /// Queue an APPLICATION_CLOSE, drain route-bound output, and select the next deadline using scratch storage.
        pub fn closeApplicationWithRoutePathAndDrainDatagramsWithScratch(
            self: *Self,
            connection_id: u64,
            error_code: u64,
            reason_phrase: []const u8,
            now_nanos: i64,
            out: []DatagramPathResult,
        ) (root.Error || endpoint.RouteError)!CloseDatagramPathDrainResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            if (out.len == 0) return error.BufferTooSmall;
            _ = self.records.deadline_view_scratch orelse return error.BufferTooSmall;
            const connection = connection_of(record);
            try connection.closeApplication(error_code, reason_phrase);
            const drain = self.drainDatagramsWithRoutePath(
                connection_id,
                connection,
                now_nanos,
                .{
                    .space = .application,
                    .destination_connection_id = destination_connection_id_of(record),
                },
                path,
                out,
            );
            return .{
                .drain = .{
                    .datagrams_written = drain.datagrams_written,
                    .first_error = drain.first_error,
                },
                .next_deadline = try self.nextDeadlineWithScratch(),
            };
        }

        /// Return the active close deadline for an endpoint-owned server record.
        pub fn closeDeadline(
            self: *Self,
            connection_id: u64,
        ) error{UnknownConnectionId}!?i64 {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            return connection_of(record).closeDeadline();
        }

        /// Atomically attach a Retry-pending record and switch its Initial route.
        ///
        /// The caller retains `record` on failure. Once the Original-DCID route
        /// is installed, every later failure retires that handle's routes and
        /// timer before returning, so no route can outlive its record admission.
        pub fn adoptRetryRecordAndSwitchInitialRoute(
            self: *Self,
            connection_id: u64,
            record: *Record,
            original_destination_connection_id: []const u8,
            retry_source_connection_id: []const u8,
            path: Path,
            options: endpoint.RouteOptions,
        ) (endpoint.RouteError || root.Error || error{ConnectionLimitReached})!endpoint.RouteResult {
            _ = try self.records.removeClosedRecords(&self.lifecycle);
            if (self.records.get(connection_id) != null) return error.DuplicateConnectionId;
            if (!self.records.hasCapacity()) return error.ConnectionLimitReached;

            try self.lifecycle.registerConnectionId(
                connection_id,
                original_destination_connection_id,
                path,
                options,
            );
            errdefer _ = self.lifecycle.retireConnection(connection_id);

            const route = try self.lifecycle.switchInitialDestinationConnectionIdAfterRetry(
                original_destination_connection_id,
                retry_source_connection_id,
                path,
            );
            try self.records.adopt(connection_id, record);
            return route;
        }

        /// Register an accepted Initial, drive its TLS backend, and drain its
        /// bounded Initial-space response datagrams.
        fn acceptInitial(
            self: *Self,
            connection_id: u64,
            connection: *Connection,
            now_nanos: i64,
            initial_accept: PathEndpoint.InitialAcceptResult,
            server_source_connection_id: []const u8,
            datagram: []const u8,
            options: endpoint.AcceptedInitialRouteOptions,
            backend: root.CryptoBackend,
            scratch: []u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
        ) endpoint_types.EndpointProtectedInitialError!PathTypes.EndpointAcceptedInitialCryptoBackendDatagramDrainResult {
            return self.lifecycle.processAcceptedProtectedInitialWithCryptoBackendAndDrainDatagrams(
                connection_id,
                connection,
                now_nanos,
                initial_accept,
                server_source_connection_id,
                datagram,
                options,
                backend,
                scratch,
                out,
            );
        }

        /// Initial admission and its bounded Initial and Handshake output.
        pub const InitialRecordAdmissionResult = struct {
            /// Initial-space processing and bounded output drain.
            initial: PathTypes.EndpointAcceptedInitialCryptoBackendDatagramDrainResult,
            /// Handshake-space output after Initial processing installed keys.
            handshake: ?endpoint_types.EndpointCryptoBackendDriveDatagramDrainResult = null,
        };

        /// Admit an Initial with the existing ownership boundary.
        ///
        /// Before registry adoption, an error leaves `record` with the caller.
        /// After adoption, an error retires and destroys the record. Generated
        /// datagrams remain caller-owned, including output written before an
        /// error. Use `acceptOwnedInitialRecord()` for unconditional transfer.
        pub fn acceptInitialRecord(
            self: *Self,
            connection_id: u64,
            record: *Record,
            now_nanos: i64,
            initial_accept: PathEndpoint.InitialAcceptResult,
            server_source_connection_id: []const u8,
            datagram: []const u8,
            options: endpoint.AcceptedInitialRouteOptions,
            scratch: []u8,
            initial_out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
        ) (endpoint_types.EndpointProtectedInitialError || root.Error || error{ConnectionLimitReached})!InitialRecordAdmissionResult {
            return self.acceptInitialRecordImpl(.retain_before_adoption, connection_id, record, now_nanos, initial_accept, server_source_connection_id, datagram, options, scratch, initial_out, handshake_out);
        }

        /// Consume a caller-owned record on success or error during admission.
        ///
        /// Allocate `record` with this endpoint's registry allocator. A record
        /// already owned by a registry is not valid input. On success, the
        /// registry owns the record and the caller owns the returned datagrams.
        /// On error, this method destroys the record and frees generated output,
        /// then clears those initialized datagram slots. Nonempty output slices
        /// must not overlap; overlap returns `BufferTooSmall` and consumes the
        /// record before adoption.
        pub fn acceptOwnedInitialRecord(
            self: *Self,
            connection_id: u64,
            record: *Record,
            now_nanos: i64,
            initial_accept: PathEndpoint.InitialAcceptResult,
            server_source_connection_id: []const u8,
            datagram: []const u8,
            options: endpoint.AcceptedInitialRouteOptions,
            scratch: []u8,
            initial_out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
        ) (endpoint_types.EndpointProtectedInitialError || root.Error || error{ConnectionLimitReached})!InitialRecordAdmissionResult {
            return self.acceptInitialRecordImpl(.consume, connection_id, record, now_nanos, initial_accept, server_source_connection_id, datagram, options, scratch, initial_out, handshake_out);
        }

        const AdmissionFailureOwnership = enum { retain_before_adoption, consume };

        fn acceptInitialRecordImpl(
            self: *Self,
            comptime failure_ownership: AdmissionFailureOwnership,
            connection_id: u64,
            record: *Record,
            now_nanos: i64,
            initial_accept: PathEndpoint.InitialAcceptResult,
            server_source_connection_id: []const u8,
            datagram: []const u8,
            options: endpoint.AcceptedInitialRouteOptions,
            scratch: []u8,
            initial_out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
        ) (endpoint_types.EndpointProtectedInitialError || root.Error || error{ConnectionLimitReached})!InitialRecordAdmissionResult {
            // The registry can destroy the record before output rollback runs.
            const datagram_allocator = connection_of(record).allocator;
            var record_adopted = false;
            errdefer if (failure_ownership == .consume and !record_adopted) {
                deinit_record(record);
                self.records.allocator.destroy(record);
            };
            if (failure_ownership == .consume and initial_out.len != 0 and handshake_out.len != 0 and
                @intFromPtr(initial_out.ptr) < @intFromPtr(handshake_out.ptr + handshake_out.len) and
                @intFromPtr(handshake_out.ptr) < @intFromPtr(initial_out.ptr + initial_out.len))
            {
                return error.BufferTooSmall;
            }
            _ = try self.records.removeClosedRecords(&self.lifecycle);
            if (self.records.get(connection_id) != null) return error.DuplicateConnectionId;
            if (!self.records.hasCapacity()) return error.ConnectionLimitReached;

            const accepted = self.acceptInitial(
                connection_id,
                connection_of(record),
                now_nanos,
                initial_accept,
                server_source_connection_id,
                datagram,
                options,
                crypto_backend_of(record),
                scratch,
                initial_out,
            ) catch |err| {
                _ = self.lifecycle.retireConnection(connection_id);
                return err;
            };
            errdefer if (failure_ownership == .consume) {
                for (initial_out[0..accepted.drain.datagrams_written]) |*output| {
                    datagram_allocator.free(output.datagram);
                    output.datagram = &.{};
                }
            };
            errdefer {
                if (!record_adopted) _ = self.lifecycle.retireConnection(connection_id);
            }

            try self.records.adopt(connection_id, record);
            record_adopted = true;
            if (accepted.drain.first_error != null or !accepted.backend.handshake_keys_installed) {
                // Re-arm after the Initial flight was drained: the arm inside
                // processAcceptedProtectedInitialDatagram ran before any
                // packet was in flight, so without this refresh the endpoint
                // never schedules the Initial-space PTO that retransmits a
                // lost server flight.
                self.lifecycle.armRecoveryTimerFromConnection(connection_id, connection_of(record)) catch |err| {
                    _ = self.records.retire(&self.lifecycle, connection_id) catch return error.Internal;
                    return err;
                };
                return .{ .initial = accepted };
            }
            const handshake = self.driveBackend(
                connection_id,
                .handshake,
                scratch,
                now_nanos,
                handshake_out,
            ) catch |err| {
                _ = self.records.retire(&self.lifecycle, connection_id) catch return error.Internal;
                return err;
            };
            errdefer if (failure_ownership == .consume) {
                for (handshake_out[0..handshake.drain.datagrams_written]) |*output| {
                    datagram_allocator.free(output.datagram);
                    output.datagram = &.{};
                }
            };
            // Re-arm again: the Handshake flight is now in flight too.
            self.lifecycle.armRecoveryTimerFromConnection(connection_id, connection_of(record)) catch |err| {
                _ = self.records.retire(&self.lifecycle, connection_id) catch return error.Internal;
                return err;
            };
            return .{
                .initial = accepted,
                .handshake = handshake,
            };
        }

        /// Accept an Initial and return each output drain with its UDP route.
        pub fn acceptInitialRecordWithRoutePath(
            self: *Self,
            connection_id: u64,
            record: *Record,
            now_nanos: i64,
            initial_accept: PathEndpoint.InitialAcceptResult,
            server_source_connection_id: []const u8,
            datagram: []const u8,
            options: endpoint.AcceptedInitialRouteOptions,
            scratch: []u8,
            initial_out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
        ) (endpoint_types.EndpointProtectedInitialError || root.Error || error{ConnectionLimitReached})!InitialRecordAdmissionPathResult {
            const admitted = try self.acceptInitialRecord(
                connection_id,
                record,
                now_nanos,
                initial_accept,
                server_source_connection_id,
                datagram,
                options,
                scratch,
                initial_out,
                handshake_out,
            );
            const path = admitted.initial.accepted_initial.initial_accept.path;
            return .{
                .initial = .{
                    .accepted = admitted.initial,
                    .path = path,
                },
                .handshake = if (admitted.handshake) |handshake| .{
                    .backend = handshake,
                    .path = path,
                } else null,
            };
        }

        /// Try to admit an Initial without turning active-capacity exhaustion
        /// into a socket-loop error.
        ///
        /// A `dropped_capacity` result means the caller still owns `record` and
        /// no lifecycle route or timer was installed. Other errors keep the
        /// existing throwing semantics from `acceptInitialRecordWithRoutePath`.
        pub fn tryAcceptInitialRecordWithRoutePath(
            self: *Self,
            connection_id: u64,
            record: *Record,
            now_nanos: i64,
            initial_accept: PathEndpoint.InitialAcceptResult,
            server_source_connection_id: []const u8,
            datagram: []const u8,
            options: endpoint.AcceptedInitialRouteOptions,
            scratch: []u8,
            initial_out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
        ) (endpoint_types.EndpointProtectedInitialError || root.Error)!InitialRecordAdmissionAttemptPathResult {
            const admitted = self.acceptInitialRecordWithRoutePath(
                connection_id,
                record,
                now_nanos,
                initial_accept,
                server_source_connection_id,
                datagram,
                options,
                scratch,
                initial_out,
                handshake_out,
            ) catch |err| switch (err) {
                error.ConnectionLimitReached => return .{ .dropped_capacity = .{
                    .active_connections = self.activeConnectionCount(),
                    .active_connection_limit = self.activeConnectionLimit(),
                } },
                else => return @errorCast(err),
            };
            return .{ .admitted = admitted };
        }

        /// Drive one TLS packet-number space and drain its bounded output.
        pub fn driveBackend(
            self: *Self,
            connection_id: u64,
            space: endpoint_types.EndpointInstalledKeyDatagramSpace,
            scratch: []u8,
            now_nanos: i64,
            out: []endpoint_types.EndpointPolledDatagramResult,
        ) (root.Error || error{UnknownConnectionId})!endpoint_types.EndpointCryptoBackendDriveDatagramDrainResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const conn = connection_of(record);
            const drive_views = [_]root.EndpointCryptoBackendDriveView{.{
                .connection_id = connection_id,
                .connection = conn,
                .backend = crypto_backend_of(record),
                .scratch = scratch,
            }};
            const poll_views = [_]root.EndpointConnectionPollView{.{
                .connection_id = connection_id,
                .connection = conn,
                .destination_connection_id = destination_connection_id_of(record),
                .source_connection_id = source_connection_id_of(record),
            }};
            return self.lifecycle.driveCryptoBackendStepWithDrain(&.{packetNumberSpace(space)}, &drive_views, .{}, &.{}, &poll_views, now_nanos, space, out);
        }

        /// Drive one TLS space and return the output drain with its UDP route.
        pub fn driveBackendWithRoutePath(
            self: *Self,
            connection_id: u64,
            space: endpoint_types.EndpointInstalledKeyDatagramSpace,
            scratch: []u8,
            now_nanos: i64,
            out: []endpoint_types.EndpointPolledDatagramResult,
        ) (root.Error || endpoint.RouteError)!CryptoBackendDatagramDrainPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            return .{
                .backend = try self.driveBackend(connection_id, space, scratch, now_nanos, out),
                .path = path,
            };
        }

        /// Drive the TLS Initial space and drain bounded protected Initial output.
        pub fn driveInitialBackend(
            self: *Self,
            connection_id: u64,
            scratch: []u8,
            now_nanos: i64,
            initial_token: []const u8,
            version: quic_packet.Version,
            out: []endpoint_types.EndpointPolledDatagramResult,
        ) (root.Error || error{UnknownConnectionId})!endpoint_types.EndpointCryptoBackendDriveProtectedLongDatagramDrainResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const initial_secrets = protection.deriveInitialSecrets(
                version,
                initial_destination_connection_id_of(record),
            ) catch return error.InvalidPacket;
            const keys = switch (connection_of(record).side) {
                .client => initial_secrets.client,
                .server => initial_secrets.server,
            };
            return self.lifecycle.driveCryptoBackendInSpaceAndDrainProtectedLongCryptoDatagrams(
                connection_id,
                connection_of(record),
                .initial,
                crypto_backend_of(record),
                scratch,
                .initial,
                now_nanos,
                destination_connection_id_of(record),
                source_connection_id_of(record),
                initial_token,
                keys,
                out,
            );
        }

        /// Drive Initial TLS output and return the drain with its UDP route.
        pub fn driveInitialBackendWithRoutePath(
            self: *Self,
            connection_id: u64,
            scratch: []u8,
            now_nanos: i64,
            initial_token: []const u8,
            version: quic_packet.Version,
            out: []endpoint_types.EndpointPolledDatagramResult,
        ) (root.Error || endpoint.RouteError)!ProtectedLongBackendDatagramDrainPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            return .{
                .backend = try self.driveInitialBackend(
                    connection_id,
                    scratch,
                    now_nanos,
                    initial_token,
                    version,
                    out,
                ),
                .path = path,
            };
        }

        /// Authenticate and accept the Retry follow-up Initial for one route.
        pub fn validateRetryInitial(
            self: *Self,
            policy: *PathEndpoint.AddressValidationPolicy,
            connection_id: u64,
            now_nanos: i64,
            path: Path,
            datagram: []const u8,
            supported_versions: []const quic_packet.Version,
        ) (endpoint_types.EndpointRetryProtectedInitialError || error{UnknownConnectionId})!PathTypes.EndpointRetryProtectedInitialResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const result = try self.lifecycle.processRetryValidatedProtectedInitialDatagram(
                policy,
                connection_id,
                connection_of(record),
                now_nanos,
                path,
                datagram,
                supported_versions,
            );
            mark_retry_validated(record);
            return result;
        }

        /// Validate a Retry follow-up Initial, drive TLS, and route outputs.
        ///
        /// This is the socket-facing server Retry continuation. It keeps the
        /// authenticated follow-up Initial, one-time token consumption,
        /// Initial-space backend output, and optional Handshake backend output
        /// on the endpoint-owned record and committed route.
        pub fn validateRetryInitialWithRoutePath(
            self: *Self,
            policy: *PathEndpoint.AddressValidationPolicy,
            connection_id: u64,
            now_nanos: i64,
            path: Path,
            datagram: []const u8,
            supported_versions: []const quic_packet.Version,
            scratch: []u8,
            initial_out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
        ) (endpoint_types.EndpointRetryProtectedInitialError || root.Error || endpoint.RouteError)!RetryInitialProcessPathResult {
            const info = protection.peekProtectedLongPacketInfo(datagram) catch return error.InvalidPacket;
            if (info.packet_type != .initial) return error.InvalidPacket;
            _ = try self.lifecycle.currentRoutePath(info.dcid);
            const retry = try self.validateRetryInitial(
                policy,
                connection_id,
                now_nanos,
                path,
                datagram,
                supported_versions,
            );
            const initial = try self.driveInitialBackendWithRoutePath(
                connection_id,
                scratch,
                now_nanos,
                &[_]u8{},
                retry.initial_accept.version,
                initial_out,
            );
            if (initial.backend.drain.first_error != null or !initial.backend.backend.handshake_keys_installed) {
                return .{
                    .retry = retry,
                    .initial = initial,
                };
            }
            return .{
                .retry = retry,
                .initial = initial,
                .handshake = try self.driveBackendWithRoutePath(
                    connection_id,
                    .handshake,
                    scratch,
                    now_nanos,
                    handshake_out,
                ),
            };
        }

        /// Authenticate coalesced Initial/Handshake input and drive TLS output.
        ///
        /// Once Handshake keys exist, this keeps the retained Initial receive
        /// path and the corresponding Handshake backend drive on the same
        /// endpoint-owned record boundary. The caller still owns UDP sends for
        /// the returned bounded output datagrams.
        pub fn processInitialWithHandshakeKeys(
            self: *Self,
            connection_id: u64,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            scratch: []u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
        ) (endpoint_types.EndpointProtectedInitialError || root.Error || error{UnknownConnectionId})!endpoint_types.EndpointRoutedCryptoBackendDriveDatagramDrainResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const route = try self.lifecycle.processRoutedProtectedLongDatagramWithInstalledHandshakeKeys(
                connection_id,
                connection_of(record),
                path,
                now_nanos,
                initial_destination_connection_id_of(record),
                datagram,
            );
            return .{
                .route = route,
                .backend = try self.driveBackend(connection_id, .handshake, scratch, now_nanos, out),
            };
        }

        /// Process a routed Initial and return Handshake output with its route.
        pub fn processInitialWithHandshakeKeysWithRoutePath(
            self: *Self,
            connection_id: u64,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            scratch: []u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
        ) (endpoint_types.EndpointProtectedInitialError || root.Error || endpoint.RouteError)!RoutedBackendDatagramDrainPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const output_path = try self.currentRecordRoutePath(record);
            const processed = try self.processInitialWithHandshakeKeys(
                connection_id,
                path,
                now_nanos,
                datagram,
                scratch,
                out,
            );
            return .{
                .route = processed.route,
                .backend = .{
                    .backend = processed.backend,
                    .path = output_path,
                },
            };
        }

        /// Result of processing one routed Initial and any resulting Handshake drive.
        pub const InitialProcessResult = struct {
            /// Initial-space receive, backend drive, and bounded output drain.
            initial: endpoint_types.EndpointRoutedCryptoBackendDriveProtectedLongDatagramDrainResult,
            /// Handshake-space backend drive after Initial processing installed keys.
            handshake: ?endpoint_types.EndpointCryptoBackendDriveDatagramDrainResult = null,
        };

        /// Authenticate a routed Initial, drive TLS, and drain bounded output.
        ///
        /// If Initial processing installs Handshake keys without an Initial
        /// drain error, the endpoint immediately drives the same record's
        /// Handshake backend into `handshake_out`. Separate output buffers
        /// preserve the caller's existing per-space bounds.
        pub fn processInitial(
            self: *Self,
            connection_id: u64,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            scratch: []u8,
            initial_token: []const u8,
            initial_out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
        ) (endpoint_types.EndpointProtectedDatagramError || root.Error || error{UnknownConnectionId})!InitialProcessResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const info = protection.peekProtectedLongPacketInfo(datagram) catch return error.InvalidPacket;
            if (info.packet_type != .initial) return error.InvalidPacket;
            const initial_secrets = protection.deriveInitialSecrets(
                info.version,
                initial_destination_connection_id_of(record),
            ) catch return error.InvalidPacket;
            const receive_keys = switch (connection_of(record).side) {
                .client => initial_secrets.server,
                .server => initial_secrets.client,
            };
            const send_keys = switch (connection_of(record).side) {
                .client => initial_secrets.client,
                .server => initial_secrets.server,
            };
            const initial = try self.lifecycle.processRoutedProtectedLongDatagramInSpaceAndDriveCryptoBackendAndDrainDatagrams(
                connection_id,
                connection_of(record),
                .initial,
                path,
                now_nanos,
                receive_keys,
                datagram,
                crypto_backend_of(record),
                scratch,
                destination_connection_id_of(record),
                source_connection_id_of(record),
                initial_token,
                send_keys,
                initial_out,
            );
            if (initial.backend.drain.first_error != null or !initial.backend.backend.handshake_keys_installed) {
                return .{ .initial = initial };
            }
            return .{
                .initial = initial,
                .handshake = try self.driveBackend(connection_id, .handshake, scratch, now_nanos, handshake_out),
            };
        }

        /// Process a routed Initial and return all output drains with routes.
        pub fn processInitialWithRoutePath(
            self: *Self,
            connection_id: u64,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            scratch: []u8,
            initial_token: []const u8,
            initial_out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
        ) (endpoint_types.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!InitialProcessPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const output_path = try self.currentRecordRoutePath(record);
            const processed = try self.processInitial(
                connection_id,
                path,
                now_nanos,
                datagram,
                scratch,
                initial_token,
                initial_out,
                handshake_out,
            );
            return .{
                .initial = .{
                    .route = processed.initial.route,
                    .backend = .{
                        .backend = processed.initial.backend,
                        .path = output_path,
                    },
                },
                .handshake = if (processed.handshake) |handshake| .{
                    .backend = handshake,
                    .path = output_path,
                } else null,
            };
        }

        /// Authenticate a routed Handshake packet, drive TLS, and drain output.
        pub fn processHandshake(
            self: *Self,
            connection_id: u64,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            scratch: []u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
        ) (endpoint_types.EndpointProtectedDatagramError || error{UnknownConnectionId})!endpoint_types.EndpointRoutedCryptoBackendDriveDatagramDrainResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            return self.lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendAndDrainDatagrams(
                connection_id,
                connection_of(record),
                path,
                now_nanos,
                datagram,
                crypto_backend_of(record),
                scratch,
                destination_connection_id_of(record),
                source_connection_id_of(record),
                out,
            );
        }

        /// Process a routed Handshake packet and return output with its route.
        pub fn processHandshakeWithRoutePath(
            self: *Self,
            connection_id: u64,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            scratch: []u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
        ) (endpoint_types.EndpointProtectedDatagramError || endpoint.RouteError)!RoutedBackendDatagramDrainPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const output_path = try self.currentRecordRoutePath(record);
            const processed = try self.processHandshake(
                connection_id,
                path,
                now_nanos,
                datagram,
                scratch,
                out,
            );
            return .{
                .route = processed.route,
                .backend = .{
                    .backend = processed.backend,
                    .path = output_path,
                },
            };
        }

        /// Dispatch one routed long-header packet by packet type.
        ///
        /// This keeps Initial and Handshake receive/TLS-drive/output routing
        /// behind the server endpoint owner. Callers that receive a coalesced
        /// datagram still split it into long packets first.
        pub fn processLongPacketWithRoutePath(
            self: *Self,
            connection_id: u64,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            scratch: []u8,
            initial_token: []const u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
        ) (endpoint_types.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!LongPacketProcessPathResult {
            const info = protection.peekProtectedLongPacketInfo(datagram) catch return error.InvalidPacket;
            return switch (info.packet_type) {
                .initial => .{ .initial = try self.processInitialWithRoutePath(
                    connection_id,
                    path,
                    now_nanos,
                    datagram,
                    scratch,
                    initial_token,
                    out,
                    handshake_out,
                ) },
                .handshake => .{ .handshake = try self.processHandshakeWithRoutePath(
                    connection_id,
                    path,
                    now_nanos,
                    datagram,
                    scratch,
                    out,
                ) },
                else => error.InvalidPacket,
            };
        }

        /// Dispatch one routed long-header datagram.
        ///
        /// Single-packet datagrams use `processLongPacketWithRoutePath()`.
        /// Coalesced Initial/Handshake datagrams are accepted only after
        /// Handshake keys exist, matching the installed-key coalesced path.
        /// Other packet-leading coalesced datagrams are rejected so trailing
        /// bytes cannot be hidden behind a single-packet dispatch.
        pub fn processLongDatagramWithRoutePath(
            self: *Self,
            connection_id: u64,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            scratch: []u8,
            initial_token: []const u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
        ) (endpoint_types.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!LongDatagramProcessPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const info = protection.peekProtectedLongPacketInfo(datagram) catch return error.InvalidPacket;
            if (info.len < datagram.len) {
                if (info.packet_type == .initial) {
                    if (!connection_of(record).hasHandshakeProtectionKeys()) return error.InvalidPacket;
                    return .{ .coalesced_initial_handshake = try self.processInitialWithHandshakeKeysWithRoutePath(
                        connection_id,
                        path,
                        now_nanos,
                        datagram,
                        scratch,
                        handshake_out,
                    ) };
                }
                // Coalesced long-header + trailing bytes where the first
                // packet is Handshake (not Initial). RFC 9000 §12.2 allows
                // coalescing any combination of packet types. Process the
                // first long-header packet with a slice so the trailing
                // bytes (1-RTT short header or padding) do not cause the
                // entire datagram to be rejected. The caller's coalesced
                // long+short dispatch processes any trailing 1-RTT data.
                return .{ .packet = try self.processLongPacketWithRoutePath(
                    connection_id,
                    path,
                    now_nanos,
                    datagram[0..info.len],
                    scratch,
                    initial_token,
                    out,
                    handshake_out,
                ) };
            }
            return .{ .packet = try self.processLongPacketWithRoutePath(
                connection_id,
                path,
                now_nanos,
                datagram,
                scratch,
                initial_token,
                out,
                handshake_out,
            ) };
        }

        /// Dispatch one already-routed UDP datagram by packet header form.
        ///
        /// Socket loops can classify once with `feedDatagramWithResponsePath()`
        /// or `routeDatagram()`, then keep long-header CRYPTO and installed-key
        /// short-packet processing behind this endpoint owner.
        pub fn processRoutedDatagramWithRoutePath(
            self: *Self,
            route: endpoint.RouteResult,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            installed_key_options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
        ) (endpoint_types.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!RoutedDatagramProcessPathResult {
            if (datagram.len == 0) return error.InvalidPacket;
            if ((datagram[0] & 0x40) == 0) return error.InvalidPacket;
            return switch (quic_packet.parseHeaderForm(datagram[0])) {
                .long => .{ .long = try self.processLongDatagramWithRoutePath(
                    route.connection_id,
                    path,
                    now_nanos,
                    datagram,
                    scratch,
                    initial_token,
                    out,
                    handshake_out,
                ) },
                .short => short: {
                    const record = self.records.get(route.connection_id) orelse return error.Internal;
                    break :short .{ .installed_key = try self.processRoutedInstalledKeyDatagramWithRoutePath(
                        route,
                        record,
                        path,
                        now_nanos,
                        datagram,
                        installed_key_options,
                    ) };
                },
            };
        }

        /// Dispatch one already-routed UDP datagram using scratch-backed short-packet handling.
        ///
        /// Long-header processing still uses the caller-provided CRYPTO scratch
        /// buffers. Short-header installed-key processing uses registry-owned
        /// deadline scratch for the route-bound receive/poll result.
        pub fn processRoutedDatagramWithRoutePathWithScratch(
            self: *Self,
            route: endpoint.RouteResult,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            installed_key_options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
        ) (endpoint_types.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!RoutedDatagramProcessPathResult {
            if (datagram.len == 0) return error.InvalidPacket;
            if ((datagram[0] & 0x40) == 0) return error.InvalidPacket;
            return switch (quic_packet.parseHeaderForm(datagram[0])) {
                .long => .{ .long = try self.processLongDatagramWithRoutePath(
                    route.connection_id,
                    path,
                    now_nanos,
                    datagram,
                    scratch,
                    initial_token,
                    out,
                    handshake_out,
                ) },
                .short => short: {
                    const record = self.records.get(route.connection_id) orelse return error.Internal;
                    break :short .{ .installed_key = try self.processRoutedInstalledKeyDatagramWithRoutePathWithScratch(
                        route,
                        record,
                        path,
                        now_nanos,
                        datagram,
                        installed_key_options,
                    ) };
                },
            };
        }

        /// Dispatch one already-routed UDP datagram and drain bounded output.
        pub fn processRoutedDatagramAndDrainWithRoutePath(
            self: *Self,
            route: endpoint.RouteResult,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            installed_key_options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
            installed_key_out: []DatagramPathResult,
        ) (endpoint_types.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!RoutedDatagramDrainPathResult {
            if (datagram.len == 0) return error.InvalidPacket;
            if ((datagram[0] & 0x40) == 0) return error.InvalidPacket;
            return switch (quic_packet.parseHeaderForm(datagram[0])) {
                .long => .{ .long = try self.processLongDatagramWithRoutePath(
                    route.connection_id,
                    path,
                    now_nanos,
                    datagram,
                    scratch,
                    initial_token,
                    out,
                    handshake_out,
                ) },
                .short => short: {
                    const record = self.records.get(route.connection_id) orelse return error.Internal;
                    break :short .{ .installed_key = try self.processRoutedInstalledKeyDatagramAndDrainWithRoutePath(
                        route,
                        record,
                        path,
                        now_nanos,
                        datagram,
                        installed_key_options,
                        installed_key_out,
                    ) };
                },
            };
        }

        /// Dispatch one already-routed UDP datagram and drain bounded output.
        ///
        /// Long-header processing keeps the existing caller scratch behavior.
        /// Short-header installed-key processing uses the scratch-backed
        /// route-bound receive/drain path.
        pub fn processRoutedDatagramAndDrainWithRoutePathWithScratch(
            self: *Self,
            route: endpoint.RouteResult,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            installed_key_options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
            installed_key_out: []DatagramPathResult,
        ) (endpoint_types.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!RoutedDatagramDrainPathResult {
            if (datagram.len == 0) return error.InvalidPacket;
            if ((datagram[0] & 0x40) == 0) return error.InvalidPacket;
            return switch (quic_packet.parseHeaderForm(datagram[0])) {
                .long => .{ .long = try self.processLongDatagramWithRoutePath(
                    route.connection_id,
                    path,
                    now_nanos,
                    datagram,
                    scratch,
                    initial_token,
                    out,
                    handshake_out,
                ) },
                .short => short: {
                    const record = self.records.get(route.connection_id) orelse return error.Internal;
                    break :short .{ .installed_key = try self.processRoutedInstalledKeyDatagramAndDrainWithRoutePathWithScratch(
                        route,
                        record,
                        path,
                        now_nanos,
                        datagram,
                        installed_key_options,
                        installed_key_out,
                    ) };
                },
            };
        }

        /// Classify one UDP datagram and process it if it routes to an owned record.
        ///
        /// Non-routed Initial, Version Negotiation, stateless reset, and drop
        /// results stay visible to the caller. Routed long-header and
        /// short-header datagrams are dispatched through the endpoint owner.
        pub fn processDatagramWithRoutePath(
            self: *Self,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
            installed_key_options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
        ) (endpoint_types.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!DatagramProcessPathResult {
            const action = try self.feedDatagramWithResponsePath(
                installed_key_options.out,
                path,
                datagram,
                unpredictable_prefix,
                supported_versions,
            );
            return switch (action) {
                .routed => |route| .{ .routed = try self.processRoutedDatagramWithRoutePath(
                    route,
                    path,
                    now_nanos,
                    datagram,
                    installed_key_options,
                    scratch,
                    initial_token,
                    out,
                    handshake_out,
                ) },
                .accept_initial => |initial| .{ .accept_initial = initial },
                .version_negotiation => |response| .{ .version_negotiation = response },
                .stateless_reset => |reset| .{ .stateless_reset = reset },
                .dropped => .dropped,
            };
        }

        /// Classify one UDP datagram and process routed packets using scratch-backed short-packet handling.
        pub fn processDatagramWithRoutePathWithScratch(
            self: *Self,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
            installed_key_options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
        ) (endpoint_types.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!DatagramProcessPathResult {
            const action = try self.feedDatagramWithResponsePath(
                installed_key_options.out,
                path,
                datagram,
                unpredictable_prefix,
                supported_versions,
            );
            return switch (action) {
                .routed => |route| .{ .routed = try self.processRoutedDatagramWithRoutePathWithScratch(
                    route,
                    path,
                    now_nanos,
                    datagram,
                    installed_key_options,
                    scratch,
                    initial_token,
                    out,
                    handshake_out,
                ) },
                .accept_initial => |initial| .{ .accept_initial = initial },
                .version_negotiation => |response| .{ .version_negotiation = response },
                .stateless_reset => |reset| .{ .stateless_reset = reset },
                .dropped => .dropped,
            };
        }

        /// Classify one UDP datagram, process routed packets, and drain bounded output.
        pub fn processDatagramAndDrainWithRoutePath(
            self: *Self,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
            installed_key_options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
            installed_key_out: []DatagramPathResult,
        ) (endpoint_types.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!DatagramProcessDrainPathResult {
            const action = try self.feedDatagramWithResponsePath(
                installed_key_options.out,
                path,
                datagram,
                unpredictable_prefix,
                supported_versions,
            );
            return switch (action) {
                .routed => |route| .{ .routed = try self.processRoutedDatagramAndDrainWithRoutePath(
                    route,
                    path,
                    now_nanos,
                    datagram,
                    installed_key_options,
                    scratch,
                    initial_token,
                    out,
                    handshake_out,
                    installed_key_out,
                ) },
                .accept_initial => |initial| .{ .accept_initial = initial },
                .version_negotiation => |response| .{ .version_negotiation = response },
                .stateless_reset => |reset| .{ .stateless_reset = reset },
                .dropped => .dropped,
            };
        }

        /// Classify one UDP datagram, process routed packets, and drain bounded output using scratch-backed short-packet handling.
        pub fn processDatagramAndDrainWithRoutePathWithScratch(
            self: *Self,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
            installed_key_options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
            installed_key_out: []DatagramPathResult,
        ) (endpoint_types.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!DatagramProcessDrainPathResult {
            const action = try self.feedDatagramWithResponsePath(
                installed_key_options.out,
                path,
                datagram,
                unpredictable_prefix,
                supported_versions,
            );
            return switch (action) {
                .routed => |route| .{ .routed = try self.processRoutedDatagramAndDrainWithRoutePathWithScratch(
                    route,
                    path,
                    now_nanos,
                    datagram,
                    installed_key_options,
                    scratch,
                    initial_token,
                    out,
                    handshake_out,
                    installed_key_out,
                ) },
                .accept_initial => |initial| .{ .accept_initial = initial },
                .version_negotiation => |response| .{ .version_negotiation = response },
                .stateless_reset => |reset| .{ .stateless_reset = reset },
                .dropped => .dropped,
            };
        }

        /// Run one bounded server receive step and sweep endpoint pending work.
        pub fn receiveDatagramStepWithRoutePath(
            self: *Self,
            allocator: std.mem.Allocator,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
            installed_key_options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
            installed_key_out: []DatagramPathResult,
            pending_space: endpoint_types.EndpointInstalledKeyDatagramSpace,
            pending_out: []DatagramPathResult,
        ) (endpoint_types.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!DatagramStepPathResult {
            const process = try self.processDatagramAndDrainWithRoutePath(
                path,
                now_nanos,
                datagram,
                unpredictable_prefix,
                supported_versions,
                installed_key_options,
                scratch,
                initial_token,
                out,
                handshake_out,
                installed_key_out,
            );
            const pending = try self.sweepPendingWorkAndDrainWithRoutePath(
                allocator,
                now_nanos,
                pending_space,
                pending_out,
            );
            return .{
                .process = process,
                .pending_work = pending.pending_work,
                .pending_drain = pending.pending_drain,
                .next_deadline = pending.next_deadline,
            };
        }

        /// Run one bounded server receive step using registry scratch storage.
        pub fn receiveDatagramStepWithRoutePathWithScratch(
            self: *Self,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
            installed_key_options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
            installed_key_out: []DatagramPathResult,
            pending_space: endpoint_types.EndpointInstalledKeyDatagramSpace,
            pending_out: []DatagramPathResult,
        ) (endpoint_types.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!DatagramStepPathResult {
            try self.ensureReceiveStepScratch();
            const process = try self.processDatagramAndDrainWithRoutePathWithScratch(
                path,
                now_nanos,
                datagram,
                unpredictable_prefix,
                supported_versions,
                installed_key_options,
                scratch,
                initial_token,
                out,
                handshake_out,
                installed_key_out,
            );
            const pending = try self.sweepPendingWorkAndDrainWithRoutePathWithScratch(
                now_nanos,
                pending_space,
                pending_out,
            );
            return .{
                .process = process,
                .pending_work = pending.pending_work,
                .pending_drain = pending.pending_drain,
                .next_deadline = pending.next_deadline,
            };
        }

        /// Run one bounded server receive step with Initial admission using
        /// registry scratch storage.
        ///
        /// Scratch storage is checked before packet processing so dynamic
        /// registries cannot return `BufferTooSmall` after taking ownership of
        /// the caller-supplied `record`.
        pub fn receiveDatagramStepWithRoutePathAndInitialRecordAdmissionWithScratch(
            self: *Self,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
            installed_key_options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
            connection_id: u64,
            record: *Record,
            server_source_connection_id: []const u8,
            options: endpoint.AcceptedInitialRouteOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
            installed_key_out: []DatagramPathResult,
            pending_space: endpoint_types.EndpointInstalledKeyDatagramSpace,
            pending_out: []DatagramPathResult,
        ) (endpoint_types.EndpointProtectedDatagramError || endpoint_types.EndpointProtectedInitialError || root.Error || endpoint.RouteError)!InitialAdmissionDatagramStepPathResult {
            try self.ensureReceiveStepScratch();
            const process = try self.processDatagramAndDrainWithRoutePathWithScratch(
                path,
                now_nanos,
                datagram,
                unpredictable_prefix,
                supported_versions,
                installed_key_options,
                scratch,
                initial_token,
                out,
                handshake_out,
                installed_key_out,
            );
            var admission: ?InitialRecordAdmissionAttemptPathResult = null;
            switch (process) {
                .accept_initial => |initial| {
                    admission = try self.tryAcceptInitialRecordWithRoutePath(
                        connection_id,
                        record,
                        now_nanos,
                        initial,
                        server_source_connection_id,
                        datagram,
                        options,
                        scratch,
                        out,
                        handshake_out,
                    );
                },
                else => {},
            }
            const pending = try self.sweepPendingWorkAndDrainWithRoutePathWithScratch(
                now_nanos,
                pending_space,
                pending_out,
            );
            return .{
                .process = process,
                .admission = admission,
                .pending_work = pending.pending_work,
                .pending_drain = pending.pending_drain,
                .next_deadline = pending.next_deadline,
            };
        }

        /// Run one bounded server receive step, admitting a caller-supplied
        /// record when the datagram is a fresh Initial.
        ///
        /// The endpoint takes ownership of `record` only when `admission` is
        /// `.admitted`. For routed packets, Version Negotiation, stateless
        /// reset responses, drops, and capacity drops, the caller still owns
        /// the record.
        pub fn receiveDatagramStepWithRoutePathAndInitialRecordAdmission(
            self: *Self,
            allocator: std.mem.Allocator,
            path: Path,
            now_nanos: i64,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
            installed_key_options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions,
            connection_id: u64,
            record: *Record,
            server_source_connection_id: []const u8,
            options: endpoint.AcceptedInitialRouteOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []endpoint_types.EndpointPolledDatagramResult,
            handshake_out: []endpoint_types.EndpointPolledDatagramResult,
            installed_key_out: []DatagramPathResult,
            pending_space: endpoint_types.EndpointInstalledKeyDatagramSpace,
            pending_out: []DatagramPathResult,
        ) (endpoint_types.EndpointProtectedDatagramError || endpoint_types.EndpointProtectedInitialError || root.Error || endpoint.RouteError)!InitialAdmissionDatagramStepPathResult {
            const process = try self.processDatagramAndDrainWithRoutePath(
                path,
                now_nanos,
                datagram,
                unpredictable_prefix,
                supported_versions,
                installed_key_options,
                scratch,
                initial_token,
                out,
                handshake_out,
                installed_key_out,
            );
            var admission: ?InitialRecordAdmissionAttemptPathResult = null;
            switch (process) {
                .accept_initial => |initial| {
                    admission = try self.tryAcceptInitialRecordWithRoutePath(
                        connection_id,
                        record,
                        now_nanos,
                        initial,
                        server_source_connection_id,
                        datagram,
                        options,
                        scratch,
                        out,
                        handshake_out,
                    );
                },
                else => {},
            }
            const pending = try self.sweepPendingWorkAndDrainWithRoutePath(
                allocator,
                now_nanos,
                pending_space,
                pending_out,
            );
            return .{
                .process = process,
                .admission = admission,
                .pending_work = pending.pending_work,
                .pending_drain = pending.pending_drain,
                .next_deadline = pending.next_deadline,
            };
        }

        fn ensureReceiveStepScratch(self: *Self) root.Error!void {
            _ = self.records.deadline_view_scratch orelse return error.BufferTooSmall;
            _ = self.records.receive_view_scratch orelse return error.BufferTooSmall;
            _ = self.records.poll_view_scratch orelse return error.BufferTooSmall;
        }

        fn sweepPendingWorkAndDrainWithRoutePathWithScratch(
            self: *Self,
            now_nanos: i64,
            pending_space: endpoint_types.EndpointInstalledKeyDatagramSpace,
            pending_out: []DatagramPathResult,
        ) root.Error!PendingStepPathResult {
            self.preflightDueRecoveryRoutes(now_nanos) catch |err| {
                const route_error = classifyRoutePreflightError(err) orelse return @errorCast(err);
                return .{
                    .pending_work = .{},
                    .pending_drain = .{ .first_route_error = route_error },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                };
            };
            if (pending_out.len == 0 and self.hasDueRecoveryForInstalledKeySpace(now_nanos, pending_space)) {
                return .{
                    .pending_work = .{},
                    .pending_drain = .{ .first_error = error.BufferTooSmall },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                };
            }
            const pending_work = try self.records.processPendingWorkWithScratch(
                &self.lifecycle,
                now_nanos,
            );
            const pending_drain = if (pending_work.recovery_serviced_count == 0)
                DatagramPathDrainResult{}
            else
                self.drainDatagramsAcrossRecordsWithRoutePathWithScratch(
                    now_nanos,
                    pending_space,
                    pending_out,
                );
            return .{
                .pending_work = pending_work,
                .pending_drain = pending_drain,
                .next_deadline = try self.nextDeadlineWithScratch(),
            };
        }

        fn sweepPendingWorkAndDrainWithRoutePath(
            self: *Self,
            allocator: std.mem.Allocator,
            now_nanos: i64,
            pending_space: endpoint_types.EndpointInstalledKeyDatagramSpace,
            pending_out: []DatagramPathResult,
        ) (root.Error || endpoint.RouteError)!PendingStepPathResult {
            self.preflightDueRecoveryRoutes(now_nanos) catch |err| {
                const route_error = classifyRoutePreflightError(err) orelse return @errorCast(err);
                return .{
                    .pending_work = .{},
                    .pending_drain = .{ .first_route_error = route_error },
                    .next_deadline = try self.nextDeadline(allocator),
                };
            };
            if (pending_out.len == 0 and self.hasDueRecoveryForInstalledKeySpace(now_nanos, pending_space)) {
                return .{
                    .pending_work = .{},
                    .pending_drain = .{ .first_error = error.BufferTooSmall },
                    .next_deadline = try self.nextDeadline(allocator),
                };
            }
            const pending_work = try self.records.processPendingWork(
                &self.lifecycle,
                allocator,
                now_nanos,
            );
            const pending_drain = if (pending_work.recovery_serviced_count == 0)
                DatagramPathDrainResult{}
            else
                self.drainDatagramsAcrossRecordsWithRoutePath(
                    allocator,
                    now_nanos,
                    pending_space,
                    pending_out,
                );
            return .{
                .pending_work = pending_work,
                .pending_drain = pending_drain,
                .next_deadline = try self.nextDeadline(allocator),
            };
        }
    };
}

test "Tls13ServerEndpoint IPv6 record admission retains its complete route" {
    const Record = struct {
        transport: Tls13ServerTransport,
        retry_validated: bool = false,

        fn connectionRef(self: *@This()) *Connection {
            return self.transport.connectionRef();
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.transport.cryptoBackend();
        }

        fn destinationConnectionId(self: *const @This()) []const u8 {
            return self.transport.peerInitialSourceConnectionId();
        }

        fn sourceConnectionId(self: *const @This()) []const u8 {
            return self.transport.localInitialSourceConnectionId();
        }

        fn initialDestinationConnectionId(self: *const @This()) []const u8 {
            return if (self.retry_validated)
                self.transport.localInitialSourceConnectionId()
            else
                self.transport.originalDestinationConnectionId();
        }

        fn markRetryValidated(self: *@This()) void {
            self.retry_validated = true;
        }

        fn deinit(self: *@This()) void {
            self.transport.deinit();
        }
    };
    const Legacy = Tls13ServerEndpoint(
        Record,
        Record.connectionRef,
        Record.cryptoBackend,
        Record.destinationConnectionId,
        Record.sourceConnectionId,
        Record.initialDestinationConnectionId,
        Record.markRetryValidated,
        Record.deinit,
    );
    const LegacyInstance = Tls13ServerEndpointForTuple(
        endpoint.Udp4Tuple,
        Record,
        Record.connectionRef,
        Record.cryptoBackend,
        Record.destinationConnectionId,
        Record.sourceConnectionId,
        Record.initialDestinationConnectionId,
        Record.markRetryValidated,
        Record.deinit,
    );
    try std.testing.expect(Legacy == LegacyInstance);
    try std.testing.expect(@TypeOf(@as(Legacy.DatagramPathResult, undefined).path.remote.octets) == [4]u8);

    const Server = Tls13ServerEndpointForTuple(
        endpoint.Udp6Tuple,
        Record,
        Record.connectionRef,
        Record.cryptoBackend,
        Record.destinationConnectionId,
        Record.sourceConnectionId,
        Record.initialDestinationConnectionId,
        Record.markRetryValidated,
        Record.deinit,
    );
    var server = try Server.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 2,
        .max_stateless_reset_tokens = 2,
    });
    defer server.deinit();
    const path = endpoint.Udp6Tuple{
        .local = endpoint.Udp6Address.init(.{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 4433, 3),
        .remote = endpoint.Udp6Address.init(.{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 }, 4444, 3),
    };
    const record = try std.testing.allocator.create(Record);
    var record_owned = false;
    errdefer if (!record_owned) std.testing.allocator.destroy(record);
    record.* = .{ .transport = try Tls13ServerTransport.init(std.testing.allocator, .{}, .{}) };
    errdefer if (!record_owned) record.deinit();
    _ = try server.adoptRetryRecordAndSwitchInitialRoute(7, record, "original", "retry", path, .{});
    record_owned = true;
    try std.testing.expectEqual(@as(usize, 1), server.activeConnectionCount());
    try std.testing.expect((try server.lifecycle.currentRoutePath("retry")).eql(path));
    try std.testing.expect(@TypeOf(@as(Server.InitialRecordAdmissionResult, undefined).initial) == endpoint_types.ForTuple(endpoint.Udp6Tuple).EndpointAcceptedInitialCryptoBackendDatagramDrainResult);
    const retired = try server.retireRecord(7);
    try std.testing.expectEqual(@as(usize, 1), retired.routes_retired);
    try std.testing.expectEqual(@as(usize, 0), server.activeConnectionCount());
}
