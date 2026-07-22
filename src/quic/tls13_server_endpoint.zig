//! Reusable endpoint ownership for TLS 1.3 server connection records.
//!
//! This type owns lifecycle routing/timers and record storage, but deliberately
//! leaves UDP socket I/O, admission policy, and application dispatch with its
//! caller.

const std = @import("std");
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
const tls13 = @import("tls13.zig");
const tls13_client_endpoint = @import("tls13_client_endpoint.zig");
const tls13_server_transport = @import("tls13_server_transport.zig");

const Connection = connection_module.Connection;
const EndpointConnectionLifecycle = endpoint_lifecycle.EndpointConnectionLifecycle;
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
    const Registry = endpoint_connection_registry.EndpointConnectionRegistry(
        Record,
        connection_of,
        deinit_record,
    );

    return struct {
        const Self = @This();

        /// Endpoint-owned 1-RTT datagram paired with its committed UDP route.
        pub const OneRttDatagramPathResult = struct {
            datagram: []u8,
            path: endpoint.Udp4Tuple,
        };

        /// Endpoint-owned protected datagram paired with its committed UDP route.
        pub const DatagramPathResult = struct {
            /// Endpoint-owned connection handle that produced `datagram`.
            connection_id: u64,
            /// Protected datagram emitted by the selected record.
            datagram: []u8,
            /// Current committed UDP tuple for this record's local route CID.
            path: endpoint.Udp4Tuple,
        };

        /// Endpoint response datagram paired with the UDP tuple it answers.
        pub const DatagramResponsePathResult = struct {
            /// Response datagram written into caller-provided scratch storage.
            datagram: []const u8,
            /// UDP tuple that produced the response.
            path: endpoint.Udp4Tuple,
        };

        /// Route classification with response datagrams paired to their path.
        pub const DatagramActionPathResult = union(enum) {
            routed: endpoint.RouteResult,
            accept_initial: endpoint.InitialAcceptResult,
            version_negotiation: DatagramResponsePathResult,
            stateless_reset: DatagramResponsePathResult,
            dropped,
        };

        /// Installed-key receive result with any immediate output route.
        pub const InstalledKeyDatagramRoutePollResult = struct {
            /// Receive, path validation, and route-update result when feed succeeded.
            feed: ?root.EndpointFeedInstalledKeyPathUpdateResult = null,
            /// Feed error returned after the endpoint had selected a record.
            feed_error: ?root.EndpointProtectedDatagramError = null,
            /// Peer-issued CID sequence whose stateless reset token matched.
            stateless_reset_sequence_number: ?u64 = null,
            /// Protected output emitted after feed or close-on-error handling.
            datagram: ?DatagramPathResult = null,
            /// Next endpoint-visible deadline after receive processing and optional output.
            next_deadline: ?root.EndpointConnectionDeadline = null,
        };

        /// Due-work result with every drained datagram paired to a route.
        pub const DueWorkDatagramPathDrainResult = struct {
            /// Deadline that was due when this pending-work pass started.
            deadline: root.EndpointConnectionDeadline,
            /// Pending-work actions applied for the due deadline.
            pending_work: root.EndpointPendingWorkResult,
            /// Bounded output drain after a due recovery timer, if any.
            drain: DatagramPathDrainResult,
            /// Next endpoint-visible deadline after due work and output drain.
            next_deadline: ?root.EndpointConnectionDeadline = null,
        };

        /// Pending-work sweep result with every drained datagram paired to a route.
        pub const PendingWorkDatagramPathDrainResult = struct {
            /// Pending-work actions applied across endpoint-owned records.
            pending_work: root.EndpointPendingWorkSweepResult,
            /// Bounded output drain after pending recovery work, if any.
            drain: DatagramPathDrainResult,
            /// Next endpoint-visible deadline after pending work and output drain.
            next_deadline: ?root.EndpointConnectionDeadline = null,
        };

        /// Installed-key receive plus pending-work result with route-bound output drain.
        pub const FeedPendingWorkDatagramPathDrainResult = struct {
            /// Receive classification and processing result.
            feed: root.EndpointFeedInstalledKeyDatagramResult,
            /// Pending-work actions applied after receive processing.
            pending_work: root.EndpointPendingWorkSweepResult,
            /// Bounded output drain after pending recovery work, if any.
            drain: DatagramPathDrainResult,
            /// Next endpoint-visible deadline after receive, pending work, and output drain.
            next_deadline: ?root.EndpointConnectionDeadline = null,
        };

        /// Installed-key receive plus pending-work result with one route-bound output poll.
        pub const FeedPendingWorkDatagramPathPollResult = struct {
            /// Receive classification and processing result.
            feed: root.EndpointFeedInstalledKeyDatagramResult,
            /// Pending-work actions applied after receive processing.
            pending_work: root.EndpointPendingWorkSweepResult,
            /// Route preflight error before pending recovery work, if any.
            pending_route_error: ?endpoint.RouteError = null,
            /// Protected output emitted after pending recovery work, if any.
            datagram: ?DatagramPathResult = null,
            /// Next endpoint-visible deadline after receive, pending work, and output poll.
            next_deadline: ?root.EndpointConnectionDeadline = null,
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
            next_deadline: ?root.EndpointConnectionDeadline = null,
        };

        /// Application stream/control result with bounded route-bound output.
        pub const OneRttControlDatagramPathDrainResult = struct {
            drain: DatagramPathDrainResult = .{},
            next_deadline: ?root.EndpointConnectionDeadline = null,
        };

        /// Accepted Initial output paired with the committed UDP route.
        pub const AcceptedInitialDatagramDrainPathResult = struct {
            accepted: root.EndpointAcceptedInitialCryptoBackendDatagramDrainResult,
            path: endpoint.Udp4Tuple,
        };

        /// Backend-driven installed-key output paired with the committed route.
        pub const CryptoBackendDatagramDrainPathResult = struct {
            backend: root.EndpointCryptoBackendDriveDatagramDrainResult,
            path: endpoint.Udp4Tuple,
        };

        /// Backend-driven long-header output paired with the committed route.
        pub const ProtectedLongBackendDatagramDrainPathResult = struct {
            backend: root.EndpointCryptoBackendDriveProtectedLongDatagramDrainResult,
            path: endpoint.Udp4Tuple,
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
            feed: ?root.EndpointFeedInstalledKeyPathUpdateResult = null,
            /// Feed error returned after the endpoint had selected a record.
            feed_error: ?root.EndpointProtectedDatagramError = null,
            /// Peer-issued CID sequence whose stateless reset token matched.
            stateless_reset_sequence_number: ?u64 = null,
            /// Bounded protected output drain after receive or close-on-error handling.
            drain: root.EndpointDatagramDrainResult = .{},
            /// Next endpoint-visible deadline after receive processing and bounded output.
            next_deadline: ?root.EndpointConnectionDeadline = null,
        };

        /// Routed datagram dispatch with bounded route-bound output drain.
        pub const RoutedDatagramDrainPathResult = union(enum) {
            long: LongDatagramProcessPathResult,
            installed_key: InstalledKeyDatagramRouteDrainResult,
        };

        /// Endpoint classification plus routed datagram processing result.
        pub const DatagramProcessPathResult = union(enum) {
            routed: RoutedDatagramProcessPathResult,
            accept_initial: endpoint.InitialAcceptResult,
            version_negotiation: DatagramResponsePathResult,
            stateless_reset: DatagramResponsePathResult,
            dropped,
        };

        /// Endpoint classification plus routed datagram processing and bounded drain.
        pub const DatagramProcessDrainPathResult = union(enum) {
            routed: RoutedDatagramDrainPathResult,
            accept_initial: endpoint.InitialAcceptResult,
            version_negotiation: DatagramResponsePathResult,
            stateless_reset: DatagramResponsePathResult,
            dropped,
        };

        /// One server socket-loop receive step with route-bound output and pending work.
        pub const DatagramStepPathResult = struct {
            /// Endpoint classification plus routed datagram processing result.
            process: DatagramProcessDrainPathResult,
            /// Pending work swept across endpoint-owned records after receive.
            pending_work: root.EndpointPendingWorkSweepResult,
            /// Bounded route-bound output after pending recovery work, if any.
            pending_drain: DatagramPathDrainResult,
            /// Next endpoint-visible deadline after receive, drain, and pending work.
            next_deadline: ?root.EndpointConnectionDeadline = null,
        };

        /// One server socket-loop receive step that may admit a new Initial record.
        pub const InitialAdmissionDatagramStepPathResult = struct {
            /// Endpoint classification plus routed datagram processing result.
            process: DatagramProcessDrainPathResult,
            /// Admission result when `process` classified a fresh Initial.
            admission: ?InitialRecordAdmissionAttemptPathResult = null,
            /// Pending work swept across endpoint-owned records after receive.
            pending_work: root.EndpointPendingWorkSweepResult,
            /// Bounded route-bound output after pending recovery work, if any.
            pending_drain: DatagramPathDrainResult,
            /// Next endpoint-visible deadline after receive, optional admission, and pending work.
            next_deadline: ?root.EndpointConnectionDeadline = null,
        };

        const PendingStepPathResult = struct {
            pending_work: root.EndpointPendingWorkSweepResult = .{},
            pending_drain: DatagramPathDrainResult = .{},
            next_deadline: ?root.EndpointConnectionDeadline = null,
        };

        /// Routed installed-key backend processing with route-bound output.
        pub const RoutedBackendDatagramDrainPathResult = struct {
            route: endpoint.RouteResult,
            backend: CryptoBackendDatagramDrainPathResult,
        };

        /// Retry follow-up Initial validation with route-bound TLS output.
        pub const RetryInitialProcessPathResult = struct {
            /// Authenticated Retry follow-up metadata and token validation.
            retry: root.EndpointRetryProtectedInitialResult,
            /// Initial-space TLS backend output after the Retry follow-up.
            initial: ProtectedLongBackendDatagramDrainPathResult,
            /// Handshake-space backend output after Initial installed keys.
            handshake: ?CryptoBackendDatagramDrainPathResult = null,
        };

        lifecycle: EndpointConnectionLifecycle,
        records: Registry,

        fn packetNumberSpace(space: root.EndpointInstalledKeyDatagramSpace) root.PacketNumberSpace {
            return switch (space) {
                .handshake => .handshake,
                .zero_rtt, .application => .application,
            };
        }

        fn preflightDueRecoveryRoutes(
            self: *Self,
            now_millis: i64,
        ) (root.Error || endpoint.RouteError)!void {
            _ = try self.records.removeClosedRecords(&self.lifecycle);
            var iterator = self.records.records.iterator();
            while (iterator.next()) |entry| {
                const connection_id = entry.key_ptr.*;
                const record = entry.value_ptr.*;
                const connection = connection_of(record);
                const deadline = self.lifecycle.nextDeadline(connection_id, connection) orelse continue;
                if (deadline.deadline_millis > now_millis) continue;
                if (deadline.kind != .recovery) continue;
                if (deadline.recovery == null) continue;
                _ = try self.currentRecordRoutePath(record);
            }
        }

        fn hasDueRecoveryForInstalledKeySpace(
            self: *const Self,
            now_millis: i64,
            space: root.EndpointInstalledKeyDatagramSpace,
        ) bool {
            const packet_space = packetNumberSpace(space);
            var iterator = self.records.records.iterator();
            while (iterator.next()) |entry| {
                const connection_id = entry.key_ptr.*;
                const record = entry.value_ptr.*;
                const connection = connection_of(record);
                const deadline = self.lifecycle.nextDeadline(connection_id, connection) orelse continue;
                if (deadline.deadline_millis > now_millis) continue;
                if (deadline.kind != .recovery) continue;
                const recovery = deadline.recovery orelse continue;
                if (recovery.space == packet_space) return true;
            }
            return false;
        }

        fn currentRecordRoutePath(self: *const Self, record: *const Record) endpoint.RouteError!endpoint.Udp4Tuple {
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
            pending_work: root.EndpointPendingWorkResult,
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
            path: endpoint.Udp4Tuple,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
        ) endpoint.RouteError!endpoint.DatagramAction {
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
            path: endpoint.Udp4Tuple,
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
            path: endpoint.Udp4Tuple,
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
        ) error{ Internal, UnknownConnectionId }!root.EndpointConnectionRetireResult {
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
        ) !?root.EndpointConnectionDeadline {
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
        ) root.Error!?root.EndpointConnectionDeadline {
            return self.records.nextDeadlineWithStorage(&self.lifecycle, out);
        }

        /// Select the earliest endpoint-owned deadline using registry scratch storage.
        pub fn nextDeadlineWithScratch(self: *Self) root.Error!?root.EndpointConnectionDeadline {
            return self.records.nextDeadlineWithScratch(&self.lifecycle);
        }

        /// Sweep all endpoint-owned records, retire closed records, and return
        /// the next endpoint-visible deadline.
        pub fn processPendingWorkAndSelectNextDeadline(
            self: *Self,
            allocator: std.mem.Allocator,
            now_millis: i64,
        ) root.Error!root.EndpointPendingWorkNextDeadlineResult {
            return self.records.processPendingWorkAndSelectNextDeadline(
                &self.lifecycle,
                allocator,
                now_millis,
            );
        }

        /// Sweep pending work and select the next endpoint-owned deadline using scratch storage.
        pub fn processPendingWorkAndSelectNextDeadlineWithScratch(
            self: *Self,
            now_millis: i64,
        ) root.Error!root.EndpointPendingWorkNextDeadlineResult {
            return self.records.processPendingWorkAndSelectNextDeadlineWithScratch(
                &self.lifecycle,
                now_millis,
            );
        }

        /// Sweep pending work across endpoint-owned records and drain route-bound output.
        pub fn processPendingWorkAndDrainDatagramsWithRoutePath(
            self: *Self,
            allocator: std.mem.Allocator,
            now_millis: i64,
            space: root.EndpointInstalledKeyDatagramSpace,
            out: []DatagramPathResult,
        ) root.Error!PendingWorkDatagramPathDrainResult {
            self.preflightDueRecoveryRoutes(now_millis) catch |err| {
                const route_error = classifyRoutePreflightError(err) orelse return @errorCast(err);
                return .{
                    .pending_work = .{},
                    .drain = .{ .first_route_error = route_error },
                    .next_deadline = try self.nextDeadline(allocator),
                };
            };
            if (out.len == 0 and self.hasDueRecoveryForInstalledKeySpace(now_millis, space)) {
                return .{
                    .pending_work = .{},
                    .drain = .{ .first_error = error.BufferTooSmall },
                    .next_deadline = try self.nextDeadline(allocator),
                };
            }
            const pending_work = try self.records.processPendingWork(
                &self.lifecycle,
                allocator,
                now_millis,
            );
            const drain = if (pending_work.recovery_serviced_count == 0)
                DatagramPathDrainResult{}
            else
                self.drainDatagramsAcrossRecordsWithRoutePath(
                    allocator,
                    now_millis,
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
            now_millis: i64,
            space: root.EndpointInstalledKeyDatagramSpace,
            out: []DatagramPathResult,
        ) root.Error!PendingWorkDatagramPathDrainResult {
            self.preflightDueRecoveryRoutes(now_millis) catch |err| {
                const route_error = classifyRoutePreflightError(err) orelse return @errorCast(err);
                return .{
                    .pending_work = .{},
                    .drain = .{ .first_route_error = route_error },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                };
            };
            if (out.len == 0 and self.hasDueRecoveryForInstalledKeySpace(now_millis, space)) {
                return .{
                    .pending_work = .{},
                    .drain = .{ .first_error = error.BufferTooSmall },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                };
            }
            const pending_work = try self.records.processPendingWorkWithScratch(
                &self.lifecycle,
                now_millis,
            );
            const drain = if (pending_work.recovery_serviced_count == 0)
                DatagramPathDrainResult{}
            else
                self.drainDatagramsAcrossRecordsWithRoutePathWithScratch(
                    now_millis,
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
            now_millis: i64,
            out: []root.EndpointPolledDatagramResult,
        ) root.Error!?root.EndpointDueWorkDatagramDrainResult {
            const deadline = (try self.nextDeadline(allocator)) orelse return null;
            if (deadline.deadline_millis > now_millis) return null;
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
                    now_millis,
                    options,
                    out,
                )
            else if (deadline.kind == .recovery and deadline.recovery != null and deadline.recovery.?.space == .initial) pending: {
                if (out.len == 0) return error.BufferTooSmall;
                const pending = try self.lifecycle.processPendingWork(
                    deadline.connection_id,
                    connection,
                    now_millis,
                );
                const serviced = pending.recovery_serviced orelse break :pending root.EndpointPendingWorkDatagramDrainResult{
                    .pending_work = pending,
                    .drain = .{},
                };
                if (serviced.timer.space != .initial) return error.InvalidPacket;
                break :pending root.EndpointPendingWorkDatagramDrainResult{
                    .pending_work = pending,
                    .drain = self.drainInitialDatagrams(
                        deadline.connection_id,
                        record,
                        connection,
                        now_millis,
                        out,
                    ),
                };
            } else root.EndpointPendingWorkDatagramDrainResult{
                .pending_work = try self.lifecycle.processPendingWork(
                    deadline.connection_id,
                    connection,
                    now_millis,
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
            now_millis: i64,
            out: []root.EndpointPolledDatagramResult,
        ) root.Error!?root.EndpointDueWorkDatagramDrainResult {
            const deadline = (try self.nextDeadlineWithScratch()) orelse return null;
            if (deadline.deadline_millis > now_millis) return null;
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
                    now_millis,
                    options,
                    out,
                )
            else if (deadline.kind == .recovery and deadline.recovery != null and deadline.recovery.?.space == .initial) pending: {
                if (out.len == 0) return error.BufferTooSmall;
                const pending = try self.lifecycle.processPendingWork(
                    deadline.connection_id,
                    connection,
                    now_millis,
                );
                const serviced = pending.recovery_serviced orelse break :pending root.EndpointPendingWorkDatagramDrainResult{
                    .pending_work = pending,
                    .drain = .{},
                };
                if (serviced.timer.space != .initial) return error.InvalidPacket;
                break :pending root.EndpointPendingWorkDatagramDrainResult{
                    .pending_work = pending,
                    .drain = self.drainInitialDatagrams(
                        deadline.connection_id,
                        record,
                        connection,
                        now_millis,
                        out,
                    ),
                };
            } else root.EndpointPendingWorkDatagramDrainResult{
                .pending_work = try self.lifecycle.processPendingWork(
                    deadline.connection_id,
                    connection,
                    now_millis,
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
            now_millis: i64,
            out: []DatagramPathResult,
        ) (root.Error || endpoint.RouteError)!?DueWorkDatagramPathDrainResult {
            const deadline = (try self.nextDeadline(allocator)) orelse return null;
            if (deadline.deadline_millis > now_millis) return null;
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
                    now_millis,
                );
                const serviced = pending.recovery_serviced orelse break :pending pending;
                if (serviced.timer.space != options.recoveryPacketNumberSpace()) return error.InvalidPacket;
                const drain = self.drainDatagramsWithRoutePath(
                    deadline.connection_id,
                    connection,
                    now_millis,
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
                    now_millis,
                );
                const serviced = pending.recovery_serviced orelse break :pending pending;
                if (serviced.timer.space != .initial) return error.InvalidPacket;
                const drain = self.drainInitialDatagramsWithRoutePath(
                    deadline.connection_id,
                    record,
                    connection,
                    now_millis,
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
                now_millis,
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
            now_millis: i64,
            out: []DatagramPathResult,
        ) (root.Error || endpoint.RouteError)!?DueWorkDatagramPathDrainResult {
            const deadline = (try self.nextDeadlineWithScratch()) orelse return null;
            if (deadline.deadline_millis > now_millis) return null;
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
                    now_millis,
                );
                const serviced = pending.recovery_serviced orelse break :pending pending;
                if (serviced.timer.space != options.recoveryPacketNumberSpace()) return error.InvalidPacket;
                const drain = self.drainDatagramsWithRoutePath(
                    deadline.connection_id,
                    connection,
                    now_millis,
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
                    now_millis,
                );
                const serviced = pending.recovery_serviced orelse break :pending pending;
                if (serviced.timer.space != .initial) return error.InvalidPacket;
                const drain = self.drainInitialDatagramsWithRoutePath(
                    deadline.connection_id,
                    record,
                    connection,
                    now_millis,
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
                now_millis,
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
            now_millis: i64,
            path: endpoint.Udp4Tuple,
            out: []DatagramPathResult,
        ) root.EndpointDatagramDrainResult {
            var result = root.EndpointDatagramDrainResult{};
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
                    now_millis,
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
            now_millis: i64,
            out: []root.EndpointPolledDatagramResult,
        ) root.EndpointDatagramDrainResult {
            var result = root.EndpointDatagramDrainResult{};
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
                    now_millis,
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
            now_millis: i64,
            options: root.EndpointPollInstalledKeyDatagramOptions,
            path: endpoint.Udp4Tuple,
            out: []DatagramPathResult,
        ) root.EndpointDatagramDrainResult {
            var result = root.EndpointDatagramDrainResult{};
            while (result.datagrams_written < out.len) {
                const datagram = self.lifecycle.pollDatagram(
                    connection_id,
                    connection,
                    now_millis,
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
            path: root.endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            options: root.EndpointFeedInstalledKeyDatagramOptions,
        ) root.EndpointProtectedDatagramError!root.EndpointFeedInstalledKeyDatagramResult {
            _ = allocator;
            return self.feedDatagramWithInstalledKeysOwned(
                path,
                now_millis,
                datagram,
                options,
            );
        }

        fn feedDatagramWithInstalledKeysOwned(
            self: *Self,
            path: root.endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            options: root.EndpointFeedInstalledKeyDatagramOptions,
        ) root.EndpointProtectedDatagramError!root.EndpointFeedInstalledKeyDatagramResult {
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
                now_millis,
                datagram,
                options,
            );
        }

        /// Route one installed-key datagram and select the next endpoint-owned deadline using scratch storage.
        pub fn feedDatagramWithInstalledKeysAndSelectNextDeadlineWithScratch(
            self: *Self,
            path: root.endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            options: root.EndpointFeedInstalledKeyDatagramOptions,
        ) root.EndpointProtectedDatagramError!root.EndpointFeedInstalledKeyDatagramNextDeadlineResult {
            _ = try self.records.nextDeadlineWithScratch(&self.lifecycle);
            return .{
                .feed = try self.feedDatagramWithInstalledKeysOwned(
                    path,
                    now_millis,
                    datagram,
                    options,
                ),
                .next_deadline = try self.nextDeadlineWithScratch(),
            };
        }

        /// Route one installed-key datagram, sweep pending work, and select the next deadline using scratch storage.
        pub fn feedDatagramWithInstalledKeysAndProcessPendingWorkAndSelectNextDeadlineWithScratch(
            self: *Self,
            path: root.endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            options: root.EndpointFeedInstalledKeyDatagramOptions,
        ) root.EndpointProtectedDatagramError!root.EndpointFeedPendingWorkNextDeadlineResult {
            _ = self.records.receive_view_scratch orelse return error.BufferTooSmall;
            _ = self.records.deadline_view_scratch orelse return error.BufferTooSmall;
            const feed = try self.feedDatagramWithInstalledKeysOwned(
                path,
                now_millis,
                datagram,
                options,
            );
            const pending_deadline = try self.processPendingWorkAndSelectNextDeadlineWithScratch(now_millis);
            return .{
                .feed = feed,
                .pending_work = pending_deadline.pending_work,
                .next_deadline = pending_deadline.next_deadline,
            };
        }

        /// Route one installed-key datagram, sweep pending work, and drain route-bound output using scratch storage.
        pub fn feedDatagramWithInstalledKeysAndProcessPendingWorkAndDrainDatagramsWithRoutePathWithScratch(
            self: *Self,
            path: root.endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            options: root.EndpointFeedInstalledKeyDatagramOptions,
            space: root.EndpointInstalledKeyDatagramSpace,
            out: []DatagramPathResult,
        ) root.EndpointProtectedDatagramError!FeedPendingWorkDatagramPathDrainResult {
            _ = self.records.receive_view_scratch orelse return error.BufferTooSmall;
            _ = self.records.deadline_view_scratch orelse return error.BufferTooSmall;
            _ = self.records.poll_view_scratch orelse return error.BufferTooSmall;
            const feed = try self.feedDatagramWithInstalledKeysOwned(
                path,
                now_millis,
                datagram,
                options,
            );
            const pending_drain = try self.processPendingWorkAndDrainDatagramsWithRoutePathWithScratch(
                now_millis,
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
            path: root.endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            options: root.EndpointFeedInstalledKeyDatagramOptions,
            space: root.EndpointInstalledKeyDatagramSpace,
        ) root.EndpointProtectedDatagramError!FeedPendingWorkDatagramPathPollResult {
            _ = self.records.receive_view_scratch orelse return error.BufferTooSmall;
            _ = self.records.deadline_view_scratch orelse return error.BufferTooSmall;
            _ = self.records.poll_view_scratch orelse return error.BufferTooSmall;
            const feed = try self.feedDatagramWithInstalledKeysOwned(
                path,
                now_millis,
                datagram,
                options,
            );
            self.preflightDueRecoveryRoutes(now_millis) catch |err| {
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
                now_millis,
            );
            const datagram_out = if (pending_work.recovery_serviced_count == 0)
                null
            else
                try self.pollDatagramWithRoutePathWithScratch(
                    now_millis,
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
            path: root.endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            options: root.EndpointFeedInstalledKeyDatagramOptions,
        ) root.EndpointProtectedDatagramError!root.EndpointFeedPathUpdateDatagramPollResult {
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
                now_millis,
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
            path: root.endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            options: root.EndpointFeedInstalledKeyDatagramOptions,
        ) root.EndpointProtectedDatagramError!InstalledKeyDatagramRoutePollResult {
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
                now_millis,
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
            path: root.endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            options: root.EndpointFeedInstalledKeyDatagramOptions,
        ) root.EndpointProtectedDatagramError!InstalledKeyDatagramRoutePollResult {
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
                now_millis,
                datagram,
                options,
            );
        }

        fn processRoutedInstalledKeyDatagramWithRoutePath(
            self: *Self,
            route: endpoint.RouteResult,
            record: *Record,
            path: root.endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            options: root.EndpointFeedInstalledKeyDatagramOptions,
        ) root.EndpointProtectedDatagramError!InstalledKeyDatagramRoutePollResult {
            const connection = connection_of(record);
            const destination_connection_id = destination_connection_id_of(record);
            const route_path = try self.lifecycle.currentRoutePath(route.destination_connection_id.asSlice());
            if (datagram.len != 0 and quic_packet.parseHeaderForm(datagram[0]) == .short) {
                if (connection.processStatelessResetDatagram(now_millis, datagram)) |sequence_number| {
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
                now_millis,
                datagram,
                options,
            ) catch |err| {
                if (err != error.InvalidPacket) return err;
                const close_datagram = if (connection.connectionState() == .closing) try self.lifecycle.pollDatagram(
                    route.connection_id,
                    connection,
                    now_millis,
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
                now_millis,
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
            path: root.endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            options: root.EndpointFeedInstalledKeyDatagramOptions,
        ) root.EndpointProtectedDatagramError!InstalledKeyDatagramRoutePollResult {
            const connection = connection_of(record);
            const destination_connection_id = destination_connection_id_of(record);
            const route_path = try self.lifecycle.currentRoutePath(route.destination_connection_id.asSlice());
            if (datagram.len != 0 and quic_packet.parseHeaderForm(datagram[0]) == .short) {
                if (connection.processStatelessResetDatagram(now_millis, datagram)) |sequence_number| {
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
                now_millis,
                datagram,
                options,
            ) catch |err| {
                if (err != error.InvalidPacket) return err;
                const close_datagram = if (connection.connectionState() == .closing) try self.lifecycle.pollDatagram(
                    route.connection_id,
                    connection,
                    now_millis,
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
                now_millis,
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
            path: root.endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            options: root.EndpointFeedInstalledKeyDatagramOptions,
            out: []DatagramPathResult,
        ) (root.EndpointProtectedDatagramError || endpoint.RouteError)!InstalledKeyDatagramRouteDrainResult {
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
                now_millis,
                datagram,
                options,
                out,
            );
        }

        fn processRoutedInstalledKeyDatagramAndDrainWithRoutePath(
            self: *Self,
            route: endpoint.RouteResult,
            record: *Record,
            path: root.endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            options: root.EndpointFeedInstalledKeyDatagramOptions,
            out: []DatagramPathResult,
        ) (root.EndpointProtectedDatagramError || endpoint.RouteError)!InstalledKeyDatagramRouteDrainResult {
            const connection = connection_of(record);
            const destination_connection_id = destination_connection_id_of(record);
            const route_path = try self.lifecycle.currentRoutePath(route.destination_connection_id.asSlice());
            if (datagram.len != 0 and quic_packet.parseHeaderForm(datagram[0]) == .short) {
                if (connection.processStatelessResetDatagram(now_millis, datagram)) |sequence_number| {
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
                now_millis,
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
                            now_millis,
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
                now_millis,
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
            path: root.endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            options: root.EndpointFeedInstalledKeyDatagramOptions,
            out: []DatagramPathResult,
        ) (root.EndpointProtectedDatagramError || endpoint.RouteError)!InstalledKeyDatagramRouteDrainResult {
            const connection = connection_of(record);
            const destination_connection_id = destination_connection_id_of(record);
            const route_path = try self.lifecycle.currentRoutePath(route.destination_connection_id.asSlice());
            if (datagram.len != 0 and quic_packet.parseHeaderForm(datagram[0]) == .short) {
                if (connection.processStatelessResetDatagram(now_millis, datagram)) |sequence_number| {
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
                now_millis,
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
                            now_millis,
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
                now_millis,
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
            now_millis: i64,
        ) (root.Error || error{UnknownConnectionId})!?[]u8 {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            return self.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                connection_id,
                connection_of(record),
                now_millis,
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
            now_millis: i64,
        ) (root.Error || endpoint.RouteError)!?OneRttDatagramPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.lifecycle.currentRoutePath(source_connection_id_of(record));
            const datagram = (try self.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                connection_id,
                connection_of(record),
                now_millis,
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
            now_millis: i64,
            space: root.EndpointInstalledKeyDatagramSpace,
        ) (root.Error || endpoint.RouteError)!?DatagramPathResult {
            _ = try self.records.removeClosedRecords(&self.lifecycle);
            if (self.records.poll_view_scratch) |views| {
                return self.pollDatagramAcrossRecordViewsWithRoutePath(
                    try self.records.fillPollViews(views, destination_connection_id_of, source_connection_id_of),
                    now_millis,
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
                now_millis,
                space,
            );
        }

        /// Poll the first installed-key datagram using registry-owned poll scratch.
        pub fn pollDatagramWithRoutePathWithScratch(
            self: *Self,
            now_millis: i64,
            space: root.EndpointInstalledKeyDatagramSpace,
        ) (root.Error || endpoint.RouteError)!?DatagramPathResult {
            _ = try self.records.removeClosedRecords(&self.lifecycle);
            const views = self.records.poll_view_scratch orelse return error.BufferTooSmall;
            return self.pollDatagramAcrossRecordViewsWithRoutePath(
                try self.records.fillPollViews(views, destination_connection_id_of, source_connection_id_of),
                now_millis,
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
            now_millis: i64,
            space: root.EndpointInstalledKeyDatagramSpace,
            out: []DatagramPathResult,
        ) DatagramPathDrainResult {
            var result = DatagramPathDrainResult{};
            while (result.datagrams_written < out.len) {
                const datagram = self.pollDatagramWithRoutePath(
                    allocator,
                    now_millis,
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
            now_millis: i64,
            space: root.EndpointInstalledKeyDatagramSpace,
            out: []DatagramPathResult,
        ) DatagramPathDrainResult {
            var result = DatagramPathDrainResult{};
            while (result.datagrams_written < out.len) {
                const datagram = self.pollDatagramWithRoutePathWithScratch(
                    now_millis,
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
            now_millis: i64,
            space: root.EndpointInstalledKeyDatagramSpace,
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
                    now_millis,
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
            now_millis: i64,
        ) (root.Error || endpoint.RouteError)!?OneRttDatagramPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            try connection_of(record).sendOnStream(stream_id, data, fin);
            const datagram = (try self.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                connection_id,
                connection_of(record),
                now_millis,
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
            now_millis: i64,
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
                now_millis,
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
            now_millis: i64,
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
                now_millis,
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
            now_millis: i64,
        ) (root.Error || endpoint.RouteError)!?OneRttDatagramPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            try connection_of(record).resetStream(stream_id, application_error_code);
            const datagram = (try self.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                connection_id,
                connection_of(record),
                now_millis,
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
            now_millis: i64,
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
                now_millis,
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
            now_millis: i64,
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
                now_millis,
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
            now_millis: i64,
        ) (root.Error || endpoint.RouteError)!?OneRttDatagramPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            try connection_of(record).stopSending(stream_id, application_error_code);
            const datagram = (try self.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                connection_id,
                connection_of(record),
                now_millis,
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
            now_millis: i64,
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
                now_millis,
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
            now_millis: i64,
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
                now_millis,
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
            now_millis: i64,
        ) (root.Error || endpoint.RouteError)!?OneRttDatagramPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            try connection_of(record).closeConnection(error_code, frame_type, reason_phrase);
            const datagram = (try self.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                connection_id,
                connection_of(record),
                now_millis,
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
            now_millis: i64,
        ) (root.Error || endpoint.RouteError)!?OneRttDatagramPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            try connection_of(record).closeApplication(error_code, reason_phrase);
            const datagram = (try self.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                connection_id,
                connection_of(record),
                now_millis,
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
            now_millis: i64,
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
                now_millis,
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
            now_millis: i64,
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
                now_millis,
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
            now_millis: i64,
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
                now_millis,
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
            now_millis: i64,
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
                now_millis,
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
        pub fn closeDeadlineMillis(
            self: *Self,
            connection_id: u64,
        ) error{UnknownConnectionId}!?i64 {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            return connection_of(record).closeDeadlineMillis();
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
            path: endpoint.Udp4Tuple,
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
            now_millis: i64,
            initial_accept: endpoint.InitialAcceptResult,
            server_source_connection_id: []const u8,
            datagram: []const u8,
            options: endpoint.AcceptedInitialRouteOptions,
            backend: root.CryptoBackend,
            scratch: []u8,
            out: []root.EndpointPolledDatagramResult,
        ) root.EndpointProtectedInitialError!root.EndpointAcceptedInitialCryptoBackendDatagramDrainResult {
            return self.lifecycle.processAcceptedProtectedInitialWithCryptoBackendAndDrainDatagrams(
                connection_id,
                connection,
                now_millis,
                initial_accept,
                server_source_connection_id,
                datagram,
                options,
                backend,
                scratch,
                out,
            );
        }

        /// Accept an Initial and transfer its record into endpoint ownership.
        ///
        /// Route installation, Initial-space TLS driving, bounded Initial
        /// output, record admission, and the first Handshake-space TLS drive
        /// succeed together. The caller retains `record` on failure; any route
        /// or timer installed before that failure is retired.
        pub const InitialRecordAdmissionResult = struct {
            /// Initial-space processing and bounded output drain.
            initial: root.EndpointAcceptedInitialCryptoBackendDatagramDrainResult,
            /// Handshake-space output after Initial processing installed keys.
            handshake: ?root.EndpointCryptoBackendDriveDatagramDrainResult = null,
        };

        pub fn acceptInitialRecord(
            self: *Self,
            connection_id: u64,
            record: *Record,
            now_millis: i64,
            initial_accept: endpoint.InitialAcceptResult,
            server_source_connection_id: []const u8,
            datagram: []const u8,
            options: endpoint.AcceptedInitialRouteOptions,
            scratch: []u8,
            initial_out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
        ) (root.EndpointProtectedInitialError || root.Error || error{ConnectionLimitReached})!InitialRecordAdmissionResult {
            _ = try self.records.removeClosedRecords(&self.lifecycle);
            if (self.records.get(connection_id) != null) return error.DuplicateConnectionId;
            if (!self.records.hasCapacity()) return error.ConnectionLimitReached;

            const accepted = self.acceptInitial(
                connection_id,
                connection_of(record),
                now_millis,
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
            var record_adopted = false;
            errdefer {
                if (!record_adopted) _ = self.lifecycle.retireConnection(connection_id);
            }

            try self.records.adopt(connection_id, record);
            record_adopted = true;
            if (accepted.drain.first_error != null or !accepted.backend.handshake_keys_installed) {
                return .{ .initial = accepted };
            }
            const handshake = self.driveBackend(
                connection_id,
                .handshake,
                scratch,
                now_millis,
                handshake_out,
            ) catch |err| {
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
            now_millis: i64,
            initial_accept: endpoint.InitialAcceptResult,
            server_source_connection_id: []const u8,
            datagram: []const u8,
            options: endpoint.AcceptedInitialRouteOptions,
            scratch: []u8,
            initial_out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
        ) (root.EndpointProtectedInitialError || root.Error || error{ConnectionLimitReached})!InitialRecordAdmissionPathResult {
            const admitted = try self.acceptInitialRecord(
                connection_id,
                record,
                now_millis,
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
            now_millis: i64,
            initial_accept: endpoint.InitialAcceptResult,
            server_source_connection_id: []const u8,
            datagram: []const u8,
            options: endpoint.AcceptedInitialRouteOptions,
            scratch: []u8,
            initial_out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
        ) (root.EndpointProtectedInitialError || root.Error)!InitialRecordAdmissionAttemptPathResult {
            const admitted = self.acceptInitialRecordWithRoutePath(
                connection_id,
                record,
                now_millis,
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
            space: root.EndpointInstalledKeyDatagramSpace,
            scratch: []u8,
            now_millis: i64,
            out: []root.EndpointPolledDatagramResult,
        ) (root.Error || error{UnknownConnectionId})!root.EndpointCryptoBackendDriveDatagramDrainResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            return self.lifecycle.driveCryptoBackendInSpaceAndDrainDatagrams(
                connection_id,
                connection_of(record),
                packetNumberSpace(space),
                crypto_backend_of(record),
                scratch,
                now_millis,
                .{
                    .space = space,
                    .destination_connection_id = destination_connection_id_of(record),
                    .source_connection_id = source_connection_id_of(record),
                },
                out,
            );
        }

        /// Drive one TLS space and return the output drain with its UDP route.
        pub fn driveBackendWithRoutePath(
            self: *Self,
            connection_id: u64,
            space: root.EndpointInstalledKeyDatagramSpace,
            scratch: []u8,
            now_millis: i64,
            out: []root.EndpointPolledDatagramResult,
        ) (root.Error || endpoint.RouteError)!CryptoBackendDatagramDrainPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            return .{
                .backend = try self.driveBackend(connection_id, space, scratch, now_millis, out),
                .path = path,
            };
        }

        /// Drive the TLS Initial space and drain bounded protected Initial output.
        pub fn driveInitialBackend(
            self: *Self,
            connection_id: u64,
            scratch: []u8,
            now_millis: i64,
            initial_token: []const u8,
            version: quic_packet.Version,
            out: []root.EndpointPolledDatagramResult,
        ) (root.Error || error{UnknownConnectionId})!root.EndpointCryptoBackendDriveProtectedLongDatagramDrainResult {
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
                now_millis,
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
            now_millis: i64,
            initial_token: []const u8,
            version: quic_packet.Version,
            out: []root.EndpointPolledDatagramResult,
        ) (root.Error || endpoint.RouteError)!ProtectedLongBackendDatagramDrainPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const path = try self.currentRecordRoutePath(record);
            return .{
                .backend = try self.driveInitialBackend(
                    connection_id,
                    scratch,
                    now_millis,
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
            policy: *endpoint.AddressValidationPolicy,
            connection_id: u64,
            now_millis: i64,
            path: endpoint.Udp4Tuple,
            datagram: []const u8,
            supported_versions: []const quic_packet.Version,
        ) (root.EndpointRetryProtectedInitialError || error{UnknownConnectionId})!root.EndpointRetryProtectedInitialResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const result = try self.lifecycle.processRetryValidatedProtectedInitialDatagram(
                policy,
                connection_id,
                connection_of(record),
                now_millis,
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
            policy: *endpoint.AddressValidationPolicy,
            connection_id: u64,
            now_millis: i64,
            path: endpoint.Udp4Tuple,
            datagram: []const u8,
            supported_versions: []const quic_packet.Version,
            scratch: []u8,
            initial_out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
        ) (root.EndpointRetryProtectedInitialError || root.Error || endpoint.RouteError)!RetryInitialProcessPathResult {
            const info = protection.peekProtectedLongPacketInfo(datagram) catch return error.InvalidPacket;
            if (info.packet_type != .initial) return error.InvalidPacket;
            _ = try self.lifecycle.currentRoutePath(info.dcid);
            const retry = try self.validateRetryInitial(
                policy,
                connection_id,
                now_millis,
                path,
                datagram,
                supported_versions,
            );
            const initial = try self.driveInitialBackendWithRoutePath(
                connection_id,
                scratch,
                now_millis,
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
                    now_millis,
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
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            scratch: []u8,
            out: []root.EndpointPolledDatagramResult,
        ) (root.EndpointProtectedInitialError || root.Error || error{UnknownConnectionId})!root.EndpointRoutedCryptoBackendDriveDatagramDrainResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const route = try self.lifecycle.processRoutedProtectedLongDatagramWithInstalledHandshakeKeys(
                connection_id,
                connection_of(record),
                path,
                now_millis,
                initial_destination_connection_id_of(record),
                datagram,
            );
            return .{
                .route = route,
                .backend = try self.driveBackend(connection_id, .handshake, scratch, now_millis, out),
            };
        }

        /// Process a routed Initial and return Handshake output with its route.
        pub fn processInitialWithHandshakeKeysWithRoutePath(
            self: *Self,
            connection_id: u64,
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            scratch: []u8,
            out: []root.EndpointPolledDatagramResult,
        ) (root.EndpointProtectedInitialError || root.Error || endpoint.RouteError)!RoutedBackendDatagramDrainPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const output_path = try self.currentRecordRoutePath(record);
            const processed = try self.processInitialWithHandshakeKeys(
                connection_id,
                path,
                now_millis,
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
            initial: root.EndpointRoutedCryptoBackendDriveProtectedLongDatagramDrainResult,
            /// Handshake-space backend drive after Initial processing installed keys.
            handshake: ?root.EndpointCryptoBackendDriveDatagramDrainResult = null,
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
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            scratch: []u8,
            initial_token: []const u8,
            initial_out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
        ) (root.EndpointProtectedDatagramError || root.Error || error{UnknownConnectionId})!InitialProcessResult {
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
                now_millis,
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
                .handshake = try self.driveBackend(connection_id, .handshake, scratch, now_millis, handshake_out),
            };
        }

        /// Process a routed Initial and return all output drains with routes.
        pub fn processInitialWithRoutePath(
            self: *Self,
            connection_id: u64,
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            scratch: []u8,
            initial_token: []const u8,
            initial_out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
        ) (root.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!InitialProcessPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const output_path = try self.currentRecordRoutePath(record);
            const processed = try self.processInitial(
                connection_id,
                path,
                now_millis,
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
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            scratch: []u8,
            out: []root.EndpointPolledDatagramResult,
        ) (root.EndpointProtectedDatagramError || error{UnknownConnectionId})!root.EndpointRoutedCryptoBackendDriveDatagramDrainResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            return self.lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendAndDrainDatagrams(
                connection_id,
                connection_of(record),
                path,
                now_millis,
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
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            scratch: []u8,
            out: []root.EndpointPolledDatagramResult,
        ) (root.EndpointProtectedDatagramError || endpoint.RouteError)!RoutedBackendDatagramDrainPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const output_path = try self.currentRecordRoutePath(record);
            const processed = try self.processHandshake(
                connection_id,
                path,
                now_millis,
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
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            scratch: []u8,
            initial_token: []const u8,
            out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
        ) (root.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!LongPacketProcessPathResult {
            const info = protection.peekProtectedLongPacketInfo(datagram) catch return error.InvalidPacket;
            return switch (info.packet_type) {
                .initial => .{ .initial = try self.processInitialWithRoutePath(
                    connection_id,
                    path,
                    now_millis,
                    datagram,
                    scratch,
                    initial_token,
                    out,
                    handshake_out,
                ) },
                .handshake => .{ .handshake = try self.processHandshakeWithRoutePath(
                    connection_id,
                    path,
                    now_millis,
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
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            scratch: []u8,
            initial_token: []const u8,
            out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
        ) (root.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!LongDatagramProcessPathResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            const info = protection.peekProtectedLongPacketInfo(datagram) catch return error.InvalidPacket;
            if (info.len < datagram.len) {
                if (info.packet_type != .initial) return error.InvalidPacket;
                if (!connection_of(record).hasHandshakeProtectionKeys()) return error.InvalidPacket;
                return .{ .coalesced_initial_handshake = try self.processInitialWithHandshakeKeysWithRoutePath(
                    connection_id,
                    path,
                    now_millis,
                    datagram,
                    scratch,
                    handshake_out,
                ) };
            }
            return .{ .packet = try self.processLongPacketWithRoutePath(
                connection_id,
                path,
                now_millis,
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
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            installed_key_options: root.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
        ) (root.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!RoutedDatagramProcessPathResult {
            if (datagram.len == 0) return error.InvalidPacket;
            if ((datagram[0] & 0x40) == 0) return error.InvalidPacket;
            return switch (quic_packet.parseHeaderForm(datagram[0])) {
                .long => .{ .long = try self.processLongDatagramWithRoutePath(
                    route.connection_id,
                    path,
                    now_millis,
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
                        now_millis,
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
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            installed_key_options: root.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
        ) (root.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!RoutedDatagramProcessPathResult {
            if (datagram.len == 0) return error.InvalidPacket;
            if ((datagram[0] & 0x40) == 0) return error.InvalidPacket;
            return switch (quic_packet.parseHeaderForm(datagram[0])) {
                .long => .{ .long = try self.processLongDatagramWithRoutePath(
                    route.connection_id,
                    path,
                    now_millis,
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
                        now_millis,
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
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            installed_key_options: root.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
            installed_key_out: []DatagramPathResult,
        ) (root.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!RoutedDatagramDrainPathResult {
            if (datagram.len == 0) return error.InvalidPacket;
            if ((datagram[0] & 0x40) == 0) return error.InvalidPacket;
            return switch (quic_packet.parseHeaderForm(datagram[0])) {
                .long => .{ .long = try self.processLongDatagramWithRoutePath(
                    route.connection_id,
                    path,
                    now_millis,
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
                        now_millis,
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
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            installed_key_options: root.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
            installed_key_out: []DatagramPathResult,
        ) (root.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!RoutedDatagramDrainPathResult {
            if (datagram.len == 0) return error.InvalidPacket;
            if ((datagram[0] & 0x40) == 0) return error.InvalidPacket;
            return switch (quic_packet.parseHeaderForm(datagram[0])) {
                .long => .{ .long = try self.processLongDatagramWithRoutePath(
                    route.connection_id,
                    path,
                    now_millis,
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
                        now_millis,
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
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
            installed_key_options: root.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
        ) (root.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!DatagramProcessPathResult {
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
                    now_millis,
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
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
            installed_key_options: root.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
        ) (root.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!DatagramProcessPathResult {
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
                    now_millis,
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
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
            installed_key_options: root.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
            installed_key_out: []DatagramPathResult,
        ) (root.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!DatagramProcessDrainPathResult {
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
                    now_millis,
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
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
            installed_key_options: root.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
            installed_key_out: []DatagramPathResult,
        ) (root.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!DatagramProcessDrainPathResult {
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
                    now_millis,
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
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
            installed_key_options: root.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
            installed_key_out: []DatagramPathResult,
            pending_space: root.EndpointInstalledKeyDatagramSpace,
            pending_out: []DatagramPathResult,
        ) (root.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!DatagramStepPathResult {
            const process = try self.processDatagramAndDrainWithRoutePath(
                path,
                now_millis,
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
                now_millis,
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
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
            installed_key_options: root.EndpointFeedInstalledKeyDatagramOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
            installed_key_out: []DatagramPathResult,
            pending_space: root.EndpointInstalledKeyDatagramSpace,
            pending_out: []DatagramPathResult,
        ) (root.EndpointProtectedDatagramError || root.Error || endpoint.RouteError)!DatagramStepPathResult {
            try self.ensureReceiveStepScratch();
            const process = try self.processDatagramAndDrainWithRoutePathWithScratch(
                path,
                now_millis,
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
                now_millis,
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
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
            installed_key_options: root.EndpointFeedInstalledKeyDatagramOptions,
            connection_id: u64,
            record: *Record,
            server_source_connection_id: []const u8,
            options: endpoint.AcceptedInitialRouteOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
            installed_key_out: []DatagramPathResult,
            pending_space: root.EndpointInstalledKeyDatagramSpace,
            pending_out: []DatagramPathResult,
        ) (root.EndpointProtectedDatagramError || root.EndpointProtectedInitialError || root.Error || endpoint.RouteError)!InitialAdmissionDatagramStepPathResult {
            try self.ensureReceiveStepScratch();
            const process = try self.processDatagramAndDrainWithRoutePathWithScratch(
                path,
                now_millis,
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
                        now_millis,
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
                now_millis,
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
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            unpredictable_prefix: []const u8,
            supported_versions: []const quic_packet.Version,
            installed_key_options: root.EndpointFeedInstalledKeyDatagramOptions,
            connection_id: u64,
            record: *Record,
            server_source_connection_id: []const u8,
            options: endpoint.AcceptedInitialRouteOptions,
            scratch: []u8,
            initial_token: []const u8,
            out: []root.EndpointPolledDatagramResult,
            handshake_out: []root.EndpointPolledDatagramResult,
            installed_key_out: []DatagramPathResult,
            pending_space: root.EndpointInstalledKeyDatagramSpace,
            pending_out: []DatagramPathResult,
        ) (root.EndpointProtectedDatagramError || root.EndpointProtectedInitialError || root.Error || endpoint.RouteError)!InitialAdmissionDatagramStepPathResult {
            const process = try self.processDatagramAndDrainWithRoutePath(
                path,
                now_millis,
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
                        now_millis,
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
                now_millis,
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
            now_millis: i64,
            pending_space: root.EndpointInstalledKeyDatagramSpace,
            pending_out: []DatagramPathResult,
        ) root.Error!PendingStepPathResult {
            self.preflightDueRecoveryRoutes(now_millis) catch |err| {
                const route_error = classifyRoutePreflightError(err) orelse return @errorCast(err);
                return .{
                    .pending_work = .{},
                    .pending_drain = .{ .first_route_error = route_error },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                };
            };
            if (pending_out.len == 0 and self.hasDueRecoveryForInstalledKeySpace(now_millis, pending_space)) {
                return .{
                    .pending_work = .{},
                    .pending_drain = .{ .first_error = error.BufferTooSmall },
                    .next_deadline = try self.nextDeadlineWithScratch(),
                };
            }
            const pending_work = try self.records.processPendingWorkWithScratch(
                &self.lifecycle,
                now_millis,
            );
            const pending_drain = if (pending_work.recovery_serviced_count == 0)
                DatagramPathDrainResult{}
            else
                self.drainDatagramsAcrossRecordsWithRoutePathWithScratch(
                    now_millis,
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
            now_millis: i64,
            pending_space: root.EndpointInstalledKeyDatagramSpace,
            pending_out: []DatagramPathResult,
        ) (root.Error || endpoint.RouteError)!PendingStepPathResult {
            self.preflightDueRecoveryRoutes(now_millis) catch |err| {
                const route_error = classifyRoutePreflightError(err) orelse return @errorCast(err);
                return .{
                    .pending_work = .{},
                    .pending_drain = .{ .first_route_error = route_error },
                    .next_deadline = try self.nextDeadline(allocator),
                };
            };
            if (pending_out.len == 0 and self.hasDueRecoveryForInstalledKeySpace(now_millis, pending_space)) {
                return .{
                    .pending_work = .{},
                    .pending_drain = .{ .first_error = error.BufferTooSmall },
                    .next_deadline = try self.nextDeadline(allocator),
                };
            }
            const pending_work = try self.records.processPendingWork(
                &self.lifecycle,
                allocator,
                now_millis,
            );
            const pending_drain = if (pending_work.recovery_serviced_count == 0)
                DatagramPathDrainResult{}
            else
                self.drainDatagramsAcrossRecordsWithRoutePath(
                    allocator,
                    now_millis,
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

test "Tls13ServerEndpoint owns bounded records with lifecycle state" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,
        retry_validated: bool = false,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn initialDestinationConnectionId(self: *const @This()) []const u8 {
            return if (self.retry_validated) "retry" else "initial";
        }

        fn markRetryValidated(self: *@This()) void {
            self.retry_validated = true;
        }

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const RejectingInitialBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {
            return error.InvalidPacket;
        }

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const RejectingHandshakeBackend = struct {
        secrets: root.HandshakeTrafficSecrets,
        secrets_sent: bool = false,

        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
                .pull_handshake_traffic_secrets = pullHandshakeTrafficSecrets,
            };
        }

        fn receive(_: *anyopaque, space: root.PacketNumberSpace, _: []const u8) root.Error!void {
            if (space == .handshake) return error.InvalidPacket;
        }

        fn pull(_: *anyopaque, space: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            if (space == .handshake) return error.InvalidPacket;
            return null;
        }

        fn pullHandshakeTrafficSecrets(context: *anyopaque) root.Error!?root.HandshakeTrafficSecrets {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.secrets_sent) return null;
            self.secrets_sent = true;
            return self.secrets;
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 2, .{
        .max_routes = 3,
        .max_stateless_reset_tokens = 3,
    });
    defer endpoint_owner.deinit();
    try std.testing.expect(endpoint_owner.records.hasCapacity());
    try std.testing.expect(endpoint_owner.hasConnectionCapacity());
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.activeConnectionCount());
    try std.testing.expectEqual(@as(usize, 2), endpoint_owner.activeConnectionLimit());
    var active_ids: [2]u64 = undefined;
    try std.testing.expectEqual(@as(usize, 0), (try endpoint_owner.activeConnectionIds(&active_ids)).len);
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.routeCount());
    try std.testing.expect(endpoint_owner.lifecycle.router.routes.capacity >= 3);
    try std.testing.expect(endpoint_owner.lifecycle.router.reset_tokens.capacity >= 3);
    try std.testing.expect(endpoint_owner.lifecycle.recovery_timers.entries.capacity >= 2);
    var empty_backend = EmptyBackend{};

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 7,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    const secrets = try protection.deriveInitialSecrets(.v1, "endpoint");
    try record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    const record_handle = record.handle;
    try endpoint_owner.records.adopt(record_handle, record);
    record_owned = false;
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.closeWithRoutePath(record_handle, 0, 0, "missing route", 1));
    try std.testing.expectEqual(connection_module.ConnectionState.active, record.connection.connectionState());
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.closeApplicationWithRoutePath(record_handle, 0, "missing route", 1));
    try std.testing.expectEqual(connection_module.ConnectionState.active, record.connection.connectionState());
    var missing_route_close_out: [1]TestEndpoint.DatagramPathResult = undefined;
    try std.testing.expectError(
        error.UnknownConnectionId,
        endpoint_owner.closeWithRoutePathAndDrainDatagrams(
            std.testing.allocator,
            record_handle,
            0,
            0,
            "missing route",
            1,
            &missing_route_close_out,
        ),
    );
    try std.testing.expectEqual(connection_module.ConnectionState.active, record.connection.connectionState());
    try std.testing.expectError(
        error.UnknownConnectionId,
        endpoint_owner.closeApplicationWithRoutePathAndDrainDatagrams(
            std.testing.allocator,
            record_handle,
            0,
            "missing route",
            1,
            &missing_route_close_out,
        ),
    );
    try std.testing.expectEqual(connection_module.ConnectionState.active, record.connection.connectionState());
    try std.testing.expectError(
        error.UnknownConnectionId,
        endpoint_owner.closeApplicationWithRoutePathAndDrainDatagramsWithScratch(
            record_handle,
            0,
            "missing route",
            1,
            &missing_route_close_out,
        ),
    );
    try std.testing.expectEqual(connection_module.ConnectionState.active, record.connection.connectionState());
    const server_unidirectional_stream = try endpoint_owner.openUniStream(record_handle);
    try std.testing.expectEqual(@as(u64, 3), server_unidirectional_stream);
    const server_bidirectional_stream = try endpoint_owner.openStream(record_handle);
    try std.testing.expectEqual(@as(u64, 1), server_bidirectional_stream);
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.sendStreamWithRoutePath(record_handle, server_bidirectional_stream, "missing route", false, 1));
    try std.testing.expectEqual(@as(usize, 0), record.connection.send_queue.items.len);
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.resetStreamWithRoutePath(record_handle, server_unidirectional_stream, 41, 1));
    try std.testing.expectEqual(@as(usize, 0), record.connection.pending_reset_streams.items.len);
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.stopSendingWithRoutePath(record_handle, server_bidirectional_stream, 42, 1));
    try std.testing.expectEqual(@as(usize, 0), record.connection.pending_stop_sending.items.len);
    var missing_route_control_out: [1]TestEndpoint.DatagramPathResult = undefined;
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.sendStreamWithRoutePathAndDrainDatagrams(
        std.testing.allocator,
        record_handle,
        server_bidirectional_stream,
        "missing route",
        false,
        1,
        &missing_route_control_out,
    ));
    try std.testing.expectEqual(@as(usize, 0), record.connection.send_queue.items.len);
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.resetStreamWithRoutePathAndDrainDatagrams(
        std.testing.allocator,
        record_handle,
        server_unidirectional_stream,
        41,
        1,
        &missing_route_control_out,
    ));
    try std.testing.expectEqual(@as(usize, 0), record.connection.pending_reset_streams.items.len);
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.stopSendingWithRoutePathAndDrainDatagrams(
        std.testing.allocator,
        record_handle,
        server_bidirectional_stream,
        42,
        1,
        &missing_route_control_out,
    ));
    try std.testing.expectEqual(@as(usize, 0), record.connection.pending_stop_sending.items.len);
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.sendStreamWithRoutePathAndDrainDatagramsWithScratch(
        record_handle,
        server_bidirectional_stream,
        "missing route",
        false,
        1,
        &missing_route_control_out,
    ));
    try std.testing.expectEqual(@as(usize, 0), record.connection.send_queue.items.len);
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.resetStreamWithRoutePathAndDrainDatagramsWithScratch(
        record_handle,
        server_unidirectional_stream,
        41,
        1,
        &missing_route_control_out,
    ));
    try std.testing.expectEqual(@as(usize, 0), record.connection.pending_reset_streams.items.len);
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.stopSendingWithRoutePathAndDrainDatagramsWithScratch(
        record_handle,
        server_bidirectional_stream,
        42,
        1,
        &missing_route_control_out,
    ));
    try std.testing.expectEqual(@as(usize, 0), record.connection.pending_stop_sending.items.len);
    const record_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 5443),
    };
    try endpoint_owner.lifecycle.registerConnectionId(
        record_handle,
        TestRecord.sourceConnectionId(record),
        record_path,
        .{ .active_migration_disabled = false },
    );
    try std.testing.expect(endpoint_owner.records.hasCapacity());
    try std.testing.expect(endpoint_owner.hasConnectionCapacity());
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.activeConnectionCount());
    const single_active_ids = try endpoint_owner.activeConnectionIds(&active_ids);
    try std.testing.expectEqual(@as(usize, 1), single_active_ids.len);
    try std.testing.expectEqual(record_handle, single_active_ids[0]);
    var no_active_ids: [0]u64 = .{};
    try std.testing.expectError(error.BufferTooSmall, endpoint_owner.activeConnectionIds(&no_active_ids));

    var scratchless_endpoint = TestEndpoint.init(std.testing.allocator);
    defer scratchless_endpoint.deinit();
    const scratchless_record = try std.testing.allocator.create(TestRecord);
    var scratchless_record_initialized = false;
    var scratchless_record_owned = true;
    errdefer {
        if (scratchless_record_owned) {
            if (scratchless_record_initialized) scratchless_record.deinit();
            std.testing.allocator.destroy(scratchless_record);
        }
    }
    scratchless_record.* = .{
        .handle = 77,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    scratchless_record_initialized = true;
    try scratchless_record.connection.validatePeerAddress();
    try scratchless_record.connection.confirmHandshake();
    try scratchless_record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try scratchless_endpoint.lifecycle.registerConnectionId(
        scratchless_record.handle,
        TestRecord.sourceConnectionId(scratchless_record),
        record_path,
        .{},
    );
    errdefer _ = scratchless_endpoint.lifecycle.retireConnection(scratchless_record.handle);
    try scratchless_endpoint.records.adopt(scratchless_record.handle, scratchless_record);
    scratchless_record_owned = false;
    const scratchless_send_stream = try scratchless_endpoint.openStream(scratchless_record.handle);
    const scratchless_reset_stream = try scratchless_endpoint.openUniStream(scratchless_record.handle);
    const scratchless_stop_stream = try scratchless_endpoint.openStream(scratchless_record.handle);
    var scratchless_out: [1]TestEndpoint.DatagramPathResult = undefined;
    try std.testing.expectError(error.BufferTooSmall, scratchless_endpoint.sendStreamWithRoutePathAndDrainDatagramsWithScratch(
        scratchless_record.handle,
        scratchless_send_stream,
        "server scratch",
        false,
        1,
        &scratchless_out,
    ));
    try std.testing.expectEqual(@as(usize, 0), scratchless_record.connection.send_queue.items.len);
    try std.testing.expectError(error.BufferTooSmall, scratchless_endpoint.resetStreamWithRoutePathAndDrainDatagramsWithScratch(
        scratchless_record.handle,
        scratchless_reset_stream,
        61,
        1,
        &scratchless_out,
    ));
    try std.testing.expectEqual(@as(usize, 0), scratchless_record.connection.pending_reset_streams.items.len);
    try std.testing.expectError(error.BufferTooSmall, scratchless_endpoint.stopSendingWithRoutePathAndDrainDatagramsWithScratch(
        scratchless_record.handle,
        scratchless_stop_stream,
        62,
        1,
        &scratchless_out,
    ));
    try std.testing.expectEqual(@as(usize, 0), scratchless_record.connection.pending_stop_sending.items.len);

    const stream_datagram = (try endpoint_owner.sendStreamWithRoutePath(
        record_handle,
        server_bidirectional_stream,
        "server",
        false,
        1,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(stream_datagram.datagram);
    try std.testing.expect(stream_datagram.datagram.len != 0);
    try std.testing.expect(stream_datagram.path.eql(record_path));
    const reset_datagram = (try endpoint_owner.resetStreamWithRoutePath(
        record_handle,
        server_unidirectional_stream,
        41,
        2,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(reset_datagram.datagram);
    try std.testing.expect(reset_datagram.datagram.len != 0);
    try std.testing.expect(reset_datagram.path.eql(record_path));
    const stop_datagram = (try endpoint_owner.stopSendingWithRoutePath(
        record_handle,
        server_bidirectional_stream,
        42,
        3,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(stop_datagram.datagram);
    try std.testing.expect(stop_datagram.datagram.len != 0);
    try std.testing.expect(stop_datagram.path.eql(record_path));
    const drain_send_stream = try endpoint_owner.openStream(record_handle);
    const drain_reset_stream = try endpoint_owner.openUniStream(record_handle);
    const drain_stop_stream = try endpoint_owner.openStream(record_handle);
    var zero_control_out: [0]TestEndpoint.DatagramPathResult = .{};
    try std.testing.expectError(error.BufferTooSmall, endpoint_owner.sendStreamWithRoutePathAndDrainDatagrams(
        std.testing.allocator,
        record_handle,
        drain_send_stream,
        "server drain",
        false,
        4,
        &zero_control_out,
    ));
    try std.testing.expectEqual(@as(usize, 0), record.connection.send_queue.items.len);
    try std.testing.expectError(error.BufferTooSmall, endpoint_owner.resetStreamWithRoutePathAndDrainDatagrams(
        std.testing.allocator,
        record_handle,
        drain_reset_stream,
        51,
        4,
        &zero_control_out,
    ));
    try std.testing.expectEqual(@as(usize, 0), record.connection.pending_reset_streams.items.len);
    try std.testing.expectError(error.BufferTooSmall, endpoint_owner.stopSendingWithRoutePathAndDrainDatagrams(
        std.testing.allocator,
        record_handle,
        drain_stop_stream,
        52,
        4,
        &zero_control_out,
    ));
    try std.testing.expectEqual(@as(usize, 0), record.connection.pending_stop_sending.items.len);
    try std.testing.expectError(error.BufferTooSmall, endpoint_owner.sendStreamWithRoutePathAndDrainDatagramsWithScratch(
        record_handle,
        drain_send_stream,
        "server drain",
        false,
        4,
        &zero_control_out,
    ));
    try std.testing.expectEqual(@as(usize, 0), record.connection.send_queue.items.len);
    try std.testing.expectError(error.BufferTooSmall, endpoint_owner.resetStreamWithRoutePathAndDrainDatagramsWithScratch(
        record_handle,
        drain_reset_stream,
        51,
        4,
        &zero_control_out,
    ));
    try std.testing.expectEqual(@as(usize, 0), record.connection.pending_reset_streams.items.len);
    try std.testing.expectError(error.BufferTooSmall, endpoint_owner.stopSendingWithRoutePathAndDrainDatagramsWithScratch(
        record_handle,
        drain_stop_stream,
        52,
        4,
        &zero_control_out,
    ));
    try std.testing.expectEqual(@as(usize, 0), record.connection.pending_stop_sending.items.len);

    var control_out: [2]TestEndpoint.DatagramPathResult = undefined;
    const sent_drain = try endpoint_owner.sendStreamWithRoutePathAndDrainDatagrams(
        std.testing.allocator,
        record_handle,
        drain_send_stream,
        "server drain",
        false,
        4,
        &control_out,
    );
    try std.testing.expect(sent_drain.drain.datagrams_written >= 1);
    try std.testing.expectEqual(@as(?root.Error, null), sent_drain.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), sent_drain.drain.first_route_error);
    for (control_out[0..sent_drain.drain.datagrams_written]) |drained| {
        defer std.testing.allocator.free(drained.datagram);
        try std.testing.expectEqual(record_handle, drained.connection_id);
        try std.testing.expect(drained.path.eql(record_path));
        try std.testing.expect(drained.datagram.len != 0);
    }
    try std.testing.expect(sent_drain.next_deadline != null);

    const reset_drain = try endpoint_owner.resetStreamWithRoutePathAndDrainDatagrams(
        std.testing.allocator,
        record_handle,
        drain_reset_stream,
        51,
        5,
        &control_out,
    );
    try std.testing.expect(reset_drain.drain.datagrams_written >= 1);
    try std.testing.expectEqual(@as(?root.Error, null), reset_drain.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), reset_drain.drain.first_route_error);
    for (control_out[0..reset_drain.drain.datagrams_written]) |drained| {
        defer std.testing.allocator.free(drained.datagram);
        try std.testing.expectEqual(record_handle, drained.connection_id);
        try std.testing.expect(drained.path.eql(record_path));
        try std.testing.expect(drained.datagram.len != 0);
    }
    try std.testing.expect(reset_drain.next_deadline != null);

    const stop_drain = try endpoint_owner.stopSendingWithRoutePathAndDrainDatagrams(
        std.testing.allocator,
        record_handle,
        drain_stop_stream,
        52,
        6,
        &control_out,
    );
    try std.testing.expect(stop_drain.drain.datagrams_written >= 1);
    try std.testing.expectEqual(@as(?root.Error, null), stop_drain.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), stop_drain.drain.first_route_error);
    for (control_out[0..stop_drain.drain.datagrams_written]) |drained| {
        defer std.testing.allocator.free(drained.datagram);
        try std.testing.expectEqual(record_handle, drained.connection_id);
        try std.testing.expect(drained.path.eql(record_path));
        try std.testing.expect(drained.datagram.len != 0);
    }
    try std.testing.expect(stop_drain.next_deadline != null);
    const scratch_send_stream = try endpoint_owner.openStream(record_handle);
    const scratch_reset_stream = try endpoint_owner.openUniStream(record_handle);
    const scratch_stop_stream = try endpoint_owner.openStream(record_handle);

    var scratch_send_out: [2]TestEndpoint.DatagramPathResult = undefined;
    const scratch_sent_drain = try endpoint_owner.sendStreamWithRoutePathAndDrainDatagramsWithScratch(
        record_handle,
        scratch_send_stream,
        "server scratch",
        false,
        7,
        &scratch_send_out,
    );
    try std.testing.expect(scratch_sent_drain.drain.datagrams_written >= 1);
    try std.testing.expectEqual(@as(?root.Error, null), scratch_sent_drain.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), scratch_sent_drain.drain.first_route_error);
    for (scratch_send_out[0..scratch_sent_drain.drain.datagrams_written]) |drained| {
        defer std.testing.allocator.free(drained.datagram);
        try std.testing.expectEqual(record_handle, drained.connection_id);
        try std.testing.expect(drained.path.eql(record_path));
        try std.testing.expect(drained.datagram.len != 0);
    }
    try std.testing.expect(scratch_sent_drain.next_deadline != null);

    var scratch_reset_out: [2]TestEndpoint.DatagramPathResult = undefined;
    const scratch_reset_drain = try endpoint_owner.resetStreamWithRoutePathAndDrainDatagramsWithScratch(
        record_handle,
        scratch_reset_stream,
        61,
        8,
        &scratch_reset_out,
    );
    try std.testing.expect(scratch_reset_drain.drain.datagrams_written >= 1);
    try std.testing.expectEqual(@as(?root.Error, null), scratch_reset_drain.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), scratch_reset_drain.drain.first_route_error);
    for (scratch_reset_out[0..scratch_reset_drain.drain.datagrams_written]) |drained| {
        defer std.testing.allocator.free(drained.datagram);
        try std.testing.expectEqual(record_handle, drained.connection_id);
        try std.testing.expect(drained.path.eql(record_path));
        try std.testing.expect(drained.datagram.len != 0);
    }
    try std.testing.expect(scratch_reset_drain.next_deadline != null);

    var scratch_stop_out: [2]TestEndpoint.DatagramPathResult = undefined;
    const scratch_stop_drain = try endpoint_owner.stopSendingWithRoutePathAndDrainDatagramsWithScratch(
        record_handle,
        scratch_stop_stream,
        62,
        9,
        &scratch_stop_out,
    );
    try std.testing.expect(scratch_stop_drain.drain.datagrams_written >= 1);
    try std.testing.expectEqual(@as(?root.Error, null), scratch_stop_drain.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), scratch_stop_drain.drain.first_route_error);
    for (scratch_stop_out[0..scratch_stop_drain.drain.datagrams_written]) |drained| {
        defer std.testing.allocator.free(drained.datagram);
        try std.testing.expectEqual(record_handle, drained.connection_id);
        try std.testing.expect(drained.path.eql(record_path));
        try std.testing.expect(drained.datagram.len != 0);
    }
    try std.testing.expect(scratch_stop_drain.next_deadline != null);
    var stream_read_buffer: [8]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try endpoint_owner.recvStream(record_handle, server_bidirectional_stream, &stream_read_buffer));
    try std.testing.expect(!try endpoint_owner.streamFinished(record_handle, server_bidirectional_stream));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.openUniStream(99));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.sendStreamWithRoutePath(99, server_bidirectional_stream, "server", false, 1));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.resetStreamWithRoutePath(99, server_unidirectional_stream, 41, 2));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.stopSendingWithRoutePath(99, server_bidirectional_stream, 42, 3));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.sendStreamWithRoutePathAndDrainDatagrams(std.testing.allocator, 99, server_bidirectional_stream, "server", false, 1, &control_out));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.resetStreamWithRoutePathAndDrainDatagrams(std.testing.allocator, 99, server_unidirectional_stream, 41, 2, &control_out));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.stopSendingWithRoutePathAndDrainDatagrams(std.testing.allocator, 99, server_bidirectional_stream, 42, 3, &control_out));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.sendStreamWithRoutePathAndDrainDatagramsWithScratch(99, server_bidirectional_stream, "server", false, 1, &control_out));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.resetStreamWithRoutePathAndDrainDatagramsWithScratch(99, server_unidirectional_stream, 41, 2, &control_out));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.stopSendingWithRoutePathAndDrainDatagramsWithScratch(99, server_bidirectional_stream, 42, 3, &control_out));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.resetStream(99, server_unidirectional_stream, 41));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.stopSending(99, server_bidirectional_stream, 42));
    try record.connection.sendPing();
    const one_rtt = (try endpoint_owner.pollOneRttDatagram(record_handle, 1)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(one_rtt);
    try std.testing.expect(one_rtt.len != 0);
    _ = try endpoint_owner.retireRecord(record_handle);
    try std.testing.expect(endpoint_owner.records.hasCapacity());
    try std.testing.expect(endpoint_owner.hasConnectionCapacity());
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.activeConnectionCount());
    try std.testing.expectEqual(@as(usize, 0), (try endpoint_owner.activeConnectionIds(&active_ids)).len);
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.pollOneRttDatagram(record_handle, 2));

    const retry_record = try std.testing.allocator.create(TestRecord);
    var retry_record_initialized = false;
    var retry_record_owned = true;
    errdefer {
        if (retry_record_owned) {
            if (retry_record_initialized) retry_record.deinit();
            std.testing.allocator.destroy(retry_record);
        }
    }
    retry_record.* = .{
        .handle = 8,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    retry_record_initialized = true;
    const retry_record_handle = retry_record.handle;
    const retry_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 5443),
    };
    const original_dcid = [_]u8{ 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87 };
    const retry_scid = [_]u8{ 0x90, 0x91, 0x92, 0x93 };
    const retry_route = try endpoint_owner.adoptRetryRecordAndSwitchInitialRoute(
        retry_record.handle,
        retry_record,
        &original_dcid,
        &retry_scid,
        retry_path,
        .{ .active_migration_disabled = true },
    );
    retry_record_owned = false;
    try std.testing.expectEqual(retry_record.handle, retry_route.connection_id);
    try std.testing.expect(endpoint_owner.records.get(retry_record.handle) != null);
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.activeConnectionCount());
    const retry_active_ids = try endpoint_owner.activeConnectionIds(&active_ids);
    try std.testing.expectEqual(@as(usize, 1), retry_active_ids.len);
    try std.testing.expectEqual(retry_record.handle, retry_active_ids[0]);
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());
    const routed_short = [_]u8{ 0x40, 0x90, 0x91, 0x92, 0x93 };
    try std.testing.expectEqual(retry_record.handle, (try endpoint_owner.routeDatagram(retry_path, &routed_short)).connection_id);
    var classification_out: [32]u8 = undefined;
    const classified = try endpoint_owner.feedDatagram(
        &classification_out,
        retry_path,
        &routed_short,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
    );
    switch (classified) {
        .routed => |route| try std.testing.expectEqual(retry_record.handle, route.connection_id),
        else => return error.TestUnexpectedResult,
    }
    try retry_record.connection.validatePeerAddress();
    try retry_record.connection.confirmHandshake();
    try retry_record.connection.recordPeerAddressBytesReceived(1);
    _ = try retry_record.connection.recordPacketSentInSpace(.application, 10, 100);
    try endpoint_owner.lifecycle.armRecoveryTimerFromConnection(retry_record.handle, &retry_record.connection);
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.recoveryTimerCount());
    var backend_scratch: [1]u8 = undefined;
    var backend_output: [1]root.EndpointPolledDatagramResult = undefined;
    const backend_progress = try endpoint_owner.driveBackend(
        retry_record.handle,
        .handshake,
        &backend_scratch,
        1,
        &backend_output,
    );
    try std.testing.expectEqual(@as(usize, 0), backend_progress.backend.progress.outbound_chunks);
    try std.testing.expectError(
        error.UnknownConnectionId,
        endpoint_owner.driveBackend(
            99,
            .handshake,
            &backend_scratch,
            1,
            &backend_output,
        ),
    );
    const initial_backend_progress = try endpoint_owner.driveInitialBackend(
        retry_record.handle,
        &backend_scratch,
        1,
        &[_]u8{},
        .v1,
        &backend_output,
    );
    try std.testing.expectEqual(@as(usize, 0), initial_backend_progress.backend.outbound_chunks);
    try std.testing.expectError(
        error.UnknownConnectionId,
        endpoint_owner.driveInitialBackend(
            99,
            &backend_scratch,
            1,
            &[_]u8{},
            .v1,
            &backend_output,
        ),
    );
    const validation_secret: address_validation_token.Secret = [_]u8{0x55} ** address_validation_token.secret_len;
    var validation_policy = endpoint.AddressValidationPolicy.init(std.testing.allocator, validation_secret, .{});
    defer validation_policy.deinit();
    try std.testing.expectError(
        error.UnknownConnectionId,
        endpoint_owner.validateRetryInitial(
            &validation_policy,
            99,
            1,
            retry_path,
            &[_]u8{},
            &[_]quic_packet.Version{.v1},
        ),
    );
    try std.testing.expectError(
        error.UnknownConnectionId,
        endpoint_owner.processInitialWithHandshakeKeys(
            99,
            retry_path,
            1,
            &[_]u8{},
            &backend_scratch,
            &backend_output,
        ),
    );
    try std.testing.expectError(
        error.UnknownConnectionId,
        endpoint_owner.processInitial(
            99,
            retry_path,
            1,
            &[_]u8{},
            &backend_scratch,
            &[_]u8{},
            &backend_output,
            &backend_output,
        ),
    );
    try std.testing.expectError(
        error.UnknownConnectionId,
        endpoint_owner.processHandshake(
            99,
            retry_path,
            1,
            &[_]u8{},
            &backend_scratch,
            &backend_output,
        ),
    );

    const duplicate_record = try std.testing.allocator.create(TestRecord);
    var duplicate_record_initialized = false;
    var duplicate_record_owned = true;
    errdefer {
        if (duplicate_record_owned) {
            if (duplicate_record_initialized) duplicate_record.deinit();
            std.testing.allocator.destroy(duplicate_record);
        }
    }
    duplicate_record.* = .{
        .handle = retry_record.handle,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    duplicate_record_initialized = true;
    try std.testing.expectError(
        error.DuplicateConnectionId,
        endpoint_owner.adoptRetryRecordAndSwitchInitialRoute(
            duplicate_record.handle,
            duplicate_record,
            &original_dcid,
            &retry_scid,
            retry_path,
            .{ .active_migration_disabled = true },
        ),
    );
    duplicate_record_owned = false;
    duplicate_record.deinit();
    std.testing.allocator.destroy(duplicate_record);

    const rollback_record = try std.testing.allocator.create(TestRecord);
    var rollback_record_initialized = false;
    var rollback_record_owned = true;
    errdefer {
        if (rollback_record_owned) {
            if (rollback_record_initialized) rollback_record.deinit();
            std.testing.allocator.destroy(rollback_record);
        }
    }
    rollback_record.* = .{
        .handle = 9,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    rollback_record_initialized = true;
    const rollback_original_dcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    try std.testing.expectError(
        error.DuplicateConnectionId,
        endpoint_owner.adoptRetryRecordAndSwitchInitialRoute(
            rollback_record.handle,
            rollback_record,
            &rollback_original_dcid,
            &retry_scid,
            retry_path,
            .{ .active_migration_disabled = true },
        ),
    );
    try std.testing.expect(endpoint_owner.records.get(rollback_record.handle) == null);
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());
    rollback_record_owned = false;
    rollback_record.deinit();
    std.testing.allocator.destroy(rollback_record);

    var client = try Connection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    const accepted_original_dcid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7 };
    const accepted_client_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const accepted_server_scid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3 };
    const accepted_secrets = try protection.deriveInitialSecrets(.v1, &accepted_original_dcid);
    try client.sendCryptoInSpace(.initial, "endpoint record admission");
    const initial_datagram = (try client.pollInitialProtectedDatagram(
        1,
        &accepted_original_dcid,
        &accepted_client_scid,
        &[_]u8{},
        accepted_secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(initial_datagram);
    var action_buffer: [256]u8 = undefined;
    const accepted_action = try endpoint_owner.lifecycle.handleDatagramWithVersionNegotiation(
        &action_buffer,
        retry_path,
        initial_datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
    );
    const accepted_initial = switch (accepted_action) {
        .accept_initial => |initial_accept| initial_accept,
        else => return error.TestUnexpectedResult,
    };

    const rejecting_record = try std.testing.allocator.create(TestRecord);
    var rejecting_record_initialized = false;
    var rejecting_record_owned = true;
    errdefer {
        if (rejecting_record_owned) {
            if (rejecting_record_initialized) rejecting_record.deinit();
            std.testing.allocator.destroy(rejecting_record);
        }
    }
    rejecting_record.* = .{
        .handle = 10,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = undefined,
    };
    rejecting_record_initialized = true;
    var rejecting_backend = RejectingInitialBackend{};
    rejecting_record.backend = rejecting_backend.backend();
    var rejecting_scratch: [256]u8 = undefined;
    var rejecting_output: [1]root.EndpointPolledDatagramResult = undefined;
    try std.testing.expectError(
        error.InvalidPacket,
        endpoint_owner.acceptInitialRecord(
            rejecting_record.handle,
            rejecting_record,
            2,
            accepted_initial,
            &accepted_server_scid,
            initial_datagram,
            .{ .active_migration_disabled = true },
            &rejecting_scratch,
            &rejecting_output,
            &rejecting_output,
        ),
    );
    try std.testing.expect(endpoint_owner.records.get(rejecting_record.handle) == null);
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());
    rejecting_record_owned = false;
    rejecting_record.deinit();
    std.testing.allocator.destroy(rejecting_record);

    const handshake_rejecting_record = try std.testing.allocator.create(TestRecord);
    var handshake_rejecting_record_initialized = false;
    var handshake_rejecting_record_owned = true;
    errdefer {
        if (handshake_rejecting_record_owned) {
            if (handshake_rejecting_record_initialized) handshake_rejecting_record.deinit();
            std.testing.allocator.destroy(handshake_rejecting_record);
        }
    }
    handshake_rejecting_record.* = .{
        .handle = 12,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = undefined,
    };
    handshake_rejecting_record_initialized = true;
    var handshake_rejecting_backend = RejectingHandshakeBackend{ .secrets = .{
        .local = accepted_secrets.server.secret,
        .peer = accepted_secrets.client.secret,
    } };
    handshake_rejecting_record.backend = handshake_rejecting_backend.backend();
    const handshake_rejecting_handle = handshake_rejecting_record.handle;
    try std.testing.expectError(
        error.InvalidPacket,
        endpoint_owner.acceptInitialRecord(
            handshake_rejecting_handle,
            handshake_rejecting_record,
            2,
            accepted_initial,
            &accepted_server_scid,
            initial_datagram,
            .{ .active_migration_disabled = true },
            &rejecting_scratch,
            &rejecting_output,
            &rejecting_output,
        ),
    );
    handshake_rejecting_record_owned = false;
    try std.testing.expect(endpoint_owner.records.get(handshake_rejecting_handle) == null);
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.recoveryTimerCount());

    const retired_record = try endpoint_owner.retireRecord(retry_record_handle);
    try std.testing.expectEqual(@as(usize, 1), retired_record.routes_retired);
    try std.testing.expect(retired_record.recovery_timer_disarmed);
    try std.testing.expect(endpoint_owner.records.get(retry_record_handle) == null);
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.recoveryTimerCount());
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.retireRecord(retry_record_handle));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.routeDatagram(retry_path, &routed_short));
    try std.testing.expectEqual(@as(usize, 0), (try endpoint_owner.activeConnectionIds(&active_ids)).len);

    var full_endpoint = try TestEndpoint.initWithCapacity(std.testing.allocator, 0, .{
        .max_routes = 0,
        .max_stateless_reset_tokens = 0,
    });
    defer full_endpoint.deinit();
    try std.testing.expect(!full_endpoint.hasConnectionCapacity());
    try std.testing.expectEqual(@as(usize, 0), full_endpoint.activeConnectionCount());
    try std.testing.expectEqual(@as(usize, 0), full_endpoint.activeConnectionLimit());
    try std.testing.expectEqual(@as(usize, 0), (try full_endpoint.activeConnectionIds(&active_ids)).len);
    const capacity_record = try std.testing.allocator.create(TestRecord);
    capacity_record.* = .{
        .handle = 11,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    defer {
        capacity_record.deinit();
        std.testing.allocator.destroy(capacity_record);
    }
    const capacity_attempt = try full_endpoint.tryAcceptInitialRecordWithRoutePath(
        capacity_record.handle,
        capacity_record,
        3,
        accepted_initial,
        &accepted_server_scid,
        initial_datagram,
        .{ .active_migration_disabled = true },
        &rejecting_scratch,
        &rejecting_output,
        &rejecting_output,
    );
    switch (capacity_attempt) {
        .dropped_capacity => |dropped| {
            try std.testing.expectEqual(@as(usize, 0), dropped.active_connections);
            try std.testing.expectEqual(@as(usize, 0), dropped.active_connection_limit);
        },
        .admitted => return error.TestUnexpectedResult,
    }
    try std.testing.expect(full_endpoint.records.get(capacity_record.handle) == null);
    try std.testing.expectEqual(@as(usize, 0), full_endpoint.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), full_endpoint.activeConnectionCount());

    var closed_capacity_endpoint = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 2,
        .max_stateless_reset_tokens = 1,
    });
    defer closed_capacity_endpoint.deinit();
    const stale_record = try std.testing.allocator.create(TestRecord);
    var stale_record_initialized = false;
    var stale_record_owned = true;
    errdefer {
        if (stale_record_owned) {
            if (stale_record_initialized) stale_record.deinit();
            std.testing.allocator.destroy(stale_record);
        }
    }
    stale_record.* = .{
        .handle = 13,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    stale_record_initialized = true;
    try stale_record.connection.validatePeerAddress();
    try stale_record.connection.confirmHandshake();
    try stale_record.connection.installOneRttTrafficSecrets(.{
        .local = accepted_secrets.server.secret,
        .peer = accepted_secrets.client.secret,
    });
    const stale_record_handle = stale_record.handle;
    const stale_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_445),
    };
    try closed_capacity_endpoint.lifecycle.registerConnectionId(
        stale_record.handle,
        TestRecord.sourceConnectionId(stale_record),
        stale_path,
        .{},
    );
    try closed_capacity_endpoint.records.adopt(stale_record.handle, stale_record);
    stale_record_owned = false;
    const stale_close = (try closed_capacity_endpoint.closeWithRoutePath(
        stale_record.handle,
        0,
        @intFromEnum(frame.FrameType.crypto),
        "done",
        4,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(stale_close.datagram);
    const stale_close_deadline = stale_record.connection.closeDeadlineMillis() orelse return error.TestUnexpectedResult;
    try std.testing.expectError(error.ConnectionClosed, stale_record.connection.checkCloseTimeouts(stale_close_deadline));
    try std.testing.expectEqual(connection_module.ConnectionState.closed, stale_record.connection.connectionState());
    const closed_capacity_view: *const TestEndpoint = &closed_capacity_endpoint;
    try std.testing.expectEqual(@as(usize, 0), closed_capacity_view.activeConnectionCount());
    try std.testing.expect(closed_capacity_view.hasConnectionCapacity());
    var closed_capacity_active_ids: [1]u64 = undefined;
    try std.testing.expectEqual(@as(usize, 0), (try closed_capacity_view.activeConnectionIds(&closed_capacity_active_ids)).len);
    try std.testing.expectEqual(@as(usize, 1), closed_capacity_endpoint.lifecycle.routeCount());

    try std.testing.expectEqual(@as(usize, 1), try closed_capacity_endpoint.reclaimClosedRecords());
    try std.testing.expect(closed_capacity_endpoint.records.get(stale_record_handle) == null);
    try std.testing.expectEqual(@as(usize, 0), closed_capacity_endpoint.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), closed_capacity_endpoint.lifecycle.recoveryTimerCount());
    try std.testing.expectEqual(@as(usize, 0), try closed_capacity_endpoint.reclaimClosedRecords());
    try std.testing.expect(closed_capacity_endpoint.hasConnectionCapacity());

    const reclaimed_capacity_record = try std.testing.allocator.create(TestRecord);
    var reclaimed_capacity_record_initialized = false;
    var reclaimed_capacity_record_owned = true;
    errdefer {
        if (reclaimed_capacity_record_owned) {
            if (reclaimed_capacity_record_initialized) reclaimed_capacity_record.deinit();
            std.testing.allocator.destroy(reclaimed_capacity_record);
        }
    }
    reclaimed_capacity_record.* = .{
        .handle = 14,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    reclaimed_capacity_record_initialized = true;
    var reclaimed_initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var reclaimed_handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    const reclaimed_capacity = try closed_capacity_endpoint.tryAcceptInitialRecordWithRoutePath(
        reclaimed_capacity_record.handle,
        reclaimed_capacity_record,
        4,
        accepted_initial,
        TestRecord.sourceConnectionId(reclaimed_capacity_record),
        initial_datagram,
        .{ .active_migration_disabled = true },
        &rejecting_scratch,
        &reclaimed_initial_out,
        &reclaimed_handshake_out,
    );
    switch (reclaimed_capacity) {
        .admitted => |admitted| {
            reclaimed_capacity_record_owned = false;
            for (reclaimed_initial_out[0..admitted.initial.accepted.drain.datagrams_written]) |datagram| {
                std.testing.allocator.free(datagram.datagram);
            }
            if (admitted.handshake) |handshake| {
                for (reclaimed_handshake_out[0..handshake.backend.drain.datagrams_written]) |datagram| {
                    std.testing.allocator.free(datagram.datagram);
                }
            }
        },
        .dropped_capacity => return error.TestUnexpectedResult,
    }
    try std.testing.expect(closed_capacity_endpoint.records.get(stale_record_handle) == null);
    try std.testing.expect(closed_capacity_endpoint.records.get(reclaimed_capacity_record.handle) != null);
    try std.testing.expectEqual(@as(usize, 1), closed_capacity_view.activeConnectionCount());
    const reclaimed_active_ids = try closed_capacity_view.activeConnectionIds(&closed_capacity_active_ids);
    try std.testing.expectEqual(@as(usize, 1), reclaimed_active_ids.len);
    try std.testing.expectEqual(reclaimed_capacity_record.handle, reclaimed_active_ids[0]);
    try std.testing.expectEqual(@as(usize, 2), closed_capacity_endpoint.lifecycle.routeCount());
    try std.testing.expect(!closed_capacity_view.hasConnectionCapacity());

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    try std.testing.expect((try endpoint_owner.nextDeadline(no_allocation_allocator.allocator())) == null);

    var dynamic_endpoint = TestEndpoint.init(std.testing.allocator);
    defer dynamic_endpoint.deinit();
    try std.testing.expect(dynamic_endpoint.hasConnectionCapacity());
    try std.testing.expectEqual(@as(usize, 0), dynamic_endpoint.activeConnectionCount());
    try std.testing.expectEqual(std.math.maxInt(usize), dynamic_endpoint.activeConnectionLimit());
    try std.testing.expectEqual(@as(usize, 0), (try dynamic_endpoint.activeConnectionIds(&active_ids)).len);
    try std.testing.expectEqual(@as(usize, 0), dynamic_endpoint.lifecycle.routeCount());
    try std.testing.expectEqual(@as(?root.EndpointConnectionDeadline, null), try dynamic_endpoint.nextDeadline(std.testing.allocator));

    var deadline_endpoint = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 1,
        .max_stateless_reset_tokens = 0,
    });
    defer deadline_endpoint.deinit();
    const deadline_record = try std.testing.allocator.create(TestRecord);
    var deadline_record_initialized = false;
    var deadline_record_owned = true;
    errdefer {
        if (deadline_record_owned) {
            if (deadline_record_initialized) deadline_record.deinit();
            std.testing.allocator.destroy(deadline_record);
        }
    }
    deadline_record.* = .{
        .handle = 15,
        .connection = try Connection.init(std.testing.allocator, .server, .{ .max_idle_timeout_ms = 20 }),
        .backend = empty_backend.backend(),
    };
    deadline_record_initialized = true;
    deadline_record.connection.last_packet_activity_millis = 10;
    try deadline_endpoint.records.adopt(deadline_record.handle, deadline_record);
    deadline_record_owned = false;

    var empty_deadline_views: [0]root.EndpointConnectionView = .{};
    try std.testing.expectError(error.BufferTooSmall, deadline_endpoint.nextDeadlineWithStorage(&empty_deadline_views));
    var deadline_views: [1]root.EndpointConnectionView = undefined;
    const storage_deadline = (try deadline_endpoint.nextDeadlineWithStorage(&deadline_views)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.idle_timeout, storage_deadline.kind);
    try std.testing.expectEqual(deadline_record.handle, storage_deadline.connection_id);
    try std.testing.expectEqual(@as(i64, 30), storage_deadline.deadline_millis);
}

test "Tls13ServerEndpoint drive backend route path resolves route before pulling backend output" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "initial";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const PullingBackend = struct {
        pull_calls: usize = 0,

        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(context: *anyopaque, _: root.PacketNumberSpace, out: []u8) root.Error!?[]const u8 {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.pull_calls += 1;
            if (out.len < 3) return error.BufferTooSmall;
            @memcpy(out[0..3], "tls");
            return out[0..3];
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 1,
        .max_stateless_reset_tokens = 1,
    });
    defer endpoint_owner.deinit();
    var pulling_backend = PullingBackend{};
    const record = try std.testing.allocator.create(TestRecord);
    record.* = .{
        .handle = 7,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = pulling_backend.backend(),
    };
    const record_handle = record.handle;
    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 5443),
    };
    try endpoint_owner.lifecycle.registerConnectionId(record_handle, TestRecord.sourceConnectionId(record), path, .{});
    try endpoint_owner.records.adopt(record_handle, record);
    try std.testing.expect(try endpoint_owner.lifecycle.retireConnectionIdOnPath(TestRecord.sourceConnectionId(record), path));

    var scratch: [16]u8 = undefined;
    var output: [1]root.EndpointPolledDatagramResult = undefined;
    try std.testing.expectError(
        error.UnknownConnectionId,
        endpoint_owner.driveBackendWithRoutePath(
            record_handle,
            .handshake,
            &scratch,
            1,
            &output,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), pulling_backend.pull_calls);
    try std.testing.expectError(
        error.UnknownConnectionId,
        endpoint_owner.driveInitialBackendWithRoutePath(
            record_handle,
            &scratch,
            1,
            &[_]u8{},
            .v1,
            &output,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), pulling_backend.pull_calls);
}

test "Tls13ServerEndpoint pairs stateless endpoint responses with receive path" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "initial";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = TestEndpoint.init(std.testing.allocator);
    defer endpoint_owner.deinit();
    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 5443),
    };

    const unsupported_initial = [_]u8{
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
    var response_out: [128]u8 = undefined;
    const version_response = try endpoint_owner.feedDatagramWithResponsePath(
        &response_out,
        path,
        &unsupported_initial,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
    );
    switch (version_response) {
        .version_negotiation => |response| {
            try std.testing.expect(response.path.eql(path));
            var parsed = try quic_packet.parseVersionNegotiationPacket(response.datagram, std.testing.allocator);
            defer quic_packet.deinitVersionNegotiationPacket(&parsed, std.testing.allocator);
            try std.testing.expectEqualSlices(u8, &[_]u8{ 0x11, 0x22, 0x33 }, parsed.dcid);
            try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb }, parsed.scid);
            try std.testing.expectEqualSlices(quic_packet.Version, &[_]quic_packet.Version{.v1}, parsed.versions);
        },
        else => return error.TestUnexpectedResult,
    }
    var process_scratch: [64]u8 = undefined;
    var process_initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var process_handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    const processed_version_response = try endpoint_owner.processDatagramWithRoutePath(
        path,
        0,
        &unsupported_initial,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &response_out,
            .unpredictable_prefix = &.{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &process_scratch,
        &[_]u8{},
        &process_initial_out,
        &process_handshake_out,
    );
    switch (processed_version_response) {
        .version_negotiation => |response| try std.testing.expect(response.path.eql(path)),
        else => return error.TestUnexpectedResult,
    }

    const retired_cid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const reset_token = [_]u8{0x9a} ** quic_packet.stateless_reset_token_len;
    try endpoint_owner.lifecycle.registerConnectionId(77, &retired_cid, path, .{
        .stateless_reset_token = reset_token,
    });
    try std.testing.expect(try endpoint_owner.lifecycle.retireConnectionIdOnPath(&retired_cid, path));
    const reset_prefix = [_]u8{ 0x40, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01, 0x02 };
    const retired_datagram = [_]u8{
        0x40, 0x31, 0x32, 0x33, 0x34, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    };
    const reset_response = try endpoint_owner.feedDatagramWithResponsePath(
        &response_out,
        path,
        &retired_datagram,
        &reset_prefix,
        &[_]quic_packet.Version{.v1},
    );
    switch (reset_response) {
        .stateless_reset => |response| {
            try std.testing.expect(response.path.eql(path));
            try std.testing.expectEqual(reset_prefix.len + quic_packet.stateless_reset_token_len, response.datagram.len);
            try std.testing.expect(quic_packet.matchesStatelessReset(response.datagram, reset_token));
        },
        else => return error.TestUnexpectedResult,
    }
}

test "Tls13ServerEndpoint dispatches routed long packets with route paths" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: Backend,
        peer_cid: [4]u8,
        local_cid: [4]u8,
        original_cid: [8]u8,

        const Backend = struct {
            received_initial: bool = false,
            received_handshake: bool = false,

            fn backend(self: *@This()) root.CryptoBackend {
                return .{
                    .context = self,
                    .receive = receive,
                    .pull = pull,
                };
            }

            fn receive(context: *anyopaque, space: root.PacketNumberSpace, data: []const u8) root.Error!void {
                const self: *@This() = @ptrCast(@alignCast(context));
                if (space == .initial and std.mem.eql(u8, data, "client initial")) {
                    self.received_initial = true;
                } else if (space == .handshake and std.mem.eql(u8, data, "client handshake")) {
                    self.received_handshake = true;
                }
            }

            fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
                return null;
            }
        };

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend.backend();
        }

        fn destinationConnectionId(self: *const @This()) []const u8 {
            return &self.peer_cid;
        }

        fn sourceConnectionId(self: *const @This()) []const u8 {
            return &self.local_cid;
        }

        fn initialDestinationConnectionId(self: *const @This()) []const u8 {
            return &self.original_cid;
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = TestEndpoint.init(std.testing.allocator);
    defer endpoint_owner.deinit();
    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 5443),
    };
    const original_cid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_cid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const server_cid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3 };

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 91,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = .{},
        .peer_cid = client_cid,
        .local_cid = server_cid,
        .original_cid = original_cid,
    };
    record_initialized = true;
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, &original_cid, path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, &server_cid, path, .{});
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;

    var client = try Connection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    const initial_secrets = try protection.deriveInitialSecrets(.v1, &original_cid);
    try client.sendCryptoInSpace(.initial, "client initial");
    const initial_datagram = (try client.pollInitialProtectedDatagram(
        1,
        &original_cid,
        &client_cid,
        &[_]u8{},
        initial_secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(initial_datagram);

    var scratch: [256]u8 = undefined;
    var route_out: [64]u8 = undefined;
    var initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    const initial_dispatch = try endpoint_owner.processDatagramWithRoutePath(
        path,
        2,
        initial_datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &route_out,
            .unpredictable_prefix = &.{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &scratch,
        &[_]u8{},
        &initial_out,
        &handshake_out,
    );
    const initial_result = switch (initial_dispatch) {
        .routed => |routed| switch (routed) {
            .long => |long| switch (long) {
                .packet => |packet_result| packet_result,
                else => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    };
    switch (initial_result) {
        .initial => |initial| {
            try std.testing.expectEqual(record.handle, initial.initial.route.connection_id);
            try std.testing.expect(initial.initial.backend.path.eql(path));
            try std.testing.expectEqual(@as(usize, 0), initial.initial.backend.backend.drain.datagrams_written);
            try std.testing.expectEqual(@as(?TestEndpoint.CryptoBackendDatagramDrainPathResult, null), initial.handshake);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(record.backend.received_initial);

    const client_hs = [_]u8{0x31} ** protection.traffic_secret_len;
    const server_hs = [_]u8{0x32} ** protection.traffic_secret_len;
    try client.installHandshakeTrafficSecrets(.{
        .local = client_hs,
        .peer = server_hs,
    });
    try record.connection.installHandshakeTrafficSecrets(.{
        .local = server_hs,
        .peer = client_hs,
    });
    try client.sendCryptoInSpace(.handshake, "client handshake");
    const handshake_datagram = (try client.pollProtectedHandshakeDatagramWithInstalledKeys(
        3,
        &server_cid,
        &client_cid,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(handshake_datagram);

    const handshake_dispatch = try endpoint_owner.processDatagramWithRoutePath(
        path,
        4,
        handshake_datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &route_out,
            .unpredictable_prefix = &.{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &scratch,
        &[_]u8{},
        &initial_out,
        &handshake_out,
    );
    const handshake_result = switch (handshake_dispatch) {
        .routed => |routed| switch (routed) {
            .long => |long| switch (long) {
                .packet => |packet_result| packet_result,
                else => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    };
    switch (handshake_result) {
        .handshake => |handshake| {
            try std.testing.expectEqual(record.handle, handshake.route.connection_id);
            try std.testing.expect(handshake.backend.path.eql(path));
            try std.testing.expectEqual(@as(usize, 0), handshake.backend.backend.drain.datagrams_written);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(record.backend.received_handshake);

    const client_1rtt = [_]u8{0x51} ** protection.traffic_secret_len;
    const server_1rtt = [_]u8{0x52} ** protection.traffic_secret_len;
    try client.installOneRttTrafficSecrets(.{
        .local = client_1rtt,
        .peer = server_1rtt,
    });
    try record.connection.installOneRttTrafficSecrets(.{
        .local = server_1rtt,
        .peer = client_1rtt,
    });
    try record.connection.validatePeerAddress();
    try client.confirmHandshake();
    try record.connection.confirmHandshake();
    try client.sendPing();
    const short_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(5, &server_cid)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(short_datagram);
    const short_dispatch = try endpoint_owner.processDatagramWithRoutePath(
        path,
        6,
        short_datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &route_out,
            .unpredictable_prefix = &.{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &scratch,
        &[_]u8{},
        &initial_out,
        &handshake_out,
    );
    switch (short_dispatch) {
        .routed => |routed| switch (routed) {
            .installed_key => |processed_short| {
                try std.testing.expect((processed_short.feed orelse return error.TestUnexpectedResult).feed == .routed);
                const polled_short = processed_short.datagram orelse return error.TestUnexpectedResult;
                defer std.testing.allocator.free(polled_short.datagram);
                try std.testing.expectEqual(record.handle, polled_short.connection_id);
                try std.testing.expect(polled_short.path.eql(path));
                try std.testing.expect(polled_short.datagram.len > 0);
                try std.testing.expectEqual(@as(?root.EndpointConnectionDeadline, null), processed_short.next_deadline);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }

    try client.sendPing();
    const draining_short_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(7, &server_cid)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(draining_short_datagram);
    const migrated_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 5444),
    };
    const challenge_data = [_]u8{ 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb };
    var installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const short_drain_dispatch = try endpoint_owner.processDatagramAndDrainWithRoutePath(
        migrated_path,
        8,
        draining_short_datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &route_out,
            .unpredictable_prefix = &.{},
            .supported_versions = &[_]quic_packet.Version{.v1},
            .path_challenge_data = challenge_data,
        },
        &scratch,
        &[_]u8{},
        &initial_out,
        &handshake_out,
        &installed_key_out,
    );
    switch (short_drain_dispatch) {
        .routed => |routed| switch (routed) {
            .installed_key => |processed_short| {
                try std.testing.expect((processed_short.feed orelse return error.TestUnexpectedResult).feed == .routed);
                try std.testing.expectEqual(@as(usize, 1), processed_short.drain.datagrams_written);
                defer std.testing.allocator.free(installed_key_out[0].datagram);
                try std.testing.expectEqual(record.handle, installed_key_out[0].connection_id);
                try std.testing.expect(installed_key_out[0].path.eql(migrated_path));
                try std.testing.expect(installed_key_out[0].datagram.len > 0);
                const next_deadline = processed_short.next_deadline orelse return error.TestUnexpectedResult;
                try std.testing.expectEqual(record.handle, next_deadline.connection_id);
                try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, next_deadline.kind);
                try std.testing.expectEqual(root.PacketNumberSpace.application, next_deadline.recovery.?.space);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }

    const unsupported_coalesced = try std.testing.allocator.alloc(u8, handshake_datagram.len + initial_datagram.len);
    defer std.testing.allocator.free(unsupported_coalesced);
    @memcpy(unsupported_coalesced[0..handshake_datagram.len], handshake_datagram);
    @memcpy(unsupported_coalesced[handshake_datagram.len..], initial_datagram);
    try std.testing.expectError(error.InvalidPacket, endpoint_owner.processLongDatagramWithRoutePath(
        record.handle,
        path,
        4,
        unsupported_coalesced,
        &scratch,
        &[_]u8{},
        &initial_out,
        &handshake_out,
    ));
}

test "Tls13ServerEndpoint dispatches coalesced long datagrams with installed Handshake keys" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: Backend,
        peer_cid: [4]u8,
        local_cid: [4]u8,
        original_cid: [8]u8,

        const Backend = struct {
            received_handshake: bool = false,

            fn backend(self: *@This()) root.CryptoBackend {
                return .{
                    .context = self,
                    .receive = receive,
                    .pull = pull,
                };
            }

            fn receive(context: *anyopaque, space: root.PacketNumberSpace, data: []const u8) root.Error!void {
                const self: *@This() = @ptrCast(@alignCast(context));
                if (space == .handshake and std.mem.eql(u8, data, "client coalesced handshake")) {
                    self.received_handshake = true;
                }
            }

            fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
                return null;
            }
        };

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend.backend();
        }

        fn destinationConnectionId(self: *const @This()) []const u8 {
            return &self.peer_cid;
        }

        fn sourceConnectionId(self: *const @This()) []const u8 {
            return &self.local_cid;
        }

        fn initialDestinationConnectionId(self: *const @This()) []const u8 {
            return &self.original_cid;
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = TestEndpoint.init(std.testing.allocator);
    defer endpoint_owner.deinit();
    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 5443),
    };
    const original_cid = [_]u8{ 0x93, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_cid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3 };
    const server_cid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3 };

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 92,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = .{},
        .peer_cid = client_cid,
        .local_cid = server_cid,
        .original_cid = original_cid,
    };
    record_initialized = true;
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, &original_cid, path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, &server_cid, path, .{});
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;

    var client = try Connection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    const initial_secrets = try protection.deriveInitialSecrets(.v1, &original_cid);
    try client.sendCryptoInSpace(.initial, "coalesced duplicate initial");
    const initial_datagram = (try client.pollInitialProtectedDatagram(
        1,
        &original_cid,
        &client_cid,
        &[_]u8{},
        initial_secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(initial_datagram);

    const client_hs = [_]u8{0x41} ** protection.traffic_secret_len;
    const server_hs = [_]u8{0x42} ** protection.traffic_secret_len;
    try client.installHandshakeTrafficSecrets(.{
        .local = client_hs,
        .peer = server_hs,
    });
    try record.connection.installHandshakeTrafficSecrets(.{
        .local = server_hs,
        .peer = client_hs,
    });
    try client.sendCryptoInSpace(.handshake, "client coalesced handshake");
    const handshake_datagram = (try client.pollProtectedHandshakeDatagramWithInstalledKeys(
        2,
        &server_cid,
        &client_cid,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(handshake_datagram);

    const coalesced = try std.testing.allocator.alloc(u8, initial_datagram.len + handshake_datagram.len);
    defer std.testing.allocator.free(coalesced);
    @memcpy(coalesced[0..initial_datagram.len], initial_datagram);
    @memcpy(coalesced[initial_datagram.len..], handshake_datagram);

    var scratch: [256]u8 = undefined;
    var initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    const result = try endpoint_owner.processLongDatagramWithRoutePath(
        record.handle,
        path,
        3,
        coalesced,
        &scratch,
        &[_]u8{},
        &initial_out,
        &handshake_out,
    );
    switch (result) {
        .coalesced_initial_handshake => |coalesced_result| {
            try std.testing.expectEqual(record.handle, coalesced_result.route.connection_id);
            try std.testing.expect(coalesced_result.backend.path.eql(path));
            try std.testing.expectEqual(@as(usize, 0), coalesced_result.backend.backend.drain.datagrams_written);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(record.backend.received_handshake);
}

test "Tls13ServerEndpoint routed long route path fails before delivering CRYPTO to backend when route is missing" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: Backend,
        peer_cid: [4]u8,
        local_cid: [4]u8,
        original_cid: [8]u8,

        const Backend = struct {
            initial_receives: usize = 0,
            handshake_receives: usize = 0,
            pulls: usize = 0,

            fn backend(self: *@This()) root.CryptoBackend {
                return .{
                    .context = self,
                    .receive = receive,
                    .pull = pull,
                };
            }

            fn receive(context: *anyopaque, space: root.PacketNumberSpace, _: []const u8) root.Error!void {
                const self: *@This() = @ptrCast(@alignCast(context));
                switch (space) {
                    .initial => self.initial_receives += 1,
                    .handshake => self.handshake_receives += 1,
                    .application => {},
                }
            }

            fn pull(context: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
                const self: *@This() = @ptrCast(@alignCast(context));
                self.pulls += 1;
                return null;
            }
        };

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend.backend();
        }

        fn destinationConnectionId(self: *const @This()) []const u8 {
            return &self.peer_cid;
        }

        fn sourceConnectionId(self: *const @This()) []const u8 {
            return &self.local_cid;
        }

        fn initialDestinationConnectionId(self: *const @This()) []const u8 {
            return &self.original_cid;
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = TestEndpoint.init(std.testing.allocator);
    defer endpoint_owner.deinit();
    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 5443),
    };
    const original_cid = [_]u8{ 0x85, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    const server_cid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 94,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = .{},
        .peer_cid = client_cid,
        .local_cid = server_cid,
        .original_cid = original_cid,
    };
    record_initialized = true;
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, &original_cid, path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, &server_cid, path, .{});
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;

    var client = try Connection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    const initial_secrets = try protection.deriveInitialSecrets(.v1, &original_cid);
    try client.sendCryptoInSpace(.initial, "missing route initial");
    const initial_datagram = (try client.pollInitialProtectedDatagram(
        1,
        &original_cid,
        &client_cid,
        &[_]u8{},
        initial_secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(initial_datagram);

    const client_hs = [_]u8{0x71} ** protection.traffic_secret_len;
    const server_hs = [_]u8{0x72} ** protection.traffic_secret_len;
    try client.installHandshakeTrafficSecrets(.{
        .local = client_hs,
        .peer = server_hs,
    });
    try record.connection.installHandshakeTrafficSecrets(.{
        .local = server_hs,
        .peer = client_hs,
    });
    try client.sendCryptoInSpace(.handshake, "missing route handshake");
    const handshake_datagram = (try client.pollProtectedHandshakeDatagramWithInstalledKeys(
        2,
        &server_cid,
        &client_cid,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(handshake_datagram);

    const coalesced = try std.testing.allocator.alloc(u8, initial_datagram.len + handshake_datagram.len);
    defer std.testing.allocator.free(coalesced);
    @memcpy(coalesced[0..initial_datagram.len], initial_datagram);
    @memcpy(coalesced[initial_datagram.len..], handshake_datagram);

    try std.testing.expect(try endpoint_owner.lifecycle.retireConnectionIdOnPath(&server_cid, path));
    var scratch: [256]u8 = undefined;
    var initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]root.EndpointPolledDatagramResult = undefined;

    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.processInitialWithRoutePath(
        record.handle,
        path,
        3,
        initial_datagram,
        &scratch,
        &[_]u8{},
        &initial_out,
        &handshake_out,
    ));
    try std.testing.expectEqual(@as(usize, 0), record.backend.initial_receives);
    try std.testing.expectEqual(@as(usize, 0), record.backend.handshake_receives);
    try std.testing.expectEqual(@as(usize, 0), record.backend.pulls);

    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.processInitialWithHandshakeKeysWithRoutePath(
        record.handle,
        path,
        4,
        coalesced,
        &scratch,
        &handshake_out,
    ));
    try std.testing.expectEqual(@as(usize, 0), record.backend.initial_receives);
    try std.testing.expectEqual(@as(usize, 0), record.backend.handshake_receives);
    try std.testing.expectEqual(@as(usize, 0), record.backend.pulls);

    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.processHandshakeWithRoutePath(
        record.handle,
        path,
        5,
        handshake_datagram,
        &scratch,
        &handshake_out,
    ));
    try std.testing.expectEqual(@as(usize, 0), record.backend.initial_receives);
    try std.testing.expectEqual(@as(usize, 0), record.backend.handshake_receives);
    try std.testing.expectEqual(@as(usize, 0), record.backend.pulls);
}

test "Tls13ServerEndpoint validates Retry Initial and returns route-bound TLS output" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const retry_scid = [_]u8{ 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };
    const supported_versions = [_]quic_packet.Version{.v1};
    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 192, 0, 2, 29 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 198, 51, 100, 27 }, 50_000),
    };

    const RetryBackend = struct {
        received_initial: bool = false,
        pulled_initial: bool = false,
        pulled_handshake_secrets: bool = false,

        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
                .pull_handshake_traffic_secrets = pullHandshakeTrafficSecrets,
            };
        }

        fn receive(context: *anyopaque, space: root.PacketNumberSpace, data: []const u8) root.Error!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (space == .initial and std.mem.eql(u8, data, "client after retry")) {
                self.received_initial = true;
            }
        }

        fn pull(context: *anyopaque, space: root.PacketNumberSpace, out_buf: []u8) root.Error!?[]const u8 {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (space != .initial or self.pulled_initial) return null;
            const bytes = "server after retry";
            if (out_buf.len < bytes.len) return error.BufferTooSmall;
            @memcpy(out_buf[0..bytes.len], bytes);
            self.pulled_initial = true;
            return out_buf[0..bytes.len];
        }

        fn pullHandshakeTrafficSecrets(context: *anyopaque) root.Error!?root.HandshakeTrafficSecrets {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.pulled_handshake_secrets) return null;
            self.pulled_handshake_secrets = true;
            return .{
                .local = [_]u8{0x11} ** protection.traffic_secret_len,
                .peer = [_]u8{0x22} ** protection.traffic_secret_len,
            };
        }
    };

    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend_value: root.CryptoBackend,
        retry_validated: bool = false,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend_value;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return &client_scid;
        }

        fn sourceConnectionId(self: *const @This()) []const u8 {
            return if (self.retry_validated) &retry_scid else &original_dcid;
        }

        fn initialDestinationConnectionId(self: *const @This()) []const u8 {
            return if (self.retry_validated) &retry_scid else &original_dcid;
        }

        fn markRetryValidated(self: *@This()) void {
            self.retry_validated = true;
        }

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };

    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = TestEndpoint.init(std.testing.allocator);
    defer endpoint_owner.deinit();

    const secret: address_validation_token.Secret = [_]u8{0xf1} ** address_validation_token.secret_len;
    const nonce: address_validation_token.Nonce = [_]u8{0x2c} ** address_validation_token.nonce_len;
    var policy = endpoint.AddressValidationPolicy.init(std.testing.allocator, secret, .{
        .max_previous_secrets = 1,
        .max_replay_entries = 4,
    });
    defer policy.deinit();
    const token = try policy.issueTokenForPath(std.testing.allocator, .retry, 1_000, 60_000, path, nonce);
    defer std.testing.allocator.free(token);

    var backend = RetryBackend{};
    const record = try std.testing.allocator.create(TestRecord);
    record.* = .{
        .handle = 31,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend_value = backend.backend(),
    };
    try record.connection.issueRetryToken(token);
    const record_handle = record.handle;
    _ = try endpoint_owner.adoptRetryRecordAndSwitchInitialRoute(
        record_handle,
        record,
        &original_dcid,
        &retry_scid,
        path,
        .{ .active_migration_disabled = true },
    );

    const retry_secrets = try protection.deriveInitialSecrets(.v1, &retry_scid);
    var client = try Connection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try client.sendCryptoInSpace(.initial, "client after retry");
    const followup_initial = (try client.pollInitialProtectedDatagram(
        1_010,
        &retry_scid,
        &client_scid,
        token,
        retry_secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(followup_initial);

    var scratch: [8192]u8 = undefined;
    var initial_outputs: [2]root.EndpointPolledDatagramResult = undefined;
    var handshake_outputs: [2]root.EndpointPolledDatagramResult = undefined;
    const processed = try endpoint_owner.validateRetryInitialWithRoutePath(
        &policy,
        record_handle,
        1_020,
        path,
        followup_initial,
        &supported_versions,
        &scratch,
        &initial_outputs,
        &handshake_outputs,
    );
    defer {
        for (initial_outputs[0..processed.initial.backend.drain.datagrams_written]) |output| {
            std.testing.allocator.free(output.datagram);
        }
        if (processed.handshake) |handshake| {
            for (handshake_outputs[0..handshake.backend.drain.datagrams_written]) |output| {
                std.testing.allocator.free(output.datagram);
            }
        }
    }

    try std.testing.expectEqual(record_handle, processed.retry.route.connection_id);
    try std.testing.expectEqual(quic_packet.Version.v1, processed.retry.initial_accept.version);
    try std.testing.expect(processed.initial.path.eql(path));
    try std.testing.expect(processed.handshake != null);
    try std.testing.expect(processed.handshake.?.path.eql(path));
    try std.testing.expectEqual(@as(usize, 1), processed.initial.backend.backend.inbound_chunks);
    try std.testing.expectEqual(@as(usize, "client after retry".len), processed.initial.backend.backend.inbound_bytes);
    try std.testing.expectEqual(@as(usize, 1), processed.initial.backend.backend.outbound_chunks);
    try std.testing.expect(processed.initial.backend.backend.handshake_keys_installed);
    try std.testing.expectEqual(@as(usize, 1), processed.initial.backend.drain.datagrams_written);
    try std.testing.expect(initial_outputs[0].datagram.len >= 1200);
    try std.testing.expect(backend.received_initial);
    try std.testing.expect(backend.pulled_initial);
    try std.testing.expect(backend.pulled_handshake_secrets);
    const owned_record = endpoint_owner.records.get(record_handle) orelse return error.TestUnexpectedResult;
    try std.testing.expect(owned_record.retry_validated);
    try std.testing.expect(owned_record.connection.peerAddressValidated());
    try std.testing.expectEqual(@as(usize, 0), owned_record.connection.pendingRetryTokenCount());
    try std.testing.expectEqual(@as(usize, 1), policy.replayFilterEntryCount());
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());
    try std.testing.expect((try endpoint_owner.lifecycle.currentRoutePath(&retry_scid)).eql(path));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.lifecycle.currentRoutePath(&original_dcid));
}

test "Tls13ServerEndpoint validates Retry Initial route before consuming token state" {
    const original_dcid = [_]u8{ 0x86, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x45, 0x46, 0x47, 0x48 };
    const retry_scid = [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    const supported_versions = [_]quic_packet.Version{.v1};
    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 192, 0, 2, 30 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 198, 51, 100, 28 }, 50_001),
    };

    const RetryBackend = struct {
        received_initial: bool = false,
        pulled_initial: bool = false,

        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(context: *anyopaque, space: root.PacketNumberSpace, _: []const u8) root.Error!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (space == .initial) self.received_initial = true;
        }

        fn pull(context: *anyopaque, space: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (space == .initial) self.pulled_initial = true;
            return null;
        }
    };

    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend_value: root.CryptoBackend,
        retry_validated: bool = false,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend_value;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return &client_scid;
        }

        fn sourceConnectionId(self: *const @This()) []const u8 {
            return if (self.retry_validated) &retry_scid else &original_dcid;
        }

        fn initialDestinationConnectionId(self: *const @This()) []const u8 {
            return if (self.retry_validated) &retry_scid else &original_dcid;
        }

        fn markRetryValidated(self: *@This()) void {
            self.retry_validated = true;
        }

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };

    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = TestEndpoint.init(std.testing.allocator);
    defer endpoint_owner.deinit();

    const secret: address_validation_token.Secret = [_]u8{0xf2} ** address_validation_token.secret_len;
    const nonce: address_validation_token.Nonce = [_]u8{0x2d} ** address_validation_token.nonce_len;
    var policy = endpoint.AddressValidationPolicy.init(std.testing.allocator, secret, .{
        .max_previous_secrets = 1,
        .max_replay_entries = 4,
    });
    defer policy.deinit();
    const token = try policy.issueTokenForPath(std.testing.allocator, .retry, 1_000, 60_000, path, nonce);
    defer std.testing.allocator.free(token);

    var backend = RetryBackend{};
    const record = try std.testing.allocator.create(TestRecord);
    record.* = .{
        .handle = 32,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend_value = backend.backend(),
    };
    try record.connection.issueRetryToken(token);
    const record_handle = record.handle;
    _ = try endpoint_owner.adoptRetryRecordAndSwitchInitialRoute(
        record_handle,
        record,
        &original_dcid,
        &retry_scid,
        path,
        .{ .active_migration_disabled = true },
    );

    const retry_secrets = try protection.deriveInitialSecrets(.v1, &retry_scid);
    var client = try Connection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try client.sendCryptoInSpace(.initial, "retry should wait for route");
    const followup_initial = (try client.pollInitialProtectedDatagram(
        1_010,
        &retry_scid,
        &client_scid,
        token,
        retry_secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(followup_initial);

    try std.testing.expect(try endpoint_owner.lifecycle.retireConnectionIdOnPath(&retry_scid, path));
    var scratch: [8192]u8 = undefined;
    var initial_outputs: [1]root.EndpointPolledDatagramResult = undefined;
    var handshake_outputs: [1]root.EndpointPolledDatagramResult = undefined;
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.validateRetryInitialWithRoutePath(
        &policy,
        record_handle,
        1_020,
        path,
        followup_initial,
        &supported_versions,
        &scratch,
        &initial_outputs,
        &handshake_outputs,
    ));

    try std.testing.expect(!record.retry_validated);
    try std.testing.expect(!record.connection.peerAddressValidated());
    try std.testing.expectEqual(@as(usize, 1), record.connection.pendingRetryTokenCount());
    try std.testing.expectEqual(@as(usize, 0), policy.replayFilterEntryCount());
    try std.testing.expect(!backend.received_initial);
    try std.testing.expect(!backend.pulled_initial);
}

test "Tls13ServerEndpoint feeds installed-key short datagram without receive-view allocation" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "initial";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var dynamic_endpoint = TestEndpoint.init(std.testing.allocator);
    defer dynamic_endpoint.deinit();

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 1,
        .max_stateless_reset_tokens = 1,
    });
    defer endpoint_owner.deinit();

    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const server_dcid = "local";
    const secrets = try protection.deriveInitialSecrets(.v1, "endpoint-feed");
    var empty_backend = EmptyBackend{};

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 81,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    try record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;

    var client = try Connection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try client.confirmHandshake();
    try client.installOneRttTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });
    try client.sendPing();
    const datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(1, server_dcid)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(datagram);

    var dynamic_out: [64]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, dynamic_endpoint.feedDatagramWithInstalledKeysAndSelectNextDeadlineWithScratch(
        path,
        2,
        datagram,
        .{
            .space = .application,
            .out = &dynamic_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
    ));

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const feed_deadline = try endpoint_owner.feedDatagramWithInstalledKeysAndSelectNextDeadlineWithScratch(
        path,
        2,
        datagram,
        .{
            .space = .application,
            .out = &[_]u8{},
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
    );
    const route = switch (feed_deadline.feed) {
        .routed => |route| route,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(record.handle, route.connection_id);
    try std.testing.expect(feed_deadline.next_deadline == null);

    try client.sendPing();
    const pending_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(3, server_dcid)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(pending_datagram);
    try std.testing.expectError(error.BufferTooSmall, dynamic_endpoint.feedDatagramWithInstalledKeysAndProcessPendingWorkAndSelectNextDeadlineWithScratch(
        path,
        4,
        pending_datagram,
        .{
            .space = .application,
            .out = &dynamic_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
    ));
    const feed_pending_deadline = try endpoint_owner.feedDatagramWithInstalledKeysAndProcessPendingWorkAndSelectNextDeadlineWithScratch(
        path,
        4,
        pending_datagram,
        .{
            .space = .application,
            .out = &[_]u8{},
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
    );
    const pending_route = switch (feed_pending_deadline.feed) {
        .routed => |pending_route| pending_route,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(record.handle, pending_route.connection_id);
    try std.testing.expectEqual(@as(usize, 0), feed_pending_deadline.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), feed_pending_deadline.pending_work.close_retired_count);
    try std.testing.expectEqual(@as(usize, 0), feed_pending_deadline.pending_work.recovery_serviced_count);
    try std.testing.expect(feed_pending_deadline.next_deadline == null);

    try client.sendPing();
    const drain_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(5, server_dcid)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(drain_datagram);
    var route_drain_out: [1]TestEndpoint.DatagramPathResult = undefined;
    try std.testing.expectError(error.BufferTooSmall, dynamic_endpoint.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDrainDatagramsWithRoutePathWithScratch(
        path,
        6,
        drain_datagram,
        .{
            .space = .application,
            .out = &dynamic_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        .application,
        &route_drain_out,
    ));
    const feed_pending_drain = try endpoint_owner.feedDatagramWithInstalledKeysAndProcessPendingWorkAndDrainDatagramsWithRoutePathWithScratch(
        path,
        6,
        drain_datagram,
        .{
            .space = .application,
            .out = &[_]u8{},
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        .application,
        &route_drain_out,
    );
    const drain_route = switch (feed_pending_drain.feed) {
        .routed => |drain_route| drain_route,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(record.handle, drain_route.connection_id);
    try std.testing.expectEqual(@as(usize, 0), feed_pending_drain.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), feed_pending_drain.pending_work.close_retired_count);
    try std.testing.expectEqual(@as(usize, 0), feed_pending_drain.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), feed_pending_drain.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), feed_pending_drain.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), feed_pending_drain.drain.first_route_error);
    try std.testing.expect(feed_pending_drain.next_deadline == null);

    try client.sendPing();
    const poll_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(7, server_dcid)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(poll_datagram);
    try std.testing.expectError(error.BufferTooSmall, dynamic_endpoint.feedDatagramWithInstalledKeysAndProcessPendingWorkAndPollDatagramWithRoutePathWithScratch(
        path,
        8,
        poll_datagram,
        .{
            .space = .application,
            .out = &dynamic_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        .application,
    ));
    const feed_pending_poll = try endpoint_owner.feedDatagramWithInstalledKeysAndProcessPendingWorkAndPollDatagramWithRoutePathWithScratch(
        path,
        8,
        poll_datagram,
        .{
            .space = .application,
            .out = &[_]u8{},
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        .application,
    );
    const poll_route = switch (feed_pending_poll.feed) {
        .routed => |poll_route| poll_route,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(record.handle, poll_route.connection_id);
    try std.testing.expectEqual(@as(usize, 0), feed_pending_poll.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), feed_pending_poll.pending_work.close_retired_count);
    try std.testing.expectEqual(@as(usize, 0), feed_pending_poll.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), feed_pending_poll.pending_route_error);
    try std.testing.expect(feed_pending_poll.datagram == null);
    try std.testing.expect(feed_pending_poll.next_deadline == null);

    try client.sendPing();
    const route_poll_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(9, server_dcid)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(route_poll_datagram);
    try std.testing.expectError(error.BufferTooSmall, dynamic_endpoint.feedInstalledKeyDatagramWithRoutePathWithScratch(
        path,
        10,
        route_poll_datagram,
        .{
            .space = .application,
            .out = &dynamic_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
    ));
    const route_poll = try endpoint_owner.feedInstalledKeyDatagramWithRoutePathWithScratch(
        path,
        10,
        route_poll_datagram,
        .{
            .space = .application,
            .out = &[_]u8{},
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
    );
    const route_poll_feed = route_poll.feed orelse return error.TestUnexpectedResult;
    const route_poll_route = switch (route_poll_feed.feed) {
        .routed => |route_poll_route| route_poll_route,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(record.handle, route_poll_route.connection_id);
    if (route_poll.datagram) |polled| {
        defer std.testing.allocator.free(polled.datagram);
        try std.testing.expectEqual(record.handle, polled.connection_id);
        try std.testing.expect(polled.path.eql(path));
    }
    try std.testing.expect(route_poll.next_deadline == null);

    try client.sendPing();
    const route_drain_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(11, server_dcid)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(route_drain_datagram);
    var route_drain_scratch_out: [1]TestEndpoint.DatagramPathResult = undefined;
    try std.testing.expectError(error.BufferTooSmall, dynamic_endpoint.feedInstalledKeyDatagramAndDrainWithRoutePathWithScratch(
        path,
        12,
        route_drain_datagram,
        .{
            .space = .application,
            .out = &dynamic_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &route_drain_scratch_out,
    ));
    const route_drain = try endpoint_owner.feedInstalledKeyDatagramAndDrainWithRoutePathWithScratch(
        path,
        12,
        route_drain_datagram,
        .{
            .space = .application,
            .out = &[_]u8{},
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &route_drain_scratch_out,
    );
    const route_drain_feed = route_drain.feed orelse return error.TestUnexpectedResult;
    const route_drain_route = switch (route_drain_feed.feed) {
        .routed => |route_drain_route| route_drain_route,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(record.handle, route_drain_route.connection_id);
    for (route_drain_scratch_out[0..route_drain.drain.datagrams_written]) |drained| {
        defer std.testing.allocator.free(drained.datagram);
        try std.testing.expectEqual(record.handle, drained.connection_id);
        try std.testing.expect(drained.path.eql(path));
    }
    try std.testing.expectEqual(@as(?root.Error, null), route_drain.drain.first_error);
    try std.testing.expect(route_drain.next_deadline == null);

    try client.sendPing();
    const routed_dispatch_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(13, server_dcid)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(routed_dispatch_datagram);
    const dispatch_route = try endpoint_owner.routeDatagram(path, routed_dispatch_datagram);
    var process_scratch: [64]u8 = undefined;
    var process_initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var process_handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    const routed_dispatch = try endpoint_owner.processRoutedDatagramWithRoutePathWithScratch(
        dispatch_route,
        path,
        14,
        routed_dispatch_datagram,
        .{
            .space = .application,
            .out = &[_]u8{},
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &process_scratch,
        &[_]u8{},
        &process_initial_out,
        &process_handshake_out,
    );
    const routed_dispatch_short = switch (routed_dispatch) {
        .installed_key => |installed_key| installed_key,
        else => return error.TestUnexpectedResult,
    };
    const routed_dispatch_feed = routed_dispatch_short.feed orelse return error.TestUnexpectedResult;
    const routed_dispatch_route = switch (routed_dispatch_feed.feed) {
        .routed => |routed_dispatch_route| routed_dispatch_route,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(record.handle, routed_dispatch_route.connection_id);
    if (routed_dispatch_short.datagram) |polled| {
        defer std.testing.allocator.free(polled.datagram);
        try std.testing.expectEqual(record.handle, polled.connection_id);
        try std.testing.expect(polled.path.eql(path));
    }
    try std.testing.expect(routed_dispatch_short.next_deadline == null);

    try client.sendPing();
    const routed_dispatch_drain_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(15, server_dcid)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(routed_dispatch_drain_datagram);
    const dispatch_drain_route = try endpoint_owner.routeDatagram(path, routed_dispatch_drain_datagram);
    var process_installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const routed_dispatch_drain = try endpoint_owner.processRoutedDatagramAndDrainWithRoutePathWithScratch(
        dispatch_drain_route,
        path,
        16,
        routed_dispatch_drain_datagram,
        .{
            .space = .application,
            .out = &[_]u8{},
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &process_scratch,
        &[_]u8{},
        &process_initial_out,
        &process_handshake_out,
        &process_installed_key_out,
    );
    const routed_dispatch_drain_short = switch (routed_dispatch_drain) {
        .installed_key => |installed_key| installed_key,
        else => return error.TestUnexpectedResult,
    };
    const routed_dispatch_drain_feed = routed_dispatch_drain_short.feed orelse return error.TestUnexpectedResult;
    const routed_dispatch_drain_route = switch (routed_dispatch_drain_feed.feed) {
        .routed => |routed_dispatch_drain_route| routed_dispatch_drain_route,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(record.handle, routed_dispatch_drain_route.connection_id);
    for (process_installed_key_out[0..routed_dispatch_drain_short.drain.datagrams_written]) |drained| {
        defer std.testing.allocator.free(drained.datagram);
        try std.testing.expectEqual(record.handle, drained.connection_id);
        try std.testing.expect(drained.path.eql(path));
    }
    try std.testing.expectEqual(@as(?root.Error, null), routed_dispatch_drain_short.drain.first_error);
    try std.testing.expect(routed_dispatch_drain_short.next_deadline == null);

    try client.sendPing();
    const classified_dispatch_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(17, server_dcid)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(classified_dispatch_datagram);
    const classified_dispatch = try endpoint_owner.processDatagramWithRoutePathWithScratch(
        path,
        18,
        classified_dispatch_datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &[_]u8{},
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &process_scratch,
        &[_]u8{},
        &process_initial_out,
        &process_handshake_out,
    );
    const classified_dispatch_routed = switch (classified_dispatch) {
        .routed => |routed| routed,
        else => return error.TestUnexpectedResult,
    };
    const classified_dispatch_short = switch (classified_dispatch_routed) {
        .installed_key => |installed_key| installed_key,
        else => return error.TestUnexpectedResult,
    };
    const classified_dispatch_feed = classified_dispatch_short.feed orelse return error.TestUnexpectedResult;
    const classified_dispatch_route = switch (classified_dispatch_feed.feed) {
        .routed => |classified_dispatch_route| classified_dispatch_route,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(record.handle, classified_dispatch_route.connection_id);
    if (classified_dispatch_short.datagram) |polled| {
        defer std.testing.allocator.free(polled.datagram);
        try std.testing.expectEqual(record.handle, polled.connection_id);
        try std.testing.expect(polled.path.eql(path));
    }
    try std.testing.expect(classified_dispatch_short.next_deadline == null);

    try client.sendPing();
    const classified_dispatch_drain_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(19, server_dcid)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(classified_dispatch_drain_datagram);
    var classified_installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const classified_dispatch_drain = try endpoint_owner.processDatagramAndDrainWithRoutePathWithScratch(
        path,
        20,
        classified_dispatch_drain_datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &[_]u8{},
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &process_scratch,
        &[_]u8{},
        &process_initial_out,
        &process_handshake_out,
        &classified_installed_key_out,
    );
    const classified_dispatch_drain_routed = switch (classified_dispatch_drain) {
        .routed => |routed| routed,
        else => return error.TestUnexpectedResult,
    };
    const classified_dispatch_drain_short = switch (classified_dispatch_drain_routed) {
        .installed_key => |installed_key| installed_key,
        else => return error.TestUnexpectedResult,
    };
    const classified_dispatch_drain_feed = classified_dispatch_drain_short.feed orelse return error.TestUnexpectedResult;
    const classified_dispatch_drain_route = switch (classified_dispatch_drain_feed.feed) {
        .routed => |classified_dispatch_drain_route| classified_dispatch_drain_route,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(record.handle, classified_dispatch_drain_route.connection_id);
    for (classified_installed_key_out[0..classified_dispatch_drain_short.drain.datagrams_written]) |drained| {
        defer std.testing.allocator.free(drained.datagram);
        try std.testing.expectEqual(record.handle, drained.connection_id);
        try std.testing.expect(drained.path.eql(path));
    }
    try std.testing.expectEqual(@as(?root.Error, null), classified_dispatch_drain_short.drain.first_error);
    try std.testing.expect(classified_dispatch_drain_short.next_deadline == null);

    try client.sendPing();
    const receive_step_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(21, server_dcid)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(receive_step_datagram);
    var receive_step_installed_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var receive_step_pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    try std.testing.expectError(error.BufferTooSmall, dynamic_endpoint.receiveDatagramStepWithRoutePathWithScratch(
        path,
        22,
        receive_step_datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &dynamic_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &process_scratch,
        &[_]u8{},
        &process_initial_out,
        &process_handshake_out,
        &receive_step_installed_out,
        .application,
        &receive_step_pending_out,
    ));
    const receive_step = try endpoint_owner.receiveDatagramStepWithRoutePathWithScratch(
        path,
        22,
        receive_step_datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &[_]u8{},
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &process_scratch,
        &[_]u8{},
        &process_initial_out,
        &process_handshake_out,
        &receive_step_installed_out,
        .application,
        &receive_step_pending_out,
    );
    const receive_step_routed = switch (receive_step.process) {
        .routed => |routed| routed,
        else => return error.TestUnexpectedResult,
    };
    const receive_step_short = switch (receive_step_routed) {
        .installed_key => |installed_key| installed_key,
        else => return error.TestUnexpectedResult,
    };
    const receive_step_feed = receive_step_short.feed orelse return error.TestUnexpectedResult;
    const receive_step_route = switch (receive_step_feed.feed) {
        .routed => |receive_step_route| receive_step_route,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(record.handle, receive_step_route.connection_id);
    for (receive_step_installed_out[0..receive_step_short.drain.datagrams_written]) |drained| {
        defer std.testing.allocator.free(drained.datagram);
        try std.testing.expectEqual(record.handle, drained.connection_id);
        try std.testing.expect(drained.path.eql(path));
    }
    try std.testing.expectEqual(@as(?root.Error, null), receive_step_short.drain.first_error);
    try std.testing.expectEqual(@as(usize, 0), receive_step.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), receive_step.pending_work.close_retired_count);
    try std.testing.expectEqual(@as(usize, 0), receive_step.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), receive_step.pending_drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), receive_step.pending_drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), receive_step.pending_drain.first_route_error);
    try std.testing.expect(receive_step.next_deadline == null);

    const admission_record = try std.testing.allocator.create(TestRecord);
    var admission_record_initialized = false;
    defer {
        if (admission_record_initialized) admission_record.deinit();
        std.testing.allocator.destroy(admission_record);
    }
    admission_record.* = .{
        .handle = 82,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    admission_record_initialized = true;

    try client.sendPing();
    const admission_step_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(23, server_dcid)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(admission_step_datagram);
    var admission_step_installed_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var admission_step_pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    try std.testing.expectError(error.BufferTooSmall, dynamic_endpoint.receiveDatagramStepWithRoutePathAndInitialRecordAdmissionWithScratch(
        path,
        24,
        admission_step_datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &dynamic_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        admission_record.handle,
        admission_record,
        server_dcid,
        .{ .active_migration_disabled = true },
        &process_scratch,
        &[_]u8{},
        &process_initial_out,
        &process_handshake_out,
        &admission_step_installed_out,
        .application,
        &admission_step_pending_out,
    ));
    const admission_step = try endpoint_owner.receiveDatagramStepWithRoutePathAndInitialRecordAdmissionWithScratch(
        path,
        24,
        admission_step_datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &[_]u8{},
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        admission_record.handle,
        admission_record,
        server_dcid,
        .{ .active_migration_disabled = true },
        &process_scratch,
        &[_]u8{},
        &process_initial_out,
        &process_handshake_out,
        &admission_step_installed_out,
        .application,
        &admission_step_pending_out,
    );
    const admission_step_routed = switch (admission_step.process) {
        .routed => |routed| routed,
        else => return error.TestUnexpectedResult,
    };
    const admission_step_short = switch (admission_step_routed) {
        .installed_key => |installed_key| installed_key,
        else => return error.TestUnexpectedResult,
    };
    const admission_step_feed = admission_step_short.feed orelse return error.TestUnexpectedResult;
    const admission_step_route = switch (admission_step_feed.feed) {
        .routed => |admission_step_route| admission_step_route,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(record.handle, admission_step_route.connection_id);
    try std.testing.expect(admission_step.admission == null);
    try std.testing.expect(endpoint_owner.records.get(admission_record.handle) == null);
    for (admission_step_installed_out[0..admission_step_short.drain.datagrams_written]) |drained| {
        defer std.testing.allocator.free(drained.datagram);
        try std.testing.expectEqual(record.handle, drained.connection_id);
        try std.testing.expect(drained.path.eql(path));
    }
    try std.testing.expectEqual(@as(?root.Error, null), admission_step_short.drain.first_error);
    try std.testing.expectEqual(@as(usize, 0), admission_step.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), admission_step.pending_work.close_retired_count);
    try std.testing.expectEqual(@as(usize, 0), admission_step.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), admission_step.pending_drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), admission_step.pending_drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), admission_step.pending_drain.first_route_error);
    try std.testing.expect(admission_step.next_deadline == null);

    const fixed_bit_clear = [_]u8{ 0, 0, 0 };
    var scratch: [64]u8 = undefined;
    var route_out: [64]u8 = undefined;
    var initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    const direct_options: root.EndpointFeedInstalledKeyDatagramOptions = .{
        .space = .application,
        .out = &route_out,
        .unpredictable_prefix = &[_]u8{},
        .supported_versions = &[_]quic_packet.Version{.v1},
    };
    try std.testing.expectError(
        error.InvalidPacket,
        endpoint_owner.processRoutedDatagramWithRoutePath(
            route,
            path,
            3,
            &fixed_bit_clear,
            direct_options,
            &scratch,
            &[_]u8{},
            &initial_out,
            &handshake_out,
        ),
    );
    var installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    try std.testing.expectError(
        error.InvalidPacket,
        endpoint_owner.processRoutedDatagramAndDrainWithRoutePath(
            route,
            path,
            4,
            &fixed_bit_clear,
            direct_options,
            &scratch,
            &[_]u8{},
            &initial_out,
            &handshake_out,
            &installed_key_out,
        ),
    );

    try endpoint_owner.records.remove(record.handle);
    try std.testing.expectError(
        error.Internal,
        endpoint_owner.feedDatagramWithInstalledKeys(
            no_allocation_allocator.allocator(),
            path,
            3,
            datagram,
            .{
                .space = .application,
                .out = &[_]u8{},
                .unpredictable_prefix = &[_]u8{},
                .supported_versions = &[_]quic_packet.Version{.v1},
            },
        ),
    );
}

test "Tls13ServerEndpoint pairs accepted Initial output with committed route path" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "initial";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const InitialOutputBackend = struct {
        pulled: bool = false,
        received_initial: bool = false,

        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(context: *anyopaque, space: root.PacketNumberSpace, _: []const u8) root.Error!void {
            if (space != .initial) return error.InvalidPacket;
            const self: *@This() = @ptrCast(@alignCast(context));
            self.received_initial = true;
        }

        fn pull(context: *anyopaque, space: root.PacketNumberSpace, out: []u8) root.Error!?[]const u8 {
            if (space != .initial) return null;
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.pulled) return null;
            const response = "server initial response";
            if (out.len < response.len) return error.BufferTooSmall;
            @memcpy(out[0..response.len], response);
            self.pulled = true;
            return out[0..response.len];
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 2,
        .max_stateless_reset_tokens = 1,
    });
    defer endpoint_owner.deinit();

    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const original_dcid = [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    const client_scid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    const server_scid = "local";
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);

    var client = try Connection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try client.sendCryptoInSpace(.initial, "client initial");
    const initial_datagram = (try client.pollInitialProtectedDatagram(
        1,
        &original_dcid,
        &client_scid,
        &[_]u8{},
        secrets.client,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(initial_datagram);

    var classification_out: [256]u8 = undefined;
    const action = try endpoint_owner.feedDatagram(
        &classification_out,
        path,
        initial_datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
    );
    const accepted_initial = switch (action) {
        .accept_initial => |initial| initial,
        else => return error.TestUnexpectedResult,
    };

    var backend = InitialOutputBackend{};
    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned_by_test = true;
    errdefer {
        if (record_owned_by_test) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 83,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = backend.backend(),
    };
    record_initialized = true;

    var scratch: [256]u8 = undefined;
    var initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    const admitted = try endpoint_owner.acceptInitialRecordWithRoutePath(
        record.handle,
        record,
        2,
        accepted_initial,
        server_scid,
        initial_datagram,
        .{ .active_migration_disabled = true },
        &scratch,
        &initial_out,
        &handshake_out,
    );
    record_owned_by_test = false;

    try std.testing.expect(backend.received_initial);
    try std.testing.expect(admitted.initial.path.eql(path));
    try std.testing.expectEqual(@as(usize, 1), admitted.initial.accepted.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), admitted.initial.accepted.drain.first_error);
    defer std.testing.allocator.free(initial_out[0].datagram);
    try std.testing.expectEqual(record.handle, initial_out[0].connection_id);
    try std.testing.expect(initial_out[0].datagram.len != 0);
    try std.testing.expectEqual(@as(?TestEndpoint.CryptoBackendDatagramDrainPathResult, null), admitted.handshake);
    try std.testing.expect((try endpoint_owner.lifecycle.currentRoutePath(server_scid)).eql(path));

    var step_endpoint = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 2,
        .max_stateless_reset_tokens = 1,
    });
    defer step_endpoint.deinit();
    var step_backend = InitialOutputBackend{};
    const step_record = try std.testing.allocator.create(TestRecord);
    var step_record_initialized = false;
    var step_record_owned_by_test = true;
    errdefer {
        if (step_record_owned_by_test) {
            if (step_record_initialized) step_record.deinit();
            std.testing.allocator.destroy(step_record);
        }
    }
    step_record.* = .{
        .handle = 84,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = step_backend.backend(),
    };
    step_record_initialized = true;
    var step_classification_out: [256]u8 = undefined;
    var step_scratch: [256]u8 = undefined;
    var step_initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var step_handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    var step_installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var step_pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const step = try step_endpoint.receiveDatagramStepWithRoutePathAndInitialRecordAdmission(
        std.testing.allocator,
        path,
        3,
        initial_datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &step_classification_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        step_record.handle,
        step_record,
        server_scid,
        .{ .active_migration_disabled = true },
        &step_scratch,
        &[_]u8{},
        &step_initial_out,
        &step_handshake_out,
        &step_installed_key_out,
        .application,
        &step_pending_out,
    );
    switch (step.process) {
        .accept_initial => {},
        else => return error.TestUnexpectedResult,
    }
    const step_admission = step.admission orelse return error.TestUnexpectedResult;
    switch (step_admission) {
        .admitted => |step_admitted| {
            step_record_owned_by_test = false;
            try std.testing.expect(step_backend.received_initial);
            try std.testing.expect(step_admitted.initial.path.eql(path));
            try std.testing.expectEqual(@as(usize, 1), step_admitted.initial.accepted.drain.datagrams_written);
            try std.testing.expectEqual(@as(?root.Error, null), step_admitted.initial.accepted.drain.first_error);
            defer std.testing.allocator.free(step_initial_out[0].datagram);
            try std.testing.expectEqual(step_record.handle, step_initial_out[0].connection_id);
            try std.testing.expectEqual(@as(?TestEndpoint.CryptoBackendDatagramDrainPathResult, null), step_admitted.handshake);
        },
        .dropped_capacity => return error.TestUnexpectedResult,
    }
    try std.testing.expect(step_endpoint.records.get(step_record.handle) != null);
    try std.testing.expect((try step_endpoint.lifecycle.currentRoutePath(server_scid)).eql(path));
    try std.testing.expectEqual(@as(?root.Error, null), step.pending_drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), step.pending_drain.first_route_error);

    var scratch_step_endpoint = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 2,
        .max_stateless_reset_tokens = 1,
    });
    defer scratch_step_endpoint.deinit();
    var scratch_step_backend = InitialOutputBackend{};
    const scratch_step_record = try std.testing.allocator.create(TestRecord);
    var scratch_step_record_initialized = false;
    var scratch_step_record_owned_by_test = true;
    errdefer {
        if (scratch_step_record_owned_by_test) {
            if (scratch_step_record_initialized) scratch_step_record.deinit();
            std.testing.allocator.destroy(scratch_step_record);
        }
    }
    scratch_step_record.* = .{
        .handle = 86,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = scratch_step_backend.backend(),
    };
    scratch_step_record_initialized = true;
    var scratch_step_classification_out: [256]u8 = undefined;
    var scratch_step_scratch: [256]u8 = undefined;
    var scratch_step_initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var scratch_step_handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    var scratch_step_installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var scratch_step_pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const scratch_step = try scratch_step_endpoint.receiveDatagramStepWithRoutePathAndInitialRecordAdmissionWithScratch(
        path,
        5,
        initial_datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &scratch_step_classification_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        scratch_step_record.handle,
        scratch_step_record,
        server_scid,
        .{ .active_migration_disabled = true },
        &scratch_step_scratch,
        &[_]u8{},
        &scratch_step_initial_out,
        &scratch_step_handshake_out,
        &scratch_step_installed_key_out,
        .application,
        &scratch_step_pending_out,
    );
    switch (scratch_step.process) {
        .accept_initial => {},
        else => return error.TestUnexpectedResult,
    }
    const scratch_step_admission = scratch_step.admission orelse return error.TestUnexpectedResult;
    switch (scratch_step_admission) {
        .admitted => |scratch_step_admitted| {
            scratch_step_record_owned_by_test = false;
            try std.testing.expect(scratch_step_backend.received_initial);
            try std.testing.expect(scratch_step_admitted.initial.path.eql(path));
            try std.testing.expectEqual(@as(usize, 1), scratch_step_admitted.initial.accepted.drain.datagrams_written);
            try std.testing.expectEqual(@as(?root.Error, null), scratch_step_admitted.initial.accepted.drain.first_error);
            defer std.testing.allocator.free(scratch_step_initial_out[0].datagram);
            try std.testing.expectEqual(scratch_step_record.handle, scratch_step_initial_out[0].connection_id);
            try std.testing.expectEqual(@as(?TestEndpoint.CryptoBackendDatagramDrainPathResult, null), scratch_step_admitted.handshake);
        },
        .dropped_capacity => return error.TestUnexpectedResult,
    }
    try std.testing.expect(scratch_step_endpoint.records.get(scratch_step_record.handle) != null);
    try std.testing.expect((try scratch_step_endpoint.lifecycle.currentRoutePath(server_scid)).eql(path));
    try std.testing.expectEqual(@as(?root.Error, null), scratch_step.pending_drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), scratch_step.pending_drain.first_route_error);

    var dynamic_scratch_endpoint = TestEndpoint.init(std.testing.allocator);
    defer dynamic_scratch_endpoint.deinit();
    var dynamic_scratch_backend = InitialOutputBackend{};
    const dynamic_scratch_record = try std.testing.allocator.create(TestRecord);
    var dynamic_scratch_record_initialized = false;
    defer {
        if (dynamic_scratch_record_initialized) dynamic_scratch_record.deinit();
        std.testing.allocator.destroy(dynamic_scratch_record);
    }
    dynamic_scratch_record.* = .{
        .handle = 87,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = dynamic_scratch_backend.backend(),
    };
    dynamic_scratch_record_initialized = true;
    var dynamic_scratch_classification_out: [256]u8 = undefined;
    var dynamic_scratch_scratch: [256]u8 = undefined;
    var dynamic_scratch_initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var dynamic_scratch_handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    var dynamic_scratch_installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var dynamic_scratch_pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    try std.testing.expectError(error.BufferTooSmall, dynamic_scratch_endpoint.receiveDatagramStepWithRoutePathAndInitialRecordAdmissionWithScratch(
        path,
        6,
        initial_datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &dynamic_scratch_classification_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        dynamic_scratch_record.handle,
        dynamic_scratch_record,
        server_scid,
        .{ .active_migration_disabled = true },
        &dynamic_scratch_scratch,
        &[_]u8{},
        &dynamic_scratch_initial_out,
        &dynamic_scratch_handshake_out,
        &dynamic_scratch_installed_key_out,
        .application,
        &dynamic_scratch_pending_out,
    ));
    try std.testing.expect(!dynamic_scratch_backend.received_initial);
    try std.testing.expect(dynamic_scratch_endpoint.records.get(dynamic_scratch_record.handle) == null);
    try std.testing.expectEqual(@as(usize, 0), dynamic_scratch_endpoint.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), dynamic_scratch_endpoint.activeConnectionCount());

    var full_step_endpoint = try TestEndpoint.initWithCapacity(std.testing.allocator, 0, .{
        .max_routes = 0,
        .max_stateless_reset_tokens = 0,
    });
    defer full_step_endpoint.deinit();
    var capacity_backend = InitialOutputBackend{};
    const capacity_record = try std.testing.allocator.create(TestRecord);
    var capacity_record_initialized = false;
    defer {
        if (capacity_record_initialized) capacity_record.deinit();
        std.testing.allocator.destroy(capacity_record);
    }
    capacity_record.* = .{
        .handle = 85,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = capacity_backend.backend(),
    };
    capacity_record_initialized = true;
    var capacity_classification_out: [256]u8 = undefined;
    var capacity_scratch: [256]u8 = undefined;
    var capacity_initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var capacity_handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    var capacity_installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var capacity_pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const capacity_step = try full_step_endpoint.receiveDatagramStepWithRoutePathAndInitialRecordAdmission(
        std.testing.allocator,
        path,
        4,
        initial_datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &capacity_classification_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        capacity_record.handle,
        capacity_record,
        server_scid,
        .{ .active_migration_disabled = true },
        &capacity_scratch,
        &[_]u8{},
        &capacity_initial_out,
        &capacity_handshake_out,
        &capacity_installed_key_out,
        .application,
        &capacity_pending_out,
    );
    switch (capacity_step.process) {
        .accept_initial => {},
        else => return error.TestUnexpectedResult,
    }
    const capacity_admission = capacity_step.admission orelse return error.TestUnexpectedResult;
    switch (capacity_admission) {
        .dropped_capacity => |dropped| {
            try std.testing.expectEqual(@as(usize, 0), dropped.active_connections);
            try std.testing.expectEqual(@as(usize, 0), dropped.active_connection_limit);
        },
        .admitted => return error.TestUnexpectedResult,
    }
    try std.testing.expect(!capacity_backend.received_initial);
    try std.testing.expect(full_step_endpoint.records.get(capacity_record.handle) == null);
    try std.testing.expectEqual(@as(usize, 0), full_step_endpoint.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), full_step_endpoint.activeConnectionCount());
}

test "Tls13ServerEndpoint pairs due recovery output with committed route path" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "initial";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 1,
        .max_stateless_reset_tokens = 1,
    });
    defer endpoint_owner.deinit();

    const old_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const new_path = endpoint.Udp4Tuple{
        .local = old_path.local,
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_444),
    };
    const server_dcid = "local";
    const secrets = try protection.deriveInitialSecrets(.v1, "endpoint-due");
    var empty_backend = EmptyBackend{};

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 82,
        .connection = try Connection.init(std.testing.allocator, .server, .{ .initial_rtt_ms = 100 }),
        .backend = empty_backend.backend(),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    try record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, old_path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;

    try record.connection.sendPing();
    const first = (try endpoint_owner.pollOneRttDatagram(record.handle, 10)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(first);
    const deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, deadline.kind);
    try std.testing.expectEqual(record.handle, deadline.connection_id);

    _ = try endpoint_owner.lifecycle.updateRoutePathFromValidatedDatagramAndResetSpinBit(
        server_dcid,
        new_path,
        &record.connection,
    );

    var zero_due_out: [0]TestEndpoint.DatagramPathResult = .{};
    try std.testing.expectError(error.BufferTooSmall, endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePathWithScratch(
        deadline.deadline_millis,
        &zero_due_out,
    ));
    const zero_preserved_deadline = (try endpoint_owner.nextDeadlineWithScratch()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, zero_preserved_deadline.kind);
    try std.testing.expectEqual(record.handle, zero_preserved_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, zero_preserved_deadline.recovery.?.space);

    var due_out: [1]TestEndpoint.DatagramPathResult = undefined;
    try std.testing.expect(try endpoint_owner.lifecycle.retireConnectionIdOnPath(server_dcid, new_path));
    const missing_route_due = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePath(
        std.testing.allocator,
        deadline.deadline_millis,
        &due_out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, missing_route_due.deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, missing_route_due.deadline.kind);
    try std.testing.expect(missing_route_due.pending_work.recovery_serviced == null);
    try std.testing.expectEqual(@as(usize, 0), missing_route_due.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), missing_route_due.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), missing_route_due.drain.first_route_error);
    const allocator_preserved_deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, allocator_preserved_deadline.kind);
    try std.testing.expectEqual(record.handle, allocator_preserved_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, allocator_preserved_deadline.recovery.?.space);

    const missing_route_due_scratch = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePathWithScratch(
        deadline.deadline_millis,
        &due_out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, missing_route_due_scratch.deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, missing_route_due_scratch.deadline.kind);
    try std.testing.expect(missing_route_due_scratch.pending_work.recovery_serviced == null);
    try std.testing.expectEqual(@as(usize, 0), missing_route_due_scratch.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), missing_route_due_scratch.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), missing_route_due_scratch.drain.first_route_error);
    const preserved_deadline = (try endpoint_owner.nextDeadlineWithScratch()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, preserved_deadline.kind);
    try std.testing.expectEqual(record.handle, preserved_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, preserved_deadline.recovery.?.space);
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, new_path, .{});

    const due = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePathWithScratch(
        deadline.deadline_millis,
        &due_out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, due.deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, due.deadline.kind);
    const serviced = due.pending_work.recovery_serviced orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, serviced.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, serviced.timer.space);
    try std.testing.expectEqual(@as(usize, 1), due.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), due.drain.first_error);
    defer std.testing.allocator.free(due_out[0].datagram);
    try std.testing.expectEqual(record.handle, due_out[0].connection_id);
    try std.testing.expect(due_out[0].path.eql(new_path));
    try std.testing.expect(due_out[0].datagram.len != 0);
    const next_deadline = due.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, next_deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, next_deadline.kind);
}

test "Tls13ServerEndpoint route preflight reclaims closed records before route errors" {
    const TestRecord = struct {
        handle: u64,
        local_id: []const u8,
        peer_id: []const u8,
        connection: Connection,
        backend: root.CryptoBackend,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(self: *const @This()) []const u8 {
            return self.peer_id;
        }

        fn sourceConnectionId(self: *const @This()) []const u8 {
            return self.local_id;
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "initial";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 2, .{
        .max_routes = 2,
        .max_stateless_reset_tokens = 2,
    });
    defer endpoint_owner.deinit();

    const stale_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const live_path = endpoint.Udp4Tuple{
        .local = stale_path.local,
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_444),
    };
    const secrets = try protection.deriveInitialSecrets(.v1, "preflight-cleanup");
    var empty_backend = EmptyBackend{};

    const stale_record = try std.testing.allocator.create(TestRecord);
    var stale_initialized = false;
    var stale_owned = true;
    errdefer {
        if (stale_owned) {
            if (stale_initialized) stale_record.deinit();
            std.testing.allocator.destroy(stale_record);
        }
    }
    stale_record.* = .{
        .handle = 301,
        .local_id = "stale-local",
        .peer_id = "stale-peer",
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    stale_initialized = true;
    try endpoint_owner.lifecycle.registerConnectionId(stale_record.handle, stale_record.local_id, stale_path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(stale_record.handle);
    const stale_handle = stale_record.handle;
    stale_record.connection.state = .closed;
    stale_record.connection.closed = true;
    try endpoint_owner.records.adopt(stale_handle, stale_record);
    stale_owned = false;

    const live_record = try std.testing.allocator.create(TestRecord);
    var live_initialized = false;
    var live_owned = true;
    errdefer {
        if (live_owned) {
            if (live_initialized) live_record.deinit();
            std.testing.allocator.destroy(live_record);
        }
    }
    live_record.* = .{
        .handle = 302,
        .local_id = "live-local",
        .peer_id = "live-peer",
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    live_initialized = true;
    try live_record.connection.validatePeerAddress();
    try live_record.connection.confirmHandshake();
    try live_record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    const live_handle = live_record.handle;
    try endpoint_owner.lifecycle.registerConnectionId(live_handle, live_record.local_id, live_path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(live_handle);
    _ = try live_record.connection.recordPacketSentInSpace(.application, 10, 100);
    try endpoint_owner.lifecycle.armRecoveryTimerFromConnection(live_handle, &live_record.connection);
    const live_deadline = live_record.connection.lossDetectionTimerDeadlineMillis() orelse return error.TestUnexpectedResult;
    try endpoint_owner.records.adopt(live_handle, live_record);
    live_owned = false;

    try std.testing.expectEqual(@as(usize, 2), endpoint_owner.records.count());
    try std.testing.expectEqual(@as(usize, 2), endpoint_owner.lifecycle.routeCount());
    try std.testing.expect(try endpoint_owner.lifecycle.retireConnectionIdOnPath("live-local", live_path));
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());

    var out: [1]TestEndpoint.DatagramPathResult = undefined;
    const result = try endpoint_owner.processPendingWorkAndDrainDatagramsWithRoutePathWithScratch(
        live_deadline.deadline_millis,
        .application,
        &out,
    );
    try std.testing.expectEqual(@as(usize, 0), result.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), result.pending_work.close_retired_count);
    try std.testing.expectEqual(@as(usize, 0), result.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), result.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), result.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), result.drain.first_route_error);
    try std.testing.expect(endpoint_owner.records.get(stale_handle) == null);
    try std.testing.expect(endpoint_owner.records.get(live_handle) != null);
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.records.count());
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.recoveryTimerCount());
    const preserved_deadline = result.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(live_handle, preserved_deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, preserved_deadline.kind);
}

test "Tls13ServerEndpoint polls active record output with committed route path" {
    const TestRecord = struct {
        handle: u64,
        local_id: []const u8,
        peer_id: []const u8,
        connection: Connection,
        backend: root.CryptoBackend,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(self: *const @This()) []const u8 {
            return self.peer_id;
        }

        fn sourceConnectionId(self: *const @This()) []const u8 {
            return self.local_id;
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "initial";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 2, .{
        .max_routes = 2,
        .max_stateless_reset_tokens = 2,
    });
    defer endpoint_owner.deinit();

    const first_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const second_path = endpoint.Udp4Tuple{
        .local = first_path.local,
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_444),
    };
    const secrets = try protection.deriveInitialSecrets(.v1, "endpoint-poll");
    var empty_backend = EmptyBackend{};

    const first_record = try std.testing.allocator.create(TestRecord);
    var first_initialized = false;
    var first_owned = true;
    errdefer {
        if (first_owned) {
            if (first_initialized) first_record.deinit();
            std.testing.allocator.destroy(first_record);
        }
    }
    first_record.* = .{
        .handle = 91,
        .local_id = "local-a",
        .peer_id = "peer-a",
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    first_initialized = true;
    try first_record.connection.validatePeerAddress();
    try first_record.connection.confirmHandshake();
    try first_record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try first_record.connection.sendPing();
    try endpoint_owner.lifecycle.registerConnectionId(first_record.handle, first_record.local_id, first_path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(first_record.handle);
    try endpoint_owner.records.adopt(first_record.handle, first_record);
    first_owned = false;

    const second_record = try std.testing.allocator.create(TestRecord);
    var second_initialized = false;
    var second_owned = true;
    errdefer {
        if (second_owned) {
            if (second_initialized) second_record.deinit();
            std.testing.allocator.destroy(second_record);
        }
    }
    second_record.* = .{
        .handle = 92,
        .local_id = "local-b",
        .peer_id = "peer-b",
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    second_initialized = true;
    try second_record.connection.validatePeerAddress();
    try second_record.connection.confirmHandshake();
    try second_record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try second_record.connection.sendPing();
    try endpoint_owner.lifecycle.registerConnectionId(second_record.handle, second_record.local_id, second_path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(second_record.handle);
    try endpoint_owner.records.adopt(second_record.handle, second_record);
    second_owned = false;

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const polled = (try endpoint_owner.pollDatagramWithRoutePath(
        no_allocation_allocator.allocator(),
        10,
        .application,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(polled.datagram);
    try std.testing.expect(polled.connection_id == first_record.handle or polled.connection_id == second_record.handle);
    if (polled.connection_id == first_record.handle) {
        try std.testing.expect(polled.path.eql(first_path));
    } else {
        try std.testing.expect(polled.path.eql(second_path));
    }
    try std.testing.expect(polled.datagram.len != 0);

    const next_polled = (try endpoint_owner.pollDatagramWithRoutePath(
        no_allocation_allocator.allocator(),
        11,
        .application,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(next_polled.datagram);
    try std.testing.expect(next_polled.connection_id == first_record.handle or next_polled.connection_id == second_record.handle);
    try std.testing.expect(next_polled.connection_id != polled.connection_id);
    if (next_polled.connection_id == first_record.handle) {
        try std.testing.expect(next_polled.path.eql(first_path));
    } else {
        try std.testing.expect(next_polled.path.eql(second_path));
    }
    try std.testing.expect(next_polled.datagram.len != 0);

    try std.testing.expect((try endpoint_owner.pollDatagramWithRoutePath(
        no_allocation_allocator.allocator(),
        12,
        .application,
    )) == null);

    try second_record.connection.sendPing();
    var zero_drain_out: [0]TestEndpoint.DatagramPathResult = .{};
    const zero_drain = endpoint_owner.drainDatagramsAcrossRecordsWithRoutePath(
        no_allocation_allocator.allocator(),
        13,
        .application,
        &zero_drain_out,
    );
    try std.testing.expectEqual(@as(usize, 0), zero_drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), zero_drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), zero_drain.first_route_error);

    var drain_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const drain = endpoint_owner.drainDatagramsAcrossRecordsWithRoutePath(
        no_allocation_allocator.allocator(),
        14,
        .application,
        &drain_out,
    );
    try std.testing.expectEqual(@as(usize, 1), drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), drain.first_route_error);
    defer std.testing.allocator.free(drain_out[0].datagram);
    try std.testing.expectEqual(second_record.handle, drain_out[0].connection_id);
    try std.testing.expect(drain_out[0].path.eql(second_path));
    try std.testing.expect(drain_out[0].datagram.len != 0);

    const empty_drain = endpoint_owner.drainDatagramsAcrossRecordsWithRoutePath(
        no_allocation_allocator.allocator(),
        15,
        .application,
        &drain_out,
    );
    try std.testing.expectEqual(@as(usize, 0), empty_drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), empty_drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), empty_drain.first_route_error);

    try second_record.connection.sendPing();
    _ = endpoint_owner.lifecycle.retireConnection(second_record.handle);
    try std.testing.expectError(
        error.UnknownConnectionId,
        endpoint_owner.pollDatagramWithRoutePath(
            no_allocation_allocator.allocator(),
            16,
            .application,
        ),
    );
    try endpoint_owner.lifecycle.registerConnectionId(second_record.handle, second_record.local_id, second_path, .{});
    const preserved_poll = (try endpoint_owner.pollDatagramWithRoutePath(
        no_allocation_allocator.allocator(),
        17,
        .application,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(preserved_poll.datagram);
    try std.testing.expectEqual(second_record.handle, preserved_poll.connection_id);
    try std.testing.expect(preserved_poll.path.eql(second_path));
    try std.testing.expect(preserved_poll.datagram.len != 0);

    try second_record.connection.sendPing();
    _ = endpoint_owner.lifecycle.retireConnection(second_record.handle);
    const missing_route_drain = endpoint_owner.drainDatagramsAcrossRecordsWithRoutePath(
        no_allocation_allocator.allocator(),
        18,
        .application,
        &drain_out,
    );
    try std.testing.expectEqual(@as(usize, 0), missing_route_drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), missing_route_drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), missing_route_drain.first_route_error);
    try endpoint_owner.lifecycle.registerConnectionId(second_record.handle, second_record.local_id, second_path, .{});
    var preserved_drain_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const preserved_drain = endpoint_owner.drainDatagramsAcrossRecordsWithRoutePath(
        no_allocation_allocator.allocator(),
        19,
        .application,
        &preserved_drain_out,
    );
    try std.testing.expectEqual(@as(usize, 1), preserved_drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), preserved_drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), preserved_drain.first_route_error);
    defer std.testing.allocator.free(preserved_drain_out[0].datagram);
    try std.testing.expectEqual(second_record.handle, preserved_drain_out[0].connection_id);
    try std.testing.expect(preserved_drain_out[0].path.eql(second_path));
    try std.testing.expect(preserved_drain_out[0].datagram.len != 0);

    try second_record.connection.sendPing();
    const recovery_first = (try endpoint_owner.pollDatagramWithRoutePathWithScratch(
        20,
        .application,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(recovery_first.datagram);
    const deadline = (try endpoint_owner.nextDeadline(no_allocation_allocator.allocator())) orelse return error.TestUnexpectedResult;
    try std.testing.expect(deadline.connection_id == first_record.handle or deadline.connection_id == second_record.handle);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, deadline.kind);
    try std.testing.expectEqual(root.PacketNumberSpace.application, deadline.recovery.?.space);

    var pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const recovery_local_id = if (deadline.connection_id == first_record.handle) first_record.local_id else second_record.local_id;
    const recovery_path = if (deadline.connection_id == first_record.handle) first_path else second_path;
    try std.testing.expect(try endpoint_owner.lifecycle.retireConnectionIdOnPath(recovery_local_id, recovery_path));
    const mismatched_space_pending = try endpoint_owner.processPendingWorkAndDrainDatagramsWithRoutePath(
        no_allocation_allocator.allocator(),
        deadline.deadline_millis,
        .handshake,
        &pending_out,
    );
    try std.testing.expectEqual(@as(usize, 0), mismatched_space_pending.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), mismatched_space_pending.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), mismatched_space_pending.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), mismatched_space_pending.drain.first_route_error);
    const mismatched_preserved_deadline = mismatched_space_pending.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, mismatched_preserved_deadline.kind);
    try std.testing.expectEqual(deadline.connection_id, mismatched_preserved_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, mismatched_preserved_deadline.recovery.?.space);

    const missing_route_pending = try endpoint_owner.processPendingWorkAndDrainDatagramsWithRoutePath(
        no_allocation_allocator.allocator(),
        deadline.deadline_millis,
        .application,
        &pending_out,
    );
    try std.testing.expectEqual(@as(usize, 0), missing_route_pending.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), missing_route_pending.pending_work.close_retired_count);
    try std.testing.expectEqual(@as(usize, 0), missing_route_pending.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), missing_route_pending.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), missing_route_pending.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), missing_route_pending.drain.first_route_error);
    const preserved_deadline = missing_route_pending.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, preserved_deadline.kind);
    try std.testing.expectEqual(deadline.connection_id, preserved_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, preserved_deadline.recovery.?.space);

    var zero_missing_route_pending_out: [0]TestEndpoint.DatagramPathResult = .{};
    const zero_missing_route_pending = try endpoint_owner.processPendingWorkAndDrainDatagramsWithRoutePath(
        no_allocation_allocator.allocator(),
        deadline.deadline_millis,
        .application,
        &zero_missing_route_pending_out,
    );
    try std.testing.expectEqual(@as(usize, 0), zero_missing_route_pending.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), zero_missing_route_pending.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), zero_missing_route_pending.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), zero_missing_route_pending.drain.first_route_error);
    const zero_missing_route_deadline = zero_missing_route_pending.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, zero_missing_route_deadline.kind);
    try std.testing.expectEqual(deadline.connection_id, zero_missing_route_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, zero_missing_route_deadline.recovery.?.space);

    const unsupported_initial = [_]u8{
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
    var missing_route_poll_out: [128]u8 = undefined;
    const missing_route_poll = try endpoint_owner.feedDatagramWithInstalledKeysAndProcessPendingWorkAndPollDatagramWithRoutePathWithScratch(
        first_path,
        deadline.deadline_millis,
        &unsupported_initial,
        .{
            .space = .application,
            .out = &missing_route_poll_out,
            .unpredictable_prefix = &.{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        .application,
    );
    switch (missing_route_poll.feed) {
        .version_negotiation => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 0), missing_route_poll.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), missing_route_poll.pending_work.close_retired_count);
    try std.testing.expectEqual(@as(usize, 0), missing_route_poll.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), missing_route_poll.pending_route_error);
    try std.testing.expect(missing_route_poll.datagram == null);
    const missing_route_poll_deadline = (try endpoint_owner.nextDeadlineWithScratch()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, missing_route_poll_deadline.kind);
    try std.testing.expectEqual(deadline.connection_id, missing_route_poll_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, missing_route_poll_deadline.recovery.?.space);

    var missing_route_step_out: [128]u8 = undefined;
    var missing_route_scratch: [64]u8 = undefined;
    var missing_route_initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var missing_route_handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    var missing_route_installed_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var missing_route_step_pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const missing_route_step = try endpoint_owner.receiveDatagramStepWithRoutePath(
        no_allocation_allocator.allocator(),
        first_path,
        deadline.deadline_millis,
        &unsupported_initial,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &missing_route_step_out,
            .unpredictable_prefix = &.{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &missing_route_scratch,
        &[_]u8{},
        &missing_route_initial_out,
        &missing_route_handshake_out,
        &missing_route_installed_out,
        .application,
        &missing_route_step_pending_out,
    );
    switch (missing_route_step.process) {
        .version_negotiation => |response| try std.testing.expect(response.path.eql(first_path)),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 0), missing_route_step.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), missing_route_step.pending_work.close_retired_count);
    try std.testing.expectEqual(@as(usize, 0), missing_route_step.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), missing_route_step.pending_drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), missing_route_step.pending_drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), missing_route_step.pending_drain.first_route_error);
    const missing_route_step_deadline = missing_route_step.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, missing_route_step_deadline.kind);
    try std.testing.expectEqual(deadline.connection_id, missing_route_step_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, missing_route_step_deadline.recovery.?.space);

    const missing_route_step_scratch = try endpoint_owner.receiveDatagramStepWithRoutePathWithScratch(
        first_path,
        deadline.deadline_millis,
        &unsupported_initial,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &missing_route_step_out,
            .unpredictable_prefix = &.{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &missing_route_scratch,
        &[_]u8{},
        &missing_route_initial_out,
        &missing_route_handshake_out,
        &missing_route_installed_out,
        .application,
        &missing_route_step_pending_out,
    );
    switch (missing_route_step_scratch.process) {
        .version_negotiation => |response| try std.testing.expect(response.path.eql(first_path)),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 0), missing_route_step_scratch.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), missing_route_step_scratch.pending_drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), missing_route_step_scratch.pending_drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), missing_route_step_scratch.pending_drain.first_route_error);
    const missing_route_step_scratch_deadline = missing_route_step_scratch.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, missing_route_step_scratch_deadline.kind);
    try std.testing.expectEqual(deadline.connection_id, missing_route_step_scratch_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, missing_route_step_scratch_deadline.recovery.?.space);

    var zero_missing_route_step_pending_out: [0]TestEndpoint.DatagramPathResult = .{};
    const zero_missing_route_step = try endpoint_owner.receiveDatagramStepWithRoutePath(
        no_allocation_allocator.allocator(),
        first_path,
        deadline.deadline_millis,
        &unsupported_initial,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &missing_route_step_out,
            .unpredictable_prefix = &.{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &missing_route_scratch,
        &[_]u8{},
        &missing_route_initial_out,
        &missing_route_handshake_out,
        &missing_route_installed_out,
        .application,
        &zero_missing_route_step_pending_out,
    );
    switch (zero_missing_route_step.process) {
        .version_negotiation => |response| try std.testing.expect(response.path.eql(first_path)),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 0), zero_missing_route_step.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), zero_missing_route_step.pending_drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), zero_missing_route_step.pending_drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), zero_missing_route_step.pending_drain.first_route_error);
    const zero_missing_route_step_deadline = zero_missing_route_step.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, zero_missing_route_step_deadline.kind);
    try std.testing.expectEqual(deadline.connection_id, zero_missing_route_step_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, zero_missing_route_step_deadline.recovery.?.space);

    try endpoint_owner.lifecycle.registerConnectionId(deadline.connection_id, recovery_local_id, recovery_path, .{});

    var zero_pending_out: [0]TestEndpoint.DatagramPathResult = .{};
    const zero_pending_scratch = try endpoint_owner.processPendingWorkAndDrainDatagramsWithRoutePathWithScratch(
        deadline.deadline_millis,
        .application,
        &zero_pending_out,
    );
    try std.testing.expectEqual(@as(usize, 0), zero_pending_scratch.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), zero_pending_scratch.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, error.BufferTooSmall), zero_pending_scratch.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), zero_pending_scratch.drain.first_route_error);
    const zero_pending_scratch_deadline = zero_pending_scratch.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, zero_pending_scratch_deadline.kind);
    try std.testing.expectEqual(deadline.connection_id, zero_pending_scratch_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, zero_pending_scratch_deadline.recovery.?.space);

    const zero_pending = try endpoint_owner.processPendingWorkAndDrainDatagramsWithRoutePath(
        no_allocation_allocator.allocator(),
        deadline.deadline_millis,
        .application,
        &zero_pending_out,
    );
    try std.testing.expectEqual(@as(usize, 0), zero_pending.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), zero_pending.pending_work.close_retired_count);
    try std.testing.expectEqual(@as(usize, 0), zero_pending.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), zero_pending.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, error.BufferTooSmall), zero_pending.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), zero_pending.drain.first_route_error);
    const zero_pending_deadline = zero_pending.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, zero_pending_deadline.kind);
    try std.testing.expectEqual(deadline.connection_id, zero_pending_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, zero_pending_deadline.recovery.?.space);

    const pending_drain = try endpoint_owner.processPendingWorkAndDrainDatagramsWithRoutePath(
        no_allocation_allocator.allocator(),
        deadline.deadline_millis,
        .application,
        &pending_out,
    );
    try std.testing.expectEqual(@as(usize, 0), pending_drain.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), pending_drain.pending_work.close_retired_count);
    try std.testing.expectEqual(@as(usize, 1), pending_drain.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 1), pending_drain.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), pending_drain.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), pending_drain.drain.first_route_error);
    defer std.testing.allocator.free(pending_out[0].datagram);
    try std.testing.expectEqual(deadline.connection_id, pending_out[0].connection_id);
    if (pending_out[0].connection_id == first_record.handle) {
        try std.testing.expect(pending_out[0].path.eql(first_path));
    } else {
        try std.testing.expect(pending_out[0].path.eql(second_path));
    }
    try std.testing.expect(pending_out[0].datagram.len != 0);
    const next_deadline = pending_drain.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, next_deadline.kind);

    try second_record.connection.sendPing();
    const step_first = (try endpoint_owner.pollDatagramWithRoutePath(
        no_allocation_allocator.allocator(),
        20,
        .application,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(step_first.datagram);
    const step_deadline = (try endpoint_owner.nextDeadline(no_allocation_allocator.allocator())) orelse return error.TestUnexpectedResult;
    try std.testing.expect(step_deadline.connection_id == first_record.handle or step_deadline.connection_id == second_record.handle);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, step_deadline.kind);

    var route_out: [128]u8 = undefined;
    var scratch: [64]u8 = undefined;
    var initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    var installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var zero_step_pending_out: [0]TestEndpoint.DatagramPathResult = .{};
    const zero_step = try endpoint_owner.receiveDatagramStepWithRoutePath(
        no_allocation_allocator.allocator(),
        first_path,
        step_deadline.deadline_millis,
        &unsupported_initial,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &route_out,
            .unpredictable_prefix = &.{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &scratch,
        &[_]u8{},
        &initial_out,
        &handshake_out,
        &installed_key_out,
        .application,
        &zero_step_pending_out,
    );
    switch (zero_step.process) {
        .version_negotiation => |response| try std.testing.expect(response.path.eql(first_path)),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 0), zero_step.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), zero_step.pending_work.close_retired_count);
    try std.testing.expectEqual(@as(usize, 0), zero_step.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), zero_step.pending_drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, error.BufferTooSmall), zero_step.pending_drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), zero_step.pending_drain.first_route_error);
    const zero_step_deadline = zero_step.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, zero_step_deadline.kind);
    try std.testing.expectEqual(step_deadline.connection_id, zero_step_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, zero_step_deadline.recovery.?.space);

    var step_pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const step = try endpoint_owner.receiveDatagramStepWithRoutePath(
        no_allocation_allocator.allocator(),
        first_path,
        step_deadline.deadline_millis,
        &unsupported_initial,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &route_out,
            .unpredictable_prefix = &.{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &scratch,
        &[_]u8{},
        &initial_out,
        &handshake_out,
        &installed_key_out,
        .application,
        &step_pending_out,
    );
    switch (step.process) {
        .version_negotiation => |response| try std.testing.expect(response.path.eql(first_path)),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 0), step.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), step.pending_work.close_retired_count);
    try std.testing.expectEqual(@as(usize, 1), step.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 1), step.pending_drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), step.pending_drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), step.pending_drain.first_route_error);
    defer std.testing.allocator.free(step_pending_out[0].datagram);
    try std.testing.expectEqual(step_deadline.connection_id, step_pending_out[0].connection_id);
    if (step_pending_out[0].connection_id == first_record.handle) {
        try std.testing.expect(step_pending_out[0].path.eql(first_path));
    } else {
        try std.testing.expect(step_pending_out[0].path.eql(second_path));
    }
    try std.testing.expect(step_pending_out[0].datagram.len != 0);
    const step_next_deadline = step.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, step_next_deadline.kind);

    try first_record.connection.sendPing();
    var terminal_close_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const terminal_close = try endpoint_owner.closeWithRoutePathAndDrainDatagrams(
        no_allocation_allocator.allocator(),
        second_record.handle,
        0,
        @intFromEnum(frame.FrameType.ping),
        "done",
        30,
        &terminal_close_out,
    );
    try std.testing.expectEqual(@as(usize, 1), terminal_close.drain.datagrams_written);
    defer std.testing.allocator.free(terminal_close_out[0].datagram);
    const close_deadline = (try endpoint_owner.closeDeadlineMillis(second_record.handle)) orelse return error.TestUnexpectedResult;
    const terminal_record_handle = second_record.handle;
    try std.testing.expectError(error.ConnectionClosed, second_record.connection.checkCloseTimeouts(close_deadline));
    try std.testing.expectEqual(connection_module.ConnectionState.closed, second_record.connection.connectionState());
    var terminal_poll_views: [2]root.EndpointConnectionPollView = undefined;
    const terminal_views = try endpoint_owner.records.fillPollViews(
        &terminal_poll_views,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
    );
    for (terminal_views, 0..) |view, index| {
        if (view.connection_id == terminal_record_handle) {
            endpoint_owner.records.next_poll_index = index;
            break;
        }
    }
    const terminal_skipped = (try endpoint_owner.pollDatagramWithRoutePath(
        no_allocation_allocator.allocator(),
        close_deadline,
        .application,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(terminal_skipped.datagram);
    try std.testing.expectEqual(first_record.handle, terminal_skipped.connection_id);
    try std.testing.expect(terminal_skipped.path.eql(first_path));
    try std.testing.expect(terminal_skipped.datagram.len != 0);
    try std.testing.expect(endpoint_owner.records.get(terminal_record_handle) == null);
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());
}

test "Tls13ServerEndpoint pairs Initial due recovery output with committed route path" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "client01";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "server01";
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "origin01";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 1,
        .max_stateless_reset_tokens = 1,
    });
    defer endpoint_owner.deinit();

    const old_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const new_path = endpoint.Udp4Tuple{
        .local = old_path.local,
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_444),
    };
    const server_dcid = "server01";
    const client_dcid = "client01";
    const initial_dcid = "origin01";
    const secrets = try protection.deriveInitialSecrets(.v1, initial_dcid);
    var empty_backend = EmptyBackend{};

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 83,
        .connection = try Connection.init(std.testing.allocator, .server, .{ .initial_rtt_ms = 100 }),
        .backend = empty_backend.backend(),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.sendPingInSpace(.initial);
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, old_path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;

    const first = (try record.connection.pollProtectedLongDatagram(
        10,
        client_dcid,
        server_dcid,
        &[_]u8{},
        .{ .initial = secrets.server },
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(first);
    try endpoint_owner.lifecycle.armRecoveryTimerFromConnection(record.handle, &record.connection);

    const deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, deadline.kind);
    try std.testing.expectEqual(record.handle, deadline.connection_id);
    const timer = deadline.recovery orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.PacketNumberSpace.initial, timer.space);

    _ = try endpoint_owner.lifecycle.updateRoutePathFromValidatedDatagramAndResetSpinBit(
        server_dcid,
        new_path,
        &record.connection,
    );

    var zero_due_out: [0]TestEndpoint.DatagramPathResult = .{};
    try std.testing.expectError(error.BufferTooSmall, endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePathWithScratch(
        deadline.deadline_millis,
        &zero_due_out,
    ));
    const zero_preserved_deadline = (try endpoint_owner.nextDeadlineWithScratch()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, zero_preserved_deadline.kind);
    try std.testing.expectEqual(record.handle, zero_preserved_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.initial, zero_preserved_deadline.recovery.?.space);

    var due_out: [1]TestEndpoint.DatagramPathResult = undefined;
    try std.testing.expect(try endpoint_owner.lifecycle.retireConnectionIdOnPath(server_dcid, new_path));
    const missing_route_due = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePath(
        std.testing.allocator,
        deadline.deadline_millis,
        &due_out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, missing_route_due.deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, missing_route_due.deadline.kind);
    try std.testing.expect(missing_route_due.pending_work.recovery_serviced == null);
    try std.testing.expectEqual(@as(usize, 0), missing_route_due.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), missing_route_due.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), missing_route_due.drain.first_route_error);
    const allocator_preserved_deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, allocator_preserved_deadline.kind);
    try std.testing.expectEqual(record.handle, allocator_preserved_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.initial, allocator_preserved_deadline.recovery.?.space);

    const missing_route_due_scratch = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePathWithScratch(
        deadline.deadline_millis,
        &due_out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, missing_route_due_scratch.deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, missing_route_due_scratch.deadline.kind);
    try std.testing.expect(missing_route_due_scratch.pending_work.recovery_serviced == null);
    try std.testing.expectEqual(@as(usize, 0), missing_route_due_scratch.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), missing_route_due_scratch.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), missing_route_due_scratch.drain.first_route_error);
    const preserved_deadline = (try endpoint_owner.nextDeadlineWithScratch()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, preserved_deadline.kind);
    try std.testing.expectEqual(record.handle, preserved_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.initial, preserved_deadline.recovery.?.space);
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, new_path, .{});

    const due = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePathWithScratch(
        deadline.deadline_millis,
        &due_out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, due.deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, due.deadline.kind);
    const serviced = due.pending_work.recovery_serviced orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, serviced.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.initial, serviced.timer.space);
    try std.testing.expectEqual(@as(usize, 1), due.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), due.drain.first_error);
    defer std.testing.allocator.free(due_out[0].datagram);
    try std.testing.expectEqual(record.handle, due_out[0].connection_id);
    try std.testing.expect(due_out[0].path.eql(new_path));
    const info = try protection.peekProtectedLongPacketInfo(due_out[0].datagram);
    try std.testing.expectEqual(quic_packet.PacketType.initial, info.packet_type);
    const next_deadline = due.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, next_deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, next_deadline.kind);
}

test "Tls13ServerEndpoint drains Initial due recovery output without route metadata" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "client01";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "server01";
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "origin01";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 1,
        .max_stateless_reset_tokens = 1,
    });
    defer endpoint_owner.deinit();

    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const server_dcid = "server01";
    const client_dcid = "client01";
    const initial_dcid = "origin01";
    const secrets = try protection.deriveInitialSecrets(.v1, initial_dcid);
    var empty_backend = EmptyBackend{};

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 84,
        .connection = try Connection.init(std.testing.allocator, .server, .{ .initial_rtt_ms = 100 }),
        .backend = empty_backend.backend(),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.sendPingInSpace(.initial);
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;

    const first = (try record.connection.pollProtectedLongDatagram(
        10,
        client_dcid,
        server_dcid,
        &[_]u8{},
        .{ .initial = secrets.server },
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(first);
    try endpoint_owner.lifecycle.armRecoveryTimerFromConnection(record.handle, &record.connection);

    const deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, deadline.kind);
    const timer = deadline.recovery orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.PacketNumberSpace.initial, timer.space);

    var zero_due_out: [0]root.EndpointPolledDatagramResult = .{};
    try std.testing.expectError(error.BufferTooSmall, endpoint_owner.processDueDeadlineAndDrainDatagramsWithScratch(
        deadline.deadline_millis,
        &zero_due_out,
    ));
    const preserved_deadline = (try endpoint_owner.nextDeadlineWithScratch()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, preserved_deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, preserved_deadline.kind);
    try std.testing.expectEqual(root.PacketNumberSpace.initial, preserved_deadline.recovery.?.space);

    var due_out: [1]root.EndpointPolledDatagramResult = undefined;
    const due = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithScratch(
        deadline.deadline_millis,
        &due_out,
    )) orelse return error.TestUnexpectedResult;
    const serviced = due.pending_work.recovery_serviced orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, serviced.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.initial, serviced.timer.space);
    try std.testing.expectEqual(@as(usize, 1), due.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), due.drain.first_error);
    defer std.testing.allocator.free(due_out[0].datagram);
    try std.testing.expectEqual(record.handle, due_out[0].connection_id);
    const info = try protection.peekProtectedLongPacketInfo(due_out[0].datagram);
    try std.testing.expectEqual(quic_packet.PacketType.initial, info.packet_type);
    const next_deadline = due.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, next_deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, next_deadline.kind);
}

test "Tls13ServerEndpoint retires record when idle deadline closes server" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "initial";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 1,
        .max_stateless_reset_tokens = 1,
    });
    defer endpoint_owner.deinit();

    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const server_dcid = "local";
    const secrets = try protection.deriveInitialSecrets(.v1, "endpoint-idle");
    var empty_backend = EmptyBackend{};

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 85,
        .connection = try Connection.init(std.testing.allocator, .server, .{ .max_idle_timeout_ms = 10 }),
        .backend = empty_backend.backend(),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    try record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;
    const record_handle = record.handle;

    try record.connection.sendPing();
    const first = (try endpoint_owner.pollOneRttDatagram(record_handle, 10)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(first);
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.recoveryTimerCount());

    const idle_deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.idle_timeout, idle_deadline.kind);
    try std.testing.expectEqual(record_handle, idle_deadline.connection_id);
    try std.testing.expectEqual(@as(i64, 20), idle_deadline.deadline_millis);

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    var out: [1]root.EndpointPolledDatagramResult = undefined;
    try std.testing.expect((try endpoint_owner.processDueDeadlineAndDrainDatagrams(
        no_allocation_allocator.allocator(),
        19,
        &out,
    )) == null);
    try std.testing.expect(endpoint_owner.records.get(record_handle) != null);
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());

    const due = (try endpoint_owner.processDueDeadlineAndDrainDatagrams(
        no_allocation_allocator.allocator(),
        20,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.idle_timeout, due.deadline.kind);
    try std.testing.expect(due.pending_work.idle_retired != null);
    try std.testing.expectEqual(@as(?root.EndpointConnectionRetireResult, null), due.pending_work.close_retired);
    try std.testing.expectEqual(@as(usize, 0), due.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.EndpointConnectionDeadline, null), due.next_deadline);
    try std.testing.expect(endpoint_owner.records.get(record_handle) == null);
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.recoveryTimerCount());
}

test "Tls13ServerEndpoint receive step retires idle record while reporting input" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "initial";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 1,
        .max_stateless_reset_tokens = 1,
    });
    defer endpoint_owner.deinit();

    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const server_dcid = "local";
    const secrets = try protection.deriveInitialSecrets(.v1, "endpoint-step-idle");
    var empty_backend = EmptyBackend{};

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 87,
        .connection = try Connection.init(std.testing.allocator, .server, .{ .max_idle_timeout_ms = 10 }),
        .backend = empty_backend.backend(),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    try record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;
    const record_handle = record.handle;

    try record.connection.sendPing();
    const first = (try endpoint_owner.pollOneRttDatagram(record_handle, 10)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(first);
    const idle_deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.idle_timeout, idle_deadline.kind);
    try std.testing.expectEqual(record_handle, idle_deadline.connection_id);

    const unsupported_initial = [_]u8{
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
    var route_out: [128]u8 = undefined;
    var scratch: [64]u8 = undefined;
    var initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    var installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const step = try endpoint_owner.receiveDatagramStepWithRoutePath(
        no_allocation_allocator.allocator(),
        path,
        idle_deadline.deadline_millis,
        &unsupported_initial,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &route_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &scratch,
        &[_]u8{},
        &initial_out,
        &handshake_out,
        &installed_key_out,
        .application,
        &pending_out,
    );
    switch (step.process) {
        .version_negotiation => |response| try std.testing.expect(response.path.eql(path)),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 1), step.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), step.pending_work.close_retired_count);
    try std.testing.expectEqual(@as(usize, 0), step.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), step.pending_drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.EndpointConnectionDeadline, null), step.next_deadline);
    try std.testing.expect(endpoint_owner.records.get(record_handle) == null);
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.activeConnectionCount());
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.recoveryTimerCount());
}

test "Tls13ServerEndpoint receive step reports key discard while reporting input" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "initial";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 1,
        .max_stateless_reset_tokens = 1,
    });
    defer endpoint_owner.deinit();

    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const server_dcid = "local";
    var empty_backend = EmptyBackend{};

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 88,
        .connection = try Connection.init(std.testing.allocator, .server, .{ .initial_rtt_ms = 100 }),
        .backend = empty_backend.backend(),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    const local_secret = [_]u8{0x6a} ** protection.traffic_secret_len;
    const peer_secret = [_]u8{0x6b} ** protection.traffic_secret_len;
    try record.connection.installOneRttTrafficSecrets(.{
        .local = local_secret,
        .peer = peer_secret,
    });
    record.connection.last_packet_activity_millis = 10;
    try record.connection.initiateOneRttKeyUpdate();
    try std.testing.expectEqual(@as(?bool, true), record.connection.localOneRttRetainsKeyGeneration(0));
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;
    const record_handle = record.handle;

    const discard_deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.key_discard, discard_deadline.kind);
    try std.testing.expectEqual(record_handle, discard_deadline.connection_id);

    const unsupported_initial = [_]u8{
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
    var route_out: [128]u8 = undefined;
    var scratch: [64]u8 = undefined;
    var initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    var installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const step = try endpoint_owner.receiveDatagramStepWithRoutePath(
        no_allocation_allocator.allocator(),
        path,
        discard_deadline.deadline_millis,
        &unsupported_initial,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &route_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &scratch,
        &[_]u8{},
        &initial_out,
        &handshake_out,
        &installed_key_out,
        .application,
        &pending_out,
    );
    switch (step.process) {
        .version_negotiation => |response| try std.testing.expect(response.path.eql(path)),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 0), step.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), step.pending_work.close_retired_count);
    try std.testing.expectEqual(@as(usize, 1), step.pending_work.key_discard_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), step.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), step.pending_drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.EndpointConnectionDeadline, null), step.next_deadline);
    const retained = endpoint_owner.records.get(record_handle) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?bool, false), retained.connection.localOneRttRetainsKeyGeneration(0));
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.activeConnectionCount());
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());
}

test "Tls13ServerEndpoint services key discard deadline without input" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "initial";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 1,
        .max_stateless_reset_tokens = 1,
    });
    defer endpoint_owner.deinit();

    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const server_dcid = "local";
    var empty_backend = EmptyBackend{};

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 89,
        .connection = try Connection.init(std.testing.allocator, .server, .{ .initial_rtt_ms = 100 }),
        .backend = empty_backend.backend(),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    const local_secret = [_]u8{0x6c} ** protection.traffic_secret_len;
    const peer_secret = [_]u8{0x6d} ** protection.traffic_secret_len;
    try record.connection.installOneRttTrafficSecrets(.{
        .local = local_secret,
        .peer = peer_secret,
    });
    record.connection.last_packet_activity_millis = 10;
    try record.connection.initiateOneRttKeyUpdate();
    try std.testing.expectEqual(@as(?u64, 1), record.connection.localOneRttKeyUpdateCount());
    try std.testing.expectEqual(@as(?bool, true), record.connection.localOneRttRetainsKeyGeneration(0));
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;
    const record_handle = record.handle;

    const discard_deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.key_discard, discard_deadline.kind);
    try std.testing.expectEqual(record_handle, discard_deadline.connection_id);
    try std.testing.expect((try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePath(
        std.testing.allocator,
        discard_deadline.deadline_millis - 1,
        &.{},
    )) == null);

    var pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const due = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePath(
        std.testing.allocator,
        discard_deadline.deadline_millis,
        &pending_out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.key_discard, due.deadline.kind);
    try std.testing.expectEqual(record_handle, due.deadline.connection_id);
    try std.testing.expectEqual(@as(?root.EndpointConnectionRetireResult, null), due.pending_work.idle_retired);
    try std.testing.expectEqual(@as(?root.EndpointConnectionRetireResult, null), due.pending_work.close_retired);
    try std.testing.expect(due.pending_work.key_discard_serviced);
    try std.testing.expectEqual(@as(?root.EndpointLossDetectionTimerDeadline, null), due.pending_work.recovery_serviced);
    try std.testing.expectEqual(@as(usize, 0), due.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.EndpointConnectionDeadline, null), due.next_deadline);

    const retained = endpoint_owner.records.get(record_handle) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?bool, false), retained.connection.localOneRttRetainsKeyGeneration(0));
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.activeConnectionCount());
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());
}

test "Tls13ServerEndpoint drains key discard deadline without route path" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "initial";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 1,
        .max_stateless_reset_tokens = 1,
    });
    defer endpoint_owner.deinit();

    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const server_dcid = "local";
    var empty_backend = EmptyBackend{};

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 90,
        .connection = try Connection.init(std.testing.allocator, .server, .{ .initial_rtt_ms = 100 }),
        .backend = empty_backend.backend(),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    const local_secret = [_]u8{0x6e} ** protection.traffic_secret_len;
    const peer_secret = [_]u8{0x6f} ** protection.traffic_secret_len;
    try record.connection.installOneRttTrafficSecrets(.{
        .local = local_secret,
        .peer = peer_secret,
    });
    record.connection.last_packet_activity_millis = 10;
    try record.connection.initiateOneRttKeyUpdate();
    try std.testing.expectEqual(@as(?u64, 1), record.connection.localOneRttKeyUpdateCount());
    try std.testing.expectEqual(@as(?bool, true), record.connection.localOneRttRetainsKeyGeneration(0));
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;
    const record_handle = record.handle;

    const discard_deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.key_discard, discard_deadline.kind);
    try std.testing.expectEqual(record_handle, discard_deadline.connection_id);
    var out: [1]root.EndpointPolledDatagramResult = undefined;
    try std.testing.expect((try endpoint_owner.processDueDeadlineAndDrainDatagrams(
        std.testing.allocator,
        discard_deadline.deadline_millis - 1,
        &out,
    )) == null);

    const due = (try endpoint_owner.processDueDeadlineAndDrainDatagrams(
        std.testing.allocator,
        discard_deadline.deadline_millis,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.key_discard, due.deadline.kind);
    try std.testing.expectEqual(record_handle, due.deadline.connection_id);
    try std.testing.expectEqual(@as(?root.EndpointConnectionRetireResult, null), due.pending_work.idle_retired);
    try std.testing.expectEqual(@as(?root.EndpointConnectionRetireResult, null), due.pending_work.close_retired);
    try std.testing.expect(due.pending_work.key_discard_serviced);
    try std.testing.expectEqual(@as(?root.EndpointLossDetectionTimerDeadline, null), due.pending_work.recovery_serviced);
    try std.testing.expectEqual(@as(usize, 0), due.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.EndpointConnectionDeadline, null), due.next_deadline);

    const retained = endpoint_owner.records.get(record_handle) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(?bool, false), retained.connection.localOneRttRetainsKeyGeneration(0));
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.activeConnectionCount());
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());
}

test "Tls13ServerEndpoint sweeps pending work and keeps next live deadline" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,
        destination_connection_id: []const u8,
        source_connection_id: []const u8,
        initial_destination_connection_id: []const u8,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(self: *const @This()) []const u8 {
            return self.destination_connection_id;
        }

        fn sourceConnectionId(self: *const @This()) []const u8 {
            return self.source_connection_id;
        }

        fn initialDestinationConnectionId(self: *const @This()) []const u8 {
            return self.initial_destination_connection_id;
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 2, .{
        .max_routes = 2,
        .max_stateless_reset_tokens = 2,
    });
    defer endpoint_owner.deinit();
    var dynamic_endpoint = TestEndpoint.init(std.testing.allocator);
    defer dynamic_endpoint.deinit();
    try std.testing.expectError(
        error.BufferTooSmall,
        dynamic_endpoint.processPendingWorkAndSelectNextDeadlineWithScratch(20),
    );

    var empty_backend = EmptyBackend{};
    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const secrets = try protection.deriveInitialSecrets(.v1, "sweep-id");

    const idle_record = try std.testing.allocator.create(TestRecord);
    var idle_initialized = false;
    var idle_owned = true;
    errdefer {
        if (idle_owned) {
            if (idle_initialized) idle_record.deinit();
            std.testing.allocator.destroy(idle_record);
        }
    }
    idle_record.* = .{
        .handle = 91,
        .connection = try Connection.init(std.testing.allocator, .server, .{ .max_idle_timeout_ms = 10 }),
        .backend = empty_backend.backend(),
        .destination_connection_id = "peer-a",
        .source_connection_id = "local-a",
        .initial_destination_connection_id = "initial-a",
    };
    idle_initialized = true;
    try idle_record.connection.validatePeerAddress();
    try idle_record.connection.confirmHandshake();
    try idle_record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try idle_record.connection.sendPing();
    const idle_first = (try idle_record.connection.pollProtectedShortDatagramWithInstalledKeys(
        10,
        idle_record.destination_connection_id,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(idle_first);
    try endpoint_owner.lifecycle.registerConnectionId(
        idle_record.handle,
        idle_record.source_connection_id,
        path,
        .{},
    );
    errdefer _ = endpoint_owner.lifecycle.retireConnection(idle_record.handle);
    try endpoint_owner.records.adopt(idle_record.handle, idle_record);
    idle_owned = false;

    const live_record = try std.testing.allocator.create(TestRecord);
    var live_initialized = false;
    var live_owned = true;
    errdefer {
        if (live_owned) {
            if (live_initialized) live_record.deinit();
            std.testing.allocator.destroy(live_record);
        }
    }
    live_record.* = .{
        .handle = 92,
        .connection = try Connection.init(std.testing.allocator, .server, .{ .max_idle_timeout_ms = 100 }),
        .backend = empty_backend.backend(),
        .destination_connection_id = "peer-b",
        .source_connection_id = "local-b",
        .initial_destination_connection_id = "initial-b",
    };
    live_initialized = true;
    try live_record.connection.validatePeerAddress();
    try live_record.connection.confirmHandshake();
    try live_record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try live_record.connection.sendPing();
    const live_first = (try live_record.connection.pollProtectedShortDatagramWithInstalledKeys(
        10,
        live_record.destination_connection_id,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(live_first);
    try endpoint_owner.lifecycle.registerConnectionId(
        live_record.handle,
        live_record.source_connection_id,
        path,
        .{},
    );
    errdefer _ = endpoint_owner.lifecycle.retireConnection(live_record.handle);
    try endpoint_owner.records.adopt(live_record.handle, live_record);
    live_owned = false;

    try std.testing.expectEqual(@as(usize, 2), endpoint_owner.activeConnectionCount());
    const first_deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(idle_record.handle, first_deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.idle_timeout, first_deadline.kind);
    try std.testing.expectEqual(@as(i64, 20), first_deadline.deadline_millis);

    const swept = try endpoint_owner.processPendingWorkAndSelectNextDeadlineWithScratch(20);
    try std.testing.expectEqual(@as(usize, 1), swept.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), swept.pending_work.close_retired_count);
    try std.testing.expect(endpoint_owner.records.get(91) == null);
    try std.testing.expect(endpoint_owner.records.get(92) != null);
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.activeConnectionCount());
    const next = swept.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 92), next.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.idle_timeout, next.kind);
    try std.testing.expectEqual(@as(i64, 110), next.deadline_millis);
}

test "Tls13ServerEndpoint closes with route output and retires record at close deadline" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "initial";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 1,
        .max_stateless_reset_tokens = 1,
    });
    defer endpoint_owner.deinit();

    const old_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const new_path = endpoint.Udp4Tuple{
        .local = old_path.local,
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_444),
    };
    const server_dcid = "local";
    const secrets = try protection.deriveInitialSecrets(.v1, "endpoint-close");
    var empty_backend = EmptyBackend{};

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 84,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    try record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, old_path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;
    const record_handle = record.handle;

    _ = try endpoint_owner.lifecycle.updateRoutePathFromValidatedDatagramAndResetSpinBit(
        server_dcid,
        new_path,
        &record.connection,
    );
    const close_datagram = (try endpoint_owner.closeWithRoutePath(record_handle, 0, 0, "server done", 10)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(close_datagram.datagram);
    try std.testing.expect(close_datagram.path.eql(new_path));
    try std.testing.expect(close_datagram.datagram.len != 0);

    const close_deadline = (try endpoint_owner.closeDeadlineMillis(record_handle)) orelse return error.TestUnexpectedResult;
    const deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.close_timeout, deadline.kind);
    try std.testing.expectEqual(record_handle, deadline.connection_id);
    try std.testing.expectEqual(close_deadline, deadline.deadline_millis);

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    var due_out: [1]TestEndpoint.DatagramPathResult = undefined;
    try std.testing.expect((try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePath(
        no_allocation_allocator.allocator(),
        close_deadline - 1,
        &due_out,
    )) == null);
    const due = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePath(
        no_allocation_allocator.allocator(),
        close_deadline,
        &due_out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.close_timeout, due.deadline.kind);
    try std.testing.expect(due.pending_work.close_retired != null);
    try std.testing.expectEqual(@as(?root.EndpointConnectionRetireResult, null), due.pending_work.idle_retired);
    try std.testing.expectEqual(@as(usize, 0), due.drain.datagrams_written);
    try std.testing.expect(endpoint_owner.records.get(record_handle) == null);
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.routeCount());
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.closeDeadlineMillis(record_handle));
}

test "Tls13ServerEndpoint drains close output with route and deadline" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,
        destination_connection_id: []const u8,
        source_connection_id: []const u8,
        initial_destination_connection_id: []const u8,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(self: *const @This()) []const u8 {
            return self.destination_connection_id;
        }

        fn sourceConnectionId(self: *const @This()) []const u8 {
            return self.source_connection_id;
        }

        fn initialDestinationConnectionId(self: *const @This()) []const u8 {
            return self.initial_destination_connection_id;
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 2, .{
        .max_routes = 2,
        .max_stateless_reset_tokens = 2,
    });
    defer endpoint_owner.deinit();

    const old_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const new_path = endpoint.Udp4Tuple{
        .local = old_path.local,
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_444),
    };
    const other_path = endpoint.Udp4Tuple{
        .local = old_path.local,
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_445),
    };
    const other_secrets = try protection.deriveInitialSecrets(.v1, "close-other");
    const secrets = try protection.deriveInitialSecrets(.v1, "server-close-drain");
    var empty_backend = EmptyBackend{};

    const other_record = try std.testing.allocator.create(TestRecord);
    var other_record_initialized = false;
    var other_record_owned = true;
    errdefer {
        if (other_record_owned) {
            if (other_record_initialized) other_record.deinit();
            std.testing.allocator.destroy(other_record);
        }
    }
    other_record.* = .{
        .handle = 84,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
        .destination_connection_id = "peer-other",
        .source_connection_id = "local-other",
        .initial_destination_connection_id = "initial-other",
    };
    other_record_initialized = true;
    try other_record.connection.validatePeerAddress();
    try other_record.connection.confirmHandshake();
    try other_record.connection.installOneRttTrafficSecrets(.{
        .local = other_secrets.server.secret,
        .peer = other_secrets.client.secret,
    });
    try other_record.connection.sendPing();
    try endpoint_owner.lifecycle.registerConnectionId(
        other_record.handle,
        TestRecord.sourceConnectionId(other_record),
        other_path,
        .{},
    );
    errdefer _ = endpoint_owner.lifecycle.retireConnection(other_record.handle);
    try endpoint_owner.records.adopt(other_record.handle, other_record);
    other_record_owned = false;

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 85,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
        .destination_connection_id = "peer",
        .source_connection_id = "local",
        .initial_destination_connection_id = "initial",
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    try record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try endpoint_owner.lifecycle.registerConnectionId(
        record.handle,
        TestRecord.sourceConnectionId(record),
        old_path,
        .{},
    );
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;
    const record_handle = record.handle;

    _ = try endpoint_owner.lifecycle.updateRoutePathFromValidatedDatagramAndResetSpinBit(
        TestRecord.sourceConnectionId(record),
        new_path,
        &record.connection,
    );
    var poll_views: [2]root.EndpointConnectionPollView = undefined;
    const views = try endpoint_owner.records.fillPollViews(
        &poll_views,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
    );
    for (views, 0..) |view, index| {
        if (view.connection_id == other_record.handle) {
            endpoint_owner.records.next_poll_index = index;
            break;
        }
    }
    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    var zero_out: [0]TestEndpoint.DatagramPathResult = .{};
    try std.testing.expectError(error.BufferTooSmall, endpoint_owner.closeWithRoutePathAndDrainDatagrams(
        no_allocation_allocator.allocator(),
        record_handle,
        0,
        0,
        "server done",
        10,
        &zero_out,
    ));
    try std.testing.expectEqual(connection_module.ConnectionState.active, record.connection.connectionState());
    try std.testing.expectEqual(@as(?i64, null), try endpoint_owner.closeDeadlineMillis(record_handle));
    try std.testing.expectError(error.BufferTooSmall, endpoint_owner.closeWithRoutePathAndDrainDatagramsWithScratch(
        record_handle,
        0,
        0,
        "server done",
        10,
        &zero_out,
    ));
    try std.testing.expectEqual(connection_module.ConnectionState.active, record.connection.connectionState());
    try std.testing.expectEqual(@as(?i64, null), try endpoint_owner.closeDeadlineMillis(record_handle));

    var out: [2]TestEndpoint.DatagramPathResult = undefined;
    const closed = try endpoint_owner.closeWithRoutePathAndDrainDatagramsWithScratch(
        record_handle,
        0,
        0,
        "server done",
        10,
        &out,
    );
    try std.testing.expectEqual(@as(usize, 2), closed.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), closed.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), closed.drain.first_route_error);
    for (out[0..closed.drain.datagrams_written]) |drained| {
        defer std.testing.allocator.free(drained.datagram);
        try std.testing.expectEqual(record_handle, drained.connection_id);
        try std.testing.expect(drained.path.eql(new_path));
        try std.testing.expect(drained.datagram.len != 0);
    }
    const other_datagram = (try endpoint_owner.pollOneRttDatagramWithRoutePath(other_record.handle, 11)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(other_datagram.datagram);
    try std.testing.expect(other_datagram.path.eql(other_path));
    try std.testing.expect(other_datagram.datagram.len != 0);
    const next_deadline = closed.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.close_timeout, next_deadline.kind);
    try std.testing.expectEqual(record_handle, next_deadline.connection_id);
    try std.testing.expect((try endpoint_owner.closeDeadlineMillis(record_handle)) != null);
}

test "Tls13ServerEndpoint drains application close output with route and deadline" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,
        destination_connection_id: []const u8,
        source_connection_id: []const u8,
        initial_destination_connection_id: []const u8,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(self: *const @This()) []const u8 {
            return self.destination_connection_id;
        }

        fn sourceConnectionId(self: *const @This()) []const u8 {
            return self.source_connection_id;
        }

        fn initialDestinationConnectionId(self: *const @This()) []const u8 {
            return self.initial_destination_connection_id;
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 1,
        .max_stateless_reset_tokens = 1,
    });
    defer endpoint_owner.deinit();

    const old_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const new_path = endpoint.Udp4Tuple{
        .local = old_path.local,
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_444),
    };
    const secrets = try protection.deriveInitialSecrets(.v1, "server-app-close");
    var empty_backend = EmptyBackend{};
    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 86,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
        .destination_connection_id = "peer",
        .source_connection_id = "local",
        .initial_destination_connection_id = "initial",
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    try record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try endpoint_owner.lifecycle.registerConnectionId(
        record.handle,
        TestRecord.sourceConnectionId(record),
        old_path,
        .{},
    );
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;
    const record_handle = record.handle;

    _ = try endpoint_owner.lifecycle.updateRoutePathFromValidatedDatagramAndResetSpinBit(
        TestRecord.sourceConnectionId(record),
        new_path,
        &record.connection,
    );
    var zero_out: [0]TestEndpoint.DatagramPathResult = .{};
    try std.testing.expectError(error.BufferTooSmall, endpoint_owner.closeApplicationWithRoutePathAndDrainDatagramsWithScratch(
        record_handle,
        57,
        "server app done",
        10,
        &zero_out,
    ));
    try std.testing.expectEqual(connection_module.ConnectionState.active, record.connection.connectionState());
    try std.testing.expectEqual(@as(?i64, null), try endpoint_owner.closeDeadlineMillis(record_handle));

    var out: [1]TestEndpoint.DatagramPathResult = undefined;
    const closed = try endpoint_owner.closeApplicationWithRoutePathAndDrainDatagramsWithScratch(
        record_handle,
        57,
        "server app done",
        10,
        &out,
    );
    try std.testing.expectEqual(@as(usize, 1), closed.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), closed.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), closed.drain.first_route_error);
    defer std.testing.allocator.free(out[0].datagram);
    try std.testing.expectEqual(record_handle, out[0].connection_id);
    try std.testing.expect(out[0].path.eql(new_path));

    const local_keys = protection.deriveAes128PacketProtectionKeys(secrets.server.secret);
    var opened = try protection.unprotectShortPacketAes128(
        std.testing.allocator,
        local_keys,
        out[0].datagram,
        TestRecord.destinationConnectionId(record).len,
        0,
    );
    defer protection.deinitProtectedShortPacket(&opened, std.testing.allocator);
    var decoded = try frame.decodeFrameSlice(opened.packet.plaintext, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    switch (decoded.frame) {
        .application_close => |close| {
            try std.testing.expectEqual(@as(u64, 57), close.error_code);
            try std.testing.expectEqualStrings("server app done", close.reason_phrase);
        },
        else => return error.TestUnexpectedResult,
    }
    const next_deadline = closed.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.close_timeout, next_deadline.kind);
    try std.testing.expectEqual(record_handle, next_deadline.connection_id);
    try std.testing.expect((try endpoint_owner.closeDeadlineMillis(record_handle)) != null);
}

test "Tls13ServerEndpoint receive step retires closing record while reporting input" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "initial";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 1,
        .max_stateless_reset_tokens = 1,
    });
    defer endpoint_owner.deinit();

    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const server_dcid = "local";
    const secrets = try protection.deriveInitialSecrets(.v1, "endpoint-step-close");
    var empty_backend = EmptyBackend{};

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 89,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    try record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;
    const record_handle = record.handle;

    const close_datagram = (try endpoint_owner.closeWithRoutePath(record_handle, 0, 0, "server done", 10)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(close_datagram.datagram);
    try std.testing.expect(close_datagram.path.eql(path));
    const close_deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.close_timeout, close_deadline.kind);
    try std.testing.expectEqual(record_handle, close_deadline.connection_id);

    const unsupported_initial = [_]u8{
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
    var route_out: [128]u8 = undefined;
    var scratch: [64]u8 = undefined;
    var initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    var installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const step = try endpoint_owner.receiveDatagramStepWithRoutePath(
        no_allocation_allocator.allocator(),
        path,
        close_deadline.deadline_millis,
        &unsupported_initial,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &route_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &scratch,
        &[_]u8{},
        &initial_out,
        &handshake_out,
        &installed_key_out,
        .application,
        &pending_out,
    );
    switch (step.process) {
        .version_negotiation => |response| try std.testing.expect(response.path.eql(path)),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 0), step.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 1), step.pending_work.close_retired_count);
    try std.testing.expectEqual(@as(usize, 0), step.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), step.pending_drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.EndpointConnectionDeadline, null), step.next_deadline);
    try std.testing.expect(endpoint_owner.records.get(record_handle) == null);
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.activeConnectionCount());
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.routeCount());
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.closeDeadlineMillis(record_handle));
}

test "Tls13ServerEndpoint pairs path-update feed output with selected tuple" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "initial";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 1,
        .max_stateless_reset_tokens = 1,
    });
    defer endpoint_owner.deinit();

    const old_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 50_000),
    };
    const new_path = endpoint.Udp4Tuple{
        .local = old_path.local,
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 50_001),
    };
    const server_dcid = "local";
    const client_dcid = "peer";
    const secrets = try protection.deriveInitialSecrets(.v1, "endpoint");
    var empty_backend = EmptyBackend{};

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 88,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    try record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, old_path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;

    var client = try Connection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    try client.confirmHandshake();
    try client.installOneRttTrafficSecrets(.{
        .local = secrets.client.secret,
        .peer = secrets.server.secret,
    });

    const challenge_data = [_]u8{ 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb };
    const options = root.EndpointFeedInstalledKeyDatagramOptions{
        .space = .application,
        .out = &[_]u8{},
        .unpredictable_prefix = &[_]u8{},
        .supported_versions = &[_]quic_packet.Version{.v1},
        .path_challenge_data = challenge_data,
    };

    try client.sendPing();
    const migrated_ping = (try client.pollProtectedShortDatagramWithInstalledKeys(1, server_dcid)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(migrated_ping);
    const ping_result = try endpoint_owner.feedDatagramWithInstalledKeysAndUpdatePathOrCloseAndPollDatagram(
        new_path,
        2,
        migrated_ping,
        options,
    );
    try std.testing.expect(ping_result.feed.path_challenge_queued);
    try std.testing.expect((ping_result.output_path orelse return error.TestUnexpectedResult).eql(new_path));
    const challenge_packet = ping_result.datagram orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(challenge_packet.datagram);
    try std.testing.expectEqual(record.handle, challenge_packet.connection_id);

    try client.processProtectedShortDatagramWithInstalledKeys(3, client_dcid.len, challenge_packet.datagram);
    const response = (try client.pollProtectedShortDatagramWithInstalledKeys(4, server_dcid)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(response);
    const validation_result = try endpoint_owner.feedDatagramWithInstalledKeysAndUpdatePathOrCloseAndPollDatagram(
        new_path,
        5,
        response,
        options,
    );
    const updated_route = validation_result.feed.updated_route orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, updated_route.connection_id);
    try std.testing.expect((validation_result.output_path orelse return error.TestUnexpectedResult).eql(new_path));
    const ack_packet = validation_result.datagram orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(ack_packet.datagram);
    try std.testing.expectEqual(record.handle, ack_packet.connection_id);
    try std.testing.expect(!(try endpoint_owner.routeDatagram(new_path, response)).path_changed);

    try record.connection.sendPing();
    const committed_output = (try endpoint_owner.pollOneRttDatagramWithRoutePath(record.handle, 6)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(committed_output.datagram);
    try std.testing.expect(committed_output.path.eql(new_path));
    try std.testing.expect(committed_output.datagram.len != 0);

    try client.sendPing();
    const routed_ping = (try client.pollProtectedShortDatagramWithInstalledKeys(7, server_dcid)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(routed_ping);
    const routed_result = try endpoint_owner.feedInstalledKeyDatagramWithRoutePath(
        new_path,
        8,
        routed_ping,
        options,
    );
    try std.testing.expect((routed_result.feed orelse return error.TestUnexpectedResult).feed == .routed);
    const routed_ack = routed_result.datagram orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(routed_ack.datagram);
    try std.testing.expectEqual(record.handle, routed_ack.connection_id);
    try std.testing.expect(routed_ack.path.eql(new_path));
    const routed_next_deadline = routed_result.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, routed_next_deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, routed_next_deadline.kind);

    try record.connection.sendPing();
    const malformed_on_route = [_]u8{ 0x40, 'l', 'o', 'c', 'a', 'l', 0x00 };
    const malformed_result = try endpoint_owner.feedInstalledKeyDatagramWithRoutePath(
        new_path,
        9,
        &malformed_on_route,
        options,
    );
    try std.testing.expectEqual(@as(?root.EndpointProtectedDatagramError, error.InvalidPacket), malformed_result.feed_error);
    try std.testing.expect(malformed_result.feed == null);
    try std.testing.expectEqual(connection_module.ConnectionState.active, record.connection.connectionState());
    try std.testing.expect(malformed_result.datagram == null);
    const malformed_next_deadline = malformed_result.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, malformed_next_deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, malformed_next_deadline.kind);

    const queued_server_ping = (try endpoint_owner.pollOneRttDatagramWithRoutePath(record.handle, 10)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(queued_server_ping.datagram);
    try std.testing.expect(queued_server_ping.path.eql(new_path));
    try std.testing.expect(queued_server_ping.datagram.len != 0);

    const invalid_packet_number = record.connection.nextPeerPacketNumber(.application);
    const illegal_plaintext = [_]u8{@intFromEnum(frame.FrameType.handshake_done)} ++ ([_]u8{0} ** 31);
    const illegal_handshake_done = try protection.protectShortPacketAes128(std.testing.allocator, .{
        .dcid = server_dcid,
        .spin_bit = false,
        .key_phase = false,
        .packet_number = invalid_packet_number,
    }, try quic_packet.encodePacketNumberForHeader(invalid_packet_number, null), secrets.client, &illegal_plaintext);
    defer std.testing.allocator.free(illegal_handshake_done);

    const error_result = try endpoint_owner.feedInstalledKeyDatagramWithRoutePath(
        new_path,
        11,
        illegal_handshake_done,
        options,
    );
    try std.testing.expectEqual(@as(?root.EndpointProtectedDatagramError, error.InvalidPacket), error_result.feed_error);
    try std.testing.expect(error_result.feed == null);
    try std.testing.expectEqual(connection_module.ConnectionState.closing, record.connection.connectionState());

    const close_output = error_result.datagram orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(close_output.datagram);
    try std.testing.expectEqual(record.handle, close_output.connection_id);
    try std.testing.expect(close_output.path.eql(new_path));
    const close_next_deadline = error_result.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, close_next_deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.close_timeout, close_next_deadline.kind);
    try client.processProtectedShortDatagramWithInstalledKeys(12, client_dcid.len, close_output.datagram);
    try std.testing.expectEqual(connection_module.ConnectionState.draining, client.connectionState());
}

test "Tls13ServerEndpoint installed-key close output uses routed CID path when current route is missing" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,
        local_id: []const u8,
        routed_id: []const u8,
        peer_id: []const u8,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(self: *const @This()) []const u8 {
            return self.peer_id;
        }

        fn sourceConnectionId(self: *const @This()) []const u8 {
            return self.local_id;
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "initial";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );
    const IllegalHandshakeDone = struct {
        fn protect(allocator: std.mem.Allocator, dcid: []const u8, packet_number: u64, secret: protection.Aes128PacketProtectionKeys) ![]u8 {
            const illegal_plaintext = [_]u8{@intFromEnum(frame.FrameType.handshake_done)} ++ ([_]u8{0} ** 31);
            return protection.protectShortPacketAes128(allocator, .{
                .dcid = dcid,
                .spin_bit = false,
                .key_phase = false,
                .packet_number = packet_number,
            }, try quic_packet.encodePacketNumberForHeader(packet_number, null), secret, &illegal_plaintext);
        }
    };

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 4, .{
        .max_routes = 6,
        .max_stateless_reset_tokens = 4,
    });
    defer endpoint_owner.deinit();
    const first_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 50_010),
    };
    const second_path = endpoint.Udp4Tuple{
        .local = first_path.local,
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 50_011),
    };
    const secrets = try protection.deriveInitialSecrets(.v1, "close-route");
    var empty_backend = EmptyBackend{};

    const poll_record = try std.testing.allocator.create(TestRecord);
    poll_record.* = .{
        .handle = 101,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
        .local_id = "loc-a",
        .routed_id = "alt-a",
        .peer_id = "peer-a",
    };
    try poll_record.connection.validatePeerAddress();
    try poll_record.connection.confirmHandshake();
    try poll_record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try endpoint_owner.lifecycle.registerConnectionId(poll_record.handle, poll_record.local_id, first_path, .{});
    try endpoint_owner.lifecycle.registerConnectionId(poll_record.handle, poll_record.routed_id, first_path, .{});
    try endpoint_owner.records.adopt(poll_record.handle, poll_record);
    try std.testing.expect(try endpoint_owner.lifecycle.retireConnectionIdOnPath(poll_record.local_id, first_path));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.lifecycle.currentRoutePath(poll_record.local_id));
    const poll_illegal = try IllegalHandshakeDone.protect(
        std.testing.allocator,
        poll_record.routed_id,
        poll_record.connection.nextPeerPacketNumber(.application),
        secrets.client,
    );
    defer std.testing.allocator.free(poll_illegal);
    var route_out: [64]u8 = undefined;
    const options = root.EndpointFeedInstalledKeyDatagramOptions{
        .space = .application,
        .out = &route_out,
        .unpredictable_prefix = &[_]u8{},
        .supported_versions = &[_]quic_packet.Version{.v1},
    };
    const poll_result = try endpoint_owner.feedInstalledKeyDatagramWithRoutePath(
        first_path,
        1,
        poll_illegal,
        options,
    );
    try std.testing.expectEqual(@as(?root.EndpointProtectedDatagramError, error.InvalidPacket), poll_result.feed_error);
    const close_poll = poll_result.datagram orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(close_poll.datagram);
    try std.testing.expectEqual(poll_record.handle, close_poll.connection_id);
    try std.testing.expect(close_poll.path.eql(first_path));
    try std.testing.expectEqual(connection_module.ConnectionState.closing, poll_record.connection.connectionState());

    const drain_record = try std.testing.allocator.create(TestRecord);
    drain_record.* = .{
        .handle = 102,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
        .local_id = "loc-b",
        .routed_id = "alt-b",
        .peer_id = "peer-b",
    };
    try drain_record.connection.validatePeerAddress();
    try drain_record.connection.confirmHandshake();
    try drain_record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try endpoint_owner.lifecycle.registerConnectionId(drain_record.handle, drain_record.local_id, second_path, .{});
    try endpoint_owner.lifecycle.registerConnectionId(drain_record.handle, drain_record.routed_id, second_path, .{});
    try endpoint_owner.records.adopt(drain_record.handle, drain_record);
    try std.testing.expect(try endpoint_owner.lifecycle.retireConnectionIdOnPath(drain_record.local_id, second_path));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.lifecycle.currentRoutePath(drain_record.local_id));
    const drain_illegal = try IllegalHandshakeDone.protect(
        std.testing.allocator,
        drain_record.routed_id,
        drain_record.connection.nextPeerPacketNumber(.application),
        secrets.client,
    );
    defer std.testing.allocator.free(drain_illegal);
    var scratch: [64]u8 = undefined;
    var initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    var installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const drain_result = try endpoint_owner.processDatagramAndDrainWithRoutePath(
        second_path,
        2,
        drain_illegal,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        options,
        &scratch,
        &[_]u8{},
        &initial_out,
        &handshake_out,
        &installed_key_out,
    );
    const installed = switch (drain_result) {
        .routed => |routed| switch (routed) {
            .installed_key => |installed_key| installed_key,
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(?root.EndpointProtectedDatagramError, error.InvalidPacket), installed.feed_error);
    try std.testing.expectEqual(@as(usize, 1), installed.drain.datagrams_written);
    defer std.testing.allocator.free(installed_key_out[0].datagram);
    try std.testing.expectEqual(drain_record.handle, installed_key_out[0].connection_id);
    try std.testing.expect(installed_key_out[0].path.eql(second_path));
    try std.testing.expectEqual(connection_module.ConnectionState.closing, drain_record.connection.connectionState());

    const zero_path = endpoint.Udp4Tuple{
        .local = first_path.local,
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 50_012),
    };
    const zero_record = try std.testing.allocator.create(TestRecord);
    zero_record.* = .{
        .handle = 103,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
        .local_id = "loc-c",
        .routed_id = "alt-c",
        .peer_id = "peer-c",
    };
    try zero_record.connection.validatePeerAddress();
    try zero_record.connection.confirmHandshake();
    try zero_record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try endpoint_owner.lifecycle.registerConnectionId(zero_record.handle, zero_record.local_id, zero_path, .{});
    try endpoint_owner.records.adopt(zero_record.handle, zero_record);
    const zero_illegal = try IllegalHandshakeDone.protect(
        std.testing.allocator,
        zero_record.local_id,
        zero_record.connection.nextPeerPacketNumber(.application),
        secrets.client,
    );
    defer std.testing.allocator.free(zero_illegal);
    var zero_installed_key_out: [0]TestEndpoint.DatagramPathResult = .{};
    const zero_result = try endpoint_owner.processDatagramAndDrainWithRoutePath(
        zero_path,
        3,
        zero_illegal,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        options,
        &scratch,
        &[_]u8{},
        &initial_out,
        &handshake_out,
        &zero_installed_key_out,
    );
    const zero_installed = switch (zero_result) {
        .routed => |routed| switch (routed) {
            .installed_key => |installed_key| installed_key,
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(?root.EndpointProtectedDatagramError, error.InvalidPacket), zero_installed.feed_error);
    try std.testing.expectEqual(@as(usize, 0), zero_installed.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, error.BufferTooSmall), zero_installed.drain.first_error);
    try std.testing.expectEqual(connection_module.ConnectionState.closing, zero_record.connection.connectionState());
    const preserved_close = (try endpoint_owner.pollOneRttDatagramWithRoutePath(zero_record.handle, 4)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(preserved_close.datagram);
    try std.testing.expect(preserved_close.path.eql(zero_path));

    const receive_step_path = endpoint.Udp4Tuple{
        .local = first_path.local,
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 50_013),
    };
    const receive_step_record = try std.testing.allocator.create(TestRecord);
    receive_step_record.* = .{
        .handle = 104,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
        .local_id = "loc-d",
        .routed_id = "alt-d",
        .peer_id = "peer-d",
    };
    try receive_step_record.connection.validatePeerAddress();
    try receive_step_record.connection.confirmHandshake();
    try receive_step_record.connection.installOneRttTrafficSecrets(.{
        .local = secrets.server.secret,
        .peer = secrets.client.secret,
    });
    try endpoint_owner.lifecycle.registerConnectionId(receive_step_record.handle, receive_step_record.local_id, receive_step_path, .{});
    try endpoint_owner.records.adopt(receive_step_record.handle, receive_step_record);

    const ping_plaintext = [_]u8{@intFromEnum(frame.FrameType.ping)} ++ ([_]u8{0} ** 31);
    const ping_packet_number = receive_step_record.connection.nextPeerPacketNumber(.application);
    const ping_datagram = try protection.protectShortPacketAes128(std.testing.allocator, .{
        .dcid = receive_step_record.local_id,
        .spin_bit = false,
        .key_phase = false,
        .packet_number = ping_packet_number,
    }, try quic_packet.encodePacketNumberForHeader(ping_packet_number, null), secrets.client, &ping_plaintext);
    defer std.testing.allocator.free(ping_datagram);

    var zero_receive_step_installed_out: [0]TestEndpoint.DatagramPathResult = .{};
    var receive_step_pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const receive_step = try endpoint_owner.receiveDatagramStepWithRoutePath(
        std.testing.allocator,
        receive_step_path,
        5,
        ping_datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        options,
        &scratch,
        &[_]u8{},
        &initial_out,
        &handshake_out,
        &zero_receive_step_installed_out,
        .application,
        &receive_step_pending_out,
    );
    const receive_step_installed = switch (receive_step.process) {
        .routed => |routed| switch (routed) {
            .installed_key => |installed_key| installed_key,
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    };
    const receive_step_feed = receive_step_installed.feed orelse return error.TestUnexpectedResult;
    const receive_step_route = switch (receive_step_feed.feed) {
        .routed => |routed| routed,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(receive_step_record.handle, receive_step_route.connection_id);
    try std.testing.expectEqual(@as(usize, 0), receive_step_installed.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, error.BufferTooSmall), receive_step_installed.drain.first_error);
    try std.testing.expectEqual(connection_module.ConnectionState.active, receive_step_record.connection.connectionState());

    const preserved_ack = (try endpoint_owner.pollOneRttDatagramWithRoutePath(receive_step_record.handle, 6)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(preserved_ack.datagram);
    try std.testing.expect(preserved_ack.path.eql(receive_step_path));
}

test "Tls13ServerEndpoint bounded receive reports active stateless reset and retires record" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "initial";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 1,
        .max_stateless_reset_tokens = 1,
    });
    defer endpoint_owner.deinit();

    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const server_dcid = "local";
    const peer_connection_id = [_]u8{ 0xea, 0xeb, 0xec, 0xed };
    const reset_token = [_]u8{0xbb} ** quic_packet.stateless_reset_token_len;
    var empty_backend = EmptyBackend{};

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 86,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    record_initialized = true;

    var encoded: [64]u8 = undefined;
    var writer = buffer.fixedWriter(&encoded);
    try frame.encodeFrame(writer.writer(), .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = &peer_connection_id,
        .stateless_reset_token = reset_token,
    } });
    try record.connection.processDatagram(0, writer.getWritten());
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    _ = try record.connection.recordPacketSentInSpace(.application, 1, 64);
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;
    const record_handle = record.handle;
    try endpoint_owner.lifecycle.armRecoveryTimerFromConnection(record_handle, &record.connection);
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.recoveryTimerCount());

    var reset_prefix: [1 + server_dcid.len]u8 = undefined;
    reset_prefix[0] = 0x40;
    @memcpy(reset_prefix[1..], server_dcid);
    var reset_datagram: [64]u8 = undefined;
    var reset_writer = buffer.fixedWriter(&reset_datagram);
    try quic_packet.encodeStatelessReset(reset_writer.writer(), &reset_prefix, reset_token);

    var route_out: [64]u8 = undefined;
    var scratch: [64]u8 = undefined;
    var initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    var installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const reset_process = try endpoint_owner.processDatagramAndDrainWithRoutePath(
        path,
        10,
        reset_writer.getWritten(),
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &route_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &scratch,
        &[_]u8{},
        &initial_out,
        &handshake_out,
        &installed_key_out,
    );
    const reset = switch (reset_process) {
        .routed => |routed| switch (routed) {
            .installed_key => |installed_key| installed_key,
            .long => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    };
    const feed = reset.feed orelse return error.TestUnexpectedResult;
    try std.testing.expect(feed.feed == .dropped);
    try std.testing.expectEqual(@as(usize, 0), reset.drain.datagrams_written);
    try std.testing.expectEqual(@as(?u64, 0), reset.stateless_reset_sequence_number);
    const reset_next_deadline = reset.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record_handle, reset_next_deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.close_timeout, reset_next_deadline.kind);
    try std.testing.expectEqual(connection_module.ConnectionState.draining, record.connection.connectionState());
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.recoveryTimerCount());

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const deadline = (try endpoint_owner.nextDeadline(no_allocation_allocator.allocator())) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.close_timeout, deadline.kind);
    try std.testing.expectEqual(record_handle, deadline.connection_id);

    var due_out: [1]TestEndpoint.DatagramPathResult = undefined;
    try std.testing.expect((try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePath(
        no_allocation_allocator.allocator(),
        deadline.deadline_millis - 1,
        &due_out,
    )) == null);
    try std.testing.expect(endpoint_owner.records.get(record_handle) != null);

    const due = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePath(
        no_allocation_allocator.allocator(),
        deadline.deadline_millis,
        &due_out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(due.pending_work.close_retired != null);
    try std.testing.expectEqual(@as(usize, 0), due.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.EndpointConnectionDeadline, null), due.next_deadline);
    try std.testing.expect(endpoint_owner.records.get(record_handle) == null);
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.routeCount());
}

test "Tls13ServerEndpoint receive step reports active stateless reset and close deadline" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,
        backend: root.CryptoBackend,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.backend;
        }

        fn destinationConnectionId(_: *const @This()) []const u8 {
            return "peer";
        }

        fn sourceConnectionId(_: *const @This()) []const u8 {
            return "local";
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "initial";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.connection.deinit();
        }
    };
    const EmptyBackend = struct {
        fn backend(self: *@This()) root.CryptoBackend {
            return .{
                .context = self,
                .receive = receive,
                .pull = pull,
            };
        }

        fn receive(_: *anyopaque, _: root.PacketNumberSpace, _: []const u8) root.Error!void {}

        fn pull(_: *anyopaque, _: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
            return null;
        }
    };
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 1,
        .max_stateless_reset_tokens = 1,
    });
    defer endpoint_owner.deinit();

    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
    };
    const server_dcid = "local";
    const peer_connection_id = [_]u8{ 0xda, 0xdb, 0xdc, 0xdd };
    const reset_token = [_]u8{0xbc} ** quic_packet.stateless_reset_token_len;
    var empty_backend = EmptyBackend{};

    const record = try std.testing.allocator.create(TestRecord);
    var record_initialized = false;
    var record_owned = true;
    errdefer {
        if (record_owned) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = 87,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
        .backend = empty_backend.backend(),
    };
    record_initialized = true;

    var encoded: [64]u8 = undefined;
    var writer = buffer.fixedWriter(&encoded);
    try frame.encodeFrame(writer.writer(), .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = &peer_connection_id,
        .stateless_reset_token = reset_token,
    } });
    try record.connection.processDatagram(0, writer.getWritten());
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    _ = try record.connection.recordPacketSentInSpace(.application, 1, 64);
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;
    const record_handle = record.handle;
    try endpoint_owner.lifecycle.armRecoveryTimerFromConnection(record_handle, &record.connection);
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.recoveryTimerCount());

    var reset_prefix: [1 + server_dcid.len]u8 = undefined;
    reset_prefix[0] = 0x40;
    @memcpy(reset_prefix[1..], server_dcid);
    var reset_datagram: [64]u8 = undefined;
    var reset_writer = buffer.fixedWriter(&reset_datagram);
    try quic_packet.encodeStatelessReset(reset_writer.writer(), &reset_prefix, reset_token);

    var route_out: [64]u8 = undefined;
    var scratch: [64]u8 = undefined;
    var initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    var installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const step = try endpoint_owner.receiveDatagramStepWithRoutePath(
        std.testing.allocator,
        path,
        10,
        reset_writer.getWritten(),
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &route_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &scratch,
        &[_]u8{},
        &initial_out,
        &handshake_out,
        &installed_key_out,
        .application,
        &pending_out,
    );
    const reset = switch (step.process) {
        .routed => |routed| switch (routed) {
            .installed_key => |installed_key| installed_key,
            .long => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    };
    const feed = reset.feed orelse return error.TestUnexpectedResult;
    try std.testing.expect(feed.feed == .dropped);
    try std.testing.expectEqual(@as(?u64, 0), reset.stateless_reset_sequence_number);
    try std.testing.expectEqual(@as(usize, 0), reset.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), reset.drain.first_error);
    try std.testing.expectEqual(connection_module.ConnectionState.draining, record.connection.connectionState());
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.recoveryTimerCount());
    try std.testing.expectEqual(@as(usize, 0), step.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), step.pending_work.close_retired_count);
    try std.testing.expectEqual(@as(usize, 0), step.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), step.pending_drain.datagrams_written);

    const reset_next_deadline = reset.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record_handle, reset_next_deadline.connection_id);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.close_timeout, reset_next_deadline.kind);
    const step_next_deadline = step.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(reset_next_deadline, step_next_deadline);
}

test "Tls13 endpoints complete certificate-verified local handshake through endpoint routes" {
    const TestServerRecord = struct {
        handle: u64,
        transport: Tls13ServerTransport,
        retry_validated: bool = false,

        fn clientScid(self: *const @This()) []const u8 {
            return self.transport.connection.peerDestinationConnectionId() orelse
                self.transport.peerInitialSourceConnectionId();
        }

        fn connectionRef(self: *@This()) *Connection {
            return self.transport.connectionRef();
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.transport.cryptoBackend();
        }

        fn destinationConnectionId(self: *const @This()) []const u8 {
            return self.clientScid();
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
    const TestServerEndpoint = Tls13ServerEndpoint(
        TestServerRecord,
        TestServerRecord.connectionRef,
        TestServerRecord.cryptoBackend,
        TestServerRecord.destinationConnectionId,
        TestServerRecord.sourceConnectionId,
        TestServerRecord.initialDestinationConnectionId,
        TestServerRecord.markRetryValidated,
        TestServerRecord.deinit,
    );

    const pem = @embedFile("testdata/quicz-echo-ca.pem");
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    const begin = std.mem.indexOf(u8, pem, begin_marker) orelse return error.TestUnexpectedResult;
    const encoded_start = begin + begin_marker.len;
    const encoded_end = std.mem.indexOfPos(u8, pem, encoded_start, end_marker) orelse return error.TestUnexpectedResult;
    const encoded = std.mem.trim(u8, pem[encoded_start..encoded_end], " \t\r\n");
    var cert_der_storage: [512]u8 = undefined;
    const decoder = std.base64.standard.decoderWithIgnore("\r\n");
    const cert_der_len = try decoder.decode(&cert_der_storage, encoded);
    const cert_der = cert_der_storage[0..cert_der_len];

    const now_sec: i64 = 1_800_000_000;
    var ca_bundle = std.crypto.Certificate.Bundle.empty;
    defer ca_bundle.deinit(std.testing.allocator);
    try ca_bundle.bytes.appendSlice(std.testing.allocator, cert_der);
    try ca_bundle.parseCert(std.testing.allocator, 0, now_sec);

    const server_private_key = [_]u8{
        0x5b, 0xbf, 0x4f, 0x5a, 0x48, 0x42, 0x9f, 0x00,
        0x5a, 0x57, 0x09, 0xc3, 0xb4, 0xc1, 0x3a, 0x64,
        0x2e, 0xb1, 0x61, 0xf5, 0x0b, 0xde, 0x64, 0x4b,
        0x3a, 0x38, 0xa6, 0x8f, 0xfa, 0x48, 0xda, 0x51,
    };
    const alpn = [_][]const u8{"hq-interop"};
    const connection_config = root.Config{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
        .max_datagram_size = 8192,
        .chosen_version = .v1,
        .available_versions = &[_]quic_packet.Version{.v1},
    };
    const client_tls_config = tls13.TlsConfig{
        .alpn = &alpn,
        .server_name = "localhost",
        .skip_cert_verify = false,
        .now_sec = now_sec,
        .ca_bundle = &ca_bundle,
    };
    const server_tls_config = tls13.TlsConfig{
        .alpn = &alpn,
        .cert_chain_der = &.{cert_der},
        .private_key_bytes = &server_private_key,
        .private_key_algorithm = .ecdsa_p256_sha256,
    };

    const client_handle: u64 = 7001;
    const server_handle: u64 = 7002;
    const original_dcid = [_]u8{ 0x0d, 0xc1, 0xd0, 0x01, 0x02, 0x03, 0x04, 0x05 };
    const client_scid = [_]u8{ 0xc1, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const server_scid = [_]u8{ 0x5e, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const client_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_443),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
    };
    const server_path = endpoint.Udp4Tuple{
        .local = client_path.remote,
        .remote = client_path.local,
    };

    var client = try Tls13ClientEndpoint.init(
        std.testing.allocator,
        client_handle,
        client_path,
        .{ .active_migration_disabled = true },
        connection_config,
        client_tls_config,
        original_dcid,
        client_scid,
    );
    defer client.deinit();

    var server_endpoint = try TestServerEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 2,
        .max_stateless_reset_tokens = 1,
    });
    defer server_endpoint.deinit();

    const record = try std.testing.allocator.create(TestServerRecord);
    var record_initialized = false;
    var record_owned_by_test = true;
    errdefer {
        if (record_owned_by_test) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = server_handle,
        .transport = try Tls13ServerTransport.init(
            std.testing.allocator,
            connection_config,
            server_tls_config,
        ),
    };
    record_initialized = true;
    try record.transport.connection.validatePeerAddress();
    try record.transport.setLocalInitialSourceConnectionId(&server_scid);
    try record.transport.setOriginalDestinationConnectionId(&original_dcid);

    var client_scratch: [8192]u8 = undefined;
    var server_scratch: [8192]u8 = undefined;
    const client_initial = try client.beginWithRoutePath(10, &client_scratch);
    defer std.testing.allocator.free(client_initial.datagram);
    try std.testing.expect(client_initial.path.eql(client_path));

    var classify_out: [256]u8 = undefined;
    var server_initial_out: [2]root.EndpointPolledDatagramResult = undefined;
    var server_handshake_out: [2]root.EndpointPolledDatagramResult = undefined;
    var server_installed_out: [2]TestServerEndpoint.DatagramPathResult = undefined;
    var server_pending_out: [2]TestServerEndpoint.DatagramPathResult = undefined;
    const server_initial_step = try server_endpoint.receiveDatagramStepWithRoutePathAndInitialRecordAdmission(
        std.testing.allocator,
        server_path,
        11,
        client_initial.datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &classify_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        record.handle,
        record,
        &server_scid,
        .{ .active_migration_disabled = true },
        &server_scratch,
        &[_]u8{},
        &server_initial_out,
        &server_handshake_out,
        &server_installed_out,
        .application,
        &server_pending_out,
    );
    switch (server_initial_step.process) {
        .accept_initial => {},
        else => return error.TestUnexpectedResult,
    }
    const admission = server_initial_step.admission orelse return error.TestUnexpectedResult;
    const admitted = switch (admission) {
        .admitted => |admitted| admitted,
        .dropped_capacity => return error.TestUnexpectedResult,
    };
    record_owned_by_test = false;
    try std.testing.expect(admitted.initial.path.eql(server_path));
    try std.testing.expectEqual(@as(usize, 1), admitted.initial.accepted.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), admitted.initial.accepted.drain.first_error);
    try std.testing.expect(admitted.handshake != null);
    const server_handshake = admitted.handshake.?;
    try std.testing.expect(server_handshake.path.eql(server_path));
    try std.testing.expectEqual(@as(usize, 1), server_handshake.backend.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), server_handshake.backend.drain.first_error);
    try std.testing.expectEqual(@as(usize, 0), server_initial_step.pending_drain.datagrams_written);
    defer {
        for (server_initial_out[0..admitted.initial.accepted.drain.datagrams_written]) |outbound| {
            std.testing.allocator.free(outbound.datagram);
        }
        for (server_handshake_out[0..server_handshake.backend.drain.datagrams_written]) |outbound| {
            std.testing.allocator.free(outbound.datagram);
        }
        for (server_pending_out[0..server_initial_step.pending_drain.datagrams_written]) |outbound| {
            std.testing.allocator.free(outbound.datagram);
        }
    }

    var client_finished_datagram: ?[]u8 = null;
    errdefer if (client_finished_datagram) |datagram| std.testing.allocator.free(datagram);
    var delivered_server_flights: usize = 0;
    for (server_initial_out[0..admitted.initial.accepted.drain.datagrams_written]) |outbound| {
        try std.testing.expectEqual(server_handle, outbound.connection_id);
        const received = try client.receiveWithRoutePath(12, &client_scratch, outbound.datagram);
        try std.testing.expectEqual(client_handle, received.receive.route.connection_id);
        if (received.outbound_handshake) |finished| {
            try std.testing.expect(client_finished_datagram == null);
            try std.testing.expect(finished.path.eql(client_path));
            client_finished_datagram = finished.datagram;
        }
        delivered_server_flights += 1;
    }
    for (server_handshake_out[0..server_handshake.backend.drain.datagrams_written]) |outbound| {
        try std.testing.expectEqual(server_handle, outbound.connection_id);
        const received = try client.receiveWithRoutePath(13, &client_scratch, outbound.datagram);
        try std.testing.expectEqual(client_handle, received.receive.route.connection_id);
        if (received.outbound_handshake) |finished| {
            try std.testing.expect(client_finished_datagram == null);
            try std.testing.expect(finished.path.eql(client_path));
            client_finished_datagram = finished.datagram;
        }
        delivered_server_flights += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), delivered_server_flights);
    try std.testing.expect(client.handshakeConfirmed());

    const client_finished = client_finished_datagram orelse return error.TestUnexpectedResult;
    client_finished_datagram = null;
    defer std.testing.allocator.free(client_finished);
    var server_finish_initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var server_finish_handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    var server_finish_installed_out: [2]TestServerEndpoint.DatagramPathResult = undefined;
    var server_finish_pending_out: [2]TestServerEndpoint.DatagramPathResult = undefined;
    var server_finish_route_out: [256]u8 = undefined;
    const server_finish_step = try server_endpoint.receiveDatagramStepWithRoutePath(
        std.testing.allocator,
        server_path,
        14,
        client_finished,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &server_finish_route_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &server_scratch,
        &[_]u8{},
        &server_finish_initial_out,
        &server_finish_handshake_out,
        &server_finish_installed_out,
        .application,
        &server_finish_pending_out,
    );
    var server_finish_initial_written: usize = 0;
    var server_finish_handshake_written: usize = 0;
    var server_finish_installed_written: usize = 0;
    switch (server_finish_step.process) {
        .routed => |routed| switch (routed) {
            .long => |long| switch (long) {
                .packet => |long_packet| switch (long_packet) {
                    .initial => |initial| {
                        server_finish_initial_written = initial.initial.backend.backend.drain.datagrams_written;
                        if (initial.handshake) |handshake| {
                            try std.testing.expect(handshake.path.eql(server_path));
                            server_finish_handshake_written = handshake.backend.drain.datagrams_written;
                        }
                    },
                    .handshake => |handshake| {
                        try std.testing.expect(handshake.backend.path.eql(server_path));
                        server_finish_handshake_written = handshake.backend.backend.drain.datagrams_written;
                    },
                },
                .coalesced_initial_handshake => |handshake| {
                    try std.testing.expect(handshake.backend.path.eql(server_path));
                    server_finish_handshake_written = handshake.backend.backend.drain.datagrams_written;
                },
            },
            .installed_key => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    server_finish_installed_written += server_finish_step.pending_drain.datagrams_written;
    defer {
        for (server_finish_initial_out[0..server_finish_initial_written]) |outbound| {
            std.testing.allocator.free(outbound.datagram);
        }
        for (server_finish_handshake_out[0..server_finish_handshake_written]) |outbound| {
            std.testing.allocator.free(outbound.datagram);
        }
        for (server_finish_pending_out[0..server_finish_installed_written]) |outbound| {
            std.testing.allocator.free(outbound.datagram);
        }
    }
    const active_record = server_endpoint.records.get(server_handle) orelse return error.TestUnexpectedResult;
    try std.testing.expect(active_record.transport.connection.handshakeConfirmed());
    try std.testing.expect((try server_endpoint.lifecycle.currentRoutePath(active_record.sourceConnectionId())).eql(server_path));
    try std.testing.expectEqual(@as(usize, 1), server_endpoint.activeConnectionCount());
    try std.testing.expectEqual(@as(usize, 2), server_endpoint.lifecycle.routeCount());
    try std.testing.expectEqual(@as(?root.Error, null), server_finish_step.pending_drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), server_finish_step.pending_drain.first_route_error);
    for (server_finish_pending_out[0..server_finish_step.pending_drain.datagrams_written]) |outbound| {
        try std.testing.expectEqual(server_handle, outbound.connection_id);
        try std.testing.expect(outbound.path.eql(server_path));
    }
}

test "Tls13 endpoints complete protected STREAM echo close and route retirement through endpoint routes" {
    const TestServerRecord = struct {
        handle: u64,
        transport: Tls13ServerTransport,
        retry_validated: bool = false,

        fn clientScid(self: *const @This()) []const u8 {
            return self.transport.connection.peerDestinationConnectionId() orelse
                self.transport.peerInitialSourceConnectionId();
        }

        fn connectionRef(self: *@This()) *Connection {
            return self.transport.connectionRef();
        }

        fn cryptoBackend(self: *@This()) root.CryptoBackend {
            return self.transport.cryptoBackend();
        }

        fn destinationConnectionId(self: *const @This()) []const u8 {
            return self.clientScid();
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
    const TestServerEndpoint = Tls13ServerEndpoint(
        TestServerRecord,
        TestServerRecord.connectionRef,
        TestServerRecord.cryptoBackend,
        TestServerRecord.destinationConnectionId,
        TestServerRecord.sourceConnectionId,
        TestServerRecord.initialDestinationConnectionId,
        TestServerRecord.markRetryValidated,
        TestServerRecord.deinit,
    );

    const pem = @embedFile("testdata/quicz-echo-ca.pem");
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    const begin = std.mem.indexOf(u8, pem, begin_marker) orelse return error.TestUnexpectedResult;
    const encoded_start = begin + begin_marker.len;
    const encoded_end = std.mem.indexOfPos(u8, pem, encoded_start, end_marker) orelse return error.TestUnexpectedResult;
    const encoded = std.mem.trim(u8, pem[encoded_start..encoded_end], " \t\r\n");
    var cert_der_storage: [512]u8 = undefined;
    const decoder = std.base64.standard.decoderWithIgnore("\r\n");
    const cert_der_len = try decoder.decode(&cert_der_storage, encoded);
    const cert_der = cert_der_storage[0..cert_der_len];

    const now_sec: i64 = 1_800_000_000;
    var ca_bundle = std.crypto.Certificate.Bundle.empty;
    defer ca_bundle.deinit(std.testing.allocator);
    try ca_bundle.bytes.appendSlice(std.testing.allocator, cert_der);
    try ca_bundle.parseCert(std.testing.allocator, 0, now_sec);

    const server_private_key = [_]u8{
        0x5b, 0xbf, 0x4f, 0x5a, 0x48, 0x42, 0x9f, 0x00,
        0x5a, 0x57, 0x09, 0xc3, 0xb4, 0xc1, 0x3a, 0x64,
        0x2e, 0xb1, 0x61, 0xf5, 0x0b, 0xde, 0x64, 0x4b,
        0x3a, 0x38, 0xa6, 0x8f, 0xfa, 0x48, 0xda, 0x51,
    };
    const alpn = [_][]const u8{"hq-interop"};
    const connection_config = root.Config{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
        .max_datagram_size = 8192,
        .chosen_version = .v1,
        .available_versions = &[_]quic_packet.Version{.v1},
    };
    const client_tls_config = tls13.TlsConfig{
        .alpn = &alpn,
        .server_name = "localhost",
        .skip_cert_verify = false,
        .now_sec = now_sec,
        .ca_bundle = &ca_bundle,
    };
    const server_tls_config = tls13.TlsConfig{
        .alpn = &alpn,
        .cert_chain_der = &.{cert_der},
        .private_key_bytes = &server_private_key,
        .private_key_algorithm = .ecdsa_p256_sha256,
    };

    const client_handle: u64 = 8001;
    const server_handle: u64 = 8002;
    const original_dcid = [_]u8{ 0x0d, 0xc2, 0xd0, 0x01, 0x02, 0x03, 0x04, 0x05 };
    const client_scid = [_]u8{ 0xc2, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const server_scid = [_]u8{ 0x5e, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const client_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 54_444),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4434),
    };
    const server_path = endpoint.Udp4Tuple{
        .local = client_path.remote,
        .remote = client_path.local,
    };

    var client = try Tls13ClientEndpoint.init(
        std.testing.allocator,
        client_handle,
        client_path,
        .{ .active_migration_disabled = true },
        connection_config,
        client_tls_config,
        original_dcid,
        client_scid,
    );
    defer client.deinit();

    var server_endpoint = try TestServerEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 2,
        .max_stateless_reset_tokens = 1,
    });
    defer server_endpoint.deinit();

    const record = try std.testing.allocator.create(TestServerRecord);
    var record_initialized = false;
    var record_owned_by_test = true;
    errdefer {
        if (record_owned_by_test) {
            if (record_initialized) record.deinit();
            std.testing.allocator.destroy(record);
        }
    }
    record.* = .{
        .handle = server_handle,
        .transport = try Tls13ServerTransport.init(
            std.testing.allocator,
            connection_config,
            server_tls_config,
        ),
    };
    record_initialized = true;
    try record.transport.connection.validatePeerAddress();
    try record.transport.setLocalInitialSourceConnectionId(&server_scid);
    try record.transport.setOriginalDestinationConnectionId(&original_dcid);

    var client_scratch: [8192]u8 = undefined;
    var server_scratch: [8192]u8 = undefined;

    // --- Phase 1: TLS handshake ---
    const client_initial = try client.beginWithRoutePath(10, &client_scratch);
    defer std.testing.allocator.free(client_initial.datagram);

    var classify_out: [256]u8 = undefined;
    var hs_initial_out: [2]root.EndpointPolledDatagramResult = undefined;
    var hs_handshake_out: [2]root.EndpointPolledDatagramResult = undefined;
    var hs_installed_out: [2]TestServerEndpoint.DatagramPathResult = undefined;
    var hs_pending_out: [2]TestServerEndpoint.DatagramPathResult = undefined;
    const hs_step = try server_endpoint.receiveDatagramStepWithRoutePathAndInitialRecordAdmission(
        std.testing.allocator,
        server_path,
        11,
        client_initial.datagram,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &classify_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        record.handle,
        record,
        &server_scid,
        .{ .active_migration_disabled = true },
        &server_scratch,
        &[_]u8{},
        &hs_initial_out,
        &hs_handshake_out,
        &hs_installed_out,
        .application,
        &hs_pending_out,
    );
    switch (hs_step.process) {
        .accept_initial => {},
        else => return error.TestUnexpectedResult,
    }
    const admission = hs_step.admission orelse return error.TestUnexpectedResult;
    const admitted = switch (admission) {
        .admitted => |a| a,
        .dropped_capacity => return error.TestUnexpectedResult,
    };
    record_owned_by_test = false;
    const hs_initial_written = admitted.initial.accepted.drain.datagrams_written;
    const hs_handshake_written = admitted.handshake.?.backend.drain.datagrams_written;
    defer {
        for (hs_initial_out[0..hs_initial_written]) |o| std.testing.allocator.free(o.datagram);
        for (hs_handshake_out[0..hs_handshake_written]) |o| std.testing.allocator.free(o.datagram);
        for (hs_pending_out[0..hs_step.pending_drain.datagrams_written]) |o| std.testing.allocator.free(o.datagram);
    }

    var client_finished_datagram: ?[]u8 = null;
    errdefer if (client_finished_datagram) |d| std.testing.allocator.free(d);
    for (hs_initial_out[0..hs_initial_written]) |o| {
        const r = try client.receiveWithRoutePath(12, &client_scratch, o.datagram);
        if (r.outbound_handshake) |f| client_finished_datagram = f.datagram;
    }
    for (hs_handshake_out[0..hs_handshake_written]) |o| {
        const r = try client.receiveWithRoutePath(13, &client_scratch, o.datagram);
        if (r.outbound_handshake) |f| client_finished_datagram = f.datagram;
    }
    try std.testing.expect(client.handshakeConfirmed());

    const client_finished = client_finished_datagram orelse return error.TestUnexpectedResult;
    client_finished_datagram = null;
    defer std.testing.allocator.free(client_finished);

    var fin_initial_out: [1]root.EndpointPolledDatagramResult = undefined;
    var fin_handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
    var fin_installed_out: [2]TestServerEndpoint.DatagramPathResult = undefined;
    var fin_pending_out: [2]TestServerEndpoint.DatagramPathResult = undefined;
    var fin_route_out: [256]u8 = undefined;
    _ = try server_endpoint.receiveDatagramStepWithRoutePath(
        std.testing.allocator,
        server_path,
        14,
        client_finished,
        &[_]u8{},
        &[_]quic_packet.Version{.v1},
        .{
            .space = .application,
            .out = &fin_route_out,
            .unpredictable_prefix = &[_]u8{},
            .supported_versions = &[_]quic_packet.Version{.v1},
        },
        &server_scratch,
        &[_]u8{},
        &fin_initial_out,
        &fin_handshake_out,
        &fin_installed_out,
        .application,
        &fin_pending_out,
    );
    defer {
        for (fin_pending_out[0..0]) |o| std.testing.allocator.free(o.datagram);
    }
    const active_record = server_endpoint.records.get(server_handle) orelse return error.TestUnexpectedResult;
    try std.testing.expect(active_record.transport.connection.handshakeConfirmed());

    // --- Phase 2: Client sends protected STREAM data with FIN ---
    const stream_id = try client.openStream();
    try std.testing.expectEqual(@as(u64, 0), stream_id);
    const echo_payload = "hello quicz";
    var client_stream_out: [4]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
    const client_stream_send = try client.sendStreamWithRoutePathAndDrainDatagrams(
        stream_id,
        echo_payload,
        true,
        20,
        &client_stream_out,
    );
    try std.testing.expect(client_stream_send.drain.datagrams_written >= 1);
    try std.testing.expectEqual(@as(?Tls13ClientEndpoint.ApplicationDatagramPollError, null), client_stream_send.drain.first_error);
    const client_stream_written = client_stream_send.drain.datagrams_written;
    defer {
        for (client_stream_out[0..client_stream_written]) |o| std.testing.allocator.free(o.datagram);
    }

    // --- Phase 3: Server receives every client STREAM datagram ---
    for (client_stream_out[0..client_stream_written]) |client_datagram| {
        var s_initial_out: [1]root.EndpointPolledDatagramResult = undefined;
        var s_handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
        var s_installed_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
        var s_pending_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
        var s_route_out: [256]u8 = undefined;
        const step = try server_endpoint.receiveDatagramStepWithRoutePath(
            std.testing.allocator,
            server_path,
            21,
            client_datagram.datagram,
            &[_]u8{},
            &[_]quic_packet.Version{.v1},
            .{
                .space = .application,
                .out = &s_route_out,
                .unpredictable_prefix = &[_]u8{},
                .supported_versions = &[_]quic_packet.Version{.v1},
            },
            &server_scratch,
            &[_]u8{},
            &s_initial_out,
            &s_handshake_out,
            &s_installed_out,
            .application,
            &s_pending_out,
        );
        var phase3_installed_written: usize = 0;
        switch (step.process) {
            .routed => |routed| switch (routed) {
                .installed_key => |ik| {
                    phase3_installed_written = ik.drain.datagrams_written;
                },
                else => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        }
        // Free server-side ACK/control output produced during receive.
        for (s_installed_out[0..phase3_installed_written]) |o| std.testing.allocator.free(o.datagram);
        for (s_pending_out[0..step.pending_drain.datagrams_written]) |o| std.testing.allocator.free(o.datagram);
    }

    // --- Phase 4: Server reads the stream data ---
    var server_recv_buf: [64]u8 = undefined;
    const server_recv_len = (try server_endpoint.recvStream(server_handle, stream_id, &server_recv_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(echo_payload, server_recv_buf[0..server_recv_len]);
    try std.testing.expect(try server_endpoint.streamFinished(server_handle, stream_id));

    // --- Phase 5: Server echoes the data back with FIN ---
    var server_echo_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
    const server_echo = try server_endpoint.sendStreamWithRoutePathAndDrainDatagrams(
        std.testing.allocator,
        server_handle,
        stream_id,
        server_recv_buf[0..server_recv_len],
        true,
        22,
        &server_echo_out,
    );
    try std.testing.expect(server_echo.drain.datagrams_written >= 1);
    try std.testing.expectEqual(@as(?root.Error, null), server_echo.drain.first_error);
    const server_echo_written = server_echo.drain.datagrams_written;
    defer {
        for (server_echo_out[0..server_echo_written]) |o| std.testing.allocator.free(o.datagram);
    }

    // --- Phase 6: Client receives every server echo datagram ---
    for (server_echo_out[0..server_echo_written]) |echo_datagram| {
        var c_recv_out: [4]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
        var c_due_out: [4]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
        const c_step = try client.receiveDatagramStepWithRoutePath(
            23,
            &client_scratch,
            echo_datagram.datagram,
            &c_recv_out,
            &c_due_out,
        );
        try std.testing.expect(c_step.receive.receive != null);
        for (c_recv_out[0..c_step.receive.drain.datagrams_written]) |o| std.testing.allocator.free(o.datagram);
        if (c_step.due) |due| {
            for (c_due_out[0..due.drain.datagrams_written]) |o| std.testing.allocator.free(o.datagram);
        }
    }

    // --- Phase 7: Client reads the echoed data ---
    var client_recv_buf: [64]u8 = undefined;
    const client_recv_len = (try client.recvStream(stream_id, &client_recv_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(echo_payload, client_recv_buf[0..client_recv_len]);
    try std.testing.expect(try client.streamFinished(stream_id));

    // --- Phase 8: Client sends APPLICATION_CLOSE ---
    var client_close_out: [4]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
    const client_close = try client.closeApplicationWithRoutePathAndDrainDatagrams(
        0,
        "echo done",
        30,
        &client_close_out,
    );
    try std.testing.expect(client_close.drain.datagrams_written >= 1);
    const client_close_written = client_close.drain.datagrams_written;
    defer {
        for (client_close_out[0..client_close_written]) |o| std.testing.allocator.free(o.datagram);
    }

    // --- Phase 9: Server receives every client close datagram ---
    for (client_close_out[0..client_close_written]) |close_datagram| {
        var sc_initial_out: [1]root.EndpointPolledDatagramResult = undefined;
        var sc_handshake_out: [1]root.EndpointPolledDatagramResult = undefined;
        var sc_installed_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
        var sc_pending_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
        var sc_route_out: [256]u8 = undefined;
        const sc_step = try server_endpoint.receiveDatagramStepWithRoutePath(
            std.testing.allocator,
            server_path,
            31,
            close_datagram.datagram,
            &[_]u8{},
            &[_]quic_packet.Version{.v1},
            .{
                .space = .application,
                .out = &sc_route_out,
                .unpredictable_prefix = &[_]u8{},
                .supported_versions = &[_]quic_packet.Version{.v1},
            },
            &server_scratch,
            &[_]u8{},
            &sc_initial_out,
            &sc_handshake_out,
            &sc_installed_out,
            .application,
            &sc_pending_out,
        );
        var installed_key_drain_written: usize = 0;
        switch (sc_step.process) {
            .routed => |routed| switch (routed) {
                .installed_key => |ik| {
                    installed_key_drain_written = ik.drain.datagrams_written;
                },
                else => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        }
        for (sc_installed_out[0..installed_key_drain_written]) |o| std.testing.allocator.free(o.datagram);
        for (sc_pending_out[0..sc_step.pending_drain.datagrams_written]) |o| std.testing.allocator.free(o.datagram);
    }
    const closed_record = server_endpoint.records.get(server_handle) orelse return error.TestUnexpectedResult;
    try std.testing.expect(closed_record.transport.connection.connectionState() == .closing or
        closed_record.transport.connection.connectionState() == .draining or
        closed_record.transport.connection.connectionState() == .closed);

    // --- Phase 10: Retire client route after close deadline ---
    const client_close_deadline = client.closeDeadlineMillis() orelse return error.TestUnexpectedResult;
    const client_retire = try client.retireAtCloseDeadline(client_close_deadline + 1);
    const client_retired = client_retire orelse return error.TestUnexpectedResult;
    try std.testing.expect(client_retired.routes_retired >= 1);

    // --- Phase 11: Retire server record and verify cleanup ---
    const server_retired = try server_endpoint.retireRecord(server_handle);
    try std.testing.expect(server_retired.routes_retired >= 1);
    try std.testing.expectEqual(@as(usize, 0), server_endpoint.activeConnectionCount());
}
