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

const Connection = connection_module.Connection;
const EndpointConnectionLifecycle = endpoint_lifecycle.EndpointConnectionLifecycle;

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
            drain: root.EndpointDatagramDrainResult,
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

        fn currentRecordRoutePath(self: *const Self, record: *const Record) endpoint.RouteError!endpoint.Udp4Tuple {
            return self.lifecycle.currentRoutePath(source_connection_id_of(record));
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
            return self.records.count();
        }

        /// Return the configured active-connection limit.
        ///
        /// Dynamically sized endpoints report `std.math.maxInt(usize)`.
        pub fn activeConnectionLimit(self: *const Self) usize {
            return self.records.capacityLimit();
        }

        /// Return whether this endpoint can accept one more connection record.
        pub fn hasConnectionCapacity(self: *const Self) bool {
            return self.records.hasCapacity();
        }

        /// Write active endpoint-owned connection handles into caller-owned storage.
        pub fn activeConnectionIds(self: *Self, out: []u64) root.Error![]u64 {
            return self.records.fillConnectionIds(out);
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
            if (self.records.get(connection_id) == null) return error.UnknownConnectionId;
            const retired = self.lifecycle.retireConnection(connection_id);
            self.records.remove(connection_id) catch return error.Internal;
            return retired;
        }

        /// Select the earliest deadline across all endpoint-owned records.
        pub fn nextDeadline(
            self: *Self,
            allocator: std.mem.Allocator,
        ) !?root.EndpointConnectionDeadline {
            return self.records.nextDeadline(&self.lifecycle, allocator);
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

        /// Sweep pending work across endpoint-owned records and drain route-bound output.
        pub fn processPendingWorkAndDrainDatagramsWithRoutePath(
            self: *Self,
            allocator: std.mem.Allocator,
            now_millis: i64,
            space: root.EndpointInstalledKeyDatagramSpace,
            out: []DatagramPathResult,
        ) root.Error!PendingWorkDatagramPathDrainResult {
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
                const path = try self.lifecycle.currentRoutePath(source_connection_id);
                return .{
                    .deadline = deadline,
                    .pending_work = pending,
                    .drain = self.drainDatagramsWithRoutePath(
                        deadline.connection_id,
                        connection,
                        now_millis,
                        options,
                        path,
                        out,
                    ),
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
                const path = try self.lifecycle.currentRoutePath(source_connection_id);
                return .{
                    .deadline = deadline,
                    .pending_work = pending,
                    .drain = self.drainInitialDatagramsWithRoutePath(
                        deadline.connection_id,
                        record,
                        connection,
                        now_millis,
                        path,
                        out,
                    ),
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
                const close_datagram = if (connection.connectionState() == .closing)
                    try self.pollOneRttDatagramWithRoutePath(route.connection_id, now_millis)
                else
                    null;
                return .{
                    .feed_error = err,
                    .datagram = if (close_datagram) |value| .{
                        .connection_id = route.connection_id,
                        .datagram = value.datagram,
                        .path = value.path,
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
            const output_path = feed.selected_output_path orelse
                try self.lifecycle.currentRoutePath(route.destination_connection_id.asSlice());
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
                    result.drain = self.drainDatagramsWithRoutePath(
                        route.connection_id,
                        connection,
                        now_millis,
                        .{
                            .space = .application,
                            .destination_connection_id = destination_connection_id,
                        },
                        try self.currentRecordRoutePath(record),
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
            const output_path = feed.selected_output_path orelse
                try self.lifecycle.currentRoutePath(route.destination_connection_id.asSlice());
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
            const polled = (try self.records.pollDatagramAcrossConnections(
                &self.lifecycle,
                allocator,
                now_millis,
                space,
                destination_connection_id_of,
                source_connection_id_of,
            )) orelse return null;
            const record = self.records.get(polled.connection_id) orelse return error.Internal;
            errdefer connection_of(record).allocator.free(polled.datagram);
            return .{
                .connection_id = polled.connection_id,
                .datagram = polled.datagram,
                .path = try self.currentRecordRoutePath(record),
            };
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
                const polled = self.records.pollDatagramAcrossConnections(
                    &self.lifecycle,
                    allocator,
                    now_millis,
                    space,
                    destination_connection_id_of,
                    source_connection_id_of,
                ) catch |err| {
                    result.first_error = err;
                    return result;
                };
                const datagram = polled orelse return result;
                const record = self.records.get(datagram.connection_id) orelse {
                    result.first_error = error.Internal;
                    return result;
                };
                const path = self.currentRecordRoutePath(record) catch |err| {
                    connection_of(record).allocator.free(datagram.datagram);
                    result.first_route_error = err;
                    return result;
                };
                out[result.datagrams_written] = .{
                    .connection_id = datagram.connection_id,
                    .datagram = datagram.datagram,
                    .path = path,
                };
                result.datagrams_written += 1;
            }
            return result;
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
            _ = try self.currentRecordRoutePath(record);
            try connection_of(record).closeConnection(error_code, frame_type, reason_phrase);
            return .{
                .drain = self.drainDatagramsAcrossRecordsWithRoutePath(
                    allocator,
                    now_millis,
                    .application,
                    out,
                ),
                .next_deadline = try self.nextDeadline(allocator),
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
        ) (endpoint.RouteError || error{ConnectionLimitReached})!endpoint.RouteResult {
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
            errdefer _ = self.lifecycle.retireConnection(connection_id);

            try self.records.adopt(connection_id, record);
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
                self.records.remove(connection_id) catch return error.Internal;
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
            return .{
                .backend = try self.driveBackend(connection_id, space, scratch, now_millis, out),
                .path = try self.currentRecordRoutePath(record),
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
            return .{
                .backend = try self.driveInitialBackend(
                    connection_id,
                    scratch,
                    now_millis,
                    initial_token,
                    version,
                    out,
                ),
                .path = try self.currentRecordRoutePath(record),
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
                    .path = try self.currentRecordRoutePath(record),
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
            const output_path = try self.currentRecordRoutePath(record);
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
                    .path = try self.currentRecordRoutePath(record),
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
                .process = process,
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
    const server_unidirectional_stream = try endpoint_owner.openUniStream(record_handle);
    try std.testing.expectEqual(@as(u64, 3), server_unidirectional_stream);
    const server_bidirectional_stream = try endpoint_owner.openStream(record_handle);
    try std.testing.expectEqual(@as(u64, 1), server_bidirectional_stream);
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
    var stream_read_buffer: [8]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try endpoint_owner.recvStream(record_handle, server_bidirectional_stream, &stream_read_buffer));
    try std.testing.expect(!try endpoint_owner.streamFinished(record_handle, server_bidirectional_stream));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.openUniStream(99));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.sendStreamWithRoutePath(99, server_bidirectional_stream, "server", false, 1));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.resetStreamWithRoutePath(99, server_unidirectional_stream, 41, 2));
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.stopSendingWithRoutePath(99, server_bidirectional_stream, 42, 3));
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

    const retired_record = try endpoint_owner.retireRecord(retry_record_handle);
    try std.testing.expectEqual(@as(usize, 1), retired_record.routes_retired);
    try std.testing.expect(endpoint_owner.records.get(retry_record_handle) == null);
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.routeCount());
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

    var endpoint_owner = TestEndpoint.init(std.testing.allocator);
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

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const feed_result = try endpoint_owner.feedDatagramWithInstalledKeys(
        no_allocation_allocator.allocator(),
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
    const route = switch (feed_result) {
        .routed => |route| route,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(record.handle, route.connection_id);

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

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    var due_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const due = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePath(
        no_allocation_allocator.allocator(),
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
    const recovery_first = (try endpoint_owner.pollDatagramWithRoutePath(
        no_allocation_allocator.allocator(),
        16,
        .application,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(recovery_first.datagram);
    const deadline = (try endpoint_owner.nextDeadline(no_allocation_allocator.allocator())) orelse return error.TestUnexpectedResult;
    try std.testing.expect(deadline.connection_id == first_record.handle or deadline.connection_id == second_record.handle);
    try std.testing.expectEqual(root.EndpointConnectionDeadlineKind.recovery, deadline.kind);
    try std.testing.expectEqual(root.PacketNumberSpace.application, deadline.recovery.?.space);

    var pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
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

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    var due_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const due = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePath(
        no_allocation_allocator.allocator(),
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

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    var due_out: [1]root.EndpointPolledDatagramResult = undefined;
    const due = (try endpoint_owner.processDueDeadlineAndDrainDatagrams(
        no_allocation_allocator.allocator(),
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

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const swept = try endpoint_owner.processPendingWorkAndSelectNextDeadline(
        no_allocation_allocator.allocator(),
        20,
    );
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
    const secrets = try protection.deriveInitialSecrets(.v1, "server-close-drain");
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
    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    var out: [2]TestEndpoint.DatagramPathResult = undefined;
    const closed = try endpoint_owner.closeWithRoutePathAndDrainDatagrams(
        no_allocation_allocator.allocator(),
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
