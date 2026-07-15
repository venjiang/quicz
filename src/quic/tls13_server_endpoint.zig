//! Reusable endpoint ownership for TLS 1.3 server connection records.
//!
//! This type owns lifecycle routing/timers and record storage, but deliberately
//! leaves UDP socket I/O, admission policy, and application dispatch with its
//! caller.

const std = @import("std");
const address_validation_token = @import("address_validation_token.zig");
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

        /// Installed-key receive result with any immediate output route.
        pub const InstalledKeyDatagramRoutePollResult = struct {
            /// Receive, path validation, and route-update result when feed succeeded.
            feed: ?root.EndpointFeedInstalledKeyPathUpdateResult = null,
            /// Feed error returned after the endpoint had selected a record.
            feed_error: ?root.EndpointProtectedDatagramError = null,
            /// Protected output emitted after feed or close-on-error handling.
            datagram: ?DatagramPathResult = null,
        };

        /// Due-work result with every drained datagram paired to a route.
        pub const DueWorkDatagramPathDrainResult = struct {
            /// Deadline that was due when this pending-work pass started.
            deadline: root.EndpointConnectionDeadline,
            /// Pending-work actions applied for the due deadline.
            pending_work: root.EndpointPendingWorkResult,
            /// Bounded output drain after a due recovery timer, if any.
            drain: root.EndpointDatagramDrainResult,
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

        /// Routed Initial processing with route-bound output drains.
        pub const InitialProcessPathResult = struct {
            initial: struct {
                route: endpoint.RouteResult,
                backend: ProtectedLongBackendDatagramDrainPathResult,
            },
            handshake: ?CryptoBackendDatagramDrainPathResult = null,
        };

        /// Routed installed-key backend processing with route-bound output.
        pub const RoutedBackendDatagramDrainPathResult = struct {
            route: endpoint.RouteResult,
            backend: CryptoBackendDatagramDrainPathResult,
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
        ) void {
            if (pending_work.idle_retired == null and pending_work.close_retired == null) return;
            self.records.remove(connection_id) catch unreachable;
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
        ) error{UnknownConnectionId}!root.EndpointConnectionRetireResult {
            if (self.records.get(connection_id) == null) return error.UnknownConnectionId;
            const retired = self.lifecycle.retireConnection(connection_id);
            self.records.remove(connection_id) catch unreachable;
            return retired;
        }

        /// Select the earliest deadline across all endpoint-owned records.
        pub fn nextDeadline(
            self: *Self,
            allocator: std.mem.Allocator,
        ) !?root.EndpointConnectionDeadline {
            return self.records.nextDeadline(&self.lifecycle, allocator);
        }

        /// Service the earliest due deadline and drain bounded protected output.
        pub fn processDueDeadlineAndDrainDatagrams(
            self: *Self,
            allocator: std.mem.Allocator,
            now_millis: i64,
            out: []root.EndpointPolledDatagramResult,
        ) root.Error!?root.EndpointDueWorkDatagramDrainResult {
            const result = (try self.records.processDueDeadlineAndDrainDatagrams(
                &self.lifecycle,
                allocator,
                now_millis,
                out,
                destination_connection_id_of,
                source_connection_id_of,
            )) orelse return null;
            self.retireRecordAfterTerminalPendingWork(result.deadline.connection_id, result.pending_work);
            return result;
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
            const record = self.records.get(deadline.connection_id) orelse return error.UnknownConnectionId;
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
                };
            } else try self.lifecycle.processPendingWork(
                deadline.connection_id,
                connection,
                now_millis,
            );
            self.retireRecordAfterTerminalPendingWork(deadline.connection_id, pending_work);

            return .{
                .deadline = deadline,
                .pending_work = pending_work,
                .drain = .{},
            };
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
            const record = self.records.get(route.connection_id) orelse return error.InvalidPacket;
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
            const record = self.records.get(route.connection_id) orelse return error.InvalidPacket;
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
                .accept_initial => |initial| return .{ .feed = .{ .feed = .{ .accept_initial = initial } } },
                .version_negotiation => |response| return .{ .feed = .{ .feed = .{ .version_negotiation = response } } },
                .stateless_reset => |reset| return .{ .feed = .{ .feed = .{ .stateless_reset = reset } } },
                .dropped => return .{ .feed = .{ .feed = .dropped } },
            };
            const record = self.records.get(route.connection_id) orelse return error.InvalidPacket;
            const connection = connection_of(record);
            const destination_connection_id = destination_connection_id_of(record);
            const feed = self.lifecycle.feedDatagramWithInstalledKeysAndUpdatePathOrClose(
                route.connection_id,
                connection,
                path,
                now_millis,
                datagram,
                options,
            ) catch |err| {
                if (err != error.InvalidPacket) return err;
                const close_datagram = try self.pollOneRttDatagramWithRoutePath(route.connection_id, now_millis);
                return .{
                    .feed_error = err,
                    .datagram = if (close_datagram) |value| .{
                        .connection_id = route.connection_id,
                        .datagram = value.datagram,
                        .path = value.path,
                    } else null,
                };
            };
            switch (feed.feed) {
                .routed => {},
                else => return .{ .feed = feed },
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
            try connection_of(record).closeConnection(error_code, frame_type, reason_phrase);
            return self.pollOneRttDatagramWithRoutePath(connection_id, now_millis);
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
            errdefer self.records.remove(connection_id) catch unreachable;
            if (accepted.drain.first_error != null or !accepted.backend.handshake_keys_installed) {
                return .{ .initial = accepted };
            }
            return .{
                .initial = accepted,
                .handshake = try self.driveBackend(
                    connection_id,
                    .handshake,
                    scratch,
                    now_millis,
                    handshake_out,
                ),
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
    try record.connection.sendPing();
    const record_handle = record.handle;
    try endpoint_owner.records.adopt(record_handle, record);
    record_owned = false;
    try std.testing.expect(endpoint_owner.records.hasCapacity());
    const one_rtt = (try endpoint_owner.pollOneRttDatagram(record_handle, 1)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(one_rtt);
    try std.testing.expect(one_rtt.len != 0);
    try endpoint_owner.records.remove(record_handle);
    try std.testing.expect(endpoint_owner.records.hasCapacity());
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

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    try std.testing.expect((try endpoint_owner.nextDeadline(no_allocation_allocator.allocator())) == null);

    var dynamic_endpoint = TestEndpoint.init(std.testing.allocator);
    defer dynamic_endpoint.deinit();
    try std.testing.expect(dynamic_endpoint.records.hasCapacity());
    try std.testing.expectEqual(std.math.maxInt(usize), dynamic_endpoint.records.max_records);
    try std.testing.expectEqual(@as(usize, 0), dynamic_endpoint.lifecycle.routeCount());
    try std.testing.expectEqual(@as(?root.EndpointConnectionDeadline, null), try dynamic_endpoint.nextDeadline(std.testing.allocator));
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
    switch (feed_result) {
        .routed => |route| try std.testing.expectEqual(record.handle, route.connection_id),
        else => return error.TestUnexpectedResult,
    }

    try endpoint_owner.records.remove(record.handle);
    try std.testing.expectError(
        error.InvalidPacket,
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
    try std.testing.expect(endpoint_owner.records.get(record_handle) == null);
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.recoveryTimerCount());
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
        9,
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
    try client.processProtectedShortDatagramWithInstalledKeys(10, client_dcid.len, close_output.datagram);
    try std.testing.expectEqual(connection_module.ConnectionState.draining, client.connectionState());
}
