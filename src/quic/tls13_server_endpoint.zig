//! Reusable endpoint ownership for bounded TLS 1.3 server connection records.
//!
//! This type owns lifecycle routing/timers and record storage, but deliberately
//! leaves UDP socket I/O, admission policy, and application dispatch with its
//! caller.

const std = @import("std");
const root = @import("../lib.zig");
const connection_module = @import("connection.zig");
const endpoint = @import("endpoint.zig");
const endpoint_connection_registry = @import("endpoint_connection_registry.zig");
const endpoint_lifecycle = @import("endpoint_lifecycle.zig");
const quic_packet = @import("packet.zig");
const protection = @import("protection.zig");

const Connection = connection_module.Connection;
const EndpointConnectionLifecycle = endpoint_lifecycle.EndpointConnectionLifecycle;

/// Build an endpoint owner for one caller-defined TLS server record type.
///
/// Records own their transport/backend and application metadata. The endpoint
/// owns their bounded lifetime, CID routing, recovery timers, and path policy.
pub fn Tls13ServerEndpoint(
    comptime Record: type,
    comptime connection_of: *const fn (*Record) *Connection,
    comptime deinit_record: *const fn (*Record) void,
) type {
    const Registry = endpoint_connection_registry.EndpointConnectionRegistry(
        Record,
        connection_of,
        deinit_record,
    );

    return struct {
        const Self = @This();

        lifecycle: EndpointConnectionLifecycle,
        records: Registry,

        /// Create an endpoint with bounded record, route, and reset-token storage.
        pub fn initWithCapacity(
            allocator: std.mem.Allocator,
            max_active_connections: usize,
            router_options: endpoint.EndpointRouterOptions,
        ) !Self {
            var lifecycle = EndpointConnectionLifecycle.initWithRouterOptions(allocator, router_options);
            errdefer lifecycle.deinit();
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
            comptime destination_connection_id: *const fn (*const Record) []const u8,
            comptime source_connection_id: *const fn (*const Record) []const u8,
        ) root.Error!?root.EndpointDueWorkDatagramDrainResult {
            return self.records.processDueDeadlineAndDrainDatagrams(
                &self.lifecycle,
                allocator,
                now_millis,
                out,
                destination_connection_id,
                source_connection_id,
            );
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
            return self.records.feedDatagramWithInstalledKeys(
                &self.lifecycle,
                allocator,
                path,
                now_millis,
                datagram,
                options,
            );
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
            destination_connection_id: []const u8,
        ) (root.Error || error{UnknownConnectionId})!?[]u8 {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            return self.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                connection_id,
                connection_of(record),
                now_millis,
                destination_connection_id,
            );
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
        pub fn acceptInitial(
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
        /// Route installation, TLS driving, bounded Initial output, and record
        /// admission succeed together. The caller retains `record` on failure;
        /// any route or timer installed before that failure is retired.
        pub fn acceptInitialRecord(
            self: *Self,
            connection_id: u64,
            record: *Record,
            now_millis: i64,
            initial_accept: endpoint.InitialAcceptResult,
            server_source_connection_id: []const u8,
            datagram: []const u8,
            options: endpoint.AcceptedInitialRouteOptions,
            backend: root.CryptoBackend,
            scratch: []u8,
            out: []root.EndpointPolledDatagramResult,
        ) (root.EndpointProtectedInitialError || error{ConnectionLimitReached})!root.EndpointAcceptedInitialCryptoBackendDatagramDrainResult {
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
                backend,
                scratch,
                out,
            ) catch |err| {
                _ = self.lifecycle.retireConnection(connection_id);
                return err;
            };
            errdefer _ = self.lifecycle.retireConnection(connection_id);

            try self.records.adopt(connection_id, record);
            return accepted;
        }

        /// Drive one TLS packet-number space and drain its bounded output.
        pub fn driveBackend(
            self: *Self,
            connection_id: u64,
            space: root.PacketNumberSpace,
            backend: root.CryptoBackend,
            scratch: []u8,
            now_millis: i64,
            poll_options: root.EndpointPollInstalledKeyDatagramOptions,
            out: []root.EndpointPolledDatagramResult,
        ) (root.Error || error{UnknownConnectionId})!root.EndpointCryptoBackendDriveDatagramDrainResult {
            const record = self.records.get(connection_id) orelse return error.UnknownConnectionId;
            return self.lifecycle.driveCryptoBackendInSpaceAndDrainDatagrams(
                connection_id,
                connection_of(record),
                space,
                backend,
                scratch,
                now_millis,
                poll_options,
                out,
            );
        }

        /// Drive the TLS Initial space and drain bounded protected Initial output.
        pub fn driveInitialBackend(
            self: *Self,
            connection_id: u64,
            connection: *Connection,
            backend: root.CryptoBackend,
            scratch: []u8,
            now_millis: i64,
            destination_connection_id: []const u8,
            source_connection_id: []const u8,
            initial_token: []const u8,
            keys: protection.Aes128PacketProtectionKeys,
            out: []root.EndpointPolledDatagramResult,
        ) root.Error!root.EndpointCryptoBackendDriveProtectedLongDatagramDrainResult {
            return self.lifecycle.driveCryptoBackendInSpaceAndDrainProtectedLongCryptoDatagrams(
                connection_id,
                connection,
                .initial,
                backend,
                scratch,
                .initial,
                now_millis,
                destination_connection_id,
                source_connection_id,
                initial_token,
                keys,
                out,
            );
        }

        /// Authenticate and accept the Retry follow-up Initial for one route.
        pub fn validateRetryInitial(
            self: *Self,
            policy: *endpoint.AddressValidationPolicy,
            connection_id: u64,
            connection: *Connection,
            now_millis: i64,
            path: endpoint.Udp4Tuple,
            datagram: []const u8,
            supported_versions: []const quic_packet.Version,
        ) root.EndpointRetryProtectedInitialError!root.EndpointRetryProtectedInitialResult {
            return self.lifecycle.processRetryValidatedProtectedInitialDatagram(
                policy,
                connection_id,
                connection,
                now_millis,
                path,
                datagram,
                supported_versions,
            );
        }

        /// Authenticate a routed Initial after Handshake keys are available.
        pub fn processInitialWithHandshakeKeys(
            self: *Self,
            connection_id: u64,
            connection: *Connection,
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            original_destination_connection_id: []const u8,
            datagram: []const u8,
        ) root.EndpointProtectedInitialError!endpoint.RouteResult {
            return self.lifecycle.processRoutedProtectedLongDatagramWithInstalledHandshakeKeys(
                connection_id,
                connection,
                path,
                now_millis,
                original_destination_connection_id,
                datagram,
            );
        }

        /// Authenticate a routed Initial, drive TLS, and drain bounded output.
        pub fn processInitial(
            self: *Self,
            connection_id: u64,
            connection: *Connection,
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            receive_keys: protection.Aes128PacketProtectionKeys,
            datagram: []const u8,
            backend: root.CryptoBackend,
            scratch: []u8,
            destination_connection_id: []const u8,
            source_connection_id: []const u8,
            initial_token: []const u8,
            send_keys: protection.Aes128PacketProtectionKeys,
            out: []root.EndpointPolledDatagramResult,
        ) root.EndpointProtectedDatagramError!root.EndpointRoutedCryptoBackendDriveProtectedLongDatagramDrainResult {
            return self.lifecycle.processRoutedProtectedLongDatagramInSpaceAndDriveCryptoBackendAndDrainDatagrams(
                connection_id,
                connection,
                .initial,
                path,
                now_millis,
                receive_keys,
                datagram,
                backend,
                scratch,
                destination_connection_id,
                source_connection_id,
                initial_token,
                send_keys,
                out,
            );
        }

        /// Authenticate a routed Handshake packet, drive TLS, and drain output.
        pub fn processHandshake(
            self: *Self,
            connection_id: u64,
            connection: *Connection,
            path: endpoint.Udp4Tuple,
            now_millis: i64,
            datagram: []const u8,
            backend: root.CryptoBackend,
            scratch: []u8,
            destination_connection_id: []const u8,
            source_connection_id: []const u8,
            out: []root.EndpointPolledDatagramResult,
        ) root.EndpointProtectedDatagramError!root.EndpointRoutedCryptoBackendDriveDatagramDrainResult {
            return self.lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeysAndDriveCryptoBackendAndDrainDatagrams(
                connection_id,
                connection,
                path,
                now_millis,
                datagram,
                backend,
                scratch,
                destination_connection_id,
                source_connection_id,
                out,
            );
        }
    };
}

test "Tls13ServerEndpoint owns bounded records with lifecycle state" {
    const TestRecord = struct {
        handle: u64,
        connection: Connection,

        fn connectionRef(self: *@This()) *Connection {
            return &self.connection;
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
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 2, .{
        .max_routes = 3,
        .max_stateless_reset_tokens = 3,
    });
    defer endpoint_owner.deinit();
    try std.testing.expect(endpoint_owner.records.hasCapacity());
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.routeCount());

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
    const one_rtt = (try endpoint_owner.pollOneRttDatagram(record_handle, 1, "peer")) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(one_rtt);
    try std.testing.expect(one_rtt.len != 0);
    try endpoint_owner.records.remove(record_handle);
    try std.testing.expect(endpoint_owner.records.hasCapacity());
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.pollOneRttDatagram(record_handle, 2, "peer"));

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
    };
    retry_record_initialized = true;
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
    var empty_backend = EmptyBackend{};
    var backend_scratch: [1]u8 = undefined;
    var backend_output: [1]root.EndpointPolledDatagramResult = undefined;
    const backend_progress = try endpoint_owner.driveBackend(
        retry_record.handle,
        .handshake,
        empty_backend.backend(),
        &backend_scratch,
        1,
        .{
            .space = .handshake,
            .destination_connection_id = "peer",
            .source_connection_id = "local",
        },
        &backend_output,
    );
    try std.testing.expectEqual(@as(usize, 0), backend_progress.backend.progress.outbound_chunks);
    try std.testing.expectError(
        error.UnknownConnectionId,
        endpoint_owner.driveBackend(
            99,
            .handshake,
            empty_backend.backend(),
            &backend_scratch,
            1,
            .{
                .space = .handshake,
                .destination_connection_id = "peer",
                .source_connection_id = "local",
            },
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
    };
    rejecting_record_initialized = true;
    var rejecting_backend = RejectingInitialBackend{};
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
            rejecting_backend.backend(),
            &rejecting_scratch,
            &rejecting_output,
        ),
    );
    try std.testing.expect(endpoint_owner.records.get(rejecting_record.handle) == null);
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());
    rejecting_record_owned = false;
    rejecting_record.deinit();
    std.testing.allocator.destroy(rejecting_record);

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    try std.testing.expect((try endpoint_owner.nextDeadline(no_allocation_allocator.allocator())) == null);
}
