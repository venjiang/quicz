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

        /// Drive one TLS packet-number space and drain its bounded output.
        pub fn driveBackend(
            self: *Self,
            connection_id: u64,
            connection: *Connection,
            space: root.PacketNumberSpace,
            backend: root.CryptoBackend,
            scratch: []u8,
            now_millis: i64,
            poll_options: root.EndpointPollInstalledKeyDatagramOptions,
            out: []root.EndpointPolledDatagramResult,
        ) root.Error!root.EndpointCryptoBackendDriveDatagramDrainResult {
            return self.lifecycle.driveCryptoBackendInSpaceAndDrainDatagrams(
                connection_id,
                connection,
                space,
                backend,
                scratch,
                now_millis,
                poll_options,
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
    const TestEndpoint = Tls13ServerEndpoint(
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.deinit,
    );

    var endpoint_owner = try TestEndpoint.initWithCapacity(std.testing.allocator, 1, .{
        .max_routes = 2,
        .max_stateless_reset_tokens = 2,
    });
    defer endpoint_owner.deinit();
    try std.testing.expect(endpoint_owner.records.hasCapacity());
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.routeCount());

    const record = try std.testing.allocator.create(TestRecord);
    errdefer std.testing.allocator.destroy(record);
    record.* = .{
        .handle = 7,
        .connection = try Connection.init(std.testing.allocator, .server, .{}),
    };
    try endpoint_owner.records.adopt(record.handle, record);
    try std.testing.expect(!endpoint_owner.records.hasCapacity());
    try endpoint_owner.records.remove(record.handle);
    try std.testing.expect(endpoint_owner.records.hasCapacity());

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    try std.testing.expect((try endpoint_owner.nextDeadline(no_allocation_allocator.allocator())) == null);
}
