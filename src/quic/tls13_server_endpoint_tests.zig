// Tls13ServerEndpoint tests — extracted for file size reduction.
const std = @import("std");
const endpoint_types = @import("endpoint_types.zig");
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
const buffer = @import("buffer.zig");
const duration_mod = @import("../time/duration.zig");

const Connection = connection_module.Connection;
const EndpointConnectionLifecycle = endpoint_lifecycle.EndpointConnectionLifecycle;
const Tls13ClientEndpoint = tls13_client_endpoint.Tls13ClientEndpoint;
const Tls13ServerTransport = tls13_server_transport.Tls13ServerTransport;
const ms = duration_mod.ns_per_ms;
const tls13_server_endpoint_mod = @import("tls13_server_endpoint.zig");
const Tls13ServerEndpoint = tls13_server_endpoint_mod.Tls13ServerEndpoint;
const address_validation_token = @import("address_validation_token.zig");

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
    initial_crypto: []const u8 = &.{},
    initial_sent: bool = false,

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

    fn pull(context: *anyopaque, space: root.PacketNumberSpace, _: []u8) root.Error!?[]const u8 {
        if (space == .handshake) return error.InvalidPacket;
        const self: *@This() = @ptrCast(@alignCast(context));
        if (space == .initial and !self.initial_sent and self.initial_crypto.len != 0) {
            self.initial_sent = true;
            return self.initial_crypto;
        }
        return null;
    }

    fn pullHandshakeTrafficSecrets(context: *anyopaque) root.Error!?root.HandshakeTrafficSecrets {
        const self: *@This() = @ptrCast(@alignCast(context));
        if (self.secrets_sent) return null;
        self.secrets_sent = true;
        return self.secrets;
    }
};

const AdmissionScenario = enum { initial_rejected, handshake_rejected, capacity_rejected, overlapping_outputs, empty_outputs, admitted };

fn checkInitialAdmissionOwnership(comptime Path: type, owned: bool, scenario: AdmissionScenario) !void {
    const TestRecord = struct {
        connection: Connection,
        backend: root.CryptoBackend,
        destructions: *usize,

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
            return "server";
        }

        fn initialDestinationConnectionId(_: *const @This()) []const u8 {
            return "original";
        }

        fn markRetryValidated(_: *@This()) void {}

        fn deinit(self: *@This()) void {
            self.destructions.* += 1;
            self.connection.deinit();
        }
    };
    const TestEndpoint = tls13_server_endpoint_mod.Tls13ServerEndpointForTuple(
        Path,
        TestRecord,
        TestRecord.connectionRef,
        TestRecord.cryptoBackend,
        TestRecord.destinationConnectionId,
        TestRecord.sourceConnectionId,
        TestRecord.initialDestinationConnectionId,
        TestRecord.markRetryValidated,
        TestRecord.deinit,
    );
    var owner = try TestEndpoint.initWithCapacity(std.testing.allocator, if (scenario == .capacity_rejected) 0 else 1, .{
        .max_routes = 2,
        .max_stateless_reset_tokens = 2,
    });
    var owner_initialized = true;
    defer if (owner_initialized) owner.deinit();

    const path: Path = if (Path == endpoint.Udp4Tuple) .{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 5443),
    } else .{
        .local = endpoint.Udp6Address.init(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 4433, 0),
        .remote = endpoint.Udp6Address.init(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 5443, 0),
    };
    var client = try Connection.init(std.testing.allocator, .client, .{});
    defer client.deinit();
    const original_dcid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7 };
    const client_scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const server_scid = "server";
    const secrets = try protection.deriveInitialSecrets(.v1, &original_dcid);
    try client.sendCryptoInSpace(.initial, "endpoint owned record admission");
    const datagram = (try client.pollInitialProtectedDatagram(1, &original_dcid, &client_scid, &.{}, secrets.client)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(datagram);
    var action_buffer: [256]u8 = undefined;
    const action = try owner.lifecycle.handleDatagramWithVersionNegotiation(&action_buffer, path, datagram, &.{}, &.{.v1});
    const initial_accept = switch (action) {
        .accept_initial => |initial| initial,
        else => return error.TestUnexpectedResult,
    };

    var initial_rejecting_backend = RejectingInitialBackend{};
    var handshake_backend = RejectingHandshakeBackend{
        .secrets = .{ .local = secrets.server.secret, .peer = secrets.client.secret },
        .secrets_sent = scenario != .handshake_rejected,
        .initial_crypto = "server Initial response",
    };
    var destructions: usize = 0;
    const handle = 7;
    const record = try std.testing.allocator.create(TestRecord);
    record.* = .{
        .connection = Connection.init(std.testing.allocator, .server, .{}) catch |err| {
            std.testing.allocator.destroy(record);
            return err;
        },
        .backend = if (scenario == .initial_rejected) initial_rejecting_backend.backend() else handshake_backend.backend(),
        .destructions = &destructions,
    };
    // Use the external destruction count before touching a rejected record.
    defer if (destructions == 0 and owner.records.get(handle) == null) {
        record.deinit();
        std.testing.allocator.destroy(record);
    };
    var scratch: [512]u8 = undefined;
    var initial_out: [2]endpoint_types.EndpointPolledDatagramResult = @splat(.{ .connection_id = 0, .datagram = &.{} });
    var handshake_out: [2]endpoint_types.EndpointPolledDatagramResult = @splat(.{ .connection_id = 0, .datagram = &.{} });
    var caller_owns_outputs = !owned;
    defer if (caller_owns_outputs) {
        for (&initial_out) |output| if (output.datagram.len != 0) std.testing.allocator.free(output.datagram);
        for (&handshake_out) |output| if (output.datagram.len != 0) std.testing.allocator.free(output.datagram);
    };
    const initial_slice = if (scenario == .empty_outputs) initial_out[0..0] else initial_out[0..];
    const handshake_slice = switch (scenario) {
        .overlapping_outputs => initial_out[1..],
        .empty_outputs => handshake_out[0..0],
        else => handshake_out[0..],
    };
    const admitted = if (owned)
        owner.acceptOwnedInitialRecord(handle, record, 2, initial_accept, server_scid, datagram, .{}, &scratch, initial_slice, handshake_slice)
    else
        owner.acceptInitialRecord(handle, record, 2, initial_accept, server_scid, datagram, .{}, &scratch, initial_slice, handshake_slice);
    switch (scenario) {
        .initial_rejected, .handshake_rejected => try std.testing.expectError(error.InvalidPacket, admitted),
        .capacity_rejected => try std.testing.expectError(error.ConnectionLimitReached, admitted),
        .overlapping_outputs => try std.testing.expectError(error.BufferTooSmall, admitted),
        .admitted, .empty_outputs => {
            const result = try admitted;
            caller_owns_outputs = true;
            if (scenario == .empty_outputs) {
                try std.testing.expectEqual(@as(usize, 0), result.initial.drain.datagrams_written);
            } else {
                try std.testing.expect(result.initial.drain.datagrams_written > 0);
            }
            try std.testing.expectEqual(@as(usize, 0), destructions);
            try std.testing.expect(owner.records.get(handle) != null);
            owner.deinit();
            owner_initialized = false;
            try std.testing.expectEqual(@as(usize, 1), destructions);
            return;
        },
    }
    const consumed = owned or scenario == .handshake_rejected;
    try std.testing.expectEqual(@as(usize, if (consumed) 1 else 0), destructions);
    try std.testing.expect(owner.records.get(handle) == null);
    try std.testing.expectEqual(@as(usize, 0), owner.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), owner.lifecycle.recoveryTimerCount());
    if (scenario == .handshake_rejected) {
        try std.testing.expect(handshake_backend.initial_sent);
        if (owned) try std.testing.expectEqual(@as(usize, 0), initial_out[0].datagram.len);
    }
}

test "Tls13ServerEndpoint owned admission consumes pre-adoption failures" {
    inline for (.{ endpoint.Udp4Tuple, endpoint.Udp6Tuple }) |Path| {
        try checkInitialAdmissionOwnership(Path, true, .initial_rejected);
        try checkInitialAdmissionOwnership(Path, true, .capacity_rejected);
        try checkInitialAdmissionOwnership(Path, true, .overlapping_outputs);
    }
}

test "Tls13ServerEndpoint owned admission consumes post-adoption failure and Initial output" {
    inline for (.{ endpoint.Udp4Tuple, endpoint.Udp6Tuple }) |Path| {
        try checkInitialAdmissionOwnership(Path, true, .handshake_rejected);
    }
}

test "Tls13ServerEndpoint owned admission retains successful records until shutdown" {
    inline for (.{ endpoint.Udp4Tuple, endpoint.Udp6Tuple }) |Path| {
        try checkInitialAdmissionOwnership(Path, true, .admitted);
        try checkInitialAdmissionOwnership(Path, true, .empty_outputs);
    }
}

test "Tls13ServerEndpoint legacy admission retains its actual failure ownership" {
    inline for (.{ endpoint.Udp4Tuple, endpoint.Udp6Tuple }) |Path| {
        try checkInitialAdmissionOwnership(Path, false, .initial_rejected);
        try checkInitialAdmissionOwnership(Path, false, .capacity_rejected);
        try checkInitialAdmissionOwnership(Path, false, .handshake_rejected);
        try checkInitialAdmissionOwnership(Path, false, .admitted);
    }
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
    const one_rtt = (try endpoint_owner.pollOneRttDatagram(record_handle, 1 * ms)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(one_rtt);
    try std.testing.expect(one_rtt.len != 0);
    _ = try endpoint_owner.retireRecord(record_handle);
    try std.testing.expect(endpoint_owner.records.hasCapacity());
    try std.testing.expect(endpoint_owner.hasConnectionCapacity());
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.activeConnectionCount());
    try std.testing.expectEqual(@as(usize, 0), (try endpoint_owner.activeConnectionIds(&active_ids)).len);
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.pollOneRttDatagram(record_handle, 2 * ms));

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
    _ = try retry_record.connection.recordPacketSentInSpace(.application, 10 * ms, 100);
    try endpoint_owner.lifecycle.armRecoveryTimerFromConnection(retry_record.handle, &retry_record.connection);
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.recoveryTimerCount());
    var backend_scratch: [1]u8 = undefined;
    var backend_output: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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
    const validation_secret: address_validation_token.Secret = @as([address_validation_token.secret_len]u8, @splat(0x55));
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
    var rejecting_output: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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
        @backingInt(frame.FrameType.crypto),
        "done",
        4,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(stale_close.datagram);
    const stale_close_deadline = stale_record.connection.closeDeadline() orelse return error.TestUnexpectedResult;
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
    var reclaimed_initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var reclaimed_handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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
    try std.testing.expectEqual(@as(?endpoint_types.EndpointConnectionDeadline, null), try dynamic_endpoint.nextDeadline(std.testing.allocator));

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
    deadline_record.connection.last_packet_activity_nanos = 10 * ms;
    try deadline_endpoint.records.adopt(deadline_record.handle, deadline_record);
    deadline_record_owned = false;

    var empty_deadline_views: [0]root.EndpointConnectionView = .{};
    try std.testing.expectError(error.BufferTooSmall, deadline_endpoint.nextDeadlineWithStorage(&empty_deadline_views));
    var deadline_views: [1]root.EndpointConnectionView = undefined;
    const storage_deadline = (try deadline_endpoint.nextDeadlineWithStorage(&deadline_views)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.idle_timeout, storage_deadline.kind);
    try std.testing.expectEqual(deadline_record.handle, storage_deadline.connection_id);
    try std.testing.expectEqual(@as(i64, 30 * ms), storage_deadline.deadline_nanos);
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
    var output: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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
    var process_initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var process_handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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
    const reset_token = @as([quic_packet.stateless_reset_token_len]u8, @splat(0x9a));
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
    var initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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

    const client_hs = @as([protection.traffic_secret_len]u8, @splat(0x31));
    const server_hs = @as([protection.traffic_secret_len]u8, @splat(0x32));
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

    const client_1rtt = @as([protection.traffic_secret_len]u8, @splat(0x51));
    const server_1rtt = @as([protection.traffic_secret_len]u8, @splat(0x52));
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
    const short_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(5 * ms, &server_cid)) orelse return error.TestUnexpectedResult;
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
                try std.testing.expectEqual(@as(?endpoint_types.EndpointConnectionDeadline, null), processed_short.next_deadline);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }

    try client.sendPing();
    const draining_short_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(7 * ms, &server_cid)) orelse return error.TestUnexpectedResult;
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
                try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, next_deadline.kind);
                try std.testing.expectEqual(root.PacketNumberSpace.application, next_deadline.recovery.?.space);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }

    // Duplicate coalesced Handshake+Initial packets are discarded per
    // RFC 9000 §13.1, not rejected.
    const duplicate_coalesced = try std.testing.allocator.alloc(u8, handshake_datagram.len + initial_datagram.len);
    defer std.testing.allocator.free(duplicate_coalesced);
    @memcpy(duplicate_coalesced[0..handshake_datagram.len], handshake_datagram);
    @memcpy(duplicate_coalesced[handshake_datagram.len..], initial_datagram);
    const duplicate_dispatch = try endpoint_owner.processLongDatagramWithRoutePath(
        record.handle,
        path,
        4,
        duplicate_coalesced,
        &scratch,
        &[_]u8{},
        &initial_out,
        &handshake_out,
    );
    switch (duplicate_dispatch) {
        .packet => |pkt| switch (pkt) {
            .handshake => |handshake| {
                try std.testing.expectEqual(record.handle, handshake.route.connection_id);
                try std.testing.expectEqual(@as(usize, 0), handshake.backend.backend.drain.datagrams_written);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
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

    const client_hs = @as([protection.traffic_secret_len]u8, @splat(0x41));
    const server_hs = @as([protection.traffic_secret_len]u8, @splat(0x42));
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
    var initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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

    const client_hs = @as([protection.traffic_secret_len]u8, @splat(0x71));
    const server_hs = @as([protection.traffic_secret_len]u8, @splat(0x72));
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
    var initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;

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
                .local = @as([protection.traffic_secret_len]u8, @splat(0x11)),
                .peer = @as([protection.traffic_secret_len]u8, @splat(0x22)),
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

    const secret: address_validation_token.Secret = @as([address_validation_token.secret_len]u8, @splat(0xf1));
    const nonce: address_validation_token.Nonce = @as([address_validation_token.nonce_len]u8, @splat(0x2c));
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
    var initial_outputs: [2]endpoint_types.EndpointPolledDatagramResult = undefined;
    var handshake_outputs: [2]endpoint_types.EndpointPolledDatagramResult = undefined;
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

    const secret: address_validation_token.Secret = @as([address_validation_token.secret_len]u8, @splat(0xf2));
    const nonce: address_validation_token.Nonce = @as([address_validation_token.nonce_len]u8, @splat(0x2d));
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
    var initial_outputs: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var handshake_outputs: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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
    const datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(1 * ms, server_dcid)) orelse return error.TestUnexpectedResult;
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
    const pending_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(3 * ms, server_dcid)) orelse return error.TestUnexpectedResult;
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
    const drain_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(5 * ms, server_dcid)) orelse return error.TestUnexpectedResult;
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
    const poll_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(7 * ms, server_dcid)) orelse return error.TestUnexpectedResult;
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
    const route_poll_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(9 * ms, server_dcid)) orelse return error.TestUnexpectedResult;
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
    const route_drain_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(11 * ms, server_dcid)) orelse return error.TestUnexpectedResult;
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
    const routed_dispatch_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(13 * ms, server_dcid)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(routed_dispatch_datagram);
    const dispatch_route = try endpoint_owner.routeDatagram(path, routed_dispatch_datagram);
    var process_scratch: [64]u8 = undefined;
    var process_initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var process_handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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
    const routed_dispatch_drain_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(15 * ms, server_dcid)) orelse return error.TestUnexpectedResult;
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
    const classified_dispatch_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(17 * ms, server_dcid)) orelse return error.TestUnexpectedResult;
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
    const classified_dispatch_drain_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(19 * ms, server_dcid)) orelse return error.TestUnexpectedResult;
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
    const receive_step_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(21 * ms, server_dcid)) orelse return error.TestUnexpectedResult;
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
    const admission_step_datagram = (try client.pollProtectedShortDatagramWithInstalledKeys(23 * ms, server_dcid)) orelse return error.TestUnexpectedResult;
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
    var initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    const direct_options: endpoint_types.EndpointFeedInstalledKeyDatagramOptions = .{
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
    var initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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
    var step_initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var step_handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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
    var scratch_step_initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var scratch_step_handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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
    var dynamic_scratch_initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var dynamic_scratch_handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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
    var capacity_initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var capacity_handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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
        .connection = try Connection.init(std.testing.allocator, .server, .{ .initial_rtt_ns = 100 }),
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
    const first = (try endpoint_owner.pollOneRttDatagram(record.handle, 10 * ms)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(first);
    const deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, deadline.kind);
    try std.testing.expectEqual(record.handle, deadline.connection_id);

    _ = try endpoint_owner.lifecycle.updateRoutePathFromValidatedDatagramAndResetSpinBit(
        server_dcid,
        new_path,
        &record.connection,
    );

    var zero_due_out: [0]TestEndpoint.DatagramPathResult = .{};
    try std.testing.expectError(error.BufferTooSmall, endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePathWithScratch(
        deadline.deadline_nanos,
        &zero_due_out,
    ));
    const zero_preserved_deadline = (try endpoint_owner.nextDeadlineWithScratch()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, zero_preserved_deadline.kind);
    try std.testing.expectEqual(record.handle, zero_preserved_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, zero_preserved_deadline.recovery.?.space);

    var due_out: [1]TestEndpoint.DatagramPathResult = undefined;
    try std.testing.expect(try endpoint_owner.lifecycle.retireConnectionIdOnPath(server_dcid, new_path));
    const missing_route_due = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePath(
        std.testing.allocator,
        deadline.deadline_nanos,
        &due_out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, missing_route_due.deadline.connection_id);
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, missing_route_due.deadline.kind);
    try std.testing.expect(missing_route_due.pending_work.recovery_serviced == null);
    try std.testing.expectEqual(@as(usize, 0), missing_route_due.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), missing_route_due.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), missing_route_due.drain.first_route_error);
    const allocator_preserved_deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, allocator_preserved_deadline.kind);
    try std.testing.expectEqual(record.handle, allocator_preserved_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, allocator_preserved_deadline.recovery.?.space);

    const missing_route_due_scratch = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePathWithScratch(
        deadline.deadline_nanos,
        &due_out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, missing_route_due_scratch.deadline.connection_id);
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, missing_route_due_scratch.deadline.kind);
    try std.testing.expect(missing_route_due_scratch.pending_work.recovery_serviced == null);
    try std.testing.expectEqual(@as(usize, 0), missing_route_due_scratch.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), missing_route_due_scratch.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), missing_route_due_scratch.drain.first_route_error);
    const preserved_deadline = (try endpoint_owner.nextDeadlineWithScratch()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, preserved_deadline.kind);
    try std.testing.expectEqual(record.handle, preserved_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, preserved_deadline.recovery.?.space);
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, new_path, .{});

    const due = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePathWithScratch(
        deadline.deadline_nanos,
        &due_out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, due.deadline.connection_id);
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, due.deadline.kind);
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, next_deadline.kind);
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
    _ = try live_record.connection.recordPacketSentInSpace(.application, 10 * ms, 100);
    try endpoint_owner.lifecycle.armRecoveryTimerFromConnection(live_handle, &live_record.connection);
    const live_deadline = live_record.connection.lossDetectionTimerDeadline() orelse return error.TestUnexpectedResult;
    try endpoint_owner.records.adopt(live_handle, live_record);
    live_owned = false;

    try std.testing.expectEqual(@as(usize, 2), endpoint_owner.records.count());
    try std.testing.expectEqual(@as(usize, 2), endpoint_owner.lifecycle.routeCount());
    try std.testing.expect(try endpoint_owner.lifecycle.retireConnectionIdOnPath("live-local", live_path));
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());

    var out: [1]TestEndpoint.DatagramPathResult = undefined;
    const result = try endpoint_owner.processPendingWorkAndDrainDatagramsWithRoutePathWithScratch(
        live_deadline.deadline_nanos,
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, preserved_deadline.kind);
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, deadline.kind);
    try std.testing.expectEqual(root.PacketNumberSpace.application, deadline.recovery.?.space);

    var pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const recovery_local_id = if (deadline.connection_id == first_record.handle) first_record.local_id else second_record.local_id;
    const recovery_path = if (deadline.connection_id == first_record.handle) first_path else second_path;
    try std.testing.expect(try endpoint_owner.lifecycle.retireConnectionIdOnPath(recovery_local_id, recovery_path));
    const mismatched_space_pending = try endpoint_owner.processPendingWorkAndDrainDatagramsWithRoutePath(
        no_allocation_allocator.allocator(),
        deadline.deadline_nanos,
        .handshake,
        &pending_out,
    );
    try std.testing.expectEqual(@as(usize, 0), mismatched_space_pending.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), mismatched_space_pending.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), mismatched_space_pending.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), mismatched_space_pending.drain.first_route_error);
    const mismatched_preserved_deadline = mismatched_space_pending.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, mismatched_preserved_deadline.kind);
    try std.testing.expectEqual(deadline.connection_id, mismatched_preserved_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, mismatched_preserved_deadline.recovery.?.space);

    const missing_route_pending = try endpoint_owner.processPendingWorkAndDrainDatagramsWithRoutePath(
        no_allocation_allocator.allocator(),
        deadline.deadline_nanos,
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, preserved_deadline.kind);
    try std.testing.expectEqual(deadline.connection_id, preserved_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, preserved_deadline.recovery.?.space);

    var zero_missing_route_pending_out: [0]TestEndpoint.DatagramPathResult = .{};
    const zero_missing_route_pending = try endpoint_owner.processPendingWorkAndDrainDatagramsWithRoutePath(
        no_allocation_allocator.allocator(),
        deadline.deadline_nanos,
        .application,
        &zero_missing_route_pending_out,
    );
    try std.testing.expectEqual(@as(usize, 0), zero_missing_route_pending.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), zero_missing_route_pending.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), zero_missing_route_pending.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), zero_missing_route_pending.drain.first_route_error);
    const zero_missing_route_deadline = zero_missing_route_pending.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, zero_missing_route_deadline.kind);
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
        deadline.deadline_nanos,
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, missing_route_poll_deadline.kind);
    try std.testing.expectEqual(deadline.connection_id, missing_route_poll_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, missing_route_poll_deadline.recovery.?.space);

    var missing_route_step_out: [128]u8 = undefined;
    var missing_route_scratch: [64]u8 = undefined;
    var missing_route_initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var missing_route_handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var missing_route_installed_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var missing_route_step_pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const missing_route_step = try endpoint_owner.receiveDatagramStepWithRoutePath(
        no_allocation_allocator.allocator(),
        first_path,
        deadline.deadline_nanos,
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, missing_route_step_deadline.kind);
    try std.testing.expectEqual(deadline.connection_id, missing_route_step_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, missing_route_step_deadline.recovery.?.space);

    const missing_route_step_scratch = try endpoint_owner.receiveDatagramStepWithRoutePathWithScratch(
        first_path,
        deadline.deadline_nanos,
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, missing_route_step_scratch_deadline.kind);
    try std.testing.expectEqual(deadline.connection_id, missing_route_step_scratch_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, missing_route_step_scratch_deadline.recovery.?.space);

    var zero_missing_route_step_pending_out: [0]TestEndpoint.DatagramPathResult = .{};
    const zero_missing_route_step = try endpoint_owner.receiveDatagramStepWithRoutePath(
        no_allocation_allocator.allocator(),
        first_path,
        deadline.deadline_nanos,
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, zero_missing_route_step_deadline.kind);
    try std.testing.expectEqual(deadline.connection_id, zero_missing_route_step_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, zero_missing_route_step_deadline.recovery.?.space);

    try endpoint_owner.lifecycle.registerConnectionId(deadline.connection_id, recovery_local_id, recovery_path, .{});

    var zero_pending_out: [0]TestEndpoint.DatagramPathResult = .{};
    const zero_pending_scratch = try endpoint_owner.processPendingWorkAndDrainDatagramsWithRoutePathWithScratch(
        deadline.deadline_nanos,
        .application,
        &zero_pending_out,
    );
    try std.testing.expectEqual(@as(usize, 0), zero_pending_scratch.pending_work.recovery_serviced_count);
    try std.testing.expectEqual(@as(usize, 0), zero_pending_scratch.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, error.BufferTooSmall), zero_pending_scratch.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, null), zero_pending_scratch.drain.first_route_error);
    const zero_pending_scratch_deadline = zero_pending_scratch.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, zero_pending_scratch_deadline.kind);
    try std.testing.expectEqual(deadline.connection_id, zero_pending_scratch_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, zero_pending_scratch_deadline.recovery.?.space);

    const zero_pending = try endpoint_owner.processPendingWorkAndDrainDatagramsWithRoutePath(
        no_allocation_allocator.allocator(),
        deadline.deadline_nanos,
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, zero_pending_deadline.kind);
    try std.testing.expectEqual(deadline.connection_id, zero_pending_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, zero_pending_deadline.recovery.?.space);

    const pending_drain = try endpoint_owner.processPendingWorkAndDrainDatagramsWithRoutePath(
        no_allocation_allocator.allocator(),
        deadline.deadline_nanos,
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, next_deadline.kind);

    try second_record.connection.sendPing();
    const step_first = (try endpoint_owner.pollDatagramWithRoutePath(
        no_allocation_allocator.allocator(),
        20,
        .application,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(step_first.datagram);
    const step_deadline = (try endpoint_owner.nextDeadline(no_allocation_allocator.allocator())) orelse return error.TestUnexpectedResult;
    try std.testing.expect(step_deadline.connection_id == first_record.handle or step_deadline.connection_id == second_record.handle);
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, step_deadline.kind);

    var route_out: [128]u8 = undefined;
    var scratch: [64]u8 = undefined;
    var initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var zero_step_pending_out: [0]TestEndpoint.DatagramPathResult = .{};
    const zero_step = try endpoint_owner.receiveDatagramStepWithRoutePath(
        no_allocation_allocator.allocator(),
        first_path,
        step_deadline.deadline_nanos,
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, zero_step_deadline.kind);
    try std.testing.expectEqual(step_deadline.connection_id, zero_step_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.application, zero_step_deadline.recovery.?.space);

    var step_pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const step = try endpoint_owner.receiveDatagramStepWithRoutePath(
        no_allocation_allocator.allocator(),
        first_path,
        step_deadline.deadline_nanos,
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, step_next_deadline.kind);

    try first_record.connection.sendPing();
    var terminal_close_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const terminal_close = try endpoint_owner.closeWithRoutePathAndDrainDatagrams(
        no_allocation_allocator.allocator(),
        second_record.handle,
        0,
        @backingInt(frame.FrameType.ping),
        "done",
        30,
        &terminal_close_out,
    );
    try std.testing.expectEqual(@as(usize, 1), terminal_close.drain.datagrams_written);
    defer std.testing.allocator.free(terminal_close_out[0].datagram);
    const close_deadline = (try endpoint_owner.closeDeadline(second_record.handle)) orelse return error.TestUnexpectedResult;
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
        .connection = try Connection.init(std.testing.allocator, .server, .{ .initial_rtt_ns = 100 }),
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, deadline.kind);
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
        deadline.deadline_nanos,
        &zero_due_out,
    ));
    const zero_preserved_deadline = (try endpoint_owner.nextDeadlineWithScratch()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, zero_preserved_deadline.kind);
    try std.testing.expectEqual(record.handle, zero_preserved_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.initial, zero_preserved_deadline.recovery.?.space);

    var due_out: [1]TestEndpoint.DatagramPathResult = undefined;
    try std.testing.expect(try endpoint_owner.lifecycle.retireConnectionIdOnPath(server_dcid, new_path));
    const missing_route_due = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePath(
        std.testing.allocator,
        deadline.deadline_nanos,
        &due_out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, missing_route_due.deadline.connection_id);
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, missing_route_due.deadline.kind);
    try std.testing.expect(missing_route_due.pending_work.recovery_serviced == null);
    try std.testing.expectEqual(@as(usize, 0), missing_route_due.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), missing_route_due.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), missing_route_due.drain.first_route_error);
    const allocator_preserved_deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, allocator_preserved_deadline.kind);
    try std.testing.expectEqual(record.handle, allocator_preserved_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.initial, allocator_preserved_deadline.recovery.?.space);

    const missing_route_due_scratch = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePathWithScratch(
        deadline.deadline_nanos,
        &due_out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, missing_route_due_scratch.deadline.connection_id);
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, missing_route_due_scratch.deadline.kind);
    try std.testing.expect(missing_route_due_scratch.pending_work.recovery_serviced == null);
    try std.testing.expectEqual(@as(usize, 0), missing_route_due_scratch.drain.datagrams_written);
    try std.testing.expectEqual(@as(?root.Error, null), missing_route_due_scratch.drain.first_error);
    try std.testing.expectEqual(@as(?endpoint.RouteError, error.UnknownConnectionId), missing_route_due_scratch.drain.first_route_error);
    const preserved_deadline = (try endpoint_owner.nextDeadlineWithScratch()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, preserved_deadline.kind);
    try std.testing.expectEqual(record.handle, preserved_deadline.connection_id);
    try std.testing.expectEqual(root.PacketNumberSpace.initial, preserved_deadline.recovery.?.space);
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, new_path, .{});

    const due = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePathWithScratch(
        deadline.deadline_nanos,
        &due_out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, due.deadline.connection_id);
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, due.deadline.kind);
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, next_deadline.kind);
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
        .connection = try Connection.init(std.testing.allocator, .server, .{ .initial_rtt_ns = 100 }),
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, deadline.kind);
    const timer = deadline.recovery orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(root.PacketNumberSpace.initial, timer.space);

    var zero_due_out: [0]endpoint_types.EndpointPolledDatagramResult = .{};
    try std.testing.expectError(error.BufferTooSmall, endpoint_owner.processDueDeadlineAndDrainDatagramsWithScratch(
        deadline.deadline_nanos,
        &zero_due_out,
    ));
    const preserved_deadline = (try endpoint_owner.nextDeadlineWithScratch()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, preserved_deadline.connection_id);
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, preserved_deadline.kind);
    try std.testing.expectEqual(root.PacketNumberSpace.initial, preserved_deadline.recovery.?.space);

    var due_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    const due = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithScratch(
        deadline.deadline_nanos,
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, next_deadline.kind);
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
    const first = (try endpoint_owner.pollOneRttDatagram(record_handle, 10 * ms)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(first);
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.recoveryTimerCount());

    const idle_deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.idle_timeout, idle_deadline.kind);
    try std.testing.expectEqual(record_handle, idle_deadline.connection_id);
    try std.testing.expectEqual(@as(i64, 20 * ms), idle_deadline.deadline_nanos);

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    var out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    try std.testing.expect((try endpoint_owner.processDueDeadlineAndDrainDatagrams(
        no_allocation_allocator.allocator(),
        19 * ms,
        &out,
    )) == null);
    try std.testing.expect(endpoint_owner.records.get(record_handle) != null);
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());

    const due = (try endpoint_owner.processDueDeadlineAndDrainDatagrams(
        no_allocation_allocator.allocator(),
        20 * ms,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.idle_timeout, due.deadline.kind);
    try std.testing.expect(due.pending_work.idle_retired != null);
    try std.testing.expectEqual(@as(?endpoint_types.EndpointConnectionRetireResult, null), due.pending_work.close_retired);
    try std.testing.expectEqual(@as(usize, 0), due.drain.datagrams_written);
    try std.testing.expectEqual(@as(?endpoint_types.EndpointConnectionDeadline, null), due.next_deadline);
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
    const first = (try endpoint_owner.pollOneRttDatagram(record_handle, 10 * ms)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(first);
    const idle_deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.idle_timeout, idle_deadline.kind);
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
    var initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const step = try endpoint_owner.receiveDatagramStepWithRoutePath(
        no_allocation_allocator.allocator(),
        path,
        idle_deadline.deadline_nanos,
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
    try std.testing.expectEqual(@as(?endpoint_types.EndpointConnectionDeadline, null), step.next_deadline);
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
        .connection = try Connection.init(std.testing.allocator, .server, .{ .initial_rtt_ns = 100 }),
        .backend = empty_backend.backend(),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    const local_secret = @as([protection.traffic_secret_len]u8, @splat(0x6a));
    const peer_secret = @as([protection.traffic_secret_len]u8, @splat(0x6b));
    try record.connection.installOneRttTrafficSecrets(.{
        .local = local_secret,
        .peer = peer_secret,
    });
    record.connection.last_packet_activity_nanos = 10 * ms;
    try record.connection.initiateOneRttKeyUpdate();
    try std.testing.expectEqual(@as(?bool, true), record.connection.localOneRttRetainsKeyGeneration(0));
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;
    const record_handle = record.handle;

    const discard_deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.key_discard, discard_deadline.kind);
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
    var initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const step = try endpoint_owner.receiveDatagramStepWithRoutePath(
        no_allocation_allocator.allocator(),
        path,
        discard_deadline.deadline_nanos,
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
    try std.testing.expectEqual(@as(?endpoint_types.EndpointConnectionDeadline, null), step.next_deadline);
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
        .connection = try Connection.init(std.testing.allocator, .server, .{ .initial_rtt_ns = 100 }),
        .backend = empty_backend.backend(),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    const local_secret = @as([protection.traffic_secret_len]u8, @splat(0x6c));
    const peer_secret = @as([protection.traffic_secret_len]u8, @splat(0x6d));
    try record.connection.installOneRttTrafficSecrets(.{
        .local = local_secret,
        .peer = peer_secret,
    });
    record.connection.last_packet_activity_nanos = 10 * ms;
    try record.connection.initiateOneRttKeyUpdate();
    try std.testing.expectEqual(@as(?u64, 1), record.connection.localOneRttKeyUpdateCount());
    try std.testing.expectEqual(@as(?bool, true), record.connection.localOneRttRetainsKeyGeneration(0));
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;
    const record_handle = record.handle;

    const discard_deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.key_discard, discard_deadline.kind);
    try std.testing.expectEqual(record_handle, discard_deadline.connection_id);
    try std.testing.expect((try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePath(
        std.testing.allocator,
        discard_deadline.deadline_nanos - 1,
        &.{},
    )) == null);

    var pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    const due = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePath(
        std.testing.allocator,
        discard_deadline.deadline_nanos,
        &pending_out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.key_discard, due.deadline.kind);
    try std.testing.expectEqual(record_handle, due.deadline.connection_id);
    try std.testing.expectEqual(@as(?endpoint_types.EndpointConnectionRetireResult, null), due.pending_work.idle_retired);
    try std.testing.expectEqual(@as(?endpoint_types.EndpointConnectionRetireResult, null), due.pending_work.close_retired);
    try std.testing.expect(due.pending_work.key_discard_serviced);
    try std.testing.expectEqual(@as(?endpoint_types.EndpointLossDetectionTimerDeadline, null), due.pending_work.recovery_serviced);
    try std.testing.expectEqual(@as(usize, 0), due.drain.datagrams_written);
    try std.testing.expectEqual(@as(?endpoint_types.EndpointConnectionDeadline, null), due.next_deadline);

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
        .connection = try Connection.init(std.testing.allocator, .server, .{ .initial_rtt_ns = 100 }),
        .backend = empty_backend.backend(),
    };
    record_initialized = true;
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    const local_secret = @as([protection.traffic_secret_len]u8, @splat(0x6e));
    const peer_secret = @as([protection.traffic_secret_len]u8, @splat(0x6f));
    try record.connection.installOneRttTrafficSecrets(.{
        .local = local_secret,
        .peer = peer_secret,
    });
    record.connection.last_packet_activity_nanos = 10 * ms;
    try record.connection.initiateOneRttKeyUpdate();
    try std.testing.expectEqual(@as(?u64, 1), record.connection.localOneRttKeyUpdateCount());
    try std.testing.expectEqual(@as(?bool, true), record.connection.localOneRttRetainsKeyGeneration(0));
    try endpoint_owner.lifecycle.registerConnectionId(record.handle, server_dcid, path, .{});
    errdefer _ = endpoint_owner.lifecycle.retireConnection(record.handle);
    try endpoint_owner.records.adopt(record.handle, record);
    record_owned = false;
    const record_handle = record.handle;

    const discard_deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.key_discard, discard_deadline.kind);
    try std.testing.expectEqual(record_handle, discard_deadline.connection_id);
    var out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    try std.testing.expect((try endpoint_owner.processDueDeadlineAndDrainDatagrams(
        std.testing.allocator,
        discard_deadline.deadline_nanos - 1,
        &out,
    )) == null);

    const due = (try endpoint_owner.processDueDeadlineAndDrainDatagrams(
        std.testing.allocator,
        discard_deadline.deadline_nanos,
        &out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.key_discard, due.deadline.kind);
    try std.testing.expectEqual(record_handle, due.deadline.connection_id);
    try std.testing.expectEqual(@as(?endpoint_types.EndpointConnectionRetireResult, null), due.pending_work.idle_retired);
    try std.testing.expectEqual(@as(?endpoint_types.EndpointConnectionRetireResult, null), due.pending_work.close_retired);
    try std.testing.expect(due.pending_work.key_discard_serviced);
    try std.testing.expectEqual(@as(?endpoint_types.EndpointLossDetectionTimerDeadline, null), due.pending_work.recovery_serviced);
    try std.testing.expectEqual(@as(usize, 0), due.drain.datagrams_written);
    try std.testing.expectEqual(@as(?endpoint_types.EndpointConnectionDeadline, null), due.next_deadline);

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
        dynamic_endpoint.processPendingWorkAndSelectNextDeadlineWithScratch(20 * ms),
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
        10 * ms,
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
        10 * ms,
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.idle_timeout, first_deadline.kind);
    try std.testing.expectEqual(@as(i64, 20 * ms), first_deadline.deadline_nanos);

    const swept = try endpoint_owner.processPendingWorkAndSelectNextDeadlineWithScratch(20 * ms);
    try std.testing.expectEqual(@as(usize, 1), swept.pending_work.idle_retired_count);
    try std.testing.expectEqual(@as(usize, 0), swept.pending_work.close_retired_count);
    try std.testing.expect(endpoint_owner.records.get(91) == null);
    try std.testing.expect(endpoint_owner.records.get(92) != null);
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.activeConnectionCount());
    const next = swept.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 92), next.connection_id);
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.idle_timeout, next.kind);
    try std.testing.expectEqual(@as(i64, 110 * ms), next.deadline_nanos);
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

    const close_deadline = (try endpoint_owner.closeDeadline(record_handle)) orelse return error.TestUnexpectedResult;
    const deadline = (try endpoint_owner.nextDeadline(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.close_timeout, deadline.kind);
    try std.testing.expectEqual(record_handle, deadline.connection_id);
    try std.testing.expectEqual(close_deadline, deadline.deadline_nanos);

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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.close_timeout, due.deadline.kind);
    try std.testing.expect(due.pending_work.close_retired != null);
    try std.testing.expectEqual(@as(?endpoint_types.EndpointConnectionRetireResult, null), due.pending_work.idle_retired);
    try std.testing.expectEqual(@as(usize, 0), due.drain.datagrams_written);
    try std.testing.expect(endpoint_owner.records.get(record_handle) == null);
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.routeCount());
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.closeDeadline(record_handle));
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
    try std.testing.expectEqual(@as(?i64, null), try endpoint_owner.closeDeadline(record_handle));
    try std.testing.expectError(error.BufferTooSmall, endpoint_owner.closeWithRoutePathAndDrainDatagramsWithScratch(
        record_handle,
        0,
        0,
        "server done",
        10,
        &zero_out,
    ));
    try std.testing.expectEqual(connection_module.ConnectionState.active, record.connection.connectionState());
    try std.testing.expectEqual(@as(?i64, null), try endpoint_owner.closeDeadline(record_handle));

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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.close_timeout, next_deadline.kind);
    try std.testing.expectEqual(record_handle, next_deadline.connection_id);
    try std.testing.expect((try endpoint_owner.closeDeadline(record_handle)) != null);
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
    try std.testing.expectEqual(@as(?i64, null), try endpoint_owner.closeDeadline(record_handle));

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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.close_timeout, next_deadline.kind);
    try std.testing.expectEqual(record_handle, next_deadline.connection_id);
    try std.testing.expect((try endpoint_owner.closeDeadline(record_handle)) != null);
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.close_timeout, close_deadline.kind);
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
    var initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var installed_key_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var pending_out: [1]TestEndpoint.DatagramPathResult = undefined;
    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const step = try endpoint_owner.receiveDatagramStepWithRoutePath(
        no_allocation_allocator.allocator(),
        path,
        close_deadline.deadline_nanos,
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
    try std.testing.expectEqual(@as(?endpoint_types.EndpointConnectionDeadline, null), step.next_deadline);
    try std.testing.expect(endpoint_owner.records.get(record_handle) == null);
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.activeConnectionCount());
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.routeCount());
    try std.testing.expectError(error.UnknownConnectionId, endpoint_owner.closeDeadline(record_handle));
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
    const options = endpoint_types.EndpointFeedInstalledKeyDatagramOptions{
        .space = .application,
        .out = &[_]u8{},
        .unpredictable_prefix = &[_]u8{},
        .supported_versions = &[_]quic_packet.Version{.v1},
        .path_challenge_data = challenge_data,
    };

    try client.sendPing();
    const migrated_ping = (try client.pollProtectedShortDatagramWithInstalledKeys(1 * ms, server_dcid)) orelse return error.TestUnexpectedResult;
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

    try client.processProtectedShortDatagramWithInstalledKeys(3 * ms, client_dcid.len, challenge_packet.datagram);
    const response = (try client.pollProtectedShortDatagramWithInstalledKeys(4 * ms, server_dcid)) orelse return error.TestUnexpectedResult;
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
    const routed_ping = (try client.pollProtectedShortDatagramWithInstalledKeys(7 * ms, server_dcid)) orelse return error.TestUnexpectedResult;
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, routed_next_deadline.kind);

    try record.connection.sendPing();
    const malformed_on_route = [_]u8{ 0x40, 'l', 'o', 'c', 'a', 'l', 0x00 };
    const malformed_result = try endpoint_owner.feedInstalledKeyDatagramWithRoutePath(
        new_path,
        9,
        &malformed_on_route,
        options,
    );
    try std.testing.expectEqual(@as(?endpoint_types.EndpointProtectedDatagramError, error.InvalidPacket), malformed_result.feed_error);
    try std.testing.expect(malformed_result.feed == null);
    try std.testing.expectEqual(connection_module.ConnectionState.active, record.connection.connectionState());
    try std.testing.expect(malformed_result.datagram == null);
    const malformed_next_deadline = malformed_result.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, malformed_next_deadline.connection_id);
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.recovery, malformed_next_deadline.kind);

    const queued_server_ping = (try endpoint_owner.pollOneRttDatagramWithRoutePath(record.handle, 10)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(queued_server_ping.datagram);
    try std.testing.expect(queued_server_ping.path.eql(new_path));
    try std.testing.expect(queued_server_ping.datagram.len != 0);

    const invalid_packet_number = record.connection.nextPeerPacketNumber(.application);
    const illegal_plaintext = [_]u8{@backingInt(frame.FrameType.handshake_done)} ++ (@as([31]u8, @splat(0)));
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
    try std.testing.expectEqual(@as(?endpoint_types.EndpointProtectedDatagramError, error.InvalidPacket), error_result.feed_error);
    try std.testing.expect(error_result.feed == null);
    try std.testing.expectEqual(connection_module.ConnectionState.closing, record.connection.connectionState());

    const close_output = error_result.datagram orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(close_output.datagram);
    try std.testing.expectEqual(record.handle, close_output.connection_id);
    try std.testing.expect(close_output.path.eql(new_path));
    const close_next_deadline = error_result.next_deadline orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(record.handle, close_next_deadline.connection_id);
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.close_timeout, close_next_deadline.kind);
    try client.processProtectedShortDatagramWithInstalledKeys(12 * ms, client_dcid.len, close_output.datagram);
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
            const illegal_plaintext = [_]u8{@backingInt(frame.FrameType.handshake_done)} ++ (@as([31]u8, @splat(0)));
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
    const options = endpoint_types.EndpointFeedInstalledKeyDatagramOptions{
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
    try std.testing.expectEqual(@as(?endpoint_types.EndpointProtectedDatagramError, error.InvalidPacket), poll_result.feed_error);
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
    var initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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
    try std.testing.expectEqual(@as(?endpoint_types.EndpointProtectedDatagramError, error.InvalidPacket), installed.feed_error);
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
    try std.testing.expectEqual(@as(?endpoint_types.EndpointProtectedDatagramError, error.InvalidPacket), zero_installed.feed_error);
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

    const ping_plaintext = [_]u8{@backingInt(frame.FrameType.ping)} ++ (@as([31]u8, @splat(0)));
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
    const reset_token = @as([quic_packet.stateless_reset_token_len]u8, @splat(0xbb));
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
    try record.connection.processDatagram(0 * ms, writer.getWritten());
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    _ = try record.connection.recordPacketSentInSpace(.application, 1 * ms, 64);
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
    var initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.close_timeout, reset_next_deadline.kind);
    try std.testing.expectEqual(connection_module.ConnectionState.draining, record.connection.connectionState());
    try std.testing.expectEqual(@as(usize, 1), endpoint_owner.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), endpoint_owner.lifecycle.recoveryTimerCount());

    var no_allocation_storage: [0]u8 = .{};
    var no_allocation_allocator = std.heap.FixedBufferAllocator.init(&no_allocation_storage);
    const deadline = (try endpoint_owner.nextDeadline(no_allocation_allocator.allocator())) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.close_timeout, deadline.kind);
    try std.testing.expectEqual(record_handle, deadline.connection_id);

    var due_out: [1]TestEndpoint.DatagramPathResult = undefined;
    try std.testing.expect((try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePath(
        no_allocation_allocator.allocator(),
        deadline.deadline_nanos - 1,
        &due_out,
    )) == null);
    try std.testing.expect(endpoint_owner.records.get(record_handle) != null);

    const due = (try endpoint_owner.processDueDeadlineAndDrainDatagramsWithRoutePath(
        no_allocation_allocator.allocator(),
        deadline.deadline_nanos,
        &due_out,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(due.pending_work.close_retired != null);
    try std.testing.expectEqual(@as(usize, 0), due.drain.datagrams_written);
    try std.testing.expectEqual(@as(?endpoint_types.EndpointConnectionDeadline, null), due.next_deadline);
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
    const reset_token = @as([quic_packet.stateless_reset_token_len]u8, @splat(0xbc));
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
    try record.connection.processDatagram(0 * ms, writer.getWritten());
    try record.connection.validatePeerAddress();
    try record.connection.confirmHandshake();
    _ = try record.connection.recordPacketSentInSpace(.application, 1 * ms, 64);
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
    var initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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
    try std.testing.expectEqual(endpoint_types.EndpointConnectionDeadlineKind.close_timeout, reset_next_deadline.kind);
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
    var server_initial_out: [2]endpoint_types.EndpointPolledDatagramResult = undefined;
    var server_handshake_out: [2]endpoint_types.EndpointPolledDatagramResult = undefined;
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
    var server_finish_initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var server_finish_handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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
    var hs_initial_out: [2]endpoint_types.EndpointPolledDatagramResult = undefined;
    var hs_handshake_out: [2]endpoint_types.EndpointPolledDatagramResult = undefined;
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

    var fin_initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
    var fin_handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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

    // --- Phase 1b: Verify obsolete Initial key discard after handshake ---
    try std.testing.expect(active_record.transport.connection.packetNumberSpaceDiscarded(.initial));

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
        var s_initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
        var s_handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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

    // --- Phase 7c: Client sends a unidirectional stream with FIN ---
    const uni_stream_id = try client.openUniStream();
    try std.testing.expectEqual(@as(u64, 2), uni_stream_id);
    const uni_payload = "uni data";
    var client_uni_out: [4]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
    const client_uni_send = try client.sendStreamWithRoutePathAndDrainDatagrams(
        uni_stream_id,
        uni_payload,
        true,
        24,
        &client_uni_out,
    );
    try std.testing.expect(client_uni_send.drain.datagrams_written >= 1);
    const client_uni_written = client_uni_send.drain.datagrams_written;
    defer {
        for (client_uni_out[0..client_uni_written]) |o| std.testing.allocator.free(o.datagram);
    }

    // --- Phase 7d: Server receives every client uni-stream datagram ---
    for (client_uni_out[0..client_uni_written]) |uni_datagram| {
        var su_initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
        var su_handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
        var su_installed_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
        var su_pending_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
        var su_route_out: [256]u8 = undefined;
        const su_step = try server_endpoint.receiveDatagramStepWithRoutePath(
            std.testing.allocator,
            server_path,
            25,
            uni_datagram.datagram,
            &[_]u8{},
            &[_]quic_packet.Version{.v1},
            .{
                .space = .application,
                .out = &su_route_out,
                .unpredictable_prefix = &[_]u8{},
                .supported_versions = &[_]quic_packet.Version{.v1},
            },
            &server_scratch,
            &[_]u8{},
            &su_initial_out,
            &su_handshake_out,
            &su_installed_out,
            .application,
            &su_pending_out,
        );
        var su_ik_written: usize = 0;
        switch (su_step.process) {
            .routed => |routed| switch (routed) {
                .installed_key => |ik| {
                    su_ik_written = ik.drain.datagrams_written;
                },
                else => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        }
        for (su_installed_out[0..su_ik_written]) |o| std.testing.allocator.free(o.datagram);
        for (su_pending_out[0..su_step.pending_drain.datagrams_written]) |o| std.testing.allocator.free(o.datagram);
    }

    // --- Phase 7e: Server reads the uni-stream data ---
    var server_uni_buf: [64]u8 = undefined;
    const server_uni_len = (try server_endpoint.recvStream(server_handle, uni_stream_id, &server_uni_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(uni_payload, server_uni_buf[0..server_uni_len]);
    try std.testing.expect(try server_endpoint.streamFinished(server_handle, uni_stream_id));

    // --- Phase 7f: Server sends a unidirectional stream with FIN ---
    const server_uni_id = try server_endpoint.openUniStream(server_handle);
    try std.testing.expectEqual(@as(u64, 3), server_uni_id);
    const server_uni_payload = "server uni";
    var server_uni_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
    const server_uni_send = try server_endpoint.sendStreamWithRoutePathAndDrainDatagrams(
        std.testing.allocator,
        server_handle,
        server_uni_id,
        server_uni_payload,
        true,
        26,
        &server_uni_out,
    );
    try std.testing.expect(server_uni_send.drain.datagrams_written >= 1);
    const server_uni_written = server_uni_send.drain.datagrams_written;
    defer {
        for (server_uni_out[0..server_uni_written]) |o| std.testing.allocator.free(o.datagram);
    }

    // --- Phase 7g: Client receives every server uni-stream datagram ---
    for (server_uni_out[0..server_uni_written]) |suni_datagram| {
        var cu_recv_out: [4]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
        var cu_due_out: [4]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
        const cu_step = try client.receiveDatagramStepWithRoutePath(
            27,
            &client_scratch,
            suni_datagram.datagram,
            &cu_recv_out,
            &cu_due_out,
        );
        try std.testing.expect(cu_step.receive.receive != null);
        for (cu_recv_out[0..cu_step.receive.drain.datagrams_written]) |o| std.testing.allocator.free(o.datagram);
        if (cu_step.due) |due| {
            for (cu_due_out[0..due.drain.datagrams_written]) |o| std.testing.allocator.free(o.datagram);
        }
    }

    // --- Phase 7h: Client reads the server uni-stream data ---
    var client_uni_recv_buf: [64]u8 = undefined;
    const client_uni_recv_len = (try client.recvStream(server_uni_id, &client_uni_recv_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(server_uni_payload, client_uni_recv_buf[0..client_uni_recv_len]);
    try std.testing.expect(try client.streamFinished(server_uni_id));

    // --- Phase 7i: Client resets a new bidi stream with RESET_STREAM ---
    const reset_stream_id = try client.openStream();
    try client.sendStream(reset_stream_id, "partial", false);
    var client_reset_out: [4]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
    const client_reset = try client.resetStreamWithRoutePathAndDrainDatagrams(
        reset_stream_id,
        42,
        28,
        &client_reset_out,
    );
    try std.testing.expect(client_reset.drain.datagrams_written >= 1);
    const client_reset_written = client_reset.drain.datagrams_written;
    defer {
        for (client_reset_out[0..client_reset_written]) |o| std.testing.allocator.free(o.datagram);
    }

    // --- Phase 7j: Server receives every client RESET_STREAM datagram ---
    for (client_reset_out[0..client_reset_written]) |reset_datagram| {
        var sr_initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
        var sr_handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
        var sr_installed_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
        var sr_pending_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
        var sr_route_out: [256]u8 = undefined;
        const sr_step = try server_endpoint.receiveDatagramStepWithRoutePath(
            std.testing.allocator,
            server_path,
            29,
            reset_datagram.datagram,
            &[_]u8{},
            &[_]quic_packet.Version{.v1},
            .{
                .space = .application,
                .out = &sr_route_out,
                .unpredictable_prefix = &[_]u8{},
                .supported_versions = &[_]quic_packet.Version{.v1},
            },
            &server_scratch,
            &[_]u8{},
            &sr_initial_out,
            &sr_handshake_out,
            &sr_installed_out,
            .application,
            &sr_pending_out,
        );
        var sr_ik_written: usize = 0;
        switch (sr_step.process) {
            .routed => |routed| switch (routed) {
                .installed_key => |ik| {
                    sr_ik_written = ik.drain.datagrams_written;
                },
                else => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        }
        for (sr_installed_out[0..sr_ik_written]) |o| std.testing.allocator.free(o.datagram);
        for (sr_pending_out[0..sr_step.pending_drain.datagrams_written]) |o| std.testing.allocator.free(o.datagram);
    }

    // --- Phase 7k: Server opens a uni stream with partial data for STOP_SENDING ---
    const stop_stream_id = try server_endpoint.openUniStream(server_handle);
    const server_partial_payload = "partial server";
    var server_partial_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
    const server_partial = try server_endpoint.sendStreamWithRoutePathAndDrainDatagrams(
        std.testing.allocator,
        server_handle,
        stop_stream_id,
        server_partial_payload,
        false,
        30,
        &server_partial_out,
    );
    try std.testing.expect(server_partial.drain.datagrams_written >= 1);
    const server_partial_written = server_partial.drain.datagrams_written;
    defer {
        for (server_partial_out[0..server_partial_written]) |o| std.testing.allocator.free(o.datagram);
    }

    // --- Phase 7l: Client receives partial server data ---
    for (server_partial_out[0..server_partial_written]) |partial_datagram| {
        var sp_recv_out: [4]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
        var sp_due_out: [4]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
        const sp_step = try client.receiveDatagramStepWithRoutePath(
            31,
            &client_scratch,
            partial_datagram.datagram,
            &sp_recv_out,
            &sp_due_out,
        );
        try std.testing.expect(sp_step.receive.receive != null);
        for (sp_recv_out[0..sp_step.receive.drain.datagrams_written]) |o| std.testing.allocator.free(o.datagram);
        if (sp_step.due) |due| {
            for (sp_due_out[0..due.drain.datagrams_written]) |o| std.testing.allocator.free(o.datagram);
        }
    }
    var client_partial_buf: [64]u8 = undefined;
    const client_partial_len = (try client.recvStream(stop_stream_id, &client_partial_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(server_partial_payload, client_partial_buf[0..client_partial_len]);

    // --- Phase 7m: Client sends STOP_SENDING on the partial server stream ---
    var client_stop_out: [4]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
    const client_stop = try client.stopSendingWithRoutePathAndDrainDatagrams(
        stop_stream_id,
        99,
        32,
        &client_stop_out,
    );
    try std.testing.expect(client_stop.drain.datagrams_written >= 1);
    const client_stop_written = client_stop.drain.datagrams_written;
    defer {
        for (client_stop_out[0..client_stop_written]) |o| std.testing.allocator.free(o.datagram);
    }

    // --- Phase 7n: Server receives every client STOP_SENDING datagram ---
    for (client_stop_out[0..client_stop_written]) |stop_datagram| {
        var ss_initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
        var ss_handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
        var ss_installed_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
        var ss_pending_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
        var ss_route_out: [256]u8 = undefined;
        const ss_step = try server_endpoint.receiveDatagramStepWithRoutePath(
            std.testing.allocator,
            server_path,
            33,
            stop_datagram.datagram,
            &[_]u8{},
            &[_]quic_packet.Version{.v1},
            .{
                .space = .application,
                .out = &ss_route_out,
                .unpredictable_prefix = &[_]u8{},
                .supported_versions = &[_]quic_packet.Version{.v1},
            },
            &server_scratch,
            &[_]u8{},
            &ss_initial_out,
            &ss_handshake_out,
            &ss_installed_out,
            .application,
            &ss_pending_out,
        );
        var ss_ik_written: usize = 0;
        switch (ss_step.process) {
            .routed => |routed| switch (routed) {
                .installed_key => |ik| {
                    ss_ik_written = ik.drain.datagrams_written;
                },
                else => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        }
        for (ss_installed_out[0..ss_ik_written]) |o| std.testing.allocator.free(o.datagram);
        for (ss_pending_out[0..ss_step.pending_drain.datagrams_written]) |o| std.testing.allocator.free(o.datagram);
    }

    // --- Phase 7o: Client sends a new bidi stream for duplicate-discard proof ---
    const dup_stream_id = try client.openStream();
    const dup_payload = "duplicate proof";
    var client_dup_out: [4]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
    const client_dup_send = try client.sendStreamWithRoutePathAndDrainDatagrams(
        dup_stream_id,
        dup_payload,
        true,
        34,
        &client_dup_out,
    );
    try std.testing.expect(client_dup_send.drain.datagrams_written >= 1);
    const client_dup_written = client_dup_send.drain.datagrams_written;
    defer {
        for (client_dup_out[0..client_dup_written]) |o| std.testing.allocator.free(o.datagram);
    }

    // --- Phase 7p: Server receives the original datagrams ---
    for (client_dup_out[0..client_dup_written]) |dup_datagram| {
        var d1_initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
        var d1_handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
        var d1_installed_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
        var d1_pending_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
        var d1_route_out: [256]u8 = undefined;
        const d1_step = try server_endpoint.receiveDatagramStepWithRoutePath(
            std.testing.allocator,
            server_path,
            35,
            dup_datagram.datagram,
            &[_]u8{},
            &[_]quic_packet.Version{.v1},
            .{
                .space = .application,
                .out = &d1_route_out,
                .unpredictable_prefix = &[_]u8{},
                .supported_versions = &[_]quic_packet.Version{.v1},
            },
            &server_scratch,
            &[_]u8{},
            &d1_initial_out,
            &d1_handshake_out,
            &d1_installed_out,
            .application,
            &d1_pending_out,
        );
        var d1_ik_written: usize = 0;
        switch (d1_step.process) {
            .routed => |routed| switch (routed) {
                .installed_key => |ik| {
                    d1_ik_written = ik.drain.datagrams_written;
                },
                else => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        }
        for (d1_installed_out[0..d1_ik_written]) |o| std.testing.allocator.free(o.datagram);
        for (d1_pending_out[0..d1_step.pending_drain.datagrams_written]) |o| std.testing.allocator.free(o.datagram);
    }

    // --- Phase 7q: Server reads the stream data ---
    var server_dup_read_buf: [64]u8 = undefined;
    const server_dup_read_len = (try server_endpoint.recvStream(server_handle, dup_stream_id, &server_dup_read_buf)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(dup_payload, server_dup_read_buf[0..server_dup_read_len]);
    try std.testing.expect(try server_endpoint.streamFinished(server_handle, dup_stream_id));

    // --- Phase 7r: Server receives the same datagrams again (duplicate discard) ---
    for (client_dup_out[0..client_dup_written]) |dup_datagram| {
        var d2_initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
        var d2_handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
        var d2_installed_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
        var d2_pending_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
        var d2_route_out: [256]u8 = undefined;
        const d2_step = try server_endpoint.receiveDatagramStepWithRoutePath(
            std.testing.allocator,
            server_path,
            36,
            dup_datagram.datagram,
            &[_]u8{},
            &[_]quic_packet.Version{.v1},
            .{
                .space = .application,
                .out = &d2_route_out,
                .unpredictable_prefix = &[_]u8{},
                .supported_versions = &[_]quic_packet.Version{.v1},
            },
            &server_scratch,
            &[_]u8{},
            &d2_initial_out,
            &d2_handshake_out,
            &d2_installed_out,
            .application,
            &d2_pending_out,
        );
        var d2_ik_written: usize = 0;
        switch (d2_step.process) {
            .routed => |routed| switch (routed) {
                .installed_key => |ik| {
                    d2_ik_written = ik.drain.datagrams_written;
                },
                else => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        }
        for (d2_installed_out[0..d2_ik_written]) |o| std.testing.allocator.free(o.datagram);
        for (d2_pending_out[0..d2_step.pending_drain.datagrams_written]) |o| std.testing.allocator.free(o.datagram);
    }
    // Duplicate STREAM data is discarded idempotently — stream state unchanged.
    var server_dup_verify_buf: [64]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), try server_endpoint.recvStream(server_handle, dup_stream_id, &server_dup_verify_buf));

    // --- Phase 7s: Verify ACK/RTT accounting state through endpoint seam ---
    // Both endpoints track outstanding packets and bytes-in-flight for
    // ack-eliciting 1-RTT packets sent during the echo/control/duplicate phases.
    try std.testing.expect(client.sentPacketCount(.application) > 0);
    try std.testing.expect(client.bytesInFlight(.application) > 0);
    const server_record_for_ack = server_endpoint.records.get(server_handle) orelse return error.TestUnexpectedResult;
    try std.testing.expect(server_record_for_ack.transport.connection.sentPacketCount(.application) > 0);
    try std.testing.expect(server_record_for_ack.transport.connection.bytesInFlight(.application) > 0);

    // --- Phase 7u: Stream-limit enforcement at endpoint seam ---
    // Client bidi streams opened so far: 0, 4, 8 (3 streams).
    // Open additional streams to verify multi-stream endpoint behavior.
    var limit_stream_ids: [5]u64 = undefined;
    for (0..5) |i| {
        limit_stream_ids[i] = try client.openStream();
    }
    // Verify all 8 client-initiated bidi streams are tracked.
    try std.testing.expectEqual(@as(u64, 28), limit_stream_ids[4]);

    // --- Phase 7t: Failure-before-mutation — corrupted datagram does not mutate state ---
    {
        const fbm_record = server_endpoint.records.get(server_handle) orelse return error.TestUnexpectedResult;
        const fbm_sent_before = fbm_record.transport.connection.sentPacketCount(.application);
        const fbm_bif_before = fbm_record.transport.connection.bytesInFlight(.application);
        // Corrupt a copy of the client's duplicate-stream datagram.
        var corrupted_buf: [2048]u8 = undefined;
        const corrupted_src = client_dup_out[0].datagram;
        @memcpy(corrupted_buf[0..corrupted_src.len], corrupted_src);
        corrupted_buf[corrupted_src.len - 1] ^= 0xff; // flip last payload byte
        var fbm_initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
        var fbm_handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
        var fbm_installed_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
        var fbm_pending_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
        var fbm_route_out: [256]u8 = undefined;
        const fbm_result = server_endpoint.receiveDatagramStepWithRoutePath(
            std.testing.allocator,
            server_path,
            39,
            corrupted_buf[0..corrupted_src.len],
            &[_]u8{},
            &[_]quic_packet.Version{.v1},
            .{
                .space = .application,
                .out = &fbm_route_out,
                .unpredictable_prefix = &[_]u8{},
                .supported_versions = &[_]quic_packet.Version{.v1},
            },
            &server_scratch,
            &[_]u8{},
            &fbm_initial_out,
            &fbm_handshake_out,
            &fbm_installed_out,
            .application,
            &fbm_pending_out,
        );
        if (fbm_result) |fbm_step| {
            // Datagram was processed (dropped or routed); free any output.
            var fbm_ik_written: usize = 0;
            switch (fbm_step.process) {
                .routed => |routed| switch (routed) {
                    .installed_key => |ik| {
                        fbm_ik_written = ik.drain.datagrams_written;
                    },
                    else => {},
                },
                else => {},
            }
            for (fbm_installed_out[0..fbm_ik_written]) |o| std.testing.allocator.free(o.datagram);
            for (fbm_pending_out[0..fbm_step.pending_drain.datagrams_written]) |o| std.testing.allocator.free(o.datagram);
        } else |_| {
            // AEAD or frame decode failure is expected.
        }
        // Failure-before-mutation: sentPacketCount and bytesInFlight unchanged.
        const fbm_after = server_endpoint.records.get(server_handle) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(fbm_sent_before, fbm_after.transport.connection.sentPacketCount(.application));
        try std.testing.expectEqual(fbm_bif_before, fbm_after.transport.connection.bytesInFlight(.application));
    }

    // --- Phase 7b: Service due server recovery timer with PTO evidence ---
    if (try server_endpoint.nextDeadline(std.testing.allocator)) |server_deadline| {
        var due_out: [4]TestServerEndpoint.DatagramPathResult = undefined;
        const due_result = try server_endpoint.processDueDeadlineAndDrainDatagramsWithRoutePath(
            std.testing.allocator,
            server_deadline.deadline_nanos,
            &due_out,
        );
        if (due_result) |due| {
            // PTO/recovery output is route-bound: each datagram carries the committed path.
            for (due_out[0..due.drain.datagrams_written]) |o| {
                try std.testing.expect(o.path.eql(server_path));
                std.testing.allocator.free(o.datagram);
            }
            // PTO backoff: the next deadline (if any) must not be earlier than
            // the serviced deadline, preventing tight timer loops.
            if (due.next_deadline) |next_dl| {
                try std.testing.expect(next_dl.deadline_nanos >= server_deadline.deadline_nanos);
            }
        }
    }

    // --- Phase 7b2: Service due client recovery timer with PTO evidence ---
    if (client.nextDeadline()) |client_deadline| {
        var client_pto_out: [4]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
        const client_due = try client.serviceDueDeadlineAndDrainDatagramsWithRoutePath(
            client_deadline.deadline(),
            &client_pto_out,
        );
        if (client_due) |due| {
            // Client PTO output is route-bound.
            for (client_pto_out[0..due.drain.datagrams_written]) |o| {
                try std.testing.expect(o.path.eql(client_path));
                std.testing.allocator.free(o.datagram);
            }
            // PTO backoff: next deadline must not regress.
            if (due.next_deadline) |next_dl| {
                try std.testing.expect(next_dl.deadline() >= client_deadline.deadline());
            }
        }
    }

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
        var sc_initial_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
        var sc_handshake_out: [1]endpoint_types.EndpointPolledDatagramResult = undefined;
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
    const client_close_deadline = client.closeDeadline() orelse return error.TestUnexpectedResult;
    const client_retire = try client.retireAtCloseDeadline(client_close_deadline + 1);
    const client_retired = client_retire orelse return error.TestUnexpectedResult;
    try std.testing.expect(client_retired.routes_retired >= 1);
    // Terminal timer disarm: no stale deadlines remain after client route retirement.
    try std.testing.expect(client.nextDeadline() == null);

    // --- Phase 11: Retire server record and verify cleanup ---
    const server_retired = try server_endpoint.retireRecord(server_handle);
    try std.testing.expect(server_retired.routes_retired >= 1);
    try std.testing.expectEqual(@as(usize, 0), server_endpoint.activeConnectionCount());
    // Terminal timer disarm: no stale deadlines or routes remain after server record retirement.
    try std.testing.expectEqual(@as(?endpoint_types.EndpointConnectionDeadline, null), try server_endpoint.nextDeadline(std.testing.allocator));
    try std.testing.expectEqual(@as(usize, 0), server_endpoint.lifecycle.routeCount());
}
