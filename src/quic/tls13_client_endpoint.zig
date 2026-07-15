//! Endpoint-owned lifecycle for one pure-Zig TLS 1.3 QUIC client transport.
//!
//! The endpoint owns the client transport, route registration, and recovery
//! timer mirroring. Callers retain UDP socket I/O and application policy.

const std = @import("std");
const buffer = @import("buffer.zig");
const connection_config = @import("connection_config.zig");
const endpoint = @import("endpoint.zig");
const endpoint_lifecycle = @import("endpoint_lifecycle.zig");
const frame = @import("frame.zig");
const packet = @import("packet.zig");
const protection = @import("protection.zig");
const tls13 = @import("tls13.zig");
const client_transport = @import("tls13_client_transport.zig");
const transport_types = @import("transport_types.zig");

const Config = connection_config.Config;
const EndpointConnectionLifecycle = endpoint_lifecycle.EndpointConnectionLifecycle;
const Tls13ClientTransport = client_transport.Tls13ClientTransport;

/// Owns one client transport and the lifecycle state for its UDP route.
pub const Tls13ClientEndpoint = struct {
    lifecycle: EndpointConnectionLifecycle,
    transport: Tls13ClientTransport,
    connection_id: u64,
    path: endpoint.Udp4Tuple,

    /// Create a client endpoint and register its stable Initial source CID.
    pub fn init(
        allocator: std.mem.Allocator,
        connection_id: u64,
        path: endpoint.Udp4Tuple,
        route_options: endpoint.RouteOptions,
        connection_config_value: Config,
        tls_config: tls13.TlsConfig,
        original_destination_connection_id: [8]u8,
        local_source_connection_id: [8]u8,
    ) !Tls13ClientEndpoint {
        var transport = try Tls13ClientTransport.init(
            allocator,
            connection_config_value,
            tls_config,
            original_destination_connection_id,
            local_source_connection_id,
        );
        errdefer transport.deinit();

        var lifecycle = EndpointConnectionLifecycle.init(allocator);
        errdefer lifecycle.deinit();
        try lifecycle.registerConnectionId(
            connection_id,
            &local_source_connection_id,
            path,
            route_options,
        );
        return .{
            .lifecycle = lifecycle,
            .transport = transport,
            .connection_id = connection_id,
            .path = path,
        };
    }

    /// Release the owned transport and endpoint lifecycle state.
    pub fn deinit(self: *Tls13ClientEndpoint) void {
        self.transport.deinit();
        self.lifecycle.deinit();
    }

    /// Queue ClientHello and mirror the resulting recovery timer.
    pub fn begin(self: *Tls13ClientEndpoint, now_millis: i64, scratch: []u8) ![]u8 {
        const datagram = try self.transport.begin(now_millis, scratch);
        errdefer self.transport.connection.allocator.free(datagram);
        try self.lifecycle.armRecoveryTimerFromConnection(self.connection_id, &self.transport.connection);
        return datagram;
    }

    /// Queue ClientHello and return it with the committed UDP route.
    pub fn beginWithRoutePath(self: *Tls13ClientEndpoint, now_millis: i64, scratch: []u8) !ApplicationDatagramPathResult {
        const local_source_connection_id = self.transport.connection.localInitialSourceConnectionId() orelse return error.UnknownConnectionId;
        const path = try self.lifecycle.currentRoutePath(local_source_connection_id);
        return .{
            .datagram = try self.begin(now_millis, scratch),
            .path = path,
        };
    }

    /// Route and process one peer datagram through the owned transport.
    pub fn receive(
        self: *Tls13ClientEndpoint,
        now_millis: i64,
        scratch: []u8,
        datagram: []const u8,
    ) !ReceiveResult {
        const route = try self.lifecycle.routeDatagram(self.path, datagram);
        if (route.connection_id != self.connection_id) return error.InvalidPacket;
        if (datagram.len != 0 and packet.parseHeaderForm(datagram[0]) == .short) {
            if (self.transport.connection.processStatelessResetDatagram(now_millis, datagram)) |sequence_number| {
                try self.lifecycle.armRecoveryTimerFromConnection(self.connection_id, &self.transport.connection);
                return .{
                    .route = route,
                    .transport = .{},
                    .stateless_reset_sequence_number = sequence_number,
                };
            }
        }
        const progress = try self.transport.receive(now_millis, scratch, datagram);
        try self.lifecycle.armRecoveryTimerFromConnection(self.connection_id, &self.transport.connection);
        return .{ .route = route, .transport = progress };
    }

    /// Route/process one peer datagram and pair any immediate outbound output
    /// with the endpoint's committed UDP route.
    pub fn receiveWithRoutePath(
        self: *Tls13ClientEndpoint,
        now_millis: i64,
        scratch: []u8,
        datagram: []const u8,
    ) !ReceiveDatagramPathResult {
        const local_source_connection_id = self.transport.connection.localInitialSourceConnectionId() orelse return error.UnknownConnectionId;
        const path = try self.lifecycle.currentRoutePath(local_source_connection_id);
        const received = try self.receive(now_millis, scratch, datagram);
        return .{
            .receive = received,
            .outbound_initial = if (received.transport.outbound_initial) |bytes| .{
                .datagram = bytes,
                .path = path,
            } else null,
            .outbound_handshake = if (received.transport.outbound_handshake) |bytes| .{
                .datagram = bytes,
                .path = path,
            } else null,
        };
    }

    /// Move the client's registered UDP route after caller-selected migration.
    pub fn updatePath(self: *Tls13ClientEndpoint, new_path: endpoint.Udp4Tuple) endpoint.RouteError!endpoint.RouteResult {
        const local_source_connection_id = self.transport.connection.localInitialSourceConnectionId() orelse return error.UnknownConnectionId;
        const updated = try self.lifecycle.updateRoutePathAndResetSpinBit(
            local_source_connection_id,
            self.path,
            new_path,
            &self.transport.connection,
        );
        self.path = new_path;
        return updated;
    }

    /// Poll one protected application datagram and refresh recovery scheduling.
    pub fn pollApplicationDatagram(self: *Tls13ClientEndpoint, now_millis: i64) !?[]u8 {
        const datagram = try self.transport.pollApplicationDatagram(now_millis);
        errdefer if (datagram) |bytes| self.transport.connection.allocator.free(bytes);
        try self.lifecycle.armRecoveryTimerFromConnection(self.connection_id, &self.transport.connection);
        return datagram;
    }

    /// Poll one protected application datagram with its committed UDP route.
    pub fn pollApplicationDatagramWithRoutePath(self: *Tls13ClientEndpoint, now_millis: i64) !?ApplicationDatagramPathResult {
        const local_source_connection_id = self.transport.connection.localInitialSourceConnectionId() orelse return error.UnknownConnectionId;
        const path = try self.lifecycle.currentRoutePath(local_source_connection_id);
        const datagram = (try self.pollApplicationDatagram(now_millis)) orelse return null;
        return .{
            .datagram = datagram,
            .path = path,
        };
    }

    /// Select the next client transport lifecycle deadline.
    pub fn nextDeadline(self: *const Tls13ClientEndpoint) ?client_transport.ClientTransportDeadline {
        return self.transport.nextDeadline();
    }

    /// Service one due client deadline and keep endpoint lifecycle state in sync.
    pub fn serviceDueDeadline(
        self: *Tls13ClientEndpoint,
        now_millis: i64,
    ) !?client_transport.ClientTransportDeadline {
        const deadline = self.transport.nextDeadline() orelse return null;
        if (deadline.deadlineMillis() > now_millis) return null;

        switch (deadline) {
            .idle_timeout => {
                _ = try self.lifecycle.checkIdleTimeoutsAndRetireConnection(
                    self.connection_id,
                    &self.transport.connection,
                    now_millis,
                );
            },
            .close_timeout => {
                _ = try self.lifecycle.checkCloseTimeoutsAndRetireConnection(
                    self.connection_id,
                    &self.transport.connection,
                    now_millis,
                );
            },
            .recovery, .key_discard => {
                _ = try self.transport.serviceDueDeadline(now_millis);
                try self.lifecycle.armRecoveryTimerFromConnection(self.connection_id, &self.transport.connection);
            },
        }
        return deadline;
    }

    /// Service one due client deadline and return route-bound recovery output.
    pub fn serviceDueDeadlineAndPollApplicationDatagramWithRoutePath(
        self: *Tls13ClientEndpoint,
        now_millis: i64,
    ) !?DueDeadlineApplicationDatagramPathResult {
        const serviced = (try self.serviceDueDeadline(now_millis)) orelse return null;
        const datagram = switch (serviced) {
            .recovery => try self.pollApplicationDatagramWithRoutePath(now_millis),
            .idle_timeout, .close_timeout, .key_discard => null,
        };
        return .{
            .deadline = serviced,
            .datagram = datagram,
        };
    }

    /// Return whether TLS and QUIC have reached confirmed 1-RTT state.
    pub fn handshakeConfirmed(self: *const Tls13ClientEndpoint) bool {
        return self.transport.handshakeConfirmed();
    }

    /// Return the selected configuration for a fresh post-VN client attempt.
    pub fn versionNegotiationFollowupConfig(self: *const Tls13ClientEndpoint) !Config {
        return self.transport.versionNegotiationFollowupConfig();
    }

    /// Open a locally initiated bidirectional stream.
    pub fn openStream(self: *Tls13ClientEndpoint) !u64 {
        return self.transport.openStream();
    }

    /// Queue FIN-terminated or open stream bytes.
    pub fn sendStream(self: *Tls13ClientEndpoint, stream_id: u64, data: []const u8, fin: bool) !void {
        try self.transport.sendStream(stream_id, data, fin);
    }

    /// Read received bytes from one application stream.
    pub fn recvStream(self: *Tls13ClientEndpoint, stream_id: u64, out: []u8) !?usize {
        return self.transport.recvStream(stream_id, out);
    }

    /// Return whether one application stream has received FIN.
    pub fn streamFinished(self: *const Tls13ClientEndpoint, stream_id: u64) !bool {
        return self.transport.streamFinished(stream_id);
    }

    /// Queue a protected application CONNECTION_CLOSE and poll it for UDP send.
    pub fn close(
        self: *Tls13ClientEndpoint,
        application_error_code: u64,
        frame_type: u64,
        reason: []const u8,
        now_millis: i64,
    ) !?[]u8 {
        try self.transport.connection.closeConnection(application_error_code, frame_type, reason);
        return self.pollApplicationDatagram(now_millis);
    }

    /// Queue a protected application CONNECTION_CLOSE and return it with route.
    pub fn closeWithRoutePath(
        self: *Tls13ClientEndpoint,
        application_error_code: u64,
        frame_type: u64,
        reason: []const u8,
        now_millis: i64,
    ) !?ApplicationDatagramPathResult {
        try self.transport.connection.closeConnection(application_error_code, frame_type, reason);
        return self.pollApplicationDatagramWithRoutePath(now_millis);
    }

    /// Return the active close deadline after `close()` has queued a close.
    pub fn closeDeadlineMillis(self: *const Tls13ClientEndpoint) ?i64 {
        return self.transport.connection.closeDeadlineMillis();
    }

    /// Retire the registered route after the close deadline has elapsed.
    pub fn retireAtCloseDeadline(self: *Tls13ClientEndpoint, now_millis: i64) !?endpoint_lifecycle.EndpointConnectionRetireResult {
        return self.lifecycle.checkCloseTimeoutsAndRetireConnection(
            self.connection_id,
            &self.transport.connection,
            now_millis,
        );
    }

    /// Routed receive output from the owned client transport.
    pub const ReceiveResult = struct {
        route: endpoint.RouteResult,
        transport: Tls13ClientTransport.ReceiveResult,
        stateless_reset_sequence_number: ?u64 = null,
    };

    /// Client receive result with immediate outbound datagrams paired to route.
    pub const ReceiveDatagramPathResult = struct {
        receive: ReceiveResult,
        outbound_initial: ?ApplicationDatagramPathResult = null,
        outbound_handshake: ?ApplicationDatagramPathResult = null,
    };

    /// Client endpoint application datagram paired with the committed route.
    pub const ApplicationDatagramPathResult = struct {
        datagram: []u8,
        path: endpoint.Udp4Tuple,
    };

    /// Client due-deadline result with optional route-bound recovery output.
    pub const DueDeadlineApplicationDatagramPathResult = struct {
        deadline: client_transport.ClientTransportDeadline,
        datagram: ?ApplicationDatagramPathResult = null,
    };
};

test "Tls13ClientEndpoint registers its client route before begin" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };
    const alpn = [_][]const u8{"hq-interop"};
    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4444),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
    };
    var client = try Tls13ClientEndpoint.init(
        std.testing.allocator,
        7,
        path,
        .{ .active_migration_disabled = false },
        .{},
        .{ .alpn = &alpn, .server_name = "localhost", .skip_cert_verify = true },
        original_dcid,
        client_scid,
    );
    defer client.deinit();

    try std.testing.expectEqual(@as(usize, 1), client.lifecycle.routeCount());
    var scratch: [4096]u8 = undefined;
    const initial = try client.begin(1, &scratch);
    defer std.testing.allocator.free(initial);
    try std.testing.expect(client.lifecycle.nextDeadline(client.connection_id, &client.transport.connection) != null);

    const new_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 5444),
        .remote = path.remote,
    };
    const updated = try client.updatePath(new_path);
    try std.testing.expect(!updated.path_changed);
    try std.testing.expect(client.path.eql(new_path));
    try std.testing.expect((try client.lifecycle.currentRoutePath(&client_scid)).eql(new_path));
}

test "Tls13ClientEndpoint begins with committed route path" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30 };
    const alpn = [_][]const u8{"hq-interop"};
    const old_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4444),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
    };
    const new_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 5444),
        .remote = old_path.remote,
    };
    var client = try Tls13ClientEndpoint.init(
        std.testing.allocator,
        15,
        old_path,
        .{ .active_migration_disabled = false },
        .{},
        .{ .alpn = &alpn, .server_name = "localhost", .skip_cert_verify = true },
        original_dcid,
        client_scid,
    );
    defer client.deinit();

    _ = try client.updatePath(new_path);
    var scratch: [8192]u8 = undefined;
    const initial = try client.beginWithRoutePath(1, &scratch);
    defer std.testing.allocator.free(initial.datagram);
    try std.testing.expect(initial.path.eql(new_path));
    try std.testing.expect(initial.datagram.len >= 1200);
    try std.testing.expect(client.lifecycle.nextDeadline(client.connection_id, &client.transport.connection) != null);
}

test "Tls13ClientEndpoint polls application output with committed route path" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
    const alpn = [_][]const u8{"hq-interop"};
    const old_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4444),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
    };
    const new_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 5444),
        .remote = old_path.remote,
    };
    var client = try Tls13ClientEndpoint.init(
        std.testing.allocator,
        8,
        old_path,
        .{ .active_migration_disabled = false },
        .{},
        .{ .alpn = &alpn, .server_name = "localhost", .skip_cert_verify = true },
        original_dcid,
        client_scid,
    );
    defer client.deinit();

    const traffic_secret = [_]u8{0x44} ** 32;
    try client.transport.connection.confirmHandshake();
    try client.transport.connection.installOneRttTrafficSecrets(.{
        .local = traffic_secret,
        .peer = traffic_secret,
    });
    const peer_connection_id = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const reset_token = [_]u8{0x55} ** 16;
    var encoded: [64]u8 = undefined;
    var writer = buffer.fixedWriter(&encoded);
    try frame.encodeFrame(writer.writer(), .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = &peer_connection_id,
        .stateless_reset_token = reset_token,
    } });
    try client.transport.connection.processDatagram(0, writer.getWritten());
    try client.transport.connection.sendPing();
    _ = try client.updatePath(new_path);

    const polled = (try client.pollApplicationDatagramWithRoutePath(1)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(polled.datagram);
    try std.testing.expect(polled.path.eql(new_path));
    try std.testing.expect(polled.datagram.len != 0);
    try std.testing.expect(client.lifecycle.nextDeadline(client.connection_id, &client.transport.connection) != null);
}

test "Tls13ClientEndpoint services due recovery with committed route output" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    const alpn = [_][]const u8{"hq-interop"};
    const old_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4444),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
    };
    const new_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 5444),
        .remote = old_path.remote,
    };
    var client = try Tls13ClientEndpoint.init(
        std.testing.allocator,
        9,
        old_path,
        .{ .active_migration_disabled = false },
        .{ .initial_rtt_ms = 100 },
        .{ .alpn = &alpn, .server_name = "localhost", .skip_cert_verify = true },
        original_dcid,
        client_scid,
    );
    defer client.deinit();

    const traffic_secret = [_]u8{0x55} ** 32;
    try client.transport.connection.confirmHandshake();
    try client.transport.connection.installOneRttTrafficSecrets(.{
        .local = traffic_secret,
        .peer = traffic_secret,
    });
    const peer_connection_id = [_]u8{ 0xba, 0xbb, 0xbc, 0xbd };
    const reset_token = [_]u8{0x66} ** 16;
    var encoded: [64]u8 = undefined;
    var writer = buffer.fixedWriter(&encoded);
    try frame.encodeFrame(writer.writer(), .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = &peer_connection_id,
        .stateless_reset_token = reset_token,
    } });
    try client.transport.connection.processDatagram(0, writer.getWritten());
    try client.transport.connection.sendPing();

    const first = (try client.pollApplicationDatagramWithRoutePath(10)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(first.datagram);
    const deadline = client.nextDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expect(deadline == .recovery);

    _ = try client.updatePath(new_path);
    const before_deadline = try client.serviceDueDeadlineAndPollApplicationDatagramWithRoutePath(deadline.deadlineMillis() - 1);
    try std.testing.expect(before_deadline == null);

    const serviced = (try client.serviceDueDeadlineAndPollApplicationDatagramWithRoutePath(deadline.deadlineMillis())) orelse return error.TestUnexpectedResult;
    try std.testing.expect(serviced.deadline == .recovery);
    const output = serviced.datagram orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(output.datagram);
    try std.testing.expect(output.path.eql(new_path));
    try std.testing.expect(output.datagram.len != 0);
}

test "Tls13ClientEndpoint receive returns Retry output with committed route path" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70 };
    const retry_scid = [_]u8{ 0xca, 0xcb, 0xcc, 0xcd };
    const alpn = [_][]const u8{"hq-interop"};
    const old_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4444),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
    };
    const new_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 5444),
        .remote = old_path.remote,
    };
    var client = try Tls13ClientEndpoint.init(
        std.testing.allocator,
        14,
        old_path,
        .{ .active_migration_disabled = false },
        .{},
        .{ .alpn = &alpn, .server_name = "localhost", .skip_cert_verify = true },
        original_dcid,
        client_scid,
    );
    defer client.deinit();

    var scratch: [8192]u8 = undefined;
    const initial = try client.begin(1, &scratch);
    defer std.testing.allocator.free(initial);
    _ = try client.updatePath(new_path);

    const retry = packet.RetryPacket{
        .version = .v1,
        .dcid = &client_scid,
        .scid = &retry_scid,
        .token = "retry-token-for-client-address",
        .integrity_tag = [_]u8{0} ** protection.aead_tag_len,
    };
    const retry_datagram = try protection.encodeRetryPacketWithIntegrity(
        std.testing.allocator,
        &original_dcid,
        retry,
    );
    defer std.testing.allocator.free(retry_datagram);

    const received = try client.receiveWithRoutePath(2, &scratch, retry_datagram);
    try std.testing.expect(received.receive.transport.retry_received);
    try std.testing.expect(received.receive.transport.outbound_initial != null);
    try std.testing.expect(received.outbound_handshake == null);
    const outbound_initial = received.outbound_initial orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(outbound_initial.datagram);
    try std.testing.expect(outbound_initial.path.eql(new_path));
    try std.testing.expect(outbound_initial.datagram.len >= 1200);
}

test "Tls13ClientEndpoint receive enters draining on active stateless reset" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60 };
    const alpn = [_][]const u8{"hq-interop"};
    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4444),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
    };
    var client = try Tls13ClientEndpoint.init(
        std.testing.allocator,
        13,
        path,
        .{ .active_migration_disabled = false },
        .{},
        .{ .alpn = &alpn, .server_name = "localhost", .skip_cert_verify = true },
        original_dcid,
        client_scid,
    );
    defer client.deinit();

    const peer_connection_id = [_]u8{ 0xea, 0xeb, 0xec, 0xed };
    const reset_token = [_]u8{0xbb} ** packet.stateless_reset_token_len;
    var encoded: [64]u8 = undefined;
    var writer = buffer.fixedWriter(&encoded);
    try frame.encodeFrame(writer.writer(), .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .connection_id = &peer_connection_id,
        .stateless_reset_token = reset_token,
    } });
    try client.transport.connection.processDatagram(0, writer.getWritten());
    try client.transport.connection.confirmHandshake();
    _ = try client.transport.connection.recordPacketSentInSpace(.application, 1, 64);
    try client.lifecycle.armRecoveryTimerFromConnection(client.connection_id, &client.transport.connection);
    try std.testing.expectEqual(@as(usize, 1), client.lifecycle.recoveryTimerCount());

    var reset_prefix: [1 + client_scid.len]u8 = undefined;
    reset_prefix[0] = 0x40;
    @memcpy(reset_prefix[1..], &client_scid);
    var reset_datagram: [64]u8 = undefined;
    var reset_writer = buffer.fixedWriter(&reset_datagram);
    try packet.encodeStatelessReset(reset_writer.writer(), &reset_prefix, reset_token);

    var scratch: [128]u8 = undefined;
    const received = try client.receive(10, &scratch, reset_writer.getWritten());
    try std.testing.expectEqual(@as(?u64, 0), received.stateless_reset_sequence_number);
    try std.testing.expect(!received.transport.application_processed);
    try std.testing.expectEqual(transport_types.ConnectionState.draining, client.transport.connection.connectionState());
    try std.testing.expectEqual(@as(usize, 1), client.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), client.lifecycle.recoveryTimerCount());

    const deadline = client.nextDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expect(deadline == .close_timeout);
    _ = try client.serviceDueDeadline(deadline.deadlineMillis());
    try std.testing.expectEqual(@as(usize, 0), client.lifecycle.routeCount());
}

test "Tls13ClientEndpoint retires its route when idle deadline closes the client" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    const alpn = [_][]const u8{"hq-interop"};
    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4444),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
    };
    var client = try Tls13ClientEndpoint.init(
        std.testing.allocator,
        11,
        path,
        .{ .active_migration_disabled = false },
        .{ .max_idle_timeout_ms = 10 },
        .{ .alpn = &alpn, .server_name = "localhost", .skip_cert_verify = true },
        original_dcid,
        client_scid,
    );
    defer client.deinit();
    client.transport.connection.last_packet_activity_millis = 10;

    const deadline = client.nextDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expect(deadline == .idle_timeout);
    try std.testing.expectEqual(@as(i64, 20), deadline.deadlineMillis());
    try std.testing.expectEqual(@as(usize, 1), client.lifecycle.routeCount());

    try std.testing.expect((try client.serviceDueDeadline(19)) == null);
    try std.testing.expectEqual(@as(usize, 1), client.lifecycle.routeCount());

    const serviced = (try client.serviceDueDeadline(20)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(serviced == .idle_timeout);
    try std.testing.expectEqual(@as(usize, 0), client.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), client.lifecycle.recoveryTimerCount());
}

test "Tls13ClientEndpoint closes with committed route output" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };
    const alpn = [_][]const u8{"hq-interop"};
    const old_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4444),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
    };
    const new_path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 5444),
        .remote = old_path.remote,
    };
    var client = try Tls13ClientEndpoint.init(
        std.testing.allocator,
        10,
        old_path,
        .{ .active_migration_disabled = false },
        .{},
        .{ .alpn = &alpn, .server_name = "localhost", .skip_cert_verify = true },
        original_dcid,
        client_scid,
    );
    defer client.deinit();

    const traffic_secret = [_]u8{0x77} ** 32;
    try client.transport.connection.confirmHandshake();
    try client.transport.connection.installOneRttTrafficSecrets(.{
        .local = traffic_secret,
        .peer = traffic_secret,
    });
    const peer_connection_id = [_]u8{ 0xca, 0xcb, 0xcc, 0xcd };
    const reset_token = [_]u8{0x88} ** 16;
    var encoded: [64]u8 = undefined;
    var writer = buffer.fixedWriter(&encoded);
    try frame.encodeFrame(writer.writer(), .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = &peer_connection_id,
        .stateless_reset_token = reset_token,
    } });
    try client.transport.connection.processDatagram(0, writer.getWritten());
    _ = try client.updatePath(new_path);

    const close_datagram = (try client.closeWithRoutePath(0, 0, "done", 1)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(close_datagram.datagram);
    try std.testing.expect(close_datagram.path.eql(new_path));
    try std.testing.expect(close_datagram.datagram.len != 0);
    try std.testing.expect(client.closeDeadlineMillis() != null);
}

test "Tls13ClientEndpoint retires its route when close deadline elapses" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78 };
    const alpn = [_][]const u8{"hq-interop"};
    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4444),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
    };
    var client = try Tls13ClientEndpoint.init(
        std.testing.allocator,
        12,
        path,
        .{ .active_migration_disabled = false },
        .{},
        .{ .alpn = &alpn, .server_name = "localhost", .skip_cert_verify = true },
        original_dcid,
        client_scid,
    );
    defer client.deinit();

    const traffic_secret = [_]u8{0x99} ** 32;
    try client.transport.connection.confirmHandshake();
    try client.transport.connection.installOneRttTrafficSecrets(.{
        .local = traffic_secret,
        .peer = traffic_secret,
    });
    const peer_connection_id = [_]u8{ 0xda, 0xdb, 0xdc, 0xdd };
    const reset_token = [_]u8{0xaa} ** 16;
    var encoded: [64]u8 = undefined;
    var writer = buffer.fixedWriter(&encoded);
    try frame.encodeFrame(writer.writer(), .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = &peer_connection_id,
        .stateless_reset_token = reset_token,
    } });
    try client.transport.connection.processDatagram(0, writer.getWritten());

    const close_datagram = (try client.closeWithRoutePath(0, 0, "done", 1)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(close_datagram.datagram);
    const close_deadline = client.closeDeadlineMillis() orelse return error.TestUnexpectedResult;
    const deadline = client.nextDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expect(deadline == .close_timeout);
    try std.testing.expectEqual(close_deadline, deadline.deadlineMillis());
    try std.testing.expectEqual(@as(usize, 1), client.lifecycle.routeCount());

    try std.testing.expect((try client.serviceDueDeadline(close_deadline - 1)) == null);
    try std.testing.expectEqual(@as(usize, 1), client.lifecycle.routeCount());

    const serviced = (try client.serviceDueDeadline(close_deadline)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(serviced == .close_timeout);
    try std.testing.expectEqual(@as(usize, 0), client.lifecycle.routeCount());
    try std.testing.expectEqual(@as(usize, 0), client.lifecycle.recoveryTimerCount());
}
