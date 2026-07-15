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

    /// Route/process one peer datagram and surface close-on-frame-error output.
    ///
    /// This keeps the existing throwing receive path unchanged for callers that
    /// only need success output, while giving socket loops one bounded step that
    /// can send a protected CONNECTION_CLOSE after an authenticated 1-RTT frame
    /// error.
    pub fn receiveWithRoutePathOrClose(
        self: *Tls13ClientEndpoint,
        now_millis: i64,
        scratch: []u8,
        datagram: []const u8,
    ) !ReceiveOrCloseDatagramPathResult {
        const received = self.receive(now_millis, scratch, datagram) catch |err| {
            if (err != error.InvalidPacket) return err;
            return .{
                .receive_error = error.InvalidPacket,
                .outbound_application = if (self.transport.connection.connectionState() == .closing)
                    try self.pollApplicationDatagramWithRoutePath(now_millis)
                else
                    null,
            };
        };
        const local_source_connection_id = self.transport.connection.localInitialSourceConnectionId() orelse return error.UnknownConnectionId;
        const path = try self.lifecycle.currentRoutePath(local_source_connection_id);
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
            .outbound_application = if (received.transport.application_processed)
                try self.pollApplicationDatagramWithRoutePath(now_millis)
            else
                null,
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
    ///
    /// Recovery output may be an Initial, Handshake, or 1-RTT Application
    /// datagram, depending on the due packet number space.
    pub fn serviceDueDeadlineAndPollDatagramWithRoutePath(
        self: *Tls13ClientEndpoint,
        now_millis: i64,
    ) !?DueDeadlineDatagramPathResult {
        const serviced = (try self.serviceDueDeadline(now_millis)) orelse return null;
        const datagram = switch (serviced) {
            .recovery => |recovery| try self.pollRecoveryDatagramWithRoutePath(recovery, now_millis),
            .idle_timeout, .close_timeout, .key_discard => null,
        };
        return .{
            .deadline = serviced,
            .datagram = datagram,
        };
    }

    fn pollRecoveryDatagramWithRoutePath(
        self: *Tls13ClientEndpoint,
        recovery: transport_types.LossDetectionTimerDeadline,
        now_millis: i64,
    ) !?ApplicationDatagramPathResult {
        const local_source_connection_id = self.transport.connection.localInitialSourceConnectionId() orelse return error.UnknownConnectionId;
        const path = try self.lifecycle.currentRoutePath(local_source_connection_id);
        const datagram = (try self.transport.pollRecoveryDatagram(recovery, now_millis)) orelse return null;
        errdefer self.transport.connection.allocator.free(datagram);
        try self.lifecycle.armRecoveryTimerFromConnection(self.connection_id, &self.transport.connection);
        return .{
            .datagram = datagram,
            .path = path,
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

    /// Process Version Negotiation and install the follow-up Initial route.
    ///
    /// A valid Version Negotiation packet supersedes this client attempt. The
    /// owned lifecycle retires the old route and recovery timer, then registers
    /// the caller-provided follow-up Initial Source CID for the next attempt.
    /// The current transport remains the validated old attempt; callers create
    /// the follow-up transport from `version_negotiation.followup_config`.
    pub fn processVersionNegotiationFollowupRoute(
        self: *Tls13ClientEndpoint,
        now_millis: i64,
        datagram: []const u8,
        followup_connection_id: u64,
        followup_local_initial_source_connection_id: []const u8,
        route_options: endpoint.ClientInitialRouteOptions,
    ) !?endpoint_lifecycle.EndpointVersionNegotiationFollowupResult {
        return self.lifecycle.processVersionNegotiationFollowupDatagram(
            self.connection_id,
            followup_connection_id,
            &self.transport.connection,
            now_millis,
            &self.transport.original_destination_connection_id,
            &self.transport.local_source_connection_id,
            followup_local_initial_source_connection_id,
            self.path,
            datagram,
            route_options,
        );
    }

    /// Process Version Negotiation, replace the owned transport, and emit the
    /// first follow-up Initial with its committed UDP route.
    ///
    /// This is the endpoint-owned restart path after an incompatible but valid
    /// Version Negotiation packet. The old attempt validates the VN packet; the
    /// lifecycle retires its route/timer and registers the follow-up Initial
    /// Source CID; then this endpoint installs a fresh client transport for the
    /// selected version and queues its first ClientHello Initial.
    pub fn processVersionNegotiationRestartWithRoutePath(
        self: *Tls13ClientEndpoint,
        now_millis: i64,
        scratch: []u8,
        datagram: []const u8,
        followup_connection_id: u64,
        followup_local_initial_source_connection_id: [8]u8,
        route_options: endpoint.ClientInitialRouteOptions,
        tls_config: tls13.TlsConfig,
    ) !?VersionNegotiationRestartResult {
        const followup = (try self.processVersionNegotiationFollowupRoute(
            now_millis,
            datagram,
            followup_connection_id,
            &followup_local_initial_source_connection_id,
            route_options,
        )) orelse return null;
        errdefer _ = self.lifecycle.retireConnection(followup_connection_id);

        var followup_transport = try Tls13ClientTransport.init(
            self.transport.allocator,
            followup.version_negotiation.followup_config,
            tls_config,
            self.transport.original_destination_connection_id,
            followup_local_initial_source_connection_id,
        );
        errdefer followup_transport.deinit();

        const path = try self.lifecycle.currentRoutePath(&followup_local_initial_source_connection_id);
        const initial_datagram = try followup_transport.begin(now_millis, scratch);
        errdefer followup_transport.connection.allocator.free(initial_datagram);
        try self.lifecycle.armRecoveryTimerFromConnection(followup_connection_id, &followup_transport.connection);

        self.transport.deinit();
        self.transport = followup_transport;
        self.connection_id = followup_connection_id;
        self.path = path;
        return .{
            .followup = followup,
            .initial = .{
                .datagram = initial_datagram,
                .path = path,
            },
        };
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

    /// Client receive result that can carry close-on-frame-error output.
    pub const ReceiveOrCloseDatagramPathResult = struct {
        receive: ?ReceiveResult = null,
        receive_error: ?transport_types.Error = null,
        outbound_initial: ?ApplicationDatagramPathResult = null,
        outbound_handshake: ?ApplicationDatagramPathResult = null,
        outbound_application: ?ApplicationDatagramPathResult = null,
    };

    /// Client endpoint application datagram paired with the committed route.
    pub const ApplicationDatagramPathResult = struct {
        datagram: []u8,
        path: endpoint.Udp4Tuple,
    };

    /// Client Version Negotiation restart result.
    pub const VersionNegotiationRestartResult = struct {
        followup: endpoint_lifecycle.EndpointVersionNegotiationFollowupResult,
        initial: ApplicationDatagramPathResult,
    };

    /// Client due-deadline result with optional route-bound recovery output.
    pub const DueDeadlineDatagramPathResult = struct {
        deadline: client_transport.ClientTransportDeadline,
        /// Protected datagram for the due recovery packet number space.
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

test "Tls13ClientEndpoint receive returns route-bound close on frame error" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40 };
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
        16,
        old_path,
        .{ .active_migration_disabled = false },
        .{},
        .{ .alpn = &alpn, .server_name = "localhost", .skip_cert_verify = true },
        original_dcid,
        client_scid,
    );
    defer client.deinit();

    const client_secret = [_]u8{0x31} ** protection.traffic_secret_len;
    const server_secret = [_]u8{0x32} ** protection.traffic_secret_len;
    try client.transport.connection.confirmHandshake();
    try client.transport.connection.installOneRttTrafficSecrets(.{
        .local = client_secret,
        .peer = server_secret,
    });
    const peer_connection_id = [_]u8{ 0xac, 0xad, 0xae, 0xaf };
    const reset_token = [_]u8{0x75} ** 16;
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

    const invalid_plaintext = [_]u8{0x1f} ++ ([_]u8{0} ** 31);
    const invalid_packet_number = client.transport.connection.nextPeerPacketNumber(.application);
    const invalid_datagram = try protection.protectShortPacketAes128(std.testing.allocator, .{
        .dcid = &client_scid,
        .spin_bit = false,
        .key_phase = false,
        .packet_number = invalid_packet_number,
    }, try packet.encodePacketNumberForHeader(invalid_packet_number, null), protection.deriveAes128PacketProtectionKeys(server_secret), &invalid_plaintext);
    defer std.testing.allocator.free(invalid_datagram);

    var scratch: [128]u8 = undefined;
    const received = try client.receiveWithRoutePathOrClose(10, &scratch, invalid_datagram);
    try std.testing.expect(received.receive == null);
    try std.testing.expectEqual(@as(?transport_types.Error, error.InvalidPacket), received.receive_error);
    try std.testing.expectEqual(transport_types.ConnectionState.closing, client.transport.connection.connectionState());
    const close_datagram = received.outbound_application orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(close_datagram.datagram);
    try std.testing.expect(close_datagram.path.eql(new_path));
    try std.testing.expect(close_datagram.datagram.len != 0);
}

test "Tls13ClientEndpoint receive does not drain queued application output on route mismatch" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41 };
    const decoy_dcid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    const alpn = [_][]const u8{"hq-interop"};
    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4444),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
    };
    var client = try Tls13ClientEndpoint.init(
        std.testing.allocator,
        17,
        path,
        .{ .active_migration_disabled = false },
        .{},
        .{ .alpn = &alpn, .server_name = "localhost", .skip_cert_verify = true },
        original_dcid,
        client_scid,
    );
    defer client.deinit();
    try client.lifecycle.registerConnectionId(99, &decoy_dcid, path, .{ .active_migration_disabled = false });

    const traffic_secret = [_]u8{0x45} ** protection.traffic_secret_len;
    try client.transport.connection.confirmHandshake();
    try client.transport.connection.installOneRttTrafficSecrets(.{
        .local = traffic_secret,
        .peer = traffic_secret,
    });
    const peer_connection_id = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const reset_token = [_]u8{0x56} ** 16;
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

    const decoy_datagram = [_]u8{ 0x40, 0xd1, 0xd2, 0xd3, 0xd4, 0x00 };
    var scratch: [128]u8 = undefined;
    const received = try client.receiveWithRoutePathOrClose(10, &scratch, &decoy_datagram);
    try std.testing.expect(received.receive == null);
    try std.testing.expectEqual(@as(?transport_types.Error, error.InvalidPacket), received.receive_error);
    try std.testing.expectEqual(transport_types.ConnectionState.active, client.transport.connection.connectionState());
    try std.testing.expect(received.outbound_application == null);

    const queued = (try client.pollApplicationDatagramWithRoutePath(11)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(queued.datagram);
    try std.testing.expect(queued.path.eql(path));
    try std.testing.expect(queued.datagram.len != 0);
}

test "Tls13ClientEndpoint services Initial recovery with committed route output" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51 };
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
        19,
        old_path,
        .{ .active_migration_disabled = false },
        .{ .initial_rtt_ms = 100 },
        .{ .alpn = &alpn, .server_name = "localhost", .skip_cert_verify = true },
        original_dcid,
        client_scid,
    );
    defer client.deinit();

    var scratch: [8192]u8 = undefined;
    const initial = try client.beginWithRoutePath(1, &scratch);
    defer std.testing.allocator.free(initial.datagram);
    try std.testing.expect(initial.path.eql(old_path));

    const deadline = client.nextDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expect(deadline == .recovery);
    try std.testing.expectEqual(transport_types.PacketNumberSpace.initial, deadline.recovery.space);
    _ = try client.updatePath(new_path);

    const before_deadline = try client.serviceDueDeadlineAndPollDatagramWithRoutePath(deadline.deadlineMillis() - 1);
    try std.testing.expect(before_deadline == null);

    const serviced = (try client.serviceDueDeadlineAndPollDatagramWithRoutePath(deadline.deadlineMillis())) orelse return error.TestUnexpectedResult;
    try std.testing.expect(serviced.deadline == .recovery);
    try std.testing.expectEqual(transport_types.PacketNumberSpace.initial, serviced.deadline.recovery.space);
    const output = serviced.datagram orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(output.datagram);
    try std.testing.expect(output.path.eql(new_path));
    try std.testing.expect(output.datagram.len >= 1200);
    try std.testing.expectEqual(packet.HeaderForm.long, packet.parseHeaderForm(output.datagram[0]));
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
    const before_deadline = try client.serviceDueDeadlineAndPollDatagramWithRoutePath(deadline.deadlineMillis() - 1);
    try std.testing.expect(before_deadline == null);

    const serviced = (try client.serviceDueDeadlineAndPollDatagramWithRoutePath(deadline.deadlineMillis())) orelse return error.TestUnexpectedResult;
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

test "Tls13ClientEndpoint installs Version Negotiation follow-up route" {
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80 };
    const followup_scid = [_]u8{ 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88 };
    const alpn = [_][]const u8{"hq-interop"};
    const available_versions = [_]packet.Version{ .v2, .v1 };
    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4444),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
    };
    var client = try Tls13ClientEndpoint.init(
        std.testing.allocator,
        17,
        path,
        .{ .active_migration_disabled = false },
        .{ .chosen_version = .v2, .available_versions = &available_versions },
        .{ .alpn = &alpn, .server_name = "localhost", .skip_cert_verify = true },
        original_dcid,
        client_scid,
    );
    defer client.deinit();

    var scratch: [8192]u8 = undefined;
    const initial = try client.begin(1, &scratch);
    defer std.testing.allocator.free(initial);
    try std.testing.expect(client.lifecycle.nextDeadline(client.connection_id, &client.transport.connection) != null);

    const server_versions = [_]packet.Version{.v1};
    var vn_buf: [64]u8 = undefined;
    var vn_writer = buffer.fixedWriter(&vn_buf);
    try packet.encodeVersionNegotiationPacket(vn_writer.writer(), .{
        .dcid = &client_scid,
        .scid = &original_dcid,
        .versions = &server_versions,
    });
    const followup = (try client.processVersionNegotiationFollowupRoute(
        2,
        vn_writer.getWritten(),
        18,
        &followup_scid,
        .{ .active_migration_disabled = false },
    )) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqual(packet.Version.v1, followup.version_negotiation.selected_version);
    try std.testing.expectEqual(packet.Version.v1, followup.version_negotiation.followup_config.chosen_version);
    try std.testing.expectEqual(@as(?packet.Version, .v1), followup.version_negotiation.followup_config.version_negotiation_selected_version);
    try std.testing.expectEqual(@as(usize, 1), followup.version_negotiation.retired.routes_retired);
    try std.testing.expect(followup.version_negotiation.retired.recovery_timer_disarmed);
    try std.testing.expectEqual(@as(u64, 18), followup.followup_route.connection_id);
    try std.testing.expectEqualSlices(u8, &followup_scid, followup.followup_route.destination_connection_id.asSlice());
    try std.testing.expectEqual(@as(usize, 1), client.lifecycle.routeCount());
    try std.testing.expectError(error.UnknownConnectionId, client.lifecycle.currentRoutePath(&client_scid));
    try std.testing.expect((try client.lifecycle.currentRoutePath(&followup_scid)).eql(path));
    try std.testing.expect(client.lifecycle.nextDeadline(client.connection_id, &client.transport.connection) == null);
}

test "Tls13ClientEndpoint restarts transport after Version Negotiation" {
    const original_dcid = [_]u8{ 0x93, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90 };
    const followup_scid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const alpn = [_][]const u8{"hq-interop"};
    const available_versions = [_]packet.Version{ .v2, .v1 };
    const tls_config = tls13.TlsConfig{ .alpn = &alpn, .server_name = "localhost", .skip_cert_verify = true };
    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4444),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
    };
    var client = try Tls13ClientEndpoint.init(
        std.testing.allocator,
        21,
        path,
        .{ .active_migration_disabled = false },
        .{ .chosen_version = .v2, .available_versions = &available_versions },
        tls_config,
        original_dcid,
        client_scid,
    );
    defer client.deinit();

    var scratch: [8192]u8 = undefined;
    const initial = try client.begin(1, &scratch);
    defer std.testing.allocator.free(initial);
    try std.testing.expect(client.lifecycle.nextDeadline(client.connection_id, &client.transport.connection) != null);

    const server_versions = [_]packet.Version{.v1};
    var vn_buf: [64]u8 = undefined;
    var vn_writer = buffer.fixedWriter(&vn_buf);
    try packet.encodeVersionNegotiationPacket(vn_writer.writer(), .{
        .dcid = &client_scid,
        .scid = &original_dcid,
        .versions = &server_versions,
    });
    const restarted = (try client.processVersionNegotiationRestartWithRoutePath(
        2,
        &scratch,
        vn_writer.getWritten(),
        22,
        followup_scid,
        .{ .active_migration_disabled = false },
        tls_config,
    )) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(restarted.initial.datagram);

    try std.testing.expectEqual(packet.Version.v1, restarted.followup.version_negotiation.selected_version);
    try std.testing.expectEqual(@as(u64, 22), client.connection_id);
    try std.testing.expectEqual(packet.Version.v1, client.transport.version);
    try std.testing.expectEqualSlices(u8, &followup_scid, &client.transport.local_source_connection_id);
    try std.testing.expect(restarted.initial.path.eql(path));
    try std.testing.expect(restarted.initial.datagram.len >= 1200);
    try std.testing.expectEqual(@as(usize, 1), client.lifecycle.routeCount());
    try std.testing.expectError(error.UnknownConnectionId, client.lifecycle.currentRoutePath(&client_scid));
    try std.testing.expect((try client.lifecycle.currentRoutePath(&followup_scid)).eql(path));
    try std.testing.expect(client.lifecycle.nextDeadline(21, &client.transport.connection) == null);
    try std.testing.expect(client.lifecycle.nextDeadline(client.connection_id, &client.transport.connection) != null);
}

test "Tls13ClientEndpoint clears Version Negotiation follow-up route when restart Initial fails" {
    const original_dcid = [_]u8{ 0xa3, 0xa4, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0 };
    const followup_scid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8 };
    const alpn = [_][]const u8{"hq-interop"};
    const available_versions = [_]packet.Version{ .v2, .v1 };
    const tls_config = tls13.TlsConfig{ .alpn = &alpn, .server_name = "localhost", .skip_cert_verify = true };
    const path = endpoint.Udp4Tuple{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4444),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
    };
    var client = try Tls13ClientEndpoint.init(
        std.testing.allocator,
        23,
        path,
        .{ .active_migration_disabled = false },
        .{ .chosen_version = .v2, .available_versions = &available_versions },
        tls_config,
        original_dcid,
        client_scid,
    );
    defer client.deinit();

    var scratch: [8192]u8 = undefined;
    const initial = try client.begin(1, &scratch);
    defer std.testing.allocator.free(initial);

    const server_versions = [_]packet.Version{.v1};
    var vn_buf: [64]u8 = undefined;
    var vn_writer = buffer.fixedWriter(&vn_buf);
    try packet.encodeVersionNegotiationPacket(vn_writer.writer(), .{
        .dcid = &client_scid,
        .scid = &original_dcid,
        .versions = &server_versions,
    });

    var failing_allocator = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    client.transport.allocator = failing_allocator.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        client.processVersionNegotiationRestartWithRoutePath(
            2,
            &scratch,
            vn_writer.getWritten(),
            24,
            followup_scid,
            .{ .active_migration_disabled = false },
            tls_config,
        ),
    );

    try std.testing.expectEqual(@as(usize, 0), client.lifecycle.routeCount());
    try std.testing.expectError(error.UnknownConnectionId, client.lifecycle.currentRoutePath(&client_scid));
    try std.testing.expectError(error.UnknownConnectionId, client.lifecycle.currentRoutePath(&followup_scid));
    try std.testing.expectEqual(@as(u64, 23), client.connection_id);
    try std.testing.expectEqual(packet.Version.v2, client.transport.version);
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
