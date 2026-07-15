//! Endpoint-owned lifecycle for one pure-Zig TLS 1.3 QUIC client transport.
//!
//! The endpoint owns the client transport, route registration, and recovery
//! timer mirroring. Callers retain UDP socket I/O and application policy.

const std = @import("std");
const connection_config = @import("connection_config.zig");
const endpoint = @import("endpoint.zig");
const endpoint_lifecycle = @import("endpoint_lifecycle.zig");
const tls13 = @import("tls13.zig");
const client_transport = @import("tls13_client_transport.zig");

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

    /// Route and process one peer datagram through the owned transport.
    pub fn receive(
        self: *Tls13ClientEndpoint,
        now_millis: i64,
        scratch: []u8,
        datagram: []const u8,
    ) !ReceiveResult {
        const route = try self.lifecycle.routeDatagram(self.path, datagram);
        if (route.connection_id != self.connection_id) return error.InvalidPacket;
        const progress = try self.transport.receive(now_millis, scratch, datagram);
        try self.lifecycle.armRecoveryTimerFromConnection(self.connection_id, &self.transport.connection);
        return .{ .route = route, .transport = progress };
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

    /// Select the next client transport lifecycle deadline.
    pub fn nextDeadline(self: *const Tls13ClientEndpoint) ?client_transport.ClientTransportDeadline {
        return self.transport.nextDeadline();
    }

    /// Service one due client deadline and refresh endpoint recovery state.
    pub fn serviceDueDeadline(
        self: *Tls13ClientEndpoint,
        now_millis: i64,
    ) !?client_transport.ClientTransportDeadline {
        const serviced = try self.transport.serviceDueDeadline(now_millis);
        try self.lifecycle.armRecoveryTimerFromConnection(self.connection_id, &self.transport.connection);
        return serviced;
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
