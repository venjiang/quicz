//! Pure-Zig TLS 1.3 QUIC server connection state without socket ownership.

const std = @import("std");
const buffer = @import("../quic/buffer.zig");
const connection_module = @import("../quic/connection.zig");
const connection_config = @import("../quic/connection_config.zig");
const crypto_types = @import("../quic/crypto_types.zig");
const frame = @import("../quic/frame.zig");
const protection = @import("../quic/protection.zig");
const tls13 = @import("tls13.zig");
const tls13_backend = @import("tls13_backend.zig");
const transport_types = @import("../quic/transport_types.zig");
const protocol_limits = @import("../quic/protocol_limits.zig");

const Connection = connection_module.Connection;
const Config = connection_config.Config;
const Tls13Backend = tls13_backend.Tls13Backend;
const Error = transport_types.Error;
const LossDetectionTimerDeadline = transport_types.LossDetectionTimerDeadline;
const max_connection_id_len = protocol_limits.max_connection_id_len;

/// One deadline that a TLS-owned server connection must observe.
pub const ServerTransportDeadline = union(enum) {
    /// Packet/time-threshold loss or PTO recovery deadline.
    recovery: LossDetectionTimerDeadline,
    /// Active-connection idle timeout deadline.
    idle_timeout: i64,
    /// Closing or draining deadline.
    close_timeout: i64,
    /// Retained previous 1-RTT key generation discard deadline.
    key_discard: i64,

    /// Return the monotonic deadline value for socket wait selection.
    pub fn deadlineMillis(self: ServerTransportDeadline) i64 {
        return switch (self) {
            .recovery => |deadline| deadline.deadline_millis,
            .idle_timeout, .close_timeout, .key_discard => |deadline| deadline,
        };
    }
};

/// Owns one server `Connection` and its pure-Zig TLS backend.
///
/// The endpoint still owns routing, Retry policy, timers, and UDP I/O. This
/// type owns per-connection TLS/QUIC state and provides the protected 1-RTT
/// stream boundary used after the endpoint has authenticated a datagram.
pub const Tls13ServerTransport = struct {
    connection: Connection,
    backend: Tls13Backend,
    local_initial_source_connection_id: [max_connection_id_len]u8 = undefined,
    local_initial_source_connection_id_len: usize = 0,
    peer_initial_source_connection_id: [max_connection_id_len]u8 = undefined,
    peer_initial_source_connection_id_len: usize = 0,
    original_destination_connection_id: [max_connection_id_len]u8 = undefined,
    original_destination_connection_id_len: usize = 0,

    /// Create one server transport with caller-supplied QUIC and TLS policy.
    pub fn init(
        allocator: std.mem.Allocator,
        connection_config_value: Config,
        tls_config: tls13.TlsConfig,
    ) Error!Tls13ServerTransport {
        var connection = try Connection.init(allocator, .server, connection_config_value);
        errdefer connection.deinit();
        return .{
            .connection = connection,
            .backend = Tls13Backend.initServer(tls_config),
        };
    }

    /// Release the owned QUIC connection state.
    pub fn deinit(self: *Tls13ServerTransport) void {
        self.connection.deinit();
    }

    /// Return the `Connection` used by endpoint lifecycle routing.
    pub fn connectionRef(self: *Tls13ServerTransport) *Connection {
        return &self.connection;
    }

    /// Return the pure-Zig TLS backend for lifecycle CRYPTO driving.
    pub fn cryptoBackend(self: *Tls13ServerTransport) crypto_types.CryptoBackend {
        return self.backend.cryptoBackend();
    }

    /// Store and apply the server CID used for its first Initial response.
    pub fn setLocalInitialSourceConnectionId(
        self: *Tls13ServerTransport,
        connection_id: []const u8,
    ) Error!void {
        try validateConnectionId(connection_id, false);
        try self.connection.setLocalInitialSourceConnectionId(connection_id);
        self.local_initial_source_connection_id_len = connection_id.len;
        @memcpy(self.local_initial_source_connection_id[0..connection_id.len], connection_id);
    }

    /// Return the server CID used for Initial and subsequent routed packets.
    pub fn localInitialSourceConnectionId(self: *const Tls13ServerTransport) []const u8 {
        return self.local_initial_source_connection_id[0..self.local_initial_source_connection_id_len];
    }

    /// Store the client Initial source CID after endpoint authentication.
    pub fn setPeerInitialSourceConnectionId(
        self: *Tls13ServerTransport,
        connection_id: []const u8,
    ) Error!void {
        try validateConnectionId(connection_id, true);
        try self.connection.setPeerInitialSourceConnectionId(connection_id);
        self.peer_initial_source_connection_id_len = connection_id.len;
        @memcpy(self.peer_initial_source_connection_id[0..connection_id.len], connection_id);
    }

    /// Return the peer CID used as the destination of server packets.
    pub fn peerInitialSourceConnectionId(self: *const Tls13ServerTransport) []const u8 {
        return self.peer_initial_source_connection_id[0..self.peer_initial_source_connection_id_len];
    }

    /// Store the client Original DCID used to derive Initial protection keys.
    pub fn setOriginalDestinationConnectionId(
        self: *Tls13ServerTransport,
        connection_id: []const u8,
    ) Error!void {
        try validateConnectionId(connection_id, true);
        self.original_destination_connection_id_len = connection_id.len;
        @memcpy(self.original_destination_connection_id[0..connection_id.len], connection_id);
    }

    /// Return the client's Original DCID retained for Initial packet handling.
    pub fn originalDestinationConnectionId(self: *const Tls13ServerTransport) []const u8 {
        return self.original_destination_connection_id[0..self.original_destination_connection_id_len];
    }

    /// Read received bytes from one peer-initiated application stream.
    pub fn recvStream(self: *Tls13ServerTransport, stream_id: u64, out: []u8) Error!?usize {
        return self.connection.recvOnStream(stream_id, out);
    }

    /// Return whether the peer has FIN-completed one application stream.
    pub fn streamFinished(self: *const Tls13ServerTransport, stream_id: u64) Error!bool {
        return self.connection.recvStreamFinished(stream_id);
    }

    /// Open a locally initiated bidirectional application stream.
    pub fn openStream(self: *Tls13ServerTransport) Error!u64 {
        return self.connection.openStream();
    }

    /// Open a locally initiated unidirectional application stream.
    pub fn openUniStream(self: *Tls13ServerTransport) Error!u64 {
        return self.connection.openUniStream();
    }

    /// Queue stream bytes for protected 1-RTT transmission.
    pub fn sendStream(
        self: *Tls13ServerTransport,
        stream_id: u64,
        data: []const u8,
        fin: bool,
    ) Error!void {
        try self.connection.sendOnStream(stream_id, data, fin);
    }

    /// Abort a locally writable stream and queue a RESET_STREAM frame.
    pub fn resetStream(
        self: *Tls13ServerTransport,
        stream_id: u64,
        application_error_code: u64,
    ) Error!void {
        try self.connection.resetStream(stream_id, application_error_code);
    }

    /// Ask the peer to stop sending on a receive-capable stream.
    pub fn stopSending(
        self: *Tls13ServerTransport,
        stream_id: u64,
        application_error_code: u64,
    ) Error!void {
        try self.connection.stopSending(stream_id, application_error_code);
    }

    /// Queue a protected application CONNECTION_CLOSE and poll it for send.
    pub fn close(
        self: *Tls13ServerTransport,
        application_error_code: u64,
        frame_type: u64,
        reason: []const u8,
        now_millis: i64,
    ) Error!?[]u8 {
        try self.connection.closeConnection(application_error_code, frame_type, reason);
        return self.pollApplicationDatagram(now_millis);
    }

    /// Queue a protected APPLICATION_CLOSE and poll it for send.
    pub fn closeApplication(
        self: *Tls13ServerTransport,
        application_error_code: u64,
        reason: []const u8,
        now_millis: i64,
    ) Error!?[]u8 {
        try self.connection.closeApplication(application_error_code, reason);
        return self.pollApplicationDatagram(now_millis);
    }

    /// Return the active close deadline after `close()` queues a close.
    pub fn closeDeadlineMillis(self: *const Tls13ServerTransport) ?i64 {
        return self.connection.closeDeadlineMillis();
    }

    /// Return one protected 1-RTT datagram queued by this transport.
    pub fn pollApplicationDatagram(
        self: *Tls13ServerTransport,
        now_millis: i64,
    ) Error!?[]u8 {
        const peer_connection_id = self.connection.peerDestinationConnectionId() orelse return error.InvalidPacket;
        return self.connection.pollProtectedShortDatagramWithInstalledKeys(
            now_millis,
            peer_connection_id,
        );
    }

    /// Return the owned connection's current loss/PTO wakeup deadline.
    pub fn lossDetectionTimerDeadlineMillis(self: *const Tls13ServerTransport) ?LossDetectionTimerDeadline {
        return self.connection.lossDetectionTimerDeadlineMillis();
    }

    /// Select the earliest lifecycle deadline for this connection.
    ///
    /// Endpoint loops can merge this deadline with other live records, then
    /// call `serviceDueDeadline()` when their socket wait expires. This keeps
    /// server idle, close, retained-key, and recovery state with the TLS-owned
    /// connection rather than duplicating timer policy in an endpoint.
    pub fn nextDeadline(self: *const Tls13ServerTransport) ?ServerTransportDeadline {
        const state = self.connection.connectionState();
        var next: ?ServerTransportDeadline = null;

        if (state == .active) {
            if (self.connection.idleTimeoutDeadlineMillis()) |deadline| {
                next = .{ .idle_timeout = deadline };
            }
            if (self.connection.lossDetectionTimerDeadlineMillis()) |deadline| {
                next = selectEarlierDeadline(next, .{ .recovery = deadline });
            }
            if (self.connection.oneRttKeyDiscardDeadlineMillis()) |deadline| {
                next = selectEarlierDeadline(next, .{ .key_discard = deadline });
            }
        }
        if (state == .closing or state == .draining) {
            if (self.connection.closeDeadlineMillis()) |deadline| {
                next = selectEarlierDeadline(next, .{ .close_timeout = deadline });
            }
        }
        return next;
    }

    /// Service the earliest lifecycle deadline when it is due.
    ///
    /// A returned deadline records which state transition or recovery action
    /// was applied. Calls before the selected deadline leave transport state
    /// unchanged and return null.
    pub fn serviceDueDeadline(
        self: *Tls13ServerTransport,
        now_millis: i64,
    ) Error!?ServerTransportDeadline {
        const deadline = self.nextDeadline() orelse return null;
        if (deadline.deadlineMillis() > now_millis) return null;

        switch (deadline) {
            .recovery => {
                _ = try self.connection.serviceLossDetectionTimer(now_millis);
            },
            .idle_timeout => {
                self.connection.checkIdleTimeouts(now_millis) catch |err| switch (err) {
                    error.ConnectionClosed => {},
                    else => return err,
                };
            },
            .close_timeout => {
                self.connection.checkCloseTimeouts(now_millis) catch |err| switch (err) {
                    error.ConnectionClosed => {},
                    else => return err,
                };
            },
            .key_discard => {
                _ = self.connection.discardExpiredOneRttKeys(now_millis);
            },
        }
        return deadline;
    }
};

fn validateConnectionId(connection_id: []const u8, allow_empty: bool) Error!void {
    if ((!allow_empty and connection_id.len == 0) or connection_id.len > max_connection_id_len) return error.InvalidPacket;
}

fn selectEarlierDeadline(
    current: ?ServerTransportDeadline,
    candidate: ServerTransportDeadline,
) ServerTransportDeadline {
    if (current) |existing| {
        if (existing.deadlineMillis() <= candidate.deadlineMillis()) return existing;
    }
    return candidate;
}

test "Tls13ServerTransport owns server connection and TLS backend" {
    var transport = try Tls13ServerTransport.init(std.testing.allocator, .{}, .{});
    defer transport.deinit();
    try std.testing.expectEqual(transport_types.ConnectionSide.server, transport.connection.side);
    const stream_id = try transport.openStream();
    try transport.sendStream(stream_id, "server stream", true);
}

test "Tls13ServerTransport exposes unidirectional and stream cancellation controls" {
    var transport = try Tls13ServerTransport.init(std.testing.allocator, .{}, .{});
    defer transport.deinit();

    const unidirectional_stream = try transport.openUniStream();
    try std.testing.expectEqual(@as(u64, 3), unidirectional_stream);
    try transport.resetStream(unidirectional_stream, 41);
    try std.testing.expectEqual(@as(usize, 1), transport.connection.pending_reset_streams.items.len);

    const bidirectional_stream = try transport.openStream();
    try transport.stopSending(bidirectional_stream, 42);
    try std.testing.expectEqual(@as(usize, 1), transport.connection.pending_stop_sending.items.len);
}

test "Tls13ServerTransport owns endpoint connection IDs" {
    var transport = try Tls13ServerTransport.init(std.testing.allocator, .{}, .{});
    defer transport.deinit();

    try transport.setLocalInitialSourceConnectionId(&.{ 1, 2, 3, 4 });
    try transport.setPeerInitialSourceConnectionId(&.{ 5, 6, 7, 8 });
    try transport.setOriginalDestinationConnectionId(&.{ 9, 10, 11, 12 });

    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, transport.localInitialSourceConnectionId());
    try std.testing.expectEqualSlices(u8, &.{ 5, 6, 7, 8 }, transport.peerInitialSourceConnectionId());
    try std.testing.expectEqualSlices(u8, &.{ 9, 10, 11, 12 }, transport.originalDestinationConnectionId());
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, transport.connection.localInitialSourceConnectionId().?);
    try std.testing.expectEqualSlices(u8, &.{ 5, 6, 7, 8 }, transport.connection.peerInitialSourceConnectionId().?);
    try std.testing.expectError(error.InvalidPacket, transport.setPeerInitialSourceConnectionId(&.{}));
    try std.testing.expectError(error.InvalidPacket, transport.setLocalInitialSourceConnectionId(&.{}));
}

test "Tls13ServerTransport sends to peer Initial source connection ID before NEW_CONNECTION_ID" {
    var transport = try Tls13ServerTransport.init(std.testing.allocator, .{}, .{});
    defer transport.deinit();

    const traffic_secret = [_]u8{0x34} ** 32;
    try transport.connection.validatePeerAddress();
    try transport.connection.confirmHandshake();
    try transport.connection.installOneRttTrafficSecrets(.{
        .local = traffic_secret,
        .peer = traffic_secret,
    });
    const peer_initial_source_connection_id = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    try transport.setPeerInitialSourceConnectionId(&peer_initial_source_connection_id);
    try transport.connection.sendPing();

    const datagram = (try transport.pollApplicationDatagram(1)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(datagram);
    var opened = try protection.unprotectShortPacketAes128(
        std.testing.allocator,
        protection.deriveAes128PacketProtectionKeys(traffic_secret),
        datagram,
        peer_initial_source_connection_id.len,
        0,
    );
    defer protection.deinitProtectedShortPacket(&opened, std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &peer_initial_source_connection_id, opened.packet.header.dcid);
}

test "Tls13ServerTransport services idle lifecycle deadline" {
    const alpn = [_][]const u8{"hq-interop"};
    var transport = try Tls13ServerTransport.init(
        std.testing.allocator,
        .{ .max_idle_timeout_ms = 10 },
        .{ .alpn = &alpn },
    );
    defer transport.deinit();
    transport.connection.last_packet_activity_millis = 10;

    const deadline = transport.nextDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(i64, 20), deadline.deadlineMillis());
    try std.testing.expect(deadline == .idle_timeout);
    try std.testing.expect((try transport.serviceDueDeadline(19)) == null);
    const serviced = try transport.serviceDueDeadline(20) orelse return error.TestUnexpectedResult;
    try std.testing.expect(serviced == .idle_timeout);
    try std.testing.expectEqual(transport_types.ConnectionState.closed, transport.connection.connectionState());
}

test "Tls13ServerTransport sends to the newest peer connection ID" {
    var transport = try Tls13ServerTransport.init(std.testing.allocator, .{}, .{});
    defer transport.deinit();

    const traffic_secret = [_]u8{0x44} ** 32;
    try transport.connection.validatePeerAddress();
    try transport.connection.confirmHandshake();
    try transport.connection.installOneRttTrafficSecrets(.{
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
    try transport.connection.processDatagram(0, writer.getWritten());
    try transport.connection.sendPing();

    const datagram = (try transport.pollApplicationDatagram(1)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(datagram);
    var opened = try protection.unprotectShortPacketAes128(
        std.testing.allocator,
        protection.deriveAes128PacketProtectionKeys(traffic_secret),
        datagram,
        peer_connection_id.len,
        0,
    );
    defer protection.deinitProtectedShortPacket(&opened, std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &peer_connection_id, opened.packet.header.dcid);
}

test "Tls13ServerTransport closes with protected application output and deadline" {
    var transport = try Tls13ServerTransport.init(std.testing.allocator, .{}, .{});
    defer transport.deinit();

    const traffic_secret = [_]u8{0x84} ** 32;
    try transport.connection.validatePeerAddress();
    try transport.connection.confirmHandshake();
    try transport.connection.installOneRttTrafficSecrets(.{
        .local = traffic_secret,
        .peer = traffic_secret,
    });
    const peer_connection_id = [_]u8{ 0xca, 0xcb, 0xcc, 0xcd };
    const reset_token = [_]u8{0x85} ** 16;
    var encoded: [64]u8 = undefined;
    var writer = buffer.fixedWriter(&encoded);
    try frame.encodeFrame(writer.writer(), .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = &peer_connection_id,
        .stateless_reset_token = reset_token,
    } });
    try transport.connection.processDatagram(0, writer.getWritten());

    const datagram = (try transport.close(88, 0, "server close", 10)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(datagram);
    try std.testing.expectEqual(transport_types.ConnectionState.closing, transport.connection.connectionState());
    const close_deadline = transport.closeDeadlineMillis() orelse return error.TestUnexpectedResult;
    const next_deadline = transport.nextDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expect(next_deadline == .close_timeout);
    try std.testing.expectEqual(close_deadline, next_deadline.deadlineMillis());

    var opened = try protection.unprotectShortPacketAes128(
        std.testing.allocator,
        protection.deriveAes128PacketProtectionKeys(traffic_secret),
        datagram,
        peer_connection_id.len,
        0,
    );
    defer protection.deinitProtectedShortPacket(&opened, std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &peer_connection_id, opened.packet.header.dcid);
    var decoded = try frame.decodeFrameSlice(opened.packet.plaintext, std.testing.allocator);
    defer frame.deinitFrame(&decoded.frame, std.testing.allocator);
    try std.testing.expect(decoded.frame == .connection_close);
    try std.testing.expectEqual(@as(u64, 88), decoded.frame.connection_close.error_code);

    const serviced = (try transport.serviceDueDeadline(close_deadline)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(serviced == .close_timeout);
    try std.testing.expectEqual(transport_types.ConnectionState.closed, transport.connection.connectionState());
}
