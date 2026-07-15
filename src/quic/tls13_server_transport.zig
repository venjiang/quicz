//! Pure-Zig TLS 1.3 QUIC server connection state without socket ownership.

const std = @import("std");
const connection_module = @import("connection.zig");
const connection_config = @import("connection_config.zig");
const crypto_types = @import("crypto_types.zig");
const tls13 = @import("tls13.zig");
const tls13_backend = @import("tls13_backend.zig");
const transport_types = @import("transport_types.zig");

const Connection = connection_module.Connection;
const Config = connection_config.Config;
const Tls13Backend = tls13_backend.Tls13Backend;
const Error = transport_types.Error;
const LossDetectionTimerDeadline = transport_types.LossDetectionTimerDeadline;

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

    /// Return one protected 1-RTT datagram queued by this transport.
    pub fn pollApplicationDatagram(
        self: *Tls13ServerTransport,
        now_millis: i64,
    ) Error!?[]u8 {
        const peer_connection_id = self.connection.peerInitialSourceConnectionId() orelse return error.InvalidPacket;
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
