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

    /// Queue stream bytes for protected 1-RTT transmission.
    pub fn sendStream(
        self: *Tls13ServerTransport,
        stream_id: u64,
        data: []const u8,
        fin: bool,
    ) Error!void {
        try self.connection.sendOnStream(stream_id, data, fin);
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
};

test "Tls13ServerTransport owns server connection and TLS backend" {
    var transport = try Tls13ServerTransport.init(std.testing.allocator, .{}, .{});
    defer transport.deinit();
    try std.testing.expectEqual(transport_types.ConnectionSide.server, transport.connection.side);
    const stream_id = try transport.connection.openStream();
    try transport.sendStream(stream_id, "server stream", true);
}
