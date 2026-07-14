//! Pure-Zig TLS 1.3 QUIC client transport state without socket ownership.

const std = @import("std");
const connection_module = @import("connection.zig");
const connection_config = @import("connection_config.zig");
const packet = @import("packet.zig");
const protection = @import("protection.zig");
const tls13 = @import("tls13.zig");
const tls13_backend = @import("tls13_backend.zig");
const transport_types = @import("transport_types.zig");

const Connection = connection_module.Connection;
const Config = connection_config.Config;
const Tls13Backend = tls13_backend.Tls13Backend;
const Error = transport_types.Error;
const ClientTransportError = Error || protection.ProtectionError || packet.PacketError || error{EndOfStream};

pub const Tls13ClientTransport = struct {
    allocator: std.mem.Allocator,
    connection: Connection,
    backend: Tls13Backend,
    original_destination_connection_id: [8]u8,
    local_source_connection_id: [8]u8,
    server_initial_keys: protection.Aes128PacketProtectionKeys,
    retry_received: bool = false,
    handshake_finished_sent: bool = false,

    /// Create one client transport with stable Initial connection IDs.
    pub fn init(
        allocator: std.mem.Allocator,
        connection_config_value: Config,
        tls_config: tls13.TlsConfig,
        original_destination_connection_id: [8]u8,
        local_source_connection_id: [8]u8,
    ) ClientTransportError!Tls13ClientTransport {
        var connection = try Connection.init(allocator, .client, connection_config_value);
        errdefer connection.deinit();
        try connection.setLocalInitialSourceConnectionId(&local_source_connection_id);
        const initial_keys = try protection.deriveInitialSecrets(.v1, &original_destination_connection_id);
        return .{
            .allocator = allocator,
            .connection = connection,
            .backend = Tls13Backend.initClient(tls_config),
            .original_destination_connection_id = original_destination_connection_id,
            .local_source_connection_id = local_source_connection_id,
            .server_initial_keys = initial_keys.server,
        };
    }

    pub fn deinit(self: *Tls13ClientTransport) void {
        self.connection.deinit();
    }

    /// Queue ClientHello and return the first protected Initial datagram.
    pub fn begin(self: *Tls13ClientTransport, now_millis: i64, scratch: []u8) ClientTransportError![]u8 {
        _ = try self.connection.driveCryptoBackendInSpace(.initial, self.backend.cryptoBackend(), scratch);
        const initial_keys = try protection.deriveInitialSecrets(.v1, &self.original_destination_connection_id);
        return (try self.connection.pollProtectedLongCryptoDatagramInSpace(
            .initial,
            now_millis,
            &self.original_destination_connection_id,
            &self.local_source_connection_id,
            &[_]u8{},
            initial_keys.client,
        )) orelse error.Internal;
    }

    /// Process a Retry, protected Initial, Handshake, or 1-RTT datagram.
    ///
    /// A Retry returns the reprotected cached ClientHello. Once peer Handshake
    /// CRYPTO produces a client Finished, `outbound_handshake` contains that
    /// protected Handshake datagram. Callers retain and free non-null output.
    pub fn receive(
        self: *Tls13ClientTransport,
        now_millis: i64,
        scratch: []u8,
        datagram: []const u8,
    ) ClientTransportError!ReceiveResult {
        if (isRetryDatagram(datagram)) {
            if (self.retry_received) return error.InvalidPacket;
            try self.connection.processRetryDatagram(now_millis, &self.original_destination_connection_id, datagram);
            const retry_scid = self.connection.retrySourceConnectionId() orelse return error.InvalidPacket;
            const retry_keys = try protection.deriveInitialSecrets(.v1, retry_scid);
            self.backend.retryReceived();
            try self.connection.resetInitialCryptoSendForRetry();
            _ = try self.connection.driveCryptoBackendInSpace(.initial, self.backend.cryptoBackend(), scratch);
            const retry_initial = (try self.connection.pollProtectedLongCryptoDatagramInSpace(
                .initial,
                now_millis,
                retry_scid,
                &self.local_source_connection_id,
                &[_]u8{},
                retry_keys.client,
            )) orelse return error.Internal;
            self.server_initial_keys = retry_keys.server;
            self.retry_received = true;
            return .{ .outbound_initial = retry_initial, .retry_received = true };
        }

        var offset: usize = 0;
        while (offset < datagram.len and (datagram[offset] & 0x80) != 0) {
            const info = try protection.peekProtectedLongPacketInfo(datagram[offset..]);
            const end = std.math.add(usize, offset, info.len) catch return error.InvalidPacket;
            if (end > datagram.len) return error.InvalidPacket;
            switch (info.packet_type) {
                .initial => {
                    try self.connection.processProtectedLongDatagramInSpace(.initial, now_millis, self.server_initial_keys, datagram[offset..end]);
                    _ = try self.connection.driveCryptoBackendInSpace(.initial, self.backend.cryptoBackend(), scratch);
                },
                .handshake => {
                    try self.connection.processProtectedHandshakeDatagramWithInstalledKeys(now_millis, datagram[offset..end]);
                    _ = try self.connection.driveCryptoBackendInSpace(.handshake, self.backend.cryptoBackend(), scratch);
                },
                .zero_rtt, .retry => return error.InvalidPacket,
            }
            offset = end;
        }
        var application_processed = false;
        if (offset < datagram.len and !isZeroOnlyPadding(datagram[offset..])) {
            try self.connection.processProtectedShortDatagramWithInstalledKeys(
                now_millis,
                self.local_source_connection_id.len,
                datagram[offset..],
            );
            application_processed = true;
        }
        var outbound_handshake: ?[]u8 = null;
        if (!self.handshake_finished_sent) {
            if (self.connection.peerInitialSourceConnectionId()) |peer_scid| {
                outbound_handshake = try self.connection.pollProtectedHandshakeDatagramWithInstalledKeys(
                    now_millis,
                    peer_scid,
                    &self.local_source_connection_id,
                );
                self.handshake_finished_sent = outbound_handshake != null;
            }
        }
        return .{ .outbound_handshake = outbound_handshake, .application_processed = application_processed };
    }

    pub const ReceiveResult = struct {
        outbound_initial: ?[]u8 = null,
        outbound_handshake: ?[]u8 = null,
        retry_received: bool = false,
        application_processed: bool = false,
    };
};

fn isRetryDatagram(datagram: []const u8) bool {
    if (datagram.len < 5 or (datagram[0] & 0xc0) != 0xc0) return false;
    const version: packet.Version = @enumFromInt(std.mem.readInt(u32, datagram[1..5], .big));
    const type_bits: u2 = @intCast((datagram[0] >> 4) & 0x03);
    return packet.longHeaderPacketTypeFromBits(version, type_bits) == .retry;
}

fn isZeroOnlyPadding(datagram: []const u8) bool {
    return datagram.len > 0 and std.mem.allEqual(u8, datagram, 0);
}

test "Tls13ClientTransport emits a protected ClientHello" {
    const alpn = [_][]const u8{"hq-interop"};
    var transport = try Tls13ClientTransport.init(
        std.testing.allocator,
        .{},
        .{ .alpn = &alpn },
        .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .{ 8, 7, 6, 5, 4, 3, 2, 1 },
    );
    defer transport.deinit();
    var scratch: [8192]u8 = undefined;
    const initial = try transport.begin(1, &scratch);
    defer std.testing.allocator.free(initial);
    try std.testing.expect(initial.len >= 1200);
}

test "Tls13ClientTransport recognizes Retry and zero-only padding boundaries" {
    const retry = [_]u8{ 0xf0, 0, 0, 0, 1 };
    const initial = [_]u8{ 0xc0, 0, 0, 0, 1 };
    try std.testing.expect(isRetryDatagram(&retry));
    try std.testing.expect(!isRetryDatagram(&initial));
    try std.testing.expect(!isRetryDatagram(&[_]u8{ 0xf0, 0, 0, 0 }));
    try std.testing.expect(isZeroOnlyPadding(&[_]u8{ 0, 0, 0 }));
    try std.testing.expect(!isZeroOnlyPadding(&[_]u8{}));
    try std.testing.expect(!isZeroOnlyPadding(&[_]u8{ 0x40, 0 }));
}
