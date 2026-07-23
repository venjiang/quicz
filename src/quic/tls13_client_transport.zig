//! Pure-Zig TLS 1.3 QUIC client transport state without socket ownership.

const std = @import("std");
const buffer = @import("../quic/buffer.zig");
const connection_module = @import("../quic/connection.zig");
const connection_config = @import("../quic/connection_config.zig");
const frame = @import("../quic/frame.zig");
const packet = @import("../quic/packet.zig");
const protection = @import("../quic/protection.zig");
const tls13 = @import("../tls/tls13.zig");
const tls13_backend = @import("tls13_backend.zig");
const transport_types = @import("../quic/transport_types.zig");

const Connection = connection_module.Connection;
const Config = connection_config.Config;
const Tls13Backend = tls13_backend.Tls13Backend;
const Error = transport_types.Error;
const LossDetectionTimerDeadline = transport_types.LossDetectionTimerDeadline;
const ClientTransportError = Error || protection.ProtectionError || packet.PacketError || error{EndOfStream};

/// One deadline that a TLS-owned client socket loop must observe.
pub const ClientTransportDeadline = union(enum) {
    /// Packet/time-threshold loss or PTO recovery deadline.
    recovery: LossDetectionTimerDeadline,
    /// Active-connection idle timeout deadline.
    idle_timeout: i64,
    /// Closing or draining deadline.
    close_timeout: i64,
    /// Retained previous 1-RTT key generation discard deadline.
    key_discard: i64,

    /// Return the monotonic deadline value for socket wait selection.
    pub fn deadlineMillis(self: ClientTransportDeadline) i64 {
        return switch (self) {
            .recovery => |deadline| deadline.deadline_millis,
            .idle_timeout, .close_timeout, .key_discard => |deadline| deadline,
        };
    }
};

pub const Tls13ClientTransport = struct {
    allocator: std.mem.Allocator,
    connection: Connection,
    backend: Tls13Backend,
    version: packet.Version,
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
        const initial_keys = try protection.deriveInitialSecrets(connection_config_value.chosen_version, &original_destination_connection_id);
        return .{
            .allocator = allocator,
            .connection = connection,
            .backend = Tls13Backend.initClient(tls_config),
            .version = connection_config_value.chosen_version,
            .original_destination_connection_id = original_destination_connection_id,
            .local_source_connection_id = local_source_connection_id,
            .server_initial_keys = initial_keys.server,
        };
    }

    pub fn deinit(self: *Tls13ClientTransport) void {
        self.connection.deinit();
    }

    /// Report whether the TLS-owned handshake reached confirmed 1-RTT state.
    pub fn handshakeConfirmed(self: *const Tls13ClientTransport) bool {
        return self.connection.handshakeConfirmed();
    }

    /// Open a locally initiated bidirectional application stream.
    pub fn openStream(self: *Tls13ClientTransport) ClientTransportError!u64 {
        return self.connection.openStream();
    }

    /// Open a locally initiated unidirectional application stream.
    pub fn openUniStream(self: *Tls13ClientTransport) ClientTransportError!u64 {
        return self.connection.openUniStream();
    }

    /// Queue stream bytes for protected 1-RTT transmission.
    ///
    /// Call `pollApplicationDatagram()` until it returns null, then send and
    /// free each returned datagram through the caller's UDP socket.
    pub fn sendStream(
        self: *Tls13ClientTransport,
        stream_id: u64,
        data: []const u8,
        fin: bool,
    ) ClientTransportError!void {
        try self.connection.sendOnStream(stream_id, data, fin);
    }

    /// Abort a locally writable stream and queue a RESET_STREAM frame.
    pub fn resetStream(
        self: *Tls13ClientTransport,
        stream_id: u64,
        application_error_code: u64,
    ) ClientTransportError!void {
        try self.connection.resetStream(stream_id, application_error_code);
    }

    /// Ask the peer to stop sending on a receive-capable stream.
    pub fn stopSending(
        self: *Tls13ClientTransport,
        stream_id: u64,
        application_error_code: u64,
    ) ClientTransportError!void {
        try self.connection.stopSending(stream_id, application_error_code);
    }

    /// Queue a protected application CONNECTION_CLOSE and poll it for send.
    pub fn close(
        self: *Tls13ClientTransport,
        application_error_code: u64,
        frame_type: u64,
        reason: []const u8,
        now_millis: i64,
    ) ClientTransportError!?[]u8 {
        try self.connection.closeConnection(application_error_code, frame_type, reason);
        return self.pollApplicationDatagram(now_millis);
    }

    /// Queue a protected APPLICATION_CLOSE and poll it for send.
    pub fn closeApplication(
        self: *Tls13ClientTransport,
        application_error_code: u64,
        reason: []const u8,
        now_millis: i64,
    ) ClientTransportError!?[]u8 {
        try self.connection.closeApplication(application_error_code, reason);
        return self.pollApplicationDatagram(now_millis);
    }

    /// Return the active close deadline after `close()` queues a close.
    pub fn closeDeadlineMillis(self: *const Tls13ClientTransport) ?i64 {
        return self.connection.closeDeadlineMillis();
    }

    /// Return one protected 1-RTT application datagram queued by this transport.
    pub fn pollApplicationDatagram(
        self: *Tls13ClientTransport,
        now_millis: i64,
    ) ClientTransportError!?[]u8 {
        const peer_connection_id = self.connection.peerDestinationConnectionId() orelse return error.InvalidPacket;
        return self.connection.pollProtectedShortDatagramWithInstalledKeys(
            now_millis,
            peer_connection_id,
        );
    }

    /// Return one protected datagram after a due recovery timer is serviced.
    ///
    /// The selected packet number space controls which packet format and keys
    /// are used. Initial retransmission derives keys from the Original DCID or
    /// Retry SCID, Handshake uses installed TLS keys, and Application uses the
    /// normal 1-RTT short-packet path.
    pub fn pollRecoveryDatagram(
        self: *Tls13ClientTransport,
        deadline: LossDetectionTimerDeadline,
        now_millis: i64,
    ) ClientTransportError!?[]u8 {
        return switch (deadline.space) {
            .initial => initial: {
                const dcid = self.connection.retrySourceConnectionId() orelse &self.original_destination_connection_id;
                const initial_keys = try protection.deriveInitialSecrets(self.version, dcid);
                break :initial try self.connection.pollProtectedLongDatagram(
                    now_millis,
                    dcid,
                    &self.local_source_connection_id,
                    &[_]u8{},
                    .{ .initial = initial_keys.client },
                );
            },
            .handshake => handshake: {
                const peer_connection_id = self.connection.peerInitialSourceConnectionId() orelse return error.InvalidPacket;
                break :handshake try self.connection.pollProtectedHandshakeDatagramWithInstalledKeys(
                    now_millis,
                    peer_connection_id,
                    &self.local_source_connection_id,
                );
            },
            .application => try self.pollApplicationDatagram(now_millis),
        };
    }

    /// Read received bytes from one application stream into `out`.
    pub fn recvStream(
        self: *Tls13ClientTransport,
        stream_id: u64,
        out: []u8,
    ) ClientTransportError!?usize {
        return self.connection.recvOnStream(stream_id, out);
    }

    /// Return whether the peer has FIN-completed one application stream.
    pub fn streamFinished(self: *const Tls13ClientTransport, stream_id: u64) ClientTransportError!bool {
        return self.connection.recvStreamFinished(stream_id);
    }

    /// Return the transport's current loss/PTO wakeup deadline.
    pub fn lossDetectionTimerDeadlineMillis(self: *const Tls13ClientTransport) ?LossDetectionTimerDeadline {
        return self.connection.lossDetectionTimerDeadlineMillis();
    }

    /// Service a due loss/PTO timer before polling retransmission output.
    pub fn serviceLossDetectionTimer(
        self: *Tls13ClientTransport,
        now_millis: i64,
    ) ClientTransportError!?LossDetectionTimerDeadline {
        return self.connection.serviceLossDetectionTimer(now_millis);
    }

    /// Select the earliest active lifecycle deadline for this transport.
    ///
    /// Socket loops should wait until this deadline, receive one datagram, or
    /// call `serviceDueDeadline()` when the wait expires. This covers
    /// connection idle/close state and retained 1-RTT key discard in addition
    /// to RFC 9002 loss/PTO recovery.
    pub fn nextDeadline(self: *const Tls13ClientTransport) ?ClientTransportDeadline {
        const state = self.connection.connectionState();
        var next: ?ClientTransportDeadline = null;

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
        self: *Tls13ClientTransport,
        now_millis: i64,
    ) ClientTransportError!?ClientTransportDeadline {
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

    /// Return the selected configuration for a fresh client attempt after a
    /// validated Version Negotiation packet. The caller owns fresh connection
    /// IDs and must construct a new transport; QUIC does not continue the
    /// original connection attempt after Version Negotiation.
    pub fn versionNegotiationFollowupConfig(self: *const Tls13ClientTransport) ClientTransportError!Config {
        return self.connection.versionNegotiationFollowupConfig();
    }

    /// Queue ClientHello and return the first protected Initial datagram.
    pub fn begin(self: *Tls13ClientTransport, now_millis: i64, scratch: []u8) ClientTransportError![]u8 {
        _ = try self.connection.driveCryptoBackendInSpace(.initial, self.backend.cryptoBackend(), scratch);
        const initial_keys = try protection.deriveInitialSecrets(self.version, &self.original_destination_connection_id);
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
        if (datagram.len == 0) return error.InvalidPacket;
        if (isZeroOnlyPadding(datagram)) return error.InvalidPacket;
        if (isVersionNegotiationDatagram(datagram)) {
            const selected = try self.connection.processVersionNegotiationDatagram(
                now_millis,
                &self.original_destination_connection_id,
                &self.local_source_connection_id,
                datagram,
            );
            return .{ .version_negotiation_selected_version = selected };
        }
        if ((datagram[0] & 0x40) == 0) return error.InvalidPacket;
        if (isRetryDatagram(datagram)) {
            if (self.retry_received) return error.InvalidPacket;
            try self.connection.processRetryDatagram(now_millis, &self.original_destination_connection_id, datagram);
            const retry_scid = self.connection.retrySourceConnectionId() orelse return error.InvalidPacket;
            const retry_keys = try protection.deriveInitialSecrets(self.version, retry_scid);
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
            try self.connection.processProtectedShortDatagramWithInstalledKeysOrClose(
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
        version_negotiation_selected_version: ?packet.Version = null,
    };
};

fn isVersionNegotiationDatagram(datagram: []const u8) bool {
    return datagram.len >= 5 and (datagram[0] & 0x80) != 0 and
        std.mem.readInt(u32, datagram[1..5], .big) == 0;
}

fn isRetryDatagram(datagram: []const u8) bool {
    if (datagram.len < 5 or (datagram[0] & 0xc0) != 0xc0) return false;
    const version: packet.Version = @enumFromInt(std.mem.readInt(u32, datagram[1..5], .big));
    const type_bits: u2 = @intCast((datagram[0] >> 4) & 0x03);
    return packet.longHeaderPacketTypeFromBits(version, type_bits) == .retry;
}

fn isZeroOnlyPadding(datagram: []const u8) bool {
    return datagram.len > 0 and std.mem.allEqual(u8, datagram, 0);
}

fn selectEarlierDeadline(
    current: ?ClientTransportDeadline,
    candidate: ClientTransportDeadline,
) ClientTransportDeadline {
    if (current) |deadline| {
        if (deadline.deadlineMillis() <= candidate.deadlineMillis()) return deadline;
    }
    return candidate;
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

    const alpn = [_][]const u8{"hq-interop"};
    var transport = try Tls13ClientTransport.init(
        std.testing.allocator,
        .{},
        .{ .alpn = &alpn },
        .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .{ 8, 7, 6, 5, 4, 3, 2, 1 },
    );
    defer transport.deinit();
    var scratch: [1]u8 = undefined;
    try std.testing.expectError(error.InvalidPacket, transport.receive(1, &scratch, &[_]u8{}));
    try std.testing.expectError(error.InvalidPacket, transport.receive(1, &scratch, &[_]u8{ 0, 0, 0 }));
    try std.testing.expectError(error.InvalidPacket, transport.receive(1, &scratch, &[_]u8{ 0x20, 0x01, 0x02 }));
    try std.testing.expectError(error.InvalidPacket, transport.receive(1, &scratch, &[_]u8{ 0x80, 0, 0, 0, 1 }));
    try std.testing.expectEqual(@as(u64, 0), transport.connection.nextPeerPacketNumber(.initial));
    try std.testing.expect(!transport.retry_received);
}

test "Tls13ClientTransport services idle lifecycle deadline" {
    const alpn = [_][]const u8{"hq-interop"};
    var transport = try Tls13ClientTransport.init(
        std.testing.allocator,
        .{ .max_idle_timeout_ms = 10 },
        .{ .alpn = &alpn },
        .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .{ 8, 7, 6, 5, 4, 3, 2, 1 },
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

test "Tls13ClientTransport selects a fresh v1 attempt after Version Negotiation" {
    const alpn = [_][]const u8{"hq-interop"};
    const available_versions = [_]packet.Version{ .v2, .v1 };
    const original_dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const client_scid = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };
    var transport = try Tls13ClientTransport.init(
        std.testing.allocator,
        .{ .chosen_version = .v2, .available_versions = &available_versions },
        .{ .alpn = &alpn },
        original_dcid,
        client_scid,
    );
    defer transport.deinit();

    const expected_v2_keys = try protection.deriveInitialSecrets(.v2, &original_dcid);
    try std.testing.expectEqualSlices(u8, &expected_v2_keys.server.secret, &transport.server_initial_keys.secret);

    var scratch: [8192]u8 = undefined;
    const initial = try transport.begin(1, &scratch);
    defer std.testing.allocator.free(initial);
    try std.testing.expectEqual(@as(u32, @intFromEnum(packet.Version.v2)), std.mem.readInt(u32, initial[1..5], .big));

    const server_versions = [_]packet.Version{.v1};
    var vnp_buf: [64]u8 = undefined;
    var vnp_writer = buffer.fixedWriter(&vnp_buf);
    try packet.encodeVersionNegotiationPacket(vnp_writer.writer(), .{
        .dcid = &client_scid,
        .scid = &original_dcid,
        .versions = &server_versions,
    });
    const progress = try transport.receive(2, &scratch, vnp_writer.getWritten());
    try std.testing.expectEqual(@as(?packet.Version, .v1), progress.version_negotiation_selected_version);

    const followup_config = try transport.versionNegotiationFollowupConfig();
    try std.testing.expectEqual(packet.Version.v1, followup_config.chosen_version);
    try std.testing.expectEqual(@as(?packet.Version, .v1), followup_config.version_negotiation_selected_version);
}

test "Tls13ClientTransport exposes unidirectional and stream cancellation controls" {
    const alpn = [_][]const u8{"hq-interop"};
    var transport = try Tls13ClientTransport.init(
        std.testing.allocator,
        .{},
        .{ .alpn = &alpn },
        .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .{ 8, 7, 6, 5, 4, 3, 2, 1 },
    );
    defer transport.deinit();

    const unidirectional_stream = try transport.openUniStream();
    try std.testing.expectEqual(@as(u64, 2), unidirectional_stream);
    try transport.resetStream(unidirectional_stream, 41);
    try std.testing.expectEqual(@as(usize, 1), transport.connection.pending_reset_streams.items.len);

    const bidirectional_stream = try transport.openStream();
    try transport.stopSending(bidirectional_stream, 42);
    try std.testing.expectEqual(@as(usize, 1), transport.connection.pending_stop_sending.items.len);
}

test "Tls13ClientTransport sends to the newest peer connection ID" {
    const alpn = [_][]const u8{"hq-interop"};
    var transport = try Tls13ClientTransport.init(
        std.testing.allocator,
        .{},
        .{ .alpn = &alpn },
        .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .{ 8, 7, 6, 5, 4, 3, 2, 1 },
    );
    defer transport.deinit();

    const traffic_secret = [_]u8{0x44} ** 32;
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

test "Tls13ClientTransport closes with protected application output and deadline" {
    const alpn = [_][]const u8{"hq-interop"};
    var transport = try Tls13ClientTransport.init(
        std.testing.allocator,
        .{},
        .{ .alpn = &alpn },
        .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .{ 8, 7, 6, 5, 4, 3, 2, 1 },
    );
    defer transport.deinit();

    const traffic_secret = [_]u8{0x64} ** 32;
    try transport.connection.confirmHandshake();
    try transport.connection.installOneRttTrafficSecrets(.{
        .local = traffic_secret,
        .peer = traffic_secret,
    });
    const peer_connection_id = [_]u8{ 0xba, 0xbb, 0xbc, 0xbd };
    const reset_token = [_]u8{0x65} ** 16;
    var encoded: [64]u8 = undefined;
    var writer = buffer.fixedWriter(&encoded);
    try frame.encodeFrame(writer.writer(), .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = &peer_connection_id,
        .stateless_reset_token = reset_token,
    } });
    try transport.connection.processDatagram(0, writer.getWritten());

    const datagram = (try transport.close(77, 0, "client close", 10)) orelse return error.TestUnexpectedResult;
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
    try std.testing.expectEqual(@as(u64, 77), decoded.frame.connection_close.error_code);

    const serviced = (try transport.serviceDueDeadline(close_deadline)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(serviced == .close_timeout);
    try std.testing.expectEqual(transport_types.ConnectionState.closed, transport.connection.connectionState());
}
