const std = @import("std");
const Connection = @import("connection.zig").Connection;
const Tls13ClientTransport = @import("tls13_client_transport.zig").Tls13ClientTransport;
const Tls13Backend = @import("tls13_backend.zig").Tls13Backend;
const packet = @import("packet.zig");
const buffer = @import("buffer.zig");
const endpoint = @import("endpoint.zig");
const Tls13ClientEndpoint = @import("tls13_client_endpoint.zig").Tls13ClientEndpoint;
const frame = @import("frame.zig");
const protection = @import("protection.zig");

const allocator = std.testing.allocator;
const original_dcid = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
const client_scid = [8]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };
const server_scid = @as([17]u8, @splat(0x42));
const private_key = @as([32]u8, @splat(0x55));
const certificate = [_]u8{ 0x30, 0x82, 0x01, 0x00, 0xde, 0xad, 0xbe, 0xef };
const alpn = [_][]const u8{"h3"};
const versions = [_]packet.Version{ .v1, .v2 };

const Handshake = struct {
    client: Tls13ClientTransport,
    server: Connection,
    backend: Tls13Backend,
    initial: ?[]u8 = null,
    handshake: ?[]u8 = null,
    scratch: [8192]u8 = undefined,

    fn init(version: packet.Version) !Handshake {
        var client = try Tls13ClientTransport.init(allocator, .{
            .chosen_version = version,
            .available_versions = &versions,
            .max_datagram_size = 8192,
        }, .{ .alpn = &alpn, .skip_cert_verify = true }, original_dcid, client_scid);
        errdefer client.deinit();
        return .{
            .client = client,
            .server = try Connection.init(allocator, .server, .{
                .chosen_version = version,
                .available_versions = &versions,
                .max_datagram_size = 8192,
            }),
            .backend = Tls13Backend.initServer(.{
                .alpn = &alpn,
                .cert_chain_der = &.{&certificate},
                .private_key_bytes = &private_key,
                .private_key_algorithm = .ecdsa_p256_sha256,
            }),
        };
    }

    fn deinit(self: *Handshake) void {
        if (self.initial) |bytes| allocator.free(bytes);
        if (self.handshake) |bytes| allocator.free(bytes);
        self.client.deinit();
        self.server.deinit();
    }

    fn start(self: *Handshake) !void {
        const client_initial = try self.client.begin(0, &self.scratch);
        defer allocator.free(client_initial);
        try self.startServer(client_initial);
    }

    fn startServer(self: *Handshake, client_initial: []const u8) !void {
        try self.server.setLocalInitialSourceConnectionId(&server_scid);
        try self.server.validatePeerAddress();
        const initial_keys = try protection.deriveInitialSecrets(self.client.version, &original_dcid);
        try self.server.processProtectedLongDatagramInSpace(.initial, 1, initial_keys.client, client_initial);
        _ = try self.server.driveCryptoBackendInSpace(.initial, self.backend.cryptoBackend(), &self.scratch);
        self.initial = (try self.server.pollProtectedLongCryptoDatagramInSpace(
            .initial,
            2,
            &client_scid,
            &server_scid,
            &.{},
            initial_keys.server,
        )) orelse return error.TestUnexpectedResult;
        _ = try self.server.driveCryptoBackendInSpace(.handshake, self.backend.cryptoBackend(), &self.scratch);
        self.handshake = (try self.server.pollProtectedLongCryptoDatagramInSpace(
            .handshake,
            3,
            &client_scid,
            &server_scid,
            &.{},
            self.server.local_handshake_keys.?,
        )) orelse return error.TestUnexpectedResult;
    }

    fn confirm(self: *Handshake, finished: []const u8) !void {
        try std.testing.expect(self.client.backend.hs.isComplete());
        try std.testing.expect(!self.client.handshakeConfirmed());
        try self.server.processProtectedHandshakeDatagramWithInstalledKeys(20, finished);
        _ = try self.server.driveCryptoBackendInSpace(.handshake, self.backend.cryptoBackend(), &self.scratch);
        try std.testing.expect(self.server.handshakeConfirmed());
        const done = (try self.server.pollProtectedShortDatagramWithInstalledKeys(21, &client_scid)) orelse return error.TestUnexpectedResult;
        defer allocator.free(done);
        const received = try self.client.receive(22, &self.scratch, done);
        defer if (received.outbound_handshake) |bytes| allocator.free(bytes);
        try std.testing.expect(received.application_processed);
        try std.testing.expect(self.client.handshakeConfirmed());
    }

    fn protectHandshake(self: *Handshake, plaintext: []const u8) ![]u8 {
        return protection.protectLongPacketAes128(allocator, .{
            .version = self.client.version,
            .dcid = &client_scid,
            .scid = &server_scid,
            .packet_type = .handshake,
            .token = &.{},
            .packet_number = 0,
            .payload_length = 0,
        }, .{ .len = 1, .truncated_packet_number = 0 }, self.server.local_handshake_keys.?, plaintext);
    }
};

test "client reordering normal TLS control still completes" {
    var hs = try Handshake.init(.v1);
    defer hs.deinit();
    try hs.start();
    const initial = try hs.client.receive(4, &hs.scratch, hs.initial.?);
    defer if (initial.outbound_handshake) |bytes| allocator.free(bytes);
    try std.testing.expect(initial.outbound_handshake == null);
    const received = try hs.client.receive(5, &hs.scratch, hs.handshake.?);
    const finished = received.outbound_handshake orelse return error.TestUnexpectedResult;
    defer allocator.free(finished);
    try hs.confirm(finished);
}

test "client reordering buffers Handshake before Initial without retransmission" {
    for ([_]packet.Version{ .v1, .v2 }) |version| {
        var hs = try Handshake.init(version);
        defer hs.deinit();
        try hs.start();
        const incoming = try allocator.dupe(u8, hs.handshake.?);
        defer allocator.free(incoming);
        const early = try hs.client.receive(4, &hs.scratch, incoming);
        defer if (early.outbound_handshake) |bytes| allocator.free(bytes);
        try std.testing.expect(early.outbound_handshake == null);
        try std.testing.expect(!early.application_processed);
        try std.testing.expectEqual(@as(u64, 0), hs.client.connection.nextPeerPacketNumber(.handshake));
        @memset(incoming, 0);

        const received = try hs.client.receive(5, &hs.scratch, hs.initial.?);
        const finished = received.outbound_handshake orelse return error.TestUnexpectedResult;
        defer allocator.free(finished);
        try hs.confirm(finished);
    }
}

test "client reordering processes early 1-RTT after buffered Handshake" {
    var hs = try Handshake.init(.v1);
    defer hs.deinit();
    try hs.start();
    try hs.server.sendPing();
    const application = (try hs.server.pollProtectedShortDatagramWithInstalledKeys(4, &client_scid)) orelse return error.TestUnexpectedResult;
    defer allocator.free(application);
    const early_application = try hs.client.receive(5, &hs.scratch, application);
    defer if (early_application.outbound_handshake) |bytes| allocator.free(bytes);
    try std.testing.expect(!early_application.application_processed);
    const early_handshake = try hs.client.receive(6, &hs.scratch, hs.handshake.?);
    defer if (early_handshake.outbound_handshake) |bytes| allocator.free(bytes);
    try std.testing.expect(!hs.client.backend.hs.isComplete());
    try std.testing.expectEqual(@as(u64, 0), hs.client.connection.nextPeerPacketNumber(.application));

    const received = try hs.client.receive(7, &hs.scratch, hs.initial.?);
    const finished = received.outbound_handshake orelse return error.TestUnexpectedResult;
    defer allocator.free(finished);
    try std.testing.expect(received.application_processed);
    try std.testing.expectEqual(@as(u64, 1), hs.client.connection.nextPeerPacketNumber(.application));
    try hs.confirm(finished);
}

test "client reordering supports Handshake before Initial in one datagram" {
    var hs = try Handshake.init(.v1);
    defer hs.deinit();
    try hs.start();
    const coalesced = try std.mem.concat(allocator, u8, &.{ hs.handshake.?, hs.initial.? });
    defer allocator.free(coalesced);
    const received = try hs.client.receive(4, &hs.scratch, coalesced);
    const finished = received.outbound_handshake orelse return error.TestUnexpectedResult;
    defer allocator.free(finished);
    try hs.confirm(finished);
}

test "client reordering bounds the queue and drops new arrivals when full" {
    var hs = try Handshake.init(.v1);
    defer hs.deinit();
    try hs.start();
    const capacity = hs.client.undecryptable_packets.len;
    for (0..capacity + 3) |_| {
        const received = try hs.client.receive(4, &hs.scratch, hs.handshake.?);
        defer if (received.outbound_handshake) |bytes| allocator.free(bytes);
    }
    try std.testing.expectEqual(capacity, hs.client.undecryptable_count);
    try hs.server.sendPing();
    const ping = (try hs.server.pollProtectedShortDatagramWithInstalledKeys(5, &client_scid)) orelse return error.TestUnexpectedResult;
    defer allocator.free(ping);
    _ = try hs.client.receive(6, &hs.scratch, ping);
    try std.testing.expectEqual(capacity, hs.client.undecryptable_count);
    for (hs.client.undecryptable_packets) |pending| {
        try std.testing.expectEqualSlices(u8, hs.handshake.?, pending.bytes);
    }
    const received = try hs.client.receive(7, &hs.scratch, hs.initial.?);
    const finished = received.outbound_handshake orelse return error.TestUnexpectedResult;
    defer allocator.free(finished);
    try std.testing.expect(!received.application_processed);
    try std.testing.expectEqual(@as(usize, 0), hs.client.undecryptable_count);
    try hs.confirm(finished);
}

test "client reordering does not retain packets over the configured size" {
    var hs = try Handshake.init(.v1);
    defer hs.deinit();
    try hs.start();
    const plaintext = try allocator.alloc(u8, hs.client.connection.config.max_datagram_size);
    defer allocator.free(plaintext);
    @memset(plaintext, 0);
    const oversized = try hs.protectHandshake(plaintext);
    defer allocator.free(oversized);
    const received = try hs.client.receive(4, &hs.scratch, oversized);
    defer if (received.outbound_handshake) |bytes| allocator.free(bytes);
    try std.testing.expectEqual(@as(usize, 0), hs.client.undecryptable_count);
    try std.testing.expectEqual(@as(u64, 0), hs.client.connection.nextPeerPacketNumber(.handshake));
}

test "client reordering frees unresolved packets at deinit" {
    var hs = try Handshake.init(.v1);
    defer hs.deinit();
    try hs.start();
    _ = try hs.client.receive(4, &hs.scratch, hs.handshake.?);
    try std.testing.expectEqual(@as(usize, 1), hs.client.undecryptable_count);
}

test "client reordering allocation failure leaves the queue unchanged" {
    var hs = try Handshake.init(.v1);
    defer hs.deinit();
    try hs.start();
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    hs.client.allocator = failing.allocator();
    defer hs.client.allocator = allocator;
    try std.testing.expectError(error.OutOfMemory, hs.client.receive(4, &hs.scratch, hs.handshake.?));
    try std.testing.expectEqual(@as(usize, 0), hs.client.undecryptable_count);
}

test "client reordering discards queued Handshake after key-space discard" {
    var hs = try Handshake.init(.v1);
    defer hs.deinit();
    try hs.start();
    _ = try hs.client.receive(4, &hs.scratch, hs.handshake.?);
    try hs.client.connection.discardPacketNumberSpace(.handshake);
    _ = try hs.client.receive(5, &hs.scratch, hs.handshake.?);
    try std.testing.expectEqual(@as(usize, 0), hs.client.undecryptable_count);
}

test "client reordering releases pending packets on idle expiry" {
    var hs = try Handshake.init(.v1);
    defer hs.deinit();
    try hs.start();
    _ = try hs.client.receive(4, &hs.scratch, hs.handshake.?);
    hs.client.connection.config.max_idle_timeout_ms = 1;
    hs.client.connection.last_packet_activity_nanos = 0;
    const deadline = hs.client.connection.idleTimeoutDeadline() orelse return error.TestUnexpectedResult;
    _ = try hs.client.serviceDueDeadline(deadline);
    try std.testing.expectEqual(@as(usize, 0), hs.client.undecryptable_count);
    try std.testing.expectEqual(.closed, hs.client.connection.connectionState());
}

test "client reordering releases pending packets when closing starts" {
    for ([_]bool{ false, true }) |application_close| {
        var hs = try Handshake.init(.v1);
        defer hs.deinit();
        try hs.start();
        _ = try hs.client.receive(4, &hs.scratch, hs.handshake.?);
        // Close output still lacks peer keys, but the closing transition owns cleanup.
        if (application_close) {
            try std.testing.expectError(error.InvalidPacket, hs.client.closeApplication(1, "close", 5));
        } else {
            try std.testing.expectError(error.InvalidPacket, hs.client.close(1, 0, "close", 5));
        }
        try std.testing.expectEqual(.closing, hs.client.connection.connectionState());
        try std.testing.expectEqual(@as(usize, 0), hs.client.undecryptable_count);
    }
}

test "client reordering keeps authenticated frame errors visible" {
    for ([_]bool{ false, true }) |early| {
        var hs = try Handshake.init(.v1);
        defer hs.deinit();
        try hs.start();
        const invalid_plaintext = [_]u8{0x1f} ++ @as([31]u8, @splat(0));
        const invalid = try hs.protectHandshake(&invalid_plaintext);
        defer allocator.free(invalid);
        if (early) {
            _ = try hs.client.receive(4, &hs.scratch, invalid);
            try std.testing.expectError(error.InvalidPacket, hs.client.receive(5, &hs.scratch, hs.initial.?));
        } else {
            _ = try hs.client.receive(4, &hs.scratch, hs.initial.?);
            try std.testing.expectError(error.InvalidPacket, hs.client.receive(5, &hs.scratch, invalid));
        }
        try std.testing.expectEqual(@as(u64, 0), hs.client.connection.nextPeerPacketNumber(.handshake));
        try std.testing.expect(!hs.client.backend.hs.isComplete());
    }
}

test "client reordering does not bypass TLS certificate rejection" {
    var hs = try Handshake.init(.v1);
    defer hs.deinit();
    hs.client.backend.hs.config.skip_cert_verify = false;
    try hs.start();
    _ = try hs.client.receive(4, &hs.scratch, hs.handshake.?);
    try std.testing.expectError(error.CryptoError, hs.client.receive(5, &hs.scratch, hs.initial.?));
    try std.testing.expect(!hs.client.connection.hasOneRttProtectionKeys());
    try std.testing.expect(!hs.client.handshakeConfirmed());
}

test "client reordering clears old packets only after a valid Retry" {
    var hs = try Handshake.init(.v1);
    defer hs.deinit();
    try hs.start();
    _ = try hs.client.receive(4, &hs.scratch, hs.handshake.?);
    const retry_scid = [_]u8{ 0x11, 0x12, 0x13, 0x14 };
    const retry = try protection.encodeRetryPacketWithIntegrity(allocator, &original_dcid, .{
        .version = .v1,
        .dcid = &client_scid,
        .scid = &retry_scid,
        .token = "retry-token",
        .integrity_tag = @splat(0),
    });
    defer allocator.free(retry);
    retry[retry.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidPacket, hs.client.receive(5, &hs.scratch, retry));
    try std.testing.expectEqual(@as(usize, 1), hs.client.undecryptable_count);
    retry[retry.len - 1] ^= 1;
    const received = try hs.client.receive(6, &hs.scratch, retry);
    const initial = received.outbound_initial orelse return error.TestUnexpectedResult;
    defer allocator.free(initial);
    try std.testing.expect(received.retry_received);
    try std.testing.expectEqual(@as(usize, 0), hs.client.undecryptable_count);
}

test "client reordering clears old packets on valid Version Negotiation" {
    var hs = try Handshake.init(.v2);
    defer hs.deinit();
    try hs.start();
    _ = try hs.client.receive(4, &hs.scratch, hs.handshake.?);
    var encoded: [64]u8 = undefined;
    var writer = buffer.fixedWriter(&encoded);
    const offered = [_]packet.Version{.v1};
    try packet.encodeVersionNegotiationPacket(writer.writer(), .{
        .dcid = &client_scid,
        .scid = &original_dcid,
        .versions = &offered,
    });
    const received = try hs.client.receive(5, &hs.scratch, writer.getWritten());
    try std.testing.expectEqual(@as(?packet.Version, .v1), received.version_negotiation_selected_version);
    try std.testing.expectEqual(@as(usize, 0), hs.client.undecryptable_count);
}

test "client reordering ignored Version Negotiation preserves the flight" {
    var hs = try Handshake.init(.v1);
    defer hs.deinit();
    try hs.start();
    _ = try hs.client.receive(4, &hs.scratch, hs.handshake.?);
    var encoded: [64]u8 = undefined;
    var writer = buffer.fixedWriter(&encoded);
    const offered = [_]packet.Version{.v1};
    try packet.encodeVersionNegotiationPacket(writer.writer(), .{
        .dcid = &client_scid,
        .scid = &original_dcid,
        .versions = &offered,
    });
    const ignored = try hs.client.receive(5, &hs.scratch, writer.getWritten());
    try std.testing.expect(ignored.version_negotiation_selected_version == null);
    try std.testing.expectEqual(@as(usize, 1), hs.client.undecryptable_count);
    const received = try hs.client.receive(6, &hs.scratch, hs.initial.?);
    const finished = received.outbound_handshake orelse return error.TestUnexpectedResult;
    defer allocator.free(finished);
    try hs.confirm(finished);
}

fn initEndpoint() !Tls13ClientEndpoint {
    return Tls13ClientEndpoint.init(allocator, 123, .{
        .local = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4444),
        .remote = endpoint.Udp4Address.init(.{ 127, 0, 0, 1 }, 4433),
    }, .{}, .{ .max_datagram_size = 8192, .max_idle_timeout_ms = 1, .available_versions = &versions }, .{
        .alpn = &alpn,
        .skip_cert_verify = true,
    }, original_dcid, client_scid);
}

fn startEndpoint(hs: *Handshake, client: *Tls13ClientEndpoint) !void {
    const initial = try client.begin(0, &hs.scratch);
    defer allocator.free(initial);
    try hs.startServer(initial);
    _ = try client.receive(4, &hs.scratch, hs.handshake.?);
    try std.testing.expectEqual(@as(usize, 1), client.transport.undecryptable_count);
}

test "client reordering endpoint idle retirement releases packets" {
    var hs = try Handshake.init(.v1);
    defer hs.deinit();
    var client = try initEndpoint();
    defer client.deinit();
    try startEndpoint(&hs, &client);
    client.transport.connection.last_packet_activity_nanos = 0;
    const deadline = client.transport.connection.idleTimeoutDeadline() orelse return error.TestUnexpectedResult;
    _ = try client.serviceDueDeadline(deadline);
    try std.testing.expectEqual(.closed, client.transport.connection.connectionState());
    try std.testing.expectEqual(@as(usize, 0), client.transport.undecryptable_count);
    try std.testing.expectError(error.UnknownConnectionId, client.lifecycle.currentRoutePath(&client_scid));
}

test "client reordering endpoint reset releases packets without retiring early" {
    var hs = try Handshake.init(.v1);
    defer hs.deinit();
    var client = try initEndpoint();
    defer client.deinit();
    try startEndpoint(&hs, &client);
    const reset_token = @as([16]u8, @splat(0x77));
    var encoded: [128]u8 = undefined;
    var writer = buffer.fixedWriter(&encoded);
    try frame.encodeFrame(writer.writer(), .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 0,
        .connection_id = &server_scid,
        .stateless_reset_token = reset_token,
    } });
    try client.transport.connection.processDatagram(5, writer.getWritten());
    var reset = @as([32]u8, @splat(0x40));
    @memcpy(reset[1 .. 1 + client_scid.len], &client_scid);
    @memcpy(reset[reset.len - reset_token.len ..], &reset_token);
    const received = try client.receive(6, &hs.scratch, &reset);
    try std.testing.expectEqual(@as(?u64, 1), received.stateless_reset_sequence_number);
    try std.testing.expectEqual(.draining, client.transport.connection.connectionState());
    try std.testing.expectEqual(@as(usize, 0), client.transport.undecryptable_count);
    _ = try client.lifecycle.currentRoutePath(&client_scid);
}

test "client reordering endpoint route-bound close variants release packets" {
    for ([_]bool{ false, true }) |application_close| {
        for ([_]bool{ false, true }) |drain| {
            var hs = try Handshake.init(.v1);
            defer hs.deinit();
            var client = try initEndpoint();
            defer client.deinit();
            try startEndpoint(&hs, &client);
            if (drain) {
                var out: [1]Tls13ClientEndpoint.ApplicationDatagramPathResult = undefined;
                const result = if (application_close)
                    try client.closeApplicationWithRoutePathAndDrainDatagrams(1, "close", 5, &out)
                else
                    try client.closeWithRoutePathAndDrainDatagrams(1, 0, "close", 5, &out);
                try std.testing.expectEqual(@as(usize, 0), result.drain.datagrams_written);
                try std.testing.expectEqual(@as(?@import("transport_types.zig").Error, error.InvalidPacket), result.drain.first_error);
            } else if (application_close) {
                try std.testing.expectError(error.InvalidPacket, client.closeApplicationWithRoutePath(1, "close", 5));
            } else {
                try std.testing.expectError(error.InvalidPacket, client.closeWithRoutePath(1, 0, "close", 5));
            }
            try std.testing.expectEqual(.closing, client.transport.connection.connectionState());
            try std.testing.expectEqual(@as(usize, 0), client.transport.undecryptable_count);
        }
    }
}

test "client reordering endpoint close deadlines release packets" {
    for ([_]bool{ false, true }) |direct_retire| {
        var hs = try Handshake.init(.v1);
        defer hs.deinit();
        var client = try initEndpoint();
        defer client.deinit();
        try startEndpoint(&hs, &client);
        try client.transport.connection.closeConnection(1, 0, "close");
        var encoded: [128]u8 = undefined;
        _ = (try client.transport.connection.pollTx(5, &encoded)) orelse return error.TestUnexpectedResult;
        const deadline = client.closeDeadline() orelse return error.TestUnexpectedResult;
        if (direct_retire) {
            _ = try client.retireAtCloseDeadline(deadline);
        } else {
            _ = try client.serviceDueDeadline(deadline);
        }
        try std.testing.expectEqual(.closed, client.transport.connection.connectionState());
        try std.testing.expectEqual(@as(usize, 0), client.transport.undecryptable_count);
        try std.testing.expectError(error.UnknownConnectionId, client.lifecycle.currentRoutePath(&client_scid));
    }
}

test "client reordering direct recovery timer releases packets on idle expiry" {
    for ([_]bool{ false, true }) |idle_expired| {
        var hs = try Handshake.init(.v1);
        defer hs.deinit();
        if (idle_expired) hs.client.connection.config.max_idle_timeout_ms = 1;
        try hs.start();
        _ = try hs.client.receive(4, &hs.scratch, hs.handshake.?);
        hs.client.connection.last_packet_activity_nanos = 0;
        const recovery = hs.client.lossDetectionTimerDeadline() orelse return error.TestUnexpectedResult;
        if (idle_expired) {
            try std.testing.expectError(error.ConnectionClosed, hs.client.serviceLossDetectionTimer(recovery.deadline_nanos));
            try std.testing.expectEqual(.closed, hs.client.connection.connectionState());
            try std.testing.expectEqual(@as(usize, 0), hs.client.undecryptable_count);
        } else {
            _ = (try hs.client.serviceLossDetectionTimer(recovery.deadline_nanos)) orelse return error.TestUnexpectedResult;
            try std.testing.expectEqual(.active, hs.client.connection.connectionState());
            try std.testing.expectEqual(@as(usize, 1), hs.client.undecryptable_count);
            const received = try hs.client.receive(recovery.deadline_nanos + 1, &hs.scratch, hs.initial.?);
            const finished = received.outbound_handshake orelse return error.TestUnexpectedResult;
            defer allocator.free(finished);
            try std.testing.expect(hs.client.backend.hs.isComplete());
        }
    }
}

test "client reordering endpoint ignored VN keeps the original active flight" {
    var hs = try Handshake.init(.v1);
    defer hs.deinit();
    var client = try initEndpoint();
    defer client.deinit();
    try startEndpoint(&hs, &client);
    var encoded: [64]u8 = undefined;
    var writer = buffer.fixedWriter(&encoded);
    const offered = [_]packet.Version{.v1};
    try packet.encodeVersionNegotiationPacket(writer.writer(), .{
        .dcid = &client_scid,
        .scid = &original_dcid,
        .versions = &offered,
    });
    const followup_scid = @as([8]u8, @splat(0x99));
    const ignored = try client.processVersionNegotiationFollowupRoute(5, writer.getWritten(), 124, &followup_scid, .{});
    try std.testing.expect(ignored == null);
    try std.testing.expectEqual(@as(usize, 1), client.transport.undecryptable_count);
    const received = try client.receive(6, &hs.scratch, hs.initial.?);
    const finished = received.transport.outbound_handshake orelse return error.TestUnexpectedResult;
    defer allocator.free(finished);
    try std.testing.expect(client.transport.backend.hs.isComplete());
    try hs.server.processProtectedHandshakeDatagramWithInstalledKeys(7, finished);
    _ = try hs.server.driveCryptoBackendInSpace(.handshake, hs.backend.cryptoBackend(), &hs.scratch);
    try std.testing.expect(hs.server.handshakeConfirmed());
    _ = try client.lifecycle.currentRoutePath(&client_scid);
}

test "client reordering endpoint VN expiry releases packets before error" {
    for ([_]bool{ false, true }) |restart| {
        var hs = try Handshake.init(.v1);
        defer hs.deinit();
        var client = try initEndpoint();
        defer client.deinit();
        try startEndpoint(&hs, &client);
        client.transport.connection.last_packet_activity_nanos = 0;
        const deadline = client.transport.connection.idleTimeoutDeadline() orelse return error.TestUnexpectedResult;
        var encoded: [64]u8 = undefined;
        var writer = buffer.fixedWriter(&encoded);
        const offered = [_]packet.Version{.v1};
        try packet.encodeVersionNegotiationPacket(writer.writer(), .{
            .dcid = &client_scid,
            .scid = &original_dcid,
            .versions = &offered,
        });
        const followup_scid = @as([8]u8, @splat(0x99));
        if (restart) {
            try std.testing.expectError(error.ConnectionClosed, client.processVersionNegotiationRestartWithRoutePath(
                deadline,
                &hs.scratch,
                writer.getWritten(),
                124,
                followup_scid,
                .{},
                .{ .alpn = &alpn, .skip_cert_verify = true },
            ));
        } else {
            try std.testing.expectError(error.ConnectionClosed, client.processVersionNegotiationFollowupRoute(
                deadline,
                writer.getWritten(),
                124,
                &followup_scid,
                .{},
            ));
        }
        try std.testing.expectEqual(.closed, client.transport.connection.connectionState());
        try std.testing.expectEqual(@as(usize, 0), client.transport.undecryptable_count);
        // The existing VN error path leaves the route registered for caller cleanup.
        _ = try client.lifecycle.currentRoutePath(&client_scid);
    }
}

test "client reordering endpoint accepted VN discards the superseded flight" {
    var hs = try Handshake.init(.v1);
    defer hs.deinit();
    var client = try initEndpoint();
    defer client.deinit();
    try startEndpoint(&hs, &client);
    var encoded: [64]u8 = undefined;
    var writer = buffer.fixedWriter(&encoded);
    const offered = [_]packet.Version{.v2};
    try packet.encodeVersionNegotiationPacket(writer.writer(), .{
        .dcid = &client_scid,
        .scid = &original_dcid,
        .versions = &offered,
    });
    const followup_scid = @as([8]u8, @splat(0x99));
    const received = try client.processVersionNegotiationFollowupRoute(5, writer.getWritten(), 124, &followup_scid, .{});
    try std.testing.expect(received != null);
    try std.testing.expectEqual(.active, client.transport.connection.connectionState());
    try std.testing.expectEqual(@as(?packet.Version, .v2), client.transport.connection.version_negotiation_selected_version);
    try std.testing.expectEqual(@as(usize, 0), client.transport.undecryptable_count);
    try std.testing.expectError(error.UnknownConnectionId, client.lifecycle.currentRoutePath(&client_scid));
    _ = try client.lifecycle.currentRoutePath(&followup_scid);
}

test "client reordering endpoint accepted VN cleans up before route error" {
    var hs = try Handshake.init(.v1);
    defer hs.deinit();
    var client = try initEndpoint();
    defer client.deinit();
    try startEndpoint(&hs, &client);
    var encoded: [64]u8 = undefined;
    var writer = buffer.fixedWriter(&encoded);
    const offered = [_]packet.Version{.v2};
    try packet.encodeVersionNegotiationPacket(writer.writer(), .{
        .dcid = &client_scid,
        .scid = &original_dcid,
        .versions = &offered,
    });
    const oversized_cid = @as([21]u8, @splat(0x99));
    try std.testing.expectError(error.InvalidConnectionIdLength, client.processVersionNegotiationFollowupRoute(
        5,
        writer.getWritten(),
        124,
        &oversized_cid,
        .{},
    ));
    try std.testing.expectEqual(.active, client.transport.connection.connectionState());
    try std.testing.expectEqual(@as(?packet.Version, .v2), client.transport.connection.version_negotiation_selected_version);
    try std.testing.expectEqual(@as(usize, 0), client.transport.undecryptable_count);
    _ = try client.lifecycle.currentRoutePath(&client_scid);
}

test "client reordering fresh VN attempt keeps packets despite negotiation history" {
    var previous = try Handshake.init(.v2);
    defer previous.deinit();
    try previous.start();
    var encoded: [64]u8 = undefined;
    var writer = buffer.fixedWriter(&encoded);
    const offered = [_]packet.Version{.v1};
    try packet.encodeVersionNegotiationPacket(writer.writer(), .{
        .dcid = &client_scid,
        .scid = &original_dcid,
        .versions = &offered,
    });
    _ = try previous.client.receive(4, &previous.scratch, writer.getWritten());
    const config = try previous.client.versionNegotiationFollowupConfig();
    var fresh = try Handshake.init(.v1);
    defer fresh.deinit();
    const replacement = try Tls13ClientTransport.init(allocator, config, .{
        .alpn = &alpn,
        .skip_cert_verify = true,
    }, original_dcid, client_scid);
    fresh.client.deinit();
    fresh.client = replacement;
    try fresh.start();
    _ = try fresh.client.receive(4, &fresh.scratch, fresh.handshake.?);
    fresh.client.discardObsoletePackets();
    try std.testing.expectEqual(@as(?packet.Version, .v1), fresh.client.connection.version_negotiation_selected_version);
    try std.testing.expectEqual(@as(usize, 1), fresh.client.undecryptable_count);
}
