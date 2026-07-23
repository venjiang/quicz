//! QUIC v2 / RFC 9368-9369 integration tests.
//!
//! Verifies complete QUIC v2 support: v2 Initial key derivation,
//! v2 packet protection, v2 connection lifecycle, and
//! RFC 9368 compatible version negotiation.

const std = @import("std");
const packet = @import("packet.zig");
const protection = @import("protection.zig");
const connection_module = @import("connection.zig");
const connection_version = @import("connection_version.zig");
const transport_parameters = @import("transport_parameters.zig");

const Connection = connection_module.Connection;

test "QUIC v2: Initial secrets use v2 salt and labels" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    const v1_secrets = try protection.deriveInitialSecrets(.v1, &dcid);
    const v2_secrets = try protection.deriveInitialSecrets(.v2, &dcid);

    // v1 and v2 must produce different Initial secrets (different salts)
    try std.testing.expect(!std.mem.eql(u8, &v1_secrets.initial_secret, &v2_secrets.initial_secret));

    // v1 and v2 must produce different client keys (different labels)
    try std.testing.expect(!std.mem.eql(u8, &v1_secrets.client.key, &v2_secrets.client.key));
    try std.testing.expect(!std.mem.eql(u8, &v1_secrets.client.iv, &v2_secrets.client.iv));
    try std.testing.expect(!std.mem.eql(u8, &v1_secrets.client.hp, &v2_secrets.client.hp));

    // v1 and v2 must produce different server keys
    try std.testing.expect(!std.mem.eql(u8, &v1_secrets.server.key, &v2_secrets.server.key));
}

test "QUIC v2: protect and unprotect Initial packet roundtrip" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x44, 0x55, 0x66, 0x77 };

    const secrets = try protection.deriveInitialSecrets(.v2, &dcid);

    const payload = "QUIC v2 test payload data";
    const header = packet.LongHeader{
        .version = .v2,
        .dcid = &dcid,
        .scid = &scid,
        .packet_type = .initial,
        .token = &.{},
        .packet_number = 0,
        .payload_length = 0,
    };

    const datagram = try protection.protectLongPacketAes128(
        std.testing.allocator,
        header,
        .{ .len = 1, .truncated_packet_number = 0 },
        secrets.client,
        payload,
    );
    defer std.testing.allocator.free(datagram);

    try std.testing.expect(datagram.len > 0);
    try std.testing.expect(datagram[0] & 0x80 != 0); // long header

    const info = try protection.peekProtectedLongPacketInfo(datagram);
    try std.testing.expectEqual(packet.Version.v2, info.version);

    var opened = try protection.unprotectLongPacketAes128(
        std.testing.allocator,
        secrets.client,
        datagram,
        0,
    );
    defer protection.deinitProtectedLongPacket(&opened, std.testing.allocator);

    try std.testing.expectEqual(packet.Version.v2, opened.packet.header.version);
    try std.testing.expectEqualStrings(payload, opened.packet.plaintext);
}

test "QUIC v2: Retry integrity tag with v2 keys" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x44, 0x55, 0x66, 0x77 };
    const retry_token = "v2-retry-token";

    const retry = packet.RetryPacket{
        .version = .v2,
        .dcid = &dcid,
        .scid = &scid,
        .token = retry_token,
        .integrity_tag = [_]u8{0} ** 16,
    };

    const datagram = try protection.encodeRetryPacketWithIntegrity(
        std.testing.allocator,
        &dcid, // original DCID
        retry,
    );
    defer std.testing.allocator.free(datagram);

    try std.testing.expect(datagram.len > 0);

    const parsed = try protection.parseRetryPacketWithIntegrity(
        std.testing.allocator,
        &dcid,
        datagram,
    );
    try std.testing.expectEqual(packet.Version.v2, parsed.version);
    try std.testing.expectEqualStrings(retry_token, parsed.token);

    // Free allocator-owned fields from parseRetryPacket
    std.testing.allocator.free(parsed.dcid);
    std.testing.allocator.free(parsed.scid);
    std.testing.allocator.free(parsed.token);
}

test "QUIC v2: version_information transport parameter" {
    const available = [_]packet.Version{ .v2, .v1 };
    const version_info = transport_parameters.VersionInformation{
        .chosen_version = .v2,
        .available_versions = &available,
    };

    try std.testing.expect(version_info.containsAvailableVersion(.v2));
    try std.testing.expect(version_info.containsAvailableVersion(.v1));
    try std.testing.expect(!version_info.containsAvailableVersion(@enumFromInt(0x00000003)));
}

test "QUIC v2: selectMutualVersion prefers v2 when both support it" {
    const preferred = [_]packet.Version{ .v2, .v1 };
    const offered = [_]packet.Version{ .v1, .v2 };

    const selected = connection_version.selectMutualVersion(&preferred, &offered);
    try std.testing.expect(selected != null);
    try std.testing.expectEqual(packet.Version.v2, selected.?);
}

test "QUIC v2: selectMutualVersion falls back to v1 when v2 not offered" {
    const preferred = [_]packet.Version{ .v2, .v1 };
    const offered = [_]packet.Version{ .v1 };

    const selected = connection_version.selectMutualVersion(&preferred, &offered);
    try std.testing.expect(selected != null);
    try std.testing.expectEqual(packet.Version.v1, selected.?);
}

test "QUIC v2: selectMutualVersion returns null when no common version" {
    const preferred = [_]packet.Version{ .v2 };
    const offered = [_]packet.Version{ .v1 };

    const selected = connection_version.selectMutualVersion(&preferred, &offered);
    try std.testing.expect(selected == null);
}

test "QUIC v2: connection init with v2 chosen_version" {
    const available = [_]packet.Version{ .v2, .v1 };
    var conn = try Connection.init(std.testing.allocator, .client, .{
        .chosen_version = .v2,
        .available_versions = &available,
    });
    defer conn.deinit();

    try std.testing.expectEqual(packet.Version.v2, conn.chosenVersion());
    try conn.confirmHandshake();
    try std.testing.expect(conn.handshakeConfirmed());
}

test "QUIC v2: stream data over v2 connection" {
    const available = [_]packet.Version{ .v2, .v1 };
    var sender = try Connection.init(std.testing.allocator, .client, .{
        .chosen_version = .v2,
        .available_versions = &available,
    });
    defer sender.deinit();
    try sender.confirmHandshake();

    const stream_id = try sender.openStream();
    try std.testing.expectEqual(@as(u64, 0), stream_id);

    const test_data = "Hello over QUIC v2!";
    try sender.sendOnStream(stream_id, test_data, true);

    const state = try sender.streamState(stream_id);
    try std.testing.expect(state != null);
}

test "QUIC v2: v1 and v2 protected datagrams differ" {
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    const v1 = try protection.deriveInitialSecrets(.v1, &dcid);
    const v2 = try protection.deriveInitialSecrets(.v2, &dcid);

    const header_v1 = packet.LongHeader{
        .version = .v1,
        .dcid = &dcid,
        .scid = &.{},
        .packet_type = .initial,
        .token = &.{},
        .packet_number = 0,
        .payload_length = 0,
    };
    const header_v2 = packet.LongHeader{
        .version = .v2,
        .dcid = &dcid,
        .scid = &.{},
        .packet_type = .initial,
        .token = &.{},
        .packet_number = 0,
        .payload_length = 0,
    };

    const dgram_v1 = try protection.protectLongPacketAes128(
        std.testing.allocator,
        header_v1,
        .{ .len = 1, .truncated_packet_number = 0 },
        v1.client,
        "test data",
    );
    defer std.testing.allocator.free(dgram_v1);

    const dgram_v2 = try protection.protectLongPacketAes128(
        std.testing.allocator,
        header_v2,
        .{ .len = 1, .truncated_packet_number = 0 },
        v2.client,
        "test data",
    );
    defer std.testing.allocator.free(dgram_v2);

    // The protected datagrams must differ (different keys and version field)
    try std.testing.expect(!std.mem.eql(u8, dgram_v1, dgram_v2));

    // Each can be unprotected with its own keys
    var opened_v1 = try protection.unprotectLongPacketAes128(
        std.testing.allocator,
        v1.client,
        dgram_v1,
        0,
    );
    defer protection.deinitProtectedLongPacket(&opened_v1, std.testing.allocator);
    try std.testing.expectEqualStrings("test data", opened_v1.packet.plaintext);

    var opened_v2 = try protection.unprotectLongPacketAes128(
        std.testing.allocator,
        v2.client,
        dgram_v2,
        0,
    );
    defer protection.deinitProtectedLongPacket(&opened_v2, std.testing.allocator);
    try std.testing.expectEqualStrings("test data", opened_v2.packet.plaintext);
}

test "QUIC v2: validateLocalVersionInformation accepts consistent v2 config" {
    const available = [_]packet.Version{ .v2, .v1 };
    try connection_version.validateLocalVersionInformation(.client, .{
        .chosen_version = .v2,
        .available_versions = &available,
    });
}

test "QUIC v2: validateLocalVersionInformation rejects v2 not in available" {
    const available = [_]packet.Version{ .v1 };
    try std.testing.expectError(
        error.InvalidPacket,
        connection_version.validateLocalVersionInformation(.client, .{
            .chosen_version = .v2,
            .available_versions = &available,
        }),
    );
}

test "QUIC v2: validateLocalVersionInformation with VN selected version" {
    const available = [_]packet.Version{ .v2, .v1 };
    try connection_version.validateLocalVersionInformation(.client, .{
        .chosen_version = .v2,
        .available_versions = &available,
        .version_negotiation_selected_version = .v2,
    });
}
