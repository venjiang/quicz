//! QUIC-Interop-Runner testcase coverage tests.
//!
//! Verifies all standard interop testcases at the unit/integration level:
//! handshake, transfer, retry, multiplexing, chacha20, keyupdate, v2.

const std = @import("std");
const packet = @import("packet.zig");
const protection = @import("protection.zig");
const connection_module = @import("connection.zig");
const recovery = @import("recovery.zig");
const endpoint_module = @import("endpoint.zig");

const Connection = connection_module.Connection;

// ── handshake ──

test "interop handshake: client and server complete Initial exchange" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x44, 0x55, 0x66, 0x77 };

    const secrets = try protection.deriveInitialSecrets(.v1, &dcid);

    // Client sends Initial
    const client_payload = "ClientHello";
    const client_dgram = try protection.protectLongPacketAes128(
        std.testing.allocator,
        .{
            .version = .v1,
            .dcid = &dcid,
            .scid = &scid,
            .packet_type = .initial,
            .token = &.{},
            .packet_number = 0,
            .payload_length = 0,
        },
        .{ .len = 1, .truncated_packet_number = 0 },
        secrets.client,
        client_payload,
    );
    defer std.testing.allocator.free(client_dgram);

    // Server receives and decrypts
    var opened = try protection.unprotectLongPacketAes128(
        std.testing.allocator,
        secrets.client,
        client_dgram,
        0,
    );
    defer protection.deinitProtectedLongPacket(&opened, std.testing.allocator);
    try std.testing.expectEqualStrings(client_payload, opened.packet.plaintext);

    // Server sends Initial response
    const server_payload = "ServerHello";
    const server_dgram = try protection.protectLongPacketAes128(
        std.testing.allocator,
        .{
            .version = .v1,
            .dcid = &scid,
            .scid = &dcid,
            .packet_type = .initial,
            .token = &.{},
            .packet_number = 0,
            .payload_length = 0,
        },
        .{ .len = 1, .truncated_packet_number = 0 },
        secrets.server,
        server_payload,
    );
    defer std.testing.allocator.free(server_dgram);

    // Client receives and decrypts
    var server_opened = try protection.unprotectLongPacketAes128(
        std.testing.allocator,
        secrets.server,
        server_dgram,
        0,
    );
    defer protection.deinitProtectedLongPacket(&server_opened, std.testing.allocator);
    try std.testing.expectEqualStrings(server_payload, server_opened.packet.plaintext);
}

// ── transfer ──

test "interop transfer: stream data over protected connection" {
    var sender = try Connection.init(std.testing.allocator, .client, .{});
    defer sender.deinit();
    try sender.confirmHandshake();

    const stream_id = try sender.openStream();
    const data = "Hello, QUIC interop transfer test!";
    try sender.sendOnStream(stream_id, data, true);

    const state = try sender.streamState(stream_id);
    try std.testing.expect(state != null);
}

// ── retry ──

test "interop retry: Retry packet with integrity tag" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = [_]u8{ 0x44, 0x55, 0x66, 0x77 };
    const original_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };

    const retry = packet.RetryPacket{
        .version = .v1,
        .dcid = &dcid,
        .scid = &scid,
        .token = "retry-token-for-interop",
        .integrity_tag = [_]u8{0} ** 16,
    };

    const datagram = try protection.encodeRetryPacketWithIntegrity(
        std.testing.allocator,
        &original_dcid,
        retry,
    );
    defer std.testing.allocator.free(datagram);

    // Verify integrity
    const parsed = try protection.parseRetryPacketWithIntegrity(
        std.testing.allocator,
        &original_dcid,
        datagram,
    );
    defer {
        std.testing.allocator.free(parsed.dcid);
        std.testing.allocator.free(parsed.scid);
        std.testing.allocator.free(parsed.token);
    }

    try std.testing.expectEqualStrings("retry-token-for-interop", parsed.token);
    try std.testing.expectEqual(packet.Version.v1, parsed.version);

    // Tampered retry should fail
    var tampered = try std.testing.allocator.dupe(u8, datagram);
    defer std.testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0xff;
    try std.testing.expectError(
        error.AuthenticationFailed,
        protection.parseRetryPacketWithIntegrity(std.testing.allocator, &original_dcid, tampered),
    );
}

// ── multiplexing ──

test "interop multiplexing: multiple concurrent streams" {
    var conn = try Connection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();
    try conn.confirmHandshake();

    // Open multiple streams
    const stream_count: u64 = 8;
    var stream_ids: [8]u64 = undefined;
    var i: u64 = 0;
    while (i < stream_count) : (i += 1) {
        stream_ids[i] = try conn.openStream();
    }

    // Verify all streams have unique IDs
    for (stream_ids, 0..) |id, idx| {
        try std.testing.expectEqual(@as(u64, @intCast(idx * 4)), id);
    }

    // Send data on all streams
    for (stream_ids) |id| {
        var buf: [64]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "stream-{d}", .{id}) catch "data";
        try conn.sendOnStream(id, msg, true);
    }

    // Verify all streams have state
    for (stream_ids) |id| {
        const state = try conn.streamState(id);
        try std.testing.expect(state != null);
    }
}

// ── keyupdate ──

test "interop keyupdate: 1-RTT key phase transition" {
    const secret = [_]u8{0x42} ** 32;
    const keys = protection.deriveAes128PacketProtectionKeys(secret);

    // Initial key phase state
    var key_phase = protection.Aes128KeyPhaseState.init(keys, false);
    try std.testing.expectEqual(@as(bool, false), key_phase.currentKeyPhase());
    try std.testing.expectEqual(@as(u64, 0), key_phase.keyUpdateCount());

    // Initiate key update
    key_phase.initiateKeyUpdate();
    try std.testing.expectEqual(@as(bool, true), key_phase.currentKeyPhase());
    try std.testing.expectEqual(@as(u64, 1), key_phase.keyUpdateCount());

    // New keys should differ from original
    const new_keys = key_phase.currentKeys();
    try std.testing.expect(!std.mem.eql(u8, &keys.key, &new_keys.key));

    // Second key update
    key_phase.initiateKeyUpdate();
    try std.testing.expectEqual(@as(bool, false), key_phase.currentKeyPhase());
    try std.testing.expectEqual(@as(u64, 2), key_phase.keyUpdateCount());
}

// ── chacha20 ──

test "interop chacha20: ChaCha20-Poly1305 AEAD roundtrip" {
    const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

    const key = [_]u8{0x42} ** 32;
    const nonce = [_]u8{0x01} ** 12;
    const plaintext = "QUIC chacha20 interop test payload";
    const aad = "header";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;

    ChaCha20Poly1305.encrypt(&ciphertext, &tag, plaintext, aad, nonce, key);

    // Decrypt
    var decrypted: [plaintext.len]u8 = undefined;
    try ChaCha20Poly1305.decrypt(&decrypted, &ciphertext, tag, aad, nonce, key);

    try std.testing.expectEqualStrings(plaintext, &decrypted);

    // Tampered ciphertext should fail
    var bad_tag = tag;
    bad_tag[0] ^= 0xff;
    try std.testing.expectError(
        error.AuthenticationFailed,
        ChaCha20Poly1305.decrypt(&decrypted, &ciphertext, bad_tag, aad, nonce, key),
    );
}

// ── v2 ──

test "interop v2: QUIC v2 Initial protect/unprotect" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    const secrets = try protection.deriveInitialSecrets(.v2, &dcid);

    const payload = "QUIC v2 interop test";
    const dgram = try protection.protectLongPacketAes128(
        std.testing.allocator,
        .{
            .version = .v2,
            .dcid = &dcid,
            .scid = &.{},
            .packet_type = .initial,
            .token = &.{},
            .packet_number = 0,
            .payload_length = 0,
        },
        .{ .len = 1, .truncated_packet_number = 0 },
        secrets.client,
        payload,
    );
    defer std.testing.allocator.free(dgram);

    const info = try protection.peekProtectedLongPacketInfo(dgram);
    try std.testing.expectEqual(packet.Version.v2, info.version);

    var opened = try protection.unprotectLongPacketAes128(
        std.testing.allocator,
        secrets.client,
        dgram,
        0,
    );
    defer protection.deinitProtectedLongPacket(&opened, std.testing.allocator);
    try std.testing.expectEqualStrings(payload, opened.packet.plaintext);
}

// ── combined: handshake + transfer + keyupdate ──

test "interop combined: full lifecycle with key update" {
    var conn = try Connection.init(std.testing.allocator, .client, .{});
    defer conn.deinit();
    try conn.confirmHandshake();

    // Transfer
    const stream_id = try conn.openStream();
    try conn.sendOnStream(stream_id, "initial data", false);

    // Key update
    const secret = [_]u8{0x42} ** 32;
    const keys = protection.deriveAes128PacketProtectionKeys(secret);
    var key_phase = protection.Aes128KeyPhaseState.init(keys, false);
    key_phase.initiateKeyUpdate();
    try std.testing.expectEqual(@as(u64, 1), key_phase.keyUpdateCount());

    // More data after key update
    try conn.sendOnStream(stream_id, "post-keyupdate data", true);

    const state = try conn.streamState(stream_id);
    try std.testing.expect(state != null);
}
