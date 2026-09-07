//! Authenticated UDP connectivity-check packets.
//!
//! The rendezvous control plane provides a short-lived shared key and attempt
//! identifier. Probe retransmission is idempotent; acknowledgements echo the
//! probe nonce. The fixed-size packet is intentionally distinct from STUN and
//! QUIC wire images so one UDP socket can demultiplex all three.

const std = @import("std");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const Key = [HmacSha256.key_length]u8;
pub const AttemptId = [16]u8;
pub const Nonce = [16]u8;
pub const tag_length = 16;
pub const packet_length = 60;

const magic = "qcz-p2p1";
const body_length = packet_length - tag_length;

pub const Kind = enum(u8) {
    probe = 1,
    acknowledgement = 2,
};

pub const Message = struct {
    kind: Kind,
    attempt_id: AttemptId,
    nonce: Nonce,
};

pub fn encode(key: Key, message: Message) [packet_length]u8 {
    var packet = [_]u8{0} ** packet_length;
    @memcpy(packet[0..magic.len], magic);
    packet[8] = @intFromEnum(message.kind);
    @memcpy(packet[12..28], &message.attempt_id);
    @memcpy(packet[28..44], &message.nonce);
    const tag = authenticate(key, packet[0..body_length]);
    @memcpy(packet[body_length..packet_length], &tag);
    return packet;
}

pub fn decode(key: Key, packet: []const u8) !Message {
    if (packet.len != packet_length) return error.InvalidPacketLength;
    if (!std.mem.eql(u8, packet[0..magic.len], magic)) return error.InvalidMagic;
    if (!std.mem.allEqual(u8, packet[9..12], 0)) return error.InvalidReservedBits;
    const kind: Kind = switch (packet[8]) {
        @intFromEnum(Kind.probe) => .probe,
        @intFromEnum(Kind.acknowledgement) => .acknowledgement,
        else => return error.InvalidMessageKind,
    };

    var received_tag: [tag_length]u8 = undefined;
    @memcpy(&received_tag, packet[body_length..packet_length]);
    const expected_tag = authenticate(key, packet[0..body_length]);
    if (!std.crypto.timing_safe.eql([tag_length]u8, expected_tag, received_tag)) {
        return error.AuthenticationFailed;
    }

    var attempt_id: AttemptId = undefined;
    @memcpy(&attempt_id, packet[12..28]);
    var nonce: Nonce = undefined;
    @memcpy(&nonce, packet[28..44]);
    return .{ .kind = kind, .attempt_id = attempt_id, .nonce = nonce };
}

pub fn acknowledgement(key: Key, probe: Message) ![packet_length]u8 {
    if (probe.kind != .probe) return error.NotProbe;
    return encode(key, .{
        .kind = .acknowledgement,
        .attempt_id = probe.attempt_id,
        .nonce = probe.nonce,
    });
}

fn authenticate(key: Key, body: []const u8) [tag_length]u8 {
    var full_tag: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&full_tag, body, &key);
    var tag: [tag_length]u8 = undefined;
    @memcpy(&tag, full_tag[0..tag_length]);
    return tag;
}

test "probe and acknowledgement authenticate the same connectivity attempt" {
    const key: Key = .{0x42} ** HmacSha256.key_length;
    const probe = Message{
        .kind = .probe,
        .attempt_id = .{0x11} ** 16,
        .nonce = .{0x22} ** 16,
    };
    const decoded_probe = try decode(key, &encode(key, probe));
    try std.testing.expectEqual(probe, decoded_probe);
    const decoded_ack = try decode(key, &try acknowledgement(key, decoded_probe));
    try std.testing.expectEqual(Kind.acknowledgement, decoded_ack.kind);
    try std.testing.expectEqual(probe.attempt_id, decoded_ack.attempt_id);
    try std.testing.expectEqual(probe.nonce, decoded_ack.nonce);
}

test "tampered probe is rejected before routing" {
    const key: Key = .{0x42} ** HmacSha256.key_length;
    var packet = encode(key, .{
        .kind = .probe,
        .attempt_id = .{0x11} ** 16,
        .nonce = .{0x22} ** 16,
    });
    packet[28] ^= 0x01;
    try std.testing.expectError(error.AuthenticationFailed, decode(key, &packet));
}

test "wrong attempt key cannot authenticate a probe" {
    const packet = encode(.{0x42} ** HmacSha256.key_length, .{
        .kind = .probe,
        .attempt_id = .{0x11} ** 16,
        .nonce = .{0x22} ** 16,
    });
    try std.testing.expectError(
        error.AuthenticationFailed,
        decode(.{0x43} ** HmacSha256.key_length, &packet),
    );
}
