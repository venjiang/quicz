//! Authenticated probe responder retained by a QUIC runtime after local path
//! validation. It consumes all packets for this attempt and only answers peer
//! probes from the validated remote during a bounded handoff window.

const std = @import("std");
const wire = @import("punch_wire.zig");

pub const Action = union(enum) {
    not_punch,
    consumed,
    acknowledgement: [wire.packet_length]u8,
};

pub const PunchResponder = struct {
    key: wire.Key,
    attempt_id: wire.AttemptId,
    local_nonce: wire.Nonce,
    remote: std.Io.net.IpAddress,
    expires_at_nanos: i64,

    pub fn init(
        key: wire.Key,
        attempt_id: wire.AttemptId,
        local_nonce: wire.Nonce,
        remote: std.Io.net.IpAddress,
        now_nanos: i64,
        lifetime_ms: u32,
    ) !PunchResponder {
        if (lifetime_ms == 0 or remote.getPort() == 0) return error.InvalidResponder;
        const lifetime_nanos = std.math.mul(i64, lifetime_ms, 1_000_000) catch
            return error.InvalidResponder;
        return .{
            .key = key,
            .attempt_id = attempt_id,
            .local_nonce = local_nonce,
            .remote = remote,
            .expires_at_nanos = std.math.add(i64, now_nanos, lifetime_nanos) catch std.math.maxInt(i64),
        };
    }

    pub fn handle(
        responder: PunchResponder,
        from: std.Io.net.IpAddress,
        now_nanos: i64,
        packet: []const u8,
    ) Action {
        const message = wire.decode(responder.key, packet) catch return .not_punch;
        if (!std.mem.eql(u8, &message.attempt_id, &responder.attempt_id)) return .not_punch;
        if (message.kind == .acknowledgement) return .consumed;
        if (std.mem.eql(u8, &message.nonce, &responder.local_nonce) or
            !sameAddress(from, responder.remote) or now_nanos > responder.expires_at_nanos)
            return .consumed;
        return .{ .acknowledgement = wire.acknowledgement(responder.key, message) catch
            return .consumed };
    }

    pub fn deinit(responder: *PunchResponder) void {
        std.crypto.secureZero(u8, &responder.key);
        @memset(&responder.attempt_id, 0);
        @memset(&responder.local_nonce, 0);
        responder.expires_at_nanos = 0;
    }
};

fn sameAddress(lhs: std.Io.net.IpAddress, rhs: std.Io.net.IpAddress) bool {
    return switch (lhs) {
        .ip4 => |left| switch (rhs) {
            .ip4 => |right| left.port == right.port and std.mem.eql(u8, &left.bytes, &right.bytes),
            .ip6 => false,
        },
        .ip6 => |left| switch (rhs) {
            .ip4 => false,
            .ip6 => |right| left.port == right.port and std.mem.eql(u8, &left.bytes, &right.bytes),
        },
    };
}

test "responder consumes attempt packets and only answers bounded validated peer probes" {
    const key: wire.Key = .{0x42} ** 32;
    const remote = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 4_433 } };
    const responder = try PunchResponder.init(key, .{0x11} ** 16, .{0xa1} ** 16, remote, 1_000, 100);
    const peer_probe = wire.encode(key, .{
        .kind = .probe,
        .attempt_id = responder.attempt_id,
        .nonce = .{0xb2} ** 16,
    });
    const acknowledgement = responder.handle(remote, 2_000, &peer_probe).acknowledgement;
    const decoded = try wire.decode(key, &acknowledgement);
    try std.testing.expectEqual(wire.Kind.acknowledgement, decoded.kind);
    try std.testing.expectEqual(@as([16]u8, @splat(0xb2)), decoded.nonce);

    const peer_ack = wire.encode(key, .{
        .kind = .acknowledgement,
        .attempt_id = responder.attempt_id,
        .nonce = responder.local_nonce,
    });
    try std.testing.expectEqual(Action.consumed, responder.handle(remote, 2_000, &peer_ack));
    const other_remote = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 2 }, .port = 4_433 } };
    try std.testing.expectEqual(Action.consumed, responder.handle(other_remote, 2_000, &peer_probe));
    try std.testing.expectEqual(Action.consumed, responder.handle(remote, 101_001_001, &peer_probe));

    var tampered = peer_probe;
    tampered[12] ^= 1;
    try std.testing.expectEqual(Action.not_punch, responder.handle(remote, 2_000, &tampered));

    var cleared = responder;
    cleared.deinit();
    try std.testing.expect(std.mem.allEqual(u8, &cleared.key, 0));
    try std.testing.expect(std.mem.allEqual(u8, &cleared.attempt_id, 0));
    try std.testing.expect(std.mem.allEqual(u8, &cleared.local_nonce, 0));
}
