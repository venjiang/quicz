//! Bounded RFC 8489 Binding transaction on a caller-owned UDP socket.

const std = @import("std");
const stun = @import("stun.zig");

pub const Config = struct {
    timeout_ms: u32 = 500,
    max_attempts: u8 = 3,
    max_ignored_datagrams_per_attempt: u8 = 8,
};

pub fn discover(
    io: std.Io,
    socket: *std.Io.net.Socket,
    stun_server: std.Io.net.IpAddress,
    config: Config,
) !stun.MappedAddress {
    if (config.timeout_ms == 0 or config.max_attempts == 0 or config.max_attempts > 5) {
        return error.InvalidTransactionConfig;
    }

    var transaction_id: stun.TransactionId = undefined;
    try io.randomSecure(&transaction_id);
    const request = stun.encodeBindingRequest(transaction_id);
    var receive_buffer: [2048]u8 = undefined;

    var attempt: u8 = 0;
    while (attempt < config.max_attempts) : (attempt += 1) {
        try socket.send(io, &stun_server, &request);
        var ignored: u8 = 0;
        while (ignored <= config.max_ignored_datagrams_per_attempt) : (ignored += 1) {
            const received = socket.receiveTimeout(io, &receive_buffer, .{ .duration = .{
                .clock = .awake,
                .raw = std.Io.Duration.fromMilliseconds(config.timeout_ms),
            } }) catch break;
            if (!sameAddress(received.from, stun_server)) continue;
            const mapped = stun.decodeBindingSuccess(received.data, transaction_id) catch continue;
            return mapped;
        }
    }
    return error.StunUnavailable;
}

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

test "rejects unbounded transaction configuration" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var socket = try bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    try std.testing.expectError(
        error.InvalidTransactionConfig,
        discover(io, &socket, bind_address, .{ .max_attempts = 6 }),
    );
}
