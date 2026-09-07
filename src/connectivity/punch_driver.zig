//! Socket driver for one authenticated candidate-pair check.

const std = @import("std");
const punch_attempt = @import("punch_attempt.zig");

pub fn run(
    io: std.Io,
    socket: std.Io.net.Socket,
    remote: std.Io.net.IpAddress,
    attempt: *punch_attempt.PunchAttempt,
) !void {
    const started = std.Io.Timestamp.now(io, .awake);
    var receive_buffer: [256]u8 = undefined;
    var destination = remote;

    while (attempt.state == .probing) {
        const now_ms = elapsedMilliseconds(started, std.Io.Timestamp.now(io, .awake));
        if (attempt.nextProbe(now_ms)) |probe| try socket.send(io, &destination, &probe);
        if (attempt.state != .probing) break;

        const deadline = std.Io.Clock.Timestamp{
            .raw = started.addDuration(std.Io.Duration.fromMilliseconds(@intCast(@min(
                attempt.next_probe_ms,
                std.math.maxInt(i64),
            )))),
            .clock = .awake,
        };
        const received = socket.receiveTimeout(io, &receive_buffer, .{ .deadline = deadline }) catch continue;
        if (!sameAddress(received.from, remote)) continue;
        const result = attempt.receive(received.data) catch continue;
        if (result.acknowledgement) |acknowledgement| {
            try socket.send(io, &destination, &acknowledgement);
        }
    }

    if (attempt.state != .validated) return error.PunchFailed;
}

fn elapsedMilliseconds(started: std.Io.Timestamp, now: std.Io.Timestamp) u64 {
    const elapsed = started.durationTo(now).toMilliseconds();
    return if (elapsed <= 0) 0 else @intCast(elapsed);
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

test "elapsed milliseconds is monotonic and clamps negative input" {
    const started = std.Io.Timestamp{ .nanoseconds = 1_000_000 };
    const later = std.Io.Timestamp{ .nanoseconds = 3_500_000 };
    const earlier = std.Io.Timestamp{ .nanoseconds = 500_000 };
    try std.testing.expectEqual(@as(u64, 2), elapsedMilliseconds(started, later));
    try std.testing.expectEqual(@as(u64, 0), elapsedMilliseconds(started, earlier));
}
