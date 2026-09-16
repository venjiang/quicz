//! Opt-in, authenticated IPv4 peer discovery. Existing strict checks are unchanged.
const std = @import("std");
const strict = @import("punch_driver.zig");
const PunchAttempt = @import("punch_attempt.zig").PunchAttempt;
const Diagnostics = @import("punch_attempt.zig").Diagnostics;
const wire = @import("punch_wire.zig");
const Candidate = @import("candidate.zig").Candidate;
const Address = std.Io.net.IpAddress;

/// Borrow one IPv4 socket exclusively until one endpoint proves both directions.
/// The returned endpoint and updated nonce must be used for runtime handoff.
/// At most one authenticated extra endpoint is checked; it cannot renew the
/// original absolute deadline or consume another attempt's state.
pub fn runUntilValidated(io: std.Io, socket: std.Io.net.Socket, remote: Address, attempt: *PunchAttempt) !Address {
    if (remote != .ip4 or socket.address != .ip4 or attempt.state != .probing or attempt.probes_sent != 0 or
        attempt.peer_probe_received or attempt.local_probe_acknowledged) return error.InvalidAttempt;
    _ = try Candidate.init(1, .server_reflexive, .{ .ipv4 = .{ .address = remote.ip4.bytes, .port = remote.ip4.port } }, 1);
    const Pair = struct { endpoint: Address, punch: PunchAttempt, started_ms: u64 };
    var pairs: [2]Pair = undefined;
    pairs[0] = .{ .endpoint = remote, .punch = try PunchAttempt.init(attempt.key, attempt.attempt_id, attempt.local_nonce, attempt.config), .started_ms = 0 };
    var count: usize = 1;
    var winner: ?usize = null;
    var expired = false;
    var socket_counts: Diagnostics = .{};
    defer {
        attempt.* = pairs[winner orelse 0].punch;
        if (expired) attempt.state = .failed;
        attempt.diagnostics = socket_counts;
        for (pairs[0..count]) |pair| {
            inline for (std.meta.fields(Diagnostics)) |field| {
                @field(attempt.diagnostics, field.name) +|= @field(pair.punch.diagnostics, field.name);
            }
        }
    }
    var budget_ms: u64 = 0;
    for (0..attempt.config.max_attempts) |index| {
        const scaled = @as(u64, attempt.config.initial_retry_ms) << @intCast(index);
        budget_ms += @min(scaled, attempt.config.maximum_retry_ms);
    }
    const started = std.Io.Timestamp.now(io, .awake);
    var buffer: [256]u8 = undefined;
    while (true) {
        const now_ms: u64 = @intCast(@max(0, started.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds()));
        if (now_ms >= budget_ms) {
            expired = true;
            return error.PunchFailed;
        }
        var wake_ms = budget_ms;
        for (pairs[0..count]) |*pair| {
            if (pair.punch.nextProbe(now_ms - pair.started_ms)) |probe| {
                try socket.send(io, &pair.endpoint, &probe);
                pair.punch.diagnostics.probe_sends +|= 1;
            }
            if (pair.punch.state == .probing) wake_ms = @min(wake_ms, pair.started_ms + pair.punch.next_probe_ms);
        }
        const packet = socket.receiveTimeout(io, &buffer, .{ .deadline = .{
            .raw = started.addDuration(.fromMilliseconds(@intCast(wake_ms))),
            .clock = .awake,
        } }) catch |err| switch (err) {
            error.Timeout => continue,
            error.MessageOversize => {
                socket_counts.oversized_received +|= 1;
                continue;
            },
            else => return err,
        };
        socket_counts.datagrams_received +|= 1;
        if (started.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds() >= budget_ms) {
            expired = true;
            return error.PunchFailed;
        }
        var source: ?usize = null;
        for (pairs[0..count], 0..) |pair, index| {
            if (sameIPv4(pair.endpoint, packet.from)) {
                source = index;
                break;
            }
        }
        if (source == null) {
            if (count == pairs.len or packet.from != .ip4) {
                socket_counts.source_rejected +|= 1;
                continue;
            }
            _ = Candidate.init(2, .peer_reflexive, .{ .ipv4 = .{ .address = packet.from.ip4.bytes, .port = packet.from.ip4.port } }, 1) catch {
                socket_counts.source_rejected +|= 1;
                continue;
            };
        }
        const message = wire.decode(attempt.key, packet.data) catch |err| {
            socket_counts.packets_checked +|= 1;
            if (err == error.AuthenticationFailed) socket_counts.authentication_rejected +|= 1 else socket_counts.malformed_rejected +|= 1;
            continue;
        };
        if (!std.mem.eql(u8, &message.attempt_id, &attempt.attempt_id)) {
            socket_counts.packets_checked +|= 1;
            socket_counts.attempt_rejected +|= 1;
            continue;
        }
        if (message.kind == .probe) {
            var reflected = false;
            for (pairs[0..count]) |pair| {
                reflected = reflected or std.mem.eql(u8, &message.nonce, &pair.punch.local_nonce);
            }
            if (reflected) {
                socket_counts.packets_checked +|= 1;
                socket_counts.nonce_rejected +|= 1;
                continue;
            }
        }
        if (source == null) {
            if (message.kind != .probe) {
                socket_counts.packets_checked +|= 1;
                socket_counts.nonce_rejected +|= 1;
                continue;
            }
            var nonce: wire.Nonce = undefined;
            var unique = false;
            for (0..4) |_| {
                try io.randomSecure(&nonce);
                if (!std.mem.eql(u8, &nonce, &attempt.local_nonce) and !std.mem.eql(u8, &nonce, &message.nonce)) {
                    unique = true;
                    break;
                }
            }
            if (!unique) return error.NonceGenerationFailed;
            source = count;
            pairs[count] = .{ .endpoint = packet.from, .punch = try PunchAttempt.init(attempt.key, attempt.attempt_id, nonce, attempt.config), .started_ms = @intCast(@max(0, started.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds())) };
            count += 1;
        }
        const pair = &pairs[source.?];
        const received = pair.punch.receive(packet.data) catch continue;
        if (received.acknowledgement) |ack| {
            try socket.send(io, &pair.endpoint, &ack);
            pair.punch.diagnostics.acknowledgement_sends +|= 1;
        }
        if (pair.punch.state == .validated) {
            winner = source;
            return pair.endpoint;
        }
    }
}

fn sameIPv4(left: Address, right: Address) bool {
    return left == .ip4 and right == .ip4 and left.ip4.port == right.ip4.port and
        std.mem.eql(u8, &left.ip4.bytes, &right.ip4.bytes);
}

const TestCheck = struct {
    io: std.Io,
    socket: std.Io.net.Socket,
    remote: Address,
    attempt: PunchAttempt,
    learn: bool,
    selected: ?Address = null,
    failure: ?anyerror = null,

    fn run(self: *TestCheck) void {
        if (self.learn) {
            self.selected = runUntilValidated(self.io, self.socket, self.remote, &self.attempt) catch |err| {
                self.failure = err;
                return;
            };
        } else {
            strict.runUntilValidated(self.io, self.socket, self.remote, &self.attempt) catch |err| {
                self.failure = err;
            };
        }
    }
};

test "peer learning validates original and authenticated changed IPv4 endpoints" {
    for ([_]bool{ false, true }) |changed| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();
        const address = Address{ .ip4 = .loopback(0) };
        const host = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
        defer host.close(io);
        const peer = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
        defer peer.close(io);
        const advertised = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
        defer advertised.close(io);
        const config = @import("punch_attempt.zig").Config{ .initial_retry_ms = 50, .maximum_retry_ms = 50, .max_attempts = 5 };
        var first = TestCheck{ .io = io, .socket = host, .remote = if (changed) advertised.address else peer.address, .attempt = try PunchAttempt.init(@splat(0x42), @splat(0x11), @splat(0xa1), config), .learn = true };
        var second = TestCheck{ .io = io, .socket = peer, .remote = host.address, .attempt = try PunchAttempt.init(@splat(0x42), @splat(0x11), @splat(0xb2), config), .learn = false };
        var first_task = try io.concurrent(TestCheck.run, .{&first});
        defer first_task.cancel(io);
        var second_task = try io.concurrent(TestCheck.run, .{&second});
        defer second_task.cancel(io);
        first_task.await(io);
        second_task.await(io);
        try std.testing.expectEqual(@as(?anyerror, null), first.failure);
        try std.testing.expectEqual(@as(?anyerror, null), second.failure);
        try std.testing.expectEqual(peer.address.ip4.port, first.selected.?.ip4.port);
        try std.testing.expectEqual(.validated, first.attempt.state);
        try std.testing.expectEqual(.validated, second.attempt.state);
        try std.testing.expectEqual(!changed, std.mem.eql(u8, &first.attempt.local_nonce, &@as([16]u8, @splat(0xa1))));
    }
}

test "peer learning ignores unauthenticated unrelated reflected and ACK-only sources" {
    for (0..5) |invalid| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();
        const address = Address{ .ip4 = .loopback(0) };
        const host = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
        defer host.close(io);
        const advertised = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
        defer advertised.close(io);
        const sender = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
        defer sender.close(io);
        var check = TestCheck{ .io = io, .socket = host, .remote = advertised.address, .attempt = try PunchAttempt.init(@splat(0x42), @splat(0x11), @splat(0xa1), .{
            .initial_retry_ms = 200,
            .maximum_retry_ms = 200,
            .max_attempts = 1,
        }), .learn = true };
        var task = try io.concurrent(TestCheck.run, .{&check});
        defer task.cancel(io);
        var buffer: [256]u8 = undefined;
        _ = try advertised.receiveTimeout(io, &buffer, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
        const message = wire.Message{ .kind = if (invalid == 3) .acknowledgement else .probe, .attempt_id = if (invalid == 1) @splat(0x12) else @splat(0x11), .nonce = if (invalid == 2 or invalid == 3) @splat(0xa1) else @splat(0xb2) };
        const packet = wire.encode(if (invalid == 0) @splat(0x43) else @splat(0x42), message);
        try sender.send(io, &host.address, if (invalid == 4) packet[0..59] else &packet);
        task.await(io);
        try std.testing.expectEqual(@as(?anyerror, error.PunchFailed), check.failure);
        try std.testing.expect(check.selected == null);
        try std.testing.expectEqual(@as(u32, 1), check.attempt.diagnostics.probe_sends);
        try std.testing.expectEqual(@as(u32, 0), check.attempt.diagnostics.acknowledgement_sends);
        try std.testing.expect(!check.attempt.peer_probe_received and !check.attempt.local_probe_acknowledged);
    }
}

test "peer learning cannot combine sources or reuse the original challenge" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const address = Address{ .ip4 = .loopback(0) };
    const host = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer host.close(io);
    const advertised = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer advertised.close(io);
    const learned = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer learned.close(io);
    const third = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer third.close(io);
    var check = TestCheck{ .io = io, .socket = host, .remote = advertised.address, .attempt = try PunchAttempt.init(@splat(0x42), @splat(0x11), @splat(0xa1), .{
        .initial_retry_ms = 200,
        .maximum_retry_ms = 200,
        .max_attempts = 3,
    }), .learn = true };
    var task = try io.concurrent(TestCheck.run, .{&check});
    defer task.cancel(io);
    var buffer: [256]u8 = undefined;
    _ = try advertised.receiveTimeout(io, &buffer, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    const probe = wire.encode(@splat(0x42), .{ .kind = .probe, .attempt_id = @splat(0x11), .nonce = @splat(0xb2) });
    try learned.send(io, &host.address, &probe);
    var challenge: ?wire.Nonce = null;
    for (0..2) |_| {
        const packet = try learned.receiveTimeout(io, &buffer, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
        const message = try wire.decode(@splat(0x42), packet.data);
        if (message.kind == .probe) challenge = message.nonce;
    }
    try std.testing.expect(challenge != null);
    try std.testing.expect(!std.mem.eql(u8, &challenge.?, &@as([16]u8, @splat(0xa1))));
    const stale_ack = wire.encode(@splat(0x42), .{ .kind = .acknowledgement, .attempt_id = @splat(0x11), .nonce = @splat(0xa1) });
    try learned.send(io, &host.address, &stale_ack);
    const cross_source_ack = wire.encode(@splat(0x42), .{ .kind = .acknowledgement, .attempt_id = @splat(0x11), .nonce = challenge.? });
    try third.send(io, &host.address, &cross_source_ack);
    const reflected_learned_probe = wire.encode(@splat(0x42), .{ .kind = .probe, .attempt_id = @splat(0x11), .nonce = challenge.? });
    try advertised.send(io, &host.address, &reflected_learned_probe);
    const reflected_original_probe = wire.encode(@splat(0x42), .{ .kind = .probe, .attempt_id = @splat(0x11), .nonce = @splat(0xa1) });
    try learned.send(io, &host.address, &reflected_original_probe);
    task.await(io);
    try std.testing.expectEqual(@as(?anyerror, error.PunchFailed), check.failure);
    try std.testing.expect(check.selected == null);
    try std.testing.expectEqual(@as(u32, 3), check.attempt.diagnostics.nonce_rejected);
    try std.testing.expectEqual(@as(u32, 1), check.attempt.diagnostics.source_rejected);
    try std.testing.expectEqual(@as(u32, 1), check.attempt.diagnostics.acknowledgement_sends);
    try std.testing.expect(!check.attempt.peer_probe_received);
    try std.testing.expect(check.attempt.diagnostics.probe_sends <= 6);
}

test "peer learning has an absolute deadline and propagates cancellation" {
    for ([_]bool{ false, true }) |cancel| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();
        const address = Address{ .ip4 = .loopback(0) };
        const host = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
        defer host.close(io);
        const advertised = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
        defer advertised.close(io);
        const learned = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
        defer learned.close(io);
        var check = TestCheck{ .io = io, .socket = host, .remote = advertised.address, .attempt = try PunchAttempt.init(@splat(0x42), @splat(0x11), @splat(0xa1), .{
            .initial_retry_ms = 400,
            .maximum_retry_ms = 400,
            .max_attempts = 1,
        }), .learn = true };
        const started = std.Io.Timestamp.now(io, .awake);
        var task = try io.concurrent(TestCheck.run, .{&check});
        defer task.cancel(io);
        var buffer: [256]u8 = undefined;
        _ = try advertised.receiveTimeout(io, &buffer, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
        if (cancel) {
            task.cancel(io);
            try std.testing.expectEqual(@as(?anyerror, error.Canceled), check.failure);
            try host.send(io, &advertised.address, "borrowed-socket-open");
            const retained = try advertised.receiveTimeout(io, &buffer, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
            try std.testing.expectEqualStrings("borrowed-socket-open", retained.data);
        } else {
            try std.Io.sleep(io, .fromMilliseconds(250), .awake);
            const probe = wire.encode(@splat(0x42), .{ .kind = .probe, .attempt_id = @splat(0x11), .nonce = @splat(0xb2) });
            try learned.send(io, &host.address, &probe);
            task.await(io);
            try std.testing.expectEqual(@as(?anyerror, error.PunchFailed), check.failure);
            try std.testing.expectEqual(@as(u32, 2), check.attempt.diagnostics.probe_sends);
        }
        try std.testing.expect(started.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds() < 550);
    }
}

test "peer learning preserves the original path while a learned pair remains incomplete" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const address = Address{ .ip4 = .loopback(0) };
    const host = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer host.close(io);
    const original = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer original.close(io);
    const learned = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer learned.close(io);
    const config = @import("punch_attempt.zig").Config{ .initial_retry_ms = 200, .maximum_retry_ms = 200, .max_attempts = 3 };
    var first = TestCheck{ .io = io, .socket = host, .remote = original.address, .attempt = try PunchAttempt.init(@splat(0x42), @splat(0x11), @splat(0xa1), config), .learn = true };
    var first_task = try io.concurrent(TestCheck.run, .{&first});
    defer first_task.cancel(io);
    const probe = wire.encode(@splat(0x42), .{ .kind = .probe, .attempt_id = @splat(0x11), .nonce = @splat(0xc3) });
    try learned.send(io, &host.address, &probe);
    var buffer: [256]u8 = undefined;
    _ = try learned.receiveTimeout(io, &buffer, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    var second = TestCheck{ .io = io, .socket = original, .remote = host.address, .attempt = try PunchAttempt.init(@splat(0x42), @splat(0x11), @splat(0xb2), config), .learn = false };
    var second_task = try io.concurrent(TestCheck.run, .{&second});
    defer second_task.cancel(io);
    first_task.await(io);
    second_task.await(io);
    try std.testing.expectEqual(@as(?anyerror, null), first.failure);
    try std.testing.expectEqual(@as(?anyerror, null), second.failure);
    try std.testing.expectEqual(original.address.ip4.port, first.selected.?.ip4.port);
    try std.testing.expectEqual(@as([16]u8, @splat(0xa1)), first.attempt.local_nonce);
}

test "peer learning rejects unusable destinations before sending" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const address = Address{ .ip4 = .loopback(0) };
    const socket = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    var punch = try PunchAttempt.init(@splat(0x42), @splat(0x11), @splat(0xa1), .{});
    try std.testing.expectError(error.InvalidCandidate, runUntilValidated(io, socket, address, &punch));
    try std.testing.expectEqual(@as(u32, 0), punch.diagnostics.probe_sends);
}
