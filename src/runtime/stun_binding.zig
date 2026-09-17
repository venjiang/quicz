//! A bounded STUN transaction whose packets are read by an existing UDP loop.
const std = @import("std");
const stun = @import("../connectivity/stun.zig");
const transaction = @import("../connectivity/stun_transaction.zig");

pub const Binding = struct {
    request_mutex: std.Io.Mutex = .init,
    state_mutex: std.atomic.Mutex = .unlocked,
    changed: std.atomic.Value(u32) = .init(0),
    pending: ?Pending = null,
    stopped: bool = false,

    const Pending = struct {
        server: std.Io.net.IpAddress,
        id: stun.TransactionId,
        mapped: ?stun.MappedAddress = null,
    };

    /// Serializes requests, but never reads or closes the caller's socket.
    pub fn discover(self: *Binding, io: std.Io, socket: *std.Io.net.Socket, server: std.Io.net.IpAddress, config: transaction.Config) !stun.MappedAddress {
        if (config.timeout_ms == 0 or config.max_attempts == 0 or config.max_attempts > 5)
            return error.InvalidTransactionConfig;
        try self.request_mutex.lock(io);
        defer self.request_mutex.unlock(io);
        var id: stun.TransactionId = undefined;
        try io.randomSecure(&id);
        self.lock();
        if (self.stopped) {
            self.state_mutex.unlock();
            return error.Canceled;
        }
        self.pending = .{ .server = server, .id = id };
        self.state_mutex.unlock();
        defer {
            self.lock();
            self.pending = null;
            self.state_mutex.unlock();
        }
        const request = stun.encodeBindingRequest(id);
        var destination = server;
        for (0..config.max_attempts) |_| {
            try socket.send(io, &destination, &request);
            const deadline = std.Io.Timestamp.now(io, .awake).addDuration(.fromMilliseconds(config.timeout_ms));
            while (true) {
                const snapshot = self.changed.load(.acquire);
                self.lock();
                const stopped = self.stopped;
                const mapped = self.pending.?.mapped;
                self.state_mutex.unlock();
                if (stopped) return error.Canceled;
                if (mapped) |value| return value;
                if (std.Io.Timestamp.now(io, .awake).nanoseconds >= deadline.nanoseconds) break;
                try io.futexWaitTimeout(u32, &self.changed.raw, snapshot, .{ .deadline = deadline.withClock(.awake) });
            }
        }
        return error.StunUnavailable;
    }

    /// Returns true only for a matching response from the nominated STUN server.
    pub fn receive(self: *Binding, io: std.Io, from: std.Io.net.IpAddress, packet: []const u8) bool {
        self.lock();
        const pending = if (self.pending) |*value| value else {
            self.state_mutex.unlock();
            return false;
        };
        if (!std.meta.eql(pending.server, from)) {
            self.state_mutex.unlock();
            return false;
        }
        const mapped = stun.decodeBindingSuccess(packet, pending.id) catch {
            self.state_mutex.unlock();
            return false;
        };
        pending.mapped = mapped;
        self.state_mutex.unlock();
        self.notify(io);
        return true;
    }

    pub fn stop(self: *Binding, io: std.Io) void {
        self.lock();
        self.stopped = true;
        self.state_mutex.unlock();
        self.notify(io);
    }

    fn notify(self: *Binding, io: std.Io) void {
        _ = self.changed.fetchAdd(1, .release);
        io.futexWake(u32, &self.changed.raw, 1);
    }

    fn lock(self: *Binding) void {
        while (!self.state_mutex.tryLock()) std.atomic.spinLoopHint();
    }
};
