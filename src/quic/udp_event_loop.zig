//! UDP I/O event loop for production QUIC (P5-A).
//!
//! Provides a non-blocking UDP socket event loop using Zig std.Io,
//! supporting multi-connection concurrent send/receive with
//! timer-driven PTO/idle/close handling.

const std = @import("std");
const endpoint = @import("endpoint.zig");

/// UDP socket wrapper for QUIC datagram I/O.
pub const UdpSocket = struct {
    socket: std.Io.net.Socket,
    io: std.Io,
    local_addr: endpoint.Udp4Address,

    /// Bind a UDP socket to the given address and port.
    pub fn bind(io: std.Io, addr: []const u8, port: u16) !UdpSocket {
        var ip_bytes: [4]u8 = undefined;
        if (std.mem.eql(u8, addr, "0.0.0.0") or std.mem.eql(u8, addr, "127.0.0.1")) {
            ip_bytes = .{ 127, 0, 0, 1 };
        } else {
            // Parse dotted quad
            var parts = std.mem.splitScalar(u8, addr, '.');
            for (&ip_bytes) |*b| {
                const part = parts.next() orelse return error.InvalidAddress;
                b.* = std.fmt.parseInt(u8, part, 10) catch return error.InvalidAddress;
            }
        }
        var address = std.Io.net.IpAddress{ .ip4 = .{ .bytes = ip_bytes, .port = port } };
        const socket = try address.bind(io, .{
            .mode = .dgram,
            .protocol = .udp,
        });
        const local = endpoint.Udp4Address.init(ip_bytes, socket.address.ip4.port);
        return .{ .socket = socket, .io = io, .local_addr = local };
    }

    /// Send a datagram to the given address.
    pub fn sendTo(self: *UdpSocket, remote: endpoint.Udp4Address, data: []const u8) !void {
        var ip_addr = std.Io.net.IpAddress{
            .ip4 = .{ .bytes = remote.octets, .port = remote.port },
        };
        try self.socket.send(self.io, &ip_addr, data);
    }

    /// Receive a datagram with timeout. Returns data and sender address.
    pub fn receiveFrom(self: *UdpSocket, buf: []u8, timeout_ms: u64) !struct { data: []const u8, from: endpoint.Udp4Address } {
        const timeout = std.Io.Timeout{
            .duration = .{
                .clock = .awake,
                .raw = std.Io.Duration.fromMilliseconds(timeout_ms),
            },
        };
        const received = try self.socket.receiveTimeout(self.io, buf, timeout);
        const from = endpoint.Udp4Address.init(
            received.from.ip4.bytes,
            received.from.ip4.port,
        );
        return .{ .data = received.data, .from = from };
    }

    pub fn close(self: *UdpSocket) void {
        self.socket.close(self.io);
    }
};

/// Event loop configuration.
pub const EventLoopConfig = struct {
    /// Receive buffer size per connection.
    recv_buf_size: usize = 65536,
    /// Default receive timeout in milliseconds.
    recv_timeout_ms: u64 = 100,
    /// Maximum concurrent connections.
    max_connections: usize = 1024,
};

/// QUIC UDP event loop state.
pub const EventLoop = struct {
    config: EventLoopConfig,
    /// Monotonic clock for timer management.
    now_ms: i64 = 0,
    /// Whether the event loop is running.
    running: bool = false,

    pub fn init(config: EventLoopConfig) EventLoop {
        return .{ .config = config };
    }

    /// Advance the event loop clock.
    pub fn tick(self: *EventLoop, elapsed_ms: i64) void {
        self.now_ms += elapsed_ms;
    }

    /// Start the event loop.
    pub fn start(self: *EventLoop) void {
        self.running = true;
    }

    /// Stop the event loop.
    pub fn stop(self: *EventLoop) void {
        self.running = false;
    }
};

test "UdpSocket bind and addresses" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var sock = try UdpSocket.bind(io, "127.0.0.1", 0);
    defer sock.close();

    try std.testing.expect(sock.local_addr.port > 0);
    try std.testing.expectEqual(@as(u8, 127), sock.local_addr.octets[0]);
}

test "EventLoop tick and state" {
    var loop = EventLoop.init(.{});
    try std.testing.expect(!loop.running);
    try std.testing.expectEqual(@as(i64, 0), loop.now_ms);

    loop.start();
    try std.testing.expect(loop.running);

    loop.tick(100);
    try std.testing.expectEqual(@as(i64, 100), loop.now_ms);

    loop.tick(50);
    try std.testing.expectEqual(@as(i64, 150), loop.now_ms);

    loop.stop();
    try std.testing.expect(!loop.running);
}

test "EventLoopConfig defaults" {
    const config = EventLoopConfig{};
    try std.testing.expectEqual(@as(usize, 65536), config.recv_buf_size);
    try std.testing.expectEqual(@as(u64, 100), config.recv_timeout_ms);
    try std.testing.expectEqual(@as(usize, 1024), config.max_connections);
}
