//! Proves that STUN discovery and QUIC can reuse one client UDP socket.

const std = @import("std");
const quicz = @import("quicz");
const test_certs = @import("test_certs.zig");

const Client = quicz.runtime.client.Client;
const Server = quicz.runtime.server.Server;
const ServerConnection = quicz.runtime.server.ServerConnection;
const stun = quicz.connectivity.stun;

fn echoHandler(connection: ServerConnection) std.Io.Cancelable!void {
    var mutable_connection = connection;
    var stream = mutable_connection.acceptStream() catch return;
    var buffer: [256]u8 = undefined;
    const received = stream.receive(&buffer) catch return;
    stream.send(buffer[0..received], true) catch {};
}

const StunResponderContext = struct {
    io: std.Io,
    socket: *std.Io.net.Socket,
};

fn respondToBindingRequest(context: StunResponderContext) std.Io.Cancelable!void {
    var buffer: [256]u8 = undefined;
    const request = context.socket.receiveTimeout(context.io, &buffer, .none) catch return;
    const transaction_id = stun.decodeBindingRequest(request.data) catch return;
    const observed_address = switch (request.from) {
        .ip4 => |address| address,
        .ip6 => return,
    };
    const response = stun.encodeBindingSuccessIpv4(
        transaction_id,
        observed_address.bytes,
        observed_address.port,
    );
    var destination = request.from;
    context.socket.send(context.io, &destination, &response) catch return;
}

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stun_bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var stun_socket = try stun_bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer stun_socket.close(io);

    var client_bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    const client_socket = try client_bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    var client_socket_transferred = false;
    defer if (!client_socket_transferred) client_socket.close(io);
    const original_client_port = client_socket.address.ip4.port;

    const stun_server_address = stun_socket.address;
    var stun_group: std.Io.Group = .init;
    try stun_group.concurrent(io, respondToBindingRequest, .{StunResponderContext{
        .io = io,
        .socket = &stun_socket,
    }});

    const alpn = [_][]const u8{"quicz-connectivity-spike"};
    var server = try Server.init(allocator, io, .{
        .port = 0,
        .alpn = &alpn,
        .cert_der = &test_certs.cert_der,
        .private_key = &test_certs.private_key,
    });
    defer server.deinit();
    try server.serve(&echoHandler);

    var client = try Client.initWithSocket(allocator, io, client_socket, .{
        .server_port = server.localPort(),
        .server_name = "localhost",
        .alpn = &alpn,
        .insecure_skip_verify = true,
        .active_migration_disabled = false,
    });
    client_socket_transferred = true;
    defer client.deinit();
    if (client.localPort() != original_client_port) return error.QuicPortChanged;
    const mapped_address = try client.discoverReflexiveAddress(stun_server_address, .{
        .timeout_ms = 1_000,
        .max_attempts = 1,
    });
    stun_group.await(io) catch {};
    switch (mapped_address) {
        .ipv4 => |mapped| {
            if (mapped.port != original_client_port) return error.StunPortMismatch;
        },
        .ipv6 => return error.UnexpectedAddressFamily,
    }

    const payload = "STUN and QUIC share one UDP socket";
    if (!try client.runEchoSession(payload)) return error.EchoMismatch;
    std.debug.print(
        "shared-socket connectivity: STUN port={d} QUIC port={d} echo=ok\n",
        .{ original_client_port, client.localPort() },
    );
}
