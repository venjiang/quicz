//! Exercises the exported blocking mobile C ABI against the native runtime server.

const std = @import("std");
const quicz = @import("quicz");
const mobile = @import("quicz_mobile");
const test_certs = @import("test_certs.zig");

const Server = quicz.runtime.server.Server;
const ServerConnection = quicz.runtime.server.ServerConnection;
const PunchAttempt = quicz.connectivity.punch_attempt.PunchAttempt;

const HostPunchContext = struct {
    io: std.Io,
    socket: std.Io.net.Socket,
    remote: std.Io.net.IpAddress,
    attempt: *PunchAttempt,
    failure: *?anyerror,
};

fn runHostPunch(context: HostPunchContext) std.Io.Cancelable!void {
    quicz.connectivity.punch_driver.run(
        context.io,
        context.socket,
        context.remote,
        context.attempt,
    ) catch |err| {
        context.failure.* = err;
    };
}

fn echoHandler(connection: ServerConnection) std.Io.Cancelable!void {
    var mutable_connection = connection;
    var stream = mutable_connection.acceptStream() catch return;
    var buffer: [256]u8 = undefined;
    const received = stream.receive(&buffer) catch return;
    stream.send(buffer[0..received], true) catch {};
}

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const alpn = "quicz-mobile-abi-spike";
    const alpn_list = [_][]const u8{alpn};

    var host_bind_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    const host_socket = try host_bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    var host_socket_transferred = false;
    defer if (!host_socket_transferred) host_socket.close(io);
    const host_port = host_socket.address.ip4.port;

    const server_name = "localhost";
    const ca_pem = @embedFile("interop/testdata/quicz-echo-ca.pem");
    var ca_der_buffer: [1024]u8 = undefined;
    const ca_der = try quicz.tls_pem.decodeBlock(ca_pem, "CERTIFICATE", &ca_der_buffer);
    const config = mobile.ClientConfig{
        .server_ipv4 = .{ 127, 0, 0, 1 },
        .server_port = host_port,
        .allow_migration = 1,
        .reserved = 0,
        .server_name = server_name.ptr,
        .server_name_length = server_name.len,
        .alpn = alpn.ptr,
        .alpn_length = alpn.len,
        .ca_certificate_der = ca_der.ptr,
        .ca_certificate_der_length = ca_der.len,
    };
    var handle: ?*anyopaque = null;
    if (mobile.quicz_mobile_client_create(&config, &handle) != 0) return error.CreateFailed;
    defer mobile.quicz_mobile_client_destroy(handle);

    var app_endpoint: mobile.Ipv4Endpoint = undefined;
    if (mobile.quicz_mobile_client_bound_ipv4(handle, &app_endpoint) != 0) return error.LocalEndpointFailed;
    const key: quicz.connectivity.punch_wire.Key = .{0x42} ** 32;
    const attempt_id: quicz.connectivity.punch_wire.AttemptId = .{0x11} ** 16;
    var host_attempt = try PunchAttempt.init(key, attempt_id, .{0xb2} ** 16, .{});
    var host_failure: ?anyerror = null;
    var host_punch_group: std.Io.Group = .init;
    try host_punch_group.concurrent(io, runHostPunch, .{HostPunchContext{
        .io = io,
        .socket = host_socket,
        // The client socket is wildcard-bound; candidate gathering supplies
        // the reachable interface address while preserving its bound port.
        .remote = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = app_endpoint.port } },
        .attempt = &host_attempt,
        .failure = &host_failure,
    }});
    const punch_config = mobile.PunchConfig{
        .remote = .{ .address = .{ 127, 0, 0, 1 }, .port = host_port },
        .key = key,
        .attempt_id = attempt_id,
        .nonce = .{0xa1} ** 16,
        .initial_retry_ms = 100,
        .maximum_retry_ms = 1_000,
        .max_attempts = 5,
        .reserved = .{ 0, 0, 0 },
    };
    if (mobile.quicz_mobile_client_punch_ipv4(handle, &punch_config) != 0) return error.PunchFailed;
    host_punch_group.await(io) catch {};
    if (host_failure) |err| return err;

    var server = try Server.initWithSocket(allocator, io, host_socket, .{
        .port = host_port,
        .alpn = &alpn_list,
        .cert_der = &test_certs.cert_der,
        .private_key = &test_certs.private_key,
    });
    host_socket_transferred = true;
    defer server.deinit();
    try server.serve(&echoHandler);
    if (mobile.quicz_mobile_client_connect(handle) != 0) return error.ConnectFailed;

    var stream_id: u64 = 0;
    if (mobile.quicz_mobile_client_open_bidi(handle, &stream_id) != 0) return error.OpenStreamFailed;
    const payload = "mobile ABI stream echo";
    if (mobile.quicz_mobile_client_send(handle, stream_id, payload.ptr, payload.len, 1) != 0) return error.SendFailed;
    var buffer: [256]u8 = undefined;
    var received: usize = 0;
    if (mobile.quicz_mobile_client_receive(handle, stream_id, &buffer, buffer.len, &received) != 0) return error.ReceiveFailed;
    if (!std.mem.eql(u8, payload, buffer[0..received])) return error.EchoMismatch;

    mobile.quicz_mobile_client_close(handle);
    std.debug.print("mobile C ABI: punch/connect/open/send/receive/close ok\n", .{});
}
