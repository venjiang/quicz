//! Exercises the exported blocking mobile C ABI against the native runtime server.

const std = @import("std");
const quicz = @import("quicz");
const mobile = @import("quicz_mobile");
const test_certs = @import("test_certs.zig");

const Server = quicz.runtime.server.Server;
const ServerConnection = quicz.runtime.server.ServerConnection;

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

    var server = try Server.init(allocator, io, .{
        .port = 0,
        .alpn = &alpn_list,
        .cert_der = &test_certs.cert_der,
        .private_key = &test_certs.private_key,
    });
    defer server.deinit();
    try server.serve(&echoHandler);

    const server_name = "localhost";
    const ca_pem = @embedFile("interop/testdata/quicz-echo-ca.pem");
    var ca_der_buffer: [1024]u8 = undefined;
    const ca_der = try quicz.tls_pem.decodeBlock(ca_pem, "CERTIFICATE", &ca_der_buffer);
    const config = mobile.ClientConfig{
        .server_ipv4 = .{ 127, 0, 0, 1 },
        .server_port = server.localPort(),
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
    std.debug.print("mobile C ABI: connect/open/send/receive/close ok\n", .{});
}
