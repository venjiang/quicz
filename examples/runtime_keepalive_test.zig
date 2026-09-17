const std = @import("std");
const quicz = @import("quicz");
const test_certs = @import("quicz-test-cert");

const Client = quicz.runtime.client.Client;
const Server = quicz.runtime.server.Server;
const ServerConnection = quicz.runtime.server.ServerConnection;

fn echoAfterIdle(connection: ServerConnection) std.Io.Cancelable!void {
    var mutable_connection = connection;
    var stream = mutable_connection.acceptStream() catch return;
    var buffer: [64]u8 = undefined;
    _ = stream.receive(&buffer) catch return;
    const received = stream.receive(&buffer) catch return;
    stream.send(buffer[0..received], true) catch {};
}

test "runtime keepalive preserves an otherwise idle connection" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const alpn = [_][]const u8{"quicz-runtime-keepalive-test"};

    var server = try Server.init(std.testing.allocator, io, .{
        .port = 0,
        .alpn = &alpn,
        .cert_der = &test_certs.cert_der,
        .private_key = &test_certs.private_key,
        .max_idle_timeout_ms = 120,
    });
    defer server.deinit();
    try server.serve(&echoAfterIdle);

    var client = try Client.init(std.testing.allocator, io, .{
        .server_port = server.localPort(),
        .server_name = "localhost",
        .alpn = &alpn,
        .insecure_skip_verify = true,
        .keepalive_interval_ms = 30,
    });
    defer client.deinit();
    try client.connect();
    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "ready", false);

    try io.sleep(.fromMilliseconds(360), .awake);

    try client.sendOnStream(stream_id, "still alive", false);
    var received: [32]u8 = undefined;
    const count = try client.receive(stream_id, &received);
    try std.testing.expectEqualStrings("still alive", received[0..count]);
}
