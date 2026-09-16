//! Public C ABI regression under a hosted thread's blocked cancellation signal.
const std = @import("std");
const builtin = @import("builtin");
const quicz = @import("quicz");
const mobile = @import("quicz_mobile");
const certs = @import("test_certs.zig");

fn echo(connection: quicz.runtime.server.ServerConnection) std.Io.Cancelable!void {
    var peer = connection;
    var stream = peer.acceptStream() catch return;
    var buffer: [64]u8 = undefined;
    const count = stream.receive(&buffer) catch return;
    stream.send(buffer[0..count], true) catch {};
}

fn watchdog(done: *std.Io.Event, io: std.Io) void {
    const deadline = std.Io.Timestamp.now(io, .awake).addDuration(.fromSeconds(8));
    while (!done.isSet()) {
        done.waitTimeout(io, .{ .deadline = .{ .clock = .awake, .raw = deadline } }) catch {};
        if (!done.isSet() and std.Io.Timestamp.now(io, .awake).nanoseconds >= deadline.nanoseconds) {
            std.debug.print("FAIL: mobile connect or cleanup exceeded 8 seconds\n", .{});
            std.process.exit(1);
        }
    }
}

pub fn main(init: std.process.Init) !void {
    var threaded = std.Io.Threaded.init(init.gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var done: std.Io.Event = .unset;
    const guard_thread = try std.Thread.spawn(.{}, watchdog, .{ &done, io });
    defer {
        done.set(io);
        guard_thread.join();
    }
    var server = try quicz.runtime.server.Server.init(init.gpa, io, .{
        .port = 0,
        .alpn = &.{"quicz-mobile-deadline-v1"},
        .cert_der = &certs.cert_der,
        .private_key = &certs.private_key,
    });
    defer server.deinit();
    try server.serve(&echo);

    // The server workers were started first. Only new mobile workers inherit
    // this hosted-thread environment; the API must leave it unchanged.
    var previous: std.posix.sigset_t = undefined;
    if (comptime builtin.os.tag.isDarwin()) {
        var blocked = std.posix.sigemptyset();
        std.posix.sigaddset(&blocked, .IO);
        std.posix.sigprocmask(std.posix.SIG.BLOCK, &blocked, &previous);
    }
    defer if (comptime builtin.os.tag.isDarwin()) {
        std.posix.sigprocmask(std.posix.SIG.SETMASK, &previous, null);
    };
    var ca_buffer: [1024]u8 = undefined;
    const ca = try quicz.tls_pem.decodeBlock(
        @embedFile("interop/testdata/quicz-echo-ca.pem"),
        "CERTIFICATE",
        &ca_buffer,
    );
    for ([_]u32{ 1_000, 3_000 }) |timeout_ms| {
        const config = mobile.ClientConfig{
            .server_ipv4 = .{ 127, 0, 0, 1 },
            .server_port = server.socket.address.ip4.port,
            .allow_migration = 0,
            .reserved = 0,
            .server_name = "localhost".ptr,
            .server_name_length = "localhost".len,
            .alpn = "quicz-mobile-deadline-v1".ptr,
            .alpn_length = "quicz-mobile-deadline-v1".len,
            .ca_certificate_der = ca.ptr,
            .ca_certificate_der_length = ca.len,
        };
        var handle: ?*anyopaque = null;
        if (mobile.quicz_mobile_client_create(&config, &handle) != 0) return error.CreateFailed;
        defer mobile.quicz_mobile_client_destroy(handle);
        if (mobile.quicz_mobile_client_connect_timeout(handle, timeout_ms) != 0) return error.ConnectFailed;
        const started = std.Io.Timestamp.now(io, .awake);
        if (mobile.quicz_mobile_client_connect_timeout(handle, timeout_ms) != 0) return error.ReusedConnectFailed;
        const elapsed_ms = started.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds();
        std.debug.print("timeout_ms={d} reused_ms={d}\n", .{ timeout_ms, elapsed_ms });
        if (elapsed_ms >= 250) return error.SuccessWaitedForDeadline;
        var stream: u64 = 0;
        if (mobile.quicz_mobile_client_open_bidi(handle, &stream) != 0) return error.StreamFailed;
        const payload = "deadline-echo";
        if (mobile.quicz_mobile_client_send(handle, stream, payload.ptr, payload.len, 1) != 0) return error.SendFailed;
        var response: [64]u8 = undefined;
        var count: usize = 0;
        if (mobile.quicz_mobile_client_receive(handle, stream, &response, response.len, &count) != 0) return error.ReceiveFailed;
        if (!std.mem.eql(u8, payload, response[0..count])) return error.EchoMismatch;
        mobile.quicz_mobile_client_close(handle);
    }
    const loopback = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    const silent = try loopback.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer silent.close(io);
    const silent_config = mobile.ClientConfig{
        .server_ipv4 = .{ 127, 0, 0, 1 },
        .server_port = silent.address.ip4.port,
        .allow_migration = 0,
        .reserved = 0,
        .server_name = "localhost".ptr,
        .server_name_length = "localhost".len,
        .alpn = "quicz-mobile-deadline-v1".ptr,
        .alpn_length = "quicz-mobile-deadline-v1".len,
        .ca_certificate_der = ca.ptr,
        .ca_certificate_der_length = ca.len,
    };
    var silent_client: ?*anyopaque = null;
    if (mobile.quicz_mobile_client_create(&silent_config, &silent_client) != 0) return error.CreateFailed;
    const started = std.Io.Timestamp.now(io, .awake);
    const outcome = mobile.quicz_mobile_client_connect_timeout(silent_client, 100);
    mobile.quicz_mobile_client_destroy(silent_client);
    if (outcome != @intFromEnum(mobile.Result.connection_timed_out)) return error.TimeoutNotReported;
    if (started.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds() > 500) return error.TimeoutNotBounded;
    if (comptime builtin.os.tag.isDarwin()) {
        var current: std.posix.sigset_t = undefined;
        std.posix.sigprocmask(std.posix.SIG.SETMASK, null, &current);
        if (!std.posix.sigismember(&current, .IO)) return error.CallerSignalMaskChanged;
    }
    std.debug.print("mobile deadline: successful connection, echo, timeout and cleanup passed\n", .{});
}
