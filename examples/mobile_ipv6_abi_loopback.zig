//! Native IPv6 C ABI: layout, same-socket STUN/punch, verified QUIC, and stream I/O.

const std = @import("std");
const quicz = @import("quicz");
const mobile = @import("quicz_mobile");
const c = @import("quicz_mobile_c");
const certs = @import("test_certs.zig");
const Server = quicz.runtime.server.IPv6Server;
const PunchAttempt = quicz.connectivity.punch_attempt.PunchAttempt;
const timeout: std.Io.Timeout = .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(2) } };

fn checkLayout(comptime C: type, comptime Zig: type) void {
    if (@sizeOf(C) != @sizeOf(Zig) or @alignOf(C) != @alignOf(Zig)) @compileError("C and Zig mobile ABI layouts differ");
    inline for (std.meta.fields(Zig)) |field| {
        if (@offsetOf(C, field.name) != @offsetOf(Zig, field.name)) @compileError("C and Zig mobile ABI field offsets differ");
    }
}

comptime {
    checkLayout(c.quicz_mobile_client_config, mobile.ClientConfig);
    checkLayout(c.quicz_mobile_ipv4_endpoint, mobile.Ipv4Endpoint);
    checkLayout(c.quicz_mobile_punch_config, mobile.PunchConfig);
    checkLayout(c.quicz_mobile_punch_diagnostics, mobile.PunchDiagnostics);
    checkLayout(c.quicz_mobile_ipv6_endpoint, mobile.Ipv6Endpoint);
    checkLayout(c.quicz_mobile_client_ipv6_config, mobile.Client6Config);
    checkLayout(c.quicz_mobile_punch_ipv6_config, mobile.Punch6Config);
    if (c.QUICZ_MOBILE_ABI_VERSION != 1) @compileError("legacy ABI version changed");
    if (@sizeOf(mobile.Ipv4Endpoint) != 6 or @sizeOf(mobile.PunchConfig) != 84 or
        @sizeOf(mobile.PunchDiagnostics) != 56 or @sizeOf(mobile.Ipv6Endpoint) != 24 or
        @sizeOf(mobile.Punch6Config) != 100) @compileError("fixed mobile ABI layout changed");
    if (@sizeOf(usize) == 8 and (@sizeOf(mobile.ClientConfig) != 56 or
        @offsetOf(mobile.ClientConfig, "server_name") != 8 or
        @sizeOf(mobile.Client6Config) != 96)) @compileError("64-bit mobile configuration layout changed");
    _ = c.quicz_mobile_client_create_ipv6;
    _ = c.quicz_mobile_client_bound_ipv6;
    _ = c.quicz_mobile_client_discover_ipv6;
    _ = c.quicz_mobile_client_punch_ipv6;
    _ = c.quicz_mobile_client_punch_ipv6_with_diagnostics;
}

fn watchdog(done: *std.Io.Event, io: std.Io) void {
    const deadline = std.Io.Timestamp.now(io, .awake).addDuration(.fromSeconds(20));
    while (!done.isSet()) {
        done.waitTimeout(io, .{ .deadline = .{ .clock = .awake, .raw = deadline } }) catch {};
        if (!done.isSet() and std.Io.Timestamp.now(io, .awake).nanoseconds >= deadline.nanoseconds) {
            std.debug.print("FAIL: mobile IPv6 ABI or cleanup exceeded 20 seconds\n", .{});
            std.process.exit(1);
        }
    }
}

fn serveStun(io: std.Io, socket: *std.Io.net.Socket) !void {
    for (0..2) |index| {
        var request: [128]u8 = undefined;
        const received = try socket.receiveTimeout(io, &request, timeout);
        const transaction = try quicz.connectivity.stun.decodeBindingRequest(received.data);
        const peer = switch (received.from) {
            .ip4 => return error.WrongStunFamily,
            .ip6 => |value| value,
        };
        if (index == 1) {
            const response = quicz.connectivity.stun.encodeBindingSuccessIpv4(transaction, .{ 127, 0, 0, 1 }, peer.port);
            try socket.send(io, &received.from, &response);
            continue;
        }
        // RFC 8489 XOR-MAPPED-ADDRESS: cookie plus the 96-bit transaction ID.
        var response: [44]u8 = @splat(0);
        std.mem.writeInt(u16, response[0..2], 0x0101, .big);
        std.mem.writeInt(u16, response[2..4], 24, .big);
        std.mem.writeInt(u32, response[4..8], 0x2112a442, .big);
        @memcpy(response[8..20], &transaction);
        std.mem.writeInt(u16, response[20..22], 0x0020, .big);
        std.mem.writeInt(u16, response[22..24], 20, .big);
        response[25] = 2;
        std.mem.writeInt(u16, response[26..28], peer.port ^ 0x2112, .big);
        const cookie = [_]u8{ 0x21, 0x12, 0xa4, 0x42 };
        for (peer.bytes, 0..) |byte, address_index| {
            const mask = if (address_index < cookie.len) cookie[address_index] else transaction[address_index - cookie.len];
            response[28 + address_index] = byte ^ mask;
        }
        try socket.send(io, &received.from, &response);
    }
}

fn runHostPunch(io: std.Io, socket: std.Io.net.Socket, remote: std.Io.net.IpAddress, attempt: *PunchAttempt) !void {
    try quicz.connectivity.punch_driver.runUntilValidated(io, socket, remote, attempt);
}

fn echo(connection: Server.ServerConnection) std.Io.Cancelable!void {
    var peer = connection;
    var stream = peer.acceptStream() catch return;
    var buffer: [4096]u8 = undefined;
    while (true) {
        const count = stream.receive(&buffer) catch return;
        stream.send(buffer[0..count], count == 0) catch return;
        if (count == 0) {
            stream.flush() catch return;
            return;
        }
    }
}

fn checkPunchClose(comptime ipv6: bool, io: std.Io, ca: []const u8) !bool {
    const Worker = struct {
        handle: ?*anyopaque,
        config4: mobile.PunchConfig,
        config6: mobile.Punch6Config,
        result: i32 = -1,
        diagnostics: mobile.PunchDiagnostics = .{},

        fn run(self: *@This()) void {
            self.result = if (ipv6)
                mobile.quicz_mobile_client_punch_ipv6_with_diagnostics(self.handle, &self.config6, &self.diagnostics)
            else
                mobile.quicz_mobile_client_punch_ipv4_with_diagnostics(self.handle, &self.config4, &self.diagnostics);
        }
    };
    var passed = true;
    const local: std.Io.net.IpAddress = if (ipv6) .{ .ip6 = .loopback(0) } else .{ .ip4 = .loopback(0) };
    for ([_]bool{ false, true }) |blocked_signal| {
        const silent = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
        defer silent.close(io);
        const endpoint6: mobile.Ipv6Endpoint = .{
            .address = std.Io.net.Ip6Address.loopback(0).bytes,
            .port = silent.address.getPort(),
            .reserved = 0,
            .scope_id = 0,
        };
        const config6: mobile.Client6Config = .{
            .local = .{ .address = endpoint6.address, .port = 0, .reserved = 0, .scope_id = 0 },
            .remote = endpoint6,
            .server_name = "localhost".ptr,
            .server_name_length = "localhost".len,
            .alpn = "quicz-mobile-close".ptr,
            .alpn_length = "quicz-mobile-close".len,
            .ca_certificate_der = ca.ptr,
            .ca_certificate_der_length = ca.len,
        };
        const config4: mobile.ClientConfig = .{
            .server_ipv4 = .{ 127, 0, 0, 1 },
            .server_port = silent.address.getPort(),
            .allow_migration = 0,
            .reserved = 0,
            .server_name = config6.server_name,
            .server_name_length = config6.server_name_length,
            .alpn = config6.alpn,
            .alpn_length = config6.alpn_length,
            .ca_certificate_der = ca.ptr,
            .ca_certificate_der_length = ca.len,
        };
        var handle: ?*anyopaque = null;
        const created = if (ipv6) mobile.quicz_mobile_client_create_ipv6(&config6, &handle) else mobile.quicz_mobile_client_create(&config4, &handle);
        if (created != 0) return error.CloseClientCreationFailed;
        defer mobile.quicz_mobile_client_destroy(handle);
        var bound_address = local;
        if (ipv6) {
            var bound: mobile.Ipv6Endpoint = undefined;
            if (mobile.quicz_mobile_client_bound_ipv6(handle, &bound) != 0) return error.CloseClientBoundFailed;
            bound_address.ip6.port = bound.port;
        } else {
            var bound: mobile.Ipv4Endpoint = undefined;
            if (mobile.quicz_mobile_client_bound_ipv4(handle, &bound) != 0) return error.CloseClientBoundFailed;
            bound_address.ip4.port = bound.port;
        }
        var previous: std.posix.sigset_t = undefined;
        if (comptime @import("builtin").os.tag.isDarwin()) {
            if (blocked_signal) {
                var blocked = std.posix.sigemptyset();
                std.posix.sigaddset(&blocked, .IO);
                std.posix.sigprocmask(std.posix.SIG.BLOCK, &blocked, &previous);
            }
        }
        defer if (comptime @import("builtin").os.tag.isDarwin()) {
            if (blocked_signal) std.posix.sigprocmask(std.posix.SIG.SETMASK, &previous, null);
        };
        var worker: Worker = .{
            .handle = handle,
            .config4 = .{
                .remote = .{ .address = .{ 127, 0, 0, 1 }, .port = silent.address.getPort() },
                .key = @splat(0x42),
                .attempt_id = @splat(0x11),
                .nonce = @splat(0xa1),
                .initial_retry_ms = 1_000,
                .maximum_retry_ms = 1_000,
                .max_attempts = 1,
                .reserved = @splat(0),
            },
            .config6 = .{
                .remote = endpoint6,
                .key = @splat(0x42),
                .attempt_id = @splat(0x11),
                .nonce = @splat(0xa1),
                .initial_retry_ms = 1_000,
                .maximum_retry_ms = 1_000,
                .max_attempts = 1,
                .reserved = @splat(0),
            },
        };
        const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
        var request: [256]u8 = undefined;
        _ = silent.receiveTimeout(io, &request, timeout) catch |err| {
            mobile.quicz_mobile_client_close(handle);
            thread.join();
            return err;
        };
        const started = std.Io.Timestamp.now(io, .awake);
        mobile.quicz_mobile_client_close(handle);
        mobile.quicz_mobile_client_close(handle);
        thread.join();
        const elapsed_ms = started.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds();
        const canceled = worker.result == @intFromEnum(mobile.Result.punch_failed) and
            worker.diagnostics.outcome == @intFromEnum(mobile.PunchOutcome.canceled) and elapsed_ms < 250;
        std.debug.print("mobile close: ipv6={} blocked_signal={} elapsed_ms={d} outcome={d}\n", .{ ipv6, blocked_signal, elapsed_ms, worker.diagnostics.outcome });
        passed = passed and canceled;
        if (!canceled) continue;
        if (mobile.quicz_mobile_client_connect_timeout(handle, 50) != @intFromEnum(mobile.Result.connection_failed)) return error.ClosedClientConnected;
        var stream_id: u64 = 0;
        if (mobile.quicz_mobile_client_open_bidi(handle, &stream_id) != @intFromEnum(mobile.Result.stream_failed)) return error.ClosedClientOpenedStream;
        if (mobile.quicz_mobile_client_send(handle, 0, null, 0, 0) != @intFromEnum(mobile.Result.stream_failed)) return error.ClosedClientSent;
        var response: [1]u8 = undefined;
        var received: usize = 0;
        if (mobile.quicz_mobile_client_receive(handle, 0, &response, response.len, &received) != @intFromEnum(mobile.Result.stream_failed)) return error.ClosedClientReceived;
        if (bound_address.bind(io, .{ .mode = .dgram, .protocol = .udp })) |unexpected| {
            unexpected.close(io);
            return error.CloseReleasedSocket;
        } else |err| {
            if (err != error.AddressInUse) return err;
        }
        if (comptime @import("builtin").os.tag.isDarwin()) {
            if (blocked_signal) {
                var current: std.posix.sigset_t = undefined;
                std.posix.sigprocmask(std.posix.SIG.SETMASK, null, &current);
                if (!std.posix.sigismember(&current, .IO)) return error.CallerSignalMaskChanged;
            }
        }
        mobile.quicz_mobile_client_destroy(handle);
        handle = null;
        const rebound = try bound_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
        rebound.close(io);
    }
    return passed;
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
    if (mobile.quicz_mobile_abi_version() != 1 or
        mobile.quicz_mobile_capabilities() & (@as(u64, 1) << 7) == 0) return error.CapabilityMissing;
    const local = std.Io.net.IpAddress{ .ip6 = .loopback(0) };
    const host_socket = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    var host_transferred = false;
    defer if (!host_transferred) host_socket.close(io);
    const remote: mobile.Ipv6Endpoint = .{ .address = local.ip6.bytes, .port = host_socket.address.getPort(), .reserved = 0, .scope_id = 0 };
    const alpn = "quicz-mobile-ipv6-abi";
    var server_name_storage = "localhost".*;
    var alpn_storage = alpn.*;
    var ca_storage: [1024]u8 = undefined;
    const ca = try quicz.tls_pem.decodeBlock(@embedFile("interop/testdata/quicz-echo-ca.pem"), "CERTIFICATE", &ca_storage);
    const closed4 = try checkPunchClose(false, io, ca);
    const closed6 = try checkPunchClose(true, io, ca);
    if (!closed4 or !closed6) return error.PunchCloseDidNotCancel;
    const config: mobile.Client6Config = .{
        .local = .{ .address = local.ip6.bytes, .port = 0, .reserved = 0, .scope_id = 0 },
        .remote = remote,
        .server_name = &server_name_storage,
        .server_name_length = server_name_storage.len,
        .alpn = &alpn_storage,
        .alpn_length = alpn_storage.len,
        .ca_certificate_der = ca.ptr,
        .ca_certificate_der_length = ca.len,
    };
    var handle: ?*anyopaque = null;
    if (mobile.quicz_mobile_client_create_ipv6(&config, &handle) != 0) return error.CreateFailed;
    defer mobile.quicz_mobile_client_destroy(handle);
    // The constructor must retain its own inputs after the caller releases them.
    @memset(&server_name_storage, 0);
    @memset(&alpn_storage, 0);
    @memset(&ca_storage, 0);
    if (mobile.quicz_mobile_client_set_keepalive_interval(handle, 10_000) != 0) return error.KeepaliveFailed;
    var bound: mobile.Ipv6Endpoint = undefined;
    if (mobile.quicz_mobile_client_bound_ipv6(handle, &bound) != 0 or bound.port == 0) return error.BoundFailed;
    if (!std.mem.eql(u8, &bound.address, &local.ip6.bytes) or bound.scope_id != 0 or bound.reserved != 0) return error.BoundAddressChanged;

    var stun_socket = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer stun_socket.close(io);
    var stun = try io.concurrent(serveStun, .{ io, &stun_socket });
    defer _ = stun.cancel(io) catch {};
    const stun_endpoint: mobile.Ipv6Endpoint = .{ .address = local.ip6.bytes, .port = stun_socket.address.getPort(), .reserved = 0, .scope_id = 0 };
    var mapped: mobile.Ipv6Endpoint = undefined;
    if (mobile.quicz_mobile_client_discover_ipv6(handle, &stun_endpoint, 500, 1, &mapped) != 0) return error.DiscoveryFailed;
    if (!std.mem.eql(u8, &mapped.address, &bound.address) or mapped.port != bound.port or
        mapped.scope_id != 0 or mapped.reserved != 0) return error.MappingMismatch;
    if (mobile.quicz_mobile_client_discover_ipv6(handle, &stun_endpoint, 500, 1, &mapped) != @intFromEnum(mobile.Result.discovery_failed)) return error.WrongMappingFamilyAccepted;
    try stun.await(io);

    const key: quicz.connectivity.punch_wire.Key = .{0x42} ** 32;
    const attempt_id: quicz.connectivity.punch_wire.AttemptId = .{0x11} ** 16;
    const host_nonce: quicz.connectivity.punch_wire.Nonce = .{0xb2} ** 16;
    var attempt = try PunchAttempt.init(key, attempt_id, host_nonce, .{});
    const app_address = std.Io.net.IpAddress{ .ip6 = .{ .bytes = bound.address, .port = bound.port } };
    var host_punch = try io.concurrent(runHostPunch, .{ io, host_socket, app_address, &attempt });
    defer _ = host_punch.cancel(io) catch {};
    const punch: mobile.Punch6Config = .{
        .remote = remote,
        .key = key,
        .attempt_id = attempt_id,
        .nonce = .{0xa1} ** 16,
        .initial_retry_ms = 100,
        .maximum_retry_ms = 1_000,
        .max_attempts = 5,
        .reserved = .{ 0, 0, 0 },
    };
    var diagnostics: mobile.PunchDiagnostics = undefined;
    if (mobile.quicz_mobile_client_punch_ipv6_with_diagnostics(handle, &punch, &diagnostics) != 0) return error.PunchFailed;
    try host_punch.await(io);
    if (diagnostics.outcome != @intFromEnum(mobile.PunchOutcome.validated) or
        diagnostics.peer_probe == 0 or diagnostics.local_ack == 0) return error.ProofMissing;
    var responder = try quicz.connectivity.punch_responder.PunchResponder.init(key, attempt_id, host_nonce, app_address, @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds), 2_000);
    defer responder.deinit();
    var server = try Server.initWithSocket(init.gpa, io, host_socket, .{
        .port = remote.port,
        .alpn = &.{alpn},
        .cert_der = &certs.cert_der,
        .private_key = &certs.private_key,
        .max_connections = 1,
        .punch_responder = responder,
    });
    host_transferred = true;
    defer server.deinit();
    try server.serve(&echo);
    if (mobile.quicz_mobile_client_connect_timeout(handle, 2_000) != 0) return error.ConnectFailed;
    if (mobile.quicz_mobile_client_connect_timeout(handle, 2_000) != 0) return error.ReusedConnectFailed;
    var after: mobile.Ipv6Endpoint = undefined;
    if (mobile.quicz_mobile_client_bound_ipv6(handle, &after) != 0 or after.port != bound.port or
        !std.mem.eql(u8, &after.address, &bound.address)) return error.SocketChanged;
    var stream: u64 = 0;
    if (mobile.quicz_mobile_client_open_bidi(handle, &stream) != 0) return error.OpenFailed;
    var payload: [4096]u8 = undefined;
    try io.randomSecure(&payload);
    if (mobile.quicz_mobile_client_send(handle, stream, &payload, payload.len, 1) != 0) return error.SendFailed;
    var response: [4096]u8 = undefined;
    var count: usize = 0;
    while (count < response.len) {
        var received: usize = 0;
        if (mobile.quicz_mobile_client_receive(handle, stream, response[count..].ptr, response.len - count, &received) != 0) return error.ReceiveFailed;
        if (received == 0) break;
        count += received;
    }
    if (!std.mem.eql(u8, &payload, response[0..count])) return error.EchoMismatch;
    var end: [1]u8 = undefined;
    var end_count: usize = 0;
    if (mobile.quicz_mobile_client_receive(handle, stream, &end, end.len, &end_count) != 0 or end_count != 0) return error.FinMissing;
    mobile.quicz_mobile_client_close(handle);
    std.debug.print("mobile IPv6 ABI: C layouts, copied inputs, STUN, authenticated punch, verified TLS, 4 KiB stream and close passed\n", .{});
}
