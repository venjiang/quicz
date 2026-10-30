//! Native IPv6 runtime regressions through real UDP sockets and TLS.

const std = @import("std");
const quicz = @import("../lib.zig");
const runtime_client = @import("client.zig");
const runtime_server = @import("server.zig");
const IPv6Client = runtime_client.IPv6Client;
const IPv6Server = runtime_server.IPv6Server;
const alpn = [_][]const u8{"quicz-native-ipv6-test"};
const timeout: std.Io.Timeout = .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(2) } };

fn waitForAdmission(io: std.Io, admission: *const runtime_server.ConnectionAdmission, expected: usize) !void {
    const started = std.Io.Timestamp.now(io, .awake);
    while (admission.inUse() != expected) {
        if (started.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds() >= 1_000)
            return error.Timeout;
        try io.sleep(.fromMilliseconds(5), .awake);
    }
}
// Existing localhost identity from the mutual-TLS loopback fixture.
const private_key = [_]u8{
    0x5b, 0xbf, 0x4f, 0x5a, 0x48, 0x42, 0x9f, 0x00,
    0x5a, 0x57, 0x09, 0xc3, 0xb4, 0xc1, 0x3a, 0x64,
    0x2e, 0xb1, 0x61, 0xf5, 0x0b, 0xde, 0x64, 0x4b,
    0x3a, 0x38, 0xa6, 0x8f, 0xfa, 0x48, 0xda, 0x51,
};

const Fixture = struct {
    cert_der: [512]u8 = undefined,
    cert_len: usize = 0,
    trust: std.crypto.Certificate.Bundle = .empty,

    fn init(io: std.Io, trust_pem: []const u8) !Fixture {
        var fixture: Fixture = .{};
        errdefer fixture.trust.deinit(std.testing.allocator);
        const cert = try quicz.tls_pem.decodeBlock(@embedFile("../quic/testdata/quicz-echo-ca.pem"), "CERTIFICATE", &fixture.cert_der);
        fixture.cert_len = cert.len;
        var trust_der: [1024]u8 = undefined;
        const anchor = try quicz.tls_pem.decodeBlock(trust_pem, "CERTIFICATE", &trust_der);
        try fixture.trust.bytes.appendSlice(std.testing.allocator, anchor);
        try fixture.trust.parseCert(std.testing.allocator, 0, std.Io.Clock.real.now(io).toSeconds());
        return fixture;
    }

    fn deinit(self: *Fixture) void {
        self.trust.deinit(std.testing.allocator);
    }
};

fn initHandedOffServer(io: std.Io, fixture: *const Fixture) !IPv6Server {
    const local = std.Io.net.IpAddress{ .ip6 = .loopback(0) };
    const socket = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    errdefer socket.close(io);
    return IPv6Server.initWithSocket(std.testing.allocator, io, socket, .{
        .port = socket.address.getPort(),
        .alpn = &alpn,
        .cert_der = fixture.cert_der[0..fixture.cert_len],
        .private_key = &private_key,
        .max_connections = 2,
    });
}

fn initHandedOffClient(io: std.Io, port: u16, fixture: *const Fixture) !IPv6Client {
    const local = std.Io.net.IpAddress{ .ip6 = .loopback(0) };
    const socket = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    errdefer socket.close(io);
    return IPv6Client.initWithSocket(std.testing.allocator, io, socket, .{
        .server_host = std.Io.net.Ip6Address.loopback(0).bytes,
        .server_port = port,
        .server_name = "localhost",
        .alpn = &alpn,
        .ca_bundle = &fixture.trust,
        .insecure_skip_verify = false,
    });
}

fn EchoForServer(comptime Server: type) type {
    return struct {
        fn run(connection: Server.ServerConnection) std.Io.Cancelable!void {
            var mutable_connection = connection;
            var stream = mutable_connection.acceptStream() catch return;
            var bytes: [4096]u8 = undefined;
            while (true) {
                const count = stream.receive(&bytes) catch return;
                stream.send(bytes[0..count], count == 0) catch return;
                if (count == 0) {
                    stream.flush() catch return;
                    return;
                }
            }
        }
    };
}

fn TransferForClient(comptime Client: type) type {
    return struct {
        fn run(client: *Client, stream_id: u64, payload: []const u8, done: *std.Io.Event) !void {
            defer done.set(client.io);
            try client.sendOnStream(stream_id, payload, true);
            var actual: [4096]u8 = undefined;
            var received: usize = 0;
            while (received < actual.len) {
                const count = try client.receive(stream_id, actual[received..]);
                if (count == 0) break;
                received += count;
            }
            try std.testing.expectEqualSlices(u8, payload, actual[0..received]);
            var trailing: [1]u8 = undefined;
            try std.testing.expectEqual(@as(usize, 0), try client.receive(stream_id, &trailing));
        }
    };
}

fn exchangeWithDeadline(client: anytype, stream_id: u64, payload: []const u8) !void {
    var done: std.Io.Event = .unset;
    var transfer = try client.io.concurrent(TransferForClient(@TypeOf(client.*)).run, .{ client, stream_id, payload, &done });
    defer _ = transfer.cancel(client.io) catch {};
    try done.waitTimeout(client.io, timeout);
    try transfer.await(client.io);
}

fn receiveUntilCanceled(client: *IPv6Client, stream_id: u64, started: *std.Io.Event) !usize {
    started.set(client.io);
    var bytes: [8]u8 = undefined;
    return client.receive(stream_id, &bytes);
}

test "IPv6 runtime verifies localhost and echoes a stream after socket handoff" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io, @embedFile("../quic/testdata/quicz-echo-ca.pem"));
    defer fixture.deinit();
    var server = try initHandedOffServer(io, &fixture);
    defer server.deinit();
    try server.serve(&EchoForServer(IPv6Server).run);
    var client = try initHandedOffClient(io, server.localPort(), &fixture);
    defer client.deinit();
    const client_port = client.localPort();
    try client.connectWithTimeout(2_000);
    try std.testing.expectEqual(client_port, client.localPort());
    try std.testing.expectEqual(server.localPort(), client.client.path.remote.port);
    try std.testing.expectEqualSlices(u8, &std.Io.net.Ip6Address.loopback(0).bytes, &client.client.path.remote.octets);
    var payload: [4096]u8 = undefined;
    try io.randomSecure(&payload);
    try exchangeWithDeadline(&client, try client.openStream(), &payload);
    client.close();
}

test "IPv4 and IPv6 listeners share pending and active connection capacity" {
    for ([_]bool{ true, false }) |pending_handshake| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();
        var fixture = try Fixture.init(io, @embedFile("../quic/testdata/quicz-echo-ca.pem"));
        defer fixture.deinit();
        var admission = runtime_server.ConnectionAdmission.init(1);

        var server4 = try runtime_server.Server.init(std.testing.allocator, io, .{
            .port = 0,
            .alpn = &alpn,
            .cert_der = fixture.cert_der[0..fixture.cert_len],
            .private_key = &private_key,
            .max_connections = 2,
        });
        var server4_alive = true;
        defer if (server4_alive) server4.deinit();
        try server4.attachConnectionAdmission(&admission);
        try server4.start();

        var server6 = try initHandedOffServer(io, &fixture);
        var server6_alive = true;
        defer if (server6_alive) server6.deinit();
        try server6.attachConnectionAdmission(&admission);
        try server6.serve(&EchoForServer(IPv6Server).run);

        var holder = try runtime_client.Client.init(std.testing.allocator, io, .{
            .server_port = server4.localPort(),
            .server_name = "localhost",
            .alpn = &alpn,
            .ca_bundle = &fixture.trust,
        });
        var holder_alive = true;
        defer if (holder_alive) holder.deinit();
        if (pending_handshake) {
            // Send only a real ClientHello. No receiver can complete this TLS flight.
            var scratch: [8192]u8 = undefined;
            const initial = try holder.client.beginWithRoutePath(0, &scratch);
            defer std.testing.allocator.free(initial.datagram);
            try holder.socket.send(io, &server4.socket.address, initial.datagram);
        } else {
            try holder.connectWithTimeout(2_000);
        }
        try waitForAdmission(io, &admission, 1);

        {
            var blocked = try initHandedOffClient(io, server6.localPort(), &fixture);
            defer blocked.deinit();
            try std.testing.expectError(error.ConnectionTimedOut, blocked.connectWithTimeout(100));
            try std.testing.expectEqual(@as(usize, 1), admission.inUse());
        }

        holder.deinit();
        holder_alive = false;
        server4.deinit();
        server4_alive = false;
        try std.testing.expectEqual(@as(usize, 0), admission.inUse());

        {
            var admitted = try initHandedOffClient(io, server6.localPort(), &fixture);
            defer admitted.deinit();
            try admitted.connectWithTimeout(2_000);
            try std.testing.expectEqual(@as(usize, 1), admission.inUse());
            var payload: [4096]u8 = undefined;
            try io.randomSecure(&payload);
            try exchangeWithDeadline(&admitted, try admitted.openStream(), &payload);
            admitted.close();
        }
        server6.deinit();
        server6_alive = false;
        try std.testing.expectEqual(@as(usize, 0), admission.inUse());
    }
}

fn expectIdleAdmissionRelease(comptime Server: type, comptime Client: type) !void {
    const Handler = struct {
        fn run(connection: Server.ServerConnection) std.Io.Cancelable!void {
            var waiting = connection;
            waiting.waitClosed() catch return;
        }
    };
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io, @embedFile("../quic/testdata/quicz-echo-ca.pem"));
    defer fixture.deinit();
    var admission = runtime_server.ConnectionAdmission.init(1);
    var server = try Server.init(std.testing.allocator, io, .{
        .port = 0,
        .alpn = &alpn,
        .cert_der = fixture.cert_der[0..fixture.cert_len],
        .private_key = &private_key,
        .max_connections = 2,
        .max_idle_timeout_ms = 100,
    });
    defer server.deinit();
    try server.attachConnectionAdmission(&admission);
    try server.serve(&Handler.run);
    const config: Client.Config = if (Client == IPv6Client) .{
        .server_port = server.localPort(),
        .bind_addr = .loopback(0),
        .server_name = "localhost",
        .alpn = &alpn,
        .ca_bundle = &fixture.trust,
    } else .{
        .server_port = server.localPort(),
        .server_name = "localhost",
        .alpn = &alpn,
        .ca_bundle = &fixture.trust,
    };
    var client = try Client.init(std.testing.allocator, io, config);
    var client_alive = true;
    defer if (client_alive) client.deinit();
    try client.connectWithTimeout(2_000);
    try std.testing.expectEqual(@as(usize, 1), admission.inUse());
    // Drop the peer without a QUIC close, then let the server's idle timer retire it.
    client.deinit();
    client_alive = false;
    try waitForAdmission(io, &admission, 0);
    try std.testing.expect(server.started);
    var replacement = try Client.init(std.testing.allocator, io, config);
    defer replacement.deinit();
    try replacement.connectWithTimeout(2_000);
    try std.testing.expectEqual(@as(usize, 1), admission.inUse());
    replacement.close();
}

test "idle retirement releases shared admission without stopping either family listener" {
    try expectIdleAdmissionRelease(runtime_server.Server, runtime_client.Client);
    try expectIdleAdmissionRelease(IPv6Server, IPv6Client);
}

test "IPv4 runtime verifies localhost and echoes a stream through its legacy configuration" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io, @embedFile("../quic/testdata/quicz-echo-ca.pem"));
    defer fixture.deinit();
    var server = try runtime_server.Server.init(std.testing.allocator, io, .{
        .port = 0,
        .alpn = &alpn,
        .cert_der = fixture.cert_der[0..fixture.cert_len],
        .private_key = &private_key,
        .max_connections = 1,
    });
    defer server.deinit();
    try server.serve(&EchoForServer(runtime_server.Server).run);
    var client = try runtime_client.Client.init(std.testing.allocator, io, .{
        .server_port = server.localPort(),
        .server_name = "localhost",
        .alpn = &alpn,
        .ca_bundle = &fixture.trust,
        .insecure_skip_verify = false,
    });
    defer client.deinit();
    try client.connectWithTimeout(2_000);
    var payload: [4096]u8 = undefined;
    try io.randomSecure(&payload);
    try exchangeWithDeadline(&client, try client.openStream(), &payload);
    client.close();
}

test "IPv6 reader cancellation preserves the connection and close releases owned sockets" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io, @embedFile("../quic/testdata/quicz-echo-ca.pem"));
    defer fixture.deinit();
    var server_address: std.Io.net.IpAddress = undefined;
    var client_address: std.Io.net.IpAddress = undefined;
    {
        var server = try initHandedOffServer(io, &fixture);
        defer server.deinit();
        server_address = server.socket.address;
        try server.serve(&EchoForServer(IPv6Server).run);
        var client = try initHandedOffClient(io, server.localPort(), &fixture);
        defer client.deinit();
        client_address = client.socket.address;
        try client.connectWithTimeout(2_000);
        const stream_id = try client.openStream();
        var started: std.Io.Event = .unset;
        var reader = try io.concurrent(receiveUntilCanceled, .{ &client, stream_id, &started });
        defer _ = reader.cancel(io) catch {};
        try started.waitTimeout(io, timeout);
        try std.testing.expectError(error.Canceled, reader.cancel(io));
        var payload: [4096]u8 = undefined;
        try io.randomSecure(&payload);
        try exchangeWithDeadline(&client, stream_id, &payload);
        client.close();
    }
    const rebound_server = try server_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer rebound_server.close(io);
    const rebound_client = try client_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer rebound_client.close(io);
}

test "IPv6 runtime family rejection leaves the handed-off socket with its caller" {
    const io = std.testing.io;
    var fixture = try Fixture.init(io, @embedFile("../quic/testdata/quicz-echo-ca.pem"));
    defer fixture.deinit();
    const local = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    const socket = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    var caller_owns_socket = true;
    defer if (caller_owns_socket) socket.close(io);
    if (IPv6Server.initWithSocket(std.testing.allocator, io, socket, .{
        .port = socket.address.getPort(),
        .alpn = &alpn,
        .cert_der = fixture.cert_der[0..fixture.cert_len],
        .private_key = &private_key,
        .max_connections = 1,
    })) |unexpected| {
        caller_owns_socket = false;
        var server = unexpected;
        server.deinit();
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expectEqual(error.UnsupportedServerSocketFamily, err);
    }
    if (IPv6Client.initWithSocket(std.testing.allocator, io, socket, .{
        .server_port = socket.address.getPort(),
        .alpn = &alpn,
        .ca_bundle = &fixture.trust,
    })) |unexpected| {
        caller_owns_socket = false;
        var client = unexpected;
        client.deinit();
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expectEqual(error.UnsupportedClientSocketFamily, err);
    }
    const peer = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer peer.close(io);
    try peer.send(io, &socket.address, "caller still owns this socket");
    var bytes: [64]u8 = undefined;
    const received = try socket.receiveTimeout(io, &bytes, timeout);
    try std.testing.expectEqualStrings("caller still owns this socket", received.data);
    try std.testing.expectEqual(peer.address.getPort(), received.from.getPort());
}

fn rejectUnrelatedTrust(comptime Server: type, comptime Client: type) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io, @embedFile("../quic/testdata/quicz-client-ca.pem"));
    defer fixture.deinit();
    var server = try Server.init(std.testing.allocator, io, .{
        .port = 0,
        .alpn = &alpn,
        .cert_der = fixture.cert_der[0..fixture.cert_len],
        .private_key = &private_key,
        .max_connections = 1,
    });
    defer server.deinit();
    try server.start();
    const config: Client.Config = if (Client == IPv6Client) .{
        .server_port = server.localPort(),
        .bind_addr = .loopback(0),
        .server_name = "localhost",
        .alpn = &alpn,
        .ca_bundle = &fixture.trust,
        .insecure_skip_verify = false,
    } else .{
        .server_port = server.localPort(),
        .server_name = "localhost",
        .alpn = &alpn,
        .ca_bundle = &fixture.trust,
        .insecure_skip_verify = false,
    };
    var client = try Client.init(std.testing.allocator, io, config);
    defer client.deinit();
    // The TLS backend maps certificate rejection to the existing runtime CryptoError.
    try std.testing.expectError(error.CryptoError, client.connectWithTimeout(2_000));
}

test "IPv4 runtime rejects an unrelated trust anchor" {
    try rejectUnrelatedTrust(runtime_server.Server, runtime_client.Client);
}

test "IPv6 runtime rejects an unrelated trust anchor" {
    try rejectUnrelatedTrust(IPv6Server, IPv6Client);
}

test "legacy runtime fields callbacks and configuration retain their IPv4 shapes" {
    const Client = runtime_client.Client;
    const Server = runtime_server.Server;
    const ServerEndpoint = @TypeOf(@as(Server, undefined).server_ep);
    try std.testing.expect(@TypeOf(@as(Client, undefined).client) == quicz.Tls13ClientEndpoint);
    try std.testing.expect(@TypeOf(@as(Client, undefined).client.path.remote.octets) == [4]u8);
    try std.testing.expect(@TypeOf(@as(ServerEndpoint, undefined).lifecycle) == quicz.EndpointConnectionLifecycle);
    try std.testing.expect(@TypeOf(@as(ServerEndpoint.DatagramPathResult, undefined).path) == quicz.endpoint.Udp4Tuple);
    try std.testing.expect(runtime_server.Stream == Server.Stream);
    try std.testing.expect(runtime_server.ServerConnection == Server.ServerConnection);
    try std.testing.expect(@TypeOf(@as(runtime_server.Stream, undefined).server) == *Server);
    try std.testing.expect(@TypeOf(@as(runtime_server.ServerConnection, undefined).server) == *Server);
    try std.testing.expect(runtime_server.HandlerFn == *const fn (runtime_server.ServerConnection) std.Io.Cancelable!void);
    const client_names = [_][]const u8{
        "server_host",          "server_port", "server_name",     "alpn",                      "ca_bundle",
        "insecure_skip_verify", "version",     "prefer_chacha20", "active_migration_disabled", "keepalive_interval_ms",
    };
    const client_types = .{ [4]u8, u16, []const u8, []const []const u8, ?*const std.crypto.Certificate.Bundle, bool, quicz.packet.Version, bool, bool, u32 };
    const client_fields = @typeInfo(Client.Config).@"struct";
    try std.testing.expectEqual(client_names.len, client_fields.field_names.len);
    inline for (client_fields.field_names, client_fields.field_types, 0..) |name, field_type, index| {
        try std.testing.expectEqualStrings(client_names[index], name);
        try std.testing.expect(field_type == client_types[index]);
    }
    const server_names = [_][]const u8{
        "port",      "alpn",            "cert_der",        "private_key",              "private_key_algorithm",    "prefer_chacha20",              "max_idle_timeout_ms",
        "bind_addr", "max_connections", "punch_responder", "punch_responder_registry", "shared_punch_coordinator", "shared_punch_failure_handler",
    };
    const server_types = .{
        u16,                                                []const []const u8,                                          []const u8,                                                           []const u8,                                                            quicz.tls13.PrivateKeyAlgorithm, bool, u64, ?[4]u8, usize,
        ?quicz.connectivity.punch_responder.PunchResponder, ?*quicz.connectivity.punch_responder.PunchResponderRegistry, ?*quicz.connectivity.shared_punch_coordinator.SharedPunchCoordinator, ?*const fn (quicz.connectivity.shared_punch_coordinator.Failure) void,
    };
    const server_fields = @typeInfo(Server.Config).@"struct";
    try std.testing.expectEqual(server_names.len, server_fields.field_names.len);
    inline for (server_fields.field_names, server_fields.field_types, 0..) |name, field_type, index| {
        try std.testing.expectEqualStrings(server_names[index], name);
        try std.testing.expect(field_type == server_types[index]);
    }
    try std.testing.expect(!@hasField(Client.Config, "server_scope_id"));
    try std.testing.expect(!@hasField(Server.Config, "bind_scope_id"));
}
