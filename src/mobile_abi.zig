//! Stable C entry points for mobile platform adapters.
//!
//! This first boundary exposes only version and capability negotiation. Network,
//! connection, and stream handles will be added after the iOS static-library and
//! Swift import path are proven. Unsupported connectivity features are omitted
//! deliberately so callers cannot mistake QUIC transport support for NAT traversal.

const std = @import("std");
const quicz = @import("quicz");

const Client = quicz.runtime.client.Client;

// iOS does not export the dyld stack-introspection symbol used by Zig's
// default Mach-O panic renderer. The ABI returns explicit status codes for
// recoverable failures; invariant violations terminate without stack I/O.
pub const panic = std.debug.no_panic;

pub const abi_version: u32 = 1;

pub const Capability = enum(u6) {
    stream = 0,
    datagram = 1,
    path_validation = 2,
    migration = 3,
    multipath = 4,
    stun = 5,
    hole_punch = 6,
};

pub const Result = enum(i32) {
    ok = 0,
    invalid_argument = 1,
    allocation_failed = 2,
    open_failed = 3,
    connection_failed = 4,
    stream_failed = 5,
    discovery_failed = 6,
    punch_failed = 7,
    connection_timed_out = 8,
};

pub const Ipv4Endpoint = extern struct {
    address: [4]u8,
    port: u16,
};

pub const PunchConfig = extern struct {
    remote: Ipv4Endpoint,
    key: quicz.connectivity.punch_wire.Key,
    attempt_id: quicz.connectivity.punch_wire.AttemptId,
    nonce: quicz.connectivity.punch_wire.Nonce,
    initial_retry_ms: u32,
    maximum_retry_ms: u32,
    max_attempts: u8,
    reserved: [3]u8,
};

pub const ClientConfig = extern struct {
    server_ipv4: [4]u8,
    server_port: u16,
    allow_migration: u8,
    reserved: u8,
    server_name: ?[*]const u8,
    server_name_length: usize,
    alpn: ?[*]const u8,
    alpn_length: usize,
    ca_certificate_der: ?[*]const u8,
    ca_certificate_der_length: usize,
};

const MobileClient = struct {
    allocator: std.mem.Allocator,
    threaded: std.Io.Threaded,
    server_name: []u8,
    alpn: []u8,
    alpn_list: [1][]const u8,
    ca_bundle: std.crypto.Certificate.Bundle,
    server_endpoint: Ipv4Endpoint,
    client: Client,

    fn create(config: *const ClientConfig, verify_server: bool) !*MobileClient {
        const allocator = std.heap.c_allocator;
        const server_name = requiredBytes(config.server_name, config.server_name_length) orelse return error.InvalidArgument;
        const alpn = requiredBytes(config.alpn, config.alpn_length) orelse return error.InvalidArgument;
        const ca_der = if (verify_server)
            requiredBytes(config.ca_certificate_der, config.ca_certificate_der_length) orelse return error.InvalidArgument
        else
            &.{};
        if (config.server_port == 0 or config.reserved != 0) return error.InvalidArgument;

        const state = try allocator.create(MobileClient);
        errdefer allocator.destroy(state);
        state.allocator = allocator;
        state.threaded = std.Io.Threaded.init(allocator, .{});
        errdefer state.threaded.deinit();
        state.server_name = try allocator.dupe(u8, server_name);
        errdefer allocator.free(state.server_name);
        state.alpn = try allocator.dupe(u8, alpn);
        errdefer allocator.free(state.alpn);
        state.alpn_list = .{state.alpn};
        state.server_endpoint = .{ .address = config.server_ipv4, .port = config.server_port };
        state.ca_bundle = .empty;
        errdefer state.ca_bundle.deinit(allocator);
        if (verify_server) {
            try state.ca_bundle.bytes.appendSlice(allocator, ca_der);
            const now = std.Io.Clock.real.now(state.threaded.io()).toSeconds();
            try state.ca_bundle.parseCert(allocator, 0, now);
        }
        state.client = try Client.init(allocator, state.threaded.io(), .{
            .server_host = config.server_ipv4,
            .server_port = config.server_port,
            .server_name = state.server_name,
            .alpn = &state.alpn_list,
            .ca_bundle = if (verify_server) &state.ca_bundle else null,
            .insecure_skip_verify = !verify_server,
            .active_migration_disabled = config.allow_migration == 0,
        });
        return state;
    }

    fn destroy(self: *MobileClient) void {
        self.client.deinit();
        self.ca_bundle.deinit(self.allocator);
        self.threaded.deinit();
        self.allocator.free(self.server_name);
        self.allocator.free(self.alpn);
        self.allocator.destroy(self);
    }
};

const mobile_client_creation_stack_size = 8 * 1024 * 1024;

const MobileClientCreation = struct {
    config: *const ClientConfig,
    verify_server: bool,
    client: ?*MobileClient = null,
    failure: ?anyerror = null,

    fn run(self: *MobileClientCreation) void {
        self.client = MobileClient.create(self.config, self.verify_server) catch |err| {
            self.failure = err;
            return;
        };
    }
};

/// MobileClient contains the QUIC transport state by value. Debug builds need
/// more stack than Swift concurrency workers provide while constructing that
/// state, so creation uses a short-lived, bounded large-stack thread. The
/// returned client and its std.Io runtime are safe to use from the caller.
fn createMobileClient(config: *const ClientConfig, verify_server: bool) !*MobileClient {
    var creation = MobileClientCreation{
        .config = config,
        .verify_server = verify_server,
    };
    const thread = try std.Thread.spawn(
        .{ .stack_size = mobile_client_creation_stack_size },
        MobileClientCreation.run,
        .{&creation},
    );
    thread.join();
    if (creation.failure) |failure| return failure;
    return creation.client orelse error.ClientCreationFailed;
}

pub fn capabilityMask() u64 {
    return bit(.stream) |
        bit(.datagram) |
        bit(.path_validation) |
        bit(.migration) |
        bit(.multipath) |
        bit(.stun) |
        bit(.hole_punch);
}

fn bit(capability: Capability) u64 {
    return @as(u64, 1) << @intFromEnum(capability);
}

pub export fn quicz_mobile_abi_version() callconv(.c) u32 {
    return abi_version;
}

pub export fn quicz_mobile_capabilities() callconv(.c) u64 {
    return capabilityMask();
}

pub export fn quicz_mobile_client_create_unverified(
    config: ?*const ClientConfig,
    client_out: ?*?*anyopaque,
) callconv(.c) i32 {
    const valid_config = config orelse return code(.invalid_argument);
    const output = client_out orelse return code(.invalid_argument);
    output.* = null;
    const client = createMobileClient(valid_config, false) catch |err| return switch (err) {
        error.InvalidArgument => code(.invalid_argument),
        error.OutOfMemory => code(.allocation_failed),
        else => code(.open_failed),
    };
    output.* = @ptrCast(client);
    return code(.ok);
}

pub export fn quicz_mobile_client_create(
    config: ?*const ClientConfig,
    client_out: ?*?*anyopaque,
) callconv(.c) i32 {
    const valid_config = config orelse return code(.invalid_argument);
    const output = client_out orelse return code(.invalid_argument);
    output.* = null;
    const client = createMobileClient(valid_config, true) catch |err| return switch (err) {
        error.InvalidArgument => code(.invalid_argument),
        error.OutOfMemory => code(.allocation_failed),
        else => code(.open_failed),
    };
    output.* = @ptrCast(client);
    return code(.ok);
}

pub export fn quicz_mobile_client_connect(handle: ?*anyopaque) callconv(.c) i32 {
    const client = clientFromHandle(handle) orelse return code(.invalid_argument);
    client.client.connect() catch return code(.connection_failed);
    return code(.ok);
}

const ConnectOutcome = union(enum) {
    connection: anyerror!void,
    deadline: std.Io.Cancelable!void,
};

fn connectClient(client: *MobileClient) anyerror!void {
    return client.client.connect();
}

fn waitConnectTimeout(io: std.Io, timeout_ms: u32) std.Io.Cancelable!void {
    return std.Io.Timeout.sleep(.{ .duration = .{
        .clock = .awake,
        .raw = .fromMilliseconds(timeout_ms),
    } }, io);
}

pub export fn quicz_mobile_client_connect_timeout(
    handle: ?*anyopaque,
    timeout_ms: u32,
) callconv(.c) i32 {
    const client = clientFromHandle(handle) orelse return code(.invalid_argument);
    if (timeout_ms == 0) return code(.invalid_argument);
    const io = client.threaded.io();
    const Selection = std.Io.Select(ConnectOutcome);
    var selected_buffer: [2]ConnectOutcome = undefined;
    var selection: Selection = .init(io, &selected_buffer);
    defer selection.cancelDiscard();
    selection.concurrent(.connection, connectClient, .{client}) catch
        return code(.connection_failed);
    selection.concurrent(.deadline, waitConnectTimeout, .{ io, timeout_ms }) catch
        return code(.connection_failed);
    const outcome = selection.await() catch return code(.connection_failed);
    return switch (outcome) {
        .connection => |result| if (result) code(.ok) else |_| code(.connection_failed),
        .deadline => |deadline| if (deadline) code(.connection_timed_out) else |_| code(.connection_failed),
    };
}

pub export fn quicz_mobile_client_bound_ipv4(
    handle: ?*anyopaque,
    endpoint_out: ?*Ipv4Endpoint,
) callconv(.c) i32 {
    const client = clientFromHandle(handle) orelse return code(.invalid_argument);
    const output = endpoint_out orelse return code(.invalid_argument);
    const address = switch (client.client.socket.address) {
        .ip4 => |endpoint| endpoint,
        .ip6 => return code(.open_failed),
    };
    output.* = .{ .address = address.bytes, .port = address.port };
    return code(.ok);
}

pub export fn quicz_mobile_client_discover_ipv4(
    handle: ?*anyopaque,
    stun_server: ?*const Ipv4Endpoint,
    timeout_ms: u32,
    max_attempts: u8,
    mapped_endpoint_out: ?*Ipv4Endpoint,
) callconv(.c) i32 {
    const client = clientFromHandle(handle) orelse return code(.invalid_argument);
    const server = stun_server orelse return code(.invalid_argument);
    const output = mapped_endpoint_out orelse return code(.invalid_argument);
    const server_address = std.Io.net.IpAddress{ .ip4 = .{
        .bytes = server.address,
        .port = server.port,
    } };
    const mapped = client.client.discoverReflexiveAddress(server_address, .{
        .timeout_ms = timeout_ms,
        .max_attempts = max_attempts,
    }) catch return code(.discovery_failed);
    switch (mapped) {
        .ipv4 => |endpoint| output.* = .{ .address = endpoint.address, .port = endpoint.port },
        .ipv6 => return code(.discovery_failed),
    }
    return code(.ok);
}

pub export fn quicz_mobile_client_punch_ipv4(
    handle: ?*anyopaque,
    config: ?*const PunchConfig,
) callconv(.c) i32 {
    const client = clientFromHandle(handle) orelse return code(.invalid_argument);
    const valid_config = config orelse return code(.invalid_argument);
    if (!std.mem.allEqual(u8, &valid_config.reserved, 0) or
        !std.mem.eql(u8, &valid_config.remote.address, &client.server_endpoint.address) or
        valid_config.remote.port != client.server_endpoint.port) return code(.invalid_argument);
    var attempt = quicz.connectivity.punch_attempt.PunchAttempt.init(
        valid_config.key,
        valid_config.attempt_id,
        valid_config.nonce,
        .{
            .initial_retry_ms = valid_config.initial_retry_ms,
            .maximum_retry_ms = valid_config.maximum_retry_ms,
            .max_attempts = valid_config.max_attempts,
        },
    ) catch return code(.invalid_argument);
    const remote = std.Io.net.IpAddress{ .ip4 = .{
        .bytes = valid_config.remote.address,
        .port = valid_config.remote.port,
    } };
    quicz.connectivity.punch_driver.runUntilValidated(
        client.client.io,
        client.client.socket,
        remote,
        &attempt,
    ) catch return code(.punch_failed);
    const responder_lifetime_ms = std.math.mul(u32, valid_config.maximum_retry_ms, 2) catch
        return code(.invalid_argument);
    var responder = quicz.connectivity.punch_responder.PunchResponder.init(
        valid_config.key,
        valid_config.attempt_id,
        valid_config.nonce,
        remote,
        @intCast(std.Io.Timestamp.now(client.client.io, .awake).nanoseconds),
        responder_lifetime_ms,
    ) catch return code(.punch_failed);
    defer responder.deinit();
    client.client.retainPunchResponder(responder) catch return code(.punch_failed);
    return code(.ok);
}

pub export fn quicz_mobile_client_open_bidi(
    handle: ?*anyopaque,
    stream_id_out: ?*u64,
) callconv(.c) i32 {
    const client = clientFromHandle(handle) orelse return code(.invalid_argument);
    const output = stream_id_out orelse return code(.invalid_argument);
    output.* = client.client.openStream() catch return code(.stream_failed);
    return code(.ok);
}

pub export fn quicz_mobile_client_set_keepalive_interval(
    handle: ?*anyopaque,
    interval_ms: u32,
) callconv(.c) i32 {
    const client = clientFromHandle(handle) orelse return code(.invalid_argument);
    client.client.setKeepaliveInterval(interval_ms) catch return code(.invalid_argument);
    return code(.ok);
}

pub export fn quicz_mobile_client_send(
    handle: ?*anyopaque,
    stream_id: u64,
    bytes: ?[*]const u8,
    length: usize,
    finish: u8,
) callconv(.c) i32 {
    const client = clientFromHandle(handle) orelse return code(.invalid_argument);
    const payload = optionalBytes(bytes, length) orelse return code(.invalid_argument);
    client.client.sendOnStream(stream_id, payload, finish != 0) catch return code(.stream_failed);
    return code(.ok);
}

pub export fn quicz_mobile_client_receive(
    handle: ?*anyopaque,
    stream_id: u64,
    buffer: ?[*]u8,
    capacity: usize,
    received_out: ?*usize,
) callconv(.c) i32 {
    const client = clientFromHandle(handle) orelse return code(.invalid_argument);
    const output = received_out orelse return code(.invalid_argument);
    output.* = 0;
    if (capacity == 0) return code(.invalid_argument);
    const destination = buffer orelse return code(.invalid_argument);
    output.* = client.client.receive(stream_id, destination[0..capacity]) catch return code(.stream_failed);
    return code(.ok);
}

pub export fn quicz_mobile_client_close(handle: ?*anyopaque) callconv(.c) void {
    const client = clientFromHandle(handle) orelse return;
    client.client.close();
}

pub export fn quicz_mobile_client_destroy(handle: ?*anyopaque) callconv(.c) void {
    const client = clientFromHandle(handle) orelse return;
    client.destroy();
}

fn clientFromHandle(handle: ?*anyopaque) ?*MobileClient {
    const pointer = handle orelse return null;
    return @ptrCast(@alignCast(pointer));
}

fn requiredBytes(pointer: ?[*]const u8, length: usize) ?[]const u8 {
    if (length == 0) return null;
    return (pointer orelse return null)[0..length];
}

fn optionalBytes(pointer: ?[*]const u8, length: usize) ?[]const u8 {
    if (length == 0) return &.{};
    return (pointer orelse return null)[0..length];
}

fn code(result: Result) i32 {
    return @intFromEnum(result);
}

test "mobile ABI reports only implemented transport capabilities" {
    try std.testing.expectEqual(@as(u32, 1), quicz_mobile_abi_version());
    try std.testing.expectEqual(@as(u64, 0x7f), quicz_mobile_capabilities());
}

test "mobile client ABI rejects incomplete configuration" {
    var client: ?*anyopaque = undefined;
    const config = ClientConfig{
        .server_ipv4 = .{ 127, 0, 0, 1 },
        .server_port = 0,
        .allow_migration = 0,
        .reserved = 0,
        .server_name = null,
        .server_name_length = 0,
        .alpn = null,
        .alpn_length = 0,
        .ca_certificate_der = null,
        .ca_certificate_der_length = 0,
    };
    try std.testing.expectEqual(code(.invalid_argument), quicz_mobile_client_create_unverified(&config, &client));
    try std.testing.expect(client == null);
}

test "mobile client ABI configures keepalive without changing ABI version" {
    try std.testing.expectEqual(
        code(.invalid_argument),
        quicz_mobile_client_set_keepalive_interval(null, 10_000),
    );
    const server_name = "localhost";
    const alpn = "quicz-mobile-keepalive-test";
    var config = ClientConfig{
        .server_ipv4 = .{ 127, 0, 0, 1 },
        .server_port = 4433,
        .allow_migration = 0,
        .reserved = 0,
        .server_name = server_name.ptr,
        .server_name_length = server_name.len,
        .alpn = alpn.ptr,
        .alpn_length = alpn.len,
        .ca_certificate_der = null,
        .ca_certificate_der_length = 0,
    };
    var client: ?*anyopaque = null;
    try std.testing.expectEqual(code(.ok), quicz_mobile_client_create_unverified(&config, &client));
    defer quicz_mobile_client_destroy(client);
    try std.testing.expectEqual(
        code(.ok),
        quicz_mobile_client_set_keepalive_interval(client, 10_000),
    );
    try std.testing.expectEqual(@as(u32, 1), quicz_mobile_abi_version());
}

const SmallStackCreateContext = struct {
    config: ClientConfig,
    result: i32 = code(.open_failed),
};

fn createClientFromSmallStack(context: *SmallStackCreateContext) void {
    var client: ?*anyopaque = null;
    context.result = quicz_mobile_client_create_unverified(&context.config, &client);
    if (client) |handle| quicz_mobile_client_destroy(handle);
}

test "mobile client creation is safe on a 512 KiB caller stack" {
    const server_name = "localhost";
    const alpn = "quicz-mobile-stack-test";
    var context = SmallStackCreateContext{ .config = .{
        .server_ipv4 = .{ 127, 0, 0, 1 },
        .server_port = 4433,
        .allow_migration = 0,
        .reserved = 0,
        .server_name = server_name.ptr,
        .server_name_length = server_name.len,
        .alpn = alpn.ptr,
        .alpn_length = alpn.len,
        .ca_certificate_der = null,
        .ca_certificate_der_length = 0,
    } };
    const thread = try std.Thread.spawn(
        .{ .stack_size = 512 * 1024 },
        createClientFromSmallStack,
        .{&context},
    );
    thread.join();
    try std.testing.expectEqual(code(.ok), context.result);
}

test "mobile client connect timeout bounds a silent UDP peer" {
    var silent_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    const silent_socket = try silent_address.bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer silent_socket.close(std.testing.io);
    const server_name = "localhost";
    const alpn = "quicz-mobile-timeout-test";
    var config = ClientConfig{
        .server_ipv4 = .{ 127, 0, 0, 1 },
        .server_port = silent_socket.address.ip4.port,
        .allow_migration = 0,
        .reserved = 0,
        .server_name = server_name.ptr,
        .server_name_length = server_name.len,
        .alpn = alpn.ptr,
        .alpn_length = alpn.len,
        .ca_certificate_der = null,
        .ca_certificate_der_length = 0,
    };
    var client: ?*anyopaque = null;
    try std.testing.expectEqual(code(.ok), quicz_mobile_client_create_unverified(&config, &client));
    defer quicz_mobile_client_destroy(client);
    try std.testing.expectEqual(
        code(.connection_timed_out),
        quicz_mobile_client_connect_timeout(client, 10),
    );
}

fn respondToMobileStun(socket: *std.Io.net.Socket) std.Io.Cancelable!void {
    const stun = quicz.connectivity.stun;
    var buffer: [64]u8 = undefined;
    const request = socket.receiveTimeout(std.testing.io, &buffer, .{ .duration = .{
        .clock = .awake,
        .raw = .fromMilliseconds(1_000),
    } }) catch return;
    const transaction_id = stun.decodeBindingRequest(request.data) catch return;
    const observed = switch (request.from) {
        .ip4 => |address| address,
        .ip6 => return,
    };
    const response = stun.encodeBindingSuccessIpv4(transaction_id, observed.bytes, observed.port);
    var destination = request.from;
    socket.send(std.testing.io, &destination, &response) catch return;
}

test "mobile ABI discovers the mapping of its existing UDP socket" {
    const server_name = "localhost";
    const alpn = "quicz-mobile-stun-test";
    var config = ClientConfig{
        .server_ipv4 = .{ 127, 0, 0, 1 },
        .server_port = 4433,
        .allow_migration = 0,
        .reserved = 0,
        .server_name = server_name.ptr,
        .server_name_length = server_name.len,
        .alpn = alpn.ptr,
        .alpn_length = alpn.len,
        .ca_certificate_der = null,
        .ca_certificate_der_length = 0,
    };
    var client: ?*anyopaque = null;
    try std.testing.expectEqual(code(.ok), quicz_mobile_client_create_unverified(&config, &client));
    defer quicz_mobile_client_destroy(client);
    var bound = Ipv4Endpoint{ .address = @splat(0), .port = 0 };
    try std.testing.expectEqual(code(.ok), quicz_mobile_client_bound_ipv4(client, &bound));

    var stun_address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    var stun_socket = try stun_address.bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer stun_socket.close(std.testing.io);
    var responder = try std.testing.io.concurrent(respondToMobileStun, .{&stun_socket});
    defer responder.cancel(std.testing.io) catch {};
    const stun_server = Ipv4Endpoint{
        .address = stun_socket.address.ip4.bytes,
        .port = stun_socket.address.ip4.port,
    };
    var mapped = Ipv4Endpoint{ .address = @splat(0), .port = 0 };
    try std.testing.expectEqual(
        code(.ok),
        quicz_mobile_client_discover_ipv4(client, &stun_server, 1_000, 1, &mapped),
    );
    try responder.await(std.testing.io);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, mapped.address);
    try std.testing.expectEqual(bound.port, mapped.port);
}
