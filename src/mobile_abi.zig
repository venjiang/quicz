//! Stable C entry points for mobile platform adapters.
//!
//! This first boundary exposes only version and capability negotiation. Network,
//! connection, and stream handles will be added after the iOS static-library and
//! Swift import path are proven. Unsupported connectivity features are omitted
//! deliberately so callers cannot mistake QUIC transport support for NAT traversal.

const std = @import("std");
const builtin = @import("builtin");
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

/// Additive capability bit without extending the legacy closed Zig enum.
pub const native_ipv6_capability_bit: u64 = @as(u64, 1) << 7;

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

pub const PunchOutcome = enum(u32) {
    not_started = 0,
    validated = 1,
    retry_exhausted = 2,
    canceled = 3,
    io_failed = 4,
};

/// Per-call, address-free proof diagnostics. No identity or packet contents.
pub const PunchDiagnostics = extern struct {
    duration_ms: u64 = 0,
    outcome: u32 = @intFromEnum(PunchOutcome.not_started),
    probes_sent: u32 = 0,
    acks_sent: u32 = 0,
    datagrams_received: u32 = 0,
    source_rejected: u32 = 0,
    oversized_received: u32 = 0,
    packets_checked: u32 = 0,
    malformed_rejected: u32 = 0,
    authentication_rejected: u32 = 0,
    attempt_rejected: u32 = 0,
    nonce_rejected: u32 = 0,
    peer_probe: u8 = 0,
    local_ack: u8 = 0,
    reserved: [2]u8 = @splat(0),
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

/// Scope-zero native IPv6 endpoint used by the additive C ABI.
pub const Ipv6Endpoint = extern struct {
    address: [16]u8,
    port: u16,
    reserved: u16,
    scope_id: u32,
};

/// Explicit local/remote IPv6 configuration with verified server trust.
pub const Client6Config = extern struct {
    local: Ipv6Endpoint,
    remote: Ipv6Endpoint,
    server_name: ?[*]const u8,
    server_name_length: usize,
    alpn: ?[*]const u8,
    alpn_length: usize,
    ca_certificate_der: ?[*]const u8,
    ca_certificate_der_length: usize,
};

/// IPv6 punch configuration with the unchanged authentication and retry fields.
pub const Punch6Config = extern struct {
    remote: Ipv6Endpoint,
    key: quicz.connectivity.punch_wire.Key,
    attempt_id: quicz.connectivity.punch_wire.AttemptId,
    nonce: quicz.connectivity.punch_wire.Nonce,
    initial_retry_ms: u32,
    maximum_retry_ms: u32,
    max_attempts: u8,
    reserved: [3]u8,
};

fn ConfigForTuple(comptime Path: type) type {
    return if (Path == quicz.endpoint.Udp4Tuple) ClientConfig else Client6Config;
}

fn MobileStateForTuple(comptime Path: type) type {
    const is_ipv6 = Path == quicz.endpoint.Udp6Tuple;
    const RuntimeClient = if (is_ipv6) quicz.runtime.client.IPv6Client else Client;
    const Endpoint = if (is_ipv6) Ipv6Endpoint else Ipv4Endpoint;
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        threaded: std.Io.Threaded,
        server_name: []u8,
        alpn: []u8,
        alpn_list: [1][]const u8,
        ca_bundle: std.crypto.Certificate.Bundle,
        server_endpoint: Endpoint,
        client: RuntimeClient,
        closed: std.atomic.Value(bool),
        close_event: std.Io.Event,

        fn create(config: *const ConfigForTuple(Path), verify_server: bool) !*Self {
            const allocator = std.heap.c_allocator;
            const server_name = requiredBytes(config.server_name, config.server_name_length) orelse return error.InvalidArgument;
            const alpn = requiredBytes(config.alpn, config.alpn_length) orelse return error.InvalidArgument;
            const ca_der = if (verify_server)
                requiredBytes(config.ca_certificate_der, config.ca_certificate_der_length) orelse return error.InvalidArgument
            else
                &.{};
            if (is_ipv6) {
                if (!verify_server or !validIpv6Endpoint(config.local, true) or
                    !validIpv6Endpoint(config.remote, false)) return error.InvalidArgument;
            } else {
                if (config.server_port == 0 or config.reserved != 0) return error.InvalidArgument;
            }

            const state = try allocator.create(Self);
            errdefer allocator.destroy(state);
            state.allocator = allocator;
            state.closed = .init(false);
            state.close_event = .unset;
            state.threaded = std.Io.Threaded.init(allocator, .{});
            errdefer state.threaded.deinit();
            state.server_name = try allocator.dupe(u8, server_name);
            errdefer allocator.free(state.server_name);
            state.alpn = try allocator.dupe(u8, alpn);
            errdefer allocator.free(state.alpn);
            state.alpn_list = .{state.alpn};
            state.server_endpoint = if (is_ipv6) config.remote else .{
                .address = config.server_ipv4,
                .port = config.server_port,
            };
            state.ca_bundle = .empty;
            errdefer state.ca_bundle.deinit(allocator);
            if (verify_server) {
                try state.ca_bundle.bytes.appendSlice(allocator, ca_der);
                const now = std.Io.Clock.real.now(state.threaded.io()).toSeconds();
                try state.ca_bundle.parseCert(allocator, 0, now);
            }
            const runtime_config: RuntimeClient.Config = if (is_ipv6) .{
                .server_host = config.remote.address,
                .server_port = config.remote.port,
                .server_scope_id = config.remote.scope_id,
                .bind_addr = .{ .bytes = config.local.address, .port = config.local.port },
                .server_name = state.server_name,
                .alpn = &state.alpn_list,
                .ca_bundle = &state.ca_bundle,
                .insecure_skip_verify = false,
                .active_migration_disabled = true,
            } else .{
                .server_host = config.server_ipv4,
                .server_port = config.server_port,
                .server_name = state.server_name,
                .alpn = &state.alpn_list,
                .ca_bundle = if (verify_server) &state.ca_bundle else null,
                .insecure_skip_verify = !verify_server,
                .active_migration_disabled = config.allow_migration == 0,
            };
            state.client = try RuntimeClient.init(allocator, state.threaded.io(), runtime_config);
            return state;
        }

        fn punchUntilValidated(self: *Self, remote: std.Io.net.IpAddress, attempt: *quicz.connectivity.punch_attempt.PunchAttempt) !void {
            if (self.closed.load(.acquire)) return error.Canceled;
            const Completion = union(enum) {
                punch: anyerror!void,
                closed: std.Io.Cancelable!void,
            };
            var completions: [2]Completion = undefined;
            var select = std.Io.Select(Completion).init(self.threaded.io(), &completions);
            defer select.cancelDiscard();
            try select.concurrent(.closed, std.Io.Event.wait, .{ &self.close_event, self.threaded.io() });
            try select.concurrent(.punch, runCancelablePunch, .{ self.threaded.io(), self.client.socket, remote, attempt });
            const completion = try select.await();
            // Join the socket reader before diagnostics or responder handoff.
            select.cancelDiscard();
            if (self.closed.load(.acquire)) return error.Canceled;
            switch (completion) {
                .punch => |result| try result,
                .closed => return error.Canceled,
            }
        }

        fn destroy(self: *Self) void {
            self.client.deinit();
            self.ca_bundle.deinit(self.allocator);
            self.threaded.deinit();
            self.allocator.free(self.server_name);
            self.allocator.free(self.alpn);
            self.allocator.destroy(self);
        }
    };
}

// Both constructors return this owner. The payloads retain stable addresses
// for native I/O, borrowed CA configuration, and in-flight blocking calls.
const MobileOwner = union(enum) {
    ipv4: *MobileStateForTuple(quicz.endpoint.Udp4Tuple),
    ipv6: *MobileStateForTuple(quicz.endpoint.Udp6Tuple),

    fn destroy(self: *MobileOwner) void {
        switch (self.*) {
            inline else => |state| state.destroy(),
        }
        std.heap.c_allocator.destroy(self);
    }
};

fn runCancelablePunch(io: std.Io, socket: std.Io.net.Socket, remote: std.Io.net.IpAddress, attempt: *quicz.connectivity.punch_attempt.PunchAttempt) !void {
    // Hosted Darwin callers may mask the signal used by Threaded to interrupt
    // recvmsg. Change only this owned worker and restore its inherited mask.
    var previous: std.posix.sigset_t = undefined;
    if (comptime builtin.os.tag.isDarwin()) {
        var cancel_signal = std.posix.sigemptyset();
        std.posix.sigaddset(&cancel_signal, .IO);
        std.posix.sigprocmask(std.posix.SIG.UNBLOCK, &cancel_signal, &previous);
    }
    defer if (comptime builtin.os.tag.isDarwin()) {
        std.posix.sigprocmask(std.posix.SIG.SETMASK, &previous, null);
    };
    try quicz.connectivity.punch_driver.runUntilValidated(io, socket, remote, attempt);
}

const mobile_client_creation_stack_size = 8 * 1024 * 1024;

fn MobileStateCreationForTuple(comptime Path: type) type {
    return struct {
        const Self = @This();
        config: *const ConfigForTuple(Path),
        verify_server: bool,
        state: ?*MobileStateForTuple(Path) = null,
        failure: ?anyerror = null,

        fn run(self: *Self) void {
            self.state = MobileStateForTuple(Path).create(self.config, self.verify_server) catch |err| {
                self.failure = err;
                return;
            };
        }
    };
}

// Construct the by-value QUIC state on the same bounded large stack used by
// the IPv4 ABI. No initialized state or I/O runtime moves between owners.
fn createMobileClient(comptime Path: type, config: *const ConfigForTuple(Path), verify_server: bool) !*MobileOwner {
    const owner = try std.heap.c_allocator.create(MobileOwner);
    errdefer std.heap.c_allocator.destroy(owner);
    const Creation = MobileStateCreationForTuple(Path);
    var creation = Creation{ .config = config, .verify_server = verify_server };
    const thread = try std.Thread.spawn(
        .{ .stack_size = mobile_client_creation_stack_size },
        Creation.run,
        .{&creation},
    );
    thread.join();
    if (creation.failure) |failure| return failure;
    const state = creation.state orelse return error.ClientCreationFailed;
    owner.* = if (Path == quicz.endpoint.Udp4Tuple) .{ .ipv4 = state } else .{ .ipv6 = state };
    return owner;
}

fn validIpv6Endpoint(value: Ipv6Endpoint, allow_zero_port: bool) bool {
    if (value.reserved != 0 or value.scope_id != 0 or (!allow_zero_port and value.port == 0)) return false;
    const loopback = std.Io.net.Ip6Address.loopback(0).bytes;
    return value.address[0] & 0xe0 == 0x20 or std.mem.eql(u8, &value.address, &loopback);
}

pub fn capabilityMask() u64 {
    return bit(.stream) |
        bit(.datagram) |
        bit(.path_validation) |
        bit(.migration) |
        bit(.multipath) |
        bit(.stun) |
        bit(.hole_punch) |
        native_ipv6_capability_bit;
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
    const client = createMobileClient(quicz.endpoint.Udp4Tuple, valid_config, false) catch |err| return switch (err) {
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
    const client = createMobileClient(quicz.endpoint.Udp4Tuple, valid_config, true) catch |err| return switch (err) {
        error.InvalidArgument => code(.invalid_argument),
        error.OutOfMemory => code(.allocation_failed),
        else => code(.open_failed),
    };
    output.* = @ptrCast(client);
    return code(.ok);
}

pub export fn quicz_mobile_client_create_ipv6(
    config: ?*const Client6Config,
    client_out: ?*?*anyopaque,
) callconv(.c) i32 {
    const output = client_out orelse return code(.invalid_argument);
    output.* = null;
    const valid_config = config orelse return code(.invalid_argument);
    const owner = createMobileClient(quicz.endpoint.Udp6Tuple, valid_config, true) catch |err| return switch (err) {
        error.InvalidArgument => code(.invalid_argument),
        error.OutOfMemory => code(.allocation_failed),
        else => code(.open_failed),
    };
    output.* = @ptrCast(owner);
    return code(.ok);
}

pub export fn quicz_mobile_client_connect(handle: ?*anyopaque) callconv(.c) i32 {
    const client = clientFromHandle(handle) orelse return code(.invalid_argument);
    switch (client.*) {
        inline else => |state| {
            if (state.closed.load(.acquire)) return code(.connection_failed);
            state.client.connect() catch return code(.connection_failed);
        },
    }
    return code(.ok);
}

pub export fn quicz_mobile_client_connect_timeout(
    handle: ?*anyopaque,
    timeout_ms: u32,
) callconv(.c) i32 {
    const client = clientFromHandle(handle) orelse return code(.invalid_argument);
    if (timeout_ms == 0) return code(.invalid_argument);
    switch (client.*) {
        inline else => |state| {
            if (state.closed.load(.acquire)) return code(.connection_failed);
            state.client.connectWithTimeout(timeout_ms) catch |err| return switch (err) {
                error.ConnectionTimedOut => code(.connection_timed_out),
                else => code(.connection_failed),
            };
        },
    }
    return code(.ok);
}

pub export fn quicz_mobile_client_bound_ipv4(
    handle: ?*anyopaque,
    endpoint_out: ?*Ipv4Endpoint,
) callconv(.c) i32 {
    const client = stateFromHandle(quicz.endpoint.Udp4Tuple, handle) orelse return code(.invalid_argument);
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
    const client = stateFromHandle(quicz.endpoint.Udp4Tuple, handle) orelse return code(.invalid_argument);
    if (client.closed.load(.acquire)) return code(.discovery_failed);
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

pub export fn quicz_mobile_client_bound_ipv6(
    handle: ?*anyopaque,
    endpoint_out: ?*Ipv6Endpoint,
) callconv(.c) i32 {
    const state = stateFromHandle(quicz.endpoint.Udp6Tuple, handle) orelse return code(.invalid_argument);
    const output = endpoint_out orelse return code(.invalid_argument);
    const address = switch (state.client.socket.address) {
        .ip4 => return code(.open_failed),
        .ip6 => |value| value,
    };
    output.* = .{ .address = address.bytes, .port = address.port, .reserved = 0, .scope_id = address.interface.index };
    return code(.ok);
}

pub export fn quicz_mobile_client_discover_ipv6(
    handle: ?*anyopaque,
    stun_server: ?*const Ipv6Endpoint,
    timeout_ms: u32,
    max_attempts: u8,
    mapped_endpoint_out: ?*Ipv6Endpoint,
) callconv(.c) i32 {
    const state = stateFromHandle(quicz.endpoint.Udp6Tuple, handle) orelse return code(.invalid_argument);
    if (state.closed.load(.acquire)) return code(.discovery_failed);
    const server = stun_server orelse return code(.invalid_argument);
    const output = mapped_endpoint_out orelse return code(.invalid_argument);
    if (!validIpv6Endpoint(server.*, false)) return code(.invalid_argument);
    const server_address = std.Io.net.IpAddress{ .ip6 = .{ .bytes = server.address, .port = server.port } };
    const mapped = state.client.discoverReflexiveAddress(server_address, .{
        .timeout_ms = timeout_ms,
        .max_attempts = max_attempts,
    }) catch return code(.discovery_failed);
    switch (mapped) {
        .ipv4 => return code(.discovery_failed),
        .ipv6 => |value| {
            const endpoint_value: Ipv6Endpoint = .{ .address = value.address, .port = value.port, .reserved = 0, .scope_id = 0 };
            if (!validIpv6Endpoint(endpoint_value, false)) return code(.discovery_failed);
            output.* = endpoint_value;
        },
    }
    return code(.ok);
}

pub export fn quicz_mobile_client_punch_ipv4(
    handle: ?*anyopaque,
    config: ?*const PunchConfig,
) callconv(.c) i32 {
    return punchForTuple(quicz.endpoint.Udp4Tuple, handle, config, null);
}

/// The snapshot describes UDP proof, not the subsequent QUIC handshake.
pub export fn quicz_mobile_client_punch_ipv4_with_diagnostics(
    handle: ?*anyopaque,
    config: ?*const PunchConfig,
    diagnostics_out: ?*PunchDiagnostics,
) callconv(.c) i32 {
    const output = diagnostics_out orelse return code(.invalid_argument);
    output.* = .{};
    return punchForTuple(quicz.endpoint.Udp4Tuple, handle, config, output);
}

pub export fn quicz_mobile_client_punch_ipv6(
    handle: ?*anyopaque,
    config: ?*const Punch6Config,
) callconv(.c) i32 {
    return punchForTuple(quicz.endpoint.Udp6Tuple, handle, config, null);
}

pub export fn quicz_mobile_client_punch_ipv6_with_diagnostics(
    handle: ?*anyopaque,
    config: ?*const Punch6Config,
    diagnostics_out: ?*PunchDiagnostics,
) callconv(.c) i32 {
    const output = diagnostics_out orelse return code(.invalid_argument);
    output.* = .{};
    return punchForTuple(quicz.endpoint.Udp6Tuple, handle, config, output);
}

fn PunchConfigForTuple(comptime Path: type) type {
    return if (Path == quicz.endpoint.Udp4Tuple) PunchConfig else Punch6Config;
}

fn punchForTuple(comptime Path: type, handle: ?*anyopaque, config: ?*const PunchConfigForTuple(Path), diagnostics_out: ?*PunchDiagnostics) i32 {
    const client = stateFromHandle(Path, handle) orelse return code(.invalid_argument);
    const valid_config = config orelse return code(.invalid_argument);
    if (!std.mem.allEqual(u8, &valid_config.reserved, 0) or
        !std.mem.eql(u8, &valid_config.remote.address, &client.server_endpoint.address) or
        valid_config.remote.port != client.server_endpoint.port) return code(.invalid_argument);
    if (Path == quicz.endpoint.Udp6Tuple and !validIpv6Endpoint(valid_config.remote, false)) return code(.invalid_argument);
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
    const remote: std.Io.net.IpAddress = if (Path == quicz.endpoint.Udp4Tuple) .{ .ip4 = .{
        .bytes = valid_config.remote.address,
        .port = valid_config.remote.port,
    } } else .{ .ip6 = .{
        .bytes = valid_config.remote.address,
        .port = valid_config.remote.port,
    } };
    const started = std.Io.Timestamp.now(client.client.io, .awake);
    var outcome: PunchOutcome = .not_started;
    defer if (diagnostics_out) |output| {
        const counters = attempt.diagnostics;
        const elapsed = started.durationTo(std.Io.Timestamp.now(client.client.io, .awake)).toMilliseconds();
        output.* = .{
            .duration_ms = @intCast(@max(0, elapsed)),
            .outcome = @intFromEnum(outcome),
            .probes_sent = counters.probe_sends,
            .acks_sent = counters.acknowledgement_sends,
            .datagrams_received = counters.datagrams_received,
            .source_rejected = counters.source_rejected,
            .oversized_received = counters.oversized_received,
            .packets_checked = counters.packets_checked,
            .malformed_rejected = counters.malformed_rejected,
            .authentication_rejected = counters.authentication_rejected,
            .attempt_rejected = counters.attempt_rejected,
            .nonce_rejected = counters.nonce_rejected,
            .peer_probe = @intFromBool(attempt.peer_probe_received),
            .local_ack = @intFromBool(attempt.local_probe_acknowledged),
        };
    };
    client.punchUntilValidated(remote, &attempt) catch |err| {
        outcome = switch (err) {
            error.PunchFailed => .retry_exhausted,
            error.Canceled => .canceled,
            else => .io_failed,
        };
        return code(.punch_failed);
    };
    outcome = .validated;
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
    switch (client.*) {
        inline else => |state| {
            if (state.closed.load(.acquire)) return code(.stream_failed);
            output.* = state.client.openStream() catch return code(.stream_failed);
        },
    }
    return code(.ok);
}

pub export fn quicz_mobile_client_set_keepalive_interval(
    handle: ?*anyopaque,
    interval_ms: u32,
) callconv(.c) i32 {
    const client = clientFromHandle(handle) orelse return code(.invalid_argument);
    switch (client.*) {
        inline else => |state| {
            if (state.closed.load(.acquire)) return code(.invalid_argument);
            state.client.setKeepaliveInterval(interval_ms) catch return code(.invalid_argument);
        },
    }
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
    switch (client.*) {
        inline else => |state| {
            if (state.closed.load(.acquire)) return code(.stream_failed);
            state.client.sendOnStream(stream_id, payload, finish != 0) catch return code(.stream_failed);
        },
    }
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
    switch (client.*) {
        inline else => |state| {
            if (state.closed.load(.acquire)) return code(.stream_failed);
            output.* = state.client.receive(stream_id, destination[0..capacity]) catch return code(.stream_failed);
        },
    }
    return code(.ok);
}

pub export fn quicz_mobile_client_close(handle: ?*anyopaque) callconv(.c) void {
    const client = clientFromHandle(handle) orelse return;
    switch (client.*) {
        inline else => |state| {
            state.closed.store(true, .release);
            state.close_event.set(state.threaded.io());
            state.client.close();
        },
    }
}

pub export fn quicz_mobile_client_destroy(handle: ?*anyopaque) callconv(.c) void {
    const client = clientFromHandle(handle) orelse return;
    client.destroy();
}

fn clientFromHandle(handle: ?*anyopaque) ?*MobileOwner {
    const pointer = handle orelse return null;
    return @ptrCast(@alignCast(pointer));
}

fn stateFromHandle(comptime Path: type, handle: ?*anyopaque) ?*MobileStateForTuple(Path) {
    const owner = clientFromHandle(handle) orelse return null;
    return if (Path == quicz.endpoint.Udp4Tuple) switch (owner.*) {
        .ipv4 => |state| state,
        .ipv6 => null,
    } else switch (owner.*) {
        .ipv4 => null,
        .ipv6 => |state| state,
    };
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
    try std.testing.expectEqual(@as(u64, 0xff), quicz_mobile_capabilities());
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

test "mobile punch diagnostics retain silent peer counters on failure" {
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    const silent = try address.bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer silent.close(std.testing.io);
    const server_name = "localhost";
    const alpn = "quicz-mobile-punch-test";
    const config = ClientConfig{
        .server_ipv4 = .{ 127, 0, 0, 1 },
        .server_port = silent.address.ip4.port,
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
    const punch = PunchConfig{
        .remote = .{ .address = .{ 127, 0, 0, 1 }, .port = silent.address.ip4.port },
        .key = @splat(0x42),
        .attempt_id = @splat(0x11),
        .nonce = @splat(0x21),
        .initial_retry_ms = 10,
        .maximum_retry_ms = 10,
        .max_attempts = 1,
        .reserved = @splat(0),
    };
    var diagnostics: PunchDiagnostics = undefined;
    try std.testing.expectEqual(code(.punch_failed), quicz_mobile_client_punch_ipv4_with_diagnostics(client, &punch, &diagnostics));
    try std.testing.expectEqual(@as(u32, 1), diagnostics.probes_sent);
    try std.testing.expectEqual(@as(u32, 0), diagnostics.datagrams_received);
    try std.testing.expectEqual(@intFromEnum(PunchOutcome.retry_exhausted), diagnostics.outcome);
    try std.testing.expectEqual(@as(u8, 0), diagnostics.peer_probe);
    try std.testing.expectEqual(@as(u8, 0), diagnostics.local_ack);
    try std.testing.expect(diagnostics.duration_ms >= 10);

    var bound: Ipv4Endpoint = undefined;
    try std.testing.expectEqual(code(.ok), quicz_mobile_client_bound_ipv4(client, &bound));
    const destination = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = bound.port } };
    const invalid_proof = quicz.connectivity.punch_wire.encode(@splat(0x99), .{
        .kind = .probe,
        .attempt_id = punch.attempt_id,
        .nonce = @splat(0x33),
    });
    try silent.send(std.testing.io, &destination, &invalid_proof);
    try std.testing.expectEqual(code(.punch_failed), quicz_mobile_client_punch_ipv4_with_diagnostics(client, &punch, &diagnostics));
    try std.testing.expectEqual(@as(u32, 1), diagnostics.probes_sent);
    try std.testing.expectEqual(@as(u32, 1), diagnostics.datagrams_received);
    try std.testing.expectEqual(@as(u32, 1), diagnostics.packets_checked);
    try std.testing.expectEqual(@as(u32, 1), diagnostics.authentication_rejected);
    try std.testing.expectEqual(@as(u32, 0), diagnostics.source_rejected);
    try std.testing.expectEqual(@as(u8, 0), diagnostics.peer_probe);

    // An invalid subsequent call must not expose the previous attempt's counts.
    try std.testing.expectEqual(code(.invalid_argument), quicz_mobile_client_punch_ipv4_with_diagnostics(null, &punch, &diagnostics));
    try std.testing.expectEqualDeep(PunchDiagnostics{}, diagnostics);
    try std.testing.expectEqual(code(.invalid_argument), quicz_mobile_client_punch_ipv4_with_diagnostics(client, &punch, null));
    try std.testing.expectEqual(code(.punch_failed), quicz_mobile_client_punch_ipv4(client, &punch));
}

test "mobile punch diagnostics report verified bidirectional proof" {
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(0) };
    const peer = try address.bind(std.testing.io, .{ .mode = .dgram, .protocol = .udp });
    defer peer.close(std.testing.io);
    const server_name = "localhost";
    const alpn = "quicz-mobile-punch-test";
    const config = ClientConfig{
        .server_ipv4 = .{ 127, 0, 0, 1 },
        .server_port = peer.address.ip4.port,
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
    var bound: Ipv4Endpoint = undefined;
    try std.testing.expectEqual(code(.ok), quicz_mobile_client_bound_ipv4(client, &bound));
    var peer_attempt = try quicz.connectivity.punch_attempt.PunchAttempt.init(
        @splat(0x42),
        @splat(0x11),
        @splat(0x33),
        .{ .initial_retry_ms = 10, .maximum_retry_ms = 20, .max_attempts = 5 },
    );
    const destination = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = bound.port } };
    var serving = try std.testing.io.concurrent(quicz.connectivity.punch_driver.run, .{
        std.testing.io, peer, destination, &peer_attempt,
    });
    defer serving.cancel(std.testing.io) catch {};
    const punch = PunchConfig{
        .remote = .{ .address = .{ 127, 0, 0, 1 }, .port = peer.address.ip4.port },
        .key = @splat(0x42),
        .attempt_id = @splat(0x11),
        .nonce = @splat(0x21),
        .initial_retry_ms = 10,
        .maximum_retry_ms = 20,
        .max_attempts = 5,
        .reserved = @splat(0),
    };
    var diagnostics: PunchDiagnostics = undefined;
    try std.testing.expectEqual(code(.ok), quicz_mobile_client_punch_ipv4_with_diagnostics(client, &punch, &diagnostics));
    try serving.await(std.testing.io);
    try std.testing.expectEqual(@intFromEnum(PunchOutcome.validated), diagnostics.outcome);
    try std.testing.expect(diagnostics.probes_sent >= 1);
    try std.testing.expect(diagnostics.acks_sent >= 1);
    try std.testing.expect(diagnostics.datagrams_received >= 2);
    try std.testing.expectEqual(@as(u32, 0), diagnostics.authentication_rejected);
    try std.testing.expectEqual(@as(u8, 1), diagnostics.peer_probe);
    try std.testing.expectEqual(@as(u8, 1), diagnostics.local_ack);
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(PunchDiagnostics));
    try std.testing.expectEqual(@as(u32, 1), quicz_mobile_abi_version());
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

fn testClient6Config(ca_der: []const u8, remote_port: u16) Client6Config {
    const server_name = "localhost";
    const alpn = "quicz-mobile-ipv6-test";
    const loopback = std.Io.net.Ip6Address.loopback(0).bytes;
    return .{
        .local = .{ .address = loopback, .port = 0, .reserved = 0, .scope_id = 0 },
        .remote = .{ .address = loopback, .port = remote_port, .reserved = 0, .scope_id = 0 },
        .server_name = server_name.ptr,
        .server_name_length = server_name.len,
        .alpn = alpn.ptr,
        .alpn_length = alpn.len,
        .ca_certificate_der = ca_der.ptr,
        .ca_certificate_der_length = ca_der.len,
    };
}

test "mobile IPv6 ABI retains its bound endpoint and rejects IPv4 operations" {
    var ca_storage: [1024]u8 = undefined;
    const ca_der = try quicz.tls_pem.decodeBlock(@embedFile("quic/testdata/quicz-echo-ca.pem"), "CERTIFICATE", &ca_storage);
    const config = testClient6Config(ca_der, 4433);
    var handle: ?*anyopaque = null;
    try std.testing.expectEqual(code(.ok), quicz_mobile_client_create_ipv6(&config, &handle));
    defer quicz_mobile_client_destroy(handle);
    var bound: Ipv6Endpoint = undefined;
    try std.testing.expectEqual(code(.ok), quicz_mobile_client_bound_ipv6(handle, &bound));
    try std.testing.expectEqualSlices(u8, &config.local.address, &bound.address);
    try std.testing.expect(bound.port != 0);
    try std.testing.expectEqual(@as(u32, 0), bound.scope_id);
    try std.testing.expectEqual(@as(u16, 0), bound.reserved);
    var old_bound: Ipv4Endpoint = undefined;
    try std.testing.expectEqual(code(.invalid_argument), quicz_mobile_client_bound_ipv4(handle, &old_bound));
    const old_punch: PunchConfig = .{
        .remote = .{ .address = .{ 127, 0, 0, 1 }, .port = 4433 },
        .key = .{0x41} ** 32,
        .attempt_id = .{0x11} ** 16,
        .nonce = .{0x21} ** 16,
        .initial_retry_ms = 1,
        .maximum_retry_ms = 1,
        .max_attempts = 1,
        .reserved = .{ 0, 0, 0 },
    };
    var diagnostics: PunchDiagnostics = undefined;
    try std.testing.expectEqual(code(.invalid_argument), quicz_mobile_client_punch_ipv4_with_diagnostics(handle, &old_punch, &diagnostics));
    try std.testing.expectEqualDeep(PunchDiagnostics{}, diagnostics);
    try std.testing.expectEqual(@as(u32, 1), quicz_mobile_abi_version());
    try std.testing.expect(quicz_mobile_capabilities() & (@as(u64, 1) << 7) != 0);
}

fn testPunch6Config(remote: Ipv6Endpoint) Punch6Config {
    return .{
        .remote = remote,
        .key = .{0x41} ** 32,
        .attempt_id = .{0x11} ** 16,
        .nonce = .{0x21} ** 16,
        .initial_retry_ms = 1,
        .maximum_retry_ms = 1,
        .max_attempts = 1,
        .reserved = .{ 0, 0, 0 },
    };
}

test "mobile IPv6 configuration rejects unsupported endpoints and clears output" {
    var ca_storage: [1024]u8 = undefined;
    const ca_der = try quicz.tls_pem.decodeBlock(@embedFile("quic/testdata/quicz-echo-ca.pem"), "CERTIFICATE", &ca_storage);
    const valid = testClient6Config(ca_der, 4433);
    var handle: ?*anyopaque = null;
    try std.testing.expectEqual(code(.ok), quicz_mobile_client_create_ipv6(&valid, &handle));
    defer quicz_mobile_client_destroy(handle);
    var invalid = [_]Client6Config{valid} ** 10;
    invalid[0].local.reserved = 1;
    invalid[1].remote.reserved = 1;
    invalid[2].local.scope_id = 1;
    invalid[3].remote.scope_id = 1;
    invalid[4].remote.port = 0;
    invalid[5].local.address = @splat(0);
    invalid[6].remote.address = @splat(0);
    invalid[7].local.address = std.Io.net.Ip6Address.fromIp4(.loopback(0)).bytes;
    invalid[8].remote.address = std.Io.net.Ip6Address.fromIp4(.loopback(0)).bytes;
    invalid[9].remote.address[0] = 0xfe;
    for (invalid) |config| {
        var output = handle;
        try std.testing.expectEqual(code(.invalid_argument), quicz_mobile_client_create_ipv6(&config, &output));
        try std.testing.expect(output == null);
    }
    var output = handle;
    try std.testing.expectEqual(code(.invalid_argument), quicz_mobile_client_create_ipv6(null, &output));
    try std.testing.expect(output == null);
    try std.testing.expectEqual(code(.invalid_argument), quicz_mobile_client_create_ipv6(&valid, null));
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(Ipv6Endpoint));
    try std.testing.expectEqual(@as(usize, 100), @sizeOf(Punch6Config));
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(PunchDiagnostics));
}

test "mobile address operations reject the other valid owner family" {
    var ca_storage: [1024]u8 = undefined;
    const ca_der = try quicz.tls_pem.decodeBlock(@embedFile("quic/testdata/quicz-echo-ca.pem"), "CERTIFICATE", &ca_storage);
    const config6 = testClient6Config(ca_der, 4433);
    const config4: ClientConfig = .{
        .server_ipv4 = .{ 127, 0, 0, 1 },
        .server_port = 4433,
        .allow_migration = 0,
        .reserved = 0,
        .server_name = config6.server_name,
        .server_name_length = config6.server_name_length,
        .alpn = config6.alpn,
        .alpn_length = config6.alpn_length,
        .ca_certificate_der = config6.ca_certificate_der,
        .ca_certificate_der_length = config6.ca_certificate_der_length,
    };
    var owner4: ?*anyopaque = null;
    try std.testing.expectEqual(code(.ok), quicz_mobile_client_create_unverified(&config4, &owner4));
    defer quicz_mobile_client_destroy(owner4);
    var owner6: ?*anyopaque = null;
    try std.testing.expectEqual(code(.ok), quicz_mobile_client_create_ipv6(&config6, &owner6));
    defer quicz_mobile_client_destroy(owner6);
    var endpoint6: Ipv6Endpoint = undefined;
    try std.testing.expectEqual(code(.invalid_argument), quicz_mobile_client_bound_ipv6(owner4, &endpoint6));
    try std.testing.expectEqual(code(.invalid_argument), quicz_mobile_client_discover_ipv6(owner4, &config6.remote, 1, 1, &endpoint6));
    const punch6 = testPunch6Config(config6.remote);
    try std.testing.expectEqual(code(.invalid_argument), quicz_mobile_client_punch_ipv6(owner4, &punch6));
    var diagnostics: PunchDiagnostics = undefined;
    try std.testing.expectEqual(code(.invalid_argument), quicz_mobile_client_punch_ipv6_with_diagnostics(owner4, &punch6, &diagnostics));
    try std.testing.expectEqualDeep(PunchDiagnostics{}, diagnostics);
    try std.testing.expectEqual(code(.invalid_argument), quicz_mobile_client_punch_ipv6_with_diagnostics(null, &punch6, &diagnostics));
    try std.testing.expectEqualDeep(PunchDiagnostics{}, diagnostics);
    try std.testing.expectEqual(code(.invalid_argument), quicz_mobile_client_punch_ipv6_with_diagnostics(owner6, &punch6, null));
    const endpoint4: Ipv4Endpoint = .{ .address = .{ 127, 0, 0, 1 }, .port = 3478 };
    var mapped4: Ipv4Endpoint = undefined;
    try std.testing.expectEqual(code(.invalid_argument), quicz_mobile_client_discover_ipv4(owner6, &endpoint4, 1, 1, &mapped4));
    const punch4: PunchConfig = .{
        .remote = endpoint4,
        .key = punch6.key,
        .attempt_id = punch6.attempt_id,
        .nonce = punch6.nonce,
        .initial_retry_ms = 1,
        .maximum_retry_ms = 1,
        .max_attempts = 1,
        .reserved = .{ 0, 0, 0 },
    };
    try std.testing.expectEqual(code(.invalid_argument), quicz_mobile_client_punch_ipv4(owner6, &punch4));
    try std.testing.expectEqual(code(.invalid_argument), quicz_mobile_client_set_keepalive_interval(null, 1));
}

const SmallStackCreate6Context = struct {
    config: Client6Config,
    result: i32 = code(.open_failed),
    bound_port: u16 = 0,
};

fn createClient6FromSmallStack(context: *SmallStackCreate6Context) void {
    var handle: ?*anyopaque = null;
    context.result = quicz_mobile_client_create_ipv6(&context.config, &handle);
    if (handle) |owner| {
        defer quicz_mobile_client_destroy(owner);
        var bound: Ipv6Endpoint = undefined;
        context.result = quicz_mobile_client_bound_ipv6(owner, &bound);
        if (context.result == code(.ok)) context.bound_port = bound.port;
    }
}

test "mobile IPv6 creation is safe on a 512 KiB caller stack" {
    var ca_storage: [1024]u8 = undefined;
    const ca_der = try quicz.tls_pem.decodeBlock(@embedFile("quic/testdata/quicz-echo-ca.pem"), "CERTIFICATE", &ca_storage);
    var context: SmallStackCreate6Context = .{ .config = testClient6Config(ca_der, 4433) };
    const thread = try std.Thread.spawn(.{ .stack_size = 512 * 1024 }, createClient6FromSmallStack, .{&context});
    thread.join();
    try std.testing.expectEqual(code(.ok), context.result);
    try std.testing.expect(context.bound_port != 0);
}

test "mobile IPv6 timeout keeps its socket until explicit destruction" {
    const io = std.testing.io;
    const local = std.Io.net.IpAddress{ .ip6 = .loopback(0) };
    const silent = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer silent.close(io);
    var ca_storage: [1024]u8 = undefined;
    const ca_der = try quicz.tls_pem.decodeBlock(@embedFile("quic/testdata/quicz-echo-ca.pem"), "CERTIFICATE", &ca_storage);
    const config = testClient6Config(ca_der, silent.address.getPort());
    var bound: Ipv6Endpoint = undefined;
    {
        var handle: ?*anyopaque = null;
        try std.testing.expectEqual(code(.ok), quicz_mobile_client_create_ipv6(&config, &handle));
        defer quicz_mobile_client_destroy(handle);
        try std.testing.expectEqual(code(.ok), quicz_mobile_client_set_keepalive_interval(handle, 10_000));
        try std.testing.expectEqual(code(.ok), quicz_mobile_client_bound_ipv6(handle, &bound));
        try std.testing.expectEqual(code(.connection_timed_out), quicz_mobile_client_connect_timeout(handle, 10));
        var after: Ipv6Endpoint = undefined;
        try std.testing.expectEqual(code(.ok), quicz_mobile_client_bound_ipv6(handle, &after));
        try std.testing.expectEqualDeep(bound, after);
        quicz_mobile_client_close(handle);
    }
    const rebound_address = std.Io.net.IpAddress{ .ip6 = .{ .bytes = bound.address, .port = bound.port } };
    const rebound = try rebound_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer rebound.close(io);
}

fn rejectUnrelatedMobileCA(comptime ipv6: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_storage: [1024]u8 = undefined;
    const certificate = try quicz.tls_pem.decodeBlock(@embedFile("quic/testdata/quicz-echo-ca.pem"), "CERTIFICATE", &certificate_storage);
    const private_key = [_]u8{
        0x5b, 0xbf, 0x4f, 0x5a, 0x48, 0x42, 0x9f, 0x00,
        0x5a, 0x57, 0x09, 0xc3, 0xb4, 0xc1, 0x3a, 0x64,
        0x2e, 0xb1, 0x61, 0xf5, 0x0b, 0xde, 0x64, 0x4b,
        0x3a, 0x38, 0xa6, 0x8f, 0xfa, 0x48, 0xda, 0x51,
    };
    const Server = if (ipv6) quicz.runtime.server.IPv6Server else quicz.runtime.server.Server;
    var server = try Server.init(std.testing.allocator, io, .{
        .port = 0,
        .alpn = &.{"quicz-mobile-ipv6-test"},
        .cert_der = certificate,
        .private_key = &private_key,
        .max_connections = 1,
    });
    defer server.deinit();
    try server.start();
    var wrong_ca_storage: [1024]u8 = undefined;
    const wrong_ca = try quicz.tls_pem.decodeBlock(@embedFile("quic/testdata/quicz-client-ca.pem"), "CERTIFICATE", &wrong_ca_storage);
    const config6 = testClient6Config(wrong_ca, server.localPort());
    var handle: ?*anyopaque = null;
    if (ipv6) {
        try std.testing.expectEqual(code(.ok), quicz_mobile_client_create_ipv6(&config6, &handle));
    } else {
        const config4: ClientConfig = .{
            .server_ipv4 = .{ 127, 0, 0, 1 },
            .server_port = server.localPort(),
            .allow_migration = 0,
            .reserved = 0,
            .server_name = config6.server_name,
            .server_name_length = config6.server_name_length,
            .alpn = config6.alpn,
            .alpn_length = config6.alpn_length,
            .ca_certificate_der = config6.ca_certificate_der,
            .ca_certificate_der_length = config6.ca_certificate_der_length,
        };
        try std.testing.expectEqual(code(.ok), quicz_mobile_client_create(&config4, &handle));
    }
    defer quicz_mobile_client_destroy(handle);
    try std.testing.expectEqual(code(.connection_failed), quicz_mobile_client_connect_timeout(handle, 2_000));
}

test "mobile IPv4 verified constructor rejects an unrelated CA" {
    try rejectUnrelatedMobileCA(false);
}

test "mobile IPv6 verified constructor rejects an unrelated CA" {
    try rejectUnrelatedMobileCA(true);
}

fn legacyCapabilitySwitch(capability: Capability) u8 {
    return switch (capability) {
        .stream => 0,
        .datagram => 1,
        .path_validation => 2,
        .migration => 3,
        .multipath => 4,
        .stun => 5,
        .hole_punch => 6,
    };
}

test "mobile Zig capability callers retain their exhaustive legacy switch" {
    try std.testing.expectEqual(@as(u8, 0), legacyCapabilitySwitch(.stream));
    try std.testing.expectEqual(@as(u8, 6), legacyCapabilitySwitch(.hole_punch));
    try std.testing.expectEqual(@as(u64, 128), native_ipv6_capability_bit);
}
