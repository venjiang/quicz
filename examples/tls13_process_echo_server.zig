//! Pure-Zig TLS 1.3 QUIC echo server for local process interoperability.
//!
//! Usage: quicz-tls13-process-echo-server <bind_host> <bind_port> [completion_target] [sequential|concurrent|concurrent-retry|concurrent-limit|concurrent-reset|concurrent-stop|concurrent-uni|concurrent-flow|rolling] [max_active_connections] [idle_timeout_ms]
//!
//! A concurrent mode with completion_target=0 runs until interrupted and
//! requires an explicit positive max_active_connections value.
//! Concurrent mode accepts and routes the requested number of loopback
//! connections through one UDP socket and one endpoint lifecycle owner. It
//! waits on the lifecycle's earliest deadline and retires idle connections.

const std = @import("std");
const test_certs = @import("test_certs.zig");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const EndpointConnectionLifecycle = quicz.EndpointConnectionLifecycle;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const Tls13ServerTransport = quicz.Tls13ServerTransport;
const endpoint = quicz.endpoint;
const quic_packet = quicz.packet;
const protection = quicz.protection;
const address_validation_token = quicz.address_validation_token;

const server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
const max_initial_datagrams: usize = 4;
const max_application_datagrams: usize = 16;
const server_max_datagram_size: usize = 8192;
const default_server_idle_timeout_ms: u64 = 30_000;
const retry_token_lifetime_nanos: u64 = 10 * std.time.ns_per_s;
const max_retry_datagram_size: usize = 256;
const echo_stream_ids = [_]u64{ 0, 4 };
const echo_payloads = [_][]const u8{ "hello", "world" };
const interop_echo_stream_ids = [_]u64{ 0, 4, 8, 12 };
const interop_echo_payloads = [_][]const u8{ "hello", "world", "again", "more" };
const echo_total_bytes: usize = 10;
const flow_control_payload = @as([12_288]u8, @splat('f'));
/// Active server certificate (DER) and private key: overridden by CERT/KEY
/// environment variables (PEM, loaded via quicz.tls_pem), otherwise the
/// embedded test pair.
var active_cert: []const u8 = undefined;
var active_key: [32]u8 = undefined;

fn readFile(io: std.Io, path: []const u8, buf: []u8) ![]u8 {
    const file = try std.Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);
    const n = try file.readPositionalAll(io, buf, 0);
    return buf[0..n];
}

const client_uni_stream_id: u64 = 2;
const server_uni_stream_id: u64 = 3;
const client_uni_payload = "uni";
const server_uni_payload = "uni-reply";

fn recvTimeoutForDeadline(io: std.Io, deadline_nanos: ?i64) std.Io.Timeout {
    const now_nanos: i64 = @intCast(std.Io.Clock.awake.now(io).nanoseconds);
    const timeout_nanos = if (deadline_nanos) |deadline|
        @max(@as(i64, 0), deadline - now_nanos)
    else
        10 * std.time.ns_per_s;
    return .{ .duration = .{
        .clock = .awake,
        .raw = std.Io.Duration.fromNanoseconds(timeout_nanos),
    } };
}

fn recvTimeout() std.Io.Timeout {
    return .{ .duration = .{
        .clock = .awake,
        .raw = std.Io.Duration.fromSeconds(10),
    } };
}

fn nowNanos(io: std.Io) i64 {
    return @intCast(std.Io.Clock.awake.now(io).nanoseconds);
}

fn require(condition: bool) !void {
    if (!condition) return error.UnexpectedState;
}

const ManagedProcessConnection = struct {
    handle: u64,
    transport: Tls13ServerTransport,
    peer_address: std.Io.net.IpAddress,
    retry_datagram: [max_retry_datagram_size]u8 = undefined,
    retry_datagram_len: usize = 0,
    retry_validated: bool = false,
    retry_accepted: bool = false,
    client_reset_received: bool = false,
    client_stop_sending_sent: bool = false,
    client_stop_reset_received: bool = false,
    client_uni_received: bool = false,
    server_uni_sent: bool = false,
    flow_bytes_received: usize = 0,
    flow_echoed: bool = false,
    request_received: [interop_echo_stream_ids.len]bool = .{ false, false, false, false },
    echoed: [interop_echo_stream_ids.len]bool = .{ false, false, false, false },

    fn clientScid(self: *const ManagedProcessConnection) []const u8 {
        return self.transport.connection.peerDestinationConnectionId() orelse
            self.transport.peerInitialSourceConnectionId();
    }

    fn retryDatagram(self: *const ManagedProcessConnection) []const u8 {
        return self.retry_datagram[0..self.retry_datagram_len];
    }

    fn deinit(self: *ManagedProcessConnection) void {
        self.transport.deinit();
    }

    fn connectionRef(self: *ManagedProcessConnection) *Connection {
        return self.transport.connectionRef();
    }

    fn cryptoBackend(self: *ManagedProcessConnection) quicz.CryptoBackend {
        return self.transport.cryptoBackend();
    }

    fn destinationConnectionId(self: *const ManagedProcessConnection) []const u8 {
        return self.clientScid();
    }

    fn sourceConnectionId(self: *const ManagedProcessConnection) []const u8 {
        return self.transport.localInitialSourceConnectionId();
    }

    fn initialDestinationConnectionId(self: *const ManagedProcessConnection) []const u8 {
        return if (self.retry_validated)
            self.transport.localInitialSourceConnectionId()
        else
            self.transport.originalDestinationConnectionId();
    }

    fn markRetryValidated(self: *ManagedProcessConnection) void {
        self.retry_validated = true;
    }
};

const ProcessConnectionRegistry = quicz.EndpointConnectionRegistry(
    ManagedProcessConnection,
    ManagedProcessConnection.connectionRef,
    ManagedProcessConnection.deinit,
);

const ProcessServerEndpoint = quicz.Tls13ServerEndpoint(
    ManagedProcessConnection,
    ManagedProcessConnection.connectionRef,
    ManagedProcessConnection.cryptoBackend,
    ManagedProcessConnection.destinationConnectionId,
    ManagedProcessConnection.sourceConnectionId,
    ManagedProcessConnection.initialDestinationConnectionId,
    ManagedProcessConnection.markRetryValidated,
    ManagedProcessConnection.deinit,
);

fn randomRetryTokenNonce(io: std.Io) !address_validation_token.Nonce {
    var nonce: address_validation_token.Nonce = undefined;
    try io.randomSecure(&nonce);
    return nonce;
}

fn serverPath(bind_address: std.Io.net.IpAddress, peer_address: std.Io.net.IpAddress) !endpoint.Udp4Tuple {
    return .{
        .local = endpoint.Udp4Address.init(bind_address.ip4.bytes, bind_address.ip4.port),
        .remote = endpoint.Udp4Address.init(peer_address.ip4.bytes, peer_address.ip4.port),
    };
}

fn peerAddressForPath(path: endpoint.Udp4Tuple) std.Io.net.IpAddress {
    return .{ .ip4 = .{
        .bytes = path.remote.octets,
        .port = path.remote.port,
    } };
}

fn currentPeerAddress(
    server_endpoint: *const ProcessServerEndpoint,
    managed: *const ManagedProcessConnection,
) std.Io.net.IpAddress {
    const route_path = server_endpoint.lifecycle.currentRoutePath(managed.sourceConnectionId()) catch return managed.peer_address;
    return peerAddressForPath(route_path);
}

fn sendToCurrentRoute(
    io: std.Io,
    socket: *std.Io.net.Socket,
    server_endpoint: *const ProcessServerEndpoint,
    managed: *const ManagedProcessConnection,
    datagram: []const u8,
) !void {
    const peer_address = currentPeerAddress(server_endpoint, managed);
    try socket.send(io, &peer_address, datagram);
}

fn sendHandshakeConfirmation(
    io: std.Io,
    socket: *std.Io.net.Socket,
    server_endpoint: *ProcessServerEndpoint,
    managed: *ManagedProcessConnection,
    now_nanos: i64,
) !void {
    if (!managed.connectionRef().pending_handshake_done) return;
    const datagram = (try server_endpoint.pollOneRttDatagram(managed.handle, now_nanos)) orelse return error.UnexpectedState;
    defer managed.connectionRef().allocator.free(datagram);
    try sendToCurrentRoute(io, socket, server_endpoint, managed, datagram);
}

fn destroyManagedConnection(
    server_endpoint: *ProcessServerEndpoint,
    handle: u64,
) !void {
    _ = try server_endpoint.retireRecord(handle);
}

fn serveConcurrent(
    allocator: std.mem.Allocator,
    io: std.Io,
    socket: *std.Io.net.Socket,
    bind_address: std.Io.net.IpAddress,
    completion_target: usize,
    max_active_connections: usize,
    retry_enabled: bool,
    initial_max_streams_bidi: u64,
    expect_client_reset: bool,
    expect_client_stop_sending: bool,
    expect_client_uni_stream: bool,
    expect_flow_control: bool,
    idle_timeout_ms: u64,
) !void {
    const alpn = [_][]const u8{"hq-interop"};
    const max_routes = std.math.mul(usize, max_active_connections, 2) catch return error.InvalidConnectionCount;
    var server_endpoint = try ProcessServerEndpoint.initWithCapacity(allocator, max_active_connections, .{
        .max_routes = max_routes,
        .max_stateless_reset_tokens = max_routes,
    });
    defer server_endpoint.deinit();
    var retry_token_secret: address_validation_token.Secret = undefined;
    try io.randomSecure(&retry_token_secret);
    var address_validation = endpoint.AddressValidationPolicy.init(allocator, retry_token_secret, .{});
    defer address_validation.deinit();
    const connections = &server_endpoint.records;

    var receive_buffer: [server_max_datagram_size]u8 = undefined;
    var endpoint_output: [128]u8 = undefined;
    var next_handle: u64 = 1;
    var accepted_count: usize = 0;
    var completed: usize = 0;
    var capacity_dropped_initials: usize = 0;

    const runs_continuously = completion_target == 0;
    receive_loop: while (runs_continuously or completed < completion_target) {
        const next_deadline = try server_endpoint.nextDeadline(allocator);
        const received = socket.receiveTimeout(
            io,
            &receive_buffer,
            recvTimeoutForDeadline(io, if (next_deadline) |deadline| deadline.deadline_nanos else null),
        ) catch |err| switch (err) {
            error.Timeout => {
                var due_datagrams: [max_initial_datagrams]quicz.endpoint_types.EndpointPolledDatagramResult = undefined;
                const due = (try server_endpoint.processDueDeadlineAndDrainDatagrams(
                    allocator,
                    nowNanos(io),
                    &due_datagrams,
                )) orelse continue;
                for (due_datagrams[0..due.drain.datagrams_written]) |output| {
                    defer allocator.free(output.datagram);
                    const managed = connections.get(output.connection_id) orelse continue;
                    try sendToCurrentRoute(io, socket, &server_endpoint, managed, output.datagram);
                }
                if (due.drain.first_error) |drain_error| {
                    return drain_error;
                }
                if (due.deadline.kind == .recovery) {
                    std.debug.print("zig_process_server: connection={d} concurrent=true pto_serviced=true\n", .{due.deadline.connection_id});
                }
                if (due.pending_work.idle_retired != null or due.pending_work.close_retired != null) {
                    if (connections.get(due.deadline.connection_id)) |managed| {
                        const completed_connection = !retry_enabled or managed.retry_accepted;
                        const retired_after_close_timeout = due.pending_work.close_retired != null;
                        try destroyManagedConnection(&server_endpoint, due.deadline.connection_id);
                        if (completed_connection) {
                            completed += 1;
                            if (retired_after_close_timeout) {
                                std.debug.print("zig_process_server: connection={d} concurrent=true close_cleanup=true\n", .{completed});
                            } else {
                                std.debug.print("zig_process_server: connection={d} concurrent=true idle_cleanup=true\n", .{completed});
                            }
                        } else {
                            std.debug.print("zig_process_server: connection={d} concurrent=true retry_expired=true\n", .{due.deadline.connection_id});
                        }
                    } else {
                        completed += 1;
                        std.debug.print("zig_process_server: connection={d} concurrent=true already_cleaned=true\n", .{completed});
                    }
                }
                continue;
            },
            else => return err,
        };
        const now_nanos = nowNanos(io);
        const path = try serverPath(bind_address, received.from);
        const action = try server_endpoint.feedDatagram(
            &endpoint_output,
            path,
            received.data,
            &[_]u8{},
            &[_]quic_packet.Version{.v1},
        );
        switch (action) {
            .accept_initial => |initial_accept| {
                const initial_info = try protection.peekProtectedLongPacketInfo(received.data);
                if (initial_info.packet_type != .initial) return error.InvalidPacket;
                if (retry_enabled) {
                    if (!connections.hasCapacity()) {
                        var pending = connections.valueIterator();
                        while (pending.next()) |managed| {
                            if (managed.*.retry_datagram_len == 0 or
                                !std.mem.eql(u8, managed.*.transport.originalDestinationConnectionId(), initial_info.dcid) or
                                !std.meta.eql(managed.*.peer_address, received.from)) continue;
                            try sendToCurrentRoute(io, socket, &server_endpoint, managed.*, managed.*.retryDatagram());
                            std.debug.print("zig_process_server: connection={d} concurrent=true retry_reissued=true\n", .{managed.*.handle});
                            continue :receive_loop;
                        }
                        capacity_dropped_initials +|= 1;
                        continue;
                    }
                } else if (!connections.hasCapacity()) {
                    capacity_dropped_initials +|= 1;
                    continue;
                }

                const handle = next_handle;
                next_handle += 1;
                var connection_scid: [8]u8 = undefined;
                try io.randomSecure(&connection_scid);
                const managed = try allocator.create(ManagedProcessConnection);
                var managed_initialized = false;
                var managed_adopted = false;
                errdefer {
                    if (managed_adopted) {
                        if (server_endpoint.retireRecord(handle)) |_| {} else |_| {}
                    } else {
                        if (managed_initialized) managed.deinit();
                        allocator.destroy(managed);
                    }
                }
                const transport = try Tls13ServerTransport.init(allocator, .{
                    .initial_max_data = 8192,
                    .initial_max_stream_data = 2048,
                    .initial_max_streams_bidi = initial_max_streams_bidi,
                    .max_datagram_size = server_max_datagram_size,
                    // Keep the local loss-recovery probe comfortably ahead of
                    // the configured endpoint idle timeout.
                    .initial_rtt_ns = 100000000,
                    .max_idle_timeout_ms = idle_timeout_ms,
                }, .{
                    .alpn = &alpn,
                    .cert_chain_der = &.{active_cert},
                    .private_key_bytes = &active_key,
                    .private_key_algorithm = .ecdsa_p256_sha256,
                });
                managed.* = .{
                    .handle = handle,
                    .transport = transport,
                    .peer_address = received.from,
                };
                managed_initialized = true;
                try managed.transport.connection.validatePeerAddress();
                try managed.transport.setLocalInitialSourceConnectionId(&connection_scid);
                try managed.transport.setOriginalDestinationConnectionId(initial_info.dcid);

                if (retry_enabled) {
                    try managed.transport.setPeerInitialSourceConnectionId(initial_accept.source_connection_id);
                    const token = try address_validation.issueTokenForPathForVersion(
                        allocator,
                        .retry,
                        initial_info.version,
                        now_nanos,
                        retry_token_lifetime_nanos,
                        path,
                        try randomRetryTokenNonce(io),
                    );
                    defer allocator.free(token);
                    const retry_datagram = try managed.transport.connection.issueRetryDatagram(
                        now_nanos,
                        initial_info.dcid,
                        initial_accept.source_connection_id,
                        managed.transport.localInitialSourceConnectionId(),
                        token,
                    );
                    defer allocator.free(retry_datagram);
                    if (retry_datagram.len > managed.retry_datagram.len) return error.InvalidPacket;
                    @memcpy(managed.retry_datagram[0..retry_datagram.len], retry_datagram);
                    managed.retry_datagram_len = retry_datagram.len;
                    _ = try server_endpoint.adoptRetryRecordAndSwitchInitialRoute(
                        handle,
                        managed,
                        initial_info.dcid,
                        managed.transport.localInitialSourceConnectionId(),
                        path,
                        .{ .active_migration_disabled = false },
                    );
                    managed_adopted = true;
                    try sendToCurrentRoute(io, socket, &server_endpoint, managed, retry_datagram);
                    std.debug.print("zig_process_server: connection={d} concurrent=true retry_issued=true\n", .{handle});
                    continue;
                }

                var scratch: [8192]u8 = undefined;
                var initial_outputs: [max_initial_datagrams]quicz.endpoint_types.EndpointPolledDatagramResult = undefined;
                var handshake_outputs: [max_initial_datagrams]quicz.endpoint_types.EndpointPolledDatagramResult = undefined;
                const accepted = try server_endpoint.acceptInitialRecord(
                    handle,
                    managed,
                    now_nanos,
                    initial_accept,
                    managed.transport.localInitialSourceConnectionId(),
                    received.data,
                    .{ .active_migration_disabled = false },
                    &scratch,
                    &initial_outputs,
                    &handshake_outputs,
                );
                managed_adopted = true;
                accepted_count += 1;
                for (initial_outputs[0..accepted.initial.drain.datagrams_written]) |output| {
                    defer allocator.free(output.datagram);
                    try sendToCurrentRoute(io, socket, &server_endpoint, managed, output.datagram);
                }
                if (accepted.initial.drain.first_error) |drain_error| return drain_error;
                if (accepted.handshake) |handshake| {
                    for (handshake_outputs[0..handshake.drain.datagrams_written]) |output| {
                        defer allocator.free(output.datagram);
                        try sendToCurrentRoute(io, socket, &server_endpoint, managed, output.datagram);
                    }
                    if (handshake.drain.first_error) |drain_error| return drain_error;
                }
            },
            .routed => |route| {
                const managed = connections.get(route.connection_id) orelse return error.UnknownConnectionId;
                if (retry_enabled and managed.transport.connection.pendingRetryTokenCount() != 0) {
                    const retry_initial = try server_endpoint.validateRetryInitial(
                        &address_validation,
                        managed.handle,
                        now_nanos,
                        path,
                        received.data,
                        &[_]quic_packet.Version{.v1},
                    );
                    managed.retry_datagram_len = 0;
                    var retry_scratch: [8192]u8 = undefined;
                    var retry_initial_outputs: [max_initial_datagrams]quicz.endpoint_types.EndpointPolledDatagramResult = undefined;
                    const retry_initial_progress = try server_endpoint.driveInitialBackend(
                        managed.handle,
                        &retry_scratch,
                        now_nanos,
                        &[_]u8{},
                        retry_initial.initial_accept.version,
                        &retry_initial_outputs,
                    );
                    for (retry_initial_outputs[0..retry_initial_progress.drain.datagrams_written]) |output| {
                        defer allocator.free(output.datagram);
                        try sendToCurrentRoute(io, socket, &server_endpoint, managed, output.datagram);
                    }
                    if (retry_initial_progress.drain.first_error) |drain_error| return drain_error;
                    if (!retry_initial_progress.backend.handshake_keys_installed) continue;
                    var retry_handshake_outputs: [max_initial_datagrams]quicz.endpoint_types.EndpointPolledDatagramResult = undefined;
                    const retry_handshake_progress = try server_endpoint.driveBackend(
                        managed.handle,
                        .handshake,
                        &retry_scratch,
                        now_nanos,
                        &retry_handshake_outputs,
                    );
                    for (retry_handshake_outputs[0..retry_handshake_progress.drain.datagrams_written]) |output| {
                        defer allocator.free(output.datagram);
                        try sendToCurrentRoute(io, socket, &server_endpoint, managed, output.datagram);
                    }
                    if (retry_handshake_progress.drain.first_error) |drain_error| return drain_error;
                    accepted_count += 1;
                    managed.retry_accepted = true;
                    std.debug.print("zig_process_server: connection={d} concurrent=true retry_validated=true\n", .{managed.handle});
                    continue;
                }
                if ((received.data[0] & 0x80) != 0) {
                    if (managed.transport.connection.handshakeConfirmed()) {
                        // Independent clients can retransmit Initial or
                        // Handshake packets after their keys are discarded.
                        // Keep lifecycle route ownership, but never decrypt a
                        // retired packet-number space.
                        const late_route = try server_endpoint.routeDatagram(path, received.data);
                        try require(late_route.connection_id == managed.handle);
                        continue;
                    }
                    const first_long_info = try protection.peekProtectedLongPacketInfo(received.data);
                    if (first_long_info.packet_type == .initial and
                        first_long_info.len < received.data.len and
                        managed.transport.connection.hasHandshakeProtectionKeys())
                    {
                        var coalesced_scratch: [8192]u8 = undefined;
                        var coalesced_handshake_outputs: [max_initial_datagrams]quicz.endpoint_types.EndpointPolledDatagramResult = undefined;
                        const coalesced_handshake = try server_endpoint.processInitialWithHandshakeKeys(
                            managed.handle,
                            path,
                            now_nanos,
                            received.data,
                            &coalesced_scratch,
                            &coalesced_handshake_outputs,
                        );
                        for (coalesced_handshake_outputs[0..coalesced_handshake.backend.drain.datagrams_written]) |output| {
                            defer allocator.free(output.datagram);
                            try sendToCurrentRoute(io, socket, &server_endpoint, managed, output.datagram);
                        }
                        if (coalesced_handshake.backend.drain.first_error) |drain_error| return drain_error;
                        try sendHandshakeConfirmation(io, socket, &server_endpoint, managed, now_nanos);
                        continue;
                    }
                    var datagram_offset: usize = 0;
                    while (datagram_offset < received.data.len) {
                        const packet_bytes = received.data[datagram_offset..];
                        const long_info = try protection.peekProtectedLongPacketInfo(packet_bytes);
                        const long_packet = packet_bytes[0..long_info.len];
                        switch (long_info.packet_type) {
                            .initial => {
                                var initial_outputs: [max_initial_datagrams]quicz.endpoint_types.EndpointPolledDatagramResult = undefined;
                                var handshake_outputs: [max_initial_datagrams]quicz.endpoint_types.EndpointPolledDatagramResult = undefined;
                                var initial_scratch: [8192]u8 = undefined;
                                const initial = try server_endpoint.processInitial(
                                    managed.handle,
                                    path,
                                    now_nanos,
                                    long_packet,
                                    &initial_scratch,
                                    &[_]u8{},
                                    &initial_outputs,
                                    &handshake_outputs,
                                );
                                try require(initial.initial.route.connection_id == managed.handle);
                                for (initial_outputs[0..initial.initial.backend.drain.datagrams_written]) |output| {
                                    defer allocator.free(output.datagram);
                                    try sendToCurrentRoute(io, socket, &server_endpoint, managed, output.datagram);
                                }
                                if (initial.initial.backend.drain.first_error) |drain_error| return drain_error;
                                if (initial.handshake) |handshake| {
                                    for (handshake_outputs[0..handshake.drain.datagrams_written]) |output| {
                                        defer allocator.free(output.datagram);
                                        try sendToCurrentRoute(io, socket, &server_endpoint, managed, output.datagram);
                                    }
                                    if (handshake.drain.first_error) |drain_error| return drain_error;
                                    if (retry_enabled and managed.retry_validated and !managed.retry_accepted) {
                                        accepted_count += 1;
                                        managed.retry_accepted = true;
                                        std.debug.print("zig_process_server: connection={d} concurrent=true retry_validated=true\n", .{managed.handle});
                                    }
                                }
                            },
                            .handshake => {
                                var handshake_outputs: [max_initial_datagrams]quicz.endpoint_types.EndpointPolledDatagramResult = undefined;
                                var handshake_scratch: [8192]u8 = undefined;
                                const handshake = try server_endpoint.processHandshake(
                                    managed.handle,
                                    path,
                                    now_nanos,
                                    long_packet,
                                    &handshake_scratch,
                                    &handshake_outputs,
                                );
                                try require(handshake.route.connection_id == managed.handle);
                                for (handshake_outputs[0..handshake.backend.drain.datagrams_written]) |output| {
                                    defer allocator.free(output.datagram);
                                    try sendToCurrentRoute(io, socket, &server_endpoint, managed, output.datagram);
                                }
                                if (handshake.backend.drain.first_error) |drain_error| return drain_error;
                            },
                            else => return error.InvalidPacket,
                        }
                        datagram_offset += long_info.len;
                    }
                    try sendHandshakeConfirmation(io, socket, &server_endpoint, managed, now_nanos);
                    continue;
                }

                var path_challenge_data: [8]u8 = undefined;
                try io.randomSecure(&path_challenge_data);
                const application_result = try server_endpoint.lifecycle.feedDatagramWithInstalledKeysAndUpdatePathOrClose(
                    managed.handle,
                    managed.connectionRef(),
                    path,
                    now_nanos,
                    received.data,
                    .{
                        .space = .application,
                        .out = &endpoint_output,
                        .unpredictable_prefix = &[_]u8{},
                        .supported_versions = &[_]quic_packet.Version{.v1},
                        .path_challenge_data = path_challenge_data,
                    },
                );
                const application_route = switch (application_result.feed) {
                    .routed => |application_route| application_route,
                    .dropped => continue,
                    else => return error.InvalidPacket,
                };
                try require(application_route.connection_id == managed.handle);
                if (application_result.path_challenge_queued) {
                    std.debug.print("zig_process_server: connection={d} concurrent=true path_challenge_queued=true\n", .{managed.handle});
                }
                if (application_result.updated_route != null) {
                    std.debug.print("zig_process_server: connection={d} concurrent=true route_updated=true\n", .{managed.handle});
                }
                if (application_result.selected_output_path) |output_path| {
                    const path_output = (server_endpoint.pollOneRttDatagram(
                        managed.handle,
                        now_nanos,
                    ) catch |err| switch (err) {
                        error.ConnectionClosed => null,
                        else => return err,
                    }) orelse null;
                    if (path_output) |output_datagram| {
                        defer allocator.free(output_datagram);
                        const peer_address = peerAddressForPath(output_path);
                        try socket.send(io, &peer_address, output_datagram);
                    }
                }
                if (expect_client_reset and !managed.client_reset_received) {
                    if (try managed.transport.connection.streamState(echo_stream_ids[0])) |stream_state| {
                        if (stream_state.receive == .reset_received and stream_state.receive_reset_error_code == 41) {
                            managed.client_reset_received = true;
                            std.debug.print("zig_process_server: connection={d} concurrent=true client_reset_received=true reset_error=41\n", .{managed.handle});
                        }
                    }
                }
                if (expect_client_stop_sending) {
                    if (!managed.client_stop_sending_sent) {
                        if (try managed.transport.connection.streamState(echo_stream_ids[0])) |stream_state| {
                            if (stream_state.receive == .receiving and stream_state.receive_buffered.? != 0) {
                                try managed.transport.stopSending(echo_stream_ids[0], 42);
                                managed.client_stop_sending_sent = true;
                                std.debug.print("zig_process_server: connection={d} concurrent=true stop_sending_sent=true stop_error=42\n", .{managed.handle});
                            }
                        }
                    }
                    if (managed.client_stop_sending_sent and !managed.client_stop_reset_received) {
                        if (try managed.transport.connection.streamState(echo_stream_ids[0])) |stream_state| {
                            if (stream_state.receive == .reset_received and stream_state.receive_reset_error_code == 42) {
                                managed.client_stop_reset_received = true;
                                std.debug.print("zig_process_server: connection={d} concurrent=true client_stop_reset_received=true reset_error=42\n", .{managed.handle});
                            }
                        }
                    }
                }
                var queued_echo = false;
                if (expect_flow_control and !managed.flow_echoed) {
                    var flow_buffer: [1024]u8 = undefined;
                    while (try managed.transport.recvStream(echo_stream_ids[0], &flow_buffer)) |flow_len| {
                        const next_len = std.math.add(usize, managed.flow_bytes_received, flow_len) catch return error.UnexpectedState;
                        if (next_len > flow_control_payload.len or !std.mem.eql(u8, flow_buffer[0..flow_len], flow_control_payload[managed.flow_bytes_received..next_len])) return error.UnexpectedState;
                        managed.flow_bytes_received = next_len;
                    }
                    if (managed.flow_bytes_received == flow_control_payload.len and try managed.transport.streamFinished(echo_stream_ids[0])) {
                        try managed.transport.sendStream(echo_stream_ids[0], &flow_control_payload, true);
                        managed.flow_echoed = true;
                        queued_echo = true;
                    }
                }
                if (expect_client_uni_stream and !managed.client_uni_received) {
                    var uni_buffer: [128]u8 = undefined;
                    if (try managed.transport.recvStream(client_uni_stream_id, &uni_buffer)) |received_len| {
                        try require(std.mem.eql(u8, uni_buffer[0..received_len], client_uni_payload));
                        try require(try managed.transport.streamFinished(client_uni_stream_id));
                        managed.client_uni_received = true;
                        const uni_stream_id = try managed.transport.openUniStream();
                        try require(uni_stream_id == server_uni_stream_id);
                        try managed.transport.sendStream(uni_stream_id, server_uni_payload, true);
                        managed.server_uni_sent = true;
                        queued_echo = true;
                        std.debug.print("zig_process_server: connection={d} concurrent=true uni_received=true client_stream=2 server_stream=3\n", .{managed.handle});
                    }
                }
                if (!expect_flow_control) {
                    inline for (interop_echo_stream_ids, interop_echo_payloads, 0..) |stream_id, payload, index| {
                        const skip_echo = expect_client_stop_sending and index == 0;
                        if (!skip_echo and !managed.request_received[index]) {
                            var stream_buffer: [128]u8 = undefined;
                            const echo_len = managed.transport.recvStream(stream_id, &stream_buffer) catch |err| switch (err) {
                                error.StreamClosed, error.ConnectionClosed => null,
                                else => return err,
                            };
                            if (echo_len) |received_len| {
                                try require(std.mem.eql(u8, stream_buffer[0..received_len], payload));
                                try require(try managed.transport.streamFinished(stream_id));
                                managed.request_received[index] = true;
                            }
                        }
                        if (!skip_echo and managed.request_received[index] and !managed.echoed[index]) {
                            try managed.transport.sendStream(stream_id, payload, true);
                            managed.echoed[index] = true;
                            queued_echo = true;
                        }
                    }
                }
                var sent_packets: usize = 0;
                while (sent_packets < max_initial_datagrams) : (sent_packets += 1) {
                    const output_packet = (server_endpoint.pollOneRttDatagram(
                        managed.handle,
                        now_nanos + @as(i64, @intCast(sent_packets)),
                    ) catch |err| switch (err) {
                        error.ConnectionClosed => null,
                        else => return err,
                    }) orelse break;
                    defer allocator.free(output_packet);
                    try sendToCurrentRoute(io, socket, &server_endpoint, managed, output_packet);
                }
                if (queued_echo) {
                    try require(sent_packets > 0);
                }
                if (managed.transport.connection.connectionState() == .draining) {
                    if (expect_client_reset and !managed.client_reset_received) return error.UnexpectedState;
                    if (expect_client_stop_sending and !managed.client_stop_reset_received) return error.UnexpectedState;
                    if (expect_client_uni_stream and (!managed.client_uni_received or !managed.server_uni_sent)) return error.UnexpectedState;
                }
            },
            .version_negotiation => |datagram| try socket.send(io, &received.from, datagram),
            .stateless_reset => |datagram| try socket.send(io, &received.from, datagram),
            .dropped => {},
        }
    }
    try require(runs_continuously or accepted_count == completion_target);
    std.debug.print("zig_process_server: accepted_connections={d} max_active_connections={d} capacity_dropped_initials={d} concurrent=true complete=true\n", .{ accepted_count, max_active_connections, capacity_dropped_initials });
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next();
    const bind_host = args.next() orelse return error.MissingArgs;
    const bind_port = try std.fmt.parseInt(u16, args.next() orelse return error.MissingArgs, 10);
    const completion_target = if (args.next()) |raw_count|
        try std.fmt.parseInt(usize, raw_count, 10)
    else
        1;
    const mode = args.next() orelse "sequential";
    const max_active_connections = if (args.next()) |raw_count|
        try std.fmt.parseInt(usize, raw_count, 10)
    else if (completion_target != 0)
        completion_target
    else
        return error.MissingActiveConnectionCapacity;
    if (max_active_connections == 0) return error.InvalidConnectionCount;
    const idle_timeout_ms = if (args.next()) |raw_timeout|
        try std.fmt.parseInt(u64, raw_timeout, 10)
    else
        default_server_idle_timeout_ms;
    if (args.next() != null) return error.TooManyArgs;
    const bind_address = try std.Io.net.IpAddress.parseIp4(bind_host, bind_port);
    var socket = try bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    std.debug.print("zig_process_server: listening={s}:{d} completion_target={d} max_active_connections={d} idle_timeout_ms={d} mode={s}\n", .{ bind_host, bind_port, completion_target, max_active_connections, idle_timeout_ms, mode });

    // CERT/KEY environment variables override the embedded test certificate
    // (PEM loaded via quicz.tls_pem), matching the external server wrappers.
    var pem_cert_buf: [64 * 1024]u8 = undefined;
    var cert_der_buf: [8192]u8 = undefined;
    var key_pem_buf: [64 * 1024]u8 = undefined;
    var key_der_buf: [512]u8 = undefined;
    active_cert = &test_certs.cert_der;
    active_key = test_certs.private_key;
    if (init.environ_map.get("CERT")) |cert_path| {
        if (init.environ_map.get("KEY")) |key_path| {
            const cert_pem_data = try readFile(io, cert_path, &pem_cert_buf);
            active_cert = try quicz.tls_pem.decodeBlock(cert_pem_data, "CERTIFICATE", &cert_der_buf);
            const key_pem_data = try readFile(io, key_path, &key_pem_buf);
            active_key = try quicz.tls_pem.parsePrivateKeyP256(key_pem_data, &key_der_buf);
        }
    }

    if (std.mem.eql(u8, mode, "concurrent") or std.mem.eql(u8, mode, "rolling")) {
        return serveConcurrent(allocator, io, &socket, bind_address, completion_target, max_active_connections, false, 8, false, false, false, false, idle_timeout_ms);
    }
    if (std.mem.eql(u8, mode, "concurrent-retry")) {
        return serveConcurrent(allocator, io, &socket, bind_address, completion_target, max_active_connections, true, 8, false, false, false, false, idle_timeout_ms);
    }
    if (std.mem.eql(u8, mode, "concurrent-limit")) {
        return serveConcurrent(allocator, io, &socket, bind_address, completion_target, max_active_connections, false, 1, false, false, false, false, idle_timeout_ms);
    }
    if (std.mem.eql(u8, mode, "concurrent-reset")) {
        return serveConcurrent(allocator, io, &socket, bind_address, completion_target, max_active_connections, false, 8, true, false, false, false, idle_timeout_ms);
    }
    if (std.mem.eql(u8, mode, "concurrent-stop")) {
        return serveConcurrent(allocator, io, &socket, bind_address, completion_target, max_active_connections, false, 8, false, true, false, false, idle_timeout_ms);
    }
    if (std.mem.eql(u8, mode, "concurrent-uni")) {
        return serveConcurrent(allocator, io, &socket, bind_address, completion_target, max_active_connections, false, 8, false, false, true, false, idle_timeout_ms);
    }
    if (std.mem.eql(u8, mode, "concurrent-flow")) {
        return serveConcurrent(allocator, io, &socket, bind_address, completion_target, max_active_connections, false, 8, false, false, false, true, idle_timeout_ms);
    }
    if (!std.mem.eql(u8, mode, "sequential")) return error.InvalidMode;
    if (completion_target == 0) return error.InvalidConnectionCount;

    const alpn = [_][]const u8{"hq-interop"};
    for (0..completion_target) |connection_index| {
        var connection = try Connection.init(allocator, .server, .{
            .initial_max_data = 8192,
            .initial_max_stream_data = 2048,
            .initial_max_streams_bidi = 8,
            .max_datagram_size = server_max_datagram_size,
        });
        defer connection.deinit();
        try connection.validatePeerAddress();
        try connection.setLocalInitialSourceConnectionId(&server_scid);

        var backend = Tls13Backend.initServer(.{
            .alpn = &alpn,
            .cert_chain_der = &.{active_cert},
            .private_key_bytes = &active_key,
            .private_key_algorithm = .ecdsa_p256_sha256,
        });
        var scratch: [8192]u8 = undefined;
        var receive_buffer: [server_max_datagram_size]u8 = undefined;

        // The endpoint owns acceptance and route registration. Connection and TLS
        // storage are freshly allocated for each accepted connection.
        const server_handle: u64 = 1;
        var lifecycle = EndpointConnectionLifecycle.init(allocator);
        defer lifecycle.deinit();

        const received_initial = receive_initial: while (true) {
            const candidate = try socket.receiveTimeout(io, &receive_buffer, recvTimeout());
            const header = protection.peekProtectedLongPacketInfo(candidate.data) catch continue;
            // The previous session can leave late ACK or close packets on this socket.
            if (header.packet_type == .initial) break :receive_initial candidate;
        };
        const server_path = endpoint.Udp4Tuple{
            .local = endpoint.Udp4Address.init(bind_address.ip4.bytes, bind_address.ip4.port),
            .remote = endpoint.Udp4Address.init(received_initial.from.ip4.bytes, received_initial.from.ip4.port),
        };
        var endpoint_output: [128]u8 = undefined;
        const initial_accept = switch (try lifecycle.feedDatagram(
            &endpoint_output,
            server_path,
            received_initial.data,
            &[_]u8{},
            &[_]quic_packet.Version{.v1},
        )) {
            .accept_initial => |value| value,
            else => return error.InvalidPacket,
        };
        const initial_info = try protection.peekProtectedLongPacketInfo(received_initial.data);
        var original_dcid: [20]u8 = undefined;
        @memcpy(original_dcid[0..initial_info.dcid.len], initial_info.dcid);
        const initial_secrets = try protection.deriveInitialSecrets(initial_info.version, initial_info.dcid);
        const accepted_initial = try lifecycle.processAcceptedProtectedInitialWithCryptoBackendAndPollDatagram(
            server_handle,
            &connection,
            1,
            initial_accept,
            &server_scid,
            received_initial.data,
            .{ .active_migration_disabled = true },
            backend.cryptoBackend(),
            &scratch,
        );
        // The accept metadata borrows the UDP receive buffer, which subsequent
        // receives reuse. Keep the peer CID from Connection-owned state for the
        // later 1-RTT echo destination.
        const client_scid = connection.peerInitialSourceConnectionId() orelse return error.MissingPeerConnectionId;

        // A client may split its ClientHello across Initial packets or retransmit
        // an Initial before the server can emit a response. Keep using Connection's
        // authenticated CRYPTO reassembly until TLS derives Handshake keys, while
        // accepting only the original client's Initial DCID.
        var initial_progress = accepted_initial.backend;
        var initial_datagrams: usize = 1;
        while (!initial_progress.handshake_keys_installed and initial_datagrams < max_initial_datagrams) : (initial_datagrams += 1) {
            const next_initial = try socket.receiveTimeout(io, &receive_buffer, recvTimeout());
            const next_info = try protection.peekProtectedLongPacketInfo(next_initial.data);
            if (next_info.packet_type != .initial) return error.InvalidPacket;
            if (next_info.version != initial_info.version or !std.mem.eql(u8, next_info.dcid, original_dcid[0..initial_info.dcid.len])) {
                return error.InvalidPacket;
            }
            try connection.processProtectedLongDatagramInSpace(.initial, 1, initial_secrets.client, next_initial.data);
            initial_progress = try connection.driveCryptoBackendInSpace(.initial, backend.cryptoBackend(), &scratch);
        }
        try require(initial_progress.handshake_keys_installed);
        // A large external ClientHello can span several Initial packets. The
        // lifecycle's first poll is therefore allowed to be empty; after the
        // reassembly loop, poll the same lifecycle-owned output path once more.
        const server_initial = accepted_initial.response_datagram orelse
            (try lifecycle.pollProtectedLongCryptoDatagramInSpace(
                server_handle,
                &connection,
                .initial,
                @intCast(initial_datagrams),
                client_scid,
                &server_scid,
                &[_]u8{},
                initial_secrets.server,
            )) orelse return error.UnexpectedState;
        defer allocator.free(server_initial);
        try socket.send(io, &received_initial.from, server_initial);

        _ = try connection.driveCryptoBackendInSpace(.handshake, backend.cryptoBackend(), &scratch);
        const server_handshake = (try connection.pollProtectedHandshakeDatagramWithInstalledKeys(
            3,
            client_scid,
            &server_scid,
        )) orelse return error.UnexpectedState;
        defer allocator.free(server_handshake);
        try socket.send(io, &received_initial.from, server_handshake);

        // Clients may ACK the server Initial before sending Client Finished. Keep
        // consuming a bounded number of coalesced long-header datagrams until the
        // TLS backend reports completion instead of assuming the next packet is
        // necessarily a Handshake CRYPTO packet.
        var handshake_confirmed = false;
        var handshake_datagrams: usize = 0;
        while (!handshake_confirmed and handshake_datagrams < max_initial_datagrams) : (handshake_datagrams += 1) {
            const received = try socket.receiveTimeout(io, &receive_buffer, recvTimeout());
            var datagram_offset: usize = 0;
            var received_handshake = false;
            while (datagram_offset < received.data.len) {
                const packet_bytes = received.data[datagram_offset..];
                const long_info = try protection.peekProtectedLongPacketInfo(packet_bytes);
                const long_packet = packet_bytes[0..long_info.len];
                switch (long_info.packet_type) {
                    .initial => {
                        // Handshake keys prove the complete ClientHello was already
                        // reassembled. A coalesced follow-up Initial can only carry
                        // acknowledgements or a retransmission, so leave it
                        // unconsumed and continue with the following long packet.
                    },
                    .handshake => {
                        const client_route = try lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
                            server_handle,
                            &connection,
                            server_path,
                            4 + @as(i64, @intCast(handshake_datagrams)),
                            long_packet,
                        );
                        try require(client_route.connection_id == server_handle);
                        received_handshake = true;
                    },
                    else => return error.InvalidPacket,
                }
                datagram_offset += long_info.len;
            }
            if (!received_handshake) continue;
            const handshake_progress = try lifecycle.driveCryptoBackendInSpaceAndArmConnection(
                server_handle,
                &connection,
                .handshake,
                backend.cryptoBackend(),
                &scratch,
            );
            handshake_confirmed = handshake_progress.handshake_confirmed;
        }
        try require(handshake_confirmed);
        try require(connection.handshakeConfirmed());
        const confirmation = (try lifecycle.pollProtectedShortDatagramWithInstalledKeys(
            server_handle,
            &connection,
            4 + @as(i64, @intCast(handshake_datagrams)),
            client_scid,
        )) orelse return error.UnexpectedState;
        defer allocator.free(confirmation);
        try socket.send(io, &received_initial.from, confirmation);

        var request_received: [echo_stream_ids.len]bool = .{ false, false };
        var echoed: [echo_stream_ids.len]bool = .{ false, false };
        var application_datagrams: usize = 0;
        while (application_datagrams < max_application_datagrams) : (application_datagrams += 1) {
            const received = try socket.receiveTimeout(io, &receive_buffer, recvTimeout());
            const stream_route = try lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
                server_handle,
                &connection,
                server_path,
                5 + @as(i64, @intCast(application_datagrams)),
                received.data,
            );
            try require(stream_route.connection_id == server_handle);
            var queued_echo = false;
            inline for (echo_stream_ids, echo_payloads, 0..) |stream_id, payload, index| {
                if (!request_received[index]) {
                    var stream_buffer: [128]u8 = undefined;
                    if (try connection.recvOnStream(stream_id, &stream_buffer)) |received_len| {
                        try require(std.mem.eql(u8, stream_buffer[0..received_len], payload));
                        try require(try connection.recvStreamFinished(stream_id));
                        request_received[index] = true;
                    }
                }
                if (request_received[index] and !echoed[index]) {
                    try connection.sendOnStream(stream_id, payload, true);
                    echoed[index] = true;
                    queued_echo = true;
                }
            }
            if (queued_echo) {
                var sent_packets: usize = 0;
                while (sent_packets < 4) : (sent_packets += 1) {
                    const packet = (try lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                        server_handle,
                        &connection,
                        6 + @as(i64, @intCast(application_datagrams + sent_packets)),
                        client_scid,
                    )) orelse break;
                    defer allocator.free(packet);
                    try socket.send(io, &received_initial.from, packet);
                }
                try require(sent_packets > 0);
            }
            if (std.mem.allEqual(bool, &echoed, true)) break;
        }
        if (!std.mem.allEqual(bool, &request_received, true)) return error.MissingStreamData;
        if (!std.mem.allEqual(bool, &echoed, true)) return error.MissingStreamFin;

        // Independent clients can ACK in Initial, Handshake, or 1-RTT space before
        // their CONNECTION_CLOSE. Keep routing those authenticated packets until
        // the close is observed.
        var close_received = false;
        var close_datagrams: usize = 0;
        while (!close_received and close_datagrams < max_initial_datagrams) : (close_datagrams += 1) {
            const received = socket.receiveTimeout(io, &receive_buffer, recvTimeout()) catch |err| switch (err) {
                error.Timeout => break,
                else => return err,
            };
            const now_nanos = 10 + @as(i64, @intCast(close_datagrams));
            const close_route = if ((received.data[0] & 0x80) == 0)
                try lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
                    server_handle,
                    &connection,
                    server_path,
                    now_nanos,
                    received.data,
                )
            else blk: {
                const long_info = try protection.peekProtectedLongPacketInfo(received.data);
                const long_packet = received.data[0..long_info.len];
                break :blk switch (long_info.packet_type) {
                    // Once the handshake is confirmed, late packets in discarded
                    // long-header spaces can be routed but must not be decrypted
                    // with retired keys. Wait for the 1-RTT close instead.
                    .initial, .handshake => try lifecycle.routeDatagram(server_path, long_packet),
                    else => return error.InvalidPacket,
                };
            };
            try require(close_route.connection_id == server_handle);
            close_received = connection.connectionState() == .draining;
        }
        if (!close_received) {
            // Some clients terminate their local endpoint after the confirmed echo
            // without awaiting a peer close. Emit one local close before retiring
            // this one-shot server cleanly.
            try connection.closeConnection(0, 0, "process echo complete");
            const close_packet = (try lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                server_handle,
                &connection,
                10 + @as(i64, @intCast(close_datagrams)),
                client_scid,
            )) orelse return error.UnexpectedState;
            defer allocator.free(close_packet);
            try socket.send(io, &received_initial.from, close_packet);
        }
        const server_drain_deadline = connection.closeDeadline() orelse return error.UnexpectedState;
        const server_retired = (try lifecycle.checkCloseTimeoutsAndRetireConnection(
            server_handle,
            &connection,
            server_drain_deadline,
        )) orelse return error.UnexpectedState;
        try require(server_retired.routes_retired > 0);
        try require(connection.connectionState() == .closed);
        try require(lifecycle.routeCount() == 0);

        std.debug.print("zig_process_server: connection={d} handshake_done=true echo_streams=2 echo_bytes={d} close_cleanup=true\n", .{ connection_index + 1, echo_total_bytes });
    }
    std.debug.print("zig_process_server: accepted_connections={d} complete=true\n", .{completion_target});
}
