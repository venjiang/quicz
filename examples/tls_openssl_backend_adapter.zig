const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

extern fn quicz_openssl_tls_backend_new() ?*anyopaque;
extern fn quicz_openssl_tls_backend_free(context: *anyopaque) void;
extern fn quicz_openssl_tls_backend_receive(
    context: *anyopaque,
    space: quicz.TlsBackendPacketSpace,
    data: [*]const u8,
    data_len: usize,
) callconv(.c) quicz.TlsBackendStatus;
extern fn quicz_openssl_tls_backend_pull(
    context: *anyopaque,
    space: quicz.TlsBackendPacketSpace,
    out: [*]u8,
    out_len: usize,
    written_len: *usize,
) callconv(.c) quicz.TlsBackendStatus;
extern fn quicz_openssl_tls_backend_set_local_transport_parameters(
    context: *anyopaque,
    data: [*]const u8,
    data_len: usize,
) callconv(.c) quicz.TlsBackendStatus;
extern fn quicz_openssl_tls_backend_pull_peer_transport_parameters(
    context: *anyopaque,
    out: [*]u8,
    out_len: usize,
    written_len: *usize,
) callconv(.c) quicz.TlsBackendStatus;
extern fn quicz_openssl_tls_backend_pull_handshake_traffic_secrets(
    context: *anyopaque,
    out: *quicz.HandshakeTrafficSecrets,
) callconv(.c) quicz.TlsBackendStatus;
extern fn quicz_openssl_tls_backend_pull_1rtt_traffic_secrets(
    context: *anyopaque,
    out: *quicz.OneRttTrafficSecrets,
) callconv(.c) quicz.TlsBackendStatus;
extern fn quicz_openssl_tls_backend_callbacks_set(context: *anyopaque) c_int;
extern fn quicz_openssl_tls_backend_local_transport_parameters_set(context: *anyopaque) c_int;
extern fn quicz_openssl_tls_backend_ssl_is_quic_after_callbacks(context: *anyopaque) c_int;
extern fn quicz_openssl_tls_backend_local_transport_parameters_len(context: *anyopaque) usize;
extern fn quicz_openssl_tls_backend_received_crypto_len(context: *anyopaque) usize;
extern fn quicz_openssl_tls_backend_peer_transport_parameters_len(context: *anyopaque) usize;
extern fn quicz_openssl_tls_backend_got_transport_params_callbacks(context: *anyopaque) c_int;
extern fn quicz_openssl_tls_backend_yield_secret_callbacks(context: *anyopaque) c_int;
extern fn quicz_openssl_tls_backend_pending_inbound_crypto_len(context: *anyopaque) usize;
extern fn quicz_openssl_tls_backend_released_inbound_crypto_len(context: *anyopaque) usize;
extern fn quicz_openssl_tls_backend_inbound_crypto_recv_callbacks(context: *anyopaque) c_int;
extern fn quicz_openssl_tls_backend_inbound_crypto_release_callbacks(context: *anyopaque) c_int;
extern fn quicz_openssl_tls_backend_generated_crypto_len(context: *anyopaque) usize;
extern fn quicz_openssl_tls_backend_handshake_drive_calls(context: *anyopaque) c_int;
extern fn quicz_openssl_tls_backend_last_ssl_error(context: *anyopaque) c_int;
extern fn quicz_openssl_tls_backend_debug_consume_inbound_once(context: *anyopaque) quicz.TlsBackendStatus;
extern fn quicz_openssl_tls_backend_debug_got_transport_parameters(
    context: *anyopaque,
    params: [*]const u8,
    params_len: usize,
) quicz.TlsBackendStatus;
extern fn quicz_openssl_tls_backend_debug_yield_handshake_secret(
    context: *anyopaque,
    direction: c_int,
    secret: [*]const u8,
    secret_len: usize,
) quicz.TlsBackendStatus;
extern fn quicz_openssl_tls_backend_debug_yield_application_secret(
    context: *anyopaque,
    direction: c_int,
    secret: [*]const u8,
    secret_len: usize,
) quicz.TlsBackendStatus;

const OpenSslPairTranscriptResult = extern struct {
    initialized: c_int,
    client_done: c_int,
    server_done: c_int,
    client_send_callbacks: c_int,
    server_send_callbacks: c_int,
    client_recv_callbacks: c_int,
    server_recv_callbacks: c_int,
    client_release_callbacks: c_int,
    server_release_callbacks: c_int,
    client_yield_secret_callbacks: c_int,
    server_yield_secret_callbacks: c_int,
    client_got_transport_params_callbacks: c_int,
    server_got_transport_params_callbacks: c_int,
    client_alert_callbacks: c_int,
    server_alert_callbacks: c_int,
    client_last_alert: c_int,
    server_last_alert: c_int,
    client_last_ssl_error: c_int,
    server_last_ssl_error: c_int,
    client_read_level: c_int,
    server_read_level: c_int,
    client_write_level: c_int,
    server_write_level: c_int,
    drive_iterations: c_int,
    error_queue_code: c_ulong,
    client_out_level_bytes: [4]usize,
    server_out_level_bytes: [4]usize,
};

extern fn quicz_openssl_pair_transcript_run() OpenSslPairTranscriptResult;
extern fn quicz_openssl_pair_transcript_copy_server_crypto(
    level: c_int,
    out: [*]u8,
    out_len: usize,
    written_len: *usize,
) c_int;
extern fn quicz_openssl_pair_transcript_copy_client_secret(
    level: c_int,
    direction: c_int,
    out: [*]u8,
    out_len: usize,
    written_len: *usize,
) c_int;
extern fn quicz_openssl_pair_transcript_copy_server_secret(
    level: c_int,
    direction: c_int,
    out: [*]u8,
    out_len: usize,
    written_len: *usize,
) c_int;

const FixedWriter = struct {
    buffer: []u8,
    pos: usize = 0,

    pub fn writer(self: *FixedWriter) *FixedWriter {
        return self;
    }

    pub fn writeByte(self: *FixedWriter, byte: u8) !void {
        if (self.pos >= self.buffer.len) return error.NoSpaceLeft;
        self.buffer[self.pos] = byte;
        self.pos += 1;
    }

    pub fn writeAll(self: *FixedWriter, bytes: []const u8) !void {
        if (self.buffer.len - self.pos < bytes.len) return error.NoSpaceLeft;
        @memcpy(self.buffer[self.pos..][0..bytes.len], bytes);
        self.pos += bytes.len;
    }

    pub fn getWritten(self: FixedWriter) []const u8 {
        return self.buffer[0..self.pos];
    }
};

fn require(condition: bool) ExampleError!void {
    if (!condition) return error.UnexpectedState;
}

fn fixedWriter(buffer: []u8) FixedWriter {
    return .{ .buffer = buffer };
}

fn copyOpenSslServerCrypto(level: usize, out: []u8) ExampleError![]const u8 {
    var written_len: usize = 0;
    const copied = quicz_openssl_pair_transcript_copy_server_crypto(
        @intCast(level),
        out.ptr,
        out.len,
        &written_len,
    );
    try require(copied == 1);
    return out[0..written_len];
}

fn copyOpenSslClientSecret(
    level: usize,
    direction: usize,
) ExampleError![quicz.protection.traffic_secret_len]u8 {
    var secret: [quicz.protection.traffic_secret_len]u8 = undefined;
    var written_len: usize = 0;
    const copied = quicz_openssl_pair_transcript_copy_client_secret(
        @intCast(level),
        @intCast(direction),
        &secret,
        secret.len,
        &written_len,
    );
    try require(copied == 1);
    try require(written_len == secret.len);
    return secret;
}

fn copyOpenSslServerSecret(
    level: usize,
    direction: usize,
) ExampleError![quicz.protection.traffic_secret_len]u8 {
    var secret: [quicz.protection.traffic_secret_len]u8 = undefined;
    var written_len: usize = 0;
    const copied = quicz_openssl_pair_transcript_copy_server_secret(
        @intCast(level),
        @intCast(direction),
        &secret,
        secret.len,
        &written_len,
    );
    try require(copied == 1);
    try require(written_len == secret.len);
    return secret;
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const transcript = quicz_openssl_pair_transcript_run();
    try require(transcript.initialized == 1);
    try require(transcript.client_done == 1);
    try require(transcript.server_done == 1);
    try require(transcript.client_alert_callbacks == 0);
    try require(transcript.server_alert_callbacks == 0);
    try require(transcript.client_last_ssl_error == 0);
    try require(transcript.server_last_ssl_error == 0);
    try require(transcript.client_yield_secret_callbacks >= 4);
    try require(transcript.server_yield_secret_callbacks >= 4);
    try require(transcript.server_out_level_bytes[2] > 0);

    const openssl_context = quicz_openssl_tls_backend_new() orelse return error.OutOfMemory;
    defer quicz_openssl_tls_backend_free(openssl_context);

    var tls_backend = quicz.TlsBackend{
        .context = openssl_context,
        .receive = quicz_openssl_tls_backend_receive,
        .pull = quicz_openssl_tls_backend_pull,
        .set_local_transport_parameters = quicz_openssl_tls_backend_set_local_transport_parameters,
        .pull_peer_transport_parameters = quicz_openssl_tls_backend_pull_peer_transport_parameters,
        .pull_handshake_traffic_secrets = quicz_openssl_tls_backend_pull_handshake_traffic_secrets,
        .pull_1rtt_traffic_secrets = quicz_openssl_tls_backend_pull_1rtt_traffic_secrets,
    };

    var connection = try quicz.Connection.init(allocator, .client, .{
        .initial_max_data = 4096,
        .initial_max_stream_data = 1024,
    });
    defer connection.deinit();

    var scratch: [4096]u8 = undefined;
    const initial_progress = try connection.driveCryptoBackendInSpace(
        .initial,
        tls_backend.cryptoBackend(),
        &scratch,
    );

    try require(quicz_openssl_tls_backend_callbacks_set(openssl_context) == 1);
    try require(quicz_openssl_tls_backend_ssl_is_quic_after_callbacks(openssl_context) == 0);
    try require(quicz_openssl_tls_backend_local_transport_parameters_set(openssl_context) == 1);
    try require(quicz_openssl_tls_backend_local_transport_parameters_len(openssl_context) == initial_progress.local_transport_parameters_bytes);
    try require(quicz_openssl_tls_backend_handshake_drive_calls(openssl_context) > 0);
    try require(quicz_openssl_tls_backend_generated_crypto_len(openssl_context) > 0);
    try require(initial_progress.inbound_bytes == 0);
    try require(initial_progress.outbound_chunks == 1);
    try require(initial_progress.outbound_bytes == quicz_openssl_tls_backend_generated_crypto_len(openssl_context));
    try require(!initial_progress.peer_transport_parameters_applied);
    try require(!initial_progress.handshake_keys_installed);
    try require(!initial_progress.handshake_confirmed);
    const initial_recv_callbacks = quicz_openssl_tls_backend_inbound_crypto_recv_callbacks(openssl_context);
    const initial_release_callbacks = quicz_openssl_tls_backend_inbound_crypto_release_callbacks(openssl_context);

    var peer_transport_parameter_buf: [128]u8 = undefined;
    var peer_transport_parameter_out = fixedWriter(&peer_transport_parameter_buf);
    try quicz.transport_parameters.encode(peer_transport_parameter_out.writer(), .{
        .initial_max_data = 8192,
        .initial_max_stream_data_bidi_local = 2048,
        .initial_max_streams_bidi = 8,
    });
    const peer_transport_parameters = peer_transport_parameter_out.getWritten();
    try require(quicz_openssl_tls_backend_debug_got_transport_parameters(
        openssl_context,
        peer_transport_parameters.ptr,
        peer_transport_parameters.len,
    ) == .ok);

    const client_handshake_local = try copyOpenSslClientSecret(2, 1);
    const client_handshake_peer = try copyOpenSslClientSecret(2, 0);
    try require(quicz_openssl_tls_backend_debug_yield_handshake_secret(
        openssl_context,
        1,
        &client_handshake_local,
        client_handshake_local.len,
    ) == .ok);
    try require(quicz_openssl_tls_backend_debug_yield_handshake_secret(
        openssl_context,
        0,
        &client_handshake_peer,
        client_handshake_peer.len,
    ) == .ok);

    var inbound_crypto_buf: [8192]u8 = undefined;
    const inbound_crypto = try copyOpenSslServerCrypto(2, &inbound_crypto_buf);
    try require(inbound_crypto.len == transcript.server_out_level_bytes[2]);
    var inbound_payload_buf: [96]u8 = undefined;
    var inbound_payload = fixedWriter(&inbound_payload_buf);
    try quicz.frame.encodeFrame(inbound_payload.writer(), .{ .crypto = .{
        .offset = 0,
        .data = inbound_crypto,
    } });
    try connection.processDatagramInSpace(.handshake, 0, inbound_payload.getWritten());

    const handshake_progress = try connection.driveCryptoBackendInSpace(
        .handshake,
        tls_backend.cryptoBackend(),
        &scratch,
    );

    try require(quicz_openssl_tls_backend_received_crypto_len(openssl_context) == inbound_crypto.len);
    try require(quicz_openssl_tls_backend_peer_transport_parameters_len(openssl_context) == peer_transport_parameters.len);
    try require(quicz_openssl_tls_backend_got_transport_params_callbacks(openssl_context) == 1);
    try require(quicz_openssl_tls_backend_yield_secret_callbacks(openssl_context) == 2);
    try require(quicz_openssl_tls_backend_pending_inbound_crypto_len(openssl_context) == inbound_crypto.len);
    try require(handshake_progress.peer_transport_parameters_applied);
    try require(handshake_progress.peer_transport_parameters_bytes == peer_transport_parameters.len);
    try require(handshake_progress.handshake_keys_installed);
    try require(handshake_progress.inbound_bytes == inbound_crypto.len);
    try require(handshake_progress.outbound_chunks == 0);
    try require(!handshake_progress.handshake_confirmed);
    try require(connection.hasHandshakeProtectionKeys());

    const client_application_local = try copyOpenSslClientSecret(3, 1);
    const client_application_peer = try copyOpenSslClientSecret(3, 0);
    const server_application_local = try copyOpenSslServerSecret(3, 1);
    const server_application_peer = try copyOpenSslServerSecret(3, 0);
    try require(std.mem.eql(u8, &client_application_local, &server_application_peer));
    try require(std.mem.eql(u8, &server_application_local, &client_application_peer));

    try require(quicz_openssl_tls_backend_debug_yield_application_secret(
        openssl_context,
        1,
        &client_application_local,
        client_application_local.len,
    ) == .ok);
    try require(quicz_openssl_tls_backend_debug_yield_application_secret(
        openssl_context,
        0,
        &client_application_peer,
        client_application_peer.len,
    ) == .ok);

    const application_progress = try connection.driveCryptoBackendInSpace(
        .application,
        tls_backend.cryptoBackend(),
        &scratch,
    );
    try require(quicz_openssl_tls_backend_yield_secret_callbacks(openssl_context) == 4);
    try require(application_progress.one_rtt_keys_installed);
    try require(!application_progress.peer_transport_parameters_applied);
    try require(!application_progress.handshake_keys_installed);
    try require(!application_progress.zero_rtt_keys_installed);
    try require(application_progress.inbound_bytes == 0);
    try require(application_progress.outbound_chunks == 0);
    try require(!application_progress.handshake_confirmed);
    try require(connection.hasOneRttProtectionKeys());

    var peer = try quicz.Connection.init(allocator, .server, .{
        .initial_max_data = 4096,
        .initial_max_stream_data = 1024,
        .initial_max_streams_bidi = 4,
    });
    defer peer.deinit();
    try peer.installOneRttTrafficSecrets(.{
        .local = server_application_local,
        .peer = server_application_peer,
    });
    try connection.confirmHandshake();
    try peer.confirmHandshake();
    try peer.validatePeerAddress();
    try require(peer.hasOneRttProtectionKeys());

    const client_dcid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    const server_dcid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    try connection.sendPing();
    const protected_ping = (try connection.pollProtectedShortDatagramWithInstalledKeys(
        30,
        &server_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(protected_ping);
    try require(protected_ping.len > 0);
    try peer.processProtectedShortDatagramWithInstalledKeys(31, server_dcid.len, protected_ping);
    const server_ack_largest = peer.pendingAckLargest(.application) orelse return error.UnexpectedState;
    try require(server_ack_largest == 0);

    const protected_ack = (try peer.pollProtectedShortDatagramWithInstalledKeys(
        32,
        &client_dcid,
    )) orelse return error.UnexpectedState;
    defer allocator.free(protected_ack);
    try require(protected_ack.len > 0);
    try connection.processProtectedShortDatagramWithInstalledKeys(33, client_dcid.len, protected_ack);
    try require(connection.bytesInFlight(.application) == 0);

    try require(quicz_openssl_tls_backend_debug_consume_inbound_once(openssl_context) == .ok);
    try require(quicz_openssl_tls_backend_inbound_crypto_recv_callbacks(openssl_context) == initial_recv_callbacks + 1);
    try require(quicz_openssl_tls_backend_inbound_crypto_release_callbacks(openssl_context) == initial_release_callbacks + 1);
    try require(quicz_openssl_tls_backend_pending_inbound_crypto_len(openssl_context) == 0);
    try require(quicz_openssl_tls_backend_released_inbound_crypto_len(openssl_context) == inbound_crypto.len);

    std.debug.print(
        "[tls-openssl-backend-adapter] callbacks={} ssl_is_quic={} local_tp_bytes={} initial_outbound_bytes={} generated_crypto_bytes={} handshake_drive_calls={} last_ssl_error={} peer_tp_bytes={} got_tp_callbacks={} yield_secret_callbacks={} transcript_handshake_bytes={} handshake_inbound_bytes={} inbound_recv_callbacks={} inbound_release_callbacks={} inbound_released_bytes={} handshake_outbound_chunks={} handshake_keys={} one_rtt_keys={} protected_ping_bytes={} protected_ack_bytes={} server_ack_largest={} client_inflight={} confirmed={}\n",
        .{
            quicz_openssl_tls_backend_callbacks_set(openssl_context),
            quicz_openssl_tls_backend_ssl_is_quic_after_callbacks(openssl_context),
            initial_progress.local_transport_parameters_bytes,
            initial_progress.outbound_bytes,
            quicz_openssl_tls_backend_generated_crypto_len(openssl_context),
            quicz_openssl_tls_backend_handshake_drive_calls(openssl_context),
            quicz_openssl_tls_backend_last_ssl_error(openssl_context),
            handshake_progress.peer_transport_parameters_bytes,
            quicz_openssl_tls_backend_got_transport_params_callbacks(openssl_context),
            quicz_openssl_tls_backend_yield_secret_callbacks(openssl_context),
            transcript.server_out_level_bytes[2],
            handshake_progress.inbound_bytes,
            quicz_openssl_tls_backend_inbound_crypto_recv_callbacks(openssl_context),
            quicz_openssl_tls_backend_inbound_crypto_release_callbacks(openssl_context),
            quicz_openssl_tls_backend_released_inbound_crypto_len(openssl_context),
            handshake_progress.outbound_chunks,
            handshake_progress.handshake_keys_installed,
            application_progress.one_rtt_keys_installed,
            protected_ping.len,
            protected_ack.len,
            server_ack_largest,
            connection.bytesInFlight(.application),
            application_progress.handshake_confirmed,
        },
    );
}
