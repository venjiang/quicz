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

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const openssl_context = quicz_openssl_tls_backend_new() orelse return error.OutOfMemory;
    defer quicz_openssl_tls_backend_free(openssl_context);

    var tls_backend = quicz.TlsBackend{
        .context = openssl_context,
        .receive = quicz_openssl_tls_backend_receive,
        .pull = quicz_openssl_tls_backend_pull,
        .set_local_transport_parameters = quicz_openssl_tls_backend_set_local_transport_parameters,
        .pull_peer_transport_parameters = quicz_openssl_tls_backend_pull_peer_transport_parameters,
        .pull_handshake_traffic_secrets = quicz_openssl_tls_backend_pull_handshake_traffic_secrets,
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

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &original_dcid);
    try require(quicz_openssl_tls_backend_debug_yield_handshake_secret(
        openssl_context,
        1,
        &secrets.client.secret,
        secrets.client.secret.len,
    ) == .ok);
    try require(quicz_openssl_tls_backend_debug_yield_handshake_secret(
        openssl_context,
        0,
        &secrets.server.secret,
        secrets.server.secret.len,
    ) == .ok);

    const inbound_crypto = "openssl wrapper receives crypto";
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

    try require(quicz_openssl_tls_backend_debug_consume_inbound_once(openssl_context) == .ok);
    try require(quicz_openssl_tls_backend_inbound_crypto_recv_callbacks(openssl_context) == initial_recv_callbacks + 1);
    try require(quicz_openssl_tls_backend_inbound_crypto_release_callbacks(openssl_context) == initial_release_callbacks + 1);
    try require(quicz_openssl_tls_backend_pending_inbound_crypto_len(openssl_context) == 0);
    try require(quicz_openssl_tls_backend_released_inbound_crypto_len(openssl_context) == inbound_crypto.len);

    std.debug.print(
        "[tls-openssl-backend-adapter] callbacks={} ssl_is_quic={} local_tp_bytes={} initial_outbound_bytes={} generated_crypto_bytes={} handshake_drive_calls={} last_ssl_error={} peer_tp_bytes={} got_tp_callbacks={} yield_secret_callbacks={} handshake_inbound_bytes={} inbound_recv_callbacks={} inbound_release_callbacks={} inbound_released_bytes={} handshake_outbound_chunks={} handshake_keys={} confirmed={}\n",
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
            handshake_progress.inbound_bytes,
            quicz_openssl_tls_backend_inbound_crypto_recv_callbacks(openssl_context),
            quicz_openssl_tls_backend_inbound_crypto_release_callbacks(openssl_context),
            quicz_openssl_tls_backend_released_inbound_crypto_len(openssl_context),
            handshake_progress.outbound_chunks,
            handshake_progress.handshake_keys_installed,
            handshake_progress.handshake_confirmed,
        },
    );
}
