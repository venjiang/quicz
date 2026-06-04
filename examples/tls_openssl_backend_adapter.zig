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
extern fn quicz_openssl_tls_backend_callbacks_set(context: *anyopaque) c_int;
extern fn quicz_openssl_tls_backend_local_transport_parameters_set(context: *anyopaque) c_int;
extern fn quicz_openssl_tls_backend_ssl_is_quic_after_callbacks(context: *anyopaque) c_int;
extern fn quicz_openssl_tls_backend_local_transport_parameters_len(context: *anyopaque) usize;
extern fn quicz_openssl_tls_backend_received_crypto_len(context: *anyopaque) usize;
extern fn quicz_openssl_tls_backend_generated_crypto_len(context: *anyopaque) usize;
extern fn quicz_openssl_tls_backend_handshake_drive_calls(context: *anyopaque) c_int;
extern fn quicz_openssl_tls_backend_last_ssl_error(context: *anyopaque) c_int;

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
    try require(handshake_progress.inbound_bytes == inbound_crypto.len);
    try require(handshake_progress.outbound_chunks == 0);
    try require(!handshake_progress.peer_transport_parameters_applied);
    try require(!handshake_progress.handshake_keys_installed);
    try require(!handshake_progress.handshake_confirmed);

    std.debug.print(
        "[tls-openssl-backend-adapter] callbacks={} ssl_is_quic={} local_tp_bytes={} initial_outbound_bytes={} generated_crypto_bytes={} handshake_drive_calls={} last_ssl_error={} handshake_inbound_bytes={} handshake_outbound_chunks={} handshake_keys={} confirmed={}\n",
        .{
            quicz_openssl_tls_backend_callbacks_set(openssl_context),
            quicz_openssl_tls_backend_ssl_is_quic_after_callbacks(openssl_context),
            initial_progress.local_transport_parameters_bytes,
            initial_progress.outbound_bytes,
            quicz_openssl_tls_backend_generated_crypto_len(openssl_context),
            quicz_openssl_tls_backend_handshake_drive_calls(openssl_context),
            quicz_openssl_tls_backend_last_ssl_error(openssl_context),
            handshake_progress.inbound_bytes,
            handshake_progress.outbound_chunks,
            handshake_progress.handshake_keys_installed,
            handshake_progress.handshake_confirmed,
        },
    );
}
