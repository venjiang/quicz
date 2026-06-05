const std = @import("std");
const quicz = @import("quicz");

const ExampleError = error{UnexpectedState};

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
extern fn quicz_openssl_pair_transcript_copy_client_crypto(
    level: c_int,
    out: [*]u8,
    out_len: usize,
    written_len: *usize,
) c_int;
extern fn quicz_openssl_pair_transcript_copy_server_crypto(
    level: c_int,
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

fn packetNumberSpaceForOpenSslLevel(level: usize) ?quicz.PacketNumberSpace {
    return switch (level) {
        0 => .initial,
        2 => .handshake,
        3 => .application,
        else => null,
    };
}

fn copyOpenSslCrypto(is_client: bool, level: usize, out: []u8) ExampleError![]const u8 {
    var written_len: usize = 0;
    const copied = if (is_client)
        quicz_openssl_pair_transcript_copy_client_crypto(
            @intCast(level),
            out.ptr,
            out.len,
            &written_len,
        )
    else
        quicz_openssl_pair_transcript_copy_server_crypto(
            @intCast(level),
            out.ptr,
            out.len,
            &written_len,
        );
    try require(copied == 1);
    return out[0..written_len];
}

fn injectCryptoFrame(
    receiver: *quicz.Connection,
    space: quicz.PacketNumberSpace,
    data: []const u8,
) !void {
    var raw: [8192]u8 = undefined;
    var writer = fixedWriter(&raw);
    try quicz.frame.encodeFrame(writer.writer(), .{ .crypto = .{
        .offset = 0,
        .data = data,
    } });
    try receiver.processDatagramInSpace(space, 0, writer.getWritten());
}

fn verifyCryptoDelivery(
    sender_is_client: bool,
    level: usize,
    expected_len: usize,
    receiver: *quicz.Connection,
) !usize {
    var crypto_bytes: [8192]u8 = undefined;
    const copied = try copyOpenSslCrypto(sender_is_client, level, &crypto_bytes);
    try require(copied.len == expected_len);
    if (copied.len == 0) return 0;

    const space = packetNumberSpaceForOpenSslLevel(level) orelse return error.UnexpectedState;
    try injectCryptoFrame(receiver, space, copied);

    var read_buf: [8192]u8 = undefined;
    const read_len = (try receiver.recvCryptoInSpace(space, &read_buf)) orelse return error.UnexpectedState;
    try require(read_len == copied.len);
    try require(std.mem.eql(u8, read_buf[0..read_len], copied));
    try require((try receiver.recvCryptoInSpace(space, &read_buf)) == null);
    return read_len;
}

pub fn main() !void {
    const result = quicz_openssl_pair_transcript_run();

    try require(result.initialized == 1);
    try require(result.client_done == 1);
    try require(result.server_done == 1);
    try require(result.client_last_ssl_error == 0);
    try require(result.server_last_ssl_error == 0);
    try require(result.client_alert_callbacks == 0);
    try require(result.server_alert_callbacks == 0);
    try require(result.client_yield_secret_callbacks >= 4);
    try require(result.server_yield_secret_callbacks >= 4);
    try require(result.client_got_transport_params_callbacks == 1);
    try require(result.server_got_transport_params_callbacks == 1);
    try require(result.client_send_callbacks > 0);
    try require(result.server_send_callbacks > 0);
    try require(result.client_recv_callbacks > 0);
    try require(result.server_recv_callbacks > 0);
    try require(result.client_release_callbacks > 0);
    try require(result.server_release_callbacks > 0);
    try require(result.client_read_level == 3);
    try require(result.server_read_level == 3);
    try require(result.client_write_level == 3);
    try require(result.server_write_level == 3);
    try require(result.client_out_level_bytes[1] == 0);
    try require(result.server_out_level_bytes[1] == 0);
    try require(result.client_out_level_bytes[0] > 0);
    try require(result.server_out_level_bytes[0] > 0);
    try require(result.server_out_level_bytes[2] > 0);
    try require(result.server_out_level_bytes[3] > 0);
    try require(result.error_queue_code == 0);

    const allocator = std.heap.page_allocator;
    var client_connection = try quicz.Connection.init(allocator, .client, .{
        .max_datagram_size = 8192,
    });
    defer client_connection.deinit();
    var server_connection = try quicz.Connection.init(allocator, .server, .{
        .max_datagram_size = 8192,
    });
    defer server_connection.deinit();

    const client_initial_bytes = try verifyCryptoDelivery(
        true,
        0,
        result.client_out_level_bytes[0],
        &server_connection,
    );
    const server_initial_bytes = try verifyCryptoDelivery(
        false,
        0,
        result.server_out_level_bytes[0],
        &client_connection,
    );
    const client_handshake_bytes = try verifyCryptoDelivery(
        true,
        2,
        result.client_out_level_bytes[2],
        &server_connection,
    );
    const server_handshake_bytes = try verifyCryptoDelivery(
        false,
        2,
        result.server_out_level_bytes[2],
        &client_connection,
    );
    const client_application_bytes = try verifyCryptoDelivery(
        true,
        3,
        result.client_out_level_bytes[3],
        &server_connection,
    );
    const server_application_bytes = try verifyCryptoDelivery(
        false,
        3,
        result.server_out_level_bytes[3],
        &client_connection,
    );

    std.debug.print(
        "[tls-openssl-pair-transcript] initialized={} client_done={} server_done={} client_send={} server_send={} client_recv={} server_recv={} client_release={} server_release={} client_yield={} server_yield={} client_tp={} server_tp={} client_levels={}/{}/{}/{} server_levels={}/{}/{}/{} quicz_delivery={}/{}/{}/{}/{}/{} iterations={} alerts={}/{} errors={}/{}\n",
        .{
            result.initialized,
            result.client_done,
            result.server_done,
            result.client_send_callbacks,
            result.server_send_callbacks,
            result.client_recv_callbacks,
            result.server_recv_callbacks,
            result.client_release_callbacks,
            result.server_release_callbacks,
            result.client_yield_secret_callbacks,
            result.server_yield_secret_callbacks,
            result.client_got_transport_params_callbacks,
            result.server_got_transport_params_callbacks,
            result.client_out_level_bytes[0],
            result.client_out_level_bytes[1],
            result.client_out_level_bytes[2],
            result.client_out_level_bytes[3],
            result.server_out_level_bytes[0],
            result.server_out_level_bytes[1],
            result.server_out_level_bytes[2],
            result.server_out_level_bytes[3],
            client_initial_bytes,
            server_initial_bytes,
            client_handshake_bytes,
            server_handshake_bytes,
            client_application_bytes,
            server_application_bytes,
            result.drive_iterations,
            result.client_alert_callbacks,
            result.server_alert_callbacks,
            result.client_last_ssl_error,
            result.server_last_ssl_error,
        },
    );
}
