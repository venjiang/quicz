const std = @import("std");

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

fn require(condition: bool) ExampleError!void {
    if (!condition) return error.UnexpectedState;
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
    try require(result.client_out_level_bytes[0] > 0);
    try require(result.server_out_level_bytes[0] > 0);
    try require(result.server_out_level_bytes[2] > 0);
    try require(result.server_out_level_bytes[3] > 0);
    try require(result.error_queue_code == 0);

    std.debug.print(
        "[tls-openssl-pair-transcript] initialized={} client_done={} server_done={} client_send={} server_send={} client_recv={} server_recv={} client_release={} server_release={} client_yield={} server_yield={} client_tp={} server_tp={} client_levels={}/{}/{}/{} server_levels={}/{}/{}/{} iterations={} alerts={}/{} errors={}/{}\n",
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
            result.drive_iterations,
            result.client_alert_callbacks,
            result.server_alert_callbacks,
            result.client_last_ssl_error,
            result.server_last_ssl_error,
        },
    );
}
