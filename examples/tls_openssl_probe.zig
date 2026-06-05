const std = @import("std");
const c = @import("c");

const ExampleError = error{UnexpectedState};

fn require(condition: bool) ExampleError!void {
    if (!condition) return error.UnexpectedState;
}

pub fn main() !void {
    const result = c.quicz_openssl_probe_run();

    try require(result.version_number != 0);
    try require(result.has_quic_method == 1);
    try require(result.quic_ctx_created == 1);
    try require(result.quic_ssl_created == 1);
    try require(result.quic_ssl_is_quic == 1);
    try require(result.tls_ctx_created == 1);
    try require(result.tls_ssl_created == 1);
    try require(result.tls_ssl_is_quic_before_callbacks == 0);
    try require(result.callbacks_set == 1);
    try require(result.transport_params_set == 1);
    try require(result.crypto_send_id == 2001);
    try require(result.yield_secret_id == 2004);
    try require(result.got_transport_params_id == 2005);

    std.debug.print(
        "[tls-openssl-probe] version=0x{x} quic_method={} quic_ctx={} quic_ssl={} quic_is_quic={} tls_ctx={} tls_ssl={} tls_quic_before={} callbacks={} tls_quic_after={} transport_params={} dispatch={}/{}/{}\n",
        .{
            result.version_number,
            result.has_quic_method,
            result.quic_ctx_created,
            result.quic_ssl_created,
            result.quic_ssl_is_quic,
            result.tls_ctx_created,
            result.tls_ssl_created,
            result.tls_ssl_is_quic_before_callbacks,
            result.callbacks_set,
            result.tls_ssl_is_quic_after_callbacks,
            result.transport_params_set,
            result.crypto_send_id,
            result.yield_secret_id,
            result.got_transport_params_id,
        },
    );
}
