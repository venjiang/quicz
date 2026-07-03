#ifndef QUICZ_TLS_OPENSSL_BACKEND_ADAPTER_H
#define QUICZ_TLS_OPENSSL_BACKEND_ADAPTER_H

#include "tls_backend_c_abi.h"
#include "tls_openssl_pair_transcript.h"

void *quicz_openssl_tls_backend_new(void);
void *quicz_openssl_tls_backend_new_server(void);
void quicz_openssl_tls_backend_free(void *context);
enum quicz_tls_backend_status quicz_openssl_tls_backend_receive(
    void *context,
    enum quicz_tls_backend_packet_space space,
    const uint8_t *data,
    size_t data_len
);
enum quicz_tls_backend_status quicz_openssl_tls_backend_pull(
    void *context,
    enum quicz_tls_backend_packet_space space,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
);
enum quicz_tls_backend_status quicz_openssl_tls_backend_set_local_transport_parameters(
    void *context,
    const uint8_t *data,
    size_t data_len
);
enum quicz_tls_backend_status quicz_openssl_tls_backend_pull_peer_transport_parameters(
    void *context,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
);
enum quicz_tls_backend_status quicz_openssl_tls_backend_pull_handshake_traffic_secrets(
    void *context,
    struct quicz_handshake_traffic_secrets *out
);
enum quicz_tls_backend_status quicz_openssl_tls_backend_pull_1rtt_traffic_secrets(
    void *context,
    struct quicz_one_rtt_traffic_secrets *out
);
bool quicz_openssl_tls_backend_handshake_confirmed(void *context);
enum quicz_tls_backend_status quicz_openssl_tls_backend_pull_negotiated_alpn(
    void *context,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
);
int quicz_openssl_tls_backend_callbacks_set(void *context);
int quicz_openssl_tls_backend_local_transport_parameters_set(void *context);
int quicz_openssl_tls_backend_ssl_is_quic_after_callbacks(void *context);
size_t quicz_openssl_tls_backend_local_transport_parameters_len(void *context);
size_t quicz_openssl_tls_backend_received_crypto_len(void *context);
size_t quicz_openssl_tls_backend_peer_transport_parameters_len(void *context);
int quicz_openssl_tls_backend_got_transport_params_callbacks(void *context);
int quicz_openssl_tls_backend_keylog_callbacks(void *context);
size_t quicz_openssl_tls_backend_keylog_bytes(void *context);
int quicz_openssl_tls_backend_yield_secret_callbacks(void *context);
size_t quicz_openssl_tls_backend_pending_inbound_crypto_len(void *context);
size_t quicz_openssl_tls_backend_released_inbound_crypto_len(void *context);
int quicz_openssl_tls_backend_inbound_crypto_recv_callbacks(void *context);
int quicz_openssl_tls_backend_inbound_crypto_release_callbacks(void *context);
size_t quicz_openssl_tls_backend_generated_crypto_len(void *context);
int quicz_openssl_tls_backend_handshake_drive_calls(void *context);
int quicz_openssl_tls_backend_last_ssl_error(void *context);
enum quicz_tls_backend_status quicz_openssl_tls_backend_debug_consume_inbound_once(void *context);
enum quicz_tls_backend_status quicz_openssl_tls_backend_debug_copy_handshake_traffic_secrets(
    void *context,
    struct quicz_handshake_traffic_secrets *out
);
enum quicz_tls_backend_status quicz_openssl_tls_backend_debug_got_transport_parameters(
    void *context,
    const uint8_t *params,
    size_t params_len
);
enum quicz_tls_backend_status quicz_openssl_tls_backend_debug_yield_handshake_secret(
    void *context,
    int direction,
    const uint8_t *secret,
    size_t secret_len
);
enum quicz_tls_backend_status quicz_openssl_tls_backend_debug_yield_application_secret(
    void *context,
    int direction,
    const uint8_t *secret,
    size_t secret_len
);

#endif
