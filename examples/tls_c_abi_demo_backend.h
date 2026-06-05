#ifndef QUICZ_TLS_C_ABI_DEMO_BACKEND_H
#define QUICZ_TLS_C_ABI_DEMO_BACKEND_H

#include "tls_backend_c_abi.h"

void quicz_tls_c_demo_reset(void);
enum quicz_tls_backend_status quicz_tls_c_demo_set_peer_transport_parameters(const uint8_t *data, size_t data_len);
enum quicz_tls_backend_status quicz_tls_c_demo_set_outbound_crypto(const uint8_t *data, size_t data_len);
void quicz_tls_c_demo_set_handshake_secrets(const uint8_t *local, const uint8_t *peer, size_t secret_len);
enum quicz_tls_backend_status quicz_tls_c_demo_receive(
    void *context,
    enum quicz_tls_backend_packet_space space,
    const uint8_t *data,
    size_t data_len
);
enum quicz_tls_backend_status quicz_tls_c_demo_pull(
    void *context,
    enum quicz_tls_backend_packet_space space,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
);
enum quicz_tls_backend_status quicz_tls_c_demo_set_local_transport_parameters(
    void *context,
    const uint8_t *data,
    size_t data_len
);
enum quicz_tls_backend_status quicz_tls_c_demo_pull_peer_transport_parameters(
    void *context,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
);
enum quicz_tls_backend_status quicz_tls_c_demo_pull_handshake_traffic_secrets(
    void *context,
    struct quicz_handshake_traffic_secrets *out
);
bool quicz_tls_c_demo_handshake_confirmed(void *context);
size_t quicz_tls_c_demo_local_transport_parameters_len(void);
size_t quicz_tls_c_demo_inbound_crypto_len(void);
bool quicz_tls_c_demo_inbound_crypto_matches(const uint8_t *data, size_t data_len);

#endif
