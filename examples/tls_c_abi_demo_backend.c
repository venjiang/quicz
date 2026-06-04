#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum quicz_tls_backend_status {
    QUICZ_TLS_BACKEND_OK = 0,
    QUICZ_TLS_BACKEND_PENDING = 1,
    QUICZ_TLS_BACKEND_BUFFER_TOO_SMALL = 2,
    QUICZ_TLS_BACKEND_CRYPTO_ERROR = 3,
    QUICZ_TLS_BACKEND_INTERNAL = 4,
};

enum quicz_tls_backend_packet_space {
    QUICZ_TLS_BACKEND_INITIAL = 0,
    QUICZ_TLS_BACKEND_HANDSHAKE = 1,
    QUICZ_TLS_BACKEND_APPLICATION = 2,
};

struct quicz_handshake_traffic_secrets {
    uint8_t local[32];
    uint8_t peer[32];
};

static uint8_t local_transport_parameters[256];
static size_t local_transport_parameters_len;
static uint8_t inbound_crypto[128];
static size_t inbound_crypto_len;
static uint8_t peer_transport_parameters[128];
static size_t peer_transport_parameters_len;
static bool peer_transport_parameters_sent;
static uint8_t outbound_crypto[128];
static size_t outbound_crypto_len;
static bool outbound_crypto_sent;
static struct quicz_handshake_traffic_secrets handshake_secrets;
static bool handshake_secrets_sent;

void quicz_tls_c_demo_reset(void) {
    local_transport_parameters_len = 0;
    inbound_crypto_len = 0;
    peer_transport_parameters_len = 0;
    peer_transport_parameters_sent = false;
    outbound_crypto_len = 0;
    outbound_crypto_sent = false;
    memset(&handshake_secrets, 0, sizeof(handshake_secrets));
    handshake_secrets_sent = false;
}

enum quicz_tls_backend_status quicz_tls_c_demo_set_peer_transport_parameters(
    const uint8_t *data,
    size_t data_len
) {
    if (data_len > sizeof(peer_transport_parameters)) {
        return QUICZ_TLS_BACKEND_BUFFER_TOO_SMALL;
    }
    memcpy(peer_transport_parameters, data, data_len);
    peer_transport_parameters_len = data_len;
    peer_transport_parameters_sent = false;
    return QUICZ_TLS_BACKEND_OK;
}

enum quicz_tls_backend_status quicz_tls_c_demo_set_outbound_crypto(
    const uint8_t *data,
    size_t data_len
) {
    if (data_len > sizeof(outbound_crypto)) {
        return QUICZ_TLS_BACKEND_BUFFER_TOO_SMALL;
    }
    memcpy(outbound_crypto, data, data_len);
    outbound_crypto_len = data_len;
    outbound_crypto_sent = false;
    return QUICZ_TLS_BACKEND_OK;
}

void quicz_tls_c_demo_set_handshake_secrets(
    const uint8_t *local,
    const uint8_t *peer,
    size_t secret_len
) {
    if (secret_len > sizeof(handshake_secrets.local)) {
        secret_len = sizeof(handshake_secrets.local);
    }
    memcpy(handshake_secrets.local, local, secret_len);
    memcpy(handshake_secrets.peer, peer, secret_len);
    handshake_secrets_sent = false;
}

enum quicz_tls_backend_status quicz_tls_c_demo_receive(
    void *context,
    enum quicz_tls_backend_packet_space space,
    const uint8_t *data,
    size_t data_len
) {
    (void)context;
    if (space != QUICZ_TLS_BACKEND_HANDSHAKE) {
        return QUICZ_TLS_BACKEND_CRYPTO_ERROR;
    }
    if (data_len > sizeof(inbound_crypto) - inbound_crypto_len) {
        return QUICZ_TLS_BACKEND_BUFFER_TOO_SMALL;
    }
    memcpy(inbound_crypto + inbound_crypto_len, data, data_len);
    inbound_crypto_len += data_len;
    return QUICZ_TLS_BACKEND_OK;
}

enum quicz_tls_backend_status quicz_tls_c_demo_pull(
    void *context,
    enum quicz_tls_backend_packet_space space,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
) {
    (void)context;
    if (space != QUICZ_TLS_BACKEND_HANDSHAKE) {
        return QUICZ_TLS_BACKEND_CRYPTO_ERROR;
    }
    if (outbound_crypto_sent) {
        return QUICZ_TLS_BACKEND_PENDING;
    }
    if (out_len < outbound_crypto_len) {
        return QUICZ_TLS_BACKEND_BUFFER_TOO_SMALL;
    }
    memcpy(out, outbound_crypto, outbound_crypto_len);
    *written_len = outbound_crypto_len;
    outbound_crypto_sent = true;
    return QUICZ_TLS_BACKEND_OK;
}

enum quicz_tls_backend_status quicz_tls_c_demo_set_local_transport_parameters(
    void *context,
    const uint8_t *data,
    size_t data_len
) {
    (void)context;
    if (data_len > sizeof(local_transport_parameters)) {
        return QUICZ_TLS_BACKEND_BUFFER_TOO_SMALL;
    }
    memcpy(local_transport_parameters, data, data_len);
    local_transport_parameters_len = data_len;
    return QUICZ_TLS_BACKEND_OK;
}

enum quicz_tls_backend_status quicz_tls_c_demo_pull_peer_transport_parameters(
    void *context,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
) {
    (void)context;
    if (peer_transport_parameters_sent) {
        return QUICZ_TLS_BACKEND_PENDING;
    }
    if (out_len < peer_transport_parameters_len) {
        return QUICZ_TLS_BACKEND_BUFFER_TOO_SMALL;
    }
    memcpy(out, peer_transport_parameters, peer_transport_parameters_len);
    *written_len = peer_transport_parameters_len;
    peer_transport_parameters_sent = true;
    return QUICZ_TLS_BACKEND_OK;
}

enum quicz_tls_backend_status quicz_tls_c_demo_pull_handshake_traffic_secrets(
    void *context,
    struct quicz_handshake_traffic_secrets *out
) {
    (void)context;
    if (handshake_secrets_sent) {
        return QUICZ_TLS_BACKEND_PENDING;
    }
    *out = handshake_secrets;
    handshake_secrets_sent = true;
    return QUICZ_TLS_BACKEND_OK;
}

bool quicz_tls_c_demo_handshake_confirmed(void *context) {
    (void)context;
    return true;
}

size_t quicz_tls_c_demo_local_transport_parameters_len(void) {
    return local_transport_parameters_len;
}

size_t quicz_tls_c_demo_inbound_crypto_len(void) {
    return inbound_crypto_len;
}

bool quicz_tls_c_demo_inbound_crypto_matches(const uint8_t *data, size_t data_len) {
    return inbound_crypto_len == data_len && memcmp(inbound_crypto, data, data_len) == 0;
}
