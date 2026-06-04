#include <openssl/core_dispatch.h>
#include <openssl/ssl.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

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

struct quicz_openssl_tls_backend {
    SSL_CTX *ctx;
    SSL *ssl;
    int callbacks_set;
    int local_transport_parameters_set;
    int ssl_is_quic_after_callbacks;
    size_t local_transport_parameters_len;
    size_t received_crypto_len;
};

static int crypto_send_cb(SSL *ssl, const unsigned char *buf, size_t buf_len, size_t *consumed, void *arg) {
    (void)ssl;
    (void)buf;
    (void)arg;
    *consumed = buf_len;
    return 1;
}

static int crypto_recv_rcd_cb(SSL *ssl, const unsigned char **buf, size_t *bytes_read, void *arg) {
    (void)ssl;
    (void)arg;
    *buf = NULL;
    *bytes_read = 0;
    return 1;
}

static int crypto_release_rcd_cb(SSL *ssl, size_t bytes_read, void *arg) {
    (void)ssl;
    (void)bytes_read;
    (void)arg;
    return 1;
}

static int yield_secret_cb(
    SSL *ssl,
    uint32_t prot_level,
    int direction,
    const unsigned char *secret,
    size_t secret_len,
    void *arg
) {
    (void)ssl;
    (void)prot_level;
    (void)direction;
    (void)secret;
    (void)secret_len;
    (void)arg;
    return 1;
}

static int got_transport_params_cb(SSL *ssl, const unsigned char *params, size_t params_len, void *arg) {
    (void)ssl;
    (void)params;
    (void)params_len;
    (void)arg;
    return 1;
}

static int alert_cb(SSL *ssl, unsigned char alert_code, void *arg) {
    (void)ssl;
    (void)alert_code;
    (void)arg;
    return 1;
}

static const OSSL_DISPATCH quicz_openssl_tls_dispatch[] = {
    { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND, (void (*)(void))crypto_send_cb },
    { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD, (void (*)(void))crypto_recv_rcd_cb },
    { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD, (void (*)(void))crypto_release_rcd_cb },
    { OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET, (void (*)(void))yield_secret_cb },
    { OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS, (void (*)(void))got_transport_params_cb },
    { OSSL_FUNC_SSL_QUIC_TLS_ALERT, (void (*)(void))alert_cb },
    { 0, NULL },
};

void *quicz_openssl_tls_backend_new(void) {
    struct quicz_openssl_tls_backend *backend = calloc(1, sizeof(*backend));
    if (backend == NULL) {
        return NULL;
    }

    backend->ctx = SSL_CTX_new(TLS_client_method());
    if (backend->ctx == NULL) {
        free(backend);
        return NULL;
    }

    backend->ssl = SSL_new(backend->ctx);
    if (backend->ssl == NULL) {
        SSL_CTX_free(backend->ctx);
        free(backend);
        return NULL;
    }

    backend->callbacks_set = SSL_set_quic_tls_cbs(backend->ssl, quicz_openssl_tls_dispatch, backend);
    backend->ssl_is_quic_after_callbacks = SSL_is_quic(backend->ssl);
    return backend;
}

void quicz_openssl_tls_backend_free(void *context) {
    struct quicz_openssl_tls_backend *backend = context;
    if (backend == NULL) {
        return;
    }
    SSL_free(backend->ssl);
    SSL_CTX_free(backend->ctx);
    free(backend);
}

enum quicz_tls_backend_status quicz_openssl_tls_backend_receive(
    void *context,
    enum quicz_tls_backend_packet_space space,
    const uint8_t *data,
    size_t data_len
) {
    struct quicz_openssl_tls_backend *backend = context;
    if (backend == NULL || backend->ssl == NULL) {
        return QUICZ_TLS_BACKEND_INTERNAL;
    }
    if (space != QUICZ_TLS_BACKEND_HANDSHAKE) {
        return QUICZ_TLS_BACKEND_CRYPTO_ERROR;
    }
    (void)data;
    backend->received_crypto_len += data_len;
    return QUICZ_TLS_BACKEND_OK;
}

enum quicz_tls_backend_status quicz_openssl_tls_backend_pull(
    void *context,
    enum quicz_tls_backend_packet_space space,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
) {
    (void)context;
    (void)space;
    (void)out;
    (void)out_len;
    *written_len = 0;
    return QUICZ_TLS_BACKEND_PENDING;
}

enum quicz_tls_backend_status quicz_openssl_tls_backend_set_local_transport_parameters(
    void *context,
    const uint8_t *data,
    size_t data_len
) {
    struct quicz_openssl_tls_backend *backend = context;
    if (backend == NULL || backend->ssl == NULL) {
        return QUICZ_TLS_BACKEND_INTERNAL;
    }
    if (!SSL_set_quic_tls_transport_params(backend->ssl, data, data_len)) {
        return QUICZ_TLS_BACKEND_CRYPTO_ERROR;
    }
    backend->local_transport_parameters_set = 1;
    backend->local_transport_parameters_len = data_len;
    return QUICZ_TLS_BACKEND_OK;
}

enum quicz_tls_backend_status quicz_openssl_tls_backend_pull_peer_transport_parameters(
    void *context,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
) {
    (void)context;
    (void)out;
    (void)out_len;
    *written_len = 0;
    return QUICZ_TLS_BACKEND_PENDING;
}

int quicz_openssl_tls_backend_callbacks_set(void *context) {
    const struct quicz_openssl_tls_backend *backend = context;
    return backend != NULL ? backend->callbacks_set : 0;
}

int quicz_openssl_tls_backend_local_transport_parameters_set(void *context) {
    const struct quicz_openssl_tls_backend *backend = context;
    return backend != NULL ? backend->local_transport_parameters_set : 0;
}

int quicz_openssl_tls_backend_ssl_is_quic_after_callbacks(void *context) {
    const struct quicz_openssl_tls_backend *backend = context;
    return backend != NULL ? backend->ssl_is_quic_after_callbacks : 0;
}

size_t quicz_openssl_tls_backend_local_transport_parameters_len(void *context) {
    const struct quicz_openssl_tls_backend *backend = context;
    return backend != NULL ? backend->local_transport_parameters_len : 0;
}

size_t quicz_openssl_tls_backend_received_crypto_len(void *context) {
    const struct quicz_openssl_tls_backend *backend = context;
    return backend != NULL ? backend->received_crypto_len : 0;
}
