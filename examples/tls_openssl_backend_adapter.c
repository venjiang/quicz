#include "tls_openssl_backend_adapter.h"

#include <openssl/core_dispatch.h>
#include <openssl/ssl.h>

#include <stdlib.h>
#include <string.h>

struct quicz_openssl_tls_backend {
    SSL_CTX *ctx;
    SSL *ssl;
    int callbacks_set;
    int local_transport_parameters_set;
    int ssl_is_quic_after_callbacks;
    size_t local_transport_parameters_len;
    uint8_t peer_transport_parameters[512];
    size_t peer_transport_parameters_len;
    int peer_transport_parameters_available;
    int peer_transport_parameters_sent;
    int got_transport_params_callbacks;
    int keylog_callbacks;
    size_t keylog_bytes;
    struct quicz_handshake_traffic_secrets handshake_secrets;
    int handshake_local_secret_available;
    int handshake_peer_secret_available;
    int handshake_secrets_sent;
    struct quicz_one_rtt_traffic_secrets one_rtt_secrets;
    int one_rtt_local_secret_available;
    int one_rtt_peer_secret_available;
    int one_rtt_secrets_sent;
    int yield_secret_callbacks;
    size_t received_crypto_len;
    uint8_t inbound_crypto[8192];
    size_t inbound_crypto_len;
    size_t inbound_crypto_read_len;
    size_t inbound_crypto_released_len;
    int inbound_crypto_recv_callbacks;
    int inbound_crypto_release_callbacks;
    uint8_t outbound_crypto[8192];
    size_t outbound_crypto_len;
    size_t total_outbound_crypto_len;
    int outbound_crypto_overflow;
    int handshake_drive_calls;
    int last_ssl_error;
};

static int crypto_send_cb(SSL *ssl, const unsigned char *buf, size_t buf_len, size_t *consumed, void *arg) {
    (void)ssl;
    struct quicz_openssl_tls_backend *backend = arg;
    if (backend == NULL) {
        return 0;
    }
    if (buf_len > sizeof(backend->outbound_crypto) - backend->outbound_crypto_len) {
        backend->outbound_crypto_overflow = 1;
        return 0;
    }
    memcpy(backend->outbound_crypto + backend->outbound_crypto_len, buf, buf_len);
    backend->outbound_crypto_len += buf_len;
    backend->total_outbound_crypto_len += buf_len;
    *consumed = buf_len;
    return 1;
}

static int crypto_recv_rcd_cb(SSL *ssl, const unsigned char **buf, size_t *bytes_read, void *arg) {
    (void)ssl;
    struct quicz_openssl_tls_backend *backend = arg;
    if (backend == NULL || backend->inbound_crypto_read_len != 0) {
        *buf = NULL;
        *bytes_read = 0;
        return 1;
    }
    backend->inbound_crypto_recv_callbacks += 1;
    if (backend->inbound_crypto_len != 0) {
        *buf = backend->inbound_crypto;
        *bytes_read = backend->inbound_crypto_len;
        backend->inbound_crypto_read_len = backend->inbound_crypto_len;
        return 1;
    }
    *buf = NULL;
    *bytes_read = 0;
    return 1;
}

static int crypto_release_rcd_cb(SSL *ssl, size_t bytes_read, void *arg) {
    (void)ssl;
    struct quicz_openssl_tls_backend *backend = arg;
    if (backend == NULL || bytes_read > backend->inbound_crypto_read_len) {
        return 0;
    }
    backend->inbound_crypto_release_callbacks += 1;
    backend->inbound_crypto_released_len += bytes_read;
    if (bytes_read < backend->inbound_crypto_read_len) {
        const size_t remaining = backend->inbound_crypto_read_len - bytes_read;
        memmove(backend->inbound_crypto, backend->inbound_crypto + bytes_read, remaining);
        backend->inbound_crypto_len = remaining;
    } else {
        backend->inbound_crypto_len = 0;
    }
    backend->inbound_crypto_read_len = 0;
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
    struct quicz_openssl_tls_backend *backend = arg;
    if (backend == NULL) {
        return 0;
    }
    backend->yield_secret_callbacks += 1;
    if (prot_level != OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE &&
        prot_level != OSSL_RECORD_PROTECTION_LEVEL_APPLICATION) {
        return 1;
    }
    if (secret_len != sizeof(backend->handshake_secrets.local)) {
        return 0;
    }
    if (prot_level == OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE) {
        if (direction == 1) {
            memcpy(backend->handshake_secrets.local, secret, secret_len);
            backend->handshake_local_secret_available = 1;
            backend->handshake_secrets_sent = 0;
            return 1;
        }
        if (direction == 0) {
            memcpy(backend->handshake_secrets.peer, secret, secret_len);
            backend->handshake_peer_secret_available = 1;
            backend->handshake_secrets_sent = 0;
            return 1;
        }
        return 1;
    }
    if (direction == 1) {
        memcpy(backend->one_rtt_secrets.local, secret, secret_len);
        backend->one_rtt_local_secret_available = 1;
        backend->one_rtt_secrets_sent = 0;
        return 1;
    }
    if (direction == 0) {
        memcpy(backend->one_rtt_secrets.peer, secret, secret_len);
        backend->one_rtt_peer_secret_available = 1;
        backend->one_rtt_secrets_sent = 0;
        return 1;
    }
    return 1;
}

static int got_transport_params_cb(SSL *ssl, const unsigned char *params, size_t params_len, void *arg) {
    (void)ssl;
    struct quicz_openssl_tls_backend *backend = arg;
    if (backend == NULL || params_len > sizeof(backend->peer_transport_parameters)) {
        return 0;
    }
    memcpy(backend->peer_transport_parameters, params, params_len);
    backend->peer_transport_parameters_len = params_len;
    backend->peer_transport_parameters_available = 1;
    backend->peer_transport_parameters_sent = 0;
    backend->got_transport_params_callbacks += 1;
    return 1;
}

static void keylog_cb(const SSL *ssl, const char *line) {
    struct quicz_openssl_tls_backend *backend = SSL_get_app_data(ssl);
    if (backend == NULL || line == NULL) {
        return;
    }
    backend->keylog_callbacks += 1;
    backend->keylog_bytes += strlen(line);
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

    SSL_set_app_data(backend->ssl, backend);
    SSL_CTX_set_keylog_callback(backend->ctx, keylog_cb);
    backend->callbacks_set = SSL_set_quic_tls_cbs(backend->ssl, quicz_openssl_tls_dispatch, backend);
    backend->ssl_is_quic_after_callbacks = SSL_is_quic(backend->ssl);
    SSL_set_connect_state(backend->ssl);
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
    (void)space;
    if (data_len > sizeof(backend->inbound_crypto) - backend->inbound_crypto_len) {
        return QUICZ_TLS_BACKEND_BUFFER_TOO_SMALL;
    }
    memcpy(backend->inbound_crypto + backend->inbound_crypto_len, data, data_len);
    backend->inbound_crypto_len += data_len;
    backend->received_crypto_len += data_len;
    return QUICZ_TLS_BACKEND_OK;
}

static enum quicz_tls_backend_status copy_pending_outbound(
    struct quicz_openssl_tls_backend *backend,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
) {
    if (backend->outbound_crypto_len == 0) {
        return QUICZ_TLS_BACKEND_PENDING;
    }
    if (out_len < backend->outbound_crypto_len) {
        return QUICZ_TLS_BACKEND_BUFFER_TOO_SMALL;
    }
    memcpy(out, backend->outbound_crypto, backend->outbound_crypto_len);
    *written_len = backend->outbound_crypto_len;
    backend->outbound_crypto_len = 0;
    return QUICZ_TLS_BACKEND_OK;
}

enum quicz_tls_backend_status quicz_openssl_tls_backend_pull(
    void *context,
    enum quicz_tls_backend_packet_space space,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
) {
    struct quicz_openssl_tls_backend *backend = context;
    *written_len = 0;
    if (backend == NULL || backend->ssl == NULL) {
        return QUICZ_TLS_BACKEND_INTERNAL;
    }
    if (space != QUICZ_TLS_BACKEND_INITIAL) {
        return QUICZ_TLS_BACKEND_PENDING;
    }

    enum quicz_tls_backend_status pending_status = copy_pending_outbound(backend, out, out_len, written_len);
    if (pending_status != QUICZ_TLS_BACKEND_PENDING) {
        return pending_status;
    }

    backend->handshake_drive_calls += 1;
    int rc = SSL_do_handshake(backend->ssl);
    if (rc != 1) {
        backend->last_ssl_error = SSL_get_error(backend->ssl, rc);
    } else {
        backend->last_ssl_error = SSL_ERROR_NONE;
    }
    if (backend->outbound_crypto_overflow) {
        return QUICZ_TLS_BACKEND_BUFFER_TOO_SMALL;
    }

    pending_status = copy_pending_outbound(backend, out, out_len, written_len);
    if (pending_status != QUICZ_TLS_BACKEND_PENDING) {
        return pending_status;
    }
    if (rc == 1 || backend->last_ssl_error == SSL_ERROR_WANT_READ || backend->last_ssl_error == SSL_ERROR_WANT_WRITE) {
        return QUICZ_TLS_BACKEND_PENDING;
    }
    return QUICZ_TLS_BACKEND_CRYPTO_ERROR;
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
    if (backend->local_transport_parameters_set) {
        return QUICZ_TLS_BACKEND_OK;
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
    struct quicz_openssl_tls_backend *backend = context;
    *written_len = 0;
    if (backend == NULL) {
        return QUICZ_TLS_BACKEND_INTERNAL;
    }
    if (!backend->peer_transport_parameters_available || backend->peer_transport_parameters_sent) {
        return QUICZ_TLS_BACKEND_PENDING;
    }
    if (out_len < backend->peer_transport_parameters_len) {
        return QUICZ_TLS_BACKEND_BUFFER_TOO_SMALL;
    }
    memcpy(out, backend->peer_transport_parameters, backend->peer_transport_parameters_len);
    *written_len = backend->peer_transport_parameters_len;
    backend->peer_transport_parameters_sent = 1;
    return QUICZ_TLS_BACKEND_OK;
}

enum quicz_tls_backend_status quicz_openssl_tls_backend_pull_handshake_traffic_secrets(
    void *context,
    struct quicz_handshake_traffic_secrets *out
) {
    struct quicz_openssl_tls_backend *backend = context;
    if (backend == NULL) {
        return QUICZ_TLS_BACKEND_INTERNAL;
    }
    if (!backend->handshake_local_secret_available ||
        !backend->handshake_peer_secret_available ||
        backend->handshake_secrets_sent) {
        return QUICZ_TLS_BACKEND_PENDING;
    }
    *out = backend->handshake_secrets;
    backend->handshake_secrets_sent = 1;
    return QUICZ_TLS_BACKEND_OK;
}

enum quicz_tls_backend_status quicz_openssl_tls_backend_pull_1rtt_traffic_secrets(
    void *context,
    struct quicz_one_rtt_traffic_secrets *out
) {
    struct quicz_openssl_tls_backend *backend = context;
    if (backend == NULL) {
        return QUICZ_TLS_BACKEND_INTERNAL;
    }
    if (!backend->one_rtt_local_secret_available ||
        !backend->one_rtt_peer_secret_available ||
        backend->one_rtt_secrets_sent) {
        return QUICZ_TLS_BACKEND_PENDING;
    }
    *out = backend->one_rtt_secrets;
    backend->one_rtt_secrets_sent = 1;
    return QUICZ_TLS_BACKEND_OK;
}

bool quicz_openssl_tls_backend_handshake_confirmed(void *context) {
    const struct quicz_openssl_tls_backend *backend = context;
    return backend != NULL &&
        backend->peer_transport_parameters_available &&
        backend->handshake_local_secret_available &&
        backend->handshake_peer_secret_available &&
        backend->one_rtt_local_secret_available &&
        backend->one_rtt_peer_secret_available;
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

size_t quicz_openssl_tls_backend_peer_transport_parameters_len(void *context) {
    const struct quicz_openssl_tls_backend *backend = context;
    return backend != NULL ? backend->peer_transport_parameters_len : 0;
}

int quicz_openssl_tls_backend_got_transport_params_callbacks(void *context) {
    const struct quicz_openssl_tls_backend *backend = context;
    return backend != NULL ? backend->got_transport_params_callbacks : 0;
}

int quicz_openssl_tls_backend_keylog_callbacks(void *context) {
    const struct quicz_openssl_tls_backend *backend = context;
    return backend != NULL ? backend->keylog_callbacks : 0;
}

size_t quicz_openssl_tls_backend_keylog_bytes(void *context) {
    const struct quicz_openssl_tls_backend *backend = context;
    return backend != NULL ? backend->keylog_bytes : 0;
}

int quicz_openssl_tls_backend_yield_secret_callbacks(void *context) {
    const struct quicz_openssl_tls_backend *backend = context;
    return backend != NULL ? backend->yield_secret_callbacks : 0;
}

size_t quicz_openssl_tls_backend_pending_inbound_crypto_len(void *context) {
    const struct quicz_openssl_tls_backend *backend = context;
    return backend != NULL ? backend->inbound_crypto_len : 0;
}

size_t quicz_openssl_tls_backend_released_inbound_crypto_len(void *context) {
    const struct quicz_openssl_tls_backend *backend = context;
    return backend != NULL ? backend->inbound_crypto_released_len : 0;
}

int quicz_openssl_tls_backend_inbound_crypto_recv_callbacks(void *context) {
    const struct quicz_openssl_tls_backend *backend = context;
    return backend != NULL ? backend->inbound_crypto_recv_callbacks : 0;
}

int quicz_openssl_tls_backend_inbound_crypto_release_callbacks(void *context) {
    const struct quicz_openssl_tls_backend *backend = context;
    return backend != NULL ? backend->inbound_crypto_release_callbacks : 0;
}

size_t quicz_openssl_tls_backend_generated_crypto_len(void *context) {
    const struct quicz_openssl_tls_backend *backend = context;
    return backend != NULL ? backend->total_outbound_crypto_len : 0;
}

int quicz_openssl_tls_backend_handshake_drive_calls(void *context) {
    const struct quicz_openssl_tls_backend *backend = context;
    return backend != NULL ? backend->handshake_drive_calls : 0;
}

int quicz_openssl_tls_backend_last_ssl_error(void *context) {
    const struct quicz_openssl_tls_backend *backend = context;
    return backend != NULL ? backend->last_ssl_error : 0;
}

enum quicz_tls_backend_status quicz_openssl_tls_backend_debug_consume_inbound_once(void *context) {
    struct quicz_openssl_tls_backend *backend = context;
    if (backend == NULL) {
        return QUICZ_TLS_BACKEND_INTERNAL;
    }
    const unsigned char *buf = NULL;
    size_t bytes_read = 0;
    if (!crypto_recv_rcd_cb(backend->ssl, &buf, &bytes_read, backend)) {
        return QUICZ_TLS_BACKEND_CRYPTO_ERROR;
    }
    if (bytes_read == 0) {
        return QUICZ_TLS_BACKEND_PENDING;
    }
    if (buf == NULL) {
        return QUICZ_TLS_BACKEND_INTERNAL;
    }
    if (!crypto_release_rcd_cb(backend->ssl, bytes_read, backend)) {
        return QUICZ_TLS_BACKEND_CRYPTO_ERROR;
    }
    return QUICZ_TLS_BACKEND_OK;
}

enum quicz_tls_backend_status quicz_openssl_tls_backend_debug_got_transport_parameters(
    void *context,
    const uint8_t *params,
    size_t params_len
) {
    struct quicz_openssl_tls_backend *backend = context;
    if (backend == NULL) {
        return QUICZ_TLS_BACKEND_INTERNAL;
    }
    return got_transport_params_cb(backend->ssl, params, params_len, backend)
        ? QUICZ_TLS_BACKEND_OK
        : QUICZ_TLS_BACKEND_BUFFER_TOO_SMALL;
}

enum quicz_tls_backend_status quicz_openssl_tls_backend_debug_yield_handshake_secret(
    void *context,
    int direction,
    const uint8_t *secret,
    size_t secret_len
) {
    struct quicz_openssl_tls_backend *backend = context;
    if (backend == NULL) {
        return QUICZ_TLS_BACKEND_INTERNAL;
    }
    return yield_secret_cb(
        backend->ssl,
        OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE,
        direction,
        secret,
        secret_len,
        backend
    ) ? QUICZ_TLS_BACKEND_OK : QUICZ_TLS_BACKEND_CRYPTO_ERROR;
}

enum quicz_tls_backend_status quicz_openssl_tls_backend_debug_yield_application_secret(
    void *context,
    int direction,
    const uint8_t *secret,
    size_t secret_len
) {
    struct quicz_openssl_tls_backend *backend = context;
    if (backend == NULL) {
        return QUICZ_TLS_BACKEND_INTERNAL;
    }
    return yield_secret_cb(
        backend->ssl,
        OSSL_RECORD_PROTECTION_LEVEL_APPLICATION,
        direction,
        secret,
        secret_len,
        backend
    ) ? QUICZ_TLS_BACKEND_OK : QUICZ_TLS_BACKEND_CRYPTO_ERROR;
}
