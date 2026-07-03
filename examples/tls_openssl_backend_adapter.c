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
    uint8_t inbound_crypto[4][8192];
    size_t inbound_crypto_len[4];
    size_t inbound_crypto_read_len[4];
    size_t inbound_crypto_released_len;
    uint32_t read_level;
    uint32_t write_level;
    int inbound_crypto_recv_callbacks;
    int inbound_crypto_release_callbacks;
    uint8_t outbound_crypto[4][8192];
    size_t outbound_crypto_len[4];
    size_t total_outbound_crypto_len;
    int outbound_crypto_overflow;
    int handshake_drive_calls;
    int last_ssl_error;
};

static const unsigned char quicz_openssl_backend_demo_psk[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static const unsigned char quicz_alpn_protos[] = {
    11, 'h', 'q', '-', 'i', 'n', 't', 'e', 'r', 'o', 'p',
};

static int alpn_select_cb(
    SSL *ssl,
    const unsigned char **out,
    unsigned char *outlen,
    const unsigned char *client_protos,
    unsigned int client_protos_len,
    void *arg
) {
    (void)ssl;
    (void)arg;
    int status = SSL_select_next_proto(
        (unsigned char **)out,
        outlen,
        quicz_alpn_protos,
        sizeof(quicz_alpn_protos),
        client_protos,
        client_protos_len
    );
    if (status == OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

static int crypto_send_cb(SSL *ssl, const unsigned char *buf, size_t buf_len, size_t *consumed, void *arg) {
    (void)ssl;
    struct quicz_openssl_tls_backend *backend = arg;
    if (backend == NULL || backend->write_level >= 4) {
        return 0;
    }
    if (buf_len > sizeof(backend->outbound_crypto[backend->write_level]) - backend->outbound_crypto_len[backend->write_level]) {
        backend->outbound_crypto_overflow = 1;
        return 0;
    }
    memcpy(
        backend->outbound_crypto[backend->write_level] + backend->outbound_crypto_len[backend->write_level],
        buf,
        buf_len
    );
    backend->outbound_crypto_len[backend->write_level] += buf_len;
    backend->total_outbound_crypto_len += buf_len;
    *consumed = buf_len;
    return 1;
}

static int crypto_recv_rcd_cb(SSL *ssl, const unsigned char **buf, size_t *bytes_read, void *arg) {
    (void)ssl;
    struct quicz_openssl_tls_backend *backend = arg;
    if (backend == NULL ||
        backend->read_level >= 4 ||
        backend->inbound_crypto_read_len[backend->read_level] != 0) {
        *buf = NULL;
        *bytes_read = 0;
        return 1;
    }
    backend->inbound_crypto_recv_callbacks += 1;
    if (backend->inbound_crypto_len[backend->read_level] != 0) {
        *buf = backend->inbound_crypto[backend->read_level];
        *bytes_read = backend->inbound_crypto_len[backend->read_level];
        backend->inbound_crypto_read_len[backend->read_level] = backend->inbound_crypto_len[backend->read_level];
        return 1;
    }
    *buf = NULL;
    *bytes_read = 0;
    return 1;
}

static int crypto_release_rcd_cb(SSL *ssl, size_t bytes_read, void *arg) {
    (void)ssl;
    struct quicz_openssl_tls_backend *backend = arg;
    if (backend == NULL ||
        backend->read_level >= 4 ||
        bytes_read > backend->inbound_crypto_read_len[backend->read_level]) {
        return 0;
    }
    backend->inbound_crypto_release_callbacks += 1;
    backend->inbound_crypto_released_len += bytes_read;
    if (bytes_read < backend->inbound_crypto_read_len[backend->read_level]) {
        const size_t remaining = backend->inbound_crypto_read_len[backend->read_level] - bytes_read;
        memmove(
            backend->inbound_crypto[backend->read_level],
            backend->inbound_crypto[backend->read_level] + bytes_read,
            remaining
        );
        backend->inbound_crypto_len[backend->read_level] = remaining;
    } else {
        backend->inbound_crypto_len[backend->read_level] = 0;
    }
    backend->inbound_crypto_read_len[backend->read_level] = 0;
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
    if (prot_level < 4) {
        if (direction == 0) {
            backend->read_level = prot_level;
        } else if (direction == 1) {
            backend->write_level = prot_level;
        }
    }
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

static unsigned int psk_client_cb(
    SSL *ssl,
    const char *hint,
    char *identity,
    unsigned int max_identity_len,
    unsigned char *psk,
    unsigned int max_psk_len
) {
    (void)ssl;
    (void)hint;
    const char *identity_value = "quicz-psk";
    if (strlen(identity_value) + 1 > max_identity_len || sizeof(quicz_openssl_backend_demo_psk) > max_psk_len) {
        return 0;
    }
    strcpy(identity, identity_value);
    memcpy(psk, quicz_openssl_backend_demo_psk, sizeof(quicz_openssl_backend_demo_psk));
    return (unsigned int)sizeof(quicz_openssl_backend_demo_psk);
}

static unsigned int psk_server_cb(
    SSL *ssl,
    const char *identity,
    unsigned char *psk,
    unsigned int max_psk_len
) {
    (void)ssl;
    if (identity == NULL ||
        strcmp(identity, "quicz-psk") != 0 ||
        sizeof(quicz_openssl_backend_demo_psk) > max_psk_len) {
        return 0;
    }
    memcpy(psk, quicz_openssl_backend_demo_psk, sizeof(quicz_openssl_backend_demo_psk));
    return (unsigned int)sizeof(quicz_openssl_backend_demo_psk);
}

static void *quicz_openssl_tls_backend_new_for_role(int is_client) {
    struct quicz_openssl_tls_backend *backend = calloc(1, sizeof(*backend));
    if (backend == NULL) {
        return NULL;
    }

    backend->ctx = SSL_CTX_new(is_client ? TLS_client_method() : TLS_server_method());
    if (backend->ctx == NULL) {
        free(backend);
        return NULL;
    }
    if (!SSL_CTX_set_min_proto_version(backend->ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(backend->ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_cipher_list(backend->ctx, "PSK") ||
        !SSL_CTX_set_ciphersuites(backend->ctx, "TLS_AES_128_GCM_SHA256")) {
        SSL_CTX_free(backend->ctx);
        free(backend);
        return NULL;
    }
    SSL_CTX_set_psk_client_callback(backend->ctx, psk_client_cb);
    SSL_CTX_set_psk_server_callback(backend->ctx, psk_server_cb);
    if (!is_client) {
        SSL_CTX_set_alpn_select_cb(backend->ctx, alpn_select_cb, NULL);
    }

    backend->ssl = SSL_new(backend->ctx);
    if (backend->ssl == NULL) {
        SSL_CTX_free(backend->ctx);
        free(backend);
        return NULL;
    }

    SSL_set_app_data(backend->ssl, backend);
    if (is_client) {
        SSL_set_alpn_protos(backend->ssl, quicz_alpn_protos, sizeof(quicz_alpn_protos));
    }
    SSL_CTX_set_keylog_callback(backend->ctx, keylog_cb);
    backend->callbacks_set = SSL_set_quic_tls_cbs(backend->ssl, quicz_openssl_tls_dispatch, backend);
    backend->ssl_is_quic_after_callbacks = SSL_is_quic(backend->ssl);
    if (is_client) {
        SSL_set_connect_state(backend->ssl);
    } else {
        SSL_set_accept_state(backend->ssl);
    }
    return backend;
}

static int packet_space_level(enum quicz_tls_backend_packet_space space, uint32_t *level) {
    if (level == NULL) {
        return 0;
    }
    switch (space) {
        case QUICZ_TLS_BACKEND_INITIAL:
            *level = OSSL_RECORD_PROTECTION_LEVEL_NONE;
            return 1;
        case QUICZ_TLS_BACKEND_HANDSHAKE:
            *level = OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE;
            return 1;
        case QUICZ_TLS_BACKEND_APPLICATION:
            *level = OSSL_RECORD_PROTECTION_LEVEL_APPLICATION;
            return 1;
    }
    return 0;
}

void *quicz_openssl_tls_backend_new(void) {
    return quicz_openssl_tls_backend_new_for_role(1);
}

void *quicz_openssl_tls_backend_new_server(void) {
    return quicz_openssl_tls_backend_new_for_role(0);
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
    uint32_t level = 0;
    if (!packet_space_level(space, &level)) {
        return QUICZ_TLS_BACKEND_INTERNAL;
    }
    if (data_len > sizeof(backend->inbound_crypto[level]) - backend->inbound_crypto_len[level]) {
        return QUICZ_TLS_BACKEND_BUFFER_TOO_SMALL;
    }
    memcpy(backend->inbound_crypto[level] + backend->inbound_crypto_len[level], data, data_len);
    backend->inbound_crypto_len[level] += data_len;
    backend->received_crypto_len += data_len;
    return QUICZ_TLS_BACKEND_OK;
}

static enum quicz_tls_backend_status copy_pending_outbound(
    struct quicz_openssl_tls_backend *backend,
    uint32_t level,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
) {
    if (level >= 4) {
        return QUICZ_TLS_BACKEND_INTERNAL;
    }
    if (backend->outbound_crypto_len[level] == 0) {
        return QUICZ_TLS_BACKEND_PENDING;
    }
    if (out_len < backend->outbound_crypto_len[level]) {
        return QUICZ_TLS_BACKEND_BUFFER_TOO_SMALL;
    }
    memcpy(out, backend->outbound_crypto[level], backend->outbound_crypto_len[level]);
    *written_len = backend->outbound_crypto_len[level];
    backend->outbound_crypto_len[level] = 0;
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
    uint32_t level = 0;
    if (!packet_space_level(space, &level)) {
        return QUICZ_TLS_BACKEND_INTERNAL;
    }

    enum quicz_tls_backend_status pending_status = copy_pending_outbound(backend, level, out, out_len, written_len);
    if (pending_status != QUICZ_TLS_BACKEND_PENDING) {
        return pending_status;
    }
    if (level != OSSL_RECORD_PROTECTION_LEVEL_NONE) {
        return QUICZ_TLS_BACKEND_PENDING;
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

    pending_status = copy_pending_outbound(backend, level, out, out_len, written_len);
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
        backend->one_rtt_peer_secret_available &&
        backend->received_crypto_len != 0 &&
        backend->inbound_crypto_released_len == backend->received_crypto_len;
}

enum quicz_tls_backend_status quicz_openssl_tls_backend_pull_negotiated_alpn(
    void *context,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
) {
    const struct quicz_openssl_tls_backend *backend = context;
    if (backend == NULL || backend->ssl == NULL) {
        return QUICZ_TLS_BACKEND_INTERNAL;
    }
    const unsigned char *alpn = NULL;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(backend->ssl, &alpn, &alpn_len);
    if (alpn == NULL || alpn_len == 0) {
        return QUICZ_TLS_BACKEND_PENDING;
    }
    if (out_len < alpn_len) {
        return QUICZ_TLS_BACKEND_BUFFER_TOO_SMALL;
    }
    memcpy(out, alpn, alpn_len);
    *written_len = alpn_len;
    return QUICZ_TLS_BACKEND_OK;
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
    if (backend == NULL) {
        return 0;
    }
    size_t pending_len = 0;
    for (size_t level = 0; level < 4; level += 1) {
        pending_len += backend->inbound_crypto_len[level];
    }
    return pending_len;
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

enum quicz_tls_backend_status quicz_openssl_tls_backend_debug_copy_handshake_traffic_secrets(
    void *context,
    struct quicz_handshake_traffic_secrets *out
) {
    const struct quicz_openssl_tls_backend *backend = context;
    if (backend == NULL || out == NULL) {
        return QUICZ_TLS_BACKEND_INTERNAL;
    }
    if (!backend->handshake_local_secret_available || !backend->handshake_peer_secret_available) {
        return QUICZ_TLS_BACKEND_PENDING;
    }
    *out = backend->handshake_secrets;
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
