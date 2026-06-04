#include <openssl/core_dispatch.h>
#include <openssl/opensslv.h>
#include <openssl/quic.h>
#include <openssl/ssl.h>

#include <stddef.h>
#include <stdint.h>

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

static const OSSL_DISPATCH quicz_openssl_quic_tls_dispatch[] = {
    { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND, (void (*)(void))crypto_send_cb },
    { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD, (void (*)(void))crypto_recv_rcd_cb },
    { OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD, (void (*)(void))crypto_release_rcd_cb },
    { OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET, (void (*)(void))yield_secret_cb },
    { OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS, (void (*)(void))got_transport_params_cb },
    { OSSL_FUNC_SSL_QUIC_TLS_ALERT, (void (*)(void))alert_cb },
    { 0, NULL },
};

struct quicz_openssl_probe_result {
    unsigned long version_number;
    int has_quic_method;
    int quic_ctx_created;
    int quic_ssl_created;
    int quic_ssl_is_quic;
    int tls_ctx_created;
    int tls_ssl_created;
    int tls_ssl_is_quic_before_callbacks;
    int tls_ssl_is_quic_after_callbacks;
    int callbacks_set;
    int transport_params_set;
    int crypto_send_id;
    int yield_secret_id;
    int got_transport_params_id;
};

struct quicz_openssl_probe_result quicz_openssl_probe_run(void) {
    struct quicz_openssl_probe_result result = {
        OPENSSL_VERSION_NUMBER,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND,
        OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET,
        OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS,
    };

#ifdef OPENSSL_NO_QUIC
    return result;
#else
    const SSL_METHOD *method = OSSL_QUIC_client_method();
    result.has_quic_method = method != NULL;
    if (method != NULL) {
        SSL_CTX *quic_ctx = SSL_CTX_new(method);
        result.quic_ctx_created = quic_ctx != NULL;
        if (quic_ctx != NULL) {
            SSL *quic_ssl = SSL_new(quic_ctx);
            result.quic_ssl_created = quic_ssl != NULL;
            if (quic_ssl != NULL) {
                result.quic_ssl_is_quic = SSL_is_quic(quic_ssl);
                SSL_free(quic_ssl);
            }
            SSL_CTX_free(quic_ctx);
        }
    }

    SSL_CTX *tls_ctx = SSL_CTX_new(TLS_client_method());
    result.tls_ctx_created = tls_ctx != NULL;
    if (tls_ctx == NULL) {
        return result;
    }

    SSL *tls_ssl = SSL_new(tls_ctx);
    result.tls_ssl_created = tls_ssl != NULL;
    if (tls_ssl != NULL) {
        const unsigned char transport_parameters[] = { 0x00, 0x04, 0x80, 0x00, 0x75, 0x30 };
        result.tls_ssl_is_quic_before_callbacks = SSL_is_quic(tls_ssl);
        result.callbacks_set = SSL_set_quic_tls_cbs(tls_ssl, quicz_openssl_quic_tls_dispatch, NULL);
        result.tls_ssl_is_quic_after_callbacks = SSL_is_quic(tls_ssl);
        result.transport_params_set = SSL_set_quic_tls_transport_params(
            tls_ssl,
            transport_parameters,
            sizeof(transport_parameters)
        );
        SSL_free(tls_ssl);
    }

    SSL_CTX_free(tls_ctx);
    return result;
#endif
}
