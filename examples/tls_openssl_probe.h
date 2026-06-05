#ifndef QUICZ_TLS_OPENSSL_PROBE_H
#define QUICZ_TLS_OPENSSL_PROBE_H

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

struct quicz_openssl_probe_result quicz_openssl_probe_run(void);

#endif
