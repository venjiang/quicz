#include <openssl/core_dispatch.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define QUICZ_OPENSSL_LEVEL_COUNT 4
#define QUICZ_OPENSSL_CRYPTO_BUF_LEN 65536
#define QUICZ_OPENSSL_SECRET_LEN 32
#define QUICZ_OPENSSL_TRANSPORT_PARAMS_BUF_LEN 512
#define QUICZ_OPENSSL_READ_SECRET 0
#define QUICZ_OPENSSL_WRITE_SECRET 1
#define QUICZ_OPENSSL_SECRET_DIRECTION_COUNT 2

struct quicz_openssl_pair_transcript_result {
    int initialized;
    int client_done;
    int server_done;
    int client_send_callbacks;
    int server_send_callbacks;
    int client_recv_callbacks;
    int server_recv_callbacks;
    int client_release_callbacks;
    int server_release_callbacks;
    int client_yield_secret_callbacks;
    int server_yield_secret_callbacks;
    int client_got_transport_params_callbacks;
    int server_got_transport_params_callbacks;
    size_t client_peer_transport_parameters_len;
    size_t server_peer_transport_parameters_len;
    int client_keylog_callbacks;
    int server_keylog_callbacks;
    size_t client_keylog_bytes;
    size_t server_keylog_bytes;
    int client_alert_callbacks;
    int server_alert_callbacks;
    int client_last_alert;
    int server_last_alert;
    int client_last_ssl_error;
    int server_last_ssl_error;
    int client_read_level;
    int server_read_level;
    int client_write_level;
    int server_write_level;
    int drive_iterations;
    unsigned long error_queue_code;
    size_t client_out_level_bytes[QUICZ_OPENSSL_LEVEL_COUNT];
    size_t server_out_level_bytes[QUICZ_OPENSSL_LEVEL_COUNT];
};

struct quicz_openssl_endpoint {
    SSL_CTX *ctx;
    SSL *ssl;
    unsigned char in[QUICZ_OPENSSL_LEVEL_COUNT][QUICZ_OPENSSL_CRYPTO_BUF_LEN];
    size_t in_len[QUICZ_OPENSSL_LEVEL_COUNT];
    size_t in_read_len[QUICZ_OPENSSL_LEVEL_COUNT];
    unsigned char out[QUICZ_OPENSSL_LEVEL_COUNT][QUICZ_OPENSSL_CRYPTO_BUF_LEN];
    size_t out_len[QUICZ_OPENSSL_LEVEL_COUNT];
    size_t out_total_len[QUICZ_OPENSSL_LEVEL_COUNT];
    unsigned char out_history[QUICZ_OPENSSL_LEVEL_COUNT][QUICZ_OPENSSL_CRYPTO_BUF_LEN];
    size_t out_history_len[QUICZ_OPENSSL_LEVEL_COUNT];
    unsigned char secrets[QUICZ_OPENSSL_LEVEL_COUNT][QUICZ_OPENSSL_SECRET_DIRECTION_COUNT][QUICZ_OPENSSL_SECRET_LEN];
    int secret_available[QUICZ_OPENSSL_LEVEL_COUNT][QUICZ_OPENSSL_SECRET_DIRECTION_COUNT];
    uint32_t read_level;
    uint32_t write_level;
    int send_callbacks;
    int recv_callbacks;
    int release_callbacks;
    int yield_secret_callbacks;
    int got_transport_params_callbacks;
    unsigned char peer_transport_parameters[QUICZ_OPENSSL_TRANSPORT_PARAMS_BUF_LEN];
    size_t peer_transport_parameters_len;
    int keylog_callbacks;
    size_t keylog_bytes;
    int alert_callbacks;
    int last_alert;
    int handshake_done;
    int last_ssl_error;
    unsigned char local_transport_parameters[QUICZ_OPENSSL_TRANSPORT_PARAMS_BUF_LEN];
    size_t local_transport_parameters_len;
};

struct quicz_openssl_pair_transcript_context {
    struct quicz_openssl_endpoint *client;
    struct quicz_openssl_endpoint *server;
};

static unsigned char quicz_openssl_last_client_crypto[QUICZ_OPENSSL_LEVEL_COUNT][QUICZ_OPENSSL_CRYPTO_BUF_LEN];
static size_t quicz_openssl_last_client_crypto_len[QUICZ_OPENSSL_LEVEL_COUNT];
static unsigned char quicz_openssl_last_server_crypto[QUICZ_OPENSSL_LEVEL_COUNT][QUICZ_OPENSSL_CRYPTO_BUF_LEN];
static size_t quicz_openssl_last_server_crypto_len[QUICZ_OPENSSL_LEVEL_COUNT];
static unsigned char quicz_openssl_last_client_peer_transport_parameters[QUICZ_OPENSSL_TRANSPORT_PARAMS_BUF_LEN];
static size_t quicz_openssl_last_client_peer_transport_parameters_len;
static unsigned char quicz_openssl_last_server_peer_transport_parameters[QUICZ_OPENSSL_TRANSPORT_PARAMS_BUF_LEN];
static size_t quicz_openssl_last_server_peer_transport_parameters_len;
static unsigned char quicz_openssl_last_client_secrets[QUICZ_OPENSSL_LEVEL_COUNT][QUICZ_OPENSSL_SECRET_DIRECTION_COUNT][QUICZ_OPENSSL_SECRET_LEN];
static int quicz_openssl_last_client_secret_available[QUICZ_OPENSSL_LEVEL_COUNT][QUICZ_OPENSSL_SECRET_DIRECTION_COUNT];
static unsigned char quicz_openssl_last_server_secrets[QUICZ_OPENSSL_LEVEL_COUNT][QUICZ_OPENSSL_SECRET_DIRECTION_COUNT][QUICZ_OPENSSL_SECRET_LEN];
static int quicz_openssl_last_server_secret_available[QUICZ_OPENSSL_LEVEL_COUNT][QUICZ_OPENSSL_SECRET_DIRECTION_COUNT];
static unsigned char quicz_openssl_configured_client_transport_parameters[QUICZ_OPENSSL_TRANSPORT_PARAMS_BUF_LEN];
static size_t quicz_openssl_configured_client_transport_parameters_len;
static unsigned char quicz_openssl_configured_server_transport_parameters[QUICZ_OPENSSL_TRANSPORT_PARAMS_BUF_LEN];
static size_t quicz_openssl_configured_server_transport_parameters_len;
static int quicz_openssl_transport_parameters_configured;

static const unsigned char quicz_openssl_demo_psk[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static int crypto_send_cb(SSL *ssl, const unsigned char *buf, size_t buf_len, size_t *consumed, void *arg) {
    (void)ssl;
    struct quicz_openssl_endpoint *endpoint = arg;
    if (endpoint == NULL || endpoint->write_level >= QUICZ_OPENSSL_LEVEL_COUNT) {
        return 0;
    }
    if (buf_len > sizeof(endpoint->out[endpoint->write_level]) - endpoint->out_len[endpoint->write_level] ||
        buf_len > sizeof(endpoint->out_history[endpoint->write_level]) - endpoint->out_history_len[endpoint->write_level]) {
        return 0;
    }
    memcpy(endpoint->out[endpoint->write_level] + endpoint->out_len[endpoint->write_level], buf, buf_len);
    endpoint->out_len[endpoint->write_level] += buf_len;
    endpoint->out_total_len[endpoint->write_level] += buf_len;
    memcpy(endpoint->out_history[endpoint->write_level] + endpoint->out_history_len[endpoint->write_level], buf, buf_len);
    endpoint->out_history_len[endpoint->write_level] += buf_len;
    endpoint->send_callbacks += 1;
    *consumed = buf_len;
    return 1;
}

static int crypto_recv_rcd_cb(SSL *ssl, const unsigned char **buf, size_t *bytes_read, void *arg) {
    (void)ssl;
    struct quicz_openssl_endpoint *endpoint = arg;
    if (endpoint == NULL ||
        endpoint->read_level >= QUICZ_OPENSSL_LEVEL_COUNT ||
        endpoint->in_read_len[endpoint->read_level] != 0) {
        *buf = NULL;
        *bytes_read = 0;
        return 1;
    }
    endpoint->recv_callbacks += 1;
    if (endpoint->in_len[endpoint->read_level] == 0) {
        *buf = NULL;
        *bytes_read = 0;
        return 1;
    }
    *buf = endpoint->in[endpoint->read_level];
    *bytes_read = endpoint->in_len[endpoint->read_level];
    endpoint->in_read_len[endpoint->read_level] = endpoint->in_len[endpoint->read_level];
    return 1;
}

static int crypto_release_rcd_cb(SSL *ssl, size_t bytes_read, void *arg) {
    (void)ssl;
    struct quicz_openssl_endpoint *endpoint = arg;
    if (endpoint == NULL ||
        endpoint->read_level >= QUICZ_OPENSSL_LEVEL_COUNT ||
        bytes_read > endpoint->in_read_len[endpoint->read_level]) {
        return 0;
    }
    if (bytes_read < endpoint->in_read_len[endpoint->read_level]) {
        const size_t remaining = endpoint->in_read_len[endpoint->read_level] - bytes_read;
        memmove(endpoint->in[endpoint->read_level], endpoint->in[endpoint->read_level] + bytes_read, remaining);
        endpoint->in_len[endpoint->read_level] = remaining;
    } else {
        endpoint->in_len[endpoint->read_level] = 0;
    }
    endpoint->in_read_len[endpoint->read_level] = 0;
    endpoint->release_callbacks += 1;
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
    (void)secret;
    (void)secret_len;
    struct quicz_openssl_endpoint *endpoint = arg;
    if (endpoint == NULL || prot_level >= QUICZ_OPENSSL_LEVEL_COUNT) {
        return 0;
    }
    if (direction == 0) {
        endpoint->read_level = prot_level;
    } else if (direction == 1) {
        endpoint->write_level = prot_level;
    }
    if ((direction == QUICZ_OPENSSL_READ_SECRET || direction == QUICZ_OPENSSL_WRITE_SECRET) &&
        secret_len == QUICZ_OPENSSL_SECRET_LEN) {
        memcpy(endpoint->secrets[prot_level][direction], secret, secret_len);
        endpoint->secret_available[prot_level][direction] = 1;
    }
    endpoint->yield_secret_callbacks += 1;
    return 1;
}

static int got_transport_params_cb(SSL *ssl, const unsigned char *params, size_t params_len, void *arg) {
    (void)ssl;
    struct quicz_openssl_endpoint *endpoint = arg;
    if (endpoint == NULL ||
        (params_len > 0 && params == NULL) ||
        params_len > sizeof(endpoint->peer_transport_parameters)) {
        return 0;
    }
    if (params_len > 0) {
        memcpy(endpoint->peer_transport_parameters, params, params_len);
    }
    endpoint->peer_transport_parameters_len = params_len;
    endpoint->got_transport_params_callbacks += 1;
    return 1;
}

static void keylog_cb(const SSL *ssl, const char *line) {
    struct quicz_openssl_endpoint *endpoint = SSL_get_app_data(ssl);
    if (endpoint == NULL || line == NULL) {
        return;
    }
    endpoint->keylog_callbacks += 1;
    endpoint->keylog_bytes += strlen(line);
}

static int alert_cb(SSL *ssl, unsigned char alert_code, void *arg) {
    (void)ssl;
    struct quicz_openssl_endpoint *endpoint = arg;
    if (endpoint == NULL) {
        return 0;
    }
    endpoint->alert_callbacks += 1;
    endpoint->last_alert = alert_code;
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
    if (strlen(identity_value) + 1 > max_identity_len || sizeof(quicz_openssl_demo_psk) > max_psk_len) {
        return 0;
    }
    strcpy(identity, identity_value);
    memcpy(psk, quicz_openssl_demo_psk, sizeof(quicz_openssl_demo_psk));
    return (unsigned int)sizeof(quicz_openssl_demo_psk);
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
        sizeof(quicz_openssl_demo_psk) > max_psk_len) {
        return 0;
    }
    memcpy(psk, quicz_openssl_demo_psk, sizeof(quicz_openssl_demo_psk));
    return (unsigned int)sizeof(quicz_openssl_demo_psk);
}

static void free_endpoint(struct quicz_openssl_endpoint *endpoint) {
    if (endpoint == NULL) {
        return;
    }
    SSL_free(endpoint->ssl);
    SSL_CTX_free(endpoint->ctx);
    free(endpoint);
}

int quicz_openssl_pair_transcript_configure_transport_parameters(
    const unsigned char *client_params,
    size_t client_params_len,
    const unsigned char *server_params,
    size_t server_params_len
) {
    if ((client_params_len > 0 && client_params == NULL) ||
        (server_params_len > 0 && server_params == NULL) ||
        client_params_len > sizeof(quicz_openssl_configured_client_transport_parameters) ||
        server_params_len > sizeof(quicz_openssl_configured_server_transport_parameters)) {
        return 0;
    }
    memset(
        quicz_openssl_configured_client_transport_parameters,
        0,
        sizeof(quicz_openssl_configured_client_transport_parameters)
    );
    memset(
        quicz_openssl_configured_server_transport_parameters,
        0,
        sizeof(quicz_openssl_configured_server_transport_parameters)
    );
    if (client_params_len > 0) {
        memcpy(quicz_openssl_configured_client_transport_parameters, client_params, client_params_len);
    }
    if (server_params_len > 0) {
        memcpy(quicz_openssl_configured_server_transport_parameters, server_params, server_params_len);
    }
    quicz_openssl_configured_client_transport_parameters_len = client_params_len;
    quicz_openssl_configured_server_transport_parameters_len = server_params_len;
    quicz_openssl_transport_parameters_configured = 1;
    return 1;
}

static int init_endpoint(struct quicz_openssl_endpoint *endpoint, int is_client) {
    static const unsigned char client_transport_parameters[] = {
        0x0f, 0x04, 0x21, 0x22, 0x23, 0x24,
        0x04, 0x02, 0x60, 0x00,
        0x05, 0x02, 0x48, 0x00,
        0x06, 0x02, 0x48, 0x00,
        0x08, 0x01, 0x08
    };
    static const unsigned char server_transport_parameters[] = {
        0x00, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
        0x0f, 0x04, 0x31, 0x32, 0x33, 0x34,
        0x04, 0x02, 0x60, 0x00,
        0x05, 0x02, 0x48, 0x00,
        0x06, 0x02, 0x48, 0x00,
        0x08, 0x01, 0x08
    };
    const unsigned char *transport_parameters = is_client ? client_transport_parameters : server_transport_parameters;
    size_t transport_parameters_len = is_client ? sizeof(client_transport_parameters) : sizeof(server_transport_parameters);
    if (quicz_openssl_transport_parameters_configured) {
        transport_parameters = is_client ?
            quicz_openssl_configured_client_transport_parameters :
            quicz_openssl_configured_server_transport_parameters;
        transport_parameters_len = is_client ?
            quicz_openssl_configured_client_transport_parameters_len :
            quicz_openssl_configured_server_transport_parameters_len;
    }

    memset(endpoint, 0, sizeof(*endpoint));
    if (transport_parameters_len > sizeof(endpoint->local_transport_parameters)) {
        return 0;
    }
    memcpy(endpoint->local_transport_parameters, transport_parameters, transport_parameters_len);
    endpoint->local_transport_parameters_len = transport_parameters_len;
    endpoint->ctx = SSL_CTX_new(is_client ? TLS_client_method() : TLS_server_method());
    if (endpoint->ctx == NULL) {
        return 0;
    }
    if (!SSL_CTX_set_min_proto_version(endpoint->ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(endpoint->ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_cipher_list(endpoint->ctx, "PSK") ||
        !SSL_CTX_set_ciphersuites(endpoint->ctx, "TLS_AES_128_GCM_SHA256")) {
        return 0;
    }
    SSL_CTX_set_psk_client_callback(endpoint->ctx, psk_client_cb);
    SSL_CTX_set_psk_server_callback(endpoint->ctx, psk_server_cb);

    endpoint->ssl = SSL_new(endpoint->ctx);
    if (endpoint->ssl == NULL) {
        return 0;
    }
    SSL_set_app_data(endpoint->ssl, endpoint);
    SSL_CTX_set_keylog_callback(endpoint->ctx, keylog_cb);
    if (!SSL_set_quic_tls_cbs(endpoint->ssl, quicz_openssl_tls_dispatch, endpoint) ||
        !SSL_set_quic_tls_transport_params(
            endpoint->ssl,
            endpoint->local_transport_parameters,
            endpoint->local_transport_parameters_len
        )) {
        return 0;
    }
    if (is_client) {
        SSL_set_connect_state(endpoint->ssl);
    } else {
        SSL_set_accept_state(endpoint->ssl);
    }
    return 1;
}

static int pump_crypto(struct quicz_openssl_endpoint *from, struct quicz_openssl_endpoint *to) {
    for (uint32_t level = 0; level < QUICZ_OPENSSL_LEVEL_COUNT; level += 1) {
        if (from->out_len[level] == 0) {
            continue;
        }
        if (from->out_len[level] > sizeof(to->in[level]) - to->in_len[level]) {
            return 0;
        }
        memcpy(to->in[level] + to->in_len[level], from->out[level], from->out_len[level]);
        to->in_len[level] += from->out_len[level];
        from->out_len[level] = 0;
    }
    return 1;
}

static void drive_handshake(struct quicz_openssl_endpoint *endpoint) {
    const int rc = SSL_do_handshake(endpoint->ssl);
    if (rc == 1) {
        endpoint->handshake_done = 1;
        endpoint->last_ssl_error = SSL_ERROR_NONE;
    } else {
        endpoint->last_ssl_error = SSL_get_error(endpoint->ssl, rc);
    }
}

static void copy_result_endpoint(
    struct quicz_openssl_pair_transcript_result *result,
    const struct quicz_openssl_endpoint *client,
    const struct quicz_openssl_endpoint *server
) {
    result->client_done = client->handshake_done;
    result->server_done = server->handshake_done;
    result->client_send_callbacks = client->send_callbacks;
    result->server_send_callbacks = server->send_callbacks;
    result->client_recv_callbacks = client->recv_callbacks;
    result->server_recv_callbacks = server->recv_callbacks;
    result->client_release_callbacks = client->release_callbacks;
    result->server_release_callbacks = server->release_callbacks;
    result->client_yield_secret_callbacks = client->yield_secret_callbacks;
    result->server_yield_secret_callbacks = server->yield_secret_callbacks;
    result->client_got_transport_params_callbacks = client->got_transport_params_callbacks;
    result->server_got_transport_params_callbacks = server->got_transport_params_callbacks;
    result->client_peer_transport_parameters_len = client->peer_transport_parameters_len;
    result->server_peer_transport_parameters_len = server->peer_transport_parameters_len;
    result->client_keylog_callbacks = client->keylog_callbacks;
    result->server_keylog_callbacks = server->keylog_callbacks;
    result->client_keylog_bytes = client->keylog_bytes;
    result->server_keylog_bytes = server->keylog_bytes;
    result->client_alert_callbacks = client->alert_callbacks;
    result->server_alert_callbacks = server->alert_callbacks;
    result->client_last_alert = client->last_alert;
    result->server_last_alert = server->last_alert;
    result->client_last_ssl_error = client->last_ssl_error;
    result->server_last_ssl_error = server->last_ssl_error;
    result->client_read_level = (int)client->read_level;
    result->server_read_level = (int)server->read_level;
    result->client_write_level = (int)client->write_level;
    result->server_write_level = (int)server->write_level;
    for (uint32_t level = 0; level < QUICZ_OPENSSL_LEVEL_COUNT; level += 1) {
        result->client_out_level_bytes[level] = client->out_total_len[level];
        result->server_out_level_bytes[level] = server->out_total_len[level];
    }
}

static void copy_last_crypto(
    const struct quicz_openssl_endpoint *client,
    const struct quicz_openssl_endpoint *server
) {
    memset(quicz_openssl_last_client_crypto_len, 0, sizeof(quicz_openssl_last_client_crypto_len));
    memset(quicz_openssl_last_server_crypto_len, 0, sizeof(quicz_openssl_last_server_crypto_len));
    for (uint32_t level = 0; level < QUICZ_OPENSSL_LEVEL_COUNT; level += 1) {
        memcpy(quicz_openssl_last_client_crypto[level], client->out_history[level], client->out_history_len[level]);
        quicz_openssl_last_client_crypto_len[level] = client->out_history_len[level];
        memcpy(quicz_openssl_last_server_crypto[level], server->out_history[level], server->out_history_len[level]);
        quicz_openssl_last_server_crypto_len[level] = server->out_history_len[level];
    }
}

static void copy_last_transport_parameters(
    const struct quicz_openssl_endpoint *client,
    const struct quicz_openssl_endpoint *server
) {
    memset(quicz_openssl_last_client_peer_transport_parameters, 0, sizeof(quicz_openssl_last_client_peer_transport_parameters));
    memset(quicz_openssl_last_server_peer_transport_parameters, 0, sizeof(quicz_openssl_last_server_peer_transport_parameters));
    quicz_openssl_last_client_peer_transport_parameters_len = client->peer_transport_parameters_len;
    quicz_openssl_last_server_peer_transport_parameters_len = server->peer_transport_parameters_len;
    memcpy(
        quicz_openssl_last_client_peer_transport_parameters,
        client->peer_transport_parameters,
        client->peer_transport_parameters_len
    );
    memcpy(
        quicz_openssl_last_server_peer_transport_parameters,
        server->peer_transport_parameters,
        server->peer_transport_parameters_len
    );
}

static void copy_last_secrets(
    const struct quicz_openssl_endpoint *client,
    const struct quicz_openssl_endpoint *server
) {
    memset(quicz_openssl_last_client_secret_available, 0, sizeof(quicz_openssl_last_client_secret_available));
    memset(quicz_openssl_last_server_secret_available, 0, sizeof(quicz_openssl_last_server_secret_available));
    for (uint32_t level = 0; level < QUICZ_OPENSSL_LEVEL_COUNT; level += 1) {
        for (uint32_t direction = 0; direction < QUICZ_OPENSSL_SECRET_DIRECTION_COUNT; direction += 1) {
            if (client->secret_available[level][direction]) {
                memcpy(
                    quicz_openssl_last_client_secrets[level][direction],
                    client->secrets[level][direction],
                    QUICZ_OPENSSL_SECRET_LEN
                );
                quicz_openssl_last_client_secret_available[level][direction] = 1;
            }
            if (server->secret_available[level][direction]) {
                memcpy(
                    quicz_openssl_last_server_secrets[level][direction],
                    server->secrets[level][direction],
                    QUICZ_OPENSSL_SECRET_LEN
                );
                quicz_openssl_last_server_secret_available[level][direction] = 1;
            }
        }
    }
}

struct quicz_openssl_pair_transcript_result quicz_openssl_pair_transcript_run(void) {
    struct quicz_openssl_pair_transcript_result result;
    memset(&result, 0, sizeof(result));
    memset(quicz_openssl_last_client_crypto_len, 0, sizeof(quicz_openssl_last_client_crypto_len));
    memset(quicz_openssl_last_server_crypto_len, 0, sizeof(quicz_openssl_last_server_crypto_len));
    memset(quicz_openssl_last_client_peer_transport_parameters, 0, sizeof(quicz_openssl_last_client_peer_transport_parameters));
    memset(quicz_openssl_last_server_peer_transport_parameters, 0, sizeof(quicz_openssl_last_server_peer_transport_parameters));
    quicz_openssl_last_client_peer_transport_parameters_len = 0;
    quicz_openssl_last_server_peer_transport_parameters_len = 0;
    memset(quicz_openssl_last_client_secret_available, 0, sizeof(quicz_openssl_last_client_secret_available));
    memset(quicz_openssl_last_server_secret_available, 0, sizeof(quicz_openssl_last_server_secret_available));

    struct quicz_openssl_endpoint *client = calloc(1, sizeof(*client));
    struct quicz_openssl_endpoint *server = calloc(1, sizeof(*server));
    if (client == NULL || server == NULL) {
        free_endpoint(client);
        free_endpoint(server);
        return result;
    }
    if (!init_endpoint(client, 1) || !init_endpoint(server, 0)) {
        result.error_queue_code = ERR_peek_error();
        free_endpoint(client);
        free_endpoint(server);
        return result;
    }
    result.initialized = 1;

    for (int iteration = 0; iteration < 80; iteration += 1) {
        if (client->handshake_done && server->handshake_done) {
            break;
        }
        drive_handshake(client);
        if (!pump_crypto(client, server)) {
            break;
        }
        drive_handshake(server);
        if (!pump_crypto(server, client)) {
            break;
        }
        result.drive_iterations = iteration + 1;
    }

    copy_result_endpoint(&result, client, server);
    copy_last_crypto(client, server);
    copy_last_transport_parameters(client, server);
    copy_last_secrets(client, server);
    result.error_queue_code = ERR_peek_error();
    free_endpoint(client);
    free_endpoint(server);
    return result;
}

static int copy_crypto_level(
    const unsigned char history[QUICZ_OPENSSL_LEVEL_COUNT][QUICZ_OPENSSL_CRYPTO_BUF_LEN],
    const size_t history_len[QUICZ_OPENSSL_LEVEL_COUNT],
    int level,
    unsigned char *out,
    size_t out_len,
    size_t *written_len
) {
    if (written_len == NULL || level < 0 || level >= QUICZ_OPENSSL_LEVEL_COUNT) {
        return 0;
    }
    *written_len = 0;
    const size_t level_len = history_len[level];
    if (level_len > out_len) {
        return 0;
    }
    if (level_len != 0 && out == NULL) {
        return 0;
    }
    memcpy(out, history[level], level_len);
    *written_len = level_len;
    return 1;
}

int quicz_openssl_pair_transcript_copy_client_crypto(
    int level,
    unsigned char *out,
    size_t out_len,
    size_t *written_len
) {
    return copy_crypto_level(
        quicz_openssl_last_client_crypto,
        quicz_openssl_last_client_crypto_len,
        level,
        out,
        out_len,
        written_len
    );
}

int quicz_openssl_pair_transcript_copy_server_crypto(
    int level,
    unsigned char *out,
    size_t out_len,
    size_t *written_len
) {
    return copy_crypto_level(
        quicz_openssl_last_server_crypto,
        quicz_openssl_last_server_crypto_len,
        level,
        out,
        out_len,
        written_len
    );
}

int quicz_openssl_pair_transcript_copy_client_peer_transport_parameters(
    unsigned char *out,
    size_t out_len,
    size_t *written_len
) {
    if (written_len == NULL || quicz_openssl_last_client_peer_transport_parameters_len > out_len) {
        if (written_len != NULL) {
            *written_len = 0;
        }
        return 0;
    }
    *written_len = quicz_openssl_last_client_peer_transport_parameters_len;
    memcpy(out, quicz_openssl_last_client_peer_transport_parameters, *written_len);
    return 1;
}

int quicz_openssl_pair_transcript_copy_server_peer_transport_parameters(
    unsigned char *out,
    size_t out_len,
    size_t *written_len
) {
    if (written_len == NULL || quicz_openssl_last_server_peer_transport_parameters_len > out_len) {
        if (written_len != NULL) {
            *written_len = 0;
        }
        return 0;
    }
    *written_len = quicz_openssl_last_server_peer_transport_parameters_len;
    memcpy(out, quicz_openssl_last_server_peer_transport_parameters, *written_len);
    return 1;
}

static int copy_secret(
    const unsigned char secrets[QUICZ_OPENSSL_LEVEL_COUNT][QUICZ_OPENSSL_SECRET_DIRECTION_COUNT][QUICZ_OPENSSL_SECRET_LEN],
    const int available[QUICZ_OPENSSL_LEVEL_COUNT][QUICZ_OPENSSL_SECRET_DIRECTION_COUNT],
    int level,
    int direction,
    unsigned char *out,
    size_t out_len,
    size_t *written_len
) {
    if (written_len == NULL ||
        level < 0 ||
        level >= QUICZ_OPENSSL_LEVEL_COUNT ||
        direction < 0 ||
        direction >= QUICZ_OPENSSL_SECRET_DIRECTION_COUNT ||
        !available[level][direction] ||
        out_len < QUICZ_OPENSSL_SECRET_LEN ||
        out == NULL) {
        if (written_len != NULL) {
            *written_len = 0;
        }
        return 0;
    }
    memcpy(out, secrets[level][direction], QUICZ_OPENSSL_SECRET_LEN);
    *written_len = QUICZ_OPENSSL_SECRET_LEN;
    return 1;
}

int quicz_openssl_pair_transcript_copy_client_secret(
    int level,
    int direction,
    unsigned char *out,
    size_t out_len,
    size_t *written_len
) {
    return copy_secret(
        quicz_openssl_last_client_secrets,
        quicz_openssl_last_client_secret_available,
        level,
        direction,
        out,
        out_len,
        written_len
    );
}

int quicz_openssl_pair_transcript_copy_server_secret(
    int level,
    int direction,
    unsigned char *out,
    size_t out_len,
    size_t *written_len
) {
    return copy_secret(
        quicz_openssl_last_server_secrets,
        quicz_openssl_last_server_secret_available,
        level,
        direction,
        out,
        out_len,
        written_len
    );
}

void *quicz_openssl_pair_transcript_context_new(void) {
    struct quicz_openssl_pair_transcript_context *context = calloc(1, sizeof(*context));
    if (context == NULL) {
        return NULL;
    }
    context->client = calloc(1, sizeof(*context->client));
    context->server = calloc(1, sizeof(*context->server));
    if (context->client == NULL ||
        context->server == NULL ||
        !init_endpoint(context->client, 1) ||
        !init_endpoint(context->server, 0)) {
        free_endpoint(context->client);
        free_endpoint(context->server);
        free(context);
        return NULL;
    }
    return context;
}

void quicz_openssl_pair_transcript_context_free(void *opaque_context) {
    struct quicz_openssl_pair_transcript_context *context = opaque_context;
    if (context == NULL) {
        return;
    }
    free_endpoint(context->client);
    free_endpoint(context->server);
    free(context);
}

static struct quicz_openssl_endpoint *context_endpoint(
    struct quicz_openssl_pair_transcript_context *context,
    int is_client
) {
    if (context == NULL) {
        return NULL;
    }
    return is_client ? context->client : context->server;
}

int quicz_openssl_pair_transcript_context_drive(void *opaque_context, int is_client) {
    struct quicz_openssl_endpoint *endpoint = context_endpoint(opaque_context, is_client);
    if (endpoint == NULL) {
        return 0;
    }
    drive_handshake(endpoint);
    return 1;
}

struct quicz_openssl_pair_transcript_result quicz_openssl_pair_transcript_context_result(void *opaque_context) {
    struct quicz_openssl_pair_transcript_result result;
    memset(&result, 0, sizeof(result));
    struct quicz_openssl_pair_transcript_context *context = opaque_context;
    if (context == NULL || context->client == NULL || context->server == NULL) {
        return result;
    }
    result.initialized = 1;
    copy_result_endpoint(&result, context->client, context->server);
    result.error_queue_code = ERR_peek_error();
    return result;
}

int quicz_openssl_pair_transcript_context_provide_crypto(
    void *opaque_context,
    int is_client,
    int level,
    const unsigned char *data,
    size_t data_len
) {
    struct quicz_openssl_endpoint *endpoint = context_endpoint(opaque_context, is_client);
    if (endpoint == NULL ||
        level < 0 ||
        level >= QUICZ_OPENSSL_LEVEL_COUNT ||
        (data_len > 0 && data == NULL) ||
        data_len > sizeof(endpoint->in[level]) - endpoint->in_len[level]) {
        return 0;
    }
    if (data_len > 0) {
        memcpy(endpoint->in[level] + endpoint->in_len[level], data, data_len);
    }
    endpoint->in_len[level] += data_len;
    return 1;
}

int quicz_openssl_pair_transcript_context_copy_pending_crypto(
    void *opaque_context,
    int is_client,
    int level,
    unsigned char *out,
    size_t out_len,
    size_t *written_len
) {
    struct quicz_openssl_endpoint *endpoint = context_endpoint(opaque_context, is_client);
    if (written_len == NULL ||
        endpoint == NULL ||
        level < 0 ||
        level >= QUICZ_OPENSSL_LEVEL_COUNT ||
        endpoint->out_len[level] > out_len ||
        (endpoint->out_len[level] > 0 && out == NULL)) {
        if (written_len != NULL) {
            *written_len = 0;
        }
        return 0;
    }
    memcpy(out, endpoint->out[level], endpoint->out_len[level]);
    *written_len = endpoint->out_len[level];
    endpoint->out_len[level] = 0;
    return 1;
}

int quicz_openssl_pair_transcript_context_copy_secret(
    void *opaque_context,
    int is_client,
    int level,
    int direction,
    unsigned char *out,
    size_t out_len,
    size_t *written_len
) {
    struct quicz_openssl_endpoint *endpoint = context_endpoint(opaque_context, is_client);
    if (endpoint == NULL) {
        if (written_len != NULL) {
            *written_len = 0;
        }
        return 0;
    }
    return copy_secret(
        endpoint->secrets,
        endpoint->secret_available,
        level,
        direction,
        out,
        out_len,
        written_len
    );
}
