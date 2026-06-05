#ifndef QUICZ_TLS_OPENSSL_PAIR_TRANSCRIPT_H
#define QUICZ_TLS_OPENSSL_PAIR_TRANSCRIPT_H

#include <stddef.h>
#include <stdint.h>

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

int quicz_openssl_pair_transcript_configure_transport_parameters(
    const uint8_t *client_params,
    size_t client_params_len,
    const uint8_t *server_params,
    size_t server_params_len
);
struct quicz_openssl_pair_transcript_result quicz_openssl_pair_transcript_run(void);
int quicz_openssl_pair_transcript_copy_client_crypto(
    int level,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
);
int quicz_openssl_pair_transcript_copy_server_crypto(
    int level,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
);
int quicz_openssl_pair_transcript_copy_client_peer_transport_parameters(
    uint8_t *out,
    size_t out_len,
    size_t *written_len
);
int quicz_openssl_pair_transcript_copy_server_peer_transport_parameters(
    uint8_t *out,
    size_t out_len,
    size_t *written_len
);
int quicz_openssl_pair_transcript_copy_client_secret(
    int level,
    int direction,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
);
int quicz_openssl_pair_transcript_copy_server_secret(
    int level,
    int direction,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
);
void *quicz_openssl_pair_transcript_context_new(void);
void quicz_openssl_pair_transcript_context_free(void *opaque_context);
int quicz_openssl_pair_transcript_context_drive(void *opaque_context, int is_client);
struct quicz_openssl_pair_transcript_result quicz_openssl_pair_transcript_context_result(void *opaque_context);
int quicz_openssl_pair_transcript_context_provide_crypto(
    void *opaque_context,
    int is_client,
    int level,
    const uint8_t *data,
    size_t data_len
);
int quicz_openssl_pair_transcript_context_copy_pending_crypto(
    void *opaque_context,
    int is_client,
    int level,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
);
int quicz_openssl_pair_transcript_context_copy_secret(
    void *opaque_context,
    int is_client,
    int level,
    int direction,
    uint8_t *out,
    size_t out_len,
    size_t *written_len
);

#endif
