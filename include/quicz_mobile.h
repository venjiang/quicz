#ifndef QUICZ_MOBILE_H
#define QUICZ_MOBILE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QUICZ_MOBILE_ABI_VERSION 1u

enum quicz_mobile_capability {
    QUICZ_MOBILE_CAPABILITY_STREAM = 1ull << 0,
    QUICZ_MOBILE_CAPABILITY_DATAGRAM = 1ull << 1,
    QUICZ_MOBILE_CAPABILITY_PATH_VALIDATION = 1ull << 2,
    QUICZ_MOBILE_CAPABILITY_MIGRATION = 1ull << 3,
    QUICZ_MOBILE_CAPABILITY_MULTIPATH = 1ull << 4,
    QUICZ_MOBILE_CAPABILITY_STUN = 1ull << 5,
    QUICZ_MOBILE_CAPABILITY_HOLE_PUNCH = 1ull << 6,
};

enum quicz_mobile_result {
    QUICZ_MOBILE_OK = 0,
    QUICZ_MOBILE_INVALID_ARGUMENT = 1,
    QUICZ_MOBILE_ALLOCATION_FAILED = 2,
    QUICZ_MOBILE_OPEN_FAILED = 3,
    QUICZ_MOBILE_CONNECTION_FAILED = 4,
    QUICZ_MOBILE_STREAM_FAILED = 5,
    QUICZ_MOBILE_DISCOVERY_FAILED = 6,
    QUICZ_MOBILE_PUNCH_FAILED = 7,
    QUICZ_MOBILE_CONNECTION_TIMED_OUT = 8,
};

typedef struct quicz_mobile_client quicz_mobile_client;

typedef struct quicz_mobile_client_config {
    uint8_t server_ipv4[4];
    uint16_t server_port;
    uint8_t allow_migration;
    uint8_t reserved;
    const uint8_t *server_name;
    size_t server_name_length;
    const uint8_t *alpn;
    size_t alpn_length;
    const uint8_t *ca_certificate_der;
    size_t ca_certificate_der_length;
} quicz_mobile_client_config;

typedef struct quicz_mobile_ipv4_endpoint {
    uint8_t address[4];
    uint16_t port;
} quicz_mobile_ipv4_endpoint;

typedef struct quicz_mobile_punch_config {
    quicz_mobile_ipv4_endpoint remote;
    uint8_t key[32];
    uint8_t attempt_id[16];
    uint8_t nonce[16];
    uint32_t initial_retry_ms;
    uint32_t maximum_retry_ms;
    uint8_t max_attempts;
    uint8_t reserved[3];
} quicz_mobile_punch_config;

enum quicz_mobile_punch_outcome {
    QUICZ_MOBILE_PUNCH_NOT_STARTED = 0,
    QUICZ_MOBILE_PUNCH_VALIDATED = 1,
    QUICZ_MOBILE_PUNCH_RETRY_EXHAUSTED = 2,
    QUICZ_MOBILE_PUNCH_CANCELED = 3,
    QUICZ_MOBILE_PUNCH_IO_FAILED = 4,
};

/* Fixed per-call diagnostics; no addresses, identities, or packet contents.
 * Counts saturate at UINT32_MAX. Outcome describes UDP proof, not QUIC. */
typedef struct quicz_mobile_punch_diagnostics {
    uint64_t duration_ms;
    uint32_t outcome;
    uint32_t probes_sent;
    uint32_t acks_sent;
    uint32_t datagrams_received;
    uint32_t source_rejected;
    uint32_t oversized_received;
    uint32_t packets_checked;
    uint32_t malformed_rejected;
    uint32_t authentication_rejected;
    uint32_t attempt_rejected;
    uint32_t nonce_rejected;
    uint8_t peer_probe;
    uint8_t local_ack;
    uint8_t reserved[2];
} quicz_mobile_punch_diagnostics;

uint32_t quicz_mobile_abi_version(void);
uint64_t quicz_mobile_capabilities(void);

/* Experimental blocking API. Callers must serialize destroy with all other
 * operations and run connect/discover/send/receive off the UI thread. The
 * unverified constructor is test-only; production callers provide a DER CA
 * certificate to quicz_mobile_client_create. */
int32_t quicz_mobile_client_create_unverified(
    const quicz_mobile_client_config *config,
    quicz_mobile_client **client_out
);
int32_t quicz_mobile_client_create(
    const quicz_mobile_client_config *config,
    quicz_mobile_client **client_out
);
int32_t quicz_mobile_client_connect(quicz_mobile_client *client);
int32_t quicz_mobile_client_connect_timeout(
    quicz_mobile_client *client,
    uint32_t timeout_ms
);
int32_t quicz_mobile_client_bound_ipv4(
    quicz_mobile_client *client,
    quicz_mobile_ipv4_endpoint *endpoint_out
);
int32_t quicz_mobile_client_discover_ipv4(
    quicz_mobile_client *client,
    const quicz_mobile_ipv4_endpoint *stun_server,
    uint32_t timeout_ms,
    uint8_t max_attempts,
    quicz_mobile_ipv4_endpoint *mapped_endpoint_out
);
int32_t quicz_mobile_client_punch_ipv4(
    quicz_mobile_client *client,
    const quicz_mobile_punch_config *config
);
/* Clears diagnostics_out on entry and fills it on failure as well as success.
 * The output pointer is required. Lifecycle/serialization rules are unchanged. */
int32_t quicz_mobile_client_punch_ipv4_with_diagnostics(
    quicz_mobile_client *client,
    const quicz_mobile_punch_config *config,
    quicz_mobile_punch_diagnostics *diagnostics_out
);
int32_t quicz_mobile_client_open_bidi(
    quicz_mobile_client *client,
    uint64_t *stream_id_out
);
/* Configure application-space PING keepalive before connect. Zero disables it. */
int32_t quicz_mobile_client_set_keepalive_interval(
    quicz_mobile_client *client,
    uint32_t interval_ms
);
int32_t quicz_mobile_client_send(
    quicz_mobile_client *client,
    uint64_t stream_id,
    const uint8_t *bytes,
    size_t length,
    uint8_t finish
);
int32_t quicz_mobile_client_receive(
    quicz_mobile_client *client,
    uint64_t stream_id,
    uint8_t *buffer,
    size_t capacity,
    size_t *received_out
);
void quicz_mobile_client_close(quicz_mobile_client *client);
void quicz_mobile_client_destroy(quicz_mobile_client *client);

#ifdef __cplusplus
}
#endif

#endif
