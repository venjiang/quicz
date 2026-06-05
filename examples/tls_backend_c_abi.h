#ifndef QUICZ_TLS_BACKEND_C_ABI_H
#define QUICZ_TLS_BACKEND_C_ABI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

struct quicz_one_rtt_traffic_secrets {
    uint8_t local[32];
    uint8_t peer[32];
};

#endif
