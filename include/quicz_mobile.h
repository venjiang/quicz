#ifndef QUICZ_MOBILE_H
#define QUICZ_MOBILE_H

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
};

uint32_t quicz_mobile_abi_version(void);
uint64_t quicz_mobile_capabilities(void);

#ifdef __cplusplus
}
#endif

#endif
