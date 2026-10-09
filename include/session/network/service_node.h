#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef struct network_service_node {
    char ed25519_pubkey_hex[65];  // The 64-byte ed25519 pubkey in hex + null terminator.
    uint8_t ip[4];
    uint16_t https_port;
    uint16_t omq_port;
    uint16_t version[3];
    uint64_t swarm_id;
    int64_t requested_unlock_height;  // -1 if unknown; 0 if no unlock has been requested.
} network_service_node;

#ifdef __cplusplus
}
#endif
