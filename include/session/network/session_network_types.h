#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "../export.h"
#include "session/network/service_node.h"

typedef enum CONNECTION_STATUS {
    CONNECTION_STATUS_UNKNOWN,
    CONNECTION_STATUS_CONNECTING,
    CONNECTION_STATUS_CONNECTED,
    CONNECTION_STATUS_DISCONNECTED,
} CONNECTION_STATUS;

typedef enum {
    SESSION_NETWORK_REQUEST_CATEGORY_STANDARD,
    SESSION_NETWORK_REQUEST_CATEGORY_STANDARD_SMALL,
    SESSION_NETWORK_REQUEST_CATEGORY_FILE,
    SESSION_NETWORK_REQUEST_CATEGORY_FILE_SMALL,
} SESSION_NETWORK_REQUEST_CATEGORY;

typedef enum {
    SESSION_NETWORK_PATH_CATEGORY_STANDARD,
    SESSION_NETWORK_PATH_CATEGORY_FILE,
} SESSION_NETWORK_PATH_CATEGORY;

typedef struct network_server_destination {
    const char* method;
    const char* protocol;
    const char* host;
    uint16_t port;
    const char* x25519_pubkey_hex;
    const char* const* headers_kv_pairs;
    size_t headers_kv_pairs_len;
} network_server_destination;

typedef struct {
    char ed25519_pubkey_hex[65];  // The 64-byte ed25519 pubkey in hex + null terminator.
    uint8_t ip[4];
    uint16_t port;
} session_remote_address;

typedef struct {
    // Only ONE of these pointers should be set, the other should be left null
    const network_service_node* snode_dest;
    const network_server_destination* server_dest;
    const session_remote_address* remote_addr_dest;

    const char* endpoint;
    const unsigned char* body;
    size_t body_size;

    SESSION_NETWORK_REQUEST_CATEGORY category;
    uint64_t request_timeout_ms;
    uint64_t overall_timeout_ms;  // Use 0 for no overall timeout

    const char* upload_file_name;  // Optional name for file uploads, null terminated

    const char* request_id;  // Optional id for the request to trace through logs, null terminated

    // The account whose swarm this request addresses, as 64 hex chars of its X25519 pubkey — the
    // same value passed to session_network_get_swarm() to choose the destination node.  Null for a
    // request aimed at a node rather than about an account (a cache refresh, a clock resync) or at
    // a server, which no swarm membership applies to.  For a `batch` or `sequence` request each
    // sub-request's account is read from the body instead, and this is used only if the body
    // can't be parsed.
    //
    // Set it whenever there is one: a storage server rejects a request whose pubkey is outside its
    // swarm with a 421, and recovering means re-resolving this account's swarm.  Left null, such a
    // request fails on the first 421 instead of being redirected.
    const char* swarm_pubkey_hex;

} session_request_params;

typedef struct {
    SESSION_NETWORK_PATH_CATEGORY category;
} session_onion_path_metadata;

typedef struct {
    char destination_pubkey[65];         // The 64-byte ed25519 pubkey in hex + null terminator.
    char destination_snode_address[65];  // The 64-byte .snode address + null terminator.
} session_router_tunnel_metadata;

typedef struct {
    const network_service_node* nodes;
    size_t nodes_count;

    // Only ONE of these pointers should be set, the other should be left null
    const session_onion_path_metadata* onion_metadata;
    const session_router_tunnel_metadata* session_router_metadata;

} session_path_info;

#ifdef __cplusplus
}
#endif
