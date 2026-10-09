#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#include "session/export.h"
#include "session/log_level.h"
#include "session/network/session_network_types.h"
#include "session/onionreq/builder.h"
#include "session/platform.h"

typedef struct network_object {
    // Internal opaque object pointer; calling code should leave this alone.
    void* internals;
} network_object;
typedef struct session_response_handle_cpp_t session_response_handle_t;

typedef enum {
    SESSION_NETWORK_MAINNET = 0,
    SESSION_NETWORK_TESTNET = 1,
    SESSION_NETWORK_DEVNET = 2
} SESSION_NETWORK_NETID;

typedef enum {
    SESSION_NETWORK_ROUTER_ONION_REQUESTS = 0,
    SESSION_NETWORK_ROUTER_SESSION_ROUTER = 1,
    SESSION_NETWORK_ROUTER_DIRECT = 2,
} SESSION_NETWORK_ROUTER;

typedef enum {
    SESSION_NETWORK_TRANSPORT_QUIC = 0,
} SESSION_NETWORK_TRANSPORT;

typedef void (*session_network_request_t)(
        const char* url,
        const char* body_data,
        size_t body_size,
        session_response_handle_t* response_handle,
        void* ctx);

typedef struct session_network_config {
    // Basic options
    SESSION_NETWORK_NETID netid;
    SESSION_NETWORK_ROUTER router;
    SESSION_NETWORK_TRANSPORT transport;

    // File server options
    const char* custom_file_server_scheme;
    const char* custom_file_server_host;
    uint16_t custom_file_server_port;
    const char* custom_file_server_pubkey_hex;
    uint64_t custom_file_server_max_file_size;
    bool file_server_use_stream_encryption;

    // General options
    bool increase_no_file_limit;
    uint8_t path_length;
    bool enforce_subnet_diversity;
    uint8_t redirect_retry_count;
    uint64_t min_retry_delay_ms;
    uint64_t max_retry_delay_ms;
    uint8_t num_nodes_to_check_for_network_offset;
    uint32_t min_resume_clock_resync_interval_minutes;

    // Devnet options (only used when netid_target == SESSION_NETWORK_DEVNET)
    const network_service_node* devnet_seed_nodes;
    size_t devnet_seed_nodes_size;

    // Snode pool options
    const char* cache_dir;
    const char* fallback_snode_pool_path;
    uint32_t cache_expiration_minutes;
    uint64_t cache_min_lifetime_ms;
    size_t cache_min_size;
    size_t cache_min_swarm_size;
    uint8_t cache_num_nodes_to_use_for_refresh;
    uint8_t cache_min_num_refresh_presence_to_include_node;
    uint8_t cache_node_strike_threshold;

    // Onion request router options (only used when router ==
    // SESSION_NETWORK_ROUTER_ONION_REQUESTS)
    uint8_t onionreq_path_strike_threshold;
    uint8_t onionreq_path_build_retry_limit;
    uint8_t onionreq_min_path_count_standard;
    uint8_t onionreq_min_path_count_file;
    bool onionreq_single_path_mode;
    bool onionreq_disable_pre_build_paths;
    uint32_t onionreq_path_rotation_frequency_minutes;
    uint8_t onionreq_edge_node_cache_duration_days;

    // Quic transport options (for transport == SESSION_NETWORK_TRANSPORT_QUIC)
    uint32_t quic_handshake_timeout_seconds;
    uint32_t quic_keep_alive_seconds;
    bool quic_disable_mtu_discovery;  // same as quic_max_udp_payload = 1200
    /// Maximum QUIC UDP payload size; 0 for no cap.  Must otherwise be at least 1200.  Takes
    /// precedence over quic_disable_mtu_discovery when non-zero.
    size_t quic_max_udp_payload;

} session_network_config;

typedef void (*session_network_response_t)(
        bool success,
        bool timeout,
        int16_t status_code,
        const char* const* headers_kv_pairs,
        size_t headers_kv_pairs_len,
        const unsigned char* response,
        size_t response_size,
        void* ctx);

typedef struct session_upload_handle_t session_upload_handle_t;
typedef struct session_download_handle_t session_download_handle_t;

typedef struct session_file_metadata {
    char file_id[65];  // 64 char string + null terminator
    uint64_t size;
    int64_t uploaded_timestamp;  // unix timestamp
    int64_t expiry_timestamp;    // unix timestamp
} session_file_metadata;

typedef struct session_upload_callbacks {
    // Called repeatedly to get next chunk of data to upload
    // Should return number of bytes written to `buffer`, or 0 when done
    // Return -1 to cancel the upload
    size_t (*next_data)(unsigned char* buffer, size_t buffer_capacity, void* ctx);

    // Called when download completes (a null `metadata` value means an error occured)
    void (*on_complete)(
            const session_file_metadata* metadata, int16_t status_code, bool timeout, void* ctx);

    void* ctx;  // User context passed to all callbacks
} session_upload_callbacks;

typedef struct session_download_callbacks {
    // Called as data arrives (may be called multiple times for streaming)
    void (*on_data)(
            const session_file_metadata* metadata,
            const unsigned char* data,
            size_t data_len,
            void* ctx);

    // Called when download completes (a null `metadata` value means an error occured)
    void (*on_complete)(
            const session_file_metadata* metadata, int16_t status_code, bool timeout, void* ctx);

    void* ctx;  // User context passed to all callbacks
} session_download_callbacks;

/// API: network/session_network_default_config
///
/// Populates an instance with the default configuration options.
///
/// Inputs:
/// - `config` -- [in] Pointer to session_network_config object
LIBSESSION_EXPORT session_network_config session_network_config_default();

LIBSESSION_EXPORT bool session_network_init(
        network_object** network,
        const session_network_config* config,
        char* error) LIBSESSION_WARN_UNUSED;

/// API: network/session_network_free
///
/// Frees a network object.
///
/// Inputs:
/// - `network` -- [in] Pointer to network_object object
LIBSESSION_EXPORT void session_network_free(network_object* network);

/// API: network/session_request_params_free
///
/// Frees a request params object.
///
/// Inputs:
/// - `params` -- [in] Pointer to session_request_params object
LIBSESSION_EXPORT void session_request_params_free(session_request_params* params);

LIBSESSION_EXPORT void session_network_suspend(network_object* network);
LIBSESSION_EXPORT void session_network_resume(
        network_object* network, bool automatically_reconnect);
LIBSESSION_EXPORT void session_network_close_connections(network_object* network);
LIBSESSION_EXPORT void session_network_clear_cache(network_object* network);

LIBSESSION_EXPORT bool session_network_has_retrieved_time_offset(network_object* network);
LIBSESSION_EXPORT int64_t session_network_time_offset(network_object* network);
LIBSESSION_EXPORT uint16_t session_network_hardfork(network_object* network);
LIBSESSION_EXPORT uint16_t session_network_softfork(network_object* network);

/// API: network/network_set_status_changed_callback
///
/// Registers a callback to be called whenever the network connection status changes.
///
/// Inputs:
/// - `network` -- [in] Pointer to the network object
/// - `callback` -- [in] callback to be called when the network connection status changes.
/// - `ctx` -- [in, optional] Pointer to an optional context. Set to NULL if unused.
LIBSESSION_EXPORT void session_network_set_status_changed_callback(
        network_object* network, void (*callback)(CONNECTION_STATUS status, void* ctx), void* ctx);

LIBSESSION_EXPORT void session_network_set_network_info_changed_callback(
        network_object* netowrk,
        void (*callback)(
                int64_t network_time_offset, uint16_t hardfork, uint16_t softfork, void* ctx),
        void* ctx);

LIBSESSION_EXPORT void session_network_callbacks_respond(
        network_object* network,
        session_response_handle_t* response_handle,
        bool success,
        bool timeout,
        int16_t status_code,
        const char* const* headers,
        const char* const* header_values,
        size_t headers_size,
        const char* body,
        size_t body_len);

LIBSESSION_EXPORT CONNECTION_STATUS session_network_get_status(network_object* network);

LIBSESSION_EXPORT void session_network_get_active_paths(
        network_object* network, session_path_info** out_paths, size_t* out_paths_len);

LIBSESSION_EXPORT void session_network_paths_free(session_path_info* paths);

LIBSESSION_EXPORT void session_network_get_swarm(
        network_object* network,
        const char* swarm_pubkey_hex,
        bool ignore_strike_count,
        void (*callback)(network_service_node* nodes, size_t nodes_len, void*),
        void* ctx);

LIBSESSION_EXPORT void session_network_get_random_nodes(
        network_object* network,
        uint16_t count,
        void (*callback)(network_service_node*, size_t, void*),
        void* ctx);

LIBSESSION_EXPORT void session_network_send_request(
        network_object* network,
        const session_request_params* params,
        session_network_response_t callback,
        void* ctx);

/// API: file_server/session_network_upload
///
/// Initiates a streaming upload.
///
/// The upload will call next_data() repeatedly until it returns 0 (EOF) or -1 (cancel).
/// For simple in-memory uploads, next_data() can return all data in one call.
///
/// Inputs:
/// - `network` -- [in] network object
/// - `file_name` -- [in, optional] name of the file being uploaded (null-terminated, can be NULL)
/// - `ttl` -- [in] ttl to use for the file (0 to ignore)
/// - `callbacks` -- [in] callbacks for data provision and completion
/// - `stall_timeout_ms` -- [in] timeout if no progress for this duration
/// - `request_timeout_ms` -- [in] timeout for the request itself
/// - `overall_timeout_ms` -- [in] timeout including pre-flight operations (0 to ignore)
///
/// Returns: handle to the upload, or NULL on error. Caller must free with session_upload_free()
LIBSESSION_EXPORT session_upload_handle_t* session_network_upload(
        network_object* network,
        const char* file_name,
        uint64_t ttl,
        const session_upload_callbacks* callbacks,
        int64_t stall_timeout_ms,
        int64_t request_timeout_ms,
        int64_t overall_timeout_ms,
        int8_t desired_path_index);

/// API: file_server/session_network_download
///
/// Initiates a streaming download.
///
/// The download will call on_data() as chunks arrive (for lokinet) or once with all data
/// (for onion requests).
///
/// Inputs:
/// - `network` -- [in] network object
/// - `download_url` -- [in] url to download data from (null-terminated)
/// - `callbacks` -- [in] callbacks for data receipt and completion
/// - `stall_timeout_ms` -- [in] timeout if no progress for this duration
/// - `request_timeout_ms` -- [in] timeout for the request itself
/// - `overall_timeout_ms` -- [in] timeout including pre-flight operations (0 to ignore)
/// - `partial_min_interval_ms` -- [in] minimum interval between on_data calls (default 250ms)
///
/// Returns: handle to the download, or NULL on error. Caller must free with session_download_free()
LIBSESSION_EXPORT session_download_handle_t* session_network_download(
        network_object* network,
        const char* download_url,
        const session_download_callbacks* callbacks,
        int64_t stall_timeout_ms,
        int64_t request_timeout_ms,
        int64_t overall_timeout_ms,
        int64_t partial_min_interval_ms,
        int8_t desired_path_index);

/// Cancels an in-progress upload
LIBSESSION_EXPORT void session_network_upload_cancel(session_upload_handle_t* handle);

/// Cancels an in-progress download
LIBSESSION_EXPORT void session_network_download_cancel(session_download_handle_t* handle);

/// Frees an upload handle (safe to call after completion or cancellation)
LIBSESSION_EXPORT void session_network_upload_free(session_upload_handle_t* handle);

/// Frees a download handle (safe to call after completion or cancellation)
LIBSESSION_EXPORT void session_network_download_free(session_download_handle_t* handle);

#ifdef __cplusplus
}
#endif
