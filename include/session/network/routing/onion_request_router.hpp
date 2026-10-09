#pragma once

#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "session/network/backends/session_file_server.hpp"
#include "session/network/request_queue.hpp"
#include "session/network/routing/network_router.hpp"
#include "session/network/snode_pool.hpp"

namespace session::network {

namespace config {
    struct OnionRequestRouter {
        FileServer file_server_config;
        std::optional<std::filesystem::path> cache_directory;
        std::chrono::days edge_node_cache_duration;

        opt::netid::Target netid;
        std::vector<service_node> seed_nodes;

        network::opt::retry_delay retry_delay;

        uint8_t path_length;
        uint8_t path_strike_threshold;
        uint8_t path_build_retry_limit;
        std::chrono::minutes path_rotation_frequency;
        uint8_t node_strike_threshold;
        bool disable_pre_build_paths;
        bool single_path_mode;
        std::unordered_map<PathCategory, uint8_t> min_path_counts;
    };
}  // namespace config

struct cached_edge_node {
    service_node node;
    std::chrono::system_clock::time_point first_connected_at;

    template <typename OutputIt>
    void to_disk(OutputIt out) const {
        auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                 first_connected_at.time_since_epoch())
                                 .count();

        fmt::format_to(
                out,
                "{}|{}|{}|{}|{}.{}.{}|{}|{}\n",
                node.remote_pubkey.hex(),
                node.host(),
                node.https_port,
                node.omq_port,
                node.storage_server_version[0],
                node.storage_server_version[1],
                node.storage_server_version[2],
                node.swarm_id,
                timestamp);
    }

    static cached_edge_node from_disk(std::string_view str);
};

namespace cached_edge_node_disk_format {
    constexpr size_t TIMESTAMP = 10;  // unix timestamp

    constexpr size_t MAX_LINE_SIZE = service_node_disk_format::MAX_LINE_SIZE + TIMESTAMP;
}  // namespace cached_edge_node_disk_format

struct OnionPath {
    std::string id;
    std::vector<service_node> nodes;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point edge_first_connected_at;

    size_t active_requests = 0;
    uint16_t strike_count = 0;
    bool rotation_in_progress = false;

    std::string to_string() const;
};

struct PendingRotation {
    std::string old_path_id;
    PathCategory category;
    OnionPath new_path;
};

inline PathCategory to_path_category(RequestCategory category) {
    switch (category) {
        case RequestCategory::standard: return PathCategory::standard;
        case RequestCategory::standard_small: return PathCategory::standard;
        case RequestCategory::file: return PathCategory::file;
        case RequestCategory::file_small: return PathCategory::file;
    }
    return PathCategory::standard;  // Should not be reached
}

class OnionRequestRouter : public IRouter, public std::enable_shared_from_this<OnionRequestRouter> {
  private:
    friend class TestOnionRequestRouter;

    bool _ready = false;
    bool _suspended = false;
    config::OnionRequestRouter _config;
    std::shared_ptr<oxen::quic::Loop> _loop;
    std::shared_ptr<oxen::quic::Loop> _disk_loop;
    std::weak_ptr<SnodePool> _snode_pool;
    std::weak_ptr<ITransport> _transport;

    std::vector<cached_edge_node> _cached_edge_nodes;
    std::unordered_map<PathCategory, std::vector<OnionPath>> _paths;
    std::unordered_map<PathCategory, std::vector<OnionPath>> _paths_pending_drop;
    std::unordered_map<PathCategory, std::shared_ptr<detail::RequestQueue>> _request_queues;
    std::unordered_map<std::string, std::pair<UploadRequest, std::thread>> _active_uploads;
    std::unordered_map<std::string, DownloadRequest> _active_downloads;

    oxen::quic::event_ptr _path_rotation_timer;
    std::unordered_map<PathCategory, int> _in_progress_path_builds;
    std::unordered_map<std::string, int> _path_build_retries;
    std::unordered_map<
            std::string,
            std::pair<
                    std::vector<service_node>,
                    std::optional<std::chrono::system_clock::time_point>>>
            _pending_paths;
    std::multimap<std::chrono::steady_clock::time_point, std::pair<std::string, PathCategory>>
            _path_rotation_schedule;
    std::unordered_map<std::string, PendingRotation> _pending_rotation_paths;

    // Disk I/O
    std::filesystem::path _edge_node_cache_file_path;

  public:
    OnionRequestRouter(
            config::OnionRequestRouter config,
            std::shared_ptr<oxen::quic::Loop> loop,
            std::shared_ptr<oxen::quic::Loop> disk_loop,
            std::weak_ptr<SnodePool> snode_pool,
            std::weak_ptr<ITransport> transport);
    ~OnionRequestRouter() override;

    void suspend() override;
    void resume(bool automatically_reconnect = true) override;
    void close_connections() override;
    void clear_cache() override;

    ConnectionStatus get_status() const override { return _status.load(); };
    std::vector<PathInfo> get_active_paths() override;
    std::vector<service_node> get_all_used_nodes() override;
    void send_request(Request request, network_response_callback_t callback) override;
    void upload(UploadRequest request) override;
    void download(DownloadRequest request) override;

  private:
    std::atomic<ConnectionStatus> _status{ConnectionStatus::unknown};

    // Disk I/O functions
    void _load_from_disk();
    static void _clear_disk_cache(const std::filesystem::path& file_path);
    static void _perform_edge_node_write(
            const std::filesystem::path& file_path, std::span<const cached_edge_node> edge_nodes);

    // All of the below functions should only be called from within `_loop`
    void _finish_setup();
    void _pre_build_paths_if_needed();
    void _drop_struck_cached_edge_nodes();
    void _close_connections();
    void _update_status();
    void _send_request_internal(Request request, network_response_callback_t callback);
    void _upload_internal(UploadRequest request);
    void _download_internal(DownloadRequest request);

    void _build_path(
            PathCategory category,
            std::optional<std::string> initiating_req_id,
            const std::vector<service_node>& nodes_to_exclude,
            std::optional<std::string> original_path_id = std::nullopt,
            std::optional<service_node> specific_edge_node = std::nullopt,
            std::optional<std::chrono::system_clock::time_point> edge_node_first_connection_at =
                    std::nullopt);
    void _on_edge_connectivity_response(
            const std::string& path_id,
            PathCategory category,
            std::optional<std::string> initiating_req_id,
            bool success,
            std::optional<uint64_t> error_code);

    OnionPath* _find_valid_path(const Request& request);

    void _send_on_path(OnionPath& path, Request request, network_response_callback_t callback);
    void _handle_transport_response(
            std::string path_id,
            Request original_request,
            bool success,
            bool timeout,
            int16_t status_code,
            std::vector<std::pair<std::string, std::string>> headers,
            std::optional<std::string> decrypted_body,
            network_response_callback_t callback);

    void _decrement_and_cleanup_path(const std::string& path_id, PathCategory category);
    void _handle_path_failure(
            const std::string& path_id,
            const PathCategory& category,
            const std::unordered_set<ed25519_pubkey>& already_penalized_nodes);
    void _try_repair_path(
            const std::string& path_id,
            const PathCategory& category,
            const ed25519_pubkey& bad_node_pubkey);

    void _schedule_path_rotation(
            const std::string& path_id,
            PathCategory category,
            std::chrono::steady_clock::time_point rotate_at);
    void _check_path_rotations(std::optional<std::chrono::steady_clock::time_point> now);
    void _update_rotation_timer();
    void _rotate_path(const std::string& path_id, PathCategory category);
    void _on_rotation_verification_response(
            const std::string& new_path_id,
            bool success,
            bool timeout,
            int16_t status_code,
            std::chrono::steady_clock::time_point rotate_at);
};

}  // namespace session::network
