#pragma once

#include <filesystem>
#include <limits>
#include <optional>
#include <oxen/quic.hpp>

#include "session/network/backends/session_file_server.hpp"
#include "session/network/network_config.hpp"
#include "session/network/routing/network_router.hpp"
#include "session/network/snode_pool.hpp"
#include "session/network/transport/network_transport.hpp"
#include "session/platform.hpp"
#include "session/types.hpp"

namespace session::network {

namespace detail {
    class RequestQueue;
}

namespace fs = std::filesystem;  // NOLINT(misc-unused-alias-decls)

class Network : public std::enable_shared_from_this<Network> {
  private:
    const config::Config config;
    std::shared_ptr<oxen::quic::Loop> _loop;  // Main loop for network events and syncronization
    std::shared_ptr<oxen::quic::Loop> _disk_loop;  // Auxiliary loop for blocking I/O
    std::shared_ptr<SnodePool> _snode_pool;
    std::shared_ptr<ITransport> _transport;
    std::shared_ptr<IRouter> _router;
    bool _suspended = false;

    std::chrono::steady_clock::time_point _last_successful_clock_resync;
    std::optional<std::string> _current_clock_resync_id;
    std::vector<std::optional<std::chrono::milliseconds>> _clock_resync_results;
    std::shared_ptr<detail::RequestQueue> _clock_resync_request_queue;
    std::shared_ptr<std::vector<std::pair<
            DownloadRequest,
            std::function<void(std::variant<file_metadata, int16_t>, bool)>>>>
            _clock_resync_download_queue;

  public:
    const config::FileServer file_server_config;

    // Hook to be notified whenever the network connection status changes.
    std::function<void(ConnectionStatus status)> on_status_changed;
    std::function<void(std::chrono::milliseconds network_time_offset, int hardfork, int softfork)>
            on_network_info_changed;

    template <typename... Opt>
        requires(!std::is_same_v<
                 std::decay_t<std::tuple_element_t<0, std::tuple<Opt...>>>,
                 config::Config>)
    Network(Opt&&... opts) : Network(Config(std::forward<Opt>(opts)...)){};
    explicit Network(config::Config config);
    virtual ~Network();

    bool has_retrieved_time_offset() const {
        return (_last_successful_clock_resync == std::chrono::steady_clock::time_point{});
    };
    std::chrono::milliseconds network_time_offset() const { return _network_time_offset; };
    fork_versions fork() const { return _fork_versions.load(); };
    uint16_t hardfork() const { return _fork_versions.load().hardfork; };
    uint16_t softfork() const { return _fork_versions.load().softfork; };

    void suspend();
    void resume(bool automatically_reconnect = true);
    void close_connections();
    void clear_cache();

    ConnectionStatus get_status();
    std::vector<PathInfo> get_active_paths();

    /// API: network/get_swarm
    ///
    /// Retrieves the swarm for the given pubkey.  If there is already an entry in the cache for the
    /// swarm then that will be returned, otherwise a network request will be made to retrieve the
    /// swarm and save it to the cache.
    ///
    /// Inputs:
    /// - 'swarm_pubkey' - [in] public key for the swarm.
    /// - 'ignore_strike_count' - [in] flag indicating whether node strikes should be ignored when
    /// retrieving the swarm.
    /// - 'callback' - [in] callback to be called with the retrieved swarm (in the case of an error
    /// the callback will be called with an empty list).
    void get_swarm(
            session::network::x25519_pubkey swarm_pubkey,
            bool ignore_strike_count,
            std::function<void(swarm_id_t swarm_id, std::vector<service_node> swarm)> callback);

    /// API: network/get_random_nodes
    ///
    /// Retrieves a number of random nodes from the snode pool.  If the are no nodes in the pool a
    /// new pool will be populated and the nodes will be retrieved from that.
    ///
    /// Inputs:
    /// - 'count' - [in] the number of nodes to retrieve.
    /// - 'callback' - [in] callback to be called with the retrieved nodes (in the case of an error
    /// the callback will be called with an empty list).
    void get_random_nodes(
            uint16_t count, std::function<void(std::vector<service_node> nodes)> callback);

    void send_request(Request request, network_response_callback_t callback);
    void upload(UploadRequest request);
    void download(DownloadRequest request);

  private:
    std::atomic<ConnectionStatus> _status{ConnectionStatus::unknown};
    std::atomic<std::chrono::milliseconds> _network_time_offset{0ms};
    std::atomic<fork_versions> _fork_versions{{0, 0}};

    void configure();

    void _close_connections();
    void _recalculate_status();
    void _update_status(ConnectionStatus new_status);
    void _update_network_state(const nlohmann::json& json);

    // An account's redirect is left empty where there was none to take.
    response::swarm_rejections _take_swarm_redirects(
            const Request& request, const nlohmann::json* json, int16_t status_code);
    void _refresh_if_unredirected(const response::swarm_rejections& rejections);
    void _handle_421_retry(
            Request original_request,
            response::swarm_rejections rejections,
            std::vector<std::pair<std::string, std::string>> headers,
            std::optional<std::string> body,
            network_response_callback_t final_callback);

    void _resync_clock(
            std::optional<Request> original_request, network_response_callback_t request_callback);
    void _launch_next_clock_out_of_sync_request(
            const std::string& request_id,
            const uint8_t index,
            const service_node& node,
            const uint8_t total_requests);
    void _on_clock_resync_complete();

    Request _preprocess_request(Request request);
};

}  // namespace session::network
