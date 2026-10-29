#pragma once

#include <filesystem>
#include <limits>
#include <optional>
#include <oxen/quic.hpp>
#include <span>

#include "session/clock.hpp"
#include "session/network/backends/session_file_server.hpp"
#include "session/network/network_config.hpp"
#include "session/network/routing/network_router.hpp"
#include "session/network/snode_pool.hpp"
#include "session/network/transport/network_transport.hpp"
#include "session/platform.hpp"
#include "session/types.hpp"

namespace session {
class TestHelper;
}

namespace session::network {

namespace detail {
    class RequestQueue;

    /// The offset a clock resync applies, given what each of its requests measured (nullopt for
    /// one that failed): the median of the measurements, or zero when that is smaller than
    /// `min_offset` in either direction.  nullopt when every request failed, which leaves the
    /// current offset in place.
    std::optional<std::chrono::milliseconds> resync_offset(
            std::span<const std::optional<std::chrono::milliseconds>> measured,
            std::chrono::milliseconds min_offset);
}  // namespace detail

namespace fs = std::filesystem;  // NOLINT(misc-unused-alias-decls)

/// Owns the loops everything below it runs on, and is itself singly owned: a Network is held by one
/// `unique_ptr` and nothing else, so no callback can keep it alive and its destructor always runs
/// on whichever thread its owner drops it from.  That is what lets it join the loop threads at the
/// end of ~Network -- joining them from a callback of their own would abort.
class Network {
    friend class session::TestHelper;  // for unit tests: see _set_router

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

    /// The owner's, fixed at construction; see NetworkHooks.  Only ever read on the loop.  The
    /// destructor empties them, on the loop, before tearing anything down.
    NetworkHooks _hooks;

    /// Our own jobs, rather than the loop's shared queue, so that ~Network can take them away from
    /// the loop: `stop()` waits out whatever is running and cancels the rest.  Together with the
    /// components below being destroyed before it is stopped, that is what lets every job and
    /// callback here capture `this` bare.
    ///
    /// Declared last so that it is also the first member destroyed.  Held in an optional because
    /// the loop it runs on is created in the constructor body -- after the file-descriptor limit
    /// has been raised, which has to come first -- rather than in the initialiser list.
    std::optional<oxen::quic::JobQueue> _jq;

  public:
    const config::FileServer file_server_config;

    template <typename... Opt>
        requires(!std::is_same_v<
                 std::decay_t<std::tuple_element_t<0, std::tuple<Opt...>>>,
                 config::Config>)
    Network(Opt&&... opts) : Network{config::Config{std::forward<Opt>(opts)...}} {};
    explicit Network(config::Config config, NetworkHooks hooks = {});
    virtual ~Network();

    bool has_retrieved_time_offset() const {
        return (_last_successful_clock_resync != std::chrono::steady_clock::time_point{});
    };
    std::chrono::milliseconds network_time_offset() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(AdjustedClock::get_offset());
    };
    fork_versions fork() const { return _fork_versions.load(); };
    uint16_t hardfork() const { return _fork_versions.load().hardfork; };
    uint16_t softfork() const { return _fork_versions.load().softfork; };

    /// Whether a storage server can push to us on this network, i.e. whether the `server_push` hook
    /// can ever fire and a subscription is worth making.
    ///
    /// False for onion requests, and not as a matter of it being unimplemented: the storage server
    /// keys a subscription to the connection the request arrived on, which for an onion request is
    /// the last relay's rather than ours, so subscribing over one would register a relay as the
    /// subscriber.  Anything relying on pushed messages has to keep polling in that mode.
    bool supports_server_push() const { return config.router != opt::router::Type::onion_requests; }

    /// How requests reach their destination on this network.
    opt::router::Type router() const { return config.router; }

    void suspend();
    void resume(bool automatically_reconnect = true);
    void close_connections();
    void clear_cache();

    ConnectionStatus get_status();
    /// The route traffic to `node` is taking right now, for showing a user where it goes.  A
    /// snapshot rather than a commitment; see IRouter::get_path_to.
    std::optional<PathInfo> get_path_to(const service_node& node);

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
    ///   the callback will be called with an empty list).  The order of items in the swarm vector
    ///   will be shuffled (but may prioritize some nodes over others depend on observed past
    ///   behaviour; see SnodePool::get_swarm).
    virtual void get_swarm(
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

    virtual void send_request(Request request, network_response_callback_t callback);
    [[deprecated("use upload_file() instead")]]
    void upload(UploadRequest request);
    virtual void upload_file(FileUploadRequest request, std::span<const std::byte> seed);
    virtual void download(DownloadRequest request);

  private:
    std::atomic<ConnectionStatus> _status{ConnectionStatus::unknown};
    std::atomic<fork_versions> _fork_versions{{0, 0}};

    void configure();

    void _close_connections();
    void _recalculate_status();
    void _update_status(ConnectionStatus new_status);
    void _update_network_state(const std::string& body);
    // Writes the swarm a 421 reported into the cache.  Does not retry: choosing another member is
    // the caller's, since only the caller can know which node it ended up talking to.
    void _adopt_swarm_from_421(const x25519_pubkey& swarm_pubkey, std::string_view body);

    void _resync_clock(
            std::optional<Request> original_request, network_response_callback_t request_callback);
    void _launch_next_clock_out_of_sync_request(
            const std::string& request_id,
            const uint8_t index,
            const service_node& node,
            const uint8_t total_requests);
    void _on_clock_resync_complete(const uint8_t total_requests);

    Request _preprocess_request(Request request);
};

}  // namespace session::network
