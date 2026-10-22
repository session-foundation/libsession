#pragma once

#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include "session/network/key_types.hpp"
#include "session/network/network_config.hpp"
#include "session/network/service_node.hpp"
#include "swarm.hpp"

namespace session {
class TestHelper;
}

namespace session::network {

namespace config {
    struct SnodePool {
        std::optional<std::filesystem::path> cache_directory;
        // A pool of the network `netid` names, which nothing checks (see
        // `opt::fallback_snode_pool_path`).
        std::optional<std::filesystem::path> fallback_snode_pool_path;
        std::chrono::minutes cache_expiration;
        std::chrono::milliseconds cache_min_lifetime;
        bool enforce_subnet_diversity;
        network::opt::retry_delay retry_delay;

        opt::netid::Target netid;
        std::vector<service_node> seed_nodes;

        size_t cache_min_size;
        size_t cache_min_swarm_size;
        uint8_t cache_num_nodes_to_use_for_refresh;
        uint8_t cache_min_num_refresh_presence_to_include_node;
        uint16_t cache_node_strike_threshold;

        /// Storage server version at or above which a swarm member is preferred, or nullopt to
        /// treat every member alike.
        ///
        /// Deliberately a version rather than a reason: what the version *means* belongs to
        /// whoever sets this, and this layer only has to order by it.
        std::optional<std::array<uint16_t, 3>> prefer_min_version;
    };
}  // namespace config

class empty_file_exception : public std::runtime_error {
  public:
    empty_file_exception() : std::runtime_error{"Empty file"} {}
};

class SnodePool : public std::enable_shared_from_this<SnodePool> {
    friend class session::TestHelper;  // for unit tests

  public:
    using network_fetcher_t = std::function<void(Request, network_response_callback_t)>;
    using fetcher_connectivity_check_t = std::function<bool()>;

    SnodePool(
            config::SnodePool config,
            oxen::quic::Loop& loop,
            oxen::quic::Loop& disk_loop,
            network_fetcher_t direct_fetcher);
    virtual ~SnodePool();

    void suspend();
    void resume();

    // Sets the network fetcher which should be used once the snode cache exists
    void set_routed_fetcher(
            network_fetcher_t routed_fetcher, fetcher_connectivity_check_t connectivity_check);

    // Returns the number of nodes currently in the pool
    size_t size();

    // Forcibly clears the cache from memory and disk
    void clear_cache();

    // Records that a specific node has failed a request
    virtual void record_node_failure(const service_node& node, bool permanent = false);
    virtual void record_node_failure(const ed25519_pubkey& key, bool permanent = false);
    uint16_t node_strike_count(const service_node& node);
    uint16_t node_strike_count(const ed25519_pubkey& key);
    void clear_node_strikes();

    // Checks if the pool is empty or stale and triggers a refresh if needed
    virtual void refresh_if_needed(
            const std::vector<service_node>& in_use_nodes,
            std::function<void()> on_refresh_complete = nullptr);

    virtual void get_swarm(
            session::network::x25519_pubkey swarm_pubkey,
            bool ignore_strike_count,
            std::function<void(swarm::swarm_id_t, std::vector<service_node>)> callback);

    /// Replaces the cached swarm for an account with one a storage server told us authoritatively,
    /// as a 421 body does.
    ///
    /// Overrides the locally computed membership, which is only as fresh as the snode cache
    /// (`cache_expiration`, hours) and is exactly what a 421 says was wrong.  The override lives
    /// until the next snode cache refresh recomputes everything.
    virtual void set_swarm(
            session::network::x25519_pubkey swarm_pubkey,
            swarm::swarm_id_t swarm_id,
            std::vector<service_node> nodes);

    virtual std::vector<service_node> get_unused_nodes(
            size_t count, const std::vector<service_node>& exclude = {});

  private:
    friend class TestSnodePool;

    bool _suspended = false;
    config::SnodePool _config;
    oxen::quic::Loop& _loop;
    // Only ever given jobs that capture what they need by value, so it needs no queue of its own.
    oxen::quic::Loop& _disk_loop;
    network_fetcher_t _direct_fetcher;
    std::optional<network_fetcher_t> _routed_fetcher;
    std::optional<fetcher_connectivity_check_t> _routed_fetcher_connectivity_check;

    // Data
    std::vector<service_node> _snode_cache;
    std::vector<std::pair<swarm::swarm_id_t, std::vector<service_node>>> _all_swarms;
    std::unordered_map<x25519_pubkey, std::pair<swarm::swarm_id_t, std::vector<service_node>>>
            _swarm_cache;
    std::map<ed25519_pubkey, std::vector<std::chrono::sys_seconds>> _snode_strikes;
    bool _strikes_flush_scheduled = false;

    // Disk I/O
    std::filesystem::path _snode_cache_file_path;
    std::filesystem::path _strikes_file_path;

    // Refresh logic
    std::chrono::system_clock::time_point _last_snode_cache_update;
    std::optional<std::string> _current_snode_cache_refresh_id;
    int _snode_cache_refresh_failure_count = 0;
    std::vector<service_node> _refresh_candidate_nodes;
    std::vector<std::vector<std::byte>> _snode_refresh_results;
    std::vector<std::function<void()>> _after_snode_cache_refresh;

    // Subnet diversity, when the cache holds enough usable nodes but too few distinct /24 subnets
    // to fill a request from them (see `get_unused_nodes`).  A refresh for it tries, in order,
    // stopping at the first that gives a pool to judge by:
    //  1. the seed nodes over the routed fetcher: authentic, since routing can only drop or delay a
    //     reply encrypted for them, and private, but blockable by the very nodes in doubt;
    //  2. the prepackaged pool, if it spans more subnets than the cache: trusted, but stale;
    //  3. the seed nodes directly: authentic, but they see the client's address.
    // A list from the seed nodes that is still too cramped is the network as it is, so diversity
    // then relaxes - sharing as few subnets as it can, and only until the next refresh - as it does
    // once every step has failed.
    enum class CacheSource : uint8_t { other, prepackaged, seed_nodes };
    enum class SubnetRefresh : uint8_t { none, routed, direct };
    CacheSource _cache_source = CacheSource::other;
    // A request came up short for subnets, and a refresh is wanted for it
    bool _subnet_shortfall = false;
    // The refresh in progress is for subnets, and which step
    SubnetRefresh _subnet_refresh = SubnetRefresh::none;
    // Steps already tried since a cache last came from anywhere but the prepackaged pool
    bool _routed_subnet_refresh_failed = false;
    bool _direct_subnet_refresh_failed = false;
    bool _subnet_diversity_relaxed = false;

    /// This pool's own jobs, rather than the loop's shared queue, so that ~SnodePool can take them
    /// away from the loop before anything is torn down: `stop()` waits out whatever is running and
    /// cancels the rest, including anything scheduled with call_later.  That is what lets the jobs
    /// capture `this` bare.
    ///
    /// Declared last so that it is also the first member destroyed.
    oxen::quic::JobQueue _jq{_loop};

    // Disk I/O functions
    void _load_from_disk();
    static void _clear_disk_cache(const std::filesystem::path& path);
    static void _perform_cache_write(
            const std::filesystem::path& path, const std::vector<service_node>& cache);
    static void _perform_strikes_write(
            const std::filesystem::path& path,
            const std::map<ed25519_pubkey, std::vector<std::chrono::sys_seconds>>& strikes);

    // Refresh functions
    void _refresh_snode_cache(std::optional<std::string> request_id = std::nullopt);
    void _run_after_refresh_callbacks();
    // The steps of a refresh for subnets (see `_cache_source`).  `_choose_subnet_refresh` picks
    // the next fetch, or returns false having ended the refresh without one;
    // `_subnet_refresh_failed` moves on from a fetch that got no usable pool.
    bool _choose_subnet_refresh(const std::string& request_id);
    void _subnet_refresh_failed(const std::string& request_id);
    bool _adopt_prepackaged_for_subnets(const std::string& request_id);
    void _relax_for_subnets(const std::string& request_id, std::string_view why);
    // The prepackaged pool at `fallback_snode_pool_path`, or nullopt if there is none or it cannot
    // be used
    std::optional<std::vector<service_node>> _load_fallback_pool(const std::string& request_id);
    // How many distinct /24 subnets the nodes without too many strikes span
    size_t _usable_subnet_count(const std::vector<service_node>& nodes) const;
    void _launch_next_refresh_request(
            const std::string& request_id,
            const uint8_t index,
            const bool refreshing_from_seed_nodes,
            const bool use_direct_fetcher,
            const uint8_t total_requests);
    void _retry_refresh_request(
            const std::string& request_id,
            const uint8_t index,
            const bool refreshing_from_seed_nodes,
            const bool use_direct_fetcher,
            const uint8_t total_requests);
    void _on_refresh_complete(
            std::string refresh_id,
            std::vector<std::vector<std::byte>> raw_results,
            const bool refreshing_from_seed_nodes,
            const bool use_direct_fetcher,
            const uint8_t total_requests);
    void _update_cache(std::string refresh_id, std::vector<service_node> nodes, CacheSource source);
};

}  // namespace session::network
