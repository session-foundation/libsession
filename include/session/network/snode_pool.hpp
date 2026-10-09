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

namespace session::network {

namespace config {
    struct SnodePool {
        std::optional<std::filesystem::path> cache_directory;
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
    };
}  // namespace config

class empty_file_exception : public std::runtime_error {
  public:
    empty_file_exception() : std::runtime_error{"Empty file"} {}
};

class SnodePool : public std::enable_shared_from_this<SnodePool> {
  public:
    using network_fetcher_t = std::function<void(Request, network_response_callback_t)>;

    // `refreshed` is false when the pool could not be refreshed at all - suspended, no candidate
    // nodes, no fetcher.  Callers that retry their work on this callback have to check it: without
    // it the only way to signal "that didn't happen" was to never call back, which leaves whatever
    // the caller set up beforehand set up forever.
    using refresh_callback_t = std::function<void(bool refreshed)>;
    using fetcher_connectivity_check_t = std::function<bool()>;

    SnodePool(
            config::SnodePool config,
            std::shared_ptr<oxen::quic::Loop> loop,
            std::shared_ptr<oxen::quic::Loop> disk_loop,
            network_fetcher_t direct_fetcher);
    ~SnodePool() = default;

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

    // Whether the node has collected enough unexpired strikes to be kept out of node selection.
    // Callers that pick a node by some other route - a cached one, say - need this to apply the
    // same bar `get_unused_nodes` does, rather than comparing a raw count to a threshold they'd
    // have to know about.
    virtual bool node_struck_out(const service_node& node);
    virtual bool node_struck_out(const ed25519_pubkey& key);
    void clear_node_strikes();

    // Checks if the pool is empty or stale and triggers a refresh if needed
    virtual void refresh_if_needed(
            const std::vector<service_node>& in_use_nodes,
            refresh_callback_t on_refresh_complete = nullptr);

    // Re-resolves `swarm_pubkey` after a node we believed was in its swarm has told us the account
    // isn't there.  Where `refresh_if_needed` decides on the cache's age, this decides on that
    // rejection, so a mapping we have direct proof is wrong can be replaced long before
    // `cache_expiration`.  `on_complete` runs once the swarm can be resolved again.
    virtual void invalidate_swarm(
            session::network::x25519_pubkey swarm_pubkey, refresh_callback_t on_complete = nullptr);

    // Records the swarm a node named when it rejected a request for `swarm_pubkey`, so the mapping
    // can be corrected without refreshing the whole pool - a swarm change would otherwise have
    // every client of that swarm fetch the full node list, where nothing made them before.
    //
    // Only the node pubkeys are taken from the response, and only ones that resolve against the
    // pool we fetched ourselves, so a redirect can reach registered service nodes we already know
    // and nothing else.  Returns false when the redirect is unusable, which is the caller's cue to
    // fall back to `invalidate_swarm`.
    virtual bool record_swarm_redirect(
            session::network::x25519_pubkey swarm_pubkey,
            const std::vector<ed25519_pubkey>& swarm_node_keys);

    virtual void get_swarm(
            session::network::x25519_pubkey swarm_pubkey,
            bool ignore_strike_count,
            std::function<void(swarm::swarm_id_t, std::vector<service_node>)> callback);

    virtual std::vector<service_node> get_unused_nodes(
            size_t count, const std::vector<service_node>& exclude = {});

  private:
    friend class TestSnodePool;

    bool _suspended = false;
    config::SnodePool _config;
    std::shared_ptr<oxen::quic::Loop> _loop;
    std::shared_ptr<oxen::quic::Loop> _disk_loop;
    network_fetcher_t _direct_fetcher;
    std::optional<network_fetcher_t> _routed_fetcher;
    std::optional<fetcher_connectivity_check_t> _routed_fetcher_connectivity_check;

    // Data
    std::vector<service_node> _snode_cache;
    std::vector<std::pair<swarm::swarm_id_t, std::vector<service_node>>> _all_swarms;
    std::unordered_map<x25519_pubkey, std::pair<swarm::swarm_id_t, std::vector<service_node>>>
            _swarm_cache;

    // Swarms a node has redirected us to, which `get_swarm` prefers over its own calculation.  Kept
    // apart from `_swarm_cache` deliberately: that is a memo of `_all_swarms` and stays one, where
    // these are claims from outside that outrank it until the pool is refreshed.  The count is the
    // account's redirects since that refresh, which past a limit also ask for the next one.
    std::unordered_map<x25519_pubkey, std::pair<std::vector<service_node>, uint8_t>>
            _swarm_overrides;
    std::map<ed25519_pubkey, std::vector<std::chrono::sys_seconds>> _snode_strikes;
    bool _strikes_flush_scheduled = false;

    // Disk I/O
    std::filesystem::path _snode_cache_file_path;
    std::filesystem::path _strikes_file_path;

    // Refresh logic
    std::chrono::system_clock::time_point _last_snode_cache_update;
    std::chrono::system_clock::time_point _last_evidence_refresh;
    std::chrono::seconds _evidence_refresh_backoff{0};
    std::optional<std::string> _current_snode_cache_refresh_id;
    int _snode_cache_refresh_failure_count = 0;
    std::vector<service_node> _refresh_candidate_nodes;
    std::vector<std::vector<std::byte>> _snode_refresh_results;
    std::vector<refresh_callback_t> _after_snode_cache_refresh;

    // Counts a node's strikes that haven't expired yet.  `record_node_failure` only appends, so the
    // raw vector answers a different question - every strike the node has ever collected.
    size_t _active_strike_count(const ed25519_pubkey& key) const;
    bool _node_struck_out(const ed25519_pubkey& key) const;

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
    void _update_cache(std::string refresh_id, std::vector<service_node> nodes);
    void _run_pending_refresh_callbacks(bool refreshed);
};

}  // namespace session::network
