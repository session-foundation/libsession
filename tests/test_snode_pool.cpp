#include <catch2/catch_test_macros.hpp>
#include <session/network/snode_pool.hpp>
#include <thread>

#include "utils.hpp"

using namespace session;
using namespace session::network;

namespace session::network {

class TestSnodePool : public SnodePool {
  public:
    std::optional<std::vector<service_node>> mock_unused_nodes;

    TestSnodePool(
            config::SnodePool config,
            std::shared_ptr<oxen::quic::Loop> loop,
            std::shared_ptr<oxen::quic::Loop> disk_loop,
            network_fetcher_t direct_fetcher = [](Request, network_response_callback_t) {}) :
            SnodePool(
                    std::move(config),
                    std::move(loop),
                    std::move(disk_loop),
                    std::move(direct_fetcher)) {}

    void reset_state_with_cache(std::vector<service_node> cache) {
        _loop->call_get([this, cache] {
            _snode_cache = cache;
            _snode_strikes.clear();
        });
    }

    // How often the pool was asked to check whether it needs refreshing; read it only after a
    // loop job has run, since the checks are scheduled onto the loop
    int refresh_checks = 0;

    void refresh_if_needed(
            const std::vector<service_node>& /*in_use_nodes*/,
            refresh_callback_t /*on_refresh_complete*/ = nullptr) override {
        // Don't trigger a cache refresh
        ++refresh_checks;
    }

    void debug_queue_post_refresh_callback(refresh_callback_t cb) {
        _loop->call_get([this, cb = std::move(cb)]() mutable {
            _after_snode_cache_refresh.push_back(std::move(cb));
        });
    }

    // Removes the spare capacity from the pending-callback vector, so that a callback registering
    // another callback while they're being run is *guaranteed* to reallocate the vector.  Without
    // this the re-registration can land in spare capacity, nothing reallocates, and iterating the
    // vector by reference stays accidentally valid - which is exactly why the real crash only
    // showed up on some launches.
    //
    // Copy-then-move-back rather than `shrink_to_fit`, which is only a hint the stdlib may ignore
    // outright.  The move-assign is required to take over the copy's buffer, so we inherit the
    // copy's capacity - but that is only guaranteed to be *at least* `size()`, so this is still
    // best-effort.  The return value is what actually makes it safe: it confirms the capacity
    // really is tight rather than letting the test quietly stop exercising the bug.
    bool debug_remove_post_refresh_callback_spare_capacity() {
        return _loop->call_get([this] {
            auto exact_sized_copy = _after_snode_cache_refresh;
            _after_snode_cache_refresh = std::move(exact_sized_copy);
            return _after_snode_cache_refresh.capacity() == _after_snode_cache_refresh.size();
        });
    }

    size_t pending_post_refresh_callbacks() {
        return _loop->call_get([this] { return _after_snode_cache_refresh.size(); });
    }

    // Called from the test thread, so this also covers `_update_cache` being entered from off the
    // loop thread
    void update_cache(std::vector<service_node> nodes) { _update_cache("test", std::move(nodes)); }

    bool debug_refresh_in_progress() {
        return _loop->call_get([this] { return _current_snode_cache_refresh_id.has_value(); });
    }

    void debug_start_refresh() {
        _loop->call_get([this] { _refresh_snode_cache(); });
    }

    std::optional<std::string> debug_refresh_id() {
        return _loop->call_get([this] { return _current_snode_cache_refresh_id; });
    }

    size_t debug_refresh_candidate_count() {
        return _loop->call_get([this] { return _refresh_candidate_nodes.size(); });
    }

    void debug_clear_refresh_candidates() {
        _loop->call_get([this] { _refresh_candidate_nodes.clear(); });
    }

    int debug_refresh_failure_count() {
        return _loop->call_get([this] { return _snode_cache_refresh_failure_count; });
    }

    void debug_set_refresh_failure_count(int count) {
        _loop->call_get([this, count] { _snode_cache_refresh_failure_count = count; });
    }

    // Launches one of the refresh `request_id`'s fetches, as its retries do
    void debug_launch_refresh_request(const std::string& request_id) {
        _loop->call_get([this, request_id] {
            _launch_next_refresh_request(request_id, 0, false, true, 1);
        });
    }

    // Backdates the pool snapshot so the age-based policies can be exercised without waiting
    void debug_age_pool(std::chrono::seconds by) {
        _loop->call_get([this, by] { _last_snode_cache_update -= by; });
    }

    void debug_age_evidence_refresh(std::chrono::seconds by) {
        _loop->call_get([this, by] { _last_evidence_refresh -= by; });
    }

    std::chrono::seconds debug_evidence_backoff() {
        return _loop->call_get([this] { return _evidence_refresh_backoff; });
    }

    // Runs `fn` on the loop thread, which is what makes `get_swarm` / `invalidate_swarm` resolve
    // inline rather than being queued: a test observing them from off the loop has no ordering
    // guarantee at all
    void debug_run_on_loop(std::function<void()> fn) {
        _loop->call_get([fn = std::move(fn)] { fn(); });
    }

    // Backdates every recorded strike so `STRIKE_EXPIRY` can be crossed without a 48h wait
    void debug_age_strikes(std::chrono::seconds by) {
        _loop->call_get([this, by] {
            for (auto& [key, stamps] : _snode_strikes)
                for (auto& stamp : stamps)
                    stamp -= by;
        });
    }

    // Every strike on record, expired or not - which is what the decision sites used to count
    size_t debug_recorded_strikes(const ed25519_pubkey& key) {
        return _loop->call_get([this, &key] {
            auto it = _snode_strikes.find(key);
            return (it == _snode_strikes.end() ? size_t{0} : it->second.size());
        });
    }

    // Reaches past the no-op override above to the real age-based policy, on the loop thread so it
    // resolves inline
    void debug_refresh_if_needed(refresh_callback_t cb) {
        _loop->call_get([this, cb = std::move(cb)]() mutable {
            SnodePool::refresh_if_needed({}, std::move(cb));
        });
    }

    void debug_on_refresh_complete(std::vector<std::vector<std::byte>> raw_results) {
        auto total_requests = static_cast<uint8_t>(raw_results.size());
        _loop->call_get([&] {
            _on_refresh_complete("test", std::move(raw_results), false, true, total_requests);
        });
    }
};

// `TestSnodePool` stubs out `refresh_if_needed` so tests don't kick off real refreshes; the swarm
// invalidation test needs the real age-based policy to compare against, so it uses this instead
class TestSnodePoolAgePolicy : public TestSnodePool {
  public:
    using TestSnodePool::TestSnodePool;

    void refresh_if_needed(
            const std::vector<service_node>& in_use_nodes,
            refresh_callback_t on_refresh_complete = nullptr) override {
        SnodePool::refresh_if_needed(in_use_nodes, std::move(on_refresh_complete));
    }
};

// Encodes nodes the way the storage server returns them, so they can be fed to
// `_on_refresh_complete`: 51 bytes per node, all multi-byte fields big-endian
std::vector<std::byte> to_snode_cache_bin(const std::vector<service_node>& nodes) {
    std::vector<std::byte> result;
    result.reserve(nodes.size() * 51);

    auto append = [&result](uint64_t value, size_t bytes) {
        for (size_t i = bytes; i-- > 0;)
            result.push_back(static_cast<std::byte>((value >> (i * 8)) & 0xff));
    };

    for (const auto& node : nodes) {
        for (auto byte : node.view_remote_key())
            result.push_back(static_cast<std::byte>(byte));

        append(node.swarm_id, 8);
        append(node.ip.addr, 4);
        append(node.https_port, 2);
        append(node.omq_port, 2);

        for (auto part : node.storage_server_version)
            append(part, 1);
    }

    return result;
}
}  // namespace session::network

TEST_CASE("Network", "[network][get_unused_nodes]") {
    session::network::config::SnodePool pool_config = {
            .cache_expiration = std::chrono::minutes{5},
            .cache_min_lifetime = std::chrono::minutes{5},
            .enforce_subnet_diversity = false,
            .retry_delay = network::opt::retry_delay{50ms, 200ms},
            .netid = opt::netid::Target::testnet,
            .cache_node_strike_threshold = 3};
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    auto ed_pk2 = "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hexbytes;
    auto ed_pk3 = "e17a692033200ae41350df9709754edde7343e2cf2f23e88f993319e0720e5e5"_hexbytes;
    auto ed_pk4 = "7b633fa6fb462b90db6f0f50384190ce7715e31b7aa93d87dbd7e94e33d4251f"_hexbytes;
    std::vector<service_node> snode_cache;
    std::vector<service_node> unused_nodes;

    for (uint16_t i = 0; i < 5; ++i) {
        snode_cache.emplace_back(service_node{
                ed25519_pubkey::from_bytes(ed_pk),
                oxen::quic::ipv4{"192.168.0.{}"_format(i)},
                static_cast<uint16_t>(20000 + i),
                static_cast<uint16_t>(30000 + i),
                {2, 11, 0},
                0});
        snode_cache.emplace_back(service_node{
                ed25519_pubkey::from_bytes(ed_pk2),
                oxen::quic::ipv4{"192.168.1.{}"_format(i)},
                static_cast<uint16_t>(20100 + i),
                static_cast<uint16_t>(30100 + i),
                {2, 11, 0},
                1});
        snode_cache.emplace_back(service_node{
                ed25519_pubkey::from_bytes(ed_pk3),
                oxen::quic::ipv4{"192.168.2.{}"_format(i)},
                static_cast<uint16_t>(20200 + i),
                static_cast<uint16_t>(30200 + i),
                {2, 11, 0},
                2});
        snode_cache.emplace_back(service_node{
                ed25519_pubkey::from_bytes(ed_pk4),
                oxen::quic::ipv4{"192.168.3.{}"_format(i)},
                static_cast<uint16_t>(20300 + i),
                static_cast<uint16_t>(30300 + i),
                {2, 11, 0},
                3});
    }
    std::sort(snode_cache.begin(), snode_cache.end());

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, loop, disk_loop);
    snode_pool->reset_state_with_cache(snode_cache);

    // Should return a result in a different order (since this is random, it's possible that it
    // could return the same order so repeat up to 5 times to make the chance of this negligible)
    snode_pool->reset_state_with_cache(snode_cache);
    auto results_differed = false;
    auto first_result = snode_pool->get_unused_nodes(20);

    for (auto i = 0; i < 5; ++i) {
        auto next_result = snode_pool->get_unused_nodes(20);

        if (next_result != first_result) {
            results_differed = true;
            break;
        }
    }
    INFO("get_unused_nodes() produced the same result 5 times in a row.");
    CHECK(results_differed);

    // Should contain the entire snode cache initially
    snode_pool->reset_state_with_cache(snode_cache);
    unused_nodes = snode_pool->get_unused_nodes(20);
    std::sort(unused_nodes.begin(), unused_nodes.end());
    CHECK(unused_nodes == snode_cache);

    // Should exclude nodes in the exclusion list
    snode_pool->reset_state_with_cache(snode_cache);
    std::vector<service_node> excluded(snode_cache.begin(), snode_cache.begin() + 10);
    std::vector<service_node> remaining(snode_cache.begin() + 10, snode_cache.end());
    unused_nodes = snode_pool->get_unused_nodes(24, excluded);
    std::sort(unused_nodes.begin(), unused_nodes.end());
    CHECK(unused_nodes == remaining);

    // Should exclude nodes which have passed the failure threshold
    snode_pool->reset_state_with_cache(snode_cache);
    for (uint16_t i = 0; i < 10; ++i) {
        snode_pool->record_node_failure(snode_cache[i], true);
    }
    unused_nodes = snode_pool->get_unused_nodes(10);
    std::sort(unused_nodes.begin(), unused_nodes.end());
    CHECK(unused_nodes == remaining);

    // ... but only once they have passed it: ordinary strikes below the threshold leave a node in
    // use (strikes are per pubkey, so these apply to every node sharing the struck node's key)
    snode_pool->reset_state_with_cache(snode_cache);
    auto struck_key = snode_cache[0].remote_pubkey;
    auto uses_struck_key = [&struck_key](const service_node& n) {
        return n.remote_pubkey == struck_key;
    };
    auto with_struck_key = std::ranges::count_if(snode_cache, uses_struck_key);

    snode_pool->record_node_failure(snode_cache[0]);
    snode_pool->record_node_failure(snode_cache[0]);
    CHECK(std::ranges::count_if(snode_pool->get_unused_nodes(20), uses_struck_key) ==
          with_struck_key);

    snode_pool->record_node_failure(snode_cache[0]);
    CHECK(std::ranges::none_of(snode_pool->get_unused_nodes(20), uses_struck_key));

    // Should exclude nodes which have the same subnet
    pool_config = {
            .cache_expiration = std::chrono::minutes{5},
            .cache_min_lifetime = std::chrono::minutes{5},
            .enforce_subnet_diversity = true,
            .retry_delay = network::opt::retry_delay{50ms, 200ms},
            .netid = opt::netid::Target::testnet,
            .cache_node_strike_threshold = 3};
    snode_pool = std::make_shared<TestSnodePool>(pool_config, loop, disk_loop);
    snode_pool->reset_state_with_cache(snode_cache);
    unused_nodes = snode_pool->get_unused_nodes(20);
    std::sort(unused_nodes.begin(), unused_nodes.end());
    CHECK(unused_nodes.size() == 4);

    std::set<oxen::quic::ipv4> result_subnets;
    for (const auto& node : unused_nodes)
        result_subnets.insert(node.ip.to_base(24));
    CHECK(result_subnets.size() == 4);
}

TEST_CASE("Network", "[network][update_cache]") {
    session::network::config::SnodePool pool_config = {
            .cache_expiration = 5min,
            .cache_min_lifetime = 5min,
            .enforce_subnet_diversity = false,
            .retry_delay = network::opt::retry_delay{50ms, 200ms},
            .netid = opt::netid::Target::testnet,
            .cache_node_strike_threshold = 3};
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    std::vector<service_node> snode_cache;

    for (uint16_t i = 0; i < 5; ++i)
        snode_cache.emplace_back(service_node{
                ed25519_pubkey::from_bytes(ed_pk),
                oxen::quic::ipv4{"192.168.0.{}"_format(i)},
                static_cast<uint16_t>(20000 + i),
                static_cast<uint16_t>(30000 + i),
                {2, 11, 0},
                0});

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, loop, disk_loop);

    // Should tolerate a post-refresh callback registering another post-refresh callback (which is
    // what a deferred `get_swarm` does when the refresh left the cache empty) rather than
    // invalidating the vector it's iterating
    std::vector<int> callbacks_run;
    snode_pool->debug_queue_post_refresh_callback([&](bool) {
        callbacks_run.push_back(0);
        snode_pool->debug_queue_post_refresh_callback([&](bool) { callbacks_run.push_back(3); });
    });
    snode_pool->debug_queue_post_refresh_callback([&](bool) { callbacks_run.push_back(1); });
    snode_pool->debug_queue_post_refresh_callback([&](bool) { callbacks_run.push_back(2); });
    REQUIRE(snode_pool->debug_remove_post_refresh_callback_spare_capacity());
    snode_pool->update_cache({});
    CHECK(callbacks_run == std::vector<int>{0, 1, 2});

    // The callback registered during the run should be kept for the next refresh, not discarded
    CHECK(snode_pool->pending_post_refresh_callbacks() == 1);
    snode_pool->update_cache({});
    CHECK(callbacks_run == std::vector<int>{0, 1, 2, 3});
    CHECK(snode_pool->pending_post_refresh_callbacks() == 0);

    // Should have stored the nodes by the time it returns
    snode_pool->update_cache(snode_cache);
    CHECK(snode_pool->size() == snode_cache.size());
}

TEST_CASE("Network", "[network][refresh_min_cache_size]") {
    session::network::config::SnodePool pool_config = {
            .cache_expiration = 5min,
            .cache_min_lifetime = 5min,
            .enforce_subnet_diversity = false,
            .retry_delay = network::opt::retry_delay{50ms, 200ms},
            .netid = opt::netid::Target::testnet,
            .cache_min_size = 12,
            .cache_node_strike_threshold = 3};
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    std::vector<service_node> snode_cache;

    for (uint16_t i = 0; i < 20; ++i)
        snode_cache.emplace_back(service_node{
                ed25519_pubkey::from_bytes(ed_pk),
                oxen::quic::ipv4{"192.168.0.{}"_format(i)},
                static_cast<uint16_t>(20000 + i),
                static_cast<uint16_t>(30000 + i),
                {2, 11, 0},
                0});

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, loop, disk_loop);
    snode_pool->reset_state_with_cache(snode_cache);
    REQUIRE(snode_pool->size() == 20);

    // The encoding needs to round-trip or the rest of this test proves nothing
    REQUIRE(service_node::process_snode_cache_bin(to_snode_cache_bin(snode_cache)).first ==
            snode_cache);

    // A refresh returning fewer than `cache_min_size` nodes should be discarded rather than
    // replacing the perfectly good cache we already have
    std::vector<service_node> too_few(snode_cache.begin(), snode_cache.begin() + 11);
    snode_pool->debug_on_refresh_complete({to_snode_cache_bin(too_few)});
    CHECK(snode_pool->size() == 20);

    // ... and an empty refresh likewise
    snode_pool->debug_on_refresh_complete({{}});
    CHECK(snode_pool->size() == 20);

    // A refresh with enough nodes should still replace it
    std::vector<service_node> enough(snode_cache.begin(), snode_cache.begin() + 12);
    snode_pool->debug_on_refresh_complete({to_snode_cache_bin(enough)});
    CHECK(snode_pool->size() == 12);
}

TEST_CASE("Network", "[network][invalidate_swarm]") {
    session::network::config::SnodePool pool_config{
            .cache_expiration = 2h,
            .cache_min_lifetime = 2s,
            .enforce_subnet_diversity = false,
            .retry_delay = network::opt::retry_delay{50ms, 200ms},
            .netid = opt::netid::Target::testnet,
            .cache_min_size = 12,
            .cache_min_swarm_size = 3,
            .cache_num_nodes_to_use_for_refresh = 1,
            .cache_min_num_refresh_presence_to_include_node = 1,
            .cache_node_strike_threshold = 3};

    auto ed_pk_before = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    auto ed_pk_after = "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hexbytes;

    // Two snapshots of the same two swarms, with an entirely different set of nodes serving them.
    // Which swarm the pubkey lands in doesn't matter; what matters is that the correct answer
    // changed and no node is common to both.
    auto pool_snapshot = [](const std::vector<unsigned char>& ed_pk, uint8_t subnet) {
        std::vector<service_node> nodes;

        for (uint16_t i = 0; i < 12; ++i)
            nodes.emplace_back(service_node{
                    ed25519_pubkey::from_bytes(ed_pk),
                    oxen::quic::ipv4{"192.168.{}.{}"_format(subnet, i)},
                    static_cast<uint16_t>(20000 + i),
                    static_cast<uint16_t>(30000 + i),
                    {2, 11, 0},
                    static_cast<uint64_t>(i < 6 ? 0 : 1)});

        return nodes;
    };
    auto nodes_before = pool_snapshot(ed_pk_before, 0);
    auto nodes_after = pool_snapshot(ed_pk_after, 1);

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePoolAgePolicy>(pool_config, loop, disk_loop);
    snode_pool->update_cache(nodes_before);
    snode_pool->debug_age_pool(10min);

    auto swarm_pubkey = x25519_pubkey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000");

    std::vector<service_node> rejected_swarm, recovered_swarm;
    bool age_policy_started_refresh = false, recovery_ran = false;

    snode_pool->debug_run_on_loop([&] {
        snode_pool->get_swarm(
                swarm_pubkey, true, [&](swarm::swarm_id_t, std::vector<service_node> nodes) {
                    rejected_swarm = std::move(nodes);
                });

        // Asking by age is what the 421 path used to do, and on a cache this far short of
        // `cache_expiration` it declines - which is what left the disproven mapping in place
        snode_pool->refresh_if_needed({});
        age_policy_started_refresh = snode_pool->debug_refresh_in_progress();

        snode_pool->invalidate_swarm(swarm_pubkey, [&](bool refreshed) {
            recovery_ran = true;
            CHECK(refreshed);
            snode_pool->get_swarm(
                    swarm_pubkey, true, [&](swarm::swarm_id_t, std::vector<service_node> nodes) {
                        recovered_swarm = std::move(nodes);
                    });
        });
    });

    REQUIRE_FALSE(rejected_swarm.empty());
    CHECK_FALSE(age_policy_started_refresh);

    // The rejection has to produce a refresh, and the retry has to wait for it rather than being
    // handed the answer that was just rejected
    REQUIRE(snode_pool->debug_refresh_in_progress());
    CHECK_FALSE(recovery_ran);

    snode_pool->update_cache(nodes_after);
    REQUIRE(recovery_ran);
    REQUIRE_FALSE(recovered_swarm.empty());

    for (const auto& node : recovered_swarm)
        CHECK(std::ranges::find(rejected_swarm, node) == rejected_swarm.end());

    // A rejection that arrives after we already refreshed on one has to be held off, or a node that
    // rejects everything keeps a client refreshing from three nodes forever
    CHECK(snode_pool->debug_evidence_backoff() == 1min);
    snode_pool->debug_age_pool(10min);
    snode_pool->debug_run_on_loop([&] { snode_pool->invalidate_swarm(swarm_pubkey); });
    CHECK_FALSE(snode_pool->debug_refresh_in_progress());

    // Once it has elapsed the next one runs, and the one after it waits twice as long again
    snode_pool->debug_age_evidence_refresh(90s);
    snode_pool->debug_run_on_loop([&] { snode_pool->invalidate_swarm(swarm_pubkey); });
    CHECK(snode_pool->debug_refresh_in_progress());
    CHECK(snode_pool->debug_evidence_backoff() == 2min);

    // Staying quiet for twice the interval means the next incident starts from the base delay
    // rather than inheriting an escalated one
    snode_pool->update_cache(nodes_after);
    snode_pool->debug_age_pool(10min);
    snode_pool->debug_age_evidence_refresh(10min);
    snode_pool->debug_run_on_loop([&] { snode_pool->invalidate_swarm(swarm_pubkey); });
    CHECK(snode_pool->debug_refresh_in_progress());
    CHECK(snode_pool->debug_evidence_backoff() == 1min);
}

TEST_CASE("Network", "[network][swarm_redirect]") {
    session::network::config::SnodePool pool_config{
            .cache_expiration = 2h,
            .cache_min_lifetime = 2s,
            .enforce_subnet_diversity = false,
            .retry_delay = network::opt::retry_delay{50ms, 200ms},
            .netid = opt::netid::Target::testnet,
            .cache_min_size = 12,
            .cache_min_swarm_size = 3,
            .cache_num_nodes_to_use_for_refresh = 1,
            .cache_min_num_refresh_presence_to_include_node = 1,
            .cache_node_strike_threshold = 3};

    // A redirect is resolved by node pubkey, so every node needs its own
    auto key_for = [](uint16_t i) {
        return ed25519_pubkey::from_hex(
                "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46a{:02x}"_format(i));
    };
    std::vector<service_node> snode_cache;

    for (uint16_t i = 0; i < 12; ++i)
        snode_cache.emplace_back(service_node{
                key_for(i),
                oxen::quic::ipv4{"192.168.0.{}"_format(i)},
                static_cast<uint16_t>(20000 + i),
                static_cast<uint16_t>(30000 + i),
                {2, 11, 0},
                static_cast<uint64_t>(i < 6 ? 0 : 1)});

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePoolAgePolicy>(pool_config, loop, disk_loop);
    snode_pool->update_cache(snode_cache);

    // Old enough that the fallback would refresh, so "no refresh happened" below means the redirect
    // was taken rather than the pool being too fresh to bother
    snode_pool->debug_age_pool(10min);

    auto swarm_pubkey = x25519_pubkey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000");

    std::vector<service_node> calculated;
    snode_pool->debug_run_on_loop([&] {
        snode_pool->get_swarm(
                swarm_pubkey, true, [&](swarm::swarm_id_t, std::vector<service_node> nodes) {
                    calculated = std::move(nodes);
                });
    });
    REQUIRE(calculated.size() == 6);

    // Everything the calculation didn't pick, which is what a real redirect would be naming
    std::vector<service_node> elsewhere;
    for (const auto& node : snode_cache)
        if (std::ranges::find(calculated, node) == calculated.end())
            elsewhere.push_back(node);
    REQUIRE(elsewhere.size() == 6);

    // Membership is the claim in every comparison below; the pool is reshuffled on each refresh and
    // a redirect is resolved in pool order, so neither side has an order worth asserting
    auto sorted = [](std::vector<service_node> nodes) {
        std::ranges::sort(nodes);
        return nodes;
    };
    auto keys_of = [](const std::vector<service_node>& nodes, size_t count) {
        std::vector<ed25519_pubkey> keys;
        for (size_t i = 0; i < count && i < nodes.size(); ++i)
            keys.push_back(nodes[i].remote_pubkey);
        return keys;
    };

    // Nodes we've never heard of can't redirect us anywhere - this is what stops a response putting
    // us in touch with something that isn't a registered service node
    CHECK_FALSE(snode_pool->record_swarm_redirect(swarm_pubkey, {key_for(200), key_for(201)}));

    auto current_swarm = [&] {
        std::vector<service_node> swarm;
        snode_pool->debug_run_on_loop([&] {
            snode_pool->get_swarm(
                    swarm_pubkey, true, [&](swarm::swarm_id_t, std::vector<service_node> nodes) {
                        swarm = std::move(nodes);
                    });
        });
        return sorted(std::move(swarm));
    };
    auto overridden = sorted(std::vector<service_node>(elsewhere.begin(), elsewhere.begin() + 4));

    // A usable redirect is taken, and - the point of all this - no pool refresh is started for it
    REQUIRE(snode_pool->record_swarm_redirect(swarm_pubkey, keys_of(elsewhere, 4)));
    CHECK_FALSE(snode_pool->debug_refresh_in_progress());
    CHECK(current_swarm() == overridden);
    CHECK_FALSE(snode_pool->debug_refresh_in_progress());

    // How the named swarm relates to the one we sent to says nothing, since swarms can be
    // rearranged any way at all: a node that has left the overridden swarm names its current
    // members, and one in it naming the calculated swarm is how a wrong redirect gets put right
    CHECK(snode_pool->record_swarm_redirect(swarm_pubkey, keys_of(elsewhere, 4)));
    CHECK(current_swarm() == overridden);
    CHECK(snode_pool->record_swarm_redirect(swarm_pubkey, keys_of(calculated, 6)));
    CHECK(current_swarm() == sorted(calculated));

    // Two sets of nodes that disagree, each redirecting to the other
    auto bounce = [&](int times) {
        for (int i = 0; i < times; ++i)
            REQUIRE(snode_pool->record_swarm_redirect(
                    swarm_pubkey, i % 2 == 0 ? keys_of(elsewhere, 4) : keys_of(calculated, 6)));
    };

    // Every redirect counts, but none is refused for it - refusing would only fail the request.
    // Up to the limit nothing else happens...
    bounce(5);
    CHECK(current_swarm() == overridden);
    CHECK_FALSE(snode_pool->debug_refresh_in_progress());

    // ... and past it the redirect is still followed, but also asks for a refresh, which the pool
    // being old enough lets start
    CHECK(snode_pool->record_swarm_redirect(swarm_pubkey, keys_of(calculated, 6)));
    CHECK(current_swarm() == sorted(calculated));
    CHECK(snode_pool->debug_refresh_in_progress());

    // A refreshed pool is ground truth again, so redirects correcting the old one are dropped
    REQUIRE(snode_pool->record_swarm_redirect(swarm_pubkey, keys_of(elsewhere, 4)));
    snode_pool->update_cache(snode_cache);
    CHECK(current_swarm() == sorted(calculated));

    // ... and the calculated swarm itself, or part of it, is followed like any other
    CHECK(snode_pool->record_swarm_redirect(swarm_pubkey, keys_of(calculated, 6)));
    CHECK(current_swarm() == sorted(calculated));
    auto remaining = std::vector<service_node>(calculated.begin() + 1, calculated.end());
    CHECK(snode_pool->record_swarm_redirect(swarm_pubkey, keys_of(remaining, 5)));
    CHECK(current_swarm() == sorted(remaining));

    // Past the limit with the refresh throttled - the pool was only just refreshed - redirects are
    // still followed, rather than leaving the account on a swarm already known to be wrong
    bounce(6);
    CHECK(snode_pool->record_swarm_redirect(swarm_pubkey, keys_of(elsewhere, 4)));
    CHECK(current_swarm() == overridden);
    CHECK_FALSE(snode_pool->debug_refresh_in_progress());

    // A redirect naming nodes we mostly haven't heard of is followed with the ones we have - they
    // are the right swarm, where the one we had just rejected us - and asks for the refresh that
    // can fill in the rest (from a fresh count, so the limit plays no part)
    snode_pool->update_cache(snode_cache);
    snode_pool->debug_age_pool(10min);
    snode_pool->debug_age_evidence_refresh(10min);
    auto partial = keys_of(elsewhere, 2);
    partial.push_back(key_for(200));
    partial.push_back(key_for(201));
    CHECK(snode_pool->record_swarm_redirect(swarm_pubkey, partial));
    CHECK(current_swarm() ==
          sorted(std::vector<service_node>(elsewhere.begin(), elsewhere.begin() + 2)));
    CHECK(snode_pool->debug_refresh_in_progress());

    // A redirect naming too few nodes to be a swarm asks for the refresh whether or not any of the
    // names were unknown.  One naming a single node we do know has no stale pool to explain it, and
    // is the only thing serving the account until a refresh drops it, so it is the case that most
    // wants one
    snode_pool->update_cache(snode_cache);
    snode_pool->debug_age_pool(10min);
    snode_pool->debug_age_evidence_refresh(10min);
    CHECK(snode_pool->record_swarm_redirect(swarm_pubkey, keys_of(elsewhere, 1)));
    CHECK(current_swarm() ==
          sorted(std::vector<service_node>(elsewhere.begin(), elsewhere.begin() + 1)));
    CHECK(snode_pool->debug_refresh_in_progress());
}

TEST_CASE("Network", "[network][get_swarm_checks_age]") {
    session::network::config::SnodePool pool_config{
            .cache_expiration = 2h,
            .cache_min_lifetime = 2s,
            .enforce_subnet_diversity = false,
            .retry_delay = network::opt::retry_delay{50ms, 200ms},
            .netid = opt::netid::Target::testnet,
            .cache_min_swarm_size = 3,
            .cache_node_strike_threshold = 3};

    std::vector<service_node> snode_cache;
    for (uint16_t i = 0; i < 6; ++i)
        snode_cache.emplace_back(service_node{
                ed25519_pubkey::from_hex(
                        "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46a{:02x}"_format(
                                i)),
                oxen::quic::ipv4{"192.168.0.{}"_format(i)},
                static_cast<uint16_t>(20000 + i),
                static_cast<uint16_t>(30000 + i),
                {2, 11, 0},
                static_cast<uint64_t>(i < 3 ? 0 : 1)});

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, loop, disk_loop);
    snode_pool->update_cache(snode_cache);

    auto swarm_pubkey = x25519_pubkey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000");

    // The check is scheduled onto the loop, so it has run by the time a later loop job does
    auto checks_for_one_get_swarm = [&] {
        snode_pool->debug_run_on_loop([&] {
            snode_pool->refresh_checks = 0;
            snode_pool->get_swarm(swarm_pubkey, true, [](auto, auto) {});
        });
        snode_pool->debug_run_on_loop([] {});
        return snode_pool->refresh_checks;
    };

    // Worked out from the pool and cached...
    CHECK(checks_for_one_get_swarm() == 1);

    // ... then answered from that cache, and from an override, each of which returns before the
    // swarm is worked out, and neither of which may skip checking whether the pool is stale
    CHECK(checks_for_one_get_swarm() == 1);

    std::vector<ed25519_pubkey> redirect;
    for (const auto& node : snode_cache)
        redirect.push_back(node.remote_pubkey);
    REQUIRE(snode_pool->record_swarm_redirect(swarm_pubkey, redirect));
    CHECK(checks_for_one_get_swarm() == 1);
}

TEST_CASE("Network", "[network][strike_expiry]") {
    session::network::config::SnodePool pool_config{
            .cache_expiration = 5min,
            .cache_min_lifetime = 5min,
            .enforce_subnet_diversity = false,
            .retry_delay = network::opt::retry_delay{50ms, 200ms},
            .netid = opt::netid::Target::testnet,
            .cache_min_size = 0,
            .cache_min_swarm_size = 0,
            .cache_num_nodes_to_use_for_refresh = 0,
            .cache_min_num_refresh_presence_to_include_node = 0,
            .cache_node_strike_threshold = 3};

    // Strikes are keyed by node pubkey, so these have to differ per node or striking one strikes
    // every node sharing its key
    std::vector<std::vector<unsigned char>> ed_pks{
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes,
            "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hexbytes,
            "e17a692033200ae41350df9709754edde7343e2cf2f23e88f993319e0720e5e5"_hexbytes,
            "7b633fa6fb462b90db6f0f50384190ce7715e31b7aa93d87dbd7e94e33d4251f"_hexbytes};
    std::vector<service_node> snode_cache;

    for (uint16_t i = 0; i < ed_pks.size(); ++i)
        snode_cache.emplace_back(service_node{
                ed25519_pubkey::from_bytes(ed_pks[i]),
                oxen::quic::ipv4{"192.168.0.{}"_format(i)},
                static_cast<uint16_t>(20000 + i),
                static_cast<uint16_t>(30000 + i),
                {2, 11, 0},
                0});

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, loop, disk_loop);
    snode_pool->reset_state_with_cache(snode_cache);

    snode_pool->record_node_failure(snode_cache[0], true);
    snode_pool->record_node_failure(snode_cache[1], true);
    REQUIRE(snode_pool->node_strike_count(snode_cache[0]) == 3);
    REQUIRE(snode_pool->get_unused_nodes(4).size() == 2);

    // Once the strikes are older than `STRIKE_EXPIRY` the node has to become selectable again; a
    // node dropped for a blip two days ago is not evidence about the node now
    snode_pool->debug_age_strikes(49h);
    CHECK(snode_pool->node_strike_count(snode_cache[0]) == 0);
    CHECK(snode_pool->get_unused_nodes(4).size() == 4);

    // ... and a fresh failure starts from one rather than stacking onto the expired ones, which is
    // also what stops the vector growing for the life of the process
    snode_pool->record_node_failure(snode_cache[0]);
    CHECK(snode_pool->node_strike_count(snode_cache[0]) == 1);
    CHECK(snode_pool->debug_recorded_strikes(snode_cache[0].remote_pubkey) == 1);
}

TEST_CASE("Network", "[network][refresh_callback_contract]") {
    session::network::config::SnodePool pool_config{
            .cache_expiration = 2h,
            .cache_min_lifetime = 2s,
            .enforce_subnet_diversity = false,
            .retry_delay = network::opt::retry_delay{50ms, 200ms},
            .netid = opt::netid::Target::testnet,
            .seed_nodes = {},
            .cache_min_size = 0,
            .cache_min_swarm_size = 0,
            .cache_num_nodes_to_use_for_refresh = 0,
            .cache_min_num_refresh_presence_to_include_node = 0,
            .cache_node_strike_threshold = 3};
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    std::vector<service_node> snode_cache;

    for (uint16_t i = 0; i < 5; ++i)
        snode_cache.emplace_back(service_node{
                ed25519_pubkey::from_bytes(ed_pk),
                oxen::quic::ipv4{"192.168.0.{}"_format(i)},
                static_cast<uint16_t>(20000 + i),
                static_cast<uint16_t>(30000 + i),
                {2, 11, 0},
                0});

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, loop, disk_loop);

    auto run = [&snode_pool] {
        std::pair<bool, bool> result{false, true};  // {called, refreshed}
        snode_pool->debug_refresh_if_needed(
                [&result](bool refreshed) { result = {true, refreshed}; });
        return result;
    };

    // An empty cache and no seed nodes means the refresh cannot even start.  The callback still has
    // to run: callers set state up before calling (`_resync_clock` sets its in-progress id) and
    // never hearing back leaves that set for the life of the process.
    auto [called, refreshed] = run();
    CHECK(called);
    CHECK_FALSE(refreshed);

    // Nothing needing a refresh is the answer the caller asked for, not a failure to get one
    snode_pool->update_cache(snode_cache);
    std::tie(called, refreshed) = run();
    CHECK(called);
    CHECK(refreshed);

    // ... and a suspended pool reports that it didn't refresh rather than going quiet
    snode_pool->suspend();
    std::tie(called, refreshed) = run();
    CHECK(called);
    CHECK_FALSE(refreshed);
}

TEST_CASE("Network", "[network][suspend_refresh]") {
    session::network::config::SnodePool pool_config{
            .cache_expiration = 2h,
            .cache_min_lifetime = 2s,
            .enforce_subnet_diversity = false,
            .retry_delay = network::opt::retry_delay{50ms, 200ms},
            .netid = opt::netid::Target::testnet,
            .cache_min_size = 1,
            .cache_min_swarm_size = 1,
            .cache_num_nodes_to_use_for_refresh = 1,
            .cache_min_num_refresh_presence_to_include_node = 1,
            .cache_node_strike_threshold = 3};

    std::vector<service_node> snode_cache;
    for (uint16_t i = 0; i < 4; ++i)
        snode_cache.emplace_back(service_node{
                ed25519_pubkey::from_hex(
                        "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46a{:02x}"_format(
                                i)),
                oxen::quic::ipv4{"192.168.0.{}"_format(i)},
                static_cast<uint16_t>(20000 + i),
                static_cast<uint16_t>(30000 + i),
                {2, 11, 0},
                0});

    // The default fetcher never answers, so a refresh stays in progress until the test ends it
    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, loop, disk_loop);
    snode_pool->update_cache(snode_cache);

    SECTION("Suspending abandons a refresh in progress, and answers what waits on it") {
        snode_pool->debug_start_refresh();
        REQUIRE(snode_pool->debug_refresh_in_progress());

        std::optional<bool> answer;
        snode_pool->debug_queue_post_refresh_callback(
                [&answer](bool refreshed) { answer = refreshed; });
        snode_pool->debug_set_refresh_failure_count(3);

        snode_pool->suspend();
        CHECK(answer == false);
        CHECK_FALSE(snode_pool->debug_refresh_in_progress());
        CHECK(snode_pool->debug_refresh_failure_count() == 0);
    }

    SECTION("A fetch belonging to an abandoned refresh leaves the next refresh alone") {
        snode_pool->debug_start_refresh();
        auto abandoned = snode_pool->debug_refresh_id();
        REQUIRE(abandoned);
        snode_pool->suspend();
        snode_pool->resume();

        snode_pool->debug_start_refresh();
        auto current = snode_pool->debug_refresh_id();
        REQUIRE(current);
        REQUIRE(current != abandoned);
        auto candidates = snode_pool->debug_refresh_candidate_count();

        snode_pool->debug_launch_refresh_request(*abandoned);
        CHECK(snode_pool->debug_refresh_id() == current);
        CHECK(snode_pool->debug_refresh_candidate_count() == candidates);
    }

    SECTION("An abandoned refresh's retry after running out of candidates restarts nothing") {
        // Running out schedules a retry of the whole refresh, after the retry delay
        auto run_out_then_suspend = [&] {
            snode_pool->debug_start_refresh();
            auto id = snode_pool->debug_refresh_id();
            REQUIRE(id);
            snode_pool->debug_clear_refresh_candidates();
            snode_pool->debug_launch_refresh_request(*id);
            snode_pool->suspend();
            snode_pool->resume();
        };
        auto past_retry_delay = [] { std::this_thread::sleep_for(500ms); };

        // Once it was the refresh that used to restart itself here
        run_out_then_suspend();
        past_retry_delay();
        CHECK_FALSE(snode_pool->debug_refresh_in_progress());

        // ... and with another refresh started by the time it fires, that one is left running
        run_out_then_suspend();
        snode_pool->debug_start_refresh();
        auto current = snode_pool->debug_refresh_id();
        REQUIRE(current);
        past_retry_delay();
        CHECK(snode_pool->debug_refresh_id() == current);
    }
}
