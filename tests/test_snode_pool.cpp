#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <session/network/snode_pool.hpp>

#include "utils.hpp"

using namespace session;
using namespace session::network;

namespace session::network {

class TestSnodePool : public SnodePool {
  public:
    std::optional<std::vector<service_node>> mock_unused_nodes;

    TestSnodePool(
            config::SnodePool config,
            oxen::quic::Loop& loop,
            oxen::quic::Loop& disk_loop,
            network_fetcher_t direct_fetcher = [](Request, network_response_callback_t) {}) :
            SnodePool(std::move(config), loop, disk_loop, std::move(direct_fetcher)) {}

    void reset_state_with_cache(std::vector<service_node> cache) {
        _jq.call_get([this, cache] {
            _snode_cache = cache;
            _snode_strikes.clear();
        });
    }

    void refresh_if_needed(
            const std::vector<service_node>& /*in_use_nodes*/,
            std::function<void()> /*on_refresh_complete*/ = nullptr) override {
        // Do nothing (don't want to trigger a cache refresh)
    }

    void debug_queue_post_refresh_callback(std::function<void()> cb) {
        _jq.call_get([this, cb = std::move(cb)]() mutable {
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
        return _jq.call_get([this] {
            auto exact_sized_copy = _after_snode_cache_refresh;
            _after_snode_cache_refresh = std::move(exact_sized_copy);
            return _after_snode_cache_refresh.capacity() == _after_snode_cache_refresh.size();
        });
    }

    size_t pending_post_refresh_callbacks() {
        return _jq.call_get([this] { return _after_snode_cache_refresh.size(); });
    }

    // Called from the test thread, so this also covers `_update_cache` being entered from off the
    // loop thread
    void update_cache(std::vector<service_node> nodes) { _update_cache("test", std::move(nodes)); }

    // Puts a swarm straight into the cache so get_swarm answers from it rather than resolving one.
    void seed_swarm(const x25519_pubkey& pubkey, std::vector<service_node> nodes) {
        _jq.call_get([&] {
            _swarm_cache[pubkey] = {swarm::swarm_id_t{0}, std::move(nodes)};
            return 0;
        });
    }

    void debug_on_refresh_complete(std::vector<std::vector<std::byte>> raw_results) {
        auto total_requests = static_cast<uint8_t>(raw_results.size());
        _jq.call_get([&] {
            _on_refresh_complete("test", std::move(raw_results), false, true, total_requests);
        });
    }
};

// Encodes nodes the way the storage server returns them, so they can be fed to
// `_on_refresh_complete`: 51 bytes per node, all multi-byte fields big-endian
static std::vector<std::byte> to_snode_cache_bin(const std::vector<service_node>& nodes) {
    std::vector<std::byte> result;
    result.reserve(nodes.size() * 51);

    auto append = [&result](uint64_t value, size_t bytes) {
        for (size_t i = bytes; i-- > 0;)
            result.push_back(static_cast<std::byte>((value >> (i * 8)) & 0xff));
    };

    for (const auto& node : nodes) {
        for (auto byte : node.view_remote_key())
            result.push_back(byte);

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
            std::nullopt,
            std::nullopt,
            std::chrono::minutes{5},
            std::chrono::minutes{5},
            false,  // enforce_subnet_diversity
            network::opt::retry_delay{50ms, 200ms},
            opt::netid::Target::testnet,
            {},
            0,
            0,
            3,  // cache_node_strike_threshold
            false};
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hex_b;
    auto ed_pk2 = "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hex_b;
    auto ed_pk3 = "e17a692033200ae41350df9709754edde7343e2cf2f23e88f993319e0720e5e5"_hex_b;
    auto ed_pk4 = "7b633fa6fb462b90db6f0f50384190ce7715e31b7aa93d87dbd7e94e33d4251f"_hex_b;
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
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, *loop, *disk_loop);
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

    // Should exclude nodes which have the same subnet
    pool_config = {
            std::nullopt,
            std::nullopt,
            std::chrono::minutes{5},
            std::chrono::minutes{5},
            true,  // enforce_subnet_diversity
            network::opt::retry_delay{50ms, 200ms},
            opt::netid::Target::testnet,
            {},
            0,
            0,
            3,  // cache_node_strike_threshold
            false};
    snode_pool = std::make_shared<TestSnodePool>(pool_config, *loop, *disk_loop);
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
            std::nullopt,
            std::nullopt,
            5min,
            5min,
            false,  // enforce_subnet_diversity
            network::opt::retry_delay{50ms, 200ms},
            opt::netid::Target::testnet,
            {},
            0,
            0,
            3,  // cache_node_strike_threshold
            false};
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hex_b;
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
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, *loop, *disk_loop);

    // Should tolerate a post-refresh callback registering another post-refresh callback (which is
    // what a deferred `get_swarm` does when the refresh left the cache empty) rather than
    // invalidating the vector it's iterating
    std::vector<int> callbacks_run;
    snode_pool->debug_queue_post_refresh_callback([&] {
        callbacks_run.push_back(0);
        snode_pool->debug_queue_post_refresh_callback([&] { callbacks_run.push_back(3); });
    });
    snode_pool->debug_queue_post_refresh_callback([&] { callbacks_run.push_back(1); });
    snode_pool->debug_queue_post_refresh_callback([&] { callbacks_run.push_back(2); });
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

    // And hand back a copy of every one of them, in whatever order the cache keeps
    auto nodes = snode_pool->nodes();
    CHECK(std::ranges::is_permutation(nodes, snode_cache));
}

TEST_CASE("Network", "[network][refresh_min_cache_size]") {
    session::network::config::SnodePool pool_config = {
            std::nullopt,
            std::nullopt,
            5min,
            5min,
            false,  // enforce_subnet_diversity
            network::opt::retry_delay{50ms, 200ms},
            opt::netid::Target::testnet,
            {},
            12,  // cache_min_size
            0,
            0,
            3,  // cache_node_strike_threshold
            false};
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hex_b;
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
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, *loop, *disk_loop);
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

TEST_CASE("Network", "[network][swarm_version_preference]") {
    constexpr std::array<uint16_t, 3> old_ss{2, 11, 0};
    constexpr std::array<uint16_t, 3> new_ss{2, 11, 1};

    auto make_config = [](std::optional<std::array<uint16_t, 3>> prefer) {
        session::network::config::SnodePool config = {
                std::nullopt,
                std::nullopt,
                std::chrono::minutes{5},
                std::chrono::minutes{5},
                false,
                network::opt::retry_delay{50ms, 200ms},
                opt::netid::Target::testnet,
                {},
                0,
                0,
                3,
                0,
                3};
        config.prefer_min_version = prefer;
        return config;
    };

    // Alternating, so that grouping by version can only come from the preference rather than from
    // the order they were put in.
    auto member = [](uint8_t n, std::array<uint16_t, 3> version) {
        return service_node{
                ed25519_pubkey::from_hex("{:02x}{}"_format(n, std::string(62, '0'))),
                oxen::quic::ipv4{"192.168.0.{}"_format(n)},
                static_cast<uint16_t>(20000 + n),
                static_cast<uint16_t>(30000 + n),
                version,
                0};
    };
    std::vector<service_node> swarm;
    for (uint8_t i = 0; i < 6; i++)
        swarm.push_back(member(i, i % 2 ? new_ss : old_ss));

    auto pubkey = x25519_pubkey::from_hex(std::string(64, 'a'));

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();

    auto ordered = [&](TestSnodePool& pool) {
        std::vector<service_node> got;
        pool.get_swarm(pubkey, false, [&got](auto, std::vector<service_node> nodes) {
            got = std::move(nodes);
        });
        // get_swarm answers from the cache on the pool's own queue; this waits for that to drain.
        pool.pending_post_refresh_callbacks();
        return got;
    };

    SECTION("preferred versions come first") {
        auto pool = std::make_shared<TestSnodePool>(make_config(new_ss), *loop, *disk_loop);
        pool->seed_swarm(pubkey, swarm);

        auto got = ordered(*pool);
        REQUIRE(got.size() == swarm.size());

        // Asserted as a boundary rather than a fixed order: each subset keeps its shuffled order,
        // so which preferred node comes first is deliberately not fixed.
        for (size_t i = 0; i < got.size(); i++)
            CHECK((got[i].storage_server_version >= new_ss) == (i < 3));
    }

    SECTION("a swarm with nothing preferred is still usable") {
        std::vector<service_node> all_old;
        for (uint8_t i = 0; i < 4; i++)
            all_old.push_back(member(i, old_ss));

        auto pool = std::make_shared<TestSnodePool>(make_config(new_ss), *loop, *disk_loop);
        pool->seed_swarm(pubkey, all_old);

        // Ordering, not filtering: preferring what none of them are must not empty the swarm.
        CHECK(ordered(*pool).size() == all_old.size());
    }

    SECTION("without a preference nothing is lost") {
        auto pool = std::make_shared<TestSnodePool>(make_config(std::nullopt), *loop, *disk_loop);
        pool->seed_swarm(pubkey, swarm);
        CHECK(ordered(*pool).size() == swarm.size());
    }

    SECTION("strikes still outrank the version") {
        auto pool = std::make_shared<TestSnodePool>(make_config(new_ss), *loop, *disk_loop);
        pool->seed_swarm(pubkey, swarm);

        // A node that has actually failed us is worse than one merely predicted to be unreachable,
        // so striking out every preferred member puts them behind the rest.
        for (const auto& n : swarm)
            if (n.storage_server_version >= new_ss)
                pool->record_node_failure(n, /*permanent=*/true);

        auto got = ordered(*pool);
        REQUIRE(!got.empty());
        CHECK(got.front().storage_server_version == old_ss);
    }
}
