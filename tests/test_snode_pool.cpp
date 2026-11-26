#include <oxenc/hex.h>

#include <catch2/catch_test_macros.hpp>
#include <fstream>
#include <nlohmann/json.hpp>
#include <session/network/snode_pool.hpp>
#include <session/random.hpp>
#include <set>

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

    // Off by default: most tests here don't want a cache refresh, and the ones that do turn it on
    bool real_refresh = false;

    void refresh_if_needed(
            const std::vector<service_node>& in_use_nodes,
            std::function<void()> on_refresh_complete = nullptr) override {
        if (real_refresh)
            SnodePool::refresh_if_needed(in_use_nodes, std::move(on_refresh_complete));
    }

    // As `reset_state_with_cache`, and with the cache just refreshed, so that its age alone does
    // not call for another refresh
    void reset_state_with_fresh_cache(std::vector<service_node> cache) {
        _jq.call_get([this, cache] {
            _snode_cache = cache;
            _snode_strikes.clear();
            _last_snode_cache_update = std::chrono::system_clock::now();
        });
    }

    bool subnet_diversity_relaxed() {
        return _jq.call_get([this] { return _subnet_diversity_relaxed; });
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
    void update_cache(std::vector<service_node> nodes) {
        _update_cache("test", std::move(nodes), CacheSource::other);
    }

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

namespace {

// `count` nodes spread over `subnets` /24 subnets, each with its own key
std::vector<service_node> nodes_in_subnets(size_t count, size_t subnets, uint8_t key_tag) {
    std::vector<service_node> nodes;
    for (size_t i = 0; i < count; ++i) {
        std::array<std::byte, 32> key{};
        key[0] = std::byte{key_tag};
        key[1] = static_cast<std::byte>(i);
        nodes.emplace_back(service_node{
                ed25519_pubkey::from_bytes(key),
                oxen::quic::ipv4{"10.{}.{}.{}"_format(key_tag, i % subnets, i / subnets + 1)},
                static_cast<uint16_t>(20000 + i),
                static_cast<uint16_t>(30000 + i),
                {2, 11, 0},
                0});
    }
    return nodes;
}

size_t distinct_subnets(const std::vector<service_node>& nodes) {
    std::set<uint32_t> subnets;
    for (const auto& node : nodes)
        subnets.insert(node.ip.to_base(24).addr);
    return subnets.size();
}

// The pool's refresh requests, answered by hand: each is held until the test replies to it, on the
// loop, as the transport would.
struct HeldRefreshes {
    std::mutex mutex;
    std::vector<std::pair<Request, network_response_callback_t>> requests;

    SnodePool::network_fetcher_t fetcher() {
        return [this](Request request, network_response_callback_t cb) {
            std::lock_guard lock{mutex};
            requests.emplace_back(std::move(request), std::move(cb));
        };
    }

    // Waits for the next request, so that a refresh started asynchronously has got as far as
    // asking someone
    std::optional<std::pair<Request, network_response_callback_t>> next() {
        for (int i = 0; i < 200; ++i) {
            {
                std::lock_guard lock{mutex};
                if (!requests.empty()) {
                    auto front = std::move(requests.front());
                    requests.erase(requests.begin());
                    return front;
                }
            }
            std::this_thread::sleep_for(10ms);
        }
        return std::nullopt;
    }
};

session::network::config::SnodePool subnet_config(
        std::vector<service_node> seed_nodes,
        std::optional<std::filesystem::path> prepackaged = std::nullopt) {
    return {std::nullopt,
            std::move(prepackaged),
            5min,
            0ms,   // cache_min_lifetime
            true,  // enforce_subnet_diversity
            network::opt::retry_delay{10ms, 20ms},
            opt::netid::Target::testnet,
            std::move(seed_nodes),
            12,  // cache_min_size
            0,
            3,  // cache_num_nodes_to_use_for_refresh
            2,
            3,  // cache_node_strike_threshold
            std::nullopt};
}

}  // namespace

TEST_CASE(
        "SnodePool: a cache with too few subnets refreshes from the seed nodes",
        "[network][subnets]") {
    // 20 nodes over 2 subnets: enough by count, too few to give 3 nodes from distinct subnets.
    // Before, the refresh check saw enough nodes and called back at once, and a path build
    // retrying on that callback failed the same way without end.
    auto seed = nodes_in_subnets(1, 1, 99);
    auto cramped = nodes_in_subnets(20, 2, 1);
    auto diverse = nodes_in_subnets(30, 30, 2);

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    HeldRefreshes held;
    auto pool =
            std::make_shared<TestSnodePool>(subnet_config(seed), *loop, *disk_loop, held.fetcher());
    pool->reset_state_with_fresh_cache(cramped);
    pool->real_refresh = true;

    CHECK(pool->get_unused_nodes(3).size() == 2);

    std::atomic<int> refreshed{0};
    pool->refresh_if_needed({}, [&] { refreshed++; });
    auto request = held.next();
    REQUIRE(request);
    // Asked of the seed node rather than of the cramped cache's own nodes, and not called back
    // before it answered
    REQUIRE(std::holds_alternative<service_node>(request->first.destination));
    CHECK(std::get<service_node>(request->first.destination).remote_pubkey ==
          seed[0].remote_pubkey);
    CHECK(refreshed == 0);

    SECTION("which fixes it") {
        auto bin = to_snode_cache_bin(diverse);
        loop->call_get([&] {
            request->second(
                    true,
                    false,
                    200,
                    {},
                    std::string{reinterpret_cast<const char*>(bin.data()), bin.size()});
        });
        loop->call_get([] {});
        CHECK(refreshed == 1);

        auto nodes = pool->get_unused_nodes(3);
        CHECK(nodes.size() == 3);
        CHECK(distinct_subnets(nodes) == 3);
        CHECK_FALSE(pool->subnet_diversity_relaxed());
    }

    SECTION("which still has too few, so diversity gives way until the next refresh") {
        auto still_cramped = nodes_in_subnets(20, 2, 3);
        auto bin = to_snode_cache_bin(still_cramped);
        loop->call_get([&] {
            request->second(
                    true,
                    false,
                    200,
                    {},
                    std::string{reinterpret_cast<const char*>(bin.data()), bin.size()});
        });
        loop->call_get([] {});
        CHECK(refreshed == 1);

        auto nodes = pool->get_unused_nodes(3);
        CHECK(nodes.size() == 3);
        CHECK(pool->subnet_diversity_relaxed());
        // Both subnets used, so only one is shared
        CHECK(distinct_subnets(nodes) == 2);

        // The next refresh is judged afresh
        pool->update_cache(diverse);
        CHECK_FALSE(pool->subnet_diversity_relaxed());
        CHECK(distinct_subnets(pool->get_unused_nodes(3)) == 3);
    }

    SECTION("which cannot reach the seed nodes, so diversity gives way") {
        loop->call_get([&] { request->second(false, true, 0, {}, std::nullopt); });
        // The failed request is retried after `retry_delay`, finds no seed node left, and gives up
        for (int i = 0; i < 200 && refreshed == 0; ++i)
            std::this_thread::sleep_for(10ms);
        CHECK(refreshed == 1);
        CHECK(pool->subnet_diversity_relaxed());
        CHECK(pool->get_unused_nodes(3).size() == 3);
        // The cramped cache is kept rather than replaced
        CHECK(pool->size() == cramped.size());
    }
}

namespace {

// A prepackaged pool of `nodes` in its own temporary directory, removed with it
struct PrepackagedPool {
    std::filesystem::path dir = std::filesystem::temp_directory_path() /
                                "snode-pool-prepackaged-{}"_format(random::unique_id("t"));
    std::filesystem::path path = dir / "service_nodes.json";

    explicit PrepackagedPool(const std::vector<service_node>& nodes) {
        std::filesystem::create_directories(dir);
        nlohmann::json states = nlohmann::json::array();
        for (const auto& node : nodes)
            states.push_back(
                    {{"pubkey_ed25519", oxenc::to_hex(node.view_remote_key())},
                     {"public_ip", node.ip.to_string()},
                     {"storage_https_port", node.https_port},
                     {"storage_lmq_port", node.omq_port},
                     {"swarm_id", node.swarm_id},
                     {"requested_unlock_height", 0}});
        std::ofstream{path} << nlohmann::json{{"height", 1}, {"service_node_states", states}};
    }
    ~PrepackagedPool() {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

void answer(
        oxen::quic::Loop& loop,
        std::pair<Request, network_response_callback_t>& request,
        const std::vector<service_node>& nodes) {
    auto bin = to_snode_cache_bin(nodes);
    loop.call_get([&] {
        request.second(
                true,
                false,
                200,
                {},
                std::string{reinterpret_cast<const char*>(bin.data()), bin.size()});
    });
    loop.call_get([] {});
}

void fail(oxen::quic::Loop& loop, std::pair<Request, network_response_callback_t>& request) {
    loop.call_get([&] { request.second(false, true, 0, {}, std::nullopt); });
}

bool none_held(HeldRefreshes& held) {
    std::lock_guard lock{held.mutex};
    return held.requests.empty();
}

const service_node& destination(const std::pair<Request, network_response_callback_t>& request) {
    return std::get<service_node>(request.first.destination);
}

}  // namespace

TEST_CASE(
        "SnodePool: a refresh for subnets asks the seed nodes over the routed fetcher first",
        "[network][subnets]") {
    auto seed = nodes_in_subnets(1, 1, 99);
    auto cramped = nodes_in_subnets(20, 1, 1);

    SECTION("whose list, still too cramped, is the network as it is") {
        auto loop = std::make_shared<oxen::quic::Loop>();
        auto disk_loop = std::make_shared<oxen::quic::Loop>();
        HeldRefreshes direct, routed;
        PrepackagedPool prepackaged{nodes_in_subnets(25, 25, 4)};
        auto pool = std::make_shared<TestSnodePool>(
                subnet_config(seed, prepackaged.path), *loop, *disk_loop, direct.fetcher());
        pool->set_routed_fetcher(routed.fetcher(), [] { return true; });
        pool->reset_state_with_fresh_cache(cramped);
        pool->real_refresh = true;

        CHECK(pool->get_unused_nodes(3).size() == 1);
        std::atomic<int> refreshed{0};
        pool->refresh_if_needed({}, [&] { refreshed++; });
        auto request = routed.next();
        REQUIRE(request);
        CHECK(destination(*request).remote_pubkey == seed[0].remote_pubkey);
        answer(*loop, *request, nodes_in_subnets(20, 2, 5));
        CHECK(refreshed == 1);

        // Neither the stale prepackaged pool nor the seed nodes directly could say more
        CHECK(pool->get_unused_nodes(3).size() == 3);
        CHECK(pool->subnet_diversity_relaxed());
        CHECK(pool->size() == 20);
        CHECK(none_held(direct));
    }

    SECTION("then, if no seed node answers, the prepackaged pool if it spans more") {
        auto loop = std::make_shared<oxen::quic::Loop>();
        auto disk_loop = std::make_shared<oxen::quic::Loop>();
        HeldRefreshes direct, routed;
        PrepackagedPool prepackaged{nodes_in_subnets(25, 25, 4)};
        auto pool = std::make_shared<TestSnodePool>(
                subnet_config(seed, prepackaged.path), *loop, *disk_loop, direct.fetcher());
        pool->set_routed_fetcher(routed.fetcher(), [] { return true; });
        pool->reset_state_with_fresh_cache(cramped);
        pool->real_refresh = true;

        CHECK(pool->get_unused_nodes(3).size() == 1);
        std::atomic<int> refreshed{0};
        pool->refresh_if_needed({}, [&] { refreshed++; });
        auto request = routed.next();
        REQUIRE(request);
        fail(*loop, *request);
        for (int i = 0; i < 200 && refreshed == 0; ++i)
            std::this_thread::sleep_for(10ms);
        CHECK(refreshed == 1);

        CHECK(pool->size() == 25);
        CHECK(distinct_subnets(pool->get_unused_nodes(3)) == 3);
        CHECK_FALSE(pool->subnet_diversity_relaxed());
        CHECK(none_held(direct));
    }

    SECTION("then the seed nodes directly, when the prepackaged pool is no help") {
        auto loop = std::make_shared<oxen::quic::Loop>();
        auto disk_loop = std::make_shared<oxen::quic::Loop>();
        HeldRefreshes direct, routed;
        auto pool = std::make_shared<TestSnodePool>(
                subnet_config(seed), *loop, *disk_loop, direct.fetcher());
        pool->set_routed_fetcher(routed.fetcher(), [] { return true; });
        pool->reset_state_with_fresh_cache(cramped);
        pool->real_refresh = true;

        CHECK(pool->get_unused_nodes(3).size() == 1);
        std::atomic<int> refreshed{0};
        pool->refresh_if_needed({}, [&] { refreshed++; });
        auto routed_request = routed.next();
        REQUIRE(routed_request);
        fail(*loop, *routed_request);

        auto direct_request = direct.next();
        REQUIRE(direct_request);
        CHECK(destination(*direct_request).remote_pubkey == seed[0].remote_pubkey);
        CHECK(refreshed == 0);
        answer(*loop, *direct_request, nodes_in_subnets(30, 30, 2));
        CHECK(refreshed == 1);
        CHECK(distinct_subnets(pool->get_unused_nodes(3)) == 3);
        CHECK_FALSE(pool->subnet_diversity_relaxed());
    }

    SECTION("and the seed nodes directly after a prepackaged pool that is better but still short") {
        auto loop = std::make_shared<oxen::quic::Loop>();
        auto disk_loop = std::make_shared<oxen::quic::Loop>();
        HeldRefreshes direct, routed;
        // Two subnets beat the cache's one, but still cannot give three nodes from distinct ones
        PrepackagedPool prepackaged{nodes_in_subnets(20, 2, 4)};
        auto pool = std::make_shared<TestSnodePool>(
                subnet_config(seed, prepackaged.path), *loop, *disk_loop, direct.fetcher());
        pool->set_routed_fetcher(routed.fetcher(), [] { return true; });
        pool->reset_state_with_fresh_cache(cramped);
        pool->real_refresh = true;

        CHECK(pool->get_unused_nodes(3).size() == 1);
        std::atomic<int> refreshed{0};
        pool->refresh_if_needed({}, [&] { refreshed++; });
        auto routed_request = routed.next();
        REQUIRE(routed_request);
        fail(*loop, *routed_request);
        for (int i = 0; i < 200 && refreshed == 0; ++i)
            std::this_thread::sleep_for(10ms);
        REQUIRE(refreshed == 1);
        CHECK(pool->size() == 20);

        // A stale pool is not evidence enough to give way: the seed nodes are asked, directly
        CHECK(pool->get_unused_nodes(3).size() == 2);
        CHECK_FALSE(pool->subnet_diversity_relaxed());
        pool->refresh_if_needed({}, [&] { refreshed++; });
        auto direct_request = direct.next();
        REQUIRE(direct_request);
        CHECK(none_held(routed));
        fail(*loop, *direct_request);
        for (int i = 0; i < 200 && refreshed == 1; ++i)
            std::this_thread::sleep_for(10ms);
        CHECK(refreshed == 2);
        CHECK(pool->subnet_diversity_relaxed());
        CHECK(pool->get_unused_nodes(3).size() == 3);
    }
}

TEST_CASE(
        "SnodePool: without a routed fetcher, a cache with too few subnets is replaced by a "
        "prepackaged pool that spans more before the seed nodes are asked directly",
        "[network][subnets]") {
    auto seed = nodes_in_subnets(1, 1, 99);
    auto cramped = nodes_in_subnets(20, 2, 1);
    auto prepackaged_nodes = nodes_in_subnets(25, 25, 4);
    PrepackagedPool prepackaged{prepackaged_nodes};

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    HeldRefreshes held;
    auto pool = std::make_shared<TestSnodePool>(
            subnet_config(seed, prepackaged.path), *loop, *disk_loop, held.fetcher());
    pool->reset_state_with_fresh_cache(cramped);
    pool->real_refresh = true;

    CHECK(pool->get_unused_nodes(3).size() == 2);
    std::atomic<int> refreshed{0};
    pool->refresh_if_needed({}, [&] { refreshed++; });
    for (int i = 0; i < 200 && refreshed == 0; ++i)
        std::this_thread::sleep_for(10ms);
    CHECK(refreshed == 1);
    // Taken before the seed nodes are asked directly, which would show them the client's address
    CHECK(none_held(held));

    CHECK(pool->size() == prepackaged_nodes.size());
    auto nodes = pool->get_unused_nodes(3);
    CHECK(nodes.size() == 3);
    CHECK(distinct_subnets(nodes) == 3);
    CHECK_FALSE(pool->subnet_diversity_relaxed());
}

TEST_CASE(
        "SnodePool: a caller retrying on every refresh callback stops once subnets give way",
        "[network][subnets]") {
    // What the onion request router does when it cannot fill a path: ask for a refresh, and retry
    // when called back.  With a refresh check that ignored subnets, the callback came back at once,
    // inline, and this recursed until the process ran out of memory.
    auto seed = nodes_in_subnets(1, 1, 99);
    auto cramped = nodes_in_subnets(20, 2, 1);

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    HeldRefreshes held;
    auto pool =
            std::make_shared<TestSnodePool>(subnet_config(seed), *loop, *disk_loop, held.fetcher());
    pool->reset_state_with_fresh_cache(cramped);
    pool->real_refresh = true;

    // An existing path, as the router excludes it when building the next
    std::vector<service_node> in_use{cramped[0], cramped[1], cramped[2]};

    std::atomic<int> attempts{0};
    std::atomic<bool> built{false};
    std::function<void()> build = [&] {
        if (++attempts > 50)
            return;
        if (pool->get_unused_nodes(3, in_use).size() >= 3)
            built = true;
        else
            pool->refresh_if_needed(in_use, build);
    };
    loop->call_get([&] { build(); });

    // Waiting on the seed nodes, not retrying
    auto request = held.next();
    REQUIRE(request);
    CHECK(attempts == 1);
    CHECK_FALSE(built);

    // The seed nodes' network is just as cramped, so diversity gives way and the retry succeeds
    auto bin = to_snode_cache_bin(nodes_in_subnets(20, 2, 5));
    loop->call_get([&] {
        request->second(
                true,
                false,
                200,
                {},
                std::string{reinterpret_cast<const char*>(bin.data()), bin.size()});
    });
    loop->call_get([] {});
    CHECK(built);
    CHECK(attempts == 2);
}

TEST_CASE(
        "SnodePool: with no seed nodes, a cache with too few subnets gives way rather than "
        "waiting",
        "[network][subnets]") {
    auto cramped = nodes_in_subnets(20, 2, 1);

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    HeldRefreshes held;
    auto pool =
            std::make_shared<TestSnodePool>(subnet_config({}), *loop, *disk_loop, held.fetcher());
    pool->reset_state_with_fresh_cache(cramped);
    pool->real_refresh = true;

    CHECK(pool->get_unused_nodes(3).size() == 2);
    std::atomic<int> refreshed{0};
    pool->refresh_if_needed({}, [&] { refreshed++; });
    for (int i = 0; i < 200 && refreshed == 0; ++i)
        std::this_thread::sleep_for(10ms);
    CHECK(refreshed == 1);
    CHECK(pool->subnet_diversity_relaxed());
    CHECK(distinct_subnets(pool->get_unused_nodes(3)) == 2);
}

TEST_CASE(
        "SnodePool: a cache bootstrapped from the seed nodes is not refreshed from them again "
        "for its subnets",
        "[network][subnets]") {
    // Testnet: the bootstrap itself comes from the seed nodes and is as cramped as the network is,
    // so asking them again would return the same.
    auto seed = nodes_in_subnets(1, 1, 99);

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    HeldRefreshes held;
    auto pool =
            std::make_shared<TestSnodePool>(subnet_config(seed), *loop, *disk_loop, held.fetcher());
    pool->real_refresh = true;

    std::atomic<int> refreshed{0};
    pool->refresh_if_needed({}, [&] { refreshed++; });
    auto bootstrap = held.next();
    REQUIRE(bootstrap);
    auto bin = to_snode_cache_bin(nodes_in_subnets(20, 2, 6));
    loop->call_get([&] {
        bootstrap->second(
                true,
                false,
                200,
                {},
                std::string{reinterpret_cast<const char*>(bin.data()), bin.size()});
    });
    loop->call_get([] {});
    REQUIRE(refreshed == 1);

    auto nodes = pool->get_unused_nodes(3);
    CHECK(nodes.size() == 3);
    CHECK(pool->subnet_diversity_relaxed());
    std::this_thread::sleep_for(100ms);
    std::lock_guard lock{held.mutex};
    CHECK(held.requests.empty());
}

TEST_CASE("Network config: subnet diversity is enforced on mainnet only", "[network][subnets]") {
    // Every testnet node is run by one party, and devnet nodes by a developer, whatever their
    // addresses; testnet's 26 nodes span only 12 /24 subnets, exactly what four paths need.
    using network::config::Config;
    CHECK(Config{}.enforce_subnet_diversity);
    CHECK(Config{opt::netid::mainnet()}.enforce_subnet_diversity);
    CHECK_FALSE(Config{opt::netid::testnet()}.enforce_subnet_diversity);
    CHECK_FALSE(Config{opt::netid::devnet(nodes_in_subnets(1, 1, 9))}.enforce_subnet_diversity);
    // And the explicit option still turns it off on mainnet
    CHECK_FALSE(Config{opt::netid::mainnet(), opt::disable_subnet_diversity{}}
                        .enforce_subnet_diversity);
}
