#include <fmt/core.h>
#include <sodium/randombytes.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <nlohmann/json.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/crypto/x25519.hpp>
#include <session/network/key_types.hpp>
#include <session/network/request_queue.hpp>
#include <session/network/routing/onion_request_router.hpp>
#include <session/onionreq/hop_encryption.hpp>
#include <tuple>

#include "utils.hpp"

using namespace session;
using namespace session::network;

namespace session::network {
class TestOnionRequestRouter {
  public:
    static void set_paths(
            std::shared_ptr<OnionRequestRouter> router,
            PathCategory category,
            std::vector<OnionPath> paths) {
        router->_paths.emplace(category, paths);
    }

    static std::vector<OnionPath> get_paths(
            std::shared_ptr<OnionRequestRouter> router, PathCategory category) {
        return router->_paths[category];
    }

    static void set_request_queues(
            std::shared_ptr<OnionRequestRouter> router,
            std::unordered_map<PathCategory, std::shared_ptr<detail::RequestQueue>> queues) {
        router->_request_queues = queues;
    }

    static uint16_t strike_count(
            std::shared_ptr<OnionRequestRouter> router,
            PathCategory category,
            std::string path_id) {
        for (auto& path : router->_paths[category])
            if (path.id == path_id)
                return path.strike_count;

        return 0;
    }

    static void build_path(
            std::shared_ptr<OnionRequestRouter> router,
            PathCategory category,
            std::optional<std::string> initiating_req_id = std::nullopt,
            const std::vector<service_node>& nodes_to_exclude_ = {},
            std::optional<std::string> original_path_id = std::nullopt) {
        router->_build_path(category, initiating_req_id, nodes_to_exclude_, original_path_id);
    }

    static OnionPath* find_valid_path(
            std::shared_ptr<OnionRequestRouter> router, const Request& request) {
        return router->_find_valid_path(request);
    }

    static void handle_transport_response(
            std::shared_ptr<OnionRequestRouter> router,
            std::string path_id,
            Request original_request,
            bool success,
            bool timeout,
            int16_t status_code,
            std::vector<std::pair<std::string, std::string>> headers,
            std::optional<std::string> decrypted_body,
            network_response_callback_t callback) {
        router->_handle_transport_response(
                path_id,
                original_request,
                success,
                timeout,
                status_code,
                std::move(headers),
                std::move(decrypted_body),
                std::move(callback));
    }
};

namespace detail {
    class TestRequestQueue : public detail::RequestQueue, public CallTracker {
      public:
        TestRequestQueue(oxen::quic::Loop& loop) : detail::RequestQueue(loop) {};

        void add(Request request, network_response_callback_t callback) override {
            if (check_should_ignore_and_log_call("add"))
                return;
            detail::RequestQueue::add(std::move(request), std::move(callback));
        }

        void add_front(std::pair<Request, network_response_callback_t> req_pair) override {
            if (check_should_ignore_and_log_call("add_front"))
                return;
            detail::RequestQueue::add_front(std::move(req_pair));
        }

        std::deque<std::pair<Request, network_response_callback_t>> pop_all() override {
            if (check_should_ignore_and_log_call("pop_all"))
                return {};
            return detail::RequestQueue::pop_all();
        }

      private:
        void check_timeouts(std::optional<std::chrono::steady_clock::time_point> now) override {
            if (check_should_ignore_and_log_call("check_timeouts"))
                return;
            detail::RequestQueue::check_timeouts(now);
        }

        void update_timeout() override {
            if (check_should_ignore_and_log_call("update_timeout"))
                return;
            detail::RequestQueue::update_timeout();
        }
    };
}  // namespace detail

namespace {
    class TestSnodePool : public SnodePool, public CallTracker {
      public:
        std::optional<std::vector<service_node>> mock_unused_nodes;

        TestSnodePool(
                config::SnodePool config,
                oxen::quic::Loop& loop,
                oxen::quic::Loop& disk_loop,
                network_fetcher_t direct_fetcher = [](Request, network_response_callback_t) {}) :
                SnodePool(std::move(config), loop, disk_loop, std::move(direct_fetcher)) {}

        void record_node_failure(const service_node& node, bool permanent = false) override {
            if (check_should_ignore_and_log_call("record_node_failure(node)"))
                return;
            SnodePool::record_node_failure(node, permanent);
        }

        void record_node_failure(const ed25519_pubkey& key, bool permanent = false) override {
            if (check_should_ignore_and_log_call("record_node_failure(key)"))
                return;
            SnodePool::record_node_failure(key, permanent);
        }

        void refresh_if_needed(
                const std::vector<service_node>& /*in_use_nodes*/,
                std::function<void()> /*on_refresh_complete*/ = nullptr) override {
            func_called("refresh_if_needed");
            // Do nothing (don't want to trigger a cache refresh)
        }

        void get_swarm(
                session::network::x25519_pubkey /*swarm_pubkey*/,
                bool /*ignore_strike_count*/,
                std::function<void(swarm::swarm_id_t, std::vector<service_node>)> /*callback*/)
                override {
            func_called("get_swarm");
            // Do nothing (don't want to trigger a cache refresh)
        }

        std::vector<service_node> get_unused_nodes(
                size_t count, const std::vector<service_node>& exclude = {}) override {
            if (check_should_ignore_and_log_call("get_unused_nodes"))
                return {};

            if (mock_unused_nodes)
                return *mock_unused_nodes;

            return SnodePool::get_unused_nodes(count, exclude);
        }
    };

    class TestTransport : public ITransport, public CallTracker {
      public:
        void suspend() override { func_called("suspend"); };
        void resume(bool /*automatically_reconnect*/ = true) override { func_called("resume"); };
        void close_connections() override { func_called("close_connections"); };

        ConnectionStatus get_status() const override { return ConnectionStatus::unknown; };
        void verify_connectivity(
                service_node,
                std::chrono::milliseconds /*timeout*/,
                const std::string& /*request_id*/,
                const RequestCategory,
                std::function<void(bool success, std::optional<uint64_t> error_code)> /*callback*/)
                override {
            func_called("verify_connectivity");
        }
        void add_failure_listener(const ed25519_pubkey&, std::function<void()>) override {
            func_called("add_failure_listener");
        }
        void remove_failure_listeners(const ed25519_pubkey&) override {
            func_called("remove_failure_listeners");
        }

        void send_request(Request, network_response_callback_t) override {
            func_called("send_request");
        }
    };

    struct Result {
        bool success;
        bool timeout;
        int16_t status_code;
        std::vector<std::pair<std::string, std::string>> headers;
        std::optional<std::string> response;
    };
}  // namespace

TEST_CASE("Network", "[network][onion_request_router][handle_errors]") {
    const auto node_strike_threshold = 3;
    config::SnodePool pool_config = {
            .cache_directory = std::nullopt,
            .fallback_snode_pool_path = std::nullopt,
            .cache_expiration = std::chrono::minutes{5},
            .cache_min_lifetime = std::chrono::minutes{5},
            .enforce_subnet_diversity = false,
            .retry_delay = network::opt::retry_delay{50ms, 200ms},
            .netid = opt::netid::Target::testnet,
            .seed_nodes = {},
            .cache_min_size = 0,
            .cache_min_swarm_size = 0,
            .cache_num_nodes_to_use_for_refresh = 3,
            .cache_min_num_refresh_presence_to_include_node = 2,
            .cache_node_strike_threshold = node_strike_threshold};
    config::OnionRequestRouter config = {
            file_server::DEFAULT_CONFIG,
            std::nullopt,
            std::chrono::days{10},
            opt::netid::Target::testnet,
            {},
            network::opt::retry_delay{50ms, 200ms},
            3,
            3,
            10,
            10min,
            node_strike_threshold,
            true,
            true,
            {{PathCategory::standard, 1}}};
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hex_b;
    auto ed_pk2 = "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hex_b;
    auto ed_pk3 = "e17a692033200ae41350df9709754edde7343e2cf2f23e88f993319e0720e5e5"_hex_b;
    auto ed_pk4 = "7b633fa6fb462b90db6f0f50384190ce7715e31b7aa93d87dbd7e94e33d4251f"_hex_b;
    auto target = service_node{
            ed25519_pubkey::from_bytes(ed_pk),
            oxen::quic::ipv4{"127.0.0.1"},
            20001,
            30001,
            {2, 11, 0},
            0};
    auto target2 = service_node{
            ed25519_pubkey::from_bytes(ed_pk2),
            oxen::quic::ipv4{"127.0.0.1"},
            20002,
            30002,
            {2, 11, 0},
            0};
    auto target3 = service_node{
            ed25519_pubkey::from_bytes(ed_pk3),
            oxen::quic::ipv4{"127.0.0.1"},
            20003,
            30003,
            {2, 11, 0},
            0};
    auto target4 = service_node{
            ed25519_pubkey::from_bytes(ed_pk4),
            oxen::quic::ipv4{"127.0.0.1"},
            20004,
            30004,
            {2, 11, 0},
            0};
    auto request =
            Request{"AAAA", target, "info", to_vector("test"), RequestCategory::standard, 0ms};
    std::optional<OnionPath> path;
    Result result;

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, *loop, *disk_loop);
    auto transport = std::make_shared<TestTransport>();
    std::shared_ptr<OnionRequestRouter> router;

    // We don't give a node a strike by default (require specific error messages to match)
    snode_pool->clear_node_strikes();
    snode_pool->reset_calls();
    path.emplace(OnionPath{"Test", {target2, target3, target4}});
    router = std::make_shared<OnionRequestRouter>(config, *loop, *disk_loop, snode_pool, transport);
    TestOnionRequestRouter::set_paths(router, PathCategory::standard, {*path});
    TestOnionRequestRouter::handle_transport_response(
            router,
            "Test",
            request,
            false,
            false,
            500,
            {},
            std::nullopt,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, headers, response};
            });

    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 500);
    CHECK(result.response.value_or("") == "");
    CHECK(snode_pool->did_not_call("record_node_failure(node)"));
    CHECK(snode_pool->did_not_call("record_node_failure(key)"));
    CHECK(snode_pool->node_strike_count(target2) == 0);
    CHECK(snode_pool->node_strike_count(target3) == 0);
    CHECK(snode_pool->node_strike_count(target4) == 0);
    CHECK(TestOnionRequestRouter::strike_count(router, PathCategory::standard, "Test") == 0);

    // path gets a strike for a handled error
    snode_pool->clear_node_strikes();
    snode_pool->reset_calls();
    path.emplace(OnionPath{"Test", {target2, target3, target4}});
    router = std::make_shared<OnionRequestRouter>(config, *loop, *disk_loop, snode_pool, transport);
    TestOnionRequestRouter::set_paths(router, PathCategory::standard, {*path});
    TestOnionRequestRouter::handle_transport_response(
            router,
            "Test",
            request,
            false,
            false,
            500,
            {},
            "Invalid response from snode",
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, headers, response};
            });
    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 500);
    CHECK(result.response.value_or("") == "Invalid response from snode");
    CHECK(snode_pool->did_not_call("record_node_failure(node)"));
    CHECK(snode_pool->did_not_call("record_node_failure(key)"));
    CHECK(snode_pool->node_strike_count(target2) == 0);
    CHECK(snode_pool->node_strike_count(target3) == 0);
    CHECK(snode_pool->node_strike_count(target4) == 0);
    CHECK(TestOnionRequestRouter::strike_count(router, PathCategory::standard, "Test") == 1);

    // Path is dropped if it gets too many strikes
    snode_pool->clear_node_strikes();
    REQUIRE(snode_pool->node_strike_count(target2) == 0);
    snode_pool->reset_calls();
    path.emplace(OnionPath{"Test", {target2, target3, target4}});
    router = std::make_shared<OnionRequestRouter>(config, *loop, *disk_loop, snode_pool, transport);
    TestOnionRequestRouter::set_paths(
            router,
            PathCategory::standard,
            {OnionPath{
                    "Test",
                    {target2, target3, target4},
                    std::chrono::system_clock::now(),
                    std::chrono::system_clock::now(),
                    0,
                    9}});
    TestOnionRequestRouter::handle_transport_response(
            router,
            "Test",
            request,
            false,
            false,
            500,
            {},
            "Invalid response from snode",
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, headers, response};
            });
    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 500);
    CHECK(result.response.value_or("") == "Invalid response from snode");
    CHECK(snode_pool->called("record_node_failure(node)", 3));
    CHECK(snode_pool->node_strike_count(target2) == 1);
    CHECK(snode_pool->node_strike_count(target3) == 1);
    CHECK(snode_pool->node_strike_count(target4) == 1);
    CHECK(TestOnionRequestRouter::strike_count(router, PathCategory::standard, "Test") ==
          0);  // Path dropped and reset

    // Both node and path get strikes for 502s specifying the node
    snode_pool->clear_node_strikes();
    snode_pool->reset_calls();
    snode_pool->mock_unused_nodes = {target};
    path.emplace(OnionPath{"Test", {target2, target3, target4}});
    router = std::make_shared<OnionRequestRouter>(config, *loop, *disk_loop, snode_pool, transport);
    TestOnionRequestRouter::set_paths(router, PathCategory::standard, {*path});
    TestOnionRequestRouter::handle_transport_response(
            router,
            "Test",
            request,
            false,
            false,
            502,
            {},
            "Next node not found: {}"_format(ed25519_pubkey::from_bytes(ed_pk3).hex()),
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, headers, response};
            });
    CHECK_FALSE(result.success);
    CHECK_FALSE(result.timeout);
    CHECK(result.status_code == 502);
    CHECK(result.response.value_or("") ==
          "Next node not found: {}"_format(ed25519_pubkey::from_bytes(ed_pk3).hex()));
    CHECK(snode_pool->called("record_node_failure(key)", 1));
    CHECK(snode_pool->node_strike_count(target2) == 0);
    CHECK(snode_pool->node_strike_count(target3) == node_strike_threshold);  // Node "dropped"
    CHECK(snode_pool->node_strike_count(target4) == 0);
    CHECK(TestOnionRequestRouter::strike_count(router, PathCategory::standard, "Test") == 1);
    CHECK(TestOnionRequestRouter::get_paths(router, PathCategory::standard).front().nodes[1] !=
          target3);

    // Check a timeout with a server destination doesn't impact the failure counts
    auto server_request =
            Request{"AAAA",
                    ServerDestination{
                            "https",
                            "open.getsession.org",
                            x25519_pubkey::from_hex("a03c383cf63c3c4efe67acc52112a6dd734b3a946b9545"
                                                    "f488aaa93da7991238"),
                            443,
                            std::nullopt,
                            "GET"},
                    "info",
                    to_vector("test"),
                    RequestCategory::standard,
                    0ms};
    snode_pool->clear_node_strikes();
    snode_pool->reset_calls();
    path.emplace(OnionPath{"Test", {target2, target3, target4}});
    router = std::make_shared<OnionRequestRouter>(config, *loop, *disk_loop, snode_pool, transport);
    TestOnionRequestRouter::set_paths(router, PathCategory::standard, {*path});
    TestOnionRequestRouter::handle_transport_response(
            router,
            "Test",
            server_request,
            false,
            true,
            -1,
            {},
            std::nullopt,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, headers, response};
            });
    CHECK_FALSE(result.success);
    CHECK(result.timeout);
    CHECK(result.status_code == -1);
    CHECK(result.response.value_or("") == "");
    CHECK(snode_pool->did_not_call("record_node_failure(node)"));
    CHECK(snode_pool->did_not_call("record_node_failure(key)"));
    CHECK(snode_pool->node_strike_count(target2) == 0);
    CHECK(snode_pool->node_strike_count(target3) == 0);
    CHECK(snode_pool->node_strike_count(target4) == 0);
    CHECK(TestOnionRequestRouter::strike_count(router, PathCategory::standard, "Test") == 0);

    // 406 and 421 errors don't affect strike counts
    auto server_codes_with_no_changes = {406, 421};

    for (auto code : server_codes_with_no_changes) {
        snode_pool->clear_node_strikes();
        snode_pool->reset_calls();
        path.emplace(OnionPath{"Test", {target2, target3, target4}});
        router = std::make_shared<OnionRequestRouter>(
                config, *loop, *disk_loop, snode_pool, transport);
        TestOnionRequestRouter::set_paths(router, PathCategory::standard, {*path});
        TestOnionRequestRouter::handle_transport_response(
                router,
                "Test",
                server_request,
                false,
                false,
                code,
                {},
                std::nullopt,
                [&result](
                        bool success,
                        bool timeout,
                        int16_t status_code,
                        std::vector<std::pair<std::string, std::string>> headers,
                        std::optional<std::string> response) {
                    result = {success, timeout, status_code, headers, response};
                });
        CHECK_FALSE(result.success);
        CHECK(result.timeout == false);
        CHECK(result.status_code == code);
        CHECK(result.response.value_or("") == "");
        CHECK(snode_pool->did_not_call("record_node_failure(node)"));
        CHECK(snode_pool->did_not_call("record_node_failure(key)"));
        CHECK(snode_pool->node_strike_count(target2) == 0);
        CHECK(snode_pool->node_strike_count(target3) == 0);
        CHECK(snode_pool->node_strike_count(target4) == 0);
        CHECK(TestOnionRequestRouter::strike_count(router, PathCategory::standard, "Test") == 0);
    }
}

TEST_CASE("Network", "[network][onion_request_router][build_path]") {
    config::SnodePool pool_config = {
            .cache_directory = std::nullopt,
            .fallback_snode_pool_path = std::nullopt,
            .cache_expiration = std::chrono::minutes{5},
            .cache_min_lifetime = std::chrono::minutes{5},
            .enforce_subnet_diversity = false,
            .retry_delay = network::opt::retry_delay{50ms, 200ms},
            .netid = opt::netid::Target::testnet,
            .seed_nodes = {},
            .cache_min_size = 0,
            .cache_min_swarm_size = 0,
            .cache_num_nodes_to_use_for_refresh = 3,
            .cache_min_num_refresh_presence_to_include_node = 2,
            .cache_node_strike_threshold = 3};
    config::OnionRequestRouter config = {
            file_server::DEFAULT_CONFIG,
            std::nullopt,
            std::chrono::days{10},
            opt::netid::Target::testnet,
            {},
            network::opt::retry_delay{50ms, 200ms},
            3,
            3,
            10,
            10min,
            3,
            true,
            true,
            {{PathCategory::standard, 1}}};
    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, *loop, *disk_loop);
    auto transport = std::make_shared<TestTransport>();
    std::shared_ptr<OnionRequestRouter> router;

    // Nothing should happen if the network is suspended
    snode_pool->reset_calls();
    router = std::make_shared<OnionRequestRouter>(config, *loop, *disk_loop, snode_pool, transport);
    router->suspend();
    TestOnionRequestRouter::build_path(router, PathCategory::standard);
    CHECK(snode_pool->did_not_call("get_unused_nodes"));

    // If the unused nodes are empty it refreshes them
    snode_pool->reset_calls();
    router = std::make_shared<OnionRequestRouter>(config, *loop, *disk_loop, snode_pool, transport);
    TestOnionRequestRouter::build_path(router, PathCategory::standard);
    CHECK(snode_pool->called("get_unused_nodes"));
    CHECK(snode_pool->called("refresh_if_needed"));
}

TEST_CASE("Network", "[network][onion_request_router][find_valid_path]") {
    config::SnodePool pool_config = {
            .cache_directory = std::nullopt,
            .fallback_snode_pool_path = std::nullopt,
            .cache_expiration = std::chrono::minutes{5},
            .cache_min_lifetime = std::chrono::minutes{5},
            .enforce_subnet_diversity = false,
            .retry_delay = network::opt::retry_delay{50ms, 200ms},
            .netid = opt::netid::Target::testnet,
            .seed_nodes = {},
            .cache_min_size = 0,
            .cache_min_swarm_size = 0,
            .cache_num_nodes_to_use_for_refresh = 3,
            .cache_min_num_refresh_presence_to_include_node = 2,
            .cache_node_strike_threshold = 3};
    config::OnionRequestRouter config = {
            file_server::DEFAULT_CONFIG,
            std::nullopt,
            std::chrono::days{10},
            opt::netid::Target::testnet,
            {},
            network::opt::retry_delay{50ms, 200ms},
            3,
            3,
            10,
            10min,
            3,
            true,
            false,
            {{PathCategory::standard, 1}}};
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hex_b;
    auto ed_pk2 = "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hex_b;
    auto ed_pk3 = "e17a692033200ae41350df9709754edde7343e2cf2f23e88f993319e0720e5e5"_hex_b;
    auto ed_pk4 = "7b633fa6fb462b90db6f0f50384190ce7715e31b7aa93d87dbd7e94e33d4251f"_hex_b;
    auto target = service_node{
            ed25519_pubkey::from_bytes(ed_pk),
            oxen::quic::ipv4{"127.0.0.1"},
            20001,
            30001,
            {2, 11, 0},
            0};
    auto target2 = service_node{
            ed25519_pubkey::from_bytes(ed_pk2),
            oxen::quic::ipv4{"127.0.0.1"},
            20002,
            30002,
            {2, 11, 0},
            0};
    auto target3 = service_node{
            ed25519_pubkey::from_bytes(ed_pk3),
            oxen::quic::ipv4{"127.0.0.1"},
            20003,
            30003,
            {2, 11, 0},
            0};
    auto target4 = service_node{
            ed25519_pubkey::from_bytes(ed_pk4),
            oxen::quic::ipv4{"127.0.0.1"},
            20004,
            30004,
            {2, 11, 0},
            0};
    auto path1 = OnionPath{"Test1", {target, target2, target3}};
    auto path2 = OnionPath{"Test2", {target2, target3, target4}};
    auto request =
            Request{"AAAA", target, "info", to_vector("test"), RequestCategory::standard, 0ms};

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, *loop, *disk_loop);
    auto transport = std::make_shared<TestTransport>();
    std::shared_ptr<OnionRequestRouter> router;

    // It returns nothing when given no path options
    router = std::make_shared<OnionRequestRouter>(config, *loop, *disk_loop, snode_pool, transport);
    TestOnionRequestRouter::set_paths(router, PathCategory::standard, {});
    CHECK(TestOnionRequestRouter::find_valid_path(router, request) == nullptr);

    // It excludes paths which include the IP of the target
    router = std::make_shared<OnionRequestRouter>(config, *loop, *disk_loop, snode_pool, transport);
    TestOnionRequestRouter::set_paths(router, PathCategory::standard, {path1});
    CHECK(TestOnionRequestRouter::find_valid_path(router, request) == nullptr);

    // It returns a path when there is a valid one
    router = std::make_shared<OnionRequestRouter>(config, *loop, *disk_loop, snode_pool, transport);
    TestOnionRequestRouter::set_paths(router, PathCategory::standard, {path2});
    CHECK(TestOnionRequestRouter::find_valid_path(router, request) != nullptr);

    // In 'single_path_mode' it does allow the path to include the IP of the target (so that
    // requests can still be made)
    config = {
            file_server::DEFAULT_CONFIG,
            std::nullopt,
            std::chrono::days{10},
            opt::netid::Target::testnet,
            {},
            network::opt::retry_delay{50ms, 200ms},
            3,
            3,
            10,
            10min,
            3,
            true,
            true,  // single path mode
            {{PathCategory::standard, 1}}};
    router = std::make_shared<OnionRequestRouter>(config, *loop, *disk_loop, snode_pool, transport);
    TestOnionRequestRouter::set_paths(router, PathCategory::standard, {path1});
    CHECK(TestOnionRequestRouter::find_valid_path(router, request) != nullptr);
}

TEST_CASE("Network", "[network][onion_request_router][check_request_queue_timeouts]") {
    config::SnodePool pool_config = {
            .cache_directory = std::nullopt,
            .fallback_snode_pool_path = std::nullopt,
            .cache_expiration = std::chrono::minutes{5},
            .cache_min_lifetime = std::chrono::minutes{5},
            .enforce_subnet_diversity = false,
            .retry_delay = network::opt::retry_delay{50ms, 200ms},
            .netid = opt::netid::Target::testnet,
            .seed_nodes = {},
            .cache_min_size = 0,
            .cache_min_swarm_size = 0,
            .cache_num_nodes_to_use_for_refresh = 3,
            .cache_min_num_refresh_presence_to_include_node = 2,
            .cache_node_strike_threshold = 3};
    config::OnionRequestRouter config = {
            file_server::DEFAULT_CONFIG,
            std::nullopt,
            std::chrono::days{10},
            opt::netid::Target::testnet,
            {},
            network::opt::retry_delay{50ms, 200ms},
            3,
            3,
            10,
            10min,
            3,
            true,
            false,
            {{PathCategory::standard, 1}}};
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hex_b;
    auto target = service_node{
            ed25519_pubkey::from_bytes(ed_pk),
            oxen::quic::ipv4{"127.0.0.1"},
            20001,
            30001,
            {2, 11, 0},
            0};
    auto target2 = service_node{
            ed25519_pubkey::from_bytes(ed_pk),
            oxen::quic::ipv4{"127.0.0.1"},
            20002,
            30002,
            {2, 11, 0},
            0};
    auto target3 = service_node{
            ed25519_pubkey::from_bytes(ed_pk),
            oxen::quic::ipv4{"127.0.0.1"},
            20003,
            30003,
            {2, 11, 0},
            0};
    auto target4 = service_node{
            ed25519_pubkey::from_bytes(ed_pk),
            oxen::quic::ipv4{"127.0.0.1"},
            20004,
            30004,
            {2, 11, 0},
            0};
    auto path = OnionPath{"Test1", {target2, target3, target4}};
    auto request =
            Request{"AAAA", target, "info", to_vector("test"), RequestCategory::standard, 0ms};
    Result result;

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, *loop, *disk_loop);
    auto transport = std::make_shared<TestTransport>();
    auto queue = std::make_shared<detail::TestRequestQueue>(*loop);
    std::shared_ptr<OnionRequestRouter> router;

    // Test that it doesn't start checking for timeouts when the request doesn't have an overall
    // timeout
    request =
            Request{"AAAA",
                    target,
                    "info",
                    to_vector("test"),
                    RequestCategory::standard,
                    1000ms,
                    std::nullopt};
    router = std::make_shared<OnionRequestRouter>(config, *loop, *disk_loop, snode_pool, transport);
    queue = std::make_shared<detail::TestRequestQueue>(*loop);
    TestOnionRequestRouter::set_request_queues(router, {{PathCategory::standard, queue}});
    router->send_request(
            request,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, headers, response};
            });
    CHECK(queue->did_not_call("check_timeouts", 250ms));

    // Test that it does trigger the timeout when an overall timeout is provided (will call
    // `check_timeouts` at the timeout rather than poll)
    request = Request{
            "AAAA", target, "info", to_vector("test"), RequestCategory::standard, 1000ms, 100ms};
    router = std::make_shared<OnionRequestRouter>(config, *loop, *disk_loop, snode_pool, transport);
    queue = std::make_shared<detail::TestRequestQueue>(*loop);
    TestOnionRequestRouter::set_request_queues(router, {{PathCategory::standard, queue}});
    router->send_request(
            request,
            [&result](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                result = {success, timeout, status_code, headers, response};
            });
    CHECK(queue->called("add", 250ms));
    CHECK(queue->called("check_timeouts", 250ms));

    // Test that it fails the request with a timeout if it has an overall timeout and the path build
    // takes too long
    std::promise<Result> prom;
    request = Request{
            "AAAA", target, "info", to_vector("test"), RequestCategory::standard, 1000ms, 200ms};
    router = std::make_shared<OnionRequestRouter>(config, *loop, *disk_loop, snode_pool, transport);
    queue = std::make_shared<detail::TestRequestQueue>(*loop);
    TestOnionRequestRouter::set_request_queues(router, {{PathCategory::standard, queue}});
    router->send_request(
            request,
            [&prom](bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> headers,
                    std::optional<std::string> response) {
                prom.set_value({success, timeout, status_code, headers, response});
            });

    // Wait for the result to be set
    result = prom.get_future().get();

    CHECK_FALSE(result.success);
    CHECK(result.timeout);
}

TEST_CASE("Network", "[network][onion_request_router][short_string]") {
    auto pk = ed25519_pubkey::from_hex(
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    auto pk2 = ed25519_pubkey::from_hex(
            "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876");
    auto pk3 = ed25519_pubkey::from_hex(
            "e17a692033200ae41350df9709754edde7343e2cf2f23e88f993319e0720e5e5");

    for (const auto& key : {pk, pk2, pk3})
        CHECK(key.short_string() == key.snode_address().substr(0, 8));
    CHECK(pk.short_string() == "j15s9zdp");

    auto node = [](const ed25519_pubkey& key) {
        return service_node{key, oxen::quic::ipv4{"127.0.0.1"}, 20001, 30001, {2, 11, 0}, 0};
    };
    auto path = OnionPath{"Test", {node(pk), node(pk2), node(pk3)}};
    CHECK(path.to_string() == "j15s9zdp⟷m4twhhi5⟷hf7g1ebu");
}

}  // namespace session::network
