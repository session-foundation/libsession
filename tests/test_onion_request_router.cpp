#include <fmt/core.h>
#include <sodium/randombytes.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <nlohmann/json.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <session/curve25519.hpp>
#include <session/ed25519.hpp>
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
        router->_paths[category] = std::move(paths);
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

    static void set_cached_edge_nodes(
            std::shared_ptr<OnionRequestRouter> router, std::vector<cached_edge_node> nodes) {
        router->_cached_edge_nodes = std::move(nodes);
    }

    static std::vector<cached_edge_node> cached_edge_nodes(
            std::shared_ptr<OnionRequestRouter> router) {
        return router->_cached_edge_nodes;
    }

    static void drop_struck_cached_edge_nodes(std::shared_ptr<OnionRequestRouter> router) {
        router->_drop_struck_cached_edge_nodes();
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

    static void send_on_path(
            std::shared_ptr<OnionRequestRouter> router,
            OnionPath& path,
            Request request,
            network_response_callback_t callback) {
        router->_send_on_path(path, std::move(request), std::move(callback));
    }

    static void rotate_path(
            std::shared_ptr<OnionRequestRouter> router,
            const std::string& path_id,
            PathCategory category) {
        router->_rotate_path(path_id, category);
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
        TestRequestQueue(std::shared_ptr<oxen::quic::Loop> loop) : detail::RequestQueue(loop) {};

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
                std::shared_ptr<oxen::quic::Loop> loop,
                std::shared_ptr<oxen::quic::Loop> disk_loop,
                network_fetcher_t direct_fetcher = [](Request, network_response_callback_t) {}) :
                SnodePool(
                        std::move(config),
                        std::move(loop),
                        std::move(disk_loop),
                        std::move(direct_fetcher)) {}

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

        // When set, `refresh_if_needed` calls back with it straight away - as the real one does, on
        // the loop thread, when nothing needs refreshing - instead of never calling back.  Only the
        // first `max_refresh_callbacks` calls do, so code that asks again on every callback stops
        // there instead of recursing until the stack gives out.
        std::optional<bool> refresh_result;
        int max_refresh_callbacks = 20;

        void refresh_if_needed(
                const std::vector<service_node>& /*in_use_nodes*/,
                refresh_callback_t on_refresh_complete = nullptr) override {
            func_called("refresh_if_needed");
            // Don't trigger a real cache refresh
            if (refresh_result && on_refresh_complete &&
                get_call_count("refresh_if_needed") <= max_refresh_callbacks)
                on_refresh_complete(*refresh_result);
        }

        void get_swarm(
                session::network::x25519_pubkey /*swarm_pubkey*/,
                bool /*ignore_strike_count*/,
                std::function<void(swarm::swarm_id_t, std::vector<service_node>)> /*callback*/)
                override {
            func_called("get_swarm");
            // Do nothing (don't want to trigger a cache refresh)
        }

        // The `count` of each `get_unused_nodes` call, which the mock result doesn't reflect
        std::vector<size_t> unused_node_counts;

        std::vector<service_node> get_unused_nodes(
                size_t count, const std::vector<service_node>& exclude = {}) override {
            unused_node_counts.push_back(count);
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
                service_node /*node*/,
                std::chrono::milliseconds /*timeout*/,
                const std::string& /*request_id*/,
                const RequestCategory /*category*/,
                std::function<void(bool success, std::optional<uint64_t> error_code)> /*callback*/)
                override {
            func_called("verify_connectivity");
        }
        void add_failure_listener(
                const ed25519_pubkey& /*pubkey*/, std::function<void()> /*listener*/) override {
            func_called("add_failure_listener");
        }
        void remove_failure_listeners(const ed25519_pubkey& /*pubkey*/) override {
            func_called("remove_failure_listeners");
        }

        // Answered the way a node on the path does when it fails a request itself: a status of its
        // own and a plaintext body, which is nothing the destination encrypted
        std::optional<std::pair<int16_t, std::string>> plaintext_reply;

        void send_request(Request /*request*/, network_response_callback_t callback) override {
            func_called("send_request");
            if (plaintext_reply)
                callback(
                        false,
                        false,
                        plaintext_reply->first,
                        {content_type_plain_text},
                        plaintext_reply->second);
        }
    };

    struct Result {
        bool success;
        bool timeout;
        int16_t status_code;
        std::vector<std::pair<std::string, std::string>> headers;
        std::optional<std::string> response;
    };

    config::SnodePool test_pool_config() {
        return {.cache_directory = std::nullopt,
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
    }

    config::OnionRequestRouter test_router_config() {
        return {.file_server_config = file_server::DEFAULT_CONFIG,
                .cache_directory = std::nullopt,
                .edge_node_cache_duration = std::chrono::days{10},
                .netid = opt::netid::Target::testnet,
                .seed_nodes = {},
                .retry_delay = network::opt::retry_delay{50ms, 200ms},
                .path_length = 3,
                .path_strike_threshold = 3,
                .path_build_retry_limit = 10,
                .path_rotation_frequency = 10min,
                .node_strike_threshold = 3,
                .disable_pre_build_paths = true,
                .single_path_mode = true,
                .min_path_counts = {{PathCategory::standard, 1}}};
    }

    service_node test_node(std::string_view pk_hex, uint16_t port) {
        return service_node{
                ed25519_pubkey::from_hex(pk_hex),
                oxen::quic::ipv4{"127.0.0.1"},
                port,
                static_cast<uint16_t>(port + 10000),
                {2, 11, 0},
                0};
    }

    network_response_callback_t record_into(std::optional<Result>& result) {
        return [&result](
                       bool success,
                       bool timeout,
                       int16_t status_code,
                       std::vector<std::pair<std::string, std::string>> headers,
                       std::optional<std::string> response) {
            result = {success, timeout, status_code, headers, response};
        };
    }
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
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    auto ed_pk2 = "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hexbytes;
    auto ed_pk3 = "e17a692033200ae41350df9709754edde7343e2cf2f23e88f993319e0720e5e5"_hexbytes;
    auto ed_pk4 = "7b633fa6fb462b90db6f0f50384190ce7715e31b7aa93d87dbd7e94e33d4251f"_hexbytes;
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
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, loop, disk_loop);
    auto transport = std::make_shared<TestTransport>();
    std::shared_ptr<OnionRequestRouter> router;

    // We don't give a node a strike by default (require specific error messages to match)
    snode_pool->clear_node_strikes();
    snode_pool->reset_calls();
    path.emplace(OnionPath{"Test", {target2, target3, target4}});
    router = std::make_shared<OnionRequestRouter>(config, loop, disk_loop, snode_pool, transport);
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
    router = std::make_shared<OnionRequestRouter>(config, loop, disk_loop, snode_pool, transport);
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
    router = std::make_shared<OnionRequestRouter>(config, loop, disk_loop, snode_pool, transport);
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
    router = std::make_shared<OnionRequestRouter>(config, loop, disk_loop, snode_pool, transport);
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
    router = std::make_shared<OnionRequestRouter>(config, loop, disk_loop, snode_pool, transport);
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
                config, loop, disk_loop, snode_pool, transport);
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
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, loop, disk_loop);
    auto transport = std::make_shared<TestTransport>();
    std::shared_ptr<OnionRequestRouter> router;

    // Nothing should happen if the network is suspended
    snode_pool->reset_calls();
    router = std::make_shared<OnionRequestRouter>(config, loop, disk_loop, snode_pool, transport);
    router->suspend();
    TestOnionRequestRouter::build_path(router, PathCategory::standard);
    CHECK(snode_pool->did_not_call("get_unused_nodes"));

    // If the unused nodes are empty it refreshes them
    snode_pool->reset_calls();
    router = std::make_shared<OnionRequestRouter>(config, loop, disk_loop, snode_pool, transport);
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
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    auto ed_pk2 = "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hexbytes;
    auto ed_pk3 = "e17a692033200ae41350df9709754edde7343e2cf2f23e88f993319e0720e5e5"_hexbytes;
    auto ed_pk4 = "7b633fa6fb462b90db6f0f50384190ce7715e31b7aa93d87dbd7e94e33d4251f"_hexbytes;
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
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, loop, disk_loop);
    auto transport = std::make_shared<TestTransport>();
    std::shared_ptr<OnionRequestRouter> router;

    // It returns nothing when given no path options
    router = std::make_shared<OnionRequestRouter>(config, loop, disk_loop, snode_pool, transport);
    TestOnionRequestRouter::set_paths(router, PathCategory::standard, {});
    CHECK(TestOnionRequestRouter::find_valid_path(router, request) == nullptr);

    // It excludes paths which include the IP of the target
    router = std::make_shared<OnionRequestRouter>(config, loop, disk_loop, snode_pool, transport);
    TestOnionRequestRouter::set_paths(router, PathCategory::standard, {path1});
    CHECK(TestOnionRequestRouter::find_valid_path(router, request) == nullptr);

    // It returns a path when there is a valid one
    router = std::make_shared<OnionRequestRouter>(config, loop, disk_loop, snode_pool, transport);
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
    router = std::make_shared<OnionRequestRouter>(config, loop, disk_loop, snode_pool, transport);
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
    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
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
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, loop, disk_loop);
    auto transport = std::make_shared<TestTransport>();
    auto queue = std::make_shared<detail::TestRequestQueue>(loop);
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
    router = std::make_shared<OnionRequestRouter>(config, loop, disk_loop, snode_pool, transport);
    queue = std::make_shared<detail::TestRequestQueue>(loop);
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
    router = std::make_shared<OnionRequestRouter>(config, loop, disk_loop, snode_pool, transport);
    queue = std::make_shared<detail::TestRequestQueue>(loop);
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
    router = std::make_shared<OnionRequestRouter>(config, loop, disk_loop, snode_pool, transport);
    queue = std::make_shared<detail::TestRequestQueue>(loop);
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

TEST_CASE("Network", "[network][onion_request_router][cached_edge_nodes]") {
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

    auto ed_pk = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"_hexbytes;
    auto ed_pk2 = "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"_hexbytes;
    auto healthy = service_node{
            ed25519_pubkey::from_bytes(ed_pk),
            oxen::quic::ipv4{"127.0.0.1"},
            20001,
            30001,
            {2, 11, 0},
            0};
    auto struck = service_node{
            ed25519_pubkey::from_bytes(ed_pk2),
            oxen::quic::ipv4{"127.0.0.2"},
            20002,
            30002,
            {2, 11, 0},
            0};

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(pool_config, loop, disk_loop);
    auto transport = std::make_shared<TestTransport>();
    auto router =
            std::make_shared<OnionRequestRouter>(config, loop, disk_loop, snode_pool, transport);

    auto now = std::chrono::system_clock::now();
    TestOnionRequestRouter::set_cached_edge_nodes(
            router, {cached_edge_node{healthy, now}, cached_edge_node{struck, now}});

    // Both are well inside `edge_node_cache_duration`, which is the only thing that used to matter
    TestOnionRequestRouter::drop_struck_cached_edge_nodes(router);
    CHECK(TestOnionRequestRouter::cached_edge_nodes(router).size() == 2);

    // A cached edge node is forced as a path's first hop without going through `get_unused_nodes`,
    // so nothing else would apply the strike filter to it.  Striking it out has to cost it the
    // cached-edge role outright - skipping it while keeping the entry would hand the role back when
    // the strikes expire, long after we moved to another edge node.
    snode_pool->SnodePool::record_node_failure(struck, true);
    REQUIRE(snode_pool->node_struck_out(struck));

    // Only the cached-edge role is lost; nothing here touches `_snode_cache`, so it stays a node
    // like any other and `get_unused_nodes` can pick it again when its strikes expire
    TestOnionRequestRouter::drop_struck_cached_edge_nodes(router);
    auto remaining = TestOnionRequestRouter::cached_edge_nodes(router);
    REQUIRE(remaining.size() == 1);
    CHECK(remaining.front().node == healthy);
}

TEST_CASE("Network", "[network][onion_request_router][undecrypted_response]") {
    auto target =
            test_node("4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7", 20001);
    auto path_nodes = std::vector<service_node>{
            test_node("5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876", 20002),
            test_node("e17a692033200ae41350df9709754edde7343e2cf2f23e88f993319e0720e5e5", 20003),
            test_node("7b633fa6fb462b90db6f0f50384190ce7715e31b7aa93d87dbd7e94e33d4251f", 20004)};

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(test_pool_config(), loop, disk_loop);
    auto transport = std::make_shared<TestTransport>();
    auto router = std::make_shared<OnionRequestRouter>(
            test_router_config(), loop, disk_loop, snode_pool, transport);

    // The router is driven on the loop, as its own code is, and checked from here
    loop->call_get([&] {
        TestOnionRequestRouter::set_paths(
                router, PathCategory::standard, {OnionPath{"Test", path_nodes}});
    });

    auto send_with_reply = [&](int16_t status) {
        transport->plaintext_reply.emplace(status, "Forged by a node on the path");
        auto request = Request{
                "AAAA", target, "retrieve", to_vector("{}"), RequestCategory::standard, 10s};

        bool have_path = false;
        std::optional<Result> result;
        loop->call_get([&] {
            if (auto* path = TestOnionRequestRouter::find_valid_path(router, request)) {
                have_path = true;
                TestOnionRequestRouter::send_on_path(router, *path, request, record_into(result));
            }
        });
        REQUIRE(have_path);
        REQUIRE(result);
        return *result;
    };

    // Each of these is acted on as the destination's verdict (a swarm redirect, a clock resync),
    // which only the destination can give; a node on the path sending one mustn't pass for it
    for (int16_t status : {ERROR_MISDIRECTED_REQUEST, ERROR_NOT_ACCEPTABLE, ERROR_TOO_EARLY}) {
        CAPTURE(status);
        auto result = send_with_reply(status);
        CHECK_FALSE(result.success);
        CHECK(result.status_code == ERROR_UNAUTHENTICATED_RESPONSE);
        CHECK(result.response.value_or("").find("status {}"_format(status)) != std::string::npos);
    }

    // Anything else a node on the path says about its own failure is reported as it was
    auto result = send_with_reply(502);
    CHECK_FALSE(result.success);
    CHECK(result.status_code == 502);
}

TEST_CASE("Network", "[network][onion_request_router][build_path_too_few_nodes]") {
    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(test_pool_config(), loop, disk_loop);
    auto transport = std::make_shared<TestTransport>();
    auto router = std::make_shared<OnionRequestRouter>(
            test_router_config(), loop, disk_loop, snode_pool, transport);

    // Run on the loop, as the router's own code is: that also puts it after the router's setup,
    // which asks for the (empty) pool to be refreshed and mustn't be counted below
    std::optional<Result> result;
    loop->call_get([&] {
        snode_pool->reset_calls();

        auto queue = std::make_shared<detail::TestRequestQueue>(loop);
        TestOnionRequestRouter::set_request_queues(router, {{PathCategory::standard, queue}});
        queue->add(
                Request{"AAAA",
                        test_node(
                                "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7",
                                20001),
                        "retrieve",
                        to_vector("{}"),
                        RequestCategory::standard,
                        10s},
                record_into(result));

        // A path needs three nodes and the pool can only offer one, while saying nothing needs
        // refreshing - which is a pool too concentrated in a few subnets to fill a path, say
        snode_pool->mock_unused_nodes = std::vector{test_node(
                "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876", 20002)};
        snode_pool->refresh_result = true;

        TestOnionRequestRouter::build_path(router, PathCategory::standard, "AAAA");
    });

    // Asking for a refresh once and then giving up; without checking that the pool can now fill a
    // path, every "refreshed" rebuilt straight into another refresh request, and only the mock's
    // limit stops it
    CHECK(snode_pool->get_call_count("refresh_if_needed") == 1);
    REQUIRE(result);
    CHECK_FALSE(result->success);
    CHECK(result->status_code == ERROR_INSUFFICIENT_NODES);
    CHECK(result->response.value_or("").find("too few usable nodes") != std::string::npos);
}

TEST_CASE("Network", "[network][onion_request_router][rotate_path]") {
    auto key1 = "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7"sv;
    auto key2 = "5ea34e72bb044654a6a23675690ef5ffaaf1656b02f93fb76655f9cbdbe89876"sv;
    auto key3 = "e17a692033200ae41350df9709754edde7343e2cf2f23e88f993319e0720e5e5"sv;
    auto key4 = "7b633fa6fb462b90db6f0f50384190ce7715e31b7aa93d87dbd7e94e33d4251f"sv;
    auto edge = test_node(key1, 20001);
    auto path_nodes = std::vector{edge, test_node(key2, 20002), test_node(key3, 20003)};

    auto loop = std::make_shared<oxen::quic::Loop>();
    auto disk_loop = std::make_shared<oxen::quic::Loop>();
    auto snode_pool = std::make_shared<TestSnodePool>(test_pool_config(), loop, disk_loop);
    auto transport = std::make_shared<TestTransport>();
    auto config = test_router_config();
    auto router =
            std::make_shared<OnionRequestRouter>(config, loop, disk_loop, snode_pool, transport);
    snode_pool->mock_unused_nodes =
            std::vector{test_node(key2, 20012), test_node(key3, 20013), test_node(key4, 20014)};

    // Rotates a path whose edge node was connected just now, so well inside
    // `edge_node_cache_duration`, and returns what the rotation asked the pool for.  The first
    // request says which it chose: a whole new path, or the rest of one that keeps the edge node.
    auto rotate = [&] {
        std::vector<size_t> counts;
        loop->call_get([&] {
            auto now = std::chrono::system_clock::now();
            TestOnionRequestRouter::set_paths(
                    router, PathCategory::standard, {OnionPath{"Test", path_nodes, now, now}});
            snode_pool->unused_node_counts.clear();
            TestOnionRequestRouter::rotate_path(router, "Test", PathCategory::standard);
            counts = snode_pool->unused_node_counts;
        });
        return counts;
    };

    auto kept = rotate();
    REQUIRE_FALSE(kept.empty());
    CHECK(kept.front() == config.path_length - 1u);

    // Struck out since we connected to it, the edge node is replaced along with the rest
    snode_pool->record_node_failure(edge, true);
    auto replaced = rotate();
    REQUIRE_FALSE(replaced.empty());
    CHECK(replaced.front() == config.path_length);
}
}  // namespace session::network
