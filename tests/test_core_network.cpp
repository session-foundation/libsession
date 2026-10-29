#include <session/network/session_network.h>

#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <mutex>
#include <session/core.hpp>
#include <session/network/session_network.hpp>
#include <thread>

#include "test_helper.hpp"
#include "utils.hpp"

using namespace session;

TEST_CASE("Core can hold an optional Network interface", "[core][network]") {
    core::callbacks callbacks;
    auto db_path = std::filesystem::temp_directory_path() / "test_core_network.db";
    if (std::filesystem::exists(db_path))
        std::filesystem::remove(db_path);

    core::Core core{db_path, callbacks};

    SECTION("Network is initially null") {
        CHECK(core.network() == nullptr);
    }

    SECTION("Network can be set and retrieved") {
        network::Network* attached = nullptr;
        core.set_network([&](network::NetworkHooks hooks) {
            auto network =
                    std::make_unique<network::Network>(network::config::Config{}, std::move(hooks));
            attached = network.get();
            return network;
        });
        CHECK(core.network() == attached);
    }

    SECTION("make_network refuses hooks that are Core's own") {
        CHECK_THROWS_AS(
                core.make_network(
                        network::config::Config{},
                        network::NetworkHooks{
                                .connection_lost = [](const network::ed25519_pubkey&) {}}),
                std::invalid_argument);
        CHECK(core.network() == nullptr);
    }

    if (std::filesystem::exists(db_path))
        std::filesystem::remove(db_path);
}

TEST_CASE("Core::make_network passes the owner's hooks through", "[core][network][hooks]") {
    // Before the Core, which outlives anything declared after it: its Network reports a final
    // status as it is torn down.  Locked because a real Network reports its own changes on its
    // loop too, while the test reads.
    std::mutex lock;
    std::vector<network::ConnectionStatus> seen;
    auto saw = [&](network::ConnectionStatus status) {
        std::lock_guard l{lock};
        return std::ranges::find(seen, status) != seen.end();
    };

    TempCore core;
    auto& net = core->make_network(
            network::config::Config{},
            network::NetworkHooks{.status_changed = [&](network::ConnectionStatus status) {
                std::lock_guard l{lock};
                seen.push_back(status);
            }});

    // Connected is what a Network with no seed nodes never reaches by itself.
    TestHelper::network_status(net, network::ConnectionStatus::connected);
    CHECK(saw(network::ConnectionStatus::connected));
}

TEST_CASE("A Network calls the hooks it was built with, on its loop", "[network][hooks]") {
    using network::ConnectionStatus;

    // Connected is what a Network with no seed nodes never reaches by itself, so it can only be
    // the one reported here.  Waited for by `network_status`, so nothing races the read.
    std::optional<std::thread::id> called_on;
    MockNetwork net{
            network::config::Config{},
            network::NetworkHooks{.status_changed = [&](ConnectionStatus status) {
                if (status == ConnectionStatus::connected)
                    called_on = std::this_thread::get_id();
            }}};

    TestHelper::network_status(net, ConnectionStatus::connected);
    REQUIRE(called_on);
    CHECK(*called_on != std::this_thread::get_id());
}

TEST_CASE(
        "A Network tells its owner it has gone, and nothing more, as it is torn down",
        "[network][hooks]") {
    using network::ConnectionStatus;

    std::vector<ConnectionStatus> seen;
    std::optional<bool> others_left;
    network::Network* raw = nullptr;
    auto net = std::make_unique<MockNetwork>(
            network::config::Config{},
            network::NetworkHooks{
                    .status_changed =
                            [&](ConnectionStatus status) {
                                seen.push_back(status);
                                if (status == ConnectionStatus::disconnected)
                                    others_left = TestHelper::has_hooks_besides_status(*raw);
                            },
                    .network_info_changed = [](std::chrono::milliseconds, int, int) {},
                    .server_push = [](const network::ed25519_pubkey&,
                                      std::string_view,
                                      std::span<const std::byte>) {},
                    .connection_established = [](const network::ed25519_pubkey&) {},
                    .connection_lost = [](const network::ed25519_pubkey&) {}});
    raw = net.get();

    TestHelper::network_status(*net, ConnectionStatus::connected);
    net.reset();

    // Read once the Network is gone, so nothing races it.  It may have reported connecting by
    // itself before any of this.
    REQUIRE(seen.size() >= 2);
    CHECK(seen[seen.size() - 2] == ConnectionStatus::connected);
    CHECK(seen.back() == ConnectionStatus::disconnected);
    // Asked as the final status was reported, which is before the transport closed anything.
    CHECK(others_left == false);
}

TEST_CASE(
        "The C API's network callbacks can be set and cleared while it runs", "[network][hooks]") {
    auto config = session_network_config_default();
    network_object* net = nullptr;
    char error[256];
    REQUIRE(session_network_init(&net, &config, error));

    std::vector<CONNECTION_STATUS> seen;
    auto record = [](CONNECTION_STATUS status, void* ctx) {
        static_cast<std::vector<CONNECTION_STATUS>*>(ctx)->push_back(status);
    };

    SECTION("a callback set after init hears the final status") {
        session_network_set_status_changed_callback(net, record, &seen);
        session_network_free(net);
        // A real network, so it may already have started connecting.
        REQUIRE_FALSE(seen.empty());
        CHECK(seen.back() == CONNECTION_STATUS_DISCONNECTED);
    }

    SECTION("a cleared callback hears nothing") {
        session_network_set_status_changed_callback(net, record, &seen);
        session_network_set_status_changed_callback(net, nullptr, nullptr);
        session_network_free(net);
        // It may have heard connecting before it was cleared, but not the final status after.
        CHECK(std::ranges::find(seen, CONNECTION_STATUS_DISCONNECTED) == seen.end());
    }
}
