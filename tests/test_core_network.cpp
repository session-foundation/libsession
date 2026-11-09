#include <catch2/catch_test_macros.hpp>
#include <session/core.hpp>
#include <session/network/network_config.hpp>
#include <session/network/session_network.hpp>

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
        auto network = std::make_unique<network::Network>(network::config::Config{});
        auto* attached = network.get();
        core.set_network(std::move(network));
        CHECK(core.network() == attached);
    }

    if (std::filesystem::exists(db_path))
        std::filesystem::remove(db_path);
}

TEST_CASE("Network: a one-shot config implies the onion one-shot settings", "[network]") {
    // Whichever order the options come in: the onion router reads only its own two flags.
    network::config::Config before{network::opt::one_shot{}, network::opt::path_length{2}};
    network::config::Config after{network::opt::path_length{2}, network::opt::one_shot{}};
    for (auto* cfg : {&before, &after}) {
        CHECK(cfg->one_shot);
        CHECK(cfg->onionreq_single_path_mode);
        CHECK(cfg->onionreq_disable_pre_build_paths);
    }

    network::config::Config ordinary{network::opt::path_length{2}};
    CHECK_FALSE(ordinary.one_shot);
    CHECK_FALSE(ordinary.onionreq_single_path_mode);
}
