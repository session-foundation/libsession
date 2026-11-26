#include <catch2/catch_test_macros.hpp>
#include <session/network/network_config.hpp>

using namespace session::network;

TEST_CASE("Network config: QUIC congestion control", "[network][config][quic]") {
    SECTION("unset by default") {
        config::Config cfg{opt::quic_keep_alive{std::chrono::seconds{10}}};
        CHECK_FALSE(cfg.quic_congestion_control.has_value());
    }
    SECTION("explicit algorithm") {
        config::Config cfg{opt::quic_congestion_control::bbr};
        REQUIRE(cfg.quic_congestion_control.has_value());
        CHECK(*cfg.quic_congestion_control == opt::quic_congestion_control::bbr);
    }
}
