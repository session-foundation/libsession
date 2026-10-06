#include <session/network/session_network.h>

#include <catch2/catch_test_macros.hpp>
#include <session/network/network_config.hpp>

using namespace session::network;

TEST_CASE("Network config: QUIC UDP payload cap", "[network][config][quic]") {
    SECTION("unset by default") {
        config::Config cfg{opt::quic_keep_alive{std::chrono::seconds{10}}};
        CHECK_FALSE(cfg.quic_max_udp_payload.has_value());
    }
    SECTION("explicit cap") {
        config::Config cfg{opt::quic_max_udp_payload{1400}};
        REQUIRE(cfg.quic_max_udp_payload.has_value());
        CHECK(*cfg.quic_max_udp_payload == 1400);
    }
    SECTION("disable_mtu_discovery is a 1200-byte cap") {
        config::Config cfg{opt::quic_disable_mtu_discovery{}};
        REQUIRE(cfg.quic_max_udp_payload.has_value());
        CHECK(*cfg.quic_max_udp_payload == 1200);
    }
    SECTION("below the QUIC minimum is rejected") {
        CHECK_THROWS_AS(config::Config{opt::quic_max_udp_payload{1199}}, std::invalid_argument);
        CHECK_NOTHROW(config::Config{opt::quic_max_udp_payload{1200}});
    }
    SECTION("C defaults leave it uncapped") {
        auto c = session_network_config_default();
        CHECK(c.quic_max_udp_payload == 0);
        CHECK_FALSE(c.quic_disable_mtu_discovery);
    }
}
