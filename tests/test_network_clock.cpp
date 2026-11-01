#include <catch2/catch_test_macros.hpp>
#include <session/network/session_network.hpp>
#include <vector>

#include "test_helper.hpp"
#include "utils.hpp"

using namespace session;
using namespace std::literals;

namespace {

std::optional<std::chrono::milliseconds> resync(
        std::vector<std::optional<std::chrono::milliseconds>> measured,
        std::chrono::milliseconds min_offset = 5s) {
    return network::detail::resync_offset(measured, min_offset);
}

}  // namespace

TEST_CASE("Network clock: a resync applies the median of what its requests measured", "[network]") {
    CHECK(resync({30s, 10s, 20s}) == 20s);
    CHECK(resync({10s, 40s, 20s, 30s}) == 25s);
    CHECK(resync({-20s, -40s, -30s}) == -30s);

    // A failed request is left out of the median rather than counted as no offset.
    CHECK(resync({std::nullopt, 10s, 20s}) == 15s);
    CHECK(resync({std::nullopt, 12s, std::nullopt}) == 12s);
}

TEST_CASE("Network clock: a resync whose requests all failed changes nothing", "[network]") {
    CHECK(resync({std::nullopt, std::nullopt, std::nullopt}) == std::nullopt);
    CHECK(resync({}) == std::nullopt);
}

TEST_CASE(
        "Network clock: a median offset smaller than the minimum leaves the device clock alone",
        "[network]") {
    // Each node a second or so out from a device that keeps good time: noise, not drift.
    CHECK(resync({1200ms, -300ms, 900ms}) == 0ms);
    CHECK(resync({-4999ms, -4999ms, -4999ms}) == 0ms);

    // The median decides, not any one node: a single node far out does not move the clock.
    CHECK(resync({800ms, 1h, -200ms}) == 0ms);

    // At the minimum and beyond it, in either direction, the offset is applied.
    CHECK(resync({5s, 5s, 5s}) == 5s);
    CHECK(resync({-6s, -7s, -8s}) == -7s);

    // A minimum of zero applies every offset.
    CHECK(resync({1ms, 2ms, 3ms}, 0ms) == 2ms);
}

TEST_CASE("Network clock: the default minimum offset is five seconds", "[network]") {
    CHECK(network::config::Config{}.min_network_offset == 5s);
    CHECK(network::config::Config{network::opt::min_network_offset{2s}}.min_network_offset == 2s);
}

TEST_CASE("Network clock: a resync sets the offset and reports it to the client", "[network]") {
    ScopedClockOffset restore{0ms};
    network::Network net{network::config::Config{}};

    std::optional<std::chrono::milliseconds> reported;
    net.on_network_info_changed = [&](std::chrono::milliseconds offset, int, int) {
        reported = offset;
    };

    // Not retrieved until a resync has succeeded, and a resync whose requests all failed has not.
    CHECK_FALSE(net.has_retrieved_time_offset());
    TestHelper::finish_clock_resync(net, {std::nullopt, std::nullopt, std::nullopt});
    CHECK_FALSE(net.has_retrieved_time_offset());
    CHECK_FALSE(reported);

    TestHelper::finish_clock_resync(net, {-8s, -7s, -9s});
    CHECK(net.has_retrieved_time_offset());
    CHECK(net.network_time_offset() == -8s);
    CHECK(reported == -8s);

    // The device's clock has been fixed: the offset goes back to zero rather than staying put, and
    // the client hears about it.
    TestHelper::finish_clock_resync(net, {400ms, -100ms, 1s});
    CHECK(net.has_retrieved_time_offset());
    CHECK(net.network_time_offset() == 0ms);
    CHECK(reported == 0ms);
}
