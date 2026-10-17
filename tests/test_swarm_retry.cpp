#include <catch2/catch_test_macros.hpp>
#include <session/core.hpp>
#include <session/network/session_network.hpp>

#include "test_helper.hpp"

using namespace session;
using namespace session::network;
using namespace std::literals;

// Re-aiming a swarm request is Core's, not Network's: only Core can know whether being answered by
// a different member matters to it, and a substitution made below Core is invisible to the
// bookkeeping that depends on it.  These drive it through the poll, which is a real caller rather
// than a harness, so what is asserted is the behaviour a caller actually gets.

namespace {

std::string key_hex(uint8_t n) {
    return fmt::format("{:02x}{}", n, std::string(62, '0'));
}

service_node node_at(uint8_t n) {
    return service_node{
            ed25519_pubkey::from_hex(key_hex(n)),
            oxen::quic::ipv4{127, 0, 0, 1},
            static_cast<uint16_t>(1000 + n),
            static_cast<uint16_t>(2000 + n),
            {2, 8, 0},
            0,
            0};
}

/// Who each poll was addressed to, in order.  Polls only, because a poll that completes goes on to
/// push the device group, which walks the members as a separate operation of its own.
std::vector<ed25519_pubkey> tried(const MockNetwork& net) {
    std::vector<ed25519_pubkey> out;
    for (const auto& s : net.sent_requests)
        if (s.request.endpoint == "batch")
            out.push_back(std::get<service_node>(s.request.destination).remote_pubkey);
    return out;
}

/// Whether every entry is distinct -- what "once per member" means, given get_swarm hands members
/// back in a shuffled order rather than a fixed one.
bool all_distinct(std::vector<ed25519_pubkey> keys) {
    std::ranges::sort(keys, [](const auto& a, const auto& b) { return a.hex() < b.hex(); });
    return std::ranges::adjacent_find(keys) == keys.end();
}

/// A batch response that says nothing was found, so a poll treats the member as drained.
std::string empty_batch(const Request& req) {
    auto batch = parse_json(*req.body);
    auto results = nlohmann::json::array();
    for (size_t i = 0; i < batch["requests"].size(); i++)
        results.push_back({{"code", 200}, {"body", {{"messages", nlohmann::json::array()}}}});
    return nlohmann::json{{"results", std::move(results)}}.dump();
}

struct PollFixture {
    TempCore core;
    MockNetwork* net;

    explicit PollFixture(size_t members) : net{attach_mock_network(*core)} {
        for (size_t i = 0; i < members; i++)
            net->current_swarm.push_back(node_at(static_cast<uint8_t>(i + 1)));
    }

    void poll() { TestHelper::poll(*core); }
};

}  // namespace

TEST_CASE("Core: an unreachable member moves the request to the next one", "[core][swarm]") {
    PollFixture f{4};

    // Only one member is reachable; the rest have no relay contact, which is what session routing
    // reports as an invalid destination rather than as a failure of the request.
    auto reachable = f.net->current_swarm[2].remote_pubkey;
    f.net->auto_reply = [&](const Request& req) -> std::optional<MockNetwork::Reply> {
        if (std::get<service_node>(req.destination).remote_pubkey == reachable)
            return MockNetwork::Reply{true, false, 200, empty_batch(req)};
        return MockNetwork::Reply{false, false, ERROR_INVALID_DESTINATION, "unreachable"};
    };

    f.poll();

    // It reached the one that works, spending no member twice on the way.  Which it tried first is
    // deliberately not asserted: get_swarm shuffles, so the order is not fixed.
    auto attempts = tried(*f.net);
    REQUIRE(attempts.size() >= 2);
    CHECK(attempts.size() <= f.net->current_swarm.size());
    CHECK(attempts.back() == reachable);
    CHECK(all_distinct(attempts));
}

TEST_CASE("Core: running out of members ends the walk", "[core][swarm]") {
    PollFixture f{3};

    f.net->auto_reply = [](const Request&) -> std::optional<MockNetwork::Reply> {
        return MockNetwork::Reply{false, false, ERROR_INVALID_DESTINATION, "unreachable"};
    };

    f.poll();

    // Every member tried, once each: it ends when selection has nothing left rather than at a
    // fixed count, and never revisits one already spent.
    auto attempts = tried(*f.net);
    CHECK(attempts.size() == 3);
    CHECK(all_distinct(attempts));
}

TEST_CASE(
        "Core: a failure that is not the member's fault is not retried elsewhere",
        "[core][swarm]") {
    PollFixture f{3};

    // A 500 says the request was carried and the server disliked it.  Asking a different member of
    // the same swarm the same question gets the same answer, so this is not what the walk is for.
    f.net->auto_reply = [](const Request&) -> std::optional<MockNetwork::Reply> {
        return MockNetwork::Reply{false, false, 500, "nope"};
    };

    f.poll();

    CHECK(tried(*f.net).size() == 1);
}

TEST_CASE("Core: a misdirected request is re-aimed at another member", "[core][swarm]") {
    PollFixture f{3};

    // A 421 says this member does not hold the account.  Unlike an unreachable member it says our
    // swarm information was wrong, so Core re-resolves rather than merely stepping along -- but
    // either way the member that said it must not be asked again.
    auto wrong = f.net->current_swarm[0].remote_pubkey;
    f.net->auto_reply = [&](const Request& req) -> std::optional<MockNetwork::Reply> {
        if (std::get<service_node>(req.destination).remote_pubkey == wrong)
            return MockNetwork::Reply{false, false, ERROR_MISDIRECTED_REQUEST, "wrong swarm"};
        return MockNetwork::Reply{true, false, 200, empty_batch(req)};
    };

    f.poll();

    auto attempts = tried(*f.net);
    REQUIRE(attempts.size() >= 1);
    if (attempts.front() == wrong) {
        REQUIRE(attempts.size() == 2);
        CHECK(attempts.back() != wrong);
    }
}

TEST_CASE("Core: redirects are bounded", "[core][swarm]") {
    PollFixture f{3};

    // Every member insists the account is not theirs.  Re-resolving cannot help -- the corrected
    // swarm is the one now rejecting us -- so this has to stop rather than loop.
    f.net->auto_reply = [](const Request&) -> std::optional<MockNetwork::Reply> {
        return MockNetwork::Reply{false, false, ERROR_MISDIRECTED_REQUEST, "wrong swarm"};
    };

    f.poll();

    // Bounded, and bounded low: a handful of attempts, not one per member per round.
    CHECK(tried(*f.net).size() <= 5);
}
