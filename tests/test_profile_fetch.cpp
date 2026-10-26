#include <oxenc/base64.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <nlohmann/json.hpp>
#include <session/config/user_profile.hpp>
#include <session/core.hpp>
#include <thread>

#include "test_helper.hpp"

using namespace session;
using namespace std::literals;

namespace {

/// Longer than the fetch's grace window, so a wait of this long has seen it close.
constexpr auto PAST_THE_WINDOW = 800ms;

constexpr auto USER_PROFILE = static_cast<int16_t>(config::Namespace::UserProfile);

/// A swarm of `n` members with distinct keys, so each keeps a retrieve cursor of its own.
std::vector<network::service_node> swarm_of(size_t n) {
    std::vector<network::service_node> swarm(n);
    for (size_t i = 0; i < n; i++)
        swarm[i].remote_pubkey[0] = std::byte(i + 1);
    return swarm;
}

/// Another device of the same account, descending from what this one has already published: a
/// device built from nothing would land on our own seqno and be a merge of two histories, which is
/// not what this fetch is about.
///
/// Our side is read on Core's loop, the only thread allowed to touch its configs.  The other device
/// is a plain config object of the test's own, and needs no such care.
config::UserProfile another_device(TempCore& c) {
    auto dump = TestHelper::on_loop(*c, [&] {
        auto& ours = c->configs.user_profile();
        auto [seqno, messages, obsolete] = ours.push();
        ours.confirm_pushed(seqno, {"seededprofile"});
        c->configs.store_dumps();
        return ours.make_dump();
    });
    auto seed = c->globals.account_seed();
    return config::UserProfile{seed.ed25519_secret(), dump};
}

/// The profile name this Core holds, read where it is allowed to be read and copied out.
std::optional<std::string> name_of(TempCore& c) {
    return TestHelper::on_loop(*c, [&]() -> std::optional<std::string> {
        auto name = c->configs.user_profile().get_name();
        return name ? std::optional<std::string>{std::string{*name}} : std::nullopt;
    });
}

/// What that device pushes after renaming itself.
std::vector<std::vector<std::byte>> renamed(config::UserProfile& theirs, std::string_view name) {
    theirs.set_name(name);
    auto [seqno, messages, obsolete] = theirs.push();
    theirs.confirm_pushed(seqno, {"pushed{}"_format(seqno)});
    return messages;
}

/// A member's answer to the fetch's single retrieve, carrying `messages` under `hash`.
std::string answer(const std::vector<std::vector<std::byte>>& messages, std::string_view hash) {
    auto body = retrieved_body();
    for (const auto& m : messages)
        body["messages"].push_back(retrieved_message(m, hash));
    return nlohmann::json{{"results", {{{"code", 200}, {"body", std::move(body)}}}}}.dump();
}

std::string empty_answer() {
    return answer({}, "");
}

/// The fetch's request to each member, in the order they were sent.
std::vector<MockNetwork::SentRequest> sent_to_each(MockNetwork& net) {
    return std::exchange(net.sent_requests, {});
}

void reply(TempCore& c, MockNetwork::SentRequest& to, std::string body) {
    to.callback(true, false, 200, {}, std::move(body));
    TestHelper::drain(*c);
}

}  // namespace

TEST_CASE("Profile fetch: a stale first config is overtaken inside the window", "[core][profile]") {
    TempCore c;
    auto* net = attach_mock_network(*c);
    net->current_swarm = swarm_of(3);
    auto theirs = another_device(c);
    auto older = renamed(theirs, "Stale");
    auto newer = renamed(theirs, "Current");

    int calls = 0;
    bool found = false;
    c->fetch_user_profile([&](bool f) {
        calls++;
        found = f;
    });
    TestHelper::drain(*c);
    auto sent = sent_to_each(*net);
    REQUIRE(sent.size() == 3);

    // The first member is behind its swarm.  Its config is merged, and the fetch does not report on
    // it: that is the whole point of the window.
    reply(c, sent[0], answer(older, "h-old"));
    CHECK(name_of(c) == "Stale");
    CHECK(calls == 0);

    // A second member has the newer one, inside the window.
    reply(c, sent[1], answer(newer, "h-new"));
    CHECK(name_of(c) == "Current");
    CHECK(calls == 0);

    // The third never answers; the window closes on its own.
    std::this_thread::sleep_for(PAST_THE_WINDOW);
    TestHelper::drain(*c);
    CHECK(calls == 1);
    CHECK(found);
    CHECK(name_of(c) == "Current");
}

TEST_CASE("Profile fetch: a config arriving after it reported is still merged", "[core][profile]") {
    TempCore c;
    auto* net = attach_mock_network(*c);
    net->current_swarm = swarm_of(2);
    auto theirs = another_device(c);
    auto older = renamed(theirs, "Stale");
    auto newer = renamed(theirs, "Current");

    int calls = 0;
    c->fetch_user_profile([&](bool) { calls++; });
    TestHelper::drain(*c);
    auto sent = sent_to_each(*net);
    REQUIRE(sent.size() == 2);

    reply(c, sent[0], answer(older, "h-old"));
    std::this_thread::sleep_for(PAST_THE_WINDOW);
    TestHelper::drain(*c);
    REQUIRE(calls == 1);

    // Too late to be reported, not too late to count: it came from our own swarm, and dropping it
    // would only leave the next poll to fetch it again.
    reply(c, sent[1], answer(newer, "h-new"));
    CHECK(name_of(c) == "Current");
    CHECK(calls == 1);

    // And the cursor is written against the member that gave it, not the one that was first.
    CHECK(TestHelper::namespace_last_hash(*c, USER_PROFILE, net->current_swarm[1].remote_pubkey) ==
          "h-new");
    CHECK(TestHelper::namespace_last_hash(*c, USER_PROFILE, net->current_swarm[0].remote_pubkey) ==
          "h-old");
}

TEST_CASE(
        "Profile fetch: the window closes early once every member has answered",
        "[core][profile]") {
    TempCore c;
    auto* net = attach_mock_network(*c);
    net->current_swarm = swarm_of(2);
    auto theirs = another_device(c);
    auto config = renamed(theirs, "Current");

    int calls = 0;
    bool found = false;
    c->fetch_user_profile([&](bool f) {
        calls++;
        found = f;
    });
    TestHelper::drain(*c);
    auto sent = sent_to_each(*net);
    REQUIRE(sent.size() == 2);

    reply(c, sent[0], answer(config, "h1"));
    CHECK(calls == 0);
    // Nobody is left to wait for, so there is no reason to sit out the rest of the window.
    reply(c, sent[1], empty_answer());
    CHECK(calls == 1);
    CHECK(found);

    // Nor does the window's own end report a second time.
    std::this_thread::sleep_for(PAST_THE_WINDOW);
    TestHelper::drain(*c);
    CHECK(calls == 1);
}

TEST_CASE("Profile fetch: every member empty concludes with nothing found", "[core][profile]") {
    TempCore c;
    auto* net = attach_mock_network(*c);
    net->current_swarm = swarm_of(3);

    int calls = 0;
    bool found = true;
    c->fetch_user_profile([&](bool f) {
        calls++;
        found = f;
    });
    TestHelper::drain(*c);
    auto sent = sent_to_each(*net);
    REQUIRE(sent.size() == 3);

    // An empty answer never ends the fetch on its own, however many give it...
    reply(c, sent[0], empty_answer());
    reply(c, sent[1], empty_answer());
    CHECK(calls == 0);

    // ...and the last one does, at once: there is no window, since nothing opened one.
    reply(c, sent[2], empty_answer());
    CHECK(calls == 1);
    CHECK_FALSE(found);
}

TEST_CASE("Profile fetch: every member is asked with a signed retrieve", "[core][profile]") {
    TempCore c;
    auto* net = attach_mock_network(*c);
    net->current_swarm = swarm_of(2);

    c->fetch_user_profile([](bool) {});
    TestHelper::drain(*c);
    auto sent = sent_to_each(*net);
    REQUIRE(sent.size() == 2);

    for (auto& request : sent) {
        auto batch = parse_json(*request.request.body);
        REQUIRE(batch["requests"].size() == 1);
        auto params = batch["requests"][0]["params"];
        CHECK(params["namespace"] == USER_PROFILE);
        CHECK(params.contains("signature"));
        CHECK(params.contains("pubkey_ed25519"));
        CHECK(params.contains("timestamp"));
        // No cursor: this asks members that may never have been asked before, so resuming from
        // any one member's position would ask the wrong question.
        CHECK_FALSE(params.contains("last_hash"));
    }
}
