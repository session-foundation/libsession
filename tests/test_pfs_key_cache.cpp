#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>
#include <session/clock.hpp>
#include <session/config/namespaces.hpp>
#include <session/core.hpp>
#include <session/network/session_network.hpp>

#include "test_helper.hpp"
#include "utils.hpp"

using namespace session;
using namespace std::literals;
using core::Core;
using core::MessageEncryption;
using core::MessageSendStatus;
using core::PfsKeyFetch;
using core::PfsKeyState;

namespace {

// Minimal valid SessionProtos::Content protobuf: field 15 (sigTimestamp) = 1.
constexpr auto MINIMAL_CONTENT = "7801"_hex_b;

// The cache stores whole seconds, so a time read back can sit a second either side of the clock
// read beside it.
bool near(std::optional<std::chrono::sys_seconds> t, std::chrono::sys_seconds expected) {
    return t && *t - expected <= 1s && expected - *t <= 1s;
}

// A Core looking up the keys of `remote`, with what it reports recorded.
struct Lookup {
    struct Status {
        int64_t id;
        MessageSendStatus status;
        std::optional<MessageEncryption> encryption;
    };
    std::vector<Status> sends;
    std::vector<PfsKeyFetch> fetched;

    TempCore c{[this] {
        core::callbacks cbs;
        cbs.message_send_status =
                [this](int64_t id, MessageSendStatus s, auto, std::optional<MessageEncryption> e) {
                    sends.push_back({id, s, e});
                };
        cbs.pfs_keys_fetched = [this](std::span<const std::byte, 33>, PfsKeyFetch r) {
            fetched.push_back(r);
        };
        return cbs;
    }()};
    MockNetwork* net = attach_mock_network(*c);

    TempCore remote;
    b33 sid = [this] {
        b33 s;
        std::ranges::copy(remote->globals.session_id(), s.begin());
        return s;
    }();
    std::vector<std::byte> published = remote->devices.build_account_pubkey_message();
    std::pair<std::array<std::byte, 32>, std::array<std::byte, 1184>> keys =
            TestHelper::active_account_pubkeys(*remote);

    core::PfsKeyInfo info() { return c->pfs_key_info(sid); }

    size_t lookups() {
        return std::ranges::count_if(
                net->sent_requests, [](const auto& r) { return r.request.endpoint == "retrieve"; });
    }
    size_t find_key() { return answer_retrieves(*net, {published}); }
    size_t find_nothing() { return answer_retrieves(*net); }
    size_t fail() { return fail_retrieves(*net); }

    int64_t send(bool force_v2 = false) {
        return c->send_dm(
                sid,
                std::as_bytes(std::span{MINIMAL_CONTENT}),
                clock_now_ms(),
                std::nullopt,
                14 * 24h,
                force_v2);
    }
    std::vector<MessageSendStatus> statuses(int64_t id) {
        std::vector<MessageSendStatus> found;
        for (const auto& s : sends)
            if (s.id == id)
                found.push_back(s.status);
        return found;
    }
    // What the send was encrypted with, as reported when it went out; unset while it has not.
    std::optional<MessageEncryption> encryption(int64_t id) {
        for (const auto& s : sends)
            if (s.id == id && s.status == MessageSendStatus::sending)
                return s.encryption;
        return std::nullopt;
    }
};

}  // namespace

TEST_CASE("prefetch_pfs_keys throws without network", "[core][pfs]") {
    TempCore c;
    TempCore remote;
    b33 sid;
    std::ranges::copy(remote->globals.session_id(), sid.begin());
    CHECK_THROWS_AS(c->prefetch_pfs_keys(sid), std::logic_error);
}

TEST_CASE("PFS key cache: a lookup that finds a key", "[core][pfs]") {
    Lookup l;

    CHECK(l.c->prefetch_pfs_keys(l.sid) == PfsKeyState::none);
    REQUIRE(l.lookups() == 1);
    auto req = parse_json(*l.net->sent_requests[0].request.body);
    CHECK(req["pubkey"] == oxenc::to_hex(l.sid));
    CHECK(req["namespace"] == static_cast<int16_t>(config::Namespace::AccountPubkeys));
    CHECK(l.info().fetching);

    REQUIRE(l.find_key() == 1);
    CHECK(l.fetched == std::vector{PfsKeyFetch::new_key});
    auto now = clock_now_s();
    auto info = l.info();
    CHECK(info.state == PfsKeyState::usable);
    CHECK_FALSE(info.fetching);
    CHECK(info.x25519_pub == l.keys.first);
    CHECK(info.mlkem768_pub == l.keys.second);
    CHECK(near(info.checked_at, now));
    CHECK(info.confirmed_at == info.checked_at);
    CHECK(info.cache_expiry == *info.checked_at + Core::PFS_KEY_REFRESH);

    SECTION("used without a lookup until the refresh is due") {
        ScopedClockOffset later{Core::PFS_KEY_REFRESH - 1min};
        CHECK(l.c->prefetch_pfs_keys(l.sid) == PfsKeyState::usable);
        CHECK(l.lookups() == 0);
    }

    SECTION("looked up again once it is, and re-confirmed by finding it unchanged") {
        ScopedClockOffset later{Core::PFS_KEY_REFRESH};
        CHECK(l.info().state == PfsKeyState::refresh_due);
        CHECK(l.c->prefetch_pfs_keys(l.sid) == PfsKeyState::refresh_due);
        REQUIRE(l.lookups() == 1);
        // In flight: a second prefetch joins it.
        CHECK(l.c->prefetch_pfs_keys(l.sid) == PfsKeyState::refresh_due);
        CHECK(l.lookups() == 1);

        REQUIRE(l.find_key() == 1);
        CHECK(l.fetched.back() == PfsKeyFetch::unchanged);
        info = l.info();
        CHECK(info.state == PfsKeyState::usable);
        CHECK(near(info.confirmed_at, clock_now_s()));
    }
}

TEST_CASE("PFS key cache: a lookup that finds nothing", "[core][pfs]") {
    Lookup l;

    SECTION("with no key held: nak, until the empty hold lapses") {
        l.c->prefetch_pfs_keys(l.sid);
        REQUIRE(l.find_nothing() == 1);
        CHECK(l.fetched == std::vector{PfsKeyFetch::not_found});

        auto info = l.info();
        CHECK(info.state == PfsKeyState::nak);
        CHECK(near(info.checked_at, clock_now_s()));
        CHECK_FALSE(info.confirmed_at);
        CHECK_FALSE(info.x25519_pub);
        CHECK(info.cache_expiry == *info.checked_at + Core::PFS_KEY_EMPTY_HOLD);

        CHECK(l.c->prefetch_pfs_keys(l.sid) == PfsKeyState::nak);
        CHECK(l.lookups() == 0);

        ScopedClockOffset later{Core::PFS_KEY_EMPTY_HOLD};
        CHECK(l.c->prefetch_pfs_keys(l.sid) == PfsKeyState::none);
        CHECK(l.lookups() == 1);
        // Still says when it was last checked.
        CHECK(l.info().checked_at == info.checked_at);
    }

    SECTION("with a key confirmed within the empty grace: re-confirmed, and kept going by it") {
        TestHelper::seed_pfs_cache(*l.c, l.sid, l.keys.first, l.keys.second);
        ScopedClockOffset later{Core::PFS_KEY_EMPTY_GRACE - 1min};
        l.c->prefetch_pfs_keys(l.sid);
        REQUIRE(l.find_nothing() == 1);

        auto info = l.info();
        CHECK(info.state == PfsKeyState::usable);
        CHECK(info.x25519_pub == l.keys.first);
        CHECK(near(info.confirmed_at, clock_now_s()));
        CHECK(info.checked_at == info.confirmed_at);
        CHECK(info.cache_expiry == *info.checked_at + Core::PFS_KEY_EMPTY_HOLD);

        // Measured from the re-confirmation, not from when the key was found.
        later.advance(Core::PFS_KEY_EMPTY_GRACE - 1min);
        CHECK(l.c->prefetch_pfs_keys(l.sid) == PfsKeyState::refresh_due);
        REQUIRE(l.find_nothing() == 1);
        CHECK(l.info().state == PfsKeyState::usable);
    }

    SECTION("with a key confirmed longer ago than that: dropped") {
        TestHelper::seed_pfs_cache(*l.c, l.sid, l.keys.first, l.keys.second);
        ScopedClockOffset later{Core::PFS_KEY_EMPTY_GRACE};
        l.c->prefetch_pfs_keys(l.sid);
        REQUIRE(l.find_nothing() == 1);

        auto info = l.info();
        CHECK(info.state == PfsKeyState::nak);
        CHECK_FALSE(info.x25519_pub);
        CHECK_FALSE(info.mlkem768_pub);
        CHECK_FALSE(info.confirmed_at);
        CHECK(near(info.checked_at, clock_now_s()));
    }
}

TEST_CASE("PFS key cache: a lookup that fails", "[core][pfs]") {
    Lookup l;

    SECTION("with nothing held: recorded as checked, and still due") {
        l.c->prefetch_pfs_keys(l.sid);
        REQUIRE(l.fail() == 1);
        CHECK(l.fetched == std::vector{PfsKeyFetch::failed});

        auto info = l.info();
        CHECK(info.state == PfsKeyState::none);
        CHECK_FALSE(info.fetching);
        CHECK(near(info.checked_at, clock_now_s()));
        CHECK_FALSE(info.confirmed_at);

        CHECK(l.c->prefetch_pfs_keys(l.sid) == PfsKeyState::none);
        CHECK(l.lookups() == 1);
    }

    SECTION("after an empty answer: that answer still holds") {
        TestHelper::seed_pfs_nak(*l.c, l.sid);
        auto expiry = l.info().cache_expiry;
        l.c->refetch_pfs_keys(l.sid);
        REQUIRE(l.fail() == 1);
        CHECK(l.info().state == PfsKeyState::nak);
        CHECK(l.info().cache_expiry == expiry);
    }

    SECTION("with a key held") {
        TestHelper::seed_pfs_cache(*l.c, l.sid, l.keys.first, l.keys.second);
        auto confirmed = l.info().confirmed_at;
        REQUIRE(confirmed);

        SECTION("confirmed within the failed grace: used for the failed hold") {
            ScopedClockOffset later{Core::PFS_KEY_FAILED_GRACE - 1min};
            l.c->prefetch_pfs_keys(l.sid);
            REQUIRE(l.fail() == 1);

            auto info = l.info();
            CHECK(info.state == PfsKeyState::usable);
            CHECK(info.confirmed_at == confirmed);
            CHECK(near(info.checked_at, clock_now_s()));
            CHECK(info.cache_expiry == *info.checked_at + Core::PFS_KEY_FAILED_HOLD);

            later.advance(Core::PFS_KEY_FAILED_HOLD);
            CHECK(l.info().state == PfsKeyState::refresh_due);
        }

        SECTION("confirmed longer ago than that: kept, but due") {
            ScopedClockOffset later{Core::PFS_KEY_FAILED_GRACE};
            l.c->prefetch_pfs_keys(l.sid);
            REQUIRE(l.fail() == 1);

            auto info = l.info();
            CHECK(info.state == PfsKeyState::refresh_due);
            CHECK(info.x25519_pub == l.keys.first);
            CHECK(info.confirmed_at == confirmed);
            CHECK(near(info.checked_at, clock_now_s()));
        }

        SECTION("the grace ends a failed hold early when a refetch fails inside it") {
            ScopedClockOffset later{Core::PFS_KEY_FAILED_GRACE - 30s};
            l.c->prefetch_pfs_keys(l.sid);
            REQUIRE(l.fail() == 1);
            REQUIRE(l.info().state == PfsKeyState::usable);

            later.advance(45s);
            REQUIRE(l.info().state == PfsKeyState::usable);
            l.c->refetch_pfs_keys(l.sid);
            REQUIRE(l.fail() == 1);
            auto info = l.info();
            CHECK(info.state == PfsKeyState::refresh_due);
            CHECK(info.x25519_pub == l.keys.first);
        }
    }
}

TEST_CASE("PFS key cache: a response that cannot be read is a failed lookup", "[core][pfs]") {
    Lookup l;
    auto send = l.send();
    REQUIRE(l.lookups() == 1);

    SECTION("no messages array") {
        answer_requests(*l.net, "retrieve", [](MockNetwork::SentRequest& r) {
            r.callback(true, false, 200, {}, R"({"more": false})");
        });
    }
    SECTION("not json") {
        answer_requests(*l.net, "retrieve", [](MockNetwork::SentRequest& r) {
            r.callback(true, false, 200, {}, "not json");
        });
    }

    CHECK(l.fetched == std::vector{PfsKeyFetch::failed});
    // Not stranded: the lookup is over, and the send waits on its retry.
    CHECK_FALSE(l.info().fetching);
    CHECK(l.statuses(send) ==
          std::vector{MessageSendStatus::awaiting_keys, MessageSendStatus::retrying});
    CHECK(TestHelper::pfs_retry_due(*l.c, l.sid));
}

TEST_CASE("PFS key cache: messages that are not valid keys are an empty answer", "[core][pfs]") {
    Lookup l;
    l.c->prefetch_pfs_keys(l.sid);

    SECTION("garbage") {
        REQUIRE(answer_retrieves(*l.net, {to_vector<std::byte>("not a bt-dict"sv)}) == 1);
    }
    SECTION("signed by the wrong account") {
        REQUIRE(answer_retrieves(*l.net, {l.c->devices.build_account_pubkey_message()}) == 1);
    }

    CHECK(l.fetched == std::vector{PfsKeyFetch::not_found});
    CHECK(l.info().state == PfsKeyState::nak);
}

TEST_CASE("pfs_key_info reports the cache, and looks up nothing", "[core][pfs]") {
    Lookup l;

    auto info = l.info();
    CHECK(info.state == PfsKeyState::none);
    CHECK_FALSE(info.x25519_pub);
    CHECK_FALSE(info.checked_at);
    CHECK_FALSE(info.confirmed_at);
    CHECK_FALSE(info.cache_expiry);
    CHECK_FALSE(info.fetching);

    TestHelper::seed_pfs_cache(*l.c, l.sid, l.keys.first, l.keys.second);
    CHECK(l.info().state == PfsKeyState::usable);
    ScopedClockOffset later{Core::PFS_KEY_REFRESH};
    CHECK(l.info().state == PfsKeyState::refresh_due);

    CHECK(l.lookups() == 0);
}

TEST_CASE("pfs_key_info says a lookup is in flight, whatever started it", "[core][pfs]") {
    Lookup l;
    REQUIRE_FALSE(l.info().fetching);

    SECTION("a prefetch") {
        l.c->prefetch_pfs_keys(l.sid);
    }
    SECTION("a refetch") {
        l.c->refetch_pfs_keys(l.sid);
    }
    SECTION("a send") {
        l.send();
    }
    SECTION("a retry of a failed one") {
        l.send();
        REQUIRE(l.fail() == 1);
        REQUIRE_FALSE(l.info().fetching);
        TestHelper::fire_pfs_retry(*l.c, l.sid);
    }

    CHECK(l.info().fetching);
    REQUIRE(l.find_nothing() == 1);
    CHECK_FALSE(l.info().fetching);
}

TEST_CASE("refetch_pfs_keys looks up whatever the cache says, once at a time", "[core][pfs]") {
    TempCore c;
    TempCore remote;
    b33 sid;
    std::ranges::copy(remote->globals.session_id(), sid.begin());
    CHECK_THROWS_AS(c->refetch_pfs_keys(sid), std::logic_error);

    Lookup l;

    SECTION("despite a usable key") {
        TestHelper::seed_pfs_cache(*l.c, l.sid, l.keys.first, l.keys.second);
        l.c->refetch_pfs_keys(l.sid);
        CHECK(l.lookups() == 1);
    }

    SECTION("despite a recent empty answer") {
        TestHelper::seed_pfs_nak(*l.c, l.sid);
        l.c->refetch_pfs_keys(l.sid);
        REQUIRE(l.lookups() == 1);
        REQUIRE(l.find_key() == 1);
        CHECK(l.info().state == PfsKeyState::usable);
    }

    SECTION("joining one in flight, from anywhere") {
        l.c->refetch_pfs_keys(l.sid);
        l.c->refetch_pfs_keys(l.sid);
        CHECK(l.c->prefetch_pfs_keys(l.sid) == PfsKeyState::none);
        l.send();
        REQUIRE(l.lookups() == 1);

        // One answer, one report; and the next asks again.
        REQUIRE(l.find_key() == 1);
        CHECK(l.fetched == std::vector{PfsKeyFetch::new_key});
        l.c->refetch_pfs_keys(l.sid);
        CHECK(l.lookups() == 1);
    }
}

TEST_CASE("send_dm: within the cache expiry, what the cache says, with no lookup", "[core][pfs]") {
    Lookup l;

    SECTION("a key: PFS") {
        TestHelper::seed_pfs_cache(*l.c, l.sid, l.keys.first, l.keys.second);
        auto id = l.send();
        CHECK(l.encryption(id) == MessageEncryption::v2_pfs);
    }
    SECTION("no key: v1") {
        TestHelper::seed_pfs_nak(*l.c, l.sid);
        auto id = l.send();
        CHECK(l.encryption(id) == MessageEncryption::v1);
    }
    SECTION("no key, forced v2: v2 without PFS") {
        TestHelper::seed_pfs_nak(*l.c, l.sid);
        auto id = l.send(true);
        CHECK(l.encryption(id) == MessageEncryption::v2_basic);
    }

    CHECK(l.lookups() == 0);
    CHECK(stores(*l.net).size() == 1);
}

TEST_CASE("send_dm: past the cache expiry, waits on a lookup and goes by it", "[core][pfs]") {
    Lookup l;

    SECTION("nothing held") {
        auto id = l.send();
        CHECK(l.statuses(id) == std::vector{MessageSendStatus::awaiting_keys});
        CHECK(stores(*l.net).empty());

        SECTION("found a key: PFS") {
            REQUIRE(l.find_key() == 1);
            CHECK(l.encryption(id) == MessageEncryption::v2_pfs);
        }
        SECTION("found nothing: v1") {
            REQUIRE(l.find_nothing() == 1);
            CHECK(l.encryption(id) == MessageEncryption::v1);
        }
    }

    SECTION("a key held") {
        TestHelper::seed_pfs_cache(*l.c, l.sid, l.keys.first, l.keys.second);

        SECTION("found nothing, within the empty grace: PFS with the key held") {
            ScopedClockOffset later{Core::PFS_KEY_EMPTY_GRACE - 1min};
            auto id = l.send();
            CHECK(l.statuses(id) == std::vector{MessageSendStatus::awaiting_keys});
            REQUIRE(l.find_nothing() == 1);
            CHECK(l.encryption(id) == MessageEncryption::v2_pfs);
        }
        SECTION("found nothing, past it: v1") {
            ScopedClockOffset later{Core::PFS_KEY_EMPTY_GRACE};
            auto id = l.send();
            REQUIRE(l.find_nothing() == 1);
            CHECK(l.encryption(id) == MessageEncryption::v1);
        }
        SECTION("failed, within the failed grace: PFS, and no lookup for the failed hold") {
            ScopedClockOffset later{Core::PFS_KEY_FAILED_GRACE - 1min};
            auto id = l.send();
            REQUIRE(l.fail() == 1);
            CHECK(l.encryption(id) == MessageEncryption::v2_pfs);

            auto next = l.send();
            CHECK(l.encryption(next) == MessageEncryption::v2_pfs);
            CHECK(l.lookups() == 0);
        }
    }
}

TEST_CASE("send_dm: a failed lookup with no key to fall back on is retried", "[core][pfs]") {
    Lookup l;

    SECTION("with nothing held") {}
    SECTION("with a key past the failed grace") {
        TestHelper::seed_pfs_cache(*l.c, l.sid, l.keys.first, l.keys.second);
    }
    ScopedClockOffset later{Core::PFS_KEY_FAILED_GRACE};

    auto id = l.send();
    REQUIRE(l.fail() == 1);
    CHECK(l.statuses(id) ==
          std::vector{MessageSendStatus::awaiting_keys, MessageSendStatus::retrying});
    CHECK(stores(*l.net).empty());
    CHECK(l.lookups() == 0);

    auto due = TestHelper::pfs_retry_due(*l.c, l.sid);
    REQUIRE(due);
    CHECK(*due - clock_now_ms() <= Core::PFS_FETCH_RETRY_FIRST);
    CHECK(*due - clock_now_ms() > Core::PFS_FETCH_RETRY_FIRST - 1s);

    // A send made meanwhile waits for the same retry rather than looking up again.
    auto joined = l.send();
    CHECK(l.statuses(joined) == std::vector{MessageSendStatus::retrying});
    CHECK(l.lookups() == 0);

    // Each failure in a row doubles the wait, up to the most.
    auto expected = Core::PFS_FETCH_RETRY_FIRST;
    for (int i = 0; i < 6; i++) {
        TestHelper::fire_pfs_retry(*l.c, l.sid);
        REQUIRE(l.lookups() == 1);
        REQUIRE(l.fail() == 1);
        expected = std::min(expected * 2, Core::PFS_FETCH_RETRY_MAX);
        due = TestHelper::pfs_retry_due(*l.c, l.sid);
        REQUIRE(due);
        CHECK(*due - clock_now_ms() <= expected);
        CHECK(*due - clock_now_ms() > expected - 1s);
    }
    CHECK(expected == Core::PFS_FETCH_RETRY_MAX);
    CHECK(stores(*l.net).empty());

    // A lookup that succeeds releases them all, and ends the retrying.
    TestHelper::fire_pfs_retry(*l.c, l.sid);
    REQUIRE(l.find_key() == 1);
    CHECK(l.encryption(id) == MessageEncryption::v2_pfs);
    CHECK(l.encryption(joined) == MessageEncryption::v2_pfs);
    CHECK(stores(*l.net).size() == 2);
    CHECK_FALSE(TestHelper::pfs_retry_due(*l.c, l.sid));
}

TEST_CASE("send_dm: a retry with no send left waiting looks up nothing", "[core][pfs]") {
    Lookup l;
    l.send();
    REQUIRE(l.fail() == 1);
    REQUIRE(TestHelper::pfs_retry_due(*l.c, l.sid));

    // An answer from elsewhere -- a refetch -- releases the send before the retry comes round.
    l.c->refetch_pfs_keys(l.sid);
    REQUIRE(l.find_nothing() == 1);
    CHECK_FALSE(TestHelper::pfs_retry_due(*l.c, l.sid));

    TestHelper::fire_pfs_retry(*l.c, l.sid);
    CHECK(l.lookups() == 0);
}
