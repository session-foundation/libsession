#include <catch2/catch_test_macros.hpp>

#include "../utils.hpp"
#include "live_utils.hpp"

using namespace session;
using namespace std::literals;

// Default timeout for live network operations.
static constexpr auto LIVE_TIMEOUT = 30s;

// What `core` holds of `sid`'s keys once a lookup of them has completed.
static std::optional<core::PfsKeyInfo> wait_for_lookup(core::Core& core, const b33& sid) {
    return wait_for(
            [&] {
                auto info = core.pfs_key_info(sid);
                return info.checked_at && !info.fetching ? std::optional{info} : std::nullopt;
            },
            LIVE_TIMEOUT);
}

TEST_CASE("Live: PFS key prefetch returns NAK for account with no published keys", "[live][pfs]") {
    // Core A is a fresh account that has never published its AccountPubkeys to the swarm.
    // Core B fetches keys for Core A's session id and should receive a NAK (empty namespace).
    auto core_a = make_live_core();
    auto core_b = make_live_core();

    b33 sid_a;
    std::ranges::copy(core_a->globals.session_id(), sid_a.begin());

    core_b->prefetch_pfs_keys(sid_a);

    auto info = wait_for_lookup(*core_b, sid_a);
    REQUIRE(info);
    CHECK(info->state == core::PfsKeyState::nak);
    CHECK_FALSE(info->confirmed_at);
    CHECK_FALSE(info->x25519_pub);
}

TEST_CASE("Live: PFS key prefetch retrieves keys after store to swarm", "[live][pfs]") {
    // Core A stores its AccountPubkeys to the swarm; Core B then fetches them.
    auto core_a = make_live_core();
    auto core_b = make_live_core();

    // Store Core A's account pubkeys to its swarm.
    REQUIRE(store_account_pubkeys(*core_a, LIVE_TIMEOUT));

    // Now fetch from Core B's perspective.
    b33 sid_a;
    std::ranges::copy(core_a->globals.session_id(), sid_a.begin());

    core_b->prefetch_pfs_keys(sid_a);

    auto info = wait_for_lookup(*core_b, sid_a);
    REQUIRE(info);
    CHECK(info->state == core::PfsKeyState::usable);
    CHECK(info->confirmed_at == info->checked_at);

    // The fetched pubkeys must match what Core A has as its active account keys.
    auto [expected_x25519, expected_mlkem768] =
            session::TestHelper::active_account_pubkeys(*core_a);
    CHECK(info->x25519_pub == expected_x25519);
    CHECK(info->mlkem768_pub == expected_mlkem768);
}
