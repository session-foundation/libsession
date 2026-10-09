#include <fmt/format.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <session/config/contacts.hpp>

#include "utils.hpp"

using namespace session::config;

TEST_CASE("Dirty/Mutable test case", "[config][dirty]") {

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(
            ed_pk.data(), ed_sk.data(), reinterpret_cast<const unsigned char*>(seed.data()));
    int rc = crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data());
    REQUIRE(rc == 0);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(oxenc::to_hex(seed.begin(), seed.end()) ==
          oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    session::config::Contacts c1{session::to_span(seed), std::nullopt};
    c1.set_name("050000000000000000000000000000000000000000000000000000000000000000", "alfonso");
    auto [seqno, data, obsolete] = c1.push();
    CHECK(obsolete == std::vector<std::string>{});
    c1.confirm_pushed(seqno, {"fakehash1"});

    session::config::Contacts c2{session::to_span(seed), c1.dump()};
    session::config::Contacts c3{session::to_span(seed), c1.dump()};

    CHECK_FALSE(c2.needs_dump());
    CHECK_FALSE(c2.needs_push());
    CHECK_FALSE(c3.needs_dump());
    CHECK_FALSE(c3.needs_push());

    c2.set_name("051111111111111111111111111111111111111111111111111111111111111111", "barney");
    c3.set_name(
            "052222222222222222222222222222222222222222222222222222222222222222", "chalmondeley");

    auto [seqno2, data2, obs2] = c2.push();
    auto [seqno3, data3, obs3] = c3.push();
    REQUIRE(data2.size() == 1);
    REQUIRE(data3.size() == 1);

    REQUIRE(seqno2 == 2);
    CHECK(as_set(obs2) == make_set("fakehash1"s));
    REQUIRE(seqno3 == 2);
    CHECK(as_set(obs3) == make_set("fakehash1"s));

    auto r = c1.merge(std::vector<std::pair<std::string, std::span<const unsigned char>>>{
            {{"fakehash2", data2[0]}, {"fakehash3", data3[0]}}});
    CHECK(r == std::unordered_set{{"fakehash2"s, "fakehash3"s}});
    CHECK(c1.needs_dump());
    CHECK(c1.needs_push());  // because we have the merge conflict to push
    CHECK(c1.is_dirty());
    CHECK(!c1.is_clean());

    c1.set_name("053333333333333333333333333333333333333333333333333333333333333333", "elly");

    CHECK(c1.needs_dump());
    CHECK(c1.needs_push());  // because we have the merge conflict to push
    auto [seqno4, data4, obs4] = c1.push();
    CHECK(!c1.is_dirty());
    CHECK(!c1.is_clean());  // not clean yet because we haven't confirmed

    CHECK(seqno4 == 3);  // The merge *and* change should go into the same message update/seqno
    CHECK(as_set(obs4) == make_set("fakehash1"s, "fakehash2"s, "fakehash3"s));
}

// There was a bug where if we merge the current config into itself then the current hash would be
// included in the old_hashes (which would result in clients deleting the current config from the
// swarm)
TEST_CASE("Merge existing config into clean state", "[config][merge_existing]") {
    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(
            ed_pk.data(), ed_sk.data(), reinterpret_cast<const unsigned char*>(seed.data()));
    int rc = crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data());
    REQUIRE(rc == 0);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(oxenc::to_hex(seed.begin(), seed.end()) ==
          oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    session::config::Contacts c1{std::span<const unsigned char>{seed}, std::nullopt};
    c1.set_name("050000000000000000000000000000000000000000000000000000000000000000", "alfonso");
    auto [seqno, data, obsolete] = c1.push();
    CHECK(obsolete == std::vector<std::string>{});
    c1.confirm_pushed(seqno, {"fakehash1"s});
    c1.dump();
    CHECK(!c1.needs_dump());
    CHECK(!c1.needs_push());

    auto r = c1.merge(std::vector<std::pair<std::string, std::span<const unsigned char>>>{
            {{"fakehash1"s, session::to_span(data[0])}}});
    CHECK(as_set(r) == make_set("fakehash1"s));

    auto old_hashes = c1.old_hashes();
    CHECK(old_hashes.empty());
}

// There was a bug where if the current config is in a dirty state and we merge a config which makes
// the same change we would remain in the dirty state but the merged configs has would be included
// in old_hashes (which ends up being the same hash the dirty config gets after pushing, resulting
// in the current config getting deleted from the swarm)
TEST_CASE("Merge config matching local changse", "[config][merge_matching_dirty]") {
    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk, curve_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(
            ed_pk.data(), ed_sk.data(), reinterpret_cast<const unsigned char*>(seed.data()));
    int rc = crypto_sign_ed25519_pk_to_curve25519(curve_pk.data(), ed_pk.data());
    REQUIRE(rc == 0);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(oxenc::to_hex(seed.begin(), seed.end()) ==
          oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    session::config::Contacts c1{std::span<const unsigned char>{seed}, std::nullopt};
    c1.set_name("050000000000000000000000000000000000000000000000000000000000000000", "alfonso");
    auto [seqno, data, obsolete] = c1.push();
    CHECK(obsolete == std::vector<std::string>{});
    c1.confirm_pushed(seqno, {"fakehash1"s});

    session::config::Contacts c2{std::span<const unsigned char>{seed}, c1.dump()};

    CHECK_FALSE(c2.needs_dump());
    CHECK_FALSE(c2.needs_push());

    // If the current dirty state matches a merged config we should end up in a clean state
    c1.set_name("051111111111111111111111111111111111111111111111111111111111111111", "barney");
    c2.set_name("051111111111111111111111111111111111111111111111111111111111111111", "barney");

    auto [seqno2, data2, obs2] = c2.push();

    REQUIRE(seqno2 == 2);
    CHECK(obs2 == std::vector{"fakehash1"s});
    c2.confirm_pushed(seqno2, {"fakehash2"s});

    CHECK(c1.is_dirty());  // already dirty before the merge
    auto r = c1.merge(std::vector<std::pair<std::string, std::span<const unsigned char>>>{
            {{"fakehash2"s, session::to_span(data2[0])}}});
    CHECK(r == std::unordered_set{{"fakehash2"s}});
    CHECK(c1.needs_dump());

    CHECK_FALSE(c1.needs_push());  // the merge resulted in the config being identical
    CHECK_FALSE(c1.is_dirty());
    CHECK(c1.is_clean());

    // Ensure if there are still changes after a merge where something was merged in we remain dirty
    c1.set_name("051111111111111111111111111111111111111111111111111111111111111112", "barney2");
    c1.set_name("051111111111111111111111111111111111111111111111111111111111111113", "barney3");
    c2.set_name("051111111111111111111111111111111111111111111111111111111111111112", "barney2");

    auto [seqno3, data3, obs3] = c2.push();
    REQUIRE(seqno3 == 3);
    CHECK(obs3 == std::vector{"fakehash2"s});
    c2.confirm_pushed(seqno3, {"fakehash3"s});

    CHECK(c1.is_dirty());  // already dirty before the merge
    auto r2 = c1.merge(std::vector<std::pair<std::string, std::span<const unsigned char>>>{
            {{"fakehash3", session::to_span(data3[0])}}});
    CHECK(r2 == std::unordered_set{{"fakehash3"s}});
    CHECK(c1.needs_dump());

    CHECK(c1.needs_push());  // there are still changes after the merge
    CHECK(c1.is_dirty());
    CHECK_FALSE(c1.is_clean());

    // Ensure if there are still changes after a merge where nothing was merged in we remain dirty
    // (push enough changes that we have a seqNo larger than the `lag` setting we use)
    for (auto i = 5; i < 20; ++i) {
        c1.set_name(
                fmt::format(
                        "0511111111111111111111111111111111111111111111111111111111111111{:02}", i),
                fmt::format("barney{}", i));
        auto [seqno_i, data_i, obs_i] = c1.push();
        // One behind i because the first merge above adopted c2's identical config at c2's own
        // seqno rather than consuming a new one.
        REQUIRE(seqno_i == i - 1);
        c1.confirm_pushed(seqno_i, {"fakehash" + std::to_string(i)});
        CHECK_FALSE(c1.needs_push());
        CHECK_FALSE(c1.is_dirty());
        CHECK(c1.is_clean());
    }

    c2.set_name("051111111111111111111111111111111111111111111111111111111111111150", "barney50");
    auto [seqno4, data4, obs4] = c2.push();
    REQUIRE(seqno4 == 4);
    CHECK(obs4 == std::vector{"fakehash3"s});

    c1.set_name("051111111111111111111111111111111111111111111111111111111111111140", "barney40");
    auto size_before_merge = c1.size();  // retrieve size before trying to merge
    CHECK(c1.is_dirty());                // already dirty before the merge
    auto r4 = c1.merge(std::vector<std::pair<std::string, std::span<const unsigned char>>>{
            {{"fakehash21", session::to_span(data4[0])}}});
    CHECK(r4 == std::unordered_set{{"fakehash21"s}});
    CHECK(c1.needs_dump());

    CHECK(c1.size() == size_before_merge);  // barney21 didn't get merged (seqNo too old)
    CHECK(c1.needs_push());                 // there are still changes after the merge
    CHECK(c1.is_dirty());
    CHECK_FALSE(c1.is_clean());
}

// When we are dirty and merge an incoming config that makes the identical change, we adopt the
// incoming message as-is: same data, same seqno, standing behind its storage hash.  There was a bug
// where the adoption consumed an extra seqno that no stored message occupies, so that the peer's
// *next* ordinary change (correctly landing on the value we had burned) looked like a conflict:
// merging it produced a pointless conflict-resolution push instead of a clean adoption.
TEST_CASE("Merge matching local changes adopts without consuming a seqno", "[config][merge]") {
    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;
    std::array<unsigned char, 32> ed_pk;
    std::array<unsigned char, 64> ed_sk;
    crypto_sign_ed25519_seed_keypair(
            ed_pk.data(), ed_sk.data(), reinterpret_cast<const unsigned char*>(seed.data()));

    session::config::Contacts c1{session::to_span(seed), std::nullopt};
    c1.set_name("050000000000000000000000000000000000000000000000000000000000000000", "alfonso");
    auto [seqno1, data1, obs1] = c1.push();
    REQUIRE(seqno1 == 1);
    c1.confirm_pushed(seqno1, {"fakehash1"});

    auto dump1 = c1.dump();
    session::config::Contacts c2{session::to_span(seed), dump1};

    // Both devices make the same change; c2 gets its push in first.
    c1.set_name("051111111111111111111111111111111111111111111111111111111111111111", "barney");
    c2.set_name("051111111111111111111111111111111111111111111111111111111111111111", "barney");

    auto [seqno2, data2, obs2] = c2.push();
    REQUIRE(seqno2 == 2);
    c2.confirm_pushed(seqno2, {"fakehash2"});

    REQUIRE(c1.is_dirty());
    auto r = c1.merge(std::vector<std::pair<std::string, std::span<const unsigned char>>>{
            {{"fakehash2"s, session::to_span(data2[0])}}});
    CHECK(r == std::unordered_set{{"fakehash2"s}});
    CHECK(c1.is_clean());
    CHECK_FALSE(c1.needs_push());
    CHECK(c1.curr_hashes() == std::unordered_set{{"fakehash2"s}});

    // c2, still on seqno 2, makes an ordinary change of its own; c1 must accept it as a clean
    // adoption at seqno 3, not as a conflict with a phantom seqno 3 of c1's.
    c2.set_name("052222222222222222222222222222222222222222222222222222222222222222", "carl");
    auto [seqno3, data3, obs3] = c2.push();
    REQUIRE(seqno3 == 3);
    c2.confirm_pushed(seqno3, {"fakehash3"});

    r = c1.merge(std::vector<std::pair<std::string, std::span<const unsigned char>>>{
            {{"fakehash3"s, session::to_span(data3[0])}}});
    CHECK(r == std::unordered_set{{"fakehash3"s}});
    CHECK(c1.is_clean());
    CHECK_FALSE(c1.needs_push());
    CHECK(c1.curr_hashes() == std::unordered_set{{"fakehash3"s}});
    CHECK(c1.get("052222222222222222222222222222222222222222222222222222222222222222")
                  .value()
                  .name == "carl");

    // A new change by c1 must consume seqno 4, agreeing with c2's numbering, and obsolete exactly
    // the messages both devices know about.
    c1.set_name("053333333333333333333333333333333333333333333333333333333333333333", "dora");
    auto [seqno4, data4, obs4] = c1.push();
    CHECK(seqno4 == 4);
    CHECK(as_set(obs4) == make_set("fakehash1"s, "fakehash2"s, "fakehash3"s));

    // Same identical-change situation, but the peer had already pushed a further change on top by
    // the time we merge: both messages arrive together and we adopt the newest at its own seqno.
    session::config::Contacts c3{session::to_span(seed), dump1};
    c3.set_name("051111111111111111111111111111111111111111111111111111111111111111", "barney");
    REQUIRE(c3.is_dirty());
    r = c3.merge(std::vector<std::pair<std::string, std::span<const unsigned char>>>{
            {{"fakehash2"s, session::to_span(data2[0])},
             {"fakehash3"s, session::to_span(data3[0])}}});
    CHECK(r == std::unordered_set{{"fakehash2"s, "fakehash3"s}});
    CHECK(c3.is_clean());
    CHECK_FALSE(c3.needs_push());
    CHECK(c3.curr_hashes() == std::unordered_set{{"fakehash3"s}});

    c3.set_name("054444444444444444444444444444444444444444444444444444444444444444", "edgar");
    auto [seqno5, data5, obs5] = c3.push();
    CHECK(seqno5 == 4);
}
