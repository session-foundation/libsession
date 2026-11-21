#include <oxenc/base64.h>
#include <oxenc/bt_producer.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>
#include <session/config/contacts.h>
#include <session/config/groups/info.h>
#include <session/config/groups/keys.h>
#include <session/config/groups/members.h>
#include <sodium/crypto_sign_ed25519.h>

#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators_range.hpp>
#include <catch2/matchers/catch_matchers.hpp>
#include <iterator>
#include <session/config/groups/info.hpp>
#include <session/config/groups/keys.hpp>
#include <session/config/groups/members.hpp>
#include <session/config/user_groups.hpp>
#include <string_view>
#include <unordered_map>

#include "utils.hpp"

using namespace std::literals;
using namespace session::config;

static std::array<unsigned char, 64> sk_from_seed(std::span<const unsigned char> seed) {
    std::array<unsigned char, 32> ignore;
    std::array<unsigned char, 64> sk;
    crypto_sign_ed25519_seed_keypair(ignore.data(), sk.data(), seed.data());
    return sk;
}

static std::string session_id_from_ed(std::span<const unsigned char> ed_pk) {
    std::string sid;
    std::array<unsigned char, 32> xpk;
    int rc = crypto_sign_ed25519_pk_to_curve25519(xpk.data(), ed_pk.data());
    REQUIRE(rc == 0);
    sid.reserve(66);
    sid += "05";
    oxenc::to_hex(xpk.begin(), xpk.end(), std::back_inserter(sid));
    return sid;
}

// Hacky little class that implements `[n]` on a std::list.  This is inefficient (since it access
// has to iterate n times through the list) but we only use it on small lists in this test code so
// convenience wins over efficiency.  (Why not just use a vector?  Because vectors requires `T` to
// be moveable, so we'd either have to use std::unique_ptr for members, which is also annoying).
template <typename T>
struct hacky_list : std::list<T> {
    T& operator[](size_t n) { return *std::next(std::begin(*this), n); }
};

struct pseudo_client {
    std::array<unsigned char, 64> secret_key;
    const std::span<const unsigned char> public_key{secret_key.data() + 32, 32};
    std::string session_id{session_id_from_ed(public_key)};

    groups::Info info;
    groups::Members members;
    groups::Keys keys;

    pseudo_client(
            std::span<const unsigned char> seed,
            bool admin,
            const unsigned char* gpk,
            std::optional<const unsigned char*> gsk,
            std::optional<std::span<const unsigned char>> info_dump = std::nullopt,
            std::optional<std::span<const unsigned char>> members_dump = std::nullopt,
            std::optional<std::span<const unsigned char>> keys_dump = std::nullopt) :
            secret_key{sk_from_seed(seed)},
            info{std::span<const unsigned char>{gpk, 32},
                 admin ? std::make_optional<std::span<const unsigned char>>({*gsk, 64})
                       : std::nullopt,
                 info_dump},
            members{std::span<const unsigned char>{gpk, 32},
                    admin ? std::make_optional<std::span<const unsigned char>>({*gsk, 64})
                          : std::nullopt,
                    members_dump},
            keys{session::to_span(secret_key),
                 std::span<const unsigned char>{gpk, 32},
                 admin ? std::make_optional<std::span<const unsigned char>>({*gsk, 64})
                       : std::nullopt,
                 keys_dump,
                 info,
                 members} {
        if (gsk)
            keys.rekey(info, members);
    }
};

TEST_CASE("Group Keys - C++ API", "[config][groups][keys][cpp]") {

    const std::vector<unsigned char> group_seed =
            "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210"_hexbytes;
    const std::vector<unsigned char> admin1_seed =
            "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"_hexbytes;
    const std::vector<unsigned char> admin2_seed =
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"_hexbytes;
    const std::array member_seeds = {
            "000111222333444555666777888999aaabbbcccdddeeefff0123456789abcdef"_hexbytes,  // member1
            "00011122435111155566677788811263446552465222efff0123456789abcdef"_hexbytes,  // member2
            "00011129824754185548239498168169316979583253efff0123456789abcdef"_hexbytes,  // member3
            "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"_hexbytes,  // member4
            "3333333333333333333333333333333333333333333333333333333333333333"_hexbytes,  // member3b
            "4444444444444444444444444444444444444444444444444444444444444444"_hexbytes,  // member4b
    };

    std::array<unsigned char, 32> group_pk;
    std::array<unsigned char, 64> group_sk;

    crypto_sign_ed25519_seed_keypair(group_pk.data(), group_sk.data(), group_seed.data());
    REQUIRE(oxenc::to_hex(group_seed.begin(), group_seed.end()) ==
            oxenc::to_hex(group_sk.begin(), group_sk.begin() + 32));

    // Using list instead of vector so that `psuedo_client` doesn't have to be moveable, which lets
    // us put the Info/Member/Keys directly inside it (rather than having to use a unique_ptr, which
    // would also be annoying).
    hacky_list<pseudo_client> admins;
    hacky_list<pseudo_client> members;

    // Initialize admin and member objects
    admins.emplace_back(admin1_seed, true, group_pk.data(), group_sk.data());
    admins.emplace_back(admin2_seed, true, group_pk.data(), group_sk.data());

    for (int i = 0; i < 4; ++i)
        members.emplace_back(member_seeds[i], false, group_pk.data(), std::nullopt);

    REQUIRE(admins[0].session_id ==
            "05f1e8b64bbf761edf8f7b47e3a1f369985644cce0a62adb8e21604474bdd49627");
    REQUIRE(admins[1].session_id ==
            "05c5ba413c336f2fe1fb9a2c525f8a86a412a1db128a7841b4e0e217fa9eb7fd5e");
    REQUIRE(members[0].session_id ==
            "05ece06dd8e02fb2f7d9497f956a1996e199953c651f4016a2f79a3b3e38d55628");
    REQUIRE(members[1].session_id ==
            "053ac269b71512776b0bd4a1234aaf93e67b4e9068a2c252f3b93a20acb590ae3c");
    REQUIRE(members[2].session_id ==
            "05a2b03abdda4df8316f9d7aed5d2d1e483e9af269d0b39191b08321b8495bc118");
    REQUIRE(members[3].session_id ==
            "050a41669a06c098f22633aee2eba03764ef6813bd4f770a3a2b9033b868ca470d");

    for (const auto& a : admins)
        REQUIRE(a.members.size() == 0);
    for (const auto& m : members)
        REQUIRE(m.members.size() == 0);

    std::vector<std::pair<std::string, std::span<const unsigned char>>> info_configs;
    std::vector<std::pair<std::string, std::span<const unsigned char>>> mem_configs;

    // add admin account, re-key, distribute
    auto& admin1 = admins[0];

    auto m = admin1.members.get_or_construct(admin1.session_id);
    m.admin = true;
    m.name = "Admin1";
    admin1.members.set(m);

    CHECK(admin1.members.needs_push());

    auto maybe_key_config = admin1.keys.pending_config();
    REQUIRE(maybe_key_config);
    auto new_keys_config1 = *maybe_key_config;

    auto [iseq1, new_info_config1, iobs1] = admin1.info.push();
    admin1.info.confirm_pushed(iseq1, {"fakehash1"});
    REQUIRE(new_info_config1.size() == 1);
    info_configs.emplace_back("fakehash1", new_info_config1[0]);

    auto [mseq1, new_mem_config1, mobs1] = admin1.members.push();
    admin1.members.confirm_pushed(mseq1, {"fakehash1"});
    REQUIRE(new_mem_config1.size() == 1);
    mem_configs.emplace_back("fakehash1", new_mem_config1[0]);

    /*  Even though we have only added one admin, admin2 will still be able to see group info
        like group size and merge all configs. This is because they have loaded the key config
        message, which they can decrypt with the group secret key.
    */
    for (auto& a : admins) {
        a.keys.load_key_message(
                "keyhash1", new_keys_config1, get_timestamp_ms(), a.info, a.members);
        CHECK(a.info.merge(info_configs) == std::unordered_set{{"fakehash1"s}});
        CHECK(a.members.merge(mem_configs) == std::unordered_set{{"fakehash1"s}});
        CHECK(a.members.size() == 1);
        CHECK(a.keys.active_hashes() == std::unordered_set{{"keyhash1"s}});
    }

    /*  All attempts to merge non-admin members will throw, as none of the non admin members
        will be able to decrypt the new info/member configs using the updated keys
    */
    for (auto& m : members) {
        m.keys.load_key_message(
                "keyhash1", new_keys_config1, get_timestamp_ms(), m.info, m.members);
        CHECK_THROWS(m.info.merge(info_configs));
        CHECK_THROWS(m.members.merge(mem_configs));
        CHECK(m.members.size() == 0);
        CHECK(m.keys.active_hashes().empty());
    }

    info_configs.clear();
    mem_configs.clear();

    // add non-admin members, re-key, distribute
    for (size_t i = 0; i < members.size(); ++i) {
        auto m = admin1.members.get_or_construct(members[i].session_id);
        m.admin = false;
        m.name = "Member{}"_format(i);
        admin1.members.set(m);
    }

    CHECK(admin1.members.needs_push());

    auto new_keys_config2 = admin1.keys.rekey(admin1.info, admin1.members);
    CHECK(not new_keys_config2.empty());

    auto [iseq2, new_info_config2, iobs2] = admin1.info.push();
    admin1.info.confirm_pushed(iseq2, {"fakehash2"});
    REQUIRE(new_info_config2.size() == 1);
    info_configs.emplace_back("fakehash2", new_info_config2[0]);

    auto [mseq2, new_mem_config2, mobs2] = admin1.members.push();
    admin1.members.confirm_pushed(mseq2, {"fakehash2"});
    REQUIRE(new_mem_config2.size() == 1);
    mem_configs.emplace_back("fakehash2", new_mem_config2[0]);

    for (auto& a : admins) {
        a.keys.load_key_message(
                "keyhash2", new_keys_config2, get_timestamp_ms(), a.info, a.members);
        CHECK(a.info.merge(info_configs) == std::unordered_set{{"fakehash2"s}});
        CHECK(a.members.merge(mem_configs) == std::unordered_set{{"fakehash2"s}});
        CHECK(a.members.size() == 5);
        CHECK(a.keys.active_hashes() == std::unordered_set{{"keyhash1"s, "keyhash2"s}});
    }

    for (auto& m : members) {
        m.keys.load_key_message(
                "keyhash2", new_keys_config2, get_timestamp_ms(), m.info, m.members);
        CHECK(m.info.merge(info_configs) == std::unordered_set{{"fakehash2"s}});
        CHECK(m.members.merge(mem_configs) == std::unordered_set{{"fakehash2"s}});
        CHECK(m.members.size() == 5);
        CHECK(m.keys.active_hashes() == std::unordered_set{{"keyhash2"s}});
    }

    info_configs.clear();
    mem_configs.clear();

    // change group info, re-key, distribute
    admin1.info.set_name("tomatosauce"s);
    admin1.info.set_description("this is where you go to play in the tomato sauce, I guess");

    CHECK(admin1.info.needs_push());

    auto new_keys_config3 = admin1.keys.rekey(admin1.info, admin1.members);
    CHECK(not new_keys_config3.empty());

    auto [iseq3, new_info_config3, iobs3] = admin1.info.push();
    admin1.info.confirm_pushed(iseq3, {"fakehash3"});
    REQUIRE(new_info_config3.size() == 1);
    info_configs.emplace_back("fakehash3", new_info_config3[0]);

    auto [mseq3, new_mem_config3, mobs3] = admin1.members.push();
    admin1.members.confirm_pushed(mseq3, {"fakehash3"});
    REQUIRE(new_mem_config3.size() == 1);
    mem_configs.emplace_back("fakehash3", new_mem_config3[0]);

    for (auto& a : admins) {
        a.keys.load_key_message(
                "keyhash3", new_keys_config3, get_timestamp_ms(), a.info, a.members);
        CHECK(a.info.merge(info_configs) == std::unordered_set{{"fakehash3"s}});
        CHECK(a.members.merge(mem_configs) == std::unordered_set{{"fakehash3"s}});
        CHECK(a.info.get_name() == "tomatosauce"s);
        CHECK(a.info.get_description() ==
              "this is where you go to play in the tomato sauce, I guess"s);
        CHECK(a.keys.active_hashes() ==
              std::unordered_set{{"keyhash1"s, "keyhash2"s, "keyhash3"s}});
    }

    for (auto& m : members) {
        m.keys.load_key_message(
                "keyhash3", new_keys_config3, get_timestamp_ms(), m.info, m.members);
        CHECK(m.info.merge(info_configs) == std::unordered_set{{"fakehash3"s}});
        CHECK(m.members.merge(mem_configs) == std::unordered_set{{"fakehash3"s}});
        CHECK(m.info.get_name() == "tomatosauce"s);
        CHECK(m.info.get_description() ==
              "this is where you go to play in the tomato sauce, I guess"s);
        CHECK(m.keys.active_hashes() == std::unordered_set{{"keyhash2"s, "keyhash3"s}});
    }

    info_configs.clear();
    mem_configs.clear();

    // remove members, re-key, distribute
    CHECK(admin1.members.size() == 5);
    CHECK(admin1.members.erase(members[3].session_id));
    CHECK(admin1.members.erase(members[2].session_id));
    CHECK(admin1.members.size() == 3);

    CHECK(admin1.members.needs_push());

    std::vector<unsigned char> old_key = session::to_vector(admin1.keys.group_enc_key());
    auto new_keys_config4 = admin1.keys.rekey(admin1.info, admin1.members);
    CHECK(not new_keys_config4.empty());

    CHECK(old_key != session::to_vector(admin1.keys.group_enc_key()));

    auto [iseq4, new_info_config4, iobs4] = admin1.info.push();
    admin1.info.confirm_pushed(iseq4, {"fakehash4"});
    REQUIRE(new_info_config4.size() == 1);
    info_configs.emplace_back("fakehash4", new_info_config4[0]);

    auto [mseq4, new_mem_config4, mobs4] = admin1.members.push();
    admin1.members.confirm_pushed(mseq4, {"fakehash4"});
    REQUIRE(new_mem_config4.size() == 1);
    mem_configs.emplace_back("fakehash4", new_mem_config4[0]);

    for (auto& a : admins) {
        CHECK(a.keys.load_key_message(
                "keyhash4", new_keys_config4, get_timestamp_ms(), a.info, a.members));
        CHECK(a.info.merge(info_configs) == std::unordered_set{{"fakehash4"s}});
        CHECK(a.members.merge(mem_configs) == std::unordered_set{{"fakehash4"s}});
        CHECK(a.members.size() == 3);
        CHECK(a.keys.active_hashes() ==
              std::unordered_set{{"keyhash1"s, "keyhash2"s, "keyhash3"s, "keyhash4"s}});
    }

    for (size_t i = 0; i < members.size(); i++) {
        auto& m = members[i];
        bool found_key = m.keys.load_key_message(
                "keyhash4", new_keys_config2, get_timestamp_ms(), m.info, m.members);

        CHECK(m.keys.active_hashes() ==
              std::unordered_set{{"keyhash2"s, "keyhash3"s, "keyhash4"s}});
        if (i < 2) {  // We should still be in the group
            CHECK(found_key);
            CHECK(m.info.merge(info_configs) == std::unordered_set{{"fakehash4"s}});
            CHECK(m.members.merge(mem_configs) == std::unordered_set{{"fakehash4"s}});
            CHECK(m.members.size() == 3);
        } else {
            CHECK_FALSE(found_key);
            CHECK(m.info.merge(info_configs) == std::unordered_set<std::string>{});
            CHECK(m.members.merge(mem_configs) == std::unordered_set<std::string>{});
            CHECK(m.members.size() == 5);
        }
    }

    members.pop_back();
    members.pop_back();

    info_configs.clear();
    mem_configs.clear();

    // middle-out time
    auto msg = "hello to all my friends sitting in the tomato sauce"s;

    for (int i = 0; i < 5; ++i)
        msg += msg;

    auto compressed = admin1.keys.encrypt_message(session::to_span(msg));
    CHECK(compressed.size() == 256);
    auto uncompressed = admin1.keys.encrypt_message(session::to_span(msg), false);
    CHECK(uncompressed.size() == 2048);

    CHECK(compressed.size() < msg.size());

    // Add two new members and send them supplemental keys
    for (int i = 0; i < 2; ++i) {
        auto& m = members.emplace_back(member_seeds[4 + i], false, group_pk.data(), std::nullopt);

        auto memb = admin1.members.get_or_construct(m.session_id);
        memb.set_invite_sent();
        memb.supplement = true;
        memb.name = i == 0 ? "fred" : "JOHN";
        admin1.members.set(memb);

        CHECK_FALSE(m.keys.admin());
    }

    REQUIRE(members[2].session_id ==
            "054eb4fafee2bd3018a24e310de8106333c2b364eaed029a7f05d7b45ccc77683a");
    REQUIRE(members[3].session_id ==
            "057ce31baa9a04b5cfb83ab7ccdd7b669b911a082d29883d6aad3256294a0a5e0c");

    // We actually send supplemental keys to members 1, as well, by mistake just to make sure it
    // doesn't do or hurt anything to get a supplemental key you already have.
    std::vector<std::string> supp_sids;
    std::transform(
            std::next(members.begin()), members.end(), std::back_inserter(supp_sids), [](auto& m) {
                return m.session_id;
            });
    auto supp = admin1.keys.key_supplement(supp_sids);
    CHECK(admin1.members.needs_push());
    CHECK_FALSE(admin1.info.needs_push());
    auto [mseq5, mpush5, mobs5] = admin1.members.push();
    REQUIRE(mpush5.size() == 1);
    mem_configs.emplace_back("fakehash5", mpush5[0]);
    admin1.members.confirm_pushed(mseq5, {"fakehash5"});
    info_configs.emplace_back("fakehash4", new_info_config4[0]);

    for (auto& a : admins) {
        CHECK_FALSE(
                a.keys.load_key_message("keyhash5", supp, get_timestamp_ms(), a.info, a.members));
    }

    for (size_t i = 0; i < members.size(); i++) {
        auto& m = members[i];
        bool found_key =
                m.keys.load_key_message("keyhash5", supp, get_timestamp_ms(), m.info, m.members);

        if (i < 1) {
            // This supp key wasn't for us
            CHECK_FALSE(found_key);
            CHECK(m.keys.size() == 3);
            CHECK(m.keys.group_keys().size() == 3);
        } else {
            CHECK(found_key);
            // new_keys_config1 never went to the initial members, but did go out in the
            // supplement, which is why we have the extra key here.
            CHECK(m.keys.size() == 4);
            CHECK(m.keys.group_keys().size() == 4);
        }

        CHECK(m.info.merge(info_configs) == std::unordered_set{{"fakehash4"s}});
        CHECK(m.members.merge(mem_configs) == std::unordered_set{{"fakehash5"s}});
        REQUIRE(m.info.get_name());
        CHECK(*m.info.get_name() == "tomatosauce"sv);
        CHECK(m.members.size() == 5);

        if (i < 2)
            CHECK(m.keys.active_hashes() ==
                  std::unordered_set{{"keyhash2"s, "keyhash3"s, "keyhash4"s, "keyhash5"s}});
        else
            CHECK(m.keys.active_hashes() == std::unordered_set{{"keyhash5"s}});
    }

    std::pair<std::string, std::vector<unsigned char>> decrypted1, decrypted2;
    REQUIRE_NOTHROW(decrypted1 = members.back().keys.decrypt_message(compressed));
    CHECK(decrypted1.first == admin1.session_id);
    CHECK(session::to_string(decrypted1.second) == msg);

    REQUIRE_NOTHROW(decrypted2 = members.back().keys.decrypt_message(uncompressed));
    CHECK(decrypted2.first == admin1.session_id);
    CHECK(session::to_string(decrypted2.second) == msg);

    auto bad_compressed = compressed;
    bad_compressed.back() ^= 0b100;
    CHECK_THROWS_WITH(
            members.back().keys.decrypt_message(bad_compressed),
            "unable to decrypt ciphertext with any current group keys; tried 4");

    // Duplicate members[1] from dumps
    auto& m1b = members.emplace_back(
            member_seeds[1],
            false,
            group_pk.data(),
            std::nullopt,
            members[1].info.dump(),
            members[1].members.dump(),
            members[1].keys.dump());
    CHECK(m1b.keys.size() == 4);
    CHECK(m1b.keys.group_keys().size() == 4);
    CHECK(m1b.keys.active_hashes() ==
          std::unordered_set{{"keyhash2"s, "keyhash3"s, "keyhash4"s, "keyhash5"s}});
    CHECK(m1b.members.size() == 5);
    auto m1b_m2 = m1b.members.get(members[2].session_id);
    REQUIRE(m1b_m2);
    CHECK(m1b.members.get_status(*m1b_m2) == session::config::groups::member::Status::invite_sent);
    CHECK(m1b_m2->name == "fred");

    // Rekey after 10d, then again after 71d (10+61) and everything except those two new gens should
    // get dropped as stale.
    info_configs.clear();
    mem_configs.clear();
    std::vector<unsigned char> new_keys_config6 =
            session::to_vector(admin1.keys.rekey(admin1.info, admin1.members));
    auto [iseq6, ipush6, iobs6] = admin1.info.push();
    info_configs.emplace_back("ifakehash6", ipush6[0]);
    REQUIRE(info_configs.size() == 1);
    admin1.info.confirm_pushed(iseq6, {"ifakehash6"});
    auto [mseq6, mpush6, mobs6] = admin1.members.push();
    REQUIRE(mpush6.size() == 1);
    mem_configs.emplace_back("mfakehash6", mpush6[0]);
    admin1.members.confirm_pushed(mseq6, {"mfakehash6"});

    for (auto& a : admins) {
        CHECK(a.keys.load_key_message(
                "keyhash6",
                new_keys_config6,
                get_timestamp_ms() + 10LL * 86400 * 1000,
                a.info,
                a.members));
        CHECK(a.info.merge(info_configs) == std::unordered_set{{"ifakehash6"s}});
        CHECK(a.members.merge(mem_configs) == std::unordered_set{{"mfakehash6"s}});
        CHECK(a.members.size() == 5);
        CHECK(a.keys.active_hashes() == std::unordered_set{
                                                {"keyhash1"s,
                                                 "keyhash2"s,
                                                 "keyhash3"s,
                                                 "keyhash4"s,
                                                 "keyhash5"s,
                                                 "keyhash6"s}});
    }

    std::vector<unsigned char> new_keys_config7 =
            session::to_vector(admin1.keys.rekey(admin1.info, admin1.members));

    // Make sure we can encrypt & decrypt even if the rekey is still pending:
    CHECK_NOTHROW(
            admin1.keys.decrypt_message(admin1.keys.encrypt_message(session::to_span("abc"))));

    auto [iseq7, ipush7, iobs7] = admin1.info.push();
    REQUIRE(ipush7.size() == 1);
    info_configs.emplace_back("ifakehash7", ipush7[0]);
    admin1.info.confirm_pushed(iseq7, {"ifakehash7"});

    auto [mseq7, mpush7, mobs7] = admin1.members.push();
    REQUIRE(mpush7.size() == 1);
    mem_configs.emplace_back("mfakehash7", mpush7[0]);
    admin1.members.confirm_pushed(mseq7, {"mfakehash7"});

    for (auto& a : admins) {
        CHECK(a.keys.load_key_message(
                "keyhash7",
                new_keys_config7,
                get_timestamp_ms() + 71LL * 86400 * 1000,
                a.info,
                a.members));
        CHECK(a.info.merge(info_configs) == std::unordered_set{{"ifakehash6"s, "ifakehash7"s}});
        CHECK(a.members.merge(mem_configs) == std::unordered_set{{"mfakehash6"s, "mfakehash7"s}});
        CHECK(a.members.size() == 5);
        CHECK(a.keys.active_hashes() == std::unordered_set{{"keyhash6"s, "keyhash7"s}});
    }

    for (size_t i = 0; i < members.size(); i++) {
        auto& m = members[i];
        CHECK(m.keys.load_key_message(
                "keyhash6",
                new_keys_config6,
                get_timestamp_ms() + 10LL * 86400 * 1000,
                m.info,
                m.members));
        CHECK(m.keys.load_key_message(
                "keyhash7",
                new_keys_config7,
                get_timestamp_ms() + 71LL * 86400 * 1000,
                m.info,
                m.members));
        CHECK(m.info.merge(info_configs) == std::unordered_set{{"ifakehash6"s, "ifakehash7"s}});
        CHECK(m.members.merge(mem_configs) == std::unordered_set{{"mfakehash6"s, "mfakehash7"s}});
        CHECK(m.members.size() == 5);
        CHECK(m.keys.active_hashes() == std::unordered_set{{"keyhash6"s, "keyhash7"s}});
    }

    // Make sure keys propagate on dump restore to info/members:
    pseudo_client admin1b{
            admin1_seed,
            true,
            group_pk.data(),
            group_sk.data(),
            admin1.info.dump(),
            admin1.members.dump(),
            admin1.keys.dump()};
    admin1b.info.set_name("Test New Name");
    admin1b.info.set_description("Test New Desc");
    CHECK_THROWS(
            admin1b.info.set_name("Test New Name Really long "
                                  "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl"
                                  "mnopqrstuvwxyz"));
    CHECK_THROWS(admin1b.info.set_description(std::string(2050, 'z')));
    CHECK_NOTHROW(admin1b.info.push());
    admin1b.members.set(
            admin1b.members.get_or_construct("05124076571076017981235497801235098712093870981273590"
                                             "8746387172343"));
    CHECK_NOTHROW(admin1b.members.push());

    // Test values weren't overrided
    CHECK(admin1b.info.get_name() == "Test New Name");
    CHECK(admin1b.info.get_description() == "Test New Desc");
}

TEST_CASE("Group Keys - C API", "[config][groups][keys][c]") {
    struct pseudo_client {
        std::array<unsigned char, 64> secret_key;
        const std::span<const unsigned char> public_key{secret_key.data() + 32, 32};
        std::string session_id{session_id_from_ed(public_key)};

        config_group_keys* keys;
        config_object* info;
        config_object* members;

        pseudo_client(
                std::vector<unsigned char> seed,
                bool is_admin,
                unsigned char* gpk,
                std::optional<unsigned char*> gsk) :
                secret_key{sk_from_seed(seed)} {
            int rv = groups_members_init(&members, gpk, is_admin ? *gsk : NULL, NULL, 0, NULL);
            REQUIRE(rv == 0);

            rv = groups_info_init(&info, gpk, is_admin ? *gsk : NULL, NULL, 0, NULL);
            REQUIRE(rv == 0);

            rv = groups_keys_init(
                    &keys,
                    secret_key.data(),
                    gpk,
                    is_admin ? *gsk : NULL,
                    info,
                    members,
                    NULL,
                    0,
                    NULL);
            REQUIRE(rv == 0);

            if (is_admin)
                REQUIRE(groups_keys_rekey(keys, info, members, nullptr, nullptr));
        }

        ~pseudo_client() {
            config_free(info);
            config_free(members);
        }
    };

    const std::vector<unsigned char> group_seed =
            "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210"_hexbytes;
    const std::vector<unsigned char> admin1_seed =
            "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"_hexbytes;
    const std::vector<unsigned char> admin2_seed =
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"_hexbytes;
    const std::array member_seeds = {
            "000111222333444555666777888999aaabbbcccdddeeefff0123456789abcdef"_hexbytes,  // member1
            "00011122435111155566677788811263446552465222efff0123456789abcdef"_hexbytes,  // member2
            "00011129824754185548239498168169316979583253efff0123456789abcdef"_hexbytes,  // member3
            "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"_hexbytes   // member4
    };

    std::array<unsigned char, 32> group_pk;
    std::array<unsigned char, 64> group_sk;

    crypto_sign_ed25519_seed_keypair(
            group_pk.data(),
            group_sk.data(),
            reinterpret_cast<const unsigned char*>(group_seed.data()));
    REQUIRE(oxenc::to_hex(group_seed.begin(), group_seed.end()) ==
            oxenc::to_hex(group_sk.begin(), group_sk.begin() + 32));

    hacky_list<pseudo_client> admins;
    hacky_list<pseudo_client> members;

    // Initialize admin and member objects
    admins.emplace_back(admin1_seed, true, group_pk.data(), group_sk.data());
    admins.emplace_back(admin2_seed, true, group_pk.data(), group_sk.data());

    for (int i = 0; i < 4; ++i)
        members.emplace_back(member_seeds[i], false, group_pk.data(), std::nullopt);

    REQUIRE(admins[0].session_id ==
            "05f1e8b64bbf761edf8f7b47e3a1f369985644cce0a62adb8e21604474bdd49627");
    REQUIRE(admins[1].session_id ==
            "05c5ba413c336f2fe1fb9a2c525f8a86a412a1db128a7841b4e0e217fa9eb7fd5e");
    REQUIRE(members[0].session_id ==
            "05ece06dd8e02fb2f7d9497f956a1996e199953c651f4016a2f79a3b3e38d55628");
    REQUIRE(members[1].session_id ==
            "053ac269b71512776b0bd4a1234aaf93e67b4e9068a2c252f3b93a20acb590ae3c");
    REQUIRE(members[2].session_id ==
            "05a2b03abdda4df8316f9d7aed5d2d1e483e9af269d0b39191b08321b8495bc118");
    REQUIRE(members[3].session_id ==
            "050a41669a06c098f22633aee2eba03764ef6813bd4f770a3a2b9033b868ca470d");

    for (const auto& a : admins)
        REQUIRE(groups_members_size(a.members) == 0);
    for (const auto& m : members)
        REQUIRE(groups_members_size(m.members) == 0);

    // add admin account, re-key, distribute
    auto& admin1 = admins[0];
    config_group_member new_admin1;

    REQUIRE(groups_members_get_or_construct(
            admin1.members, &new_admin1, admin1.session_id.c_str()));

    new_admin1.admin = true;
    groups_members_set(admin1.members, &new_admin1);

    CHECK(config_needs_push(admin1.members));

    const unsigned char* new_keys_config_1;
    size_t key_len1;
    REQUIRE(groups_keys_pending_config(admin1.keys, &new_keys_config_1, &key_len1));

    config_push_data* new_info_config1 = config_push(admin1.info);
    CHECK(new_info_config1->seqno == 1);
    CHECK(new_info_config1->n_configs == 1);

    config_push_data* new_mem_config1 = config_push(admin1.members);
    CHECK(new_mem_config1->seqno == 1);
    CHECK(new_mem_config1->n_configs == 1);

    const char* merge_hash1[1];
    const unsigned char* merge_data1[2];
    size_t merge_size1[2];

    merge_hash1[0] = "fakehash1";

    merge_data1[0] = new_info_config1->config[0];
    merge_size1[0] = new_info_config1->config_lens[0];

    merge_data1[1] = new_mem_config1->config[0];
    merge_size1[1] = new_mem_config1->config_lens[0];

    const char* tmphash;  // test suite cheat: &(tmphash = "asdf") to fake a length-1 array.

    /*  Even though we have only added one admin, admin2 will still be able to see group info
        like group size and merge all configs. This is because they have loaded the key config
        message, which they can decrypt with the group secret key.
    */
    for (auto& a : admins) {
        REQUIRE(groups_keys_load_message(
                a.keys,
                "fakekeyshash1",
                new_keys_config_1,
                key_len1,
                get_timestamp_ms(),
                a.info,
                a.members));
        config_string_list* hashes;
        hashes = config_merge(a.info, merge_hash1, &merge_data1[0], &merge_size1[0], 1);
        REQUIRE(hashes->len);
        free(hashes);
        config_confirm_pushed(a.info, new_info_config1->seqno, &(tmphash = "fakehash1"), 1);

        hashes = config_merge(a.members, merge_hash1, &merge_data1[1], &merge_size1[1], 1);
        REQUIRE(hashes->len);
        free(hashes);
        config_confirm_pushed(a.members, new_mem_config1->seqno, &(tmphash = "fakehash1"), 1);

        REQUIRE(groups_members_size(a.members) == 1);
    }

    /*  All attempts to merge non-admin members will throw, as none of the non admin members
        will be able to decrypt the new info/member configs using the updated keys
    */
    for (auto& m : members) {
        // this will return true if the message was parsed successfully, NOT if the keys were
        // decrypted
        REQUIRE(groups_keys_load_message(
                m.keys,
                "fakekeyshash1",
                new_keys_config_1,
                key_len1,
                get_timestamp_ms(),
                m.info,
                m.members));
        [[maybe_unused]] config_string_list* hashes;
        hashes = config_merge(m.info, merge_hash1, &merge_data1[0], &merge_size1[0], 1);
        REQUIRE(m.info->last_error == "Cannot merge configs without any decryption keys"sv);
        m.info->last_error = nullptr;
        hashes = config_merge(m.members, merge_hash1, &merge_data1[1], &merge_size1[1], 1);
        REQUIRE(m.members->last_error == "Cannot merge configs without any decryption keys"sv);
        m.members->last_error = nullptr;

        REQUIRE(groups_members_size(m.members) == 0);
    }

    free(new_info_config1);
    free(new_mem_config1);

    for (size_t i = 0; i < members.size(); ++i) {
        config_group_member new_mem;

        REQUIRE(groups_members_get_or_construct(
                members[i].members, &new_mem, members[i].session_id.c_str()));
        new_mem.admin = false;
        groups_members_set(admin1.members, &new_mem);
    }

    CHECK(config_needs_push(admin1.members));

    const unsigned char* new_keys_config_2;
    size_t key_len2;
    REQUIRE(groups_keys_rekey(
            admin1.keys, admin1.info, admin1.members, &new_keys_config_2, &key_len2));

    config_push_data* new_info_config2 = config_push(admin1.info);
    CHECK(new_info_config2->seqno == 2);

    config_push_data* new_mem_config2 = config_push(admin1.members);
    CHECK(new_mem_config2->seqno == 2);

    const char* merge_hash2[1];
    const unsigned char* merge_data2[2];
    size_t merge_size2[2];

    merge_hash2[0] = "fakehash2";

    REQUIRE(new_info_config2->n_configs == 1);
    REQUIRE(new_mem_config2->n_configs == 1);

    merge_data2[0] = new_info_config2->config[0];
    merge_size2[0] = new_info_config2->config_lens[0];

    merge_data2[1] = new_mem_config2->config[0];
    merge_size2[1] = new_mem_config2->config_lens[0];

    for (auto& a : admins) {
        REQUIRE(groups_keys_load_message(
                a.keys,
                "fakekeyshash2",
                new_keys_config_2,
                key_len2,
                get_timestamp_ms(),
                a.info,
                a.members));
        config_string_list* hashes;
        hashes = config_merge(a.info, merge_hash2, &merge_data2[0], &merge_size2[0], 1);
        REQUIRE(hashes->len);
        free(hashes);
        config_confirm_pushed(a.info, new_info_config2->seqno, &(tmphash = "fakehash2"), 1);
        hashes = config_merge(a.members, merge_hash2, &merge_data2[1], &merge_size2[1], 1);
        REQUIRE(hashes->len);
        free(hashes);
        config_confirm_pushed(a.members, new_mem_config2->seqno, &(tmphash = "fakehash2"), 1);

        REQUIRE(groups_members_size(a.members) == 5);
    }

    {
        // Test get keys bulk API
        {
            size_t keys_size = groups_keys_size(admins[0].keys);
            std::vector<span_u8> keys_list;
            keys_list.resize(keys_size);
            size_t keys_read =
                    groups_keys_get_keys(admins[0].keys, 0, keys_list.data(), keys_list.size());
            REQUIRE(keys_read == keys_size);
        }

        // Test get keys OOB
        {
            size_t keys_size = groups_keys_size(admins[0].keys);
            std::vector<span_u8> keys_list;
            keys_list.resize(keys_size);
            size_t keys_read = groups_keys_get_keys(
                    admins[0].keys, keys_size, keys_list.data(), keys_list.size());
            REQUIRE(keys_read == 0);
        }
    }

    free(new_info_config2);
    free(new_mem_config2);
}

TEST_CASE("Group Keys - swarm authentication", "[config][groups][keys][swarm]") {

    const std::vector<unsigned char> group_seed =
            "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210"_hexbytes;
    const std::vector<unsigned char> admin_seed =
            "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"_hexbytes;
    const std::vector<unsigned char> member_seed =
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"_hexbytes;

    std::array<unsigned char, 32> group_pk;
    std::array<unsigned char, 64> group_sk;

    crypto_sign_ed25519_seed_keypair(group_pk.data(), group_sk.data(), group_seed.data());
    REQUIRE(oxenc::to_hex(group_seed.begin(), group_seed.end()) ==
            oxenc::to_hex(group_sk.begin(), group_sk.begin() + 32));

    CHECK(oxenc::to_hex(group_pk.begin(), group_pk.end()) ==
          "c50cb3ae956947a8de19135b5be2685ff348afc63fc34a837aca12bc5c1f5625");

    pseudo_client admin{admin_seed, true, group_pk.data(), group_sk.data()};
    pseudo_client member{member_seed, false, group_pk.data(), std::nullopt};
    session::config::UserGroups member_groups{member_seed, std::nullopt};

    CHECK(admin.session_id == "05f1e8b64bbf761edf8f7b47e3a1f369985644cce0a62adb8e21604474bdd49627");

    CHECK(member.session_id ==
          "05c5ba413c336f2fe1fb9a2c525f8a86a412a1db128a7841b4e0e217fa9eb7fd5"
          "e");
    CHECK(oxenc::to_hex(group_pk.begin(), group_pk.end()) ==
          "c50cb3ae956947a8de19135b5be2685ff348afc63fc34a837aca12bc5c1f5625");
    CHECK(member.info.id == "03c50cb3ae956947a8de19135b5be2685ff348afc63fc34a837aca12bc5c1f5625");

    auto auth_data = admin.keys.swarm_make_subaccount(member.session_id);
    {
        auto g = member_groups.get_or_construct_group(member.info.id);
        g.auth_data = auth_data;
        member_groups.set(g);
    }

    session::config::UserGroups member_gr2{member_seed, std::nullopt};
    auto [seqno, push, obs] = member_groups.push();

    REQUIRE(push.size() == 1);

    std::vector<std::pair<std::string, std::span<const unsigned char>>> gr_conf;
    gr_conf.emplace_back("fakehash1", push[0]);

    member_gr2.merge(gr_conf);

    auto g = member_groups.get_group(member.info.id);
    REQUIRE(g);
    CHECK(g->id == member.info.id);
    CHECK(g->auth_data == auth_data);

    auto to_sign = session::to_span("retrieve9991693340111000");
    auto subauth_b64 = member.keys.swarm_subaccount_sign(to_sign, auth_data);

    CHECK(subauth_b64.subaccount == "AwMAAIWvMR2nJXCFnK5+hNahNecWqMC39/TVVLjaR3imNug5");
    CHECK(subauth_b64.subaccount_sig ==
          "6brvv/"
          "2jfciBAJeRKMGSepNJLullyrVVHijyVDE+8GC5Oc89UNxjNrq1kVV1P+pkUIRDOew24gSLFgLZfdl+BQ==");
    CHECK(subauth_b64.signature ==
          "c3PJ4g29v5RivKm8Tdg49vGU2/"
          "6kVd0yONnpz5U5zePMYptqW3iYQ0TYf2rEzv3qqkPhS5p67M5GAccHoBHGDQ==");

    auto subauth = member.keys.swarm_subaccount_sign(to_sign, auth_data, true);
    CHECK(oxenc::to_base64(subauth.subaccount) == subauth_b64.subaccount);
    CHECK(oxenc::to_base64(subauth.subaccount_sig) == subauth_b64.subaccount_sig);
    CHECK(oxenc::to_base64(subauth.signature) == subauth_b64.signature);

    CHECK(0 ==
          crypto_sign_ed25519_verify_detached(
                  reinterpret_cast<const unsigned char*>(subauth.signature.data()),
                  to_sign.data(),
                  to_sign.size(),
                  reinterpret_cast<const unsigned char*>(subauth.subaccount.substr(4).data())));

    CHECK(member.keys.swarm_verify_subaccount(auth_data));
    CHECK(session::config::groups::Keys::swarm_verify_subaccount(
            member.info.id, session::to_span(member.secret_key), auth_data));

    // Try flipping a bit in each position of the auth data and make sure it fails to validate:
    for (size_t i = 0; i < auth_data.size(); i++) {
        for (int b = 0; b < 8; b++) {
            if (i == 35 && b == 7)  // This is the sign bit of k, which can be flipped but gets
                                    // flipped back when dealing with the missing X->Ed conversion
                                    // sign bit, so won't actually change anything if it flips.
                continue;
            auto auth_data2 = auth_data;
            auth_data2[i] ^= 1 << b;
            CHECK_FALSE(session::config::groups::Keys::swarm_verify_subaccount(
                    member.info.id, session::to_span(member.secret_key), auth_data2));
        }
    }
}

TEST_CASE("Group Keys promotion", "[config][groups][keys][promotion]") {

    const std::vector<unsigned char> group_seed =
            "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210"_hexbytes;
    const std::vector<unsigned char> admin1_seed =
            "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"_hexbytes;
    const std::vector<unsigned char> member1_seed =
            "000111222333444555666777888999aaabbbcccdddeeefff0123456789abcdef"_hexbytes;

    std::array<unsigned char, 32> group_pk;
    std::array<unsigned char, 64> group_sk;

    crypto_sign_ed25519_seed_keypair(group_pk.data(), group_sk.data(), group_seed.data());
    REQUIRE(oxenc::to_hex(group_seed.begin(), group_seed.end()) ==
            oxenc::to_hex(group_sk.begin(), group_sk.begin() + 32));

    pseudo_client admin{admin1_seed, true, group_pk.data(), group_sk.data()};
    pseudo_client member{member1_seed, false, group_pk.data(), std::nullopt};

    std::vector<std::pair<std::string, std::span<const unsigned char>>> configs;
    {
        auto m = admin.members.get_or_construct(admin.session_id);
        m.admin = true;
        m.name = "Lrrr";
        admin.members.set(m);
    }
    {
        auto m = admin.members.get_or_construct(member.session_id);
        m.admin = false;
        m.name = "Nibbler";
        admin.members.set(m);
    }
    admin.info.set_name("Omicron Persei 8");
    auto [mseq, mdata, mobs] = admin.members.push();
    admin.members.confirm_pushed(mseq, {"mpush1"});
    auto [iseq, idata, iobs] = admin.info.push();
    admin.info.confirm_pushed(mseq, {"ipush1"});

    REQUIRE(admin.keys.pending_config());
    member.keys.load_key_message(
            "keyhash1",
            *admin.keys.pending_config(),
            get_timestamp_ms(),
            member.info,
            member.members);
    admin.keys.load_key_message(
            "keyhash1",
            *admin.keys.pending_config(),
            get_timestamp_ms(),
            member.info,
            member.members);

    member.keys.load_key_message(
            "keyhash2",
            admin.keys.key_supplement(member.session_id),
            get_timestamp_ms(),
            member.info,
            member.members);

    REQUIRE(mdata.size() == 1);
    configs.emplace_back("mpush1", mdata[0]);
    CHECK(member.members.merge(configs) == std::unordered_set{{"mpush1"s}});

    configs.clear();
    REQUIRE(idata.size() == 1);
    configs.emplace_back("ipush1", idata[0]);
    CHECK(member.info.merge(configs) == std::unordered_set{{"ipush1"s}});

    REQUIRE(admin.keys.admin());
    REQUIRE_FALSE(member.keys.admin());
    REQUIRE(member.info.is_readonly());
    REQUIRE(member.members.is_readonly());

    member.keys.load_admin_key(session::to_span(group_sk), member.info, member.members);

    CHECK(member.keys.admin());
    CHECK_FALSE(member.members.is_readonly());
    CHECK_FALSE(member.info.is_readonly());

    member.info.set_name("new name"s);

    CHECK(member.info.needs_push());
    auto [iseq2, idata2, iobs2] = member.info.push();
    REQUIRE(idata2.size() == 1);

    configs.clear();
    configs.emplace_back("ihash2", idata2[0]);

    CHECK(admin.info.merge(configs) == std::unordered_set{{"ihash2"s}});

    CHECK(admin.info.get_name() == "new name");
}

TEST_CASE(
        "Group Keys - the same key under a second message hash",
        "[config][groups][keys][recovery]") {

    // insert_key's early-return path: we already hold this key, but this is a *different* message
    // carrying it.  Both copies want renewing, so the new hash has to be recorded -- and persisted,
    // or it is silently lost on the next restart and that message stops being renewed.
    const std::vector<unsigned char> group_seed =
            "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210"_hexbytes;
    const std::vector<unsigned char> admin_seed =
            "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"_hexbytes;
    const std::vector<unsigned char> member_seed =
            "000111222333444555666777888999aaabbbcccdddeeefff0123456789abcdef"_hexbytes;

    std::array<unsigned char, 32> group_pk;
    std::array<unsigned char, 64> group_sk;
    crypto_sign_ed25519_seed_keypair(group_pk.data(), group_sk.data(), group_seed.data());

    pseudo_client admin{admin_seed, true, group_pk.data(), group_sk.data()};
    pseudo_client member{member_seed, false, group_pk.data(), std::nullopt};

    for (const auto* c : {&admin, &member}) {
        auto m = admin.members.get_or_construct(c->session_id);
        m.admin = (c == &admin);
        admin.members.set(m);
    }
    auto rekey1 = session::to_vector(admin.keys.rekey(admin.info, admin.members));

    constexpr int64_t t0 = 1'700'000'000'000;
    REQUIRE(admin.keys.load_key_message("keyhash1", rekey1, t0, admin.info, admin.members));
    REQUIRE(member.keys.load_key_message("keyhash1", rekey1, t0, member.info, member.members));

    member.keys.dump();  // clear needs_dump
    REQUIRE_FALSE(member.keys.needs_dump());

    CHECK(member.keys.load_key_message("keyhash1b", rekey1, t0, member.info, member.members));
    CHECK(member.keys.active_hashes().count("keyhash1b"));
    CHECK(member.keys.needs_dump());

    // Re-loading a message we already know changes nothing, so it must not ask for a dump.
    member.keys.dump();
    CHECK(member.keys.load_key_message("keyhash1b", rekey1, t0, member.info, member.members));
    CHECK_FALSE(member.keys.needs_dump());

    // The second copy survives the round trip, so it is still renewable after a restart.
    auto dump = member.keys.dump();
    pseudo_client reloaded{
            member_seed, false, group_pk.data(), std::nullopt, std::nullopt, std::nullopt, dump};
    CHECK(reloaded.keys.active_hashes().count("keyhash1b"));
}

// Recovery support: `Keys` retains the raw bytes of each active keys message so that a message
// which has expired from the swarm can be re-stored *verbatim*.  Verbatim is the whole point — a
// keys message carries an admin signature and junk padding derived from the group secret key, so a
// member cannot regenerate one, but it can push back bytes it already holds.
namespace {

// Rebuilds a Keys dump with the "C" (retained message bytes) key stripped, i.e. the format written
// before this feature existed.  Used to check an old dump still loads.
std::vector<unsigned char> strip_retained_messages(std::span<const unsigned char> dump) {
    // Re-emit the raw sub-encodings rather than re-serialising values, so what comes out is
    // byte-for-byte what the old code would have written.
    oxenc::bt_dict_consumer d{dump};
    std::string out = "d";
    REQUIRE(d.skip_until("A"));
    out += "1:A";
    out += d.consume_list_data();
    if (d.skip_until("C"))
        d.consume_dict_data();  // drop it
    REQUIRE(d.skip_until("L"));
    out += "1:L";
    out += d.consume_list_data();
    if (d.skip_until("P")) {
        out += "1:P";
        out += d.consume_dict_data();
    }
    out += "e";
    return session::to_vector(out);
}

}  // namespace

TEST_CASE("Group Keys - retained message bytes", "[config][groups][keys][recovery]") {

    const std::vector<unsigned char> group_seed =
            "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210"_hexbytes;
    const std::vector<unsigned char> admin_seed =
            "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"_hexbytes;
    const std::vector<unsigned char> member_seed =
            "000111222333444555666777888999aaabbbcccdddeeefff0123456789abcdef"_hexbytes;
    const std::vector<unsigned char> member2_seed =
            "00011122435111155566677788811263446552465222efff0123456789abcdef"_hexbytes;

    std::array<unsigned char, 32> group_pk;
    std::array<unsigned char, 64> group_sk;
    crypto_sign_ed25519_seed_keypair(group_pk.data(), group_sk.data(), group_seed.data());

    pseudo_client admin{admin_seed, true, group_pk.data(), group_sk.data()};
    pseudo_client member{member_seed, false, group_pk.data(), std::nullopt};
    pseudo_client member2{member2_seed, false, group_pk.data(), std::nullopt};

    // Put the admin and member1 in the group, then rekey so member1 can actually read the message.
    for (const auto* c : {&admin, &member}) {
        auto m = admin.members.get_or_construct(c->session_id);
        m.admin = (c == &admin);
        admin.members.set(m);
    }
    auto rekey1 = session::to_vector(admin.keys.rekey(admin.info, admin.members));

    constexpr int64_t t0 = 1'700'000'000'000;

    // The admin has to load its own rekey back to confirm it; until it does, the key is only
    // pending and the generation doesn't advance.
    REQUIRE(admin.keys.load_key_message("keyhash1", rekey1, t0, admin.info, admin.members));
    REQUIRE(member.keys.load_key_message("keyhash1", rekey1, t0, member.info, member.members));

    SECTION("bytes are retained verbatim, and survive a dump/reload") {
        auto held = member.keys.active_key_messages();
        REQUIRE(held.size() == 1);
        REQUIRE(held.count("keyhash1"));
        CHECK(to_hex(session::to_vector(held.at("keyhash1"))) == to_hex(rekey1));

        auto one = member.keys.active_key_message("keyhash1");
        REQUIRE(one);
        CHECK(to_hex(session::to_vector(*one)) == to_hex(rekey1));
        CHECK_FALSE(member.keys.active_key_message("nosuchhash"));

        // Every hash we advertise for renewal has bytes behind it.
        CHECK(as_set(member.keys.active_hashes()) == std::set<std::string>{{"keyhash1"s}});

        auto dump = member.keys.dump();
        pseudo_client reloaded{
                member_seed,
                false,
                group_pk.data(),
                std::nullopt,
                std::nullopt,
                std::nullopt,
                dump};

        auto held2 = reloaded.keys.active_key_messages();
        REQUIRE(held2.size() == 1);
        REQUIRE(held2.count("keyhash1"));
        CHECK(to_hex(session::to_vector(held2.at("keyhash1"))) == to_hex(rekey1));
    }

    SECTION("a supplemental is retained alongside the full message of the same generation") {
        // This is why storage is keyed by hash rather than generation: one generation carries the
        // full rekey plus every supplemental issued against it, and a member that receives only
        // the supplemental does not get the key.
        auto supp = admin.keys.key_supplement(member2.session_id);
        // False here just means "no key in it for us" -- it is addressed to member2.  We still
        // retain it, which is the point: this is the path where a message is recorded against the
        // generation without contributing a key, and a member who receives only the supplemental
        // needs the full message too.
        CHECK_FALSE(member.keys.load_key_message(
                "keyhash2", supp, t0 + 1000, member.info, member.members));

        auto held = member.keys.active_key_messages();
        REQUIRE(held.size() == 2);
        REQUIRE(held.count("keyhash1"));
        REQUIRE(held.count("keyhash2"));
        CHECK(to_hex(session::to_vector(held.at("keyhash1"))) == to_hex(rekey1));
        CHECK(to_hex(session::to_vector(held.at("keyhash2"))) == to_hex(supp));

        // Both belong to the same generation, and both are advertised for renewal.
        CHECK(as_set(member.keys.active_hashes()) ==
              std::set<std::string>{{"keyhash1"s, "keyhash2"s}});

        // ...and both survive a dump/reload, which is what recovery after a restart depends on.
        auto dump = member.keys.dump();
        pseudo_client reloaded{
                member_seed,
                false,
                group_pk.data(),
                std::nullopt,
                std::nullopt,
                std::nullopt,
                dump};
        auto held2 = reloaded.keys.active_key_messages();
        REQUIRE(held2.size() == 2);
        CHECK(to_hex(session::to_vector(held2.at("keyhash1"))) == to_hex(rekey1));
        CHECK(to_hex(session::to_vector(held2.at("keyhash2"))) == to_hex(supp));
    }

    SECTION("pruning: bytes are dropped when their generation expires") {
        // The generation-erase branch of remove_expired().  Expiry is driven by the swarm-provided
        // message timestamps, not the system clock, so we just hand it messages far enough apart.
        auto rekey2 = session::to_vector(admin.keys.rekey(admin.info, admin.members));
        REQUIRE(admin.keys.load_key_message(
                "keyhash2", rekey2, t0 + 1000, admin.info, admin.members));
        REQUIRE(member.keys.load_key_message(
                "keyhash2", rekey2, t0 + 1000, member.info, member.members));
        CHECK(member.keys.active_key_messages().size() == 2);

        // A third generation, more than KEY_EXPIRY (60d) after the second, retires the first.
        constexpr int64_t past_expiry = t0 + 1000 + 61 * 24 * 60 * 60 * 1000LL;
        auto rekey3 = session::to_vector(admin.keys.rekey(admin.info, admin.members));
        REQUIRE(admin.keys.load_key_message(
                "keyhash3", rekey3, past_expiry, admin.info, admin.members));
        REQUIRE(member.keys.load_key_message(
                "keyhash3", rekey3, past_expiry, member.info, member.members));

        auto held = member.keys.active_key_messages();
        CHECK_FALSE(held.count("keyhash1"));

        // The invariant that bounds this cache: it holds exactly the hashes we still advertise.
        std::set<std::string> held_hashes;
        for (const auto& [h, _] : held)
            held_hashes.insert(h);
        CHECK(held_hashes == as_set(member.keys.active_hashes()));

        // And the shrink is real on disk, not just in memory.
        auto dump = member.keys.dump();
        pseudo_client reloaded{
                member_seed,
                false,
                group_pk.data(),
                std::nullopt,
                std::nullopt,
                std::nullopt,
                dump};
        CHECK_FALSE(reloaded.keys.active_key_messages().count("keyhash1"));
    }

    SECTION("pruning: bytes are dropped when we hold no keys at all") {
        // The other branch of remove_expired(): `keys_` empty means we aren't keeping any of the
        // group's history, so active_msgs_ is cleared outright.  member2 was never given the keys,
        // so it reaches this by loading a supplemental addressed to somebody else.
        auto supp = admin.keys.key_supplement(member.session_id);

        REQUIRE(member2.keys.size() == 0);
        CHECK_FALSE(member2.keys.load_key_message(
                "keyhash9", supp, t0 + 1000, member2.info, member2.members));

        CHECK(member2.keys.active_hashes().empty());
        CHECK(member2.keys.active_key_messages().empty());
    }

    SECTION("dump compatibility, both directions") {
        auto supp = admin.keys.key_supplement(member2.session_id);
        // False here just means "no key in it for us" -- it is addressed to member2.  We still
        // retain it, which is the point: this is the path where a message is recorded against the
        // generation without contributing a key, and a member who receives only the supplemental
        // needs the full message too.
        CHECK_FALSE(member.keys.load_key_message(
                "keyhash2", supp, t0 + 1000, member.info, member.members));
        auto dump = member.keys.dump();

        SECTION("an old dump loads under new code") {
            auto old_dump = strip_retained_messages(dump);
            pseudo_client reloaded{
                    member_seed,
                    false,
                    group_pk.data(),
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    old_dump};

            // The hashes still load; we simply have no bytes for them, which is exactly the
            // position of every group that predates this feature.
            CHECK(as_set(reloaded.keys.active_hashes()) ==
                  std::set<std::string>{{"keyhash1"s, "keyhash2"s}});
            CHECK(reloaded.keys.active_key_messages().empty());

            // Still fully functional: it can decrypt with the keys it loaded.
            CHECK(reloaded.keys.size() == member.keys.size());
        }

        SECTION("re-loading the messages captures bytes an old dump never had") {
            // An old dump knows the hashes but not the bytes, so re-loading the same messages is
            // the one way a device that predates retention can come to hold them.  Every key in
            // them is already known, so nothing about the keys changes -- only the bytes, and a
            // dump has to be flagged for those or they are gone again after the next restart.
            pseudo_client reloaded{
                    member_seed,
                    false,
                    group_pk.data(),
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    strip_retained_messages(dump)};
            REQUIRE(reloaded.keys.active_key_messages().empty());
            reloaded.keys.dump();
            REQUIRE_FALSE(reloaded.keys.needs_dump());

            CHECK(reloaded.keys.load_key_message(
                    "keyhash1", rekey1, t0, reloaded.info, reloaded.members));
            CHECK(reloaded.keys.needs_dump());

            // The supplemental holds no key for this member, so the load reports false; the bytes
            // are retained all the same.
            reloaded.keys.dump();
            CHECK_FALSE(reloaded.keys.load_key_message(
                    "keyhash2", supp, t0 + 1000, reloaded.info, reloaded.members));
            CHECK(reloaded.keys.needs_dump());

            CHECK(reloaded.keys.size() == member.keys.size());

            pseudo_client restarted{
                    member_seed,
                    false,
                    group_pk.data(),
                    std::nullopt,
                    std::nullopt,
                    std::nullopt,
                    reloaded.keys.dump()};
            auto held = restarted.keys.active_key_messages();
            REQUIRE(held.size() == 2);
            CHECK(to_hex(session::to_vector(held.at("keyhash1"))) == to_hex(rekey1));
            CHECK(to_hex(session::to_vector(held.at("keyhash2"))) == to_hex(supp));
        }

        SECTION("a new dump loads under old code") {
            // Old code reads with skip_until over "A", "L", "P" and never asks for "C", so the
            // unknown key is skipped.  Parsing the new dump the way the old code does must still
            // yield the same "A" and "L".
            oxenc::bt_dict_consumer d{dump};
            REQUIRE(d.skip_until("A"));
            auto active = d.consume_list_consumer();
            std::set<std::string> hashes;
            while (!active.is_finished()) {
                auto lst = active.consume_list_consumer();
                lst.consume_integer<int64_t>();  // generation
                while (!lst.is_finished())
                    hashes.insert(lst.consume_string());
            }
            CHECK(hashes == std::set<std::string>{{"keyhash1"s, "keyhash2"s}});

            // "C" sorts between "A" and "L", so a consumer that skips straight to "L" must still
            // find it -- this is the assertion that would fail if the new key were misplaced.
            REQUIRE(d.skip_until("L"));
            auto keys = d.consume_list_consumer();
            CHECK_FALSE(keys.is_finished());
        }
    }

    SECTION("C API") {
        auto dump = member.keys.dump();
        config_group_keys* conf;
        config_object* info_conf;
        config_object* mem_conf;
        char err[256];
        REQUIRE(groups_info_init(&info_conf, group_pk.data(), nullptr, nullptr, 0, err) == 0);
        REQUIRE(groups_members_init(&mem_conf, group_pk.data(), nullptr, nullptr, 0, err) == 0);

        auto member_sk = sk_from_seed(member_seed);
        REQUIRE(groups_keys_init(
                        &conf,
                        member_sk.data(),
                        group_pk.data(),
                        nullptr,
                        info_conf,
                        mem_conf,
                        dump.data(),
                        dump.size(),
                        err) == 0);

        const unsigned char* data = nullptr;
        size_t datalen = 0;
        CHECK(groups_keys_active_message(conf, "keyhash1", &data, &datalen));
        REQUIRE(data);
        CHECK(to_hex(std::vector<unsigned char>{data, data + datalen}) == to_hex(rekey1));

        // A hash we don't hold bytes for is a plain "no", not an error.
        const unsigned char* missing = nullptr;
        size_t missinglen = 0;
        CHECK_FALSE(groups_keys_active_message(conf, "nosuchhash", &missing, &missinglen));
        CHECK(missing == nullptr);

        groups_keys_free(conf);
        config_free(info_conf);
        config_free(mem_conf);
    }
}

TEST_CASE("Group Keys - one message, several generations", "[config][groups][keys][recovery]") {

    // `key_supplement` packs every key in `keys_`, so a member that can decrypt one ends up
    // recording the same hash against each generation it carried.  Retained bytes are therefore
    // shared between generations, and must outlive the *oldest* of them expiring -- pruning per
    // dropped generation would strand a hash that is still active under a newer one.
    const std::vector<unsigned char> group_seed =
            "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210"_hexbytes;
    const std::vector<unsigned char> admin_seed =
            "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"_hexbytes;
    const std::vector<unsigned char> member_seed =
            "000111222333444555666777888999aaabbbcccdddeeefff0123456789abcdef"_hexbytes;

    std::array<unsigned char, 32> group_pk;
    std::array<unsigned char, 64> group_sk;
    crypto_sign_ed25519_seed_keypair(group_pk.data(), group_sk.data(), group_seed.data());

    pseudo_client admin{admin_seed, true, group_pk.data(), group_sk.data()};
    pseudo_client member{member_seed, false, group_pk.data(), std::nullopt};

    for (const auto* c : {&admin, &member}) {
        auto m = admin.members.get_or_construct(c->session_id);
        m.admin = (c == &admin);
        admin.members.set(m);
    }

    constexpr int64_t t0 = 1'700'000'000'000;

    auto rekey1 = session::to_vector(admin.keys.rekey(admin.info, admin.members));
    REQUIRE(admin.keys.load_key_message("keyhash1", rekey1, t0, admin.info, admin.members));
    REQUIRE(member.keys.load_key_message("keyhash1", rekey1, t0, member.info, member.members));

    auto rekey2 = session::to_vector(admin.keys.rekey(admin.info, admin.members));
    REQUIRE(admin.keys.load_key_message("keyhash2", rekey2, t0 + 1000, admin.info, admin.members));
    REQUIRE(member.keys.load_key_message(
            "keyhash2", rekey2, t0 + 1000, member.info, member.members));

    // Addressed to the member itself, so it decrypts and yields a key per generation the admin
    // holds -- all of which the member already has, i.e. insert_key's early-return path, twice.
    REQUIRE(admin.keys.size() == 2);
    auto supp = admin.keys.key_supplement(member.session_id);
    CHECK(member.keys.load_key_message("supphash", supp, t0 + 2000, member.info, member.members));

    REQUIRE(member.keys.active_key_message("supphash"));
    CHECK(to_hex(session::to_vector(*member.keys.active_key_message("supphash"))) == to_hex(supp));

    // A third generation far enough ahead to retire the first.
    constexpr int64_t past_expiry = t0 + 1000 + 61 * 24 * 60 * 60 * 1000LL;
    auto rekey3 = session::to_vector(admin.keys.rekey(admin.info, admin.members));
    REQUIRE(admin.keys.load_key_message(
            "keyhash3", rekey3, past_expiry, admin.info, admin.members));
    REQUIRE(member.keys.load_key_message(
            "keyhash3", rekey3, past_expiry, member.info, member.members));

    // The first generation's own message is gone...
    CHECK_FALSE(member.keys.active_key_message("keyhash1"));

    // ...but the supplemental is still named by a generation we keep, so its bytes must survive.
    CHECK(member.keys.active_hashes().count("supphash"));
    REQUIRE(member.keys.active_key_message("supphash"));
    CHECK(to_hex(session::to_vector(*member.keys.active_key_message("supphash"))) == to_hex(supp));

    // The invariant, stated as the tests above state it: what we advertise is what we can re-store.
    std::set<std::string> held;
    for (const auto& [h, _] : member.keys.active_key_messages())
        held.insert(h);
    CHECK(held == as_set(member.keys.active_hashes()));

    // And the same after a restart.
    auto dump = member.keys.dump();
    pseudo_client reloaded{
            member_seed, false, group_pk.data(), std::nullopt, std::nullopt, std::nullopt, dump};
    REQUIRE(reloaded.keys.active_key_message("supphash"));
    CHECK(to_hex(session::to_vector(*reloaded.keys.active_key_message("supphash"))) ==
          to_hex(supp));
    CHECK_FALSE(reloaded.keys.active_key_message("keyhash1"));
}

namespace {

// Rebuilds a Keys dump with an extra "C" entry whose hash is not named in "A" -- the sort of orphan
// a hand-written or corrupted dump can carry, and which nothing would ever prune again.
std::vector<unsigned char> add_orphan_retained_message(
        std::span<const unsigned char> dump, std::string_view hash) {
    oxenc::bt_dict_consumer d{dump};
    std::string out = "d";

    REQUIRE(d.skip_until("A"));
    out += "1:A";
    out += d.consume_list_data();

    std::map<std::string, std::string> msgs;
    if (d.skip_until("C")) {
        auto c = d.consume_dict_consumer();
        while (!c.is_finished()) {
            auto [h, v] = c.next_string();
            msgs.emplace(h, v);
        }
    }
    REQUIRE(msgs.emplace(hash, "not a keys message at all").second);
    {
        oxenc::bt_dict_producer c;
        for (const auto& [h, v] : msgs)
            c.append(h, v);
        out += "1:C";
        out += c.view();
    }

    REQUIRE(d.skip_until("L"));
    out += "1:L";
    out += d.consume_list_data();
    if (d.skip_until("P")) {
        out += "1:P";
        out += d.consume_dict_data();
    }
    out += "e";
    return session::to_vector(out);
}

}  // namespace

TEST_CASE("Group Keys - orphaned retained messages", "[config][groups][keys][recovery]") {

    const std::vector<unsigned char> group_seed =
            "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210"_hexbytes;
    const std::vector<unsigned char> admin_seed =
            "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"_hexbytes;
    const std::vector<unsigned char> member_seed =
            "000111222333444555666777888999aaabbbcccdddeeefff0123456789abcdef"_hexbytes;

    std::array<unsigned char, 32> group_pk;
    std::array<unsigned char, 64> group_sk;
    crypto_sign_ed25519_seed_keypair(group_pk.data(), group_sk.data(), group_seed.data());

    pseudo_client admin{admin_seed, true, group_pk.data(), group_sk.data()};
    pseudo_client member{member_seed, false, group_pk.data(), std::nullopt};

    for (const auto* c : {&admin, &member}) {
        auto m = admin.members.get_or_construct(c->session_id);
        m.admin = (c == &admin);
        admin.members.set(m);
    }

    constexpr int64_t t0 = 1'700'000'000'000;
    auto rekey1 = session::to_vector(admin.keys.rekey(admin.info, admin.members));
    REQUIRE(admin.keys.load_key_message("keyhash1", rekey1, t0, admin.info, admin.members));
    REQUIRE(member.keys.load_key_message("keyhash1", rekey1, t0, member.info, member.members));

    SECTION("an orphan in the dump is dropped, and the cleaned dump is written back") {
        auto tampered = add_orphan_retained_message(member.keys.dump(), "zorphanhash");
        pseudo_client reloaded{
                member_seed,
                false,
                group_pk.data(),
                std::nullopt,
                std::nullopt,
                std::nullopt,
                tampered};

        CHECK_FALSE(reloaded.keys.active_key_message("zorphanhash"));
        CHECK(reloaded.keys.active_key_message("keyhash1"));

        // Pruning it in memory is only half the job: the orphan is still on disk until something
        // asks for a dump, and nothing else here would.
        CHECK(reloaded.keys.needs_dump());

        auto cleaned = reloaded.keys.dump();
        pseudo_client again{
                member_seed,
                false,
                group_pk.data(),
                std::nullopt,
                std::nullopt,
                std::nullopt,
                cleaned};
        CHECK_FALSE(again.keys.active_key_message("zorphanhash"));
        CHECK(again.keys.active_key_message("keyhash1"));
        // A dump with nothing to prune must not ask to be rewritten on every load.
        CHECK_FALSE(again.keys.needs_dump());
    }
}
