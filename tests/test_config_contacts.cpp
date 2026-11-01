#include <oxenc/endian.h>
#include <oxenc/hex.h>
#include <session/config/contacts.h>
#include <session/session_protocol.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <random>
#include <session/config/contacts.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/util.hpp>
#include <string_view>

#include "utils.hpp"

static constexpr int64_t created_ts = 1680064059;

using namespace session;

TEST_CASE("Contacts", "[config][contacts]") {

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hex_b;
    auto [ed_pk, ed_sk] = ed25519::keypair(seed);
    auto curve_pk = ed25519::pk_to_x25519(ed_pk);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(oxenc::to_hex(seed.begin(), seed.end()) ==
          oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    session::config::Contacts contacts{seed, std::nullopt};

    constexpr auto definitely_real_id =
            "050000000000000000000000000000000000000000000000000000000000000000"sv;

    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();

    CHECK_FALSE(contacts.get(definitely_real_id));

    CHECK(contacts.empty());
    CHECK(contacts.size() == 0);

    auto c = contacts.get_or_construct(definitely_real_id);

    CHECK(c.name.empty());
    CHECK(c.nickname.empty());
    CHECK(c.profile_updated == std::chrono::sys_seconds{});
    CHECK_FALSE(c.approved);
    CHECK_FALSE(c.approved_me);
    CHECK_FALSE(c.blocked);
    CHECK_FALSE(c.profile_picture);
    CHECK(c.created == 0);
    CHECK(c.notifications == session::config::notify_mode::defaulted);
    CHECK(c.delete_before == std::chrono::sys_seconds{});
    CHECK(c.delete_attach_before == std::chrono::sys_seconds{});
    CHECK(c.mute_until == 0);

    CHECK_FALSE(contacts.needs_push());
    CHECK_FALSE(contacts.needs_dump());
    CHECK(std::get<seqno_t>(contacts.push()) == 0);

    c.set_name("Joe");
    c.set_nickname("Joey");
    c.profile_updated = std::chrono::sys_seconds{1s};
    c.approved = true;
    c.approved_me = true;
    c.created = created_ts * 1'000;
    c.notifications = session::config::notify_mode::all;
    c.mute_until = (now + 1800) * 1'000'000;
    c.delete_before = std::chrono::sys_seconds{std::chrono::seconds{now - 100}};
    c.delete_attach_before = std::chrono::sys_seconds{std::chrono::seconds{now - 50}};

    contacts.set(c);

    REQUIRE(contacts.get(definitely_real_id).has_value());

    CHECK(contacts.get(definitely_real_id)->name == "Joe");
    CHECK(contacts.get(definitely_real_id)->nickname == "Joey");
    CHECK(contacts.get(definitely_real_id)->profile_updated.time_since_epoch() == 1s);
    CHECK(contacts.get(definitely_real_id)->approved);
    CHECK(contacts.get(definitely_real_id)->approved_me);
    CHECK_FALSE(contacts.get(definitely_real_id)->profile_picture);
    CHECK_FALSE(contacts.get(definitely_real_id)->blocked);
    CHECK(contacts.get(definitely_real_id)->delete_before.time_since_epoch() ==
          std::chrono::seconds{now - 100});
    CHECK(contacts.get(definitely_real_id)->delete_attach_before.time_since_epoch() ==
          std::chrono::seconds{now - 50});
    CHECK(contacts.get(definitely_real_id)->session_id == definitely_real_id);

    CHECK(contacts.needs_push());
    CHECK(contacts.needs_dump());

    auto [seqno, to_push, obs] = contacts.push();

    CHECK(seqno == 1);

    // Pretend we uploaded it
    contacts.confirm_pushed(seqno, {"fakehash1"});
    CHECK(contacts.needs_dump());
    CHECK_FALSE(contacts.needs_push());

    // NB: Not going to check encrypted data and decryption here because that's general (not
    // specific to contacts) and is covered already in the user profile tests.

    session::config::Contacts contacts2{seed, contacts.dump()};
    CHECK_FALSE(contacts2.needs_push());
    CHECK_FALSE(contacts2.needs_dump());
    CHECK(std::get<seqno_t>(contacts2.push()) == 1);
    CHECK_FALSE(contacts.needs_dump());  // Because we just called dump() above, to load up
                                         // contacts2.

    auto x = contacts2.get(definitely_real_id);
    REQUIRE(x);
    CHECK(x->name == "Joe");
    CHECK(x->nickname == "Joey");
    CHECK(x->profile_updated.time_since_epoch() == 1s);
    CHECK(x->approved);
    CHECK(x->approved_me);
    CHECK_FALSE(x->profile_picture);
    CHECK_FALSE(x->blocked);
    CHECK(x->created == created_ts);
    CHECK(x->notifications == session::config::notify_mode::all);
    CHECK(x->mute_until == now + 1800);

    auto another_id = "051111111111111111111111111111111111111111111111111111111111111111"sv;
    auto c2 = contacts2.get_or_construct(another_id);
    // We're not setting any fields, but we should still keep a record of the session id
    contacts2.set(c2);

    CHECK(contacts2.needs_push());

    std::tie(seqno, to_push, obs) = contacts2.push();
    REQUIRE(to_push.size() == 1);

    CHECK(seqno == 2);

    std::vector<std::pair<std::string, std::span<const std::byte>>> merge_configs;
    merge_configs.emplace_back("fakehash2", to_push[0]);
    contacts.merge(merge_configs);
    contacts2.confirm_pushed(seqno, {"fakehash2"});

    CHECK_FALSE(contacts.needs_push());
    CHECK(std::get<seqno_t>(contacts.push()) == seqno);

    // Iterate through and make sure we got everything we expected
    std::vector<std::string> session_ids;
    std::vector<std::string> nicknames;
    std::vector<std::chrono::sys_seconds> profile_updateds;
    CHECK(contacts.size() == 2);
    CHECK_FALSE(contacts.empty());
    for (const auto& cc : contacts) {
        session_ids.push_back(cc.session_id);
        nicknames.emplace_back(cc.nickname.empty() ? "(N/A)" : cc.nickname);
        profile_updateds.emplace_back(cc.profile_updated);
    }

    REQUIRE(session_ids.size() == 2);
    REQUIRE(session_ids.size() == contacts.size());
    CHECK(session_ids[0] == definitely_real_id);
    CHECK(session_ids[1] == another_id);
    CHECK(nicknames[0] == "Joey");
    CHECK(nicknames[1] == "(N/A)");
    CHECK(profile_updateds[0].time_since_epoch() == 1s);
    CHECK(profile_updateds[1].time_since_epoch() == 0s);

    // Conflict! Oh no!

    // On client 1 delete a contact:
    contacts.erase(definitely_real_id);

    // Client 2 adds a new friend:
    auto third_id = "052222222222222222222222222222222222222222222222222222222222222222"sv;
    contacts2.set_nickname(third_id, "Nickname 3");
    contacts2.set_profile_updated(third_id, session::to_sys_seconds(2));
    contacts2.set_approved(third_id, true);
    contacts2.set_blocked(third_id, true);

    session::config::profile_pic p;
    {
        // These don't stay alive, so we use set_key/set_url to make a local copy:
        constexpr auto k = "qwerty78901234567890123456789012"_bytes;
        std::vector<std::byte> key(k.begin(), k.end());
        std::string url = "http://example.com/huge.bmp";
        p.set_key(std::move(key));
        p.url = std::move(url);
    }
    contacts2.set_profile_pic(third_id, std::move(p));

    CHECK(contacts.needs_push());
    CHECK(contacts2.needs_push());
    std::tie(seqno, to_push, obs) = contacts.push();
    auto [seqno2, to_push2, obs2] = contacts2.push();
    REQUIRE(to_push.size() == 1);
    REQUIRE(to_push2.size() == 1);

    CHECK(seqno == seqno2);
    CHECK(to_push != to_push2);
    CHECK(as_set(obs) == make_set("fakehash2"s));
    CHECK(as_set(obs2) == make_set("fakehash2"s));

    contacts.confirm_pushed(seqno, {"fakehash3a"});
    contacts2.confirm_pushed(seqno2, {"fakehash3b"});

    merge_configs.clear();
    merge_configs.emplace_back("fakehash3b", to_push2[0]);
    contacts.merge(merge_configs);
    CHECK(contacts.needs_push());

    merge_configs.clear();
    merge_configs.emplace_back("fakehash3a", to_push[0]);
    contacts2.merge(merge_configs);
    CHECK(contacts2.needs_push());

    std::tie(seqno, to_push, obs) = contacts.push();
    CHECK(seqno == seqno2 + 1);
    std::tie(seqno2, to_push2, obs2) = contacts2.push();
    CHECK(seqno == seqno2);
    // Disabled check for now: doesn't work with protobuf (because of the non-deterministic
    // encryption in the middle of the protobuf wrapping).
    // TODO: reenable once protobuf isn't always-on.
    // CHECK(printable(to_push) == printable(to_push2));
    CHECK(as_set(obs) == make_set("fakehash3a"s, "fakehash3b"));
    CHECK(as_set(obs2) == make_set("fakehash3a"s, "fakehash3b"));

    contacts.confirm_pushed(seqno, {"fakehash4"});
    contacts2.confirm_pushed(seqno2, {"fakehash4"});

    CHECK_FALSE(contacts.needs_push());
    CHECK_FALSE(contacts2.needs_push());

    session_ids.clear();
    nicknames.clear();
    profile_updateds.clear();
    for (const auto& cc : contacts) {
        session_ids.push_back(cc.session_id);
        nicknames.emplace_back(cc.nickname.empty() ? "(N/A)" : cc.nickname);
        profile_updateds.emplace_back(cc.profile_updated);
    }
    REQUIRE(session_ids.size() == 2);
    CHECK(session_ids[0] == another_id);
    CHECK(session_ids[1] == third_id);
    CHECK(nicknames[0] == "(N/A)");
    CHECK(nicknames[1] == "Nickname 3");
    CHECK(profile_updateds[0].time_since_epoch() == 0s);
    CHECK(profile_updateds[1].time_since_epoch() == 2s);

    CHECK_THROWS(
            c.set_nickname("12345678901234567890123456789012345678901234567890123456789012345678901"
                           "23456789012345678901234567890A"));
    CHECK_NOTHROW(
            c.set_nickname_truncated("1234567890123456789012345678901234567890123456789012345678901"
                                     "234567890123456789012345678901234567890A"));
    CHECK(c.nickname ==
          "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"
          "901234567890");
    CHECK_NOTHROW(
            c.set_nickname_truncated("1234567890123456789012345678901234567890123456789012345678901"
                                     "234567890123456789012345678901234567🎂"));
    CHECK(c.nickname ==
          "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"
          "901234567");
    CHECK_NOTHROW(
            c.set_nickname_truncated("1234567890123456789012345678901234567890123456789012345678901"
                                     "2345678901234567890123456789012345🎂🎂"));
    CHECK(c.nickname ==
          "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"
          "9012345🎂");
}

TEST_CASE("Contacts (C API)", "[config][contacts][c]") {
    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hex_b;
    auto [ed_pk, ed_sk] = ed25519::keypair(seed);
    auto curve_pk = ed25519::pk_to_x25519(ed_pk);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(oxenc::to_hex(seed.begin(), seed.end()) ==
          oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    config_object* conf;
    REQUIRE(0 == contacts_init(&conf, to_unsigned(ed_sk.data()), NULL, 0, NULL));

    const char* const definitely_real_id =
            "050000000000000000000000000000000000000000000000000000000000000000";

    contacts_contact c;
    CHECK_FALSE(contacts_get(conf, &c, definitely_real_id));

    CHECK(contacts_get_or_construct(conf, &c, definitely_real_id));

    CHECK(c.session_id == std::string_view{definitely_real_id});
    CHECK(strlen(c.name) == 0);
    CHECK(strlen(c.nickname) == 0);
    CHECK(c.profile_updated == 0);
    CHECK_FALSE(c.approved);
    CHECK_FALSE(c.approved_me);
    CHECK_FALSE(c.blocked);
    CHECK(strlen(c.profile_pic.url) == 0);
    CHECK(c.created == 0);

    strcpy(c.name, "Joe");
    strcpy(c.nickname, "Joey");
    c.profile_updated = 1;
    c.approved = true;
    c.approved_me = true;
    c.created = created_ts;

    contacts_set(conf, &c);

    contacts_contact c2;
    REQUIRE(contacts_get(conf, &c2, definitely_real_id));

    CHECK(c2.name == "Joe"sv);
    CHECK(c2.nickname == "Joey"sv);
    CHECK(c2.profile_updated == 1);
    CHECK(c2.approved);
    CHECK(c2.approved_me);
    CHECK_FALSE(c2.blocked);
    CHECK(strlen(c2.profile_pic.url) == 0);

    CHECK(config_needs_push(conf));
    CHECK(config_needs_dump(conf));

    config_push_data* to_push = config_push(conf);
    CHECK(to_push->seqno == 1);

    config_object* conf2;
    REQUIRE(contacts_init(&conf2, to_unsigned(ed_sk.data()), NULL, 0, NULL) == 0);

    const char* merge_hash[1];
    const unsigned char* merge_data[1];
    size_t merge_size[1];
    merge_hash[0] = "fakehash1";
    REQUIRE(to_push->n_configs == 1);
    merge_data[0] = to_push->config[0];
    merge_size[0] = to_push->config_lens[0];
    config_string_list* accepted = config_merge(conf2, merge_hash, merge_data, merge_size, 1);
    REQUIRE(accepted->len == 1);
    CHECK(accepted->value[0] == "fakehash1"sv);
    free(accepted);

    const char* tmphash;  // test suite cheat: &(tmphash = "asdf") to fake a length-1 array.

    config_confirm_pushed(conf, to_push->seqno, &(tmphash = "fakehash1"), 1);
    free(to_push);

    contacts_contact c3;
    REQUIRE(contacts_get(conf2, &c3, definitely_real_id));
    CHECK(c3.name == "Joe"sv);
    CHECK(c3.nickname == "Joey"sv);
    CHECK(c3.profile_updated == 1);
    CHECK(c3.approved);
    CHECK(c3.approved_me);
    CHECK_FALSE(c3.blocked);
    CHECK(strlen(c3.profile_pic.url) == 0);
    CHECK(c3.created == created_ts);

    auto another_id = "051111111111111111111111111111111111111111111111111111111111111111";
    REQUIRE(contacts_get_or_construct(conf, &c3, another_id));
    CHECK(strlen(c3.name) == 0);
    CHECK(strlen(c3.nickname) == 0);
    CHECK(c3.profile_updated == 0);
    CHECK_FALSE(c3.approved);
    CHECK_FALSE(c3.approved_me);
    CHECK_FALSE(c3.blocked);
    CHECK(strlen(c3.profile_pic.url) == 0);
    CHECK(c3.created == 0);

    contacts_set(conf2, &c3);

    to_push = config_push(conf2);

    merge_hash[0] = "fakehash2";
    REQUIRE(to_push->n_configs == 1);
    merge_data[0] = to_push->config[0];
    merge_size[0] = to_push->config_lens[0];
    accepted = config_merge(conf, merge_hash, merge_data, merge_size, 1);
    REQUIRE(accepted->len == 1);
    CHECK(accepted->value[0] == "fakehash2"sv);
    free(accepted);

    config_confirm_pushed(conf2, to_push->seqno, &(tmphash = "fakehash2"), 1);

    REQUIRE(to_push->obsolete_len > 0);
    CHECK(to_push->obsolete_len == 1);
    CHECK(to_push->obsolete[0] == "fakehash1"sv);
    free(to_push);

    // Iterate through and make sure we got everything we expected
    std::vector<std::string> session_ids;
    std::vector<std::string> nicknames;
    std::vector<int64_t> profile_updateds;

    CHECK(contacts_size(conf) == 2);
    contacts_iterator* it = contacts_iterator_new(conf);
    contacts_contact ci;
    for (; !contacts_iterator_done(it, &ci); contacts_iterator_advance(it)) {
        session_ids.push_back(ci.session_id);
        nicknames.emplace_back(strlen(ci.nickname) ? ci.nickname : "(N/A)");
        profile_updateds.emplace_back(ci.profile_updated);
    }
    contacts_iterator_free(it);

    REQUIRE(session_ids.size() == 2);
    CHECK(session_ids[0] == definitely_real_id);
    CHECK(session_ids[1] == another_id);
    CHECK(nicknames[0] == "Joey");
    CHECK(nicknames[1] == "(N/A)");
    CHECK(profile_updateds[0] == 1);
    CHECK(profile_updateds[1] == 0);

    // Changing things while iterating:
    it = contacts_iterator_new(conf);
    int deletions = 0, non_deletions = 0;
    std::vector<std::string> contacts_to_remove;
    while (!contacts_iterator_done(it, &ci)) {
        if (ci.session_id != std::string_view{definitely_real_id}) {
            contacts_to_remove.push_back(ci.session_id);
            deletions++;
        } else {
            non_deletions++;
        }
        contacts_iterator_advance(it);
    }
    for (auto& cont : contacts_to_remove)
        contacts_erase(conf, cont.c_str());

    CHECK(deletions == 1);
    CHECK(non_deletions == 1);

    CHECK(contacts_get(conf, &ci, definitely_real_id));
    CHECK_FALSE(contacts_get(conf, &ci, another_id));
}

static constexpr auto EXPECT_BIG_DUMP_SIZE = 1'597'004;

TEST_CASE("huge contacts compression", "[config][compression][contacts]") {
    // Test that we can produce a config message whose *uncompressed* length exceeds the maximum
    // message length as long as its *compressed* length does not.

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hex_b;
    auto [ed_pk, ed_sk] = ed25519::keypair(seed);
    auto curve_pk = ed25519::pk_to_x25519(ed_pk);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");

    session::config::Contacts contacts{seed, std::nullopt};

    for (uint16_t i = 0; i < 12000; i++) {
        char buf[2];
        oxenc::write_host_as_big(i, buf);
        std::string session_id = "05000000000000000000000000000000000000000000000000000000000000";
        session_id += oxenc::to_hex(buf, buf + 2);
        REQUIRE(session_id.size() == 66);

        auto c = contacts.get_or_construct(session_id);
        c.nickname = "My friend {}"_format(i);
        c.approved = true;
        c.approved_me = true;
        contacts.set(c);
    }

    CHECK(contacts.needs_push());
    CHECK(contacts.needs_dump());

    auto [seqno, to_push, obs] = contacts.push();
    CHECK(seqno == 1);
    CHECK(to_push.size() == 1);
    CHECK(to_push[0].size() == 56'320 + 181);  // 181 == protobuf overhead
    auto dump = contacts.dump();
    // With tons of duplicate info the push should have been nicely compressible, but our dump
    // (which currently isn't compressed) is much larger:
    CHECK(dump.size() == EXPECT_BIG_DUMP_SIZE);

    contacts.confirm_pushed(seqno, {"fakehash1"});
    dump = contacts.dump();
    CHECK(dump.size() == EXPECT_BIG_DUMP_SIZE + 11);  // We will have added '9:fakehash1'
}

TEST_CASE("huger contacts with multipart messages", "[config][multipart][contacts]") {
    // Test that we can produce a config message whose *uncompressed* length exceeds the maximum
    // message length as long as its *compressed* length does not.

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hex_b;
    auto [ed_pk, ed_sk] = ed25519::keypair(seed);
    auto curve_pk = ed25519::pk_to_x25519(ed_pk);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");

    session::config::Contacts contacts{seed, std::nullopt};

    std::string friend42;

    for (size_t i = 0; i < 12000; i++) {
        // Unlike the above case where we have nearly identical Session IDs, here our session IDs
        // are randomly generated and thus not usefully compressible, which results in a much larger
        // (compressed) config.
        std::mt19937_64 rng{i};
        b33 random_sessionid;
        random_sessionid[0] = std::byte{0x05};
        for (int i = 1; i < 33; i += 8)
            oxenc::write_host_as_little(rng(), random_sessionid.data() + i);

        std::string session_id = oxenc::to_hex(random_sessionid);

        auto c = contacts.get_or_construct(session_id);
        c.nickname = "My friend {}"_format(i);
        c.approved = true;
        c.approved_me = true;
        contacts.set(c);

        if (i == 42)
            friend42 = std::move(session_id);
    }

    CHECK(contacts.needs_push());
    CHECK(contacts.needs_dump());

    auto [seqno, to_push, obs] = contacts.push();

    CHECK(seqno == 1);
    REQUIRE(to_push.size() == 12);
    CHECK(to_push[0].size() == 76'800);   // maxed out
    CHECK(to_push[1].size() == 76'800);   // maxed out
    CHECK(to_push[2].size() == 76'800);   // maxed out
    CHECK(to_push[3].size() == 76'800);   // maxed out
    CHECK(to_push[4].size() == 76'800);   // maxed out
    CHECK(to_push[5].size() == 76'800);   // maxed out
    CHECK(to_push[6].size() == 76'800);   // maxed out
    CHECK(to_push[7].size() == 76'800);   // maxed out
    CHECK(to_push[8].size() == 76'800);   // maxed out
    CHECK(to_push[9].size() == 76'800);   // maxed out
    CHECK(to_push[10].size() == 76'800);  // maxed out
    CHECK(to_push[11].size() == 1'040);   // last part

    // Still compressible, but much less than the test case above
    auto dump = contacts.dump();
    constexpr auto base_dump_size = EXPECT_BIG_DUMP_SIZE
                                  /**/
                                  + 35   // 32:[finalhash]
                                  + 2    // d...e
                                  + 6    //   1:#i0e
                                  + 18;  //   1:Ti1234567890555e

    CHECK(dump.size() == base_dump_size);

    {
        std::unordered_set<std::string> fakehashes;
        for (int i = 0; i < 12; i++)
            fakehashes.insert("fakehash{:02d}"_format(i));
        contacts.confirm_pushed(seqno, fakehashes);

        CHECK(contacts.curr_hashes() == fakehashes);
        CHECK(contacts.active_hashes() == fakehashes);
    }

    dump = contacts.dump();
    CHECK(dump.size() == base_dump_size + 12 * 13);  // 12 x "10:fakehashNN"

    auto c2 = std::make_unique<session::config::Contacts>(seed, std::nullopt);

    std::vector<std::pair<std::string, std::span<const std::byte>>> merge_configs, merge_more;
    bool dump_load_in_between = false;
    std::mt19937_64 rng{12345};

    auto old_seqno = std::get<seqno_t>(c2->push());
    REQUIRE(old_seqno == 0);

    CHECK_FALSE(c2->get(friend42));

    // Test loading the push data back into a new config:
    SECTION("all parts in expected order") {
        for (int i = 0; i < 12; i++)
            merge_configs.emplace_back("fakehash{:02d}"_format(i), to_push[i]);
    }
    SECTION("all parts, shuffled order") {
        for (int i = 0; i < 12; i++)
            merge_configs.emplace_back("fakehash{:02d}"_format(i), to_push[i]);
        std::shuffle(merge_configs.begin(), merge_configs.end(), rng);
    }
    SECTION("missing parts") {
        for (int i = 0; i < 12; i++)
            merge_configs.emplace_back("fakehash{:02d}"_format(i), to_push[i]);
        std::shuffle(merge_configs.begin(), merge_configs.end(), rng);

        // Simulate a partial fetch where we got just 8 parts in random order, then we get the last
        // 2 in a follow-up fetch.
        for (int i = 8; i < 12; i++)
            merge_more.push_back(std::move(merge_configs[i]));
        merge_configs.resize(8);
    }
    SECTION("missing parts with dump in between") {
        for (int i = 0; i < 12; i++)
            merge_configs.emplace_back("fakehash{:02d}"_format(i), to_push[i]);
        std::shuffle(merge_configs.begin(), merge_configs.end(), rng);

        // Same as the above, except we are going to dump and reload from that dump in between
        // fetching the first batch and the remaining ones.
        dump_load_in_between = true;
        for (int i = 0; i < 2; i++) {
            merge_more.push_back(std::move(merge_configs.back()));
            merge_configs.pop_back();
        }
    }

    auto merge_hashes = [](const auto& merge_confs) {
        std::unordered_set<std::string> result;
        for (const auto& [hash, data] : merge_confs)
            result.emplace(hash);
        return result;
    };

    std::unordered_set<std::string> fakehashes;
    for (auto& [h, d] : merge_configs)
        fakehashes.insert(h);

    int merged = 0;
    std::unordered_set<std::string> accepted;
    CHECK_FALSE(c2->needs_dump());
    accepted = c2->merge(merge_configs);
    merged += merge_configs.size();
    CHECK(accepted == merge_hashes(merge_configs));
    CHECK(c2->needs_dump());
    CHECK_FALSE(c2->needs_push());
    CHECK(c2->active_hashes() == fakehashes);

    if (merged >= 12) {
        CHECK(c2->curr_hashes() == fakehashes);
    } else {
        CHECK(c2->curr_hashes().empty());
        CHECK(c2->active_hashes() == fakehashes);
        dump = c2->dump();
        size_t total_dumps = 0;
        for (auto& [hash, data] : merge_configs)
            total_dumps += hash.size() + data.size() - 90 /* multipart+encryption overhead */;
        // Our dump should be storing all the partial bodies, with a little overhead:
        CHECK(dump.size() > total_dumps);
        CHECK(dump.size() < total_dumps + 500 /* ~ various other dump overhead */);

        if (dump_load_in_between) {
            auto c2b = std::make_unique<session::config::Contacts>(seed, c2->dump());
            CHECK_FALSE(c2b->needs_dump());
            c2 = std::move(c2b);
            CHECK_FALSE(c2->needs_dump());
        }

        CHECK(std::get<seqno_t>(c2->push()) == 0);
        accepted = c2->merge(merge_more);
        CHECK(accepted == merge_hashes(merge_more));
        CHECK(c2->needs_dump());
        for (auto& [h, d] : merge_more)
            fakehashes.insert(h);
        CHECK(c2->curr_hashes() == fakehashes);
        CHECK(c2->active_hashes() == fakehashes);
    }

    CHECK_FALSE(c2->needs_push());
    CHECK(std::get<seqno_t>(c2->push()) == 1);

    auto myfriend = c2->get(friend42);
    REQUIRE(myfriend);
    CHECK(myfriend->nickname == "My friend 42");

    dump = c2->dump();
    CHECK(dump.size() == base_dump_size + 12 * 13);  // 12 x "10:fakehashNN"
}

TEST_CASE("multipart message expiry", "[config][multipart][contacts][expiry]") {
    // Tests that stored multipart message expires as expected.

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hex_b;
    auto [ed_pk, ed_sk] = ed25519::keypair(seed);
    auto curve_pk = ed25519::pk_to_x25519(ed_pk);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");

    session::config::Contacts contacts{seed, std::nullopt};

    std::string friend42;

    b32 seedi = {};
    for (uint16_t i = 0; i < 2000; i++) {
        // Unlike the above case where we have nearly identical Session IDs, here our session IDs
        // are randomly generated from fixed seeds and thus not usefully compressible, which results
        // in a much larger (compressed) config.
        seedi[0] = static_cast<std::byte>(i % 256);
        seedi[1] = static_cast<std::byte>(i >> 8);
        auto [i_ed_pk, i_ed_sk] = ed25519::keypair(seedi);
        auto i_curve_pk = ed25519::pk_to_x25519(i_ed_pk);
        std::string session_id = "05" + oxenc::to_hex(i_curve_pk.begin(), i_curve_pk.end());

        auto c = contacts.get_or_construct(session_id);
        c.nickname = "My friend {:04d}"_format(i);
        c.approved = true;
        c.approved_me = true;
        contacts.set(c);

        if (i == 42)
            friend42 = std::move(session_id);
    }

    CHECK(contacts.needs_push());
    CHECK(contacts.needs_dump());

    auto [seqno, to_push, obs] = contacts.push();

    CHECK(seqno == 1);
    CHECK(to_push.size() == 2);
    CHECK(to_push[0].size() == 76'800);  // maxed out
    CHECK(to_push[1].size() == 35'980);  // last part

    contacts.confirm_pushed(seqno, {"fakehash0", "fakehash1"});

    auto c2 = std::make_unique<session::config::Contacts>(seed, std::nullopt);

    // Long enough that the time the test itself takes never matters (it can run for many seconds
    // unoptimized under emulation); the clock is moved past them instead of waiting them out.
    c2->MULTIPART_MAX_WAIT = 10min;
    c2->MULTIPART_MAX_REMEMBER = 30min;
    ScopedClockOffset clock{0s};

    auto old_seqno = std::get<seqno_t>(c2->push());
    REQUIRE(old_seqno == 0);

    std::vector<std::pair<std::string, std::span<const std::byte>>> merge_configs;
    merge_configs.emplace_back("fakehash0", to_push[0]);

    std::unordered_set<std::string> accepted;
    CHECK_FALSE(c2->needs_dump());
    accepted = c2->merge(merge_configs);
    CHECK(accepted == std::unordered_set{{"fakehash0"s}});
    CHECK(c2->needs_dump());
    auto dump = c2->dump();
    CHECK(dump.size() > 76'710);
    CHECK(dump.size() < 77'000);
    CHECK_FALSE(c2->needs_push());
    CHECK(std::get<seqno_t>(c2->push()) == 0);

    // Let the stored part expire
    clock.advance(11min);

    // Dump should trigger a cleanup of cached parts:
    dump = c2->dump();
    CHECK(dump.size() < 200);

    merge_configs.clear();
    merge_configs.emplace_back("fakehash1", to_push[1]);
    accepted = c2->merge(merge_configs);
    CHECK(accepted == std::unordered_set{{"fakehash1"s}});
    CHECK(c2->needs_dump());
    // This should *not* have completed a set, because of the earlier expiry:
    CHECK(std::get<seqno_t>(c2->push()) == 0);
    dump = c2->dump();
    CHECK(dump.size() > 35'890);
    CHECK(dump.size() < 36'200);

    merge_configs.clear();
    merge_configs.emplace_back("fakehash0", to_push[0]);
    accepted = c2->merge(merge_configs);
    CHECK(accepted == std::unordered_set{{"fakehash0"s}});
    CHECK(c2->needs_dump());
    CHECK_FALSE(c2->needs_push());
    // Now we should have completed the set
    CHECK(std::get<seqno_t>(c2->push()) == 1);
    auto myfriend = c2->get(friend42);
    REQUIRE(myfriend);
    CHECK(myfriend->nickname == "My friend 0042");
    dump = c2->dump();
    auto full_size = dump.size();
    // We shouldn't be storing any part data, but we *are* now storing all the actual data.  Every
    // contact here should be a dict pair encoded as:
    CHECK(full_size > 266000);
    CHECK(full_size < 266300);
    // Go look for the 1:* where we store multipart info, and make sure it's within the last 100
    // bytes of the dump (to make sure that we don't have cached data stored inside it):
    auto pattern = session::to_span("1:*");
    auto it = std::find_end(dump.begin(), dump.end(), pattern.begin(), pattern.end());
    REQUIRE(it != dump.end());
    auto x = std::distance(dump.begin(), it);
    CHECK(x > full_size - 100);
    CHECK(x < dump.size());

    ////////////////////////////////////////////
    // Now we check "done" expiry

    // Initially reloading a part should do nothing, since we should have the "done" stubs still
    // stored.  (It's still "accepted" because that just means we found it parseable and valid, even
    // though we discard it.).
    accepted = c2->merge(merge_configs);
    CHECK(accepted == std::unordered_set{{"fakehash0"s}});
    CHECK_FALSE(c2->needs_dump());
    dump = c2->dump();
    CHECK(dump.size() == full_size);

    // test that the remember timer is getting properly applied for a completed set rather than the
    // wait timer by making sure we don't lose anything in the repeated dump:
    clock.advance(11min);
    dump = c2->dump();
    CHECK(dump.size() == full_size);  // expect no change

    clock.advance(21min);
    // Now we should hit the remember timer, and should discard the cached completed set data when
    // we dump:
    dump = c2->dump();
    // We should have lost the entry pair for this set, which for a done set will be:
    // 32:HASH
    // d1:#i0e1:Ti1234567890123ee
    CHECK(dump.size() == full_size - (35 + 26));
    full_size -= 35 + 26;

    // Since we've forgotten about the completed set, this time we *should* store it:
    accepted = c2->merge(merge_configs);
    CHECK(accepted == std::unordered_set{{"fakehash0"s}});
    CHECK(c2->needs_dump());
    dump = c2->dump();
    CHECK(dump.size() > full_size + 76'710);
    CHECK(dump.size() < full_size + 77'000);

    // Complete the set; this should *not* change the seqno, as this should be recognized as a
    // duplicate seqno/config hash with the regular hash handling:
    merge_configs.emplace_back("fakehash1", to_push[1]);
    accepted = c2->merge(merge_configs);
    CHECK(accepted == std::unordered_set{{"fakehash0"s, "fakehash1"s}});
    dump = c2->dump();
    CHECK(dump.size() == full_size + 35 + 26);
    CHECK(std::get<seqno_t>(contacts.push()) == 1);
}

TEST_CASE("needs_dump bug", "[config][needs_dump]") {

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hex_b;

    session::config::Contacts contacts{seed, std::nullopt};

    CHECK_FALSE(contacts.needs_dump());

    auto c = contacts.get_or_construct(
            "050000000000000000000000000000000000000000000000000000000000000000"sv);

    c.approved = true;
    contacts.set(c);

    CHECK(contacts.needs_dump());

    c.approved_me = true;
    contacts.set(c);

    CHECK(contacts.needs_dump());

    (void)contacts.dump();

    CHECK_FALSE(contacts.needs_dump());

    c.approved = false;
    contacts.set(c);
    CHECK(contacts.needs_dump());

    c.approved_me = false;
    contacts.set(c);
    CHECK(contacts.needs_dump());
}

TEST_CASE("Contacts", "[config][blinded_contacts]") {

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hex_b;
    auto [ed_pk, ed_sk] = ed25519::keypair(seed);
    auto curve_pk = ed25519::pk_to_x25519(ed_pk);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(oxenc::to_hex(seed.begin(), seed.end()) ==
          oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    session::config::Contacts contacts{seed, std::nullopt};

    constexpr auto definitely_real_id =
            "150000000000000000000000000000000000000000000000000000000000000000"sv;
    constexpr auto comm_base_url = "https://example.com/"sv;
    constexpr auto comm_pubkey_hex =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"sv;

    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();

    CHECK_FALSE(contacts.get_blinded(definitely_real_id));

    CHECK(contacts.empty());
    CHECK(contacts.size() == 0);

    auto c = contacts.get_or_construct_blinded(comm_base_url, comm_pubkey_hex, definitely_real_id);

    CHECK(c.session_id() == "150000000000000000000000000000000000000000000000000000000000000000");
    CHECK(c.name.empty());
    CHECK_FALSE(c.profile_picture);
    CHECK(c.profile_updated == std::chrono::sys_seconds{});
    CHECK(c.priority == 0);
    CHECK(c.legacy_blinding);
    CHECK(c.created.time_since_epoch() == 0s);

    CHECK_FALSE(contacts.needs_push());
    CHECK_FALSE(contacts.needs_dump());
    CHECK(std::get<seqno_t>(contacts.push()) == 0);

    c.set_name("Joe");
    c.profile_updated = std::chrono::sys_seconds{1s};
    c.created = session::to_sys_seconds(created_ts * 1'000);
    c.priority = 1;
    contacts.set_blinded(c);

    REQUIRE(contacts.get_blinded(definitely_real_id).has_value());

    CHECK(contacts.get_blinded(definitely_real_id)->name == "Joe");
    CHECK_FALSE(contacts.get_blinded(definitely_real_id)->profile_picture);
    CHECK(contacts.get_blinded(definitely_real_id)->profile_updated.time_since_epoch() == 1s);
    CHECK(contacts.get_blinded(definitely_real_id)->priority == 1);
    CHECK(contacts.get_blinded(definitely_real_id)->legacy_blinding);
    CHECK(contacts.get_blinded(definitely_real_id)->session_id() == definitely_real_id);

    CHECK(contacts.needs_push());
    CHECK(contacts.needs_dump());

    auto [seqno, to_push, obs] = contacts.push();

    CHECK(seqno == 1);

    // Pretend we uploaded it
    contacts.confirm_pushed(seqno, {"fakehash1"});
    CHECK(contacts.needs_dump());
    CHECK_FALSE(contacts.needs_push());

    // NB: Not going to check encrypted data and decryption here because that's general (not
    // specific to contacts) and is covered already in the user profile tests.
    session::config::Contacts contacts2{seed, contacts.dump()};
    CHECK_FALSE(contacts2.needs_push());
    CHECK_FALSE(contacts2.needs_dump());
    CHECK(std::get<seqno_t>(contacts2.push()) == 1);
    CHECK_FALSE(contacts.needs_dump());  // Because we just called dump() above, to load up
                                         // contacts2.

    auto x = contacts2.get_blinded(definitely_real_id);
    REQUIRE(x);
    CHECK(x->name == "Joe");
    CHECK_FALSE(x->profile_picture);
    CHECK(x->profile_updated.time_since_epoch() == 1s);
    CHECK(x->priority == 1);
    CHECK(x->created.time_since_epoch() == created_ts * 1s);
    CHECK(x->legacy_blinding == true);

    auto another_id = "251111111111111111111111111111111111111111111111111111111111111111"sv;
    auto c2 = contacts2.get_or_construct_blinded(comm_base_url, comm_pubkey_hex, another_id);
    // We're not setting any fields, but we should still keep a record of the session id
    contacts2.set_blinded(c2);

    CHECK(contacts2.needs_push());

    std::tie(seqno, to_push, obs) = contacts2.push();
    REQUIRE(to_push.size() == 1);

    CHECK(seqno == 2);

    std::vector<std::pair<std::string, std::span<const std::byte>>> merge_configs;
    merge_configs.emplace_back("fakehash2", to_push[0]);
    contacts.merge(merge_configs);
    contacts2.confirm_pushed(seqno, {"fakehash2"});

    CHECK_FALSE(contacts.needs_push());
    CHECK(std::get<seqno_t>(contacts.push()) == seqno);

    // Iterate through and make sure we got everything we expected
    auto blinded = contacts.blinded();
    std::vector<std::string> session_ids;
    std::vector<std::string> names;
    std::vector<std::chrono::sys_seconds> profile_updateds;
    std::vector<bool> legacy_blindings;
    CHECK(blinded.size() == 2);
    for (const auto& cc : blinded) {
        session_ids.push_back(cc.session_id());
        names.emplace_back(cc.name.empty() ? "(N/A)" : cc.name);
        profile_updateds.emplace_back(cc.profile_updated);
        legacy_blindings.emplace_back(cc.legacy_blinding);
    }

    REQUIRE(session_ids.size() == 2);
    REQUIRE(session_ids.size() == blinded.size());
    CHECK(session_ids[0] == definitely_real_id);
    CHECK(session_ids[1] == another_id);
    CHECK(names[0] == "Joe");
    CHECK(names[1] == "(N/A)");
    CHECK(profile_updateds[0].time_since_epoch() == 1s);
    CHECK(profile_updateds[1].time_since_epoch() == 0s);
    CHECK(legacy_blindings[0]);
    CHECK_FALSE(legacy_blindings[1]);

    // Conflict! Oh no!

    // On client 1 delete a contact:
    CHECK(contacts.erase_blinded(comm_base_url, definitely_real_id));

    // Client 2 adds a new friend:
    auto third_id = "152222222222222222222222222222222222222222222222222222222222222222"sv;
    auto c3 = contacts2.get_or_construct_blinded(comm_base_url, comm_pubkey_hex, third_id);
    c3.set_name("Name 3");

    session::config::profile_pic p;
    {
        // These don't stay alive, so we use set_key/set_url to make a local copy:
        auto key = to_vector("qwerty78901234567890123456789012"_bytes);
        std::string url = "http://example.com/huge.bmp";
        p.set_key(std::move(key));
        p.url = std::move(url);
    }
    c3.profile_picture = std::move(p);
    contacts2.set_blinded(c3);

    CHECK(contacts.needs_push());
    CHECK(contacts2.needs_push());

    std::tie(seqno, to_push, obs) = contacts.push();
    auto [seqno2, to_push2, obs2] = contacts2.push();
    REQUIRE(to_push.size() == 1);
    REQUIRE(to_push2.size() == 1);

    CHECK(seqno == seqno2);
    CHECK(to_push != to_push2);
    CHECK(as_set(obs) == make_set("fakehash2"s));
    CHECK(as_set(obs2) == make_set("fakehash2"s));

    contacts.confirm_pushed(seqno, {"fakehash3a"});
    contacts2.confirm_pushed(seqno2, {"fakehash3b"});

    merge_configs.clear();
    merge_configs.emplace_back("fakehash3b", to_push2[0]);
    contacts.merge(merge_configs);
    CHECK(contacts.needs_push());

    merge_configs.clear();
    merge_configs.emplace_back("fakehash3a", to_push[0]);
    contacts2.merge(merge_configs);
    CHECK(contacts2.needs_push());

    std::tie(seqno, to_push, obs) = contacts.push();
    CHECK(seqno == seqno2 + 1);
    std::tie(seqno2, to_push2, obs2) = contacts2.push();
    CHECK(seqno == seqno2);
    // Disabled check for now: doesn't work with protobuf (because of the non-deterministic
    // encryption in the middle of the protobuf wrapping).
    // TODO: reenable once protobuf isn't always-on.
    // CHECK(printable(to_push) == printable(to_push2));
    CHECK(as_set(obs) == make_set("fakehash3a"s, "fakehash3b"));
    CHECK(as_set(obs2) == make_set("fakehash3a"s, "fakehash3b"));

    contacts.confirm_pushed(seqno, {"fakehash4"});
    contacts2.confirm_pushed(seqno2, {"fakehash4"});

    CHECK_FALSE(contacts.needs_push());
    CHECK_FALSE(contacts2.needs_push());

    auto blinded2 = contacts.blinded();
    session_ids.clear();
    names.clear();
    profile_updateds.clear();
    legacy_blindings.clear();
    for (const auto& cc : blinded2) {
        session_ids.push_back(cc.session_id());
        names.emplace_back(cc.name.empty() ? "(N/A)" : cc.name);
        profile_updateds.emplace_back(cc.profile_updated);
        legacy_blindings.emplace_back(cc.legacy_blinding);
    }
    REQUIRE(session_ids.size() == 2);
    CHECK(session_ids[0] == another_id);
    CHECK(session_ids[1] == third_id);
    CHECK(names[0] == "(N/A)");
    CHECK(names[1] == "Name 3");
    CHECK(profile_updateds[0].time_since_epoch() == 0s);
    CHECK(profile_updateds[1].time_since_epoch() == 0s);
    CHECK_FALSE(legacy_blindings[0]);
    CHECK(legacy_blindings[1]);

    // Ensure that we throw correctly when giving invalid blinded ids
    auto invalid_id_1 = "072222222222222222222222222222222222222222222222222222222222222222"sv;
    auto invalid_id_2 = "992222222222222222222222222222222222222222222222222222222222222222"sv;
    CHECK_THROWS(contacts.get_or_construct_blinded(comm_base_url, comm_pubkey_hex, invalid_id_1));
    CHECK_THROWS(contacts.get_or_construct_blinded(comm_base_url, comm_pubkey_hex, invalid_id_2));
}

TEST_CASE("Contacts Pro Storage", "[config][contacts][pro]") {

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hex_b;

    session::config::Contacts contacts{seed, std::nullopt};

    REQUIRE(contacts.is_clean());

    // Set the bitsets onto the profile
    {
        auto c = contacts.get_or_construct(
                "050000000000000000000000000000000000000000000000000000000000000000"sv);
        CHECK(c.profile_flags == ProProfileFlags::None);

        c.profile_flags |= ProProfileFlags::ProBadge;
        contacts.set(c);

        CHECK(contacts.is_dirty());

        c = contacts.get_or_construct(
                "050000000000000000000000000000000000000000000000000000000000000000"sv);
        CHECK(contains(c.profile_flags, ProProfileFlags::ProBadge));

        contacts.set(c);
        c = contacts.get_or_construct(
                "050000000000000000000000000000000000000000000000000000000000000000"sv);
        CHECK_FALSE(contains(c.profile_flags, ProProfileFlags::AnimatedAvatar));

        c.profile_flags |= ProProfileFlags::AnimatedAvatar;
        contacts.set(c);
        c = contacts.get_or_construct(
                "050000000000000000000000000000000000000000000000000000000000000000"sv);

        CHECK(contains(c.profile_flags, ProProfileFlags::ProBadge));
        CHECK(contains(c.profile_flags, ProProfileFlags::AnimatedAvatar));
    }

    // Set and unset the bitset from the profile on a new contact
    {
        auto c = contacts.get_or_construct(
                "050000000000000000000000000000000000000000000000000000000000000001"sv);
        CHECK(c.profile_flags == ProProfileFlags::None);

        c.profile_flags |= ProProfileFlags::ProBadge;
        contacts.set(c);

        c = contacts.get_or_construct(
                "050000000000000000000000000000000000000000000000000000000000000001"sv);
        CHECK(contains(c.profile_flags, ProProfileFlags::ProBadge));

        c.profile_flags &= ~ProProfileFlags::ProBadge;
        contacts.set(c);

        c = contacts.get_or_construct(
                "050000000000000000000000000000000000000000000000000000000000000001"sv);
        CHECK(!contains(c.profile_flags, ProProfileFlags::ProBadge));
    }

    CHECK(contacts.needs_push());
    CHECK(contacts.needs_dump());

    auto [seqno, to_push, obs] = contacts.push();
    // Simulated push:
    contacts.confirm_pushed(seqno, {"fakehash1"});
    // Simulated dump:
    contacts.dump();

    REQUIRE_FALSE(contacts.needs_push());
    REQUIRE_FALSE(contacts.needs_dump());

    {
        auto c = contacts.get_or_construct(
                "050000000000000000000000000000000000000000000000000000000000000000"sv);
        CHECK(contains(c.profile_flags, ProProfileFlags::ProBadge));
        CHECK(contains(c.profile_flags, ProProfileFlags::AnimatedAvatar));
        // This previously exposed a bug in set_erase_impl where the contact was being dirtied even
        // when nothing was actually being removed.
        contacts.set(c);
    }

    CHECK_FALSE(contacts.needs_push());
    CHECK_FALSE(contacts.needs_dump());
}
