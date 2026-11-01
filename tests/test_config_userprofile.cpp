#include <oxenc/hex.h>
#include <session/config/encrypt.h>
#include <session/config/user_profile.h>

#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include <session/config/base.hpp>
#include <session/config/user_profile.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/util.hpp>
#include <string_view>

#include "../src/config/internal.hpp"
#include "utils.hpp"

using namespace session;
using namespace std::literals;

namespace {
struct UserProfileTester {
    static std::chrono::sys_seconds get_profile_updated_value(config_object* conf) {
        return std::chrono::sys_seconds{std::chrono::seconds{
                session::config::unbox<session::config::UserProfile>(conf)->data["t"].integer_or(
                        0)}};
    }

    static void set_profile_updated(config_object* conf, std::chrono::sys_seconds value) {
        session::config::unbox<session::config::UserProfile>(conf)->data["t"] =
                static_cast<int>(value.time_since_epoch().count());
    }

    static void set_profile_updated(
            session::config::UserProfile& profile, std::chrono::sys_seconds value) {
        profile.data["t"] = static_cast<int>(value.time_since_epoch().count());
    }

    static std::chrono::sys_seconds get_reupload_profile_updated_value(config_object* conf) {
        return std::chrono::sys_seconds{std::chrono::seconds{
                session::config::unbox<session::config::UserProfile>(conf)->data["T"].integer_or(
                        0)}};
    }

    static void set_reupload_profile_updated(config_object* conf, std::chrono::sys_seconds value) {
        session::config::unbox<session::config::UserProfile>(conf)->data["T"] =
                static_cast<int>(value.time_since_epoch().count());
    }

    static uint64_t get_raw_profile_updated_value(config_object* conf) {
        return session::config::unbox<session::config::UserProfile>(conf)->data["t"].integer_or(0);
    }
};
}  // namespace

TEST_CASE("UserProfile", "[config][user_profile]") {

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hex_b;
    auto [ed_pk, ed_sk] = ed25519::keypair(seed);
    auto curve_pk = ed25519::pk_to_x25519(ed_pk);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");
    CHECK(oxenc::to_hex(seed.begin(), seed.end()) ==
          oxenc::to_hex(ed_sk.begin(), ed_sk.begin() + 32));

    session::config::UserProfile profile{seed, std::nullopt};

    CHECK_THROWS(
            profile.set_name("123456789012345678901234567890123456789012345678901234567890123456789"
                             "0123456789012345678901234567890A"));
    CHECK_NOTHROW(
            profile.set_name_truncated("12345678901234567890123456789012345678901234567890123456789"
                                       "01234567890123456789012345678901234567890A"));
    CHECK(profile.get_name() ==
          "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"
          "901234567890");
    CHECK_NOTHROW(
            profile.set_name_truncated("12345678901234567890123456789012345678901234567890123456789"
                                       "01234567890123456789012345678901234567🎂"));
    CHECK(profile.get_name() ==
          "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"
          "901234567");
    CHECK_NOTHROW(
            profile.set_name_truncated("12345678901234567890123456789012345678901234567890123456789"
                                       "012345678901234567890123456789012345🎂🎂"));
    CHECK(profile.get_name() ==
          "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"
          "9012345🎂");
}

TEST_CASE("user profile C API", "[config][user_profile][c]") {

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hex_b;
    auto [ed_pk, ed_sk] = ed25519::keypair(seed);
    auto curve_pk = ed25519::pk_to_x25519(ed_pk);

    REQUIRE(oxenc::to_hex(ed_pk.begin(), ed_pk.end()) ==
            "4cb76fdc6d32278e3f83dbf608360ecc6b65727934b85d2fb86862ff98c46ab7");
    REQUIRE(oxenc::to_hex(curve_pk.begin(), curve_pk.end()) ==
            "d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72");

    // Initialize a brand new, empty config because we have no dump data to deal with.
    char err[256];
    config_object* conf;
    int rc = user_profile_init(&conf, to_unsigned(ed_sk.data()), NULL, 0, err);
    REQUIRE(rc == 0);

    // We don't need to push anything, since this is an empty config
    CHECK_FALSE(config_needs_push(conf));
    // And we haven't changed anything so don't need to dump to db
    CHECK_FALSE(config_needs_dump(conf));

    // Since it's empty there shouldn't be a name.
    const char* name = user_profile_get_name(conf);
    CHECK(name == nullptr);  // (should be NULL instead of nullptr in C)

    // We don't need to push since we haven't changed anything, so this call is mainly just for
    // testing:
    config_push_data* to_push = config_push(conf);
    REQUIRE(to_push);
    CHECK(to_push->seqno == 0);
    REQUIRE(to_push->n_configs == 1);
    CHECK(to_push->config_lens[0] == 256 + 176);  // 176 = protobuf overhead
    const char* enc_domain = "UserProfile";
    REQUIRE(config_encryption_domain(conf) == std::string_view{enc_domain});

    // There's nothing particularly profound about this value (it is multiple layers of nested
    // protobuf with some encryption and padding halfway through); this test is just here to ensure
    // that our pushed messages are deterministic:
    CHECK(oxenc::to_hex(to_push->config[0], to_push->config[0] + to_push->config_lens[0]) ==
          "080112ab030a0012001aa20308062801429b0326ec9746282053eb119228e6c36012966e7d2642163169ba39"
          "98af44ca65f967768dd78ee80fffab6f809f6cef49c73a36c82a89622ff0de2ceee06b8c638e2c876fa9047f"
          "449dbe24b1fc89281a264fe90abdeffcdd44f797bd4572a6c5ae8d88bf372c3c717943ebd570222206fabf0e"
          "e9f3c6756f5d71a32616b1df53d12887961f5c129207a79622ccc1a4bba976886d9a6ddf0fe5d570e5075d01"
          "ecd627f656e95f27b4c40d5661b5664cedd3e568206effa1308b0ccd663ca61a6d39c0731891804a8cf5edcf"
          "8b98eaa5580c3d436e22156e38455e403869700956c3c1dd0b4470b663e75c98c5b859b53ccef6559215d804"
          "9f755be9c2d6b3f4a310f97c496fc392f65b6431dd87788ac61074fd8cd409702e1b839b3f774d38cf8b28f0"
          "226c4efa5220ac6ae060793e36e7ef278d42d042f15b21291f3bb29e3158f09d154b93f83fd8a319811a26cb"
          "5240d90cbb360fafec0b7eff4c676ae598540813d062dc9468365c73b4cfa2ffd02d48cdcd8f0c71324c6d0a"
          "60346a7a0e50af3be64684b37f9e6c831115bf112ddd18acde08eaec376f0872a3952000");

    free(to_push);

    // These should also be unset:
    auto pic = user_profile_get_pic(conf);
    CHECK(strlen(pic.url) == 0);
    CHECK(user_profile_get_nts_priority(conf) == 0);
    CHECK(user_profile_get_nts_expiry(conf) == 0);

    // Now let's go set them:
    CHECK(0 == user_profile_set_name(conf, "Kallie"));
    user_profile_pic p;
    strcpy(p.url, "http://example.org/omg-pic-123.bmp");  // NB: length must be < sizeof(p.url)!
    memcpy(p.key, "secret78901234567890123456789012", 32);
    CHECK(0 == user_profile_set_pic(conf, p));
    user_profile_set_nts_priority(conf, 9);
    UserProfileTester::set_profile_updated(conf, std::chrono::sys_seconds{123s});

    // Retrieve them just to make sure they set properly:
    name = user_profile_get_name(conf);
    REQUIRE(name != nullptr);  // (should be NULL instead of nullptr in C)
    CHECK(name == "Kallie"sv);

    pic = user_profile_get_pic(conf);
    REQUIRE(pic.url != ""s);
    CHECK(pic.url == "http://example.org/omg-pic-123.bmp"sv);
    CHECK(std::ranges::equal(to_byte_span(pic.key), "secret78901234567890123456789012"_bytes));

    CHECK(user_profile_get_nts_priority(conf) == 9);

    // Since we've made changes, we should need to push new config to the swarm, *and* should need
    // to dump the updated state:

    CHECK(config_needs_push(conf));
    CHECK(config_needs_dump(conf));
    to_push = config_push(conf);
    CHECK(to_push->seqno == 1);  // incremented since we made changes (this only increments once
                                 // between dumps; even though we changed two fields here).

    // The hash of a completely empty, initial seqno=0 message:
    auto exp_hash0 = "ea173b57beca8af18c3519a7bbf69c3e7a05d1c049fa9558341d8ebb48b0c965"_hex_b;

    // The data to be actually pushed, expanded like this to make it somewhat human-readable:
    // clang-format off
    auto exp_push1_decrypted = session::to_vector(
        "d"
          "1:#" "i1e"
          "1:&" "d"
            "1:+" "i9e"
            "1:n" "6:Kallie"
            "1:p" "34:http://example.org/omg-pic-123.bmp"
            "1:q" "32:secret78901234567890123456789012"
            "1:t" "i123e"
          "e"
          "1:<" "l"
            "l" "i0e" "32:" + session::to_string(exp_hash0) + "de" "e"
          "e"
          "1:=" "d"
            "1:+" "0:"
            "1:n" "0:"
            "1:p" "0:"
            "1:q" "0:"
            "1:t" "0:"
          "e"
        "e");
    // clang-format on
    auto exp_push1_encrypted =
            "9693a69686da3055f1ecdfb239c3bf8e746951a36d888c2fb7c02e856a5c2091b24e39a7e1af828f"
            "1fa09fe8bf7d274afde0a0847ba143c43ffb8722301b5ae32e2f078b9a5e19097403336e50b18c84"
            "aade446cd2823b011f97d6ad2116a53feb814efecc086bc172d31f4214b4d7c630b63bbe575b0868"
            "2d146da44915063a07a78556ab5eff4f67f6aa26211e8d330b53d28567a931028c393709a325425d"
            "e7486ccde24416a7fd4a8ba5fa73899c65f4276dfaddd5b2100adcf0f793104fb235b31ce32ec656"
            "056009a9ebf58d45d7d696b74e0c7ff0499c4d23204976f19561dc0dba6dc53a2497d28ce03498ea"
            "49bf122762d7bc1d6d9c02f6d54f8384"_hex_b;

    // Copy this out; we need to hold onto it to do the confirmation later on
    seqno_t seqno = to_push->seqno;

    // config_push gives us back a buffer that we are required to free when done.  (Without this
    // we'd leak memory!)
    free(to_push);

    // We haven't dumped, so still need to dump:
    CHECK(config_needs_dump(conf));
    // We did call push, but we haven't confirmed it as stored yet, so this will still return true:
    CHECK(config_needs_push(conf));
    unsigned char* dump1;
    size_t dump1len;

    config_dump(conf, &dump1, &dump1len);
    // (in a real client we'd now store this to disk)

    CHECK_FALSE(config_needs_dump(conf));

    // clang-format off
    CHECK(printable(dump1, dump1len) == printable(
        "d"
          "1:!" "i2e"
          "1:${}:{}"
          "1:(" "le"
          "1:)" "le"
          "1:*" "de"
          "1:+" "de"
        "e"_format(exp_push1_decrypted.size(), session::to_string(exp_push1_decrypted))));
    // clang-format on
    free(dump1);  // done with the dump; don't leak!

    const char* tmphash;  // test suite cheat: &(tmphash = "asdf") to fake a length-1 array.

    // So now imagine we got back confirmation from the swarm that the push has been stored:
    config_confirm_pushed(conf, seqno, &(tmphash = "fakehash1"), 1);

    CHECK_FALSE(config_needs_push(conf));
    CHECK(config_needs_dump(conf));  // The confirmation changes state, so this makes us need a dump
                                     // again.
    config_dump(conf, &dump1, &dump1len);

    // clang-format off
    CHECK(printable(dump1, dump1len) == printable(
        "d"
          "1:!" "i0e"
          "1:${}:{}"
          "1:(" "l" "9:fakehash1" "e"
          "1:)" "le"
          "1:*" "de"
          "1:+" "de"
        "e"_format(exp_push1_decrypted.size(), session::to_string(exp_push1_decrypted))));
    // clang-format on
    free(dump1);

    CHECK_FALSE(config_needs_dump(conf));

    // Now we're going to set up a second, competing config object (in the real world this would be
    // another Session client somewhere).

    // Start with an empty config, as above:
    config_object* conf2;
    REQUIRE(user_profile_init(&conf2, to_unsigned(ed_sk.data()), NULL, 0, err) == 0);
    CHECK_FALSE(config_needs_dump(conf2));

    // Now imagine we just pulled down the encrypted string from the swarm; we merge it into conf2:
    const unsigned char* merge_data[1];
    const char* merge_hash[1];
    size_t merge_size[1];
    merge_hash[0] = "fakehash1";
    merge_data[0] = to_unsigned(exp_push1_encrypted.data());
    merge_size[0] = exp_push1_encrypted.size();
    config_string_list* accepted = config_merge(conf2, merge_hash, merge_data, merge_size, 1);
    REQUIRE(accepted->len == 1);
    CHECK(accepted->value[0] == "fakehash1"sv);
    free(accepted);

    // Our state has changed, so we need to dump:
    CHECK(config_needs_dump(conf2));
    unsigned char* dump2;
    size_t dump2len;
    config_dump(conf2, &dump2, &dump2len);
    // (store in db)
    free(dump2);
    CHECK_FALSE(config_needs_dump(conf2));

    // We *don't* need to push: even though we updated, all we did is update to the merged data (and
    // didn't have any sort of merge conflict needed):
    REQUIRE_FALSE(config_needs_push(conf2));

    // Now let's create a conflicting update:

    // Change the name on both clients:
    user_profile_set_name(conf, "Nibbler");
    UserProfileTester::set_profile_updated(conf, std::chrono::sys_seconds{123s});

    user_profile_set_name(conf2, "Raz");

    // And, on conf2, we're also going to change some other things:
    strcpy(p.url, "http://new.example.com/pic");
    memcpy(p.key, "qwert\0yuio1234567890123456789012", 32);
    user_profile_set_pic(conf2, p);

    user_profile_set_nts_expiry(conf2, 86400);
    CHECK(user_profile_get_nts_expiry(conf2) == 86400);

    // Note-to-self's own delete-before pair: it needs them here because it has no contacts entry to
    // carry them, unlike every other conversation.
    CHECK(user_profile_get_nts_delete_before(conf2) == 0);
    CHECK(user_profile_get_nts_delete_attach_before(conf2) == 0);
    user_profile_set_nts_delete_before(conf2, 1700000000);
    user_profile_set_nts_delete_attach_before(conf2, 1700000500);
    CHECK(user_profile_get_nts_delete_before(conf2) == 1700000000);
    CHECK(user_profile_get_nts_delete_attach_before(conf2) == 1700000500);
    // Zero clears, rather than meaning "the epoch".
    user_profile_set_nts_delete_before(conf2, 0);
    CHECK(user_profile_get_nts_delete_before(conf2) == 0);
    CHECK(user_profile_get_nts_delete_attach_before(conf2) == 1700000500);

    // Deleting the messages takes their attachments too, so an attachment instruction the message
    // one already covers is dropped rather than kept saying nothing.
    user_profile_set_nts_delete_before(conf2, 1700000500);
    CHECK(user_profile_get_nts_delete_attach_before(conf2) == 0);

    // And from the other side: one that arrives already covered is not recorded at all.
    user_profile_set_nts_delete_attach_before(conf2, 1700000400);
    CHECK(user_profile_get_nts_delete_attach_before(conf2) == 0);

    // A later one still means something, and is kept.
    user_profile_set_nts_delete_attach_before(conf2, 1700000900);
    CHECK(user_profile_get_nts_delete_attach_before(conf2) == 1700000900);
    CHECK(user_profile_get_nts_delete_before(conf2) == 1700000500);

    CHECK(user_profile_get_blinded_msgreqs(conf2) == -1);
    user_profile_set_blinded_msgreqs(conf2, 0);
    CHECK(user_profile_get_blinded_msgreqs(conf2) == 0);
    user_profile_set_blinded_msgreqs(conf2, -1);
    CHECK(user_profile_get_blinded_msgreqs(conf2) == -1);
    user_profile_set_blinded_msgreqs(conf2, 1);
    CHECK(user_profile_get_blinded_msgreqs(conf2) == 1);

    CHECK(user_profile_get_pro_auto_renewing(conf2) == 0);
    user_profile_set_pro_auto_renewing(conf2, 1);
    CHECK(user_profile_get_pro_auto_renewing(conf2) == 1);
    user_profile_set_pro_auto_renewing(conf2, 0);
    CHECK(user_profile_get_pro_auto_renewing(conf2) == 0);

    CHECK(user_profile_get_pro_grace_period(conf2) == 0);
    user_profile_set_pro_grace_period(conf2, 3600);
    CHECK(user_profile_get_pro_grace_period(conf2) == 3600);
    // Zero erases and reads back as 0 -- unset and zero are the same account state here, which is
    // why there is deliberately no presence check to go with it.
    user_profile_set_pro_grace_period(conf2, 0);
    CHECK(user_profile_get_pro_grace_period(conf2) == 0);
    // Negative clears rather than storing a negative duration.
    user_profile_set_pro_grace_period(conf2, -5);
    CHECK(user_profile_get_pro_grace_period(conf2) == 0);

    UserProfileTester::set_profile_updated(conf2, std::chrono::sys_seconds{124s});

    // Both have changes, so push need a push
    CHECK(config_needs_push(conf));
    CHECK(config_needs_push(conf2));
    to_push = config_push(conf);

    CHECK(to_push->seqno == 2);  // incremented, since we made a field change
    config_confirm_pushed(conf2, to_push->seqno, &(tmphash = "fakehash2"), 1);

    config_push_data* to_push2 = config_push(conf2);
    CHECK(to_push2->seqno == 2);  // incremented, since we made a field change
    config_confirm_pushed(conf2, to_push2->seqno, &(tmphash = "fakehash3"), 1);

    config_dump(conf, &dump1, &dump1len);
    config_dump(conf2, &dump2, &dump2len);
    // (store in db)
    free(dump1);
    free(dump2);

    // Since we set different things, we're going to get back different serialized data to be
    // pushed:
    REQUIRE(to_push->n_configs == 1);
    REQUIRE(to_push2->n_configs == 1);
    CHECK(printable(to_push->config[0], to_push->config_lens[0]) !=
          printable(to_push2->config[0], to_push2->config_lens[0]));

    // Now imagine that each client pushed its `seqno=2` config to the swarm, but then each client
    // also fetches new messages and pulls down the other client's `seqno=2` value.

    // Feed the new config into each other.  (This array could hold multiple configs if we pulled
    // down more than one).
    merge_hash[0] = "fakehash2";
    merge_data[0] = to_push->config[0];
    merge_size[0] = to_push->config_lens[0];
    accepted = config_merge(conf2, merge_hash, merge_data, merge_size, 1);
    free(to_push);
    REQUIRE(accepted->len == 1);
    CHECK(accepted->value[0] == "fakehash2"sv);
    free(accepted);
    merge_hash[0] = "fakehash3";
    merge_data[0] = to_push2->config[0];
    merge_size[0] = to_push2->config_lens[0];
    accepted = config_merge(conf, merge_hash, merge_data, merge_size, 1);
    REQUIRE(accepted->len == 1);
    CHECK(accepted->value[0] == "fakehash3"sv);
    free(accepted);
    free(to_push2);

    // Now after the merge we *will* want to push from both client, since both will have generated a
    // merge conflict update (with seqno = 3).
    to_push = config_push(conf);
    to_push2 = config_push(conf2);

    REQUIRE(to_push->seqno == 3);
    REQUIRE(to_push2->seqno == 3);
    REQUIRE(config_needs_push(conf));
    REQUIRE(config_needs_push(conf2));

    // They should have resolved the conflict to the same thing:
    CHECK(user_profile_get_name(conf) == "Nibbler"sv);
    CHECK(user_profile_get_name(conf2) == "Nibbler"sv);
    // (Note that they could have also both resolved to "Raz" here, but the hash of the serialized
    // message just happens to have a higher hash -- and thus gets priority -- for this particular
    // test).

    // Since only one of them set a profile pic there should be no conflict there:
    pic = user_profile_get_pic(conf);
#if defined(__APPLE__) || defined(__clang__) || defined(__llvm__)
    REQUIRE(pic.url);
#else
    REQUIRE(pic.url != nullptr);
#endif
    CHECK(pic.url == "http://new.example.com/pic"sv);
#if defined(__APPLE__) || defined(__clang__) || defined(__llvm__)
    REQUIRE(pic.key);
#else
    REQUIRE(pic.key != nullptr);
#endif
    CHECK(oxenc::to_hex(to_byte_span(pic.key)) ==
          "7177657274007975696f31323334353637383930313233343536373839303132");
    pic = user_profile_get_pic(conf2);
#if defined(__APPLE__) || defined(__clang__) || defined(__llvm__)
    REQUIRE(pic.url);
#else
    REQUIRE(pic.url != nullptr);
#endif
    CHECK(pic.url == "http://new.example.com/pic"sv);
#if defined(__APPLE__) || defined(__clang__) || defined(__llvm__)
    REQUIRE(pic.key);
#else
    REQUIRE(pic.key != nullptr);
#endif
    CHECK(oxenc::to_hex(to_byte_span(pic.key)) ==
          "7177657274007975696f31323334353637383930313233343536373839303132");

    CHECK(user_profile_get_nts_priority(conf) == 9);
    CHECK(user_profile_get_nts_priority(conf2) == 9);
    CHECK(user_profile_get_nts_expiry(conf) == 86400);
    CHECK(user_profile_get_nts_expiry(conf2) == 86400);
    CHECK(user_profile_get_blinded_msgreqs(conf) == 1);
    CHECK(user_profile_get_blinded_msgreqs(conf2) == 1);

    config_confirm_pushed(conf, to_push->seqno, &(tmphash = "fakehash4"), 1);
    config_confirm_pushed(conf2, to_push2->seqno, &(tmphash = "fakehash4"), 1);

    config_dump(conf, &dump1, &dump1len);
    config_dump(conf2, &dump2, &dump2len);
    // (store in db)
    free(dump1);
    free(dump2);

    CHECK_FALSE(config_needs_dump(conf));
    CHECK_FALSE(config_needs_dump(conf2));
    CHECK_FALSE(config_needs_push(conf));
    CHECK_FALSE(config_needs_push(conf2));

    // Check the current pic
    pic = user_profile_get_pic(conf);
    REQUIRE(pic.url != ""s);

    CHECK(pic.url == "http://new.example.com/pic"sv);
    CHECK(std::ranges::equal(to_byte_span(pic.key), "qwert\0yuio1234567890123456789012"_bytes));

    // Reupload the "current" pic and confirm it gets returned
    strcpy(p.url, "testUrl");
    memcpy(p.key, "secret78901234567890123456789000", 32);
    CHECK(0 == user_profile_set_reupload_pic(conf, p));

    pic = user_profile_get_pic(conf);
    REQUIRE(pic.url != ""s);

    CHECK(pic.url == "testUrl"sv);
    CHECK(std::ranges::equal(to_byte_span(pic.key), "secret78901234567890123456789000"_bytes));

    // Upload a "new" pic and it now gets returned
    strcpy(p.url, "testNewUrl");
    memcpy(p.key, "secret78901234567890123456789111", 32);
    CHECK(0 == user_profile_set_pic(conf, p));
    pic = user_profile_get_pic(conf);
    REQUIRE(pic.url != ""s);

    CHECK(pic.url == "testNewUrl"sv);
    CHECK(std::ranges::equal(to_byte_span(pic.key), "secret78901234567890123456789111"_bytes));

    // Ensure the timestamp for the last modified pic gets updated correctly when the name gets set
    UserProfileTester::set_profile_updated(conf, std::chrono::sys_seconds{0s});
    UserProfileTester::set_reupload_profile_updated(conf, std::chrono::sys_seconds{0s});

    CHECK(0 == user_profile_set_pic(conf, p));
    UserProfileTester::set_profile_updated(conf, std::chrono::sys_seconds{123s});
    user_profile_set_name(conf, "test1");
    CHECK(UserProfileTester::get_profile_updated_value(conf).time_since_epoch().count() != 123);
    UserProfileTester::set_profile_updated(conf, std::chrono::sys_seconds{0s});

    UserProfileTester::set_reupload_profile_updated(conf, std::chrono::sys_seconds{124s});
    CHECK(0 == user_profile_set_reupload_pic(conf, p));
    user_profile_set_name(conf, "test2");
    CHECK(UserProfileTester::get_reupload_profile_updated_value(conf).time_since_epoch().count() !=
          124);

    // Ensure the timestamp for the last modified pic gets updated correctly when the blinded msgreq
    // is set
    UserProfileTester::set_profile_updated(conf, std::chrono::sys_seconds{0s});
    UserProfileTester::set_reupload_profile_updated(conf, std::chrono::sys_seconds{0s});

    strcpy(p.url, "http://example.org/omg-pic-124.bmp");  // NB: length must be < sizeof(p.url)!
    CHECK(0 == user_profile_set_pic(conf, p));
    UserProfileTester::set_profile_updated(conf, std::chrono::sys_seconds{123s});
    user_profile_set_blinded_msgreqs(conf, 0);
    CHECK(UserProfileTester::get_profile_updated_value(conf).time_since_epoch().count() != 123);
    UserProfileTester::set_profile_updated(conf, std::chrono::sys_seconds{0s});

    UserProfileTester::set_reupload_profile_updated(conf, std::chrono::sys_seconds{124s});
    CHECK(0 == user_profile_set_reupload_pic(conf, p));
    user_profile_set_blinded_msgreqs(conf, 1);
    CHECK(UserProfileTester::get_reupload_profile_updated_value(conf).time_since_epoch().count() !=
          124);

    // Ensure the timestamp is stored in seconds seconds (was incorrectly stored as microseconds)
    auto time_before_call = std::chrono::system_clock::now();
    strcpy(p.url, "http://example.org/omg-pic-125.bmp");  // NB: length must be < sizeof(p.url)!
    CHECK(0 == user_profile_set_pic(conf, p));
    auto time_after_call = std::chrono::system_clock::now();
    auto before_seconds =
            std::chrono::duration_cast<std::chrono::seconds>(time_before_call.time_since_epoch())
                    .count();
    auto after_seconds =
            std::chrono::duration_cast<std::chrono::seconds>(time_before_call.time_since_epoch())
                    .count();

    auto raw_value = UserProfileTester::get_raw_profile_updated_value(conf);
    INFO("Checking if raw_value " << raw_value << " is within the range [" << before_seconds << ", "
                                  << after_seconds << "]");
    CHECK((raw_value >= before_seconds && raw_value <= after_seconds));
}

TEST_CASE("UserProfile media-saved notifications", "[config][user_profile]") {
    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hex_b;
    session::config::UserProfile profile{seed, std::nullopt};

    // The default is to tell them, and it costs nothing to carry: an account that has never touched
    // this has no key for it, which is the whole reason the key is stored the other way up.
    CHECK(profile.get_notify_media_saved());
    CHECK_FALSE(profile.needs_push());

    profile.set_notify_media_saved(false);
    CHECK_FALSE(profile.get_notify_media_saved());
    CHECK(profile.needs_push());

    // Setting it back removes the key rather than storing a 0.
    profile.set_notify_media_saved(true);
    CHECK(profile.get_notify_media_saved());

    // Whether the key is really gone is not something the accessor can tell us, since absent and
    // false answer the same; a config built from the dump carries only what was stored.
    auto [seqno, push, obs] = profile.push();
    profile.confirm_pushed(seqno, {"fakehash"});
    session::config::UserProfile reloaded{seed, profile.make_dump()};
    CHECK(reloaded.get_notify_media_saved());
    reloaded.set_notify_media_saved(true);
    CHECK_FALSE(reloaded.needs_push());
}

TEST_CASE("UserProfile media-saved does not age the profile", "[config][user_profile]") {
    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hex_b;
    session::config::UserProfile profile{seed, std::nullopt};

    profile.set_name("Leela");
    auto stamped = profile.get_profile_updated();
    REQUIRE(stamped > std::chrono::sys_seconds{});

    // `t`/`T` say when the *profile* last changed, and a client uses that to decide whose name and
    // picture win.  This is not the profile, so advancing it would claim ours is fresher than it is
    // and could make a stale name beat a newer one from another device.
    profile.set_notify_media_saved(false);
    CHECK(profile.get_profile_updated() == stamped);
}

TEST_CASE("user profile timestamp update bug", "[config][user_profile]") {

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hex_b;

    session::config::UserProfile profile{seed, std::nullopt};

    // Initially the code would update `profile_updated` even if the data hadn't changed, this test
    // verifies that no longer happens
    auto key = to_vector("qwerty78901234567890123456789012"_bytes);
    std::string url = "http://example.com/huge.bmp";
    profile.set_name("Nibbler");
    profile.set_blinded_msgreqs(true);
    profile.set_profile_pic(url, key);
    auto seconds_before_call = profile.get_profile_updated();
    ScopedClockOffset later{2s};
    profile.set_name("Nibbler");
    profile.set_blinded_msgreqs(true);
    profile.set_profile_pic(url, key);
    auto seconds_after_call = profile.get_profile_updated();
    CHECK(profile.get_profile_updated() == seconds_before_call);

    // Also make sure it does change
    profile.set_name("Nibbler1");
    CHECK(profile.get_profile_updated() != seconds_before_call);
}

TEST_CASE("UserProfile Pro Storage", "[config][user_profile][pro]") {

    const auto seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hex_b;

    session::config::UserProfile profile{seed, std::nullopt};

    // Ensure the bitset is being updated correctly
    CHECK(profile.get_profile_flags() == ProProfileFlags::None);

    profile.set_pro_badge(true);
    CHECK(contains(profile.get_profile_flags(), ProProfileFlags::ProBadge));

    profile.set_pro_badge(false);
    CHECK(profile.get_profile_flags() == ProProfileFlags::None);

    profile.set_animated_avatar(true);
    CHECK(contains(profile.get_profile_flags(), ProProfileFlags::AnimatedAvatar));

    profile.set_animated_avatar(false);
    CHECK(profile.get_profile_flags() == ProProfileFlags::None);

    profile.set_pro_badge(true);
    profile.set_animated_avatar(true);
    CHECK(contains(profile.get_profile_flags(), ProProfileFlags::ProBadge));
    CHECK(contains(profile.get_profile_flags(), ProProfileFlags::AnimatedAvatar));

    profile.set_animated_avatar(false);
    CHECK(contains(profile.get_profile_flags(), ProProfileFlags::ProBadge));
    CHECK_FALSE(contains(profile.get_profile_flags(), ProProfileFlags::AnimatedAvatar));

    {
        session::config::UserProfile profile2{seed, profile.dump()};
        CHECK(contains(profile2.get_profile_flags(), ProProfileFlags::ProBadge));
        CHECK_FALSE(contains(profile2.get_profile_flags(), ProProfileFlags::AnimatedAvatar));
    }

    // Ensure the pro config is being stored correctly
    auto [rotating_pk, rotating_sk] = ed25519::keypair();
    auto [signing_pk, signing_sk] = ed25519::keypair();

    session::config::ProConfig pro_cpp = {};
    pro_pro_config pro = {};
    {
        // CPP
        pro_cpp.rotating_privkey = rotating_sk;
        pro_cpp.proof.rotating_pubkey = rotating_pk;
        pro_cpp.proof.expiry_at = std::chrono::sys_seconds(1s);
        constexpr auto revocation_tag =
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex_b;
        static_assert(pro_cpp.proof.revocation_tag.max_size() == revocation_tag.size());
        std::memcpy(
                pro_cpp.proof.revocation_tag.data(), revocation_tag.data(), revocation_tag.size());

        // C
        std::memcpy(pro.rotating_privkey.data, rotating_sk.data(), rotating_sk.size());
        std::memcpy(pro.proof.rotating_pubkey.data, rotating_pk.data(), rotating_pk.size());
        pro.proof.expiry_ts = pro_cpp.proof.expiry_at.time_since_epoch().count();
        std::memcpy(pro.proof.revocation_tag.data, revocation_tag.data(), revocation_tag.size());
    }

    UserProfileTester::set_profile_updated(profile, std::chrono::sys_seconds{123s});
    CHECK(profile.get_profile_updated().time_since_epoch().count() == 123);
    CHECK_FALSE(profile.get_pro_config().has_value());
    profile.set_pro_config(pro_cpp);
    CHECK(profile.get_pro_config() == pro_cpp);
    CHECK(profile.get_profile_updated().time_since_epoch().count() != 123);

    {
        session::config::UserProfile profile2{seed, profile.dump()};
        CHECK(profile.get_pro_config() == pro_cpp);
    }

    profile.remove_pro_config();
    CHECK_FALSE(profile.get_pro_config().has_value());

    auto access_expiry = std::chrono::sys_seconds{std::chrono::seconds{500}};
    profile.set_pro_access_expiry(access_expiry);
    CHECK(profile.get_pro_access_expiry() == access_expiry);

    // Pro auto-renewing flag: presence-only, defaults to false, and (backend-derived state, not a
    // user edit) does not stamp the profile-updated timestamp.
    CHECK_FALSE(profile.get_pro_auto_renewing());
    UserProfileTester::set_profile_updated(profile, std::chrono::sys_seconds{456s});
    profile.set_pro_auto_renewing(true);
    CHECK(profile.get_pro_auto_renewing());
    CHECK(profile.get_profile_updated().time_since_epoch().count() == 456);
    profile.set_pro_auto_renewing(false);
    CHECK_FALSE(profile.get_pro_auto_renewing());

    // Grace period: synced so any device can compute when coverage actually ends, at `E + G`. `E`
    // is the payment-due date -- the instant the term was paid through -- and `G` is how much
    // longer the backend keeps serving past it (the store's dunning window plus its renewal-latency
    // allowance). Carrying `G` is the whole reason this key exists: `E` alone cannot answer it.
    CHECK(profile.get_pro_grace_period() == 0s);
    UserProfileTester::set_profile_updated(profile, std::chrono::sys_seconds{456s});
    profile.set_pro_grace_period(1h);
    CHECK(profile.get_pro_grace_period() == 1h);
    // Backend-derived, like E/I/R/A: no profile-updated bump.
    CHECK(profile.get_profile_updated().time_since_epoch().count() == 456);
    // The property the key exists for: expiry plus grace is the instant coverage ends.
    profile.set_pro_access_expiry(std::chrono::sys_seconds{5000s});
    CHECK(*profile.get_pro_access_expiry() + profile.get_pro_grace_period() ==
          std::chrono::sys_seconds{5000s} + 1h);
    // Zero clears; unset and zero are indistinguishable *and* equivalent (coverage ends at `E`).
    profile.set_pro_grace_period(0s);
    CHECK(profile.get_pro_grace_period() == 0s);
    CHECK(*profile.get_pro_access_expiry() + profile.get_pro_grace_period() ==
          std::chrono::sys_seconds{5000s});

    // Clearing `E` clears the renewing flag with it, for the same reason it clears `G`: `A`
    // describes the subscription `E` denotes, and a renewing flag with no expiry beside it
    // describes a subscription that is not there. Pinned because the alternative -- every consumer
    // testing `E` before reading `A` -- is a convention nothing enforces.
    profile.set_pro_auto_renewing(true);
    profile.set_pro_access_expiry(std::chrono::sys_seconds{9000s});
    CHECK(profile.get_pro_auto_renewing());
    profile.set_pro_access_expiry(std::nullopt);
    CHECK_FALSE(profile.get_pro_auto_renewing());
    CHECK(profile.get_pro_grace_period() == 0s);
    CHECK_FALSE(profile.get_pro_access_expiry().has_value());

    // Clearing `E` also clears `G`: the pair is only meaningful as `E + G`, so a `G` that outlived
    // its `E` would silently pair with the NEXT `E` write -- and that write is typically a proof
    // outcome, which carries no grace to correct it with. Enforced in the setter, not at call
    // sites.
    profile.set_pro_grace_period(1h);
    CHECK(profile.get_pro_grace_period() == 1h);
    profile.set_pro_access_expiry(std::nullopt);
    CHECK_FALSE(profile.get_pro_access_expiry().has_value());
    CHECK(profile.get_pro_grace_period() == 0s);
    // ...and a later `E` write therefore cannot inherit the stale grace.
    profile.set_pro_access_expiry(std::chrono::sys_seconds{9000s});
    CHECK(*profile.get_pro_access_expiry() + profile.get_pro_grace_period() ==
          std::chrono::sys_seconds{9000s});

    // Refund-requested flag (synced via config, not the Pro backend)
    CHECK_FALSE(profile.get_refund_requested().has_value());

    const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());

    // A recent request is returned as-is, and stamps the profile-updated timestamp so it
    // time-orders across devices.
    UserProfileTester::set_profile_updated(profile, std::chrono::sys_seconds{456s});
    auto refund_at = now - 1h;
    profile.set_refund_requested(refund_at);
    CHECK(profile.get_refund_requested() == refund_at);
    CHECK(profile.get_profile_updated().time_since_epoch().count() != 456);

    {
        // Round-trips through a dump/reload.
        session::config::UserProfile profile2{seed, profile.dump()};
        CHECK(profile2.get_refund_requested() == refund_at);
    }

    // A stored value more than a week old is ignored on read (treated as absent).
    profile.set_refund_requested(now - std::chrono::weeks{2});
    CHECK_FALSE(profile.get_refund_requested().has_value());

    // Clearing removes it entirely.
    profile.set_refund_requested(std::nullopt);
    CHECK_FALSE(profile.get_refund_requested().has_value());

    // Pro-prepaid ("purchase in flight") marker: insert-only-if-not-pro, 1-week read gate, and
    // auto-clear when entitlement lands. (No proof, access expiry in the past -> not currently
    // pro.)
    CHECK_FALSE(profile.get_pro_prepaid().has_value());

    auto prepaid_at = now - 1h;
    profile.set_pro_prepaid(prepaid_at);
    CHECK(profile.get_pro_prepaid() == prepaid_at);

    // A stale (>1wk) marker is ignored on read.
    profile.set_pro_prepaid(now - std::chrono::weeks{2});
    CHECK_FALSE(profile.get_pro_prepaid().has_value());

    // Confirming a live access expiry clears the marker (entitlement arrived).
    profile.set_pro_prepaid(prepaid_at);
    REQUIRE(profile.get_pro_prepaid().has_value());
    profile.set_pro_access_expiry(now + 1h);
    CHECK_FALSE(profile.get_pro_prepaid().has_value());

    // While pro (live access expiry), setting the marker is a no-op.
    profile.set_pro_prepaid(prepaid_at);
    CHECK_FALSE(profile.get_pro_prepaid().has_value());

    // A landed (still-valid) proof also clears it: back to not-pro, mark pending, store a proof.
    profile.set_pro_access_expiry(std::nullopt);
    profile.set_pro_prepaid(prepaid_at);
    REQUIRE(profile.get_pro_prepaid().has_value());
    pro_cpp.proof.expiry_at = now + 1h;
    profile.set_pro_config(pro_cpp);
    CHECK_FALSE(profile.get_pro_prepaid().has_value());

    // Explicit clear via nullopt.
    profile.remove_pro_config();
    profile.set_pro_prepaid(prepaid_at);
    REQUIRE(profile.get_pro_prepaid().has_value());
    profile.set_pro_prepaid(std::nullopt);
    CHECK_FALSE(profile.get_pro_prepaid().has_value());

    // pro_renewal_target: centralised "when to renew" decision.
    {
        session::config::UserProfile pr{seed, std::nullopt};

        // No proof and no purchase in flight -> not Pro, nothing to fetch.
        CHECK_FALSE(pr.pro_renewal_target(now).has_value());

        // No proof but a purchase in flight (prepaid) -> fetch immediately.
        pr.set_pro_prepaid(now - 1h);
        REQUIRE(pr.get_pro_prepaid().has_value());
        CHECK(pr.pro_renewal_target(now) == now);
        pr.set_pro_prepaid(std::nullopt);

        auto store_proof = [&](std::chrono::sys_seconds expiry) {
            session::config::ProConfig pc = {};
            pc.rotating_privkey = rotating_sk;  // any valid 64-byte key (only sizes matter here)
            pc.proof.rotating_pubkey = rotating_pk;
            pc.proof.expiry_at = expiry;
            pr.set_pro_config(pc);
        };

        // Valid proof (10 days out), entitlement a month out -> preemptive ~1h before expiry.
        auto expiry = now + 10 * 24h;
        store_proof(expiry);
        pr.set_pro_access_expiry(now + 30 * 24h);
        auto target = pr.pro_renewal_target(now);
        REQUIRE(target.has_value());
        CHECK(*target <= expiry - 59min);
        CHECK(*target >= expiry - 61min);

        // Same proof but entitlement ending within the hour -> don't renew.
        pr.set_pro_access_expiry(now + 30min);
        CHECK_FALSE(pr.pro_renewal_target(now).has_value());

        // No access expiry at all -> don't preemptively renew.
        pr.set_pro_access_expiry(std::nullopt);
        CHECK_FALSE(pr.pro_renewal_target(now).has_value());

        // Expired proof -> renew immediately, regardless of entitlement.
        store_proof(now - 1h);
        CHECK(pr.pro_renewal_target(now) == now);

        // Near-boundary deferral: when renewal is already due and `now` sits at a rotating-seed
        // period boundary, defer by PRO_RENEWAL_BOUNDARY_DEFER as long as that leaves at least
        // PRO_RENEWAL_BOUNDARY_MIN_VALIDITY of proof validity; otherwise just renew now.
        auto at_boundary = now - now.time_since_epoch() % session::PRO_ROTATING_SEED_PERIOD;
        pr.set_pro_access_expiry(at_boundary + 30 * 24h);
        store_proof(at_boundary + 30min);  // due (within lead), plenty of validity left
        CHECK(pr.pro_renewal_target(at_boundary) ==
              at_boundary + session::PRO_RENEWAL_BOUNDARY_DEFER);

        // Expiry only MIN_VALIDITY out: after any defer, < MIN_VALIDITY remains -> renew now.
        store_proof(at_boundary + session::PRO_RENEWAL_BOUNDARY_MIN_VALIDITY);
        auto r = pr.pro_renewal_target(at_boundary);
        REQUIRE(r.has_value());
        CHECK(*r <= at_boundary);
    }
}
