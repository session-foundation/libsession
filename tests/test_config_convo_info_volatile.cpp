#include <oxenc/hex.h>
#include <session/config/convo_info_volatile.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <session/config/convo_info_volatile.hpp>
#include <session/types.hpp>
#include <string_view>
#include <variant>

#include "utils.hpp"

TEST_CASE("Conversations", "[config][conversations]") {

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

    session::config::ConvoInfoVolatile convos{std::span<const unsigned char>{seed}, std::nullopt};

    constexpr auto definitely_real_id =
            "055000000000000000000000000000000000000000000000000000000000000000"sv;

    constexpr auto benders_nightmare_group =
            "030111101001001000101010011011010010101010111010000110100001210000"sv;

    constexpr auto legacy_blinded_id =
            "150000000000000000000000000000000000101010111010000110100001210000"sv;
    constexpr auto blinded_id =
            "255000000000000000000000000000000000101010111010000110100001210000"sv;

    CHECK_FALSE(convos.get_1to1(definitely_real_id));

    CHECK(convos.empty());
    CHECK(convos.size() == 0);

    auto c = convos.get_or_construct_1to1(definitely_real_id);

    CHECK(c.session_id == definitely_real_id);
    CHECK(c.last_read == 0);

    CHECK_FALSE(convos.needs_push());
    CHECK_FALSE(convos.needs_dump());
    CHECK(std::get<seqno_t>(convos.push()) == 0);

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();

    c.last_read = now_ms;

    // The new data doesn't get stored until we call this:
    convos.set(c);

    REQUIRE_FALSE(convos.get_legacy_group(definitely_real_id).has_value());
    REQUIRE(convos.get_1to1(definitely_real_id).has_value());
    CHECK(convos.get_1to1(definitely_real_id)->last_read == now_ms);

    CHECK(convos.needs_push());
    CHECK(convos.needs_dump());

    const auto community_pubkey =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hexbytes;

    auto og = convos.get_or_construct_community(
            "http://Example.ORG:5678", "SudokuRoom", community_pubkey);
    CHECK(og.base_url() == "http://example.org:5678");  // Note: lower-case
    CHECK(og.room() == "sudokuroom");                   // Note: lower-case
    CHECK(og.pubkey().size() == 32);
    CHECK(og.pubkey_hex() == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    og.unread = true;

    // The new data doesn't get stored until we call this:
    convos.set(og);

    CHECK_FALSE(convos.get_group(benders_nightmare_group));

    auto g = convos.get_or_construct_group(benders_nightmare_group);
    CHECK(g.id == benders_nightmare_group);
    CHECK(g.last_read == 0);
    CHECK_FALSE(g.unread);

    g.last_read = now_ms;
    g.unread = true;
    convos.set(g);

    CHECK_FALSE(convos.get_blinded_1to1(legacy_blinded_id));
    CHECK_FALSE(convos.get_blinded_1to1(blinded_id));

    auto lb = convos.get_or_construct_blinded_1to1(legacy_blinded_id);
    CHECK(lb.blinded_session_id == legacy_blinded_id);
    CHECK(lb.last_read == 0);
    CHECK_FALSE(lb.unread);

    lb.last_read = now_ms;
    lb.unread = true;
    convos.set(lb);

    auto b = convos.get_or_construct_blinded_1to1(blinded_id);
    CHECK(b.blinded_session_id == blinded_id);
    CHECK(b.last_read == 0);
    CHECK_FALSE(b.unread);

    b.last_read = now_ms;
    b.unread = true;
    convos.set(b);

    auto [seqno, to_push, obs] = convos.push();

    CHECK(seqno == 1);

    // Pretend we uploaded it
    convos.confirm_pushed(seqno, {"hash1"});
    CHECK(convos.needs_dump());
    CHECK_FALSE(convos.needs_push());

    // NB: Not going to check encrypted data and decryption here because that's general (not
    // specific to convos) and is covered already in the user profile tests.

    session::config::ConvoInfoVolatile convos2{seed, convos.dump()};
    CHECK_FALSE(convos.needs_push());
    CHECK_FALSE(convos.needs_dump());
    CHECK(std::get<seqno_t>(convos.push()) == 1);
    CHECK_FALSE(convos.needs_dump());  // Because we just called dump() above, to load up
                                       // convos2.

    auto x1 = convos2.get_1to1(definitely_real_id);
    REQUIRE(x1);
    CHECK(x1->last_read == now_ms);
    CHECK(x1->session_id == definitely_real_id);
    CHECK_FALSE(x1->unread);

    auto x2 = convos2.get_community("http://EXAMPLE.org:5678", "sudokuRoom");
    REQUIRE(x2);
    CHECK(x2->base_url() == "http://example.org:5678");
    CHECK(x2->room() == "sudokuroom");
    CHECK(x2->pubkey_hex() == to_hex(community_pubkey));
    CHECK(x2->unread);

    auto x3 = convos2.get_group(benders_nightmare_group);
    REQUIRE(x3);
    CHECK(x3->last_read == now_ms);
    CHECK(x3->unread);

    auto x4 = convos2.get_blinded_1to1(legacy_blinded_id);
    REQUIRE(x4);
    CHECK(x4->blinded_session_id ==
          "150000000000000000000000000000000000101010111010000110100001210000");
    CHECK(x4->last_read == now_ms);
    CHECK(x4->unread);

    auto x5 = convos2.get_blinded_1to1(blinded_id);
    REQUIRE(x5);
    CHECK(x5->blinded_session_id ==
          "255000000000000000000000000000000000101010111010000110100001210000");
    CHECK(x5->last_read == now_ms);
    CHECK(x5->unread);

    auto another_id = "051111111111111111111111111111111111111111111111111111111111111111"sv;
    auto c2 = convos.get_or_construct_1to1(another_id);
    c2.unread = true;
    convos2.set(c2);

    auto c3 = convos2.get_or_construct_legacy_group(
            "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    c3.last_read = now_ms - 50;
    convos2.set(c3);

    auto c4 = convos2.get_or_construct_blinded_1to1(
            "2512345ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    c4.unread = true;
    convos2.set(c4);

    CHECK(convos2.needs_push());

    std::tie(seqno, to_push, obs) = convos2.push();

    CHECK(seqno == 2);

    REQUIRE(to_push.size() == 1);
    std::vector<std::pair<std::string, std::span<const unsigned char>>> merge_configs;
    merge_configs.emplace_back("hash2", to_push[0]);
    convos.merge(merge_configs);
    convos2.confirm_pushed(seqno, {"hash2"});

    CHECK_FALSE(convos.needs_push());
    CHECK(std::get<seqno_t>(convos.push()) == seqno);

    using session::config::convo::blinded_one_to_one;
    using session::config::convo::community;
    using session::config::convo::group;
    using session::config::convo::legacy_group;
    using session::config::convo::one_to_one;

    std::vector<std::string> seen, expected;
    for (const auto& e :
         {"1-to-1: 051111111111111111111111111111111111111111111111111111111111111111",
          "1-to-1: 055000000000000000000000000000000000000000000000000000000000000000",
          "gr: 030111101001001000101010011011010010101010111010000110100001210000",
          "comm: http://example.org:5678/r/sudokuroom",
          "lgr: 05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          "lb: 150000000000000000000000000000000000101010111010000110100001210000",
          "b: 2512345ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          "b: 255000000000000000000000000000000000101010111010000110100001210000"})
        expected.emplace_back(e);

    for (auto* conv : {&convos, &convos2}) {
        // Iterate through and make sure we got everything we expected
        seen.clear();
        CHECK(conv->size() == 8);
        CHECK(conv->size_1to1() == 2);
        CHECK(conv->size_communities() == 1);
        CHECK(conv->size_legacy_groups() == 1);
        CHECK(conv->size_groups() == 1);
        CHECK(conv->size_blinded_1to1() == 3);
        CHECK_FALSE(conv->empty());
        for (const auto& convo : *conv) {
            if (auto* c = std::get_if<one_to_one>(&convo))
                seen.push_back("1-to-1: "s + c->session_id);
            else if (auto* c = std::get_if<group>(&convo))
                seen.push_back("gr: " + c->id);
            else if (auto* c = std::get_if<community>(&convo))
                seen.push_back(
                        "comm: " + std::string{c->base_url()} + "/r/" + std::string{c->room()});
            else if (auto* c = std::get_if<legacy_group>(&convo))
                seen.push_back("lgr: " + c->id);
            else if (auto* c = std::get_if<blinded_one_to_one>(&convo); c->legacy_blinding)
                seen.push_back("lb: " + c->blinded_session_id);
            else if (auto* c = std::get_if<blinded_one_to_one>(&convo); !c->legacy_blinding)
                seen.push_back("b: " + c->blinded_session_id);
            else
                seen.push_back("unknown convo type!");
        }

        CHECK(seen == expected);
    }

    CHECK_FALSE(convos.needs_push());
    convos.erase_1to1("052000000000000000000000000000000000000000000000000000000000000000");
    CHECK_FALSE(convos.needs_push());
    convos.erase_1to1("055000000000000000000000000000000000000000000000000000000000000000");
    convos.erase_blinded_1to1("255000000000000000000000000000000000101010111010000110100001210000");
    CHECK(convos.needs_push());
    CHECK(convos.size() == 6);
    CHECK(convos.size_1to1() == 1);
    CHECK(convos.size_groups() == 1);
    CHECK(convos.size_blinded_1to1() == 2);

    // Check the single-type iterators:
    seen.clear();
    for (auto it = convos.begin_1to1(); it != convos.end(); ++it)
        seen.push_back(it->session_id);
    CHECK(seen == std::vector<std::string>{
                          "051111111111111111111111111111111111111111111111111111111111111111",
                  });

    seen.clear();
    for (auto it = convos.begin_communities(); it != convos.end(); ++it)
        seen.emplace_back(it->base_url());
    CHECK(seen == std::vector<std::string>{
                          "http://example.org:5678",
                  });

    seen.clear();
    for (auto it = convos.begin_legacy_groups(); it != convos.end(); ++it)
        seen.emplace_back(it->id);
    CHECK(seen == std::vector<std::string>{
                          "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                  });

    seen.clear();
    for (auto it = convos.begin_blinded_1to1(); it != convos.end(); ++it)
        seen.emplace_back(it->blinded_session_id);
    CHECK(seen == std::vector<std::string>{
                          "150000000000000000000000000000000000101010111010000110100001210000",
                          "2512345ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                  });

    // Ensure that we throw correctly when giving invalid blinded ids
    auto invalid_id_1 = "072222222222222222222222222222222222222222222222222222222222222222"sv;
    auto invalid_id_2 = "992222222222222222222222222222222222222222222222222222222222222222"sv;
    CHECK_THROWS(convos.get_or_construct_blinded_1to1(invalid_id_1));
    CHECK_THROWS(convos.get_or_construct_blinded_1to1(invalid_id_2));
}

TEST_CASE("Conversations (C API)", "[config][conversations][c]") {
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

    config_object* conf;
    REQUIRE(0 == convo_info_volatile_init(&conf, ed_sk.data(), NULL, 0, NULL));

    const char* const definitely_real_id =
            "055000000000000000000000000000000000000000000000000000000000000000";

    convo_info_volatile_1to1 c;
    CHECK_FALSE(convo_info_volatile_get_1to1(conf, &c, definitely_real_id));
    CHECK(conf->last_error == nullptr);

    CHECK_FALSE(convo_info_volatile_get_1to1(conf, &c, "05123456"));
    CHECK(conf->last_error ==
          "Invalid session ID: expected 66 hex digits starting with 05; got 05123456"sv);

    CHECK(convo_info_volatile_size(conf) == 0);

    CHECK(convo_info_volatile_get_or_construct_1to1(conf, &c, definitely_real_id));

    CHECK(c.session_id == std::string_view{definitely_real_id});
    CHECK(c.last_read == 0);
    CHECK_FALSE(c.unread);

    CHECK_FALSE(config_needs_push(conf));
    CHECK_FALSE(config_needs_dump(conf));

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();

    c.last_read = now_ms;

    // The new data doesn't get stored until we call this:
    convo_info_volatile_set_1to1(conf, &c);

    convo_info_volatile_legacy_group cg;
    REQUIRE_FALSE(convo_info_volatile_get_legacy_group(conf, &cg, definitely_real_id));
    REQUIRE(convo_info_volatile_get_1to1(conf, &c, definitely_real_id));
    CHECK(c.last_read == now_ms);

    CHECK(config_needs_push(conf));
    CHECK(config_needs_dump(conf));

    const auto community_pubkey =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hexbytes;

    convo_info_volatile_community og;

    CHECK_FALSE(convo_info_volatile_get_or_construct_community(
            conf,
            &og,
            "bad-url",
            "room",
            "0000000000000000000000000000000000000000000000000000000000000000"_hexbytes.data()));
    CHECK(conf->last_error == "Invalid URL: invalid/missing protocol://"sv);
    CHECK_FALSE(convo_info_volatile_get_or_construct_community(
            conf,
            &og,
            "https://example.com",
            "bad room name",
            "0000000000000000000000000000000000000000000000000000000000000000"_hexbytes.data()));
    CHECK(conf->last_error == "Invalid community URL: room token contains invalid characters"sv);

    CHECK(convo_info_volatile_get_or_construct_community(
            conf, &og, "http://Example.ORG:5678", "SudokuRoom", community_pubkey.data()));
    CHECK(conf->last_error == nullptr);
    CHECK(og.base_url == "http://example.org:5678"sv);  // Note: lower-case
    CHECK(og.room == "sudokuroom"sv);                   // Note: lower-case
    CHECK(oxenc::to_hex(og.pubkey, og.pubkey + 32) ==
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    og.unread = true;

    // The new data doesn't get stored until we call this:
    convo_info_volatile_set_community(conf, &og);

    const char* const blinded_id =
            "150000000000000000000000000000000000101010111010000110100001210000";
    convo_info_volatile_blinded_1to1 b1;
    REQUIRE_FALSE(convo_info_volatile_get_blinded_1to1(conf, &b1, blinded_id));
    REQUIRE(convo_info_volatile_get_or_construct_blinded_1to1(conf, &b1, blinded_id));
    b1.last_read = now_ms;
    convo_info_volatile_set_blinded_1to1(conf, &b1);

    CHECK(config_needs_push(conf));
    CHECK(config_needs_dump(conf));

    config_push_data* to_push = config_push(conf);
    auto seqno = to_push->seqno;
    CHECK(seqno == 1);
    REQUIRE(to_push->n_configs == 1);
    free(to_push);

    const char* tmphash;  // test suite cheat: &(tmphash = "asdf") to fake a length-1 array.

    // Pretend we uploaded it
    config_confirm_pushed(conf, seqno, &(tmphash = "hash1"), 1);
    CHECK(config_needs_dump(conf));
    CHECK_FALSE(config_needs_push(conf));

    unsigned char* dump;
    size_t dumplen;
    config_dump(conf, &dump, &dumplen);

    config_object* conf2;
    REQUIRE(convo_info_volatile_init(&conf2, ed_sk.data(), dump, dumplen, NULL) == 0);
    free(dump);

    CHECK_FALSE(config_needs_push(conf2));
    CHECK_FALSE(config_needs_dump(conf2));

    REQUIRE(convo_info_volatile_get_1to1(conf2, &c, definitely_real_id));
    CHECK(c.last_read == now_ms);
    CHECK(c.session_id == std::string_view{definitely_real_id});
    CHECK_FALSE(c.unread);

    REQUIRE(convo_info_volatile_get_community(conf2, &og, "http://EXAMPLE.org:5678", "sudokuRoom"));
    CHECK(og.base_url == "http://example.org:5678"sv);
    CHECK(og.room == "sudokuroom"sv);
    CHECK(oxenc::to_hex(og.pubkey, og.pubkey + 32) == to_hex(community_pubkey));

    auto another_id = "051111111111111111111111111111111111111111111111111111111111111111";
    convo_info_volatile_1to1 c2;
    REQUIRE(convo_info_volatile_get_or_construct_1to1(conf2, &c2, another_id));
    c2.unread = true;
    convo_info_volatile_set_1to1(conf2, &c2);

    REQUIRE(convo_info_volatile_get_or_construct_legacy_group(
            conf2, &cg, "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"));
    cg.last_read = now_ms - 50;
    convo_info_volatile_set_legacy_group(conf2, &cg);
    CHECK(config_needs_push(conf2));

    convo_info_volatile_blinded_1to1 b2;
    REQUIRE(convo_info_volatile_get_or_construct_blinded_1to1(
            conf2, &b2, "2512345ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"));
    b2.unread = true;
    convo_info_volatile_set_blinded_1to1(conf2, &b2);
    CHECK(config_needs_push(conf2));

    to_push = config_push(conf2);
    CHECK(to_push->seqno == 2);
    REQUIRE(to_push->n_configs == 1);

    const char* hash_data[1];
    const unsigned char* merge_data[1];
    size_t merge_size[1];
    hash_data[0] = "hash123";
    merge_data[0] = to_push->config[0];
    merge_size[0] = to_push->config_lens[0];
    config_string_list* accepted = config_merge(conf, hash_data, merge_data, merge_size, 1);
    REQUIRE(accepted->len == 1);
    CHECK(accepted->value[0] == "hash123"sv);
    free(accepted);
    config_confirm_pushed(conf2, seqno, &(tmphash = "hash123"), 1);
    free(to_push);

    CHECK_FALSE(config_needs_push(conf));

    std::vector<std::string> seen;
    for (auto* conf : {conf, conf2}) {
        // Iterate through and make sure we got everything we expected
        seen.clear();
        CHECK(convo_info_volatile_size(conf) == 6);
        CHECK(convo_info_volatile_size_1to1(conf) == 2);
        CHECK(convo_info_volatile_size_communities(conf) == 1);
        CHECK(convo_info_volatile_size_legacy_groups(conf) == 1);
        CHECK(convo_info_volatile_size_blinded_1to1(conf) == 2);

        convo_info_volatile_1to1 c1;
        convo_info_volatile_community c2;
        convo_info_volatile_legacy_group c3;
        convo_info_volatile_blinded_1to1 c4;
        convo_info_volatile_iterator* it = convo_info_volatile_iterator_new(conf);
        for (; !convo_info_volatile_iterator_done(it); convo_info_volatile_iterator_advance(it)) {
            if (convo_info_volatile_it_is_1to1(it, &c1)) {
                seen.push_back("1-to-1: "s + c1.session_id);
            } else if (convo_info_volatile_it_is_community(it, &c2)) {
                seen.push_back("comm: "s + c2.base_url + "/r/" + c2.room);
            } else if (convo_info_volatile_it_is_legacy_group(it, &c3)) {
                seen.push_back("lgr: "s + c3.group_id);
            } else if (convo_info_volatile_it_is_blinded_1to1(it, &c4)) {
                seen.push_back("b: "s + c4.blinded_session_id);
            }
        }
        convo_info_volatile_iterator_free(it);

        CHECK(seen == std::vector<std::string>{
                              "1-to-1: "
                              "051111111111111111111111111111111111111111111111111111111111111111",
                              "1-to-1: "
                              "055000000000000000000000000000000000000000000000000000000000000000",
                              "comm: http://example.org:5678/r/sudokuroom",
                              "lgr: "
                              "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                              "b: "
                              "150000000000000000000000000000000000101010111010000110100001210000",
                              "b: "
                              "2512345cccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                              "c"});
    }

    CHECK_FALSE(config_needs_push(conf));
    convo_info_volatile_erase_1to1(
            conf, "052000000000000000000000000000000000000000000000000000000000000000");
    CHECK_FALSE(config_needs_push(conf));
    convo_info_volatile_erase_1to1(
            conf, "055000000000000000000000000000000000000000000000000000000000000000");
    convo_info_volatile_erase_blinded_1to1(
            conf, "2512345ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    CHECK(config_needs_push(conf));
    CHECK(convo_info_volatile_size(conf) == 4);
    CHECK(convo_info_volatile_size_1to1(conf) == 1);
    CHECK(convo_info_volatile_size_blinded_1to1(conf) == 1);

    // Check the single-type iterators:
    seen.clear();

    convo_info_volatile_iterator* it;
    convo_info_volatile_1to1 ci;
    for (it = convo_info_volatile_iterator_new_1to1(conf); !convo_info_volatile_iterator_done(it);
         convo_info_volatile_iterator_advance(it)) {
        REQUIRE(convo_info_volatile_it_is_1to1(it, &ci));
        seen.push_back(ci.session_id);
    }
    convo_info_volatile_iterator_free(it);
    CHECK(seen == std::vector<std::string>{{
                          "051111111111111111111111111111111111111111111111111111111111111111",
                  }});

    seen.clear();
    convo_info_volatile_community ogi;
    for (it = convo_info_volatile_iterator_new_communities(conf);
         !convo_info_volatile_iterator_done(it);
         convo_info_volatile_iterator_advance(it)) {
        REQUIRE(convo_info_volatile_it_is_community(it, &ogi));
        seen.emplace_back(ogi.base_url);
    }
    convo_info_volatile_iterator_free(it);
    CHECK(seen == std::vector<std::string>{
                          "http://example.org:5678",
                  });

    seen.clear();
    convo_info_volatile_legacy_group cgi;
    for (it = convo_info_volatile_iterator_new_legacy_groups(conf);
         !convo_info_volatile_iterator_done(it);
         convo_info_volatile_iterator_advance(it)) {
        REQUIRE(convo_info_volatile_it_is_legacy_group(it, &cgi));
        seen.emplace_back(cgi.group_id);
    }
    convo_info_volatile_iterator_free(it);
    CHECK(seen == std::vector<std::string>{
                          "05cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                  });

    seen.clear();
    convo_info_volatile_blinded_1to1 bi;
    for (it = convo_info_volatile_iterator_new_blinded_1to1(conf);
         !convo_info_volatile_iterator_done(it);
         convo_info_volatile_iterator_advance(it)) {
        REQUIRE(convo_info_volatile_it_is_blinded_1to1(it, &bi));
        seen.emplace_back(bi.blinded_session_id);
    }
    convo_info_volatile_iterator_free(it);
    CHECK(seen == std::vector<std::string>{
                          "150000000000000000000000000000000000101010111010000110100001210000",
                  });
}

TEST_CASE("Conversation pruning", "[config][conversations][pruning]") {

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

    session::config::ConvoInfoVolatile convos{std::span<const unsigned char>{seed}, std::nullopt};

    auto some_pubkey = [](unsigned char x) -> std::vector<unsigned char> {
        std::vector<unsigned char> s =
                "0000000000000000000000000000000000000000000000000000000000000000"_hexbytes;
        s[31] = x;
        return s;
    };
    auto some_session_id = [&](unsigned char x) -> std::string {
        auto pk = some_pubkey(x);
        return "05" + oxenc::to_hex(pk.begin(), pk.end());
    };
    const auto now = std::chrono::system_clock::now() - 1ms;
    auto unix_timestamp = [&now](int days_ago) -> int64_t {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                       (now - days_ago * 24h).time_since_epoch())
                .count();
    };

    for (int i = 0; i <= 65; i++) {
        if (i % 3 == 0) {
            auto c = convos.get_or_construct_1to1(some_session_id(i));
            c.last_read = unix_timestamp(i);
            if (i % 5 == 0)
                c.unread = true;

            if (i % 7 == 0) {
                c.pro_expiry_at =
                        std::chrono::sys_seconds{std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::milliseconds{unix_timestamp(i)})};

                session::array_uc32 hash{};
                std::fill(hash.begin(), hash.end(), static_cast<uint8_t>(i % 256));
                c.pro_revocation_tag = hash;
            }

            convos.set(c);
        } else if (i % 3 == 1) {
            auto c = convos.get_or_construct_legacy_group(some_session_id(i));
            c.last_read = unix_timestamp(i);
            if (i % 5 == 0)
                c.unread = true;
            convos.set(c);
        } else {
            auto c = convos.get_or_construct_community(
                    "https://example.org", "room{}"_format(i), some_pubkey(i));
            c.last_read = unix_timestamp(i);
            if (i % 5 == 0)
                c.unread = true;
            convos.set(c);
        }
    }

    // (15, 30, 45, 60) == 4 have `unread` set.
    // (21, 42, 63) == 3 have pro proof.
    // (0) == 1 has both unread and pro proof.
    // (3, 6, 9, 12, 18, 24, 27) == 7 are recent enough.
    CHECK(convos.size_1to1() == 4 + 3 + 1 + 7);
    // 1, 4, 7, ..., 28 == 10 last_read's
    // 40, 55 = 2 unread flags
    CHECK(convos.size_legacy_groups() == 10 + 2);
    // 2, 5, 8, ..., 29 == 10 last_read's
    // 35, 50, 65 = 3 unread flags
    CHECK(convos.size_communities() == 10 + 3);
    // 31 (0-30) were recent enough to be kept
    // 6 more (35, 40, 45, 50, 55, 60) have `unread` set.
    // 3 more (21, 42, 63) have pro proof.
    CHECK(convos.size() == 40);

    // Now we deliberately set some values in the internals that are too old to see that they get
    // properly pruned when we push.  (This is only for testing, clients should never touch the
    // internals like this!)

    // These ones wouldn't be stored by the normal `set()` interface, but won't get pruned either:
    convos.data["1"][oxenc::from_hex(some_session_id(80))]["r"] = unix_timestamp(33);
    convos.data["1"][oxenc::from_hex(some_session_id(81))]["r"] = unix_timestamp(40);
    convos.data["1"][oxenc::from_hex(some_session_id(82))]["r"] = unix_timestamp(44);
    // These ones should get pruned as soon as we push:
    convos.data["1"][oxenc::from_hex(some_session_id(83))]["r"] = unix_timestamp(45);
    convos.data["1"][oxenc::from_hex(some_session_id(84))]["r"] = unix_timestamp(46);
    convos.data["1"][oxenc::from_hex(some_session_id(85))]["r"] = unix_timestamp(1000);

    // 6 additional 1-to-1s got added unconditionally
    CHECK(convos.size_1to1() == 21);
    int count = 0;
    for (auto it = convos.begin_1to1(); it != convos.end(); it++) {
        count++;
    }
    CHECK(count == 21);

    CHECK(convos.size() == 46);

    // Push and confirm the pruned
    auto [seqno, push_data, obs] = convos.push();

    // The push should have pruned these:
    // 63 - where pro proof is too old
    // 83, 84, 85 - where last_read is too old
    CHECK(convos.size_1to1() == 17);
    CHECK(convos.size() == 42);
}

TEST_CASE("Conversation dump/load state bug", "[config][conversations][dump-load]") {

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

    config_object* conf;
    REQUIRE(0 == convo_info_volatile_init(&conf, ed_sk.data(), NULL, 0, NULL));

    convo_info_volatile_1to1 c;
    CHECK(convo_info_volatile_get_or_construct_1to1(
            conf, &c, "050123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    c.last_read = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
    convo_info_volatile_set_1to1(conf, &c);

    // Fake push:
    config_push_data* to_push = config_push(conf);
    seqno_t seqno = to_push->seqno;
    REQUIRE(to_push->n_configs == 1);
    free(to_push);
    CHECK(seqno == 1);

    const char* tmphash;  // test suite cheat: &(tmphash = "asdf") to fake a length-1 array.

    config_confirm_pushed(conf, seqno, &(tmphash = "somehash"), 1);
    CHECK(config_needs_dump(conf));

    // Dump:
    unsigned char* dump;
    size_t dumplen;
    config_dump(conf, &dump, &dumplen);

    // Load the dump:
    config_object* conf2;
    REQUIRE(0 == convo_info_volatile_init(&conf2, ed_sk.data(), dump, dumplen, NULL));

    free(dump);

    // Change the original again, then push it for conf2:
    CHECK(convo_info_volatile_get_or_construct_1to1(
            conf, &c, "051111111111111111111111111111111111111111111111111111111111111111"));
    c.last_read = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
    convo_info_volatile_set_1to1(conf, &c);

    to_push = config_push(conf);
    CHECK(to_push->seqno == 2);
    REQUIRE(to_push->n_configs == 1);
    config_confirm_pushed(conf, to_push->seqno, &(tmphash = "hash5235"), 1);

    // But *before* we load the push make a dirtying change to conf2 that we *don't* push (so that
    // we'll be merging into a dirty-state config):
    CHECK(convo_info_volatile_get_or_construct_1to1(
            conf2, &c, "052222111111111111111111111111111111111111111111111111111111111111"));
    c.last_read = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
    convo_info_volatile_set_1to1(conf2, &c);

    // And now, *before* we push the dirty config, also merge the incoming push from `conf`:
    const char* merge_hash[1];
    const unsigned char* merge_data[1];
    size_t merge_size[1];
    merge_hash[0] = "hash5235";
    REQUIRE(to_push->n_configs == 1);
    merge_data[0] = to_push->config[0];
    merge_size[0] = to_push->config_lens[0];

    config_string_list* accepted = config_merge(conf2, merge_hash, merge_data, merge_size, 1);
    REQUIRE(accepted->len == 1);
    CHECK(accepted->value[0] == "hash5235"sv);
    free(accepted);
    free(to_push);

    CHECK(config_needs_push(conf2));

    convo_info_volatile_1to1 c1;
    REQUIRE(convo_info_volatile_get_or_construct_1to1(
            conf2, &c1, "051111111111111111111111111111111111111111111111111111111111111111"));
    c1.last_read += 10;
    // Prior to the commit that added this test case (and fix), this call would fail with:
    //     Internal error: unexpected dirty but non-mutable ConfigMessage
    // because of the above dirty->merge->dirty (without an intermediate push) pattern.
    REQUIRE_NOTHROW(convo_info_volatile_set_1to1(conf2, &c1));

    CHECK(config_needs_push(conf2));
    to_push = config_push(conf2);
    CHECK(to_push->seqno == 3);
    REQUIRE(to_push->n_configs == 1);
    config_confirm_pushed(conf2, to_push->seqno, &(tmphash = "hashz"), 1);
    CHECK_FALSE(config_needs_push(conf2));

    config_dump(conf2, &dump, &dumplen);
    free(dump);
    CHECK_FALSE(config_needs_dump(conf2));
}

TEST_CASE("Conversation pro data", "[config][conversations][pro]") {

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

    config_object* conf;
    REQUIRE(0 == convo_info_volatile_init(&conf, ed_sk.data(), NULL, 0, NULL));

    convo_info_volatile_1to1 c;
    CHECK(convo_info_volatile_get_or_construct_1to1(
            conf, &c, "051111111111111111111111111111111111111111111111111111111111111111"));
    c.last_read = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
    c.pro_expiry_ts = 10000;

    session::array_uc32 hash{};
    std::fill(hash.begin(), hash.end(), static_cast<uint8_t>(3));
    std::memcpy(c.pro_revocation_tag.data, hash.data(), hash.size());
    c.has_pro_revocation_tag = true;
    convo_info_volatile_set_1to1(conf, &c);

    // Fake push:
    config_push_data* to_push = config_push(conf);
    seqno_t seqno = to_push->seqno;
    REQUIRE(to_push->n_configs == 1);
    free(to_push);
    CHECK(seqno == 1);

    const char* tmphash;  // test suite cheat: &(tmphash = "asdf") to fake a length-1 array.

    config_confirm_pushed(conf, seqno, &(tmphash = "somehash"), 1);
    CHECK(config_needs_dump(conf));

    // Dump:
    unsigned char* dump;
    size_t dumplen;
    config_dump(conf, &dump, &dumplen);

    // Load the dump:
    config_object* conf2;
    REQUIRE(0 == convo_info_volatile_init(&conf2, ed_sk.data(), dump, dumplen, NULL));

    free(dump);

    convo_info_volatile_1to1 c2;
    CHECK(convo_info_volatile_get_or_construct_1to1(
            conf2, &c2, "051111111111111111111111111111111111111111111111111111111111111111"));

    CHECK(c2.pro_expiry_ts == c.pro_expiry_ts);
    CHECK(c.has_pro_revocation_tag);
    CHECK(c2.has_pro_revocation_tag);
    CHECK(oxenc::to_hex(c2.pro_revocation_tag.data) == oxenc::to_hex(c.pro_revocation_tag.data));
}