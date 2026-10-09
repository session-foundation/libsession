#include <catch2/catch_test_macros.hpp>
#include <session/network/key_types.hpp>
#include <session/network/service_node.hpp>
#include <session/network/session_network_types.hpp>
#include <session/network/swarm.hpp>
#include <tuple>

#include "utils.hpp"

using namespace session;
using namespace session::network;
using namespace session::network::swarm;

swarm_id_t get_swarm_id(
        std::string swarm_pubkey_hex,
        std::vector<std::pair<swarm_id_t, std::vector<service_node>>> swarms) {
    if (swarm_pubkey_hex.size() == 66)
        swarm_pubkey_hex = swarm_pubkey_hex.substr(2);

    auto pk = x25519_pubkey::from_hex(swarm_pubkey_hex);
    return get_swarm(pk, swarms).first;
}

TEST_CASE("Swarm", "[network][swarm][pubkey_to_swarm_space]") {
    x25519_pubkey pk;

    pk = x25519_pubkey::from_hex(
            "3506f4a71324b7dd114eddbf4e311f39dde243e1f2cb97c40db1961f70ebaae8");
    CHECK(pubkey_to_swarm_space(pk) == 17589930838143112648ULL);
    pk = x25519_pubkey::from_hex(
            "cf27da303a50ac8c4b2d43d27259505c9bcd73fc21cf2a57902c3d050730b604");
    CHECK(pubkey_to_swarm_space(pk) == 10370619079776428163ULL);
    pk = x25519_pubkey::from_hex(
            "d3511706b8b34f6e8411bf07bd22ba6b2435ca56846fbccf6eb1e166a6cd15cc");
    CHECK(pubkey_to_swarm_space(pk) == 2144983569669512198ULL);
    pk = x25519_pubkey::from_hex(
            "0f06693428fca9102a451e3f28d9cc743d8ea60a89ab6aa69eb119470c11cbd3");
    CHECK(pubkey_to_swarm_space(pk) == 9690840703409570833ULL);
    pk = x25519_pubkey::from_hex(
            "ffba630924aa1224bb930dde21c0d11bf004608f2812217f8ac812d6c7e3ad48");
    CHECK(pubkey_to_swarm_space(pk) == 4532060000165252872ULL);
    pk = x25519_pubkey::from_hex(
            "eeeeeeeeeeeeeeee777777777777777711111111111111118888888888888888");
    CHECK(pubkey_to_swarm_space(pk) == 0);
    pk = x25519_pubkey::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(pubkey_to_swarm_space(pk) == 0);
    pk = x25519_pubkey::from_hex(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe");
    CHECK(pubkey_to_swarm_space(pk) == 1);
    pk = x25519_pubkey::from_hex(
            "ffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffff");
    CHECK(pubkey_to_swarm_space(pk) == 1ULL << 63);
    pk = x25519_pubkey::from_hex(
            "000000000000000000000000000000000000000000000000ffffffffffffffff");
    CHECK(pubkey_to_swarm_space(pk) == (uint64_t)-1);
    pk = x25519_pubkey::from_hex(
            "0000000000000000000000000000000000000000000000000123456789abcdef");
    CHECK(pubkey_to_swarm_space(pk) == 0x0123456789abcdefULL);
}

TEST_CASE("Swarm", "[network][swarm][get_swarm]") {
    std::vector<std::pair<swarm_id_t, std::vector<service_node>>> swarms = {
            {100, {}}, {200, {}}, {300, {}}, {399, {}}, {498, {}}, {596, {}}, {694, {}}};

    // Exact matches:
    // 0x64 = 100, 0xc8 = 200, 0x1f2 = 498
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000064", swarms) ==
          100);
    CHECK(get_swarm_id(
                  "0500000000000000000000000000000000000000000000000000000000000000c8", swarms) ==
          200);
    CHECK(get_swarm_id(
                  "0500000000000000000000000000000000000000000000000000000000000001f2", swarms) ==
          498);

    // Nearest
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000000", swarms) ==
          100);
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000001", swarms) ==
          100);

    // Nearest, with wraparound
    // 0x8000... is closest to the top value
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000008000000000000000", swarms) ==
          694);

    // 0xa000... is closest (via wraparound) to the smallest
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000a000000000000000", swarms) ==
          100);

    // This is the invalid swarm id for swarms, but should still work for a client
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000ffffffffffffffff", swarms) ==
          100);
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000fffffffffffffffe", swarms) ==
          100);

    // Midpoint tests; we prefer the lower value when exactly in the middle between two swarms.
    // 0x96 = 150
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000095", swarms) ==
          100);
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000096", swarms) ==
          100);
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000097", swarms) ==
          200);

    // 0xfa = 250
    CHECK(get_swarm_id(
                  "0500000000000000000000000000000000000000000000000000000000000000f9", swarms) ==
          200);
    CHECK(get_swarm_id(
                  "0500000000000000000000000000000000000000000000000000000000000000fa", swarms) ==
          200);
    CHECK(get_swarm_id(
                  "0500000000000000000000000000000000000000000000000000000000000000fb", swarms) ==
          300);

    // 0x15d = 349
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000000000000000015d", swarms) ==
          300);
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000000000000000015e", swarms) ==
          399);

    // 0x1c0 = 448
    CHECK(get_swarm_id(
                  "0500000000000000000000000000000000000000000000000000000000000001c0", swarms) ==
          399);
    CHECK(get_swarm_id(
                  "0500000000000000000000000000000000000000000000000000000000000001c1", swarms) ==
          498);

    // 0x223 = 547
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000222", swarms) ==
          498);
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000223", swarms) ==
          498);
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000224", swarms) ==
          596);

    // 0x285 = 645
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000285", swarms) ==
          596);
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000286", swarms) ==
          694);

    // 0x800....d is the midpoint between 694 and 100 (the long way).  We always round "down" (which
    // in this case, means wrapping to the largest swarm).
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000800000000000018c", swarms) ==
          694);
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000800000000000018d", swarms) ==
          694);
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000800000000000018e", swarms) ==
          100);

    // With a swarm at -20 the midpoint is now 40 (=0x28).  When our value is the *low* value we
    // prefer the *last* swarm in the case of a tie (while consistent with the general case of
    // preferring the left edge, it means we're inconsistent with the other wraparound case, above.
    // *sigh*).
    swarms.push_back({(uint64_t)-20, {}});
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000027", swarms) ==
          swarms.back().first);
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000028", swarms) ==
          swarms.back().first);
    CHECK(get_swarm_id(
                  "050000000000000000000000000000000000000000000000000000000000000029", swarms) ==
          swarms.front().first);

    // The code used to have a broken edge case if we have a swarm at zero and a client at max-u64
    // because of an overflow in how the distance is calculated (the first swarm will be calculated
    // as max-u64 away, rather than 1 away), and so the id always maps to the highest swarm (even
    // though 0xfff...fe maps to the lowest swarm; the first check here, then, would fail.
    swarms.insert(swarms.begin(), {0, {}});
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000ffffffffffffffff", swarms) ==
          0);
    CHECK(get_swarm_id(
                  "05000000000000000000000000000000000000000000000000fffffffffffffffe", swarms) ==
          0);
}

namespace {
using json = nlohmann::json;

x25519_pubkey account(char c) {
    return x25519_pubkey::from_hex(std::string(64, c));
}

std::vector<ed25519_pubkey> nodes(std::string_view chars) {
    std::vector<ed25519_pubkey> keys;
    for (char c : chars)
        keys.push_back(ed25519_pubkey::from_hex(std::string(64, c)));
    return keys;
}

json rejection(std::optional<std::string> echoed, std::string_view node_chars) {
    auto snodes = json::array();
    for (char c : node_chars)
        snodes.push_back({{"pubkey_ed25519", std::string(64, c)}, {"ip", "10.0.0.1"}});

    json body = {{"snodes", std::move(snodes)}, {"swarm", "abc"}};
    if (echoed)
        body["pubkey"] = *echoed;
    return body;
}

json batch(std::vector<std::pair<int, json>> results) {
    auto list = json::array();
    for (auto& [code, body] : results)
        list.push_back({{"code", code}, {"body", std::move(body)}});
    return {{"results", std::move(list)}};
}

response::swarm_rejections rejections(
        const json& body,
        int16_t status_code,
        std::vector<std::optional<x25519_pubkey>> accounts = {}) {
    return response::find_swarm_rejections(&body, status_code, accounts);
}

const std::string A = "05" + std::string(64, 'a');
const std::string B = "03" + std::string(64, 'b');
}  // namespace

TEST_CASE("Swarm", "[network][swarm][batch_error]") {
    CHECK(response::find_uniform_batch_error(batch({{421, {}}, {421, {}}}).dump()) == 421);
    CHECK_FALSE(response::find_uniform_batch_error(batch({{421, {}}, {406, {}}}).dump()));
    CHECK_FALSE(response::find_uniform_batch_error(batch({{421, {}}, {200, {}}}).dump()));
    CHECK_FALSE(response::find_uniform_batch_error(batch({}).dump()));
    CHECK_FALSE(response::find_uniform_batch_error(rejection(A, "12").dump()));
    CHECK_FALSE(response::find_uniform_batch_error("not json"));
}

TEST_CASE("Swarm", "[network][swarm][rejections]") {
    SECTION("A plain 421 is attributed to the request's account") {
        auto r = rejections(rejection(A, "123"), 421, {account('a')});
        CHECK_FALSE(r.unattributed);
        REQUIRE(r.accounts.size() == 1);
        CHECK(r.accounts.at(account('a')) == nodes("123"));
    }

    SECTION("An account echoed in testnet form, without a prefix, still matches") {
        auto r = rejections(rejection(std::string(64, 'a'), "12"), 421, {account('a')});
        REQUIRE(r.accounts.count(account('a')));
        CHECK(r.accounts.at(account('a')) == nodes("12"));
    }

    SECTION("A 421 needn't name its account") {
        auto r = rejections(
                batch({{421, rejection(std::nullopt, "12")}, {421, rejection(std::nullopt, "34")}}),
                421,
                {account('a'), account('b')});
        CHECK_FALSE(r.unattributed);
        REQUIRE(r.accounts.size() == 2);
        CHECK(r.accounts.at(account('a')) == nodes("12"));
        CHECK(r.accounts.at(account('b')) == nodes("34"));
    }

    SECTION("Nothing is found in a response that isn't a 421") {
        auto r = rejections(json{{"t", 1}}, 200, {account('a')});
        CHECK(r.accounts.empty());
        CHECK_FALSE(r.unattributed);
    }

    SECTION("A batch can reject some accounts and answer others") {
        auto r = rejections(
                batch({{421, rejection(A, "12")},
                       {200, json{{"messages", json::array()}}},
                       {421, rejection(B, "34")}}),
                200,
                {account('a'), account('c'), account('b')});
        CHECK_FALSE(r.unattributed);
        REQUIRE(r.accounts.size() == 2);
        CHECK(r.accounts.at(account('a')) == nodes("12"));
        CHECK(r.accounts.at(account('b')) == nodes("34"));
    }

    SECTION("Several rejections of one account are one redirect") {
        auto r = rejections(
                batch({{421, rejection(A, "12")}, {421, rejection(A, "12")}}), 421, {account('a')});
        REQUIRE(r.accounts.size() == 1);
        CHECK(r.accounts.at(account('a')) == nodes("12"));
    }

    SECTION("A single account applies to every sub-request") {
        auto r = rejections(
                batch({{421, rejection(std::nullopt, "12")}, {421, rejection(std::nullopt, "12")}}),
                421,
                {account('a')});
        REQUIRE(r.accounts.size() == 1);
        CHECK(r.accounts.at(account('a')) == nodes("12"));
    }

    SECTION("A sequence that stopped early is still attributed by position") {
        auto r = rejections(
                batch({{200, json::object()}, {421, rejection(std::nullopt, "34")}}),
                200,
                {account('a'), account('b'), account('c')});
        REQUIRE(r.accounts.size() == 1);
        CHECK(r.accounts.at(account('b')) == nodes("34"));
    }

    // The account a 421 names is the responding node's word; taking it would let any node redirect
    // any account it likes, not just those it was asked about
    SECTION("The account a 421 names is never trusted in place of the request's") {
        auto r = rejections(rejection(A, "12"), 421, {account('b')});
        CHECK(r.accounts.empty());
        CHECK(r.unattributed);

        r = rejections(
                batch({{421, rejection("05" + std::string(64, 'c'), "12")},
                       {421, rejection(B, "34")}}),
                421,
                {account('a'), account('b')});
        CHECK(r.unattributed);
        REQUIRE(r.accounts.size() == 1);
        CHECK(r.accounts.at(account('b')) == nodes("34"));

        CHECK(rejections(rejection(A, "12"), 421).accounts.empty());
    }

    SECTION("A sub-request with no account leaves its 421 unattributed") {
        auto r = rejections(
                batch({{200, json::object()}, {421, rejection(std::nullopt, "12")}}),
                200,
                {account('a'), std::nullopt});
        CHECK(r.accounts.empty());
        CHECK(r.unattributed);
    }

    SECTION("A 421 whose body isn't JSON has no redirect") {
        std::vector<std::optional<x25519_pubkey>> accounts{account('a')};
        auto r = response::find_swarm_rejections(nullptr, 421, accounts);
        REQUIRE(r.accounts.size() == 1);
        CHECK(r.accounts.at(account('a')).empty());
        CHECK(response::find_swarm_rejections(nullptr, 200, accounts).accounts.empty());
    }
}

TEST_CASE("Swarm", "[network][swarm][batch_request_accounts]") {
    SECTION("A pregenerated batch body gives each sub-request's account") {
        auto body = json{{"requests",
                          {{{"method", "retrieve"}, {"params", {{"pubkey", A}}}},
                           {{"method", "info"}, {"params", json::object()}},
                           {{"method", "retrieve"}, {"params", {{"pubkey", B}}}}}}}
                            .dump();
        auto bytes = std::span{reinterpret_cast<const unsigned char*>(body.data()), body.size()};

        auto accounts = batch_request_accounts("batch", bytes);
        REQUIRE(accounts);
        CHECK(*accounts ==
              std::vector<std::optional<x25519_pubkey>>{account('a'), std::nullopt, account('b')});
        CHECK(batch_request_accounts("sequence", bytes) == accounts);
        CHECK_FALSE(batch_request_accounts("retrieve", bytes));

        // A sub-request naming no account takes the one the caller gave for the whole request,
        // while those that name their own keep it
        CHECK(batch_request_accounts("batch", bytes, account('c')) ==
              std::vector<std::optional<x25519_pubkey>>{account('a'), account('c'), account('b')});

        std::string_view junk = "not json";
        CHECK_FALSE(batch_request_accounts(
                "batch", {reinterpret_cast<const unsigned char*>(junk.data()), junk.size()}));
    }
}
