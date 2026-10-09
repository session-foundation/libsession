// Round-trip determinism of config storage.
//
// Config recovery (re-storing an unchanged config to refresh its TTL, rather than pushing a new
// revision) depends on two properties that were previously only established by reading the code:
//
//  1. Loading a config from its stored dump and re-pushing it reproduces the message that was
//     originally received from the swarm *byte for byte*.  The storage server hashes the
//     ciphertext, so byte-equality is what makes a re-store an idempotent TTL refresh instead of a
//     second message.
//  2. `push()` on a clean config does not bump the seqno, so a re-store is not a new revision and
//     provokes no merge.
//
// The tests below exercise the full round trip (push -> receive -> dump -> reload -> push), not
// just "encrypt the same bytes twice": recovery happens after a restart, so the reload path is the
// part that has to be reproducible — including a signature the reloading device cannot re-derive.

#include <oxenc/endian.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <random>
#include <session/config/contacts.hpp>
#include <session/config/encrypt.hpp>
#include <session/config/groups/info.hpp>
#include <session/config/namespaces.hpp>
#include <session/config/protos.hpp>
#include <session/config/user_profile.hpp>
#include <session/hash.hpp>
#include <session/util.hpp>

#include "utils.hpp"

using namespace session;
using namespace session::config;

namespace {

// The user's ed25519 seed; also the config encryption key for user configs.
const auto user_seed = "0123456789abcdef0123456789abcdef00000000000000000000000000000000"_hexbytes;

// Group identity keypair (the admin holds the secret key; members hold only the pubkey).
const auto group_seed = "0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210"_hexbytes;

// The group's symmetric config encryption key (normally handed out by groups::Keys).
const auto group_enc_key =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_hexbytes;

struct GroupKeys {
    std::array<unsigned char, 32> pk;
    std::array<unsigned char, 64> sk;
};

GroupKeys group_keys() {
    GroupKeys k{};
    crypto_sign_ed25519_seed_keypair(k.pk.data(), k.sk.data(), group_seed.data());
    return k;
}

// A single incoming message as `merge()` wants it.
std::vector<std::pair<std::string, std::vector<unsigned char>>> incoming(
        std::string hash, std::vector<unsigned char> data) {
    std::vector<std::pair<std::string, std::vector<unsigned char>>> configs;
    configs.emplace_back(std::move(hash), std::move(data));
    return configs;
}

// Strip the null prefix padding that `pad_message` adds, so the result is the bencoded config.
std::vector<unsigned char> unpad(std::vector<unsigned char> plain) {
    auto it = std::find_if(plain.begin(), plain.end(), [](unsigned char c) { return c != 0; });
    plain.erase(plain.begin(), it);
    return plain;
}

}  // namespace

TEST_CASE("config re-store is byte-identical: user config", "[config][determinism][user]") {

    // === The device that creates the config pushes it to the swarm ===

    UserProfile a{to_span(user_seed), std::nullopt};
    a.set_name("Determinism");
    a.set_profile_pic(
            "http://example.com/12345",
            "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"_hexbytes);

    auto [seqno, pushes, obs] = a.push();
    REQUIRE(pushes.size() == 1);
    CHECK(seqno == 1);
    // `received` stands in for the message as it lands on (and is fetched back from) the swarm.
    const auto received = pushes[0];
    a.confirm_pushed(seqno, {"fakehash1"});

    // User configs really are protobuf-wrapped: the stored bytes are not the config ciphertext,
    // they unwrap *to* it.  This is the layer most likely to smuggle in a timestamp.
    CHECK_THROWS(decrypt(received, user_seed, "UserProfile"));
    std::vector<unsigned char> unwrapped;
    REQUIRE_NOTHROW(unwrapped = protos::unwrap_config(user_seed, received, Namespace::UserProfile));
    CHECK_NOTHROW(decrypt(unwrapped, user_seed, "UserProfile"));

    SECTION("the pushing device reproduces it after a dump/reload") {
        auto dump = a.dump();
        UserProfile reloaded{to_span(user_seed), to_span(dump)};

        CHECK_FALSE(reloaded.needs_push());
        auto [s, p, o] = reloaded.push();
        CHECK(s == seqno);
        REQUIRE(p.size() == 1);
        CHECK(to_hex(p[0]) == to_hex(received));
        CHECK(o.empty());
    }

    SECTION("a receiving device reproduces it after a dump/reload") {
        UserProfile b{to_span(user_seed), std::nullopt};
        CHECK(b.merge(incoming("fakehash1", received)) == std::unordered_set{{"fakehash1"s}});
        CHECK_FALSE(b.needs_push());
        CHECK(b.get_name() == "Determinism");

        auto dump = b.dump();
        UserProfile reloaded{to_span(user_seed), to_span(dump)};

        CHECK_FALSE(reloaded.needs_push());
        auto [s, p, o] = reloaded.push();
        CHECK(s == seqno);
        REQUIRE(p.size() == 1);
        CHECK(to_hex(p[0]) == to_hex(received));
        CHECK(o.empty());
    }
}

TEST_CASE("config re-store is byte-identical: group config", "[config][determinism][groups]") {

    auto gk = group_keys();

    groups::Info admin{gk.pk, to_span(gk.sk), std::nullopt};
    admin.add_key(group_enc_key, false);
    admin.set_name("Determinism Group");
    admin.set_expiry_timer(1h);
    admin.set_created(1682529839);

    auto [seqno, pushes, obs] = admin.push();
    REQUIRE(pushes.size() == 1);
    CHECK(seqno == 1);
    const auto received = pushes[0];
    admin.confirm_pushed(seqno, {"fakehash1"});

    // Group configs go up raw — no protobuf wrapper — so the stored bytes decrypt straight to a
    // bencoded config dict with the group's config key.
    std::vector<unsigned char> plain;
    REQUIRE_NOTHROW(plain = unpad(decrypt(received, group_enc_key, "groups::Info")));
    REQUIRE_FALSE(plain.empty());
    CHECK(plain.front() == 'd');

    SECTION("the pushing admin reproduces it after a dump/reload") {
        auto dump = admin.dump();
        groups::Info reloaded{gk.pk, to_span(gk.sk), to_span(dump)};
        reloaded.add_key(group_enc_key, false);

        CHECK_FALSE(reloaded.needs_push());
        auto [s, p, o] = reloaded.push();
        CHECK(s == seqno);
        REQUIRE(p.size() == 1);
        CHECK(to_hex(p[0]) == to_hex(received));
        CHECK(o.empty());
    }

    SECTION("a receiving admin reproduces it after a dump/reload") {
        groups::Info admin2{gk.pk, to_span(gk.sk), std::nullopt};
        admin2.add_key(group_enc_key, false);
        CHECK(admin2.merge(incoming("fakehash1", received)) == std::unordered_set{{"fakehash1"s}});
        CHECK_FALSE(admin2.needs_push());

        auto dump = admin2.dump();
        groups::Info reloaded{gk.pk, to_span(gk.sk), to_span(dump)};
        reloaded.add_key(group_enc_key, false);

        auto [s, p, o] = reloaded.push();
        CHECK(s == seqno);
        REQUIRE(p.size() == 1);
        CHECK(to_hex(p[0]) == to_hex(received));
        CHECK(o.empty());
    }
}

TEST_CASE(
        "config re-store is byte-identical: multipart config", "[config][determinism][multipart]") {

    // A config too big for one message is split into parts (and, note, skips protobuf wrapping
    // entirely — see the `else` branch in ConfigBase::push()).  Recovery has to re-store every
    // part, so each one has to come back byte-identical after a dump/reload, including the
    // reassembly state the dump carries in its "*" key.
    Contacts contacts{to_span(user_seed), std::nullopt};

    for (size_t i = 0; i < 3000; i++) {
        // Random (i.e. poorly compressible) session ids, so the config gets big enough to split.
        std::mt19937_64 rng{i};
        std::array<unsigned char, 33> random_sessionid;
        random_sessionid[0] = 0x05;
        for (int j = 1; j < 33; j += 8)
            oxenc::write_host_as_little(rng(), random_sessionid.data() + j);

        auto c = contacts.get_or_construct(oxenc::to_hex(random_sessionid));
        c.nickname = "My friend {}"_format(i);
        c.approved = true;
        contacts.set(c);
    }

    auto [seqno, pushes, obs] = contacts.push();
    REQUIRE(pushes.size() > 1);
    const auto received = pushes;

    std::unordered_set<std::string> hashes;
    std::vector<std::pair<std::string, std::vector<unsigned char>>> configs;
    for (size_t i = 0; i < received.size(); i++) {
        auto hash = "fakehash_part{}"_format(i);
        hashes.insert(hash);
        configs.emplace_back(std::move(hash), received[i]);
    }
    contacts.confirm_pushed(seqno, hashes);

    SECTION("the pushing device reproduces every part after a dump/reload") {
        auto dump = contacts.dump();
        Contacts reloaded{to_span(user_seed), to_span(dump)};

        CHECK_FALSE(reloaded.needs_push());
        auto [s, p, o] = reloaded.push();
        CHECK(s == seqno);
        REQUIRE(p.size() == received.size());
        for (size_t i = 0; i < p.size(); i++)
            CHECK(to_hex(p[i]) == to_hex(received[i]));
        CHECK(o.empty());
    }

    SECTION("a receiving device reproduces every part after a dump/reload") {
        Contacts b{to_span(user_seed), std::nullopt};
        CHECK(b.merge(configs) == hashes);
        CHECK_FALSE(b.needs_push());

        auto dump = b.dump();
        Contacts reloaded{to_span(user_seed), to_span(dump)};

        CHECK_FALSE(reloaded.needs_push());
        auto [s, p, o] = reloaded.push();
        CHECK(s == seqno);
        REQUIRE(p.size() == received.size());
        for (size_t i = 0; i < p.size(); i++)
            CHECK(to_hex(p[i]) == to_hex(received[i]));
        CHECK(o.empty());
    }
}

TEST_CASE(
        "config re-store is byte-identical: dump with a retained signature",
        "[config][determinism][groups][signature]") {

    // The load-bearing case for group recovery: a non-admin member has no signing key, so it can
    // only reproduce the admin's bytes if the signature survives dump -> reload (make_dump()
    // serialises with signing disabled, but writes the stored signature; the reload trusts it).
    auto gk = group_keys();

    groups::Info admin{gk.pk, to_span(gk.sk), std::nullopt};
    admin.add_key(group_enc_key, false);
    admin.set_name("Signed Group");
    admin.set_created(1682529839);
    auto [seqno, pushes, obs] = admin.push();
    REQUIRE(pushes.size() == 1);
    const auto received = pushes[0];
    admin.confirm_pushed(seqno, {"fakehash1"});

    // The message is signed: the bencoded config ends with a "~" key holding the 64-byte
    // signature, i.e. `1:~64:<64 bytes>` followed by the dict's closing `e`.
    auto plain = unpad(decrypt(received, group_enc_key, "groups::Info"));
    REQUIRE(plain.size() > 71);
    CHECK(printable(std::span{plain}.subspan(plain.size() - 71, 6)) == "1:~64:");
    CHECK(plain.back() == 'e');

    groups::Info member{gk.pk, std::nullopt, std::nullopt};
    member.add_key(group_enc_key, false);
    CHECK(member.merge(incoming("fakehash1", received)) == std::unordered_set{{"fakehash1"s}});
    REQUIRE(member.is_readonly());
    CHECK(member.get_name() == "Signed Group");

    auto dump = member.dump();
    groups::Info reloaded{gk.pk, std::nullopt, to_span(dump)};
    reloaded.add_key(group_enc_key, false);
    REQUIRE(reloaded.is_readonly());

    CHECK_FALSE(reloaded.needs_push());
    auto [s, p, o] = reloaded.push();
    CHECK(s == seqno);
    REQUIRE(p.size() == 1);
    CHECK(to_hex(p[0]) == to_hex(received));
    CHECK(o.empty());

    // ...and the re-store is still a validly signed config, not merely the right length: another
    // member verifies the signature against the group pubkey when it merges, and would throw
    // (dropping the message) if it no longer matched.
    groups::Info member2{gk.pk, std::nullopt, std::nullopt};
    member2.add_key(group_enc_key, false);
    CHECK(member2.merge(incoming("fakehash1", p[0])) == std::unordered_set{{"fakehash1"s}});
    CHECK(member2.get_name() == "Signed Group");
}

TEST_CASE("push on a clean config does not bump the seqno", "[config][determinism][seqno]") {

    // Recovery must never dirty the config: dirtying bumps the seqno and turns an idempotent
    // re-store into a new revision plus a merge.

    SECTION("user config") {
        UserProfile a{to_span(user_seed), std::nullopt};
        a.set_name("Determinism");
        auto [seqno, pushes, obs] = a.push();
        a.confirm_pushed(seqno, {"fakehash1"});
        REQUIRE(a.is_clean());
        REQUIRE_FALSE(a.needs_push());

        for (int i = 0; i < 3; i++) {
            auto [s, p, o] = a.push();
            CHECK(s == seqno);
            REQUIRE(p.size() == 1);
            CHECK(to_hex(p[0]) == to_hex(pushes[0]));
            CHECK(o.empty());
            CHECK(a.is_clean());
            CHECK_FALSE(a.is_dirty());
            CHECK_FALSE(a.needs_push());
        }
    }

    SECTION("group config, admin") {
        auto gk = group_keys();
        groups::Info admin{gk.pk, to_span(gk.sk), std::nullopt};
        admin.add_key(group_enc_key, false);
        admin.set_name("Determinism Group");
        auto [seqno, pushes, obs] = admin.push();
        admin.confirm_pushed(seqno, {"fakehash1"});
        REQUIRE(admin.is_clean());
        REQUIRE_FALSE(admin.needs_push());

        for (int i = 0; i < 3; i++) {
            auto [s, p, o] = admin.push();
            CHECK(s == seqno);
            REQUIRE(p.size() == 1);
            CHECK(to_hex(p[0]) == to_hex(pushes[0]));
            CHECK(o.empty());
            CHECK(admin.is_clean());
            CHECK_FALSE(admin.is_dirty());
            CHECK_FALSE(admin.needs_push());
        }
    }

    SECTION("group config, read-only member") {
        auto gk = group_keys();
        groups::Info admin{gk.pk, to_span(gk.sk), std::nullopt};
        admin.add_key(group_enc_key, false);
        admin.set_name("Determinism Group");
        auto [seqno, pushes, obs] = admin.push();

        groups::Info member{gk.pk, std::nullopt, std::nullopt};
        member.add_key(group_enc_key, false);
        REQUIRE(member.merge(incoming("fakehash1", pushes[0])) ==
                std::unordered_set{{"fakehash1"s}});
        REQUIRE(member.is_readonly());
        REQUIRE_FALSE(member.needs_push());

        for (int i = 0; i < 3; i++) {
            auto [s, p, o] = member.push();
            CHECK(s == seqno);
            REQUIRE(p.size() == 1);
            CHECK(to_hex(p[0]) == to_hex(pushes[0]));
            CHECK(o.empty());
            CHECK_FALSE(member.is_dirty());
            CHECK_FALSE(member.needs_push());
        }
    }
}

TEST_CASE(
        "push on a clean config still consumes the obsolete-hash list",
        "[config][determinism][seqno][obsolete]") {

    // A re-store leaves the seqno and the bytes alone, but it is NOT side-effect free:
    // `ConfigBase::push()` ends by clearing `_old_hashes` unconditionally, outside the
    // `if (is_dirty())` guard above it.  So a recovery push hands back the superseded hashes and
    // forgets them.  A caller that treats a recovery push as a no-op and discards its
    // obsolete-hash return will leak those messages on the swarm: nothing reports them again, and
    // the next dump no longer records them.
    UserProfile a{to_span(user_seed), std::nullopt};
    a.set_name("First");
    auto [s1, p1, o1] = a.push();
    a.confirm_pushed(s1, {"fakehash1"});
    a.set_name("Second");
    auto [s2, p2, o2] = a.push();
    a.confirm_pushed(s2, {"fakehash2"});

    // A device that fetches both messages at once: the seqno-2 message carries the seqno-1 diff,
    // so it supersedes it and fakehash1 becomes obsolete.
    UserProfile b{to_span(user_seed), std::nullopt};
    std::vector<std::pair<std::string, std::vector<unsigned char>>> both;
    both.emplace_back("fakehash1", p1[0]);
    both.emplace_back("fakehash2", p2[0]);
    CHECK(b.merge(both) == std::unordered_set{{"fakehash1"s, "fakehash2"s}});
    REQUIRE(b.is_clean());
    REQUIRE_FALSE(b.needs_push());

    // The re-store itself is byte-identical and does not move the seqno, as everywhere above...
    auto [s3, p3, o3] = b.push();
    CHECK(s3 == s2);
    REQUIRE(p3.size() == 1);
    CHECK(to_hex(p3[0]) == to_hex(p2[0]));

    // ...but it also hands back the obsolete hash and clears it.
    CHECK(o3 == std::vector{"fakehash1"s});

    auto [s4, p4, o4] = b.push();
    CHECK(s4 == s2);
    REQUIRE(p4.size() == 1);
    CHECK(to_hex(p4[0]) == to_hex(p2[0]));
    CHECK(o4.empty());  // consumed by the previous push, not re-reported
}

TEST_CASE(
        "a read-only member re-stores but is never handed the obsolete hashes",
        "[config][determinism][groups][obsolete]") {

    // The hand-back and the clear are gated differently (at the end of `ConfigBase::push()`):
    //
    //     if (!is_readonly())
    //         for (auto& old : _old_hashes)
    //             obs.push_back(std::move(old));   // <-- read-only: skipped
    //     _old_hashes.clear();                     // <-- read-only: still happens
    //
    // So a read-only member — the actor that *can* re-store (see the retained-signature case) —
    // never receives the superseded hashes at all.  That is coherent rather than broken: a
    // member's subaccount carries Write but not Delete, so it could not prune them anyway.  But
    // it means an EMPTY obsolete list is the *expected* result on the member path, not evidence
    // that recovery failed, and superseded messages persist until an admin next pushes.
    auto gk = group_keys();

    groups::Info admin{gk.pk, to_span(gk.sk), std::nullopt};
    admin.add_key(group_enc_key, false);
    admin.set_name("First");
    auto [s1, p1, o1] = admin.push();
    admin.confirm_pushed(s1, {"fakehash1"});
    admin.set_name("Second");
    auto [s2, p2, o2] = admin.push();
    admin.confirm_pushed(s2, {"fakehash2"});

    std::vector<std::pair<std::string, std::vector<unsigned char>>> both;
    both.emplace_back("fakehash1", p1[0]);
    both.emplace_back("fakehash2", p2[0]);

    SECTION("an admin that merged both is handed fakehash1") {
        groups::Info admin2{gk.pk, to_span(gk.sk), std::nullopt};
        admin2.add_key(group_enc_key, false);
        REQUIRE(admin2.merge(both) == std::unordered_set{{"fakehash1"s, "fakehash2"s}});
        REQUIRE_FALSE(admin2.is_readonly());

        auto [s, p, o] = admin2.push();
        CHECK(s == s2);
        REQUIRE(p.size() == 1);
        CHECK(to_hex(p[0]) == to_hex(p2[0]));
        CHECK(o == std::vector{"fakehash1"s});
    }

    SECTION("a read-only member that merged both is handed nothing") {
        groups::Info member{gk.pk, std::nullopt, std::nullopt};
        member.add_key(group_enc_key, false);
        REQUIRE(member.merge(both) == std::unordered_set{{"fakehash1"s, "fakehash2"s}});
        REQUIRE(member.is_readonly());

        // The re-store still works — byte-identical, same seqno...
        auto [s, p, o] = member.push();
        CHECK(s == s2);
        REQUIRE(p.size() == 1);
        CHECK(to_hex(p[0]) == to_hex(p2[0]));

        // ...but the obsolete hash is dropped rather than returned.
        CHECK(o.empty());
    }
}

TEST_CASE(
        "the protobuf config wrapper contains no wall-clock or random data",
        "[config][determinism][proto]") {

    // The wrapper is deterministic only because every non-deterministic element was deliberately
    // pinned: Envelope.timestamp is hardcoded to 1, padding is a bare 0x80 with no random fill,
    // and the inner encryption is encrypt_for_recipient_deterministic (src/config/protos.cpp).
    //
    // Adding a field carrying a wall-clock value or fresh randomness would silently break config
    // re-store idempotency, and every test above would keep passing, because they only compare
    // bytes produced within a single run.  This golden digest is the tripwire for that: if it
    // fails, check what changed in wrap_config before updating the constant.
    const auto payload = "Hello from the other side"_bytes;

    const std::pair<Namespace, std::string_view> expected[] = {
            {Namespace::UserProfile,
             "e5bcbe0595e82d55e80079dc9cf8c8b6952c099ee8306c413833e0eecd45ce03"},
            {Namespace::Contacts,
             "1573a2e233008a47f445a8f1b328fe37bcd49450c94b743202b68902a1a94a89"},
            {Namespace::ConvoInfoVolatile,
             "121dabefb251fa586c14f7e9c82590361c2db4efcb9817771bb4d9b0aaba9362"},
            {Namespace::UserGroups,
             "b78bd9b62719db76ff7a9ec59eef3de0b4aaee4e4d55b515f70b04d674f8b8a9"},
    };

    for (const auto& [ns, digest] : expected) {
        auto wrapped = protos::wrap_config(user_seed, payload, 1, ns);
        CHECK(to_hex(session::hash::hash(32, wrapped)) == digest);
    }
}
