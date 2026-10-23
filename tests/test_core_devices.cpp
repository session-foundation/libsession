#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <session/clock.hpp>
#include <session/core.hpp>
#include <session/core/devices.hpp>
#include <session/core/error_codes.hpp>
#include <session/core/globals.hpp>
#include <session/xed25519.hpp>
#include <set>
#include <thread>

#include "test_helper.hpp"
#include "utils.hpp"

using namespace session;
using namespace session::core;
using namespace std::literals;

namespace {

/// A Core whose account was *restored* rather than generated, and which therefore owes no device
/// group: this is the state a device is in before it has joined one.
///
/// A plain `TempCore` generates its account, which now establishes a group with itself as the only
/// member -- so anything asserting on an unregistered device has to say which of the two it means.
TempCore restored_core() {
    std::array<std::byte, 32> seed{};
    random::fill(seed);
    return TempCore{core::predefined_seed{std::span<const std::byte, 32>{seed}}};
}

}  // namespace

TEST_CASE("Devices - identity", "[core][devices]") {
    TempCore c;

    SECTION("device_id is the id in hex") {
        auto id = c->devices.device_id();
        REQUIRE(id.size() == 2 * device::ID_SIZE);
        CHECK(std::all_of(id.begin(), id.end(), [](char ch) {
            return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
        }));
    }

    SECTION("device_id is stable") {
        CHECK(c->devices.device_id() == c->devices.device_id());
    }

    SECTION("two independent cores have different device IDs") {
        TempCore c2;
        CHECK(c->devices.device_id() != c2->devices.device_id());
    }
}

TEST_CASE("Devices - initial state", "[core][devices]") {
    auto c = restored_core();

    SECTION("device_info defaults") {
        auto [info, is_registered] = c->devices.device_info(await);
        // Nothing held for it anywhere, so what it would publish first.
        CHECK(info.seqno == 1);
        CHECK(info.description.empty());
        CHECK_FALSE(is_registered);
    }

    SECTION("devices() is empty") {
        CHECK(c->devices.devices(true, true, true).empty());
    }

    SECTION("needs_push is false") {
        auto np = c->devices.needs_push();
        CHECK_FALSE(np.device_group);
        CHECK_FALSE(np.account_pubkey);
    }
}

TEST_CASE("Devices - update_info and same_user_fields", "[core][devices]") {
    auto c = restored_core();

    SECTION("update_info persists fields") {
        device::Info info{};
        info.type = device::Type::Session_iOS;
        info.description = "test phone";
        info.version = {1, 2, 3};

        c->devices.update_info(info, await);

        auto [got, is_registered] = c->devices.device_info(await);
        CHECK(got.seqno == 1);
        CHECK(got.type == device::Type::Session_iOS);
        CHECK(got.description == "test phone");
        CHECK(got.version == std::array<int, 3>{1, 2, 3});
        CHECK(got.state == device::State::Unregistered);
        CHECK_FALSE(is_registered);

        // Across a restart too: it is this device's own, not anything a group holds.
        auto path = c.path;
        c.core.reset();
        c.core = std::make_unique<core::Core>(path);
        CHECK(c->devices.device_info(await).first.description == "test phone");
    }

    SECTION("extra fields round-trip") {
        device::Info info{};
        info.extra["custom_key"] = std::string{"hello"};
        c->devices.update_info(info, await);

        auto [got, _] = c->devices.device_info(await);
        REQUIRE(got.extra.count("custom_key"));
        CHECK(std::get<std::string>(got.extra.at("custom_key")) == "hello");
    }

    SECTION("same_user_fields ignores state/seqno/pk_*") {
        device::Info a{}, b{};
        a.type = device::Type::Session_iOS;
        a.description = "foo";
        a.version = {1, 2, 3};
        b = a;

        CHECK(a.same_user_fields(b));

        // Differ in seqno — should still be "same" user fields
        b.seqno = 99;
        CHECK(a.same_user_fields(b));

        // Differ in description — not same
        b.seqno = a.seqno;
        b.description = "bar";
        CHECK_FALSE(a.same_user_fields(b));
    }

    SECTION("a device outside a group describing itself puts nothing in the group's list") {
        device::Info info{};
        info.description = "my device";
        c->devices.update_info(info, await);

        CHECK(c->devices.devices(true, true, true).empty());
        CHECK(c->devices.device_info(await).first.description == "my device");
    }
}

namespace {
constexpr auto cake = "\xf0\x9f\x8e\x82"sv;
// One ending exactly at the cap with a 4-byte character, and one that same character straddles.
const auto at_cap = std::string(device::DESCRIPTION_MAX - cake.size(), 'a') + std::string{cake};
const auto straddling = std::string(device::DESCRIPTION_MAX - 1, 'b') + std::string{cake};
const auto straddling_cut = std::string(device::DESCRIPTION_MAX - 1, 'b');
// Differs from `straddling` only in the character the cap falls inside.
const auto straddling_other = straddling_cut + "\xf0\x9f\x8d\xb0";
}  // namespace

TEST_CASE(
        "Devices - update_info cuts a description to DESCRIPTION_MAX on a character boundary",
        "[core][devices]") {
    REQUIRE(at_cap.size() == device::DESCRIPTION_MAX);
    auto c = restored_core();
    device::Info info{};
    info.description = straddling;
    c->devices.update_info(info, await);
    auto got = c->devices.device_info(await).first;
    CHECK(got.description == straddling_cut);

    // Differing only past the cap is no change, and costs no seqno.
    info.description = straddling_other;
    c->devices.update_info(info, await);
    CHECK(c->devices.device_info(await).first.seqno == got.seqno);

    info.description = at_cap;
    c->devices.update_info(info, await);
    CHECK(c->devices.device_info(await).first.description == at_cap);
}

TEST_CASE(
        "Devices - this device's seqno counts on from what the swarm holds for it",
        "[core][devices]") {
    TempCore c;
    auto seqno = [&] { return c->devices.device_info(await).first.seqno; };
    auto owed = [&] { return c->devices.needs_push().device_group; };
    auto push = [&] {
        c->devices.mark_device_group_pushed(c->devices.build_device_group_message(), "h");
    };

    // Nothing held yet, so the first record is 1 however often it is described before it goes out.
    device::Info info{};
    info.description = "first";
    c->devices.update_info(info, await);
    CHECK(seqno() == 1);
    info.description = "second";
    c->devices.update_info(info, await);
    CHECK(seqno() == 1);
    push();
    CHECK(seqno() == 1);
    CHECK_FALSE(owed());

    // Each change makes the next record one past what is held, once however often it is made, and
    // a change back to what is held is no change at all.
    int64_t n = 1;
    auto changed = [&](auto&& change) {
        change();
        CHECK(seqno() == n + 1);
        CHECK(owed());
        change();
        CHECK(seqno() == n + 1);
        push();
        CHECK(seqno() == ++n);
        CHECK_FALSE(owed());
    };
    changed([&] {
        info.description = "third";
        c->devices.update_info(info, await);
    });
    changed([&] {
        info.type = device::Type::Session_Desktop;
        c->devices.update_info(info, await);
    });
    changed([&] {
        info.version = {2, 0, 0};
        c->devices.update_info(info, await);
    });
    changed([&] {
        info.extra["custom_key"] = std::string{"hello"};
        c->devices.update_info(info, await);
    });
    info.description = "fourth";
    c->devices.update_info(info, await);
    CHECK(seqno() == n + 1);
    info.description = "third";
    c->devices.update_info(info, await);
    CHECK(seqno() == n);
    CHECK_FALSE(owed());

    // New keys are a new record too.
    c->devices.rotate_device_keys();
    CHECK(seqno() == n + 1);
    CHECK(owed());
    push();
    CHECK(seqno() == n + 1);

    // And what the group holds for it is what it said.
    auto self = c->devices.device_info(await).first;
    auto held = c->devices.devices(true, false, false, self.id).at(self.id);
    CHECK(held.description == "third");
    CHECK(held.type == device::Type::Session_Desktop);
    CHECK(held.pk_x25519 == c->devices.active_device_keys().front().x25519_pub);
}

TEST_CASE("Devices - device keys", "[core][devices]") {
    TempCore c;

    SECTION("active_device_keys returns at least one key with correct sizes") {
        auto keys = c->devices.active_device_keys();
        REQUIRE_FALSE(keys.empty());
        CHECK(keys.front().x25519_pub.size() == 32);
        CHECK(keys.front().mlkem768_pub.size() == 1184);
        CHECK_FALSE(keys.front().rotated.has_value());
    }

    SECTION("rotate_device_keys produces a distinct key") {
        auto before = c->devices.active_device_keys();
        REQUIRE_FALSE(before.empty());

        c->devices.rotate_device_keys();
        auto after = c->devices.active_device_keys();

        CHECK(after.front().x25519_pub != before.front().x25519_pub);
        CHECK(after.front().mlkem768_pub != before.front().mlkem768_pub);
        CHECK_FALSE(after.front().rotated.has_value());
    }

    SECTION("after one rotation active_device_keys has two entries") {
        auto initial = c->devices.active_device_keys();  // ensure initial key exists
        REQUIRE(initial.size() == 1);
        c->devices.rotate_device_keys();
        auto keys = c->devices.active_device_keys();
        CHECK(keys.size() == 2);
        CHECK_FALSE(keys.front().rotated.has_value());
        CHECK(keys.back().rotated.has_value());
    }

    SECTION("after two rotations only the current key and the one before it are kept") {
        auto first = c->devices.active_device_keys().front().x25519_pub;
        auto second = c->devices.rotate_device_keys().x25519_pub;
        auto third = c->devices.rotate_device_keys().x25519_pub;
        auto keys = c->devices.active_device_keys();
        REQUIRE(keys.size() == 2);
        CHECK(keys[0].x25519_pub == third);
        CHECK_FALSE(keys[0].rotated.has_value());
        CHECK(keys[1].x25519_pub == second);
        CHECK(keys[1].rotated.has_value());
        CHECK(first != second);
    }
}

TEST_CASE("Devices - device group payload padding", "[core][devices]") {
    TempCore c;

    // Real keys, not random bytes: ML-KEM encapsulation is performed against each device's pubkey.
    // Rotating produces distinct valid keypairs, and the last of them stays this device's own, so
    // this Core can also decrypt whatever it encrypts below to that one.
    std::vector<device::Info> infos;
    for (int i = 0; i < 5; i++) {
        auto k = c->devices.rotate_device_keys();
        auto& info = infos.emplace_back();
        random::fill(info.id);
        info.seqno = 1;
        info.timestamp = clock_now_s();
        info.type = device::Type::Session_Desktop;
        info.description = "test device";
        info.state = device::State::Registered;
        info.version = {1, 0, 0};
        info.pk_x25519 = k.x25519_pub;
        info.pk_mlkem768 = k.mlkem768_pub;
    }

    auto encrypted_size = [&](size_t n) {
        device::map m;
        for (size_t i = 0; i < n; i++)
            m.emplace(infos[i].id, infos[i]);
        return TestHelper::encrypt_device_data(c->devices, m).size();
    };

    SECTION("the payload is padded to 2300 + 6400N") {
        device::map m;
        m.emplace(infos[0].id, infos[0]);
        auto enc = TestHelper::encrypt_device_data(c->devices, m);

        // The encrypted payload sits in the envelope's "d" field, and is the padded plaintext plus
        // the poly1305 tag.  One device is one bucket, on top of the account key allowance.
        oxenc::bt_dict_consumer env{to_string_view(enc)};
        REQUIRE(env.skip_until("d"));
        auto payload = env.consume_string_view();
        CHECK(payload.size() == 2300 + 6400 + 16);
    }

    SECTION("groups of up to 4 devices are indistinguishable by size") {
        auto one = encrypted_size(1);
        CHECK(encrypted_size(2) == one);
        CHECK(encrypted_size(3) == one);
        CHECK(encrypted_size(4) == one);

        // The 5th device crosses into the next bucket, which is expected and unavoidable — the
        // guarantee is bucketing, not constant size.
        CHECK(encrypted_size(5) > one);
    }

    SECTION("padding round-trips off again") {
        device::map m;
        for (size_t i = 2; i < 5; i++)
            m.emplace(infos[i].id, infos[i]);

        auto enc = TestHelper::encrypt_device_data(c->devices, m);
        auto plaintext = TestHelper::decrypt_device_data(c->devices, enc);

        // A bt-encoded dict always ends in 'e'; if any padding survived, it would not.
        REQUIRE_FALSE(plaintext.empty());
        CHECK(plaintext.back() == std::byte{'e'});

        // And the recovered payload really is the device dict, not a truncation of it.
        oxenc::bt_dict_consumer btdc{to_string_view(plaintext)};
        REQUIRE(btdc.skip_until("D"));
        auto devs = btdc.consume_dict_consumer();
        int count = 0;
        while (!devs.is_finished()) {
            devs.skip_until(devs.key());
            devs.consume_dict_consumer();
            count++;
        }
        CHECK(count == 3);
    }

    SECTION("a kicked device is named in the payload but is not a recipient") {
        auto ciphertexts_size = [](std::span<const std::byte> msg) {
            oxenc::bt_dict_consumer outer{msg};
            return outer.require_span<std::byte>("C").size();
        };

        device::map m;
        for (size_t i = 0; i < 4; i++)
            m.emplace(infos[i].id, infos[i]);
        auto four_registered = ciphertexts_size(TestHelper::encrypt_device_data(c->devices, m));

        // A fifth entry, kicked rather than registered.
        auto kicked = infos[4];
        kicked.state = device::State::Kicked;
        kicked.kicked = clock_now_s();
        m.emplace(kicked.id, kicked);

        auto with_kicked = TestHelper::encrypt_device_data(c->devices, m);

        // Five entries, but still only four recipients, so the ciphertext list stays in the 4
        // bucket.  Were the kicked device handed a key it would cross into the 8 bucket and grow --
        // which is what makes this an assertion about the recipient set rather than about padding.
        CHECK(ciphertexts_size(with_kicked) == four_registered);

        // And it is still named in the payload: that is how every other device learns it is gone.
        auto plaintext = TestHelper::decrypt_device_data(c->devices, with_kicked);
        oxenc::bt_dict_consumer btdc{to_string_view(plaintext)};
        REQUIRE(btdc.skip_until("D"));
        auto devs = btdc.consume_dict_consumer();
        std::string_view kicked_key{
                reinterpret_cast<const char*>(kicked.id.data()), kicked.id.size()};
        CHECK(devs.skip_until(kicked_key));
    }
}

TEST_CASE("Devices - account keys", "[core][devices]") {
    // Restored: two sections here are about what the rotation timers say for a device that is *not*
    // in a group, and a generated account is in one from the moment it exists.
    auto c = restored_core();

    SECTION("active_account_keys returns at least one key with correct sizes") {
        auto keys = c->devices.active_account_keys();
        REQUIRE_FALSE(keys.empty());
        CHECK(keys.front().x25519_pub.size() == 32);
        CHECK(keys.front().mlkem768_pub.size() == 1184);
        CHECK_FALSE(keys.front().rotated.has_value());
    }

    SECTION("rotate_account_keys produces a distinct key: newer timestamp wins") {
        auto before = c->devices.active_account_keys();
        REQUIRE(before.size() == 1);

        // Advance clock by 1s so the new key has a strictly later created timestamp and
        // deterministically wins tie-breaking (created DESC, seed ASC).
        ScopedClockOffset adv{1s};
        c->devices.rotate_account_keys();
        auto after = c->devices.active_account_keys();

        REQUIRE(after.size() == 2);
        CHECK_FALSE(after.front().rotated.has_value());
        CHECK(after.back().rotated.has_value());
        CHECK(after.front().x25519_pub != before.front().x25519_pub);
    }

    SECTION("a rotation within the same second as the key it replaces still supersedes it") {
        // Pinned to the start of a second so that both keys are created within it.
        ScopedClockOffset pin_to_next_second{
                (clock_now_s() + 1s) - std::chrono::system_clock::now()};

        // Whichever seed is lower: a rotation that a tie could undo would, after a removal, leave
        // current the key the removed device holds.  Eight in a row, since any one of them wins a
        // seed tie half the time by luck alone.
        auto before = c->devices.active_account_keys();
        REQUIRE(before.size() == 1);
        for (size_t n = 2; n <= 9; n++) {
            c->devices.rotate_account_keys();
            auto keys = c->devices.active_account_keys();
            REQUIRE(keys.size() == n);
            CHECK(keys.front().x25519_pub != before.front().x25519_pub);
            CHECK_FALSE(keys.front().rotated.has_value());
            before = keys;
        }
    }

    SECTION("keys created in the same second settle on the lower seed, in either order") {
        // What two devices' rotations crossing looks like once both have merged: the same created
        // time from different seeds.  Every device must settle on the same one.
        for (bool reversed : {false, true}) {
            auto conn = c->database().conn();
            conn.prepared_exec("DELETE FROM device_account_keys");
            std::array<std::byte, 32> low, high;
            low.fill(std::byte{0x01});
            high.fill(std::byte{0xff});
            for (auto* seed : reversed ? std::array{&low, &high} : std::array{&high, &low})
                conn.prepared_exec(
                        "INSERT INTO device_account_keys"
                        " (created, seed, pubkey_mlkem768, pubkey_x25519)"
                        " VALUES (1700000000, ?, zeroblob(1184), zeroblob(32))",
                        *seed);
            auto active = conn.prepared_get<sqlite::blob_guts<std::array<std::byte, 32>>>(
                    "SELECT seed FROM device_account_keys WHERE rotated IS NULL");
            CHECK(active == low);
        }
    }

    SECTION("after one rotation active_account_keys has two entries") {
        c->devices.active_account_keys();  // ensure initial key exists
        c->devices.rotate_account_keys();
        auto keys = c->devices.active_account_keys();
        CHECK(keys.size() == 2);
        CHECK_FALSE(keys.front().rotated.has_value());
        CHECK(keys.back().rotated.has_value());
    }

    SECTION("old key pruned after ACCOUNT_KEY_RETENTION") {
        c->devices.active_account_keys();  // ensure initial key exists
        c->devices.rotate_account_keys();
        {
            auto keys = c->devices.active_account_keys();
            CHECK(keys.size() == 2);
        }

        // Advance clock past retention window: old rotated key should be pruned.  Two seconds,
        // because a rotation made within the second its predecessor was created is stamped a
        // second ahead, and the old key's rotation time with it.
        ScopedClockOffset advance_past_retention{Devices::ACCOUNT_KEY_RETENTION + 2s};
        auto keys = c->devices.active_account_keys();
        CHECK(keys.size() == 1);
        CHECK_FALSE(keys.front().rotated.has_value());
    }

    SECTION("next_account_rotation returns nullopt when not in device group") {
        CHECK_FALSE(c->devices.next_account_rotation().has_value());
        CHECK_FALSE(c->devices.account_rotation_due());
    }

    SECTION("next_device_rotation returns nullopt when not in device group") {
        CHECK_FALSE(c->devices.next_device_rotation().has_value());
        CHECK_FALSE(c->devices.device_rotation_due());
    }
}

TEST_CASE(
        "Devices - a push confirmed after its keys were forgotten distributes no other",
        "[core][devices]") {
    TempCore c;
    auto push = c->devices.build_device_group_message();
    REQUIRE_FALSE(push.keys.empty());

    // What leaving the group does to them, while the push is still in flight.
    c->database().conn().prepared_exec("DELETE FROM device_account_keys");
    c->devices.rotate_account_keys();

    c->devices.mark_device_group_pushed(push, "h");
    CHECK(c->database().conn().prepared_get<int64_t>(
                  "SELECT distributed FROM device_account_keys") == 0);
}

TEST_CASE("Devices - link request SAS", "[core][devices][sas]") {
    SECTION("indices into Matrix's table, as the emoji were before") {
        std::array<std::byte, 16> seed;
        for (size_t i = 0; i < seed.size(); i++)
            seed[i] = std::byte(i);
        auto sas = sas_from_seed(seed);
        CHECK(sas == Sas{0, 4, 32, 0, 3, 16, 16, 1, 6, 28, 0, 2, 9, 40, 48, 2, 12, 52, 32, 3, 15});

        std::vector<std::string_view> emoji;
        for (auto i : sas)
            emoji.push_back(sas_emoji(i).emoji);
        CHECK(emoji == std::vector{"🐶"sv, "🦄"sv, "🎩"sv, "🐶"sv, "🐎"sv, "🌳"sv, "🌳"sv,
                                   "🐱"sv, "🐘"sv, "🎂"sv, "🐶"sv, "🦁"sv, "🐓"sv, "🎁"sv,
                                   "🔨"sv, "🦁"sv, "🐟"sv, "🚲"sv, "🎩"sv, "🐎"sv, "🌷"sv});
    }

    SECTION("each emoji with Matrix's description") {
        CHECK(sas_emoji(0).emoji == "🐶");
        CHECK(sas_emoji(0).description == "Dog");
        CHECK(sas_emoji(36).description == "Thumbs Up");
        CHECK(sas_emoji(63).emoji == "📌");
        CHECK(sas_emoji(63).description == "Pin");
        std::set<std::string_view> descriptions;
        for (uint8_t i = 0; i < 64; i++)
            descriptions.insert(sas_emoji(i).description);
        CHECK(descriptions.size() == 64);
        CHECK_THROWS_AS(sas_emoji(64), std::out_of_range);
    }

    SECTION("Argon2id at 64 MiB and 2 passes, as the spec says") {
        CHECK(SAS_ARGON2_OPSLIMIT == 2);
        CHECK(SAS_ARGON2_MEMLIMIT == 64 * 1024 * 1024);
        // Computed independently, from libsodium's Argon2id through PyNaCl, with the salt from
        // hashlib's BLAKE2b.
        auto plaintext = "SessionLinkEmoji test plaintext"sv;
        CHECK(oxenc::to_hex(derive_sas_seed(to_span<std::byte>(plaintext))) ==
              "419dcb7bc15bd4a8b281dee155e27bb6");
    }
}

TEST_CASE("Devices - build_link_request", "[core][devices]") {
    // Restored, not generated: asking to join a group only makes sense for a device that adopted
    // an existing account's seed.  A device that generated the account *is* the group.
    auto c = restored_core();
    TempCore group;  // only its link key is used, to encrypt to

    SECTION("returns non-empty message and 21-entry SAS") {
        auto result = TestHelper::build_link_request(*c, *group);
        CHECK_FALSE(result.message.empty());
        CHECK(result.sas.size() == 21);
        for (auto s : result.sas)
            CHECK(s < 64);
    }

    SECTION("consecutive calls produce different messages") {
        auto r1 = TestHelper::build_link_request(*c, *group);
        auto r2 = TestHelper::build_link_request(*c, *group);
        CHECK(r1.message != r2.message);
    }
}

TEST_CASE("Devices - build_account_pubkey_message", "[core][devices]") {
    TempCore c;

    SECTION("non-empty output with correct structure") {
        auto msg = c->devices.build_account_pubkey_message();
        REQUIRE_FALSE(msg.empty());

        auto dict = oxenc::bt_dict_consumer{msg};

        // "M" — mlkem768 pubkey (1184 bytes)
        CHECK(dict.require<std::string_view>("M").size() == 1184);

        // "X" — x25519 pubkey (32 bytes)
        CHECK(dict.require<std::string_view>("X").size() == 32);

        // "~" — XEd25519 signature (64 bytes)
        CHECK(dict.require<std::string_view>("~").size() == 64);
    }

    SECTION("M and X match active account keys") {
        auto keys = c->devices.active_account_keys();
        REQUIRE_FALSE(keys.empty());

        auto msg = c->devices.build_account_pubkey_message();
        auto dict = oxenc::bt_dict_consumer{msg};

        auto M = dict.require<std::string_view>("M");
        auto X = dict.require<std::string_view>("X");

        CHECK(std::memcmp(M.data(), keys.front().mlkem768_pub.data(), 1184) == 0);
        CHECK(std::memcmp(X.data(), keys.front().x25519_pub.data(), 32) == 0);
    }

    SECTION("signature verifies against account x25519 pubkey") {
        auto msg = c->devices.build_account_pubkey_message();
        auto dict = oxenc::bt_dict_consumer{msg};

        dict.require<std::string_view>("M");
        dict.require<std::string_view>("X");

        // Use require_signature to correctly extract the signed body (everything in the dict
        // before the "~" key) and the signature value.
        auto x25519_pub = c->globals.session_id().template subspan<1>();  // skip 0x05 prefix
        bool sig_valid = false;
        dict.require_signature(
                "~", [&](std::span<const std::byte> body, std::span<const std::byte> sig) {
                    sig_valid =
                            sig.size() == 64 && xed25519::verify(sig.first<64>(), x25519_pub, body);
                });
        CHECK(sig_valid);
    }
}

TEST_CASE("Devices - establishing the group", "[core][devices]") {

    SECTION("a generated account establishes a group with itself") {
        TempCore c;

        auto [info, registered] = c->devices.device_info(await);
        CHECK(registered);
        CHECK(info.state == device::State::Registered);
        CHECK(info.id == c->devices.device_info(await).first.id);

        // Exactly one device, and it is us.
        auto devs = c->devices.devices(true, true, true);
        REQUIRE(devs.size() == 1);
        CHECK(devs.begin()->first == info.id);

        // The whole point: a registered device is one that `needs_push` will speak for.  Before
        // this existed, nothing ever registered a device, so nothing was ever owed a push and no
        // group could come into being.
        CHECK(c->devices.needs_push().device_group);

        // The group payload carries the account's shared key seeds, so one is minted here.
        auto keys = c->devices.active_account_keys();
        REQUIRE(keys.size() == 1);
        CHECK_FALSE(keys.front().rotated.has_value());
    }

    SECTION("a restored account does not") {
        auto c = restored_core();

        auto [info, registered] = c->devices.device_info(await);
        CHECK_FALSE(registered);
        CHECK(c->devices.devices(true, true, true).empty());
        CHECK_FALSE(c->devices.needs_push().device_group);
    }

    SECTION("it survives a restart, and does not happen twice") {
        std::optional<device::Id> first_id;
        int64_t first_seqno = 0;
        auto path = std::filesystem::temp_directory_path() /
                    fmt::format("{}.db", random::unique_id("test_estab", 7));
        {
            Core c{path};
            auto [info, registered] = c.devices.device_info(await);
            REQUIRE(registered);
            first_id = info.id;
            first_seqno = info.seqno;
        }
        {
            // Reopened: the flag was cleared the first time, so this must not re-register or
            // re-mint anything -- a second establish would bump the seqno and mint a second key.
            Core c{path};
            auto [info, registered] = c.devices.device_info(await);
            CHECK(registered);
            CHECK(info.id == *first_id);
            CHECK(info.seqno == first_seqno);
            CHECK(c.devices.active_account_keys().size() == 1);
        }
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
}

TEST_CASE("Devices - a removal cannot be undone by a message", "[core][devices]") {
    TempCore c;

    // A second device, with keys this core holds so that what we encrypt below is readable back.
    auto k = c->devices.rotate_device_keys();
    device::Info other{};
    random::fill(other.id);
    other.seqno = 1;
    other.timestamp = clock_now_s();
    other.type = device::Type::Session_Android;
    other.description = "other device";
    other.state = device::State::Registered;
    other.version = {1, 0, 0};
    other.pk_x25519 = k.x25519_pub;
    other.pk_mlkem768 = k.mlkem768_pub;

    auto [self, registered] = c->devices.device_info(await);
    REQUIRE(registered);

    auto deliver = [&](const device::map& m) {
        TestHelper::receive_device_group_message(
                c->devices, TestHelper::encrypt_device_data(c->devices, m));
    };
    auto state_of = [&](const device::Id& id) {
        auto devs = c->devices.devices(true, true, true);
        auto found = devs.find(id);
        REQUIRE(found != devs.end());
        return found->second;
    };

    // It joins.
    deliver({{self.id, self}, {other.id, other}});
    REQUIRE(state_of(other.id).state == device::State::Registered);

    // It is removed, a while ago.
    auto kicked_at = clock_now_s() - 1h;
    auto gone = other;
    gone.state = device::State::Kicked;
    gone.kicked = kicked_at;
    deliver({{self.id, self}, {gone.id, gone}});

    auto after_kick = state_of(other.id);
    REQUIRE(after_kick.state == device::State::Kicked);
    REQUIRE(after_kick.kicked == kicked_at);

    // Now it pushes itself back in with a higher seqno, which it can do: it still holds the account
    // seed, so it can sign and encrypt a message everyone accepts.
    auto returning = other;
    returning.seqno = 5;
    returning.description = "back again";
    deliver({{self.id, self}, {returning.id, returning}});

    auto after = state_of(other.id);

    // Refused: still removed, and none of its claims adopted.
    CHECK(after.state == device::State::Kicked);
    CHECK(after.description == "other device");

    // And restated rather than merely ignored: the tombstone moves to the front of the removed
    // list, and we owe a push so that devices which never saw the removal learn of it.
    REQUIRE(after.kicked.has_value());
    CHECK(*after.kicked > kicked_at);
    CHECK(c->devices.needs_push().device_group);
}

TEST_CASE(
        "Devices - two records at one seqno settle the same way either way round",
        "[core][devices]") {
    // Only a bug or a forgery produces two different records at the same state and seqno -- a
    // device bumps its own seqno whenever it changes.  What matters is that two devices seeing them
    // in opposite orders still end up holding the same thing, rather than each keeping whichever
    // arrived first and disagreeing from then on.
    auto make_variant = [](const device::Info& base, std::string description) {
        auto v = base;
        v.description = std::move(description);
        return v;
    };

    // Every field fixed, including the pubkeys: the tie is broken on the encoded record, so a
    // record that differs between the two runs is two different questions rather than one asked
    // twice. These keys are never used to decrypt anything -- this core reads the message as
    // itself.
    auto settle = [&](bool reversed) {
        TempCore c;

        device::Info other{};
        for (size_t i = 0; i < other.id.size(); i++)
            other.id[i] = std::byte{static_cast<unsigned char>(i)};
        other.seqno = 1;
        other.timestamp = std::chrono::sys_seconds{1700000000s};
        other.type = device::Type::Session_Android;
        other.state = device::State::Registered;
        other.version = {1, 0, 0};
        other.pk_x25519.fill(std::byte{0x11});
        other.pk_mlkem768.fill(std::byte{0x22});

        auto [self, registered] = c->devices.device_info(await);
        REQUIRE(registered);

        auto a = make_variant(other, "first description");
        auto b = make_variant(other, "second description");
        if (reversed)
            std::swap(a, b);

        for (const auto& v : {a, b})
            TestHelper::receive_device_group_message(
                    c->devices,
                    TestHelper::encrypt_device_data(c->devices, {{self.id, self}, {v.id, v}}));

        auto devs = c->devices.devices(true, true, true);
        auto found = devs.find(other.id);
        REQUIRE(found != devs.end());
        return found->second.description;
    };

    CHECK(settle(false) == settle(true));
}

TEST_CASE("Devices - a tombstone for an unknown device is kept", "[core][devices]") {
    TempCore c;

    // Keys this core holds, so that the message we build is readable back and the returning record
    // below is a usable recipient.
    auto k = c->devices.rotate_device_keys();

    auto [self, registered] = c->devices.device_info(await);
    REQUIRE(registered);

    auto deliver = [&](const device::map& m) {
        TestHelper::receive_device_group_message(
                c->devices, TestHelper::encrypt_device_data(c->devices, m));
    };
    auto state_of = [&](const device::Id& id) {
        auto devs = c->devices.devices(true, true, true);
        auto found = devs.find(id);
        REQUIRE(found != devs.end());
        return found->second;
    };

    // A removal for a device we have never held a record of -- which is what a device joining after
    // the removal sees, since the group carries the tombstone but nothing else about it.
    auto kicked_at = clock_now_s() - 1h;
    device::Info gone{};
    random::fill(gone.id);
    gone.state = device::State::Kicked;
    gone.kicked = kicked_at;
    deliver({{self.id, self}, {gone.id, gone}});

    // Stored, rather than dropped for want of a row to update: the tombstone is the whole point of
    // the entry, and needs no details to do its job.
    auto after_kick = state_of(gone.id);
    CHECK(after_kick.state == device::State::Kicked);
    CHECK(after_kick.kicked == kicked_at);

    // And it does its job: the removed device cannot talk its way back in, exactly as it could not
    // for a device that saw the removal first.
    auto returning = gone;
    returning.state = device::State::Registered;
    returning.kicked.reset();
    returning.seqno = 5;
    returning.timestamp = clock_now_s();
    returning.description = "back again";
    returning.type = device::Type::Session_Android;
    returning.version = {1, 0, 0};
    returning.pk_x25519 = k.x25519_pub;
    returning.pk_mlkem768 = k.mlkem768_pub;
    deliver({{self.id, self}, {returning.id, returning}});

    auto after = state_of(gone.id);
    CHECK(after.state == device::State::Kicked);
    CHECK(after.description != "back again");
}

TEST_CASE("Devices - a departure is a tombstone of its own kind", "[core][devices]") {
    TempCore c;
    auto k = c->devices.rotate_device_keys();

    auto [self, registered] = c->devices.device_info(await);
    REQUIRE(registered);

    auto deliver = [&](const device::map& m) {
        TestHelper::receive_device_group_message(
                c->devices, TestHelper::encrypt_device_data(c->devices, m));
    };
    auto state_of = [&](const device::Id& id) {
        auto devs = c->devices.devices(true, true, true);
        auto found = devs.find(id);
        REQUIRE(found != devs.end());
        return found->second;
    };
    auto tombstone = [&](const device::Id& id, device::State state, auto when) {
        device::Info t{};
        t.id = id;
        t.state = state;
        t.kicked = when;
        return t;
    };

    device::Id id;
    random::fill(id);
    auto t0 = clock_now_s() - 3h;
    auto t1 = clock_now_s() - 2h;
    auto t2 = clock_now_s() - 1h;

    // It leaves.
    deliver({{self.id, self}, {id, tombstone(id, device::State::Left, t1)}});
    CHECK(state_of(id).state == device::State::Left);
    CHECK(state_of(id).kicked == t1);

    // And is written back as a departure, which is all its tombstone says.
    auto plaintext = TestHelper::decrypt_device_data(
            c->devices,
            TestHelper::encrypt_device_data(c->devices, c->devices.devices(true, true, true)));
    oxenc::bt_dict_consumer btdc{to_string_view(plaintext)};
    REQUIRE(btdc.skip_until("D"));
    auto devs = btdc.consume_dict_consumer();
    REQUIRE(devs.skip_until(std::string_view{reinterpret_cast<const char*>(id.data()), id.size()}));
    auto written = devs.consume_dict_consumer();
    CHECK(written.require<int64_t>("l") == t1.time_since_epoch().count());
    CHECK(written.is_finished());

    // A removal beats it, even one timestamped earlier: a device that left and was then removed
    // must read as removed everywhere, or it would never be told.
    deliver({{self.id, self}, {id, tombstone(id, device::State::Kicked, t0)}});
    CHECK(state_of(id).state == device::State::Kicked);
    CHECK(state_of(id).kicked == t0);

    // A later departure does not undo it.
    deliver({{self.id, self}, {id, tombstone(id, device::State::Left, t2)}});
    CHECK(state_of(id).state == device::State::Kicked);
    CHECK(state_of(id).kicked == t0);

    // Between removals the later wins, and an older one changes nothing.
    deliver({{self.id, self}, {id, tombstone(id, device::State::Kicked, t2)}});
    CHECK(state_of(id).kicked == t2);
    deliver({{self.id, self}, {id, tombstone(id, device::State::Kicked, t1)}});
    CHECK(state_of(id).kicked == t2);

    // A device that left cannot re-add itself any more than a removed one can.
    device::Id leaver;
    random::fill(leaver);
    deliver({{self.id, self}, {leaver, tombstone(leaver, device::State::Left, t1)}});
    device::Info returning{};
    returning.id = leaver;
    returning.state = device::State::Registered;
    returning.seqno = 5;
    returning.timestamp = clock_now_s();
    returning.description = "back again";
    returning.type = device::Type::Session_Android;
    returning.version = {1, 0, 0};
    returning.pk_x25519 = k.x25519_pub;
    returning.pk_mlkem768 = k.mlkem768_pub;
    deliver({{self.id, self}, {leaver, returning}});
    CHECK(state_of(leaver).state == device::State::Left);
    CHECK(state_of(leaver).description != "back again");
    CHECK(state_of(leaver).kicked > t1);
}

TEST_CASE("Devices - a single-recipient group is readable", "[core][devices]") {
    TempCore c;

    // The common case: an account with one device, which is what establishing a group produces.
    // With one recipient every other slot in the message is padding, so nothing else can stand in
    // for a real entry that was overwritten.
    auto [self, registered] = c->devices.device_info(await);
    REQUIRE(registered);

    auto enc = TestHelper::encrypt_device_data(c->devices, device::map{{self.id, self}});
    auto plain = TestHelper::decrypt_device_data(c->devices, enc);

    REQUIRE_FALSE(plain.empty());
    oxenc::bt_dict_consumer btdc{to_string_view(plain)};
    REQUIRE(btdc.skip_until("D"));
    auto devs = btdc.consume_dict_consumer();
    std::string_view self_key{reinterpret_cast<const char*>(self.id.data()), self.id.size()};
    CHECK(devs.skip_until(self_key));
}

namespace {

/// An account's existing device, and a second one on the same account asking to join it.
struct Linking {
    // What each side is told.  Declared first so they outlive the Cores that report to them.
    DeviceEventsRecorder events;
    DeviceEventsRecorder applicant_events;

    TempCore core{reporting_to(events)};  // generated, so it is in the group and can admit others
    std::array<std::byte, 32> seed = seed_of(core);
    TempCore applicant{
            core::predefined_seed{std::span<const std::byte, 32>{seed}},
            reporting_to(applicant_events)};

    static core::callbacks reporting_to(DeviceEventsRecorder& r) {
        core::callbacks cb;
        cb.devices = &r;
        return cb;
    }

    static std::array<std::byte, 32> seed_of(TempCore& c) {
        std::array<std::byte, 32> out;
        auto s = c->globals.account_seed();
        std::ranges::copy(std::as_bytes(s.seed()), out.begin());
        return out;
    }

    static device::Id id_of(TempCore& c) {
        auto hex = c->devices.device_id();
        device::Id id;
        oxenc::from_hex(hex.begin(), hex.end(), reinterpret_cast<unsigned char*>(id.data()));
        return id;
    }

    device::Id applicant_id() { return id_of(applicant); }

    // The applicant's request, as the existing device receives it.  Whole seconds, because that is
    // what the deadline is stored in, so a test can compare it exactly.
    auto
    ask(std::chrono::sys_seconds expiry = std::chrono::floor<std::chrono::seconds>(clock_now_s()) +
                                          10min,
        std::string hash = "L1") {
        auto req = TestHelper::build_link_request(*applicant, *core);
        TestHelper::deliver_device_message(*core, req.message, expiry, std::move(hash));
        return req;
    }

    // The existing device's group, as the applicant sees it once it has fetched a group message:
    // what it asks to join.  A completed fetch, so the applicant knows where it stands --
    // DeviceGroupVisible -- before it asks.
    device::GroupId show_group() {
        TestHelper::deliver_device_message(
                *applicant,
                core->devices.build_device_group_message().message,
                std::chrono::floor<std::chrono::seconds>(clock_now_s()) + Devices::DEVICE_GROUP_TTL,
                "G0");
        auto group = TestHelper::group_id(*core);
        REQUIRE(group);
        return *group;
    }

    device::Info state_of_applicant() {
        auto devs = core->devices.devices(true, true, true);
        auto found = devs.find(applicant_id());
        REQUIRE(found != devs.end());
        return found->second;
    }

    // The applicant asks, is accepted here, reads the group message admitting it, and has its user
    // confirm the SAS, leaving a group of two.
    void admit() {
        ask();
        REQUIRE(core->devices.accept_request(events.added.at(0).id, await));
        TestHelper::deliver_device_message(
                *applicant,
                core->devices.build_device_group_message().message,
                std::chrono::floor<std::chrono::seconds>(clock_now_s()) + 10min,
                "G1");
        REQUIRE(applicant->devices.confirm_link(await));
        REQUIRE(applicant->devices.device_info(await).second);
    }
};

}  // namespace

TEST_CASE(
        "Devices - a link request is listed with its SAS and the swarm's deadline",
        "[core][devices][linking]") {
    Linking l;
    auto expiry = std::chrono::floor<std::chrono::seconds>(clock_now_s()) + 7min;
    auto sent = l.ask(expiry);

    auto incoming = l.core->devices.incoming_link_requests(await);
    REQUIRE(incoming.size() == 1);
    CHECK(incoming[0].sas == sent.sas);
    CHECK(incoming[0].expires == expiry);
    CHECK(incoming[0].status == device::LinkStatus::Pending);
    CHECK(oxenc::to_hex(incoming[0].device.id) == l.applicant->devices.device_id());

    // One id per request for the whole session, however many times it is read.
    CHECK(l.core->devices.incoming_link_requests(await)[0].id == incoming[0].id);
    CHECK(l.core->devices.link_requests(await)[0].id == incoming[0].id);
}

TEST_CASE("Devices - accepting a request admits the device, once", "[core][devices][linking]") {
    Linking l;
    l.ask();
    auto id = l.core->devices.incoming_link_requests(await).at(0).id;

    CHECK(l.core->devices.accept_request(id, await));
    CHECK(l.state_of_applicant().state == device::State::Registered);

    // Kept, not removed: it is the request most worth being able to look back at.
    CHECK(l.core->devices.incoming_link_requests(await).empty());
    auto all = l.core->devices.link_requests(await);
    REQUIRE(all.size() == 1);
    CHECK(all[0].status == device::LinkStatus::Accepted);

    // Carried by the next push as a transition to broadcast, which is how every other device hears
    // of it.  Asked of the message rather than of needs_push(), which a fresh account's first push
    // already makes true whether or not anything was accepted.
    auto push = l.core->devices.build_device_group_message();
    CHECK(std::ranges::any_of(
            push.broadcast, [&](const auto& b) { return b.first == l.applicant_id(); }));

    CHECK_FALSE(l.core->devices.accept_request(id, await));
}

TEST_CASE(
        "Devices - ignoring a request is local and leaves the device pending",
        "[core][devices][linking]") {
    Linking l;
    l.ask();
    auto id = l.core->devices.incoming_link_requests(await).at(0).id;

    CHECK(l.core->devices.ignore_request(id, await));
    CHECK(l.core->devices.incoming_link_requests(await).empty());
    CHECK(l.core->devices.link_requests(await).at(0).status == device::LinkStatus::Ignored);

    // Pending rather than removed or kicked, so the same request redelivered does not prompt again
    // but a real retry from the applicant still can.
    CHECK(l.state_of_applicant().state == device::State::Pending);

    CHECK_FALSE(l.core->devices.ignore_request(id, await));
}

TEST_CASE(
        "Devices - a request ignored here can still be accepted here while it is live",
        "[core][devices][linking]") {
    Linking l;
    l.ask();
    auto id = l.events.added.at(0).id;

    // Whatever came before it, an acceptance tells this device's application what any does.
    SECTION("accepted outright") {}
    SECTION("ignored first") {
        REQUIRE(l.core->devices.ignore_request(id, await));
    }
    SECTION("ignored and deleted from the swarm first") {
        REQUIRE(l.core->devices.ignore_request(id, true, await));
    }

    l.events = DeviceEventsRecorder{};
    REQUIRE(l.core->devices.accept_request(id, await));
    CHECK(l.core->devices.link_requests(await).at(0).status == device::LinkStatus::Accepted);
    CHECK(l.events.ended.empty());
    CHECK(l.events.members.empty());
    CHECK(l.events.replaced.size() == 1);
    CHECK(l.events.membership.empty());

    TestHelper::deliver_device_message(
            *l.applicant,
            l.core->devices.build_device_group_message().message,
            std::chrono::floor<std::chrono::seconds>(clock_now_s()) + 10min,
            "G1");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Approved);
}

TEST_CASE(
        "Devices - a request ignored here cannot be accepted past its deadline",
        "[core][devices][linking]") {
    Linking l;
    l.ask();
    auto id = l.events.added.at(0).id;
    REQUIRE(l.core->devices.ignore_request(id, await));

    ScopedClockOffset later{11min};
    CHECK_FALSE(l.core->devices.accept_request(id, await));
    CHECK(l.state_of_applicant().state == device::State::Pending);
    CHECK(l.core->devices.link_requests(await).at(0).status == device::LinkStatus::Ignored);
}

TEST_CASE(
        "Devices - a request ignored here is superseded by the device asking again",
        "[core][devices][linking]") {
    Linking l;
    l.ask();
    auto first = l.events.added.at(0).id;
    REQUIRE(l.core->devices.ignore_request(first, await));

    // Accepting the old one now would admit the device as the new request describes it, under the
    // emoji the user compared for the old one.
    l.ask(std::chrono::floor<std::chrono::seconds>(clock_now_s()) + 10min, "L2");
    CHECK(l.core->devices.link_requests(await).back().status == device::LinkStatus::Superseded);
    CHECK_FALSE(l.core->devices.accept_request(first, await));
    CHECK(l.core->devices.accept_request(l.events.added.at(1).id, await));
}

TEST_CASE("Devices - a request past its deadline cannot be accepted", "[core][devices][linking]") {
    Linking l;
    auto expiry = std::chrono::floor<std::chrono::seconds>(clock_now_s()) - 1s;
    l.ask(expiry);

    CHECK(l.core->devices.incoming_link_requests(await).empty());

    auto all = l.core->devices.link_requests(await);
    REQUIRE(all.size() == 1);
    CHECK(all[0].status == device::LinkStatus::Pending);
    CHECK(all[0].expired(std::chrono::system_clock::now()));
    CHECK_FALSE(l.core->devices.accept_request(all[0].id, await));
}

TEST_CASE("Devices - a resent request replaces the one on screen", "[core][devices][linking]") {
    Linking l;
    auto first = l.ask();
    auto first_id = l.core->devices.incoming_link_requests(await).at(0).id;

    auto second = l.ask(std::chrono::floor<std::chrono::seconds>(clock_now_s()) + 10min, "L2");
    REQUIRE(second.sas != first.sas);

    // One live request, and it is the new one: a user comparing emoji must be shown the SAS of the
    // record that would actually be admitted.
    auto incoming = l.core->devices.incoming_link_requests(await);
    REQUIRE(incoming.size() == 1);
    CHECK(incoming[0].id != first_id);
    CHECK(incoming[0].sas == second.sas);

    auto all = l.core->devices.link_requests(await);
    REQUIRE(all.size() == 2);
    CHECK(all[1].status == device::LinkStatus::Superseded);

    CHECK_FALSE(l.core->devices.accept_request(first_id, await));
    CHECK(l.core->devices.accept_request(incoming[0].id, await));
}

TEST_CASE(
        "Devices - forgetting requests never takes one still waiting", "[core][devices][linking]") {
    Linking l;
    l.ask();
    auto id = l.core->devices.incoming_link_requests(await).at(0).id;

    std::vector<int> ids{id, id + 1000};  // the second was never handed out
    CHECK(l.core->devices.forget_link_requests(ids, await) == 0);
    CHECK(l.core->devices.link_requests(await).size() == 1);

    l.core->devices.ignore_request(id, await);
    CHECK(l.core->devices.forget_link_requests(ids, await) == 1);
    CHECK(l.core->devices.link_requests(await).empty());
}

TEST_CASE("Devices - a link request id is never handed out twice", "[core][devices][linking]") {
    Linking l;
    l.ask();
    auto first = l.core->devices.incoming_link_requests(await).at(0).id;
    l.core->devices.ignore_request(first, await);

    // Forgotten, which takes away the row holding the highest id: the one row whose id an insert
    // would otherwise take next.
    REQUIRE(l.core->devices.forget_link_requests(std::vector{first}, await) == 1);
    REQUIRE(l.core->devices.link_requests(await).empty());

    l.ask(std::chrono::floor<std::chrono::seconds>(clock_now_s()) + 10min, "L2");
    auto incoming = l.core->devices.incoming_link_requests(await);
    REQUIRE(incoming.size() == 1);
    CHECK(incoming[0].id != first);
    CHECK_THROWS_AS(l.core->devices.accept_request(first, await), std::invalid_argument);
}

TEST_CASE("Devices - an id this session never handed out is an error", "[core][devices][linking]") {
    Linking l;
    CHECK_THROWS_AS(l.core->devices.accept_request(12345, await), std::invalid_argument);
    CHECK_THROWS_AS(l.core->devices.ignore_request(12345, await), std::invalid_argument);
}

namespace {
auto in(std::chrono::minutes m) {
    return std::chrono::floor<std::chrono::seconds>(clock_now_s()) + m;
}

// For what happens with no call to wait on.  `done` runs on Core's loop, which is the thread that
// writes the recorders it reads.
template <typename F>
bool eventually(Core& core, F done) {
    auto give_up = std::chrono::steady_clock::now() + 5s;
    while (!core.call_get(done)) {
        if (std::chrono::steady_clock::now() > give_up)
            return false;
        std::this_thread::sleep_for(20ms);
    }
    return true;
}
}  // namespace

TEST_CASE(
        "Devices events - a request is announced once, by the fetch that brought it",
        "[core][devices][linking][events]") {
    Linking l;
    auto sent = l.ask();

    REQUIRE(l.events.added.size() == 1);
    CHECK(l.events.added[0].sas == sent.sas);

    // Neither reading it nor fetching again announces it a second time.
    l.core->devices.incoming_link_requests(await);
    TestHelper::finish_fetch(*l.core);
    CHECK(l.events.added.size() == 1);

    // Where this device stands became known with the first fetch, and is not told again by later
    // ones that change nothing.
    CHECK(l.events.membership == std::vector{device::Membership::InGroup});
}

TEST_CASE(
        "Devices events - nothing is announced before the first fetch",
        "[core][devices][linking][events]") {
    Linking l;
    auto req = TestHelper::build_link_request(*l.applicant, *l.core);

    // Stored, as a request left over from before a restart would be, but the swarm not yet asked.
    TestHelper::deliver_device_message(*l.core, req.message, in(10min), "L1", /*is_final=*/false);

    // A local change reports what it can -- and a request is not something it can report yet.
    device::Info info{};
    info.description = "renamed";
    l.core->devices.update_info(info, await);
    CHECK(l.events.added.empty());

    TestHelper::finish_fetch(*l.core);
    CHECK(l.events.added.size() == 1);
}

TEST_CASE(
        "Devices events - a request the application already read is not announced",
        "[core][devices][linking][events]") {
    Linking l;
    auto req = TestHelper::build_link_request(*l.applicant, *l.core);
    TestHelper::deliver_device_message(*l.core, req.message, in(10min), "L1", /*is_final=*/false);

    // Drawn from before the fetch: the application has it, so the fetch must not hand it over
    // twice.
    REQUIRE(l.core->devices.incoming_link_requests(await).size() == 1);
    TestHelper::finish_fetch(*l.core);
    CHECK(l.events.added.empty());
}

TEST_CASE(
        "Devices events - a request read after it closed is not reported closed",
        "[core][devices][linking][events]") {
    Linking l;
    auto first = TestHelper::build_link_request(*l.applicant, *l.core);
    TestHelper::deliver_device_message(*l.core, first.message, in(10min), "L1", /*is_final=*/false);
    auto second = TestHelper::build_link_request(*l.applicant, *l.core);
    TestHelper::deliver_device_message(
            *l.core, second.message, in(10min), "L2", /*is_final=*/false);

    // The superseded one is there to be read, and reads as superseded.
    REQUIRE(l.core->devices.link_requests(await).size() == 2);
    TestHelper::finish_fetch(*l.core);
    CHECK(l.events.ended.empty());
}

TEST_CASE(
        "Devices events - a resend closes the old prompt before opening the new one",
        "[core][devices][linking][events]") {
    Linking l;
    l.ask();
    auto first = l.events.added.at(0).id;

    auto second = l.ask(in(10min), "L2");

    REQUIRE(l.events.ended.size() == 1);
    CHECK(l.events.ended[0] == std::pair{first, device::LinkRequestEnd::Superseded});
    REQUIRE(l.events.added.size() == 2);
    CHECK(l.events.added[1].id != first);
    CHECK(l.events.added[1].sas == second.sas);

    std::vector<std::string> prompts;
    for (const auto& e : l.events.order)
        if (e == "added" || e == "ended")
            prompts.push_back(e);
    CHECK(prompts == std::vector<std::string>{"added", "ended", "added"});
}

TEST_CASE(
        "Devices events - acceptance by another device closes the prompt here",
        "[core][devices][linking][events]") {
    Linking l;
    l.ask();
    auto id = l.events.added.at(0).id;

    // Another device admitted it, and its group message says so.
    auto [self, registered] = l.core->devices.device_info(await);
    REQUIRE(registered);
    auto admitted = l.state_of_applicant();
    admitted.state = device::State::Registered;
    auto group = TestHelper::encrypt_device_data(
            l.core->devices, {{self.id, self}, {admitted.id, admitted}});
    TestHelper::deliver_device_message(*l.core, group, in(10min), "G1");

    REQUIRE(l.events.ended.size() == 1);
    CHECK(l.events.ended[0] == std::pair{id, device::LinkRequestEnd::Accepted});
    REQUIRE(!l.events.replaced.empty());
    CHECK(l.events.replaced.back().at(l.applicant_id()).state == device::State::Registered);
}

TEST_CASE(
        "Devices events - another device joining or leaving the group is a notice",
        "[core][devices][events]") {
    Linking l;
    l.ask();
    auto [self, registered] = l.core->devices.device_info(await);
    REQUIRE(registered);
    auto deliver = [&](const device::Info& applicant, std::string hash) {
        TestHelper::deliver_device_message(
                *l.core,
                TestHelper::encrypt_device_data(
                        l.core->devices, {{self.id, self}, {applicant.id, applicant}}),
                in(10min),
                std::move(hash));
    };

    // Admitted by another device.
    auto admitted = l.state_of_applicant();
    admitted.state = device::State::Registered;
    deliver(admitted, "G1");
    REQUIRE(l.events.members.size() == 1);
    CHECK(l.events.members[0].id == l.applicant_id());
    CHECK(l.events.members[0].state == device::State::Registered);

    // The notice, then the list to redraw.
    auto member = std::ranges::find(l.events.order, "member");
    REQUIRE(member != l.events.order.end());
    CHECK(std::ranges::find(member, l.events.order.end(), "replaced") != l.events.order.end());

    auto gone = admitted;
    gone.kicked = clock_now_s();
    SECTION("removed elsewhere") {
        gone.state = device::State::Kicked;
        deliver(gone, "G2");
        REQUIRE(l.events.members.size() == 2);
        CHECK(l.events.members[1].state == device::State::Kicked);
    }
    SECTION("left") {
        gone.state = device::State::Left;
        deliver(gone, "G2");
        REQUIRE(l.events.members.size() == 2);
        CHECK(l.events.members[1].state == device::State::Left);
    }
}

TEST_CASE(
        "Devices events - no notice for a change made here, or for a new group's members",
        "[core][devices][events]") {
    Linking l;

    // Accepted here, and the applicant admitted: neither side has news of the other.
    l.admit();
    CHECK(l.events.members.empty());
    CHECK(l.applicant_events.members.empty());

    // Removed here.
    REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
    TestHelper::finish_fetch(*l.core);
    CHECK(l.events.members.empty());

    // A tombstone for a device this one never knew of says nothing about the group it knew.
    auto [self, registered] = l.core->devices.device_info(await);
    device::Info stranger{};
    random::fill(stranger.id);
    stranger.state = device::State::Kicked;
    stranger.kicked = clock_now_s();
    TestHelper::deliver_device_message(
            *l.core,
            TestHelper::encrypt_device_data(
                    l.core->devices, {{self.id, self}, {stranger.id, stranger}}),
            in(10min),
            "G9");
    CHECK(l.events.members.empty());
}

TEST_CASE(
        "Devices events - an unanswered request closes when its deadline passes",
        "[core][devices][linking][events]") {
    Linking l;
    l.ask(in(1min));
    auto id = l.events.added.at(0).id;

    ScopedClockOffset later{2min};
    TestHelper::finish_fetch(*l.core);

    REQUIRE(l.events.ended.size() == 1);
    CHECK(l.events.ended[0] == std::pair{id, device::LinkRequestEnd::Expired});
}

// Deadlines are stored in whole seconds, so these land somewhere between half a second and a second
// and a half out.
TEST_CASE(
        "Devices events - a deadline closes the prompt with no fetch to notice it",
        "[core][devices][linking][events]") {
    Linking l;
    auto req = TestHelper::build_link_request(*l.applicant, *l.core);
    TestHelper::deliver_device_message(*l.core, req.message, clock_now_ms() + 1500ms, "L1");
    auto id = l.events.added.at(0).id;

    REQUIRE(eventually(*l.core, [&] { return !l.events.ended.empty(); }));
    CHECK(l.events.ended[0] == std::pair{id, device::LinkRequestEnd::Expired});
}

TEST_CASE(
        "Devices events - a request read rather than announced still closes at its deadline",
        "[core][devices][linking][events]") {
    Linking l;
    auto req = TestHelper::build_link_request(*l.applicant, *l.core);
    TestHelper::deliver_device_message(
            *l.core, req.message, clock_now_ms() + 1500ms, "L1", /*is_final=*/false);
    auto id = l.core->devices.incoming_link_requests(await).at(0).id;

    REQUIRE(eventually(*l.core, [&] { return !l.events.ended.empty(); }));
    CHECK(l.events.ended[0] == std::pair{id, device::LinkRequestEnd::Expired});
}

TEST_CASE(
        "Devices events - ignoring here is not reported back", "[core][devices][linking][events]") {
    Linking l;
    l.ask();

    CHECK(l.core->devices.ignore_request(l.events.added.at(0).id, await));
    TestHelper::finish_fetch(*l.core);
    CHECK(l.events.ended.empty());
}

TEST_CASE(
        "Devices events - accepting here reports the device list, not a closed request",
        "[core][devices][linking][events]") {
    Linking l;
    l.ask();

    // The list changed, which other views need to hear; the request closing is something only the
    // caller was waiting on, and it knows.
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    TestHelper::finish_fetch(*l.core);
    CHECK(l.events.ended.empty());
    REQUIRE(l.events.replaced.size() == 1);
    CHECK(l.events.replaced[0].at(l.applicant_id()).state == device::State::Registered);
}

TEST_CASE(
        "Devices events - a link request alone does not change the device list",
        "[core][devices][linking][events]") {
    Linking l;
    l.ask();
    CHECK(l.events.replaced.empty());
}

TEST_CASE(
        "Devices events - a removal is reported once, not every time it is restated",
        "[core][devices][events]") {
    Linking l;
    TestHelper::finish_fetch(*l.core);

    auto [self, registered] = l.core->devices.device_info(await);
    REQUIRE(registered);
    auto gone = l.applicant->devices.device_info(await).first;
    gone.state = device::State::Kicked;
    gone.kicked = std::chrono::floor<std::chrono::seconds>(clock_now_s()) - 1h;
    device::map group{{self.id, self}, {gone.id, gone}};

    TestHelper::deliver_device_message(
            *l.core, TestHelper::encrypt_device_data(l.core->devices, group), in(10min), "G1");
    REQUIRE(l.events.replaced.size() == 1);
    CHECK(l.events.replaced[0].at(gone.id).state == device::State::Kicked);

    // Every group message carries the group's recent tombstones.
    TestHelper::deliver_device_message(
            *l.core, TestHelper::encrypt_device_data(l.core->devices, group), in(10min), "G2");
    CHECK(l.events.replaced.size() == 1);
}

TEST_CASE(
        "Devices events - a device hears it was admitted, not that it asked",
        "[core][devices][linking][events]") {
    Linking l;
    TestHelper::finish_fetch(*l.applicant);
    REQUIRE(l.applicant_events.membership == std::vector{device::Membership::NoGroup});
    l.applicant_events.membership.clear();

    // Its own request has it Requesting, which it knows: it is the one asking.
    l.ask();
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant_events.membership.empty());

    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    auto group = l.core->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(*l.applicant, group, in(10min), "G1");

    // Approved, which it hears wherever its user is, but not in until they confirm the SAS.
    CHECK(l.applicant_events.membership == std::vector{device::Membership::Approved});
    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(l.applicant_events.membership ==
          std::vector{device::Membership::Approved, device::Membership::InGroup});
}

namespace {

using Asked = std::optional<Expected<Devices::OutgoingLinkRequest>>;

// Whether `r` is the fetch of the device namespace alone that asking to join begins with, rather
// than an ordinary poll.
// A fetch of namespace `ns` alone, as Devices asks for one outside the polling schedule.
bool is_fetch_of(const MockNetwork::SentRequest& r, int ns) {
    if (r.request.endpoint != "batch")
        return false;
    auto reqs = push_requests(r);
    return reqs.size() == 1 && reqs[0]["params"]["namespace"] == ns;
}

bool is_device_fetch(const MockNetwork::SentRequest& r) {
    return is_fetch_of(r, 21);
}

bool is_pubkey_fetch(const MockNetwork::SentRequest& r) {
    return is_fetch_of(r, -21);
}

using Held = std::vector<std::pair<std::vector<std::byte>, std::string>>;

// Answers a fetch of `ns`, as a swarm holding `held` -- messages and their hashes -- beyond what
// the device already has; or fails it, as an unreachable swarm would.
size_t answer_fetch_of(
        int ns, TempCore& c, MockNetwork& net, const Held& held = {}, bool reached = true) {
    auto answered = answer_requests(
            net,
            [ns](const MockNetwork::SentRequest& r) { return is_fetch_of(r, ns); },
            [&](MockNetwork::SentRequest& r) {
                if (!reached)
                    return r.callback(false, true, 0, {}, std::nullopt);
                auto body = retrieved_body();
                for (const auto& [data, hash] : held)
                    body["messages"].push_back(retrieved_message(data, hash));
                nlohmann::json result{{"code", 200}, {"body", std::move(body)}};
                r.callback(true, false, 200, {}, nlohmann::json{{"results", {result}}}.dump());
            },
            1);
    TestHelper::drain(*c);
    return answered;
}

// The same for the group's own namespace: the fetch asking to join begins with, and the one every
// push follows.
size_t answer_fetch(TempCore& c, MockNetwork& net, const Held& held = {}, bool reached = true) {
    return answer_fetch_of(21, c, net, held, reached);
}

TEST_CASE(
        "Devices - a fetched message keeps the expiry the swarm reports for it",
        "[core][devices][fetch]") {
    Linking l;
    auto fetch_one = [](TempCore& c, std::span<const std::byte> data, sys_ms expiration) {
        auto* net = attach_mock_network(*c);
        TestHelper::fetch(*c, {config::Namespace::Devices}, nullptr);
        TestHelper::drain(*c);
        auto body = retrieved_body();
        body["messages"].push_back(retrieved_message(data, "M1", clock_now_ms(), expiration));
        nlohmann::json result{{"code", 200}, {"body", std::move(body)}};
        REQUIRE(answer_requests(
                        *net,
                        is_device_fetch,
                        [&](MockNetwork::SentRequest& r) {
                            r.callback(
                                    true,
                                    false,
                                    200,
                                    {},
                                    nlohmann::json{{"results", {result}}}.dump());
                        },
                        1) == 1);
        TestHelper::drain(*c);
    };

    SECTION("a group's message puts the group in view") {
        fetch_one(
                l.applicant,
                l.core->devices.build_device_group_message().message,
                clock_now_ms() + Devices::DEVICE_GROUP_TTL);
        auto state = l.applicant->devices.membership(await);
        CHECK(state.membership == device::Membership::DeviceGroupVisible);
        REQUIRE(state.others.size() == 1);
        CHECK(state.others[0].id == *TestHelper::group_id(*l.core));
    }

    SECTION("a link request takes it as its deadline") {
        auto deadline = std::chrono::floor<std::chrono::seconds>(clock_now_ms() + 7min);
        fetch_one(l.core, TestHelper::build_link_request(*l.applicant, *l.core).message, deadline);
        auto requests = l.core->devices.incoming_link_requests(await);
        REQUIRE(requests.size() == 1);
        CHECK(requests[0].expires == deadline);
    }
}

// Asks for a link from `c` and runs the job, answering the fetch it begins with as a swarm holding
// nothing new, so that the upload has been sent by the time this returns.  What it answers lands in
// `into`, once the upload is answered.
void request_link(TempCore& c, const device::GroupId& group, Asked& into) {
    c->devices.request_link(
            group, [&into](Expected<Devices::OutgoingLinkRequest> r) { into = std::move(r); });
    TestHelper::drain(*c);
    if (auto* net = dynamic_cast<MockNetwork*>(c->network()))
        answer_fetch(c, *net);
}

// The applicant asks to join the existing device's group, having first seen it in the swarm.
void request_link(Linking& l, Asked& into) {
    request_link(l.applicant, l.show_group(), into);
}

bool same(const Devices::OutgoingLinkRequest& a, const Devices::OutgoingLinkRequest& b) {
    return a.sas == b.sas && a.expires == b.expires;
}

// The link request carried by the oldest upload not yet answered.  Read before answering it, since
// answering takes it off the list.
std::vector<std::byte> uploaded(MockNetwork& net) {
    auto sent = pushes(net);
    REQUIRE(!sent.empty());
    auto store = push_requests(*sent.front())[0]["params"];
    return to_vector<std::byte>(oxenc::from_base64(store["data"].get<std::string_view>()));
}

// Answers the oldest upload not yet answered as the swarm would: storing it, or refusing it.
void answer_upload(TempCore& c, MockNetwork& net, bool stored) {
    auto answered = answer_requests(
            net,
            "sequence",
            [stored](MockNetwork::SentRequest& r) {
                // One result per store, in order, as the swarm answers: a group push can carry the
                // account's key beside it.
                auto results = nlohmann::json::array();
                for (const auto& req : push_requests(r))
                    if (req["method"] == "store") {
                        auto hash = results.empty() ? "L1"s : "L1-{}"_format(results.size());
                        results.push_back(
                                stored ? nlohmann::json{{"code", 200}, {"body", {{"hash", hash}}}}
                                       : nlohmann::json{{"code", 406}, {"body", "refused"}});
                    }
                r.callback(true, false, 200, {}, nlohmann::json{{"results", results}}.dump());
            },
            1);
    REQUIRE(answered == 1);
    TestHelper::drain(*c);
}

device::State own_state(TempCore& c) {
    return c->devices.device_info(await).first.state;
}

// What `membership()` lists as the groups starting one would replace: its group and its others.
std::vector<device::GroupId> in_view(const device::MembershipState& state) {
    std::vector<device::GroupId> out;
    if (state.group)
        out.push_back(*state.group);
    for (const auto& g : state.others)
        out.push_back(g.id);
    return out;
}

// Starts a group as an application does once its user has confirmed replacing what is in view.
device::GroupId start_over(TempCore& c) {
    return c->devices.start_device_group(in_view(c->devices.membership(await)), await);
}

}  // namespace

TEST_CASE(
        "Devices - a requested link is uploaded, prompted for elsewhere, and its admission "
        "reported",
        "[core][devices][linking][request]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l, got);

    auto sent = pushes(*net);
    REQUIRE(sent.size() == 1);
    auto store = push_requests(*sent[0])[0]["params"];
    CHECK(store["namespace"] == 21);
    CHECK(store["ttl"] == std::chrono::milliseconds{Devices::LINK_REQUEST_TTL}.count());
    auto message = uploaded(*net);

    // Not answered, nor there to be read, until the swarm has it: until then there is nothing
    // another device could accept.
    CHECK_FALSE(got);
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());
    auto asked = **got;
    CHECK(asked.expires > clock_now_s() + 9min);
    CHECK(own_state(l.applicant) == device::State::Pending);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Requesting);

    // What the waiting screen is redrawn from is what it was first drawn from.
    auto waiting = l.applicant->devices.outgoing_link_request(await);
    REQUIRE(waiting);
    CHECK(same(*waiting, asked));

    // The other device prompts with what this one shows, and the user, seeing them match there,
    // approves it.
    TestHelper::deliver_device_message(*l.core, message, asked.expires, "L1");
    REQUIRE(l.events.added.size() == 1);
    CHECK(l.events.added[0].sas == asked.sas);
    REQUIRE(l.core->devices.accept_request(l.events.added[0].id, await));
    auto group = l.core->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(*l.applicant, group, in(10min), "G1");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Approved);
    waiting = l.applicant->devices.outgoing_link_request(await);
    REQUIRE(waiting);
    CHECK(same(*waiting, asked));

    // And then here.  Seeing the group, being approved -- not asking, which it did itself -- and
    // then being admitted.
    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(l.applicant_events.membership == std::vector{
                                                   device::Membership::DeviceGroupVisible,
                                                   device::Membership::Approved,
                                                   device::Membership::InGroup});
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));
}

TEST_CASE(
        "Devices - a link request the swarm refused is withdrawn, and reported only as a failure",
        "[core][devices][linking][request]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l, got);
    answer_upload(l.applicant, *net, false);

    REQUIRE(got);
    REQUIRE_FALSE(got->has_value());
    CHECK(got->error().code == err::store_failed);
    CHECK(own_state(l.applicant) == device::State::Unregistered);
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));

    // The caller has been told; that it is no longer waiting is not news.
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant_events.membership == std::vector{device::Membership::DeviceGroupVisible});
}

TEST_CASE(
        "Devices - a refused upload does not withdraw the request that replaced it",
        "[core][devices][linking][request]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked first, second;
    request_link(l, first);
    request_link(l, second);

    answer_upload(l.applicant, *net, false);
    REQUIRE(first);
    CHECK_FALSE(first->has_value());
    CHECK(own_state(l.applicant) == device::State::Pending);

    answer_upload(l.applicant, *net, true);
    REQUIRE(second);
    REQUIRE(second->has_value());
    CHECK(own_state(l.applicant) == device::State::Pending);
    auto waiting = l.applicant->devices.outgoing_link_request(await);
    REQUIRE(waiting);
    CHECK(same(*waiting, **second));
}

TEST_CASE(
        "Devices - asking again while a request is out reopens it",
        "[core][devices][linking][request]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked first, second;
    request_link(l, first);
    auto message = uploaded(*net);
    answer_upload(l.applicant, *net, true);
    REQUIRE(first);
    REQUIRE(first->has_value());

    // The same emoji and deadline, at once, with nothing uploaded.
    auto uploads = pushes(*net).size();
    request_link(l, second);
    REQUIRE(second);
    REQUIRE(second->has_value());
    CHECK(same(**second, **first));
    CHECK(pushes(*net).size() == uploads);

    // Approved, too, by an approval the asking itself fetches: it is not let go.
    TestHelper::deliver_device_message(*l.core, message, (*first)->expires, "L1");
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    Asked third;
    l.applicant->devices.request_link(
            *TestHelper::group_id(*l.core),
            [&third](Expected<Devices::OutgoingLinkRequest> r) { third = std::move(r); });
    TestHelper::drain(*l.applicant);
    REQUIRE(answer_fetch(
                    l.applicant,
                    *net,
                    {{l.core->devices.build_device_group_message().message, "G1"}}) == 1);
    REQUIRE(third);
    REQUIRE(third->has_value());
    CHECK(same(**third, **first));
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Approved);
    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
}

TEST_CASE(
        "Devices - asking to join fetches the group first, and asks under the key it finds",
        "[core][devices][linking][request]") {
    Linking l;
    l.admit();
    l.core->devices.mark_device_group_pushed(l.core->devices.build_device_group_message(), "G2");
    auto group = *TestHelper::group_id(*l.core);

    // A new device, which saw the group while the applicant was in it.
    TempCore asking{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::deliver_device_message(
            *asking, l.core->devices.build_device_group_message().message, in(10min), "G3");
    auto* net = attach_mock_network(*asking);

    // The applicant removed since, which moves the group to a key the applicant does not hold.
    REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
    auto since = l.core->devices.build_device_group_message().message;

    Asked got;
    asking->devices.request_link(
            group, [&got](Expected<Devices::OutgoingLinkRequest> r) { got = std::move(r); });
    TestHelper::drain(*asking);
    CHECK(pushes(*net).empty());
    auto prompts = l.events.added.size();

    SECTION("finding the group as it is now: asked under its current key, and prompted for") {
        REQUIRE(answer_fetch(asking, *net, {{since, "G4"}}) == 1);
        auto message = uploaded(*net);
        answer_upload(asking, *net, true);
        REQUIRE(got);
        REQUIRE(got->has_value());
        TestHelper::deliver_device_message(*l.core, message, (*got)->expires, "L2");
        CHECK(l.events.added.size() == prompts + 1);
    }

    SECTION("finding nothing newer: under the key it saw, which the removed device holds") {
        REQUIRE(answer_fetch(asking, *net) == 1);
        auto message = uploaded(*net);
        answer_upload(asking, *net, true);
        REQUIRE(got);
        REQUIRE(got->has_value());
        TestHelper::deliver_device_message(*l.core, message, (*got)->expires, "L2");
        CHECK(l.events.added.size() == prompts);
    }
}

TEST_CASE(
        "Devices - what the fetch before asking finds can stop the asking",
        "[core][devices][linking][request]") {
    Linking l;
    auto group = l.show_group();
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    l.applicant->devices.request_link(
            group, [&got](Expected<Devices::OutgoingLinkRequest> r) { got = std::move(r); });
    TestHelper::drain(*l.applicant);

    SECTION("the swarm out of reach") {
        while (!got && answer_fetch(l.applicant, *net, {}, false))
            ;
        REQUIRE(got);
        REQUIRE_FALSE(got->has_value());
        CHECK(got->error().code == err::network_unavailable);
    }

    SECTION("the group dissolved since") {
        REQUIRE(answer_fetch(
                        l.applicant,
                        *net,
                        {{TestHelper::build_dissolution(*l.core, {group}), "T1"}}) == 1);
        REQUIRE(got);
        REQUIRE_FALSE(got->has_value());
        CHECK(got->error().code == err::unknown_group);
    }

    CHECK(pushes(*net).empty());
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));
    CHECK(own_state(l.applicant) == device::State::Unregistered);
}

TEST_CASE(
        "Devices - an unanswered link request lapses at its deadline",
        "[core][devices][linking][request]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l, got);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());

    REQUIRE(l.applicant_events.membership == std::vector{device::Membership::DeviceGroupVisible});
    l.applicant_events.membership.clear();

    // Brought to within a second of the deadline, and the timer re-armed from there, so that it is
    // the timer that finds the request lapsed rather than anything this test does.
    ScopedClockOffset later{Devices::LINK_REQUEST_TTL - 1s};
    TestHelper::finish_fetch(*l.applicant);
    REQUIRE(l.applicant_events.membership.empty());

    REQUIRE(eventually(*l.applicant, [&] { return !l.applicant_events.membership.empty(); }));
    CHECK(l.applicant_events.membership == std::vector{device::Membership::DeviceGroupVisible});
    CHECK(own_state(l.applicant) == device::State::Unregistered);
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));
}

namespace {
void restart_applicant(Linking& l) {
    l.applicant.core.reset();
    l.applicant.core = std::make_unique<core::Core>(
            l.applicant.path, Linking::reporting_to(l.applicant_events));
}
}  // namespace

TEST_CASE(
        "Devices - a link request left waiting at shutdown is still waiting after a restart",
        "[core][devices][linking][request]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l, got);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());

    restart_applicant(l);

    CHECK(own_state(l.applicant) == device::State::Pending);
    auto waiting = l.applicant->devices.outgoing_link_request(await);
    REQUIRE(waiting);
    CHECK(same(*waiting, **got));

    // And it still lapses, with no fetch to notice: the restart re-arms its deadline.  Reported
    // once a fetch has made where it stands known again.
    ScopedClockOffset later{Devices::LINK_REQUEST_TTL - 1s};
    restart_applicant(l);
    l.applicant_events.membership.clear();
    REQUIRE(eventually(
            *l.applicant, [&] { return own_state(l.applicant) == device::State::Unregistered; }));
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant_events.membership == std::vector{device::Membership::DeviceGroupVisible});
}

TEST_CASE(
        "Devices - a link request never confirmed stored is withdrawn at the next start",
        "[core][devices][linking][request]") {
    Linking l;
    attach_mock_network(*l.applicant);
    Asked got;
    request_link(l, got);
    REQUIRE(own_state(l.applicant) == device::State::Pending);

    restart_applicant(l);
    l.applicant_events.membership.clear();

    CHECK(own_state(l.applicant) == device::State::Unregistered);
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant_events.membership == std::vector{device::Membership::DeviceGroupVisible});
}

TEST_CASE(
        "Devices - a link is not requested without a network, or by a device already in the group",
        "[core][devices][linking][request]") {
    Linking l;
    Asked got;

    SECTION("no network") {
        request_link(l, got);
        REQUIRE(got);
        REQUIRE_FALSE(got->has_value());
        CHECK(got->error().code == err::network_unavailable);
        CHECK(own_state(l.applicant) == device::State::Unregistered);
    }

    SECTION("already registered") {
        attach_mock_network(*l.core);
        request_link(l.core, *TestHelper::group_id(*l.core), got);
        REQUIRE(got);
        REQUIRE_FALSE(got->has_value());
        CHECK(got->error().code == err::already_registered);
        CHECK(own_state(l.core) == device::State::Registered);
    }
}

TEST_CASE(
        "Devices - a group's identifier is carried readably only for seed holders",
        "[core][devices][group-id]") {
    TempCore c;
    auto id = TestHelper::group_id(*c);
    REQUIRE(id);
    CHECK(std::chrono::abs(id->created() - clock_now()) <= 1min);

    auto m1 = c->devices.build_device_group_message().message;
    auto m2 = c->devices.build_device_group_message().message;
    CHECK(TestHelper::group_of(*c, m1) == id);
    CHECK(TestHelper::group_of(*c, m2) == id);

    // To anyone without the seed it is different in every message, so nothing links them.
    auto at = [](std::span<const std::byte> msg) {
        oxenc::bt_dict_consumer outer{msg};
        auto v = outer.require_span<std::byte>("@");
        return std::vector<std::byte>{v.begin(), v.end()};
    };
    CHECK(at(m1) != at(m2));
    CHECK(std::ranges::search(m1, id->value).empty());
}

TEST_CASE(
        "Devices - groups seen in the swarm are remembered, with the key to ask them on",
        "[core][devices][group-id]") {
    Linking l;
    auto group = TestHelper::group_id(*l.core);
    REQUIRE(group);
    auto key = [&] { return l.core->devices.active_account_keys().front().x25519_pub; };

    // A group the applicant cannot read is still a group it can see, and ask to join.
    auto first_key = key();
    auto first = l.core->devices.build_device_group_message().message;
    auto expiry = in(10min);
    TestHelper::deliver_device_message(*l.applicant, first, expiry, "G1");
    auto seen = TestHelper::seen_group(*l.applicant, *group);
    REQUIRE(seen);
    CHECK(seen->first == first_key);
    CHECK(seen->second == epoch_seconds(expiry));

    // The key follows the group's newest message, by when it was written rather than when it
    // arrived, whichever order they arrive in.
    l.core->devices.rotate_account_keys();
    auto second_key = key();
    REQUIRE(second_key != first_key);
    std::vector<std::byte> second;
    {
        ScopedClockOffset later{1h};
        second = l.core->devices.build_device_group_message().message;
        TestHelper::deliver_device_message(*l.applicant, second, in(10min), "G2");
    }
    CHECK(TestHelper::seen_group(*l.applicant, *group)->first == second_key);
    TestHelper::deliver_device_message(*l.applicant, first, expiry, "G1");
    CHECK(TestHelper::seen_group(*l.applicant, *group)->first == second_key);

    // Not from a message whose signature does not check out, newer though it is: anything else
    // could plant a key of its own for requests to this group to be encrypted to.
    {
        ScopedClockOffset later{2h};
        auto forged = l.core->devices.build_device_group_message().message;
        oxenc::bt_dict_consumer outer{forged};
        auto x_at = outer.require_span<std::byte>("X").data() - forged.data();
        forged[x_at] ^= std::byte{1};
        TestHelper::deliver_device_message(*l.applicant, forged, in(10min), "G3");
    }
    CHECK(TestHelper::seen_group(*l.applicant, *group)->first == second_key);
}

TEST_CASE(
        "Devices - a group message dated too far ahead of this device's clock is ignored",
        "[core][devices][group-id]") {
    Linking l;
    l.admit();
    TempCore outsider{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    auto group = *TestHelper::group_id(*l.core);

    // The applicant renames itself, and pushes from a clock running `ahead`.
    auto renamed = l.applicant->devices.device_info(await).first;
    auto push = [&](std::string description, std::chrono::minutes ahead, std::string hash) {
        renamed.description = description;
        l.applicant->devices.update_info(renamed, await);
        std::vector<std::byte> message;
        {
            ScopedClockOffset fast{ahead};
            message = l.applicant->devices.build_device_group_message().message;
        }
        TestHelper::deliver_device_message(*l.core, message, in(10min), hash);
        TestHelper::deliver_device_message(*outsider, message, in(10min), hash);
    };

    // Neither merged nor noted as the group's newest, which would hold back every honest message
    // for as long as it is ahead.
    push("from the future", Devices::GROUP_MESSAGE_MAX_AHEAD + 1min, "G2");
    CHECK(l.state_of_applicant().description != "from the future");
    CHECK_FALSE(TestHelper::seen_group(*outsider, group));

    // A clock merely running fast is another matter.
    push("a little fast", Devices::GROUP_MESSAGE_MAX_AHEAD - 1min, "G3");
    CHECK(l.state_of_applicant().description == "a little fast");
    CHECK(TestHelper::seen_group(*outsider, group));
}

TEST_CASE(
        "Devices - a group identifier says when its group was created",
        "[core][devices][group-id]") {
    device::GroupId id{};
    oxenc::write_host_as_little(uint32_t{29'600'000}, id.value.data());
    CHECK(id.created().time_since_epoch() == 29'600'000min);

    // The emoji come from a hash rather than the bytes, so groups created in the same minute -- the
    // same leading half -- still look different.
    auto other = id;
    other.value[7] = std::byte{1};
    CHECK(id.sas() != other.sas());
    CHECK(id.sas() == device::GroupId{id.value}.sas());
}

TEST_CASE(
        "Devices - an admitted device takes on its group's identifier",
        "[core][devices][group-id]") {
    Linking l;
    CHECK_FALSE(TestHelper::group_id(*l.applicant));
    l.admit();
    CHECK(TestHelper::group_id(*l.applicant) == TestHelper::group_id(*l.core));
}

TEST_CASE(
        "Devices - a readable message from another group is not merged",
        "[core][devices][group-id]") {
    Linking l;
    l.admit();
    auto ours = TestHelper::group_id(*l.core);
    REQUIRE(ours);

    device::Info info{};
    info.description = "changed";
    l.core->devices.update_info(info, await);
    auto other = *ours;
    other.value[7] ^= std::byte{0xff};
    TestHelper::set_group_id(*l.core, other);
    auto message = l.core->devices.build_device_group_message().message;

    TestHelper::deliver_device_message(*l.applicant, message, in(10min), "G2");
    auto [core_self, _] = l.core->devices.device_info(await);
    auto seen = l.applicant->devices.devices(true, false, false, core_self.id);
    REQUIRE(seen.size() == 1);
    CHECK(seen.begin()->second.description != "changed");
    CHECK(TestHelper::group_id(*l.applicant) == ours);
}

TEST_CASE(
        "Devices - a link request is readable only by the group it asks to join",
        "[core][devices][linking]") {
    Linking l;

    // A seed holder outside the group -- what a removed device is.  It must learn nothing from a
    // request: not the applicant's keys, not its SAS, not that there is one.
    DeviceEventsRecorder outsider_events;
    TempCore outsider{
            core::predefined_seed{std::span<const std::byte, 32>{l.seed}},
            Linking::reporting_to(outsider_events)};

    auto req = TestHelper::build_link_request(*l.applicant, *l.core);
    TestHelper::deliver_device_message(*outsider, req.message, in(10min), "L1");
    CHECK(outsider_events.added.empty());
    CHECK(outsider->devices.link_requests(await).empty());

    // Nor does the key indicator say which group's key the request is for, to anyone without the
    // seed: the group's key is visible in its messages, and a bare prefix of it would match.
    oxenc::bt_dict_consumer outer{req.message};
    auto indicator = outer.require_span<std::byte, 2>("i");
    auto key = l.core->devices.active_account_keys().front().x25519_pub;
    CHECK_FALSE((indicator[0] == key[0] && indicator[1] == key[1]));

    TestHelper::deliver_device_message(*l.core, req.message, in(10min), "L1");
    REQUIRE(l.events.added.size() == 1);
    CHECK(l.events.added[0].sas == req.sas);
}

TEST_CASE(
        "Devices - a link request not signed by the account is not prompted for",
        "[core][devices][linking]") {
    Linking l;
    auto k = l.applicant->devices.active_device_keys().front();

    // A request anything could encrypt, since the group's link key is published.
    auto request = [&](std::optional<std::span<const std::byte, 64>> signer) {
        oxenc::bt_dict_producer out;
        out.append("I", l.applicant_id());
        {
            auto i = out.append_dict("i");
            i.append("#", 1);
            i.append("@", epoch_seconds(clock_now_s()));
            i.append("M", k.mlkem768_pub);
            i.append("X", k.x25519_pub);
        }
        if (signer)
            out.append_signature("~", [&](std::span<const std::byte> body) {
                return ed25519::sign(*signer, body);
            });
        auto s = std::move(out).str();
        return TestHelper::encrypt_link_request(*l.applicant, *l.core, to_span(s));
    };

    b32 other_pk;
    b64 other_sk;
    ed25519::keypair(other_pk, other_sk);

    TestHelper::deliver_device_message(*l.core, request(std::nullopt), in(10min), "L1");
    TestHelper::deliver_device_message(*l.core, request(other_sk), in(10min), "L2");
    CHECK(l.events.added.empty());

    // The same request, signed as the account: so it was the signature that was missing above.
    auto seed = l.applicant->globals.account_seed();
    TestHelper::deliver_device_message(*l.core, request(seed.ed25519_secret()), in(10min), "L3");
    CHECK(l.events.added.size() == 1);
}

TEST_CASE(
        "Devices - a link request survives the group rotating its key",
        "[core][devices][linking]") {
    Linking l;

    // Asked on the key the applicant last saw, which the group has since moved on from.
    auto req = TestHelper::build_link_request(*l.applicant, *l.core);
    l.core->devices.rotate_account_keys();

    TestHelper::deliver_device_message(*l.core, req.message, in(10min), "L1");
    REQUIRE(l.events.added.size() == 1);
    CHECK(l.events.added[0].sas == req.sas);
}

TEST_CASE(
        "Devices - membership is unknown until the first fetch says otherwise",
        "[core][devices][membership]") {
    DeviceEventsRecorder events;
    TempCore c{Linking::reporting_to(events)};

    // In a group by its own record, but that record may be stale: removed, or cut off, while away.
    auto before = c->devices.membership(await);
    CHECK(before.membership == device::Membership::Unknown);

    TestHelper::finish_fetch(*c);
    auto after = c->devices.membership(await);
    CHECK(after.membership == device::Membership::InGroup);
    CHECK(after.group == TestHelper::group_id(*c));
    CHECK(after.others.empty());
    CHECK(events.membership == std::vector{device::Membership::InGroup});
}

TEST_CASE(
        "Devices - a device outside any group sees whether there are groups to join",
        "[core][devices][membership]") {
    Linking l;
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::NoGroup);

    auto group = l.show_group();
    auto state = l.applicant->devices.membership(await);
    CHECK(state.membership == device::Membership::DeviceGroupVisible);
    CHECK_FALSE(state.group);
    REQUIRE(state.others.size() == 1);
    CHECK(state.others[0].id == group);
    CHECK(l.applicant_events.membership ==
          std::vector{device::Membership::NoGroup, device::Membership::DeviceGroupVisible});
}

namespace {
// Counted directly: active_account_keys() mints one when there are none.
int account_key_count(TempCore& c) {
    return c->database().conn().prepared_get<int>("SELECT count(*) FROM device_account_keys");
}

// The code a call failed with, or empty if it did not.
template <typename F>
std::string failure_code(F&& f) {
    try {
        f();
    } catch (const session::error& e) {
        return std::string{e.err().code};
    }
    return {};
}
}  // namespace

TEST_CASE(
        "Devices - a second group beside ours is a fork, until the user keeps one",
        "[core][devices][membership][dissolve]") {
    Linking l;
    TestHelper::finish_fetch(*l.core);
    auto ours = *TestHelper::group_id(*l.core);
    auto* net = attach_mock_network(*l.core);

    // Another device on the account starts a group of its own.
    TestHelper::start_device_group(*l.applicant);
    auto second = *TestHelper::group_id(*l.applicant);
    auto written = std::chrono::floor<std::chrono::seconds>(clock_now_s());
    TestHelper::deliver_device_message(
            *l.core, l.applicant->devices.build_device_group_message().message, in(10min), "B1");

    auto state = l.core->devices.membership(await);
    CHECK(state.membership == device::Membership::Forked);
    CHECK(l.events.membership.back() == device::Membership::Forked);
    CHECK(state.group == ours);
    REQUIRE(state.others.size() == 1);
    CHECK(state.others[0].id == second);
    CHECK(std::chrono::abs(state.others[0].last_seen - written) <= 1s);

    // Nothing is wrong with its group, which goes on working while the user decides.
    CHECK(l.core->devices.needs_push().device_group);

    // Only another group in view can be dissolved, and only from here.
    CHECK_THROWS_AS(l.core->devices.dissolve_group(ours, await), std::invalid_argument);
    CHECK_FALSE(l.core->devices.dissolve_group(device::GroupId{}, await));

    // The user keeps this one.
    REQUIRE(l.core->devices.dissolve_group(second, await));
    state = l.core->devices.membership(await);
    CHECK(state.membership == device::Membership::InGroup);
    CHECK(state.others.empty());
    CHECK(l.core->devices.needs_push().device_group);
    // Its own doing, so not news to it.
    CHECK(l.events.membership.back() == device::Membership::Forked);

    // The other group's message deleted, and a tombstone naming it published in the same push --
    // the latest one, after this group's own.
    auto sent = pushes(*net);
    REQUIRE(!sent.empty());
    auto reqs = push_requests(*sent.back());
    REQUIRE(reqs.size() == 2);
    CHECK(reqs[0]["method"] == "store");
    CHECK(reqs[1]["method"] == "delete");
    CHECK(reqs[1]["params"]["messages"] == nlohmann::json::array({"B1"}));
    auto tombstone = to_vector<std::byte>(
            oxenc::from_base64(reqs[0]["params"]["data"].get<std::string_view>()));
    TestHelper::deliver_device_message(*l.applicant, tombstone, in(10min), "T1");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Dissolved);

    // Nothing left to dissolve.
    CHECK_FALSE(l.core->devices.dissolve_group(second, await));
}

TEST_CASE(
        "Devices - a device whose group is gone beside another is dropped",
        "[core][devices][membership]") {
    Linking l;
    auto old_id = Linking::id_of(l.core);

    // Another group, whose message outlives everything we know of our own.
    TestHelper::start_device_group(*l.applicant);
    auto theirs = *TestHelper::group_id(*l.applicant);
    TestHelper::deliver_device_message(
            *l.core,
            l.applicant->devices.build_device_group_message().message,
            in(1min) + Devices::DEVICE_GROUP_TTL + 1h,
            "B1");
    REQUIRE(l.core->devices.membership(await).membership == device::Membership::Forked);

    // Ours gone from the swarm, as far as we can tell; theirs not.  Whatever became of ours, the
    // account's group is now the other: nothing to push, and nothing for this device to dissolve.
    ScopedClockOffset later{Devices::DEVICE_GROUP_TTL + 1h};
    TestHelper::finish_fetch(*l.core);
    CHECK(l.core->devices.membership(await).membership == device::Membership::Dropped);
    CHECK(l.events.membership.back() == device::Membership::Dropped);
    CHECK_FALSE(l.core->devices.needs_push().device_group);
    CHECK_FALSE(l.core->devices.dissolve_group(theirs, await));

    // It comes back as a new device, like a removed one.
    auto* net = attach_mock_network(*l.core);
    Asked got;
    request_link(l.core, theirs, got);
    answer_upload(l.core, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());
    CHECK(Linking::id_of(l.core) != old_id);
    CHECK(l.core->devices.membership(await).membership == device::Membership::Requesting);
}

TEST_CASE(
        "Devices - a device whose group is dissolved leaves it behind, under a new id",
        "[core][devices][dissolve]") {
    Linking l;
    l.admit();
    auto group = *TestHelper::group_id(*l.core);
    auto old_id = l.applicant_id();
    auto leftover = l.core->devices.build_device_group_message().message;

    // Another of the account's devices, whose user chose to keep a group of its own.
    ScopedClockOffset later{1min};
    TempCore keeper{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::deliver_device_message(
            *l.applicant, TestHelper::build_dissolution(*keeper, {group}), in(10min), "T1");

    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Dissolved);
    CHECK(l.applicant_events.membership.back() == device::Membership::Dissolved);
    CHECK(l.applicant_id() != old_id);
    CHECK(l.applicant->devices.devices(true, true, true).empty());
    CHECK_FALSE(TestHelper::group_id(*l.applicant));
    CHECK(account_key_count(l.applicant) == 0);
    CHECK_FALSE(l.applicant->devices.needs_push().device_group);

    // What the group left behind is nothing to it now, nor something it could join.
    TestHelper::deliver_device_message(*l.applicant, leftover, in(10min), "G2");
    CHECK(l.applicant->devices.membership(await).others.empty());
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Dissolved);

    // Until it starts or joins a group.
    start_over(l.applicant);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
}

TEST_CASE("Devices - a dissolved group is no longer one to join", "[core][devices][dissolve]") {
    Linking l;
    auto theirs = l.show_group();
    TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_device_group(*other);
    auto second = *TestHelper::group_id(*other);
    TestHelper::deliver_device_message(
            *l.applicant, other->devices.build_device_group_message().message, in(10min), "B1");
    REQUIRE(l.applicant->devices.membership(await).others.size() == 2);

    // One tombstone, naming both.
    TestHelper::deliver_device_message(
            *l.applicant, TestHelper::build_dissolution(*other, {theirs, second}), in(10min), "T1");
    auto state = l.applicant->devices.membership(await);
    CHECK(state.membership == device::Membership::NoGroup);
    CHECK(state.others.empty());
}

namespace {
// The message stored by a push, and what it deleted.
std::pair<std::vector<std::byte>, nlohmann::json> pushed(const MockNetwork::SentRequest& push) {
    auto reqs = push_requests(push);
    std::vector<std::byte> stored;
    nlohmann::json deleted = nlohmann::json::array();
    for (const auto& req : reqs) {
        // Namespace 21's: the account's key for contacts, to -21, can go out beside it.
        if (req["method"] == "store" && req["params"]["namespace"] == 21)
            stored = to_vector<std::byte>(
                    oxenc::from_base64(req["params"]["data"].get<std::string_view>()));
        else if (req["method"] == "delete")
            deleted = req["params"]["messages"];
    }
    return {stored, deleted};
}

// The pushes that are not our own group's: tombstones and deletions.
std::vector<MockNetwork::SentRequest*> dissolutions(MockNetwork& net) {
    std::vector<MockNetwork::SentRequest*> out;
    for (auto* p : pushes(net)) {
        auto [stored, deleted] = pushed(*p);
        if (stored.empty() ? !deleted.empty()
                           : oxenc::bt_dict_consumer{stored}.require<std::string_view>("") != "G")
            out.push_back(p);
    }
    return out;
}
}  // namespace

TEST_CASE(
        "Devices - a dissolved group seen again is dissolved again", "[core][devices][dissolve]") {
    Linking l;
    TestHelper::finish_fetch(*l.core);
    auto* net = attach_mock_network(*l.core);

    // A group of one device, beside ours, with a message of it ours never sees until later.
    TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_device_group(*other);
    auto theirs = *TestHelper::group_id(*other);
    auto leftover = other->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(
            *l.core, other->devices.build_device_group_message().message, in(10min), "B1");

    ScopedClockOffset later{1min};
    REQUIRE(l.core->devices.dissolve_group(theirs, await));
    REQUIRE(dissolutions(*net).size() == 1);
    auto [first_tombstone, first_deleted] = pushed(*dissolutions(*net)[0]);
    CHECK(first_deleted == nlohmann::json::array({"B1"}));

    // Something the dissolving device did not know to delete: deleted, and that is all.
    TestHelper::deliver_device_message(*l.core, leftover, in(10min), "B0");
    REQUIRE(dissolutions(*net).size() == 2);
    auto [none, leftover_deleted] = pushed(*dissolutions(*net)[1]);
    CHECK(none.empty());
    CHECK(leftover_deleted == nlohmann::json::array({"B0"}));

    // Its device back after the tombstone has gone, pushing again: told again, and that message
    // deleted too.
    later.advance(1min);
    auto back = other->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(*l.core, back, in(10min), "B2");
    CHECK(l.core->devices.membership(await).membership == device::Membership::InGroup);
    REQUIRE(dissolutions(*net).size() == 3);
    auto [tombstone, deleted] = pushed(*dissolutions(*net)[2]);
    CHECK(deleted == nlohmann::json::array({"B2"}));
    TestHelper::deliver_device_message(*other, tombstone, in(10min), "T2");
    CHECK(other->devices.membership(await).membership == device::Membership::Dissolved);

    // A device outside any group is in no position to decide which group is the account's: it
    // knows of the dissolution, but takes a group pushing since it as any other.
    TestHelper::deliver_device_message(*l.applicant, first_tombstone, in(10min), "T1");
    TestHelper::deliver_device_message(*l.applicant, leftover, in(10min), "B0");
    CHECK(l.applicant->devices.membership(await).others.empty());
    TestHelper::deliver_device_message(*l.applicant, back, in(10min), "B2");
    auto seen = l.applicant->devices.membership(await).others;
    REQUIRE(seen.size() == 1);
    CHECK(seen[0].id == theirs);
}

TEST_CASE(
        "Devices - a device back after its group lapsed dissolves again what it saw dissolved",
        "[core][devices][dissolve]") {
    Linking l;
    TestHelper::finish_fetch(*l.core);
    auto* net = attach_mock_network(*l.core);

    TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_device_group(*other);
    auto theirs = *TestHelper::group_id(*other);
    TestHelper::deliver_device_message(
            *l.core, other->devices.build_device_group_message().message, in(10min), "B1");
    // Its own group's push, which would hold back every later one until answered.
    answer_upload(l.core, *net, true);
    REQUIRE(l.core->devices.dissolve_group(theirs, await));
    REQUIRE(dissolutions(*net).size() == 1);

    // Away for longer than its group's messages last, and back to find nothing of it: either an
    // empty swarm, or a third group, which leaves it dropped.
    bool dropped = GENERATE(false, true);
    TempCore third{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_device_group(*third);
    if (dropped)
        TestHelper::deliver_device_message(
                *l.core,
                third->devices.build_device_group_message().message,
                in(1min) + Devices::DEVICE_GROUP_TTL + 1h,
                "C1");
    ScopedClockOffset later{Devices::DEVICE_GROUP_TTL + 1h};
    auto expected = dropped ? device::Membership::Dropped : device::Membership::InGroup;
    REQUIRE(l.core->devices.membership(await).membership == expected);

    // The dissolved group's device, back too and never told, in the first fetch since.  Telling it
    // again decides nothing, so even a dropped device does it; the third group it leaves alone.
    // Before anything else, too: the rotation all that time away has made due, and the push
    // carrying it, come after the fetch.
    auto before = pushes(*net).size();
    auto back = other->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(*l.core, back, in(10min), "B2");
    auto sent = pushes(*net);
    REQUIRE(sent.size() > before);
    auto [tombstone, deleted] = pushed(*sent[before]);
    CHECK(oxenc::bt_dict_consumer{tombstone}.require<std::string_view>("") == "T");
    CHECK(deleted == nlohmann::json::array({"B2"}));
    TestHelper::deliver_device_message(*other, tombstone, in(10min), "T2");
    CHECK(other->devices.membership(await).membership == device::Membership::Dissolved);
    TestHelper::deliver_device_message(*third, tombstone, in(10min), "T2");
    CHECK(third->devices.membership(await).membership == device::Membership::InGroup);

    // And then its own group again -- unless it is dropped, when the account's group is the third.
    CHECK(l.core->devices.membership(await).membership == expected);
    REQUIRE(sent.size() == before + (dropped ? 1 : 2));
    if (!dropped)
        CHECK(oxenc::bt_dict_consumer{pushed(*sent.back()).first}.require<std::string_view>("") ==
              "G");
}

TEST_CASE(
        "Devices - joining one of several groups dissolves the rest", "[core][devices][dissolve]") {
    Linking l;
    TestHelper::finish_fetch(*l.core);

    // Another group on the account, which the existing device sees too: forked.
    TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_device_group(*other);
    auto theirs = *TestHelper::group_id(*other);
    auto b1 = other->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(*l.core, b1, in(10min), "B1");
    REQUIRE(l.core->devices.membership(await).membership == device::Membership::Forked);

    // The new device sees both, and the user picks the existing device's.
    TestHelper::deliver_device_message(*l.applicant, b1, in(10min), "B1");
    auto ours = l.show_group();
    REQUIRE(l.applicant->devices.membership(await).others.size() == 2);
    auto* net = attach_mock_network(*l.applicant);
    l.admit();

    // Completing the join is the choice of that group over the other.
    auto state = l.applicant->devices.membership(await);
    CHECK(state.membership == device::Membership::InGroup);
    CHECK(state.group == ours);
    CHECK(state.others.empty());
    auto sent = dissolutions(*net);
    REQUIRE(sent.size() == 1);
    auto [tombstone, deleted] = pushed(*sent[0]);
    CHECK(deleted == nlohmann::json::array({"B1"}));

    // Which the other group's device, and the existing device it forked, both hear of.
    TestHelper::deliver_device_message(*other, tombstone, in(10min), "T1");
    CHECK(other->devices.membership(await).membership == device::Membership::Dissolved);
    TestHelper::deliver_device_message(*l.core, tombstone, in(10min), "T1");
    CHECK(l.core->devices.membership(await).membership == device::Membership::InGroup);
    CHECK(l.core->devices.membership(await).others.empty());
    CHECK(theirs != ours);
}

TEST_CASE(
        "Devices - ignoring a request deletes it from the swarm only when asked to",
        "[core][devices][linking]") {
    Linking l;
    auto* net = attach_mock_network(*l.core);

    // The group's own pushes go the same way, so look for the deletion by what it names.
    auto deleted = [&](std::string_view hash) {
        for (auto* push : pushes(*net))
            for (const auto& req : push_requests(*push))
                if (req["method"] == "delete" &&
                    req["params"]["messages"] == nlohmann::json::array({hash}))
                    return true;
        return false;
    };

    l.ask(in(10min), "L1");
    REQUIRE(l.core->devices.ignore_request(l.events.added.at(0).id, await));
    TestHelper::drain(*l.core);
    CHECK_FALSE(deleted("L1"));

    // One the user does not recognise.
    l.ask(in(10min), "L2");
    REQUIRE(l.core->devices.ignore_request(l.events.added.at(1).id, true, await));
    TestHelper::drain(*l.core);
    CHECK(deleted("L2"));
}

TEST_CASE(
        "Devices - a device admitted only by an impostor's group does not join",
        "[core][devices][linking][confirm]") {
    Linking l;

    // A seed holder outside the real group -- a removed device, say -- publishes a group of its
    // own, and the applicant asks to join that one instead.
    DeviceEventsRecorder impostor_events;
    TempCore impostor{
            core::predefined_seed{std::span<const std::byte, 32>{l.seed}},
            Linking::reporting_to(impostor_events)};
    TestHelper::start_device_group(*impostor);
    auto req = TestHelper::build_link_request(*l.applicant, *impostor);

    // The real group cannot read the request, so it never prompts, and the user never sees a SAS
    // to compare.
    TestHelper::deliver_device_message(*l.core, req.message, in(10min), "L1");
    CHECK(l.events.added.empty());

    // The impostor can, and admits it.
    TestHelper::deliver_device_message(*impostor, req.message, in(10min), "L1");
    REQUIRE(impostor_events.added.size() == 1);
    REQUIRE(impostor->devices.accept_request(impostor_events.added[0].id, await));
    TestHelper::deliver_device_message(
            *l.applicant, impostor->devices.build_device_group_message().message, in(10min), "G1");

    // Readable, but not enough: with no confirmation from its user, who has no device of theirs
    // showing emoji to compare, it does not join.
    CHECK(own_state(l.applicant) == device::State::Pending);
    CHECK_FALSE(TestHelper::group_id(*l.applicant));
    CHECK(l.applicant_events.membership == std::vector{device::Membership::Approved});
}

TEST_CASE(
        "Devices - an admission held for confirmation survives its deadline and a restart",
        "[core][devices][linking][confirm]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l, got);
    auto message = uploaded(*net);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());

    TestHelper::deliver_device_message(*l.core, message, (*got)->expires, "L1");
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");
    REQUIRE(own_state(l.applicant) == device::State::Pending);
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Approved);

    // The approval came in time, so the request no longer lapses.
    ScopedClockOffset later{Devices::LINK_REQUEST_TTL + 1min};
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Approved);

    restart_applicant(l);
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Approved);
    CHECK(l.applicant_events.membership.back() == device::Membership::Approved);

    // The fetch that brought the admission will not bring it again; it was kept.
    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(own_state(l.applicant) == device::State::Registered);
    CHECK(TestHelper::group_id(*l.applicant) == TestHelper::group_id(*l.core));
}

TEST_CASE(
        "Devices - confirming before the approval is refused, and authorises nothing",
        "[core][devices][linking][confirm]") {
    Linking l;
    CHECK_FALSE(l.applicant->devices.confirm_link(await));

    l.ask();
    TestHelper::finish_fetch(*l.applicant);
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Requesting);
    CHECK_FALSE(l.applicant->devices.confirm_link(await));

    // The approval, when it comes, still waits for the user.
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");
    CHECK(own_state(l.applicant) == device::State::Pending);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Approved);

    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(own_state(l.applicant) == device::State::Registered);
}

TEST_CASE(
        "Devices - an admission after the request lapsed here still waits for the user",
        "[core][devices][linking][confirm]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l, got);
    auto message = uploaded(*net);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());
    TestHelper::deliver_device_message(*l.core, message, in(20min), "L1");
    l.applicant_events.membership.clear();

    // Lapsed here, by the timer, before the acceptance reached this device.
    ScopedClockOffset later{Devices::LINK_REQUEST_TTL + 1s};
    TestHelper::finish_fetch(*l.applicant);
    REQUIRE(eventually(*l.applicant, [&] { return !l.applicant_events.membership.empty(); }));
    REQUIRE(l.applicant_events.membership.back() == device::Membership::DeviceGroupVisible);

    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");

    // Not taken: any holder of the seed could have sent it.  Approved, and waiting on the user.
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Approved);
    CHECK(l.applicant_events.membership.back() == device::Membership::Approved);
    auto shown = l.applicant->devices.outgoing_link_request(await);
    REQUIRE(shown);
    CHECK(shown->sas == (**got).sas);

    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
}

TEST_CASE(
        "Devices - an admission on no request of this device's is not taken",
        "[core][devices][linking][confirm]") {
    Linking l;
    l.ask();
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));

    // As though it had never asked: what an impostor's group, admitting it unbidden, looks like.
    auto id = l.applicant_id();
    TestHelper::on_loop(*l.applicant, [&] {
        auto c = l.applicant->database().conn();
        c.prepared_exec("DELETE FROM device_own_requests");
        c.prepared_exec(
                "UPDATE devices SET state = ? WHERE unique_id = ?",
                static_cast<int>(device::State::Unregistered),
                id);
        return 0;
    });

    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");
    CHECK(l.applicant->devices.membership(await).membership ==
          device::Membership::DeviceGroupVisible);
    CHECK(own_state(l.applicant) == device::State::Unregistered);
    CHECK_FALSE(l.applicant->devices.confirm_link(await));
}

TEST_CASE(
        "Devices - an admission on a request since replaced is not taken",
        "[core][devices][linking][confirm]") {
    Linking l;
    l.ask();
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));

    // The user is looking at the newer one, whose emoji the accepting device never showed.
    TestHelper::build_link_request(*l.applicant, *l.core);
    TestHelper::finish_fetch(*l.applicant);
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Requesting);
    CHECK_FALSE(l.applicant->devices.confirm_link(await));
    CHECK(own_state(l.applicant) == device::State::Pending);
}

TEST_CASE(
        "Devices - a second admission does not replace the one held",
        "[core][devices][linking][confirm]") {
    Linking l;
    l.ask();
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Approved);

    // Another, readable and admitting the same record, saying something else of the group.
    auto group = l.core->devices.devices(true, true, true);
    auto core_id = Linking::id_of(l.core);
    group.at(core_id).description = "Not what the user approved";
    TestHelper::deliver_device_message(
            *l.applicant, TestHelper::encrypt_device_data(l.core->devices, group), in(10min), "G2");

    REQUIRE(l.applicant->devices.confirm_link(await));
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
    CHECK(l.applicant->devices.devices().at(core_id).description != "Not what the user approved");
}

TEST_CASE(
        "Devices - a description from the swarm is held to DESCRIPTION_MAX",
        "[core][devices][linking]") {
    Linking l;
    l.admit();
    auto core_id = Linking::id_of(l.core);
    // Otherwise the admission's record and the one below share a seqno, and the digest picks.
    l.core->devices.mark_device_group_pushed(l.core->devices.build_device_group_message(), "G1");

    SECTION("one at the cap arrives whole") {
        auto self = l.core->devices.device_info(await).first;
        self.description = at_cap;
        l.core->devices.update_info(self, await);
        TestHelper::deliver_device_message(
                *l.applicant,
                l.core->devices.build_device_group_message().message,
                in(10min),
                "G2");
        CHECK(l.applicant->devices.devices().at(core_id).description == at_cap);
    }

    SECTION("a longer one is held cut on a character boundary") {
        auto group = l.core->devices.devices(true, true, true);
        auto& record = group.at(core_id);
        record.description = straddling;
        record.seqno++;
        TestHelper::deliver_device_message(
                *l.applicant,
                TestHelper::encrypt_device_data(l.core->devices, group),
                in(10min),
                "G2");
        auto held = l.applicant->devices.devices().at(core_id);
        REQUIRE(held.seqno == record.seqno);
        CHECK(held.description == straddling_cut);
    }
}

TEST_CASE(
        "Devices - a link request under a key a removed device holds is not read",
        "[core][devices][linking][removal]") {
    Linking l;
    l.admit();

    // The group's key, delivered to both devices: by the admission, and by the existing device's
    // push once the swarm confirms it.
    auto key = l.core->devices.active_account_keys().front().x25519_pub;
    l.core->devices.mark_device_group_pushed(l.core->devices.build_device_group_message(), "G2");
    std::set<device::Id> both{Linking::id_of(l.core), l.applicant_id()};
    auto pushed_to = TestHelper::key_recipients(*l.core, key);
    CHECK(std::set(pushed_to.begin(), pushed_to.end()) == both);
    auto merged_to = TestHelper::key_recipients(*l.applicant, key);
    CHECK(std::set(merged_to.begin(), merged_to.end()) == both);

    // A new device asking under that key.
    TempCore asking{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    auto request = TestHelper::build_link_request(*asking, *l.core);
    REQUIRE(l.events.added.size() == 1);

    SECTION("rotated away from since: still read") {
        l.core->devices.rotate_account_keys();
        TestHelper::deliver_device_message(*l.core, request.message, in(10min), "L2");
        CHECK(l.events.added.size() == 2);
    }

    SECTION("held by a device removed since: not read") {
        REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
        TestHelper::deliver_device_message(*l.core, request.message, in(10min), "L2");
        CHECK(l.events.added.size() == 1);
    }
}

TEST_CASE(
        "Devices - starting a group with others in view dissolves them",
        "[core][devices][membership][dissolve]") {
    Linking l;
    TestHelper::finish_fetch(*l.core);
    auto theirs = l.show_group();
    REQUIRE(l.applicant_events.membership == std::vector{device::Membership::DeviceGroupVisible});
    auto held_before = l.applicant->devices.active_account_keys().front().x25519_pub;
    auto* net = attach_mock_network(*l.applicant);

    auto mine = start_over(l.applicant);
    CHECK(mine != theirs);

    // With a key of its own, not whatever it held before.
    CHECK(account_key_count(l.applicant) == 1);
    CHECK(l.applicant->devices.active_account_keys().front().x25519_pub != held_before);

    // The only group now, and nothing to alert about: the choice was this device's own.
    auto state = l.applicant->devices.membership(await);
    CHECK(state.membership == device::Membership::InGroup);
    CHECK(state.group == mine);
    CHECK(state.others.empty());
    CHECK(l.applicant_events.membership == std::vector{device::Membership::DeviceGroupVisible});

    // The other group's message deleted, and a tombstone naming it published.
    auto sent = pushes(*net);
    REQUIRE(sent.size() == 1);
    auto reqs = push_requests(*sent[0]);
    REQUIRE(reqs.size() == 2);
    CHECK(reqs[0]["method"] == "store");
    CHECK(reqs[1]["method"] == "delete");
    CHECK(reqs[1]["params"]["messages"] == nlohmann::json::array({"G0"}));

    // Which the devices of that group learn of, after which the group kept is the one they see.
    auto tombstone = to_vector<std::byte>(
            oxenc::from_base64(reqs[0]["params"]["data"].get<std::string_view>()));
    TestHelper::deliver_device_message(*l.core, tombstone, in(10min), "T1");
    CHECK(l.core->devices.membership(await).membership == device::Membership::Dissolved);
    TestHelper::deliver_device_message(
            *l.core, l.applicant->devices.build_device_group_message().message, in(10min), "B1");
    state = l.core->devices.membership(await);
    REQUIRE(state.others.size() == 1);
    CHECK(state.others[0].id == mine);
}

TEST_CASE(
        "Devices - a group is started only when the user can have decided to",
        "[core][devices][membership]") {
    Linking l;

    // Before any fetch, nothing is known of what the swarm holds.
    CHECK(failure_code([&] { start_over(l.applicant); }) == err::membership_unknown);

    // Requesting: starting a group instead withdraws the request.
    TestHelper::finish_fetch(*l.core);
    l.show_group();
    TestHelper::build_link_request(*l.applicant, *l.core);
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Requesting);
    start_over(l.applicant);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
    CHECK(own_state(l.applicant) == device::State::Registered);
}

TEST_CASE(
        "Devices - a device in a group does not ask to join another",
        "[core][devices][membership][linking]") {
    Linking l;
    l.admit();

    // Another group on the account, which the applicant sees: forked.
    TempCore third{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_device_group(*third);
    auto other = *TestHelper::group_id(*third);
    TestHelper::deliver_device_message(
            *l.applicant, third->devices.build_device_group_message().message, in(10min), "Y1");
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Forked);

    // An account has one group, so there is no switching: leaving comes first.
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l.applicant, other, got);
    REQUIRE(got);
    REQUIRE_FALSE(got->has_value());
    CHECK(got->error().code == err::already_registered);
    CHECK(pushes(*net).empty());
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));
    CHECK(own_state(l.applicant) == device::State::Registered);

    // Its user choosing the other group: leave, then ask.
    REQUIRE(l.applicant->devices.leave_group(await));
    CHECK(l.applicant->devices.membership(await).membership ==
          device::Membership::DeviceGroupVisible);
    got.reset();
    request_link(l.applicant, other, got);
    CHECK(own_state(l.applicant) == device::State::Pending);
    answer_upload(l.applicant, *net, true);  // the departure from the group it left
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    CHECK(got->has_value());
}

TEST_CASE(
        "Devices - a device leaving its group tells it, and forgets it",
        "[core][devices][membership][leave]") {
    Linking l;
    l.admit();
    auto group = *TestHelper::group_id(*l.core);
    auto* net = attach_mock_network(*l.applicant);
    auto old_id = l.applicant_id();

    REQUIRE(l.applicant->devices.leave_group(await));

    // Under a new identity, with nothing of the group left, though the group itself is still
    // there to see.
    CHECK(l.applicant_id() != old_id);
    CHECK(l.applicant->devices.devices(true, true, true).empty());
    CHECK_FALSE(TestHelper::group_id(*l.applicant));
    CHECK(account_key_count(l.applicant) == 0);
    auto state = l.applicant->devices.membership(await);
    CHECK(state.membership == device::Membership::DeviceGroupVisible);
    REQUIRE(state.others.size() == 1);
    CHECK(state.others[0].id == group);
    // Its own doing, so not news to it.
    CHECK(l.applicant_events.membership.back() == device::Membership::InGroup);

    // And the group hears of the departure, from a message it can read and the leaver will not
    // again, and moves to an account key the leaver does not hold: the one it was given, by the
    // push that admitted it.
    auto sent = pushes(*net);
    REQUIRE(sent.size() == 1);
    auto [farewell, deleted] = pushed(*sent[0]);
    REQUIRE_FALSE(farewell.empty());
    l.core->devices.mark_device_group_pushed(l.core->devices.build_device_group_message(), "G1");
    auto key_before = l.core->devices.active_account_keys().front().x25519_pub;
    TestHelper::deliver_device_message(*l.core, farewell, in(10min), "G9");
    CHECK(l.core->devices.devices(true, true, true, old_id).at(old_id).state ==
          device::State::Left);
    ScopedClockOffset later{Devices::KEY_ROTATION_JITTER + 1s};
    TestHelper::finish_fetch(*l.core);
    CHECK(l.core->devices.active_account_keys().front().x25519_pub != key_before);

    // Nothing more to leave.
    CHECK_FALSE(l.applicant->devices.leave_group(await));
}

TEST_CASE(
        "Devices - a device that left a group can join it again, as a new device",
        "[core][devices][membership][leave]") {
    Linking l;
    l.admit();
    auto group = *TestHelper::group_id(*l.core);
    auto old_id = l.applicant_id();
    auto* net = attach_mock_network(*l.applicant);
    REQUIRE(l.applicant->devices.leave_group(await));
    TestHelper::deliver_device_message(*l.core, pushed(*pushes(*net)[0]).first, in(10min), "G9");
    REQUIRE(l.core->devices.devices(true, true, true, old_id).at(old_id).state ==
            device::State::Left);

    // The id it left under is spent there; the one it holds now has never been seen.
    answer_upload(l.applicant, *net, true);
    Asked got;
    request_link(l.applicant, group, got);
    auto request = uploaded(*net);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());
    auto prompts = l.events.added.size();
    TestHelper::deliver_device_message(*l.core, request, (*got)->expires, "L2");
    REQUIRE(l.events.added.size() == prompts + 1);
    CHECK_FALSE(l.events.added.back().replaces);
    REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G10");
    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);

    // Both: the departure of the old id, and the new one in the group.
    auto held = l.core->devices.devices(true, true, true);
    CHECK(held.at(old_id).state == device::State::Left);
    CHECK(held.at(l.applicant_id()).state == device::State::Registered);
}

namespace {
int pending_pushes(TempCore& c) {
    return c->database().conn().prepared_get<int>("SELECT count(*) FROM device_pending_pushes");
}
}  // namespace

TEST_CASE(
        "Devices - a departure made without a network goes once there is one",
        "[core][devices][membership][leave]") {
    Linking l;
    l.admit();
    auto old_id = l.applicant_id();

    // Built, and kept, though nothing of the group is left to build it from again.
    REQUIRE(l.applicant->devices.leave_group(await));
    CHECK(pending_pushes(l.applicant) == 1);
    CHECK_FALSE(TestHelper::group_id(*l.applicant));

    SECTION("at the next fetch, and again until the swarm has it") {
        auto* net = attach_mock_network(*l.applicant);
        TestHelper::finish_fetch(*l.applicant);
        REQUIRE(pushes(*net).size() == 1);
        auto [farewell, deleted] = pushed(*pushes(*net)[0]);
        REQUIRE_FALSE(farewell.empty());

        answer_upload(l.applicant, *net, false);
        CHECK(pending_pushes(l.applicant) == 1);
        TestHelper::finish_fetch(*l.applicant);
        REQUIRE(pushes(*net).size() == 1);
        answer_upload(l.applicant, *net, true);
        CHECK(pending_pushes(l.applicant) == 0);

        // Nothing more to send.
        TestHelper::finish_fetch(*l.applicant);
        CHECK(pushes(*net).empty());

        TestHelper::deliver_device_message(*l.core, farewell, in(10min), "G9");
        CHECK(l.core->devices.devices(true, true, true, old_id).at(old_id).state ==
              device::State::Left);
    }

    SECTION("after a restart") {
        restart_applicant(l);
        auto* net = attach_mock_network(*l.applicant);
        TestHelper::finish_fetch(*l.applicant);
        REQUIRE(pushes(*net).size() == 1);
        auto [farewell, deleted] = pushed(*pushes(*net)[0]);
        TestHelper::deliver_device_message(*l.core, farewell, in(10min), "G9");
        CHECK(l.core->devices.devices(true, true, true, old_id).at(old_id).state ==
              device::State::Left);
    }

    SECTION("not once the group it was for has expired from the swarm") {
        ScopedClockOffset later{Devices::DEVICE_GROUP_TTL + 1min};
        auto* net = attach_mock_network(*l.applicant);
        TestHelper::finish_fetch(*l.applicant);
        CHECK(pushes(*net).empty());
        CHECK(pending_pushes(l.applicant) == 0);
    }
}

TEST_CASE(
        "Devices - a departure is stored in the same commit as the leaving",
        "[core][devices][membership][leave]") {
    Linking l;
    l.admit();
    auto old_id = l.applicant_id();
    auto group = *TestHelper::group_id(*l.applicant);
    auto sql = [&](const std::string& query) {
        TestHelper::on_loop(
                *l.applicant, [&] { return l.applicant->database().conn().prepared_exec(query); });
    };

    // Forgetting the group made to fail, after the departure is built, as an interruption there
    // would leave things.
    sql("CREATE TRIGGER interrupted BEFORE DELETE ON devices BEGIN SELECT RAISE(ABORT, 'x'); END");
    CHECK_THROWS(l.applicant->devices.leave_group(await));
    sql("DROP TRIGGER interrupted");

    // None of it, then: no departure waiting to go for a group still held.
    CHECK(pending_pushes(l.applicant) == 0);
    CHECK(TestHelper::group_id(*l.applicant) == group);
    CHECK(l.applicant_id() == old_id);
    CHECK(own_state(l.applicant) == device::State::Registered);

    // And all of it, done again.
    REQUIRE(l.applicant->devices.leave_group(await));
    CHECK(pending_pushes(l.applicant) == 1);
    CHECK_FALSE(TestHelper::group_id(*l.applicant));
    CHECK(l.applicant_id() != old_id);
}

TEST_CASE(
        "Devices - a dissolution made without a network goes once there is one",
        "[core][devices][dissolve]") {
    Linking l;
    TestHelper::finish_fetch(*l.core);
    TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_device_group(*other);
    auto theirs = *TestHelper::group_id(*other);
    TestHelper::deliver_device_message(
            *l.core, other->devices.build_device_group_message().message, in(10min), "B1");
    REQUIRE(l.core->devices.membership(await).membership == device::Membership::Forked);
    // Nothing of its own owed, so that the push the fetch sends below is the dissolution's.
    l.core->devices.mark_device_group_pushed(l.core->devices.build_device_group_message(), "G0");
    TestHelper::deliver_pubkey_message(*l.core, l.core->devices.build_account_pubkey_message());

    REQUIRE(l.core->devices.dissolve_group(theirs, await));
    CHECK(pending_pushes(l.core) == 1);

    auto* net = attach_mock_network(*l.core);
    TestHelper::finish_fetch(*l.core);
    REQUIRE(pushes(*net).size() == 1);
    auto [tombstone, deleted] = pushed(*pushes(*net)[0]);
    CHECK(deleted == nlohmann::json::array({"B1"}));
    answer_upload(l.core, *net, true);
    CHECK(pending_pushes(l.core) == 0);

    TestHelper::deliver_device_message(*other, tombstone, in(10min), "T1");
    CHECK(other->devices.membership(await).membership == device::Membership::Dissolved);
}

TEST_CASE(
        "Devices - a device leaving a group of its own dissolves it",
        "[core][devices][membership][leave]") {
    TempCore c;
    TestHelper::deliver_device_message(
            *c, c->devices.build_device_group_message().message, in(10min), "B1");
    auto* net = attach_mock_network(*c);

    REQUIRE(c->devices.leave_group(await));

    // Nobody was left in it to tell, so it is dissolved: deleted, with a tombstone in its place for
    // any other group's devices, and no group to see.
    auto sent = pushes(*net);
    REQUIRE(sent.size() == 1);
    auto [stored, deleted] = pushed(*sent[0]);
    REQUIRE_FALSE(stored.empty());
    CHECK(oxenc::bt_dict_consumer{stored}.require<std::string_view>("") == "T");
    CHECK(deleted == nlohmann::json::array({"B1"}));
    CHECK(c->devices.membership(await).others.empty());
}

TEST_CASE(
        "Devices - a device no longer in good standing leaves without a word",
        "[core][devices][membership][leave]") {
    Linking l;
    l.admit();

    SECTION("displaced") {
        // A copy of it admitted in its place, as in "a device whose place another has taken".
        TempCore copy{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
        TestHelper::set_device_id(*copy, l.applicant_id());
        ScopedClockOffset later{Devices::DISPLACEMENT_GRACE + 1min};
        TestHelper::deliver_device_message(
                *l.core, TestHelper::build_link_request(*copy, *l.core).message, in(10min), "L2");
        REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
        TestHelper::deliver_device_message(
                *l.applicant,
                l.core->devices.build_device_group_message().message,
                in(10min),
                "G2");
        REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Displaced);
    }
    SECTION("removed") {
        REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
        TestHelper::deliver_device_message(
                *l.applicant,
                l.core->devices.build_device_group_message().message,
                in(10min),
                "G2");
        REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Removed);
    }

    // A departure under its id would now apply to another device, or could not undo its removal.
    auto* net = attach_mock_network(*l.applicant);
    REQUIRE(l.applicant->devices.leave_group(await));
    CHECK(pushes(*net).empty());
    CHECK_FALSE(TestHelper::group_id(*l.applicant));
    CHECK(l.applicant->devices.membership(await).membership ==
          device::Membership::DeviceGroupVisible);
}

namespace {
// The record of device `id` that a group message carries, as `reader` -- one of its recipients --
// reads it.
device::Info record_in(Devices& reader, std::span<const std::byte> message, const device::Id& id) {
    auto plaintext = TestHelper::decrypt_device_data(reader, message);
    oxenc::bt_dict_consumer btdc{to_string_view(plaintext)};
    REQUIRE(btdc.skip_until("D"));
    auto devs = btdc.consume_dict_consumer();
    REQUIRE(devs.skip_until(std::string_view{reinterpret_cast<const char*>(id.data()), id.size()}));
    auto rec = devs.consume_dict_consumer();
    device::Info info{};
    info.seqno = rec.require<int64_t>("#");
    rec.skip_until("X");
    auto X = rec.consume_span<std::byte, 32>();
    std::ranges::copy(X, info.pk_x25519.begin());
    info.description = rec.maybe<std::string_view>("d").value_or(""sv);
    return info;
}
}  // namespace

TEST_CASE(
        "Devices - what a device says of itself goes with it from group to group",
        "[core][devices][membership]") {
    Linking l;
    device::Info described{};
    described.description = "Alice's tablet";
    described.type = device::Type::Session_Android;
    described.version = {1, 2, 3};
    l.applicant->devices.update_info(described, await);
    TestHelper::finish_fetch(*l.applicant);

    // A group of its own: the first record of it carries the description.
    start_over(l.applicant);
    auto own = record_in(
            l.applicant->devices,
            l.applicant->devices.build_device_group_message().message,
            l.applicant_id());
    CHECK(own.description == "Alice's tablet");
    CHECK(own.seqno == 1);

    // The account's other group, which the user chooses: leave this one, then join that.
    l.show_group();
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Forked);
    REQUIRE(l.applicant->devices.leave_group(await));
    l.ask(in(10min), "L1");
    REQUIRE(!l.events.added.empty());
    CHECK(l.events.added.back().device.description == "Alice's tablet");
    REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");
    REQUIRE(l.applicant->devices.confirm_link(await));
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
    auto held = l.state_of_applicant();
    CHECK(held.description == "Alice's tablet");
    CHECK(held.type == device::Type::Session_Android);
    CHECK(held.version == std::array<int, 3>{1, 2, 3});
}

TEST_CASE(
        "Devices - a forged record of this device's own is overtaken by its next push",
        "[core][devices]") {
    Linking l;
    device::Info described{};
    described.description = "the real one";
    l.applicant->devices.update_info(described, await);
    l.admit();
    auto id = l.applicant_id();
    auto [core_self, _] = l.core->devices.device_info(await);
    auto mine = [&] { return l.applicant->devices.devices(true, false, false, id).at(id); };
    auto held = mine();

    // A seed holder who knows this device's keys writes a record for it at the seqno the group
    // holds, saying something else.  Whichever of two such records has the higher digest wins the
    // merge; the held one's is made the lowest there is, so that the forged one is the winner.
    TestHelper::on_loop(*l.applicant, [&] {
        return l.applicant->database().conn().prepared_exec(
                "UPDATE devices SET digest = zeroblob(8) WHERE unique_id = ?", id);
    });
    auto forged = held;
    forged.description = "forged";
    TestHelper::receive_device_group_message(
            l.applicant->devices,
            TestHelper::encrypt_device_data(
                    l.core->devices, {{core_self.id, core_self}, {id, forged}}));
    REQUIRE(mine().description == "forged");
    CHECK(mine().seqno == held.seqno);

    // Merged like anyone's, but nothing of it goes into what this device publishes: its next push
    // carries its own record, past the forged one.
    CHECK(l.applicant->devices.needs_push().device_group);
    auto push = l.applicant->devices.build_device_group_message();
    auto pushed = record_in(l.core->devices, push.message, id);
    CHECK(pushed.description == "the real one");
    CHECK(pushed.seqno == held.seqno + 1);
    CHECK(pushed.pk_x25519 == l.applicant->devices.active_device_keys().front().x25519_pub);

    // Which the group takes, and so does this device once the swarm has it.
    TestHelper::deliver_device_message(*l.core, push.message, in(10min), "G2");
    CHECK(l.state_of_applicant().description == "the real one");
    l.applicant->devices.mark_device_group_pushed(push, "G2");
    CHECK(mine().description == "the real one");
    CHECK(mine().seqno == held.seqno + 1);
    CHECK_FALSE(l.applicant->devices.needs_push().device_group);
}

TEST_CASE(
        "Devices - a removed device comes back under a new identity",
        "[core][devices][membership]") {
    Linking l;
    l.admit();
    auto group = *TestHelper::group_id(*l.core);
    auto old_id = l.applicant_id();
    REQUIRE(l.core->devices.remove_device(old_id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G2");
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Removed);

    // Asking again is all it takes: the new identity comes with the asking.
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l.applicant, group, got);
    auto request = uploaded(*net);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());
    CHECK(l.applicant_id() != old_id);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Requesting);

    // Nothing of its old group left to carry into one it starts, or to mistake for the one it
    // joins -- its account keys included.
    auto held = l.applicant->devices.devices(true, true, true);
    REQUIRE(held.size() == 1);
    CHECK(held.begin()->first == l.applicant_id());
    CHECK_FALSE(TestHelper::group_id(*l.applicant));
    CHECK(account_key_count(l.applicant) == 0);

    // And joins again like any device asking: the new id is not the one the group removed.
    TestHelper::deliver_device_message(*l.core, request, (*got)->expires, "L2");
    REQUIRE(l.events.added.size() == 2);
    REQUIRE(l.core->devices.accept_request(l.events.added[1].id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G3");
    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
}

namespace {

// The applicant as it would be after losing track of having joined -- restored from a backup taken
// before, at `seqno`: not in a group as far as it knows, and holding keys the group never saw.
void lose_track(Linking& l, int64_t seqno) {
    auto id = l.applicant_id();
    TestHelper::on_loop(*l.applicant, [&] {
        l.applicant->database().conn().prepared_exec(
                "UPDATE devices SET state = ?, seqno = ? WHERE unique_id = ?",
                static_cast<int>(device::State::Unregistered),
                seqno,
                id);
        l.applicant->devices.rotate_device_keys();
        return 0;
    });
}

}  // namespace

TEST_CASE(
        "Devices - a device that lost track of joining asks to replace its record",
        "[core][devices][linking]") {
    Linking l;
    auto backup = l.applicant->devices.device_info(await).first.seqno;
    l.admit();

    // Details changed since joining, which the group holds and the backup does not: the request
    // comes from a device whose seqno is behind its record's.
    auto renamed = l.applicant->devices.device_info(await).first;
    renamed.description = "renamed";
    l.applicant->devices.update_info(renamed, await);
    TestHelper::deliver_device_message(
            *l.core, l.applicant->devices.build_device_group_message().message, in(10min), "G1b");
    auto before = l.state_of_applicant();
    REQUIRE(before.description == "renamed");
    auto keys_before = account_key_count(l.core);

    ScopedClockOffset later{1min};
    lose_track(l, backup);
    l.ask(in(10min), "L2");

    REQUIRE(l.events.added.size() == 2);
    auto asked = l.events.added[1];
    REQUIRE(asked.replaces);
    CHECK(asked.replaces->pk_x25519 == before.pk_x25519);
    CHECK(asked.device.pk_x25519 != before.pk_x25519);
    // Until someone accepts, the group goes on encrypting to the record it holds.
    CHECK(l.state_of_applicant().pk_x25519 == before.pk_x25519);

    REQUIRE(l.core->devices.accept_request(asked.id, await));
    auto after = l.state_of_applicant();
    CHECK(after.state == device::State::Registered);
    CHECK(after.pk_x25519 == asked.device.pk_x25519);
    CHECK(after.seqno > before.seqno);
    CHECK(account_key_count(l.core) == keys_before + 1);

    // And the device joins as any new device does: once its user has confirmed the SAS too.
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G2");
    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
    CHECK(l.applicant->devices.device_info(await).first.pk_x25519 == after.pk_x25519);
}

TEST_CASE(
        "Devices - the request that admitted a device does not ask to replace it",
        "[core][devices][linking]") {
    Linking l;
    auto first = l.ask();
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));

    // Still in the swarm, and fetched again by a device that missed it the first time round.
    TestHelper::deliver_device_message(*l.core, first.message, in(10min), "L1-again");
    CHECK(l.events.added.size() == 1);
    CHECK(l.core->devices.incoming_link_requests(await).empty());
}

TEST_CASE(
        "Devices - a removed device cannot ask to replace its record", "[core][devices][linking]") {
    Linking l;
    auto backup = l.applicant->devices.device_info(await).first.seqno;
    l.admit();
    REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));

    ScopedClockOffset later{1min};
    lose_track(l, backup);
    l.ask(in(10min), "L2");
    CHECK(l.events.added.size() == 1);
    CHECK(l.core->devices.incoming_link_requests(await).empty());
}

TEST_CASE(
        "Devices - a replacement accepted elsewhere closes the prompt here",
        "[core][devices][linking]") {
    Linking l;
    auto backup = l.applicant->devices.device_info(await).first.seqno;
    l.admit();

    // A third device in the group, to see the request without answering it.
    DeviceEventsRecorder third_events;
    TempCore third{
            core::predefined_seed{std::span<const std::byte, 32>{l.seed}},
            Linking::reporting_to(third_events)};
    TestHelper::deliver_device_message(
            *l.core, TestHelper::build_link_request(*third, *l.core).message, in(10min), "L3");
    REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
    TestHelper::deliver_device_message(
            *third, l.core->devices.build_device_group_message().message, in(10min), "G2");
    REQUIRE(third->devices.confirm_link(await));
    REQUIRE(third->devices.membership(await).membership == device::Membership::InGroup);

    ScopedClockOffset later{1min};
    lose_track(l, backup);
    auto asked = TestHelper::build_link_request(*l.applicant, *l.core);
    TestHelper::deliver_device_message(*l.core, asked.message, in(10min), "L4");
    TestHelper::deliver_device_message(*third, asked.message, in(10min), "L4");
    REQUIRE(third_events.added.size() == 1);
    REQUIRE(third_events.added[0].replaces);

    REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
    TestHelper::deliver_device_message(
            *third, l.core->devices.build_device_group_message().message, in(10min), "G3");
    CHECK(third_events.ended ==
          std::vector{std::pair{third_events.added[0].id, device::LinkRequestEnd::Accepted}});
    CHECK(third->devices.incoming_link_requests(await).empty());
}

TEST_CASE(
        "Devices - a device whose place another has taken is told so",
        "[core][devices][membership]") {
    Linking l;
    l.admit();

    // A copy of the applicant, under its id but with keys of its own, admitted in its place.
    TempCore copy{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::set_device_id(*copy, l.applicant_id());
    ScopedClockOffset later{Devices::DISPLACEMENT_GRACE + 1min};
    TestHelper::deliver_device_message(
            *l.core, TestHelper::build_link_request(*copy, *l.core).message, in(10min), "L2");
    REQUIRE(l.events.added.back().replaces);
    REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));

    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G2");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Displaced);
    CHECK(l.applicant_events.membership.back() == device::Membership::Displaced);

    // It speaks for the group no longer: nothing pushed, nobody admitted or removed.
    CHECK_FALSE(l.applicant->devices.needs_push().device_group);
    CHECK_FALSE(l.applicant->devices.remove_device(Linking::id_of(l.core), await));

    // The way back is a removed device's: asking to join again, as a new device, which takes the
    // new identity as part of the asking.
    auto old_id = l.applicant_id();
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l.applicant, *TestHelper::group_id(*l.core), got);
    auto request = uploaded(*net);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());
    CHECK(l.applicant_id() != old_id);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Requesting);

    // Not under the id the copy now holds, so asking as a new device, not to replace it.
    auto prompts = l.events.added.size();
    TestHelper::deliver_device_message(*l.core, request, (*got)->expires, "L3");
    REQUIRE(l.events.added.size() == prompts + 1);
    CHECK_FALSE(l.events.added.back().replaces);
}

TEST_CASE(
        "Devices - a snapshot that has yet to hear of this device does not displace it",
        "[core][devices][membership]") {
    Linking l;
    // The group as it was before the applicant joined, which a member could still push for a moment
    // after: built before it fetched the admission.
    auto before = l.core->devices.build_device_group_message().message;

    // Admitted by a message held until the user confirms, which is when it is read -- but as of
    // when it was written.
    l.ask();
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");
    REQUIRE(l.applicant->devices.confirm_link(await));
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::InGroup);

    TestHelper::deliver_device_message(*l.applicant, before, in(10min), "G-stale");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);

    // Nor when it arrives long after: it is as old as it was written, which is not something a
    // storage server can change.
    ScopedClockOffset later{Devices::DISPLACEMENT_GRACE + 1min};
    TestHelper::deliver_device_message(*l.applicant, before, in(10min), "G-late");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);

    // Beyond the grace, though, a message leaving it out is one the group sent without it.
    auto [core_self, _] = l.core->devices.device_info(await);
    TestHelper::deliver_device_message(
            *l.applicant,
            TestHelper::encrypt_device_data(l.core->devices, {{core_self.id, core_self}}),
            in(10min),
            "G-without");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Displaced);

    // And reading the group again, at or past what displaced it, puts it back.
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G2");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
}

TEST_CASE(
        "Devices - a removed device starts a group under a new identity",
        "[core][devices][membership]") {
    Linking l;
    l.admit();
    auto old_id = l.applicant_id();
    auto theirs = *TestHelper::group_id(*l.core);
    REQUIRE(l.core->devices.remove_device(old_id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G2");
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Removed);

    // Out of the group it was removed from first, and so, under the rule for starting a group
    // with others in view, dissolving it: nothing of that group comes along.
    auto mine = start_over(l.applicant);
    CHECK(mine != theirs);
    CHECK(l.applicant_id() != old_id);
    auto state = l.applicant->devices.membership(await);
    CHECK(state.membership == device::Membership::InGroup);
    CHECK(state.others.empty());
    auto devs = l.applicant->devices.devices(true, true, true);
    REQUIRE(devs.size() == 1);
    CHECK(devs.begin()->first == l.applicant_id());
}

TEST_CASE(
        "Devices - a removed device is told so, though it can read nothing else",
        "[core][devices][removal]") {
    Linking l;
    l.admit();
    auto key_before = l.core->devices.active_account_keys().front().x25519_pub;

    REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
    CHECK(l.state_of_applicant().state == device::State::Kicked);

    // The key it held is no longer the current one.
    CHECK(l.core->devices.active_account_keys().front().x25519_pub != key_before);

    // It is given no key to the message that removes it...
    auto group = l.core->devices.build_device_group_message().message;
    CHECK_THROWS_AS(
            TestHelper::decrypt_device_data(l.applicant->devices, group),
            device::decryption_failed);

    // ...but learns of the removal from the kicked list all the same.
    TestHelper::deliver_device_message(*l.applicant, group, in(10min), "G2");
    CHECK(own_state(l.applicant) == device::State::Kicked);
    REQUIRE(!l.applicant_events.membership.empty());
    CHECK(l.applicant_events.membership.back() == device::Membership::Removed);
}

TEST_CASE(
        "Devices - a member learning of a departure replaces the account key within the jitter",
        "[core][devices][removal][rotation]") {
    Linking l;
    l.admit();
    // The existing device's push, confirmed: what delivered the key to the applicant.
    l.core->devices.mark_device_group_pushed(l.core->devices.build_device_group_message(), "G1");
    auto current = [&] { return l.core->devices.active_account_keys().front().x25519_pub; };
    auto before = current();
    auto scheduled = *l.core->devices.next_account_rotation();
    REQUIRE(scheduled > clock_now() + Devices::KEY_ROTATION_PERIOD - Devices::KEY_ROTATION_JITTER);

    // The farewell the applicant pushes on leaving: its own view of the group, itself departed.
    auto [self, registered] = l.core->devices.device_info(await);
    REQUIRE(registered);
    auto leaver = l.state_of_applicant();
    leaver.state = device::State::Left;
    leaver.kicked = clock_now_s();
    auto farewell = TestHelper::encrypt_device_data(
            l.applicant->devices, {{self.id, self}, {leaver.id, leaver}});
    TestHelper::deliver_device_message(*l.core, farewell, in(10min), "G2");

    // Not at once, but soon: every member learning of it is due within the jitter, and whichever
    // rotates first stands the rest down.  The same moment however often it is asked.
    CHECK(current() == before);
    auto due = *l.core->devices.next_account_rotation();
    CHECK(due <= clock_now() + Devices::KEY_ROTATION_JITTER);
    CHECK(*l.core->devices.next_account_rotation() == due);

    // A key the departed device does not hold, and nothing early about the next.
    ScopedClockOffset later{Devices::KEY_ROTATION_JITTER + 1s};
    TestHelper::finish_fetch(*l.core);
    auto after = current();
    CHECK(after != before);
    for (const auto& k : l.applicant->devices.active_account_keys())
        CHECK(k.x25519_pub != after);
    CHECK(*l.core->devices.next_account_rotation() >
          clock_now() + Devices::KEY_ROTATION_PERIOD - Devices::KEY_ROTATION_JITTER);

    // Hearing of the same departure again -- restated later, as a device trying to return gets --
    // is not a second one.
    leaver.kicked = clock_now_s() + 1h;
    TestHelper::deliver_device_message(
            *l.core,
            TestHelper::encrypt_device_data(
                    l.applicant->devices, {{self.id, self}, {leaver.id, leaver}}),
            in(10min),
            "G3");
    CHECK(current() == after);
}

TEST_CASE(
        "Devices - a member learning of a removal brings both its rotations forward",
        "[core][devices][removal][rotation]") {
    Linking l;
    l.admit();
    l.core->devices.mark_device_group_pushed(l.core->devices.build_device_group_message(), "G1");
    auto soon = [] { return clock_now() + Devices::KEY_ROTATION_JITTER; };
    REQUIRE(*l.core->devices.next_account_rotation() > soon());
    REQUIRE(*l.core->devices.next_device_rotation() > soon());

    // A removal made elsewhere, by a device that kept the key the removed device holds -- one that
    // never heard of the rotation the remover made, say.
    auto [self, registered] = l.core->devices.device_info(await);
    REQUIRE(registered);
    auto removed = l.state_of_applicant();
    removed.state = device::State::Kicked;
    removed.kicked = clock_now_s();
    TestHelper::deliver_device_message(
            *l.core,
            TestHelper::encrypt_device_data(
                    l.applicant->devices, {{self.id, self}, {removed.id, removed}}),
            in(10min),
            "G2");

    // The account key, because the removed device holds it; our device keys, because it knows them.
    CHECK(*l.core->devices.next_account_rotation() <= soon());
    CHECK(*l.core->devices.next_device_rotation() <= soon());
}

namespace {

// The devices a group message says anything about, records and tombstones alike.
std::set<device::Id> carried_ids(Devices& d, std::span<const std::byte> message) {
    auto plaintext = TestHelper::decrypt_device_data(d, message);
    oxenc::bt_dict_consumer btdc{to_string_view(plaintext)};
    REQUIRE(btdc.skip_until("D"));
    auto devs = btdc.consume_dict_consumer();
    std::set<device::Id> ids;
    while (!devs.is_finished()) {
        auto key = devs.key();
        REQUIRE(key.size() == device::ID_SIZE);
        device::Id id;
        std::memcpy(id.data(), key.data(), id.size());
        ids.insert(id);
        devs.consume_dict_data();
    }
    return ids;
}

size_t kicked_slots(std::span<const std::byte> message) {
    oxenc::bt_dict_consumer outer{message};
    return outer.skip_until("k") ? outer.consume_span<std::byte>().size() / 16 : 0;
}

device::Info tombstone(device::State state, std::chrono::sys_seconds when) {
    device::Info t{};
    random::fill(t.id);
    t.state = state;
    t.kicked = when;
    return t;
}

}  // namespace

TEST_CASE(
        "Devices - a message carries only the most recent removal markers",
        "[core][devices][removal]") {
    TempCore c;
    auto [self, registered] = c->devices.device_info(await);
    REQUIRE(registered);
    device::map group{{self.id, self}};

    // Another device holding the account seed, to read the `kicked` list as a removed one would.
    TempCore removed{core::predefined_seed{std::span<const std::byte, 32>{Linking::seed_of(c)}}};

    // Removals and departures, the newest first.
    std::vector<device::Info> markers;
    for (int i = 0; i < 10; i++) {
        auto& m = markers.emplace_back(tombstone(
                i % 2 ? device::State::Left : device::State::Kicked,
                std::chrono::floor<std::chrono::seconds>(clock_now_s()) - (i + 1) * 1h));
        group.emplace(m.id, m);
    }

    // One bucket's worth for each bucket of live devices: 4 with only this one in the group, 8 with
    // a fifth device.  Departures count towards it, though only removals are in `kicked`.
    auto check = [&](size_t cap) {
        auto message = TestHelper::encrypt_device_data(c->devices, group);
        auto carried = carried_ids(c->devices, message);
        for (size_t i = 0; i < markers.size(); i++) {
            CHECK(carried.contains(markers[i].id) == (i < cap));
            if (markers[i].state == device::State::Kicked) {
                TestHelper::set_device_id(*removed, markers[i].id);
                CHECK(TestHelper::names_us_kicked(*removed, message) == (i < cap));
            }
        }
        CHECK(kicked_slots(message) == 4);
    };

    SECTION("one device") {
        check(4);
    }
    SECTION("five devices") {
        for (int i = 0; i < 4; i++) {
            auto k = c->devices.rotate_device_keys();
            device::Info other{};
            random::fill(other.id);
            other.seqno = 1;
            other.timestamp = clock_now_s();
            other.state = device::State::Registered;
            other.pk_x25519 = k.x25519_pub;
            other.pk_mlkem768 = k.mlkem768_pub;
            group.emplace(other.id, other);
        }
        check(8);
    }
}

TEST_CASE(
        "Devices - a message from our group we cannot read says what became of us by its removals",
        "[core][devices][membership][removal]") {
    Linking l;
    l.admit();
    auto now = std::chrono::floor<std::chrono::seconds>(clock_now_s());

    // A removal the applicant knows of, from a message it could read.
    auto known = tombstone(device::State::Kicked, now - 1h);
    auto group = l.core->devices.devices(true, true, true);
    group.emplace(known.id, known);
    TestHelper::deliver_device_message(
            *l.applicant, TestHelper::encrypt_device_data(l.core->devices, group), in(10min), "G1");
    REQUIRE(l.applicant->devices.devices(false, false, true).contains(known.id));

    // The group gone on without the applicant, carrying `removed` -- as any holder of the seed
    // could write it.
    auto core_self = l.core->devices.device_info(await).first;
    auto without = [&](std::vector<device::Info> removed) {
        device::map m{{core_self.id, core_self}};
        for (auto& r : removed)
            m.emplace(r.id, r);
        return TestHelper::encrypt_device_data(l.core->devices, m);
    };
    auto membership = [&] { return l.applicant->devices.membership(await).membership; };

    SECTION("naming it: removed, however soon after what it last read") {
        auto ours = tombstone(device::State::Kicked, now);
        ours.id = l.applicant_id();
        TestHelper::deliver_device_message(*l.applicant, without({known, ours}), in(10min), "G2");
        CHECK(membership() == device::Membership::Removed);
    }

    SECTION("with a removal it knew of and not its own: displaced") {
        ScopedClockOffset later{Devices::DISPLACEMENT_GRACE + 1min};
        TestHelper::deliver_device_message(*l.applicant, without({known}), in(10min), "G2");
        CHECK(membership() == device::Membership::Displaced);
    }

    SECTION("with no removal at all") {
        SECTION("having read the group lately: displaced") {
            ScopedClockOffset later{Devices::DISPLACEMENT_GRACE + 1min};
            TestHelper::deliver_device_message(*l.applicant, without({}), in(10min), "G2");
            CHECK(membership() == device::Membership::Displaced);
        }
        SECTION("not for longer than removals are carried: dropped") {
            ScopedClockOffset later{Devices::REMOVAL_MARKER_MAX_AGE + 1h};
            TestHelper::deliver_device_message(*l.applicant, without({}), in(10min), "G2");
            CHECK(membership() == device::Membership::Dropped);
        }
    }

    SECTION("with only removals it never heard of: dropped, which acts on nothing") {
        // Within the grace, a snapshot that may have yet to hear of it, and so nothing.
        auto unknown = tombstone(device::State::Kicked, now);
        TestHelper::deliver_device_message(*l.applicant, without({unknown}), in(10min), "G2");
        REQUIRE(membership() == device::Membership::InGroup);

        // A forger cannot make more of it than that: nothing pushed, nobody admitted or removed.
        ScopedClockOffset later{Devices::DISPLACEMENT_GRACE + 1min};
        TestHelper::deliver_device_message(*l.applicant, without({unknown}), in(10min), "G3");
        CHECK(membership() == device::Membership::Dropped);
        CHECK(l.applicant_events.membership.back() == device::Membership::Dropped);
        CHECK_FALSE(l.applicant->devices.needs_push().device_group);
        CHECK_FALSE(l.applicant->devices.remove_device(Linking::id_of(l.core), await));

        // A later one telling more says so.
        later.advance(1min);
        TestHelper::deliver_device_message(*l.applicant, without({known}), in(10min), "G4");
        CHECK(membership() == device::Membership::Displaced);

        // And reading the group again, at or past both, puts it back.
        TestHelper::deliver_device_message(
                *l.applicant,
                l.core->devices.build_device_group_message().message,
                in(10min),
                "G5");
        CHECK(membership() == device::Membership::InGroup);
    }
}

// What a device out of its group sees of the groups it could ask to join, and that it can.
void check_asks_back_into(TempCore& c, const device::GroupId& group) {
    auto state = c->devices.membership(await);
    CHECK_FALSE(state.group);
    REQUIRE(state.others.size() == 1);
    CHECK(state.others.front().id == group);

    auto* net = attach_mock_network(*c);
    Asked got;
    request_link(c, state.others.front().id, got);
    answer_upload(c, *net, true);
    REQUIRE(got);
    CHECK(got->has_value());
    CHECK(c->devices.membership(await).membership == device::Membership::Requesting);
}

TEST_CASE(
        "Devices - a device out of its group still sees it, to ask its way back",
        "[core][devices][membership]") {
    Linking l;
    l.admit();
    auto group = *TestHelper::group_id(*l.core);
    auto now = std::chrono::floor<std::chrono::seconds>(clock_now_s());
    ScopedClockOffset later{0s};

    // The group gone on without the applicant, carrying `removed`.
    auto core_self = l.core->devices.device_info(await).first;
    auto without = [&](std::vector<device::Info> removed) {
        device::map m{{core_self.id, core_self}};
        for (auto& r : removed)
            m.emplace(r.id, r);
        return TestHelper::encrypt_device_data(l.core->devices, m);
    };
    auto membership = [&] { return l.applicant->devices.membership(await).membership; };

    SECTION("removed") {
        auto ours = tombstone(device::State::Kicked, now);
        ours.id = l.applicant_id();
        TestHelper::deliver_device_message(*l.applicant, without({ours}), in(10min), "G2");
        REQUIRE(membership() == device::Membership::Removed);
    }
    SECTION("displaced") {
        later.advance(Devices::DISPLACEMENT_GRACE + 1min);
        TestHelper::deliver_device_message(*l.applicant, without({}), in(10min), "G2");
        REQUIRE(membership() == device::Membership::Displaced);
    }
    SECTION("dropped, by a message that cannot say why") {
        later.advance(Devices::DISPLACEMENT_GRACE + 1min);
        TestHelper::deliver_device_message(
                *l.applicant, without({tombstone(device::State::Kicked, now)}), in(10min), "G2");
        REQUIRE(membership() == device::Membership::Dropped);
    }

    check_asks_back_into(l.applicant, group);
}

TEST_CASE(
        "Devices - a device whose group is gone beside another sees the other, to ask to join",
        "[core][devices][membership]") {
    Linking l;
    TestHelper::start_device_group(*l.applicant);
    auto theirs = *TestHelper::group_id(*l.applicant);
    TestHelper::deliver_device_message(
            *l.core,
            l.applicant->devices.build_device_group_message().message,
            in(1min) + Devices::DEVICE_GROUP_TTL + 1h,
            "B1");

    ScopedClockOffset later{Devices::DEVICE_GROUP_TTL + 1h};
    TestHelper::finish_fetch(*l.core);
    REQUIRE(l.core->devices.membership(await).membership == device::Membership::Dropped);

    // Its own group is not among them: nothing of it is left in the swarm to ask.
    check_asks_back_into(l.core, theirs);
}

TEST_CASE("Devices - a removal announced by another group is ignored", "[core][devices][removal]") {
    Linking l;
    l.admit();

    // Another group on the account, whose message names the applicant's id as removed.
    TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_device_group(*other);
    auto other_self = other->devices.device_info(await).first;
    auto ours = tombstone(
            device::State::Kicked, std::chrono::floor<std::chrono::seconds>(clock_now_s()));
    ours.id = l.applicant_id();
    auto message = TestHelper::encrypt_device_data(
            other->devices, {{other_self.id, other_self}, {ours.id, ours}});
    REQUIRE(TestHelper::names_us_kicked(*l.applicant, message));

    ScopedClockOffset later{Devices::DISPLACEMENT_GRACE + 1min};
    TestHelper::deliver_device_message(*l.applicant, message, in(10min), "B1");
    CHECK(l.applicant->devices.device_info(await).first.state == device::State::Registered);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Forked);
}

TEST_CASE(
        "Devices - an old removal leaves the group's messages but not this device",
        "[core][devices][removal]") {
    TempCore c;
    auto k = c->devices.rotate_device_keys();
    auto [self, registered] = c->devices.device_info(await);
    REQUIRE(registered);

    auto removal = tombstone(device::State::Kicked, clock_now_s());
    TestHelper::receive_device_group_message(
            c->devices,
            TestHelper::encrypt_device_data(c->devices, {{self.id, self}, {removal.id, removal}}));
    REQUIRE(carried_ids(c->devices, c->devices.build_device_group_message().message)
                    .contains(removal.id));

    ScopedClockOffset later{Devices::REMOVAL_MARKER_MAX_AGE + 1h};
    auto message = c->devices.build_device_group_message().message;
    CHECK_FALSE(carried_ids(c->devices, message).contains(removal.id));
    CHECK(kicked_slots(message) == 0);

    // Still held here, and still what stops the device coming back.
    auto held = c->devices.devices(true, true, true, removal.id);
    REQUIRE(held.size() == 1);
    CHECK(held.begin()->second.state == device::State::Kicked);

    auto returning = removal;
    returning.state = device::State::Registered;
    returning.kicked.reset();
    returning.seqno = 5;
    returning.timestamp = clock_now_s();
    returning.pk_x25519 = k.x25519_pub;
    returning.pk_mlkem768 = k.mlkem768_pub;
    TestHelper::receive_device_group_message(
            c->devices,
            TestHelper::encrypt_device_data(
                    c->devices, {{self.id, self}, {returning.id, returning}}));
    CHECK(c->devices.devices(true, true, true, removal.id).begin()->second.state ==
          device::State::Kicked);

    // Restated as of now, so that the group's messages carry it again.
    CHECK(carried_ids(c->devices, c->devices.build_device_group_message().message)
                  .contains(removal.id));
}

TEST_CASE("Devices - a device that left is not told it was removed", "[core][devices][removal]") {
    Linking l;
    l.admit();

    // A group message carrying a departure for it, as the group it left would push.
    auto [self, registered] = l.core->devices.device_info(await);
    REQUIRE(registered);
    auto left = l.state_of_applicant();
    left.state = device::State::Left;
    left.kicked = clock_now_s();
    auto group =
            TestHelper::encrypt_device_data(l.core->devices, {{self.id, self}, {left.id, left}});

    TestHelper::deliver_device_message(*l.applicant, group, in(10min), "G2");
    CHECK(own_state(l.applicant) == device::State::Registered);
}

TEST_CASE(
        "Devices - only a device in the group can be removed, and only by another",
        "[core][devices][removal]") {
    Linking l;
    device::Id unknown;
    random::fill(unknown);
    CHECK_FALSE(l.core->devices.remove_device(unknown, await));

    // Still only asking: that is ignore_request's to answer.
    l.ask();
    CHECK_FALSE(l.core->devices.remove_device(l.applicant_id(), await));
    CHECK(l.state_of_applicant().state == device::State::Pending);

    // A device outside the group has nobody to remove.
    auto [self, registered] = l.core->devices.device_info(await);
    CHECK_FALSE(l.applicant->devices.remove_device(self.id, await));

    CHECK_THROWS_AS(l.core->devices.remove_device(self.id, await), std::invalid_argument);
}

namespace {

// Each of the pair's pushes confirmed and read by the other, so that neither owes anything.
void settle(Linking& l) {
    auto mine = l.applicant->devices.build_device_group_message();
    l.applicant->devices.mark_device_group_pushed(mine, "S1");
    TestHelper::deliver_device_message(*l.core, mine.message, in(10min), "S1");
    auto theirs = l.core->devices.build_device_group_message();
    l.core->devices.mark_device_group_pushed(theirs, "S2");
    TestHelper::deliver_device_message(*l.applicant, theirs.message, in(10min), "S2");
    REQUIRE_FALSE(l.core->devices.needs_push().device_group);
    REQUIRE_FALSE(l.applicant->devices.needs_push().device_group);
}

bool carries_transition(const Devices::DeviceGroupPush& push, const device::Id& id) {
    return std::ranges::any_of(push.broadcast, [&](const auto& b) { return b.first == id; });
}

}  // namespace

TEST_CASE(
        "Devices - merging another device's change owes no push of our own",
        "[core][devices][push]") {
    Linking l;
    l.admit();
    settle(l);

    // The device that makes a change owes the push carrying it.
    TempCore third{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::deliver_device_message(
            *l.core, TestHelper::build_link_request(*third, *l.core).message, in(10min), "L2");
    REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
    REQUIRE(l.core->devices.needs_push().device_group);

    // The message carrying it is in the swarm already, so the other member has nothing to relay.
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G3");
    REQUIRE(l.applicant->devices.devices().size() == 3);
    CHECK_FALSE(l.applicant->devices.needs_push().device_group);

    // Nor for a removal, nor the account key the removing device minted with it.
    REQUIRE(l.core->devices.remove_device(Linking::id_of(third), await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G4");
    REQUIRE(l.applicant->devices.devices().size() == 2);
    REQUIRE(l.applicant->devices.active_account_keys().front().x25519_pub ==
            l.core->devices.active_account_keys().front().x25519_pub);
    CHECK_FALSE(l.applicant->devices.needs_push().device_group);
}

TEST_CASE(
        "Devices - a removal restated while its push is in flight is still owed after it",
        "[core][devices][push]") {
    Linking l;
    l.admit();
    // The removed device's view of the group, which it can push again whenever it likes.
    auto revived = l.applicant->devices.build_device_group_message().message;

    REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
    auto push = l.core->devices.build_device_group_message();
    REQUIRE(carries_transition(push, l.applicant_id()));

    // Brought back while the push is in flight, and the removal restated.
    TestHelper::deliver_device_message(*l.core, revived, in(10min), "G2");
    l.core->devices.mark_device_group_pushed(push, "G3");
    CHECK(carries_transition(l.core->devices.build_device_group_message(), l.applicant_id()));
}

TEST_CASE(
        "Devices - an account key merged from another device is not ours to distribute",
        "[core][devices][push][rotation]") {
    Linking l;
    l.admit();
    settle(l);

    l.core->devices.rotate_account_keys();
    auto push = l.core->devices.build_device_group_message();
    l.core->devices.mark_device_group_pushed(push, "G3");
    TestHelper::deliver_device_message(*l.applicant, push.message, in(10min), "G3");
    REQUIRE(l.applicant->devices.active_account_keys().front().x25519_pub ==
            l.core->devices.active_account_keys().front().x25519_pub);
    CHECK_FALSE(l.applicant->devices.needs_push().device_group);
}

namespace {
auto account_key(TempCore& c) {
    return c->devices.active_account_keys().front().x25519_pub;
}
auto device_key(TempCore& c) {
    return c->devices.active_device_keys().front().x25519_pub;
}
}  // namespace

TEST_CASE(
        "Devices - a member rotates both its keys when due, after a fetch, in one push",
        "[core][devices][rotation]") {
    Linking l;
    auto* net = attach_mock_network(*l.core);
    TestHelper::finish_fetch(*l.core);
    answer_upload(l.core, *net, true);
    REQUIRE_FALSE(l.core->devices.needs_push().device_group);
    auto account = account_key(l.core);
    auto device = device_key(l.core);

    // Long away: both overdue, but nothing rotated until a fetch has brought what waited for it,
    // encrypted to the keys it had.
    ScopedClockOffset later{Devices::KEY_ROTATION_PERIOD + Devices::KEY_ROTATION_JITTER};
    REQUIRE(l.core->devices.account_rotation_due());
    REQUIRE(l.core->devices.device_rotation_due());
    CHECK(account_key(l.core) == account);
    CHECK(device_key(l.core) == device);

    auto before = pushes(*net).size();
    TestHelper::finish_fetch(*l.core);
    CHECK(account_key(l.core) != account);
    CHECK(device_key(l.core) != device);
    REQUIRE(pushes(*net).size() == before + 1);
    answer_upload(l.core, *net, true);
    CHECK_FALSE(l.core->devices.needs_push().device_group);

    // Once: the next fetch finds neither due.
    account = account_key(l.core);
    device = device_key(l.core);
    TestHelper::finish_fetch(*l.core);
    CHECK(account_key(l.core) == account);
    CHECK(device_key(l.core) == device);
    CHECK(pushes(*net).empty());
}

TEST_CASE(
        "Devices - a device outside a group keeps the keys its request names",
        "[core][devices][rotation][linking]") {
    Linking l;
    l.ask();
    TestHelper::finish_fetch(*l.applicant);
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Requesting);
    CHECK_FALSE(l.applicant->devices.next_device_rotation());
    CHECK_FALSE(l.applicant->devices.next_account_rotation());

    auto device = device_key(l.applicant);
    ScopedClockOffset later{Devices::KEY_ROTATION_PERIOD + Devices::KEY_ROTATION_JITTER};
    TestHelper::finish_fetch(*l.applicant);
    CHECK(device_key(l.applicant) == device);
}

TEST_CASE(
        "Devices - a device with a quiet swarm still rotates on time",
        "[core][devices][rotation]") {
    Linking l;
    auto* net = attach_mock_network(*l.core);
    TestHelper::finish_fetch(*l.core);
    answer_upload(l.core, *net, true);
    auto account = account_key(l.core);
    auto device = device_key(l.core);

    // To within a second of the earlier rotation, and the timer re-armed from there by a fetch, so
    // that it is the timer that notices rather than anything this test does.
    auto next = std::min(
            *l.core->devices.next_account_rotation(), *l.core->devices.next_device_rotation());
    ScopedClockOffset later{
            std::chrono::duration_cast<std::chrono::seconds>(next - clock_now()) - 1s};
    TestHelper::finish_fetch(*l.core);
    REQUIRE(account_key(l.core) == account);
    REQUIRE(device_key(l.core) == device);

    // It fetches the group, and rotates after that fetch, as after any other.
    REQUIRE(eventually(
            *l.core, [&] { return std::ranges::any_of(net->sent_requests, is_device_fetch); }));
    later.advance(2s);
    REQUIRE(answer_fetch(l.core, *net) == 1);
    CHECK((account_key(l.core) != account || device_key(l.core) != device));
}

TEST_CASE(
        "Devices - a key minted without hearing of a removal is replaced, at once by the remover",
        "[core][devices][removal][rotation]") {
    Linking l;
    l.admit();

    // A third member, which hears nothing of what follows until it has rotated.
    TempCore third{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::deliver_device_message(
            *l.core, TestHelper::build_link_request(*third, *l.core).message, in(10min), "L2");
    REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
    auto joined = l.core->devices.build_device_group_message();
    l.core->devices.mark_device_group_pushed(joined, "G2");
    TestHelper::deliver_device_message(*third, joined.message, in(10min), "G2");
    REQUIRE(third->devices.confirm_link(await));
    REQUIRE(third->devices.membership(await).membership == device::Membership::InGroup);

    // The existing device removes the applicant, rotating as it does...
    ScopedClockOffset later{1min};
    REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
    auto removal = l.core->devices.build_device_group_message();
    l.core->devices.mark_device_group_pushed(removal, "G3");

    // ...while the third rotates on its own schedule, and its push delivers the newer key -- the
    // one every device will take as current -- to the removed device.
    later.advance(1min);
    third->devices.rotate_account_keys();
    auto concurrent = third->devices.build_device_group_message();
    third->devices.mark_device_group_pushed(concurrent, "G4");
    auto leaked = account_key(third);

    SECTION("the remover replaces it at once") {
        TestHelper::deliver_device_message(*l.core, concurrent.message, in(10min), "G4");
        CHECK(account_key(l.core) != leaked);
    }

    SECTION("any other member within the jitter, standing down when another gets there first") {
        TestHelper::deliver_device_message(*third, removal.message, in(10min), "G3");
        REQUIRE(account_key(third) == leaked);
        CHECK(*third->devices.next_account_rotation() <=
              clock_now() + Devices::KEY_ROTATION_JITTER);

        TestHelper::deliver_device_message(*l.core, concurrent.message, in(10min), "G4");
        TestHelper::deliver_device_message(
                *third, l.core->devices.build_device_group_message().message, in(10min), "G5");
        CHECK(account_key(third) == account_key(l.core));
        CHECK(*third->devices.next_account_rotation() >
              clock_now() + Devices::KEY_ROTATION_PERIOD - Devices::KEY_ROTATION_JITTER);
    }
}

TEST_CASE(
        "Devices - a device admitted to a group with an old departure does not rotate",
        "[core][devices][rotation][linking]") {
    Linking l;

    // A device that was in the group once, and left a month ago.
    auto [self, registered] = l.core->devices.device_info(await);
    REQUIRE(registered);
    auto gone = tombstone(
            device::State::Left,
            std::chrono::floor<std::chrono::seconds>(clock_now_s()) - Devices::DEVICE_GROUP_TTL);
    TestHelper::deliver_device_message(
            *l.core,
            TestHelper::encrypt_device_data(l.core->devices, {{self.id, self}, {gone.id, gone}}),
            in(10min),
            "G0");
    REQUIRE(l.core->devices.devices(false, false, true).contains(gone.id));

    // Every departure in the group's history is new to a device joining it, and none of them
    // holds the key it is given.
    l.admit();
    CHECK(account_key(l.applicant) == account_key(l.core));
    CHECK(*l.applicant->devices.next_account_rotation() >
          clock_now() + Devices::KEY_ROTATION_PERIOD - Devices::KEY_ROTATION_JITTER);
}

TEST_CASE(
        "Devices - a description changed only past DESCRIPTION_MAX asks for no push",
        "[core][devices][push]") {
    Linking l;
    l.admit();
    auto [self, registered] = l.core->devices.device_info(await);
    self.description = straddling;
    l.core->devices.update_info(self, await);
    auto* net = attach_mock_network(*l.core);
    TestHelper::finish_fetch(*l.core);
    answer_upload(l.core, *net, true);
    REQUIRE_FALSE(l.core->devices.needs_push().device_group);
    TestHelper::drain(*l.core);
    REQUIRE_FALSE(std::ranges::any_of(net->sent_requests, is_device_fetch));

    self.description = straddling_other;
    l.core->devices.update_info(self, await);
    TestHelper::drain(*l.core);
    CHECK_FALSE(std::ranges::any_of(net->sent_requests, is_device_fetch));
}

TEST_CASE(
        "Devices - a change of ours fetches the group at once, and the push follows",
        "[core][devices][push]") {
    Linking l;
    l.admit();
    auto* net = attach_mock_network(*l.core);
    TestHelper::finish_fetch(*l.core);
    answer_upload(l.core, *net, true);
    REQUIRE_FALSE(l.core->devices.needs_push().device_group);
    REQUIRE_FALSE(std::ranges::any_of(net->sent_requests, is_device_fetch));

    SECTION("a removal") {
        REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
    }
    SECTION("our own record") {
        auto [self, registered] = l.core->devices.device_info(await);
        self.description = "Renamed";
        l.core->devices.update_info(self, await);
    }

    // Not waiting for the swarm to send something, which a subscribed device would: the fetch
    // that every push follows, asked for now.
    REQUIRE(pushes(*net).empty());
    REQUIRE(answer_fetch(l.core, *net) == 1);
    CHECK(pushes(*net).size() == 1);
}

namespace {

// Admits `c`, another device of the account, to `l`'s group through the existing device, and has
// the applicant read the message that admitted it.
void join(Linking& l, TempCore& c) {
    TestHelper::deliver_device_message(
            *l.core, TestHelper::build_link_request(*c, *l.core).message, in(10min), "L-join");
    REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
    auto joined = l.core->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(*c, joined, in(10min), "G-join");
    REQUIRE(c->devices.confirm_link(await));
    TestHelper::deliver_device_message(*l.applicant, joined, in(10min), "G-join");
}

// A live record for a device of nobody's making but the caller's, with real keys to encrypt to.
device::Info planted_record() {
    TempCore planted;
    auto keys = planted->devices.active_device_keys().front();
    device::Info info{};
    random::fill(info.id);
    info.seqno = 1;
    info.timestamp = std::chrono::floor<std::chrono::seconds>(clock_now_s());
    info.type = device::Type::Session_Desktop;
    info.description = "Planted";
    info.state = device::State::Registered;
    info.version = {1, 0, 0};
    info.pk_x25519 = keys.x25519_pub;
    info.pk_mlkem768 = keys.mlkem768_pub;
    return info;
}

}  // namespace

TEST_CASE(
        "Devices - the group's scheduled account rotation is the same on every member",
        "[core][devices][rotation]") {
    Linking l;
    CHECK_FALSE(l.applicant->devices.scheduled_account_rotation());
    CHECK(l.applicant->devices.account_rotation_schedule().empty());

    l.admit();
    TempCore third{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    join(l, third);
    auto third_id = Linking::id_of(third);
    // The existing device's push, confirmed: what delivered the key to the third.
    l.core->devices.mark_device_group_pushed(l.core->devices.build_device_group_message(), "G1");

    // One time, whichever member asks: the earliest of the three devices' own.
    auto scheduled = l.core->devices.scheduled_account_rotation();
    REQUIRE(scheduled);
    CHECK(l.applicant->devices.scheduled_account_rotation() == scheduled);
    CHECK(third->devices.scheduled_account_rotation() == scheduled);
    CHECK(*scheduled == std::min(
                                {*l.core->devices.next_account_rotation(),
                                 *l.applicant->devices.next_account_rotation(),
                                 *third->devices.next_account_rotation()}));

    // The whole schedule: one slot per member, earliest first, each member's its own time, and the
    // same list on every member.
    auto schedule = l.core->devices.account_rotation_schedule();
    REQUIRE(schedule.size() == 3);
    CHECK(std::ranges::is_sorted(schedule, {}, &decltype(schedule)::value_type::second));
    CHECK(schedule.front().second == *scheduled);
    CHECK(l.applicant->devices.account_rotation_schedule() == schedule);
    std::set<device::Id> ids;
    for (const auto& [id, at] : schedule)
        ids.insert(id);
    CHECK(ids == std::set{Linking::id_of(l.core), l.applicant_id(), third_id});
    for (auto* member : {&l.core, &l.applicant, &third}) {
        auto id = Linking::id_of(*member);
        auto mine = std::ranges::find(schedule, id, &decltype(schedule)::value_type::first);
        REQUIRE(mine != schedule.end());
        CHECK(mine->second == *(*member)->devices.next_account_rotation());
    }

    // The third leaves, holding the current key, so the other two replace it early -- each at a
    // moment of its own.  What they show the user stays one time, and the schedule's.
    auto leaver = l.core->devices.devices(true, true, true).at(third_id);
    leaver.state = device::State::Left;
    leaver.kicked = clock_now_s();
    auto group = l.core->devices.devices(true, true, true);
    group.at(third_id) = leaver;
    auto farewell = TestHelper::encrypt_device_data(third->devices, group);
    TestHelper::deliver_device_message(*l.core, farewell, in(10min), "G-left");
    TestHelper::deliver_device_message(*l.applicant, farewell, in(10min), "G-left");

    auto now_scheduled = l.core->devices.scheduled_account_rotation();
    REQUIRE(now_scheduled);
    CHECK(l.applicant->devices.scheduled_account_rotation() == now_scheduled);
    CHECK(*now_scheduled >
          clock_now() + Devices::KEY_ROTATION_PERIOD - Devices::KEY_ROTATION_JITTER);
    for (auto* member : {&l.core, &l.applicant}) {
        auto own = *(*member)->devices.next_account_rotation();
        CHECK(own <= clock_now() + Devices::KEY_ROTATION_JITTER);
        CHECK(own < *now_scheduled);
    }
}

TEST_CASE(
        "Devices - a removed device can add a device until the members' keys move on",
        "[core][devices][removal][attack]") {
    DeviceEventsRecorder third_events;
    Linking l;
    l.admit();
    TempCore third{
            core::predefined_seed{std::span<const std::byte, 32>{l.seed}},
            Linking::reporting_to(third_events)};
    join(l, third);

    // The applicant is removed, and never hears of it: it still holds the seed, the group's
    // identifier, and every member's device keys as they were.
    REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
    TestHelper::deliver_device_message(
            *third, l.core->devices.build_device_group_message().message, in(10min), "G3");
    auto known = l.applicant->devices.devices(true, true, true);
    REQUIRE(known.size() == 3);

    // A group message of its own making, registering a device of its own.
    ScopedClockOffset later{1min};
    auto planted = planted_record();
    auto forged_group = known;
    forged_group.emplace(planted.id, planted);
    auto forged = TestHelper::encrypt_device_data(l.applicant->devices, forged_group);

    // Nothing prevents it.  What answers it is that every member says so.
    for (auto [member, events] :
         {std::pair{&l.core, &l.events}, std::pair{&third, &third_events}}) {
        TestHelper::deliver_device_message(**member, forged, in(10min), "F1");
        CHECK((*member)->devices.devices().contains(planted.id));
        CHECK(std::ranges::any_of(events->members, [&](const device::Info& i) {
            return i.id == planted.id && i.state == device::State::Registered;
        }));
    }

    // Two rotations each and the keys it knew are gone, so the same forgery reads as nothing to
    // any of them -- and as Displaced, a message from their own group carrying no removals at all.
    // A seed holder can have any member conclude that, as it can do the group every other harm;
    // what the design promises is that each member notices, loudly.
    for (auto* member : {&l.core, &third}) {
        (*member)->devices.rotate_device_keys();
        (*member)->devices.rotate_device_keys();
    }
    later.advance(Devices::DISPLACEMENT_GRACE + 1min);
    auto again = TestHelper::encrypt_device_data(l.applicant->devices, forged_group);
    for (auto [member, events] :
         {std::pair{&l.core, &l.events}, std::pair{&third, &third_events}}) {
        CHECK_THROWS_AS(
                TestHelper::decrypt_device_data((*member)->devices, again),
                device::decryption_failed);
        events->membership.clear();
        TestHelper::deliver_device_message(**member, again, in(10min), "F2");
        CHECK((*member)->devices.membership(await).membership == device::Membership::Displaced);
        CHECK(events->membership == std::vector{device::Membership::Displaced});
    }
}

TEST_CASE(
        "Devices - a message to our previous device key still reads, one to the key before not",
        "[core][devices][rotation]") {
    Linking l;
    l.admit();
    // Encrypted to the existing device's keys as they are now.
    auto group = l.applicant->devices.devices(true, true, true);
    auto message = TestHelper::encrypt_device_data(l.applicant->devices, group);

    l.core->devices.rotate_device_keys();
    CHECK_NOTHROW(TestHelper::decrypt_device_data(l.core->devices, message));

    l.core->devices.rotate_device_keys();
    CHECK_THROWS_AS(
            TestHelper::decrypt_device_data(l.core->devices, message), device::decryption_failed);
}

namespace {

// `c`'s group push, built and taken as stored by the swarm under `hash`.
std::vector<std::byte> push_from(TempCore& c, const std::string& hash) {
    auto push = c->devices.build_device_group_message();
    c->devices.mark_device_group_pushed(push, hash);
    return push.message;
}

// Each device pushes in turn and every other reads it, twice over, so that each has read
// everything the others hold.
void exchange(const std::vector<TempCore*>& cores) {
    int n = 0;
    for (int round = 0; round < 2; round++)
        for (auto* from : cores) {
            auto hash = "X" + std::to_string(n++);
            auto message = push_from(*from, hash);
            for (auto* to : cores)
                if (to != from)
                    TestHelper::deliver_device_message(**to, message, in(10min), hash);
        }
}

// What `c` holds of the group, by what decides a merge: every live record and tombstone.
using View = std::map<
        device::Id,
        std::tuple<
                device::State,
                int64_t,
                std::optional<std::chrono::sys_seconds>,
                std::array<std::byte, 32>>>;
View view(TempCore& c) {
    View out;
    for (const auto& [id, info] : c->devices.devices(true, true, true)) {
        if (info.state == device::State::Registered)
            out[id] = {info.state, info.seqno, std::nullopt, info.pk_x25519};
        else if (info.state == device::State::Kicked || info.state == device::State::Left)
            out[id] = {info.state, 0, info.kicked, {}};
    }
    return out;
}

}  // namespace

TEST_CASE(
        "Devices - an admission and a removal made at once by different members converge",
        "[core][devices][convergence]") {
    Linking l;
    l.admit();
    TempCore third{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    join(l, third);
    TempCore fourth{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    exchange({&l.core, &l.applicant, &third});

    // The existing device admits a fourth while the applicant removes the third, neither having
    // heard of the other's change.
    ScopedClockOffset later{1min};
    TestHelper::deliver_device_message(
            *l.core, TestHelper::build_link_request(*fourth, *l.core).message, in(10min), "L4");
    REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
    REQUIRE(l.applicant->devices.remove_device(Linking::id_of(third), await));
    auto admitted = push_from(l.core, "P-A");
    auto removed = push_from(l.applicant, "P-B");

    TestHelper::deliver_device_message(*fourth, admitted, in(10min), "P-A");
    REQUIRE(fourth->devices.confirm_link(await));
    TestHelper::deliver_device_message(*l.core, removed, in(10min), "P-B");
    TestHelper::deliver_device_message(*l.applicant, admitted, in(10min), "P-A");

    // The new device could read only the admission -- the removal was encrypted to the devices its
    // maker knew -- so it hears of the rest with the members' next pushes.
    exchange({&l.core, &l.applicant, &fourth});
    auto held = view(l.core);
    CHECK(held.size() == 4);
    CHECK(std::get<0>(held.at(Linking::id_of(third))) == device::State::Kicked);
    CHECK(view(l.applicant) == held);
    CHECK(view(fourth) == held);
    CHECK(account_key(l.applicant) == account_key(l.core));
    CHECK(account_key(fourth) == account_key(l.core));
}

TEST_CASE(
        "Devices - two devices accepted before a push are admitted by that one push",
        "[core][devices][convergence][linking]") {
    Linking l;
    TempCore second{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    l.ask();
    TestHelper::deliver_device_message(
            *l.core, TestHelper::build_link_request(*second, *l.core).message, in(10min), "L2");
    REQUIRE(l.events.added.size() == 2);
    REQUIRE(l.core->devices.accept_request(l.events.added[0].id, await));
    REQUIRE(l.core->devices.accept_request(l.events.added[1].id, await));

    auto push = push_from(l.core, "G1");
    auto carried = carried_ids(l.core->devices, push);
    CHECK(carried.contains(l.applicant_id()));
    CHECK(carried.contains(Linking::id_of(second)));

    for (auto* asking : {&l.applicant, &second}) {
        TestHelper::deliver_device_message(**asking, push, in(10min), "G1");
        REQUIRE((*asking)->devices.confirm_link(await));
        CHECK((*asking)->devices.membership(await).membership == device::Membership::InGroup);
    }
    auto devs = l.core->devices.devices();
    CHECK(devs.size() == 3);
    CHECK(devs.contains(l.applicant_id()));
    CHECK(devs.contains(Linking::id_of(second)));
}

TEST_CASE(
        "Devices - a request accepted by two members at once admits the device once",
        "[core][devices][convergence][linking]") {
    DeviceEventsRecorder asking_events;
    Linking l;
    l.admit();
    TempCore asking{
            core::predefined_seed{std::span<const std::byte, 32>{l.seed}},
            Linking::reporting_to(asking_events)};
    auto request = TestHelper::build_link_request(*asking, *l.core);
    TestHelper::deliver_device_message(*l.core, request.message, in(10min), "L2");
    TestHelper::deliver_device_message(*l.applicant, request.message, in(10min), "L2");
    REQUIRE(l.applicant_events.added.size() == 1);
    auto at_core = l.events.added.back().id;
    auto at_applicant = l.applicant_events.added.back().id;

    // Both members accept before either has heard of the other's acceptance.
    REQUIRE(l.core->devices.accept_request(at_core, await));
    REQUIRE(l.applicant->devices.accept_request(at_applicant, await));
    auto from_core = push_from(l.core, "P-A");
    auto from_applicant = push_from(l.applicant, "P-B");

    TestHelper::deliver_device_message(*asking, from_core, in(10min), "P-A");
    REQUIRE(asking->devices.confirm_link(await));
    TestHelper::deliver_device_message(*asking, from_applicant, in(10min), "P-B");
    TestHelper::deliver_device_message(*l.core, from_applicant, in(10min), "P-B");
    TestHelper::deliver_device_message(*l.applicant, from_core, in(10min), "P-A");

    auto asking_id = Linking::id_of(asking);
    CHECK(asking->devices.membership(await).membership == device::Membership::InGroup);
    CHECK(view(l.core) == view(l.applicant));
    CHECK(view(asking) == view(l.core));
    CHECK(std::ranges::count_if(
                  view(l.core), [&](const auto& v) { return v.first == asking_id; }) == 1);

    // Neither is told its prompt ended: each closed it itself, by accepting, and hearing of the
    // other's acceptance afterwards is not a second ending.
    auto ended = [](const DeviceEventsRecorder& e, int reqid) {
        return std::ranges::count_if(e.ended, [&](const auto& x) { return x.first == reqid; });
    };
    CHECK(ended(l.events, at_core) == 0);
    CHECK(ended(l.applicant_events, at_applicant) == 0);
}

TEST_CASE(
        "Devices - a device removed by two members at once is removed once",
        "[core][devices][convergence][removal]") {
    Linking l;
    l.admit();
    TempCore third{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    join(l, third);
    exchange({&l.core, &l.applicant, &third});

    // Both remove it, and both rotate as they do, neither having heard of the other's.  Its own
    // removal is no news to either, beyond the list to redraw.
    for (auto* events : {&l.events, &l.applicant_events})
        *events = DeviceEventsRecorder{};
    ScopedClockOffset later{1min};
    auto gone = Linking::id_of(third);
    REQUIRE(l.core->devices.remove_device(gone, await));
    later.advance(30s);
    REQUIRE(l.applicant->devices.remove_device(gone, await));
    for (auto* events : {&l.events, &l.applicant_events}) {
        CHECK(events->members.empty());
        CHECK(events->replaced.size() == 1);
    }

    // Nor is the other's removal of the same device, already gone here: only the time it went
    // moves, for the one that removed it first, which is a list to redraw.
    auto from_core = push_from(l.core, "P-A");
    auto from_applicant = push_from(l.applicant, "P-B");
    TestHelper::deliver_device_message(*l.core, from_applicant, in(10min), "P-B");
    TestHelper::deliver_device_message(*l.applicant, from_core, in(10min), "P-A");
    CHECK(l.events.members.empty());
    CHECK(l.applicant_events.members.empty());
    CHECK(l.events.replaced.size() == 2);
    CHECK(l.applicant_events.replaced.size() == 1);

    // One key, settled by the merge; one removal, at the later of the two times; and nothing
    // owed, nor any early rotation, since the current key reached neither the removed device.
    CHECK(account_key(l.core) == account_key(l.applicant));
    CHECK(view(l.core) == view(l.applicant));
    CHECK(std::get<0>(view(l.core).at(gone)) == device::State::Kicked);
    for (auto* member : {&l.core, &l.applicant}) {
        CHECK_FALSE((*member)->devices.needs_push().device_group);
        CHECK(*(*member)->devices.next_account_rotation() >
              clock_now() + Devices::KEY_ROTATION_PERIOD - Devices::KEY_ROTATION_JITTER);
    }
}

TEST_CASE(
        "Devices - a member away across an admission learns of it from the new device alone",
        "[core][devices][convergence][linking]") {
    Linking l;
    l.admit();
    exchange({&l.core, &l.applicant});

    // The existing device admits a third while the applicant is away, and never pushes again.
    TempCore third{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::deliver_device_message(
            *l.core, TestHelper::build_link_request(*third, *l.core).message, in(10min), "L3");
    REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
    TestHelper::deliver_device_message(*third, push_from(l.core, "G3"), in(10min), "G3");
    REQUIRE(third->devices.confirm_link(await));

    // What the applicant finds on its return is the new device's own push.
    auto members_before = l.applicant_events.members.size();
    TestHelper::deliver_device_message(*l.applicant, push_from(third, "G4"), in(10min), "G4");
    CHECK(l.applicant->devices.devices().contains(Linking::id_of(third)));
    REQUIRE(l.applicant_events.members.size() == members_before + 1);
    CHECK(l.applicant_events.members.back().id == Linking::id_of(third));
    CHECK(l.applicant_events.members.back().state == device::State::Registered);
}

TEST_CASE(
        "Devices - five devices each read every other's push, and agree on the group",
        "[core][devices][convergence]") {
    Linking l;
    l.admit();
    std::vector<TempCore> more;
    for (int i = 0; i < 3; i++)
        more.emplace_back(core::predefined_seed{std::span<const std::byte, 32>{l.seed}});
    for (auto& c : more)
        join(l, c);

    std::vector<TempCore*> all{&l.core, &l.applicant};
    for (auto& c : more)
        all.push_back(&c);
    exchange(all);

    auto held = view(l.core);
    CHECK(held.size() == 5);
    for (auto* from : all) {
        auto message = from->core->devices.build_device_group_message().message;
        for (auto* to : all)
            if (to != from)
                CHECK_NOTHROW(TestHelper::decrypt_device_data((*to)->devices, message));
        CHECK(view(*from) == held);
    }
}

namespace {

// `count` devices the applicant never hears of, each admitted by the existing device and then
// removed by it, a minute apart.
void removals_since(Linking& l, ScopedClockOffset& clock, int count) {
    for (int i = 0; i < count; i++) {
        clock.advance(1min);
        TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
        TestHelper::deliver_device_message(
                *l.core,
                TestHelper::build_link_request(*other, *l.core).message,
                in(10min),
                "LR" + std::to_string(i));
        REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
        REQUIRE(l.core->devices.remove_device(Linking::id_of(other), await));
    }
}

}  // namespace

TEST_CASE(
        "Devices - a device whose removal is no longer carried reads as dropped, not removed",
        "[core][devices][classify]") {
    Linking l;
    l.admit();
    ScopedClockOffset later{1min};
    REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));

    // As many removals since as a group of one device carries.
    removals_since(l, later, 4);
    later.advance(Devices::DISPLACEMENT_GRACE);
    auto message = l.core->devices.build_device_group_message().message;
    CHECK(kicked_slots(message) == 4);

    l.applicant_events.membership.clear();
    TestHelper::deliver_device_message(*l.applicant, message, in(10min), "G9");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Dropped);
    CHECK(l.applicant_events.membership == std::vector{device::Membership::Dropped});
    CHECK(own_state(l.applicant) == device::State::Registered);
}

TEST_CASE(
        "Devices - a removal restated after ours was evicted reads as displaced",
        "[core][devices][classify]") {
    Linking l;
    l.admit();
    TempCore known{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    join(l, known);

    // A removal the applicant hears of...
    ScopedClockOffset later{1min};
    REQUIRE(l.core->devices.remove_device(Linking::id_of(known), await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G3");
    REQUIRE(l.applicant->devices.devices(false, false, true).contains(Linking::id_of(known)));
    // ...with what the removed device still holds of the group, less the applicant.
    auto revival_group = known->devices.devices(true, true, true);
    revival_group.erase(l.applicant_id());

    // Then the applicant's own, unheard, and three more.
    later.advance(1min);
    REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
    removals_since(l, later, 3);

    // The removed device pushes its old view again, and the existing device restates its removal,
    // as new as any.
    later.advance(1min);
    TestHelper::deliver_device_message(
            *l.core,
            TestHelper::encrypt_device_data(known->devices, revival_group),
            in(10min),
            "G8");
    later.advance(Devices::DISPLACEMENT_GRACE);
    auto message = l.core->devices.build_device_group_message().message;
    CHECK(kicked_slots(message) == 4);

    // The known false Displaced from the review: the cap has evicted our own removal while a
    // removal older than it, reasserted, is still carried -- and a known removal carried says the
    // list reaches back past our time, which here it does not.
    l.applicant_events.membership.clear();
    TestHelper::deliver_device_message(*l.applicant, message, in(10min), "G9");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Displaced);
    CHECK(l.applicant_events.membership == std::vector{device::Membership::Displaced});
}

TEST_CASE(
        "Devices - a message carrying no removals says displaced only within the marker age",
        "[core][devices][classify]") {
    Linking l;
    l.admit();
    auto core_self = l.core->devices.device_info(await).first;
    auto without_us = [&] {
        return TestHelper::encrypt_device_data(l.core->devices, {{core_self.id, core_self}});
    };

    l.applicant_events.membership.clear();
    SECTION("last read just within it: displaced") {
        ScopedClockOffset later{Devices::REMOVAL_MARKER_MAX_AGE - 1min};
        TestHelper::deliver_device_message(*l.applicant, without_us(), in(10min), "G2");
        CHECK(l.applicant->devices.membership(await).membership == device::Membership::Displaced);
        CHECK(l.applicant_events.membership == std::vector{device::Membership::Displaced});
    }
    SECTION("last read just past it: dropped") {
        ScopedClockOffset later{Devices::REMOVAL_MARKER_MAX_AGE + 1min};
        TestHelper::deliver_device_message(*l.applicant, without_us(), in(10min), "G2");
        CHECK(l.applicant->devices.membership(await).membership == device::Membership::Dropped);
        CHECK(l.applicant_events.membership == std::vector{device::Membership::Dropped});
    }
}

namespace {

// The tombstone carried by the newest dissolution `net` has seen sent.
std::vector<std::byte> latest_tombstone(MockNetwork& net) {
    auto sent = dissolutions(net);
    REQUIRE(!sent.empty());
    return pushed(*sent.back()).first;
}

int dissolved_count(TempCore& c) {
    return c->database().conn().prepared_get<int>("SELECT count(*) FROM device_dissolved_groups");
}

}  // namespace

TEST_CASE(
        "Devices - two forked devices dissolving each other at once both end dissolved",
        "[core][devices][dissolve]") {
    DeviceEventsRecorder other_events;
    Linking l;
    TestHelper::finish_fetch(*l.core);
    auto* net = attach_mock_network(*l.core);
    TempCore other{
            core::predefined_seed{std::span<const std::byte, 32>{l.seed}},
            Linking::reporting_to(other_events)};
    TestHelper::start_device_group(*other);
    auto* other_net = attach_mock_network(*other);
    auto ours = *TestHelper::group_id(*l.core);
    auto theirs = *TestHelper::group_id(*other);
    TestHelper::deliver_device_message(
            *l.core, other->devices.build_device_group_message().message, in(10min), "B1");
    TestHelper::deliver_device_message(
            *other, l.core->devices.build_device_group_message().message, in(10min), "A1");
    REQUIRE(l.core->devices.membership(await).membership == device::Membership::Forked);
    REQUIRE(other->devices.membership(await).membership == device::Membership::Forked);

    // Each user keeps their own, before either device has heard of the other's choice.
    REQUIRE(l.core->devices.dissolve_group(theirs, await));
    REQUIRE(other->devices.dissolve_group(ours, await));
    auto from_core = latest_tombstone(*net);
    auto from_other = latest_tombstone(*other_net);
    auto sent = dissolutions(*net).size();
    auto other_sent = dissolutions(*other_net).size();

    l.events.membership.clear();
    other_events.membership.clear();
    TestHelper::deliver_device_message(*l.core, from_other, in(10min), "T2");
    TestHelper::deliver_device_message(*other, from_core, in(10min), "T1");
    CHECK(l.core->devices.membership(await).membership == device::Membership::Dissolved);
    CHECK(other->devices.membership(await).membership == device::Membership::Dissolved);
    CHECK(l.events.membership == std::vector{device::Membership::Dissolved});
    CHECK(other_events.membership == std::vector{device::Membership::Dissolved});

    // And nothing more: neither tells the other again.
    CHECK(dissolutions(*net).size() == sent);
    CHECK(dissolutions(*other_net).size() == other_sent);
    CHECK_FALSE(l.core->devices.dissolve_group(theirs, await));

    // What is left is to start again -- its own doing, so not reported -- and to ask to join that.
    // The other, Dissolved until it joins or starts a group, stays so on seeing the new one, and is
    // told of it: there is now a group to offer joining.
    auto mine = start_over(l.core);
    CHECK(l.core->devices.membership(await).membership == device::Membership::InGroup);
    CHECK(l.events.membership == std::vector{device::Membership::Dissolved});
    TestHelper::deliver_device_message(
            *other, l.core->devices.build_device_group_message().message, in(10min), "A2");
    CHECK(other->devices.membership(await).membership == device::Membership::Dissolved);
    auto told = std::vector{device::Membership::Dissolved, device::Membership::Dissolved};
    CHECK(other_events.membership == told);
    while (!pushes(*other_net).empty())
        answer_upload(other, *other_net, true);
    Asked got;
    request_link(other, mine, got);
    answer_upload(other, *other_net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());
    CHECK(other->devices.membership(await).membership == device::Membership::Requesting);
    CHECK(other_events.membership == told);
}

TEST_CASE(
        "Devices events - a change in the groups in view is a change of membership",
        "[core][devices][events][membership]") {
    Linking l;
    TestHelper::finish_fetch(*l.core);
    TestHelper::finish_fetch(*l.applicant);
    TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_device_group(*other);
    auto theirs = *TestHelper::group_id(*other);
    auto their_message = other->devices.build_device_group_message().message;

    SECTION("dissolved before the kept group is in view, then seeing it") {
        auto* other_net = attach_mock_network(*other);
        TestHelper::deliver_device_message(
                *other, l.core->devices.build_device_group_message().message, in(10min), "A1");
        REQUIRE(other->devices.dissolve_group(*TestHelper::group_id(*l.core), await));
        l.events.membership.clear();
        TestHelper::deliver_device_message(*l.core, latest_tombstone(*other_net), in(10min), "T1");
        REQUIRE(l.core->devices.membership(await).others.empty());
        REQUIRE(l.events.membership == std::vector{device::Membership::Dissolved});

        TestHelper::deliver_device_message(*l.core, their_message, in(10min), "B1");
        CHECK(l.core->devices.membership(await).others.size() == 1);
        CHECK(l.events.membership ==
              std::vector{device::Membership::Dissolved, device::Membership::Dissolved});
    }

    SECTION("forked, until the other group lapses") {
        TestHelper::deliver_device_message(*l.core, their_message, in(10min), "B1");
        REQUIRE(l.events.membership.back() == device::Membership::Forked);
        ScopedClockOffset later{11min};
        TestHelper::finish_fetch(*l.core);
        CHECK(l.events.membership.back() == device::Membership::InGroup);
    }

    SECTION("a second group beside the one in view") {
        l.show_group();
        REQUIRE(l.applicant_events.membership.back() == device::Membership::DeviceGroupVisible);
        l.applicant_events.membership.clear();
        TestHelper::deliver_device_message(*l.applicant, their_message, in(10min), "B1");
        CHECK(l.applicant->devices.membership(await).others.size() == 2);
        CHECK(l.applicant_events.membership == std::vector{device::Membership::DeviceGroupVisible});
    }
}

TEST_CASE(
        "Devices - a sole member leaving for another group dissolves its own",
        "[core][devices][dissolve][leave]") {
    // The core alone in its group, the applicant alone in another; each sees the other's.
    Linking l;
    TestHelper::start_device_group(*l.applicant);
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "A1");
    TestHelper::deliver_device_message(
            *l.core, l.applicant->devices.build_device_group_message().message, in(10min), "B1");
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Forked);
    REQUIRE(l.core->devices.membership(await).membership == device::Membership::Forked);
    auto old_id = Linking::id_of(l.core);

    // Its user chooses the other group: leave, then ask to join it.
    auto* net = attach_mock_network(*l.core);
    REQUIRE(l.core->devices.leave_group(await));
    auto tombstone = latest_tombstone(*net);
    REQUIRE(oxenc::bt_dict_consumer{tombstone}.require<std::string_view>("") == "T");

    auto req = TestHelper::build_link_request(*l.core, *l.applicant);
    TestHelper::deliver_device_message(*l.applicant, req.message, in(10min), "L1");
    REQUIRE(l.applicant->devices.accept_request(l.applicant_events.added.at(0).id, await));
    TestHelper::deliver_device_message(
            *l.core, l.applicant->devices.build_device_group_message().message, in(10min), "B2");
    REQUIRE(l.core->devices.confirm_link(await));
    REQUIRE(l.core->devices.membership(await).membership == device::Membership::InGroup);

    // The group left behind is no fork any more, without its user having to say so.
    l.applicant_events.membership.clear();
    TestHelper::deliver_device_message(*l.applicant, tombstone, in(10min), "T1");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
    CHECK(l.applicant->devices.membership(await).others.empty());
    CHECK(l.applicant_events.membership == std::vector{device::Membership::InGroup});

    // And the identity it left under is in nobody's list.
    CHECK_FALSE(l.applicant->devices.devices(true, true, true).contains(old_id));
    CHECK_FALSE(l.core->devices.devices(true, true, true).contains(old_id));

    // Its own tombstone, read back, only reminds it the old group is gone.
    TestHelper::deliver_device_message(*l.core, tombstone, in(10min), "T1");
    CHECK(l.core->devices.membership(await).membership == device::Membership::InGroup);
}

namespace {
struct by_value {
    bool operator()(const device::GroupId& a, const device::GroupId& b) const {
        return a.value < b.value;
    }
};
using GroupSet = std::set<device::GroupId, by_value>;

GroupSet dissolved_ids(TempCore& c) {
    GroupSet out;
    for (auto id :
         c->database().conn().prepared_results<sqlite::blob_guts<std::array<std::byte, 8>>>(
                 "SELECT group_id FROM device_dissolved_groups"))
        out.insert(device::GroupId{id});
    return out;
}

GroupSet listed(const device::MembershipState& state) {
    auto groups = in_view(state);
    return {groups.begin(), groups.end()};
}
}  // namespace

TEST_CASE(
        "Devices - a member starting a group dissolves its own, and its devices are told",
        "[core][devices][dissolve][membership]") {
    Linking l;
    l.admit();
    auto old_group = *TestHelper::group_id(*l.applicant);
    auto old_id = l.applicant_id();
    auto old_key = l.applicant->devices.active_account_keys().front().x25519_pub;
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G2");
    auto before = l.applicant->devices.membership(await);
    REQUIRE(before.membership == device::Membership::InGroup);
    REQUIRE(listed(before) == GroupSet{old_group});

    auto* net = attach_mock_network(*l.applicant);
    auto mine = l.applicant->devices.start_device_group(in_view(before), await);

    // A new group, under a new identity and a new account key, with nothing of the old.
    CHECK(mine != old_group);
    CHECK(l.applicant_id() != old_id);
    CHECK(l.applicant->devices.active_account_keys().front().x25519_pub != old_key);
    auto state = l.applicant->devices.membership(await);
    CHECK(state.membership == device::Membership::InGroup);
    CHECK(state.group == mine);
    CHECK(state.others.empty());
    auto devs = l.applicant->devices.devices(true, true, true);
    REQUIRE(devs.size() == 1);
    CHECK(devs.begin()->first == l.applicant_id());

    // The old group dissolved as its sole member leaving would: its messages deleted, and a
    // tombstone naming it -- exactly what membership() listed.
    CHECK(dissolved_ids(l.applicant) == listed(before));
    REQUIRE(dissolutions(*net).size() == 1);
    auto [tombstone, deleted] = pushed(*dissolutions(*net).front());
    CHECK(oxenc::bt_dict_consumer{tombstone}.require<std::string_view>("") == "T");
    CHECK(std::ranges::find(deleted, "G2") != deleted.end());

    // The other member, told, has no group; it sees the new one to ask to join.
    TestHelper::deliver_device_message(*l.core, tombstone, in(10min), "T1");
    CHECK(l.core->devices.membership(await).membership == device::Membership::Dissolved);
    TestHelper::deliver_device_message(
            *l.core, l.applicant->devices.build_device_group_message().message, in(10min), "N1");
    auto theirs = l.core->devices.membership(await);
    CHECK(theirs.membership == device::Membership::Dissolved);
    REQUIRE(theirs.others.size() == 1);
    CHECK(theirs.others[0].id == mine);
}

TEST_CASE(
        "Devices - a forked device starting a group dissolves both",
        "[core][devices][dissolve][membership]") {
    Linking l;
    TestHelper::start_device_group(*l.applicant);
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "A1");
    TestHelper::deliver_device_message(
            *l.core, l.applicant->devices.build_device_group_message().message, in(10min), "B1");
    auto ours = *TestHelper::group_id(*l.core);
    auto theirs = *TestHelper::group_id(*l.applicant);
    auto before = l.core->devices.membership(await);
    REQUIRE(before.membership == device::Membership::Forked);
    REQUIRE(listed(before) == GroupSet{ours, theirs});

    auto* net = attach_mock_network(*l.core);
    auto mine = l.core->devices.start_device_group(in_view(before), await);
    CHECK(mine != ours);
    CHECK(mine != theirs);
    CHECK(dissolved_ids(l.core) == listed(before));
    auto state = l.core->devices.membership(await);
    CHECK(state.membership == device::Membership::InGroup);
    CHECK(state.others.empty());

    // One tombstone naming both, and the other group's device told by it.
    auto tombstone = latest_tombstone(*net);
    TestHelper::deliver_device_message(*l.applicant, tombstone, in(10min), "T1");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Dissolved);
}

TEST_CASE(
        "Devices - starting a group dissolves only what the user confirmed replacing",
        "[core][devices][dissolve][membership]") {
    Linking l;
    l.admit();
    auto own = *TestHelper::group_id(*l.applicant);
    auto confirmed = in_view(l.applicant->devices.membership(await));
    REQUIRE(confirmed == std::vector{own});
    auto* net = attach_mock_network(*l.applicant);

    SECTION("a group appearing after the user was shown the list: refused, and nothing done") {
        TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
        TestHelper::start_device_group(*other);
        auto newcomer = *TestHelper::group_id(*other);
        TestHelper::deliver_device_message(
                *l.applicant, other->devices.build_device_group_message().message, in(10min), "B1");
        REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Forked);

        auto old_id = l.applicant_id();
        auto old_key = l.applicant->devices.active_account_keys().front().x25519_pub;
        auto queued = pending_pushes(l.applicant);
        CHECK(failure_code([&] { l.applicant->devices.start_device_group(confirmed, await); }) ==
              err::groups_changed);

        auto state = l.applicant->devices.membership(await);
        CHECK(state.membership == device::Membership::Forked);
        CHECK(state.group == own);
        CHECK(l.applicant_id() == old_id);
        CHECK(l.applicant->devices.active_account_keys().front().x25519_pub == old_key);
        CHECK(dissolved_ids(l.applicant).empty());
        CHECK(pending_pushes(l.applicant) == queued);
        CHECK(dissolutions(*net).empty());

        // Shown again, and confirmed with the newcomer: as any start.
        auto mine = l.applicant->devices.start_device_group({own, newcomer}, await);
        CHECK(dissolved_ids(l.applicant) == GroupSet{own, newcomer});
        CHECK(l.applicant->devices.membership(await).group == mine);
    }

    SECTION("one confirmed that is no longer in view: gone either way, and no matter") {
        TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
        TestHelper::start_device_group(*other);
        confirmed.push_back(*TestHelper::group_id(*other));

        auto mine = l.applicant->devices.start_device_group(confirmed, await);
        CHECK(dissolved_ids(l.applicant) == GroupSet{own});
        CHECK(l.applicant->devices.membership(await).group == mine);
    }
}

TEST_CASE(
        "Devices - starting a group with none in view confirms an empty list",
        "[core][devices][membership]") {
    Linking l;
    TestHelper::finish_fetch(*l.applicant);

    SECTION("none there: started") {
        REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::NoGroup);
        auto mine = l.applicant->devices.start_device_group({}, await);
        CHECK(l.applicant->devices.membership(await).group == mine);
        CHECK(dissolved_ids(l.applicant).empty());
    }

    SECTION("one there after all: refused, until it is confirmed") {
        auto theirs = l.show_group();
        REQUIRE(l.applicant->devices.membership(await).membership ==
                device::Membership::DeviceGroupVisible);
        CHECK(failure_code([&] { l.applicant->devices.start_device_group({}, await); }) ==
              err::groups_changed);
        CHECK(l.applicant->devices.membership(await).membership ==
              device::Membership::DeviceGroupVisible);

        l.applicant->devices.start_device_group({theirs}, await);
        CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
        CHECK(dissolved_ids(l.applicant) == GroupSet{theirs});
    }
}

TEST_CASE(
        "Devices - a join to a revived group is undone when a kept group's device returns",
        "[core][devices][dissolve]") {
    DeviceEventsRecorder other_events, joiner_events;
    Linking l;
    TestHelper::finish_fetch(*l.core);
    auto* net = attach_mock_network(*l.core);
    TempCore other{
            core::predefined_seed{std::span<const std::byte, 32>{l.seed}},
            Linking::reporting_to(other_events)};
    TestHelper::start_device_group(*other);
    auto theirs = *TestHelper::group_id(*other);
    TestHelper::deliver_device_message(
            *l.core, other->devices.build_device_group_message().message, in(10min), "B1");
    REQUIRE(l.core->devices.dissolve_group(theirs, await));

    // Everything lapses.  The dissolved group's device, never told, is back first, and a new
    // device that never saw any of it joins the only group in the swarm.
    ScopedClockOffset later{Devices::DEVICE_GROUP_TTL + 1h};
    TempCore joiner{
            core::predefined_seed{std::span<const std::byte, 32>{l.seed}},
            Linking::reporting_to(joiner_events)};
    TestHelper::deliver_device_message(
            *joiner, other->devices.build_device_group_message().message, in(10min), "B2");
    REQUIRE(joiner->devices.membership(await).membership == device::Membership::DeviceGroupVisible);
    TestHelper::deliver_device_message(
            *other, TestHelper::build_link_request(*joiner, *other).message, in(10min), "L1");
    auto asked = other->devices.incoming_link_requests(await);
    REQUIRE(asked.size() == 1);
    REQUIRE(other->devices.accept_request(asked[0].id, await));
    auto admitted = other->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(*joiner, admitted, in(10min), "B3");
    REQUIRE(joiner->devices.confirm_link(await));
    REQUIRE(joiner->devices.membership(await).membership == device::Membership::InGroup);

    // Then a device of the group that was kept returns, and remembers.
    TestHelper::deliver_device_message(*l.core, admitted, in(10min), "B3");
    auto tombstone = latest_tombstone(*net);
    joiner_events.membership.clear();
    other_events.membership.clear();
    TestHelper::deliver_device_message(*joiner, tombstone, in(10min), "T2");
    TestHelper::deliver_device_message(*other, tombstone, in(10min), "T2");
    CHECK(joiner->devices.membership(await).membership == device::Membership::Dissolved);
    CHECK(other->devices.membership(await).membership == device::Membership::Dissolved);
    CHECK(joiner_events.membership == std::vector{device::Membership::Dissolved});
    CHECK(other_events.membership == std::vector{device::Membership::Dissolved});
}

TEST_CASE(
        "Devices - starting a group from dissolved dissolves the group that was kept",
        "[core][devices][dissolve]") {
    DeviceEventsRecorder other_events;
    Linking l;
    TestHelper::finish_fetch(*l.core);
    auto* net = attach_mock_network(*l.core);
    auto ours = *TestHelper::group_id(*l.core);
    TempCore other{
            core::predefined_seed{std::span<const std::byte, 32>{l.seed}},
            Linking::reporting_to(other_events)};
    TestHelper::start_device_group(*other);
    TestHelper::deliver_device_message(
            *l.core, other->devices.build_device_group_message().message, in(10min), "B1");
    TestHelper::deliver_device_message(
            *l.core, TestHelper::build_dissolution(*other, {ours}), in(10min), "T1");
    REQUIRE(l.core->devices.membership(await).membership == device::Membership::Dissolved);
    REQUIRE(l.core->devices.membership(await).others.size() == 1);

    // Starting one after all is choosing it over the group in view, the one that was kept: the
    // starter's own doing, so not reported to it.
    l.events.membership.clear();
    other_events.membership.clear();
    start_over(l.core);
    auto state = l.core->devices.membership(await);
    CHECK(state.membership == device::Membership::InGroup);
    CHECK(state.others.empty());
    CHECK(l.events.membership.empty());
    TestHelper::deliver_device_message(*other, latest_tombstone(*net), in(10min), "T2");
    CHECK(other->devices.membership(await).membership == device::Membership::Dissolved);
    CHECK(other_events.membership == std::vector{device::Membership::Dissolved});
}

TEST_CASE(
        "Devices - a dissolution interrupted partway leaves the device as it was",
        "[core][devices][dissolve]") {
    Linking l;
    l.admit();
    auto group = *TestHelper::group_id(*l.applicant);
    auto old_id = l.applicant_id();
    auto sql = [&](const std::string& query) {
        TestHelper::on_loop(
                *l.applicant, [&] { return l.applicant->database().conn().prepared_exec(query); });
    };
    TempCore keeper{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    auto tombstone = TestHelper::build_dissolution(*keeper, {group});

    // Forgetting the group made to fail, as an interruption there would leave things.
    l.applicant_events.membership.clear();
    sql("CREATE TRIGGER interrupted BEFORE DELETE ON devices BEGIN SELECT RAISE(ABORT, 'x'); END");
    TestHelper::deliver_device_message(*l.applicant, tombstone, in(10min), "T1");
    sql("DROP TRIGGER interrupted");

    // None of it, then: still in the group, under its id, nothing marked dissolved, and nothing
    // reported.
    CHECK(TestHelper::group_id(*l.applicant) == group);
    CHECK(l.applicant_id() == old_id);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
    CHECK(dissolved_count(l.applicant) == 0);
    CHECK(l.applicant_events.membership.empty());

    // And all of it, the tombstone read again.
    TestHelper::deliver_device_message(*l.applicant, tombstone, in(10min), "T1");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Dissolved);
    CHECK(l.applicant_id() != old_id);
    CHECK(dissolved_count(l.applicant) == 1);
    CHECK(l.applicant_events.membership == std::vector{device::Membership::Dissolved});
}

TEST_CASE(
        "Devices - a dissolution stored but not deleted from the swarm is not tried again",
        "[core][devices][dissolve]") {
    Linking l;
    TestHelper::finish_fetch(*l.core);
    auto* net = attach_mock_network(*l.core);
    TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_device_group(*other);
    auto theirs = *TestHelper::group_id(*other);
    TestHelper::deliver_device_message(
            *l.core, other->devices.build_device_group_message().message, in(10min), "B1");
    REQUIRE(l.core->devices.dissolve_group(theirs, await));
    REQUIRE(pending_pushes(l.core) == 1);

    // The swarm stores the tombstone and fails the delete that follows it.
    auto answered = answer_requests(
            *net,
            [](const MockNetwork::SentRequest& r) {
                if (r.request.endpoint != "sequence")
                    return false;
                auto [stored, deleted] = pushed(r);
                return !stored.empty() &&
                       oxenc::bt_dict_consumer{stored}.require<std::string_view>("") == "T";
            },
            [](MockNetwork::SentRequest& r) {
                nlohmann::json results = nlohmann::json::array(
                        {{{"code", 200}, {"body", {{"hash", "T1"}}}},
                         {{"code", 500}, {"body", "failed"}}});
                r.callback(true, false, 200, {}, nlohmann::json{{"results", results}}.dump());
            },
            1);
    REQUIRE(answered == 1);
    TestHelper::drain(*l.core);

    // A known gap, pinned as it stands: the push counts as done once its store is, so the dissolved
    // group's message stays in the swarm, deleted by nobody, until it lapses.
    CHECK(pending_pushes(l.core) == 0);
    TestHelper::finish_fetch(*l.core);
    CHECK(dissolutions(*net).empty());
}

namespace {

// Shuts `c` down and starts it again on the same database, reporting to `events`, which it starts
// afresh: what follows is what the new run reports.
void restart(TempCore& c, DeviceEventsRecorder& events) {
    c.core.reset();
    events = DeviceEventsRecorder{};
    c.core = std::make_unique<core::Core>(c.path, Linking::reporting_to(events));
}

}  // namespace

TEST_CASE(
        "Devices - a dissolved device is still dissolved after a restart",
        "[core][devices][restart]") {
    Linking l;
    l.admit();
    TempCore keeper{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::deliver_device_message(
            *l.applicant,
            TestHelper::build_dissolution(*keeper, {*TestHelper::group_id(*l.applicant)}),
            in(10min),
            "T1");
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Dissolved);

    restart(l.applicant, l.applicant_events);
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Dissolved);
    CHECK(l.applicant_events.membership == std::vector{device::Membership::Dissolved});
}

TEST_CASE(
        "Devices - a dropped device is still dropped after a restart", "[core][devices][restart]") {
    Linking l;
    SECTION("its group gone from the swarm beside another") {
        TestHelper::start_device_group(*l.applicant);
        TestHelper::deliver_device_message(
                *l.core,
                l.applicant->devices.build_device_group_message().message,
                in(1min) + Devices::DEVICE_GROUP_TTL + 1h,
                "B1");
        ScopedClockOffset later{Devices::DEVICE_GROUP_TTL + 1h};
        TestHelper::finish_fetch(*l.core);
        REQUIRE(l.core->devices.membership(await).membership == device::Membership::Dropped);

        restart(l.core, l.events);
        TestHelper::finish_fetch(*l.core);
        CHECK(l.core->devices.membership(await).membership == device::Membership::Dropped);
        CHECK(l.events.membership == std::vector{device::Membership::Dropped});
    }
    SECTION("a message from its group it cannot read, saying too little") {
        l.admit();
        auto core_self = l.core->devices.device_info(await).first;
        auto unknown = tombstone(
                device::State::Kicked, std::chrono::floor<std::chrono::seconds>(clock_now_s()));
        ScopedClockOffset later{Devices::DISPLACEMENT_GRACE + 1min};
        TestHelper::deliver_device_message(
                *l.applicant,
                TestHelper::encrypt_device_data(
                        l.core->devices, {{core_self.id, core_self}, {unknown.id, unknown}}),
                in(10min),
                "G2");
        REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Dropped);

        restart(l.applicant, l.applicant_events);
        TestHelper::finish_fetch(*l.applicant);
        CHECK(l.applicant->devices.membership(await).membership == device::Membership::Dropped);
        CHECK(l.applicant_events.membership == std::vector{device::Membership::Dropped});
    }
}

TEST_CASE(
        "Devices - when the next rotations are due is the same after a restart",
        "[core][devices][restart][rotation]") {
    Linking l;
    l.admit();
    l.core->devices.mark_device_group_pushed(l.core->devices.build_device_group_message(), "G1");

    // A departure, making the account key's rotation due early; and the device keys' own time.
    auto [self, registered] = l.core->devices.device_info(await);
    auto leaver = l.state_of_applicant();
    leaver.state = device::State::Left;
    leaver.kicked = std::chrono::floor<std::chrono::seconds>(clock_now_s());
    TestHelper::deliver_device_message(
            *l.core,
            TestHelper::encrypt_device_data(
                    l.applicant->devices, {{self.id, self}, {leaver.id, leaver}}),
            in(10min),
            "G2");
    auto account = *l.core->devices.next_account_rotation();
    auto device = *l.core->devices.next_device_rotation();
    REQUIRE(account <= clock_now() + Devices::KEY_ROTATION_JITTER);

    restart(l.core, l.events);
    CHECK(*l.core->devices.next_account_rotation() == account);
    CHECK(*l.core->devices.next_device_rotation() == device);
}

TEST_CASE(
        "Devices - a fork, and a dissolution not yet sent, survive a restart",
        "[core][devices][restart][dissolve]") {
    Linking l;
    TestHelper::finish_fetch(*l.core);
    TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_device_group(*other);
    auto theirs = *TestHelper::group_id(*other);
    TestHelper::deliver_device_message(
            *l.core, other->devices.build_device_group_message().message, in(10min), "B1");
    REQUIRE(l.core->devices.membership(await).membership == device::Membership::Forked);

    restart(l.core, l.events);
    TestHelper::finish_fetch(*l.core);
    CHECK(l.core->devices.membership(await).membership == device::Membership::Forked);
    CHECK(l.events.membership == std::vector{device::Membership::Forked});

    // Kept, with no network to send the dissolution by, and then the device stopped.
    REQUIRE(l.core->devices.dissolve_group(theirs, await));
    REQUIRE(pending_pushes(l.core) == 1);
    restart(l.core, l.events);
    auto* net = attach_mock_network(*l.core);
    TestHelper::finish_fetch(*l.core);
    REQUIRE(dissolutions(*net).size() == 1);
    TestHelper::deliver_device_message(*other, latest_tombstone(*net), in(10min), "T1");
    CHECK(other->devices.membership(await).membership == device::Membership::Dissolved);
}

TEST_CASE(
        "Devices - asking another group while approved lets the approval go",
        "[core][devices][linking][confirm]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    TempCore other{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_device_group(*other);
    TestHelper::deliver_device_message(
            *l.applicant, other->devices.build_device_group_message().message, in(10min), "B0");

    Asked first;
    request_link(l, first);
    auto request = uploaded(*net);
    answer_upload(l.applicant, *net, true);
    REQUIRE(first);
    REQUIRE(first->has_value());
    TestHelper::deliver_device_message(*l.core, request, (*first)->expires, "L1");
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    auto admission = l.core->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(*l.applicant, admission, in(10min), "G1");
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Approved);

    // The other group instead: a new request, with emoji of its own, and the move to Requesting
    // the asking device's own doing, so not reported.
    l.applicant_events.membership.clear();
    Asked second;
    request_link(l.applicant, *TestHelper::group_id(*other), second);
    answer_upload(l.applicant, *net, true);
    REQUIRE(second);
    REQUIRE(second->has_value());
    CHECK((*second)->sas != (*first)->sas);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Requesting);
    CHECK_FALSE(l.applicant->devices.confirm_link(await));
    CHECK(l.applicant_events.membership.empty());

    // And the approval of the first is nothing now, even fetched again.
    TestHelper::deliver_device_message(*l.applicant, admission, in(10min), "G1-again");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Requesting);
    CHECK_FALSE(l.applicant->devices.confirm_link(await));
    CHECK(own_state(l.applicant) == device::State::Pending);
    CHECK(l.applicant_events.membership.empty());

    // The existing device closed its prompt by approving, and is never told the approval was let
    // go: it goes on listing the applicant as a member, as with any approval never confirmed.
    auto approved = l.events.added.at(0).id;
    CHECK(std::ranges::none_of(l.events.ended, [&](const auto& e) { return e.first == approved; }));
    CHECK(l.core->devices.devices().contains(l.applicant_id()));
}

TEST_CASE(
        "Devices - the fetch timer tries again when its fetch fails", "[core][devices][rotation]") {
    Linking l;
    auto* net = attach_mock_network(*l.core);
    TestHelper::finish_fetch(*l.core);
    answer_upload(l.core, *net, true);
    auto account = account_key(l.core);
    auto device = device_key(l.core);

    // To within a second of the earlier rotation, the timer re-armed from there by a fetch.
    auto next = std::min(
            *l.core->devices.next_account_rotation(), *l.core->devices.next_device_rotation());
    ScopedClockOffset later{
            std::chrono::duration_cast<std::chrono::seconds>(next - clock_now()) - 1s};
    TestHelper::finish_fetch(*l.core);
    REQUIRE(eventually(
            *l.core, [&] { return std::ranges::any_of(net->sent_requests, is_device_fetch); }));

    // The swarm out of reach: nothing rotated, and the timer set to try again by itself.
    later.advance(2s);
    REQUIRE(answer_fetch(l.core, *net, {}, false) == 1);
    CHECK(account_key(l.core) == account);
    CHECK(device_key(l.core) == device);
    CHECK(TestHelper::fetch_timer_armed(*l.core));
    CHECK_FALSE(std::ranges::any_of(net->sent_requests, is_device_fetch));

    // Its retry, fired now rather than waited for, fetches again, and rotates after that fetch.
    TestHelper::fire_fetch_timer(*l.core);
    REQUIRE(eventually(
            *l.core, [&] { return std::ranges::any_of(net->sent_requests, is_device_fetch); }));
    REQUIRE(answer_fetch(l.core, *net) == 1);
    CHECK((account_key(l.core) != account || device_key(l.core) != device));
}

namespace {
// When a push that failed will be tried again, from now; zero for none.
std::chrono::milliseconds retry_in(TempCore& c) {
    auto due = TestHelper::push_retry_due(*c);
    return due ? std::chrono::ceil<std::chrono::seconds>(*due - clock_now_ms()) : 0ms;
}

// Fires the fetch timer, as its interval running out would, and answers the fetch it makes with
// nothing new: what follows is the push of whatever is owed.
void retry_now(TempCore& c, MockNetwork& net) {
    TestHelper::fire_fetch_timer(*c);
    REQUIRE(eventually(
            *c, [&] { return std::ranges::any_of(net.sent_requests, is_device_fetch); }));
    REQUIRE(answer_fetch(c, net) == 1);
    REQUIRE(pushes(net).size() == 1);
}
}  // namespace

TEST_CASE(
        "Devices - a group push the swarm did not store is tried again by a fetch of our own",
        "[core][devices][push]") {
    // A new account, owing its group's first push -- and subscribed, as far as this goes: nothing
    // polls, so nothing fetches unless something asks.
    TempCore c;
    auto* net = attach_mock_network(*c);
    TestHelper::finish_fetch(*c);
    REQUIRE(pushes(*net).size() == 1);

    answer_upload(c, *net, false);
    CHECK(retry_in(c) == Devices::PUSH_RETRY_FIRST);
    CHECK(TestHelper::fetch_timer_armed(*c));
    CHECK_FALSE(std::ranges::any_of(net->sent_requests, is_device_fetch));

    // Failing again waits longer.
    retry_now(c, *net);
    answer_upload(c, *net, false);
    CHECK(retry_in(c) == 2 * Devices::PUSH_RETRY_FIRST);

    // Stored at last: nothing left to try again, and a later failure waits only the first again.
    retry_now(c, *net);
    answer_upload(c, *net, true);
    CHECK_FALSE(TestHelper::push_retry_due(*c));
    CHECK_FALSE(c->devices.needs_push().device_group);

    device::Info renamed{};
    renamed.description = "renamed";
    c->devices.update_info(renamed, await);
    REQUIRE(answer_fetch(c, *net) == 1);
    answer_upload(c, *net, false);
    CHECK(retry_in(c) == Devices::PUSH_RETRY_FIRST);
}

TEST_CASE(
        "Devices - a departure the swarm did not store is tried again by a fetch of our own",
        "[core][devices][push][leave]") {
    Linking l;
    l.admit();
    auto* net = attach_mock_network(*l.core);
    REQUIRE(l.core->devices.leave_group(await));
    REQUIRE(pushes(*net).size() == 1);
    auto departure = pushed(*pushes(*net).front()).first;

    answer_upload(l.core, *net, false);
    CHECK(retry_in(l.core) == Devices::PUSH_RETRY_FIRST);
    CHECK(TestHelper::fetch_timer_armed(*l.core));

    // The same departure, kept as it was queued, and gone once the swarm has it.
    retry_now(l.core, *net);
    CHECK(pushed(*pushes(*net).front()).first == departure);
    answer_upload(l.core, *net, true);
    CHECK_FALSE(TestHelper::push_retry_due(*l.core));
    CHECK(pending_pushes(l.core) == 0);
}

TEST_CASE(
        "Devices - a change made while a group push is in flight follows it",
        "[core][devices][push]") {
    TempCore c;
    auto* net = attach_mock_network(*c);
    TestHelper::finish_fetch(*c);
    REQUIRE(pushes(*net).size() == 1);

    // Renamed while that is out: the fetch it asks for finds a push already in flight, and adds
    // none of its own.
    device::Info renamed{};
    renamed.description = "renamed";
    c->devices.update_info(renamed, await);
    REQUIRE(answer_fetch(c, *net) == 1);
    REQUIRE(pushes(*net).size() == 1);

    // The first lands, carrying the old record; the rename is still owed, and asks for the fetch
    // its push follows.
    answer_upload(c, *net, true);
    REQUIRE(c->devices.needs_push().device_group);
    REQUIRE(eventually(
            *c, [&] { return std::ranges::any_of(net->sent_requests, is_device_fetch); }));
    REQUIRE(answer_fetch(c, *net) == 1);
    REQUIRE(pushes(*net).size() == 1);
    answer_upload(c, *net, true);

    CHECK_FALSE(c->devices.needs_push().device_group);
    CHECK(c->devices.devices(true, true, true).at(Linking::id_of(c)).description == "renamed");
}

namespace {
// The namespaces a push stores to, in order.
std::vector<int> stored_namespaces(const MockNetwork::SentRequest& push) {
    std::vector<int> out;
    for (const auto& req : push_requests(push))
        if (req["method"] == "store")
            out.push_back(req["params"]["namespace"].get<int>());
    return out;
}
}  // namespace

TEST_CASE(
        "Devices - the account's key goes to -21 once PFS/PQ is enabled, by a member",
        "[core][devices][push][pfs]") {
    // The applicant is restored, so its account has not enabled PFS/PQ.
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    TestHelper::finish_fetch(*l.applicant);
    REQUIRE_FALSE(l.applicant->pfs_enabled());

    // Outside the group the setting is taken, but nothing is published: only a member keeps the
    // key current.
    l.applicant->enable_pfs();
    TestHelper::drain(*l.applicant);
    CHECK_FALSE(l.applicant->devices.needs_push().account_pubkey);
    CHECK_FALSE(std::ranges::any_of(net->sent_requests, is_device_fetch));

    // Admitted, and its group message pushed: what is owed then is the key alone, beside nothing.
    l.admit();
    TestHelper::finish_fetch(*l.applicant);
    while (!pushes(*net).empty()) {
        if (stored_namespaces(*pushes(*net).front()) == std::vector{-21})
            break;
        answer_upload(l.applicant, *net, true);
    }
    REQUIRE(pushes(*net).size() == 1);
    CHECK(stored_namespaces(*pushes(*net).front()) == std::vector{-21});

    // Refused, it is tried again as any push is; stored, nothing is owed.
    answer_upload(l.applicant, *net, false);
    CHECK(retry_in(l.applicant) == Devices::PUSH_RETRY_FIRST);
    retry_now(l.applicant, *net);
    CHECK(stored_namespaces(*pushes(*net).front()) == std::vector{-21});
    answer_upload(l.applicant, *net, true);
    CHECK_FALSE(l.applicant->devices.needs_push().account_pubkey);
    CHECK_FALSE(TestHelper::push_retry_due(*l.applicant));
}

TEST_CASE(
        "Devices - enabling PFS/PQ on a member fetches, and then publishes the key",
        "[core][devices][push][pfs]") {
    Linking l;
    l.admit();
    auto* net = attach_mock_network(*l.applicant);
    TestHelper::finish_fetch(*l.applicant);
    while (!pushes(*net).empty())
        answer_upload(l.applicant, *net, true);
    REQUIRE_FALSE(l.applicant->devices.needs_push().device_group);
    REQUIRE_FALSE(l.applicant->devices.needs_push().account_pubkey);

    // Not waiting for the swarm to send something: the fetch a push follows, asked for now.
    l.applicant->enable_pfs();
    REQUIRE(eventually(*l.applicant, [&] {
        return std::ranges::any_of(net->sent_requests, is_device_fetch);
    }));
    REQUIRE(answer_fetch(l.applicant, *net) == 1);
    REQUIRE(pushes(*net).size() == 1);
    CHECK(stored_namespaces(*pushes(*net).front()) == std::vector{-21});
    answer_upload(l.applicant, *net, true);
    CHECK_FALSE(l.applicant->devices.needs_push().account_pubkey);
}

TEST_CASE(
        "Devices - the account's current key seen on -21 is what our own copies go to at once",
        "[core][devices][pfs]") {
    Linking l;
    l.admit();
    auto own_keys = [&] { return l.applicant->pfs_key_info(l.applicant->globals.session_id()); };
    REQUIRE(own_keys().state == core::PfsKeyState::none);

    std::vector<std::optional<core::MessageEncryption>> sent;
    TestHelper::set_message_send_status(
            *l.applicant, [&](int64_t, core::MessageSendStatus s, auto, auto encryption) {
                if (s == core::MessageSendStatus::sending)
                    sent.push_back(encryption);
            });
    auto send_to_self = [&] {
        l.applicant->send_dm(
                l.applicant->globals.session_id(),
                std::as_bytes(std::span{"7801"_hex_b}),
                clock_now_ms());
    };

    SECTION("stored there by this device") {
        auto* net = attach_mock_network(*l.applicant);
        TestHelper::finish_fetch(*l.applicant);
        while (!pushes(*net).empty())
            answer_upload(l.applicant, *net, true);
        l.applicant->enable_pfs();
        REQUIRE(eventually(*l.applicant, [&] {
            return std::ranges::any_of(net->sent_requests, is_device_fetch);
        }));
        REQUIRE(answer_fetch(l.applicant, *net) == 1);
        REQUIRE(pushes(*net).size() == 1);

        // Not before the swarm has it.
        CHECK(own_keys().state == core::PfsKeyState::none);
        answer_upload(l.applicant, *net, true);

        auto [x25519, mlkem768] = TestHelper::active_account_pubkeys(*l.applicant);
        auto info = own_keys();
        CHECK(info.state == core::PfsKeyState::usable);
        CHECK(info.x25519_pub == x25519);
        CHECK(info.mlkem768_pub == mlkem768);
        REQUIRE(info.confirmed_at);
        CHECK(info.cache_expiry == *info.confirmed_at + Core::PFS_KEY_REFRESH);

        net->sent_requests.clear();
        send_to_self();
        CHECK(sent ==
              std::vector<std::optional<core::MessageEncryption>>{core::MessageEncryption::v2_pfs});
        CHECK_FALSE(std::ranges::any_of(net->sent_requests, [](const auto& r) {
            return r.request.endpoint == "retrieve";
        }));
    }

    SECTION("stored there by another device, and fetched") {
        TestHelper::deliver_pubkey_message(
                *l.applicant, l.core->devices.build_account_pubkey_message(), "P1");

        auto [x25519, mlkem768] = TestHelper::active_account_pubkeys(*l.core);
        auto info = own_keys();
        CHECK(info.state == core::PfsKeyState::usable);
        CHECK(info.x25519_pub == x25519);
        CHECK(info.mlkem768_pub == mlkem768);

        send_to_self();
        CHECK(sent ==
              std::vector<std::optional<core::MessageEncryption>>{core::MessageEncryption::v2_pfs});
    }

    SECTION("a key rotated away since: nothing") {
        auto old = l.applicant->devices.build_account_pubkey_message();
        ScopedClockOffset later{1min};
        l.applicant->devices.rotate_account_keys();
        TestHelper::deliver_pubkey_message(*l.applicant, old, "P1");
        CHECK(own_keys().state == core::PfsKeyState::none);
    }
}

namespace {
// A key published to -21 under the account's seed by a device that is none of ours: a seed holder
// elsewhere, with keys of its own.
std::vector<std::byte> foreign_pubkey_message(TempCore& c) {
    TempCore stranger{core::predefined_seed{std::span<const std::byte, 32>{Linking::seed_of(c)}}};
    return stranger->devices.build_account_pubkey_message();
}

// `c` watching for rogue keys, with everything it owes pushed, so that what follows is all a key
// on -21 makes it do.
MockNetwork* watching(TempCore& c, int& alerts) {
    TestHelper::set_rogue_account_key(*c, [&alerts] { alerts++; });
    auto* net = attach_mock_network(*c);
    TestHelper::finish_fetch(*c);
    while (!pushes(*net).empty())
        answer_upload(c, *net, true);
    return net;
}

bool device_fetch_asked(TempCore& c, MockNetwork& net) {
    return eventually(*c, [&] { return std::ranges::any_of(net.sent_requests, is_device_fetch); });
}
}  // namespace

TEST_CASE(
        "Devices - a key on -21 that is not ours is judged once the group has been fetched",
        "[core][devices][pfs][rogue]") {
    Linking l;
    l.admit();
    int alerts = 0;
    auto* net = watching(l.core, alerts);
    REQUIRE(l.core->pfs_enabled());
    REQUIRE_FALSE(l.core->devices.needs_push().account_pubkey);

    SECTION("another device's rotation, its -21 store seen before its group message: nothing") {
        l.applicant->devices.rotate_account_keys();
        TestHelper::deliver_pubkey_message(
                *l.core, l.applicant->devices.build_account_pubkey_message(), "P2");
        CHECK(alerts == 0);

        // Not judged on sight: a fetch of the group is asked for, and the rotation is in it.
        REQUIRE(device_fetch_asked(l.core, *net));
        TestHelper::deliver_device_message(
                *l.core,
                l.applicant->devices.build_device_group_message().message,
                in(10min),
                "G9");
        REQUIRE(answer_fetch(l.core, *net) == 1);
        CHECK(alerts == 0);
        CHECK_FALSE(l.core->devices.needs_push().account_pubkey);
    }

    SECTION("a key none of ours, still unknown after the fetch: rogue, and ours goes over it") {
        TestHelper::deliver_pubkey_message(*l.core, foreign_pubkey_message(l.core), "P2");
        CHECK(alerts == 0);
        REQUIRE(device_fetch_asked(l.core, *net));
        REQUIRE(answer_fetch(l.core, *net) == 1);
        CHECK(alerts == 1);
        CHECK(l.core->devices.needs_push().account_pubkey);
        REQUIRE(pushes(*net).size() == 1);
        CHECK(stored_namespaces(*pushes(*net).front()) == std::vector{-21});
    }

    SECTION("our own key, rotated away since: nothing, and nothing to check") {
        auto old = l.core->devices.build_account_pubkey_message();
        l.core->devices.rotate_account_keys();
        TestHelper::deliver_pubkey_message(*l.core, old, "P2");
        TestHelper::drain(*l.core);
        CHECK(alerts == 0);
        CHECK_FALSE(std::ranges::any_of(net->sent_requests, is_device_fetch));
    }
}

TEST_CASE(
        "Devices - a rogue key is reported without PFS/PQ, and nothing is published over it",
        "[core][devices][pfs][rogue]") {
    // The applicant is restored, so its account has not enabled PFS/PQ.
    Linking l;
    l.admit();
    int alerts = 0;
    auto* net = watching(l.applicant, alerts);
    REQUIRE_FALSE(l.applicant->pfs_enabled());

    TestHelper::deliver_pubkey_message(*l.applicant, foreign_pubkey_message(l.applicant), "P2");
    REQUIRE(device_fetch_asked(l.applicant, *net));
    REQUIRE(answer_fetch(l.applicant, *net) == 1);
    CHECK(alerts == 1);
    CHECK_FALSE(l.applicant->devices.needs_push().account_pubkey);
    CHECK(pushes(*net).empty());
}

TEST_CASE(
        "Devices - account_keys lists the account's keys without their secrets",
        "[core][devices][pfs]") {
    TempCore c;
    auto first = c->devices.active_account_keys().front();
    {
        // Later than the first, so that the new key is the current one rather than a tie.
        ScopedClockOffset later{1min};
        c->devices.rotate_account_keys();
    }
    auto current = c->devices.active_account_keys().front();
    REQUIRE(current.x25519_pub != first.x25519_pub);

    // Current first, then the rotated one, which is kept for its retention after it was replaced.
    auto keys = c->devices.account_keys();
    REQUIRE(keys.size() == 2);
    CHECK(keys[0].x25519_pub == current.x25519_pub);
    CHECK(keys[0].mlkem768_pub == current.mlkem768_pub);
    CHECK(keys[0].created == current.created);
    CHECK_FALSE(keys[0].rotated);
    CHECK_FALSE(keys[0].retained_until);
    CHECK(keys[1].x25519_pub == first.x25519_pub);
    CHECK(keys[1].created == first.created);
    REQUIRE(keys[1].rotated);
    CHECK(*keys[1].retained_until ==
          *keys[1].rotated +
                  std::chrono::duration_cast<std::chrono::seconds>(Devices::ACCOUNT_KEY_RETENTION));

    // Seen on -21: that key, and only that one.
    CHECK_FALSE(keys[0].published);
    TestHelper::deliver_pubkey_message(*c, c->devices.build_account_pubkey_message());
    keys = c->devices.account_keys();
    CHECK(keys[0].published);
    CHECK_FALSE(keys[1].published);

    // Past its retention the rotated one is gone.
    ScopedClockOffset later{Devices::ACCOUNT_KEY_RETENTION + 1h};
    keys = c->devices.account_keys();
    REQUIRE(keys.size() == 1);
    CHECK(keys[0].x25519_pub == current.x25519_pub);
}

TEST_CASE(
        "Devices - a device outside its group does not judge what -21 holds",
        "[core][devices][pfs][rogue]") {
    Linking l;
    int alerts = 0;
    TestHelper::set_rogue_account_key(*l.applicant, [&alerts] { alerts++; });
    std::vector<std::byte> key;

    SECTION("restored, with its account's group in view: the group's own key") {
        // Holding no account keys at all, so every key of its group is one it does not hold.
        l.show_group();
        REQUIRE(l.applicant->devices.membership(await).membership ==
                device::Membership::DeviceGroupVisible);
        key = l.core->devices.build_account_pubkey_message();
    }
    SECTION("removed: a key it does not hold") {
        l.admit();
        REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
        TestHelper::deliver_device_message(
                *l.applicant,
                l.core->devices.build_device_group_message().message,
                in(10min),
                "G2");
        REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Removed);
        key = foreign_pubkey_message(l.core);
    }

    auto* net = attach_mock_network(*l.applicant);
    TestHelper::deliver_pubkey_message(*l.applicant, key, "P1");
    TestHelper::drain(*l.applicant);
    CHECK(alerts == 0);
    CHECK_FALSE(std::ranges::any_of(net->sent_requests, is_device_fetch));
}

TEST_CASE(
        "Devices - an admission stored as the asking device subscribed arrives all the same",
        "[core][devices][linking][poll]") {
    Linking l;
    auto* net = attach_push_network(*l.applicant);
    auto group = l.show_group();
    Asked got;
    request_link(l.applicant, group, got);
    auto request = uploaded(*net);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());

    // The asking device drains its swarm and subscribes, so that nothing polls from here.
    TestHelper::poll(*l.applicant);
    REQUIRE(subscribe(*net));
    REQUIRE_FALSE(TestHelper::polling(*l.applicant));

    // Approved in the moment between: too late for the draining poll, too early to be pushed.
    TestHelper::deliver_device_message(*l.core, request, (*got)->expires, "L1");
    REQUIRE(l.core->devices.accept_request(l.events.added.back().id, await));
    auto admission = l.core->devices.build_device_group_message().message;

    // The poll that closes that gap fails, which once left the device waiting for a restart.
    REQUIRE(answer_batch(*net, {}, false));
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Requesting);

    // Core polls again by itself, and the admission is there.
    TestHelper::fire_poll_retry(*l.applicant);
    REQUIRE(answer_batch(*net, {{21, {{admission, "G1"}}}}));
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Approved);
}

TEST_CASE(
        "Devices - a device fetches -21 itself on becoming a member",
        "[core][devices][pfs][rogue]") {
    Linking l;
    int alerts = 0;
    TestHelper::set_rogue_account_key(*l.applicant, [&alerts] { alerts++; });
    auto* net = attach_mock_network(*l.applicant);
    auto settle = [&] {
        while (std::ranges::any_of(net->sent_requests, is_device_fetch))
            answer_fetch(l.applicant, *net);
        while (!pushes(*net).empty())
            answer_upload(l.applicant, *net, true);
    };

    bool rogue = GENERATE(false, true);
    std::vector<std::byte> key;
    SECTION("admitted") {
        l.admit();
        key = rogue ? foreign_pubkey_message(l.core)
                    : l.core->devices.build_account_pubkey_message();
    }
    SECTION("starting a group") {
        TestHelper::finish_fetch(*l.applicant);
        start_over(l.applicant);
        key = rogue ? foreign_pubkey_message(l.applicant)
                    : l.applicant->devices.build_account_pubkey_message();
    }

    // Nothing polls here, as nothing does on a device subscribed for pushes: the read is asked for
    // at once, and what it finds is judged as a member.
    REQUIRE(eventually(*l.applicant, [&] {
        return std::ranges::any_of(net->sent_requests, is_pubkey_fetch);
    }));
    REQUIRE(answer_fetch_of(-21, l.applicant, *net, {{key, "P1"}}) == 1);
    settle();
    CHECK(alerts == (rogue ? 1 : 0));
    CHECK(l.applicant->devices.account_keys().front().published == !rogue);
}

TEST_CASE(
        "Devices - a device reads -21 again once admitted, and judges it then",
        "[core][devices][pfs][rogue]") {
    Linking l;
    int alerts = 0;
    TestHelper::set_rogue_account_key(*l.applicant, [&alerts] { alerts++; });
    auto* net = attach_mock_network(*l.applicant);
    net->current_node.remote_pubkey[0] = std::byte{0xAA};
    auto cursor = [&] {
        return TestHelper::namespace_last_hash(
                *l.applicant,
                static_cast<int16_t>(config::Namespace::AccountPubkeys),
                net->current_node.remote_pubkey);
    };
    // Answers every fetch of the group asked for, so that a key held over from before would be
    // judged by the time this returns.
    auto settle = [&] {
        while (std::ranges::any_of(net->sent_requests, is_device_fetch))
            answer_fetch(l.applicant, *net);
        while (!pushes(*net).empty())
            answer_upload(l.applicant, *net, true);
    };

    bool rogue = GENERATE(false, true);
    auto key =
            rogue ? foreign_pubkey_message(l.core) : l.core->devices.build_account_pubkey_message();

    // Seen while asking, and passed by the retrieve cursor, as a poll leaves it.
    TestHelper::deliver_pubkey_message(*l.applicant, key, "P1");
    TestHelper::record_swarm_cursor(
            *l.applicant, net->current_node, config::Namespace::AccountPubkeys, "P1");
    REQUIRE(cursor() == "P1");

    // Admitted: the cursor is gone, so the next poll reads -21 from the start -- and nothing from
    // before is held over to be judged.
    l.admit();
    CHECK_FALSE(cursor());
    TestHelper::finish_fetch(*l.applicant);
    settle();
    CHECK(alerts == 0);

    // What the re-read finds, judged now that it holds the group's keys.
    TestHelper::deliver_pubkey_message(*l.applicant, key, "P1");
    settle();
    CHECK(alerts == (rogue ? 1 : 0));
}

TEST_CASE(
        "Devices - two fetches of the same namespace asked at once are one request",
        "[core][devices][fetch]") {
    TempCore c;
    auto* net = attach_mock_network(*c);
    int done = 0;
    for (int i = 0; i < 2; i++)
        TestHelper::fetch(*c, {config::Namespace::Devices}, [&done](bool fetched) {
            if (fetched)
                done++;
        });
    TestHelper::drain(*c);
    CHECK(std::ranges::count_if(net->sent_requests, is_device_fetch) == 1);

    REQUIRE(answer_fetch(c, *net) == 1);
    CHECK(done == 2);
    CHECK_FALSE(std::ranges::any_of(net->sent_requests, is_device_fetch));
}

namespace {

// `message`'s outer dict with `key` added where it sorts, and signed again by `signer`'s account
// key as its author would have: what a later version of the format might send.
std::vector<std::byte> with_extra_key(
        TempCore& signer, std::span<const std::byte> message, std::string_view key) {
    oxenc::bt_dict_consumer in{message};
    oxenc::bt_dict_producer out;
    bool added = false;
    auto add = [&] {
        out.append(key, "from a later version");
        added = true;
    };
    while (!in.is_finished() && in.key() != "~") {
        if (!added && key < in.key())
            add();
        auto k = std::string{in.key()};
        if (in.is_integer())
            out.append(k, in.consume_integer<int64_t>());
        else
            out.append(k, in.consume_string_view());
    }
    if (!added)
        add();
    out.append_signature("~", [&](std::span<const std::byte> body) {
        auto seed = signer->globals.account_seed();
        return ed25519::sign(seed.ed25519_secret(), body);
    });
    return to_vector<std::byte>(std::move(out).str());
}

}  // namespace

TEST_CASE(
        "Devices - a tombstone carrying a field from a later version is a removal all the same",
        "[core][devices][wire]") {
    Linking l;
    l.admit();
    TempCore third{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    join(l, third);

    // The applicant's view of the group, the third device removed, written as a later version
    // would write the tombstone.
    auto group = l.applicant->devices.devices(true, true, true);
    auto& gone = group.at(Linking::id_of(third));
    gone.state = device::State::Kicked;
    gone.kicked = std::chrono::floor<std::chrono::seconds>(clock_now_s());
    auto plaintext = to_string(TestHelper::decrypt_device_data(
            l.applicant->devices, TestHelper::encrypt_device_data(l.applicant->devices, group)));
    auto plain = "d1:ri{}ee"_format(gone.kicked->time_since_epoch().count());
    auto pos = plaintext.find(plain);
    REQUIRE(pos != std::string::npos);
    plaintext.replace(
            pos,
            plain.size(),
            "d1:ri{}e1:z6:futuree"_format(gone.kicked->time_since_epoch().count()));

    l.events = DeviceEventsRecorder{};
    TestHelper::deliver_device_message(
            *l.core,
            TestHelper::encrypt_device_payload(l.applicant->devices, group, plaintext),
            in(10min),
            "G3");
    auto held = l.core->devices.devices(true, true, true);
    CHECK(held.at(Linking::id_of(third)).state == device::State::Kicked);
    REQUIRE(l.events.members.size() == 1);
    CHECK(l.events.members[0].id == Linking::id_of(third));
    CHECK(l.events.members[0].state == device::State::Kicked);
    CHECK(l.events.replaced.size() == 1);
}

TEST_CASE(
        "Devices - outer fields from a later version are carried by the signature and ignored",
        "[core][devices][wire]") {
    Linking l;
    l.admit();

    SECTION("in a group message") {
        // The admission's push confirmed, so that the record below is one past what it carried.
        push_from(l.core, "G1");
        auto [self, registered] = l.core->devices.device_info(await);
        self.description = "Renamed";
        l.core->devices.update_info(self, await);
        auto message =
                with_extra_key(l.core, l.core->devices.build_device_group_message().message, "j");
        l.applicant_events.replaced.clear();
        TestHelper::deliver_device_message(*l.applicant, message, in(10min), "G2");
        CHECK(l.applicant->devices.devices().at(self.id).description == "Renamed");
        CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
        CHECK(l.applicant_events.replaced.size() == 1);
    }

    SECTION("in a tombstone") {
        TempCore keeper{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
        auto tombstone = with_extra_key(
                keeper,
                TestHelper::build_dissolution(*keeper, {*TestHelper::group_id(*l.applicant)}),
                "j");
        TestHelper::deliver_device_message(*l.applicant, tombstone, in(10min), "T1");
        CHECK(l.applicant->devices.membership(await).membership == device::Membership::Dissolved);
    }
}

TEST_CASE(
        "Devices - a record's fields from a later version are kept and carried on",
        "[core][devices][wire]") {
    Linking l;
    l.admit();
    auto core_self = l.core->devices.device_info(await).first;

    // The applicant, become a later version, describes itself with a field this one does not know.
    auto newer = l.applicant->devices.device_info(await).first;
    newer.seqno++;
    newer.extra["zz"] = "future";
    l.events.replaced.clear();
    TestHelper::deliver_device_message(
            *l.core,
            TestHelper::encrypt_device_data(
                    l.applicant->devices, {{core_self.id, core_self}, {newer.id, newer}}),
            in(10min),
            "G2");
    auto held = l.core->devices.devices().at(newer.id);
    REQUIRE(held.extra.contains("zz"));
    CHECK(std::get<std::string>(held.extra.at("zz")) == "future");
    CHECK(l.events.replaced.size() == 1);

    // And the existing device's own next push says it on the applicant's behalf, unchanged.
    auto pushed_payload = to_string(TestHelper::decrypt_device_data(
            l.core->devices, l.core->devices.build_device_group_message().message));
    CHECK(pushed_payload.find("2:zz6:future") != std::string::npos);
}

TEST_CASE(
        "Devices - an account key pruned takes the devices it reached with it",
        "[core][devices][rotation]") {
    Linking l;
    l.admit();
    push_from(l.core, "G1");
    auto key = account_key(l.core);
    auto recipients_of = [&](const std::array<std::byte, 32>& pub) {
        return l.core->database().conn().prepared_get<int>(
                "SELECT count(*) FROM device_account_key_recipients r"
                " JOIN device_account_keys k ON k.id = r.key WHERE k.pubkey_x25519 = ?",
                pub);
    };
    auto rows = [&] {
        return l.core->database().conn().prepared_get<int>(
                "SELECT count(*) FROM device_account_key_recipients");
    };
    REQUIRE(recipients_of(key) == 2);

    // Rotated away, and kept for as long as contacts may still encrypt to it; then gone, and what
    // it reached gone with it.
    l.core->devices.rotate_account_keys();
    auto before = rows();
    ScopedClockOffset later{Devices::ACCOUNT_KEY_RETENTION + 2s};
    l.core->devices.active_account_keys();
    CHECK(account_key_count(l.core) == 1);
    CHECK(rows() == before - 2);
}

TEST_CASE(
        "Devices - a key rotated by a device with a slow clock is not the link key at once",
        "[core][devices][rotation]") {
    Linking l;
    l.admit();
    auto group = *TestHelper::group_id(*l.core);
    push_from(l.core, "G1");
    auto previous = account_key(l.core);
    REQUIRE(TestHelper::seen_group(*l.core, group)->first == previous);

    // The applicant's clock is ten minutes behind: it rotates, and its push is written as of then.
    ScopedClockOffset slow{-10min};
    l.applicant->devices.rotate_account_keys();
    auto rotated = account_key(l.applicant);
    TestHelper::deliver_device_message(*l.core, push_from(l.applicant, "G2"), in(10min), "G2");

    // The existing device takes the new key as current, being the newest made -- but the link key
    // it holds for the group is the one in the group's newest message by `t`, which is still its
    // own.  Joining devices go on encrypting to the previous key, which is retained and honoured,
    // until a push dated later than that one says otherwise.
    CHECK(account_key(l.core) == rotated);
    CHECK(TestHelper::seen_group(*l.core, group)->first == previous);
}
