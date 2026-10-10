#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <sodium/crypto_sign_ed25519.h>

#include <catch2/catch_test_macros.hpp>
#include <session/clock.hpp>
#include <session/core.hpp>
#include <session/core/devices.hpp>
#include <session/core/error_codes.hpp>
#include <session/core/globals.hpp>
#include <session/xed25519.hpp>
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

    SECTION("device_id is 64-char hex") {
        auto id = c->devices.device_id();
        REQUIRE(id.size() == 64);
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
        // seqno == 0 is the sentinel meaning no row exists yet
        CHECK(info.seqno == 0);
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

    SECTION("update_info persists fields and sets seqno=1") {
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
    }

    SECTION("identical update does not bump seqno") {
        device::Info info{};
        info.type = device::Type::Session_Desktop;
        info.description = "desktop";
        info.version = {0, 1, 0};

        c->devices.update_info(info, await);
        CHECK(c->devices.device_info(await).first.seqno == 1);

        c->devices.update_info(info, await);  // identical — should not bump
        CHECK(c->devices.device_info(await).first.seqno == 1);
    }

    SECTION("changed description bumps seqno") {
        device::Info info{};
        info.description = "first";
        c->devices.update_info(info, await);
        CHECK(c->devices.device_info(await).first.seqno == 1);

        info.description = "second";
        c->devices.update_info(info, await);
        CHECK(c->devices.device_info(await).first.seqno == 2);
    }

    SECTION("changed type bumps seqno") {
        device::Info info{};
        info.type = device::Type::Session_Android;
        c->devices.update_info(info, await);
        CHECK(c->devices.device_info(await).first.seqno == 1);

        info.type = device::Type::Session_Desktop;
        c->devices.update_info(info, await);
        CHECK(c->devices.device_info(await).first.seqno == 2);
    }

    SECTION("changed version bumps seqno") {
        device::Info info{};
        info.version = {1, 0, 0};
        c->devices.update_info(info, await);
        CHECK(c->devices.device_info(await).first.seqno == 1);

        info.version = {2, 0, 0};
        c->devices.update_info(info, await);
        CHECK(c->devices.device_info(await).first.seqno == 2);
    }

    SECTION("extra fields round-trip and participate in comparison") {
        device::Info info{};
        info.extra["custom_key"] = std::string{"hello"};
        c->devices.update_info(info, await);

        auto [got, _] = c->devices.device_info(await);
        CHECK(got.seqno == 1);
        REQUIRE(got.extra.count("custom_key"));
        CHECK(std::get<std::string>(got.extra.at("custom_key")) == "hello");

        // Same extra — no bump
        c->devices.update_info(info, await);
        CHECK(c->devices.device_info(await).first.seqno == 1);

        // Changed extra — bump
        info.extra["custom_key"] = std::string{"world"};
        c->devices.update_info(info, await);
        CHECK(c->devices.device_info(await).first.seqno == 2);
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

    SECTION("update_info device appears in devices(include_unregistered=true)") {
        device::Info info{};
        info.description = "my device";
        c->devices.update_info(info, await);

        auto devs = c->devices.devices(false, false, true);
        CHECK(devs.size() == 1);
        CHECK(devs.begin()->second.description == "my device");
    }
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

    SECTION("after two rotations active_device_keys has three entries") {
        c->devices.active_device_keys();  // ensure initial key exists
        c->devices.rotate_device_keys();
        c->devices.rotate_device_keys();
        auto keys = c->devices.active_device_keys();
        CHECK(keys.size() == 3);
        CHECK_FALSE(keys[0].rotated.has_value());
        CHECK(keys[1].rotated.has_value());
        CHECK(keys[2].rotated.has_value());
    }
}

TEST_CASE("Devices - device group payload padding", "[core][devices]") {
    TempCore c;

    // Real keys, not random bytes: ML-KEM encapsulation is performed against each device's pubkey.
    // Rotating produces distinct valid keypairs, and all of them stay in this device's active key
    // set, so this Core can also decrypt whatever it encrypts below.
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
        for (size_t i = 0; i < 3; i++)
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

TEST_CASE("Devices - build_link_request", "[core][devices]") {
    // Restored, not generated: asking to join a group only makes sense for a device that adopted
    // an existing account's seed.  A device that generated the account *is* the group.
    auto c = restored_core();
    TempCore group;  // only its link key is used, to encrypt to

    SECTION("returns non-empty message and 21-entry SAS") {
        auto result = TestHelper::build_link_request(*c, *group);
        CHECK_FALSE(result.message.empty());
        CHECK(result.sas.size() == 21);
        for (const auto& s : result.sas)
            CHECK_FALSE(s.empty());
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
        std::optional<std::array<std::byte, 32>> first_id;
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
    auto state_of = [&](const std::array<std::byte, 32>& id) {
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
    auto state_of = [&](const std::array<std::byte, 32>& id) {
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
    auto state_of = [&](const std::array<std::byte, 32>& id) {
        auto devs = c->devices.devices(true, true, true);
        auto found = devs.find(id);
        REQUIRE(found != devs.end());
        return found->second;
    };
    auto tombstone = [&](const std::array<std::byte, 32>& id, device::State state, auto when) {
        device::Info t{};
        t.id = id;
        t.state = state;
        t.kicked = when;
        return t;
    };

    std::array<std::byte, 32> id;
    random::fill(id);
    auto t0 = clock_now_s() - 3h;
    auto t1 = clock_now_s() - 2h;
    auto t2 = clock_now_s() - 1h;

    // It leaves.
    deliver({{self.id, self}, {id, tombstone(id, device::State::Left, t1)}});
    CHECK(state_of(id).state == device::State::Left);
    CHECK(state_of(id).kicked == t1);

    // And is written back as a departure: the timestamp negated.
    auto plaintext = TestHelper::decrypt_device_data(
            c->devices,
            TestHelper::encrypt_device_data(c->devices, c->devices.devices(true, true, true)));
    oxenc::bt_dict_consumer btdc{to_string_view(plaintext)};
    REQUIRE(btdc.skip_until("D"));
    auto devs = btdc.consume_dict_consumer();
    REQUIRE(devs.skip_until(std::string_view{reinterpret_cast<const char*>(id.data()), id.size()}));
    CHECK(devs.consume_integer<int64_t>() == -t1.time_since_epoch().count());

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
    std::array<std::byte, 32> leaver;
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

    static std::array<std::byte, 32> id_of(TempCore& c) {
        auto hex = c->devices.device_id();
        std::array<std::byte, 32> id;
        oxenc::from_hex(hex.begin(), hex.end(), reinterpret_cast<unsigned char*>(id.data()));
        return id;
    }

    std::array<std::byte, 32> applicant_id() { return id_of(applicant); }

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
    // GroupsVisible -- before it asks.
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

    // The applicant asks, is accepted here, has its user confirm the SAS, and reads the group
    // message admitting it, leaving a group of two.
    void admit() {
        ask();
        REQUIRE(core->devices.accept_request(events.added.at(0).id, await));
        REQUIRE(applicant->devices.confirm_link(await));
        TestHelper::deliver_device_message(
                *applicant,
                core->devices.build_device_group_message().message,
                std::chrono::floor<std::chrono::seconds>(clock_now_s()) + 10min,
                "G1");
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
    CHECK(std::ranges::find(push.broadcast, l.applicant_id()) != push.broadcast.end());

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
    CHECK_FALSE(l.core->devices.accept_request(id, await));
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

    // Every group message carries every tombstone.
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

    // Its own request has it Waiting, which it knows: it is the one asking.
    l.ask();
    TestHelper::finish_fetch(*l.applicant);
    CHECK(l.applicant_events.membership.empty());

    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    auto group = l.core->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(*l.applicant, group, in(10min), "G1");

    // Admitted, but not in until its user confirms the SAS.
    CHECK(l.applicant_events.membership.empty());
    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(l.applicant_events.membership == std::vector{device::Membership::InGroup});
}

namespace {

using Asked = std::optional<Expected<Devices::OutgoingLinkRequest>>;

// Asks for a link from `c` and runs the job, so that the upload has been sent by the time this
// returns.  What it answers lands in `into`, once the upload is answered.
void request_link(TempCore& c, const device::GroupId& group, Asked& into) {
    c->devices.request_link(
            group, [&into](Expected<Devices::OutgoingLinkRequest> r) { into = std::move(r); });
    TestHelper::drain(*c);
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
                auto result = stored ? nlohmann::json{{"code", 200}, {"body", {{"hash", "L1"}}}}
                                     : nlohmann::json{{"code", 406}, {"body", "refused"}};
                r.callback(true, false, 200, {}, nlohmann::json{{"results", {result}}}.dump());
            },
            1);
    REQUIRE(answered == 1);
    TestHelper::drain(*c);
}

device::State own_state(TempCore& c) {
    return c->devices.device_info(await).first.state;
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
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Waiting);

    // What the waiting screen is redrawn from is what it was first drawn from.
    auto waiting = l.applicant->devices.outgoing_link_request(await);
    REQUIRE(waiting);
    CHECK(same(*waiting, asked));

    // The other device prompts with what this one shows, and the user, seeing them match, says so
    // on both.
    TestHelper::deliver_device_message(*l.core, message, asked.expires, "L1");
    REQUIRE(l.events.added.size() == 1);
    CHECK(l.events.added[0].sas == asked.sas);
    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(l.applicant->devices.outgoing_link_request(await)->confirmed);

    REQUIRE(l.core->devices.accept_request(l.events.added[0].id, await));
    auto group = l.core->devices.build_device_group_message().message;
    TestHelper::deliver_device_message(*l.applicant, group, in(10min), "G1");

    // Seeing the group, then -- not asking, which it did itself -- being admitted to it.
    CHECK(l.applicant_events.membership ==
          std::vector{device::Membership::GroupsVisible, device::Membership::InGroup});
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
    CHECK(l.applicant_events.membership == std::vector{device::Membership::GroupsVisible});
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
        "Devices - a request being replaced is not shown while its replacement uploads",
        "[core][devices][linking][request]") {
    Linking l;
    auto* net = attach_mock_network(*l.applicant);
    Asked first, second;
    request_link(l, first);
    answer_upload(l.applicant, *net, true);
    REQUIRE(l.applicant->devices.outgoing_link_request(await));

    // Its SAS is about to be superseded, so it must not be what a redraw shows in the meantime.
    request_link(l, second);
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));

    answer_upload(l.applicant, *net, true);
    auto waiting = l.applicant->devices.outgoing_link_request(await);
    REQUIRE(waiting);
    REQUIRE(second);
    REQUIRE(second->has_value());
    CHECK(same(*waiting, **second));
    CHECK(waiting->sas != (*first)->sas);
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

    REQUIRE(l.applicant_events.membership == std::vector{device::Membership::GroupsVisible});
    l.applicant_events.membership.clear();

    // Brought to within a second of the deadline, and the timer re-armed from there, so that it is
    // the timer that finds the request lapsed rather than anything this test does.
    ScopedClockOffset later{Devices::LINK_REQUEST_TTL - 1s};
    TestHelper::finish_fetch(*l.applicant);
    REQUIRE(l.applicant_events.membership.empty());

    REQUIRE(eventually(*l.applicant, [&] { return !l.applicant_events.membership.empty(); }));
    CHECK(l.applicant_events.membership == std::vector{device::Membership::GroupsVisible});
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
    CHECK(l.applicant_events.membership == std::vector{device::Membership::GroupsVisible});
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
    CHECK(l.applicant_events.membership == std::vector{device::Membership::GroupsVisible});
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

    // The key follows the group's newest message, whichever order they arrive in.
    l.core->devices.rotate_account_keys();
    auto second_key = key();
    REQUIRE(second_key != first_key);
    auto second = l.core->devices.build_device_group_message().message;
    {
        ScopedClockOffset later{1h};
        TestHelper::deliver_device_message(*l.applicant, second, in(10min), "G2");
    }
    CHECK(TestHelper::seen_group(*l.applicant, *group)->first == second_key);
    TestHelper::deliver_device_message(*l.applicant, first, expiry, "G1");
    CHECK(TestHelper::seen_group(*l.applicant, *group)->first == second_key);

    // Not from a message whose signature does not check out: anything else could plant a key of
    // its own for requests to this group to be encrypted to.
    auto forged = first;
    oxenc::bt_dict_consumer outer{forged};
    auto x_at = outer.require_span<std::byte>("X").data() - forged.data();
    forged[x_at] ^= std::byte{1};
    {
        ScopedClockOffset later{2h};
        TestHelper::deliver_device_message(*l.applicant, forged, in(10min), "G3");
    }
    CHECK(TestHelper::seen_group(*l.applicant, *group)->first == second_key);
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
        "Devices - a group from before identifiers gets one from its first push",
        "[core][devices][group-id]") {
    Linking l;
    l.admit();
    for (auto* c : {&l.core, &l.applicant})
        (*c)->database().conn().prepared_exec("DELETE FROM globals WHERE key = 'devices_group_id'");

    auto message = l.core->devices.build_device_group_message().message;
    auto minted = TestHelper::group_id(*l.core);
    REQUIRE(minted);
    CHECK(TestHelper::group_of(*l.core, message) == minted);

    // And the rest of the group adopts it, rather than minting a different one of its own.
    TestHelper::deliver_device_message(*l.applicant, message, in(10min), "G2");
    CHECK(TestHelper::group_id(*l.applicant) == minted);
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
    CHECK(state.membership == device::Membership::GroupsVisible);
    CHECK_FALSE(state.group);
    REQUIRE(state.others.size() == 1);
    CHECK(state.others[0].id == group);
    CHECK(l.applicant_events.membership ==
          std::vector{device::Membership::NoGroup, device::Membership::GroupsVisible});
}

TEST_CASE(
        "Devices - a second group alongside ours is alerted, until dismissed",
        "[core][devices][membership]") {
    Linking l;
    TestHelper::finish_fetch(*l.core);

    // Another device on the account starts a group of its own.
    TestHelper::start_group(*l.applicant);
    auto second = TestHelper::group_id(*l.applicant);
    REQUIRE(second);
    auto theirs = [&](std::string hash) {
        TestHelper::deliver_device_message(
                *l.core,
                l.applicant->devices.build_device_group_message().message,
                in(10min),
                std::move(hash));
    };

    theirs("B1");
    CHECK(l.events.appeared == std::vector{*second});
    auto state = l.core->devices.membership(await);
    CHECK(state.membership == device::Membership::InGroup);
    REQUIRE(state.others.size() == 1);
    CHECK(state.others[0].id == *second);
    CHECK_FALSE(state.others[0].dismissed);

    // Once per run, not per message.
    theirs("B2");
    CHECK(l.events.appeared.size() == 1);

    // Dismissed, it stays quiet across a restart, where an undismissed one would alert again.
    REQUIRE(l.core->devices.dismiss_group(*second, await));
    CHECK(l.core->devices.membership(await).others.at(0).dismissed);
    l.core.core.reset();
    l.core.core = std::make_unique<core::Core>(l.core.path, Linking::reporting_to(l.events));
    l.events.appeared.clear();
    theirs("B3");
    CHECK(l.events.appeared.empty());

    // A group it has not dismissed still alerts.
    TempCore third{core::predefined_seed{std::span<const std::byte, 32>{l.seed}}};
    TestHelper::start_group(*third);
    TestHelper::deliver_device_message(
            *l.core, third->devices.build_device_group_message().message, in(10min), "C1");
    CHECK(l.events.appeared == std::vector{*TestHelper::group_id(*third)});

    // And one never seen is nothing to dismiss.
    CHECK_FALSE(l.core->devices.dismiss_group(device::GroupId{}, await));
}

TEST_CASE(
        "Devices - a device whose group is gone beside another is cut off, dismissed or not",
        "[core][devices][membership]") {
    Linking l;

    // Another group, whose message outlives everything we know of our own.
    TestHelper::start_group(*l.applicant);
    auto second = TestHelper::group_id(*l.applicant);
    REQUIRE(second);
    TestHelper::deliver_device_message(
            *l.core,
            l.applicant->devices.build_device_group_message().message,
            in(1min) + Devices::DEVICE_GROUP_TTL + 1h,
            "B1");
    REQUIRE(l.core->devices.membership(await).membership == device::Membership::InGroup);

    // Dismissing the other group does not quiet what comes next.
    REQUIRE(l.core->devices.dismiss_group(*second, await));

    // Ours gone from the swarm, as far as we can tell; theirs not.
    ScopedClockOffset later{Devices::DEVICE_GROUP_TTL + 1h};
    TestHelper::finish_fetch(*l.core);
    CHECK(l.core->devices.membership(await).membership == device::Membership::CutOff);
    CHECK(l.events.membership.back() == device::Membership::CutOff);
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
    TestHelper::start_group(*impostor);
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

    // Readable, but not enough: with no confirmation from its user, it does not join.
    CHECK(own_state(l.applicant) == device::State::Pending);
    CHECK_FALSE(TestHelper::group_id(*l.applicant));
    CHECK(l.applicant_events.membership == std::vector{device::Membership::Waiting});
}

TEST_CASE(
        "Devices - an admission held for confirmation survives a restart",
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

    l.applicant.core.reset();
    l.applicant.core = std::make_unique<core::Core>(
            l.applicant.path, Linking::reporting_to(l.applicant_events));

    // The fetch that brought the admission will not bring it again; it was kept.
    REQUIRE(l.applicant->devices.confirm_link(await));
    CHECK(own_state(l.applicant) == device::State::Registered);
    CHECK(TestHelper::group_id(*l.applicant) == TestHelper::group_id(*l.core));
}

TEST_CASE("Devices - a new request needs confirming again", "[core][devices][linking][confirm]") {
    Linking l;
    CHECK_FALSE(l.applicant->devices.confirm_link(await));

    l.ask();
    REQUIRE(l.applicant->devices.confirm_link(await));

    // Asked again: a new SAS, which the user has not compared.
    auto second = l.ask(in(10min), "L2");
    REQUIRE(l.events.added.size() == 2);
    REQUIRE(l.core->devices.accept_request(l.events.added[1].id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");
    CHECK(own_state(l.applicant) == device::State::Pending);

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
    REQUIRE(l.applicant_events.membership.back() == device::Membership::GroupsVisible);

    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");

    // Not taken: any holder of the seed could have sent it.  Back to waiting, on the user.
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Waiting);
    CHECK(l.applicant_events.membership.back() == device::Membership::Waiting);
    auto shown = l.applicant->devices.outgoing_link_request(await);
    REQUIRE(shown);
    CHECK(shown->accepted);
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
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::GroupsVisible);
    CHECK(own_state(l.applicant) == device::State::Unregistered);
    CHECK_FALSE(l.applicant->devices.confirm_link(await));
}

TEST_CASE(
        "Devices - asking again does not lose an earlier request accepted meanwhile",
        "[core][devices][linking][confirm]") {
    Linking l;
    l.ask();

    SECTION("confirmed before asking again: it admits the device") {
        REQUIRE(l.applicant->devices.confirm_link(await));
        REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
        l.ask(in(10min), "L2");  // never reaches the accepting device

        TestHelper::deliver_device_message(
                *l.applicant,
                l.core->devices.build_device_group_message().message,
                in(10min),
                "G1");
        CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
    }

    SECTION("never confirmed: the user is looking at the newer one, which must admit it instead") {
        REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
        auto second = TestHelper::build_link_request(*l.applicant, *l.core);

        TestHelper::deliver_device_message(
                *l.applicant,
                l.core->devices.build_device_group_message().message,
                in(10min),
                "G1");
        CHECK(l.applicant->devices.membership(await).membership == device::Membership::Waiting);
        REQUIRE(l.applicant->devices.confirm_link(await));
        CHECK(own_state(l.applicant) == device::State::Pending);
    }
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
        "Devices - a device can start a group alongside those already there",
        "[core][devices][membership]") {
    Linking l;
    auto theirs = l.show_group();
    REQUIRE(l.applicant_events.membership == std::vector{device::Membership::GroupsVisible});
    auto held_before = l.applicant->devices.active_account_keys().front().x25519_pub;

    auto mine = l.applicant->devices.start_group(await);
    CHECK(mine != theirs);

    // With a key of its own, not whatever it held before.
    CHECK(account_key_count(l.applicant) == 1);
    CHECK(l.applicant->devices.active_account_keys().front().x25519_pub != held_before);
    auto state = l.applicant->devices.membership(await);
    CHECK(state.membership == device::Membership::InGroup);
    CHECK(state.group == mine);
    REQUIRE(state.others.size() == 1);
    CHECK(state.others[0].id == theirs);

    // Its own doing, so not news to it; news to the group it started beside.
    CHECK(l.applicant_events.membership == std::vector{device::Membership::GroupsVisible});
    TestHelper::finish_fetch(*l.core);
    TestHelper::deliver_device_message(
            *l.core, l.applicant->devices.build_device_group_message().message, in(10min), "B1");
    CHECK(l.events.appeared == std::vector{mine});
}

TEST_CASE(
        "Devices - a group is started only when the user can have decided to",
        "[core][devices][membership]") {
    Linking l;

    // Before any fetch, nothing is known of what the swarm holds.
    CHECK(failure_code([&] { l.applicant->devices.start_group(await); }) ==
          err::membership_unknown);

    // Already in one.
    TestHelper::finish_fetch(*l.core);
    CHECK(failure_code([&] { l.core->devices.start_group(await); }) == err::already_registered);

    // Waiting on a request: starting a group instead withdraws it.
    l.show_group();
    TestHelper::build_link_request(*l.applicant, *l.core);
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Waiting);
    l.applicant->devices.start_group(await);
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
    CHECK(own_state(l.applicant) == device::State::Registered);
}

TEST_CASE(
        "Devices - a device switches groups, leaving its old one behind",
        "[core][devices][membership][switch]") {
    Linking l;
    l.admit();
    auto x = *TestHelper::group_id(*l.core);

    // Another group on the account, started by a third device.
    DeviceEventsRecorder third_events;
    TempCore third{
            core::predefined_seed{std::span<const std::byte, 32>{l.seed}},
            Linking::reporting_to(third_events)};
    TestHelper::start_group(*third);
    auto y = *TestHelper::group_id(*third);
    TestHelper::deliver_device_message(
            *l.applicant,
            third->devices.build_device_group_message().message,
            in(10min) + Devices::DEVICE_GROUP_TTL,
            "Y1");

    // Attached only now, so that the uploads it sees are the ones this test is about.
    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l.applicant, y, got);
    auto request = uploaded(*net);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());

    // Still a working member of its group while it asks.
    auto state = l.applicant->devices.membership(await);
    CHECK(state.membership == device::Membership::InGroup);
    CHECK(state.group == x);
    CHECK(l.applicant->devices.outgoing_link_request(await));

    TestHelper::deliver_device_message(*third, request, (*got)->expires, "L1");
    REQUIRE(third_events.added.size() == 1);
    REQUIRE(third->devices.accept_request(third_events.added[0].id, await));
    TestHelper::deliver_device_message(
            *l.applicant, third->devices.build_device_group_message().message, in(10min), "Y2");

    // Admitted, but held for its user, like any admission.
    CHECK(TestHelper::group_id(*l.applicant) == x);

    REQUIRE(l.applicant->devices.confirm_link(await));
    state = l.applicant->devices.membership(await);
    CHECK(state.membership == device::Membership::InGroup);
    CHECK(state.group == y);
    CHECK_FALSE(l.applicant->devices.outgoing_link_request(await));

    // Y's devices, not X's; and none of X's keys.
    auto [core_self, _] = l.core->devices.device_info(await);
    auto [third_self, __] = third->devices.device_info(await);
    auto devs = l.applicant->devices.devices(true, true, true);
    CHECK(devs.contains(third_self.id));
    CHECK_FALSE(devs.contains(core_self.id));
    auto x_key = l.core->devices.active_account_keys().front().x25519_pub;
    for (const auto& k : l.applicant->devices.active_account_keys())
        CHECK(k.x25519_pub != x_key);

    // Not alerted about the group it has just left.
    auto old = std::ranges::find(state.others, x, &device::VisibleGroup::id);
    REQUIRE(old != state.others.end());
    CHECK(old->dismissed);

    // And X hears of the departure, from a message it can read and the leaver will not again.
    auto farewell = pushes(*net);
    REQUIRE(!farewell.empty());
    auto store = push_requests(*farewell.back())[0];
    REQUIRE(store["method"] == "store");
    auto message = to_vector<std::byte>(
            oxenc::from_base64(store["params"]["data"].get<std::string_view>()));
    auto key_before = l.core->devices.active_account_keys().front().x25519_pub;
    TestHelper::deliver_device_message(*l.core, message, in(10min), "G9");
    CHECK(l.state_of_applicant().state == device::State::Left);
    CHECK(l.core->devices.active_account_keys().front().x25519_pub != key_before);
}

TEST_CASE(
        "Devices - a device leaving a group of its own deletes it",
        "[core][devices][membership][switch]") {
    Linking l;
    auto theirs = l.show_group();

    // A group started by mistake, whose message has been in the swarm.
    l.applicant->devices.start_group(await);
    TestHelper::deliver_device_message(
            *l.applicant,
            l.applicant->devices.build_device_group_message().message,
            in(10min),
            "B1");

    auto* net = attach_mock_network(*l.applicant);
    Asked got;
    request_link(l.applicant, theirs, got);
    auto request = uploaded(*net);
    answer_upload(l.applicant, *net, true);
    REQUIRE(got);
    REQUIRE(got->has_value());

    TestHelper::deliver_device_message(*l.core, request, (*got)->expires, "L1");
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    REQUIRE(l.applicant->devices.confirm_link(await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");
    REQUIRE(TestHelper::group_id(*l.applicant) == theirs);

    // Nobody was left in it, so it is deleted rather than told anything.
    bool deleted = false;
    for (auto* push : pushes(*net)) {
        auto reqs = push_requests(*push);
        if (reqs.size() == 1 && reqs[0]["method"] == "delete" &&
            reqs[0]["params"]["messages"] == nlohmann::json::array({"B1"}))
            deleted = true;
    }
    CHECK(deleted);
}

TEST_CASE(
        "Devices - a removed device comes back under a new identity",
        "[core][devices][membership]") {
    Linking l;
    CHECK_FALSE(l.core->devices.renew_device_identity(await));

    l.admit();
    auto old_id = l.applicant_id();
    REQUIRE(l.core->devices.remove_device(old_id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G2");
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Removed);

    REQUIRE(l.applicant->devices.renew_device_identity(await));
    CHECK(l.applicant_id() != old_id);
    auto state = l.applicant->devices.membership(await);
    CHECK(state.membership == device::Membership::GroupsVisible);
    CHECK_FALSE(state.group);

    // Nothing of its old group left to carry into one it starts, or to mistake for the one it
    // joins -- its account keys included.
    CHECK(l.applicant->devices.devices(true, true, true).empty());
    CHECK_FALSE(TestHelper::group_id(*l.applicant));
    CHECK(account_key_count(l.applicant) == 0);

    // And joins again like any device asking: the new id is not the one the group removed.
    l.ask(in(10min), "L2");
    REQUIRE(l.events.added.size() == 2);
    REQUIRE(l.core->devices.accept_request(l.events.added[1].id, await));
    REQUIRE(l.applicant->devices.confirm_link(await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G3");
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
    REQUIRE(l.applicant->devices.confirm_link(await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G2");
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
    REQUIRE(third->devices.confirm_link(await));
    TestHelper::deliver_device_message(
            *third, l.core->devices.build_device_group_message().message, in(10min), "G2");
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
    CHECK(failure_code([&] { l.applicant->devices.start_group(await); }) == err::removed);

    // The way back is the removed device's: a new identity.
    REQUIRE(l.applicant->devices.renew_device_identity(await));
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::GroupsVisible);
}

TEST_CASE(
        "Devices - a snapshot that has yet to hear of this device does not displace it",
        "[core][devices][membership]") {
    Linking l;
    // The group as it was before the applicant joined, which a member could still push for a moment
    // after: built before it fetched the admission.
    auto before = l.core->devices.build_device_group_message().message;

    // Admitted by a message held until the user confirms, which is when it is read -- but as of
    // when the swarm stored it.
    l.ask();
    REQUIRE(l.core->devices.accept_request(l.events.added.at(0).id, await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G1");
    REQUIRE(l.applicant->devices.confirm_link(await));
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::InGroup);

    TestHelper::deliver_device_message(*l.applicant, before, in(10min), "G-stale");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);

    // Beyond the grace, though, a message leaving it out is one the group sent without it.
    ScopedClockOffset later{Devices::DISPLACEMENT_GRACE + 1min};
    TestHelper::deliver_device_message(*l.applicant, before, in(10min), "G-late");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::Displaced);

    // And reading the group again, at or past what displaced it, puts it back.
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G2");
    CHECK(l.applicant->devices.membership(await).membership == device::Membership::InGroup);
}

TEST_CASE("Devices - a removed device cannot start a group", "[core][devices][membership]") {
    Linking l;
    l.admit();
    REQUIRE(l.core->devices.remove_device(l.applicant_id(), await));
    TestHelper::deliver_device_message(
            *l.applicant, l.core->devices.build_device_group_message().message, in(10min), "G2");
    REQUIRE(l.applicant->devices.membership(await).membership == device::Membership::Removed);

    CHECK(failure_code([&] { l.applicant->devices.start_group(await); }) == err::removed);
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
        "Devices - a member learning of a departure rotates the account key",
        "[core][devices][removal]") {
    Linking l;
    l.admit();
    auto current = [&] { return l.core->devices.active_account_keys().front().x25519_pub; };
    auto before = current();

    // The farewell the applicant pushes on leaving: its own view of the group, itself departed.
    auto [self, registered] = l.core->devices.device_info(await);
    REQUIRE(registered);
    auto leaver = l.state_of_applicant();
    leaver.state = device::State::Left;
    leaver.kicked = clock_now_s();
    auto farewell = TestHelper::encrypt_device_data(
            l.applicant->devices, {{self.id, self}, {leaver.id, leaver}});
    TestHelper::deliver_device_message(*l.core, farewell, in(10min), "G2");

    // A key the departed device does not hold.
    auto after = current();
    CHECK(after != before);
    for (const auto& k : l.applicant->devices.active_account_keys())
        CHECK(k.x25519_pub != after);

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
        "Devices - a member learning of a removal elsewhere does not rotate",
        "[core][devices][removal]") {
    Linking l;
    l.admit();
    auto before = l.core->devices.active_account_keys().front().x25519_pub;

    // The device that removed it rotated in the same step; a second rotation here buys nothing.
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
    CHECK(l.core->devices.active_account_keys().front().x25519_pub == before);
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
    std::array<std::byte, 32> unknown;
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
