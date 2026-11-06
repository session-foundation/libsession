#include <catch2/catch_test_macros.hpp>
#include <session/core.hpp>

#include "test_helper.hpp"

using namespace session;
using namespace session::core;
using namespace oxenc::literals;

TEST_CASE("Globals: set/get round-trip", "[core][globals]") {
    TempCore c{};

    CHECK(!c->globals.get_text("nope"));

    c->globals.set("a_string", "hello");
    c->globals.set("an_int", int64_t{42});
    c->globals.set("a_real", 1.5);

    CHECK(c->globals.get_text("a_string") == "hello");
    CHECK(c->globals.get_integer("an_int") == 42);
    CHECK(c->globals.get_real("a_real") == 1.5);

    // Wrong-type reads come back empty rather than throwing.
    CHECK(!c->globals.get_integer("a_string"));
}

TEST_CASE("Globals: erase", "[core][globals]") {
    TempCore c{};

    c->globals.set("doomed", "value");
    REQUIRE(c->globals.get_text("doomed") == "value");

    CHECK(c->globals.erase("doomed"));
    CHECK(!c->globals.get_text("doomed"));

    // Erasing something that was never set is not an error, just false.
    CHECK(!c->globals.erase("doomed"));
    CHECK(!c->globals.erase("never_existed"));
}

TEST_CASE("Globals: values persist across reopen", "[core][globals]") {
    auto path = std::filesystem::temp_directory_path() /
                fmt::format("{}.db", session::random::unique_id("test_globals", 7));
    std::filesystem::remove(path);

    {
        Core core{path};
        core.globals.set("kept", "yes");
        core.globals.set("dropped", "no");
        CHECK(core.globals.erase("dropped"));
    }
    {
        Core core{path};
        CHECK(core.globals.get_text("kept") == "yes");
        CHECK(!core.globals.get_text("dropped"));
    }

    std::error_code ec;
    std::filesystem::remove(path, ec);
}

TEST_CASE("Globals: defer_account leaves the account unresolved", "[core][globals]") {
    auto path = std::filesystem::temp_directory_path() /
                fmt::format("{}.db", session::random::unique_id("test_defer", 7));
    std::filesystem::remove(path);

    constexpr auto seed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"_hex_b;

    SECTION("an unresolved account refuses everything needing an identity") {
        Core core{path, defer_account{}};
        CHECK_FALSE(core.globals.have_account());

        CHECK_THROWS_AS(core.globals.session_id(), no_account);
        CHECK_THROWS_AS(core.globals.session_id_hex(), no_account);
        CHECK_THROWS_AS(core.globals.pubkey_ed25519(), no_account);
        CHECK_THROWS_AS(core.globals.account_seed(), no_account);
        CHECK_THROWS_AS(core.globals.seed_mnemonic(), no_account);

        // Refused here rather than failing later inside a background poll.
        CHECK_THROWS_AS(
                core.set_network([](network::NetworkHooks hooks) {
                    return std::make_unique<MockNetwork>(
                            network::config::Config{}, std::move(hooks));
                }),
                no_account);

        // Everything not needing an identity still works, which is what makes the state useful:
        // the application can open the database and ask, before deciding.
        core.globals.set("some_setting", "value");
        CHECK(core.globals.get_text("some_setting") == "value");
    }

    SECTION("create_account resolves it, and persists") {
        std::string id;
        {
            Core core{path, defer_account{}};
            REQUIRE_FALSE(core.globals.have_account());
            core.globals.create_account(await);
            CHECK(core.globals.have_account());
            id = core.globals.session_id_hex();
            CHECK(id.starts_with("05"));
            // Adopting a second identity would orphan everything stored against the first.
            CHECK_THROWS_AS(core.globals.create_account(await), std::logic_error);
        }
        // Reopening finds the stored seed, so defer_account is a no-op on an existing account.
        Core core{path, defer_account{}};
        CHECK(core.globals.have_account());
        CHECK(core.globals.session_id_hex() == id);
    }

    SECTION("restore_account adopts a given seed") {
        std::string restored;
        {
            Core core{path, defer_account{}};
            core.globals.restore_account(predefined_seed{seed}, await);
            CHECK(core.globals.have_account());
            restored = core.globals.session_id_hex();
        }

        // The same seed via the constructor must reach the same identity.
        auto other = std::filesystem::temp_directory_path() /
                     fmt::format("{}.db", session::random::unique_id("test_defer", 7));
        std::filesystem::remove(other);
        {
            Core core{other, predefined_seed{seed}};
            CHECK(core.globals.session_id_hex() == restored);
        }
        std::error_code ec2;
        std::filesystem::remove(other, ec2);
    }

    SECTION("without the option an account is created outright, as before") {
        Core core{path};
        CHECK(core.globals.have_account());
    }

    std::error_code ec;
    std::filesystem::remove(path, ec);
}
