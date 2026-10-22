#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <session/core.hpp>

#include "schema_fingerprint.hpp"
#include "test_helper.hpp"
#include "test_schema_registry.hpp"

using namespace session;
using namespace session::core;

namespace {

bool table_exists(Core& core, std::string_view name) {
    return TestHelper::db_conn(core)
            .prepared_maybe_get<std::string>(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", name)
            .has_value();
}

}  // namespace

TEST_CASE(
        "schema_extension: migrations are applied and recorded under the owner prefix",
        "[core][schema]") {
    auto path = std::filesystem::temp_directory_path() /
                fmt::format("{}.db", session::random::unique_id("test_schema", 7));
    std::filesystem::remove(path);

    {
        Core core{path, schema_extension{"testext", session::test::schema::MIGRATIONS}};

        CHECK(table_exists(core, "ext_thing"));
        // Core's own schema must still be present despite the extension reusing a name.
        CHECK(table_exists(core, "globals"));
        CHECK(table_exists(core, "ext_globals"));

        CHECK(TestHelper::migration_applied(core, "testext:000_ext_thing"));
        CHECK(TestHelper::migration_applied(core, "testext:000_globals"));
        CHECK(TestHelper::migration_applied(core, "@created"));
        CHECK(!TestHelper::migration_applied(core, "000_ext_thing"));
    }

    // Reopening must not re-apply them.
    {
        Core core{path, schema_extension{"testext", session::test::schema::MIGRATIONS}};
        CHECK(table_exists(core, "ext_thing"));
    }

    std::error_code ec;
    std::filesystem::remove(path, ec);
}

TEST_CASE(
        "apply_migrations: two Cores opening a database with a migration pending",
        "[core][schema][threads]") {
    // The app and its notification extension can open the same file at once just after an update,
    // both with the same migration pending.  Unless each reads what is applied only once it holds
    // the write lock, the one that waited applies again what the other just committed -- here a
    // CREATE TABLE, failing on a table that already exists.  Repeated because whether both read
    // before either commits is up to the scheduler.
    for (int round = 0; round < 20; round++) {
        INFO("round " << round);
        auto path = std::filesystem::temp_directory_path() /
                    fmt::format("{}.db", session::random::unique_id("test_schema", 7));
        {
            Core core{path};
        }

        // Spun on rather than a latch, which the macOS deployment target does not have
        std::atomic<int> starting{2};
        std::exception_ptr errs[2];
        auto open = [&](std::exception_ptr& err) {
            try {
                for (--starting; starting;) {
                }
                Core core{path, schema_extension{"testext", session::test::schema::MIGRATIONS}};
            } catch (...) {
                err = std::current_exception();
            }
        };
        std::thread ta{[&] { open(errs[0]); }};
        std::thread tb{[&] { open(errs[1]); }};
        ta.join();
        tb.join();

        for (auto& err : errs)
            if (err)
                std::rethrow_exception(err);

        {
            Core core{path, schema_extension{"testext", session::test::schema::MIGRATIONS}};
            CHECK(table_exists(core, "ext_thing"));
            CHECK(TestHelper::migration_applied(core, "testext:000_ext_thing"));
        }
        // With every Core gone, the last connection's close has checkpointed and removed these:
        // one still here is a connection something left open.
        CHECK_FALSE(std::filesystem::exists(path.string() + "-wal"));
        CHECK_FALSE(std::filesystem::exists(path.string() + "-shm"));
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
}

TEST_CASE("schema_extension: migrations order by name, not filename", "[core][schema]") {
    auto path = std::filesystem::temp_directory_path() /
                fmt::format("{}.db", session::random::unique_id("test_schema", 7));
    std::filesystem::remove(path);

    // tests/schema/ holds 001_ordering.sql plus 001_ordering+002.sql, which ALTERs the table the
    // first one creates.  '+' sorts below '.', so ordering by filename would run the addendum
    // first and Core construction would throw here rather than reaching the checks below.
    Core core{path, schema_extension{"testext", session::test::schema::MIGRATIONS}};

    CHECK(TestHelper::migration_applied(core, "testext:001_ordering"));
    CHECK(TestHelper::migration_applied(core, "testext:001_ordering+002"));

    auto cols = TestHelper::db_conn(core).get_columns("ext_ordering");
    CHECK(std::ranges::any_of(cols, [](const auto& c) { return c.name == "added_later"; }));

    std::error_code ec;
    std::filesystem::remove(path, ec);
}

TEST_CASE("schema_extension: full_schema matches replaying the migrations", "[core][schema]") {
    // The whole point of full_schema.sql: it must land in exactly the same place the migration
    // chain does, or fresh installs and upgraded ones diverge -- silently, since whoever makes the
    // change already has an upgraded database and never sees the fresh path.
    auto build = [](std::string_view full_schema) {
        auto path = std::filesystem::temp_directory_path() /
                    fmt::format("{}.db", session::random::unique_id("test_drift", 7));
        std::filesystem::remove(path);

        std::string fingerprint;
        {
            Core core{
                    path,
                    schema_extension{"testext", session::test::schema::MIGRATIONS, full_schema}};
            auto conn = TestHelper::db_conn(core);
            fingerprint = session::test::schema_fingerprint(conn);
        }

        std::error_code ec;
        std::filesystem::remove(path, ec);
        return fingerprint;
    };

    auto from_full = build(session::test::schema::FULL_SCHEMA);
    auto from_chain = build("");  // no full schema, so every migration runs

    CHECK(from_full == from_chain);

    // Guard against the comparison passing because both sides are empty.
    CHECK(from_full.find("table ext_ordering") != std::string::npos);
    CHECK(from_full.find("added_later") != std::string::npos);
}

TEST_CASE(
        "schema_extension: full_schema records migrations without running them", "[core][schema]") {
    auto path = std::filesystem::temp_directory_path() /
                fmt::format("{}.db", session::random::unique_id("test_drift", 7));
    std::filesystem::remove(path);

    {
        Core core{
                path,
                schema_extension{
                        "testext",
                        session::test::schema::MIGRATIONS,
                        session::test::schema::FULL_SCHEMA}};

        // Every migration is marked applied even though none ran, so a later reopen -- and any
        // migration added after this point -- behaves as if the chain had been replayed.
        CHECK(TestHelper::migration_applied(core, "testext:000_ext_thing"));
        CHECK(TestHelper::migration_applied(core, "testext:001_ordering"));
        CHECK(TestHelper::migration_applied(core, "testext:001_ordering+002"));
        CHECK(table_exists(core, "ext_ordering"));
    }

    // Reopening must not now try to run any of them against the already-built schema.
    {
        Core core{
                path,
                schema_extension{
                        "testext",
                        session::test::schema::MIGRATIONS,
                        session::test::schema::FULL_SCHEMA}};
        CHECK(table_exists(core, "ext_ordering"));
    }

    std::error_code ec;
    std::filesystem::remove(path, ec);
}

TEST_CASE("schema_extension: rejects unusable owners", "[core][schema]") {
    auto path = std::filesystem::temp_directory_path() /
                fmt::format("{}.db", session::random::unique_id("test_schema", 7));
    std::filesystem::remove(path);

    CHECK_THROWS_AS(
            Core(path, schema_extension{"", session::test::schema::MIGRATIONS}),
            std::invalid_argument);
    CHECK_THROWS_AS(
            Core(path, schema_extension{"has:colon", session::test::schema::MIGRATIONS}),
            std::invalid_argument);
    // Two sets under one owner would let their names collide.
    CHECK_THROWS_AS(
            Core(path,
                 schema_extension{"dup", session::test::schema::MIGRATIONS},
                 schema_extension{"dup", session::test::schema::MIGRATIONS}),
            std::invalid_argument);

    std::error_code ec;
    std::filesystem::remove(path, ec);
}
