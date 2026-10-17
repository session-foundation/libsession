#include "../schema_fingerprint.hpp"
#include "common.hpp"

// ── ConversationId ──────────────────────────────────────────────────────────────────────────────

TEST_CASE("ConversationId: round-trips through its string form", "[client][convo_id]") {
    constexpr auto sid = "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    constexpr auto gid = "03fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;

    auto dm = ConversationId::dm(sid);
    CHECK(dm.type() == ConversationId::Type::dm);
    CHECK(dm.to_string() == oxenc::to_hex(sid));
    CHECK(ConversationId::parse(dm.to_string()) == dm);
    CHECK(std::ranges::equal(dm.session_id(), sid));

    auto group = ConversationId::group(gid);
    CHECK(group.type() == ConversationId::Type::group);
    CHECK(ConversationId::parse(group.to_string()) == group);
    CHECK(std::ranges::equal(group.group_id(), gid));

    // Same 32-byte body, different prefix: distinct conversations.
    CHECK(dm != group);

    auto com = ConversationId::community("http://example.com", "room");
    CHECK(com.type() == ConversationId::Type::community);
    CHECK(com.to_string() == "community:http://example.com/room");
    CHECK(ConversationId::parse(com.to_string()) == com);
    auto [url, room] = com.community();
    CHECK(url == "http://example.com");
    CHECK(room == "room");
}

TEST_CASE("ConversationId: normalises community URLs and rooms", "[client][convo_id]") {
    auto a = ConversationId::community("http://Example.COM/", "Room");
    auto b = ConversationId::community("http://example.com", "room");
    CHECK(a == b);

    CHECK_THROWS_AS(ConversationId::community("", "room"), std::invalid_argument);
    CHECK_THROWS_AS(ConversationId::community("http://x.com", ""), std::invalid_argument);
    CHECK_THROWS_AS(ConversationId::community("http://x.com", "a/b"), std::invalid_argument);
}

TEST_CASE("ConversationId: rejects bad input and mistyped access", "[client][convo_id]") {
    constexpr auto sid = "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    constexpr auto bad_prefix =
            "07fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;

    CHECK_THROWS_AS(ConversationId::dm(bad_prefix), std::invalid_argument);
    CHECK_THROWS_AS(ConversationId::group(bad_prefix), std::invalid_argument);

    CHECK_THROWS_AS(ConversationId::parse(""), std::invalid_argument);
    CHECK_THROWS_AS(ConversationId::parse("nonsense"), std::invalid_argument);
    CHECK_THROWS_AS(ConversationId::parse(oxenc::to_hex(bad_prefix)), std::invalid_argument);
    CHECK_THROWS_AS(ConversationId::parse("05zz"), std::invalid_argument);
    CHECK_THROWS_AS(ConversationId::parse("community:noroom"), std::invalid_argument);

    // Extracting the wrong kind is a programming error, not a parse error.
    auto dm = ConversationId::dm(sid);
    CHECK_THROWS_AS(dm.group_id(), std::logic_error);
    CHECK_THROWS_AS(dm.community(), std::logic_error);
}

// ── Schema ──────────────────────────────────────────────────────────────────────────────────────

TEST_CASE("Client: applies its migrations under the client owner", "[client][schema]") {
    TempClient c;

    // Both schemas are created from their full_schema.sql, each marking its own owner.
    CHECK(TestHelper::migration_applied(c->core, "client:@created"));
    CHECK(TestHelper::migration_applied(c->core, "@created"));

    // Not Connection::table_exists(): its query in session-sqlite is missing a closing paren and
    // throws "incomplete input" for every caller.
    auto has_table = [&](std::string_view name) {
        return c->core.database()
                .conn()
                .prepared_maybe_get<std::string>(
                        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", name)
                .has_value();
    };
    CHECK(has_table("accounts"));
    CHECK(has_table("conversations"));
    CHECK(has_table("messages"));
    CHECK(has_table("message_raw_content"));
    // Client's tables live in Core's database, not a second file.
    CHECK(has_table("globals"));
}

TEST_CASE("Client: resetting interrupted sends at start-up reads an index", "[client][schema]") {
    TempClient c;
    auto conn = c->core.database().conn();
    auto plan = [&](const std::string& sql) {
        SQLite::Statement st{conn.sql, "EXPLAIN QUERY PLAN " + sql};
        std::string out;
        while (st.executeStep())
            out += st.getColumn(3).getText();
        return out;
    };
    // Client::_init's statements, bound parameters and all: a partial index is only used when the
    // query's WHERE implies the index's, and `x IN (?, ?)` and `x = ?` both imply `x IS NOT NULL`.
    CHECK(plan("UPDATE messages SET send_state = ? WHERE send_state IN (?, ?)")
                  .find("USING INDEX messages_send_state") != std::string::npos);
    CHECK(plan("UPDATE messages SET sync_send_state = ? WHERE sync_send_state IN (?, ?)")
                  .find("USING INDEX messages_sync_send_state") != std::string::npos);
    CHECK(plan("UPDATE messages SET send_state = ? WHERE send_state = ?")
                  .find("USING INDEX messages_send_state") != std::string::npos);
    CHECK(plan("UPDATE messages SET sync_send_state = ? WHERE sync_send_state = ?")
                  .find("USING INDEX messages_sync_send_state") != std::string::npos);
}

TEST_CASE("Client: a message id is never handed out twice", "[client][schema]") {
    TempClient c;
    SenderKeys kept, dropped;
    auto dropped_convo = ConversationId::dm(dropped.session_id);

    deliver(*c, kept, "one", from_epoch_ms(1000), "h1");
    deliver(*c, dropped, "two", from_epoch_ms(2000), "h2");
    auto newest = c->conversation(dropped_convo, await)->messages(await).front().id;

    // Each takes away the row holding the highest id, which is the one row whose id an insert
    // would otherwise take next.
    SECTION("purged") {
        REQUIRE(c->delete_message(newest, await));
        REQUIRE(c->purge_deleted_message(newest, await));
    }
    SECTION("its conversation deleted") {
        c->conversation(dropped_convo, await)->delete_conversation(await);
    }
    REQUIRE_FALSE(c->message(newest, await));

    deliver(*c, kept, "three", from_epoch_ms(3000), "h3");
    auto next = c->conversation(ConversationId::dm(kept.session_id), await)->messages(await);
    REQUIRE(next.front().body == "three");
    CHECK(next.front().id > newest);
}

TEST_CASE("Client: an attachment cache id is never handed out twice", "[client][schema]") {
    TempClient c;
    auto [gone, next] = TestHelper::on_loop(c->core, [&] {
        auto conn = c->core.database().conn();
        auto insert = [&](std::string_view name) {
            conn.prepared_exec(
                    "INSERT INTO attachment_cache (name, size, last_used) VALUES (?, 1, 1)", name);
            return conn.prepared_get<int64_t>(
                    "SELECT id FROM attachment_cache WHERE name = ?", name);
        };
        auto gone = insert("first");
        conn.prepared_exec("DELETE FROM attachment_cache WHERE id = ?", gone);
        return std::pair{gone, insert("second")};
    });
    CHECK(next > gone);
}

TEST_CASE("Client: upgrading for AUTOINCREMENT keeps every row and reference", "[client][schema]") {
    TempClient c{TempClient::unopened};
    SenderKeys sender;
    auto convo = ConversationId::dm(sender.session_id);

    auto db = [](core::Core& core, auto&& f) {
        return TestHelper::on_loop(core, [&] {
            auto conn = core.database().conn();
            return f(conn);
        });
    };

    // Valid against the tables both before and after 006 rebuilds them.
    using row = std::tuple<int64_t, int64_t, std::optional<std::string>, std::optional<int64_t>>;
    auto snapshot = [](sqlite::Connection& conn) {
        std::vector<row> rows;
        for (auto [a, b, s, n] : conn.prepared_results<
                                 int64_t,
                                 int64_t,
                                 std::optional<std::string>,
                                 std::optional<int64_t>>(R"(
            SELECT id, conversation, body, count FROM messages
                JOIN (SELECT id AS cid, count FROM conversations) ON cid = conversation
            UNION ALL SELECT message, length(content), NULL, NULL FROM message_raw_content
            UNION ALL SELECT message, idx, url, cached FROM message_attachments
            UNION ALL SELECT id, size, name, last_used FROM attachment_cache
            ORDER BY 1, 2, 3)"))
            rows.emplace_back(a, b, std::move(s), n);
        return rows;
    };

    auto [before, file_msg] = [&] {
        auto old = open_client_schema_before(c.path, "006_ids_never_reused");
        REQUIRE(TestHelper::migration_applied(old, "client:005_attachment_availability"));
        REQUIRE_FALSE(TestHelper::migration_applied(old, "client:006_ids_never_reused"));

        return db(old, [&](sqlite::Connection& conn) {
            conn.prepared_exec("INSERT INTO accounts (session_id) VALUES (?)", sender.session_id);
            conn.prepared_exec(
                    "INSERT INTO conversations (dm, created, last_activity)"
                    " VALUES ((SELECT id FROM accounts), 1, 2000)");
            auto insert_message = [&](std::string_view body, int64_t ts, std::string_view hash) {
                conn.prepared_exec(
                        "INSERT INTO messages (conversation, swarm_hash, sender, outgoing,"
                        " timestamp, body) VALUES ((SELECT id FROM conversations), ?,"
                        " (SELECT id FROM accounts), 0, ?, ?)",
                        hash,
                        ts,
                        body);
                return conn.prepared_get<int64_t>("SELECT last_insert_rowid()");
            };
            insert_message("plain", 1000, "h1");
            auto file_msg = insert_message("with a file", 2000, "h2");

            conn.prepared_exec(
                    "INSERT INTO message_raw_content (message, content) VALUES (?, X'0a0b0c')",
                    file_msg);
            conn.prepared_exec(
                    "INSERT INTO attachment_cache (name, size, last_used) VALUES ('f', 10, 1)");
            conn.prepared_exec(
                    "INSERT INTO message_attachments (message, idx, url, content_type, cached)"
                    " VALUES (?, 0, 'http://fs.example/file/111#d', 'image/png',"
                    " (SELECT id FROM attachment_cache))",
                    file_msg);
            return std::pair{snapshot(conn), file_msg};
        });
    }();
    REQUIRE(before.size() == 5);

    c.reopen();
    REQUIRE(TestHelper::migration_applied(c->core, "client:006_ids_never_reused"));

    CHECK(db(c->core, snapshot) == before);

    // The children point at the rebuilt tables, and not at the ones the rebuild dropped: deleting
    // through them still reaches them.
    auto [cached, children] = db(c->core, [&](sqlite::Connection& conn) {
        conn.prepared_exec("DELETE FROM attachment_cache");
        auto cached = conn.prepared_get<int64_t>(
                "SELECT count(*) FROM message_attachments WHERE cached IS NOT NULL");
        conn.prepared_exec("DELETE FROM messages WHERE id = ?", file_msg);
        auto children = conn.prepared_get<int64_t>(
                "SELECT (SELECT count(*) FROM message_attachments WHERE message = ?1) + "
                "(SELECT count(*) FROM message_raw_content WHERE message = ?1)",
                file_msg);
        return std::pair{cached, children};
    });
    CHECK(cached == 0);
    CHECK(children == 0);

    // The deleted message held the highest id, so this is the insert that would retake it.
    deliver(*c, sender, "after", from_epoch_ms(3000), "h3");
    auto messages = c->conversation(convo, await)->messages(await);
    REQUIRE(messages.size() == 2);
    CHECK(messages.front().body == "after");
    CHECK(messages.front().id > file_msg);
}

TEST_CASE("Client: the base schema and every migration make today's schema", "[client][schema]") {
    // Schema only: a migration that seeds rows is not checked here.
    TempClient fresh;
    TempClient upgraded{TempClient::unopened};
    open_client_schema_before(upgraded.path, {});
    upgraded.reopen();
    auto fingerprint = [](Client& c) {
        return TestHelper::on_loop(c.core, [&] {
            auto conn = c.core.database().conn();
            return session::test::schema_fingerprint(conn);
        });
    };
    CHECK(fingerprint(*upgraded) == fingerprint(*fresh));
}
