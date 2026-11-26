#include "config_helpers.hpp"

// Recent, because ConvoInfoVolatile refuses to store a last-read older than PRUNE_LOW (30 days)
// and would silently keep nothing at all from the 1970 timestamps the other tests here use.
sys_ms recently(std::chrono::milliseconds ago) {
    return clock_now_ms() - ago;
}

TEST_CASE("Client: reading a conversation publishes the watermark", "[client][volatile]") {
    TempClient c;
    SenderKeys them;
    auto id = ConversationId::dm(them.session_id);
    auto hex = oxenc::to_hex(them.session_id);
    approve(*c, them.session_id);

    auto newest = recently(2s);
    deliver(*c, them, "one", recently(3s), "h1");
    deliver(*c, them, "two", newest, "h2");
    REQUIRE(c->conversation(id, await)->unread() == 2);

    c->conversation(id, await)->mark_read(await);

    CHECK(c->conversation(id, await)->unread() == 0);
    auto entry = in_configs(*c, [&](auto& cfg) { return cfg.convo_info_volatile().get_1to1(hex); });
    REQUIRE(entry);
    CHECK(entry->last_read == newest.time_since_epoch().count());
}

TEST_CASE("Client: a watermark from another device applies", "[client][volatile]") {
    TempClient c;
    SenderKeys them;
    auto id = ConversationId::dm(them.session_id);
    auto hex = oxenc::to_hex(them.session_id);
    approve(*c, them.session_id);

    auto older = recently(30s);
    deliver(*c, them, "one", older, "h1");
    deliver(*c, them, "two", recently(10s), "h2");
    REQUIRE(c->conversation(id, await)->unread() == 2);

    // Read up to the first message on another device.
    auto read = volatile_from_another_device(*c.client, [&](config::ConvoInfoVolatile& theirs) {
        auto e = theirs.get_or_construct_1to1(hex);
        e.last_read = older.time_since_epoch().count();
        theirs.set(e);
    });
    merge_volatile(*c.client, read);

    CHECK(c->conversation(id, await)->unread() == 1);
}

TEST_CASE("Client: a stale watermark cannot unread what we have read", "[client][volatile]") {
    TempClient c;
    SenderKeys them;
    auto id = ConversationId::dm(them.session_id);
    auto hex = oxenc::to_hex(them.session_id);
    approve(*c, them.session_id);

    auto older = recently(30s);
    auto newest = recently(10s);
    deliver(*c, them, "one", older, "h1");
    deliver(*c, them, "two", newest, "h2");
    c->conversation(id, await)->mark_read(await);
    REQUIRE(c->conversation(id, await)->unread() == 0);

    // The config permits a value to be written backwards on purpose, and a same-seqno conflict
    // resolves by a tie-break that knows nothing about which value is newer -- so an older one
    // really can arrive, and applying it would make read messages unread again.
    auto stale = volatile_from_another_device(*c.client, [&](config::ConvoInfoVolatile& theirs) {
        auto e = theirs.get_or_construct_1to1(hex);
        e.last_read = older.time_since_epoch().count();
        theirs.set(e);
    });
    merge_volatile(*c.client, stale);

    CHECK(c->conversation(id, await)->unread() == 0);

    // ...and we do not publish the stale value back out, either.
    TestHelper::sync_convo_volatile(*c.client, id);
    auto entry = in_configs(*c, [&](auto& cfg) { return cfg.convo_info_volatile().get_1to1(hex); });
    REQUIRE(entry);
    CHECK(entry->last_read == newest.time_since_epoch().count());
}

TEST_CASE("Client: marking unread syncs, and reading clears it", "[client][volatile]") {
    TempClient c;
    SenderKeys them;
    auto id = ConversationId::dm(them.session_id);
    auto hex = oxenc::to_hex(them.session_id);
    approve(*c, them.session_id);

    deliver(*c, them, "one", recently(5s), "h1");
    c->conversation(id, await)->mark_read(await);
    REQUIRE(c->conversation(id, await)->unread() == 0);

    c->conversation(id, await)->set_marked_unread(true, await);

    // Survives having read everything, which is the whole point of it.
    CHECK(c->conversation(id, await)->marked_unread());
    CHECK(c->conversation(id, await)->unread() == 0);
    CHECK(in_configs(*c, [&](auto& cfg) {
              return cfg.convo_info_volatile().get_1to1(hex);
          })->unread);

    c->conversation(id, await)->mark_read(await);
    CHECK_FALSE(c->conversation(id, await)->marked_unread());
    CHECK_FALSE(in_configs(*c, [&](auto& cfg) {
                    return cfg.convo_info_volatile().get_1to1(hex);
                })->unread);
}

TEST_CASE("Client: read state for a conversation we do not have is ignored", "[client][volatile]") {
    TempClient c;
    auto them = "05" + std::string(64, '8');
    auto id = dm_from_hex(them);

    // An entry outlives the conversation it describes: this config is pruned by age, not by
    // anything noticing a deletion.  Creating a conversation from one would resurrect what another
    // device deleted.
    auto orphan = volatile_from_another_device(*c.client, [&](config::ConvoInfoVolatile& theirs) {
        auto e = theirs.get_or_construct_1to1(them);
        e.last_read = clock_now_ms().time_since_epoch().count();
        theirs.set(e);
    });
    merge_volatile(*c.client, orphan);

    CHECK_FALSE(c->conversation(id, await));
    CHECK(c->conversations(await).empty());
}

TEST_CASE("Client: a read point far ahead of our clock is held near it", "[client][volatile]") {
    TempClient c;
    SenderKeys them;
    auto id = ConversationId::dm(them.session_id);
    auto hex = oxenc::to_hex(them.session_id);
    approve(*c, them.session_id);

    // One message from a clock a month ahead, read up to by its own timestamp, as an app does.
    auto ahead = clock_now_ms() + 30 * 24h;
    deliver(*c, them, "from the future", ahead, "h1");
    c->conversation(id, await)->mark_read(ahead, await);

    // It stays unread until its time comes: the read point stops short of it...
    CHECK(c->conversation(id, await)->unread() == 1);
    auto entry = in_configs(*c, [&](auto& cfg) { return cfg.convo_info_volatile().get_1to1(hex); });
    REQUIRE(entry);
    CHECK(entry->last_read < ahead.time_since_epoch().count());

    // ...and stops within minutes of now, past which arrivals count again.  (The lead is five
    // minutes; ten is clear of it.)
    deliver(*c, them, "soon", clock_now_ms() + 10min, "h2");
    CHECK(c->conversation(id, await)->unread() == 2);
}

TEST_CASE(
        "Client: a read point far ahead from another device is held near our clock",
        "[client][volatile]") {
    TempClient c;
    SenderKeys them;
    auto id = ConversationId::dm(them.session_id);
    auto hex = oxenc::to_hex(them.session_id);
    approve(*c, them.session_id);
    deliver(*c, them, "one", recently(10s), "h1");

    auto ahead = volatile_from_another_device(*c.client, [&](config::ConvoInfoVolatile& theirs) {
        auto e = theirs.get_or_construct_1to1(hex);
        e.last_read = (clock_now_ms() + 30 * 24h).time_since_epoch().count();
        theirs.set(e);
    });
    merge_volatile(*c.client, ahead);
    REQUIRE(c->conversation(id, await)->unread() == 0);

    // Held within minutes of now: the lead is five minutes, and ten is clear of it.
    deliver(*c, them, "two", clock_now_ms() + 10min, "h2");
    CHECK(c->conversation(id, await)->unread() == 1);
}
