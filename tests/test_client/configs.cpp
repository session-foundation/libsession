#include "config_helpers.hpp"

TEST_CASE("Client: a merged contact reaches all three tables", "[client][configs]") {
    TempClient c;
    auto them = "05" + std::string(64, 'a');
    auto id = dm_from_hex(them);

    auto pushed = contacts_from_another_device(*c.client, them, [](auto& e) {
        e.set_name("Padmé");
        e.set_nickname("Pad");
        e.approved = true;
        e.approved_me = true;
        e.priority = 3;
        e.exp_mode = config::expiration_mode::after_read;
        e.exp_timer = std::chrono::seconds{86400};
    });
    merge_contacts(*c.client, pushed);

    // The conversation exists because the config says the contact does, not because anything has
    // been said in it.
    auto convo = c->conversation(id, await);
    REQUIRE(convo);
    CHECK(convo->priority() == 3);

    // Nickname wins over name for display, which is what the split is for.
    CHECK(convo->display_name() == "Pad");

    auto conn = c->core.database().conn();
    CHECK(conn.prepared_get<std::string>(
                  "SELECT name FROM accounts WHERE session_id = ?", id.session_id()) == "Padmé");
    auto [approved, approved_me, blocked] = conn.prepared_get<int, int, int>(
            R"(SELECT approved, approved_me, blocked FROM contacts
               WHERE account = (SELECT id FROM accounts WHERE session_id = ?))",
            id.session_id());
    CHECK(approved == 1);
    CHECK(approved_me == 1);
    CHECK(blocked == 0);
}

TEST_CASE("Client: re-deriving a contact changes nothing", "[client][configs]") {
    TempClient c;
    auto them = "05" + std::string(64, 'b');
    auto id = dm_from_hex(them);

    auto pushed = contacts_from_another_device(*c.client, them, [](auto& e) {
        e.set_name("Leia");
        e.set_nickname("Lei");
        e.approved = true;
        e.approved_me = true;
        e.blocked = false;
        e.priority = 7;
        e.notifications = config::notify_mode::disabled;
        e.mute_until = 1700000000;
        e.exp_mode = config::expiration_mode::after_send;
        e.exp_timer = std::chrono::seconds{600};
        e.created = 1690000000;
        e.profile_updated = std::chrono::sys_seconds{std::chrono::seconds{1695000000}};
    });
    merge_contacts(*c.client, pushed);

    // The property that makes the mapping trustworthy: applying a config to the tables and then
    // deriving a config back from those tables is the identity.  Anything lost, rounded or
    // defaulted on the way through shows up here as a config that went dirty -- and a mapping that
    // dirties on every pass would push a pointless update after every merge, forever.
    REQUIRE_FALSE(in_configs(*c, [](auto& cfg) { return cfg.contacts().needs_push(); }));
    TestHelper::sync_contact(*c.client, id);
    in_configs(*c, [](auto& cfg) {
        CHECK_FALSE(cfg.contacts().needs_push());
        CHECK_FALSE(cfg.contacts().needs_dump());
    });
}

TEST_CASE("Client: a contact removed elsewhere takes its history", "[client][configs]") {
    std::vector<ConversationId> gone;
    callbacks cbs;
    cbs.conversation_removed = [&](ConversationId&& id, ConversationList) {
        gone.push_back(std::move(id));
    };
    TempClient c{cbs};

    auto them = "05" + std::string(64, 'c');
    auto id = dm_from_hex(them);

    auto pushed = contacts_from_another_device(*c.client, them, [](auto& e) {
        e.set_name("Anakin");
        e.approved = true;
    });
    merge_contacts(*c.client, pushed);
    REQUIRE(c->conversation(id, await));

    auto conn = c->core.database().conn();
    auto account = conn.prepared_get<int64_t>(
            "SELECT id FROM accounts WHERE session_id = ?", id.session_id());
    conn.prepared_exec(
            R"(INSERT INTO messages (conversation, sender, outgoing, timestamp, body)
               VALUES ((SELECT id FROM conversations WHERE dm = ?1), ?1, 0, 1000, 'hi'))",
            account);
    REQUIRE(c->conversation(id, await)->messages(await).size() == 1);

    // Now the other device removes them entirely.  An absent entry can only mean the stronger
    // thing, since hiding arrives as a negative priority instead.
    auto emptied = contacts_update_from_another_device(
            *c.client, [&](config::Contacts& theirs) { theirs.erase(them); });
    merge_contacts(*c.client, emptied);

    // Conversation and history both gone, and reported.
    CHECK_FALSE(c->conversation(id, await));
    CHECK(conn.prepared_get<int64_t>("SELECT count(*) FROM messages WHERE sender = ?", account) ==
          0);
    CHECK(std::ranges::find(gone, id) != gone.end());

    // But not the account: we may have seen them in a group, and their profile renders that.
    CHECK(conn.prepared_get<int64_t>(
                  "SELECT count(*) FROM accounts WHERE session_id = ?", id.session_id()) == 1);
    CHECK(conn.prepared_get<int64_t>("SELECT count(*) FROM contacts WHERE account = ?", account) ==
          0);
}

TEST_CASE(
        "Client: a contact whose dump was lost is published, not destroyed", "[client][configs]") {
    TempClient c;
    auto them = "05" + std::string(64, 'e');
    auto id = dm_from_hex(them);

    auto pushed = contacts_from_another_device(*c.client, them, [](auto& e) {
        e.set_name("Rey");
        e.approved = true;
    });
    merge_contacts(*c.client, pushed);
    REQUIRE(c->conversation(id, await));

    // Stand in for a crash between committing the row and writing the dump: the tables hold a
    // contact the config has never heard of.  Reconciled inward first, that is indistinguishable
    // from one deleted elsewhere and would be destroyed with its history.
    REQUIRE(in_configs(*c, [&](auto& cfg) { return cfg.contacts().erase(them); }));

    c.reopen();

    // Startup derives outward before reconciling inward, so it is published rather than deleted.
    CHECK(c->conversation(id, await));
    CHECK(in_configs(*c, [&](auto& cfg) { return cfg.contacts().get(them); }).has_value());
}

TEST_CASE("Client: a new account starts with note to self hidden", "[client][configs]") {
    TempClient c;
    auto me = self_convo(*c.client);

    // Seeded at account creation rather than left at the default, because nts_priority is carried
    // in the shared UserProfile config: a default of 0 would not merely show the conversation here,
    // it would make it appear on every other device on the account once they synced.
    CHECK(in_configs(*c, [](auto& cfg) { return cfg.user_profile().get_nts_priority(); }) == -1);
    CHECK_FALSE(listed(*c.client, me));
}

TEST_CASE("Client: writing a note to self reveals it", "[client][configs]") {
    TempClient c;
    auto me = self_convo(*c.client);

    REQUIRE_FALSE(listed(*c.client, me));

    c->send_message(me, {.body = "a reminder"}, await);

    // Both halves: it is in our own list, and UserProfile says so, which is what stops the other
    // devices on the account from carrying on hiding it.
    CHECK(listed(*c.client, me));
    in_configs(*c, [](auto& cfg) {
        CHECK(cfg.user_profile().get_nts_priority() == 0);
        CHECK(cfg.user_profile().needs_push());
    });
}

TEST_CASE("Client: revealing note to self keeps a pin it already had", "[client][configs]") {
    TempClient c;
    auto me = self_convo(*c.client);

    auto pinned = profile_from_another_device(*c.client, [](auto& p) { p.set_nts_priority(7); });
    merge_profile(*c.client, pinned);
    REQUIRE(c->conversation(me, await)->priority() == 7);

    c->send_message(me, {.body = "a reminder"}, await);

    // Already visible, so there is nothing to reveal and the pin is left where the user put it.
    CHECK(in_configs(*c, [](auto& cfg) { return cfg.user_profile().get_nts_priority(); }) == 7);
    CHECK(c->conversation(me, await)->priority() == 7);
}

TEST_CASE("Client: our own profile reaches the conversation", "[client][configs]") {
    TempClient c;
    auto me = self_convo(*c.client);

    auto pushed = profile_from_another_device(*c.client, [](auto& p) {
        p.set_name("Leia");
        p.set_nts_priority(0);  // another device unhid it
    });
    merge_profile(*c.client, pushed);

    auto convo = c->conversation(me, await);
    REQUIRE(convo);
    CHECK(convo->display_name() == "Leia");
    CHECK(convo->dm()->note_to_self);
    CHECK(listed(*c.client, me));
}

TEST_CASE("Client: hiding note to self elsewhere keeps it out of the list", "[client][configs]") {
    TempClient c;
    auto me = self_convo(*c.client);

    // Visible first, so the hide is a change rather than the initial state.
    auto shown = profile_from_another_device(*c.client, [](auto& p) {
        p.set_name("Leia");
        p.set_nts_priority(0);
    });
    merge_profile(*c.client, shown);
    REQUIRE(listed(*c.client, me));

    auto hidden = profile_from_another_device(*c.client, [](auto& p) {
        p.set_name("Leia");
        p.set_nts_priority(-1);
    });
    merge_profile(*c.client, hidden);

    // Still reachable by name -- hiding is a statement about the list, not about existence -- but
    // gone from it.
    auto convo = c->conversation(me, await);
    REQUIRE(convo);
    CHECK(convo->priority() == -1);
    CHECK_FALSE(listed(*c.client, me));
}

TEST_CASE("Client: a note-to-self timer waits for the conversation", "[client][configs]") {
    TempClient c;
    auto me = self_convo(*c.client);

    // A timer set on another device while we have no note-to-self conversation.  There is nothing
    // to attach it to yet, and that is not a loss: the config is where it lives until there is.
    auto pushed = profile_from_another_device(
            *c.client, [](auto& p) { p.set_nts_expiry(std::chrono::seconds{600}); });
    merge_profile(*c.client, pushed);
    REQUIRE_FALSE(c->conversation(me, await));

    // Writing a note brings the conversation into being, and everything the config was holding for
    // it lands at that moment rather than being lost.
    c->send_message(me, {.body = "a reminder"}, await);
    REQUIRE(c->conversation(me, await));

    auto [mode, timer] = c->core.database().conn().prepared_get<int, int64_t>(
            "SELECT exp_mode, exp_timer FROM conversations"
            " WHERE dm = (SELECT id FROM accounts WHERE session_id = ?)",
            c->core.globals.session_id());

    // The config carries a duration and no mode, because only one mode means anything when the
    // reader is also the writer: there is no moment at which someone else reads it.
    CHECK(mode == static_cast<int>(config::expiration_mode::after_send));
    CHECK(timer == 600);
}

TEST_CASE("Client: a restart reconciles what nothing announced", "[client][configs]") {
    TempClient c;
    auto me = self_convo(*c.client);

    auto pushed = profile_from_another_device(*c.client, [](auto& p) {
        p.set_name("Leia");
        p.set_nts_priority(0);
    });
    merge_profile(*c.client, pushed);
    REQUIRE(c->conversation(me, await)->display_name() == "Leia");

    // Put the database behind the config behind its back, which is what a crash between merging and
    // reconciling leaves -- or a config merged by a version that could not yet reconcile it.  In
    // neither case is a further notification owed, so nothing would ever come back for it.
    c->core.database().conn().prepared_exec(
            "UPDATE accounts SET name = NULL WHERE session_id = ?", c->core.globals.session_id());
    REQUIRE(c->conversation(me, await)->display_name().empty());

    c.reopen();

    // Starting up reconciles regardless of whether anything changed, so it is repaired.
    CHECK(c->conversation(me, await)->display_name() == "Leia");
}

TEST_CASE("Client: reconciling twice does not disturb the list", "[client][configs]") {
    TempClient c;
    auto me = self_convo(*c.client);

    auto pushed = profile_from_another_device(*c.client, [](auto& p) {
        p.set_name("Leia");
        p.set_nts_priority(0);
    });
    merge_profile(*c.client, pushed);

    auto before = c->conversation(me, await);
    REQUIRE(before);

    // The same profile again reconciles again, since the seqno detector overfires on an identical
    // config, so reconciliation has to be idempotent.  The specific trap is ensure_conversation,
    // which bumps last_activity on a row that already exists -- called unguarded it would shuffle
    // note to self to the top of the list on every single config merge.
    merge_profile(*c.client, pushed);

    auto after = c->conversation(me, await);
    REQUIRE(after);
    CHECK(after->last_activity() == before->last_activity());
    CHECK(after->display_name() == before->display_name());
}

TEST_CASE("Client: blocking someone makes them a contact", "[client][configs]") {
    TempClient c;
    auto them = "05" + std::string(64, '1');
    auto id = dm_from_hex(them);

    // Someone we have merely seen: an account row and nothing else, which is what an unanswered
    // message request looks like.
    {
        auto conn = c->core.database().conn();
        conn.prepared_exec("INSERT INTO accounts (session_id) VALUES (?)", id.session_id());
    }
    REQUIRE_FALSE(in_configs(*c, [&](auto& cfg) { return cfg.contacts().get(them); }));

    // Through Client, not through a DM: there is no conversation here, which is exactly the case
    // that carve-out exists for.
    c->set_blocked(id, true, await);

    // The block has to be synced and the entry is the only place it can live, so blocking makes
    // one.  It does not approve them: refusing someone's messages is not accepting them.
    auto entry = in_configs(*c, [&](auto& cfg) { return cfg.contacts().get(them); });
    REQUIRE(entry);
    CHECK(entry->blocked);
    CHECK_FALSE(entry->approved);

    c->set_blocked(id, false, await);
    REQUIRE(in_configs(*c, [&](auto& cfg) { return cfg.contacts().get(them); }));
    CHECK_FALSE(in_configs(*c, [&](auto& cfg) { return cfg.contacts().get(them); })->blocked);
}

TEST_CASE("Client: clearing a conversation says when it was cleared", "[client][configs]") {
    std::vector<ConversationId> reloaded;
    callbacks cbs;
    cbs.history_replaced = [&](const ConversationId& id) { reloaded.push_back(id); };
    TempClient c{cbs};

    auto them = "05" + std::string(64, '2');
    auto id = dm_from_hex(them);
    c->open_dm(id, await);
    insert_message(*c.client, id, 1000, "hi");
    REQUIRE(c->conversation(id, await)->messages(await).size() == 1);

    auto before = std::chrono::floor<std::chrono::seconds>(clock_now_ms());
    c->conversation(id, await)->clear_messages(await);

    CHECK(c->conversation(id, await)->messages(await).empty());
    CHECK(c->conversation(id, await));  // The conversation stays; only its history went.
    CHECK(std::ranges::find(reloaded, id) != reloaded.end());

    // And the moment is recorded rather than the deletion being local, so a device that has been
    // offline through all of this deletes the same messages when it catches up.
    auto entry = in_configs(*c, [&](auto& cfg) { return cfg.contacts().get(them); });
    REQUIRE(entry);
    CHECK(entry->delete_before >= before);
}

TEST_CASE("Client: deleting a conversation keeps the contact", "[client][configs]") {
    TempClient c;
    auto them = "05" + std::string(64, '3');
    auto id = dm_from_hex(them);
    c->open_dm(id, await);
    c->conversation(id, await)->set_priority(5, await);
    insert_message(*c.client, id, 1000, "hi");
    REQUIRE(listed(*c.client, id));

    c->conversation(id, await)->delete_conversation(await);

    CHECK_FALSE(listed(*c.client, id));
    CHECK(c->conversation(id, await)->messages(await).empty());

    auto entry = in_configs(*c, [&](auto& cfg) { return cfg.contacts().get(them); });
    REQUIRE(entry);  // Still a contact, so a message from them brings the conversation back.
    CHECK(entry->approved);
    CHECK(entry->priority == -1);  // The pin it had is not among the things kept.
    CHECK(entry->delete_before > std::chrono::sys_seconds{});
}

TEST_CASE("Client: hiding note to self keeps what is in it", "[client][configs]") {
    TempClient c;
    auto me = self_convo(*c.client);
    c->open_dm(me, await);
    insert_message(*c.client, me, 1000, "note");
    REQUIRE(listed(*c.client, me));

    c->conversation(me, await)->delete_conversation(/*keep_messages=*/true, await);

    CHECK_FALSE(listed(*c.client, me));
    CHECK(c->conversation(me, await)->messages(await).size() == 1);
    CHECK(in_configs(*c, [](auto& cfg) { return cfg.user_profile().get_nts_priority(); }) == -1);

    // No instruction to destroy anything, which is the whole difference between hiding a
    // conversation and deleting one.
    CHECK(in_configs(*c, [](auto& cfg) { return cfg.user_profile().get_nts_delete_before(); }) ==
          std::chrono::sys_seconds{});
}

TEST_CASE("Client: deleting a contact takes the entry that held the block", "[client][configs]") {
    std::vector<ConversationId> gone;
    callbacks cbs;
    cbs.conversation_removed = [&](ConversationId&& id, ConversationList) {
        gone.push_back(std::move(id));
    };
    TempClient c{cbs};

    auto them = "05" + std::string(64, '4');
    auto id = dm_from_hex(them);
    c->open_dm(id, await);
    c->dm(id, await)->set_blocked(true, await);
    insert_message(*c.client, id, 1000, "hi");

    c->dm(id, await)->delete_contact(await);

    CHECK_FALSE(c->conversation(id, await));
    CHECK(std::ranges::find(gone, id) != gone.end());

    // No entry means no delete-before instruction is owed: another device merging this drops the
    // conversation and its history because the contact is gone, not because it was told to.  It
    // also means the block is gone, since the entry was the only thing holding it.
    CHECK_FALSE(in_configs(*c, [&](auto& cfg) { return cfg.contacts().get(them); }));

    auto conn = c->core.database().conn();
    CHECK(conn.prepared_get<int64_t>("SELECT count(*) FROM messages") == 0);
    CHECK(conn.prepared_get<int64_t>(
                  "SELECT count(*) FROM accounts WHERE session_id = ?", id.session_id()) == 1);
}

TEST_CASE("Client: a delete-before from another device destroys history", "[client][configs]") {
    TempClient c;
    auto them = "05" + std::string(64, '5');
    auto id = dm_from_hex(them);

    auto pushed = contacts_from_another_device(*c.client, them, [](auto& e) { e.approved = true; });
    merge_contacts(*c.client, pushed);
    REQUIRE(c->conversation(id, await));

    insert_message(*c.client, id, 1'000'000, "old");
    insert_message(*c.client, id, 3'000'000, "new");
    REQUIRE(c->conversation(id, await)->messages(await).size() == 2);

    // Retroactive: what the instruction is about is the history that was there when someone chose
    // to destroy it, not merely what arrives after it.
    auto cleared = contacts_update_from_another_device(*c.client, [&](config::Contacts& theirs) {
        auto e = theirs.get_or_construct(them);
        e.delete_before = std::chrono::sys_seconds{2000s};
        theirs.set(e);
    });
    merge_contacts(*c.client, cleared);

    auto left = c->conversation(id, await)->messages(await);
    REQUIRE(left.size() == 1);
    CHECK(left[0].body == "new");
}

TEST_CASE("Client: approval is not walked back by a merge", "[client][configs]") {
    TempClient c;
    auto them = "05" + std::string(64, '7');
    auto id = dm_from_hex(them);

    c->open_dm(id, await);
    REQUIRE(in_configs(*c, [&](auto& cfg) { return cfg.contacts().get(them); }));
    REQUIRE(in_configs(*c, [&](auto& cfg) { return cfg.contacts().get(them); })->approved);

    // Another client clearing both flags on its way to deleting the contact, merged without the
    // deletion that was to follow.  Copied verbatim this would file the conversation back under
    // message requests -- and there is no message anyone could send to put it back.
    auto unapproved = contacts_update_from_another_device(*c.client, [&](config::Contacts& theirs) {
        auto e = theirs.get_or_construct(them);
        e.approved = false;
        e.approved_me = false;
        theirs.set(e);
    });
    merge_contacts(*c.client, unapproved);

    CHECK(c->message_requests(await).empty());
    REQUIRE(c->conversation(id, await));
    CHECK_FALSE(c->conversation(id, await)->dm()->request);
}

TEST_CASE("Client: a delete-before is not walked back", "[client][configs]") {
    TempClient c;
    auto them = "05" + std::string(64, '6');
    auto id = dm_from_hex(them);
    c->open_dm(id, await);

    // Another device cleared at a moment this one has not reached yet -- clock skew is enough for
    // that.  Publishing our own, smaller value would tell it to un-delete what it destroyed.
    auto later = std::chrono::floor<std::chrono::seconds>(clock_now_ms()) + 1h;
    in_configs(*c, [&](auto& cfg) {
        auto entry = cfg.contacts().get_or_construct(them);
        entry.delete_before = later;
        cfg.contacts().set(entry);
    });

    c->conversation(id, await)->clear_messages(await);

    in_configs(*c, [&](auto& cfg) {
        REQUIRE(cfg.contacts().get(them));
        CHECK(cfg.contacts().get(them)->delete_before == later);
    });
}

TEST_CASE("Client: our own profile is account state, not a conversation", "[client][configs]") {
    TempClient c;

    // Nothing set yet, and -- the point of this being on Client -- no note-to-self conversation
    // needed for the question to have an answer.
    CHECK(c->conversations(await).empty());
    CHECK(c->display_name(await).empty());

    c->set_display_name("Leia", await);
    CHECK(c->display_name(await) == "Leia");
    // Copied to a string inside the excursion: get_name() hands back a view into the config.
    CHECK(in_configs(*c, [](auto& cfg) {
              return std::string{cfg.user_profile().get_name().value_or("")};
          }) == "Leia");

    // Still no conversation: setting a name is not writing to yourself.
    CHECK(c->conversations(await).empty());
}

TEST_CASE("Client: the save-notification preference follows the account", "[client][configs]") {
    TempClient c;

    // Session's default is to tell people when you save their files.
    CHECK(c->notify_media_saved(await));

    c->set_notify_media_saved(false, await);
    CHECK_FALSE(c->notify_media_saved(await));
    CHECK_FALSE(
            in_configs(*c, [](auto& cfg) { return cfg.user_profile().get_notify_media_saved(); }));

    // What another device set reaches us through a merge, like any other profile field.
    auto pushed = profile_from_another_device(
            *c.client, [](config::UserProfile& p) { p.set_notify_media_saved(true); });
    merge_profile(*c.client, pushed);
    CHECK(c->notify_media_saved(await));
}

TEST_CASE(
        "Client: a conversation reports the picture it has been told about", "[client][configs]") {
    TempClient c;
    auto them = "05" + std::string(64, 'b');
    auto id = dm_from_hex(them);

    std::vector<std::byte> key(32, std::byte{0x7});
    auto pushed = contacts_from_another_device(*c.client, them, [&](auto& e) {
        e.set_name("Padmé");
        e.profile_picture = config::profile_pic{"http://fs.example/file/99#pubkey=aa", key};
    });
    merge_contacts(*c.client, pushed);

    auto convo = c->conversation(id, await);
    REQUIRE(convo);
    CHECK(convo->picture().url == "http://fs.example/file/99#pubkey=aa");
    CHECK(convo->picture().key == key);

    // Somebody we know nothing about has none, which is not the same as an error.
    auto stranger = dm_from_hex("05" + std::string(64, 'c'));
    c->open_dm(stranger, await);
    CHECK(c->conversation(stranger, await)->picture().url.empty());
}

TEST_CASE("Client: no picture is nullopt rather than a failure", "[client][configs]") {
    TempClient c;
    SenderKeys them;
    auto id = ConversationId::dm(them.session_id);
    c->open_dm(id, await);

    std::optional<std::vector<std::byte>> got;
    std::optional<Error> err;
    bool called = false;
    c->profile_picture(id, [&](auto r) {
        if (r)
            got = *std::move(r);
        else
            err = std::move(r).error();
        called = true;
    });
    sync(*c);

    REQUIRE(called);
    CHECK_FALSE(err.has_value());
    CHECK_FALSE(got.has_value());
}

TEST_CASE("Client: config sizes are the size of each config's dump", "[client][configs]") {
    SECTION("nothing to measure before there is an account") {
        TempClient c{core::defer_account{}};
        CHECK(c->config_sizes(await).empty());
    }

    SECTION("one entry per config, growing with what is put in it") {
        TempClient c;
        auto before = c->config_sizes(await);
        CHECK(before.size() == 5);
        for (auto name :
             {"user_profile", "contacts", "convo_info_volatile", "user_groups", "local"})
            CHECK(before.contains(name));

        c->set_display_name("A name long enough to make the dump measurably larger", await);
        auto after = c->config_sizes(await);
        CHECK(after.at("user_profile") > before.at("user_profile"));
        CHECK(after.at("user_profile") == in_configs(*c, [](auto& cfg) {
                  return static_cast<int>(cfg.user_profile().make_dump().size());
              }));
    }
}
