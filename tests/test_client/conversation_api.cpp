#include "config_helpers.hpp"

TEST_CASE("Client: a conversation reports the settings it carries", "[client][convos]") {
    TempClient c;
    auto them = "05" + std::string(64, 'a');
    auto id = dm_from_hex(them);
    c->open_dm(id, await);

    auto convo = [&] { return *c->conversation(id, await); };

    // Defaults, and the ones a screen needs in order to draw a toggle rather than a button.
    CHECK(convo().notifications() == config::notify_mode::defaulted);
    CHECK(convo().mute_until() == std::chrono::sys_seconds{});
    CHECK(convo().exp_mode() == config::expiration_mode::none);
    CHECK_FALSE(convo().dm()->blocked);

    c->conversation(id, await)->set_notifications(config::notify_mode::disabled, await);
    c->conversation(id, await)->set_mute_until(std::chrono::sys_seconds{1700000000s}, await);
    c->conversation(id, await)->set_expiry(config::expiration_mode::after_read, 86400s, await);
    c->set_blocked(id, true, await);
    c->dm(id, await)->set_nickname("Bilbo", await);

    CHECK(convo().notifications() == config::notify_mode::disabled);
    CHECK(convo().mute_until() == std::chrono::sys_seconds{1700000000s});
    CHECK(convo().exp_mode() == config::expiration_mode::after_read);
    CHECK(convo().exp_timer() == 86400s);
    CHECK(convo().dm()->blocked);

    // The two halves display_name merges.  A row wants the merge; a screen that edits the nickname
    // has to show both, and cannot when only the resolved answer arrives.
    CHECK(convo().dm()->nickname == "Bilbo");
    CHECK(convo().display_name() == "Bilbo");
    CHECK(convo().dm()->name.empty());

    // All of it reaches the Contacts config, which is what makes it follow the account rather than
    // the device.
    auto entry = in_configs(*c, [&](auto& cfg) { return cfg.contacts().get(them); });
    REQUIRE(entry);
    CHECK(entry->notifications == config::notify_mode::disabled);
    CHECK(entry->mute_until == 1700000000);
    CHECK(entry->exp_mode == config::expiration_mode::after_read);
    CHECK(entry->exp_timer == 86400s);
    CHECK(entry->blocked);
    CHECK(entry->nickname == "Bilbo");

    // Clearing the nickname falls back to what they call themselves.
    c->dm(id, await)->set_nickname("", await);
    CHECK(convo().dm()->nickname.empty());
    CHECK_FALSE(in_configs(*c, [&](auto& cfg) {
                    return cfg.contacts().get(them);
                })->nickname == "Bilbo");

    // A timer without a mode expires nothing, so it is not stored as though it were a setting.
    c->conversation(id, await)->set_expiry(config::expiration_mode::none, 3600s, await);
    CHECK(convo().exp_mode() == config::expiration_mode::none);
    CHECK(convo().exp_timer() == 0s);
}

TEST_CASE("Client: a nickname too long to sync is refused rather than stored", "[client][convos]") {
    TempClient c;
    auto them = "05" + std::string(64, 'a');
    auto id = dm_from_hex(them);
    c->open_dm(id, await);

    c->dm(id, await)->set_nickname("Bilbo", await);

    // One byte over is enough.  What must not happen is the row being written and the config then
    // refusing it: a sync rebuilds the whole entry from that row, so it would never carry again --
    // taking every later change to this contact with it.
    std::string too_long(config::contact_info::MAX_NAME_LENGTH + 1, 'x');
    REQUIRE(config::validate_contact_name(too_long).has_value());
    CHECK_THROWS_AS(c->dm(id, await)->set_nickname(too_long, await), std::invalid_argument);

    // Nothing moved: not the database, and not the config it is reconciled into.
    CHECK(c->conversation(id, await)->dm()->nickname == "Bilbo");
    CHECK(in_configs(*c, [&](auto& cfg) { return cfg.contacts().get(them); })->nickname == "Bilbo");

    // And the contact still syncs, which is the part that would have been lost quietly.
    c->set_blocked(id, true, await);
    CHECK(in_configs(*c, [&](auto& cfg) { return cfg.contacts().get(them); })->blocked);

    // Exactly at the limit is fine: the check is the config's own, not a stricter one.
    std::string at_limit(config::contact_info::MAX_NAME_LENGTH, 'y');
    CHECK_FALSE(config::validate_contact_name(at_limit).has_value());
    c->dm(id, await)->set_nickname(at_limit, await);
    CHECK(in_configs(*c, [&](auto& cfg) { return cfg.contacts().get(them); })->nickname ==
          at_limit);
}

TEST_CASE("Client: settings from another device reach the conversation", "[client][configs]") {
    TempClient c;
    auto them = "05" + std::string(64, 'b');
    auto id = dm_from_hex(them);

    auto pushed = contacts_from_another_device(*c.client, them, [](auto& e) {
        e.set_name("Frodo");
        e.set_nickname("Mr Underhill");
        e.approved = true;
        e.blocked = true;
        e.notifications = config::notify_mode::disabled;
        e.mute_until = 1700000000;
        e.exp_mode = config::expiration_mode::after_send;
        e.exp_timer = 600s;
    });
    merge_contacts(*c.client, pushed);

    auto convo = c->conversation(id, await);
    REQUIRE(convo);
    CHECK(convo->notifications() == config::notify_mode::disabled);
    CHECK(convo->mute_until() == std::chrono::sys_seconds{1700000000s});
    CHECK(convo->exp_mode() == config::expiration_mode::after_send);
    CHECK(convo->exp_timer() == 600s);
    REQUIRE(convo->dm());
    CHECK(convo->dm()->blocked);
    CHECK(convo->dm()->name == "Frodo");
    CHECK(convo->dm()->nickname == "Mr Underhill");
    CHECK(convo->display_name() == "Mr Underhill");
}

TEST_CASE("Client: a page size has to be a page", "[client][convos]") {
    TempClient c;
    auto id = dm_from_hex("05" + std::string(64, 'a'));
    c->open_dm(id, await);
    c->send_message(id, {.body = "hi"}, await);

    // Unchecked, these reach SQLite as `LIMIT ?`, where a negative is no limit at all: asking for
    // one message would load every message in the conversation.
    for (int limit : {0, -1, -50}) {
        CHECK_THROWS_AS(c->conversation(id, await)->messages(limit, await), std::invalid_argument);
        CHECK_THROWS_AS(
                c->conversation(id, await)->messages(limit, std::nullopt, true, await),
                std::invalid_argument);
    }

    // The handler form refuses on the calling thread too, rather than reporting it: the caller is
    // still there to catch, and a bad page size is its bug rather than a runtime condition.
    auto ignore = [](Expected<std::vector<Message>>) {};
    CHECK_THROWS_AS(c->conversation(id, await)->messages(0, ignore), std::invalid_argument);

    CHECK(c->conversation(id, await)->messages(1, await).size() == 1);
}

TEST_CASE("Client: a conversation knows which kind it is", "[client][convos]") {
    TempClient c;
    SenderKeys them;
    auto id = ConversationId::dm(them.session_id);
    c->open_dm(id, await);

    auto convo = c->conversation(id, await);
    REQUIRE(convo);

    // The kind is what makes a question askable: `request` is a thing only a DM can be, and asking
    // it of a community should not compile rather than quietly answering false.
    REQUIRE(convo->dm());
    CHECK_FALSE(convo->dm()->request);
    CHECK_FALSE(convo->group());
    CHECK_FALSE(convo->community());

    // Common fields reach through whichever kind it is.
    CHECK(convo->id() == id);
    CHECK(convo->unread() == 0);
}

TEST_CASE(
        "Client: a handler-form operation outlives the conversation it came from",
        "[client][convos]") {
    TempClient c;
    SenderKeys them;
    auto id = ConversationId::dm(them.session_id);
    approve(*c, them.session_id);
    deliver(*c, them, "hi", from_epoch_ms(5000), "h1");
    REQUIRE(c->conversation(id, await)->unread() == 1);

    // The natural way to write any of these is on something that has already gone by the time the
    // work runs: a temporary, a handler's parameter, or a list element whose list got replaced.  So
    // the operation must not reach back into the object -- and only the handler form can get this
    // wrong, since the waiting form runs before it returns.
    std::optional<Error> error = Error{"test.not_called", "not called"};
    {
        auto convo = c->conversation(id, await);
        REQUIRE(convo);
        convo->mark_read([&](auto r) {
            if (r)
                error.reset();
            else
                error = std::move(r).error();
        });
    }  // convo destroyed here, before the loop has run the work
    sync(*c);

    CHECK_FALSE(error.has_value());
    CHECK(c->conversation(id, await)->unread() == 0);

    // And on an outright temporary, which is how it reads at a call site.
    std::optional<Error> paged = Error{"test.not_called", "not called"};
    size_t got = 0;
    c->conversation(id, await)->messages(50, [&](auto r) {
        if (r) {
            paged.reset();
            got = r->size();
        } else
            paged = std::move(r).error();
    });
    sync(*c);
    CHECK_FALSE(paged.has_value());
    CHECK(got == 1);
}

TEST_CASE("Client: every conversation kind starts with its base", "[client][convos]") {
    // What makes reading a common field off AnyConversation free: each alternative holds its
    // `Conversation` at offset zero, so every arm of the variant's dispatch computes the same
    // address and the compiler folds it away.  Put another base ahead of `Conversation` and that
    // silently becomes a runtime selection instead.
    //
    TempClient c;
    Conversation base{*c.client, dm_from_hex("05" + std::string(64, '9'))};
    DM dm{base};
    Group group{base};
    Community community{base};
    CHECK(static_cast<const void*>(&dm) == static_cast<const Conversation*>(&dm));
    CHECK(static_cast<const void*>(&group) == static_cast<const Conversation*>(&group));
    CHECK(static_cast<const void*>(&community) == static_cast<const Conversation*>(&community));
}

TEST_CASE("Client: auto-download is per conversation and stays here", "[client][convos]") {
    TempClient c;
    SenderKeys them;
    auto id = ConversationId::dm(them.session_id);
    c->open_dm(id, await);

    // Unset means nobody has been asked, which is what a client prompts on.  It is not `none`.
    CHECK_FALSE(c->conversation(id, await)->auto_download().has_value());

    c->conversation(id, await)->set_auto_download(AutoDownload::image_attachments, await);
    CHECK(c->conversation(id, await)->auto_download() == AutoDownload::image_attachments);

    // Answering "none" is an answer: it records that the question was asked, so a client that
    // prompts when unset does not prompt again.
    c->conversation(id, await)->set_auto_download(AutoDownload::none, await);
    auto after = c->conversation(id, await)->auto_download();
    REQUIRE(after.has_value());
    CHECK(*after == AutoDownload::none);

    // Device-local: nothing about it reaches the config that follows the account.  Checked by
    // deriving the contact outward and finding the config unchanged -- if this were synced, the
    // setting above would have dirtied it.
    // Read each time rather than binding the config: a reference to one is only ours for as long
    // as the excursion onto the loop lasts.
    auto contacts_dirty = [&] {
        return in_configs(*c, [](auto& cfg) { return cfg.contacts().needs_push(); });
    };
    TestHelper::sync_contact(*c.client, id);
    auto before_push = contacts_dirty();
    c->conversation(id, await)->set_auto_download(AutoDownload::all, await);
    TestHelper::sync_contact(*c.client, id);
    CHECK(contacts_dirty() == before_push);

    // And it survives a restart, being a stored property rather than a session's opinion.
    c.reopen();
    CHECK(c->conversation(id, await)->auto_download() == AutoDownload::all);
}

TEST_CASE("Client: the badge counts what the user should be told about", "[client][badge]") {
    TempClient c;
    CHECK(c->badge_count(await) == 0);

    SenderKeys friend_, stranger, muted, silenced, blocked;
    for (auto* k : {&friend_, &muted, &silenced, &blocked})
        approve(*c, k->session_id);

    int64_t ts = 1'700'000'000'000;
    auto send = [&](SenderKeys& from, int n, std::string_view tag) {
        for (int i = 0; i < n; i++, ts++)
            deliver(*c, from, "msg", from_epoch_ms(ts), "{}-{}"_format(tag, i));
    };
    send(friend_, 3, "friend");
    send(stranger, 4, "stranger");
    send(muted, 2, "muted");
    send(silenced, 2, "silenced");
    send(blocked, 2, "blocked");

    c->conversation(ConversationId::dm(muted.session_id), await)
            ->set_mute_until(std::chrono::floor<std::chrono::seconds>(clock_now() + 1h), await);
    c->conversation(ConversationId::dm(silenced.session_id), await)
            ->set_notifications(config::notify_mode::disabled, await);
    c->set_blocked(ConversationId::dm(blocked.session_id), true, await);

    // The friend's three, and the stranger's request once however many it holds.
    CHECK(c->badge_count(await) == 3 + 1);

    // Mentions-only is a group setting: on a one-to-one conversation it still counts everything.
    c->conversation(ConversationId::dm(friend_.session_id), await)
            ->set_notifications(config::notify_mode::mentions_only, await);
    CHECK(c->badge_count(await) == 3 + 1);

    // Reading empties it; a mute that has passed counts again.
    c->conversation(ConversationId::dm(friend_.session_id), await)->mark_read(await);
    CHECK(c->badge_count(await) == 1);
    c->conversation(ConversationId::dm(muted.session_id), await)
            ->set_mute_until(std::chrono::floor<std::chrono::seconds>(clock_now() - 1h), await);
    CHECK(c->badge_count(await) == 1 + 2);
}
