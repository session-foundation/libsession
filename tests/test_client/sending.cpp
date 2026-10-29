#include "common.hpp"

// ── Sending ─────────────────────────────────────────────────────────────────────────────────────

TEST_CASE("Client: send_message stores, dispatches and reaches sent", "[client][send]") {
    TempClient c;
    auto* net = attach_mock_network(c->core);

    constexpr auto peer =
            "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    auto convo = ConversationId::dm(peer);

    // No PFS keys published for either of us, so these fall back to v1 sends: the recipient's copy
    // and the copy for our own swarm, which needs our own keys answered too.
    TestHelper::seed_pfs_nak(c->core, peer);
    TestHelper::seed_pfs_nak(c->core, own_sid(*c));

    auto id = c->send_message(convo, {.body = "general kenobi"}, await);

    // A store to the recipient's swarm and one to our own, both into the default namespace, with
    // something in them.
    auto sent = stores(*net);
    REQUIRE(sent.size() == 2);
    for (const auto* r : sent) {
        auto body = store_body(*r);
        CHECK(body["namespace"] == static_cast<int16_t>(config::Namespace::Default));
        CHECK_FALSE(body["data"].get<std::string>().empty());
    }
    CHECK(accept_stores(*net) == 2);

    auto msg = c->message(id, await);
    REQUIRE(msg.has_value());
    CHECK(msg->body == "general kenobi");
    CHECK(msg->outgoing);
    CHECK(msg->sender == own_sid(*c));
    CHECK(msg->send_state == SendState::sent);

    // Of the two hashes the two stores were assigned, the one kept is our own swarm's: it is the
    // copy we can still act on, and the one a redelivery would arrive under.
    CHECK(msg->hash == store_hash_for(oxenc::to_hex(own_sid(*c))));

    // The conversation was created by the send and shows the outgoing message as its preview.
    auto convos = c->conversations(await);
    REQUIRE(convos.size() == 1);
    CHECK(preview_body(convos[0]) == "general kenobi");
    // Ours, which is what lets a row prefix "You: ".
    REQUIRE(convos[0].last_preview());
    CHECK(convos[0].last_preview()->outgoing);
    // Our own message is never unread.
    CHECK(convos[0].unread() == 0);
}

TEST_CASE("Client: a failed send is recorded as failed", "[client][send]") {
    TempClient c;
    auto* net = attach_mock_network(c->core);

    constexpr auto peer =
            "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    TestHelper::seed_pfs_nak(c->core, peer);
    TestHelper::seed_pfs_nak(c->core, own_sid(*c));

    auto id = c->send_message(ConversationId::dm(peer), {.body = "into the void"}, await);

    // The swarm refusing the store is what a failure is, rather than us declining to attempt one.
    auto sent = stores(*net);
    REQUIRE(sent.size() == 2);
    for (auto* r : sent)
        r->callback(false, false, 500, {}, "nope");

    CHECK(c->message(id, await)->send_state == SendState::failed);
}

TEST_CASE("Client: sending to a non-DM conversation is rejected", "[client][send]") {
    TempClient c;
    constexpr auto gid = "03fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    CHECK_THROWS_AS(
            c->send_message(ConversationId::group(gid), {.body = "hi"}, await),
            std::invalid_argument);
}

TEST_CASE("Client: an in-flight send becomes interrupted after a restart", "[client][send]") {
    // The store is captured and never answered, which leaves the message mid-flight -- exactly the
    // state a crash would leave behind.
    TempClient c;
    auto* net = attach_mock_network(c->core);

    constexpr auto peer =
            "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    TestHelper::seed_pfs_nak(c->core, peer);
    TestHelper::seed_pfs_nak(c->core, own_sid(*c));

    auto id = c->send_message(ConversationId::dm(peer), {.body = "did this land?"}, await);
    CHECK(c->message(id, await)->send_state == SendState::sending);

    c.reopen();

    // Not "failed": we genuinely do not know whether the swarm stored it.
    CHECK(c->message(id, await)->send_state == SendState::interrupted);
    CHECK(c->message(id, await)->body == "did this land?");
}

// ── Signals ─────────────────────────────────────────────────────────────────────────────────────

TEST_CASE("Client: the application is told what changed", "[client][signals]") {
    SenderKeys sender;
    Recorder r;
    TempClient c{r.handlers()};

    deliver(*c, sender, "ping", from_epoch_ms(1000), "h1");
    sync(*c);

    auto convo = ConversationId::dm(sender.session_id);
    // The request list and not the conversation list: an inbound message from someone we have not
    // written to is a request, and the two lists are complements, so only the one it sits in is
    // stale.  A conversation-list replacement here would say something false about the other.
    CHECK(r.order == std::vector<std::string>{"added", "message", "updated", "requests"});
    REQUIRE(r.requests_replaced.size() == 1);
    CHECK(r.replaced.empty());

    // Every handler is given the state itself, not something to go and look up.
    REQUIRE(r.added.size() == 1);
    CHECK(r.added[0].id() == convo);
    REQUIRE(r.msg_added.size() == 1);
    REQUIRE(r.msg_added[0].size() == 1);
    CHECK(r.msg_added[0][0].conversation == convo);
    CHECK(r.msg_added[0][0].body == "ping");
    REQUIRE(r.updated.size() == 1);
    CHECK(preview_body(r.updated[0]) == "ping");
    CHECK(r.updated[0].unread() == 1);

    // A second message on an existing conversation does not re-announce the conversation, but the
    // list is stale again -- the row's snippet changed, and the list is what carries it for a
    // subscriber that holds no per-row handler.
    r.order.clear();
    r.requests_replaced.clear();
    deliver(*c, sender, "pong", from_epoch_ms(2000), "h2");
    sync(*c);
    CHECK(r.order == std::vector<std::string>{"message", "updated", "requests"});
    CHECK(r.requests_replaced.size() == 1);
    REQUIRE(r.updated.size() == 2);
    CHECK(preview_body(r.updated.back()) == "pong");
}

TEST_CASE("Client: a subscriber that wants lists is sent them", "[client][signals]") {
    SenderKeys a, b;
    Recorder r;
    // No order handlers, so the order events have nowhere to go and a whole list is the only way
    // this subscriber can learn that one row now sits in front of another.
    TempClient c{r.handlers()};
    approve(*c, a.session_id);
    approve(*c, b.session_id);
    auto ida = ConversationId::dm(a.session_id);
    auto idb = ConversationId::dm(b.session_id);

    deliver(*c, a, "first", from_epoch_ms(1000), "h1");
    deliver(*c, b, "second", from_epoch_ms(2000), "h2");
    sync(*c);
    r.order.clear();
    r.replaced.clear();

    deliver(*c, a, "third", from_epoch_ms(3000), "h3");
    sync(*c);

    CHECK(r.order == std::vector<std::string>{"message", "updated", "replaced"});
    REQUIRE(r.replaced.size() == 1);
    REQUIRE(r.replaced[0].size() == 2);
    CHECK(r.replaced[0][0].id() == ida);
    CHECK(r.replaced[0][1].id() == idb);
}

TEST_CASE("Client: a replacement is sent even when nothing moved", "[client][signals]") {
    SenderKeys sender;
    Recorder r;
    TempClient c{r.handlers()};
    approve(*c, sender.session_id);

    deliver(*c, sender, "ping", from_epoch_ms(1000), "h1");
    sync(*c);
    r.order.clear();
    r.replaced.clear();

    // A second message to the only conversation moves nothing, so an order event would be
    // suppressed -- but the snippet changed, and for this subscriber the list is the only thing
    // carrying it.  Suppressing the list on an unchanged order would leave it showing "ping".
    deliver(*c, sender, "pong", from_epoch_ms(2000), "h2");
    sync(*c);

    REQUIRE(r.replaced.size() == 1);
    REQUIRE(r.replaced[0].size() == 1);
    CHECK(preview_body(r.replaced[0][0]) == "pong");
}

TEST_CASE("Client: a change that moves nothing still replaces the list", "[client][signals]") {
    SenderKeys sender;
    Recorder r;
    TempClient c{r.handlers()};
    approve(*c, sender.session_id);
    auto id = ConversationId::dm(sender.session_id);

    deliver(*c, sender, "ping", from_epoch_ms(1000), "h1");
    sync(*c);
    REQUIRE(r.replaced.size() >= 1);
    CHECK(r.replaced.back()[0].unread() == 1);
    r.order.clear();
    r.replaced.clear();

    // Reading the conversation changes `unread_count` and moves nothing, so it never reaches
    // `_dirty_order`.  For this subscriber the list is the only thing carrying the count, so
    // driving the replacement off what *moved* rather than off what *changed* would leave it
    // showing an unread conversation the user has just read.
    c->conversation(id, await)->mark_read(await);
    sync(*c);

    REQUIRE(r.replaced.size() == 1);
    REQUIRE(r.replaced[0].size() == 1);
    CHECK(r.replaced[0][0].unread() == 0);
}

TEST_CASE(
        "Client: a batch reports each message but settles the conversation once",
        "[client][signals]") {
    SenderKeys sender;
    Recorder r;
    TempClient c{r.handlers()};

    // One delivery carrying several messages, as a swarm poll produces.
    std::vector<std::string> encoded;
    for (int i = 0; i < 5; i++) {
        SessionProtos::Content content;
        auto ts = from_epoch_ms(1000 + i);
        content.set_sigtimestamp(static_cast<uint64_t>(epoch_ms(ts)));
        content.mutable_datamessage()->set_body("m{}"_format(i));
        encoded.push_back(content.SerializeAsString());
    }
    std::vector<std::vector<std::byte>> wire;
    for (int i = 0; i < 5; i++)
        wire.push_back(encode_dm_v1(
                std::as_bytes(std::span{encoded[i]}),
                sender.ed_sk,
                from_epoch_ms(1000 + i),
                own_sid(*c),
                std::nullopt));
    std::vector<core::SwarmMessage> batch;
    for (int i = 0; i < 5; i++)
        batch.push_back(core::SwarmMessage{
                wire[i],
                "b{}"_format(i),
                from_epoch_ms(1000 + i),
                from_epoch_ms(1'000'000'000'000)});

    c->core.loop().call_get([&] {
        c->core.receive_messages(batch, config::Namespace::Default, true);
        return 0;
    });
    sync(*c);

    // Five messages, but the conversation settles once rather than being rebuilt five times.
    CHECK(std::ranges::count(r.order, "message") == 5);
    CHECK(std::ranges::count(r.order, "updated") == 1);
    REQUIRE(r.updated.size() == 1);
    CHECK(r.updated[0].unread() == 5);
    CHECK(preview_body(r.updated[0]) == "m4");
}

TEST_CASE("Client: an update says where its row was and now belongs", "[client][signals]") {
    SenderKeys a, b;
    Recorder r;
    TempClient c{r.handlers()};
    approve(*c, a.session_id);
    approve(*c, b.session_id);
    auto ida = ConversationId::dm(a.session_id);
    auto idb = ConversationId::dm(b.session_id);

    deliver(*c, a, "first", from_epoch_ms(1000), "h1");
    sync(*c);

    // The add already says where it goes: nothing to remove, into the conversation list, and
    // nothing above it -- which an unset anchor is what says.
    REQUIRE(r.add_placements.size() == 1);
    CHECK(r.add_placements[0].from == ConversationList::none);
    CHECK(r.add_placements[0].to == ConversationList::conversations);
    CHECK_FALSE(r.add_placements[0].after.has_value());

    // The update that follows it agrees, and now knows where the add put it.
    REQUIRE(r.placements.size() == 1);
    CHECK(r.placements[0].from == ConversationList::conversations);
    CHECK(r.placements[0].to == ConversationList::conversations);

    // Pinning a puts it above everything unpinned, so the next row to move sits after it rather
    // than at the top -- which is the case an anchor exists to express and a bare "moved to front"
    // could not.
    c->conversation(ida, await)->set_priority(3, await);
    r.placements.clear();

    deliver(*c, b, "second", from_epoch_ms(2000), "h2");
    sync(*c);

    REQUIRE(r.placements.size() == 1);
    CHECK(r.placements[0].from == ConversationList::conversations);
    CHECK(r.placements[0].to == ConversationList::conversations);
    REQUIRE(r.placements[0].after.has_value());
    CHECK(*r.placements[0].after == ida);
    CHECK(r.updated.back().id() == idb);
}

TEST_CASE("Client: a hidden row is given no position", "[client][signals]") {
    SenderKeys sender;
    Recorder r;
    TempClient c{r.handlers()};
    approve(*c, sender.session_id);
    auto id = ConversationId::dm(sender.session_id);

    deliver(*c, sender, "ping", from_epoch_ms(1000), "h1");
    sync(*c);
    c->conversation(id, await)->set_priority(-1, await);
    r.placements.clear();

    // Hidden is in neither list, so there is no gap to name.  Unset here means "do not place
    // this", not "place it first" -- which is why the two are different states.
    deliver(*c, sender, "pong", from_epoch_ms(2000), "h2");
    sync(*c);

    // Taken out of where it was and not put back: `to == none` is what hiding looks like, and
    // `from` still names the list it has to come out of.
    REQUIRE(r.placements.size() == 1);
    CHECK(r.placements[0].from == ConversationList::conversations);
    CHECK(r.placements[0].to == ConversationList::none);
}

TEST_CASE("Client: a request is placed in the request list", "[client][signals]") {
    SenderKeys stranger;
    Recorder r;
    TempClient c{r.handlers()};

    // Nobody approved: a stranger's first message is a request, so the position names that list.
    deliver(*c, stranger, "hello", from_epoch_ms(1000), "h1");
    sync(*c);

    // The add places it in the request list; nothing held it before.
    REQUIRE(r.add_placements.size() == 1);
    CHECK(r.add_placements[0].from == ConversationList::none);
    CHECK(r.add_placements[0].to == ConversationList::requests);
    CHECK_FALSE(r.add_placements[0].after.has_value());
}

TEST_CASE("Client: a removal says which list to take it out of", "[client][signals]") {
    SenderKeys sender;
    Recorder r;
    TempClient c{r.handlers()};
    approve(*c, sender.session_id);
    auto id = ConversationId::dm(sender.session_id);

    deliver(*c, sender, "ping", from_epoch_ms(1000), "h1");
    sync(*c);
    r.order.clear();

    // Deleting the contact removes the conversation row outright.  The list it was in has to come
    // from what the subscriber was last told, not from the database -- by the time this is
    // reported the row is already gone, so there is nothing left to look it up from.
    c->dm(id, await)->delete_contact(await);

    REQUIRE(r.removed.size() == 1);
    CHECK(r.removed[0] == id);
    REQUIRE(r.removed_from.size() == 1);
    CHECK(r.removed_from[0] == ConversationList::conversations);
}

TEST_CASE("Client: state is committed before the handler fires", "[client][signals]") {
    SenderKeys sender;
    std::optional<std::string> body_seen_from_handler;
    Client* self = nullptr;

    TempClient c{callbacks{.messages_added = [&](std::vector<Message>&& m) {
        // Waiting from inside a handler: the loop runs it inline, since it is already this thread.
        body_seen_from_handler = self->message(m.at(0).id, await)->body;
    }}};
    self = &*c;

    deliver(*c, sender, "readable already", from_epoch_ms(1000), "h1");
    CHECK(body_seen_from_handler == "readable already");
}

TEST_CASE("Client: a throwing handler is contained", "[client][signals]") {
    SenderKeys sender;
    TempClient c{callbacks{.messages_added = [](std::vector<Message>&&) {
        throw std::runtime_error{"deliberate"};
    }}};

    // The exception is caught and logged rather than escaping into Core's event loop, and the
    // message is stored regardless: a broken listener must not cost us data.
    CHECK_NOTHROW(deliver(*c, sender, "still fine", from_epoch_ms(1000), "h1"));
    CHECK(c->conversation(ConversationId::dm(sender.session_id), await)->messages(await).size() ==
          1);
}

TEST_CASE("Client: send status changes are reported as messages_updated", "[client][signals]") {
    Recorder r;
    TempClient c{r.handlers()};
    auto* net = attach_mock_network(c->core);

    constexpr auto peer =
            "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;

    // Only the peer's keys are answered, so only the recipient's copy is dispatched: the copy for
    // our own swarm stays waiting on our keys.  That is what makes the single update below the one
    // for `send_state` rather than for the sync copy's.
    TestHelper::seed_pfs_nak(c->core, peer);

    auto id = c->send_message(ConversationId::dm(peer), {.body = "hello"}, await);
    sync(*c);
    r.order.clear();
    r.msg_updated.clear();

    REQUIRE(accept_stores(*net) == 1);

    CHECK(r.order == std::vector<std::string>{"messages_updated"});
    REQUIRE(r.msg_updated.size() == 1);
    REQUIRE(r.msg_updated[0].size() == 1);
    CHECK(r.msg_updated[0][0].id == id);
    CHECK(r.msg_updated[0][0].send_state == SendState::sent);

    // The only store that landed was the recipient's, and that hash belongs to their swarm: it is
    // not something we could ever look up, so it is not recorded as ours.
    CHECK_FALSE(r.msg_updated[0][0].hash.has_value());
}

TEST_CASE("Client: priority orders the list and hides", "[client][convos]") {
    TempClient c;
    SenderKeys a, b, d;
    for (const auto& k : {a, b, d})
        approve(*c, k.session_id);

    // Three conversations, most recent first: d, b, a.
    deliver(*c, a, "first", from_epoch_ms(1000), "h1");
    deliver(*c, b, "second", from_epoch_ms(2000), "h2");
    deliver(*c, d, "third", from_epoch_ms(3000), "h3");
    sync(*c);

    auto ida = ConversationId::dm(a.session_id);
    auto idb = ConversationId::dm(b.session_id);
    auto idd = ConversationId::dm(d.session_id);

    auto ids = [&] {
        std::vector<ConversationId> out;
        for (const auto& convo : c->conversations(await))
            out.push_back(convo.id());
        return out;
    };
    CHECK(ids() == std::vector{idd, idb, ida});

    // Higher priority sorts first, regardless of recency.
    c->conversation(ida, await)->set_priority(1, await);
    CHECK(ids() == std::vector{ida, idd, idb});
    CHECK(c->conversation(ida, await)->priority() == 1);

    // A bigger number outranks a smaller one.
    c->conversation(idb, await)->set_priority(5, await);
    CHECK(ids() == std::vector{idb, ida, idd});

    // Equal priorities form a block that sorts among itself by recency: b is pinned alongside a but
    // is the more recently active of the two, so it leads.  d stays below both, unpinned.
    c->conversation(ida, await)->set_priority(5, await);
    CHECK(ids() == std::vector{idb, ida, idd});

    // Negative is hidden: gone from the list entirely rather than sorted last.
    c->conversation(idb, await)->set_priority(-1, await);
    CHECK(ids() == std::vector{ida, idd});

    // Still reachable by name, though: hidden is a statement about the list, and this is the only
    // way back to one.
    REQUIRE(c->conversation(idb, await).has_value());
    CHECK(c->conversation(idb, await)->priority() == -1);

    // ...and unhiding brings it back where its priority says.
    c->conversation(idb, await)->set_priority(0, await);
    CHECK(ids() == std::vector{ida, idd, idb});
}

TEST_CASE("Client: a priority change replaces the whole list", "[client][signals]") {
    SenderKeys a, b;
    Recorder r;
    TempClient c{r.handlers()};
    approve(*c, a.session_id);
    approve(*c, b.session_id);

    deliver(*c, a, "first", from_epoch_ms(1000), "h1");
    deliver(*c, b, "second", from_epoch_ms(2000), "h2");
    sync(*c);
    // Each delivery changed a row in the list, which reports the list, so what the setup sent is
    // cleared along with the order.
    r.order.clear();
    r.replaced.clear();

    c->conversation(ConversationId::dm(a.session_id), await)->set_priority(3, await);

    // Reported as a replacement, not as an update to the one conversation whose priority changed:
    // what moved is the list.  And the order alongside it, for this subscriber holding both
    // handlers: pinning moved every row that was above the pinned one.
    //
    // The conversation list only.  Priority moves a row within the list it is in and never between
    // the two, so the request list did not change and is not read.
    CHECK(r.order == std::vector<std::string>{"replaced"});
    REQUIRE(r.replaced.size() == 1);
    REQUIRE(r.replaced[0].size() == 2);
    CHECK(r.replaced[0][0].id() == ConversationId::dm(a.session_id));
    CHECK(r.replaced[0][0].priority() == 3);

    // Hiding removes it from the replacement list, which is how a subscriber learns it is gone.
    r.order.clear();
    r.replaced.clear();
    c->conversation(ConversationId::dm(a.session_id), await)->set_priority(-1, await);
    CHECK(r.order == std::vector<std::string>{"replaced"});
    REQUIRE(r.replaced.size() == 1);
    REQUIRE(r.replaced[0].size() == 1);
    CHECK(r.replaced[0][0].id() == ConversationId::dm(b.session_id));

    // Setting the same value again changes nothing, so it says nothing.
    r.order.clear();
    c->conversation(ConversationId::dm(a.session_id), await)->set_priority(-1, await);
    CHECK(r.order.empty());
}

TEST_CASE("Client: the two copies of a send report separately", "[client][send]") {
    TempClient c;
    auto* net = attach_mock_network(c->core);

    constexpr auto peer =
            "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;
    TestHelper::seed_pfs_nak(c->core, peer);
    TestHelper::seed_pfs_nak(c->core, own_sid(*c));

    auto id = c->send_message(ConversationId::dm(peer), {.body = "two ways"}, await);

    // Which swarm a store is bound for is the pubkey it names, so the two copies can be answered
    // independently and in either order.
    auto sent = stores(*net);
    REQUIRE(sent.size() == 2);

    auto my_hex = oxenc::to_hex(own_sid(*c));
    auto is_self = [&](const MockNetwork::SentRequest* r) {
        return store_body(*r)["pubkey"].get<std::string>() == my_hex;
    };
    auto to_peer = std::ranges::find_if_not(sent, is_self);
    auto to_self = std::ranges::find_if(sent, is_self);
    REQUIRE(to_peer != sent.end());
    REQUIRE(to_self != sent.end());

    // The recipient's copy lands; our own swarm has not answered yet.
    (*to_peer)->callback(true, false, 200, {}, "{}");
    CHECK(c->message(id, await)->send_state == SendState::sent);
    CHECK(c->message(id, await)->sync_send_state == SendState::sending);

    // The sync copy fails, which says nothing about whether the message arrived.
    (*to_self)->callback(false, false, 500, {}, "nope");
    CHECK(c->message(id, await)->send_state == SendState::sent);
    CHECK(c->message(id, await)->sync_send_state == SendState::failed);
}

TEST_CASE("Client: sending to ourselves stores once", "[client][send]") {
    TempClient c;
    auto* net = attach_mock_network(c->core);

    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    // Mirrors opening the conversation first, as a UI does, before sending into it.
    auto convo = c->open_dm(ConversationId::dm(me), await);
    CHECK(convo.id == ConversationId::dm(me));

    auto id = c->send_message(ConversationId::dm(me), {.body = "note to self"}, await);
    CHECK(c->message(id, await)->body == "note to self");
    CHECK(preview_body(*c->conversation(ConversationId::dm(me), await)) == "note to self");

    // One store reaching the swarm, not two: our own swarm is the recipient's, so the sync copy
    // would be the same store twice.
    CHECK(accept_stores(*net) == 1);

    // One swarm, so one send: there is no separate sync copy to have a state for.
    CHECK(c->message(id, await)->send_state.has_value());
    CHECK_FALSE(c->message(id, await)->sync_send_state.has_value());

    // That single store went to our own swarm, so its hash is one worth keeping.
    CHECK(c->message(id, await)->hash == store_hash_for(oxenc::to_hex(me)));
    CHECK(c->conversation(ConversationId::dm(me), await)->messages(await).size() == 1);

    // ...and when our own swarm hands it straight back on the next poll, which is what note to self
    // does, it must recognise its own message rather than storing a second copy.  What makes that
    // work is the msgid: the copy coming back carries the one we generated when sending, which is
    // exactly what a hash of the two copies could not do.
    auto ts = c->message(id, await)->timestamp;
    auto msgid = c->core.loop().call_get([&] {
        return c->core.database().conn().prepared_get<int64_t>(
                "SELECT msgid FROM messages WHERE id = ?", id);
    });
    SessionProtos::Content sent;
    sent.set_sigtimestamp(static_cast<uint64_t>(epoch_ms(ts)));
    sent.set_msgid(msgid);
    sent.mutable_datamessage()->set_body("note to self");
    sent.mutable_datamessage()->set_timestamp(static_cast<uint64_t>(epoch_ms(ts)));
    sent.mutable_datamessage()->set_synctarget(oxenc::to_hex(me));
    auto plaintext = sent.SerializeAsString();
    auto encoded = encode_dm_v1(
            std::as_bytes(std::span{plaintext}), self_keys(*c).ed_sk, ts, me, std::nullopt);
    core::SwarmMessage sm{encoded, "swarmhash", ts, from_epoch_ms(1'000'000'000'000)};
    c->core.loop().call_get([&] {
        c->core.receive_messages({&sm, 1}, config::Namespace::Default, true);
        return 0;
    });

    CHECK(c->conversation(ConversationId::dm(me), await)->messages(await).size() == 1);
}
