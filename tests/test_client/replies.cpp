#include "common.hpp"

namespace {

/// Adds a quote naming `author` at `ts`, optionally with the target's msgid.
auto quoting(const b33& author, sys_ms ts, std::optional<int64_t> msgid = std::nullopt) {
    return [author, ts, msgid](SessionProtos::DataMessage& d) {
        auto* q = d.mutable_quote();
        q->set_msgtimestamp(static_cast<uint64_t>(ts.time_since_epoch().count()));
        q->set_author(oxenc::to_hex(author.begin(), author.end()));
        if (msgid)
            q->set_msgid(*msgid);
    };
}

}  // namespace

TEST_CASE("Client: a reply names what it answers", "[client][replies]") {
    TempClient c;
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);

    auto first = from_epoch_ms(1000);
    deliver(*c, peer, "the original", first, "h1", "", std::nullopt, nullptr, 7777);
    deliver(*c,
            peer,
            "the answer",
            from_epoch_ms(2000),
            "h2",
            "",
            std::nullopt,
            quoting(peer.session_id, first, 7777));
    sync(*c);

    auto msgs = c->conversation(convo, await)->messages(await);
    REQUIRE(msgs.size() == 2);
    // Newest first.
    const auto& answer = msgs[0];
    const auto& original = msgs[1];

    REQUIRE(answer.reply);
    CHECK(answer.reply->author == peer.session_id);
    CHECK(answer.reply->timestamp == first);
    REQUIRE(answer.reply->message_id.has_value());
    CHECK(*answer.reply->message_id == original.id);

    // The original is not itself a reply -- unset means "not a reply", which is a different
    // statement from an unresolved reference.
    CHECK_FALSE(original.reply.has_value());
}

TEST_CASE(
        "Client: a reply to a message we do not have still names its author", "[client][replies]") {
    TempClient c;
    SenderKeys peer;

    auto missing = from_epoch_ms(500);
    deliver(*c,
            peer,
            "answering something we never got",
            from_epoch_ms(2000),
            "h1",
            "",
            std::nullopt,
            quoting(peer.session_id, missing, 4242));
    sync(*c);

    auto msgs = c->conversation(ConversationId::dm(peer.session_id), await)->messages(await);
    REQUIRE(msgs.size() == 1);
    REQUIRE(msgs[0].reply);
    // Unresolved, but the author and timestamp came off the wire, so a client can still say who
    // was replied to over an "original message not found" line.
    CHECK_FALSE(msgs[0].reply->message_id.has_value());
    CHECK(msgs[0].reply->author == peer.session_id);
    CHECK(msgs[0].reply->timestamp == missing);
}

TEST_CASE("Client: a reply resolves once its target arrives", "[client][replies]") {
    TempClient c;
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);

    // Out of order: the answer first.  This is the case that makes resolving-on-read necessary
    // rather than merely tidy -- resolved once at receipt, this reference would stay empty forever.
    auto first = from_epoch_ms(1000);
    deliver(*c,
            peer,
            "the answer",
            from_epoch_ms(2000),
            "h2",
            "",
            std::nullopt,
            quoting(peer.session_id, first, 7777));
    sync(*c);

    auto msgs = c->conversation(convo, await)->messages(await);
    REQUIRE(msgs.size() == 1);
    REQUIRE(msgs[0].reply);
    REQUIRE_FALSE(msgs[0].reply->message_id.has_value());

    deliver(*c, peer, "the original", first, "h1", "", std::nullopt, nullptr, 7777);
    sync(*c);

    msgs = c->conversation(convo, await)->messages(await);
    REQUIRE(msgs.size() == 2);
    REQUIRE(msgs[0].reply);
    REQUIRE(msgs[0].reply->message_id.has_value());
    CHECK(*msgs[0].reply->message_id == msgs[1].id);
}

TEST_CASE("Client: msgid disambiguates a same-millisecond target", "[client][replies]") {
    TempClient c;
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);

    // Two messages from one sender stamped identically: exactly what msgid exists for.
    auto same = from_epoch_ms(1000);
    deliver(*c, peer, "first", same, "h1", "", std::nullopt, nullptr, 111);
    deliver(*c, peer, "second", same, "h2", "", std::nullopt, nullptr, 222);
    deliver(*c,
            peer,
            "answering the second",
            from_epoch_ms(2000),
            "h3",
            "",
            std::nullopt,
            quoting(peer.session_id, same, 222));
    sync(*c);

    auto msgs = c->conversation(convo, await)->messages(await);
    REQUIRE(msgs.size() == 3);

    int64_t second_id = 0;
    for (const auto& m : msgs)
        if (m.body == "second")
            second_id = m.id;
    REQUIRE(second_id != 0);

    REQUIRE(msgs[0].reply);
    REQUIRE(msgs[0].reply->message_id.has_value());
    CHECK(*msgs[0].reply->message_id == second_id);
}

TEST_CASE("Client: an ambiguous target resolves stably", "[client][replies]") {
    TempClient c;
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);

    // No msgid on the quote: the wire cannot say which of the two was meant, so we pick the lowest
    // id.  Arbitrary, but the same answer on every read, which is what matters to a display.
    auto same = from_epoch_ms(1000);
    deliver(*c, peer, "first", same, "h1", "", std::nullopt, nullptr, 111);
    deliver(*c, peer, "second", same, "h2", "", std::nullopt, nullptr, 222);
    deliver(*c,
            peer,
            "answering one of them",
            from_epoch_ms(2000),
            "h3",
            "",
            std::nullopt,
            quoting(peer.session_id, same));
    sync(*c);

    auto msgs = c->conversation(convo, await)->messages(await);
    REQUIRE(msgs.size() == 3);
    REQUIRE(msgs[0].reply);
    REQUIRE(msgs[0].reply->message_id.has_value());
    auto picked = *msgs[0].reply->message_id;

    auto again = c->conversation(convo, await)->messages(await);
    REQUIRE(again[0].reply->message_id == picked);

    // And it is one of the two candidates, not something else.
    CHECK((again[1].id == picked || again[2].id == picked));
}

TEST_CASE("Client: a quote with an unusable author is dropped", "[client][replies]") {
    TempClient c;
    SenderKeys peer;

    auto target = from_epoch_ms(1000);
    deliver(*c, peer, "the original", target, "h0", "", std::nullopt, nullptr, 999);
    deliver(*c,
            peer,
            "body survives",
            from_epoch_ms(2000),
            "h1",
            "",
            std::nullopt,
            [](SessionProtos::DataMessage& d) {
                auto* q = d.mutable_quote();
                q->set_msgtimestamp(1000);
                q->set_author("not a session id");
            });
    // A well-formed one alongside it, so that "no reply" here means the bad reference was rejected
    // rather than that nothing writes references at all.
    deliver(*c,
            peer,
            "a good reply",
            from_epoch_ms(3000),
            "h2",
            "",
            std::nullopt,
            quoting(peer.session_id, target, 999));
    sync(*c);

    auto msgs = c->conversation(ConversationId::dm(peer.session_id), await)->messages(await);
    REQUIRE(msgs.size() == 3);

    auto by_body = [&](std::string_view b) -> const Message& {
        auto it = std::ranges::find_if(msgs, [&](const Message& m) { return m.body == b; });
        REQUIRE(it != msgs.end());
        return *it;
    };

    // The message carrying the bad quote is kept; only the unusable reference is discarded.
    CHECK_FALSE(by_body("body survives").reply.has_value());
    CHECK(by_body("a good reply").reply.has_value());
}

TEST_CASE("Client: a reply is re-reported when its target arrives", "[client][replies]") {
    Recorder rec;
    TempClient c{rec.handlers()};
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);

    auto target_ts = from_epoch_ms(1000);
    deliver(*c,
            peer,
            "the answer",
            from_epoch_ms(2000),
            "h2",
            "",
            std::nullopt,
            quoting(peer.session_id, target_ts, 7777));
    sync(*c);

    auto arrivals = Recorder::messages(rec.msg_added);
    REQUIRE(arrivals.size() == 1);
    auto reply_id = arrivals[0].id;
    REQUIRE_FALSE(arrivals[0].reply->message_id.has_value());
    rec.msg_updated.clear();

    // The target lands afterwards.  Nothing about the reply's own row changes, but what it resolves
    // to does -- and a display holding it has no way to know that without being told.
    deliver(*c, peer, "the original", target_ts, "h1", "", std::nullopt, nullptr, 7777);
    sync(*c);

    auto changed = Recorder::messages(rec.msg_updated);
    auto reported =
            std::ranges::find_if(changed, [&](const Message& m) { return m.id == reply_id; });
    REQUIRE(reported != changed.end());
    REQUIRE(reported->reply);
    CHECK(reported->reply->message_id.has_value());
}

TEST_CASE("Client: deleting a target re-reports the replies to it", "[client][replies]") {
    Recorder rec;
    TempClient c{rec.handlers()};
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);

    auto target_ts = from_epoch_ms(1000);
    deliver(*c, peer, "the original", target_ts, "h1", "", std::nullopt, nullptr, 7777);
    deliver(*c,
            peer,
            "the answer",
            from_epoch_ms(2000),
            "h2",
            "",
            std::nullopt,
            quoting(peer.session_id, target_ts, 7777));
    sync(*c);

    auto msgs = c->conversation(convo, await)->messages(await);
    REQUIRE(msgs.size() == 2);
    auto reply_id = msgs[0].id;
    auto target_id = msgs[1].id;
    rec.msg_updated.clear();

    c->delete_message(target_id, await);
    sync(*c);

    // The target itself is reported, and so is the reply that points at it: what it should draw
    // has changed even though its own row has not.
    auto changed = Recorder::messages(rec.msg_updated);
    CHECK(std::ranges::any_of(changed, [&](const Message& m) { return m.id == target_id; }));
    CHECK(std::ranges::any_of(changed, [&](const Message& m) { return m.id == reply_id; }));
}

TEST_CASE("Client: a reply carries the message it answers", "[client][replies]") {
    TempClient c;
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);

    auto first = from_epoch_ms(1000);
    deliver(*c, peer, "what was said", first, "h1", "", std::nullopt, nullptr, 7777);
    deliver(*c,
            peer,
            "the answer",
            from_epoch_ms(2000),
            "h2",
            "",
            std::nullopt,
            quoting(peer.session_id, first, 7777));
    sync(*c);

    auto msgs = c->conversation(convo, await)->messages(await);
    REQUIRE(msgs.size() == 2);
    REQUIRE(msgs[0].reply);
    REQUIRE(msgs[0].reply->message);

    // The whole message, not a summary of it: a caller drawing a reply line needs whatever it
    // needs, and that is not knowable from here.
    const auto& target = *msgs[0].reply->message;
    CHECK(target.id == msgs[1].id);
    CHECK(target.body == "what was said");
    CHECK(target.sender == peer.session_id);
    CHECK(target.timestamp == first);
}

TEST_CASE("Client: a window and a newer page carry what replies answer", "[client][replies]") {
    TempClient c;
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);

    auto first = from_epoch_ms(1000);
    deliver(*c, peer, "what was said", first, "h1", "", std::nullopt, nullptr, 7777);
    deliver(*c,
            peer,
            "the answer",
            from_epoch_ms(2000),
            "h2",
            "",
            std::nullopt,
            quoting(peer.session_id, first, 7777));
    sync(*c);

    auto original = c->conversation(convo, await)->messages(await).at(1);
    REQUIRE(original.body == "what was said");

    auto window = c->conversation(convo, await)->messages_around(original.id, 1, 1, await);
    REQUIRE(window.size() == 2);
    REQUIRE(window[0].reply);
    REQUIRE(window[0].reply->message);
    CHECK(window[0].reply->message->body == "what was said");

    auto newer = c->conversation(convo, await)
                         ->messages({.limit = 1, .after = original.cursor()}, await);
    REQUIRE(newer.size() == 1);
    REQUIRE(newer[0].reply);
    REQUIRE(newer[0].reply->message);
    CHECK(newer[0].reply->message->id == original.id);
}

TEST_CASE("Client: a quoted attachment-only message arrives whole", "[client][replies]") {
    TempClient c;
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);

    // No body at all: exactly the case a body-only summary could not draw.
    auto first = from_epoch_ms(1000);
    deliver(
            *c,
            peer,
            "",
            first,
            "h1",
            "",
            std::nullopt,
            [](SessionProtos::DataMessage& d) {
                auto* a = d.add_attachments();
                a->set_id(1);
                a->set_url("http://fs.example/file/1#d");
                a->set_key(std::string(32, 'k'));
                a->set_contenttype("image/png");
                a->set_filename("photo.png");
            },
            7777);
    deliver(*c,
            peer,
            "nice one",
            from_epoch_ms(2000),
            "h2",
            "",
            std::nullopt,
            quoting(peer.session_id, first, 7777));
    sync(*c);

    auto msgs = c->conversation(convo, await)->messages(await);
    REQUIRE(msgs.size() == 2);
    REQUIRE(msgs[0].reply);
    REQUIRE(msgs[0].reply->message);

    const auto& target = *msgs[0].reply->message;
    CHECK(target.body.empty());
    REQUIRE(target.attachments.size() == 1);
    CHECK(target.attachments[0].filename == "photo.png");
    // Derived on the nested message too, not left at its default.
    CHECK(target.gallery_viewable);
}

TEST_CASE("Client: reply loading stops one level down", "[client][replies]") {
    TempClient c;
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);

    // A chain: A <- B <- C.  Reading C must give B, and B must name A without carrying it.
    auto a_ts = from_epoch_ms(1000);
    auto b_ts = from_epoch_ms(2000);
    deliver(*c, peer, "A", a_ts, "h1", "", std::nullopt, nullptr, 111);
    deliver(*c, peer, "B", b_ts, "h2", "", std::nullopt, quoting(peer.session_id, a_ts, 111), 222);
    deliver(*c,
            peer,
            "C",
            from_epoch_ms(3000),
            "h3",
            "",
            std::nullopt,
            quoting(peer.session_id, b_ts, 222));
    sync(*c);

    auto msgs = c->conversation(convo, await)->messages(await);
    REQUIRE(msgs.size() == 3);
    const auto& cmsg = msgs[0];

    REQUIRE(cmsg.reply);
    REQUIRE(cmsg.reply->message);
    CHECK(cmsg.reply->message->body == "B");

    // B is itself a reply, and says so -- but the payload stops here, which is what keeps a read
    // from walking a chain of unbounded length.  The id is still there to ask with.
    const auto& nested = *cmsg.reply->message;
    REQUIRE(nested.reply);
    CHECK(nested.reply->author == peer.session_id);
    CHECK(nested.reply->timestamp == a_ts);
    CHECK(nested.reply->message_id.has_value());
    CHECK(nested.reply->message == nullptr);
}

TEST_CASE("Client: several replies to one message share one copy", "[client][replies]") {
    TempClient c;
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);

    auto first = from_epoch_ms(1000);
    deliver(*c, peer, "the original", first, "h1", "", std::nullopt, nullptr, 7777);
    deliver(*c,
            peer,
            "answer one",
            from_epoch_ms(2000),
            "h2",
            "",
            std::nullopt,
            quoting(peer.session_id, first, 7777));
    deliver(*c,
            peer,
            "answer two",
            from_epoch_ms(3000),
            "h3",
            "",
            std::nullopt,
            quoting(peer.session_id, first, 7777));
    sync(*c);

    auto msgs = c->conversation(convo, await)->messages(await);
    REQUIRE(msgs.size() == 3);
    REQUIRE(msgs[0].reply);
    REQUIRE(msgs[1].reply);
    REQUIRE(msgs[0].reply->message);

    // One read, one payload: the pointers are the same object, not two copies of it.
    CHECK(msgs[0].reply->message == msgs[1].reply->message);
}

TEST_CASE("Client: many distinct reply targets load correctly", "[client][replies]") {
    TempClient c;
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);

    // More distinct targets than the lookup caches a statement for, so this exercises the one-off
    // statement branch as well as the binding of a longer placeholder list.
    constexpr int n = 6;
    std::vector<sys_ms> stamps;
    for (int i = 0; i < n; i++) {
        auto ts = from_epoch_ms(1000 + i);
        stamps.push_back(ts);
        deliver(*c,
                peer,
                "original {}"_format(i),
                ts,
                "o{}"_format(i),
                "",
                std::nullopt,
                nullptr,
                100 + i);
    }
    for (int i = 0; i < n; i++)
        deliver(*c,
                peer,
                "answer {}"_format(i),
                from_epoch_ms(5000 + i),
                "a{}"_format(i),
                "",
                std::nullopt,
                quoting(peer.session_id, stamps[i], 100 + i));
    sync(*c);

    auto msgs = c->conversation(convo, await)->messages(await);
    REQUIRE(msgs.size() == 2 * n);

    // Every answer resolved, and each to its *own* target rather than all to one of them -- which
    // is what a mis-bound placeholder list would produce.
    int checked = 0;
    for (const auto& m : msgs) {
        if (!m.body.starts_with("answer "))
            continue;
        auto which = m.body.substr(7);
        REQUIRE(m.reply);
        REQUIRE(m.reply->message);
        CHECK(m.reply->message->body == "original {}"_format(which));
        checked++;
    }
    CHECK(checked == n);
}

TEST_CASE("Client: a sent reply names what it answers", "[client][replies][send]") {
    TempClient c;
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);
    auto convo = ConversationId::dm(me);

    auto first = c->send_message(convo, {.body = "the original"}, await);
    auto second = c->send_message(convo, {.body = "answering", .reply_to = first}, await);
    sync(*c);

    auto msg = c->message(second, await);
    REQUIRE(msg);
    REQUIRE(msg->reply);
    CHECK(msg->reply->author == me);
    REQUIRE(msg->reply->message_id.has_value());
    CHECK(*msg->reply->message_id == first);

    // Our own reply resolves through the same rule as an incoming one, so the message comes with
    // it rather than only the reference.
    REQUIRE(msg->reply->message);
    CHECK(msg->reply->message->body == "the original");
}

TEST_CASE("Client: a sent reply puts a quote on the wire", "[client][replies][send]") {
    TempClient c;
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);
    auto convo = ConversationId::dm(me);

    auto first = c->send_message(convo, {.body = "the original"}, await);
    auto second = c->send_message(convo, {.body = "answering", .reply_to = first}, await);
    sync(*c);

    // What was stored is what goes out, so the wire form is checkable from the raw content.
    auto dump = c->message_debug(second, await);
    REQUIRE(dump);
    CHECK(dump->find("quote") != std::string::npos);
    CHECK(dump->find("msgTimestamp") != std::string::npos);
    // The snippet is deliberately absent: current clients do not send one, and one that arrives
    // would not be trusted.
    CHECK(dump->find("text") == std::string::npos);
}

TEST_CASE("Client: reply_to must name a message in this conversation", "[client][replies][send]") {
    TempClient c;
    SenderKeys peer;
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto mine = c->send_message(ConversationId::dm(me), {.body = "a note"}, await);

    // Nonexistent, and in another conversation: both are caller error, and both are refused on the
    // calling thread rather than accepted and then silently dropped.
    CHECK_THROWS_AS(
            c->send_message(ConversationId::dm(me), {.body = "x", .reply_to = 999999}, await),
            std::invalid_argument);

    c->open_dm(ConversationId::dm(peer.session_id), await);
    TestHelper::seed_pfs_nak(c->core, peer.session_id);
    CHECK_THROWS_AS(
            c->send_message(
                    ConversationId::dm(peer.session_id), {.body = "x", .reply_to = mine}, await),
            std::invalid_argument);
}
