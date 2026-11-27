#include "config_helpers.hpp"

// The two ways a subscriber can keep the conversation lists -- by placements alone, or by whole
// lists alone -- each followed from an empty start through every event a Client sends, and both
// held to what `conversations()` and `message_requests()` say after each change.

namespace {

std::vector<ConversationId> ids_of(const std::vector<AnyConversation>& list) {
    std::vector<ConversationId> out;
    for (const auto& convo : list)
        out.push_back(convo.id());
    return out;
}

/// Both lists, kept the two ways from one Recorder's events.
struct Kept {
    // By placements: each applied in the order it arrived, and nothing else.
    std::vector<ConversationId> convos, requests;
    // By whole lists: the last one each handler was sent, and nothing else.
    std::vector<ConversationId> whole_convos, whole_requests;

    void catch_up(const Recorder& r) {
        for (; at < r.order.size(); at++) {
            const auto& what = r.order[at];
            if (what == "added") {
                place(r.added[added].id(), r.add_placements[added]);
                added++;
            } else if (what == "updated") {
                place(r.updated[updated].id(), r.placements[updated]);
                updated++;
            } else if (what == "removed") {
                take(r.removed[removed], r.removed_from[removed]);
                removed++;
            } else if (what == "replaced") {
                whole_convos = ids_of(r.replaced[replaced++]);
            } else if (what == "requests") {
                whole_requests = ids_of(r.requests_replaced[requests_replaced++]);
            }
        }
    }

  private:
    size_t at = 0, added = 0, updated = 0, removed = 0, replaced = 0, requests_replaced = 0;

    std::vector<ConversationId>& list(ConversationList which) {
        return which == ConversationList::requests ? requests : convos;
    }

    // `from` is what this subscriber was last told, and it has been told everything since the
    // start, so the row has to be exactly there.
    void take(const ConversationId& id, ConversationList from) {
        if (from != ConversationList::none)
            CHECK(std::ranges::find(list(from), id) != list(from).end());
        std::erase(convos, id);
        std::erase(requests, id);
        CHECK(std::ranges::find(list(ConversationList::conversations), id) == convos.end());
    }

    void place(const ConversationId& id, const ListPlacement& p) {
        take(id, p.from);
        if (p.to == ConversationList::none) {
            CHECK_FALSE(p.after.has_value());
            return;
        }
        auto& into = list(p.to);
        auto at = into.begin();
        if (p.after) {
            at = std::ranges::find(into, *p.after);
            // An anchor this subscriber does not hold is exactly what ordering the batch prevents.
            REQUIRE(at != into.end());
            ++at;
        }
        into.insert(at, id);
    }
};

/// Settles the Client, catches up on what it sent, and holds both ways to the lists as they are.
void check_kept(Kept& kept, const Recorder& r, Client& c) {
    sync(c);
    kept.catch_up(r);
    auto convos = ids_of(c.conversations(await));
    auto requests = ids_of(c.message_requests(await));
    CHECK(kept.convos == convos);
    CHECK(kept.requests == requests);
    CHECK(kept.whole_convos == convos);
    CHECK(kept.whole_requests == requests);
}

std::string hex_id(char fill) {
    return "05" + std::string(64, fill);
}

}  // namespace

TEST_CASE(
        "Client: messages, a request and its approval keep both ways in step",
        "[client][signals]") {
    SenderKeys a, b, stranger;
    Recorder r;
    TempClient c{r.handlers()};
    Kept kept;
    approve(*c, a.session_id);
    approve(*c, b.session_id);

    deliver(*c, a, "first", from_epoch_ms(1000), "h1");
    check_kept(kept, r, *c);
    deliver(*c, b, "second", from_epoch_ms(2000), "h2");
    check_kept(kept, r, *c);
    deliver(*c, stranger, "let me in", from_epoch_ms(3000), "h3");
    check_kept(kept, r, *c);
    REQUIRE(kept.requests.size() == 1);

    // Back to the top of the list on new activity.
    deliver(*c, a, "third", from_epoch_ms(4000), "h4");
    check_kept(kept, r, *c);
    CHECK(kept.convos.front() == ConversationId::dm(a.session_id));

    // Writing back approves the stranger: one placement takes it out of the requests and puts it
    // into the conversations.
    c->send_message(ConversationId::dm(stranger.session_id), {.body = "come in"}, await);
    check_kept(kept, r, *c);
    CHECK(kept.requests.empty());
    CHECK(kept.convos.front() == ConversationId::dm(stranger.session_id));
}

TEST_CASE("Client: pins, hides and deletions are placements too", "[client][signals]") {
    SenderKeys a, b, d;
    Recorder r;
    TempClient c{r.handlers()};
    Kept kept;
    for (const auto& k : {a, b, d})
        approve(*c, k.session_id);
    auto ida = ConversationId::dm(a.session_id);
    auto idb = ConversationId::dm(b.session_id);
    auto idd = ConversationId::dm(d.session_id);

    deliver(*c, a, "first", from_epoch_ms(1000), "h1");
    deliver(*c, b, "second", from_epoch_ms(2000), "h2");
    deliver(*c, d, "third", from_epoch_ms(3000), "h3");
    check_kept(kept, r, *c);
    CHECK(kept.convos == std::vector{idd, idb, ida});

    c->conversation(ida, await)->set_priority(1, await);
    check_kept(kept, r, *c);
    CHECK(kept.convos == std::vector{ida, idd, idb});

    c->conversation(ida, await)->set_priority(0, await);
    check_kept(kept, r, *c);
    CHECK(kept.convos == std::vector{idd, idb, ida});

    // Hidden is in neither list, so its placement only takes it out.
    c->conversation(idb, await)->set_priority(-1, await);
    check_kept(kept, r, *c);
    CHECK(kept.convos == std::vector{idd, ida});

    c->conversation(idb, await)->set_priority(0, await);
    check_kept(kept, r, *c);
    CHECK(kept.convos == std::vector{idd, idb, ida});

    // Deleting a conversation hides it; deleting the contact removes it outright.
    c->conversation(idd, await)->delete_conversation(true, await);
    check_kept(kept, r, *c);
    CHECK(kept.convos == std::vector{idb, ida});

    c->dm(ida, await)->delete_contact(await);
    check_kept(kept, r, *c);
    CHECK(kept.convos == std::vector{idb});
}

TEST_CASE(
        "Client: note to self's priority from another device is a placement", "[client][signals]") {
    SenderKeys a;
    Recorder r;
    TempClient c{r.handlers()};
    Kept kept;
    approve(*c, a.session_id);
    deliver(*c, a, "first", from_epoch_ms(1000), "h1");
    c->send_message(self_convo(*c), {.body = "a note"}, await);
    check_kept(kept, r, *c);
    REQUIRE(kept.convos.size() == 2);

    // Pinned elsewhere, then hidden elsewhere.
    merge_profile(*c, profile_from_another_device(*c, [](config::UserProfile& p) {
        p.set_nts_priority(5);
    }));
    check_kept(kept, r, *c);
    CHECK(kept.convos.front() == self_convo(*c));

    merge_profile(*c, profile_from_another_device(*c, [](config::UserProfile& p) {
        p.set_nts_priority(-1);
    }));
    check_kept(kept, r, *c);
    CHECK(kept.convos == std::vector{ConversationId::dm(a.session_id)});
}

TEST_CASE(
        "Client: a merge that pins, unpins, hides, adds and removes at once is placed in order",
        "[client][signals]") {
    Recorder r;
    TempClient c{r.handlers()};
    Kept kept;

    // Six contacts, made by another device, each with its own age so the list's order is fixed:
    // newest first, with a pinned and the hidden d leading and missing respectively.
    const std::string ha = hex_id('a'), hb = hex_id('b'), hc = hex_id('c'), hd = hex_id('d'),
                      he = hex_id('e'), hf = hex_id('f');
    auto set = [](config::Contacts& theirs, const std::string& hex, int priority, int64_t created) {
        auto entry = theirs.get_or_construct(hex);
        entry.approved = true;
        entry.priority = priority;
        entry.created = created;
        theirs.set(entry);
    };
    merge_contacts(*c, contacts_update_from_another_device(*c, [&](config::Contacts& theirs) {
        set(theirs, ha, 2, 1'700'000'100);
        set(theirs, hb, 0, 1'700'000'200);
        set(theirs, hc, 0, 1'700'000'300);
        set(theirs, hd, -1, 1'700'000'400);
        set(theirs, hf, 0, 1'700'000'500);
    }));
    check_kept(kept, r, *c);
    auto ida = dm_from_hex(ha), idb = dm_from_hex(hb), idc = dm_from_hex(hc), idd = dm_from_hex(hd),
         ide = dm_from_hex(he), idf = dm_from_hex(hf);
    CHECK(kept.convos == std::vector{ida, idf, idc, idb});

    // One merge: b pinned above everything, a unpinned, c hidden, d unhidden, e new and pinned
    // below b, f gone.  Several rows move at once, and some of them are each other's anchors.
    merge_contacts(*c, contacts_update_from_another_device(*c, [&](config::Contacts& theirs) {
        set(theirs, hb, 9, 1'700'000'200);
        set(theirs, ha, 0, 1'700'000'100);
        set(theirs, hc, -1, 1'700'000'300);
        set(theirs, hd, 0, 1'700'000'400);
        set(theirs, he, 4, 1'700'000'600);
        theirs.erase(hf);
    }));
    check_kept(kept, r, *c);
    CHECK(kept.convos == std::vector{idb, ide, idd, ida});
}
