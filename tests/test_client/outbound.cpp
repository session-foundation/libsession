#include <mutex>

#include "common.hpp"

// ── Outbound activity ───────────────────────────────────────────────────────────────────────────
//
// What a platform holds the process alive on when the app goes to the background.  Every test here
// starts from a Client with nothing outstanding -- its account's configs pushed and confirmed, and
// the peer already a contact, so that sending to them changes no config -- so that what it sees is
// the work it caused and nothing else.

namespace {

constexpr auto PEER = "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;

/// Every `outbound_changed` report, in order.  Handlers run on Core's loop and a test reads from
/// its own thread, hence the lock.
struct OutboundLog {
    std::mutex m;
    std::vector<bool> reports;

    callbacks handlers() {
        return {.outbound_changed = [this](bool busy) {
            std::lock_guard l{m};
            reports.push_back(busy);
        }};
    }

    std::vector<bool> seen() {
        std::lock_guard l{m};
        return reports;
    }

    void clear() {
        std::lock_guard l{m};
        reports.clear();
    }

    /// The last report, which is what `outbound_busy()` should agree with; false before any.
    bool last() {
        std::lock_guard l{m};
        return !reports.empty() && reports.back();
    }
};

/// A MockNetwork whose file server holds every upload until told to let it finish, so that a test
/// can look at a send while its attachment is still going up.
struct HeldUploads : MockNetwork {
    struct Held {
        network::FileUploadRequest request;
        std::vector<std::byte> seed;
    };
    std::vector<Held> held;

    void upload_file(network::FileUploadRequest request, std::span<const std::byte> seed) override {
        held.push_back({std::move(request), {seed.begin(), seed.end()}});
    }

    /// Completes every held upload, on Core's loop where a real completion is handled.
    size_t release() {
        auto pending = std::exchange(held, {});
        for (auto& h : pending)
            core->call_get([&] { MockNetwork::upload_file(std::move(h.request), h.seed); });
        return pending.size();
    }
};

/// Answers every config push the network has been handed as the swarm would, every store kept --
/// or, with `accepted` false, refuses them all.
size_t answer_config_pushes(MockNetwork& net, bool accepted = true) {
    static int next_hash = 0;
    return answer_requests(net, "sequence", [accepted](MockNetwork::SentRequest& r) {
        if (!accepted)
            return r.callback(false, false, 500, {}, "nope");
        auto subs = parse_json(*r.request.body)["requests"];
        auto results = nlohmann::json::array();
        for (size_t i = 0; i < subs.size(); i++)
            results.push_back(
                    {{"code", 200}, {"body", {{"hash", "config{}"_format(next_hash++)}}}});
        r.callback(true, false, 200, {}, nlohmann::json{{"results", results}}.dump());
    });
}

bool push_pending(Client& c) {
    return in_configs(c, [](core::Configs& cf) { return cf.push_pending(); });
}

/// Sends whatever config push is owed now rather than after the debounce, and stops at that: the
/// request is left on the wire for the test to answer.
void push_configs_now(Client& c) {
    in_configs(c, [](core::Configs& cf) {
        TestHelper::backdate_push_state(cf, 1h, 1h);
        TestHelper::push_if_due(cf);
    });
}

/// Pushes and confirms whatever configs are owed, so that nothing is outstanding.
void settle_configs(Client& c, MockNetwork& net) {
    // Twice, because a confirmed push can leave something owed: anything changed while it was out.
    for (int i = 0; i < 2; i++) {
        sync(c);
        push_configs_now(c);
        answer_config_pushes(net);
    }
    REQUIRE_FALSE(push_pending(c));
}

/// Makes `sid` an approved contact with a conversation, in the tables and in the config alike, so
/// that writing to them or hearing from them changes nothing that has to be pushed.
void befriend(Client& c, const b33& sid) {
    approve(c, sid);
    c.open_dm(ConversationId::dm(sid), await);
    TestHelper::sync_contact(c, ConversationId::dm(sid));
}

/// The starting point every test below wants: a network, the peer a contact the config already
/// knows, PFS keys answered for both swarms, and nothing owed.  Leaves `peer_keys` unanswered when
/// false, so that a send to them has to wait for a key fetch.
template <typename Net = MockNetwork>
Net* quiet_start(TempClient& c, bool peer_keys = true) {
    auto owned = std::make_unique<Net>();
    auto* net = owned.get();
    net->core = &c->core;
    c->core.set_network(std::move(owned));

    if (peer_keys)
        TestHelper::seed_pfs_nak(c->core, PEER);
    TestHelper::seed_pfs_nak(c->core, own_sid(*c));
    b33 peer;
    std::ranges::copy(PEER, peer.begin());
    befriend(*c, peer);
    settle_configs(*c, *net);
    net->sent_requests.clear();
    return net;
}

/// How to answer the two stores of a send, split by destination.  Held by value, so that they
/// outlive the network's list of what it was sent.
struct Copies {
    network::network_response_callback_t to_peer, to_self;
};
Copies copies(Client& c, MockNetwork& net) {
    Copies out;
    auto my_hex = oxenc::to_hex(own_sid(c));
    for (auto* r : stores(net))
        (store_body(*r)["pubkey"].get<std::string>() == my_hex ? out.to_self : out.to_peer) =
                r->callback;
    REQUIRE(out.to_peer);
    REQUIRE(out.to_self);
    return out;
}

/// A small file to attach, removed when the test ends.
struct TempFile {
    std::filesystem::path path{
            std::filesystem::temp_directory_path() / random::unique_id("test_outbound", 7)};
    TempFile() { std::ofstream{path, std::ios::binary} << "an attachment"; }
    ~TempFile() {
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
};

}  // namespace

TEST_CASE("Client: outbound is idle at start", "[client][outbound]") {
    // The first run of an account is not idle -- it owes the swarm its defaults -- so this is the
    // second, once they have been published.
    OutboundLog first;
    TempClient c{first.handlers()};
    quiet_start(c);
    sync(*c);
    REQUIRE(first.seen() == std::vector{true, false});

    OutboundLog log;
    c.reopen(log.handlers());

    CHECK_FALSE(c->outbound_busy());
    sync(*c);
    // Idle is where a Client starts, so it is not reported: a handler first hears when that stops.
    CHECK(log.seen().empty());
}

TEST_CASE("Client: outbound is busy from the start when a push is owed", "[client][outbound]") {
    // A new account owes the swarm its defaults from the moment it exists, and the constructor is
    // where it comes into being.
    OutboundLog log;
    TempClient c{log.handlers()};

    CHECK(c->outbound_busy());
    sync(*c);
    CHECK(log.seen() == std::vector{true});
}

TEST_CASE("Client: outbound covers a send until it is sent", "[client][outbound]") {
    OutboundLog log;
    TempClient c{log.handlers()};
    // No keys known for the peer, so the send waits on a fetch for them: pending, before sending.
    auto* net = quiet_start(c, /*peer_keys=*/false);
    log.clear();

    auto id = c->send_message(ConversationId::dm(PEER), {.body = "hello"}, await);
    REQUIRE(c->message(id, await)->send_state == SendState::pending);
    CHECK(c->outbound_busy());

    // The fetch comes back empty, which releases the send to go out unencrypted for PFS.
    fail_retrieves(*net);
    REQUIRE(c->message(id, await)->send_state == SendState::sending);
    CHECK(c->outbound_busy());

    CHECK(accept_stores(*net) == 2);
    REQUIRE(c->message(id, await)->send_state == SendState::sent);
    CHECK_FALSE(c->outbound_busy());

    sync(*c);
    CHECK(log.seen() == std::vector{true, false});
}

TEST_CASE("Client: outbound ends when a send fails", "[client][outbound]") {
    OutboundLog log;
    TempClient c{log.handlers()};
    auto* net = quiet_start(c);
    log.clear();

    auto id = c->send_message(ConversationId::dm(PEER), {.body = "into the void"}, await);
    CHECK(c->outbound_busy());

    CHECK(answer_stores(*net, false) == 2);
    REQUIRE(c->message(id, await)->send_state == SendState::failed);
    REQUIRE(c->message(id, await)->sync_send_state == SendState::failed);
    CHECK_FALSE(c->outbound_busy());

    sync(*c);
    CHECK(log.seen() == std::vector{true, false});
}

TEST_CASE("Client: outbound covers an attachment upload and then its send", "[client][outbound]") {
    OutboundLog log;
    TempClient c{log.handlers()};
    auto* net = quiet_start<HeldUploads>(c);
    log.clear();
    TempFile file;

    auto id = c->send_message(
            ConversationId::dm(PEER),
            {.body = "look", .attachments = {OutgoingAttachment{.path = file.path}}},
            await);
    sync(*c);
    REQUIRE(net->held.size() == 1);
    REQUIRE(c->message(id, await)->send_state == SendState::uploading);
    CHECK(c->outbound_busy());

    // The upload finishing is not the end: the message itself has still to go.
    REQUIRE(net->release() == 1);
    sync(*c);
    REQUIRE(c->message(id, await)->send_state == SendState::sending);
    CHECK(c->outbound_busy());

    CHECK(accept_stores(*net) == 2);
    REQUIRE(c->message(id, await)->send_state == SendState::sent);
    CHECK_FALSE(c->outbound_busy());

    sync(*c);
    // One stretch of work from the user's point of view, so one report each way.
    CHECK(log.seen() == std::vector{true, false});
}

TEST_CASE("Client: outbound ends when an upload fails", "[client][outbound]") {
    OutboundLog log;
    TempClient c{log.handlers()};
    auto* net = quiet_start<HeldUploads>(c);
    log.clear();
    TempFile file;

    auto id = c->send_message(
            ConversationId::dm(PEER),
            {.body = "look", .attachments = {OutgoingAttachment{.path = file.path}}},
            await);
    sync(*c);
    REQUIRE(net->held.size() == 1);
    CHECK(c->outbound_busy());

    auto held = std::exchange(net->held, {});
    c->core.call_get([&] { held[0].request.on_complete(int16_t{500}, false); });
    sync(*c);
    REQUIRE(c->message(id, await)->send_state == SendState::failed);
    CHECK_FALSE(c->outbound_busy());

    // Retrying starts it all again, from the upload.
    REQUIRE(c->retry_send(id, await));
    sync(*c);
    REQUIRE(net->held.size() == 1);
    REQUIRE(c->message(id, await)->send_state == SendState::uploading);
    CHECK(c->outbound_busy());

    REQUIRE(net->release() == 1);
    sync(*c);
    CHECK(accept_stores(*net) == 2);
    REQUIRE(c->message(id, await)->send_state == SendState::sent);
    CHECK_FALSE(c->outbound_busy());

    sync(*c);
    CHECK(log.seen() == std::vector{true, false, true, false});
}

TEST_CASE("Client: outbound ends with an upload whose message was deleted", "[client][outbound]") {
    OutboundLog log;
    TempClient c{log.handlers()};
    auto* net = quiet_start<HeldUploads>(c);
    log.clear();
    TempFile file;

    auto id = c->send_message(
            ConversationId::dm(PEER),
            {.body = "look", .attachments = {OutgoingAttachment{.path = file.path}}},
            await);
    sync(*c);
    REQUIRE(net->held.size() == 1);

    // The message goes, but the file is still on its way to the server: still busy until then.
    REQUIRE(c->delete_message(id, await));
    REQUIRE(c->purge_deleted_message(id, await));
    REQUIRE_FALSE(c->message(id, await));
    settle_configs(*c, *net);
    CHECK(c->outbound_busy());

    // Its upload ending is the end of it, with nothing left to send.
    REQUIRE(net->release() == 1);
    sync(*c);
    CHECK(stores(*net).empty());
    CHECK_FALSE(c->outbound_busy());

    sync(*c);
    CHECK(log.seen() == std::vector{true, false});
}

TEST_CASE("Client: outbound waits for the copy to our own swarm", "[client][outbound]") {
    OutboundLog log;
    TempClient c{log.handlers()};
    auto* net = quiet_start(c);
    log.clear();

    auto id = c->send_message(ConversationId::dm(PEER), {.body = "two ways"}, await);
    auto [to_peer, to_self] = copies(*c, *net);

    // The recipient has it, which is all the message list shows -- but our other devices do not.
    to_peer(true, false, 200, {}, "{}");
    REQUIRE(c->message(id, await)->send_state == SendState::sent);
    REQUIRE(c->message(id, await)->sync_send_state == SendState::sending);
    CHECK(c->outbound_busy());

    to_self(true, false, 200, {}, "{}");
    REQUIRE(c->message(id, await)->sync_send_state == SendState::sent);
    CHECK_FALSE(c->outbound_busy());

    sync(*c);
    CHECK(log.seen() == std::vector{true, false});
}

TEST_CASE(
        "Client: outbound covers a config change until its push is answered",
        "[client][outbound]") {
    OutboundLog log;
    TempClient c{log.handlers()};
    auto* net = quiet_start(c);
    log.clear();

    c->set_display_name("Leia", await);
    // The change schedules a push rather than sending one, and a scheduled push already counts:
    // backgrounding during the debounce is exactly the case this exists for.
    sync(*c);
    REQUIRE(push_pending(*c));
    CHECK(c->outbound_busy());

    // Going out is no change: it was pending before and still is.
    push_configs_now(*c);
    REQUIRE(stores(*net).empty());
    REQUIRE(net->sent_requests.size() == 1);
    CHECK(c->outbound_busy());

    SECTION("stored") {
        CHECK(answer_config_pushes(*net) == 1);
        CHECK_FALSE(c->outbound_busy());
        CHECK_FALSE(in_configs(*c, [](core::Configs& cf) { return cf.needs_push(); }));
    }
    SECTION("refused") {
        // Still owed, but nothing is going to deliver it until something schedules another push,
        // so there is nothing to stay awake for.
        CHECK(answer_config_pushes(*net, false) == 1);
        CHECK_FALSE(c->outbound_busy());
        CHECK(in_configs(*c, [](core::Configs& cf) { return cf.needs_push(); }));
    }

    sync(*c);
    CHECK(log.seen() == std::vector{true, false});
}

TEST_CASE("Client: outbound reports each transition once", "[client][outbound]") {
    OutboundLog log;
    TempClient c{log.handlers()};
    auto* net = quiet_start(c);
    log.clear();

    // Overlapping work: a second send and a config change start while the first send is out, and
    // the first send finishes while the others are not.  None of that is a transition.
    auto first = c->send_message(ConversationId::dm(PEER), {.body = "one"}, await);
    auto first_copies = copies(*c, *net);
    net->sent_requests.clear();

    auto second = c->send_message(ConversationId::dm(PEER), {.body = "two"}, await);
    auto second_copies = copies(*c, *net);

    c->set_display_name("Leia", await);
    sync(*c);

    first_copies.to_peer(true, false, 200, {}, "{}");
    first_copies.to_self(true, false, 200, {}, "{}");
    REQUIRE(c->message(first, await)->sync_send_state == SendState::sent);
    sync(*c);
    CHECK(log.seen() == std::vector{true});
    CHECK(c->outbound_busy() == log.last());

    second_copies.to_peer(true, false, 200, {}, "{}");
    second_copies.to_self(true, false, 200, {}, "{}");
    REQUIRE(c->message(second, await)->sync_send_state == SendState::sent);
    sync(*c);
    // The config push is still owed, so still busy.
    CHECK(log.seen() == std::vector{true});
    CHECK(c->outbound_busy() == log.last());

    push_configs_now(*c);
    answer_config_pushes(*net);
    sync(*c);
    CHECK(log.seen() == std::vector{true, false});
    CHECK(c->outbound_busy() == log.last());
}

TEST_CASE("Client: receiving is not outbound work", "[client][outbound]") {
    OutboundLog log;
    TempClient c{log.handlers()};
    auto* net = quiet_start(c);

    // Someone we already know -- and who has written before, since the first message from anyone
    // says they approved us, which is a change to the contact and is published like one.
    SenderKeys sender;
    befriend(*c, sender.session_id);
    deliver(*c, sender, "hi there", from_epoch_ms(1000), "h1");
    settle_configs(*c, *net);
    sync(*c);
    // Publishing all that was outbound work, and was reported as it went.
    REQUIRE(std::ranges::count(log.seen(), true) > 0);
    REQUIRE_FALSE(log.last());
    log.clear();

    deliver(*c, sender, "are you there?", from_epoch_ms(2000), "h2");
    sync(*c);
    REQUIRE(c->conversation(ConversationId::dm(sender.session_id), await)->messages(await).size() ==
            2);

    CHECK_FALSE(c->outbound_busy());
    CHECK(log.seen().empty());
}

TEST_CASE("Client: outbound starts idle after a run left sends in flight", "[client][outbound]") {
    OutboundLog log;
    TempClient c;
    auto* net = quiet_start<HeldUploads>(c);

    // Left mid-flight, exactly as a process killed in the background would leave them.
    SECTION("sending") {
        auto id = c->send_message(ConversationId::dm(PEER), {.body = "did this land?"}, await);
        REQUIRE(c->message(id, await)->send_state == SendState::sending);
        REQUIRE(c->outbound_busy());

        c.reopen(log.handlers());
        CHECK(c->message(id, await)->send_state == SendState::interrupted);
        CHECK(c->message(id, await)->sync_send_state == SendState::interrupted);
    }
    SECTION("uploading") {
        TempFile file;
        auto id = c->send_message(
                ConversationId::dm(PEER),
                {.body = "look", .attachments = {OutgoingAttachment{.path = file.path}}},
                await);
        sync(*c);
        REQUIRE(net->held.size() == 1);
        REQUIRE(c->outbound_busy());

        // Dropped rather than completed: the process is gone before the file server answers.
        net->held.clear();
        c.reopen(log.handlers());
        CHECK(c->message(id, await)->send_state == SendState::failed);
    }

    CHECK_FALSE(c->outbound_busy());
    sync(*c);
    CHECK(log.seen().empty());
}

TEST_CASE(
        "Client: outbound is answered from the send-state indexes", "[client][outbound][schema]") {
    TempClient c;
    auto conn = c->core.database().conn();
    std::string plan;
    SQLite::Statement st{
            conn.sql, "EXPLAIN QUERY PLAN " + std::string{TestHelper::outbound_query<Client>()}};
    while (st.executeStep())
        plan += "{}\n"_format(st.getColumn(3).getText());

    // It runs on every send status, so neither half may scan the table.
    CHECK(plan.find("INDEX messages_send_state") != std::string::npos);
    CHECK(plan.find("INDEX messages_sync_send_state") != std::string::npos);
    CHECK(plan.find("SCAN messages") == std::string::npos);
}
