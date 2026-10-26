#include <sqlite3.h>

#include "common.hpp"

// ── The suspend contract ────────────────────────────────────────────────────────────────────────

namespace {

constexpr auto PEER = "05fe94b7ad4b7f1cc1bb92671f1f0d243f226e115b33770465e82b503fc3e96e1f"_hex_b;

// The bytes a swarm holds for a plain v1 DM to `to`.
std::vector<std::byte> dm_bytes(
        Client& to, const SenderKeys& from, std::string_view body, sys_ms ts) {
    SessionProtos::Content content;
    content.set_sigtimestamp(static_cast<uint64_t>(ts.time_since_epoch().count()));
    content.mutable_datamessage()->set_body(std::string{body});
    auto plaintext = content.SerializeAsString();
    return encode_dm_v1(
            std::as_bytes(std::span{plaintext}), from.ed_sk, ts, own_sid(to), std::nullopt);
}

// A storage server's answer to a batch of retrieves: `messages` in the one asking for `ns`.
std::string retrieve_answer(
        std::span<const std::byte> request_body,
        int16_t ns,
        const std::vector<std::pair<std::string, std::vector<std::byte>>>& messages) {
    auto batch = parse_json(request_body);
    auto results = nlohmann::json::array();
    for (const auto& r : batch["requests"]) {
        nlohmann::json body;
        body["messages"] = nlohmann::json::array();
        if (r["params"]["namespace"] == ns)
            for (const auto& [hash, data] : messages)
                body["messages"].push_back({{"data", oxenc::to_base64(data)}, {"hash", hash}});
        results.push_back({{"code", 200}, {"body", std::move(body)}});
    }
    return nlohmann::json{{"results", std::move(results)}}.dump();
}

// A mock network's reply, run on a thread of its own: the mock hands a reply to Core's loop and
// waits for it to be handled, and while storage is suspended handling it waits for the resume,
// which the test's own thread has to be free to make.  `held()` says the reply has not been
// handled yet - which, given time to arrive, is the proof that it was held.
struct HeldAnswer {
    std::shared_ptr<std::atomic<bool>> returned = std::make_shared<std::atomic<bool>>(false);
    std::thread thread;

    bool held() const { return !*returned; }
    void join() { thread.join(); }
};

template <typename F>
HeldAnswer answer_while_suspended(F answer) {
    HeldAnswer a;
    a.thread = std::thread{[answer = std::move(answer), returned = a.returned]() mutable {
        answer();
        *returned = true;
    }};
    std::this_thread::sleep_for(100ms);
    return a;
}

// A message on its way out: both of its stores captured and unanswered.
int64_t start_send(TempClient& c, MockNetwork& net) {
    TestHelper::seed_pfs_nak(c->core, PEER);
    TestHelper::seed_pfs_nak(c->core, own_sid(*c));
    auto id = c->send_message(ConversationId::dm(PEER), {.body = "out it goes"}, await);
    REQUIRE(stores(net).size() == 2);
    return id;
}

}  // namespace

TEST_CASE("Client: suspended storage holds no lock on the database", "[client][suspend]") {
    // What iOS checks before it kills a suspended app: whether the process holds a lock on a file
    // in the shared container.  Another process able to take the exclusive lock, and to checkpoint
    // and truncate the WAL, at once and without waiting, is what holding none looks like.
    TempClient c;
    SenderKeys sender;
    approve(*c, sender.session_id);
    deliver(*c, sender, "before", from_epoch_ms(5000), "h1");

    auto result = c->suspend_storage(5s, false, true);
    CHECK(result.closed);
    CHECK(result.checkpointed);
    CHECK(c->core.storage_suspended());
    // What the outsider below cannot tell apart: an idle connection still open holds a lock on the
    // shared-memory file without stopping its exclusive lock or its checkpoint.
    CHECK(c->core.database().open_connections() == 0);

    sqlite3* other;
    REQUIRE(sqlite3_open_v2(c.path.c_str(), &other, SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK);
    sqlite3_busy_timeout(other, 0);
    CHECK(sqlite3_exec(other, "BEGIN EXCLUSIVE", nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_exec(other, "ROLLBACK", nullptr, nullptr, nullptr);
    int log = -1, done = -1;
    CHECK(sqlite3_wal_checkpoint_v2(other, nullptr, SQLITE_CHECKPOINT_TRUNCATE, &log, &done) ==
          SQLITE_OK);
    sqlite3_close(other);

    c->resume_storage();
    CHECK_FALSE(c->core.storage_suspended());
    deliver(*c, sender, "after", from_epoch_ms(6000), "h2");
    CHECK(c->conversation(ConversationId::dm(sender.session_id), await)->messages(await).size() ==
          2);
}

TEST_CASE("Client: a blocking call while storage is suspended is refused", "[client][suspend]") {
    // Rather than waiting: the thread making it may be the one that would resume.
    TempClient c;
    c->suspend_storage(1s);
    CHECK_THROWS_AS(c->conversations(await), sqlite::database_suspended);
    c->resume_storage();
    CHECK_NOTHROW(c->conversations(await));
}

TEST_CASE(
        "Client: database work off Core's threads while suspended is refused",
        "[client][suspend]") {
    TempClient c;
    c->suspend_storage(1s);
    CHECK_THROWS_AS(c->core.database().conn(), sqlite::database_suspended);
    c->resume_storage();
    CHECK_NOTHROW(c->core.database().conn());
}

TEST_CASE(
        "Client: a poll answered while suspended is stored when storage resumes",
        "[client][suspend][poll]") {
    TempClient c;
    auto* net = attach_mock_network(c->core);
    net->current_node.remote_pubkey[0] = std::byte{0x01};
    const auto& node = net->current_node.remote_pubkey;
    constexpr int16_t dm_ns = static_cast<int16_t>(config::Namespace::Default);

    SenderKeys sender;
    approve(*c, sender.session_id);
    std::vector<std::pair<std::string, std::vector<std::byte>>> batch{
            {"h1", dm_bytes(*c, sender, "one", from_epoch_ms(5000))}};

    // A poll goes out, and storage is suspended before its answer arrives.
    net->sent_requests.clear();
    TestHelper::poll(c->core);
    REQUIRE(net->sent_requests.size() == 1);
    auto first = net->sent_requests[0];
    c->suspend_storage(1s);

    // Handling it waits for the resume, holding Core's loop up.
    auto answer = answer_while_suspended([&] {
        first.callback(true, false, 200, {}, retrieve_answer(*first.request.body, dm_ns, batch));
    });
    CHECK(net->sent_requests.size() == 1);
    CHECK(answer.held());

    c->resume_storage();
    answer.join();
    TestHelper::drain(c->core);
    auto convo = c->conversation(ConversationId::dm(sender.session_id), await);
    REQUIRE(convo);
    CHECK(convo->messages(await).size() == 1);
    CHECK(TestHelper::namespace_last_hash(c->core, dm_ns, node) == "h1");

    // And resuming polls at once, from where the held answer left the cursor.
    auto is_retrieve = [](const MockNetwork::SentRequest& r) {
        auto body = parse_json(*r.request.body);
        return body.contains("requests") && body["requests"][0]["method"] == "retrieve";
    };
    CHECK(std::ranges::count_if(net->sent_requests, is_retrieve) == 2);
}

TEST_CASE(
        "Client: a send that completes while suspended is recorded when storage resumes",
        "[client][suspend][send]") {
    TempClient c;
    auto* net = attach_mock_network(c->core);
    auto id = start_send(c, *net);

    c->suspend_storage(1s);
    size_t accepted = 0;
    auto answer = answer_while_suspended([&] { accepted = accept_stores(*net); });
    CHECK(answer.held());

    c->resume_storage();
    answer.join();
    CHECK(accepted == 2);
    sync(*c);
    auto msg = c->message(id, await);
    CHECK(msg->send_state == SendState::sent);
    CHECK(msg->sync_send_state == SendState::sent);
    CHECK(msg->hash == store_hash_for(oxenc::to_hex(own_sid(*c))));
}

TEST_CASE(
        "Client: a send answered while suspended is recorded if the Client ends first",
        "[client][suspend][send]") {
    // Ending the Client lets the held answer finish rather than waiting for ever.  A process killed
    // while suspended runs no destructor, and that send is called interrupted on the next launch:
    // see `SendState::interrupted`.
    TempClient c;
    auto* net = attach_mock_network(c->core);
    auto id = start_send(c, *net);

    c->suspend_storage(1s);
    size_t accepted = 0;
    auto answer = answer_while_suspended([&] { accepted = accept_stores(*net); });
    CHECK(answer.held());
    c.reopen();
    answer.join();
    CHECK(accepted == 2);
    auto msg = c->message(id, await);
    CHECK(msg->send_state == SendState::sent);
    CHECK(msg->sync_send_state == SendState::sent);
}

TEST_CASE(
        "Client: an in-flight send unanswered while suspended is still interrupted after a restart",
        "[client][suspend][send]") {
    // The case nothing can know: no answer reached the process before it ended.
    TempClient c;
    auto* net = attach_mock_network(c->core);
    auto id = start_send(c, *net);

    c->suspend_storage(1s);
    c.reopen();
    CHECK(c->message(id, await)->send_state == SendState::interrupted);
}

TEST_CASE(
        "Client: a download that completes while suspended finishes when storage resumes",
        "[client][suspend][attachments]") {
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    TestHelper::seed_pfs_nak(c->core, peer.session_id);

    std::vector<std::byte> plaintext(9000);
    for (size_t i = 0; i < plaintext.size(); i++)
        plaintext[i] = static_cast<std::byte>(i * 31 % 256);
    auto seed = random::random(32);
    auto [ciphertext, key] = attachment::encrypt(seed, plaintext, attachment::Domain::ATTACHMENT);
    deliver(
            *c,
            peer,
            "",
            from_epoch_ms(1000),
            "h1",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& data) {
                auto* a = data.add_attachments();
                a->set_id(1);
                a->set_url("http://fs.example/file/1#d");
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                a->set_size(plaintext.size());
                a->set_filename("payload.bin");
            },
            42);
    sync(*c);
    auto msg_id =
            c->conversation(ConversationId::dm(peer.session_id), await)->messages(await).at(0).id;

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_suspend", 7);
    std::filesystem::create_directories(dir);
    auto dest = dir / "saved.bin";
    std::promise<std::optional<Error>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(msg_id, 0, dest, nullptr, [&](auto r) {
        done.set_value(r ? std::nullopt : std::optional{std::move(r).error()});
    });
    sync(*c);
    REQUIRE(net->downloads.size() == 1);

    // The file arrives while suspended.  Recording it needs the database, so it waits for the
    // resume -- holding the loops up, so nothing here may wait on them until then.
    c->suspend_storage(1s);
    size_t served = 0;
    auto answer = answer_while_suspended([&] { served = serve_downloads(*net, ciphertext); });
    CHECK(waiter.wait_for(200ms) == std::future_status::timeout);

    c->resume_storage();
    answer.join();
    REQUIRE(served == 1);
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
    CHECK_FALSE(waiter.get().has_value());
    CHECK(std::filesystem::file_size(dest) == plaintext.size());
    CHECK(c->message(msg_id, await)->attachments.at(0).saved_at.has_value());

    std::filesystem::remove_all(dir);
}

TEST_CASE(
        "Client: suspending again while a job is held returns without waiting on it",
        "[client][suspend]") {
    // The second suspend used to wait on the loop for its turn, behind the held job - with the
    // suspend lock held, and for ever if its thread was the one to resume.
    TempClient c;
    auto* net = attach_mock_network(c->core);
    auto id = start_send(c, *net);

    c->suspend_storage(1s);
    size_t accepted = 0;
    auto answer = answer_while_suspended([&] { accepted = accept_stores(*net); });
    REQUIRE(answer.held());

    auto again = std::async(std::launch::async, [&] { return c->suspend_storage(1s); });
    bool returned = again.wait_for(5s) == std::future_status::ready;
    if (!returned)
        // Unblocks it, so that a failure here ends the test rather than hanging it
        c->resume_storage();
    REQUIRE(returned);
    CHECK(again.get().closed);
    CHECK(c->core.storage_suspended());

    c->resume_storage();
    answer.join();
    CHECK(accepted == 2);
    sync(*c);
    CHECK(c->message(id, await)->send_state == SendState::sent);
}

TEST_CASE("Core: destroyed while suspended with a job held and no Client", "[core][suspend]") {
    // ~Client resumes before it stops anything; a Core used on its own has to do the same, before
    // the first thing it waits on the loop for.
    auto core = std::make_unique<TempCore>();
    (*core)->suspend_storage(1s);

    // Spun on rather than a latch, which the macOS deployment target does not have
    std::atomic<bool> posted{false};
    (*core)->loop().call([&] {
        posted = true;
        // Held: Core's loop waits here for the resume
        (*core)->database().conn();
    });
    while (!posted) {
    }
    std::this_thread::sleep_for(50ms);

    auto& db = (*core)->database();
    auto destroyed = std::async(std::launch::async, [&] { core.reset(); });
    bool done = destroyed.wait_for(10s) == std::future_status::ready;
    if (!done)
        // Releases the held job, so that a failure here ends the test rather than hanging it
        db.resume();
    CHECK(done);
}

TEST_CASE("Core: a blocking call while storage is suspended is refused", "[core][suspend]") {
    // As Client's: rather than waiting for a resume its own thread may be the one to make
    TempCore core;
    core->suspend_storage(1s);
    CHECK_THROWS_AS(core->call_get([] { return 0; }), sqlite::database_suspended);
    CHECK_THROWS_AS(core->devices.device_info(await), sqlite::database_suspended);

    // A call taking a callback is queued instead, and answered once resumed
    std::promise<bool> answered;
    core->call([&] { answered.set_value(true); });

    core->resume_storage();
    CHECK(answered.get_future().get());
    CHECK(core->call_get([] { return 1; }) == 1);
    CHECK_NOTHROW(core->devices.device_info(await));
}
