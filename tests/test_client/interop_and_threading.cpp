#include "common.hpp"

// ── Core interoperability ───────────────────────────────────────────────────────────────────────

TEST_CASE("Client: an asynchronous call reports that it succeeded", "[client][callbacks]") {
    TempClient c;
    SenderKeys sender;
    approve(*c, sender.session_id);
    deliver(*c, sender, "hello", from_epoch_ms(1000), "h1");
    sync(*c);

    // Qualified, because Client masks the asynchronous forms deliberately: choosing the easy
    // class means choosing it for everything.
    std::optional<Error> reported_error = Error{"test.not_called", "not called"};
    std::vector<AnyConversation> got;
    c->Client::conversations([&](Expected<std::vector<AnyConversation>> r) {
        if (r) {
            reported_error.reset();
            got = *std::move(r);
        } else
            reported_error = std::move(r).error();
    });
    sync(*c);

    // Called exactly once, and saying it worked rather than leaving the caller to assume so.
    CHECK_FALSE(reported_error.has_value());
    REQUIRE(got.size() == 1);
    CHECK(got[0].id() == ConversationId::dm(sender.session_id));
}

TEST_CASE("Client: handlers arrive through the dispatcher", "[client][callbacks]") {
    // Stands in for an application's loop: jobs are collected rather than run, so a handler that
    // ran on Core's loop instead of being handed over is visible as one that never happened.
    std::vector<std::function<void()>> queued;
    std::thread::id dispatched_on;

    Recorder r;
    TempClient c{r.handlers()};
    c->set_dispatcher([&](std::function<void()> job) {
        dispatched_on = std::this_thread::get_id();
        queued.push_back(std::move(job));
    });

    SenderKeys sender;
    deliver(*c, sender, "hello", from_epoch_ms(1000), "h1");
    sync(*c);

    // Handed over rather than called: nothing has reached the application yet.
    CHECK(r.msg_added.empty());
    CHECK(r.added.empty());
    REQUIRE(!queued.empty());

    // Handed over from Core's loop, which is the thread an application must not be touched from.
    CHECK(dispatched_on != std::this_thread::get_id());

    for (auto& job : queued)
        job();
    queued.clear();

    REQUIRE(Recorder::messages(r.msg_added).size() == 1);
    CHECK(Recorder::messages(r.msg_added)[0].body == "hello");
    CHECK(r.added.size() == 1);

    // Unsetting puts things back the way they are without one, which is what an application does
    // when its loop stops accepting work.
    c->set_dispatcher(nullptr);
    deliver(*c, sender, "direct", from_epoch_ms(2000), "h2");
    sync(*c);

    CHECK(queued.empty());
    REQUIRE(Recorder::messages(r.msg_added).size() == 2);
    CHECK(Recorder::messages(r.msg_added)[1].body == "direct");
}

TEST_CASE("Client: Core is usable directly through the Client", "[client][callbacks]") {
    TempClient c;

    // The account state is Core's, and reachable without Client wrapping any of it.
    CHECK(c->core.globals.session_id()[0] == std::byte{0x05});
    CHECK_FALSE(c->core.devices.device_id().empty());

    // Globals set through Core survive a Client restart, i.e. it really is one database.
    c->core.globals.set("client_test_key", "value"sv);
    c.reopen();
    CHECK(c->core.globals.get_text("client_test_key") == "value");
}

// ── Threading ───────────────────────────────────────────────────────────────────────────────────

TEST_CASE("Client: reads are safe while messages arrive on another thread", "[client][threads]") {
    // An application reads conversations and history from its UI thread while Core's poll thread
    // writes arriving messages.  Those are two connections from the shared pool against a WAL
    // database, so readers should not block behind the writer nor see SQLITE_BUSY -- but that is a
    // claim about configuration, and nothing exercised it until this.
    TempClient c;
    SenderKeys sender;
    auto convo = ConversationId::dm(sender.session_id);

    constexpr int N = 300;
    std::atomic<bool> writing{true};
    std::atomic<int> reads{0};
    std::exception_ptr writer_err, reader_err;

    std::thread writer{[&] {
        try {
            for (int i = 1; i <= N; i++)
                deliver(*c, sender, "msg{}"_format(i), from_epoch_ms(i * 1000), "h{}"_format(i));
        } catch (...) {
            writer_err = std::current_exception();
        }
        writing = false;
    }};

    std::thread reader{[&] {
        try {
            while (writing) {
                for (const auto& convo_row : c->conversations(await))
                    convo_row.messages(50, await);
                reads++;
            }
        } catch (...) {
            reader_err = std::current_exception();
        }
    }};

    writer.join();
    reader.join();

    // Rethrown on this thread: Catch2's assertion macros are not safe to use from the others.
    if (writer_err)
        std::rethrow_exception(writer_err);
    if (reader_err)
        std::rethrow_exception(reader_err);

    CHECK(reads > 0);  // the reader really did run alongside, rather than after
    CHECK(c->conversation(convo, await)->messages(N + 10, await).size() == N);
}

TEST_CASE("Client: two Clients on one database both store what they receive", "[client][threads]") {
    // Another process on the same file -- a notification extension, say -- is another connection
    // that commits whenever it likes.  A transaction that reads before it writes has its snapshot
    // overtaken by such a commit, and the write then fails at once with SQLITE_BUSY: waiting cannot
    // help a stale snapshot, so the busy timeout is never consulted.  Each store here reads first
    // (is the sender blocked, does the conversation exist), so with two receiving at once that is
    // a lost message unless the write lock is taken when the transaction begins.
    TempClient a;
    auto b = std::make_unique<Client>(a.path);
    SenderKeys sender;

    constexpr int N = 200;
    std::exception_ptr a_err, b_err;
    auto receive_into = [&](Client& c, std::string_view tag, int offset, std::exception_ptr& err) {
        try {
            for (int i = 1; i <= N; i++)
                deliver(c,
                        sender,
                        "{}{}"_format(tag, i),
                        from_epoch_ms((offset + i) * 1000),
                        "{}{}"_format(tag, i));
        } catch (...) {
            err = std::current_exception();
        }
    };
    std::thread ta{[&] { receive_into(*a, "a", 0, a_err); }};
    std::thread tb{[&] { receive_into(*b, "b", N, b_err); }};
    ta.join();
    tb.join();
    b.reset();

    if (a_err)
        std::rethrow_exception(a_err);
    if (b_err)
        std::rethrow_exception(b_err);

    auto stored = a->core.loop().call_get([&] {
        return a->core.database().conn().prepared_get<int64_t>("SELECT count(*) FROM messages");
    });
    CHECK(stored == 2 * N);
}
