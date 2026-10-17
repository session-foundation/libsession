#include "common.hpp"

namespace {

using files = std::vector<std::string>;

// One conversation with a peer, whose files a mock network serves, and a way to restart.
struct Backlog {
    TempCacheDir dir;
    TempClient c;
    SenderKeys peer;
    ConversationId convo = ConversationId::dm(peer.session_id);
    // Onion requests fetch one file at a time, which is what makes an order observable.
    bool one_at_a_time;
    MockNetwork* net = nullptr;
    std::map<std::string, std::vector<std::byte>> served;
    decltype(random::random(32)) seed = random::random(32);
    int64_t when = 1000;

    explicit Backlog(bool one_at_a_time = false, bool with_cache = true) :
            one_at_a_time{one_at_a_time} {
        attach();
        if (with_cache)
            c->set_cache_dir(dir.path);
        c->open_dm(convo, await);
    }

    void attach() {
        network::config::Config config;
        if (!one_at_a_time)
            config.router = network::opt::router::Type::direct;
        net = attach_mock_network(c->core, std::move(config));
        net->served = served;
        sync(*c);
    }

    // A restart, with the cache directory and the network given back in either order.
    void reopen(bool network_first) {
        c.reopen();
        if (network_first)
            attach();
        c->set_cache_dir(dir.path);
        sync(*c);
        if (!network_first)
            attach();
        sync(*c);
    }

    struct File {
        std::vector<std::byte> ciphertext, key;
        std::string type;
        size_t size;
    };
    std::map<std::string, File> made;

    // A message carrying one new file, served as `file`, sent at `ts` (else just after the last).
    // Returns the message's id.
    int64_t arrive(
            const std::string& file,
            std::string type = "image/png",
            size_t size = 3000,
            std::optional<int64_t> ts = std::nullopt) {
        std::vector<std::byte> data(size);
        random::fill(data);
        auto [ct, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);
        made[file] = {ct, to_vector<std::byte>(key), std::move(type), size};
        served[file] = ct;
        net->served[file] = ct;
        return carry(file, "h" + file, ts);
    }

    // Another message carrying a file `arrive` made, as a forward would.
    int64_t carry(
            const std::string& file, std::string hash, std::optional<int64_t> ts = std::nullopt) {
        const auto& f = made.at(file);
        deliver(*c,
                peer,
                "",
                from_epoch_ms(ts ? *ts : when++),
                std::move(hash),
                "",
                std::nullopt,
                [&](SessionProtos::DataMessage& d) {
                    auto* a = d.add_attachments();
                    a->set_id(1);
                    a->set_url(network::file_server::generate_download_url(file, {}, true));
                    a->set_key(
                            std::string{reinterpret_cast<const char*>(f.key.data()), f.key.size()});
                    a->set_size(f.size);
                    a->set_contenttype(f.type);
                });
        sync(*c);
        // Ids only grow, so the newest arrival is the largest whatever its timestamp.
        int64_t newest = 0;
        for (const auto& m : c->conversation(convo, await)->messages(await))
            newest = std::max(newest, m.id);
        return newest;
    }

    void set(AutoDownload mode) {
        c->conversation(convo, await)->set_auto_download(mode, await);
        sync(*c);
    }

    // `mode`, and what is already here too: what a ticked "also download what is here" does.
    void fetch(AutoDownload mode) {
        set(mode);
        fetch_existing();
    }

    void fetch_existing() {
        c->conversation(convo, await)->download_existing_attachments(await);
        sync(*c);
    }

    // Rows still flagged, which the unavailable paths leave no other way to observe.
    int64_t owed() {
        return c->core.loop().call_get([&] {
            return c->core.database().conn().prepared_get<int64_t>(
                    "SELECT count(*) FROM message_attachments WHERE auto_pending IS NOT NULL");
        });
    }

    ExistingAttachmentCounts counts() {
        return c->conversation(convo, await)->existing_attachments(await);
    }

    // The files being fetched, in the order they were asked for.
    files fetching() const {
        files found;
        for (const auto& r : net->downloads)
            found.push_back(network::file_server::parse_download_url(r.download_url)->file_id);
        return found;
    }

    void serve() {
        serve_downloads(*net);
        sync(*c);
    }

    void request(int64_t message) {
        c->attachment_data(message, 0, nullptr, [](auto) {});
        sync(*c);
    }
};

}  // namespace

TEST_CASE(
        "Client: turning auto-download on can fetch what is already here",
        "[client][auto][existing]") {
    Backlog b;
    auto image = b.arrive("a");
    auto doc = b.arrive("b", "application/pdf");
    b.arrive("c", "image/png", 20000);
    REQUIRE(b.fetching().empty());

    SECTION("leaving it fetches only what arrives afterwards") {
        b.set(AutoDownload::all);
        CHECK(b.fetching().empty());
        b.arrive("d");
        CHECK(b.fetching() == files{"d"});
    }

    SECTION("the count is what fetching then queues, for either mode") {
        auto n = b.counts();
        CHECK(n.all.count == 3);
        CHECK(n.all.bytes == 26000);
        CHECK(n.image_attachments.count == 2);
        CHECK(n.image_attachments.bytes == 23000);

        b.c->set_auto_download_max_size(10000, await);
        n = b.counts();
        CHECK(n.all.count == 2);
        CHECK(n.all.bytes == 6000);
        CHECK(n.image_attachments.count == 1);

        b.fetch(AutoDownload::all);
        CHECK(b.fetching() == files{"b", "a"});
        // Still counted while only queued: they are not here yet.
        CHECK(b.counts().all.count == 2);
        b.serve();
        CHECK(b.counts().all.count == 0);
    }

    SECTION("images only fetches the pictures, newest first") {
        b.fetch(AutoDownload::image_attachments);
        CHECK(b.fetching() == files{"c", "a"});
    }

    SECTION("asking later, with the setting already on, still fetches") {
        b.set(AutoDownload::all);
        b.fetch_existing();
        CHECK(b.fetching() == files{"c", "b", "a"});
    }

    SECTION("there is nothing to fetch with it unset or off") {
        CHECK_THROWS_AS(b.fetch_existing(), std::invalid_argument);
        b.set(AutoDownload::none);
        CHECK_THROWS_AS(b.fetch_existing(), std::invalid_argument);
        CHECK(b.fetching().empty());
    }

    SECTION("a file already here is neither counted nor fetched") {
        b.request(image);
        b.serve();
        CHECK(b.counts().all.count == 2);
        b.fetch(AutoDownload::all);
        CHECK(b.fetching() == files{"c", "b"});
    }

    SECTION("a file the server no longer has is neither counted nor fetched") {
        b.request(doc);
        fail_downloads(*b.net, 404);
        sync(*b.c);
        CHECK(b.counts().all.count == 2);
        b.fetch(AutoDownload::all);
        CHECK(b.fetching() == files{"c", "a"});
    }
}

TEST_CASE("Client: a new arrival goes ahead of the backlog", "[client][auto][existing]") {
    Backlog b{true};
    b.arrive("a");
    b.arrive("b");
    b.fetch(AutoDownload::all);
    REQUIRE(b.fetching() == files{"b"});

    b.arrive("c");
    b.serve();
    CHECK(b.fetching() == files{"c"});
    b.serve();
    CHECK(b.fetching() == files{"a"});
}

TEST_CASE("Client: what auto-download still owes survives a restart", "[client][auto][existing]") {
    bool network_first = GENERATE(false, true);
    Backlog b{true};
    b.arrive("a");
    b.arrive("b");
    b.fetch(AutoDownload::all);
    REQUIRE(b.fetching() == files{"b"});

    b.reopen(network_first);
    CHECK(b.fetching() == files{"b"});
    b.serve();
    CHECK(b.fetching() == files{"a"});
    b.serve();
    CHECK(b.fetching().empty());

    b.reopen(network_first);
    CHECK(b.fetching().empty());
}

TEST_CASE("Client: an evicted file is not owed again", "[client][auto][existing][evict]") {
    Backlog b;
    b.arrive("a");
    b.arrive("b");
    // Room for one of the two, so the second to land evicts the first.
    b.c->set_attachment_cache_limit(4000, await);
    b.fetch(AutoDownload::all);
    REQUIRE(b.fetching() == files{"b", "a"});
    b.serve();

    size_t cached = 0;
    for (const auto& m : b.c->conversation(b.convo, await)->messages(await))
        cached += m.attachments[0].availability == AttachmentAvailability::cached;
    REQUIRE(cached == 1);

    b.reopen(false);
    CHECK(b.fetching().empty());
}

TEST_CASE(
        "Client: changing the setting forgets what it no longer takes",
        "[client][auto][existing]") {
    Backlog b{true};
    b.arrive("a");
    b.arrive("b", "application/pdf");
    b.arrive("c");
    b.fetch(AutoDownload::all);
    REQUIRE(b.fetching() == files{"c"});

    SECTION("off forgets all of it, and on again does not bring it back") {
        b.set(AutoDownload::none);
        b.serve();
        CHECK(b.fetching().empty());

        b.reopen(false);
        CHECK(b.fetching().empty());
        b.set(AutoDownload::all);
        CHECK(b.fetching().empty());
    }

    SECTION("off and on again before the queue is reached does not bring it back") {
        b.set(AutoDownload::none);
        b.set(AutoDownload::all);
        b.serve();
        CHECK(b.fetching().empty());
    }

    SECTION("images only forgets the rest") {
        b.set(AutoDownload::image_attachments);
        b.serve();
        CHECK(b.fetching() == files{"a"});
        b.serve();
        CHECK(b.fetching().empty());
    }
}

TEST_CASE(
        "Client: a failed auto-download stays owed only while it may succeed",
        "[client][auto][existing]") {
    Backlog b{true};
    b.arrive("a");
    b.fetch(AutoDownload::all);
    REQUIRE(b.fetching() == files{"a"});

    SECTION("a file the server no longer has is dropped") {
        fail_downloads(*b.net, 404);
        sync(*b.c);
        b.reopen(false);
        CHECK(b.fetching().empty());
    }

    SECTION("a transient failure is tried again at the next start, not before") {
        fail_downloads(*b.net, 503);
        sync(*b.c);
        CHECK(b.fetching().empty());
        b.reopen(false);
        CHECK(b.fetching() == files{"a"});
    }

    SECTION("asking again retries what a failed attempt left owed") {
        fail_downloads(*b.net, 503);
        sync(*b.c);
        CHECK(b.counts().all.count == 1);
        b.fetch(AutoDownload::all);
        CHECK(b.fetching() == files{"a"});
    }
}

TEST_CASE("Client: a file fetched another way is no longer owed", "[client][auto][existing]") {
    Backlog b{true};
    auto older = b.arrive("a");
    b.arrive("b");
    b.fetch(AutoDownload::all);
    REQUIRE(b.fetching() == files{"b"});

    // Asked for directly while it waits its turn, and held to no auto-download limit.
    b.request(older);
    REQUIRE(b.fetching() == files{"b", "a"});
    b.serve();
    CHECK(b.fetching().empty());

    b.reopen(false);
    CHECK(b.fetching().empty());
}

TEST_CASE(
        "Client: a file several messages carry is counted and fetched once",
        "[client][auto][existing]") {
    Backlog b;
    auto first = b.arrive("a");
    auto forward = b.carry("a", "h-forward");
    auto n = b.counts();
    CHECK(n.all.count == 1);
    CHECK(n.all.bytes == 3000);

    b.fetch(AutoDownload::all);
    CHECK(b.fetching() == files{"a"});
    b.serve();
    for (auto id : {first, forward})
        CHECK(b.c->message(id, await)->attachments[0].availability ==
              AttachmentAvailability::cached);
}

TEST_CASE(
        "Client: the backlog goes newest message first by when it was sent",
        "[client][auto][existing]") {
    Backlog b{true};
    b.arrive("newer", "image/png", 3000, 5000);
    // Delivered after, sent before: a late or synced delivery.
    b.arrive("older", "image/png", 3000, 2000);
    b.fetch(AutoDownload::all);
    CHECK(b.fetching() == files{"newer"});
}

TEST_CASE(
        "Client: a size limit lowered while queued forgets what it refuses",
        "[client][auto][existing]") {
    Backlog b{true};
    b.arrive("a");
    b.arrive("b");
    b.fetch(AutoDownload::all);
    REQUIRE(b.fetching() == files{"b"});

    // Raised again before the queue reaches `a`: it was forgotten when the limit refused it.
    b.c->set_auto_download_max_size(1000, await);
    b.c->set_auto_download_max_size(std::nullopt, await);
    b.serve();
    CHECK(b.fetching().empty());
    b.reopen(false);
    CHECK(b.fetching().empty());
}

TEST_CASE("Client: a message deleted while queued is not fetched", "[client][auto][existing]") {
    Backlog b{true};
    auto older = b.arrive("a");
    b.arrive("b");
    b.fetch(AutoDownload::all);
    REQUIRE(b.fetching() == files{"b"});

    b.c->delete_message(older, await);
    b.serve();
    CHECK(b.fetching().empty());
    b.reopen(false);
    CHECK(b.fetching().empty());
}

TEST_CASE("Client: without a cache there is nothing to fetch", "[client][auto][existing]") {
    Backlog b{false, false};
    b.arrive("a");
    auto n = b.counts();
    CHECK(n.all.count == 0);
    CHECK(n.image_attachments.count == 0);

    b.fetch(AutoDownload::all);
    CHECK(b.fetching().empty());
    b.c->set_cache_dir(b.dir.path);
    sync(*b.c);
    CHECK(b.fetching().empty());
}

TEST_CASE("Client: reloading the queue does not fetch a file twice", "[client][auto][existing]") {
    Backlog b;
    b.c->set_auto_download_concurrency(2, await);
    b.arrive("a");
    b.fetch(AutoDownload::all);
    REQUIRE(b.fetching() == files{"a"});

    // A second reload while `a` runs must not spend the other slot joining it.
    b.c->set_cache_dir(b.dir.path);
    sync(*b.c);
    b.arrive("b");
    CHECK(b.fetching() == files{"a", "b"});
}

TEST_CASE(
        "Client: a file several messages carry takes one slot, not one each",
        "[client][auto][existing]") {
    Backlog b;
    b.c->set_auto_download_concurrency(2, await);
    b.arrive("x");
    b.arrive("a");
    b.carry("a", "h-forward");
    b.fetch(AutoDownload::all);
    CHECK(b.fetching() == files{"a", "x"});
}

TEST_CASE("Client: asking twice does not queue anything twice", "[client][auto][existing]") {
    Backlog b{true};
    b.arrive("a");
    b.arrive("b");
    b.arrive("c");
    b.fetch(AutoDownload::all);
    b.fetch_existing();
    REQUIRE(b.fetching() == files{"c"});
    b.serve();
    REQUIRE(b.fetching() == files{"b"});
    b.serve();
    REQUIRE(b.fetching() == files{"a"});

    // A duplicate entry would try `a` again at once.
    fail_downloads(*b.net, 503);
    sync(*b.c);
    CHECK(b.fetching().empty());
}

TEST_CASE("Client: a file found unavailable is no longer owed", "[client][auto][existing]") {
    Backlog b{true};
    b.fetch(AutoDownload::all);
    b.arrive("a");
    REQUIRE(b.fetching() == files{"a"});
    REQUIRE(b.owed() == 1);

    SECTION("the server no longer has it") {
        fail_downloads(*b.net, 404);
        sync(*b.c);
        CHECK(b.owed() == 0);
    }

    SECTION("its bytes are not the file they claimed to be") {
        std::vector<std::byte> garbage(4000);
        random::fill(garbage);
        serve_downloads(*b.net, garbage);
        sync(*b.c);
        CHECK(b.c->conversation(b.convo, await)->messages(await)[0].attachments[0].availability ==
              AttachmentAvailability::unreadable);
        CHECK(b.owed() == 0);
    }
}
