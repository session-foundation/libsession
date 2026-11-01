#include <session/client/error_codes.hpp>

#include "../../src/client/download_cache.hpp"
#include "../utils.hpp"
#include "common.hpp"
#include "config_helpers.hpp"

namespace cache = session::client::cache;

TEST_CASE("Client: an arriving message records the files it names", "[client][attachments]") {
    TempClient c;
    SenderKeys peer;

    // `id` is deprecated in favour of `url` but is still `required` by the protobuf, so every
    // pointer carries one whether or not anything reads it.
    uint64_t next_id = 111;
    auto add = [&next_id](
                       SessionProtos::DataMessage& data,
                       std::string_view url,
                       size_t key_len,
                       auto&& fill) {
        auto* a = data.add_attachments();
        a->set_id(next_id++);
        a->set_url(std::string{url});
        a->set_key(std::string(key_len, 'k'));
        fill(a);
    };

    // Three attachments and no body at all: the case that used to be discarded outright, since a
    // message was only history if it had text.
    deliver(*c,
            peer,
            "",
            from_epoch_ms(1000),
            "h1",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& data) {
                // Stream-encrypted, as anything we send is: 32-byte key, `d` in the url.
                add(data, "http://fs.example/file/111#d", 32, [](auto* a) {
                    a->set_size(4321);
                    a->set_contenttype("image/png");
                    a->set_filename("kitten.png");
                    a->set_width(640);
                    a->set_height(480);
                });
                // Legacy, which is what every current client actually sends: 64-byte key and a
                // digest, and no fragment on the url.
                add(data, "http://fs.example/file/222", 64, [](auto* a) {
                    a->set_digest(std::string(32, 'd'));
                    a->set_size(99);
                    a->set_contenttype("application/pdf");
                    a->set_filename("invoice.pdf");
                    a->set_flags(1);
                });
                // A pointer with no url at all: unfetchable, but still one of three files the
                // sender said were here, so it is not silently dropped.
                add(data, "", 32, [](auto* a) { a->clear_url(); });
            });
    sync(*c);

    auto msgs = c->conversation(ConversationId::dm(peer.session_id), await)->messages(await);
    REQUIRE(msgs.size() == 1);
    const auto& m = msgs[0];
    CHECK(m.body.empty());
    CHECK_FALSE(m.outgoing);
    REQUIRE(m.attachments.size() == 3);

    CHECK(m.attachments[0].index == 0);
    CHECK(m.attachments[0].content_type == "image/png");
    CHECK(m.attachments[0].filename == "kitten.png");
    CHECK(m.attachments[0].size == 4321);
    CHECK(m.attachments[0].width == 640);
    CHECK(m.attachments[0].height == 480);
    CHECK_FALSE(m.attachments[0].voice_message);
    // Always true on an incoming attachment: the file server is where it came from.
    CHECK(m.attachments[0].uploaded);

    CHECK(m.attachments[1].voice_message);
    CHECK(m.attachments[1].uploaded);

    // The unusable one still occupies its position, so the indices keep meaning what the sender
    // meant by them.
    CHECK(m.attachments[2].index == 2);
    CHECK_FALSE(m.attachments[2].uploaded);
}

TEST_CASE("Client: a message reports the attachments it carries", "[client][send][attachments]") {
    TempClient c;
    auto* net = attach_mock_network(c->core);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_attach", 7);
    std::filesystem::create_directories(dir);
    auto write = [&](std::string_view name) {
        auto p = dir / name;
        std::ofstream{p, std::ios::binary} << "not really a file";
        return p;
    };
    // Names chosen for the ways extension parsing goes wrong: several dots, and a dotfile whose
    // leading dot must not be read as an extension.
    auto photo = write("holiday.snap.PNG");
    auto doc = write("notes.pdf");
    auto mystery = write(".hidden");

    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto id = c->send_message(
            ConversationId::dm(me),
            {.attachments =
                     {OutgoingAttachment{.path = photo},
                      OutgoingAttachment{
                              .path = doc, .content_type = "application/x-my-own", .width = 4},
                      OutgoingAttachment{.path = mystery, .voice_message = true}}},
            await);

    auto msg = c->message(id, await);
    REQUIRE(msg.has_value());

    // An attachments-only message: nothing to show but the files, which is exactly the case that
    // used to be indistinguishable from an empty message.
    CHECK(msg->body.empty());
    REQUIRE(msg->attachments.size() == 3);

    // Ordered by position, and that position is what an upload report names.
    CHECK(msg->attachments[0].index == 0);
    CHECK(msg->attachments[1].index == 1);
    CHECK(msg->attachments[2].index == 2);

    // Inferred from the last extension, case-insensitively, when the caller named none...
    CHECK(msg->attachments[0].content_type == "image/png");
    CHECK(msg->attachments[0].filename == "holiday.snap.PNG");
    CHECK_FALSE(msg->attachments[0].voice_message);

    // ...and never overriding one the caller did name.
    CHECK(msg->attachments[1].content_type == "application/x-my-own");
    CHECK(msg->attachments[1].width == 4);
    CHECK_FALSE(msg->attachments[1].height.has_value());

    // A dotfile has no extension -- "hidden" is the name, not the type -- so it falls back rather
    // than being given a type invented out of the filename.
    CHECK(msg->attachments[2].content_type == "application/octet-stream");
    CHECK(msg->attachments[2].filename == ".hidden");
    CHECK(msg->attachments[2].voice_message);

    // Each file reached the server, and the size recorded is the file's own -- read at upload time,
    // not the padded ciphertext's length that the server reports back.
    sync(*c);
    msg = c->message(id, await);
    REQUIRE(msg.has_value());
    for (const auto& a : msg->attachments) {
        CHECK(a.uploaded);
        CHECK(a.size == static_cast<int64_t>(std::string_view{"not really a file"}.size()));
    }

    // The same list reaches a paged read, not only the single-message one.
    auto page = c->conversation(ConversationId::dm(me), await)->messages(await);
    REQUIRE(page.size() == 1);
    CHECK(page[0].attachments.size() == 3);
    CHECK(page[0].attachments[0].content_type == "image/png");

    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: an attachment carries a thumbhash in both directions", "[client][attachments]") {
    TempClient c;
    SenderKeys peer;
    attach_mock_network(c->core);

    // Opaque to libsession in both directions: stored and handed back as written, never decoded
    // and never checked against the file.  Bytes rather than text, and these are not valid
    // ThumbHashes -- which is the point, since nothing here looks.
    const std::vector<std::byte> incoming_hash(20, std::byte{0x7f});
    const std::vector<std::byte> outgoing_hash(25, std::byte{0x2a});

    deliver(*c,
            peer,
            "",
            from_epoch_ms(1000),
            "h1",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& data) {
                auto* a = data.add_attachments();
                a->set_id(111);
                a->set_url("http://fs.example/file/111#d");
                a->set_key(std::string(32, 'k'));
                a->set_contenttype("image/png");
                a->set_thumbhash(incoming_hash.data(), incoming_hash.size());
            });
    sync(*c);

    auto msgs = c->conversation(ConversationId::dm(peer.session_id), await)->messages(await);
    REQUIRE(msgs.size() == 1);
    REQUIRE(msgs[0].attachments.size() == 1);
    CHECK(msgs[0].attachments[0].thumbhash == incoming_hash);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_thumbhash", 7);
    std::filesystem::create_directories(dir);
    auto photo = dir / "beach.png";
    std::ofstream{photo, std::ios::binary} << "not really a file";

    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    // Supplied by the sender, like width/height: encoding one needs the pixels, so an unset
    // thumbhash stays unset.
    auto id = c->send_message(
            ConversationId::dm(me),
            {.attachments =
                     {OutgoingAttachment{.path = photo, .thumbhash = outgoing_hash},
                      OutgoingAttachment{.path = photo}}},
            await);

    auto msg = c->message(id, await);
    REQUIRE(msg.has_value());
    REQUIRE(msg->attachments.size() == 2);
    CHECK(msg->attachments[0].thumbhash == outgoing_hash);
    CHECK_FALSE(msg->attachments[1].thumbhash.has_value());

    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: an over-long thumbhash is refused", "[client][attachments]") {
    TempClient c;
    SenderKeys peer;
    attach_mock_network(c->core);

    // One byte past MAX_THUMBHASH_SIZE, which is the largest the format can produce.
    const std::vector<std::byte> too_long(MAX_THUMBHASH_SIZE + 1, std::byte{0x01});

    deliver(*c,
            peer,
            "",
            from_epoch_ms(1000),
            "h1",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& data) {
                auto* a = data.add_attachments();
                a->set_id(222);
                a->set_url("http://fs.example/file/222#d");
                a->set_key(std::string(32, 'k'));
                a->set_contenttype("image/png");
                a->set_filename("wide.png");
                a->set_thumbhash(too_long.data(), too_long.size());
            });
    sync(*c);

    // Dropped, not rejected: the placeholder is decoration a remote peer supplied, and losing it
    // must not cost the attachment it describes.
    auto msgs = c->conversation(ConversationId::dm(peer.session_id), await)->messages(await);
    REQUIRE(msgs.size() == 1);
    REQUIRE(msgs[0].attachments.size() == 1);
    CHECK_FALSE(msgs[0].attachments[0].thumbhash.has_value());
    CHECK(msgs[0].attachments[0].filename == "wide.png");
    CHECK(msgs[0].attachments[0].content_type == "image/png");

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_thumbhash_cap", 7);
    std::filesystem::create_directories(dir);
    auto photo = dir / "beach.png";
    std::ofstream{photo, std::ios::binary} << "not really a file";

    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    // Thrown on the way out, where the value is our own caller's and the mistake is theirs to see.
    CHECK_THROWS_AS(
            c->send_message(
                    ConversationId::dm(me),
                    {.attachments = {OutgoingAttachment{.path = photo, .thumbhash = too_long}}},
                    await),
            std::invalid_argument);

    // The longest one that is allowed still goes through.
    const std::vector<std::byte> longest(MAX_THUMBHASH_SIZE, std::byte{0x01});
    auto id = c->send_message(
            ConversationId::dm(me),
            {.attachments = {OutgoingAttachment{.path = photo, .thumbhash = longest}}},
            await);
    auto msg = c->message(id, await);
    REQUIRE(msg.has_value());
    REQUIRE(msg->attachments.size() == 1);
    CHECK(msg->attachments[0].thumbhash == longest);

    std::filesystem::remove_all(dir);
}

TEST_CASE(
        "Client: saving an attachment fetches, decrypts and reports it", "[client][attachments]") {
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    // So the notification below goes out as a v1 send rather than queueing behind a key fetch.
    TestHelper::seed_pfs_nak(c->core, peer.session_id);

    // A real attachment: encrypted exactly as a sender would, so what the download serves is what
    // the decryptor has to cope with, chunk boundaries and padding included.
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

    auto msgs = c->conversation(ConversationId::dm(peer.session_id), await)->messages(await);
    REQUIRE(msgs.size() == 1);
    auto msg_id = msgs[0].id;

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_save", 7);
    std::filesystem::create_directories(dir);
    auto dest = dir / "saved.bin";

    std::vector<AttachmentProgress> reports;
    std::promise<std::optional<Error>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(
            msg_id,
            0,
            dest,
            [&](const AttachmentProgress& p) { reports.push_back(p); },
            [&](auto r) {
                done.set_value(r ? std::nullopt : std::optional{std::move(r).error()});
            });

    // Nothing is fetched until asked, and asking produces exactly one download.
    sync(*c);
    REQUIRE(net->downloads.size() == 1);
    CHECK(net->downloads[0].download_url == "http://fs.example/file/1#d");

    REQUIRE(serve_downloads(*net, ciphertext) == 1);
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
    CHECK_FALSE(waiter.get().has_value());

    // The file is the file, byte for byte, with the padding that hid its length gone.
    REQUIRE(std::filesystem::exists(dest));
    CHECK(std::filesystem::file_size(dest) == plaintext.size());
    {
        std::ifstream in{dest, std::ios::binary};
        std::vector<std::byte> got(plaintext.size());
        in.read(reinterpret_cast<char*>(got.data()), got.size());
        CHECK(!!(got == plaintext));
    }
    // ...and nothing is left behind that could be mistaken for it.
    CHECK_FALSE(std::filesystem::exists(dest.string() + ".part"));

    // Progress reported as a send does: an opening 0/0 that says it has begun, then exactly one
    // terminal result.  Each report says which attachment of which message it is about, since a
    // caller may be watching several.
    REQUIRE(reports.size() >= 2);
    CHECK_FALSE(reports.front().result.has_value());
    CHECK(reports.front().done == 0);
    CHECK(reports.front().total == 0);
    CHECK(succeeded(reports.back().result));
    for (const auto& r : reports) {
        CHECK(r.message_id == msg_id);
        CHECK(r.index == 0);
    }

    // And the sender is told, since nothing said otherwise.
    sync(*c);
    CHECK(stores(*net).size() == 1);

    // We also remember that we saved it, which is what stops a client offering "save" forever and
    // writing a second copy.  Recorded whether or not the sender was told.
    auto saved = c->message(msg_id, await);
    REQUIRE(saved.has_value());
    REQUIRE(saved->attachments.size() == 1);
    REQUIRE(saved->attachments[0].saved_at.has_value());
    CHECK(*saved->attachments[0].saved_at > from_epoch_ms(0));

    std::filesystem::remove_all(dir);
}

TEST_CASE(
        "Client: a save can be kept to ourselves, and a bad one writes nothing",
        "[client][attachments]") {
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    TestHelper::seed_pfs_nak(c->core, peer.session_id);

    std::vector<std::byte> plaintext(500, std::byte{7});
    auto seed = random::random(32);
    auto [ciphertext, key] = attachment::encrypt(seed, plaintext, attachment::Domain::ATTACHMENT);

    auto add = [&](SessionProtos::DataMessage& data) {
        auto* a = data.add_attachments();
        a->set_id(1);
        a->set_url("http://fs.example/file/2#d");
        a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
        a->set_size(plaintext.size());
    };
    deliver(*c, peer, "", from_epoch_ms(2000), "h2", "", std::nullopt, add, 43);
    sync(*c);
    auto msg_id =
            c->conversation(ConversationId::dm(peer.session_id), await)->messages(await)[0].id;

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_save", 7);
    std::filesystem::create_directories(dir);

    // The promise is shared rather than captured by reference: save_attachment's callback outlives
    // this scope, and a reference to a local here would dangle by the time the download is served.
    auto save = [&](const std::filesystem::path& dest, bool notify) {
        auto done = std::make_shared<std::promise<std::optional<Error>>>();
        auto waiter = done->get_future();
        c->Client::save_attachment(
                msg_id,
                0,
                dest,
                nullptr,
                [done](auto r) {
                    done->set_value(r ? std::nullopt : std::optional{std::move(r).error()});
                },
                notify);
        sync(*c);
        return waiter;
    };

    // Asked not to tell them, we do not -- the file still lands.
    {
        auto quiet = dir / "quiet.bin";
        auto waiter = save(quiet, false);
        REQUIRE(serve_downloads(*net, ciphertext) == 1);
        REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
        CHECK_FALSE(waiter.get().has_value());
        CHECK(std::filesystem::exists(quiet));
        sync(*c);
        CHECK(stores(*net).empty());

        // Telling them and remembering it ourselves are separate: a private save is still a save.
        CHECK(c->message(msg_id, await)->attachments[0].saved_at.has_value());
    }

    // The account's own answer refuses the notification even when the caller asked for it, so a
    // client that never grew a setting for this still honours one made on another device.
    {
        in_configs(*c, [](auto& cfg) { cfg.user_profile().set_notify_media_saved(false); });
        auto loud = dir / "still-quiet.bin";
        auto waiter = save(loud, true);
        REQUIRE(serve_downloads(*net, ciphertext) == 1);
        REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
        CHECK_FALSE(waiter.get().has_value());
        CHECK(std::filesystem::exists(loud));
        sync(*c);
        CHECK(stores(*net).empty());
        in_configs(*c, [](auto& cfg) { cfg.user_profile().set_notify_media_saved(true); });
    }

    // A file that fails to authenticate is a failure, not a corrupt file on disk: the ciphertext is
    // written to a temporary name and only renamed once it has been decrypted whole.
    {
        auto bad = dir / "bad.bin";
        auto corrupt = ciphertext;
        corrupt[corrupt.size() / 2] ^= std::byte{0xff};
        auto waiter = save(bad, true);
        REQUIRE(serve_downloads(*net, corrupt) == 1);
        REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
        CHECK(waiter.get().has_value());
        CHECK_FALSE(std::filesystem::exists(bad));
        CHECK_FALSE(std::filesystem::exists(bad.string() + ".part"));
        // Nothing was saved, so nobody is told one was.
        sync(*c);
        CHECK(stores(*net).empty());
    }

    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: an attachment we sent can be saved back", "[client][attachments]") {
    // The whole path in one go: a file is encrypted and uploaded by sending it, and then fetched,
    // decrypted and written by saving it.  Nothing here knows what the other half did except
    // through what was stored -- the url, its `d` fragment, the key and the size -- so a
    // disagreement between the two shows up as bytes that do not match.
    TempClient c;
    auto* net = attach_mock_network(c->core);

    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_roundtrip", 7);
    std::filesystem::create_directories(dir);
    auto source = dir / "original.bin";

    // Larger than one encryption chunk, so the streaming path is what runs rather than a single
    // block that would hide a chunk-boundary bug.
    std::vector<std::byte> contents(70 * 1024);
    for (size_t i = 0; i < contents.size(); i++)
        contents[i] = static_cast<std::byte>((i * 7 + i / 251) % 256);
    {
        std::ofstream out{source, std::ios::binary};
        out.write(reinterpret_cast<const char*>(contents.data()), contents.size());
    }

    auto id = c->send_message(
            ConversationId::dm(me),
            {.body = "here it is", .attachments = {OutgoingAttachment{.path = source}}},
            await);
    sync(*c);
    REQUIRE(accept_stores(*net) == 1);

    auto msg = c->message(id, await);
    REQUIRE(msg.has_value());
    REQUIRE(msg->attachments.size() == 1);
    CHECK(msg->attachments[0].uploaded);
    // What the pointer advertises is the file's own length, not the padded ciphertext's.
    CHECK(msg->attachments[0].size == static_cast<int64_t>(contents.size()));

    auto dest = dir / "saved.bin";
    std::promise<std::optional<Error>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(msg->id, 0, dest, nullptr, [&done](auto r) {
        done.set_value(r ? std::nullopt : std::optional{std::move(r).error()});
    });
    sync(*c);

    // Served from what the upload left behind, found by the id in the url the send generated.
    REQUIRE(serve_downloads(*net) == 1);
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
    CHECK_FALSE(waiter.get().has_value());

    REQUIRE(std::filesystem::exists(dest));
    REQUIRE(std::filesystem::file_size(dest) == contents.size());
    std::ifstream in{dest, std::ios::binary};
    std::vector<std::byte> got(contents.size());
    in.read(reinterpret_cast<char*>(got.data()), got.size());
    CHECK(!!(got == contents));

    // Stamped, even though the message is outgoing: this conversation is with ourselves, so the
    // recipient saving it and us saving it are the same event.
    CHECK(c->message(id, await)->attachments[0].saved_at.has_value());

    std::filesystem::remove_all(dir);
}

TEST_CASE(
        "Client: a save does not destroy files it was not asked to touch",
        "[client][attachments]") {
    TempClient c;
    auto* net = attach_mock_network(c->core);

    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_clobber", 7);
    std::filesystem::create_directories(dir);
    auto source = dir / "sent.bin";
    std::vector<std::byte> contents(1024, std::byte{0x11});
    {
        std::ofstream out{source, std::ios::binary};
        out.write(reinterpret_cast<const char*>(contents.data()), contents.size());
    }
    auto id = c->send_message(
            ConversationId::dm(me),
            {.body = "here", .attachments = {OutgoingAttachment{.path = source}}},
            await);
    sync(*c);
    REQUIRE(accept_stores(*net) == 1);

    auto dest = dir / "report.pdf";

    // Two files the caller never mentioned: somebody's own scratch file from another downloader,
    // and something that appeared at the destination after the caller checked it was free.
    auto their_part = dir / "report.pdf.part";
    {
        std::ofstream out{their_part};
        out << "theirs";
    }
    {
        std::ofstream out{dest};
        out << "appeared since";
    }

    std::promise<std::pair<std::optional<Error>, std::filesystem::path>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(id, 0, dest, nullptr, [&done](auto r) {
        if (r)
            done.set_value({std::nullopt, *std::move(r)});
        else
            done.set_value({std::move(r).error(), {}});
    });
    sync(*c);
    REQUIRE(serve_downloads(*net) == 1);
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
    auto [err, saved_to] = waiter.get();
    REQUIRE_FALSE(err.has_value());

    // Neither file was touched, and the caller is told where its own went.
    CHECK(std::filesystem::exists(their_part));
    CHECK(std::filesystem::file_size(their_part) == 6);
    CHECK(std::filesystem::file_size(dest) == 14);
    CHECK(saved_to == dir / "report (1).pdf");
    CHECK(std::filesystem::file_size(saved_to) == contents.size());

    std::filesystem::remove_all(dir);
}

TEST_CASE(
        "Client: an approved replacement is not renamed out of the way", "[client][attachments]") {
    TempClient c;
    auto* net = attach_mock_network(c->core);

    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_replace", 7);
    std::filesystem::create_directories(dir);
    auto source = dir / "sent.bin";
    std::vector<std::byte> contents(1024, std::byte{0x22});
    {
        std::ofstream out{source, std::ios::binary};
        out.write(reinterpret_cast<const char*>(contents.data()), contents.size());
    }
    auto id = c->send_message(
            ConversationId::dm(me),
            {.body = "here", .attachments = {OutgoingAttachment{.path = source}}},
            await);
    sync(*c);
    REQUIRE(accept_stores(*net) == 1);

    auto dest = dir / "report.pdf";
    {
        std::ofstream out{dest};
        out << "the one the user chose to replace";
    }

    std::promise<std::filesystem::path> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(
            id,
            0,
            dest,
            nullptr,
            [&done](auto r) { done.set_value(r ? *std::move(r) : std::filesystem::path{}); },
            /*notify_sender=*/true,
            /*replace=*/true);
    sync(*c);
    REQUIRE(serve_downloads(*net) == 1);
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);

    // Renaming here would be worse than clobbering: the file the user agreed to replace would still
    // be sitting there, and their answer would have been thrown away.
    CHECK(waiter.get() == dest);
    CHECK(std::filesystem::file_size(dest) == contents.size());
    CHECK_FALSE(std::filesystem::exists(dir / "report (1).pdf"));

    std::filesystem::remove_all(dir);
}

TEST_CASE(
        "Client: saving what we sent someone else does not claim they saved it",
        "[client][attachments]") {
    TempClient c;
    auto* net = attach_mock_network(c->core);

    SenderKeys peer;
    TestHelper::seed_pfs_nak(c->core, peer.session_id);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_theirs", 7);
    std::filesystem::create_directories(dir);
    auto source = dir / "sent.bin";
    std::vector<std::byte> contents(2048, std::byte{0x5a});
    {
        std::ofstream out{source, std::ios::binary};
        out.write(reinterpret_cast<const char*>(contents.data()), contents.size());
    }

    auto id = c->send_message(
            ConversationId::dm(peer.session_id),
            {.body = "for you", .attachments = {OutgoingAttachment{.path = source}}},
            await);
    sync(*c);
    REQUIRE(accept_stores(*net) >= 1);

    auto dest = dir / "my-copy.bin";
    std::promise<std::optional<Error>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(id, 0, dest, nullptr, [&done](auto r) {
        done.set_value(r ? std::nullopt : std::optional{std::move(r).error()});
    });
    sync(*c);
    REQUIRE(serve_downloads(*net) == 1);
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
    REQUIRE_FALSE(waiter.get().has_value());
    REQUIRE(std::filesystem::exists(dest));

    // `saved_at` on an outgoing attachment means *they* saved it, which is what lets a sender read
    // it as "the file reached a person rather than a file server".  Our own copy says nothing about
    // that, so it must leave the field alone -- otherwise a UI reports "they have it" about someone
    // who may never have opened the conversation.
    auto msg = c->message(id, await);
    REQUIRE(msg);
    REQUIRE(msg->attachments.size() == 1);
    CHECK_FALSE(msg->attachments[0].saved_at.has_value());

    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: a peer can tell us they saved what we sent", "[client][attachments]") {
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);

    TestHelper::seed_pfs_nak(c->core, peer.session_id);
    TestHelper::seed_pfs_nak(c->core, own_sid(*c));

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_notified", 7);
    std::filesystem::create_directories(dir);
    auto one = dir / "one.bin";
    auto two = dir / "two.bin";
    std::ofstream{one, std::ios::binary} << "first file";
    std::ofstream{two, std::ios::binary} << "second file";

    auto id = c->send_message(
            ConversationId::dm(peer.session_id),
            {.body = "two of them",
             .attachments = {OutgoingAttachment{.path = one}, OutgoingAttachment{.path = two}}},
            await);
    sync(*c);
    REQUIRE(accept_stores(*net) == 2);

    auto sent = c->message(id, await);
    REQUIRE(sent.has_value());
    REQUIRE(sent->attachments.size() == 2);
    // Nobody has said anything yet, and an upload reaching the file server is not someone saving
    // it.
    CHECK_FALSE(sent->attachments[0].saved_at.has_value());
    CHECK_FALSE(sent->attachments[1].saved_at.has_value());

    // What the peer's client sends when its user saves one file out of the message.
    auto msgid = c->core.loop().call_get([&] {
        return c->core.database().conn().prepared_get<int64_t>(
                "SELECT msgid FROM messages WHERE id = ?", id);
    });
    auto notify = [&](auto&& fill, sys_ms at) {
        SessionProtos::Content content;
        content.set_sigtimestamp(static_cast<uint64_t>(epoch_ms(at)));
        auto* note = content.mutable_dataextractionnotification();
        note->set_type(SessionProtos::DataExtractionNotification::MEDIA_SAVED);
        fill(note);

        auto plaintext = content.SerializeAsString();
        auto encoded = encode_dm_v1(
                std::as_bytes(std::span{plaintext}), peer.ed_sk, at, own_sid(*c), std::nullopt);
        core::SwarmMessage sm{
                encoded, random::unique_id("h", 8), at, from_epoch_ms(1'000'000'000'000)};
        c->core.loop().call_get([&] {
            c->core.receive_messages({&sm, 1}, config::Namespace::Default, true);
            return 0;
        });
        sync(*c);
    };

    auto saved_at = from_epoch_ms(9'000'000);
    notify(
            [&](auto* note) {
                note->set_msgtimestamp(static_cast<uint64_t>(epoch_ms(sent->timestamp)));
                note->set_msgid(msgid);
                note->set_attindex(1);
            },
            saved_at);

    auto after = c->message(id, await);
    REQUIRE(after.has_value());
    // Only the one they named, and stamped with when *they* saved it -- not the message's own
    // timestamp, which is what identifies it and is generally older.
    CHECK_FALSE(after->attachments[0].saved_at.has_value());
    REQUIRE(after->attachments[1].saved_at.has_value());
    CHECK(*after->attachments[1].saved_at == saved_at);

    // -1 is "all of them, together", which is what saving from a gallery view reports.
    auto all_at = from_epoch_ms(9'500'000);
    notify(
            [&](auto* note) {
                note->set_msgtimestamp(static_cast<uint64_t>(epoch_ms(sent->timestamp)));
                note->set_msgid(msgid);
                note->set_attindex(-1);
            },
            all_at);

    auto all = c->message(id, await);
    REQUIRE(all->attachments[0].saved_at == all_at);
    // The later save overwrites the earlier one: what this answers is "is there any point offering
    // save again", not a history of every time they did.
    CHECK(all->attachments[1].saved_at == all_at);

    // A notification naming a message we do not have changes nothing, and neither does one that
    // names no message at all -- which is every notification the other clients send today, since
    // their `timestamp` field means something different in each of them.
    notify(
            [&](auto* note) {
                note->set_msgtimestamp(static_cast<uint64_t>(epoch_ms(sent->timestamp)));
                note->set_msgid(msgid + 1);
                note->set_attindex(0);
            },
            from_epoch_ms(9'900'000));
    notify([&](auto* note) { note->set_timestamp(12345); }, from_epoch_ms(9'900'000));

    auto unchanged = c->message(id, await);
    CHECK(unchanged->attachments[0].saved_at == all_at);
    CHECK(unchanged->attachments[1].saved_at == all_at);

    std::filesystem::remove_all(dir);
}

TEST_CASE("Client: a legacy attachment is saved", "[client][attachments][legacy]") {
    // Every Session client still sends attachments encrypted the old way, so this is the path most
    // received attachments actually take.  The blob is fixed rather than generated: libsession has
    // no legacy encryptor -- deliberately, since we never send these -- so producing one here would
    // mean writing the very thing we chose not to have, and testing it against itself.  It came
    // from an independent implementation written against session-android's
    // AttachmentCipherInputStream.
    //
    // 56 bytes of text, zero-padded to 128, then AES-256-CBC with an HMAC and a digest over it.
    constexpr auto LEGACY_KEY =
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
            "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"_hex_b;
    constexpr auto LEGACY_BLOB =
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf22bf91f23b4781cc75fcba799b05fa6d"
            "f93931dc76588ba849c27514c2e21560130db54a94a65303ea60adc0166ff90c"
            "e07d033f2107b1ed38ddc006b1c71c3bb796d591ebbb2f9877027962dcb6ab13"
            "b10b97cb736fddd7e2edd7b0908cd2b0ba84be5def8e67316556917af6faf793"
            "56695fbd811fad5de80b9f70b15eb6987e18eab948150964e6309b24c3367b59"
            "7a75cd3520a42061ce5ef6a0d647b1eb310fc355214c1f3eab964a9e7df62c65"_hex_b;
    constexpr auto LEGACY_DIGEST =
            "f75f0a8286252a371f131c711ddc5b04cc69092c8b8397b0460f1bc6946907c4"_hex_b;
    constexpr auto LEGACY_TEXT = "a legacy attachment, from a client that has not moved on"sv;

    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    TestHelper::seed_pfs_nak(c->core, peer.session_id);

    // No `d` fragment on the url, a 64-byte key and a digest: that combination is what tells the
    // save which of the two schemes to use, and nothing else does.
    deliver(
            *c,
            peer,
            "",
            from_epoch_ms(3000),
            "legacy_hash",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& data) {
                auto* a = data.add_attachments();
                a->set_id(9);
                a->set_url("http://fs.example/file/legacy1");
                a->set_key(std::string{
                        reinterpret_cast<const char*>(LEGACY_KEY.data()), LEGACY_KEY.size()});
                a->set_digest(std::string{
                        reinterpret_cast<const char*>(LEGACY_DIGEST.data()), LEGACY_DIGEST.size()});
                a->set_size(LEGACY_TEXT.size());
                a->set_filename("legacy.txt");
            },
            44);
    sync(*c);

    auto msgs = c->conversation(ConversationId::dm(peer.session_id), await)->messages(await);
    REQUIRE(msgs.size() == 1);
    REQUIRE(msgs[0].attachments.size() == 1);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_legacy", 7);
    std::filesystem::create_directories(dir);
    auto dest = dir / "legacy.txt";

    std::promise<std::optional<Error>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(msgs[0].id, 0, dest, nullptr, [&done](auto r) {
        done.set_value(r ? std::nullopt : std::optional{std::move(r).error()});
    });
    sync(*c);

    REQUIRE(serve_downloads(*net, LEGACY_BLOB) == 1);
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
    CHECK_FALSE(waiter.get().has_value());

    // Trimmed to the length the pointer claimed, with the zero padding that hid it gone.
    REQUIRE(std::filesystem::exists(dest));
    REQUIRE(std::filesystem::file_size(dest) == LEGACY_TEXT.size());
    std::ifstream in{dest, std::ios::binary};
    std::string got{std::istreambuf_iterator<char>{in}, {}};
    CHECK(got == LEGACY_TEXT);

    std::filesystem::remove_all(dir);
}

TEST_CASE(
        "Client: a message with attachments needs readable files", "[client][send][attachments]") {
    TempClient c{};
    auto me = own_sid(*c);

    CHECK_THROWS_AS(
            c->send_message(
                    ConversationId::dm(me),
                    {.body = "here you go",
                     .attachments = {OutgoingAttachment{.path = "/nonexistent/nope.png"}}},
                    await),
            std::invalid_argument);

    // Rejected before anything was stored, rather than leaving a message that can never be sent --
    // and not even a conversation, which is a stronger thing to be able to say than that it has no
    // messages in it.
    CHECK_FALSE(c->conversation(ConversationId::dm(me), await).has_value());
}

TEST_CASE(
        "Client: attachments that cannot be uploaded fail the message",
        "[client][send][attachments]") {
    auto file = std::filesystem::temp_directory_path() / "libsession_attachment_test.bin";
    {
        std::ofstream out{file, std::ios::binary};
        out << "some file contents";
    }

    Recorder r;
    TempClient c{r.handlers()};
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    std::vector<std::tuple<size_t, int64_t, int64_t, std::optional<Expected<void>>>> reports;

    // No network is attached, so the upload cannot even be attempted.  The message must still end
    // up somewhere final: the failure is what a caller waits on, and a message left in `uploading`
    // would wait forever.
    auto id = c->send_message(
            ConversationId::dm(me),
            {.body = "here you go", .attachments = {OutgoingAttachment{.path = file}}},
            [&](size_t idx, int64_t sent, int64_t total, std::optional<Expected<void>> result) {
                reports.emplace_back(idx, sent, total, std::move(result));
            },
            await);
    sync(*c);

    auto msg = c->message(id, await);
    REQUIRE(msg);
    CHECK(msg->body == "here you go");
    CHECK(msg->send_state == SendState::failed);

    REQUIRE(reports.size() == 1);
    auto& [idx, sent, total, result] = reports.front();
    CHECK(idx == 0);
    CHECK(failure_code(result) == err::network_unavailable);

    std::filesystem::remove(file);
}

TEST_CASE(
        "Client: throttling never squelches what a caller must hear",
        "[client][send][attachments]") {
    auto file = std::filesystem::temp_directory_path() / "libsession_throttle_test.bin";
    {
        std::ofstream out{file, std::ios::binary};
        out << "some file contents";
    }

    TempClient c;
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    // Long enough that anything passing through the throttle would be dropped: what arrives is
    // exactly what is exempt from it.
    c->set_high_freq_dispatch_interval(1h);

    std::vector<std::optional<Expected<void>>> results;
    auto record = [&](size_t, int64_t, int64_t, std::optional<Expected<void>> result) {
        results.push_back(std::move(result));
    };
    auto id = c->send_message(
            ConversationId::dm(me),
            {.body = "here you go", .attachments = {OutgoingAttachment{.path = file}}},
            record,
            await);
    sync(*c);

    // With no network the upload cannot start, so the one report is its failure -- which is the
    // point: an outcome is never a thing the throttle may drop.
    CHECK(c->message(id, await)->send_state == SendState::failed);
    REQUIRE(results.size() == 1);
    CHECK(failure_code(results.front()) == err::network_unavailable);

    std::filesystem::remove(file);
}

TEST_CASE("Client: retrying a send that cannot work", "[client][send][attachments]") {
    auto file = std::filesystem::temp_directory_path() / "libsession_retry_test.bin";
    {
        std::ofstream out{file, std::ios::binary};
        out << "some file contents";
    }

    Recorder r;
    TempClient c{r.handlers()};
    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto id = c->send_message(
            ConversationId::dm(me),
            {.body = "here you go", .attachments = {OutgoingAttachment{.path = file}}},
            await);
    sync(*c);
    REQUIRE(c->message(id, await)->send_state == SendState::failed);

    // Retrying is allowed while the failure is one that might not recur, and reports itself as
    // started rather than as succeeded -- the outcome arrives through the message's state.
    std::vector<std::optional<Expected<void>>> results;
    auto record = [&](size_t, int64_t, int64_t, std::optional<Expected<void>> result) {
        results.push_back(std::move(result));
    };
    CHECK(c->retry_send(id, record, await));
    sync(*c);
    REQUIRE(results.size() == 1);
    CHECK(failure_code(results.front()) == err::network_unavailable);
    CHECK(c->message(id, await)->send_state == SendState::failed);

    // With the file gone the retry can only ever fail the same way, so the message becomes
    // terminal rather than staying something an application would offer to try again.
    std::filesystem::remove(file);

    results.clear();
    CHECK(c->retry_send(id, record, await));
    sync(*c);
    REQUIRE(results.size() == 1);
    CHECK(failure_code(results.front()) == err::attachment_file_missing);
    CHECK(c->message(id, await)->send_state == SendState::unsendable);

    // ... and being terminal, it is refused rather than attempted again.
    CHECK_FALSE(c->retry_send(id, await));
}

TEST_CASE(
        "Client: a stream attachment must be the size its sender claimed",
        "[client][attachments][size]") {
    // The pointer's size is exact -- the file server is told the byte count up front and refuses
    // anything else -- so a file that decrypts to a different length is not a file we asked for.
    // Nothing else catches this for a stream attachment: the format strips its own padding and
    // never consults the pointer, so before this the claim was simply ignored.
    // One short, one long: over-reporting and under-reporting are both lies.
    int64_t claimed = GENERATE(8999, 9001);

    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);

    std::vector<std::byte> plaintext(9000);
    random::fill(plaintext);
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
            [&, claimed](SessionProtos::DataMessage& data) {
                auto* a = data.add_attachments();
                a->set_id(1);
                a->set_url("http://fs.example/file/1#d");
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                // A lie in one direction or the other; the truth is 9000.
                a->set_size(static_cast<uint32_t>(claimed));
                a->set_filename("payload.bin");
            },
            42);
    sync(*c);

    auto msg_id =
            c->conversation(ConversationId::dm(peer.session_id), await)->messages(await)[0].id;

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_size", 7);
    std::filesystem::create_directories(dir);
    auto dest = dir / "saved.bin";

    std::promise<std::optional<Error>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(msg_id, 0, dest, nullptr, [&](auto r) {
        done.set_value(r ? std::nullopt : std::optional{std::move(r).error()});
    });

    sync(*c);
    REQUIRE(serve_downloads(*net, ciphertext) == 1);
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);

    // Reported as a failure rather than saved short or saved long.
    auto err = waiter.get();
    REQUIRE(err.has_value());
    CHECK(err->message.find("sender said") != std::string::npos);

    // And nothing is left on disk that could be mistaken for the file.
    CHECK_FALSE(std::filesystem::exists(dest));
    CHECK_FALSE(std::filesystem::exists(dest.string() + ".part"));

    std::filesystem::remove_all(dir);
}

TEST_CASE(
        "Client: two askers for one attachment share one download", "[client][attachments][join]") {
    // A conversation opening while its attachments are being fetched asks for bytes that are not in
    // the cache yet.  Without joining, that starts a second download of the same file: the cache is
    // still empty, so a display sees a miss and fetches it again.
    TempCacheDir dir;
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    std::vector<std::byte> plaintext(9000);
    random::fill(plaintext);
    auto seed = random::random(32);
    auto [ciphertext, key] = attachment::encrypt(seed, plaintext, attachment::Domain::ATTACHMENT);
    net->served["shared"] = ciphertext;

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
                a->set_url(network::file_server::generate_download_url("shared", {}, true));
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                a->set_size(plaintext.size());
                a->set_contenttype("image/png");
            },
            42);
    sync(*c);
    auto msg_id =
            c->conversation(ConversationId::dm(peer.session_id), await)->messages(await)[0].id;

    std::vector<std::optional<std::vector<std::byte>>> got(2);
    std::vector<std::vector<AttachmentProgress>> seen(2);
    for (int i = 0; i < 2; i++)
        c->attachment_data(
                msg_id,
                0,
                [&, i](const AttachmentProgress& p) { seen[i].push_back(p); },
                [&, i](auto r) {
                    REQUIRE(r.has_value());
                    got[i] = *std::move(r);
                });
    sync(*c);

    // One transfer, not two.
    REQUIRE(net->downloads.size() == 1);

    REQUIRE(serve_downloads(*net, ciphertext) == 1);
    sync(*c);

    // Both askers get the whole file.
    for (int i = 0; i < 2; i++) {
        REQUIRE(got[i]);
        CHECK(*got[i] == plaintext);
        // ...and both were told how it was going, not only the one that started it.
        CHECK_FALSE(seen[i].empty());
        CHECK(succeeded(seen[i].back().result));
        CHECK(seen[i].back().message_id == msg_id);
    }

    // The second asker joined midway and was told where it had got to straight away, rather than
    // being left with nothing until the next chunk.
    CHECK_FALSE(seen[1].empty());

    // And having finished, a third ask is served from the cache with no download at all.
    net->downloads.clear();
    std::optional<std::vector<std::byte>> third;
    c->attachment_data(msg_id, 0, nullptr, [&](auto r) {
        REQUIRE(r.has_value());
        third = *std::move(r);
    });
    sync(*c);
    CHECK(net->downloads.empty());
    REQUIRE(third);
    CHECK(*third == plaintext);
}

TEST_CASE("Client: saving joins a fetch already under way", "[client][attachments][join]") {
    // Something is being fetched into the cache -- a gallery, or the auto-downloader -- and a save
    // asks for the same file.  Waiting on it costs nothing, since that copy is kept either way, and
    // fetching it twice would be two transfers of one file.
    TempCacheDir dir;
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);
    TestHelper::seed_pfs_nak(c->core, peer.session_id);

    std::vector<std::byte> plaintext(9000);
    random::fill(plaintext);
    auto seed = random::random(32);
    auto [ciphertext, key] = attachment::encrypt(seed, plaintext, attachment::Domain::ATTACHMENT);
    net->served["both"] = ciphertext;

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
                a->set_url(network::file_server::generate_download_url("both", {}, true));
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                a->set_size(plaintext.size());
                a->set_contenttype("image/png");
            },
            42);
    sync(*c);
    auto msg_id =
            c->conversation(ConversationId::dm(peer.session_id), await)->messages(await)[0].id;

    // A display asks first, so the file is being accumulated.
    std::optional<std::vector<std::byte>> shown;
    c->attachment_data(msg_id, 0, nullptr, [&](auto r) {
        REQUIRE(r.has_value());
        shown = *std::move(r);
    });
    sync(*c);
    REQUIRE(net->downloads.size() == 1);

    // Now a save of the same attachment, while that is still in flight.
    auto dest = dir.path / "saved.png";
    std::vector<AttachmentProgress> saw;
    std::promise<std::optional<Error>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(
            msg_id,
            0,
            dest,
            [&](const AttachmentProgress& p) { saw.push_back(p); },
            [&](auto r) {
                done.set_value(r ? std::nullopt : std::optional{std::move(r).error()});
            });
    sync(*c);

    // Still one transfer: the save waited rather than asking for the same bytes again.
    CHECK(net->downloads.size() == 1);

    REQUIRE(serve_downloads(*net, ciphertext) == 1);
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
    CHECK_FALSE(waiter.get().has_value());
    sync(*c);

    // Both callers got what they asked for: the display its bytes, the save its file.
    REQUIRE(shown);
    CHECK(*shown == plaintext);
    REQUIRE(std::filesystem::exists(dest));
    CHECK(std::filesystem::file_size(dest) == plaintext.size());
    {
        std::ifstream in{dest, std::ios::binary};
        std::vector<std::byte> got(plaintext.size());
        in.read(reinterpret_cast<char*>(got.data()), got.size());
        CHECK(!!(got == plaintext));
    }

    // The save was told how the transfer it joined was going, not left silent until it finished.
    CHECK_FALSE(saw.empty());
    CHECK(succeeded(saw.back().result));
}

TEST_CASE("Client: a save is a fetch like any other", "[client][attachments][join]") {
    // Saved straight to its destination as it arrives, and still shown as being fetched while it
    // runs -- and, with somewhere to keep it, kept too, so that a display asking meanwhile waits
    // for it and a second save does not fetch the file again.
    TempCacheDir dir, out;
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    bool caching = GENERATE(true, false);
    if (caching)
        c->set_cache_dir(dir.path);

    std::vector<std::byte> plaintext(9000);
    random::fill(plaintext);
    auto [ciphertext, key] =
            attachment::encrypt(random::random(32), plaintext, attachment::Domain::ATTACHMENT);
    net->served["saved"] = ciphertext;
    deliver(
            *c,
            peer,
            "",
            from_epoch_ms(1000),
            "h1",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& d) {
                auto* a = d.add_attachments();
                a->set_id(1);
                a->set_url(network::file_server::generate_download_url("saved", {}, true));
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                a->set_size(plaintext.size());
                a->set_contenttype("image/png");
            },
            7);
    sync(*c);
    auto id = c->conversation(ConversationId::dm(peer.session_id), await)->messages(await)[0].id;
    auto availability = [&] { return c->message(id, await)->attachments[0].availability; };
    auto contents = [](const std::filesystem::path& p) {
        std::ifstream in{p, std::ios::binary};
        std::vector<std::byte> got(std::filesystem::file_size(p));
        in.read(reinterpret_cast<char*>(got.data()), static_cast<std::streamsize>(got.size()));
        return got;
    };

    std::vector<Expected<std::filesystem::path>> saved;
    auto save = [&](const std::filesystem::path& dest) {
        c->Client::save_attachment(
                id, 0, dest, nullptr, [&](auto r) { saved.push_back(std::move(r)); }, false);
    };

    save(out.path / "first.png");
    sync(*c);
    REQUIRE(net->downloads.size() == 1);
    // Without a cache nothing ever reads as fetching, a display's download included: whatever it
    // fetches, the next ask fetches again.
    CHECK(availability() ==
          (caching ? AttachmentAvailability::fetching : AttachmentAvailability::absent));

    std::optional<std::vector<std::byte>> shown;
    c->attachment_data(id, 0, nullptr, [&](auto r) {
        REQUIRE(r.has_value());
        shown = *std::move(r);
    });
    sync(*c);

    // Nothing is kept of a save with no cache, so there is no way to hand a display the part that
    // has already been written: it fetches the file for itself.
    CHECK(net->downloads.size() == (caching ? 1 : 2));

    REQUIRE(serve_downloads(*net) == (caching ? 1 : 2));
    sync(*c);

    REQUIRE(saved.size() == 1);
    REQUIRE(saved[0].has_value());
    CHECK(*saved[0] == out.path / "first.png");
    CHECK(contents(*saved[0]) == plaintext);
    REQUIRE(shown);
    CHECK(*shown == plaintext);
    CHECK(availability() ==
          (caching ? AttachmentAvailability::cached : AttachmentAvailability::absent));

    save(out.path / "second.png");
    sync(*c);
    if (caching)
        CHECK(net->downloads.empty());
    else
        REQUIRE(serve_downloads(*net) == 1);
    sync(*c);
    REQUIRE(saved.size() == 2);
    REQUIRE(saved[1].has_value());
    CHECK(contents(*saved[1]) == plaintext);
}

TEST_CASE("Client: a save that cannot be written fails alone", "[client][attachments][join]") {
    // One download with a save and a display on it: the save's destination going away is the
    // save's failure, and the display still gets its bytes.
    TempCacheDir dir, out;
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    std::vector<std::byte> plaintext(9000);
    random::fill(plaintext);
    auto [ciphertext, key] =
            attachment::encrypt(random::random(32), plaintext, attachment::Domain::ATTACHMENT);
    net->served["lost"] = ciphertext;
    deliver(
            *c,
            peer,
            "",
            from_epoch_ms(1000),
            "h1",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& d) {
                auto* a = d.add_attachments();
                a->set_id(1);
                a->set_url(network::file_server::generate_download_url("lost", {}, true));
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                a->set_size(plaintext.size());
                a->set_contenttype("image/png");
            },
            7);
    sync(*c);
    auto id = c->conversation(ConversationId::dm(peer.session_id), await)->messages(await)[0].id;

    auto gone = out.path / "gone";
    std::filesystem::create_directories(gone);
    std::optional<Expected<std::filesystem::path>> saved;
    c->Client::save_attachment(
            id, 0, gone / "x.png", nullptr, [&](auto r) { saved = std::move(r); }, false);
    std::optional<std::vector<std::byte>> shown;
    c->attachment_data(id, 0, nullptr, [&](auto r) {
        REQUIRE(r.has_value());
        shown = *std::move(r);
    });
    sync(*c);
    REQUIRE(net->downloads.size() == 1);

    std::filesystem::remove_all(gone);
    REQUIRE(serve_downloads(*net) == 1);
    sync(*c);

    REQUIRE(saved);
    REQUIRE_FALSE(saved->has_value());
    CHECK(saved->error().code == err::save_failed);
    REQUIRE(shown);
    CHECK(*shown == plaintext);
    CHECK(c->message(id, await)->attachments[0].availability == AttachmentAvailability::cached);
}

TEST_CASE(
        "Client: a requested file too big to keep is fetched and not kept",
        "[client][attachments][cache]") {
    TempCacheDir dir, out;
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    CHECK_THROWS_AS(c->set_requested_cache_max_size(-1, await), std::invalid_argument);
    CHECK_THROWS_AS(c->set_auto_download_max_size(-1, await), std::invalid_argument);
    CHECK_THROWS_AS(c->set_attachment_cache_limit(-1, await), std::invalid_argument);
    CHECK_THROWS_AS(
            c->set_requested_cache_max_size(-1, result_function<>{}), std::invalid_argument);
    CHECK_FALSE(c->requested_cache_max_size(await));

    std::vector<std::byte> plaintext(5000);
    random::fill(plaintext);
    auto [ciphertext, key] =
            attachment::encrypt(random::random(32), plaintext, attachment::Domain::ATTACHMENT);
    net->served["big"] = ciphertext;
    net->served["unsized"] = ciphertext;
    auto arrive = [&](std::string hash, std::string file, bool sized) {
        deliver(
                *c,
                peer,
                "",
                from_epoch_ms(sized ? 1000 : 2000),
                hash,
                "",
                std::nullopt,
                [&](SessionProtos::DataMessage& d) {
                    auto* a = d.add_attachments();
                    a->set_id(1);
                    a->set_url(network::file_server::generate_download_url(file, {}, true));
                    a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                    if (sized)
                        a->set_size(plaintext.size());
                    a->set_contenttype("image/png");
                },
                7);
        sync(*c);
        for (const auto& m :
             c->conversation(ConversationId::dm(peer.session_id), await)->messages(await))
            if (m.attachments[0].size.has_value() == sized)
                return m.id;
        FAIL("no message for " << file);
        return int64_t{0};
    };
    auto id = arrive("h1", "big", true);
    auto availability = [&](int64_t id) {
        return c->message(id, await)->attachments[0].availability;
    };

    // Either way of asking, each fetched in full and not kept, so each fetches again.
    auto show = [&](int64_t id) {
        std::optional<std::vector<std::byte>> got;
        c->attachment_data(id, 0, nullptr, [&](auto r) {
            REQUIRE(r.has_value());
            got = *std::move(r);
        });
        sync(*c);
        REQUIRE(serve_downloads(*net) == 1);
        sync(*c);
        REQUIRE(got);
        CHECK(*got == plaintext);
    };
    auto save = [&](int64_t id) {
        std::optional<Expected<std::filesystem::path>> saved;
        c->Client::save_attachment(
                id,
                0,
                out.path / "saved.png",
                nullptr,
                [&](auto r) { saved = std::move(r); },
                false,
                true);
        sync(*c);
        REQUIRE(serve_downloads(*net) == 1);
        sync(*c);
        REQUIRE(saved);
        CHECK(saved->has_value());
    };

    c->set_requested_cache_max_size(plaintext.size() - 1, await);
    CHECK(c->requested_cache_max_size(await) == plaintext.size() - 1);
    for (int i = 0; i < 2; i++) {
        show(id);
        CHECK(availability(id) == AttachmentAvailability::absent);
        save(id);
        CHECK(availability(id) == AttachmentAvailability::absent);
    }

    // With a limit, a file that does not say how big it is cannot be shown to fit.
    auto unsized = arrive("h2", "unsized", false);
    c->set_requested_cache_max_size(1'000'000, await);
    show(unsized);
    CHECK(availability(unsized) == AttachmentAvailability::absent);

    // A file that fits is kept -- and stays served from there once the limit would turn it away,
    // since the limit is on what is kept, not on what is read.
    c->set_requested_cache_max_size(plaintext.size(), await);
    show(id);
    CHECK(availability(id) == AttachmentAvailability::cached);
    c->set_requested_cache_max_size(0, await);
    std::optional<std::vector<std::byte>> got;
    c->attachment_data(id, 0, nullptr, [&](auto r) { got = *std::move(r); });
    sync(*c);
    CHECK(net->downloads.empty());
    REQUIRE(got);
    CHECK(*got == plaintext);
}

TEST_CASE("Client: a conversation set to auto-download fetches on arrival", "[client][auto]") {
    TempCacheDir dir;
    std::vector<std::pair<ConversationId, AttachmentProgress>> progress;
    callbacks cbs;
    cbs.attachment_progress = [&](const ConversationId& id, const AttachmentProgress& p) {
        progress.emplace_back(id, p);
    };
    TempClient c{cbs};
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    auto convo = ConversationId::dm(peer.session_id);
    c->open_dm(convo, await);

    std::vector<std::byte> image(4000), doc(4000);
    random::fill(image);
    random::fill(doc);
    auto seed = random::random(32);
    auto [image_ct, image_key] = attachment::encrypt(seed, image, attachment::Domain::ATTACHMENT);
    auto [doc_ct, doc_key] = attachment::encrypt(seed, doc, attachment::Domain::ATTACHMENT);
    net->served["img"] = image_ct;
    net->served["doc"] = doc_ct;

    auto arrive = [&](std::string hash, bool with_doc) {
        deliver(*c,
                peer,
                "",
                from_epoch_ms(1000),
                hash,
                "",
                std::nullopt,
                [&](SessionProtos::DataMessage& data) {
                    auto* a = data.add_attachments();
                    a->set_id(1);
                    a->set_url(network::file_server::generate_download_url("img", {}, true));
                    a->set_key(std::string{
                            reinterpret_cast<const char*>(image_key.data()), image_key.size()});
                    a->set_size(image.size());
                    a->set_contenttype("image/png");
                    if (with_doc) {
                        auto* b = data.add_attachments();
                        b->set_id(2);
                        b->set_url(network::file_server::generate_download_url("doc", {}, true));
                        b->set_key(std::string{
                                reinterpret_cast<const char*>(doc_key.data()), doc_key.size()});
                        b->set_size(doc.size());
                        b->set_contenttype("application/pdf");
                    }
                });
        sync(*c);
    };

    SECTION("unasked means nothing is fetched") {
        // Never having been asked is not consent, and is what a client prompts on.
        REQUIRE_FALSE(c->conversation(convo, await)->auto_download().has_value());
        arrive("h1", false);
        CHECK(net->downloads.empty());
        CHECK(progress.empty());
        CHECK_FALSE(c->conversation(convo, await)->messages(await)[0].gallery);
    }

    SECTION("images only fetches the image and leaves the document") {
        c->conversation(convo, await)->set_auto_download(AutoDownload::image_attachments, await);
        arrive("h2", true);
        REQUIRE(net->downloads.size() == 1);
        CHECK(net->downloads[0].download_url.find("img") != std::string::npos);

        // Not a gallery: one of its attachments is not an image, so it cannot be shown as one.
        auto m = c->conversation(convo, await)->messages(await)[0];
        CHECK_FALSE(m.gallery_viewable);
        CHECK_FALSE(m.gallery);
    }

    SECTION("all fetches both, and an all-image message opens as a gallery") {
        c->conversation(convo, await)->set_auto_download(AutoDownload::all, await);
        arrive("h3", true);
        // One at a time, as under onion requests there always is: the second once the first ends.
        REQUIRE(net->downloads.size() == 1);
        REQUIRE(serve_downloads(*net) == 1);
        sync(*c);
        CHECK(net->downloads.size() == 1);

        // Two attachments, one of them a pdf: still not gallery viewable even though both were
        // fetched.  What is downloaded and what can be displayed as a gallery are different
        // questions.
        CHECK_FALSE(c->conversation(convo, await)->messages(await)[0].gallery);

        arrive("h4", false);
        auto m = c->conversation(convo, await)->messages(await)[0];
        CHECK(m.gallery_viewable);
        CHECK(m.gallery);
    }

    SECTION("a size limit refuses what is too big, before fetching it") {
        c->conversation(convo, await)->set_auto_download(AutoDownload::all, await);
        c->set_auto_download_max_size(1000, await);
        arrive("h5", false);
        CHECK(net->downloads.empty());

        // Raising it lets the next one through, so the limit is read per message rather than
        // remembered from startup.
        c->set_auto_download_max_size(std::nullopt, await);
        arrive("h6", false);
        CHECK(net->downloads.size() == 1);
    }

    SECTION("what a requested file may keep does not govern what is fetched unasked") {
        c->conversation(convo, await)->set_auto_download(AutoDownload::all, await);
        c->set_requested_cache_max_size(0, await);
        arrive("h8", false);
        REQUIRE(serve_downloads(*net, image_ct) == 1);
        sync(*c);
        CHECK(c->conversation(convo, await)->messages(await)[0].attachments[0].availability ==
              AttachmentAvailability::cached);
    }

    SECTION("the fetch is reported, cached, and never told to the sender") {
        c->conversation(convo, await)->set_auto_download(AutoDownload::all, await);
        arrive("h7", false);
        REQUIRE(net->downloads.size() == 1);
        REQUIRE(serve_downloads(*net, image_ct) == 1);
        sync(*c);

        // Broadcast, since nobody asked for it and there is no caller to hand a report to.
        REQUIRE_FALSE(progress.empty());
        CHECK(progress.back().first == convo);
        CHECK(succeeded(progress.back().second.result));

        // In the cache, so opening the conversation costs nothing...
        CHECK(std::filesystem::exists(TestHelper::cache_path(
                *c,
                cache::ATTACHMENT_DIR,
                network::file_server::generate_download_url("img", {}, true))));

        // ...and the sender is *not* told, because nobody has saved anything.  That notification
        // belongs to a save, whether or not the bytes came from the cache.
        CHECK(stores(*net).empty());
    }
}

TEST_CASE("Client: the cache evicts least recently used", "[client][auto][evict]") {
    TempCacheDir dir;
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    auto convo = ConversationId::dm(peer.session_id);
    c->open_dm(convo, await);
    c->conversation(convo, await)->set_auto_download(AutoDownload::all, await);

    // `last_used` is a millisecond timestamp, and the whole of this test would otherwise run inside
    // one of them, leaving every row tied and the eviction order arbitrary.  Real uses are spread
    // out; these have to be spread out by hand.
    ScopedClockOffset clock{0s};
    auto later = [t = 0s]() mutable { AdjustedClock::set_offset(t += 1s); };

    auto seed = random::random(32);
    // Three files, fetched in order, each about the same size on disk.
    std::vector<std::string> urls;
    std::vector<int64_t> ids;
    for (int i = 0; i < 3; i++) {
        later();
        std::vector<std::byte> data(3000);
        random::fill(data);
        auto [ct, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);
        auto file_id = "f{}"_format(i);
        net->served[file_id] = ct;
        auto url = network::file_server::generate_download_url(file_id, {}, true);
        urls.push_back(url);

        deliver(*c,
                peer,
                "",
                from_epoch_ms(1000 + i),
                "h{}"_format(i),
                "",
                std::nullopt,
                [&, url](SessionProtos::DataMessage& d) {
                    auto* a = d.add_attachments();
                    a->set_id(static_cast<uint64_t>(i + 1));
                    a->set_url(url);
                    a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                    a->set_size(data.size());
                    a->set_contenttype("image/png");
                });
        sync(*c);
        REQUIRE(serve_downloads(*net, ct) == 1);
        sync(*c);
        ids.push_back(c->conversation(convo, await)->messages(await)[0].id);
    }

    auto cached = [&](const std::string& url) {
        return std::filesystem::exists(TestHelper::cache_path(*c, cache::ATTACHMENT_DIR, url));
    };
    for (const auto& u : urls)
        REQUIRE(cached(u));

    // Reach for the *oldest* one, which makes it the most recently used.  Under oldest-first
    // eviction it would still be first to go; under least-recently-used it is last.
    later();
    c->attachment_data(ids[0], 0, nullptr, [](auto) {});
    sync(*c);

    // Now a limit that only two of the three fit under.
    auto one =
            std::filesystem::file_size(TestHelper::cache_path(*c, cache::ATTACHMENT_DIR, urls[0]));
    c->set_attachment_cache_limit(static_cast<int64_t>(one * 2 + one / 2), await);

    // Nothing happens until something is added, which is the only moment the total can grow.
    CHECK(cached(urls[1]));

    // A fourth arrival pushes it over and evicts.
    later();
    std::vector<std::byte> more(3000);
    random::fill(more);
    auto [more_ct, more_key] = attachment::encrypt(seed, more, attachment::Domain::ATTACHMENT);
    net->served["f3"] = more_ct;
    auto more_url = network::file_server::generate_download_url("f3", {}, true);
    deliver(*c,
            peer,
            "",
            from_epoch_ms(2000),
            "h3",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& d) {
                auto* a = d.add_attachments();
                a->set_id(9);
                a->set_url(more_url);
                a->set_key(std::string{
                        reinterpret_cast<const char*>(more_key.data()), more_key.size()});
                a->set_size(more.size());
                a->set_contenttype("image/png");
            });
    sync(*c);
    REQUIRE(serve_downloads(*net, more_ct) == 1);
    sync(*c);

    // The one just fetched is kept -- a download that completed and immediately vanished would read
    // as a failure.
    CHECK(cached(more_url));
    // The one that was read most recently is kept, though it is the oldest by arrival.
    CHECK(cached(urls[0]));
    // The one nobody has touched since it arrived is gone.
    CHECK_FALSE(cached(urls[1]));

    // The index agrees with the directory rather than describing files that are no longer there.
    auto rows = c->core.database().conn().prepared_get<int64_t>(
            "SELECT count(*) FROM attachment_cache");
    size_t on_disk = 0;
    for (const auto& e : std::filesystem::directory_iterator{dir.path / cache::ATTACHMENT_DIR})
        if (!e.path().filename().string().ends_with(cache::PARTIAL_SUFFIX))
            on_disk++;
    CHECK(static_cast<size_t>(rows) == on_disk);
}

TEST_CASE("Client: the cache reports how much disk it is using", "[client][evict]") {
    TempCacheDir dir;
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    auto convo = ConversationId::dm(peer.session_id);
    c->open_dm(convo, await);
    c->conversation(convo, await)->set_auto_download(AutoDownload::all, await);

    // Nothing cached is 0, not an absent answer: a limit can be unset, a usage cannot.
    CHECK(c->attachment_cache_size(await) == 0);

    auto seed = random::random(32);
    int64_t on_disk = 0;
    for (int i = 0; i < 2; i++) {
        std::vector<std::byte> data(3000);
        random::fill(data);
        auto [ct, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);
        auto file_id = "f{}"_format(i);
        net->served[file_id] = ct;
        auto url = network::file_server::generate_download_url(file_id, {}, true);

        deliver(*c,
                peer,
                "",
                from_epoch_ms(1000 + i),
                "h{}"_format(i),
                "",
                std::nullopt,
                [&, url](SessionProtos::DataMessage& d) {
                    auto* a = d.add_attachments();
                    a->set_id(static_cast<uint64_t>(i + 1));
                    a->set_url(url);
                    a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                    a->set_size(data.size());
                    a->set_contenttype("image/png");
                });
        sync(*c);
        REQUIRE(serve_downloads(*net, ct) == 1);
        sync(*c);

        on_disk += static_cast<int64_t>(
                std::filesystem::file_size(TestHelper::cache_path(*c, cache::ATTACHMENT_DIR, url)));
        CHECK(c->attachment_cache_size(await) == on_disk);
    }

    // Bytes on disk rather than the attachments' own sizes, which is what makes it comparable with
    // the limit: the cached copies are encrypted and padded, so they cost more than they contain.
    CHECK(c->attachment_cache_size(await) > 2 * 3000);
}

TEST_CASE("Client: the sweep reconciles the cache with what the database says", "[client][evict]") {
    TempCacheDir dir;
    SenderKeys peer;
    auto convo = ConversationId::dm(peer.session_id);
    auto seed = random::random(32);

    TempClient c;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    c->open_dm(convo, await);
    c->conversation(convo, await)->set_auto_download(AutoDownload::all, await);

    std::vector<std::byte> data(2000);
    random::fill(data);
    auto [ct, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);
    net->served["real"] = ct;
    auto url = network::file_server::generate_download_url("real", {}, true);

    deliver(*c,
            peer,
            "",
            from_epoch_ms(1000),
            "hh",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& d) {
                auto* a = d.add_attachments();
                a->set_id(1);
                a->set_url(url);
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                a->set_size(data.size());
                a->set_contenttype("image/png");
            });
    sync(*c);
    REQUIRE(serve_downloads(*net, ct) == 1);
    sync(*c);

    auto real_name = TestHelper::cache_path(*c, cache::ATTACHMENT_DIR, url).filename().string();
    REQUIRE(std::filesystem::exists(dir.path / cache::ATTACHMENT_DIR / real_name));

    // What a crash between writing a file and recording it leaves: a file no row names.
    auto orphan_name =
            TestHelper::cache_path(*c, cache::ATTACHMENT_DIR, "http://fs.example/file/ghost")
                    .filename()
                    .string();
    std::ofstream{dir.path / cache::ATTACHMENT_DIR / orphan_name, std::ios::binary}
            << "no row names this";

    // An in-progress write, which is not garbage but unfinished.
    auto partial = "{}{}"_format(orphan_name, cache::PARTIAL_SUFFIX);
    std::ofstream{dir.path / cache::ATTACHMENT_DIR / partial, std::ios::binary} << "half";

    // And the other direction: a row naming a file that is not there.  Not cosmetic -- eviction
    // totals `size` over the rows, so this one makes the cache look 10 MB fuller than it is.
    std::string stale_name = "deadbeef";
    c->core.loop().call_get([&] {
        c->core.database().conn().prepared_exec(
                "INSERT INTO attachment_cache (name, size, last_used) VALUES (?, ?, ?)",
                stale_name,
                int64_t{10'000'000},
                int64_t{1});
        return 0;
    });

    // Reopened, which is when a client sweeps: the leaks above are exactly what survives a restart.
    // The sweep goes back and forth between the disk loop, which lists and removes, and Core's,
    // which decides -- which is what `sync` waits out.
    c.reopen();
    c->set_cache_dir(dir.path);
    sync(*c);

    CHECK(std::filesystem::exists(dir.path / cache::ATTACHMENT_DIR / real_name));
    CHECK_FALSE(std::filesystem::exists(dir.path / cache::ATTACHMENT_DIR / orphan_name));
    CHECK(std::filesystem::exists(dir.path / cache::ATTACHMENT_DIR / partial));

    auto rows = c->core.loop().call_get([&] {
        return c->core.database().conn().prepared_get<int64_t>(
                "SELECT count(*) FROM attachment_cache WHERE name = ?", stale_name);
    });
    CHECK(rows == 0);

    // The tracked file kept its row: reconciling is not an excuse to rebuild the index.
    auto kept = c->core.loop().call_get([&] {
        return c->core.database().conn().prepared_get<int64_t>(
                "SELECT count(*) FROM attachment_cache WHERE name = ?", real_name);
    });
    CHECK(kept == 1);
}

TEST_CASE("Client: the list preview describes a message's attachments", "[client][attachments]") {
    TempClient c;
    SenderKeys gallery, mixed, voice, wordy;
    // Approved, or these would be message requests and `conversations()` would not list them.
    for (const auto* who : {&gallery, &mixed, &voice, &wordy})
        approve(*c, who->session_id);

    uint64_t next_id = 500;
    auto add = [&next_id](
                       SessionProtos::DataMessage& data,
                       std::string_view ctype,
                       std::string_view name,
                       int flags = 0) {
        auto* a = data.add_attachments();
        a->set_id(next_id);
        a->set_url("http://fs.example/file/{}#d"_format(next_id++));
        a->set_key(std::string(32, 'k'));
        a->set_size(10);
        if (!ctype.empty())
            a->set_contenttype(std::string{ctype});
        if (!name.empty())
            a->set_filename(std::string{name});
        if (flags)
            a->set_flags(flags);
    };

    // Attachments and no body at all: the case that rendered as a blank row, because an empty
    // preview string could not say whether there was a message.
    deliver(*c, gallery, "", from_epoch_ms(1000), "h1", "", std::nullopt, [&](auto& data) {
        add(data, "image/png", "kitten.png");
        add(data, "image/jpeg", "puppy.jpg");
    });
    // Not all images, so a row must not offer to show them as one.  The second file carries no name
    // at all, which a sender is free to omit.
    deliver(*c, mixed, "", from_epoch_ms(2000), "h2", "", std::nullopt, [&](auto& data) {
        add(data, "image/png", "chart.png");
        add(data, "application/pdf", "");
    });
    // A voice message, which a row names rather than counts.
    deliver(*c, voice, "", from_epoch_ms(3000), "h3", "", std::nullopt, [&](auto& data) {
        add(data, "audio/ogg", "clip.ogg", 1);
    });
    // Body *and* attachments together -- the combination that rules out describing a preview with a
    // single kind enum, since a row wants both halves.
    deliver(*c,
            wordy,
            "look at this",
            from_epoch_ms(4000),
            "h4",
            "",
            std::nullopt,
            [&](auto& data) { add(data, "image/png", "photo.png"); });
    sync(*c);

    auto convos = c->conversations(await);
    REQUIRE(convos.size() == 4);

    auto preview_of = [&](const SenderKeys& who) {
        auto id = ConversationId::dm(who.session_id);
        auto found = std::ranges::find_if(convos, [&](const auto& c) { return c.id() == id; });
        REQUIRE(found != convos.end());
        REQUIRE(found->last_preview());
        return *found->last_preview();
    };

    auto g = preview_of(gallery);
    CHECK(g.body.empty());
    // Named, and in the order the sender listed them rather than whatever the table hands back.
    CHECK(g.filenames == std::vector<std::string>{"kitten.png", "puppy.jpg"});
    CHECK(g.all_images);
    CHECK_FALSE(g.voice_message);
    CHECK_FALSE(g.outgoing);

    auto m = preview_of(mixed);
    // The unnamed file still occupies its place, so the count stays right and the entries stay
    // aligned with the attachment indices -- a row draws its own fallback for the empty one.
    CHECK(m.filenames == std::vector<std::string>{"chart.png", ""});
    CHECK_FALSE(m.all_images);

    auto v = preview_of(voice);
    CHECK(v.filenames == std::vector<std::string>{"clip.ogg"});
    CHECK(v.voice_message);
    CHECK_FALSE(v.all_images);

    auto w = preview_of(wordy);
    CHECK(w.body == "look at this");
    CHECK(w.filenames == std::vector<std::string>{"photo.png"});
    CHECK(w.all_images);
}

TEST_CASE("Client: a text-only message previews no attachments", "[client][attachments]") {
    TempClient c;
    SenderKeys peer;
    approve(*c, peer.session_id);

    deliver(*c, peer, "just words", from_epoch_ms(1000), "h1");
    sync(*c);

    auto convos = c->conversations(await);
    REQUIRE(convos.size() == 1);
    REQUIRE(convos[0].last_preview());
    // A message with no attachments does not come back from the aggregate query at all, so this is
    // what says the defaults it was left with are the right ones.
    CHECK(convos[0].last_preview()->body == "just words");
    CHECK(convos[0].last_preview()->filenames.empty());
    CHECK_FALSE(convos[0].last_preview()->all_images);
    CHECK_FALSE(convos[0].last_preview()->voice_message);
}

TEST_CASE(
        "Client: a file we send is kept in the cache",
        "[client][attachments][availability][send]") {
    // Otherwise a message we just sent draws as something to press, and pressing it fetches back a
    // file that came off this disk a moment ago.
    TempCacheDir cache;
    TempClient c;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(cache.path);

    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_outgoing", 7);
    std::filesystem::create_directories(dir);

    std::vector<std::byte> contents(5000);
    random::fill(contents);
    auto write_file = [&](const std::filesystem::path& to) {
        std::ofstream out{to, std::ios::binary};
        out.write(reinterpret_cast<const char*>(contents.data()), contents.size());
    };
    auto picture = dir / "picture.png";
    auto document = dir / "notes.pdf";
    write_file(picture);
    write_file(document);

    auto as_image = OutgoingAttachment{.path = picture, .content_type = "image/png"};
    auto as_document = OutgoingAttachment{.path = document, .content_type = "application/pdf"};

    auto send = [&](std::vector<OutgoingAttachment> files) {
        auto id = c->send_message(ConversationId::dm(me), {.attachments = std::move(files)}, await);
        sync(*c);
        REQUIRE(accept_stores(*net) == 1);
        return id;
    };
    auto availability = [&](int64_t id, size_t index) {
        return c->message(id, await)->attachments[index].availability;
    };

    // A gallery, which is drawn as the picture itself and so needs it whatever the setting says --
    // that setting rations bandwidth, and there is none to ration for a file already on this disk.
    auto gallery_id = send({as_image});
    CHECK(availability(gallery_id, 0) == AttachmentAvailability::cached);

    // Not a gallery, so it follows the rule the same file would have met arriving, and nobody has
    // been asked yet.
    CHECK(availability(send({as_document}), 0) == AttachmentAvailability::absent);

    // Nor is a message mixing the two, however much of it is pictures: it draws as a list of
    // attachments like any other, so the exception does not reach the image in it either.
    auto mixed_id = send({as_image, as_document});
    CHECK(availability(mixed_id, 0) == AttachmentAvailability::absent);
    CHECK(availability(mixed_id, 1) == AttachmentAvailability::absent);

    // And anything is kept once that rule says it would have been fetched, so what a conversation
    // holds does not depend on which end of it a file came from.
    c->conversation(ConversationId::dm(me), await)->set_auto_download(AutoDownload::all, await);
    CHECK(availability(send({as_document}), 0) == AttachmentAvailability::cached);

    // The copy is that file and not merely a file of the right length: saving it back is served
    // from the cache with no request at all, and what lands is what was sent.
    net->downloads.clear();
    auto dest = dir / "saved.png";
    std::promise<std::optional<Error>> done;
    auto waiter = done.get_future();
    c->Client::save_attachment(gallery_id, 0, dest, nullptr, [&done](auto r) {
        done.set_value(r ? std::nullopt : std::optional{std::move(r).error()});
    });
    sync(*c);
    CHECK(net->downloads.empty());
    REQUIRE(waiter.wait_for(5s) == std::future_status::ready);
    CHECK_FALSE(waiter.get().has_value());

    REQUIRE(std::filesystem::file_size(dest) == contents.size());
    std::ifstream in{dest, std::ios::binary};
    std::vector<std::byte> got(contents.size());
    in.read(reinterpret_cast<char*>(got.data()), got.size());
    CHECK(!!(got == contents));

    // And nothing a requested file could not be: this copy stands in for fetching it back.
    c->set_requested_cache_max_size(contents.size() - 1, await);
    CHECK(availability(send({as_image}), 0) == AttachmentAvailability::absent);
    c->set_requested_cache_max_size(contents.size(), await);
    CHECK(availability(send({as_image}), 0) == AttachmentAvailability::cached);

    std::filesystem::remove_all(dir);
}

TEST_CASE(
        "Client: sending a file tells the messages already showing it",
        "[client][attachments][availability][signals][send]") {
    // An attachment url is a hash of the encrypted body, so uploading a file puts it at the url
    // somebody may already have sent us.  Keeping our copy makes their message drawable too, and
    // nothing else is going to tell them: the upload's own completion reports the message being
    // sent, which is a different message in a different conversation.
    TempCacheDir cache;
    Recorder r;
    TempClient c{r.handlers()};
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(cache.path);

    auto me = own_sid(*c);
    TestHelper::seed_pfs_nak(c->core, me);

    auto dir = std::filesystem::temp_directory_path() / random::unique_id("test_shared", 7);
    std::filesystem::create_directories(dir);
    auto picture = dir / "picture.png";
    std::vector<std::byte> contents(4000);
    random::fill(contents);
    {
        std::ofstream out{picture, std::ios::binary};
        out.write(reinterpret_cast<const char*>(contents.data()), contents.size());
    }

    // Pinned so the url our upload lands at is one this test can name in advance, which is what
    // stands in for the two ends having encrypted the same file to the same place.
    net->next_file_id = 4242;
    auto shared = network::file_server::generate_download_url(
            "4242", c->core.network()->file_server_config, true);

    deliver(
            *c,
            peer,
            "",
            from_epoch_ms(1000),
            "h1",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& d) {
                auto* a = d.add_attachments();
                a->set_id(1);
                a->set_url(shared);
                a->set_key(std::string(32, 'k'));
                a->set_size(contents.size());
                a->set_contenttype("image/png");
            },
            7);
    sync(*c);

    auto theirs =
            c->conversation(ConversationId::dm(peer.session_id), await)->messages(await)[0].id;
    CHECK(c->message(theirs, await)->attachments[0].availability == AttachmentAvailability::absent);

    r.msg_updated.clear();
    c->send_message(
            ConversationId::dm(me),
            {.attachments = {OutgoingAttachment{.path = picture, .content_type = "image/png"}}},
            await);
    sync(*c);
    REQUIRE(accept_stores(*net) == 1);

    // Their message can now be drawn from disk...
    CHECK(c->message(theirs, await)->attachments[0].availability == AttachmentAvailability::cached);

    // ...and was told so, in a conversation nothing about this send belongs to.
    bool announced = false;
    for (const auto& m : Recorder::messages(r.msg_updated))
        if (m.id == theirs && !m.attachments.empty() &&
            m.attachments[0].availability == AttachmentAvailability::cached)
            announced = true;
    CHECK(announced);

    std::filesystem::remove_all(dir);
}

TEST_CASE(
        "Client: an attachment says whether its bytes are already here",
        "[client][attachments][availability]") {
    // What a display needs before it can decide between drawing the file, drawing a bar, and
    // drawing something to press -- and it has to come with the message, since a client that asked
    // per attachment would cross the language boundary once for every file on the page.
    TempCacheDir dir;
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    std::vector<std::byte> plaintext(20000);
    random::fill(plaintext);
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
                a->set_url(network::file_server::generate_download_url("here", {}, true));
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                a->set_size(plaintext.size());
                a->set_contenttype("image/png");
            },
            42);
    sync(*c);

    auto convo = ConversationId::dm(peer.session_id);
    auto att = [&] { return c->conversation(convo, await)->messages(await)[0].attachments[0]; };
    auto msg_id = c->conversation(convo, await)->messages(await)[0].id;

    // Nobody has asked for it, so the decision is the user's.
    CHECK(att().availability == AttachmentAvailability::absent);
    CHECK(att().fetch_done == 0);
    CHECK(att().fetch_total == 0);

    c->attachment_data(msg_id, 0, nullptr, [](auto) {});
    sync(*c);
    REQUIRE(net->downloads.size() == 1);

    // A transfer is running before a single byte of it has arrived, which is what keeps a download
    // button from being drawn over the top of one that is already going.
    CHECK(att().availability == AttachmentAvailability::fetching);

    std::span<const std::byte> whole{ciphertext};
    network::file_metadata meta{"here", static_cast<int64_t>(ciphertext.size()), {}, {}};
    auto half = ciphertext.size() / 2;
    net->downloads[0].on_data(meta, whole.first(half));
    sync(*c);

    // Half of it is here.  The reports went to whoever started the fetch, so a conversation opened
    // now has nowhere else to learn where it has reached.
    CHECK(att().availability == AttachmentAvailability::fetching);
    CHECK(att().fetch_done == static_cast<int64_t>(half));
    CHECK(att().fetch_total == static_cast<int64_t>(ciphertext.size()));

    net->downloads[0].on_data(meta, whole.subspan(half));
    net->downloads[0].on_complete(meta, false);
    net->downloads.clear();
    sync(*c);

    // Finished: the bytes can be had without a request, and there is no longer a transfer to say
    // anything about.
    CHECK(att().availability == AttachmentAvailability::cached);
    CHECK(att().fetch_done == 0);
    CHECK(att().fetch_total == 0);

    // And when the cache gives that copy up to make room for another file, the decision goes back
    // to the user -- which is the whole reason this is read from the cache each time rather than
    // recorded on the message when the download finished.
    c->set_attachment_cache_limit(1, await);
    net->served["other"] = ciphertext;
    deliver(
            *c,
            peer,
            "",
            from_epoch_ms(2000),
            "h2",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& data) {
                auto* a = data.add_attachments();
                a->set_id(2);
                a->set_url(network::file_server::generate_download_url("other", {}, true));
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                a->set_size(plaintext.size());
                a->set_contenttype("image/png");
            },
            43);
    sync(*c);
    auto newer = c->conversation(convo, await)->messages(await)[0].id;
    c->attachment_data(newer, 0, nullptr, [](auto) {});
    sync(*c);
    REQUIRE(serve_downloads(*net) == 1);
    sync(*c);

    CHECK(c->conversation(convo, await)->messages(await)[1].attachments[0].availability ==
          AttachmentAvailability::absent);
}

TEST_CASE(
        "Client: one report covers every message a change reached",
        "[client][attachments][availability][signals]") {
    // The two things a batch promises: it is ordered oldest first, and it is not confined to one
    // conversation.  An attachment url is a hash of the encrypted body, so one file reaching three
    // people's messages is ordinary rather than contrived -- and it is one thing that happened, so
    // it is one report.
    TempCacheDir dir;
    Recorder r;
    TempClient c{r.handlers()};
    SenderKeys alice, bob;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    std::vector<std::byte> plaintext(3000);
    random::fill(plaintext);
    auto seed = random::random(32);
    auto [ciphertext, key] = attachment::encrypt(seed, plaintext, attachment::Domain::ATTACHMENT);
    auto url = network::file_server::generate_download_url("shared", {}, true);
    net->served["shared"] = ciphertext;

    // Delivered newest first, so the order they are reported in cannot be the order they arrived.
    int64_t next = 90;
    auto arrive = [&](const SenderKeys& from, std::string hash, int64_t ts) {
        deliver(
                *c,
                from,
                "",
                from_epoch_ms(ts),
                std::move(hash),
                "",
                std::nullopt,
                [&](SessionProtos::DataMessage& d) {
                    auto* a = d.add_attachments();
                    a->set_id(static_cast<uint64_t>(next));
                    a->set_url(url);
                    a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                    a->set_size(plaintext.size());
                    a->set_contenttype("image/png");
                },
                next++);
        sync(*c);
        // By timestamp rather than by position: `messages()` pages newest first, so the one just
        // delivered is not the one at the front once a conversation has more than one.
        for (const auto& m :
             c->conversation(ConversationId::dm(from.session_id), await)->messages(await))
            if (m.timestamp == from_epoch_ms(ts))
                return m.id;
        FAIL("delivered message not found");
        return int64_t{0};
    };
    auto newest = arrive(alice, "h1", 3000);
    auto oldest = arrive(bob, "h2", 1000);
    auto middle = arrive(alice, "h3", 2000);

    r.msg_updated.clear();
    c->attachment_data(oldest, 0, nullptr, [](auto) {});
    sync(*c);
    REQUIRE(serve_downloads(*net) == 1);
    sync(*c);

    // The transfer starting and the transfer finishing, each of them once.
    REQUIRE(r.msg_updated.size() == 2);
    for (const auto& batch : r.msg_updated) {
        // All three, across two conversations, in one call.
        REQUIRE(batch.size() == 3);
        std::set<ConversationId> convos;
        for (const auto& m : batch)
            convos.insert(m.conversation);
        CHECK(convos.size() == 2);

        // Oldest first, which is the reverse of the order they arrived in.
        std::vector<int64_t> order;
        for (const auto& m : batch)
            order.push_back(m.id);
        CHECK(order == std::vector<int64_t>{oldest, middle, newest});
    }

    CHECK(r.msg_updated.back()[0].attachments[0].availability == AttachmentAvailability::cached);
}

TEST_CASE(
        "Client: every change to what we hold of a file is reported",
        "[client][attachments][availability][signals]") {
    // One file, two messages showing it, and every way its availability can change -- because what
    // decides whether a display is right is not the state but whether it was *told* about the move
    // into it.  Both messages every time: the file is one file, and telling only whoever asked for
    // it leaves the other drawing the wrong thing.
    TempCacheDir dir;
    Recorder r;
    TempClient c{r.handlers()};
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    std::vector<std::byte> plaintext(3000);
    random::fill(plaintext);
    auto seed = random::random(32);
    auto [ciphertext, key] = attachment::encrypt(seed, plaintext, attachment::Domain::ATTACHMENT);
    auto url = network::file_server::generate_download_url("watched", {}, true);
    net->served["watched"] = ciphertext;

    int64_t next = 80;
    auto arrive = [&](std::string hash, int64_t ts, std::string file_id) {
        deliver(
                *c,
                peer,
                "",
                from_epoch_ms(ts),
                std::move(hash),
                "",
                std::nullopt,
                [&](SessionProtos::DataMessage& d) {
                    auto* a = d.add_attachments();
                    a->set_id(static_cast<uint64_t>(next));
                    a->set_url(network::file_server::generate_download_url(file_id, {}, true));
                    a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                    a->set_size(plaintext.size());
                    a->set_contenttype("image/png");
                },
                next++);
        sync(*c);
    };

    auto convo = ConversationId::dm(peer.session_id);
    arrive("h1", 1000, "watched");
    arrive("h2", 2000, "watched");
    auto ids = [&] {
        std::vector<int64_t> found;
        for (const auto& m : c->conversation(convo, await)->messages(await))
            found.push_back(m.id);
        return found;
    }();
    REQUIRE(ids.size() == 2);
    std::set<int64_t> both{ids.begin(), ids.end()};

    // Who was told since the last time we looked, and what they were told the state is.
    auto told = [&] {
        std::map<int64_t, AttachmentAvailability> seen;
        for (const auto& m : Recorder::messages(r.msg_updated))
            if (!m.attachments.empty())
                seen[m.id] = m.attachments[0].availability;
        r.msg_updated.clear();
        return seen;
    };
    auto told_both = [&](AttachmentAvailability state) {
        auto seen = told();
        std::set<int64_t> who;
        for (const auto& [id, s] : seen) {
            who.insert(id);
            CHECK(s == state);
        }
        CHECK(who == both);
    };
    auto start_fetch = [&] {
        c->attachment_data(ids[0], 0, nullptr, [](auto) {});
        sync(*c);
        REQUIRE(net->downloads.size() == 1);
    };

    told();  // The arrivals themselves are `messages_added`, so start from clean.

    // absent -> fetching.
    start_fetch();
    told_both(AttachmentAvailability::fetching);

    // fetching -> absent, for a failure that says nothing about the file.
    REQUIRE(fail_downloads(*net, 500) == 1);
    sync(*c);
    told_both(AttachmentAvailability::absent);

    // fetching -> cached.
    start_fetch();
    told_both(AttachmentAvailability::fetching);
    REQUIRE(serve_downloads(*net) == 1);
    sync(*c);
    told_both(AttachmentAvailability::cached);

    // cached -> absent, by eviction.
    c->set_attachment_cache_limit(1, await);
    arrive("h3", 3000, "other");
    net->served["other"] = ciphertext;
    auto third = c->conversation(convo, await)->messages(await)[0].id;
    c->attachment_data(third, 0, nullptr, [](auto) {});
    sync(*c);
    REQUIRE(serve_downloads(*net) == 1);
    sync(*c);
    {
        auto seen = told();
        // The third message is in here too, having just cached its own file; what matters is that
        // the two showing the evicted one were told it is gone.
        for (auto id : both) {
            REQUIRE(seen.count(id) == 1);
            CHECK(seen.at(id) == AttachmentAvailability::absent);
        }
    }
    c->set_attachment_cache_limit(std::nullopt, await);

    // fetching -> not_found, for a failure that does say something: both are told, and both are
    // told why rather than merely that nothing is here.
    start_fetch();
    told();
    REQUIRE(fail_downloads(*net, 404) == 1);
    sync(*c);
    told_both(AttachmentAvailability::not_found);

    // not_found -> absent: a resend makes it fetchable again, for the message that first failed as
    // well as the new arrival.
    arrive("h4", 4000, "watched");
    {
        auto seen = told();
        for (auto id : both) {
            REQUIRE(seen.count(id) == 1);
            CHECK(seen.at(id) == AttachmentAvailability::absent);
        }
    }
}

TEST_CASE(
        "Client: a local copy is followed rather than recomputed",
        "[client][attachments][availability][evict]") {
    // What the reference from an attachment to its cached file buys, end to end: a message that
    // arrives after the file is already here knows that without being told, and a message loses the
    // file it was drawing loudly rather than silently.
    TempCacheDir dir;
    Recorder r;
    TempClient c{r.handlers()};
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    auto seed = random::random(32);
    int64_t next = 60;
    auto arrive = [&](std::string file_id, std::string hash, int64_t ts) {
        std::vector<std::byte> data(3000);
        random::fill(data);
        auto [ct, key] = attachment::encrypt(seed, data, attachment::Domain::ATTACHMENT);
        net->served[file_id] = ct;
        auto url = network::file_server::generate_download_url(file_id, {}, true);
        deliver(
                *c,
                peer,
                "",
                from_epoch_ms(ts),
                std::move(hash),
                "",
                std::nullopt,
                [&](SessionProtos::DataMessage& d) {
                    auto* a = d.add_attachments();
                    a->set_id(static_cast<uint64_t>(next));
                    a->set_url(url);
                    a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                    a->set_size(data.size());
                    a->set_contenttype("image/png");
                },
                next++);
        sync(*c);
        return url;
    };

    auto convo = ConversationId::dm(peer.session_id);
    auto newest = [&] { return c->conversation(convo, await)->messages(await)[0].id; };
    auto availability = [&](int64_t id) {
        return c->message(id, await)->attachments[0].availability;
    };

    auto url = arrive("shared", "h1", 1000);
    auto first = newest();
    CHECK(availability(first) == AttachmentAvailability::absent);

    c->attachment_data(first, 0, nullptr, [](auto) {});
    sync(*c);
    REQUIRE(serve_downloads(*net) == 1);
    sync(*c);
    CHECK(availability(first) == AttachmentAvailability::cached);

    // A second message naming the same file, arriving after it is already here.  It has never been
    // fetched for *this* message, and nothing hashes anything to work that out: the row it is
    // inserted beside already points at the entry.
    arrive("shared", "h2", 2000);
    auto second = newest();
    CHECK(availability(second) == AttachmentAvailability::cached);

    // Now squeeze it out, by caching something else under a limit neither fits.
    r.msg_updated.clear();
    c->set_attachment_cache_limit(1, await);
    arrive("other", "h3", 3000);
    auto third = newest();
    c->attachment_data(third, 0, nullptr, [](auto) {});
    sync(*c);
    REQUIRE(serve_downloads(*net) == 1);
    sync(*c);

    // Both messages showing the evicted file are back to needing a download...
    CHECK(availability(first) == AttachmentAvailability::absent);
    CHECK(availability(second) == AttachmentAvailability::absent);
    CHECK(availability(third) == AttachmentAvailability::cached);

    // ...and both were told so.  This is the part a keyed hash could not do: eviction holds a file
    // name, and getting from that back to the messages drawing it is only possible because the
    // reference runs that way.
    std::set<int64_t> told;
    for (const auto& m : Recorder::messages(r.msg_updated))
        told.insert(m.id);
    CHECK(told.count(first) == 1);
    CHECK(told.count(second) == 1);
}

TEST_CASE(
        "Client: a file that cannot be fetched is marked unavailable",
        "[client][attachments][unavailable]") {
    // Two messages naming one file, which is the case the column exists for: what a fetch discovers
    // is about the *file*, so a verdict reached while fetching for one of them has to reach the
    // other as well, or a transcript shows the same bytes as broken in one place and fine in
    // another.
    TempCacheDir dir;
    Recorder r;
    TempClient c{r.handlers()};
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    std::vector<std::byte> plaintext(2000);
    random::fill(plaintext);
    auto seed = random::random(32);
    auto [ciphertext, key] = attachment::encrypt(seed, plaintext, attachment::Domain::ATTACHMENT);
    auto url = network::file_server::generate_download_url("expired", {}, true);

    int64_t next_msgid = 41;
    auto arrive = [&](std::string hash, int64_t ts) {
        deliver(
                *c,
                peer,
                "",
                from_epoch_ms(ts),
                std::move(hash),
                "",
                std::nullopt,
                [&](SessionProtos::DataMessage& data) {
                    auto* a = data.add_attachments();
                    a->set_id(static_cast<uint64_t>(next_msgid));
                    a->set_url(url);
                    a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                    a->set_size(plaintext.size());
                    a->set_contenttype("image/png");
                },
                next_msgid++);
        sync(*c);
    };
    arrive("h1", 1000);
    arrive("h2", 2000);

    auto convo = ConversationId::dm(peer.session_id);
    auto verdicts = [&] {
        std::vector<AttachmentAvailability> found;
        for (const auto& m : c->conversation(convo, await)->messages(await)) {
            REQUIRE(m.attachments.size() == 1);
            found.push_back(m.attachments[0].availability);
        }
        return found;
    };

    using V = std::vector<AttachmentAvailability>;
    constexpr auto absent = AttachmentAvailability::absent;
    CHECK(verdicts() == V{absent, absent});

    // Asks for the bytes and has `answer` answer the download, returning the code of the error the
    // caller was given: the caller hears the same verdict the rows record, and the progress report
    // that ends the transfer says the same again.
    auto try_fetch = [&](auto&& answer) {
        std::optional<Error> error;
        std::optional<Expected<void>> last;
        c->attachment_data(
                c->conversation(convo, await)->messages(await).back().id,
                0,
                [&](const AttachmentProgress& p) { last = p.result; },
                [&](auto r) {
                    if (!r)
                        error = std::move(r).error();
                });
        sync(*c);
        REQUIRE(net->downloads.size() == 1);
        answer();
        sync(*c);
        REQUIRE(error);
        CHECK(failure_code(last) == error->code);
        return error->code;
    };

    // Asks again once there is a verdict, which answers from it: nothing is downloaded.
    auto ask_again = [&] {
        std::optional<Error> error;
        c->attachment_data(
                c->conversation(convo, await)->messages(await).back().id, 0, nullptr, [&](auto r) {
                    if (!r)
                        error = std::move(r).error();
                });
        sync(*c);
        CHECK(net->downloads.empty());
        REQUIRE(error);
        return error->code;
    };

    // A server error says nothing about the file -- the next attempt may well work -- so nothing is
    // recorded and the fetch stays on offer.
    CHECK(try_fetch([&] { REQUIRE(fail_downloads(*net, 500) == 1); }) == err::download_failed);
    CHECK(verdicts() == V{absent, absent});

    r.msg_updated.clear();

    // 404 is how the file server answers for an upload it no longer holds, which is what an expired
    // one looks like: worth recording, and recorded for both messages rather than the one that
    // asked.
    CHECK(try_fetch([&] { REQUIRE(fail_downloads(*net, 404) == 1); }) == err::file_not_found);
    CHECK(verdicts() == V{AttachmentAvailability::not_found, AttachmentAvailability::not_found});
    // One report carrying both, rather than one report each: it is one file, and what happened
    // happened to both of them at once.
    REQUIRE_FALSE(r.msg_updated.empty());
    CHECK(r.msg_updated.back().size() == 2);
    CHECK(ask_again() == err::file_not_found);

    // The repair: the sender sends the same file again, which -- the url being a hash of the
    // encrypted body -- lands at the same url.  That clears the verdict for the messages that
    // already carried it, not only for the new arrival, so all three are fetchable again.
    arrive("h3", 3000);
    CHECK(verdicts() == V{absent, absent, absent});

    // Bytes that arrive and do not authenticate are the other permanent failure, and a different
    // thing to tell a user: a resend would reproduce them, so asking for one is no use.
    auto corrupt = ciphertext;
    corrupt[corrupt.size() / 2] ^= std::byte{0xff};
    CHECK(try_fetch([&] { REQUIRE(serve_downloads(*net, corrupt) == 1); }) == err::file_unreadable);
    CHECK(verdicts() == V{AttachmentAvailability::unreadable,
                          AttachmentAvailability::unreadable,
                          AttachmentAvailability::unreadable});
    CHECK(ask_again() == err::file_unreadable);
}

TEST_CASE(
        "Client: a fetch that cannot start leaves nothing behind",
        "[client][attachments][availability]") {
    // No network yet, so the download cannot even begin.  The caller is told so -- and the file
    // must go back to being something to fetch, not sit at `fetching` for ever with every later
    // request for it waiting on a transfer that was never sent.
    TempCacheDir dir;
    TempClient c;
    SenderKeys peer;
    c->set_cache_dir(dir.path);

    std::vector<std::byte> plaintext(3000);
    random::fill(plaintext);
    auto [ciphertext, key] =
            attachment::encrypt(random::random(32), plaintext, attachment::Domain::ATTACHMENT);
    deliver(
            *c,
            peer,
            "",
            from_epoch_ms(1000),
            "h1",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& d) {
                auto* a = d.add_attachments();
                a->set_id(1);
                a->set_url(network::file_server::generate_download_url("later", {}, true));
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                a->set_size(plaintext.size());
                a->set_contenttype("image/png");
            },
            7);
    sync(*c);
    auto id = c->conversation(ConversationId::dm(peer.session_id), await)->messages(await)[0].id;

    std::optional<Expected<std::vector<std::byte>>> answer;
    c->attachment_data(id, 0, nullptr, [&](auto r) { answer = std::move(r); });
    sync(*c);
    REQUIRE(answer);
    REQUIRE_FALSE(answer->has_value());
    CHECK(answer->error().code == err::network_unavailable);
    CHECK(c->message(id, await)->attachments[0].availability == AttachmentAvailability::absent);

    // Once there is a network the same request works, rather than joining the one that never was.
    auto* net = attach_mock_network(c->core);
    net->served["later"] = ciphertext;
    std::optional<std::vector<std::byte>> got;
    c->attachment_data(id, 0, nullptr, [&](auto r) {
        REQUIRE(r.has_value());
        got = *std::move(r);
    });
    sync(*c);
    REQUIRE(serve_downloads(*net) == 1);
    sync(*c);
    REQUIRE(got);
    CHECK(*got == plaintext);
}

namespace {
// The temporary names in `dir`'s attachment cache, and how much each holds.
std::vector<uintmax_t> partial_cache_files(const std::filesystem::path& dir) {
    std::vector<uintmax_t> sizes;
    std::error_code ec;
    for (const auto& e : std::filesystem::directory_iterator{dir / cache::ATTACHMENT_DIR, ec})
        if (e.path().string().ends_with(cache::PARTIAL_SUFFIX))
            sizes.push_back(e.file_size());
    return sizes;
}
}  // namespace

TEST_CASE("Client: a download fills the cache as it arrives", "[client][attachments][cache]") {
    // Written as it comes, encrypted under our own key, rather than held until the end: nothing
    // keeps the whole file in memory while it downloads, and the display that asked is served by
    // reading it back.
    TempCacheDir dir;
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    auto size = GENERATE(0, 3000, 200'000);
    std::vector<std::byte> plaintext(size);
    random::fill(plaintext);
    auto [ciphertext, key] =
            attachment::encrypt(random::random(32), plaintext, attachment::Domain::ATTACHMENT);
    deliver(
            *c,
            peer,
            "",
            from_epoch_ms(1000),
            "h1",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& d) {
                auto* a = d.add_attachments();
                a->set_id(1);
                a->set_url(network::file_server::generate_download_url("streamed", {}, true));
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                a->set_size(plaintext.size());
                a->set_contenttype("image/png");
            },
            7);
    sync(*c);
    auto id = c->conversation(ConversationId::dm(peer.session_id), await)->messages(await)[0].id;

    std::optional<std::vector<std::byte>> got;
    c->attachment_data(id, 0, nullptr, [&](auto r) {
        REQUIRE(r.has_value());
        got = *std::move(r);
    });
    sync(*c);
    REQUIRE(net->downloads.size() == 1);
    auto request = std::move(net->downloads[0]);
    net->downloads.clear();

    network::file_metadata meta{"streamed", static_cast<int64_t>(ciphertext.size()), {}, {}};
    std::span all{ciphertext};
    auto half = all.size() / 2;
    request.on_data(meta, all.first(half));
    sync(*c);

    // Halfway through a file of several chunks, some of it is already on disk.  Under a temporary
    // name, though: nothing can be found in the cache until it is whole and verified.
    if (size == 200'000) {
        auto parts = partial_cache_files(dir.path);
        REQUIRE(parts.size() == 1);
        CHECK(parts[0] > 0);
    }
    CHECK_FALSE(got);

    request.on_data(meta, all.subspan(half));
    request.on_complete(meta, false);
    sync(*c);

    REQUIRE(got);
    CHECK(*got == plaintext);
    CHECK(c->message(id, await)->attachments[0].availability == AttachmentAvailability::cached);
    CHECK(partial_cache_files(dir.path).empty());
}

TEST_CASE(
        "Client: a cache that cannot be written still gets the file to whoever asked",
        "[client][attachments][cache]") {
    TempCacheDir dir;
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    std::vector<std::byte> plaintext(3000);
    random::fill(plaintext);
    auto [ciphertext, key] =
            attachment::encrypt(random::random(32), plaintext, attachment::Domain::ATTACHMENT);
    net->served["unkept"] = ciphertext;
    deliver(
            *c,
            peer,
            "",
            from_epoch_ms(1000),
            "h1",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& d) {
                auto* a = d.add_attachments();
                a->set_id(1);
                a->set_url(network::file_server::generate_download_url("unkept", {}, true));
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                a->set_size(plaintext.size());
                a->set_contenttype("image/png");
            },
            7);
    sync(*c);
    auto id = c->conversation(ConversationId::dm(peer.session_id), await)->messages(await)[0].id;

    // Something in the way of the attachment cache, so nothing can be written into it.
    auto attachments = dir.path / cache::ATTACHMENT_DIR;
    std::filesystem::remove_all(attachments);
    std::ofstream{attachments} << "in the way";

    std::optional<std::vector<std::byte>> got;
    c->attachment_data(id, 0, nullptr, [&](auto r) {
        REQUIRE(r.has_value());
        got = *std::move(r);
    });
    sync(*c);
    REQUIRE(serve_downloads(*net) == 1);
    sync(*c);

    // The download worked, but there is no copy to read back, so the one way left to have the
    // bytes is to fetch them again without a cache in the way.
    CHECK_FALSE(got);
    REQUIRE(serve_downloads(*net) == 1);
    sync(*c);
    REQUIRE(got);
    CHECK(*got == plaintext);
    CHECK(c->message(id, await)->attachments[0].availability == AttachmentAvailability::absent);
}

TEST_CASE(
        "Client: an attachment that cannot be auto-downloaded does not lose its message",
        "[client][attachments][auto]") {
    // A pointer with no url is still stored -- it is one of the files the sender said were there --
    // but there is nothing to fetch.  Fetching it on arrival must cost that attachment and nothing
    // else: the arrival is announced after auto-download runs, so a failure escaping it would mean
    // the message was stored and never reported.
    TempCacheDir dir;
    Recorder r;
    TempClient c{r.handlers()};
    SenderKeys peer;
    attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    auto convo = ConversationId::dm(peer.session_id);
    c->open_dm(convo, await);
    c->conversation(convo, await)->set_auto_download(AutoDownload::all, await);
    r.msg_added.clear();

    deliver(*c,
            peer,
            "no url",
            from_epoch_ms(1000),
            "h1",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& d) {
                auto* a = d.add_attachments();
                a->set_id(1);
                a->set_key(std::string(32, 'k'));
                a->set_contenttype("image/png");
            });
    sync(*c);

    auto added = Recorder::messages(r.msg_added);
    REQUIRE(added.size() == 1);
    CHECK(added[0].body == "no url");

    // It is shown as what it is -- a file its sender gave no way to fetch -- and asking for it says
    // the same, rather than offering a download that can never work.
    REQUIRE(added[0].attachments.size() == 1);
    CHECK(added[0].attachments[0].availability == AttachmentAvailability::unreadable);
    std::optional<Error> error;
    c->attachment_data(added[0].id, 0, nullptr, [&](auto r) {
        if (!r)
            error = std::move(r).error();
    });
    sync(*c);
    REQUIRE(error);
    CHECK(error->code == err::file_unreadable);
}

TEST_CASE(
        "Client: asking for something that cannot be fetched says why",
        "[client][attachments][unavailable]") {
    TempCacheDir dir;
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    // A stream url with a key the stream scheme cannot use: nothing the file server sends could
    // be decrypted with it.
    deliver(*c,
            peer,
            "",
            from_epoch_ms(1000),
            "h1",
            "",
            std::nullopt,
            [&](SessionProtos::DataMessage& d) {
                auto* a = d.add_attachments();
                a->set_id(1);
                a->set_url(network::file_server::generate_download_url("short", {}, true));
                a->set_key(std::string(16, 'k'));
                a->set_contenttype("image/png");
            });
    sync(*c);
    auto id = c->conversation(ConversationId::dm(peer.session_id), await)->messages(await)[0].id;

    auto code_of = [&](int64_t message_id, size_t index) {
        std::optional<Error> error;
        c->attachment_data(message_id, index, nullptr, [&](auto r) {
            if (!r)
                error = std::move(r).error();
        });
        sync(*c);
        REQUIRE(error);
        return error->code;
    };

    CHECK(code_of(id + 1000, 0) == err::message_not_found);
    CHECK(code_of(id, 1) == err::attachment_not_found);

    // Refused without anything being sent, and recorded, since no attempt could ever do better.
    CHECK(code_of(id, 0) == err::file_unreadable);
    CHECK(net->downloads.empty());
    CHECK(c->message(id, await)->attachments[0].availability == AttachmentAvailability::unreadable);

    // A save is refused the same way.
    std::optional<Error> saved;
    c->save_attachment(id, 0, dir.path / "out.png", nullptr, [&](auto r) {
        if (!r)
            saved = std::move(r).error();
    });
    sync(*c);
    REQUIRE(saved);
    CHECK(saved->code == err::file_unreadable);
    CHECK(net->downloads.empty());
    CHECK_FALSE(std::filesystem::exists(dir.path / "out.png"));
}

TEST_CASE(
        "Client: a bad pointer to a good file does not break the good one",
        "[client][attachments][unavailable]") {
    // Nothing ties a pointer's key to the bytes its url names.  Alice sends a file; Mallory sends a
    // pointer to the same url with a key of her own making.  Mallory's copy cannot be read, and
    // that must stay a fact about Mallory's pointer rather than become one about Alice's file.
    TempCacheDir dir;
    TempClient c;
    SenderKeys alice, mallory;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    std::vector<std::byte> plaintext(3000);
    random::fill(plaintext);
    auto [ciphertext, key] =
            attachment::encrypt(random::random(32), plaintext, attachment::Domain::ATTACHMENT);
    net->served["shared"] = ciphertext;
    auto url = network::file_server::generate_download_url("shared", {}, true);
    std::vector<std::byte> garbage(key.size());
    random::fill(garbage);

    auto send = [&](const SenderKeys& from, std::span<const std::byte> k, std::string hash) {
        deliver(
                *c,
                from,
                "",
                from_epoch_ms(1000),
                std::move(hash),
                "",
                std::nullopt,
                [&](SessionProtos::DataMessage& d) {
                    auto* a = d.add_attachments();
                    a->set_id(1);
                    a->set_url(url);
                    a->set_key(std::string{reinterpret_cast<const char*>(k.data()), k.size()});
                    a->set_size(plaintext.size());
                    a->set_contenttype("image/png");
                },
                7);
        sync(*c);
        return c->conversation(ConversationId::dm(from.session_id), await)->messages(await)[0].id;
    };
    auto alices = send(alice, key, "h1");
    auto mallorys = send(mallory, garbage, "h2");

    auto availability = [&](int64_t id) {
        return c->message(id, await)->attachments[0].availability;
    };
    auto fetch = [&](int64_t id, std::optional<Error>& error, auto&... got) {
        c->attachment_data(id, 0, nullptr, [&](auto r) {
            error.reset();
            if (r)
                ((got = *r), ...);
            else
                error = std::move(r).error();
        });
        sync(*c);
    };

    // Both asked for at once.  Joining would mean Alice's taking the answer to Mallory's, which
    // Mallory's key decides; so each is a transfer of its own.  Answered with a failure that says
    // nothing about either, so that no verdict is left behind by it.
    std::optional<Error> mallory_error, alice_error;
    std::optional<std::vector<std::byte>> alice_got;
    fetch(mallorys, mallory_error);
    fetch(alices, alice_error, alice_got);
    REQUIRE(fail_downloads(*net, 500) == 2);
    sync(*c);
    REQUIRE(mallory_error);
    CHECK(mallory_error->code == err::download_failed);
    REQUIRE(alice_error);
    CHECK(alice_error->code == err::download_failed);

    // Mallory's alone: its failure is a verdict on Mallory's pointer, and Alice's is untouched.
    fetch(mallorys, mallory_error);
    REQUIRE(serve_downloads(*net) == 1);
    sync(*c);
    REQUIRE(mallory_error);
    CHECK(mallory_error->code == err::file_unreadable);
    CHECK(availability(mallorys) == AttachmentAvailability::unreadable);
    CHECK(availability(alices) == AttachmentAvailability::absent);

    // Asked again, Mallory's answers from its verdict, and Alice's is fetched as though nothing
    // had happened.
    fetch(mallorys, mallory_error);
    CHECK(net->downloads.empty());
    REQUIRE(mallory_error);
    CHECK(mallory_error->code == err::file_unreadable);

    fetch(alices, alice_error, alice_got);
    REQUIRE(serve_downloads(*net) == 1);
    sync(*c);

    CHECK_FALSE(alice_error.has_value());
    REQUIRE(alice_got);
    CHECK(*alice_got == plaintext);

    // And now the file is here, Mallory's message is served it from the cache like every other
    // message naming it -- so it can no longer say the file cannot be had, which would draw "gone"
    // over a file sitting on this disk.
    CHECK(availability(alices) == AttachmentAvailability::cached);
    CHECK(availability(mallorys) == AttachmentAvailability::cached);
}

TEST_CASE(
        "Client: a download that cannot be used is stopped rather than finished",
        "[client][attachments][cancel]") {
    // The stream scheme authenticates each chunk as it arrives, so a file that has been tampered
    // with is known to be unusable from the bad chunk onwards -- and everything after it is
    // bandwidth spent on a file we have already decided to throw away.
    TempCacheDir dir;
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    // Large enough that stopping early is visibly different from running to the end.
    std::vector<std::byte> plaintext(200'000);
    random::fill(plaintext);
    auto seed = random::random(32);
    auto [ciphertext, key] = attachment::encrypt(seed, plaintext, attachment::Domain::ATTACHMENT);
    REQUIRE(ciphertext.size() > 50'000);

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
                a->set_url(network::file_server::generate_download_url("tampered", {}, true));
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                a->set_size(plaintext.size());
                a->set_contenttype("image/png");
            },
            42);
    sync(*c);
    auto msg_id =
            c->conversation(ConversationId::dm(peer.session_id), await)->messages(await)[0].id;

    // Corrupted in the second chunk, so the first one authenticates and the failure happens partway
    // rather than at the very start.
    auto corrupt = ciphertext;
    corrupt[5000] ^= std::byte{0xff};

    std::optional<Error> reported;
    bool answered = false;
    c->attachment_data(msg_id, 0, nullptr, [&](auto r) {
        if (!r)
            reported = std::move(r).error();
        answered = true;
    });
    sync(*c);
    REQUIRE(net->downloads.size() == 1);

    auto chunks =
            serve_one_download(net->downloads[0], "tampered", corrupt, 4096, [&] { sync(*c); });
    net->downloads.clear();
    sync(*c);

    // Stopped well short of the end.  Not a tighter bound than that: how soon the tampering is
    // noticed depends on how much the stream format has to have in hand before it can authenticate
    // the block the bad byte landed in, which is its business and not something to pin here.
    auto whole = (corrupt.size() + 4095) / 4096;
    CHECK(chunks < whole / 2);

    // And what the caller is told is what actually went wrong, not the cancellation we asked for on
    // the strength of it -- which is also what decides that trying again is pointless.
    REQUIRE(answered);
    REQUIRE(reported);
    CHECK(reported->code == err::file_unreadable);
    CHECK(reported->message.find("decryption failed") != std::string::npos);
}

TEST_CASE("Client: a request for an attachment can be withdrawn", "[client][attachments][cancel]") {
    TempCacheDir dir, out;
    std::vector<AttachmentProgress> broadcast;
    callbacks cbs;
    cbs.attachment_progress = [&](const ConversationId&, const AttachmentProgress& p) {
        broadcast.push_back(p);
    };
    TempClient c{cbs};
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);
    auto convo = ConversationId::dm(peer.session_id);
    c->open_dm(convo, await);

    // Several chunks, so that half of it is partway through something.
    std::vector<std::byte> plaintext(200'000);
    random::fill(plaintext);
    auto [ciphertext, key] =
            attachment::encrypt(random::random(32), plaintext, attachment::Domain::ATTACHMENT);
    auto arrive = [&] {
        deliver(
                *c,
                peer,
                "",
                from_epoch_ms(1000),
                "h1",
                "",
                std::nullopt,
                [&](SessionProtos::DataMessage& d) {
                    auto* a = d.add_attachments();
                    a->set_id(1);
                    a->set_url(network::file_server::generate_download_url("wanted", {}, true));
                    a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                    a->set_size(plaintext.size());
                    a->set_contenttype("image/png");
                },
                7);
        sync(*c);
        return c->conversation(convo, await)->messages(await)[0].id;
    };
    auto availability = [&](int64_t id) {
        return c->message(id, await)->attachments[0].availability;
    };

    network::file_metadata meta{"wanted", static_cast<int64_t>(ciphertext.size()), {}, {}};
    std::span all{ciphertext};
    auto half = all.size() / 2;
    auto take_request = [&] {
        REQUIRE(net->downloads.size() == 1);
        auto r = std::move(net->downloads[0]);
        net->downloads.clear();
        return r;
    };
    auto serve_half = [&](network::DownloadRequest& r) {
        r.on_data(meta, all.first(half));
        sync(*c);
    };
    auto serve_rest = [&](network::DownloadRequest& r) {
        r.on_data(meta, all.subspan(half));
        r.on_complete(meta, false);
        sync(*c);
    };
    auto was_cancelled = [](const auto& r) {
        return !r.has_value() && r.error().code == err::download_cancelled;
    };

    std::optional<Expected<std::vector<std::byte>>> shown;
    std::vector<AttachmentProgress> seen;
    auto show = [&](int64_t id) {
        return c->attachment_data(
                id,
                0,
                [&](const AttachmentProgress& p) { seen.push_back(p); },
                [&](auto r) { shown = std::move(r); });
    };
    std::vector<Expected<std::filesystem::path>> saved;
    auto dest = out.path / "saved.png";
    auto save = [&](int64_t id) {
        return c->Client::save_attachment(
                id, 0, dest, nullptr, [&](auto r) { saved.push_back(std::move(r)); }, false);
    };

    SECTION("a display alone stops the download, and leaves nothing behind") {
        auto id = arrive();
        auto token = show(id);
        sync(*c);
        auto request = take_request();
        serve_half(request);
        CHECK(partial_cache_files(dir.path).size() == 1);

        c->cancel_attachment_transfer(token);
        sync(*c);
        REQUIRE(shown);
        CHECK(was_cancelled(*shown));
        REQUIRE_FALSE(seen.empty());
        CHECK(seen.back().token == token);
        CHECK(failure_code(seen.back().result) == err::download_cancelled);
        CHECK(*request.cancelled);
        CHECK(partial_cache_files(dir.path).empty());
        CHECK(availability(id) == AttachmentAvailability::absent);

        // Whatever the network still delivers changes nothing.
        auto reports = seen.size();
        serve_rest(request);
        CHECK(seen.size() == reports);
        CHECK(was_cancelled(*shown));
        CHECK(partial_cache_files(dir.path).empty());
        CHECK(availability(id) == AttachmentAvailability::absent);
    }

    SECTION("a display sharing the download leaves it running for the other") {
        auto id = arrive();
        std::optional<Expected<std::vector<std::byte>>> other;
        c->attachment_data(id, 0, nullptr, [&](auto r) { other = std::move(r); });
        auto token = show(id);
        CHECK(token != 0);
        sync(*c);
        auto request = take_request();
        serve_half(request);

        c->cancel_attachment_transfer(token);
        sync(*c);
        REQUIRE(shown);
        CHECK(was_cancelled(*shown));
        CHECK_FALSE(*request.cancelled);
        CHECK(availability(id) == AttachmentAvailability::fetching);

        serve_rest(request);
        REQUIRE(other);
        REQUIRE(other->has_value());
        CHECK(**other == plaintext);
        CHECK(availability(id) == AttachmentAvailability::cached);
    }

    SECTION("a save alone stops the download, and removes what it had written") {
        auto id = arrive();
        auto token = save(id);
        sync(*c);
        auto request = take_request();
        serve_half(request);
        CHECK_FALSE(std::filesystem::is_empty(out.path));

        c->cancel_attachment_transfer(token);
        sync(*c);
        REQUIRE(saved.size() == 1);
        CHECK(was_cancelled(saved[0]));
        CHECK(std::filesystem::is_empty(out.path));
        CHECK(*request.cancelled);
        CHECK(partial_cache_files(dir.path).empty());
        CHECK(availability(id) == AttachmentAvailability::absent);

        serve_rest(request);
        CHECK(saved.size() == 1);
        CHECK(std::filesystem::is_empty(out.path));
    }

    SECTION("a save leaves the download running for a display") {
        // Either way round: a save that started the download is written as it arrives, and one
        // that joined is served afterwards, and withdrawing either is the same to the display.
        auto id = arrive();
        bool save_first = GENERATE(true, false);
        uint64_t token;
        if (save_first) {
            token = save(id);
            show(id);
        } else {
            show(id);
            token = save(id);
        }
        sync(*c);
        auto request = take_request();
        serve_half(request);

        c->cancel_attachment_transfer(token);
        sync(*c);
        REQUIRE(saved.size() == 1);
        CHECK(was_cancelled(saved[0]));
        CHECK_FALSE(*request.cancelled);

        serve_rest(request);
        REQUIRE(shown);
        REQUIRE(shown->has_value());
        CHECK(**shown == plaintext);
        CHECK(saved.size() == 1);
        CHECK(std::filesystem::is_empty(out.path));
        CHECK(availability(id) == AttachmentAvailability::cached);
    }

    SECTION("an auto-download is withdrawn by the token its progress carries") {
        c->conversation(convo, await)->set_auto_download(AutoDownload::all, await);
        auto id = arrive();
        auto request = take_request();
        REQUIRE_FALSE(broadcast.empty());
        auto token = broadcast.back().token;
        CHECK(token != 0);

        c->cancel_attachment_transfer(token);
        sync(*c);
        CHECK(*request.cancelled);
        CHECK(failure_code(broadcast.back().result) == err::download_cancelled);
        CHECK(availability(id) == AttachmentAvailability::absent);
    }

    SECTION("deleting the attachment withdraws every request for it") {
        auto id = arrive();
        show(id);
        save(id);
        sync(*c);
        auto request = take_request();
        serve_half(request);

        auto how = GENERATE(as<std::string>{}, "message", "clear", "conversation");
        if (how == "message")
            CHECK(c->delete_message(id, await));
        else if (how == "clear")
            c->conversation(convo, await)->clear_messages(await);
        else
            c->conversation(convo, await)->delete_conversation(await);
        sync(*c);

        REQUIRE(shown);
        CHECK(was_cancelled(*shown));
        REQUIRE(saved.size() == 1);
        CHECK(was_cancelled(saved[0]));
        CHECK(*request.cancelled);
        CHECK(std::filesystem::is_empty(out.path));
        CHECK(partial_cache_files(dir.path).empty());
    }

    // Holds the disk loop until released, so that what is queued there behind it runs in a known
    // order once it is.  Released on the way out whatever happens, or the loop never stops.
    struct Gate {
        std::promise<void> opened;
        std::shared_future<void> open = opened.get_future().share();
        bool released = false;
        void release() {
            if (!std::exchange(released, true))
                opened.set_value();
        }
        ~Gate() { release(); }
    };
    auto core_turn = [&] { c->core.loop().call_get([] { return 0; }); };

    SECTION("a cancel that crosses a save finishing as it arrived loses to it") {
        auto id = arrive();
        auto token = save(id);
        sync(*c);
        auto request = take_request();
        serve_half(request);
        request.on_data(meta, all.subspan(half));
        request.on_complete(meta, false);

        // The download's ending on the disk loop, which hands it to Core's loop; that queues the
        // save's finish behind the gate, and the cancel then goes in behind the finish.
        c->core.disk_loop()->call_get([] { return 0; });
        Gate gate;
        c->core.disk_loop()->call([open = gate.open] { open.wait(); });
        core_turn();
        c->cancel_attachment_transfer(token);
        core_turn();
        gate.release();
        sync(*c);

        REQUIRE(saved.size() == 1);
        REQUIRE(saved[0].has_value());
        CHECK(std::filesystem::exists(*saved[0]));
    }

    SECTION("a cancel that crosses a save from the cache loses to it") {
        auto id = arrive();
        show(id);
        sync(*c);
        auto request = take_request();
        serve_half(request);
        serve_rest(request);
        REQUIRE(availability(id) == AttachmentAvailability::cached);

        Gate gate;
        c->core.disk_loop()->call([open = gate.open] { open.wait(); });
        auto token = save(id);
        core_turn();
        c->cancel_attachment_transfer(token);
        core_turn();
        gate.release();
        sync(*c);

        CHECK(net->downloads.empty());
        REQUIRE(saved.size() == 1);
        REQUIRE(saved[0].has_value());
        CHECK(std::filesystem::exists(*saved[0]));
    }

    SECTION("a request that has already finished is not withdrawn") {
        auto id = arrive();
        auto token = save(id);
        sync(*c);
        auto request = take_request();
        serve_half(request);
        serve_rest(request);
        REQUIRE(saved.size() == 1);
        REQUIRE(saved[0].has_value());

        c->cancel_attachment_transfer(token);
        sync(*c);
        CHECK(saved.size() == 1);
        CHECK(std::filesystem::exists(*saved[0]));
    }
}

TEST_CASE("Client: auto-downloads take turns, newest first", "[client][auto][queue]") {
    TempCacheDir dir;
    std::vector<AttachmentProgress> broadcast;
    callbacks cbs;
    cbs.attachment_progress = [&](const ConversationId&, const AttachmentProgress& p) {
        broadcast.push_back(p);
    };
    TempClient c{cbs};
    SenderKeys peer;
    bool onion = GENERATE(false, true);
    network::config::Config config;
    if (!onion)
        config.router = network::opt::router::Type::direct;
    auto* net = attach_mock_network(c->core, std::move(config));
    c->set_cache_dir(dir.path);
    auto convo = ConversationId::dm(peer.session_id);
    c->open_dm(convo, await);
    c->conversation(convo, await)->set_auto_download(AutoDownload::all, await);

    CHECK_THROWS_AS(c->set_auto_download_concurrency(0, await), std::invalid_argument);
    CHECK_FALSE(c->auto_download_concurrency(await));

    std::vector<std::byte> plaintext(3000);
    random::fill(plaintext);
    auto [ciphertext, key] =
            attachment::encrypt(random::random(32), plaintext, attachment::Domain::ATTACHMENT);
    int64_t when = 1000;
    auto arrive = [&](const std::string& file) {
        net->served[file] = ciphertext;
        deliver(
                *c,
                peer,
                "",
                from_epoch_ms(when++),
                "h" + file,
                "",
                std::nullopt,
                [&](SessionProtos::DataMessage& d) {
                    auto* a = d.add_attachments();
                    a->set_id(1);
                    a->set_url(network::file_server::generate_download_url(file, {}, true));
                    a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                    a->set_size(plaintext.size());
                    a->set_contenttype("image/png");
                },
                7);
        sync(*c);
    };
    // Which files are being fetched, in the order they were asked for.
    auto fetching = [&] {
        std::vector<std::string> files;
        for (const auto& r : net->downloads)
            files.push_back(network::file_server::parse_download_url(r.download_url)->file_id);
        return files;
    };
    using files = std::vector<std::string>;

    SECTION("as many at once as the setting allows, or one under onion requests") {
        for (auto f : {"a", "b", "c", "d", "e"})
            arrive(f);
        // The default of 4, the rest waiting; one of them under onion requests, whatever the
        // setting says.
        CHECK(fetching() == (onion ? files{"a"} : files{"a", "b", "c", "d"}));

        c->set_auto_download_concurrency(5, await);
        sync(*c);
        CHECK(fetching().size() == (onion ? 1 : 5));
    }

    SECTION("what arrives while others wait goes first") {
        c->set_auto_download_concurrency(1, await);
        for (auto f : {"a", "b", "c"})
            arrive(f);
        CHECK(fetching() == files{"a"});

        std::vector<std::string> order;
        while (!net->downloads.empty()) {
            order.push_back(fetching()[0]);
            REQUIRE(serve_downloads(*net) == 1);
            sync(*c);
        }
        CHECK(order == files{"a", "c", "b"});
    }

    SECTION("withdrawing one, or its failing, frees its turn") {
        c->set_auto_download_concurrency(1, await);
        arrive("a");
        arrive("b");
        arrive("c");
        REQUIRE(fetching() == files{"a"});

        REQUIRE_FALSE(broadcast.empty());
        c->cancel_attachment_transfer(broadcast.back().token);
        sync(*c);
        REQUIRE(fetching().size() == 2);
        CHECK(fetching()[1] == "c");

        // A 404 is as much an ending as a success.
        net->served.erase("c");
        net->downloads.erase(net->downloads.begin());
        REQUIRE(serve_downloads(*net) == 1);
        sync(*c);
        CHECK(fetching() == files{"b"});
    }

    SECTION("one deleted while it waits is not fetched") {
        c->set_auto_download_concurrency(1, await);
        arrive("a");
        arrive("b");
        auto messages = c->conversation(convo, await)->messages(await);
        auto waiting = std::ranges::find_if(
                messages, [&](const Message& m) { return m.timestamp == from_epoch_ms(1001); });
        REQUIRE(waiting != messages.end());
        CHECK(c->delete_message(waiting->id, await));

        REQUIRE(serve_downloads(*net) == 1);
        sync(*c);
        CHECK(net->downloads.empty());
    }
}

TEST_CASE(
        "Client: a deletion from another device withdraws the requests it orphans",
        "[client][attachments][cancel][configs]") {
    TempCacheDir dir, out;
    TempClient c;
    SenderKeys peer;
    auto* net = attach_mock_network(c->core);
    c->set_cache_dir(dir.path);

    std::vector<std::byte> plaintext(200'000);
    random::fill(plaintext);
    auto [ciphertext, key] =
            attachment::encrypt(random::random(32), plaintext, attachment::Domain::ATTACHMENT);

    // Each way a merge deletes, and the conversation it has to be in: note to self's history is
    // the profile's to clear, anyone else's the contact's.
    auto how = GENERATE(
            as<std::string>{}, "delete before", "delete attachments before", "remove", "self");
    bool self = how == "self";
    auto convo = self ? self_convo(*c) : ConversationId::dm(peer.session_id);
    auto them = oxenc::to_hex(peer.session_id.begin(), peer.session_id.end());
    if (!self)
        c->open_dm(convo, await);

    deliver(
            *c,
            self ? self_keys(*c) : peer,
            "",
            from_epoch_ms(1000),
            "h1",
            "",
            self ? std::optional{own_sid(*c)} : std::nullopt,
            [&](SessionProtos::DataMessage& d) {
                auto* a = d.add_attachments();
                a->set_id(1);
                a->set_url(network::file_server::generate_download_url("doomed", {}, true));
                a->set_key(std::string{reinterpret_cast<const char*>(key.data()), key.size()});
                a->set_size(plaintext.size());
                a->set_contenttype("image/png");
            },
            7);
    sync(*c);
    auto messages = c->conversation(convo, await)->messages(await);
    REQUIRE(messages.size() == 1);
    auto id = messages[0].id;

    // The save first, so that it is the one written as the file arrives and has something on disk
    // to lose; the display joins it.
    std::optional<Expected<std::filesystem::path>> saved;
    c->Client::save_attachment(
            id, 0, out.path / "saved.png", nullptr, [&](auto r) { saved = std::move(r); }, false);
    std::optional<Expected<std::vector<std::byte>>> shown;
    c->attachment_data(id, 0, nullptr, [&](auto r) { shown = std::move(r); });
    sync(*c);
    REQUIRE(net->downloads.size() == 1);
    auto request = std::move(net->downloads[0]);
    net->downloads.clear();
    network::file_metadata meta{"doomed", static_cast<int64_t>(ciphertext.size()), {}, {}};
    request.on_data(meta, std::span{ciphertext}.first(ciphertext.size() / 2));
    sync(*c);
    REQUIRE_FALSE(std::filesystem::is_empty(out.path));

    auto later = std::chrono::sys_seconds{2000s};
    if (self)
        merge_profile(*c, profile_from_another_device(*c, [&](config::UserProfile& theirs) {
            theirs.set_nts_delete_before(later);
        }));
    else
        merge_contacts(*c, contacts_update_from_another_device(*c, [&](config::Contacts& theirs) {
            if (how == "remove") {
                theirs.erase(them);
                return;
            }
            auto e = theirs.get_or_construct(them);
            (how == "delete before" ? e.delete_before : e.delete_attach_before) = later;
            theirs.set(e);
        }));
    sync(*c);

    auto withdrawn = [](const auto& r) {
        return r && !r->has_value() && r->error().code == err::download_cancelled;
    };
    CHECK(withdrawn(shown));
    CHECK(withdrawn(saved));
    CHECK(*request.cancelled);
    CHECK(std::filesystem::is_empty(out.path));
    CHECK(partial_cache_files(dir.path).empty());
}
