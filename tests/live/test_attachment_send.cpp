#include <SessionProtos.pb.h>
#include <fmt/format.h>

#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <fstream>
#include <session/client.hpp>
#include <session/hash.hpp>
#include <session/network/backends/session_file_server.hpp>
#include <session/sqlite.hpp>

#include "live_utils.hpp"

using namespace session;
using namespace session::client;
using namespace std::literals;

namespace {

struct LiveClient {
    std::filesystem::path dir;
    std::unique_ptr<Client> client;

    LiveClient() :
            dir{std::filesystem::temp_directory_path() /
                fmt::format("{}", random::unique_id("live_client", 7))} {
        std::filesystem::create_directories(dir);
        client = std::make_unique<Client>(dir / "client.db");
        client->core.set_network([this](session::network::NetworkHooks hooks) {
            return make_testnet_network(dir / "netcache", std::move(hooks));
        });
    }

    ~LiveClient() {
        client.reset();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }

    Client* operator->() { return client.get(); }
};

// Waits for the message to leave `uploading`, which is the only state the caller is told nothing
// more about: everything after it is reported through send state changes.
bool wait_until_sent(Client& c, int64_t id, std::chrono::seconds limit) {
    auto deadline = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < deadline) {
        auto msg = c.message(id, await);
        REQUIRE(msg);
        if (msg->send_state == SendState::sent)
            return true;
        if (msg->send_state == SendState::failed || msg->send_state == SendState::unsendable)
            return false;
        std::this_thread::sleep_for(200ms);
    }
    return false;
}

}  // namespace

TEST_CASE(
        "Live: a message's attachment is uploaded and named in what is stored", "[live][client]") {
    auto file = std::filesystem::temp_directory_path() / "live_attachment_send.bin";
    std::vector<std::byte> contents(64 * 1024);
    randombytes_buf(contents.data(), contents.size());
    {
        std::ofstream out{file, std::ios::binary};
        out.write(reinterpret_cast<const char*>(contents.data()), contents.size());
    }

    LiveClient c;
    b33 me;
    std::ranges::copy(c->core.globals.session_id(), me.begin());

    std::vector<std::tuple<size_t, int64_t, int64_t, std::optional<Expected<void>>>> reports;
    auto id = c->send_message(
            ConversationId::dm(me),
            {.body = "with an attachment",
             .attachments = {OutgoingAttachment{
                     .path = file, .content_type = "application/octet-stream"}}},
            [&](size_t idx, int64_t sent, int64_t total, std::optional<Expected<void>> result) {
                reports.emplace_back(idx, sent, total, std::move(result));
            },
            await);

    REQUIRE(wait_until_sent(*c.client, id, 120s));

    // The upload reported itself finished, and did so as a result rather than by reaching the
    // total: the file server's acceptance is what counts.
    REQUIRE(!reports.empty());
    auto& [idx, sent, total, result] = reports.back();
    CHECK(idx == 0);
    REQUIRE(result.has_value());
    CHECK(result->has_value());
    CHECK(total > 0);

    // What was stored has to name the upload, or the recipient has no way to fetch it.
    // Both columns are blobs, and the content's length is not fixed -- so it is read as a `blob`
    // view from a statement kept alive around it, rather than through a one-shot call that would
    // finalize the statement and invalidate the view.
    std::vector<std::byte> raw;
    int64_t stored_msgid = 0;
    {
        auto conn = c->core.database().conn();
        auto st = conn.prepared_bind(
                "SELECT r.content, m.msgid FROM message_raw_content r"
                " JOIN messages m ON m.id = r.message WHERE r.message = ?",
                id);
        REQUIRE(st->executeStep());
        auto [content, msgid] = sqlite::get<sqlite::blob, int64_t>(*st);
        raw.assign(content.begin(), content.end());
        stored_msgid = msgid;
    }

    SessionProtos::Content parsed;
    REQUIRE(parsed.ParseFromArray(raw.data(), static_cast<int>(raw.size())));
    REQUIRE(parsed.has_datamessage());
    REQUIRE(parsed.datamessage().attachments_size() == 1);

    const auto& ptr = parsed.datamessage().attachments(0);
    CHECK(ptr.has_url());
    CHECK(!ptr.url().empty());
    CHECK(ptr.key().size() == 32);
    CHECK(ptr.contenttype() == "application/octet-stream");

    // The file's own size, exactly -- not the encrypted size the file server reports back, which is
    // larger and is what every other client would misread.  Pinned to the byte rather than to `>
    // 0`, which is what let the two be confused in the first place.
    CHECK(ptr.size() == contents.size());

    // The url has to be one the download path can actually use, rather than merely non-empty.
    auto info = network::file_server::parse_download_url(ptr.url());
    REQUIRE(info);
    CHECK(!info->file_id.empty());

    // ...and it has to say how the file is encrypted.  upload_file only ever uses the stream
    // scheme, so a url without this fragment sends every recipient to the legacy decryptor, which
    // cannot open it: an unopenable attachment rather than a failed download.
    CHECK(info->wants_stream_decryption);

    // Also asserted on the url itself, since the check above would pass just as happily if both
    // sides of the round trip were wrong together.
    CHECK(ptr.url().find('#') != std::string::npos);

    // And the deprecated numeric id, which old clients still read, has to agree with it while the
    // file server is still issuing numeric ids.
    if (std::ranges::all_of(info->file_id, [](char ch) { return ch >= '0' && ch <= '9'; }))
        CHECK(std::to_string(ptr.id()) == info->file_id);

    // The one that would corrupt a conversation rather than merely break a download.  Sending with
    // attachments stores the message twice: once with the body alone, and again once the uploads
    // have given it something to point at.  The identifier has to survive that rewrite, because it
    // is what the copy returning from our own swarm is recognised by -- so the content finally sent
    // must carry the same one the row was stored with, rather than a fresh one.
    REQUIRE(parsed.has_msgid());
    CHECK(parsed.msgid() == stored_msgid);

    std::filesystem::remove(file);
}
