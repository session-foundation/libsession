#pragma once

#include <SessionProtos.pb.h>

#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <fstream>
#include <future>
#include <oxen/quic/loop.hpp>
#include <session/attachments.hpp>
#include <session/client.hpp>
#include <session/clock.hpp>
#include <session/config/contacts.hpp>
#include <session/config/convo_info_volatile.hpp>
#include <session/config/expiring.hpp>
#include <session/config/namespaces.hpp>
#include <session/config/user_profile.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/format.hpp>
#include <session/random.hpp>
#include <session/session_protocol.hpp>
#include <thread>

#include "../test_helper.hpp"

using namespace session;
using namespace session::client;
using namespace std::literals;
using namespace oxenc::literals;

/// Named rather than anonymous, and `inline` rather than `static`: nine translation units include
/// this, and an anonymous namespace would give each its own copy of every helper and a warning for
/// each one it happens not to use.  The using-directive at the bottom is what keeps the test bodies
/// reading as they did when they were all one file.
namespace client_test {

struct SenderKeys {
    b32 ed_pk;
    b64 ed_sk;
    b33 session_id;

    SenderKeys() {
        ed25519::keypair(ed_pk, ed_sk);
        ed25519::pk_to_session_id(session_id, ed_pk);
    }
};

/// RAII Client over a unique temporary database, mirroring TempCore.  Unlike TempCore this can
/// close and reopen the same file, which is how the restart behaviour is exercised.
struct TempClient {
    std::filesystem::path path;
    std::unique_ptr<Client> client;

    template <core::CoreOption... Opts>
    explicit TempClient(Opts&&... opts) :
            path{std::filesystem::temp_directory_path() /
                 fmt::format("{}.db", random::unique_id("test_client", 7))},
            client{std::make_unique<Client>(path, std::forward<Opts>(opts)...)} {}

    template <core::CoreOption... Opts>
    explicit TempClient(callbacks cbs, Opts&&... opts) :
            path{std::filesystem::temp_directory_path() /
                 fmt::format("{}.db", random::unique_id("test_client", 7))},
            client{std::make_unique<Client>(path, std::move(cbs), std::forward<Opts>(opts)...)} {}

    template <core::CoreOption... Opts>
    void reopen(Opts&&... opts) {
        client.reset();
        client = std::make_unique<Client>(path, std::forward<Opts>(opts)...);
    }

    ~TempClient() {
        client.reset();
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }

    Client* operator->() { return client.get(); }
    Client& operator*() { return *client; }
};

/// A cache directory that removes itself, so a failing assertion cannot leave one behind.
struct TempCacheDir {
    std::filesystem::path path{
            std::filesystem::temp_directory_path() /
            fmt::format("{}", random::unique_id("test_cache", 8))};

    TempCacheDir() { std::filesystem::create_directories(path); }
    ~TempCacheDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

inline b33 own_sid(Client& c) {
    b33 out;
    std::ranges::copy(c.core.globals.session_id(), out.begin());
    return out;
}

/// `c`'s own sending keys, for building the copy of an outgoing message that Session stores on the
/// sender's own swarm.
inline SenderKeys self_keys(Client& c) {
    SenderKeys k;
    auto seed = c.core.globals.account_seed();
    std::ranges::copy(seed.ed25519_secret(), k.ed_sk.begin());
    std::ranges::copy(seed.ed25519_secret().last<32>(), k.ed_pk.begin());
    std::ranges::copy(c.core.globals.session_id(), k.session_id.begin());
    return k;
}

/// Marks an account as approved, which is what having written to them would have done.
///
/// A stranger's first message is a message request, so a test that is about anything else -- the
/// ordering of the list, what a priority does, what a handler is told -- has to say that this is an
/// ordinary conversation, or the list it is asking about is empty.
inline void approve(Client& c, const b33& sid) {
    c.core.loop().call_get([&] {
        auto conn = c.core.database().conn();
        conn.prepared_exec("INSERT OR IGNORE INTO accounts (session_id) VALUES (?)", sid);
        conn.prepared_exec(
                R"(
            INSERT INTO contacts (account, approved)
            VALUES ((SELECT id FROM accounts WHERE session_id = ?), 1)
            ON CONFLICT (account) DO UPDATE SET approved = 1
        )",
                sid);
        return 0;
    });
}

/// Builds, encrypts and delivers a v1 DM into `to` as if it had arrived from the swarm.
inline void deliver(
        Client& to,
        const SenderKeys& from,
        std::string_view body,
        sys_ms ts,
        std::string hash,
        std::string_view display_name = "",
        std::optional<b33> sync_target = std::nullopt,
        const std::function<void(SessionProtos::DataMessage&)>& decorate = nullptr,
        std::optional<int64_t> msgid = std::nullopt) {
    SessionProtos::Content content;
    content.set_sigtimestamp(static_cast<uint64_t>(ts.time_since_epoch().count()));
    if (msgid)
        content.set_msgid(*msgid);
    auto* data = content.mutable_datamessage();
    data->set_body(std::string{body});
    if (!display_name.empty())
        data->mutable_profile()->set_displayname(std::string{display_name});
    if (sync_target)
        data->set_synctarget(oxenc::to_hex(sync_target->begin(), sync_target->end()));
    if (decorate)
        decorate(*data);

    auto plaintext = content.SerializeAsString();
    auto encoded = encode_dm_v1(
            std::as_bytes(std::span{plaintext}), from.ed_sk, ts, own_sid(to), std::nullopt);

    core::SwarmMessage sm{encoded, std::move(hash), ts, from_epoch_ms(1'000'000'000'000)};

    // Core delivers arriving messages from its event loop, so do the same here rather than writing
    // the database from the test thread: the connection pool is single-threaded by design.
    to.core.loop().call_get([&] {
        to.core.receive_messages({&sm, 1}, config::Namespace::Default, true);
        return 0;
    });
}

/// Records every callback so a test can assert on what a subscriber was told, and in what order.
struct Recorder {
    std::vector<std::string> order;
    std::vector<AnyConversation> added, updated;
    std::vector<ConversationId> removed;
    std::vector<ConversationList> removed_from;
    std::vector<std::vector<AnyConversation>> replaced, requests_replaced;

    /// One entry per *call*, so a test can tell one report of three messages from three reports of
    /// one.  `messages()` below flattens them when only the content matters.
    std::vector<std::vector<Message>> msg_added, msg_updated;

    /// Every message in `batches`, in the order it was reported.
    static std::vector<Message> messages(const std::vector<std::vector<Message>>& batches) {
        std::vector<Message> all;
        for (const auto& batch : batches)
            all.insert(all.end(), batch.begin(), batch.end());
        return all;
    }
    /// Where each event said its row was and now belongs, kept apart so a test can say which
    /// callback it means.
    std::vector<ListPlacement> add_placements, placements;

    callbacks handlers() {
        return {
                .conversation_added =
                        [this](AnyConversation&& c, ListPlacement&& p) {
                            order.push_back("added");
                            added.push_back(std::move(c));
                            add_placements.push_back(std::move(p));
                        },
                .conversation_updated =
                        [this](AnyConversation&& c, ListPlacement&& p) {
                            order.push_back("updated");
                            updated.push_back(std::move(c));
                            placements.push_back(std::move(p));
                        },
                .conversation_removed =
                        [this](ConversationId&& id, ConversationList from) {
                            order.push_back("removed");
                            removed.push_back(std::move(id));
                            removed_from.push_back(from);
                        },
                .conversation_list_replaced =
                        [this](std::vector<AnyConversation>&& l) {
                            order.push_back("replaced");
                            replaced.push_back(std::move(l));
                        },
                .request_list_replaced =
                        [this](std::vector<AnyConversation>&& l) {
                            order.push_back("requests");
                            requests_replaced.push_back(std::move(l));
                        },
                .messages_added =
                        [this](std::vector<Message>&& m) {
                            order.push_back("message");
                            msg_added.push_back(std::move(m));
                        },
                .messages_updated =
                        [this](std::vector<Message>&& m) {
                            order.push_back("messages_updated");
                            msg_updated.push_back(std::move(m));
                        },
        };
    }
};

/// Waits for work Client deferred onto the loop -- the coalesced conversation_updated -- to have
/// run, by queueing a job behind it and waiting on that.
///
/// **This does not settle everything.**  `process_job_queue` swaps the queue out and drains only
/// what was in it, so a `call_soon` issued from *within* a job lands in the next batch and needs
/// another `sync` to run.  Worse, a job that a transaction queued may run before that transaction
/// commits, since the commit happens further up the stack than the job knows about -- so a second
/// connection can see the row as it was, or not at all.  A test that waits on state written that
/// way is testing the scheduler.  Wait on the observable outcome instead.
inline void sync(Client& c) {
    // Work goes back and forth between the two: a download's bytes are handled on the disk loop,
    // which reports its end onto Core's, which may send it back to read the file.  A few rounds
    // covers the longest such exchange.
    for (int i = 0; i < 3; i++) {
        c.core.disk_loop()->call_get([] { return 0; });
        c.core.loop().call_get([] { return 0; });
    }
}

/// The body of a conversation's last-message preview, or "" if it has no preview at all.
///
/// So that an assertion about the body reads as one: dereferencing the optional in the CHECK itself
/// would make "there is no preview" undefined behaviour rather than a failure, and a test that
/// crashes instead of failing tells you nothing about which of the two went wrong.  A test that
/// cares about the difference asserts on `last_preview()` directly.
inline std::string preview_body(const AnyConversation& c) {
    const auto& p = c.last_preview();
    return p ? p->body : "";
}

/// Reads something out of the account's configs, on Core's loop where they belong.
///
/// The configs are the loop's -- see `core::detail::CoreComponent` -- and a test is on its own
/// thread like any other application.  `Client` wraps the parts an application actually wants;
/// this is for the tests that reach past it to check what was written underneath.
///
/// **Return a value.**  Anything pointing into a config -- a reference, or the `string_view` that
/// getters like `get_name()` hand back -- is dangling the moment this returns, since the config is
/// only ours for as long as the excursion lasts.  Copy it inside the lambda.
template <typename F>
auto in_configs(Client& c, F&& f) {
    return TestHelper::on_loop(c.core, [&] { return f(c.core.configs); });
}

/// Whether a transfer's progress `result` says it ended well.
inline bool succeeded(const std::optional<Expected<void>>& result) {
    return result && result->has_value();
}

/// The code a transfer's progress `result` failed with, or nullopt if it has not ended or did not
/// fail.
inline std::optional<std::string_view> failure_code(const std::optional<Expected<void>>& result) {
    if (!result || result->has_value())
        return std::nullopt;
    return result->error().code;
}

}  // namespace client_test

using namespace client_test;
