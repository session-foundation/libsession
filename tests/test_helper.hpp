#pragma once

#include <fmt/format.h>
#include <oxenc/base64.h>

#include <filesystem>
#include <fstream>
#include <map>
#include <nlohmann/json.hpp>
#include <session/attachments.hpp>
#include <session/core.hpp>
#include <session/core/devices.hpp>
#include <session/format.hpp>
#include <session/network/backends/session_file_server.hpp>
#include <session/network/key_types.hpp>
#include <session/network/routing/network_router.hpp>
#include <session/network/session_network.hpp>
#include <session/network/snode_pool.hpp>
#include <session/random.hpp>
#include <session/sodium_array.hpp>
#include <session/sqlite.hpp>
#include <session/util.hpp>
#include <span>

namespace session {

// nlohmann can't parse a std::byte range directly: libc++'s std::char_traits has no std::byte
// specialization.  Parse request/response bodies via a char view instead.
inline nlohmann::json parse_json(std::span<const std::byte> body) {
    return nlohmann::json::parse(to_string_view(body));
}

/// One message as a storage server's `retrieve` lists it (oxenss `process_retrieve`): every field,
/// every time, and `data` base64-encoded, as it is for a json request.  A real expiry by default:
/// a link request takes it as its deadline, and a group is in view only until it.
inline nlohmann::json retrieved_message(
        std::span<const std::byte> data,
        std::string_view hash,
        sys_ms timestamp = clock_now_ms(),
        sys_ms expiration = clock_now_ms() + std::chrono::minutes{10}) {
    return {{"hash", hash},
            {"timestamp", epoch_ms(timestamp)},
            {"expiration", epoch_ms(expiration)},
            {"data", oxenc::to_base64(to_string_view(data))}};
}

/// The body of a `retrieve` answer, as the server sends it: always both fields.
inline nlohmann::json retrieved_body(
        nlohmann::json messages = nlohmann::json::array(), bool more = false) {
    return {{"messages", std::move(messages)}, {"more", more}};
}

/// A minimal in-process mock of network::Network for unit tests.
/// Tests can set `current_node` to control which node get_swarm returns, and inspect
/// `sent_requests` to observe outgoing requests and fire their callbacks.
class MockNetwork : public network::Network {
  public:
    explicit MockNetwork(network::config::Config config = {}) :
            network::Network(std::move(config)) {}

    struct SentRequest {
        network::Request request;
        network::network_response_callback_t callback;
    };
    std::vector<SentRequest> sent_requests;

    // The node returned by get_swarm; tests can change this to simulate swarm-member switches.
    network::service_node current_node;

    // The whole swarm, for code that asks every member rather than one.  Returned instead of
    // `current_node` when set.
    std::vector<network::service_node> current_swarm;

    /// Set to answer requests as they are sent rather than leaving them in `sent_requests` for the
    /// test to fire by hand.  Return nullopt to leave one pending.
    ///
    /// Called with the request; the tuple is (success, timeout, status, body).  Requests are still
    /// recorded either way, so a test can assert on what was sent as well as script the answer.
    using Reply = std::tuple<bool, bool, int16_t, std::optional<std::string>>;
    std::function<std::optional<Reply>(const network::Request&)> auto_reply;

    /// The Core this is attached to, set by attach_mock_network, so that a response driven by hand
    /// can be delivered on Core's loop as a real one is.  Null only for a MockNetwork built
    /// directly, which is what the Network-level tests do.
    core::Core* core = nullptr;

    void send_request(
            network::Request request, network::network_response_callback_t callback) override {
        std::optional<Reply> scripted;
        if (auto_reply)
            scripted = auto_reply(request);

        // Wrapped so that answering lands on Core's loop, which is where a real response is
        // handled: the Network delivers on its own thread and Core marshals it across.  Done here
        // rather than at each answering helper because a test may fire `sent_requests[i].callback`
        // itself, and what that prompts -- continuing a swarm walk, writing a cache entry -- would
        // otherwise sit on the queue until something else happened to run it.  `call_get` is inline
        // once already on the loop, so scripted replies, which are sent from there, cost nothing.
        network::network_response_callback_t on_loop =
                [this, callback = std::move(callback)](
                        bool ok,
                        bool timeout,
                        int16_t status,
                        std::vector<std::pair<std::string, std::string>> headers,
                        std::optional<std::string> body) {
                    if (!core)
                        return callback(ok, timeout, status, std::move(headers), std::move(body));
                    core->call_get([&] {
                        callback(ok, timeout, status, std::move(headers), std::move(body));
                    });
                };

        sent_requests.push_back({std::move(request), on_loop});

        if (scripted) {
            auto [ok, timeout, status, body] = std::move(*scripted);
            on_loop(ok, timeout, status, {}, std::move(body));
        }
    }

    void get_swarm(
            network::x25519_pubkey /*swarm_pubkey*/,
            bool /*ignore_strike_count*/,
            std::function<
                    void(network::swarm_id_t swarm_id, std::vector<network::service_node> swarm)>
                    callback) override {
        if (current_swarm.empty())
            callback(0, {current_node});
        else
            callback(0, current_swarm);
    }

    std::vector<network::DownloadRequest> downloads;

    void download(network::DownloadRequest request) override {
        downloads.push_back(std::move(request));
    }

    // A file server, in as much as anything needs one: uploads are encrypted and kept here, and a
    // download of one serves it back.  Enough to round-trip an attachment through the code that
    // sends and saves it without a network, which is the only part of a file server that is
    // interesting to test against.
    //
    // `served` is keyed by the id in the download url, so a url built by generate_download_url from
    // what upload_file returned finds its way back to the right bytes.
    std::map<std::string, std::vector<std::byte>> served;
    int next_file_id = 1000;

    void upload_file(network::FileUploadRequest request, std::span<const std::byte> seed) override {
        // Encrypted the same way the routers do it, so what a save reads back is what a real
        // upload would have left on the server: same scheme, same padding, same key derivation.
        std::vector<std::byte> plain;
        {
            std::ifstream in{request.file, std::ios::binary};
            std::string bytes{std::istreambuf_iterator<char>{in}, {}};
            plain = to_vector<std::byte>(bytes);
        }
        auto [ciphertext, key] =
                attachment::encrypt(seed, plain, request.domain, request.allow_large);

        auto id = std::to_string(next_file_id++);
        served.emplace(id, std::move(ciphertext));

        network::file_metadata meta{id, static_cast<int64_t>(served.at(id).size()), {}, {}};
        if (request.on_progress)
            request.on_progress(meta.size, meta.size);
        if (request.on_complete)
            request.on_complete(std::pair{meta, key}, false);
    }
};

/// Gives `core` a fresh MockNetwork and hands back a non-owning pointer to it.  A Core owns its
/// Network outright -- nothing else may hold it alive -- so a test that goes on poking at the mock
/// keeps a raw pointer rather than a second reference.
///
/// `config` for a test that depends on how the network is configured -- which router it uses, say.
inline MockNetwork* attach_mock_network(core::Core& core, network::config::Config config = {}) {
    auto net = std::make_unique<MockNetwork>(std::move(config));
    auto* raw = net.get();
    raw->core = &core;
    core.set_network(std::move(net));
    return raw;
}

/// Answers one captured download with `data`, delivered in chunks as a transport would rather than
/// in one piece -- a decryptor that only works when handed the whole file at once is a bug this is
/// meant to catch -- and stops the moment its caller asks it to, as a router does.  Returns how
/// many chunks were delivered, which is how a test tells a transfer that was cut short from one
/// that ran to the end.
///
/// `between` runs after each chunk.  A consumer that handles chunks on a thread of its own only
/// asks to stop once it has got to one, and a test counting how soon that happens lets it catch up
/// here -- as a real transfer's pace would -- rather than having every chunk delivered first.
inline size_t serve_one_download(
        network::DownloadRequest& r,
        std::string id,
        std::span<const std::byte> data,
        size_t chunk = 4096,
        std::function<void()> between = nullptr) {
    network::file_metadata meta{std::move(id), static_cast<int64_t>(data.size()), {}, {}};
    size_t delivered = 0;
    for (size_t at = 0; at < data.size() && !r.is_cancelled(); at += chunk) {
        r.on_data(meta, data.subspan(at, std::min(chunk, data.size() - at)));
        delivered++;
        if (between)
            between();
    }
    if (r.is_cancelled())
        r.on_complete(network::ERROR_REQUEST_CANCELLED, false);
    else
        r.on_complete(meta, false);
    return delivered;
}

/// Answers every captured download with `data`.  Returns how many there were.
inline size_t serve_downloads(
        MockNetwork& net, std::span<const std::byte> data, size_t chunk = 4096) {
    auto pending = std::exchange(net.downloads, {});
    for (auto& r : pending)
        serve_one_download(r, "served", data, chunk);
    return pending.size();
}

/// Answers every captured download from what was uploaded, looked up by the file id in its url --
/// so a message whose attachment this Client uploaded can be saved back through the same object.
/// A url naming something never uploaded is answered as the file server answers a missing file.
inline size_t serve_downloads(MockNetwork& net, size_t chunk = 4096) {
    auto pending = std::exchange(net.downloads, {});
    for (auto& r : pending) {
        auto info = network::file_server::parse_download_url(r.download_url);
        auto found = info ? net.served.find(info->file_id) : net.served.end();
        if (found == net.served.end()) {
            r.on_complete(static_cast<int16_t>(404), false);
            continue;
        }

        serve_one_download(r, info->file_id, found->second, chunk);
    }
    return pending.size();
}

/// Fails every captured download, as a file server that no longer holds the file would.
inline size_t fail_downloads(MockNetwork& net, int16_t status = 404) {
    auto pending = std::exchange(net.downloads, {});
    for (auto& r : pending)
        r.on_complete(status, false);
    return pending.size();
}

/// Keeps everything a Core reports through DeviceEvents, in order.  Reports arrive on Core's loop,
/// so a test reads these after draining it.  `on_added` runs inside the report itself, for a test
/// that needs to look at the state it is reported in.
struct DeviceEventsRecorder : core::DeviceEvents {
    std::function<void(const core::device::LinkRequest&)> on_added;

    std::vector<core::device::LinkRequest> added;
    std::vector<std::pair<int, core::device::LinkRequestEnd>> ended;
    std::vector<core::device::map> replaced;
    std::vector<core::device::Membership> membership;
    std::vector<core::device::Info> members;
    std::vector<std::string> order;  // which of them, as they arrived

    void link_request_added(core::device::LinkRequest request) override {
        if (on_added)
            on_added(request);
        order.push_back("added");
        added.push_back(std::move(request));
    }
    void link_request_ended(int reqid, core::device::LinkRequestEnd why) override {
        order.push_back("ended");
        ended.emplace_back(reqid, why);
    }
    void devices_replaced(core::device::map devices) override {
        order.push_back("replaced");
        replaced.push_back(std::move(devices));
    }
    void membership_changed(core::device::Membership m) override {
        order.push_back("membership");
        membership.push_back(m);
    }
    void device_membership_changed(core::device::Info device) override {
        order.push_back("member");
        members.push_back(std::move(device));
    }
};

/// The store requests a MockNetwork has captured, in the order they were sent.  Filtered rather
/// than taken wholesale because a Core with a network attached also fetches PFS keys, so a test
/// that asked for a send finds retrieves in the list it never asked for.
inline std::vector<MockNetwork::SentRequest*> stores(MockNetwork& net) {
    std::vector<MockNetwork::SentRequest*> found;
    for (auto& r : net.sent_requests)
        if (r.request.endpoint == "store")
            found.push_back(&r);
    return found;
}

/// The swarm polls a MockNetwork has captured.  Filtered rather than taken wholesale for the same
/// reason as `stores()`: a poll is a "batch" of retrieves and a push is a "sequence", so a test
/// that counts requests to check how many times it polled also counts whatever the poll went on to
/// send.
inline std::vector<MockNetwork::SentRequest*> polls(MockNetwork& net) {
    std::vector<MockNetwork::SentRequest*> found;
    for (auto& r : net.sent_requests)
        if (r.request.endpoint == "batch")
            found.push_back(&r);
    return found;
}

/// The swarm pushes a MockNetwork has captured.  A push is a "sequence" of store subrequests
/// followed by at most one delete, so its payload is inside the body rather than in the request
/// itself the way a bare "store" endpoint's is.
inline std::vector<MockNetwork::SentRequest*> pushes(MockNetwork& net) {
    std::vector<MockNetwork::SentRequest*> found;
    for (auto& r : net.sent_requests)
        if (r.request.endpoint == "sequence")
            found.push_back(&r);
    return found;
}

/// The subrequests a push carries, in the order they will be applied.
inline nlohmann::json push_requests(const MockNetwork::SentRequest& r) {
    if (!r.request.body)
        throw std::logic_error{"push request has no body"};
    return parse_json(*r.request.body)["requests"];
}

/// The JSON a store request carries, which is where the namespace and the payload are.
inline nlohmann::json store_body(const MockNetwork::SentRequest& r) {
    if (!r.request.body)
        throw std::logic_error{"store request has no body"};
    return parse_json(*r.request.body);
}

/// The encrypted message a store request is depositing, decoded back out of its base64.
inline std::vector<std::byte> store_payload(const MockNetwork::SentRequest& r) {
    return to_vector<std::byte>(oxenc::from_base64(store_body(r)["data"].get<std::string_view>()));
}

/// The hash answer_stores has the swarm assign a store.  Distinct per destination swarm, so that a
/// test can tell the copy of an outgoing message left in our own swarm from the recipient's.
inline std::string store_hash_for(std::string_view pubkey_hex) {
    return "hash-for-{}"_format(pubkey_hex);
}

/// Hands the first `max` captured requests that `which` picks to `respond`, leaving everything else
/// pending, and returns how many were answered.
///
/// The pending list is taken away before any of it runs, and must be: a response can prompt Core to
/// send something new, and that push_back would otherwise reallocate `sent_requests` out from under
/// the very callback being invoked.
inline size_t answer_requests(
        MockNetwork& net,
        const std::function<bool(const MockNetwork::SentRequest&)>& which,
        const std::function<void(MockNetwork::SentRequest&)>& respond,
        size_t max = std::numeric_limits<size_t>::max()) {
    auto pending = std::exchange(net.sent_requests, {});
    size_t answered = 0;
    std::vector<MockNetwork::SentRequest> others;

    for (auto& r : pending) {
        if (answered < max && which(r)) {
            respond(r);
            answered++;
        } else
            others.push_back(std::move(r));
    }

    // Whatever the responses prompted belongs in the list too, after what was already waiting: it
    // was sent later, and "the oldest one not yet answered" has to keep meaning that.
    auto prompted = std::exchange(net.sent_requests, std::move(others));
    for (auto& r : prompted)
        net.sent_requests.push_back(std::move(r));

    return answered;
}

/// The same, for the requests to `endpoint`.
inline size_t answer_requests(
        MockNetwork& net,
        std::string_view endpoint,
        const std::function<void(MockNetwork::SentRequest&)>& respond,
        size_t max = std::numeric_limits<size_t>::max()) {
    return answer_requests(
            net,
            [endpoint](const MockNetwork::SentRequest& r) {
                return r.request.endpoint == endpoint;
            },
            respond,
            max);
}

/// A MockNetwork whose routing can carry the storage servers' pushes, so that a drained poll goes
/// on to subscribe -- as the default, onion requests, never does.
inline MockNetwork* attach_push_network(core::Core& core) {
    network::config::Config config;
    config.router = network::opt::router::Type::direct;
    return attach_mock_network(core, std::move(config));
}

/// Answers the oldest captured poll batch: each namespace with what `held` has for it (message and
/// hash), the rest with nothing.  Or fails it, as an unreachable member would.  Returns whether
/// there was one.
inline bool answer_batch(
        MockNetwork& net,
        const std::map<int, std::vector<std::pair<std::vector<std::byte>, std::string>>>& held = {},
        bool reached = true) {
    return answer_requests(
                   net,
                   "batch",
                   [&](MockNetwork::SentRequest& r) {
                       if (!reached)
                           return r.callback(false, true, 0, {}, std::nullopt);
                       auto results = nlohmann::json::array();
                       // Bound first: ranging over a temporary's element would read it after it
                       // has gone.
                       auto batch = parse_json(*r.request.body);
                       for (const auto& req : batch["requests"]) {
                           auto body = retrieved_body();
                           if (auto it = held.find(req["params"]["namespace"].get<int>());
                               it != held.end())
                               for (const auto& [data, hash] : it->second)
                                   body["messages"].push_back(retrieved_message(data, hash));
                           results.push_back({{"code", 200}, {"body", std::move(body)}});
                       }
                       r.callback(
                               true,
                               false,
                               200,
                               {},
                               nlohmann::json{{"results", std::move(results)}}.dump());
                   },
                   1) == 1;
}

/// Answers the polls pending (a caller polls first) until drained, and accepts the subscription
/// that follows, as a storage server does: from here nothing polls.  Leaves the poll Core sends on
/// subscribing -- the one that closes the gap between draining and the subscription taking effect
/// -- unanswered, for the caller.  Returns whether there was a subscription to accept.
inline bool subscribe(MockNetwork& net) {
    while (answer_batch(net)) {
    }
    return answer_requests(
                   net,
                   "monitor",
                   [](MockNetwork::SentRequest& r) {
                       r.callback(true, false, 200, {}, "d7:successi1ee");
                   },
                   1) == 1;
}

/// Answers every captured store, and returns how many there were -- which is itself worth asserting
/// on, since an outgoing message is two stores and a note to self is one.
inline size_t answer_stores(MockNetwork& net, bool accepted) {
    return answer_requests(net, "store", [accepted](MockNetwork::SentRequest& r) {
        if (accepted) {
            nlohmann::json resp = {
                    {"hash", store_hash_for(store_body(r)["pubkey"].get<std::string_view>())}};
            r.callback(true, false, 200, {}, resp.dump());
        } else
            r.callback(false, false, 500, {}, "nope");
    });
}

inline size_t accept_stores(MockNetwork& net) {
    return answer_stores(net, true);
}

/// Answers captured key fetches with these AccountPubkeys messages, or with none: the lookup that
/// found nothing, which releases a send queued behind it with the non-PFS encryption when no key is
/// held.
inline size_t answer_retrieves(
        MockNetwork& net,
        const std::vector<std::vector<std::byte>>& messages = {},
        size_t max = std::numeric_limits<size_t>::max()) {
    return answer_requests(
            net,
            "retrieve",
            [&](MockNetwork::SentRequest& r) {
                auto body = retrieved_body();
                for (const auto& m : messages)
                    body["messages"].push_back(retrieved_message(m, "pubkeys"));
                r.callback(true, false, 200, {}, body.dump());
            },
            max);
}

/// Times out captured key fetches: a failed lookup.
inline size_t fail_retrieves(MockNetwork& net, size_t max = std::numeric_limits<size_t>::max()) {
    return answer_requests(
            net,
            "retrieve",
            [](MockNetwork::SentRequest& r) { r.callback(false, true, 0, {}, std::nullopt); },
            max);
}

// Smart-pointer-like RAII wrapper around a Core backed by a unique temporary DB file.
// The DB file is removed on destruction.  Default encryption uses a zeroed raw_key.
// If `extra_dir` is set, that directory tree is also removed recursively on destruction (used by
// make_live_core to clean up the network's cache directory).
struct TempCore {
    std::filesystem::path path;
    std::optional<std::filesystem::path> extra_dir;
    std::unique_ptr<core::Core> core;

    template <core::CoreOption... Opts>
    explicit TempCore(Opts&&... opts) :
            path{std::filesystem::temp_directory_path() /
                 fmt::format("{}.db", session::random::unique_id("test_core", 7))},
            core{std::make_unique<core::Core>(path, std::forward<Opts>(opts)...)} {}

    TempCore(TempCore&&) = default;
    TempCore& operator=(TempCore&&) = default;

    ~TempCore() {
        core.reset();  // close DB before removing the file
        std::error_code ec;
        std::filesystem::remove(path, ec);
        if (extra_dir)
            std::filesystem::remove_all(*extra_dir, ec);
    }

    core::Core* operator->() { return core.get(); }
    core::Core& operator*() { return *core; }
};

/// Stands in for a real router so that Network's own logic -- which sits *above* routing, and which
/// MockNetwork's send_request override skips entirely -- can be driven without a network.
///
/// Every request is recorded and answered from `replies`, keyed by the destination node's pubkey,
/// so a test says "this node is unreachable, that one answers" and then asserts on which were tried
/// and in what order.  Everything else IRouter requires is a no-op: routing strategy is not what is
/// under test here.
class FakeRouter : public network::IRouter {
  public:
    struct Reply {
        bool success = true;
        bool timeout = false;
        int16_t status = 200;
        std::optional<std::string> body = "{}";
    };

    // Destination pubkey -> how that node answers.  Anything not named here answers as unreachable,
    // which makes "only this node works" the short thing to write.
    std::map<network::ed25519_pubkey, Reply> replies;
    Reply default_reply{false, false, network::ERROR_INVALID_DESTINATION, "Node is not reachable"};

    // Every destination tried, in order.  The point of most assertions.
    std::vector<network::ed25519_pubkey> tried;
    std::vector<std::chrono::milliseconds> timeouts;

    void send_request(
            network::Request request, network::network_response_callback_t callback) override {
        auto* node = std::get_if<network::service_node>(&request.destination);
        if (!node)
            return callback(false, false, network::ERROR_INVALID_DESTINATION, {}, "not a node");

        tried.push_back(node->remote_pubkey);
        timeouts.push_back(request.request_timeout);

        auto found = replies.find(node->remote_pubkey);
        const auto& reply = found != replies.end() ? found->second : default_reply;
        callback(reply.success, reply.timeout, reply.status, {}, reply.body);
    }

    void suspend() override {}
    void resume(bool) override {}
    void close_connections() override {}
    void clear_cache() override {}
    network::ConnectionStatus get_status() const override {
        return network::ConnectionStatus::connected;
    }
    void upload(network::UploadRequest) override {}
    void upload_file(network::FileUploadRequest, std::span<const std::byte>) override {}
    void download(network::DownloadRequest) override {}
};

class TestHelper {
  public:
    /// Polls the way the ticker does: on the loop.
    ///
    /// Not `core._poll()` on the caller's thread.  A poll reaches component state, which is the
    /// loop's alone, and everything the walk does afterwards keys off being there already --
    /// `JobQueue::call` runs inline inside the loop and defers outside it, so a poll driven from a
    /// test's own thread would answer its first member and leave the rest of the walk queued.
    static void poll(core::Core& core) {
        core.call_get([&core] { core._poll(); });
    }

    // When Core's own retry of a failed poll fires (unset with none scheduled), firing it now, and
    // whether the poll timer is running -- which it is not while subscribed.
    static std::optional<sys_ms> poll_retry_due(core::Core& core) {
        return core.call_get([&core] { return core._poll_retry_due; });
    }
    static void fire_poll_retry(core::Core& core) {
        core.call_get([&core] {
            if (core._poll_retry_timer)
                core._jq.wake(core._poll_retry_timer);
        });
        // A wake runs the timer on a later turn of the loop; wait for it.
        drain(core);
    }
    static bool polling(core::Core& core) {
        return core.call_get([&core] { return static_cast<bool>(core._poll_timer); });
    }

    /// Runs `f` on Core's loop and hands back what it returned.
    ///
    /// Core's components are the loop's, not the caller's, and a test is on its own thread like
    /// any other application.  Wrap the body of anything reaching into `configs` -- or any other
    /// component state -- in one of these; there is no need for one per call, since everything
    /// inside runs on the loop for as long as `f` does.
    ///
    /// This is a test's version of what `Client` does for every one of its own methods.  There is
    /// deliberately no application-facing equivalent on `Configs`: nothing outside libsession
    /// reaches its accessors, and `Client` wraps the parts an application actually wants.
    template <typename F>
    static auto on_loop(core::Core& core, F&& f) {
        return core.call_get(std::forward<F>(f));
    }

    /// Runs everything already queued on Core's job queue and waits for it.
    ///
    /// Needed wherever a test drives a network response by hand: in production those arrive on the
    /// Network's own loop and Core marshals them onto its queue, so the work is finished a moment
    /// after the callback returns rather than during it.  A test calling the handler directly has
    /// to wait for that in the same way, and the queue is FIFO, so a round-trip through it is
    /// enough -- everything posted earlier has run by the time this returns.
    static void drain(core::Core& core) {
        on_loop(core, [] {});
    }

    /// Puts a swarm straight into the pool's cache.  get_swarm consults it first and answers from
    /// it without touching the network, which is what lets swarm-level behaviour be tested at all:
    /// a test pool has no seed nodes, so nothing would ever resolve otherwise.
    static void seed_swarm(
            network::SnodePool& pool,
            const network::x25519_pubkey& swarm_pubkey,
            std::vector<network::service_node> nodes) {
        pool._swarm_cache[swarm_pubkey] = {0, std::move(nodes)};
    }

    /// Substitutes the router beneath a Network, so its own logic can be exercised against
    /// scripted answers.  Also hands back the pool, which a test has to seed for anything
    /// swarm-addressed to resolve.
    static void set_router(network::Network& net, std::shared_ptr<network::IRouter> router) {
        net._router = std::move(router);
    }
    static network::SnodePool& snode_pool(network::Network& net) { return *net._snode_pool; }
    static oxen::quic::Loop& disk_loop(network::Network& net) { return *net._disk_loop; }

    static sqlite::Connection db_conn(core::Core& core) { return core.db.conn(); }

    /// Where a url's cached file lives, with the cache key applied.
    ///
    /// Asked of the Client rather than computed, because the name is keyed on a secret only it
    /// has -- which is the whole point, so that a directory listing is not a list of what this
    /// account has downloaded.  A test checking what was written has to ask whoever wrote it.
    ///
    /// A template for the same reason the config helpers below are: this header does not know the
    /// client types.
    template <typename Client>
    static std::filesystem::path cache_path(
            Client& c, std::string_view kind, std::string_view url) {
        return c._cache_path(kind, url);
    }

    /// Drives the database-to-config direction directly, which is what makes the round-trip
    /// assertable: applying a config and then deriving one back has to be the identity, and only a
    /// test can ask for the second half in isolation.
    ///
    /// A template so that this header need not know the client types; it is only ever instantiated
    /// where they are complete.
    ///
    /// Both hop onto the loop themselves rather than leaving it to the caller: what they reach is
    /// a `_`-form on Client, which is what Client's own methods call from inside `_async`, and it
    /// touches the configs.
    template <typename Client, typename Id>
    static void sync_contact(Client& c, const Id& id) {
        on_loop(c.core, [&] { c._sync_contact(id); });
    }

    template <typename Client, typename Id>
    static void sync_convo_volatile(Client& c, const Id& id) {
        on_loop(c.core, [&] { c._sync_convo_volatile(id); });
    }

    /// The push debounce, driven by hand.  A test that waited out real intervals would be both slow
    /// and racy -- the timer fires on the event loop while the test reads from its own thread -- so
    /// what is exercised here is the decision the timer makes, with the clock supplied.
    static bool push_scheduled(core::Configs& configs) { return configs._push_scheduled; }
    static void push_if_due(core::Configs& configs) { configs._push_if_due(); }
    static void backdate_push_state(
            core::Configs& configs,
            std::chrono::milliseconds since_last_change,
            std::chrono::milliseconds since_first_change) {
        auto now = std::chrono::steady_clock::now();
        configs._last_change = now - since_last_change;
        configs._burst_started = now - since_first_change;
    }

    // Returns whether the given migration name is recorded as applied.
    static bool migration_applied(core::Core& core, std::string_view name) {
        return core.db.conn()
                .prepared_maybe_get<std::string>(
                        "SELECT name FROM migrations_applied WHERE name = ?", name)
                .has_value();
    }

    // The cursor a retrieve from this namespace+node would send: the newest hash that node handed
    // us and still holds.  Derived rather than stored, so this asks the same question the poll
    // does.
    static std::optional<std::string> namespace_last_hash(
            core::Core& core, int16_t ns, const network::ed25519_pubkey& sn_pubkey) {
        return core.db.conn().prepared_maybe_get<std::string>(
                R"(
SELECT h.hash FROM swarm_hashes h JOIN swarm_nodes n ON n.id = h.node
 WHERE h.namespace = ? AND n.pubkey = ? AND (h.expiry IS NULL OR h.expiry > ?)
 ORDER BY h.id DESC LIMIT 1
)",
                ns,
                sn_pubkey,
                epoch_ms(clock_now_ms()));
    }

    // When the cursor entry for `hash` from this namespace+node lapses, in epoch ms; nullopt where
    // the node never said.  Throws if there is no such entry.
    static std::optional<int64_t> swarm_hash_expiry(
            core::Core& core,
            int16_t ns,
            const network::ed25519_pubkey& sn_pubkey,
            std::string_view hash) {
        return core.db.conn().prepared_get<std::optional<int64_t>>(
                R"(
SELECT h.expiry FROM swarm_hashes h JOIN swarm_nodes n ON n.id = h.node
 WHERE h.namespace = ? AND n.pubkey = ? AND h.hash = ?
)",
                ns,
                sn_pubkey,
                hash);
    }

    // Device group payload encryption/decryption, which are private to Devices, for tests that need
    // to build a group message with contents of their choosing.
    static std::vector<std::byte> encrypt_device_data(
            core::Devices& d, const core::device::map& devices) {
        return d.encrypt_device_data(devices);
    }
    // The same with a payload of the caller's making, encrypted to the devices `devices` lists as
    // live, under the current account key as the link key.
    static std::vector<std::byte> encrypt_device_payload(
            core::Devices& d, const core::device::map& devices, std::string payload) {
        std::vector<const core::device::Info*> records;
        for (const auto& [id, info] : devices)
            records.push_back(&info);
        return d._encrypt_group_payload(
                records, d.active_account_keys().front().x25519_pub, std::move(payload));
    }
    static std::vector<std::byte> decrypt_device_data(
            core::Devices& d, std::span<const std::byte> data) {
        return d.decrypt_device_data(data);
    }

    // Feeds an encrypted device group message through the receive path, as a poll would.  The hash
    // defaults to empty, which is a message with no swarm identity: merged, but never recorded as
    // something a push supersedes.
    static void receive_device_group_message(
            core::Devices& d, std::span<const std::byte> data, const std::string& hash = "") {
        d.receive_device_group_message(data, hash);
    }

    // Gives `core` another device's id, as a copy of that device's data would have it -- though
    // not its keys, which is what a copy that has since rotated them looks like.
    static void set_device_id(
            core::Core& core, std::span<const std::byte, core::device::ID_SIZE> id) {
        on_loop(core, [&] {
            std::ranges::copy(id, core.devices.self_id.begin());
            return 0;
        });
    }

    // The devices `core` holds its account key with X25519 pubkey `pub` as delivered to.
    static std::vector<core::device::Id> key_recipients(
            core::Core& core, std::span<const std::byte, 32> pub) {
        return on_loop(core, [&] {
            auto key = core.devices.conn().prepared_get<int64_t>(
                    "SELECT id FROM device_account_keys WHERE pubkey_x25519 = ?", pub);
            return core.devices._key_recipients(key);
        });
    }

    // Whether a group message's `kicked` list names `core`'s device.
    static bool names_us_kicked(core::Core& core, std::span<const std::byte> message) {
        return on_loop(core, [&] {
            return core.devices._unreadable_verdict(message) == core::device::Membership::Removed;
        });
    }

    // A link request as `request_link` builds it, asking to join `member`'s group, without the
    // upload, for a test that hands it to another device itself.  Leaves no deadline behind, so the
    // request never lapses on its own.
    static auto build_link_request(core::Core& core, core::Core& member) {
        auto link_x25519 = member.devices.active_account_keys().front().x25519_pub;
        auto group = *group_id(member);
        return on_loop(core, [&] { return core.devices._build_link_request(group, link_x25519); });
    }

    // A link request from `core` to `member`'s group carrying arbitrary contents, signed or not.
    static std::vector<std::byte> encrypt_link_request(
            core::Core& core, core::Core& member, std::span<const std::byte> plaintext) {
        auto link_x25519 = member.devices.active_account_keys().front().x25519_pub;
        return on_loop(
                core, [&] { return core.devices._encrypt_link_request(plaintext, link_x25519); });
    }

    // Gives `core` a group of its own, as a new account gets one -- a second group, on an account
    // that already has a first.
    static void start_device_group(core::Core& core) {
        on_loop(core, [&] {
            core.devices._mark_group_owed();
            core.devices.establish_group();
        });
    }

    // A tombstone dissolving `groups`, as `core` would publish it, without publishing it.
    static std::vector<std::byte> build_dissolution(
            core::Core& core, std::vector<core::device::GroupId> groups) {
        return on_loop(
                core, [&] { return core.devices._build_dissolution(groups, clock_now_ms()); });
    }

    static std::optional<core::device::GroupId> group_id(core::Core& core) {
        return on_loop(core, [&] { return core.devices._group_id(); });
    }
    static void set_group_id(core::Core& core, const core::device::GroupId& id) {
        on_loop(core, [&] { core.devices._set_group_id(id); });
    }
    // What `device_groups` holds for a group: its link key and when it expires.
    static std::optional<std::pair<std::array<std::byte, 32>, int64_t>> seen_group(
            core::Core& core, const core::device::GroupId& group) {
        return on_loop(core, [&]() -> std::optional<std::pair<std::array<std::byte, 32>, int64_t>> {
            auto row = core.devices.conn()
                               .prepared_maybe_get<
                                       sqlite::blob_guts<std::array<std::byte, 32>>,
                                       int64_t>(
                                       "SELECT link_x25519, expires_at FROM device_groups"
                                       " WHERE group_id = ?",
                                       std::span<const std::byte>{group.value});
            if (!row)
                return std::nullopt;
            auto& [key, expires] = *row;
            return std::pair{std::array<std::byte, 32>{key}, expires};
        });
    }

    static core::device::GroupId group_of(core::Core& core, std::span<const std::byte> message) {
        return on_loop(core, [&] { return core.devices._group_of(message); });
    }

    // Delivers one namespace-21 message as a completed fetch would: through the same dispatch, with
    // `is_final` set so the deferred work -- the prompts, and the ids they carry -- happens too,
    // and with the expiry the swarm assigned it, which a link request takes as its deadline.
    static void deliver_device_message(
            core::Core& core,
            std::span<const std::byte> data,
            sys_ms expiry,
            std::string hash = "hash",
            bool is_final = true) {
        on_loop(core, [&] {
            core::SwarmMessage m{
                    .data = data,
                    .hash = std::move(hash),
                    .timestamp = clock_now_ms(),
                    .expiry = expiry};
            core.devices.parse_device_messages(std::span{&m, 1}, is_final);
        });
    }

    // Leaves `hash` as where the next retrieve of `ns` from `node` resumes, as a poll that returned
    // it would.
    static void record_swarm_cursor(
            core::Core& core,
            const network::service_node& node,
            config::Namespace ns,
            std::string hash) {
        on_loop(core, [&] {
            core::SwarmMessage m{
                    .hash = std::move(hash),
                    .timestamp = clock_now_ms(),
                    .expiry = clock_now_ms() + std::chrono::hours{24}};
            core._record_swarm_cursor(node.remote_pubkey, ns, std::span{&m, 1});
        });
    }

    // Sets `core`'s rogue_account_key callback after the fact, for a Core built with other
    // callbacks of its own.
    static void set_message_send_status(
            core::Core& core,
            std::function<
                    void(int64_t,
                         core::MessageSendStatus,
                         std::optional<std::string_view>,
                         std::optional<core::MessageEncryption>)> f) {
        on_loop(core, [&] { core.callbacks.message_send_status = std::move(f); });
    }
    static void set_rogue_account_key(core::Core& core, std::function<void()> f) {
        on_loop(core, [&] { core.callbacks.rogue_account_key = std::move(f); });
    }
    // Fires it, as a rogue key judged would: for what a layer above Core does with it.
    static void fire_rogue_account_key(core::Core& core) {
        on_loop(core, [&] { core.callbacks.rogue_account_key(); });
    }

    // Ends a PFS key fetch for `session_id` as its answer would, firing pfs_keys_fetched.
    static void finish_pfs_fetch(
            core::Core& core, std::span<const std::byte, 33> session_id, core::PfsKeyFetch r) {
        on_loop(core, [&] { core._pfs_fetch_done(session_id, r); });
    }

    // The same for namespace -21: what the account's key outbox holds, as a fetch of it finds it.
    static void deliver_pubkey_message(
            core::Core& core, std::span<const std::byte> data, std::string hash = "pubkey") {
        on_loop(core, [&] {
            core::SwarmMessage m{
                    .data = data,
                    .hash = std::move(hash),
                    .timestamp = clock_now_ms(),
                    .expiry = clock_now_ms() + core::Devices::ACCOUNT_PUBKEY_TTL};
            core.devices.parse_account_pubkeys(std::span{&m, 1}, true);
        });
    }

    // A namespace-21 fetch completing with nothing new, which is still a completed fetch.
    static void finish_fetch(core::Core& core) {
        on_loop(core, [&] { core.devices.parse_device_messages({}, true); });
    }

    // Whether the fetch timer will fire by itself, and firing it now: what it does once its
    // interval is up, without waiting that out in real time.
    static bool fetch_timer_armed(core::Core& core) {
        return on_loop(core, [&] { return core.devices.jq().armed(core.devices._fetch_timer); });
    }
    static void fire_fetch_timer(core::Core& core) {
        on_loop(core, [&] { core.devices.jq().wake(core.devices._fetch_timer); });
    }

    // When a push that was not stored is next to be tried; unset with none pending a retry.
    static std::optional<sys_ms> push_retry_due(core::Core& core) {
        return on_loop(core, [&] { return core.devices._push_retry_at; });
    }

    // Core's one-off fetch of `namespaces`, as Devices asks for one.
    static void fetch(
            core::Core& core,
            std::vector<config::Namespace> namespaces,
            std::function<void(bool)> done) {
        on_loop(core, [&] { core._fetch(std::move(namespaces), std::move(done)); });
    }

    // Returns the raw 32-byte seed for the account key identified by the given x25519 public key.
    static cleared_b32 account_key_seed(
            core::Devices& d, std::span<const std::byte, 32> x25519_pub) {
        cleared_b32 seed;
        auto c = d.conn();
        auto blob = c.prepared_get<sqlite::blob_guts<std::array<std::byte, 32>>>(
                "SELECT seed FROM device_account_keys WHERE pubkey_x25519 = ?",
                std::as_bytes(x25519_pub));
        std::ranges::copy(blob, seed.begin());
        return seed;
    }

    // Returns the {pubkey_x25519, pubkey_mlkem768} of the active (unrotated) account key.
    static std::pair<std::array<std::byte, 32>, std::array<std::byte, 1184>> active_account_pubkeys(
            core::Core& core) {
        auto [x25519, mlkem768] =
                core.db.conn()
                        .prepared_get<
                                sqlite::blob_guts<std::array<std::byte, 32>>,
                                sqlite::blob_guts<std::array<std::byte, 1184>>>(
                                "SELECT pubkey_x25519, pubkey_mlkem768"
                                " FROM device_account_keys WHERE rotated IS NULL");
        return {x25519, mlkem768};
    }

    // Returns true if any swarm node has handed us a hash in the given namespace.  Used by live
    // tests to detect that a poll completed and delivered at least one message.
    static bool has_any_namespace_sync(core::Core& core, config::Namespace ns) {
        auto count = core.db.conn().prepared_get<int64_t>(
                "SELECT COUNT(*) FROM swarm_hashes WHERE namespace = ?", static_cast<int16_t>(ns));
        return count > 0;
    }

    // Records a lookup of `remote_session_id` that found these keys: `usable` for
    // PFS_KEY_REFRESH.
    static void seed_pfs_cache(
            core::Core& core,
            std::span<const std::byte, 33> remote_session_id,
            std::span<const std::byte, 32> x25519_pub,
            std::span<const std::byte, 1184> mlkem768_pub) {
        core._store_pfs_keys(remote_session_id, x25519_pub, mlkem768_pub);
    }

    // Records a lookup of `remote_session_id` that found nothing: `nak` for PFS_KEY_EMPTY_HOLD,
    // so that sends to them go out at once with the non-PFS encryption.  With a key already held
    // it re-confirms that instead, as the real outcome does.
    static void seed_pfs_nak(core::Core& core, std::span<const std::byte, 33> remote_session_id) {
        core._store_pfs_empty(remote_session_id);
    }

    // The scheduled retry of a failed lookup of `session_id` that sends wait on, if any.
    static std::optional<sys_ms> pfs_retry_due(
            core::Core& core, std::span<const std::byte, 33> session_id) {
        b33 sid;
        std::ranges::copy(session_id, sid.begin());
        return core.call_get([&]() -> std::optional<sys_ms> {
            auto it = core._pfs_retries.find(sid);
            return it == core._pfs_retries.end() ? std::nullopt : it->second.due;
        });
    }
    // Runs the scheduled retry now rather than after its backoff.
    static void fire_pfs_retry(core::Core& core, std::span<const std::byte, 33> session_id) {
        b33 sid;
        std::ranges::copy(session_id, sid.begin());
        core.call_get([&] { core._retry_pfs_fetch(sid); });
    }
};

}  // namespace session
