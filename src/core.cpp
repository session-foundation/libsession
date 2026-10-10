#include <SessionProtos.pb.h>
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <mlkem_native.h>
#include <oxenc/base64.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <sodium/core.h>

#include <cassert>
#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/quic/loop.hpp>
#include <session/clock.hpp>
#include <session/core.hpp>
#include <session/core/schema/schema_registry.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/format.hpp>
#include <session/network/session_network.hpp>
#include <session/network/session_network_types.hpp>
#include <session/pro_backend.hpp>
#include <session/session_encrypt.hpp>
#include <session/session_protocol.hpp>
#include <session/util.hpp>
#include <session/xed25519.hpp>
#include <unordered_set>

#include "core/swarm_request.hpp"
#include "session/config/namespaces.hpp"
#include "session/core/component.hpp"

namespace session::core {

namespace log = oxen::log;
using namespace session::sqlite;
using namespace oxen::log::literals;
static auto cat = log::Cat("core");

// How many recent hashes to keep per namespace per swarm node, as a position to fall back to when
// the newest ones are deleted from the swarm.  Deleting more than this in a run costs one full
// retrieve from that node, which is the same thing that happens today for any other reason.
static constexpr int SWARM_HASH_HISTORY = 100;

static cleared_b32 seed_from_words(
        std::span<const std::string_view> words, const mnemonics::Mnemonics& lang) {
    auto n = words.size();
    if (n != 12 && n != 13 && n != 24 && n != 25)
        throw std::invalid_argument{
                "Seed phrase must be 12, 13, 24, or 25 words (got {})"_format(n)};

    cleared_b32 result;
    if (n <= 13) {
        // 12 or 13 words → 16-byte seed in the lower half; upper 16 bytes are zeroed
        mnemonics::words_to_bytes(words, lang, std::span<std::byte>(result.data(), 16));
        std::memset(result.data() + 16, 0, 16);
    } else {
        // 24 or 25 words → full 32-byte seed
        mnemonics::words_to_bytes(words, lang, std::span<std::byte>(result.data(), 32));
    }
    return result;
}

predefined_seed::predefined_seed(
        std::span<const std::string_view> words, const mnemonics::Mnemonics& lang) :
        predefined_seed{seed_from_words(words, lang)} {}

predefined_seed::predefined_seed(
        std::span<const std::string_view> words, std::string_view lang_name) :
        predefined_seed{words, mnemonics::get_language(lang_name)} {}

void Core::NetworkDeleter::operator()(network::Network* p) const {
    delete p;
}

void Core::init() {
    if (sodium_init() < 0)
        throw std::runtime_error{"libsodium initialization failed!"};

    apply_migrations();

    for (auto* component : _comp_init)
        component->init();

    _comp_init.clear();

    _update_polling();

    // Last: from here a poll can run and another thread can hold this Core, so a component
    // touched from anywhere but the loop is misuse rather than construction.
    _constructed = true;
}

void Core::register_comp_init(detail::CoreComponent* c) {
    _comp_init.push_back(c);
}

quic::Loop& Core::loop() {
    return _loop;
}

Core::~Core() {
    // Tearing a Network down fails every request its transport is still holding, and failing them
    // fires the hooks installed in set_network -- which marshal onto our loop and reach members
    // that are already gone.  Members are destroyed in reverse declaration order and `_jq` is
    // declared after `_network`, so by the time ~Network runs it has been destroyed while `_loop`,
    // declared first, is still alive to run the job: a dropped subscription removing its timers
    // from a queue that no longer exists, at every exit that had a subscription.
    //
    // So detach before anything is torn down.  ~Network pays its own router and transport the
    // same courtesy for the same reason, and doing it here rather than by shuffling the member
    // declarations leaves the requirement stated instead of resting on where a field sits.
    if (_network) {
        _network->on_server_push = nullptr;
        _network->on_connection_established = nullptr;
        _network->on_connection_lost = nullptr;
    }

    // Before the Network goes, because a poll or a renew that fires while it is being torn down
    // would reach it; stopping `_jq` below cancels them too, but only once the Network is already
    // gone.  On the loop because the ids are only ever touched there.
    call_get([this] {
        for (auto* timer : {&_poll_timer, &_sub_timer, &_probe_timer})
            _remove_timer(*timer);
    });

    // Blocking, and it must not run on the Network's own loop -- it does not, because a Core is
    // destroyed by whoever owns it.  Before the queue is stopped rather than after: tearing the
    // Network down fails whatever it still holds, and those completions marshal onto our queue,
    // which throws if it has already been stopped.  Queued here they are simply cancelled below.
    _network.reset();

    // One job that settles and then shuts the queue down from inside itself, which is what
    // `process_job_queue` is written for -- it re-checks the running flag between jobs, so nothing
    // else in the batch runs once this returns.  `stop()` clears the queue and deletes every armed
    // `call_later`, so by the time the members below are destroyed there is no job, no timer and no
    // deferred deleter left that could reach one of them.  None of what a component holds is
    // thread-safe, so that guarantee is the point rather than a tidiness.
    //
    // The dump goes first because a change settles a turn of the loop after it is made, and one
    // made just before this is still queued ahead of us -- so it runs, and then this writes what it
    // could not.
    //
    // Swallowed rather than propagated: this is a destructor, and a database that cannot be written
    // is not something the caller tearing Core down can act on.
    try {
        call_get([this] {
            if (globals.have_account())
                configs.store_dumps();
            _jq.stop();
        });
    } catch (const std::exception& e) {
        log::warning(cat, "Could not shut Core's queue down cleanly: {}", e.what());
    }
}

network::Network& Core::make_network(network::config::Config config) {
    if (!config.disk_loop)
        config.disk_loop = _disk_loop;
    auto net = std::make_unique<network::Network>(std::move(config));
    auto& ref = *net;
    set_network(std::move(net));
    return ref;
}

void Core::set_network(std::unique_ptr<network::Network> network) {
    // Polling signs its retrieve requests with the account key, so attaching a network before the
    // account has an identity would fail inside a background poll rather than here.  Refuse at the
    // call site, where the ordering mistake actually is.
    if (network && !globals.have_account())
        throw no_account{};

    // Replacing an attached Network is unsupported, and unsupported here means unsafe rather than
    // merely unimplemented: see the TODO in core.hpp.  Refuse rather than corrupt.
    if (_network)
        throw network_already_attached{};

    // Ownership moves in via release() because the two pointer types differ deliberately: the
    // parameter is a plain unique_ptr so callers can hand over a std::make_unique, while the
    // member's deleter (which is just `delete`) is what keeps Network an incomplete type in
    // core.hpp -- including session_network.hpp there costs ~6x the compile time per file.
    _network.reset(network.release());

    if (_network) {
        // These fire on the network's loop; each hops onto ours before touching subscription
        // state.  Safe to capture `this` bare: the Network is declared after `_loop` so it is
        // destroyed first, and ~Network does not return until no callback of its is still in
        // flight.
        // The body is copied because it has to be: the span is the transport's buffer and is only
        // valid for the duration of this call, so anything deferred must own its bytes.  That cost
        // is what a push is worth -- a poll response arrives the same way and is copied too.
        //
        // Which node sent it is deliberately not checked: `_sub_node` is our loop's, and by the
        // time this runs the answer could have changed anyway.  It does not need to be, either --
        // everything here is authenticated downstream, replays dedup on the swarm hash, and
        // configs merge by seqno, so the worst a connected node achieves by pushing us something
        // is making us do work we would have done anyway.
        _network->on_server_push = [this](const network::ed25519_pubkey& /*node*/,
                                          std::string_view endpoint,
                                          std::span<const std::byte> body) {
            call([this, endpoint = std::string{endpoint}, body = to_vector(body)] {
                _handle_server_push(endpoint, body);
            });
        };

        _network->on_connection_lost = [this](const network::ed25519_pubkey& node) {
            call([this, node] {
                if (_sub_node && _sub_node->remote_pubkey == node)
                    _drop_subscription("connection lost");
            });
        };

        _network->on_connection_established = [this](const network::ed25519_pubkey& node) {
            call([this, node] {
                // A rebuilt connection carries no subscription: the far end keyed the old one to
                // the connection that just went away.  Losing it should already have dropped us,
                // so this is the case where it somehow did not.
                if (_subscribed && _sub_node && _sub_node->remote_pubkey == node)
                    _drop_subscription("connection was re-established");
            });
        };
    }

    _update_polling();
}

void Core::_remove_timer(quic::TimerID& timer) {
    if (auto t = std::exchange(timer, {}))
        _jq.remove(t);
}

void Core::_update_polling() {
    if (_network && !_poll_timer)
        _poll_timer = _jq.add_timer(_poll_interval, [this] { _poll(); });
    else if (!_network)
        _remove_timer(_poll_timer);
}

void Core::set_poll_interval(std::chrono::milliseconds interval) {
    // Marshalled onto the loop rather than done here: this replaces the timer, and both
    // `_poll_interval` and `_poll_timer` are otherwise only touched there.  `call` runs it inline
    // when we are already on the loop thread, so this costs nothing in that case.
    //
    // On our own queue rather than the loop's, so that a interval change still in flight when Core
    // goes away is dropped rather than run against a half-destroyed one.
    _jq.call([this, interval] {
        _poll_interval = interval;
        _remove_timer(_poll_timer);
        _update_polling();
    });
}

// Order matters: the batch's results are handled in this order, so a namespace whose contents
// another one's depend on has to come first.  The configs lead because a message arriving in the
// same poll may be from a contact those configs are what tells us about; among themselves,
// ConvoInfoVolatile comes last because it refers to conversations that Contacts and UserGroups
// are what establish.
static constexpr std::array POLL_NAMESPACES = {
        config::Namespace::UserProfile,
        config::Namespace::Contacts,
        config::Namespace::UserGroups,
        config::Namespace::ConvoInfoVolatile,
        config::Namespace::Default,
        config::Namespace::Devices,
        config::Namespace::AccountPubkeys};

// Ceiling on continuation rounds within one poll.  A well-behaved node exhausts a namespace in far
// fewer; this exists so that a node whose `more` never goes false cannot poll indefinitely.
static constexpr int POLL_MAX_ROUNDS = 20;

/// One namespace's slice of a batch retrieve response, decoded but not yet handled.
///
/// The decoded bytes are kept beside the messages because `SwarmMessage::data` spans into them:
/// the messages are only usable while this object is.
struct retrieved_namespace {
    std::vector<std::vector<std::byte>> data;
    std::vector<SwarmMessage> messages;
    /// The node says it is holding more past what it returned.  A retrieve is capped by the
    /// storage server, so this is how a namespace reports that one round did not exhaust it.
    bool more = false;
};

namespace {

    /// Decodes one result of a batch retrieve, or nothing where the node did not answer it.
    ///
    /// **Nothing and an empty answer are different**, and the difference is load-bearing: a
    /// namespace that failed or answered malformedly is not reported to its handler at all, while
    /// one that answered with nothing is -- "we asked and there is nothing" is an answer, and some
    /// handlers act on it.
    ///
    /// Takes no node and touches no database, deliberately. Which node an answer came from matters
    /// to whoever called: the retrieve cursor is kept per node and has to stay with the one that
    /// produced it, and a decoder that knew about nodes is the shape in which one node's cursor
    /// gets written from another node's response -- silently, because each node's cursor is
    /// individually plausible.
    std::optional<retrieved_namespace> decode_retrieved(const nlohmann::json& res, int16_t ns_val) {
        auto code_it = res.find("code");
        if (code_it == res.end() || code_it->get<int>() != 200) {
            log::warning(cat, "Retrieve of namespace {} failed: {}", ns_val, res.dump());
            return std::nullopt;
        }
        auto body_it = res.find("body");
        if (body_it == res.end())
            return std::nullopt;
        auto msgs_it = body_it->find("messages");
        if (msgs_it == body_it->end() || !msgs_it->is_array())
            return std::nullopt;

        retrieved_namespace got;
        if (auto m = body_it->find("more"); m != body_it->end() && m->is_boolean())
            got.more = m->get<bool>();

        log::debug(cat, "Retrieved {} message(s) from namespace {}", msgs_it->size(), ns_val);

        for (const auto& msg : *msgs_it) {
            auto data_it = msg.find("data");
            if (data_it == msg.end() || !data_it->is_string())
                continue;
            auto& decoded = got.data.emplace_back();
            auto b64 = data_it->get<std::string_view>();
            decoded.reserve(oxenc::from_base64_size(b64.size()));
            oxenc::from_base64(b64.begin(), b64.end(), std::back_inserter(decoded));

            SwarmMessage swarm_msg;
            swarm_msg.data = {decoded.data(), decoded.size()};

            if (auto h = msg.find("hash"); h != msg.end() && h->is_string())
                swarm_msg.hash = h->get<std::string>();

            if (auto t = msg.find("timestamp"); t != msg.end() && t->is_number_integer())
                swarm_msg.timestamp = from_epoch_ms(t->get<int64_t>());

            if (auto e = msg.find("expiry"); e != msg.end() && e->is_number_integer())
                swarm_msg.expiry = from_epoch_ms(e->get<int64_t>());

            got.messages.push_back(std::move(swarm_msg));
        }

        // A node claiming more while returning nothing cannot be continued: there is no new hash to
        // move the cursor to, so another round would ask the same question and get the same answer.
        // Reported as finished instead, or a handler waiting on `is_final` would wait for one that
        // never comes.
        got.more = got.more && !got.messages.empty();
        return got;
    }

}  // namespace

/// How long the first member's config is left open for others to add to.
///
/// A member can be behind its swarm, so the first config to arrive is not necessarily the newest.
/// Merging whatever else comes in over a short window lets a stale first answer be overtaken before
/// the fetch reports -- and configs merge rather than replace, so each extra answer can only bring
/// the result forward.  Short because somebody is watching a progress indicator: long enough to let
/// in a few more members, not to wait for all of them.
constexpr std::chrono::milliseconds PROFILE_FETCH_GRACE{500};

/// How far a fan-out has got.
///
/// Shared between every in-flight request and the grace timer, and touched only on Core's job
/// queue, which is what makes plain fields safe here: the responses arrive on the network's threads
/// and are marshalled across before any of this is read.
struct Core::ProfileFanOut {
    std::function<void(bool)> done;
    size_t outstanding = 0;
    /// Whether any member has answered with a config, which is what `done` reports.
    bool found = false;
    bool grace_started = false;
    bool concluded = false;
};

// The namespaces we ask a storage server to push to us: the ones we poll, in ascending order,
// which is what the server requires (it rejects an unordered `n=` list).  Derived from
// POLL_NAMESPACES rather than written out so that adding a namespace to the poll cannot leave the
// subscription silently not covering it.
static constexpr auto SUBSCRIBE_NAMESPACES = [] {
    std::array<int16_t, POLL_NAMESPACES.size()> ns{};
    for (size_t i = 0; i < POLL_NAMESPACES.size(); i++)
        ns[i] = static_cast<int16_t>(POLL_NAMESPACES[i]);
    std::ranges::sort(ns);
    return ns;
}();

// How often a live subscription is re-sent.  The storage server expires one 65 minutes after the
// last renewal, so this leaves four times the headroom it needs -- and the expiry only ever
// matters on a connection that has stayed up that long, since losing the connection loses the
// subscription outright.
static constexpr auto SUBSCRIPTION_RENEW_INTERVAL = 15min;

// How often the subscribed node is probed; see _subscription_probe.
static constexpr auto SUBSCRIPTION_PROBE_INTERVAL = 30s;

// The namespace the probe asks about: negative and of the form -(20n+1), which is what makes a
// retrieve of it need no signature (oxenss/common/namespace.h, is_noauth_retrieve_namespace), and
// otherwise unassigned, so it is permanently empty and the reply is a fixed 57 bytes.  Deliberately
// not a memorable number: it should not look like it means something.
static constexpr int16_t PROBE_NAMESPACE = -3741;

// A probe is answered or it is not; there is no reason to spend the swarm budget on it.
static constexpr auto PROBE_TIMEOUT = 10s;

// What the storage server pushes a subscribed client, as the endpoint of a request of its own.
static constexpr auto NOTIFY_ENDPOINT = "notify"sv;

// How many times a swarm request is re-aimed after a 421 before it is given up on.
//
// One redirect is the ordinary case: our membership was stale, the rejection corrected it, the
// next member answers.  More than that means the corrected swarm is also being rejected, and
// asking a fourth time will not change that.
static constexpr int SWARM_REDIRECT_LIMIT = 3;

// The least time worth starting another attempt with.  A request given a second or two cannot
// resolve a node, connect and get an answer, so spending the remainder of the budget on it only
// delays telling the caller what we already know.
static constexpr auto MIN_RETRY_BUDGET = 2s;

struct Core::SwarmOp {
    network::x25519_pubkey swarm_pubkey;
    std::string endpoint;
    std::function<std::vector<std::byte>(const network::service_node&)> make_body;
    std::function<void(SwarmResponse)> on_done;

    // Members already spent on this operation, in the order they were tried: ones that could not
    // be reached, and ones that said the account is not theirs.  Both are reasons not to ask
    // again, and a list rather than a count because "once per member" cannot be expressed as a
    // number -- choosing the next one has to know which are gone.
    std::vector<network::service_node> spent;

    // A member to go back to rather than choosing afresh, for an operation that has to continue
    // against the one it started with -- a retrieve continuation resumes from a cursor that is
    // that member's alone.  Dropped the moment that member turns out to be wrong or unusable,
    // which puts us back to choosing normally.
    std::optional<network::service_node> prefer;

    int redirects = 0;
    std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();
};

void Core::_swarm_request(
        network::x25519_pubkey swarm_pubkey,
        std::string endpoint,
        std::function<std::vector<std::byte>(const network::service_node&)> make_body,
        std::function<void(SwarmResponse)> on_done,
        std::optional<network::service_node> prefer) {
    auto op = std::make_shared<SwarmOp>(
            swarm_pubkey, std::move(endpoint), std::move(make_body), std::move(on_done));
    op->prefer = std::move(prefer);
    _swarm_attempt(std::move(op));
}

void Core::_swarm_attempt(std::shared_ptr<SwarmOp> op) {
    // Non-owning, as everywhere else here: keeping the Network alive from a callback could make
    // the loop thread its last owner and run ~Network there.
    auto* net = _network.get();
    if (!net)
        return op->on_done({false, network::ERROR_NO_ROUTING_LAYER, "no network attached", {}});

    // Read out before the call: `op` is moved into the callback below, and the order of those two
    // against each other is unspecified, so reading through `op` in the argument list can happen
    // after it has been emptied.
    auto swarm_pubkey = op->swarm_pubkey;

    net->get_swarm(
            swarm_pubkey,
            false,
            [this, op = std::move(op), net](
                    network::swarm::swarm_id_t, std::vector<network::service_node> swarm) mutable {
                auto fail = [&op](int16_t status, std::string why) {
                    op->on_done(
                            {false,
                             status,
                             std::move(why),
                             op->spent.empty() ? network::service_node{} : op->spent.back()});
                };

                if (swarm.empty())
                    return fail(network::ERROR_NO_SNODE_POOL, "no swarm members available");

                if (op->prefer) {
                    auto pinned = *op->prefer;
                    return _swarm_send(std::move(op), std::move(pinned));
                }

                // The first member not already spent.  get_swarm shuffles and partitions by strike
                // count, so this is the least-struck members first in a random order among equals
                // -- the right preference anyway; what matters is only that a member already tried
                // is never chosen again, which is what ends the walk.
                auto next = std::ranges::find_if(swarm, [&op](const network::service_node& n) {
                    return std::ranges::find(op->spent, n) == op->spent.end();
                });

                if (next == swarm.end()) {
                    log::warning(
                            cat,
                            "No swarm member left to try for '{}': all {} are spent.",
                            op->endpoint,
                            op->spent.size());
                    return fail(network::ERROR_INVALID_DESTINATION, "no usable swarm member");
                }

                _swarm_send(std::move(op), *next);
            });
}

void Core::_swarm_send(std::shared_ptr<SwarmOp> op, network::service_node node) {
    auto* net = _network.get();
    if (!net)
        return op->on_done({false, network::ERROR_NO_ROUTING_LAYER, "no network attached", node});

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - op->started);
    if (SWARM_OVERALL_TIMEOUT - elapsed < MIN_RETRY_BUDGET) {
        log::warning(cat, "Out of time to try another member for '{}'.", op->endpoint);
        return op->on_done(
                {false, network::ERROR_REQUEST_TIMEOUT, "swarm request budget exhausted", node});
    }

    // Rebuilt per attempt: a retrieve carries the chosen node's cursor, so reusing the body built
    // for a previous member would resume from a position that member never gave us.
    net->send_request(
            swarm_request(node, op->swarm_pubkey, op->endpoint, op->make_body(node)),
            [this, op, node](
                    bool /*success*/,
                    bool timeout,
                    int16_t status,
                    std::vector<std::pair<std::string, std::string>> /*headers*/,
                    std::optional<std::string> body) mutable {
                // Onto our own queue: this runs on the *network's* loop, a different thread
                // entirely -- Network builds its own quic::Loop -- and everything below reaches
                // Core's state, from re-resolving a swarm to whatever `on_done` does with the
                // answer.  Marshalling here rather than in each caller covers every swarm
                // operation at once, since they all come back through this one handler.  It also
                // means a response landing after Core has gone is dropped rather than run against
                // a Core that is being torn down.
                call([this,
                      op = std::move(op),
                      node = std::move(node),
                      timeout,
                      status,
                      body = std::move(body)]() mutable {
                    _swarm_response(
                            std::move(op), std::move(node), timeout, status, std::move(body));
                });
            });
}

void Core::_swarm_response(
        std::shared_ptr<SwarmOp> op,
        network::service_node node,
        bool timeout,
        int16_t status,
        std::optional<std::string> body) {
    // Not this member's swarm.  Network has already taken the corrected membership
    // out of the rejection, so resolving again gets the new one -- and whatever we
    // were sticking to is exactly what was wrong.
    if (status == network::ERROR_MISDIRECTED_REQUEST) {
        op->prefer.reset();

        // Spent, not merely wrong to stick to: a member that says the account is not its own will
        // say so again, and the corrected swarm may not have arrived -- an older server sends no
        // swarm with the rejection, and then re-resolving returns the very same membership.
        op->spent.push_back(node);

        if (++op->redirects > SWARM_REDIRECT_LIMIT)
            log::warning(
                    cat,
                    "Giving up on '{}': redirected {} times.",
                    op->endpoint,
                    op->redirects - 1);
        else {
            log::info(
                    cat,
                    "{} does not hold {}; re-resolving its swarm.",
                    node.remote_pubkey.hex(),
                    op->swarm_pubkey.hex());
            return _swarm_attempt(std::move(op));
        }
    }

    // The member itself could not be reached.  The swarm is not in question, so move to another
    // one rather than failing.
    else if (status == network::ERROR_INVALID_DESTINATION) {
        log::info(
                cat,
                "{} unreachable for '{}'; trying another member.",
                node.remote_pubkey.hex(),
                op->endpoint);
        op->prefer.reset();
        op->spent.push_back(node);
        return _swarm_attempt(std::move(op));
    }

    op->on_done({timeout, status, std::move(body), node});
}

void Core::_poll() {
    if (!_network) {
        log::debug(cat, "Not polling: no network attached");
        return;
    }

    log::debug(cat, "Polling swarm for {}", globals.session_id_hex());
    _send_poll({POLL_NAMESPACES.begin(), POLL_NAMESPACES.end()}, 0, std::nullopt);
}

void Core::fetch_user_profile(std::function<void(bool found)> done) {
    // Non-owning: the Network is ours alone, and callbacks below must not keep it alive -- doing so
    // could make the loop thread the last owner and run ~Network there.
    auto* net = _network.get();
    if (!net || !globals.have_account()) {
        if (done)
            done(false);
        return;
    }

    auto state = std::make_shared<Core::ProfileFanOut>();
    state->done = std::move(done);

    net->get_swarm(globals.pubkey_x25519(), false, [this, net, state](auto, auto swarm) {
        // Onto our own queue rather than the loop's: work queued here is cancelled when Core goes
        // away, so a swarm lookup or an answer landing during teardown is dropped instead of run
        // against components that are already being destroyed.
        _jq.call([this, net, state, swarm = std::move(swarm)] {
            if (state->concluded)
                return;
            if (swarm.empty()) {
                // Not an error worth failing loudly over: the ordinary poll still runs, and this
                // was only ever an attempt to get there sooner.  A swarm of one is still worth
                // asking -- one member holding the config is the whole answer.
                log::warning(cat, "Cannot fan out a profile fetch: no swarm members available");
                _conclude_profile_fetch(*state);
                return;
            }

            auto body = _profile_retrieve_body();
            state->outstanding = swarm.size();

            for (const auto& node : swarm) {
                net->send_request(
                        swarm_request(node, globals.pubkey_x25519(), "batch", body),
                        [this, state, node](
                                bool success,
                                bool timeout,
                                int16_t /*status_code*/,
                                std::vector<std::pair<std::string, std::string>> /*headers*/,
                                std::optional<std::string> body) {
                            // Marshalled rather than handled here: these arrive on the network's
                            // threads, several at once by design, and everything they touch --
                            // the tally, the config merge, the cursor -- belongs to Core's queue.
                            _jq.call([this,
                                      state,
                                      node,
                                      success,
                                      timeout,
                                      body = std::move(body)]() mutable {
                                _handle_profile_response(
                                        state,
                                        node,
                                        (success && body) ? std::move(body) : std::nullopt,
                                        timeout);
                            });
                        });
            }
        });
    });
}

/// The body of a profile retrieve: one namespace, and no cursor.
///
/// **No `last_hash`, deliberately.** A cursor says "everything after what I already have", and the
/// point of this fetch is to get the config from a member that may never have been asked before --
/// resuming from another member's position would ask the wrong question.  The same body goes to
/// every member, which is also what makes their answers comparable.
std::vector<std::byte> Core::_profile_retrieve_body() {
    auto now_ms = epoch_ms(clock_now_ms());
    auto ns_val = static_cast<int16_t>(config::Namespace::UserProfile);

    nlohmann::json params = {
            {"pubkey", globals.session_id_hex()},
            {"namespace", ns_val},
    };

    // The profile is owner-writable, so retrieving it always needs a signature -- and signing is
    // allowed on any namespace, so there is no case in which leaving it out would be right.
    assert(retrieve_requires_auth(ns_val));
    auto seed = globals.account_seed();
    auto to_sign = ns_signature_value("retrieve", ns_val, now_ms);
    params["pubkey_ed25519"] = globals.pubkey_ed25519().hex();
    params["timestamp"] = now_ms;
    params["signature"] = "{:b}"_format(ed25519::sign(seed.ed25519_secret(), to_span(to_sign)));

    nlohmann::json requests = nlohmann::json::array();
    requests.push_back({{"method", "retrieve"}, {"params", std::move(params)}});
    return to_vector(nlohmann::json{{"requests", std::move(requests)}}.dump());
}

/// One member's answer, whenever it arrives -- including after the fetch has reported.
///
/// **Every config that arrives is merged**, even one landing after `done` has been called: it came
/// from a member of our own swarm, and dropping it would only leave the next ordinary poll to fetch
/// it again.  What the end of the fetch decides is when `done` is called, not which answers count.
void Core::_handle_profile_response(
        const std::shared_ptr<ProfileFanOut>& state,
        const network::service_node& node,
        std::optional<std::string> body,
        bool timed_out) {
    --state->outstanding;

    // Decoded here and merged below, outside the `try`: a failure while merging is not a failure to
    // parse, and reporting it as one would send somebody looking at the wrong thing.
    std::optional<retrieved_namespace> got;
    if (body) {
        try {
            auto json = nlohmann::json::parse(*body);
            auto it = json.find("results");
            if (it != json.end() && it->is_array() && !it->empty())
                got = decode_retrieved(
                        (*it)[0], static_cast<int16_t>(config::Namespace::UserProfile));
        } catch (const std::exception& e) {
            log::warning(cat, "Failed to parse profile fetch response: {}", e.what());
        }
    } else {
        log::warning(
                cat,
                "Profile fetch from {} failed: {}",
                node.remote_pubkey.hex(),
                timed_out ? "timed out" : "request failed");
    }

    if (got && !got->messages.empty()) {
        _absorb_profile_answer(node.remote_pubkey, got->messages);
        state->found = true;
        // The first config opens the window rather than ending the fetch; see PROFILE_FETCH_GRACE.
        // Only a config opens it: an answer with nothing in it is the condition this routes around.
        if (!state->concluded && !state->grace_started) {
            state->grace_started = true;
            _jq.call_later(PROFILE_FETCH_GRACE, [this, state] { _conclude_profile_fetch(*state); });
        }
    }

    // An empty answer never ends the fetch on its own; the last one to arrive does.
    if (state->outstanding == 0)
        _conclude_profile_fetch(*state);
}

/// Merges one member's config and records where that member's next retrieve resumes.
void Core::_absorb_profile_answer(
        const network::ed25519_pubkey& node, std::span<const SwarmMessage> messages) {
    auto configs_held = configs.batch();
    // Final, even where the member said it was holding more.  This is a one-shot fetch rather than
    // a poll that continues: the cursor recorded below is what lets the ordinary poll pick up
    // anything left, and a handler told to wait for a final that never comes would wait for ever.
    receive_messages(messages, config::Namespace::UserProfile, true);
    _record_swarm_cursor(node, config::Namespace::UserProfile, messages);
}

/// Reports the fan-out's result, once.  Whichever of the grace timer and the last answer comes
/// first reports it; the other finds it already done.
void Core::_conclude_profile_fetch(ProfileFanOut& state) {
    if (state.concluded)
        return;
    state.concluded = true;

    log::info(
            cat,
            "Profile fetch concluded: {}",
            state.found ? "config merged" : "nothing held by the swarm");

    if (state.done)
        state.done(state.found);
}

void Core::_send_poll(
        std::vector<config::Namespace> namespaces,
        int round,
        std::optional<network::service_node> node) {
    _swarm_request(
            globals.pubkey_x25519(),
            "batch",
            [this, namespaces](const network::service_node& n) {
                return _build_poll_body(n, namespaces);
            },
            [this, namespaces, round](SwarmResponse res) mutable {
                if (!res.ok() || !res.body) {
                    log::warning(
                            cat,
                            "Swarm poll request failed: {}",
                            res.timeout ? "timed out"
                            : res.body  ? *res.body
                                        : "request failed");
                    return;
                }

                // The member that actually answered, which is not necessarily the one the attempt
                // started with.  Everything below records against it -- the retrieve cursors, and
                // the subscription that a drained poll goes on to make.
                _swarm_node = res.node;

                _handle_poll_response(res.node, std::move(namespaces), std::move(*res.body), round);
            },
            std::move(node));
}

std::vector<std::byte> Core::_build_poll_body(
        const network::service_node& node, const std::vector<config::Namespace>& namespaces) {
    auto now_ms = epoch_ms(clock_now_ms());
    auto ed25519_hex = globals.pubkey_ed25519().hex();

    // Build per-namespace signatures for namespaces that require authentication; index-aligned with
    // `namespaces`.  Empty string means no auth needed for that namespace.  Signed here rather than
    // once per poll because the signature covers a timestamp the storage server checks for
    // freshness, so a continuation round cannot reuse the first round's.
    std::vector<std::string> ns_sig(namespaces.size());
    {
        auto seed = globals.account_seed();
        for (size_t i = 0; i < namespaces.size(); ++i) {
            auto ns_val = static_cast<int16_t>(namespaces[i]);
            if (!retrieve_requires_auth(ns_val))
                continue;
            auto to_sign = ns_signature_value("retrieve", ns_val, now_ms);
            auto sig = ed25519::sign(seed.ed25519_secret(), to_span(to_sign));
            ns_sig[i] = "{:b}"_format(sig);
        }
    }

    // Build one batch subrequest per namespace.
    nlohmann::json requests = nlohmann::json::array();
    {
        auto conn = db.conn();

        for (size_t i = 0; i < namespaces.size(); ++i) {
            auto ns_val = static_cast<int16_t>(namespaces[i]);
            nlohmann::json params = {
                    {"pubkey", globals.session_id_hex()},
                    {"namespace", ns_val},
            };

            if (!ns_sig[i].empty()) {
                params["pubkey_ed25519"] = ed25519_hex;
                params["timestamp"] = now_ms;
                params["signature"] = ns_sig[i];
            }

            // The newest hash this node handed us that it still holds.  Derived rather than stored
            // so that deleting a hash from the swarm moves the cursor back to its predecessor on
            // its own, with nothing to remember to update.  A continuation round therefore picks up
            // the hashes the previous round recorded, with no separate cursor to thread through.
            //
            // A NULL expiry is a node that did not tell us when it would drop the message, which is
            // unknown rather than expired: refusing to use it would throw away a working cursor
            // over a missing field.
            auto last_hash = conn.prepared_maybe_get<std::string>(
                    R"(
SELECT h.hash FROM swarm_hashes h JOIN swarm_nodes n ON n.id = h.node
 WHERE h.namespace = ? AND n.pubkey = ? AND (h.expiry IS NULL OR h.expiry > ?)
 ORDER BY h.id DESC LIMIT 1
)",
                    ns_val,
                    node.remote_pubkey,
                    epoch_ms(clock_now_ms()));
            if (last_hash)
                params["last_hash"] = *last_hash;

            requests.push_back({{"method", "retrieve"}, {"params", std::move(params)}});
        }
    }

    auto body_str = nlohmann::json{{"requests", std::move(requests)}}.dump();

    log::debug(
            cat,
            "Retrieving {} namespaces from {}: {}",
            namespaces.size(),
            node.remote_pubkey.hex(),
            body_str);

    return to_vector(body_str);
}

/// Records where this node's next retrieve of `ns` should resume from.
///
/// **The node is a parameter and not something read from the surroundings, deliberately.** The
/// cursor is kept per (namespace, node) -- the swarm filters a retrieve on a hash that particular
/// member still holds -- so writing one node's cursor from another node's answer is a silent fault:
/// each cursor is individually plausible, and what it costs shows up much later as a namespace that
/// re-fetches for ever or one that skips past messages, depending which way it landed.
///
/// Called only once the batch has been handled: the swarm filters on last_hash, so advancing past
/// messages that threw would drop them permanently.  Handling and then dying before this point
/// re-delivers the batch instead, which is why message handlers must tolerate seeing a message
/// twice.
void Core::_record_swarm_cursor(
        const network::ed25519_pubkey& node_pubkey,
        config::Namespace ns,
        std::span<const SwarmMessage> messages) {
    if (messages.empty())
        return;

    auto ns_val = static_cast<int16_t>(ns);
    auto conn = db.conn();

    // Every hash goes in, not just the ones that produced something we kept: the cursor is a
    // position in what this node returned, so leaving out what we ignored would park it behind
    // those and fetch them again on every poll.  Insertion order is the order the node returned
    // them, which is what `id DESC` reads back.
    conn.prepared_exec(
            "INSERT INTO swarm_nodes (pubkey) VALUES (?) ON CONFLICT DO NOTHING", node_pubkey);
    auto node_id =
            conn.prepared_get<int64_t>("SELECT id FROM swarm_nodes WHERE pubkey = ?", node_pubkey);

    for (const auto& m : messages) {
        if (m.hash.empty())
            continue;
        conn.prepared_exec(
                R"(
INSERT INTO swarm_hashes (namespace, node, hash, expiry) VALUES (?, ?, ?, ?)
ON CONFLICT(namespace, node, hash) DO UPDATE SET expiry = max(expiry, excluded.expiry)
)",
                ns_val,
                node_id,
                m.hash,
                m.expiry.time_since_epoch().count() > 0 ? std::optional{epoch_ms(m.expiry)}
                                                        : std::nullopt);
    }

    // An expired hash is not a cursor: the node no longer holds the message to measure from.
    conn.prepared_exec(
            "DELETE FROM swarm_hashes WHERE expiry IS NOT NULL AND expiry <= ?",
            epoch_ms(clock_now_ms()));

    // And a cap on top of that, because expiry alone bounds this at every message in the retention
    // window.  Only the newest entry is ever read; the rest exist solely to walk back past hashes
    // deleted from the swarm, so keeping more than a run of deletions could plausibly cover buys
    // nothing but disk.
    conn.prepared_exec(
            R"(
DELETE FROM swarm_hashes
 WHERE namespace = ?1 AND node = ?2
   AND id NOT IN (SELECT id FROM swarm_hashes
                   WHERE namespace = ?1 AND node = ?2
                   ORDER BY id DESC LIMIT ?3)
)",
            ns_val,
            node_id,
            SWARM_HASH_HISTORY);
}

void Core::_handle_poll_response(
        network::service_node node,
        std::vector<config::Namespace> namespaces,
        std::string body,
        int round) {

    const auto& sn_pubkey = node.remote_pubkey;

    // Namespaces the node says it has more of, to continue in another round.  Collected rather than
    // continued in place because the cursor each one resumes from is written below.
    std::vector<config::Namespace> unfinished;

    try {
        auto json = nlohmann::json::parse(body);
        auto it = json.find("results");
        if (it == json.end() || !it->is_array())
            return;

        // One poll can carry several config namespaces, and each merge would otherwise dump on its
        // way out.  Nothing reads those intermediate states, so hold them until the whole response
        // is handled.  (An external caller feeding receive_messages() directly can take its own.)
        auto configs_held = configs.batch();

        auto& results = *it;
        for (size_t i = 0; i < namespaces.size() && i < results.size(); ++i) {
            auto ns = namespaces[i];
            auto ns_val = static_cast<int16_t>(ns);

            auto got = decode_retrieved(results[i], ns_val);
            if (!got)
                continue;

            const auto& swarm_messages = got->messages;
            receive_messages(swarm_messages, ns, !got->more);
            if (got->more)
                unfinished.push_back(ns);

            _record_swarm_cursor(sn_pubkey, ns, swarm_messages);
        }
    } catch (const std::exception& e) {
        log::warning(cat, "Failed to parse poll response: {}", e.what());
        return;
    }

    // Nothing reports more, so this node's namespaces are drained and its cursors are current --
    // which is exactly the state a subscription has to start from, or the gap between the last
    // retrieve and the subscription taking effect would be lost.
    if (unfinished.empty()) {
        _maybe_subscribe(node);
        return;
    }

    if (round + 1 >= POLL_MAX_ROUNDS) {
        log::warning(
                cat,
                "Stopping poll of {} after {} rounds with {} namespace(s) still reporting more",
                sn_pubkey.hex(),
                POLL_MAX_ROUNDS,
                unfinished.size());
        return;
    }

    // Named rather than chosen afresh: the cursor these resume from is this node's, so the
    // continuation has to go back to the same one.  If it has since become unusable the swarm
    // request falls back to choosing normally, and the round starts over from that member's
    // cursor rather than resuming from one it never issued.
    _send_poll(std::move(unfinished), round + 1, std::move(node));
}

std::optional<network::PathInfo> Core::current_swarm_path() const {
    if (!_swarm_node || !_network)
        return std::nullopt;

    return _network->get_path_to(*_swarm_node);
}

void Core::_maybe_subscribe(const network::service_node& node) {
    // On our queue because everything below -- the timer ids especially -- is Core's loop state.
    // Inline once the caller is already there, which the poll response now is, so this costs a
    // check rather than a turn of the loop.
    call([this, node] {
        // Already have one, or are waiting on one: a subscription is with a single node, and
        // there is no reason to move while it works.
        if (_sub_node)
            return;

        auto* net = _network.get();
        if (!net)
            return;

        if (!net->supports_server_push()) {
            log::debug(cat, "Not subscribing: this routing mode cannot receive pushes");
            return;
        }

        _sub_node = node;
        _send_subscribe(net, node);
    });
}

void Core::_send_subscribe(network::Network* net, network::service_node node) {
    auto now_s = epoch_ms(clock_now_ms()) / 1000;

    // Mirrors the storage server's sig_msg in handle_monitor_message_single: the literal
    // "MONITOR", the 33-byte account pubkey in hex, the timestamp in *seconds*, the want-data
    // flag as 0/1, and the namespaces comma-joined in the same order they are sent.
    auto to_sign = "MONITOR{}{}{}{}"_format(
            globals.session_id_hex(), now_s, 1, fmt::join(SUBSCRIBE_NAMESPACES, ","));

    b64 sig;
    {
        auto seed = globals.account_seed();
        ed25519::sign(sig, seed.ed25519_secret(), to_span(to_sign));
    }

    // bt dict keys have to be appended in sorted order: P < d < n < s < t.
    oxenc::bt_dict_producer d;
    d.append("P", to_string_view(globals.pubkey_ed25519().view()));
    // Ask for the message body, not just its metadata.  These are the same bytes a retrieve would
    // have returned, so carrying them costs nothing over fetching them and saves the round trip:
    // a notification is then self-sufficient.
    d.append("d", 1);
    {
        auto ns_list = d.append_list("n");
        for (auto ns : SUBSCRIBE_NAMESPACES)
            ns_list.append(ns);
    }
    d.append("s", to_string_view(sig));
    d.append("t", now_s);

    log::debug(cat, "Subscribing to {} for {}", node.remote_pubkey.hex(), globals.session_id_hex());

    net->send_request(
            swarm_request(node, globals.pubkey_x25519(), "monitor", to_vector(std::move(d).str())),
            [this, node](
                    bool success,
                    bool timeout,
                    int16_t /*status_code*/,
                    std::vector<std::pair<std::string, std::string>> /*headers*/,
                    std::optional<std::string> body) {
                call([this, node, success, timeout, body = std::move(body)] {
                    // We gave this subscription up while the request was in flight.
                    if (!_sub_node || _sub_node->remote_pubkey != node.remote_pubkey)
                        return;

                    if (!success || !body)
                        return _drop_subscription(
                                timeout ? "subscribe timed out" : "subscribe request failed");

                    // The reply is bt, not the JSON every other storage server endpoint answers
                    // with: `monitor` is handled outside the RPC dispatch and replies with what
                    // handle_monitor built.
                    try {
                        oxenc::bt_dict_consumer d{*body};

                        if (d.skip_until("errcode")) {
                            auto code = d.consume_integer<int>();
                            std::string err;
                            if (d.skip_until("error"))
                                err = d.consume_string();
                            return _drop_subscription(
                                    "subscribe rejected (code {}): {}"_format(code, err));
                        }

                        if (!d.skip_until("success") || d.consume_integer<int>() != 1)
                            return _drop_subscription("subscribe reply did not report success");
                    } catch (const std::exception& e) {
                        return _drop_subscription(
                                "could not parse subscribe reply: {}"_format(e.what()));
                    }

                    if (!_subscribed) {
                        _subscribed = true;

                        // Stop polling: from here the node pushes what arrives, and the only
                        // requests we make are the renew tick's.
                        _remove_timer(_poll_timer);
                        _sub_timer = _jq.add_timer(
                                SUBSCRIPTION_RENEW_INTERVAL, [this] { _subscription_renew(); });
                        _probe_timer = _jq.add_timer(
                                SUBSCRIPTION_PROBE_INTERVAL, [this] { _subscription_probe(); });

                        log::info(
                                cat, "Subscribed to {}; polling stopped", node.remote_pubkey.hex());

                        // One last poll, against the member we just subscribed with.
                        //
                        // Draining ran before the subscription existed, so a message stored
                        // between the last retrieve's snapshot and the subscription taking effect
                        // was in neither: too late for the retrieve, too early to be pushed.  This
                        // is the only thing that closes that window -- the renew sends no
                        // retrieve, and the probe asks about a namespace that is empty by design.
                        _send_poll({POLL_NAMESPACES.begin(), POLL_NAMESPACES.end()}, 0, node);
                    }
                });
            });
}

void Core::_subscription_renew() {
    if (!_sub_node)
        return;

    if (auto* net = _network.get())
        _send_subscribe(net, *_sub_node);
}

// Asks the subscribed node to retrieve a namespace that is always empty, purely for the 421 we get
// back if it has stopped holding our swarm.
//
// This exists because a subscription that has stopped applying is *silent*.  The storage server
// runs no swarm check when subscribing and none when a swarm changes underneath one:
// `get_notifiers` simply stops matching, so a client that has given up polling cannot tell "nothing
// has been sent to me" from "I am subscribed to a node that no longer holds my messages".
//
// It is deliberately the cheapest question that still produces a 421.  The storage server decides
// that from the pubkey alone, on the first two lines of its retrieve handler -- before the
// signature-required check and before verifying anything -- so the request needs no signature, no
// ed25519 pubkey and no timestamp, and PROBE_NAMESPACE has nothing in it so it needs no cursor
// either.  97 bytes out, 57 back.
//
// Two things this leans on, neither of them a promised contract:
//
// - that the swarm check precedes the auth check.  If the server ever reorders them this stops
//   working *silently*, answering 200-with-nothing where it used to answer 421.
// - that no swarm_pubkey is set on the request, which is what stops the network layer from
//   quietly retrying a 421 on some other swarm member and reporting success.  We are asking about
//   this node specifically; an answer from a different one would defeat the point.
//
// Temporary.  The storage server is gaining a notification that tells a subscriber outright when
// its subscription has stopped applying, and carries the replacement swarm with it.  Once that has
// been deployed widely enough this can go, though it has to outlive the last un-upgraded node.
void Core::_subscription_probe() {
    if (!_sub_node)
        return;

    auto* net = _network.get();
    if (!net)
        return _drop_subscription("network detached");

    // Logged even though it is uneventful: this and the renewal are the only traffic a subscribed
    // client makes, so their absence from a log is the first thing worth checking when pushes
    // stop arriving -- and a subscription that has quietly stopped applying looks exactly like a
    // conversation nobody is talking in.
    log::debug(cat, "Probing {} for a swarm change", _sub_node->remote_pubkey.hex());

    auto body =
            nlohmann::json{
                    {"pubkey", globals.session_id_hex()},
                    {"namespace", PROBE_NAMESPACE},
            }
                    .dump();

    auto node = *_sub_node;
    network::Request req{
            node,
            "retrieve",
            to_vector(body),
            network::RequestCategory::standard_small,
            PROBE_TIMEOUT};

    net->send_request(
            std::move(req),
            [this, node](
                    bool success,
                    bool /*timeout*/,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> /*headers*/,
                    std::optional<std::string> /*body*/) {
                if (success)
                    return;

                call([this, node, status_code] {
                    if (!_sub_node || _sub_node->remote_pubkey != node.remote_pubkey)
                        return;

                    if (status_code == network::ERROR_MISDIRECTED_REQUEST)
                        return _drop_subscription("node no longer holds our swarm");

                    // Anything else is the node being unreachable or unwell.  A dead connection
                    // reaches us through on_connection_lost instead, so getting here means it is
                    // notionally up but not answering, which is no better for a client that has
                    // nothing else to fall back on.
                    _drop_subscription("probe failed (status {})"_format(status_code));
                });
            });
}

void Core::_drop_subscription(std::string_view why) {
    if (!_sub_node)
        return;

    log::info(cat, "Dropping subscription with {}: {}", _sub_node->remote_pubkey.hex(), why);

    _sub_node.reset();
    _subscribed = false;

    for (auto* timer : {&_sub_timer, &_probe_timer})
        _remove_timer(*timer);

    // Back to polling, which is also what picks the next node: the swarm member a fresh
    // `get_swarm` happens to hand back first.
    _update_polling();
}

void Core::_handle_server_push(std::string_view endpoint, std::span<const std::byte> body) {
    if (endpoint != NOTIFY_ENDPOINT) {
        log::debug(cat, "Ignoring pushed '{}': not a notification", endpoint);
        return;
    }

    std::string hash;
    int16_t ns_val;
    int64_t timestamp, expiry;
    std::string_view data;

    // Keys in the order the server writes them, which is also sorted: @ h n t z ~.  `@` (the
    // account the message is for) is skipped: we subscribed for one account only.
    try {
        oxenc::bt_dict_consumer d{to_string_view(body)};

        hash = d.require<std::string>("h");
        ns_val = d.require<int16_t>("n");
        timestamp = d.require<int64_t>("t");
        expiry = d.require<int64_t>("z");

        if (!d.skip_until("~")) {
            // We subscribe with d=1, so a notification without a body is the server disagreeing
            // with us about what we asked for rather than something to go and fetch.
            log::warning(cat, "Pushed notification for {} carried no message data", hash);
            return;
        }
        data = d.consume_string_view();
    } catch (const std::exception& e) {
        log::warning(cat, "Could not parse pushed notification: {}", e.what());
        return;
    }

    log::debug(cat, "Pushed message {} in namespace {}", hash, ns_val);

    // No cursor is written for a pushed message.  The retrieve cursor is per (namespace, node) and
    // means "the newest hash that node handed us"; a push did not come from a retrieve, and
    // recording it would move the cursor past messages an interrupted retrieve had not yet
    // reached.  Re-fetching a pushed message after a reconnect is harmless -- delivery is
    // at-least-once and Client dedups on the hash -- whereas skipping one is not.
    SwarmMessage msg{
            to_span(data), std::move(hash), from_epoch_ms(timestamp), from_epoch_ms(expiry)};

    receive_messages({&msg, 1}, static_cast<config::Namespace>(ns_val), true);
}

PfsKeyStatus Core::prefetch_pfs_keys(std::span<const std::byte, 33> session_id) {
    // Non-owning: the Network is ours alone, and callbacks below must not keep it alive -- doing so
    // could make the loop thread the last owner and run ~Network there.
    auto* net = _network.get();
    if (!net)
        throw std::logic_error{"prefetch_pfs_keys called without a network object"};

    // One copy of session_id for async use; subsequently moved into lambdas.
    b33 sid;
    std::ranges::copy(session_id, sid.begin());

    // Skip the fetch if the cached entry is still fresh, or a recent NAK suppresses retrying.
    // Otherwise determine whether we have a stale (but usable) key or no key at all.
    auto status = PfsKeyStatus::fetching;
    {
        auto conn = db.conn();
        if (auto row = conn.prepared_maybe_get<std::optional<int64_t>, std::optional<int64_t>>(
                    "SELECT fetched_at, nak_at FROM pfs_key_cache WHERE session_id = ?", sid)) {
            auto [fetched_at, nak_at] = *row;
            if (fetched_at) {
                auto age = clock_now_s() - from_epoch_s(*fetched_at);
                if (age < PFS_KEY_FRESH_DURATION) {
                    log::debug(
                            cat,
                            "prefetch_pfs_keys: cached key for {} is still fresh ({} old), "
                            "skipping",
                            session_id,
                            age);
                    return PfsKeyStatus::fresh;
                }
                log::debug(
                        cat,
                        "prefetch_pfs_keys: cached key for {} is stale ({} old), re-fetching",
                        session_id,
                        age);
                status = PfsKeyStatus::stale;
            } else if (nak_at) {
                auto age = clock_now_s() - from_epoch_s(*nak_at);
                if (age < PFS_KEY_NAK_DURATION) {
                    log::debug(
                            cat,
                            "prefetch_pfs_keys: recent NAK for {} ({} old), skipping",
                            session_id,
                            age);
                    return PfsKeyStatus::nak;
                }
                log::debug(
                        cat,
                        "prefetch_pfs_keys: expired NAK for {} ({} old), re-fetching",
                        session_id,
                        age);
            }
        } else {
            log::debug(cat, "prefetch_pfs_keys: no cached key for {}, fetching", session_id);
        }
    }

    // The swarm is indexed by the x25519 pubkey — the session_id without its 0x05 prefix.
    network::x25519_pubkey x25519_pub;
    std::ranges::copy(session_id.subspan<1>(), x25519_pub.begin());

    auto now_ms = epoch_ms(clock_now_ms());

    // AccountPubkeys (-21) allows unauthenticated retrieve: no signature needed.
    nlohmann::json params = {
            {"pubkey", oxenc::to_hex(session_id)},
            {"namespace", static_cast<int16_t>(config::Namespace::AccountPubkeys)},
    };

    _swarm_request(
            x25519_pub,
            "retrieve",
            [body = params.dump()](const network::service_node&) { return to_vector(body); },
            [this, sid = std::move(sid)](SwarmResponse res) {
                if (!res.ok() || !res.body) {
                    log::warning(
                            cat,
                            "Failed to fetch PFS keys for {}: {}",
                            sid,
                            res.timeout ? "timed out"
                            : res.body  ? *res.body
                                        : "request failed");
                    _pfs_fetch_done(sid, PfsKeyFetch::failed);
                    return;
                }

                return _handle_pfs_response(sid, std::move(*res.body));
            });
    return status;
}

bool Core::_store_pfs_keys(
        std::span<const std::byte, 33> session_id,
        std::span<const std::byte, 32> x25519_pub,
        std::span<const std::byte, 1184> mlkem768_pub) {
    auto now_s = epoch_seconds(clock_now_s());
    auto conn = db.conn();
    SQLite::Transaction tx{conn.sql};

    bool is_unchanged = conn.prepared_maybe_get<int>(
                                    R"(
SELECT 1 FROM pfs_key_cache
WHERE session_id = ? AND pubkey_x25519 = ? AND pubkey_mlkem768 = ?
)",
                                    session_id,
                                    x25519_pub,
                                    mlkem768_pub)
                                .has_value();

    conn.prepared_exec(
            R"(
INSERT INTO pfs_key_cache (session_id, fetched_at, nak_at, pubkey_x25519, pubkey_mlkem768)
VALUES (?, ?, NULL, ?, ?)
ON CONFLICT(session_id) DO UPDATE SET
    fetched_at = excluded.fetched_at,
    pubkey_x25519 = excluded.pubkey_x25519,
    pubkey_mlkem768 = excluded.pubkey_mlkem768
)",
            session_id,
            now_s,
            x25519_pub,
            mlkem768_pub);
    tx.commit();
    return !is_unchanged;
}

void Core::_store_pfs_nak(std::span<const std::byte, 33> session_id) {
    auto now_s = epoch_seconds(clock_now_s());
    db.conn().prepared_exec(
            R"(
INSERT INTO pfs_key_cache (session_id, fetched_at, nak_at, pubkey_x25519, pubkey_mlkem768)
VALUES (?, NULL, ?, NULL, NULL)
ON CONFLICT(session_id) DO UPDATE SET nak_at = excluded.nak_at
)",
            session_id,
            now_s);
}

void Core::_handle_pfs_response(std::span<const std::byte, 33> sid, std::string body) {
    try {
        auto json = nlohmann::json::parse(body);
        auto msgs_it = json.find("messages");
        if (msgs_it == json.end() || !msgs_it->is_array()) {
            log::warning(
                    cat,
                    "prefetch_pfs_keys: response missing or invalid "
                    "'messages' array");
            return;
        }

        // Strip the 0x05 prefix to get the x25519 pubkey for
        // signature verification.
        auto x25519_pub = sid.subspan<1>();

        // Track the most recently valid pubkeys seen across all messages.
        std::optional<std::array<std::byte, 32>> pk_x25519;
        std::optional<std::array<std::byte, MLKEM768_PUBLICKEYBYTES>> pk_mlkem768;

        for (const auto& msg : *msgs_it) {
            auto data_it = msg.find("data");
            if (data_it == msg.end() || !data_it->is_string()) {
                log::warning(
                        cat,
                        "prefetch_pfs_keys: message missing or "
                        "non-string 'data' field");
                continue;
            }
            auto b64 = data_it->get<std::string_view>();
            std::vector<std::byte> decoded;
            decoded.reserve(oxenc::from_base64_size(b64.size()));
            oxenc::from_base64(b64.begin(), b64.end(), std::back_inserter(decoded));
            try {
                oxenc::bt_dict_consumer in{decoded};
                auto M = in.require_span<std::byte, MLKEM768_PUBLICKEYBYTES>("M");
                auto X = in.require_span<std::byte, 32>("X");
                in.require_signature(
                        "~",
                        [&x25519_pub](
                                std::span<const std::byte> b, std::span<const std::byte> sig) {
                            if (sig.size() != 64 ||
                                !xed25519::verify(sig.first<64>(), x25519_pub, b))
                                throw std::runtime_error{"signature verification failed"};
                        });
                std::ranges::copy(X, pk_x25519.emplace().begin());
                std::ranges::copy(M, pk_mlkem768.emplace().begin());
            } catch (const std::exception& e) {
                log::warning(
                        cat,
                        "Ignoring malformed remote account pubkey "
                        "message: {}",
                        e.what());
            }
        }

        if (!pk_x25519 || !pk_mlkem768) {
            log::debug(
                    cat,
                    "prefetch_pfs_keys: no valid account pubkey message "
                    "found in response");
            _store_pfs_nak(sid);
            _pfs_fetch_done(sid, PfsKeyFetch::not_found);
            return;
        }

        bool changed = _store_pfs_keys(sid, *pk_x25519, *pk_mlkem768);
        _pfs_fetch_done(sid, changed ? PfsKeyFetch::new_key : PfsKeyFetch::unchanged);
    } catch (const std::exception& e) {
        log::warning(cat, "Failed to process PFS key fetch response: {}", e.what());
    }
}

void Core::delete_from_swarm(
        std::vector<std::string> hashes, std::function<void(bool)> on_complete) {
    if (hashes.empty()) {
        if (on_complete)
            on_complete(true);
        return;
    }

    // Non-owning: the Network is ours alone, and callbacks below must not keep it alive -- doing so
    // could make the loop thread the last owner and run ~Network there.
    auto* net = _network.get();
    if (!net)
        throw std::logic_error{"delete_from_swarm: no network object"};

    b64 sig;
    {
        auto seed = globals.account_seed();
        // Signed over the hashes in the order they are sent, so the two must not be reordered
        // independently.
        auto to_sign = delete_signature_value(hashes);
        ed25519::sign(sig, seed.ed25519_secret(), std::as_bytes(std::span{to_sign}));
    }

    nlohmann::json params = {
            {"pubkey", globals.session_id_hex()},
            {"pubkey_ed25519", globals.pubkey_ed25519().hex()},
            {"messages", hashes},
            {"signature", "{:b}"_format(sig)},
    };
    auto body = to_vector<std::byte>(params.dump());

    _swarm_request(
            globals.pubkey_x25519(),
            "delete",
            [body = std::move(body)](const network::service_node&) { return body; },
            [this, hashes = std::move(hashes), on_complete](SwarmResponse res) {
                if (!res.ok()) {
                    log::warning(
                            cat,
                            "Swarm delete failed ({}): {}",
                            res.timeout ? "timed out" : "status {}"_format(res.status_code),
                            res.body.value_or("no response body"));
                    if (on_complete)
                        on_complete(false);
                    return;
                }

                // Forget the cursors naming what we just deleted, so the next retrieve measures
                // from the newest hash the node still holds.  Done on success only: a failed
                // delete leaves the messages there, and dropping the cursor would replay the
                // retention window for nothing.
                {
                    auto conn = db.conn();
                    for (const auto& h : hashes)
                        conn.prepared_exec("DELETE FROM swarm_hashes WHERE hash = ?", h);
                }

                if (on_complete)
                    on_complete(true);
            });
}

void Core::_send_to_swarm(
        std::span<const std::byte, 33> dest_pubkey,
        config::Namespace ns,
        std::vector<std::byte> payload,
        std::chrono::milliseconds ttl,
        std::function<void(bool success, std::optional<std::string_view> swarm_hash)> on_complete) {
    // Non-owning: the Network is ours alone, and callbacks below must not keep it alive -- doing so
    // could make the loop thread the last owner and run ~Network there.
    auto* net = _network.get();
    if (!net)
        throw std::logic_error{"_send_to_swarm: no network object"};

    auto ns_val = static_cast<int16_t>(ns);
    auto now_ms = epoch_ms(clock_now_ms());

    // The pubkey in the body and the swarm the request goes to must be the same account: a storage
    // server answers a store for a pubkey outside its own swarm with a 421, and the retry that
    // provokes cannot recover, because every node of the swarm we picked says the same thing.
    nlohmann::json params = {
            {"pubkey", oxenc::to_hex(dest_pubkey.begin(), dest_pubkey.end())},
            {"namespace", ns_val},
            {"data", "{:b}"_format(payload)},
            {"timestamp", now_ms},
            {"ttl", ttl.count()},
    };

    // Signed only where the storage server actually requires it.  Signing anyway would not merely
    // be redundant -- a public inbox store skips signature checking entirely, so the server never
    // reads it -- it would identify us as the one doing the storing.  For a message deposited in
    // our own swarm that distinguishes a copy we sent from one we were sent, which is precisely
    // what a storage server should not be able to tell.
    //
    // TODO: this signs with the account key, which is only right when the destination swarm is our
    // own.  Storing to a group swarm (namespaces 11-14) also requires authentication, but we do not
    // hold the group's key: a non-admin member signs with the subaccount token the admins issued
    // them and sends it alongside as `subaccount` + `subaccount_sig`, which the server checks
    // carries subaccount_access::Write (and, for a public outbox namespace, Delete as well).  Until
    // that exists, a group store signed here will be rejected with a 401.
    bool signed_store = store_requires_auth(ns_val);
    if (signed_store) {
        auto to_sign = ns_signature_value("store", ns_val, now_ms);
        b64 sig;
        {
            auto seed = globals.account_seed();
            ed25519::sign(sig, seed.ed25519_secret(), std::as_bytes(std::span{to_sign}));
        }
        params["pubkey_ed25519"] = globals.pubkey_ed25519().hex();
        params["sig_timestamp"] = now_ms;
        params["signature"] = "{:b}"_format(sig);
    }

    auto body = to_vector<std::byte>(params.dump());

    log::debug(
            cat,
            "Storing {}B to namespace {} of {}{}",
            payload.size(),
            ns_val,
            params["pubkey"].get<std::string_view>(),
            signed_store ? ", signed" : "");

    // Resolve the recipient's swarm and send.
    network::x25519_pubkey x25519_pub;
    std::memcpy(x25519_pub.data(), dest_pubkey.data() + 1, 32);

    _swarm_request(
            x25519_pub,
            "store",
            [body = std::move(body), x25519_pub](const network::service_node& node) {
                // Read this against the "Storing ... of <pubkey>" line above: a store rejected as
                // misdirected means the pubkey in the body and the swarm we resolved are not the
                // same account, which no amount of trying other members will fix.
                log::debug(
                        cat, "Storing to swarm of {} via {}", x25519_pub.hex(), node.to_string());
                return body;
            },
            [on_complete = std::move(on_complete)](SwarmResponse res) {
                if (!res.ok())
                    log::warning(
                            cat,
                            "Store request failed ({}): {}",
                            res.timeout ? "timed out" : "status {}"_format(res.status_code),
                            res.body.value_or("no response body"));
                if (!on_complete)
                    return;

                std::optional<std::string> hash;
                if (res.ok() && res.body) {
                    try {
                        auto json = nlohmann::json::parse(*res.body);
                        if (auto h = json.find("hash"); h != json.end() && h->is_string())
                            hash = h->get<std::string>();
                    } catch (const std::exception& e) {
                        log::warning(cat, "Could not read stored message hash: {}", e.what());
                    }
                }
                on_complete(res.ok(), hash ? std::optional<std::string_view>{*hash} : std::nullopt);
            });
}

void Core::_do_send_dm(
        int64_t message_id,
        std::span<const std::byte, 33> recipient,
        std::span<const std::byte> content,
        sys_ms sent_timestamp,
        const ed25519::OptionalPrivKeySpan& pro_privkey,
        std::chrono::milliseconds ttl,
        bool force_v2) {
    auto fire_status = [&](MessageSendStatus status) {
        if (callbacks.message_send_status) {
            try {
                callbacks.message_send_status(message_id, status, std::nullopt);
            } catch (const std::exception& e) {
                log::error(cat, "message_send_status callback threw: {}", e.what());
            }
        }
    };

    // Look up cached PFS keys for the recipient.
    using X = sqlite::blob_guts<b32>;
    using M = sqlite::blob_guts<std::array<std::byte, 1184>>;
    auto row = db.conn()
                       .prepared_maybe_get<
                               std::optional<int64_t>,
                               std::optional<int64_t>,
                               std::optional<X>,
                               std::optional<M>>(
                               "SELECT fetched_at, nak_at, pubkey_x25519, pubkey_mlkem768"
                               " FROM pfs_key_cache WHERE session_id = ?",
                               recipient);

    const b32* pfs_x25519 = nullptr;
    const std::array<std::byte, 1184>* pfs_mlkem768 = nullptr;
    if (row) {
        auto& [fetched_at, nak_at, pk_x, pk_m] = *row;
        if (fetched_at && pk_x && pk_m) {
            pfs_x25519 = &static_cast<const b32&>(*pk_x);
            pfs_mlkem768 = &static_cast<const std::array<std::byte, 1184>&>(*pk_m);
        }
    }

    // Encrypt the message.  v2 (PFS or nopfs) produces the complete wire format directly
    // (0x00 0x02 | ki | E | mlkem_ct | encrypted_inner) — no protobuf wrapping.  v1 uses
    // encode_dm_v1 which wraps in Envelope + WebSocketMessage protobufs.
    std::vector<std::byte> payload;
    try {
        auto seed = globals.account_seed();
        auto ed_sec = seed.ed25519_secret();

        std::string_view version;
        if (pfs_x25519) {
            payload = encrypt_for_recipient_v2(
                    ed_sec, recipient, *pfs_x25519, *pfs_mlkem768, content, pro_privkey);
            version = "v2 PFS";
        } else if (force_v2) {
            payload = encrypt_for_recipient_v2_nopfs(ed_sec, recipient, content, pro_privkey);
            version = "v2 nopfs";
        } else {
            payload = encode_dm_v1(content, ed_sec, sent_timestamp, recipient, pro_privkey);
            version = "v1";
        }

        log::debug(
                cat,
                "send_dm: message {} encrypted for {} as {} ({}B)",
                message_id,
                oxenc::to_hex(recipient),
                version,
                payload.size());
    } catch (const std::exception& e) {
        log::warning(cat, "send_dm: encryption failed for message {}: {}", message_id, e.what());
        fire_status(MessageSendStatus::encrypt_failed);
        return;
    }

    // Dispatch to swarm.
    fire_status(MessageSendStatus::sending);
    try {
        _send_to_swarm(
                recipient,
                config::Namespace::Default,
                std::move(payload),
                ttl,
                [this, message_id](bool success, std::optional<std::string_view> swarm_hash) {
                    if (callbacks.message_send_status) {
                        try {
                            callbacks.message_send_status(
                                    message_id,
                                    success ? MessageSendStatus::success
                                            : MessageSendStatus::network_error,
                                    swarm_hash);
                        } catch (const std::exception& e) {
                            log::error(cat, "message_send_status callback threw: {}", e.what());
                        }
                    }
                });
    } catch (const std::logic_error&) {
        fire_status(MessageSendStatus::no_network);
    }
}

void Core::_pfs_fetch_done(std::span<const std::byte, 33> session_id, PfsKeyFetch result) {
    if (callbacks.pfs_keys_fetched) {
        try {
            callbacks.pfs_keys_fetched(session_id, result);
        } catch (const std::exception& e) {
            // Contained so that a misbehaving callback cannot strand the queued sends below.
            log::error(cat, "pfs_keys_fetched callback threw: {}", e.what());
        }
    }
    _flush_pending_sends(session_id);
}

void Core::_flush_pending_sends(std::span<const std::byte, 33> session_id) {
    auto it = _pending_sends.begin();
    while (it != _pending_sends.end()) {
        if (std::ranges::equal(it->recipient, session_id)) {
            auto pending = std::move(*it);
            it = _pending_sends.erase(it);
            _do_send_dm(
                    pending.id,
                    pending.recipient,
                    pending.content,
                    pending.sent_timestamp,
                    pending.pro_privkey ? ed25519::OptionalPrivKeySpan{*pending.pro_privkey}
                                        : ed25519::OptionalPrivKeySpan{},
                    pending.ttl,
                    pending.force_v2);
        } else {
            ++it;
        }
    }
}

int64_t Core::send_dm(
        std::span<const std::byte, 33> recipient_session_id,
        std::span<const std::byte> content,
        sys_ms sent_timestamp,
        const ed25519::OptionalPrivKeySpan& pro_privkey,
        std::chrono::milliseconds ttl,
        bool force_v2) {
    auto id = _next_message_id++;

    log::debug(
            cat,
            "send_dm: message {} to {} ({}B content)",
            id,
            oxenc::to_hex(recipient_session_id),
            content.size());

    // Check cache state to decide whether we can send immediately or must queue.
    auto conn = db.conn();
    auto row = conn.prepared_maybe_get<std::optional<int64_t>, std::optional<int64_t>>(
            "SELECT fetched_at, nak_at FROM pfs_key_cache WHERE session_id = ?",
            recipient_session_id);

    bool have_cached_key = false;
    bool is_nak = false;

    if (row) {
        auto& [fetched_at, nak_at] = *row;
        if (fetched_at)
            have_cached_key = true;
        else if (nak_at)
            is_nak = true;
    }

    if (have_cached_key || is_nak) {
        // Can send immediately: either we have keys (use v2 PFS) or it's a NAK (use v1 or v2
        // nopfs).
        _do_send_dm(id, recipient_session_id, content, sent_timestamp, pro_privkey, ttl, force_v2);
    } else if (_network) {
        // No cache entry at all: need to fetch keys first.  Queue the send and initiate a
        // prefetch; _pfs_fetch_done() releases it when the fetch settles, whatever the outcome.
        PendingSend pending;
        pending.id = id;
        std::ranges::copy(recipient_session_id, pending.recipient.begin());
        pending.content.assign(content.begin(), content.end());
        pending.sent_timestamp = sent_timestamp;
        if (pro_privkey) {
            auto& stored = pending.pro_privkey.emplace();
            std::memcpy(stored.data(), pro_privkey->data(), 64);
        }
        pending.ttl = ttl;
        pending.force_v2 = force_v2;
        _pending_sends.push_back(std::move(pending));

        if (callbacks.message_send_status)
            callbacks.message_send_status(id, MessageSendStatus::awaiting_keys, std::nullopt);

        prefetch_pfs_keys(recipient_session_id);
    } else {
        // No cache and no network: fire immediate failure.
        if (callbacks.message_send_status)
            callbacks.message_send_status(id, MessageSendStatus::no_network, std::nullopt);
    }

    return id;
}

int64_t Core::send_dm(
        std::span<const std::byte, 33> recipient_session_id,
        const SessionProtos::Content& content,
        sys_ms sent_timestamp,
        const ed25519::OptionalPrivKeySpan& pro_privkey,
        std::chrono::milliseconds ttl,
        bool force_v2) {

    auto ts = static_cast<uint64_t>(sent_timestamp.time_since_epoch().count());

    std::string serialized;
    if (!content.has_sigtimestamp()) {
        auto stamped = content;
        stamped.set_sigtimestamp(ts);
        serialized = stamped.SerializeAsString();
    } else {
        if (content.sigtimestamp() != ts)
            throw std::invalid_argument{fmt::format(
                    "send_dm: Content sigTimestamp ({}) disagrees with sent_timestamp ({})",
                    content.sigtimestamp(),
                    ts)};
        serialized = content.SerializeAsString();
    }

    return send_dm(
            recipient_session_id,
            to_span<std::byte>(serialized),
            sent_timestamp,
            pro_privkey,
            ttl,
            force_v2);
}

void Core::_handle_direct_messages(std::span<const SwarmMessage> messages) {
    if (!callbacks.message_received && !callbacks.message_decrypt_failed)
        return;

    auto seed = globals.account_seed();
    auto session_id = globals.session_id();
    // Long-term X25519 pub/sec used for v2 key-indicator prefix decryption.
    std::span<const std::byte, 32> x25519_pub{session_id.data() + 1, 32};
    auto x25519_sec = seed.x25519_key();

    // Ed25519 secret key used for v1 envelope decryption.
    auto ed_sec = seed.ed25519_secret();

    auto fire_received = [&](ReceivedMessage out) {
        if (!callbacks.message_received)
            return;
        try {
            callbacks.message_received(std::move(out));
        } catch (const std::exception& e) {
            log::error(cat, "message_received callback threw: {}", e.what());
        }
    };

    auto fire_fail = [&](const SwarmMessage& msg, MessageDecryptFailure reason) {
        if (!callbacks.message_decrypt_failed)
            return;
        try {
            callbacks.message_decrypt_failed(msg, reason);
        } catch (const std::exception& e) {
            log::error(cat, "message_decrypt_failed callback threw: {}", e.what());
        }
    };

    for (const auto& msg : messages) {
        auto data = msg.data;
        if (data.empty()) {
            fire_fail(msg, MessageDecryptFailure::bad_format);
            continue;
        }

        if (data[0] == std::byte{0x00}) {
            // Version 2 (PFS+PQ) or an unrecognised future version.
            if (data.size() < 2 || data[1] != std::byte{0x02}) {
                fire_fail(msg, MessageDecryptFailure::unknown_version);
                continue;
            }

            // Extract the 2-byte ML-KEM key indicator, then look up matching account keys.
            std::array<std::byte, 2> ki;
            try {
                ki = decrypt_incoming_v2_prefix(x25519_sec, x25519_pub, data);
            } catch (const std::exception&) {
                // Ciphertext is too short or otherwise structurally malformed.
                fire_fail(msg, MessageDecryptFailure::bad_format);
                continue;
            }

            auto keys = devices.active_account_keys(ki);

            bool decrypted = false;
            for (auto& key : keys) {
                try {
                    auto result = decrypt_incoming_v2(
                            session_id, key.x25519_sec, key.x25519_pub, key.mlkem768_sec, data);
                    ReceivedMessage out;
                    out.hash = msg.hash;
                    out.timestamp = msg.timestamp;
                    out.expiry = msg.expiry;
                    out.sender_session_id = result.sender_session_id;
                    out.version = 2;
                    out.content = std::move(result.content);
                    out.pro_signature = result.pro_signature;
                    out.pfs_encrypted = true;
                    fire_received(std::move(out));
                    decrypted = true;
                    break;
                } catch (const DecryptV2Error&) {
                    // This key didn't work; try the next candidate.
                } catch (const std::exception& e) {
                    // Unrecoverable structural error in the message itself.
                    log::warning(cat, "v2 direct message format error: {}", e.what());
                    fire_fail(msg, MessageDecryptFailure::bad_format);
                    decrypted = true;  // Prevent the non-PFS fallback attempt.
                    break;
                }
            }
            if (!decrypted) {
                // No PFS key matched; try the non-PFS fallback (sender had no PFS keys).
                try {
                    auto result =
                            decrypt_incoming_v2_nopfs(session_id, x25519_sec, x25519_pub, data);
                    ReceivedMessage out;
                    out.hash = msg.hash;
                    out.timestamp = msg.timestamp;
                    out.expiry = msg.expiry;
                    out.sender_session_id = result.sender_session_id;
                    out.version = 2;
                    out.content = std::move(result.content);
                    out.pro_signature = result.pro_signature;
                    // pfs_encrypted remains false (default)
                    fire_received(std::move(out));
                } catch (const DecryptV2Error&) {
                    // Non-PFS fallback also failed: message cannot be read.
                    fire_fail(msg, MessageDecryptFailure::no_pfs_key);
                } catch (const std::exception& e) {
                    log::warning(cat, "v2 direct message format error: {}", e.what());
                    fire_fail(msg, MessageDecryptFailure::bad_format);
                }
            }

        } else {
            // Version 1: protobuf WebSocketMessage → Envelope wire format.
            try {
                auto decoded = decode_dm_envelope(ed_sec, data, pro_backend::PUBKEY);

                ReceivedMessage out;
                out.hash = msg.hash;
                out.timestamp = msg.timestamp;
                out.expiry = msg.expiry;
                out.version = 1;
                // Reconstruct the 33-byte (0x05-prefixed) session ID from the x25519 pubkey.
                out.sender_session_id[0] = std::byte{0x05};
                std::ranges::copy(decoded.sender_x25519_pubkey, out.sender_session_id.begin() + 1);
                out.content = std::move(decoded.content_plaintext);
                if (decoded.envelope.flags & SESSION_PROTOCOL_ENVELOPE_FLAGS_PRO_SIG)
                    out.pro_signature = decoded.envelope.pro_sig;
                fire_received(std::move(out));
            } catch (const std::exception& e) {
                log::warning(cat, "v1 direct message decryption error: {}", e.what());
                fire_fail(msg, MessageDecryptFailure::decrypt_failed);
            }
        }
    }
}

void Core::_swarm_push(
        std::vector<SwarmStore> stores,
        std::vector<std::string> obsolete,
        std::function<void(std::optional<std::vector<SwarmStoreResult>>)> done) {

    if (stores.empty() && obsolete.empty())
        return;

    auto now_ms = epoch_ms(clock_now_ms());
    auto pubkey_hex = globals.session_id_hex();
    auto ed25519_hex = globals.pubkey_ed25519().hex();

    auto sign = [this](std::string_view value) {
        b64 sig;
        auto seed = globals.account_seed();
        ed25519::sign(sig, seed.ed25519_secret(), std::as_bytes(std::span{value}));
        return "{:b}"_format(sig);
    };

    auto requests = nlohmann::json::array();
    for (const auto& s : stores) {
        auto ns_val = static_cast<int16_t>(s.ns);
        nlohmann::json params = {
                {"pubkey", pubkey_hex},
                {"namespace", ns_val},
                {"data", "{:b}"_format(s.data)},
                {"timestamp", now_ms},
                {"ttl", s.ttl.count()},
                {"pubkey_ed25519", ed25519_hex},
                {"sig_timestamp", now_ms},
                {"signature", sign(ns_signature_value("store", ns_val, now_ms))},
        };
        requests.push_back({{"method", "store"}, {"params", std::move(params)}});
    }

    // Last, and one subrequest for all of them: they go to the same pubkey's swarm, and putting the
    // delete after every store is what stops a message being dropped before its replacement exists.
    if (!obsolete.empty()) {
        nlohmann::json params = {
                {"pubkey", pubkey_hex},
                {"pubkey_ed25519", ed25519_hex},
                {"messages", obsolete},
                // Signed over the hashes in the order they are sent, so the two must not be
                // reordered independently.
                {"signature", sign(delete_signature_value(obsolete))},
        };
        requests.push_back({{"method", "delete"}, {"params", std::move(params)}});
    }

    auto body = to_vector<std::byte>(nlohmann::json{{"requests", std::move(requests)}}.dump());

    log::debug(
            cat,
            "Pushing {} message(s) to the swarm, obsoleting {}",
            stores.size(),
            obsolete.size());

    // Unlike a poll's, this body does not depend on which member it goes to.
    _swarm_request(
            globals.pubkey_x25519(),
            "sequence",
            [body = std::move(body)](const network::service_node&) { return body; },
            [count = stores.size(), done = std::move(done)](SwarmResponse res) {
                if (!done)
                    return;

                if (!res.ok() || !res.body) {
                    log::warning(
                            cat,
                            "Swarm push failed ({}): {}",
                            res.timeout ? "timed out" : "status {}"_format(res.status_code),
                            res.body.value_or("no response body"));
                    return done(std::nullopt);
                }

                std::vector<SwarmStoreResult> out(count);
                try {
                    auto json = nlohmann::json::parse(*res.body);
                    auto results = json.find("results");
                    if (results == json.end() || !results->is_array()) {
                        log::warning(cat, "Swarm push response carried no results");
                        return done(std::nullopt);
                    }

                    for (size_t i = 0; i < count && i < results->size(); i++) {
                        const auto& r = (*results)[i];
                        auto code = r.find("code");
                        auto b = r.find("body");
                        if (code == r.end() || code->get<int>() != 200 || b == r.end())
                            continue;
                        auto h = b->find("hash");
                        if (h == b->end() || !h->is_string())
                            continue;
                        out[i] = {.stored = true, .hash = h->get<std::string>()};
                    }
                } catch (const std::exception& e) {
                    log::warning(cat, "Could not read swarm push response: {}", e.what());
                    return done(std::nullopt);
                }

                done(std::move(out));
            });
}

void Core::receive_messages(
        std::span<const SwarmMessage> messages, config::Namespace ns, bool is_final) {
    using config::Namespace;
    switch (ns) {
        case Namespace::Default: _handle_direct_messages(messages); break;
        case Namespace::Devices: devices.parse_device_messages(messages, is_final); break;
        case Namespace::AccountPubkeys: devices.parse_account_pubkeys(messages, is_final); break;
        case Namespace::UserProfile:
        case Namespace::Contacts:
        case Namespace::ConvoInfoVolatile:
        case Namespace::UserGroups: configs.merge(ns, messages); break;
        default:
            log::warning(
                    cat,
                    "receive_messages: ignoring unhandled namespace {}",
                    static_cast<int16_t>(ns));
    }
}

void Core::apply_migrations() {
    auto cat = log::Cat("schema");

    auto conn = db.conn();
    exec_query(conn.sql, R"(
CREATE TABLE IF NOT EXISTS migrations_applied (
    name TEXT PRIMARY KEY NOT NULL
) STRICT
)");

    std::unordered_set<std::string> applied;
    {
        SQLite::Statement st{conn.sql, "SELECT name FROM migrations_applied"};
        while (st.executeStep())
            applied.insert(get<std::string>(st));
    }

    log::debug(cat, "Checking schema migrations");

    // Core's own migrations record their bare name; an extension's are recorded as "owner:name" so
    // that two sets cannot collide.  A collision would not error, it would silently mark the second
    // migration as already applied.  Core's names deliberately stay unprefixed: prefixing them now
    // would re-run every migration on every existing database.
    auto apply_set = [&](std::string_view owner,
                         std::span<const schema::Migration> migrations,
                         std::string_view full_schema) {
        auto key_for = [&owner](std::string_view name) {
            return owner.empty() ? std::string{name} : "{}:{}"_format(owner, name);
        };

        // full_schema.sql creates the schema outright; the migrations beside it are deltas that
        // upgrade a database built from an *older* full_schema.  Nothing builds the schema from
        // nothing, and that is the point: a CREATE lives in one place rather than being duplicated
        // into an initial migration that then never changes.
        //
        // So a database with no record of this owner is built from the full schema, with the
        // migrations recorded as applied without running.  Keyed on the owner rather than on the
        // database being new, so an extension added to an existing database takes this path too.
        //
        // The marker is a row of its own rather than being inferred from the migration list,
        // because that list is legitimately empty until the first delta is written -- "none of this
        // owner's migrations are applied" would then be vacuously true on every open, re-running
        // the full schema against tables that already exist.  Migration names all begin with a
        // digit, so this cannot collide with one.
        auto created_key = owner.empty() ? std::string{"@created"} : "{}:@created"_format(owner);

        if (!full_schema.empty() && !applied.count(created_key) &&
            std::ranges::none_of(migrations, [&](const auto& m) {
                return applied.count(key_for(m.name)) > 0;
            })) {
            try {
                log::info(
                        cat, "Creating {} schema from full_schema", owner.empty() ? "core" : owner);

                SQLite::Transaction tx{conn.sql};

                conn.sql.exec(std::string{full_schema});
                conn.prepared_exec("INSERT INTO migrations_applied (name) VALUES (?)", created_key);
                for (const auto& m : migrations)
                    conn.prepared_exec(
                            "INSERT INTO migrations_applied (name) VALUES (?)", key_for(m.name));

                tx.commit();
            } catch (const std::exception& e) {
                log::critical(
                        cat,
                        "Creating {} schema from full_schema failed: {}",
                        owner.empty() ? "core" : owner,
                        e.what());
                throw;
            }
            return;
        }

        for (const auto& [name, apply] : migrations) {
            auto key = key_for(name);
            if (applied.count(key)) {
                log::debug(cat, "Schema migration {} already applied", key);
                continue;
            }

            try {
                log::info(cat, "Applying database schema migration {}", key);

                SQLite::Transaction tx{conn.sql};

                apply(conn, *this);
                conn.prepared_exec("INSERT INTO migrations_applied (name) VALUES (?)", key);

                tx.commit();
            } catch (const std::exception& e) {
                log::critical(cat, "Database schema migration '{}' failed: {}", key, e.what());
                throw;
            }
        }
    };

    apply_set("", schema::MIGRATIONS, schema::FULL_SCHEMA);

    std::unordered_set<std::string_view> owners;
    for (const auto& ext : _schema_extensions) {
        if (ext.owner.empty() || ext.owner.find(':') != std::string_view::npos)
            throw std::invalid_argument{
                    "schema_extension owner must be non-empty and must not contain ':' (got '{}')"_format(
                            ext.owner)};
        if (!owners.insert(ext.owner).second)
            throw std::invalid_argument{
                    "duplicate schema_extension owner '{}': migration names would collide"_format(
                            ext.owner)};
        apply_set(ext.owner, ext.migrations, ext.full_schema);
    }
    _schema_extensions.clear();

    log::debug(cat, "All schema migrations are applied");
}

}  // namespace session::core
