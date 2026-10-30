#include "session/push/notifications.hpp"

#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <session/format.hpp>
#include <session/network/session_network.hpp>

#include "client_access.hpp"
#include "core_access.hpp"
#include "internal.hpp"

namespace session::push {

namespace log = oxen::log;
static auto cat = log::Cat("push");

using detail::ClientAccess;
using detail::CoreAccess;
using namespace session::literals;

namespace {

    /// How far a fetch has got.
    ///
    /// Shared between its in-flight requests and its timers, and touched only on Core's job queue:
    /// the answers arrive on the network's threads and the swarm request marshals them across
    /// before any of this is read.  Holds the Core and Client by pointer rather than holding the
    /// Notifications, which may be gone by the time an answer lands; both outlive anything on
    /// Core's queue, which is cancelled as Core goes.
    /// How a fetch ended, before any stored message is looked up.
    struct Outcome {
        FetchResult result;
        /// For `unreadable`: the message's bytes and why they did not decrypt, so that a caller
        /// that can fix the cause -- fetching new keys -- can try them again.
        std::vector<std::byte> undecrypted;
        std::optional<core::MessageDecryptFailure> why;
    };

    struct Fetch {
        core::Core* core;
        config::Namespace ns;
        /// The message wanted; empty to bring the namespace up to date from one member instead.
        std::string hash;
        std::function<void(Outcome)> done;
        std::chrono::steady_clock::time_point deadline;

        /// Members still being asked in the current round.
        size_t outstanding = 0;
        /// Rounds started: the first, and the one retry.
        int attempts = 0;
        /// Whether any member answered usably, which separates not_found from failed.
        bool answered = false;
        bool concluded = false;
    };

    // The least time worth starting another round with: a request given less cannot resolve a node,
    // connect and get an answer.
    constexpr auto MIN_ROUND_BUDGET = 2s;

    void ask(
            const std::shared_ptr<Fetch>& op, std::optional<network::service_node> node, int round);
    void member_done(const std::shared_ptr<Fetch>& op);

    void conclude(Fetch& op, Outcome outcome) {
        if (op.concluded)
            return;
        op.concluded = true;

        auto result = outcome.result;
        log::info(
                cat,
                "Fetch of {} concluded: {}",
                op.hash.empty() ? "namespace {}"_format(static_cast<int16_t>(op.ns))
                                : "a pushed message"s,
                result == FetchResult::found        ? "found"
                : result == FetchResult::unreadable ? "found, but it did not decrypt"
                : result == FetchResult::not_found  ? "not yet on the members asked"
                : result == FetchResult::failed     ? "no member answered"
                                                    : "no network");
        if (op.done)
            std::exchange(op.done, nullptr)(std::move(outcome));
    }

    void conclude(Fetch& op, FetchResult result) {
        conclude(op, Outcome{result});
    }

    void start_round(const std::shared_ptr<Fetch>& op) {
        auto* net = op->core->network();
        if (!net || op->concluded)
            return;

        op->attempts++;
        net->get_swarm(op->core->globals.pubkey_x25519(), false, [op](auto, auto swarm) {
            op->core->call([op, swarm = std::move(swarm)] {
                if (op->concluded)
                    return;
                if (swarm.empty()) {
                    log::warning(cat, "Cannot fetch a pushed message: no swarm members available");
                    op->outstanding = 1;
                    return member_done(op);
                }

                // Distinct members to start from: get_swarm hands them back least-struck first and
                // shuffled among equals, so the front of the list is the right choice.  One that
                // turns out to be wrong or unreachable is walked past by the swarm request itself,
                // which may land on one another branch is asking; the answers then arrive twice.
                auto n = std::min(swarm.size(), Notifications::FETCH_MEMBERS);
                op->outstanding = n;
                for (size_t i = 0; i < n; i++)
                    ask(op, swarm[i], 0);
            });
        });
    }

    void answer(const std::shared_ptr<Fetch>& op, CoreAccess::SwarmResponse res, int round) {
        auto& core = *op->core;

        std::optional<core::retrieved_namespace> got;
        if (res.ok() && res.body) {
            try {
                auto json = nlohmann::json::parse(*res.body);
                auto it = json.find("results");
                if (it != json.end() && it->is_array() && !it->empty())
                    got = core::decode_retrieved((*it)[0], static_cast<int16_t>(op->ns));
            } catch (const std::exception& e) {
                log::warning(cat, "Failed to parse pushed message fetch response: {}", e.what());
            }
        } else {
            // Once the fetch has its answer, the members still being asked are abandoned -- the
            // one-shot network is usually torn down straight after -- so their failing is expected
            // and not worth a warning.
            log::log(
                    cat,
                    op->concluded ? log::Level::debug : log::Level::warn,
                    "Pushed message fetch from {} failed: {}",
                    res.node.remote_pubkey.hex(),
                    res.timeout ? "timed out" : "request failed");
        }

        if (!got)
            return member_done(op);

        op->answered = true;

        // Received whether or not the fetch has already concluded: it came from our own swarm, and
        // dropping it would only leave the next poll to fetch it again.  The cursor is recorded
        // because this is an ordinary retrieve from it; see the TODO on fetch_message.
        core::ReceiveResult received;
        {
            auto configs_held = core.configs.batch();
            received = core.receive_messages(got->messages, op->ns, !got->more);
        }
        CoreAccess::record_cursor(core, res.node.remote_pubkey, op->ns, got->messages);

        if (op->concluded)
            return;

        // Bringing a namespace up to date ends once one member has handed over all it holds.
        if (op->hash.empty()) {
            if (!got->more)
                return conclude(*op, FetchResult::found);
        } else if (auto it = std::ranges::find(got->messages, op->hash, &core::SwarmMessage::hash);
                   it != got->messages.end()) {
            auto failed = std::ranges::find(
                    received.undecryptable,
                    op->hash,
                    &std::pair<std::string, core::MessageDecryptFailure>::first);
            if (failed == received.undecryptable.end())
                return conclude(*op, FetchResult::found);
            return conclude(
                    *op,
                    Outcome{FetchResult::unreadable,
                            {it->data.begin(), it->data.end()},
                            failed->second});
        }

        // Not yet, but this member says it holds more past what it returned, so the message may
        // still be among it.  The continuation goes back to the same member, whose cursor it
        // resumes from.
        if (got->more && round + 1 < core::POLL_MAX_ROUNDS)
            return ask(op, res.node, round + 1);

        member_done(op);
    }

    void
    ask(const std::shared_ptr<Fetch>& op, std::optional<network::service_node> node, int round) {
        CoreAccess::swarm_request(
                *op->core,
                "batch",
                [core = op->core, ns = op->ns](const network::service_node& n) {
                    return CoreAccess::retrieve_body(*core, n, ns);
                },
                [op, round](CoreAccess::SwarmResponse res) { answer(op, std::move(res), round); },
                std::move(node));
    }

    void member_done(const std::shared_ptr<Fetch>& op) {
        if (op->concluded || --op->outstanding > 0)
            return;

        // Every member of this round has answered without it.  Ask again once, after giving the
        // swarm a moment to propagate, if the deadline leaves room for that and a request after it.
        auto retry_at = std::chrono::steady_clock::now() + Notifications::FETCH_RETRY_DELAY;
        if (op->attempts < 2 && retry_at + MIN_ROUND_BUDGET < op->deadline) {
            op->core->call_later(Notifications::FETCH_RETRY_DELAY, [op] { start_round(op); });
            return;
        }

        conclude(*op, op->answered ? FetchResult::not_found : FetchResult::failed);
    }

    std::shared_ptr<Fetch> start_fetch(
            core::Core& core,
            config::Namespace ns,
            std::string hash,
            std::chrono::steady_clock::time_point deadline,
            std::function<void(Outcome)> done) {
        auto op = std::make_shared<Fetch>();
        op->core = &core;
        op->ns = ns;
        op->hash = std::move(hash);
        op->done = std::move(done);
        op->deadline = deadline;

        if (!core.network() || !core.globals.have_account()) {
            conclude(*op, FetchResult::no_network);
            return op;
        }

        auto remaining = std::max<std::chrono::milliseconds>(
                0ms,
                std::chrono::duration_cast<std::chrono::milliseconds>(
                        deadline - std::chrono::steady_clock::now()));
        core.call_later(remaining, [op] {
            conclude(*op, op->answered ? FetchResult::not_found : FetchResult::failed);
        });
        core.call([op] { start_round(op); });
        return op;
    }

    // Hands `cb` what is stored under the push's hash once handling ends with `outcome`.
    void report_stored(
            client::Client& client, Payload p, Handled outcome, result_function<HandledPush> cb) {
        auto hash = p.hash;
        client.message_by_hash(
                std::move(hash),
                [p = std::move(p), outcome, cb = std::move(cb)](auto stored) mutable {
                    if (!stored)
                        return cb(Expected<HandledPush>{unexpected{stored.error()}});
                    cb(Expected<HandledPush>{
                            HandledPush{outcome, std::move(p), std::move(*stored)}});
                });
    }

    // A message that arrived but did not decrypt.  For want of a key, which is what a key rotation
    // we have not yet heard about looks like, the device group is fetched -- that is where a
    // rotation's new keys arrive -- and the message tried again; it is unreadable if it still
    // fails, or failed for any other reason.  `delivered` is what to report if the retry reads it.
    void retry_unreadable(
            core::Core& core,
            client::Client& client,
            Payload p,
            std::vector<std::byte> data,
            core::MessageDecryptFailure why,
            std::chrono::steady_clock::time_point deadline,
            Handled delivered,
            result_function<HandledPush> cb) {
        auto unreadable = [&client](Payload p, result_function<HandledPush> cb) {
            ClientAccess::report(
                    client,
                    cb,
                    Expected<HandledPush>{
                            HandledPush{Handled::unreadable, std::move(p), std::nullopt}});
        };

        if (why != core::MessageDecryptFailure::no_pfs_key ||
            std::chrono::steady_clock::now() + MIN_ROUND_BUDGET >= deadline)
            return unreadable(std::move(p), std::move(cb));

        log::info(cat, "A pushed message needs keys we lack; fetching the device group");
        start_fetch(
                core,
                config::Namespace::Devices,
                "",
                deadline,
                [&core,
                 &client,
                 unreadable,
                 p = std::move(p),
                 data = std::move(data),
                 delivered,
                 cb = std::move(cb)](Outcome) mutable {
                    core.call([&core,
                               &client,
                               unreadable,
                               p = std::move(p),
                               data = std::move(data),
                               delivered,
                               cb = std::move(cb)]() mutable {
                        core::SwarmMessage m{data, p.hash, p.timestamp, p.expiry};
                        if (!core.receive_messages({&m, 1}, p.ns, true).undecryptable.empty())
                            return unreadable(std::move(p), std::move(cb));
                        report_stored(client, std::move(p), delivered, std::move(cb));
                    });
                });
    }

    // Fetches the message a push stands for -- one too large to carry, or what a push without data
    // means -- and reports what came of it.
    void fetch_for_push(
            core::Core& core,
            client::Client& client,
            std::chrono::steady_clock::time_point until,
            Payload p,
            result_function<HandledPush> cb) {
        auto ns = p.ns;
        auto hash = p.hash;
        start_fetch(
                core,
                ns,
                std::move(hash),
                until,
                [&core, &client, until, p = std::move(p), cb = std::move(cb)](
                        Outcome fetched) mutable {
                    switch (fetched.result) {
                        case FetchResult::found:
                            return report_stored(
                                    client, std::move(p), Handled::fetched, std::move(cb));
                        case FetchResult::unreadable:
                            return retry_unreadable(
                                    core,
                                    client,
                                    std::move(p),
                                    std::move(fetched.undecrypted),
                                    *fetched.why,
                                    until,
                                    Handled::fetched,
                                    std::move(cb));
                        // A poll may have brought it in regardless, so look.
                        case FetchResult::not_found:
                            return report_stored(
                                    client, std::move(p), Handled::not_found, std::move(cb));
                        case FetchResult::failed:
                        case FetchResult::no_network:
                            return report_stored(
                                    client, std::move(p), Handled::fetch_failed, std::move(cb));
                    }
                });
    }

}  // namespace

bool Notifications::claim(int64_t message_id) {
    auto& core = _client.core;
    return core.call_get([&core, message_id] {
        return core.database().conn().prepared_exec(
                       "INSERT INTO notified (message, at) VALUES (?, ?) ON CONFLICT DO NOTHING",
                       message_id,
                       epoch_ms(clock_now_ms())) > 0;
    });
}

bool Notifications::fetch_on_push(config::Namespace ns) {
    switch (ns) {
        // A change to the device group may be a key rotation, without whose keys later messages
        // will not decrypt, or a link request the user is waiting on.
        case config::Namespace::Devices: return true;
        // What was read on another device, so that its notifications here can be removed.
        case config::Namespace::ConvoInfoVolatile: return true;
        // A contact's name or our nickname for them, so a notification does not show a stale one.
        case config::Namespace::Contacts: return true;
        // Groups we have left, been removed from, or that were deleted, whose messages could no
        // longer be decrypted and should not notify.
        case config::Namespace::UserGroups: return true;
        // A group's keys, without which its later messages will not decrypt; and its name and
        // members, for the same reason as Contacts.  Group swarms are not subscribed until Client
        // holds groups, so these wait on that.
        case config::Namespace::GroupKeys:
        case config::Namespace::GroupInfo:
        case config::Namespace::GroupMembers: return true;
        // Our own profile changes nothing a notification shows.
        default: return false;
    }
}

std::optional<config::Namespace> Notifications::fetch_first(config::Namespace ns) {
    switch (ns) {
        // Re-encrypted with the group's newest keys whenever those change, so fetched before them
        // they may not decrypt.
        case config::Namespace::GroupInfo:
        case config::Namespace::GroupMembers: return config::Namespace::GroupKeys;
        default: return std::nullopt;
    }
}

void Notifications::handle(
        std::string_view enc_payload,
        std::chrono::milliseconds deadline,
        result_function<HandledPush> cb) {
    auto* core = &_client.core;
    auto* client = &_client;

    // Reports an outcome that has no stored message to look up.
    auto report = [core, client](
                          result_function<HandledPush> cb,
                          Handled outcome,
                          std::optional<Payload> payload) {
        core->call([client, cb = std::move(cb), outcome, payload = std::move(payload)]() mutable {
            ClientAccess::report(
                    *client,
                    cb,
                    Expected<HandledPush>{HandledPush{outcome, std::move(payload), std::nullopt}});
        });
    };

    Payload p;
    try {
        p = decode(enc_payload, encryption_key());
    } catch (const undecryptable&) {
        log::warning(cat, "A push did not decrypt with our key; renewing the subscription");
        core->call([core] { detail::mark_subscription_due(*core); });
        return report(std::move(cb), Handled::undecryptable, std::nullopt);
    } catch (const malformed& e) {
        log::warning(cat, "Malformed push: {}", e.what());
        return report(std::move(cb), Handled::malformed, std::nullopt);
    }

    // TODO: a group's swarm, once Core holds groups; until then every push is for the account.
    if (!core->globals.have_account() || p.swarm != core->globals.session_id_hex())
        return report(std::move(cb), Handled::not_ours, std::move(p));

    auto until = std::chrono::steady_clock::now() + deadline;

    if (p.data) {
        core->call([core, client, until, p = std::move(p), cb = std::move(cb)]() mutable {
            core::SwarmMessage m{*p.data, p.hash, p.timestamp, p.expiry};
            core::ReceiveResult received;
            {
                auto configs_held = core->configs.batch();
                received = core->receive_messages({&m, 1}, p.ns, true);
            }
            if (!received.undecryptable.empty()) {
                auto data = std::move(*p.data);
                auto why = received.undecryptable.front().second;
                return retry_unreadable(
                        *core,
                        *client,
                        std::move(p),
                        std::move(data),
                        why,
                        until,
                        Handled::received,
                        std::move(cb));
            }
            report_stored(*client, std::move(p), Handled::received, std::move(cb));
        });
        return;
    }

    if (!p.too_large && !fetch_on_push(p.ns))
        return report(std::move(cb), Handled::nothing_to_do, std::move(p));
    auto ns = p.ns;

    auto fetch = [core, client, until, p = std::move(p), cb = std::move(cb)]() mutable {
        fetch_for_push(*core, *client, until, std::move(p), std::move(cb));
    };
    // Some namespaces are encrypted with keys that arrive in another, so that one comes first or
    // what is fetched may not be readable.
    if (auto first = fetch_first(ns))
        start_fetch(
                *core, *first, "", until, [fetch = std::move(fetch)](Outcome) mutable { fetch(); });
    else
        fetch();
}

void Notifications::fetch_message(
        config::Namespace ns,
        std::string hash,
        std::chrono::milliseconds deadline,
        result_function<FetchedMessage> cb) {
    // Reports whatever is then stored under the hash: a poll may have brought the message in even
    // when the members asked did not have it.
    auto* client = &_client;
    start_fetch(
            _client.core,
            ns,
            hash,
            std::chrono::steady_clock::now() + deadline,
            [client, hash, cb = std::move(cb)](Outcome outcome) mutable {
                client->message_by_hash(
                        hash, [result = outcome.result, cb = std::move(cb)](auto stored) mutable {
                            if (!cb)
                                return;
                            if (!stored)
                                return cb(Expected<FetchedMessage>{unexpected{stored.error()}});
                            cb(Expected<FetchedMessage>{
                                    FetchedMessage{result, std::move(*stored)}});
                        });
            });
}

}  // namespace session::push
