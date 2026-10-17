#include "session/core/configs.hpp"

#include <algorithm>
#include <cassert>
#include <oxen/log.hpp>
#include <oxen/quic/loop.hpp>
#include <session/clock.hpp>
#include <session/config/base.hpp>
#include <session/config/contacts.hpp>
#include <session/config/convo_info_volatile.hpp>
#include <session/config/local.hpp>
#include <session/config/user_groups.hpp>
#include <session/config/user_profile.hpp>
#include <session/core.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/util.hpp>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace session::core {

static auto cat = oxen::log::Cat("configs");

namespace log = oxen::log;

Configs::Configs(Core& core) : CoreComponent{core} {}

Configs::~Configs() = default;

void Configs::_load() {
    // Every public entry point on this class reaches the config objects through here, so this is
    // the one place the threading rule has to hold: the objects are built lazily, so two threads
    // arriving together would race on construction, and once built they are what `merge()` mutates
    // on the loop while a reader is walking them.
    assert(on_loop());

    if (_loaded)
        return;

    auto seed = core.globals.account_seed();
    auto key = seed.ed25519_secret();

    // Copied out rather than referenced: a sqlite::blob spans the statement's own memory, which is
    // reused as the iteration advances.
    std::unordered_map<std::string, std::vector<std::byte>> dumps;
    for (auto [type, data] : conn().prepared_results<std::string, sqlite::blob>(
                 "SELECT type, data FROM config_dumps WHERE pubkey = ?", core.globals.session_id()))
        dumps.emplace(std::move(type), std::vector<std::byte>{data.begin(), data.end()});

    auto stored = [&dumps](std::string_view type) -> std::optional<std::span<const std::byte>> {
        if (auto it = dumps.find(std::string{type}); it != dumps.end())
            return std::span<const std::byte>{it->second};
        return std::nullopt;
    };

    _user_profile = std::make_unique<config::UserProfile>(key, stored("UserProfile"));
    _contacts = std::make_unique<config::Contacts>(key, stored("Contacts"));
    _convo_info_volatile =
            std::make_unique<config::ConvoInfoVolatile>(key, stored("ConvoInfoVolatile"));
    _user_groups = std::make_unique<config::UserGroups>(key, stored("UserGroups"));
    _local = std::make_unique<config::Local>(key, stored("Local"));

    _loaded = true;

    // The names above are literals because a dump has to be handed to the constructor, so there is
    // no object to ask for its domain until after it exists.  Anything left unclaimed is therefore
    // either a typo in one of them -- which would silently discard a config and resync it from the
    // swarm -- or a dump written by a version that knows a config this one does not.
    for (auto* conf : all())
        dumps.erase(std::string{conf->encryption_domain()});
    for (const auto& [type, _] : dumps)
        log::warning(cat, "Ignoring stored config dump of unrecognised type {}", type);

    log::debug(cat, "Loaded {} config(s)", all().size());
}

std::vector<config::ConfigBase*> Configs::all() {
    _load();
    return {_user_profile.get(),
            _contacts.get(),
            _convo_info_volatile.get(),
            _user_groups.get(),
            _local.get()};
}

// Each of these schedules a settle, because handing out the reference is the last thing that
// happens before a caller may change what it points at, and it is the only thing this layer sees.
// A config is mutated through that reference; nothing tells us afterwards, and asking the config to
// tell us does not work either -- its own "needs dump" flag is set *before* the assignment that
// follows, so anything acting on it would serialise a change that has not happened yet.
//
// Reads schedule one too, since a reader and a writer ask the same question.  That costs a job that
// finds every config clean and does nothing: `store_dumps` skips what has not changed and
// `needs_push` is five state reads.

config::UserProfile& Configs::user_profile() {
    _load();
    _schedule_settle();
    return *_user_profile;
}

config::Contacts& Configs::contacts() {
    _load();
    _schedule_settle();
    return *_contacts;
}

config::ConvoInfoVolatile& Configs::convo_info_volatile() {
    _load();
    _schedule_settle();
    return *_convo_info_volatile;
}

config::UserGroups& Configs::user_groups() {
    _load();
    _schedule_settle();
    return *_user_groups;
}

config::Local& Configs::local() {
    _load();
    _schedule_settle();
    return *_local;
}

config::ConfigBase* Configs::for_namespace(config::Namespace ns) {
    _load();
    switch (ns) {
        case config::Namespace::UserProfile: return _user_profile.get();
        case config::Namespace::Contacts: return _contacts.get();
        case config::Namespace::ConvoInfoVolatile: return _convo_info_volatile.get();
        case config::Namespace::UserGroups: return _user_groups.get();
        default: return nullptr;
    }
}

void Configs::_store(config::ConfigBase& conf) {
    if (!conf.needs_dump())
        return;

    conn().prepared_exec(
            R"(
INSERT INTO config_dumps (pubkey, type, data) VALUES (?, ?, ?)
ON CONFLICT (pubkey, type) DO UPDATE SET data = excluded.data
)",
            core.globals.session_id(),
            conf.encryption_domain(),
            conf.dump());
}

void Configs::store_dumps() {
    for (auto* conf : all())
        _store(*conf);
}

Configs::Batch::Batch(Configs& configs) : _configs{configs} {
    _configs._batch_depth++;
}

Configs::Batch::~Batch() {
    if (--_configs._batch_depth != 0)
        return;

    // `_flush` writes to the database, so it can throw -- and this runs during unwinding whenever
    // the work inside the batch threw, where a second exception is a call to std::terminate.  The
    // changes stay dirty, so the next thing to settle writes them.
    try {
        _configs._flush();
    } catch (const std::exception& e) {
        log::warning(cat, "Could not flush configs at the end of a batch: {}", e.what());
    }
}

void Configs::_flush() {
    if (_batch_depth > 0)
        return;

    store_dumps();

    // Unconditional rather than only after a merge, so that this is the one place that decides a
    // push is owed: a settle scheduled by an accessor lands here knowing only that someone held a
    // config, and whether that left anything to publish is this check's to answer.
    if (needs_push())
        _schedule_push();

    // After the dumps, so a handler never reads state that is not yet on disk.  A throwing handler
    // must not take the merge down with it, and the change is not redelivered -- the next merge of
    // that config reports it again, and reconciliation compares rather than replays regardless.
    if (!_changed.empty()) {
        auto changed = std::move(_changed);
        _changed.clear();
        if (cb().configs_changed) {
            try {
                cb().configs_changed(changed);
            } catch (const std::exception& e) {
                log::warning(cat, "configs_changed callback threw: {}", e.what());
            }
        }
    }
}

void Configs::merge(config::Namespace ns, std::span<const SwarmMessage> messages) {
    // A poll reports every namespace it successfully fetched, including ones that returned nothing,
    // because some handlers need to know the fetch happened.  Configs are not among them: there is
    // no state here that a completed-but-empty poll settles, so an empty batch would only run a
    // merge of nothing and a flush behind it, on every namespace, on every poll.
    if (messages.empty())
        return;

    auto held = batch();

    auto* conf = for_namespace(ns);
    if (!conf) {
        log::warning(
                cat,
                "Ignoring {} config message(s) for namespace {}, which holds no config",
                messages.size(),
                static_cast<int16_t>(ns));
        return;
    }

    std::vector<std::pair<std::string, std::span<const std::byte>>> incoming;
    incoming.reserve(messages.size());
    for (const auto& m : messages)
        incoming.emplace_back(m.hash, m.data);

    // The returned hash set says which messages parsed, not whether any of them mattered -- a stale
    // config counts as parsed.  The seqno is what actually moves when a merge changes something.
    auto before = conf->seqno();
    auto accepted = conf->merge(incoming);
    if (conf->seqno() != before && std::ranges::find(_changed, ns) == _changed.end())
        _changed.push_back(ns);

    log::debug(
            cat,
            "Merged {} of {} {} config message(s); {}, {}",
            accepted.size(),
            incoming.size(),
            conf->encryption_domain(),
            conf->needs_push() ? "needs push" : "up to date",
            conf->needs_dump() ? "changed" : "unchanged");

    _flush();
}

void Configs::initialise_new_account() {
    // Note to self starts with no conversation, which UserProfile can only say by giving it a
    // negative priority.  A contact's conversation exists because there is an entry for it in the
    // Contacts config; UserProfile has no entry to be absent, since it exists from the moment the
    // account does, so priority carries existence as well as visibility here.  An account that has
    // never written a note is indistinguishable from one that set 0 deliberately unless this is
    // written, because the getter reports an unset value as 0.
    //
    // It matters that this is not a local display decision: nts_priority lives in the shared
    // UserProfile config, so leaving it at the default 0 would not merely show the conversation
    // here, it would make it appear on every device on the account the moment they synced.
    user_profile().set_nts_priority(-1);
    _flush();
}

std::vector<config::ConfigBase*> Configs::_pushable() {
    _load();
    return {_user_profile.get(), _contacts.get(), _convo_info_volatile.get(), _user_groups.get()};
}

bool Configs::needs_push() {
    for (auto* conf : _pushable())
        if (conf->needs_push())
            return true;
    return false;
}

// The longest a storage server will hold a message in a namespace only its owner may write
// (oxenss TTL_MAXIMUM_PRIVATE; the limit for public namespaces is half of it).  This is the ceiling
// rather than a chosen figure: a config is what a device that has been away comes back to, so there
// is nothing to be gained by expiring it sooner.
static constexpr auto CONFIG_TTL = 30 * 24h;

void Configs::_schedule_settle() {
    // Not while Core is still being built.  The loop thread is already running by then, but the
    // constructing thread is legitimately off it -- that is what `on_loop()` allows for -- so a job
    // posted here would serialise a config on the loop while construction is still writing to it.
    // Nothing is owed: construction flushes what it changes itself.
    if (!core._constructed)
        return;

    // Once per turn of the loop, however many configs were handed out and however many fields were
    // touched in each.
    if (_settle_scheduled)
        return;
    _settle_scheduled = true;

    // `call_soon` rather than running it here, and that is the whole of why this works: the caller
    // is holding a reference it has not written through yet -- `dirty()` bumps the seqno and marks
    // the config before the assignment that follows it -- so there is no moment during the accessor
    // at which the config is whole.  Once the job that took the reference has returned, there is.
    jq().call_soon([this] {
        _settle_scheduled = false;
        try {
            _flush();
        } catch (const std::exception& e) {
            log::warning(cat, "Could not settle config changes: {}", e.what());
        }
    });
}

void Configs::_schedule_push() {
    auto now = std::chrono::steady_clock::now();
    _last_change = now;
    if (_burst_started == std::chrono::steady_clock::time_point{})
        _burst_started = now;

    if (_push_scheduled)
        return;
    _push_scheduled = true;
    _arm_push_timer(push_debounce);
}

void Configs::_arm_push_timer(std::chrono::milliseconds delay) {
    // On Core's queue rather than the loop, so stopping the queue deletes the pending timer.  The
    // `_alive` canary the network callback below still needs is exactly what that spares us here.
    jq().call_later(delay, [this] { _push_if_due(); });
}

void Configs::_push_if_due() {
    auto now = std::chrono::steady_clock::now();
    auto quiet = now - _last_change;
    auto waited = now - _burst_started;

    if (quiet >= push_debounce || waited >= push_max_delay) {
        _push_scheduled = false;
        _burst_started = {};
        push_now();
        return;
    }

    // Changes are still arriving, so wait for them -- but no further than the cap allows.  Both
    // bounds are recomputed rather than tracked, so a re-arm cannot drift past the deadline the
    // first change set.
    using std::chrono::duration_cast;
    using std::chrono::milliseconds;
    _arm_push_timer(std::min(
            duration_cast<milliseconds>(push_debounce - quiet),
            duration_cast<milliseconds>(push_max_delay - waited)));
}

void Configs::push_now() {
    // Its own assert because the early return below reads push state without going through
    // _load(), so this is the one path that could otherwise skip the check entirely.
    assert(on_loop());

    if (_push_in_flight)
        return;
    _send_push();
}

void Configs::_send_push() {
    // Checked here rather than at the scheduling end so that everything up to the wire still
    // happens: changes are held and dumped, and needs_push() keeps reporting them, so the state
    // reads as unpublished rather than as settled.
    if (!push_enabled) {
        log::warning(cat, "Not pushing configs: pushing is disabled");
        return;
    }

    // Here even though the transport reports a missing network itself, because by then it is too
    // late: `push()` below moves each config into waiting for confirmation, which is a change of
    // state to dump, and with nothing to send it on that change would never be confirmed.
    if (!core.network()) {
        log::debug(cat, "Not pushing configs: no network attached");
        return;
    }

    std::vector<Pending> pending;
    std::vector<SwarmStore> stores;
    std::vector<std::string> obsolete;

    for (auto* conf : _pushable()) {
        if (!conf->needs_push())
            continue;

        auto [seqno, messages, superseded] = conf->push();

        pending.push_back({conf, seqno, stores.size(), messages.size()});

        for (auto& msg : messages)
            stores.push_back(
                    {.ns = conf->storage_namespace(),
                     .data = std::move(msg),
                     .ttl = std::chrono::duration_cast<std::chrono::milliseconds>(CONFIG_TTL)});

        obsolete.insert(obsolete.end(), superseded.begin(), superseded.end());
    }

    if (pending.empty())
        return;

    _push_in_flight = true;

    core._swarm_push(
            std::move(stores),
            std::move(obsolete),
            [this, alive = std::weak_ptr<int>{_alive}, pending = std::move(pending)](
                    std::optional<std::vector<SwarmStoreResult>> results) {
                if (alive.expired())
                    return;
                _push_in_flight = false;

                if (!results)
                    return;

                // A config is confirmed only if *every* message it split into was stored.
                // Confirming a partial push would drop the parts that did land from the obsolete
                // list while leaving the config believing it is clean, so the missing part would
                // never be sent again.
                for (const auto& p : pending) {
                    std::unordered_set<std::string> hashes;
                    bool stored = true;
                    for (size_t i = p.first; stored && i < p.first + p.count; i++) {
                        if (i >= results->size() || !(*results)[i].stored) {
                            stored = false;
                            break;
                        }
                        hashes.insert((*results)[i].hash);
                    }

                    if (!stored) {
                        log::warning(
                                cat,
                                "Config push: {} was not stored, leaving it dirty",
                                p.conf->encryption_domain());
                        continue;
                    }
                    p.conf->confirm_pushed(p.seqno, std::move(hashes));
                }

                // Confirming changes the configs' state, and a change that arrived while this was
                // in flight has re-dirtied them.
                store_dumps();
                if (needs_push())
                    _schedule_push();
            });
}

}  // namespace session::core
