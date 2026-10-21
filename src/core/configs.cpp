#include "session/core/configs.hpp"

#include <SQLiteCpp/Transaction.h>
#include <sqlite3.h>

#include <algorithm>
#include <cassert>
#include <nlohmann/json.hpp>
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
#include <session/network/session_network.hpp>
#include <session/util.hpp>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "swarm_request.hpp"

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

    _known_dumps = dumps;
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

template <typename F>
void Configs::_slot(std::string_view type, F&& f) {
    if (type == "UserProfile")
        f(_user_profile);
    else if (type == "Contacts")
        f(_contacts);
    else if (type == "ConvoInfoVolatile")
        f(_convo_info_volatile);
    else if (type == "UserGroups")
        f(_user_groups);
    else if (type == "Local")
        f(_local);
}

// Stands in for the storage hash of a state another process holds but has not pushed: merging it
// as a message is the only way to reuse the config merge, and the merge needs a hash for each one.
// It must never reach a storage server, nor be taken for a hash of something stored there.
static constexpr std::string_view UNPUBLISHED = "unpublished-dump:";

static bool unpublished(std::string_view hash) {
    return hash.starts_with(UNPUBLISHED);
}

void Configs::_store(config::ConfigBase& conf) {
    if (!conf.needs_dump())
        return;

    auto c = conn();
    std::string type{conf.encryption_domain()};
    std::optional<std::vector<std::byte>> now;
    for (auto data : c.prepared_results<sqlite::blob>(
                 "SELECT data FROM config_dumps WHERE pubkey = ? AND type = ?",
                 core.globals.session_id(),
                 type))
        now.emplace(data.begin(), data.end());
    auto known = _known_dumps.find(type);
    auto* out = &conf;
    if (now && (known == _known_dumps.end() || known->second != *now)) {
        // Theirs, as the message it would push.  Pushed and confirmed, it carries its real hashes;
        // otherwise it exists only in that dump, and a placeholder stands in for them.
        auto seed = core.globals.account_seed();
        std::span<const std::byte> stored{*now};
        std::unique_ptr<config::ConfigBase> theirs;
        try {
            _slot(type, [&]<typename T>(std::unique_ptr<T>&) {
                theirs = std::make_unique<T>(seed.ed25519_secret(), stored);
            });
        } catch (const std::exception& e) {
            log::warning(
                    cat, "Overwriting unreadable {} dump from another process: {}", type, e.what());
        }
        auto hashes = theirs ? theirs->curr_hashes() : std::unordered_set<std::string>{};
        bool published = theirs && theirs->is_clean();
        std::vector<std::pair<std::string, std::vector<std::byte>>> incoming;
        if (theirs) {
            auto [seqno, msgs, obsolete] = theirs->push();
            published = published && hashes.size() == msgs.size();
            auto h = hashes.begin();
            for (auto& msg : msgs)
                incoming.emplace_back(
                        published ? *h++ : "{}{}"_format(UNPUBLISHED, incoming.size()),
                        std::move(msg));
        }

        auto before = conf.seqno();
        if (!incoming.empty()) {
            conf.merge(incoming);
            log::info(cat, "Merged {} written by another process before writing ours", type);
        } else if (theirs) {
            log::warning(cat, "Overwriting {} written by another process: it cannot merge", type);
        }

        // Theirs held everything ours did, and the merge adopted it as stored on the swarm --
        // which an unpushed state is not.  Their dump says exactly what it is, so take that.
        bool rebuilt = std::ranges::any_of(conf.curr_hashes(), unpublished);
        if (rebuilt)  // destroys `conf`
            _slot(type, [&]<typename T>(std::unique_ptr<T>& slot) {
                slot = std::make_unique<T>(seed.ed25519_secret(), stored);
                out = slot.get();
            });
        if ((rebuilt || out->seqno() != before) &&
            std::ranges::find(_changed, out->storage_namespace()) == _changed.end())
            _changed.push_back(out->storage_namespace());
    }

    // Once dumped, a dirty state is visible to the other process, which may build on it; amending
    // it in place would give it a new hash under the same seqno, and their copy of the old one
    // would then replay its stale values over ours.  Serialising it into a message ends the
    // amending: the next change starts a new seqno.  push() also hands over the hashes it
    // supersedes, which the real push then deletes.
    if (out->is_dirty()) {
        auto [seqno, msgs, obsolete] = out->push();
        auto& held = _obsolete[type];
        held.insert(held.end(), obsolete.begin(), obsolete.end());
    }
    auto dump = out->dump();
    c.prepared_exec(
            R"(
INSERT INTO config_dumps (pubkey, type, data) VALUES (?, ?, ?)
ON CONFLICT (pubkey, type) DO UPDATE SET data = excluded.data
)",
            core.globals.session_id(),
            type,
            dump);
    _known_dumps[type] = std::move(dump);
}

std::vector<config::Namespace> Configs::reload_if_changed() {
    assert(on_loop());
    std::vector<config::Namespace> reloaded;
    if (!_loaded)
        return reloaded;

    auto seed = core.globals.account_seed();
    for (auto [type, data] : conn().prepared_results<std::string, sqlite::blob>(
                 "SELECT type, data FROM config_dumps WHERE pubkey = ?",
                 core.globals.session_id())) {
        std::vector<std::byte> now{data.begin(), data.end()};
        auto it = _known_dumps.find(type);
        if (it != _known_dumps.end() && it->second == now)
            continue;
        config::ConfigBase* conf = nullptr;
        _slot(type, [&]<typename T>(std::unique_ptr<T>& slot) {
            slot = std::make_unique<T>(seed.ed25519_secret(), std::span<const std::byte>{now});
            conf = slot.get();
        });
        if (!conf)
            continue;
        log::info(cat, "Reloaded config {}: another process changed its dump", type);
        reloaded.push_back(conf->storage_namespace());
        _known_dumps[type] = std::move(now);
    }
    for (auto ns : reloaded)
        if (std::ranges::find(_changed, ns) == _changed.end())
            _changed.push_back(ns);
    if (!reloaded.empty())
        _schedule_settle();
    return reloaded;
}

void Configs::store_dumps() {
    auto confs = all();
    if (std::ranges::none_of(confs, [](auto* conf) { return conf->needs_dump(); }))
        return;

    // One write transaction across every comparison and write in _store, which would be worth
    // nothing if another process could write in between.  A caller's open transaction is joined.
    auto c = conn();
    std::optional<SQLite::Transaction> tx;
    if (sqlite3_get_autocommit(c.sql.getHandle()))
        tx.emplace(c.sql, SQLite::TransactionBehavior::IMMEDIATE);
    for (auto* conf : confs)
        _store(*conf);
    if (tx)
        tx->commit();
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

    // Resuming pushes whatever changed meanwhile; see `Core::resume_storage`.
    if (_push_in_flight || core.storage_suspended())
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

    auto net = core.network();
    if (!net) {
        log::debug(cat, "Not pushing configs: no network attached");
        return;
    }

    auto now_ms = epoch_ms(clock_now_ms());
    auto pubkey_hex = core.globals.session_id_hex();
    auto ed25519_hex = core.globals.pubkey_ed25519().hex();

    auto sign = [this](std::string_view value) {
        b64 sig;
        auto seed = core.globals.account_seed();
        ed25519::sign(sig, seed.ed25519_secret(), std::as_bytes(std::span{value}));
        return "{:b}"_format(sig);
    };

    std::vector<Pending> pending;
    std::vector<std::string> obsolete;
    auto requests = nlohmann::json::array();

    for (auto* conf : _pushable()) {
        if (!conf->needs_push())
            continue;

        auto ns_val = static_cast<int16_t>(conf->storage_namespace());
        auto [seqno, messages, superseded] = conf->push();

        pending.push_back({conf, seqno, requests.size(), messages.size()});

        for (const auto& msg : messages) {
            nlohmann::json params = {
                    {"pubkey", pubkey_hex},
                    {"namespace", ns_val},
                    {"data", "{:b}"_format(msg)},
                    {"timestamp", now_ms},
                    {"ttl", std::chrono::milliseconds{CONFIG_TTL}.count()},
                    {"pubkey_ed25519", ed25519_hex},
                    {"sig_timestamp", now_ms},
                    {"signature", sign(ns_signature_value("store", ns_val, now_ms))},
            };
            requests.push_back({{"method", "store"}, {"params", std::move(params)}});
        }

        // With whatever `_store` serialising it superseded, less the placeholders standing in for a
        // state that was never stored anywhere.
        auto& held = _obsolete[std::string{conf->encryption_domain()}];
        superseded.insert(superseded.end(), held.begin(), held.end());
        held.clear();
        for (auto& hash : superseded)
            if (!unpublished(hash))
                obsolete.push_back(std::move(hash));
    }

    if (pending.empty())
        return;

    // One delete for every config's obsolete hashes rather than one each: they go to the same
    // pubkey's swarm, so a single delete is the same information in fewer requests.  It goes last
    // so that nothing is dropped before its replacement has been stored -- which is why this is a
    // sequence rather than a batch, since a sequence stops at the first failure.
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
            "Pushing {} config(s) in {} subrequest(s), obsoleting {} message(s)",
            pending.size(),
            requests.size(),
            obsolete.size());

    _push_in_flight = true;

    core._swarm_request(
            core.globals.pubkey_x25519(),
            "sequence",
            [body = std::move(body)](const network::service_node&) { return body; },
            [this, alive = std::weak_ptr<int>{_alive}, pending = std::move(pending)](
                    Core::SwarmResponse res) {
                if (alive.expired())
                    return;
                _push_in_flight = false;

                if (!res.ok() || !res.body) {
                    log::warning(
                            cat,
                            "Config push failed ({}): {}",
                            res.timeout ? "timed out" : "status {}"_format(res.status_code),
                            res.body.value_or("no response body"));
                    return;
                }

                // A config is confirmed only if *every* message it split into was stored.
                // Confirming a partial push would drop the parts that did land from the obsolete
                // list while leaving the config believing it is clean, so the missing part would
                // never be sent again.
                try {
                    auto json = nlohmann::json::parse(*res.body);
                    auto results = json.find("results");
                    if (results == json.end() || !results->is_array()) {
                        log::warning(cat, "Config push response carried no results");
                        return;
                    }

                    for (const auto& p : pending) {
                        std::unordered_set<std::string> hashes;
                        bool stored = true;
                        for (size_t i = p.first; stored && i < p.first + p.count; i++) {
                            if (i >= results->size()) {
                                stored = false;
                                break;
                            }
                            const auto& r = (*results)[i];
                            auto code = r.find("code");
                            auto b = r.find("body");
                            if (code == r.end() || code->get<int>() != 200 || b == r.end()) {
                                stored = false;
                                break;
                            }
                            auto h = b->find("hash");
                            if (h == b->end() || !h->is_string()) {
                                stored = false;
                                break;
                            }
                            hashes.insert(h->get<std::string>());
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
                } catch (const std::exception& e) {
                    log::warning(cat, "Could not read config push response: {}", e.what());
                    return;
                }

                // Confirming changes the configs' state, and a change that arrived while this was
                // in flight has re-dirtied them.
                store_dumps();
                if (needs_push())
                    _schedule_push();
            });
}

void Configs::_handle_push_response(
        std::vector<Pending> pending,
        bool success,
        bool timeout,
        int16_t status,
        std::optional<std::string> resp) {
    assert(on_loop());

    _push_in_flight = false;

    if (!success || !resp) {
        log::warning(
                cat,
                "Config push failed ({}): {}",
                timeout ? "timed out" : "status {}"_format(status),
                resp.value_or("no response body"));
        return;
    }

    // A config is confirmed only if *every* message it split into was stored.  Confirming a
    // partial push would drop the parts that did land from the obsolete list while leaving the
    // config believing it is clean, so the missing part would never be sent again.
    try {
        auto json = nlohmann::json::parse(*resp);
        auto results = json.find("results");
        if (results == json.end() || !results->is_array()) {
            log::warning(cat, "Config push response carried no results");
            return;
        }

        for (const auto& p : pending) {
            std::unordered_set<std::string> hashes;
            bool stored = true;
            for (size_t i = p.first; stored && i < p.first + p.count; i++) {
                if (i >= results->size()) {
                    stored = false;
                    break;
                }
                const auto& r = (*results)[i];
                auto code = r.find("code");
                auto b = r.find("body");
                if (code == r.end() || code->get<int>() != 200 || b == r.end()) {
                    stored = false;
                    break;
                }
                auto h = b->find("hash");
                if (h == b->end() || !h->is_string()) {
                    stored = false;
                    break;
                }
                hashes.insert(h->get<std::string>());
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
    } catch (const std::exception& e) {
        log::warning(cat, "Could not read config push response: {}", e.what());
        return;
    }

    // Confirming changes the configs' state, and a change that arrived while this was in flight
    // has re-dirtied them.
    store_dumps();
    if (needs_push())
        _schedule_push();
}

}  // namespace session::core
