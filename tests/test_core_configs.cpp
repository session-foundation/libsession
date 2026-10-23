#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <session/config/contacts.hpp>
#include <session/config/convo_info_volatile.hpp>
#include <session/config/local.hpp>
#include <session/config/user_groups.hpp>
#include <session/config/user_profile.hpp>
#include <session/core.hpp>

#include "test_helper.hpp"

using namespace session;
using namespace session::core;

namespace {

/// Reopens the same database file, which is how "does this survive a restart" is asked: the configs
/// are rebuilt from their dumps rather than from anything still in memory.
void reopen(TempCore& c) {
    c.core.reset();
    c.core = std::make_unique<core::Core>(c.path);
}

/// Publishes the defaults a new account is created with, so a test can start from "nothing owed"
/// rather than from "this account has just come into being and has not said so yet".
void settle_new_account(TempCore& c) {
    auto& profile = c->configs.user_profile();
    auto [seqno, messages, obsolete] = profile.push();
    profile.confirm_pushed(seqno, {"seededprofile"});
    c->configs.store_dumps();
}

/// What another device pushed to its Contacts config, having added one contact.  Unlike the profile
/// helper this starts from nothing, because a new account seeds no contacts, so there is no shared
/// history for it to descend from and nothing for it to collide with.
std::vector<std::vector<std::byte>> contacts_from_another_device(
        TempCore& c, std::string_view session_id) {
    auto seed = c->globals.account_seed();
    config::Contacts theirs{seed.ed25519_secret(), std::nullopt};
    theirs.set(theirs.get_or_construct(std::string{session_id}));
    auto [seqno, messages, obsolete] = theirs.push();
    return messages;
}

int64_t stored_dumps(TempCore& c) {
    return c->database().conn().prepared_get<int64_t>("SELECT count(*) FROM config_dumps");
}

/// A config message as it would arrive from the swarm: what another device on this account pushed.
/// Built from a second config object holding the same account key, since that is exactly what
/// another device is.
std::vector<std::vector<std::byte>> push_from_another_device(TempCore& c, std::string_view name) {
    // Descends from what we published rather than being invented beside it: a device built from
    // nothing would land on the same seqno as our own account defaults and have to be merged with
    // them, which is a different scenario (and one this file covers separately).
    settle_new_account(c);

    auto seed = c->globals.account_seed();
    config::UserProfile theirs{seed.ed25519_secret(), c->configs.user_profile().make_dump()};
    theirs.set_name(name);
    auto [seqno, messages, obsolete] = theirs.push();
    return messages;
}

/// Note the spans: a SwarmMessage points at its data rather than owning it, exactly as one decoded
/// from a poll response does, so whatever is passed in here has to outlive the result.
std::vector<SwarmMessage> as_swarm_messages(
        const std::vector<std::vector<std::byte>>& messages, std::string_view tag = "fakehash") {
    std::vector<SwarmMessage> out;
    for (size_t i = 0; i < messages.size(); i++) {
        SwarmMessage m;
        m.hash = fmt::format("{}{}", tag, i);
        m.data = messages[i];
        out.push_back(std::move(m));
    }
    return out;
}

/// A Core with a mock network attached, ready to have a push observed.
struct PushableCore {
    TempCore core;
    MockNetwork* net = nullptr;

    PushableCore() {
        net = attach_mock_network(*core);
        net->current_node.remote_pubkey[0] = std::byte{0x01};
        net->sent_requests.clear();
    }

    core::Core* operator->() { return &*core; }

    const network::Request& only_request() {
        REQUIRE(net->sent_requests.size() == 1);
        return net->sent_requests[0].request;
    }

    /// The subrequests of the one request sent, bound to a local: ranging over
    /// `parse_json(body)["requests"]` directly would iterate a reference into a dead temporary.
    nlohmann::json subrequests() { return parse_json(*only_request().body)["requests"]; }

    /// Answers the outstanding request as the storage server would, one result per subrequest.
    /// `hashes` gives the hash each store returns; a nullopt is a store that failed.
    void answer(std::vector<std::optional<std::string>> hashes, int delete_code = 200) {
        auto results = nlohmann::json::array();
        for (auto& h : hashes) {
            if (h)
                results.push_back({{"code", 200}, {"body", {{"hash", *h}}}});
            else
                results.push_back({{"code", 503}, {"body", {{"reason", "nope"}}}});
        }
        auto subs = subrequests();
        while (results.size() < subs.size())
            results.push_back({{"code", delete_code}, {"body", nlohmann::json::object()}});

        auto callback = net->sent_requests[0].callback;
        net->sent_requests.clear();
        callback(true, false, 200, {}, nlohmann::json{{"results", results}}.dump());
    }
};

}  // namespace

TEST_CASE("Configs: a fresh account starts with its defaults", "[core][configs]") {
    TempCore c{};

    TestHelper::on_loop(*c, [&] {
        // Not blank: creating an account writes the defaults it should start life with, and note
        // to self starting hidden is one of them.  It is owed to the swarm precisely because it is
        // shared -- the account's other devices have to be told, or they would each invent their
        // own answer.
        CHECK(c->configs.user_profile().get_nts_priority() == -1);
        CHECK(c->configs.user_profile().get_min_message_version() == 2);
        CHECK(c->configs.needs_push());
        CHECK(stored_dumps(c) == 1);

        // Everything not defaulted is still empty.
        CHECK_FALSE(c->configs.user_profile().get_name());
        CHECK(c->configs.contacts().size() == 0);

        settle_new_account(c);
        CHECK_FALSE(c->configs.needs_push());
    });
}

TEST_CASE("Configs: enabling PFS/PQ raises the account's lowest version, once", "[core][configs]") {
    std::array<std::byte, 32> seed;
    random::fill(seed);
    TempCore c{core::predefined_seed{std::span<const std::byte, 32>{seed}}};

    // Restored, so not enabled, and nothing owed.
    CHECK_FALSE(c->pfs_enabled());
    TestHelper::on_loop(*c, [&] { REQUIRE_FALSE(c->configs.needs_push()); });

    // Enabled, which is a config change like any other, owed to the account's other devices.
    c->enable_pfs();
    CHECK(c->pfs_enabled());
    TestHelper::on_loop(*c, [&] {
        CHECK(c->configs.user_profile().get_min_message_version() == 2);
        CHECK(c->configs.needs_push());
    });

    // Again, and on an account already past it: nothing to do, and never a step down.
    c->enable_pfs();
    TestHelper::on_loop(*c, [&] { c->configs.user_profile().set_min_message_version(3); });
    c->enable_pfs();
    CHECK(c->pfs_enabled());
    TestHelper::on_loop(
            *c, [&] { CHECK(c->configs.user_profile().get_min_message_version() == 3); });
}

TEST_CASE("Configs: a namespace names exactly one config", "[core][configs]") {
    TempCore c{};

    auto base = [](auto& conf) { return static_cast<config::ConfigBase*>(&conf); };

    TestHelper::on_loop(*c, [&] {
        CHECK(c->configs.for_namespace(config::Namespace::UserProfile) ==
              base(c->configs.user_profile()));
        CHECK(c->configs.for_namespace(config::Namespace::Contacts) == base(c->configs.contacts()));
        CHECK(c->configs.for_namespace(config::Namespace::UserGroups) ==
              base(c->configs.user_groups()));
        CHECK(c->configs.for_namespace(config::Namespace::ConvoInfoVolatile) ==
              base(c->configs.convo_info_volatile()));

        // Local reports UserProfile's namespace, having none of its own, so the lookup must not be
        // answering from storage_namespace() -- if it were, one of these two would win
        // arbitrarily.
        CHECK(c->configs.for_namespace(config::Namespace::UserProfile) != base(c->configs.local()));

        // A namespace that holds no config at all.
        CHECK(c->configs.for_namespace(config::Namespace::Default) == nullptr);
    });
}

TEST_CASE("Configs: a dumped config survives a restart", "[core][configs]") {
    TempCore c{};

    TestHelper::on_loop(*c, [&] {
        c->configs.user_profile().set_name("Leia");
        c->configs.local().set_setting("some_toggle", true);
        c->configs.store_dumps();
    });

    // Outside the wrapper on purpose: this destroys the Core, and so the very loop the wrapper
    // would be running on.
    reopen(c);

    TestHelper::on_loop(*c, [&] {
        CHECK(c->configs.user_profile().get_name() == "Leia");
        CHECK(c->configs.local().get_setting("some_toggle") == true);

        // Reloading is not a change, so it owes no new dump.
        CHECK_FALSE(c->configs.user_profile().needs_dump());
    });
}

TEST_CASE("Configs: merging what another device pushed", "[core][configs]") {
    TempCore c{};

    TestHelper::on_loop(*c, [&] {
        auto pushed = push_from_another_device(c, "Padmé");
        auto incoming = as_swarm_messages(pushed);
        c->receive_messages(incoming, config::Namespace::UserProfile, true);

        CHECK(c->configs.user_profile().get_name() == "Padmé");

        // Adopting someone else's config outright is not a change of ours, so there is nothing to
        // push back -- but it is a change to what we hold, so it is written out.
        CHECK_FALSE(c->configs.needs_push());
        CHECK(stored_dumps(c) == 1);
    });

    reopen(c);
    TestHelper::on_loop(*c, [&] { CHECK(c->configs.user_profile().get_name() == "Padmé"); });
}

TEST_CASE("Configs: a local change survives merging a config that predates it", "[core][configs]") {
    TempCore c{};

    TestHelper::on_loop(*c, [&] {
        // Our own unpushed change participates in the merge as though it had been pushed, so a
        // config from another device that has never heard of it does not erase it.  This is what
        // makes "in our database but not in the config" mean deleted elsewhere rather than not yet
        // synced.
        c->configs.contacts().set(
                c->configs.contacts().get_or_construct("05" + std::string(64, 'a')));
        REQUIRE(c->configs.contacts().size() == 1);

        auto seed = c->globals.account_seed();
        config::Contacts theirs{seed.ed25519_secret(), std::nullopt};
        theirs.set(theirs.get_or_construct("05" + std::string(64, 'b')));
        auto [seqno, messages, obsolete] = theirs.push();

        auto incoming = as_swarm_messages(messages);
        c->receive_messages(incoming, config::Namespace::Contacts, true);

        // Both contacts are present, and the merged result is ours to push since only we hold it.
        CHECK(c->configs.contacts().size() == 2);
        CHECK(c->configs.needs_push());
    });
}

TEST_CASE("Configs: Local is never owed to a swarm", "[core][configs]") {
    TempCore c{};

    TestHelper::on_loop(*c, [&] {
        settle_new_account(c);

        c->configs.local().set_setting("a_toggle", true);

        // The change is real -- it is held, and dumped like any other config...
        CHECK(c->configs.local().get_setting("a_toggle") == true);
        CHECK(c->configs.local().needs_dump());

        // ...but Local has no swarm, so it can never make the account owe a push.  It declines on
        // its own account (needs_push() is overridden to false) and is also left out of the
        // pushable set, so neither alone is load-bearing.
        CHECK_FALSE(c->configs.local().needs_push());
        CHECK_FALSE(c->configs.needs_push());
    });
}

TEST_CASE("Configs: a batch holds back the dump", "[core][configs]") {
    TempCore c{};

    TestHelper::on_loop(*c, [&] {
        settle_new_account(c);

        // Contacts rather than UserProfile, because a new account has already dumped the latter to
        // record its defaults: counting rows only shows the deferral for a config that has none
        // yet.
        auto pushed = contacts_from_another_device(c, "05" + std::string(64, 'a'));
        auto profile = as_swarm_messages(pushed);
        REQUIRE(stored_dumps(c) == 1);

        {
            auto held = c->configs.batch();
            c->receive_messages(profile, config::Namespace::Contacts, true);

            // The merge landed, but writing it out is deferred: nothing reads a half-processed
            // batch.
            CHECK(c->configs.contacts().size() == 1);
            CHECK(stored_dumps(c) == 1);
        }

        CHECK(stored_dumps(c) == 2);
    });
}

namespace {

/// Records what configs_changed reported, one entry per firing.
struct ChangeWatcher {
    std::vector<std::vector<config::Namespace>> reported;

    core::callbacks callbacks() {
        core::callbacks cbs;
        cbs.configs_changed = [this](std::span<const config::Namespace> changed) {
            reported.emplace_back(changed.begin(), changed.end());
        };
        return cbs;
    }
};

}  // namespace

TEST_CASE("Configs: a merge that changed something is reported", "[core][configs][notify]") {
    ChangeWatcher w;
    TempCore c{w.callbacks()};

    TestHelper::on_loop(*c, [&] {
        auto pushed = push_from_another_device(c, "Padmé");
        auto incoming = as_swarm_messages(pushed);
        c->receive_messages(incoming, config::Namespace::UserProfile, true);

        REQUIRE(w.reported.size() == 1);
        CHECK(w.reported[0] == std::vector{config::Namespace::UserProfile});

        // The same message again changes nothing, and nothing is what gets reported -- otherwise
        // every poll that re-fetched the same config would send the application round the houses
        // again.
        c->receive_messages(incoming, config::Namespace::UserProfile, true);
        CHECK(w.reported.size() == 1);
    });
}

TEST_CASE("Configs: one batch reports everything it changed, once", "[core][configs][notify]") {
    ChangeWatcher w;
    TempCore c{w.callbacks()};

    TestHelper::on_loop(*c, [&] {
        auto profile_pushed = push_from_another_device(c, "Leia");
        auto profile = as_swarm_messages(profile_pushed);
        auto contacts_pushed = contacts_from_another_device(c, "05" + std::string(64, 'a'));
        auto contacts = as_swarm_messages(contacts_pushed);

        {
            auto held = c->configs.batch();
            c->receive_messages(profile, config::Namespace::UserProfile, true);
            c->receive_messages(contacts, config::Namespace::Contacts, true);
        }

        // One notification carrying both, not one per config: a poll can deliver all four, and
        // telling the application about each in turn shows it a half-applied state.
        REQUIRE(w.reported.size() == 1);
        auto changed = w.reported[0];
        std::ranges::sort(changed);
        CHECK(changed == std::vector{config::Namespace::UserProfile, config::Namespace::Contacts});
    });
}

TEST_CASE("Configs: a conflicting merge at our own seqno is reported", "[core][configs][notify]") {
    ChangeWatcher w;
    TempCore c{w.callbacks()};

    // A local change of our own, at some seqno.
    //
    // Wrapped in pieces rather than all at once: GENERATE and SECTION below have to stay at test
    // scope, since Catch2 re-runs the case for each of them.
    auto our_seqno = TestHelper::on_loop(*c, [&] {
        c->configs.contacts().set(
                c->configs.contacts().get_or_construct("05" + std::string(64, 'a')));
        return c->configs.contacts().seqno();
    });

    // Our config can be in either of two states here, and _merge takes a different path for each:
    // Dirty means the change has not been serialised into a message at all, so nothing else can
    // have built on it; Waiting means a message exists and has gone to the swarm, so another device
    // may well have seen it.  A generator rather than sections, so that this composes with the
    // sections below into all four combinations rather than replacing them.
    const bool already_a_message = GENERATE(false, true);
    CAPTURE(already_a_message);
    TestHelper::on_loop(*c, [&] {
        if (already_a_message)
            c->configs.contacts().push();
        REQUIRE(c->configs.contacts().is_dirty() == !already_a_message);
        REQUIRE(c->configs.contacts().seqno() == our_seqno);
    });

    // Another device changed things from the same starting point, so its push carries the *same*
    // seqno as ours with different contents.  Both shapes of disagreement are worth covering: one
    // where neither side's data contains the other, and one where theirs contains ours outright --
    // the second being the case where "adopt the superset" would leave the seqno alone if the
    // superset were chosen on data rather than on the diff chain.
    std::vector<std::string> theirs_has;
    size_t expected_contacts = 0;

    SECTION("neither side's changes contain the other's") {
        theirs_has = {"05" + std::string(64, 'b')};
        expected_contacts = 2;
    }
    SECTION("theirs contains ours and more") {
        theirs_has = {"05" + std::string(64, 'a'), "05" + std::string(64, 'b')};
        expected_contacts = 2;
    }

    TestHelper::on_loop(*c, [&] {
        std::vector<std::vector<std::byte>> pushed;
        {
            auto seed = c->globals.account_seed();
            config::Contacts theirs{seed.ed25519_secret(), std::nullopt};
            for (const auto& id : theirs_has)
                theirs.set(theirs.get_or_construct(id));
            REQUIRE(theirs.seqno() == our_seqno);
            auto [seqno, messages, obsolete] = theirs.push();
            pushed = std::move(messages);
        }
        auto incoming = as_swarm_messages(pushed);

        c->receive_messages(incoming, config::Namespace::Contacts, true);

        // The data changed, so the application has to be told.  The risk being checked is that
        // resolving two same-numbered configs might leave the seqno where it was, which a seqno
        // comparison would then miss.  It does not: two distinct messages at one seqno are a
        // conflict whatever their contents, and a conflict resolves to one past the highest.
        CHECK(c->configs.contacts().size() == expected_contacts);
        CHECK(c->configs.contacts().seqno() > our_seqno);
        REQUIRE(w.reported.size() == 1);
        CHECK(w.reported[0] == std::vector{config::Namespace::Contacts});
    });
}

TEST_CASE("Configs: merging a change identical to our own", "[core][configs][notify]") {
    ChangeWatcher w;
    TempCore c{w.callbacks()};

    auto contact = "05" + std::string(64, 'a');

    TestHelper::on_loop(*c, [&] {
        c->configs.contacts().set(c->configs.contacts().get_or_construct(contact));

        // Another device made the very same change from the same starting point.
        auto pushed = contacts_from_another_device(c, contact);
        auto incoming = as_swarm_messages(pushed);
        c->receive_messages(incoming, config::Namespace::Contacts, true);

        // Nothing is lost: we already held exactly what arrived.
        CHECK(c->configs.contacts().size() == 1);
        CHECK(c->configs.contacts().get(contact).has_value());

        // And nothing is owed: agreeing with another device settles clean against that device's
        // message rather than leaving us dirty, so it costs no push carrying no changes.
        CHECK_FALSE(c->configs.contacts().needs_push());
    });

    // The seqno is deliberately not asserted.  It currently advances even though the data did not,
    // because merging while dirty builds a MutableConfigMessage and that constructor increments
    // unconditionally (see its comment in config.hpp) -- and the unwind for that spurious increment
    // in _merge only applies when the winning config is our own, which here it is not.  Pinning
    // that down would be encoding an accident.

    // Deliberately not asserted: whether this reported to the application.  It currently does,
    // because the seqno moved even though the data did not, so the reconciling layer does a walk
    // that finds nothing to do.  That is the safe direction to be wrong in and is idempotent by
    // design -- and if the merge ever learns to recognise an identical config and leave the seqno
    // alone, this would stop reporting with no change needed here.  What must never happen is the
    // reverse, and the case above covers that.
}

TEST_CASE("Configs: an adopted duplicate leaves no gap behind", "[core][configs][notify]") {
    ChangeWatcher w;
    TempCore c{w.callbacks()};

    TestHelper::on_loop(*c, [&] {
        auto seed = c->globals.account_seed();
        config::Contacts them{seed.ed25519_secret(), std::nullopt};

        auto a = "05" + std::string(64, 'a');
        auto b = "05" + std::string(64, 'b');

        // Both devices make the same change from the same starting point.
        c->configs.contacts().set(c->configs.contacts().get_or_construct(a));
        them.set(them.get_or_construct(a));
        REQUIRE(c->configs.contacts().seqno() == them.seqno());
        auto agreed_seqno = them.seqno();

        {
            auto [seqno, messages, obsolete] = them.push();
            them.confirm_pushed(seqno, {"theirs1"});
            auto incoming = as_swarm_messages(messages, "theirs");
            c->receive_messages(incoming, config::Namespace::Contacts, true);
        }

        // Adopting their identical config leaves us on the seqno the swarm actually holds, rather
        // than one past it: no number is consumed that no stored message occupies.
        CHECK(c->configs.contacts().seqno() == agreed_seqno);
        CHECK_FALSE(c->configs.contacts().needs_push());

        // So the other device's further change of its own lands on the next number up, with
        // nothing of ours already sitting on it.
        them.set(them.get_or_construct(b));
        REQUIRE(them.seqno() == agreed_seqno + 1);

        {
            auto [seqno, messages, obsolete] = them.push();
            auto incoming = as_swarm_messages(messages, "theirs2-");
            c->receive_messages(incoming, config::Namespace::Contacts, true);
        }

        // Their change arrives intact and ours is still there.
        CHECK(c->configs.contacts().size() == 2);
        CHECK(c->configs.contacts().get(a).has_value());
        CHECK(c->configs.contacts().get(b).has_value());

        // ...and it is adopted at its own seqno rather than resolving as a conflict one past both,
        // so we are left neither dirty nor owing a push for a change that was never ours.  One
        // real change, one seqno -- which is also what keeps the "within N" conflict window from
        // spending two of its five carrying a single change.
        CHECK(c->configs.contacts().seqno() == agreed_seqno + 1);
        CHECK_FALSE(c->configs.contacts().needs_push());
    });
}

TEST_CASE("Configs: a local change is not reported back", "[core][configs][notify]") {
    ChangeWatcher w;
    TempCore c{w.callbacks()};

    TestHelper::on_loop(*c, [&] {
        {
            auto held = c->configs.batch();
            c->configs.user_profile().set_name("Leia");
        }

        // The application made this change; being told about it would be news to nobody, and
        // would invite it to reconcile its own write back over itself.
        CHECK(w.reported.empty());
    });
}

TEST_CASE("Configs: a change goes out as one signed sequence", "[core][configs][push]") {
    PushableCore c;

    TestHelper::on_loop(*c.core, [&] {
        c->configs.user_profile().set_name("Leia");
        // Local changes too: it must not appear in what goes out.
        c->configs.local().set_setting("a_toggle", true);
        c->configs.push_now();

        CHECK(c.only_request().endpoint == "sequence");

        auto subs = c.subrequests();
        REQUIRE(subs.size() == 1);
        CHECK(subs[0]["method"] == "store");
        CHECK(subs[0]["params"]["namespace"] == 2);
        CHECK(subs[0]["params"]["ttl"] == std::chrono::milliseconds{30 * 24h}.count());
        // Config namespaces are owner-write, so the store carries a signature and the key to
        // check it.
        CHECK(subs[0]["params"].contains("signature"));
        CHECK(subs[0]["params"].contains("pubkey_ed25519"));

        // Nothing is obsolete on a first push, so there is nothing to delete.
        CHECK_FALSE(subs[0].contains("delete"));
    });
}

TEST_CASE("Configs: two dirty configs share one request", "[core][configs][push]") {
    PushableCore c;

    TestHelper::on_loop(*c.core, [&] {
        c->configs.user_profile().set_name("Leia");
        c->configs.contacts().set(
                c->configs.contacts().get_or_construct("05" + std::string(64, 'a')));
        c->configs.push_now();

        auto subs = c.subrequests();
        REQUIRE(subs.size() == 2);
        std::vector<int> namespaces{subs[0]["params"]["namespace"], subs[1]["params"]["namespace"]};
        std::ranges::sort(namespaces);
        CHECK(namespaces == std::vector<int>{2, 3});
    });
}

TEST_CASE("Configs: a stored push stops being owed", "[core][configs][push]") {
    PushableCore c;

    TestHelper::on_loop(*c.core, [&] {
        c->configs.user_profile().set_name("Leia");
        c->configs.push_now();

        // Handing it to the swarm is not the same as it having arrived, so it is still owed until
        // the store is confirmed -- otherwise a failed push would be forgotten.
        CHECK(c->configs.needs_push());

        c.answer({"hash1"});
        CHECK_FALSE(c->configs.needs_push());
    });
}

TEST_CASE("Configs: a rejected store leaves the config dirty", "[core][configs][push]") {
    PushableCore c;

    TestHelper::on_loop(*c.core, [&] {
        c->configs.user_profile().set_name("Leia");
        c->configs.push_now();
        c.answer({std::nullopt});

        // The change is still ours to deliver, and pushing again offers it again.
        CHECK(c->configs.needs_push());
        c->configs.push_now();
        CHECK(c.subrequests().size() == 1);
    });
}

TEST_CASE("Configs: the next push deletes what it replaces", "[core][configs][push]") {
    PushableCore c;

    TestHelper::on_loop(*c.core, [&] {
        c->configs.user_profile().set_name("Leia");
        c->configs.push_now();
        c.answer({"hash1"});

        c->configs.user_profile().set_name("Padmé");
        c->configs.push_now();

        auto subs = c.subrequests();
        REQUIRE(subs.size() == 2);
        CHECK(subs[0]["method"] == "store");

        // The delete goes last: a sequence stops at its first failure, so nothing is removed
        // before what replaces it has been stored.
        CHECK(subs[1]["method"] == "delete");
        CHECK(subs[1]["params"]["messages"] == nlohmann::json::array({"hash1"}));
        CHECK(subs[1]["params"].contains("signature"));
    });
}

TEST_CASE("Configs: a change schedules a push rather than sending one", "[core][configs][push]") {
    PushableCore c;

    TestHelper::on_loop(*c.core, [&] {
        {
            auto held = c->configs.batch();
            c->configs.user_profile().set_name("Leia");
        }

        // Releasing the batch is what notices the change; it schedules rather than sending, so a
        // run of changes coalesces into one request.
        CHECK(TestHelper::push_scheduled(c->configs));
        CHECK(c.net->sent_requests.empty());
    });
}

TEST_CASE(
        "Configs: a change nobody announced is still written and pushed", "[core][configs][push]") {
    TempCore c;

    // An account's own creation writes the defaults, which is a change like any other.  Let that
    // reach disk first, so the only thing left to dump is what this test does.
    TestHelper::drain(*c);

    // All in one job, because nothing may run between clearing the pending push and making the
    // change: with no network attached the defaults can never be confirmed, so `needs_push()` stays
    // true and any settle in between would arm the timer again.
    TestHelper::on_loop(*c, [&] {
        TestHelper::backdate_push_state(c->configs, 3s, 4s);
        TestHelper::push_if_due(c->configs);
        REQUIRE_FALSE(TestHelper::push_scheduled(c->configs));
        REQUIRE_FALSE(c->configs.user_profile().needs_dump());

        // A bare change: no batch around it, nothing merged, nothing polling.  That is the shape
        // every Client setter makes, and it used to reach neither disk nor the swarm -- the only
        // thing that armed the timer was a caller announcing a run of changes was over, and no
        // local caller ever did.  It survived because a poll held a batch every few seconds and
        // swept it up.
        c->configs.user_profile().set_name("Leia");

        // Still nothing: the settle is queued rather than run, because this job is still holding
        // the reference it changed through and the config is mid-change until it returns.
        CHECK(c->configs.user_profile().needs_dump());
        CHECK_FALSE(TestHelper::push_scheduled(c->configs));
    });

    // One turn of the loop, with nothing else prompting it.
    TestHelper::drain(*c);

    TestHelper::on_loop(*c, [&] {
        CHECK_FALSE(c->configs.user_profile().needs_dump());
        CHECK(TestHelper::push_scheduled(c->configs));
    });
}

TEST_CASE("Configs: a locally made change survives a restart", "[core][configs]") {
    TempCore c;

    TestHelper::on_loop(*c, [&] { c->configs.user_profile().set_name("Leia"); });
    TestHelper::drain(*c);

    reopen(c);

    CHECK(TestHelper::on_loop(*c, [&] {
              return std::string{c->configs.user_profile().get_name().value_or("")};
          }) == "Leia");
}

TEST_CASE(
        "Configs: changes in quick succession make one push, not several",
        "[core][configs][push]") {
    PushableCore c;
    c->configs.push_debounce = 2s;
    c->configs.push_max_delay = 10s;

    // Three changes, each in its own job, the way three calls from an application arrive.  Each one
    // settles separately; what must not happen is three pushes, or three timers racing each other.
    for (std::string_view name : {"Leia", "Leia Organa", "General Organa"})
        TestHelper::on_loop(*c.core, [&] { c->configs.user_profile().set_name(name); });
    TestHelper::drain(*c.core);

    TestHelper::on_loop(*c.core, [&] {
        REQUIRE(TestHelper::push_scheduled(c->configs));
        REQUIRE(c.net->sent_requests.empty());
    });

    SECTION("a further change pushes the deadline out again") {
        TestHelper::on_loop(*c.core, [&] {
            // Quiet long enough that it would go out right now -- and then touched again, which is
            // what has to move the deadline.  Backdated past the threshold deliberately: at 1.9s it
            // would be held back whether or not the change reset anything, and the test would pass
            // without testing.
            TestHelper::backdate_push_state(c->configs, 3s, 4s);
            c->configs.user_profile().set_name("Leia Skywalker");
        });
        TestHelper::drain(*c.core);

        TestHelper::on_loop(*c.core, [&] {
            TestHelper::push_if_due(c->configs);
            CHECK(c.net->sent_requests.empty());
            CHECK(TestHelper::push_scheduled(c->configs));
        });
    }

    SECTION("quiet for long enough sends one request carrying all of them") {
        TestHelper::on_loop(*c.core, [&] {
            TestHelper::backdate_push_state(c->configs, 3s, 4s);
            TestHelper::push_if_due(c->configs);
            CHECK(c.net->sent_requests.size() == 1);
            CHECK(c->configs.user_profile().get_name() == "General Organa");
        });
    }
}

TEST_CASE("Configs: the debounce waits for quiet, up to a limit", "[core][configs][push]") {
    PushableCore c;
    c->configs.push_debounce = 2s;
    c->configs.push_max_delay = 10s;

    // Wrapped per section rather than all at once: Catch2 re-runs the case for each SECTION, so
    // they have to stay at test scope.
    TestHelper::on_loop(*c.core, [&] {
        {
            auto held = c->configs.batch();
            c->configs.user_profile().set_name("Leia");
        }
        REQUIRE(TestHelper::push_scheduled(c->configs));
    });

    SECTION("changes still arriving hold it back") {
        TestHelper::on_loop(*c.core, [&] {
            TestHelper::backdate_push_state(c->configs, 500ms, 1s);
            TestHelper::push_if_due(c->configs);
            CHECK(c.net->sent_requests.empty());
            CHECK(TestHelper::push_scheduled(c->configs));
        });
    }

    SECTION("quiet for long enough sends it") {
        TestHelper::on_loop(*c.core, [&] {
            TestHelper::backdate_push_state(c->configs, 3s, 4s);
            TestHelper::push_if_due(c->configs);
            CHECK(c.net->sent_requests.size() == 1);
            CHECK_FALSE(TestHelper::push_scheduled(c->configs));
        });
    }

    SECTION("a steady trickle cannot defer it past the cap") {
        TestHelper::on_loop(*c.core, [&] {
            // Never quiet -- the last change was a moment ago -- but the burst began long enough
            // ago that waiting for quiet would mean waiting indefinitely.
            TestHelper::backdate_push_state(c->configs, 100ms, 11s);
            TestHelper::push_if_due(c->configs);
            CHECK(c.net->sent_requests.size() == 1);
        });
    }
}

TEST_CASE("Configs: pushing can be switched off entirely", "[core][configs][push]") {
    PushableCore c;
    c->configs.push_enabled = false;

    TestHelper::on_loop(*c.core, [&] {
        c->configs.user_profile().set_name("Leia");
        c->configs.push_now();

        // Nothing goes out...
        CHECK(c.net->sent_requests.empty());

        // ...and nothing pretends it did: the change is still held and still owed, so the state
        // reads as unpublished rather than as settled.
        CHECK(c->configs.user_profile().get_name() == "Leia");
        CHECK(c->configs.needs_push());

        // Switching it back on lets everything accumulated since go out together.
        c->configs.push_enabled = true;
        c->configs.push_now();
        CHECK(c.net->sent_requests.size() == 1);
    });
}

TEST_CASE("Configs: a push already in flight is not duplicated", "[core][configs][push]") {
    PushableCore c;

    TestHelper::on_loop(*c.core, [&] {
        c->configs.user_profile().set_name("Leia");
        c->configs.push_now();
        REQUIRE(c.net->sent_requests.size() == 1);

        // A second change while the first is out must not race it onto the wire; the completion
        // picks it up instead.
        c->configs.contacts().set(
                c->configs.contacts().get_or_construct("05" + std::string(64, 'a')));
        c->configs.push_now();
        CHECK(c.net->sent_requests.size() == 1);
    });
}
