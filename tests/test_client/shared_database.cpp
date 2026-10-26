// Two Clients on one database, as an app and its notification or share extension are: each a Core
// with its own connection pool and its own configs in memory, sharing nothing but the file.

#include <session/config/user_groups.hpp>

#include "config_helpers.hpp"

using namespace client_test;

namespace {

std::string profile_name(Client& c) {
    return TestHelper::on_loop(c.core, [&] {
        return std::string{c.core.configs.user_profile().get_name().value_or("")};
    });
}

const std::string contact_x = "05" + std::string(64, 'a');
const std::string contact_y = "05" + std::string(64, 'b');

template <typename F>
auto on(Client& c, F&& f) {
    return TestHelper::on_loop(c.core, std::forward<F>(f));
}

// Changes a config the way the application would, then writes the dumps a settle would write, so
// that each step lands before the other Client acts.
template <typename F>
void change(Client& c, F&& f) {
    on(c, std::forward<F>(f));
    on(c, [&] { c.core.configs.store_dumps(); });
}

// Through the Client rather than the config: the Client rebuilds a contact's config entry from its
// database row, so an entry edited behind its back is overwritten.
void set_nickname(Client& c, const std::string& sid, std::string_view nickname) {
    c.dm(dm_from_hex(sid), await)->set_nickname(nickname, await);
    on(c, [&] { c.core.configs.store_dumps(); });
}

// Two contacts with nicknames, then every account config pushed and confirmed, so that what follows
// starts from a clean, published state rather than the unpushed defaults of a new account.
void published_baseline(Client& c) {
    for (auto& sid : {contact_x, contact_y}) {
        c.open_dm(dm_from_hex(sid), await);
        set_nickname(c, sid, sid == contact_x ? "X0" : "Y0");
    }
    on(c, [&] {
        auto& cf = c.core.configs;
        for (config::ConfigBase* conf :
             {static_cast<config::ConfigBase*>(&cf.user_profile()),
              static_cast<config::ConfigBase*>(&cf.contacts()),
              static_cast<config::ConfigBase*>(&cf.convo_info_volatile()),
              static_cast<config::ConfigBase*>(&cf.user_groups())}) {
            auto [seqno, msgs, obsolete] = conf->push();
            conf->confirm_pushed(seqno, {"base-" + std::string{conf->encryption_domain()}});
        }
        cf.store_dumps();
    });
}

struct ProfileView {
    std::string name, pic;
    bool needs_push;
    int priority;
};

ProfileView profile(Client& c) {
    return on(c, [&] {
        const auto& p = c.core.configs.user_profile();
        return ProfileView{
                std::string{p.get_name().value_or("")},
                p.get_profile_pic().url,
                p.needs_push(),
                p.get_nts_priority()};
    });
}

std::string nickname(Client& c, std::string_view sid) {
    return on(c, [&] {
        auto entry = c.core.configs.contacts().get(sid);
        return entry ? entry->nickname : std::string{"(no contact)"};
    });
}

// The stored dump itself: a Client opened afterwards rebuilds contact entries from its rows at
// start-up, and so could report a change the dump has lost.
std::string stored_nickname(Client& c, const std::string& sid) {
    return on(c, [&] {
        std::vector<std::byte> dump;
        for (auto data : c.core.database().conn().prepared_results<sqlite::blob>(
                     "SELECT data FROM config_dumps WHERE pubkey = ? AND type = 'Contacts'",
                     c.core.globals.session_id()))
            dump.assign(data.begin(), data.end());
        auto seed = c.core.globals.account_seed();
        config::Contacts contacts{seed.ed25519_secret(), dump};
        auto entry = contacts.get(sid);
        return entry ? entry->nickname : std::string{"(no contact)"};
    });
}

const std::vector<std::byte> pic_key(32, std::byte{0x42});

}  // namespace

TEST_CASE(
        "Shared database: changes the extension made while the app was suspended reach the app",
        "[client][configs][shared-db]") {
    TempClient app;
    app->set_display_name("Before", await);
    auto from_other = profile_from_another_device(
            *app, [](config::UserProfile& p) { p.set_name("Renamed elsewhere"); });

    // A rename merged from another device's push, or a change the extension made itself and could
    // not push: in the second case its dump is the only copy.
    bool merged = GENERATE(true, false);
    REQUIRE(app->suspend_storage(2s).closed);
    {
        auto ext = std::make_unique<Client>(app.path);
        if (merged)
            merge_profile(*ext, from_other);
        else
            ext->set_display_name("Changed in extension", await);
        on(*ext, [&] { ext->core.configs.store_dumps(); });
        REQUIRE(ext->suspend_storage(2s).closed);
    }
    app->resume_storage();

    auto expect = merged ? "Renamed elsewhere" : "Changed in extension";
    CHECK(profile_name(*app) == expect);

    // And a change of the app's own afterwards keeps it.
    change(*app, [&] { app->core.configs.user_profile().set_nts_priority(3); });
    app.reopen();
    CHECK(profile_name(*app) == expect);
    CHECK(profile(*app).priority == 3);
    if (!merged)
        // Still owed to the swarm, so the app's next push carries the extension's change.
        CHECK(profile(*app).needs_push);
}

TEST_CASE(
        "Shared database: a stale copy written by the app keeps what the extension merged",
        "[client][configs][shared-db]") {
    // No suspend and resume to reload it: the app writes the copy it loaded before.
    TempClient app;
    app->set_display_name("Before", await);
    auto from_other = profile_from_another_device(
            *app, [](config::UserProfile& p) { p.set_name("Renamed elsewhere"); });
    {
        auto ext = std::make_unique<Client>(app.path);
        merge_profile(*ext, from_other);
        on(*ext, [&] { ext->core.configs.store_dumps(); });
    }
    CHECK(profile_name(*app) == "Before");

    change(*app, [&] { app->core.configs.user_profile().set_nts_priority(3); });
    app.reopen();
    CHECK(profile_name(*app) == "Renamed elsewhere");
}

TEST_CASE(
        "Shared database: two live Clients change different fields of one config",
        "[client][configs][shared-db]") {
    TempClient a;
    published_baseline(*a);
    auto b = std::make_unique<Client>(a.path);

    SECTION("UserProfile: A's name, then B's picture") {
        change(*a, [&] { a->core.configs.user_profile().set_name("Name from A"); });
        change(*b,
               [&] { b->core.configs.user_profile().set_profile_pic("http://b/pic", pic_key); });
        CHECK(profile(*b).name == "Name from A");
        CHECK(profile(*b).pic == "http://b/pic");
        {
            auto fresh = std::make_unique<Client>(a.path);
            CHECK(profile(*fresh).name == "Name from A");
            CHECK(profile(*fresh).pic == "http://b/pic");
        }

        // A's copy learns of B's change when A next writes that config.
        change(*a, [&] { a->core.configs.user_profile().set_nts_priority(2); });
        CHECK(profile(*a).name == "Name from A");
        CHECK(profile(*a).pic == "http://b/pic");
        auto fresh = std::make_unique<Client>(a.path);
        CHECK(profile(*fresh).pic == "http://b/pic");
    }

    SECTION("Contacts: A's nickname for X, then B's for Y") {
        set_nickname(*a, contact_x, "X by A");
        set_nickname(*b, contact_y, "Y by B");
        CHECK(nickname(*b, contact_x) == "X by A");
        CHECK(nickname(*b, contact_y) == "Y by B");
        CHECK(stored_nickname(*a, contact_x) == "X by A");
        CHECK(stored_nickname(*a, contact_y) == "Y by B");
    }
}

TEST_CASE(
        "Shared database: two live Clients change different configs",
        "[client][configs][shared-db]") {
    TempClient a;
    published_baseline(*a);
    auto b = std::make_unique<Client>(a.path);

    change(*a, [&] { a->core.configs.user_profile().set_name("Name from A"); });
    set_nickname(*b, contact_x, "X by B");
    CHECK(stored_nickname(*a, contact_x) == "X by B");
    auto fresh = std::make_unique<Client>(a.path);
    CHECK(profile(*fresh).name == "Name from A");
    CHECK(nickname(*fresh, contact_x) == "X by B");
}

TEST_CASE(
        "Shared database: two live Clients change the same field", "[client][configs][shared-db]") {
    TempClient a;
    published_baseline(*a);
    auto b = std::make_unique<Client>(a.path);

    // Same-seqno changes to one field resolve by hash order, not by which was written last, so
    // either name may win -- but every reader agrees, and nothing else is lost.
    change(*a, [&] { a->core.configs.user_profile().set_name("Name from A"); });
    change(*b, [&] { b->core.configs.user_profile().set_name("Name from B"); });
    auto seen_b = profile(*b).name;
    CHECK((seen_b == "Name from A" || seen_b == "Name from B"));
    {
        auto fresh = std::make_unique<Client>(a.path);
        CHECK(profile(*fresh).name == seen_b);
    }

    change(*a, [&] { a->core.configs.user_profile().set_nts_priority(2); });
    {
        auto fresh = std::make_unique<Client>(a.path);
        CHECK(profile(*fresh).name == profile(*a).name);
    }

    change(*b, [&] { b->core.configs.user_profile().set_profile_pic("http://b/pic", pic_key); });
    auto fresh = std::make_unique<Client>(a.path);
    CHECK(profile(*fresh).name == profile(*b).name);
    CHECK(profile(*fresh).pic == "http://b/pic");
    CHECK(profile(*fresh).priority == 2);
    CHECK(profile(*fresh).needs_push);
}

TEST_CASE(
        "Shared database: an unpushed change survives the other live Client's write",
        "[client][configs][shared-db]") {
    TempClient a;
    published_baseline(*a);
    auto b = std::make_unique<Client>(a.path);

    SECTION("B writes a change of its own") {
        change(*a, [&] { a->core.configs.user_profile().set_name("Name from A"); });
        change(*b,
               [&] { b->core.configs.user_profile().set_profile_pic("http://b/pic", pic_key); });
        auto fresh = std::make_unique<Client>(a.path);
        CHECK(profile(*fresh).name == "Name from A");
        CHECK(profile(*fresh).pic == "http://b/pic");
        CHECK(profile(*fresh).needs_push);
        CHECK(profile(*b).needs_push);
    }

    SECTION("B's push is confirmed after A wrote") {
        // B's change goes out, and A writes its own while B's push is in flight.
        auto pushed = on(*b, [&] {
            auto& p = b->core.configs.user_profile();
            p.set_profile_pic("http://b/pic", pic_key);
            auto [seqno, msgs, obsolete] = p.push();
            b->core.configs.store_dumps();
            return seqno;
        });
        change(*a, [&] { a->core.configs.user_profile().set_name("Name from A"); });

        // The confirmation leaves B clean, and writing that state must not erase A's change.
        change(*b, [&] { b->core.configs.user_profile().confirm_pushed(pushed, {"b-pushed"}); });
        CHECK(profile(*b).name == "Name from A");
        CHECK(profile(*b).needs_push);
        auto fresh = std::make_unique<Client>(a.path);
        CHECK(profile(*fresh).name == "Name from A");
        CHECK(profile(*fresh).pic == "http://b/pic");
        CHECK(profile(*fresh).needs_push);
    }
}
