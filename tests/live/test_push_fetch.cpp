#include <fmt/format.h>
#include <oxenc/base64.h>
#include <oxenc/bt_producer.h>

#include <catch2/catch_test_macros.hpp>
#include <future>
#include <session/client.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/push/notifications.hpp>
#include <session/session_encrypt.hpp>

#include "live_utils.hpp"

using namespace session;
using namespace session::client;
using namespace std::literals;

namespace {

/// A directory of its own for a Client and its network's caches, removed afterwards.
struct Scratch {
    std::filesystem::path dir = std::filesystem::temp_directory_path() /
                                fmt::format("{}", random::unique_id("live_push", 7));
    Scratch() { std::filesystem::create_directories(dir); }
    ~Scratch() {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

/// A testnet network built the way a notification extension builds one.
std::unique_ptr<network::Network> one_shot_network(std::filesystem::path cache_dir) {
    namespace opt = network::opt;
    std::vector<opt::any> net_opts{
            opt::netid::testnet(),
            live_router_mode,
            opt::cache_directory{std::move(cache_dir)},
            opt::one_shot{}};
    return std::make_unique<network::Network>(net_opts);
}

/// The push the push server would send for `hash` in our own swarm, too large to carry its message,
/// sealed with `key` as the server seals it.
std::string too_large_push(
        const std::string& swarm_hex, const std::string& hash, size_t length, const b32& key) {
    nlohmann::json meta{
            {"@", swarm_hex},
            {"#", hash},
            {"n", 0},
            {"t", epoch_ms(clock_now_ms())},
            {"z", epoch_ms(clock_now_ms() + 14 * 24h)},
            {"l", length},
            {"B", true}};
    oxenc::bt_list_producer l;
    l.append(meta.dump());
    std::string padded{l.view()};
    if (auto over = padded.size() % 256)
        padded.append(256 - over, '\0');
    return oxenc::to_base64(encrypt_xchacha20(to_span(padded), key));
}

bool wait_until_sent(Client& c, int64_t id, std::chrono::seconds limit) {
    auto deadline = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < deadline) {
        auto msg = c.message(id, await);
        REQUIRE(msg);
        if (msg->send_state == SendState::sent && msg->sync_send_state == SendState::sent)
            return true;
        if (msg->send_state == SendState::failed || msg->send_state == SendState::unsendable)
            return false;
        std::this_thread::sleep_for(200ms);
    }
    return false;
}

}  // namespace

TEST_CASE("Live: a one-shot Client handles a push too large to carry its message", "[live][push]") {
    // The sending device: an ordinary Client, which leaves a copy of what it sends in its own swarm
    // for its other devices -- under a hash it records.
    Scratch app_dir;
    auto app = std::make_unique<Client>(app_dir.dir / "client.db");
    app->core.set_network(make_testnet_network(app_dir.dir / "netcache"));

    b32 peer_pk;
    b64 peer_sk;
    ed25519::keypair(peer_pk, peer_sk);
    b33 peer;
    ed25519::pk_to_session_id(peer, peer_pk);

    // Over the push server's 2,500-byte limit once encrypted.
    std::string body(4000, 'x');
    auto id = app->send_message(ConversationId::dm(peer), {.body = body}, await);
    REQUIRE(wait_until_sent(*app, id, 120s));
    auto sent = app->message(id, await);
    REQUIRE(sent);
    REQUIRE(sent->hash);
    auto hash = *sent->hash;

    // Another device of the same account, as its notification extension opens: a one-shot Client
    // on its own database, with a one-shot network, which has never seen the message.
    Scratch ext_dir;
    auto seed = app->core.globals.account_seed();
    auto ext = std::make_unique<Client>(
            ext_dir.dir / "client.db", core::predefined_seed{seed.seed()}, core::one_shot{});
    ext->core.set_network(one_shot_network(ext_dir.dir / "netcache"));
    push::Notifications notifications{*ext};
    REQUIRE_FALSE(ext->message_by_hash(hash, await));

    auto started = std::chrono::steady_clock::now();
    std::promise<Expected<push::HandledPush>> done;
    notifications.handle(
            too_large_push(
                    ext->core.globals.session_id_hex(),
                    hash,
                    body.size(),
                    notifications.encryption_key()),
            30s,
            [&](auto r) { done.set_value(std::move(r)); });
    auto result = done.get_future();
    REQUIRE(result.wait_for(40s) == std::future_status::ready);
    auto handled = result.get();
    auto took = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started);
    UNSCOPED_INFO("handled in " << took.count() << " ms");

    REQUIRE(handled.has_value());
    CHECK(handled->outcome == push::Handled::fetched);
    REQUIRE(handled->message);
    CHECK(handled->message->body == body);
    CHECK(handled->message->outgoing);
    oxen::log::warning(
            oxen::log::Cat("live-test"),
            "push fetch: {} in {} ms",
            handled->outcome == push::Handled::fetched ? "fetched" : "NOT fetched",
            took.count());

    // Our own message: nothing to show.
    CHECK_FALSE(notifications.decide(*handled, "You"));
}
