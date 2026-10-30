#include <oxenc/hex.h>

#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <session/client/error_codes.hpp>
#include <session/clock.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/network/session_network.hpp>
#include <session/push/notifications.hpp>
#include <session/random.hpp>

#include "../core/swarm_request.hpp"
#include "client_access.hpp"
#include "internal.hpp"

namespace session::push {

namespace log = oxen::log;
static auto cat = log::Cat("push");

using namespace session::literals;
using detail::ClientAccess;

namespace {

    // Globals keys.  Not Core's own, but kept beside them: the application and its notification
    // extension open the same database, and both need these.
    constexpr auto KEY_ENC_KEY = "push_enc_key"sv;
    constexpr auto KEY_SUBSCRIPTION = "push_subscription"sv;

    constexpr auto ENDPOINT_SUBSCRIBE = "subscribe"sv;
    constexpr auto ENDPOINT_UNSUBSCRIBE = "unsubscribe"sv;

    constexpr auto REQUEST_TIMEOUT = 20s;

    // What was last subscribed, as recorded once the push server accepted it.
    struct Recorded {
        std::string service;
        std::string token;
        std::vector<int16_t> namespaces;
        bool data;
        sys_ms at;
    };

    std::optional<Recorded> load_recorded(core::Core& core) {
        auto text = core.globals.get_text(KEY_SUBSCRIPTION);
        if (!text)
            return std::nullopt;
        try {
            auto j = nlohmann::json::parse(*text);
            return Recorded{
                    j.at("service").get<std::string>(),
                    j.at("token").get<std::string>(),
                    j.at("namespaces").get<std::vector<int16_t>>(),
                    j.at("data").get<bool>(),
                    from_epoch_ms(j.at("at").get<int64_t>())};
        } catch (const std::exception& e) {
            // Unreadable is as good as absent: the next subscribe simply sends.
            log::warning(cat, "Ignoring an unreadable recorded push subscription: {}", e.what());
            return std::nullopt;
        }
    }

    void store_recorded(core::Core& core, const Recorded& r) {
        nlohmann::json j{
                {"service", r.service},
                {"token", r.token},
                {"namespaces", r.namespaces},
                {"data", r.data},
                {"at", epoch_ms(r.at)}};
        core.globals.set(KEY_SUBSCRIPTION, j.dump());
    }

    std::vector<int16_t> namespace_values(const std::vector<config::Namespace>& namespaces) {
        std::vector<int16_t> out;
        for (auto ns : namespaces)
            out.push_back(static_cast<int16_t>(ns));
        return out;
    }

    // The fields every request about the account carries, signed over `to_sign` (which the caller
    // builds from the timestamp set here).
    template <typename MakeSigned>
    nlohmann::json signed_account_request(
            core::Core& core,
            const std::string& service,
            const std::string& token,
            MakeSigned make) {
        auto sig_ts =
                std::chrono::duration_cast<std::chrono::seconds>(clock_now_ms().time_since_epoch())
                        .count();
        auto account = core.globals.session_id_hex();
        auto to_sign = make(account, sig_ts);
        auto seed = core.globals.account_seed();
        auto sig = ed25519::sign(seed.ed25519_secret(), to_span(to_sign));
        return {{"pubkey", account},
                {"session_ed25519", core.globals.pubkey_ed25519().hex()},
                {"sig_ts", sig_ts},
                {"signature", oxenc::to_hex(sig.begin(), sig.end())},
                {"service", service},
                {"service_info", {{"token", token}}}};
    }

    // "MONITOR" || HEX(ACCOUNT) || SIG_TS || DATA01 || NS[0] "," ... "," NS[n], as the storage
    // server checks it: the push server hands this signature on when it subscribes to our swarm.
    nlohmann::json subscribe_request(
            core::Core& core,
            const Device& device,
            const std::vector<int16_t>& namespaces,
            bool data,
            const b32& enc_key) {
        auto req = signed_account_request(
                core,
                std::string{to_string(device.service)},
                device.token,
                [&](const std::string& account, int64_t sig_ts) {
                    return "MONITOR{}{}{}{}"_format(
                            account, sig_ts, data ? "1" : "0", fmt::join(namespaces, ","));
                });
        req["namespaces"] = namespaces;
        req["data"] = data;
        req["enc_key"] = oxenc::to_hex(enc_key.begin(), enc_key.end());
        return req;
    }

    nlohmann::json unsubscribe_request(
            core::Core& core, const std::string& service, const std::string& token) {
        return signed_account_request(
                core, service, token, [](const std::string& account, int64_t sig_ts) {
                    return "UNSUBSCRIBE{}{}"_format(account, sig_ts);
                });
    }

    network::Request server_request(
            const Server& server, std::string_view endpoint, const nlohmann::json& body) {
        return network::Request{
                network::ServerDestination{
                        server.scheme,
                        server.host,
                        server.pubkey,
                        server.port,
                        std::vector<std::pair<std::string, std::string>>{
                                {"Content-Type", "application/json"}},
                        "POST"},
                std::string{endpoint},
                to_vector<std::byte>(body.dump()),
                network::RequestCategory::standard_small,
                REQUEST_TIMEOUT};
    }

    // The push server answers a list of requests with a list of results, one each.  Returns the
    // first refusal's message, or nullopt if every one was accepted; throws if the answer is not
    // shaped like that at all.
    std::optional<std::string> first_refusal(const std::string& body, size_t expected) {
        auto j = nlohmann::json::parse(body);
        if (!j.is_array() || j.size() != expected)
            throw std::runtime_error{"unexpected response shape: {}"_format(body)};
        for (const auto& r : j)
            if (!r.value("success", false))
                return "{} ({})"_format(
                        r.value("message", std::string{"no reason given"}), r.value("error", -1));
        return std::nullopt;
    }

    // Sends `requests` and hands `done` either nothing (all accepted) or the error, on Core's
    // loop.  A request that fails before the push server answers is sent again, up to
    // SUBSCRIBE_ATTEMPTS in all.
    void send(
            core::Core& core,
            const Server& server,
            std::string_view endpoint,
            nlohmann::json requests,
            std::function<void(std::optional<Error>)> done,
            int attempt = 1) {
        auto* net = core.network();
        if (!net)
            return done(Error{client::err::network_unavailable, "no network"});
        auto expected = requests.size();
        auto request = server_request(server, endpoint, requests);
        net->send_request(
                std::move(request),
                [&core,
                 server,
                 endpoint = std::string{endpoint},
                 requests = std::move(requests),
                 attempt,
                 expected,
                 done = std::move(done)](
                        bool success,
                        bool timeout,
                        int16_t status,
                        std::vector<std::pair<std::string, std::string>> /*headers*/,
                        std::optional<std::string> body) mutable {
                    core.call([&core,
                               server = std::move(server),
                               endpoint = std::move(endpoint),
                               requests = std::move(requests),
                               attempt,
                               expected,
                               done = std::move(done),
                               success,
                               timeout,
                               status,
                               body = std::move(body)]() mutable {
                        if (!success || !body) {
                            auto why = timeout ? "timed out"s : "status {}"_format(status);
                            if (attempt >= Notifications::SUBSCRIBE_ATTEMPTS)
                                return done(Error{err::request_failed, std::move(why)});
                            log::info(
                                    cat,
                                    "push server {} request failed ({}); trying again",
                                    endpoint,
                                    why);
                            return core.call_later(
                                    Notifications::SUBSCRIBE_RETRY_DELAY,
                                    [&core,
                                     server = std::move(server),
                                     endpoint = std::move(endpoint),
                                     requests = std::move(requests),
                                     attempt,
                                     done = std::move(done)]() mutable {
                                        send(core,
                                             server,
                                             endpoint,
                                             std::move(requests),
                                             std::move(done),
                                             attempt + 1);
                                    });
                        }
                        try {
                            if (auto refusal = first_refusal(*body, expected))
                                return done(Error{err::rejected, std::move(*refusal)});
                        } catch (const std::exception& e) {
                            return done(Error{err::request_failed, e.what()});
                        }
                        done(std::nullopt);
                    });
                });
    }

}  // namespace

void detail::mark_subscription_due(core::Core& core) {
    auto recorded = load_recorded(core);
    if (!recorded)
        return;
    recorded->at = sys_ms{};
    store_recorded(core, *recorded);
}

std::string_view to_string(Service s) {
    switch (s) {
        case Service::apns: return "apns";
        case Service::apns_sandbox: return "apns-sandbox";
        case Service::firebase: return "firebase";
        case Service::huawei: return "huawei";
    }
    throw std::invalid_argument{"unknown push service"};
}

b32 Notifications::encryption_key() {
    auto& core = _client.core;
    b32 key;
    if (core.globals.get_blob_to(KEY_ENC_KEY, key))
        return key;

    // In one transaction, so that two processes asking at once -- the application and its
    // extension -- agree on whichever key was written first.
    auto c = core.database().conn();
    auto tx = c.begin_immediate();
    if (!core.globals.get_blob_to(KEY_ENC_KEY, key)) {
        random::fill(key);
        core.globals.set(KEY_ENC_KEY, std::span<const std::byte>{key});
    }
    tx.commit();
    return key;
}

std::vector<config::Namespace> Notifications::account_namespaces() {
    std::vector<config::Namespace> out;
    for (auto ns : core::POLL_NAMESPACES) {
        // Our own published PFS keys.  Core polls them only to learn that its own publish landed;
        // a rotation also writes the device group (21), which is subscribed and carries the
        // private keys a device actually needs.
        if (ns == config::Namespace::AccountPubkeys)
            continue;
        out.push_back(ns);
    }
    std::ranges::sort(out);
    return out;
}

void Notifications::subscribe(Device device, result_function<SubscribeResult> cb, bool force) {
    auto* core = &_client.core;
    auto* client = &_client;
    auto key = encryption_key();
    core->call([core,
                client,
                server = _server,
                device = std::move(device),
                cb = std::move(cb),
                force,
                key]() mutable {
        if (!core->network() || !core->globals.have_account())
            return ClientAccess::report(
                    *client,
                    cb,
                    Expected<SubscribeResult>{unexpected{
                            Error{client::err::network_unavailable, "no network or no account"}}});

        auto namespaces = namespace_values(account_namespaces());
        auto service = std::string{to_string(device.service)};
        auto previous = load_recorded(*core);

        bool current = previous && previous->service == service &&
                       previous->token == device.token && previous->namespaces == namespaces &&
                       clock_now_ms() - previous->at < RENEW_AFTER;
        if (current && !force)
            return ClientAccess::report(
                    *client, cb, Expected<SubscribeResult>{SubscribeResult::unchanged});

        nlohmann::json requests = nlohmann::json::array();
        requests.push_back(subscribe_request(*core, device, namespaces, /*data=*/true, key));

        send(*core,
             server,
             ENDPOINT_SUBSCRIBE,
             std::move(requests),
             [core, client, server, device, service, namespaces, previous, cb = std::move(cb)](
                     std::optional<Error> error) mutable {
                 if (error) {
                     log::warning(cat, "Push subscription failed: {}", error->message);
                     return ClientAccess::report(
                             *client, cb, Expected<SubscribeResult>{unexpected{std::move(*error)}});
                 }

                 store_recorded(
                         *core, Recorded{service, device.token, namespaces, true, clock_now_ms()});
                 log::info(cat, "Subscribed to push notifications through {}", service);

                 // The old token's subscription would otherwise linger at the push server until
                 // the push service tells it the token is dead.
                 if (previous &&
                     (previous->service != service || previous->token != device.token)) {
                     nlohmann::json old = nlohmann::json::array();
                     old.push_back(unsubscribe_request(*core, previous->service, previous->token));
                     send(*core, server, ENDPOINT_UNSUBSCRIBE, std::move(old), [](auto error) {
                         if (error)
                             log::info(
                                     cat,
                                     "Unsubscribing the old push token failed: {}",
                                     error->message);
                     });
                 }

                 ClientAccess::report(
                         *client, cb, Expected<SubscribeResult>{SubscribeResult::subscribed});
             });
    });
}

void Notifications::unsubscribe(result_function<bool> cb) {
    auto* core = &_client.core;
    auto* client = &_client;
    core->call([core, client, server = _server, cb = std::move(cb)]() mutable {
        auto previous = load_recorded(*core);
        if (!previous)
            return ClientAccess::report(*client, cb, Expected<bool>{true});
        if (!core->network() || !core->globals.have_account())
            return ClientAccess::report(
                    *client,
                    cb,
                    Expected<bool>{unexpected{
                            Error{client::err::network_unavailable, "no network or no account"}}});

        nlohmann::json requests = nlohmann::json::array();
        requests.push_back(unsubscribe_request(*core, previous->service, previous->token));
        send(*core,
             server,
             ENDPOINT_UNSUBSCRIBE,
             std::move(requests),
             [core, client, cb = std::move(cb)](std::optional<Error> error) mutable {
                 if (error)
                     return ClientAccess::report(
                             *client, cb, Expected<bool>{unexpected{std::move(*error)}});
                 core->globals.erase(KEY_SUBSCRIPTION);
                 ClientAccess::report(*client, cb, Expected<bool>{true});
             });
    });
}

}  // namespace session::push
