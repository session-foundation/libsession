#pragma once

#include <fmt/format.h>
#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <atomic>
#include <filesystem>
#include <future>
#include <memory>
#include <nlohmann/json.hpp>
#include <session/clock.hpp>
#include <session/config/namespaces.hpp>
#include <session/core.hpp>
#include <session/core/devices.hpp>
#include <session/crypto/ed25519.hpp>
#include <session/network/network_opt.hpp>
#include <session/network/session_network.hpp>
#include <session/network/session_network_types.hpp>
#include <session/util.hpp>

#include "../dns_utils.hpp"
#include "../test_helper.hpp"

using namespace std::literals;

// Defined in live/main.cpp; consumed here and in all live test files.
extern session::network::opt::router live_router_mode;

// Testnet QUIC file server direct-connect hostname and Ed25519 pubkey (for --direct mode).
// These are test-only values; the library code uses .sesh addresses for session-router mode.
inline constexpr auto TESTNET_QUIC_FS_HOST = "angus.oxen.io";
inline constexpr auto TESTNET_QUIC_FS_ED_PUBKEY =
        "929e33ded05e653fec04b49645117f51851f102a947e04806791be416ed76602";

// Creates a Network instance pointed at testnet using the current live_router_mode.
inline std::unique_ptr<session::network::Network> make_testnet_network(
        std::filesystem::path cache_dir, session::network::NetworkHooks hooks = {}) {
    namespace opt = session::network::opt;

    std::vector<opt::any> net_opts;
    net_opts.push_back(opt::netid::testnet());
    net_opts.push_back(live_router_mode);
    net_opts.push_back(opt::cache_directory{std::move(cache_dir)});

    // For direct mode, configure the QUIC file server address so DirectRouter uses the
    // quic-files protocol instead of the legacy HTTP path.  We resolve the hostname here
    // because libquic does not do DNS resolution.
    if (live_router_mode.type == opt::router::Type::direct) {
        net_opts.push_back(opt::quic_file_server_ed_pubkey{TESTNET_QUIC_FS_ED_PUBKEY});
        net_opts.push_back(
                opt::quic_file_server_address{session::test::resolve_host(TESTNET_QUIC_FS_HOST)});
    }

    return std::make_unique<session::network::Network>(
            session::network::config::Config{net_opts}, std::move(hooks));
}

// Creates a session::TempCore connected to a fresh testnet Network.  A unique temporary directory
// is created for the network's snode-pool cache and stored in session::TempCore::extra_dir so it is
// removed when the session::TempCore is destroyed.  All CoreOption arguments are forwarded to the
// session::TempCore constructor (e.g. predefined_seed, encryption options).
template <session::core::CoreOption... Opts>
inline session::TempCore make_live_core(Opts&&... opts) {
    static std::atomic<int> n{0};
    auto cache_dir = std::filesystem::temp_directory_path() / fmt::format("live_net_cache_{}", ++n);
    std::filesystem::create_directories(cache_dir);

    session::TempCore tc{std::forward<Opts>(opts)...};
    tc.extra_dir = cache_dir;
    tc->set_network([&](session::network::NetworkHooks hooks) {
        return make_testnet_network(std::move(cache_dir), std::move(hooks));
    });
    return tc;
}

// Builds the JSON params body for a signed "store" request targeting Core's AccountPubkeys
// namespace.  The returned bytes are the raw params (no "method"/"params" wrapper); the network
// routing layer adds the wrapper as required by the transport.
//
// See session-storage-server client_rpc_endpoints.h for the store endpoint spec.
inline std::vector<std::byte> build_account_pubkeys_store_params(session::core::Core& core) {
    auto session_id_hex = oxenc::to_hex(core.globals.session_id());
    auto now_ms = session::epoch_ms(session::clock_now_ms());
    constexpr auto ns = static_cast<int16_t>(session::config::Namespace::AccountPubkeys);

    // Signature covers: "store" || namespace (decimal) || sig_timestamp (decimal)
    auto to_sign = fmt::format("store{}{}", ns, now_ms);
    auto seed = core.globals.account_seed();
    auto sig = session::ed25519::sign(seed.ed25519_secret(), session::to_span(to_sign));

    auto msg = core.devices.build_account_pubkey_message();

    nlohmann::json params = {
            {"pubkey", session_id_hex},
            {"pubkey_ed25519", core.globals.pubkey_ed25519().hex()},
            {"namespace", ns},
            {"data",
             oxenc::to_base64(
                     std::string_view{reinterpret_cast<const char*>(msg.data()), msg.size()})},
            {"timestamp", now_ms},
            {"sig_timestamp", now_ms},
            {"signature", oxenc::to_base64(sig)},
            {"ttl", int64_t{2592000000}},  // 30 days in ms
    };
    return session::to_vector(params.dump());
}

// Pushes Core's AccountPubkeys message to its swarm.  Resolves the swarm, sends the signed store
// request, and blocks until the response arrives or the timeout elapses.
// Returns true if the store was accepted by the swarm node.
inline bool store_account_pubkeys(
        session::core::Core& core, std::chrono::milliseconds timeout = 30s) {
    using namespace session::network;
    using namespace std::chrono_literals;

    auto net = core.network();
    if (!net)
        throw std::logic_error{"store_account_pubkeys called without a network object"};

    auto promise = std::make_shared<std::promise<bool>>();
    auto future = promise->get_future();

    auto body = build_account_pubkeys_store_params(core);

    net->get_swarm(
            core.globals.pubkey_x25519(),
            false,
            [promise, net, body = std::move(body)](
                    swarm_id_t, std::vector<service_node> swarm) mutable {
                if (swarm.empty()) {
                    promise->set_value(false);
                    return;
                }
                net->send_request(
                        Request{swarm.front(),
                                "store",
                                std::move(body),
                                RequestCategory::standard_small,
                                5s},
                        [promise](bool success, bool, int16_t, auto, auto) {
                            promise->set_value(success);
                        });
            });

    return future.wait_for(timeout) == std::future_status::ready && future.get();
}
