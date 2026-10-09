#include "session/network/session_network.hpp"

#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <chrono>
#include <future>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/log/level.hpp>
#include <ranges>
#include <vector>

#include "../internal-util.hpp"
#include "session/blinding.hpp"
#include "session/network/backends/session_file_server.hpp"
#include "session/network/network_config.hpp"
#include "session/network/network_opt.hpp"
#include "session/network/request_queue.hpp"
#include "session/network/routing/direct_router.hpp"
#include "session/network/routing/onion_request_router.hpp"
#include "session/network/routing/session_router_router.hpp"
#include "session/network/session_network.h"
#include "session/network/session_network_types.hpp"
#include "session/network/transport/quic_transport.hpp"
#include "session/random.hpp"

using namespace oxen;
using namespace session::network;
using namespace session::network::config;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network {

namespace {

    inline auto cat = log::Cat("network");

    constexpr auto clock_out_of_sync_error = "Clock out of sync";

    // Checks a precondition and, if true, fires the request's on_complete with the given error.
    // Returns true if the condition was met (i.e. the caller should return).
    template <typename Req>
    bool fail_if(Req& req, bool cond, int16_t err) {
        if (cond && req.on_complete)
            req.on_complete(err, false);
        return cond;
    }

    config::FileServer build_file_server_config(const config::Config& main_config) {
        config::FileServer file_server_config = main_config.netid == opt::netid::Target::testnet
                                                      ? file_server::TESTNET_CONFIG
                                                      : file_server::DEFAULT_CONFIG;

        if (main_config.custom_file_server_scheme)
            file_server_config.scheme = *main_config.custom_file_server_scheme;

        if (main_config.custom_file_server_host)
            file_server_config.host = *main_config.custom_file_server_host;

        if (main_config.custom_file_server_pubkey_hex)
            file_server_config.pubkey_hex = *main_config.custom_file_server_pubkey_hex;

        if (main_config.custom_file_server_port)
            file_server_config.port = *main_config.custom_file_server_port;

        if (main_config.custom_file_server_max_file_size)
            file_server_config.max_file_size = *main_config.custom_file_server_max_file_size;

        if (main_config.custom_file_server_srouter_address)
            file_server_config.srouter = file_server::SRouterTarget{
                    *main_config.custom_file_server_srouter_address,
                    main_config.custom_file_server_srouter_port.value_or(
                            file_server::QUIC_DEFAULT_PORT)};

        return file_server_config;
    }

    config::SnodePool build_snode_pool_config(const config::Config& main_config) {
        return {main_config.cache_directory,
                main_config.fallback_snode_pool_path,
                main_config.cache_expiration,
                main_config.cache_min_lifetime,
                main_config.enforce_subnet_diversity,
                main_config.retry_delay,
                main_config.netid,
                main_config.seed_nodes,
                main_config.cache_min_size,
                main_config.cache_min_swarm_size,
                main_config.cache_num_nodes_to_use_for_refresh,
                main_config.cache_min_num_refresh_presence_to_include_node,
                main_config.cache_node_strike_threshold,
                // Session Router only.  Onion requests reach a storage server through relays that
                // do not care what it runs, and `direct` talks to it straight, so in neither case
                // does the version predict anything -- preferring on it there would narrow the
                // swarm for no reason.
                main_config.router == opt::router::Type::session_router
                        ? std::optional{opt::MIN_SESSION_ROUTER_SS_VERSION}
                        : std::nullopt};
    }

    config::QuicTransport build_quic_transport_config(const config::Config& main_config) {
        return {main_config.quic_handshake_timeout,
                main_config.quic_tunnel_handshake_timeout,
                main_config.quic_keep_alive,
                main_config.quic_max_udp_payload};
    }

    config::DirectRouter build_direct_router_config(
            const config::Config& main_config, const config::FileServer& file_server_config) {
        return {file_server_config,
                main_config.netid,
                main_config.quic_file_server_address,
                main_config.quic_file_server_ed_pubkey,
                main_config.quic_file_server_port.value_or(file_server::QUIC_DEFAULT_PORT)};
    }

    config::SessionRouter build_session_router_config(
            const config::Config& main_config, const config::FileServer& file_server_config) {
        if (!main_config.cache_directory)
            throw std::invalid_argument{
                    "Session Router requires a cache_directory to be configured."};

        if (main_config.netid == opt::netid::Target::devnet)
            throw std::invalid_argument{"Session Router does not support devnet."};

        return {file_server_config,
                main_config.netid,
                *main_config.cache_directory,
                main_config.path_length};
    }

    config::OnionRequestRouter build_onion_request_router_config(
            const config::Config& main_config, const config::FileServer& file_server_config) {
        return {file_server_config,
                main_config.cache_directory,
                main_config.onionreq_edge_node_cache_duration,
                main_config.netid,
                main_config.seed_nodes,
                main_config.retry_delay,
                main_config.path_length,
                main_config.onionreq_path_strike_threshold,
                main_config.onionreq_path_build_retry_limit,
                main_config.onionreq_path_rotation_frequency,
                main_config.cache_node_strike_threshold,
                main_config.onionreq_disable_pre_build_paths,
                main_config.onionreq_single_path_mode,
                main_config.onionreq_min_path_counts};
    }

    std::vector<network_service_node> convert_service_nodes(
            std::vector<session::network::service_node> nodes) {
        std::vector<network_service_node> converted_nodes;
        for (auto& node : nodes) {
            network_service_node converted_node;
            node.into(converted_node);
            converted_nodes.push_back(converted_node);
        }

        return converted_nodes;
    }

}  // namespace

Network::Network(config::Config _conf) :
        config{std::move(_conf)}, file_server_config{std::move(build_file_server_config(config))} {
    // When testing (particularly on Apple platforms) we can run into the NOFILE limit, so try to
    // increase it if the config option is set
    if (config.increase_no_file_limit) {
#ifdef _WIN32
        log::debug(cat, "FD limit adjustment is not supported on Windows");
#else
        try {
            auto [oldlim, newlim] = set_rlimit_nofile();
            if (oldlim != newlim)
                log::warning(cat, "NOFILE limit was only {}; increased to {}", oldlim, newlim);
            else
                log::debug(cat, "NOFILE limit was already {}", oldlim);
        } catch (const std::system_error& e) {
            log::error(cat, "Failed to increase fd limit: {}; connections may fail!", e.what());
        }
#endif
    }

    // Now we can properly do any setup needed
    _loop = std::make_shared<quic::Loop>();
    _disk_loop = config.disk_loop ? std::move(config.disk_loop) : std::make_shared<quic::Loop>();
    _jq.emplace(*_loop);

    // Setup the transport layer
    switch (config.transport) {
        case opt::transport::Type::quic:
            // Created through the loop's deleter, so that dropping our reference to it in
            // ~Network destroys it *on the loop* and blocks until that has happened: no libquic
            // callback can then be in flight into it, which is what lets it hold a bare `this`.
            _transport = _loop->make_shared<QuicTransport>(
                    std::move(build_quic_transport_config(config)), *_loop);
            break;
    }

    // The SnodePool is needed regardless of the transport layer as it includes swarm information
    // which is needed by the clients in order to send requests
    //
    // This fetcher goes straight to the transport, bypassing the router: it is what fills an empty
    // snode cache, and onion requests cannot be built before there is one.  Hence the seed list --
    // a bootstrap that has to leak the client's IP is at least aimed at nodes chosen in advance.
    //
    // TODO: session-router mode does not need this exemption.  It bootstraps itself onto the
    // network before it can carry anything of ours, so a tunnel to a seed node is available at the
    // point this runs, and routing the bootstrap would close the one hole in that mode's IP
    // guarantee.  Left direct for now because the routed fetcher is installed further down, after
    // the router exists.
    auto bootstrap_fetcher = [bt = std::weak_ptr{_transport}](
                                     Request req, network_response_callback_t on_complete) {
        if (auto transport = bt.lock())
            transport->send_request(std::move(req), std::move(on_complete));
        else
            log::error(
                    cat,
                    "Transport provided to the SnodePool bootstrap fetcher has been destroyed.");
    };
    _snode_pool = std::make_shared<SnodePool>(
            std::move(build_snode_pool_config(config)), *_loop, *_disk_loop, bootstrap_fetcher);

    // Additional transport configuration
    _transport->set_node_failure_reporter(
            [pool = _snode_pool.get()](const ed25519_pubkey& pubkey, bool permanent) {
                if (pool)
                    pool->record_node_failure(pubkey, permanent);
            });

    // Setup the router
    switch (config.router) {
        case opt::router::Type::onion_requests:
            _router = _loop->make_shared<OnionRequestRouter>(
                    std::move(build_onion_request_router_config(config, file_server_config)),
                    *_loop,
                    *_disk_loop,
                    _snode_pool,
                    _transport);
            break;

        case opt::router::Type::session_router:
#ifdef ENABLE_NETWORKING_SROUTER
            _router = SessionRouter::make(
                    std::move(build_session_router_config(config, file_server_config)),
                    _loop,
                    _snode_pool,
                    _transport);
#else
            throw std::runtime_error{"Session Router support is not enabled in this build!"};
#endif
            break;

        case opt::router::Type::direct:
            _router = std::make_unique<DirectRouter>(
                    std::move(build_direct_router_config(config, file_server_config)),
                    _loop,
                    _transport);
            break;
    }

    // Now that we have our router setup we need to setup the `standard_fetcher` on the `SnodePool`
    auto routed_fetcher = [r = std::weak_ptr{_router}, loop = _loop](
                                  Request req, network_response_callback_t on_complete) {
        loop->call([r, req = std::move(req), on_complete = std::move(on_complete)] {
            if (auto router = r.lock())
                router->send_request(std::move(req), std::move(on_complete));
            else
                log::error(
                        cat, "Router provided to the SnodePool routed_fetcher has been destroyed.");
        });
    };
    auto routed_fetcher_connected = [r = std::weak_ptr{_router}, loop = _loop]() -> bool {
        return loop->call_get([r] {
            if (auto router = r.lock())
                return router->get_status() == ConnectionStatus::connected;

            return false;
        });
    };
    _snode_pool->set_routed_fetcher(std::move(routed_fetcher), std::move(routed_fetcher_connected));

    // Add hooks to update the connection status
    _router->on_status_changed = [this] { _recalculate_status(); };
    _transport->on_status_changed = [this] { _recalculate_status(); };

    // Pass the transport's inbound signals through to whoever owns us.  Read each hook once into
    // a local: our owner may replace it, and these fire on the loop rather than from the thread
    // that would be doing the replacing.
    _transport->on_server_push = [this](const ed25519_pubkey& node,
                                        std::string_view endpoint,
                                        std::span<const std::byte> body) {
        if (auto cb = on_server_push)
            cb(node, endpoint, body);
    };
    _transport->on_connection_established = [this](const ed25519_pubkey& node) {
        if (auto cb = on_connection_established)
            cb(node);
    };
    _transport->on_connection_lost = [this](const ed25519_pubkey& node) {
        if (auto cb = on_connection_lost)
            cb(node);
    };

    // Perform a clock resync
    _jq->call_soon([this] { _resync_clock(std::nullopt, nullptr); });
}

Network::~Network() {
    // A Network is singly owned, so this runs on whichever thread its owner dropped it from -- and
    // it must not be the loop thread, because the loops are joined at the bottom of this function
    // and a thread cannot join itself.  The only way to get here on the loop is for an owner to
    // destroy its Network from inside a callback we handed it, so say so rather than leaving the
    // std::system_error from the join to explain it.
    if (_loop->inside())
        log::critical(
                cat,
                "Network is being destroyed from its own loop thread -- most likely by dropping it "
                "from inside one of its own callbacks.  This is about to abort.");

    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] {
        // Need to ensure the destruction of the router and transport objects don't trigger
        // `_recalculate_status` since that accesses both values which could result in a crash due
        // to accessing deallocated memory
        if (_router)
            _router->on_status_changed = nullptr;
        if (_transport)
            _transport->on_status_changed = nullptr;

        _update_status(ConnectionStatus::disconnected);
    });

    // Explicitly destroy in dependency order while _loop is still alive. Their destructors post
    // final cleanup via call_get so the loop must be running when they destruct.
    //
    // This has to happen before the queue below is stopped, for two reasons: these destructors are
    // what guarantee that no callback of ours is still held anywhere (which is what lets those
    // callbacks capture `this` bare), and a component finishing up may still post onto our queue --
    // which throws once the queue has been stopped.
    _router.reset();
    _snode_pool.reset();
    _transport.reset();

    // Nothing can reach us any more, so cancel whatever is left queued here rather than letting it
    // run against members that are about to go.
    _loop->call_get([this] { _jq->stop(); });

    // Now shut down the loops, whose destructors join their threads.  A disk loop we were given is
    // only let go of here, since it belongs to whoever gave it: what we left queued on it runs
    // later, which is safe because every one of those jobs holds what it writes by value.
    _disk_loop.reset();
    _loop.reset();

    log::debug(cat, "Destroyed.");
}

void Network::clear_cache() {
    // Use 'call_get' to force this to be synchronous
    _jq->call_get([this] {
        if (_snode_pool)
            _snode_pool->clear_cache();
        if (_router)
            _router->clear_cache();
    });
}

// MARK: Connection

void Network::suspend() {
    // Use 'call_get' to force this to be synchronous.  Some of these suspend() calls queue things
    // on the disk loop, but they don't have to worry about synchronizing because we flush queued
    // disk loop jobs before we finish.
    _jq->call_get([this] {
        _suspended = true;

        // The router before the transport, so that it has let go of its path builds and failure
        // listeners before the transport closes the connections they're attached to
        if (_snode_pool)
            _snode_pool->suspend();
        if (_router)
            _router->suspend();
        if (_transport)
            _transport->suspend();

        _close_connections();
    });

    // Flush the disk loop by queuing and waiting on an empty job (any already-pending jobs will get
    // processed first).  We do this with a promise instead of a call_get just so we can warn if it
    // takes a long time.
    std::promise<void> prom;
    _disk_loop->call_get([&prom] { prom.set_value(); });
    auto fut = prom.get_future();
    bool long_wait = false;
    while (fut.wait_for(1s) != std::future_status::ready) {
        log::warning(cat, "Writing to disk is taking a long time...");
        long_wait = true;
    }
    log::log(
            cat,
            long_wait ? log::Level::warn : log::Level::debug,
            "Finished pending writes to disk");

    log::info(cat, "Suspended.");
}

void Network::resume(bool automatically_reconnect) {
    // Use 'call_get' to force this to be synchronous
    _jq->call_get([this, automatically_reconnect] {
        if (!_suspended)
            return;

        if (_snode_pool)
            _snode_pool->resume();
        if (_transport)
            _transport->resume(automatically_reconnect);
        if (_router)
            _router->resume(automatically_reconnect);

        // When resuming we may need to resync the clock but don't want to do so if the last resync
        // was too recent (eg. if a user backgrounds and foregrounds the app frequently)
        auto time_since_last_resync =
                std::chrono::steady_clock::now() - _last_successful_clock_resync;

        if (time_since_last_resync >= config.min_resume_clock_resync_interval) {
            _jq->call_soon([this] {
                log::info(
                        cat,
                        "Performing clock resync as enough time has passed since the last resync.");
                _resync_clock(std::nullopt, nullptr);
            });
        }

        _suspended = false;
        log::info(cat, "Resumed.");
    });
}

void Network::close_connections() {
    // Use 'call_get' to force this to be synchronous
    _jq->call_get([this] { _close_connections(); });
}

// MARK: Interface

ConnectionStatus Network::get_status() {
    return _status.load();
}

std::optional<PathInfo> Network::get_path_to(const service_node& node) {
    if (_router)
        return _router->get_path_to(node);

    return std::nullopt;
}

void Network::get_swarm(
        session::network::x25519_pubkey swarm_pubkey,
        bool ignore_strike_count,
        std::function<void(swarm_id_t swarm_id, std::vector<service_node> swarm)> callback) {
    _jq->call([this,
               pubkey = std::move(swarm_pubkey),
               ignore_strike_count,
               cb = std::move(callback)] {
        if (!_snode_pool) {
            log::warning(
                    cat,
                    "Attempted to get swarm for {} but SnodePool has been destroyed.",
                    pubkey.hex());
            return cb(INVALID_SWARM_ID, {});
        }

        _snode_pool->get_swarm(std::move(pubkey), ignore_strike_count, std::move(cb));
    });
}

void Network::get_random_nodes(
        uint16_t count, std::function<void(std::vector<service_node> nodes)> callback) {
    _jq->call([this, count, cb = std::move(callback)] {
        if (!_snode_pool) {
            log::warning(
                    cat,
                    "Attempted to get {} random nodes(s) but SnodePool has been destroyed.",
                    count);
            return cb({});
        }

        auto unused_nodes = _snode_pool->get_unused_nodes(count);

        // If we don't have sufficient nodes then we need to refresh the snode cache
        if (unused_nodes.size() < count) {
            std::vector<service_node> nodes_to_exclude = _router->get_all_used_nodes();

            return _snode_pool->refresh_if_needed(
                    nodes_to_exclude, [this, count, cb = std::move(cb)](bool refreshed) {
                        if (!refreshed) {
                            log::warning(
                                    cat,
                                    "Cannot get {} random nodes: the pool could not be refreshed.",
                                    count);
                            return cb({});
                        }

                        // `refreshed` includes nothing having needed refreshing, which calls back
                        // inline, so asking again of a pool that can't supply `count` would
                        // re-enter this branch until the stack gives out
                        auto nodes = _snode_pool->get_unused_nodes(count);
                        if (nodes.size() < count) {
                            log::warning(
                                    cat,
                                    "Cannot get {} random nodes: the pool has only {} to give.",
                                    count,
                                    nodes.size());
                            return cb({});
                        }

                        cb(std::move(nodes));
                    });
        }
        cb(unused_nodes);
    });
}

void Network::send_request(Request request, network_response_callback_t callback) {
    if (_suspended) {
        callback(
                false,
                false,
                ERROR_NETWORK_SUSPENDED,
                {content_type_plain_text},
                "Network is suspended.");
        return;
    }
    if (!_transport)
        return callback(
                false,
                false,
                ERROR_NO_TRANSPORT_LAYER,
                {content_type_plain_text},
                "No transport layer configured");
    if (!_router)
        return callback(
                false,
                false,
                ERROR_NO_ROUTING_LAYER,
                {content_type_plain_text},
                "No router configured");

    try {
        auto processed_request = _preprocess_request(std::move(request));
        // Bare `this`: the router is destroyed by ~Network before our queue is stopped, so it
        // cannot still be holding this callback by the time any of our state goes.
        auto router_callback = [this, original_req = processed_request, cb = std::move(callback)](
                                       bool success,
                                       bool timeout,
                                       int16_t status_code,
                                       auto headers,
                                       auto body) {
            const auto dest_is_snode =
                    std::holds_alternative<service_node>(original_req.destination);

            // Parsed once for everything below, since a retrieve's body can be large
            std::optional<nlohmann::json> json;
            if (body)
                if (auto parsed = nlohmann::json::parse(*body, nullptr, false);
                    !parsed.is_discarded())
                    json = std::move(parsed);

            // If we got a successful response (with a body) and the request was sent to a
            // service node then we should update the network state based on the response
            // (Note: we don't want to do this for server requests because they could
            // include values in different formats, eg. the "Session Network" API returns
            // `t` in seconds)
            if (success && json && dest_is_snode)
                _update_network_state(*json);

            int16_t final_status_code = status_code;

            if (json)
                if (auto uniform_error = response::uniform_batch_error(*json))
                    final_status_code = *uniform_error;

            // Taken from every snode response rather than only a 421 one: a batch can be
            // rejected for some accounts and answered for others
            response::swarm_rejections rejections;
            if (dest_is_snode)
                rejections =
                        _take_swarm_redirects(original_req, json ? &*json : nullptr, status_code);

            // If we got a 406 from a snode, or a 425 from a server, then the device clock
            // is out of sync so we need to kick off a clock resync request
            if ((final_status_code == ERROR_NOT_ACCEPTABLE && dest_is_snode) ||
                (final_status_code == ERROR_TOO_EARLY && !dest_is_snode)) {
                _resync_clock(std::move(original_req), std::move(cb));
                return;
            }

            if (final_status_code == ERROR_MISDIRECTED_REQUEST) {
                _handle_421(
                        std::move(original_req),
                        std::move(rejections),
                        std::move(headers),
                        std::move(body),
                        std::move(cb));
                return;
            }

            _refresh_if_unredirected(rejections);

            // `final_status_code`, not the raw one: a batch whose subrequests all failed
            // the same way arrives here as a transport-level 200, and reporting that
            // would leave the caller unable to tell a misdirected request from any other
            // failure -- which is exactly the decision it is now responsible for making.
            auto final_success = (success && final_status_code >= 200 && final_status_code <= 299);
            cb(final_success, timeout, final_status_code, std::move(headers), std::move(body));
        };

        _router->send_request(std::move(processed_request), std::move(router_callback));
    } catch (const std::exception& e) {
        return callback(false, false, -1, {content_type_plain_text}, e.what());
    }
}

void Network::upload(UploadRequest request) {
    if (fail_if(request, _suspended, ERROR_NETWORK_SUSPENDED))
        return;
    if (fail_if(request, !_transport, ERROR_NO_TRANSPORT_LAYER))
        return;
    if (fail_if(request, !_router, ERROR_NO_ROUTING_LAYER))
        return;

    auto user_callback = request.on_complete;
    request.on_complete = [this, user_callback](
                                  std::variant<file_metadata, int16_t> result, bool timeout) {
        if (auto* status_code = std::get_if<int16_t>(&result)) {
            // Handle 425 (clock out of sync)
            // If we got a 425 (no need to handle a 406 as we only ever upload to a server),
            // then the device clock is out of sync so we need to kick off a clock resync
            // request
            if (*status_code == ERROR_TOO_EARLY) {
                log::info(cat, "Upload received 425, triggering clock resync.");
                _resync_clock(std::nullopt, nullptr);

                // Can't retry an upload as the data stream has already been consumed, so
                // just return the error
                if (user_callback)
                    user_callback(*status_code, timeout);
                return;
            }
        }

        // Forward to user callback
        if (user_callback)
            user_callback(std::move(result), timeout);
    };

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    _router->upload(std::move(request));
#pragma GCC diagnostic pop
}

void Network::upload_file(FileUploadRequest request, std::span<const std::byte> seed) {
    if (fail_if(request, _suspended, ERROR_NETWORK_SUSPENDED))
        return;
    if (fail_if(request, !_transport, ERROR_NO_TRANSPORT_LAYER))
        return;
    if (fail_if(request, !_router, ERROR_NO_ROUTING_LAYER))
        return;

    auto user_callback = request.on_complete;
    request.on_complete =
            [this, user_callback](
                    std::variant<std::pair<file_metadata, cleared_b32>, int16_t> result,
                    bool timeout) {
                if (auto* status_code = std::get_if<int16_t>(&result)) {
                    if (*status_code == ERROR_TOO_EARLY) {
                        log::info(cat, "File upload received 425, triggering clock resync.");
                        _resync_clock(std::nullopt, nullptr);

                        if (user_callback)
                            user_callback(*status_code, timeout);
                        return;
                    }
                }

                if (user_callback)
                    user_callback(std::move(result), timeout);
            };

    _router->upload_file(std::move(request), seed);
}

void Network::download(DownloadRequest request) {
    if (fail_if(request, _suspended, ERROR_NETWORK_SUSPENDED))
        return;
    if (fail_if(request, !_transport, ERROR_NO_TRANSPORT_LAYER))
        return;
    if (fail_if(request, !_router, ERROR_NO_ROUTING_LAYER))
        return;

    auto user_callback = request.on_complete;
    request.on_complete = [this, user_callback, req = request](
                                  std::variant<file_metadata, int16_t> result, bool timeout) {
        if (auto* status_code = std::get_if<int16_t>(&result)) {
            // If we got a 425 (no need to handle a 406 as we only ever download from a server),
            // then the device clock is out of sync so we need to kick off a clock resync request
            if (*status_code == ERROR_TOO_EARLY) {
                log::info(cat, "Download received 425, triggering clock resync and retrying.");

                // We want to automatically retry the download after the resync so store the request
                if (!_clock_resync_download_queue)
                    _clock_resync_download_queue = std::make_shared<std::vector<std::pair<
                            DownloadRequest,
                            std::function<void(std::variant<file_metadata, int16_t>, bool)>>>>();

                _clock_resync_download_queue->emplace_back(req, user_callback);
                _resync_clock(std::nullopt, nullptr);
                return;
            }
        }

        // Forward to user callback
        if (user_callback)
            user_callback(std::move(result), timeout);
    };

    _router->download(std::move(request));
}

// MARK: Internal Logic

void Network::_close_connections() {
    // The router first, for the same reason as in `suspend`: otherwise each edge connection the
    // transport closes fires a failure listener into a live router, which retires the path and
    // starts rebuilding it
    if (_router)
        _router->close_connections();
    if (_transport)
        _transport->close_connections();

    _recalculate_status();
    log::info(cat, "Closed all connections.");
}

void Network::_recalculate_status() {
    _jq->call([this] {
        if (!_transport || !_router)
            return _update_status(ConnectionStatus::disconnected);

        auto transport_status = _transport->get_status();
        auto router_status = _router->get_status();

        // If both layers report being fully connected then we are connected
        if (transport_status == ConnectionStatus::connected &&
            router_status == ConnectionStatus::connected)
            _update_status(ConnectionStatus::connected);
        // If either layer is disconnected, the whole system is disconnected
        else if (
                transport_status == ConnectionStatus::disconnected ||
                router_status == ConnectionStatus::disconnected)
            _update_status(ConnectionStatus::disconnected);
        // If either layer is trying to connect, the whole system is connecting
        else if (
                transport_status == ConnectionStatus::connecting ||
                router_status == ConnectionStatus::connecting)
            _update_status(ConnectionStatus::connecting);
        // Otherwise, we are in an unknown state
        else
            _update_status(ConnectionStatus::unknown);
    });
}

void Network::_update_status(ConnectionStatus new_status) {
    if (_status == new_status)
        return;

    _status = new_status;

    if (on_status_changed)
        on_status_changed(new_status);
}

Request Network::_preprocess_request(Request request) {
    std::visit(
            [&](auto&& details) {
                using T = std::decay_t<decltype(details)>;

                if constexpr (std::is_same_v<T, UploadInfo>) {
                    if (!request.body)
                        throw std::invalid_argument("Upload request must have a body.");

                    if (request.category != RequestCategory::file) {
                        log::warning(
                                cat,
                                "Request {} has UploadInfo but category is not 'file', forcing "
                                "to 'file'.",
                                request.request_id);
                        request.category = RequestCategory::file;
                    }

                    // Add the required headers if they weren't provided
                    if (auto* dest = std::get_if<ServerDestination>(&request.destination)) {
                        if (!dest->headers)
                            dest->headers.emplace();

                        std::unordered_set<std::string> existing_keys;
                        if (dest->headers)
                            for (const auto& [key, val] : *dest->headers)
                                existing_keys.insert(key);

                        if (existing_keys.find("Content-Type") == existing_keys.end())
                            dest->headers->emplace_back("Content-Type", "application/octet-stream");

                        if (existing_keys.find("Content-Disposition") == existing_keys.end()) {
                            if (details.file_name)
                                dest->headers->emplace_back(
                                        "Content-Disposition",
                                        fmt::format(
                                                "attachment; filename=\"{}\"", *details.file_name));
                            else
                                dest->headers->emplace_back("Content-Disposition", "attachment");
                        }
                    }
                } else if constexpr (std::is_same_v<T, std::monostate>) { /* No special handling */
                }
            },
            request.details);

    return request;
}

void Network::_update_network_state(const nlohmann::json& json) {
    try {
        const nlohmann::json* target_json = &json;

        // If it was a batch/sequence request then take the one with the highest "t" value as that
        // would have been the one which was returned last
        int64_t max_t = -1;
        for (const auto& sub : response::subresponses(json)) {
            if (!sub.body)
                continue;

            if (auto t = sub.body->find("t"); t != sub.body->end() && t->is_number())
                if (auto current_t = t->get<int64_t>(); current_t > max_t) {
                    max_t = current_t;
                    target_json = sub.body;
                }
        }

        // Update hardfork/softfork versions
        auto old_versions = _fork_versions.load();

        if (target_json->contains("hf") && (*target_json)["hf"].is_array() &&
            (*target_json)["hf"].size() >= 2) {
            std::pair<uint16_t, uint16_t> new_versions = {
                    (*target_json)["hf"][0].get<uint16_t>(),
                    (*target_json)["hf"][1].get<uint16_t>()};

            auto current_versions = old_versions;
            auto desired_next_versions = current_versions;

            if (new_versions.first > desired_next_versions.hardfork)
                desired_next_versions = {new_versions.first, new_versions.second};
            else if (
                    new_versions.first == desired_next_versions.hardfork &&
                    new_versions.second > desired_next_versions.softfork)
                desired_next_versions.softfork = new_versions.second;

            if (current_versions != desired_next_versions)
                _fork_versions.compare_exchange_weak(current_versions, desired_next_versions);
            log::trace(
                    cat,
                    "Fork version set to: {}.{}",
                    desired_next_versions.hardfork,
                    desired_next_versions.softfork);
        }

        // If the network info changed then call the callback
        if (on_network_info_changed) {
            auto new_versions = _fork_versions.load();

            if (new_versions != old_versions)
                on_network_info_changed(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                                AdjustedClock::get_offset()),
                        new_versions.hardfork,
                        new_versions.softfork);
        }
    } catch (const std::exception& e) {
        log::warning(cat, "Failed to parse network state from response: {}", e.what());
    }
}

// MARK: Specific Error Handling

// A node that rejects a request for an account usually names the swarm it actually belongs to.
// Taking its word (bounded - see `record_swarm_redirect`) fixes the one mapping we know is wrong,
// where refreshing has every client of a changed swarm fetch the full node list for it.
response::swarm_rejections Network::_take_swarm_redirects(
        const Request& request, const nlohmann::json* json, int16_t status_code) {
    auto rejections = response::find_swarm_rejections(json, status_code, request.swarm_pubkeys);

    for (auto& [account, keys] : rejections.accounts)
        if (!keys.empty() && !_snode_pool->record_swarm_redirect(account, keys))
            keys.clear();

    return rejections;
}

// With no usable redirect the pool itself is the only thing that can put a rejection right, and
// one refresh re-resolves every account at once
void Network::_refresh_if_unredirected(const response::swarm_rejections& rejections) {
    for (const auto& [account, keys] : rejections.accounts)
        if (keys.empty())
            return _snode_pool->invalidate_swarm(account);
}

// The caller retries a 421 by re-resolving the account's swarm, so the 421 is reported only once
// that would give a different answer: straight away when a redirect was taken, and after the
// refresh when one has to run.  A rejection nothing can correct is reported as
// ERROR_SWARM_UNRESOLVED instead, because re-resolving it would return the swarm that just
// rejected us.
void Network::_handle_421(
        Request original_request,
        response::swarm_rejections rejections,
        std::vector<std::pair<std::string, std::string>> headers,
        std::optional<std::string> body,
        network_response_callback_t final_callback) {
    // Only a node's rejection says anything about a swarm
    if (!std::holds_alternative<service_node>(original_request.destination))
        return final_callback(
                false, false, ERROR_MISDIRECTED_REQUEST, std::move(headers), std::move(body));

    if (rejections.accounts.empty()) {
        log::warning(
                cat,
                "Request {} received 421 but names no account to re-resolve.",
                original_request.request_id);
        return final_callback(
                false,
                false,
                ERROR_SWARM_UNRESOLVED,
                {content_type_plain_text},
                "421 Misdirected Request for a request with no swarm");
    }

    // A retry goes to a single swarm, which a batch spanning several accounts doesn't have.  Their
    // redirects are already taken, so the next request for each goes to the right place.
    if (rejections.accounts.size() > 1 || rejections.unattributed) {
        log::info(
                cat,
                "Request {} received 421s for {} accounts.",
                original_request.request_id,
                rejections.accounts.size());
        _refresh_if_unredirected(rejections);
        return final_callback(
                false, false, ERROR_MISDIRECTED_REQUEST, std::move(headers), std::move(body));
    }

    auto [swarm_pubkey, redirect] = *rejections.accounts.begin();

    if (!redirect.empty())
        return final_callback(
                false, false, ERROR_MISDIRECTED_REQUEST, std::move(headers), std::move(body));

    log::info(
            cat,
            "Request {} received 421 with no usable redirect; re-resolving the swarm of {}.",
            original_request.request_id,
            swarm_pubkey.hex());

    _snode_pool->invalidate_swarm(
            swarm_pubkey,
            [cb = std::move(final_callback), headers = std::move(headers), body = std::move(body)](
                    bool swarm_resolved) mutable {
                // Without a re-resolve there is nothing better than the mapping the 421 disproved
                // - a redirect naming any node we know would have been taken instead.  The
                // refresh has been asked for, and the account's next rejection asks again.
                if (!swarm_resolved)
                    return cb(
                            false,
                            false,
                            ERROR_SWARM_UNRESOLVED,
                            {content_type_plain_text},
                            "421 Misdirected Request, and the swarm could not be re-resolved");

                cb(false, false, ERROR_MISDIRECTED_REQUEST, std::move(headers), std::move(body));
            });
}

void Network::_resync_clock(
        std::optional<Request> original_request, network_response_callback_t request_callback) {
    if (_suspended) {
        log::info(cat, "Ignoring clock resync attempt as network is suspended.");
        if (request_callback)
            request_callback(
                    false,
                    false,
                    ERROR_NETWORK_SUSPENDED,
                    {content_type_plain_text},
                    "Network is suspended.");
        return;
    }

    if (!_snode_pool) {
        log::info(cat, "Ignoring clock resync attempt as SnodePool has been destroyed.");
        if (request_callback)
            request_callback(
                    false,
                    false,
                    ERROR_NO_SNODE_POOL,
                    {content_type_plain_text},
                    "SnodePool was destroyed.");
    }

    // Add the request to the request queue, we do this so we can trigger it's callback after the
    // resync completes as it would likely fail with another clock out of sync error if it gets
    // retried immediately
    if (original_request && request_callback) {
        // If we don't have a resync request queue then create one
        if (!_clock_resync_request_queue)
            _clock_resync_request_queue = std::make_shared<detail::RequestQueue>(*_loop);

        _clock_resync_request_queue->add(std::move(*original_request), std::move(request_callback));
    }

    // Only allow a single clock resync at a time
    if (_current_clock_resync_id) {
        log::debug(
                cat,
                "A resync is already in progress ({}), adding request to be processed after "
                "result.",
                *_current_clock_resync_id);
        return;
    }

    const std::string request_id = random::unique_id("CoS");
    log::info(cat, "[Request {}] Starting clock resync.", request_id);
    _current_clock_resync_id = request_id;
    _clock_resync_results.clear();

    // Refresh the snode pool if needed to ensure we have the most up-to-date cache
    std::vector<service_node> nodes_to_exclude = _router->get_all_used_nodes();
    _snode_pool->refresh_if_needed(std::move(nodes_to_exclude), [this, request_id](bool refreshed) {
        // `_current_clock_resync_id` was set before this call, so giving up without clearing it
        // blocks every later resync attempt for the life of the process and strands everything
        // queued behind it.  Completing with no results takes the existing "resync finished,
        // successful or not" path, which does both and leaves the offset we already had alone -
        // an old offset beats none, and this says nothing about whether it was right.
        if (!refreshed) {
            log::warning(
                    cat,
                    "[Request {}] Abandoning clock resync: the snode pool could not be refreshed.",
                    request_id);
            return _on_clock_resync_complete();
        }

        // Pick the random nodes we want to use for retrying (these won't change for this resync
        // attempt)
        auto resync_nodes =
                _snode_pool->get_unused_nodes(config.num_nodes_to_check_for_network_offset);

        for (uint8_t i = 0; i < resync_nodes.size(); ++i)
            _launch_next_clock_out_of_sync_request(
                    request_id, i, resync_nodes[i], config.num_nodes_to_check_for_network_offset);
    });
}

void Network::_launch_next_clock_out_of_sync_request(
        const std::string& request_id,
        const uint8_t index,
        const service_node& node,
        const uint8_t total_requests) {
    if (!_current_clock_resync_id)
        return;

    const auto target_request_id = "{}-{}"_format(request_id, index);
    log::info(
            cat,
            "[Request {}] Launching clock resync request to {}",
            target_request_id,
            node.to_string());
    const Request request = Request{
            target_request_id,
            network_destination{node},
            std::string{"info"},
            std::nullopt,
            RequestCategory::standard,
            10s,
            std::nullopt,     // overall_timeout
            std::nullopt,     // desired_path_index
            std::monostate{}  // details
    };

    auto start = std::chrono::steady_clock::now();
    send_request(
            std::move(request),
            [this, request_id, target_request_id, total_requests, start](
                    bool success,
                    bool timeout,
                    int16_t status_code,
                    std::vector<std::pair<std::string, std::string>> /*headers*/,
                    std::optional<std::string> response) {
                auto end_steady = std::chrono::steady_clock::now();
                auto end_system = clock_now_ms();

                // If the resync was cancelled or completed while we were in-flight, do nothing
                if (!_current_clock_resync_id || *_current_clock_resync_id != request_id) {
                    log::info(
                            cat,
                            "[Request {}] Ignoring stale clock resync response.",
                            target_request_id);
                    return;
                }

                try {
                    if (!success || timeout || !response)
                        throw std::runtime_error{response.value_or("Unknown error.")};

                    if (status_code < 200 || status_code > 299)
                        throw status_code_exception{
                                status_code,
                                {content_type_plain_text},
                                "Request failed with status code: {}, error: {}"_format(
                                        status_code, response.value_or("Unknown error."))};

                    auto json = nlohmann::json::parse(*response);

                    if (!json.contains("t") || !json["t"].is_number())
                        throw std::runtime_error{"Response didn't contain a 't' value"};

                    sys_ms server_time{std::chrono::milliseconds{json["t"].get<int64_t>()}};
                    auto latency = std::chrono::ceil<std::chrono::milliseconds>(
                            ((end_steady - start) / 2));
                    auto offset = (server_time - end_system) - latency;

                    _clock_resync_results.emplace_back(offset);

                    log::info(
                            cat,
                            "[Request {}] Received clock resync response {}/{} with offset: {}ms.",
                            target_request_id,
                            _clock_resync_results.size(),
                            total_requests,
                            offset.count());
                } catch (const std::exception& e) {
                    // If one of the requests fails then don't worry about it (we still get the
                    // median, and if this happens to result in subsequent clock out of sync errors
                    // then we will trigger another resync)
                    _clock_resync_results.push_back(std::nullopt);

                    log::warning(
                            cat,
                            "[Request {}] Clock resync attempt {}/{} failed: {}.",
                            target_request_id,
                            _clock_resync_results.size(),
                            total_requests,
                            e.what());
                }

                // If we've received all the results then we need to process them and complete the
                // resync
                if (_clock_resync_results.size() >= total_requests)
                    _on_clock_resync_complete();
            });
}

void Network::_on_clock_resync_complete() {

    auto raw_results = std::move(_clock_resync_results);
    auto refresh_id = std::move(*_current_clock_resync_id);
    _clock_resync_results.clear();
    _current_clock_resync_id.reset();

    log::info(
            cat,
            "[Request {}] Have {} responses, processing and finalizing clock resync.",
            refresh_id,
            raw_results.size());

    // Filter and sort the offsets and find the median
    std::vector<std::chrono::milliseconds> result;

    for (const auto& opt : raw_results)
        if (opt)
            result.push_back(*opt);

    const auto count = result.size();

    // If we got a successful response then we should update the network offset
    if (count > 0) {
        std::chrono::milliseconds median_offset;
        std::sort(result.begin(), result.end());

        if (count % 2 == 1)
            median_offset = result[count / 2];
        else {
            auto mid_index = (count / 2);
            auto middle_values_sum = (result[mid_index - 1] + result[mid_index]);
            median_offset = (middle_values_sum / 2);
        }

        AdjustedClock::set_offset(median_offset);
        _last_successful_clock_resync = std::chrono::steady_clock::now();
        log::info(
                cat, "[Request {}] Network offset set to: {}ms", refresh_id, median_offset.count());

        // Trigger the network info changed callback to update the client
        if (on_network_info_changed) {
            auto versions = _fork_versions.load();

            on_network_info_changed(median_offset, versions.hardfork, versions.softfork);
        }
    }

    // Now that the clock resync is complete (regardless of whether it was successful or not) we can
    // fail any requests which received clock out of sync errors while waiting for the resync to
    // complete (we can't automatically retry as libSession can't currently reconstruct the requests
    // with updated timestamps)
    if (_clock_resync_request_queue && !_clock_resync_request_queue->is_empty()) {
        auto pending = _clock_resync_request_queue->pop_all();
        log::debug(cat, "Failing {} requests queued during clock resync.", pending.size());

        for (auto& [req, cb] : pending) {
            const auto dest_is_snode = std::holds_alternative<service_node>(req.destination);
            cb(false,
               false,
               (dest_is_snode ? ERROR_NOT_ACCEPTABLE : ERROR_TOO_EARLY),
               {content_type_plain_text},
               clock_out_of_sync_error);
        }
    }

    // Retry queued downloads
    if (_clock_resync_download_queue && !_clock_resync_download_queue->empty()) {
        log::debug(
                cat,
                "Retrying {} downloads after clock resync.",
                _clock_resync_download_queue->size());

        for (auto& [download_req, cb] : *_clock_resync_download_queue) {
            // Restore the user's callback and retry
            download_req.on_complete = cb;
            download(download_req);
        }
        _clock_resync_download_queue->clear();
    }
}

}  // namespace session::network

// MARK: C API

struct session_response_handle_cpp_t {
    session::network::network_response_callback_t cpp_callback;
};

namespace {

inline session::network::Network* unbox(network_object* network_) {
    assert(network_ && network_->internals);
    return static_cast<session::network::Network*>(network_->internals);
}

}  // namespace

extern "C" {

using namespace session;
using namespace session::network;

struct session_upload_handle_t {
    std::shared_ptr<std::atomic<bool>> cancelled;
    session_upload_callbacks callbacks;
};

struct session_download_handle_t {
    std::shared_ptr<std::atomic<bool>> cancelled;
    session_download_callbacks callbacks;
};

LIBSESSION_C_API session_network_config session_network_config_default() {
    Config cpp_defaults{};
    session_network_config config = {};

    switch (cpp_defaults.netid) {
        case opt::netid::Target::mainnet: config.netid = SESSION_NETWORK_MAINNET;
        case opt::netid::Target::testnet: config.netid = SESSION_NETWORK_TESTNET;
        case opt::netid::Target::devnet: config.netid = SESSION_NETWORK_DEVNET;
        default: config.netid = SESSION_NETWORK_MAINNET;
    }

    switch (cpp_defaults.router) {
        case opt::router::Type::onion_requests:
            config.router = SESSION_NETWORK_ROUTER_ONION_REQUESTS;
        case opt::router::Type::session_router:
            config.router = SESSION_NETWORK_ROUTER_SESSION_ROUTER;
        case opt::router::Type::direct: config.router = SESSION_NETWORK_ROUTER_DIRECT;
        default: config.router = SESSION_NETWORK_ROUTER_ONION_REQUESTS;
    }

    switch (cpp_defaults.transport) {
        case opt::transport::Type::quic: config.transport = SESSION_NETWORK_TRANSPORT_QUIC;
        default: config.transport = SESSION_NETWORK_TRANSPORT_QUIC;
    }

    config.increase_no_file_limit = cpp_defaults.increase_no_file_limit;
    config.path_length = cpp_defaults.path_length;
    config.enforce_subnet_diversity = cpp_defaults.enforce_subnet_diversity;
    config.min_retry_delay_ms = cpp_defaults.retry_delay.base_delay.count();
    config.max_retry_delay_ms = cpp_defaults.retry_delay.max_delay.count();
    config.num_nodes_to_check_for_network_offset =
            cpp_defaults.num_nodes_to_check_for_network_offset;
    config.min_resume_clock_resync_interval_minutes =
            std::chrono::duration_cast<std::chrono::minutes>(
                    cpp_defaults.min_resume_clock_resync_interval)
                    .count();

    config.devnet_seed_nodes = nullptr;
    config.devnet_seed_nodes_size = 0;

    config.cache_dir = nullptr;
    config.fallback_snode_pool_path = nullptr;
    config.cache_expiration_minutes =
            std::chrono::duration_cast<std::chrono::minutes>(cpp_defaults.cache_expiration).count();
    config.cache_min_lifetime_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(cpp_defaults.cache_min_lifetime)
                    .count();

    config.cache_min_size = cpp_defaults.cache_min_size;
    config.cache_min_swarm_size = cpp_defaults.cache_min_swarm_size;
    config.cache_num_nodes_to_use_for_refresh = cpp_defaults.cache_num_nodes_to_use_for_refresh;
    config.cache_min_num_refresh_presence_to_include_node =
            cpp_defaults.cache_min_num_refresh_presence_to_include_node;
    config.cache_node_strike_threshold = cpp_defaults.cache_node_strike_threshold;

    config.onionreq_path_strike_threshold = cpp_defaults.onionreq_path_strike_threshold;
    config.onionreq_path_build_retry_limit = cpp_defaults.onionreq_path_build_retry_limit;
    config.onionreq_min_path_count_standard =
            cpp_defaults.onionreq_min_path_counts[PathCategory::standard];
    config.onionreq_min_path_count_file = cpp_defaults.onionreq_min_path_counts[PathCategory::file];
    config.onionreq_single_path_mode = cpp_defaults.onionreq_single_path_mode;
    config.onionreq_disable_pre_build_paths = cpp_defaults.onionreq_disable_pre_build_paths;
    config.onionreq_path_rotation_frequency_minutes =
            cpp_defaults.onionreq_path_rotation_frequency.count();
    config.onionreq_edge_node_cache_duration_days =
            cpp_defaults.onionreq_edge_node_cache_duration.count();

    config.quic_handshake_timeout_seconds =
            std::chrono::duration_cast<std::chrono::seconds>(cpp_defaults.quic_handshake_timeout)
                    .count();
    config.quic_tunnel_handshake_timeout_seconds =
            std::chrono::duration_cast<std::chrono::seconds>(
                    cpp_defaults.quic_tunnel_handshake_timeout)
                    .count();
    config.quic_keep_alive_seconds =
            std::chrono::duration_cast<std::chrono::seconds>(cpp_defaults.quic_keep_alive).count();
    config.quic_disable_mtu_discovery = cpp_defaults.quic_max_udp_payload.has_value();
    config.quic_max_udp_payload = cpp_defaults.quic_max_udp_payload.value_or(0);

    return config;
}

LIBSESSION_C_API bool session_network_init(
        network_object** network, const session_network_config* config, char* error) {
    if (!network || !config) {
        session::copy_c_str(error, 256, "network or config were null.");
        return false;
    }

    try {
        // Build the configuration options (ordered this way for the debug logs to make the most
        // sense)
        std::vector<opt::any> cpp_opts;

        // Network ID
        switch (config->netid) {
            case SESSION_NETWORK_MAINNET: cpp_opts.emplace_back(opt::netid::mainnet()); break;
            case SESSION_NETWORK_TESTNET: cpp_opts.emplace_back(opt::netid::testnet()); break;
            case SESSION_NETWORK_DEVNET:
                if (!config->devnet_seed_nodes || config->devnet_seed_nodes_size == 0)
                    throw std::runtime_error(
                            "SESSION_NETWORK_DEVNET requires at least one seed node.");

                std::vector<service_node> seed_nodes;
                seed_nodes.reserve(config->devnet_seed_nodes_size);

                for (size_t i = 0; i < config->devnet_seed_nodes_size; ++i)
                    seed_nodes.push_back(service_node::from(config->devnet_seed_nodes[i]));

                cpp_opts.emplace_back(opt::netid::devnet(std::move(seed_nodes)));
                break;
        }

        // Router
        switch (config->router) {
            case SESSION_NETWORK_ROUTER_ONION_REQUESTS:
                cpp_opts.emplace_back(opt::router::onion_requests());
                break;
            case SESSION_NETWORK_ROUTER_SESSION_ROUTER:
                cpp_opts.emplace_back(opt::router::session_router());
                break;
            case SESSION_NETWORK_ROUTER_DIRECT: cpp_opts.emplace_back(opt::router::direct()); break;
        }

        // Transport
        switch (config->transport) {
            case SESSION_NETWORK_TRANSPORT_QUIC:
                cpp_opts.emplace_back(opt::transport::quic());
                break;
        }

        // Custom File Server
        if (config->custom_file_server_scheme)
            cpp_opts.emplace_back(opt::file_server_scheme(config->custom_file_server_scheme));

        if (config->custom_file_server_host)
            cpp_opts.emplace_back(opt::file_server_host(config->custom_file_server_host));

        if (config->custom_file_server_port > 0)
            cpp_opts.emplace_back(opt::file_server_port(config->custom_file_server_port));

        if (config->custom_file_server_pubkey_hex)
            cpp_opts.emplace_back(
                    opt::file_server_pubkey_hex(config->custom_file_server_pubkey_hex));

        if (config->custom_file_server_max_file_size > 0)
            cpp_opts.emplace_back(
                    opt::file_server_max_file_size(config->custom_file_server_max_file_size));

        // General
        if (config->increase_no_file_limit)
            cpp_opts.emplace_back(opt::increase_no_file_limit{});

        if (!config->enforce_subnet_diversity)
            cpp_opts.emplace_back(opt::disable_subnet_diversity{});

        if (config->min_retry_delay_ms > 0 || config->max_retry_delay_ms > 0)
            cpp_opts.emplace_back(opt::retry_delay{
                    std::chrono::milliseconds{config->min_retry_delay_ms},
                    std::chrono::milliseconds{config->max_retry_delay_ms}});

        if (config->num_nodes_to_check_for_network_offset > 0)
            cpp_opts.emplace_back(opt::num_nodes_to_check_for_network_offset{
                    config->num_nodes_to_check_for_network_offset});

        if (config->min_resume_clock_resync_interval_minutes > 0)
            cpp_opts.emplace_back(opt::min_resume_clock_resync_interval{
                    std::chrono::minutes{config->min_resume_clock_resync_interval_minutes}});

        // Snode cache
        if (config->cache_dir)
            cpp_opts.emplace_back(opt::cache_directory{std::filesystem::path{config->cache_dir}});

        if (config->fallback_snode_pool_path)
            cpp_opts.emplace_back(opt::fallback_snode_pool_path{
                    std::filesystem::path{config->fallback_snode_pool_path}});

        if (config->cache_expiration_minutes > 0)
            cpp_opts.emplace_back(
                    opt::cache_expiration{std::chrono::minutes{config->cache_expiration_minutes}});

        if (config->cache_min_lifetime_ms > 0)
            cpp_opts.emplace_back(opt::cache_min_lifetime{
                    std::chrono::milliseconds{config->cache_min_lifetime_ms}});

        if (config->cache_min_size > 0)
            cpp_opts.emplace_back(opt::cache_min_size{config->cache_min_size});

        if (config->cache_min_swarm_size > 0)
            cpp_opts.emplace_back(opt::cache_min_swarm_size{config->cache_min_swarm_size});

        // A `0` value is valid for these options
        cpp_opts.emplace_back(opt::cache_num_nodes_to_use_for_refresh{
                config->cache_num_nodes_to_use_for_refresh});
        cpp_opts.emplace_back(opt::cache_min_num_refresh_presence_to_include_node{
                config->cache_min_num_refresh_presence_to_include_node});

        if (config->cache_node_strike_threshold > 0)
            cpp_opts.emplace_back(
                    opt::cache_node_strike_threshold{config->cache_node_strike_threshold});

        // Router-specific settings
        switch (config->router) {
            case SESSION_NETWORK_ROUTER_ONION_REQUESTS:
                // Process the Onion Request options since we are using them
                if (config->path_length > 0)
                    cpp_opts.emplace_back(opt::path_length{config->path_length});

                if (config->onionreq_path_strike_threshold > 0)
                    cpp_opts.emplace_back(opt::onionreq_path_strike_threshold{
                            config->onionreq_path_strike_threshold});

                if (config->onionreq_path_build_retry_limit > 0)
                    cpp_opts.emplace_back(opt::onionreq_path_build_retry_limit{
                            config->onionreq_path_build_retry_limit});

                if (config->onionreq_min_path_count_standard > 0)
                    cpp_opts.emplace_back(opt::onionreq_min_path_count{
                            PathCategory::standard, config->onionreq_min_path_count_standard});

                if (config->onionreq_min_path_count_file > 0)
                    cpp_opts.emplace_back(opt::onionreq_min_path_count{
                            PathCategory::file, config->onionreq_min_path_count_file});

                if (config->onionreq_single_path_mode)
                    cpp_opts.emplace_back(opt::onionreq_single_path_mode{});

                if (config->onionreq_disable_pre_build_paths)
                    cpp_opts.emplace_back(opt::onionreq_disable_pre_build_paths{});

                if (config->onionreq_path_rotation_frequency_minutes > 0)
                    cpp_opts.emplace_back(
                            opt::onionreq_path_rotation_frequency{std::chrono::minutes{
                                    config->onionreq_path_rotation_frequency_minutes}});

                if (config->onionreq_edge_node_cache_duration_days > 0)
                    cpp_opts.emplace_back(opt::onionreq_edge_node_cache_duration{
                            std::chrono::days{config->onionreq_edge_node_cache_duration_days}});
                break;

            case SESSION_NETWORK_ROUTER_SESSION_ROUTER:
                // Process the Session Router options since we are using them
                if (config->path_length > 0)
                    cpp_opts.emplace_back(opt::path_length{config->path_length});
                break;

            case SESSION_NETWORK_ROUTER_DIRECT: break;
        }

        // Transport-specific settings
        switch (config->transport) {
            case SESSION_NETWORK_TRANSPORT_QUIC:
                if (config->quic_handshake_timeout_seconds > 0)
                    cpp_opts.emplace_back(opt::quic_handshake_timeout{
                            std::chrono::seconds{config->quic_handshake_timeout_seconds}});

                if (config->quic_tunnel_handshake_timeout_seconds > 0)
                    cpp_opts.emplace_back(opt::quic_tunnel_handshake_timeout{
                            std::chrono::seconds{config->quic_tunnel_handshake_timeout_seconds}});

                if (config->quic_keep_alive_seconds > 0)
                    cpp_opts.emplace_back(opt::quic_keep_alive{
                            std::chrono::seconds{config->quic_keep_alive_seconds}});

                if (config->quic_max_udp_payload > 0)
                    cpp_opts.emplace_back(opt::quic_max_udp_payload{config->quic_max_udp_payload});
                else if (config->quic_disable_mtu_discovery)
                    cpp_opts.emplace_back(opt::quic_max_udp_payload{1200});

                break;
        }

        // Construct the Network instance
        Config final_config(cpp_opts);
        auto n = std::make_unique<Network>(std::move(final_config));
        auto n_object = std::make_unique<network_object>();
        n_object->internals = n.release();
        *network = n_object.release();
        return true;
    } catch (const std::exception& e) {
        session::copy_c_str(error, 256, e.what());
        return false;
    }
}

LIBSESSION_C_API void session_network_free(network_object* network) {
    delete static_cast<session::network::Network*>(network->internals);
    delete network;
}

LIBSESSION_C_API void session_request_params_free(session_request_params* params) {
    if (params)
        std::free(params);
}

LIBSESSION_C_API void session_network_suspend(network_object* network) {
    unbox(network)->suspend();
}

LIBSESSION_C_API void session_network_resume(
        network_object* network, bool automatically_reconnect) {
    unbox(network)->resume(automatically_reconnect);
}

LIBSESSION_C_API void session_network_close_connections(network_object* network) {
    unbox(network)->close_connections();
}

LIBSESSION_C_API void session_network_clear_cache(network_object* network) {
    unbox(network)->clear_cache();
}

LIBSESSION_C_API bool session_network_has_retrieved_time_offset(network_object* network) {
    return unbox(network)->has_retrieved_time_offset();
}

LIBSESSION_C_API int64_t session_network_time_offset(network_object* network) {
    return unbox(network)->network_time_offset().count();
}

LIBSESSION_C_API uint16_t session_network_hardfork(network_object* network) {
    return unbox(network)->hardfork();
}

LIBSESSION_C_API uint16_t session_network_softfork(network_object* network) {
    return unbox(network)->softfork();
}

LIBSESSION_C_API void session_network_set_status_changed_callback(
        network_object* network, void (*callback)(CONNECTION_STATUS status, void* ctx), void* ctx) {
    if (!callback)
        unbox(network)->on_status_changed = nullptr;
    else
        unbox(network)->on_status_changed = [cb = std::move(callback),
                                             ctx](ConnectionStatus status) {
            cb(static_cast<CONNECTION_STATUS>(status), ctx);
        };
}

LIBSESSION_C_API void session_network_set_network_info_changed_callback(
        network_object* network,
        void (*callback)(
                int64_t network_time_offset, uint16_t hardfork, uint16_t softfork, void* ctx),
        void* ctx) {
    if (!callback)
        unbox(network)->on_network_info_changed = nullptr;
    else
        unbox(network)->on_network_info_changed =
                [cb = std::move(callback), ctx](
                        std::chrono::milliseconds network_time_offset,
                        uint16_t hardfork,
                        uint16_t softfork) {
                    cb(network_time_offset.count(), hardfork, softfork, ctx);
                };
}

LIBSESSION_C_API void session_network_callbacks_respond(
        network_object* /*network*/,
        session_response_handle_t* response_handle,
        bool success,
        bool timeout,
        int16_t status_code,
        const char* const* headers_,
        const char* const* header_values,
        size_t headers_size,
        const char* body_,
        size_t body_len) {
    if (!response_handle)
        return;

    std::unique_ptr<session_response_handle_cpp_t> handle_edge(response_handle);
    std::vector<std::pair<std::string, std::string>> headers;
    headers.reserve(headers_size);

    if (headers_size > 0)
        for (size_t i = 0; i < headers_size; i++)
            headers.emplace_back(headers_[i], header_values[i]);

    std::optional<std::string> body;
    if (body_len > 0)
        body.emplace(body_, body_len);

    handle_edge->cpp_callback(success, timeout, status_code, std::move(headers), std::move(body));
}

LIBSESSION_C_API CONNECTION_STATUS session_network_get_status(network_object* network) {
    if (!network)
        return CONNECTION_STATUS_UNKNOWN;

    return static_cast<CONNECTION_STATUS>(unbox(network)->get_status());
}

LIBSESSION_C_API void session_network_get_swarm(
        network_object* network,
        const char* swarm_pubkey_hex,
        bool ignore_strike_count,
        void (*callback)(network_service_node* nodes, size_t nodes_len, void*),
        void* ctx) {
    assert(swarm_pubkey_hex && callback);
    unbox(network)->get_swarm(
            x25519_pubkey::from_hex({swarm_pubkey_hex, 64}),
            ignore_strike_count,
            [cb = std::move(callback), ctx](swarm_id_t, std::vector<service_node> nodes) {
                auto c_nodes = convert_service_nodes(nodes);
                cb(c_nodes.data(), c_nodes.size(), ctx);
            });
}

LIBSESSION_C_API void session_network_get_random_nodes(
        network_object* network,
        uint16_t count,
        void (*callback)(network_service_node*, size_t, void*),
        void* ctx) {
    assert(callback);
    unbox(network)->get_random_nodes(
            count, [cb = std::move(callback), ctx](std::vector<service_node> nodes) {
                auto c_nodes = convert_service_nodes(nodes);
                cb(c_nodes.data(), c_nodes.size(), ctx);
            });
}

LIBSESSION_C_API void session_network_send_request(
        network_object* network,
        const session_request_params* params,
        session_network_response_t callback,
        void* ctx) {
    assert(callback);

    try {
        if (!network)
            throw std::invalid_argument("Invalid request: 'network' cannot be null.");
        if (!params)
            throw std::invalid_argument("Invalid request: 'params' cannot be null.");

        network_destination dest;

        if (params->snode_dest && params->server_dest)
            throw std::invalid_argument(
                    "Invalid request: Cannot have both 'snode_dest' and 'server_dest' set.");

        if (params->snode_dest) {
            dest = service_node::from(*params->snode_dest);
        } else if (params->server_dest) {
            const auto& c_server = *params->server_dest;

            std::optional<std::vector<std::pair<std::string, std::string>>> headers;
            if (c_server.headers_kv_pairs && c_server.headers_kv_pairs_len > 0) {
                if (c_server.headers_kv_pairs_len % 2 != 0)
                    throw std::invalid_argument(
                            "Invalid request: Header must have an even number of key-value "
                            "strings.");

                headers.emplace();
                headers->reserve(c_server.headers_kv_pairs_len / 2);
                for (int i = 0; i < c_server.headers_kv_pairs_len; i += 2) {
                    const char* key = c_server.headers_kv_pairs[i];
                    const char* val = c_server.headers_kv_pairs[i + 1];

                    if (!key || !val)
                        throw std::invalid_argument(
                                "Invalid request: Header list contains a null key or value.");

                    headers->emplace_back(key, val);
                }
            }

            dest = ServerDestination{
                    c_server.protocol,
                    c_server.host,
                    x25519_pubkey::from_hex(c_server.x25519_pubkey_hex),
                    (c_server.port > 0 ? std::optional{c_server.port} : std::nullopt),
                    headers,
                    c_server.method};
        } else
            throw std::invalid_argument(
                    "Invalid request: Must have either 'snode_dest' or 'server_dest' set.");

        std::optional<std::vector<std::byte>> body;
        if (params->body && params->body_size > 0)
            body = to_vector(to_byte_span(params->body, params->body_size));

        std::optional<std::string> request_id;
        if (params->request_id)
            request_id = params->request_id;

        auto request = Request{
                dest,
                std::string{params->endpoint},
                body,
                static_cast<RequestCategory>(params->category),
                std::chrono::milliseconds{params->request_timeout_ms},
                (params->overall_timeout_ms > 0
                         ? std::optional{std::chrono::milliseconds{params->overall_timeout_ms}}
                         : std::nullopt),
                std::nullopt,
                request_id};

        std::optional<x25519_pubkey> swarm_pubkey;
        if (params->swarm_pubkey_hex)
            swarm_pubkey = x25519_pubkey::from_hex({params->swarm_pubkey_hex, 64});

        std::optional<std::vector<std::optional<x25519_pubkey>>> batch_accounts;
        if (request.body)
            batch_accounts = batch_request_accounts(request.endpoint, *request.body, swarm_pubkey);
        if (batch_accounts)
            request.swarm_pubkeys = std::move(*batch_accounts);
        else if (swarm_pubkey)
            request.swarm_pubkeys = {*swarm_pubkey};

        auto cpp_callback = [c_cb = callback, c_ctx = ctx](
                                    bool success,
                                    bool timeout,
                                    int16_t status_code,
                                    std::vector<std::pair<std::string, std::string>> headers,
                                    std::optional<std::string> body) {
            std::vector<const char*> c_headers;
            c_headers.reserve(headers.size() * 2 + 1);
            for (const auto& [key, val] : headers) {
                c_headers.push_back(key.c_str());
                c_headers.push_back(val.c_str());
            }
            c_headers.push_back(nullptr);  // NULL terminator

            c_cb(success,
                 timeout,
                 status_code,
                 c_headers.data(),
                 (headers.size() * 2),
                 body ? reinterpret_cast<const unsigned char*>(body->data()) : nullptr,
                 body ? body->size() : 0,
                 c_ctx);
        };

        unbox(network)->send_request(std::move(request), std::move(cpp_callback));
    } catch (const std::exception& e) {
        callback(
                false,
                false,
                -1,
                nullptr,
                0,
                reinterpret_cast<const unsigned char*>(e.what()),
                strlen(e.what()),
                ctx);
    }
}

LIBSESSION_C_API session_upload_handle_t* session_network_upload(
        network_object* network,
        const char* file_name,
        uint64_t ttl,
        const session_upload_callbacks* callbacks,
        int64_t stall_timeout_ms,
        int64_t request_timeout_ms,
        int64_t overall_timeout_ms,
        int8_t desired_path_index) {

    if (!network || !callbacks || !callbacks->next_data)
        return nullptr;

    try {
        auto handle = std::make_unique<session_upload_handle_t>();
        handle->callbacks = *callbacks;

        UploadRequest cpp_request{};
        if (file_name)
            cpp_request.file_name.emplace(file_name);
        if (ttl > 0)
            cpp_request.ttl = std::chrono::seconds{ttl};
        cpp_request.stall_timeout = std::chrono::milliseconds{stall_timeout_ms};
        cpp_request.request_timeout = std::chrono::milliseconds{request_timeout_ms};
        if (overall_timeout_ms > 0)
            cpp_request.overall_timeout.emplace(overall_timeout_ms);

        if (desired_path_index >= 0)
            cpp_request.desired_path_index = static_cast<uint8_t>(desired_path_index);

        const auto next_data_fn = callbacks->next_data;
        const auto on_complete_fn = callbacks->on_complete;
        const auto ctx = callbacks->ctx;

        cpp_request.next_data = [next_data_fn, ctx]() -> std::vector<std::byte> {
            std::vector<std::byte> buffer(64 * 1024);  // 64KB chunks
            size_t bytes = next_data_fn(to_unsigned(buffer.data()), buffer.size(), ctx);

            if (bytes == 0 || bytes == static_cast<size_t>(-1))
                return {};

            buffer.resize(bytes);
            return buffer;
        };

        cpp_request.on_complete = [on_complete_fn,
                                   ctx](std::variant<file_metadata, int16_t> result, bool timeout) {
            std::visit(
                    [&]<typename T>(T& arg) {
                        if constexpr (std::same_as<T, file_metadata>) {
                            session_file_metadata c_meta{};
                            std::strncpy(
                                    c_meta.file_id, arg.id.c_str(), sizeof(c_meta.file_id) - 1);
                            c_meta.file_id[sizeof(c_meta.file_id) - 1] = '\0';
                            c_meta.size = arg.size;
                            c_meta.uploaded_timestamp = epoch_seconds(arg.uploaded);
                            c_meta.expiry_timestamp = epoch_seconds(arg.expiry);

                            on_complete_fn(&c_meta, -1, false, ctx);
                        } else {
                            // int16_t status code
                            on_complete_fn(nullptr, arg, timeout, ctx);
                        }
                    },
                    result);
        };

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        handle->cancelled = cpp_request.cancelled;
        unbox(network)->upload(std::move(cpp_request));
#pragma GCC diagnostic pop

        return handle.release();
    } catch (...) {
        return nullptr;
    }
}

LIBSESSION_C_API session_download_handle_t* session_network_download(
        network_object* network,
        const char* download_url,
        const session_download_callbacks* callbacks,
        int64_t stall_timeout_ms,
        int64_t request_timeout_ms,
        int64_t overall_timeout_ms,
        int8_t desired_path_index) {

    if (!network || !download_url || !callbacks)
        return nullptr;

    try {
        auto handle = std::make_unique<session_download_handle_t>();
        handle->callbacks = *callbacks;

        auto cpp_request = DownloadRequest{};
        cpp_request.download_url = download_url;
        cpp_request.stall_timeout = std::chrono::milliseconds{stall_timeout_ms};
        cpp_request.request_timeout = std::chrono::milliseconds{request_timeout_ms};
        cpp_request.overall_timeout =
                (overall_timeout_ms > 0
                         ? std::optional{std::chrono::milliseconds{overall_timeout_ms}}
                         : std::nullopt);
        if (desired_path_index >= 0)
            cpp_request.desired_path_index = static_cast<uint8_t>(desired_path_index);

        const auto on_data_fn = callbacks->on_data;
        const auto on_complete_fn = callbacks->on_complete;
        const auto ctx = callbacks->ctx;

        if (on_data_fn)
            cpp_request.on_data = [on_data_fn, ctx](
                                          const file_metadata& metadata,
                                          std::span<const std::byte> data) {
                session_file_metadata c_meta{};
                std::strncpy(c_meta.file_id, metadata.id.c_str(), sizeof(c_meta.file_id) - 1);
                c_meta.file_id[sizeof(c_meta.file_id) - 1] = '\0';
                c_meta.size = metadata.size;
                c_meta.uploaded_timestamp = epoch_seconds(metadata.uploaded);
                c_meta.expiry_timestamp = epoch_seconds(metadata.expiry);

                on_data_fn(&c_meta, to_unsigned(data.data()), data.size(), ctx);
            };

        cpp_request.on_complete = [on_complete_fn,
                                   ctx](std::variant<file_metadata, int16_t> result, bool timeout) {
            std::visit(
                    [&](auto&& arg) {
                        using T = std::decay_t<decltype(arg)>;
                        if constexpr (std::is_same_v<T, file_metadata>) {
                            session_file_metadata c_meta{};
                            std::strncpy(
                                    c_meta.file_id, arg.id.c_str(), sizeof(c_meta.file_id) - 1);
                            c_meta.file_id[sizeof(c_meta.file_id) - 1] = '\0';
                            c_meta.size = arg.size;
                            c_meta.uploaded_timestamp = epoch_seconds(arg.uploaded);
                            c_meta.expiry_timestamp = epoch_seconds(arg.expiry);

                            on_complete_fn(&c_meta, -1, false, ctx);
                        } else {
                            // int16_t status code
                            on_complete_fn(nullptr, arg, timeout, ctx);
                        }
                    },
                    result);
        };

        handle->cancelled = cpp_request.cancelled;
        unbox(network)->download(std::move(cpp_request));

        return handle.release();
    } catch (...) {
        return nullptr;
    }
}

LIBSESSION_C_API void session_network_upload_cancel(session_upload_handle_t* handle) {
    if (handle && handle->cancelled)
        *handle->cancelled = true;
}

LIBSESSION_C_API void session_network_download_cancel(session_download_handle_t* handle) {
    if (handle && handle->cancelled)
        *handle->cancelled = true;
}

LIBSESSION_C_API void session_network_upload_free(session_upload_handle_t* handle) {
    delete handle;
}

LIBSESSION_C_API void session_network_download_free(session_download_handle_t* handle) {
    delete handle;
}

}  // extern "C"
