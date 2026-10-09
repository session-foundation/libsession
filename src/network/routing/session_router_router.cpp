#include "session/network/routing/session_router_router.hpp"

#include <fmt/ranges.h>
#include <fmt/std.h>
#include <oxenc/base32z.h>
#include <oxenc/base64.h>

#include <algorithm>
#include <array>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <session/router.hpp>

#include "session/crypto/ed25519.hpp"
#include "session/format.hpp"
#include "session/network/network_opt.hpp"
#include "session/onionreq/builder.hpp"
#include "session/onionreq/response_parser.hpp"
#include "session/random.hpp"

using namespace oxen;
using namespace session;
using namespace session::network;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network {

// Holding the claim is what keeps the tunnel mapped; dropping it releases our hold, and Session
// Router tears the mapping down once nobody else is holding it either.
struct ActiveTunnel {
    session::router::udp_tunnel tunnel;

    // Set once the session behind the mapping is up.  Until then requests wait in
    // `_pending_requests` rather than being written into a mapping with nothing to carry them.
    bool established = false;
};

static std::optional<ed25519_pubkey> pubkey_from_srouter_address(std::string_view address);

// The name Session Router knows a storage node by: its ed25519 pubkey in base32z, plus ".snode".
static std::string srouter_address(std::span<const std::byte, 32> remote_pubkey) {
    return "{:a}.snode"_format(remote_pubkey);
}

// The inner QUIC connection's UDP payload size: the minimum QUIC guarantees every path carries.
// Session Router sends each of its packets in a datagram on its link to the first hop, adding 172
// bytes of framing, so an inner packet goes in one piece as long as that link's path carries 1372
// bytes of UDP payload, which a typical 1500-byte MTU path does with room to spare.  A larger inner
// size would have its packets split in two whenever the link's path carries less than it plus that
// framing, which we can't tell from here; a smaller one would only waste space.
static constexpr size_t TUNNELED_QUIC_MAX_UDP_PAYLOAD = 1200;

namespace {
    auto cat = oxen::log::Cat("session-router");

    static constexpr std::string_view PROXIED_REQUESTS_KEY{"proxied_requests"};

    std::string pending_request_key(const network_destination& dest) {
        std::optional<std::string> key;

        std::visit(
                [&key]<typename T>(const T& arg) {
                    if constexpr (
                            std::is_same_v<T, oxen::quic::RemoteAddress> ||
                            std::is_same_v<T, service_node>) {
                        key = oxenc::to_hex(arg.view_remote_key());
                    } else {
                        static_assert(std::is_same_v<T, ServerDestination>);
                        key = PROXIED_REQUESTS_KEY;
                    }
                },
                dest);

        if (!key)
            throw std::runtime_error{"Invalid destination"};

        return *key;
    }

    std::pair<std::span<const std::byte, 32>, uint16_t> remote_info_for_destination(
            const network_destination& dest, const std::string& request_id) {
        std::optional<std::pair<std::span<const std::byte, 32>, uint16_t>> result;

        std::visit(
                [&result, &request_id]<typename T>(const T& arg) {
                    if constexpr (std::is_same_v<T, oxen::quic::RemoteAddress>) {
                        log::trace(
                                cat, "[Request {}]: Using pre-resolved RemoteAddress.", request_id);
                        result.emplace(
                                as_span(arg.view_remote_key()).template first<32>(), arg.port());
                    } else if constexpr (std::is_same_v<T, service_node>) {
                        log::trace(
                                cat,
                                "[Request {}]: Resolving service_node to RemoteAddress.",
                                request_id);
                        result.emplace(arg.view_remote_key(), arg.omq_port);
                    }
                },
                dest);

        if (!result)
            throw std::runtime_error{"Invalid destination"};

        return *result;
    }

}  // namespace

std::shared_ptr<SessionRouter> SessionRouter::make(
        config::SessionRouter config,
        std::shared_ptr<oxen::quic::Loop> loop,
        std::weak_ptr<SnodePool> snode_pool,
        std::weak_ptr<ITransport> transport) {
    // Need a factory constructor because we want to call `weak_from_this` during the initial set
    // (which isn't supported during construction), this approach allows us to do so
    auto result = std::shared_ptr<SessionRouter>(
            new SessionRouter(std::move(config), loop, snode_pool, transport));
    result->_init();
    return result;
}

SessionRouter::SessionRouter(
        config::SessionRouter config,
        std::shared_ptr<oxen::quic::Loop> loop,
        std::weak_ptr<SnodePool> snode_pool,
        std::weak_ptr<ITransport> transport) :
        _config{std::move(config)}, _loop{loop}, _snode_pool{snode_pool}, _transport{transport} {}

void SessionRouter::_init() {
    log::trace(cat, "Initializing.");

    // "listen=:0" listens on a random port - this prevents multiple test devices on the same
    // machine from trying to listen on the same port and colliding
    auto test_ini = R"(
    [router]
    netid={}
    data-dir={}
    [bind]
    listen=:0
    )"_format(opt::netid::to_string(_config.netid), _config.cache_directory);

    try {
        _update_status(ConnectionStatus::connecting);

        srouter = std::make_shared<session::router::SessionRouter>(test_ini, _loop);
        srouter->on_connected(
                [weak_self = weak_from_this(), this] {
                    auto self = weak_self.lock();
                    if (!self)
                        return;

                    auto snode_pool = _snode_pool.lock();
                    if (!snode_pool)
                        return;

                    if (snode_pool->size() == 0)
                        // The pool outlives us, so this one keeps its weak guard.
                        snode_pool->refresh_if_needed({}, [weak_self, this](bool refreshed) {
                            // Setup finishes either way: not finishing leaves the router
                            // permanently unusable, where finishing with an empty pool just means
                            // the first request refreshes again
                            if (!refreshed)
                                log::warning(
                                        cat,
                                        "Finishing router setup without a refreshed snode pool.");

                            if (auto self = weak_self.lock())
                                _jq.call([this] { _finish_setup(); });
                        });
                    else
                        _finish_setup();
                },
                /*with_path*/ true,
                /*persist*/ false);
    } catch (const std::exception& e) {
        log::error(cat, "Failed to start ({}).", e.what());
        _update_status(ConnectionStatus::disconnected);
        throw;
    }
}

SessionRouter::~SessionRouter() {
    std::vector<std::thread> threads_to_join;

    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this, &threads_to_join] {
        // Harvest upload thread handles *before* _close_connections clears the map
        for (auto& [_, upload] : _active_uploads)
            if (upload.second.joinable())
                threads_to_join.push_back(std::move(upload.second));

        _close_connections();
    });

    // Block until upload threads have finished.  These wait on loop jobs of their own, so this has
    // to happen out here rather than inside the job above -- and it is why this object must be
    // destroyed off the loop thread: joining from the loop would be waiting on ourselves.
    for (auto& t : threads_to_join)
        if (t.joinable())
            t.join();

    // Only once nothing can post any more: a post to a stopped queue throws, and a throw on one of
    // those upload threads would be a terminate.
    _loop->call_get([this] { _jq.stop(); });

    log::debug(cat, "Destroyed.");
}

// MARK: IRouter

void SessionRouter::suspend() {
    // Use 'call_get' to force this to be synchronous
    _jq.call_get([this] {
        _suspended = true;
        _close_connections();
        log::info(cat, "Suspended.");
    });
}

void SessionRouter::resume(bool /*automatically_reconnect*/) {
    // Use 'call_get' to force this to be synchronous
    _jq.call_get([this] {
        if (!_suspended)
            return;

        _suspended = false;
        log::info(cat, "Resumed.");
    });
}

void SessionRouter::close_connections() {
    // Use 'call_get' to force this to be synchronous
    _jq.call_get([this] { _close_connections(); });
}

void SessionRouter::clear_cache() {
    // TODO: Implement this.
}

std::optional<PathInfo> SessionRouter::get_path_to(const service_node& node) {
    if (!srouter)
        return std::nullopt;

    // Deliberately the single-session lookup rather than get_all_session_paths(): we hold a
    // session to every swarm member we have spoken to, to the file server, and to every group's
    // swarm, and reporting all of them answers a question nobody asked.
    auto path = srouter->get_path_for_session(srouter_address(node.remote_pubkey));
    if (!path)
        return std::nullopt;

    PathInfo info;
    info.hops.reserve(path->hops.size());

    for (const auto& [address, ip] : path->hops) {
        auto pubkey = pubkey_from_srouter_address(address);
        if (!pubkey) {
            log::warning(cat, "Omitting path hop with an unparseable address: {}", address);
            continue;
        }

        try {
            info.hops.push_back({*pubkey, oxen::quic::ipv4{ip}});
        } catch (const std::exception& e) {
            log::warning(cat, "Omitting path hop {} with an unparseable ip {}", address, ip);
        }
    }

    return info;
}

void SessionRouter::send_request(Request request, network_response_callback_t callback) {
    _jq.call([this, req = std::move(request), cb = std::move(callback)]() mutable {
        _send_request_internal(std::move(req), std::move(cb));
    });
}

void SessionRouter::upload(UploadRequest request) {
    _jq.call([this, req = std::move(request)]() mutable { _upload_internal(std::move(req)); });
}

void SessionRouter::upload_file(FileUploadRequest request, std::span<const std::byte> seed) {
    auto quic_target = file_server::default_quic_target(_config.file_server_config, _config.netid);
    if (!quic_target) {
        // TODO: legacy file upload fallback
        if (request.on_complete)
            request.on_complete(ERROR_FILE_SERVER_UNAVAILABLE, false);
        return;
    }

    // Construct the Encryptor now (on the caller's thread), consuming the seed.
    auto enc = std::make_shared<attachment::Encryptor>(seed, request.domain);
    auto target = std::move(*quic_target);

    // Dispatch to the loop thread so we wait for _ready before spawning the upload thread.
    _jq.call([this,
              enc = std::move(enc),
              request = std::move(request),
              target = std::move(target)]() mutable {
        if (!_ready) {
            log::debug(cat, "Router not ready, queueing upload_file.");
            // _pending_operations is ours and is run from our own jobs, so `this` is safe here too.
            _pending_operations.emplace_back([this,
                                              enc = std::move(enc),
                                              request = std::move(request),
                                              target = std::move(target)]() mutable {
                _start_file_upload(std::move(enc), std::move(request), std::move(target));
            });
            return;
        }

        _start_file_upload(std::move(enc), std::move(request), std::move(target));
    });
}

void SessionRouter::_start_file_upload(
        std::shared_ptr<attachment::Encryptor> enc,
        FileUploadRequest request,
        file_server::SRouterTarget target) {
    const std::string upload_id = random::unique_id("UPL");
    auto& upload_thread =
            _active_uploads.emplace(upload_id, std::make_pair(UploadRequest{}, std::thread{}))
                    .first->second.second;

    upload_thread = std::thread([weak_self = weak_from_this(),
                                 this,
                                 enc = std::move(enc),
                                 request = std::move(request),
                                 target = std::move(target),
                                 upload_id]() mutable {
        // The get_client callback runs on the loop thread: it establishes the tunnel
        // and returns the QuicFileClient.  This blocks (via promise/future) until the
        // tunnel is established.
        auto client_promise = std::make_shared<std::promise<QuicFileClient*>>();
        auto client_future = client_promise->get_future();

        streaming_file_upload(
                _loop,
                std::move(*enc),
                std::move(request),
                [weak_self, this, target, client_promise]() -> QuicFileClient* {
                    auto self = weak_self.lock();
                    if (!self)
                        return nullptr;

                    // The claim is kept alongside the other tunnels rather than in a local: the
                    // file client goes on using this port long after this function has returned.
                    //
                    // establish_udp does not block -- the port mapping is local, so local_port is
                    // usable on return -- but the session behind it may not be up yet.  Sending
                    // into a mapping with nothing behind it means the QUIC handshake's packets are
                    // dropped and retried on QUIC's own timer, which is where a cold upload spends
                    // seconds doing nothing.  So the callbacks are taken: `established` is what
                    // says the mapping now carries traffic, and a failure is reported rather than
                    // waited out -- an unreachable relay is known immediately and there is no
                    // point spending the request timeout discovering it again.
                    auto& held = _tunnel(target.address);
                    if (!held.tunnel) {
                        auto address = target.address;
                        held.tunnel = srouter->establish_udp(
                                target.address,
                                target.port,
                                [weak_self, this, address](router::tunnel_info) {
                                    if (auto self = weak_self.lock())
                                        _tunnel(address).established = true;
                                },
                                [weak_self, this, address](router::tunnel_failure failure) {
                                    auto self = weak_self.lock();
                                    if (!self)
                                        return;
                                    log::error(
                                            cat,
                                            "File server {} is {}.",
                                            address,
                                            failure == router::tunnel_failure::unreachable
                                                    ? "unreachable"
                                                    : "not responding");
                                    // Drops the claim, so the next attempt builds a fresh mapping
                                    // rather than reusing one known to carry nothing.
                                    _fail_tunnel(
                                            address,
                                            failure == router::tunnel_failure::unreachable);
                                });
                    }
                    if (!held.tunnel) {
                        log::error(cat, "File server {} is unreachable.", target.address);
                        return nullptr;
                    }

                    auto pubkey = pubkey_from_srouter_address(held.tunnel->remote);
                    if (!pubkey)
                        return nullptr;

                    return &_get_file_client(
                            *pubkey, "::1", held.tunnel->local_port, TUNNELED_QUIC_MAX_UDP_PAYLOAD);
                });

        _jq.call([this, upload_id] { _cleanup_upload(upload_id); });
    });
}

void SessionRouter::download(DownloadRequest request) {
    _jq.call([this, req = std::move(request)]() mutable { _download_internal(std::move(req)); });
}

// MARK: Internal Logic

void SessionRouter::_finish_setup() {
    // Start processing requests
    _ready = true;
    log::debug(cat, "Finishing setup, router is now ready.");

    auto requests_to_process = std::move(_pending_requests);
    auto ops_to_process = std::move(_pending_operations);

    size_t pending_count = ops_to_process.size();
    for (auto& [_, reqs] : requests_to_process)
        pending_count += reqs.size();

    if (pending_count == 0)
        return;

    log::debug(cat, "Processing {} operations queued during initialization.", pending_count);

    for (auto& [address, requests] : requests_to_process) {
        if (!requests.empty()) {
            log::debug(
                    cat, "Processing {} queued requests for address {}.", requests.size(), address);

            for (auto&& [req, cb] : std::move(requests))
                _send_request_internal(std::move(req), std::move(cb));
        }
    }

    for (auto& op : ops_to_process)
        op();
}

void SessionRouter::_close_connections() {
    // Cancel any uploads and downloads
    for (auto& [id, request_and_thread] : _active_uploads) {
        request_and_thread.first.cancel();

        if (request_and_thread.first.on_complete)
            request_and_thread.first.on_complete(ERROR_CONNECTION_CLOSED, false);
    }

    for (auto& [id, request] : _active_downloads) {
        request.cancel();

        if (request.on_complete)
            request.on_complete(ERROR_CONNECTION_CLOSED, false);
    }

    _active_uploads.clear();
    _active_downloads.clear();

    // Cancel any pending requests (they can't succeed once the connection is closed)
    for (const auto& [pubkey, pupkey_requests] : _pending_requests)
        for (const auto& [info, callback] : pupkey_requests)
            callback(
                    false,
                    false,
                    ERROR_NETWORK_SUSPENDED,
                    {content_type_plain_text},
                    "Network is suspended.");

    // Clear all storage of requests, paths and connections so that we are in a fresh state on
    // relaunch; dropping our claims releases the tunnels behind them.
    _active_tunnels.clear();
    _pending_requests.clear();
    _update_status(ConnectionStatus::disconnected);
    log::info(cat, "Closed all connections.");
}

void SessionRouter::_update_status(ConnectionStatus new_status) {
    ConnectionStatus old_status = _status.load();
    if (old_status == new_status)
        return;

    _status.store(new_status);

    if (on_status_changed)
        on_status_changed();
}

void SessionRouter::_send_request_internal(Request request, network_response_callback_t callback) {
    // If we are suspended then fail immediately
    if (_suspended)
        return callback(
                false,
                false,
                ERROR_NETWORK_SUSPENDED,
                {content_type_plain_text},
                "SessionRouter is suspended.");

    // Queue the request if we aren't ready
    auto key = pending_request_key(request.destination);

    if (!_ready) {
        log::debug(cat, "[Request {}]: Router not ready, queueing request.", request.request_id);

        // Queue the request if not ready. We need the pubkey hex as the key.
        try {
            _pending_requests[key].emplace_back(std::move(request), std::move(callback));
        } catch (const std::exception& e) {
            log::critical(
                    cat,
                    "[Request {}]: Dropping after failure to queue due to error: {}.",
                    request.request_id,
                    e.what());
            return callback(
                    false,
                    false,
                    ERROR_FAILED_TO_QUEUE_REQUEST,
                    {content_type_plain_text},
                    e.what());
        }
        return;
    }

    // If the request is being sent to a `ServerDestination` then we need to make a proxied request
    // instead
    if (std::holds_alternative<ServerDestination>(request.destination)) {
        log::debug(
                cat,
                "[Request {}]: Destination is a server, finding a proxy node.",
                request.request_id);
        _send_proxy_request(std::move(request), std::move(callback));
        return;
    }

    // When sending a direct request the response will be a json array of [{status_code}, {body}] so
    // we need to process that before triggering the callback
    auto json_parsing_callback =
            [cb = std::move(callback)](
                    bool success, bool timeout, int16_t status_code_, auto headers, auto response) {
                if (!response)
                    return cb(success, timeout, status_code_, headers, response);

                // If the response isn't JSON then just return it directly
                if (!nlohmann::json::accept(*response))
                    return cb(success, timeout, status_code_, headers, *response);

                try {
                    nlohmann::json response_json = nlohmann::json::parse(*response);

                    if (!response_json.is_array() || response_json.size() != 2)
                        throw std::runtime_error{"Unexpected JSON response structure."};

                    uint16_t status_code = response_json[0].get<uint16_t>();
                    std::string data = response_json[1].dump();
                    return cb(success, timeout, status_code, headers, data);
                } catch (const std::exception& e) {
                    return cb(false, timeout, status_code_, {content_type_plain_text}, e.what());
                }
            };

    _send_direct_request(std::move(request), std::move(json_parsing_callback));
}

void SessionRouter::_send_direct_request(Request request, network_response_callback_t callback) {
    // Both the request and the callback are handed off partway through -- to _send_via_tunnel, or
    // to the pending queue -- so nothing after that point may touch either one, the error handler
    // included.  A moved-from std::function is valid but unspecified rather than guaranteed empty,
    // so `if (callback)` is not a safe test; track the hand-off instead.  Keep the id and the key
    // in locals of our own for the same reason: they are what the error path has left to report.
    std::string req_id = request.request_id;
    std::string remote_pubkey_hex;
    bool handed_off = false;

    try {
        if (std::holds_alternative<ServerDestination>(request.destination))
            throw std::runtime_error{"Attempted to send server request directly"};

        auto [remote_pubkey_view, remote_port] =
                remote_info_for_destination(request.destination, req_id);

        // Copy the key out rather than carrying the view: it points into request.destination, and
        // for a RemoteAddress destination that is a vector whose buffer the queued copy takes
        // ownership of below -- so the view outlives its owner, and _fail_tunnel erasing that queue
        // entry would free the bytes while _establish_tunnel is still reading them.
        std::array<std::byte, 32> remote_pubkey;
        std::ranges::copy(remote_pubkey_view, remote_pubkey.begin());
        remote_pubkey_hex = oxenc::to_hex(remote_pubkey);

        if (auto it = _active_tunnels.find(remote_pubkey_hex);
            it != _active_tunnels.end() && it->second->established) {
            log::trace(cat, "[Request {}] Found active tunnel.", req_id);
            handed_off = true;
            _send_via_tunnel(
                    it->second->tunnel->remote,
                    it->second->tunnel->local_port,
                    std::move(request),
                    std::move(callback));
            return;
        }

        // Add the request to the pending queue to be picked up once we have a tunnel for it
        handed_off = true;
        _pending_requests[remote_pubkey_hex].emplace_back(std::move(request), std::move(callback));

        // If there is only a single pending request then we wouldn't have started establishing a
        // tunnel
        if (_pending_requests.at(remote_pubkey_hex).size() == 1) {
            log::info(
                    cat,
                    "[Request {}] No tunnel to {}, initiating new tunnel.",
                    req_id,
                    remote_pubkey_hex);
            _establish_tunnel(remote_pubkey, remote_port, req_id);
        } else
            log::debug(
                    cat,
                    "[Request {}] Tunnel to {} is pending, queueing request.",
                    req_id,
                    remote_pubkey_hex);
    } catch (const std::exception& e) {
        log::error(cat, "[Request {}] Failed to send request due to error: {}", req_id, e.what());

        // Once queued, the queue owns the callback and _fail_tunnel is what reports the error --
        // to every other request waiting on the same tunnel as well, which calling the one callback
        // here would have left stranded.
        if (handed_off)
            return _fail_tunnel(remote_pubkey_hex, true);

        return callback(
                false,
                false,
                ERROR_INVALID_DESTINATION,
                {content_type_plain_text},
                "Failed to send request due to error: {}"_format(e.what()));
    }
}

void SessionRouter::_send_proxy_request(Request request, network_response_callback_t callback) {
    auto snode_pool = _snode_pool.lock();
    if (!snode_pool) {
        return callback(
                false,
                false,
                ERROR_NO_SNODE_POOL,
                {content_type_plain_text},
                "SnodePool was destroyed, cannot find proxy.");
    }

    auto proxy_nodes = snode_pool->get_unused_nodes(1);

    if (proxy_nodes.empty()) {
        log::warning(
                cat,
                "[Request {}]: No available proxy nodes, waiting for SnodePool refresh.",
                request.request_id);

        snode_pool->refresh_if_needed(
                {},
                [weak_self = weak_from_this(),
                 this,
                 req = std::move(request),
                 cb = std::move(callback)](bool refreshed) {
                    auto self = weak_self.lock();
                    if (!self)
                        return;

                    if (!refreshed)
                        return cb(
                                false,
                                false,
                                ERROR_INSUFFICIENT_NODES,
                                {content_type_plain_text},
                                "Failed to refresh the snode pool to find a proxy.");

                    auto snode_pool = _snode_pool.lock();
                    if (!snode_pool)
                        return cb(
                                false,
                                false,
                                ERROR_NO_SNODE_POOL,
                                {content_type_plain_text},
                                "SnodePool was destroyed, cannot find proxy.");

                    if (snode_pool->get_unused_nodes(1).empty())
                        return cb(
                                false,
                                false,
                                ERROR_INSUFFICIENT_NODES,
                                {content_type_plain_text},
                                "SnodePool refresh failed.");

                    log::info(
                            cat,
                            "[Request {}]: SnodePool refresh complete, retrying proxy selection.",
                            req.request_id);
                    _send_proxy_request(std::move(req), std::move(cb));
                });
        return;
    }

    service_node proxy_node = proxy_nodes[0];
    std::vector<std::byte> encrypted_blob;
    std::shared_ptr<onionreq::ResponseParser> parser;
    log::debug(
            cat, "[Request {}]: Selected {} as proxy.", request.request_id, proxy_node.to_string());

    try {
        std::vector<service_node> proxy_path = {proxy_node};
        auto builder = onionreq::Builder(request.destination, request.endpoint, proxy_path);
        encrypted_blob = builder.generate_onion_blob(request.body);
        parser = std::make_shared<onionreq::ResponseParser>(builder);
    } catch (const std::exception& e) {
        log::warning(
                cat,
                "[Request {}]: Failed to build proxy request payload: {}",
                request.request_id,
                e.what());
        return callback(
                false,
                false,
                ERROR_FAILED_GENERATE_ONION_PAYLOAD,
                {content_type_plain_text},
                "Failed to build proxy request");
    }

    Request proxy_request{
            request.request_id,
            network_destination{proxy_node},  // Send to the proxy node
            std::string{"onion_req"},         // Send to onion request handling endpoint
            std::move(encrypted_blob),        // Encrypted payload
            request.category,
            request.time_remaining(),
            request.overall_timeout};

    auto proxy_callback = [parser = std::move(parser), cb = std::move(callback)](
                                  bool success,
                                  bool timeout,
                                  int16_t status,
                                  auto headers,
                                  auto response) {
        try {
            if (!success)
                throw std::runtime_error{response.value_or("Unknown request failure")};
            if (timeout)
                throw std::runtime_error{response.value_or("Timed out")};
            if (!response)
                throw std::runtime_error{"Unexpected empty response"};

            onionreq::DecryptedResponse decrypted = parser->decrypted_response(*response);
            cb(true,
               false,
               decrypted.status_code,
               std::move(decrypted.headers),
               std::move(decrypted.body));
        } catch (const std::exception& e) {
            cb(false,
               timeout,
               response::undecrypted_status(status),
               std::move(headers),
               "Failed to handle proxied request response (status {}) due to error: {}"_format(
                       status, e.what()));
        }
    };

    // Now that we have a service_node destination we can send a direct request
    _send_direct_request(std::move(proxy_request), std::move(proxy_callback));
}

// Extracts the Ed25519 pubkey from a resolved session-router address like "b32zpubkey.sesh"
// or "b32zpubkey.snode".  Returns nullopt if the address is not a valid pubkey-based address.
static std::optional<ed25519_pubkey> pubkey_from_srouter_address(std::string_view address) {
    auto dot = address.find('.');
    if (dot == std::string_view::npos || dot == 0)
        return std::nullopt;

    auto b32z = address.substr(0, dot);
    if (!oxenc::is_base32z(b32z) || oxenc::from_base32z_size(b32z.size()) != 32)
        return std::nullopt;

    std::optional<ed25519_pubkey> result{std::in_place};
    oxenc::from_base32z(b32z.begin(), b32z.end(), result->begin());

    // The length and alphabet checks above only establish that the label decodes to 32 bytes; the
    // address names a router by its Ed25519 pubkey, so 32 bytes that are not one do not name
    // anything.  The caller hands this straight to a file client as the remote's identity key.
    if (!ed25519::is_valid_pubkey(*result))
        return std::nullopt;

    return result;
}

void SessionRouter::_cleanup_upload(const std::string& upload_id) {
    auto node = _active_uploads.extract(upload_id);
    if (!node.empty()) {
        auto& thread = node.mapped().second;
        if (thread.joinable())
            thread.join();
    }
}

QuicFileClient& SessionRouter::_get_file_client(
        const ed25519_pubkey& pubkey,
        std::string_view address,
        uint16_t port,
        std::optional<size_t> max_udp_payload) {
    auto [it, inserted] = _file_clients.try_emplace(pubkey, nullptr);
    if (inserted)
        it->second = std::make_unique<QuicFileClient>(
                _loop, pubkey, std::string{address}, port, max_udp_payload);
    else
        it->second->set_target(pubkey, std::string{address}, port);
    return *it->second;
}

void SessionRouter::_quic_upload_via_tunnel(
        UploadRequest upload_request,
        std::string upload_id,
        std::vector<std::byte> data,
        router::tunnel_info info) {
    auto pubkey = pubkey_from_srouter_address(info.remote);
    if (!pubkey) {
        log::error(
                cat,
                "[Upload {}]: Could not extract pubkey from resolved address {}",
                upload_id,
                info.remote);
        upload_request.on_complete(ERROR_UNKNOWN, false);
        _cleanup_upload(upload_id);
        return;
    }

    _get_file_client(*pubkey, "::1", info.local_port, TUNNELED_QUIC_MAX_UDP_PAYLOAD)
            .upload(std::move(data),
                    upload_request.ttl,
                    [weak_self = weak_from_this(), this, upload_request, upload_id](
                            std::variant<file_metadata, int16_t> result) {
                        auto self = weak_self.lock();
                        if (!self)
                            return;

                        if (auto* meta = std::get_if<file_metadata>(&result))
                            log::info(
                                    cat, "[Upload {}]: Success, file ID: {}", upload_id, meta->id);
                        else
                            log::error(
                                    cat,
                                    "[Upload {}]: Failed with error {}",
                                    upload_id,
                                    std::get<int16_t>(result));

                        upload_request.on_complete(std::move(result), false);
                        _cleanup_upload(upload_id);
                    });
}

void SessionRouter::_quic_download_via_tunnel(
        DownloadRequest request,
        std::string download_id,
        std::string file_id,
        router::tunnel_info info) {
    auto pubkey = pubkey_from_srouter_address(info.remote);
    if (!pubkey) {
        log::error(
                cat,
                "[Download {}]: Could not extract pubkey from resolved address {}",
                download_id,
                info.remote);
        _active_downloads.erase(download_id);
        request.on_complete(ERROR_UNKNOWN, false);
        return;
    }

    _get_file_client(*pubkey, "::1", info.local_port, TUNNELED_QUIC_MAX_UDP_PAYLOAD)
            .download(
                    std::move(file_id),
                    request.on_data,
                    [weak_self = weak_from_this(), this, request, download_id](
                            std::variant<file_metadata, int16_t> result) {
                        auto self = weak_self.lock();
                        if (!self)
                            return;

                        _active_downloads.erase(download_id);

                        if (auto* meta = std::get_if<file_metadata>(&result))
                            log::info(
                                    cat,
                                    "[Download {}]: Success, file ID: {} ({} bytes)",
                                    download_id,
                                    meta->id,
                                    meta->size);
                        else
                            log::error(
                                    cat,
                                    "[Download {}]: Failed with error {}",
                                    download_id,
                                    std::get<int16_t>(result));

                        request.on_complete(std::move(result), false);
                    },
                    request.cancelled);
}

void SessionRouter::_upload_internal(UploadRequest request) {
    if (!_ready) {
        log::debug(cat, "Router not ready, queueing upload.");
        _pending_operations.emplace_back(
                [weak_self = weak_from_this(), req = std::move(request)]() mutable {
                    if (auto self = weak_self.lock())
                        self->_upload_internal(std::move(req));
                });
        return;
    }

    const std::string upload_id = random::unique_id("UP");
    log::info(cat, "[Upload {}]: Starting upload.", upload_id);

    request.on_complete = make_callback_atomic(std::move(request.on_complete));

    auto quic_target = file_server::default_quic_target(_config.file_server_config, _config.netid);
    if (!quic_target) {
        _upload_internal_legacy(std::move(request), std::move(upload_id));
        return;
    }

    // QUIC upload: accumulate data on background thread, then tunnel and upload
    auto& upload_thread = _active_uploads.emplace(upload_id, std::make_pair(request, std::thread{}))
                                  .first->second.second;

    upload_thread = std::thread([weak_self = weak_from_this(),
                                 this,
                                 upload_request = request,
                                 upload_id,
                                 target = std::move(*quic_target)] {
        auto self = weak_self.lock();
        if (!self)
            return;

        try {
            std::vector<std::byte> all_data;
            while (true) {
                if (upload_request.is_cancelled())
                    throw cancellation_exception{"Cancelled during data accumulation."};
                auto chunk = upload_request.next_data();
                if (chunk.empty())
                    break;
                auto* p = reinterpret_cast<const std::byte*>(chunk.data());
                all_data.insert(all_data.end(), p, p + chunk.size());
            }

            if (all_data.empty())
                throw std::runtime_error{"No data to upload"};

            log::debug(
                    cat,
                    "[Upload {}]: Accumulated {} bytes, establishing tunnel to {}.",
                    upload_id,
                    all_data.size(),
                    target.address);

            _jq.call([this,
                      upload_request,
                      upload_id,
                      target,
                      data = std::move(all_data)]() mutable {
                if (upload_request.is_cancelled()) {
                    upload_request.on_complete(ERROR_REQUEST_CANCELLED, false);
                    _cleanup_upload(upload_id);
                    return;
                }

                auto& held = _tunnel(target.address);
                held.tunnel = srouter->establish_udp(
                        target.address,
                        target.port,
                        [weak_self = weak_from_this(),
                         this,
                         upload_request,
                         upload_id,
                         data = std::move(data)](router::tunnel_info info) mutable {
                            if (auto self = weak_self.lock())
                                _quic_upload_via_tunnel(
                                        upload_request,
                                        upload_id,
                                        std::move(data),
                                        std::move(info));
                        },
                        [weak_self = weak_from_this(), this, upload_request, upload_id](
                                router::tunnel_failure failure) {
                            if (auto self = weak_self.lock()) {
                                bool timeout = failure == router::tunnel_failure::timeout;
                                log::error(
                                        cat,
                                        "[Upload {}]: Tunnel establishment failed: {}.",
                                        upload_id,
                                        timeout ? "timed out" : "remote is unreachable");
                                upload_request.on_complete(
                                        timeout ? ERROR_BUILD_TIMEOUT : ERROR_INVALID_DESTINATION,
                                        timeout);
                                _cleanup_upload(upload_id);
                            }
                        });
                if (!held.tunnel) {
                    // Neither callback fires when the remote is unreachable, so this is the only
                    // chance to report it.
                    log::error(cat, "[Upload {}]: {} is unreachable.", upload_id, target.address);
                    upload_request.on_complete(ERROR_INVALID_DESTINATION, false);
                    _cleanup_upload(upload_id);
                }
            });
        } catch (const cancellation_exception&) {
            _jq.call([this, upload_request, upload_id] {
                upload_request.on_complete(ERROR_REQUEST_CANCELLED, false);
                _cleanup_upload(upload_id);
            });
        } catch (const std::exception& e) {
            log::error(cat, "[Upload {}]: Exception: {}", upload_id, e.what());
            _jq.call([this, upload_request, upload_id] {
                upload_request.on_complete(ERROR_UNKNOWN, false);
                _cleanup_upload(upload_id);
            });
        }
    });
}

// Legacy HTTP-based upload path, used when no QUIC file server target is available.
void SessionRouter::_upload_internal_legacy(UploadRequest request, std::string upload_id) {
    auto& upload_thread = _active_uploads.emplace(upload_id, std::make_pair(request, std::thread{}))
                                  .first->second.second;

    // Ours, and joined before the queue is stopped -- see ~SessionRouter.
    upload_thread = std::thread([this,
                                 upload_request = request,
                                 upload_id,
                                 file_server_config = _config.file_server_config] {
        try {
            Request request =
                    file_server::to_request(upload_id, file_server_config, upload_request);

            _jq.call([this, upload_request, req = std::move(request), upload_id]() mutable {
                if (upload_request.is_cancelled() || !req.body) {
                    log::debug(cat, "[Upload {}]: Cancelled before sending request.", upload_id);
                    upload_request.on_complete(ERROR_REQUEST_CANCELLED, false);
                    _cleanup_upload(upload_id);
                    return;
                }

                const auto upload_size = req.body->size();
                log::debug(
                        cat,
                        "[Upload {}]: Accumulated {} bytes, building request.",
                        upload_id,
                        upload_size);

                _send_request_internal(
                        std::move(req),
                        // Ends up held by the transport, which outlives us: weak guard.
                        [weak_self = weak_from_this(),
                         this,
                         upload_id,
                         upload_request,
                         upload_size](
                                bool success,
                                bool timeout,
                                int16_t status_code,
                                std::vector<std::pair<std::string, std::string>> headers,
                                std::optional<std::string> body) {
                            auto self = weak_self.lock();
                            if (!self)
                                return;

                            _cleanup_upload(upload_id);

                            try {
                                if (upload_request.is_cancelled())
                                    throw cancellation_exception{"Cancelled during request."};

                                if (!success || timeout)
                                    throw status_code_exception{
                                            status_code,
                                            headers,
                                            fmt::format(
                                                    "Request failed with status {}, timeout={}.",
                                                    status_code,
                                                    timeout)};

                                if (!body)
                                    throw std::runtime_error{"No response body."};

                                auto metadata =
                                        file_server::parse_upload_response(*body, upload_size);
                                log::info(
                                        cat,
                                        "[Upload {}]: Successfully uploaded {} bytes as file ID: "
                                        "{}",
                                        upload_id,
                                        metadata.size,
                                        metadata.id);

                                upload_request.on_complete(std::move(metadata), false);
                            } catch (const cancellation_exception&) {
                                log::error(cat, "[Upload {}]: Cancelled", upload_id);
                                upload_request.on_complete(ERROR_REQUEST_CANCELLED, false);
                            } catch (const status_code_exception& e) {
                                log::error(
                                        cat,
                                        "[Upload {}]: Failure with error: {}",
                                        upload_id,
                                        e.what());
                                upload_request.on_complete(e.status_code, false);
                            } catch (const std::exception& e) {
                                log::error(
                                        cat,
                                        "[Upload {}]: Failure with error: {}",
                                        upload_id,
                                        e.what());
                                upload_request.on_complete(ERROR_UNKNOWN, false);
                            }
                        });
            });
        } catch (const std::exception& e) {
            log::error(cat, "[Upload {}]: Exception during upload: {}", upload_id, e.what());

            _jq.call([this, upload_request, upload_id] {
                _cleanup_upload(upload_id);
                upload_request.on_complete(ERROR_UNKNOWN, false);
            });
        }
    });
}

void SessionRouter::_download_internal(DownloadRequest request) {
    if (!_ready) {
        log::debug(cat, "Router not ready, queueing download.");
        _pending_operations.emplace_back(
                [weak_self = weak_from_this(), req = std::move(request)]() mutable {
                    if (auto self = weak_self.lock())
                        self->_download_internal(std::move(req));
                });
        return;
    }

    const std::string download_id = random::unique_id("DL");
    log::info(cat, "[Download {}]: Starting download.", download_id);

    request.on_complete = make_callback_atomic(std::move(request.on_complete));

    // Check for a QUIC target: first from the URL's sr= fragment, then from default mapping
    std::optional<file_server::SRouterTarget> quic_target;
    auto download_info = file_server::parse_download_url(request.download_url);
    if (download_info && download_info->srouter_target)
        quic_target = std::move(download_info->srouter_target);
    else
        quic_target = file_server::default_quic_target(_config.file_server_config, _config.netid);

    if (!quic_target || !download_info) {
        _download_internal_legacy(std::move(request), std::move(download_id));
        return;
    }

    // QUIC download path
    _active_downloads[download_id] = request;
    auto file_id = download_info->file_id;

    auto& held = _tunnel(quic_target->address);
    held.tunnel = srouter->establish_udp(
            quic_target->address,
            quic_target->port,
            [weak_self = weak_from_this(), this, request, download_id, file_id](
                    router::tunnel_info info) mutable {
                if (auto self = weak_self.lock())
                    _quic_download_via_tunnel(
                            request, download_id, std::move(file_id), std::move(info));
            },
            [weak_self = weak_from_this(), this, request, download_id](
                    router::tunnel_failure failure) {
                if (auto self = weak_self.lock()) {
                    bool timeout = failure == router::tunnel_failure::timeout;
                    log::error(
                            cat,
                            "[Download {}]: Tunnel establishment failed: {}.",
                            download_id,
                            timeout ? "timed out" : "remote is unreachable");
                    _active_downloads.erase(download_id);
                    request.on_complete(
                            timeout ? ERROR_BUILD_TIMEOUT : ERROR_INVALID_DESTINATION, timeout);
                }
            });
    if (!held.tunnel) {
        // Neither callback fires when the remote is unreachable, so this is the only chance to
        // report it.
        log::error(cat, "[Download {}]: {} is unreachable.", download_id, quic_target->address);
        _active_downloads.erase(download_id);
        request.on_complete(ERROR_INVALID_DESTINATION, false);
    }
}

// Legacy HTTP-based download path, used when no QUIC file server target is available.
void SessionRouter::_download_internal_legacy(DownloadRequest request, std::string download_id) {
    _active_downloads[download_id] = request;

    try {
        Request req = file_server::to_request(download_id, _config.file_server_config, request);

        send_request(
                std::move(req),
                [weak_self = weak_from_this(), this, download_id, request](
                        bool success,
                        bool timeout,
                        int16_t status_code,
                        std::vector<std::pair<std::string, std::string>> headers,
                        std::optional<std::string> body) {
                    auto self = weak_self.lock();
                    if (!self)
                        return;

                    _active_downloads.erase(download_id);

                    try {
                        if (request.is_cancelled())
                            throw cancellation_exception{"Cancelled during request."};

                        if (!success || timeout)
                            throw status_code_exception{
                                    status_code,
                                    headers,
                                    fmt::format(
                                            "Request failed with status {}, timeout={}.",
                                            status_code,
                                            timeout)};

                        if (!body)
                            throw std::runtime_error{"No response body."};

                        auto [metadata, data] = file_server::parse_download_response(
                                request.download_url, headers, *body);
                        log::info(
                                cat,
                                "[Download {}]: Successfully downloaded {} bytes for file ID: {}",
                                download_id,
                                data.size(),
                                metadata.id);

                        if (request.on_data)
                            request.on_data(metadata, to_span<const std::byte>(data));

                        request.on_complete(std::move(metadata), false);
                    } catch (const cancellation_exception&) {
                        log::error(cat, "[Download {}]: Cancelled", download_id);
                        request.on_complete(ERROR_REQUEST_CANCELLED, false);
                    } catch (const status_code_exception& e) {
                        log::error(
                                cat,
                                "[Download {}]: Failure with error: {}",
                                download_id,
                                e.what());
                        request.on_complete(e.status_code, false);
                    } catch (const std::exception& e) {
                        log::error(
                                cat,
                                "[Download {}]: Failure with error: {}",
                                download_id,
                                e.what());
                        request.on_complete(ERROR_UNKNOWN, false);
                    }
                });
    } catch (const invalid_url_exception& e) {
        log::error(cat, "[Download {}]: Exception during download: {}", download_id, e.what());
        request.on_complete(ERROR_INVALID_DOWNLOAD_URL, false);
        _active_downloads.erase(download_id);
    } catch (const std::exception& e) {
        log::error(cat, "[Download {}]: Exception during download: {}", download_id, e.what());
        request.on_complete(ERROR_UNKNOWN, false);
        _active_downloads.erase(download_id);
    }
}

void SessionRouter::_establish_tunnel(
        std::span<const std::byte, 32> remote_pubkey,
        const uint16_t remote_port,
        const std::string& initiating_req_id) {
    auto address_pubkey_hex = oxenc::to_hex(remote_pubkey);

    if (address_pubkey_hex.size() != 64) {
        log::critical(
                cat,
                "Destination had an invalid remote key, request {} is being dropped.",
                initiating_req_id);
        _fail_tunnel(address_pubkey_hex, false);
        return;
    }

    // TODO: Need to clean this up
    // std::string RouterID::AddressPrinter::to_string() const
    // {
    //     std::string r;
    //     r.reserve(B32Z_ID_SIZE + (is_relay ? RELAY_DOT_TLD : CLIENT_DOT_TLD).size());
    //     oxenc::to_base32z(rid.begin(), rid.end(), std::back_inserter(r));
    //     r += is_relay ? RELAY_DOT_TLD : CLIENT_DOT_TLD;
    //     return r;
    // }

    // srouter::RouterID router_id{remote_pubkey.first<32>()};
    // auto snode_address = "34d9udo9ethfcrcaxcgdyxsi1w8gr79jzornsytcfgdw5rpmif8y.loki";//
    // address.to_network_address(true);
    //  auto snode_address = "55fxd8stjrt9g6rsbftx7eesy47pj4751xjghinr3k9ffxh4ieyo.snode";
    // auto srouter_address = router_id.to_network_address(true);
    auto test_port = remote_port;  // 35519;

    log::debug(
            cat,
            "[Request {}] Establishing new tunnel to {}.",
            initiating_req_id,
            address_pubkey_hex);
    auto tunnel = srouter->establish_udp(
            srouter_address(remote_pubkey),
            test_port,
            [weak_self = weak_from_this(), this, address_pubkey_hex, initiating_req_id](
                    router::tunnel_info info) mutable {
                auto self = weak_self.lock();
                if (!self)
                    return;

                log::info(
                        cat,
                        "[Request {}] Tunnel to remote {} established.",
                        initiating_req_id,
                        address_pubkey_hex);

                // This can fire before `establish_udp` returns, when a session to the remote is
                // already up, so the lease may not have been recorded yet.
                _tunnel(address_pubkey_hex).established = true;

                auto requests_to_process = std::move(_pending_requests[address_pubkey_hex]);
                _pending_requests.erase(address_pubkey_hex);

                // We had a successful connection so update the status to connected
                _update_status(ConnectionStatus::connected);

                if (!requests_to_process.empty()) {
                    log::debug(
                            cat,
                            "Processing {} pending requests on new tunnel to {}.",
                            requests_to_process.size(),
                            info.remote);

                    for (auto&& [req, cb] : std::move(requests_to_process))
                        _send_via_tunnel(
                                info.remote, info.local_port, std::move(req), std::move(cb));
                }
            },
            [weak_self = weak_from_this(), this, address_pubkey_hex, initiating_req_id](
                    router::tunnel_failure failure) mutable {
                auto self = weak_self.lock();
                if (!self)
                    return;

                // A relay contact we didn't have when the tunnel was requested, and which the
                // lookup then found doesn't exist, arrives here rather than as a nullopt return.
                bool unreachable = failure == router::tunnel_failure::unreachable;

                log::info(
                        cat,
                        "[Request {}] Session router connection to {} failed: {}.",
                        initiating_req_id,
                        address_pubkey_hex,
                        unreachable ? "node is not reachable" : "timed out");

                _fail_tunnel(address_pubkey_hex, unreachable);
            });

    // No tunnel at all means Session Router holds no relay contact for this node, i.e. it isn't
    // participating in the network rather than merely being slow to answer.  Neither callback
    // fires in that case, so the failure is ours to report.
    if (!tunnel) {
        log::info(
                cat,
                "[Request {}] {} is not reachable via session router.",
                initiating_req_id,
                address_pubkey_hex);

        _fail_tunnel(address_pubkey_hex, true);
        return;
    }

    // The established callback may already have run, so keep whatever it recorded and only fill
    // in the claim.
    _tunnel(address_pubkey_hex).tunnel = std::move(tunnel);
}

ActiveTunnel& SessionRouter::_tunnel(const std::string& pubkey_hex) {
    auto& entry = _active_tunnels[pubkey_hex];
    if (!entry)
        entry = std::make_unique<ActiveTunnel>();
    return *entry;
}

void SessionRouter::_fail_tunnel(const std::string& pubkey_hex, bool unreachable) {
    // Dropping our claim releases the mapping; a later attempt builds a fresh one, which is also
    // what gives Session Router the chance to notice that an unreachable node has come back.
    _active_tunnels.erase(pubkey_hex);

    if (auto snode_pool = _snode_pool.lock())
        if (auto key = ed25519_pubkey::maybe_from_hex(pubkey_hex))
            snode_pool->record_node_failure(*key, unreachable);

    if (auto it = _pending_requests.find(pubkey_hex); it != _pending_requests.end()) {
        auto to_fail = std::move(it->second);
        _pending_requests.erase(it);

        log::error(cat, "Failing {} pending request(s) to {}.", to_fail.size(), pubkey_hex);

        for (auto& [req, cb] : to_fail)
            cb(false,
               !unreachable,
               unreachable ? ERROR_INVALID_DESTINATION : ERROR_REQUEST_TIMEOUT,
               {content_type_plain_text},
               unreachable ? "Node is not reachable via session router" : "Timeout");
    }

    // If we no longer have any active connections then we are disconnected
    if (_active_tunnels.empty())
        _update_status(ConnectionStatus::disconnected);
}

void SessionRouter::_send_via_tunnel(
        std::string tunnel_remote,
        uint16_t tunnel_local_port,
        Request request,
        network_response_callback_t callback) {
    // If the request has already timedout at this point then just fail it immediately
    auto timeout = request.time_remaining();
    if (timeout <= 0s)
        return callback(
                false,
                true,
                ERROR_REQUEST_TIMEOUT,
                {content_type_plain_text},
                "Request already timed out");

    auto transport = _transport.lock();
    if (!transport) {
        log::critical(cat, "Transport was destroyed, cannot send request.");
        return;
    }

    // We have a valid connection and stream so we can send the request
    log::debug(cat, "[Request {}] Sending to {}.", request.request_id, tunnel_remote);

    auto [remote_pubkey, _] = remote_info_for_destination(request.destination, request.request_id);
    const auto remote_pubkey_hex = oxenc::to_hex(remote_pubkey);
    auto test_key = remote_pubkey;
    // auto test_key =
    // oxenc::from_base64("1n+DAM9hKyJhtXSPR5L/HdemIKPiHs8dZsPn2kEQuMs="); auto test_key
    // = oxenc::from_base32z("55fxd8stjrt9g6rsbftx7eesy47pj4751xjghinr3k9ffxh4ieyo");
    auto router_target =
            oxen::quic::RemoteAddress{as_span<unsigned char>(test_key), "::1", tunnel_local_port};

    // Construct the actual request to send
    std::optional<std::chrono::milliseconds> remaining_overall_timeout =
            (request.overall_timeout.has_value() ? std::optional{request.time_remaining()}
                                                 : std::nullopt);
    Request router_request{
            request.request_id,
            network_destination{router_target},  // Send to local router address
            request.endpoint,                    // Send to onion request handling endpoint
            request.body,
            request.category,
            request.time_remaining(),
            remaining_overall_timeout};
    router_request.tunnelled = true;

    transport->send_request(std::move(router_request), std::move(callback));
}

}  // namespace session::network
