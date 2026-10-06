#include "session/network/routing/session_router_router.hpp"

#include <fmt/ranges.h>
#include <fmt/std.h>
#include <oxenc/base32z.h>
#include <oxenc/base64.h>

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <session/router.hpp>

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

    std::pair<std::span<const unsigned char>, uint16_t> remote_info_for_destination(
            const network_destination& dest, const std::string& request_id) {
        std::optional<std::pair<std::span<const unsigned char>, uint16_t>> result;

        std::visit(
                [&result, &request_id]<typename T>(const T& arg) {
                    if constexpr (std::is_same_v<T, oxen::quic::RemoteAddress>) {
                        log::trace(
                                cat, "[Request {}]: Using pre-resolved RemoteAddress.", request_id);
                        result.emplace(arg.view_remote_key(), arg.port());
                    } else if constexpr (std::is_same_v<T, service_node>) {
                        log::trace(
                                cat,
                                "[Request {}]: Resolving service_node to RemoteAddress.",
                                request_id);
                        result.emplace(arg.remote_pubkey, arg.omq_port);
                    }
                },
                dest);

        if (!result)
            throw std::runtime_error{"Invalid destination"};

        if (result->first.size() != 32)
            throw std::runtime_error{"Invalid remote key"};

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
    [logging]
    type=none
    level=*=debug,quic=info
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
                        snode_pool->refresh_if_needed({}, [weak_self, this](bool refreshed) {
                            auto self = weak_self.lock();
                            if (!self)
                                return;

                            // Setup finishes either way: not finishing leaves the router
                            // permanently unusable, where finishing with an empty pool just means
                            // the first request refreshes again
                            if (!refreshed)
                                log::warning(
                                        cat,
                                        "Finishing router setup without a refreshed snode pool.");

                            _loop->call([weak_self] {
                                if (auto self = weak_self.lock())
                                    self->_finish_setup();
                            });
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
    if (_loop)
        _loop->call_get([this, &threads_to_join] {
            // Harvest upload thread handles *before* _close_connections clears the map
            for (auto& [_, upload] : _active_uploads)
                if (upload.second.joinable())
                    threads_to_join.push_back(std::move(upload.second));

            _close_connections();
        });

    // Block until upload threads have finished
    for (auto& t : threads_to_join)
        if (t.joinable())
            t.join();

    log::debug(cat, "Destroyed.");
}

// MARK: IRouter

void SessionRouter::suspend() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] {
        _suspended = true;
        _close_connections();
        log::info(cat, "Suspended.");
    });
}

void SessionRouter::resume(bool /*automatically_reconnect*/) {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] {
        if (!_suspended)
            return;

        _suspended = false;
        log::info(cat, "Resumed.");
    });
}

void SessionRouter::close_connections() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] { _close_connections(); });
}

void SessionRouter::clear_cache() {
    // TODO: Implement this.
}

std::vector<PathInfo> SessionRouter::get_active_paths() {
    // TODO: Implement this.
    return {};
}

void SessionRouter::send_request(Request request, network_response_callback_t callback) {
    _loop->call([weak_self = weak_from_this(), req = std::move(request), cb = std::move(callback)] {
        if (auto self = weak_self.lock())
            self->_send_request_internal(std::move(req), std::move(cb));
    });
}

void SessionRouter::upload(UploadRequest request) {
    _loop->call([weak_self = weak_from_this(), req = std::move(request)] {
        if (auto self = weak_self.lock())
            self->_upload_internal(std::move(req));
    });
}

void SessionRouter::download(DownloadRequest request) {
    _loop->call([weak_self = weak_from_this(), req = std::move(request)] {
        if (auto self = weak_self.lock())
            self->_download_internal(std::move(req));
    });
}

// MARK: Internal Logic

void SessionRouter::_finish_setup() {
    // Start processing requests
    _ready = true;
    log::debug(cat, "Finishing setup, router is now ready.");

    auto requests_to_process = std::move(_pending_requests);
    if (requests_to_process.empty())
        return;

    // Process any requests that were queued before we were ready
    log::debug(
            cat,
            "Processing {} requests queued during initialization.",
            requests_to_process.size());

    for (auto& [address, requests] : requests_to_process) {
        if (!requests.empty()) {
            log::debug(
                    cat, "Processing {} queued requests for address {}.", requests.size(), address);

            for (auto&& [req, cb] : std::move(requests))
                _send_request_internal(std::move(req), std::move(cb));
        }
    }
}

void SessionRouter::_close_connections() {
    // TODO: Need to close any active connections on the session router instance.

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
    // relaunch
    _active_tunnels.clear();
    {
        std::lock_guard lock{_tunnel_claims_mutex};
        _tunnel_claims.clear();
    }
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
    try {
        if (std::holds_alternative<ServerDestination>(request.destination))
            throw std::runtime_error{"Attempted to send server request directly"};

        auto [remote_pubkey, remote_port] =
                remote_info_for_destination(request.destination, request.request_id);
        const auto remote_pubkey_hex = oxenc::to_hex(remote_pubkey);

        if (auto it = _active_tunnels.find(remote_pubkey_hex); it != _active_tunnels.end()) {
            log::trace(cat, "[Request {}] Found active tunnel.", request.request_id);
            _send_via_tunnel(it->second, std::move(request), std::move(callback));
            return;
        }

        // Add the request to the pending queue to be picked up once we have a tunnel for it
        std::string initiating_req_id = request.request_id;
        _pending_requests[remote_pubkey_hex].emplace_back(std::move(request), std::move(callback));

        // If there is only a single pending request then we wouldn't have started establishing a
        // tunnel
        if (_pending_requests.at(remote_pubkey_hex).size() == 1) {
            log::info(
                    cat,
                    "[Request {}] No tunnel to {}, initiating new tunnel.",
                    initiating_req_id,
                    remote_pubkey_hex);
            _establish_tunnel(remote_pubkey, remote_port, initiating_req_id);
        } else
            log::debug(
                    cat,
                    "[Request {}] Tunnel to {} is pending, queueing request.",
                    initiating_req_id,
                    remote_pubkey_hex);
    } catch (const std::exception& e) {
        log::error(
                cat,
                "[Request {}] Failed to send request due to error: {}",
                request.request_id,
                e.what());
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
    std::vector<unsigned char> encrypted_blob;
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

void SessionRouter::_upload_internal(UploadRequest request) {
    // TODO: Update this to use streaming approach
    const std::string upload_id = random::unique_id("UP");
    log::info(cat, "[Upload {}]: Starting upload.", upload_id);

    // Make the callback atomic so we don't need to worry about it being called multiple times (eg.
    // network shutdown cancelling the request and the transport shutdown automatically triggering
    // callbacks)
    request.on_complete = make_callback_atomic(std::move(request.on_complete));
    auto& [_, upload_thread] =
            _active_uploads.emplace(upload_id, std::make_pair(request, std::thread{}))
                    .first->second;

    // Accumulate data on a background thread as we don't know whether `next_data` is doing file I/O
    // or just reading from memory (it's a bit of a waste if it's in-memory data but loading from
    // disk should be prioritised)
    upload_thread = std::thread([weak_self = weak_from_this(),
                                 this,
                                 upload_request = request,
                                 upload_id,
                                 file_server_config = _config.file_server_config] {
        auto self = weak_self.lock();
        if (!self)
            return;

        // Onion requests don't support streaming data so we need to load all the data from the
        // streaming source into memory
        try {
            Request request =
                    file_server::to_request(upload_id, file_server_config, upload_request);

            _loop->call([weak_self, this, upload_request, req = std::move(request), upload_id] {
                auto self = weak_self.lock();
                if (!self)
                    return;

                if (upload_request.is_cancelled() || !req.body) {
                    log::debug(cat, "[Upload {}]: Cancelled before sending request.", upload_id);
                    upload_request.on_complete(ERROR_REQUEST_CANCELLED, false);

                    auto active_upload_node = _active_uploads.extract(upload_id);
                    if (!active_upload_node.empty() &&
                        active_upload_node.mapped().second.joinable())
                        active_upload_node.mapped().second.join();
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
                        [weak_self, this, upload_id, upload_request, upload_size](
                                bool success,
                                bool timeout,
                                int16_t status_code,
                                std::vector<std::pair<std::string, std::string>> headers,
                                std::optional<std::string> body) {
                            auto self = weak_self.lock();
                            if (!self)
                                return;

                            // Join the thread to keep it alive during callback handling
                            auto active_upload_node = _active_uploads.extract(upload_id);
                            if (!active_upload_node.empty() &&
                                active_upload_node.mapped().second.joinable())
                                active_upload_node.mapped().second.join();

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

            _loop->call([weak_self, this, upload_request, upload_id] {
                auto self = weak_self.lock();
                if (!self)
                    return;

                // Join the thread to keep it alive during callback handling
                auto active_upload_node = _active_uploads.extract(upload_id);
                if (!active_upload_node.empty() && active_upload_node.mapped().second.joinable())
                    active_upload_node.mapped().second.join();

                upload_request.on_complete(ERROR_UNKNOWN, false);
            });
        }
    });
}

void SessionRouter::_download_internal(DownloadRequest request) {
    const std::string download_id = random::unique_id("DL");
    log::info(cat, "[Download {}]: Starting download.", download_id);

    // Make the callback atomic so we don't need to worry about it being called multiple times (eg.
    // network shutdown cancelling the request and the transport shutdown automatically triggering
    // callbacks)
    request.on_complete = make_callback_atomic(std::move(request.on_complete));
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
                            request.on_data(metadata, std::move(data));

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
        std::span<const unsigned char>& remote_pubkey,
        const uint16_t remote_port,
        const std::string& initiating_req_id) {
    auto address_pubkey_hex = oxenc::to_hex(remote_pubkey);

    if (address_pubkey_hex.size() != 64) {
        log::critical(
                cat,
                "Destination had an invalid remote key, request {} is being dropped.",
                initiating_req_id);
        // Fail all the pending requests for this connection
        if (auto it = _pending_requests.find(address_pubkey_hex); it != _pending_requests.end()) {
            auto to_fail = std::move(it->second);
            _pending_requests.erase(it);
            log::error(
                    cat,
                    "Failing {} pending request(s) due to connection failure.",
                    to_fail.size());

            for (auto& [req, cb] : to_fail)
                cb(false,
                   false,
                   ERROR_INVALID_DESTINATION,
                   {content_type_plain_text},
                   "Failed to establish tunnel to remote.");
        }
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

    std::string srouter_address;
    srouter_address.reserve(oxenc::to_base32z_size(32UL) + ".snode"sv.size());
    oxenc::to_base32z(
            remote_pubkey.begin(), remote_pubkey.begin() + 32, std::back_inserter(srouter_address));
    srouter_address += ".snode"sv;

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
    auto claim = srouter->establish_udp(
            srouter_address,
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

                auto requests_to_process = std::move(_pending_requests[address_pubkey_hex]);
                _pending_requests.erase(address_pubkey_hex);
                _active_tunnels.insert_or_assign(address_pubkey_hex, info);

                // We had a successful connection so update the status to connected
                _update_status(ConnectionStatus::connected);

                if (!requests_to_process.empty()) {
                    log::debug(
                            cat,
                            "Processing {} pending requests on new tunnel to {}.",
                            requests_to_process.size(),
                            info.remote);

                    for (auto&& [req, cb] : std::move(requests_to_process))
                        _send_via_tunnel(info, std::move(req), std::move(cb));
                }
            },
            [weak_self = weak_from_this(), this, address_pubkey_hex, initiating_req_id](
                    router::tunnel_failure reason) mutable {
                auto self = weak_self.lock();
                if (!self)
                    return;

                log::info(
                        cat,
                        "[Request {}] Unable to establish session router UDP connection to {} "
                        "({}).",
                        initiating_req_id,
                        address_pubkey_hex,
                        reason == router::tunnel_failure::unreachable ? "no relay contact"
                                                                      : "timed out");

                _active_tunnels.erase(address_pubkey_hex);
                {
                    std::lock_guard lock{_tunnel_claims_mutex};
                    _tunnel_claims.erase(address_pubkey_hex);
                }

                // Fail all the pending requests for this connection
                if (auto it = _pending_requests.find(address_pubkey_hex);
                    it != _pending_requests.end()) {
                    auto to_fail = std::move(it->second);
                    _pending_requests.erase(it);

                    log::error(
                            cat,
                            "Failing {} pending requests due to UDP connection failure.",
                            to_fail.size());

                    for (auto& [req, cb] : to_fail)
                        cb(false,
                           false,
                           ERROR_REQUEST_TIMEOUT,
                           {content_type_plain_text},
                           "Timeout");
                }

                // If we have no longer have any active connections then we are disconnected
                if (_active_tunnels.empty())
                    _update_status(ConnectionStatus::disconnected);
            });

    // Keep the tunnel open for as long as we hold the node's entry.  If the failure callback has
    // already run on session-router's thread this leaves a claim behind for a tunnel that failed,
    // which is harmless: a later request to the same node replaces it.
    std::lock_guard lock{_tunnel_claims_mutex};
    _tunnel_claims.insert_or_assign(
            address_pubkey_hex, std::make_shared<router::udp_tunnel>(std::move(claim)));
}

void SessionRouter::_send_via_tunnel(
        router::tunnel_info tunnel, Request request, network_response_callback_t callback) {
    // TODO: Is there a way to check that the 'tunnel_info' still active?.

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
    log::debug(cat, "[Request {}] Sending to {}.", request.request_id, tunnel.remote);

    auto [remote_pubkey, _] = remote_info_for_destination(request.destination, request.request_id);
    const auto remote_pubkey_hex = oxenc::to_hex(remote_pubkey);
    auto test_key = remote_pubkey;
    // auto test_key =
    // oxenc::from_base64("1n+DAM9hKyJhtXSPR5L/HdemIKPiHs8dZsPn2kEQuMs="); auto test_key
    // = oxenc::from_base32z("55fxd8stjrt9g6rsbftx7eesy47pj4751xjghinr3k9ffxh4ieyo");
    auto router_target = oxen::quic::RemoteAddress{test_key, "::1", tunnel.local_port};

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

    transport->send_request(std::move(router_request), std::move(callback));
}

}  // namespace session::network
