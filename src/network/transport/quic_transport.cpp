#include "session/network/transport/quic_transport.hpp"

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/quic/gnutls_crypto.hpp>

#include "session/crypto/ed25519.hpp"
#include "session/network/session_network_types.hpp"

using namespace oxen;
using namespace session;
using namespace session::network;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network {

namespace {
    inline auto cat = log::Cat("quic-transport");

    static constexpr uint16_t ACTIVE_STREAM_PRUNE_LIMIT = 32;

    inline bool use_reserved_stream(RequestCategory category) {
        switch (category) {
            case RequestCategory::standard: return false;
            case RequestCategory::standard_small: return true;
            case RequestCategory::file: return false;
            case RequestCategory::file_small: return true;
            // Small enough to qualify for the reserved stream, and deliberately kept off it: a
            // config push is the one swarm request that can be large, and stream 0 also carries
            // the polls, the stores and the server's pushes back to us.
            case RequestCategory::config: return false;
        }
        return false;  // Shouldn't happen
    }
}  // namespace

constexpr auto ALPN = "oxenstorage"sv;

QuicTransport::QuicTransport(config::QuicTransport config, oxen::quic::Loop& loop) :
        _config{std::move(config)}, _loop{loop} {
    log::trace(cat, "Initializing.");
    _recreate_endpoint();
}

QuicTransport::~QuicTransport() {
    // Nothing queued here runs after this, and whatever was running has finished by the time it
    // returns -- so no job of ours can be part-way through when the members below go.
    _jq.stop();

    // Our own queue is stopped, so this last piece of teardown goes on the loop's.
    // _close_connections resets the endpoint, and the endpoint's deleter destroys it *on the loop*,
    // so once this returns libquic can no longer call into the connection callbacks below -- which
    // is what lets those callbacks hold a bare `this`.
    _loop.call_get([this] { _close_connections(); });
    log::debug(cat, "Destroyed.");
}

// MARK: ITransport

void QuicTransport::suspend() {
    // Use 'call_get' to force this to be synchronous
    _jq.call_get([this] {
        if (_suspended)
            return;

        _suspended = true;
        _close_connections();
        log::info(cat, "Suspended.");
    });
}

void QuicTransport::resume(bool /*automatically_reconnect*/) {
    // Use 'call_get' to force this to be synchronous
    _jq.call_get([this] {
        // Recreate the endpoint before updating the `_suspended` flag to avoid the chance that
        // something will try to use it before we are ready
        _recreate_endpoint();
        _suspended = false;
        log::info(cat, "Resumed.");
    });
}

void QuicTransport::close_connections() {
    // Use 'call_get' to force this to be synchronous
    _jq.call_get([this] { _close_connections(); });
}

void QuicTransport::set_node_failure_reporter(node_failure_reporter_t reporter) {
    _jq.call([this, r = std::move(reporter)]() mutable {
        _report_node_failure.emplace(std::move(r));
    });
}

void QuicTransport::verify_connectivity(
        service_node node,
        std::chrono::milliseconds /*timeout*/,
        const std::string& request_id,
        const RequestCategory category,
        std::function<void(bool success, std::optional<uint64_t> error_code)> callback) {
    // For Quic, a successful connection IS a successful ping so we can just check for an existing
    // connection and, if one doesn't exist, try to establish one
    _jq.call([this, node = std::move(node), cb = std::move(callback), request_id, category]() {
        const auto pubkey_hex = node.remote_pubkey.hex();

        // If we already have a connection we can stop here
        if (_active_connection_ids.count(pubkey_hex) || _pending_requests.count(pubkey_hex))
            return cb(true, std::nullopt);

        _pending_verification_callbacks[pubkey_hex].push_back(std::move(cb));

        // Only try to establish a connection if we are the first to ask for one
        if (_pending_requests.count(pubkey_hex) == 0 &&
            _pending_verification_callbacks.at(pubkey_hex).size() == 1)
            _establish_connection(
                    {node.remote_pubkey.view(), node.host(), node.omq_port},
                    request_id,
                    category,
                    false);
    });
}

void QuicTransport::add_failure_listener(
        const ed25519_pubkey& pubkey, std::function<void()> listener) {
    _jq.call([this, pk_hex = pubkey.hex(), l = std::move(listener)]() mutable {
        _failure_listeners[pk_hex].push_back(std::move(l));
    });
}

void QuicTransport::remove_failure_listeners(const ed25519_pubkey& pubkey) {
    _jq.call([this, pk_hex = pubkey.hex()] { _failure_listeners.erase(pk_hex); });
}

void QuicTransport::send_request(Request request, network_response_callback_t callback) {
    log::trace(cat, "Dispatching request {} to loop.", request.request_id);
    _jq.call([this, req = std::move(request), cb = std::move(callback)]() mutable {
        _send_request_internal(std::move(req), std::move(cb));
    });
}

// MARK: Internal Logic

void QuicTransport::_recreate_endpoint() {
    _endpoint = quic::Endpoint::endpoint(
            _loop,
            quic::Address{},
            (_config.max_udp_payload
                     ? std::make_optional<quic::opt::max_udp_payload>(*_config.max_udp_payload)
                     : std::nullopt));
}

void QuicTransport::_close_connections() {
    // Taken out before the endpoint goes.  Resetting it destroys it on the spot (close_conns()
    // only defers), and its destructor closes every connection with code 0 through the handler
    // that fails whatever is pending on it - so left in place, our own close would reach each
    // pending verification as an error code, which is what gets a node struck.  Answering copies
    // also keeps a callback that calls back into the transport from changing the maps being walked.
    auto verifications = std::exchange(_pending_verification_callbacks, {});
    auto requests = std::exchange(_pending_requests, {});

    if (_endpoint)
        _endpoint->close_conns();
    _endpoint.reset();

    // Clear all storage of requests, paths and connections so that we are in a fresh state on
    // relaunch
    _active_connection_ids.clear();
    _available_stream_ids.clear();
    _update_status(ConnectionStatus::disconnected);

    // Answered only now the transport is fully closed, so anything a callback asks of it fails
    // cleanly, without an error code, rather than meeting half-closed state.  A verification gets
    // no error code either: a close we asked for is no evidence against the node.
    for (const auto& [pubkey, callbacks] : verifications)
        for (const auto& callback : callbacks)
            callback(false, std::nullopt);

    for (const auto& [pubkey, pubkey_requests] : requests)
        for (const auto& [info, callback] : pubkey_requests)
            callback(
                    false,
                    false,
                    (_suspended ? ERROR_NETWORK_SUSPENDED : ERROR_CONNECTION_CLOSED),
                    {content_type_plain_text},
                    (_suspended ? "QuickTransport is suspended."
                                : "QuickTransport closed its connections."));

    log::info(cat, "Closed all connections.");
}

void QuicTransport::_update_status(ConnectionStatus new_status) {
    ConnectionStatus old_status = _status.load();
    if (old_status == new_status)
        return;

    // Prevent swapping from "connected" back to "connecting" if a background connection is being
    // established while we are already connected
    if (old_status == ConnectionStatus::connected && new_status == ConnectionStatus::connecting)
        return;

    // If we already tried to reconnect but failed, then we want to prevent swapping between
    // "disconnected" and "connecting"
    if (old_status == ConnectionStatus::disconnected &&
        new_status == ConnectionStatus::connecting && _has_attempted_reconnect)
        return;

    _status.store(new_status);

    if (old_status == ConnectionStatus::disconnected && new_status == ConnectionStatus::connecting)
        _has_attempted_reconnect = true;

    if (new_status == ConnectionStatus::connected)
        _has_attempted_reconnect = false;

    if (on_status_changed)
        on_status_changed();
}

void QuicTransport::_send_request_internal(Request request, network_response_callback_t callback) {
    // If we are suspended then fail immediately
    if (_suspended)
        return callback(
                false,
                false,
                ERROR_NETWORK_SUSPENDED,
                {content_type_plain_text},
                "QuickTransport is suspended.");

    std::optional<oxen::quic::RemoteAddress> remote;

    std::visit(
            [&remote, request_id = request.request_id]<typename T>(const T& arg) {
                if constexpr (std::is_same_v<T, oxen::quic::RemoteAddress>) {
                    log::trace(cat, "[Request {}]: Using pre-resolved RemoteAddress.", request_id);
                    remote = arg;
                } else if constexpr (std::is_same_v<T, service_node>) {
                    log::trace(
                            cat,
                            "[Request {}]: Resolving service_node to RemoteAddress.",
                            request_id);
                    remote.emplace(arg.remote_pubkey.view(), arg.host(), arg.omq_port);
                }
            },
            request.destination);

    if (!remote) {
        log::critical(cat, "[Request {}] Invalid destination type!", request.request_id);
        return callback(
                false,
                false,
                ERROR_INVALID_DESTINATION,
                {content_type_plain_text},
                "Internal error: invalid destination for QuicTransport");
    }

    const auto remote_pubkey_hex = oxenc::to_hex(remote->view_remote_key());

    // If an active connection exists then we can send the request over that
    if (auto it = _active_connection_ids.find(remote_pubkey_hex);
        it != _active_connection_ids.end()) {
        log::trace(cat, "[Request {}] Found active connection ID.", request.request_id);
        _send_on_connection(it->second, remote_pubkey_hex, std::move(request), std::move(callback));
        return;
    }

    // If we should already be establishing a connection then we can just add this as a pending
    // request and it'll be picked up once the connection is made
    if (_pending_requests.count(remote_pubkey_hex)) {
        log::debug(
                cat,
                "[Request {}] Connection to {} is pending, queueing request.",
                request.request_id,
                remote_pubkey_hex);
        _pending_requests[remote_pubkey_hex].emplace_back(std::move(request), std::move(callback));
        return;
    }

    // No connection exists so we need to start a new one and queue the request
    log::info(
            cat,
            "[Request {}] No connection to {}, initiating new connection.",
            request.request_id,
            remote_pubkey_hex);
    // Everything the connect needs has to be read before the request is moved into the queue.
    std::string initiating_req_id = request.request_id;
    auto category = request.category;
    bool tunnelled = request.tunnelled;
    _pending_requests[remote_pubkey_hex].emplace_back(std::move(request), std::move(callback));
    _establish_connection(*remote, initiating_req_id, category, tunnelled);
}

void QuicTransport::_establish_connection(
        const oxen::quic::RemoteAddress& address,
        const std::string& initiating_req_id,
        const RequestCategory /*category*/,
        bool tunnelled) {
    const auto address_pubkey_hex = oxenc::to_hex(address.view_remote_key());

    try {
        if (_suspended)
            throw std::runtime_error{"QuickTransport is suspended"};
        if (!_endpoint)
            throw std::runtime_error{"Network is invalid"};

        auto [conn_pk, conn_sk] = ed25519::keypair();
        auto creds = quic::GNUTLSCreds::make_from_ed_seckey(to_string_view(conn_sk));

        // If we are starting a connection attempt then transition to the "connecting" state
        if (_status.load() == ConnectionStatus::unknown ||
            _status.load() == ConnectionStatus::disconnected)
            _update_status(ConnectionStatus::connecting);

        log::debug(
                cat,
                "[Request {}] Establishing new connection to {}.",
                initiating_req_id,
                address_pubkey_hex);

        _endpoint->connect(
                address,
                creds,
                oxen::quic::opt::outbound_alpn(ALPN),
                oxen::quic::opt::handshake_timeout{
                        tunnelled ? _config.tunnel_handshake_timeout : _config.handshake_timeout},
                oxen::quic::opt::keep_alive{_config.keep_alive},
                // libquic hands these a live Connection, so they run inline on the loop rather than
                // as jobs of ours.  ~QuicTransport destroys the endpoint on the loop before the
                // members below are touched, so there is no window in which this can fire late.
                [this, address_pubkey_hex, initiating_req_id](oxen::quic::Connection& conn) {
                    log::info(
                            cat,
                            "[Request {}] Successfully established connection to {}.",
                            initiating_req_id,
                            address_pubkey_hex);

                    auto stream = conn.open_stream<oxen::quic::BTRequestStream>();
                    auto conn_id = conn.reference_id();
                    auto stream_id = stream->stream_id();

                    // Anything the far end sends us of its own accord arrives here.  Registered
                    // generically rather than per endpoint name because what those names mean is
                    // the storage server's business, not the transport's.
                    //
                    // Caught rather than left to propagate: this runs inside libquic's stream
                    // machinery, where an exception would tear down the connection for a fault in
                    // a consumer's handler.
                    stream->register_generic_handler(
                            [this, address_pubkey_hex](oxen::quic::message msg) {
                                if (!on_server_push)
                                    return;
                                try {
                                    on_server_push(
                                            ed25519_pubkey::from_hex(address_pubkey_hex),
                                            msg.endpoint(),
                                            msg.body<std::byte>());
                                } catch (const std::exception& e) {
                                    log::error(
                                            cat,
                                            "Handler for pushed '{}' from {} threw: {}",
                                            msg.endpoint(),
                                            address_pubkey_hex,
                                            e.what());
                                }
                            });
                    auto it = _pending_verification_callbacks.find(address_pubkey_hex);
                    decltype(it->second) verification_callbacks;
                    if (it != _pending_verification_callbacks.end()) {
                        verification_callbacks = std::move(it->second);
                        _pending_verification_callbacks.erase(it);
                    }

                    auto requests_to_process = std::move(_pending_requests[address_pubkey_hex]);
                    _pending_requests.erase(address_pubkey_hex);
                    _active_connection_ids.insert_or_assign(address_pubkey_hex, conn_id);

                    // We had a successful connection so update the status to connected
                    _update_status(ConnectionStatus::connected);

                    for (const auto& pending_cb : verification_callbacks)
                        pending_cb(true, std::nullopt);

                    if (!requests_to_process.empty()) {
                        log::debug(
                                cat,
                                "Processing {} pending requests on new stream {} with conn {}.",
                                requests_to_process.size(),
                                stream_id,
                                conn_id.to_string());

                        for (auto&& [req, cb] : std::move(requests_to_process))
                            _send_on_connection(
                                    conn_id, address_pubkey_hex, std::move(req), std::move(cb));
                    }

                    // Last, so that anything already waiting on this connection goes out ahead of
                    // whatever the listener sends, and so that the connection is in
                    // `_active_connection_ids` by the time it does.
                    if (on_connection_established) {
                        try {
                            on_connection_established(ed25519_pubkey::from_hex(address_pubkey_hex));
                        } catch (const std::exception& e) {
                            log::error(
                                    cat,
                                    "Connection-established listener for {} threw: {}",
                                    address_pubkey_hex,
                                    e.what());
                        }
                    }
                },
                [this, address_pubkey_hex, initiating_req_id](
                        oxen::quic::Connection&, uint64_t error_code) {
                    _fail_connection(
                            address_pubkey_hex, initiating_req_id, error_code, std::nullopt);
                });
    } catch (const std::exception& e) {
        _fail_connection(address_pubkey_hex, initiating_req_id, std::nullopt, e.what());
    }
}

void QuicTransport::_send_on_connection(
        oxen::quic::ConnectionID conn_id,
        const std::string remote_pubkey_hex,
        Request request,
        network_response_callback_t callback) {
    if (!_endpoint)
        return callback(
                false,
                false,
                ERROR_NETWORK_MISCONFIGURED,
                {content_type_plain_text},
                "Network is invalid");

    // Try to retrieve the active connection first
    auto conn = _endpoint->get_conn(conn_id);
    if (!conn) {
        log::warning(
                cat,
                "[Request {}] Attempted to send on a connection (ID {}) that no longer exists.",
                request.request_id,
                conn_id.to_string());

        // Since the connection is dead we should remove it from our active list and fail the
        // request (the client can retry if they want)
        for (auto it = _active_connection_ids.begin(); it != _active_connection_ids.end(); ++it) {
            if (it->second == conn_id) {
                _active_connection_ids.erase(it);
                _available_stream_ids.erase(conn_id);
                break;
            }
        }

        return callback(
                false,
                false,
                -1,
                {content_type_plain_text},
                "Connection died before request could be sent");
    }

    // If the request has already timedout at this point then just fail it immediately
    auto timeout = request.time_remaining();
    if (timeout <= 0s)
        return callback(
                false,
                true,
                ERROR_REQUEST_TIMEOUT,
                {content_type_plain_text},
                "Request already timed out");

    // Determine whether we want to use the "reserved" stream (ie. for really small requests) or
    // create a new stream (to maximise concurrency based on the configuration limits)
    std::shared_ptr<oxen::quic::BTRequestStream> target_stream;

    try {
        if (use_reserved_stream(request.category))
            // There will **always** be a stream `0` so we use that as the reserved stream
            target_stream = conn->get_stream<oxen::quic::BTRequestStream>(0);
        else {
            int64_t stream_id = -1;

            if (auto& streams = _available_stream_ids[conn_id]; !streams.empty()) {
                stream_id = *streams.begin();
                streams.erase(streams.begin());
            }

            if (stream_id != -1) {
                try {
                    target_stream = conn->get_stream<oxen::quic::BTRequestStream>(stream_id);
                } catch (const std::exception& e) {
                    log::warning(
                            cat,
                            "[Request {}] Failed to retrieve stream {} on conn {} due to error: {}",
                            request.request_id,
                            stream_id,
                            conn_id.to_string(),
                            e.what());
                }
            }

            if (!target_stream) {
                log::debug(
                        cat,
                        "[Request {}] Unable to find existing stream{}, creating new stream on "
                        "conn {}",
                        request.request_id,
                        (stream_id == -1 ? "" : " {}"_format(stream_id)),
                        conn_id.to_string());
                target_stream = conn->open_stream<oxen::quic::BTRequestStream>();
            }
        }
    } catch (const std::exception& e) {
        return callback(
                false, false, ERROR_FAILED_TO_GET_STREAM, {content_type_plain_text}, e.what());
    }

    // We have a valid connection and stream so we can send the request
    log::debug(
            cat,
            "[Request {}] Sending on stream {} with conn {}",
            request.request_id,
            target_stream->stream_id(),
            conn_id.to_string());

    std::span<const std::byte> payload{};

    if (request.body)
        payload = to_span<std::byte>(*request.body);

    target_stream->command(
            request.endpoint,
            payload,
            timeout,
            [this,
             cb = std::move(callback),
             conn_id,
             remote_pubkey_hex,
             stream_id = target_stream->stream_id(),
             req_id = request.request_id](quic::message resp) {
                log::trace(cat, "[Request {}] Received response.", req_id);

                // Since the request completed it's round-trip if it isn't the "reserverd" stream
                // (not used for general requests) then we can either add it back to the pool, or
                // close it if there are more that the active stream price limit
                if (stream_id != 0 && _endpoint) {
                    auto conn = _endpoint->get_conn(conn_id);

                    if (conn && conn->get_streams_available() <= ACTIVE_STREAM_PRUNE_LIMIT)
                        _available_stream_ids[conn_id].insert(stream_id);
                    else if (auto stream = conn->get_stream<oxen::quic::BTRequestStream>(stream_id))
                        stream->close();
                }

                if (resp.timed_out) {
                    log::debug(cat, "[Request {}] Timed out.", req_id);
                    return cb(
                            false,
                            true,
                            ERROR_REQUEST_TIMEOUT,
                            {content_type_plain_text},
                            "Request timed out");
                }

                if (resp.is_error()) {
                    auto final_timeout = resp.timed_out;
                    auto final_status_code = -1;
                    std::string_view err_body = resp.body();
                    if (err_body.empty())
                        err_body = "Unknown QUIC layer error"sv;

                    // The response doesn't provide a status code but the body can include it,
                    // in which case we should try to extract it from the body so we can perform
                    // any status code related logic
                    if (auto result = response::parse_text_error(err_body)) {
                        final_status_code = result->first;
                        final_timeout = result->second;
                    }

                    log::warning(cat, "[Request {}] Failed with QUIC error: {}.", req_id, err_body);
                    return cb(
                            false,
                            final_timeout,
                            final_status_code,
                            {content_type_plain_text},
                            std::make_optional<std::string>(err_body));
                }

                log::debug(cat, "[Request {}] Received raw success response.", req_id);
                cb(true, false, 200, {}, std::string{resp.body()});
            });
}

void QuicTransport::_fail_connection(
        const std::string& address_pubkey_hex,
        const std::string& initiating_req_id,
        std::optional<uint64_t> error_code,
        std::optional<std::string> custom_error) {
    if (error_code == NGTCP2_NO_ERROR)
        log::info(
                cat,
                "[Request {}] Connection to {} closed gracefully.",
                initiating_req_id,
                address_pubkey_hex);
    else if (error_code == static_cast<uint64_t>(NGTCP2_ERR_HANDSHAKE_TIMEOUT)) {
        log::warning(
                cat,
                "[Request {}] Handshake timeout when connecting to {}. "
                "The node is likely unreachable.",
                initiating_req_id,
                address_pubkey_hex);

        // If the connection failed with a handshake timeout then the node is
        // unreachable, either due to a device network issue or because the node is down
        // so report a failure to disincentivise use of the node in case it's not a network issue
        if (_report_node_failure)
            (*_report_node_failure)(ed25519_pubkey::from_hex(address_pubkey_hex), false);
    } else if (error_code == quic::CONN_SEND_FAIL) {
        log::warning(
                cat,
                "[Request {}] Connection to {} failed as we were unable to send it a packet "
                "(error: {})",
                initiating_req_id,
                address_pubkey_hex,
                *error_code);
    } else if (error_code)
        log::warning(
                cat,
                "[Request {}] Connection to {} failed or was closed with error code: {}",
                initiating_req_id,
                address_pubkey_hex,
                *error_code);
    else
        log::error(
                cat,
                "[Request {}] Connection to {} failed or was closed due to error: {}.",
                initiating_req_id,
                address_pubkey_hex,
                custom_error.value_or("Unknown error"));

    // Clear the connection and stream ids
    if (auto id = _active_connection_ids.extract(address_pubkey_hex))
        _available_stream_ids.erase(id.mapped());

    // Process any waiting verification requests
    if (auto it = _pending_verification_callbacks.find(address_pubkey_hex);
        it != _pending_verification_callbacks.end()) {
        for (const auto& pending_cb : it->second)
            pending_cb(false, error_code);
        _pending_verification_callbacks.erase(it);
    }

    // Fail all the pending requests for this connection
    if (auto it = _pending_requests.find(address_pubkey_hex); it != _pending_requests.end()) {
        auto to_fail = std::move(it->second);
        _pending_requests.erase(it);

        std::string failure_reason = "Failed to establish connection to service node";
        if (error_code == static_cast<uint64_t>(NGTCP2_ERR_HANDSHAKE_TIMEOUT))
            failure_reason += " (handshake timeout)";

        log::error(cat, "Failing {} pending request(s) due to connection failure.", to_fail.size());

        for (auto& [req, cb] : to_fail)
            cb(false, false, -1, {content_type_plain_text}, failure_reason);
    }

    // Notify any failure listeners that the connection has been closed
    if (auto it = _failure_listeners.find(address_pubkey_hex); it != _failure_listeners.end()) {
        auto to_fail = std::move(it->second);
        _failure_listeners.erase(it);

        for (const auto& listener : to_fail)
            listener();
    }

    if (on_connection_lost) {
        try {
            on_connection_lost(ed25519_pubkey::from_hex(address_pubkey_hex));
        } catch (const std::exception& e) {
            log::error(
                    cat, "Connection-lost listener for {} threw: {}", address_pubkey_hex, e.what());
        }
    }

    // If we have no longer have any active connections then we are disconnected
    if (_active_connection_ids.empty())
        _update_status(ConnectionStatus::disconnected);
}

}  // namespace session::network
