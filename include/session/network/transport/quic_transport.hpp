#pragma once

#include <atomic>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "session/network/key_types.hpp"
#include "session/network/network_config.hpp"
#include "session/network/transport/network_transport.hpp"

namespace oxen::quic {
class Loop;
class Endpoint;
struct ConnectionID;
}  // namespace oxen::quic

namespace session::network {

namespace config {
    struct QuicTransport {
        std::chrono::milliseconds handshake_timeout;
        std::chrono::seconds keep_alive;

        std::optional<size_t> max_udp_payload;
    };
}  // namespace config

class QuicTransport : public ITransport, public std::enable_shared_from_this<QuicTransport> {
  private:
    bool _suspended = false;
    config::QuicTransport _config;
    std::shared_ptr<oxen::quic::Loop> _loop;
    std::shared_ptr<oxen::quic::Endpoint> _endpoint;

    std::unordered_map<std::string, oxen::quic::ConnectionID> _active_connection_ids;
    std::unordered_map<oxen::quic::ConnectionID, std::set<int64_t>> _available_stream_ids;
    std::unordered_map<std::string, std::vector<std::function<void(bool, std::optional<uint64_t>)>>>
            _pending_verification_callbacks;
    std::unordered_map<std::string, std::vector<std::pair<Request, network_response_callback_t>>>
            _pending_requests;
    std::unordered_map<std::string, std::vector<std::function<void()>>> _failure_listeners;

  public:
    explicit QuicTransport(config::QuicTransport config, std::shared_ptr<oxen::quic::Loop> loop);
    ~QuicTransport() override;

    void suspend() override;
    void resume(bool automatically_reconnect = true) override;
    void close_connections() override;

    ConnectionStatus get_status() const override { return _status.load(); };
    void set_node_failure_reporter(node_failure_reporter_t reporter) override;
    void verify_connectivity(
            service_node node,
            std::chrono::milliseconds timeout,
            const std::string& request_id,
            const RequestCategory category,
            std::function<void(bool success, std::optional<uint64_t> error_code)> callback)
            override;
    void add_failure_listener(
            const ed25519_pubkey& pubkey, std::function<void()> listener) override;
    void remove_failure_listeners(const ed25519_pubkey& pubkey) override;
    void send_request(Request request, network_response_callback_t callback) override;

  private:
    // The current connection status of this transport layer
    std::atomic<ConnectionStatus> _status{ConnectionStatus::unknown};

    // Callback which will be called when failing to connect to a node
    std::optional<node_failure_reporter_t> _report_node_failure;

    // True if we have already transitioned to "connecting" since the last time we were fully
    // disconnected
    bool _has_attempted_reconnect = false;

    void _recreate_endpoint();
    void _close_connections();
    void _update_status(ConnectionStatus new_status);
    void _send_request_internal(Request request, network_response_callback_t callback);
    void _establish_connection(
            const oxen::quic::RemoteAddress& address,
            const std::string& initiating_req_id,
            const RequestCategory category);
    void _send_on_connection(
            oxen::quic::ConnectionID conn_id,
            const std::string remote_pubkey_hex,
            Request request,
            network_response_callback_t callback);
    void _fail_connection(
            const std::string& address_pubkey_hex,
            const std::string& initiating_req_id,
            std::optional<uint64_t> error_code,
            std::optional<std::string> custom_error);
};

}  // namespace session::network