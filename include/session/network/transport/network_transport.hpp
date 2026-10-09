#pragma once

#include "session/network/session_network_types.hpp"

namespace session::network {

class ITransport {
  public:
    std::function<void()> on_status_changed;

    virtual ~ITransport() = default;

    virtual void suspend() = 0;
    virtual void resume(bool automatically_reconnect = true) = 0;
    virtual void close_connections() = 0;

    virtual ConnectionStatus get_status() const = 0;
    virtual void set_node_failure_reporter(node_failure_reporter_t /*reporter*/) {}
    virtual void verify_connectivity(
            service_node node,
            std::chrono::milliseconds timeout,
            const std::string& request_id,
            const RequestCategory category,
            std::function<void(bool success, std::optional<uint64_t> error_code)> callback) = 0;
    virtual void add_failure_listener(
            const ed25519_pubkey& pubkey, std::function<void()> listener) = 0;
    virtual void remove_failure_listeners(const ed25519_pubkey& pubkey) = 0;

    virtual void send_request(Request request, network_response_callback_t callback) = 0;
};

}  // namespace session::network