#pragma once

#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "session/network/backends/session_file_server.hpp"
#include "session/network/request_queue.hpp"
#include "session/network/routing/network_router.hpp"
#include "session/network/snode_pool.hpp"

namespace session::router {
class SessionRouter;
struct tunnel_info;
};  // namespace session::router

namespace session::network {

namespace config {
    struct SessionRouter {
        FileServer file_server_config;
        opt::netid::Target netid;
        fs::path cache_directory;

        uint8_t path_length;
    };
}  // namespace config

class SessionRouter : public IRouter, public std::enable_shared_from_this<SessionRouter> {
  private:
    bool _ready = false;
    bool _suspended = false;
    config::SessionRouter _config;
    std::shared_ptr<oxen::quic::Loop> _loop;
    std::shared_ptr<session::router::SessionRouter> srouter;
    std::weak_ptr<SnodePool> _snode_pool;
    std::weak_ptr<ITransport> _transport;

    std::unordered_map<std::string, session::router::tunnel_info> _active_tunnels;

    // The claim on each tunnel we have asked session-router for.  session-router closes a tunnel
    // when its last claim is destroyed, so these have to outlive the request that created them:
    // dropping the return value of establish_udp() tears the tunnel down immediately.  Type-erased
    // (each is a session::router::udp_tunnel) so that this header need not include
    // <session/router.hpp>.  Guarded separately from `_active_tunnels` because session-router
    // invokes the failure callback, which releases a claim, from its own thread.
    std::mutex _tunnel_claims_mutex;
    std::unordered_map<std::string, std::shared_ptr<void>> _tunnel_claims;
    std::unordered_map<std::string, std::vector<std::pair<Request, network_response_callback_t>>>
            _pending_requests;
    std::unordered_map<std::string, std::pair<UploadRequest, std::thread>> _active_uploads;
    std::unordered_map<std::string, DownloadRequest> _active_downloads;

  public:
    static std::shared_ptr<SessionRouter> make(
            config::SessionRouter config,
            std::shared_ptr<oxen::quic::Loop> loop,
            std::weak_ptr<SnodePool> snode_pool,
            std::weak_ptr<ITransport> transport);
    ~SessionRouter() override;

    void suspend() override;
    void resume(bool automatically_reconnect = true) override;
    void close_connections() override;
    void clear_cache() override;

    ConnectionStatus get_status() const override { return _status.load(); };
    std::vector<PathInfo> get_active_paths() override;
    void send_request(Request request, network_response_callback_t callback) override;
    void upload(UploadRequest request) override;
    void download(DownloadRequest request) override;

  private:
    std::atomic<ConnectionStatus> _status{ConnectionStatus::unknown};

    SessionRouter(
            config::SessionRouter config,
            std::shared_ptr<oxen::quic::Loop> loop,
            std::weak_ptr<SnodePool> snode_pool,
            std::weak_ptr<ITransport> transport);
    void _init();

    // All of the below functions should only be called from within `_loop`
    void _finish_setup();
    void _close_connections();
    void _update_status(ConnectionStatus new_status);
    void _send_request_internal(Request request, network_response_callback_t callback);
    void _send_direct_request(Request request, network_response_callback_t callback);
    void _send_proxy_request(Request request, network_response_callback_t callback);
    void _upload_internal(UploadRequest request);
    void _download_internal(DownloadRequest request);
    void _establish_tunnel(
            std::span<const unsigned char>& remote_pubkey,
            const uint16_t remote_port,
            const std::string& initiating_req_id);
    void _send_via_tunnel(
            session::router::tunnel_info tunnel,
            Request request,
            network_response_callback_t callback);
};

}  // namespace session::network
