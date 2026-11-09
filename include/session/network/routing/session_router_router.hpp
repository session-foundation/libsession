#pragma once

#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "session/network/backends/quic_file_client.hpp"
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

        // See `opt::one_shot`.
        bool one_shot = false;
    };
}  // namespace config

// A tunnel we are holding open, and whether it is usable yet.  Defined in the .cpp: naming
// session-router's claim type here would drag <session/router.hpp> into every consumer of this
// header, and what we hold a tunnel with is nobody else's business.
struct ActiveTunnel;

class SessionRouter : public IRouter, public std::enable_shared_from_this<SessionRouter> {
  private:
    bool _ready = false;
    bool _suspended = false;
    config::SessionRouter _config;
    // The one component that keeps a share of the loop rather than a reference: the session-router
    // library takes a `shared_ptr<Loop>` (router.hpp:137), so ownership has to be shared with it.
    // What keeps that from destroying the loop from its own thread is the same invariant as
    // everywhere else here -- this object is destroyed by whoever owns it, off the loop.
    std::shared_ptr<oxen::quic::Loop> _loop;
    std::shared_ptr<session::router::SessionRouter> srouter;
    std::weak_ptr<SnodePool> _snode_pool;
    std::weak_ptr<ITransport> _transport;

    // Pool of QUIC file server clients, keyed by Ed25519 pubkey.  Multiple requests to the
    // same server share one client (and thus one connection with idle timeout).
    std::unordered_map<ed25519_pubkey, std::unique_ptr<QuicFileClient>> _file_clients;
    std::unordered_map<std::string, std::unique_ptr<ActiveTunnel>> _active_tunnels;
    std::unordered_map<std::string, std::vector<std::pair<Request, network_response_callback_t>>>
            _pending_requests;
    std::vector<std::function<void()>> _pending_operations;
    std::unordered_map<std::string, std::pair<UploadRequest, std::thread>> _active_uploads;
    std::unordered_map<std::string, DownloadRequest> _active_downloads;

    /// This router's own jobs, rather than the loop's shared queue, so that ~SessionRouter can take
    /// them away from the loop before anything is torn down: `stop()` waits out whatever is running
    /// and cancels the rest.  That is what lets the jobs capture `this` bare.
    ///
    /// Declared last so that it is also the first member destroyed.
    oxen::quic::JobQueue _jq{*_loop};

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
    std::optional<PathInfo> get_path_to(const service_node& node) override;
    void send_request(Request request, network_response_callback_t callback) override;
    void upload(UploadRequest request) override;  // deprecated: use upload_file()
    void upload_file(FileUploadRequest request, std::span<const std::byte> seed) override;
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
    void _start_file_upload(
            std::shared_ptr<attachment::Encryptor> enc,
            FileUploadRequest request,
            file_server::SRouterTarget target);
    void _upload_internal_legacy(UploadRequest request, std::string upload_id);
    void _download_internal(DownloadRequest request);
    void _download_internal_legacy(DownloadRequest request, std::string download_id);
    void _cleanup_upload(const std::string& upload_id);
    QuicFileClient& _get_file_client(
            const ed25519_pubkey& pubkey,
            std::string_view address,
            uint16_t port,
            std::optional<size_t> max_udp_payload = std::nullopt);

    void _quic_upload_via_tunnel(
            UploadRequest upload_request,
            std::string upload_id,
            std::vector<std::byte> data,
            session::router::tunnel_info info);
    void _quic_download_via_tunnel(
            DownloadRequest request,
            std::string download_id,
            std::string file_id,
            session::router::tunnel_info info);
    void _establish_tunnel(
            std::span<const std::byte, 32> remote_pubkey,
            const uint16_t remote_port,
            const std::string& initiating_req_id);
    // Takes the tunnel's endpoint by value rather than a reference into `_active_tunnels`: a
    // response callback that runs inline can fail the tunnel out from under us.
    void _send_via_tunnel(
            std::string tunnel_remote,
            uint16_t tunnel_local_port,
            Request request,
            network_response_callback_t callback);

    // The tunnel entry for a node, created empty if we have none yet.
    ActiveTunnel& _tunnel(const std::string& pubkey_hex);

    // Fails every request waiting on a tunnel to `pubkey_hex`, and tells the SnodePool so that the
    // node stops being selected.  `unreachable` distinguishes a node Session Router has no relay
    // contact for -- which will stay unreachable until it rejoins the network -- from one that
    // merely failed to establish this time.
    void _fail_tunnel(const std::string& pubkey_hex, bool unreachable);
};

}  // namespace session::network
