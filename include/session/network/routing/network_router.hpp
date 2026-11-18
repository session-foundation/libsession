#pragma once

#include "session/network/transport/network_transport.hpp"

namespace session::network {

class IRouter {
  public:
    std::function<void()> on_status_changed;

    virtual ~IRouter() = default;

    virtual void suspend() = 0;
    virtual void resume(bool automatically_reconnect = true) = 0;
    virtual void close_connections() = 0;
    virtual void clear_cache() = 0;

    virtual ConnectionStatus get_status() const = 0;
    /// The route traffic to `node` is taking right now, for showing a user where it goes.
    ///
    /// A snapshot, not a commitment: a router may rotate away from it at any time, and asking
    /// again a moment later can legitimately give a different answer.  Nullopt when there is
    /// nothing to report -- nothing has been sent to that node yet, or no route to it exists.
    ///
    /// Takes the whole node rather than its pubkey because sending direct has no route to look
    /// up: the answer is the node itself, and that needs its address.
    virtual std::optional<PathInfo> get_path_to(const service_node&) { return std::nullopt; };
    /// Every path the router is holding open, with how each is performing and how many requests
    /// have gone along it.  A snapshot like `get_path_to`; empty from a router that keeps no paths
    /// of its own.  Safe to call from any thread.
    virtual std::vector<OpenPath> get_open_paths() { return {}; };
    virtual std::vector<service_node> get_all_used_nodes() { return {}; };
    virtual void send_request(Request request, network_response_callback_t callback) = 0;
    [[deprecated("use upload_file() instead")]]
    virtual void upload(UploadRequest request) = 0;
    /// Upload a file from disk with streaming encryption.  The seed is consumed immediately
    /// (before this returns) to initialize the encryption key derivation state.
    virtual void upload_file(FileUploadRequest request, std::span<const std::byte> seed) = 0;
    virtual void download(DownloadRequest request) = 0;
};

}  // namespace session::network