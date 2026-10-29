#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "session/attachments.hpp"
#include "session/network/key_types.hpp"
#include "session/network/service_node.hpp"
#include "session/network/session_network_types.h"
#include "session/sodium_array.hpp"

namespace session::network {

constexpr int16_t ERROR_BAD_REQUEST = 400;
constexpr int16_t ERROR_NOT_ACCEPTABLE = 406;
constexpr int16_t ERROR_REQUEST_TIMEOUT = 408;
constexpr int16_t ERROR_PAYLOAD_TOO_LARGE = 413;
constexpr int16_t ERROR_MISDIRECTED_REQUEST = 421;
constexpr int16_t ERROR_TOO_EARLY = 425;
constexpr int16_t ERROR_NETWORK_MISCONFIGURED = -10001;
constexpr int16_t ERROR_NETWORK_SUSPENDED = -10002;
constexpr int16_t ERROR_NO_TRANSPORT_LAYER = -10003;
constexpr int16_t ERROR_NO_ROUTING_LAYER = -10004;
constexpr int16_t ERROR_NO_SNODE_POOL = -10005;
constexpr int16_t ERROR_CONNECTION_CLOSED = -10006;
constexpr int16_t ERROR_INVALID_DOWNLOAD_URL = -10007;
constexpr int16_t ERROR_FAILED_TO_QUEUE_REQUEST = -10008;
constexpr int16_t ERROR_INVALID_DESTINATION = -10009;
constexpr int16_t ERROR_FAILED_GENERATE_ONION_PAYLOAD = -10010;
constexpr int16_t ERROR_FAILED_TO_GET_STREAM = -10011;
constexpr int16_t ERROR_BUILD_TIMEOUT = -10100;
constexpr int16_t ERROR_REQUEST_CANCELLED = -10200;
constexpr int16_t ERROR_FILE_SERVER_UNAVAILABLE = -10300;
constexpr int16_t ERROR_UNKNOWN = -11000;

const std::pair<std::string, std::string> content_type_plain_text = {
        "Content-Type", "text/plain; charset=UTF-8"};
const std::pair<std::string, std::string> content_type_json = {"Content-Type", "application/json"};

class cancellation_exception : public std::runtime_error {
  public:
    cancellation_exception(std::string message) : std::runtime_error(message) {}
};

class invalid_url_exception : public std::runtime_error {
  public:
    invalid_url_exception(std::string message) : std::runtime_error(message) {}
};

class status_code_exception : public std::runtime_error {
  public:
    int16_t status_code;
    std::vector<std::pair<std::string, std::string>> headers;

    status_code_exception(
            int16_t status_code,
            std::vector<std::pair<std::string, std::string>> headers,
            std::string message) :
            std::runtime_error(message), status_code{status_code}, headers{headers} {}
};

enum class ConnectionStatus {
    unknown = CONNECTION_STATUS_UNKNOWN,
    connecting = CONNECTION_STATUS_CONNECTING,
    connected = CONNECTION_STATUS_CONNECTED,
    disconnected = CONNECTION_STATUS_DISCONNECTED,
};

/// What a Network tells its owner, fixed when the Network is built: it starts connecting in its
/// constructor and reads these on its loop from then on, so there is no later moment at which one
/// could be changed without racing that read.  Any of them may be left empty.  Each is called on
/// the Network's loop, so a hook that blocks holds up the whole network.
struct NetworkHooks {
    /// Notified whenever the network connection status changes, including a final `disconnected`
    /// as the Network is destroyed, which is the last call any of these hooks receives.
    std::function<void(ConnectionStatus status)> status_changed;

    /// Notified when the network's clock offset or fork versions change.
    std::function<void(std::chrono::milliseconds network_time_offset, int hardfork, int softfork)>
            network_info_changed;

    /// Notified when a storage server sends us something we did not ask for, on a connection we
    /// already hold -- which is how a swarm subscription delivers messages.  `node` names the
    /// swarm member; `endpoint` and `body` are the pushed request's, unparsed.
    ///
    /// Only reachable with a routing mode that gives the storage server a connection to us, which
    /// means `session_router` or `direct`.  Under `onion_requests` the server has nothing to push
    /// down: the connection it can see belongs to the last relay rather than to us, so it would
    /// key the subscription to that relay.  This is not a property of onion routing in general --
    /// `session_router` is onion-routed too, and is the mode this exists for.
    std::function<void(
            const ed25519_pubkey& node, std::string_view endpoint, std::span<const std::byte> body)>
            server_push;

    /// Notified once a connection to `node` is usable, including when it comes back after having
    /// been lost.  Per-connection state the far end holds for us -- a subscription -- does not
    /// survive that, so this is where it has to be established again.
    std::function<void(const ed25519_pubkey& node)> connection_established;

    /// Notified when a connection to `node` is gone, for any reason.  A subscription held on it is
    /// gone too, and the far end will not say so: it simply stops pushing.  Not called for the
    /// connections a Network closes as it is destroyed.
    std::function<void(const ed25519_pubkey& node)> connection_lost;
};

/// What a request is for, which decides how it is carried.
///
/// The `_small` distinction is a QUIC stream choice: a small request goes on the connection's
/// reserved stream 0, sharing it with everything else small, while the rest take a stream of their
/// own from the connection's pool.  Ordering is per-stream, so what shares a stream waits for what
/// is ahead of it.
///
/// Two of these are meaningful only under one routing mode, because the thing they distinguish does
/// not exist under the other.
enum class RequestCategory {
    standard = SESSION_NETWORK_REQUEST_CATEGORY_STANDARD,
    standard_small = SESSION_NETWORK_REQUEST_CATEGORY_STANDARD_SMALL,

    /// A file transfer.  Only means anything under `onion_requests`, where a file goes to the file
    /// server through a storage node like everything else and so shares that node's connection.
    /// Session Router reaches the file server directly rather than through a snode, so there is no
    /// shared connection for a file to be separated from.
    file = SESSION_NETWORK_REQUEST_CATEGORY_FILE,
    file_small = SESSION_NETWORK_REQUEST_CATEGORY_FILE_SMALL,

    /// A config push.  Only means anything under Session Router, which holds a real QUIC connection
    /// per storage node and can therefore put this on a stream of its own -- so a large config does
    /// not delay a small store queued behind it on the reserved stream.  Under `onion_requests`
    /// there is no such connection to open a second stream on, and this behaves as
    /// `standard_small`.
    config = SESSION_NETWORK_REQUEST_CATEGORY_CONFIG,
};

enum class PathCategory {
    standard = SESSION_NETWORK_PATH_CATEGORY_STANDARD,
    file = SESSION_NETWORK_PATH_CATEGORY_FILE,
};

inline std::string to_string(RequestCategory category) {
    switch (category) {
        case RequestCategory::standard: return "standard";
        case RequestCategory::standard_small: return "standard_small";
        case RequestCategory::file: return "file";
        case RequestCategory::file_small: return "file_small";
        case RequestCategory::config: return "config";
    }
    return "unknown";  // Should not be reached
}

inline std::string to_string(PathCategory category) {
    switch (category) {
        case PathCategory::standard: return "standard";
        case PathCategory::file: return "file";
    }
    return "unknown";  // Should not be reached
}

inline std::string to_path_prefix(PathCategory category) {
    switch (category) {
        case PathCategory::standard: return "SP";
        case PathCategory::file: return "FP";
    }
    return "UNKNOWN-PATH";  // Should not be reached
}

struct ServerDestination {
    std::string protocol;
    std::string host;
    session::network::x25519_pubkey x25519_pubkey;
    std::optional<uint16_t> port;
    std::optional<std::vector<std::pair<std::string, std::string>>> headers;
    std::string method;

    ServerDestination(
            std::string protocol,
            std::string host,
            session::network::x25519_pubkey x25519_pubkey,
            std::optional<uint16_t> port = std::nullopt,
            std::optional<std::vector<std::pair<std::string, std::string>>> headers = std::nullopt,
            std::string method = "GET") :
            protocol{std::move(protocol)},
            host{std::move(host)},
            x25519_pubkey{std::move(x25519_pubkey)},
            port{std::move(port)},
            headers{std::move(headers)},
            method{std::move(method)} {}
};

using network_destination =
        std::variant<service_node, ServerDestination, oxen::quic::RemoteAddress>;

struct CancellationToken {
    std::atomic<bool> cancelled{false};

    void cancel() { cancelled.store(true); }
    bool is_cancelled() const { return cancelled.load(); }
};

struct UploadInfo {
    std::optional<std::string> file_name;
};

using RequestDetails = std::variant<std::monostate, UploadInfo>;

struct Request {
    std::string request_id;
    network_destination destination;
    std::string endpoint;
    std::optional<std::vector<std::byte>> body;
    RequestCategory category;

    /// Timeout for an in-flight request after it has been sent via the transport mechanism.
    std::chrono::milliseconds request_timeout;

    /// An optional, overall timeout for the entire operation, starting from the moment the request
    /// is created. This includes time spent in queues waiting for a path to be built or a
    /// connection to be established. If this timeout is exceeded while the request is still in a
    /// queue, it will be timed out.
    std::optional<std::chrono::milliseconds> overall_timeout;

    /// An optional value which can be provided to send a request down a specific path, should only
    /// be used for testing. A NULL value will result in a path being selected using the default
    /// behaviour.
    std::optional<uint8_t> desired_path_index;

    /// True when `destination` is the local end of a Session Router tunnel rather than an address
    /// out on the internet.  The transport cannot tell from the address -- it is a loopback port
    /// either way -- and it needs to know, because a handshake whose packets cross a whole tunnel
    /// gets a different budget than one that does not.
    bool tunnelled = false;

    /// Any extra request details which may modify the structure of the request.
    RequestDetails details;

    /// The account whose swarm this request addresses, when it addresses one: the X25519 pubkey of
    /// a session ID, group ID, etc.  Set it for anything sent to a swarm member *about* that
    /// account, and leave it unset for a request merely aimed at a node (a snode cache refresh, a
    /// clock resync), which no swarm membership applies to.
    ///
    /// Set it to have a 421's correction applied: the swarm the storage server reports in the
    /// rejection is written into the cache for *this account*, which cannot be derived from the
    /// node we happened to ask.  Recovering from the 421 is still the caller's -- see
    /// `Network::send_request`.
    std::optional<session::network::x25519_pubkey> swarm_pubkey;

    /// The time the request was created, this is used primarily for determining whether the
    /// `overall_timeout` has been exceeded.
    std::chrono::steady_clock::time_point creation_time = std::chrono::steady_clock::now();

    Request(std::string request_id,
            network_destination destination,
            std::string endpoint,
            std::optional<std::vector<std::byte>> body,
            RequestCategory category,
            std::chrono::milliseconds request_timeout,
            std::optional<std::chrono::milliseconds> overall_timeout = std::nullopt,
            std::optional<uint8_t> desired_path_index = std::nullopt,
            RequestDetails details = std::monostate{});

    Request(network_destination destination,
            std::string endpoint,
            std::optional<std::vector<std::byte>> body,
            RequestCategory category,
            std::chrono::milliseconds request_timeout,
            std::optional<std::chrono::milliseconds> overall_timeout = std::nullopt,
            std::optional<uint8_t> desired_path_index = std::nullopt,
            std::optional<std::string> request_id = std::nullopt,
            RequestDetails details = std::monostate{});

    std::chrono::milliseconds time_remaining() const {
        if (!overall_timeout)
            return request_timeout;

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - creation_time);
        auto remaining = *overall_timeout - elapsed;

        return (remaining > std::chrono::milliseconds::zero() ? remaining
                                                              : std::chrono::milliseconds::zero());
    }
};

struct file_metadata {
    std::string id;
    int64_t size;
    std::chrono::sys_seconds uploaded;
    std::chrono::sys_seconds expiry;
};

struct FileTransferRequest {
    std::chrono::milliseconds stall_timeout = 25s;
    std::chrono::milliseconds request_timeout;
    std::optional<std::chrono::milliseconds> overall_timeout;
    std::chrono::milliseconds progress_interval = 1s;
    std::optional<int8_t> desired_path_index;

    // This shared ptr is designed to be held by the caller (without the rest of the request object)
    // to provide a means to trigger a request cancellation by setting it.
    std::shared_ptr<std::atomic<bool>> cancelled = std::make_shared<std::atomic<bool>>(false);

    void cancel() {
        if (cancelled)
            *cancelled = true;
    }
    bool is_cancelled() const { return !cancelled || *cancelled; }

    // Called when transfer completes (file_metadata) or fails (int16_t error code)
    std::function<void(std::variant<file_metadata, int16_t> result, bool timeout)> on_complete;

    // Called periodically during a transfer with progress information, at most once per
    // progress_interval, and only when progress has been made since the last call.
    // For uploads, progress_bytes is total bytes acked by the remote; for downloads, it is
    // total bytes received.
    std::function<void(int64_t progress_bytes, int64_t total_bytes)> on_progress;
};

struct UploadRequest : FileTransferRequest {
    std::function<std::vector<std::byte>()> next_data;
    std::optional<std::string> file_name;
    std::optional<std::chrono::seconds> ttl;
};

struct FileUploadRequest : FileTransferRequest {
    std::filesystem::path file;
    attachment::Domain domain = attachment::Domain::ATTACHMENT;
    bool allow_large = false;
    std::optional<std::chrono::seconds> ttl;

    // Hides FileTransferRequest::on_complete: this version includes the decryption key
    // alongside the file metadata on success.
    std::function<void(
            std::variant<std::pair<file_metadata, cleared_b32>, int16_t> result, bool timeout)>
            on_complete;
};

struct DownloadRequest : FileTransferRequest {
    std::string download_url;

    // Called as data arrives, once per chunk received, with a non-owning view of that chunk and the
    // file's metadata.  `info.size` is the total, and is known before the first chunk arrives, so a
    // caller wanting transfer progress accumulates the chunk sizes itself rather than being told.
    //
    // Any coalescing of these belongs above this layer: throttling here would mean holding payload
    // to save an in-process call, whereas a consumer relaying progress across a process boundary
    // can drop redundant notifications for free.
    std::function<void(const file_metadata& info, std::span<const std::byte> data)> on_data;
};

using node_failure_reporter_t = std::function<void(const ed25519_pubkey&, bool)>;
using network_response_callback_t = std::function<void(
        bool success,
        bool timeout,
        int16_t status_code,
        std::vector<std::pair<std::string, std::string>> headers,
        std::optional<std::string> response)>;

namespace response {
    std::optional<std::pair<int16_t, bool>> parse_text_error(std::string_view body);
    std::optional<int16_t> find_uniform_batch_error(std::string_view body);
}  // namespace response

/// One hop of a route, for showing a user where their traffic goes.  Identity and location, which
/// is all a diagnostic needs -- deliberately not a `service_node`, because a hop is not always one:
/// a Session Router relay has no ports, no storage server version and no swarm, and filling those
/// in with zeros would make a swarm id of 0 that means something else.
struct PathHop {
    ed25519_pubkey pubkey;
    oxen::quic::ipv4 ip;
};

/// A route, as shown to a user.  Deliberately separate from how a router represents the paths it
/// actually sends on: those carry pool membership, strike counts and other bookkeeping that means
/// nothing outside the router, and mixing the two ends up publishing one to serve the other.
struct PathInfo {
    /// The hops we can see, in order from the one nearest us.
    ///
    /// Whether the last of them is the destination depends on the route, and the caller cannot
    /// tell from here.  Sending direct, the only hop *is* the destination.  A Session Router
    /// tunnel to a `.snode` terminates at the storage node, so it is; a path to a client
    /// terminates at the pivot relay, with the rest belonging to the other side and invisible to
    /// us; and an `onion_requests` path is built before any destination is chosen, so its last
    /// hop is a relay that will forward to whatever the request names.  Reporting what is known
    /// beats a shape that promises a destination which is sometimes a guess.
    std::vector<PathHop> hops;
};

}  // namespace session::network
