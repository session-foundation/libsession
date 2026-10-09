#pragma once

#include <cstddef>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
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
constexpr int16_t ERROR_UNAUTHENTICATED_RESPONSE = -10012;
constexpr int16_t ERROR_INSUFFICIENT_NODES = -10013;
constexpr int16_t ERROR_BUILD_TIMEOUT = -10100;
constexpr int16_t ERROR_REQUEST_CANCELLED = -10200;
constexpr int16_t ERROR_FILE_SERVER_UNAVAILABLE = -10300;
// A 421 whose swarm could not be corrected, so re-resolving would return the one that rejected us;
// distinct from ERROR_MISDIRECTED_REQUEST, which means re-resolving now gives a better answer.
constexpr int16_t ERROR_SWARM_UNRESOLVED = -10400;
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

    /// The accounts this request addresses: one entry per sub-request of a `batch` or `sequence`,
    /// in order, or a single entry for any other request.  Each is the 32-byte pubkey an account's
    /// swarm is computed from (a session ID or group ID without its prefix); an entry is empty for
    /// a sub-request that isn't about an account.  A single entry applies to every sub-request.
    /// Leave it empty for a request merely aimed at a node (a snode cache refresh, a clock resync).
    ///
    /// Required to recover from a 421: it is what says whose swarm the redirect a 421 carries is
    /// for.  The account a storage server names in a 421 is only checked against it, never trusted
    /// in its place.  Network corrects the swarm but does not retry; that is the caller's -- see
    /// `Network::send_request`.
    std::vector<std::optional<session::network::x25519_pubkey>> swarm_pubkeys;

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

/// The accounts of each sub-request in a pregenerated `batch`/`sequence` body, in the form
/// `Request::swarm_pubkeys` takes, for a request whose body was built by the caller.  A
/// sub-request whose params name no account gets `fallback` instead: the account the caller said
/// the request is for.  Returns nullopt when `endpoint` is neither or the body can't be parsed.
std::optional<std::vector<std::optional<x25519_pubkey>>> batch_request_accounts(
        std::string_view endpoint,
        std::span<const std::byte> body,
        std::optional<x25519_pubkey> fallback = std::nullopt);

namespace response {
    std::optional<std::pair<int16_t, bool>> parse_text_error(std::string_view body);
    std::optional<int16_t> find_uniform_batch_error(std::string_view body);

    /// As `find_uniform_batch_error`, for a body that has already been parsed.
    std::optional<int16_t> uniform_batch_error(const nlohmann::json& json);

    /// The status to report for a proxied response that could not be decrypted, whose status
    /// therefore came from whichever node on the way answered rather than from the destination.
    /// Statuses that are acted on as the destination's verdict (406, 421, 425) become
    /// `ERROR_UNAUTHENTICATED_RESPONSE`, since any node on the path could have sent them; anything
    /// else is returned unchanged.
    int16_t undecrypted_status(int16_t status);

    /// One result of a `batch`/`sequence` response, or the whole of any other response.
    struct subresponse {
        /// The result's own status code; nullopt for a response that isn't a batch, whose status
        /// is the one it came back with.
        std::optional<int16_t> code;

        /// The result's body when it is a JSON object.  Points into the parsed response.
        const nlohmann::json* body = nullptr;
    };

    /// The sub-responses of a parsed response: one per entry of `results` for a batch or sequence,
    /// otherwise the response itself as the only one.  The returned bodies point into `json`.
    std::vector<subresponse> subresponses(const nlohmann::json& json);

    /// The accounts a response's 421s rejected.
    struct swarm_rejections {
        /// Each rejected account, with the ed25519 pubkeys of the swarm its 421 redirected it to:
        /// empty when the 421 named no swarm.  An account with several 421s takes the first.
        std::unordered_map<x25519_pubkey, std::vector<ed25519_pubkey>> accounts;

        /// Whether a 421 could not be attributed to any account.
        bool unattributed = false;
    };

    /// Finds the 421s in a storage server response.  `json` is its parsed body, or null when the
    /// body isn't JSON.  `status_code` is the response's own status, which is the only status a
    /// response that isn't a batch has.  `accounts` is the request's `swarm_pubkeys`, which each
    /// 421 is attributed by; a 421 naming a different account than its position does is ignored.
    swarm_rejections find_swarm_rejections(
            const nlohmann::json* json,
            int16_t status_code,
            std::span<const std::optional<x25519_pubkey>> accounts);
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
