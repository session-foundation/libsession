#include "session/network/routing/onion_request_router.hpp"

#include <event2/event.h>
#include <fmt/ranges.h>

#include <chrono>
#include <exception>
#include <fstream>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <ranges>

#include "session/file.hpp"
#include "session/hash.hpp"
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

namespace fs = std::filesystem;

namespace {
    auto cat = oxen::log::Cat("onion-request-router");

    class pre_decryption_exception : public std::runtime_error {
      public:
        pre_decryption_exception(std::string message) : std::runtime_error(message) {}
    };

    enum class ErrorType {
        IntermediateNodeUnreachable,  // 502, node in path
        DestinationUnreachable,       // 502, destination node
        SnodeNotReady,                // 503, specific snode
        EdgeNotReady,                 // 503, edge node
        PathTimedOut,                 // 504
        InvalidHopResponse,           // 500
        UnparseableData,              // 502 from decrypted payload
        DestinationNotReady,          // 503 from decrypted payload
        ClockOutOfSync,               // 406/425
        SnodeNotInSwarm               // 421
    };

    struct ErrorBehaviour {
        uint16_t code;
        std::string_view body_pattern;
        ErrorType error_type;

        /// Penalty flags - can be combined
        bool penalize_extracted_node = false;
        bool penalize_destination = false;
        bool penalize_edge = false;
        bool penalize_path = false;

        bool force_remove_node = false;  // true = permanent failure, false = single strike
        bool extract_pubkey = false;     // true if `body_pattern` is followed by a node pubkey
    };

    constexpr std::array error_patterns = {
            ErrorBehaviour{
                    .code = 502,
                    .body_pattern = "Next node not found: "sv,
                    .error_type = ErrorType::IntermediateNodeUnreachable,
                    .penalize_extracted_node = true,
                    .penalize_path = true,  // also penalise the path to prevent attempted path
                                            // control via error manipulation
                    .force_remove_node = true,
                    .extract_pubkey = true},

            ErrorBehaviour{
                    .code = 502,
                    .body_pattern = "Next node is currently unreachable: "sv,
                    .error_type = ErrorType::IntermediateNodeUnreachable,
                    .penalize_extracted_node = true,
                    .penalize_path = true,  // also penalise the path to prevent attempted path
                                            // control via error manipulation
                    .force_remove_node = true,
                    .extract_pubkey = true},

            ErrorBehaviour{
                    .code = 502,
                    .body_pattern = "Next node not found: "sv,
                    .error_type = ErrorType::DestinationUnreachable,
                    .penalize_destination = true,
                    .force_remove_node = true,
                    .extract_pubkey = true},

            ErrorBehaviour{
                    .code = 502,
                    .body_pattern = "Next node is currently unreachable: "sv,
                    .error_type = ErrorType::DestinationUnreachable,
                    .penalize_destination = true,
                    .force_remove_node = true,
                    .extract_pubkey = true},

            ErrorBehaviour{
                    .code = 502,
                    .body_pattern = "oxend returned unparsable data"sv,
                    .error_type = ErrorType::UnparseableData,
                    .penalize_destination = true,
                    .force_remove_node = true},

            ErrorBehaviour{
                    .code = 503,
                    .body_pattern = "Snode not ready: "sv,
                    .error_type = ErrorType::SnodeNotReady,
                    .penalize_extracted_node = true,
                    .extract_pubkey = true},

            ErrorBehaviour{
                    .code = 503,
                    .body_pattern = "Service node is not ready: "sv,
                    .error_type = ErrorType::EdgeNotReady,
                    .penalize_edge = true},

            ErrorBehaviour{
                    .code = 503,
                    .body_pattern = "Server busy, try again later"sv,
                    .error_type = ErrorType::EdgeNotReady,
                    .penalize_edge = true},

            ErrorBehaviour{
                    .code = 504,
                    .body_pattern = "Request time out"sv,
                    .error_type = ErrorType::PathTimedOut,
                    .penalize_path = true},

            ErrorBehaviour{
                    .code = 500,
                    .body_pattern = "Invalid response from snode"sv,
                    .error_type = ErrorType::InvalidHopResponse,
                    .penalize_path = true},

            // Cases with custom handling

            ErrorBehaviour{
                    .code = 406, .body_pattern = ""sv, .error_type = ErrorType::ClockOutOfSync},

            ErrorBehaviour{
                    .code = 421, .body_pattern = ""sv, .error_type = ErrorType::SnodeNotInSwarm},
    };

    std::optional<std::pair<ErrorBehaviour, std::optional<std::string_view>>> parse_error_response(
            uint16_t status_code,
            const std::optional<std::string>& error_body,
            std::optional<std::span<const unsigned char>> destination_pubkey) {
        for (const auto& pattern : error_patterns) {
            if (pattern.code != status_code)
                continue;

            // If no body pattern specified (empty string), just match on status code
            std::string_view body_view =
                    (error_body ? std::string_view{*error_body} : std::string_view{});

            if (pattern.body_pattern.empty() ||
                (!body_view.empty() && body_view.find(pattern.body_pattern) != std::string::npos)) {
                std::optional<std::string_view> extracted_pubkey;

                // Extract pubkey if needed
                if (pattern.extract_pubkey && !body_view.empty()) {
                    auto pos = body_view.find(pattern.body_pattern);

                    if (pos != std::string::npos) {
                        auto start = pos + pattern.body_pattern.size();
                        auto end = body_view.find_first_of(" \n\r\t", start);
                        extracted_pubkey =
                                (end != std::string::npos ? body_view.substr(start, end - start)
                                                          : body_view.substr(start));
                    }
                }

                // If we matched on an `IntermediateNodeUnreachable` error then we need to check if
                // it's actually a `DestinationUnreachable` error
                if (pattern.error_type == ErrorType::IntermediateNodeUnreachable &&
                    extracted_pubkey && destination_pubkey && extracted_pubkey->size() == 64 &&
                    oxenc::is_hex(*extracted_pubkey)) {
                    try {
                        auto extracted_key = ed25519_pubkey::from_hex(*extracted_pubkey);
                        auto extracted_span = to_span(extracted_key.view());

                        if (std::equal(
                                    extracted_span.begin(),
                                    extracted_span.end(),
                                    destination_pubkey->begin(),
                                    destination_pubkey->end())) {
                            // It's the destination - find and return the `DestinationUnreachable`
                            // pattern with the same `body_pattern`
                            for (const auto& dest_pattern : error_patterns) {
                                if (dest_pattern.error_type == ErrorType::DestinationUnreachable &&
                                    dest_pattern.body_pattern == pattern.body_pattern) {
                                    return std::pair{dest_pattern, extracted_pubkey};
                                }
                            }
                        }
                    } catch (...) {
                    }
                }

                return std::pair{pattern, extracted_pubkey};
            }
        }

        return std::nullopt;
    }

    inline std::string to_string(PathCategory category, bool single_path_mode) {
        if (single_path_mode)
            return "single_path";

        return to_string(category);
    }

    inline std::string to_path_prefix(PathCategory category, bool single_path_mode) {
        if (single_path_mode)
            return "ONLY-P";

        return to_path_prefix(category);
    }

    inline RequestCategory to_small_request_category(PathCategory category) {
        switch (category) {
            case PathCategory::standard: return RequestCategory::standard_small;
            case PathCategory::file: return RequestCategory::file_small;
        }
        return RequestCategory::standard_small;  // Should not be reached
    }

    std::vector<service_node> extract_nodes(
            const std::unordered_map<PathCategory, std::vector<OnionPath>>& paths,
            const std::unordered_map<
                    std::string,
                    std::pair<
                            std::vector<service_node>,
                            std::optional<std::chrono::system_clock::time_point>>>& pending_paths) {
        std::vector<service_node> all_used_nodes;

        for (const auto& [pt, path_list] : paths)
            for (const auto& p : path_list)
                all_used_nodes.insert(all_used_nodes.end(), p.nodes.begin(), p.nodes.end());

        for (const auto& [pid, nodes_and_timestamp] : pending_paths)
            all_used_nodes.insert(
                    all_used_nodes.end(),
                    nodes_and_timestamp.first.begin(),
                    nodes_and_timestamp.first.end());

        return all_used_nodes;
    }
}  // namespace

std::string OnionPath::to_string() const {
    std::vector<std::string> node_descriptions;
    std::transform(
            nodes.begin(),
            nodes.end(),
            std::back_inserter(node_descriptions),
            [](const service_node& node) { return node.to_string(); });

    return "{}"_format(fmt::join(node_descriptions, ", "));
}

cached_edge_node cached_edge_node::from_disk(std::string_view str) {
    auto parts = split(str, "|");
    if (parts.size() < 7)
        throw std::invalid_argument("Invalid cached edge node serialisation: {}"_format(str));

    // Parse the service_node (first 6 parts)
    auto value = fmt::format("{}", fmt::join(std::span(parts.begin(), parts.begin() + 6), "|"));
    auto node = service_node::from_disk(value);

    // Parse timestamp if present, otherwise use current time
    std::chrono::system_clock::time_point cached_at;
    int64_t timestamp;
    if (quic::parse_int(parts[6], timestamp))
        cached_at = std::chrono::sys_seconds{std::chrono::seconds{timestamp}};
    else
        cached_at = std::chrono::system_clock::now();

    return {std::move(node), cached_at};
}

OnionRequestRouter::OnionRequestRouter(
        config::OnionRequestRouter config,
        std::shared_ptr<oxen::quic::Loop> loop,
        std::shared_ptr<oxen::quic::Loop> disk_loop,
        std::weak_ptr<SnodePool> snode_pool,
        std::weak_ptr<ITransport> transport) :
        _config{std::move(config)},
        _loop{loop},
        _disk_loop{disk_loop},
        _snode_pool{snode_pool},
        _transport{transport} {
    log::trace(cat, "Initializing.");

    _request_queues[PathCategory::standard] = detail::RequestQueue::make(_loop);
    _request_queues[PathCategory::file] = detail::RequestQueue::make(_loop);

    if (_config.cache_directory) {
        std::string cache_file_name;

        switch (_config.netid) {
            case opt::netid::Target::mainnet: cache_file_name = "edge_nodes"; break;
            case opt::netid::Target::testnet: cache_file_name = "edge_nodes_testnet"; break;
            case opt::netid::Target::devnet:
                std::string seed_node_data;

                for (const auto& node : _config.seed_nodes)
                    node.to_disk(std::back_inserter(seed_node_data));

                auto hash_bytes = session::hash::hash(32, session::to_span(seed_node_data));
                cache_file_name = "edge_nodes_devnet_" + oxenc::to_hex(hash_bytes);
                break;
        }

        _edge_node_cache_file_path = *_config.cache_directory / cache_file_name;
        _load_from_disk();
    }

    _loop->call_soon([this] {
        auto snode_pool = _snode_pool.lock();
        if (!snode_pool) {
            log::critical(cat, "SnodePool was destroyed, cannot setup router.");
            return;
        }

        if (snode_pool->size() == 0)
            snode_pool->refresh_if_needed({}, [weak_self = weak_from_this()](bool refreshed) {
                // Setup finishes either way: not finishing leaves the router permanently unusable,
                // where finishing with an empty pool just means the first request refreshes again
                if (!refreshed)
                    log::warning(cat, "Finishing router setup without a refreshed snode pool.");

                if (auto self = weak_self.lock())
                    self->_loop->call([weak_self] {
                        if (auto self = weak_self.lock())
                            self->_finish_setup();
                    });
            });
        else
            _finish_setup();
    });
}

OnionRequestRouter::~OnionRequestRouter() {
    // Use 'call_get' to force this to be synchronous
    if (_loop)
        _loop->call_get([this] { _close_connections(); });

    log::debug(cat, "Destroyed.");
}

// MARK: Disk I/O Functions

void OnionRequestRouter::_load_from_disk() {
    if (_edge_node_cache_file_path.empty()) {
        log::error(cat, "Tried to load cache from disk without a cache file path.");
        return;
    }

    // Load the cache if present
    try {
        if (!fs::exists(_edge_node_cache_file_path))
            throw empty_file_exception{};

        std::vector<std::byte> loaded_edge_node_data = read_whole_file(_edge_node_cache_file_path);
        std::vector<cached_edge_node> loaded_edge_nodes;
        auto invalid_entries = 0;
        auto expired_entries = 0;

        auto now = std::chrono::system_clock::now();
        auto edge_node_expiration_timestamp = (now - _config.edge_node_cache_duration);
        std::string_view data_view(
                reinterpret_cast<const char*>(loaded_edge_node_data.data()),
                loaded_edge_node_data.size());
        loaded_edge_nodes.reserve(
                (data_view.size() / cached_edge_node_disk_format::MAX_LINE_SIZE) +
                1);  // +1 for safety

        size_t start = 0;
        while (start < data_view.size()) {
            // Find either \n or \r
            size_t end = data_view.find_first_of("\n\r", start);
            if (end == std::string_view::npos)
                end = data_view.size();

            if (end > start) {  // Skip empty lines
                std::string_view line = data_view.substr(start, end - start);

                try {
                    auto edge_node = cached_edge_node::from_disk(line);

                    if (edge_node.first_connected_at > edge_node_expiration_timestamp)
                        loaded_edge_nodes.push_back(cached_edge_node::from_disk(line));
                    else
                        ++expired_entries;
                } catch (...) {
                    ++invalid_entries;
                }
            }

            // Skip past any line ending characters (\n, \r, or both in any order)
            start = end;
            while (start < data_view.size() &&
                   (data_view[start] == '\n' || data_view[start] == '\r')) {
                ++start;
            }
        }

        if (loaded_edge_node_data.size() > 0 && loaded_edge_nodes.size() == 0 &&
            invalid_entries > 0)
            throw std::runtime_error{"Edge node cache has invalid format"};

        if (expired_entries > 0)
            log::warning(cat, "Skipped {} expired entries in edge node cache.", expired_entries);

        if (invalid_entries > 0)
            log::warning(cat, "Skipped {} invalid entries in edge node cache.", invalid_entries);

        std::shuffle(loaded_edge_nodes.begin(), loaded_edge_nodes.end(), csrng);
        _cached_edge_nodes = std::move(loaded_edge_nodes);

        log::info(cat, "Loaded cache of {} edge nodes.", _cached_edge_nodes.size());
    } catch (const empty_file_exception) {
        log::info(cat, "No existing edge node cache.");
    } catch (const std::exception& e) {
        log::error(cat, "Failed to load edge node cache ({}).", e.what());

        if (fs::exists(_edge_node_cache_file_path))
            fs::remove_all(_edge_node_cache_file_path);
    }
}

void OnionRequestRouter::_clear_disk_cache(const std::filesystem::path& file_path) {
    try {
        if (!file_path.empty() && fs::exists(file_path))
            fs::remove_all(file_path);
        log::info(cat, "Cleared edge node cache from disk.");
    } catch (const std::exception& e) {
        log::error(cat, "Failed to clear edge node cache file: {}", e.what());
    }
}

void OnionRequestRouter::_perform_edge_node_write(
        const std::filesystem::path& file_path, std::span<const cached_edge_node> edge_nodes) {
    if (file_path.empty())
        return;

    try {
        // Create the cache directories if needed
        fs::create_directories(file_path.parent_path());

        // Save the edge nodes to disk
        auto tmp_path = file_path;
        tmp_path += u8"_new";

        {
            std::string output_buffer;
            output_buffer.reserve(edge_nodes.size() * cached_edge_node_disk_format::MAX_LINE_SIZE);

            for (const auto& edge_node : edge_nodes)
                edge_node.to_disk(std::back_inserter(output_buffer));

            std::ofstream file(tmp_path, std::ios::binary);
            file.write(output_buffer.data(), output_buffer.size());
            file.close();
        }

        fs::rename(tmp_path, file_path);
        log::debug(cat, "Finished writing edge node cache to disk.");
    } catch (const std::exception& e) {
        log::error(cat, "Failed to write edge node cache: {}", e.what());
    }
}

// MARK: IRouter

void OnionRequestRouter::suspend() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] {
        _suspended = true;

        // Write the edge nodes to disk before suspension completes
        if (_disk_loop) {
            std::vector<cached_edge_node> edge_nodes;

            for (const auto& path_list : std::views::values(_paths))
                for (const auto& path : path_list)
                    if (!path.nodes.empty())
                        edge_nodes.emplace_back(path.nodes[0], path.edge_first_connected_at);

            _disk_loop->call([path = _edge_node_cache_file_path, nodes = std::move(edge_nodes)] {
                OnionRequestRouter::_perform_edge_node_write(path, nodes);
            });
        }

        _close_connections();
        log::info(cat, "Suspended.");
    });
}

void OnionRequestRouter::resume(bool automatically_reconnect) {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this, automatically_reconnect] {
        if (!_suspended)
            return;

        _suspended = false;

        if (automatically_reconnect)
            _pre_build_paths_if_needed();

        log::info(cat, "Resumed.");
    });
}

void OnionRequestRouter::close_connections() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] { _close_connections(); });
}

void OnionRequestRouter::clear_cache() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] {
        _cached_edge_nodes = {};

        _disk_loop->call([path = _edge_node_cache_file_path] {
            OnionRequestRouter::_clear_disk_cache(path);
        });
    });
}

std::vector<PathInfo> OnionRequestRouter::get_active_paths() {
    return _loop->call_get([this] {
        std::vector<PathInfo> result;
        result.reserve(_paths.size());

        for (const auto& [category, path_list] : _paths)
            for (const auto& p : path_list)
                result.push_back({p.nodes, OnionPathMetadata{category}});

        return result;
    });
}

std::vector<service_node> OnionRequestRouter::get_all_used_nodes() {
    return _loop->call_get([this] { return extract_nodes(_paths, _pending_paths); });
}

void OnionRequestRouter::send_request(Request request, network_response_callback_t callback) {
    _loop->call([weak_self = weak_from_this(), req = std::move(request), cb = std::move(callback)] {
        if (auto self = weak_self.lock())
            self->_send_request_internal(std::move(req), std::move(cb));
    });
}

void OnionRequestRouter::upload(UploadRequest request) {
    _loop->call([weak_self = weak_from_this(), req = std::move(request)] {
        if (auto self = weak_self.lock())
            self->_upload_internal(std::move(req));
    });
}

void OnionRequestRouter::download(DownloadRequest request) {
    _loop->call([weak_self = weak_from_this(), req = std::move(request)] {
        if (auto self = weak_self.lock())
            self->_download_internal(std::move(req));
    });
}

// MARK: Internal Logic

void OnionRequestRouter::_finish_setup() {
    // Start processing requests
    _ready = true;
    log::debug(cat, "Finishing setup, router is now ready.");

    // Pre-build paths if needed
    _pre_build_paths_if_needed();

    // Process any requests that were queued before we were ready
    for (auto& [category, queue] : _request_queues) {
        if (!queue->is_empty()) {
            auto pending = queue->pop_all();
            log::debug(
                    cat,
                    "Processing {} requests queued during initialization for category '{}'.",
                    pending.size(),
                    to_string(category));

            for (auto& [req, cb] : pending)
                _send_request_internal(std::move(req), std::move(cb));
        }
    }
}

// A cached edge node is handed to `_build_path` as a forced first hop, so it is the one node in a
// path that never passes the strike filter `get_unused_nodes` applies to the rest, and the only
// thing that dropped it was `edge_node_cache_duration` (10 days).
//
// Being struck out costs it the cached-edge-node role, not its place in the pool: it stays a node
// like any other and `get_unused_nodes` can pick it again once its strikes expire.  Keeping the
// entry and merely skipping it would hand the role back at that expiry, by which point we have been
// running on a different edge node for two days - that is a second change of first hop, not a
// return to a stable one.
void OnionRequestRouter::_drop_struck_cached_edge_nodes() {
    auto snode_pool = _snode_pool.lock();

    if (!snode_pool)
        return;

    std::erase_if(_cached_edge_nodes, [&snode_pool](const auto& cached) {
        if (!snode_pool->node_struck_out(cached.node))
            return false;

        log::debug(
                cat,
                "Dropping cached edge node {}, it has been struck out.",
                cached.node.to_string());
        return true;
    });
}

void OnionRequestRouter::_pre_build_paths_if_needed() {
    if (!_config.disable_pre_build_paths) {
        log::info(cat, "Pre-building initial paths.");
        _drop_struck_cached_edge_nodes();
        std::vector<cached_edge_node> edge_nodes = _cached_edge_nodes;

        if (_config.single_path_mode) {
            std::optional<cached_edge_node> edge_node = std::nullopt;
            if (!edge_nodes.empty()) {
                edge_node = edge_nodes.back();
                edge_nodes.pop_back();
            }

            log::debug(
                    cat,
                    "Pre-building 1 path for single_path_mode{}.",
                    (!edge_node.has_value() ? " with cached edge node" : ""));
            _build_path(
                    PathCategory::standard,
                    "pre-build-{}-{}"_format(to_string(PathCategory::standard, true), 1),
                    {},
                    std::nullopt,
                    (edge_node ? std::optional{edge_node->node} : std::nullopt),
                    (edge_node ? std::optional{edge_node->first_connected_at} : std::nullopt));
        } else {
            for (const auto& [category, min_count] : _config.min_path_counts) {
                for (int i = 0; i < min_count; ++i) {
                    std::optional<cached_edge_node> edge_node = std::nullopt;
                    if (!edge_nodes.empty()) {
                        edge_node = edge_nodes.back();
                        edge_nodes.pop_back();
                    }

                    log::debug(
                            cat,
                            "Pre-building {} path(s) for category '{}'{}.",
                            min_count,
                            to_string(category, _config.single_path_mode),
                            (!edge_node.has_value() ? " with cached edge node" : ""));
                    _build_path(
                            category,
                            "pre-build-{}-{}"_format(to_string(category, false), i + 1),
                            {},
                            std::nullopt,
                            (edge_node ? std::optional{edge_node->node} : std::nullopt),
                            (edge_node ? std::optional{edge_node->first_connected_at}
                                       : std::nullopt));
                }
            }
        }
    } else
        log::debug(cat, "Path pre-building is disabled.");
}

void OnionRequestRouter::_close_connections() {
    std::vector<std::thread> threads_to_join;

    // Cancel any uploads and downloads
    for (auto& [id, request_and_thread] : _active_uploads) {
        if (request_and_thread.second.joinable())
            threads_to_join.push_back(std::move(request_and_thread.second));

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
    for (auto& [path_type, path_type_queue] : _request_queues) {
        auto to_fail = path_type_queue->pop_all();

        for (const auto& [req, callback] : to_fail)
            callback(
                    false,
                    false,
                    ERROR_NETWORK_SUSPENDED,
                    {content_type_plain_text},
                    "Network is suspended.");
    }

    // Stop any pending path rotations
    if (_path_rotation_timer) {
        event_del(_path_rotation_timer.get());
        _path_rotation_timer.reset();
    }

    // Remove any failure listeners for the edge nodes of the current paths
    if (auto transport = _transport.lock())
        for (const auto& [category, path_list] : _paths)
            for (const auto& p : path_list)
                if (!p.nodes.empty())
                    transport->remove_failure_listeners(
                            ed25519_pubkey::from_bytes(p.nodes[0].view_remote_key()));

    // Clear all storage of requests, paths and connections so that we are in a fresh state on
    // relaunch
    //
    // The connection status is recalculated based on these values so we need to call them
    // before recalculation so it correctly detects the "disconnected" state
    _paths.clear();
    _paths_pending_drop.clear();
    _in_progress_path_builds.clear();
    _path_build_retries.clear();
    _pending_paths.clear();
    _path_rotation_schedule.clear();
    _pending_rotation_paths.clear();
    _update_status();

    // Block until upload threads have finished
    for (auto& t : threads_to_join)
        if (t.joinable())
            t.join();

    log::info(cat, "Closed all connections.");
}

void OnionRequestRouter::_update_status() {
    ConnectionStatus new_status = ConnectionStatus::disconnected;

    // If we have at least one active "standard" path we are considered connected
    auto paths_it = _paths.find(PathCategory::standard);
    if (paths_it != _paths.end() && !paths_it->second.empty())
        new_status = ConnectionStatus::connected;
    // If we have at least one active non-standard path then considered connecting (not properly
    // connected, but some requests may work)
    else if (std::any_of(
                     _paths.begin(), _paths.end(), [](const auto& p) { return !p.second.empty(); }))
        new_status = ConnectionStatus::connecting;
    // Otherwise if we are building one then we are connecting
    else if (std::any_of(
                     _in_progress_path_builds.begin(),
                     _in_progress_path_builds.end(),
                     [](const auto& p) { return p.second > 0; }))
        new_status = ConnectionStatus::connecting;

    if (_status.load() != new_status) {
        _status.store(new_status);

        if (on_status_changed)
            on_status_changed();
    }
}

void OnionRequestRouter::_send_request_internal(
        Request request, network_response_callback_t callback) {
    // If we are suspended then fail immediately
    if (_suspended)
        return callback(
                false,
                false,
                ERROR_NETWORK_SUSPENDED,
                {content_type_plain_text},
                "OnionRequestRouter is suspended.");

    auto path_category_for_initiating_req =
            (_config.single_path_mode ? PathCategory::standard
                                      : to_path_category(request.category));

    if (!_ready) {
        log::debug(cat, "[Request {}]: Router not ready, queueing request.", request.request_id);

        try {
            _request_queues.at(path_category_for_initiating_req)
                    ->add(std::move(request), std::move(callback));
        } catch (const std::exception& e) {
            log::critical(
                    cat,
                    "No request queue for category '{}', request {} is being dropped.",
                    to_string(path_category_for_initiating_req, _config.single_path_mode),
                    request.request_id);
            return callback(
                    false,
                    false,
                    ERROR_FAILED_TO_QUEUE_REQUEST,
                    {content_type_plain_text},
                    "Unhandled request category");
        }
        return;
    }

    // Try to use an existing path if we have one
    log::trace(
            cat,
            "[Request {}]: Received request for category '{}', searching for a path.",
            request.request_id,
            to_string(path_category_for_initiating_req, _config.single_path_mode));
    OnionPath* path = _find_valid_path(request);

    if (path) {
        log::debug(
                cat, "[Request {}]: Found valid path {}, sending.", request.request_id, path->id);
        _send_on_path(*path, std::move(request), std::move(callback));
        return;
    }

    // No valid path, queue the request an build a path
    log::debug(cat, "[Request {}]: No path available, queueing request.", request.request_id);

    // Add the request to the queue for its category
    auto initiating_req_id = request.request_id;

    try {
        _request_queues.at(path_category_for_initiating_req)
                ->add(std::move(request), std::move(callback));
    } catch (const std::exception& e) {
        log::critical(
                cat,
                "No request queue for category '{}', request {} is being dropped.",
                to_string(path_category_for_initiating_req, _config.single_path_mode),
                request.request_id);
        return callback(
                false,
                false,
                ERROR_FAILED_TO_QUEUE_REQUEST,
                {content_type_plain_text},
                "Unhandled request category");
    }

    // Check if we need to build additional paths
    const auto current = _paths.count(path_category_for_initiating_req)
                               ? _paths.at(path_category_for_initiating_req).size()
                               : 0;
    const auto in_progress = _in_progress_path_builds[path_category_for_initiating_req];
    bool should_build = false;

    // In single path mode, we only build if we have zero paths (current or in-progress)
    if (_config.single_path_mode)
        should_build = (current + in_progress == 0);
    else {
        // In multi-path mode, we build if we are below the min number
        const auto needed = _config.min_path_counts.at(path_category_for_initiating_req);
        should_build = (current + in_progress < needed);
    }

    if (should_build) {
        log::info(
                cat,
                "[Request {}]: Path count for '{}' is insufficient, building new path.",
                initiating_req_id,
                to_string(path_category_for_initiating_req, _config.single_path_mode));

        _build_path(path_category_for_initiating_req, initiating_req_id, {});
    }
}

void OnionRequestRouter::_upload_internal(UploadRequest request) {
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

void OnionRequestRouter::_download_internal(DownloadRequest request) {
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

void OnionRequestRouter::_build_path(
        PathCategory category,
        std::optional<std::string> initiating_req_id,
        const std::vector<service_node>& nodes_to_exclude_,
        std::optional<std::string> original_path_id,
        std::optional<service_node> specific_edge_node,
        std::optional<std::chrono::system_clock::time_point> edge_node_first_connection_at) {
    if (_suspended) {
        log::info(cat, "Ignoring build_path call as network is suspended.");
        return;
    }

    const std::string req_id_log = (initiating_req_id ? *initiating_req_id : "internal");
    const std::string path_id =
            original_path_id.value_or(random::unique_id(to_path_prefix(category)));
    log::info(
            cat,
            "[Request {} Path {}]: Starting build for {} path.",
            req_id_log,
            path_id,
            to_string(category, _config.single_path_mode));

    // If we were misconfigured to have a `path_length` of `0` then just fail all requests
    if (_config.path_length == 0) {
        log::error(
                cat,
                "[Request {} Path {}]: Cannot build path, path_size is configured to 0.",
                req_id_log,
                path_id);

        auto queue_it = _request_queues.find(category);
        if (queue_it == _request_queues.end()) {
            log::critical(
                    cat,
                    "No request queue for category '{}'.",
                    to_string(category, _config.single_path_mode));
            return;
        }

        if (!queue_it->second->is_empty()) {
            auto to_fail = queue_it->second->pop_all();

            for (const auto& [req, cb] : to_fail)
                cb(false,
                   false,
                   ERROR_NETWORK_MISCONFIGURED,
                   {content_type_plain_text},
                   "Router misconfigured: path_length is 0.");
        }
        return;
    }

    _in_progress_path_builds[category]++;
    _update_status();

    auto nodes_to_exclude = extract_nodes(_paths, _pending_paths);
    nodes_to_exclude.insert(
            nodes_to_exclude.end(), nodes_to_exclude_.begin(), nodes_to_exclude_.end());

    auto snode_pool = _snode_pool.lock();
    if (!snode_pool) {
        log::critical(cat, "SnodePool was destroyed, cannot build path.");
        return;
    }

    // Get enough nodes for the path (use the specified edge-node if provided)
    auto path_nodes = snode_pool->get_unused_nodes(
            (specific_edge_node.has_value() ? _config.path_length - 1 : _config.path_length),
            nodes_to_exclude);

    if (specific_edge_node)
        path_nodes.insert(path_nodes.begin(), *specific_edge_node);

    // If we don't have enough nodes to build a path then we should try to refresh the snode pool
    if (path_nodes.size() < _config.path_length) {
        log::warning(
                cat,
                "[Request {} Path {}]: Failed to get enough nodes from SnodePool (need {}, got "
                "{}), queueing retry after pool refresh.",
                req_id_log,
                path_id,
                _config.path_length,
                path_nodes.size());
        _in_progress_path_builds[category]--;

        snode_pool->refresh_if_needed(
                nodes_to_exclude,
                [weak_self = weak_from_this(), this, category, initiating_req_id, nodes_to_exclude](
                        bool refreshed) {
                    auto self = weak_self.lock();
                    if (!self)
                        return;

                    // Rebuilding lands back in this same branch unless the pool can now fill a
                    // path, and `refreshed` includes nothing having needed refreshing, which calls
                    // back inline - so rebuilding without checking first recurses until the stack
                    // gives out
                    std::optional<std::string_view> cannot_build;
                    if (!refreshed)
                        cannot_build = "the snode pool could not be refreshed";
                    else if (auto pool = _snode_pool.lock();
                             !pool ||
                             pool->get_unused_nodes(_config.path_length, nodes_to_exclude).size() <
                                     _config.path_length)
                        cannot_build = "the snode pool has too few usable nodes";

                    if (cannot_build) {
                        log::error(
                                cat,
                                "[Request {}]: Cannot build a path, {}.",
                                initiating_req_id.value_or("internal"),
                                *cannot_build);
                        _update_status();

                        auto queue_it = _request_queues.find(category);
                        if (queue_it == _request_queues.end()) {
                            log::critical(
                                    cat,
                                    "No request queue for category '{}'.",
                                    to_string(category, _config.single_path_mode));
                            return;
                        }

                        if (!queue_it->second->is_empty()) {
                            auto to_fail = queue_it->second->pop_all();
                            log::error(
                                    cat,
                                    "Failing {} queued requests for '{}' paths; {}.",
                                    to_fail.size(),
                                    to_string(category, _config.single_path_mode),
                                    *cannot_build);

                            for (const auto& [req, cb] : to_fail)
                                cb(false,
                                   false,
                                   ERROR_INSUFFICIENT_NODES,
                                   {content_type_plain_text},
                                   "Cannot build a path: {}."_format(*cannot_build));
                        }
                        return;
                    }

                    log::info(
                            cat,
                            "[Request {}]: SnodePool refresh complete, retrying path build.",
                            initiating_req_id.value_or("internal"));
                    _build_path(category, initiating_req_id, nodes_to_exclude);
                });
        return;
    }

    // Attempty to verify connectivity to the edge node
    _pending_paths[path_id] = std::make_pair(path_nodes, edge_node_first_connection_at);
    auto edge_node = path_nodes.front();
    log::debug(
            cat,
            "[Request {} Path {}]: Testing connectivity to edge node {}.",
            req_id_log,
            path_id,
            edge_node.to_string());

    auto transport = _transport.lock();
    if (!transport) {
        log::critical(cat, "Transport was destroyed, cannot build path.");
        return;
    }

    transport->verify_connectivity(
            edge_node,
            3s,
            "{} - Path Build {}"_format(req_id_log, path_id),
            to_small_request_category(category),  // "small" category for reserved stream
            [weak_self = weak_from_this(), path_id, category, initiating_req_id](
                    bool success, std::optional<uint64_t> error_code) {
                if (auto self = weak_self.lock())
                    self->_on_edge_connectivity_response(
                            path_id, category, initiating_req_id, success, error_code);
            });
}

void OnionRequestRouter::_on_edge_connectivity_response(
        const std::string& path_id,
        PathCategory category,
        std::optional<std::string> initiating_req_id,
        bool success,
        std::optional<uint64_t> error_code) {
    const std::string req_id_log = initiating_req_id.value_or("internal");

    auto pending_it = _pending_paths.find(path_id);
    if (pending_it == _pending_paths.end()) {
        log::warning(
                cat,
                "[Request {} Path {}]: Received connection callback for a path that is no longer "
                "pending, ignoring.",
                req_id_log,
                path_id);
        return;
    }

    // Extract the pending path nodes and remove it from the pending list
    auto [path_nodes, edge_node_first_connection_at] = std::move(pending_it->second);
    _pending_paths.erase(pending_it);

    const auto& edge_node = path_nodes.front();

    if (_in_progress_path_builds[category] > 0)
        _in_progress_path_builds[category]--;

    if (!success) {
        // The edge node failed so record the failure and try to build a new path to replace this
        // failed one (excluding the failed edge node from the next attempt)
        log::warning(
                cat,
                "[Request {} Path {}]: Failed to verify connectivity to edge node {}, retrying "
                "path build.",
                req_id_log,
                path_id,
                edge_node.to_string());

        // The "handshake timeout" error already records a node failure, so don't record another
        if (error_code && *error_code != static_cast<uint64_t>(NGTCP2_ERR_HANDSHAKE_TIMEOUT))
            if (auto snode_pool = _snode_pool.lock())
                snode_pool->record_node_failure(edge_node);

        int& retries = _path_build_retries[path_id];
        retries++;

        // If we tried, and failed, to build the path too many times then give up and fail all
        // pending requests
        if (retries > _config.path_build_retry_limit) {
            log::critical(
                    cat, "[Path {}]: Aborting build after {} failed attempts.", path_id, retries);
            _path_build_retries.erase(path_id);
            _update_status();

            auto queue_it = _request_queues.find(category);
            if (queue_it == _request_queues.end()) {
                log::critical(
                        cat,
                        "No request queue for category '{}'.",
                        to_string(category, _config.single_path_mode));
                return;
            }

            if (!queue_it->second->is_empty()) {
                auto to_fail = queue_it->second->pop_all();
                log::error(
                        cat,
                        "Failing {} queued requests for '{}' paths due to persistent path build "
                        "failures.",
                        to_fail.size(),
                        to_string(category, _config.single_path_mode));

                for (const auto& [req, cb] : to_fail)
                    cb(false,
                       false,
                       -1,
                       {content_type_plain_text},
                       "Failed to build a required onion path after multiple retries.");
            }
            return;
        }

        auto delay = _config.retry_delay.exponential(retries);
        log::info(
                cat,
                "[Path {}]: Retrying path build in {}ms (attempt {}/{})",
                path_id,
                delay.count(),
                retries,
                _config.path_build_retry_limit);
        _update_status();

        _loop->call_later(
                delay,
                [weak_self = weak_from_this(), path_id, category, initiating_req_id, edge_node] {
                    if (auto self = weak_self.lock())
                        self->_build_path(category, initiating_req_id, {edge_node}, path_id);
                });
        return;
    }

    auto created_at = std::chrono::system_clock::now();
    auto edge_first_connected_at =
            (edge_node_first_connection_at.has_value() ? *edge_node_first_connection_at
                                                       : created_at);
    auto rotate_at = (std::chrono::steady_clock::now() + _config.path_rotation_frequency);

    OnionPath new_path{path_id, std::move(path_nodes), created_at, edge_first_connected_at};
    log::info(
            cat,
            "[Request {} Path {}]: New {} path is active with nodes: [{}].",
            req_id_log,
            path_id,
            to_string(category, _config.single_path_mode),
            new_path.to_string());
    _paths[category].push_back(std::move(new_path));
    _path_build_retries.erase(path_id);
    _schedule_path_rotation(path_id, category, rotate_at);
    _update_status();

    // Now, check the queue for any requests that were waiting for this path.
    auto queue_it = _request_queues.find(category);
    if (queue_it == _request_queues.end()) {
        log::critical(
                cat,
                "No request queue for category '{}'.",
                to_string(category, _config.single_path_mode));
        return;
    }

    auto pending_requests = queue_it->second->pop_all();

    if (!pending_requests.empty()) {
        std::deque<std::pair<Request, network_response_callback_t>> requeue;
        log::debug(
                cat,
                "[Request {} Path {}]: Processing {} queued requests.",
                req_id_log,
                path_id,
                pending_requests.size());

        for (auto&& [req, cb] : std::move(pending_requests)) {
            // Retrieve any path that is valid for the request
            OnionPath* path_to_use = _find_valid_path(req);

            if (path_to_use)
                _send_on_path(*path_to_use, std::move(req), std::move(cb));
            else
                requeue.emplace_back(std::move(req), std::move(cb));
        }

        // Put any un-sendable requests back into the front of the queue (or fail in
        // `single_path_mode`)
        if (!requeue.empty()) {
            if (_config.single_path_mode) {
                log::warning(
                        cat,
                        "[Path {}]: {} requests could not be sent on the single available path, "
                        "failing them.",
                        path_id,
                        requeue.size());
                for (const auto& [req, cb] : requeue)
                    cb(false,
                       false,
                       ERROR_INVALID_DESTINATION,
                       {content_type_plain_text},
                       "Request destination conflicts with the only available path in "
                       "single_path_mode");

                return;
            }

            log::debug(
                    cat,
                    "[Path {}]: Unable to process {} queued requests, requing them.",
                    path_id,
                    requeue.size());

            while (!requeue.empty()) {
                auto& req_pair = requeue.back();
                queue_it->second->add_front(std::move(req_pair));
                requeue.pop_back();
            }

            if (_in_progress_path_builds[category] == 0) {
                log::info(
                        cat,
                        "Building additional {} path for remaining requests.",
                        to_string(category, _config.single_path_mode));
                _build_path(category, "requeue-build", {});
            }
        }
    }

    // Now that we've established a path we need to start observing it in case the connection is
    // lost
    auto transport = _transport.lock();
    if (!transport)
        return;

    transport->add_failure_listener(
            ed25519_pubkey::from_bytes(edge_node.view_remote_key()),
            [weak_self = weak_from_this(), this, pid = path_id, category] {
                auto self = weak_self.lock();
                if (!self)
                    return;

                log::warning(
                        cat,
                        "[Path {}]: Transport reported connection failure, retiring path.",
                        pid);

                // Set the strike_count of the path to the max value and report the error
                // to trigger a rebuild
                auto& active_paths = _paths[category];
                auto path_it = std::find_if(
                        active_paths.begin(), active_paths.end(), [&pid](const auto& p) {
                            return p.id == pid;
                        });

                if (path_it != active_paths.end())
                    path_it->strike_count = _config.path_strike_threshold;

                _handle_path_failure(pid, category, {});
            });
}

OnionPath* OnionRequestRouter::_find_valid_path(const Request& request) {
    // If we are in `single_path_mode` then just return the first path we have (don't care about
    // category as there should only be one path)
    if (_config.single_path_mode) {
        for (auto& [category, category_paths] : _paths)
            if (!category_paths.empty())
                return &category_paths.front();
        return nullptr;
    }

    auto it = _paths.find(to_path_category(request.category));
    if (it == _paths.end() || it->second.empty())
        return nullptr;

    std::vector<OnionPath>& candidate_paths = it->second;
    std::vector<OnionPath*> suitable_paths;
    suitable_paths.reserve(candidate_paths.size());

    auto target_node = std::get_if<service_node>(&request.destination);

    // We want to allow explicit path selection for client-side automated tests so if a
    // `desired_path_index` has been specified then use it
    if (request.desired_path_index) {
        if (candidate_paths.size() < *request.desired_path_index)
            return nullptr;

        return &candidate_paths[*request.desired_path_index];
    }

    for (OnionPath& path : candidate_paths) {
        // Ignore failed paths (these should have been removed from the list but better to be safe)
        if (path.strike_count >= _config.path_strike_threshold)
            continue;

        // Filter by destination conflict
        if (target_node) {
            bool conflict = false;

            for (const auto& path_node : path.nodes) {
                if (path_node == *target_node) {
                    conflict = true;
                    break;
                }
            }

            if (conflict && _config.single_path_mode)
                log::warning(
                        cat,
                        "[Request {}]: Path destination conflicts with the only available path, "
                        "but single_path_mode is enabled, proceeding.",
                        request.request_id);
            else if (conflict)
                continue;
        }

        suitable_paths.push_back(&path);
    }

    if (suitable_paths.empty())
        return nullptr;

    // Sort by the number of active requests, ascending, randomise the order if equal (stable sort
    // will maintain the random order from the shuffle)
    std::shuffle(suitable_paths.begin(), suitable_paths.end(), csrng);
    std::stable_sort(
            suitable_paths.begin(),
            suitable_paths.end(),
            [](const OnionPath* a, const OnionPath* b) {
                return a->active_requests < b->active_requests;
            });

    OnionPath* best_path = suitable_paths.front();
    const auto min_paths_for_type = _config.min_path_counts[to_path_category(request.category)];

    // Return the path with the fewest active requests if we had one with no requests, or
    // already have the minimum number of paths for this type
    if (best_path->active_requests == 0 || candidate_paths.size() >= min_paths_for_type)
        return best_path;

    // Otherwise we want to build a new path (want to maintain the minimum path count)
    return nullptr;
}

void OnionRequestRouter::_send_on_path(
        OnionPath& path, Request request, network_response_callback_t callback) {
    log::trace(cat, "[Request {}]: Sending on path {}", request.request_id, path.id);

    std::vector<unsigned char> encrypted_blob;
    std::shared_ptr<session::onionreq::ResponseParser> parser;

    try {
        auto builder =
                session::onionreq::Builder(request.destination, request.endpoint, path.nodes);
        encrypted_blob = builder.generate_onion_blob(request.body);
        parser = std::make_shared<session::onionreq::ResponseParser>(builder);
    } catch (const std::exception& e) {
        log::warning(
                cat,
                "[Request {}]: Failed to prepare onion payload: {}",
                request.request_id,
                e.what());
        return callback(
                false,
                false,
                ERROR_FAILED_GENERATE_ONION_PAYLOAD,
                {content_type_plain_text},
                "Failed to construct onion request payload");
    }

    // Construct the actual request to send
    std::optional<std::chrono::milliseconds> remaining_overall_timeout =
            (request.overall_timeout.has_value() ? std::optional{request.time_remaining()}
                                                 : std::nullopt);
    Request onion_request{
            request.request_id,
            network_destination{path.nodes.front()},  // Send to edge node
            std::string{"onion_req"},                 // Send to onion request handling endpoint
            std::move(encrypted_blob),                // Encrypted payload
            request.category,
            request.time_remaining(),
            remaining_overall_timeout};

    // Increment the `active_requests` and actually send the `onion_request`
    path.active_requests++;

    auto transport = _transport.lock();
    if (!transport) {
        log::critical(cat, "Transport was destroyed, cannot send request.");
        return;
    }

    auto decryption_callback =
            [weak_self = weak_from_this(),
             this,
             parser = std::move(parser),
             path_id = path.id,
             original_request = std::move(request),
             cb = std::move(callback)](
                    bool success, bool timeout, int16_t status, auto headers, auto response) {
                auto self = weak_self.lock();
                if (!self)
                    return;

                try {
                    if (!success)
                        throw std::runtime_error{response.value_or("Unknown request failure")};
                    if (timeout)
                        throw std::runtime_error{response.value_or("Timed out")};
                    if (!response)
                        throw std::runtime_error{"Unexpected empty response"};

                    onionreq::DecryptedResponse decrypted = parser->decrypted_response(*response);
                    _handle_transport_response(
                            path_id,
                            std::move(original_request),
                            true,
                            false,
                            decrypted.status_code,
                            std::move(decrypted.headers),
                            std::move(decrypted.body),
                            std::move(cb));
                } catch (const std::exception& e) {
                    _handle_transport_response(
                            path_id,
                            std::move(original_request),
                            false,
                            timeout,
                            response::undecrypted_status(status),
                            std::move(headers),
                            "Failed to handle onion response (status {}) due to error: {}"_format(
                                    status, e.what()),
                            std::move(cb));
                }
            };

    transport->send_request(std::move(onion_request), std::move(decryption_callback));
}

void OnionRequestRouter::_handle_transport_response(
        std::string path_id,
        Request original_request,
        bool success,
        bool timeout,
        int16_t status_code,
        std::vector<std::pair<std::string, std::string>> headers,
        std::optional<std::string> decrypted_body,
        network_response_callback_t callback) {
    auto final_success = success;
    auto final_status_code = status_code;
    auto destination_snode = std::get_if<service_node>(&original_request.destination);
    std::unordered_set<ed25519_pubkey> penalized_nodes;

    if (decrypted_body)
        if (auto uniform_error = response::find_uniform_batch_error(*decrypted_body))
            final_status_code = *uniform_error;

    if (final_success)
        final_success = (final_status_code >= 200 && final_status_code <= 299);

    if (!final_success) {
        auto parsed_error = parse_error_response(
                final_status_code,
                decrypted_body,
                (destination_snode ? std::optional{destination_snode->view_remote_key()}
                                   : std::nullopt));

        if (parsed_error) {
            const auto& [pattern, extracted_pubkey] = *parsed_error;

            log::debug(
                    cat,
                    "[Request {}]: Mmatched error type {} on path {}.",
                    original_request.request_id,
                    static_cast<int>(pattern.error_type),
                    path_id);

            // Apply penalties based on the pattern
            auto snode_pool = _snode_pool.lock();

            if (pattern.penalize_extracted_node && extracted_pubkey && snode_pool) {
                try {
                    auto pubkey = ed25519_pubkey::from_hex(*extracted_pubkey);
                    snode_pool->record_node_failure(pubkey, pattern.force_remove_node);
                    penalized_nodes.insert(pubkey);
                    log::debug(
                            cat,
                            "[Request {}]: Penalized extracted node {} ({} strikes).",
                            original_request.request_id,
                            pubkey.hex(),
                            pattern.force_remove_node ? "permanent" : "1");
                } catch (...) {
                    log::warning(
                            cat,
                            "[Request {}]: Invalid extracted pubkey.",
                            original_request.request_id);
                }
            }

            if (pattern.penalize_destination && destination_snode && snode_pool) {
                auto dest_key = ed25519_pubkey::from_bytes(destination_snode->view_remote_key());
                snode_pool->record_node_failure(*destination_snode, pattern.force_remove_node);
                penalized_nodes.insert(dest_key);
                log::debug(
                        cat,
                        "[Request {}]: Penalized destination node ({} strikes).",
                        original_request.request_id,
                        pattern.force_remove_node ? "permanent" : "1");
            }

            // Generally this shouldn't happen (as we would have failed to establish a QUIC
            // connection), but may as well keep it just to be safe
            if (pattern.penalize_edge && snode_pool) {
                auto& active_paths = _paths[to_path_category(original_request.category)];
                auto path_it = std::find_if(
                        active_paths.begin(), active_paths.end(), [&path_id](const auto& p) {
                            return p.id == path_id;
                        });

                if (path_it != active_paths.end() && !path_it->nodes.empty()) {
                    const auto& edge_node = path_it->nodes.front();
                    auto edge_key = ed25519_pubkey::from_bytes(edge_node.view_remote_key());
                    snode_pool->record_node_failure(edge_node, pattern.force_remove_node);
                    penalized_nodes.insert(edge_key);
                    log::debug(
                            cat,
                            "[Request {}]: Penalized edge node ({} strikes).",
                            original_request.request_id,
                            pattern.force_remove_node ? "permanent" : "1");
                }
            }

            // Now that we have applied snode penalties, check if any node in any path has hit the
            // threshold and try to repair the path if needed (we need to check all paths because
            // it's possible the failed node was a "destination" node which just happens to be in
            // a different path from the one this request was sent along)
            if (snode_pool) {
                for (auto& [path_cat, paths] : _paths) {
                    for (auto& path : paths) {
                        std::vector<ed25519_pubkey> nodes_to_repair;

                        for (const auto& node : path.nodes) {
                            auto node_key = ed25519_pubkey::from_bytes(node.view_remote_key());

                            if (snode_pool->node_strike_count(node_key) >=
                                _config.node_strike_threshold)
                                nodes_to_repair.push_back(node_key);
                        }

                        // Repair any bad nodes in the path
                        if (!nodes_to_repair.empty()) {
                            if (nodes_to_repair.size() == 1) {
                                log::debug(
                                        cat,
                                        "[Request {} Path {}]: Node {} has hit the strike "
                                        "threshold, "
                                        "attempting repair.",
                                        original_request.request_id,
                                        path.id,
                                        nodes_to_repair[0].hex());
                            } else {
                                log::debug(
                                        cat,
                                        "[Request {} Path {}]: {} node(s) have hit the strike "
                                        "threshold, "
                                        "attempting repair.",
                                        original_request.request_id,
                                        path.id,
                                        nodes_to_repair.size());
                            }

                            for (const auto& node_key : nodes_to_repair)
                                _try_repair_path(path_id, path_cat, node_key);
                        }
                    }
                }
            }

            // It's possible for a path to have maxed out it's strikes if `_try_repair_path` was
            // called with the edge node, in that case we need to call `_handle_path_failure` to
            // drop the path
            struct PathToFail {
                PathCategory cat;
                std::string id;
            };
            std::vector<PathToFail> paths_to_retire;

            for (auto& [path_cat, paths] : _paths) {
                for (auto& path : paths) {
                    bool failed_locally =
                            (path_cat == to_path_category(original_request.category) &&
                             path.id == path_id && pattern.penalize_path);
                    bool failed_globally = (path.strike_count >= _config.path_strike_threshold);

                    if (failed_locally || failed_globally)
                        paths_to_retire.push_back({path_cat, path.id});
                }
            }

            for (const auto& path : paths_to_retire) {
                log::debug(
                        cat,
                        "[Request {}]: Received error {} resuling in path {} failure.",
                        original_request.request_id,
                        final_status_code,
                        path.id);
                _handle_path_failure(path.id, path.cat, penalized_nodes);
            }
        } else {
            log::warning(
                    cat,
                    "[Request {}]: Received unhandled error {} on path {}.",
                    original_request.request_id,
                    final_status_code,
                    path_id);
        }
    }

    // Clean up paths if needed
    _decrement_and_cleanup_path(path_id, to_path_category(original_request.category));

    // Now we can trigger the callback with the result
    return callback(
            final_success,
            timeout,
            final_status_code,
            std::move(headers),
            std::move(decrypted_body));
}

void OnionRequestRouter::_decrement_and_cleanup_path(
        const std::string& path_id, PathCategory category) {
    // Check active paths first
    auto& active_paths = _paths[category];

    if (auto it = std::find_if(
                active_paths.begin(),
                active_paths.end(),
                [&path_id](const auto& p) { return p.id == path_id; });
        it != active_paths.end()) {
        if (it->active_requests > 0)
            it->active_requests--;

        // The path is still active so we don't need to do anything else
        return;
    }

    // If we didn't find an active path then check paths pending drop
    auto& dying_paths = _paths_pending_drop[category];
    if (auto it = std::find_if(
                dying_paths.begin(),
                dying_paths.end(),
                [&path_id](const auto& p) { return p.id == path_id; });
        it != dying_paths.end()) {
        if (it->active_requests > 0)
            it->active_requests--;

        // If this was the last request, we can now safely delete the path
        if (it->active_requests == 0) {
            log::debug(cat, "Retiring path {} as it has no more active requests.", path_id);

            if (auto transport = _transport.lock())
                if (!it->nodes.empty())
                    transport->remove_failure_listeners(
                            ed25519_pubkey::from_bytes(it->nodes[0].view_remote_key()));

            dying_paths.erase(it);
        }

        return;
    }

    // This can happen if the path was already retired and removed, it's not an error
    log::trace(cat, "Request completed on path {}, which has already been removed.", path_id);
}

void OnionRequestRouter::_handle_path_failure(
        const std::string& path_id,
        const PathCategory& category,
        const std::unordered_set<ed25519_pubkey>& already_penalized_nodes) {
    auto& active_paths = _paths[category];
    auto path_it =
            std::find_if(active_paths.begin(), active_paths.end(), [&path_id](const auto& p) {
                return p.id == path_id;
            });

    // If the path is no longer in the active list then no need to do anything
    if (path_it == active_paths.end()) {
        log::trace(cat, "[Path {}]: Failure on path, but path is no longer active.", path_id);
        return;
    }

    // Increment the `strike_count` on the path
    OnionPath& path = *path_it;

    if (path.strike_count < _config.path_strike_threshold)
        path.strike_count++;

    log::debug(
            cat,
            "[Path {}]: Recorded failure, total failures: {}/{}",
            path.id,
            path.strike_count,
            _config.path_strike_threshold);

    // If the path has exceeded its strike threshold, retire it.
    if (path.strike_count >= _config.path_strike_threshold) {
        log::warning(cat, "[Path {}]: Path has exceeded its strike threshold.", path.id);

        // Tell the SnodePool that all nodes on this path are now suspect
        if (auto snode_pool = _snode_pool.lock())
            for (const auto& node : path.nodes) {
                auto node_key = ed25519_pubkey::from_bytes(node.view_remote_key());

                // Skip nodes we already penalized to avoid double-penalizing
                if (already_penalized_nodes.count(node_key)) {
                    log::trace(
                            cat,
                            "[Path {}]: Skipping penalty for node {} (already penalized).",
                            path.id,
                            node_key.hex());
                    continue;
                }

                snode_pool->record_node_failure(node);
                log::debug(
                        cat,
                        "[Path {}]: Penalized path node {} due to path failure.",
                        path.id,
                        node_key.hex());
            }

        // Remove failure listeners for the path
        if (auto transport = _transport.lock())
            if (!path.nodes.empty())
                transport->remove_failure_listeners(
                        ed25519_pubkey::from_bytes(path.nodes[0].view_remote_key()));

        // Store for subsequent path building
        const auto old_path_id = path.id;
        auto nodes_to_exclude = path.nodes;

        if (path.active_requests == 0) {
            log::debug(cat, "[Path {}]: Retiring idle path immediately.", old_path_id);
            active_paths.erase(path_it);
            _update_status();
        } else {
            log::debug(
                    cat,
                    "[Path {}]: Retiring active path ({} active requests), moving to pending drop.",
                    old_path_id,
                    path.active_requests);
            _paths_pending_drop[category].push_back(std::move(path));
            active_paths.erase(path_it);
            _update_status();
        }

        // Automatically rebuild if needed
        PathCategory category_to_rebuild =
                (_config.single_path_mode ? PathCategory::standard : category);
        const auto min_paths =
                (_config.single_path_mode ? 1 : _config.min_path_counts.at(category_to_rebuild));
        const auto current_active =
                (_paths.count(category_to_rebuild) ? _paths.at(category_to_rebuild).size() : 0);
        const auto in_progress = _in_progress_path_builds[category_to_rebuild];

        if (current_active + in_progress < min_paths) {
            log::info(
                    cat,
                    "Path count for {} is below the minimum {}, building replacement.",
                    to_string(category, _config.single_path_mode),
                    min_paths);
            _build_path(category, "failure-replacement-" + old_path_id, nodes_to_exclude);
        }
    }
}

void OnionRequestRouter::_try_repair_path(
        const std::string& path_id,
        const PathCategory& category,
        const ed25519_pubkey& bad_node_pubkey) {
    auto& active_paths = _paths[category];
    auto path_it =
            std::find_if(active_paths.begin(), active_paths.end(), [&path_id](const auto& p) {
                return p.id == path_id;
            });

    // If the path is no longer in the active list then no need to do anything
    if (path_it == active_paths.end())
        return;

    try {
        OnionPath& path = *path_it;
        auto bad_node_it = std::find_if(
                path.nodes.begin(), path.nodes.end(), [&bad_node_pubkey](const auto& node) {
                    return to_string_view(node.view_remote_key()) == bad_node_pubkey.view();
                });

        if (bad_node_it == path.nodes.end())
            return;

        if (bad_node_it == path.nodes.begin()) {
            log::warning(
                    cat,
                    "[Path {}]: Edge node {} failed, dropping path.",
                    path.id,
                    bad_node_pubkey.hex());
            path.strike_count = _config.path_strike_threshold;
            return;
        }

        log::debug(
                cat,
                "[Path {}]: Attempting to repair path by replacing node {}.",
                path.id,
                bad_node_pubkey.hex());

        auto snode_pool = _snode_pool.lock();
        if (!snode_pool) {
            log::critical(
                    cat,
                    "[Path {}]: Cannot repair path as SnodePool was destroyed, dropping instead.",
                    path.id);
            path.strike_count = _config.path_strike_threshold;
            return;
        }

        // The bad node should have already been penalised at this point
        auto used_nodes = extract_nodes(_paths, _pending_paths);
        auto replacements = snode_pool->get_unused_nodes(1, used_nodes);

        // If we found a replacement node then swap out the bad one if we have a replacement node,
        // if we don't then we need to drop the path (and rely on path rebuilding to give us a full
        // replacement path)
        if (!replacements.empty()) {
            log::info(
                    cat,
                    "[Path {}]: Repaired path by replacing node {} with {}.",
                    path.id,
                    bad_node_it->to_string(),
                    replacements[0].to_string());
            *bad_node_it = replacements[0];
        } else {
            log::warning(
                    cat,
                    "[Path {}]: Cannot repair path due to lack of replacement node, "
                    "dropping instead.",
                    path.id);
            path.strike_count = _config.path_strike_threshold;
        }
    } catch (...) {
    }
}

void OnionRequestRouter::_schedule_path_rotation(
        const std::string& path_id,
        PathCategory category,
        std::chrono::steady_clock::time_point rotate_at) {
    _path_rotation_schedule.emplace(rotate_at, std::make_pair(path_id, category));
    _update_rotation_timer();
}

void OnionRequestRouter::_check_path_rotations(
        std::optional<std::chrono::steady_clock::time_point> now) {
    if (!now)
        now = std::chrono::steady_clock::now();

    std::list<std::pair<std::string, PathCategory>> to_rotate;
    auto it = _path_rotation_schedule.begin();

    for (; it != _path_rotation_schedule.end() && it->first <= *now; ++it)
        to_rotate.push_back(it->second);

    _path_rotation_schedule.erase(_path_rotation_schedule.begin(), it);

    for (auto& [path_id, category] : to_rotate) {
        try {
            _rotate_path(path_id, category);
        } catch (const std::exception& e) {
            log::error(cat, "Uncaught exception from path rotation: {}", e.what());
        }
    }
}

void OnionRequestRouter::_update_rotation_timer() {
    if (_path_rotation_schedule.empty()) {
        if (_path_rotation_timer)
            event_del(_path_rotation_timer.get());
        return;
    }

    if (!_path_rotation_timer) {
        // If this is the first request timeout then set up the timeout event timer:
        _path_rotation_timer.reset(event_new(
                _loop->get_event_base(),
                -1,          // Not attached to an actual socket
                EV_TIMEOUT,  // Stays active (i.e. repeats) once fired
                [](evutil_socket_t, short, void* self) {
                    auto* me = static_cast<OnionRequestRouter*>(self);
                    me->_check_path_rotations(std::chrono::steady_clock::now());
                    me->_update_rotation_timer();
                },
                this));
    }

    auto rotates_in = std::chrono::ceil<std::chrono::microseconds>(
            _path_rotation_schedule.begin()->first - std::chrono::steady_clock::now());
    if (rotates_in < 0us)
        rotates_in = 0us;
#ifdef _WIN32
    using suseconds_t = long;
#endif
    timeval rotate_interval{
            .tv_sec = static_cast<time_t>(rotates_in / 1s),
            .tv_usec = static_cast<suseconds_t>((rotates_in % 1s).count())};

    event_add(_path_rotation_timer.get(), &rotate_interval);
}

void OnionRequestRouter::_rotate_path(const std::string& path_id, PathCategory category) {
    auto& active_paths = _paths[category];
    auto path_it =
            std::find_if(active_paths.begin(), active_paths.end(), [&path_id](const auto& p) {
                return p.id == path_id;
            });

    if (path_it == active_paths.end()) {
        log::debug(cat, "[Path {}]: Path no longer exists, skipping rotation.", path_id);
        return;
    }

    OnionPath& path = *path_it;

    if (path.rotation_in_progress) {
        log::debug(cat, "[Path {}]: Rotation already in progress, skipping.", path_id);
        return;
    }

    log::info(cat, "[Path {}]: Starting path rotation.", path_id);
    path.rotation_in_progress = true;

    const std::string new_path_id = random::unique_id("RP");
    service_node edge_node = path.nodes.front();
    auto nodes_to_exclude = extract_nodes(_paths, _pending_paths);

    auto snode_pool = _snode_pool.lock();
    if (!snode_pool) {
        log::critical(cat, "SnodePool was destroyed, cannot rotate path.");
        return;
    }

    // Get enough nodes for the path (if the edge node has been used for longer than the cache
    // duration, or has been struck out since we connected to it, then we should create an entirely
    // new path, otherwise we should try to reuse the edge node)
    auto now = std::chrono::system_clock::now();
    auto rotate_at = (std::chrono::steady_clock::now() + _config.path_rotation_frequency);
    std::vector<service_node> rotated_path_nodes;

    if (now > path.edge_first_connected_at + _config.edge_node_cache_duration ||
        snode_pool->node_struck_out(edge_node))
        rotated_path_nodes = snode_pool->get_unused_nodes(_config.path_length, nodes_to_exclude);
    else {
        rotated_path_nodes =
                snode_pool->get_unused_nodes(_config.path_length - 1, nodes_to_exclude);
        rotated_path_nodes.insert(rotated_path_nodes.begin(), edge_node);
    }

    // Also need a 'destination' to varify path reachability
    nodes_to_exclude.insert(
            nodes_to_exclude.end(), rotated_path_nodes.begin(), rotated_path_nodes.end());
    auto target_node = snode_pool->get_unused_nodes(1, nodes_to_exclude);

    if (rotated_path_nodes.size() < _config.path_length || target_node.empty()) {
        log::warning(
                cat,
                "[Path {}]: Failed to get enough nodes for rotation, retrying later.",
                path_id);
        path.rotation_in_progress = false;
        _schedule_path_rotation(path_id, category, std::chrono::steady_clock::now() + 1min);
        return;
    }

    OnionPath new_path{
            new_path_id, std::move(rotated_path_nodes), now, path.edge_first_connected_at};

    // Send /info request to verify path before rotating
    Request info_request{
            "path-rotation-verify-" + new_path_id,
            network_destination{target_node.front()},
            std::string{"info"},
            std::nullopt,
            to_small_request_category(category),
            10s,
            std::nullopt};

    _pending_rotation_paths[new_path_id] = {path_id, category, std::move(new_path)};
    auto& pending_rotation = _pending_rotation_paths[new_path_id];

    _send_on_path(
            pending_rotation.new_path,
            std::move(info_request),
            [weak_self = weak_from_this(), this, new_path_id, rotate_at = std::move(rotate_at)](
                    bool success,
                    bool timeout,
                    int16_t status,
                    auto /*headers*/,
                    auto /*response*/) {
                auto self = weak_self.lock();
                if (!self)
                    return;

                _on_rotation_verification_response(
                        new_path_id, success, timeout, status, rotate_at);
            });
}

void OnionRequestRouter::_on_rotation_verification_response(
        const std::string& new_path_id,
        bool success,
        bool timeout,
        int16_t status_code,
        std::chrono::steady_clock::time_point rotate_at) {
    auto pending_it = _pending_rotation_paths.find(new_path_id);
    if (pending_it == _pending_rotation_paths.end()) {
        log::warning(
                cat, "[Path {}]: Rotation verification response for unknown path.", new_path_id);
        return;
    }

    auto [old_path_id, category, new_path] = std::move(pending_it->second);
    _pending_rotation_paths.erase(pending_it);

    auto& active_paths = _paths[category];
    auto old_path_it =
            std::find_if(active_paths.begin(), active_paths.end(), [&old_path_id](const auto& p) {
                return p.id == old_path_id;
            });

    if (old_path_it == active_paths.end()) {
        log::warning(cat, "[Path {}]: Old path disappeared during rotation.", old_path_id);
        return;
    }

    if (!success || timeout) {
        log::warning(
                cat,
                "[Path {}]: Verification /info request failed (status: {}, timeout: {}), "
                "discarding rotation path {}.",
                old_path_id,
                status_code,
                timeout,
                new_path_id);

        // Clear rotation_in_progress and retry later
        old_path_it->rotation_in_progress = false;
        _schedule_path_rotation(old_path_id, category, std::chrono::steady_clock::now() + 1min);
        return;
    }

    log::info(
            cat,
            "[Path {}]: Verification successful, completing rotation to path {} with nodes: [{}].",
            old_path_id,
            new_path_id,
            new_path.to_string());

    _schedule_path_rotation(new_path_id, category, rotate_at);
    _paths[category].push_back(std::move(new_path));

    // Re-find old_path_it (push_back may have reallocated the vector, invalidating all iterators)
    old_path_it =
            std::find_if(active_paths.begin(), active_paths.end(), [&old_path_id](const auto& p) {
                return p.id == old_path_id;
            });

    // Just in case
    if (old_path_it == active_paths.end()) {
        log::warning(
                cat,
                "[Path {}]: Old path disappeared after push_back during rotation.",
                old_path_id);
        _update_status();
        return;
    }

    // Retire the old path
    if (old_path_it->active_requests == 0) {
        log::info(
                cat, "[Path {}]: Retiring old path immediately (no active requests).", old_path_id);
        active_paths.erase(old_path_it);
    } else {
        log::info(
                cat,
                "[Path {}]: Moving old path to pending drop ({} active requests).",
                old_path_id,
                old_path_it->active_requests);
        _paths_pending_drop[category].push_back(std::move(*old_path_it));
        active_paths.erase(old_path_it);
    }

    log::info(
            cat,
            "[Path {}]: Rotation complete, new path {} is now active.",
            old_path_id,
            new_path_id);
    _update_status();
}

}  // namespace session::network
