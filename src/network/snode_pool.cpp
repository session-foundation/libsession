#include "session/network/snode_pool.hpp"

#include <fmt/ranges.h>
#include <oxenc/base64.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <concepts>
#include <exception>
#include <fstream>
#include <limits>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/utils.hpp>
#include <type_traits>

#include "session/clock.hpp"
#include "session/file.hpp"
#include "session/hash.hpp"
#include "session/random.hpp"

using namespace oxen;
using namespace std::literals;
using namespace oxen::log::literals;

namespace std {

template <>
struct hash<oxen::quic::ipv4> {
    size_t operator()(const oxen::quic::ipv4& ip) const noexcept {
        return std::hash<uint32_t>{}(ip.addr);
    }
};

}  // namespace std

namespace session::network {

namespace fs = std::filesystem;

namespace {
    inline auto cat = log::Cat("snode_pool");

    const std::chrono::seconds STRIKE_EXPIRY = 48h;
    const std::chrono::seconds SAVE_THROTTLE = 5min;

    // A swarm rejection is evidence against the pool snapshot the swarm was derived from, so it is
    // only worth acting on once that snapshot is old enough for a refresh to plausibly return
    // something different.
    const std::chrono::seconds EVIDENCE_REFRESH_MIN_POOL_AGE = 1min;

    // A rejection arriving *after* we already refreshed on one is the refresh telling us it didn't
    // help - the network hasn't settled, or the node is lying - so each successive one waits twice
    // as long, up to `cache_expiration`.  A single 3-node refresh per minute sustained indefinitely
    // is not an acceptable resting state for a client on a bad connection, and without this it is
    // exactly what a persistent rejection source would produce.
    const std::chrono::seconds EVIDENCE_REFRESH_BASE_BACKOFF = 1min;

    // An account redirected more than this many times within one pool generation is being bounced
    // between nodes that disagree, or its swarm has moved on too far for our pool to keep up.  A
    // redirect is still the best information we have, so past it each one is still followed, and
    // also asks for the refresh that can settle it.  Legitimate rearrangements count too (nothing
    // resets this short of a refresh), hence the headroom.
    constexpr uint8_t SWARM_REDIRECTS_BEFORE_REFRESH = 8;
}  // namespace

SnodePool::SnodePool(
        config::SnodePool config,
        oxen::quic::Loop& loop,
        oxen::quic::Loop& disk_loop,
        network_fetcher_t direct_fetcher) :
        _config{std::move(config)},
        _loop{loop},
        _disk_loop{disk_loop},
        _direct_fetcher{std::move(direct_fetcher)} {

    if (_config.cache_directory) {
        std::string cache_file_name;

        switch (_config.netid) {
            case opt::netid::Target::mainnet: cache_file_name = "snode_pool"; break;
            case opt::netid::Target::testnet: cache_file_name = "snode_pool_testnet"; break;
            case opt::netid::Target::devnet:
                std::string seed_node_data;

                for (const auto& node : _config.seed_nodes)
                    node.to_disk(std::back_inserter(seed_node_data));

                cache_file_name =
                        "snode_pool_devnet_" +
                        oxenc::to_hex(session::hash::blake2b<32>(session::to_span(seed_node_data)));
                break;
        }

        _snode_cache_file_path = *_config.cache_directory / cache_file_name;
        _strikes_file_path = *_config.cache_directory / (cache_file_name + "_strikes");
        _load_from_disk();
    }
}

SnodePool::~SnodePool() {
    // Cancels the queue's jobs -- including the delayed refresh and strike-flush ones -- and waits
    // out whatever is running, so that nothing is part-way through us when the members below go.
    _jq.stop();
}

// MARK: Disk I/O Functions

// Consume a raw integer (in little-endian format) from the beginning of `b`, throwing if
// `b` is too short, and dropping the read bytes from it.
template <typename T>
static T consume(std::string_view& b) {
    static_assert(std::is_trivially_copyable_v<T> && std::is_default_constructible_v<T>);
    if (b.size() < sizeof(T))
        throw std::out_of_range{
                "Unable to consume data: reached end of data before parsing finished"};
    T val;
    std::memcpy(&val, b.data(), sizeof(T));
    if constexpr (std::integral<T>)
        oxenc::little_to_host_inplace(val);
    b.remove_prefix(sizeof(T));
    return val;
}

void SnodePool::_load_from_disk() {
    if (_snode_cache_file_path.empty()) {
        log::error(cat, "Tried to load cache from disk without a cache file path.");
        return;
    }

    // Load the cache if present
    try {
        if (!fs::exists(_snode_cache_file_path))
            throw empty_file_exception{};

        auto ftime = fs::last_write_time(_snode_cache_file_path);
        _last_snode_cache_update =
                std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                        ftime - fs::file_time_type::clock::now() +
                        std::chrono::system_clock::now());

        std::vector<std::byte> loaded_cache_data = read_whole_file(_snode_cache_file_path);
        std::vector<service_node> loaded_cache;
        auto invalid_entries = 0;

        std::string_view data_view(
                reinterpret_cast<const char*>(loaded_cache_data.data()), loaded_cache_data.size());
        loaded_cache.reserve((data_view.size() / service_node_disk_format::MAX_LINE_SIZE));

        while (!data_view.empty()) {
            // Find entry deliminted by either \n or \r
            auto end = data_view.find_first_of("\n\r");
            if (end == 0) {
                // Skip empty lines
                data_view.remove_prefix(1);
                continue;
            }
            auto line = data_view.substr(0, end);
            data_view.remove_prefix(line.size());
            try {
                loaded_cache.push_back(service_node::from_disk(line));
            } catch (...) {
                ++invalid_entries;
            }
        }

        if (loaded_cache_data.size() > 0 && loaded_cache.size() == 0)
            throw std::runtime_error{"Snode cache has invalid format"};

        if (invalid_entries > 0)
            log::warning(cat, "Skipped {} invalid entries in snode cache.", invalid_entries);

        std::ranges::shuffle(loaded_cache, csrng);
        _snode_cache = std::move(loaded_cache);
        _all_swarms = swarm::generate_swarms(_snode_cache);

        log::info(
                cat,
                "Loaded cache of {} snodes, {} swarms.",
                _snode_cache.size(),
                _all_swarms.size());
    } catch (const empty_file_exception) {
        log::info(cat, "No existing snode cache, will rebuild.");
    } catch (const std::exception& e) {
        log::error(cat, "Failed to load snode cache, will rebuild ({}).", e.what());

        if (fs::exists(_snode_cache_file_path))
            fs::remove_all(_snode_cache_file_path);
    }

    // Load the strikes if present
    try {
        if (!fs::exists(_strikes_file_path))
            throw empty_file_exception{};

        std::vector<std::byte> loaded_strikes_data = read_whole_file(_strikes_file_path);

        if (loaded_strikes_data.empty())
            throw empty_file_exception{};

        // We want to filter on load so we don't start the app with expired strikes
        auto threshold = clock_now_s() - STRIKE_EXPIRY;

        std::string_view buf{
                reinterpret_cast<const char*>(loaded_strikes_data.data()),
                loaded_strikes_data.size()};

        decltype(_snode_strikes) loaded_strikes;
        bool invalid_entries = false;
        auto entry_count = consume<uint32_t>(buf);
        try {
            for (uint32_t i = 0; i < entry_count; ++i) {
                auto key = consume<ed25519_pubkey>(buf);
                auto num_stamps = consume<uint16_t>(buf);

                // Read timestamps, skipping any stale ones
                std::vector<std::chrono::sys_seconds> valid_stamps;
                for (int j = 0; j < num_stamps; ++j) {
                    std::chrono::sys_seconds ts{
                            std::chrono::seconds{static_cast<int64_t>(consume<uint64_t>(buf))}};
                    if (ts > threshold)
                        valid_stamps.push_back(ts);
                }

                // Only add node if it still has active strikes
                if (!valid_stamps.empty())
                    loaded_strikes[key] = std::move(valid_stamps);
            }
        } catch (...) {
            invalid_entries = true;
        }

        if (invalid_entries)
            log::warning(
                    cat, "Skipped {} truncated/invalid entries in strikes file.", invalid_entries);

        _snode_strikes = std::move(loaded_strikes);
        log::info(cat, "Loaded {} active strike entries from disk.", _snode_strikes.size());
    } catch (const empty_file_exception) {
    } catch (const std::exception& e) {
        log::error(cat, "Failed to load snode cache, will rebuild ({}).", e.what());

        if (fs::exists(_strikes_file_path))
            fs::remove_all(_strikes_file_path);
    }
}

void SnodePool::_clear_disk_cache(const std::filesystem::path& path) {
    try {
        if (!path.empty() && fs::exists(path))
            fs::remove_all(path);
        log::info(cat, "Cleared snode cache from disk.");
    } catch (const std::exception& e) {
        log::error(cat, "Failed to clear snode cache file: {}", e.what());
    }
}

void SnodePool::_perform_cache_write(
        const std::filesystem::path& path, const std::vector<service_node>& cache) {
    if (path.empty())
        return;

    try {
        if (cache.empty())
            throw std::runtime_error{"cache was empty."};

        // Create the cache directories if needed
        fs::create_directories(path.parent_path());

        // Save the snode pool to disk
        auto tmp_path = path;
        tmp_path += u8"_new";

        {
            std::string output_buffer;
            output_buffer.reserve(cache.size() * service_node_disk_format::MAX_LINE_SIZE);

            for (const auto& snode : cache)
                snode.to_disk(std::back_inserter(output_buffer));

            std::ofstream file(tmp_path, std::ios::binary);
            file.write(output_buffer.data(), output_buffer.size());
            file.close();
        }

        fs::rename(tmp_path, path);
        log::debug(cat, "Finished writing snode cache to disk.");
    } catch (const std::exception& e) {
        log::error(cat, "Failed to write snode cache: {}", e.what());
    }
}

void SnodePool::_perform_strikes_write(
        const std::filesystem::path& path,
        const std::map<ed25519_pubkey, std::vector<std::chrono::sys_seconds>>& strikes) {
    if (path.empty())
        return;

    try {
        auto expiry_threshold = std::chrono::system_clock::now() - STRIKE_EXPIRY;
        std::vector<char> buffer;

        auto buf_add = [&buffer]<typename T>(const T& val) {
            static_assert(std::is_trivially_copyable_v<T>);
            buffer.resize(buffer.size() + sizeof(T));
            auto* write = buffer.data() + buffer.size() - sizeof(T);
            if constexpr (std::integral<T>)
                oxenc::write_host_as_little(val, write);
            else
                std::memcpy(write, &val, sizeof(T));
        };

        // Simple binary format: [Count(4)][Key(32)][NumStamps(2)][Stamp(8)]...
        uint32_t entry_count = 0;
        buf_add(entry_count);

        for (const auto& [key, timestamps] : strikes) {
            uint16_t t_count = 0;
            for (const auto& t : timestamps)
                if (t > expiry_threshold)
                    t_count++;

            // Drop node if no active strikes
            if (t_count == 0)
                continue;

            entry_count++;

            buf_add(key);      // Write Key (32 bytes)
            buf_add(t_count);  // Write Timestamp Count (2 bytes)
            // Write Timestamps (8 bytes each):
            for (const auto& t : timestamps)
                if (t > expiry_threshold)
                    buf_add(static_cast<uint64_t>(epoch_seconds(t)));
        }

        // Patch total count at the beginning
        oxenc::write_host_as_little(entry_count, buffer.data());

        // Create the cache directories if needed
        fs::create_directories(path.parent_path());

        // Save the strikes to disk
        auto tmp_path = path;
        tmp_path += u8"_new";

        {
            std::ofstream file(tmp_path, std::ios::binary);
            file.write(buffer.data(), buffer.size());
        }

        fs::rename(tmp_path, path);
        log::debug(cat, "Finished writing {} strike entries to disk.", entry_count);

    } catch (const std::exception& e) {
        log::error(cat, "Failed to write strikes: {}", e.what());
    }
}

// MARK: Refresh Functions

void SnodePool::_refresh_snode_cache(std::optional<std::string> request_id_opt) {
    _jq.call([this, request_id_opt] {
        if (_suspended) {
            log::info(cat, "Ignoring refresh as pool is suspended.");

            // Anything queued against a refresh we are declining to start has nothing left to wait
            // for: suspending abandons any refresh in progress, so none can answer it later
            _run_pending_refresh_callbacks(false);
            return;
        }

        const auto request_id = request_id_opt.value_or(random::unique_id("RSC"));
        bool use_routed_fetcher = true;
        uint8_t num_nodes_for_refresh = 0;

        // Only allow a single cache refresh at a time
        if (_current_snode_cache_refresh_id) {
            log::debug(
                    cat,
                    "[Request {}] Ignoring refresh snode cache attempt; a refresh is already in "
                    "progress ({}).",
                    request_id,
                    *_current_snode_cache_refresh_id);
            return;
        }

        log::info(cat, "[Request {}] Starting cache refresh.", request_id);
        _current_snode_cache_refresh_id = request_id;
        _snode_refresh_results.clear();
        _refresh_candidate_nodes.clear();

        // We should only use the routed_fetcher if it exists, passes a connectivity check, and
        // there are enough cached nodes
        const auto cache_insufficient =
                (_config.cache_num_nodes_to_use_for_refresh > 0 &&
                 _snode_cache.size() < _config.cache_num_nodes_to_use_for_refresh);
        use_routed_fetcher =
                (cache_insufficient && _routed_fetcher && _routed_fetcher_connectivity_check &&
                 (*_routed_fetcher_connectivity_check)());

        // We should only refresh using seed nodes if using cached nodes is disabled, or there
        // aren't enough cached nodes to refresh from
        const auto use_seed_nodes =
                (_config.cache_num_nodes_to_use_for_refresh == 0 || cache_insufficient);

        // Seed nodes are trusted so we only need to use a single node when refreshing from them
        num_nodes_for_refresh = (use_seed_nodes ? 1 : _config.cache_num_nodes_to_use_for_refresh);
        _refresh_candidate_nodes = (use_seed_nodes ? _config.seed_nodes : _snode_cache);
        std::ranges::shuffle(_refresh_candidate_nodes, csrng);

        if (!use_routed_fetcher && use_seed_nodes)
            log::debug(
                    cat,
                    "[Request {}] Refreshing using seed nodes{}.",
                    request_id,
                    (cache_insufficient ? " (cache is insufficient)" : ""));
        else if (!use_routed_fetcher && !use_seed_nodes)
            log::warning(
                    cat,
                    "[Request {}] {}, using direct fetcher to fetch from {} nodes for cache "
                    "refresh.",
                    request_id,
                    (!_routed_fetcher ? "No routed fetcher set" : "Routed fetcher not ready"),
                    num_nodes_for_refresh);
        else if (use_routed_fetcher && use_seed_nodes)
            log::debug(
                    cat,
                    "[Request {}] Refreshing using seed nodes (cache is insufficient).",
                    request_id);
        else
            log::debug(
                    cat,
                    "[Request {}] Refrshing via routed fetcher using {} nodes.",
                    request_id,
                    num_nodes_for_refresh);

        // If we (somehow) have no candidate nodes then error and reset the state so we can try
        // again later
        if (_refresh_candidate_nodes.empty()) {
            log::critical(
                    cat,
                    "Cannot refresh cache: {}",
                    (use_seed_nodes ? "No seed nodes are configured!"
                                    : "Found no nodes and decided not to use seed nodes!"));
            _current_snode_cache_refresh_id.reset();
            _run_pending_refresh_callbacks(false);
            return;
        }

        // Kick off the concurrent requests (if there are any)
        for (uint8_t i = 0; i < num_nodes_for_refresh; ++i)
            _launch_next_refresh_request(
                    request_id, i, use_seed_nodes, !use_routed_fetcher, num_nodes_for_refresh);
    });
}

void SnodePool::_launch_next_refresh_request(
        const std::string& request_id,
        const uint8_t index,
        const bool refreshing_from_seed_nodes,
        const bool use_direct_fetcher,
        const uint8_t total_requests) {
    _jq.call([this,
              request_id,
              index,
              refreshing_from_seed_nodes,
              use_direct_fetcher,
              total_requests] {
        // A retry scheduled for a refresh that has since been abandoned or replaced mustn't touch
        // the one in its place - its candidates in particular
        if (_current_snode_cache_refresh_id != request_id)
            return;

        const auto target_request_id = "{}-{}"_format(request_id, index);

        if (_refresh_candidate_nodes.empty()) {
            // If we run out of candidate nodes then we should fail this refresh request and kick
            // off a new one with a new id (the `_refresh_snode_cache` will decide which nodes and
            // fetcher should be used)
            //
            // If this was a bootstrap request then we've failed to refresh from all seed nodes so
            // we should try to use the `fallback_snode_pool_path` if it exists, otherwise just
            // retry indefinitely (not much else we can do)
            if (refreshing_from_seed_nodes && _config.fallback_snode_pool_path &&
                !_config.fallback_snode_pool_path->empty() &&
                fs::exists(*_config.fallback_snode_pool_path)) {
                log::warning(
                        cat,
                        "[Request {}] Ran out of seed nodes for refresh, using fallback cache.",
                        request_id);

                try {
                    std::vector<std::byte> loaded_fallback_data =
                            read_whole_file(*_config.fallback_snode_pool_path);
                    auto json = nlohmann::json::parse(
                            reinterpret_cast<const char*>(loaded_fallback_data.data()),
                            reinterpret_cast<const char*>(
                                    loaded_fallback_data.data() + loaded_fallback_data.size()));
                    auto nodes = json.at("service_node_states").get<nlohmann::json::array_t>();
                    auto height = json.at("height").get<int>();
                    auto file_time = fs::last_write_time(*_config.fallback_snode_pool_path);
                    auto file_time_sys =
                            std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                                    file_time - fs::file_time_type::clock::now() +
                                    std::chrono::system_clock::now());
                    auto file_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                file_time_sys.time_since_epoch())
                                                .count();
                    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                          std::chrono::system_clock::now().time_since_epoch())
                                          .count();
                    auto seconds_since_build = (now_ms - file_time_ms) / 1000;
                    auto expected_height_diff = seconds_since_build / 120;
                    auto expected_current_height = height + expected_height_diff;

                    std::vector<service_node> parsed_nodes;
                    parsed_nodes.reserve(nodes.size());
                    auto invalid_count = 0;
                    auto unlocked_count = 0;

                    for (auto& json_node : nodes)
                        try {
                            auto snode = service_node::from_json(json_node);

                            // If a node has an unlock height and it is in the past then it's
                            // possible that the node is offline so don't both including it in the
                            // initial cache (if we get a successful connection and refresh the
                            // cache then it would be added back at that point)
                            if (snode.requested_unlock_height > 0 &&
                                snode.requested_unlock_height <= expected_current_height) {
                                unlocked_count++;
                                continue;
                            }

                            parsed_nodes.emplace_back(std::move(snode));
                        } catch (...) {
                            invalid_count++;
                        }

                    if (parsed_nodes.size() < _config.cache_min_size)
                        throw std::runtime_error{
                                "Failed to parse enough fallback nodes to meet the min cache size"};

                    if (invalid_count > 0)
                        log::warning(
                                cat,
                                "[Request {}] Failed to parse {} fallback nodes.",
                                request_id,
                                invalid_count);

                    if (unlocked_count > 0)
                        log::warning(
                                cat,
                                "[Request {}] {} fallback nodes might be unlocked.",
                                request_id,
                                unlocked_count);

                    _update_cache(request_id, std::move(parsed_nodes));
                    return;
                } catch (const std::exception& e) {
                    log::error(
                            cat,
                            "[Request {}] Failed to process fallback cache, will just retry seed "
                            "nodes.",
                            target_request_id);
                }
            }

            _snode_cache_refresh_failure_count++;
            auto delay = _config.retry_delay.exponential(_snode_cache_refresh_failure_count);
            log::warning(
                    cat,
                    "[Request {}] Ran out of nodes for refresh, discarding partial results and "
                    "trying again in {}ms.",
                    target_request_id,
                    delay.count());
            _jq.call_later(delay, [this, request_id] {
                // We need to wait until after the `call_later` to reset the `refresh_id` (and clear
                // previous results) as if we don't then additional refreshes could be triggered
                // during the delay

                // Abandoned (by a suspend) or replaced during the delay: resetting the id would
                // wipe out whichever refresh has it now, and there is nothing of ours to restart
                if (_current_snode_cache_refresh_id != request_id)
                    return;

                _current_snode_cache_refresh_id.reset();
                _snode_refresh_results.clear();
                _refresh_snode_cache();
            });
            return;
        }

        auto target_node = _refresh_candidate_nodes.back();
        _refresh_candidate_nodes.pop_back();
        auto fetcher_to_use = (use_direct_fetcher ? _direct_fetcher : *_routed_fetcher);

        // If we somehow got into '_launch_next_refresh_request' for a routed request then we need
        // to make sure '_routed_fetcher' was set before we try to use it
        if (!fetcher_to_use) {
            log::critical(
                    cat, "[Request {}] No fetcher available, aborting refresh.", target_request_id);
            _current_snode_cache_refresh_id.reset();
            _refresh_candidate_nodes.clear();
            _run_pending_refresh_callbacks(false);
            return;
        }

        log::debug(
                cat,
                "[Request {}] Launching {} refresh request to {}",
                target_request_id,
                (use_direct_fetcher ? "direct" : "routed"),
                target_node.to_string());
        const auto request =
                Request{target_request_id,
                        network_destination{target_node},
                        std::string{"active_nodes_bin"},
                        std::nullopt,
                        RequestCategory::standard,
                        10s,
                        std::nullopt,       // overall_timeout
                        std::nullopt,       // desired_path_index
                        std::monostate{}};  // details

        fetcher_to_use(
                request,
                // The fetcher hands this to the transport, which outlives us, so unlike our own
                // jobs this one cannot rely on the queue being stopped and keeps a weak guard.
                [weak_self = weak_from_this(),
                 this,
                 request_id,
                 index,
                 target_request_id,
                 refreshing_from_seed_nodes,
                 use_direct_fetcher,
                 total_requests](
                        bool success,
                        bool timeout,
                        int16_t status_code,
                        std::vector<std::pair<std::string, std::string>> /*headers*/,
                        std::optional<std::string> response) {
                    auto self = weak_self.lock();
                    if (!self)
                        return;

                    // If the refresh was cancelled or completed while we were in-flight, do nothing
                    if (!_current_snode_cache_refresh_id ||
                        *_current_snode_cache_refresh_id != request_id) {
                        log::debug(
                                cat,
                                "[Request {}] Ignoring stale refresh response.",
                                target_request_id);
                        return;
                    }

                    std::vector<std::byte> result;

                    try {
                        if (!success || timeout || !response)
                            throw std::runtime_error{response.value_or("Unknown error.")};

                        if (status_code < 200 || status_code > 299)
                            throw status_code_exception{
                                    status_code,
                                    {content_type_plain_text},
                                    "Request failed with status code: {}, error: {}"_format(
                                            status_code, response.value_or("Unknown error."))};

                        result.assign(
                                reinterpret_cast<const std::byte*>(response->data()),
                                reinterpret_cast<const std::byte*>(
                                        response->data() + response->length()));
                    } catch (const std::exception& e) {
                        _snode_cache_refresh_failure_count++;
                        auto delay =
                                _config.retry_delay.exponential(_snode_cache_refresh_failure_count);

                        log::warning(
                                cat,
                                "Failed to refresh cache from one node: {}. Trying another in "
                                "{}ms.",
                                e.what(),
                                delay.count());
                        _jq.call_later(
                                delay,
                                [this,
                                 request_id,
                                 index,
                                 refreshing_from_seed_nodes,
                                 use_direct_fetcher,
                                 total_requests] {
                                    _retry_refresh_request(
                                            request_id,
                                            index,
                                            refreshing_from_seed_nodes,
                                            use_direct_fetcher,
                                            total_requests);
                                });
                        return;
                    }

                    _snode_refresh_results.push_back(std::move(result));
                    log::info(
                            cat,
                            "[Request {}] Received refresh response {}/{}.",
                            target_request_id,
                            _snode_refresh_results.size(),
                            total_requests);

                    // If we've received all the results then we need to process them and complete
                    // the refresh
                    if (_snode_refresh_results.size() >= total_requests) {
                        auto final_results = std::move(_snode_refresh_results);
                        auto refresh_id = *_current_snode_cache_refresh_id;
                        _on_refresh_complete(
                                refresh_id,
                                final_results,
                                refreshing_from_seed_nodes,
                                use_direct_fetcher,
                                total_requests);
                    }
                });
    });
}

void SnodePool::_retry_refresh_request(
        const std::string& request_id,
        const uint8_t index,
        const bool refreshing_from_seed_nodes,
        const bool use_direct_fetcher,
        const uint8_t total_requests) {
    _launch_next_refresh_request(
            request_id, index, refreshing_from_seed_nodes, use_direct_fetcher, total_requests);
}

void SnodePool::_on_refresh_complete(
        std::string refresh_id,
        std::vector<std::vector<std::byte>> raw_results,
        const bool refreshing_from_seed_nodes,
        const bool use_direct_fetcher,
        const uint8_t total_requests) {
    log::info(
            cat,
            "[Request {}] Have {} responses, processing and finalizing cache refresh.",
            refresh_id,
            raw_results.size());

    _jq.call([this,
              refresh_id,
              raw_results,
              refreshing_from_seed_nodes,
              use_direct_fetcher,
              total_requests] {
        // Throw away everything we received and start the requests again after a backoff
        auto discard_and_retry = [this,
                                  refresh_id,
                                  refreshing_from_seed_nodes,
                                  use_direct_fetcher,
                                  total_requests](std::string_view reason) {
            _snode_refresh_results.clear();
            _snode_cache_refresh_failure_count++;
            auto delay = _config.retry_delay.exponential(_snode_cache_refresh_failure_count);

            log::error(
                    cat,
                    "[Request {}] Discarding responses and retrying after {}ms due to {}.",
                    refresh_id,
                    delay.count(),
                    reason);
            _jq.call_later(
                    delay,
                    [this,
                     refresh_id,
                     refreshing_from_seed_nodes,
                     use_direct_fetcher,
                     total_requests] {
                        for (uint8_t i = 0; i < total_requests; ++i)
                            _launch_next_refresh_request(
                                    refresh_id,
                                    i,
                                    refreshing_from_seed_nodes,
                                    use_direct_fetcher,
                                    total_requests);
                    });
        };

        // Sort the vectors (so make it easier to find the intersection)
        std::vector<std::vector<service_node>> processed_nodes;
        processed_nodes.reserve(raw_results.size());
        for (size_t i = 0; i < raw_results.size(); ++i) {
            try {
                auto& nodes_bin = raw_results[i];
                std::pair<std::vector<service_node>, int> result;
                auto& [nodes, invalid_count] = result;

                // Due to how onion requests work they need to return JSON data which means the data
                // could be base64-encoded, so handle that case if needed
                if (!use_direct_fetcher && oxenc::is_base64(nodes_bin)) {
                    std::vector<std::byte> converted_nodes;
                    oxenc::from_base64(
                            nodes_bin.begin(),
                            nodes_bin.end(),
                            std::back_inserter(converted_nodes));
                    result = service_node::process_snode_cache_bin(converted_nodes);
                } else
                    result = service_node::process_snode_cache_bin(nodes_bin);

                log::info(
                        cat,
                        "[Request {}] Refresh response #{} included {} nodes, {} invalid.",
                        refresh_id,
                        (i + 1),
                        nodes.size(),
                        invalid_count);
                std::ranges::stable_sort(nodes);
                processed_nodes.emplace_back(std::move(nodes));
            } catch (const std::exception& e) {
                discard_and_retry("invalid response #{}: {}"_format((i + 1), e.what()));
                return;
            }
        }

        // If we triggered multiple requests then filter to nodes that appear in the minimum number
        // of results
        std::vector<service_node> nodes;

        if (processed_nodes.size() == 1)
            nodes = std::move(processed_nodes[0]);
        else if (processed_nodes.size() > 1) {
            const size_t required_count = _config.cache_min_num_refresh_presence_to_include_node;

            struct Cursor {
                const std::vector<service_node>* vec;
                size_t index;
            };

            auto cmp = [](const Cursor& a, const Cursor& b) {
                return (*a.vec)[a.index] > (*b.vec)[b.index];  // min-heap
            };
            std::priority_queue<Cursor, std::vector<Cursor>, decltype(cmp)> heap(cmp);

            // Initialise heap with first element of each set
            for (const auto& vec : processed_nodes)
                if (!vec.empty())
                    heap.push(Cursor{&vec, 0});

            while (!heap.empty()) {
                service_node current = (*heap.top().vec)[heap.top().index];
                size_t count = 0;

                std::vector<Cursor> same;

                // Pop all equal elements
                while (!heap.empty()) {
                    const auto& top = heap.top();
                    const service_node& val = (*top.vec)[top.index];

                    if (val < current || current < val)
                        break;

                    same.push_back(top);
                    heap.pop();
                }

                if (same.size() >= required_count)
                    nodes.push_back(current);

                // Advance all matching cursors
                for (auto& cur : same) {
                    size_t next_index = cur.index + 1;

                    if (next_index < cur.vec->size())
                        heap.push(Cursor{cur.vec, next_index});
                }
            }
        }

        // Only replace the cache if the refresh actually came back with a usable pool.  A refresh
        // can legitimately succeed and still produce too few nodes (most easily when the multi-
        // request intersection finds little in common), and overwriting a good cache with that
        // leaves us with nothing to route through until the next refresh completes.  Treat it as a
        // failed refresh and retry instead, keeping whatever cache we already have.
        if (nodes.empty() || nodes.size() < _config.cache_min_size) {
            discard_and_retry("a refreshed cache of only {} nodes (need {})"_format(
                    nodes.size(), _config.cache_min_size));
            return;
        }

        // Update the cache with the combined nodes
        _update_cache(refresh_id, std::move(nodes));
    });
}

void SnodePool::_update_cache(std::string refresh_id, std::vector<service_node> nodes) {
    // Use 'call_get' to force this to be synchronous; a plain 'call' would queue when we aren't
    // already on the loop thread, and the captured `nodes` reference would dangle
    _jq.call_get([this, refresh_id, &nodes] {
        // Shuffle the nodes so we don't have a specific order
        std::ranges::shuffle(nodes, csrng);
        log::info(
                cat,
                "[Request {}] Cache refresh complete with {} nodes.",
                refresh_id,
                nodes.size());

        // Update the in-memory caches and, since the swarm cache could now be invalid, clear it and
        // re-generate `_all_swarms`
        _snode_cache = std::move(nodes);
        _all_swarms = swarm::generate_swarms(_snode_cache);
        _swarm_cache.clear();

        // The pool these redirects were correcting has been replaced, so they have outlived what
        // they were for.  Keeping them would let one node's claim outlast the ground truth that
        // would have overruled it.
        _swarm_overrides.clear();
        _last_snode_cache_update = std::chrono::system_clock::now();

        // Reset all failure and refresh-in-progress state
        _current_snode_cache_refresh_id.reset();
        _snode_refresh_results.clear();
        _refresh_candidate_nodes.clear();
        _snode_cache_refresh_failure_count = 0;

        _disk_loop.call([path = _snode_cache_file_path, cache = _snode_cache] {
            SnodePool::_perform_cache_write(path, cache);
        });

        _run_pending_refresh_callbacks(true);
    });
}

void SnodePool::_run_pending_refresh_callbacks(bool refreshed) {
    if (_after_snode_cache_refresh.empty())
        return;

    // These must be moved out of the member before being run: a callback can re-enter the pool and
    // register another post-refresh callback (`get_swarm` does exactly that if the cache is still
    // empty), which would reallocate the vector we're iterating and leave us calling through a
    // freed `std::function`. Anything registered while we're here accumulates in the now-empty
    // member and runs after the next refresh instead of being silently discarded.
    auto callbacks = std::move(_after_snode_cache_refresh);
    _after_snode_cache_refresh.clear();  // A moved-from vector is valid but unspecified

    log::debug(
            cat,
            "Executing {} post-refresh callbacks ({}).",
            callbacks.size(),
            (refreshed ? "refreshed" : "refresh did not happen"));

    for (const auto& cb : callbacks) {
        try {
            cb(refreshed);
        } catch (const std::exception& e) {
            log::error(cat, "Exception thrown in a post-refresh callback: {}", e.what());
        }
    }
}

// MARK: Public Functions

void SnodePool::suspend() {
    // Use 'call_get' to force this to be synchronous
    _jq.call_get([this] {
        _suspended = true;

        // A refresh in progress can only fail from here on, since every fetch is refused while
        // suspended, so it is abandoned rather than left to work its way through the candidates,
        // and whatever waits on it is answered now.  The failures it built up are dropped too:
        // they say nothing about the network we resume on.
        if (_current_snode_cache_refresh_id) {
            log::info(
                    cat,
                    "[Request {}] Abandoning cache refresh for suspension.",
                    *_current_snode_cache_refresh_id);
            _current_snode_cache_refresh_id.reset();
            _refresh_candidate_nodes.clear();
            _snode_refresh_results.clear();
            _snode_cache_refresh_failure_count = 0;
            _run_pending_refresh_callbacks(false);
        }

        // Force a strike write immediately if we had one scheduled
        if (_strikes_flush_scheduled)
            _disk_loop.call([path = _strikes_file_path, strikes = _snode_strikes] {
                SnodePool::_perform_strikes_write(path, strikes);
            });
        log::info(cat, "Suspended.");
    });
}

void SnodePool::resume() {
    // Use 'call_get' to force this to be synchronous
    _jq.call_get([this] {
        if (!_suspended)
            return;

        _suspended = false;
        log::info(cat, "Resumed.");
    });
}

void SnodePool::set_routed_fetcher(
        network_fetcher_t routed_fetcher, fetcher_connectivity_check_t connectivity_check) {
    _jq.call([this, rf = std::move(routed_fetcher), cc = std::move(connectivity_check)] {
        _routed_fetcher = std::move(rf);
        _routed_fetcher_connectivity_check = std::move(cc);
    });
}

size_t SnodePool::size() {
    return _jq.call_get([this] { return _snode_cache.size(); });
}

void SnodePool::clear_cache() {
    // Use 'call_get' to force this to be synchronous
    _jq.call_get([this] {
        _snode_cache = {};
        _all_swarms = {};
        _swarm_cache = {};
        _swarm_overrides = {};

        _disk_loop.call([path = _snode_cache_file_path] { SnodePool::_clear_disk_cache(path); });
    });
}

size_t SnodePool::_active_strike_count(const ed25519_pubkey& key) const {
    auto it = _snode_strikes.find(key);

    if (it == _snode_strikes.end())
        return 0;

    auto threshold = clock_now_s() - STRIKE_EXPIRY;

    return std::ranges::count_if(it->second, [threshold](auto t) { return t > threshold; });
}

bool SnodePool::_node_struck_out(const ed25519_pubkey& key) const {
    auto strikes = _active_strike_count(key);

    // The `strikes > 0` is what keeps a threshold of 0 meaning "drop a node on its first strike";
    // comparing straight against 0 also drops every node that has never failed at all
    return (strikes > 0 && strikes >= _config.cache_node_strike_threshold);
}

void SnodePool::record_node_failure(const service_node& node, bool permanent) {
    record_node_failure(node.remote_pubkey, permanent);
}

void SnodePool::record_node_failure(const ed25519_pubkey& key, bool permanent) {
    _jq.call([this, key, permanent] {
        auto now = clock_now_s();
        auto& stamps = _snode_strikes[key];
        std::erase_if(stamps, [threshold = now - STRIKE_EXPIRY](auto t) { return t <= threshold; });

        // A permanent failure has to strike the node out whatever the threshold is - looping up to
        // a threshold of 0 records nothing and leaves the node in rotation
        auto strikes = (permanent ? std::max<uint16_t>(1, _config.cache_node_strike_threshold) : 1);

        for (uint16_t i = 0; i < strikes; ++i)
            stamps.push_back(now);

        log::trace(cat, "Recorded strike for node {}, total: {}", key.hex(), stamps.size());

        // Throttle persisting the strikes to disk to at most every X minutes
        if (!_strikes_flush_scheduled && !_suspended) {
            _strikes_flush_scheduled = true;

            _jq.call_later(SAVE_THROTTLE, [this] {
                _strikes_flush_scheduled = false;

                if (_suspended)
                    return;

                _disk_loop.call([path = _strikes_file_path, strikes = _snode_strikes] {
                    SnodePool::_perform_strikes_write(path, strikes);
                });
            });
        }
    });
}

uint16_t SnodePool::node_strike_count(const service_node& node) {
    return node_strike_count(node.remote_pubkey);
}

uint16_t SnodePool::node_strike_count(const ed25519_pubkey& key) {
    return _jq.call_get([this, &key] { return static_cast<uint16_t>(_active_strike_count(key)); });
}

bool SnodePool::node_struck_out(const service_node& node) {
    return node_struck_out(node.remote_pubkey);
}

bool SnodePool::node_struck_out(const ed25519_pubkey& key) {
    return _jq.call_get([this, &key] { return _node_struck_out(key); });
}

void SnodePool::clear_node_strikes() {
    // Use 'call_get' to force this to be synchronous
    _jq.call_get([this] {
        _snode_strikes.clear();
        _strikes_flush_scheduled = false;

        // Immediately write to disk after clearing the snode strikes
        _disk_loop.call(
                [path = _strikes_file_path] { SnodePool::_perform_strikes_write(path, {}); });
    });
}

void SnodePool::refresh_if_needed(
        const std::vector<service_node>& in_use_nodes, refresh_callback_t on_refresh_complete) {
    _jq.call([this, in_use_nodes, cb = std::move(on_refresh_complete)] {
        if (_suspended) {
            log::info(cat, "Ignoring refresh as pool is suspended.");

            if (cb)
                cb(false);
            return;
        }

        bool needs_to_start_refresh = false;
        bool already_running = false;
        std::optional<std::chrono::milliseconds> delay;

        // Don't bother if we are alread doing a refresh
        if (_current_snode_cache_refresh_id)
            already_running = true;
        else {
            auto cache_lifetime = std::chrono::system_clock::now() - _last_snode_cache_update;
            needs_to_start_refresh =
                    (_snode_cache.empty() || cache_lifetime > _config.cache_expiration);

            // Also need to refresh if there are not enough non-failed nodes in the cache
            if (!needs_to_start_refresh) {
                size_t usable_nodes_count = 0;

                std::unordered_set<ed25519_pubkey> in_use_keys;
                for (const auto& node : in_use_nodes)
                    in_use_keys.insert(node.remote_pubkey);

                for (const auto& node : _snode_cache) {
                    if (_node_struck_out(node.remote_pubkey))
                        continue;

                    // If the caller considers the node as already in use then it wouldn't be
                    // considered usable so ignore it for the purpose of determining whether we have
                    // enough nodes to avoid a refresh
                    if (in_use_keys.count(node.remote_pubkey))
                        continue;

                    usable_nodes_count++;

                    if (usable_nodes_count >= _config.cache_min_size)
                        break;
                }

                if (usable_nodes_count < _config.cache_min_size)
                    needs_to_start_refresh = true;
            }

            if (needs_to_start_refresh && cache_lifetime < _config.cache_min_lifetime)
                delay.emplace(std::chrono::duration_cast<std::chrono::milliseconds>(
                        _config.cache_min_lifetime - cache_lifetime));
        }

        // If a refresh is needed or already running, queue the callback
        if ((needs_to_start_refresh || already_running) && cb)
            _after_snode_cache_refresh.push_back(std::move(cb));

        // Kick off a refresh if needed (if none was needed then we should trigger the
        // on_refresh_complete callback immediately)
        if (needs_to_start_refresh)
            if (delay) {
                _jq.call_later(*delay, [this] { _refresh_snode_cache(); });
            } else
                _refresh_snode_cache();
        else if (!already_running && cb)
            // Nothing needed refreshing, which is the answer the caller wanted rather than a
            // failure to get one
            cb(true);
    });
}

void SnodePool::invalidate_swarm(x25519_pubkey swarm_pubkey, refresh_callback_t on_complete) {
    _jq.call([this, swarm_pubkey, cb = std::move(on_complete)]() mutable {
        if (_suspended) {
            log::info(cat, "Ignoring swarm invalidation as pool is suspended.");

            if (cb)
                cb(false);
            return;
        }

        // The swarm cache only ever memoises `swarm::get_swarm(pubkey, _all_swarms)`, and
        // `_all_swarms` is generated from the pool, so dropping the single entry would recompute
        // the same rejected answer.  What the rejection actually disproves is the pool snapshot,
        // and a refresh is the only thing that replaces it - clearing the swarm cache as it goes.
        auto now = std::chrono::system_clock::now();

        if (!_current_snode_cache_refresh_id) {
            // The backoff is deliberately global rather than per-swarm: a refresh replaces the pool
            // every swarm is derived from, so a rejection for one swarm is exactly as unhelpful to
            // act on right after a refresh as a second rejection for the swarm that prompted it
            auto pool_age = now - _last_snode_cache_update;
            auto since_last = now - _last_evidence_refresh;

            // Quiet for twice the interval we were holding means whatever caused the last run is
            // over, so the next incident starts from the base delay rather than inheriting it
            if (since_last > 2 * _evidence_refresh_backoff)
                _evidence_refresh_backoff = 0s;

            if (pool_age < EVIDENCE_REFRESH_MIN_POOL_AGE || since_last < _evidence_refresh_backoff)
                log::debug(
                        cat,
                        "Swarm {} was rejected, but the pool is {}s old and the last refresh on a "
                        "rejection was {}s ago (backoff {}s); leaving it alone.",
                        swarm_pubkey.hex(),
                        std::chrono::duration_cast<std::chrono::seconds>(pool_age).count(),
                        std::chrono::duration_cast<std::chrono::seconds>(since_last).count(),
                        _evidence_refresh_backoff.count());
            else {
                _evidence_refresh_backoff = std::min(
                        std::chrono::seconds{_config.cache_expiration},
                        (_evidence_refresh_backoff == 0s ? EVIDENCE_REFRESH_BASE_BACKOFF
                                                         : _evidence_refresh_backoff * 2));
                _last_evidence_refresh = now;

                log::info(
                        cat,
                        "Swarm {} was rejected by a node we had in it, refreshing the pool (next "
                        "rejection-driven refresh no sooner than {}s from now).",
                        swarm_pubkey.hex(),
                        _evidence_refresh_backoff.count());
                _refresh_snode_cache();
            }
        }

        if (!cb)
            return;

        // `_refresh_snode_cache` runs inline here (we are on the loop thread) and can decline to
        // start, so it is the refresh id - not the call above - that says whether there is anything
        // to wait for.  A callback queued against a refresh that never started never runs, and on
        // this path that would strand the request that triggered the rejection.
        if (_current_snode_cache_refresh_id)
            _after_snode_cache_refresh.push_back(std::move(cb));
        else
            // No refresh started, so the caller is holding the same swarm answer it came in with
            cb(false);
    });
}

bool SnodePool::record_swarm_redirect(
        x25519_pubkey swarm_pubkey, const std::vector<ed25519_pubkey>& swarm_node_keys) {
    return _jq.call_get([this, swarm_pubkey, &swarm_node_keys] {
        if (_snode_cache.empty() || _all_swarms.empty())
            return false;

        // Resolving the names against our own pool is what makes a redirect safe to act on: the
        // responding node chooses which registered nodes we end up talking to, but it cannot invent
        // a node or point us at an address of its own choosing, because we never read the contact
        // details it sent
        std::unordered_set<ed25519_pubkey> named{swarm_node_keys.begin(), swarm_node_keys.end()};
        std::vector<service_node> resolved;

        for (const auto& node : _snode_cache)
            if (named.count(node.remote_pubkey))
                resolved.push_back(node);

        if (resolved.empty()) {
            log::debug(
                    cat,
                    "Ignoring redirect for {}: none of the {} named nodes are in our pool.",
                    swarm_pubkey.hex(),
                    swarm_node_keys.size());
            return false;
        }

        // Too few of the named nodes resolved to call the result a swarm: either our pool is too
        // old to know the rest, or the redirect isn't describing one.  Only a refresh settles
        // which, and the nodes we do have still beat the swarm that just rejected us, so they are
        // followed meanwhile.  Deliberately not also requiring that some names were unknown - a
        // redirect naming one node we do know is the shape with no stale pool to explain it.
        const bool too_few_resolved = resolved.size() < _config.cache_min_swarm_size;

        auto& [nodes, redirects] = _swarm_overrides[swarm_pubkey];
        nodes = std::move(resolved);

        // Saturating, because counting carries on past the limit for as long as the refresh it
        // asks for is throttled, and wrapping would stop it asking
        if (redirects < std::numeric_limits<decltype(redirects)>::max())
            ++redirects;

        log::debug(
                cat,
                "Redirected to a swarm of {} nodes for {} (redirect {} since the pool was "
                "refreshed).",
                nodes.size(),
                swarm_pubkey.hex(),
                redirects);

        if (too_few_resolved) {
            log::warning(
                    cat,
                    "Asking for a refresh for {}: only {} of the {} nodes its redirect named are "
                    "ones we know.",
                    swarm_pubkey.hex(),
                    nodes.size(),
                    named.size());
            invalidate_swarm(swarm_pubkey);
        } else if (redirects > SWARM_REDIRECTS_BEFORE_REFRESH) {
            // Past the limit every redirect asks again, for as long as the refresh stays
            // throttled, so only crossing it is worth a warning
            if (redirects == SWARM_REDIRECTS_BEFORE_REFRESH + 1)
                log::warning(
                        cat,
                        "Asking for a refresh for {}: {} redirects since the pool was refreshed.",
                        swarm_pubkey.hex(),
                        redirects);
            else
                log::debug(
                        cat,
                        "Asking again for a refresh for {}: {} redirects since the pool was "
                        "refreshed.",
                        swarm_pubkey.hex(),
                        redirects);
            invalidate_swarm(swarm_pubkey);
        }

        return true;
    });
}

std::vector<service_node> SnodePool::get_unused_nodes(
        size_t count, const std::vector<service_node>& exclude_nodes) {
    // Kick of a cache refresh in the background if needed (call_soon to ensure it is scheduled
    // after whatever called `get_unused_nodes` which may be something trying to make it's own
    // request that we would want to run first)
    _jq.call_soon([this, exclude_nodes] { refresh_if_needed(exclude_nodes); });

    return _jq.call_get([this, count, exclude_nodes] {
        if (_snode_cache.empty()) {
            log::warning(cat, "Cannot get unused nodes: snode cache is empty.");
            return std::vector<service_node>{};
        }

        // Then try to get the desired number of nodes from the current cache
        std::vector<service_node> result;
        result.reserve(count);

        std::unordered_set<ed25519_pubkey> exclusion_keys;
        exclusion_keys.reserve(exclude_nodes.size());
        for (const auto& node : exclude_nodes)
            exclusion_keys.insert(node.remote_pubkey);

        std::unordered_set<oxen::quic::ipv4> used_subnets;
        if (_config.enforce_subnet_diversity)
            for (const auto& node : exclude_nodes)
                used_subnets.insert(node.ip.to_base(24));

        // Pick a random starting index to start checking for unused nodes
        size_t start_index = random::get_uniform_distribution<size_t>(0, _snode_cache.size() - 1);

        for (size_t i = 0; i < _snode_cache.size(); ++i) {
            if (result.size() >= count)
                break;

            const size_t current_index = (start_index + i) % _snode_cache.size();
            const auto& node = _snode_cache[current_index];

            // Skip nodes explicitly excluded (needed in case subnet diversity is disabled)
            if (exclusion_keys.count(node.remote_pubkey))
                continue;

            // Skip nodes with too many failures
            if (_node_struck_out(node.remote_pubkey))
                continue;

            // Skip nodes whos IP addresses are in the exclusion list
            if (_config.enforce_subnet_diversity) {
                auto subnet = node.ip.to_base(24);
                if (used_subnets.count(subnet))
                    continue;
            }

            result.push_back(node);

            if (_config.enforce_subnet_diversity)
                used_subnets.insert(node.ip.to_base(24));
        }

        if (result.size() < count)
            log::warning(cat, "Could only find {}/{} suitable unused nodes.", result.size(), count);

        return result;
    });
}

void SnodePool::get_swarm(
        session::network::x25519_pubkey swarm_pubkey,
        bool ignore_strike_count,
        std::function<void(swarm_id_t swarm_id, std::vector<service_node> swarm)> callback) {
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, swarm_pubkey.hex());

    _jq.call([this, swarm_pubkey, ignore_strike_count, cb = std::move(callback)] {
        // Trigger a non-blocking background refresh if the data is stale.  Up here so that it runs
        // for every call: answers from an override or the swarm cache below return early, and
        // they are most of them.
        _jq.call_soon([this] { refresh_if_needed({}); });

        auto filter_by_strikes =
                [this](std::vector<service_node> nodes) -> std::vector<service_node> {
            // Shuffle everything to start with
            std::ranges::shuffle(nodes, csrng);

            auto get_strike_count = [this](const service_node& node) -> size_t {
                return _active_strike_count(node.remote_pubkey);
            };

            // Partition into below-threshold and above-thresold.  This keeps the shuffled order of
            // each set:
            auto over_nodes = std::ranges::stable_partition(
                    nodes.begin(), nodes.end(), [&](const auto& node) {
                        return get_strike_count(node) < _config.cache_node_strike_threshold;
                    });

            // Within the ones we would use, put the preferred versions first -- again stable, so
            // each subset keeps its shuffled order.  Strikes stay the outer split: one is a node
            // that has actually failed us, whereas the version is only a prediction about whether
            // it can be reached at all.
            //
            // Ordering rather than filtering, and only the retained set is touched, so everything
            // below about adopting struck nodes to make up the numbers is unaffected -- a swarm
            // with no preferred members still hands back exactly what it did before.
            if (_config.prefer_min_version)
                std::ranges::stable_partition(
                        nodes.begin(), over_nodes.begin(), [&](const auto& node) {
                            return node.storage_server_version >= *_config.prefer_min_version;
                        });

            auto under_count = nodes.size() - over_nodes.size();
            if (over_nodes.empty()) {
                // Nothing we can do even if we want more
            } else if (under_count >= _config.cache_min_swarm_size) {
                // We got enough without considering over-threshold nodes, so just drop them:
                nodes.erase(over_nodes.begin(), over_nodes.end());
            } else {
                // We need to adopt some under-threshold nodes, so stable-sort them by strike count
                // (the stable part of the sort means we retain their shuffled order among ties),
                // and then resize nodes to drop off everything beyond the minimum required
                std::ranges::stable_sort(over_nodes, std::ranges::less{}, get_strike_count);
                nodes.resize(std::min(nodes.size(), _config.cache_min_swarm_size));
            }

            return nodes;
        };

        // A node that rejected a request for this account told us where it belongs, which beats
        // anything we can work out from a pool we now know is behind.  There is no swarm id to give
        // back - a redirect names members, not an id - and nothing downstream reads it.
        if (auto it = _swarm_overrides.find(swarm_pubkey); it != _swarm_overrides.end()) {
            const auto& swarm_nodes = it->second.first;

            return cb(
                    swarm::INVALID_SWARM_ID,
                    (ignore_strike_count ? swarm_nodes : filter_by_strikes(swarm_nodes)));
        }

        // Check the in-memory swarm cache first
        if (auto it = _swarm_cache.find(swarm_pubkey); it != _swarm_cache.end()) {
            const auto& swarm_nodes = it->second.second;

            return cb(
                    it->second.first,
                    (ignore_strike_count ? swarm_nodes : filter_by_strikes(swarm_nodes)));
        }

        // If we have no snode cache or no swarms then we need to rebuild the cache (which will also
        // rebuild the swarms) and run this request again
        if (_snode_cache.empty() || _all_swarms.empty()) {
            log::debug(cat, "Cache is empty, deferring get_swarm until refresh is complete.");

            // Queue this entire function call to be re-run after the refresh.
            _after_snode_cache_refresh.push_back(
                    [this, swarm_pubkey, ignore_strike_count, cb = std::move(cb)](bool refreshed) {
                        // Re-deferring when the refresh never happened would just queue against the
                        // next one that doesn't either; there is no swarm to give back
                        if (!refreshed)
                            return cb(swarm::INVALID_SWARM_ID, {});

                        this->get_swarm(swarm_pubkey, ignore_strike_count, std::move(cb));
                    });

            // If a refresh isn't already running we need to start one
            if (!_current_snode_cache_refresh_id)
                _refresh_snode_cache();

            return;
        }

        // Perform the swarm calculation using our local copy of the data
        auto swarm = swarm::get_swarm(swarm_pubkey, _all_swarms);
        _swarm_cache[swarm_pubkey] = swarm;

        log::info(
                cat,
                "Found swarm with {} nodes for {}, adding to cache.",
                swarm.second.size(),
                swarm_pubkey.hex());

        cb(swarm.first, (ignore_strike_count ? swarm.second : filter_by_strikes(swarm.second)));
    });
}

}  // namespace session::network
