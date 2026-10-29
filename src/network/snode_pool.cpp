#include "session/network/snode_pool.hpp"

#include <fmt/ranges.h>
#include <oxenc/base64.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <concepts>
#include <exception>
#include <fstream>
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

        // A refresh for subnets picks its step here, and may finish without fetching anything: by
        // adopting the prepackaged pool, or by relaxing diversity.  Its step is kept until the
        // refresh completes or gives up, so that a retry of this same refresh asks the same way.
        if (std::exchange(_subnet_shortfall, false) && _subnet_refresh == SubnetRefresh::none &&
            !_choose_subnet_refresh(request_id))
            return;
        const bool for_subnets = _subnet_refresh != SubnetRefresh::none;

        // We should only use the routed_fetcher if it exists, passes a connectivity check, and
        // there are enough cached nodes
        const auto cache_insufficient =
                (_config.cache_num_nodes_to_use_for_refresh > 0 &&
                 _snode_cache.size() < _config.cache_num_nodes_to_use_for_refresh);
        use_routed_fetcher = for_subnets ? _subnet_refresh == SubnetRefresh::routed
                                         : (cache_insufficient && _routed_fetcher &&
                                            _routed_fetcher_connectivity_check &&
                                            (*_routed_fetcher_connectivity_check)());

        // We should only refresh using seed nodes if using cached nodes is disabled, there aren't
        // enough cached nodes to refresh from, or the cache spans too few subnets: refreshing that
        // from its own nodes would hand back the same network
        const auto use_seed_nodes =
                (_config.cache_num_nodes_to_use_for_refresh == 0 || cache_insufficient ||
                 for_subnets);

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
            return;
        }

        // Kick off the concurrent requests (if there are any)
        for (uint8_t i = 0; i < num_nodes_for_refresh; ++i)
            _launch_next_refresh_request(
                    request_id, i, use_seed_nodes, !use_routed_fetcher, num_nodes_for_refresh);
    });
}

std::optional<std::vector<service_node>> SnodePool::_load_fallback_pool(
        const std::string& request_id) {
    if (!_config.fallback_snode_pool_path || _config.fallback_snode_pool_path->empty() ||
        !fs::exists(*_config.fallback_snode_pool_path))
        return std::nullopt;

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
        auto file_time_sys = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                file_time - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
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

                // If a node has an unlock height and it is in the past then it's possible that the
                // node is offline so don't both including it in the initial cache (if we get a
                // successful connection and refresh the cache then it would be added back at that
                // point)
                if (snode.requested_unlock_height &&
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

        return parsed_nodes;
    } catch (const std::exception& e) {
        log::error(cat, "[Request {}] Failed to process fallback cache: {}", request_id, e.what());
        return std::nullopt;
    }
}

size_t SnodePool::_usable_subnet_count(const std::vector<service_node>& nodes) const {
    std::unordered_set<oxen::quic::ipv4> subnets;
    for (const auto& node : nodes) {
        auto it = _snode_strikes.find(node.remote_pubkey);
        if (it == _snode_strikes.end() || it->second.size() < _config.cache_node_strike_threshold)
            subnets.insert(node.ip.to_base(24));
    }
    return subnets.size();
}

bool SnodePool::_choose_subnet_refresh(const std::string& request_id) {
    const bool can_route = !_config.seed_nodes.empty() && _routed_fetcher &&
                           _routed_fetcher_connectivity_check &&
                           (*_routed_fetcher_connectivity_check)();

    // 1. The seed nodes, routed
    if (!_routed_subnet_refresh_failed && can_route) {
        log::info(
                cat,
                "[Request {}] Refreshing for subnets from the seed nodes, routed.",
                request_id);
        _subnet_refresh = SubnetRefresh::routed;
        return true;
    }

    // 2. The prepackaged pool, when routing was not even possible: the same as it having failed
    if (!_routed_subnet_refresh_failed) {
        _routed_subnet_refresh_failed = true;
        if (_adopt_prepackaged_for_subnets(request_id))
            return false;
    }

    // 3. The seed nodes, directly
    if (!_direct_subnet_refresh_failed && !_config.seed_nodes.empty()) {
        log::info(
                cat,
                "[Request {}] Refreshing for subnets from the seed nodes, directly.",
                request_id);
        _subnet_refresh = SubnetRefresh::direct;
        return true;
    }

    _direct_subnet_refresh_failed = true;
    _relax_for_subnets(request_id, "there are no seed nodes to ask");
    return false;
}

void SnodePool::_subnet_refresh_failed(const std::string& request_id) {
    const auto failed = std::exchange(_subnet_refresh, SubnetRefresh::none);
    _current_snode_cache_refresh_id.reset();
    _snode_refresh_results.clear();
    _refresh_candidate_nodes.clear();

    if (failed == SubnetRefresh::routed) {
        log::warning(
                cat,
                "[Request {}] No seed node answered over the routed fetcher with a usable pool.",
                request_id);
        _routed_subnet_refresh_failed = true;
        if (_adopt_prepackaged_for_subnets(request_id))
            return;

        // On to the seed nodes directly, as a fresh refresh: the callbacks waiting on this one are
        // still queued for it
        _subnet_shortfall = true;
        _refresh_snode_cache();
        return;
    }

    _direct_subnet_refresh_failed = true;
    _relax_for_subnets(request_id, "no seed node answered directly with a usable pool");
}

bool SnodePool::_adopt_prepackaged_for_subnets(const std::string& request_id) {
    // Nobody on the network can alter the prepackaged pool, and the connection to each node still
    // checks its key, so it being stale only means some of its nodes are gone.  Worth it only if it
    // spans more subnets than what we have - which it may not, if it is what the cache was built
    // from.  It is trusted to be a pool of this network, as at bootstrap: nothing in the file says
    // which (see `opt::fallback_snode_pool_path`).
    auto fallback = _load_fallback_pool(request_id);
    if (!fallback || _usable_subnet_count(*fallback) <= _usable_subnet_count(_snode_cache))
        return false;

    log::warning(
            cat,
            "[Request {}] Using the prepackaged snode pool, which spans more /24 subnets than the "
            "cache.",
            request_id);
    _update_cache(request_id, std::move(*fallback), CacheSource::prepackaged);
    return true;
}

void SnodePool::_relax_for_subnets(const std::string& request_id, std::string_view why) {
    // The cache we have is still usable, only not diverse enough, so rather than wait indefinitely,
    // use it with as little subnet sharing as it allows
    log::warning(
            cat,
            "[Request {}] The snode cache spans too few /24 subnets and {}; allowing nodes to "
            "share "
            "subnets, as few as possible, until the next refresh.",
            request_id,
            why);
    _subnet_refresh = SubnetRefresh::none;
    _subnet_diversity_relaxed = true;
    _current_snode_cache_refresh_id.reset();
    _snode_refresh_results.clear();
    _refresh_candidate_nodes.clear();
    _run_after_refresh_callbacks();
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
        if (!_current_snode_cache_refresh_id)
            return;

        const auto target_request_id = "{}-{}"_format(request_id, index);

        if (_refresh_candidate_nodes.empty() && _subnet_refresh != SubnetRefresh::none) {
            _subnet_refresh_failed(request_id);
            return;
        }

        if (_refresh_candidate_nodes.empty()) {
            // If we run out of candidate nodes then we should fail this refresh request and kick
            // off a new one with a new id (the `_refresh_snode_cache` will decide which nodes and
            // fetcher should be used)
            //
            // If this was a bootstrap request then we've failed to refresh from all seed nodes so
            // we should try to use the `fallback_snode_pool_path` if it exists, otherwise just
            // retry indefinitely (not much else we can do)
            if (refreshing_from_seed_nodes)
                if (auto fallback = _load_fallback_pool(request_id)) {
                    log::warning(
                            cat,
                            "[Request {}] Ran out of seed nodes for refresh, using fallback cache.",
                            request_id);
                    _update_cache(request_id, std::move(*fallback), CacheSource::prepackaged);
                    return;
                }

            _snode_cache_refresh_failure_count++;
            auto delay = _config.retry_delay.exponential(_snode_cache_refresh_failure_count);
            log::warning(
                    cat,
                    "[Request {}] Ran out of nodes for refresh, discarding partial results and "
                    "trying again in {}ms.",
                    target_request_id,
                    delay.count());
            _jq.call_later(delay, [this] {
                // We need to wait until after the `call_later` to reset the `refresh_id` (and clear
                // previous results) as if we don't then additional refreshes could be triggered
                // during the delay
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
            _subnet_refresh = SubnetRefresh::none;
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
        // From the seed nodes, routed or not, it is the network as they see it: routing can only
        // drop or delay a reply encrypted for the seed node, not change it
        _update_cache(
                refresh_id,
                std::move(nodes),
                refreshing_from_seed_nodes ? CacheSource::seed_nodes : CacheSource::other);
    });
}

void SnodePool::_update_cache(
        std::string refresh_id, std::vector<service_node> nodes, CacheSource source) {
    // Use 'call_get' to force this to be synchronous; a plain 'call' would queue when we aren't
    // already on the loop thread, and the captured `nodes` reference would dangle
    _jq.call_get([this, refresh_id, &nodes, source] {
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
        _last_snode_cache_update = std::chrono::system_clock::now();

        // Reset all failure and refresh-in-progress state
        _current_snode_cache_refresh_id.reset();
        _snode_refresh_results.clear();
        _refresh_candidate_nodes.clear();
        _snode_cache_refresh_failure_count = 0;

        // A new cache is judged afresh: diversity is enforced again.  Only adopting the prepackaged
        // pool is itself a step of a refresh for subnets, after which the seed nodes directly are
        // still to try; any other cache starts the steps over.
        _cache_source = source;
        _subnet_refresh = SubnetRefresh::none;
        _subnet_diversity_relaxed = false;
        _subnet_shortfall = false;
        if (source != CacheSource::prepackaged) {
            _routed_subnet_refresh_failed = false;
            _direct_subnet_refresh_failed = false;
        }

        _disk_loop.call([path = _snode_cache_file_path, cache = _snode_cache] {
            SnodePool::_perform_cache_write(path, cache);
        });

        _run_after_refresh_callbacks();
    });
}

void SnodePool::_run_after_refresh_callbacks() {
    // These must be moved out of the member before being run: a callback can re-enter the pool and
    // register another post-refresh callback (`get_swarm` does exactly that if the cache is still
    // empty), which would reallocate the vector we're iterating and leave us calling through a
    // freed `std::function`. Anything registered while we're here accumulates in the now-empty
    // member and runs after the next refresh instead of being silently discarded.
    if (_after_snode_cache_refresh.empty())
        return;

    auto callbacks = std::move(_after_snode_cache_refresh);
    _after_snode_cache_refresh.clear();  // A moved-from vector is valid but unspecified

    log::debug(cat, "Executing {} post-refresh callbacks.", callbacks.size());

    for (const auto& cb : callbacks) {
        try {
            cb();
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
        _subnet_shortfall = false;
        _cache_source = CacheSource::other;
        _routed_subnet_refresh_failed = false;
        _direct_subnet_refresh_failed = false;
        _subnet_diversity_relaxed = false;

        _disk_loop.call([path = _snode_cache_file_path] { SnodePool::_clear_disk_cache(path); });
    });
}

void SnodePool::record_node_failure(const service_node& node, bool permanent) {
    record_node_failure(node.remote_pubkey, permanent);
}

void SnodePool::record_node_failure(const ed25519_pubkey& key, bool permanent) {
    _jq.call([this, key, permanent] {
        auto now = clock_now_s();

        if (permanent)
            for (int i = 0; i < _config.cache_node_strike_threshold; ++i)
                _snode_strikes[key].push_back(now);
        else
            _snode_strikes[key].push_back(now);

        log::trace(
                cat,
                "Recorded strike for node {}, total: {}",
                key.hex(),
                _snode_strikes[key].size());

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
    return _jq.call_get([this, &key] {
        auto it = _snode_strikes.find(key);
        if (it == _snode_strikes.end())
            return uint16_t{0};

        const auto& stamps = it->second;

        const auto threshold = clock_now_s() - STRIKE_EXPIRY;

        uint16_t count = 0;
        for (auto t : stamps)
            if (t > threshold)
                count++;

        return count;
    });
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
        const std::vector<service_node>& in_use_nodes, std::function<void()> on_refresh_complete) {
    _jq.call([this, in_use_nodes, cb = std::move(on_refresh_complete)] {
        if (_suspended) {
            log::info(cat, "Ignoring refresh as pool is suspended.");
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
                    auto it = _snode_strikes.find(node.remote_pubkey);
                    if (it != _snode_strikes.end() &&
                        it->second.size() >= _config.cache_node_strike_threshold)
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

            // Enough nodes by count, but `get_unused_nodes` could not draw them from distinct
            // subnets: without a refresh, a caller retrying on our callback is answered at once and
            // fails the same way, for ever
            if (_subnet_shortfall)
                needs_to_start_refresh = true;

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
            cb();
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

        std::unordered_set<ed25519_pubkey> exclusion_keys;
        exclusion_keys.reserve(exclude_nodes.size());
        for (const auto& node : exclude_nodes)
            exclusion_keys.insert(node.remote_pubkey);

        // Pick a random starting index to start checking for unused nodes
        const size_t start_index =
                random::get_uniform_distribution<size_t>(0, _snode_cache.size() - 1);

        // At most `max_share` nodes from any one /24 subnet, counting those in `exclude_nodes`, or
        // no limit at all for 0.  Each pass allows one more per subnet, so a subnet is shared only
        // once every subnet with fewer nodes in use has nothing left to give.
        auto pick = [&](size_t max_share) {
            std::vector<service_node> result;
            result.reserve(count);
            std::vector<bool> taken(_snode_cache.size(), false);

            std::unordered_map<oxen::quic::ipv4, size_t> subnet_uses;
            if (max_share > 0)
                for (const auto& node : exclude_nodes)
                    subnet_uses[node.ip.to_base(24)]++;

            for (size_t share = 1; result.size() < count && (max_share == 0 || share <= max_share);
                 ++share) {
                for (size_t i = 0; i < _snode_cache.size() && result.size() < count; ++i) {
                    const size_t current_index = (start_index + i) % _snode_cache.size();
                    if (taken[current_index])
                        continue;
                    const auto& node = _snode_cache[current_index];

                    // Skip nodes explicitly excluded (needed in case subnet diversity is disabled)
                    if (exclusion_keys.count(node.remote_pubkey))
                        continue;

                    // Skip nodes with too many failures
                    auto it = _snode_strikes.find(node.remote_pubkey);
                    if (it != _snode_strikes.end() &&
                        it->second.size() >= _config.cache_node_strike_threshold)
                        continue;

                    if (max_share > 0) {
                        auto& uses = subnet_uses[node.ip.to_base(24)];
                        if (uses >= share)
                            continue;
                        uses++;
                    }

                    taken[current_index] = true;
                    result.push_back(node);
                }

                if (max_share == 0)
                    break;
            }
            return result;
        };

        if (!_config.enforce_subnet_diversity) {
            auto result = pick(0);
            if (result.size() < count)
                log::warning(
                        cat, "Could only find {}/{} suitable unused nodes.", result.size(), count);
            return result;
        }

        // Enough to never be the limit: every node picked, and every excluded one, in one subnet
        const size_t any_share = count + exclude_nodes.size();

        auto result = pick(_subnet_diversity_relaxed ? any_share : 1);
        if (result.size() >= count)
            return result;

        // Short only because of subnet diversity: refresh for it (see `_choose_subnet_refresh`),
        // and give way only for a cache that is the seed nodes' own list, or once every way of
        // reaching them has failed
        if (!_subnet_diversity_relaxed) {
            if (auto shared = pick(any_share); shared.size() >= count) {
                if (_cache_source == CacheSource::seed_nodes || _direct_subnet_refresh_failed) {
                    log::warning(
                            cat,
                            "The snode cache spans too few /24 subnets for {} nodes from distinct "
                            "subnets, {}; allowing nodes to share subnets, as few as possible, "
                            "until the next refresh.",
                            count,
                            (_cache_source == CacheSource::seed_nodes
                                     ? "as the seed nodes list the network"
                                     : "and the seed nodes cannot be reached"));
                    _subnet_diversity_relaxed = true;
                    return shared;
                }

                if (!_subnet_shortfall)
                    log::warning(
                            cat,
                            "Could only find {}/{} unused nodes in distinct /24 subnets; "
                            "refreshing for more.",
                            result.size(),
                            count);
                _subnet_shortfall = true;
                return result;
            }
        }

        log::warning(cat, "Could only find {}/{} suitable unused nodes.", result.size(), count);
        return result;
    });
}

void SnodePool::set_swarm(
        session::network::x25519_pubkey swarm_pubkey,
        swarm_id_t swarm_id,
        std::vector<service_node> nodes) {
    _jq.call([this, swarm_pubkey, swarm_id, nodes = std::move(nodes)]() mutable {
        log::info(
                cat,
                "Overriding cached swarm for {} with {} authoritative node(s).",
                swarm_pubkey.hex(),
                nodes.size());
        _swarm_cache[swarm_pubkey] = {swarm_id, std::move(nodes)};
    });
}

void SnodePool::get_swarm(
        session::network::x25519_pubkey swarm_pubkey,
        bool ignore_strike_count,
        std::function<void(swarm_id_t swarm_id, std::vector<service_node> swarm)> callback) {
    log::trace(cat, "{} called for {}.", __PRETTY_FUNCTION__, swarm_pubkey.hex());

    _jq.call([this, swarm_pubkey, ignore_strike_count, cb = std::move(callback)] {
        auto filter_by_strikes =
                [this](std::vector<service_node> nodes) -> std::vector<service_node> {
            // Shuffle everything to start with
            std::ranges::shuffle(nodes, csrng);

            auto get_strike_count = [this](const service_node& node) -> size_t {
                auto it = _snode_strikes.find(node.remote_pubkey);
                return (it != _snode_strikes.end() ? it->second.size() : 0);
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
                    [this, swarm_pubkey, ignore_strike_count, cb = std::move(cb)]() {
                        this->get_swarm(swarm_pubkey, ignore_strike_count, std::move(cb));
                    });

            // If a refresh isn't already running we need to start one
            if (!_current_snode_cache_refresh_id)
                _refresh_snode_cache();

            return;
        }

        // Trigger a non-blocking background refresh if the data is stale
        _jq.call_soon([this] { refresh_if_needed({}); });

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
