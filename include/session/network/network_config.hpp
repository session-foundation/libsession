#pragma once

#include <chrono>
#include <filesystem>
#include <limits>
#include <oxen/log.hpp>
#include <type_traits>

#include "network_opt.hpp"
#include "session/types.hpp"

namespace session::network::config {

using namespace std::chrono_literals;
namespace fs = std::filesystem;

struct Config {
  public:
    opt::netid::Target netid = opt::netid::Target::mainnet;
    opt::router::Type router = opt::router::Type::onion_requests;
    opt::transport::Type transport = opt::transport::Type::quic;

    // File server options
    std::optional<std::string> custom_file_server_scheme = std::nullopt;
    std::optional<std::string> custom_file_server_host = std::nullopt;
    std::optional<uint16_t> custom_file_server_port = std::nullopt;
    std::optional<std::string> custom_file_server_pubkey_hex = std::nullopt;
    std::optional<uint64_t> custom_file_server_max_file_size = std::nullopt;
    bool file_server_use_stream_encryption = false;

    // General options
    bool increase_no_file_limit = false;
    uint8_t path_length = 3;
    bool enforce_subnet_diversity = true;
    uint8_t redirect_retry_count = 1;
    opt::retry_delay retry_delay = opt::retry_delay(200ms, 5s);
    uint8_t num_nodes_to_check_for_network_offset = 3;
    std::chrono::minutes min_resume_clock_resync_interval = 10min;

    // Netid Options
    std::vector<service_node> seed_nodes;

    // Snode Pool Options
    std::optional<fs::path> cache_directory;
    std::optional<fs::path> fallback_snode_pool_path;
    std::chrono::minutes cache_expiration = 2h;
    std::chrono::milliseconds cache_min_lifetime = 2s;
    size_t cache_min_size = 12;
    size_t cache_min_swarm_size = 3;
    uint8_t cache_num_nodes_to_use_for_refresh = 3;
    uint8_t cache_min_num_refresh_presence_to_include_node = 2;
    uint8_t cache_node_strike_threshold = 3;

    // Onion Request Router Options
    uint8_t onionreq_path_strike_threshold = 3;
    uint8_t onionreq_path_build_retry_limit = 10;
    std::unordered_map<PathCategory, uint8_t> onionreq_min_path_counts = {
            {PathCategory::standard, 2}, {PathCategory::file, 2}};
    bool onionreq_single_path_mode = false;
    bool onionreq_disable_pre_build_paths = false;
    std::chrono::minutes onionreq_path_rotation_frequency{10min};
    std::chrono::days onionreq_edge_node_cache_duration = std::chrono::days{10};

    // Quic Transport Options
    std::chrono::milliseconds quic_handshake_timeout{3s};
    std::chrono::seconds quic_keep_alive{10s};
    std::optional<size_t> quic_max_udp_payload;

    template <typename... Opt>
        requires(sizeof...(Opt) > 0 && (opt::is_option<std::decay_t<Opt>> && ...))
    Config(Opt&&... opts) {
        // parse all options
        ((void)handle_config_opt(std::forward<Opt>(opts)), ...);
        _init();
    }
    explicit Config(const std::vector<opt::any>& opts);

    Config() = default;

  private:
    void _init();

    void handle_config_opt(opt::netid netid);
    void handle_config_opt(opt::router router);
    void handle_config_opt(opt::transport transport);

    // File server options
    void handle_config_opt(opt::file_server_scheme fss);
    void handle_config_opt(opt::file_server_host fsh);
    void handle_config_opt(opt::file_server_port fsp);
    void handle_config_opt(opt::file_server_pubkey_hex fsph);
    void handle_config_opt(opt::file_server_max_file_size fsmfs);
    void handle_config_opt(opt::file_server_use_stream_encryption fsuse);

    // General options
    void handle_config_opt(opt::increase_no_file_limit infl);
    void handle_config_opt(opt::path_length pl);
    void handle_config_opt(opt::disable_subnet_diversity dsd);
    void handle_config_opt(opt::redirect_retry_count rrc);
    void handle_config_opt(opt::retry_delay rd);
    void handle_config_opt(opt::num_nodes_to_check_for_network_offset nncno);
    void handle_config_opt(opt::min_resume_clock_resync_interval mrcri);

    // Snode pool options
    void handle_config_opt(opt::cache_directory dir);
    void handle_config_opt(opt::fallback_snode_pool_path fspp);
    void handle_config_opt(opt::cache_expiration ce);
    void handle_config_opt(opt::cache_min_lifetime mcl);
    void handle_config_opt(opt::cache_min_size mcs);
    void handle_config_opt(opt::cache_min_swarm_size mss);
    void handle_config_opt(opt::cache_num_nodes_to_use_for_refresh nnr);
    void handle_config_opt(opt::cache_min_num_refresh_presence_to_include_node mnrp);
    void handle_config_opt(opt::cache_node_strike_threshold nst);

    // Quic transport options
    void handle_config_opt(opt::quic_handshake_timeout qht);
    void handle_config_opt(opt::quic_keep_alive qka);
    void handle_config_opt(opt::quic_max_udp_payload qmup);
    void handle_config_opt(opt::quic_disable_mtu_discovery qdmd);

    // Onion request router options
    void handle_config_opt(opt::onionreq_path_strike_threshold pst);
    void handle_config_opt(opt::onionreq_path_build_retry_limit pbrl);
    void handle_config_opt(opt::onionreq_min_path_count mpc);
    void handle_config_opt(opt::onionreq_single_path_mode spm);
    void handle_config_opt(opt::onionreq_disable_pre_build_paths dpbp);
    void handle_config_opt(opt::onionreq_path_rotation_frequency prf);
    void handle_config_opt(opt::onionreq_edge_node_cache_duration encd);

    template <typename Opt>
    void handle_config_opt(std::optional<Opt>&& o) {
        if (o)
            handle_config_opt(*std::move(o));
    }
    template <typename Opt>
    void handle_config_opt(const std::optional<Opt>& o) {
        if (o)
            handle_config_opt(*o);
    }
};

}  // namespace session::network::config
