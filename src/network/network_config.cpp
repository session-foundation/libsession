#include "session/network/network_config.hpp"

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <variant>

using namespace oxen;
using namespace oxen::log::literals;

namespace session::network::config {

inline auto cat = oxen::log::Cat("network");

Config::Config(const std::vector<opt::any>& opts) {
    for (const auto& o : opts)
        std::visit([this](const auto& option) { handle_config_opt(option); }, o);
    _init();
}

void Config::_init() {
    log::debug(cat, "Network config created successfully");
}

void Config::handle_config_opt(opt::netid netid_) {
    netid = netid_.target;
    seed_nodes = std::move(netid_.seed_nodes);

    switch (netid_.target) {
        case opt::netid::Target::mainnet:
            log::debug(
                    cat, "Network config set to mainnet with {} seed node(s)", seed_nodes.size());
            break;
        case opt::netid::Target::testnet:
            log::debug(
                    cat, "Network config set to testnet with {} seed node(s)", seed_nodes.size());
            break;

        case opt::netid::Target::devnet:
            log::debug(cat, "Network config set to devnet with {} seed node(s)", seed_nodes.size());
            break;
    }
}

void Config::handle_config_opt(opt::router router_) {
    router = router_.type;

    switch (router_.type) {
        case opt::router::Type::onion_requests:
            log::debug(cat, "Network config set to route requests using Onion Requests");
            break;

        case opt::router::Type::session_router:
            log::debug(cat, "Network config set to route requests using Session Router");
            break;

        case opt::router::Type::direct:
            log::debug(cat, "Network config set to route requests directly");
            break;
    }
}

void Config::handle_config_opt(opt::transport transport_) {
    transport = transport_.type;

    switch (transport_.type) {
        case opt::transport::Type::quic:
            log::debug(cat, "Network config set to transport requests via QUIC");
            break;
    }
}

// MARK: File server options

void Config::handle_config_opt(opt::file_server_scheme fss) {
    custom_file_server_scheme = fss.scheme;
    log::debug(cat, "Network config custom file server scheme set to {}", fss.scheme);
}

void Config::handle_config_opt(opt::file_server_host fsh) {
    custom_file_server_host = fsh.host;
    log::debug(cat, "Network config custom file server host set to {}", fsh.host);
}

void Config::handle_config_opt(opt::file_server_port fsp) {
    custom_file_server_port = fsp.port;
    log::debug(cat, "Network config custom file server port set to {}", fsp.port);
}

void Config::handle_config_opt(opt::file_server_pubkey_hex fsph) {
    custom_file_server_pubkey_hex = fsph.pubkey_hex;
    log::debug(cat, "Network config custom file server pubkey set to {}", fsph.pubkey_hex);
}

void Config::handle_config_opt(opt::file_server_max_file_size fsmfs) {
    custom_file_server_max_file_size = fsmfs.max_file_size;
    log::debug(
            cat, "Network config custom file server max file size set to {}", fsmfs.max_file_size);
}

void Config::handle_config_opt(opt::file_server_use_stream_encryption fsuse) {
    file_server_use_stream_encryption = fsuse.use_stream_encryption;
    log::debug(
            cat,
            "Network config file use stream encryption set to {}",
            fsuse.use_stream_encryption);
}

// MARK: General options

void Config::handle_config_opt(opt::increase_no_file_limit) {
    increase_no_file_limit = true;
    log::debug(cat, "Network config will attempt to increase the NOFILE limit");
}

void Config::handle_config_opt(opt::path_length pl) {
    path_length = pl.length;
    log::debug(cat, "Network config path length set to {}", pl.length);
}

void Config::handle_config_opt(opt::disable_subnet_diversity) {
    enforce_subnet_diversity = false;
    log::debug(cat, "Network config disabled subnet diversity");
}

void Config::handle_config_opt(opt::redirect_retry_count rrc) {
    redirect_retry_count = rrc.count;
    log::debug(cat, "Network config redirect retry count set to {}", rrc.count);
}

void Config::handle_config_opt(opt::retry_delay rd) {
    retry_delay = std::move(rd);
    log::debug(
            cat,
            "Network config retry delay set to min: {}ms, max: {}ms",
            retry_delay.base_delay.count(),
            retry_delay.max_delay.count());
}

void Config::handle_config_opt(opt::num_nodes_to_check_for_network_offset nncno) {
    num_nodes_to_check_for_network_offset = nncno.count;
    log::debug(
            cat,
            "Network config number of nodes to be used for calculating median network offset set "
            "to {}",
            nncno.count);
}

void Config::handle_config_opt(opt::min_resume_clock_resync_interval mrcri) {
    min_resume_clock_resync_interval = mrcri.duration;
    log::debug(
            cat,
            "Network config minimum interval between clock resyncs after resuming set to {}min",
            mrcri.duration.count());
}

// MARK: Snode Pool Options

void Config::handle_config_opt(opt::cache_directory dir) {
    cache_directory = std::move(dir.path);

    if (cache_directory)
        log::debug(cat, "Network config using cache dir {}", cache_directory->string());
}

void Config::handle_config_opt(opt::fallback_snode_pool_path fspp) {
    fallback_snode_pool_path = std::move(fspp.path);

    if (fallback_snode_pool_path)
        log::debug(
                cat,
                "Network config using fallback snode pool path {}",
                fallback_snode_pool_path->string());
}

void Config::handle_config_opt(opt::cache_expiration ce) {
    cache_expiration = ce.duration;
    log::debug(
            cat,
            "Network config snode pool cache expiration set to {} minutes",
            ce.duration.count());
}

void Config::handle_config_opt(opt::cache_min_lifetime mcl) {
    cache_min_lifetime = mcl.duration;
    log::debug(
            cat,
            "Network config snode pool minimum cache lifetime set to {}ms",
            mcl.duration.count());
}

void Config::handle_config_opt(opt::cache_min_size mcs) {
    cache_min_size = mcs.size;
    log::debug(cat, "Network config min snode pool cache size set to {}", mcs.size);
}

void Config::handle_config_opt(opt::cache_min_swarm_size mss) {
    cache_min_swarm_size = mss.size;
    log::debug(cat, "Network config min swarm size set to {}", mss.size);
}

void Config::handle_config_opt(opt::cache_num_nodes_to_use_for_refresh nnr) {
    cache_num_nodes_to_use_for_refresh = nnr.count;
    log::debug(
            cat,
            "Network config number of cached nodes to be used for refreshing the snode pool cache "
            "set to {}{}",
            nnr.count,
            (nnr.count > 0 ? "" : ", refreshes will always use a random seed node"));
}

void Config::handle_config_opt(opt::cache_min_num_refresh_presence_to_include_node mnrp) {
    cache_min_num_refresh_presence_to_include_node = mnrp.count;
    log::debug(
            cat,
            "Network config minimum number of refresh responses a node needs to be present in to "
            "be included in the snode pool cache set to {}{}",
            mnrp.count,
            (mnrp.count > 1 ? "" : ", nodes will always be included"));
}

void Config::handle_config_opt(opt::cache_node_strike_threshold nst) {
    cache_node_strike_threshold = nst.count;
    log::debug(cat, "Network config snode pool node strike threshold set to {}", nst.count);
}

// MARK: Quic Transport Options

void Config::handle_config_opt(opt::quic_handshake_timeout qht) {
    quic_handshake_timeout = qht.duration;
    log::debug(cat, "Network config quic handshake timeout set to {}ms", qht.duration.count());
}

void Config::handle_config_opt(opt::quic_keep_alive qka) {
    quic_keep_alive = qka.duration;
    log::debug(cat, "Network config quic keep alive set to {}s", qka.duration.count());
}

void Config::handle_config_opt(opt::quic_max_udp_payload qmup) {
    // libquic rejects anything smaller, but only once the endpoint is built: catch it here, where
    // it is still a configuration error rather than a failure deep inside network setup.
    if (qmup.size < 1200)
        throw std::invalid_argument{
                "quic_max_udp_payload must be at least 1200, got {}"_format(qmup.size)};
    quic_max_udp_payload = qmup.size;
    log::debug(cat, "Network config max QUIC UDP payload set to {} bytes", qmup.size);
}

void Config::handle_config_opt(opt::quic_disable_mtu_discovery) {
    handle_config_opt(opt::quic_max_udp_payload{1200});
}

// MARK: Onion Request Router Options

void Config::handle_config_opt(opt::onionreq_path_strike_threshold pst) {
    onionreq_path_strike_threshold = pst.count;
    log::debug(cat, "Network config onion request path strike threshold set to {}", pst.count);
}

void Config::handle_config_opt(opt::onionreq_path_build_retry_limit pbrl) {
    onionreq_path_build_retry_limit = pbrl.count;
    log::debug(cat, "Network config onion request path build retry limit set to {}", pbrl.count);
}

void Config::handle_config_opt(opt::onionreq_min_path_count mpc) {
    onionreq_min_path_counts.emplace(mpc.category, mpc.min_count);

    log::debug(
            cat,
            "Network config min {} onion request path count set to {}",
            to_string(mpc.category),
            mpc.min_count);
}

void Config::handle_config_opt(opt::onionreq_single_path_mode) {
    onionreq_single_path_mode = true;
    log::debug(cat, "Network config onion requests set to single path mode");
}

void Config::handle_config_opt(opt::onionreq_disable_pre_build_paths) {
    onionreq_disable_pre_build_paths = true;
    log::debug(cat, "Network config disabled pre-building onion request paths");
}

void Config::handle_config_opt(opt::onionreq_path_rotation_frequency prf) {
    onionreq_path_rotation_frequency = prf.duration;
    log::debug(
            cat,
            "Network config onion request path rotation frequency set to {}min",
            prf.duration.count());
}

void Config::handle_config_opt(opt::onionreq_edge_node_cache_duration encd) {
    onionreq_edge_node_cache_duration = encd.duration;
    log::debug(
            cat,
            "Network config onion request edge node cache duration set to {}d",
            encd.duration.count());
}

}  // namespace session::network::config
