#pragma once

#include <filesystem>
#include <type_traits>
#include <variant>

#include "session/network/service_node.hpp"
#include "session/network/session_network_types.hpp"
#include "session/types.hpp"

namespace session::network {
class Endpoint;
class Stream;

namespace opt {
    namespace fs = std::filesystem;
    using namespace std::chrono_literals;

    namespace {
        inline std::vector<unsigned char> from_hex(std::string_view s) {
            std::vector<unsigned char> out;
            out.reserve(s.size() / 2);
            oxenc::from_hex(s.begin(), s.end(), std::back_inserter(out));

            return out;
        }
    }  // namespace

    /// Can be used to override the default (mainnet) netid that the network will populate it's
    /// internal caches from, 'devnet' allows for specifying a custom server.
    struct netid {
        enum class Target {
            mainnet,
            testnet,
            devnet,
        };

        Target target;
        std::vector<service_node> seed_nodes;

      private:
        netid(Target t, std::vector<service_node> seed_nodes = {}) :
                target{t}, seed_nodes{std::move(seed_nodes)} {}

      public:
        netid() = delete;

        static netid mainnet() {
            auto seed_nodes = {
                    service_node{
                            ed25519_pubkey::from_hex("1f000f09a7b07828dcb72af7cd16857050c10c02bd58a"
                                                     "fb0e38111fb6cda1fef"),
                            oxen::quic::ipv4{"95.216.33.113"},
                            uint16_t{22100},
                            uint16_t{20200},
                            {2, 11, 0},
                            swarm::INVALID_SWARM_ID},
                    service_node{
                            ed25519_pubkey::from_hex("1f101f0acee4db6f31aaa8b4df134e85ca8a4878efaef"
                                                     "7f971e88ab144c1a7ce"),
                            oxen::quic::ipv4{"37.27.236.229"},
                            uint16_t{22101},
                            uint16_t{20201},
                            {2, 11, 0},
                            swarm::INVALID_SWARM_ID},
                    service_node{
                            ed25519_pubkey::from_hex("1f202f00f4d2d4acc01e20773999a291cf3e3136c3254"
                                                     "74d159814e06199919f"),
                            oxen::quic::ipv4{"172.96.140.124"},
                            uint16_t{22102},
                            uint16_t{20202},
                            {2, 11, 0},
                            swarm::INVALID_SWARM_ID},
                    service_node{
                            ed25519_pubkey::from_hex("1f303f1d7523c46fa5398826740d13282d26b5de90fba"
                                                     "e5749442f66afb6d78b"),
                            oxen::quic::ipv4{"208.73.207.54"},
                            uint16_t{22103},
                            uint16_t{20203},
                            {2, 11, 0},
                            swarm::INVALID_SWARM_ID},
                    service_node{
                            ed25519_pubkey::from_hex("1f604f1c858a121a681d8f9b470ef72e6946ee1b9c5ad"
                                                     "15a35e16b50c28db7b0"),
                            oxen::quic::ipv4{"104.194.8.115"},
                            uint16_t{22104},
                            uint16_t{20204},
                            {2, 11, 0},
                            swarm::INVALID_SWARM_ID},
            };

            return netid(Target::mainnet, seed_nodes);
        }

        static netid testnet() {
            auto seed_nodes = {
                    // service_node{
                    //         ed25519_pubkey::from_hex("decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9"),
                    //         oxen::quic::ipv4{"144.76.164.202"},
                    //         uint16_t{35500},
                    //         uint16_t{35400},
                    //         {2, 10, 0},
                    //         swarm::INVALID_SWARM_ID},  // This is the original one

                    service_node{
                            ed25519_pubkey::from_hex("decaf20025ca6389d8225bda6a32d7fc4ee5176d21e3b"
                                                     "2e9e08c3505a48a811a"),
                            oxen::quic::ipv4{"23.88.6.250"},
                            uint16_t{35520},
                            uint16_t{35420},
                            {2, 10, 0},
                            swarm::INVALID_SWARM_ID},  // session router one
            };

            return netid(Target::testnet, seed_nodes);
        }

        static netid devnet(std::vector<service_node> seed_nodes) {
            if (seed_nodes.empty())
                throw std::invalid_argument(
                        "devnet must be configured with at least one seed node.");

            return netid(Target::devnet, std::move(seed_nodes));
        }

        static std::string to_string(Target target) {
            switch (target) {
                case Target::mainnet: return "session-router";
                case Target::testnet: return "testnet";
                case Target::devnet: return "devnet";
            }

            return "session-router";  // Shouldn't happen
        }
    };

    /// Can be used to override the default (onion_requests) routing method for requests.
    struct router {
        enum class Type {
            onion_requests,
            session_router,
            direct,
        };

        Type type;

      private:
        router(Type t) : type{t} {}

      public:
        router() = delete;

        static router onion_requests() { return router(Type::onion_requests); }
        static router session_router() { return router(Type::session_router); }
        static router direct() { return router(Type::direct); }
    };

    /// Can be used to override the default (quic_onionreq) transport layer used to send requests.
    struct transport {
        enum class Type {
            quic,
        };
        // TODO: Add in "HTTP" as an option

        Type type;

      private:
        transport(Type t) : type{t} {}

      public:
        transport() = delete;

        static transport quic() { return transport(Type::quic); }
    };

    /// Can be used to override the default file server scheme.
    struct file_server_scheme {
        std::string scheme;

        file_server_scheme(std::string scheme) : scheme{scheme} {}
    };

    /// Can be used to override the default file server host.
    struct file_server_host {
        std::string host;

        file_server_host(std::string host) : host{host} {}
    };

    /// Can be used to override the default file server port.
    struct file_server_port {
        uint16_t port;

        file_server_port(uint16_t port) : port{port} {}
    };

    /// Can be used to override the default file server pubkey.
    struct file_server_pubkey_hex {
        std::string pubkey_hex;

        file_server_pubkey_hex(std::string pubkey_hex) : pubkey_hex{pubkey_hex} {}
    };

    /// Can be used to override the default file server max file size.
    ///
    /// Note: This value is limited by the configuration on the file server, changing it will only
    /// result in checks that prevent requests we know will fail from being made.
    struct file_server_max_file_size {
        uint64_t max_file_size;

        file_server_max_file_size(uint16_t max_file_size) : max_file_size{max_file_size} {}
    };

    /// Can be used to override the default (false) flag indicating whether files uploaded to the
    /// file server should use XChaCha20-stream based encryption.
    struct file_server_use_stream_encryption {
        bool use_stream_encryption;

        file_server_use_stream_encryption(bool use_stream_encryption) :
                use_stream_encryption{use_stream_encryption} {}
    };

    /// Can be used to attempt to increase the NOFILE limit (can cause issues with automated tests).
    struct increase_no_file_limit {};

    /// Can be used to override the default (3) path length used when building onion request or
    /// session router paths.
    struct path_length {
        uint8_t length;

        path_length(uint8_t length) : length{length} {}
    };

    /// Can be used to prevent the code from excluding nodes within the same `/24` subnet from being
    /// included in the same path when building onion request or session router paths.
    struct disable_subnet_diversity {};

    /// Can be used to override the default (1) number of request retries that will occur when
    /// receiving a 421 error.
    struct redirect_retry_count {
        uint8_t count;

        redirect_retry_count(uint8_t count) : count{count} {}
    };

    struct retry_delay {
        std::chrono::milliseconds base_delay;
        std::chrono::milliseconds max_delay;

        retry_delay(std::chrono::milliseconds base_delay, std::chrono::milliseconds max_delay) :
                base_delay{base_delay}, max_delay{max_delay} {}

        /// API: retry_delay/exponential
        ///
        /// A function which generates an exponential delay to wait before retrying a request/action
        /// based on the provided failure count.
        ///
        /// Inputs:
        /// - 'failure_count' - [in] the number of times the request has already failed.
        inline std::chrono::milliseconds exponential(int failure_count) {
            if (failure_count <= 0)
                return base_delay;

            auto delay = base_delay * std::pow(2.0, failure_count - 1);
            auto final_delay = std::chrono::floor<std::chrono::milliseconds>(delay);

            return std::min(final_delay, max_delay);
        }
    };

    /// Can be used to override the default (3) number of nodes to fetch from when determining the
    /// median network offset from the local device time.
    struct num_nodes_to_check_for_network_offset {
        uint8_t count;

        num_nodes_to_check_for_network_offset(uint8_t count) : count{count} {}
    };

    /// Can be used to override the default (10min) minimum duration that needs to pass before a
    /// clock resync after resuming the network.
    struct min_resume_clock_resync_interval {
        std::chrono::minutes duration;

        min_resume_clock_resync_interval(std::chrono::minutes duration) : duration{duration} {}
    };

    // MARK: Snode Pool Options

    /// Can be used to override the default ('.') path the network uses to cache files (eg. snode
    /// pool and session router bootstrap).
    struct cache_directory {
        fs::path path;
        cache_directory(fs::path p) : path{p} {}
    };

    /// Can be used to specify a path to a snode pool cache file that should be used if we are
    /// unable to bootstrap.
    struct fallback_snode_pool_path {
        fs::path path;
        fallback_snode_pool_path(fs::path p) : path{p} {}
    };

    /// Can be used to override the default (2h) duration that the snode cache can be used for
    /// before it needs to be refreshed.
    struct cache_expiration {
        std::chrono::minutes duration;
        cache_expiration(std::chrono::minutes duration) : duration{duration} {}
    };

    /// Can be used to override the default (2s) minimum duration that the snode cache should live
    /// for, if a refresh is triggered within this period it will be delayed until the minimum
    /// duration has passed to prevent excessive looping.
    struct cache_min_lifetime {
        std::chrono::milliseconds duration;
        cache_min_lifetime(std::chrono::milliseconds duration) : duration{duration} {}
    };

    /// Can be used to override the default (12) minimum number of unused nodes before we trigger a
    /// snode cache refresh.
    ///
    /// Note: If the cache size is somehow smaller than this value (eg. Testnet is having issues)
    /// then the minimum size will be the full cache size (minus enough to build a path) or at least
    /// the size of a single path.
    struct cache_min_size {
        size_t size;
        cache_min_size(size_t size) : size{size} {}
    };

    /// Can be used to override the default (3) minimum number of nodes to return in a swarm, if
    /// enough nodes are excluded due to their strike count when retrieving a swarm then nodes which
    /// are over the threshold will be included until this minimum count is met.
    struct cache_min_swarm_size {
        size_t size;
        cache_min_swarm_size(size_t size) : size{size} {}
    };

    /// Can be used to override the default (3) number of cached nodes used to refresh the cache for
    /// any subsequent refreshes after populating from a seed node.
    ///
    /// Note: Providing a value of `0` will result in the cache _always_ being refreshed using a
    /// seed node.
    struct cache_num_nodes_to_use_for_refresh {
        uint8_t count;
        cache_num_nodes_to_use_for_refresh(uint8_t count) : count{count} {}
    };

    /// Can be used to override the default (2) number of refresh requests a node must be present in
    /// to be included in the cache.
    ///
    /// Note: This does not apply when refreshing from seed nodes. A value of `0` is equivalet to a
    /// value of `1`.
    struct cache_min_num_refresh_presence_to_include_node {
        uint8_t count;
        cache_min_num_refresh_presence_to_include_node(uint8_t count) : count{count} {}
    };

    /// Can be used to override the default (3) number of times a specific node in a path can
    /// receive an error before it is removed from the path and replaced by a new node (or the path
    /// is rebuilt if it happens to be the edge node).
    struct cache_node_strike_threshold {
        uint16_t count;
        cache_node_strike_threshold(uint16_t count) : count{count} {}
    };

    // MARK: Quic Transport Options

    /// Can be used to override the default (10s) handshake timeout duration for Quic connections.
    struct quic_handshake_timeout {
        std::chrono::milliseconds duration;
        quic_handshake_timeout(std::chrono::milliseconds duration) : duration{duration} {}
    };

    /// Can be used to override the default (0ms) keep alive duration for Quic connections.
    struct quic_keep_alive {
        std::chrono::seconds duration;
        quic_keep_alive(std::chrono::seconds duration) : duration{duration} {}
    };

    /// Caps the QUIC UDP payload size.  Path MTU discovery still probes upward from 1200 but never
    /// past this value.  Must be at least 1200, the QUIC minimum.
    struct quic_max_udp_payload {
        size_t size;
        explicit quic_max_udp_payload(size_t s) : size{s} {}
    };

    /// Equivalent to `quic_max_udp_payload{1200}`, which leaves path MTU discovery nothing to
    /// probe.
    struct quic_disable_mtu_discovery {};

    // MARK: Onion Request Router Options

    /// Can be used to override the default (3) number of times a path can receive an error before
    /// it is dropped and replaced by a new path.
    struct onionreq_path_strike_threshold {
        uint16_t count;

        onionreq_path_strike_threshold(uint16_t count) : count{count} {}
    };

    /// Can be used to override the default (3) number of times a path can receive an error before
    /// it is dropped and replaced by a new path.
    struct onionreq_path_build_retry_limit {
        uint16_t count;

        onionreq_path_build_retry_limit(uint16_t count) : count{count} {}
    };

    /// Can be used to override the default (2) minimum number of paths that are maintained for each
    /// request category when using onion requests. If `onionreq_single_path_mode` is provided this
    /// will be ignored.
    struct onionreq_min_path_count {
        PathCategory category;
        uint8_t min_count;

        onionreq_min_path_count(PathCategory category, uint8_t min_count) :
                category{category}, min_count{min_count} {}
    };

    /// Can be used to force the onion request router to only use a single path regardless of what
    /// category the requests sent have. When this option is provided `onionreq_min_path_count` will
    /// be ignored.
    struct onionreq_single_path_mode {};

    /// Can be used to prevent the network instance from building onion request paths when
    /// initialised, when this option is provided paths will be built when the first request it
    /// made.
    struct onionreq_disable_pre_build_paths {};

    /// Can be used to override the default (10min) frequency that onion request paths are rotated.
    struct onionreq_path_rotation_frequency {
        std::chrono::minutes duration;
        onionreq_path_rotation_frequency(std::chrono::minutes duration) : duration{duration} {}
    };

    /// Can be used to override the default (10d) duration that edge nodes are reused for.
    struct onionreq_edge_node_cache_duration {
        std::chrono::days duration;
        onionreq_edge_node_cache_duration(std::chrono::days duration) : duration{duration} {}
    };

    // A variant over every option type declared above.
    using any = std::variant<
            netid,
            router,
            transport,

            // File server options
            file_server_scheme,
            file_server_host,
            file_server_port,
            file_server_pubkey_hex,
            file_server_max_file_size,
            file_server_use_stream_encryption,

            // General options
            increase_no_file_limit,
            path_length,
            disable_subnet_diversity,
            redirect_retry_count,
            retry_delay,
            num_nodes_to_check_for_network_offset,
            min_resume_clock_resync_interval,

            // Snode pool options
            cache_directory,
            fallback_snode_pool_path,
            cache_expiration,
            cache_min_lifetime,
            cache_min_size,
            cache_min_swarm_size,
            cache_num_nodes_to_use_for_refresh,
            cache_min_num_refresh_presence_to_include_node,
            cache_node_strike_threshold,

            // Quic transport options
            quic_handshake_timeout,
            quic_keep_alive,
            quic_max_udp_payload,
            quic_disable_mtu_discovery,

            // Onion request router options
            onionreq_path_strike_threshold,
            onionreq_min_path_count,
            onionreq_single_path_mode,
            onionreq_disable_pre_build_paths,
            onionreq_path_build_retry_limit,
            onionreq_path_rotation_frequency,
            onionreq_edge_node_cache_duration>;

    namespace detail {
        template <typename T, typename Variant>
        inline constexpr bool is_alternative = false;
        template <typename T, typename... Ts>
        inline constexpr bool is_alternative<T, std::variant<Ts...>> =
                (std::is_same_v<T, Ts> || ...);
    }  // namespace detail

    // True if T is exactly one of the option types making up `any`.
    template <typename T>
    inline constexpr bool is_option = detail::is_alternative<T, any>;

}  //  namespace opt
}  // namespace session::network
