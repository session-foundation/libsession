#pragma once

#include <fmt/ranges.h>
#include <oxenc/hex.h>

#include <nlohmann/json.hpp>
#include <oxen/quic.hpp>

#include "session/network/service_node.h"
#include "session/network/swarm.hpp"

namespace session::network {

using namespace session::network::swarm;

namespace service_node_disk_format {
    constexpr size_t PUBKEY_HEX = 64;    // 32 bytes * 2 hex chars
    constexpr size_t IP_MAX = 15;        // 255.255.255.255
    constexpr size_t PORT_MAX = 5;       // 65535
    constexpr size_t VERSION_MAX = 17;   // 65535.65535.65535
    constexpr size_t SWARM_ID_MAX = 20;  // uint64_t max value
    constexpr size_t FIELD_COUNT = 6;
    constexpr size_t SEPARATORS = FIELD_COUNT - 1;  // 5 pipes
    constexpr size_t LINE_ENDING = 2;               // \r\n (just in case)

    constexpr size_t MAX_LINE_SIZE = PUBKEY_HEX + IP_MAX + (PORT_MAX * 2) + VERSION_MAX +
                                     SWARM_ID_MAX + SEPARATORS + LINE_ENDING;
}  // namespace service_node_disk_format

struct alignas(4) fork_versions {
    uint16_t hardfork;
    uint16_t softfork;

    auto operator<=>(const fork_versions& other) const = default;
};

struct service_node {
    ed25519_pubkey remote_pubkey;
    oxen::quic::ipv4 ip;
    uint16_t https_port;
    uint16_t omq_port;
    std::array<uint16_t, 3> storage_server_version;
    swarm_id_t swarm_id;

    // -1 when we don't know: most sources (the binary pool format, the on-disk cache, swarm
    // responses) carry no unlock information at all, and 0 would claim they said "not requested".
    int64_t requested_unlock_height = -1;

    oxen::quic::RemoteAddress to_https_address() const {
        return oxen::quic::RemoteAddress{remote_pubkey, ip, https_port};
    }

    oxen::quic::RemoteAddress to_omq_address() const {
        return oxen::quic::RemoteAddress{remote_pubkey, ip, omq_port};
    }

    std::span<const unsigned char> view_remote_key() const { return remote_pubkey; }
    std::string host() const { return ip.to_string(); }

    std::string to_string() const;
    std::string to_https_string() const;
    std::string to_omq_string() const;

    static service_node from(const network_service_node& node);
    void into(network_service_node& n) const;

    template <typename OutputIt>
    void to_disk(OutputIt out) const {
        fmt::format_to(
                out,
                "{}|{}|{}|{}|{}.{}.{}|{}\n",
                remote_pubkey.hex(),
                host(),
                https_port,
                omq_port,
                storage_server_version[0],
                storage_server_version[1],
                storage_server_version[2],
                swarm_id);
    }

    static service_node from_disk(std::string_view str);
    static std::pair<std::vector<service_node>, int> process_snode_cache_bin(
            std::vector<std::byte> cache_bin);

    static service_node from_json(nlohmann::json json);

    bool operator==(const service_node& other) const = default;
    auto operator<=>(const service_node& other) const = default;
};

inline std::ostream& operator<<(std::ostream& os, const service_node& sn) {
    return os << sn.to_string();
}

}  // namespace session::network
