#include "session/network/service_node.hpp"

#include <fmt/ranges.h>

#include <oxen/log/format.hpp>
#include <oxen/quic.hpp>
#include <oxen/quic/utils.hpp>

using namespace oxen;
using namespace oxen::log::literals;

namespace session::network {

std::string service_node::to_string() const {
    return remote_pubkey.hex();
}

std::string service_node::to_https_string() const {
    return "{}:{}"_format(host(), https_port);
}

std::string service_node::to_omq_string() const {
    return "{}:{}"_format(host(), omq_port);
}

service_node service_node::from(const network_service_node& node) {
    return {ed25519_pubkey::from_hex(node.ed25519_pubkey_hex),
            oxen::quic::ipv4{std::span<const uint8_t, 4>(node.ip, 4)},
            node.https_port,
            node.omq_port,
            {node.version[0], node.version[1], node.version[2]},
            node.swarm_id,
            node.requested_unlock_height};
}

void service_node::into(network_service_node& n) const {
    auto ed25519_pubkey_hex = remote_pubkey.hex();
    strncpy(n.ed25519_pubkey_hex, ed25519_pubkey_hex.c_str(), 64);
    n.ed25519_pubkey_hex[64] = '\0';  // Ensure null termination
    n.ip[0] = (ip.addr >> 24) & 0xFF;
    n.ip[1] = (ip.addr >> 16) & 0xFF;
    n.ip[2] = (ip.addr >> 8) & 0xFF;
    n.ip[3] = ip.addr & 0xFF;
    n.https_port = https_port;
    n.omq_port = omq_port;
    std::memcpy(n.version, storage_server_version.data(), sizeof(storage_server_version));
    n.swarm_id = swarm_id;
    n.requested_unlock_height = requested_unlock_height;
}

service_node service_node::from_json(nlohmann::json json) {
    auto pk_ed = json["pubkey_ed25519"].get<std::string_view>();
    if (pk_ed.size() != 64 || !oxenc::is_hex(pk_ed))
        throw std::invalid_argument{
                "Invalid service node json: pubkey_ed25519 is not a valid, hex pubkey"};

    std::vector<std::byte> pubkey;
    pubkey.reserve(32);
    oxenc::from_hex(pk_ed.begin(), pk_ed.end(), std::back_inserter(pubkey));

    // When parsing a node from JSON it'll generally be from the 'get_swarm` endpoint or a 421
    // error neither of which contain the `storage_server_version` - luckily we don't need the
    // version for these two cases so can just default it to `0.0.0`
    std::array<uint16_t, 3> storage_server_version = {0, 0, 0};
    if (json.contains("storage_server_version")) {
        if (json["storage_server_version"].is_array()) {
            if (json["storage_server_version"].size() > 0) {
                // Convert the version to a string and parse it back into a version code to
                // ensure the version formats remain consistent throughout
                auto json_version = json["storage_server_version"].get<std::vector<int>>();

                for (size_t i = 0; i < 3; ++i)
                    storage_server_version[i] =
                            (i < json_version.size() ? static_cast<uint16_t>(json_version[i]) : 0);
            }
        } else {
            auto json_version = json["storage_server_version"].get<std::string>();
            auto split_version = session::split(json_version, ".");

            for (size_t i = 0; i < 3 && i < split_version.size(); ++i) {
                int value;

                if (!quic::parse_int(split_version[i], value))
                    throw std::invalid_argument{"Invalid version"};

                storage_server_version[i] = static_cast<uint16_t>(value);
            }
        }
    }

    std::string ip;
    if (json.contains("public_ip"))
        ip = json["public_ip"].get<std::string>();
    else
        ip = json["ip"].get<std::string>();

    if (ip == "0.0.0.0")
        throw std::runtime_error{"Invalid IP address"};

    uint16_t https_port;
    if (json.contains("storage_https_port"))
        https_port = json["storage_https_port"].get<uint16_t>();
    else if (json.contains("storage_port"))
        https_port = json["storage_port"].get<uint16_t>();
    else
        https_port = json["port_https"].get<uint16_t>();

    uint16_t omq_port;
    if (json.contains("storage_lmq_port"))
        omq_port = json["storage_lmq_port"].get<uint16_t>();
    else
        omq_port = json["port_omq"].get<uint16_t>();

    if (omq_port == 0)
        throw std::runtime_error{"Invalid omq port"};

    swarm_id_t swarm_id = INVALID_SWARM_ID;
    if (json.contains("swarm_id"))
        swarm_id = json["swarm_id"].get<swarm_id_t>();
    else if (json.contains("swarm"))
        if (!quic::parse_int(json["swarm"].get<std::string>(), swarm_id, 16))
            throw std::runtime_error{"Invalid swarm id"};

    // Swarm responses (the `get_swarm` endpoint and 421 bodies) omit this entirely, and an oxend
    // node dump omits it for a node with no unlock requested; neither case is distinguishable here
    auto requested_unlock_height = json.value<int64_t>("requested_unlock_height", -1);

    return {ed25519_pubkey::from_bytes(pubkey),
            quic::ipv4{ip},
            https_port,
            omq_port,
            storage_server_version,
            swarm_id,
            requested_unlock_height};
}

service_node service_node::from_disk(std::string_view str) {
    // Format is "{ed_pubkey}|{ip}|{https_port}|{omq_port}|{version}|{swarm_id}"
    auto parts = split(str, "|");
    if (parts.size() != 6)
        throw std::invalid_argument("Invalid service node serialisation: {}"_format(str));
    if (parts[0].size() != 64 || !oxenc::is_hex(parts[0]))
        throw std::invalid_argument{
                "Invalid service node serialisation: pubkey is not hex or has wrong size"};

    uint16_t https_port, omq_port;
    if (!quic::parse_int(parts[2], https_port))
        throw std::invalid_argument{"Invalid service node serialization: invalid https_port"};
    if (!quic::parse_int(parts[3], omq_port))
        throw std::invalid_argument{"Invalid service node serialization: invalid omq_port"};

    auto version_parts = split(parts[4], ".");
    std::array<uint16_t, 3> version_array{0, 0, 0};
    for (size_t i = 0; i < std::min(size_t{3}, version_parts.size()); ++i) {
        uint16_t v;

        if (quic::parse_int(version_parts[i], v))
            version_array[i] = v;
    }

    if (version_array == std::array<uint16_t, 3>{0, 0, 0})
        throw std::invalid_argument{"Invalid service node serialization: invalid version"};

    swarm_id_t swarm_id = INVALID_SWARM_ID;
    quic::parse_int(parts[5], swarm_id);

    return {ed25519_pubkey::from_hex(parts[0]),
            quic::ipv4{std::string{parts[1]}},
            https_port,
            omq_port,
            version_array,
            swarm_id};
}

std::pair<std::vector<service_node>, int> service_node::process_snode_cache_bin(
        std::vector<std::byte> cache_bin) {
    constexpr size_t SNODE_SIZE = 51;
    constexpr size_t PK_SIZE = 32;
    constexpr size_t SWARM_ID_SIZE = 8;
    constexpr size_t IP_SIZE = 4;
    constexpr size_t HTTPS_PORT_SIZE = 2;
    constexpr size_t OMQ_PORT_SIZE = 2;
    constexpr size_t VERSION_SIZE = 3;

    // Sanity check field sizes
    static_assert(
            PK_SIZE + SWARM_ID_SIZE + IP_SIZE + HTTPS_PORT_SIZE + OMQ_PORT_SIZE + VERSION_SIZE ==
                    SNODE_SIZE,
            "Field sizes do not sum to snode size");

    if (cache_bin.size() % SNODE_SIZE != 0)
        throw std::runtime_error{
                "Snode cache size is not a multiple of snode size ({})."_format(SNODE_SIZE)};

    // Parse the binary
    int failed_nodes = 0;
    std::vector<service_node> nodes;
    nodes.reserve(cache_bin.size() / SNODE_SIZE);

    const std::byte* current_ptr = cache_bin.data();
    const std::byte* const end_ptr = cache_bin.data() + cache_bin.size();

    while (current_ptr < end_ptr) {
        const std::byte* note_ptr = current_ptr;

        try {
            // Pubkey
            std::vector<std::byte> pubkey;
            pubkey.assign(current_ptr, current_ptr + PK_SIZE);
            note_ptr += PK_SIZE;

            // Swarm ID
            uint64_t swarm_id_u64 = 0;
            for (int i = 0; i < SWARM_ID_SIZE; ++i)
                swarm_id_u64 = (swarm_id_u64 << 8) |
                               static_cast<uint64_t>(static_cast<unsigned char>(note_ptr[i]));

            swarm_id_t swarm_id = static_cast<swarm_id_t>(swarm_id_u64);
            note_ptr += SWARM_ID_SIZE;

            // Public IP
            std::span<const uint8_t, IP_SIZE> ip_bytes_span(
                    reinterpret_cast<const uint8_t*>(note_ptr), IP_SIZE);
            quic::ipv4 ip(ip_bytes_span);
            note_ptr += IP_SIZE;

            // IP can be 0 (ie. node is not in a valid state for use yet)
            if (ip.addr == 0)
                throw std::runtime_error{"Invalid IP"};

            // HTTPS port
            uint16_t https_port =
                    (static_cast<uint16_t>(static_cast<unsigned char>(note_ptr[0])) << 8) |
                    (static_cast<uint16_t>(static_cast<unsigned char>(note_ptr[1])));
            note_ptr += HTTPS_PORT_SIZE;

            // QUIC port
            uint16_t quic_port =
                    (static_cast<uint16_t>(static_cast<unsigned char>(note_ptr[0])) << 8) |
                    (static_cast<uint16_t>(static_cast<unsigned char>(note_ptr[1])));
            note_ptr += OMQ_PORT_SIZE;

            // quic_port can be 0 (ie. node is not in a valid state for use yet)
            if (quic_port == 0)
                throw std::runtime_error{"Invalid QUIC port"};

            // Storage server version
            std::array<uint16_t, 3> version_array{0, 0, 0};
            for (size_t i = 0; i < VERSION_SIZE; ++i)
                version_array[i] = static_cast<uint16_t>(static_cast<unsigned char>(note_ptr[i]));
            note_ptr += VERSION_SIZE;

            nodes.emplace_back(
                    ed25519_pubkey::from_bytes(std::move(pubkey)),
                    ip,
                    https_port,
                    quic_port,
                    std::move(version_array),
                    swarm_id);
        } catch (...) {
            failed_nodes++;
        }

        // Move the ptr to the start of the next node
        current_ptr += SNODE_SIZE;
    }

    return {nodes, failed_nodes};
}

}  // namespace session::network
