#include "session_network_internal.hpp"

#include <numeric>
#include <oxen/quic/address.hpp>
#include <string>
#include <variant>
#include <vector>

#include "session/network/service_node.hpp"

namespace session::network::detail {

session_request_params* convert_cpp_request_to_c(const session::network::Request& req) {
    size_t total_size = sizeof(session_request_params);
    size_t string_data_size = 0;

    // Calculate the expected size
    auto add_string_size = [&](const std::string& s) {
        if (!s.empty())
            string_data_size += s.length() + 1;
    };

    add_string_size(req.request_id);
    add_string_size(req.endpoint);

    std::visit(
            [&]<typename T>(const T& arg) {
                if constexpr (std::is_same_v<T, service_node>) {
                    total_size += sizeof(network_service_node);
                } else if constexpr (std::is_same_v<T, ServerDestination>) {
                    total_size += sizeof(network_server_destination);
                    add_string_size(arg.protocol);
                    add_string_size(arg.host);
                    add_string_size(arg.method);
                    add_string_size(arg.x25519_pubkey.hex());

                    if (arg.headers) {
                        // key pointers + value pointers + NULL terminator
                        string_data_size += (arg.headers->size() * 2 + 1) * sizeof(const char*);
                        add_string_size(arg.x25519_pubkey.hex());

                        for (const auto& [k, v] : *arg.headers) {
                            add_string_size(k);
                            add_string_size(v);
                        }
                    }
                } else if constexpr (std::is_same_v<T, oxen::quic::RemoteAddress>) {
                    total_size += sizeof(session_remote_address);
                }
            },
            req.destination);

    size_t body_size = req.body ? req.body->size() : 0;
    total_size += body_size;

    // Allocate the data and assign values
    unsigned char* buffer = static_cast<unsigned char*>(std::malloc(total_size + string_data_size));
    if (!buffer)
        return nullptr;

    auto* c_params = reinterpret_cast<session_request_params*>(buffer);
    unsigned char* current_ptr = buffer + sizeof(session_request_params);

    auto copy_string = [&](const std::string& s) -> const char* {
        if (s.empty())
            return nullptr;
        char* dest = reinterpret_cast<char*>(current_ptr);
        std::memcpy(dest, s.c_str(), s.length() + 1);
        current_ptr += s.length() + 1;
        return dest;
    };

    new (c_params) session_request_params{};
    c_params->request_id = copy_string(req.request_id);
    c_params->endpoint = copy_string(req.endpoint);

    c_params->category = static_cast<SESSION_NETWORK_REQUEST_CATEGORY>(req.category);
    c_params->request_timeout_ms = req.request_timeout.count();
    c_params->overall_timeout_ms = (req.overall_timeout ? req.overall_timeout->count() : 0);

    if (body_size > 0) {
        std::memcpy(current_ptr, req.body->data(), body_size);
        c_params->body = current_ptr;
        c_params->body_size = body_size;
        current_ptr += body_size;
    }

    std::visit(
            [&]<typename T>(const T& arg) {
                if constexpr (std::is_same_v<T, service_node>) {
                    auto* c_snode = reinterpret_cast<network_service_node*>(current_ptr);
                    arg.into(*c_snode);
                    c_params->snode_dest = c_snode;
                    current_ptr += sizeof(network_service_node);
                } else if constexpr (std::is_same_v<T, ServerDestination>) {
                    auto* c_server_dest =
                            reinterpret_cast<network_server_destination*>(current_ptr);
                    new (c_server_dest) network_server_destination{};
                    c_params->server_dest = c_server_dest;
                    current_ptr += sizeof(network_server_destination);

                    c_server_dest->protocol = copy_string(arg.protocol);
                    c_server_dest->host = copy_string(arg.host);
                    c_server_dest->method = copy_string(arg.method);
                    c_server_dest->x25519_pubkey_hex = copy_string(arg.x25519_pubkey.hex());
                    c_server_dest->port = arg.port.value_or(0);

                    if (arg.headers) {
                        auto** c_headers_array = reinterpret_cast<const char**>(current_ptr);
                        c_server_dest->headers_kv_pairs = c_headers_array;
                        c_server_dest->headers_kv_pairs_len = arg.headers->size() * 2;
                        current_ptr += (arg.headers->size() * 2 + 1) * sizeof(const char*);

                        int i = 0;
                        for (const auto& [k, v] : *arg.headers) {
                            c_headers_array[i++] = copy_string(k);
                            c_headers_array[i++] = copy_string(v);
                        }
                        c_headers_array[i] = nullptr;  // Null terminator for safety
                    }
                } else if constexpr (std::is_same_v<T, oxen::quic::RemoteAddress>) {
                    auto* c_remote = reinterpret_cast<session_remote_address*>(current_ptr);
                    new (c_remote) session_remote_address{};
                    c_params->remote_addr_dest = c_remote;
                    current_ptr += sizeof(session_remote_address);

                    auto ed25519_pubkey_hex = oxenc::to_hex(arg.view_remote_key());
                    oxen::quic::ipv4 ip = arg.to_ipv4();

                    strncpy(c_remote->ed25519_pubkey_hex, ed25519_pubkey_hex.c_str(), 64);
                    c_remote->ed25519_pubkey_hex[64] = '\0';  // Ensure null termination
                    c_remote->ip[0] = (ip.addr >> 24) & 0xFF;
                    c_remote->ip[1] = (ip.addr >> 16) & 0xFF;
                    c_remote->ip[2] = (ip.addr >> 8) & 0xFF;
                    c_remote->ip[3] = ip.addr & 0xFF;
                    c_remote->port = arg.port();
                }
            },
            req.destination);

    std::visit(
            [&]<typename T>(const T& arg) {
                if constexpr (std::is_same_v<T, UploadInfo>) {
                    if (arg.file_name)
                        c_params->upload_file_name = copy_string(*arg.file_name);
                }
            },
            req.details);

    return c_params;
}

}  // namespace session::network::detail