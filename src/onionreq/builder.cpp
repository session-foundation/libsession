#include "session/onionreq/builder.hpp"

#include <fmt/format.h>
#include <fmt/ranges.h>
#include <nettle/gcm.h>
#include <oxenc/bt.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_generichash.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

#include <exception>
#include <limits>
#include <memory>
#include <nlohmann/json.hpp>
#include <oxen/log/format.hpp>
#include <oxen/quic/address.hpp>

#include "session/export.h"
#include "session/network/key_types.hpp"
#include "session/network/service_node.hpp"
#include "session/network/session_network_types.hpp"
#include "session/onionreq/builder.h"
#include "session/onionreq/hop_encryption.hpp"
#include "session/util.hpp"
#include "session/xed25519.hpp"

using namespace std::literals;
using namespace oxen::log::literals;
using namespace session::network;

namespace session::onionreq {

namespace detail {
    session::network::x25519_pubkey pubkey_for_destination(network_destination destination) {
        if (auto* dest = std::get_if<network::service_node>(&destination))
            return network::compute_x25519_pubkey(dest->remote_pubkey);

        if (auto* dest = std::get_if<ServerDestination>(&destination))
            return dest->x25519_pubkey;

        throw std::runtime_error{"Invalid destination."};
    }
}  // namespace detail

namespace {

    std::vector<unsigned char> encode_size(uint32_t s) {
        std::vector<unsigned char> result;
        result.resize(4);
        oxenc::write_host_as_little(s, result.data());
        return result;
    }
}  // namespace

EncryptType parse_enc_type(std::string_view enc_type) {
    if (enc_type == "xchacha20" || enc_type == "xchacha20-poly1305")
        return EncryptType::xchacha20;
    if (enc_type == "aes-gcm" || enc_type == "gcm")
        return EncryptType::aes_gcm;
    throw std::runtime_error{"Invalid encryption type " + std::string{enc_type}};
}

Builder Builder::make(
        const network_destination& destination,
        const std::string& endpoint,
        const std::vector<network::service_node>& nodes,
        const EncryptType enc_type_) {
    return Builder{destination, endpoint, nodes, enc_type_};
}

Builder::Builder(
        const network_destination& destination,
        const std::string& endpoint,
        const std::vector<network::service_node>& nodes,
        const EncryptType enc_type_) :
        endpoint_{endpoint},
        enc_type{enc_type_},
        is_v4_request{std::holds_alternative<network::ServerDestination>(destination)},
        destination_x25519_public_key_{detail::pubkey_for_destination(destination)} {
    set_destination(destination);
    for (auto& n : nodes)
        add_hop(n.remote_pubkey);
}

void Builder::add_hop(std::span<const unsigned char> remote_key) {
    auto ed25519_key = network::ed25519_pubkey::from_bytes(remote_key);
    hops_.push_back({ed25519_key, network::compute_x25519_pubkey(ed25519_key)});
}

void Builder::set_destination(network_destination destination) {
    ed25519_public_key_.reset();

    if (auto* dest = std::get_if<session::network::service_node>(&destination)) {
        is_v4_request = false;
        ed25519_public_key_.emplace(network::ed25519_pubkey::from_bytes(dest->remote_pubkey));
    } else if (auto* dest = std::get_if<ServerDestination>(&destination)) {
        is_v4_request = true;
        host_.emplace(dest->host);
        method_.emplace(dest->method);

        // Remove the '://' from the protocol if it was given
        size_t pos = dest->protocol.find("://");
        if (pos != std::string::npos)
            protocol_.emplace(dest->protocol.substr(0, pos));
        else
            protocol_.emplace(dest->protocol);

        if (dest->port)
            port_.emplace(*dest->port);

        if (dest->headers)
            headers_.emplace(*dest->headers);
    } else
        throw std::invalid_argument{"Invalid destination type."};
}

std::vector<unsigned char> Builder::generate_onion_blob(
        const std::optional<std::vector<unsigned char>>& plaintext_body) {
    return build(_generate_payload(plaintext_body));
}

std::vector<unsigned char> Builder::_generate_payload(
        std::optional<std::vector<unsigned char>> body) const {
    // If we don't have the data required for a server request, then assume it's targeting a
    // service node which has a different structure (`method` is the endpoint and the body is
    // `params`)
    if (!host_ || !protocol_ || !method_ || !destination_x25519_public_key_) {
        nlohmann::json params_json;

        if (body && !body->empty())
            params_json = nlohmann::json::parse(*body);
        else
            params_json = nlohmann::json::object();

        nlohmann::json wrapped_payload = {{"method", endpoint_}, {"params", params_json}};

        std::string payload_str = wrapped_payload.dump();
        return {payload_str.begin(), payload_str.end()};
    }

    // Otherwise generate the payload for a server request
    auto headers_json = nlohmann::json::object();

    if (headers_)
        for (const auto& [key, value] : *headers_) {
            // Some platforms might automatically add this header, but we don't want to include it
            if (key != "User-Agent")
                headers_json[key] = value;
        }

    if (body && !headers_json.contains("Content-Type"))
        headers_json["Content-Type"] = "application/json";

    // When making a server request we need a leading forward-slash on the `endpoint`
    auto final_endpoint = endpoint_;

    if (!final_endpoint.empty() && final_endpoint[0] != '/')
        final_endpoint = '/' + final_endpoint;

    // Structure the request information
    nlohmann::json request_info{
            {"method", *method_}, {"endpoint", final_endpoint}, {"headers", headers_json}};
    std::vector<std::string> payload{request_info.dump()};

    // If we were given a body, add it to the payload
    if (body && !body->empty())
        payload.emplace_back(session::to_string(*body));

    auto result = oxenc::bt_serialize(payload);
    return to_vector(result);
}

std::vector<unsigned char> Builder::build(std::vector<unsigned char> payload) {
    std::vector<unsigned char> blob;

    // First hop:
    //
    // [N][ENCRYPTED]{json}
    //
    // where json has the ephemeral_key indicating how we encrypted ENCRYPTED for this first hop.
    // The first hop decrypts ENCRYPTED into:
    //
    // [N][BLOB]{json}
    //
    // where [N] is the length of the blob and {json} now contains either:
    // - a "headers" key with an empty value.  This is how we indicate that the request is for this
    //   node as the final hop, and means that the BLOB is actually JSON it should parse to get the
    //   request info (which has "method", "params", etc. in it).
    // - "host"/"target"/"port"/"protocol" asking for an HTTP or HTTPS proxy request to be made
    //   (though "target" must start with /loki/ or /oxen/ and end with /lsrpc).  (There is still a
    //   blob here, but it is not used and typically empty).
    // - "destination" and "ephemeral_key" to forward the request to the next hop.
    //
    // This later case continues onion routing by giving us something like:
    //
    //      {"destination":"ed25519pubkey","ephemeral_key":"x25519-eph-pubkey-for-decryption","enc_type":"xchacha20"}
    //
    // (enc_type can also be aes-gcm, and defaults to that if not specified).  We forward this via
    // oxenmq to the given ed25519pubkey (but since oxenmq uses x25519 pubkeys we first have to go
    // look it up), sending an oxenmq request to sn.onion_req_v2 of the following (but bencoded, not
    // json):
    //
    //  { "d": "BLOB", "ek": "ephemeral-key-in-binary", "et": "xchacha20", "nh": N }
    //
    // where BLOB is the opaque data received from the previous hop and N is the hop number which
    // gets incremented at each hop (and terminates if it exceeds 15).  That next hop decrypts BLOB,
    // giving it a value interpreted as the same [N][BLOB]{json} as above, and we recurse.
    //
    // On the *return* trip, the message gets encrypted (once!) at the final destination using the
    // derived key from the pubkey given to the final hop, base64-encoded, then passed back without
    // any onion encryption at all all the way back to the client.

    // Ephemeral keypair:
    network::x25519_pubkey A;
    network::x25519_seckey a;
    nlohmann::json final_route;

    {
        crypto_box_keypair(A.data(), a.data());
        HopEncryption e{a, A, false};

        // The data we send to the destination differs depending on whether the destination is a
        // server or a service node
        if (host_ && protocol_ && destination_x25519_public_key_) {
            final_route = {
                    {"host", *host_},
                    {"target", "/oxen/v4/lsrpc"},  // All servers support V4 onion requests
                    {"method", "POST"},
                    {"protocol", *protocol_},
                    {"port", port_.value_or(*protocol_ == "https" ? 443 : 80)},
                    {"ephemeral_key", A.hex()},  // The x25519 ephemeral_key here is the key for the
                                                 // *next* hop to use
                    {"enc_type", to_string(enc_type)},
            };

            blob = e.encrypt(enc_type, payload, *destination_x25519_public_key_);
        } else if (ed25519_public_key_ && destination_x25519_public_key_) {
            nlohmann::json control{{"headers", ""}};
            final_route = {
                    {"destination", ed25519_public_key_.value().hex()},  // Next hop's ed25519 key
                    {"ephemeral_key", A.hex()},  // The x25519 ephemeral_key here is the key for the
                                                 // *next* hop to use
                    {"enc_type", to_string(enc_type)},
            };

            auto control_dump = control.dump();
            auto control_span = to_span(control_dump);
            auto data = encode_size(payload.size());
            data.insert(data.end(), payload.begin(), payload.end());
            data.insert(data.end(), control_span.begin(), control_span.end());
            blob = e.encrypt(enc_type, data, *destination_x25519_public_key_);
        } else {
            if (!destination_x25519_public_key_)
                throw std::runtime_error{"Destination not set: No destination x25519 public key"};
            if (!ed25519_public_key_)
                throw std::runtime_error{"Destination not set: No destination ed25519 public key"};
            throw std::runtime_error{
                    "Destination not set: " + host_.value_or("N/A") + ", " +
                    protocol_.value_or("N/A")};
        }

        // Save these because we need them again to decrypt the final response:
        final_hop_x25519_keypair.reset();
        final_hop_x25519_keypair.emplace(A, a);
    }

    for (auto it = hops_.rbegin(); it != hops_.rend(); ++it) {
        // Routing data for this hop:
        nlohmann::json routing;

        if (it == hops_.rbegin()) {
            routing = final_route;
        } else {
            routing = {
                    {"destination", std::prev(it)->first.hex()},  // Next hop's ed25519 key
                    {"ephemeral_key", A.hex()},  // The x25519 ephemeral_key here is the key for the
                                                 // *next* hop to use
                    {"enc_type", to_string(enc_type)},
            };
        }

        auto routing_dump = routing.dump();
        auto routing_span = to_span(routing_dump);
        auto data = encode_size(blob.size());
        data.insert(data.end(), blob.begin(), blob.end());
        data.insert(data.end(), routing_span.begin(), routing_span.end());

        // Generate eph key for *this* request and encrypt it:
        crypto_box_keypair(A.data(), a.data());
        HopEncryption e{a, A, false};
        blob = e.encrypt(enc_type, data, it->second);
    }

    // The data going to the first hop needs to be wrapped in one more layer to tell the first hop
    // how to decrypt the initial payload:
    auto wrapper_dump =
            nlohmann::json{{"ephemeral_key", A.hex()}, {"enc_type", to_string(enc_type)}}.dump();
    auto wrapper_span = to_span(wrapper_dump);
    auto result = encode_size(blob.size());
    result.insert(result.end(), blob.begin(), blob.end());
    result.insert(result.end(), wrapper_span.begin(), wrapper_span.end());

    return result;
}
}  // namespace session::onionreq

namespace {

session::onionreq::Builder& unbox(onion_request_builder_object* builder) {
    assert(builder && builder->internals);
    return *static_cast<session::onionreq::Builder*>(builder->internals);
}

}  // namespace

extern "C" {

LIBSESSION_C_API void onion_request_builder_init(onion_request_builder_object** builder) {
    auto c_builder = std::make_unique<onion_request_builder_object>();
    c_builder->internals = new session::onionreq::Builder{};
    *builder = c_builder.release();
}

LIBSESSION_C_API void onion_request_builder_free(onion_request_builder_object* builder) {
    delete static_cast<session::onionreq::Builder*>(builder->internals);
    delete builder;
}

LIBSESSION_C_API void onion_request_builder_set_enc_type(
        onion_request_builder_object* builder, ENCRYPT_TYPE enc_type) {
    assert(builder);

    switch (enc_type) {
        case ENCRYPT_TYPE::ENCRYPT_TYPE_AES_GCM:
            unbox(builder).set_enc_type(session::onionreq::EncryptType::aes_gcm);
            break;

        case ENCRYPT_TYPE::ENCRYPT_TYPE_X_CHA_CHA_20:
            unbox(builder).set_enc_type(session::onionreq::EncryptType::xchacha20);
            break;

        default: throw std::runtime_error{"Invalid encryption type"};
    }
}

LIBSESSION_C_API void onion_request_builder_set_snode_destination(
        onion_request_builder_object* builder,
        const uint8_t ip[4],
        const uint16_t quic_port,
        const char* ed25519_pubkey) {
    assert(builder && ip && ed25519_pubkey);

    std::vector<unsigned char> pubkey;
    pubkey.reserve(32);
    oxenc::from_hex(ed25519_pubkey, ed25519_pubkey + 64, std::back_inserter(pubkey));

    unbox(builder).set_destination(session::network::service_node{
            session::network::ed25519_pubkey::from_bytes(pubkey),
            oxen::quic::ipv4{std::span<const uint8_t, 4>(ip, 4)},
            0,
            quic_port,
            {0, 0, 0},
            session::network::INVALID_SWARM_ID});
}

LIBSESSION_C_API void onion_request_builder_set_server_destination(
        onion_request_builder_object* builder,
        const char* protocol,
        const char* host,
        const char* method,
        uint16_t port,
        const char* x25519_pubkey) {
    assert(builder && protocol && host && protocol && x25519_pubkey);

    unbox(builder).set_destination(session::network::ServerDestination{
            protocol,
            host,
            session::network::x25519_pubkey::from_hex({x25519_pubkey, 64}),
            port,
            std::nullopt,
            method});
}

LIBSESSION_C_API void onion_request_builder_add_hop(
        onion_request_builder_object* builder,
        const char* ed25519_pubkey,
        const char* x25519_pubkey) {
    assert(builder && ed25519_pubkey && x25519_pubkey);

    unbox(builder).add_hop(
            {session::network::ed25519_pubkey::from_hex({ed25519_pubkey, 64}),
             session::network::x25519_pubkey::from_hex({x25519_pubkey, 64})});
}

LIBSESSION_C_API bool onion_request_builder_build(
        onion_request_builder_object* builder,
        const unsigned char* payload_in,
        size_t payload_in_len,
        unsigned char** payload_out,
        size_t* payload_out_len,
        unsigned char* final_x25519_pubkey_out,
        unsigned char* final_x25519_seckey_out) {
    assert(builder && payload_in);

    try {
        auto& unboxed_builder = unbox(builder);
        auto payload = unboxed_builder.build({payload_in, payload_in + payload_in_len});

        if (unboxed_builder.final_hop_x25519_keypair) {
            auto key_pair = unboxed_builder.final_hop_x25519_keypair.value();
            std::memcpy(final_x25519_pubkey_out, key_pair.first.data(), key_pair.first.size());
            std::memcpy(final_x25519_seckey_out, key_pair.second.data(), key_pair.second.size());
        } else {
            throw std::runtime_error{"Final keypair not generated"};
        }

        *payload_out = static_cast<unsigned char*>(malloc(payload.size()));
        *payload_out_len = payload.size();
        std::memcpy(*payload_out, payload.data(), payload.size());

        return true;
    } catch (...) {
        return false;
    }
}
}
