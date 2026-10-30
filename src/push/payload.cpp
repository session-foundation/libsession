#include "session/push/payload.hpp"

#include <oxenc/base64.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>

#include <nlohmann/json.hpp>
#include <session/format.hpp>
#include <session/session_encrypt.hpp>
#include <session/util.hpp>

namespace session::push {

using namespace session::literals;

namespace {

    // A swarm id as the push server writes it: 33 bytes in hex.
    void check_swarm(const std::string& swarm) {
        if (swarm.size() != 66 || !oxenc::is_hex(swarm))
            throw malformed{"push payload has an invalid swarm id"};
    }

    // The JSON metadata, which is what the push server ordinarily sends.
    void read_json(Payload& p, std::string_view text) {
        nlohmann::json j;
        try {
            j = nlohmann::json::parse(text);
            p.swarm = j.at("@").get<std::string>();
            p.hash = j.at("#").get<std::string>();
            p.ns = static_cast<config::Namespace>(j.at("n").get<int16_t>());
            p.timestamp = from_epoch_ms(j.at("t").get<int64_t>());
            p.expiry = from_epoch_ms(j.at("z").get<int64_t>());
            if (auto l = j.find("l"); l != j.end())
                p.length = l->get<size_t>();
            if (auto b = j.find("B"); b != j.end())
                p.too_large = b->get<bool>();
        } catch (const nlohmann::json::exception& e) {
            throw malformed{"push payload metadata is not valid: {}"_format(e.what())};
        }
    }

    // The same metadata as a bencoded dict, which is what APNs pushes without a body carry.  Keys
    // in sorted order, as a bencoded dict requires.
    void read_dict(Payload& p, oxenc::bt_dict_consumer d) {
        try {
            p.hash = d.require<std::string>("#");
            p.swarm = d.require<std::string>("@");
            if (auto B = d.maybe<int>("B"))
                p.too_large = *B != 0;
            if (auto l = d.maybe<uint64_t>("l"))
                p.length = *l;
            p.ns = static_cast<config::Namespace>(d.require<int16_t>("n"));
            p.timestamp = from_epoch_ms(d.require<int64_t>("t"));
            p.expiry = from_epoch_ms(d.require<int64_t>("z"));
        } catch (const std::exception& e) {
            throw malformed{"push payload metadata is not valid: {}"_format(e.what())};
        }
    }

}  // namespace

Payload decode(std::span<const std::byte> enc_payload, std::span<const std::byte, 32> enc_key) {
    std::vector<std::byte> plain;
    try {
        plain = decrypt_push_notification(enc_payload, enc_key);
    } catch (const std::exception& e) {
        throw undecryptable{e.what()};
    }

    Payload p;
    try {
        oxenc::bt_list_consumer list{plain};
        if (list.is_string())
            read_json(p, list.consume_string_view());
        else if (list.is_dict())
            read_dict(p, list.consume_dict_consumer());
        else
            throw malformed{"push payload metadata is neither JSON nor a dict"};

        if (!list.is_finished())
            p.data = to_vector<std::byte>(list.consume_string_view());
    } catch (const malformed&) {
        throw;
    } catch (const std::exception& e) {
        throw malformed{"push payload is not a bencoded list: {}"_format(e.what())};
    }

    check_swarm(p.swarm);
    if (p.hash.empty())
        throw malformed{"push payload has no message hash"};
    if (p.data && p.too_large)
        throw malformed{"push payload carries a message it says was too large"};
    return p;
}

Payload decode(std::string_view enc_payload_b64, std::span<const std::byte, 32> enc_key) {
    if (!oxenc::is_base64(enc_payload_b64))
        throw malformed{"push payload is not base64"};
    std::vector<std::byte> bytes;
    bytes.reserve(oxenc::from_base64_size(enc_payload_b64.size()));
    oxenc::from_base64(enc_payload_b64.begin(), enc_payload_b64.end(), std::back_inserter(bytes));
    return decode(std::span<const std::byte>{bytes}, enc_key);
}

}  // namespace session::push
