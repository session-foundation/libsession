#include "session/onionreq/response_parser.hpp"

#include <oxenc/base64.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/endian.h>
#include <sodium/core.h>

#include <session/format.hpp>
#include <stdexcept>

#include "session/export.h"
#include "session/onionreq/builder.h"
#include "session/onionreq/builder.hpp"
#include "session/onionreq/hop_encryption.hpp"
#include "session/onionreq/response_parser.h"
#include "session/util.hpp"

using namespace session;

namespace session::onionreq {

ResponseParser::ResponseParser(session::onionreq::Builder builder) {
    auto dest_x25519_pubkey = builder.get_destination_x25519_public_key();

    if (!dest_x25519_pubkey)
        throw std::runtime_error{"Builder does not contain destination x25519 public key"};
    if (!builder.final_hop_x25519_keypair)
        throw std::runtime_error{"Builder does not contain final keypair"};

    enc_type_ = builder.enc_type;
    destination_x25519_public_key_ = *dest_x25519_pubkey;
    x25519_keypair_ = builder.final_hop_x25519_keypair.value();
    v4_request_ = builder.is_v4_request;
}

bool ResponseParser::response_long_enough(EncryptType enc_type, size_t response_size) {
    return HopEncryption::response_long_enough(enc_type, response_size);
}

std::vector<std::byte> ResponseParser::decrypt(std::vector<std::byte> ciphertext) const {
    HopEncryption d{x25519_keypair_.second, x25519_keypair_.first, false};

    // FIXME: The legacy PN server doesn't support 'xchacha20' onion requests so would return an
    // error encrypted with 'aes_gcm' so try to decrypt in case that is what happened - this
    // workaround can be removed once the legacy PN server is removed
    try {
        return d.decrypt(enc_type_, ciphertext, destination_x25519_public_key_);
    } catch (const std::exception& e) {
        if (enc_type_ == session::onionreq::EncryptType::xchacha20) {
            try {
                return d.decrypt(
                        session::onionreq::EncryptType::aes_gcm,
                        ciphertext,
                        destination_x25519_public_key_);
            } catch (...) {
                throw std::runtime_error{std::string(decryption_failed_error)};
            }
        } else
            throw;
    }
}

DecryptedResponse ResponseParser::decrypted_response(const std::string& encrypted_response) {
    // Ensure the response is long enough to be processed, if not then handle it as an error
    if (!response_long_enough(enc_type_, encrypted_response.size()))
        throw std::runtime_error{
                "Response is too short to be an onion request response: " + encrypted_response};

    if (v4_request_)
        return _decrypt_v4_response(encrypted_response);
    else
        return _decrypt_v3_response(encrypted_response);
}

DecryptedResponse ResponseParser::_decrypt_v3_response(const std::string& response) {
    std::string base64_iv_and_ciphertext;
    try {
        nlohmann::json response_json = nlohmann::json::parse(response);

        if (!response_json.contains("result") || !response_json["result"].is_string())
            throw std::runtime_error{"JSON missing result field."};

        base64_iv_and_ciphertext = response_json["result"].get<std::string>();
    } catch (...) {
        base64_iv_and_ciphertext = response;
    }

    if (!oxenc::is_base64(base64_iv_and_ciphertext))
        throw std::runtime_error{"Invalid base64 encoded IV and ciphertext."};

    std::vector<std::byte> iv_and_ciphertext;
    oxenc::from_base64(
            base64_iv_and_ciphertext.begin(),
            base64_iv_and_ciphertext.end(),
            std::back_inserter(iv_and_ciphertext));
    auto result = decrypt(iv_and_ciphertext);
    // Parse as a char view: libc++'s std::char_traits has no std::byte specialization.
    auto result_json = nlohmann::json::parse(to_string_view(result));
    int16_t status_code;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;

    if (result_json.contains("status_code") && result_json["status_code"].is_number())
        status_code = result_json["status_code"].get<int16_t>();
    else if (result_json.contains("status") && result_json["status"].is_number())
        status_code = result_json["status"].get<int16_t>();
    else
        throw std::runtime_error{"Invalid JSON response, missing required status_code field."};

    if (result_json.contains("headers")) {
        auto header_vals = result_json["headers"];

        for (auto it = header_vals.begin(); it != header_vals.end(); ++it)
            headers.emplace_back(it.key(), it.value());
    }

    if (result_json.contains("body") && result_json["body"].is_string())
        body = result_json["body"].get<std::string>();
    else
        body = result_json.dump();

    return {status_code, headers, body};
}

DecryptedResponse ResponseParser::_decrypt_v4_response(const std::string& response) {
    auto response_data = to_vector(response);
    auto result = decrypt(response_data);

    // Process the bencoded response
    oxenc::bt_list_consumer result_bencode{to_span<std::byte>(result)};

    if (result_bencode.is_finished() || !result_bencode.is_string())
        throw std::runtime_error{"Invalid bencoded response"};

    auto response_info_string = result_bencode.consume_string();
    int16_t status_code;
    std::vector<std::pair<std::string, std::string>> headers;
    nlohmann::json response_info_json = nlohmann::json::parse(response_info_string);

    if (response_info_json.contains("code") && response_info_json["code"].is_number())
        status_code = response_info_json["code"].get<int16_t>();
    else
        throw std::runtime_error{"Invalid JSON response, missing required code field."};

    if (response_info_json.contains("headers")) {
        auto header_vals = response_info_json["headers"];

        for (auto it = header_vals.begin(); it != header_vals.end(); ++it)
            headers.emplace_back(it.key(), it.value());
    }

    if (result_bencode.is_finished())
        return {status_code, headers, std::nullopt};

    return {status_code, headers, result_bencode.consume_string()};
}

}  // namespace session::onionreq

extern "C" {

LIBSESSION_C_API bool onion_request_decrypt(
        const unsigned char* ciphertext_,
        size_t ciphertext_len,
        ENCRYPT_TYPE enc_type_,
        unsigned char* destination_x25519_pubkey,
        unsigned char* final_x25519_pubkey,
        unsigned char* final_x25519_seckey,
        unsigned char** plaintext_out,
        size_t* plaintext_out_len) {
    assert(ciphertext_ && destination_x25519_pubkey && final_x25519_pubkey && final_x25519_seckey &&
           ciphertext_len > 0);

    try {
        auto enc_type = session::onionreq::EncryptType::xchacha20;

        switch (enc_type_) {
            case ENCRYPT_TYPE::ENCRYPT_TYPE_AES_GCM:
                enc_type = session::onionreq::EncryptType::aes_gcm;
                break;

            case ENCRYPT_TYPE::ENCRYPT_TYPE_X_CHA_CHA_20:
                enc_type = session::onionreq::EncryptType::xchacha20;
                break;

            default:
                throw std::runtime_error{
                        "Invalid decryption type {}"_format(static_cast<int>(enc_type_))};
        }

        session::onionreq::HopEncryption d{
                session::network::x25519_seckey::from_bytes(to_byte_span<32>(final_x25519_seckey)),
                session::network::x25519_pubkey::from_bytes(to_byte_span<32>(final_x25519_pubkey)),
                false};

        std::vector<std::byte> result;
        std::vector<std::byte> ciphertext{to_vector(to_byte_span(ciphertext_, ciphertext_len))};

        // FIXME: The legacy PN server doesn't support 'xchacha20' onion requests so would return an
        // error encrypted with 'aes_gcm' so try to decrypt in case that is what happened - this
        // workaround can be removed once the legacy PN server is removed
        try {
            result = d.decrypt(
                    enc_type,
                    ciphertext,
                    session::network::x25519_pubkey::from_bytes(
                            to_byte_span<32>(destination_x25519_pubkey)));
        } catch (...) {
            if (enc_type == session::onionreq::EncryptType::xchacha20)
                result = d.decrypt(
                        session::onionreq::EncryptType::aes_gcm,
                        ciphertext,
                        session::network::x25519_pubkey::from_bytes(
                                to_byte_span<32>(destination_x25519_pubkey)));
            else
                return false;
        }

        *plaintext_out = static_cast<unsigned char*>(malloc(result.size()));
        *plaintext_out_len = result.size();
        std::memcpy(*plaintext_out, result.data(), result.size());
        return true;
    } catch (...) {
        return false;
    }
}
}
