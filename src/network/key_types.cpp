#include "session/network/key_types.hpp"

#include <oxenc/base32z.h>
#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <cstring>
#include <session/crypto/ed25519.hpp>
#include <session/crypto/x25519.hpp>
#include <session/format.hpp>
#include <type_traits>

namespace session::network {

namespace detail {

    void load_from_hex(void* buffer, size_t length, std::string_view hex) {
        if (!oxenc::is_hex(hex))
            throw std::runtime_error{"Hex key data is invalid: data is not hex"};
        if (hex.size() != 2 * length)
            throw std::runtime_error{
                    "Hex key data is invalid: expected {} hex digits, received {}"_format(
                            length, hex.size())};
        oxenc::from_hex(hex.begin(), hex.end(), reinterpret_cast<unsigned char*>(buffer));
    }

    void load_from_bytes(void* buffer, size_t length, std::string_view bytes) {
        if (bytes.size() != length)
            throw std::runtime_error{"Key data is invalid: expected {} bytes, received {}"_format(
                    length, bytes.size())};
        std::memmove(buffer, bytes.data(), length);
    }

}  // namespace detail

std::string ed25519_pubkey::snode_address() const {
    auto addr = oxenc::to_base32z(begin(), end());
    addr += ".snode";
    return addr;
}

std::string ed25519_pubkey::short_string() const {
    // 5 bytes is exactly 8 base32z characters, so this is a prefix of snode_address()
    return oxenc::to_base32z(begin(), begin() + 5);
}

legacy_pubkey legacy_seckey::pubkey() const {
    legacy_pubkey pk;
    ed25519::scalarmult_base_noclamp(pk, *this);
    return pk;
};
ed25519_pubkey ed25519_seckey::pubkey() const {
    ed25519_pubkey pk;
    ed25519::sk_to_pk(pk, ed25519::PrivKeySpan::from(*this));
    return pk;
};
x25519_pubkey x25519_seckey::pubkey() const {
    x25519_pubkey pk;
    x25519::scalarmult_base(pk, *this);
    return pk;
};

template <typename T>
static T parse_pubkey(std::string_view pubkey_in) {
    T pk{};
    static_assert(pk.size() == 32);
    if (pubkey_in.size() == 32)
        detail::load_from_bytes(pk.data(), 32, pubkey_in);
    else if (pubkey_in.size() == 64 && oxenc::is_hex(pubkey_in))
        oxenc::from_hex(pubkey_in.begin(), pubkey_in.end(), pk.begin());
    else if (
            (pubkey_in.size() == 43 || (pubkey_in.size() == 44 && pubkey_in.back() == '=')) &&
            oxenc::is_base64(pubkey_in))
        oxenc::from_base64(pubkey_in.begin(), pubkey_in.end(), pk.begin());
    else if (pubkey_in.size() == 52 && oxenc::is_base32z(pubkey_in))
        oxenc::from_base32z(pubkey_in.begin(), pubkey_in.end(), pk.begin());

    return pk;
}

legacy_pubkey parse_legacy_pubkey(std::string_view pubkey_in) {
    return parse_pubkey<legacy_pubkey>(pubkey_in);
}
ed25519_pubkey parse_ed25519_pubkey(std::string_view pubkey_in) {
    return parse_pubkey<ed25519_pubkey>(pubkey_in);
}
x25519_pubkey parse_x25519_pubkey(std::string_view pubkey_in) {
    return parse_pubkey<x25519_pubkey>(pubkey_in);
}
x25519_pubkey compute_x25519_pubkey(std::span<const std::byte, 32> ed25519_pk) {
    return x25519_pubkey::from_bytes(ed25519::pk_to_x25519(ed25519_pk));
}

}  // namespace session::network
