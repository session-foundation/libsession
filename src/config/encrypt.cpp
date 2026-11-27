#include "session/config/encrypt.hpp"

#include <oxenc/endian.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_generichash_blake2b.h>

#include <array>
#include <cassert>

#include "session/config/encrypt.h"
#include "session/export.h"
#include "session/hash.hpp"
#include "session/util.hpp"

using namespace std::literals;

namespace session::config {

// namespace {

//     // Helper function to go from char pointers to the unsigned char pointers sodium needs:
//     const unsigned char* to_unsigned(const char* x) {
//         return reinterpret_cast<const unsigned char*>(x);
//     }

// }  // namespace

static constexpr size_t DOMAIN_MAX_SIZE = 24;
static constexpr auto NONCE_KEY_PREFIX = "libsessionutil-config-encrypted-"sv;
static_assert(NONCE_KEY_PREFIX.size() + DOMAIN_MAX_SIZE < crypto_generichash_blake2b_KEYBYTES_MAX);

static std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> make_encrypt_key(
        std::span<const std::byte> key_base, uint64_t message_size, std::string_view domain) {
    if (key_base.size() != 32)
        throw std::invalid_argument{"encrypt called with key_base != 32 bytes"};
    if (domain.size() < 1 || domain.size() > DOMAIN_MAX_SIZE)
        throw std::invalid_argument{"encrypt called with domain size not in [1, 24]"};

    // We hash the key because we're using a deterministic nonce: the `key_base` value is expected
    // to be a long-term value for which nonce reuse (via hash collision) would be bad: by
    // incorporating the domain and message size we at least vary the key to further restrict the
    // nonce reuse concern so that you would not only have to hash collide but also have it happen
    // on messages of identical sizes and identical domain.
    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> key{0};
    oxenc::host_to_big_inplace(message_size);
    hash::blake2b(
            key,
            key_base,
            std::span{reinterpret_cast<const unsigned char*>(&message_size), sizeof(message_size)},
            to_span(domain));
    return key;
}

void encrypt_prealloced(
        std::span<std::byte> message,
        std::span<const std::byte> key_base,
        std::string_view domain) {
    if (message.size() < ENCRYPT_DATA_OVERHEAD)
        throw std::invalid_argument{
                "encrypt_prealloced: buffer is smaller than ENCRYPT_DATA_OVERHEAD"};
    auto plaintext = message.first(message.size() - ENCRYPT_DATA_OVERHEAD);
    auto key = make_encrypt_key(key_base, plaintext.size(), domain);

    std::string nonce_key{NONCE_KEY_PREFIX};
    nonce_key += domain;

    auto nonce =
            hash::blake2b_key<crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>(nonce_key, plaintext);

    unsigned long long outlen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
            to_unsigned(message.data()),
            &outlen,
            to_unsigned(plaintext.data()),
            plaintext.size(),
            nullptr,
            0,
            nullptr,
            to_unsigned(nonce.data()),
            key.data());

    assert(outlen == plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    std::memcpy(to_unsigned(message.data()) + outlen, to_unsigned(nonce.data()), nonce.size());
}

std::vector<std::byte> encrypt(
        std::span<const std::byte> message,
        std::span<const std::byte> key_base,
        std::string_view domain) {
    std::vector<std::byte> out(message.size() + ENCRYPT_DATA_OVERHEAD);
    std::memcpy(out.data(), message.data(), message.size());
    encrypt_prealloced(out, key_base, domain);
    return out;
}

void encrypt_inplace(
        std::vector<std::byte>& message,
        std::span<const std::byte> key_base,
        std::string_view domain) {
    message.resize(message.size() + ENCRYPT_DATA_OVERHEAD);
    encrypt_prealloced(message, key_base, domain);
}

static_assert(
        ENCRYPT_DATA_OVERHEAD ==
        crypto_aead_xchacha20poly1305_IETF_ABYTES + crypto_aead_xchacha20poly1305_IETF_NPUBBYTES);

std::vector<std::byte> decrypt(
        std::span<const std::byte> ciphertext,
        std::span<const std::byte> key_base,
        std::string_view domain) {
    auto x = session::to_vector<std::byte>(ciphertext);
    decrypt_inplace(x, key_base, domain);
    return x;
}

void decrypt_inplace(
        std::vector<std::byte>& ciphertext,
        std::span<const std::byte> key_base,
        std::string_view domain) {
    size_t message_len = ciphertext.size() - ENCRYPT_DATA_OVERHEAD;
    if (message_len > ciphertext.size())  // overflow
        throw decrypt_error{"Decryption failed: ciphertext is too short"};

    std::span<const std::byte> nonce = std::span<const std::byte>{ciphertext}.subspan(
            ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    auto key = make_encrypt_key(key_base, message_len, domain);

    unsigned long long mlen_wrote = 0;
    if (0 != crypto_aead_xchacha20poly1305_ietf_decrypt(
                     to_unsigned(ciphertext.data()),
                     &mlen_wrote,
                     nullptr,
                     to_unsigned(ciphertext.data()),
                     ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
                     nullptr,
                     0,
                     to_unsigned(nonce.data()),
                     key.data()))
        throw decrypt_error{"Message decryption failed"};

    assert(mlen_wrote == message_len);
    ciphertext.resize(mlen_wrote);
}

void pad_message(std::vector<std::byte>& data, size_t overhead) {
    size_t target_size = padded_size(data.size(), overhead);
    if (target_size > data.size())
        data.insert(data.begin(), target_size - data.size(), std::byte{0});
}

}  // namespace session::config

extern "C" {

LIBSESSION_EXPORT unsigned char* config_encrypt(
        const unsigned char* plaintext,
        size_t len,
        const unsigned char* key_base,
        const char* domain,
        size_t* ciphertext_size) {

    std::vector<std::byte> ciphertext;
    try {
        ciphertext = session::config::encrypt(
                std::span{reinterpret_cast<const std::byte*>(plaintext), len},
                std::span<const std::byte, 32>{reinterpret_cast<const std::byte*>(key_base), 32},
                domain);
    } catch (...) {
        return nullptr;
    }

    auto* data = static_cast<unsigned char*>(std::malloc(ciphertext.size()));
    std::memcpy(data, ciphertext.data(), ciphertext.size());
    *ciphertext_size = ciphertext.size();
    return data;
}

LIBSESSION_EXPORT unsigned char* config_decrypt(
        const unsigned char* ciphertext,
        size_t clen,
        const unsigned char* key_base,
        const char* domain,
        size_t* plaintext_size) {

    std::vector<std::byte> plaintext;
    try {
        plaintext = session::config::decrypt(
                std::span{reinterpret_cast<const std::byte*>(ciphertext), clen},
                std::span<const std::byte, 32>{reinterpret_cast<const std::byte*>(key_base), 32},
                domain);
    } catch (const std::exception& e) {
        return nullptr;
    }

    auto* data = static_cast<unsigned char*>(std::malloc(plaintext.size()));
    std::memcpy(data, plaintext.data(), plaintext.size());
    *plaintext_size = plaintext.size();
    return data;
}

LIBSESSION_EXPORT size_t config_padded_size(size_t s, size_t overhead) {
    return session::config::padded_size(s, overhead);
}
}
