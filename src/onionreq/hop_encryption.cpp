#include "session/onionreq/hop_encryption.hpp"

#include <nettle/gcm.h>
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
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>

#include "../nettle-compat.hpp"
#include "session/export.h"
#include "session/network/key_types.hpp"
#include "session/onionreq/builder.hpp"
#include "session/util.hpp"
#include "session/xed25519.hpp"

namespace session::onionreq {

namespace {

    // Derive shared secret from our (ephemeral) `seckey` and the other party's `pubkey`
    std::array<uint8_t, crypto_scalarmult_BYTES> calculate_shared_secret(
            const network::x25519_seckey& seckey, const network::x25519_pubkey& pubkey) {
        std::array<uint8_t, crypto_scalarmult_BYTES> secret;
        if (crypto_scalarmult(secret.data(), seckey.data(), pubkey.data()) != 0)
            throw std::runtime_error("Shared key derivation failed (crypto_scalarmult)");
        return secret;
    }

    constexpr std::string_view salt{"LOKI"};

    std::array<uint8_t, crypto_scalarmult_BYTES> derive_symmetric_key(
            const network::x25519_seckey& seckey, const network::x25519_pubkey& pubkey) {
        auto key = calculate_shared_secret(seckey, pubkey);

        auto usalt = to_span(salt);

        crypto_auth_hmacsha256_state state;

        crypto_auth_hmacsha256_init(&state, usalt.data(), usalt.size());
        crypto_auth_hmacsha256_update(&state, key.data(), key.size());
        crypto_auth_hmacsha256_final(&state, key.data());

        return key;
    }

    // More robust shared secret calculation, used when using xchacha20-poly1305 encryption.  (This
    // could be used for AES-GCM as well, but would break backwards compatibility with existing
    // Session clients).
    std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> xchacha20_shared_key(
            const network::x25519_pubkey& local_pub,
            const network::x25519_seckey& local_sec,
            const network::x25519_pubkey& remote_pub,
            bool local_first) {
        std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> key;
        static_assert(crypto_aead_xchacha20poly1305_ietf_KEYBYTES >= crypto_scalarmult_BYTES);
        if (0 != crypto_scalarmult(
                         key.data(),
                         local_sec.data(),
                         remote_pub.data()))  // Use key as tmp storage for aB
            throw std::runtime_error{"Failed to compute shared key for xchacha20"};
        crypto_generichash_state h;
        crypto_generichash_init(&h, nullptr, 0, key.size());
        crypto_generichash_update(&h, key.data(), crypto_scalarmult_BYTES);
        crypto_generichash_update(
                &h, (local_first ? local_pub : remote_pub).data(), local_pub.size());
        crypto_generichash_update(
                &h, (local_first ? remote_pub : local_pub).data(), local_pub.size());
        crypto_generichash_final(&h, key.data(), key.size());
        return key;
    }

}  // namespace

bool HopEncryption::response_long_enough(EncryptType type, size_t response_size) {
    switch (type) {
        case EncryptType::xchacha20:
            return (response_size >= crypto_aead_xchacha20poly1305_ietf_ABYTES);
        case EncryptType::aes_gcm: return (response_size >= GCM_IV_SIZE + GCM_DIGEST_SIZE);
    }
    return false;
}

std::vector<unsigned char> HopEncryption::encrypt(
        EncryptType type,
        std::vector<unsigned char> plaintext,
        const network::x25519_pubkey& pubkey) const {
    switch (type) {
        case EncryptType::xchacha20: return encrypt_xchacha20(plaintext, pubkey);
        case EncryptType::aes_gcm: return encrypt_aesgcm(plaintext, pubkey);
    }
    throw std::runtime_error{"Invalid encryption type"};
}

std::vector<unsigned char> HopEncryption::decrypt(
        EncryptType type,
        std::vector<unsigned char> ciphertext,
        const network::x25519_pubkey& pubkey) const {
    switch (type) {
        case EncryptType::xchacha20: return decrypt_xchacha20(ciphertext, pubkey);
        case EncryptType::aes_gcm: return decrypt_aesgcm(ciphertext, pubkey);
    }
    throw std::runtime_error{"Invalid decryption type"};
}

std::vector<unsigned char> HopEncryption::encrypt_aesgcm(
        std::vector<unsigned char> plaintext, const network::x25519_pubkey& pubKey) const {
    auto key = derive_symmetric_key(private_key_, pubKey);

    // Initialise cipher context with the key
    struct gcm_aes256_ctx ctx;
    static_assert(key.size() == AES256_KEY_SIZE);
    gcm_aes256_set_key(&ctx, key.data());

    std::vector<unsigned char> output;
    output.resize(GCM_IV_SIZE + plaintext.size() + GCM_DIGEST_SIZE);

    // Start the output with the random IV, and load it into ctx
    auto* o = output.data();
    randombytes_buf(o, GCM_IV_SIZE);
    gcm_aes256_set_iv(&ctx, GCM_IV_SIZE, o);
    o += GCM_IV_SIZE;

    // Append encrypted data
    gcm_aes256_encrypt(&ctx, plaintext.size(), o, plaintext.data());
    o += plaintext.size();

    // Append digest
    nettle_digest<gcm_aes256_digest>(&ctx, GCM_DIGEST_SIZE, o);
    o += GCM_DIGEST_SIZE;

    assert(o == output.data() + output.size());

    return output;
}

std::vector<unsigned char> HopEncryption::decrypt_aesgcm(
        std::vector<unsigned char> ciphertext_, const network::x25519_pubkey& pubKey) const {
    std::span<const unsigned char> ciphertext = to_span(ciphertext_);

    if (!response_long_enough(EncryptType::aes_gcm, ciphertext_.size()))
        throw std::invalid_argument{
                "Ciphertext data is too short: " + session::to_string(ciphertext_)};

    auto key = derive_symmetric_key(private_key_, pubKey);

    // Initialise cipher context with the key
    struct gcm_aes256_ctx ctx;
    static_assert(key.size() == AES256_KEY_SIZE);
    gcm_aes256_set_key(&ctx, key.data());

    gcm_aes256_set_iv(&ctx, GCM_IV_SIZE, ciphertext.data());

    ciphertext = ciphertext.subspan(GCM_IV_SIZE);
    auto digest_in = ciphertext.subspan(ciphertext.size() - GCM_DIGEST_SIZE);
    ciphertext = ciphertext.subspan(0, ciphertext.size() - GCM_DIGEST_SIZE);

    std::vector<unsigned char> plaintext;
    plaintext.resize(ciphertext.size());

    gcm_aes256_decrypt(&ctx, ciphertext.size(), plaintext.data(), ciphertext.data());

    std::array<uint8_t, GCM_DIGEST_SIZE> digest_out;
    nettle_digest<gcm_aes256_digest>(&ctx, digest_out.size(), digest_out.data());

    if (sodium_memcmp(digest_out.data(), digest_in.data(), GCM_DIGEST_SIZE) != 0)
        throw std::runtime_error{"Decryption failed (AES256-GCM)"};

    return plaintext;
}

std::vector<unsigned char> HopEncryption::encrypt_xchacha20(
        std::vector<unsigned char> plaintext, const network::x25519_pubkey& pubKey) const {

    std::vector<unsigned char> ciphertext;
    ciphertext.resize(
            crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + plaintext.size() +
            crypto_aead_xchacha20poly1305_ietf_ABYTES);

    const auto key = xchacha20_shared_key(public_key_, private_key_, pubKey, !server_);

    // Generate random nonce, and stash it at the beginning of ciphertext:
    randombytes_buf(ciphertext.data(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    auto* c = reinterpret_cast<unsigned char*>(ciphertext.data()) +
              crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    unsigned long long clen;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
            c,
            &clen,
            plaintext.data(),
            plaintext.size(),
            nullptr,
            0,        // additional data
            nullptr,  // nsec (always unused)
            reinterpret_cast<const unsigned char*>(ciphertext.data()),
            key.data());
    assert(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + clen <= ciphertext.size());
    ciphertext.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + clen);
    return ciphertext;
}

std::vector<unsigned char> HopEncryption::decrypt_xchacha20(
        std::vector<unsigned char> ciphertext_, const network::x25519_pubkey& pubKey) const {
    std::span<const unsigned char> ciphertext = to_span(ciphertext_);

    // Extract nonce from the beginning of the ciphertext:
    auto nonce = ciphertext.subspan(0, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    ciphertext = ciphertext.subspan(nonce.size());

    if (!response_long_enough(EncryptType::xchacha20, ciphertext_.size()))
        throw std::invalid_argument{
                "Ciphertext data is too short: " +
                std::string(reinterpret_cast<const char*>(ciphertext_.data()))};

    const auto key = xchacha20_shared_key(public_key_, private_key_, pubKey, !server_);

    std::vector<unsigned char> plaintext;
    plaintext.resize(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    auto* m = reinterpret_cast<unsigned char*>(plaintext.data());
    unsigned long long mlen;
    if (0 != crypto_aead_xchacha20poly1305_ietf_decrypt(
                     m,
                     &mlen,
                     nullptr,  // nsec (always unused)
                     ciphertext.data(),
                     ciphertext.size(),
                     nullptr,
                     0,  // additional data
                     nonce.data(),
                     key.data()))
        throw std::runtime_error{"Could not decrypt (XChaCha20-Poly1305)"};
    assert(mlen <= plaintext.size());
    plaintext.resize(mlen);
    return plaintext;
}

}  // namespace session::onionreq
