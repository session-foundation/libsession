#include "session/hash.hpp"

#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_hash_sha512.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_xof_shake256.h>
#include <sodium/utils.h>

#include <stdexcept>

#include "session/export.h"
#include "session/hash.h"
#include "session/util.hpp"

namespace {

using namespace session;

void hash_impl(
        std::span<std::byte> hash,
        std::span<const std::byte> msg,
        std::optional<std::span<const std::byte>> key) {
    const auto size = hash.size();
    if (size < crypto_generichash_blake2b_BYTES_MIN || size > crypto_generichash_blake2b_BYTES_MAX)
        throw std::invalid_argument{"Invalid size: expected between 16 and 64 bytes (inclusive)"};

    if (key && key->size() > crypto_generichash_blake2b_BYTES_MAX)
        throw std::invalid_argument{"Invalid key: expected less than 65 bytes"};

    crypto_generichash_blake2b(
            to_unsigned(hash.data()),
            size,
            to_unsigned(msg.data()),
            msg.size(),
            key ? to_unsigned(key->data()) : nullptr,
            key ? key->size() : 0);
}

}  // namespace

namespace session::hash {

void hash(
        std::span<std::byte> hash,
        std::span<const std::byte> msg,
        std::optional<std::span<const std::byte>> key) {
    hash_impl(hash, msg, key);
}

std::vector<std::byte> hash(
        const size_t size,
        std::span<const std::byte> msg,
        std::optional<std::span<const std::byte>> key) {
    std::vector<std::byte> result(size);
    hash_impl(result, msg, key);
    return result;
}

}  // namespace session::hash

namespace session::hash::detail {

// The header's stand-in buffers and constants must track libsodium exactly: a mismatch has to fail
// to compile here rather than corrupt memory or silently change a hash.
template <typename State, size_t Size, size_t Align>
constexpr bool state_fits = sizeof(State) == Size && alignof(State) <= Align;

static_assert(state_fits<crypto_generichash_blake2b_state, 384, 64>);
static_assert(state_fits<crypto_xof_shake256_state, 256, 16>);
static_assert(crypto_generichash_blake2b_BYTES_MAX == 64);
static_assert(crypto_generichash_blake2b_KEYBYTES_MAX == 64);
static_assert(crypto_generichash_blake2b_PERSONALBYTES == 16);
static_assert(SHAKE256_DOMAIN == crypto_xof_shake256_DOMAIN_STANDARD);
static_assert(crypto_hash_sha512_BYTES == 64);
static_assert(crypto_auth_hmacsha256_BYTES == 32);
static_assert(ARGON2_SALTBYTES == crypto_pwhash_SALTBYTES);
static_assert(ARGON2_OPSLIMIT_MODERATE == crypto_pwhash_OPSLIMIT_MODERATE);
static_assert(ARGON2_MEMLIMIT_MODERATE == crypto_pwhash_MEMLIMIT_MODERATE);
static_assert(ARGON2ID13 == crypto_pwhash_ALG_ARGON2ID13);
static_assert(crypto_pwhash_BYTES_MIN == 16);

static auto* blake2b_state(unsigned char* st) {
    return reinterpret_cast<crypto_generichash_blake2b_state*>(st);
}
static auto* keccak_state(unsigned char* st) {
    return reinterpret_cast<crypto_xof_shake256_state*>(st);
}

blake2b_hasher_base::blake2b_hasher_base(
        size_t outlen,
        std::span<const unsigned char> key,
        std::optional<std::span<const std::byte, 16>> pers) {
    key = key.first(std::min<size_t>(key.size(), crypto_generichash_blake2b_KEYBYTES_MAX));
    crypto_generichash_blake2b_init_salt_personal(
            blake2b_state(st),
            key.data(),
            key.size(),
            outlen,
            /*salt=*/nullptr,
            pers ? to_unsigned(pers->data()) : nullptr);
}

blake2b_hasher_base::~blake2b_hasher_base() {
    sodium_memzero(st, sizeof(st));
}

void blake2b_hasher_base::update(std::initializer_list<std::span<const unsigned char>> parts) {
    for (auto part : parts)
        crypto_generichash_blake2b_update(blake2b_state(st), part.data(), part.size());
}

void blake2b_hasher_base::finalize(std::span<unsigned char> out) {
    crypto_generichash_blake2b_final(blake2b_state(st), out.data(), out.size());
}

keccak_base::keccak_base(unsigned char domain) {
    crypto_xof_shake256_init_with_domain(keccak_state(st), domain);
}

keccak_base::~keccak_base() {
    sodium_memzero(st, sizeof(st));
}

void keccak_base::absorb(std::initializer_list<std::span<const unsigned char>> parts) {
    for (auto part : parts)
        crypto_xof_shake256_update(keccak_state(st), part.data(), part.size());
}

void keccak_base::squeeze(std::span<unsigned char> out) {
    crypto_xof_shake256_squeeze(keccak_state(st), out.data(), out.size());
}

void sha512(
        std::span<unsigned char, 64> out,
        std::initializer_list<std::span<const unsigned char>> parts) {
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    for (auto part : parts)
        crypto_hash_sha512_update(&st, part.data(), part.size());
    crypto_hash_sha512_final(&st, out.data());
    sodium_memzero(&st, sizeof(st));
}

void hmac_sha256(
        std::span<unsigned char, 32> out,
        std::span<const unsigned char> key,
        std::initializer_list<std::span<const unsigned char>> parts) {
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key.data(), key.size());
    for (auto part : parts)
        crypto_auth_hmacsha256_update(&st, part.data(), part.size());
    crypto_auth_hmacsha256_final(&st, out.data());
    sodium_memzero(&st, sizeof(st));
}

void argon2(
        std::span<unsigned char> out,
        std::span<const char> password,
        std::span<const std::byte, 16> salt,
        unsigned long long opslimit,
        size_t memlimit,
        int alg) {
    if (0 != crypto_pwhash(
                     out.data(),
                     out.size(),
                     password.data(),
                     password.size(),
                     to_unsigned(salt.data()),
                     opslimit,
                     memlimit,
                     alg))
        throw std::runtime_error{"crypto_pwhash failed (out of memory?)"};
}

}  // namespace session::hash::detail

extern "C" {

LIBSESSION_C_API bool session_hash(
        size_t size,
        const unsigned char* msg_in,
        size_t msg_len,
        const unsigned char* key_in,
        size_t key_len,
        unsigned char* hash_out) {
    try {
        std::optional<std::span<const std::byte>> key;

        if (key_in && key_len)
            key = std::span{reinterpret_cast<const std::byte*>(key_in), key_len};

        hash_impl(
                std::span{reinterpret_cast<std::byte*>(hash_out), size},
                std::span{reinterpret_cast<const std::byte*>(msg_in), msg_len},
                key);
        return true;
    } catch (...) {
        return false;
    }
}

}  // extern "C"
