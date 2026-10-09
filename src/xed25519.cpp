#include "session/xed25519.hpp"

#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/randombytes.h>

#include <cassert>
#include <cstring>
#include <stdexcept>

#include "session/export.h"
#include "session/util.hpp"

namespace session::xed25519 {

template <size_t N>
using bytes = std::array<unsigned char, N>;

namespace {

    // We construct an Ed25519-like signature with one important difference: where Ed25519
    // calculates `r = H(S || M) mod L` (where S is the second half of the SHA-512 hash of the
    // secret key) we instead calculate `r = H(a || M || Z) mod L`.
    //
    // This deviates from Signal's XEd25519 specified derivation of r in that we use a personalized
    // Black2b hash (for better performance and cryptographic properties), rather than a
    // custom-prefixed SHA-512 hash.
    bytes<32> xed25519_compute_r(const bytes<32>& a, std::span<const unsigned char> msg) {
        bytes<64> random;
        randombytes_buf(random.data(), random.size());

        constexpr static bytes<16> personality = {
                'x', 'e', 'd', '2', '5', '5', '1', '9', 's', 'i', 'g', 'n', 'a', 't', 'u', 'r'};

        crypto_generichash_blake2b_state st;
        static_assert(personality.size() == crypto_generichash_blake2b_PERSONALBYTES);
        crypto_generichash_blake2b_init_salt_personal(
                &st, nullptr, 0, 64, nullptr, personality.data());
        crypto_generichash_blake2b_update(&st, a.data(), a.size());
        crypto_generichash_blake2b_update(&st, msg.data(), msg.size());
        crypto_generichash_blake2b_update(&st, random.data(), random.size());
        bytes<64> h_aMZ;
        crypto_generichash_blake2b_final(&st, h_aMZ.data(), h_aMZ.size());

        bytes<32> r;
        crypto_core_ed25519_scalar_reduce(r.data(), h_aMZ.data());
        return r;
    }

    // Assigns S = H(R || A || M) mod L
    void ed25519_hram(
            unsigned char* S,
            const unsigned char* R,
            const bytes<32>& A,
            std::span<const unsigned char> msg) {
        bytes<64> hram;
        crypto_hash_sha512_state st;
        crypto_hash_sha512_init(&st);
        crypto_hash_sha512_update(&st, R, 32);
        crypto_hash_sha512_update(&st, A.data(), A.size());
        crypto_hash_sha512_update(&st, msg.data(), msg.size());
        crypto_hash_sha512_final(&st, hram.data());

        crypto_core_ed25519_scalar_reduce(S, hram.data());
    }

}  // namespace

bytes<64> sign(
        std::span<const unsigned char, 32> curve25519_privkey, std::span<const unsigned char> msg) {

    bytes<32> A;
    // Convert the x25519 privkey to an ed25519 pubkey:
    crypto_scalarmult_ed25519_base(A.data(), curve25519_privkey.data());

    // Signal's XEd25519 spec requires that the sign bit be zero, so if it isn't we negate.
    bool negative = A[31] >> 7;

    A[31] &= 0x7f;

    bytes<32> a, neg_a;
    std::memcpy(a.data(), curve25519_privkey.data(), a.size());
    crypto_core_ed25519_scalar_negate(neg_a.data(), a.data());
    constant_time_conditional_assign(a, neg_a, negative);

    // We now have our a, A privkey/public.  (Note that a is just the private key scalar, *not* the
    // ed25519 secret key).

    bytes<32> r = xed25519_compute_r(a, msg);
    bytes<64> signature;  // R || S
    auto* R = signature.data();
    auto* S = signature.data() + 32;

    crypto_scalarmult_ed25519_base_noclamp(R, r.data());

    // Now we have compute S = r + H(R || A || M)a
    ed25519_hram(S, R, A, msg);                      // S = H(R||A||M)
    crypto_core_ed25519_scalar_mul(S, S, a.data());  // S *= a
    crypto_core_ed25519_scalar_add(S, S, r.data());  // S += r

    return signature;
}

std::string sign(std::string_view curve25519_privkey, std::string_view msg) {
    auto privkey = to_span(curve25519_privkey);
    if (privkey.size() != 32)
        throw std::invalid_argument{"Invalid curve25519_privkey: expected 32 bytes"};

    auto sig = sign(privkey.first<32>(), to_span(msg));
    return std::string{reinterpret_cast<const char*>(sig.data()), sig.size()};
}

bool verify(
        std::span<const unsigned char, 64> signature,
        std::span<const unsigned char, 32> curve25519_pubkey,
        std::span<const unsigned char> msg) {
    auto ed_pubkey = pubkey(curve25519_pubkey);
    return 0 == crypto_sign_ed25519_verify_detached(
                        signature.data(), msg.data(), msg.size(), ed_pubkey.data());
}

bool verify(std::string_view signature, std::string_view curve25519_pubkey, std::string_view msg) {
    auto sig = to_span(signature);
    if (sig.size() != crypto_sign_ed25519_BYTES)
        throw std::invalid_argument{"Invalid signature: expected 64 bytes"};

    auto pubkey = to_span(curve25519_pubkey);
    if (pubkey.size() != 32)
        throw std::invalid_argument{"Invalid curve25519_pubkey: expected 32 bytes"};

    return verify(sig.first<64>(), pubkey.first<32>(), to_span(msg));
}

// pubkey(std::span<const unsigned char, 32>) is in xed25519-tweetnacl.cpp

std::string pubkey(std::string_view curve25519_pubkey) {
    auto x_pk = to_span(curve25519_pubkey);
    if (x_pk.size() != 32)
        throw std::invalid_argument{"Invalid curve25519_pubkey: expected 32 bytes"};

    auto ed_pk = pubkey(x_pk.first<32>());
    return std::string{reinterpret_cast<const char*>(ed_pk.data()), ed_pk.size()};
}

}  // namespace session::xed25519

extern "C" {

LIBSESSION_C_API bool session_xed25519_sign(
        unsigned char* signature,
        const unsigned char* curve25519_privkey,
        const unsigned char* msg,
        size_t msg_len) {
    assert(signature != NULL);
    try {
        auto sig = session::xed25519::sign(
                std::span<const unsigned char, 32>{curve25519_privkey, 32}, {msg, msg_len});
        std::memcpy(signature, sig.data(), sig.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_xed25519_verify(
        const unsigned char* signature,
        const unsigned char* pubkey,
        const unsigned char* msg,
        size_t msg_len) {
    return session::xed25519::verify(
            std::span<const unsigned char, 64>{signature, 64},
            std::span<const unsigned char, 32>{pubkey, 32},
            {msg, msg_len});
}

LIBSESSION_C_API bool session_xed25519_pubkey(
        unsigned char* ed25519_pubkey, const unsigned char* curve25519_pubkey) {
    assert(ed25519_pubkey != NULL);
    try {
        auto edpk = session::xed25519::pubkey(
                std::span<const unsigned char, 32>{curve25519_pubkey, 32});
        std::memcpy(ed25519_pubkey, edpk.data(), edpk.size());
        return true;
    } catch (...) {
        return false;
    }
}

}  // extern "C"
