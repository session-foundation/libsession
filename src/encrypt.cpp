#include "session/encrypt.hpp"

#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_core_hchacha20.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_stream_xchacha20.h>

#include <stdexcept>

#include "session/util.hpp"

namespace session::encryption {

// The header spells these out so that it need not include libsodium; they must track libsodium's
// values exactly.
static_assert(XCHACHA20_KEYBYTES == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
static_assert(XCHACHA20_KEYBYTES == crypto_stream_xchacha20_KEYBYTES);
static_assert(XCHACHA20_NONCEBYTES == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
static_assert(XCHACHA20_NONCEBYTES == crypto_stream_xchacha20_NONCEBYTES);
static_assert(XCHACHA20_ABYTES == crypto_aead_xchacha20poly1305_ietf_ABYTES);
static_assert(HCHACHA20_OUTPUTBYTES == crypto_core_hchacha20_OUTPUTBYTES);
static_assert(HCHACHA20_INPUTBYTES == crypto_core_hchacha20_INPUTBYTES);
static_assert(HCHACHA20_KEYBYTES == crypto_core_hchacha20_KEYBYTES);
static_assert(BOX_PUBLICKEYBYTES == crypto_box_PUBLICKEYBYTES);
static_assert(BOX_SECRETKEYBYTES == crypto_box_SECRETKEYBYTES);
static_assert(BOX_MACBYTES == crypto_box_MACBYTES);
static_assert(BOX_NONCEBYTES == crypto_box_NONCEBYTES);
static_assert(BOX_SEALBYTES == crypto_box_SEALBYTES);
static_assert(SECRETBOX_KEYBYTES == crypto_secretbox_KEYBYTES);
static_assert(SECRETBOX_NONCEBYTES == crypto_secretbox_NONCEBYTES);
static_assert(SECRETBOX_MACBYTES == crypto_secretbox_MACBYTES);

void xchacha20poly1305_encrypt(
        std::span<std::byte> out,
        std::span<const std::byte> msg,
        std::span<const std::byte, XCHACHA20_NONCEBYTES> nonce,
        std::span<const std::byte, XCHACHA20_KEYBYTES> key) {
    crypto_aead_xchacha20poly1305_ietf_encrypt(
            ucdata(out),
            nullptr,
            ucdata(msg),
            msg.size(),
            nullptr,
            0,
            nullptr,
            ucdata(nonce),
            ucdata(key));
}

bool xchacha20poly1305_decrypt(
        std::span<std::byte> out,
        std::span<const std::byte> ciphertext,
        std::span<const std::byte, XCHACHA20_NONCEBYTES> nonce,
        std::span<const std::byte, XCHACHA20_KEYBYTES> key) {
    return 0 == crypto_aead_xchacha20poly1305_ietf_decrypt(
                        ucdata(out),
                        nullptr,
                        nullptr,
                        ucdata(ciphertext),
                        ciphertext.size(),
                        nullptr,
                        0,
                        ucdata(nonce),
                        ucdata(key));
}

void xchacha20_xor(
        std::span<std::byte> out,
        std::span<const std::byte> in,
        std::span<const std::byte, XCHACHA20_NONCEBYTES> nonce,
        std::span<const std::byte, XCHACHA20_KEYBYTES> key) {
    crypto_stream_xchacha20_xor(ucdata(out), ucdata(in), in.size(), ucdata(nonce), ucdata(key));
}

void hchacha20(
        std::span<std::byte, HCHACHA20_OUTPUTBYTES> out,
        std::span<const std::byte, HCHACHA20_INPUTBYTES> nonce_prefix,
        std::span<const std::byte, HCHACHA20_KEYBYTES> key) {
    crypto_core_hchacha20(ucdata(out), ucdata(nonce_prefix), ucdata(key), nullptr);
}

void box_easy(
        std::span<std::byte> out,
        std::span<const std::byte> msg,
        std::span<const std::byte, BOX_NONCEBYTES> nonce,
        std::span<const std::byte, BOX_PUBLICKEYBYTES> recipient_pk,
        std::span<const std::byte, BOX_SECRETKEYBYTES> sender_sk) {
    if (0 != crypto_box_easy(
                     ucdata(out),
                     ucdata(msg),
                     msg.size(),
                     ucdata(nonce),
                     ucdata(recipient_pk),
                     ucdata(sender_sk)))
        throw std::runtime_error{"crypto_box_easy failed (invalid public key?)"};
}

void box_seal(
        std::span<std::byte> out,
        std::span<const std::byte> msg,
        std::span<const std::byte, BOX_PUBLICKEYBYTES> pk) {
    if (0 != crypto_box_seal(ucdata(out), ucdata(msg), msg.size(), ucdata(pk)))
        throw std::runtime_error{"crypto_box_seal failed (invalid public key?)"};
}

bool box_seal_open(
        std::span<std::byte> out,
        std::span<const std::byte> ciphertext,
        std::span<const std::byte, BOX_PUBLICKEYBYTES> pk,
        std::span<const std::byte, BOX_SECRETKEYBYTES> sk) {
    return 0 == crypto_box_seal_open(
                        ucdata(out), ucdata(ciphertext), ciphertext.size(), ucdata(pk), ucdata(sk));
}

bool secretbox_open_easy(
        std::span<std::byte> out,
        std::span<const std::byte> ciphertext,
        std::span<const std::byte, SECRETBOX_NONCEBYTES> nonce,
        std::span<const std::byte, SECRETBOX_KEYBYTES> key) {
    return 0 ==
           crypto_secretbox_open_easy(
                   ucdata(out), ucdata(ciphertext), ciphertext.size(), ucdata(nonce), ucdata(key));
}

}  // namespace session::encryption
