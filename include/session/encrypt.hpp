#pragma once

#include <cstddef>
#include <span>

namespace session::encryption {

// ─── Constants ───────────────────────────────────────────────────────────────

inline constexpr size_t XCHACHA20_KEYBYTES = 32;
inline constexpr size_t XCHACHA20_NONCEBYTES = 24;
inline constexpr size_t XCHACHA20_ABYTES = 16;  // authentication tag size

inline constexpr size_t HCHACHA20_OUTPUTBYTES = 32;
inline constexpr size_t HCHACHA20_INPUTBYTES = 16;
inline constexpr size_t HCHACHA20_KEYBYTES = 32;

inline constexpr size_t BOX_PUBLICKEYBYTES = 32;
inline constexpr size_t BOX_SECRETKEYBYTES = 32;
inline constexpr size_t BOX_MACBYTES = 16;
inline constexpr size_t BOX_NONCEBYTES = 24;
inline constexpr size_t BOX_SEALBYTES = BOX_PUBLICKEYBYTES + BOX_MACBYTES;  // 48

inline constexpr size_t SECRETBOX_KEYBYTES = 32;
inline constexpr size_t SECRETBOX_NONCEBYTES = 24;
inline constexpr size_t SECRETBOX_MACBYTES = 16;

// ─── XChaCha20-Poly1305 AEAD ─────────────────────────────────────────────────

/// Encrypts `msg` with `key` and `nonce`, writing ciphertext (msg.size() + ABYTES bytes) into
/// `out`.
void xchacha20poly1305_encrypt(
        std::span<std::byte> out,
        std::span<const std::byte> msg,
        std::span<const std::byte, XCHACHA20_NONCEBYTES> nonce,
        std::span<const std::byte, XCHACHA20_KEYBYTES> key);

/// Decrypts `ciphertext` with `key` and `nonce`, writing plaintext (ciphertext.size() - ABYTES
/// bytes) into `out`.  Returns false if authentication fails.
bool xchacha20poly1305_decrypt(
        std::span<std::byte> out,
        std::span<const std::byte> ciphertext,
        std::span<const std::byte, XCHACHA20_NONCEBYTES> nonce,
        std::span<const std::byte, XCHACHA20_KEYBYTES> key);

// ─── XChaCha20 stream ────────────────────────────────────────────────────────

/// XOR-encrypts/decrypts `in` with the XChaCha20 keystream derived from `nonce` and `key`,
/// writing the result into `out`.  `out` and `in` must be the same size and may alias.
void xchacha20_xor(
        std::span<std::byte> out,
        std::span<const std::byte> in,
        std::span<const std::byte, XCHACHA20_NONCEBYTES> nonce,
        std::span<const std::byte, XCHACHA20_KEYBYTES> key);

// ─── HChaCha20 ───────────────────────────────────────────────────────────────

/// Derives a 32-byte subkey from a 32-byte key and a 16-byte nonce prefix using HChaCha20.
/// This is the subkey-derivation step used internally by XChaCha20.
void hchacha20(
        std::span<std::byte, HCHACHA20_OUTPUTBYTES> out,
        std::span<const std::byte, HCHACHA20_INPUTBYTES> nonce_prefix,
        std::span<const std::byte, HCHACHA20_KEYBYTES> key);

// ─── Box (X25519 + XSalsa20-Poly1305) ────────────────────────────────────────

/// Encrypts `msg` for `recipient_pk` from `sender_sk`, writing ciphertext into `out`.
/// `out` must be `msg.size() + BOX_MACBYTES` bytes.
void box_easy(
        std::span<std::byte> out,
        std::span<const std::byte> msg,
        std::span<const std::byte, BOX_NONCEBYTES> nonce,
        std::span<const std::byte, BOX_PUBLICKEYBYTES> recipient_pk,
        std::span<const std::byte, BOX_SECRETKEYBYTES> sender_sk);

/// Seals `msg` for `pk` (anonymous sender), writing ciphertext into `out`.
/// `out` must be `msg.size() + BOX_SEALBYTES` bytes.
void box_seal(
        std::span<std::byte> out,
        std::span<const std::byte> msg,
        std::span<const std::byte, BOX_PUBLICKEYBYTES> pk);

/// Decrypts a sealed box.  `out` must be `ciphertext.size() - BOX_SEALBYTES` bytes.
/// Returns false if authentication fails.
bool box_seal_open(
        std::span<std::byte> out,
        std::span<const std::byte> ciphertext,
        std::span<const std::byte, BOX_PUBLICKEYBYTES> pk,
        std::span<const std::byte, BOX_SECRETKEYBYTES> sk);

// ─── Secretbox (XSalsa20-Poly1305 with shared key) ───────────────────────────

/// Decrypts a secretbox ciphertext using a shared key.  `out` must be
/// `ciphertext.size() - SECRETBOX_MACBYTES` bytes.  Returns false if authentication fails.
bool secretbox_open_easy(
        std::span<std::byte> out,
        std::span<const std::byte> ciphertext,
        std::span<const std::byte, SECRETBOX_NONCEBYTES> nonce,
        std::span<const std::byte, SECRETBOX_KEYBYTES> key);

}  // namespace session::encryption
