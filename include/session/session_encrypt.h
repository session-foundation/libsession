#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "export.h"
#include "types.h"

/// API: crypto/session_encrypt_for_recipient_deterministic
///
/// This function attempts to encrypt a message using the SessionProtocol.
///
/// Inputs:
/// - `plaintext_in` -- [in] Pointer to a data buffer containing the encrypted data.
/// - `plaintext_len` -- [in] Length of `plaintext_in`
/// - `ed25519_privkey` -- [in] the Ed25519 private key of the sender (64 bytes).
/// - `recipient_pubkey` -- [in] the x25519 public key of the recipient (32 bytes).
/// - `ciphertext_out` -- [out] Pointer-pointer to an output buffer; a new buffer is allocated, the
///   encrypted data written to it, and then the pointer to that buffer is stored here.
///   This buffer must be `free()`d by the caller when done with it *unless* the function returns
///   false, in which case the buffer pointer will not be set.
/// - `ciphertext_len` -- [out] Pointer to a size_t where the length of `ciphertext_out` is stored.
///   Not touched if the function returns false.
///
/// Outputs:
/// - `bool` -- True if the message was successfully decrypted, false if decryption failed.  If
///   (and only if) true is returned then `plaintext_out` must be freed when done with it.
LIBSESSION_EXPORT bool session_encrypt_for_recipient_deterministic(
        const unsigned char* plaintext_in,
        size_t plaintext_len,
        const unsigned char* ed25519_privkey,  /* 64 bytes */
        const unsigned char* recipient_pubkey, /* 32 bytes */
        unsigned char** ciphertext_out,
        size_t* ciphertext_len);

/// API: crypto/session_encrypt_for_blinded_recipient
///
/// This function attempts to encrypt a message using the SessionBlindingProtocol.
///
/// Inputs:
/// - `plaintext_in` -- [in] Pointer to a data buffer containing the encrypted data.
/// - `plaintext_len` -- [in] Length of `plaintext_in`
/// - `ed25519_privkey` -- [in] the Ed25519 private key of the sender (64 bytes).
/// - `community_pubkey` -- [in] the public key of the community server to route
///   the blinded message through (32 bytes).
/// - `recipient_blinded_id` -- [in] the blinded id of the recipient including the blinding
///   prefix (33 bytes), 'blind15' or 'blind25' encryption will be chosed based on this value.
/// - `ciphertext_out` -- [out] Pointer-pointer to an output buffer; a new buffer is allocated, the
///   encrypted data written to it, and then the pointer to that buffer is stored here.
///   This buffer must be `free()`d by the caller when done with it *unless* the function returns
///   false, in which case the buffer pointer will not be set.
/// - `ciphertext_len` -- [out] Pointer to a size_t where the length of `ciphertext_out` is stored.
///   Not touched if the function returns false.
///
/// Outputs:
/// - `bool` -- True if the message was successfully decrypted, false if decryption failed.  If
///   (and only if) true is returned then `plaintext_out` must be freed when done with it.
LIBSESSION_EXPORT bool session_encrypt_for_blinded_recipient(
        const unsigned char* plaintext_in,
        size_t plaintext_len,
        const unsigned char* ed25519_privkey,      /* 64 bytes */
        const unsigned char* community_pubkey,     /* 32 bytes */
        const unsigned char* recipient_blinded_id, /* 33 bytes */
        unsigned char** ciphertext_out,
        size_t* ciphertext_len);

typedef struct session_encrypt_group_message {
    bool success;
    span_u8 ciphertext;
    size_t error_len_incl_null_terminator;
} session_encrypt_group_message;

/// API: crypto/session_encrypt_for_group
///
/// Compresses, signs, and encrypts group message content.
///
/// See: crypto/encrypt_for_group
///
/// This function will set `success` to false on failure:
/// - if any of the keys passed in are invalidly sized or non-valid keys
/// - if there no encryption keys are available at all (which should not occur in normal use).
/// - if given a plaintext buffer larger than 1MB (even if the compressed version would be much
///   smaller).  It is recommended that clients impose their own limits much smaller than this
///   on data passed into encrypt_message; this limitation is in *this* function to match the
///   `decrypt_message` limit which is merely intended to guard against decompression memory
///   exhaustion attacks.
///
/// Inputs:
/// - `user_ed25519_privkey` -- the private key of the user. Can be a 32-byte seed, or a 64-byte
///   libsodium secret key.  The latter is a bit faster as it doesn't have to re-compute the pubkey
/// - `group_ed25519_pubkey` -- the 32 byte public key of the group
/// - `group_enc_key` -- The group's encryption key (32 bytes) for groups v2 messages, typically the
///   latest key for the group (e.g., groups_keys_group_enc_key).
///   libsodium secret key
/// - `plaintext` -- the binary message to encrypt.
/// - `compress` -- can be specified as `false` to forcibly disable compression.  Normally
///   omitted, to use compression if and only if it reduces the size.
/// - `padding` -- the padding multiple: padding will be added as needed to attain a multiple of
///   this value for the final result.  0 or 1 disables padding entirely.  Normally omitted to
///   use the default of next-multiple-of-256.
/// - `error` -- Pointer to the character buffer to be populated with the error message if the
///   returned `success` was false, untouched otherwise. If this is set to `NULL`, then on failure,
///   the returned `error_len_incl_null_terminator` is the number of bytes required by the user to
///   receive the error. The message may be truncated if the buffer is too small, but it's always
///   guaranteed that `error` is null-terminated on failure when a buffer is passed in even if the
///   error must be truncated to fit in the buffer.
/// - `error_len` -- The capacity of the character buffer passed by the user. This should be 0 if
///   `error` is NULL. This function will fill the buffer up to `error_len - 1` characters with the
///   last character reserved for the null-terminator.
///
/// Outputs:
/// - `success` -- True if the encryption was successful, false otherwise
/// - `ciphertext` -- the encrypted, etc. value to send to the swarm. This ciphertext must be freed
///   with the CRT's `free` when the caller is done with the memory.
/// - `error_len_incl_null_terminator` The length of the error message if `success` was false. If
///   the user passes in an non-`NULL` error buffer this is amount of characters written to the
///   error buffer. If the user passes in a `NULL` error buffer, this is the amount of characters
///   required to write the error. Both counts include the null-terminator. The user must allocate
///   at minimum the requested length, including the null-terminator in order for the error message
///   to be preserved in full.
LIBSESSION_EXPORT session_encrypt_group_message session_encrypt_for_group(
        const unsigned char* user_ed25519_privkey,
        size_t user_ed25519_privkey_len,
        const unsigned char* group_ed25519_pubkey,
        const unsigned char* group_enc_key,
        size_t group_enc_key_len,
        const unsigned char* plaintext,
        size_t plaintext_len,
        bool compress,
        size_t padding,
        char* error,
        size_t error_len);

/// API: crypto/session_decrypt_incoming
///
/// This function attempts to decrypt a message using the SessionProtocol.
///
/// Inputs:
/// - `ciphertext_in` -- [in] Pointer to a data buffer containing the encrypted data.
/// - `ciphertext_len` -- [in] Length of `ciphertext_in`
/// - `ed25519_privkey` -- [in] the Ed25519 private key of the receiver (64 bytes).
/// - `session_id_out` -- [out] pointer to a buffer of at least 67 bytes where the null-terminated,
///   hex-encoded session_id of the message's author will be written if decryption/verification was
///   successful.
/// - `plaintext_out` -- [out] Pointer-pointer to an output buffer; a new buffer is allocated, the
///   decrypted data written to it, and then the pointer to that buffer is stored here.
///   This buffer must be `free()`d by the caller when done with it *unless* the function returns
///   false, in which case the buffer pointer will not be set.
/// - `plaintext_len` -- [out] Pointer to a size_t where the length of `plaintext_out` is stored.
///   Not touched if the function returns false.
///
/// Outputs:
/// - `bool` -- True if the message was successfully decrypted, false if decryption failed.  If
///   (and only if) true is returned then `plaintext_out` must be freed when done with it.
LIBSESSION_EXPORT bool session_decrypt_incoming(
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* ed25519_privkey, /* 64 bytes */
        char* session_id_out,                 /* 67 byte output buffer */
        unsigned char** plaintext_out,
        size_t* plaintext_len);

/// API: crypto/session_decrypt_incoming_legacy_group
///
/// This function attempts to decrypt a message using the SessionProtocol.
///
/// Inputs:
/// - `ciphertext_in` -- [in] Pointer to a data buffer containing the encrypted data.
/// - `ciphertext_len` -- [in] Length of `ciphertext_in`
/// - `x25519_pubkey` -- [in] the x25519 public key of the receiver (32 bytes).
/// - `x25519_seckey` -- [in] the x25519 secret key of the receiver (32 bytes).
/// - `session_id_out` -- [out] pointer to a buffer of at least 67 bytes where the null-terminated,
///   hex-encoded session_id of the message's author will be written if decryption/verification was
///   successful.
/// - `plaintext_out` -- [out] Pointer-pointer to an output buffer; a new buffer is allocated, the
///   decrypted data written to it, and then the pointer to that buffer is stored here.
///   This buffer must be `free()`d by the caller when done with it *unless* the function returns
///   false, in which case the buffer pointer will not be set.
/// - `plaintext_len` -- [out] Pointer to a size_t where the length of `plaintext_out` is stored.
///   Not touched if the function returns false.
///
/// Outputs:
/// - `bool` -- True if the message was successfully decrypted, false if decryption failed.  If
///   (and only if) true is returned then `plaintext_out` must be freed when done with it.
LIBSESSION_EXPORT bool session_decrypt_incoming_legacy_group(
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* x25519_pubkey, /* 32 bytes */
        const unsigned char* x25519_seckey, /* 32 bytes */
        char* session_id_out,               /* 67 byte output buffer */
        unsigned char** plaintext_out,
        size_t* plaintext_len);

/// API: crypto/session_decrypt_for_blinded_recipient
///
/// This function attempts to decrypt a message using the SessionBlindingProtocol.
///
/// Inputs:
/// - `ciphertext_in` -- [in] Pointer to a data buffer containing the encrypted data.
/// - `ciphertext_len` -- [in] Length of `ciphertext_in`
/// - `ed25519_privkey` -- [in] the Ed25519 private key of the receiver (64 bytes).
/// - `community_pubkey` -- [in] the public key of the community server to route
///   the blinded message through (32 bytes).
/// - `sender_id` -- [in] the blinded id of the sender including the blinding prefix (33 bytes),
///   'blind15' or 'blind25' decryption will be chosed based on this value.
/// - `recipient_id` -- [in] the blinded id of the recipient including the blinding prefix (33
/// bytes),
///   must match the same 'blind15' or 'blind25' type of the `sender_id`.
/// - `session_id_out` -- [out] pointer to a buffer of at least 67 bytes where the null-terminated,
///   hex-encoded session_id of the message's author will be written if decryption/verification was
///   successful.
/// - `plaintext_out` -- [out] Pointer-pointer to an output buffer; a new buffer is allocated, the
///   decrypted data written to it, and then the pointer to that buffer is stored here.
///   This buffer must be `free()`d by the caller when done with it *unless* the function returns
///   false, in which case the buffer pointer will not be set.
/// - `plaintext_len` -- [out] Pointer to a size_t where the length of `plaintext_out` is stored.
///   Not touched if the function returns false.
///
/// Outputs:
/// - `bool` -- True if the message was successfully decrypted, false if decryption failed.  If
///   (and only if) true is returned then `plaintext_out` must be freed when done with it.
LIBSESSION_EXPORT bool session_decrypt_for_blinded_recipient(
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* ed25519_privkey,  /* 64 bytes */
        const unsigned char* community_pubkey, /* 32 bytes */
        const unsigned char* sender_id,        /* 33 bytes */
        const unsigned char* recipient_id,     /* 33 bytes */
        char* session_id_out,                  /* 67 byte output buffer */
        unsigned char** plaintext_out,
        size_t* plaintext_len);

typedef struct session_decrypt_group_message_result {
    bool success;
    size_t index;         // Index of the key that successfully decrypted the message
    char session_id[66];  // In hex
    span_u8 plaintext;    // Decrypted message on success. Must be freed by calling the CRT's `free`
    char error_len_incl_null_terminator;
} session_decrypt_group_message_result;

/// API: crypto/session_decrypt_group_message
///
/// Decrypts group message content that was presumably encrypted with `session_encrypt_for_group`,
/// verifies the sender signature, decompresses the message (if necessary) and then returns the
/// author pubkey and the plaintext data.
///
/// See: crypto/decrypt_group_message
///
/// Inputs:
/// - `decrypt_ed25519_privkey_list` -- the list of private keys to try to decrypt the message with.
///   Can be a 32-byte seed, or a 64-byte libsodium secret key. The public key component is not
///   used.
/// - `group_ed25519_pubkey` -- the 32 byte public key of the group
/// - `ciphertext` -- an encrypted, encoded, signed, (possibly) compressed message as produced
///   by `encrypt_message()`.
/// - `error` -- Pointer to the character buffer to be populated with the error message if the
///   returned `success` was false, untouched otherwise. If this is set to `NULL`, then on failure,
///   the returned `error_len_incl_null_terminator` is the number of bytes required by the user to
///   receive the error. The message may be truncated if the buffer is too small, but it's always
///   guaranteed that `error` is null-terminated on failure when a buffer is passed in even if the
///   error must be truncated to fit in the buffer.
/// - `error_len` -- The capacity of the character buffer passed by the user. This should be 0 if
///   `error` is NULL. This function will fill the buffer up to `error_len - 1` characters with the
///   last character reserved for the null-terminator.
///
/// Outputs:
/// - `success` -- True if the decryption was successful, false otherwise
/// - `index` -- Index of the key that successfully decrypted the message if decryption was
///   successful.
/// - `session_id` -- The 66 byte 05 prefixed session ID of the user that sent the message
/// - `plaintext` -- Decrypted message if successful. This plaintext must be freed with the CRT's
///   `free` when the caller is done with the memory.
/// - `error_len_incl_null_terminator` The length of the error message if `success` was false. If
///   the user passes in an non-`NULL` error buffer this is amount of characters written to the
///   error buffer. If the user passes in a `NULL` error buffer, this is the amount of characters
///   required to write the error. Both counts include the null-terminator. The user must allocate
///   at minimum the requested length, including the null-terminator in order for the error message
///   to be preserved in full.
LIBSESSION_EXPORT session_decrypt_group_message_result session_decrypt_group_message(
        const span_u8* decrypt_ed25519_privkey_list,
        size_t decrypt_ed25519_privkey_len,
        const unsigned char* group_ed25519_pubkey,
        const unsigned char* ciphertext,
        size_t ciphertext_len,
        char* error,
        size_t error_len);

/// API: crypto/session_decrypt_ons_response
///
/// This function attempts to decrypt an ONS response.
///
/// Inputs:
/// - `lowercase_name_in` -- [in] Pointer to a NULL-terminated buffer containing the lowercase name
/// used to trigger the response.
/// - `ciphertext_in` -- [in] Pointer to a data buffer containing the encrypted data.
/// - `ciphertext_len` -- [in] Length of `ciphertext_in`.
/// - `nonce_in` -- [in, optional] Pointer to a data buffer containing the nonce (24 bytes) or NULL.
/// - `session_id_out` -- [out] pointer to a buffer of at least 67 bytes where the null-terminated,
///   hex-encoded session_id will be written if decryption was successful.
///
/// Outputs:
/// - `bool` -- True if the session ID was successfully decrypted, false if decryption failed.
LIBSESSION_EXPORT bool session_decrypt_ons_response(
        const char* lowercase_name_in,
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* nonce_in, /* 24 bytes or NULL */
        char* session_id_out /* 67 byte output buffer */);

/// API: crypto/session_decrypt_push_notification
///
/// Decrypts a push notification payload.
///
/// Inputs:
/// - `payload_in` -- [in] the payload included in the push notification.
/// - `payload_len` -- [in] Length of `payload_in`.
/// - `enc_key_in` -- [in] the device encryption key used when subscribing for push notifications
/// (32 bytes).
/// - `plaintext_out` -- [out] Pointer-pointer to an output buffer; a new buffer is allocated, the
///   decrypted data written to it, and then the pointer to that buffer is stored here.
///   This buffer must be `free()`d by the caller when done with it *unless* the function returns
///   false, in which case the buffer pointer will not be set.
/// - `plaintext_len` -- [out] Pointer to a size_t where the length of `plaintext_out` is stored.
///   Not touched if the function returns false.
///
/// Outputs:
/// - `bool` -- True if the decryption was successful, false if decryption failed.
LIBSESSION_EXPORT bool session_decrypt_push_notification(
        const unsigned char* payload_in,
        size_t payload_len,
        const unsigned char* enc_key_in, /* 32 bytes */
        unsigned char** plaintext_out,
        size_t* plaintext_len);

/// API: crypto/session_encrypt_xchacha20
///
/// Encrypts a value with a given key using xchacha20.
///
/// Inputs:
/// - `plaintext_in` -- [in] the data to encrypt.
/// - `plaintext_len` -- [in] the length of `plaintext_in`.
/// - `enc_key_in` -- [in] the key to use for encryption (32 bytes).
/// - `ciphertext_out` -- [out] Pointer-pointer to an output buffer; a new buffer is allocated, the
///   encrypted data written to it, and then the pointer to that buffer is stored here.
///   This buffer must be `free()`d by the caller when done with it *unless* the function returns
///   false, in which case the buffer pointer will not be set.
/// - `ciphertext_len` -- [out] Pointer to a size_t where the length of `ciphertext_out` is stored.
///   Not touched if the function returns false.
///
/// Outputs:
/// - `bool` -- True if the encryption was successful, false if encryption failed.
LIBSESSION_EXPORT bool session_encrypt_xchacha20(
        const unsigned char* plaintext_in,
        size_t plaintext_len,
        const unsigned char* enc_key_in, /* 32 bytes */
        unsigned char** ciphertext_out,
        size_t* ciphertext_len);

/// API: crypto/session_decrypt_xchacha20
///
/// Decrypts a value that was encrypted with the `encrypt_xchacha20` function.
///
/// Inputs:
/// - `ciphertext_in` -- [in] the data to decrypt.
/// - `ciphertext_len` -- [in] the length of `ciphertext_in`.
/// - `enc_key_in` -- [in] the key to use for decryption (32 bytes).
/// - `plaintext_out` -- [out] Pointer-pointer to an output buffer; a new buffer is allocated, the
///   decrypted data written to it, and then the pointer to that buffer is stored here.
///   This buffer must be `free()`d by the caller when done with it *unless* the function returns
///   false, in which case the buffer pointer will not be set.
/// - `plaintext_len` -- [out] Pointer to a size_t where the length of `plaintext_out` is stored.
///   Not touched if the function returns false.
///
/// Outputs:
/// - `bool` -- True if the decryption was successful, false if decryption failed.
LIBSESSION_EXPORT bool session_decrypt_xchacha20(
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* enc_key_in, /* 32 bytes */
        unsigned char** plaintext_out,
        size_t* plaintext_len);

#ifdef __cplusplus
}
#endif
