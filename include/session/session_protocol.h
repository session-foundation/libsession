#pragma once

#include <stdint.h>

#include "export.h"
#include "types.h"

/// The C header for session_protocol. See the CPP header for more indepth comments. Only the
/// differences between the C and CPP headers are documented to avoid duplication.

#ifdef __cplusplus
extern "C" {
#endif

/// Protocol limit/padding constants. Each points at the C++ `session::*` value (defined there --
/// the primary; C references). Statically-initialized `const int`s (not compile-time constants).
/// - `SESSION_PROTOCOL_STANDARD_CHARACTER_LIMIT` -- max UTF-16 code points in a standard
///   (non-Pro) message; a longer one must activate the Session Pro higher-character-limit feature.
/// - `SESSION_PROTOCOL_PRO_HIGHER_CHARACTER_LIMIT` -- max UTF-16 code points a Pro user can send.
/// - `SESSION_PROTOCOL_STANDARD_PINNED_CONVERSATION_LIMIT` -- pins allowed without Session Pro.
/// - `SESSION_PROTOCOL_COMMUNITY_OR_1O1_MSG_PADDING` -- byte multiple a community/1o1 `Content` is
///   padded up to before wrapping in an envelope.
LIBSESSION_EXPORT extern const int SESSION_PROTOCOL_STANDARD_CHARACTER_LIMIT;
LIBSESSION_EXPORT extern const int SESSION_PROTOCOL_PRO_HIGHER_CHARACTER_LIMIT;
LIBSESSION_EXPORT extern const int SESSION_PROTOCOL_STANDARD_PINNED_CONVERSATION_LIMIT;
LIBSESSION_EXPORT extern const int SESSION_PROTOCOL_COMMUNITY_OR_1O1_MSG_PADDING;

/// Bundle of hard-coded strings that an implementing application may use for various scenarios.
/// Each is a static, null-terminated C string.
typedef struct session_protocol_strings {
    const char* build_variant_apk;
    const char* build_variant_fdroid;
    const char* build_variant_huawei;
    const char* build_variant_ipa;
    const char* url_donations;
    const char* url_donations_app;
    const char* url_download;
    const char* url_faq;
    const char* url_feedback;
    const char* url_network;
    const char* url_privacy_policy;
    const char* url_pro_access_not_found;
    const char* url_pro_faq;
    const char* url_pro_page;
    const char* url_pro_privacy_policy;
    const char* url_pro_roadmap;
    const char* url_pro_support;
    const char* url_pro_terms_of_service;
    const char* url_pro_upgrade;
    const char* url_staking;
    const char* url_support;
    const char* url_survey;
    const char* url_terms_of_service;
    const char* url_token;
    const char* url_translate;
} session_protocol_strings;
extern const session_protocol_strings SESSION_PROTOCOL_STRINGS;

typedef enum SESSION_PROTOCOL_PRO_STATUS {  // See session::ProStatus
    SESSION_PROTOCOL_PRO_STATUS_NIL,
    SESSION_PROTOCOL_PRO_STATUS_INVALID_PRO_BACKEND_SIG,
    SESSION_PROTOCOL_PRO_STATUS_INVALID_USER_SIG,
    SESSION_PROTOCOL_PRO_STATUS_VALID,
    SESSION_PROTOCOL_PRO_STATUS_EXPIRED,
    // Nothing could be evaluated, so the proof is unusable (see session::ProStatus::Invalid).
    SESSION_PROTOCOL_PRO_STATUS_INVALID,
} SESSION_PROTOCOL_PRO_STATUS;

typedef struct session_protocol_pro_signed_message {
    span_u8 sig;
    span_u8 msg;
} session_protocol_pro_signed_message;

typedef struct session_protocol_pro_proof {
    bytes32 revocation_tag;
    bytes32 rotating_pubkey;
    int64_t expiry_ts;
    bytes64 sig;
} session_protocol_pro_proof;

// Feature flags for profile features where each enum value indicates the bit position in the
// corresponding bitset, e.g. (1 << ENUM_VAL)
typedef enum SESSION_PROTOCOL_PRO_PROFILE_FEATURES {
    SESSION_PROTOCOL_PRO_PROFILE_FEATURES_PRO_BADGE,
    SESSION_PROTOCOL_PRO_PROFILE_FEATURES_ANIMATED_AVATAR,
    SESSION_PROTOCOL_PRO_PROFILE_FEATURES_COUNT,
} SESSION_PROTOCOL_PRO_PROFILE_FEATURES;

// Strongly typed bitset for profile features. Each profile enum value corresponds to the bit
// position to set on the bitset (e.g. 1 << ENUM_VALUE). This bitset is wrapped in a struct and has
// helper functions (`session_protocol_pro_profile_bitset_*` family of functions) that accepts the
// typed-enum to mitigate against mixing up the profile features with the message features.
//
// The enums are kept as bit positions (ENUM_VAL = 1 << N) instead of bit values (ENUM_VAL = 1)
// for ergonomic usage in the way we sync and store these bitsets on the protocol swarms. These
// bitsets are stored as sets which allows us to do diffs and deltas on the set of values. The
// syncing scheme does not allow bit-level deltas which makes handling conflicts between competing
// synced configurations, awkward.
typedef struct session_protocol_pro_profile_bitset {
    uint64_t data;
} session_protocol_pro_profile_bitset;

// Feature flags for message features where each enum value indicates the bit position in the
// corresponding bitset.
typedef enum SESSION_PROTOCOL_PRO_MESSAGE_FEATURES {
    SESSION_PROTOCOL_PRO_MESSAGE_FEATURES_10K_CHARACTER_LIMIT,
} SESSION_PROTOCOL_PRO_MESSAGE_FEATURES;

// Strongly typed bitset for Session Pro message features (see
// `session_protocol_pro_profile_bitset`)
typedef struct session_protocol_pro_message_bitset {
    uint64_t data;
} session_protocol_pro_message_bitset;

typedef enum SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS {  // See session::ProFeaturesForMsgStatus
    SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS_SUCCESS,
    SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS_EXCEEDS_CHARACTER_LIMIT,
} SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS;

typedef enum SESSION_PROTOCOL_DESTINATION_TYPE {  // See session::DestinationType
    SESSION_PROTOCOL_DESTINATION_TYPE_SYNC_OR_1O1,
    SESSION_PROTOCOL_DESTINATION_TYPE_GROUP,
    SESSION_PROTOCOL_DESTINATION_TYPE_COMMUNITY_INBOX,
    SESSION_PROTOCOL_DESTINATION_TYPE_COMMUNITY,
} SESSION_PROTOCOL_DESTINATION_TYPE;

typedef struct session_protocol_destination {  // See session::Destination
    SESSION_PROTOCOL_DESTINATION_TYPE type;
    const void* pro_rotating_ed25519_privkey;
    size_t pro_rotating_ed25519_privkey_len;
    bytes33 recipient_pubkey;
    uint64_t sent_timestamp_ms;
    bytes32 community_inbox_server_pubkey;
    bytes33 group_ed25519_pubkey;
    bytes32 group_enc_key;
} session_protocol_destination;

// Indicates which optional fields in the envelope has been populated out of the optional fields in
// an envelope after it has been parsed off the wire.
typedef uint32_t SESSION_PROTOCOL_ENVELOPE_FLAGS;
enum ENVELOPE_FLAGS_ {
    SESSION_PROTOCOL_ENVELOPE_FLAGS_SOURCE = 1 << 0,
    SESSION_PROTOCOL_ENVELOPE_FLAGS_SOURCE_DEVICE = 1 << 1,
    SESSION_PROTOCOL_ENVELOPE_FLAGS_SERVER_TIMESTAMP = 1 << 2,
    SESSION_PROTOCOL_ENVELOPE_FLAGS_PRO_SIG = 1 << 3,
    SESSION_PROTOCOL_ENVELOPE_FLAGS_TIMESTAMP = 1 << 4,
};

typedef struct session_protocol_envelope {
    SESSION_PROTOCOL_ENVELOPE_FLAGS flags;
    uint64_t timestamp_ms;
    bytes33 source;
    uint32_t source_device;
    uint64_t server_timestamp;
    bytes64 pro_sig;
} session_protocol_envelope;

typedef struct session_protocol_decode_envelope_keys {
    span_u8 group_ed25519_pubkey;
    const span_u8* decrypt_keys;
    size_t decrypt_keys_len;
} session_protocol_decode_envelope_keys;

typedef struct session_protocol_decoded_pro {
    SESSION_PROTOCOL_PRO_STATUS status;
    session_protocol_pro_proof proof;
    session_protocol_pro_message_bitset msg_bitset;
    session_protocol_pro_profile_bitset profile_bitset;
} session_protocol_decoded_pro;

typedef struct session_protocol_decoded_envelope {
    // Indicates if the decryption was successful. If the decryption step failed and threw an
    // exception, this is false.
    bool success;
    session_protocol_envelope envelope;
    span_u8 content_plaintext;
    bytes32 sender_ed25519_pubkey;
    bytes32 sender_x25519_pubkey;
    session_protocol_decoded_pro pro;
    size_t error_len_incl_null_terminator;
} session_protocol_decoded_envelope;

/// API: session_protocol/session_protocol_decode_envelope_free
///
/// Free the decoded result produced by `session_protocol_decode_envelope`. It is safe to pass a
/// `NULL` or any result returned by the decode function irrespective of if the function succeeded
/// or failed.
///
/// Inputs:
/// - `envelope` -- decoded result to free. This object is zeroed out on free and should no
///   longer be used after it is freed.
LIBSESSION_EXPORT void session_protocol_decode_envelope_free(
        session_protocol_decoded_envelope* envelope);

typedef struct session_protocol_encoded_for_destination {
    // Indicates if the encryption was successful. If any step failed and threw an exception, this
    // is false.
    bool success;
    span_u8 ciphertext;
    size_t error_len_incl_null_terminator;
} session_protocol_encoded_for_destination;

/// API: session_protocol/session_protocol_encode_for_destination_free
///
/// Free the encryption result for a destination produced by
/// `session_protocol_encrypt_for_destination`. It is safe to pass a `NULL` or any result returned
/// by the encrypt function irrespective of if the function succeeded or failed.
///
/// Inputs:
/// - `encrypt` -- Encryption result to free. This object is zeroed out on free and should no longer
///   be used after it is freed.
LIBSESSION_EXPORT void session_protocol_encode_for_destination_free(
        session_protocol_encoded_for_destination* encrypt);

typedef struct session_protocol_decoded_community_message {
    bool success;
    bool has_envelope;
    session_protocol_envelope envelope;
    span_u8 content_plaintext;
    bool has_pro;
    bytes64 pro_sig;
    session_protocol_decoded_pro pro;
    size_t error_len_incl_null_terminator;
} session_protocol_decoded_community_message;

/// API: session_protocol/session_protocol_decode_for_community_free
///
/// Free the decoded result produced by `session_protocol_decode_for_community`. It is safe to pass
/// a `NULL` or any result returned by the decode function irrespective of if the function
/// succeeded or failed.
///
/// Inputs:
/// - `community_msg` -- decoded result to free. This object is zeroed out on free and should no
///   longer be used after it is freed.
LIBSESSION_EXPORT void session_protocol_decode_for_community_free(
        session_protocol_decoded_community_message* community_msg);

/// API: session_protocol/session_protocol_pro_profile_bitset_is_set
///
/// Check if the feature flag is set on the bitset
LIBSESSION_EXPORT bool session_protocol_pro_profile_bitset_is_set(
        session_protocol_pro_profile_bitset value, SESSION_PROTOCOL_PRO_PROFILE_FEATURES features);

/// API: session_protocol/session_protocol_pro_profile_bitset_set
///
/// Set the feature flag on the bitset
LIBSESSION_EXPORT void session_protocol_pro_profile_bitset_set(
        session_protocol_pro_profile_bitset* value, SESSION_PROTOCOL_PRO_PROFILE_FEATURES features);

/// API: session_protocol/session_protocol_pro_profile_bitset_unset
///
/// Unset the feature flag on the bitset
LIBSESSION_EXPORT void session_protocol_pro_profile_bitset_unset(
        session_protocol_pro_profile_bitset* value, SESSION_PROTOCOL_PRO_PROFILE_FEATURES features);

/// API: session_protocol/session_protocol_pro_profile_bitset_is_set
///
/// Check if the feature flag is set on the bitset
LIBSESSION_EXPORT bool session_protocol_pro_message_bitset_is_set(
        session_protocol_pro_message_bitset value, SESSION_PROTOCOL_PRO_MESSAGE_FEATURES features);

/// API: session_protocol/session_protocol_pro_profile_bitset_set
///
/// Set the feature flag on the bitset
LIBSESSION_EXPORT void session_protocol_pro_message_bitset_set(
        session_protocol_pro_message_bitset* value, SESSION_PROTOCOL_PRO_MESSAGE_FEATURES features);

/// API: session_protocol/session_protocol_pro_profile_bitset_unset
///
/// Unset the feature flag on the bitset
LIBSESSION_EXPORT void session_protocol_pro_message_bitset_unset(
        session_protocol_pro_message_bitset* value, SESSION_PROTOCOL_PRO_MESSAGE_FEATURES features);

/// API: session_protocol/session_protocol_pro_proof_verify_signature
///
/// Verify the proof was signed by the `verify_pubkey`
///
/// Inputs:
/// - `proof` -- Proof to verify
/// - `verify_pubkey` -- Array of bytes containing the public key to (typically the Session Pro
///   Backend public key) verify the proof against.
/// - `verify_pubkey_len` -- Length of the `verify_pubkey` this must be 32 bytes, but is
///   parameterised to detect errors about incorrectly sized arrays by the caller.
///
/// Outputs:
/// - `bool` -- True if verified, false otherwise
LIBSESSION_EXPORT bool session_protocol_pro_proof_verify_signature(
        session_protocol_pro_proof const* proof,
        uint8_t const* verify_pubkey,
        size_t verify_pubkey_len) NON_NULL_ARG(1, 2);

/// API: session_protocol/session_protocol_pro_rotating_seed
///
/// Deterministically derive the rotating Session Pro seed for the 7-day seed period containing
/// `now_unix_ts` (see the C++ ProProof::rotating_seed). Every device on an account derives the
/// same 32-byte seed for the same period, so concurrent proof (re)generations converge rather than
/// racing. The 7-day quantization is a property of the derivation only, NOT the key-rotation
/// cadence (which the backend dictates via the proof expiry).
///
/// Inputs:
/// - `master_seed` -- the account's Session Pro master key/seed (from
///   session_ed25519_pro_privkey_for_ed25519_seed), NOT the session-id seed; first 32 bytes used.
/// - `now_unix_ts` -- the current unix time (seconds; floored to the 7-day seed period internally).
/// - `rotating_seed_out` -- [out] 32-byte buffer to receive the derived seed.
LIBSESSION_EXPORT void session_protocol_pro_rotating_seed(
        const unsigned char* master_seed, int64_t now_unix_ts, unsigned char* rotating_seed_out)
        NON_NULL_ARG(1, 3);

/// API: session_protocol/session_protocol_pro_proof_verify_message
///
/// Check if the `rotating_pubkey` in the proof was the signatory of the message and signature
/// passed in. This function throws if an signature is passed in that isn't 64 bytes.
///
/// Inputs:
/// - `proof` -- Proof to verify
/// - `sig` -- Signature to verify with the `rotating_pubkey`. The signature should have
///   originally been signed over `msg` passed in.
/// - `sig_len` -- Length of the signature, should be 64 bytes
/// - `msg` -- Message that the signature signed over with. It will be verified using the
///   embedded `rotating_pubkey`.
/// - `msg_len` -- Length of the message
///
/// Outputs:
/// - `bool` -- True if verified, false otherwise (bad signature, or, invalid arguments).
LIBSESSION_EXPORT bool session_protocol_pro_proof_verify_message(
        session_protocol_pro_proof const* proof,
        uint8_t const* sig,
        size_t sig_len,
        uint8_t const* msg,
        size_t msg_len) NON_NULL_ARG(1, 2, 4);

/// API: session_protocol/session_protocol_pro_proof_is_active
///
/// Check if the Pro proof is currently entitled to Pro given the `ts` with respect to the
/// proof's `expiry_at`
///
/// Inputs:
/// - `proof` -- Proof to verify
/// - `ts` -- The unix timestamp to check the proof expiry time against
///
/// Outputs:
/// - `bool` -- True if expired, false otherwise
LIBSESSION_EXPORT bool session_protocol_pro_proof_is_active(
        session_protocol_pro_proof const* proof, int64_t ts) NON_NULL_ARG(1);

/// API: session_protocol/session_protocol_pro_proof_status
///
/// Evaluate the status of the pro proof by checking it is signed by the `verify_pubkey`, it has
/// not expired via `ts` and optionally verify that the `signed_msg` was signed by the
/// `rotating_pubkey` embedded in the proof.
///
/// Internally this function calls `pro_proof_verify_signature`, `pro_proof_verify_message` and
/// optionally `pro_proof_is_active` in sequence. This function fails if an invalidly sized public
/// key or signature are passed in. They must be 32 and 64 bytes respectively, the appropriate
/// invalid status will be returned.
///
/// Inputs:
/// - `proof` -- Proof to verify
/// - `verify_pubkey` -- 32 byte Ed25519 public key of the corresponding secret key to check if
///   they are the original signatory of the proof.
/// - `verify_pubkey_len` -- Length of the `verify_pubkey` should be 32 bytes
///   they are the original signatory of the proof.
/// - `ts` -- Unix timestamp to compared against the embedded `expiry_at`
///   to determine if the proof has expired or not
/// - `signed_msg` -- Optionally set the payload to the message with the signature to verify if
///   the embedded `rotating_pubkey` in the proof signed the given message.
///
/// Outputs:
/// - `status` - The derived status given the components of the message. If `signed_msg` is
///   not set then this function can never return `PRO_STATUS_INVALID_USER_SIG` from the set of
///   possible enum values. Otherwise this funtion can return all possible values.
LIBSESSION_EXPORT SESSION_PROTOCOL_PRO_STATUS session_protocol_pro_proof_status(
        session_protocol_pro_proof const* proof,
        const uint8_t* verify_pubkey,
        size_t verify_pubkey_len,
        int64_t ts,
        OPTIONAL const session_protocol_pro_signed_message* signed_msg) NON_NULL_ARG(1, 2);

/// API: session_protocol/session_protocol_get_pro_features_for_msg
typedef struct session_protocol_pro_features_for_msg {
    SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS status;
    /// On error (status != OK), a static, null-terminated English diagnostic string; NULL when
    /// there is no error.
    const char* error;
    session_protocol_pro_message_bitset bitset;
} session_protocol_pro_features_for_msg;

/// API: session_protocol/session_protocol_pro_features_for_message
///
/// Determine the Pro features required for a message of the given length.
///
/// Inputs:
/// - `codepoint_count` -- the number of Unicode codepoints in the message. Callers count this
///   themselves (every platform's native string type counts codepoints directly).
///
/// Outputs:
/// - `status` -- Success, or EXCEEDS_CHARACTER_LIMIT when over the maximum. When not Success, only
///   `error` is meaningful.
/// - `error` -- On a non-Success status, a read-only diagnostic string; NULL otherwise.
/// - `bitset` -- Feature flags suitable for writing directly into the protobuf
///   `ProMessage.messageFeatures`
LIBSESSION_EXPORT
session_protocol_pro_features_for_msg session_protocol_pro_features_for_message(
        size_t codepoint_count);

/// API: session_protocol_encode_for_1o1
///
/// Encode a plaintext message for a one-on-one (1o1) conversation or sync message in the Session
/// Protocol. This function wraps the plaintext in the necessary structures and encrypts it for
/// transmission to a single recipient.
///
/// See: session_protocol/encode_for_1o1 for more information
///
/// The encoded result must be freed with session_protocol_encrypt_for_destination_free when
/// the caller is done with the result.
///
/// Inputs:
/// - `plaintext` -- The protobuf serialized payload containing the Content to be encrypted
/// - `plaintext_len` -- The length of the plaintext buffer in bytes.
/// - `ed25519_privkey` -- The sender's libsodium-style secret key (64 bytes). Can also be passed as
///   a 32-byte seed. Used to encrypt the plaintext.
/// - `ed25519_privkey_len` -- The length of the ed25519_privkey buffer in bytes (32 or 64).
/// - `sent_timestamp_ms` -- The timestamp to assign to the message envelope, in milliseconds. This
///   should match the protobuf encoded Content's `sigtimestamp` in the given `plaintext`.
/// - `pro_rotating_ed25519_privkey` -- Optional rotating Session Pro Ed25519 key (64-bytes or
///   32-byte seed) to sign the encoded content if you wish to entitle the message to Session Pro.
///   If provided, the corresponding proof must be set in the `Content`. The signature must not be
///   set in `Content`.
/// - `pro_rotating_ed25519_privkey_len` -- The length of the Session Pro Ed25519 key
/// - `error` -- Pointer to the character buffer to be populated with the error message if the
///   returned success was false, untouched otherwise. If this is set to NULL, then on failure,
///   the returned error_len_incl_null_terminator is the number of bytes required by the user to
///   receive the error. The message may be truncated if the buffer is too small, but it's always
///   guaranteed that error is null-terminated on failure when a buffer is passed in even if the
///   error must be truncated to fit in the buffer.
/// - `error_len` -- The capacity of the character buffer passed by the user. This should be 0 if
///   error is NULL. This function will fill the buffer up to error_len - 1 characters with the last
///   character reserved for the null-terminator.
///
/// Outputs:
/// - `success` -- True if encoding was successful, if the underlying implementation threw
///   an exception then this is caught internally and success is set to false. All remaining fields
///   are to be ignored in the result on failure.
/// - `ciphertext` -- Encryption result for the plaintext. The returned payload is suitable for
///   sending on the wire (i.e: it has been protobuf encoded/wrapped if necessary).
/// - `error_len_incl_null_terminator` -- The length of the error message if success was false. If
///   the user passes in a non-NULL error buffer this is the amount of characters written to the
///   error buffer. If the user passes in a NULL error buffer, this is the amount of characters
///   required to write the error. Both counts include the null-terminator. The user must allocate
///   at minimum the requested length for the error message to be preserved in full.
LIBSESSION_EXPORT
session_protocol_encoded_for_destination session_protocol_encode_for_1o1(
        const void* plaintext,
        size_t plaintext_len,
        const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        uint64_t sent_timestamp_ms,
        const bytes33* recipient_pubkey,
        OPTIONAL const void* pro_rotating_ed25519_privkey,
        size_t pro_rotating_ed25519_privkey_len,
        OPTIONAL char* error,
        size_t error_len) NON_NULL_ARG(1, 3, 6);

/// API: session_protocol_encode_for_community_inbox
///
/// Encode a plaintext message for a community inbox in the Session Protocol. This function wraps
/// the plaintext in the necessary structures and encrypts it for transmission to a community inbox
/// server.
///
/// See: session_protocol/encode_for_community_inbox for more information
///
/// The encoded result must be freed with session_protocol_encrypt_for_destination_free when
/// the caller is done with the result.
///
/// Inputs:
/// - `plaintext `-- The protobuf serialized payload containing the Content to be encrypted. Must
///   not be already encrypted.
/// - `plaintext_len` -- The length of the plaintext buffer in bytes.
/// - `ed25519_privkey` -- The sender's libsodium-style secret key (64 bytes). Can also be passed as
///   a 32-byte seed. Used to encrypt the plaintext.
/// - `ed25519_privkey_len` -- The length of the ed25519_privkey buffer in bytes (32 or 64).
/// - `recipient_pubkey` -- The recipient's Session public key (33 bytes).
/// - `community_pubkey` -- The community inbox server's public key (32 bytes).
/// - `pro_rotating_ed25519_privkey` -- Optional rotating Session Pro Ed25519 key (64-bytes or
///   32-byte seed) to sign the encoded content if you wish to entitle the message to Session Pro.
///   If provided, the corresponding proof must be set in the `Content`. The signature must not be
///   set in `Content`.
/// - `pro_rotating_ed25519_privkey_len` -- The length of the Session Pro Ed25519 key
/// - `error` -- Pointer to the character buffer to be populated with the error message if the
///   returned success was false, untouched otherwise. If this is set to NULL, then on failure,
///   the returned error_len_incl_null_terminator is the number of bytes required by the user to
///   receive the error. The message may be truncated if the buffer is too small, but it's always
///   guaranteed that error is null-terminated on failure when a buffer is passed in even if the
///   error must be truncated to fit in the buffer.
/// - `error_len` -- The capacity of the character buffer passed by the user. This should be 0 if
///   error is NULL. This function will fill the buffer up to error_len - 1 characters with the
///   last character reserved for the null-terminator.
///
/// Outputs:
/// - `success` -- True if encoding was successful, if the underlying implementation threw
///   an exception then this is caught internally and success is set to false. All remaining fields
///   are to be ignored in the result on failure.
/// - `ciphertext` -- Encryption result for the plaintext. The returned payload is suitable for
///   sending on the wire (i.e: it has been protobuf encoded/wrapped if necessary).
/// - `error_len_incl_null_terminator` -- The length of the error message if success was false. If
///   the user passes in a non-NULL error buffer this is the amount of characters written to the
///   error buffer. If the user passes in a NULL error buffer, this is the amount of characters
///   required to write the error. Both counts include the null-terminator. The user must allocate
///   at minimum the requested length in order for the error message to be preserved in full.

LIBSESSION_EXPORT
session_protocol_encoded_for_destination session_protocol_encode_for_community_inbox(
        const void* plaintext,
        size_t plaintext_len,
        const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        const bytes33* recipient_pubkey,
        const bytes32* community_pubkey,
        OPTIONAL const void* pro_rotating_ed25519_privkey,
        size_t pro_rotating_ed25519_privkey_len,
        OPTIONAL char* error,
        size_t error_len) NON_NULL_ARG(1, 3, 5, 6);

/// API: session_protocol_encode_for_community
///
/// Encode a plaintext `Content` message for a community in the Session Protocol. This function
/// encodes Session Pro metadata including generating and embedding the Session Pro signature, when
/// given a Session Pro rotating Ed25519 key into the final payload suitable for transmission on the
/// wire.
///
/// See: session_protocol/encode_for_community for more information
///
/// The encoded result must be freed with session_protocol_encrypt_for_destination_free when
/// the caller is done with the result.
///
/// Inputs:
/// - `plaintext `-- The protobuf serialized payload containing the Content to be encrypted. Must
///   not be already encrypted.
/// - `plaintext_len` -- The length of the plaintext buffer in bytes.
/// - `pro_rotating_ed25519_privkey` -- Optional rotating Session Pro Ed25519 key (64-bytes or
///   32-byte seed) to sign the encoded content if you wish to entitle the message to Session Pro.
///   If provided, the corresponding proof must be set in the `Content`. The signature must not be
///   set in `Content`.
/// - `pro_rotating_ed25519_privkey_len` -- The length of the Session Pro Ed25519 key
/// - `error` -- Pointer to the character buffer to be populated with the error message if the
///   returned success was false, untouched otherwise. If this is set to NULL, then on failure,
///   the returned error_len_incl_null_terminator is the number of bytes required by the user to
///   receive the error. The message may be truncated if the buffer is too small, but it's always
///   guaranteed that error is null-terminated on failure when a buffer is passed in even if the
///   error must be truncated to fit in the buffer.
/// - `error_len` -- The capacity of the character buffer passed by the user. This should be 0 if
///   error is NULL. This function will fill the buffer up to error_len - 1 characters with the
///   last character reserved for the null-terminator.
///
/// Outputs:
/// - `success` -- True if encoding was successful, if the underlying implementation threw
///   an exception then this is caught internally and success is set to false. All remaining fields
///   are to be ignored in the result on failure.
/// - `ciphertext` -- Encryption result for the plaintext. The returned payload is suitable for
///   sending on the wire (i.e: it has been protobuf encoded/wrapped if necessary).
/// - `error_len_incl_null_terminator` -- The length of the error message if success was false. If
///   the user passes in a non-NULL error buffer this is the amount of characters written to the
///   error buffer. If the user passes in a NULL error buffer, this is the amount of characters
///   required to write the error. Both counts include the null-terminator. The user must allocate
///   at minimum the requested length in order for the error message to be preserved in full.
LIBSESSION_EXPORT
session_protocol_encoded_for_destination session_protocol_encode_for_community(
        const void* plaintext,
        size_t plaintext_len,
        OPTIONAL const void* pro_rotating_ed25519_privkey,
        size_t pro_rotating_ed25519_privkey_len,
        OPTIONAL char* err,
        size_t error_len) NON_NULL_ARG(1);

/// API: session_protocol_encode_for_group
///
/// Encode a plaintext message for a group in the Session Protocol. This function wraps the
/// plaintext in the necessary structures and encrypts it for transmission to a group, using the
/// group's encryption key. Only v2 groups, (0x03) prefixed keys are supported. Passing a legacy
/// group (0x05) prefixed key will cause the function to return a failure with an error message.
///
/// See: session_protocol/encode_for_group for more information
///
/// The encoded result must be freed with session_protocol_encrypt_for_destination_free when
/// the caller is done with the result.
///
/// Inputs:
/// - `plaintext` -- The protobuf serialized payload containing the Content to be encrypted. Must
///   not be already encrypted.
/// - `plaintext_len` -- The length of the plaintext buffer in bytes.
/// - `ed25519_privkey` -- The sender's libsodium-style secret key (64 bytes). Can also be passed as
///   a 32-byte seed. Used to encrypt the plaintext.
/// - `ed25519_privkey_len` -- The length of the ed25519_privkey buffer in bytes (32 or 64).
/// - `sent_timestamp_ms` -- The timestamp to assign to the message envelope, in milliseconds.
/// - `group_ed25519_pubkey` -- The group's public key (33 bytes) for encryption with a 0x03 prefix.
/// - `group_enc_key` -- The group's encryption key (32 bytes) for groups v2 messages, typically the
//    latest key for the group (e.g., Keys::group_enc_key).
/// - `pro_rotating_ed25519_privkey` -- Optional rotating Session Pro Ed25519 key (64-bytes or
///   32-byte seed) to sign the encoded content if you wish to entitle the message to Session Pro.
///   If provided, the corresponding proof must be set in the `Content`. The signature must not be
///   set in `Content`.
/// - `pro_rotating_ed25519_privkey_len` -- The length of the Session Pro Ed25519 key
/// - `error` -- Pointer to the character buffer to be populated with the error message if the
///   returned success was false, untouched otherwise. If this is set to NULL, then on failure,
///   the returned error_len_incl_null_terminator is the number of bytes required by the user to
///   receive the error. The message may be truncated if the buffer is too small, but it's always
///   guaranteed that error is null-terminated on failure when a buffer is passed in even if the
///   error must be truncated to fit in the buffer.
/// - `error_len` -- The capacity of the character buffer passed by the user. This should be 0 if
///   error is NULL. This function will fill the buffer up to error_len - 1 characters with the
///   last character reserved for the null-terminator.
///
/// Outputs:
/// - `success` -- True if encoding was successful, if the underlying implementation threw
///   an exception then this is caught internally and success is set to false. All remaining fields
///   are to be ignored in the result on failure.
/// - `ciphertext` -- Encryption result for the plaintext. The returned payload is suitable for
///   sending on the wire (i.e: it has been protobuf encoded/wrapped if necessary).
/// - `error_len_incl_null_terminator` -- The length of the error message if success was false. If
///   the user passes in a non-NULL error buffer this is the amount of characters written to the
///   error buffer. If the user passes in a NULL error buffer, this is the amount of characters
///   required to write the error. Both counts include the null-terminator. The user must allocate
///   at minimum the requested length in order for the error message to be preserved in full.
LIBSESSION_EXPORT
session_protocol_encoded_for_destination session_protocol_encode_for_group(
        const void* plaintext,
        size_t plaintext_len,
        const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        uint64_t sent_timestamp_ms,
        const bytes33* group_ed25519_pubkey,
        const bytes32* group_enc_key,
        OPTIONAL const void* pro_rotating_ed25519_privkey,
        size_t pro_rotating_ed25519_privkey_len,
        OPTIONAL char* error,
        size_t error_len) NON_NULL_ARG(1, 3, 6, 7);

/// API: session_protocol/session_protocol_encrypt_for_destination
///
/// Given an unencrypted plaintext representation of the content (i.e.: protobuf encoded stream of
/// `Content`), encrypt and/or wrap the plaintext in the necessary structures for transmission on
/// the Session Protocol.
///
/// See: session_protocol/encrypt_for_destination for more information
///
/// The encoded result must be freed with `session_protocol_encrypt_for_destination_free` when
/// the caller is done with the result.
///
/// Inputs:
/// - `plaintext` -- the protobuf serialised payload containing the protobuf encoded stream,
///   `Content`. It must not be already be encrypted.
/// - `ed25519_privkey` -- the libsodium-style secret key of the sender, 64 bytes. Can also be
///   passed as a 32-byte seed. Used to encrypt the plaintext.
/// - `dest` -- the extra metadata indicating the destination of the message and the necessary data
///   to encrypt a message for that destination.
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
/// - `success` -- True if encoding was successful, if the underlying implementation threw
///   an exception then this is caught internally and success is set to false. All remaining fields
///   are to be ignored in the result on failure.
/// - `ciphertext` -- Encryption result for the plaintext. The retured payload is suitable for
///   sending on the wire (i.e: it has been protobuf encoded/wrapped if necessary).
/// - `error_len_incl_null_terminator` The length of the error message if `success` was false. If
///   the user passes in an non-`NULL` error buffer this is amount of characters written to the
///   error buffer. If the user passes in a `NULL` error buffer, this is the amount of characters
///   required to write the error. Both counts include the null-terminator. The user must allocate
///   at minimum the requested length for the error message to be preserved in full.
LIBSESSION_EXPORT
session_protocol_encoded_for_destination session_protocol_encode_for_destination(
        const void* plaintext,
        size_t plaintext_len,
        OPTIONAL const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        const session_protocol_destination* dest,
        OPTIONAL char* error,
        size_t error_len) NON_NULL_ARG(1, 5);

/// API: session_protocol/session_protocol_decode_envelope
///
/// Given an envelope payload (i.e.: protobuf encoded stream of `WebsocketRequestMessage` which
/// wraps an `Envelope` for 1o1 messages/sync messages, or `Envelope` encrypted using a Groups v2
/// key) parse (or decrypt) the envelope and return the envelope content decrypted if necessary.
///
/// See: session_protocol/decode_envelope for more information
///
/// The decoded result must be freed with `session_protocol_decode_for_community_free` when the
/// caller is done with the result.
///
/// Inputs:
/// - `pro_backend_pubkey` -- the Session Pro backend public key to verify the signature embedded in
///   the proof, validating whether or not the attached proof was indeed issued by an authorised
///   issuer. Ignored if there's no proof in the message.
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
/// - `success` -- True if encoding was successful, if the underlying implementation threw
///   an exception then this is caught internally and success is set to false. All remaining fields
///   in the result are to be ignored on failure.
/// - `envelope` -- Envelope structure that was decrypted/parsed from the `envelope_plaintext`
/// - `content_plaintext` -- Decrypted contents of the envelope structure. This is the protobuf
///   encoded stream that can be parsed into a protobuf `Content` structure.
///
///   The plaintext must be freed by the CRT's `free` after the caller is done with the memory.
/// - `sender_ed25519_pubkey` -- The sender's ed25519 public key embedded in the encrypted payload.
///   This is only set for session message envelopes. Groups envelopes only embed the sender's
///   x25519 public key in which case this field is set to the zero public key.
/// - `sender_x25519_pubkey` -- The sender's x25519 public key. It's always set on successful
///   decryption either by extracting the key from the encrypted groups envelope, or, by deriving
///   the x25519 key from the sender's ed25519 key in the case of a session message envelope.
/// - `pro_status` -- The pro status associated with the envelope, if any, that the sender has
///   embedded into the envelope being parsed. This field is set to nil if there was no pro metadata
///   associated with the envelope.
///
///   This field should be used to determine the presence of pro and whether or not the caller
///   can respect the contents of the pro proof and features. A valid pro proof that can be used
///   effectively after parsing is indicated by this value being set to the Valid enum.
/// - `pro_proof` -- The pro proof in the envelope. This field is set to all zeros if `pro_status`
///   was nil, otherwise it's populated with proof data.
/// - `pro_features` -- Pro features that were activated in this envelope by the sender. This field
///   is only set if `pro_status` is not nil. It should only be enforced if the `pro_status` was
///   the Valid enum.
/// - `error_len_incl_null_terminator` The length of the error message if `success` was false. If
///   the user passes in an non-`NULL` error buffer this is amount of characters written to the
///   error buffer. If the user passes in a `NULL` error buffer, this is the amount of characters
///   required to write the error. Both counts include the null-terminator. The user must allocate
///   at minimum the requested length for the error message to be preserved in full.
LIBSESSION_EXPORT
session_protocol_decoded_envelope session_protocol_decode_envelope(
        const session_protocol_decode_envelope_keys* keys,
        const void* envelope_plaintext,
        size_t envelope_plaintext_len,
        OPTIONAL const void* pro_backend_pubkey,
        size_t pro_backend_pubkey_len,
        OPTIONAL char* error,
        size_t error_len) NON_NULL_ARG(1, 2);

/// API: session_protocol/session_protocol_decode_for_community
///
/// Given an unencrypted content or envelope payload extract the plaintext to the content and any
/// associated pro metadata if there was any in the message.
///
/// Inputs:
/// - `content_or_envelope_payload` -- the unencrypted content or envelope payload containing the
///   community message
/// - `ts` -- pass in the current system time which is used to determine, whether or
///   not the Session Pro proof has expired or not if it is in the payload. Ignored if there's no
///   proof in the message.
/// - `pro_backend_pubkey` -- the Session Pro backend public key to verify the signature embedded in
///   the proof, validating whether or not the attached proof was indeed issued by an authorised
///   issuer
///
/// Outputs:
/// - `envelope` -- Envelope structure that was parsed from the `content_or_envelope_payload` if the
///   payload was an envelope. Nil otherwise.
/// - `content_plaintext` -- The protobuf encoded stream that can be parsed into a protobuf
///   `Content` structure that was extracted from the `content_or_envelope_payload`
/// - `has_pro` -- Flag that indicates if the `pro` struct was populated or not.
/// - `pro_sig` -- Optional pro signature if there was one located in the
///   `content_or_envelope_payload`. This is the same signature as the one located in the `envelope`
///   object if the original payload was an envelope.
/// - `pro` -- Optional object that is set if there was pro metadata associatd with the envelope, if
///   any. The `status` field in the decrypted pro object should be used to determine whether or not
///   the caller can respect the contents of the `proof` and `features`.
/// - `error_len_incl_null_terminator` -- The length of the error message if success was false. If
///   the user passes in a non-NULL error buffer this is the amount of characters written to the
///   error buffer. If the user passes in a NULL error buffer, this is the amount of characters
///   required to write the error. Both counts include the null-terminator. The user must allocate
///   at minimum the requested lengthin order for the error message to be preserved in full.
///
///   If the `status` is set to valid the the caller can proceed with entitling the envelope with
///   access to pro features if it's using any.
LIBSESSION_EXPORT session_protocol_decoded_community_message session_protocol_decode_for_community(
        const void* content_or_envelope_payload,
        size_t content_or_envelope_payload_len,
        int64_t ts,
        OPTIONAL const void* pro_backend_pubkey,
        size_t pro_backend_pubkey_len,
        OPTIONAL char* error,
        size_t error_len) NON_NULL_ARG(1);

#ifdef __cplusplus
}
#endif
