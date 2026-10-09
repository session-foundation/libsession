#pragma once

#include <session/session_protocol.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <session/sodium_array.hpp>
#include <session/types.hpp>
#include <span>

/// A complimentary file to session encrypt (which has the low level encryption function for Session
/// protocol types). This file contains high-level helper functions for decoding payloads on the
/// Session protocol. Prefer functions here before resorting to the lower-level cryptography.
///
/// The general overview is that this file introduces functionality to abstract away protobufs types
/// on the Session Protocol from client implementations by wrapping the data structures where
/// necessary in libsession. In general clients will use the functions in this file as follows:
///
/// - Derive Session Pro feature flags from a message for populating the new Pro fields for messages
///
/// - Wrap and/or encrypt a plaintext content message into an Envelope or Websocket message
///   (depending on the configured namespace and destination) ready to be sent on the wire with
///   `encode_for_destination`.
///
/// - Decrypt an incoming message in its websocket wrapped, and or encrypted envelope form with
///   `decode_envelope`
///
/// TODO: In future the goal is to begin abstracting more protobuf types away from client
/// implementations such that the only dependency clients need to encode and decode Session Protocol
/// messages is libsession itself and that it will provide wrapper/proxy types for and handle
/// converting those into the wire format.

// NOTE: In the CPP file we use C-style enums for bitfields and CPP-style enums for non-bitfield
// enums where we can to benefit from the type-safety of strong enums.
//
// CPP doesn't support named bitfields without casting or operator overloads but C-style
// enums support it very well. The only issue is that using a native C-style enum enforces some type
// restrictions that compilers dislike when attempting to manipulate bit fields. For example:
//
//   enum Feature {x = 1 << 0, y = 1 << 1}
//   Feature f = x | y
//
// Causes the compiler to complain about trying to do bit ops/assign an unsigned integer to an enum
// `Feature`. We use a common C pattern/trick by suffixing an underscore to the the original enum,
// then type define the non-suffixed enum to an unsigned integer:
//
//   enum Feature_ {x = 1 << 0, y = 1 << 1}
//   typedef U64 Feature
//   Feature f = x | y
//
// Does not trigger errors as the underlying type of `f` is actually an unsigned integer. The type
// define is merely a hint to the user to what flags are to be used when manipulating the variable.

namespace session {

using namespace std::literals;

/// Maximum number of UTF-16 code points a standard (non-Pro) message can use; a longer message must
/// activate the Session Pro higher-character-limit feature. (The C `SESSION_PROTOCOL_*` symbols
/// point at these.)
inline constexpr int STANDARD_CHARACTER_LIMIT = 2000;
/// Maximum number of UTF-16 code points a Session Pro entitled user can send. Not used internally;
/// provided to centralise the protocol definition for library consumers.
inline constexpr int PRO_HIGHER_CHARACTER_LIMIT = 10000;
/// Number of conversations a user without Session Pro can pin.
inline constexpr int STANDARD_PINNED_CONVERSATION_LIMIT = 5;
/// Byte multiple a community or 1o1 message `Content` is padded up to before wrapping in an
/// envelope.
inline constexpr int COMMUNITY_OR_1O1_MSG_PADDING = 160;

// Session Pro 16-byte signing domain prefixes; each prefixes the Ed25519-signed message for its
// endpoint (pro-wire-protocol.md §2 proof, §3 signed requests). ASCII, `_`-right-padded to 16
// bytes (formerly the BLAKE2b personalisation, back when messages were pre-hashed).
//
// BUILD_PROOF_DOMAIN is also what pins a proof to its format: the `_v0` in it is part of the signed
// bytes, so a proof of some future format signed under its own domain simply fails verification
// here. That is why a proof carries no version field of its own -- and why this literal is a wire
// constant that must not be "tidied up" along with any C++ renaming.
inline constexpr std::string_view GENERATE_PROOF_DOMAIN = "ProGenerateProof";
inline constexpr std::string_view BUILD_PROOF_DOMAIN = "ProProof_v0_____";
inline constexpr std::string_view GET_PRO_STATUS_DOMAIN = "ProGetProStatus_";
inline constexpr std::string_view GET_PAYMENT_DETAILS_DOMAIN = "ProGetPayDetails";
static_assert(GENERATE_PROOF_DOMAIN.size() == 16);
static_assert(BUILD_PROOF_DOMAIN.size() == 16);
static_assert(GET_PRO_STATUS_DOMAIN.size() == 16);
static_assert(GET_PAYMENT_DETAILS_DOMAIN.size() == 16);

/// Rotation window for the Session Pro rotating key: ProProof::rotating_seed yields the same seed
/// for all timestamps within one such period and a fresh one at each boundary.
inline constexpr auto PRO_ROTATING_SEED_PERIOD = 7 * 24h;

/// How long before a proof's expiry a client preemptively renews it -- and, correspondingly, the
/// minimum remaining entitlement (access expiry beyond now) that makes a preemptive renewal worth
/// doing. See UserProfile::pro_renewal_target.
///
/// Do NOT increase this beyond 60min without a coordinating backend change: the Pro backend sizes
/// the padding on its proof-expiry grid around exactly this 1h lead, so a client that begins
/// renewing at the lead always reaches the backend after the subscription's grace-inclusive true
/// end. Renewing earlier than 1h before expiry would arrive before the upstream store's final
/// chance to report a renewal, yielding a spurious `subscription_expired` on a subscription that is
/// in fact renewing.
inline constexpr auto PRO_RENEWAL_LEAD = 60min;

/// When a renewal has come due but the current time lands right at a rotating-seed period boundary,
/// pro_renewal_target defers it by this long rather than renewing at the ambiguous instant, giving
/// a device cleanly on one side of the boundary a chance to renew first. Best-effort collision
/// avoidance only.
inline constexpr auto PRO_RENEWAL_BOUNDARY_DEFER = 1min;

/// The boundary deferral above is skipped (renew now instead) unless the deferred renewal would
/// still leave at least this much of the current proof's validity.
inline constexpr auto PRO_RENEWAL_BOUNDARY_MIN_VALIDITY = 5min;

enum class ProStatus {
    // Pro proof sig was not signed by the Pro backend key
    InvalidProBackendSig = SESSION_PROTOCOL_PRO_STATUS_INVALID_PRO_BACKEND_SIG,
    // Pro sig in the envelope was not signed by the Rotating key
    InvalidUserSig = SESSION_PROTOCOL_PRO_STATUS_INVALID_USER_SIG,
    Valid = SESSION_PROTOCOL_PRO_STATUS_VALID,      // Proof is verified; has not expired
    Expired = SESSION_PROTOCOL_PRO_STATUS_EXPIRED,  // Proof is verified; has expired
    // Nothing could be evaluated, so whatever is in DecodedPro::proof is not to be trusted. Today
    // this means the message carried no proof we can read: either the sender attached none, or it
    // is in a format this client does not know -- a new proof format is a new field/message rather
    // than a version bump on the existing one, so to an older client it simply does not appear as
    // `proof`. Deliberately the general "unusable proof" answer rather than a reason-specific one,
    // so a future unreadable-proof case needs no new status and no caller has to learn one. Such a
    // message is delivered as non-pro rather than dropped, so a future proof format costs the
    // sender their Pro affordances on old clients instead of costing them the whole message.
    Invalid = SESSION_PROTOCOL_PRO_STATUS_INVALID,
};

class ProProof {
  public:
    /// Opaque revocation tag identifying this proof (from the Session Pro backend)
    array_uc32 revocation_tag;

    /// The public key that the Session client registers their Session Pro entitlement under.
    /// Session clients must sign messages with this key along side the sending of this proof for
    /// the network to authenticate their usage of the proof
    array_uc32 rotating_pubkey;

    /// Unix epoch timestamp to which this proof's entitlement to Session Pro features is valid to
    sys_seconds expiry_at;

    /// Signature over the contents of the proof. It is signed by the Session Pro Backend key which
    /// is the entity responsible for issueing tamper-proof Sesison Pro certificates for Session
    /// clients.
    array_uc64 sig;

    /// API: pro/Proof::verify_signature
    ///
    /// Verify that the proof's contents was not tampered with by hashing the proof and checking
    /// that the hash was signed by the secret key of the given Ed25519 public key.
    ///
    /// For Session Pro intents and purposes, we expect proofs to be signed by the Session Pro
    /// Backend public key. This function throws if an incorrectly sized key is passed in.
    ///
    /// Inputs:
    /// - `verify_pubkey` -- 32 byte Ed25519 public key of the corresponding secret key to check if
    /// they are the original signatory of the proof.
    ///
    /// Outputs:
    /// - `bool` - True if the given key was the signatory of the proof, false otherwise
    bool verify_signature(const std::span<const uint8_t>& verify_pubkey) const;

    /// API: pro/Proof::verify_message
    ///
    /// Check if the `rotating_pubkey` in the proof was the signatory of the message and signature
    /// passed in. This function throws if an signature is passed in that isn't 64 bytes.
    ///
    /// Inputs:
    /// - `sig` -- Signature to verify with the `rotating_pubkey`. The signature should have
    ///   originally been signed over `msg` passed in.
    /// - `msg` -- Message that the signature signed over with. It will be verified using the
    ///   embedded `rotating_pubkey`.
    ///
    /// Outputs:
    /// - `bool` - True if the message was signed by the embedded `rotating_pubkey` false otherwise.
    bool verify_message(std::span<const uint8_t> sig, const std::span<const uint8_t> msg) const;

    /// API: pro/Proof::is_active
    ///
    /// Check if Pro proof is currently entitled to Pro given the `unix_ts` with respect to the
    /// proof's `expiry_at`
    ///
    /// Inputs:
    /// - `unix_ts` -- Unix timestamp to compare against the embedded `expiry_at`
    ///   to determine if the proof has expired or not
    ///
    /// Outputs:
    /// - `bool` - True if proof is active (i.e. has not expired), false otherwise.
    bool is_active(sys_seconds unix_ts) const;

    /// API: pro/Proof::status
    ///
    /// Evaluate the status of the pro proof by checking it is signed by the `verify_pubkey`, it has
    /// not expired via `unix_ts` and optionally verify that the `signed_msg` was signed by the
    /// `rotating_pubkey` embedded in the proof.
    ///
    /// Internally this function calls `verify_signature`, `verify_message` and optionally
    /// `is_active` in sequence. This function throws if an invalidly sized public key or signature
    /// are passed in. They must be 32 and 64 bytes respectively.
    ///
    /// Inputs:
    /// - `verify_pubkey` -- 32 byte Ed25519 public key of the corresponding secret key to check if
    ///   they are the original signatory of the proof.
    /// - `unix_ts` -- Unix timestamp to compared against the embedded `expiry_at`
    ///   to determine if the proof has expired or not
    /// - `user_sig` -- optionally, the user's 64-byte signature over `signed_msg`; when set, this
    ///   verifies that the proof's embedded `rotating_pubkey` produced it. Omit (the default) to
    ///   skip the user-signature check.
    /// - `signed_msg` -- the message bytes that `user_sig` signs; ignored when `user_sig` is unset.
    ///
    /// Outputs:
    /// - `ProStatus` - The derived status given the components of the message. If `user_sig` is
    ///   not set then this function can never return `ProStatus::InvalidUserSig` from the set of
    ///   possible enum values. Otherwise this funtion can return all possible values.
    ProStatus status(
            std::span<const uint8_t> verify_pubkey,
            sys_seconds unix_ts,
            std::optional<std::span<const uint8_t>> user_sig = std::nullopt,
            std::span<const uint8_t> signed_msg = {}) const;

    /// API: pro/Proof::signed_message
    ///
    /// Build the exact byte string that the backend signs to produce this proof's `sig`, and that
    /// verification reconstructs to check it (pro-wire-protocol.md §2, per §1.1). The message is
    /// Ed25519-signed directly — there is no pre-hash.
    std::vector<unsigned char> signed_message() const;

    /// API: pro/Proof::rotating_seed
    ///
    /// Deterministically derive the rotating Session Pro seed for the 7-day seed period containing
    /// `now`. Every device deriving "as of `now`" gets the same seed with no coordination, so
    /// concurrent proof (re)generations converge on one credential instead of racing. The 7-day
    /// quantization is a property of this derivation only; it is NOT the key-rotation cadence,
    /// which is dictated by the backend via the proof expiry. The seed is the private counterpart
    /// of the `rotating_pubkey` a proof for this period authorizes: it is fed to
    /// generate_pro_proof, and once the backend returns a signed proof for it the same seed is
    /// persisted in the config credential (its `r`) and is what subsequently signs Pro messages.
    ///
    /// Inputs:
    /// - `master_seed` -- the account's Session Pro *master* key/seed (as produced by
    ///   ed25519_pro_privkey_for_ed25519_seed), NOT the session-id seed; its first 32 bytes are
    ///   used. Rooting rotating keys under the Pro master keeps all Pro key material in one
    ///   hierarchy and lets the Pro subsystem avoid ever touching the account's identity seed.
    /// - `now` -- the current time (floored to the 7-day seed period internally).
    ///
    /// Outputs:
    /// - The 32-byte rotating seed (secret; zeroed on destruction).
    static cleared_uc32 rotating_seed(
            std::span<const unsigned char> master_seed, std::chrono::sys_seconds now);

    bool operator==(const ProProof& other) const {
        return revocation_tag == other.revocation_tag && rotating_pubkey == other.rotating_pubkey &&
               expiry_at == other.expiry_at && sig == other.sig;
    }
};

enum class ProFeaturesForMsgStatus {
    Success = SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS_SUCCESS,

    /// Message exceeded the maximum character limit allowed for Session Pro
    ExceedsCharacterLimit = SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS_EXCEEDS_CHARACTER_LIMIT,
};

struct ProProfileBitset {
    uint64_t data;
    void set(SESSION_PROTOCOL_PRO_PROFILE_FEATURES features);
    void unset(SESSION_PROTOCOL_PRO_PROFILE_FEATURES features);
    bool is_set(SESSION_PROTOCOL_PRO_PROFILE_FEATURES features) const;
};

struct ProMessageBitset {
    uint64_t data;
    void set(SESSION_PROTOCOL_PRO_MESSAGE_FEATURES features);
    void unset(SESSION_PROTOCOL_PRO_MESSAGE_FEATURES features);
    bool is_set(SESSION_PROTOCOL_PRO_MESSAGE_FEATURES features) const;
};

struct ProFeaturesForMsg {
    ProFeaturesForMsgStatus status;
    std::string_view error;
    ProMessageBitset bitset;
};

enum class DestinationType {
    SyncOr1o1 = SESSION_PROTOCOL_DESTINATION_TYPE_SYNC_OR_1O1,
    /// Both legacy and non-legacy groups are to be identified as `Group`. A non-legacy
    /// group is detected by the (0x03) prefix byte on the given `dest_group_pubkey` specified in
    /// Destination.
    Group = SESSION_PROTOCOL_DESTINATION_TYPE_GROUP,
    CommunityInbox = SESSION_PROTOCOL_DESTINATION_TYPE_COMMUNITY_INBOX,
    Community = SESSION_PROTOCOL_DESTINATION_TYPE_COMMUNITY,
};

struct Destination {
    DestinationType type;

    // Optional rotating Session Pro Ed25519 private key to sign the message with on behalf of the
    // caller. The Session Pro signature must _not_ be set in the plaintext content passed into the
    // encoding function.
    std::span<const uint8_t> pro_rotating_ed25519_privkey;

    // The timestamp to assign to the message envelope
    std::chrono::milliseconds sent_timestamp_ms;

    // When type => (CommunityInbox || SyncMessage || Contact): set to the recipient's Session
    // public key
    array_uc33 recipient_pubkey;

    // When type => CommunityInbox: set this pubkey to the server's key
    array_uc32 community_inbox_server_pubkey;

    // When type => Group: set to the group public keys for a 0x03 prefix (e.g. groups v2)
    // `group_pubkey` to encrypt the message for.
    array_uc33 group_ed25519_pubkey;

    // When type => Group: Set the encryption key of the group for groups v2 messages. Typically
    // the latest key for the group, e.g: `Keys::group_enc_key` or `groups_keys_group_enc_key`
    cleared_uc32 group_enc_key;
};

struct Envelope {
    SESSION_PROTOCOL_ENVELOPE_FLAGS flags;
    std::chrono::milliseconds timestamp;

    // Optional fields. These fields are set if the appropriate flag has been set in `flags`
    // otherwise the corresponding values are to be ignored and those fields will be
    // zero-initialised.
    array_uc33 source;
    uint32_t source_device;
    uint64_t server_timestamp;

    // Signature by the sending client's rotating key
    array_uc64 pro_sig;
};

struct DecodedPro {
    ProStatus status;  // Validity of the proof embedded in the envelope
    // Session Pro proof that was embedded in the envelope, this is always populated irrespective of
    // the status but the validity of the contents should be verified by checking `status`
    ProProof proof;
    ProMessageBitset msg_bitset;
    ProProfileBitset profile_bitset;
};

struct DecodedEnvelope {
    // The envelope parsed from the plaintext
    Envelope envelope;

    // Decoded envelope content into plaintext with padding stripped
    std::vector<uint8_t> content_plaintext;

    // Sender public key extracted from the encrypted content payload. This is not set if the
    // envelope was a groups v2 envelope where the envelope was encrypted and only the x25519 pubkey
    // was available.
    array_uc32 sender_ed25519_pubkey;

    // The x25519 pubkey, always populated on successful parse. Either it's present from decrypting
    // a Groups v2 envelope or it's re-derived from the Ed25519 pubkey.
    array_uc32 sender_x25519_pubkey;

    // Set if the envelope included a pro payload. The caller must check the status to determine if
    // the embedded pro data/proof was valid, invalid or whether or not the proof has expired.
    std::optional<DecodedPro> pro;
};

struct DecodedCommunityMessage {
    // The envelope parsed from the plaintext. Set if the plaintext was originally an envelope blob.
    // This is optional because the protocol is undergoing a migration period to start sending
    // community messages as an `Envelope` instead of `Content` so we will receive one or the other
    // kind of blob on the wire during that period.
    std::optional<Envelope> envelope;

    // The protobuf encoded `Content` with padding stripped
    std::vector<uint8_t> content_plaintext;

    // The signature if it was present in the payload. If the envelope is set and the envelope has
    // the pro signature flag set, then this signature was extracted from the envelope. When the
    // signature is sourced from the envelope, the envelope's `pro_sig` field is also set to the
    // same signature as this instance for consistency. Otherwise the signature, if set was
    // extracted from the community-exclusive pro signature field in the content message.
    std::optional<array_uc64> pro_sig;

    // Set if the envelope included a pro payload. The caller must check the status to determine if
    // the embedded pro data/proof was valid, invalid or whether or not the proof has expired.
    std::optional<DecodedPro> pro;
};

struct DecodeEnvelopeKey {
    // Set the key to decrypt the envelope. If this key is set then it's assumed that the envelope
    // payload is encrypted (e.g. groups v2) and that the contents are unencrypted. If this key is
    // not set the it's assumed the envelope is not encrypted but the contents are encrypted (e.g.:
    // 1o1 or legacy group).
    std::optional<std::span<const uint8_t>> group_ed25519_pubkey;

    // List of libsodium-style secret key to decrypt the envelope from. Can also be passed as a 32
    // byte secret key. The public key component is not used.
    //
    // If the `group_ed25519_pubkey` is set then a list of keys is accepted to attempt to decrypt
    // the envelope. For envelopes generated by a group message, we assume that the envelope is
    // encrypted and must be decrypted by the group keys associated with it (of which there may be
    // many candidate keys depending on how many times the group has been rekeyed). It's recommended
    // to pass `Keys::group_keys()` or in the C API use the `groups_keys_size` and
    // `group_keys_get_keys` combo to retrieve the keys to attempt to use to decrypt this message.
    //
    // If `group_ed25519_pubkey` is _not_ set then this function assumes the envelope is unencrypted
    // but the content is encrypted (e.g.: 1o1 and legacy group messages). The function will attempt
    // to decrypt the envelope's contents with the given keys. Typically in these cases you will
    // pass exactly 1 ed25519 private key for decryption but this function makes no pre
    // existing assumptions on the number of keys and will attempt all given keys specified
    // regardless until it finds one that successfully decrypts the envelope contents.
    std::span<std::span<const uint8_t>> decrypt_keys;
};

/// API: session_protocol/pro_features_for_message
///
/// Determine the Pro features required for a conversation message of a given length.
///
/// Inputs:
/// - `codepoint_count` -- the number of Unicode codepoints in the message. Callers count this
///   themselves (every platform's native string type counts codepoints directly).
///
/// Outputs (a ProFeaturesForMsg):
/// - `status` -- Success, or ExceedsCharacterLimit if the message is over the maximum limit. When
///   not Success, only `error` is meaningful.
/// - `error` -- On a non-Success `status`, a read-only description of the failure; empty otherwise.
/// - `bitset` -- Feature flags suitable for writing directly into the protobuf
///   `ProMessage.messageFeatures`
ProFeaturesForMsg pro_features_for_message(size_t codepoint_count);

/// API: session_protocol/pad_message
///
/// Pad a message to the required alignment for 1o1/community messages (160 bytes) including space
/// for the padding-terminating byte.
std::vector<uint8_t> pad_message(std::span<const uint8_t> payload);

/// API: session_protocol/encode_for_1o1
///
/// Encode a plaintext message for a one-on-one (1o1) conversation or sync message in the Session
/// Protocol. This function wraps the plaintext in the necessary structures and encrypts it for
/// transmission to a single recipient.
///
/// This is a high-level convenience function that internally calls encode_for_destination with
/// the appropriate Destination configuration for a 1o1 or sync message.
///
/// This function throws if any input argument is invalid (e.g., incorrect key sizes).
///
/// Inputs:
/// - plaintext -- The protobuf serialized payload containing the Content to be encrypted. Must
///   not be already encrypted and must not be padded.
/// - ed25519_privkey -- The sender's libsodium-style secret key (64 bytes). Can also be passed as
///   a 32-byte seed. Used to encrypt the plaintext.
/// - sent_timestamp -- The timestamp to assign to the message envelope, in milliseconds. This
///   should match the protobuf encoded Content's `sigtimestamp` in the given `plaintext`.
/// - recipient_pubkey -- The recipient's Session public key (33 bytes).
/// - pro_rotating_ed25519_privkey -- Optional libsodium-style secret key (64 bytes) that is the
///   secret component of the user's Session Pro Proof `rotating_pubkey`. This key is authorised to
///   entitle the message with Pro features by signing it. Can also be passed as a 32-byte seed.
///   Pass in the empty span to opt-out of Pro feature entitlement.
///
/// Outputs:
/// - Encryption result for the plaintext. The retured payload is suitable for sending on the wire
///   (i.e: it has been protobuf encoded/wrapped if necessary).
std::vector<uint8_t> encode_for_1o1(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ed25519_privkey,
        std::chrono::milliseconds sent_timestamp,
        const array_uc33& recipient_pubkey,
        std::optional<std::span<const uint8_t>> pro_rotating_ed25519_privkey);

/// API: session_protocol/encode_for_community_inbox
///
/// Encode a plaintext message for a community inbox in the Session Protocol. This function wraps
/// the plaintext in the necessary structures and encrypts it for transmission to a community inbox
/// server.
///
/// This is a high-level convenience function that internally calls encode_for_destination with
/// the appropriate Destination configuration for a community inbox message.
///
/// This function throws if any input argument is invalid (e.g., incorrect key sizes).
///
/// Inputs:
/// - plaintext -- The protobuf serialized payload containing the Content to be encrypted. Must
///   not be already encrypted and must not be padded.
/// - ed25519_privkey -- The sender's libsodium-style secret key (64 bytes). Can also be passed as
///   a 32-byte seed. Used to encrypt the plaintext.
/// - recipient_pubkey -- The recipient's Session public key (33 bytes).
/// - community_pubkey -- The community inbox server's public key (32 bytes).
/// - pro_rotating_ed25519_privkey -- Optional libsodium-style secret key (64 bytes) that is the
///   secret component of the user's Session Pro Proof `rotating_pubkey`. This key is authorised to
///   entitle the message with Pro features by signing it. Can also be passed as a 32-byte seed.
///   Pass in the empty span to opt-out of Pro feature entitlement.
///
/// Outputs:
/// - Encryption result for the plaintext. The retured payload is suitable for sending on the wire
///   (i.e: it has been protobuf encoded/wrapped if necessary).
std::vector<uint8_t> encode_for_community_inbox(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ed25519_privkey,
        const array_uc33& recipient_pubkey,
        const array_uc32& community_pubkey,
        std::optional<std::span<const uint8_t>> pro_rotating_ed25519_privkey);

/// API: session_protocol/encode_for_community
///
/// Encode a plaintext `Content` message for a community in the Session Protocol. This function
/// encodes Session Pro metadata including generating and embedding the Session Pro signature, when
/// given a Session Pro rotating Ed25519 key into the final payload suitable for transmission on the
/// wire.
///
/// This function throws if any input argument is invalid (e.g., incorrect key sizes). It also
/// throws if the pro signature is already set in the plaintext `Content` or the `plaintext` cannot
/// be interpreted as a `Content` message.
///
/// Inputs:
/// - plaintext -- The protobuf serialized payload containing the Content to be encrypted. Must
///   not be already encrypted and must not be padded.
/// - pro_rotating_ed25519_privkey -- Optional libsodium-style secret key (64 bytes) that is the
///   secret component of the user's Session Pro Proof `rotating_pubkey`. This key is authorised to
///   entitle the message with Pro features by signing it. Can also be passed as a 32-byte seed.
///   Pass in the empty span to opt-out of Pro feature entitlement.
///
/// Outputs:
/// - Encryption result for the plaintext. The retured payload is suitable for sending on the wire
///   (i.e: it has been protobuf encoded/wrapped if necessary).
std::vector<uint8_t> encode_for_community(
        std::span<const uint8_t> plaintext,
        std::optional<std::span<const uint8_t>> pro_rotating_ed25519_privkey);

/// API: session_protocol/encode_for_group
///
/// Encode a plaintext message for a group in the Session Protocol. This function wraps the
/// plaintext in the necessary structures and encrypts it for transmission to a group, using the
/// group's encryption key. Only v2 groups, (0x03) prefixed keys are supported. Passing a legacy
/// group (0x05) prefixed key will cause the function to throw.
///
/// This is a high-level convenience function that internally calls encode_for_destination with
/// the appropriate Destination configuration for a group message.
///
/// This function throws if any input argument is invalid (e.g., incorrect key sizes).
///
/// Inputs:
/// - plaintext -- The protobuf serialized payload containing the Content to be encrypted. Must
///   not be already encrypted and must not be padded.
/// - ed25519_privkey -- The sender's libsodium-style secret key (64 bytes). Can also be passed as
///   a 32-byte seed. Used to encrypt the plaintext.
/// - sent_timestamp -- The timestamp to assign to the message envelope, in milliseconds.
/// - group_ed25519_pubkey -- The group's public key (33 bytes) for encryption with a 0x03 prefix
/// - group_enc_key -- The group's encryption key (32 bytes) for groups v2 messages, typically the
///   latest key for the group (e.g., Keys::group_enc_key).
/// - pro_rotating_ed25519_privkey -- Optional libsodium-style secret key (64 bytes) that is the
///   secret component of the user's Session Pro Proof `rotating_pubkey`. This key is authorised to
///   entitle the message with Pro features by signing it. Can also be passed as a 32-byte seed.
///   Pass in the empty span to opt-out of Pro feature entitlement.
///
/// Outputs:
/// - Encryption result for the plaintext. The retured payload is suitable for sending on the wire
///   (i.e: it has been protobuf encoded/wrapped if necessary).
std::vector<uint8_t> encode_for_group(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ed25519_privkey,
        std::chrono::milliseconds sent_timestamp,
        const array_uc33& group_ed25519_pubkey,
        const cleared_uc32& group_enc_key,
        std::optional<std::span<const uint8_t>> pro_rotating_ed25519_privkey);

/// API: session_protocol/encode_for_destination
///
/// Given an unencrypted plaintext representation of the content (i.e.: protobuf encoded stream of
/// `Content`), encrypt and/or wrap the plaintext in the necessary structures for transmission on
/// the Session Protocol.
///
/// Calling this function requires filling out the options in the `Destination` struct with the
/// appropriate values for the desired destination. Check the annotation on `Destination` for more
/// information on how to fill this struct. Alternatively, there are higher level functions, encrypt
/// for 1o1, group and community functions which thunk into this low-level function for convenience.
///
/// This function throws if the API is misused (i.e.: A field was not set, but was required to be
/// set for the given destination and namespace. For example the group keys not being set
/// when sending to a group prefixed [0x3] key in a group)
/// but otherwise returns a struct with values.
///
/// Inputs:
/// - `plaintext` -- the protobuf serialised payload containing the protobuf encoded stream,
///   `Content`. It must not be already be encrypted and must not be padded.
/// - `ed25519_privkey` -- the libsodium-style secret key of the sender, 64 bytes. Can also be
///   passed as a 32-byte seed. Used to encrypt the plaintext.
/// - `dest` -- the extra metadata indicating the destination of the message and the necessary data
///   to encrypt a message for that destination.
///
/// Outputs:
/// - Encryption result for the plaintext. The retured payload is suitable for sending on the wire
///   (i.e: it has been protobuf encoded/wrapped if necessary).
std::vector<uint8_t> encode_for_destination(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ed25519_privkey,
        const Destination& dest);

/// API: session_protocol/decode_envelope
///
/// Given an envelope payload (i.e.: protobuf encoded stream of `WebsocketRequestMessage` which
/// wraps an `Envelope` for 1o1 messages/sync messages, or `Envelope` encrypted using a Groups v2
/// key) parse (or decrypt) the envelope and return the envelope content decrypted if necessary.
///
/// A groups v2 envelope will get decrypted with the group keys. A non-groups v2 envelope will get
/// decrypted with the specified Ed25519 private key in the `keys` object. Only one of these keys
/// need to be set depending on the type of envelope payload passed into the function.
///
/// If the message does not use Session Pro features, the `pro` object will be set to nil. Otherwise
/// the pro fields will be populated with data about the Session Pro proof embedded in the envelope
/// including the features used and if the proof was valid/expired e.t.c.
///
/// The sent timestamp of the protobuf encoded content is the timestamp that the Session Pro proof
/// is checked against to ensure that it was not expired at the time the message was constructed.
/// Once a proof is decoded successfully and was not deemed expired (e.g. pro status returned
/// success) any additional timestamp can be checked against the proof by comparing the timestamp on
/// the proof itself directly (since the proof has been cryptographically verified at that point).
///
/// This function will throw if parsing failed such as a required field is missing, the field is
/// smaller or larger than expected, decryption failed, or an invariant failed. Notably this
/// function does not throw if the Session Pro proof failed to verify. Always check the pro status
/// field to verify if the Session Pro was present and/or valid or invalid.
///
/// Inputs:
/// - `keys` -- the keys to decrypt either the envelope or the envelope contents. Groups v2
///   envelopes where the envelope is encrypted must set the group key. Envelopes with an encrypted
///   content must set the the libsodium-style secret key of the receiver, 64 bytes. Can also be
///   passed as a 32-byte seed.
///
///   If a group decryption key is specified, the recipient key is ignored and vice versa. Only one
///   of the keys should be set depending on the type of envelope.
///
/// - `envelope_payload` -- the envelope payload either encrypted (groups v2 style) or unencrypted
///   (1o1 or legacy groups).
/// - `pro_backend_pubkey` -- the Session Pro backend public key to verify the signature embedded in
///   the proof, validating whether or not the attached proof was indeed issued by an authorised
///   issuer
///
/// Outputs:
/// - `envelope` -- Envelope structure that was decrypted/parsed from the `envelope_plaintext`
/// - `content_plaintext` -- Decrypted contents of the envelope structure. This is the protobuf
///   encoded stream that can be parsed into a protobuf `Content` structure.
/// - `sender_ed25519_pubkey` -- The sender's ed25519 public key embedded in the encrypted payload.
///   This is only set for session message envelopes. Groups envelopes only embed the sender's
///   x25519 public key in which case this field is set to the zero public key.
/// - `sender_x25519_pubkey` -- The sender's x25519 public key. It's always set on successful
///   decryption either by extracting the key from the encrypted groups envelope, or, by deriving
///   the x25519 key from the sender's ed25519 key in the case of a session message envelope.
/// - `pro` -- Optional object that is set if there was pro metadata associatd with the envelope, if
///   any. The `status` field in the decrypted pro object should be used to determine whether or not
///   the caller can respect the contents of the `proof` and `features`.
///
///   If the `status` is set to valid the the caller can proceed with entitling the envelope with
///   access to pro features if it's using any.
DecodedEnvelope decode_envelope(
        const DecodeEnvelopeKey& keys,
        std::span<const uint8_t> envelope_payload,
        const array_uc32& pro_backend_pubkey);

/// API: session_protocol/decode_for_community
///
/// Given an unencrypted content or envelope payload extract the plaintext to the content and any
/// associated pro metadata if there was any in the message.
///
/// Inputs:
/// - `content_or_envelope_payload` -- the padded unencrypted content or envelope payload containing
///   the community message
/// - `unix_ts` -- pass in the current system time which is used to determine, whether or
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
/// - `pro_sig` -- Optional pro signature if there was one located in the
///   `content_or_envelope_payload`. This is the same signature as the one located in the `envelope`
///   object if the original payload was an envelope.
/// - `pro` -- Optional object that is set if there was pro metadata associatd with the envelope, if
///   any. The `status` field in the decrypted pro object should be used to determine whether or not
///   the caller can respect the contents of the `proof` and `features`.
///
///   If the `status` is set to valid the the caller can proceed with entitling the envelope with
///   access to pro features if it's using any.
DecodedCommunityMessage decode_for_community(
        std::span<const uint8_t> content_or_envelope_payload,
        sys_seconds unix_ts,
        const array_uc32& pro_backend_pubkey);
}  // namespace session
