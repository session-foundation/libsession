#include <fmt/core.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>
#include <session/config/groups/keys.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/randombytes.h>

#include <charconv>
#include <oxen/log.hpp>
#include <session/pro_backend.hpp>
#include <session/session_encrypt.hpp>
#include <session/session_protocol.hpp>
#include <session/types.hpp>
#include <session/util.hpp>
#include <string_view>
#include <vector>

#include "SessionProtos.pb.h"
#include "WebSocketResources.pb.h"
#include "pro_message.hpp"
#include "session/export.h"

// clang-format off
const session_protocol_strings SESSION_PROTOCOL_STRINGS = {
    .build_variant_apk        = "APK",
    .build_variant_fdroid     = "F-Droid Store",
    .build_variant_huawei     = "Huawei App Gallery",
    .build_variant_ipa        = "IPA",
    .url_donations            = "https://getsession.org/donate",
    .url_donations_app        = "https://getsession.org/donate#app",
    .url_download             = "https://getsession.org/download",
    .url_faq                  = "https://getsession.org/faq",
    .url_feedback             = "https://getsession.org/feedback",
    .url_network              = "https://docs.getsession.org/session-network",
    .url_privacy_policy       = "https://getsession.org/privacy-policy",
    .url_pro_access_not_found = "https://getsession.org/pro-recover",
    .url_pro_faq              = "https://getsession.org/pro#faq",
    .url_pro_page             = "https://getsession.org/pro",
    .url_pro_privacy_policy   = "https://getsession.org/pro-privacy",
    .url_pro_roadmap          = "https://getsession.org/pro#roadmap",
    .url_pro_support          = "https://getsession.org/pro-support",
    .url_pro_terms_of_service = "https://getsession.org/pro-terms",
    .url_pro_upgrade          = "https://getsession.org/pro#upgrade",
    .url_staking              = "https://docs.getsession.org/session-network/staking",
    .url_support              = "https://getsession.org/support",
    .url_survey               = "https://getsession.org/survey",
    .url_terms_of_service     = "https://getsession.org/terms-of-service",
    .url_token                = "https://token.getsession.org",
    .url_translate            = "https://getsession.org/translate",
};
// clang-format on

namespace {
std::vector<unsigned char> proof_signed_message(
        std::span<const std::uint8_t> revocation_tag,
        std::span<const std::uint8_t> rotating_pubkey,
        std::int64_t expiry_ts) {

    // This must match the Pro proof signed message in pro-wire-protocol.md §2 (built per §1.1). No
    // version is part of the message: the 16-byte domain prefix (BUILD_PROOF_DOMAIN) is itself what
    // binds this proof to its format, since it is covered by the signature.
    return session::pro::signed_message(
            session::BUILD_PROOF_DOMAIN, revocation_tag, rotating_pubkey, expiry_ts);
}

bool proof_verify_message_internal(
        std::span<const uint8_t> rotating_pubkey,
        std::span<const uint8_t> sig,
        std::span<const uint8_t> msg) {
    // C++ throws on bad size, C uses a fixed sized array
    assert(rotating_pubkey.size() == crypto_sign_ed25519_PUBLICKEYBYTES);
    if (sig.size() != crypto_sign_ed25519_BYTES)
        return false;

    int verify_result = crypto_sign_ed25519_verify_detached(
            reinterpret_cast<const unsigned char*>(sig.data()),
            msg.data(),
            msg.size(),
            reinterpret_cast<const unsigned char*>(rotating_pubkey.data()));
    bool result = verify_result == 0;
    return result;
}

// Copies an optional 32-byte value out of a possibly-null C pointer. A null pointer yields a
// zero-filled value (the "not provided" case); a non-null pointer with the wrong length yields
// nullopt to signal an error.
static std::optional<session::array_uc32> maybe_uc32_from_ptr(const void* ptr, size_t len) {
    session::array_uc32 out = {};
    if (ptr) {
        if (len != out.max_size())
            return std::nullopt;
        std::memcpy(out.data(), ptr, len);
    }
    return out;
}

static session_protocol_envelope envelope_from_cpp(const session::Envelope& cpp) {
    session_protocol_envelope result = {};
    result.flags = cpp.flags;
    result.timestamp_ms = static_cast<uint64_t>(cpp.timestamp.count());
    std::memcpy(result.source.data, cpp.source.data(), sizeof(result.source.data));
    result.server_timestamp = cpp.server_timestamp;
    result.source_device = cpp.source_device;
    std::memcpy(result.pro_sig.data, cpp.pro_sig.data(), sizeof(result.pro_sig.data));
    return result;
}

static session_protocol_decoded_pro decoded_pro_from_cpp(const session::DecodedPro& cpp) {
    session_protocol_decoded_pro result = {};
    result.status = static_cast<SESSION_PROTOCOL_PRO_STATUS>(cpp.status);
    std::memcpy(
            result.proof.revocation_tag.data,
            cpp.proof.revocation_tag.data(),
            cpp.proof.revocation_tag.max_size());
    std::memcpy(
            result.proof.rotating_pubkey.data,
            cpp.proof.rotating_pubkey.data(),
            cpp.proof.rotating_pubkey.max_size());
    result.proof.expiry_ts = session::epoch_seconds(cpp.proof.expiry_at);
    std::memcpy(result.proof.sig.data, cpp.proof.sig.data(), cpp.proof.sig.max_size());
    result.msg_bitset.data = cpp.msg_bitset.data;
    result.profile_bitset.data = cpp.profile_bitset.data;
    return result;
}
}  // namespace

namespace session {

static_assert(sizeof(ProProof::revocation_tag) == 32);
static_assert(sizeof(ProProof::rotating_pubkey) == crypto_sign_ed25519_PUBLICKEYBYTES);
static_assert(sizeof(ProProof::sig) == crypto_sign_ed25519_BYTES);

bool ProProof::verify_signature(const std::span<const uint8_t>& verify_pubkey) const {
    if (verify_pubkey.size() != crypto_sign_ed25519_PUBLICKEYBYTES)
        throw std::invalid_argument{fmt::format(
                "Invalid verify_pubkey: Must be 32 byte Ed25519 public key (was: {})",
                verify_pubkey.size())};

    auto msg = proof_signed_message(revocation_tag, rotating_pubkey, epoch_seconds(expiry_at));
    bool result = proof_verify_message_internal(verify_pubkey, sig, msg);
    return result;
}

bool ProProof::verify_message(std::span<const uint8_t> sig, std::span<const uint8_t> msg) const {
    if (sig.size() != crypto_sign_ed25519_BYTES)
        throw std::invalid_argument{fmt::format(
                "Invalid signed_msg: Signature must be 64 bytes (was: {})", sig.size())};
    bool result = proof_verify_message_internal(rotating_pubkey, sig, msg);
    return result;
}

bool ProProof::is_active(sys_seconds unix_ts) const {
    return unix_ts <= expiry_at;
}

ProStatus ProProof::status(
        std::span<const uint8_t> verify_pubkey,
        sys_seconds unix_ts,
        std::optional<std::span<const uint8_t>> user_sig,
        std::span<const uint8_t> signed_msg) const {
    ProStatus result = ProStatus::Valid;
    // Verify the at the proof is verified by the Session Pro Backend key (e.g.: It was
    // issued by an authoritative backend)
    if (!verify_signature(verify_pubkey))
        result = ProStatus::InvalidProBackendSig;

    // Check if the message was signed if the user passed one in to verify against
    if (result == ProStatus::Valid && user_sig) {
        if (!verify_message(*user_sig, signed_msg))
            result = ProStatus::InvalidUserSig;
    }

    // Check if the proof has expired
    if (result == ProStatus::Valid && !is_active(unix_ts))
        result = ProStatus::Expired;
    return result;
}

std::vector<unsigned char> ProProof::signed_message() const {
    return proof_signed_message(revocation_tag, rotating_pubkey, epoch_seconds(expiry_at));
}

cleared_uc32 ProProof::rotating_seed(
        std::span<const unsigned char> master_seed, std::chrono::sys_seconds now) {
    if (master_seed.size() != 32 && master_seed.size() != 64)
        throw std::invalid_argument{
                "Invalid master_seed: expected a 32-byte Ed25519 seed or 64-byte libsodium key"};

    // Floor `now` to the start of its rotation period, then hash master_seed[0:32] ‖
    // dec(period_start), where dec() is canonical decimal ASCII -- the same integer encoding the
    // rest of the Pro wire uses (signed_message, §1.1), so there's one integer convention and no
    // endianness to pin.
    auto period_start = now - now.time_since_epoch() % PRO_ROTATING_SEED_PERIOD;
    char dec[20];
    auto [ptr, ec] = std::to_chars(dec, dec + sizeof(dec), epoch_seconds(period_start));
    assert(ec == std::errc{});  // dec is large enough for any int64, so this cannot fail

    auto seed = master_seed.first(32);
    std::vector<unsigned char> msg;
    msg.reserve(seed.size() + static_cast<size_t>(ptr - dec));
    msg.insert(msg.end(), seed.begin(), seed.end());
    msg.insert(msg.end(), dec, ptr);

    static constexpr std::string_view personal = "ProRotatingSeed_";
    static_assert(personal.size() == crypto_generichash_blake2b_PERSONALBYTES);

    cleared_uc32 out = {};
    crypto_generichash_blake2b_salt_personal(
            out.data(),
            out.size(),
            msg.data(),
            msg.size(),
            nullptr,  // key
            0,
            nullptr,  // salt
            reinterpret_cast<const unsigned char*>(personal.data()));
    return out;
}

void ProProfileBitset::set(SESSION_PROTOCOL_PRO_PROFILE_FEATURES features) {
    data |= (1ULL << static_cast<uint64_t>(features));
}

void ProProfileBitset::unset(SESSION_PROTOCOL_PRO_PROFILE_FEATURES features) {
    data &= ~(1ULL << static_cast<uint64_t>(features));
}

bool ProProfileBitset::is_set(SESSION_PROTOCOL_PRO_PROFILE_FEATURES features) const {
    bool result = data & (1ULL << static_cast<uint64_t>(features));
    return result;
}

void ProMessageBitset::set(SESSION_PROTOCOL_PRO_MESSAGE_FEATURES features) {
    data |= (1ULL << static_cast<uint64_t>(features));
}

void ProMessageBitset::unset(SESSION_PROTOCOL_PRO_MESSAGE_FEATURES features) {
    data &= ~(1ULL << static_cast<uint64_t>(features));
}

bool ProMessageBitset::is_set(SESSION_PROTOCOL_PRO_MESSAGE_FEATURES features) const {
    bool result = data & (1ULL << static_cast<uint64_t>(features));
    return result;
}

ProFeaturesForMsg pro_features_for_message(size_t codepoint_count) {
    ProFeaturesForMsg result = {};
    result.status = ProFeaturesForMsgStatus::Success;
    if (codepoint_count > STANDARD_CHARACTER_LIMIT) {
        if (codepoint_count <= PRO_HIGHER_CHARACTER_LIMIT) {
            result.bitset.set(SESSION_PROTOCOL_PRO_MESSAGE_FEATURES_10K_CHARACTER_LIMIT);
        } else {
            result.error = "Message exceeds the maximum character limit allowed";
            result.status = ProFeaturesForMsgStatus::ExceedsCharacterLimit;
        }
    }
    return result;
}

std::vector<uint8_t> encode_for_1o1(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ed25519_privkey,
        std::chrono::milliseconds sent_timestamp,
        const array_uc33& recipient_pubkey,
        std::optional<std::span<const uint8_t>> pro_rotating_ed25519_privkey) {
    Destination dest = {};
    dest.type = DestinationType::SyncOr1o1;
    dest.pro_rotating_ed25519_privkey = pro_rotating_ed25519_privkey ? *pro_rotating_ed25519_privkey
                                                                     : std::span<const uint8_t>{};
    dest.sent_timestamp_ms = sent_timestamp;
    dest.recipient_pubkey = recipient_pubkey;
    std::vector<uint8_t> result = encode_for_destination(plaintext, ed25519_privkey, dest);
    return result;
}

std::vector<uint8_t> encode_for_community_inbox(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ed25519_privkey,
        const array_uc33& recipient_pubkey,
        const array_uc32& community_pubkey,
        std::optional<std::span<const uint8_t>> pro_rotating_ed25519_privkey) {
    Destination dest = {};
    dest.type = DestinationType::CommunityInbox;
    dest.pro_rotating_ed25519_privkey = pro_rotating_ed25519_privkey ? *pro_rotating_ed25519_privkey
                                                                     : std::span<const uint8_t>{};
    // Unused on the CommunityInbox path (only the envelope-based Group/1o1 path consumes it).
    dest.sent_timestamp_ms = std::chrono::milliseconds{0};
    dest.recipient_pubkey = recipient_pubkey;
    dest.community_inbox_server_pubkey = community_pubkey;
    std::vector<uint8_t> result = encode_for_destination(plaintext, ed25519_privkey, dest);
    return result;
}

std::vector<uint8_t> encode_for_community(
        std::span<const uint8_t> plaintext,
        std::optional<std::span<const uint8_t>> pro_rotating_ed25519_privkey) {
    Destination dest = {};
    dest.type = DestinationType::Community;
    dest.pro_rotating_ed25519_privkey = pro_rotating_ed25519_privkey ? *pro_rotating_ed25519_privkey
                                                                     : std::span<const uint8_t>{};
    std::span<const uint8_t> nil_ed25519_privkey;
    std::vector<uint8_t> result = encode_for_destination(plaintext, nil_ed25519_privkey, dest);
    return result;
}

std::vector<uint8_t> encode_for_group(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ed25519_privkey,
        std::chrono::milliseconds sent_timestamp,
        const array_uc33& group_ed25519_pubkey,
        const cleared_uc32& group_enc_key,
        std::optional<std::span<const uint8_t>> pro_rotating_ed25519_privkey) {
    Destination dest = {};
    dest.type = DestinationType::Group;
    dest.pro_rotating_ed25519_privkey = pro_rotating_ed25519_privkey ? *pro_rotating_ed25519_privkey
                                                                     : std::span<const uint8_t>{};
    dest.sent_timestamp_ms = sent_timestamp;
    dest.group_ed25519_pubkey = group_ed25519_pubkey;
    dest.group_enc_key = group_enc_key;
    std::vector<uint8_t> result = encode_for_destination(plaintext, ed25519_privkey, dest);
    return result;
}

// Interop between the C and CPP API. The C api will request malloc which writes to `ciphertext_c`.
// This pointer is taken verbatim and avoids requiring a copy from the CPP vector. The CPP api will
// steal the contents from `ciphertext_cpp`.
struct EncryptedForDestinationInternal {
    std::vector<uint8_t> ciphertext_cpp;
    span_u8 ciphertext_c;
};

constexpr char PADDING_TERMINATING_BYTE = 0x80;
std::vector<uint8_t> pad_message(std::span<const uint8_t> payload) {

    // Calculate amount of padding required
    size_t padded_content_size = payload.size() + 1 /*padding byte*/;
    uint8_t const bytes_for_padding =
            COMMUNITY_OR_1O1_MSG_PADDING - (padded_content_size % COMMUNITY_OR_1O1_MSG_PADDING);
    padded_content_size += bytes_for_padding;
    assert(padded_content_size % COMMUNITY_OR_1O1_MSG_PADDING == 0);

    // Do the padding
    std::vector<uint8_t> result;
    result.resize(padded_content_size);
    std::memcpy(result.data(), payload.data(), payload.size());
    result[payload.size()] = PADDING_TERMINATING_BYTE;
    return result;
}

static std::span<const uint8_t> unpad_message(std::span<const uint8_t> payload) {
    // Strip padding from content
    size_t size_without_padding = payload.size();
    while (size_without_padding) {
        char ch = payload[size_without_padding - 1];
        if (ch != 0 && ch != PADDING_TERMINATING_BYTE) {
            // Non-zero padding encountered, terminate the loop and assume message is not
            // padded
            // TODO: We should enforce this but no client enforces it right now.
            break;
        }

        size_without_padding--;
        if (ch == PADDING_TERMINATING_BYTE)
            break;
    }

    assert(size_without_padding <= payload.size());
    auto result = std::span<const uint8_t>(payload.data(), payload.data() + size_without_padding);
    return result;
}

enum class UseMalloc { No, Yes };
static EncryptedForDestinationInternal encode_for_destination_internal(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> ed25519_privkey,
        DestinationType dest_type,
        std::span<const uint8_t> dest_pro_rotating_ed25519_privkey,
        std::span<const uint8_t> dest_recipient_pubkey,
        std::chrono::milliseconds dest_sent_timestamp_ms,
        std::span<const uint8_t> dest_community_inbox_server_pubkey,
        std::span<const uint8_t> dest_group_ed25519_pubkey,
        std::span<const uint8_t> dest_group_enc_key,
        UseMalloc use_malloc) {
    // The following arguments are passed in from structs with fixed-sized arrays so we expect the
    // sizes to be correct. It being wrong would be a development error
    //
    // The ed25519_privkey is passed into the lower level layer, session encrypt which has its own
    // private key normalisation to 64 bytes for us.
    assert(dest_recipient_pubkey.size() == 1 + crypto_sign_ed25519_PUBLICKEYBYTES);
    assert(dest_community_inbox_server_pubkey.size() == crypto_sign_ed25519_PUBLICKEYBYTES);
    assert(dest_group_ed25519_pubkey.size() == 1 + crypto_sign_ed25519_PUBLICKEYBYTES);
    assert(dest_group_enc_key.size() == 32 || dest_group_enc_key.size() == 64);

    bool is_group = dest_type == DestinationType::Group;
    bool is_1o1 = dest_type == DestinationType::SyncOr1o1;
    bool is_community_inbox = dest_type == DestinationType::CommunityInbox;
    bool is_community = dest_type == DestinationType::Community;
    if (!is_community) {
        assert(ed25519_privkey.size() == crypto_sign_ed25519_SECRETKEYBYTES ||
               ed25519_privkey.size() == crypto_sign_ed25519_SEEDBYTES);
    }

    // Ensure the Session Pro rotating key is a 64 byte key if given
    cleared_uc64 pro_ed_sk_from_seed;
    if (dest_pro_rotating_ed25519_privkey.size()) {
        if (dest_pro_rotating_ed25519_privkey.size() == 32) {
            uc32 ignore_pk;
            crypto_sign_ed25519_seed_keypair(
                    ignore_pk.data(),
                    pro_ed_sk_from_seed.data(),
                    dest_pro_rotating_ed25519_privkey.data());
            dest_pro_rotating_ed25519_privkey = to_span(pro_ed_sk_from_seed);
        } else if (dest_pro_rotating_ed25519_privkey.size() == 64) {
            dest_pro_rotating_ed25519_privkey = to_span(dest_pro_rotating_ed25519_privkey);
        } else {
            throw std::runtime_error{fmt::format(
                    "Invalid dest_pro_rotating_ed25519_privkey: expected 32 or 64 bytes, received "
                    "{}",
                    dest_pro_rotating_ed25519_privkey.size())};
        }
    }

    std::span<const uint8_t> content = plaintext;

    EncryptedForDestinationInternal result = {};
    switch (dest_type) {
        case DestinationType::Group: /*FALLTHRU*/
        case DestinationType::SyncOr1o1: {
            if (is_group &&
                dest_group_ed25519_pubkey[0] != static_cast<uint8_t>(SessionIDPrefix::group)) {
                // Legacy groups which have a 05 prefixed key
                throw std::runtime_error{
                        "Unsupported configuration, encrypting for a legacy group (0x05 prefix) is "
                        "no longer supported"};
            }

            // For Sync or 1o1 mesasges, we need to pad the contents to 160 bytes, see:
            //   https://github.com/session-foundation/session-desktop/blob/a04e62427034a6b6fee39dcff7dbabf0d0131b13/ts/session/crypto/BufferPadding.ts#L49
            std::vector<uint8_t> tmp_content_buffer;
            if (is_1o1) {  // Encrypt the padded output
                std::vector<uint8_t> padded_payload = pad_message(content);
                tmp_content_buffer = encrypt_for_recipient(
                        ed25519_privkey, dest_recipient_pubkey, padded_payload);
                content = tmp_content_buffer;
            }

            // Create envelope
            // Set sourcedevice to 1 as per:
            // https://github.com/session-foundation/session-ios/blob/82deef869d0f7389b799295817f42ad14f8a1316/SessionMessagingKit/Utilities/MessageWrapper.swift#L57
            SessionProtos::Envelope envelope = {};
            envelope.set_type(
                    is_1o1 ? SessionProtos::Envelope_Type_SESSION_MESSAGE
                           : SessionProtos::Envelope_Type_CLOSED_GROUP_MESSAGE);
            envelope.set_sourcedevice(1);
            envelope.set_timestamp(dest_sent_timestamp_ms.count());
            envelope.set_content(content.data(), content.size());

            // Generate the session pro signature. If there's no pro ed25519 key specified, we still
            // fill out the pro signature with a decoy (validly-encoded but unverifiable) signature.
            // This makes pro and non-pro messages indistinguishable on the wire.
            {
                std::string* pro_sig = envelope.mutable_prosig();
                pro_sig->resize(crypto_sign_ed25519_BYTES);

                if (dest_pro_rotating_ed25519_privkey.empty()) {
                    // No pro key: attach a decoy signature -- a validly-encoded Ed25519 signature
                    // (R = r·B for a random scalar r, so a prime-order-subgroup point like a real
                    // R; s a second random scalar) that verifies against nothing. Keeps pro and
                    // non-pro envelopes indistinguishable on the wire without signing throwaway
                    // data. NOT a real signature; never verified.
                    auto* sig = reinterpret_cast<unsigned char*>(pro_sig->data());
                    std::array<unsigned char, crypto_core_ed25519_SCALARBYTES> r;
                    crypto_core_ed25519_scalar_random(r.data());
                    crypto_scalarmult_ed25519_base_noclamp(sig, r.data());
                    crypto_core_ed25519_scalar_random(sig + crypto_core_ed25519_BYTES);
                } else {
                    crypto_sign_ed25519_detached(
                            reinterpret_cast<uint8_t*>(pro_sig->data()),
                            nullptr,
                            content.data(),
                            content.size(),
                            dest_pro_rotating_ed25519_privkey.data());
                }
            }

            if (is_group) {
                std::string bytes = envelope.SerializeAsString();
                if (dest_group_ed25519_pubkey.size() == crypto_sign_ed25519_PUBLICKEYBYTES + 1)
                    dest_group_ed25519_pubkey = dest_group_ed25519_pubkey.subspan(1);

                std::vector<uint8_t> ciphertext = encrypt_for_group(
                        ed25519_privkey,
                        dest_group_ed25519_pubkey,
                        dest_group_enc_key,
                        to_span(bytes),
                        /*compress*/ true,
                        /*padding*/ 256);

                if (use_malloc == UseMalloc::Yes) {
                    result.ciphertext_c =
                            session::span_u8_copy_or_throw(ciphertext.data(), ciphertext.size());
                } else {
                    result.ciphertext_cpp = std::move(ciphertext);
                }
            } else {
                // 1o1, Wrap in websocket message
                WebSocketProtos::WebSocketMessage msg = {};
                msg.set_type(WebSocketProtos::WebSocketMessage_Type::WebSocketMessage_Type_REQUEST);

                // Make request
                WebSocketProtos::WebSocketRequestMessage* req_msg = msg.mutable_request();
                req_msg->set_verb("");      // Required but unused on iOS
                req_msg->set_path("");      // Required but unused on iOS
                req_msg->set_requestid(0);  // Required but unused on iOS
                req_msg->set_body(envelope.SerializeAsString());

                // Write message as ciphertext
                [[maybe_unused]] bool serialized = false;
                if (use_malloc == UseMalloc::Yes) {
                    result.ciphertext_c = span_u8_alloc_or_throw(msg.ByteSizeLong());
                    serialized = msg.SerializeToArray(
                            result.ciphertext_c.data, result.ciphertext_c.size);
                } else {
                    result.ciphertext_cpp.resize(msg.ByteSizeLong());
                    serialized = msg.SerializeToArray(
                            result.ciphertext_cpp.data(), result.ciphertext_cpp.size());
                }
                assert(serialized);
            }
        } break;

        case DestinationType::Community: /*FALLTHRU*/
        case DestinationType::CommunityInbox: {
            // Setup the pro signature for the community message
            std::vector<uint8_t> tmp_content_buffer;

            // Sign the message with the Session Pro key if given and then pad the message (both
            // community message types require it)
            //   https://github.com/session-foundation/session-ios/blob/82deef869d0f7389b799295817f42ad14f8a1316/SessionMessagingKit/Sending%20%26%20Receiving/MessageSender.swift#L398
            if (dest_pro_rotating_ed25519_privkey.size()) {
                // Key should be verified by the time we hit this branch
                assert(dest_pro_rotating_ed25519_privkey.size() ==
                       crypto_sign_ed25519_SECRETKEYBYTES);

                // TODO: Sub-optimal, but we parse the content again to make sure it's valid. Sign
                // the blob then, fill in the signature in-place as part of the transitioning of
                // open groups messages to envelopes. As part of that, libsession is going to take
                // responsibility of constructing community messages so that eventually all
                // platforms switch over to envelopes and we can change the implementation across
                // all platforms in one swoop and remove this.
                //
                // Parse the content blob
                SessionProtos::Content content_w_sig = {};
                if (!content_w_sig.ParseFromArray(content.data(), content.size()))
                    throw std::runtime_error{"Parsing community message failed"};

                if (content_w_sig.has_prosigforcommunitymessageonly())
                    throw std::runtime_error{
                            "Pro signature for community message must not be set. Libsession's "
                            "responsible for generating the signature and setting it"};

                // We need to sign the padded content, so we pad the `Content` then sign it
                tmp_content_buffer = pad_message(content);
                array_uc64 pro_sig;
                bool was_signed = crypto_sign_ed25519_detached(
                                          pro_sig.data(),
                                          nullptr,
                                          tmp_content_buffer.data(),
                                          tmp_content_buffer.size(),
                                          dest_pro_rotating_ed25519_privkey.data()) == 0;
                assert(was_signed);

                // Now assign the community specific pro signature field, reserialize it and we have
                // to, yes, pad it again. This is all temporary wasted work whilst transitioning
                // open groups.
                content_w_sig.set_prosigforcommunitymessageonly(pro_sig.data(), pro_sig.size());
                tmp_content_buffer.resize(content_w_sig.ByteSizeLong());
                bool serialized = content_w_sig.SerializeToArray(
                        tmp_content_buffer.data(), tmp_content_buffer.size());
                assert(serialized);

                tmp_content_buffer = pad_message(tmp_content_buffer);
                content = tmp_content_buffer;
            } else {
                tmp_content_buffer = pad_message(to_span(content));
                content = tmp_content_buffer;
            }

            // TODO: We don't need to actually pad the community message since that's unencrypted,
            // there's no need to make the message sizes uniform but we need it for backwards
            // compat. We can remove this eventually, first step is to unify the clients.

            if (is_community_inbox) {
                std::vector<uint8_t> ciphertext = encrypt_for_blinded_recipient(
                        ed25519_privkey,
                        dest_community_inbox_server_pubkey,
                        dest_recipient_pubkey,  // recipient blinded pubkey
                        content);

                if (use_malloc == UseMalloc::Yes) {
                    result.ciphertext_c =
                            span_u8_copy_or_throw(ciphertext.data(), ciphertext.size());
                } else {
                    result.ciphertext_cpp = std::move(ciphertext);
                }
            } else {
                if (use_malloc == UseMalloc::Yes) {
                    result.ciphertext_c = span_u8_copy_or_throw(content.data(), content.size());
                } else {
                    result.ciphertext_cpp = std::vector<uint8_t>(content.begin(), content.end());
                }
            }
        } break;
    }
    return result;
}

std::vector<uint8_t> encode_for_destination(
        std::span<const unsigned char> plaintext,
        std::span<const unsigned char> ed25519_privkey,
        const Destination& dest) {

    EncryptedForDestinationInternal result_internal = encode_for_destination_internal(
            /*plaintext=*/plaintext,
            /*ed25519_privkey=*/ed25519_privkey,
            /*dest_type=*/dest.type,
            /*dest_pro_rotating_ed25519_privkey=*/dest.pro_rotating_ed25519_privkey,
            /*dest_recipient_pubkey=*/dest.recipient_pubkey,
            /*dest_sent_timestamp_ms=*/dest.sent_timestamp_ms,
            /*dest_community_inbox_server_pubkey=*/dest.community_inbox_server_pubkey,
            /*dest_group_ed25519_pubkey=*/dest.group_ed25519_pubkey,
            /*dest_group_enc_key=*/dest.group_enc_key,
            /*use_malloc=*/UseMalloc::No);

    std::vector<uint8_t> result = std::move(result_internal.ciphertext_cpp);
    return result;
}

DecodedEnvelope decode_envelope(
        const DecodeEnvelopeKey& keys,
        std::span<const uint8_t> envelope_payload,
        const array_uc32& pro_backend_pubkey) {
    DecodedEnvelope result = {};
    SessionProtos::Envelope envelope = {};
    std::span<const uint8_t> envelope_plaintext = envelope_payload;

    // The caller is indicating that the envelope_payload is encrypted, if the group keys are
    // provided. We will decrypt the payload to get the plaintext. In all other cases, the envelope
    // is assumed to be websocket wrapped
    std::vector<uint8_t> envelope_from_decrypted_groups;
    std::string envelope_from_websocket_message;
    if (keys.group_ed25519_pubkey) {
        // Decrypt using the keys
        DecryptGroupMessage decrypt = decrypt_group_message(
                keys.decrypt_keys, *keys.group_ed25519_pubkey, envelope_plaintext);

        if (decrypt.session_id.size() != ((crypto_sign_ed25519_PUBLICKEYBYTES + 1) * 2))
            throw std::runtime_error{fmt::format(
                    "Parse encrypted envelope failed, extracted session ID was wrong size: "
                    "{}",
                    decrypt.session_id.size())};

        // Update the plaintext to use the decrypted envelope
        envelope_from_decrypted_groups = std::move(decrypt.plaintext);
        envelope_plaintext = envelope_from_decrypted_groups;

        // Copy keys out
        assert(decrypt.session_id.starts_with("05"));
        oxenc::from_hex(
                decrypt.session_id.begin() + 2,
                decrypt.session_id.end(),
                result.sender_x25519_pubkey.begin());
    } else {
        // Assumed to be a 1o1/sync message which is wrapped in a websocket message
        WebSocketProtos::WebSocketMessage ws_msg;
        if (!ws_msg.ParseFromArray(envelope_plaintext.data(), envelope_plaintext.size()))
            throw std::runtime_error{fmt::format(
                    "Parse websocket wrapped envelope from payload failed: {}",
                    envelope_plaintext.size())};

        if (!ws_msg.has_request())
            throw std::runtime_error{"Parse websocket wrapped envelope failed, missing request"};

        if (!ws_msg.request().has_body())
            throw std::runtime_error{
                    "Parse websocket wrapped envelope failed, missing request body"};

        WebSocketProtos::WebSocketRequestMessage* request = ws_msg.mutable_request();
        std::string* body = request->mutable_body();
        envelope_from_websocket_message = std::move(*body);
        envelope_plaintext = to_span(envelope_from_websocket_message);
    }

    if (!envelope.ParseFromArray(envelope_plaintext.data(), envelope_plaintext.size()))
        throw std::runtime_error{"Parse envelope from plaintext failed"};

    // TODO: We do not parse the envelop type anymore, we infer the type from
    // the namespace. Deciding whether or not we decrypt the envelope vs the content depends on
    // whether or not the group keys were passed in so we don't care about the type anymore.
    //
    // When the type is removed, we can remove this TODO. This is just a reminder as to why we skip
    // over that field but it's still in the schema and still being set on the sending side.

    // Parse timestamp
    if (envelope.has_timestamp()) {
        result.envelope.timestamp = std::chrono::milliseconds(envelope.timestamp());
        result.envelope.flags |= SESSION_PROTOCOL_ENVELOPE_FLAGS_TIMESTAMP;
    }

    // Parse source (optional)
    if (envelope.has_source()) {
        // Libsession is now responsible for creating the envelope. The only data that we send in
        // the source is a Session public key (see: encode_for_destination)

        // TODO: For backwards compatibility, iOS and Android does not set the source sender's
        // public key for 1o1s but marks the field as present. So we accept either a 0 sized string
        // or a 32 byte public key.
        //
        //  iOS
        //    https://github.com/session-foundation/session-ios/blob/7dc430ed548ce844f10f9a28c69fb8ccac13d8c3/SessionMessagingKit/Sending%20%26%20Receiving/MessageSender.swift#L472
        //    https://github.com/session-foundation/session-ios/blob/7dc430ed548ce844f10f9a28c69fb8ccac13d8c3/SessionMessagingKit/Utilities/MessageWrapper.swift#L56
        //
        //  Android
        //    https://github.com/session-foundation/session-android/blob/403c5f6b0e402279f25d55c0d492bdcf006608e5/app/src/main/java/org/session/libsession/messaging/sending_receiving/MessageSender.kt#L147
        //    https://github.com/session-foundation/session-android/blob/403c5f6b0e402279f25d55c0d492bdcf006608e5/app/src/main/java/org/session/libsession/messaging/utilities/MessageWrapper.kt#L40
        //
        // This can be removed after a while once we want to stop supporting old clients.
        const std::string& source = envelope.source();
        if (source.size() != 0 && source.size() != (result.envelope.source.max_size() * 2) /*hex*/)
            throw std::runtime_error(fmt::format(
                    "Parse envelope failed, source had unexpected size ({} bytes)", source.size()));

        if (source.size()) {
            oxenc::from_hex(source.begin(), source.end(), result.envelope.source.data());
            result.envelope.flags |= SESSION_PROTOCOL_ENVELOPE_FLAGS_SOURCE;
        }
    }

    // Parse source device (optional)
    if (envelope.has_sourcedevice()) {
        result.envelope.source_device = envelope.sourcedevice();
        result.envelope.flags |= SESSION_PROTOCOL_ENVELOPE_FLAGS_SOURCE_DEVICE;
    }

    // Parse server timestamp (optional)
    if (envelope.has_servertimestamp()) {
        result.envelope.server_timestamp = envelope.servertimestamp();
        result.envelope.flags |= SESSION_PROTOCOL_ENVELOPE_FLAGS_SERVER_TIMESTAMP;
    }

    // Parse content
    if (!envelope.has_content())
        throw std::runtime_error{"Parse decrypted message failed, missing content"};

    // Decrypt content
    // The envelope is encrypted in GroupsV2, contents unencrypted. In 1o1 and legacy groups, the
    // envelope is encrypted, contents is encrypted.
    if (keys.group_ed25519_pubkey) {
        result.content_plaintext.resize(envelope.content().size());
        std::memcpy(
                result.content_plaintext.data(),
                envelope.content().data(),
                envelope.content().size());
    } else {
        const std::string& content = envelope.content();
        bool decrypt_success = false;
        std::vector<uint8_t> content_plaintext;
        std::vector<uint8_t> sender_ed25519_pubkey;
        for (const auto& privkey_it : keys.decrypt_keys) {
            try {
                std::tie(content_plaintext, sender_ed25519_pubkey) =
                        session::decrypt_incoming(privkey_it, to_span(content));
                assert(result.sender_ed25519_pubkey.size() == crypto_sign_ed25519_PUBLICKEYBYTES);
                decrypt_success = true;
                break;
            } catch (...) {
            }
        }

        if (!decrypt_success) {
            throw std::runtime_error{fmt::format(
                    "Envelope content decryption failed, tried {} key(s)",
                    keys.decrypt_keys.size())};
        }

        // Strip padding from content
        std::span<const uint8_t> unpadded_content = unpad_message(content_plaintext);
        content_plaintext.resize(unpadded_content.size());
        result.content_plaintext = std::move(content_plaintext);

        std::memcpy(
                result.sender_ed25519_pubkey.data(),
                sender_ed25519_pubkey.data(),
                result.sender_ed25519_pubkey.size());

        if (crypto_sign_ed25519_pk_to_curve25519(
                    result.sender_x25519_pubkey.data(), result.sender_ed25519_pubkey.data()) != 0)
            throw std::runtime_error(
                    "Parse content failed, ed25519 public key could not be converted to x25519 "
                    "key.");
    }

    // TODO: We parse the content in libsession to extract pro metadata but we return the unparsed
    // blob back to the caller. This is temporary, eventually we will return a proxy structure for
    // the protobuf Content type to the user. We avoid returning the direct protobuf type to keep
    // the interface simple and avoid leaking protobuf implementation detail into the libsession
    // interface.
    SessionProtos::Content content = {};
    if (!content.ParseFromArray(result.content_plaintext.data(), result.content_plaintext.size()))
        throw std::runtime_error{fmt::format(
                "Parse content from envelope failed: {}b", result.content_plaintext.size())};

    // A signature must always be present on the envelope. This is to make a pro and non-pro
    // envelope indistinguishable. If the message does not have pro then this signature must still
    // be set but will be ignored. So in all instances a signature must be attached (real or
    // dummy).
    //
    // TODO: However for backwards compatibility, so old client's sending their envelopes to new
    // clients won't have the pro signature set. We have to allow these for now until we
    // deprecate the supporting of messages from those clients. For forwards compatibility, the new
    // clients will send the message with the pro signature attached. The old clients will ignore
    // the new fields.
    //
    // This should be deprecated in about 1-2yrs from this message. 2025-08-18 doyle
    if (envelope.has_prosig()) {
        // Copy (maybe dummy) pro signature into our result struct
        const std::string& pro_sig = envelope.prosig();
        if (pro_sig.size() != crypto_sign_ed25519_BYTES)
            throw std::runtime_error("Parse envelope failed, pro signature has wrong size");
        static_assert(sizeof(result.envelope.pro_sig) == crypto_sign_ed25519_BYTES);
        std::memcpy(result.envelope.pro_sig.data(), pro_sig.data(), pro_sig.size());

        if (content.has_promessage()) {
            if (!content.sigtimestamp())
                throw std::runtime_error{fmt::format(
                        "Content does not have signature timestamp set, pro proof expiry is "
                        "unverifiable (content was {}b)",
                        result.content_plaintext.size())};

            // Mark the envelope as having a pro signature that the caller can use.
            result.envelope.flags |= SESSION_PROTOCOL_ENVELOPE_FLAGS_PRO_SIG;
            DecodedPro& pro = result.pro.emplace();

            // Extract the pro message
            const SessionProtos::ProMessage& pro_msg = content.promessage();
            session::ProProof& proof = pro.proof;
            pro.msg_bitset.data = pro_msg.msgbitset();
            pro.profile_bitset.data = pro_msg.profilebitset();
            std::memcpy(result.envelope.pro_sig.data(), pro_sig.data(), pro_sig.size());

            // No proof to read: either the sender attached none, or it is in a format we don't
            // know -- a new proof format is a new field/message rather than a version bump on this
            // one, so to this client it simply isn't here. Nothing to evaluate, so the proof is
            // flagged Invalid and the message is delivered as non-pro rather than dropped: a future
            // proof format costs the sender their Pro affordances here, not the whole message.
            if (!pro_msg.has_proof()) {
                pro.status = ProStatus::Invalid;
            } else {
                // Parse the proof from protobufs
                const SessionProtos::ProProof& proto_proof = pro_msg.proof();
                // A proof that is present but the wrong shape is corruption, not forward-compat:
                // hard error.
                size_t proof_errors = 0;
                proof_errors +=
                        !proto_proof.has_revocationtag() ||
                        proto_proof.revocationtag().size() != proof.revocation_tag.max_size();
                proof_errors +=
                        !proto_proof.has_rotatingpublickey() ||
                        proto_proof.rotatingpublickey().size() != proof.rotating_pubkey.max_size();
                proof_errors += !proto_proof.has_expiryunixts();
                proof_errors +=
                        !proto_proof.has_sig() || proto_proof.sig().size() != proof.sig.max_size();
                if (proof_errors)
                    throw std::runtime_error(
                            "Parse decrypted message failed, pro metadata was malformed");

                std::memcpy(
                        proof.revocation_tag.data(),
                        proto_proof.revocationtag().data(),
                        proto_proof.revocationtag().size());
                std::memcpy(
                        proof.rotating_pubkey.data(),
                        proto_proof.rotatingpublickey().data(),
                        proto_proof.rotatingpublickey().size());
                proof.expiry_at = as_sys_seconds(proto_proof.expiryunixts());
                std::memcpy(proof.sig.data(), proto_proof.sig().data(), proto_proof.sig().size());

                // Evaluate the pro status given the extracted components (was it signed, is it
                // expired, was the message signed validly?)
                //
                // Note that we sign the envelope content wholesale. For 1o1 which are padded to 160
                // bytes, this means that we expected the user to have signed the padding as well.
                auto unix_ts = std::chrono::floor<std::chrono::seconds>(
                        std::chrono::sys_time<std::chrono::milliseconds>(
                                std::chrono::milliseconds(content.sigtimestamp())));
                pro.status = proof.status(
                        pro_backend_pubkey, unix_ts, to_span(pro_sig), to_span(envelope.content()));
            }
        }
    }
    return result;
}

DecodedCommunityMessage decode_for_community(
        std::span<const uint8_t> content_or_envelope_payload,
        sys_seconds unix_ts,
        const array_uc32& pro_backend_pubkey) {
    // TODO: Community message parsing requires a custom code path for now as we are planning to
    // migrate from sending plain `Content` to `Content` with a pro signature embedded in `Content`
    // (added exclusively for communities usecase), then, transitioning to sending an `Envelope` to
    // make it match how messages are sent for 1o1 and groups.
    //
    // We have intermediate steps to allow a timeframe for providing backwards compatibility with
    // older clients before changing data structures and shutting them out from receiving messages.
    // More detailed information on this transition is documented in the SessionProtos.proto file
    //
    // In the intermediary stages, handling community messages requires some custom code that's
    // similar but different to the normal path that it's less friction to write some custom
    // code to handle those bits than try and re-purpose the general purpose decrypt envelope
    // function.
    DecodedCommunityMessage result = {};

    // Attempt to parse the blob as an envelope
    std::optional<std::span<const uint8_t>> pro_sig;
    SessionProtos::Envelope pb_envelope = {};
    {
        bool envelope_parsed = pb_envelope.ParseFromArray(
                content_or_envelope_payload.data(), content_or_envelope_payload.size());

        if (envelope_parsed) {
            // Create the envelope
            Envelope& envelope = result.envelope.emplace();
            result.content_plaintext = std::vector<uint8_t>(
                    pb_envelope.content().begin(), pb_envelope.content().end());

            // Extract the envelope into our type
            // Parse source (optional)
            if (pb_envelope.has_source()) {
                // Libsession is now responsible for creating the envelope. The only data that we
                // send in the source is a Session public key (see: encode_for_destination)
                const std::string& source = pb_envelope.source();
                if (source.size() != envelope.source.max_size())
                    throw std::runtime_error(fmt::format(
                            "Parse envelope failed, source had unexpected size ({} bytes)",
                            source.size()));
                std::memcpy(envelope.source.data(), source.data(), source.size());
                envelope.flags |= SESSION_PROTOCOL_ENVELOPE_FLAGS_SOURCE;
            }

            // Parse source device (optional)
            if (pb_envelope.has_sourcedevice()) {
                envelope.source_device = pb_envelope.sourcedevice();
                envelope.flags |= SESSION_PROTOCOL_ENVELOPE_FLAGS_SOURCE_DEVICE;
            }

            // Parse server timestamp (optional)
            if (pb_envelope.has_servertimestamp()) {
                envelope.server_timestamp = pb_envelope.servertimestamp();
                envelope.flags |= SESSION_PROTOCOL_ENVELOPE_FLAGS_SERVER_TIMESTAMP;
            }

            // Parse pro signature (optional)
            if (pb_envelope.has_prosig()) {
                envelope.flags |= SESSION_PROTOCOL_ENVELOPE_FLAGS_PRO_SIG;
                pro_sig = to_span(pb_envelope.prosig());
            }
        } else {
            // TODO: Do wasteful copy in the interim whilst transitioning protocol
            result.content_plaintext = std::vector<uint8_t>(
                    content_or_envelope_payload.begin(), content_or_envelope_payload.end());
        }
    }

    // Parse the content blob
    std::span<const uint8_t> unpadded_content = unpad_message(result.content_plaintext);
    SessionProtos::Content content = {};
    if (!content.ParseFromArray(unpadded_content.data(), unpadded_content.size()))
        throw std::runtime_error{
                "Decoding community message failed, could not interpret blob as content or "
                "envelope"};

    // Extract the pro signature from content if it was present
    if (content.has_prosigforcommunitymessageonly()) {
        // Signature must be in the envelope if it existed or the content. Specifying both is
        // not allowed.
        if (result.envelope && result.envelope->flags & SESSION_PROTOCOL_ENVELOPE_FLAGS_PRO_SIG) {
            throw std::runtime_error(
                    "Decoding community message failed, envelope and content both had a pro "
                    "signature specified");
        }
        assert(!pro_sig);
        pro_sig = to_span(content.prosigforcommunitymessageonly());
    }

    // If there was a pro signature in one of the payloads, verify and copy it to our result struct
    if (pro_sig) {
        if (pro_sig->size() != crypto_sign_ed25519_BYTES)
            throw std::runtime_error(
                    "Decoding community message failed, pro signature has wrong size");

        // Signature was the correct size, copy it into the envelope if there was one and copy it
        // into the root structure
        if (result.envelope)
            std::memcpy(result.envelope->pro_sig.data(), pro_sig->data(), pro_sig->size());

        // Set it into the signature sitting in result
        result.pro_sig.emplace();
        std::memcpy(result.pro_sig->data(), pro_sig->data(), pro_sig->size());
    }

    if (result.pro_sig && content.has_promessage()) {
        // Extract the pro message
        DecodedPro& pro = result.pro.emplace();
        const SessionProtos::ProMessage& pro_msg = content.promessage();
        session::ProProof& proof = pro.proof;
        pro.msg_bitset.data = pro_msg.msgbitset();
        pro.profile_bitset.data = pro_msg.profilebitset();

        // No proof to read: either the sender attached none, or it is in a format we don't know --
        // a new proof format is a new field/message rather than a version bump on this one, so to
        // this client it simply isn't here. Nothing to evaluate, so the proof is flagged Invalid
        // and the message is delivered as non-pro rather than dropped: a future proof format costs
        // the sender their Pro affordances here, not the whole message.
        if (!pro_msg.has_proof()) {
            pro.status = ProStatus::Invalid;
        } else {
            // Parse the proof from protobufs
            const SessionProtos::ProProof& proto_proof = pro_msg.proof();
            // A proof that is present but the wrong shape is corruption, not forward-compat: hard
            // error.
            size_t proof_errors = 0;
            proof_errors += !proto_proof.has_revocationtag() ||
                            proto_proof.revocationtag().size() != proof.revocation_tag.max_size();
            proof_errors +=
                    !proto_proof.has_rotatingpublickey() ||
                    proto_proof.rotatingpublickey().size() != proof.rotating_pubkey.max_size();
            proof_errors += !proto_proof.has_expiryunixts();
            proof_errors +=
                    !proto_proof.has_sig() || proto_proof.sig().size() != proof.sig.max_size();
            if (proof_errors)
                throw std::runtime_error(
                        "Decoding community message failed, pro metadata was malformed");

            std::memcpy(
                    proof.revocation_tag.data(),
                    proto_proof.revocationtag().data(),
                    proto_proof.revocationtag().size());
            std::memcpy(
                    proof.rotating_pubkey.data(),
                    proto_proof.rotatingpublickey().data(),
                    proto_proof.rotatingpublickey().size());
            proof.expiry_at = as_sys_seconds(proto_proof.expiryunixts());
            std::memcpy(proof.sig.data(), proto_proof.sig().data(), proto_proof.sig().size());

            // Evaluate the pro status given the extracted components (was it signed, is it expired,
            // was the message signed validly?)
            //
            // IMPORTANT: We have to bit-manipulate the content because we're including the
            // signature inside the payload itself that we had to sign. But we originally signed the
            // payload without a signature set in it. This is only the case if we're dealing with a
            // `Content` message that had the signature inside the content instead of the envelope.
            if (result.envelope) {
                // Entering the `pro_sig` and `result.envelope` branch means that the envelope must
                // have a pro signature.
                assert(result.envelope->flags & SESSION_PROTOCOL_ENVELOPE_FLAGS_PRO_SIG);
                pro.status = proof.status(
                        pro_backend_pubkey,
                        unix_ts,
                        to_span(*result.pro_sig),
                        result.content_plaintext);
            } else {
                SessionProtos::Content content_copy_without_sig = content;
                assert(content_copy_without_sig.has_prosigforcommunitymessageonly());

                // Remove signature from the payload
                content_copy_without_sig.clear_prosigforcommunitymessageonly();
                assert(!content_copy_without_sig.has_prosigforcommunitymessageonly());

                // Reserialise the payload without the signature, repad it then verify the signature
                std::vector<uint8_t> content_copy_without_sig_payload =
                        pad_message(to_span(content_copy_without_sig.SerializeAsString()));

                pro.status = proof.status(
                        pro_backend_pubkey,
                        unix_ts,
                        to_span(*result.pro_sig),
                        to_span(content_copy_without_sig_payload));
            }
        }
    }

    // Strip padding from content, we only strip at the very end once we're done using the padded
    // content. A Session Pro proof, if provided will contain a signature that signs over the
    // content including its padding- that is verified in this function above.
    //
    // After that verification is complete then we can remove the padding here and return it to the
    // caller without padding as we no longer have a need for it.
    result.content_plaintext.resize(unpadded_content.size());

    return result;
}
}  // namespace session

using namespace session;

// Protocol limit/padding constants: C symbols pointing at the single C++ definitions above.
extern "C" {
LIBSESSION_EXPORT extern const int SESSION_PROTOCOL_STANDARD_CHARACTER_LIMIT =
        STANDARD_CHARACTER_LIMIT;
LIBSESSION_EXPORT extern const int SESSION_PROTOCOL_PRO_HIGHER_CHARACTER_LIMIT =
        PRO_HIGHER_CHARACTER_LIMIT;
LIBSESSION_EXPORT extern const int SESSION_PROTOCOL_STANDARD_PINNED_CONVERSATION_LIMIT =
        STANDARD_PINNED_CONVERSATION_LIMIT;
LIBSESSION_EXPORT extern const int SESSION_PROTOCOL_COMMUNITY_OR_1O1_MSG_PADDING =
        COMMUNITY_OR_1O1_MSG_PADDING;
}

static_assert(sizeof(session_protocol_pro_proof::revocation_tag) == 32);
static_assert(
        sizeof(session_protocol_pro_proof::rotating_pubkey) == crypto_sign_ed25519_PUBLICKEYBYTES);
static_assert(sizeof(session_protocol_pro_proof::sig) == crypto_sign_ed25519_BYTES);

static_assert(
        SESSION_PROTOCOL_PRO_PROFILE_FEATURES_COUNT <=
                sizeof(session_protocol_pro_profile_bitset::data) * 8 /*bits per byte*/,
        "There are more feature flags than is available in the bitset, the bitset needs to be "
        "upgraded into an array of bytes");

LIBSESSION_C_API bool session_protocol_pro_profile_bitset_is_set(
        session_protocol_pro_profile_bitset value, SESSION_PROTOCOL_PRO_PROFILE_FEATURES features) {
    bool result = value.data & (1ULL << features);
    return result;
}

LIBSESSION_C_API void session_protocol_pro_profile_bitset_set(
        session_protocol_pro_profile_bitset* value,
        SESSION_PROTOCOL_PRO_PROFILE_FEATURES features) {
    value->data |= (1ULL << features);
}

LIBSESSION_C_API void session_protocol_pro_profile_bitset_unset(
        session_protocol_pro_profile_bitset* value,
        SESSION_PROTOCOL_PRO_PROFILE_FEATURES features) {
    value->data &= ~(1ULL << features);
}

LIBSESSION_C_API bool session_protocol_pro_message_bitset_is_set(
        session_protocol_pro_message_bitset value, SESSION_PROTOCOL_PRO_MESSAGE_FEATURES features) {
    bool result = value.data & (1ULL << features);
    return result;
}

LIBSESSION_C_API void session_protocol_pro_message_bitset_set(
        session_protocol_pro_message_bitset* value,
        SESSION_PROTOCOL_PRO_MESSAGE_FEATURES features) {
    value->data |= (1ULL << features);
}

LIBSESSION_C_API void session_protocol_pro_message_bitset_unset(
        session_protocol_pro_message_bitset* value,
        SESSION_PROTOCOL_PRO_MESSAGE_FEATURES features) {
    value->data &= ~(1ULL << features);
}

LIBSESSION_C_API bool session_protocol_pro_proof_verify_signature(
        session_protocol_pro_proof const* proof,
        uint8_t const* verify_pubkey,
        size_t verify_pubkey_len) {
    if (verify_pubkey_len != crypto_sign_ed25519_PUBLICKEYBYTES)
        return false;
    auto verify_pubkey_span = std::span<const std::uint8_t>(verify_pubkey, verify_pubkey_len);
    auto msg = proof_signed_message(
            proof->revocation_tag.data, proof->rotating_pubkey.data, proof->expiry_ts);
    bool result = proof_verify_message_internal(verify_pubkey_span, proof->sig.data, msg);
    return result;
}

LIBSESSION_C_API void session_protocol_pro_rotating_seed(
        const unsigned char* master_seed, int64_t now_unix_ts, unsigned char* rotating_seed_out) {
    auto seed = session::ProProof::rotating_seed(
            {master_seed, 32}, std::chrono::sys_seconds{std::chrono::seconds{now_unix_ts}});
    std::memcpy(rotating_seed_out, seed.data(), seed.size());
}

LIBSESSION_C_API bool session_protocol_pro_proof_verify_message(
        session_protocol_pro_proof const* proof,
        uint8_t const* sig,
        size_t sig_len,
        uint8_t const* msg,
        size_t msg_len) {
    std::span<const uint8_t> sig_span = {sig, sig_len};
    std::span<const uint8_t> msg_span = {msg, msg_len};
    bool result = proof_verify_message_internal(proof->rotating_pubkey.data, sig_span, msg_span);
    return result;
}

LIBSESSION_C_API bool session_protocol_pro_proof_is_active(
        session_protocol_pro_proof const* proof, int64_t ts) {
    return ts <= proof->expiry_ts;
}

LIBSESSION_C_API SESSION_PROTOCOL_PRO_STATUS session_protocol_pro_proof_status(
        session_protocol_pro_proof const* proof,
        const uint8_t* verify_pubkey,
        size_t verify_pubkey_len,
        int64_t ts,
        const session_protocol_pro_signed_message* signed_msg) {
    SESSION_PROTOCOL_PRO_STATUS result = SESSION_PROTOCOL_PRO_STATUS_VALID;
    if (!session_protocol_pro_proof_verify_signature(proof, verify_pubkey, verify_pubkey_len))
        result = SESSION_PROTOCOL_PRO_STATUS_INVALID_PRO_BACKEND_SIG;

    // Check if the message was signed if the user passed one in to verify against
    if (result == SESSION_PROTOCOL_PRO_STATUS_VALID && signed_msg) {
        if (!session_protocol_pro_proof_verify_message(
                    proof,
                    signed_msg->sig.data,
                    signed_msg->sig.size,
                    signed_msg->msg.data,
                    signed_msg->msg.size))
            result = SESSION_PROTOCOL_PRO_STATUS_INVALID_USER_SIG;
    }

    // Check if the proof has expired
    if (result == SESSION_PROTOCOL_PRO_STATUS_VALID &&
        !session_protocol_pro_proof_is_active(proof, ts))
        result = SESSION_PROTOCOL_PRO_STATUS_EXPIRED;
    return result;
}

LIBSESSION_C_API
session_protocol_pro_features_for_msg session_protocol_pro_features_for_message(
        size_t codepoint_count) {
    ProFeaturesForMsg result_cpp = pro_features_for_message(codepoint_count);
    session_protocol_pro_features_for_msg result = {
            .status = static_cast<SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS>(result_cpp.status),
            .error = result_cpp.error.data(),
            .bitset = {result_cpp.bitset.data},
    };
    return result;
}

LIBSESSION_C_API
session_protocol_encoded_for_destination session_protocol_encode_for_1o1(
        const void* plaintext,
        size_t plaintext_len,
        const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        uint64_t sent_timestamp_ms,
        const bytes33* recipient_pubkey,
        const void* pro_rotating_ed25519_privkey,
        size_t pro_rotating_ed25519_privkey_len,
        char* error,
        size_t error_len) {

    session_protocol_destination dest = {};
    dest.type = SESSION_PROTOCOL_DESTINATION_TYPE_SYNC_OR_1O1;
    dest.pro_rotating_ed25519_privkey = pro_rotating_ed25519_privkey;
    dest.pro_rotating_ed25519_privkey_len = pro_rotating_ed25519_privkey_len;
    dest.recipient_pubkey = *recipient_pubkey;
    dest.sent_timestamp_ms = sent_timestamp_ms;

    session_protocol_encoded_for_destination result = session_protocol_encode_for_destination(
            plaintext,
            plaintext_len,
            ed25519_privkey,
            ed25519_privkey_len,
            &dest,
            error,
            error_len);
    return result;
}

LIBSESSION_C_API
session_protocol_encoded_for_destination session_protocol_encode_for_community_inbox(
        const void* plaintext,
        size_t plaintext_len,
        const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        const bytes33* recipient_pubkey,
        const bytes32* community_pubkey,
        const void* pro_rotating_ed25519_privkey,
        size_t pro_rotating_ed25519_privkey_len,
        char* error,
        size_t error_len) {

    session_protocol_destination dest = {};
    dest.type = SESSION_PROTOCOL_DESTINATION_TYPE_COMMUNITY_INBOX;
    dest.pro_rotating_ed25519_privkey = pro_rotating_ed25519_privkey;
    dest.pro_rotating_ed25519_privkey_len = pro_rotating_ed25519_privkey_len;
    // Unused on the CommunityInbox path (only the envelope-based Group/1o1 path consumes it).
    dest.sent_timestamp_ms = 0;
    dest.recipient_pubkey = *recipient_pubkey;
    dest.community_inbox_server_pubkey = *community_pubkey;

    session_protocol_encoded_for_destination result = session_protocol_encode_for_destination(
            plaintext,
            plaintext_len,
            ed25519_privkey,
            ed25519_privkey_len,
            &dest,
            error,
            error_len);
    return result;
}

LIBSESSION_C_API
session_protocol_encoded_for_destination session_protocol_encode_for_community(
        const void* plaintext,
        size_t plaintext_len,
        const void* pro_rotating_ed25519_privkey,
        size_t pro_rotating_ed25519_privkey_len,
        char* error,
        size_t error_len) {

    session_protocol_destination dest = {};
    dest.type = SESSION_PROTOCOL_DESTINATION_TYPE_COMMUNITY;
    dest.pro_rotating_ed25519_privkey = pro_rotating_ed25519_privkey;
    dest.pro_rotating_ed25519_privkey_len = pro_rotating_ed25519_privkey_len;

    session_protocol_encoded_for_destination result = session_protocol_encode_for_destination(
            plaintext, plaintext_len, nullptr, 0, &dest, error, error_len);
    return result;
}

LIBSESSION_C_API
session_protocol_encoded_for_destination session_protocol_encode_for_group(
        const void* plaintext,
        size_t plaintext_len,
        const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        uint64_t sent_timestamp_ms,
        const bytes33* group_ed25519_pubkey,
        const bytes32* group_enc_key,
        const void* pro_rotating_ed25519_privkey,
        size_t pro_rotating_ed25519_privkey_len,
        char* error,
        size_t error_len) {

    session_protocol_destination dest = {};
    dest.type = SESSION_PROTOCOL_DESTINATION_TYPE_GROUP;
    dest.pro_rotating_ed25519_privkey = pro_rotating_ed25519_privkey;
    dest.pro_rotating_ed25519_privkey_len = pro_rotating_ed25519_privkey_len;
    dest.group_ed25519_pubkey = *group_ed25519_pubkey;
    dest.group_enc_key = *group_enc_key;
    dest.sent_timestamp_ms = sent_timestamp_ms;

    session_protocol_encoded_for_destination result = session_protocol_encode_for_destination(
            plaintext,
            plaintext_len,
            ed25519_privkey,
            ed25519_privkey_len,
            &dest,
            error,
            error_len);
    return result;
}

LIBSESSION_C_API session_protocol_encoded_for_destination session_protocol_encode_for_destination(
        const void* plaintext,
        size_t plaintext_len,
        const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        const session_protocol_destination* dest,
        char* error,
        size_t error_len) {

    session_protocol_encoded_for_destination result = {};

    try {
        std::span<const uint8_t> dest_pro_rotating_ed25519_privkey = std::span(
                reinterpret_cast<const uint8_t*>(dest->pro_rotating_ed25519_privkey),
                reinterpret_cast<const uint8_t*>(dest->pro_rotating_ed25519_privkey) +
                        dest->pro_rotating_ed25519_privkey_len);

        EncryptedForDestinationInternal result_internal = encode_for_destination_internal(
                /*plaintext=*/{static_cast<const uint8_t*>(plaintext), plaintext_len},
                /*ed25519_privkey=*/
                {static_cast<const uint8_t*>(ed25519_privkey), ed25519_privkey_len},
                /*dest_type=*/static_cast<DestinationType>(dest->type),
                /*dest_pro_rotating_ed25519_privkey=*/dest_pro_rotating_ed25519_privkey,
                /*dest_recipient_pubkey=*/dest->recipient_pubkey.data,
                /*dest_sent_timestamp_ms=*/
                std::chrono::milliseconds(dest->sent_timestamp_ms),
                /*dest_community_inbox_server_pubkey=*/
                dest->community_inbox_server_pubkey.data,
                /*dest_group_ed25519_pubkey=*/dest->group_ed25519_pubkey.data,
                /*dest_group_enc_key=*/dest->group_enc_key.data,
                /*use_malloc=*/UseMalloc::Yes);

        result = {
                .success = true,
                .ciphertext = result_internal.ciphertext_c,
        };
    } catch (const std::exception& e) {
        std::string error_cpp = e.what();
        result.error_len_incl_null_terminator = snprintf_clamped(
                                                        error,
                                                        error_len,
                                                        "%.*s",
                                                        static_cast<int>(error_cpp.size()),
                                                        error_cpp.data()) +
                                                1;
    }

    return result;
}

LIBSESSION_C_API void session_protocol_encode_for_destination_free(
        session_protocol_encoded_for_destination* encrypt) {
    if (encrypt) {
        free(encrypt->ciphertext.data);
        *encrypt = {};
    }
}

LIBSESSION_C_API
session_protocol_decoded_envelope session_protocol_decode_envelope(
        const session_protocol_decode_envelope_keys* keys,
        const void* envelope_plaintext,
        size_t envelope_plaintext_len,
        const void* pro_backend_pubkey,
        size_t pro_backend_pubkey_len,
        char* error,
        size_t error_len) {
    session_protocol_decoded_envelope result = {};

    // Setup the pro backend pubkey
    auto pro_backend_pubkey_cpp = maybe_uc32_from_ptr(pro_backend_pubkey, pro_backend_pubkey_len);
    if (!pro_backend_pubkey_cpp) {
        result.error_len_incl_null_terminator = snprintf_clamped(
                                                        error,
                                                        error_len,
                                                        "Invalid pro_backend_pubkey: Key was "
                                                        "set but was not 32 bytes, was: %zu",
                                                        pro_backend_pubkey_len) +
                                                1;
        return result;
    }

    // Setup decryption keys and decrypt
    DecodeEnvelopeKey keys_cpp = {};
    if (keys->group_ed25519_pubkey.size) {
        keys_cpp.group_ed25519_pubkey = std::span<const uint8_t>(
                keys->group_ed25519_pubkey.data, keys->group_ed25519_pubkey.size);
    }

    DecodedEnvelope result_cpp = {};
    for (size_t index = 0; index < keys->decrypt_keys_len; index++) {
        std::span<const uint8_t> key = {
                keys->decrypt_keys[index].data, keys->decrypt_keys[index].size};
        keys_cpp.decrypt_keys = {&key, 1};
        try {
            result_cpp = decode_envelope(
                    keys_cpp,
                    {static_cast<const uint8_t*>(envelope_plaintext), envelope_plaintext_len},
                    *pro_backend_pubkey_cpp);
            result.success = true;
            break;
        } catch (const std::exception& e) {
            std::string error_cpp = e.what();
            result.error_len_incl_null_terminator = snprintf_clamped(
                                                            error,
                                                            error_len,
                                                            "%.*s",
                                                            static_cast<int>(error_cpp.size()),
                                                            error_cpp.data()) +
                                                    1;
        }
    }

    if (keys->decrypt_keys_len == 0) {
        result.error_len_incl_null_terminator =
                snprintf_clamped(error, error_len, "No keys ed25519_privkeys were provided") + 1;
    }

    // Marshall into c type
    try {
        result.content_plaintext = session::span_u8_copy_or_throw(
                result_cpp.content_plaintext.data(), result_cpp.content_plaintext.size());
    } catch (const std::exception& e) {
        std::string error_cpp = e.what();
        result.success = false;
        result.error_len_incl_null_terminator = snprintf_clamped(
                                                        error,
                                                        error_len,
                                                        "%.*s",
                                                        static_cast<int>(error_cpp.size()),
                                                        error_cpp.data()) +
                                                1;
    }

    result.envelope = envelope_from_cpp(result_cpp.envelope);
    if (result_cpp.pro) {
        result.pro = decoded_pro_from_cpp(*result_cpp.pro);
    }

    // Since we support multiple keys, if some of the keys failed but one of them succeeded, we will
    // zero out the error buffer to avoid conflating one of the failures when the function actually
    // succeeded.
    if (result.success)
        result.error_len_incl_null_terminator = 0;

    std::memcpy(
            result.sender_ed25519_pubkey.data,
            result_cpp.sender_ed25519_pubkey.data(),
            sizeof(result.sender_ed25519_pubkey.data));
    std::memcpy(
            result.sender_x25519_pubkey.data,
            result_cpp.sender_x25519_pubkey.data(),
            sizeof(result.sender_x25519_pubkey.data));

    return result;
}

LIBSESSION_C_API
void session_protocol_decode_envelope_free(session_protocol_decoded_envelope* envelope) {
    if (envelope) {
        free(envelope->content_plaintext.data);
        *envelope = {};
    }
}

LIBSESSION_C_API
session_protocol_decoded_community_message session_protocol_decode_for_community(
        const void* content_or_envelope_payload,
        size_t content_or_envelope_payload_len,
        int64_t ts,
        OPTIONAL const void* pro_backend_pubkey,
        size_t pro_backend_pubkey_len,
        OPTIONAL char* error,
        size_t error_len) {
    session_protocol_decoded_community_message result = {};
    auto content_or_envelope_payload_span = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(content_or_envelope_payload),
            content_or_envelope_payload_len);
    auto unix_ts = as_sys_seconds(ts);
    auto pro_backend_pubkey_cpp = maybe_uc32_from_ptr(pro_backend_pubkey, pro_backend_pubkey_len);
    if (!pro_backend_pubkey_cpp) {
        result.error_len_incl_null_terminator = snprintf_clamped(
                                                        error,
                                                        error_len,
                                                        "Invalid pro_backend_pubkey: Key was "
                                                        "set but was not 32 bytes, was: %zu",
                                                        pro_backend_pubkey_len) +
                                                1;
        return result;
    }

    try {
        DecodedCommunityMessage decoded = decode_for_community(
                content_or_envelope_payload_span, unix_ts, *pro_backend_pubkey_cpp);
        result.has_envelope = decoded.envelope.has_value();
        if (result.has_envelope)
            result.envelope = envelope_from_cpp(*decoded.envelope);
        result.content_plaintext = session::span_u8_copy_or_throw(
                decoded.content_plaintext.data(), decoded.content_plaintext.size());
        result.has_pro = decoded.pro.has_value();
        if (decoded.pro_sig)
            std::memcpy(result.pro_sig.data, decoded.pro_sig->data(), decoded.pro_sig->max_size());
        if (decoded.pro)
            result.pro = decoded_pro_from_cpp(*decoded.pro);
        result.success = true;
    } catch (const std::exception& e) {
        std::string error_cpp = e.what();
        result.success = false;
        result.error_len_incl_null_terminator = snprintf_clamped(
                                                        error,
                                                        error_len,
                                                        "%.*s",
                                                        static_cast<int>(error_cpp.size()),
                                                        error_cpp.data()) +
                                                1;
    }

    return result;
}

LIBSESSION_C_API void session_protocol_decode_for_community_free(
        session_protocol_decoded_community_message* community_msg) {
    if (community_msg) {
        free(community_msg->content_plaintext.data);
        *community_msg = {};
    }
}
