#include <fmt/format.h>
#include <oxenc/hex.h>
#include <session/config/groups/keys.h>
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

#include "SessionProtos.pb.h"
#include "WebSocketResources.pb.h"
#include "internal-util.hpp"
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
    .url_website              = "https://getsession.org",
};
// clang-format on

namespace {
std::vector<std::byte> proof_signed_message(
        std::span<const std::byte> revocation_tag,
        std::span<const std::byte> rotating_pubkey,
        std::int64_t expiry_ts) {

    // This must match the Pro proof signed message in pro-wire-protocol.md §2 (built per §1.1). No
    // version is part of the message: the 16-byte domain prefix (BUILD_PROOF_DOMAIN) is itself what
    // binds this proof to its format, since it is covered by the signature.
    return session::pro::signed_message(
            session::BUILD_PROOF_DOMAIN, revocation_tag, rotating_pubkey, expiry_ts);
}

// Copies an optional 32-byte value out of a possibly-null C pointer. A null pointer yields a
// zero-filled value (the "not provided" case); a non-null pointer with the wrong length yields
// nullopt to signal an error.
static std::optional<session::b32> maybe_uc32_from_ptr(const void* ptr, size_t len) {
    session::b32 out = {};
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
    result.msg_bitset = static_cast<uint64_t>(cpp.msg_flags);
    result.profile_bitset = static_cast<uint64_t>(cpp.profile_flags);
    return result;
}

// Builds a C++ ProProof from the C proof struct (the inverse of the proof half of
// decoded_pro_from_cpp).
static session::ProProof proof_from_c(const session_protocol_pro_proof& c) {
    session::ProProof proof = {};
    std::memcpy(
            proof.revocation_tag.data(), c.revocation_tag.data, proof.revocation_tag.max_size());
    std::memcpy(
            proof.rotating_pubkey.data(), c.rotating_pubkey.data, proof.rotating_pubkey.max_size());
    proof.expiry_at = session::as_sys_seconds(c.expiry_ts);
    std::memcpy(proof.sig.data(), c.sig.data, proof.sig.max_size());
    return proof;
}
}  // namespace

namespace session {

static_assert(sizeof(ProProof::revocation_tag) == 32);
static_assert(sizeof(ProProof::rotating_pubkey) == 32);
static_assert(sizeof(ProProof::sig) == 64);

bool ProProof::verify_signature(std::span<const std::byte, 32> verify_pubkey) const {
    return ed25519::verify(sig, verify_pubkey, signed_message());
}

bool ProProof::verify_message(
        std::span<const std::byte, 64> sig, std::span<const std::byte> msg) const {
    return ed25519::verify(sig, rotating_pubkey, msg);
}

bool ProProof::is_active(std::chrono::sys_seconds unix_ts) const {
    return unix_ts <= expiry_at;
}

ProStatus ProProof::status(
        std::span<const std::byte, 32> verify_pubkey,
        std::chrono::sys_seconds unix_ts,
        std::optional<std::span<const std::byte, 64>> user_sig,
        std::span<const std::byte> signed_msg) const {
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

std::vector<std::byte> ProProof::signed_message() const {
    return proof_signed_message(revocation_tag, rotating_pubkey, session::epoch_seconds(expiry_at));
}

cleared_b32 ProProof::rotating_seed(
        std::span<const std::byte> master_seed, std::chrono::sys_seconds now) {
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
    std::string_view dec_sv{dec, static_cast<size_t>(ptr - dec)};

    // Unkeyed, personalised (salt=null) BLAKE2b-256 -- byte-for-byte the libsodium
    // crypto_generichash_blake2b_salt_personal this replaces; the wrapper concatenates its args.
    auto out = session::hash::blake2b_pers<32>(
            "ProRotatingSeed_"_b2b_pers, master_seed.first(32), dec_sv);

    cleared_b32 result = {};
    std::memcpy(result.data(), out.data(), result.size());
    return result;
}

};  // namespace session

namespace session {

ProFeaturesForMsg pro_features_for_message(size_t codepoint_count) {
    ProFeaturesForMsg result = {};
    result.status = ProFeaturesForMsgStatus::Success;
    if (codepoint_count > STANDARD_CHARACTER_LIMIT) {
        if (codepoint_count <= PRO_HIGHER_CHARACTER_LIMIT) {
            result.flags |= ProMessageFlags::CharLimit10k;
        } else {
            result.error = "Message exceeds the maximum character limit allowed";
            result.status = ProFeaturesForMsgStatus::ExceedsCharacterLimit;
        }
    }
    return result;
}

constexpr std::byte PADDING_TERMINATING_BYTE{0x80};
std::vector<std::byte> pad_message(std::span<const std::byte> payload) {

    // Calculate amount of padding required
    size_t padded_content_size = payload.size() + 1 /*padding byte*/;
    uint8_t const bytes_for_padding =
            COMMUNITY_OR_1O1_MSG_PADDING - (padded_content_size % COMMUNITY_OR_1O1_MSG_PADDING);
    padded_content_size += bytes_for_padding;
    assert(padded_content_size % COMMUNITY_OR_1O1_MSG_PADDING == 0);

    // Do the padding
    std::vector<std::byte> result;
    result.resize(padded_content_size);
    std::memcpy(result.data(), payload.data(), payload.size());
    result[payload.size()] = PADDING_TERMINATING_BYTE;
    return result;
}

static std::span<const std::byte> unpad_message(std::span<const std::byte> payload) {
    auto size = payload.size() - count_trailing(payload);

    // The 0x80 terminator is required by the padding scheme, so its absence means the message was
    // not padded at all.
    // TODO: We should enforce this but no client enforces it right now.
    if (size > 0 && payload[size - 1] == PADDING_TERMINATING_BYTE)
        size--;

    return payload.first(size);
}

// Attaches a Session Pro signature to an envelope. With no pro key a decoy signature is attached
// instead, so that pro and non-pro messages are indistinguishable on the wire (see
// ed25519::decoy_signature).
static void attach_pro_sig_to_envelope(
        SessionProtos::Envelope& envelope,
        std::span<const std::byte> content,
        const ed25519::OptionalPrivKeySpan& pro_key) {
    b64 signature = pro_key ? ed25519::sign(*pro_key, content) : ed25519::decoy_signature();
    std::string* pro_sig = envelope.mutable_prosig();
    pro_sig->assign(reinterpret_cast<const char*>(signature.data()), signature.size());
}

// TODO: We don't need to actually pad the community message since that's unencrypted,
// there's no need to make the message sizes uniform but we need it for backwards
// compat. We can remove this eventually, first step is to unify the clients.
std::vector<std::byte> encode_for_community(
        std::span<const std::byte> plaintext,
        const ed25519::OptionalPrivKeySpan& pro_rotating_ed25519_privkey) {
    if (!pro_rotating_ed25519_privkey)
        return pad_message(plaintext);

    // TODO: Sub-optimal, but we parse the content again to make sure it's valid. Sign
    // the blob then, fill in the signature in-place as part of the transitioning of
    // open groups messages to envelopes. As part of that, libsession is going to take
    // responsibility of constructing community messages so that eventually all
    // platforms switch over to envelopes and we can change the implementation across
    // all platforms in one swoop and remove this.
    //
    // Parse the content blob
    SessionProtos::Content content_w_sig;
    if (!content_w_sig.ParseFromArray(plaintext.data(), plaintext.size()))
        throw std::runtime_error{"Parsing community message failed"};

    if (content_w_sig.has_prosigforcommunitymessageonly())
        throw std::runtime_error{
                "Pro signature for community message must not be set. Libsession's "
                "responsible for generating the signature and setting it"};

    // We need to sign the padded content, so we pad the `Content` then sign it
    std::vector<std::byte> padded = pad_message(plaintext);
    auto pro_sig = ed25519::sign(*pro_rotating_ed25519_privkey, padded);

    // Now assign the community specific pro signature field, reserialize it and we have
    // to, yes, pad it again. This is all temporary wasted work whilst transitioning
    // open groups.
    content_w_sig.set_prosigforcommunitymessageonly(
            reinterpret_cast<const char*>(pro_sig.data()), pro_sig.size());
    std::vector<std::byte> reserialized(content_w_sig.ByteSizeLong());
    [[maybe_unused]] bool ok =
            content_w_sig.SerializeToArray(reserialized.data(), reserialized.size());
    assert(ok);
    return pad_message(reserialized);
}

std::vector<std::byte> encode_for_community_inbox(
        std::span<const std::byte> plaintext,
        const ed25519::PrivKeySpan& ed25519_privkey,
        std::span<const std::byte, 33> recipient_pubkey,
        std::span<const std::byte, 32> community_pubkey,
        const ed25519::OptionalPrivKeySpan& pro_rotating_ed25519_privkey) {
    std::vector<std::byte> content = encode_for_community(plaintext, pro_rotating_ed25519_privkey);
    return encrypt_for_blinded_recipient(
            ed25519_privkey, community_pubkey, recipient_pubkey, content);
}

std::vector<std::byte> encode_dm_v1(
        std::span<const std::byte> plaintext,
        const ed25519::PrivKeySpan& ed25519_privkey,
        sys_ms sent_timestamp,
        std::span<const std::byte, 33> recipient_pubkey,
        const ed25519::OptionalPrivKeySpan& pro_rotating_ed25519_privkey) {
    // For 1o1 messages, encrypt the padded payload for the recipient. See:
    //   https://github.com/session-foundation/session-desktop/blob/a04e62427034a6b6fee39dcff7dbabf0d0131b13/ts/session/crypto/BufferPadding.ts#L49
    std::vector<std::byte> encrypted =
            encrypt_for_recipient(ed25519_privkey, recipient_pubkey, pad_message(plaintext));

    // Create envelope.
    // Set sourcedevice to 1 as per:
    //   https://github.com/session-foundation/session-ios/blob/82deef869d0f7389b799295817f42ad14f8a1316/SessionMessagingKit/Utilities/MessageWrapper.swift#L57
    SessionProtos::Envelope envelope;
    envelope.set_type(SessionProtos::Envelope_Type_SESSION_MESSAGE);
    envelope.set_sourcedevice(1);
    envelope.set_timestamp(epoch_ms(sent_timestamp));
    envelope.set_content(encrypted.data(), encrypted.size());
    attach_pro_sig_to_envelope(envelope, encrypted, pro_rotating_ed25519_privkey);

    // Wrap in websocket message
    WebSocketProtos::WebSocketMessage msg;
    msg.set_type(WebSocketProtos::WebSocketMessage_Type::WebSocketMessage_Type_REQUEST);
    WebSocketProtos::WebSocketRequestMessage* req_msg = msg.mutable_request();
    req_msg->set_verb("");      // Required but unused on iOS
    req_msg->set_path("");      // Required but unused on iOS
    req_msg->set_requestid(0);  // Required but unused on iOS
    req_msg->set_body(envelope.SerializeAsString());

    std::vector<std::byte> result(msg.ByteSizeLong());
    [[maybe_unused]] bool ok = msg.SerializeToArray(result.data(), result.size());
    assert(ok);
    return result;
}

std::vector<std::byte> encode_for_group(
        std::span<const std::byte> plaintext,
        const ed25519::PrivKeySpan& ed25519_privkey,
        std::chrono::milliseconds sent_timestamp,
        std::span<const std::byte, 33> group_ed25519_pubkey,
        std::span<const std::byte, 32> group_enc_key,
        const ed25519::OptionalPrivKeySpan& pro_rotating_ed25519_privkey) {
    if (group_ed25519_pubkey[0] != std::byte{static_cast<uint8_t>(SessionIDPrefix::group)}) {
        // Legacy groups which have a 05 prefixed key
        throw std::runtime_error{
                "Unsupported configuration, encrypting for a legacy group (0x05 prefix) is "
                "no longer supported"};
    }

    // Create envelope.
    // Set sourcedevice to 1 as per:
    //   https://github.com/session-foundation/session-ios/blob/82deef869d0f7389b799295817f42ad14f8a1316/SessionMessagingKit/Utilities/MessageWrapper.swift#L57
    SessionProtos::Envelope envelope;
    envelope.set_type(SessionProtos::Envelope_Type_CLOSED_GROUP_MESSAGE);
    envelope.set_sourcedevice(1);
    envelope.set_timestamp(sent_timestamp.count());
    envelope.set_content(plaintext.data(), plaintext.size());
    attach_pro_sig_to_envelope(envelope, plaintext, pro_rotating_ed25519_privkey);

    std::string bytes = envelope.SerializeAsString();
    return encrypt_for_group(
            ed25519_privkey,
            group_ed25519_pubkey.subspan<1>(),
            group_enc_key,
            to_span(bytes),
            /*compress*/ true,
            /*padding*/ 256);
}

// Parses the optional envelope metadata fields that are encoded identically for every message type
// (source device and server timestamp) into an Envelope.
static void parse_common_envelope_fields(Envelope& env, const SessionProtos::Envelope& pb) {
    if (pb.has_sourcedevice()) {
        env.source_device = pb.sourcedevice();
        env.flags |= SESSION_PROTOCOL_ENVELOPE_FLAGS_SOURCE_DEVICE;
    }
    if (pb.has_servertimestamp()) {
        env.server_timestamp = pb.servertimestamp();
        env.flags |= SESSION_PROTOCOL_ENVELOPE_FLAGS_SERVER_TIMESTAMP;
    }
}

// Shared helper 1: parses envelope metadata fields (timestamp, source, etc.) from an
// already-parsed Envelope protobuf.
static void parse_envelope_fields(
        DecodedEnvelope& result, const SessionProtos::Envelope& envelope) {

    // TODO: We do not parse the envelope type anymore, we infer the type from the namespace.
    // Deciding whether or not we decrypt the envelope vs the content depends on the function
    // called (dm vs group) so we don't care about the type anymore.  When the type is removed
    // from the schema, we can remove this TODO.

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

    parse_common_envelope_fields(result.envelope, envelope);
}

// Parses the proof and feature flags embedded in a protobuf ProMessage into a DecodedPro. A proof
// we can't read is NOT fatal: it degrades to a non-pro message flagged ProStatus::Invalid (the
// caller then skips signature evaluation), so a future proof format -- which arrives as its own
// field/message, not a version bump on this one -- cannot make an older client silently drop the
// whole message. Throws only when a proof that IS present is structurally malformed (corruption,
// not forward-compat). The caller evaluates `.status` for a proof that parsed.
static DecodedPro parse_pro_message(const SessionProtos::ProMessage& pro_msg) {
    DecodedPro pro = {};
    pro.msg_flags = static_cast<ProMessageFlags>(pro_msg.msgbitset());
    pro.profile_flags = static_cast<ProProfileFlags>(pro_msg.profilebitset());

    // No proof to read: either the sender attached none, or it is in a format we don't know -- a
    // new proof format is a new field/message rather than a version bump on this one, so to this
    // client it simply isn't here. Nothing to evaluate, so flag Invalid and let the caller deliver
    // a non-pro message rather than dropping it.
    if (!pro_msg.has_proof()) {
        pro.status = ProStatus::Invalid;
        return pro;
    }

    // A proof that is present but the wrong shape is corruption, not forward-compat: hard error.
    const SessionProtos::ProProof& proto_proof = pro_msg.proof();
    ProProof& proof = pro.proof;
    bool valid = proto_proof.has_revocationtag() &&
                 proto_proof.revocationtag().size() == proof.revocation_tag.max_size() &&
                 proto_proof.has_rotatingpublickey() &&
                 proto_proof.rotatingpublickey().size() == proof.rotating_pubkey.max_size() &&
                 proto_proof.has_expiryunixts() && proto_proof.has_sig() &&
                 proto_proof.sig().size() == proof.sig.max_size();
    if (!valid)
        throw std::runtime_error{"Parse failed, pro metadata was malformed"};

    std::memcpy(
            proof.revocation_tag.data(),
            proto_proof.revocationtag().data(),
            proto_proof.revocationtag().size());
    std::memcpy(
            proof.rotating_pubkey.data(),
            proto_proof.rotatingpublickey().data(),
            proto_proof.rotatingpublickey().size());
    proof.expiry_at = session::as_sys_seconds(proto_proof.expiryunixts());
    std::memcpy(proof.sig.data(), proto_proof.sig().data(), proto_proof.sig().size());
    return pro;
}

// Shared helper 2: parses Content protobuf from result.content_plaintext (which must already be
// set) and extracts pro metadata/verification.
static void parse_content_and_pro(
        DecodedEnvelope& result,
        const SessionProtos::Envelope& envelope,
        std::span<const std::byte, 32> pro_backend_pubkey) {

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
        if (pro_sig.size() != 64)
            throw std::runtime_error("Parse envelope failed, pro signature has wrong size");
        static_assert(sizeof(result.envelope.pro_sig) == 64);
        std::memcpy(result.envelope.pro_sig.data(), pro_sig.data(), pro_sig.size());

        if (content.has_promessage()) {
            if (!content.sigtimestamp())
                throw std::runtime_error{fmt::format(
                        "Content does not have signature timestamp set, pro proof expiry is "
                        "unverifiable (content was {}b)",
                        result.content_plaintext.size())};

            // Mark the envelope as having a pro signature that the caller can use.
            result.envelope.flags |= SESSION_PROTOCOL_ENVELOPE_FLAGS_PRO_SIG;
            DecodedPro& pro = result.pro.emplace(parse_pro_message(content.promessage()));

            // A proof we couldn't read is already flagged ProStatus::Invalid, with no proof to
            // check -- leave it as non-pro.
            if (pro.status != ProStatus::Invalid) {
                // Evaluate the pro status given the extracted components (was it signed, is it
                // expired, was the message signed validly?)
                // Note that we sign the envelope content wholesale. For 1o1 which are padded to 160
                // bytes, this means that we expected the user to have signed the padding as well.
                auto unix_ts = std::chrono::floor<std::chrono::seconds>(
                        std::chrono::sys_time<std::chrono::milliseconds>(
                                std::chrono::milliseconds(content.sigtimestamp())));
                // pro_sig.size() validated == 64 above
                pro.status = pro.proof.status(
                        pro_backend_pubkey,
                        unix_ts,
                        to_byte_span<64>(pro_sig.data()),
                        to_span(envelope.content()));
            }
        }
    }
}

DecodedEnvelope decode_dm_envelope(
        const ed25519::PrivKeySpan& ed25519_privkey,
        std::span<const std::byte> envelope_payload,
        std::span<const std::byte, 32> pro_backend_pubkey) {
    DecodedEnvelope result = {};

    // 1-on-1/sync messages are wrapped in a WebSocket message protobuf
    WebSocketProtos::WebSocketMessage ws_msg;
    if (!ws_msg.ParseFromArray(envelope_payload.data(), envelope_payload.size()))
        throw std::runtime_error{fmt::format(
                "Parse websocket wrapped envelope from payload failed: {}",
                envelope_payload.size())};
    if (!ws_msg.has_request())
        throw std::runtime_error{"Parse websocket wrapped envelope failed, missing request"};
    if (!ws_msg.request().has_body())
        throw std::runtime_error{"Parse websocket wrapped envelope failed, missing request body"};

    SessionProtos::Envelope envelope = {};
    if (!envelope.ParseFromArray(ws_msg.request().body().data(), ws_msg.request().body().size()))
        throw std::runtime_error{"Parse envelope from plaintext failed"};

    parse_envelope_fields(result, envelope);

    if (!envelope.has_content())
        throw std::runtime_error{"Parse decrypted message failed, missing content"};

    // The inner content is encrypted with Session protocol (Ed25519 DH)
    auto [content_plaintext, sender_ed25519_pubkey] =
            session::decrypt_incoming(ed25519_privkey, to_span(envelope.content()));

    // Strip padding from content
    auto unpadded = unpad_message(content_plaintext);
    content_plaintext.resize(unpadded.size());
    result.content_plaintext = std::move(content_plaintext);

    result.sender_ed25519_pubkey = sender_ed25519_pubkey;
    result.sender_x25519_pubkey = ed25519::pk_to_x25519(sender_ed25519_pubkey);

    parse_content_and_pro(result, envelope, pro_backend_pubkey);
    return result;
}

DecodedEnvelope decode_group_envelope(
        std::span<std::span<const std::byte, 32>> group_keys,
        std::span<const std::byte, 32> group_ed25519_pubkey,
        std::span<const std::byte> envelope_payload,
        std::span<const std::byte, 32> pro_backend_pubkey) {
    DecodedEnvelope result = {};

    // Groups v2: the entire envelope payload is encrypted with a group symmetric key
    DecryptGroupMessage decrypt =
            decrypt_group_message(group_keys, group_ed25519_pubkey, envelope_payload);

    if (decrypt.session_id.size() != 66)
        throw std::runtime_error{fmt::format(
                "Parse encrypted envelope failed, extracted session ID was wrong size: {}",
                decrypt.session_id.size())};

    assert(decrypt.session_id.starts_with("05"));
    oxenc::from_hex(
            decrypt.session_id.begin() + 2,
            decrypt.session_id.end(),
            result.sender_x25519_pubkey.begin());

    SessionProtos::Envelope envelope = {};
    if (!envelope.ParseFromArray(decrypt.plaintext.data(), decrypt.plaintext.size()))
        throw std::runtime_error{"Parse envelope from decrypted group data failed"};

    parse_envelope_fields(result, envelope);

    if (!envelope.has_content())
        throw std::runtime_error{"Parse decrypted message failed, missing content"};

    // Group content is plaintext (the envelope itself was the encrypted layer)
    result.content_plaintext = to_vector(envelope.content());

    parse_content_and_pro(result, envelope, pro_backend_pubkey);
    return result;
}

DecodedCommunityMessage decode_for_community(
        std::span<const std::byte> content_or_envelope_payload,
        std::chrono::sys_seconds unix_ts,
        std::span<const std::byte, 32> pro_backend_pubkey) {
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
    std::optional<std::span<const std::byte>> pro_sig;
    SessionProtos::Envelope pb_envelope = {};
    {
        bool envelope_parsed = pb_envelope.ParseFromArray(
                content_or_envelope_payload.data(), content_or_envelope_payload.size());

        if (envelope_parsed) {
            // Create the envelope
            Envelope& envelope = result.envelope.emplace();
            result.content_plaintext = to_vector(pb_envelope.content());

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

            parse_common_envelope_fields(envelope, pb_envelope);

            // Parse pro signature (optional)
            if (pb_envelope.has_prosig()) {
                envelope.flags |= SESSION_PROTOCOL_ENVELOPE_FLAGS_PRO_SIG;
                pro_sig = to_span(pb_envelope.prosig());
            }
        } else {
            // TODO: Do wasteful copy in the interim whilst transitioning protocol
            result.content_plaintext = std::vector<std::byte>(
                    content_or_envelope_payload.begin(), content_or_envelope_payload.end());
        }
    }

    // Parse the content blob
    std::span<const std::byte> unpadded_content = unpad_message(result.content_plaintext);
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
        if (pro_sig->size() != 64)
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
        DecodedPro& pro = result.pro.emplace(parse_pro_message(content.promessage()));

        // A proof we couldn't read is already flagged ProStatus::Invalid, with no proof to
        // check -- leave it as non-pro.
        if (pro.status != ProStatus::Invalid) {
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
                pro.status = pro.proof.status(
                        pro_backend_pubkey, unix_ts, *result.pro_sig, result.content_plaintext);
            } else {
                SessionProtos::Content content_copy_without_sig = content;
                assert(content_copy_without_sig.has_prosigforcommunitymessageonly());

                // Remove signature from the payload
                content_copy_without_sig.clear_prosigforcommunitymessageonly();
                assert(!content_copy_without_sig.has_prosigforcommunitymessageonly());

                // Reserialise the payload without the signature, repad it then verify the signature
                std::vector<std::byte> content_copy_without_sig_payload =
                        pad_message(to_span(content_copy_without_sig.SerializeAsString()));

                pro.status = pro.proof.status(
                        pro_backend_pubkey,
                        unix_ts,
                        *result.pro_sig,
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
static_assert(sizeof(session_protocol_pro_proof::rotating_pubkey) == 32);
static_assert(sizeof(session_protocol_pro_proof::sig) == 64);

// Session Pro feature flag bit constants exposed to the C API. The C++ enum classes
// (session::ProProfileFlags / session::ProMessageFlags) are the source of truth; these mirror their
// underlying values so C callers can OR/test them against a plain uint64_t bitset.
const uint64_t SESSION_PROTOCOL_PRO_PROFILE_FEATURE_PRO_BADGE =
        static_cast<uint64_t>(ProProfileFlags::ProBadge);
const uint64_t SESSION_PROTOCOL_PRO_PROFILE_FEATURE_ANIMATED_AVATAR =
        static_cast<uint64_t>(ProProfileFlags::AnimatedAvatar);
const uint64_t SESSION_PROTOCOL_PRO_MESSAGE_FEATURE_10K_CHARACTER_LIMIT =
        static_cast<uint64_t>(ProMessageFlags::CharLimit10k);

LIBSESSION_C_API bool session_protocol_pro_proof_verify_signature(
        session_protocol_pro_proof const* proof,
        uint8_t const* verify_pubkey,
        size_t verify_pubkey_len) {
    if (verify_pubkey_len != 32)
        return false;
    auto msg = proof_signed_message(
            to_byte_span(proof->revocation_tag.data),
            to_byte_span(proof->rotating_pubkey.data),
            proof->expiry_ts);
    return ed25519::verify(to_byte_span(proof->sig.data), to_byte_span<32>(verify_pubkey), msg);
}

LIBSESSION_C_API void session_protocol_pro_rotating_seed(
        const unsigned char* master_seed, int64_t now_unix_ts, unsigned char* rotating_seed_out) {
    auto seed = session::ProProof::rotating_seed(
            to_byte_span(master_seed, 32),
            std::chrono::sys_seconds{std::chrono::seconds{now_unix_ts}});
    std::memcpy(rotating_seed_out, seed.data(), seed.size());
}

LIBSESSION_C_API bool session_protocol_pro_proof_verify_message(
        session_protocol_pro_proof const* proof,
        uint8_t const* sig,
        size_t sig_len,
        uint8_t const* msg,
        size_t msg_len) {
    if (sig_len != 64)
        return false;
    return ed25519::verify(
            to_byte_span<64>(sig),
            to_byte_span(proof->rotating_pubkey.data),
            to_byte_span(msg, msg_len));
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
    // ProProof::status is the single source of truth for the backend-sig -> user-sig -> expiry
    // evaluation. The C API additionally validates the caller's buffer lengths (which the C++ API
    // encodes as fixed-size spans), so handle those here and delegate the rest.
    if (verify_pubkey_len != 32)
        return SESSION_PROTOCOL_PRO_STATUS_INVALID_PRO_BACKEND_SIG;

    std::optional<std::span<const std::byte, 64>> user_sig;
    std::span<const std::byte> user_msg;
    bool bad_user_sig = false;
    if (signed_msg) {
        if (signed_msg->sig.size == 64) {
            user_sig = to_byte_span<64>(signed_msg->sig.data);
            user_msg = to_byte_span(signed_msg->msg.data, signed_msg->msg.size);
        } else
            bad_user_sig = true;  // a wrong-length signature can never verify
    }

    ProStatus status = proof_from_c(*proof).status(
            to_byte_span<32>(verify_pubkey), as_sys_seconds(ts), user_sig, user_msg);

    // ProProof::status can't see a wrong-length signature (it takes a fixed-size span), so surface
    // the C API's length check here while keeping the ordering: a bad user signature supersedes a
    // valid or expired result, but not a failed backend signature.
    if (bad_user_sig && status != ProStatus::InvalidProBackendSig)
        status = ProStatus::InvalidUserSig;

    return static_cast<SESSION_PROTOCOL_PRO_STATUS>(status);
}

LIBSESSION_C_API
session_protocol_pro_features_for_msg session_protocol_pro_features_for_message(
        size_t codepoint_count) {
    auto result_cpp = pro_features_for_message(codepoint_count);
    return session_protocol_pro_features_for_msg{
            .status = static_cast<SESSION_PROTOCOL_PRO_FEATURES_FOR_MSG_STATUS>(result_cpp.status),
            .error = result_cpp.error.data(),
            .bitset = static_cast<uint64_t>(result_cpp.flags),
    };
}

// Shared try/catch wrapper for all C encode functions.
template <typename Fn>
static session_protocol_encoded_for_destination c_encode_impl(
        char* error, size_t error_len, Fn&& fn) {
    session_protocol_encoded_for_destination result = {};
    try {
        auto ciphertext = fn();
        result = {
                .success = true,
                .ciphertext = span_u8_copy_or_throw(ciphertext.data(), ciphertext.size()),
        };
    } catch (const std::exception& e) {
        result.error_len_incl_null_terminator = copy_c_str(error, error_len, e.what());
    }
    return result;
}

LIBSESSION_C_API
session_protocol_encoded_for_destination session_protocol_encode_dm_v1(
        const void* plaintext,
        size_t plaintext_len,
        const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        uint64_t sent_timestamp_ms,
        const cbytes33* recipient_pubkey,
        const void* pro_rotating_ed25519_privkey,
        size_t pro_rotating_ed25519_privkey_len,
        char* error,
        size_t error_len) {
    return c_encode_impl(error, error_len, [&] {
        return encode_dm_v1(
                std::span{static_cast<const std::byte*>(plaintext), plaintext_len},
                ed25519::PrivKeySpan{
                        static_cast<const unsigned char*>(ed25519_privkey), ed25519_privkey_len},
                from_epoch_ms(sent_timestamp_ms),
                to_byte_span(recipient_pubkey->data),
                ed25519::OptionalPrivKeySpan{
                        static_cast<const unsigned char*>(pro_rotating_ed25519_privkey),
                        pro_rotating_ed25519_privkey_len});
    });
}

LIBSESSION_C_API
session_protocol_encoded_for_destination session_protocol_encode_for_community_inbox(
        const void* plaintext,
        size_t plaintext_len,
        const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        const cbytes33* recipient_pubkey,
        const cbytes32* community_pubkey,
        const void* pro_rotating_ed25519_privkey,
        size_t pro_rotating_ed25519_privkey_len,
        char* error,
        size_t error_len) {
    return c_encode_impl(error, error_len, [&] {
        return encode_for_community_inbox(
                std::span{static_cast<const std::byte*>(plaintext), plaintext_len},
                ed25519::PrivKeySpan{
                        static_cast<const unsigned char*>(ed25519_privkey), ed25519_privkey_len},
                to_byte_span(recipient_pubkey->data),
                to_byte_span(community_pubkey->data),
                ed25519::OptionalPrivKeySpan{
                        static_cast<const unsigned char*>(pro_rotating_ed25519_privkey),
                        pro_rotating_ed25519_privkey_len});
    });
}

LIBSESSION_C_API
session_protocol_encoded_for_destination session_protocol_encode_for_community(
        const void* plaintext,
        size_t plaintext_len,
        const void* pro_rotating_ed25519_privkey,
        size_t pro_rotating_ed25519_privkey_len,
        char* error,
        size_t error_len) {
    return c_encode_impl(error, error_len, [&] {
        return encode_for_community(
                std::span{static_cast<const std::byte*>(plaintext), plaintext_len},
                ed25519::OptionalPrivKeySpan{
                        static_cast<const unsigned char*>(pro_rotating_ed25519_privkey),
                        pro_rotating_ed25519_privkey_len});
    });
}

LIBSESSION_C_API
session_protocol_encoded_for_destination session_protocol_encode_for_group(
        const void* plaintext,
        size_t plaintext_len,
        const void* ed25519_privkey,
        size_t ed25519_privkey_len,
        uint64_t sent_timestamp_ms,
        const cbytes33* group_ed25519_pubkey,
        const cbytes32* group_enc_key,
        const void* pro_rotating_ed25519_privkey,
        size_t pro_rotating_ed25519_privkey_len,
        char* error,
        size_t error_len) {
    return c_encode_impl(error, error_len, [&] {
        return encode_for_group(
                std::span{static_cast<const std::byte*>(plaintext), plaintext_len},
                ed25519::PrivKeySpan{
                        static_cast<const unsigned char*>(ed25519_privkey), ed25519_privkey_len},
                std::chrono::milliseconds(sent_timestamp_ms),
                to_byte_span(group_ed25519_pubkey->data),
                to_byte_span(group_enc_key->data),
                ed25519::OptionalPrivKeySpan{
                        static_cast<const unsigned char*>(pro_rotating_ed25519_privkey),
                        pro_rotating_ed25519_privkey_len});
    });
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
        result.error_len_incl_null_terminator = format_c_str(
                error,
                error_len,
                "Invalid pro_backend_pubkey: Key was set but was not 32 bytes, was: {}",
                pro_backend_pubkey_len);
        return result;
    }

    std::span<const std::byte> payload{
            static_cast<const std::byte*>(envelope_plaintext), envelope_plaintext_len};

    DecodedEnvelope result_cpp = {};
    if (keys->group_ed25519_pubkey.size == 32) {
        // Groups v2 path: decrypt with group symmetric keys
        auto group_pk = to_byte_span<32>(keys->group_ed25519_pubkey.data);

        std::vector<std::span<const std::byte, 32>> group_keys;
        group_keys.reserve(keys->decrypt_keys_len);
        for (size_t i = 0; i < keys->decrypt_keys_len; i++) {
            if (keys->decrypt_keys[i].size != 32)
                throw std::invalid_argument{fmt::format(
                        "Invalid group encryption key: expected 32 bytes, got {}",
                        keys->decrypt_keys[i].size)};
            group_keys.emplace_back(to_byte_span<32>(keys->decrypt_keys[i].data));
        }

        try {
            result_cpp =
                    decode_group_envelope(group_keys, group_pk, payload, *pro_backend_pubkey_cpp);
            result.success = true;
        } catch (const std::exception& e) {
            result.error_len_incl_null_terminator = format_c_str(error, error_len, "{}", e.what());
        }
    } else if (keys->group_ed25519_pubkey.size) {
        result.error_len_incl_null_terminator = format_c_str(
                error,
                error_len,
                "Invalid group_ed25519_pubkey: must be exactly 32 bytes, was: {}",
                keys->group_ed25519_pubkey.size);
        return result;
    } else {
        // DM path: decrypt with Ed25519 private key(s)
        for (size_t index = 0; index < keys->decrypt_keys_len; index++) {
            try {
                ed25519::PrivKeySpan privkey{
                        keys->decrypt_keys[index].data, keys->decrypt_keys[index].size};
                result_cpp = decode_dm_envelope(privkey, payload, *pro_backend_pubkey_cpp);
                result.success = true;
                break;
            } catch (const std::exception& e) {
                result.error_len_incl_null_terminator =
                        format_c_str(error, error_len, "{}", e.what());
            }
        }

        if (keys->decrypt_keys_len == 0) {
            result.error_len_incl_null_terminator =
                    format_c_str(error, error_len, "No ed25519 private keys were provided");
        }
    }

    // Marshall into c type
    try {
        result.content_plaintext = session::span_u8_copy_or_throw(
                result_cpp.content_plaintext.data(), result_cpp.content_plaintext.size());
    } catch (const std::exception& e) {
        result.success = false;
        result.error_len_incl_null_terminator = copy_c_str(error, error_len, e.what());
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
    std::span content_or_envelope_payload_span{
            static_cast<const std::byte*>(content_or_envelope_payload),
            content_or_envelope_payload_len};
    auto unix_ts = session::as_sys_seconds(ts);
    auto pro_backend_pubkey_cpp = maybe_uc32_from_ptr(pro_backend_pubkey, pro_backend_pubkey_len);
    if (!pro_backend_pubkey_cpp) {
        result.error_len_incl_null_terminator = format_c_str(
                error,
                error_len,
                "Invalid pro_backend_pubkey: Key was set but was not 32 bytes, was: {}",
                pro_backend_pubkey_len);
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
        result.success = false;
        result.error_len_incl_null_terminator = copy_c_str(error, error_len, e.what());
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
