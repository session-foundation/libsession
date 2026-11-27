#include "session/session_encrypt.hpp"

#include <oxenc/base64.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>
#include <session/session_encrypt.h>
#include <zstd.h>

#include <array>
#include <cassert>
#include <cstring>
#include <oxen/log.hpp>
#include <session/crypto/mlkem768.hpp>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "internal-util.hpp"
#include "session/blinding.hpp"
#include "session/clock.hpp"
#include "session/crypto/ed25519.hpp"
#include "session/crypto/x25519.hpp"
#include "session/encrypt.hpp"
#include "session/hash.hpp"
#include "session/random.hpp"
#include "session/sodium_array.hpp"
#include "session/types.hpp"
#include "session/util.hpp"

using namespace std::literals;
using namespace session::literals;

namespace session {

namespace detail {
    // detail::to_hashable takes either an integral type, system_clock::time_point, or a string
    // type and converts it to a string_view by writing an integer value (using std::to_chars)
    // into the buffer space (which should be at least 20 bytes), and returning a string_view
    // into the written buffer space.  For strings/string_views the string_view is returned
    // directly from the argument. system_clock::time_points are converted into integral
    // milliseconds since epoch then treated as an integer value.
    template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    std::string_view to_hashable(const T& val, char*& buffer) {
        std::ostringstream ss;
        ss << val;

        std::string str = ss.str();
        std::copy(str.begin(), str.end(), buffer);
        std::string_view s(buffer, str.length());
        buffer += str.length();
        return s;
    }
    inline std::string_view to_hashable(
            const std::chrono::system_clock::time_point& val, char*& buffer) {
        return to_hashable(epoch_ms(val), buffer);
    }
    template <typename T, std::enable_if_t<std::is_convertible_v<T, std::string_view>, int> = 0>
    std::string_view to_hashable(const T& value, char*&) {
        return value;
    }

}  // namespace detail

// Version tag we prepend to encrypted-for-blinded-user messages.  This is here so we can detect if
// some future version changes the format (and if not even try to load it).
inline constexpr unsigned char BLINDED_ENCRYPT_VERSION = 0;

// Constants for v2 PFS+PQ message encryption/decryption

// BLAKE2b personalization for the key indicator shared secret (KISS): a 2-byte hash that lets the
// recipient cheaply identify which of their account keys was used without revealing it externally.
constexpr auto V2_KISS_PERS = "Session-Msg-KISS"_b2b_pers;

// BLAKE2b personalization for the inner-message signature hash.
constexpr auto V2_MSG_SIG_PERS = "SessionV2Message"_b2b_pers;

// X-Wing KDF domain separator from draft-connolly-cfrg-xwing-kem: the 6 ASCII bytes '\.//^\'.
// SHA3-256(ssₘ || ssₓ || E || X || V2_XWING_LABEL) produces the combined X-Wing shared secret.
constexpr auto V2_XWING_LABEL =  //
        R"(\./)"
        R"(/^\)"_bytes;

// SHAKE256 domain prefix for deriving the XChaCha20+Poly1305 key and nonce from the X-Wing SS.
constexpr auto V2_SS_DOMAIN = "SessionV2MessageSS"_bytes;

// Shared v2 wire-format layout constants (used in both encrypt and decrypt)
static constexpr size_t V2_AEAD_OVERHEAD = encryption::XCHACHA20_ABYTES;
static constexpr size_t V2_NONCE_SIZE = encryption::XCHACHA20_NONCEBYTES;
static constexpr size_t V2_HEADER_SIZE = 2 + 2 + 32 + mlkem768::CIPHERTEXTBYTES;
static constexpr size_t V2_OUTER_OVERHEAD = V2_HEADER_SIZE + V2_AEAD_OVERHEAD;
static constexpr size_t V2_MIN_FINAL_SIZE = ((V2_OUTER_OVERHEAD + 256 + 255) / 256) * 256;

// Validates the v2 ciphertext prefix and minimum size; throws std::runtime_error on failure.
static void v2_check_header(std::span<const std::byte> ciphertext) {
    if (ciphertext.size() < V2_MIN_FINAL_SIZE)
        throw std::runtime_error{"v2 ciphertext is too short"};
    if (ciphertext[0] != std::byte{0x00} || ciphertext[1] != std::byte{0x02})
        throw std::runtime_error{"v2 ciphertext has wrong version prefix"};
}

// X-Wing KDF: computes ss = SHA3-256(ssm||ssx||E||X||V2_XWING_LABEL), then squeezes k (32B) into
// key_buf (overwriting ssm) and n (V2_NONCE_SIZE B) into nonce_out.  Callers are responsible for
// storing these outputs in cleared buffers.  E is the ephemeral X25519 pubkey; X is the PFS pubkey.
static void v2_derive_xwing_key_nonce(
        std::span<std::byte, 32> key_buf,
        std::span<std::byte, V2_NONCE_SIZE> nonce_out,
        std::span<const std::byte, 32> ssx,
        std::span<const std::byte, 32> E,
        std::span<const std::byte, 32> X) {
    cleared_b32 ss;
    hash::sha3_256(ss, key_buf, ssx, E, X, V2_XWING_LABEL);
    hash::shake256(V2_SS_DOMAIN, ss)(key_buf, nonce_out);
}

// Computes the 2-byte Key Indicator Shared Secret (KISS):
//   KISS = BLAKE2b_2(E || S, key=DH(sec, pub_for_dh), pers="Session-Msg-KISS")
// On encrypt: sender holds ephemeral secret e, DH partner is long-term S → call with
// encrypting=true On decrypt: recipient holds long-term secret s, DH partner is ephemeral E → call
// with encrypting=false
static std::array<std::byte, 2> v2_kiss(
        std::span<const std::byte, 32> sec,
        std::span<const std::byte, 32> E,
        std::span<const std::byte, 32> S,
        bool encrypting) {
    auto dh = x25519::scalarmult(sec, encrypting ? S : E);
    return hash::blake2b_key_pers<2>(dh, V2_KISS_PERS, E, S);
}

std::vector<std::byte> sign_for_recipient(
        const ed25519::PrivKeySpan& ed25519_privkey,
        std::span<const std::byte> recipient_pubkey,
        std::span<const std::byte> message) {
    // If prefixed, drop it (and do this for the caller, too) so that everything after this
    // doesn't need to worry about whether it is prefixed or not.
    if (recipient_pubkey.size() == 33 && recipient_pubkey.front() == std::byte{0x05})
        recipient_pubkey = recipient_pubkey.subspan(1);
    else if (recipient_pubkey.size() != 32)
        throw std::invalid_argument{
                "Invalid recipient_pubkey: expected 32 bytes (33 with 05 prefix)"};

    std::vector<std::byte> buf;
    buf.reserve(message.size() + 96);  // 32+32 now, but 32+64 when we reuse it for the sealed box
    buf.insert(buf.end(), message.begin(), message.end());
    buf.insert(
            buf.end(),
            ed25519_privkey.begin() + 32,
            ed25519_privkey.end());  // [32:] of a libsodium full seed value is the *pubkey*
    buf.insert(buf.end(), recipient_pubkey.begin(), recipient_pubkey.end());

    auto sig = ed25519::sign(ed25519_privkey, buf);

    // We have M||A||Y for the sig, but now we want M||A||SIG so drop Y then append SIG:
    buf.resize(buf.size() - 32);
    buf.insert(buf.end(), sig.begin(), sig.end());

    return buf;
}

static constexpr auto BOX_HASHKEY = "SessionBoxEphemeralHashKey"_bytes;

std::vector<std::byte> encrypt_for_recipient(
        const ed25519::PrivKeySpan& ed25519_privkey,
        std::span<const std::byte> recipient_pubkey,
        std::span<const std::byte> message) {

    auto signed_msg = sign_for_recipient(ed25519_privkey, recipient_pubkey, message);

    if (recipient_pubkey.size() == 33)
        recipient_pubkey =
                recipient_pubkey.subspan(1);  // sign_for_recipient already checked that this is the
                                              // proper 0x05 prefix when present.

    std::vector<std::byte> result;
    result.resize(signed_msg.size() + encryption::BOX_SEALBYTES);
    encryption::box_seal(result, signed_msg, recipient_pubkey.first<32>());

    return result;
}

std::vector<std::byte> encrypt_for_recipient_deterministic(
        const ed25519::PrivKeySpan& ed25519_privkey,
        std::span<const std::byte> recipient_pubkey,
        std::span<const std::byte> message) {

    auto signed_msg = sign_for_recipient(ed25519_privkey, recipient_pubkey, message);

    if (recipient_pubkey.size() == 33)
        recipient_pubkey = recipient_pubkey.subspan(1);  // sign_for_recipient already checked that
                                                         // this is the proper 0x05 when present.

    // To make our ephemeral seed we're going to hash: SENDER_SEED || RECIPIENT_PK || MESSAGE with a
    // keyed blake2b hash.
    cleared_b32 seed;
    hash::blake2b_key(
            seed, BOX_HASHKEY, ed25519_privkey.seed(), recipient_pubkey.first(32), message);

    auto [eph_pk, eph_sk] = x25519::seed_keypair(seed);

    // The nonce for a sealed box is not passed but is implicitly defined as the (unkeyed) blake2b
    // hash of:
    //     EPH_PUBKEY || RECIPIENT_PUBKEY
    std::array<std::byte, encryption::BOX_NONCEBYTES> nonce;
    hash::blake2b(nonce, eph_pk, recipient_pubkey);

    // A sealed box is a regular box (using the ephermal keys and nonce), but with the ephemeral
    // pubkey prepended:
    static_assert(
            encryption::BOX_SEALBYTES == encryption::BOX_PUBLICKEYBYTES + encryption::BOX_MACBYTES);

    std::vector<std::byte> result;
    result.resize(encryption::BOX_SEALBYTES + signed_msg.size());
    std::ranges::copy(eph_pk, result.begin());
    encryption::box_easy(
            std::span{result}.subspan(encryption::BOX_PUBLICKEYBYTES),
            signed_msg,
            nonce,
            recipient_pubkey.first<32>(),
            eph_sk);

    return result;
}

// Builds and returns a complete v2 DM wire-format ciphertext from already-derived header fields
// and encryption key material.  Used by both encrypt_for_recipient_v2 (PFS+PQ) and
// encrypt_for_recipient_v2_nopfs (non-PFS fallback).
static std::vector<std::byte> v2_encrypt_inner(
        std::array<std::byte, 2> ki,
        std::span<const std::byte, 32> E,
        std::span<const std::byte, mlkem768::CIPHERTEXTBYTES> outer_ct,
        std::span<const std::byte, 32> enc_key,
        std::span<const std::byte, V2_NONCE_SIZE> enc_nonce,
        const ed25519::PrivKeySpan& sender_ed25519_privkey,
        std::span<const std::byte, 33> recipient_session_id,
        std::span<const std::byte> content,
        const ed25519::OptionalPrivKeySpan& pro_ed25519_privkey) {

    auto sender_ed_pk = sender_ed25519_privkey.pubkey();

    // bt_bytes_encoded(n): total bytes to represent an n-byte bt string: decimal digits of n + 1 +
    // n
    constexpr auto bt_bytes_encoded = [](size_t n) constexpr -> size_t {
        size_t sz = 1 + n;  // ':' + n data bytes
        do {
            ++sz;
        } while (n /= 10);  // decimal digits of n
        return sz;
    };
    // Keys must be in ascending lexicographic order: "S" < "c" < "~" < "~P"
    constexpr size_t S_KEY_VAL = 3 + bt_bytes_encoded(32);    // "1:S" + "32:<sender ed pubkey>"
    constexpr size_t SIG_KEY_VAL = 3 + bt_bytes_encoded(64);  // "1:~" + "64:<signature>"
    constexpr size_t PRO_KEY_VAL = 4 + bt_bytes_encoded(64);  // "2:~P" + "64:<pro signature>"
    size_t inner_dict_size = 2                                // d...e dict delimiters
                           + S_KEY_VAL + 3 +
                             bt_bytes_encoded(content.size())  // "1:c" + "<content>"
                           + SIG_KEY_VAL + (pro_ed25519_privkey ? PRO_KEY_VAL : 0);

    // Total message must be a multiple of 256 bytes and at least V2_MIN_FINAL_SIZE bytes.
    size_t final_size =
            (std::max(V2_MIN_FINAL_SIZE, V2_OUTER_OVERHEAD + inner_dict_size) + 255) & ~size_t{255};
    size_t padded_inner_size = final_size - V2_OUTER_OVERHEAD;

    // Allocate result (zero-initialized so padding bytes are already 0), write header,
    // build inner dict directly into result buffer, then encrypt in-place.
    // (c == m is explicitly supported by libsodium for AEAD functions)
    std::vector<std::byte> result(final_size, std::byte{0});

    result[0] = std::byte{0x00};
    result[1] = std::byte{0x02};
    result[2] = ki[0];
    result[3] = ki[1];
    std::memcpy(result.data() + 4, E.data(), 32);
    std::memcpy(result.data() + 36, outer_ct.data(), mlkem768::CIPHERTEXTBYTES);

    {
        oxenc::bt_dict_producer dict{
                reinterpret_cast<char*>(result.data() + V2_HEADER_SIZE), inner_dict_size};
        dict.append("S", sender_ed_pk);
        dict.append("c", content);
        // "~" signs BLAKE2b-64(body-so-far, key=recipient_session_id_33B, pers="SessionV2Message")
        dict.append_signature("~", [&](std::span<const std::byte> body) {
            cleared_b64 h;
            hash::blake2b_key_pers(h, recipient_session_id, V2_MSG_SIG_PERS, body);
            return ed25519::sign(sender_ed25519_privkey, h);
        });
        if (pro_ed25519_privkey)
            dict.append_signature("~P", [&](std::span<const std::byte> body) {
                return ed25519::sign(*pro_ed25519_privkey, body);
            });
        assert(dict.view().size() == inner_dict_size);
    }

    // In-place AEAD encrypt (libsodium explicitly supports c == m)
    encryption::xchacha20poly1305_encrypt(
            std::span{result}.subspan(V2_HEADER_SIZE),
            std::span{result}.subspan(V2_HEADER_SIZE, padded_inner_size),
            enc_nonce,
            enc_key);

    return result;
}

std::vector<std::byte> encrypt_for_recipient_v2(
        const ed25519::PrivKeySpan& sender_ed25519_privkey,
        std::span<const std::byte, 33> recipient_session_id,
        std::span<const std::byte, 32> recipient_account_x25519,
        std::span<const std::byte, 1184> recipient_account_mlkem768,
        std::span<const std::byte> content,
        const ed25519::OptionalPrivKeySpan& pro_ed25519_privkey) {

    // S = long-term X25519 pubkey of the recipient (session ID without the 0x05 prefix)
    std::span<const std::byte, 32> S{recipient_session_id.data() + 1, 32};

    // Step 1: Generate ephemeral X25519 keypair e/E
    auto [E, e] = x25519::keypair();

    // Three cleared buffers for key material:
    // enc_key_buf: ML-KEM shared secret ssm (step 4) → SHAKE256-derived enc key k (step 6)
    // ssx_buf: eS DH result (step 2) → ML-KEM coins (step 4) → ssx DH result (step 5)
    // enc_nonce: SHAKE256-derived enc nonce n (step 6)
    cleared_b32 enc_key_buf;
    cleared_b32 ssx_buf;

    // Step 2: KISS = BLAKE2b_2(E || S, key=eS, pers="Session-Msg-KISS")
    // eS is the X25519 DH with the long-term key, used only for cheap key indicator obfuscation
    auto kiss = v2_kiss(e, E, S, /*encrypting=*/true);

    // Step 3: ki = M[0:2] ⊕ kiss  (encrypted key indicator; lets recipient quickly identify key)
    std::array<std::byte, 2> ki{
            recipient_account_mlkem768[0] ^ kiss[0], recipient_account_mlkem768[1] ^ kiss[1]};

    // Step 4: ML-KEM-768 encapsulate: ssₘ, mlkem_ct = Encapsulate(M)
    std::array<std::byte, mlkem768::CIPHERTEXTBYTES> mlkem_ct;
    random::fill(ssx_buf);  // repurpose ssx_buf as random ML-KEM coins
    mlkem768::encapsulate(mlkem_ct, enc_key_buf, recipient_account_mlkem768, ssx_buf);

    // Step 5: ssx = eX  (X25519 DH with account PFS key X, not long-term key S)
    x25519::scalarmult(ssx_buf, e, recipient_account_x25519);

    // Step 6: X-Wing KDF → enc key k (in enc_key_buf) and enc nonce n (in enc_nonce)
    std::array<std::byte, V2_NONCE_SIZE> enc_nonce;
    v2_derive_xwing_key_nonce(enc_key_buf, enc_nonce, ssx_buf, E, recipient_account_x25519);

    return v2_encrypt_inner(
            ki,
            E,
            mlkem_ct,
            enc_key_buf,
            enc_nonce,
            sender_ed25519_privkey,
            recipient_session_id,
            content,
            pro_ed25519_privkey);
}

std::array<std::byte, 2> decrypt_incoming_v2_prefix(
        std::span<const std::byte, 32> x25519_sec,
        std::span<const std::byte, 32> x25519_pub,
        std::span<const std::byte> ciphertext) {
    v2_check_header(ciphertext);
    auto E = ciphertext.subspan<4, 32>();
    auto kiss = v2_kiss(x25519_sec, E, x25519_pub, /*encrypting=*/false);
    return {ciphertext[2] ^ kiss[0], ciphertext[3] ^ kiss[1]};
}

// Decrypts the v2 AEAD payload and parses the inner bt-encoded dict.  Used by both
// decrypt_incoming_v2 (PFS+PQ) and decrypt_incoming_v2_nopfs (non-PFS fallback).
// Throws DecryptV2Error on AEAD failure; std::runtime_error on structural/format errors.
static DecryptV2Result v2_aead_decrypt_and_parse(
        std::span<const std::byte, 33> recipient_session_id,
        std::span<const std::byte, 32> key,
        std::span<const std::byte, V2_NONCE_SIZE> nonce,
        std::span<const std::byte> ciphertext) {

    size_t enc_size = ciphertext.size() - V2_HEADER_SIZE;
    std::vector<std::byte> plain(enc_size - V2_AEAD_OVERHEAD);
    if (!encryption::xchacha20poly1305_decrypt(
                plain, ciphertext.subspan(V2_HEADER_SIZE, enc_size), nonce, key))
        throw DecryptV2Error{"v2 message decryption failed"};

    // Strip zero padding from end (the plaintext was padded to a multiple of 256 bytes)
    while (!plain.empty() && plain.back() == std::byte{0})
        plain.pop_back();

    // Parse the bencoded inner dict
    oxenc::bt_dict_consumer dict{plain};

    auto sender_ed_pk = dict.require_span<std::byte, 32>("S");
    auto content_sv = dict.require_span<std::byte>("c");

    // Verify the Ed25519 signature over BLAKE2b(body, key=recipient_session_id, pers=…)
    dict.require_signature(
            "~", [&](std::span<const std::byte> body, std::span<const std::byte> sig) {
                if (sig.size() != 64)
                    throw std::runtime_error{"v2 message signature has wrong size"};
                b64 h;
                hash::blake2b_key_pers(h, recipient_session_id, V2_MSG_SIG_PERS, body);
                if (!ed25519::verify(sig.first<64>(), sender_ed_pk, h))
                    throw std::runtime_error{"v2 message signature verification failed"};
            });

    // Optional "~P" pro signature.  Extracted but not verified here — the Pro public key is
    // inside the protobuf Content, so verification is deferred to the message parsing layer.
    std::optional<b64> pro_sig;
    if (dict.skip_until("~P"))
        dict.consume_signature([&](std::span<const std::byte>, std::span<const std::byte> sig) {
            if (sig.size() != 64)
                throw std::runtime_error{"v2 ~P pro signature has wrong size"};
            std::memcpy(pro_sig.emplace().data(), sig.data(), 64);
        });

    dict.finish();

    // Convert sender Ed25519 pubkey to X25519 and build the 33-byte session ID
    b32 sender_x25519 = ed25519::pk_to_x25519(sender_ed_pk);

    DecryptV2Result result;
    result.content.assign(content_sv.begin(), content_sv.end());
    result.sender_session_id[0] = std::byte{0x05};
    std::ranges::copy(sender_x25519, result.sender_session_id.begin() + 1);
    if (pro_sig)
        std::memcpy(result.pro_signature.emplace().data(), pro_sig->data(), 64);
    return result;
}

DecryptV2Result decrypt_incoming_v2(
        std::span<const std::byte, 33> recipient_session_id,
        std::span<const std::byte, 32> account_pfs_x25519_sec,
        std::span<const std::byte, 32> account_pfs_x25519_pub,
        std::span<const std::byte, 2400> account_pfs_mlkem768_sec,
        std::span<const std::byte> ciphertext) {
    v2_check_header(ciphertext);

    auto E = ciphertext.subspan<4, 32>();
    auto mlkem_ct = ciphertext.subspan<36, mlkem768::CIPHERTEXTBYTES>();

    cleared_b32 key_buf;  // ssm → k
    cleared_b32 ssx_buf;
    std::array<std::byte, V2_NONCE_SIZE> nonce;

    // Step 1: ML-KEM-768 decapsulate → shared secret ssm in key_buf
    if (!mlkem768::decapsulate(key_buf, mlkem_ct, account_pfs_mlkem768_sec))
        throw DecryptV2Error{"ML-KEM-768 decapsulation failed"};

    // Step 2: X25519 DH with account PFS key → shared secret ssx in ssx_buf
    x25519::scalarmult(ssx_buf, account_pfs_x25519_sec, E);

    // Step 3: X-Wing KDF → enc key k (in key_buf) and enc nonce n (in nonce)
    v2_derive_xwing_key_nonce(key_buf, nonce, ssx_buf, E, account_pfs_x25519_pub);

    return v2_aead_decrypt_and_parse(recipient_session_id, key_buf, nonce, ciphertext);
}

// Non-PFS fallback key derivation domain labels (private to this translation unit).
// The outer wire format is identical to a PFS+PQ v2 message; only the key derivation differs.
constexpr auto V2_NONPFS_KDF_LABEL = "SessionV2NonPFS"_bytes;
constexpr auto V2_NONPFS_SS_DOMAIN = "SessionV2NonPFSSS"_bytes;

std::vector<std::byte> encrypt_for_recipient_v2_nopfs(
        const ed25519::PrivKeySpan& sender_ed25519_privkey,
        std::span<const std::byte, 33> recipient_session_id,
        std::span<const std::byte> content,
        const ed25519::OptionalPrivKeySpan& pro_ed25519_privkey) {

    // R = long-term X25519 pubkey of the recipient (session ID without the 0x05 prefix)
    auto R = recipient_session_id.last<32>();

    // Generate ephemeral X25519 keypair e/E
    auto [E, e] = x25519::keypair();

    // ki and the outer "mlkem_ct" slot are random: the message is externally indistinguishable
    // from a PFS+PQ v2 message, but carries no actual ML-KEM ciphertext.
    std::array<std::byte, 2> ki;
    std::array<std::byte, mlkem768::CIPHERTEXTBYTES> outer_ct;
    random::fill(ki);
    random::fill(outer_ct);

    // ss = eR, then overwritten in-place with SHA3-256(ss || R || E || V2_NONPFS_KDF_LABEL).
    cleared_b32 ss;
    x25519::scalarmult(ss, e, R);
    hash::sha3_256(ss, ss, R, E, V2_NONPFS_KDF_LABEL);

    // k, n = SHAKE256(V2_NONPFS_SS_DOMAIN, ss) → 32-byte key + 24-byte nonce
    cleared_b32 enc_key;
    std::array<std::byte, V2_NONCE_SIZE> enc_nonce;
    hash::shake256(V2_NONPFS_SS_DOMAIN, ss)(enc_key, enc_nonce);

    return v2_encrypt_inner(
            ki,
            E,
            outer_ct,
            enc_key,
            enc_nonce,
            sender_ed25519_privkey,
            recipient_session_id,
            content,
            pro_ed25519_privkey);
}

DecryptV2Result decrypt_incoming_v2_nopfs(
        std::span<const std::byte, 33> recipient_session_id,
        std::span<const std::byte, 32> x25519_sec,
        std::span<const std::byte, 32> x25519_pub,
        std::span<const std::byte> ciphertext) {
    v2_check_header(ciphertext);

    // E = ephemeral X25519 pubkey from bytes 4-35; bytes 36-1123 (fake mlkem_ct) are ignored.
    auto E = ciphertext.subspan<4, 32>();

    // ss = rE, then overwritten in-place with SHA3-256(ss || R || E || V2_NONPFS_KDF_LABEL).
    cleared_b32 ss;
    x25519::scalarmult(ss, x25519_sec, E);
    hash::sha3_256(ss, ss, x25519_pub, E, V2_NONPFS_KDF_LABEL);

    // k, n = SHAKE256(V2_NONPFS_SS_DOMAIN, ss) → 32-byte key + 24-byte nonce
    cleared_b32 key;
    std::array<std::byte, V2_NONCE_SIZE> nonce;
    hash::shake256(V2_NONPFS_SS_DOMAIN, ss)(key, nonce);

    return v2_aead_decrypt_and_parse(recipient_session_id, key, nonce, ciphertext);
}

// Calculate the shared encryption key, sending from blinded sender kS (k = S's blinding factor) to
// blinded receiver jR (j = R's blinding factor).
//
// The sender knows s, k, S, and jR, but not j/R individually.
// The receiver knows r, j, R, and kS, but not k/S individually.
//
// From the sender's perspective, then, we compute:
//
// BLAKE2b(s k[jR] || kS || [jR])
//
// The receiver can calulate the same value via:
//
// BLAKE2b(r j[kS] || [kS] || jR)
//
// (which will be the same because sR = rS, and so skjR = kjsR = kjrS = rjkS).
//
// For 15 blinding, however, the blinding factor depended only on the SOGS server pubkey, and so `j
// = k`, and so for *15* keys we don't do the double-blinding (i.e. the first terms above drop the
// double-blinding factors and become just sjR and rkS).
//
// Arguments.  "A" and "B" here are either sender and receiver, or receiver and sender, depending on
// the value of `sending`.
//
// seed -- A's 32-byte secret key (can also be 64 bytes; only the first 32 are used).
// kA -- A's 33-byte blinded id, beginning with 0x15 or 0x25
// jB -- A's 33-byte blinded id, beginning with 0x15 or 0x25 (must be the same prefix as kA).
// server_pk -- the server's pubkey (needed to compute A's `k` value)
// sending -- true if this for a message from A to B, false if this is from B to A.
static cleared_b32 blinded_shared_secret(
        const ed25519::PrivKeySpan& ed25519_privkey,
        std::span<const std::byte, 33> kA_prefixed,
        std::span<const std::byte, 33> jB_prefixed,
        std::span<const std::byte, 32> server_pk,
        bool sending) {

    // Because we're doing this generically, we use notation a/A/k for ourselves and b/jB for the
    // other person; this notion keeps everything exactly as above *except* for the concatenation in
    // the BLAKE2b hashed value: there we have to use kA || jB if we are the sender, but reverse the
    // order to jB || kA if we are the receiver.

    std::pair<b32, cleared_b32> blinded_key_pair;
    cleared_b32 k;

    if (kA_prefixed[0] == std::byte{0x15} && jB_prefixed[0] == std::byte{0x15})
        blinded_key_pair = blind15_key_pair(ed25519_privkey, server_pk, &k);
    else if (kA_prefixed[0] == std::byte{0x25} && jB_prefixed[0] == std::byte{0x25})
        blinded_key_pair = blind25_key_pair(ed25519_privkey, server_pk, &k);
    else
        throw std::invalid_argument{"Both ids must start with the same 0x15 or 0x25 prefix"};

    bool blind25 = kA_prefixed[0] == std::byte{0x25};

    auto kA = kA_prefixed.subspan<1>();
    auto jB = jB_prefixed.subspan<1>();

    cleared_b32 ka = ed25519::sk_to_private(ed25519_privkey);

    if (blind25)
        // Multiply a by k, so that we end up computing kajB = kjaB, which the other side can
        // compute as jkbA.
        ed25519::scalar_mul(ka, ka, k);
    // Else for 15 blinding we leave "ka" as just a, because j=k and so we don't need the
    // double-blind.

    cleared_b32 shared_secret;
    ed25519::scalarmult_noclamp(shared_secret, ka, jB);

    auto& sender = sending ? kA : jB;
    auto& recipient = sending ? jB : kA;

    // H(kjsR || kS || jR):
    hash::blake2b(shared_secret, shared_secret, sender, recipient);

    return shared_secret;
}

std::vector<std::byte> encrypt_for_blinded_recipient(
        const ed25519::PrivKeySpan& ed25519_privkey,
        std::span<const std::byte, 32> server_pk,
        std::span<const std::byte, 33> recipient_blinded_id,
        std::span<const std::byte> message) {

    // Generate the blinded key pair & shared encryption key
    std::pair<b32, cleared_b32> blinded_key_pair;
    if (recipient_blinded_id[0] == std::byte{0x15})
        blinded_key_pair = blind15_key_pair(ed25519_privkey, server_pk);
    else if (recipient_blinded_id[0] == std::byte{0x25})
        blinded_key_pair = blind25_key_pair(ed25519_privkey, server_pk);
    else
        throw std::invalid_argument{"Invalid recipient_blinded_id: must start with 0x15 or 0x25"};

    std::array<std::byte, 33> blinded_id;
    blinded_id[0] = recipient_blinded_id[0];
    std::ranges::copy(blinded_key_pair.first, blinded_id.begin() + 1);

    auto enc_key = blinded_shared_secret(
            ed25519_privkey, blinded_id, recipient_blinded_id, server_pk, true);

    // Inner data: msg || A (i.e. the sender's ed25519 master pubkey, *not* kA blinded pubkey)
    std::vector<std::byte> buf;
    buf.reserve(message.size() + 32);
    buf.insert(buf.end(), message.begin(), message.end());

    // append A (pubkey)
    auto pk = ed25519_privkey.pubkey();
    buf.insert(buf.end(), pk.begin(), pk.end());

    // Layout: version(1) || ciphertext(buf+ABYTES) || nonce(NPUBBYTES)
    std::vector<std::byte> ciphertext;
    ciphertext.resize(
            1 + buf.size() + encryption::XCHACHA20_ABYTES + encryption::XCHACHA20_NONCEBYTES);

    // Prepend with a version byte, so that the recipient can reliably detect if a future version is
    // no longer encrypting things the way it expects.
    ciphertext[0] = std::byte{BLINDED_ENCRYPT_VERSION};

    auto nonce = std::span{ciphertext}.last<encryption::XCHACHA20_NONCEBYTES>();
    random::fill(nonce);

    encryption::xchacha20poly1305_encrypt(
            std::span{ciphertext}.subspan(1, buf.size() + encryption::XCHACHA20_ABYTES),
            buf,
            nonce,
            enc_key);

    return ciphertext;
}

static constexpr size_t GROUPS_ENCRYPT_OVERHEAD =
        encryption::XCHACHA20_NONCEBYTES + encryption::XCHACHA20_ABYTES;

std::vector<std::byte> encrypt_for_group(
        const ed25519::PrivKeySpan& user_ed25519_privkey,
        std::span<const std::byte, 32> group_ed25519_pubkey,
        std::span<const std::byte> group_enc_key,
        std::span<const std::byte> plaintext,
        bool compress,
        size_t padding) {
    if (plaintext.size() > GROUPS_MAX_PLAINTEXT_MESSAGE_SIZE)
        throw std::runtime_error{"Cannot encrypt plaintext: message size is too large"};

    if (group_enc_key.size() != 32 && group_enc_key.size() != 64)
        throw std::invalid_argument{"Invalid group_enc_key: expected 32 or 64 bytes"};

    std::vector<std::byte> _compressed;
    if (compress) {
        _compressed = zstd_compress(plaintext);
        if (_compressed.size() < plaintext.size())
            plaintext = _compressed;
        else {
            _compressed.clear();
            compress = false;
        }
    }
    // `plaintext` is now pointing at either the original input data, or at `_compressed` local
    // variable containing the compressed form of that data.

    oxenc::bt_dict_producer dict{};

    // encoded data version (bump this if something changes in an incompatible way)
    dict.append("", 1);

    // Sender ed pubkey, by which the message can be validated.  Note that there are *two*
    // components to this validation: first the regular signature validation of the "s" signature we
    // add below, but then also validation that this Ed25519 converts to the Session ID of the
    // claimed sender of the message inside the encoded message data.
    auto sender_pk = user_ed25519_privkey.pubkey();
    dict.append("a", to_string_view(sender_pk));

    if (!compress)
        dict.append("d", to_string_view(plaintext));

    // We sign `plaintext || group_ed25519_pubkey` rather than just `plaintext` so that if this
    // encrypted data will not validate if cross-posted to any other group.  We don't actually
    // include the pubkey alongside, because that is implicitly known by the group members that
    // receive it.
    std::vector<std::byte> to_sign(plaintext.size() + group_ed25519_pubkey.size());
    std::memcpy(to_sign.data(), plaintext.data(), plaintext.size());
    std::memcpy(
            to_sign.data() + plaintext.size(),
            group_ed25519_pubkey.data(),
            group_ed25519_pubkey.size());

    auto signature = ed25519::sign(user_ed25519_privkey, to_sign);
    dict.append("s", to_string_view(signature));

    if (compress)
        dict.append("z", to_string_view(plaintext));

    auto encoded = std::move(dict).str();

    // suppose size == 250, padding = 256
    // so size + overhead(40) == 290
    // need padding of (256 - (290 % 256)) = 256 - 34 = 222
    // thus 290 + 222 = 512
    size_t final_len = GROUPS_ENCRYPT_OVERHEAD + encoded.size();
    if (padding > 1 && final_len % padding != 0) {
        size_t to_append = padding - (final_len % padding);
        encoded.resize(encoded.size() + to_append);
    }

    std::vector<std::byte> ciphertext;
    ciphertext.resize(GROUPS_ENCRYPT_OVERHEAD + encoded.size());
    auto nonce = std::span{ciphertext}.first<encryption::XCHACHA20_NONCEBYTES>();
    random::fill(nonce);

    encryption::xchacha20poly1305_encrypt(
            std::span{ciphertext}.subspan(encryption::XCHACHA20_NONCEBYTES),
            to_span(encoded),
            nonce,
            group_enc_key.first<encryption::XCHACHA20_KEYBYTES>());

    return ciphertext;
}

std::pair<std::vector<std::byte>, std::string> decrypt_incoming_session_id(
        const ed25519::PrivKeySpan& ed25519_privkey, std::span<const std::byte> ciphertext) {
    auto [buf, sender_ed_pk] = decrypt_incoming(ed25519_privkey, ciphertext);

    // Convert the sender_ed_pk to the sender's session ID
    auto sender_x_pk = ed25519::pk_to_x25519(sender_ed_pk);

    // Everything is good, so just drop A and Y off the message and prepend the '05' prefix to
    // the sender session ID
    auto sender_session_id = "05{:x}"_format(sender_x_pk);

    return {buf, sender_session_id};
}

std::pair<std::vector<std::byte>, std::string> decrypt_incoming_session_id(
        std::span<const std::byte, 32> x25519_pubkey,
        std::span<const std::byte, 32> x25519_seckey,
        std::span<const std::byte> ciphertext) {
    auto [buf, sender_ed_pk] = decrypt_incoming(x25519_pubkey, x25519_seckey, ciphertext);

    // Convert the sender_ed_pk to the sender's session ID
    auto sender_x_pk = ed25519::pk_to_x25519(sender_ed_pk);

    // Everything is good, so just drop A and Y off the message and prepend the '05' prefix to
    // the sender session ID
    auto sender_session_id = "05{:x}"_format(sender_x_pk);

    return {buf, sender_session_id};
}

std::pair<std::vector<std::byte>, b32> decrypt_incoming(
        const ed25519::PrivKeySpan& ed25519_privkey, std::span<const std::byte> ciphertext) {
    auto x_sec = ed25519::sk_to_x25519(ed25519_privkey);
    auto x_pub = x25519::scalarmult_base(x_sec);
    return decrypt_incoming(x_pub, x_sec, ciphertext);
}

std::pair<std::vector<std::byte>, b32> decrypt_incoming(
        std::span<const std::byte, 32> x25519_pubkey,
        std::span<const std::byte, 32> x25519_seckey,
        std::span<const std::byte> ciphertext) {

    if (ciphertext.size() < encryption::BOX_SEALBYTES + 32 + 64)
        throw std::runtime_error{"Invalid incoming message: ciphertext is too small"};
    const size_t outer_size = ciphertext.size() - encryption::BOX_SEALBYTES;
    const size_t msg_size = outer_size - 32 - 64;

    std::pair<std::vector<std::byte>, b32> result;
    auto& [buf, sender_ed_pk] = result;

    buf.resize(outer_size);
    if (!encryption::box_seal_open(buf, ciphertext, x25519_pubkey, x25519_seckey))
        throw std::runtime_error{"Decryption failed"};

    auto tail = std::span{buf}.subspan(msg_size);  // A(32) || SIG(64)
    std::ranges::copy(tail.first<32>(), sender_ed_pk.begin());
    b64 sig;
    std::ranges::copy(tail.last<64>(), sig.begin());
    buf.resize(buf.size() - 64);  // Remove SIG, then append Y so that we get M||A||Y to verify
    buf.insert(buf.end(), x25519_pubkey.begin(), x25519_pubkey.end());

    if (!ed25519::verify(sig, sender_ed_pk, buf))
        throw std::runtime_error{"Signature verification failed"};

    // Everything is good, so just drop A and Y off the message
    buf.resize(buf.size() - 32 - 32);

    return result;
}

std::pair<std::vector<std::byte>, std::string> decrypt_from_blinded_recipient(
        const ed25519::PrivKeySpan& ed25519_privkey,
        std::span<const std::byte, 32> server_pk,
        std::span<const std::byte, 33> sender_id,
        std::span<const std::byte, 33> recipient_id,
        std::span<const std::byte> ciphertext) {
    auto ed_pk = ed25519_privkey.pubkey();
    if (ciphertext.size() < encryption::XCHACHA20_NONCEBYTES + 1 + encryption::XCHACHA20_ABYTES)
        throw std::invalid_argument{
                "Invalid ciphertext: too short to contain valid encrypted data"};

    cleared_b32 dec_key;
    auto blinded_id = recipient_id[0] == std::byte{0x25} ? blinded25_id_from_ed(ed_pk, server_pk)
                                                         : blinded15_id_from_ed(ed_pk, server_pk);

    if (to_string_view(sender_id) == to_string_view(blinded_id))
        dec_key = blinded_shared_secret(ed25519_privkey, sender_id, recipient_id, server_pk, true);
    else
        dec_key = blinded_shared_secret(ed25519_privkey, recipient_id, sender_id, server_pk, false);

    std::pair<std::vector<std::byte>, std::string> result;
    auto& [buf, sender_session_id] = result;

    // v, ct, nc = data[0], data[1:-24], data[-24:]
    if (ciphertext[0] != std::byte{BLINDED_ENCRYPT_VERSION})
        throw std::invalid_argument{
                fmt::format("Invalid ciphertext: version is not {}", BLINDED_ENCRYPT_VERSION)};

    const size_t msg_size =
            (ciphertext.size() - encryption::XCHACHA20_ABYTES - 1 -
             encryption::XCHACHA20_NONCEBYTES);

    if (msg_size < 32)
        throw std::invalid_argument{"Invalid ciphertext: innerBytes too short"};
    buf.resize(msg_size);

    auto nonce = ciphertext.last<encryption::XCHACHA20_NONCEBYTES>();
    if (!encryption::xchacha20poly1305_decrypt(
                buf,
                ciphertext.subspan(1, msg_size + encryption::XCHACHA20_ABYTES),
                nonce,
                dec_key))
        throw std::invalid_argument{"Decryption failed"};

    // Split up: the last 32 bytes are the sender's *unblinded* ed25519 key
    b32 sender_ed_pk;
    std::ranges::copy(std::span{buf}.last<32>(), sender_ed_pk.begin());

    // Convert the sender_ed_pk to the sender's session ID
    auto sender_x_pk = ed25519::pk_to_x25519(sender_ed_pk);

    // Verify that the inner sender_ed_pk (A) yields the same outer kA we got with the message
    auto extracted_sender = recipient_id[0] == std::byte{0x25}
                                  ? blinded25_id_from_ed(sender_ed_pk, server_pk)
                                  : blinded15_id_from_ed(sender_ed_pk, server_pk);

    bool matched = to_string_view(sender_id) == to_string_view(extracted_sender);
    if (!matched && extracted_sender[0] == std::byte{0x15}) {
        // With 15-blinding we might need the negative instead:
        extracted_sender[31] ^= std::byte{0x80};
        matched = to_string_view(sender_id) == to_string_view(extracted_sender);
    }
    if (!matched)
        throw std::runtime_error{"Blinded sender id does not match the actual sender"};

    // Everything is good, so just drop the sender_ed_pk off the message and prepend the '05' prefix
    // to the sender session ID
    buf.resize(buf.size() - 32);
    sender_session_id = "05{:x}"_format(sender_x_pk);

    return result;
}

DecryptGroupMessage decrypt_group_message(
        std::span<std::span<const std::byte, 32>> group_enc_keys,
        std::span<const std::byte, 32> group_ed25519_pubkey,
        std::span<const std::byte> ciphertext) {
    DecryptGroupMessage result = {};
    auto& [res_index, session_id, data] = result;
    if (ciphertext.size() < GROUPS_ENCRYPT_OVERHEAD)
        throw std::runtime_error{"ciphertext is too small to be encrypted data"};

    // Each group encryption key is a 32-byte symmetric XChaCha20-Poly1305 key.  Multiple keys
    // are tried because the group key rotates and recently-received messages may still be
    // encrypted with a pre-rotation key.

    std::vector<std::byte> plain;

    auto nonce = ciphertext.first<encryption::XCHACHA20_NONCEBYTES>();
    ciphertext = ciphertext.subspan(encryption::XCHACHA20_NONCEBYTES);
    plain.resize(ciphertext.size() - encryption::XCHACHA20_ABYTES);

    bool decrypt_success = false;
    for (size_t index = 0; index < group_enc_keys.size(); index++) {
        decrypt_success = encryption::xchacha20poly1305_decrypt(
                plain, ciphertext, nonce, group_enc_keys[index]);
        if (decrypt_success) {
            res_index = index;
            break;
        }
    }

    if (!decrypt_success)  // none of the keys worked
        throw std::runtime_error{"unable to decrypt ciphertext with any current group keys"};

    //
    // Removing any null padding bytes from the end
    //
    trim_trailing(plain);

    //
    // Now what we have less should be a bt_dict
    //
    if (plain.empty() || plain.front() != std::byte{'d'} || plain.back() != std::byte{'e'})
        throw std::runtime_error{"decrypted data is not a bencoded dict"};

    oxenc::bt_dict_consumer dict{to_string_view(plain)};

    if (auto v = dict.require<int>(""); v != 1)
        throw std::runtime_error{
                fmt::format("group message version tag ({}) is not compatible (we support v1)", v)};

    auto ed_pk = dict.require_span<std::byte, 32>("a");
    auto x_pk = ed25519::pk_to_x25519(ed_pk);

    session_id = "05{:x}"_format(x_pk);

    auto plain_data = dict.maybe<std::span<const std::byte>>("d");
    if (plain_data && plain_data->empty())
        throw std::runtime_error{"uncompressed message data (d) cannot be empty"};

    auto ed_sig = dict.require_span<std::byte, 64>("s");

    bool compressed = false;
    auto comp_data = dict.maybe<std::span<const std::byte>>("z");
    if (comp_data) {
        if (comp_data->empty())
            throw std::runtime_error{"compressed message data (z) cannot be empty"};
        if (plain_data)
            throw std::runtime_error{
                    "message signature cannot contain both compressed (z) and uncompressed (d) "
                    "data"};

        compressed = true;
    } else if (!plain_data)
        throw std::runtime_error{"message must contain compressed (z) or uncompressed (d) data"};

    auto raw_data = comp_data ? *comp_data : *plain_data;

    // The value we verify is the raw data *followed by* the group Ed25519 pubkey.  (See the comment
    // in encrypt_message).
    std::vector<std::byte> to_verify;
    to_verify.reserve(raw_data.size() + group_ed25519_pubkey.size());

    to_verify.insert(to_verify.end(), raw_data.begin(), raw_data.end());
    to_verify.insert(to_verify.end(), group_ed25519_pubkey.begin(), group_ed25519_pubkey.end());

    if (!ed25519::verify(ed_sig.first<64>(), ed_pk.first<32>(), to_verify))
        throw std::runtime_error{"message signature failed validation"};

    if (compressed) {
        if (auto decomp = zstd_decompress(raw_data, GROUPS_MAX_PLAINTEXT_MESSAGE_SIZE)) {
            data = std::move(*decomp);
        } else
            throw std::runtime_error{"message decompression failed"};
    } else
        data.assign(raw_data.begin(), raw_data.end());

    return result;
}

// The old Argon2-based ONS encryption always used an all-zero salt and all-zero secretbox nonce.
static constexpr std::array<std::byte, hash::ARGON2_SALTBYTES> ONS_ARGON2_SALT = {};
static constexpr std::array<std::byte, encryption::SECRETBOX_NONCEBYTES> ONS_SECRETBOX_NONCE = {};

std::string decrypt_ons_response(
        std::string_view lowercase_name,
        std::span<const std::byte> ciphertext,
        std::optional<std::span<const std::byte, 24>> nonce) {
    // Handle old Argon2-based encryption used before HF16
    if (!nonce) {
        if (ciphertext.size() < encryption::SECRETBOX_MACBYTES)
            throw std::invalid_argument{"Invalid ciphertext: expected to be greater than 16 bytes"};

        b32 key;
        hash::argon2(
                key,
                {lowercase_name.data(), lowercase_name.size()},
                ONS_ARGON2_SALT,
                hash::ARGON2_OPSLIMIT_MODERATE,
                hash::ARGON2_MEMLIMIT_MODERATE,
                hash::ARGON2ID13);

        std::vector<std::byte> msg;
        msg.resize(ciphertext.size() - encryption::SECRETBOX_MACBYTES);

        if (!encryption::secretbox_open_easy(msg, ciphertext, ONS_SECRETBOX_NONCE, key))
            throw std::runtime_error{"Failed to decrypt"};

        return oxenc::to_hex(msg);
    }

    static_assert(encryption::XCHACHA20_NONCEBYTES == 24);
    if (ciphertext.size() != 33 + encryption::XCHACHA20_ABYTES)
        throw std::invalid_argument{"Invalid ciphertext: expected exactly 49 bytes"};

    // Hash the ONS name using BLAKE2b
    //
    // xchacha-based encryption
    // key = H(name, key=H(name))
    b32 name_hash;
    hash::blake2b(name_hash, lowercase_name);
    auto key = hash::blake2b_key<32>(name_hash, lowercase_name);

    std::array<std::byte, 33> buf;
    if (!encryption::xchacha20poly1305_decrypt(buf, ciphertext, *nonce, key))
        throw std::runtime_error{"Failed to decrypt"};

    return oxenc::to_hex(buf);
}

std::vector<std::byte> decrypt_push_notification(
        std::span<const std::byte> payload, std::span<const std::byte, 32> enc_key) {
    if (payload.size() < encryption::XCHACHA20_NONCEBYTES + encryption::XCHACHA20_ABYTES)
        throw std::invalid_argument{"Invalid payload: too short to contain valid encrypted data"};

    auto nonce = payload.first<encryption::XCHACHA20_NONCEBYTES>();
    auto ct = payload.subspan(encryption::XCHACHA20_NONCEBYTES);

    std::vector<std::byte> buf(ct.size() - encryption::XCHACHA20_ABYTES);

    if (!encryption::xchacha20poly1305_decrypt(buf, ct, nonce, enc_key))
        throw std::runtime_error{"Failed to decrypt; perhaps the secret key is invalid?"};

    // Removing any null padding bytes from the end
    trim_trailing(buf);

    return buf;
}

std::vector<std::byte> encrypt_xchacha20(
        std::span<const std::byte> plaintext, std::span<const std::byte, 32> key) {

    std::vector<std::byte> ciphertext(
            encryption::XCHACHA20_NONCEBYTES + plaintext.size() + encryption::XCHACHA20_ABYTES);

    auto nonce = std::span{ciphertext}.first<encryption::XCHACHA20_NONCEBYTES>();
    random::fill(nonce);

    encryption::xchacha20poly1305_encrypt(
            std::span{ciphertext}.subspan(encryption::XCHACHA20_NONCEBYTES), plaintext, nonce, key);
    return ciphertext;
}

std::vector<std::byte> decrypt_xchacha20(
        std::span<const std::byte> ciphertext, std::span<const std::byte, 32> key) {
    if (ciphertext.size() < encryption::XCHACHA20_NONCEBYTES + encryption::XCHACHA20_ABYTES)
        throw std::invalid_argument{
                "Invalid ciphertext: too short to contain valid encrypted data"};

    // Extract nonce from the beginning of the ciphertext:
    auto nonce = ciphertext.first<encryption::XCHACHA20_NONCEBYTES>();
    ciphertext = ciphertext.subspan(nonce.size());

    std::vector<std::byte> plaintext(ciphertext.size() - encryption::XCHACHA20_ABYTES);
    if (!encryption::xchacha20poly1305_decrypt(plaintext, ciphertext, nonce, key))
        throw std::runtime_error{"Could not decrypt (XChaCha20-Poly1305)"};
    return plaintext;
}

}  // namespace session

extern "C" {

using namespace session;

LIBSESSION_C_API bool session_encrypt_for_recipient_deterministic(
        const unsigned char* plaintext_in,
        size_t plaintext_len,
        const unsigned char* ed25519_privkey,
        const unsigned char* recipient_pubkey,
        unsigned char** ciphertext_out,
        size_t* ciphertext_len) {
    try {
        auto ciphertext = session::encrypt_for_recipient_deterministic(
                to_byte_span<64>(ed25519_privkey),
                to_byte_span<32>(recipient_pubkey),
                to_byte_span(plaintext_in, plaintext_len));

        *ciphertext_out = static_cast<unsigned char*>(malloc(ciphertext.size()));
        *ciphertext_len = ciphertext.size();
        std::memcpy(*ciphertext_out, ciphertext.data(), ciphertext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_encrypt_for_blinded_recipient(
        const unsigned char* plaintext_in,
        size_t plaintext_len,
        const unsigned char* ed25519_privkey,
        const unsigned char* community_pubkey,
        const unsigned char* recipient_blinded_id,
        unsigned char** ciphertext_out,
        size_t* ciphertext_len) {
    try {
        auto ciphertext = session::encrypt_for_blinded_recipient(
                to_byte_span<64>(ed25519_privkey),
                to_byte_span<32>(community_pubkey),
                to_byte_span<33>(recipient_blinded_id),
                to_byte_span(plaintext_in, plaintext_len));

        *ciphertext_out = static_cast<unsigned char*>(malloc(ciphertext.size()));
        *ciphertext_len = ciphertext.size();
        std::memcpy(*ciphertext_out, ciphertext.data(), ciphertext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API session_encrypt_group_message session_encrypt_for_group(
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
        size_t error_len) {
    session_encrypt_group_message result = {};
    try {
        std::vector<std::byte> result_cpp = encrypt_for_group(
                {user_ed25519_privkey, user_ed25519_privkey_len},
                to_byte_span<32>(group_ed25519_pubkey),
                to_byte_span(group_enc_key, group_enc_key_len),
                to_byte_span(plaintext, plaintext_len),
                compress,
                padding);
        result = {
                .success = true,
                .ciphertext = session::span_u8_copy_or_throw(result_cpp.data(), result_cpp.size()),
        };
    } catch (const std::exception& e) {
        result.error_len_incl_null_terminator = copy_c_str(error, error_len, e.what());
    }
    return result;
}

LIBSESSION_C_API bool session_decrypt_incoming(
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* ed25519_privkey,
        char* session_id_out,
        unsigned char** plaintext_out,
        size_t* plaintext_len) {
    try {
        auto result = session::decrypt_incoming_session_id(
                to_byte_span<64>(ed25519_privkey), to_byte_span(ciphertext_in, ciphertext_len));
        auto [plaintext, session_id] = result;

        std::memcpy(session_id_out, session_id.c_str(), session_id.size() + 1);
        *plaintext_out = static_cast<unsigned char*>(malloc(plaintext.size()));
        *plaintext_len = plaintext.size();
        std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_decrypt_incoming_legacy_group(
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* x25519_pubkey,
        const unsigned char* x25519_seckey,
        char* session_id_out,
        unsigned char** plaintext_out,
        size_t* plaintext_len) {
    try {
        auto result = session::decrypt_incoming_session_id(
                to_byte_span<32>(x25519_pubkey),
                to_byte_span<32>(x25519_seckey),
                to_byte_span(ciphertext_in, ciphertext_len));
        auto [plaintext, session_id] = result;

        std::memcpy(session_id_out, session_id.c_str(), session_id.size() + 1);
        *plaintext_out = static_cast<unsigned char*>(malloc(plaintext.size()));
        *plaintext_len = plaintext.size();
        std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_decrypt_for_blinded_recipient(
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* ed25519_privkey,
        const unsigned char* community_pubkey,
        const unsigned char* sender_id,
        const unsigned char* recipient_id,
        char* session_id_out,
        unsigned char** plaintext_out,
        size_t* plaintext_len) {
    try {
        auto result = session::decrypt_from_blinded_recipient(
                to_byte_span<64>(ed25519_privkey),
                to_byte_span<32>(community_pubkey),
                to_byte_span<33>(sender_id),
                to_byte_span<33>(recipient_id),
                to_byte_span(ciphertext_in, ciphertext_len));
        auto [plaintext, session_id] = result;

        std::memcpy(session_id_out, session_id.c_str(), session_id.size() + 1);
        *plaintext_out = static_cast<unsigned char*>(malloc(plaintext.size()));
        *plaintext_len = plaintext.size();
        std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API session_decrypt_group_message_result session_decrypt_group_message(
        const span_u8* decrypt_ed25519_privkey_list,
        size_t decrypt_ed25519_privkey_len,
        const unsigned char* group_ed25519_pubkey,
        const unsigned char* ciphertext,
        size_t ciphertext_len,
        char* error,
        size_t error_len) {
    session_decrypt_group_message_result result = {};
    try {
        std::vector<std::span<const std::byte, 32>> keys;
        keys.reserve(decrypt_ed25519_privkey_len);
        for (size_t i = 0; i < decrypt_ed25519_privkey_len; i++) {
            if (decrypt_ed25519_privkey_list[i].size != 32)
                throw std::invalid_argument{fmt::format(
                        "Invalid group encryption key: expected 32 bytes, got {}",
                        decrypt_ed25519_privkey_list[i].size)};
            keys.push_back(to_byte_span<32>(decrypt_ed25519_privkey_list[i].data));
        }
        auto [index, session_id, plaintext] = decrypt_group_message(
                keys,
                to_byte_span<32>(group_ed25519_pubkey),
                to_byte_span(ciphertext, ciphertext_len));
        result.success = true;
        result.index = index;
        result.plaintext = session::span_u8_copy_or_throw(plaintext.data(), plaintext.size());
        assert(session_id.size() == sizeof(result.session_id));
        std::memcpy(result.session_id, session_id.data(), sizeof(result.session_id));
    } catch (const std::exception& e) {
        result.error_len_incl_null_terminator = format_c_str(error, error_len, "{}", e.what());
    }
    return result;
}

LIBSESSION_C_API bool session_decrypt_ons_response(
        const char* name_in,
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* nonce_in,
        char* session_id_out) {
    try {
        std::optional<std::span<const std::byte, encryption::XCHACHA20_NONCEBYTES>> nonce;
        if (nonce_in)
            nonce = to_byte_span<encryption::XCHACHA20_NONCEBYTES>(nonce_in);

        auto session_id = session::decrypt_ons_response(
                name_in, to_byte_span(ciphertext_in, ciphertext_len), nonce);

        std::memcpy(session_id_out, session_id.c_str(), session_id.size() + 1);
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_decrypt_push_notification(
        const unsigned char* payload_in,
        size_t payload_len,
        const unsigned char* enc_key_in,
        unsigned char** plaintext_out,
        size_t* plaintext_len) {
    try {
        auto plaintext = session::decrypt_push_notification(
                to_byte_span(payload_in, payload_len), to_byte_span<32>(enc_key_in));

        *plaintext_out = static_cast<unsigned char*>(malloc(plaintext.size()));
        *plaintext_len = plaintext.size();
        std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_encrypt_xchacha20(
        const unsigned char* plaintext_in,
        size_t plaintext_len,
        const unsigned char* key_in,
        unsigned char** ciphertext_out,
        size_t* ciphertext_len) {
    try {
        auto ciphertext = session::encrypt_xchacha20(
                to_byte_span(plaintext_in, plaintext_len), to_byte_span<32>(key_in));

        *ciphertext_out = static_cast<unsigned char*>(malloc(ciphertext.size()));
        *ciphertext_len = ciphertext.size();
        std::memcpy(*ciphertext_out, ciphertext.data(), ciphertext.size());
        return true;
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool session_decrypt_xchacha20(
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        const unsigned char* key_in,
        unsigned char** plaintext_out,
        size_t* plaintext_len) {
    try {
        auto plaintext = session::decrypt_xchacha20(
                to_byte_span(ciphertext_in, ciphertext_len), to_byte_span<32>(key_in));

        *plaintext_out = static_cast<unsigned char*>(malloc(plaintext.size()));
        *plaintext_len = plaintext.size();
        std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
        return true;
    } catch (...) {
        return false;
    }
}

}  // extern "C"
