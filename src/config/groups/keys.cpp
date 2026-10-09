#include "session/config/groups/keys.hpp"

#include <oxenc/base64.h>
#include <oxenc/hex.h>
#include <sodium/core.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

#include <chrono>
#include <iterator>
#include <stdexcept>
#include <unordered_set>

#include "../internal.hpp"
#include "session/config/groups/info.hpp"
#include "session/config/groups/keys.h"
#include "session/config/groups/members.hpp"
#include "session/multi_encrypt.hpp"
#include "session/session_encrypt.hpp"
#include "session/xed25519.hpp"

using namespace std::literals;

namespace session::config::groups {

static auto sys_time_from_ms(int64_t milliseconds_since_epoch) {
    return std::chrono::system_clock::time_point{milliseconds_since_epoch * 1ms};
}

Keys::Keys(
        std::span<const unsigned char> user_ed25519_secretkey,
        std::span<const unsigned char> group_ed25519_pubkey,
        std::optional<std::span<const unsigned char>> group_ed25519_secretkey,
        std::optional<std::span<const unsigned char>> dumped,
        Info& info,
        Members& members) {

    if (sodium_init() == -1)
        throw std::runtime_error{"libsodium initialization failed!"};

    if (user_ed25519_secretkey.size() != 64)
        throw std::invalid_argument{"Invalid Keys construction: invalid user ed25519 secret key"};
    if (group_ed25519_pubkey.size() != 32)
        throw std::invalid_argument{"Invalid Keys construction: invalid group ed25519 public key"};
    if (group_ed25519_secretkey && group_ed25519_secretkey->size() != 64)
        throw std::invalid_argument{"Invalid Keys construction: invalid group ed25519 secret key"};

    init_sig_keys(group_ed25519_pubkey, group_ed25519_secretkey);

    user_ed25519_sk.load(user_ed25519_secretkey.data(), 64);

    if (dumped) {
        load_dump(*dumped);
        auto key_list = group_keys();
        members.replace_keys(key_list, /*dirty=*/false);
        info.replace_keys(key_list, /*dirty=*/false);
    }
}

bool Keys::needs_dump() const {
    return needs_dump_;
}

std::vector<unsigned char> Keys::dump() {
    auto dumped = make_dump();

    needs_dump_ = false;
    return dumped;
}

std::vector<unsigned char> Keys::make_dump() const {
    oxenc::bt_dict_producer d;
    {
        auto active = d.append_list("A");
        for (const auto& [gen, hashes] : active_msgs_) {
            auto lst = active.append_list();
            lst.append(gen);
            for (const auto& h : hashes)
                lst.append(h);
        }
    }

    {
        auto keys = d.append_list("L");
        for (auto& k : keys_) {
            auto ki = keys.append_dict();
            // NB: Keys must be in sorted order
            ki.append("g", k.generation);
            ki.append("k", to_string_view(k.key));
            ki.append("t", epoch_ms(k.timestamp));
        }
    }

    if (!pending_key_config_.empty()) {
        auto pending = d.append_dict("P");
        // NB: Keys must be in sorted order
        pending.append("c", to_string_view(pending_key_config_));
        pending.append("g", pending_gen_);
        pending.append("k", to_string_view(pending_key_));
    }

    return to_vector(d.view());
}

void Keys::load_dump(std::span<const unsigned char> dump) {
    oxenc::bt_dict_consumer d{dump};

    if (d.skip_until("A")) {
        auto active = d.consume_list_consumer();
        while (!active.is_finished()) {
            auto lst = active.consume_list_consumer();
            auto& hashes = active_msgs_[lst.consume_integer<int64_t>()];
            while (!lst.is_finished())
                hashes.insert(lst.consume_string());
        }
    } else {
        throw config_value_error{"Invalid Keys dump: `active` not found"};
    }

    if (d.skip_until("L")) {
        auto keys = d.consume_list_consumer();
        while (!keys.is_finished()) {
            auto kd = keys.consume_dict_consumer();
            auto& key = keys_.emplace_back();

            if (!kd.skip_until("g"))
                throw config_value_error{"Invalid Keys dump: found key without generation (g)"};
            key.generation = kd.consume_integer<int64_t>();

            if (!kd.skip_until("k"))
                throw config_value_error{"Invalid Keys dump: found key without key bytes (k)"};
            auto key_bytes = kd.consume_string_view();
            if (key_bytes.size() != key.key.size())
                throw config_value_error{
                        "Invalid Keys dump: found key with invalid size (" +
                        std::to_string(key_bytes.size()) + ")"};
            std::memcpy(key.key.data(), key_bytes.data(), key.key.size());

            if (!kd.skip_until("t"))
                throw config_value_error{"Invalid Keys dump: found key without timestamp (t)"};
            key.timestamp = sys_time_from_ms(kd.consume_integer<int64_t>());

            if (keys_.size() > 1 && *std::prev(keys_.end(), 2) >= key)
                throw config_value_error{"Invalid Keys dump: keys are not in proper sorted order"};
        }
    } else {
        throw config_value_error{"Invalid Keys dump: `keys` not found"};
    }

    if (d.skip_until("P")) {
        auto pending = d.consume_dict_consumer();

        if (!pending.skip_until("c"))
            throw config_value_error{"Invalid Keys dump: found pending without config (c)"};
        auto pc = pending.consume_string_view();
        pending_key_config_.clear();
        pending_key_config_.resize(pc.size());
        std::memcpy(pending_key_config_.data(), pc.data(), pc.size());

        if (!pending.skip_until("g"))
            throw config_value_error{"Invalid Keys dump: found pending without generation (g)"};
        pending_gen_ = pending.consume_integer<int64_t>();

        if (!pending.skip_until("k"))
            throw config_value_error{"Invalid Keys dump: found pending without key (k)"};
        auto pk = pending.consume_string_view();
        if (pk.size() != pending_key_.size())
            throw config_value_error{
                    "Invalid Keys dump: found pending key (k) with invalid size (" +
                    std::to_string(pk.size()) + ")"};
        std::memcpy(pending_key_.data(), pk.data(), pending_key_.size());
    }
}

size_t Keys::size() const {
    return keys_.size() + !pending_key_config_.empty();
}

std::vector<std::span<const unsigned char>> Keys::group_keys() const {
    std::vector<std::span<const unsigned char>> ret;
    ret.reserve(size());

    if (!pending_key_config_.empty())
        ret.emplace_back(pending_key_.data(), 32);

    for (auto it = keys_.rbegin(); it != keys_.rend(); ++it)
        ret.emplace_back(it->key.data(), 32);

    return ret;
}

std::span<const unsigned char> Keys::group_enc_key() const {
    if (!pending_key_config_.empty())
        return {pending_key_.data(), 32};
    if (keys_.empty())
        throw std::runtime_error{"group_enc_key failed: Keys object has no keys at all!"};

    auto& key = keys_.back().key;
    return {key.data(), key.size()};
}

void Keys::load_admin_key(std::span<const unsigned char> seed, Info& info, Members& members) {
    if (admin())
        return;

    if (seed.size() == 64)
        seed = seed.subspan(0, seed.size() - 32);
    else if (seed.size() != 32)
        throw std::invalid_argument{
                "Failed to load admin key: invalid secret key (expected 32 or 64 bytes)"};

    std::array<unsigned char, 32> pk;
    sodium_cleared<std::array<unsigned char, 64>> sk;
    crypto_sign_ed25519_seed_keypair(pk.data(), sk.data(), seed.data());

    if (_sign_pk.has_value() && *_sign_pk != pk)
        throw std::runtime_error{
                "Failed to load admin key: given secret key does not match group pubkey"};

    auto seckey = to_span(sk);
    set_sig_keys(seckey);
    info.set_sig_keys(seckey);
    members.set_sig_keys(seckey);
}

namespace {

    std::array<unsigned char, 32> compute_xpk(const unsigned char* ed25519_pk) {
        std::array<unsigned char, 32> xpk;
        if (0 != crypto_sign_ed25519_pk_to_curve25519(xpk.data(), ed25519_pk))
            throw std::runtime_error{
                    "An error occured while attempting to convert Ed25519 pubkey to X25519; "
                    "is the pubkey valid?"};
        return xpk;
    }

    constexpr auto seed_hash_key = "SessionGroupKeySeed"sv;
    const std::span<const unsigned char> enc_key_hash_key = to_span("SessionGroupKeyGen");
    constexpr auto enc_key_admin_hash_key = "SessionGroupKeyAdminKey"sv;
    constexpr auto enc_key_member_hash_key = "SessionGroupKeyMemberKey"sv;
    const std::span<const unsigned char> junk_seed_hash_key = to_span("SessionGroupJunkMembers");

}  // namespace

std::span<const unsigned char> Keys::rekey(Info& info, Members& members) {
    if (!admin())
        throw std::logic_error{
                "Unable to issue a new group encryption key without the main group keys"};

    // For members we calculate the outer encryption key as H(aB || A || B).  But because we only
    // have `B` (the session id) as an x25519 pubkey, we do this in x25519 space, which means we
    // have to use the x25519 conversion of a/A rather than the group's ed25519 pubkey.
    auto group_xpk = compute_xpk(_sign_pk->data());

    sodium_cleared<std::array<unsigned char, 32>> group_xsk;
    crypto_sign_ed25519_sk_to_curve25519(group_xsk.data(), _sign_sk.data());

    // We need quasi-randomness: full secure random would be great, except that different admins
    // encrypting for the same update would always create different keys, but we want it
    // deterministic so that that doesn't happen.
    //
    // So we use:
    //
    // H1(member0 || member1 || ... || memberN || generation || H2(group_secret_key))
    //
    // where:
    // - H1(.) = 56-byte BLAKE2b keyed hash with key "SessionGroupKeyGen"
    // - memberI is each members full session ID, expressed in hex (66 chars), in sorted order (note
    //   that this includes *all* members, not only non-admins).
    // - generation is the new generation value, expressed as a base 10 string (e.g. "123")
    // - H2(.) = 32-byte BLAKE2b keyed hash of the sodium group secret key seed (just the 32 byte,
    //           not the full 64 byte with the pubkey in the second half), key "SessionGroupKeySeed"
    //
    // And then from this 56-byte hash we use the first 32 bytes as the new group key and the last
    // 24 bytes as the encryption nonce.
    //
    // If we have to append junk member keys (for padding) them we reuse H1 with H(H1 || a) to
    // produce a sodium pseudo-RNG seed for deterministic junk value generation.
    //
    // To encrypt this we have one key encrypted for all admins, plus one encryption per non-admin
    // member.  For admins we encrypt using a 32-byte blake2b keyed hash of the group secret key
    // seed, just like H2, but with key "SessionGroupKeyAdminKey".

    std::array<unsigned char, 32> h2 = seed_hash(seed_hash_key);

    std::array<unsigned char, 56> h1;

    crypto_generichash_blake2b_state st;

    crypto_generichash_blake2b_init(
            &st, enc_key_hash_key.data(), enc_key_hash_key.size(), h1.size());
    for (const auto& m : members)
        crypto_generichash_blake2b_update(
                &st, to_unsigned(m.session_id.data()), m.session_id.size());

    auto gen = keys_.empty() ? 0 : keys_.back().generation + 1;
    auto gen_str = std::to_string(gen);
    crypto_generichash_blake2b_update(&st, to_unsigned(gen_str.data()), gen_str.size());

    crypto_generichash_blake2b_update(&st, h2.data(), 32);

    crypto_generichash_blake2b_final(&st, h1.data(), h1.size());

    std::span<const unsigned char> enc_key{h1.data(), 32};
    std::span<const unsigned char> nonce{h1.data() + 32, 24};

    oxenc::bt_dict_producer d{};

    d.append("#", to_string_view(nonce));

    static_assert(crypto_aead_xchacha20poly1305_ietf_KEYBYTES == 32);
    static_assert(crypto_aead_xchacha20poly1305_ietf_ABYTES == 16);
    std::array<
            unsigned char,
            crypto_aead_xchacha20poly1305_ietf_KEYBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES>
            encrypted;
    std::string_view enc_sv = to_string_view(encrypted);

    // Shared key for admins
    auto member_k = seed_hash(enc_key_admin_hash_key);
    static_assert(member_k.size() == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    crypto_aead_xchacha20poly1305_ietf_encrypt(
            encrypted.data(),
            nullptr,
            enc_key.data(),
            enc_key.size(),
            nullptr,
            0,
            nullptr,
            nonce.data(),
            member_k.data());

    d.append("G", gen);
    d.append("K", enc_sv);

    {
        auto member_keys = d.append_list("k");
        int member_count = 0;
        std::vector<std::array<unsigned char, 32>> member_xpk_raw;
        std::vector<std::span<const unsigned char>> member_xpks;
        member_xpk_raw.reserve(members.size());
        member_xpks.reserve(members.size());
        for (const auto& m : members) {
            member_xpk_raw.push_back(session_id_pk(m.session_id));
            member_xpks.emplace_back(member_xpk_raw.back().data(), member_xpk_raw.back().size());
        }

        encrypt_for_multiple(
                enc_key,
                member_xpks,
                nonce,
                to_span(group_xsk),
                to_span(group_xpk),
                enc_key_member_hash_key,
                [&](std::span<const unsigned char> enc_sv) {
                    member_keys.append(enc_sv);
                    member_count++;
                },
                true  // ignore invalid
        );

        // Pad it out with junk entries to the next MESSAGE_KEY_MULTIPLE
        if (member_count % MESSAGE_KEY_MULTIPLE) {
            int n_junk = MESSAGE_KEY_MULTIPLE - (member_count % MESSAGE_KEY_MULTIPLE);
            std::vector<unsigned char> junk_data;
            junk_data.resize(encrypted.size() * n_junk);

            std::array<unsigned char, randombytes_SEEDBYTES> rng_seed;
            crypto_generichash_blake2b_init(
                    &st, junk_seed_hash_key.data(), junk_seed_hash_key.size(), rng_seed.size());
            crypto_generichash_blake2b_update(&st, h1.data(), h1.size());
            crypto_generichash_blake2b_update(&st, _sign_sk.data(), _sign_sk.size());
            crypto_generichash_blake2b_final(&st, rng_seed.data(), rng_seed.size());

            randombytes_buf_deterministic(junk_data.data(), junk_data.size(), rng_seed.data());
            std::string_view junk_view = to_string_view(junk_data);
            while (!junk_view.empty()) {
                member_keys.append(junk_view.substr(0, encrypted.size()));
                junk_view.remove_prefix(encrypted.size());
            }
        }
    }

    // Finally we sign the message at put it as the ~ key (which is 0x7e, and thus comes later than
    // any other printable ascii key).
    d.append_signature(
            "~", [this](std::span<const unsigned char> to_sign) { return sign(to_sign); });

    // Load this key/config/gen into our pending variables
    pending_gen_ = gen;
    std::memcpy(pending_key_.data(), enc_key.data(), pending_key_.size());
    pending_key_config_.clear();
    auto conf = d.view();
    pending_key_config_.resize(conf.size());
    std::memcpy(pending_key_config_.data(), conf.data(), conf.size());

    auto new_key_list = group_keys();
    // We want to dirty the member/info lists so that they get re-encrypted and re-pushed with the
    // new key:
    members.replace_keys(new_key_list, /*dirty=*/true);
    info.replace_keys(new_key_list, /*dirty=*/true);

    needs_dump_ = true;

    return std::span<const unsigned char>{pending_key_config_.data(), pending_key_config_.size()};
}

std::vector<unsigned char> Keys::sign(std::span<const unsigned char> data) const {
    auto sig = signer_(data);
    if (sig.size() != 64)
        throw std::logic_error{"Invalid signature: signing function did not return 64 bytes"};
    return sig;
}

std::vector<unsigned char> Keys::key_supplement(const std::vector<std::string>& sids) const {
    if (!admin())
        throw std::logic_error{
                "Unable to issue supplemental group encryption keys without the main group keys"};

    if (keys_.empty())
        throw std::logic_error{
                "Unable to create supplemental keys: this object has no keys at all"};

    // For members we calculate the outer encryption key as H(aB || A || B).  But because we only
    // have `B` (the session id) as an x25519 pubkey, we do this in x25519 space, which means we
    // have to use the x25519 conversion of a/A rather than the group's ed25519 pubkey.
    auto group_xpk = compute_xpk(_sign_pk->data());

    sodium_cleared<std::array<unsigned char, 32>> group_xsk;
    crypto_sign_ed25519_sk_to_curve25519(group_xsk.data(), _sign_sk.data());

    // We need quasi-randomness here for the nonce: full secure random would be great, except that
    // different admins encrypting for the same update would always create different keys, but we
    // want it deterministic so that that doesn't happen.
    //
    // So we use a nonce of:
    //
    // H1(member0 || member1 || ... || memberN || keysdata || H2(group_secret_key))
    //
    // where:
    // - H1(.) = 24-byte BLAKE2b keyed hash with key "SessionGroupKeyGen"
    // - memberI is the full session ID of each member included in this key update, expressed in hex
    //   (66 chars), in sorted order.
    // - keysdata is the unencrypted inner value that we are encrypting for each supplemental member
    // - H2(.) = 32-byte BLAKE2b keyed hash of the sodium group secret key seed (just the 32 byte,
    //           not the full 64 byte with the pubkey in the second half), key "SessionGroupKeySeed"

    std::string supp_keys;
    {
        oxenc::bt_list_producer supp;
        for (auto& ki : keys_) {
            auto d = supp.append_dict();
            d.append("g", ki.generation);
            d.append("k", to_string_view(ki.key));
            d.append("t", epoch_ms(ki.timestamp));
        }
        supp_keys = std::move(supp).str();
    }

    std::array<unsigned char, 24> h1;

    crypto_generichash_blake2b_state st;

    crypto_generichash_blake2b_init(
            &st, enc_key_hash_key.data(), enc_key_hash_key.size(), h1.size());

    for (const auto& sid : sids)
        crypto_generichash_blake2b_update(&st, to_unsigned(sid.data()), sid.size());

    crypto_generichash_blake2b_update(&st, to_unsigned(supp_keys.data()), supp_keys.size());

    std::array<unsigned char, 32> h2 = seed_hash(seed_hash_key);
    crypto_generichash_blake2b_update(&st, h2.data(), h2.size());

    crypto_generichash_blake2b_final(&st, h1.data(), h1.size());

    std::span<const unsigned char> nonce{h1.data(), h1.size()};

    oxenc::bt_dict_producer d{};

    d.append("#", to_string_view(nonce));

    {
        auto list = d.append_list("+");
        std::vector<unsigned char> encrypted;
        encrypted.resize(supp_keys.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);

        size_t member_count = 0;

        std::vector<std::array<unsigned char, 32>> member_xpk_raw;
        std::vector<std::span<const unsigned char>> member_xpks;
        member_xpk_raw.reserve(sids.size());
        member_xpks.reserve(sids.size());
        for (const auto& sid : sids) {
            member_xpk_raw.push_back(session_id_pk(sid));
            member_xpks.emplace_back(member_xpk_raw.back().data(), member_xpk_raw.back().size());
        }

        encrypt_for_multiple(
                supp_keys,
                member_xpks,
                nonce,
                to_span(group_xsk),
                to_span(group_xpk),
                enc_key_member_hash_key,
                [&](std::span<const unsigned char> encrypted) {
                    list.append(encrypted);
                    member_count++;
                },
                true  // ignore invalid
        );

        if (member_count == 0)
            throw std::runtime_error{
                    "Unable to construct supplemental messages: invalid session ids given"};
    }

    d.append("G", keys_.back().generation);

    // Finally we sign the message at put it as the ~ key (which is 0x7e, and thus comes later than
    // any other printable ascii key).
    d.append_signature(
            "~", [this](std::span<const unsigned char> to_sign) { return sign(to_sign); });

    return to_vector(d.view());
}

// Blinding factor for subaccounts: H(sessionid || groupid) mod L, where H is 64-byte blake2b, using
// a hash key derived from the group's seed.
std::array<unsigned char, 32> Keys::subaccount_blind_factor(
        const std::array<unsigned char, 32>& session_xpk) const {

    auto mask = seed_hash("SessionGroupSubaccountMask");
    static_assert(mask.size() == crypto_generichash_blake2b_KEYBYTES);

    std::array<unsigned char, 64> h;
    crypto_generichash_blake2b_state st;
    crypto_generichash_blake2b_init(&st, mask.data(), mask.size(), h.size());
    crypto_generichash_blake2b_update(&st, to_unsigned("\x05"), 1);
    crypto_generichash_blake2b_update(&st, session_xpk.data(), session_xpk.size());
    crypto_generichash_blake2b_update(&st, to_unsigned("\x03"), 1);
    crypto_generichash_blake2b_update(&st, _sign_pk->data(), _sign_pk->size());
    crypto_generichash_blake2b_final(&st, h.data(), h.size());

    std::array<unsigned char, 32> out;
    crypto_core_ed25519_scalar_reduce(out.data(), h.data());
    return out;
}

namespace {

    // These constants are defined and explains in more detail in oxen-storage-server
    constexpr unsigned char SUBACC_FLAG_READ = 0b0001;
    constexpr unsigned char SUBACC_FLAG_WRITE = 0b0010;
    constexpr unsigned char SUBACC_FLAG_DEL = 0b0100;
    constexpr unsigned char SUBACC_FLAG_ANY_PREFIX = 0b1000;

    constexpr unsigned char subacc_flags(bool write, bool del) {
        return SUBACC_FLAG_READ | (write ? SUBACC_FLAG_WRITE : 0) | (del ? SUBACC_FLAG_DEL : 0);
    }

}  // namespace

std::vector<unsigned char> Keys::swarm_make_subaccount(
        std::string_view session_id, bool write, bool del) const {
    if (!admin())
        throw std::logic_error{"Cannot make subaccount signature: admin keys required"};

    // This gets a wee bit complicated because we only have a session_id, but we really need an
    // Ed25519 pubkey.  So we do the signal-style XEd25519 thing here where we start with the
    // positive alternative behind their x25519 pubkey and work from there.  This means,
    // unfortunately, that making a signature needs to muck around since this is the proper public
    // only half the time.

    // Terminology/variables (a/A indicates private/public keys)
    // - s/S are the Ed25519 underlying Session keys (neither is observed in this context)
    // - x/X are the X25519 conversions of s/S (x, similarly, is not observed, but X is: it's in the
    //   session_id).
    // - T = |S|, i.e. the positive of the two alternatives we get from inverting the Ed -> X
    //   pubkey.
    // - c/C is the group's Ed25519
    // - k is the blinding factor, which is: H(\x05...[sessionid]\x03...[groupid], key=M) mod L,
    //   where: H is 64-byte blake2b; M is `subaccount_blind_factor` (see above).
    // - p is the account network prefix (03)
    // - f are the flag bits, determined by `write` and `del` arguments

    auto X = session_id_pk(session_id);
    auto& c = _sign_sk;

    auto k = subaccount_blind_factor(X);

    // T = |S|
    auto T = xed25519::pubkey(X);

    // kT is the user's Ed25519 blinded pubkey:
    std::array<unsigned char, 32> kT;

    if (0 != crypto_scalarmult_ed25519_noclamp(kT.data(), k.data(), T.data()))
        throw std::runtime_error{"scalarmult failed: perhaps an invalid session id?"};

    std::vector<unsigned char> out;
    out.resize(4 + 32 + 64);
    out[0] = 0x03;                      // network prefix
    out[1] = subacc_flags(write, del);  // permission flags
    out[2] = 0;                         // reserved 1
    out[3] = 0;                         // reserved 2
    // The next 32 bytes are k (NOT kT; the user can go make kT themselves):
    std::memcpy(&out[4], k.data(), k.size());

    // And then finally, we append a group signature of: p || f || 0 || 0 || kT
    std::array<unsigned char, 36> to_sign;
    std::memcpy(&to_sign[0], out.data(), 4);  // first 4 bytes are the same as out
    std::memcpy(&to_sign[4], kT.data(), 32);  // but then we have kT instead of k
    crypto_sign_ed25519_detached(&out[36], nullptr, to_sign.data(), to_sign.size(), c.data());

    return out;
}

std::vector<unsigned char> Keys::swarm_subaccount_token(
        std::string_view session_id, bool write, bool del) const {
    if (!admin())
        throw std::logic_error{"Cannot make subaccount signature: admin keys required"};

    // Similar to the above, but we only care about getting flags || kT

    auto X = session_id_pk(session_id);
    auto k = subaccount_blind_factor(X);

    // T = |S|
    auto T = xed25519::pubkey(X);

    std::vector<unsigned char> out;
    out.resize(4 + 32);
    out[0] = 0x03;                      // network prefix
    out[1] = subacc_flags(write, del);  // permission flags
    out[2] = 0;                         // reserved 1
    out[3] = 0;                         // reserved 2
    if (0 != crypto_scalarmult_ed25519_noclamp(&out[4], k.data(), T.data()))
        throw std::runtime_error{"scalarmult failed: perhaps an invalid session id?"};
    return out;
}

Keys::swarm_auth Keys::swarm_subaccount_sign(
        std::span<const unsigned char> msg,
        std::span<const unsigned char> sign_val,
        bool binary) const {
    if (sign_val.size() != 100)
        throw std::logic_error{"Invalid signing value: size is wrong"};

    if (!_sign_pk)
        throw std::logic_error{"Unable to verify: group pubkey is not set (!?)"};

    Keys::swarm_auth result;
    auto& [token, sub_sig, sig] = result;

    // (see above for variable/crypto notation)

    std::span<const unsigned char> k = sign_val.subspan(4, 32);

    // our token is the first 4 bytes of `sign_val` (flags, etc.), followed by kT which we have to
    // compute:
    token.resize(36);
    std::memcpy(token.data(), sign_val.data(), 4);

    // T = |S|, i.e. we have to clear the sign bit from our pubkey
    std::array<unsigned char, 32> T;
    crypto_sign_ed25519_sk_to_pk(T.data(), user_ed25519_sk.data());
    bool neg = T[31] & 0x80;
    T[31] &= 0x7f;
    if (0 != crypto_scalarmult_ed25519_noclamp(to_unsigned(token.data() + 4), k.data(), T.data()))
        throw std::runtime_error{"scalarmult failed: perhaps an invalid session id or seed?"};

    // token is now set: flags || kT
    std::span<const unsigned char> kT{to_unsigned(token.data() + 4), 32};

    // sub_sig is just the admin's signature, sitting at the end of sign_val (after 4f || k):
    sub_sig = to_string_view(sign_val.subspan(36));

    // Our signing private scalar is kt, where t = ±s according to whether we had to negate S to
    // make T
    std::array<unsigned char, 32> s, s_neg;
    crypto_sign_ed25519_sk_to_curve25519(s.data(), user_ed25519_sk.data());
    crypto_core_ed25519_scalar_negate(s_neg.data(), s.data());
    xed25519::constant_time_conditional_assign(s, s_neg, neg);

    auto& t = s;

    std::array<unsigned char, 32> kt;
    crypto_core_ed25519_scalar_mul(kt.data(), k.data(), t.data());

    // We now have kt, kT, our privkey/public.  (Note that kt is a scalar, not a seed).

    // We're going to get *close* to standard Ed25519 here, except:
    //
    // where Ed25519 uses
    //
    //     r = SHA512(SHA512(seed)[32:64] || M) mod L
    //
    // we're instead going to use:
    //
    //     r = H64(H32(seed, key="SubaccountSeed") || kT || M, key="SubaccountSig") mod L
    //
    // where H64 and H32 are BLAKE2b keyed hashes of 64 and 32 bytes, respectively, thus
    // differentiating the signature for both different seeds and different blinded kT pubkeys.
    //
    // From there, we follow the standard EdDSA construction:
    //
    //     R = rB
    //     S = r + H(R || kT || M) kt    (mod L)
    //
    // (using the standard Ed25519 SHA-512 here for H)

    constexpr auto seed_hash_key = "SubaccountSeed"sv;
    constexpr auto r_hash_key = "SubaccountSig"sv;
    std::array<unsigned char, 32> hseed;
    crypto_generichash_blake2b(
            hseed.data(),
            hseed.size(),
            user_ed25519_sk.data(),
            32,
            to_unsigned(seed_hash_key.data()),
            seed_hash_key.size());

    std::array<unsigned char, 64> tmp;
    crypto_generichash_blake2b_state st;
    crypto_generichash_blake2b_init(
            &st, to_unsigned(r_hash_key.data()), r_hash_key.size(), tmp.size());
    crypto_generichash_blake2b_update(&st, hseed.data(), hseed.size());
    crypto_generichash_blake2b_update(&st, kT.data(), kT.size());
    crypto_generichash_blake2b_update(&st, msg.data(), msg.size());
    crypto_generichash_blake2b_final(&st, tmp.data(), tmp.size());

    std::array<unsigned char, 32> r;
    crypto_core_ed25519_scalar_reduce(r.data(), tmp.data());

    sig.resize(64);
    unsigned char* R = to_unsigned(sig.data());
    unsigned char* S = to_unsigned(sig.data() + 32);
    // R = rB
    crypto_scalarmult_ed25519_base_noclamp(R, r.data());

    // Compute S = r + H(R || A || M) a mod L:  (with A = kT, a = kt)
    crypto_hash_sha512_state shast;
    crypto_hash_sha512_init(&shast);
    crypto_hash_sha512_update(&shast, R, 32);
    crypto_hash_sha512_update(&shast, kT.data(), kT.size());  // A = pubkey, that is, kT
    crypto_hash_sha512_update(&shast, msg.data(), msg.size());
    std::array<unsigned char, 64> hram;
    crypto_hash_sha512_final(&shast, hram.data());      // S = H(R||A||M)
    crypto_core_ed25519_scalar_reduce(S, hram.data());  // S %= L
    crypto_core_ed25519_scalar_mul(S, S, kt.data());    // S *= a
    crypto_core_ed25519_scalar_add(S, S, r.data());     // S += r

    // sig is now set to the desired R || S, with S = r + H(R || A || M)a (all mod L)

    if (!binary) {
        token = oxenc::to_base64(token);
        sub_sig = oxenc::to_base64(sub_sig);
        sig = oxenc::to_base64(sig);
    }

    return result;
}

bool Keys::swarm_verify_subaccount(
        std::span<const unsigned char> sign_val, bool write, bool del) const {
    if (!_sign_pk)
        return false;
    return swarm_verify_subaccount(
            "03" + oxenc::to_hex(_sign_pk->begin(), _sign_pk->end()),
            std::span<const unsigned char>{user_ed25519_sk.data(), user_ed25519_sk.size()},
            sign_val,
            write,
            del);
}

bool Keys::swarm_verify_subaccount(
        std::string group_id,
        std::span<const unsigned char> user_ed_sk,
        std::span<const unsigned char> sign_val,
        bool write,
        bool del) {
    auto group_pk = session_id_pk(group_id, "03");

    if (sign_val.size() != 100)
        return false;

    std::span<const unsigned char> prefix = sign_val.subspan(0, 4);
    if (prefix[0] != 0x03 && !(prefix[1] & SUBACC_FLAG_ANY_PREFIX))
        return false;  // require either 03 prefix match, or the "any prefix" flag

    if (!(prefix[1] & SUBACC_FLAG_READ))
        return false;  // missing the read flag

    if (write && !(prefix[1] & SUBACC_FLAG_WRITE))
        return false;  // we require write, but it isn't set
                       //
    if (del && !(prefix[1] & SUBACC_FLAG_DEL))
        return false;  // we require delete, but it isn't set

    std::span<const unsigned char> k = sign_val.subspan(4, 32);
    std::span<const unsigned char> sig = sign_val.subspan(36);

    // T = |S|, i.e. we have to clear the sign bit from our pubkey
    std::array<unsigned char, 32> T;
    crypto_sign_ed25519_sk_to_pk(T.data(), user_ed_sk.data());
    T[31] &= 0x7f;

    // Compute kT, then reconstruct the `flags || kT` value the admin should have provided a
    // signature for
    std::array<unsigned char, 32> kT;
    if (0 != crypto_scalarmult_ed25519_noclamp(kT.data(), k.data(), T.data()))
        throw std::runtime_error{"scalarmult failed: perhaps an invalid session id or seed?"};

    std::array<unsigned char, 36> to_verify;
    std::memcpy(&to_verify[0], sign_val.data(), 4);  // prefix, flags, 2x future use bytes
    std::memcpy(&to_verify[4], kT.data(), 32);

    // Verify it!
    return 0 == crypto_sign_ed25519_verify_detached(
                        sig.data(), to_verify.data(), to_verify.size(), group_pk.data());
}

std::optional<std::span<const unsigned char>> Keys::pending_config() const {
    if (pending_key_config_.empty())
        return std::nullopt;
    return std::span<const unsigned char>{pending_key_config_.data(), pending_key_config_.size()};
}

void Keys::insert_key(std::string_view msg_hash, key_info&& new_key) {
    // Find all keys with the same generation and see if our key is in there (that is: we are
    // deliberately ignoring timestamp so that we don't add the same key with slight timestamp
    // variations).
    const auto [gen_begin, gen_end] =
            std::equal_range(keys_.begin(), keys_.end(), new_key, [](const auto& a, const auto& b) {
                return a.generation < b.generation;
            });
    for (auto it = gen_begin; it != gen_end; ++it)
        if (it->key == new_key.key) {
            active_msgs_[new_key.generation].emplace(msg_hash);
            return;
        }

    auto it = std::lower_bound(keys_.begin(), keys_.end(), new_key);

    if (keys_.size() >= 2 && it == keys_.begin() && new_key.generation < keys_.front().generation &&
        keys_.front().timestamp + KEY_EXPIRY < keys_.back().timestamp)
        // The new one is older than the front one, and the front one is already more than
        // KEY_EXPIRY before the last one, so this new one is stale.
        return;

    active_msgs_[new_key.generation].emplace(msg_hash);
    keys_.insert(it, std::move(new_key));
    remove_expired();
    needs_dump_ = true;
}

// Attempts xchacha20 decryption.
//
// Preconditions:
// - `ciphertext` must be at least 16 [crypto_aead_xchacha20poly1305_ietf_ABYTES]
// - `out` must have enough space (ciphertext.size() - 16
// [crypto_aead_xchacha20poly1305_ietf_ABYTES])
// - `nonce` must be 24 bytes [crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]
// - `key` must be 32 bytes [crypto_aead_xchacha20poly1305_ietf_KEYBYTES]
//
// The latter two are asserted in a debug build, but not otherwise checked.
//
// Returns true (after writing to `out`) if decryption succeeds, false if it fails.
namespace {
    bool try_decrypting(
            unsigned char* out,
            std::span<const unsigned char> encrypted,
            std::span<const unsigned char> nonce,
            std::span<const unsigned char> key) {
        assert(encrypted.size() >= crypto_aead_xchacha20poly1305_ietf_ABYTES);
        assert(nonce.size() == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        assert(key.size() == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

        return 0 == crypto_aead_xchacha20poly1305_ietf_decrypt(
                            out,
                            nullptr,
                            nullptr,
                            encrypted.data(),
                            encrypted.size(),
                            nullptr,
                            0,
                            nonce.data(),
                            key.data());
    }
    bool try_decrypting(
            unsigned char* out,
            std::span<const unsigned char> encrypted,
            std::span<const unsigned char> nonce,

            const std::array<unsigned char, 32>& key) {
        return try_decrypting(
                out, encrypted, nonce, std::span<const unsigned char>{key.data(), key.size()});
    }
}  // namespace

bool Keys::load_key_message(
        std::string_view hash,
        std::span<const unsigned char> data,
        int64_t timestamp_ms,
        Info& info,
        Members& members) {

    oxenc::bt_dict_consumer d{data};

    if (!_sign_pk || !verifier_)
        throw std::logic_error{"Group pubkey is not set; unable to load config message"};

    auto group_xpk = compute_xpk(_sign_pk->data());

    if (!d.skip_until("#"))
        throw config_value_error{"Key message has no nonce"};
    auto nonce = to_span(d.consume_string_view());

    sodium_vector<key_info> new_keys;
    std::optional<int64_t> max_gen;  // If set then associate the message with this generation
                                     // value, even if we didn't find a key for us.

    sodium_cleared<std::array<unsigned char, 32>> member_dec_key;
    sodium_cleared<std::array<unsigned char, 32>> member_xsk;
    std::array<unsigned char, 32> member_xpk;
    if (!admin()) {
        crypto_sign_ed25519_sk_to_curve25519(member_xsk.data(), user_ed25519_sk.data());
        member_xpk = compute_xpk(user_ed25519_sk.data() + 32);
    }

    if (d.skip_until("+")) {
        // This is a supplemental keys message, not a full one
        auto supp = d.consume_list_consumer();

        int member_key_pos = -1;

        auto next_ciphertext = [&]() -> std::optional<std::span<const unsigned char>> {
            while (!supp.is_finished()) {
                member_key_pos++;
                auto encrypted = to_span(supp.consume_string_view());
                // Expect an encrypted message like this, which has a minimum valid size (if both g
                // and t are 0 for some reason) of:
                // d            --   1
                //   1:k 32:... -- +38
                //   1:g i1e    -- + 6
                //   1:t iXe    -- + 6
                // e               + 1
                //                 ---
                //                  52
                if (encrypted.size() < 52 + crypto_aead_xchacha20poly1305_ietf_ABYTES)
                    throw config_value_error{
                            "Supplemental key message has invalid key info size at "
                            "index " +
                            std::to_string(member_key_pos)};

                if (!new_keys.empty() || admin())
                    continue;  // Keep parsing, to ensure validity of the whole message

                return encrypted;
            }
            return std::nullopt;
        };

        if (auto plaintext = decrypt_for_multiple(
                    next_ciphertext,
                    nonce,
                    to_span(member_xsk),
                    to_span(member_xpk),
                    to_span(group_xpk),
                    enc_key_member_hash_key)) {

            // Decryption success, we found our key list!

            oxenc::bt_list_consumer key_infos{to_string_view(*plaintext)};
            while (!key_infos.is_finished()) {
                auto& new_key = new_keys.emplace_back();
                auto keyinf = key_infos.consume_dict_consumer();
                if (!keyinf.skip_until("g"))
                    throw config_value_error{"Invalid supplemental key message: no `g` generation"};
                new_key.generation = keyinf.consume_integer<int64_t>();
                if (!keyinf.skip_until("k"))
                    throw config_value_error{"Invalid supplemental key message: no `k` key data"};
                auto key_val = keyinf.consume_string_view();
                if (key_val.size() != 32)
                    throw config_value_error{
                            "Invalid supplemental key message: `k` key has wrong size"};
                std::memcpy(new_key.key.data(), key_val.data(), 32);
                if (!keyinf.skip_until("t"))
                    throw config_value_error{"Invalid supplemental key message: no `t` timestamp"};
                new_key.timestamp = sys_time_from_ms(keyinf.consume_integer<int64_t>());
            }
        }

        // Ensure we consume all the ciphertexts (to ensure some message validity, even if we found
        // one halfway through).
        while (next_ciphertext()) {
        }

        if (!d.skip_until("G"))
            throw config_value_error{
                    "Supplemental key message missing required max generation field (G)"};
        max_gen = d.consume_integer<int64_t>();

    } else {  // Full message (i.e. not supplemental)

        bool found_key = false;
        auto& new_key = new_keys.emplace_back();
        new_key.timestamp = sys_time_from_ms(timestamp_ms);

        if (!d.skip_until("G"))
            throw config_value_error{"Key message missing required generation (G) field"};

        new_key.generation = d.consume_integer<int64_t>();
        if (new_key.generation < 0)
            throw config_value_error{"Key message contains invalid negative generation"};

        if (!d.skip_until("K"))
            throw config_value_error{
                    "Non-supplemental key message is missing required admin key (K)"};

        auto admin_key = to_span(d.consume_string_view());
        if (admin_key.size() != 32 + crypto_aead_xchacha20poly1305_ietf_ABYTES)
            throw config_value_error{"Key message has invalid admin key length"};

        if (admin()) {
            auto k = seed_hash(enc_key_admin_hash_key);

            if (!try_decrypting(new_key.key.data(), admin_key, nonce, k))
                throw config_value_error{"Failed to decrypt admin key from key message"};

            found_key = true;
        }

        // Even if we're already found a key we still parse these, so that admins and all users have
        // the same error conditions for rejecting an invalid config message.
        if (!d.skip_until("k"))
            throw config_value_error{"Config is missing member keys list (k)"};

        auto key_list = d.consume_list_consumer();

        int member_key_pos = -1;
        auto next_ciphertext = [&]() -> std::optional<std::span<const unsigned char>> {
            while (!key_list.is_finished()) {
                member_key_pos++;
                auto member_key = to_span(key_list.consume_string_view());
                if (member_key.size() != 32 + crypto_aead_xchacha20poly1305_ietf_ABYTES)
                    throw config_value_error{
                            "Key message has invalid member key length at index " +
                            std::to_string(member_key_pos)};

                if (found_key)
                    continue;

                return member_key;
            }
            return std::nullopt;
        };

        if (auto plaintext = decrypt_for_multiple(
                    next_ciphertext,
                    nonce,
                    to_span(member_xsk),
                    to_span(member_xpk),
                    to_span(group_xpk),
                    enc_key_member_hash_key)) {
            // Decryption success, we found our key!
            assert(plaintext->size() == 32);
            std::memcpy(new_key.key.data(), plaintext->data(), 32);
            found_key = true;
        }

        // Parse them all, even once we had a successful decryption, to properly count and fail on
        // invalid input:
        while (next_ciphertext()) {
        }

        if (++member_key_pos % MESSAGE_KEY_MULTIPLE != 0)
            throw config_value_error{"Member key list has wrong size (missing junk key padding?)"};

        if (!found_key) {
            max_gen = new_key.generation;
            new_keys.pop_back();
        }
    }

    verify_config_sig(d, verifier_);

    // If this is our pending config or this has a later generation than our pending config then
    // drop our pending status.
    if (admin() && !new_keys.empty() && !pending_key_config_.empty() &&
        (new_keys[0].generation > pending_gen_ || new_keys[0].key == pending_key_)) {
        pending_key_config_.clear();
        needs_dump_ = true;
    }

    if (!new_keys.empty()) {
        for (auto& k : new_keys)
            insert_key(hash, std::move(k));

        auto new_key_list = group_keys();
        members.replace_keys(new_key_list, /*dirty=*/false);
        info.replace_keys(new_key_list, /*dirty=*/false);
        return true;
    } else if (max_gen) {
        active_msgs_[*max_gen].emplace(hash);
        remove_expired();
        needs_dump_ = true;
    }

    return false;
}

std::unordered_set<std::string> Keys::active_hashes() const {
    std::unordered_set<std::string> hashes;
    for (const auto& [g, hash] : active_msgs_)
        hashes.insert(hash.begin(), hash.end());
    return hashes;
}

void Keys::remove_expired() {
    if (keys_.size() >= 2) {
        // When we're done, this will point at the first element we want to keep (i.e. we want to
        // remove everything in `[ begin(), lapsed_end )`).
        auto lapsed_end = keys_.begin();

        for (auto it = keys_.begin(); it != keys_.end();) {
            // Advance `it` if the next element is an alternate key (with a later timestamp) from
            // the same generation.  When we finish this little loop, `it` is the last element of
            // this generation and `it2` is the first element of the next generation.
            auto it2 = std::next(it);
            while (it2 != keys_.end() && it2->generation == it->generation)
                it = it2++;
            if (it2 == keys_.end())
                break;

            // it2 points at the lowest-timestamp value of the next-largest generation: if there is
            // something more than 30 days newer than it2, then that tells us that `it`'s generation
            // is no longer needed since a newer generation passed it more than 30 days ago.  (We
            // actually use 60 days for paranoid safety, but the logic is the same).
            //
            // NB: We don't trust the local system clock here (and the `timestamp` values are
            // swarm-provided), because devices are notoriously imprecise, which means that since we
            // only invalidate keys when new keys come in, we can hold onto one obsolete generation
            // indefinitely (but this is a tiny overhead and not worth trying to build a
            // system-clock-is-broken workaround to avoid).
            if (it2->timestamp + KEY_EXPIRY < keys_.back().timestamp)
                lapsed_end = it2;
            else
                break;
            it = it2;
        }

        if (lapsed_end != keys_.begin())
            keys_.erase(keys_.begin(), lapsed_end);
    }

    // Drop any active message hashes for generations we are no longer keeping around
    if (!keys_.empty())
        active_msgs_.erase(
                active_msgs_.begin(), active_msgs_.lower_bound(keys_.front().generation));
    else
        // Keys is empty, which means we aren't keep *any* keys around (or they are all invalid or
        // something) and so it isn't really up to us to keep them alive, since that's a history of
        // the group we apparently don't have access to.
        active_msgs_.clear();
}

bool Keys::needs_rekey() const {
    if (!admin() || keys_.size() < 2)
        return false;

    // We rekey if the max generation value is being used across multiple keys (which indicates some
    // sort of rekey collision, somewhat analagous to merge configs in regular config messages).
    auto last_it = std::prev(keys_.end());
    auto second_it = std::prev(last_it);
    return last_it->generation == second_it->generation;
}

std::optional<std::span<const unsigned char>> Keys::pending_key() const {
    if (!pending_key_config_.empty())
        return std::span<const unsigned char>{pending_key_.data(), pending_key_.size()};
    return std::nullopt;
}

static constexpr size_t ENCRYPT_OVERHEAD =
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES;

std::vector<unsigned char> Keys::encrypt_message(
        std::span<const unsigned char> plaintext, bool compress, size_t padding) const {
    assert(_sign_pk);
    std::vector<unsigned char> ciphertext = encrypt_for_group(
            user_ed25519_sk, *_sign_pk, group_enc_key(), plaintext, compress, padding);
    return ciphertext;
}

std::pair<std::string, std::vector<unsigned char>> Keys::decrypt_message(
        std::span<const unsigned char> ciphertext) const {
    assert(_sign_pk);

    //
    // Decrypt, using all the possible keys, starting with a pending one (if we have one)
    //
    DecryptGroupMessage decrypt = {};
    bool decrypt_success = false;
    if (auto pending = pending_key()) {
        try {
            std::span<std::span<const uint8_t>> key_list = {&(*pending), 1};
            decrypt = decrypt_group_message(key_list, *_sign_pk, ciphertext);
            decrypt_success = true;
        } catch (const std::exception&) {
        }
    }

    if (!decrypt_success) {
        for (auto& k : keys_) {
            try {
                std::span<const uint8_t> key = {k.key.data(), k.key.size()};
                std::span<std::span<const uint8_t>> key_list = {&key, 1};
                decrypt = decrypt_group_message(key_list, *_sign_pk, ciphertext);
                decrypt_success = true;
                break;
            } catch (const std::exception&) {
            }
        }
    }

    if (!decrypt_success)  // none of the keys worked
        throw std::runtime_error{fmt::format(
                "unable to decrypt ciphertext with any current group keys; tried {}",
                keys_.size() + (pending_key() ? 1 : 0))};

    std::pair<std::string, std::vector<unsigned char>> result;
    result.first = std::move(decrypt.session_id);
    result.second = std::move(decrypt.plaintext);
    return result;
}

}  // namespace session::config::groups

using namespace session;
using namespace session::config;

namespace {
groups::Keys& unbox(config_group_keys* conf) {
    assert(conf && conf->internals);
    return *static_cast<groups::Keys*>(conf->internals);
}
const groups::Keys& unbox(const config_group_keys* conf) {
    assert(conf && conf->internals);
    return *static_cast<const groups::Keys*>(conf->internals);
}

// Wraps a labmda and, if an exception is thrown, sets an error message in the internals.error
// string and updates the last_error pointer in the outer (C) config_object struct to point at it.
//
// No return value: accepts void and pointer returns; pointer returns will become nullptr on error
template <std::invocable Call>
decltype(auto) wrap_exceptions(config_group_keys* conf, Call&& f) {
    using Ret = std::invoke_result_t<Call>;

    try {
        conf->last_error = nullptr;
        return std::invoke(std::forward<Call>(f));
    } catch (const std::exception& e) {
        copy_c_str(conf->_error_buf, e.what());
        conf->last_error = conf->_error_buf;
    }
    if constexpr (std::is_pointer_v<Ret>)
        return nullptr;
    else
        static_assert(std::is_void_v<Ret>, "Don't know how to return an error value!");
}

// Same as above but accepts callbacks with value returns on errors: returns `f()` on success,
// `error_return` on exception
template <std::invocable Call, typename Ret>
Ret wrap_exceptions(config_group_keys* conf, Call&& f, Ret error_return) {
    try {
        conf->last_error = nullptr;
        return std::invoke(std::forward<Call>(f));
    } catch (const std::exception& e) {
        copy_c_str(conf->_error_buf, e.what());
        conf->last_error = conf->_error_buf;
    }
    return error_return;
}
}  // namespace

LIBSESSION_C_API int groups_keys_init(
        config_group_keys** conf,
        const unsigned char* user_ed25519_secretkey,
        const unsigned char* group_ed25519_pubkey,
        const unsigned char* group_ed25519_secretkey,
        config_object* cinfo,
        config_object* cmembers,
        const unsigned char* dump,
        size_t dumplen,
        char* error) {

    assert(user_ed25519_secretkey && group_ed25519_pubkey && cinfo && cmembers);

    std::span<const unsigned char> user_sk{user_ed25519_secretkey, 64};
    std::span<const unsigned char> group_pk{group_ed25519_pubkey, 32};
    std::optional<std::span<const unsigned char>> group_sk;
    if (group_ed25519_secretkey)
        group_sk.emplace(group_ed25519_secretkey, 64);
    std::optional<std::span<const unsigned char>> dumped;
    if (dump && dumplen)
        dumped.emplace(dump, dumplen);

    auto& info = *unbox<groups::Info>(cinfo);
    auto& members = *unbox<groups::Members>(cmembers);
    auto c_conf = std::make_unique<config_group_keys>();

    try {
        c_conf->internals = new groups::Keys{user_sk, group_pk, group_sk, dumped, info, members};
    } catch (const std::exception& e) {
        if (error) {
            std::string msg = e.what();
            if (msg.size() > 255)
                msg.resize(255);
            std::memcpy(error, msg.c_str(), msg.size() + 1);
        }
        return SESSION_ERR_INVALID_DUMP;
    }

    c_conf->last_error = nullptr;
    *conf = c_conf.release();
    return SESSION_ERR_NONE;
}

LIBSESSION_C_API void groups_keys_free(config_group_keys* conf) {
    delete static_cast<groups::Keys*>(conf->internals);
    delete conf;
}

LIBSESSION_EXPORT int16_t groups_keys_storage_namespace(const config_group_keys* conf) {
    return static_cast<int16_t>(unbox(conf).storage_namespace());
}

LIBSESSION_C_API size_t groups_keys_size(const config_group_keys* conf) {
    return unbox(conf).size();
}

LIBSESSION_C_API const unsigned char* groups_keys_get_key(const config_group_keys* conf, size_t N) {
    auto keys = unbox(conf).group_keys();
    if (N >= keys.size())
        return nullptr;
    return keys[N].data();
}

LIBSESSION_C_API size_t groups_keys_get_keys(
        const config_group_keys* conf, size_t offset, span_u8* dest, size_t dest_size) {
    size_t result = 0;
    if (dest) {
        auto keys = unbox(conf).group_keys();
        size_t clamped_offset = std::min(keys.size(), offset);
        for (size_t index = clamped_offset; index < keys.size() && result < dest_size; index++) {
            const std::span<const uint8_t>& src_key = keys[index];
            span_u8* dest_key = dest + result++;
            dest_key->data = const_cast<uint8_t*>(src_key.data());
            dest_key->size = src_key.size();
        }
    }
    return result;
}

LIBSESSION_C_API const span_u8 groups_keys_group_enc_key(const config_group_keys* conf) {
    span_u8 result = {};
    try {
        std::span<const uint8_t> key = unbox(conf).group_enc_key();
        result.data = const_cast<uint8_t*>(key.data());
        result.size = key.size();
        assert(result.size == 32);
    } catch (const std::exception& e) {
    }
    return result;
}

LIBSESSION_C_API bool groups_keys_is_admin(const config_group_keys* conf) {
    return unbox(conf).admin();
}

LIBSESSION_C_API bool groups_keys_load_admin_key(
        config_group_keys* conf,
        const unsigned char* secret,
        config_object* info,
        config_object* members) {
    return wrap_exceptions(
            conf,
            [&] {
                unbox(conf).load_admin_key(
                        std::span<const unsigned char>{secret, 32},
                        *unbox<groups::Info>(info),
                        *unbox<groups::Members>(members));
                return true;
            },
            false);
}

LIBSESSION_C_API bool groups_keys_rekey(
        config_group_keys* conf,
        config_object* info,
        config_object* members,
        const unsigned char** out,
        size_t* outlen) {
    assert(info && members);
    auto& keys = unbox(conf);
    std::span<const unsigned char> to_push;

    return wrap_exceptions(
            conf,
            [&] {
                to_push = keys.rekey(*unbox<groups::Info>(info), *unbox<groups::Members>(members));
                if (out && outlen) {
                    *out = to_push.data();
                    *outlen = to_push.size();
                }
                return true;
            },
            false);
}

LIBSESSION_C_API bool groups_keys_pending_config(
        const config_group_keys* conf, const unsigned char** out, size_t* outlen) {
    assert(out && outlen);
    if (auto pending = unbox(conf).pending_config()) {
        *out = pending->data();
        *outlen = pending->size();
        return true;
    }
    return false;
}

LIBSESSION_C_API bool groups_keys_load_message(
        config_group_keys* conf,
        const char* msg_hash,
        const unsigned char* data,
        size_t datalen,
        int64_t timestamp_ms,
        config_object* info,
        config_object* members) {
    assert(data && info && members);
    return wrap_exceptions(
            conf,
            [&] {
                unbox(conf).load_key_message(
                        msg_hash,
                        std::span<const unsigned char>{data, datalen},
                        timestamp_ms,
                        *unbox<groups::Info>(info),
                        *unbox<groups::Members>(members));
                return true;
            },
            false);
}

LIBSESSION_C_API config_string_list* groups_keys_active_hashes(const config_group_keys* conf) {
    return make_string_list(unbox(conf).active_hashes());
}

LIBSESSION_C_API bool groups_keys_needs_rekey(const config_group_keys* conf) {
    return unbox(conf).needs_rekey();
}

LIBSESSION_C_API bool groups_keys_needs_dump(const config_group_keys* conf) {
    return unbox(conf).needs_dump();
}

LIBSESSION_C_API void groups_keys_dump(
        config_group_keys* conf, unsigned char** out, size_t* outlen) {
    assert(out && outlen);
    auto dump = unbox(conf).dump();
    *out = static_cast<unsigned char*>(std::malloc(dump.size()));
    std::memcpy(*out, dump.data(), dump.size());
    *outlen = dump.size();
}

LIBSESSION_C_API void groups_keys_encrypt_message(
        const config_group_keys* conf,
        const unsigned char* plaintext_in,
        size_t plaintext_len,
        unsigned char** ciphertext_out,
        size_t* ciphertext_len) {
    assert(plaintext_in && ciphertext_out && ciphertext_len);

    std::vector<unsigned char> ciphertext;
    try {
        ciphertext = unbox(conf).encrypt_message(
                std::span<const unsigned char>{plaintext_in, plaintext_len});
        *ciphertext_out = static_cast<unsigned char*>(std::malloc(ciphertext.size()));
        std::memcpy(*ciphertext_out, ciphertext.data(), ciphertext.size());
        *ciphertext_len = ciphertext.size();
    } catch (...) {
        *ciphertext_out = nullptr;
        *ciphertext_len = 0;
    }
}

LIBSESSION_C_API bool groups_keys_decrypt_message(
        config_group_keys* conf,
        const unsigned char* ciphertext_in,
        size_t ciphertext_len,
        char* session_id,
        unsigned char** plaintext_out,
        size_t* plaintext_len) {
    assert(ciphertext_in && plaintext_out && plaintext_len);

    return wrap_exceptions(
            conf,
            [&] {
                auto [sid, plaintext] = unbox(conf).decrypt_message(
                        std::span<const unsigned char>{ciphertext_in, ciphertext_len});
                std::memcpy(session_id, sid.c_str(), sid.size() + 1);
                *plaintext_out = static_cast<unsigned char*>(std::malloc(plaintext.size()));
                std::memcpy(*plaintext_out, plaintext.data(), plaintext.size());
                *plaintext_len = plaintext.size();
                return true;
            },
            false);
}

LIBSESSION_C_API bool groups_keys_key_supplement(
        config_group_keys* conf,
        const char* const* sids,
        size_t sids_len,
        unsigned char** message,
        size_t* message_len) {
    assert(sids && message && message_len);

    std::vector<std::string> session_ids;
    for (size_t i = 0; i < sids_len; i++)
        session_ids.emplace_back(sids[i]);

    return wrap_exceptions(
            conf,
            [&] {
                auto msg = unbox(conf).key_supplement(session_ids);
                *message = static_cast<unsigned char*>(malloc(msg.size()));
                *message_len = msg.size();
                std::memcpy(*message, msg.data(), msg.size());
                return true;
            },
            false);
}

LIBSESSION_EXPORT int groups_keys_current_generation(config_group_keys* conf) {
    return unbox(conf).current_generation();
}

LIBSESSION_C_API bool groups_keys_swarm_make_subaccount_flags(
        config_group_keys* conf,
        const char* session_id,
        bool write,
        bool del,
        unsigned char* sign_value) {
    assert(sign_value);
    return wrap_exceptions(
            conf,
            [&] {
                auto val = unbox(conf).swarm_make_subaccount(session_id, write, del);
                assert(val.size() == 100);
                std::memcpy(sign_value, val.data(), val.size());
                return true;
            },
            false);
}

LIBSESSION_C_API bool groups_keys_swarm_make_subaccount(
        config_group_keys* conf, const char* session_id, unsigned char* sign_value) {
    return groups_keys_swarm_make_subaccount_flags(conf, session_id, true, false, sign_value);
}

LIBSESSION_C_API bool groups_keys_swarm_verify_subaccount_flags(
        const char* group_id,
        const unsigned char* session_ed25519_secretkey,
        const unsigned char* signing_value,
        bool write,
        bool del) {
    try {
        return groups::Keys::swarm_verify_subaccount(
                group_id,
                std::span<const unsigned char>{session_ed25519_secretkey, 64},
                std::span<const unsigned char>{signing_value, 100},
                write,
                del);
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool groups_keys_swarm_verify_subaccount(
        const char* group_id,
        const unsigned char* session_ed25519_secretkey,
        const unsigned char* signing_value) {
    try {
        return groups::Keys::swarm_verify_subaccount(
                group_id,
                std::span<const unsigned char>{session_ed25519_secretkey, 64},
                std::span<const unsigned char>{signing_value, 100});
    } catch (...) {
        return false;
    }
}

LIBSESSION_C_API bool groups_keys_swarm_subaccount_sign(
        config_group_keys* conf,
        const unsigned char* msg,
        size_t msg_len,
        const unsigned char* signing_value,

        char* subaccount,
        char* subaccount_sig,
        char* signature) {
    assert(msg && signing_value && subaccount && subaccount_sig && signature);
    return wrap_exceptions(
            conf,
            [&] {
                auto auth = unbox(conf).swarm_subaccount_sign(
                        std::span<const unsigned char>{msg, msg_len},
                        std::span<const unsigned char>{signing_value, 100});
                assert(auth.subaccount.size() == 48);
                assert(auth.subaccount_sig.size() == 88);
                assert(auth.signature.size() == 88);
                std::memcpy(subaccount, auth.subaccount.c_str(), auth.subaccount.size() + 1);
                std::memcpy(
                        subaccount_sig,
                        auth.subaccount_sig.c_str(),
                        auth.subaccount_sig.size() + 1);
                std::memcpy(signature, auth.signature.c_str(), auth.signature.size() + 1);
                return true;
            },
            false);
}

LIBSESSION_C_API bool groups_keys_swarm_subaccount_sign_binary(
        config_group_keys* conf,
        const unsigned char* msg,
        size_t msg_len,
        const unsigned char* signing_value,

        unsigned char* subaccount,
        unsigned char* subaccount_sig,
        unsigned char* signature) {
    assert(msg && signing_value && subaccount && subaccount_sig && signature);
    return wrap_exceptions(
            conf,
            [&] {
                auto auth = unbox(conf).swarm_subaccount_sign(
                        std::span<const unsigned char>{msg, msg_len},
                        std::span<const unsigned char>{signing_value, 100},
                        true);
                assert(auth.subaccount.size() == 36);
                assert(auth.subaccount_sig.size() == 64);
                assert(auth.signature.size() == 64);
                std::memcpy(subaccount, auth.subaccount.data(), 36);
                std::memcpy(subaccount_sig, auth.subaccount_sig.data(), 64);
                std::memcpy(signature, auth.signature.data(), 64);
                return true;
            },
            false);
}

LIBSESSION_C_API bool groups_keys_swarm_subaccount_token_flags(
        config_group_keys* conf,
        const char* session_id,
        bool write,
        bool del,
        unsigned char* token) {
    return wrap_exceptions(
            conf,
            [&] {
                auto tok = unbox(conf).swarm_subaccount_token(session_id, write, del);
                assert(tok.size() == 36);
                std::memcpy(token, tok.data(), 36);
                return true;
            },
            false);
}

LIBSESSION_C_API bool groups_keys_swarm_subaccount_token(
        config_group_keys* conf, const char* session_id, unsigned char* token) {
    return groups_keys_swarm_subaccount_token_flags(conf, session_id, true, false, token);
}
