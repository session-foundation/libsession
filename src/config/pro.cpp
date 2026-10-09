#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <session/config/pro.h>
#include <session/pro_backend.h>
#include <sodium/crypto_sign_ed25519.h>

#include <session/config/pro.hpp>
#include <session/sodium_array.hpp>
#include <session/util.hpp>

namespace session::config {

bool ProConfig::load(std::string_view bt_encoded) {
    if (bt_encoded.empty())
        return false;

    try {
        // A parse failure here -- including an older dict-shaped "s" from before the credential
        // became one atomic value -- is caught and treated as "no credential", self-healing on the
        // next proof fetch.
        oxenc::bt_dict_consumer d{bt_encoded};
        auto expiry = d.require<int64_t>("e");
        auto tag = d.require_span<unsigned char, sizeof(proof.revocation_tag)>("g");
        auto seed = d.require_span<unsigned char, crypto_sign_ed25519_SEEDBYTES>("r");
        auto sig = d.require_span<unsigned char, sizeof(proof.sig)>("s");

        // A future proof format would take a new config key rather than an in-dict version marker
        // (an opaque per-key-merged value can't carry a version describing itself), so there is
        // nothing to select here -- this key holds exactly the proof format below.
        proof.expiry_at = std::chrono::sys_seconds{std::chrono::seconds{expiry}};
        std::memcpy(proof.revocation_tag.data(), tag.data(), proof.revocation_tag.size());
        std::memcpy(proof.sig.data(), sig.data(), proof.sig.size());

        // Derive the rotating public key + full private key from the stored seed.
        crypto_sign_ed25519_seed_keypair(
                proof.rotating_pubkey.data(), rotating_privkey.data(), seed.data());
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::string ProConfig::serialize() const {
    oxenc::bt_dict_producer d;
    // bt dict keys MUST be appended in sorted order: e, g, r, s.
    d.append("e", epoch_seconds(proof.expiry_at));
    d.append("g", proof.revocation_tag);
    d.append("r", std::span{rotating_privkey}.first<crypto_sign_ed25519_SEEDBYTES>());
    d.append("s", proof.sig);
    return std::string{d.view()};
}

};  // namespace session::config
