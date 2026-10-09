#pragma once

#include <session/config.hpp>
#include <session/config/base.hpp>
#include <session/session_protocol.hpp>

namespace session::config {

/// keys used currently or in the past (so that we don't reuse):
///
/// s - session pro credential: a single opaque, bt-encoded string (NOT a config sub-dict). Storing
///     it as one value is deliberate: config dicts merge per-key and non-atomically, so a proof
///     split across sibling keys could end up with its signature stitched onto a *different*
///     update's fields (or its seed desynced from the pubkey the sig authorizes). As one lone
///     string the whole credential moves as an indivisible unit. The bt-encoded dict inside is:
///       e - proof expiry unix timestamp (seconds)
///       g - revocation_tag (32 bytes)
///       r - rotating ed25519 seed (32 bytes); the rotating pubkey is derived from it
///       s - proof signature by the Session Pro Backend's ed25519 key (64 bytes)
class ProConfig {
  public:
    /// Rotating private key for the public key specified in the proof. On the wire we store the
    /// seed. At runtime we derive the full key for convenience.
    cleared_uc64 rotating_privkey;

    /// A cryptographic proof for entitling an Ed25519 key to Session Pro
    ProProof proof;

    /// Parse the credential from its bt-encoded config value (the "s" key). Returns false if the
    /// value is empty, not well-formed bt, or missing/wrong-sized fields -- the caller treats that
    /// as "no usable proof" (e.g. an older client's dict-shaped value, which self-heals on the next
    /// proof fetch).
    bool load(std::string_view bt_encoded);

    /// Serialise the credential to the bt-encoded string stored at the "s" config key.
    std::string serialize() const;

    bool operator==(const ProConfig& other) const {
        return rotating_privkey == other.rotating_privkey && proof == other.proof;
    }
};
};  // namespace session::config
