#pragma once

#include <cstddef>
#include <optional>
#include <session/clock.hpp>
#include <session/config/namespaces.hpp>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace session::push {

/// A push's payload could not be decrypted with the key it was decrypted with.  Usually the push
/// was sent for a subscription made with a different key -- a stale registration, which should be
/// renewed.
struct undecryptable : std::runtime_error {
    using std::runtime_error::runtime_error;
};

/// A push's payload decrypted but is not shaped the way the push server builds one.
struct malformed : std::runtime_error {
    using std::runtime_error::runtime_error;
};

/// One push, decrypted and decoded: the push server's notice that a message was stored in a swarm
/// we subscribed to, with the message itself when it fitted.
struct Payload {
    /// The swarm the message was stored in, as the hex id it was subscribed under: our session id
    /// (`05…`) for the account, or a group's (`03…`).
    std::string swarm;

    /// The storage server's hash of the message, which is how everything else names it.
    std::string hash;

    config::Namespace ns;

    /// When the storage server stored it, and when it will drop it.
    sys_ms timestamp;
    sys_ms expiry;

    /// The message, when the push carried it.
    std::optional<std::vector<std::byte>> data;

    /// The message's length, when the subscription asked for message data at all: present whether
    /// or not the message then fitted.
    std::optional<size_t> length;

    /// The subscription asked for message data but this message was too large for a push, so it
    /// has to be fetched.  Never set together with `data`.
    bool too_large = false;
};

/// Decrypts and decodes a push's `enc_payload`, given the key the subscription was made with.
///
/// `enc_payload` is the decoded bytes: both platforms receive it base64-encoded in the push's
/// `enc_payload` field (see the overload below).
///
/// Handles both shapes the push server produces: its metadata is ordinarily a JSON string, but for
/// APNs a push without a body carries it as a bencoded dict instead (the server's
/// `broken_nobody_hack`, kept for clients of its older format).
///
/// Throws `undecryptable` if the payload does not decrypt with `enc_key`, and `malformed` if it
/// decrypts to something that is not a push payload.
Payload decode(std::span<const std::byte> enc_payload, std::span<const std::byte, 32> enc_key);

/// As above, taking the base64 text of the push's `enc_payload` field as received.  A value that is
/// not base64 is `malformed`.
Payload decode(std::string_view enc_payload_b64, std::span<const std::byte, 32> enc_key);

}  // namespace session::push
