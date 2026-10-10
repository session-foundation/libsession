#pragma once

#include <chrono>
#include <cstddef>
#include <session/clock.hpp>
#include <session/config/namespaces.hpp>
#include <span>
#include <string>
#include <vector>

namespace session::core {

/// A single message retrieved from the swarm, as returned by a retrieve request.  The data,
/// hash, timestamp, and expiry fields are exactly the four values the server returns per
/// message; data is owned externally and must remain valid for the lifetime of this struct.
struct SwarmMessage {
    std::span<const std::byte> data;
    std::string hash;
    sys_ms timestamp;
    sys_ms expiry;
};

/// One message to upload, as handed to `Core::_swarm_push`.
///
/// The TTL is per message rather than a property of the push: configs and the device group are
/// stored for a month, a device link request for ten minutes.
struct SwarmStore {
    config::Namespace ns;
    std::vector<std::byte> data;
    std::chrono::milliseconds ttl;
};

/// What became of one `SwarmStore`, in the order the stores were given.
///
/// `hash` is what the swarm assigned it, and is what a later push names to supersede it -- so a
/// caller that means to replace this message has to keep it.
struct SwarmStoreResult {
    bool stored = false;
    std::string hash;
};

}  // namespace session::core
