#pragma once

#include <session/core.hpp>

#include "../core/swarm_request.hpp"

namespace session::push::detail {

/// Core's private swarm machinery, lent to push.  Push fetches from the swarm exactly the way a
/// poll does -- the same re-aimed swarm request, the same per-node retrieve, the same cursor -- and
/// going through Core for that keeps one implementation of each.  A friend of Core rather than
/// public API, because nothing outside libsession should be building retrieves by hand.
class CoreAccess {
  public:
    using SwarmResponse = core::Core::SwarmResponse;

    static void swarm_request(
            core::Core& core,
            std::string endpoint,
            std::function<std::vector<std::byte>(const network::service_node&)> make_body,
            std::function<void(SwarmResponse)> on_done,
            std::optional<network::service_node> prefer) {
        core._swarm_request(
                core.globals.pubkey_x25519(),
                std::move(endpoint),
                std::move(make_body),
                std::move(on_done),
                std::move(prefer));
    }

    /// One retrieve of `ns` from `node`, resuming from that node's cursor.
    static std::vector<std::byte> retrieve_body(
            core::Core& core, const network::service_node& node, config::Namespace ns) {
        return core._build_poll_body(node, {ns});
    }

    static void record_cursor(
            core::Core& core,
            const network::ed25519_pubkey& node,
            config::Namespace ns,
            std::span<const core::SwarmMessage> messages) {
        core._record_swarm_cursor(node, ns, messages);
    }
};

}  // namespace session::push::detail
