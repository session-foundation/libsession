#pragma once

/// Shared plumbing for requests a Core makes to a storage server swarm: which of them have to be
/// signed, what the signed value looks like, and how long one is allowed to take.
///
/// Internal to the core library.  It exists because more than one part of Core talks to a swarm --
/// polling, sending a message, pushing a config -- and each of them needs the same three answers.
/// Transcribing them separately is how one copy ends up disagreeing with the storage server.

#include <chrono>
#include <cstdint>
#include <session/format.hpp>
#include <session/network/session_network_types.hpp>
#include <string>
#include <string_view>
#include <vector>

namespace session::core {

using namespace std::literals;
using namespace session::literals;

// Namespace access rules, mirrored from the storage server's oxenss/common/namespace.h.  The names
// match it deliberately: these decide whether a request we build has to be signed, and getting them
// out of step with the server is a 401 in production and nothing at all in testing.

// Namespaces anyone may store to, every one divisible by 10.  Namespace 0 is one, which is what
// makes it possible to be messaged by someone who does not have our keys.
constexpr bool is_public_inbox_namespace(int16_t ns) {
    return ns % 10 == 0;
}

// Namespaces anyone may retrieve from but only the owner may store to: the negative namespaces of
// the form -(20n+1), i.e. -1, -21, -41.  Storing implicitly replaces what is there.
constexpr bool is_public_outbox_namespace(int16_t ns) {
    return ns < 0 && -ns % 20 == 1;
}

// Deprecated legacy closed groups, which allow both unauthenticated store and retrieval.
constexpr int16_t LEGACY_CLOSED_NAMESPACE = -10;

constexpr bool retrieve_requires_auth(int16_t ns) {
    return !(ns == LEGACY_CLOSED_NAMESPACE || is_public_outbox_namespace(ns));
}

constexpr bool store_requires_auth(int16_t ns) {
    return !is_public_inbox_namespace(ns);
}

// The examples the storage server's own comments give, so a rule transcribed wrongly cannot build.
static_assert(
        is_public_inbox_namespace(0) && is_public_inbox_namespace(10) &&
        is_public_inbox_namespace(400) && is_public_inbox_namespace(-1230));
static_assert(
        !is_public_inbox_namespace(11) && !is_public_inbox_namespace(21) &&
        !is_public_inbox_namespace(-21));
static_assert(
        is_public_outbox_namespace(-1) && is_public_outbox_namespace(-21) &&
        is_public_outbox_namespace(-981));
static_assert(
        !is_public_outbox_namespace(1) && !is_public_outbox_namespace(21) &&
        !is_public_outbox_namespace(-20));

// The namespaces we actually use, spelled out: a DM is deposited unsigned in a stranger's inbox,
// while our own device, config and account-key namespaces are ours alone to write.
static_assert(!store_requires_auth(0) && retrieve_requires_auth(0));
static_assert(store_requires_auth(21) && retrieve_requires_auth(21));
static_assert(store_requires_auth(-21) && !retrieve_requires_auth(-21));
static_assert(!retrieve_requires_auth(LEGACY_CLOSED_NAMESPACE));
static_assert(store_requires_auth(2) && retrieve_requires_auth(2));
static_assert(store_requires_auth(5) && retrieve_requires_auth(5));

// How long one attempt at a swarm request gets, and how long the whole operation gets across every
// swarm member it tries.
//
// A node that has not answered in ten seconds is better abandoned than waited on: the swarm has
// several other members, and moving to one of them costs less than the rest of a long timeout, so
// the budget is better spent on several short attempts than on one patient one.
//
// The overall figure is what actually bounds the operation.  Without it, a swarm whose members are
// all unreachable would cost the per-request timeout once per member, which is the sort of
// arithmetic that only shows up in front of a user on a bad network.
constexpr auto SWARM_REQUEST_TIMEOUT = 10s;
constexpr auto SWARM_OVERALL_TIMEOUT = 60s;

// Builds a request sent to `node` *about* the account identified by `swarm_pubkey`.  Recording the
// swarm pubkey is what allows a 421 (the node is no longer in that account's swarm) to be recovered
// by re-resolving the swarm, and it is also what lets an unreachable node be replaced by the next
// member of the same swarm -- so it is bundled in here rather than left to each call site to
// remember.
inline network::Request swarm_request(
        const network::service_node& node,
        const network::x25519_pubkey& swarm_pubkey,
        std::string endpoint,
        std::vector<std::byte> body) {
    network::Request req{
            node,
            std::move(endpoint),
            std::move(body),
            network::RequestCategory::standard_small,
            SWARM_REQUEST_TIMEOUT};
    // A single entry: every Core request is about one account, including its batches, whose
    // sub-requests all address the same swarm
    req.swarm_pubkeys = {swarm_pubkey};
    req.overall_timeout = SWARM_OVERALL_TIMEOUT;
    return req;
}

// Builds the value a storage server signs for `endpoint` ("store", "retrieve", ...) against the
// given namespace and request timestamp.  The default namespace contributes nothing at all rather
// than a literal "0"; signing the 0 gets the request rejected with a 401.
inline std::string ns_signature_value(
        std::string_view endpoint, int16_t ns_val, int64_t timestamp_ms) {
    if (ns_val == 0)
        return "{}{}"_format(endpoint, timestamp_ms);
    return "{}{}{}"_format(endpoint, ns_val, timestamp_ms);
}

// The value signed for a `delete`, which is the odd one out: it covers the hashes being deleted and
// carries neither a namespace nor a timestamp, since the hashes it names are specific enough to
// stand alone.  Mirrors the storage server's delete_msgs documentation.
inline std::string delete_signature_value(std::span<const std::string> hashes) {
    std::string to_sign = "delete";
    for (const auto& h : hashes)
        to_sign += h;
    return to_sign;
}

}  // namespace session::core
