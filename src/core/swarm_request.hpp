#pragma once

/// Shared plumbing for requests a Core makes to a storage server swarm: which of them have to be
/// signed, what the signed value looks like, and how long one is allowed to take.
///
/// Internal to libsession: core and push include it.  It exists because more than one part talks to
/// a swarm -- polling, sending a message, pushing a config, fetching a message a push could not
/// carry -- and each of them needs the same answers.  Transcribing them separately is how one copy
/// ends up disagreeing with the storage server.

#include <array>
#include <chrono>
#include <cstdint>
#include <nlohmann/json_fwd.hpp>
#include <optional>
#include <session/config/namespaces.hpp>
#include <session/core/swarm_message.hpp>
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
    req.swarm_pubkey = swarm_pubkey;
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

// The namespaces an account's swarm is polled for.  Push subscriptions are derived from this too,
// so that a namespace added to the poll cannot be left out of them unnoticed.
//
// Order matters: the batch's results are handled in this order, so a namespace whose contents
// another one's depend on has to come first.  The configs lead because a message arriving in the
// same poll may be from a contact those configs are what tells us about; among themselves,
// ConvoInfoVolatile comes last because it refers to conversations that Contacts and UserGroups
// are what establish.
inline constexpr std::array POLL_NAMESPACES = {
        config::Namespace::UserProfile,
        config::Namespace::Contacts,
        config::Namespace::UserGroups,
        config::Namespace::ConvoInfoVolatile,
        config::Namespace::Default,
        config::Namespace::Devices,
        config::Namespace::AccountPubkeys};

// Ceiling on continuation rounds when retrieving from one node.  A well-behaved node exhausts a
// namespace in far fewer; this exists so that a node whose `more` never goes false cannot be asked
// indefinitely.
constexpr int POLL_MAX_ROUNDS = 20;

/// One namespace's slice of a batch retrieve response, decoded but not yet handled.
///
/// The decoded bytes are kept beside the messages because `SwarmMessage::data` spans into them:
/// the messages are only usable while this object is.
struct retrieved_namespace {
    std::vector<std::vector<std::byte>> data;
    std::vector<SwarmMessage> messages;
    /// The node says it is holding more past what it returned.  A retrieve is capped by the
    /// storage server, so this is how a namespace reports that one round did not exhaust it.
    bool more = false;
};

/// Decodes one result of a batch retrieve, or nothing where the node did not answer it.
///
/// **Nothing and an empty answer are different**, and the difference is load-bearing: a
/// namespace that failed or answered malformedly is not reported to its handler at all, while
/// one that answered with nothing is -- "we asked and there is nothing" is an answer, and some
/// handlers act on it.
///
/// Takes no node and touches no database, deliberately. Which node an answer came from matters
/// to whoever called: the retrieve cursor is kept per node and has to stay with the one that
/// produced it, and a decoder that knew about nodes is the shape in which one node's cursor
/// gets written from another node's response -- silently, because each node's cursor is
/// individually plausible.
std::optional<retrieved_namespace> decode_retrieved(const nlohmann::json& res, int16_t ns_val);

}  // namespace session::core
