#pragma once
#include <functional>
#include <optional>
#include <session/config/namespaces.hpp>
#include <session/core/devices.hpp>
#include <session/core/message_encryption.hpp>
#include <session/core/swarm_message.hpp>
#include <session/util.hpp>
#include <span>
#include <string_view>
#include <vector>

namespace session::core {

class Core;

/// Where a contact's PFS/PQ keys stand on this device, by the rule the spec's "Account keys" sets
/// out: until the cache entry's expiry a send uses what the entry says, and past it the next send
/// or prefetch looks the keys up first.  Reported by `Core::pfs_key_info` and returned by
/// `Core::prefetch_pfs_keys`.
enum class PfsKeyState {
    /// No key held, and no lookup answering for now: never looked up, a lookup that found nothing
    /// longer ago than `Core::PFS_KEY_EMPTY_HOLD`, or one that failed.  A send looks up first and
    /// waits for the answer.
    none,
    /// A key held, within the entry's expiry: sends are PFS/PQ encrypted with it, with no lookup.
    usable,
    /// A key held, past the entry's expiry: the next send or prefetch looks up first, and the key
    /// is still used if the lookup brings no other -- after a failed lookup only within
    /// `Core::PFS_KEY_FAILED_GRACE` of `confirmed_at`, and after one that found nothing only within
    /// `Core::PFS_KEY_EMPTY_GRACE`.
    refresh_due,
    /// No key held, within the entry's expiry after a lookup that found none: sends use the
    /// non-PFS encryption until then, with no lookup.
    nak,
};

/// What `Core::pfs_key_info` reports of a contact's PFS/PQ keys.
///
/// - `checked_at` is when the last lookup of this contact's keys completed, whatever it found: a
///   key, nothing, or no answer at all because it failed.  With no key held it is what "checked
///   <time>, no PFS/PQ keys" reports.
/// - `confirmed_at` is the last time a lookup said this key is current: when it was fetched, or
///   when a later lookup found nothing while the key was recent enough that the account cannot
///   have replaced it (see `Core::PFS_KEY_EMPTY_GRACE`).  Set exactly when a key is held.
/// - `cache_expiry` is when the next lookup is due.
/// - `fetching` is whether a lookup of this contact is in flight, whatever started it: a prefetch,
///   a refetch, or a send waiting on the keys.
///
/// The times are unset when no lookup of the contact has completed.  They are stamped by Core's
/// clock (`session::clock_now`, which corrects for the network's offset from this machine's), so
/// compare them with that and never with `std::chrono::system_clock`: the two can differ by however
/// far off this machine's clock is.
struct PfsKeyInfo {
    PfsKeyState state = PfsKeyState::none;
    /// The keys held, which sends encrypt to as `state` says; unset when none are.
    std::optional<std::array<std::byte, 32>> x25519_pub;
    std::optional<std::array<std::byte, 1184>> mlkem768_pub;
    std::optional<std::chrono::sys_seconds> checked_at;
    std::optional<std::chrono::sys_seconds> confirmed_at;
    std::optional<std::chrono::sys_seconds> cache_expiry;
    bool fetching = false;
};

/// Result passed to the pfs_keys_fetched callback when a lookup of a contact's keys completes.
enum class PfsKeyFetch {
    new_key,    ///< A key was retrieved and stored (new or changed from the previous cache entry)
    unchanged,  ///< Keys were retrieved but match what was already cached
    not_found,  ///< The fetch succeeded but the remote account pubkey namespace held no valid keys
    failed,     ///< No answer: the request failed, or its response could not be read
};

/// Reason code passed to the message_decrypt_failed callback.
enum class MessageDecryptFailure {
    no_pfs_key,      ///< Version 2 message: no PFS account key matched the key indicator AND the
                     ///< non-PFS fallback decryption also failed; the message cannot be read.
    decrypt_failed,  ///< Decryption failed (either version); key was found but did not work
    bad_format,      ///< Message is structurally malformed (e.g. invalid bencode, truncated fields)
    unknown_version,  ///< Message starts with 0x00 but carries an unrecognised version byte;
                      ///< likely a future protocol version this build does not understand
};

/// A successfully decrypted one-to-one message from Namespace::Default.
struct ReceivedMessage {
    std::string hash;                  ///< Swarm-assigned message hash
    sys_ms timestamp;                  ///< Server-reported upload timestamp
    sys_ms expiry;                     ///< Server-reported expiry timestamp
    b33 sender_session_id;             ///< 0x05-prefixed sender session ID
    MessageEncryption encryption;      ///< What its envelope used
    std::vector<std::byte> content;    ///< Decrypted protobuf-encoded payload
    std::optional<b64> pro_signature;  ///< Session Pro signature, if present
};

/// Status of a send operation initiated by Core::send_dm().
enum class MessageSendStatus {
    awaiting_keys,   ///< Waiting for a PFS+PQ pubkey fetch to complete before encrypting.
    sending,         ///< Encryption complete; the store request has been dispatched.
    retrying,        ///< Still waiting for the recipient's keys after a lookup of them failed with
                     ///< no key held to fall back on: the lookup is retried with backoff (see
                     ///< `Core::PFS_FETCH_RETRY_FIRST`) for as long as the send waits.  A failed
                     ///< store is not retried, and goes directly to network_error.
    success,         ///< The store request was accepted by a swarm node.
    network_error,   ///< The swarm lookup or store request failed (terminal).
    no_network,      ///< No network object is attached.
    encrypt_failed,  ///< Encryption failed (should not normally happen).
};

/// What a device linking interface answers to: the requests other devices send this account, and
/// the account's devices themselves.
///
/// One interface rather than a handler each because they only work as a set.  A prompt opened by
/// `link_request_added` has to be closed by `link_request_ended`, or it goes on showing the SAS of
/// a request that has been replaced -- the substitution the SAS exists to catch -- so leaving any
/// of these out has to be a compile error, not a quiet gap.
///
/// Everything here is reported once the fetch that caused it has been merged in full, so a handler
/// never sees a half-applied state.  State to draw from initially is read the ordinary way, through
/// `Devices::membership()`, `Devices::devices()` and `Devices::incoming_link_requests()`; these
/// report what changes after.
///
/// Called on Core's event loop, so a method must not block.  One that throws is logged, and the
/// others are still called; what it was told is not told again.
class DeviceEvents {
  public:
    virtual ~DeviceEvents() = default;

    /// Another device asked to join the account's device group.  The request whole, so a prompt
    /// can be drawn from it without reading anything back.
    ///
    /// Once per request per session, and not at all for one the application has already been handed
    /// by `incoming_link_requests()` -- so an application that reads nothing at startup is still
    /// told of every request waiting, and one that does is not told twice.  Held back until the
    /// first fetch from the swarm has been merged, since a request stored before shutting down may
    /// have been accepted elsewhere or expired since.  Never for this device's own request.
    virtual void link_request_added(device::LinkRequest request) = 0;

    /// A request announced by `link_request_added` can no longer be answered, and whatever prompt
    /// was drawn for it should close.  Not for a request this device accepted or ignored itself,
    /// whose prompt closed when the user acted on it, nor on hearing afterwards that another device
    /// accepted that same request too.
    virtual void link_request_ended(int reqid, device::LinkRequestEnd why) = 0;

    /// The account's devices changed: one joined, was removed, or changed how it describes itself.
    /// The whole set, since one group message can change several at once: every device that is or
    /// was in the group.  Not the ones asking to join, which arrive as link requests instead.
    virtual void devices_replaced(device::map devices) = 0;

    /// Another device joined the group, or stopped being in it: removed, or left of its own accord.
    /// Its record as it now stands -- `state` says which (Registered, Kicked or Left), and `kicked`
    /// when it went.  For a notice ("Alice's laptop was added"); `devices_replaced` follows for
    /// redrawing the list.  Not for a change this device made itself through `accept_request` or
    /// `remove_device`, nor for the members of a group this device has just been admitted to.
    virtual void device_membership_changed(device::Info device) = 0;

    /// Where this device stands, or the groups it can see, changed -- or became known with the
    /// first fetch of this run; see device::Membership for what each value means.  So the same
    /// value can arrive twice: a `Dissolved` device is told again when the group it can join
    /// appears in `MembershipState::others`.  `Removed`, `Displaced`, `Dissolved`,
    /// `Dropped` and `Forked` are the ones to alert on, and arrive as soon as the fetch that
    /// reveals them is merged.  `Approved` is the one to bring up the confirmation on, wherever
    /// the user is.  Not for the move to `Requesting` that `Devices::request_link` makes, nor back
    /// from it when that call reports failure: the caller knows.  Never `Unknown`.
    virtual void membership_changed(device::Membership membership) = 0;
};

/// Struct holding application callbacks to fire when libsession Core events happen to allow the
/// Core object to fire into the application front-end.
///
/// The signatures say what a handler may keep.  A parameter taken by rvalue reference was read for
/// this delivery and nothing else holds it, so a handler may move from it; one taken by `const&` or
/// as a span is borrowed and valid only for the duration of the call.  A handler may declare an
/// rvalue parameter as `T&&`, `const T&` or `T`, whichever suits it: only the last constructs
/// anything, and a handler that just reads pays nothing.
struct callbacks {

    /// Device group and link request events; see DeviceEvents.  Null for an application with no
    /// device linking of its own to show.  Must outlive the Core.
    DeviceEvents* devices = nullptr;

    /// Callback invoked when a lookup of a contact's PFS/PQ keys completes, whatever started it: a
    /// prefetch, a refetch, a send waiting on the keys, or a retry of a lookup that failed.  Not
    /// invoked when the cache answered without one.
    ///
    /// Parameters:
    /// - session_id -- 33-byte session ID (0x05 prefix + X25519 pubkey) of the remote user
    /// - result -- the outcome of the fetch: new_key, unchanged, not_found, or failed
    std::function<void(std::span<const std::byte, 33> session_id, PfsKeyFetch result)>
            pfs_keys_fetched;

    /// Callback invoked when a one-to-one message from Namespace::Default is successfully
    /// decrypted.  The message is passed as an rvalue reference: the callback may move from it
    /// (e.g. to take ownership of the content vector) or simply read it in place.
    ///
    /// Parameters:
    /// - msg -- the decrypted message data
    std::function<void(ReceivedMessage&& msg)> message_received;

    /// Callback invoked when a one-to-one message from Namespace::Default could not be decrypted
    /// or parsed.  The raw swarm message and a reason code are provided so the caller can decide
    /// how to handle it (e.g. log, queue for retry, surface to the user).
    ///
    /// When receive_messages() is called directly by the application, `msg` is a reference to one
    /// of the SwarmMessage elements passed in, which the caller can identify exactly by comparing
    /// pointers.  When triggered by internal polling, `msg` refers to an internally-owned object.
    ///
    /// Parameters:
    /// - msg    -- the raw swarm message that could not be decrypted
    /// - reason -- why decryption failed
    std::function<void(const SwarmMessage& msg, MessageDecryptFailure reason)>
            message_decrypt_failed;

    /// Callback fired as a send operation initiated by Core::send_dm() progresses.  This is
    /// typically invoked multiple times for a single message — once or more for intermediate
    /// states (awaiting_keys, sending, retrying) followed by a terminal state (success,
    /// network_error, no_network, or encrypt_failed).
    ///
    /// Parameters:
    /// - message_id -- the value returned by the originating send_dm() call
    /// - status -- the current state of the send
    /// - swarm_hash -- the hash the swarm assigned the stored message, on `success` and when the
    ///   storage server reported one.  Unset for every other status.
    /// - encryption -- how the message was encrypted for the recipient it was sent to, on `sending`
    ///   (when that is decided) and on `success`.  Unset for every other status.
    std::function<void(
            int64_t message_id,
            MessageSendStatus status,
            std::optional<std::string_view> swarm_hash,
            std::optional<MessageEncryption> encryption)>
            message_send_status;

    /// Callback fired when merging config messages from the swarm changed one or more of the
    /// account's configs, so that the layer holding a queryable copy of that state knows to go and
    /// reconcile it.
    ///
    /// Fires once per batch of merges rather than once per config, with every namespace that
    /// changed: one poll can carry all four, and reacting to each in turn would show the
    /// application a half-applied state.  It fires *after* the changed configs have been dumped,
    /// so what a handler reads is already on disk.
    ///
    /// Only merges are reported.  A config the application changed itself is not news to it, and
    /// Local never appears at all, since it merges nothing.
    ///
    /// This says *that* something changed, not what.  There is deliberately no diff: a config diff
    /// describes a transition between config states, while the reconciling layer's own currency is
    /// not a config state and is not tracked -- a merge can jump several updates at once, and a
    /// crash between merging and reconciling leaves it behind by an unrecorded amount.  Comparing
    /// against its own stored state is what makes reconciliation self-correcting, and a diff would
    /// silently skip anything those cases had left behind.
    ///
    /// Parameters:
    /// - changed -- the namespaces whose configs the merge altered.  Valid only for the duration of
    ///   the call.
    std::function<void(std::span<const config::Namespace> changed)> configs_changed;

    /// Callback fired when the account's key outbox (namespace -21) -- where contacts find the key
    /// they encrypt PFS/PQ messages to -- holds a key that is not one of this account's.
    ///
    /// Only a holder of the account's seed can publish there, so it means someone other than the
    /// account's own devices has the seed: tell the user, as for a forged Displaced alert, that the
    /// recovery phrase is in someone else's hands (see the device groups guide).  Whether PFS/PQ is
    /// enabled or not: a seed holder publishing a key need not have enabled it, and contacts
    /// encrypt to whatever they find.  Where it is enabled, this device publishes the account's own
    /// key over it straight away, if it is a member of its group in good standing.  Nothing is ever
    /// deleted from -21, and the seed holder can publish again.
    ///
    /// Not decided on sight: a key another device of the account has just rotated to is in -21 a
    /// moment before its group message reaches this device, so a key not yet known is checked again
    /// after a fetch of the device group, and reported only if it is still unknown then.  May fire
    /// more than once for the same key, if it is seen again.
    ///
    /// Only on a device that is a member of its group in good standing (`InGroup` or `Forked`): one
    /// outside it holds none of the group's keys to compare against.  A device that becomes a
    /// member fetches -21 again from the start, so a key published before then is still judged.
    std::function<void()> rogue_account_key;
};

}  // namespace session::core
