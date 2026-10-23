#pragma once

#include <oxenc/bt_value.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <map>
#include <optional>
#include <oxen/quic/timer_id.hpp>
#include <session/clock.hpp>
#include <session/sodium_array.hpp>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "component.hpp"
#include "link_sas.hpp"
#include "swarm_message.hpp"

namespace oxenc {
class bt_dict_consumer;
}  // namespace oxenc

namespace session {
class TestHelper;
}  // namespace session

namespace session::core {

using namespace std::literals;

class Core;
class DeviceEvents;

namespace device {

    /// A device id: random bytes libsession generates for a device the first time it starts, and
    /// again whenever it takes a new identity.  Never chosen by the application.
    inline constexpr size_t ID_SIZE = 16;
    using Id = std::array<std::byte, ID_SIZE>;

    /// The protocol's cap on `Info::description`, in bytes.  Libsession cuts anything longer to it
    /// on a UTF-8 character boundary: in `update_info`, and in every record it reads from the
    /// swarm, so no description it holds or hands out is longer.
    inline constexpr size_t DESCRIPTION_MAX = 64;

    enum class Type {
        Unknown,
        Session_iOS,
        Session_Desktop,
        Session_Android,
        Session_CLI,
    };

    // The Type a stored or encoded type string denotes; Unknown for anything else, which a caller
    // keeps verbatim in `Info::other_device`.  The inverse of `Info::encoded_type()`.
    inline Type type_from_encoded(std::string_view t) {
        if (t == "i")
            return Type::Session_iOS;
        if (t == "a")
            return Type::Session_Android;
        if (t == "d")
            return Type::Session_Desktop;
        if (t == "c")
            return Type::Session_CLI;
        return Type::Unknown;
    }

    /// A device's membership of the account's device group.
    ///
    /// **The numbers are a rank, and merging depends on it.** State never goes on the wire — it is
    /// inferred from which message a record arrived in — so a state change moves no field that the
    /// record's seqno versions, and a merge guarded on the seqno alone would discard every one of
    /// them.  Records are therefore compared as `(state, seqno)` lexicographically, which is why
    /// these are ordered from least to most authoritative and why the stored integer *is* the rank.
    ///
    /// Rank only ever increases and the order is total, so a merged result is the maximum over
    /// everything received, regardless of the order it arrived in.
    enum class State {
        Unregistered = 0,  ///< Not in the group, and never was: local device info that cannot be
                           ///< pushed because this device has not joined one yet.  Says nothing
                           ///< about any other device, which is why a removal is `Kicked`.
        Pending = 1,       ///< A device with a pending link request.  This is used for two cases:
                      ///< - This device has sent a request to join the account's device group and
                      ///<   is awaiting acceptance by an existing device.
                      ///< - Another device has sent a link request that has been received but not
                      ///<   yet accepted or ignored by this device.
        Registered = 2,  ///< Device is in the account's registered device set.  Outranks Pending so
                         ///< that an acceptance propagates even against a newer link request, which
                         ///< is what lets registration complete at all.
        Left = 3,  ///< Left the group of its own accord, to join another.  As permanent as Kicked:
                   ///< the id can never rejoin this group.  Outranks Registered for the same
                   ///< reason Kicked does, and is outranked by it, so that a device that left and
                   ///< was then removed reads as removed everywhere.  A record in this state
                   ///< always has `Info::kicked` set to the time the device left.
        Kicked = 4,  ///< Removed from the group by another device, and permanently: a kicked device
                     ///< id can never rejoin, only be replaced by a fresh one.  Outranks
                     ///< everything, so the tombstone that carries a removal cannot be undone by a
                     ///< stale record replaying an earlier state.  A record in this state always
                     ///< has `Info::kicked` set to the time the device was removed; the schema
                     ///< enforces it.
    };

    /// What became of a link request this device saw.
    ///
    /// Expiry is not among these: a request is expired when it is still `Pending` and its deadline
    /// has passed, so there is nothing to keep in step with the timestamp that decides it.
    enum class LinkStatus {
        Pending = 0,     ///< Awaiting an answer, here or on another device.
        Accepted = 1,    ///< Admitted to the group, by us or by another device.
        Ignored = 2,     ///< Dismissed here.  Local and silent: nothing is sent, and another device
                         ///< can still accept the same request -- as can this one, while it is
                         ///< live.
        Superseded = 3,  ///< The same device asked again; the newer request is the live one.
    };

    /// Why a link request stopped being answerable, for whatever prompt was drawn for it.
    ///
    /// This device's own accept or ignore is not among them: the caller did that, and knows.
    enum class LinkRequestEnd {
        Accepted,    ///< Another device admitted it.
        Superseded,  ///< The requesting device asked again, and the new request replaces it.
        Expired,     ///< Its deadline passed unanswered; no device can accept it now.
    };

    // Value returned to indicate the push status of a device info or account keys update.
    enum class PushStatus {
        Synced = 0,      // We have pushed and confirmed (i.e. fetched the update)
        Pushed = 1,      // We have pushed, but not yet confirmed
        Pending = 2,     // We need to push, but haven't yet done so
        NotInGroup = 3,  // We are not in the device group and so can't push
    };

    struct Info {
        // Unique device id, in raw bytes.
        Id id;

        // Device seqno, which goes up whenever what a device publishes for itself changes: its
        // description, type, version or keys.  For this device, one more than the record the swarm
        // holds for it when what it would publish differs from that, and that record's otherwise.
        int64_t seqno;

        // Timestamp of the most recent update.
        std::chrono::sys_seconds timestamp;

        // The device type; one of the above enum values, or DevType::Unknown if the device type is
        // not one of the standard Session clients.
        Type type = device::Type::Unknown;

        // When device type is not one of the standard session clients, this will be set to a
        // free-form string indicating the device type.  Will be empty if no device type is provided
        // in the device info at all.  When DevType has a non-Unknown value, this will be
        // empty/ignored.
        std::string other_device;

        // Device-provided description of itself.  This could contain the OS type or version,
        // possibly a device nickname, but is generally free-form data, of at most
        // `DESCRIPTION_MAX` bytes.
        std::string description;

        // Indicates whether the device is registered, pending registration, or not registered.
        State state;

        // For State::Kicked, when the device was removed; for State::Left, when it left.  Unset in
        // every other state.  A removal restated against a device trying to re-add itself moves
        // this to the restatement, so it is the latest of those rather than the first.
        std::optional<std::chrono::sys_seconds> kicked;

        // Application version triplet as reported by the device.  The 2nd and 3rd values will
        // always be in [0, 999].  (If setting device info, they will be clamped if outside this
        // range).
        std::array<int, 3> version;

        // The current device-specific X25519 pubkey
        std::array<std::byte, 32> pk_x25519;

        // The current device-specific MLKEM-768 pubkey
        std::array<std::byte, 1184> pk_mlkem768;

        // Blake2b over this record as it was encoded, and the last term the merge compares.  Unset
        // for a record that never came off the wire, such as a tombstone for a device we never
        // knew: a stored NULL makes the comparison NULL at equal state and seqno, so such a row is
        // not displaced by an equal-ranked arrival.
        std::optional<std::array<std::byte, 8>> digest;

        // Fields from a device running a newer libsession than ours, kept so that we republish them
        // rather than silently dropping what we do not understand.
        //
        // Space for future versions of libsession, not for client data: everything here is carried
        // by every other device on the account, and the payload is padded in buckets sized on the
        // assumption that a record stays within its budget.  Anything added must fit it.
        oxenc::bt_dict extra;

        // Returns the encoded device type string: "i", "a", or "d" for the standard Session
        // client types, `other_device` for unknown types, or "" if unknown with no other_device.
        std::string_view encoded_type() const {
            switch (type) {
                case Type::Session_iOS: return "i";
                case Type::Session_Android: return "a";
                case Type::Session_Desktop: return "d";
                case Type::Session_CLI: return "c";
                default: return other_device;
            }
        }

        // Returns true if the user-settable fields (those controlled by update_info()) are equal to
        // the corresponding fields in `other`.  Does NOT compare id, seqno, timestamp, state, pk_*,
        // or kicked.  The unknown `extra` fields are included in the comparison.
        bool same_user_fields(const Info& other) const;
    };

    using map = std::map<Id, Info>;

    /// A link request this device saw, and what became of it.
    ///
    /// Read rather than cached: a request can be superseded, accepted elsewhere, or expire between
    /// one draw and the next, and the SAS shown to a user must always belong to the record
    /// currently stored.  Holding one of these across a redraw is how a user ends up comparing
    /// emoji against a request that has since been replaced.
    struct LinkRequest {
        /// Identifies this request to `accept_request` and friends.
        ///
        /// Valid only within this Core session: it comes from a counter rather than the database,
        /// and a later run gives the same request a different one.  Never persist it.
        int id;

        /// The requesting device, as it described itself.
        Info device;

        /// Set when the requesting device's id is already in the group: its record as it stands
        /// now, which accepting the request replaces with `device`.  The user must be told so
        /// before they accept.  This is how a device that lost track of having joined -- restored
        /// from a backup, say -- gets back in: it confirms the SAS like any new device, and the
        /// group moves to new keys.
        std::optional<Info> replaces;

        /// The emoji to compare against what the requesting device is showing, by their indices
        /// into the SAS table (see `sas_emoji`).  The first 7 are the standard display; all 21 are
        /// there for an extended view.
        Sas sas;

        /// When we stored it, and when the swarm drops the message it arrived in.  The deadline is
        /// the swarm's rather than ours: past it the message cannot be fetched, so no device can
        /// accept the request at all.
        std::chrono::sys_seconds received;
        std::chrono::sys_seconds expires;

        LinkStatus status;

        /// True once an unanswered request is past its deadline.  Derived rather than stored, so it
        /// cannot disagree with the timestamp it comes from.
        bool expired(std::chrono::system_clock::time_point now) const {
            return status == LinkStatus::Pending && expires <= now;
        }
    };

    /// A device group's identifier (see "Group identifier" in docs/protocol-v2.md).  Fixed when the
    /// group is created, and what devices compare to tell one of an account's groups from another.
    struct GroupId {
        std::array<std::byte, 8> value;

        /// When the group was created, by the creating device's clock.
        std::chrono::sys_time<std::chrono::minutes> created() const;

        /// The emoji a user compares to check that two devices are in the same group, by their
        /// indices into the SAS table (see `sas_emoji`).  The suggested basic display is the first
        /// 4 beside `created()`; all 21 are for an extended view.  Not a security check: anyone
        /// holding the account seed can copy an identifier.
        Sas sas() const;

        bool operator==(const GroupId&) const = default;
    };

    /// Where this device stands with respect to the account's device groups.  An ongoing state
    /// rather than a step in setup: it is re-evaluated on every fetch, and any of these can recur.
    enum class Membership {
        /// Not yet known: no fetch from the swarm has completed since this Core started, and what
        /// the swarm holds decides every other value.
        Unknown,
        /// In a group, and the only group in the swarm.
        InGroup,
        /// Not in a group, and no group is in the swarm.  Either the account never had one, or
        /// every device was offline long enough for it to expire, and the two cannot be told apart
        /// -- so starting one is the user's decision.
        NoGroup,
        /// Not in a group, and one or more groups it cannot read are in the swarm: it may ask to
        /// join one, or start its own instead, which dissolves them.
        DeviceGroupVisible,
        /// This device's own link request is out, for another device of the group to approve
        /// before it lapses; see `outgoing_link_request`.  Nothing to confirm yet: `confirm_link`
        /// answers false.
        Requesting,
        /// Another device approved this one's request, and the admission waits for the user to
        /// confirm, through `confirm_link`, that the emoji match what that device showed.  It no
        /// longer lapses.
        Approved,
        /// Removed from its group by another device.  It can come back only under a new device id,
        /// which `request_link` and `start_device_group` take for it.
        Removed,
        /// Its group has moved on without it: a newer message from the group is one it cannot read,
        /// whose removals show that nothing removed it.  Another device holds its place under its
        /// id -- a restored copy of it, admitted as a replacement, or someone holding a copy of its
        /// data who has rotated it out -- or a holder of the account seed has forged that message
        /// to make it look so; the last two are attacks.  Shown so it cannot be missed, and kept
        /// as a warning once dismissed.  It can come back only under a new device id, which
        /// `request_link` and `start_device_group` take for it.
        Displaced,
        /// Its group was dissolved: the user of another of the account's devices kept another group
        /// over it.  What it held of the group is forgotten and it has a new device id; it rejoins
        /// by asking to join the group that was kept, as any device outside a group does, and stays
        /// Dissolved until it joins a group or starts one.
        Dissolved,
        /// In a group whose messages are in the swarm, while another group's are too and no
        /// tombstone names this one: the account has forked, and an account can have only one
        /// group.  Nothing is wrong with this group, which goes on working; the user decides, here
        /// or on another device, whether to keep it, dissolving the others
        /// (`Devices::dissolve_group`), to leave it for another (`Devices::leave_group`, then
        /// `Devices::request_link`), or to start over, dissolving both
        /// (`Devices::start_device_group`).
        Forked,
        /// No longer in a device group: its group is gone from the swarm while another group is
        /// there, or has moved on to keys it does not hold without showing why.  It was removed,
        /// replaced, or away too long, and cannot tell which -- it may itself have been dissolved.
        /// It pushes nothing, acts for the group in nothing, and dissolves nothing new; it can come
        /// back only under a new device id, which `request_link` and `start_device_group` take for
        /// it.
        Dropped,
    };

    /// A device group in the swarm that this device could ask to join.
    struct VisibleGroup {
        GroupId id;
        std::chrono::sys_seconds last_seen;  ///< When its newest message was written, by the
                                             ///< clock of the device that wrote it: when the
                                             ///< group was last active.
    };

    struct MembershipState {
        Membership membership;
        /// This device's group, while it is a member in good standing: `InGroup` or `Forked`.
        std::optional<GroupId> group;
        /// Every group in the swarm this device could ask to join, newest first: every one but
        /// `group`.  For a device `Removed`, `Displaced` or `Dropped`, that includes the group it
        /// was in, while that group is still in the swarm, since asking under a new identity is
        /// the way back into it.
        std::vector<VisibleGroup> others;
    };

    struct decryption_failed : std::runtime_error {
        using std::runtime_error::runtime_error;
    };
};  // namespace device

class Devices final : detail::CoreComponent {
  public:
  private:
    friend class Core;
    friend class Globals;
    friend class session::TestHelper;
    explicit Devices(Core& c) : detail::CoreComponent{c} {}

    void init() override;

    // Guards against a second push being built before the first is confirmed; see
    // push_owed().  `_alive` is what a push callback checks before touching us, since it
    // returns on the network's thread and this component does not outlive its Core.
    bool _push_in_flight = false;
    std::shared_ptr<int> _alive = std::make_shared<int>(0);

    // The `device_pending_pushes` rows sent and not yet answered, so a fetch completing meanwhile
    // does not send them a second time.
    std::unordered_set<int64_t> _pending_in_flight;

    // The ids handed out for link requests this session, both ways round.  Issued from a counter
    // rather than exposing the row id, so that nothing can take one for something that survives a
    // restart.  Loop-only, like everything that reaches them.
    int _next_reqid = 1;
    std::unordered_map<int64_t, int> _reqid_by_row;
    std::unordered_map<int, int64_t> _row_by_reqid;

    int _reqid_for(int64_t row);
    std::optional<int64_t> _row_for(int reqid);

    // What `callbacks::devices` has been told, so that `_flush_events()` reports each change once.
    //
    // A request has been handed out once it has an id, whichever way the application came by it,
    // and `_ended` holds the ones since closed: reported closed, or closed by this device itself,
    // which the caller does not need telling about.
    bool _devices_changed = false;
    // Other devices admitted, removed or departed since the last flush, for
    // `device_membership_changed`.
    std::vector<device::Id> _member_changes;
    bool _fetched = false;
    device::Membership _reported_membership = device::Membership::Unknown;
    // The ids in `others` as last reported, sorted: their `last_seen` moves with every message, so
    // only which groups are there counts as a change.
    std::vector<device::GroupId> _reported_others;
    std::unordered_set<int64_t> _ended;

    // Fires a flush at the earliest deadline among our own request and those handed out and still
    // open, so each lapses when it expires rather than at whichever fetch next completes -- which
    // could be an application-chosen interval away, or never while the network is down.
    quic::TimerID _expiry_timer;

    // Fetches the group on our own account: when a key rotation falls due, and when a push that
    // failed is due another try.  A device subscribed for pushes stops polling, so without this a
    // quiet swarm would never prompt the fetch either one waits on.  What follows is the fetch's to
    // do, as after any other: rotating (see `_rotate_due_keys`), and pushing what is owed.
    quic::TimerID _fetch_timer;

    // When a push that was not stored is next to be tried, by a fetch of our own; unset while
    // nothing failed, and from the moment a fetch completes, since what follows it is that try.
    std::optional<sys_ms> _push_retry_at;
    // How long the next failure waits: `PUSH_RETRY_FIRST`, doubling to `PUSH_RETRY_MAX`, and back
    // to the first on any push the swarm confirms.
    std::chrono::milliseconds _push_backoff = PUSH_RETRY_FIRST;

    // Lapses our own request if its deadline has passed, reports what changed through
    // `callbacks::devices`, and re-arms the expiry timer.  Run once a fetch has been merged and at
    // the end of each call here that changes something, never partway through, so a handler never
    // sees a half-applied state.
    void _flush_events();

    // The reporting half, for when there is someone to report to.  Answers the earliest deadline
    // among the requests it has handed out and are still open.
    std::optional<std::chrono::sys_seconds> _report_events(
            DeviceEvents& events,
            bool devices_changed,
            std::span<const device::Id> member_changes,
            std::chrono::sys_seconds now);

    // Reads link requests with the device each came from.  `pending_only` restricts to those still
    // awaiting an answer and not yet past their deadline.
    std::vector<device::LinkRequest> _link_requests(bool pending_only);

    // The same read without handing anything out: each request beside its row, with `id` unset.
    // What `_flush_events()` uses to tell a request the application has not seen yet from one it
    // has, since having an id is what having seen it means.
    std::vector<std::pair<int64_t, device::LinkRequest>> _read_link_requests(bool pending_only);

    // This device's group's identifier: nullopt outside a group.
    std::optional<device::GroupId> _group_id();
    void _set_group_id(const device::GroupId& id);

    // The identifier a group message carries, which needs only the account seed to read.
    device::GroupId _group_of(std::span<const std::byte> message);

    // Notes a group message in `device_groups`, and its hash in `device_group_messages`, whether or
    // not we can read it, answering whether to take it in any further.  Not for a group we know to
    // be dissolved, unless the message is newer than the dissolution and we are in no group to
    // decide for: a member deletes it from the swarm instead, and publishes the dissolution again
    // if it is newer.  Throws, so that it is not taken in either, on a bad signature and on a
    // signed time too far ahead (see `_signed_time`).
    bool _record_group(const SwarmMessage& msg);

    // Checks that the namespace-21 message `in` is reading was signed by the account, throwing if
    // not.  `what` names it in the error.
    void _verify_account_signature(oxenc::bt_dict_consumer& in, std::string_view what);

    // The signed time `t` of the message `in` is reading, once its signature is checked.  Throws
    // for a time further ahead of our clock than GROUP_MESSAGE_MAX_AHEAD.
    sys_ms _signed_time(oxenc::bt_dict_consumer& in, std::string_view what);

    // When `group` was dissolved, as the newest tombstone we have seen or published says; nullopt
    // for a group not dissolved.
    std::optional<sys_ms> _dissolved_at(const device::GroupId& group);

    // Remembers `group` as dissolved at `t`, and stops counting it among the groups in the swarm.
    void _mark_dissolved(const device::GroupId& group, sys_ms t);

    // A tombstone ("T") naming `groups`, signed at `t`; see "Dissolving a group".
    std::vector<std::byte> _build_dissolution(std::span<const device::GroupId> groups, sys_ms t);

    // Dissolves `groups`, none of them ours: deletes from the swarm every message of theirs we know
    // of, and `obsolete` with them, publishes a tombstone naming them, and remembers them as
    // dissolved.  The deletions and the tombstone go out through `_queue_push`, so without a
    // network they wait for one.
    void _dissolve(std::span<const device::GroupId> groups, std::vector<std::string> obsolete = {});

    // What `_dissolve` commits, inside the caller's transaction and sending nothing: also how a
    // sole member leaving dissolves its own group.
    void _queue_dissolution(
            std::span<const device::GroupId> groups, std::vector<std::string> obsolete);

    // Dissolves every group in the swarm but `kept`, which the user has chosen: by starting it, or
    // by completing a join to it.
    void _dissolve_all_but(const device::GroupId& kept);

    // Records the account keys `keys` (device_account_keys ids) as delivered to `devices`, by a
    // payload carrying them that was encrypted to them.  A key deleted since is skipped.
    void _record_key_delivery(std::span<const int64_t> keys, std::span<const device::Id> devices);

    // The devices account key `key` has been delivered to; see `device_account_key_recipients`.
    std::vector<device::Id> _key_recipients(int64_t key);

    // Whether account key `key` was delivered to a device that is no longer in the group, removed
    // or departed, which can therefore still use it; `ours` narrows that to one this device
    // removed.
    bool _key_held_outside(int64_t key, bool ours = false);

    // When the current account key, `key`, is to be replaced early for having reached a device no
    // longer in the group: at once by the device that removed it, and at a jittered moment within
    // KEY_ROTATION_JITTER by every other.  Recorded when first seen, so that it holds still across
    // fetches and restarts, and dropped as soon as the current key is one no such device holds --
    // a rotation by anyone stands it down.  Nullopt if there is no reason to.
    std::optional<sys_ms> _early_account_rotation(int64_t key);

    // Discards the account keys rotated away more than ACCOUNT_KEY_RETENTION ago.
    void _prune_account_keys();

    // What every device's account key rotation slot is reckoned from: the active key, and the
    // devices of the group.  Nullopt for a device that is not a member in good standing, or with
    // no active key.
    struct RotationBasis {
        int64_t key_id;
        std::chrono::sys_seconds created;
        cleared_b32 seed;
        std::vector<device::Id> registered;
    };
    std::optional<RotationBasis> _rotation_basis();

    // When `device`'s turn to rotate the account key falls, by the spec's "Account Key Rotation
    // timer": the same on every device that computes it from the same basis.
    std::chrono::system_clock::time_point _rotation_slot(
            const RotationBasis& basis, const device::Id& device);

    // Brings our next device key rotation forward to within KEY_ROTATION_JITTER, unless it is due
    // sooner already: on a removal, so that what the removed device knows of our keys goes stale.
    void _pull_in_device_rotation();

    // Deletes `hashes` from the swarm, once and without reporting back; `what` names them in logs.
    void _delete_from_swarm(std::vector<std::string> hashes, std::string_view what);

    // Records a push that must go out whatever this device forgets meanwhile -- `message` to
    // store, if any, and `obsolete` to delete -- in `device_pending_pushes`, inside the caller's
    // transaction.  Nothing is recorded with nothing to send.
    void _queue_push(
            std::optional<std::vector<std::byte>> message, std::vector<std::string> obsolete);

    // Sends what `device_pending_pushes` holds, each row deleted once the swarm confirms it, and
    // drops those too old to matter.  Run when something is queued and after every fetch, so a
    // push that fails, or was queued before a restart, goes again.
    void _send_pending_pushes();

    // Processes a tombstone ("T") message.  One naming our group dissolves this device out of it.
    void receive_dissolution(std::span<const std::byte> data);

    // Records that this account owes a device group, for `establish_group()` to act on.  Called by
    // Globals when it generates an account, which is before this component has initialised -- hence
    // a stored flag rather than doing the work there.
    void _mark_group_owed();

    device::Id self_id;

    // Encrypts the inner device data for all the members of the device group.
    std::vector<std::byte> encrypt_device_data(const device::map& devices);

    // The group message carrying `payload`: encrypted to the live devices among `records` -- the
    // records it carries -- announcing the removals among them in `kicked`, and publishing
    // `link_x25519` as the group's link key.  What `encrypt_device_data` does once the payload is
    // built.
    std::vector<std::byte> _encrypt_group_payload(
            std::span<const device::Info* const> records,
            const std::array<std::byte, 32>& link_x25519,
            std::string payload);

    // Processes a single incoming device group ("G") message.  `data` is the full raw message bytes
    // including the outer bt-dict wrapper with the "" type key.
    //
    // The group message takes the swarm hash as well, because merging one is what makes it
    // redundant: our next push carries its contents forward, and that is when it can be deleted.
    // Recorded only on a message we could decrypt -- see `device_group_merged`.
    //
    // An admission on our own request is held for the user's confirmation rather than taken, unless
    // `confirmed`: the held admission, handed back by `confirm_link`.
    void receive_device_group_message(
            std::span<const std::byte> data, const std::string& hash, bool confirmed = false);

    // In the group and able to act for it: registered, neither displaced from it nor dropped.
    bool _member();
    // Registered in a group and not displaced from it, though perhaps dropped: placed to tell what
    // it has seen -- a dissolution, or how it lost its group -- but not to act for the group.
    bool _registered();
    bool _displaced();

    // A message from our own group, signed at `t`, was one we could read.
    void _note_read(sys_ms t);

    // The link request takes the swarm's expiry, which is what bounds the request: it is when the
    // message stops being fetchable, so after it no device can accept the request at all.  And its
    // hash, which is what ignoring it can delete it from the swarm by.
    void receive_link_request(
            std::span<const std::byte> data, const std::string& hash, sys_ms expiry);

    // Handlers for incoming swarm messages by namespace, called from Core::receive_messages.
    void parse_device_messages(std::span<const SwarmMessage> messages, bool is_final);
    void parse_account_pubkeys(std::span<const SwarmMessage> messages, bool is_final);

    // Decrypts an incoming encrypted device group ("G") message, returning the bt-encoded group
    // payload plaintext (a bt-dict containing at minimum a "D" devices subdict and optionally a
    // "K" account keys list).  Throws if parsing or decryption fails.  Throws
    // `device::decryption_failed` if we could not find a key that successfully decrypts the data
    // (i.e. we are not in the device group, or all our keys have rotated past this message).
    std::vector<std::byte> decrypt_device_data(std::span<const std::byte> data);

    // What both public forms of each dispatch onto the loop, and what the rest of this class
    // calls internally, since it is already there.  Each asserts it got there.
    std::pair<device::Info, bool> _device_info();
    void _update_info(device::Info info);

    // What this device describes itself as, from its master copy (see `own_info_key`): every field
    // but the id, seqno, timestamp, state and keys.
    device::Info _described();

    // Our own row in `devices`: what the swarm holds for us, as far as we know.  Never what we
    // publish from, only what we publish against.
    std::optional<device::Info> _held_record();

    // The record we publish for ourselves: what we describe ourselves as, under our current keys.
    // The held record itself if it already says that; otherwise one past its seqno, stamped now.
    device::Info _own_record();

  public:
    // Returns the current device's random identifier, in hex.
    std::string device_id() const;

    // Returns info for all registered and/or pending devices and/or unregistered devices for this
    // account.  If `only_device` is non-empty it must be a device id, and filters the results to
    // just that one device.
    device::map devices(
            bool include_registered = true,
            bool include_pending = false,
            bool include_unregistered = false,
            std::span<const std::byte> only_device = {});

    // Returns *this* device's info and whether it is registered in the device group.
    //
    // Reads the device config, which the loop merges into, so it happens on the loop either way:
    // code already there uses the `await` form and pays nothing for it.
    void device_info(result_function<std::pair<device::Info, bool>> cb);
    std::pair<device::Info, bool> device_info(await_t);

    /// This device's own link request, as the waiting screen shows it.
    struct OutgoingLinkRequest {
        /// The emoji the user compares against what the accepting device shows, by their indices
        /// into the SAS table (see `sas_emoji`); the first 7 are the standard display.
        Sas sas;

        /// When the request lapses unapproved, for the countdown while `Requesting`.  After it no
        /// device can approve it, and asking again is the only way in.  Meaningless once
        /// `Approved`: the approval came in time, even if the message carrying it reached this
        /// device later.
        std::chrono::sys_seconds expires;
    };

    // Asks the devices of the group `group` to admit this one: fetches the group from the swarm,
    // uploads a link request for them to approve, and answers once the swarm has stored it,
    // leaving the device `Requesting`.  The request is encrypted to that group as the fetch finds
    // it, so that only its members can read it; the group must be one this device has seen in the
    // swarm, and still be there.  The account must already be restored here, and the device not in
    // a group: an account has only one, so there is no switching from one to another, only
    // `leave_group` and then asking.  A device `Removed`, `Displaced` or `Dropped` asks as a new
    // device: it takes a new device id, forgetting the group it is no longer in, as part of this
    // call.
    //
    // There is no cancelling: the request lives in the swarm until `expires`, across restarts,
    // whatever the application shows meanwhile.  Asking again for the same group while it does --
    // `Requesting` or `Approved` -- answers with that same request, emoji and deadline, and uploads
    // nothing.  Once another device approves it the device is `Approved`, and joins when its user
    // confirms the emoji through `confirm_link`; or, if `expires` passes first, it hears
    // `membership_changed` with what it sees instead.
    //
    // Fails with `err::already_registered` for a device in a group, `err::network_unavailable`
    // with no network or none that reached the swarm for the fetch, `err::unknown_group` for a
    // group the fetch does not find, or `err::store_failed` -- the last two worth retrying.  None
    // of them leaves a request outstanding, and none but the last comes after a new device id was
    // taken.
    void request_link(device::GroupId group, result_function<OutgoingLinkRequest> cb);

    // The request `request_link` made, while it is still waiting: stored by the swarm and not past
    // its deadline (`Requesting`), or approved and waiting for the user to confirm it
    // (`Approved`), whatever the deadline.  Nothing otherwise -- including while the upload is
    // still in flight, when there is nothing another device could approve yet.
    //
    // What a waiting screen is drawn from, each time it is drawn or reopened, and what to read
    // again on `membership_changed`.  Survives a restart for as long as the request itself does,
    // since the swarm's copy stays acceptable until its deadline either way.
    void outgoing_link_request(result_function<std::optional<OutgoingLinkRequest>> cb);
    std::optional<OutgoingLinkRequest> outgoing_link_request(await_t);

    // The user's confirmation, on this device, that its SAS matches the one the approving device
    // showed, which joins it to the group: `Approved` to `InGroup`.  Being able to read the group
    // message admitting it is not enough on its own, since anyone holding the account seed can
    // publish a group of its own with a link key of its own, and admit into it a device that
    // encrypted its request there.  The real group can read no such request, and so never prompts
    // for it, which is what makes the user's confirmation mean something.  See "Confirmation on
    // the requesting device".
    //
    // Only after the approval, never before: confirming ahead of it would authorise whatever
    // admission came next.  An admission is held only for the request the user is being shown,
    // matched by the record it admitted; one on an earlier request, or matching none of this
    // device's, is ignored.
    //
    // Answers false unless `Approved`.
    void confirm_link(result_function<bool> cb);
    bool confirm_link(await_t);

    // Every link request this device has seen, newest first: pending, answered, superseded and
    // expired alike.  For a history view.
    //
    // `device` is the record each request asked to have admitted, so a device that asked twice
    // appears in each row as it described itself that time.  `replaces`, by contrast, is the
    // record as it stands now.
    //
    // These and the calls below read and write the device tables and hand out request ids, all of
    // which the loop owns, so they happen there either way.
    void link_requests(result_function<std::vector<device::LinkRequest>> cb);
    std::vector<device::LinkRequest> link_requests(await_t);

    // The link requests still awaiting an answer: pending and not yet past their deadline.  What a
    // prompt is drawn from, and meant to be asked for each time one is drawn, since a request can
    // be superseded or answered elsewhere between two draws.
    void incoming_link_requests(result_function<std::vector<device::LinkRequest>> cb);
    std::vector<device::LinkRequest> incoming_link_requests(await_t);

    // Admits the requesting device to the group.  The acceptance reaches the other devices with the
    // next group push, which follows a fetch this call asks for at once.
    //
    // For a request that `replaces` a device, the requesting device's record takes the place of the
    // one held, and the account key is rotated: a copy of the device as it was, still holding the
    // replaced record's keys, must not read what comes after.
    //
    // A request this device ignored can still be accepted while it is live: ignoring is local, and
    // this is how an Ignore pressed by mistake is put right.
    //
    // Answers false if the request can no longer be accepted: accepted here or elsewhere,
    // superseded by a newer request from the same device, past its deadline, or this device is no
    // longer in the group itself.  None of those is an error -- each can happen between a prompt
    // being drawn and the user answering it.  An id this session never handed out is an error
    // (std::invalid_argument).
    void accept_request(int reqid, result_function<bool> cb);
    bool accept_request(int reqid, await_t);

    // Dismisses a request here.  Answers false if it was no longer pending.  An id this session
    // never handed out is an error (std::invalid_argument).
    //
    // By default local and silent: nothing is sent, and another device may still accept it -- the
    // ordinary case of a request being answered on a different device.  This one may too: ignoring
    // is undone by `accept_request` for as long as the request is live.  Either way the requesting
    // device is told nothing, and waits until its deadline unless some device accepts it.
    //
    // With `delete_from_swarm`, for a request the user does not recognise, it is also deleted from
    // the swarm, so that a device yet to fetch it never sees it.  A device that has already fetched
    // it is not told, and can still accept it until it expires -- this one included, since its
    // record of the request is kept.  The deletion is attempted once, and not reported on.
    void ignore_request(int reqid, result_function<bool> cb);
    void ignore_request(int reqid, bool delete_from_swarm, result_function<bool> cb);
    bool ignore_request(int reqid, await_t);
    bool ignore_request(int reqid, bool delete_from_swarm, await_t);

    // Removes link requests from the log, for a user tidying up ones already dealt with.  Answers
    // how many were removed.
    //
    // A request still awaiting an answer is never removed, named or not: dismissing one is
    // `ignore_request`, and a list the user acted on may have been drawn before it arrived.  Ids
    // this session never handed out are skipped.
    void forget_link_requests(std::vector<int> reqids, result_function<size_t> cb);
    size_t forget_link_requests(std::span<const int> reqids, await_t);

    // Removes a device from the group, permanently: its id can never rejoin.  The account key
    // rotates in the same step, so that the device does not hold the current one, and it is given
    // no key to anything the group pushes from here on; this device's own keys rotate within
    // KEY_ROTATION_JITTER, as every member's do on learning of it.  The removal reaches the other
    // devices -- and, through the `kicked` list, the removed device itself -- with the next group
    // push, which follows a fetch this call asks for at once.
    //
    // Answers false if the device is not in the group -- unknown, still only asking to join (which
    // is `ignore_request`), or already gone -- or this device is no longer in it either.  None of
    // those is an error: each can happen between a device list being drawn and the user acting on
    // it.  Passing this device's own id is an error (std::invalid_argument): a device leaves
    // through `leave_group`.
    void remove_device(device::Id id, result_function<bool> cb);
    bool remove_device(std::span<const std::byte, device::ID_SIZE> id, await_t);

    // Where this device stands, and which groups in the swarm it could ask to join.  What an
    // application prompts from at startup and draws its device screen from; read again on
    // `membership_changed`.  `Unknown` until the first fetch of this run completes, since the swarm
    // may have changed while it was down.
    void membership(result_function<device::MembershipState> cb);
    device::MembershipState membership(await_t);

    // Starts over from this device: a new device group with this device as its only member, and
    // answers its identifier.  From any state but `Unknown`.  Every group in view is dissolved,
    // since an account has only one and the user starting another is choosing it over all of them:
    // their messages are deleted from the swarm, one tombstone names them all, and each is
    // remembered as dissolved.  Their devices learn of it from the tombstone, become `Dissolved`,
    // and have to ask to join the new group.  A device that was in a group, whether a member or
    // `Removed`, `Displaced` or `Dropped` from it, leaves it as any leaving does, taking a new
    // device id and device keys.  A device `Requesting` or `Approved` withdraws its request.  The
    // group starts with a newly generated account key, whatever the device held before.
    //
    // `replacing` is the groups the user confirmed replacing: what `membership()` listed, its
    // `group` and its `others`, as shown to them -- empty when it listed none.  Only those are
    // dissolved.  If a group in view now is not among them -- one that appeared after the user was
    // shown the list -- nothing at all is done and the call fails with `err::groups_changed`, for
    // the application to show the list again.  One in `replacing` no longer in view, lapsed or
    // dissolved meanwhile, is gone either way, and is ignored.
    //
    // The dissolution, the new identity and the start are committed together; the tombstone goes
    // out as a leave's departure does, retried after fetches and across restarts, and is not
    // reported on.
    //
    // Fails with `err::membership_unknown` before the first fetch of this run, before anything
    // else: starting a group is the user's decision, made from what the swarm holds.
    void start_device_group(
            std::vector<device::GroupId> replacing, result_function<device::GroupId> cb);
    device::GroupId start_device_group(std::vector<device::GroupId> replacing, await_t);

    // Keeps this device's group over another in the swarm, which the user has chosen to do from
    // `Forked`: deletes the other's messages from the swarm, publishes a tombstone naming it, and
    // remembers it as dissolved.  Its devices learn of it from the tombstone, or, back after that
    // has expired, from this device or another of ours seeing their group again.  See "One group
    // per account".
    //
    // Answers false unless `Forked` with `group` among the groups visible: the swarm can change
    // between the choice being drawn and made.  Passing this device's own group is an error
    // (std::invalid_argument).
    void dissolve_group(device::GroupId group, result_function<bool> cb);
    bool dissolve_group(const device::GroupId& group, await_t);

    // Leaves this device's group, which it then forgets -- its devices, its account keys and its
    // identifier -- leaving the device `NoGroup` or `DeviceGroupVisible`.  For logging out or
    // clearing the device's data, and for a `Forked` device whose user chooses the other group:
    // leave, then `request_link` to it.  See "Leaving a group".
    //
    // A member in good standing tells its group: a departure is pushed to the other members, so
    // that they stop encrypting to it and move to an account key it does not hold; or, if it had no
    // other, the group is dissolved -- its messages deleted and a tombstone published, so that the
    // devices of any other group on the account stop seeing it as a fork.  That push is stored,
    // complete, in the same commit that forgets the group, and kept until the swarm confirms it:
    // attempted at once, and again after every fetch while the application runs, across restarts
    // too.  Not reported on.  An application clearing its data wipes the database with it, and so
    // gets whatever the first attempt achieved.  A device removed, displaced, dropped or dissolved
    // has nothing it may say to its group, and only forgets it.
    //
    // Leaving, the device takes a new device id and new device keys: the group it left holds the
    // old id as departed, and the new one can ask to join any group, that one included, as a new
    // device.  Answers false for a device in no group to leave.
    void leave_group(result_function<bool> cb);
    bool leave_group(await_t);

  private:
    bool _remove_device(std::span<const std::byte, device::ID_SIZE> id);
    device::MembershipState _membership();
    device::GroupId _start_device_group(const std::vector<device::GroupId>& replacing);

    // Removed from its group, displaced from it, or dropped (see Membership::Dropped): still
    // holding the group, but no longer in it.
    bool _cast_out();

    // Forgets everything of the group this device was in: its devices, its messages, its account
    // keys and its identifier.
    void _forget_group();

    // Forgets the group and our requests, and replaces our device id and device keys with new ones:
    // what leaving a group, for whatever reason, always does.
    void _new_identity();

    // `_new_identity` in halves, for a caller with more to commit along with it.  The first is the
    // database half, inside the caller's transaction, answering the new id; the second takes that
    // id as ours once the transaction has committed.  New device keys are the caller's to rotate
    // first, outside the transaction.
    device::Id _forget_identity();
    void _adopt_identity(const device::Id& id);

    bool _dissolve_group(const device::GroupId& group);

    // What makes a member Membership::Dropped: our group's messages gone from the swarm while
    // another group's are there, or one of them we cannot read that says too little to tell why.
    bool _dropped();

    // Takes where we now stand as already reported, after a change the caller made and so knows of.
    void _rebaseline_membership();

    // Takes `state` as reported, answering whether that is news: a different membership, or a
    // different set of groups in `others`.
    bool _take_as_reported(const device::MembershipState& state);

    // What a message from our own group that we cannot read says of us, by its `kicked` list (see
    // "Displaced devices"): Removed if it names us, Displaced if it shows we were not removed, and
    // Dropped if it cannot tell.  The only way a removed device learns of it: it is no longer given
    // a key to the payload.
    device::Membership _unreadable_verdict(std::span<const std::byte> data);

    struct LinkRequestResult {
        std::vector<std::byte> message;  // encrypted bytes to push to Namespace::Devices
        Sas sas;
        int64_t row;  // in device_own_requests
    };

    // Builds our link request to the group `group`, whose link key is `link_x25519`, records it as
    // our newest request, and moves our own row to Pending.
    LinkRequestResult _build_link_request(
            const device::GroupId& group, std::span<const std::byte, 32> link_x25519);

    // Takes the handler by reference and moves from it only once nothing more can throw, so that
    // `request_link` can still report a failure through it.  `_request_link` fetches the group,
    // and `_send_link_request` does the rest once it has.
    void _request_link(const device::GroupId& group, result_function<OutgoingLinkRequest>& cb);
    void _send_link_request(const device::GroupId& group, result_function<OutgoingLinkRequest>& cb);

    // Whether a device that may ask to join a group is cast out of the one it holds, and so asks
    // under a new id.  Throws err::already_registered for one in a group, which has to leave it
    // first: an account has only one.
    bool _cast_out_asking();

    // The outer link request message carrying `plaintext`, encrypted to the group whose link key is
    // `link_x25519`; see "Initiating a device link".
    std::vector<std::byte> _encrypt_link_request(
            std::span<const std::byte> plaintext, std::span<const std::byte, 32> link_x25519);

    // A link request's signed contents, if it was encrypted to an account key we hold -- which is
    // to say, if it asks to join our group.
    std::optional<std::vector<std::byte>> _decrypt_link_request(
            std::span<const std::byte, 32> E,
            std::span<const std::byte> encrypted,
            std::span<const std::byte, 2> indicator);

    // One of our own link requests; see device_own_requests.
    struct OwnRequest {
        int64_t row;
        device::GroupId group;
        std::array<std::byte, 16> sas_seed;
        std::chrono::sys_seconds asked;                   // the record's timestamp
        std::optional<std::chrono::sys_seconds> expires;  // unset until the swarm stores it
        bool held;  // an admission on it waits for the user's confirmation
    };

    template <typename... T>
    std::optional<OwnRequest> _select_own_request(std::string_view where, const T&... bind);

    // The request the user deals with: our newest.  An admission is only ever held for it, so that
    // what the user confirms is always what the waiting screen shows.
    std::optional<OwnRequest> _newest_request();

    // The request of ours that a group message admitting `record` to `group` accepted: the one
    // that carried that record.
    std::optional<OwnRequest> _own_request_admitted(
            const device::GroupId& group, const device::Info& record);

    // The newest request's deadline, while it can still lapse and until it has: unset once an
    // admission is held for it, which waits on the user instead.
    std::optional<std::chrono::sys_seconds> _own_deadline();
    std::optional<OutgoingLinkRequest> _outgoing_link_request();

    // Returns our own row from Pending to Unregistered, answering whether it was Pending.  The
    // request is kept: one already in the swarm can still be approved, which leaves us `Approved`.
    bool _withdraw_own_request();

    // Forgets every request of ours, for a device admitted to a group, starting one, or taking a
    // new identity: none of them can admit it to anything after that.
    void _forget_own_requests();

    // What `leave_group` does once on the loop: a departure (or the group's dissolution) queued
    // only by a member in good standing, in the same commit as `_forget_identity`.  False with no
    // group to leave.
    bool _leave_group();

    // Queues our departure from the group `devs` holds, or its dissolution if no one else is in it,
    // inside the caller's transaction.
    void _queue_departure(device::map& devs);

    // The hashes of our group's messages that our state was merged from: what replacing or
    // dissolving the group deletes from the swarm.
    std::vector<std::string> _merged_hashes();

    bool _confirm_link();

    // Points the expiry timer at `deadline`, or stops it.
    void _arm_expiry(std::optional<std::chrono::sys_seconds> deadline);

    // Rotates whichever of the account key and our device keys is due, for a member in good
    // standing; the push that follows a fetch then carries both.
    void _rotate_due_keys();

    // Points the fetch timer at the earliest of the two next rotations and a push retry, or stops
    // it.
    void _arm_fetch_timer();

    // A push the swarm did not store: schedules the fetch that tries it again, unless one is
    // already scheduled, and lengthens the wait for the next failure.
    void _push_failed();

    // A push the swarm confirmed: the next failure waits only `PUSH_RETRY_FIRST` again.
    void _push_stored();

    // The signed account pubkey message for the key with these public halves; see
    // `build_account_pubkey_message`.
    std::vector<std::byte> _account_pubkey_message(
            std::span<const std::byte, 1184> mlkem768_pub,
            std::span<const std::byte, 32> x25519_pub);

    // Marks the account key with these public halves as one namespace -21 holds, current or
    // rotated, answering whether there was such a key of ours at all.  The current one is also
    // recorded as our own session id's PFS/PQ key (see `Core::_cache_own_pfs_key`).
    bool _mark_published(
            std::span<const std::byte, 1184> mlkem768_pub,
            std::span<const std::byte, 32> x25519_pub);

    // Settles the keys seen on -21 that were not ours when seen (see `suspect_pubkeys_key`), by a
    // fetch of the group sent after they were: a key another device has just rotated to reaches -21
    // and 21 in separate stores, either of which this device can see first.  Does nothing with none
    // waiting, or no network to fetch with.
    void _verify_suspects();

    // Reads namespace -21 again from the start, by a fetch of its own, for a device that has just
    // become a member in good standing: the first point at which it can judge what -21 holds.
    void _reread_account_pubkeys();

    // What that fetch decides: a key now known was a rotation; one still unknown is rogue, which
    // `callbacks::rogue_account_key` reports and, with PFS/PQ enabled, our own key is published
    // over.
    void _judge_suspects();

    // Fetches the group now if anything is owed a push -- a change of ours, or the account's key
    // once PFS/PQ is enabled -- so that the push following the fetch carries it: a device
    // subscribed for pushes does not poll, and could otherwise hold it until the swarm next had
    // something for it.
    void _push_soon();

    // Picks when the device keys made at `created` are to be rotated, and records it.
    sys_ms _schedule_device_rotation(std::chrono::sys_seconds created);

    bool _accept_request(int reqid);

    // Puts the record link request `row` asks for in place of the one its device holds in the
    // group, and rotates the account key.  False if the device is no longer in the group.  Inside
    // the caller's transaction.
    bool _replace_record(int64_t row);
    bool _ignore_request(int reqid, bool delete_from_swarm);
    size_t _forget_link_requests(std::span<const int> reqids);

  public:
    // Sets what this device describes itself as -- type, description, version and `extra` -- which
    // every record it publishes is built from, in this group or any it joins later.  If the
    // device is registered, its group is owed a push carrying it, which follows a fetch this call
    // asks for at once.
    //
    // The id, seqno, timestamp, state and pk_* fields of the input value are ignored.  A
    // description longer than `device::DESCRIPTION_MAX` bytes is cut to it on a UTF-8 character
    // boundary, and `device_info()` reads back the cut value, which is what is published.
    //
    // Filling these in is the application's job -- libsession establishes the group with them
    // blank -- and an application is on its own thread when it does.  The handler form takes the
    // info by value: it outlives the call.
    void update_info(device::Info info, result_function<> cb);
    void update_info(const device::Info& info, await_t);

    // Creates the account's device group with this device as its only member, if one is owed.
    //
    // Owed means the account was *generated* here rather than restored: a brand new account has no
    // group and nothing else will ever make one, whereas a restored account may already have a
    // group belonging to devices that are merely offline, and inventing a second one would orphan
    // them.  `Globals` records which happened; this acts on that record and clears it, so it runs
    // exactly once per account and survives a crash between creating the account and getting here.
    //
    // Does nothing if this device is already registered, so it is safe to call at any time.
    //
    // Registering ourselves is what breaks the deadlock the rest of this class sits behind:
    // `needs_push()` only reports a device group push for a registered device, and the only other
    // thing that registers one is receiving a group message we can decrypt -- which cannot happen
    // until some device has pushed one.
    //
    // Also mints the account's first shared key seed, since the group payload carries it.  That is
    // not the same as *publishing* PFS keys: nothing goes to Namespace::AccountPubkeys here, and
    // until it does no other account treats this one as supporting v2 encryption.
    void establish_group();

    // Stores the X25519 + MLKEM768 keys that make up an "X-Wing" key
    struct XWingKeys {
        cleared_b32 x25519_sec;
        std::array<std::byte, 32> x25519_pub;
        cleared_array<std::byte, 2400> mlkem768_sec;
        std::array<std::byte, 1184> mlkem768_pub;
    };

    struct DeviceKeys : XWingKeys {
        std::chrono::sys_seconds created;
        std::optional<std::chrono::sys_seconds> rotated;
    };

    // Rotates the device keys used for encrypting device group data.  This also implicitly updates
    // the current device's public keys.  If the current device is registered, calling this will
    // dirty the config data and require another push.
    //
    // Keeps only the key it replaces besides the new one: a sender fetches before it pushes, and so
    // encrypts to our newest published key, or to the one before if our rotation landed between its
    // fetch and its push.  What only an older key could read is a superseded snapshot or a forgery.
    // Schedules the next rotation (see `next_device_rotation`).
    //
    // This returns the newly created keys.  (It can be safely discarded as it will already be
    // stored in the database).
    DeviceKeys rotate_device_keys();

    // Returns current and previous local device private keys, most recent first.  If there is no
    // current key at all, this generates one.
    std::vector<DeviceKeys> active_device_keys();

    struct AccountKeys : XWingKeys {
        std::chrono::sys_seconds created;
        std::optional<std::chrono::sys_seconds> rotated;
    };

    // What an application may show of an account key: its public halves and its history, and never
    // its secret.
    struct AccountKeyInfo {
        std::array<std::byte, 32> x25519_pub;
        std::array<std::byte, 1184> mlkem768_pub;
        std::chrono::sys_seconds created;
        // When a newer key replaced it; unset for the current key.
        std::optional<std::chrono::sys_seconds> rotated;
        // When it is discarded, ACCOUNT_KEY_RETENTION after it was rotated away; unset for the
        // current key, which is kept for as long as it is current.
        std::optional<std::chrono::sys_seconds> retained_until;
        // Whether it has been seen on namespace -21, where contacts find the key to encrypt to:
        // confirmed stored there by this device's push, or fetched back from there.
        bool published;
    };

    // The account keys this device holds, as `active_account_keys` returns them -- current first,
    // then the rotated ones newest first, after discarding those past their retention -- without
    // their secret halves: what an application lists, which must never be `active_account_keys`.
    // Unlike that, never makes a key where there is none.  A plain read of the database, safe from
    // any thread.
    std::vector<AccountKeyInfo> account_keys();

    // How long after rotation to keep an old account key, so that a message encrypted to it can
    // still be read for as long as it can be in the swarm.  A sender may go on encrypting to a key
    // after it is replaced, within Core::PFS_KEY_REFRESH (6h) normally and up to
    // Core::PFS_KEY_FAILED_GRACE (24h) when its lookups keep failing; the message then lasts the
    // swarm's TTL.  16 days in all.
    static constexpr auto ACCOUNT_KEY_RETENTION = 14 * 24h  // the maximum 1-to-1 message TTL
                                                + 24h       // Core::PFS_KEY_FAILED_GRACE
                                                + 24h;      // margin for clock skew, late storage

    // How often account and device keys rotate, and the window each rotation is spread over.  An
    // account key's offset within the window is skewed so that the earliest of N devices' is
    // Unif[PERIOD-JITTER/2, PERIOD+JITTER/2] whatever N is, masking the number of devices in the
    // group; a device key's is uniform, being this device's alone.
    static constexpr auto KEY_ROTATION_PERIOD = 12h;
    static constexpr auto KEY_ROTATION_JITTER = 2h;

    // How long the swarm holds a device group message.  The maximum a private namespace allows: the
    // group is what a device that has been away comes back to, and an account whose devices are all
    // offline for longer than this loses the only record of what its group is.
    static constexpr auto DEVICE_GROUP_TTL = 30 * 24h;

    // How long a group's messages go on carrying a removal or departure, for the devices that were
    // away when it happened.  Only what a message carries: a device's own table keeps every one.
    static constexpr auto REMOVAL_MARKER_MAX_AGE = std::chrono::months{6};

    // How long the swarm holds a link request, which is how long it can be answered.  Linking
    // needs the user at both devices at once, so a longer wait buys nothing.
    static constexpr auto LINK_REQUEST_TTL = 10min;

    // How much newer than the newest message from our group we could read one we cannot read must
    // be before it says we were displaced or dropped.  Just after we join, a member can push a
    // snapshot it built before fetching our admission, which leaves us out for no reason but
    // timing; this covers that, and the difference between the clocks of the two devices whose
    // timestamps are compared.  A real displacement is not missed for it: every later message is
    // unreadable too, and the account key's rotation guarantees one.
    static constexpr auto DISPLACEMENT_GRACE = 5min;

    // How far ahead of our clock a group message's signed time may be before we ignore the
    // message.  Some lead is only another device's clock running fast; much more is a broken clock
    // or a forgery, and believed, it would hold the newest time we have seen from a group -- which
    // displacement is measured from, and which picks the key requests to join it are encrypted to
    // -- out of reach of every honest message until our own clock caught up.  Ten minutes is far
    // more than clocks kept in sync disagree by, and caps what a bad time can hold back to that.
    static constexpr auto GROUP_MESSAGE_MAX_AHEAD = 10min;

    // How long a device group push the swarm did not store waits before a fetch of our own tries it
    // again: the first, doubling with each failure in a row up to the most.  The first is about as
    // long as a failed store has already taken to time out; the most keeps a device whose swarm is
    // unreachable for a while to one try every five minutes.
    static constexpr std::chrono::milliseconds PUSH_RETRY_FIRST = 10s;
    static constexpr std::chrono::milliseconds PUSH_RETRY_MAX = 5min;

    // Rotates the shared account keys used for PFS+PQ message encryption.  Generates a new random
    // seed, stores it in the database, and marks the previous active key as rotated.  Done by Core
    // itself when `account_rotation_due()` (see `next_account_rotation`), and when the group's
    // membership calls for it.
    void rotate_account_keys();

    // Returns the current active account keys after pruning obsolete ones: that is, the current key
    // plus all keys that were rotated away fewer than ACCOUNT_KEY_RETENTION ago.  Keys are returned
    // sorted from newest to oldest.  If there are no keys at all, generates an initial one.
    // Returns account keys, ordered with the active (unrotated) key first then
    // most-recently-rotated first.  Expired rotated keys are pruned before querying.  If
    // key_indicator is given, only keys whose ML-KEM-768 pubkey begins with those two bytes are
    // returned (using the indexed key_indicator virtual column); otherwise all retained keys are
    // returned and a new key is auto-generated if none is currently active.
    std::vector<AccountKeys> active_account_keys(
            std::optional<std::span<const std::byte, 2>> key_indicator = std::nullopt);

    // When this device's own device keys are due to be rotated: KEY_ROTATION_PERIOD after the
    // current ones were made, give or take half of KEY_ROTATION_JITTER, picked when they were.
    // Nullopt for a device that is not a member of a group in good standing, which never rotates on
    // schedule: the keys a link request of its names stay valid until it is admitted.
    //
    // Core rotates both kinds of key by itself, after a fetch: rotating before one would leave
    // what waits in the swarm encrypted to keys the device had just let go of.
    std::optional<std::chrono::system_clock::time_point> next_device_rotation();

    bool device_rotation_due() {
        auto t = next_device_rotation();
        return t && *t <= clock_now();
    }

    // When this device is due to rotate the account key, KEY_ROTATION_PERIOD after the current one
    // was made, offset within KEY_ROTATION_JITTER as the spec's "Account Key Rotation timer" says;
    // or sooner, if the current key reached a device no longer in the group (see "Rotating early").
    // Nullopt for a device that is not a member of a group in good standing.
    //
    // This device's own time: at most `scheduled_account_rotation()`, and earlier than it only
    // while this device is replacing the key early.
    std::optional<std::chrono::system_clock::time_point> next_account_rotation();

    // Every registered device's slot to rotate the account key, each reckoned as
    // `next_account_rotation` reckons this device's, earliest first.  Every member computes the
    // same list from the same group.  The group rotates at the earliest slot whose device is online
    // then to make it.
    //
    // Early replacement is not in it: when and whether a device replaces the key early is its own
    // (each picks its own jittered moment, and the remover goes at once), so no list including it
    // could be the same on every device; this device's is in `next_account_rotation`.  Empty for a
    // device that is not a member of a group in good standing, or with no active key.
    std::vector<std::pair<device::Id, std::chrono::system_clock::time_point>>
    account_rotation_schedule();

    // When the group's next scheduled account key rotation falls: the first slot of
    // `account_rotation_schedule`, and so the same on every member -- the one to show a user.  The
    // rotation happens then only if the device whose slot it is is online to make it; otherwise
    // the next slot's device does.  Nullopt where the schedule is empty.
    std::optional<std::chrono::system_clock::time_point> scheduled_account_rotation();

    bool account_rotation_due() {
        auto t = next_account_rotation();
        return t && *t <= clock_now();
    }

    struct DeviceGroupPush {
        std::vector<std::byte> message;  // encrypted bytes to push to Namespace::Devices
        device::Info own;                // our record as this message carries it

        // What this message carries that was owed, so that confirming it clears exactly that and no
        // more.  A device kicked, or a key minted, while the push was in flight is not in these and
        // therefore stays owed -- it would otherwise be marked clean by a message it never reached.
        // A transition is carried with the generation it had, since the same device can be owed
        // again before the swarm answers: a removal restated meanwhile, say.
        std::vector<std::pair<device::Id, int64_t>> broadcast;  // device ids and their generations
        std::vector<int64_t> keys;  // device_account_keys rows it distributes

        // Every account key it carries, and the devices it is encrypted to: what confirming it
        // records as delivered (see `device_account_key_recipients`).
        std::vector<int64_t> carried_keys;
        std::vector<device::Id> recipients;

        // Messages this one makes redundant: everything we had merged when it was built, whoever
        // wrote it.  A "G" is a snapshot of the whole group rather than one device's contribution,
        // so what obsoletes it is having taken its contents in, not having written it.  Deleted in
        // the same sequence that stores this one, after it.
        std::vector<std::string> obsolete;
    };

    // Builds the account's device group ("G") message for upload to Namespace::Devices.
    //
    // Throws std::logic_error if this device is not registered: a device outside the group has
    // nothing to say about it, and pushing anyway would announce a group of one that every other
    // device would merge in as authoritative.
    //
    // `own` comes back rather than being read again afterwards because the message is built from a
    // snapshot: pass the push to mark_device_group_pushed() once the swarm confirms the store, so
    // that it is what we take the swarm to hold for us, and a change made while the push was in
    // flight stays owed.
    DeviceGroupPush build_device_group_message();

    // Builds the signed account public key message for upload to namespace -21.  The message is a
    // bt-encoded dict containing the current active ML-KEM-768 pubkey ("M"), X25519 pubkey ("X"),
    // and a "positive alternative" Ed25519 signature ("~") over the preceding fields, allowing
    // recipients who only know the account's Session ID (X25519) to verify the keys.
    // Throws if there are no active account keys.
    std::vector<std::byte> build_account_pubkey_message();

    // How long the swarm holds the account pubkey message: as long as a namespace allows, so that a
    // contact can still find the account's key while all of its devices are away.  A rotation
    // replaces it long before then, since namespace -21 holds only one message.
    static constexpr auto ACCOUNT_PUBKEY_TTL = 30 * 24h;

    // Flags indicating which messages need to be pushed to the swarm.
    struct NeedsPush {
        bool device_group;    ///< True if an updated device group message needs to be pushed
        bool account_pubkey;  ///< True if an updated account pubkey message needs to be pushed
    };

    // Returns whether a push is currently needed.  Should be called after processing a final swarm
    // message batch (or at startup) to determine whether outgoing pushes are required.
    //
    // device_group is true when this device is registered, neither displaced nor dropped (see
    // device::Membership), AND any of the following hold:
    //   - what we would publish for ourselves differs from what the swarm holds for us
    //   - any device has a state transition (registered/removed) that this device made and has
    //     yet to broadcast; one merged from another device's message is already out
    //   - any account key seed has not yet been distributed via a confirmed push
    //
    // account_pubkey is true when the current active account key has not yet been seen confirmed
    // on the swarm (i.e. neither we nor another device has pushed it and we've received it back),
    // this device is a member in good standing as above, and PFS/PQ is enabled for the account
    // (`Core::pfs_enabled`): publishing the key is what tells contacts to encrypt to it, which
    // every device of the account must then be able to read.
    NeedsPush needs_push();

    // Records that a built device group message reached the swarm: takes the record of ours it
    // carried as what the swarm holds for us, stores its hash, and clears what `push` said it
    // carried.  `hash` is what the next push names to delete this one.
    void mark_device_group_pushed(const DeviceGroupPush& push, std::string hash);

    // Builds and uploads whatever `needs_push` says is owed -- the device group message, the
    // account pubkey message to namespace -21, or both in one request, as after a rotation.  Only
    // ever called once a fetch has been merged, so that what goes out is built on what the swarm
    // holds.
    //
    // Does nothing while a push is already in flight: the message is built from a snapshot of the
    // database, so a second one built before the first is confirmed would carry the same records
    // and race it to say what was pushed.
    void push_owed();
};

}  // namespace session::core
