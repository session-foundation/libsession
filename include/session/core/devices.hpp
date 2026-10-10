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
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "component.hpp"
#include "swarm_message.hpp"

namespace session {
class TestHelper;
}  // namespace session

namespace session::core {

using namespace std::literals;

class Core;
class DeviceEvents;

namespace device {

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
                   ///< was then removed reads as removed everywhere.  Always accompanied by
                   ///< `kicked`.
        Kicked = 4,  ///< Removed from the group by another device, and permanently: a kicked device
                     ///< id can never rejoin, only be replaced by a fresh one.  Outranks
                     ///< everything, so the tombstone that carries a removal cannot be undone by a
                     ///< stale record replaying an earlier state.  Always accompanied by `kicked`,
                     ///< which the schema enforces.
    };

    /// What became of a link request this device saw.
    ///
    /// Expiry is not among these: a request is expired when it is still `Pending` and its deadline
    /// has passed, so there is nothing to keep in step with the timestamp that decides it.
    enum class LinkStatus {
        Pending = 0,     ///< Awaiting an answer, here or on another device.
        Accepted = 1,    ///< Admitted to the group, by us or by another device.
        Ignored = 2,     ///< Dismissed here.  Local and silent: nothing is sent, and another device
                         ///< can still accept the same request.
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
        // Unique device id, in raw bytes.  Typically randomized during device initial setup.
        std::array<std::byte, 32> id;

        // Device seqno.  Incremented on device key rotation and/or info updates.
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
        // possible a device nickname, but is generally free-form data.
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
        // for a record that never came off the wire: our own, and a tombstone for a device we never
        // knew.  A stored NULL makes the comparison NULL at equal state and seqno, so such a row
        // cannot be displaced by an equal-ranked arrival -- which for our own row is the point,
        // since only we author it.
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

    using map = std::map<std::array<std::byte, 32>, Info>;

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

        /// The 21 emoji to compare against what the requesting device is showing.  The first 7 are
        /// the standard display; all 21 are there for an extended view.
        std::array<std::string_view, 21> sas;

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

        /// The emoji a user compares to check that two devices are in the same group.  The
        /// suggested basic display is the first 4 beside `created()`; all 21 are for an extended
        /// view.  Not a security check: anyone holding the account seed can copy an identifier.
        std::array<std::string_view, 21> sas() const;

        bool operator==(const GroupId&) const = default;
    };

    /// Where this device stands with respect to the account's device groups.  An ongoing state
    /// rather than a step in setup: it is re-evaluated on every fetch, and any of these can recur.
    enum class Membership {
        Unknown,  ///< Not yet known: no fetch from the swarm has completed since this Core started,
                  ///< and what the swarm holds decides every other value.
        InGroup,  ///< In a group.  Others may be visible alongside it: see MembershipState::others.
        NoGroup,  ///< Not in a group, and no group is in the swarm.  Either the account never had
                  ///< one, or every device was offline long enough for it to expire, and the two
                  ///< cannot be told apart -- so starting one is the user's decision.
        GroupsVisible,  ///< Not in a group, and one or more groups it cannot read are in the swarm:
                        ///< it may ask to join one, or start its own alongside them.
        Waiting,        ///< Waiting on this device's own link request; see `outgoing_link_request`.
        Removed,  ///< Removed from its group by another device.  It can come back only under a new
                  ///< device id.
        CutOff,   ///< Was in a group, none of whose messages are left in the swarm, while another
                  ///< group's are.  It can no longer receive anything encrypted to its group, which
                  ///< may be an attack, and is never dismissable.
        Displaced,  ///< Its group has moved on without it: a newer message from the group is one
                    ///< it cannot read, though nothing removed it.  Another device holds its place
                    ///< under its id -- a restored copy of it, admitted as a replacement, or
                    ///< someone holding a copy of its data who has rotated it out, which is an
                    ///< attack.  Never dismissable.  It can come back only under a new device id.
    };

    /// A device group in the swarm other than this device's own.
    struct VisibleGroup {
        GroupId id;
        std::chrono::sys_seconds last_seen;  ///< When its newest message was stored.
        bool dismissed;  ///< The user has dismissed it here: see `Devices::dismiss_group`.
    };

    struct MembershipState {
        Membership membership;
        std::optional<GroupId> group;      ///< This device's group, while it is in one.
        std::vector<VisibleGroup> others;  ///< Every other group in the swarm, newest first.
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
    // push_device_group().  `_alive` is what a push callback checks before touching us, since it
    // returns on the network's thread and this component does not outlive its Core.
    bool _push_in_flight = false;
    std::shared_ptr<int> _alive = std::make_shared<int>(0);

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
    std::vector<std::array<std::byte, 32>> _member_changes;
    bool _fetched = false;
    device::Membership _reported_membership = device::Membership::Unknown;
    std::set<std::array<std::byte, 8>> _announced_groups;
    std::unordered_set<int64_t> _ended;

    // Fires a flush at the earliest deadline among our own request and those handed out and still
    // open, so each lapses when it expires rather than at whichever fetch next completes -- which
    // could be an application-chosen interval away, or never while the network is down.
    quic::TimerID _expiry_timer;

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
            std::span<const std::array<std::byte, 32>> member_changes,
            std::chrono::sys_seconds now);

    // Reads link requests with the device each came from.  `pending_only` restricts to those still
    // awaiting an answer and not yet past their deadline.
    std::vector<device::LinkRequest> _link_requests(bool pending_only);

    // The same read without handing anything out: each request beside its row, with `id` unset.
    // What `_flush_events()` uses to tell a request the application has not seen yet from one it
    // has, since having an id is what having seen it means.
    std::vector<std::pair<int64_t, device::LinkRequest>> _read_link_requests(bool pending_only);

    // This device's group's identifier: nullopt outside a group, and also inside one established
    // before groups had identifiers, until a group message gives it one.
    std::optional<device::GroupId> _group_id();
    void _set_group_id(const device::GroupId& id);

    // The identifier a group message carries, which needs only the account seed to read; nullopt
    // for a message from before identifiers.
    std::optional<device::GroupId> _group_of(std::span<const std::byte> message);

    // Notes a group message in `device_groups`, whether or not we can read it.  Throws on a bad
    // signature.
    void _record_group(const SwarmMessage& msg);

    // Records that this account owes a device group, for `establish_group()` to act on.  Called by
    // Globals when it generates an account, which is before this component has initialised -- hence
    // a stored flag rather than doing the work there.
    void _mark_group_owed();

    std::array<std::byte, 32> self_id;

    // Encrypts the inner device data for all the members of the device group.
    std::vector<std::byte> encrypt_device_data(const device::map& devices);

    // Processes a single incoming device group ("D") or link request ("L") message.  `data` is the
    // full raw message bytes including the outer bt-dict wrapper with the "" type key.
    //
    // The group message takes the swarm hash as well, because merging one is what makes it
    // redundant: our next push carries its contents forward, and that is when it can be deleted.
    // Recorded only on a message we could decrypt -- see `device_group_merged`.
    void receive_device_group_message(
            std::span<const std::byte> data, const std::string& hash, sys_ms timestamp);

    // In the group and able to act for it: registered, and not displaced from it.
    bool _member();
    bool _displaced();

    // A message from our own group, stored at `timestamp`, was one we could read.
    void _note_read(sys_ms timestamp);
    //
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
    void _update_info(const device::Info& info);

  public:
    // Returns the current device's random identifier, in hex.
    std::string device_id() const;

    // Returns info for all registered and/or pending devices and/or unregistered devices for this
    // account.  If `only_device` is non-empty it must be a 32-byte device id that is used to
    // filter the results to just that one device.
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
        /// The 21 emoji the user compares against what the accepting device shows; the first 7 are
        /// the standard display.
        std::array<std::string_view, 21> sas;

        /// When the request lapses unanswered.  After it no device can accept it, and asking again
        /// is the only way in.
        std::chrono::sys_seconds expires;

        /// The user has confirmed, through `confirm_link`, that the emoji match the accepting
        /// device's; what is left is for that device to accept.
        bool confirmed = false;

        /// Another device has accepted it, and this one joins once the user confirms the emoji.
        /// Such a request stays here past `expires`: the acceptance came in time, even if the
        /// message carrying it reached this device later.
        bool accepted = false;
    };

    // Asks the devices of the group `group` to admit this one: uploads a link request for them to
    // accept, and answers once the swarm has stored it.  The request is encrypted to that group, so
    // that only its members can read it; the group must be one this device has seen in the swarm.
    // The account must already be restored here.
    //
    // A device already in a group may ask to switch to another.  It stays a working member of its
    // own until admitted, and then leaves it: a departure pushed to the members left, or the old
    // group's messages deleted if it was the only one.  The old group is dismissed and forgotten,
    // its account keys included, and the new group's arrive with the message admitting it.
    //
    // Either way it is admitted only once a group message admitting it has arrived *and* its user
    // has confirmed the SAS through `confirm_link`, and then hears `membership_changed(InGroup)` --
    // or, from outside a group, `membership_changed` with what it sees if `expires` passes first.
    // Asking again replaces the request, and its SAS, with a new one.
    //
    // Fails with `err::already_registered` for the group it is already in, `err::removed` for a
    // device displaced from its group, `err::network_unavailable`, `err::unknown_group`, or
    // `err::store_failed` -- the last worth retrying.  None of them leaves a request outstanding.
    void request_link(device::GroupId group, result_function<OutgoingLinkRequest> cb);

    // The request `request_link` made, while it is still waiting: stored by the swarm and not past
    // its deadline, or accepted and waiting for the user to confirm it (`accepted`), whatever the
    // deadline.  Nothing otherwise -- including while the upload is still in flight, when there is
    // nothing another device could accept yet.
    //
    // What a waiting screen is drawn from, each time it is drawn or reopened, and what to read
    // again on `membership_changed`.  Survives a restart for as long as the request itself does,
    // since the swarm's copy stays acceptable until its deadline either way.
    void outgoing_link_request(result_function<std::optional<OutgoingLinkRequest>> cb);
    std::optional<OutgoingLinkRequest> outgoing_link_request(await_t);

    // The user's confirmation, on this device, that its SAS matches the one the accepting device
    // showed.  A device joins only once it has this *and* a group message admitting it, in either
    // order: being able to read such a message is not enough on its own, since anyone holding the
    // account seed can publish a group of its own with a link key of its own, and admit into it a
    // device that encrypted its request there.  The real group can read no such request, and so
    // never prompts for it, which is what makes the user's confirmation mean something.  See
    // "Confirmation on the requesting device".
    //
    // An admission is matched to the request it accepted, and admits the device only if that is a
    // request the user confirmed, or the one they are being shown now; one matching none of this
    // device's requests is ignored.  So a device that asks again, after a request seemed to go
    // unanswered, is still admitted if the earlier one is accepted after all -- provided the user
    // confirmed it before moving on.
    //
    // Answers false if this device is not waiting on a request.  Asking again needs confirming
    // again: a new request has a new SAS.
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
    // next group push, which happens once the next fetch completes.
    //
    // For a request that `replaces` a device, the requesting device's record takes the place of the
    // one held, and the account key is rotated: a copy of the device as it was, still holding the
    // replaced record's keys, must not read what comes after.
    //
    // Answers false if the request can no longer be accepted: answered here or elsewhere,
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
    // ordinary case of a request being answered on a different device.  With `delete_from_swarm`,
    // for a request the user does not recognise, it is also deleted from the swarm, so that a
    // device yet to fetch it never sees it.  A device that has already fetched it is not told, and
    // can still accept it until it expires.  The deletion is attempted once, and not reported on.
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
    // no key to anything the group pushes from here on.  The removal reaches the other devices --
    // and, through the `kicked` list, the removed device itself -- with the next group push, which
    // happens once the next fetch completes.
    //
    // Answers false if the device is not in the group -- unknown, still only asking to join (which
    // is `ignore_request`), or already gone -- or this device is no longer in it either.  None of
    // those is an error: each can happen between a device list being drawn and the user acting on
    // it.  Passing this device's own id is an error (std::invalid_argument): a device leaves a
    // group by joining another.
    void remove_device(std::array<std::byte, 32> id, result_function<bool> cb);
    bool remove_device(std::span<const std::byte, 32> id, await_t);

    // Where this device stands, and which other groups are in the swarm.  What an application
    // prompts from at startup and draws its device screen from; read again on `membership_changed`
    // and `group_appeared`.  `Unknown` until the first fetch of this run completes, since the swarm
    // may have changed while it was down.
    void membership(result_function<device::MembershipState> cb);
    device::MembershipState membership(await_t);

    // Gives a removed or displaced device a new identity, so that it can ask to join again: a
    // removed id is spent, and can never rejoin the group that removed it, and a displaced one is
    // another device's now.  A new device id and new device keys
    // replace the old, and what it held of its old group -- its devices and its account keys
    // included -- is forgotten, leaving it `GroupsVisible` or `NoGroup` like any device outside a
    // group.  Its messages, the account's configs, and the groups it has seen in the swarm are
    // kept.
    //
    // Answers false for a device that has been neither removed nor displaced.
    void renew_device_identity(result_function<bool> cb);
    bool renew_device_identity(await_t);

    // Starts a new device group with this device as its only member, and answers its identifier.
    // For `NoGroup`, and for `GroupsVisible`, where the new group is started *alongside* those
    // already there: it replaces and deletes nothing, and their devices are alerted to it, so that
    // a group started by mistake can be undone by joining one of theirs instead.  A device
    // `Waiting` on a link request withdraws it.  The group starts with a newly generated account
    // key, whatever the device held before.
    //
    // Fails with `err::already_registered` for a device already in a group, `err::removed` for one
    // removed or displaced from its group, and `err::membership_unknown` before the first fetch of
    // this run: starting a group is the user's decision, made from what the swarm holds.
    void start_group(result_function<device::GroupId> cb);
    device::GroupId start_group(await_t);

    // Dismisses the alert for another group, so that `group_appeared` does not fire for it again --
    // here only: each device dismisses for itself.  Remembered across restarts.  It does not quiet
    // `CutOff`, which is never dismissable.  Answers false for a group not seen in the swarm.
    void dismiss_group(device::GroupId group, result_function<bool> cb);
    bool dismiss_group(const device::GroupId& group, await_t);

  private:
    bool _remove_device(std::span<const std::byte, 32> id);
    device::MembershipState _membership();
    device::GroupId _start_group();
    bool _renew_device_identity();

    // Forgets everything of the group this device was in: its devices, its messages, its account
    // keys and its identifier.
    void _forget_group();
    bool _dismiss_group(const device::GroupId& group);

    // Takes where we now stand as already reported, after a change the caller made and so knows of.
    void _rebaseline_membership();

    // Whether an unreadable group message names this device in its `kicked` list, which is the only
    // way a removed device learns of it: it is no longer given a key to the payload.
    bool _names_us_kicked(std::span<const std::byte> data);

    struct LinkRequestResult {
        std::vector<std::byte> message;  // encrypted bytes to push to Namespace::Devices
        std::array<std::string_view, 21> sas;
        int64_t row;  // in device_own_requests
    };

    // Builds our link request to the group `group`, whose link key is `link_x25519`, records it as
    // our newest request, and moves our own row to Pending if we are not in a group.
    LinkRequestResult _build_link_request(
            const device::GroupId& group, std::span<const std::byte, 32> link_x25519);

    // Takes the handler by reference and moves from it only once nothing more can throw, so that
    // `request_link` can still report a failure through it.
    void _request_link(const device::GroupId& group, result_function<OutgoingLinkRequest>& cb);

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
        bool confirmed;
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
    // request is kept: one already in the swarm can still be accepted, and admits us once the user
    // confirms it.
    bool _withdraw_own_request();

    // Forgets every request of ours, for a device admitted to a group, starting one, or taking a
    // new identity: none of them can admit it to anything after that.
    void _forget_own_requests();

    // Whether this device is waiting to be admitted to a group: from outside any group (Pending, or
    // with an admission held for the user's confirmation), or from inside one, asking to switch.
    bool _asking();

    // Leaves the group this device is in, on its admission to another: a departure pushed to the
    // old group's other members, or the old group's messages deleted if it had none, and the old
    // group dismissed and forgotten.  See "Leaving a group to join another".
    void _leave_group();

    bool _confirm_link();

    // Points the expiry timer at `deadline`, or stops it.
    void _arm_expiry(std::optional<std::chrono::sys_seconds> deadline);

    bool _accept_request(int reqid);

    // Puts the record link request `row` asks for in place of the one its device holds in the
    // group, and rotates the account key.  False if the device is no longer in the group.  Inside
    // the caller's transaction.
    bool _replace_record(int64_t row);
    bool _ignore_request(int reqid, bool delete_from_swarm);
    size_t _forget_link_requests(std::span<const int> reqids);

  public:
    // Updates this device's info locally to match the given info; if the current device is
    // registered then this dirties the device config data, requiring a push.
    //
    // The state and pk_* fields of the input value are ignored.
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
    // This returns the newly created keys.  (It can be safely discarded as it will already be
    // stored in the database).
    DeviceKeys rotate_device_keys();

    // Returns current and recent local device private keys.  This will be sorted with most recent
    // key first.  If there is no current key at all, this generates one.
    std::vector<DeviceKeys> active_device_keys();

    struct AccountKeys : XWingKeys {
        std::chrono::sys_seconds created;
        std::optional<std::chrono::sys_seconds> rotated;
    };

    // How long after rotation to keep an old account key.  14 days is the maximum 1-to-1 message
    // TTL, plus 24h for sender key update lag, plus 24h safety margin.
    static constexpr auto ACCOUNT_KEY_RETENTION = 16 * 24h;

    // Base rotation period and jitter window for account key rotation.  The formula is designed so
    // that the minimum rotation time across all N devices in the group is Unif[PERIOD-WINDOW/2,
    // PERIOD+WINDOW/2], regardless of N, masking the number of devices in the group.
    static constexpr auto ACCOUNT_KEY_ROTATION_PERIOD = 12h;
    static constexpr auto ACCOUNT_KEY_ROTATION_WINDOW = 2h;

    // How long the swarm holds a device group message.  The maximum a private namespace allows: the
    // group is what a device that has been away comes back to, and an account whose devices are all
    // offline for longer than this loses the only record of what its group is.
    static constexpr auto DEVICE_GROUP_TTL = 30 * 24h;

    // How long the swarm holds a link request, which is how long it can be answered.  Linking
    // needs the user at both devices at once, so a longer wait buys nothing.
    static constexpr auto LINK_REQUEST_TTL = 10min;

    // How much newer than the newest message from our group we could read one we cannot read must
    // be before it says we were displaced.  Just after we join, a member can push a snapshot it
    // built before fetching our admission, which leaves us out for no reason but timing; this
    // covers that, and the difference between the clocks of the two devices whose timestamps are
    // compared.  A real displacement is not missed for it: every later message is unreadable too,
    // and the account key's rotation guarantees one.
    static constexpr auto DISPLACEMENT_GRACE = 5min;

    // Rotates the shared account keys used for PFS+PQ message encryption.  Generates a new random
    // seed, stores it in the database, marks the previous active key as rotated, and prunes keys
    // older than ACCOUNT_KEY_RETENTION.  Should be called when account_rotation_due() is true and
    // when a device first joins the device group with no existing account keys.
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

    // Returns the time when this device's unique device key is due to be rotated.  Returns nullopt
    // if this device is not currently part of the device group.
    std::optional<std::chrono::system_clock::time_point> next_device_rotation();

    bool device_rotation_due() {
        auto t = next_device_rotation();
        return t && *t <= clock_now();
    }

    // Return true if the account key is due to be rotated by this device.  Returns nullopt if this
    // device is not currently part of the device group.
    std::optional<std::chrono::system_clock::time_point> next_account_rotation();

    bool account_rotation_due() {
        auto t = next_account_rotation();
        return t && *t <= clock_now();
    }

    struct DeviceGroupPush {
        std::vector<std::byte> message;  // encrypted bytes to push to Namespace::Devices
        int64_t seqno;                   // this device's seqno at the moment the message was built

        // What this message carries that was owed, so that confirming it clears exactly that and no
        // more.  A device kicked, or a key minted, while the push was in flight is not in these and
        // therefore stays owed -- it would otherwise be marked clean by a message it never reached.
        std::vector<std::array<std::byte, 32>> broadcast;  // device ids whose transition it carries
        std::vector<int64_t> keys;  // device_account_keys rows it distributes

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
    // `seqno` comes back rather than being read again afterwards because the message is built from
    // a snapshot: pass it to mark_device_group_pushed() once the swarm confirms the store, so that
    // a change made while the push was in flight stays dirty.
    DeviceGroupPush build_device_group_message();

    // Builds the signed account public key message for upload to namespace -21.  The message is a
    // bt-encoded dict containing the current active ML-KEM-768 pubkey ("M"), X25519 pubkey ("X"),
    // and a "positive alternative" Ed25519 signature ("~") over the preceding fields, allowing
    // recipients who only know the account's Session ID (X25519) to verify the keys.
    // Throws if there are no active account keys.
    std::vector<std::byte> build_account_pubkey_message();

    // Flags indicating which messages need to be pushed to the swarm.
    struct NeedsPush {
        bool device_group;    ///< True if an updated device group message needs to be pushed
        bool account_pubkey;  ///< True if an updated account pubkey message needs to be pushed
    };

    // Returns whether a push is currently needed.  Should be called after processing a final swarm
    // message batch (or at startup) to determine whether outgoing pushes are required.
    //
    // device_group is true when this device is registered AND any of the following hold:
    //   - our own device info has changed since the last confirmed device group push
    //   - any device has a state transition (registered/removed) that needs broadcasting
    //   - any account key seed has not yet been distributed via a confirmed push
    //
    // account_pubkey is true when the current active account key has not yet been seen confirmed
    // on the swarm (i.e. neither we nor another device has pushed it and we've received it back).
    NeedsPush needs_push();

    // Records that a built device group message reached the swarm: stores its seqno and hash
    // against this device's row, and clears what `push` said it carried.  `hash` is what the next
    // push names to delete this one.
    void mark_device_group_pushed(const DeviceGroupPush& push, std::string hash);

    // Builds and uploads the device group message, if one is owed and this device is registered.
    //
    // Does nothing while a push is already in flight: the message is built from a snapshot of the
    // database, so a second one built before the first is confirmed would carry the same records
    // and race it to say what was pushed.
    void push_device_group();
};

}  // namespace session::core
