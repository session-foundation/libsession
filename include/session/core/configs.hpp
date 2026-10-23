#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <session/config/namespaces.hpp>
#include <session/types.hpp>
#include <span>
#include <string>
#include <vector>

#include "component.hpp"
#include "swarm_message.hpp"

namespace session::config {
class ConfigBase;
class Contacts;
class ConvoInfoVolatile;
class Local;
class UserGroups;
class UserProfile;
}  // namespace session::config

namespace session {
class TestHelper;
}  // namespace session

namespace session::core {

/// This account's synced configuration: what it knows about itself, its contacts and its
/// conversations, in the form its other devices share.
///
/// Core owns these because everything mechanical about them is Core's work -- retrieving them from
/// their namespaces, merging, keeping the dumps, pushing what changed -- and none of that requires
/// knowing what a contact or a conversation actually is.  Deciding what the contents *mean*, and
/// reconciling them into something queryable, belongs to the layer above, which reads these objects
/// and is told when they change.
///
/// The configs are built on first use rather than during init(), because they are encrypted to the
/// account key and a Core opened with `defer_account` does not have one yet.  Nothing can reach
/// them before an account exists in any case: a network cannot be attached without one, so neither
/// polling nor pushing can run, and a direct caller gets the same `no_account` any other
/// account-dependent call would throw.
///
/// **Every method here belongs to Core's loop**, with no exceptions of the kind Globals has: there
/// is no self-contained query on this class.  The accessors hand out a reference into an object
/// that `merge()` rewrites on the loop as poll results arrive, and building them is itself lazy,
/// so a caller on another thread races either the construction or the merge.  A debug build
/// asserts it.
///
/// An application does not reach these directly.  `session::client::Client` wraps the parts it
/// needs -- `display_name()` and the rest of "our own account" -- and does the hop for the caller;
/// anything else wanting a config from another thread does the same thing, rather than reading one
/// from where it happens to be standing.
class Configs : public detail::CoreComponent {
    friend class session::TestHelper;

    std::unique_ptr<config::UserProfile> _user_profile;
    std::unique_ptr<config::Contacts> _contacts;
    std::unique_ptr<config::ConvoInfoVolatile> _convo_info_volatile;
    std::unique_ptr<config::UserGroups> _user_groups;
    std::unique_ptr<config::Local> _local;

    bool _loaded = false;

    // Depth of nested Batch guards.
    int _batch_depth = 0;

    // Namespaces a merge has altered since the last time the application was told, deduplicated.
    // Held rather than reported immediately so that one poll carrying several config namespaces
    // produces one notification of a settled state rather than several of partial ones.
    std::vector<config::Namespace> _changed;

    // Writes the dumps of everything that changed and schedules a push if one is owed -- unless a
    // Batch is holding it back, in which case releasing that Batch is what runs it.
    void _flush();

    // Debounce state: when the current run of changes began, and when the last one arrived.
    std::chrono::steady_clock::time_point _burst_started{};
    std::chrono::steady_clock::time_point _last_change{};
    bool _push_scheduled = false;
    bool _push_in_flight = false;

    // The network's callbacks outlive this component and are owned by the Network rather than by
    // Core's job queue, so cancelling the queue cannot reach them: they capture a weak reference
    // to this and do nothing if it has expired.  That is what stops a push completing into a
    // destroyed Core -- the queue only takes over once the callback has safely got that far.
    std::shared_ptr<int> _alive = std::make_shared<int>(0);

    // Which subrequests belong to which config, so that a result can be matched back to the config
    // whose push produced it.  A sequence answers positionally, so this is the only link.
    struct Pending {
        config::ConfigBase* conf;
        config::seqno_t seqno;
        size_t first;
        size_t count;
    };

    // Queues a flush for the next turn of the loop, once however many times it is called before
    // then.  Every accessor that hands out a config calls this; see the note above them.
    void _schedule_settle();
    bool _settle_scheduled = false;

    void _schedule_push();
    void _arm_push_timer(std::chrono::milliseconds delay);
    void _push_if_due();
    void _send_push();

    // Constructs the configs from their stored dumps, or empty if there are none.  Requires an
    // account; throws globals::no_account if there is not one yet.
    void _load();

    // Writes `conf`'s dump if it has changed since the last one was written.
    void _store(config::ConfigBase& conf);

    // The configs that have somewhere to be pushed to, which is every one except Local.
    //
    // Local already reports needs_push() as false unconditionally, so this is not what stops it
    // being pushed -- it is what stops that from being the only thing that does.  The push path
    // asks "which configs go to a swarm", and answering that by trusting each config to decline
    // would make a config with no destination indistinguishable from one with nothing to say.
    std::vector<config::ConfigBase*> _pushable();

  public:
    // Both defined where the config types are complete, so that this header can forward-declare
    // them rather than making every consumer of core.hpp parse all five.  The constructor needs it
    // as much as the destructor does: its cleanup path has to be able to destroy the members.
    explicit Configs(Core& core);
    ~Configs();

    config::UserProfile& user_profile();
    config::Contacts& contacts();
    config::ConvoInfoVolatile& convo_info_volatile();
    config::UserGroups& user_groups();

    /// Device-local settings.  Shares the config machinery -- and so gets dumped and reloaded like
    /// the rest -- but is never pushed anywhere and never merges anything.
    config::Local& local();

    /// Every config, for the operations that do not care which is which.
    std::vector<config::ConfigBase*> all();

    /// The config kept in the given namespace, or nullptr if that namespace holds none.
    ///
    /// A fixed mapping rather than a search over `storage_namespace()`, deliberately: Local reports
    /// UserProfile's namespace as a stand-in for the one it does not have, so a search would find
    /// two configs for namespace 2 and the answer would depend on the order it looked.
    config::ConfigBase* for_namespace(config::Namespace ns);

    /// Merges config messages retrieved from `ns` into the config kept there, and dumps the result
    /// if the merge changed it.
    ///
    /// A merge can leave the config needing a push even when nothing local changed, since resolving
    /// a conflict between two other devices produces a new state that only this device holds.
    void merge(config::Namespace ns, std::span<const SwarmMessage> messages);

    /// Holds back dumping until a run of changes is finished.
    ///
    /// A config is dumped when it changes, which is right when nobody knows any better -- but a
    /// caller working through a batch of messages does know better, and dumping between them writes
    /// intermediate states nobody will ever read.  Holding one of these says "there is more
    /// coming"; releasing it says "now".
    ///
    /// This is what keeps the timer honest.  Debouncing is a guess at where a batch ended, and a
    /// guess is only needed where nothing knows: with a batch held across the work, dumping happens
    /// once at a boundary that is *known*, and the timer is left to cover only the changes that
    /// arrive with no such boundary to see.
    ///
    /// Nests: `merge()` holds one itself, so a caller already holding one across several merges
    /// still gets a single flush at the end.  Neither copyable nor movable, so it cannot outlive
    /// the scope it was declared in.
    class Batch {
        Configs& _configs;

      public:
        explicit Batch(Configs& configs);
        ~Batch();
        Batch(const Batch&) = delete;
        Batch& operator=(const Batch&) = delete;
    };

    [[nodiscard]] Batch batch() { return Batch{*this}; }

    /// Writes the dump of every config that has changed since it was last written.  Immediate: a
    /// held Batch does not defer this, since asking for it explicitly is the point.
    void store_dumps();

    /// Whether any config holds changes that have not reached the swarm.
    bool needs_push();

    /// How long a push waits for changes to stop arriving before going out, and the longest it will
    /// wait once they started.  A run of changes coalesces into one request rather than one per
    /// change; the cap is what stops a steady trickle deferring the push indefinitely.
    ///
    /// Settable mostly so a test does not have to spend real seconds proving it.
    std::chrono::milliseconds push_debounce = std::chrono::seconds{2};
    std::chrono::milliseconds push_max_delay = std::chrono::seconds{10};

    /// Writes the defaults a brand-new account starts with.
    ///
    /// Only for an account created here.  Restoring one deliberately does not come through here:
    /// the real values are about to arrive from the swarm, and writing local ones first would put
    /// them in competition with what the account already says.
    void initialise_new_account();

    /// Set false to stop config changes from ever leaving this device.
    ///
    /// For working against a real account without risking it: everything else carries on as normal
    /// -- changes are held, dumped, and reported as owed by needs_push() -- but nothing is sent, so
    /// nothing this device does can reach the account's other devices or overwrite what they hold.
    ///
    /// Deliberately not a pretence that the push happened: `needs_push()` keeps saying yes, so the
    /// state is visibly unpublished rather than looking settled.  Turning it back on lets the next
    /// push carry everything accumulated since.
    bool push_enabled = true;

    /// Pushes whatever is owed immediately, rather than waiting out the debounce.
    ///
    /// Everything dirty goes in one `sequence` request: a store per config message, then a single
    /// delete naming every hash those stores obsolete.  Only what this account owns goes in it --
    /// a group's configs live under a different pubkey and are pushed separately even if their
    /// swarm turns out to be the same one, because a request that carried both would tell that
    /// swarm the two belong to the same person.
    ///
    /// Does nothing if a push is already in flight; the one in flight re-checks when it completes.
    void push_now();
};

}  // namespace session::core
