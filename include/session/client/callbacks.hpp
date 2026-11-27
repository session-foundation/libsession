#pragma once

#include <functional>
#include <optional>
#include <session/client/attachment.hpp>
#include <session/client/conversation.hpp>
#include <session/client/conversation_id.hpp>
#include <session/client/handler.hpp>
#include <session/client/message.hpp>
#include <string>
#include <vector>

namespace session::client {

/// Notifications of everything the conversation layer changes, so that an application never has to
/// ask.  A caller sets the handlers it cares about and leaves the rest empty; an unset handler is
/// simply not called.
///
/// Every handler is given the new state outright rather than an identifier to go and fetch, which
/// is what makes a display bindable without reading anything back.  It also makes applying one
/// twice harmless, which in turn makes startup race-free — see the Client constructor.
///
/// Handed to Client at construction and fixed thereafter, exactly as core::callbacks is.  There is
/// deliberately no way to register a second set: a process that wants to fan these out to somewhere
/// else — a notification daemon, a log — does that fanning out itself, which it has to anyway once
/// the other end is a separate process.
///
/// **Handlers run on Core's event loop**, not the caller's thread.  A handler must not block and
/// must not throw (an escaping exception is caught and logged, and the change is not redelivered).
/// What a handler receives is its own: it was read for this delivery and nothing else holds it, so
/// a UI moves it into its own queue and wakes its render thread.  The signatures say which is
/// which — what is given is taken by rvalue reference, what is lent by `const&`.  The two progress
/// handlers are the ones that lend, because they report repeatedly against one captured id and a
/// handler that moved from it would empty what the next report needs.
///
/// A handler may declare such a parameter as `T&&`, `const T&` or `T`, whichever suits it: only the
/// last constructs anything, and a handler that just reads pays nothing.  (`T&` is the one form
/// that will not bind.)  The `&&` is not perfect forwarding despite the spelling — `std::function`
/// is not a template on its argument — it is a promise by the caller that the object is spent
/// afterwards.
///
/// The conversation list an application maintains from these is expected to be *complete*: ordering
/// is a comparison against every other conversation, so a partial list cannot be sorted.  Showing
/// only part of it is fine, holding only part of it is not.
struct callbacks {
    /// A conversation now exists that did not before.
    std::function<void(AnyConversation&&)> conversation_added;

    /// A conversation's contents changed: a new or edited message, a name, an unread count, its
    /// last activity.  Fired once with the conversation's settled state rather than once per
    /// underlying change, so a poll that delivers fifty messages to one conversation fires this
    /// once.
    std::function<void(AnyConversation&&)> conversation_updated;

    /// A conversation is gone and should be dropped from the list.
    std::function<void(ConversationId&&)> conversation_removed;

    /// Priorities changed — a pin, unpin, hide or unhide — carrying the whole list in its new
    /// order.  A replacement rather than a description of what moved, because one config update
    /// from another device can repin, reveal and hide arbitrarily many conversations at once, and
    /// because a replacement cannot leave the application subtly out of step the way a missed
    /// delta would.
    std::function<void(std::vector<AnyConversation>&&)> conversation_list_replaced;

    /// The message requests changed, carrying the whole list of them, for the same reasons and with
    /// the same guarantees as the above.
    ///
    /// The two lists are disjoint and a conversation moves between them, so approving one fires
    /// both: it left the requests and joined the conversations.  `conversation_added` and the rest
    /// are shared between them — a request is a conversation in every respect except which list it
    /// belongs to — and `Conversation::request` is what says which one a given handler is about.
    std::function<void(std::vector<AnyConversation>&&)> request_list_replaced;

    /// Messages were added, whether received or sent from here.
    ///
    /// See `messages_updated` for what the batch is, how it is ordered, and why it is not confined
    /// to one conversation; all of that applies here too.
    std::function<void(std::vector<Message>&&)> messages_added;

    /// Existing messages changed: a send state, whether one is shown as a gallery, when its
    /// recipient saved an attachment, or an attachment's `AttachmentAvailability`.
    ///
    /// **Ordered oldest first**, by the timestamp history is ordered on and then by id — the
    /// reverse of `Conversation::messages`, which pages backwards from the newest. A handler
    /// applying these in order ends up in the same state as one that reloaded.
    ///
    /// **A batch may span conversations**, so each `Message` carries its own `conversation` rather
    /// than the call naming one. One cause routinely reaches several: a file is one file, and
    /// evicting it, fetching it, or finding it unfetchable changes every message showing it,
    /// wherever those are.
    ///
    /// Reported for **every** message in **every** conversation, not only whichever one is on
    /// screen: there is no notion here of what an application is showing, so deciding what to
    /// redraw is the application's.
    ///
    /// A message can also be reported because something it *quotes* changed, since a reply draws a
    /// preview of its target — so a handler sees messages it never asked about.
    std::function<void(std::vector<Message>&&)> messages_updated;

    /// Messages were deleted from a conversation, and anything displaying its history should read
    /// it again.
    ///
    /// Unlike `conversation_list_replaced` this carries only the conversation and not the messages
    /// themselves: a history is unbounded, and an application showing one page of it has no use for
    /// the rest.  What deletes messages is a delete-before instruction, which can take any number
    /// of them at once and is not otherwise describable as a sequence of removals.
    std::function<void(ConversationId&&)> history_replaced;

    /// An attachment is being fetched that nobody asked for — see `Conversation::auto_download`.
    ///
    /// Only for background fetches.  A `save_attachment` reports to the caller that started it, and
    /// does not come through here: this handler means "something is happening you did not ask for",
    /// which is exactly what a display has no other way of learning.
    ///
    /// The first report of a transfer arrives when it is *started*, before anything has been sent
    /// to a server, carrying 0 of 0 — so a row can show that a fetch is beginning rather than
    /// appearing to do nothing until the first bytes land.  Exactly one report carries a `result`.
    ///
    /// Reports are rate limited (see `set_dispatch_interval`) to keep the cost off the
    /// application's thread.  That is all the limiting is for: how often a spinner turns is the
    /// application's own business, and it should not be reading motion into the arrival of these.
    std::function<void(const ConversationId&, const AttachmentProgress&)> attachment_progress;

    /// The same, for a display picture, which belongs to a conversation rather than to a message —
    /// so it carries no message or index and gets its own handler rather than a struct with two
    /// fields that are never filled in.
    ///
    /// Display pictures are always fetched, with no setting to turn that off, so this fires for
    /// every one that is not already cached.
    std::function<void(
            const ConversationId&,
            int64_t done,
            int64_t total,
            std::optional<Expected<void>> result)>
            display_picture_progress;

    /// Whether this Client has outbound work in flight changed: `true` when something started
    /// going out with nothing else under way, `false` when the last of it has finished, whichever
    /// way it finished.  The same value `Client::outbound_busy()` returns.
    ///
    /// For holding the process alive.  A user who sends and immediately leaves the app expects the
    /// message to go, and an operating system that suspends a backgrounded app stops it going; a
    /// platform holds a keep-alive -- a background task on iOS, an expedited job on Android -- from
    /// `true` until `false`, and can then let the process be suspended without losing anything.
    ///
    /// What counts as outbound work:
    ///
    /// - a message whose `send_state` is `pending`, `sending` or `uploading` -- queued, on its way
    ///   to the recipient's swarm, or with its attachments still going to the file server;
    /// - a message whose `sync_send_state` is one of those: the copy for our own swarm, which can
    ///   still be going after the recipient's has arrived;
    /// - a push of the account's configs that is scheduled or unanswered -- see
    ///   `core::Configs::push_pending()` -- such as the change of name, contact or read state
    ///   that was just made here.
    ///
    /// Anything else is idle, including a send that ended `sent`, `failed`, `interrupted` or
    /// `unsendable`.  Downloads do not count: nothing is lost if one is cut off, since asking again
    /// starts it again.  Nor does a config push that failed or has nowhere to go, which stays owed
    /// until something schedules another but is not, meanwhile, going to finish.
    ///
    /// Sends are read from the database, so they include any made by another Client on the same
    /// file.  At start-up there are none: anything a previous run left in flight is marked
    /// `interrupted` or `failed` before the first answer is taken.
    ///
    /// **Fires only on a change**, never twice running with the same value, and never at all for a
    /// Client that sends nothing.  It is not fired at construction to say "idle"; a Client starts
    /// idle, and a handler first hears of it when that stops being true.  A Client that is busy the
    /// moment it is built -- a new account's first config push -- reports `true` from inside the
    /// constructor, as anything else the constructor reports is.
    ///
    /// Like every handler here it runs through the dispatcher, so it arrives after the change and
    /// may arrive after a later one has already happened; the reports arrive in order, and the last
    /// one delivered is the current state.  A platform deciding at the moment the app backgrounds
    /// should read `outbound_busy()` there rather than relying on having seen the latest report.
    std::function<void(bool busy)> outbound_changed;
};

}  // namespace session::client
