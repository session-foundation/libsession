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
/// Which of the two lists a conversation sits in.
///
/// `none` is a real answer rather than a missing one: a hidden conversation is in neither list, and
/// so is one the subscriber has not been shown.
enum class ConversationList {
    none,
    conversations,
    requests,
};

/// Where a conversation was, and where it belongs now.
///
/// Enough to apply on its own, and it reads as the two steps it is:
///
///     if (p.from != ConversationList::none) remove(p.from, convo.id());
///     if (p.to   != ConversationList::none) insert(p.to, std::move(convo), p.after);
///
/// `from` is the list the subscriber was last *told* this row was in, which is what it is holding
/// rather than what the database now says. It saves searching the list the row did not come from;
/// it does not save finding the row, which is a lookup by id either way.
///
/// The two lists are ordered differently -- conversations by `priority DESC, last_activity DESC,
/// id` and requests by `last_activity DESC, id`, with no priority term -- so which list a position
/// is in is part of the position rather than a detail.
struct ListPlacement {
    /// Where the subscriber is holding this row, so it knows which list to take it out of.
    /// `none` when it is holding it nowhere: a row it has not been shown, or one that was hidden.
    ConversationList from = ConversationList::none;
    /// Where it belongs now.  `none` means neither list, which is what hiding does -- then it is
    /// only removed.
    ConversationList to = ConversationList::none;
    /// The row it now follows in `to`; unset means first in that list.  Meaningless, and always
    /// unset, when `to` is `none`.
    std::optional<ConversationId> after;
};

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
/// The conversation list an application maintains from these is expected to be *complete*: the
/// order is given as a whole list, so a partial one cannot be placed in it.  Showing only part of
/// it is fine, holding only part of it is not.
///
/// The order itself is **ours, not the application's**.  Every handler that carries a list carries
/// it already ordered, so an application never has to sort, and should not: the two lists are not
/// sorted the same way and a comparator copied from one gets the other wrong.
struct callbacks {
    /// A conversation now exists that did not before.
    ///
    /// Carries where it belongs, on the same terms as `conversation_updated`: `from` is normally
    /// `none`, since a row that did not exist was not being held anywhere.
    std::function<void(AnyConversation&&, ListPlacement&&)> conversation_added;

    /// A conversation's contents changed: a new or edited message, a name, an unread count, its
    /// last activity.  Fired once with the conversation's settled state rather than once per
    /// underlying change, so a poll that delivers fifty messages to one conversation fires this
    /// once.
    ///
    /// The second argument says where the row was and where it belongs now, which is enough to
    /// apply without consulting anything: remove it from `from`, insert it into `to`.
    ///
    /// **Applying these in order is what keeps a list correct.**  Each one places a row relative to
    /// another, so one applied out of order, or skipped, leaves the list wrong with nothing to
    /// detect it.  A subscriber that has not read the list once with `conversations()` has nothing
    /// to place rows into.
    std::function<void(AnyConversation&&, ListPlacement&&)> conversation_updated;

    /// A conversation is gone and should be dropped from the list it is in, which is the second
    /// argument -- `none` if it was never shown in one.  Saves searching both.
    std::function<void(ConversationId&&, ConversationList)> conversation_removed;

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
};

}  // namespace session::client
