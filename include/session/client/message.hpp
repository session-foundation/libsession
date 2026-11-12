#pragma once

#include <compare>
#include <cstdint>
#include <memory>
#include <optional>
#include <session/client/attachment.hpp>
#include <session/client/conversation_id.hpp>
#include <session/clock.hpp>
#include <session/util.hpp>
#include <string>
#include <vector>

namespace session::client {

/// Delivery state of an outgoing message.  Incoming messages have no send state.
enum class SendState : int {
    /// Queued locally; Core has not yet been able to dispatch it (typically waiting on a PFS key
    /// fetch for the recipient).
    pending = 0,

    /// Handed to the swarm; awaiting confirmation.
    sending = 1,

    /// Accepted by a swarm node.
    sent = 2,

    /// Terminal failure: the swarm rejected it, there was no network, or encryption failed.
    failed = 3,

    /// The application exited while this send was in flight, so its outcome is unknown — it may or
    /// may not have reached the swarm.  Set at startup for anything left in pending or sending,
    /// because Core's in-flight send queue does not survive a restart.
    interrupted = 4,

    /// Terminal, and unlike `failed` not worth trying again: something the message needs is gone
    /// rather than merely unreachable.  Currently that means an attachment whose file is no longer
    /// where it was — retrying re-reads the same path and will fail identically every time.
    ///
    /// Kept apart from `failed` so that an application knows which failures to offer a retry for,
    /// and which to offer only deletion.
    unsendable = 6,

    /// Attachments are being uploaded to the file server.  The message exists and is displayable,
    /// but nothing has gone to a swarm yet: it cannot, because the message has to carry the
    /// pointers the upload is still producing.  How far along that is, is reported to whoever asked
    /// for the send, through the progress handler they passed to send_message.
    uploading = 5,
};

/// A position in a conversation's message history, used to page backwards.  Ordering is by
/// timestamp then message id, so this is a stable cursor even when several messages share a
/// timestamp.
struct MessageCursor {
    sys_ms timestamp;
    int64_t id;
    std::strong_ordering operator<=>(const MessageCursor&) const = default;
};

/// How far a deletion went, for a message whose content has been removed.
enum class Deletion : int {
    here = 1,       ///< Deleted on this device; the copies elsewhere are untouched.
    everywhere = 2  ///< Deleted here, and asked to be deleted wherever else it reached.
};

/// A message to send: everything about it that is the caller's to decide.
///
/// One struct rather than an overload per combination, so that gaining an optional field costs a
/// field rather than doubling the overload set — which it had already done once.  Designated
/// initialisers make a call say which parts it is using:
///
///     convo->send_message({.body = "hi"}, await);
///     convo->send_message({.body = "look", .attachments = {...}}, on_upload, await);
///     convo->send_message({.body = "agreed", .reply_to = other_id}, await);
struct OutgoingMessage {
    std::string body;

    /// Files to send with it.  See the attachment overloads' notes on what sending these costs and
    /// how progress is reported: with any attachment present, sending becomes two-stage.
    std::vector<OutgoingAttachment> attachments;

    /// The message this answers, by local id.
    ///
    /// An id rather than the author and timestamp the wire wants, because everything beyond the id
    /// is ours to look up — and a caller holding a message it is looking at has the id and nothing
    /// else, so asking for the rest would be asking it to guess.
    ///
    /// @throws std::invalid_argument, on the calling thread, if this names a message that does not
    /// exist or that belongs to another conversation.
    std::optional<int64_t> reply_to;
};

struct Message;

/// What a message is a reply to.
///
/// The wire addresses a message by who sent it and when, never by an id, so `author` and
/// `timestamp` are always known even when the message itself is not — which is what lets a client
/// name the author over an "original message not found" line.
struct Reply {
    /// Who wrote the replied-to message, and when they sent it.
    b33 author;
    sys_ms timestamp;

    /// Whether we have that message at all.  Unset means we do not — never that there is no reply;
    /// `Message::reply` being unset means that.
    ///
    /// It can become set on a later read, once the message arrives, so do not cache it alongside
    /// the message.  You are told when it changes: the quoting message is re-reported through
    /// `messages_updated`.
    std::optional<int64_t> message_id;

    /// The message itself, when it was loaded.
    ///
    /// The whole message rather than a summary of it, because every summary is missing whatever a
    /// caller needs next: a quoted message with an image and no text has nothing to show from a
    /// body alone, and `deleted`, `gallery` and the attachment list are all things a reply line may
    /// legitimately want to draw.
    ///
    /// A `shared_ptr` rather than an `optional` because `Message` contains this struct: an optional
    /// would need a complete type, and a `unique_ptr` would make `Message` non-copyable when it is
    /// copied into every callback and every page.
    ///
    /// **Null in a nested reply, even when `message_id` is set.** Loading goes one level deep, so
    /// reading a message cannot walk an arbitrarily long chain of replies — a message reached
    /// *through* a reply carries the reference to what it answered but not the answer itself.  That
    /// is why `message_id` is a separate field rather than read off this one: "we do not have it"
    /// and "it was not loaded here" are different answers, and a caller wanting the second resolved
    /// has the id to ask with.
    ///
    /// This is our own stored copy of the message, never the sender's. The wire has fields for the
    /// sender's snippet of it, which current clients do not populate and which we would not trust
    /// if they did: a forged one would put chosen words on screen attributed to someone else.
    std::shared_ptr<const Message> message;
};

struct Message {
    /// Client-assigned, database-local message id.  Stable for the life of the message; not the
    /// swarm hash and not Core's send id.
    ///
    /// Never reused, even after the message is deleted, so an id held across a deletion can only
    /// fail to find its message, never find a different one.
    int64_t id;

    ConversationId conversation;

    /// 0x05-prefixed session ID of the sender; our own account ID for outgoing messages.
    b33 sender;

    bool outgoing;

    /// The message's authenticated timestamp (the Content `sigTimestamp`), which is what history
    /// is ordered by — not the swarm's upload time.
    sys_ms timestamp;

    /// The message body.  Empty for a message that carries no text (e.g. attachments only).
    std::string body;

    /// Files attached to the message, in the order they appear in it.  Populated for every message
    /// a query returns, so a caller never has to ask a second time to find out whether there are
    /// any -- an attachments-only message is one with an empty `body` and a non-empty list here.
    std::vector<Attachment> attachments;

    /// Delivery of the copy sent to the recipient — what "did it arrive" ordinarily means, and
    /// what a message list normally shows.  Unset on an incoming message.
    std::optional<SendState> send_state;

    /// Delivery of the copy deposited in our own swarm, which is how our other devices come to see
    /// a message we sent.  A separate send, retried separately, so it can still be pending when the
    /// recipient already has the message — worth surfacing somewhere detailed rather than in the
    /// message list, since it says nothing about whether the message arrived.
    ///
    /// Unset on an incoming message, and on a note to self, where the recipient's swarm is our own
    /// and `send_state` already describes the only send there was.
    std::optional<SendState> sync_send_state;

    /// Swarm-assigned hash of the copy of this message held in *our own* swarm: for an incoming
    /// message the one we retrieved, and for an outgoing one the copy we deposit for our other
    /// devices (which for a note to self is the only copy there is).  The copy sent to someone
    /// else is stored in their swarm under a different hash, which is not reported here.
    ///
    /// Unset for an outgoing message that has not been stored yet, and for one stored by a build
    /// whose storage server did not report a hash.
    std::optional<std::string> hash;

    /// Whether this message *can* be shown as a gallery rather than as a list of attachments.
    ///
    /// Derived, never stored, and the rule is ours: today it is "has attachments, and every one of
    /// them has a content type Session displays as an image" (image::displayable_image_types, which
    /// matches what libsession will decode), but it may gain a size ceiling.  Deriving it means a
    /// change to that rule takes effect on old messages too, rather than leaving stored answers
    /// from whatever the rule used to be.
    bool gallery_viewable = false;
    /// Whether it *is* being shown that way.
    ///
    /// Stored, because it is a decision rather than a property: it is made when the message is
    /// processed — on if the conversation was auto-downloading then — and the conversation's
    /// setting may have changed since, so recomputing it later would not give the same answer.
    ///
    /// Never true when `gallery_viewable` is false: a stored decision that no longer agrees with
    /// the current rule is dropped rather than honoured, so a message that qualified under an older
    /// definition stops claiming to.
    bool gallery = false;

    /// What this message is a reply to, or unset if it is not one.
    std::optional<Reply> reply;

    /// Set once the message has been deleted, saying how far the deletion went.  The row survives
    /// so that a redelivery cannot resurrect it, and so that a message deleted only here can still
    /// be deleted everywhere afterwards.
    ///
    /// Everything the message said is gone when this is set: `body` is empty and `attachments` is
    /// empty, whatever it carried before.  What remains is who sent it and when, which is what a
    /// client needs to draw the gap where it was — and `hash`, which is what keeps it deleted.
    std::optional<Deletion> deleted;

    MessageCursor cursor() const { return {timestamp, id}; }
};

}  // namespace session::client
