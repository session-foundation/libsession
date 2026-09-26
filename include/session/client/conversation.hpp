#pragma once

#include <optional>
#include <session/client/attachment.hpp>
#include <session/client/conversation_id.hpp>
#include <session/client/handler.hpp>
#include <session/client/message.hpp>
#include <session/clock.hpp>
#include <session/config/expiring.hpp>
#include <session/config/notify.hpp>
#include <session/config/profile_pic.hpp>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace session::client {

class Client;

/// Enough of the most recent message to draw a conversation-list row, without reading the message.
///
/// A summary rather than the message itself, because a list row is not a message view: it wants a
/// line of text and a hint of what else is there, and handing over whole `Message`s to fill in a
/// column of one-liners costs a read per row for detail nobody draws.
///
/// The fields are independent, not alternatives — a message can carry a body *and* attachments, and
/// a row showing "look at this  📎2" needs both — so there is deliberately no single "kind" enum
/// here to switch on.
///
/// **Expect this to gain fields.**  Message kinds that are not yet modelled — call metadata, a
/// typing indicator — will describe themselves by adding to this struct, and adding a field is the
/// intended way to grow it: designated initialisers and defaults keep that source-compatible.  Two
/// consequences for a caller:
///
/// - Do not treat the fields you know as exhaustive.  "Empty body and no attachments" means *this
///   build* has nothing to say about the message, which today implies there is nothing to show, but
///   will later be how an unhandled kind looks.  A row that draws nothing in that case degrades
///   gracefully; one that asserts on it does not.
/// - Do not persist a preview, and do not compare two for equality to decide whether to redraw.  It
///   is a description of a message as this version understands it, and both of those turn a gained
///   field into a stale cache or a missed repaint.
struct MessagePreview {
    /// The message body, whole and untruncated.  Empty when the message carries no text, which is
    /// normal: a message can be attachments alone.  Truncation is left to the caller, since how
    /// much fits is a property of the row it is being drawn into and not of the message.
    std::string body;

    /// The name of each attachment, in the order the sender listed them, and empty for the whole
    /// message when it has none.
    ///
    /// One entry per attachment, so `filenames.size()` *is* the attachment count and the entries
    /// line up with `Attachment::index`.  An entry is an empty string when that attachment carries
    /// no name — the sender simply omits the field — so the names cannot be counted as a proxy for
    /// the attachments, and a row drawing them needs a fallback for the empty ones.
    ///
    /// Names but not types or sizes: a single-attachment row saying "invoice.pdf" is worth far more
    /// than one saying "1 file", while the rest of what an attachment is remains
    /// `Conversation::messages()`'s business.
    std::vector<std::string> filenames;

    /// True if we sent it, for a row that prefixes "You: ".
    bool outgoing = false;

    /// True if the attachments are a voice message, which a row usually names rather than counts.
    bool voice_message = false;

    /// True if there is at least one attachment and every one of them is an image, so a row can say
    /// "3 images" where it would otherwise say "3 files".  False when there are none at all.
    ///
    /// "Image" means a content type Session displays as one (image::displayable_image_types), the
    /// same rule as Message::gallery_viewable: an SVG or TIFF counts as a file.
    bool all_images = false;
};

/// A conversation: what it looks like, and everything you can do to it.
///
/// **The values are a snapshot; the operations are not.**  The fields were read when this was
/// handed to you, and the conversation may have moved on since — another device can rename, pin or
/// delete it at any moment.  The operations do not read the fields; they act through `id`, which
/// stays meaningful however old this object is.  So a stale object still does the right thing when
/// acted on, and only what it *says* can be out of date.  To see current values, ask for it again.
///
/// There is no way to obtain one that was never populated: `Client::conversation()` fetches one,
/// `conversations()` lists them, `open_dm()` makes one, and the callbacks hand them over — each of
/// those has read the database.  So an empty `display_name` means nobody knows their name, never
/// that this object has not looked yet.
///
/// Every operation comes in two forms: one taking a handler, which returns immediately and reports
/// later, and one taking `await`, which blocks the calling thread and throws instead of reporting.
/// See `await_t` for which to use where.
///
/// Cheap to copy and safe to hold, including on another thread — but it names a Client and must not
/// outlive it.
class Conversation {
  public:
    ConversationId id;

    /// Best known display name, or empty if none is known yet.
    ///
    /// For a DM this is the nickname we gave them if there is one, and otherwise the name they gave
    /// themselves — learned either from the `LokiProfile` on a message or from the Contacts config,
    /// whichever is the fresher.  Empty is normal and expected: an account we have seen but know
    /// nothing else about has no name, and the caller decides how to render that.
    std::string display_name;

    /// The most recent message that still says something, summarised for a list row.
    ///
    /// Unset when there is nothing to preview — the conversation has no messages, or every one it
    /// has was deleted.  So an *empty* `body` on a preview that is set means the message carries no
    /// text rather than that there is no message, which is the distinction a bare string could not
    /// make and the reason this is an optional.
    ///
    /// Deleted messages are skipped rather than reported: taking the newest one regardless would
    /// blank the row whenever the last thing said was later deleted, and what a list wants there is
    /// the last thing that was actually said.  A caller that wants the deleted message itself is
    /// asking about history, and should read it — `messages()` with `include_deleted`.
    std::optional<MessagePreview> last_preview;

    /// Timestamp of the most recent message, or the conversation's creation time if it has none.
    sys_ms last_activity;

    /// Count of incoming messages newer than the read watermark.
    int unread = 0;

    /// Deliberately marked unread — "come back to this" — rather than having unread messages.
    ///
    /// Independent of `unread`: it survives having read everything, which is what it is for, and
    /// reading the conversation is what clears it.  Synced, so it arrives from other devices too.
    bool marked_unread = false;

    /// Pinning, numerically identical to the value the Contacts and UserGroups configs sync: 0 is
    /// unpinned, a positive value is pinned with higher values first, and a negative value is
    /// hidden.
    ///
    /// Hidden is a statement about the *list*: `conversations()` omits them, so this is never
    /// negative on anything reached that way.  Naming a conversation still reaches one, since that
    /// is not the same as asking what the list contains — and it is how a hidden conversation is
    /// reached at all.
    ///
    /// Conversations sort by priority before recency, and equal priorities form a block that sorts
    /// among itself by last_activity — so pinning several conversations together keeps them at the
    /// top while still letting the most recently active of them lead.
    int priority = 0;

    /// When to notify about this conversation.  `defaulted` means the application's own default
    /// applies; `mentions_only` is a group notion and reads as `all` on a DM.
    ///
    /// Independent of `mute_until`, and overridden by it while that is in the future.
    config::notify_mode notifications = config::notify_mode::defaulted;

    /// Notifications are suppressed until this moment, whatever `notifications` says.  The epoch
    /// means not muted — which is not the same as `notify_mode::disabled`, since a mute expires and
    /// a UI shows it as "muted until …" rather than as off.
    std::chrono::sys_seconds mute_until{};

    /// Disappearing messages.  The timer is meaningless when the mode is `none`, and the mode is
    /// what a UI has to say out loud: after-send and after-read are a different promise to the
    /// person you are talking to, not two spellings of the same one.
    config::expiration_mode exp_mode = config::expiration_mode::none;
    std::chrono::seconds exp_timer{0};

    /// Where this conversation's picture is, if we know of one: the url it was uploaded to and the
    /// key that decrypts it.  Empty url means there is no picture, or none we have been told about.
    ///
    /// Enough to know whether there is one and whether it has changed — the url is what changes
    /// when somebody updates their picture — without fetching anything.  `Client::profile_picture`
    /// is what turns it into bytes.
    ///
    /// On the base rather than on `DM` because every kind of conversation can have one; only a DM's
    /// is wired up today, so this is empty for a group or community until that lands.
    config::profile_pic picture;

    /// What to fetch from this conversation without being asked.
    ///
    /// Unset means nobody has been asked yet, which is a different thing from having been asked and
    /// said no: Session asks within a conversation the first time and remembers the answer, and a
    /// client can only do that if it can tell the two apart.  Nothing is fetched while it is unset.
    ///
    /// Device-local and never synced.  Auto-downloading everything on a desktop and nothing on a
    /// phone is the case this exists for.
    std::optional<AutoDownload> auto_download;

    /// The display name if known, otherwise the conversation's string id — a reasonable default
    /// for a caller that has no better fallback of its own.
    std::string name_or_id() const { return display_name.empty() ? id.to_string() : display_name; }

    Conversation(Client& client, ConversationId id) : id{std::move(id)}, _client{&client} {}

    // -- Reading ------------------------------------------------------------------------------

    /// A window of history, newest first.  Pass the `cursor()` of the last message of a page as
    /// `before` to fetch the next (older) page; the message at the cursor is not repeated.
    ///
    /// Deleted messages are left out unless `include_deleted` is passed.  Out by default because a
    /// deleted message carries no body, so a caller that has not thought about `Message::deleted`
    /// would draw an empty row that looks like a bug.  A client that wants to show "message
    /// deleted" asks for them, and gets them in place, in order.
    ///
    /// Filtered in the query rather than left to the caller, because the alternative breaks paging:
    /// a page of 50 that is mostly deleted would hand back a handful of rows with nothing to say
    /// that another page is warranted.
    ///
    /// @throws std::invalid_argument if `limit` is not positive.  In particular there is no value
    /// meaning "all of it" -- SQLite reads `LIMIT -1` that way, this does not.  History grows
    /// without bound, so reading all of it means paging with `before` until a page comes back
    /// short.
    void messages(result_function<std::vector<Message>> cb) const;
    void messages(int limit, result_function<std::vector<Message>> cb) const;
    void messages(
            int limit,
            std::optional<MessageCursor> before,
            result_function<std::vector<Message>> cb) const;
    void messages(
            int limit,
            std::optional<MessageCursor> before,
            bool include_deleted,
            result_function<std::vector<Message>> cb) const;
    std::vector<Message> messages(await_t) const;
    std::vector<Message> messages(int limit, await_t) const;
    std::vector<Message> messages(int limit, std::optional<MessageCursor> before, await_t) const;
    std::vector<Message> messages(
            int limit, std::optional<MessageCursor> before, bool include_deleted, await_t) const;

    /// Removes every deleted message's leftover row from this conversation, and says how many went.
    ///
    /// A deletion leaves a row behind deliberately — see `Client::delete_message` — and this is
    /// what finally removes them, for a client that would rather not accumulate them or show them.
    ///
    /// **This can bring a message back.** A message deleted only here is still in our swarm, and
    /// that row's swarm hash is the only thing that recognises it if it is delivered again — which
    /// a storage server makes likely rather than hypothetical, since it stops honouring a
    /// `last_hash` once that has expired and answers the next poll with the whole retention window.
    /// Removing the row removes the memory of it, and the message returns looking new.
    ///
    /// The alternative — deleting our swarm copy too, so there is nothing to come back — is worse
    /// and is deliberately not done: that copy is what our *other devices* poll, so destroying it
    /// would turn "delete for me" into "delete on every device I own", including devices that have
    /// never seen the message and then never would.
    ///
    /// Messages we sent and deleted everywhere are not exposed to this: their swarm copy is already
    /// gone, so there is nothing left to return.
    void purge_deleted(result_function<size_t> cb);
    size_t purge_deleted(await_t);

    // -- Read state ---------------------------------------------------------------------------

    /// Marks incoming messages up to and including `up_to` as read, moving the unread watermark
    /// forward.  Passing nullopt marks everything currently stored as read — which is not the same
    /// as parking the watermark at infinity: a message that arrives afterwards is still unread,
    /// even if its timestamp is older than the one we just read to.
    ///
    /// Never moves the watermark backwards.  Clears `marked_unread`, since reading the conversation
    /// is the thing that was being asked for.
    void mark_read(result_function<> cb);
    void mark_read(std::optional<sys_ms> up_to, result_function<> cb);
    void mark_read(await_t);
    void mark_read(std::optional<sys_ms> up_to, await_t);

    /// Marks the conversation unread, or clears that — the deliberate "I want to come back to this"
    /// rather than a count of messages.  Synced, so it follows you between devices.
    void set_marked_unread(bool unread, result_function<> cb);
    void set_marked_unread(bool unread, await_t);

    // -- Settings -----------------------------------------------------------------------------

    /// Sets pinning: 0 unpinned, positive pinned with higher values first, negative hidden.
    ///
    /// Reported to subscribers as `conversation_list_replaced`, not as an update to the one
    /// conversation, because hiding removes a conversation from the list and unhiding returns it —
    /// so what changed is the list, not a row in it.
    void set_priority(int priority, result_function<> cb);
    void set_priority(int priority, await_t);

    /// Sets when to notify, and until when to stay quiet.  Separate calls because they are separate
    /// decisions: muting until Monday does not change what you want notified after Monday, and a UI
    /// that offered them together would have to invent an answer for the other one.
    ///
    /// A `mute_until` in the past, or the epoch, is not muted.
    void set_notifications(config::notify_mode mode, result_function<> cb);
    void set_notifications(config::notify_mode mode, await_t);
    void set_mute_until(std::chrono::sys_seconds until, result_function<> cb);
    void set_mute_until(std::chrono::sys_seconds until, await_t);

    /// Sets the disappearing-message mode and timer together, because neither means anything
    /// alone: a timer with no mode does not expire, and a mode with no timer has nothing to count.
    /// `expiration_mode::none` clears the timer whatever is passed with it.
    void set_expiry(config::expiration_mode mode, std::chrono::seconds timer, result_function<> cb);
    void set_expiry(config::expiration_mode mode, std::chrono::seconds timer, await_t);

    /// Sets what this conversation fetches without being asked.
    ///
    /// Device-local: unlike every other setting here, this one does not follow the account, because
    /// it is about what this machine's bandwidth and disk are for.  Auto-downloading everything on
    /// a desktop and nothing on a phone is the case it exists for.
    ///
    /// Calling this is also what records that the question has been asked at all, so a client that
    /// prompts on first use should call it with whatever answer it was given — `none` included,
    /// since that is not the same as never having asked, and only the latter should prompt again.
    void set_auto_download(AutoDownload mode, result_function<> cb);
    void set_auto_download(AutoDownload mode, await_t);

    // -- Sending ------------------------------------------------------------------------------

    /// Sends a message, storing it immediately and dispatching it via Core.  Yields the Client
    /// message id of the stored row, which is what subsequent `messages_updated` reports carry as
    /// delivery progresses.
    ///
    /// See `OutgoingMessage` for what a message can carry.  With no attachments this stores and
    /// dispatches in one step; with any, sending becomes two stages, described below.
    ///
    /// Sending a message carrying files turns sending into two stages: each attachment is
    /// encrypted and uploaded to the file server, and only then is the message — now able to name
    /// where those files live — dispatched to the swarms.
    ///
    /// Returns as soon as the row is stored, as the plain overload does, so the message is
    /// displayable immediately; it sits in `SendState::uploading` until the uploads finish and
    /// moves on to the ordinary send states from there.  An upload that fails fails the message,
    /// leaving it in `SendState::failed` with nothing sent.
    ///
    /// `on_upload` follows one attachment, identified by `index`, its position in `attachments`:
    ///
    /// - `result` unset — under way.  `sent`/`total` are encrypted bytes.  The first such report
    ///   for an attachment is always 0/0 and means it has started rather than that it has sent
    ///   nothing: it comes before the transfer is established, which is what tells an attachment
    ///   being worked on from one still waiting its turn.  The size is not known until then, so a
    ///   progress bar is sized from the first report carrying a non-zero total.
    /// - `result` holding success — done, and the file server gave us an id for it.  Note this is
    ///   the only thing that means done: `sent == total` merely means the last byte was
    ///   acknowledged, and the server's decision to accept the file arrives after that.
    /// - `result` holding an error — that attachment failed: `err::attachment_file_missing` if its
    ///   file has gone (the message is then `SendState::unsendable`), `err::network_unavailable`
    ///   with no network attached, and otherwise `err::upload_failed` with the status in the
    ///   message.  The message fails as a whole, but this is reported per attachment, so a list of
    ///   them can mark the one that broke rather than all of them.
    ///
    /// Reports for one attachment arrive in order — progress, then exactly one result — but
    /// reports for different attachments may interleave, and a failure does not stop the others
    /// being reported.  An attachment that never produces a result was not attempted, or had not
    /// finished when the message failed; either way that is not something to read as success.
    ///
    /// It is taken here rather than through `callbacks` because it belongs to this call: those
    /// handlers report what the network did to us, whereas this reports how something we asked for
    /// is going, and a caller passing it here can bind whatever it wants to update without matching
    /// an id back to it.
    ///
    /// Progress fires as often as the transfer reports, which on a fast upload is often; coalescing
    /// is the caller's to do, since dropping intermediate values loses nothing.  Like the
    /// `callbacks` handlers it runs on Core's event loop, so it must not block or throw — and note
    /// it can fire before this function returns, so it must not depend on anything the caller sets
    /// up afterwards.
    ///
    /// The files are read at this point, not when they were attached, so they must still exist.
    /// Nothing about them is stored: what persists is the message, whose content names the uploaded
    /// copies.  Re-sending a failed message therefore uploads again.
    ///
    /// @throws std::invalid_argument if any attachment's file cannot be opened or exceeds the file
    /// server's limit, or if `reply_to` names a message that does not exist or belongs to another
    /// conversation; thrown on the calling thread, before anything is stored or dispatched.
    using upload_progress = std::function<void(
            size_t index, int64_t sent, int64_t total, std::optional<Expected<void>> result)>;
    void send_message(OutgoingMessage msg, upload_progress on_upload, result_function<int64_t> cb);
    void send_message(OutgoingMessage msg, result_function<int64_t> cb);
    int64_t send_message(OutgoingMessage msg, upload_progress on_upload, await_t);
    int64_t send_message(OutgoingMessage msg, await_t);

    // -- Destroying ---------------------------------------------------------------------------
    //
    // Named for what a user is choosing rather than for what happens underneath — "delete
    // conversation" and "delete contact" differ by what they leave behind, not by how they delete.
    // They are composed here, and not left to a UI to assemble out of smaller pieces, because every
    // Session client has to compose them the same way: which fields a deletion resets, and what it
    // tells other devices, is part of what the operation *is*, and three clients each deriving it
    // separately is three chances to diverge.
    //
    // The deletion is *synced as an instruction*, not as a local act.  Clearing records the moment
    // it was cleared, so every device deletes what it holds from before then — including messages
    // this one never had, and messages that arrive afterwards but are older than the instruction.
    // A device that was offline for the whole thing catches up when it merges, rather than keeping
    // a history its owner told it to destroy.

    /// Deletes the messages, keeping the conversation itself and everything that describes it — the
    /// contact, the nickname, the pin.
    void clear_messages(result_function<> cb);
    void clear_messages(await_t);

    /// Removes the conversation from the list without forgetting who it is with: the contact entry
    /// stays, so a nickname and an approval survive, and a new message brings the conversation
    /// back.
    ///
    /// `keep_messages` distinguishes the two things a UI calls this for.  Deleting a conversation
    /// destroys its history; hiding one — which is what "Hide" on Note to Self does — leaves the
    /// history to come back with it.
    void delete_conversation(result_function<> cb);
    void delete_conversation(bool keep_messages, result_function<> cb);
    void delete_conversation(await_t);
    void delete_conversation(bool keep_messages, await_t);

  protected:
    /// Never null, and not owned: the Client this came from, which must outlive it.
    Client* _client;
};

/// A one-to-one conversation with another account.
class DM : public Conversation {
  public:
    explicit DM(Conversation base) : Conversation{std::move(base)} {}

    /// True while this is a message request rather than a conversation: someone we have never
    /// written to has written to us.
    ///
    /// Approval is not something anyone sets — it is recorded by messages flowing.  Writing to
    /// someone approves them, so answering a request is what accepts it, and there is no way back:
    /// what un-requests a conversation is deleting the contact, not clearing a flag.
    ///
    /// Requests are conversations in every other respect — they have history, an unread count and a
    /// name — which is why this is a property of one rather than a kind of its own.  What differs
    /// is which list it belongs to: `conversations()` omits them and `message_requests()` returns
    /// only them, so this is never true on anything the former returned.
    ///
    /// Never true for note to self.
    bool request = false;

    /// The mirror of `request`: we have written to someone who has never written back, so they have
    /// us in *their* message requests and have not answered.
    ///
    /// Set from the same evidence, read the other way round — nobody sends anything to say they
    /// accepted, so the only thing that clears this is a message from them.  A display showing
    /// "waiting for them to accept" wants this; the conversation is otherwise ordinary and is in
    /// `conversations()` like any other, because it is one we chose to start.
    ///
    /// The two are mutually exclusive: their having written to us is exactly what makes this false
    /// and what can make `request` true.
    bool awaiting_approval = false;

    /// True for the conversation with our own account — Session's "Note to Self".  It is an
    /// ordinary DM rather than a kind of its own, so this is the only thing distinguishing it, and
    /// it is reported here so that displaying it differently does not require the caller to know
    /// our session ID or to compare it themselves.  What to call it is still the caller's
    /// decision: `display_name` is whatever our own profile says, not a localised label.
    bool note_to_self = false;

    /// Whether their messages are refused on arrival.  The other half of `set_blocked`: a toggle
    /// whose state cannot be read is not a toggle, and a UI needs this to draw it as on, to offer
    /// "unblock" rather than "block", and to stop offering to block somebody already blocked.
    bool blocked = false;

    /// The two halves `display_name` merges, for a screen that *edits* the name rather than
    /// rendering it.
    ///
    /// `name` is what they call themselves — from the `LokiProfile` on a message, or from the
    /// Contacts config, whichever is fresher.  `nickname` is what we call them, which is ours and
    /// syncs to our other devices.  A list row wants the merge and should keep using
    /// `display_name`; only a screen offering to change the nickname needs to show "they call
    /// themselves X, you call them Y", and it cannot when only the resolved answer arrives.
    ///
    /// Either may be empty: an account we have seen but know nothing else about has no name, and
    /// most contacts have no nickname.
    std::string name;
    std::string nickname;

    /// Sets or clears the name we have given them, which is ours rather than theirs and follows us
    /// between devices.  An empty nickname removes it, so `display_name` falls back to `name`.
    void set_nickname(std::string_view nickname, result_function<> cb);
    void set_nickname(std::string_view nickname, await_t);

    /// Blocks or unblocks the account.  Blocking is synced, so it takes effect on every device, and
    /// what they send is refused on arrival rather than hidden when drawing.
    ///
    /// Blocking someone we hold no contact entry for creates one, since being blocked is a fact
    /// about a relationship and there is nowhere else to record it.  It does not approve them, and
    /// unblocking does not undo anything else the block implied.
    void set_blocked(bool blocked, result_function<> cb);
    void set_blocked(bool blocked, await_t);

    /// Deletes the contact along with the conversation and its history, everywhere.
    ///
    /// This is the strong one: the entry goes from the Contacts config, so every device drops the
    /// conversation rather than merely hiding it, and what the entry held — the nickname, the
    /// approval in both directions, the block — goes with it.  Deleting a blocked contact therefore
    /// unblocks them; the block lived in the entry that was removed.
    ///
    /// What survives is the account itself, because we may still see them in a group or a
    /// community and need their name to render it.  A message from them afterwards arrives as a
    /// message request, exactly as one from a stranger would.
    ///
    /// Takes no `keep_messages`: there would be no conversation left to keep them in.
    ///
    /// @throws std::invalid_argument for our own account, which is not a contact of ours.
    void delete_contact(result_function<> cb);
    void delete_contact(await_t);
};

/// A closed group.  Nothing of its own yet: what distinguishes a group — its membership, who
/// administers it, whether we have accepted the invitation — arrives with UserGroups.
class Group : public Conversation {
  public:
    explicit Group(Conversation base) : Conversation{std::move(base)} {}
};

/// A community (open group) room.  As above: moderation and room metadata arrive with the config
/// that carries them.
class Community : public Conversation {
  public:
    explicit Community(Conversation base) : Conversation{std::move(base)} {}
};

/// A conversation of whichever kind it turned out to be.
///
/// The kind is a variant rather than a pointer so that a list of these is one contiguous block with
/// no allocation per row — a conversation list is re-read on every redraw, which makes it the one
/// place where that matters.  Reading a field common to every kind costs a compare against the
/// variant's discriminant and nothing else: each alternative holds its `Conversation` at the same
/// offset, so the compiler folds the dispatch away entirely.
///
/// **Keep `Conversation` the first base of any kind added here.** A second base ahead of it moves
/// the shared fields to a different offset in that one alternative, and the accessors below quietly
/// become a runtime selection instead of nothing at all.
class AnyConversation {
  public:
    std::variant<DM, Group, Community> kind;

    AnyConversation(DM c) : kind{std::move(c)} {}
    AnyConversation(Group c) : kind{std::move(c)} {}
    AnyConversation(Community c) : kind{std::move(c)} {}

    /// Everything every kind has, values and operations alike.  The shorthands below reach through
    /// this; it is here for anything they do not cover.
    Conversation& base() {
        return std::visit([](auto& c) -> Conversation& { return c; }, kind);
    }
    const Conversation& base() const {
        return std::visit([](const auto& c) -> const Conversation& { return c; }, kind);
    }

    const ConversationId& id() const { return base().id; }
    const std::string& display_name() const { return base().display_name; }
    const std::optional<MessagePreview>& last_preview() const { return base().last_preview; }
    sys_ms last_activity() const { return base().last_activity; }
    int unread() const { return base().unread; }
    bool marked_unread() const { return base().marked_unread; }
    int priority() const { return base().priority; }
    config::notify_mode notifications() const { return base().notifications; }
    std::chrono::sys_seconds mute_until() const { return base().mute_until; }
    config::expiration_mode exp_mode() const { return base().exp_mode; }
    std::chrono::seconds exp_timer() const { return base().exp_timer; }
    const config::profile_pic& picture() const { return base().picture; }
    std::optional<AutoDownload> auto_download() const { return base().auto_download; }
    std::string name_or_id() const { return base().name_or_id(); }

    /// The kind, or nullptr if it is not that one.  This is how a caller asks a question only one
    /// kind can answer — whether a conversation is a message request, who administers a group —
    /// and the nullptr is what stops that question being asked of a kind it means nothing to.
    DM* dm() { return std::get_if<DM>(&kind); }
    Group* group() { return std::get_if<Group>(&kind); }
    Community* community() { return std::get_if<Community>(&kind); }
    const DM* dm() const { return std::get_if<DM>(&kind); }
    const Group* group() const { return std::get_if<Group>(&kind); }
    const Community* community() const { return std::get_if<Community>(&kind); }

// Forwarded rather than reimplemented, so that an overload added to Conversation is reachable here
// without anything being added below.
#define SESSION_CONVO_FORWARD(name)                \
    template <typename... A>                       \
    decltype(auto) name(A&&... a) {                \
        return base().name(std::forward<A>(a)...); \
    }                                              \
    template <typename... A>                       \
    decltype(auto) name(A&&... a) const {          \
        return base().name(std::forward<A>(a)...); \
    }

    SESSION_CONVO_FORWARD(messages)
    SESSION_CONVO_FORWARD(mark_read)
    SESSION_CONVO_FORWARD(set_marked_unread)
    SESSION_CONVO_FORWARD(set_priority)
    SESSION_CONVO_FORWARD(set_notifications)
    SESSION_CONVO_FORWARD(set_mute_until)
    SESSION_CONVO_FORWARD(set_expiry)
    SESSION_CONVO_FORWARD(set_auto_download)
    SESSION_CONVO_FORWARD(send_message)
    SESSION_CONVO_FORWARD(clear_messages)
    SESSION_CONVO_FORWARD(delete_conversation)
    SESSION_CONVO_FORWARD(purge_deleted)

#undef SESSION_CONVO_FORWARD
};

}  // namespace session::client
