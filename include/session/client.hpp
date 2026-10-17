#pragma once

#include <atomic>
#include <deque>
#include <filesystem>
#include <map>
#include <optional>
#include <oxen/quic/loop.hpp>
#include <session/client/attachment.hpp>
#include <session/client/callbacks.hpp>
#include <session/client/conversation.hpp>
#include <session/client/conversation_id.hpp>
#include <session/client/message.hpp>
#include <session/clock.hpp>
#include <session/core.hpp>
#include <session/util.hpp>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "client/schema/schema_registry.hpp"

/// `session::client::Client` is the conversation-level data model of a Session client: the
/// conversation list, message history, unread state and drafts, built on top of a `core::Core`
/// which owns the synced account state (keys, configs, polling, decryption).
///
/// Client owns a Core rather than being part of one.  The consequence that matters is the one the
/// compiler enforces: Core has no dependency on Client, and builds, tests and runs with none of
/// this in existence.  A bot that wants raw protocol events constructs a bare Core; an application
/// that wants conversations constructs a Client and reaches through `client.core` for the account
/// state.
///
/// Client is where interpretation lives.  Core hands up an authenticated sender and a span of
/// decrypted bytes; everything after that is here — parsing the payload, deciding which
/// conversation it belongs to, whether it is one of ours, what it does to unread state and to the
/// order of the list.  Composing outbound messages is the same job in reverse, which is why setting
/// and clearing protocol fields such as `syncTarget` happens at this layer and not below it.
///
/// The rule, in one line: if a question can be answered without reading what a message *says*, it
/// belongs in Core; if answering it means interpreting the payload, it belongs here.
///
///     session::client::Client client{
///         std::filesystem::path{"/path/to/session.db"},
///         session::sqlite::argon2id_password{"correct horse battery staple"}};
///
///     session::client::Client client{
///         std::filesystem::path{"/path/to/session.db"},
///         session::client::callbacks{
///             .conversation_updated = [&](const auto& convo) { redraw(convo); },
///             .messages_added = [&](auto&& msgs) { for (auto& m : msgs) append(m); },
///         }};
///
///     for (const auto& convo : client.conversations())
///         std::cout << convo.name_or_id() << ": " << convo.unread << " unread\n";
///
/// Client shares Core's database — the same file and the same connection pool, not a second
/// database — so a write from a Client handler joins whatever transaction Core already has open on
/// that thread.
// Forward declared rather than included: the generated protobuf headers are large and this one is
// public.  Only referenced by private members below.
namespace SessionProtos {
class Content;
class DataExtractionNotification;
class UnsendRequest;
}  // namespace SessionProtos

namespace session::client {

using namespace std::literals;

// Privately a DeviceEvents so that what Core reports can be relayed through the dispatcher.  A base
// rather than a member because Core holds it by pointer: a base is constructed before `core` and
// destroyed after it, which a member only is by virtue of where it is declared.
class Client : private core::DeviceEvents {
    friend class session::TestHelper;  // for unit tests

    // A conversation *is* part of Client's interface, split off rather than added to: what these
    // call is the same private machinery the methods here do.
    friend class Conversation;
    friend class DM;

  public:
    /// Constructs a Client and, internally, the Core it sits on.  Takes the options `core::Core`
    /// takes (database encryption, predefined_seed, …) and forwards them — with the one exception
    /// of `core::callbacks`, which a Client's application cannot supply: those are Client's own
    /// wiring, and the static_assert below rejects an attempt to pass a set rather than letting it
    /// be silently overwritten.
    ///
    /// What an application is told is `client::callbacks`, given as the `cbs` argument of the
    /// overloads below and reported through the dispatcher.  Anything an application needs that
    /// only Core knows is Client's job to handle and re-report there; if something Core reports has
    /// no `client::callbacks` equivalent, that is a gap to fill here rather than a reason to reach
    /// past Client for it.
    template <core::CoreOption... Opts>
    explicit Client(std::filesystem::path db_path, Opts&&... opts) :
            Client{std::move(db_path), callbacks{}, std::forward<Opts>(opts)...} {}

    /// As below, additionally taking the dispatcher every handler is delivered through.  See
    /// `dispatcher`; without one, handlers run on Core's event loop.
    template <core::CoreOption... Opts>
    explicit Client(
            std::filesystem::path db_path, callbacks cbs, dispatcher dispatch, Opts&&... opts) :
            Client{std::move(db_path), std::move(cbs), std::forward<Opts>(opts)...} {
        set_dispatcher(std::move(dispatch));
    }

    /// As above, additionally taking the change notifications to deliver.  They are fixed for the
    /// life of the Client, exactly as core::callbacks are, and are the only way an application is
    /// told anything -- see `callbacks`, and read the startup ordering note there before using it.
    template <core::CoreOption... Opts>
    explicit Client(std::filesystem::path db_path, callbacks cbs, Opts&&... opts) :
            _cbs{std::make_shared<callbacks>(std::move(cbs))},
            core{std::move(db_path),
                 _core_callbacks(),
                 core::schema_extension{"client", schema::MIGRATIONS, schema::FULL_SCHEMA},
                 std::forward<Opts>(opts)...} {
        static_assert(
                (!std::same_as<std::remove_cvref_t<Opts>, core::callbacks> && ...),
                "A Client's Core callbacks are its own wiring and cannot be supplied: what an "
                "application is told is client::callbacks, passed as this constructor's `cbs`.");
        _init();
    }

    ~Client();

    // -- Conversations and messages ---------------------------------------------------------------
    //
    // None of these touches the database on the calling thread: they hand the work to Core's event
    // loop, which is the only thread that ever touches it.
    //
    // Not because doing otherwise is unsafe -- the connection pool hands each thread its own
    // connection, and WAL lets a reader run alongside the loop's writer -- but because of what it
    // costs and what it cannot promise.  A first read from the calling thread opens a second
    // encrypted connection to keep for the life of that thread; a write contends with the loop's
    // writer for the single WAL write lock and gives up after the 5s busy timeout; and a read gets
    // a snapshot whose relationship to the notifications the application has been given is
    // undefined, so two reads either side of a callback can disagree.  Going through the loop makes
    // all three questions not arise.
    //
    // A caller that genuinely wants to read on its own thread anyway can reach the pool through
    // `core.database()` and will not corrupt anything.  It is just answering a different, weaker
    // question than these do.
    //
    // Each returns immediately and invokes `cb` when the work is done -- through the dispatcher if
    // one was given, so on the application's own thread.  A caller that would rather block on the
    // answer than be handed it passes `await` in place of the handler and takes the return value.
    //
    // **Every `cb` is invoked exactly once**, unless the Client is destroyed before its work runs.
    // That is what its leading `error` argument is for: unset when the call succeeded, and
    // otherwise carrying what went wrong, so that a caller is never left waiting on an answer that
    // will not come.  The other arguments then mean only what they always meant -- an unset
    // `std::optional<Conversation>` says the conversation does not exist, and never that we could
    // not find out.
    //
    // The message is the thrown exception's, which is generally SQLite's, and is passed along as-is
    // rather than reduced to a category of our invention: what went wrong is worth more in a log or
    // a bug report than an enumeration that discarded it.
    //
    // Argument validation happens on the calling thread, before anything is dispatched, so misuse
    // still throws where the mistake is, rather than arriving later as an error argument.

    /// The conversation list: pinned first, then most recently active.
    ///
    /// Message requests are not in it — see `message_requests()` — and neither are hidden
    /// conversations.
    void conversations(result_function<std::vector<AnyConversation>> cb);
    std::vector<AnyConversation> conversations(await_t);

    /// The message requests: accounts that have written to us and that we have never written to,
    /// most recently active first.
    ///
    /// Disjoint from `conversations()`, and the same objects otherwise — a request has history, a
    /// name and an unread count, and `Conversation::request` is true on every one of these.  It
    /// stops being a request when we answer it, since writing to someone is what approving them
    /// is; there is no separate accept, and no way back short of deleting the contact.
    void message_requests(result_function<std::vector<AnyConversation>> cb);
    std::vector<AnyConversation> message_requests(await_t);

    /// One conversation, or nullopt if we have no such conversation.
    ///
    /// What you get back carries the operations as well as the values — see `Conversation` — so
    /// this is how a caller holding only an id reaches everything that can be done to it.
    ///
    ///     client.conversation(id, [](auto err, auto convo) {
    ///         if (convo) convo->mark_read(cb);
    ///     });
    ///
    /// `dm()` is the same question asked of a kind you already know, so that what comes back is a
    /// `DM` and needs no narrowing.
    ///
    /// @throws std::invalid_argument, from `dm()`, if the id is not a one-to-one conversation.
    void conversation(const ConversationId& id, result_function<std::optional<AnyConversation>> cb);
    void dm(const ConversationId& id, result_function<std::optional<DM>> cb);
    std::optional<AnyConversation> conversation(const ConversationId& id, await_t);
    std::optional<DM> dm(const ConversationId& id, await_t);

    /// The conversation with someone, made if it was not there already — "open a chat with this
    /// account", which is the one thing `conversation()` cannot express.
    ///
    /// Cannot answer "no such conversation": that is the difference from `dm()`, and it is why the
    /// waiting form hands back a `DM` rather than an optional.  Opening one that already exists
    /// changes nothing and simply gives it to you.
    ///
    /// The handler form still carries an optional, because a call that has been dispatched can
    /// still fail — a disk error — and has nowhere to throw.  It is unset only when `error` is set,
    /// never because the conversation was missing.
    ///
    /// Only DMs so far, and so only this one; groups and communities are joined and created rather
    /// than opened, and will say so in their own words when they arrive.
    ///
    /// @throws std::invalid_argument if the id is not a one-to-one conversation.
    void open_dm(const ConversationId& id, result_function<std::optional<DM>> cb);
    DM open_dm(const ConversationId& id, await_t);

    /// True if this is our own account's session ID.
    ///
    /// Touches no database and is not dispatched, so it is callable from any thread: it compares
    /// against our own ID, which is fixed once the account exists.  False rather than throwing when
    /// there is no account yet — with no identity, nothing can be us.
    bool is_me(std::span<const std::byte, 33> session_id);

    /// True if `id` is the conversation with our own account — Session's "Note to Self".  Same
    /// answer as `Conversation::note_to_self`, for a caller holding only an id.
    ///
    /// Unlike the accessors around it this touches no database and is not dispatched onto Core's
    /// loop: it compares against our session ID, which is fixed once the account exists.  So it is
    /// callable from any thread, including a render loop, and does not need a callback form.
    ///
    /// False rather than throwing when there is no account yet: with no identity, nothing can be a
    /// conversation with ourselves.
    bool is_note_to_self(const ConversationId& id);

    /// A single message by its Client-assigned id, or nullopt if it does not exist.
    void message(int64_t id, result_function<std::optional<Message>> cb);
    std::optional<Message> message(int64_t id, await_t);

    /// Blocks or unblocks an account named by id.
    ///
    /// The same operation as `DM::set_blocked`, and forwards to it; it is here as well because
    /// blocking is a fact about a *relationship* rather than about a conversation, and there is not
    /// always a conversation to hang it off — blocking someone whose name you found in a group has
    /// nothing to open first, and opening one would be the wrong thing to do about it.
    ///
    /// @throws std::invalid_argument if the id is not a one-to-one conversation, or is our own.
    void set_blocked(const ConversationId& id, bool blocked, result_function<> cb);
    void set_blocked(const ConversationId& id, bool blocked, await_t);

    /// Sends to a conversation named by id, creating it if it does not exist.
    ///
    /// The same operation as `Conversation::send_message`, and forwards to it; it is here as well
    /// because this is the one thing that cannot require a conversation to already exist —
    /// messaging an account you have never spoken to is how the conversation begins.  With one in
    /// hand, send through it and skip the lookup.
    ///
    /// See `Conversation::send_message` for what the arguments mean and what `on_upload` reports.
    ///
    /// @throws std::invalid_argument if the conversation is not a DM (groups and communities are
    /// not implemented yet), if an attachment cannot be read, or if `reply_to` names a message that
    /// does not exist or belongs to another conversation; thrown on the calling thread, before
    /// anything is stored or dispatched.
    void send_message(
            const ConversationId& id,
            OutgoingMessage msg,
            Conversation::upload_progress on_upload,
            result_function<int64_t> cb);
    void send_message(const ConversationId& id, OutgoingMessage msg, result_function<int64_t> cb);
    int64_t send_message(
            const ConversationId& id,
            OutgoingMessage msg,
            Conversation::upload_progress on_upload,
            await_t);
    int64_t send_message(const ConversationId& id, OutgoingMessage msg, await_t);

    /// Sends a failed message again, resuming rather than restarting: attachments that already
    /// reached the file server are left alone and only the ones that did not are uploaded, because
    /// what each upload achieved is recorded against the message.  A message whose files all got
    /// up but whose send failed is simply dispatched again, uploading nothing.
    ///
    /// Returns false, having done nothing, if the message cannot be retried: it does not exist, it
    /// is not one of ours, it is not in a failed state, or it is SendState::unsendable — that last
    /// being the one an application should offer deletion for rather than a retry, since what it
    /// needs is gone rather than merely unreachable.
    ///
    /// `on_upload` reports as it does for send_message, indexed the same way, so a display built
    /// for the original send works unchanged for the retry.  Note that a retry is where a file
    /// that has since been deleted is discovered: an attachment that has gone moves the message to
    /// SendState::unsendable, which is terminal.
    void retry_send(
            int64_t message_id, Conversation::upload_progress on_upload, result_function<bool> cb);
    bool retry_send(int64_t message_id, Conversation::upload_progress on_upload, await_t);
    bool retry_send(int64_t message_id, await_t);

    /// Deletes one message from this device: its body, its decrypted content and everything it
    /// recorded about its attachments go, and what is left says only that someone said something
    /// here and when.
    ///
    /// The row stays, marked `Deletion::here`, and this is not squeamishness about the data.  The
    /// swarm still holds the message, and the swarm hash on that row is the only thing that
    /// recognises it if it is delivered again -- which a storage server makes likely rather than
    /// hypothetical, since it stops honouring a `last_hash` once that has expired and answers the
    /// next poll with the whole retention window.  Delete the row and the message comes back
    /// looking new.
    ///
    /// Files are not touched.  An attachment's path names a file the user chose -- one they picked
    /// to send, or a place they asked a download to be put -- so it is theirs in both directions
    /// and nothing here has ever unlinked one.  The rows that described the attachments do go.
    ///
    /// Deleting an unread incoming message makes it read, since there is no longer anything to
    /// read; the conversation's unread count follows.
    ///
    /// This is the whole of "delete for me": nothing is sent, so nothing tells the other side or
    /// our own other devices.  A message deleted here can still be deleted everywhere afterwards,
    /// which is why how far it went is recorded rather than merely that it happened.
    ///
    /// Returns false, having done nothing, if there is no such message.  Deleting one already
    /// deleted here is not an error and changes nothing.
    void delete_message(int64_t message_id, result_function<bool> cb);
    bool delete_message(int64_t message_id, await_t);

    /// Deletes a message we sent, here and everywhere else it reached.
    ///
    /// Does everything `delete_message` does, and then two things more: removes our own swarm's
    /// copy — the one our other devices read — and asks the recipient to remove theirs.
    ///
    /// **Only for messages we sent.** Not a policy choice: an unsend request is honoured only from
    /// the message's author or from one of your own devices, so asking a stranger to delete their
    /// own message is asking for something the other end will ignore.  Returns false for an
    /// incoming message, having done nothing — a caller wanting that message gone locally wants
    /// `delete_message`.
    ///
    /// **The remote half cannot be confirmed, and is not reported.** `cb` fires once the local
    /// deletion is done, which is immediate and certain; the swarm delete and the request to the
    /// recipient are dispatched and not waited on.  There is no acknowledgement to wait for — a
    /// recipient may be offline for a week, may be running a client that ignores unsend requests,
    /// and may have already read and screenshotted it.  Reporting "deleted everywhere" as a
    /// completed fact would be a promise nothing can keep, so this reports what it did rather than
    /// what it achieved.
    ///
    /// The message is marked `Deletion::everywhere` locally either way, since that records what we
    /// asked for, and it is what stops a client offering the same deletion twice.
    void delete_message_everywhere(int64_t message_id, result_function<bool> cb);
    bool delete_message_everywhere(int64_t message_id, await_t);

    /// Shows, or stops showing, a message as a gallery.
    ///
    /// Returns false, having done nothing, if the message does not exist or is not
    /// `gallery_viewable` — a message that cannot be shown that way cannot be asked to be, so the
    /// stored decision can never disagree with the rule that governs it.  Clearing is always
    /// allowed.
    ///
    /// Starts nothing.  Turning gallery mode on for a conversation that does not auto-download
    /// leaves its images unfetched, and getting them is the caller's move — `attachment_data` for
    /// each — because a setter that reached for the network would surprise whoever called it.
    void set_gallery(int64_t message_id, bool gallery, result_function<bool> cb);
    bool set_gallery(int64_t message_id, bool gallery, await_t);

    /// An attachment's contents, decrypted and whole.
    ///
    /// For showing a file rather than keeping it: a gallery needs the bytes, and `save_attachment`
    /// would have it write files it then reads back and deletes.
    ///
    /// Served from the cache when it is there, and fetched *and cached* when it is not, so a
    /// display does not re-fetch on every scroll.  Asking while the file is already on its way,
    /// whether for another display or for `save_attachment`, waits for that download rather than
    /// starting a second -- unless it is a save of a file too big to keep (see
    /// `requested_cache_max_size`), which keeps nothing a display could be served from.
    ///
    /// Not subject to the auto-download size limit.  That governs what arrives unasked, and this is
    /// asked for.
    ///
    /// A failure says why through `cb`'s error, and the progress report that ends the transfer
    /// carries the same one:
    ///
    /// - `err::message_not_found`, `err::attachment_not_found` — there is nothing to fetch.
    /// - `err::file_not_found` — the file server does not have the file.
    /// - `err::file_unreadable` — the file cannot be read as its sender described it.
    /// - `err::network_unavailable` — no network is attached.
    /// - `err::download_failed` — this attempt failed, for a reason that may not recur.
    ///
    /// The two about the file are verdicts on it: every message quoting it shows them as its
    /// `availability`, and asking for it again answers at once, downloading nothing, until the
    /// sender sends it again.
    ///
    /// Returns the request's token, for `cancel_attachment_transfer`, which fails it with
    /// `err::download_cancelled`.
    uint64_t attachment_data(
            int64_t message_id,
            size_t index,
            std::function<void(const AttachmentProgress&)> on_progress,
            result_function<std::vector<std::byte>> cb);

    /// Withdraws one request made by `attachment_data` or `save_attachment`, by the token it
    /// returned or that its progress reports carry: its callback, and the last progress report it
    /// gets, fail with `err::download_cancelled`, and a save leaves nothing behind.  An
    /// auto-download is withdrawn the same way, by the token in its progress.
    ///
    /// The download itself stops only once nothing else is waiting on it -- another display of
    /// the same file, a save, an auto-download -- since cancelling one of them is not cancelling
    /// the others.  A copy that was being written to the cache goes with it.
    ///
    /// Deleting an attachment -- with its message, its conversation, or a delete-before
    /// instruction from any device -- withdraws every request for it in the same way.
    ///
    /// Nothing happens for a token that has already finished, or never existed.  One that finishes
    /// while this is on its way reports how it finished, so a save that is told it succeeded has
    /// its file.  An `attachment_data` answered from the cache is too quick to withdraw, and is
    /// always served.
    void cancel_attachment_transfer(uint64_t token);

    /// Removes one deleted message's leftover row.  The conversation-wide form, and the reason a
    /// deletion leaves a row at all — including how this can bring a message back — are on
    /// `Conversation::purge_deleted`.
    ///
    /// Returns false, having done nothing, if the message does not exist or has not been deleted.
    /// Refusing a live message is the point rather than a nicety: this is the one operation here
    /// that removes history outright, and it is only ever entitled to remove what a deletion left.
    void purge_deleted_message(int64_t message_id, result_function<bool> cb);
    bool purge_deleted_message(int64_t message_id, await_t);

    /// The message as it arrived on the wire, rendered as indented text: one line per field that is
    /// set, named, with nested messages beneath their field and enums by name.
    ///
    /// For seeing what a client actually sent, which nothing else here answers.  A message is
    /// stored twice — as the columns this schema models, and as the whole decrypted `Content` it
    /// came in — and everything else reads the first of those.
    ///
    /// Rendered here rather than handed over as bytes, because the wire format is this layer's to
    /// interpret: nothing above Client parses a protobuf, and the generated headers are kept out of
    /// the public ones deliberately.
    ///
    /// Deliberately not a field on `Message`: this is asked for one message at a time by someone
    /// looking, and putting it on the row would drag the whole wire form through the query that
    /// draws a conversation.
    ///
    /// Returns nullopt when there is nothing to show — which is not an error, and covers three
    /// cases a viewer is free to render alike: a message composed here that was never given a
    /// stored wire form, one whose content has been deleted, and one whose content some later
    /// pruning removed.  Also nullopt if the stored bytes no longer parse, which is corruption
    /// rather than absence and is logged as such.
    void message_debug(int64_t message_id, result_function<std::optional<std::string>> cb);
    std::optional<std::string> message_debug(int64_t message_id, await_t);

    /// Fetches one of a message's attachments and writes it to `dest`, decrypting it on the way.
    ///
    /// Nothing is downloaded until this is called.  An arriving message records where its files are
    /// and what they are called, and stops there: whether a file is worth the bandwidth is the
    /// application's decision, and on a metered connection it is the user's.
    ///
    /// `dest` is where the caller *asked* for it, and is not remembered.  Where a file went is the
    /// application's business — it chose the location and can move it afterwards — so nothing here
    /// would stay true.  Saving the same attachment twice to two places is therefore fine and means
    /// what it says.  The file is written whole or not at all: it lands at a temporary name beside
    /// `dest` and is renamed only once it has been decrypted and verified, so an interrupted save
    /// leaves no half-file that looks finished.
    ///
    /// The cache is read first and filled as the file arrives, as for `attachment_data` and within
    /// the same `requested_cache_max_size`, since saving a file and then saving it again somewhere
    /// else is common and should not cost a second download.  A save asked for while the file is
    /// already on its way joins that download, and while it runs the attachment shows as being
    /// fetched like any other.  The exception is a save of a file too big to keep, which nothing
    /// can join -- a display or another save asked for meanwhile fetches the file for itself --
    /// since it keeps nothing a latecomer could be served from.
    ///
    /// **`cb` reports where it actually went**, which is not always `dest`.  Whether `dest` was
    /// free is something the caller decided when it asked its user; the rename happens when the
    /// download finishes, which may be minutes later, and anything that has appeared there in
    /// between is a file nobody agreed to lose.  So by default the finished file takes the next
    /// free `name (1)` instead — before the extension, since only that still opens on a
    /// double-click.
    ///
    /// A caller whose user has *already* been shown what is there and said replace it passes
    /// `replace` and gets `dest` whatever has happened since.  That is not the same decision and
    /// must not be guessed at: renaming an approved overwrite would leave the file it was meant to
    /// replace sitting there, which discards the answer the user gave rather than protecting a
    /// stranger's file.
    ///
    /// `on_progress` reports as `send_message`'s `on_upload` does and is indexed the same way, so
    /// a display built for sending works unchanged in the other direction: `result` unset means
    /// under way with `done`/`total` in encrypted bytes, and is then success once the file is
    /// written and verified, or the same error `cb` gets.
    ///
    /// Fails as `attachment_data` does, and with `err::save_failed` if the file cannot be written
    /// where it was asked to go.
    ///
    /// `notify_sender` tells the person who sent it that we saved their file, which is what
    /// Session's other clients do and so what a recipient expects.  Passing false keeps this
    /// particular save to ourselves.  Only ever sent for a message we received: saving from our own
    /// message notifies nobody, and neither does a failed save.
    ///
    /// The account's own preference — `UserProfile::get_notify_media_saved`, which follows it
    /// between devices — can refuse the notification but cannot require one.  So a client that has
    /// not grown a setting for this still honours one made elsewhere, and a caller that passes
    /// false is not overruled.
    ///
    /// Which of Session's two attachment encryptions applies is read from the url, so a caller
    /// neither chooses nor needs to know: current clients still send the legacy scheme, and files
    /// we send use the stream one.
    ///
    /// Returns the request's token, as `attachment_data` does.
    ///
    /// @throws std::invalid_argument if `dest` names a directory or its parent does not exist;
    /// thrown on the calling thread, before anything is fetched.
    uint64_t save_attachment(
            int64_t message_id,
            size_t index,
            std::filesystem::path dest,
            std::function<void(const AttachmentProgress&)> on_progress,
            result_function<std::filesystem::path> cb,
            bool notify_sender = true,
            bool replace = false);

    /// Sets, replaces or removes the dispatcher every handler is delivered through, which a caller
    /// whose loop does not exist yet when the Client is built needs: an application typically opens
    /// its database, constructs this, and only then creates the window that owns the loop.
    ///
    /// Safe to call while Core is running and from any thread.  A handler already on its way either
    /// goes to the old dispatcher or the new one; there is no flush and none is needed, since
    /// passing nullptr simply means what no dispatcher has always meant -- handlers run on Core's
    /// event loop.  An application shutting its loop down therefore has the choice of unsetting
    /// this or having its own dispatcher run the work inline once posting stops arriving anywhere.
    void set_dispatcher(dispatcher d);

    /// Gives us somewhere to keep what we download, and turns caching on.
    ///
    /// Unset by default, and with it unset nothing is cached: every fetch goes to the file server.
    /// That is the safe default rather than a limitation — we are handed a database file, not
    /// permission to write beside it, and an embedder that has somewhere in mind (an Android cache
    /// dir, an XDG cache home) should be the one to say where.
    ///
    /// **The directory must be ours outright.** Freeing what nothing references any more works by
    /// listing the directory and unlinking what is not in the list, which is only safe somewhere
    /// nothing else writes.  Point this at a directory with other things in it and they will go.
    ///
    /// Calling this starts one such pass, in the background, against what the database says should
    /// be there.  It is a net for what no code of ours was running to see -- a crash between
    /// writing a file and recording it, a contact whose row went by cascade -- so it is done once,
    /// here, rather than on a timer: those are things that happen while we are not looking, and
    /// this is the moment we look.  It runs off the event loop and reports only to the log.
    ///
    /// Contents are encrypted under a key generated once and kept in the database, so they outlive
    /// the message or config entry whose key originally opened them — and so the files are not
    /// readable by whoever ends up with the disk.  That protection is only as good as the
    /// database's: with an unencrypted database the key sits in plaintext beside them.
    void set_cache_dir(std::filesystem::path dir);

    /// A conversation's picture, decrypted and ready to decode.
    ///
    /// Served from the cache when it is there, and fetched, decrypted and cached when it is not.
    /// Which of those happened is deliberately not reported: it is the same picture either way, and
    /// a caller that had to know would end up implementing the caching decision itself.
    ///
    /// `on_progress` reports the download as `save_attachment` does — `done`/`total` in encrypted
    /// bytes while it runs, then `result` holding success or the same error `cb` gets.  It is not
    /// called at all on a cache hit: there is no progress to draw when the bytes are already here,
    /// and a progress bar that flashes for a cached read is worse than none.
    ///
    /// Returns nullopt when there is no picture to fetch — nobody has told us of one, or this is a
    /// group or community, whose pictures are real but not wired up yet.  An actual failure to
    /// fetch reports through `cb`'s error rather than as nullopt, so "there isn't one" and "we
    /// could not get it" stay apart.
    ///
    /// Needs `set_cache_dir` to cache; without it every call fetches.  Nothing is cached for a
    /// picture we could not decrypt, since what we would be storing is not the picture.
    void profile_picture(
            const ConversationId& id,
            std::function<void(int64_t done, int64_t total, std::optional<Expected<void>> result)>
                    on_progress,
            result_function<std::optional<std::vector<std::byte>>> cb);
    void profile_picture(
            const ConversationId& id, result_function<std::optional<std::vector<std::byte>>> cb);

    /// How much disk the cached attachments may occupy in total, or nullopt for no limit.
    ///
    /// Measured as bytes on disk, so it counts what caching actually costs: the files are encrypted
    /// and padded, which makes the total larger than the same attachments would be as plain files.
    /// That is the right way round for a disk limit — 5GB means 5GB of disk.
    ///
    /// Display pictures are not counted and are never evicted for this.  They are one small file
    /// per contact, replaced rather than accumulated, and a contact you have not spoken to in years
    /// should not lose the last picture you had of them; freeing them is the reference sweep's job.
    ///
    /// Going over evicts least-recently-*used* entries until it fits — used rather than oldest, so
    /// something opened weekly does not lose to something downloaded once and never looked at.
    ///
    /// Persisted and device-local: a limit set in a settings screen should outlive the process, and
    /// how much disk to spend is a property of this machine rather than of the account.  Unlike
    /// `set_cache_dir`, which is the application's to decide every run — a stored path would be the
    /// wrong one the moment the database moved.
    ///
    /// @throws std::invalid_argument if `bytes` is negative.
    void set_attachment_cache_limit(std::optional<int64_t> bytes, result_function<> cb);
    void set_attachment_cache_limit(std::optional<int64_t> bytes, await_t);
    void attachment_cache_limit(result_function<std::optional<int64_t>> cb);
    std::optional<int64_t> attachment_cache_limit(await_t);

    /// How much disk the cached attachments occupy at the moment, in bytes.
    ///
    /// The same measure as the limit, and the same total eviction compares against it: bytes on
    /// disk, which is more than the attachments themselves are, since what is cached is encrypted
    /// and padded.  Being the same measure is what makes the two worth showing together.
    ///
    /// Display pictures are excluded, exactly as they are from the limit: they are not counted
    /// towards it and are never evicted for it.
    ///
    /// Read from the index rather than by walking the directory, so it costs a query -- and is
    /// exact only for as long as the index is.  A file deleted from under us still counts until the
    /// sweep that `set_cache_dir` starts finds it gone.
    ///
    /// 0 when nothing is cached, which includes having no cache directory at all.
    void attachment_cache_size(result_function<int64_t> cb);
    int64_t attachment_cache_size(await_t);

    /// API: client/Client::config_sizes
    ///
    /// How large each of the account's configs is: the size of the dump each would write now,
    /// which is what is stored for it and close to what it costs to push.  For diagnostics -- the
    /// header of an exported log, where a config that has grown unexpectedly is the first thing
    /// worth seeing -- rather than for deciding anything.
    ///
    /// Measured by dumping each config, so it costs one serialisation of each; cheap for a header,
    /// not something to poll.
    ///
    /// Keyed by config: `user_profile`, `contacts`, `convo_info_volatile`, `user_groups` and
    /// `local`.  Empty when there is no account yet: the configs are built from it on first use,
    /// and there is nothing to measure before then.
    void config_sizes(result_function<std::unordered_map<std::string, int>> cb);
    std::unordered_map<std::string, int> config_sizes(await_t);

    /// The largest attachment that will be fetched *unasked*, or nullopt for no limit.
    ///
    /// Compared against the size in the pointer, which is the file's own length — so a limit of 2MB
    /// admits files up to 2MB, with no allowance for padding or framing.  That is a claim by the
    /// sender, and one that is separately held to: a transfer whose contents turn out to be a
    /// different size from what was declared fails.
    ///
    /// Only ever applies to automatic downloads.  `save_attachment` and `attachment_data` are
    /// somebody asking for one particular file, and are never refused for being large; whether
    /// what they fetch is kept is `requested_cache_max_size`'s question.
    ///
    /// Persisted and device-local, for the same reasons as the cache limit.
    ///
    /// @throws std::invalid_argument if `bytes` is negative.
    void set_auto_download_max_size(std::optional<int64_t> bytes, result_function<> cb);
    void set_auto_download_max_size(std::optional<int64_t> bytes, await_t);
    void auto_download_max_size(result_function<std::optional<int64_t>> cb);
    std::optional<int64_t> auto_download_max_size(await_t);

    /// The largest file that `attachment_data` or `save_attachment` will keep in the cache, or
    /// nullopt for no limit, which is the default.  0 keeps nothing they fetch.
    ///
    /// Also bounds the copy kept of a file we send, which costs the cache what a download of it
    /// would.
    ///
    /// A file over it is still fetched -- this never refuses anything -- and is simply not kept, so
    /// asking for it again fetches it again.  One already in the cache is still served from there,
    /// whatever put it there.
    ///
    /// Compared against the size the sender declared, as `auto_download_max_size` is; with a limit
    /// set, a file that declares no size is not kept.  Independent of that setting, which is about
    /// what is fetched unasked: an auto-download is kept whenever it is fetched at all.
    ///
    /// Persisted and device-local, for the same reasons as the cache limit.
    ///
    /// @throws std::invalid_argument if `bytes` is negative.
    void set_requested_cache_max_size(std::optional<int64_t> bytes, result_function<> cb);
    void set_requested_cache_max_size(std::optional<int64_t> bytes, await_t);
    void requested_cache_max_size(result_function<std::optional<int64_t>> cb);
    std::optional<int64_t> requested_cache_max_size(await_t);

    /// How many attachments are fetched unasked at once, or nullopt for the default of 4.
    ///
    /// The rest wait their turn, newest first: what has just arrived is what somebody is most
    /// likely to be looking at, so it goes ahead of a backlog -- a conversation's history arriving
    /// from another device, say -- rather than behind it.
    ///
    /// Ignored under onion requests, which always fetch one at a time: every file travels the same
    /// few relays there, and several at once only make each of them more likely to time out.
    ///
    /// Persisted and device-local, for the same reasons as the cache limit.
    ///
    /// @throws std::invalid_argument if `n` is less than 1.
    void set_auto_download_concurrency(std::optional<int> n, result_function<> cb);
    void set_auto_download_concurrency(std::optional<int> n, await_t);
    void auto_download_concurrency(result_function<std::optional<int>> cb);
    std::optional<int> auto_download_concurrency(await_t);

    // -- Our own account ----------------------------------------------------------------------
    //
    // These read and write the UserProfile config, which follows the account between devices.  They
    // are here rather than left to `client.core.configs.user_profile()` because that has to be
    // touched on Core's loop -- a config read racing a merge is not safe -- and an application
    // drawing a settings screen is on its own thread.  One place doing the hop correctly beats
    // every caller discovering the rule, or not.

    /// Our own display name: what we publish about ourselves, empty until one is set.
    ///
    /// Not to be confused with a conversation's `display_name`, which is what we call somebody
    /// else.  This is account state and has no conversation: reading it off the note-to-self
    /// conversation works only once that conversation exists, which is a bug waiting for a fresh
    /// account.
    void display_name(result_function<std::string> cb);
    std::string display_name(await_t);
    void set_display_name(std::string_view name, result_function<> cb);
    void set_display_name(std::string_view name, await_t);

    /// Whether to tell somebody when we save a file they sent us.
    ///
    /// Follows the account, so turning it off on one device turns it off everywhere.  Composes with
    /// `save_attachment`'s `notify_sender` in one direction only: this can refuse a notification
    /// and cannot require one, so a caller passing false is never overruled, and a client with no
    /// setting of its own still honours a choice made elsewhere.
    void notify_media_saved(result_function<bool> cb);
    bool notify_media_saved(await_t);
    void set_notify_media_saved(bool notify, result_function<> cb);
    void set_notify_media_saved(bool notify, await_t);

    /// How often a handler that reports continuously — such as attachment upload progress — is
    /// allowed to fire, per thing being reported on.  Defaults to 100ms; zero lets every update
    /// through.
    ///
    /// A transfer reports far faster than a display can use, and with a dispatcher each of those
    /// reports is a job handed to the application's loop, which for some toolkits means a repaint.
    /// Squelching the ones in between costs nothing, because each update supersedes the last.
    /// Whatever a caller must not miss — an upload starting, finishing, or failing — is reported
    /// outside this and is never squelched.
    ///
    /// Safe to call while Core is running and from any thread; it applies to transfers begun after
    /// it takes effect.
    void set_high_freq_dispatch_interval(std::chrono::milliseconds interval);

    // -- Change notification ------------------------------------------------------------------
    //
    // Handlers are given at construction; there is no way to add or remove one afterwards.  See
    // `callbacks` for what each reports, and note in particular that the initial conversation list
    // must be taken *after* construction, never gathered before it:
    //
    //     Client client{path, std::move(cbs)};    // 1. notifications start here
    //     auto convos = client.conversations();   // 2. install as the starting point
    //
    // Anything arriving between 1 and 2 is applied on top of the snapshot and lands on the right
    // answer, because each handler carries the whole of the new state rather than a delta, so
    // applying one twice changes nothing.

  private:
    // Declared above `core`, which is declared last: see the note there.
    // Shared rather than held, so that a handler queued to another thread stays valid if the
    // Client is destroyed before it runs.
    std::shared_ptr<callbacks> _cbs;

    // Read and written only on the loop, which is what set_dispatcher hops onto rather than
    // synchronising.  Unset means run on the loop.
    dispatcher _dispatcher;

    // As above, and for the same reason.
    std::chrono::milliseconds _high_freq_dispatch_interval{100};

    // Core's send ids are per-process (its counter restarts at 1 on every run), so this mapping
    // must not be persisted or a stale row would capture a later run's status updates.
    struct OutgoingSend {
        int64_t client_id;
        // A note to self goes to our own swarm, so its swarm hash is one we can act on later; a
        // send to someone else deposits on their swarm, and that hash is theirs to expire.
        bool own_swarm;
    };
    std::unordered_map<int64_t, OutgoingSend> _send_ids;  // core send id -> the send it belongs to

    // Status updates that arrived from send_dm() before it returned, i.e. before we knew the core
    // send id to map.  Drained by send_message() once the mapping is registered.
    struct EarlyStatus {
        core::MessageSendStatus status;
        std::optional<std::string> swarm_hash;
    };
    std::unordered_map<int64_t, EarlyStatus> _early_status;

    // Core send ids belonging to the copy of an outgoing message deposited in our own swarm.  Their
    // delivery status is deliberately not reported: what the application waits on is the copy going
    // to the recipient, and a sync copy that fails costs an entry on our other devices rather than
    // the message itself.  Tracked rather than merely unregistered so that a late status does not
    // accumulate in _early_status forever.
    std::unordered_map<int64_t, int64_t> _sync_sends;  // core send id -> client message id

    // Sends whose outcome nobody is waiting for -- the media-saved notification is the only one so
    // far.  Tracked rather than left unregistered so that their statuses are dropped as they
    // arrive, instead of accumulating in _early_status against ids that will never be claimed.
    std::unordered_set<int64_t> _quiet_sends;

    // The actual work, all of it assuming it is already on the loop thread.  The public methods
    // above are dispatches onto that thread and nothing else; these are where the database is
    // touched, and are also what Client's own handlers call, since those already run there.
    //
    std::span<const std::byte> _self_or_none();
    std::vector<AnyConversation> _conversations();
    std::vector<AnyConversation> _message_requests();
    std::optional<AnyConversation> _conversation(const ConversationId& id);
    AnyConversation _create_conversation(const ConversationId& id);
    void _mark_read(const ConversationId& id, std::optional<sys_ms> up_to);
    void _set_priority(const ConversationId& id, int priority);
    void _set_marked_unread(const ConversationId& id, bool unread);
    void _set_notifications(const ConversationId& id, config::notify_mode mode);
    void _set_mute_until(const ConversationId& id, std::chrono::sys_seconds until);
    void _set_expiry(
            const ConversationId& id, config::expiration_mode mode, std::chrono::seconds timer);
    void _set_auto_download(const ConversationId& id, AutoDownload mode);
    void _set_nickname(const ConversationId& id, std::string_view nickname);

    // One conversation-row column, updated where it differs and re-derived into the config if it
    // did.  Templated on the value only so the caller need not name the bind type.
    template <typename T>
    void _set_conversation_setting(const ConversationId& id, std::string_view column, T value);
    void _set_blocked(const ConversationId& id, bool blocked);
    void _clear_messages(const ConversationId& id);
    void _delete_conversation(const ConversationId& id, bool keep_messages);
    void _delete_contact(const ConversationId& id);
    bool _delete_message(int64_t message_id, Deletion how_far);
    bool _delete_message_everywhere(int64_t message_id);
    // Handles an inbound unsend request: finds what it names, if it names exactly one thing we
    // hold, and deletes it.
    void _on_unsend_request(
            std::span<const std::byte, 33> sender, const SessionProtos::UnsendRequest& req);

    // A transfer's progress before anything identifies which attachment it is: bytes so far and
    // expected, and on the last report, how it ended.
    using transfer_progress =
            std::function<void(int64_t done, int64_t total, std::optional<Expected<void>> result)>;

    // Somebody wanting a file's bytes: a display, an auto-download, a picture fetch.
    //
    // `token` is what `cancel_attachment_transfer` finds it by, and 0 for a fetch nothing outside
    // can name, which is therefore never withdrawn.  `message_id` and `index` are the attachment it
    // was asked for, if it was one, so that deleting it can withdraw the request.
    //
    // `ended`, on Core's loop, once it has had its answer, whatever the answer was: for something
    // counting what is under way, which `cb` cannot be, since a waiter with one is asking for the
    // bytes.
    struct Waiter {
        uint64_t token = 0;
        std::optional<int64_t> message_id;
        size_t index = 0;
        transfer_progress progress;
        result_function<std::vector<std::byte>> cb;
        std::function<void()> ended;
    };

    // Where tokens come from.  Taken on the caller's thread, so a request can hand its token back
    // before anything has happened on the loop.
    std::atomic<uint64_t> _next_token{1};

    // A download that is already happening, and everyone waiting on it.  Defined beside the code
    // that runs it: what it holds -- the cache writer the bytes stream into, and which of its
    // fields belong to which loop -- is nothing a reader of this header needs.
    //
    // Without this, a conversation opening while its attachments are auto-downloading would fetch
    // every one of them a second time: the cache is still empty, so a display asking for bytes sees
    // a miss and starts its own.  Joining instead means a display never has to know whether
    // something is already under way -- it asks for the bytes and gets them, whoever started it.
    struct Transfer;

    // A file on the file server, and what it takes to read it: what an attachment row says about
    // where its file is and how to open it.
    //
    // Everything past the url is the sender's claim: nothing ties the key, digest or size to the
    // bytes the url names, so two rows can name one file and disagree about how to read it -- a
    // client with a bug, or someone doing it on purpose.  What a fetch finds out about *reading* is
    // therefore true of a claim, not of a url, and the transfers below are told apart accordingly.
    struct RemoteFile {
        std::string url;
        std::vector<std::byte> key, digest;
        std::optional<int64_t> size;
    };

    static std::string _transfer_key(const RemoteFile& f);

    // The stored form of a verdict on a file: what `message_attachments.unavailable` holds, shown
    // to the app as the matching `AttachmentAvailability`.  A verdict is a failure that trying
    // again will not fix; nothing transient is ever one of these.
    //
    // Its own type rather than those public values because these numbers are what is on disk and
    // must never change, and the public enum's are not meant to be anything in particular.
    enum class Unavailable : int {
        not_found = 404,
        unreadable = -20002,
    };

    // How a download ended.  `not_found` and `unreadable` are the file's own doing, and become the
    // matching `Unavailable` for every message quoting it; `failed` is everything that says nothing
    // about the file -- the network, the server, a cancel, or our own side of the transfer.
    enum class DownloadResult { ok, failed, not_found, unreadable };

    // Keyed by the whole claim (see `_transfer_key`) rather than the url, because joining a
    // transfer means taking its answer: a caller whose pointer carries a different key must not be
    // handed the failure of somebody else's.  Pointers that agree -- which is what every honest
    // copy of a file is -- share one key, so they still share one download.
    //
    // Ordered so that everything under one url sits together: whether *anything* is fetching a
    // file is a question about the url, asked once per attachment on a page.
    //
    // **Only ever touched on the loop.**  A download's own callbacks run on the disk loop, so
    // everything that reads or writes this hops first; the application's own callbacks then hop
    // again, out through the dispatcher.
    std::map<std::string, std::shared_ptr<Transfer>> _in_flight;

    // Withdraws the waiter or save holding `token`, wherever it is, and stops a transfer left with
    // nobody on it.  `why` is the cancellation's message.
    void _cancel(uint64_t token, std::string_view why = "cancelled");

    // Withdraws every request for an attachment that no longer exists.  Called once whatever
    // deleted it has committed, by everything that deletes messages or attachments: asked of the
    // database rather than worked out at each of those, which delete in several different ways.
    void _withdraw_orphaned_requests();

    // Stops `found`'s transfer and forgets it if nobody is left on it, discarding whatever it was
    // keeping; true if it did.
    bool _abort_if_unwanted(std::map<std::string, std::shared_ptr<Transfer>>::iterator found);

    /// What to tell a reader about an attachment's file: the `Attachment` fields that report it,
    /// given the `cached` reference and `unavailable` verdict already read from its row.
    ///
    /// A member because it needs the one thing the message builders below cannot read from the
    /// database: whether a transfer is running, which is ours and in memory.  It is also where the
    /// states are ranked, so that a display is handed one answer rather than the pieces of one.
    struct CacheStatus {
        AttachmentAvailability availability = AttachmentAvailability::absent;
        int64_t done = 0, total = 0;
    };
    CacheStatus _attachment_availability(
            std::string_view url,
            std::optional<int64_t> cached,
            std::optional<Unavailable> unavailable);

    /// Reports that what we hold of the file at `url` has changed, as what it is: a change to
    /// every message showing that file.
    ///
    /// More than one message routinely shows the same file -- forwarded, or quoted -- which is
    /// also why the cache is keyed on the file rather than on the message that wanted it.
    void _emit_attachment_availability(std::string_view url);

    /// Every message showing the file at `url`, and the one report covering all of them.
    ///
    /// Two halves rather than one call because a caller with a condition of its own does the query
    /// itself; and collected rather than streamed because every caller goes on to write the table
    /// it is reading, and the emits can call back in.
    std::vector<int64_t> _messages_showing(sqlite::Connection& c, std::string_view url);
    void _emit_messages_showing(sqlite::Connection& c, const std::vector<int64_t>& messages);

    /// Records that fetching through `claim` failed in a way retrying will not fix, on every row
    /// the verdict is actually true of, and returns the messages whose verdict changed.  Reporting
    /// them is the caller's: a finished transfer changes more rows than its verdict does, and says
    /// so in one report of its own.
    ///
    /// Which rows those are depends on what failed.  `not_found` is the file server's answer about
    /// the url, and holds for every message showing that file.  `unreadable` is about the claim:
    /// the same bytes under a different key or size may read perfectly well, so it holds only for
    /// rows making the same claim -- otherwise one bad pointer, sent by anyone, would mark every
    /// honest copy of the file as broken.
    std::vector<int64_t> _mark_unavailable(
            sqlite::Connection& c, const RemoteFile& claim, Unavailable why);

    /// A new pointer to `url` arrived, which is the resend a `not_found` tells the user to ask
    /// for: clears the server's verdicts on that url so the file is offered again.  Leaves
    /// `unreadable` alone, since a resend reproduces the bytes that failed.
    void _clear_resendable(std::string_view url);

    // How deep a read goes when a message turns out to be a reply.
    enum class ReplyDepth {
        // Load the replied-to message, so a caller can draw the reply from one read.
        with_target,
        // Resolve the reference but leave `Reply::message` null.  This is what a *nested* message
        // gets, and is the whole of the depth limit: without it, reading one message could walk a
        // chain of replies of unbounded length.
        reference_only,
    };

    // Turns a bound statement over MESSAGE_COLUMNS into whole Messages: attachments loaded,
    // gallery decided, and replied-to messages filled in unless this is already a nested read.
    //
    // Takes a bare statement rather than a `StatementWrapper` so that it serves both a cached
    // statement and a one-off; see `_load_reply_targets` for why one of its callers cannot use the
    // cache.
    std::vector<Message> _build_messages(
            sqlite::Connection& c,
            const ConversationId& convo,
            ReplyDepth depth,
            SQLite::Statement& st);
    template <typename... Bind>
    std::vector<Message> _query_messages(
            sqlite::Connection& c,
            const ConversationId& convo,
            ReplyDepth depth,
            const std::string& query,
            const Bind&... bind);
    void _load_attachments(sqlite::Connection& c, std::vector<Message>& msgs);
    void _load_reply_targets(
            sqlite::Connection& c, const ConversationId& convo, std::vector<Message>& msgs);

    // The claim to fetch an attachment by.  Throws `session::error` rather than returning one when
    // there is nothing worth fetching, with the code the requester is owed: no such message or
    // attachment, no url, or a verdict already recorded against the file.
    RemoteFile _remote_file(int64_t message_id, size_t index);

    // Records `file`, already in the attachment cache and taking `on_disk` bytes there, as `url`'s,
    // and tells every message showing that file that it is now here.  The row is an index over the
    // file, so this comes after the file exists -- and is handed its size rather than finding it
    // out, since that is the disk loop's to do.
    //
    // Returns whether it got that far, which is what says the messages have been told: a caller
    // that gets false has left them where they were and owes them the news itself.
    bool _record_cached(const std::string& url, const std::filesystem::path& file, int64_t on_disk);

    /// Keeps a copy of a file we just uploaded, so that a message we sent can be drawn without
    /// fetching back a file that came off this disk in the first place.
    ///
    /// Under the rule that would have applied had the same file arrived, plus anything on a
    /// gallery-viewable message whatever that rule says -- see the definition.  Best effort: the
    /// source is re-read, since the upload streamed it rather than holding it, and a file that has
    /// since moved or changed is simply not cached.
    ///
    /// Call once the row carries the url, which is both where the copy belongs and what says the
    /// upload is done.
    void _cache_outgoing_attachment(int64_t client_id, size_t index, const std::string& url);

    // The cache entry holding `url`, as (id, file name), found through the attachment rows that
    // reference it rather than by hashing the url.
    //
    // That is the point of the reference: the name is whatever the entry was written under, so one
    // written under an older naming is still found, and the hash stays something applied to a file
    // being created rather than to every lookup.
    std::optional<std::pair<int64_t, std::string>> _cached_entry(
            sqlite::Connection& c, std::string_view url);

    // Marks a cache entry as used now, which is what makes eviction least-recently-used.
    void _touch_cached(int64_t id);

    // Removes least-recently-used entries until the cache fits its limit, never touching `keep` --
    // which is whatever was just written, so that a download cannot complete and immediately
    // vanish.  Does nothing when no limit is set.
    void _evict_cache(int64_t keep);

    // Removes one cache entry, file and row, and returns the messages that were drawing it for the
    // caller to report -- which it does rather than reporting them itself so that a pass dropping
    // several files is one report and not one each.
    //
    // The messages have to be read before the row goes: the foreign key clears their reference as
    // it is deleted, and nothing afterwards can say which they were.
    std::vector<int64_t> _drop_cached(sqlite::Connection& c, int64_t id, const std::string& name);

    // Every message whose attachment names cache entry `id`.
    std::vector<int64_t> _messages_cached_as(sqlite::Connection& c, int64_t id);

    // What the cache index says its files add up to, in bytes on disk.  The overload taking a
    // connection is for callers that already hold one and are about to write through it -- eviction
    // reads this to decide whether it has work to do.
    int64_t _attachment_cache_size();
    std::unordered_map<std::string, int> _config_sizes();
    int64_t _attachment_cache_size(sqlite::Connection& c);

    // Where a profile reached us from, which is what a field it does not carry means.
    enum class ProfileSource {
        config,   // States the whole profile: no picture means they have none.
        message,  // Mentions one in passing: no picture means it did not say, so keep what we have.
    };

    // Writes a profile onto an account and returns whether anything changed, dropping the cached
    // picture the account has stopped using.
    //
    // One helper rather than the same UPDATE at each place a profile arrives from: the cleanup
    // belongs wherever the url changes, and a site that omitted it would strand a file that nothing
    // afterwards can attribute to anyone.
    bool _update_profile(
            sqlite::Connection& c,
            int64_t account,
            const std::optional<std::string_view>& name,
            const std::optional<std::string_view>& pic_url,
            const std::optional<std::span<const std::byte>>& pic_key,
            int64_t updated,
            ProfileSource source);

    // Unlinks a cached profile picture unless some account still names that url.  Unlike an
    // attachment there is no size limit and no expiry, so a picture nobody points at is reclaimed
    // only by someone noticing that nobody points at it.
    void _drop_unused_picture(sqlite::Connection& c, std::string_view url);

    // Starts one pass of reconciling the cache directories against the database, in the background.
    //
    // A net, not a mechanism.  Everything that caches a file records it in the same breath, and
    // everything that stops referencing one drops it.  What collects here is what no code of ours
    // was running to see: a crash between writing a file and recording it, an account row that went
    // by cascade, a database restored from a backup older than the directory.  Nothing else can
    // ever attribute those files to anything, so nothing else can ever remove them.
    void _sweep_cache();

    // The deciding half of `_sweep_cache`, on the loop, given the listings the disk loop took.
    // What it decides is carried out back on the disk loop, which is where files are removed.
    void _reconcile_cache(std::vector<std::string> attachments, std::vector<std::string> pictures);

    // This Client's work on `core.disk_loop()`: everything it does on disk, and the decryption of
    // what it downloads, none of which belongs on the network's loop or on Core's.  Stopped at the
    // start of ~Client, so that nothing still waiting in it runs against a Client being torn down.
    //
    // Above `core`, because the network posts to it -- each chunk as it arrives -- until `core`
    // tears the network down.  So it outlives `core`, and holds the loop alive itself: a queue has
    // to go before its loop does.  Emplaced in _init, since `core` does not exist yet when the
    // members declared before it are built.
    std::shared_ptr<oxen::quic::Loop> _disk_loop;
    std::optional<oxen::quic::JobQueue> _disk_jq;

    // Posts onto `_disk_jq`, or drops the job once it has stopped: a Client going away wants none
    // of what is left.
    void _post_disk(std::function<void()> job);

    // `automatic` for an auto-download, which is always kept; anything else is kept only if
    // `_caches_requested` says so.  `ended` is the waiter's.
    void _attachment_data(
            int64_t message_id,
            size_t index,
            bool automatic,
            uint64_t token,
            std::function<void(const AttachmentProgress&)> on_progress,
            result_function<std::vector<std::byte>> cb,
            std::function<void()> ended = nullptr);

    // An attachment waiting its turn to be fetched unasked.
    struct PendingAutoDownload {
        ConversationId convo;
        int64_t message_id;
        size_t index;
    };

    // Core's loop's.  Newest at the front, and taken from there.
    std::deque<PendingAutoDownload> _auto_pending;
    size_t _auto_running = 0;
    bool _auto_pumping = false;

    // Starts queued auto-downloads until as many are running as `auto_download_concurrency`
    // allows.  Does nothing when called from within itself, which an auto-download ending as soon
    // as it starts -- a cache hit, or no network -- does: the loop already running picks up the
    // freed slot, where recursing would go one level deeper for every entry in the queue.
    void _pump_auto_downloads();

    // Whether a file somebody asked for, of the size its sender declared, is kept once fetched: it
    // needs somewhere to go, and to fit `requested_cache_max_size`.
    bool _caches_requested(std::optional<int64_t> size);

    // Decides what an arriving message's attachments are worth fetching unasked, sets whether it is
    // shown as a gallery, and starts whatever it decided on.  Does nothing without a cache
    // directory: the point of fetching early is to have the file to hand, and with nowhere to keep
    // it the download would be thrown away.
    void _auto_download(const ConversationId& convo, int64_t message_id);

    bool _set_gallery(int64_t message_id, bool gallery);
    bool _purge_deleted_message(int64_t message_id);
    size_t _purge_deleted(const ConversationId& id);
    std::optional<std::string> _message_debug(int64_t message_id);

    // Where downloads are cached, and the key they are encrypted under.  Empty path means no
    // caching.  The key is read (or generated) on first use rather than at construction, so an
    // account that never caches anything never grows one.
    std::filesystem::path _cache_dir;
    std::optional<b32> _cache_key;
    // Must be called on the loop: it touches globals.
    const b32& _cache_encryption_key();

    /// What to call a cached file, and where to put it, with the cache key applied.
    ///
    /// One place rather than at every call site: the name is keyed (see `cache::name_for`), and a
    /// caller that forgot the key would silently get the old, guessable naming back.  Taking the
    /// key out of the caller's hands is what stops that being possible.
    ///
    /// For an *attachment* this is only ever used to name a file being written -- finding one that
    /// already exists goes through `_cached_entry`, which reads the name the entry was stored with.
    /// That is what lets the naming change without orphaning everything already downloaded.  A
    /// profile picture has no such entry, so for those it remains the way in as well.
    std::filesystem::path _cache_path(std::string_view kind, std::string_view url);
    std::string _cache_name(std::string_view url);
    void _profile_picture(
            const ConversationId& id,
            transfer_progress on_progress,
            result_function<std::optional<std::vector<std::byte>>> cb);
    std::vector<Message> _messages(
            const ConversationId& id,
            int limit,
            std::optional<MessageCursor> before,
            bool include_deleted);
    std::optional<Message> _message(int64_t id);
    int64_t _send_message(const ConversationId& id, const OutgoingMessage& msg);
    int64_t _send_message(
            const ConversationId& id,
            const OutgoingMessage& msg,
            Conversation::upload_progress on_upload);

    // Uploads the message's first attachment that has no url yet and, when there are none left,
    // finishes the send.  Each upload's completion calls this again, so the chain runs one file at
    // a time and resumes wherever it was left -- which is also what a retry does.
    void _upload_next(int64_t client_id, Conversation::upload_progress on_upload);

    // The rest of `_upload_next`, once the disk loop has looked at the file: uploads attachment
    // `index` from `path`, or fails the message for good if `file_size` says the file is gone.
    void _upload_one(
            int64_t client_id,
            size_t index,
            std::string path,
            std::optional<int64_t> file_size,
            Conversation::upload_progress on_upload);

    // Rebuilds the message's content with its now-uploaded attachments named in it, replaces what
    // was stored, and dispatches it.  Rebuilt from the database rather than from what send_message
    // was given, so that this is reachable for a message whose uploads finished in an earlier run.
    void _finish_attachment_send(int64_t client_id);

    // Marks a message as failed because its attachments could not be uploaded, and reports it.
    // `permanent` distinguishes a file that is gone, which no amount of retrying will fix, from a
    // transfer that merely did not work this time.
    void _fail_attachment_send(int64_t client_id, bool permanent = false);

    bool _retry_send(int64_t client_id, Conversation::upload_progress on_upload);

    // Wraps a progress callback so each report reaches the application through the dispatcher, and
    // returns an empty function when given one — so a download can skip reporting entirely rather
    // than call something whose whole body is a check that there is nothing to do.
    //
    // A caller reporting something narrower than "this download" — one attachment of several, say —
    // binds that in first and hands the result here; what is shared is the hop and the emptiness,
    // not what the numbers are about.
    transfer_progress _dispatch_progress(transfer_progress cb);

    // The same for a caller following one attachment, with its identity filled in before the hop:
    // the download reports only numbers, and which attachment they are about is this layer's to
    // say.
    transfer_progress _attachment_progress(
            int64_t message_id,
            size_t index,
            uint64_t token,
            std::function<void(const AttachmentProgress&)> on_progress);

    // What is being downloaded.  Only ever consulted to pick between the two *legacy* formats,
    // which are different for no reason anyone chose — see `attachment::legacy_display_pic_decrypt`
    // — and which nothing in the bytes distinguishes.
    enum class DownloadKind {
        attachment,   ///< A file sent with a message.
        display_pic,  ///< A profile picture or a group avatar.
    };

    // Downloads `url`, decrypts it, and hands the plaintext to `on_data` — possibly in pieces, and
    // on the disk loop, where the network hands each chunk as it arrives.  Whatever wants the bytes
    // decides what to do with them: write them to a file the user chose, keep them in memory, put
    // them in the cache.
    //
    // **This is the one place that chooses between Session's three at-rest formats**, and no caller
    // above it learns there was a choice.  The rule:
    //
    //   - the url carries a `d` fragment -> the stream scheme, whatever is being fetched.  That
    //     fragment means stream encryption universally; it is the one honest discriminator here.
    //   - otherwise, `kind` decides: an attachment is AES-CBC with an HMAC and a separate digest;
    //     a display picture is AES-GCM with the nonce and tag inline.
    //   - no key at all -> plaintext.  Community images are stored that way.
    //
    // `kind` is a parameter rather than something inferred from the key's length because the caller
    // knows which it asked for, and inference would be a guess standing in for a fact: it happens
    // to work today only because the two legacy key sizes differ, and would misroute silently the
    // first time something else turned up with a 32-byte key and no `d`.
    //
    // The stream scheme decrypts as it arrives; both legacy ones have to accumulate, because their
    // authentication covers the whole ciphertext and cannot be checked until all of it is here.
    //
    // Anything that goes wrong stops the transfer rather than being noted while the rest is
    // received and thrown away.  The stream scheme is what makes that worth doing: it authenticates
    // each chunk as it arrives, so a failure surfaces when the bad chunk does -- which may be the
    // first or may be most of the way in, but is not "once the whole file is here".
    //
    // `on_data` is handed each piece of the file with the padding a re-encrypted copy of it should
    // carry: the padding the stream scheme's file came with, which is known before the first byte
    // of data, or for the schemes that deliver the whole file at once the padding its length
    // would get.  Either way it is what `cache::Writer` needs, and no length is.
    //
    // `on_progress` reports in encrypted bytes, unindexed; a caller that reports per-attachment
    // adds its own index.  `on_done` fires exactly once, with how it ended and, unless that is
    // `ok`, why.  An exception from `on_data` ends the transfer as `failed`: it is our side that
    // could not take the bytes, which says nothing about them.
    //
    // A claim no download could satisfy -- a url that is not a download url, or a key or digest of
    // the wrong length for the scheme it resolves to -- ends `unreadable` without anything being
    // sent, through `on_done` like any other failure and so before this returns.
    //
    // Returns the flag that stops the download when set, or nullptr for one that has already
    // ended.  Stopped that way, it ends `failed` like any other cancel.
    //
    // Throws `session::error` with `err::network_unavailable`, before starting anything, if no
    // network is attached.
    std::shared_ptr<std::atomic<bool>> _download_decrypted(
            RemoteFile remote,
            DownloadKind kind,
            std::function<void(std::span<const std::byte> plaintext, size_t padding)> on_data,
            transfer_progress on_progress,
            std::function<void(DownloadResult result, std::string why)> on_done);

    // The public error for a download that did not end `ok`.
    static Error _to_error(DownloadResult result, std::string why);

    // The verdict a download's end records against the file, if any.
    static std::optional<Unavailable> _to_unavailable(DownloadResult result);

    // What a fetch needs to know about the file it is after, independent of who wants it.
    struct FetchTarget {
        RemoteFile remote;
        DownloadKind kind;
        std::string_view dir;  // cache::ATTACHMENT_DIR or cache::PROFILE_DIR
    };

    // Serves a file from the cache, joins a fetch of it already running, or starts one.
    //
    // The joining is what this exists for.  Two things want the same file routinely -- an arrival
    // starts a download and the display then asks for the very thing being downloaded -- so a
    // second request attaches to the first, picking up its progress from wherever it has reached,
    // rather than fetching the same bytes twice and caching them twice.
    //
    // A `caching` fetch streams the file into the cache as it arrives, and its waiters are served
    // by reading it back once it is whole: nothing holds the file in memory until somebody asks
    // for it there.  One that is not caching -- there is no cache -- holds what it downloads
    // instead, since there is then nowhere to read it back from.  `target.dir` says whether the
    // cached copy is an attachment, which is indexed and evictable, or a picture, which is
    // neither.
    void _fetch_cached(FetchTarget target, bool caching, Waiter w);

    // `_fetch_cached` once the cache has missed: joins a transfer of the same claim, or starts one.
    void _fetch_uncached(FetchTarget target, bool caching, Waiter w);

    // Registers `t` under `name` and starts its download.  Its waiters are told of a download that
    // cannot even start.
    void _start_transfer(std::string name, std::shared_ptr<Transfer> t);

    // Settles a transfer that has ended and been taken out of `_in_flight`: records what the ending
    // says about the file, and serves its waiters.  `cached_size` is what its cached copy takes on
    // disk, when it was kept, and `memory` is what it held instead, for one with no cache.
    void _finish_transfer(
            std::shared_ptr<Transfer> t,
            DownloadResult result,
            std::string why,
            std::optional<int64_t> cached_size,
            std::optional<std::vector<std::byte>> memory);

    // Tells every waiter on `t` the same answer.
    void _serve_waiters(const Transfer& t, Expected<std::vector<std::byte>> answer);

    // Starts a fresh transfer without a cache for `t`'s waiters and progress, when the cache they
    // were to be served from failed them.
    void _refetch(std::shared_ptr<Transfer> t);

    // Queues a fetch of a picture we have just learned the url of, so that it is to hand before
    // anything asks to draw it.  Unconditional: unlike an attachment there is no setting, because a
    // picture is small and is wanted the moment the conversation is shown.
    //
    // Takes the connection because it must read the key on the one whose transaction just wrote it,
    // and hands the fetch values rather than an account to look up again: the write it is reacting
    // to is not visible to any other connection until a commit that happens above this call.
    void _prefetch_picture(sqlite::Connection& c, int64_t account, const std::string& url);

    // Fetches a display picture into the cache for nobody in particular, reporting to
    // `display_picture_progress` as it goes.
    void _fetch_picture(const ConversationId& id, std::string url, std::vector<std::byte> key);

    // The work behind save_attachment: served from the cache when the file is there, and otherwise
    // written as a transfer of it arrives -- one it starts, or joins -- with the file itself only
    // ever touched on the disk loop.
    void _save_attachment(
            int64_t message_id,
            size_t index,
            uint64_t token,
            std::filesystem::path dest,
            std::function<void(const AttachmentProgress&)> on_progress,
            result_function<std::filesystem::path> cb,
            bool notify_sender,
            bool replace);

    // A save in progress; defined beside the code that runs it.
    struct Save;

    // Every save not yet reported, by token: Core's loop's, and how a cancel finds one wherever it
    // has got to -- on a transfer, or reading from the cache.
    std::unordered_map<uint64_t, std::shared_ptr<Save>> _saves;

    // Joins a transfer of the file, to be served from it once it ends, or starts one written
    // straight to the save as it arrives.
    void _save_uncached(std::shared_ptr<Save> s);

    // Copies the cache entry at `file` into the save, a chunk at a time on the disk loop, and
    // fetches it instead if the entry turns out not to be readable.  `entry_id`, when given, is the
    // entry to mark as used.
    void _save_from_cache(
            std::shared_ptr<Save> s, std::filesystem::path file, std::optional<int64_t> entry_id);

    // Writes the whole of `bytes` into the save, on the disk loop, for one served from a transfer
    // that held its file rather than caching it.
    void _save_bytes(std::shared_ptr<Save> s, std::vector<std::byte> bytes);

    // On the disk loop: writes into the save, opening its temporary file on the first write, and
    // gives up on the save -- not the transfer -- if it cannot.
    static void _save_write(Save& s, std::span<const std::byte> data);

    // On the disk loop: renames the save into place, or removes what it wrote if `error` says the
    // transfer failed or the save itself has.  Settles it, so nothing after this touches it.
    static Expected<std::filesystem::path> _save_finish(Save& s, std::optional<Error> error);

    // Finishes a save written as its transfer arrived, once the transfer has ended: `_save_finish`
    // on the disk loop, then `_saved`.
    void _save_complete(std::shared_ptr<Save> s, std::optional<Error> error);

    // On the disk loop: closes and removes the save's temporary file.
    static void _save_discard(Save& s);

    // On Core's loop: tells the caller how the save ended, and on success records it and tells the
    // sender.  Only the first report counts: a cancel and the save's own ending can cross.
    void _saved(Save& s, Expected<std::filesystem::path> result);

    // Tells a message's sender that we saved one of its attachments.  Fire and forget: nothing
    // waits on it and a failure is logged rather than reported, since it is a courtesy to them
    // rather than part of what the caller asked for.
    void _notify_media_saved(int64_t message_id, size_t index);

    // Whether *we* are the recipient of a message, which is what makes our own save of one of its
    // attachments worth recording.  True for anything incoming, and for a note to self, where the
    // message is outgoing but the recipient is still us.
    bool _saved_by_recipient(int64_t message_id);

    // Records that the recipient of a message saved one of its attachments: us, for one we
    // received, and them for one we sent.  An unset `index` means all of the message's
    // attachments, which is what a peer saving several at once reports.
    //
    // Told rather than deciding: this is reached both by our own save and by a peer's notification,
    // and only the caller knows which of those it is -- for a message we sent, our save is not the
    // recipient's and theirs is.
    void _record_saved(int64_t message_id, std::optional<size_t> index, sys_ms when);

    // A peer telling us they saved a file we sent them.  `when` is the notification's own
    // timestamp -- when they saved it -- rather than the timestamp identifying which message it is
    // about, which is generally older.
    void _on_media_saved(
            std::span<const std::byte, 33> sender,
            const SessionProtos::DataExtractionNotification& note,
            sys_ms when);

    // Hands a stored message to Core: the recipient's copy and, unless it is a note to self, the
    // copy for our own swarm.  Shared by the plain and attachment-carrying sends.
    void _dispatch_sends(
            int64_t client_id,
            const ConversationId& id,
            const SessionProtos::Content& content,
            const SessionProtos::Content& synced,
            sys_ms now,
            bool to_self);

    // Runs `work` on the loop thread, logging rather than propagating anything it throws: an
    // exception escaping there has no caller to reach and would take the loop with it.
    void _dispatch(std::function<void()> work);

    void _require_dm(std::string_view op, const ConversationId& id);
    void _require_contact(std::string_view op, const ConversationId& id);
    void _require_page(std::string_view op, int limit);
    void _require_readable(const std::vector<OutgoingAttachment>& attachments);

    // Everything a send must be able to reject before storing anything: the conversation kind, the
    // attachment files, and the message being replied to.  Together in one place so that a caller
    // gets one answer rather than discovering the next problem after fixing the first, and so that
    // every send overload is guarded identically.
    //
    // On the calling thread, so caller error surfaces at the call site rather than inside the loop
    // where a callback form could only log it.
    void _require_sendable(
            std::string_view op, const ConversationId& id, const OutgoingMessage& msg);

    core::callbacks _core_callbacks();
    void _init();

    void link_request_added(core::device::LinkRequest request) override;
    void link_request_ended(int reqid, core::device::LinkRequestEnd why) override;
    void devices_replaced(core::device::map devices) override;
    void device_membership_changed(core::device::Info device) override;
    void membership_changed(core::device::Membership membership) override;
    void group_appeared(core::device::GroupId group) override;

    void _on_message_received(core::ReceivedMessage&& msg);
    void _on_send_status(
            int64_t core_id,
            core::MessageSendStatus status,
            std::optional<std::string_view> swarm_hash);

    // Applies what a config merge changed to the tables that answer queries about it.
    //
    // Every one of these compares against what we already hold and writes only where they differ,
    // rather than trusting the notification to say what moved.  That is what makes them
    // self-correcting: the config cannot describe how far behind our tables are -- a merge can
    // cross several updates at once, and a crash between merging and reconciling leaves them behind
    // by an amount nothing recorded -- so anything a previous pass missed is picked up by the next.
    void _on_configs_changed(std::span<const config::Namespace> changed);

    // Reconciles every config, whether or not anything reported a change.
    //
    // A change notification only arrives for state that changes *after* someone is listening, which
    // leaves three ways for the tables to fall behind with nothing to announce it: a config merged
    // by a version that did not yet know how to reconcile it, a crash between merging and
    // reconciling, and a dump restored from an older state.  In each the database is behind by an
    // amount nothing recorded, and no further notification is owed -- a contact list that has
    // stopped changing would stay unreconciled indefinitely.
    //
    // Safe to run when nothing has changed, because reconciliation compares rather than replays: it
    // costs a pass over the configs and writes nothing.
    void _reconcile_all();

    // Records that a note-to-self conversation now exists, by moving its priority off hidden.
    //
    // For a contact, the presence of an entry in the Contacts config is what says the conversation
    // exists, and priority separately says whether it is shown.  Note to self has no such entry to
    // be present or absent: UserProfile exists from the moment the account does, because it holds
    // the account's own name.  So priority does both jobs there, and a negative value is the only
    // way that config can express "there is no note-to-self conversation" -- which is why a new
    // account writes one, and why putting a message in it has to write the value back.
    //
    // Does nothing if it is already visible, so a pin the user chose is left alone.
    void _reveal_note_to_self(const ConversationId& id);

    // Everything the Contacts config says about the people we know.
    //
    // Each entry projects onto three tables, because it carries three different kinds of fact: who
    // someone is goes on `accounts` (which anyone we have merely *seen* also has), the relationship
    // goes on `contacts`, and how the conversation with them behaves goes on `conversations`.
    //
    // Whose name wins is decided by `profile_updated`, not by which source spoke last: the config's
    // name is applied only when its stamp is at least as new as the one we already hold, so a
    // profile observed on a message that arrived out of order cannot overwrite a newer one.
    void _reconcile_contacts();

    // Re-derives every contact we hold into the Contacts config.
    //
    // A no-op wherever the config already agrees, because assigning a config field its existing
    // value does not dirty it -- so this only writes where the config was actually missing
    // something.  That is what makes it safe to run before the deletion pass, and why it has to be:
    // creating a contact commits the row and updates the config in memory, but the *dump* happens
    // later, so a crash in between leaves a row that the config has never heard of.  Reconciled
    // inward first, that row looks like a contact deleted elsewhere and is destroyed along with its
    // history.  Derived outward first, it is simply published.
    void _sync_all_contacts();

    // Writes what our tables say about one account back into the Contacts config.
    //
    // Re-derived from the rows rather than applied alongside each change, so the mapping lives in
    // one place and cannot drift from the tables it describes: a caller has to remember to call
    // this, but it cannot remember to call it *wrongly*.  Idempotent -- assigning a config field
    // its existing value does not dirty it -- so it is safe to call whenever a row might have
    // moved.
    //
    // Not for our own account: our profile is UserProfile's, and we are not a contact.
    void _sync_contact(const ConversationId& id);

    // As above, for whichever config carries the conversation rather than for a contact
    // specifically.  The dispatch is the point: something that has changed a conversation should
    // not have to know that note to self lives in UserProfile while everybody else lives in
    // Contacts.
    void _sync_conversation(const ConversationId& id);

    // Read state — the watermark and the marked-unread flag — from ConvoInfoVolatile.
    //
    // Deliberately without the deletion pass that Contacts has.  That config is pruned by age
    // rather than by anyone noticing a removal, so an entry absent from it means only that nothing
    // has been read in that conversation lately, and treating absence as a deletion would destroy
    // conversations for having been quiet.
    //
    // Runs after whatever might have created a conversation, because read state about one we do not
    // have is nothing we can apply and nothing we should create a conversation from.
    void _reconcile_convo_volatile();

    // The other direction, for one conversation and for all of them.
    //
    // The watermark only ever moves forwards, in both directions.  The config does not enforce that
    // — it permits a value to be written backwards on purpose — and a conflict between two devices
    // at the same seqno resolves by a tie-break that knows nothing about which value is newer, so
    // without this a stale device would make read messages unread everywhere.
    void _sync_convo_volatile(const ConversationId& id);
    void _sync_all_convo_volatile();

    // Records a delete-before instruction in the config that carries this conversation, so that
    // every device deletes the same history rather than only the one the user was looking at.
    //
    // Never moves the instruction backwards.  Two devices clearing at different moments merge to
    // one value, and the one that destroys more is the one that was asked for.
    void _set_delete_before(const ConversationId& id, sys_ms before);

    // Our own name and picture, and the note-to-self conversation's settings.
    //
    // This one runs the opposite way round to the others: UserProfile is authoritative and the
    // `accounts` row is a projection of it, because the config holds structure the row does not
    // model -- a second picture slot, carrying the same image at a fresh URL, which exists so a
    // linked device that already has those bytes can skip re-downloading them.  Deriving the config
    // back from the row would flatten the two slots and destroy another device's reupload.
    void _reconcile_user_profile();

    // `swarm_hash` is recorded against the message only when it names a copy in our own swarm; the
    // caller passes nullopt for the copy sent to someone else, whose hash is meaningless here.
    void _apply_send_status(
            int64_t client_id,
            core::MessageSendStatus status,
            bool sync,
            std::optional<std::string_view> swarm_hash);

    // Runs `invoke` against the application's handlers, swallowing and logging anything it throws:
    // a broken listener is not something a data model can do anything about.
    void _emit(std::function<void(const callbacks&)> invoke);

    // Hands anything Client says outward to the dispatcher, or runs it here if there is none.
    // Everything the application supplied goes through this: the change notifications, and the
    // handlers given to individual calls.  Only called on the loop, which is what lets the
    // dispatcher itself be an ordinary member.
    void _dispatch_out(std::function<void()> job);

    // Hands `result` to `cb`, on the application's thread, if it gave us one.
    template <typename Cb, typename R>
    void _report(Cb& cb, R result) {
        if (!cb)
            return;
        _dispatch_out([cb, result = std::move(result)]() mutable { cb(std::move(result)); });
    }

    // Reports a failure, for the callers that have one in hand rather than an exception to convert.
    template <typename T = void, typename Cb>
    void _fail(Cb& cb, Error err) {
        _report(cb, Expected<T>{unexpected{std::move(err)}});
    }

    // Runs `produce` on the loop and reports what it produced to `cb`, or reports the reason it
    // could not.  This is what makes "`cb` is invoked exactly once" true: the work is database
    // access, which throws on a disk error, and by then the caller's stack is gone -- so the
    // callback they gave us is the only way left to tell them.  Logging it and returning would
    // leave them waiting for an answer that is never coming.
    template <typename Produce, typename Cb>
    void _async(Produce produce, Cb cb) {
        // `_jq`, not `loop`: this captures `this` and runs later, and ~Client has to be able to
        // throw it away.  On the loop's own queue it would instead run during Core's destruction
        // -- the loop thread keeps draining until ~Loop, which is the *last* thing ~Core does --
        // reaching a Client whose components have already gone.
        call([this, produce = std::move(produce), cb = std::move(cb)]() mutable {
            using Result = decltype(produce());
            try {
                if constexpr (std::is_void_v<Result>) {
                    produce();
                    _report(cb, Expected<void>{});
                } else
                    _report(cb, Expected<Result>{produce()});
            } catch (const std::exception& e) {
                log_operation_failure(e);
                _report(cb, Expected<Result>{unexpected{error_from(e)}});
            }
        });
    }

    // Out of line so that the logging category does not have to be reachable from this header.
    static void log_operation_failure(const std::exception& e);

    void _emit_conversation_added(const ConversationId& id);
    void _emit_conversation_removed(const ConversationId& id);
    void _emit_lists_replaced();
    void _emit_history_replaced(const ConversationId& id);
    // Reports a message, and then reports every message that replies to it.
    //
    // A reply resolves what it answers on each read, so anything that happens to a message changes
    // the replies pointing at it: one arriving makes them resolve, one being deleted changes what
    // they show.  Cascading here rather than at the ten call sites means none of them can forget
    // it, which would show up only as a display that quietly stops matching the database.
    //
    // An added message and its replies are two reports, since they are two callbacks; the replies
    // of a *changed* message join it in one.
    void _emit_message(bool added, int64_t message_id);

    // Every message that replies to `message_id`, which is what the cascade above reports.
    //
    // One level is enough, and is why this terminates: reporting B refreshes what A shows for the
    // message it replied to, but reporting A cannot change what anything shows for *A*, because a
    // message reached through a reply carries the reference to what it answered and never the
    // answer itself.  So there is no visited set, and two messages claiming to reply to each other
    // cannot loop.
    std::vector<int64_t> _repliers(sqlite::Connection& c, int64_t message_id);

    // Reports `ids` as one call, deduplicated and ordered oldest first -- the order the callback
    // promises, and the reverse of the one `messages()` pages in.
    //
    // Built here rather than by the caller: whatever prompted this may have reached a message more
    // than once, and building at the end means one build per message in its settled state.  Ids
    // that no longer resolve are dropped, so a report for something deleted along the way is simply
    // not made.
    void _emit_messages(bool added, std::vector<int64_t> ids);

    // Conversations whose settled state still has to be reported.  A conversation is marked here
    // rather than reported immediately so that a poll delivering fifty messages to one conversation
    // reports it once; `_flush_pending` is scheduled on the loop and runs when the work that
    // dirtied them is finished.
    std::vector<ConversationId> _dirty;
    bool _flush_scheduled = false;
    void _touch(const ConversationId& id);
    void _flush_pending();

  public:
    /// The account state this Client is built on: keys, device group, configs, polling.  A
    /// Client-based application uses this for everything below the conversation layer.
    ///
    /// Declared last, which is load-bearing rather than stylistic: members are destroyed in reverse
    /// declaration order, so this is destroyed *first*.  Core's callbacks and loop jobs capture
    /// `this` and reach the members above -- the signal registry, the send-id map, the pending
    /// flush -- and Core's polling thread can be part-way through delivering one when a Client is
    /// destroyed.  `quic::Loop::~Loop()` joins that thread, so once this member is gone no callback
    /// can fire, and everything destroyed after it is unreachable by definition.
    ///
    /// Put anything a Core callback touches *above* this, never below.
    core::Core core;

  private:
    /// Schedules work on this Client's job queue, which is where everything this class defers
    /// belongs -- see `_jq`.  Same shapes as `Core`'s: `call` runs inline when already on the loop
    /// thread, `call_soon` always queues, `call_later` queues after a delay, and `call_get` blocks
    /// until the answer is ready.
    ///
    /// There is deliberately no `loop` member any more.  It read as the obvious way to defer work
    /// and was the wrong one, since the loop's own queue outlives every Core member that these
    /// jobs reach through `this`.  Anything genuinely wanting the loop says `core.loop()`.
    template <typename F>
    void call(F&& f) {
        _jq.call(std::forward<F>(f));
    }
    template <typename F>
    void call_soon(F&& f) {
        _jq.call_soon(std::forward<F>(f));
    }
    template <typename F>
    void call_later(std::chrono::microseconds delay, F&& f) {
        _jq.call_later(delay, std::forward<F>(f));
    }
    /// By value, for the same reason as Core's: a reference returned here has escaped the loop.
    template <typename F>
    auto call_get(F&& f) {
        return _jq.call_get(std::forward<F>(f));
    }

    // Client's own queue on Core's loop, rather than the loop's shared one, so that work deferred
    // here is *cancelled* if the Client is destroyed with it still outstanding.  Running it instead
    // would mean reporting a change to the subscribers of a Client that is going away, against a
    // Core whose database is already being torn down.
    //
    // **Everything this class defers must go here**, not on `loop`.  The loop's own queue is not
    // emptied until `~Loop`, which is the last thing `~Core` does, so a job left on it keeps being
    // drained by the loop thread throughout the destruction of every Core member -- and every one
    // of these jobs holds `this` and reaches through it into those members.  Stopping this queue
    // is the first thing `~Client` does, while all of that is still whole.
    //
    // `loop.call_get()` is the exception and stays as it is: the calling thread is blocked inside
    // it, so there is no window in which the caller can have gone away.
    //
    // Declared after `core` -- the one thing that belongs below it -- because a JobQueue needs its
    // loop alive in order to stop, so it has to be destroyed while Core still exists.
    oxen::quic::JobQueue _jq{core.loop()};
};

}  // namespace session::client
