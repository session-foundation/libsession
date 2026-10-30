#pragma once

#include <chrono>
#include <optional>
#include <session/client.hpp>
#include <session/client/error_codes.hpp>
#include <session/config/namespaces.hpp>
#include <session/network/key_types.hpp>
#include <session/push/payload.hpp>
#include <session/util.hpp>
#include <string>

/// Push notification handling: what a device needs to receive Session messages through its
/// platform's push service (APNs, FCM, etc.) while the application isn't running.
///
/// Built as its own library (`libsession::push`, `ENABLE_PUSH`) because only mobile clients receive
/// pushes; a desktop or command-line build leaves it out.  It sits on a Client, and so on the Core
/// beneath it, and adds nothing to either: the account, its swarm and its messages are theirs, and
/// this is the layer that knows how a push names them.
///
/// The usual shape is a notification extension (or Android's push receiver) opening a Client with
/// `core::one_shot` and a network with `network::opt::one_shot`, handing it one push, and exiting.

namespace session::push {

using namespace std::literals;

/// What `Notifications::fetch_message` found in the swarm.
enum class FetchResult {
    /// A swarm member had the message, and it has been received exactly as a poll would have
    /// received it.
    found,

    /// Every member asked answered, and none had it.  The push server can notify before a message
    /// has reached every member of the swarm, so this usually means it had not reached the ones
    /// asked yet; the application's next poll picks it up.
    not_found,

    /// A member had the message, and it did not decrypt.
    unreadable,

    /// No member answered usably within the deadline.
    failed,

    /// No network is attached, or the account has no identity yet.
    no_network,
};

struct FetchedMessage {
    FetchResult result;

    /// What is stored under the message's hash once the fetch is over: set whenever the message is
    /// one the Client keeps and is there -- including when a poll got it first, which a push racing
    /// a poll makes ordinary, whatever `result` says.  Nullopt for anything else: a config message,
    /// say, or one dropped as coming from someone blocked.
    std::optional<client::Message> message;
};

/// What became of one push handed to `Notifications::handle`.
enum class Handled {
    /// The push carried the message, and it has been received.
    received,

    /// The message was fetched from the swarm and received: it was too large for the push, or the
    /// push was for a namespace subscribed without message data whose contents matter now.
    fetched,

    /// A push without the message, for a namespace that needs nothing done now (a config the
    /// application picks up on its next poll).
    nothing_to_do,

    /// The message had to be fetched, and the members asked did not have it yet.
    not_found,

    /// The message had to be fetched, and no member answered in time, or there is no network.
    fetch_failed,

    /// The message arrived, or was fetched, and did not decrypt -- even after fetching the device
    /// group, where the failure was a key we lacked, which is what a rotation we have not yet heard
    /// about looks like.
    unreadable,

    /// For a swarm this device does not hold: not our account, and no group we know.
    not_ours,

    /// The payload did not decrypt with our key.  The subscription has been marked due, so the
    /// next `subscribe` renews it.
    undecryptable,

    /// The payload decrypted to something that is not a push payload.
    malformed,
};

struct HandledPush {
    Handled outcome;

    /// What the push said, for anything that decoded (every outcome but undecryptable and
    /// malformed).
    std::optional<Payload> payload;

    /// What is stored for the message once handling is done, as for `FetchedMessage::message`:
    /// set for a message the Client keeps, however it arrived.
    std::optional<client::Message> message;
};

/// The kind of a message's first attachment, for the platform's attachment placeholder ("📷
/// Attachment").
enum class AttachmentKind {
    image,
    animated,
    video,
    audio,
    voice,
    file,
};

/// What a notification says, as structured content: each platform builds the text from its own
/// localised strings rather than libsession writing any.
struct NotificationContent {
    enum class Kind {
        /// A message, from `sender`, saying `body` and/or carrying attachments.
        message,
        /// The first message of a message request: shown without its sender or contents, titled
        /// "Session", as "You have a new message request".  Requests come from strangers, so
        /// neither their name nor their words reach the lock screen.
        message_request,
        /// A message that could not be shown: "You've got a new message.", titled "Session".
        generic,
    };
    Kind kind;

    /// The notification's identifier, which a later removal names: the message's swarm hash, or
    /// GENERIC_ID, which every generic notification shares so that a run of them is one.
    std::string id;

    /// The thread it is grouped under: the conversation's id, REQUESTS_THREAD for every request,
    /// or GENERIC_ID.
    std::string thread;

    /// Whom it is from; unset when the privacy setting hides names.
    std::optional<std::string> sender;

    /// What the message says, with mentions resolved (`@Name`, and `@` and the `you` given to
    /// `decide` for the user); unset when the privacy
    /// setting hides content or the message has no text.
    std::optional<std::string> body;

    /// The first attachment's kind and how many there are, when the privacy setting shows content.
    std::optional<AttachmentKind> attachment;
    size_t attachments = 0;

    sys_ms timestamp{};
};

/// The `Error::code` values push reports, alongside Client's (`client::err`).
namespace err {
    /// The push server refused a subscription or unsubscription.  The message carries its reason.
    inline constexpr std::string_view rejected = "push.rejected";
    /// The push server could not be reached, or did not answer in a form we understand.
    inline constexpr std::string_view request_failed = "push.request_failed";
}  // namespace err

/// The platform push service a device receives pushes through.
enum class Service {
    apns,
    /// APNs' development environment: what a build signed for development is issued tokens by.  Its
    /// tokens are not valid in production, so a debug build registers here.
    apns_sandbox,
    firebase,
    huawei,
};

/// The name the push server knows a service by.
std::string_view to_string(Service s);

/// What a device registers with: its push service, and the token that service issued it -- the
/// APNs device token in hex, or the FCM or HMS registration token, exactly as the platform hands it
/// over.
struct Device {
    Service service;
    std::string token;
};

/// Where push subscriptions are sent.  Session's own server unless a test or a private deployment
/// says otherwise.
struct Server {
    std::string scheme = "https";
    std::string host = "push.getsession.org";
    std::optional<uint16_t> port;
    /// The key onion requests to it are encrypted for.
    network::x25519_pubkey pubkey = network::x25519_pubkey::from_hex(
            "d7557fe563e2610de876c0ac7341b62f3c82d5eea4b62c702392ea4368f51b3b");
};

enum class SubscribeResult {
    /// Sent and accepted: a new subscription, or a renewal or change of one.
    subscribed,
    /// The stored subscription already matches and is recent enough, so nothing was sent.
    unchanged,
};

class Notifications {
  public:
    /// How many swarm members `fetch_message` asks at once.
    static constexpr size_t FETCH_MEMBERS = 3;

    /// How long `fetch_message` waits before asking again, when every member it asked answered
    /// without the message.
    static constexpr auto FETCH_RETRY_DELAY = 2s;

    /// How old a subscription may get before `subscribe` renews it anyway.  The push server drops a
    /// subscription whose signature is over 14 days old; renewing daily, on any run of the app,
    /// keeps people who rarely open it subscribed.
    static constexpr auto RENEW_AFTER = 24h;

    /// How many times a subscription request is sent before `subscribe` or `unsubscribe` reports
    /// it failed, and the wait between tries.  Only a request that did not reach the push server,
    /// or came back without an answer from it, is sent again: a first request on a network that has
    /// only just started often fails that way (a path or tunnel not yet usable), and the next one
    /// gets through.  A refusal is never retried.
    static constexpr int SUBSCRIBE_ATTEMPTS = 3;
    static constexpr auto SUBSCRIBE_RETRY_DELAY = 3s;

    /// Must not outlive `client`.
    explicit Notifications(client::Client& client, Server server = {}) :
            _client{client}, _server{std::move(server)} {}

    /// The key the push server encrypts this device's pushes with, for `decode`.  Created on first
    /// use and kept in the account's database, so the application and its notification extension
    /// read the same one.  Callable from any thread.
    b32 encryption_key();

    /// The namespaces of the account's swarm that pushes are subscribed for: every namespace Core
    /// polls, less any excluded with a reason (see the definition), in ascending order.
    static std::vector<config::Namespace> account_namespaces();

    /// Subscribes this device to pushes for the account, or renews its subscription.
    ///
    /// Sends only when needed: when there is no subscription, when `device` or the namespaces
    /// differ from the one recorded, or when the last one is older than RENEW_AFTER -- or always,
    /// with `force`.  So it is cheap to call on every run of the application, including background
    /// ones.  A changed token also unsubscribes the old one, best effort: the push service has
    /// usually stopped honouring it anyway.
    ///
    /// `cb` gets `subscribed` or `unchanged`, or an error: `client::err::network_unavailable`
    /// without a network or account, `err::rejected` with the push server's reason, or
    /// `err::request_failed`.  Called through the Client's dispatcher, like its other results.
    ///
    /// TODO: two registrations per device, one with message data for the namespaces that become
    /// notifications and one without for the rest, so that the push server never receives data it
    /// would only withhold.  The push server accepts one registration per device and account today,
    /// so this sends one, with data for every namespace.
    void subscribe(Device device, result_function<SubscribeResult> cb, bool force = false);

    /// Removes this device's subscription, if it has one.  `cb` gets true once the push server has
    /// accepted the removal (or there was nothing to remove), or an error as for `subscribe`.
    void unsubscribe(result_function<bool> cb);

    /// Handles one push: decodes `enc_payload` (the base64 text of the push's `enc_payload` field)
    /// with this device's key, then receives the message it carried, or fetches the message it
    /// could not carry, or fetches what a push without data stands for where that matters now (see
    /// `fetch_on_push`): the device group, whose change may be a key rotation or a link request;
    /// the read state, so that notifications for what was read elsewhere can be removed; and
    /// contacts and groups, so that a notification shows current names.
    ///
    /// Fetching is bounded by `deadline`; see `fetch_message`.  A message the push carried is
    /// received without touching the retrieve cursor, since a push is not a position in what any
    /// swarm member has returned.
    ///
    /// `cb` is called exactly once, through the Client's dispatcher.
    void handle(
            std::string_view enc_payload,
            std::chrono::milliseconds deadline,
            result_function<HandledPush> cb);

    /// Claims the posting of the notification for message `message_id`: true for the first caller
    /// across every process sharing the database, false for every caller after.  Call it just
    /// before posting, and post only on true -- the application and its notification extension can
    /// both receive the same message (a push racing a poll), and only one of them should show it.
    ///
    /// A claim lasts until it can no longer matter -- its notification taken down, or
    /// CLAIM_LIFETIME gone by -- except that a conversation's newest claim lasts as long as its
    /// message, which is what keeps a message request to one notification; `stale` prunes them.
    /// Throws if no such message exists.  Blocks until done; callable from any thread.
    bool claim(int64_t message_id);

    /// How long a claim is kept: the longest a one-to-one message stays in a swarm, and so the
    /// longest it can be delivered a second time and need deduplicating.
    static constexpr auto CLAIM_LIFETIME = std::chrono::days{14};

    /// Shared by every generic notification as both identifier and thread.
    static constexpr std::string_view GENERIC_ID = "generic";

    /// The thread every message request is grouped under.
    static constexpr std::string_view REQUESTS_THREAD = "message-requests";

    /// Decides what, if anything, to show for a handled push, and claims it: a result means this
    /// process has the claim and should post it; nullopt means show nothing.
    ///
    /// Takes what `handle` reported, so it always runs after the push's message has been received:
    /// stored, with any conversation that receiving it created already there to read the settings
    /// of.  (A message request's conversation is created by its first message, for one.)
    ///
    /// Shown: an incoming message, unread, not deleted, in a conversation that is neither muted
    /// nor silenced, from a sender not blocked -- and for a message request only its first, until
    /// the request is removed.  `open` is the conversation on screen, which gets no notification.
    /// Mentions-only is a group setting and reads as "all" on a one-to-one conversation.
    ///
    /// Generic: a push whose payload would not decrypt or decode, and a one-to-one message that
    /// had to be fetched and could not be, or that did not decrypt.  Everything else is silent:
    /// configs, control messages (none of which Client stores), our own messages, and pushes for
    /// swarms we do not hold.
    ///
    /// The content follows the privacy setting (`config::Local::get_notification_content`).
    ///
    /// Blocks until done; callable from any thread.
    ///
    /// TODO: groups, group titles and mentions, once Client holds groups.
    ///
    /// `you` is the application's own word for the user, in the user's language, which a mention of
    /// the user becomes (`@You` in English): the one piece of text libsession writes into the
    /// content, so the caller supplies it rather than libsession assuming English.
    std::optional<NotificationContent> decide(
            const HandledPush& handled,
            std::string_view you,
            std::optional<client::ConversationId> open = std::nullopt);

    /// The identifiers of shown notifications whose messages have since been read or deleted, to
    /// take down; each is reported once.  Also prunes claims that can no longer matter (see
    /// `claim`).  Call after `handle`, and whenever read state changes --
    /// which, for what was read on another device, `handle` fetches.  Blocks; callable from any
    /// thread.
    std::vector<std::string> stale();

    /// Namespaces subscribed without message data whose pushes `handle` fetches for, because what
    /// changed there affects what a notification can show or whether a later message can be read.
    static bool fetch_on_push(config::Namespace ns);

    /// The namespace `handle` fetches before `ns`, when `ns` is encrypted with keys that arrive in
    /// another: a group's info and members, re-encrypted with its newest keys.
    static std::optional<config::Namespace> fetch_first(config::Namespace ns);

    /// Fetches a message that a push announced but could not carry: the push server leaves out a
    /// body too large for a notification, and sends its namespace and swarm hash instead.  What is
    /// found is received exactly as a poll would receive it, so its handlers -- and the Client's
    /// message storage and notifications -- run as usual.
    ///
    /// The push server can notify before a message has reached every member of the swarm, so a
    /// single member may not have it yet.  This asks FETCH_MEMBERS members at once, and the first
    /// that has it ends the fetch.  If every one answers without it, it asks again once, after
    /// FETCH_RETRY_DELAY, provided that leaves time before `deadline`.  Reaching `deadline` ends it
    /// with whatever it has: not_found if any member answered, failed if none did.
    ///
    /// Answers arriving after `cb` are still received, as they came from our own swarm.
    ///
    /// `cb` is called exactly once, through the Client's dispatcher like its other results.
    ///
    /// TODO: ask for the message by its hash once storage servers can retrieve one.  Until then
    /// each member is asked for `ns` from that member's own retrieve cursor, as a poll would, and
    /// "found" means the hash was among what came back.  That is correct today, at the cost of
    /// fetching whatever else arrived since that member was last polled.  A retrieve by hash says
    /// nothing about a member's position, so once it replaces this, its answer must no longer
    /// advance the cursor.
    void fetch_message(
            config::Namespace ns,
            std::string hash,
            std::chrono::milliseconds deadline,
            result_function<FetchedMessage> cb);

  private:
    client::Client& _client;
    Server _server;
};

}  // namespace session::push
