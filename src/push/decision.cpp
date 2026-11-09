#include <oxenc/hex.h>

#include <oxen/log.hpp>
#include <session/clock.hpp>
#include <session/config/local.hpp>
#include <session/config/notify.hpp>
#include <session/format.hpp>
#include <session/push/notifications.hpp>

namespace session::push {

namespace log = oxen::log;
static auto cat = log::Cat("push");

using namespace session::literals;

// What reaches a notification, and what does not -- every kind of incoming content, so that one
// added later is a visible decision rather than whatever falls out:
//
// - An ordinary message (text and/or attachments): shown, subject to `decide`'s rules.
// - The first message of a message request: shown, without sender or contents.
// - A control message -- typing, read receipts, call signalling, expiry-timer changes, a request
//   being accepted, "media saved" (whose future is undecided) -- is not stored by Client, so there
//   is nothing to show and it is silent.
// - An unsend or a deletion takes its message's notification down rather than adding one; see
//   `stale`.
// - Not yet handled by Client, and so silent until it is: reactions (to show for reactions to our
//   own messages, never in mentions-only), calls (CallKit, decided separately), and group
//   membership and name changes (to show, as they concern the user directly).

namespace {

    NotificationContent generic() {
        NotificationContent n;
        n.kind = NotificationContent::Kind::generic;
        n.id = Notifications::GENERIC_ID;
        n.thread = Notifications::GENERIC_ID;
        n.timestamp = clock_now_ms();
        return n;
    }

    // A message's notification identifier: its swarm hash, which is what a removal names.  Every
    // incoming message has one; the fallback only keeps the identifier stable if one ever does
    // not.
    std::string notification_id(const std::optional<std::string>& hash, int64_t message_id) {
        return hash ? *hash : "message-{}"_format(message_id);
    }

    AttachmentKind kind_of(const client::Attachment& a) {
        if (a.voice_message)
            return AttachmentKind::voice;
        auto type = a.content_type.value_or("");
        if (type == "image/gif")
            return AttachmentKind::animated;
        if (type.starts_with("image/"))
            return AttachmentKind::image;
        if (type.starts_with("video/"))
            return AttachmentKind::video;
        if (type.starts_with("audio/"))
            return AttachmentKind::audio;
        return AttachmentKind::file;
    }

    std::string truncated_id(std::string_view hex) {
        return hex.size() > 8 ? "({}…{})"_format(hex.substr(0, 4), hex.substr(hex.size() - 4))
                              : std::string{hex};
    }

    // `@` followed by a session id becomes `@Name`, or `@` and the caller's `you` for us; one with
    // no known name keeps a shortened id, as a conversation shows an unnamed sender.
    std::string resolve_mentions(core::Core& core, std::string_view body, std::string_view you) {
        std::string me = core.globals.have_account() ? core.globals.session_id_hex() : "";
        std::string out;
        size_t i = 0;
        while (i < body.size()) {
            auto at = body.find('@', i);
            if (at == std::string_view::npos || at + 1 + 66 > body.size()) {
                out.append(body.substr(i));
                break;
            }
            out.append(body.substr(i, at - i));
            auto id = body.substr(at + 1, 66);
            if (!id.starts_with("05") || !oxenc::is_hex(id)) {
                out += '@';
                i = at + 1;
                continue;
            }
            if (id == me) {
                out += '@';
                out += you;
            } else {
                auto name = core.database().conn().prepared_maybe_get<std::string>(
                        R"(
SELECT COALESCE(ct.nickname, a.name) FROM accounts a LEFT JOIN contacts ct ON ct.account = a.id
 WHERE a.session_id = ?
)",
                        to_vector<std::byte>(oxenc::from_hex(id)));
                out += '@';
                out += name && !name->empty() ? *name : truncated_id(id);
            }
            i = at + 1 + 66;
        }
        return out;
    }

}  // namespace

std::optional<NotificationContent> Notifications::decide(
        const HandledPush& handled,
        std::string_view you,
        std::optional<client::ConversationId> open) {
    switch (handled.outcome) {
        case Handled::undecryptable:
        case Handled::malformed: return generic();

        // A one-to-one message we know exists and could not read.
        case Handled::unreadable:
            if (handled.payload && handled.payload->ns == config::Namespace::Default)
                return generic();
            return std::nullopt;

        case Handled::not_found:
        case Handled::fetch_failed:
            // A poll may have brought it in regardless.
            if (handled.message)
                break;
            // A one-to-one message we know exists and could not get.  TODO: a group's, naming the
            // group, once Client holds groups.
            if (handled.payload && handled.payload->ns == config::Namespace::Default)
                return generic();
            return std::nullopt;

        case Handled::nothing_to_do:
        case Handled::not_ours: return std::nullopt;

        case Handled::received:
        case Handled::fetched: break;
    }

    // Nothing stored: a config, a control message, our own other device's copy of something Client
    // keeps elsewhere, or a sender Client refused.
    if (!handled.message)
        return std::nullopt;
    const auto& m = *handled.message;
    if (m.outgoing || m.deleted)
        return std::nullopt;
    if (open && *open == m.conversation)
        return std::nullopt;

    auto convo = _client.conversation(m.conversation, await);
    if (!convo)
        return std::nullopt;
    auto* dm = std::get_if<client::DM>(&convo->kind);
    if (dm && dm->blocked)
        return std::nullopt;
    if (convo->notifications() == config::notify_mode::disabled)
        return std::nullopt;
    // TODO: in a mentions-only group, show only a message that mentions us (an `@` of our id or a
    // reply to one of our messages), once Client holds groups and records mentions.  On a
    // one-to-one conversation mentions-only reads as "all", so nothing is missing until then.
    if (convo->mute_until() > std::chrono::floor<std::chrono::seconds>(clock_now()))
        return std::nullopt;

    auto& core = _client.core;
    bool request = dm && dm->request;
    auto [unread, request_notified, privacy] = core.call_get([&] {
        auto c = core.database().conn();
        bool unread = c.prepared_get<int>(
                              R"(
SELECT m.timestamp > c.last_read FROM messages m JOIN conversations c ON c.id = m.conversation
 WHERE m.id = ?
)",
                              m.id) != 0;
        // The first message of a request since the request was last removed: removing it removes
        // its messages, and their claims with them.
        bool request_notified = request && c.prepared_get<int>(
                                                   R"(
SELECT EXISTS (SELECT 1 FROM notified n JOIN messages o ON o.id = n.message
                WHERE o.conversation = (SELECT conversation FROM messages WHERE id = ?))
)",
                                                   m.id) != 0;
        return std::tuple{
                unread, request_notified, core.configs.local().get_notification_content()};
    });
    if (!unread || request_notified)
        return std::nullopt;

    if (!claim(m.id))
        return std::nullopt;

    NotificationContent n;
    n.id = notification_id(m.hash, m.id);
    n.timestamp = m.timestamp;

    if (request) {
        n.kind = NotificationContent::Kind::message_request;
        n.thread = REQUESTS_THREAD;
        return n;
    }

    n.kind = NotificationContent::Kind::message;
    n.thread = m.conversation.to_string();
    if (privacy == config::notify_content::no_name_no_preview)
        return n;

    auto sender_hex = oxenc::to_hex(m.sender.begin(), m.sender.end());
    n.sender = convo->display_name().empty() ? truncated_id(sender_hex) : convo->display_name();
    if (privacy == config::notify_content::name_no_preview)
        return n;

    if (!m.body.empty())
        n.body = core.call_get([&] { return resolve_mentions(core, m.body, you); });
    if (!m.attachments.empty()) {
        n.attachment = kind_of(m.attachments.front());
        n.attachments = m.attachments.size();
    }
    return n;
}

std::vector<std::string> Notifications::stale() {
    auto& core = _client.core;
    return core.call_get([&core] {
        auto c = core.database().conn();
        auto tx = c.begin_immediate();
        std::vector<int64_t> gone;
        std::vector<std::string> ids;
        for (auto&& [message, hash] : c.prepared_results<int64_t, std::optional<std::string>>(R"(
SELECT n.message, m.swarm_hash
  FROM notified n JOIN messages m ON m.id = n.message JOIN conversations c ON c.id = m.conversation
 WHERE n.removed IS NULL AND (m.deleted IS NOT NULL OR m.timestamp <= c.last_read)
)")) {
            gone.push_back(message);
            ids.push_back(notification_id(hash, message));
        }
        auto now = epoch_ms(clock_now_ms());
        for (auto message : gone)
            c.prepared_exec("UPDATE notified SET removed = ? WHERE message = ?", now, message);

        // Claims that can no longer matter go: one taken down, whose message is read or deleted and
        // so would never be shown again anyway, and one older than any message stays in a swarm to
        // be delivered a second time.  Each conversation's newest claim stays regardless: it is
        // what holds a message request to the one notification for its first message.
        c.prepared_exec(
                R"(
DELETE FROM notified
 WHERE (removed IS NOT NULL OR at < ?)
   AND message NOT IN (SELECT MAX(n.message) FROM notified n JOIN messages m ON m.id = n.message
                        GROUP BY m.conversation)
)",
                now - std::chrono::duration_cast<std::chrono::milliseconds>(CLAIM_LIFETIME)
                                .count());
        tx.commit();
        if (!ids.empty())
            log::debug(cat, "{} shown notification(s) now read or deleted", ids.size());
        return ids;
    });
}

}  // namespace session::push
