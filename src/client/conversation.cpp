#include <session/client.hpp>

// Every operation here is one line of dispatch onto a `_`-form on Client: the work itself lives
// there, next to the rest of what touches the database, and this file is only about which thread it
// happens on and who is told.  The pairing is mechanical -- a handler form hands the work to
// `_async`, a waiting form hands it to the loop and lets it throw -- which is why they are together
// rather than split by direction.
//
// **A handler form must not capture `this`.**  It returns before the work runs, and the caller is
// under no obligation to keep this object alive until then: the natural way to write any of these
// is on a temporary (`client.conversation(id, …)` hands one to a handler, and
// `*client.conversation(id, await)` is a temporary outright), and a list element dies whenever the
// list is replaced.  So each captures the two things the work needs -- the Client, which outlives
// everything here, and the id, which is a value -- and nothing else.  Capturing `this` reads the id
// out of freed memory, which surfaces as a `ConversationId::Type` outside the enum and an
// "unhandled conversation kind" from a long way away.
//
// The waiting forms are exempt: `call_get` runs the work before returning, inline when it is
// already the loop's thread, so there is no window in which the object could have gone.  That
// asymmetry is also why tests written entirely in the waiting form prove nothing about the handler
// form.

namespace session::client {

// -- Reading ------------------------------------------------------------------------------------

void Conversation::messages(result_function<std::vector<Message>> cb) const {
    messages(50, std::nullopt, std::move(cb));
}
void Conversation::messages(int limit, result_function<std::vector<Message>> cb) const {
    messages(limit, std::nullopt, std::move(cb));
}
void Conversation::messages(
        int limit,
        std::optional<MessageCursor> before,
        result_function<std::vector<Message>> cb) const {
    messages(limit, before, false, std::move(cb));
}
void Conversation::messages(
        int limit,
        std::optional<MessageCursor> before,
        bool include_deleted,
        result_function<std::vector<Message>> cb) const {
    _client->_require_page("messages", limit);
    _client->_async(
            [c = _client, id = id, limit, before, include_deleted] {
                return c->_messages(id, limit, before, include_deleted);
            },
            std::move(cb));
}

std::vector<Message> Conversation::messages(await_t) const {
    return messages(50, std::nullopt, await);
}
std::vector<Message> Conversation::messages(int limit, await_t) const {
    return messages(limit, std::nullopt, await);
}
std::vector<Message> Conversation::messages(
        int limit, std::optional<MessageCursor> before, await_t) const {
    return messages(limit, before, false, await);
}
std::vector<Message> Conversation::messages(
        int limit, std::optional<MessageCursor> before, bool include_deleted, await_t) const {
    _client->_require_page("messages", limit);
    return _client->call_get([this, limit, before, include_deleted] {
        return _client->_messages(id, limit, before, include_deleted);
    });
}

void Conversation::messages_after(
        int limit, MessageCursor after, result_function<std::vector<Message>> cb) const {
    messages_after(limit, after, false, std::move(cb));
}
void Conversation::messages_after(
        int limit,
        MessageCursor after,
        bool include_deleted,
        result_function<std::vector<Message>> cb) const {
    _client->_require_page("messages_after", limit);
    _client->_async(
            [c = _client, id = id, limit, after, include_deleted] {
                return c->_messages_after(id, limit, after, include_deleted);
            },
            std::move(cb));
}
std::vector<Message> Conversation::messages_after(int limit, MessageCursor after, await_t) const {
    return messages_after(limit, after, false, await);
}
std::vector<Message> Conversation::messages_after(
        int limit, MessageCursor after, bool include_deleted, await_t) const {
    _client->_require_page("messages_after", limit);
    return _client->call_get([this, limit, after, include_deleted] {
        return _client->_messages_after(id, limit, after, include_deleted);
    });
}

void Conversation::messages_around(
        int limit, MessageCursor at, result_function<std::vector<Message>> cb) const {
    messages_around(limit, at, false, std::move(cb));
}
void Conversation::messages_around(
        int limit,
        MessageCursor at,
        bool include_deleted,
        result_function<std::vector<Message>> cb) const {
    _client->_require_page("messages_around", limit);
    _client->_async(
            [c = _client, id = id, limit, at, include_deleted] {
                return c->_messages_around(id, limit, at, include_deleted);
            },
            std::move(cb));
}
std::vector<Message> Conversation::messages_around(int limit, MessageCursor at, await_t) const {
    return messages_around(limit, at, false, await);
}
std::vector<Message> Conversation::messages_around(
        int limit, MessageCursor at, bool include_deleted, await_t) const {
    _client->_require_page("messages_around", limit);
    return _client->call_get([this, limit, at, include_deleted] {
        return _client->_messages_around(id, limit, at, include_deleted);
    });
}

void Conversation::first_unread(result_function<std::optional<MessageCursor>> cb) const {
    _client->_async([c = _client, id = id] { return c->_first_unread(id); }, std::move(cb));
}
std::optional<MessageCursor> Conversation::first_unread(await_t) const {
    return _client->call_get([this] { return _client->_first_unread(id); });
}

void Conversation::purge_deleted(result_function<size_t> cb) {
    _client->_require_dm("purge_deleted", id);
    _client->_async([c = _client, id = id] { return c->_purge_deleted(id); }, std::move(cb));
}
size_t Conversation::purge_deleted(await_t) {
    _client->_require_dm("purge_deleted", id);
    return _client->call_get([this] { return _client->_purge_deleted(id); });
}

// -- Read state ---------------------------------------------------------------------------------

void Conversation::mark_read(result_function<> cb) {
    mark_read(std::nullopt, std::move(cb));
}
void Conversation::mark_read(std::optional<sys_ms> up_to, result_function<> cb) {
    _client->_async([c = _client, id = id, up_to] { c->_mark_read(id, up_to); }, std::move(cb));
}
void Conversation::mark_read(await_t) {
    mark_read(std::nullopt, await);
}
void Conversation::mark_read(std::optional<sys_ms> up_to, await_t) {
    _client->call_get([this, up_to] { _client->_mark_read(id, up_to); });
}

void Conversation::set_marked_unread(bool unread, result_function<> cb) {
    _client->_async(
            [c = _client, id = id, unread] { c->_set_marked_unread(id, unread); }, std::move(cb));
}
void Conversation::set_marked_unread(bool unread, await_t) {
    _client->call_get([this, unread] { _client->_set_marked_unread(id, unread); });
}

// -- Settings -----------------------------------------------------------------------------------

void Conversation::set_priority(int priority, result_function<> cb) {
    _client->_async(
            [c = _client, id = id, priority] { c->_set_priority(id, priority); }, std::move(cb));
}
void Conversation::set_priority(int priority, await_t) {
    _client->call_get([this, priority] { _client->_set_priority(id, priority); });
}

void Conversation::set_notifications(config::notify_mode mode, result_function<> cb) {
    _client->_async(
            [c = _client, id = id, mode] { c->_set_notifications(id, mode); }, std::move(cb));
}
void Conversation::set_notifications(config::notify_mode mode, await_t) {
    _client->call_get([this, mode] { _client->_set_notifications(id, mode); });
}

void Conversation::set_mute_until(std::chrono::sys_seconds until, result_function<> cb) {
    _client->_async(
            [c = _client, id = id, until] { c->_set_mute_until(id, until); }, std::move(cb));
}
void Conversation::set_mute_until(std::chrono::sys_seconds until, await_t) {
    _client->call_get([this, until] { _client->_set_mute_until(id, until); });
}

void Conversation::set_expiry(
        config::expiration_mode mode, std::chrono::seconds timer, result_function<> cb) {
    _client->_async(
            [c = _client, id = id, mode, timer] { c->_set_expiry(id, mode, timer); },
            std::move(cb));
}
void Conversation::set_expiry(config::expiration_mode mode, std::chrono::seconds timer, await_t) {
    _client->call_get([this, mode, timer] { _client->_set_expiry(id, mode, timer); });
}

void Conversation::set_auto_download(AutoDownload mode, result_function<> cb) {
    _client->_async(
            [c = _client, id = id, mode] { c->_set_auto_download(id, mode); }, std::move(cb));
}
void Conversation::set_auto_download(AutoDownload mode, await_t) {
    _client->call_get([this, mode] { _client->_set_auto_download(id, mode); });
}

// -- Sending ------------------------------------------------------------------------------------

void Conversation::send_message(
        OutgoingMessage msg, upload_progress on_upload, result_function<int64_t> cb) {
    _client->_require_sendable("send_message", id, msg);
    _client->_async(
            [c = _client, id = id, msg = std::move(msg), on_upload = std::move(on_upload)] {
                return c->_send_message(id, msg, on_upload);
            },
            std::move(cb));
}
void Conversation::send_message(OutgoingMessage msg, result_function<int64_t> cb) {
    send_message(std::move(msg), nullptr, std::move(cb));
}
int64_t Conversation::send_message(OutgoingMessage msg, await_t) {
    return send_message(std::move(msg), nullptr, await);
}
int64_t Conversation::send_message(OutgoingMessage msg, upload_progress on_upload, await_t) {
    _client->_require_sendable("send_message", id, msg);
    return _client->call_get([&] { return _client->_send_message(id, msg, std::move(on_upload)); });
}

// -- Destroying ---------------------------------------------------------------------------------

void Conversation::clear_messages(result_function<> cb) {
    _client->_require_dm("clear_messages", id);
    _client->_async([c = _client, id = id] { c->_clear_messages(id); }, std::move(cb));
}
void Conversation::clear_messages(await_t) {
    _client->_require_dm("clear_messages", id);
    _client->call_get([this] { _client->_clear_messages(id); });
}

void Conversation::delete_conversation(result_function<> cb) {
    delete_conversation(false, std::move(cb));
}
void Conversation::delete_conversation(bool keep_messages, result_function<> cb) {
    _client->_require_dm("delete_conversation", id);
    _client->_async(
            [c = _client, id = id, keep_messages] { c->_delete_conversation(id, keep_messages); },
            std::move(cb));
}
void Conversation::delete_conversation(await_t) {
    delete_conversation(false, await);
}
void Conversation::delete_conversation(bool keep_messages, await_t) {
    _client->_require_dm("delete_conversation", id);
    _client->call_get([this, keep_messages] { _client->_delete_conversation(id, keep_messages); });
}

// -- One-to-one only ----------------------------------------------------------------------------

void DM::set_blocked(bool blocked, result_function<> cb) {
    _client->_require_contact("set_blocked", id);
    _client->_async(
            [c = _client, id = id, blocked] { c->_set_blocked(id, blocked); }, std::move(cb));
}
void DM::set_blocked(bool blocked, await_t) {
    _client->_require_contact("set_blocked", id);
    _client->call_get([this, blocked] { _client->_set_blocked(id, blocked); });
}

void DM::set_nickname(std::string_view nickname, result_function<> cb) {
    _client->_require_contact("set_nickname", id);
    _client->_async(
            [c = _client, id = id, nickname = std::string{nickname}] {
                c->_set_nickname(id, nickname);
            },
            std::move(cb));
}
void DM::set_nickname(std::string_view nickname, await_t) {
    _client->_require_contact("set_nickname", id);
    _client->call_get([this, nickname] { _client->_set_nickname(id, nickname); });
}

void DM::delete_contact(result_function<> cb) {
    _client->_require_contact("delete_contact", id);
    _client->_async([c = _client, id = id] { c->_delete_contact(id); }, std::move(cb));
}
void DM::delete_contact(await_t) {
    _client->_require_contact("delete_contact", id);
    _client->call_get([this] { _client->_delete_contact(id); });
}

}  // namespace session::client
