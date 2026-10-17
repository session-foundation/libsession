#pragma once

#include <string_view>

namespace client_test {

/// src/client/schema/full_schema.sql from before client migration 000, comments stripped: the one
/// schema every chain of client migrations starts from, which is why an upgrade test can begin at
/// any migration by replaying the ones before it onto this.  Taken from fb80d26c; it moves only
/// when the oldest install an upgrade is tested from does.
inline constexpr std::string_view client_schema_base = R"sql(
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,

    session_id BLOB NOT NULL UNIQUE,
    name TEXT,

    profile_pic_url TEXT,
    profile_pic_key BLOB,
    profile_updated INTEGER NOT NULL DEFAULT 0,

    pro_flags INTEGER NOT NULL DEFAULT 0,

    pro_revocation_tag BLOB,
    pro_expiry INTEGER
) STRICT;

CREATE TABLE contacts (
    account INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    nickname TEXT,

    approved INTEGER NOT NULL DEFAULT 0,
    approved_me INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE groups (
    id INTEGER PRIMARY KEY,
    group_id BLOB NOT NULL UNIQUE
) STRICT;

CREATE TABLE communities (
    id INTEGER PRIMARY KEY,
    base_url TEXT NOT NULL,
    room TEXT NOT NULL,
    UNIQUE (base_url, room)
) STRICT;

CREATE TABLE conversations (
    id INTEGER PRIMARY KEY,

    dm INTEGER UNIQUE REFERENCES accounts(id),
    closed_group INTEGER UNIQUE REFERENCES groups(id),
    community INTEGER UNIQUE REFERENCES communities(id),

    created INTEGER NOT NULL,
    last_activity INTEGER NOT NULL,

    last_read INTEGER NOT NULL DEFAULT 0,

    count INTEGER NOT NULL DEFAULT 0,
    unread_count INTEGER NOT NULL DEFAULT 0,

    priority INTEGER NOT NULL DEFAULT 0,

    marked_unread INTEGER NOT NULL DEFAULT 0,

    notifications INTEGER NOT NULL DEFAULT 0,
    mute_until INTEGER NOT NULL DEFAULT 0,

    exp_mode INTEGER NOT NULL DEFAULT 0,
    exp_timer INTEGER NOT NULL DEFAULT 0,
    CHECK ((dm IS NOT NULL) + (closed_group IS NOT NULL) + (community IS NOT NULL) = 1)
) STRICT;

CREATE INDEX conversations_order ON conversations(priority DESC, last_activity DESC);

CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    conversation INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,

    msgid INTEGER,

    swarm_hash TEXT UNIQUE,
    sender INTEGER NOT NULL REFERENCES accounts(id),
    outgoing INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    body TEXT NOT NULL,

    send_state INTEGER,
    sync_send_state INTEGER
) STRICT;

CREATE UNIQUE INDEX messages_msgid ON messages(conversation, timestamp, msgid);

CREATE INDEX messages_history ON messages(conversation, timestamp DESC, id DESC);
CREATE INDEX messages_unread ON messages(conversation, timestamp) WHERE outgoing = 0;

CREATE INDEX messages_wire_key ON messages(conversation, sender, timestamp);

CREATE TRIGGER messages_insert AFTER INSERT ON messages
BEGIN
    UPDATE conversations SET count = count + 1 WHERE id = NEW.conversation;
END;

CREATE TRIGGER messages_delete AFTER DELETE ON messages
BEGIN
    UPDATE conversations SET count = count - 1 WHERE id = OLD.conversation;
END;

CREATE TRIGGER messages_move AFTER UPDATE OF conversation ON messages
WHEN OLD.conversation != NEW.conversation
BEGIN
    UPDATE conversations SET count = count - 1 WHERE id = OLD.conversation;
    UPDATE conversations SET count = count + 1 WHERE id = NEW.conversation;
END;

CREATE TABLE message_raw_content (
    message INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    content BLOB NOT NULL
) STRICT;

CREATE TABLE message_attachments (
    message INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,

    idx INTEGER NOT NULL,

    path TEXT,

    content_type TEXT,
    filename TEXT,
    caption TEXT,
    flags INTEGER NOT NULL DEFAULT 0,
    width INTEGER,
    height INTEGER,

    url TEXT,
    key BLOB,
    size INTEGER,

    digest BLOB,

    saved_at INTEGER,

    PRIMARY KEY (message, idx)
) STRICT;
)sql";

}  // namespace client_test
