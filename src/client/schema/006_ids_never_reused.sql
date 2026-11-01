-- AUTOINCREMENT can only be had by recreating the table.  Every table referencing one being
-- recreated has to be recreated alongside it: migrations run with foreign keys on, so dropping the
-- old parent would cascade into the children's rows -- and renaming it aside first does not help,
-- since the rename carries the children's references along with it.
CREATE TABLE attachment_cache_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    last_used INTEGER NOT NULL
) STRICT;

CREATE TABLE messages_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    msgid INTEGER,
    swarm_hash TEXT UNIQUE,
    sender INTEGER NOT NULL REFERENCES accounts(id),
    outgoing INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    body TEXT NOT NULL,
    send_state INTEGER,
    sync_send_state INTEGER,
    deleted INTEGER,
    gallery INTEGER NOT NULL DEFAULT 0,
    reply_author INTEGER REFERENCES accounts(id),
    reply_timestamp INTEGER,
    reply_msgid INTEGER
) STRICT;

CREATE TABLE message_raw_content_new (
    message INTEGER PRIMARY KEY REFERENCES messages_new(id) ON DELETE CASCADE,
    content BLOB NOT NULL
) STRICT;

CREATE TABLE message_attachments_new (
    message INTEGER NOT NULL REFERENCES messages_new(id) ON DELETE CASCADE,
    idx INTEGER NOT NULL,
    path TEXT,
    content_type TEXT,
    filename TEXT,
    flags INTEGER NOT NULL DEFAULT 0,
    width INTEGER,
    height INTEGER,
    url TEXT,
    key BLOB,
    size INTEGER,
    digest BLOB,
    saved_at INTEGER,
    unavailable INTEGER,
    cached INTEGER REFERENCES attachment_cache_new(id) ON DELETE SET NULL,
    thumbhash BLOB,
    PRIMARY KEY (message, idx)
) STRICT;

INSERT INTO attachment_cache_new (id, name, size, last_used)
    SELECT id, name, size, last_used FROM attachment_cache;

-- Not through the messages triggers, which belong to the old table: `conversations.count` already
-- counts these rows, and neither this nor dropping the old table below changes it.
INSERT INTO messages_new (
        id, conversation, msgid, swarm_hash, sender, outgoing, timestamp, body, send_state,
        sync_send_state, deleted, gallery, reply_author, reply_timestamp, reply_msgid)
    SELECT
        id, conversation, msgid, swarm_hash, sender, outgoing, timestamp, body, send_state,
        sync_send_state, deleted, gallery, reply_author, reply_timestamp, reply_msgid
    FROM messages;

INSERT INTO message_raw_content_new (message, content)
    SELECT message, content FROM message_raw_content;

INSERT INTO message_attachments_new (
        message, idx, path, content_type, filename, flags, width, height, url, key, size, digest,
        saved_at, unavailable, cached, thumbhash)
    SELECT
        message, idx, path, content_type, filename, flags, width, height, url, key, size, digest,
        saved_at, unavailable, cached, thumbhash
    FROM message_attachments;

-- Children before parents, so that nothing is left referencing a table as it goes.
DROP TABLE message_attachments;
DROP TABLE message_raw_content;
DROP TABLE messages;
DROP TABLE attachment_cache;

ALTER TABLE attachment_cache_new RENAME TO attachment_cache;
ALTER TABLE messages_new RENAME TO messages;
ALTER TABLE message_raw_content_new RENAME TO message_raw_content;
ALTER TABLE message_attachments_new RENAME TO message_attachments;

CREATE INDEX attachment_cache_lru ON attachment_cache(last_used);

CREATE UNIQUE INDEX messages_msgid ON messages(conversation, timestamp, msgid);
CREATE INDEX messages_history ON messages(conversation, timestamp DESC, id DESC);
CREATE INDEX messages_unread ON messages(conversation, timestamp) WHERE outgoing = 0;
CREATE INDEX messages_wire_key ON messages(conversation, sender, timestamp);
CREATE INDEX messages_reply_target ON messages(conversation, reply_author, reply_timestamp)
    WHERE reply_timestamp IS NOT NULL;

CREATE INDEX message_attachments_url ON message_attachments(url) WHERE url IS NOT NULL;
CREATE INDEX message_attachments_cached ON message_attachments(cached) WHERE cached IS NOT NULL;

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
