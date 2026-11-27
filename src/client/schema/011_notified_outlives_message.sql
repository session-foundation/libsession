-- A claim outlives its message, so that a notification posted for one is still reported for taking
-- down once the message is gone: deleting a conversation, clearing it or declining a request
-- deletes its messages outright.  The claim keeps the hash that names its notification, and names
-- its message by id alone, which is never reused (006).  Nothing refers to this table, so it can be
-- rebuilt in place.
CREATE TABLE notified_new (
    message INTEGER PRIMARY KEY,
    hash TEXT,
    at INTEGER NOT NULL,
    removed INTEGER
) STRICT;

INSERT INTO notified_new (message, hash, at, removed)
SELECT n.message, m.swarm_hash, n.at, n.removed
  FROM notified n JOIN messages m ON m.id = n.message;

DROP TABLE notified;
ALTER TABLE notified_new RENAME TO notified;
