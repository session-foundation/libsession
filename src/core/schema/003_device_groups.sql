-- A device can now leave a group as well as be removed from one, so Left takes rank 3 and Kicked
-- moves up to 4.  Changing the CHECKs that pin that down means recreating `devices`, and with it
-- the two tables that reference it: migrations run with foreign keys on, so dropping the old parent
-- would cascade into the children's rows.
CREATE TABLE devices_new (
    id INTEGER PRIMARY KEY NOT NULL,
    unique_id BLOB UNIQUE NOT NULL CHECK(length(unique_id) == 32),
    state INTEGER NOT NULL CHECK(state >= 0 AND state <= 4),
    seqno INTEGER NOT NULL DEFAULT 1,
    pushed_seqno INTEGER,
    broadcast_needed INTEGER NOT NULL DEFAULT 0,
    timestamp INTEGER NOT NULL,
    kicked_timestamp INTEGER CHECK(kicked_timestamp > 0),
    device_type TEXT NOT NULL,
    description TEXT NOT NULL,
    version INTEGER NOT NULL,
    pubkey_mlkem768 BLOB NOT NULL CHECK(length(pubkey_mlkem768) == 1184),
    pubkey_x25519 BLOB NOT NULL CHECK(length(pubkey_x25519) == 32),
    digest BLOB CHECK(digest IS NULL OR length(digest) == 8),
    CHECK((state >= 3) == (kicked_timestamp IS NOT NULL))
) STRICT;

CREATE TABLE device_unknown_new (
    device INTEGER NOT NULL REFERENCES devices_new(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    bt_value BLOB NOT NULL,
    PRIMARY KEY(device, key)
) STRICT;

CREATE TABLE device_link_requests_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    device INTEGER NOT NULL REFERENCES devices_new(id) ON DELETE CASCADE,
    received_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    status INTEGER NOT NULL DEFAULT 0 CHECK(status >= 0 AND status <= 3),
    sas_seed BLOB NOT NULL CHECK(length(sas_seed) == 16),
    hash TEXT NOT NULL,
    info BLOB NOT NULL,
    replaces INTEGER NOT NULL DEFAULT 0 CHECK(replaces IN (0, 1))
) STRICT;

-- A digest is only recorded as a record is merged, so the next message to carry each device fills
-- it in.
INSERT INTO devices_new (
        id, unique_id, state, seqno, pushed_seqno, broadcast_needed, timestamp, kicked_timestamp,
        device_type, description, version, pubkey_mlkem768, pubkey_x25519)
    SELECT
        id, unique_id, CASE state WHEN 3 THEN 4 ELSE state END, seqno, pushed_seqno,
        broadcast_needed, timestamp, kicked_timestamp, device_type, description, version,
        pubkey_mlkem768, pubkey_x25519
    FROM devices;

INSERT INTO device_unknown_new (device, key, bt_value)
    SELECT device, key, bt_value FROM device_unknown;

-- Link requests are not carried over.  Those stored so far were not encrypted to a group, which no
-- device can answer any more, and lack the swarm hash, expiry and record now kept for each; they
-- would have lapsed within ten minutes regardless.  The requesting devices stay Pending, as an
-- ignored request leaves them.

-- Children before parents, so that nothing is left referencing a table as it goes.
DROP TABLE device_link_requests;
DROP TABLE device_unknown;
DROP TABLE devices;

ALTER TABLE devices_new RENAME TO devices;
ALTER TABLE device_unknown_new RENAME TO device_unknown;
ALTER TABLE device_link_requests_new RENAME TO device_link_requests;

CREATE INDEX device_link_requests_device ON device_link_requests(device);

-- AUTOINCREMENT, which can only be had by recreating the table: leaving a group now deletes every
-- account key, and a push in flight names the rows it distributes.
CREATE TABLE device_account_keys_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    created INTEGER NOT NULL,
    rotated INTEGER,
    distributed INTEGER NOT NULL DEFAULT 0,
    published INTEGER NOT NULL DEFAULT 0,
    seed BLOB UNIQUE NOT NULL CHECK(length(seed) == 32),
    pubkey_mlkem768 BLOB NOT NULL CHECK(length(pubkey_mlkem768) == 1184),
    pubkey_x25519 BLOB NOT NULL CHECK(length(pubkey_x25519) == 32),
    key_indicator BLOB GENERATED ALWAYS AS (substr(pubkey_mlkem768, 1, 2)) VIRTUAL
) STRICT;

INSERT INTO device_account_keys_new (
        id, created, rotated, distributed, published, seed, pubkey_mlkem768, pubkey_x25519)
    SELECT id, created, rotated, distributed, published, seed, pubkey_mlkem768, pubkey_x25519
    FROM device_account_keys;

DROP TABLE device_account_keys;
ALTER TABLE device_account_keys_new RENAME TO device_account_keys;

CREATE INDEX device_account_keys_ki_index ON device_account_keys(key_indicator);

CREATE TRIGGER device_account_key_rotation AFTER INSERT ON device_account_keys
FOR EACH ROW WHEN NEW.rotated IS NULL
BEGIN
    UPDATE device_account_keys SET rotated = winner.created
    FROM (SELECT id, created FROM device_account_keys
          WHERE rotated IS NULL
          ORDER BY created DESC, seed ASC
          LIMIT 1) AS winner
    WHERE device_account_keys.rotated IS NULL AND device_account_keys.id != winner.id;
END;

-- An existing group has no identifier yet.  It gets one from whichever of its devices pushes first,
-- and its other devices adopt it from that message.
CREATE TABLE device_group_merged (
    hash TEXT PRIMARY KEY NOT NULL
) STRICT;

CREATE TABLE device_groups (
    group_id BLOB PRIMARY KEY NOT NULL CHECK(length(group_id) == 8),
    link_x25519 BLOB NOT NULL CHECK(length(link_x25519) == 32),
    seen_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    dismissed INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE device_own_requests (
    id INTEGER PRIMARY KEY NOT NULL,
    group_id BLOB NOT NULL CHECK(length(group_id) == 8),
    timestamp INTEGER UNIQUE NOT NULL,
    pubkey_x25519 BLOB NOT NULL CHECK(length(pubkey_x25519) == 32),
    sas_seed BLOB NOT NULL CHECK(length(sas_seed) == 16),
    expires_at INTEGER,
    confirmed INTEGER NOT NULL DEFAULT 0,
    admission BLOB,
    admission_hash TEXT,
    admission_at INTEGER,
    CHECK((admission IS NULL) == (admission_at IS NULL))
) STRICT;
