-- A device can now leave a group as well as be removed from one, so Left takes rank 3 and Kicked
-- moves up to 4, and device ids shrink from 32 bytes to 16.  Changing the CHECKs that pin that down
-- means recreating `devices`, and with it the two tables that reference it: migrations run with
-- foreign keys on, so dropping the old parent would cascade into the children's rows.
CREATE TABLE devices_new (
    id INTEGER PRIMARY KEY NOT NULL,
    unique_id BLOB UNIQUE NOT NULL CHECK(length(unique_id) == 16),
    state INTEGER NOT NULL CHECK(state >= 0 AND state <= 4),
    seqno INTEGER NOT NULL DEFAULT 1,
    broadcast_needed INTEGER NOT NULL DEFAULT 0,
    timestamp INTEGER NOT NULL,
    kicked_timestamp INTEGER CHECK(kicked_timestamp > 0),
    removed_by_us INTEGER NOT NULL DEFAULT 0 CHECK(removed_by_us IN (0, 1)),
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

-- A migrated row has no digest, and gets one only when its seqno next changes: at an equal state
-- and seqno, comparing against a NULL digest is NULL, which rejects the update.
--
-- A device id keeps its first 16 bytes, which are as random as the rest of it: our own, here and
-- in `globals`, and those of devices that asked to join.
--
-- What this device describes itself as now lives in `globals` instead, and is not carried over
-- from its row: an application sets it at every start, through `update_info`.
INSERT INTO devices_new (
        id, unique_id, state, seqno, broadcast_needed, timestamp, kicked_timestamp, device_type,
        description, version, pubkey_mlkem768, pubkey_x25519)
    SELECT
        id, substr(unique_id, 1, 16), CASE state WHEN 3 THEN 4 ELSE state END, seqno,
        broadcast_needed, timestamp, kicked_timestamp, device_type, description, version,
        pubkey_mlkem768, pubkey_x25519
    FROM devices;

UPDATE globals SET value = substr(value, 1, 16) WHERE key = 'device_unique_id';

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

-- A group from before identifiers -- this device registered (state 2) in one -- gets one now, made
-- as a group created now would make it: the creation minute as a little-endian 32-bit integer, then
-- 4 random bytes.  Its device is its only member -- nothing before device groups pushed a group
-- message -- so no other copy of the group can have been given a different one, and the device
-- publishes this one with its next push.
INSERT INTO globals (key, value)
    SELECT 'devices_group_id',
           unhex(substr(m, 7, 2) || substr(m, 5, 2) || substr(m, 3, 2) || substr(m, 1, 2))
               || randomblob(4)
    FROM (SELECT printf('%08X', unixepoch() / 60) AS m)
    WHERE EXISTS (
        SELECT 1 FROM devices JOIN globals ON globals.value = devices.unique_id
        WHERE globals.key = 'device_unique_id' AND devices.state = 2);

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

CREATE TABLE device_account_key_recipients (
    key INTEGER NOT NULL REFERENCES device_account_keys(id) ON DELETE CASCADE,
    device BLOB NOT NULL CHECK(length(device) == 16),
    PRIMARY KEY(key, device)
) STRICT, WITHOUT ROWID;

CREATE TABLE device_group_merged (
    hash TEXT PRIMARY KEY NOT NULL
) STRICT;

CREATE TABLE device_groups (
    group_id BLOB PRIMARY KEY NOT NULL CHECK(length(group_id) == 8),
    link_x25519 BLOB NOT NULL CHECK(length(link_x25519) == 32),
    seen_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;

CREATE TABLE device_group_messages (
    hash TEXT PRIMARY KEY NOT NULL,
    group_id BLOB NOT NULL CHECK(length(group_id) == 8),
    expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX device_group_messages_group ON device_group_messages(group_id);

CREATE TABLE device_dissolved_groups (
    group_id BLOB PRIMARY KEY NOT NULL CHECK(length(group_id) == 8),
    dissolved_at INTEGER NOT NULL
) STRICT;

CREATE TABLE device_pending_pushes (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    message BLOB,
    obsolete BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE device_own_requests (
    id INTEGER PRIMARY KEY NOT NULL,
    group_id BLOB NOT NULL CHECK(length(group_id) == 8),
    timestamp INTEGER UNIQUE NOT NULL,
    pubkey_x25519 BLOB NOT NULL CHECK(length(pubkey_x25519) == 32),
    sas_seed BLOB NOT NULL CHECK(length(sas_seed) == 16),
    expires_at INTEGER,
    admission BLOB,
    admission_hash TEXT,
    CHECK((admission IS NULL) == (admission_hash IS NULL))
) STRICT;
