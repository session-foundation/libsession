-- Core's schema with every migration in src/core/schema/ applied.  A database with none of them
-- applied is built from this in one step and they are all recorded without running, so this file
-- -- not the migration chain -- is where the current schema is read.
--
-- Keep in step with the migrations: test_core_schema.cpp builds a database both ways and
-- compares them.

-- Table storing all the device group info
CREATE TABLE devices (
    id INTEGER PRIMARY KEY NOT NULL,
    unique_id BLOB UNIQUE NOT NULL CHECK(length(unique_id) == 32),

    -- Membership rank: 0 unregistered, 1 pending, 2 registered, 3 kicked.  Ordered least to most
    -- authoritative because merging compares (state, seqno) as a row value -- see device::State.
    state INTEGER NOT NULL CHECK(state >= 0 AND state <= 3),
    processing INTEGER,  -- non-null during batch processing: 1=new link request, 2=newly registered, 3=newly removed
    seqno INTEGER NOT NULL DEFAULT 1,
    pushed_seqno INTEGER,         -- seqno of the last confirmed device group push; NULL = never pushed
    broadcast_needed INTEGER NOT NULL DEFAULT 0,  -- 1 when a state transition (registered/removed) needs broadcasting
    timestamp INTEGER NOT NULL,
    kicked_timestamp INTEGER,  -- set when the device was kicked from the device group
    device_type TEXT NOT NULL, -- typically a/i/d (Android/iOS/Desktop), but can be anything
    description TEXT NOT NULL, -- freeform device description
    version INTEGER NOT NULL, -- = 1000000*V + 1000*v + p for version "V.v.p"
    pubkey_mlkem768 BLOB NOT NULL CHECK(length(pubkey_mlkem768) == 1184),
    pubkey_x25519 BLOB NOT NULL CHECK(length(pubkey_x25519) == 32),

    -- A kick is the one state that carries a timestamp, and is meaningless without one, so the two
    -- are tied together here rather than left to each call site to remember.
    CHECK((state == 3) == (kicked_timestamp IS NOT NULL))
) STRICT;

-- This table holds any extra info not captured by the above.  The data is stored as key/value pairs
-- where the value is the bt-encoded data received in the last device info message.  The purpose of
-- this is so that future versions that add new fields can have those unknown fields propagated by
-- older clients that do not yet understand them without the older clients silently dropping unknown
-- fields.
CREATE TABLE device_unknown (
    device INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    bt_value BLOB NOT NULL,
    PRIMARY KEY(device, key)
) STRICT;

-- This table tracks pending incoming device link requests from other devices that have been
-- received but not yet accepted, ignored, or denied.  Device info for the requesting device is
-- stored in the devices table (with state=Pending); this table holds the link-request-specific
-- fields: when the request was received locally, and the precomputed Argon2id seed from which
-- the short authentication string emoji are derived (stored to avoid re-running the expensive
-- hash on every display).
CREATE TABLE device_link_requests (
    -- The `reqid` the application is given to tell requests apart, and to match a request to the
    -- device_added that follows it.  AUTOINCREMENT because rows go -- accepted, or aged out -- and
    -- without it the next request would take the id of the newest one gone, so an application
    -- still holding that id would take one device's request for another's.
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    device INTEGER UNIQUE NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    received_at INTEGER NOT NULL,  -- unix timestamp of when this request was stored locally
    sas_seed BLOB NOT NULL CHECK(length(sas_seed) == 16)  -- 16-byte Argon2id output for SAS display
) STRICT;

-- This table holds current and recent device private keys for *this* device, including the
-- timestamp then the device keypairs were created, and when they were rotated away from.
CREATE TABLE device_privkeys (
    id INTEGER PRIMARY KEY NOT NULL,
    created INTEGER NOT NULL, -- unix timestamp
    rotated INTEGER, -- timestamp when a newer key was added, superceding this key
    seed BLOB NOT NULL CHECK(length(seed) == 32)
) STRICT;

-- This trigger handles key rotation: whenever we insert a new key, any existing keys are
-- automatically rotated with the `creation` timestamp of the new row as the rotation timestamp.
CREATE TRIGGER device_privkey_rotation AFTER INSERT ON device_privkeys
FOR EACH ROW WHEN NEW.rotated IS NULL
BEGIN
    UPDATE device_privkeys SET rotated = NEW.created WHERE rotated IS NULL AND id != NEW.id;
END;

-- This table holds current and recent *account* keys, which are shared within the device
-- group and have their public keys published for remote users to use to encrypt messages.
-- Unlike device_privkeys, these keys are shared among all devices in the device group.
CREATE TABLE device_account_keys (
    id INTEGER PRIMARY KEY NOT NULL,
    created INTEGER NOT NULL,
    rotated INTEGER, -- timestamp when a new key superceded this key
    distributed INTEGER NOT NULL DEFAULT 0,  -- 1 once this key's seed has been included in a confirmed device group push
    published INTEGER NOT NULL DEFAULT 0,    -- 1 once this key's pubkeys have been confirmed pushed as the account pubkey message
    seed BLOB UNIQUE NOT NULL CHECK(length(seed) == 32),
    pubkey_mlkem768 BLOB NOT NULL CHECK(length(pubkey_mlkem768) == 1184),
    pubkey_x25519 BLOB NOT NULL CHECK(length(pubkey_x25519) == 32),
    -- Virtual column containing the first two mlkem pubkey values to assist with lookups based on
    -- incoming message key indicator:
    key_indicator BLOB GENERATED ALWAYS AS (substr(pubkey_mlkem768, 1, 2)) VIRTUAL
) STRICT;
CREATE INDEX device_account_keys_ki_index ON device_account_keys(key_indicator);

-- When a new account key is inserted as active (rotated IS NULL), apply deterministic
-- tie-breaking: the key with the latest created timestamp wins (ties broken by smallest seed),
-- and all unrotated losers are immediately marked as rotated at the winner's creation time.
-- This handles concurrent rotations from multiple devices: once all devices sync, the trigger
-- guarantees they all converge on the same active key regardless of insertion order.
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

-- from 000_config_dumps.sql
-- The serialised state of each config object, so a config survives a restart without being rebuilt
-- from its swarm.  A dump holds the merged config together with the bookkeeping a merge needs --
-- which message hashes currently represent it, and which ones it obsoletes -- so restoring one is
-- what lets this device rejoin an ongoing exchange with its other devices rather than starting from
-- whatever the swarm happens to still hold.
--
-- Keyed by the config's encryption domain rather than its storage namespace.  The two coincide for
-- most configs but answer different questions: the domain says *which config this is*, while the
-- namespace says *where it is pushed*, which the Local config has no answer for -- it is never
-- pushed anywhere, and reports UserProfile's namespace as a stand-in.  The domain is also already
-- required to be unique per config type, and can never be changed, since changing it would break
-- decryption of everything previously written under it.
--
-- pubkey is whose config it is: this account's, or a particular group's.  Configs for different
-- pubkeys are stored, pushed and fetched separately even when their swarms coincide.
CREATE TABLE config_dumps (
    pubkey BLOB NOT NULL CHECK(length(pubkey) = 33),
    type TEXT NOT NULL,     -- ConfigBase::encryption_domain(): "UserProfile", "Contacts", ...
    data BLOB NOT NULL,
    PRIMARY KEY (pubkey, type)
) STRICT;

CREATE TABLE globals (
    key TEXT PRIMARY KEY NOT NULL,
    value ANY NOT NULL
) STRICT;


-- from 001_swarm_hash_history.sql
--
-- Every message hash a storage node has handed us, in the order that node handed it over, with the
-- moment the node will drop it.
--
-- This is where a retrieve's `last_hash` comes from -- the newest unexpired row for that node and
-- namespace -- rather than a stored cursor, so that deleting a hash from the swarm moves the cursor
-- by itself.  A stored cursor has to be corrected by whoever deletes, and the correction is
-- invisible from the delete: config pushes have destroyed their own cursor on every push since they
-- were written, which costs a full retrieve each time and was never noticed because it is only
-- expensive and never wrong.
--
-- Per node, because the cursor is.  Nodes do not agree on storage order, so a hash learned from one
-- node is not a safe cursor for another: at best it is unrecognised and the node replays its whole
-- retention window, at worst the node holds it *after* something we never received, and advancing
-- there skips that message permanently.
--
-- Expiry rather than a row count is what bounds this.  A hash is a usable cursor for exactly as long
-- as the node still holds the message, so the server's own expiry is the honest limit; a count would
-- keep dead hashes and drop live ones at the same time.
--
-- Every hash from a retrieve goes in, including messages we store nothing for -- typing indicators,
-- payloads that do not parse, anything a namespace carries that this build ignores.  Recording only
-- what we kept would leave the cursor behind those, and we would fetch them again on every poll.
--
-- Deliberately no foreign key to the client's `messages`: this is Core's, and a bare Core has no
-- such table.  It would also be the wrong fact -- a row here says a *node* still holds the message,
-- which has nothing to do with whether we kept our copy of it.
--
-- The nodes are their own table because the alternative repeats a 32-byte key in every row and
-- again in every index entry, to say something there are only a handful of distinct answers to.
--
-- Nothing prunes nodes by swarm membership, deliberately.  A node that has left is dead weight, but
-- deciding that requires trusting a swarm list to be complete, and a momentarily narrow one would
-- delete cursors that are still good -- costing a full retrieve from every node it omitted, which is
-- the exact thing this table exists to avoid.  Expiry clears their rows soon enough anyway.
CREATE TABLE swarm_nodes (
    id INTEGER PRIMARY KEY,
    pubkey BLOB NOT NULL UNIQUE CHECK(length(pubkey) = 32)
) STRICT;

CREATE TABLE swarm_hashes (
    id INTEGER PRIMARY KEY,
    namespace INTEGER NOT NULL,
    node INTEGER NOT NULL REFERENCES swarm_nodes(id) ON DELETE CASCADE,
    hash TEXT NOT NULL,
    expiry INTEGER,
    UNIQUE(namespace, node, hash)
) STRICT;

CREATE INDEX swarm_hashes_cursor ON swarm_hashes(namespace, node, id DESC);

-- Cache of remote account public keys (X25519 + ML-KEM-768) used for PFS+PQ message encryption.
-- Keys are considered fresh for PFS_KEY_FRESH_DURATION (24h) and expire after
-- PFS_KEY_EXPIRY_DURATION (48h); stale entries (24-48h old) are still usable as a fallback.
--
-- nak_at is set whenever a successful fetch returns no valid keys, and is never cleared.  It
-- suppresses re-fetching for PFS_KEY_NAK_DURATION (1h) when no valid keys exist.  When valid
-- keys are present nak_at may coexist with them (the keys are still usable as a fallback).
-- In SQLite, CHECK constraints with a NULL argument evaluate to NULL (not FALSE), so the length
-- checks do not reject NULL pubkeys.
CREATE TABLE pfs_key_cache (
    session_id BLOB NOT NULL PRIMARY KEY CHECK(length(session_id) = 33),
    fetched_at INTEGER,           -- unix timestamp (seconds) of last fetch with valid keys; NULL if none
    nak_at INTEGER,               -- unix timestamp of last fetch returning no keys; NULL if none
    pubkey_x25519 BLOB CHECK(length(pubkey_x25519) = 32),
    pubkey_mlkem768 BLOB CHECK(length(pubkey_mlkem768) = 1184)
) STRICT;

CREATE TABLE pro_revocations (
    revocation_tag BLOB PRIMARY KEY NOT NULL,
    effective_ts INTEGER NOT NULL,  -- unix seconds; a matching proof is revoked once the clock reaches this
    seen_at INTEGER NOT NULL        -- unix seconds when last seen in a fetched list (for retain_for aging)
) STRICT
