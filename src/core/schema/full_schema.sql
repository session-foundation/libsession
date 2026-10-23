-- Core's schema with every migration in src/core/schema/ applied.  A database with none of them
-- applied is built from this in one step and they are all recorded without running, so this file
-- -- not the migration chain -- is where the current schema is read.
--
-- Keep in step with the migrations: test_core_schema.cpp builds a database both ways and
-- compares them.

-- Table storing all the device group info
CREATE TABLE devices (
    id INTEGER PRIMARY KEY NOT NULL,
    unique_id BLOB UNIQUE NOT NULL CHECK(length(unique_id) == 16),

    -- Membership rank: 0 unregistered, 1 pending, 2 registered, 3 left, 4 kicked.  Ordered least to
    -- most authoritative because merging compares (state, seqno) as a row value -- see
    -- device::State.
    state INTEGER NOT NULL CHECK(state >= 0 AND state <= 4),
    -- For our own row, that of the record the swarm holds for us (0 for none yet), which the next
    -- record we publish counts on from: our row mirrors the swarm, and is never what we publish.
    seqno INTEGER NOT NULL DEFAULT 1,
    -- Nonzero while a state transition this device made (registered/removed) has yet to go out in
    -- a push of ours: a generation, bumped each time one is owed, so that a confirmed push clears
    -- it only if nothing was owed again while it was in flight.
    broadcast_needed INTEGER NOT NULL DEFAULT 0,
    timestamp INTEGER NOT NULL,
    kicked_timestamp INTEGER CHECK(kicked_timestamp > 0),  -- when the device was removed, or left
    -- 1 for a device this one removed, which is what has it replace at once an account key the
    -- removed device turns out to hold, where every other member waits a jittered while: only the
    -- remover knows it is one, so its zero delay collides with nobody's.
    removed_by_us INTEGER NOT NULL DEFAULT 0 CHECK(removed_by_us IN (0, 1)),
    device_type TEXT NOT NULL, -- typically a/i/d (Android/iOS/Desktop), but can be anything
    description TEXT NOT NULL, -- freeform device description
    version INTEGER NOT NULL, -- = 1000000*V + 1000*v + p for version "V.v.p"
    pubkey_mlkem768 BLOB NOT NULL CHECK(length(pubkey_mlkem768) == 1184),
    pubkey_x25519 BLOB NOT NULL CHECK(length(pubkey_x25519) == 32),

    -- Blake2b over the record as it was encoded, and the last term of the merge comparison: two
    -- records at the same state and seqno are the same record unless their contents differ, and
    -- without this the earlier arrival simply wins and two devices disagree forever.  Only a bug or
    -- a forgery produces that, so the ordering only has to be consistent, not meaningful.
    digest BLOB CHECK(digest IS NULL OR length(digest) == 8),

    -- The two tombstone states are the only ones that carry a timestamp, and are meaningless without
    -- one, so the two are tied together here rather than left to each call site to remember.
    CHECK((state >= 3) == (kicked_timestamp IS NOT NULL))
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
    -- What the `reqid` an application is given maps to, for as long as this run holds it.
    -- AUTOINCREMENT because rows are deleted, and without it the next request would take the id of
    -- the newest one gone, and with it anything still held against that id: the reqid an
    -- application knows the old request by, and whether that request has ended.
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    -- Not unique: a device that asks twice gets two rows.  This is the log of requests this device
    -- saw, not the set of requests outstanding, so a superseded or answered one stays readable.
    device INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    received_at INTEGER NOT NULL,  -- unix timestamp of when this request was stored locally
    -- When the swarm said it would drop the message.  Authoritative for the deadline shown to a
    -- user: a request published shortly before we polled has less time left than its full TTL, and
    -- counting from received_at would show a countdown that outlives the request itself.
    expires_at INTEGER NOT NULL,
    -- 0 pending, 1 accepted, 2 ignored, 3 superseded.  Expiry is deliberately not among them: it is
    -- `status = 0 AND expires_at <= now`, so there is no flag to fall out of step with the
    -- timestamp that decides it.
    status INTEGER NOT NULL DEFAULT 0 CHECK(status >= 0 AND status <= 3),
    sas_seed BLOB NOT NULL CHECK(length(sas_seed) == 16),  -- 16-byte Argon2id output for SAS display
    -- The swarm's hash for the message the request arrived in, which is what deleting it from the
    -- swarm names.
    hash TEXT NOT NULL,
    -- The device record the request asks to have admitted, bt-encoded as it was signed.  Kept here
    -- rather than read from `devices` because a device already in the group keeps the record it has
    -- there, keys and all, until a request replacing it is accepted.
    info BLOB NOT NULL,
    -- 1 if the device was already in the group when it asked, so accepting replaces its record.
    replaces INTEGER NOT NULL DEFAULT 0 CHECK(replaces IN (0, 1))
) STRICT;
CREATE INDEX device_link_requests_device ON device_link_requests(device);

-- Device group messages whose contents we have taken in, and which our own next push therefore
-- makes redundant.
--
-- A "G" is not one device's contribution but a complete snapshot of the whole group as its author
-- saw it, so obsolescence has nothing to do with who wrote it: once we have merged one, the message
-- we push next carries everything it said, and a device that never fetched it gets the same content
-- from ours.  Leaving them costs a copy per push per device for the full 30-day TTL, and leaves a
-- device that goes away permanently littering the namespace with snapshots nobody can clear.
--
-- Only messages we could decrypt are ever listed.  One we cannot read belongs to a group we are not
-- in, and our push carries none of it -- deleting that would destroy another group's state rather
-- than tidy up our own.
CREATE TABLE device_group_merged (
    hash TEXT PRIMARY KEY NOT NULL
) STRICT;

-- The device groups this device has seen messages from in the swarm, its own included: what a device
-- asking to join chooses among, and what tells a device that another group exists alongside its own.
-- One row per group, kept up to date from the newest of its messages seen.
--
-- Kept rather than worked out afresh at each fetch, because fetches are incremental: a message is
-- delivered once, by the fetch after it arrives, and a group whose devices are quiet would otherwise
-- vanish from view at the next restart.
CREATE TABLE device_groups (
    group_id BLOB PRIMARY KEY NOT NULL CHECK(length(group_id) == 8),
    -- The X25519 half of the group's account key, as its newest message published it: what a link
    -- request asking to join the group is encrypted to.
    link_x25519 BLOB NOT NULL CHECK(length(link_x25519) == 32),
    seen_at INTEGER NOT NULL,     -- signed time of the newest message seen, unix seconds
    -- The latest expiry among the messages seen, unix seconds.  The group is in the swarm until
    -- then, as far as fetching can tell: a deletion is not something a fetch reports.
    expires_at INTEGER NOT NULL
) STRICT;

-- The swarm hashes of the group messages seen, every group's: what dissolving a group deletes from
-- the swarm.  Kept until the swarm drops each message, after which there is nothing to delete.
CREATE TABLE device_group_messages (
    hash TEXT PRIMARY KEY NOT NULL,
    group_id BLOB NOT NULL CHECK(length(group_id) == 8),
    expires_at INTEGER NOT NULL  -- unix seconds
) STRICT;
CREATE INDEX device_group_messages_group ON device_group_messages(group_id);

-- The groups this device knows to be dissolved, by a tombstone it saw or one it published.  A
-- tombstone lives only as long as any message does, and this is what lets a device in a group that
-- sees a dissolved group in the swarm again dissolve it again.  Kept for good, whatever group the
-- device goes on to, except for a group it is itself admitted to: joining that is the user's
-- later choice.
CREATE TABLE device_dissolved_groups (
    group_id BLOB PRIMARY KEY NOT NULL CHECK(length(group_id) == 8),
    -- The signed time of the newest tombstone naming it, unix milliseconds: a message from the
    -- group written later than this is the group back, where an older one is only left over.
    dissolved_at INTEGER NOT NULL
) STRICT;

-- Pushes that outlive the state they were built from: a departure from a group this device has
-- left, and a dissolution of another group.  Each row is the complete upload, written in the same
-- transaction as the decision it announces, so that nothing the device forgets afterwards -- a
-- group it left above all -- is needed to send it, and a push that fails, or never got to go before
-- the device stopped, goes at the next fetch instead.  Deleted once the swarm confirms it, or unsent
-- once it is older than a group message lives, when what it would replace has expired anyway.
CREATE TABLE device_pending_pushes (
    -- AUTOINCREMENT because a push in flight names its row, and a row dropped meanwhile must not
    -- hand that id to a new one.
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    message BLOB,           -- the message to store, if any
    obsolete BLOB NOT NULL, -- bt-encoded list of the swarm hashes to delete with it
    created_at INTEGER NOT NULL
) STRICT;

-- The link requests this device has sent, so that a group message admitting it can be matched to
-- the request it accepted, possibly after its deadline here has passed.  Only the newest is one the
-- user can be shown, and so confirm; the SAS confirmed must be that very request's, since that is
-- what the accepting device showed, and an admission matching none of them is not ours to take,
-- since any holder of the account seed could have sent it.  The older ones are kept for as long as
-- an admission on them could still arrive, so that the next request is stamped later than any of
-- them and an admission on one can never be taken for the newest.
CREATE TABLE device_own_requests (
    id INTEGER PRIMARY KEY NOT NULL,
    group_id BLOB NOT NULL CHECK(length(group_id) == 8),
    -- With the X25519 key, what identifies the request in an admission: the record admitted is the
    -- one the request carried.  Unique because each request is stamped later than the one before.
    timestamp INTEGER UNIQUE NOT NULL,
    pubkey_x25519 BLOB NOT NULL CHECK(length(pubkey_x25519) == 32),
    sas_seed BLOB NOT NULL CHECK(length(sas_seed) == 16),
    expires_at INTEGER,  -- when the swarm drops it; NULL until the swarm confirms storing it
    -- A group message admitting us on this request, held until the user confirms the SAS through
    -- confirm_link, with the hash it arrived with: a fetch delivers a message only once.  Its time
    -- is the one signed inside it.
    admission BLOB,
    admission_hash TEXT,
    CHECK((admission IS NULL) == (admission_hash IS NULL))
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
    -- AUTOINCREMENT because a device group push names the rows it distributes, and confirming it
    -- marks them distributed.  Leaving a group deletes every key, so without it a key minted while
    -- that push was in flight would take a named id and be marked distributed by a message that
    -- never carried it.
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
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

-- The devices each account key has been delivered to, and so holds for good: a payload is
-- encrypted to exactly the registered records it carries, so every payload carrying a key -- one
-- this device merged, or pushed -- delivered it to each of them.  A key that reached a device no
-- longer in the group is one that device can still use.
CREATE TABLE device_account_key_recipients (
    key INTEGER NOT NULL REFERENCES device_account_keys(id) ON DELETE CASCADE,
    device BLOB NOT NULL CHECK(length(device) == 16),  -- the unique_id it was delivered to
    PRIMARY KEY(key, device)
) STRICT, WITHOUT ROWID;

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

-- What this device knows of a contact's account public keys (X25519 + ML-KEM-768), which PFS+PQ
-- messages to them are encrypted to; see the spec's "Account keys" for the rule this keeps.  Until
-- cache_expiry a send uses what the row says -- the keys, or none -- without looking again; past
-- it, the next send or prefetch looks up first, and the outcome sets the row.
--
-- All times are unix seconds.  A row is written by every completed lookup, so checked_at is always
-- set.  The keys and confirmed_at are present or absent together: confirmed_at is the last time a
-- lookup said this key is current, by finding it or by finding nothing while it was recent enough
-- still to be.  A keyless row within cache_expiry is a lookup that found nothing.
--
-- In SQLite, CHECK constraints with a NULL argument evaluate to NULL (not FALSE), so the length
-- checks do not reject NULL pubkeys.
CREATE TABLE pfs_key_cache (
    session_id BLOB NOT NULL PRIMARY KEY CHECK(length(session_id) = 33),
    checked_at INTEGER NOT NULL,     -- when the last lookup completed, whatever it found
    confirmed_at INTEGER,            -- when a lookup last said the keys below are current
    cache_expiry INTEGER NOT NULL,   -- when the next lookup is due
    pubkey_x25519 BLOB CHECK(length(pubkey_x25519) = 32),
    pubkey_mlkem768 BLOB CHECK(length(pubkey_mlkem768) = 1184),
    CHECK((pubkey_x25519 IS NULL) = (pubkey_mlkem768 IS NULL)),
    CHECK((pubkey_x25519 IS NULL) = (confirmed_at IS NULL))
) STRICT;

CREATE TABLE pro_revocations (
    revocation_tag BLOB PRIMARY KEY NOT NULL,
    effective_ts INTEGER NOT NULL,  -- unix seconds; a matching proof is revoked once the clock reaches this
    seen_at INTEGER NOT NULL        -- unix seconds when last seen in a fetched list (for retain_for aging)
) STRICT
