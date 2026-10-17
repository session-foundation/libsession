-- The Client schema with every migration in this directory applied.  A database with none of
-- them applied is built from this in one step; the migrations are then recorded without being
-- run.  Keep this in step with the migrations: test_client.cpp compares the two.

-- Every account we have seen, whether or not it is a contact: a message sender needs a row, so
-- this is "accounts we know of".  Being a contact is a row in `contacts`, not a property here.
--
-- The profile fields are what an account says about itself, learned either from the LokiProfile on
-- an incoming message or from the Contacts config.  `profile_updated` decides between them: it is
-- the account's *own* stamp of when it last changed its profile, not ours of when we saw it, so a
-- message arriving out of order cannot replace a newer profile with an older one.  Out of order is
-- the normal case rather than the exception, since a profile is observed from group messages as
-- readily as from a DM.  A message carrying no stamp counts as 0, so it applies only when we have
-- never had one.
--
-- The same stamp is what keeps this from churning: every message from someone repeats the value
-- they last set, so the common case compares equal, changes nothing, and dirties no config.
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    -- 33 bytes.  The prefix says which kind of identity it is: 0x05 for an account, 0x15 or 0x25
    -- for a community-blinded one, which carries a profile of its own and so gets its own row.
    session_id BLOB NOT NULL UNIQUE,
    name TEXT,                          -- NULL when no name is known; never an empty string
    -- Set together, or both NULL: a URL without its key cannot be decrypted, so either one missing
    -- is no picture at all.
    profile_pic_url TEXT,
    profile_pic_key BLOB,               -- 32 bytes
    profile_updated INTEGER NOT NULL DEFAULT 0,  -- unix seconds
    -- Session Pro.  `pro_flags` is what the profile claims -- a badge, an animated avatar -- and
    -- the proof is what lets the claim be checked.  A NULL tag means we have never seen a proof,
    -- which is not the same as holding one that has expired.
    pro_flags INTEGER NOT NULL DEFAULT 0,
    -- Set together or both NULL, like the picture above: an expiry with no tag beside it cannot be
    -- checked against the revocation list, so neither half says anything on its own.
    pro_revocation_tag BLOB,            -- 32 bytes
    pro_expiry INTEGER                  -- unix seconds
) STRICT;

-- One row per entry in the Contacts config.  Existence here *is* being a contact, so there is no
-- flag that could disagree with itself, and a contact removed on another device becomes a row that
-- goes away -- while the `accounts` row stays, because we have still seen that person.
--
-- Only what needs a relationship to mean anything lives here.  A name and a picture belong to the
-- account, since we learn those for people who are not contacts at all.
CREATE TABLE contacts (
    account INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    nickname TEXT,                      -- our own name for them, synced to our other devices
    -- Approval in each direction: whether we have accepted messages from this account, and whether
    -- it has accepted ours.  This is what separates a conversation from a message request.
    approved INTEGER NOT NULL DEFAULT 0,
    approved_me INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE groups (
    id INTEGER PRIMARY KEY,
    group_id BLOB NOT NULL UNIQUE       -- 33 bytes, 0x03-prefixed
) STRICT;

CREATE TABLE communities (
    id INTEGER PRIMARY KEY,
    base_url TEXT NOT NULL,             -- lowercased, no trailing slash
    room TEXT NOT NULL,                 -- lowercased
    UNIQUE (base_url, room)
) STRICT;

CREATE TABLE conversations (
    id INTEGER PRIMARY KEY,
    -- What the conversation is with.  Exactly one of these is set, and which one it is *is* the
    -- conversation's kind -- there is no separate type column that could disagree with it.  Each
    -- is UNIQUE so a given peer, group or room has at most one conversation; SQLite treats NULLs
    -- as distinct, so the unused columns do not collide across rows.
    -- ("closed_group" rather than "group" because the latter is a SQL keyword.)
    dm INTEGER UNIQUE REFERENCES accounts(id),
    closed_group INTEGER UNIQUE REFERENCES groups(id),
    community INTEGER UNIQUE REFERENCES communities(id),
    -- Time units differ by column here, deliberately and in step with what the configs carry: a
    -- value that gets compared against a message timestamp is in milliseconds, and everything else
    -- is unix seconds.  Nobody needs the sub-second moment a conversation was created.
    created INTEGER NOT NULL,           -- unix seconds
    last_activity INTEGER NOT NULL,     -- ms since epoch; conversation list ordering
    -- Read watermark: incoming messages with a strictly greater timestamp are unread.  A timestamp
    -- rather than a per-message flag because that is what ConvoInfoVolatile syncs.
    --
    -- Milliseconds, for the reason above: the other side of the comparison is `messages.timestamp`.
    -- At second resolution, reading a message stamped mid-second would force a choice between
    -- leaving that message unread and marking everything else in the same second read.
    last_read INTEGER NOT NULL DEFAULT 0,
    -- Cached rather than counted per query: a conversation list is redrawn far more often than its
    -- messages change.  `count` is maintained by the triggers below; `unread_count` is maintained
    -- by the application, for the reason given there.
    count INTEGER NOT NULL DEFAULT 0,
    unread_count INTEGER NOT NULL DEFAULT 0,
    -- Pinning, mirroring the value the Contacts and UserGroups configs sync: 0 is unpinned, a
    -- positive value is pinned with higher values sorting first, and a negative value is hidden.
    -- Kept numerically identical to the config so that reconciling one into the other is a copy
    -- rather than a translation.
    priority INTEGER NOT NULL DEFAULT 0,
    -- The settings below are carried per-kind by the configs -- `contact_info` for a DM,
    -- `base_group_info` for a group or community -- but they mean the same thing in each, so they
    -- are one set of columns here rather than three.
    --
    -- Set by the user to make a conversation unread again after reading it.  Independent of
    -- unread_count, which counts messages: this survives having read all of them.
    marked_unread INTEGER NOT NULL DEFAULT 0,
    -- 0 default, 1 all, 2 disabled, 3 mentions only.  Mentions-only is a group notion; a DM
    -- carrying it reads as `all`.
    notifications INTEGER NOT NULL DEFAULT 0,
    mute_until INTEGER NOT NULL DEFAULT 0,  -- unix seconds; 0 is not muted
    -- Disappearing messages: 0 none, 1 after send, 2 after read.  The timer is meaningless when the
    -- mode is none, and is a duration rather than a moment, so seconds either way.
    exp_mode INTEGER NOT NULL DEFAULT 0,
    exp_timer INTEGER NOT NULL DEFAULT 0,   -- seconds
    -- What to fetch without being asked, for this conversation: 0 nothing, 1 images, 2 everything.
    --
    -- NULL is the fourth state and the reason this is nullable: nobody has been asked yet.  Session
    -- asks within a conversation the first time and remembers the answer, which a client can only
    -- do if "never asked" is distinguishable from "asked, said no".
    --
    -- Device-local, deliberately, and so absent from every config: whether to spend this machine's
    -- bandwidth and disk is a property of the machine.  Auto-downloading everything on a desktop
    -- and nothing on a phone is the case this exists for, and syncing it would make that
    -- impossible.  Nothing in the reconcile reads or writes it.
    auto_download INTEGER,
    CHECK ((dm IS NOT NULL) + (closed_group IS NOT NULL) + (community IS NOT NULL) = 1)
) STRICT;

CREATE INDEX conversations_order ON conversations(priority DESC, last_activity DESC);

CREATE TABLE messages (
    -- AUTOINCREMENT so that no id is ever handed out twice.  Without it, deleting the newest row
    -- frees its id for the next insert, and the id is held well beyond any one transaction: by the
    -- application, which acts on messages by id, and by our own sends, uploads and transfers, which
    -- report back against it.  Anything still holding the old id would then act on the new message.
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    -- The sender's Content.msgId: 8 random bytes separating this message from another they sent in
    -- the same millisecond.  Every copy of a message carries the same value -- it is set before the
    -- copy for the recipient and the copy for our own swarm diverge -- which is what makes it the
    -- one identifier both parties agree on.
    --
    -- Only ever meaningful together with `timestamp`; it is far too small to identify a message on
    -- its own.  See the field's comment in SessionProtos.proto.
    --
    -- NULL for a message whose sender predates the field, which cannot then be told apart from
    -- another they sent in the same millisecond.
    --
    -- An opaque 64-bit pattern rather than a number: SQLite integers are signed, so a value above
    -- INT64_MAX is stored negative.  Compared for equality and nothing else.
    msgid INTEGER,
    -- Swarm-assigned hash; NULL for an outgoing message not yet stored on the swarm.  SQLite
    -- treats NULLs as distinct in a unique index, so those never collide with each other.
    swarm_hash TEXT UNIQUE,
    sender INTEGER NOT NULL REFERENCES accounts(id),
    outgoing INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,         -- ms since epoch; the Content sigTimestamp
    body TEXT NOT NULL,
    -- Delivery state of the copy sent to the recipient's swarm, for outgoing messages only:
    --   0 = queued locally, not yet dispatched
    --   1 = handed to the swarm, awaiting confirmation
    --   2 = accepted by a swarm node
    --   3 = terminal failure
    --   4 = in flight when the process exited, so the outcome is unknown
    --
    -- ...and the same for the copy deposited in our own swarm, which is how our other devices see
    -- an outgoing message.  The two are independent sends, retried separately, so a message can
    -- have reached its recipient while still owing our other devices a copy.
    --
    -- NULL in either means there is no such send: both are NULL on an incoming message, and
    -- sync_send_state is NULL for a note to self, where the recipient's swarm is our own and a
    -- second store would be the same store twice.
    send_state INTEGER,
    sync_send_state INTEGER,
    -- Set once the message's content has been removed but the row has to stay:
    --   1 = deleted here only
    --   2 = deleted everywhere, either because we asked for that or because the sender did
    --
    -- A row rather than a DELETE because `swarm_hash` is what a redelivery dedupes against, and a
    -- message deleted only here is still on the swarm to be delivered again.  Removing the row
    -- would let it come back looking new -- which is not hypothetical: a storage server stops
    -- honouring a `last_hash` once it has expired, and the poll that follows returns the whole
    -- retention window.
    --
    -- Which of the two it is has to survive, not just that it happened: deleting for everyone is
    -- still offerable on a message already deleted here, and the two are different things to draw.
    -- The direction that completes the picture is `outgoing`, so there is no column for it.
    deleted INTEGER,

    -- Whether this message is *shown* as a gallery rather than as a list of attachments.
    --
    -- A decision, which is why it is stored: it is made when the message is processed -- on if the
    -- conversation was auto-downloading then -- and the conversation's setting may have changed
    -- since, so it cannot be recomputed later and mean the same thing.  A client may set or clear
    -- it afterwards.
    --
    -- Whether a message *can* be shown that way is a separate question, derived and not stored:
    -- today it is "has attachments, and every one of them is an image", but that is our rule to
    -- change -- to particular formats, or a size ceiling -- and a stored answer would be a stale
    -- one after any such change.  So a message whose stored decision no longer agrees with the
    -- current rule simply has the decision dropped, rather than being honoured or migrated.
    gallery INTEGER NOT NULL DEFAULT 0,

    -- What this message is a reply to, as the sender addressed it: never a local message id.
    --
    -- Whether we have the replied-to message changes in *both* directions after this row is
    -- written -- a reply can arrive before the message it answers, and the target can later be
    -- deleted or pruned -- so a resolved id would be a second record needing a fix-up pass to stay
    -- true.  Resolution is done on read instead, through `messages_wire_key`, which exists for
    -- exactly this.
    --
    -- `reply_author` is an accounts FK rather than a session id so that resolution is a join.
    --
    -- `reply_msgid` is the sender's `Content.msgId` for the target, and NULL from senders predating
    -- that field.  Match on timestamp *and* msgid where both are present; with it absent, timestamp
    -- and author alone are ambiguous exactly when one sender stamped several messages in the same
    -- millisecond, which is the case msgid exists to fix.  Nothing can be done about that here, so
    -- the read side takes the lowest matching id: arbitrary, but stable across reads.
    --
    -- What the wire also carries and we deliberately do not store: the sender's own snippet of the
    -- replied-to text and its attachments.  Current clients do not populate them, and a sender can
    -- forge them -- rendering one would put chosen words on screen attributed to someone else.  We
    -- render from our own copy of the target or from nothing.  message_raw_content keeps the whole
    -- protobuf, so this is recoverable if that is ever revisited.
    reply_author INTEGER REFERENCES accounts(id),
    reply_timestamp INTEGER,
    reply_msgid INTEGER
) STRICT;

-- Delivery is at-least-once, so a redelivered message must not duplicate.  This also catches what
-- the swarm hash cannot: our own message arriving back from our swarm, which carries the same msgid
-- as the copy we sent.  Both columns are needed -- see the protobuf comment for why msgid is not an
-- identifier on its own.
CREATE UNIQUE INDEX messages_msgid ON messages(conversation, timestamp, msgid);

CREATE INDEX messages_history ON messages(conversation, timestamp DESC, id DESC);
CREATE INDEX messages_unread ON messages(conversation, timestamp) WHERE outgoing = 0;

-- Quotes and reactions from clients that set no msgId address their target by author and timestamp
-- alone.  Needed for as long as such clients exist.
CREATE INDEX messages_wire_key ON messages(conversation, sender, timestamp);

-- The other direction of the same question: "which messages reply to this one".  Asked whenever a
-- message changes, because a reply carries a copy of what it answers and so goes stale with it.
--
-- Partial because most messages are not replies, which keeps it a fraction of the size of the row
-- count -- and because a partial index is only consulted for queries whose WHERE matches it, which
-- is precisely the lookup this serves.
CREATE INDEX messages_reply_target ON messages(conversation, reply_author, reply_timestamp)
    WHERE reply_timestamp IS NOT NULL;

-- Every start resets the sends the last run left in flight (Client::_init), filtering on these two
-- columns; without an index each of those statements reads the whole table, so starting up slows
-- with history.  Partial because both are NULL on every incoming message -- usually most of them --
-- and nothing asks for those, which leaves the index the size of the outgoing messages alone.
CREATE INDEX messages_send_state ON messages(send_state) WHERE send_state IS NOT NULL;
CREATE INDEX messages_sync_send_state ON messages(sync_send_state)
    WHERE sync_send_state IS NOT NULL;

-- `count` is a structural fact about the messages table, so triggers can own it outright: there is
-- no judgement involved in how many rows a conversation has.
--
-- `unread_count` deliberately is *not* maintained here.  What counts as unread is policy, not
-- structure -- mutes, message requests, tombstones, a message arriving with a timestamp older than
-- the read watermark -- and that policy will grow.  Encoding it in triggers would scatter it
-- across SQL that is awkward to test and invisible from the code that decides it, so the
-- application maintains unread_count wherever it changes what has been read.
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

-- An index over the files in the attachment cache directory, so that "how much disk is this using"
-- and "what has gone longest without being wanted" are queries rather than a directory walk on
-- every download.
--
-- Deliberately only an index: the disk is what is actually true.  A crash between writing a file
-- and recording it, or between unlinking one and forgetting it, leaves this describing a directory
-- that no longer matches, and the sweep reconciles in both directions: a row whose file is gone is
-- dropped, and the messages drawing it are told; a file with no row is deleted, since nothing can
-- look it up.
--
-- `size` is bytes on disk, encrypted and padded, because that is what the cache limit is a limit
-- on.  `last_used` is touched on a cache hit as well as on write, which is what makes eviction
-- least-recently-*used* rather than oldest-first: something opened weekly should not lose to
-- something downloaded once and never looked at again.
--
-- Display pictures are not in here at all.  They are never evicted -- a contact you have not spoken
-- to in years should not lose the last picture you had of them -- and are freed only when superseded,
-- which is a question about what still references them rather than about size or age.
CREATE TABLE attachment_cache (
    -- Surrogate, so that an attachment row referencing this stores an integer rather than a second
    -- copy of the name -- and so that the name is free to change shape later without the references
    -- to it meaning anything different.
    --
    -- AUTOINCREMENT because a cache hit holds this across a disk read, to mark the entry used once
    -- the read is done.  Were an eviction and a new entry to free and retake the id meanwhile, that
    -- mark would land on the wrong file.
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Keyed (`cache::name_for`) so that someone reading the cache directory cannot tell which
    -- files this account has fetched.
    name TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    last_used INTEGER NOT NULL      -- ms since epoch
) STRICT;

CREATE INDEX attachment_cache_lru ON attachment_cache(last_used);

-- The full decrypted Content protobuf, kept out of the messages table so that the history scan --
-- the hot query -- does not drag it through overflow pages.  Retained so fields this schema does
-- not yet model (attachments, quotes, reactions) can be recovered without re-fetching the swarm.
CREATE TABLE message_raw_content (
    message INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    content BLOB NOT NULL
) STRICT;

-- Files attached to a message, in either direction.
--
-- The two directions are the same set of columns and differ only in which end is known first, so
-- they share the table; `messages.outgoing` says which reading applies.  `path` is the local copy
-- and `url` the remote one, and exactly one of them exists from the start:
--
--   outgoing -- `path` is the file we uploaded, and is required; `url IS NULL` means not uploaded
--   incoming -- `url` is where the file is, and is required; `path IS NULL` means not saved
--
-- Sending with attachments is two stages: each file is encrypted and uploaded, and only then can
-- the message be built, since it has to name where those files ended up.  A failure between the two
-- leaves a message that cannot be finished from the message alone -- what it needs is the local
-- files and whatever their uploads already achieved, neither of which the protobuf carries.
-- Retrying without that would mean re-uploading files that already arrived.
--
-- There is no state column: for an outgoing attachment `url IS NULL` *is* "not uploaded yet".
-- Retrying is then "upload every row for this message that has no url, then build the message and
-- send it", which cannot disagree with itself the way a separate state could, and is safe to run
-- twice.
--
-- An outgoing row's `path` outlives the upload deliberately.  It is what makes an attachment we
-- sent displayable without fetching our own upload back, and it is the only record of it: what
-- persists of a sent attachment otherwise is the pointer inside message_raw_content.
CREATE TABLE message_attachments (
    message INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,

    -- Position within the message's attachment list, which is the order they appear in the
    -- protobuf and how a progress report names one of them.
    idx INTEGER NOT NULL,

    -- Where the file is, or came from: for an outgoing attachment the one we uploaded, for an
    -- incoming one where the user asked us to save the download (NULL until they do).
    --
    -- Informational rather than owning -- closer to a symlink than a handle.  The file at the far
    -- end belongs to the user in both directions: they chose it to attach, or they chose where to
    -- put it.  So it may be moved or deleted behind our back (only fatal while this row still needs
    -- uploading), and nothing here ever unlinks it.
    --
    -- A cache of our own -- attachments kept encrypted so they outlive the file server -- would be a
    -- third thing, at a path we picked, and wants its own column: that is what a
    -- delete-attachments-before instruction is entitled to remove, and sharing this column would
    -- leave it unable to tell our copy from the user's.
    --
    -- Such a cache cannot be freed by deleting files alongside the rows that name them, because the
    -- rows go by cascade when a conversation is deleted and no code of ours runs.  It wants the same
    -- treatment as everything else here: compare and converge.  List the cached paths still
    -- referenced, list the cache directory, unlink the difference.  That survives a cascade, and
    -- also collects what a crash mid-download left behind -- which collecting paths before a delete
    -- never would.  It needs a directory we own outright, since "anything not in the list" is only
    -- safe there, and it must not eat a download in flight: either the row exists before the
    -- transfer starts, or the sweep skips the in-progress suffix.
    path TEXT,

    -- Descriptive fields, carried straight through the protobuf pointer in both directions.
    -- content_type is what a recipient displays by; the rest are optional and simply omitted when
    -- null.  On an incoming attachment these are the sender's claims and nothing more.
    content_type TEXT,
    filename TEXT,
    flags INTEGER NOT NULL DEFAULT 0,
    width INTEGER,
    height INTEGER,

    -- Where the file is on the file server, the key it is encrypted with, and how long the file
    -- itself is.
    --
    -- The last of those is the smallest of three different sizes and none of the other two: what
    -- the server stores is bigger (IV, MAC or stream framing), and what decryption yields is also
    -- bigger, since Session pads to hide the true length on top of whatever the cipher pads.  This
    -- is what is left after both, and `legacy_decrypt` resizes down to it -- which is why it cannot
    -- be either of the others and still do that job.
    --
    -- A claim by the sender, believed by nothing: it is checked against what actually arrives, and
    -- decryption throws if it exceeds that.
    --
    -- Set together when an upload succeeds, or read together out of an arriving pointer.
    url TEXT,
    key BLOB,
    size INTEGER,

    -- Legacy attachments authenticate with a separate SHA-256 digest over the ciphertext, and
    -- carry a 64-byte `key` (AES key then HMAC key) rather than the 32-byte stream key.  Null for
    -- anything encrypted with the stream scheme, which authenticates each chunk as it goes.
    digest BLOB,

    -- ms since epoch: when the *recipient* of this message last saved this attachment.  On an
    -- incoming attachment that is us, writing it to disk; on an outgoing one it is the other party,
    -- telling us they saved it.  One meaning in both directions -- "the recipient saved this, then".
    --
    -- Not a path: where a file went is the application's business, and one recorded here would be
    -- wrong as soon as it moved the file.  This answers the question an application actually has,
    -- which is whether offering "save" again is pointless.
    --
    -- NULL means "not known to have been saved", never "not saved": the outgoing case depends on
    -- the other end volunteering a DataExtractionNotification, which many clients do not.
    saved_at INTEGER,

    -- What the last attempt to fetch this file found, when what it found was that it could not be
    -- fetched: the file server does not hold it -- which is also how an expired upload answers --
    -- or the bytes arrived and failed to authenticate.
    --
    -- A cached answer rather than a fact about the url, which is what decides its lifetime.  An
    -- attachment url is a hash of the encrypted body and the encryption is deterministic, so the
    -- same file sent again by the same account lands at the *same* url.  That is the repair path:
    -- the recipient is told it could not be fetched, asks for it again, and the sender's re-upload
    -- puts those bytes back where they were.  A flag that never cleared would block precisely the
    -- action that fixes the problem.
    --
    -- Which rows a failure marks depends on what failed.  A file server status is its answer about
    -- the url, so it is set on every row naming that url, and cleared on all of them when a new row
    -- quoting it arrives -- the resend -- since showing one message's copy as gone and another's
    -- as fine would be showing the same file two ways.  Unreadable is about how this row says to
    -- read the bytes: key, digest and size are the sender's claims, and nothing ties them to the
    -- url, so it marks only rows making the same claim and a resend does not clear it.
    --
    -- Either is cleared on every row when the file is cached, by whatever route: all of them are
    -- then served it from disk, so none can say it cannot be had.
    --
    -- The value is *why*: 404, the file server's answer for an upload it does not hold, or -20002
    -- for bytes that arrived and could not be turned back into the file they claimed to be.  Only
    -- the first is worth telling the user to ask for a resend about.  These numbers are
    -- `Client::Unavailable`'s, and on disk they cannot change.
    --
    -- NULL means only that nothing has proved otherwise.
    unavailable INTEGER,

    -- The local copy of this file, or NULL for no local copy -- which is also what eviction leaves
    -- behind, since ON DELETE SET NULL clears this as the cache row goes.  That is what makes "this
    -- row says cached" and "that file has an entry" impossible to disagree in the direction that
    -- matters: the only way to be marked is to reference a living row.
    --
    -- Stored rather than derived from `url`.  The cached file is *named* by a keyed hash of the
    -- url, so deriving it would make that hash load-bearing for everything already downloaded
    -- rather than only for what is being written -- which is why changing the naming in 005 could
    -- only be done by discarding the cache.
    --
    -- The other direction of disagreement -- a row naming a file something outside us deleted -- is
    -- still possible, and is what the reconcile sweep is for.
    cached INTEGER REFERENCES attachment_cache(id) ON DELETE SET NULL,

    -- A ThumbHash of the image: 25 bytes at most, which a recipient draws in the attachment's
    -- place until the file itself arrives.  Carried opaquely, like the descriptive fields near the
    -- top -- and declared down here rather than beside them because ADD COLUMN can only append,
    -- and this file has to describe the same column order a migrated database ends up with.
    thumbhash BLOB,

    -- 1 while an auto-download still owes this file.  Cleared once it is cached or found unavailable,
    -- so eviction never makes it owed again, or once the conversation's setting stops taking it.
    auto_pending INTEGER,

    PRIMARY KEY (message, idx)
) STRICT;

-- Which messages show a given file.  Every question the attachment cache asks of this table is
-- that one -- marking a file unfetchable, clearing it again on a resend, reporting a transfer
-- starting, finishing or being evicted -- and more than one message routinely quotes the same
-- file, because an attachment url is a hash of the encrypted body: the same file sent twice by the
-- same account lands at the same url.  Without this, each of those answers scans the whole table
-- to touch a handful of rows.
--
-- Partial because a row with no url has nothing to fetch and is never the subject of any of them:
-- an outgoing attachment before its upload finishes, which on a sending-heavy account is a large
-- share of the table.
CREATE INDEX message_attachments_url ON message_attachments(url) WHERE url IS NOT NULL;

-- Which messages show a file that is being evicted, which is the question a keyed hash cannot
-- answer: it does not run backwards, so without this the only route from a cached file to the
-- messages drawing it is to hash every url in the table.
--
-- Partial for the same reason as above: most rows are not cached at any given moment, and those
-- are never the subject of this question.
CREATE INDEX message_attachments_cached ON message_attachments(cached) WHERE cached IS NOT NULL;

-- What a restart queues again, and what a setting change checks: the few rows still owed.
CREATE INDEX message_attachments_auto_pending ON message_attachments(message)
    WHERE auto_pending IS NOT NULL;
