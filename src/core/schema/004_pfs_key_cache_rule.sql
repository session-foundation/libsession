-- The contact key cache, kept by its own rule now: when a key was last confirmed current and when
-- the next lookup is due, rather than ages measured from a fetch.  A cache, so nothing is carried
-- over: what it held is looked up again the next time it is needed.
DROP TABLE pfs_key_cache;

CREATE TABLE pfs_key_cache (
    session_id BLOB NOT NULL PRIMARY KEY CHECK(length(session_id) = 33),
    checked_at INTEGER NOT NULL,
    confirmed_at INTEGER,
    cache_expiry INTEGER NOT NULL,
    pubkey_x25519 BLOB CHECK(length(pubkey_x25519) = 32),
    pubkey_mlkem768 BLOB CHECK(length(pubkey_mlkem768) = 1184),
    CHECK((pubkey_x25519 IS NULL) = (pubkey_mlkem768 IS NULL)),
    CHECK((pubkey_x25519 IS NULL) = (confirmed_at IS NULL))
) STRICT;
