-- AUTOINCREMENT can only be had by recreating the table.
CREATE TABLE device_link_requests_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    device INTEGER UNIQUE NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    received_at INTEGER NOT NULL,
    sas_seed BLOB NOT NULL CHECK(length(sas_seed) == 16)
) STRICT;

INSERT INTO device_link_requests_new (id, device, received_at, sas_seed)
    SELECT id, device, received_at, sas_seed FROM device_link_requests;

DROP TABLE device_link_requests;

ALTER TABLE device_link_requests_new RENAME TO device_link_requests;
