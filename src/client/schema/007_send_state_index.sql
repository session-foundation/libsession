CREATE INDEX messages_send_state ON messages(send_state) WHERE send_state IS NOT NULL;
CREATE INDEX messages_sync_send_state ON messages(sync_send_state)
    WHERE sync_send_state IS NOT NULL;
