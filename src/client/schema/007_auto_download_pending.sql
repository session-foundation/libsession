ALTER TABLE message_attachments ADD COLUMN auto_pending INTEGER;

CREATE INDEX message_attachments_auto_pending ON message_attachments(message)
    WHERE auto_pending IS NOT NULL;
