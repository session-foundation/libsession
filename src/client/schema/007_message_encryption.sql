-- How each message was encrypted; see the column's comment in full_schema.sql.  NULL for every
-- message from before this was recorded, which nothing can now recover.
ALTER TABLE messages ADD COLUMN encryption INTEGER;
