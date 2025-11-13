-- root user (at serial_id = 0)
INSERT INTO "users" 
    (serial_id, user_id, user_type_serial_id, name, email, ctime, mtime) 
VALUES 
    (0, 'root', (SELECT ut.serial_id FROM user_type ut WHERE ut.typ = 'Sys'), 'root', 'root@example.com', (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')));

-- --
-- Insert dummy row with serial_id 999 to make AUTOINCREMENT start at 1000
INSERT INTO "users" (serial_id, user_id, email, name, user_type_serial_id)
VALUES (999, 'dummy_user_999', 'dummy999@example.com', 'Dummy User', 1);

-- Delete the dummy row
DELETE FROM "users" WHERE serial_id = 999;

-- OR --
 
-- -- After creating the users table:
-- This directly sets the sequence counter to 999, so the next insert will use 1000. However, this only works if at least one row has been inserted into the table first (to create the entry in sqlite_sequence), so the first approach is more reliable.
-- INSERT INTO sqlite_sequence (name, seq) VALUES ('users', 999);
-- --

