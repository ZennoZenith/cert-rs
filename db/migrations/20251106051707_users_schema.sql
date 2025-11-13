-- User
CREATE TABLE "user_type" (
  serial_id INTEGER PRIMARY KEY AUTOINCREMENT,
  typ TEXT NOT NULL UNIQUE,
  -- timestamps
  ctime TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  mtime TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

INSERT INTO "user_type" 
    (serial_id, typ)
VALUES 
    (1, 'Sys'),
    (2, 'User'),
    (3, 'UnVarifiedUser');

CREATE TABLE "users" (
  serial_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  user_type_serial_id INTEGER NOT NULL DEFAULT 3, -- 3: UnVarifiedUser
  -- timestamps
  ctime TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  mtime TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  
  FOREIGN KEY(user_type_serial_id)
    REFERENCES user_type (serial_id)
    ON UPDATE CASCADE
    ON DELETE RESTRICT
) STRICT;

CREATE TABLE "password_auth" (
  user_serial_id INTEGER PRIMARY KEY,
  -- auth
  pwd TEXT NOT NULL,
  pwd_salt BLOB NOT NULL,
  token_salt BLOB NOT NULL DEFAULT (randomblob(16)),
  -- timestamps
  ctime TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  mtime TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  
  FOREIGN KEY(user_serial_id) 
    REFERENCES users (serial_id)
    ON UPDATE CASCADE
    ON DELETE RESTRICT
) STRICT;
