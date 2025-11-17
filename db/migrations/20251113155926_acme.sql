-- User
CREATE TABLE "acme_account" (
  serial_id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id TEXT NOT NULL UNIQUE,
  private_key_pem BLOB NOT NULL,
  public_key_pem BLOB NOT NULL,
  key_type TEXT NOT NULL,

  -- timestamps
  ctime TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  mtime TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

