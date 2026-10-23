CREATE TABLE secrets (
    ref        TEXT PRIMARY KEY,
    ciphertext BLOB NOT NULL,
    created_at TEXT NOT NULL
);

ALTER TABLE jobs ADD COLUMN result TEXT;
ALTER TABLE jobs ADD COLUMN last_error TEXT NOT NULL DEFAULT '';
