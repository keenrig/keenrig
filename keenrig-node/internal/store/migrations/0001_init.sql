CREATE TABLE apps (
    id          TEXT PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    desired     TEXT NOT NULL,
    desired_rev INTEGER NOT NULL DEFAULT 1,
    applied_rev INTEGER NOT NULL DEFAULT 0,
    status      TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    action     TEXT NOT NULL,
    actor      TEXT NOT NULL DEFAULT '',
    subject    TEXT NOT NULL DEFAULT '',
    data       TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE jobs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,
    args       TEXT,
    state      TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'done', 'failed')),
    attempt    INTEGER NOT NULL DEFAULT 0,
    not_before TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_jobs_state ON jobs (state, not_before);
CREATE INDEX idx_events_created ON events (created_at);
