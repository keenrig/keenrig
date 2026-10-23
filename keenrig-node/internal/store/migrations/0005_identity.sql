-- Migration 0005 — identity (T10). Vẫn EXPAND–CONTRACT: chỉ THÊM bảng mới.

-- users — chủ instance và (sau này) người dùng được mời.
--
-- password_hash lưu chuỗi argon2id ĐÃ MANG THAM SỐ (memory/time/parallelism/
-- salt), không phải hash trần. Tham số nằm cạnh hash là điều kiện để nâng chi
-- phí băm sau này mà vẫn xác thực được mật khẩu cũ — tách ra một cột cấu hình
-- toàn cục thì mọi hash cũ thành không đọc được ngay lần đổi đầu tiên.
--
-- totp_secret ở đây là KHOÁ TRA CỨU vào bảng secrets, không phải secret. Secret
-- TOTP đủ để sinh mã hợp lệ, nên nó phải nằm sau master.key như mọi secret khác.
CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    scopes        TEXT NOT NULL DEFAULT '',
    totp_ref      TEXT,
    totp_enabled  INTEGER NOT NULL DEFAULT 0 CHECK (totp_enabled IN (0, 1)),
    disabled      INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

-- Tên đăng nhập không phân biệt hoa thường: người dùng gõ "Alice" hôm nay và
-- "alice" ngày mai vẫn phải là một người, và hai tài khoản chỉ khác hoa
-- thường là một cái bẫy giả mạo.
CREATE UNIQUE INDEX idx_users_username ON users (lower(username));

-- sessions — token opaque, lưu HASH chứ không lưu token.
--
-- Vì sao hash: bảng này bị đọc bởi mọi lần xác thực và đi vào mọi bản backup.
-- Lưu token trần nghĩa là ai đọc được một bản sao DB (hoặc một bản backup cũ)
-- là mạo danh được mọi phiên đang mở. Hash thì lộ DB chỉ mất danh sách phiên.
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    user_agent TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_sessions_user ON sessions (user_id);
CREATE INDEX idx_sessions_expiry ON sessions (expires_at);

-- login_attempts — rate-limit + lockout (ID-03).
--
-- Ở TRONG DB chứ không phải trong bộ nhớ: bộ nhớ mất sau mỗi lần restart, và
-- kẻ tấn công chỉ cần làm box restart (hoặc đợi một lần OTA) để xoá sạch lịch
-- sử thử sai. Khoá theo (scope_key) = username hoặc IP.
CREATE TABLE login_attempts (
    scope_key   TEXT PRIMARY KEY,
    failures    INTEGER NOT NULL DEFAULT 0,
    first_fail  TEXT NOT NULL,
    last_fail   TEXT NOT NULL,
    locked_until TEXT
);
