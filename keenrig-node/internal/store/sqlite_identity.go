package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// --- users --------------------------------------------------------------------

const userColumns = `id, username, password_hash, scopes, totp_ref, totp_enabled, disabled, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var (
		u                    User
		totpRef              sql.NullString
		totpEnabled, disable int
		createdAt, updatedAt string
		scopes               string
	)
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &scopes, &totpRef,
		&totpEnabled, &disable, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	if scopes != "" {
		u.Scopes = strings.Split(scopes, ",")
	}
	if totpRef.Valid {
		u.TOTPRef = totpRef.String
	}
	u.TOTPEnabled = totpEnabled == 1
	u.Disabled = disable == 1
	u.CreatedAt = parseTime(createdAt)
	u.UpdatedAt = parseTime(updatedAt)
	return &u, nil
}

func (s *SQLite) CreateUser(ctx context.Context, u *User) error {
	ts := now()
	var totpRef any
	if u.TOTPRef != "" {
		totpRef = u.TOTPRef
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (`+userColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, strings.Join(u.Scopes, ","), totpRef,
		boolToInt(u.TOTPEnabled), boolToInt(u.Disabled), ts, ts)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	u.CreatedAt = parseTime(ts)
	u.UpdatedAt = u.CreatedAt
	return nil
}

// GetUserByName tra theo tên KHÔNG phân biệt hoa thường — cùng quy tắc với
// UNIQUE index, nếu không thì tạo được "Vincent" trong khi đăng nhập "vincent"
// lại báo không tồn tại.
func (s *SQLite) GetUserByName(ctx context.Context, username string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE lower(username) = lower(?)`, username)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *SQLite) GetUser(ctx context.Context, id string) (*User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// OwnerUser trả tài khoản CHỦ instance: user còn hiệu lực, có scope `admin`,
// cũ nhất.
//
// "Cũ nhất" chứ không phải "một cái bất kỳ": phiên SSO của Console (`CON-13`)
// phải rơi vào cùng một tài khoản ở mọi lần bấm, nếu không thì nhật ký kiểm
// toán của instance ghi mỗi lần một chủ thể khác cho cùng một người bấm.
//
// Lọc scope bằng `,`||scopes||`,` LIKE `%,admin,%`: cột lưu chuỗi nối bằng dấu
// phẩy, và một phép LIKE '%admin%' trần sẽ khớp cả một scope tên `admin-read`
// mai này.
func (s *SQLite) OwnerUser(ctx context.Context) (*User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users
		 WHERE disabled = 0 AND (',' || scopes || ',') LIKE '%,admin,%'
		 ORDER BY created_at, id LIMIT 1`))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *SQLite) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *SQLite) UpdateUser(ctx context.Context, u *User) error {
	var totpRef any
	if u.TOTPRef != "" {
		totpRef = u.TOTPRef
	}
	ts := now()
	err := s.execAffectOne(ctx,
		`UPDATE users SET password_hash = ?, scopes = ?, totp_ref = ?, totp_enabled = ?,
		 disabled = ?, updated_at = ? WHERE id = ?`,
		u.PasswordHash, strings.Join(u.Scopes, ","), totpRef,
		boolToInt(u.TOTPEnabled), boolToInt(u.Disabled), ts, u.ID)
	if err == nil {
		u.UpdatedAt = parseTime(ts)
	}
	return err
}

// --- sessions -----------------------------------------------------------------

// CreateSession lưu HASH của token (caller đã băm). Store không bao giờ thấy
// token trần — nhờ vậy một lần log sai chỗ ở tầng store cũng không lộ phiên.
func (s *SQLite) CreateSession(ctx context.Context, sess *Session) error {
	ts := now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, expires_at, created_at, last_seen, user_agent, ip)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sess.TokenHash, sess.UserID, formatSecondCeil(sess.ExpiresAt), ts, ts, sess.UserAgent, sess.IP)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	if isForeignKeyViolation(err) {
		return ErrNotFound
	}
	if err == nil {
		sess.CreatedAt = parseTime(ts)
		sess.LastSeen = sess.CreatedAt
	}
	return err
}

// GetSession trả phiên CÒN HẠN; hết hạn coi như không tồn tại.
//
// Lọc hạn trong SQL chứ không ở Go: quên một chỗ so sánh ở tầng trên là để lọt
// một phiên đã hết hạn, và đó là kiểu lỗi không ai nhìn ra khi đọc code.
func (s *SQLite) GetSession(ctx context.Context, tokenHash string) (*Session, error) {
	var (
		sess                           Session
		expiresAt, createdAt, lastSeen string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT token_hash, user_id, expires_at, created_at, last_seen, user_agent, ip
		 FROM sessions WHERE token_hash = ? AND expires_at > ?`, tokenHash, nowSecond()).
		Scan(&sess.TokenHash, &sess.UserID, &expiresAt, &createdAt, &lastSeen, &sess.UserAgent, &sess.IP)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sess.ExpiresAt = parseTimeRFC3339(expiresAt)
	sess.CreatedAt = parseTime(createdAt)
	sess.LastSeen = parseTime(lastSeen)
	return &sess, nil
}

// DeleteSession — logout. Xoá THẬT khỏi bảng (ID-05): đánh dấu "đã logout" mà
// giữ row lại là mời gọi một đường đọc nào đó quên kiểm cờ.
func (s *SQLite) DeleteSession(ctx context.Context, tokenHash string) error {
	return s.execAffectOne(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
}

func (s *SQLite) DeleteUserSessions(ctx context.Context, userID string) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// PurgeExpiredSessions dọn phiên hết hạn. Chạy định kỳ để bảng không phình mãi.
func (s *SQLite) PurgeExpiredSessions(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, nowSecond())
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (s *SQLite) TouchSession(ctx context.Context, tokenHash string) error {
	return s.execAffectOne(ctx, `UPDATE sessions SET last_seen = ? WHERE token_hash = ?`, now(), tokenHash)
}

// --- login attempts -----------------------------------------------------------

// RecordLoginFailure tăng bộ đếm và khoá khi chạm ngưỡng.
//
// Một câu UPSERT: đọc-rồi-ghi sẽ để hai lần thử song song cùng thấy "9 lần" và
// cùng ghi "10", tức là bỏ lỡ đúng lần chạm ngưỡng.
func (s *SQLite) RecordLoginFailure(ctx context.Context, key string, threshold int, lockFor time.Duration) (*LoginAttempts, error) {
	ts := nowSecond()
	lockUntil := formatSecondCeil(time.Now().Add(lockFor))
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO login_attempts (scope_key, failures, first_fail, last_fail, locked_until)
		 VALUES (?, 1, ?, ?, NULL)
		 ON CONFLICT(scope_key) DO UPDATE SET
			failures     = login_attempts.failures + 1,
			last_fail    = excluded.last_fail,
			locked_until = CASE WHEN login_attempts.failures + 1 >= ? THEN ? ELSE login_attempts.locked_until END`,
		key, ts, ts, threshold, lockUntil)
	if err != nil {
		return nil, err
	}
	return s.GetLoginAttempts(ctx, key)
}

func (s *SQLite) GetLoginAttempts(ctx context.Context, key string) (*LoginAttempts, error) {
	var (
		la                  LoginAttempts
		lockedUntil         sql.NullString
		firstFail, lastFail string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT scope_key, failures, first_fail, last_fail, locked_until FROM login_attempts WHERE scope_key = ?`, key).
		Scan(&la.Key, &la.Failures, &firstFail, &lastFail, &lockedUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	la.FirstFail = parseTimeRFC3339(firstFail)
	la.LastFail = parseTimeRFC3339(lastFail)
	if lockedUntil.Valid {
		t := parseTimeRFC3339(lockedUntil.String)
		la.LockedUntil = &t
	}
	return &la, nil
}

// ClearLoginFailures xoá lịch sử sau một lần đăng nhập ĐÚNG.
func (s *SQLite) ClearLoginFailures(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE scope_key = ?`, key)
	return err
}

// ClearAllLoginFailures xoá MỌI bộ đếm, cả theo user lẫn theo IP.
func (s *SQLite) ClearAllLoginFailures(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM login_attempts`)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
