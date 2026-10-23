package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// --- oidc_clients ------------------------------------------------------------------

const oidcClientColumns = `client_id, app_id, name, secret_ref, redirect_uris, created_at, updated_at`

func scanOIDCClient(row interface{ Scan(...any) error }) (*OIDCClient, error) {
	var (
		c                    OIDCClient
		appID                sql.NullString
		uris                 string
		createdAt, updatedAt string
	)
	if err := row.Scan(&c.ClientID, &appID, &c.Name, &c.SecretRef, &uris, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	if appID.Valid {
		c.AppID = appID.String
	}
	c.RedirectURIs = splitCSV(uris)
	c.CreatedAt = parseTime(createdAt)
	c.UpdatedAt = parseTime(updatedAt)
	return &c, nil
}

func (s *SQLite) PutOIDCClient(ctx context.Context, c *OIDCClient) error {
	ts := now()
	var appID any
	if c.AppID != "" {
		appID = c.AppID
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oidc_clients (`+oidcClientColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (client_id) DO UPDATE SET
		   app_id = excluded.app_id, name = excluded.name, secret_ref = excluded.secret_ref,
		   redirect_uris = excluded.redirect_uris, updated_at = excluded.updated_at`,
		c.ClientID, appID, c.Name, c.SecretRef, strings.Join(c.RedirectURIs, ","), ts, ts)
	if isForeignKeyViolation(err) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	c.UpdatedAt = parseTime(ts)
	if c.CreatedAt.IsZero() {
		c.CreatedAt = c.UpdatedAt
	}
	return nil
}

func (s *SQLite) GetOIDCClient(ctx context.Context, clientID string) (*OIDCClient, error) {
	c, err := scanOIDCClient(s.db.QueryRowContext(ctx,
		`SELECT `+oidcClientColumns+` FROM oidc_clients WHERE client_id = ?`, clientID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

func (s *SQLite) ListOIDCClients(ctx context.Context) ([]*OIDCClient, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+oidcClientColumns+` FROM oidc_clients ORDER BY client_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*OIDCClient
	for rows.Next() {
		c, err := scanOIDCClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLite) DeleteOIDCClient(ctx context.Context, clientID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM oidc_clients WHERE client_id = ?`, clientID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- oidc_codes --------------------------------------------------------------------

const oidcCodeColumns = `code_hash, client_id, user_id, redirect_uri, scope, nonce,
	code_challenge, auth_time, expires_at, created_at`

func (s *SQLite) CreateOIDCCode(ctx context.Context, c *OIDCCode) error {
	ts := now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oidc_codes (`+oidcCodeColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.CodeHash, c.ClientID, c.UserID, c.RedirectURI, c.Scope, c.Nonce,
		c.CodeChallenge, formatSecondCeil(c.AuthTime), formatSecondCeil(c.ExpiresAt), ts)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	if isForeignKeyViolation(err) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	c.CreatedAt = parseTime(ts)
	return nil
}

// ConsumeOIDCCode lấy VÀ XOÁ trong MỘT câu lệnh, bằng `DELETE … RETURNING`.
//
// # Vì sao không phải SELECT rồi DELETE
//
// Hai câu lệnh để lại một cửa sổ giữa chúng. Với mã uỷ quyền thì cửa sổ đó
// chính là toàn bộ tấn công: kẻ đọc trộm được mã (log của một reverse proxy,
// lịch sử trình duyệt, một Referer rò rỉ) chỉ cần chạy song song với người dùng
// thật, và cả hai cùng nhận được token.
//
// `DELETE … RETURNING` là nguyên khối trong SQLite, nên lần gọi THỨ HAI luôn
// trả về ErrNotFound bất kể hai lần gọi gần nhau tới đâu.
//
// Mã hết hạn KHÔNG được trả về nhưng VẪN bị xoá: lọc hạn ở mệnh đề RETURNING
// thay vì WHERE để một mã chết không nằm lại làm rác.
func (s *SQLite) ConsumeOIDCCode(ctx context.Context, codeHash string) (*OIDCCode, error) {
	var (
		c                              OIDCCode
		authTime, expiresAt, createdAt string
	)
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM oidc_codes WHERE code_hash = ? RETURNING `+oidcCodeColumns, codeHash).
		Scan(&c.CodeHash, &c.ClientID, &c.UserID, &c.RedirectURI, &c.Scope, &c.Nonce,
			&c.CodeChallenge, &authTime, &expiresAt, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.AuthTime = parseTimeRFC3339(authTime)
	c.ExpiresAt = parseTimeRFC3339(expiresAt)
	c.CreatedAt = parseTime(createdAt)
	if !c.ExpiresAt.After(parseTimeRFC3339(nowSecond())) {
		// Đã xoá rồi mới từ chối — mã chết không được nằm lại trong bảng.
		return nil, ErrNotFound
	}
	return &c, nil
}

func (s *SQLite) PurgeExpiredOIDCCodes(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM oidc_codes WHERE expires_at <= ?`, nowSecond())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
