package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

const apiTokenColumns = `token_hash, id, user_id, name, scopes, expires_at,
	allowed_ip_cidrs, created_at, last_used_at, last_used_ip`

func scanAPIToken(row interface{ Scan(...any) error }) (*APIToken, error) {
	var (
		t                    APIToken
		scopes, cidrs        string
		expiresAt, createdAt string
		lastUsedAt           sql.NullString
	)
	if err := row.Scan(&t.TokenHash, &t.ID, &t.UserID, &t.Name, &scopes, &expiresAt,
		&cidrs, &createdAt, &lastUsedAt, &t.LastUsedIP); err != nil {
		return nil, err
	}
	t.Scopes = splitCSV(scopes)
	t.AllowedIPCIDRs = splitCSV(cidrs)
	t.ExpiresAt = parseTimeRFC3339(expiresAt)
	t.CreatedAt = parseTime(createdAt)
	if lastUsedAt.Valid {
		u := parseTime(lastUsedAt.String)
		t.LastUsedAt = &u
	}
	return &t, nil
}

// splitCSV — "" → nil, không phải []string{""}.
//
// strings.Split("", ",") trả một phần tử rỗng, và một dải CIDR rỗng lọt vào
// danh sách allow sẽ làm mọi lần so khớp thất bại — token chết mà không ai
// hiểu vì sao.
func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, ",")
}

func (s *SQLite) CreateAPIToken(ctx context.Context, t *APIToken) error {
	ts := now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO api_tokens (`+apiTokenColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, '')`,
		t.TokenHash, t.ID, t.UserID, t.Name, strings.Join(t.Scopes, ","),
		formatSecondCeil(t.ExpiresAt), strings.Join(t.AllowedIPCIDRs, ","), ts)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	if isForeignKeyViolation(err) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	t.CreatedAt = parseTime(ts)
	return nil
}

// GetAPIToken trả token CÒN HẠN. Lọc hạn trong SQL chứ không ở Go — quên một
// chỗ so sánh ở tầng trên là để lọt một token đã hết hạn, và không ai nhìn ra
// khi đọc code.
func (s *SQLite) GetAPIToken(ctx context.Context, tokenHash string) (*APIToken, error) {
	t, err := scanAPIToken(s.db.QueryRowContext(ctx,
		`SELECT `+apiTokenColumns+` FROM api_tokens WHERE token_hash = ? AND expires_at > ?`,
		tokenHash, nowSecond()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

// ListAPITokens trả CẢ token đã hết hạn: người vận hành phải thấy token chết để
// dọn. Ẩn nó đi thì danh sách "sạch" trong khi bảng vẫn đầy.
func (s *SQLite) ListAPITokens(ctx context.Context, userID string) ([]*APIToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+apiTokenColumns+` FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*APIToken
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteAPIToken thu hồi. Có user_id trong WHERE để một user không thu hồi được
// token của người khác chỉ vì đoán trúng id — ràng buộc quyền nằm ở CÂU TRUY
// VẤN chứ không chỉ ở tầng service, vì tầng service có thể quên.
func (s *SQLite) DeleteAPIToken(ctx context.Context, userID, id string) error {
	return s.execAffectOne(ctx, `DELETE FROM api_tokens WHERE user_id = ? AND id = ?`, userID, id)
}

func (s *SQLite) TouchAPIToken(ctx context.Context, tokenHash, ip string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE api_tokens SET last_used_at = ?, last_used_ip = ? WHERE token_hash = ?`,
		now(), ip, tokenHash)
	return err
}

func (s *SQLite) PurgeExpiredAPITokens(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE expires_at <= ?`, nowSecond())
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
