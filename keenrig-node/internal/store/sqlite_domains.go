package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// SetEndpoints thay nguyên khối tập endpoint của app.
//
// Ghi cả tập bằng một câu UPDATE (không phải bảng con cập nhật từng dòng) vì
// endpoint là DẪN XUẤT của một lần Apply: scale 3→1 replica mà cập nhật từng
// dòng thì hai endpoint cũ ở lại làm upstream ma, gateway vẫn cân tải sang
// container đã chết.
func (s *SQLite) SetEndpoints(ctx context.Context, id string, eps []Endpoint) error {
	var val any
	if len(eps) > 0 {
		data, err := json.Marshal(eps)
		if err != nil {
			return err
		}
		val = string(data)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE apps SET endpoints = ? WHERE id = ? AND deleted_at IS NULL`, val, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- domains -----------------------------------------------------------------

const domainColumns = `app_id, fqdn, is_primary, cert_ref, created_at`

func scanDomain(row interface{ Scan(...any) error }) (*Domain, error) {
	var (
		d         Domain
		certRef   sql.NullString
		createdAt string
	)
	if err := row.Scan(&d.AppID, &d.FQDN, &d.IsPrimary, &certRef, &createdAt); err != nil {
		return nil, err
	}
	if certRef.Valid {
		d.CertRef = certRef.String
	}
	d.CreatedAt = parseTime(createdAt)
	return &d, nil
}

// AddDomain gắn FQDN vào app.
//
// Kiểm app tồn tại TRƯỚC rồi mới INSERT, dù đã có foreign key: FK vi phạm cho
// ra một lỗi chuỗi khó phân biệt với UNIQUE vi phạm, mà hai thứ này phải ra hai
// mã HTTP khác nhau (404 với app lạ, 409 với domain đã có chủ). App đang chờ
// xoá cũng phải là 404 — FK không biết gì về deleted_at.
//
// Cả hai UNIQUE (fqdn toàn cục, và partial index một domain chính mỗi app) đều
// quy về ErrConflict: caller phân biệt bằng cách đọc lại, còn ở đây phân biệt
// cũng không đổi được quyết định nào.
func (s *SQLite) AddDomain(ctx context.Context, d *Domain) error {
	var one int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM apps WHERE id = ? AND deleted_at IS NULL`, d.AppID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}

	ts := now()
	var certRef any
	if d.CertRef != "" {
		certRef = d.CertRef
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO app_domains (app_id, fqdn, is_primary, cert_ref, created_at) VALUES (?, ?, ?, ?, ?)`,
		d.AppID, d.FQDN, boolToInt(d.IsPrimary), certRef, ts)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	d.CreatedAt = parseTime(ts)
	return nil
}

func (s *SQLite) queryDomains(ctx context.Context, query string, args ...any) ([]*Domain, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *SQLite) ListDomains(ctx context.Context, appID string) ([]*Domain, error) {
	return s.queryDomains(ctx,
		`SELECT `+domainColumns+` FROM app_domains WHERE app_id = ? ORDER BY is_primary DESC, fqdn`, appID)
}

// ListAllDomains bỏ domain của app đang chờ xoá: đây là nguồn dựng desired cho
// proxy.Apply, mà proxy LEVEL-TRIGGERED — domain còn trong danh sách nghĩa là
// gateway còn phục vụ. App đang bị gỡ container thì route phải biến mất trước.
func (s *SQLite) ListAllDomains(ctx context.Context) ([]*Domain, error) {
	return s.queryDomains(ctx,
		`SELECT d.app_id, d.fqdn, d.is_primary, d.cert_ref, d.created_at
		 FROM app_domains d JOIN apps a ON a.id = d.app_id
		 WHERE a.deleted_at IS NULL ORDER BY d.fqdn`)
}

func (s *SQLite) DeleteDomain(ctx context.Context, fqdn string) error {
	return s.execAffectOne(ctx, `DELETE FROM app_domains WHERE fqdn = ?`, fqdn)
}

func (s *SQLite) SetDomainCertRef(ctx context.Context, fqdn, certRef string) error {
	var val any
	if certRef != "" {
		val = certRef
	}
	return s.execAffectOne(ctx, `UPDATE app_domains SET cert_ref = ? WHERE fqdn = ?`, val, fqdn)
}

// --- addons ------------------------------------------------------------------

// PutAppAddon upsert. created_at giữ nguyên khi cập nhật — mốc "addon này được
// cấp cho app từ bao giờ" không được reset mỗi lần đổi state.
func (s *SQLite) PutAppAddon(ctx context.Context, a *AppAddon) error {
	if a.State == "" {
		a.State = AddonPending
	}
	ts := now()
	var configRef any
	if a.ConfigRef != "" {
		configRef = a.ConfigRef
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO app_addons (app_id, addon, state, config_ref, last_error, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(app_id, addon) DO UPDATE SET
			state      = excluded.state,
			config_ref = excluded.config_ref,
			last_error = excluded.last_error,
			updated_at = excluded.updated_at`,
		a.AppID, a.Addon, a.State, configRef, a.LastError, ts, ts)
	if isForeignKeyViolation(err) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	a.UpdatedAt = parseTime(ts)
	if a.CreatedAt.IsZero() {
		a.CreatedAt = a.UpdatedAt
	}
	return nil
}

func (s *SQLite) ListAppAddons(ctx context.Context, appID string) ([]*AppAddon, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT app_id, addon, state, config_ref, last_error, created_at, updated_at
		 FROM app_addons WHERE app_id = ? ORDER BY addon`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AppAddon
	for rows.Next() {
		var (
			a                    AppAddon
			configRef            sql.NullString
			createdAt, updatedAt string
		)
		if err := rows.Scan(&a.AppID, &a.Addon, &a.State, &configRef, &a.LastError,
			&createdAt, &updatedAt); err != nil {
			return nil, err
		}
		if configRef.Valid {
			a.ConfigRef = configRef.String
		}
		a.CreatedAt = parseTime(createdAt)
		a.UpdatedAt = parseTime(updatedAt)
		out = append(out, &a)
	}
	return out, rows.Err()
}

func (s *SQLite) DeleteAppAddon(ctx context.Context, appID, addon string) error {
	return s.execAffectOne(ctx, `DELETE FROM app_addons WHERE app_id = ? AND addon = ?`, appID, addon)
}

// --- helper ------------------------------------------------------------------

// execAffectOne chạy câu lệnh và quy "không đụng row nào" về ErrNotFound.
func (s *SQLite) execAffectOne(ctx context.Context, query string, args ...any) error {
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// isForeignKeyViolation — app_id không tồn tại trong apps.
func isForeignKeyViolation(err error) bool {
	return err != nil && strings.Contains(strings.ToUpper(err.Error()), "FOREIGN KEY CONSTRAINT")
}
