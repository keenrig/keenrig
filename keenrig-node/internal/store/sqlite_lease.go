package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// AcquireLease — giành hoặc gia hạn lease bằng ĐÚNG MỘT câu SQL.
//
// Cả ba nhánh (chưa ai giữ · đã quá hạn · chính mình gia hạn) nằm trong một
// INSERT … ON CONFLICT DO UPDATE … WHERE, nên không có cửa sổ nào giữa "đọc
// xem ai đang giữ" và "ghi tên mình vào". Kiểm bằng SELECT rồi UPDATE là kiểu
// hỏng kinh điển của lease: hai tiến trình cùng đọc thấy hết hạn, cả hai cùng
// ghi, cả hai cùng tin mình là chủ.
//
// token = token cũ + 1 khi ĐỔI CHỦ, giữ nguyên khi gia hạn. Nhờ vậy chủ hiện
// tại gia hạn liên tục không làm token trôi, còn mỗi lần chuyển giao đều để lại
// một mốc mà chủ cũ không thể đoán ra.
func (s *SQLite) AcquireLease(ctx context.Context, name, holder string, ttl time.Duration) (*Lease, error) {
	if holder == "" {
		return nil, errors.New("store: AcquireLease requires a non-empty holder")
	}
	if ttl <= 0 {
		return nil, errors.New("store: AcquireLease requires ttl > 0")
	}
	nowTS := nowSecond()
	expires := formatSecondCeil(time.Now().Add(ttl))

	var l Lease
	var expiresAt string
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO leases (name, holder, token, expires_at, updated_at)
		 VALUES (?, ?, 1, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET
			holder     = excluded.holder,
			token      = CASE WHEN leases.holder = excluded.holder
			                  THEN leases.token ELSE leases.token + 1 END,
			expires_at = excluded.expires_at,
			updated_at = excluded.updated_at
		 WHERE leases.holder = excluded.holder OR leases.expires_at <= ?
		 RETURNING name, holder, token, expires_at`,
		name, holder, expires, nowTS, nowTS).Scan(&l.Name, &l.Holder, &l.Token, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		// WHERE của DO UPDATE không thoả → người khác đang giữ và chưa hết hạn.
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	l.ExpiresAt = parseTimeRFC3339(expiresAt)
	return &l, nil
}

// RenewLease — gia hạn có kiểm FENCING TOKEN.
//
// Vì sao không dùng thẳng AcquireLease: AcquireLease coi "cùng holder" là gia
// hạn hợp lệ, mà holder là chuỗi do tiến trình tự đặt. Một tiến trình bị treo
// lâu, mất lease vào tay tiến trình khác rồi lại giành về, sẽ có cùng holder
// nhưng token đã nhảy — nghĩa là đã có một khoảng nó KHÔNG phải chủ. Vòng lặp
// reconcile cần biết khoảng đó tồn tại để dừng lại, nên ở đây sai token là lỗi.
func (s *SQLite) RenewLease(ctx context.Context, name, holder string, token int64, ttl time.Duration) (*Lease, error) {
	if ttl <= 0 {
		return nil, errors.New("store: RenewLease requires ttl > 0")
	}
	expires := formatSecondCeil(time.Now().Add(ttl))

	var l Lease
	var expiresAt string
	err := s.db.QueryRowContext(ctx,
		`UPDATE leases SET expires_at = ?, updated_at = ?
		 WHERE name = ? AND holder = ? AND token = ?
		 RETURNING name, holder, token, expires_at`,
		expires, nowSecond(), name, holder, token).Scan(&l.Name, &l.Holder, &l.Token, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, s.leaseMissOrConflict(ctx, name)
	}
	if err != nil {
		return nil, err
	}
	l.ExpiresAt = parseTimeRFC3339(expiresAt)
	return &l, nil
}

// ReleaseLease — nhả sớm. Nhả lease KHÔNG phải của mình là no-op có lỗi, không
// phải xoá: chủ cũ tỉnh dậy và "dọn dẹp" đúng lúc chủ mới đang làm việc là
// đúng kịch bản mà fencing token sinh ra để chặn.
func (s *SQLite) ReleaseLease(ctx context.Context, name, holder string, token int64) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM leases WHERE name = ? AND holder = ? AND token = ?`, name, holder, token)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return s.leaseMissOrConflict(ctx, name)
	}
	return nil
}

func (s *SQLite) GetLease(ctx context.Context, name string) (*Lease, error) {
	var l Lease
	var expiresAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT name, holder, token, expires_at FROM leases WHERE name = ?`, name).
		Scan(&l.Name, &l.Holder, &l.Token, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	l.ExpiresAt = parseTimeRFC3339(expiresAt)
	return &l, nil
}

// leaseMissOrConflict phân biệt "không có lease nào" với "có nhưng không phải
// của bạn" sau khi một câu UPDATE/DELETE có điều kiện không khớp row nào.
func (s *SQLite) leaseMissOrConflict(ctx context.Context, name string) error {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM leases WHERE name = ?`, name).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return ErrConflict
}

// parseTimeRFC3339 — cột expires_at ghi bằng formatSecondCeil (độ phân giải giây).
func parseTimeRFC3339(v string) time.Time {
	t, _ := time.Parse(time.RFC3339, v)
	return t
}
