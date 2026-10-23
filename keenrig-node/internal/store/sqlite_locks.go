package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// --- locks --------------------------------------------------------------------

// AcquireLock giành khoá thao tác bằng ĐÚNG MỘT câu SQL.
//
// INSERT … ON CONFLICT DO UPDATE … WHERE expires_at <= now: khoá còn hạn của
// người khác làm WHERE không thoả → 0 row → ErrConflict. Không có cửa sổ giữa
// "đọc xem ai giữ" và "ghi tên mình" — cùng lập luận với AcquireLease.
//
// Chủ cũ giành lại khoá của CHÍNH MÌNH là hợp lệ (gia hạn): thao tác dài như
// backup phải gia hạn được, nếu không nó tự hết hạn giữa chừng.
func (s *SQLite) AcquireLock(ctx context.Context, name, holder, reason string, ttl time.Duration) (*Lock, error) {
	if holder == "" {
		return nil, errors.New("store: AcquireLock requires a non-empty holder")
	}
	if ttl <= 0 {
		return nil, errors.New("store: AcquireLock requires ttl > 0")
	}
	nowTS := nowSecond()
	expires := formatSecondCeil(time.Now().Add(ttl))

	var l Lock
	var expiresAt, acquiredAt string
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO locks (name, holder, expires_at, acquired_at, reason)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET
			holder     = excluded.holder,
			expires_at = excluded.expires_at,
			reason     = excluded.reason
		 WHERE locks.holder = excluded.holder OR locks.expires_at <= ?
		 RETURNING name, holder, expires_at, acquired_at, reason`,
		name, holder, expires, nowTS, reason, nowTS).
		Scan(&l.Name, &l.Holder, &expiresAt, &acquiredAt, &l.Reason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	l.ExpiresAt = parseTimeRFC3339(expiresAt)
	l.AcquiredAt = parseTime(acquiredAt)
	return &l, nil
}

// ReleaseLock nhả khoá. Sai holder → ErrConflict, không có → ErrNotFound.
//
// Nhả khoá KHÔNG phải của mình bị từ chối chứ không im lặng bỏ qua: chủ cũ tỉnh
// dậy sau một lần treo và "dọn dẹp" đúng lúc chủ mới đang làm việc là kịch bản
// thật, và im lặng cho qua sẽ biến nó thành hai thao tác chồng nhau.
func (s *SQLite) ReleaseLock(ctx context.Context, name, holder string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM locks WHERE name = ? AND holder = ?`, name, holder)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		var one int
		err := s.db.QueryRowContext(ctx, `SELECT 1 FROM locks WHERE name = ?`, name).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return ErrConflict
	}
	return nil
}

// ReleaseLocksByHolder nhả MỌI khoá của một chủ, trả số khoá đã nhả.
//
// Mục đích chính là LỘ lỗi lập trình, không chỉ dọn rác. Gọi ở cuối mỗi job —
// job nào quên nhả sẽ được dọn VÀ để lại một dòng log chỉ đúng vào chỗ thiếu.
func (s *SQLite) ReleaseLocksByHolder(ctx context.Context, holder string) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM locks WHERE holder = ?`, holder)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// ListLocks trả mọi khoá CÒN HẠN, ORDER BY name.
//
// Lọc hạn trong SQL: tầng trên cần biết "cái gì đang chặn tôi", và một khoá đã
// hết hạn thì không chặn ai — trả nó về chỉ làm thông báo lỗi nói sai.
func (s *SQLite) ListLocks(ctx context.Context) ([]*Lock, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, holder, expires_at, acquired_at, reason FROM locks
		 WHERE expires_at > ? ORDER BY name`, nowSecond())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Lock
	for rows.Next() {
		var (
			l                     Lock
			expiresAt, acquiredAt string
		)
		if err := rows.Scan(&l.Name, &l.Holder, &expiresAt, &acquiredAt, &l.Reason); err != nil {
			return nil, err
		}
		l.ExpiresAt = parseTimeRFC3339(expiresAt)
		l.AcquiredAt = parseTime(acquiredAt)
		out = append(out, &l)
	}
	return out, rows.Err()
}

// PurgeExpiredLocks prune expired locks, trả số khoá đã dọn.
func (s *SQLite) PurgeExpiredLocks(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM locks WHERE expires_at <= ?`, nowSecond())
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// --- tiến độ job ----------------------------------------------------------------

// SetJobProgress cập nhật phần trăm + thông điệp của job đang chạy.
//
// CHỈ tác động lên job 'running' và ĐÚNG chủ đang giữ lease: một worker đã mất
// lease (bị ReclaimExpired thu hồi) mà vẫn ghi tiến độ sẽ đè lên tiến độ của
// worker mới — người dùng thấy thanh tiến trình nhảy lùi.
func (s *SQLite) SetJobProgress(ctx context.Context, id int64, owner string, percent int, message string) error {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	return s.execAffectOne(ctx,
		`UPDATE jobs SET percent = ?, message = ?
		 WHERE id = ? AND state = 'running' AND lease_owner = ?`,
		percent, message, id, owner)
}

// PurgeFinishedJobs xoá job đã kết thúc trước mốc before, trả số job đã xoá.
func (s *SQLite) PurgeFinishedJobs(ctx context.Context, before time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM jobs WHERE state IN ('done', 'failed') AND finished_at IS NOT NULL AND finished_at <= ?`,
		formatSecondCeil(before))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// PurgeEvents xoá event cũ hơn mốc before, trả số event đã xoá.
//
// Housekeep gọi định kỳ với ngưỡng 90 ngày. Không dọn thì bảng
// audit phình vô hạn trên một instance chạy nhiều năm, và `ListEvents` chậm dần
// tới mức UI treo.
func (s *SQLite) PurgeEvents(ctx context.Context, before time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM events WHERE created_at <= ?`, before.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// GetJob đọc một job theo id.
//
// Có nó vì API phải trả lời "job của tôi tới đâu rồi" — không có đường đọc thì
// percent/message vừa thêm ở migration 0006 không ai nhìn thấy.
func (s *SQLite) GetJob(ctx context.Context, id int64) (*Job, error) {
	job, err := scanJob(s.db.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM jobs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return job, err
}

// ListJobs trả job mới nhất trước, tối đa limit. kinds rỗng = mọi kind.
func (s *SQLite) ListJobs(ctx context.Context, kinds []string, limit int) ([]*Job, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT ` + jobColumns + ` FROM jobs`
	args := []any{}
	if len(kinds) > 0 {
		query += ` WHERE kind IN (?` + strings.Repeat(", ?", len(kinds)-1) + `)`
		for _, k := range kinds {
			args = append(args, k)
		}
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
