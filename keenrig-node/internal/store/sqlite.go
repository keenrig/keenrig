package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// SQLite implement Store trên modernc.org/sqlite.
// Store KHÔNG validate desired — đó là việc của tầng api (T7).
type SQLite struct {
	db *sql.DB
	ks *keystore
}

var _ Store = (*SQLite)(nil)

// Open mở (hoặc tạo) file DB tại dbPath, tự chạy migration, rồi nạp
// (hoặc tự sinh) master key tại masterKeyPath cho keystore secrets.
// escapeDSNPath làm đường dẫn an toàn để nhét vào DSN dạng URI của SQLite.
//
// # Vì sao cần, và vì sao nó từng gây ra một lỗi im lặng
//
// DSN ở đây là một URI (`file:…?_pragma=…`) vì đó là cách duy nhất truyền pragma.
// Nhưng URI có ký tự đặc biệt: `#` mở fragment và `?` mở query. Nối đường dẫn thô
// vào nghĩa là một đường dẫn chứa `#` bị CẮT tại đó — SQLite mở (và TẠO) một
// database ở đường dẫn khác hoàn toàn, không lỗi, không cảnh báo.
//
// Đã bắt được thật: một test tên `.../TestSupportedPolicyPassescaddy#01…/platform.db`
// làm SQLite mở `.../TestSupportedPolicyPassescaddy` — một file rác ở thư mục cha,
// dùng chung giữa các lần chạy, nên test đỏ vì "slug đã tồn tại" từ lần chạy TRƯỚC.
//
// Ngoài test, đường thật cũng có: `C:\Users\Anh #2\keenrig` là tên thư mục hợp lệ
// trên Windows. Hậu quả nặng hơn test nhiều — `master.key` được đọc bằng `os` nên
// nó tới đúng chỗ, còn database thì không: khoá và dữ liệu tách khỏi nhau, và
// người vận hành thấy một instance TRỐNG thay vì một lỗi.
//
// Escape `%` TRƯỚC, nếu không ta escape lại chính dấu `%` mình vừa sinh ra.
func escapeDSNPath(p string) string {
	p = strings.ReplaceAll(p, "%", "%25")
	p = strings.ReplaceAll(p, "#", "%23")
	p = strings.ReplaceAll(p, "?", "%3F")
	return p
}

func Open(dbPath, masterKeyPath string) (*SQLite, error) {
	dsn := "file:" + escapeDSNPath(filepath.ToSlash(dbPath)) +
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// modernc.org/sqlite: 1 connection để tránh SQLITE_BUSY khi ghi song song.
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	key, err := loadOrCreateMasterKey(masterKeyPath)
	if err != nil {
		db.Close()
		return nil, err
	}
	ks, err := newKeystore(key)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &SQLite{db: db, ks: ks}, nil
}

func (s *SQLite) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Close checkpoint WAL rồi mới đóng.
//
// Không phải chi tiết dọn dẹp cho đẹp — đóng mà bỏ lại platform.db-wal có hai
// hệ quả thật:
//
//  1. BACKUP/RESTORE: copy mỗi file platform.db mà bỏ -wal là mất mọi commit
//     chưa checkpoint. Đó là cách hỏng im lặng — bản backup mở lên vẫn chạy,
//     chỉ thiếu vài giao dịch cuối.
//  2. OTA: box cũ tắt, box mới mở cùng file. File -wal/-shm còn sót làm bước
//     thay bin/ và mọi thao tác coi platform.db là MỘT file trở nên sai.
//
// TRUNCATE (không phải PASSIVE) vì ta muốn -wal thật sự về 0 byte trước khi
// trả quyền cho caller. Checkpoint lỗi thì vẫn đóng: đóng được là ưu tiên cao
// hơn, và lỗi được trả kèm để caller ghi log.
func (s *SQLite) Close() error {
	_, ckptErr := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	closeErr := s.db.Close()
	if closeErr != nil {
		return closeErr
	}
	if ckptErr != nil {
		return fmt.Errorf("store: checkpointing the WAL on close: %w", ckptErr)
	}
	return nil
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// nowSecond — riêng cho jobs.not_before: RFC3339 GIÂY UTC, fixed-width
// để so sánh chuỗi <= trong SQL đúng thứ tự thời gian.
func nowSecond() string { return time.Now().UTC().Format(time.RFC3339) }

// formatSecondCeil — RFC3339 GIÂY UTC, làm tròn LÊN. not_before chỉ có độ phân
// giải giây mà ClaimJob mở cổng đúng lúc `not_before <= now`, nên làm tròn
// XUỐNG sẽ cho job chạy sớm tới gần 1 giây so với mốc đã hẹn. Tròn lên → mốc
// lưu luôn >= mốc yêu cầu: job có thể chạy MUỘN tối đa 1 giây, không bao giờ sớm.
func formatSecondCeil(t time.Time) string {
	u := t.UTC()
	if trunc := u.Truncate(time.Second); !trunc.Equal(u) {
		u = trunc.Add(time.Second)
	}
	return u.Format(time.RFC3339)
}

// retryNotBefore — mốc not_before cho lần retry của FailJob.
// retryAfter <= 0 nghĩa là "chạy lại ngay": lấy mốc giây hiện tại (đã tới hạn,
// claim được liền) — không làm tròn lên, vì không thể claim sớm hơn "bây giờ".
// retryAfter > 0 → làm tròn LÊN để không chạy sớm hơn now+retryAfter.
func retryNotBefore(retryAfter time.Duration) string {
	if retryAfter <= 0 {
		return nowSecond()
	}
	return formatSecondCeil(time.Now().Add(retryAfter))
}

func parseTime(v string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, v)
	return t
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func (s *SQLite) CreateApp(ctx context.Context, app *App) error {
	ts := now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO apps (id, slug, desired, desired_rev, applied_rev, status, created_at, updated_at)
		 VALUES (?, ?, ?, 1, 0, NULL, ?, ?)`,
		app.ID, app.Slug, string(app.Desired), ts, ts)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	app.DesiredRev = 1
	app.AppliedRev = 0
	app.CreatedAt = parseTime(ts)
	app.UpdatedAt = app.CreatedAt
	return nil
}

const appColumns = `id, slug, desired, desired_rev, applied_rev, status, endpoints, created_at, updated_at`

func scanApp(row interface{ Scan(...any) error }) (*App, error) {
	var (
		app                  App
		desired              string
		status, endpoints    sql.NullString
		createdAt, updatedAt string
	)
	if err := row.Scan(&app.ID, &app.Slug, &desired, &app.DesiredRev, &app.AppliedRev,
		&status, &endpoints, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	app.Desired = json.RawMessage(desired)
	if status.Valid {
		app.Status = json.RawMessage(status.String)
	}
	// Endpoints hỏng KHÔNG được làm hỏng cả app: nó là cache dẫn xuất, tick
	// reconcile sau ghi đè. Trả lỗi ở đây sẽ khoá luôn cả ListApps.
	if endpoints.Valid && endpoints.String != "" {
		if err := json.Unmarshal([]byte(endpoints.String), &app.Endpoints); err != nil {
			app.Endpoints = nil
		}
	}
	app.CreatedAt = parseTime(createdAt)
	app.UpdatedAt = parseTime(updatedAt)
	return &app, nil
}

func (s *SQLite) GetApp(ctx context.Context, id string) (*App, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+appColumns+` FROM apps WHERE id = ? AND deleted_at IS NULL`, id)
	app, err := scanApp(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return app, err
}

func (s *SQLite) queryApps(ctx context.Context, query string, args ...any) ([]*App, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var apps []*App
	for rows.Next() {
		app, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		apps = append(apps, app)
	}
	return apps, rows.Err()
}

func (s *SQLite) ListApps(ctx context.Context) ([]*App, error) {
	return s.queryApps(ctx,
		`SELECT `+appColumns+` FROM apps WHERE deleted_at IS NULL ORDER BY created_at`)
}

func (s *SQLite) ListAppsNeedingReconcile(ctx context.Context) ([]*App, error) {
	return s.queryApps(ctx,
		`SELECT `+appColumns+` FROM apps
		 WHERE deleted_at IS NULL AND desired_rev > applied_rev ORDER BY created_at`)
}

func (s *SQLite) ListAppsPendingDelete(ctx context.Context) ([]*App, error) {
	return s.queryApps(ctx,
		`SELECT `+appColumns+` FROM apps WHERE deleted_at IS NOT NULL ORDER BY deleted_at`)
}

func (s *SQLite) UpdateDesired(ctx context.Context, id string, desired json.RawMessage) (int64, error) {
	var rev int64
	err := s.db.QueryRowContext(ctx,
		`UPDATE apps SET desired = ?, desired_rev = desired_rev + 1, updated_at = ?
		 WHERE id = ? AND deleted_at IS NULL RETURNING desired_rev`,
		string(desired), now(), id).Scan(&rev)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return rev, err
}

// SetStatus ghi status + applied_rev với guard: appliedRev không được vượt
// desired_rev hiện tại. UPDATE 0 row → SELECT lại để phân biệt NotFound/Conflict.
//
// appliedRev ÂM cũng là vi phạm ST-01: guard SQL `desired_rev >= ?` cho số âm
// lọt qua, và applied_rev âm khiến app luôn thoả `desired_rev > applied_rev`
// → kẹt trong ListAppsNeedingReconcile vĩnh viễn. Chặn ngay tại đây.
func (s *SQLite) SetStatus(ctx context.Context, id string, status json.RawMessage, appliedRev int64) error {
	if appliedRev < 0 {
		return ErrConflict
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE apps SET status = ?, applied_rev = ?, updated_at = ?
		 WHERE id = ? AND deleted_at IS NULL AND desired_rev >= ?`,
		string(status), appliedRev, now(), id, appliedRev)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		var one int
		err := s.db.QueryRowContext(ctx,
			`SELECT 1 FROM apps WHERE id = ? AND deleted_at IS NULL`, id).Scan(&one)
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

// DeleteApp — pha 1 xoá 2 pha: đánh dấu deleted_at (KHÔNG xoá row) để reconciler
// còn biết mà gọi runtime.Remove dọn container. App đã đánh dấu coi như không
// tồn tại với Get/List/UpdateDesired/SetStatus → xoá lần 2 trả ErrNotFound.
func (s *SQLite) DeleteApp(ctx context.Context, id string) error {
	ts := now()
	res, err := s.db.ExecContext(ctx,
		`UPDATE apps SET deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`,
		ts, ts, id)
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

// PurgeApp — pha 2: DELETE row thật, giải phóng slug. Idempotent theo nghĩa
// row đã biến mất → ErrNotFound.
func (s *SQLite) PurgeApp(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM apps WHERE id = ?`, id)
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

func (s *SQLite) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return value, err
}

func (s *SQLite) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (s *SQLite) PutSecret(ctx context.Context, ref string, plaintext []byte) error {
	blob, err := s.ks.seal(plaintext)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO secrets (ref, ciphertext, created_at) VALUES (?, ?, ?)
		 ON CONFLICT(ref) DO UPDATE SET ciphertext = excluded.ciphertext`,
		ref, blob, now())
	return err
}

func (s *SQLite) GetSecret(ctx context.Context, ref string) ([]byte, error) {
	var blob []byte
	err := s.db.QueryRowContext(ctx, `SELECT ciphertext FROM secrets WHERE ref = ?`, ref).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.ks.open(blob)
}

func (s *SQLite) DeleteSecret(ctx context.Context, ref string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM secrets WHERE ref = ?`, ref)
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

func (s *SQLite) EnqueueJob(ctx context.Context, kind string, args json.RawMessage, notBefore *time.Time) (int64, error) {
	var argsVal, nbVal any
	if len(args) > 0 {
		argsVal = string(args)
	}
	if notBefore != nil {
		nbVal = formatSecondCeil(*notBefore)
	}
	var id int64
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO jobs (kind, args, state, attempt, not_before, created_at)
		 VALUES (?, ?, 'queued', 0, ?, ?) RETURNING id`,
		kind, argsVal, nbVal, now()).Scan(&id)
	return id, err
}

const jobColumns = `id, kind, args, state, attempt, not_before, result, last_error, lease_until, lease_owner, percent, message, finished_at, created_at`

func scanJob(row interface{ Scan(...any) error }) (*Job, error) {
	var (
		job                     Job
		args, notBefore, result sql.NullString
		leaseUntil, finishedAt  sql.NullString
		createdAt               string
	)
	if err := row.Scan(&job.ID, &job.Kind, &args, &job.State, &job.Attempt,
		&notBefore, &result, &job.LastError, &leaseUntil, &job.LeaseOwner,
		&job.Percent, &job.Message, &finishedAt, &createdAt); err != nil {
		return nil, err
	}
	if finishedAt.Valid {
		t := parseTimeRFC3339(finishedAt.String)
		job.FinishedAt = &t
	}
	if leaseUntil.Valid {
		t, err := time.Parse(time.RFC3339, leaseUntil.String)
		if err != nil {
			return nil, fmt.Errorf("store: lease_until %q is not RFC3339: %w", leaseUntil.String, err)
		}
		job.LeaseUntil = &t
	}
	if args.Valid {
		job.Args = json.RawMessage(args.String)
	}
	if notBefore.Valid {
		t, err := time.Parse(time.RFC3339, notBefore.String)
		if err != nil {
			return nil, fmt.Errorf("store: not_before %q is not RFC3339: %w", notBefore.String, err)
		}
		job.NotBefore = &t
	}
	if result.Valid {
		job.Result = json.RawMessage(result.String)
	}
	job.CreatedAt = parseTime(createdAt)
	return &job, nil
}

func (s *SQLite) ClaimJob(ctx context.Context, kinds []string) (*Job, error) {
	return s.ClaimJobAs(ctx, kinds, "", DefaultJobLease)
}

// ClaimJobAs claim atomic bằng đúng 1 câu UPDATE (MaxOpenConns=1, không transaction):
// chọn job queued đến hạn có id nhỏ nhất, chuyển sang running kèm HẠN GIỮ, RETURNING cả row.
//
// lease_until ghi trong CÙNG câu UPDATE với state — tách làm hai câu sẽ mở ra
// đúng cái cửa sổ ta đang bịt: job 'running' mà chưa có hạn, worker chết đúng
// lúc đó là kẹt vĩnh viễn.
func (s *SQLite) ClaimJobAs(ctx context.Context, kinds []string, owner string, visibility time.Duration) (*Job, error) {
	if visibility <= 0 {
		visibility = DefaultJobLease
	}
	query := `UPDATE jobs SET state = 'running', lease_until = ?, lease_owner = ? WHERE id = (
		SELECT id FROM jobs WHERE state = 'queued' AND (not_before IS NULL OR not_before <= ?)`
	args := []any{formatSecondCeil(time.Now().Add(visibility)), owner, nowSecond()}
	if len(kinds) > 0 {
		query += ` AND kind IN (?` + strings.Repeat(", ?", len(kinds)-1) + `)`
		for _, k := range kinds {
			args = append(args, k)
		}
	}
	query += ` ORDER BY id LIMIT 1) RETURNING ` + jobColumns

	job, err := scanJob(s.db.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoJob
	}
	return job, err
}

// ReclaimExpired — LS-03. Job 'running' quá hạn giữ quay về 'queued', xoá dấu
// vết lease để lần claim sau ghi lại từ đầu.
//
// KHÔNG tăng attempt (xem godoc interface) và KHÔNG đụng job có lease_until
// NULL. not_before đặt về mốc hiện tại chứ không giữ mốc cũ: giữ mốc cũ thì job
// bị thu hồi sẽ đợi lại nguyên khoảng backoff nó đã đợi xong rồi.
func (s *SQLite) ReclaimExpired(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE jobs SET state = 'queued', lease_until = NULL, lease_owner = '', not_before = ?
		 WHERE state = 'running' AND lease_until IS NOT NULL AND lease_until <= ?`,
		nowSecond(), nowSecond())
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (s *SQLite) CompleteJob(ctx context.Context, id int64, result json.RawMessage) error {
	var resultVal any
	if len(result) > 0 {
		resultVal = string(result)
	}
	// Nhả lease cùng lúc kết thúc job — job 'done' còn lease_until là rác đủ để
	// làm ReclaimExpired và người đọc bảng hiểu sai ai đang giữ gì.
	res, err := s.db.ExecContext(ctx,
		`UPDATE jobs SET state = 'done', result = ?, lease_until = NULL, lease_owner = '',
		 percent = 100, finished_at = ? WHERE id = ?`,
		resultVal, nowSecond(), id)
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

// FailJob: attempt+1; đủ MaxJobAttempts → 'failed' (giữ not_before),
// chưa đủ → về 'queued' với not_before = now + retryAfter.
// CASE dùng giá trị attempt CŨ của row (SQLite semantics) nên attempt+1 = attempt mới.
//
// not_before có ĐỘ PHÂN GIẢI GIÂY (§0.5): retryAfter được làm tròn LÊN giây,
// nên job chạy lại muộn hơn yêu cầu tối đa 1 giây và không bao giờ sớm hơn.
// retryAfter dưới 1s vì thế không cho độ trễ dưới giây — dùng 0 nếu muốn
// claim lại ngay lập tức.
func (s *SQLite) FailJob(ctx context.Context, id int64, errMsg string, retryAfter time.Duration) error {
	retryAt := retryNotBefore(retryAfter)
	res, err := s.db.ExecContext(ctx,
		`UPDATE jobs SET
			attempt = attempt + 1,
			last_error = ?,
			state = CASE WHEN attempt + 1 >= ? THEN 'failed' ELSE 'queued' END,
			not_before = CASE WHEN attempt + 1 >= ? THEN not_before ELSE ? END,
			lease_until = NULL,
			lease_owner = '',
			-- finished_at CHỈ đặt khi job hết đường thử lại: job còn retry thì
			-- nó chưa kết thúc, và janitor không được dọn nó đi.
			finished_at = CASE WHEN attempt + 1 >= ? THEN ? ELSE NULL END
		 WHERE id = ?`,
		errMsg, MaxJobAttempts, MaxJobAttempts, retryAt, MaxJobAttempts, nowSecond(), id)
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

func (s *SQLite) AppendEvent(ctx context.Context, action, actor, subject string, data json.RawMessage) error {
	var d any
	if len(data) > 0 {
		d = string(data)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO events (action, actor, subject, data, created_at) VALUES (?, ?, ?, ?, ?)`,
		action, actor, subject, d, now())
	return err
}

func (s *SQLite) ListEvents(ctx context.Context, limit int) ([]*Event, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, action, actor, subject, data, created_at FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []*Event
	for rows.Next() {
		var (
			ev        Event
			data      sql.NullString
			createdAt string
		)
		if err := rows.Scan(&ev.ID, &ev.Action, &ev.Actor, &ev.Subject, &data, &createdAt); err != nil {
			return nil, err
		}
		if data.Valid {
			ev.Data = json.RawMessage(data.String)
		}
		ev.CreatedAt = parseTime(createdAt)
		events = append(events, &ev)
	}
	return events, rows.Err()
}
