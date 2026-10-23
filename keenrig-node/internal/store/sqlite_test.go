package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"testing/fstest"
	"time"
)

func openTestStore(t *testing.T) *SQLite {
	t.Helper()
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// latestVersion — user_version kỳ vọng sau migrate đầy đủ = số file migration.
// Suy ra từ FS thay vì hằng số để không phải sửa test mỗi lần thêm migration.
func latestVersion(t *testing.T) int {
	t.Helper()
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatalf("đọc migrations: %v", err)
	}
	return len(entries)
}

// BUG-4: not_before phải làm tròn LÊN giây — job không bao giờ tới hạn SỚM hơn
// mốc đã hẹn (trước đây Truncate xuống làm retryAfter dưới 1s vô nghĩa).
func TestNotBeforeRoundsUp(t *testing.T) {
	base := func(s string) time.Time {
		ts, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatal(err)
		}
		return ts
	}
	cases := []struct {
		in, want string
	}{
		{"2026-08-08T10:00:00Z", "2026-08-08T10:00:00Z"},        // đúng mốc giây → giữ nguyên
		{"2026-08-08T10:00:00.001Z", "2026-08-08T10:00:01Z"},    // dư 1ms → lên giây kế
		{"2026-08-08T10:00:00.9Z", "2026-08-08T10:00:01Z"},      // dư 900ms → lên giây kế
		{"2026-08-08T10:00:59.5Z", "2026-08-08T10:01:00Z"},      // vắt qua phút
		{"2026-08-08T12:00:00.5+02:00", "2026-08-08T10:00:01Z"}, // đổi về UTC rồi mới tròn lên
	}
	for _, c := range cases {
		if got := formatSecondCeil(base(c.in)); got != c.want {
			t.Errorf("formatSecondCeil(%s) = %s, muốn %s", c.in, got, c.want)
		}
	}

	// retryAfter > 0 → mốc trả về không được sớm hơn now+retryAfter.
	got := retryNotBefore(900 * time.Millisecond)
	floor := time.Now().Add(900 * time.Millisecond).UTC().Truncate(time.Second)
	parsed, err := time.Parse(time.RFC3339, got)
	if err != nil {
		t.Fatalf("retryNotBefore trả %q không phải RFC3339 giây: %v", got, err)
	}
	if parsed.Before(floor) {
		t.Errorf("retryNotBefore(900ms) = %s, sớm hơn mốc yêu cầu (>= %s)", got, floor.Format(time.RFC3339))
	}
	// retryAfter = 0 nghĩa "chạy lại ngay" → mốc phải đã tới hạn.
	if now := nowSecond(); retryNotBefore(0) > now {
		t.Errorf("retryNotBefore(0) = %s > now %s — job retry ngay bị hoãn", retryNotBefore(0), now)
	}
}

func TestMigrateCreatesTables(t *testing.T) {
	st := openTestStore(t)
	for _, table := range []string{"apps", "settings", "events", "jobs", "secrets"} {
		var name string
		err := st.db.QueryRow(
			`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
		if err != nil {
			t.Errorf("bảng %s không tồn tại: %v", table, err)
		}
	}
	var version int
	if err := st.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatalf("user_version: %v", err)
	}
	if want := latestVersion(t); version != want {
		t.Errorf("user_version = %d, muốn %d", version, want)
	}
}

func TestAppRoundtrip(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	app := &App{ID: "app-1", Slug: "hello", Desired: json.RawMessage(`{"image":"nginx:1"}`)}
	if err := st.CreateApp(ctx, app); err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
	if app.DesiredRev != 1 {
		t.Errorf("DesiredRev sau create = %d, muốn 1", app.DesiredRev)
	}

	got, err := st.GetApp(ctx, "app-1")
	if err != nil {
		t.Fatalf("GetApp: %v", err)
	}
	if got.ID != "app-1" || got.Slug != "hello" || string(got.Desired) != `{"image":"nginx:1"}` {
		t.Errorf("GetApp roundtrip sai: %+v", got)
	}
	if got.DesiredRev != 1 || got.AppliedRev != 0 || got.Status != nil {
		t.Errorf("GetApp default rev/status sai: %+v", got)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("timestamps rỗng")
	}

	rev, err := st.UpdateDesired(ctx, "app-1", json.RawMessage(`{"image":"nginx:2"}`))
	if err != nil {
		t.Fatalf("UpdateDesired: %v", err)
	}
	if rev != 2 {
		t.Errorf("UpdateDesired rev = %d, muốn 2", rev)
	}

	if _, err := st.GetApp(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetApp missing: muốn ErrNotFound, nhận %v", err)
	}
	if err := st.CreateApp(ctx, &App{ID: "app-2", Slug: "hello", Desired: json.RawMessage(`{}`)}); !errors.Is(err, ErrConflict) {
		t.Errorf("CreateApp slug trùng: muốn ErrConflict, nhận %v", err)
	}
}

func TestSettings(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	if _, err := st.GetSetting(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetSetting missing: muốn ErrNotFound, nhận %v", err)
	}
	if err := st.SetSetting(ctx, "k", "v1"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if err := st.SetSetting(ctx, "k", "v2"); err != nil {
		t.Fatalf("SetSetting upsert: %v", err)
	}
	v, err := st.GetSetting(ctx, "k")
	if err != nil || v != "v2" {
		t.Errorf("GetSetting = (%q, %v), muốn (v2, nil)", v, err)
	}
}

// ST-03: secret không bao giờ nằm plaintext trên đĩa.
func TestSecretsNotPlaintextOnDisk(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	const plaintext = "XYZZY-supersecret-7f3a"
	if err := st.PutSecret(context.Background(), "test/secret", []byte(plaintext)); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	// Close trước khi đọc raw — checkpoint WAL về file chính.
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(dir, "platform.db*"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("Glob platform.db* = (%v, %v), muốn ≥1 file", matches, err)
	}
	for _, f := range matches {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", f, err)
		}
		if bytes.Contains(raw, []byte(plaintext)) {
			t.Errorf("file %s chứa secret dạng plaintext", f)
		}
	}
}

func TestMasterKeyCreated(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "platform.db")
	keyPath := filepath.Join(dir, "keys", "master.key")

	st, err := Open(dbPath, keyPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("master.key không được tạo: %v", err)
	}
	if info.Size() != 32 {
		t.Errorf("master.key = %d byte, muốn 32", info.Size())
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("master.key perm = %o, muốn 0600", perm)
		}
	}

	ctx := context.Background()
	if err := st.PutSecret(ctx, "boot/token", []byte("round-trip-me")); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Open lần 2 — nạp lại key cũ, giải mã được secret đã ghi.
	st2, err := Open(dbPath, keyPath)
	if err != nil {
		t.Fatalf("Open lần 2: %v", err)
	}
	defer st2.Close()
	got, err := st2.GetSecret(ctx, "boot/token")
	if err != nil || string(got) != "round-trip-me" {
		t.Errorf("GetSecret sau reopen = (%q, %v), muốn round-trip-me", got, err)
	}
}

func TestMasterKeyWrongSize(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "master.key")
	if err := os.WriteFile(keyPath, []byte("too-short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(dir, "platform.db"), keyPath); err == nil {
		t.Error("Open với master key sai độ dài: muốn error, nhận nil")
	}
}

func openRawDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "raw.db")))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

// TestMigrate0002: DB đang ở version 1 (chỉ 0001) → migrate() nâng lên 2,
// có bảng secrets + 2 cột mới trong jobs.
func TestMigrate0002(t *testing.T) {
	db := openRawDB(t)

	ddl, err := migrationsFS.ReadFile("migrations/0001_init.sql")
	if err != nil {
		t.Fatalf("đọc 0001: %v", err)
	}
	if _, err := db.Exec(string(ddl)); err != nil {
		t.Fatalf("exec 0001: %v", err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 1`); err != nil {
		t.Fatalf("set user_version: %v", err)
	}

	if err := migrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var version int
	err = db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if want := latestVersion(t); err != nil || version != want {
		t.Errorf("user_version = (%d, %v), muốn %d", version, err, want)
	}
	var name string
	if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='secrets'`).Scan(&name); err != nil {
		t.Errorf("bảng secrets không tồn tại: %v", err)
	}
	cols := map[string]bool{}
	rows, err := db.Query(`SELECT name FROM pragma_table_info('jobs')`)
	if err != nil {
		t.Fatalf("table_info(jobs): %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		cols[c] = true
	}
	if !cols["result"] || !cols["last_error"] {
		t.Errorf("jobs thiếu cột mới, có: %v", cols)
	}
}

// TestMigrateRollback: migration SQL hỏng → lỗi, user_version giữ nguyên,
// thay đổi dở dang trong file hỏng bị rollback.
func TestMigrateRollback(t *testing.T) {
	db := openRawDB(t)

	good := fstest.MapFS{
		"migrations/0001_init.sql": &fstest.MapFile{Data: []byte(`CREATE TABLE t1 (id INTEGER PRIMARY KEY);`)},
	}
	if err := migrateFS(db, good, "migrations"); err != nil {
		t.Fatalf("migrateFS 0001: %v", err)
	}

	bad := fstest.MapFS{
		"migrations/0001_init.sql": good["migrations/0001_init.sql"],
		"migrations/0002_bad.sql": &fstest.MapFile{
			Data: []byte("CREATE TABLE t2 (id INTEGER PRIMARY KEY);\nTHIS IS NOT VALID SQL;"),
		},
	}
	if err := migrateFS(db, bad, "migrations"); err == nil {
		t.Fatal("migrateFS với SQL hỏng: muốn error, nhận nil")
	}

	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 1 {
		t.Errorf("user_version sau rollback = (%d, %v), muốn giữ 1", version, err)
	}
	var name string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='t2'`).Scan(&name)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("bảng t2 phải bị rollback, nhận err=%v", err)
	}
}
