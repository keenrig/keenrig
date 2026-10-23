package store

// Test ĐỐI KHÁNG do AGENT TESTER (vòng 2) viết — KHÔNG phải test của Coder.
// Mục tiêu: cố tình phá các bất biến của T4 (ST-01, ST-03, jobs, keystore,
// migration, concurrency) thay vì chỉ đi theo happy path.
// Đặt tên hàm/helper prefix "Tester"/"tadv" để không đụng test sẵn có.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// tadvPaths trả (dir, dbPath, keyPath) cho 1 store tạm.
func tadvPaths(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	return dir, filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key")
}

// tadvOpen mở store mới trong thư mục tạm, trả store + thư mục.
func tadvOpen(t *testing.T) (*SQLite, string) {
	t.Helper()
	dir, dbPath, keyPath := tadvPaths(t)
	st, err := Open(dbPath, keyPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st, dir
}

// tadvRawDB mở kết nối SQL thô tới file DB (để nghịch trực tiếp bảng).
func tadvRawDB(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath)+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("mở raw DB: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

func tadvCreateApp(t *testing.T, st *SQLite, id string) *App {
	t.Helper()
	app := &App{ID: id, Slug: id, Desired: json.RawMessage(`{"image":"traefik/whoami:v1.10"}`)}
	if err := st.CreateApp(context.Background(), app); err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
	return app
}

// ---------------------------------------------------------------------------
// ST-01 — SetStatus không được cho applied_rev vượt desired_rev
// ---------------------------------------------------------------------------

// TesterST01AppliedRevAboveDesiredIsConflict: app tồn tại, desired_rev=1.
// SetStatus với appliedRev 2/3/99 (đều > desired_rev) PHẢI trả đúng ErrConflict
// — không được là nil (ghi lụi) và không được là ErrNotFound (nhầm loại lỗi).
func TestAdvST01AppliedRevAboveDesiredIsConflict(t *testing.T) {
	st, _ := tadvOpen(t)
	ctx := context.Background()
	tadvCreateApp(t, st, "app-st01")

	status := json.RawMessage(`{"state":"running"}`)

	for _, rev := range []int64{2, 3, 99} {
		err := st.SetStatus(ctx, "app-st01", status, rev)
		if !errors.Is(err, ErrConflict) {
			t.Errorf("SetStatus(appliedRev=%d) với desired_rev=1 → %v, MUỐN ErrConflict", rev, err)
		}
		// Bất biến: applied_rev trong DB không được nhích lên.
		app, gerr := st.GetApp(ctx, "app-st01")
		if gerr != nil {
			t.Fatalf("GetApp: %v", gerr)
		}
		if app.AppliedRev != 0 {
			t.Fatalf("applied_rev = %d sau SetStatus bị từ chối, MUỐN giữ 0", app.AppliedRev)
		}
	}

	// Ranh giới: appliedRev == desired_rev phải OK.
	if err := st.SetStatus(ctx, "app-st01", status, 1); err != nil {
		t.Errorf("SetStatus(appliedRev=1) với desired_rev=1 → %v, muốn nil", err)
	}

	// App không tồn tại → ErrNotFound, KHÔNG phải ErrConflict (phân biệt đúng loại).
	if err := st.SetStatus(ctx, "khong-ton-tai", status, 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetStatus app lạ → %v, MUỐN ErrNotFound", err)
	}
	// App không tồn tại + rev vượt → vẫn phải là ErrNotFound.
	if err := st.SetStatus(ctx, "khong-ton-tai", status, 999); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetStatus app lạ rev 999 → %v, MUỐN ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// ST-03 — secret KHÔNG được nằm plaintext trên đĩa (mọi file trong data dir)
// ---------------------------------------------------------------------------

// tadvScanDirForPlaintext quét MỌI file thường trong dir, trả danh sách
// "file: needle" cho mỗi lần bắt được plaintext.
func tadvScanDirForPlaintext(t *testing.T, dir string, needles [][]byte) []string {
	t.Helper()
	var hits []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", dir, err)
	}
	scanned := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("đọc %s: %v", p, err)
		}
		scanned++
		for _, n := range needles {
			if bytes.Contains(raw, n) {
				hits = append(hits, fmt.Sprintf("%s chứa %q", e.Name(), n))
			}
		}
	}
	if scanned == 0 {
		t.Fatalf("không quét được file nào trong %s — test vô nghĩa", dir)
	}
	t.Logf("đã quét %d file trong data dir: %s", scanned, dir)
	return hits
}

// TesterST03SecretNeverPlaintextOnDiskStrict — bản NGHIÊM NGẶT của ST-03:
// quét TẤT CẢ file trong data dir (platform.db, -wal, -shm, master.key), không
// chỉ platform.db*. Kiểm 2 kịch bản: 1 secret, và 200 secret rồi mới Close
// (WAL to hơn, dễ lộ hơn).
func TestAdvST03SecretNeverPlaintextOnDiskStrict(t *testing.T) {
	ctx := context.Background()

	t.Run("MotSecret", func(t *testing.T) {
		dir, dbPath, keyPath := tadvPaths(t)
		st, err := Open(dbPath, keyPath)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		secret := []byte("XYZZY-TESTER-ADVERSARIAL-0f3a91-supersecret")
		if err := st.PutSecret(ctx, "tester/one", secret); err != nil {
			t.Fatalf("PutSecret: %v", err)
		}
		// Bắt buộc Close trước khi đọc raw — WAL chưa checkpoint = false-pass.
		if err := st.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if hits := tadvScanDirForPlaintext(t, dir, [][]byte{secret}); len(hits) > 0 {
			t.Errorf("ST-03 VI PHẠM — secret nằm plaintext trên đĩa: %v", hits)
		}
	})

	t.Run("HaiTramSecret", func(t *testing.T) {
		dir, dbPath, keyPath := tadvPaths(t)
		st, err := Open(dbPath, keyPath)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		needles := make([][]byte, 0, 200)
		for i := 0; i < 200; i++ {
			s := []byte(fmt.Sprintf("XYZZY-BULK-%03d-7c1d5e-supersecret", i))
			needles = append(needles, s)
			if err := st.PutSecret(ctx, fmt.Sprintf("tester/bulk/%d", i), s); err != nil {
				t.Fatalf("PutSecret %d: %v", i, err)
			}
		}
		// Đọc lại vài cái trước khi Close để chắc là dữ liệu thật, không phải no-op.
		for _, i := range []int{0, 99, 199} {
			got, err := st.GetSecret(ctx, fmt.Sprintf("tester/bulk/%d", i))
			if err != nil {
				t.Fatalf("GetSecret %d: %v", i, err)
			}
			if !bytes.Equal(got, needles[i]) {
				t.Fatalf("GetSecret %d = %q, muốn %q", i, got, needles[i])
			}
		}
		if err := st.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if hits := tadvScanDirForPlaintext(t, dir, needles); len(hits) > 0 {
			t.Errorf("ST-03 VI PHẠM (%d lần) — ví dụ: %v", len(hits), hits[:min(3, len(hits))])
		}
	})
}

// ---------------------------------------------------------------------------
// Keystore — chống hỏng dữ liệu / key sai
// ---------------------------------------------------------------------------

// TesterKeystoreTamperedCiphertextFails: sửa 1 byte ciphertext THẲNG trong SQL
// → GetSecret phải trả LỖI (GCM auth fail), tuyệt đối không trả rác và không panic.
func TestAdvKeystoreTamperedCiphertextFails(t *testing.T) {
	ctx := context.Background()
	dir, dbPath, keyPath := tadvPaths(t)
	_ = dir

	st, err := Open(dbPath, keyPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	secret := []byte("plaintext-can-bao-ve-abc123")
	if err := st.PutSecret(ctx, "tester/tamper", secret); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Lật 1 bit ở byte cuối (nằm trong GCM tag) qua SQL thô.
	raw := tadvRawDB(t, dbPath)
	var blob []byte
	if err := raw.QueryRow(`SELECT ciphertext FROM secrets WHERE ref = ?`, "tester/tamper").Scan(&blob); err != nil {
		t.Fatalf("đọc ciphertext: %v", err)
	}
	if len(blob) < 13 {
		t.Fatalf("blob chỉ %d byte — không phải nonce(12)||ciphertext", len(blob))
	}
	if bytes.Contains(blob, secret) {
		t.Fatalf("ciphertext chứa nguyên plaintext — keystore không mã hoá gì cả")
	}

	for _, tc := range []struct {
		name  string
		mutFn func(b []byte) []byte
	}{
		{"LatBitByteCuoi", func(b []byte) []byte { c := append([]byte(nil), b...); c[len(c)-1] ^= 0x01; return c }},
		{"LatBitTrongNonce", func(b []byte) []byte { c := append([]byte(nil), b...); c[0] ^= 0xFF; return c }},
		{"CatNgan", func(b []byte) []byte { return append([]byte(nil), b[:5]...) }},
		{"Rong", func(b []byte) []byte { return []byte{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := raw.Exec(`UPDATE secrets SET ciphertext = ? WHERE ref = ?`, tc.mutFn(blob), "tester/tamper"); err != nil {
				t.Fatalf("UPDATE ciphertext: %v", err)
			}
			st2, err := Open(dbPath, keyPath)
			if err != nil {
				t.Fatalf("Open lần 2: %v", err)
			}
			defer st2.Close()

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("GetSecret PANIC trên ciphertext hỏng: %v", r)
				}
			}()
			got, err := st2.GetSecret(ctx, "tester/tamper")
			if err == nil {
				t.Fatalf("GetSecret trên ciphertext hỏng trả nil error + %q — MUỐN lỗi", got)
			}
			if got != nil {
				t.Errorf("GetSecret lỗi nhưng vẫn trả %d byte dữ liệu (muốn nil)", len(got))
			}
		})
	}
}

// TesterMasterKeyBadLengthOpenFails: master.key sai độ dài (10 byte, 0 byte,
// 33 byte) → Open phải lỗi rõ ràng, không panic, không im lặng sinh key mới.
func TestAdvMasterKeyBadLengthOpenFails(t *testing.T) {
	for _, n := range []int{0, 1, 10, 31, 33, 64} {
		t.Run(fmt.Sprintf("%dByte", n), func(t *testing.T) {
			_, dbPath, keyPath := tadvPaths(t)
			if err := os.WriteFile(keyPath, bytes.Repeat([]byte("k"), n), 0o600); err != nil {
				t.Fatalf("ghi master.key: %v", err)
			}
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Open PANIC với master.key %d byte: %v", n, r)
				}
			}()
			st, err := Open(dbPath, keyPath)
			if err == nil {
				st.Close()
				t.Fatalf("Open với master.key %d byte trả nil error — MUỐN lỗi", n)
			}
			if !strings.Contains(err.Error(), "master key") && !strings.Contains(err.Error(), "keystore") {
				t.Errorf("thông báo lỗi %q không nhắc master key/keystore — khó chẩn đoán", err)
			}
			// Key sai KHÔNG được bị ghi đè im lặng.
			if b, rerr := os.ReadFile(keyPath); rerr == nil && len(b) != n {
				t.Errorf("Open đã ghi đè master.key hỏng (%d → %d byte) — mất dữ liệu", n, len(b))
			}
		})
	}
}

// TesterSecretDecryptFailsWithDifferentMasterKey: đổi master.key → secret cũ
// KHÔNG được giải mã ra (phải lỗi), tức là secret thật sự phụ thuộc key.
func TestAdvSecretDecryptFailsWithDifferentMasterKey(t *testing.T) {
	ctx := context.Background()
	_, dbPath, keyPath := tadvPaths(t)

	st, err := Open(dbPath, keyPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st.PutSecret(ctx, "tester/keyswap", []byte("noi-dung-mat")); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	st.Close()

	// Thay master.key bằng key 32 byte KHÁC.
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte("Z"), 32), 0o600); err != nil {
		t.Fatalf("ghi master.key mới: %v", err)
	}
	st2, err := Open(dbPath, keyPath)
	if err != nil {
		t.Fatalf("Open với key mới: %v", err)
	}
	defer st2.Close()
	got, err := st2.GetSecret(ctx, "tester/keyswap")
	if err == nil {
		t.Errorf("GetSecret với master.key khác trả nil error + %q — MUỐN lỗi giải mã", got)
	}
}

// ---------------------------------------------------------------------------
// Jobs — not_before, lọc kind, MaxJobAttempts
// ---------------------------------------------------------------------------

// TesterJobsNotBeforeGate: notBefore tương lai → ErrNoJob; notBefore quá khứ →
// claim được. Đồng thời kiểm cột not_before ghi đúng RFC3339 GIÂY (không Nano)
// — spec §6.4 cảnh báo Nano phá so sánh chuỗi, gây flaky.
func TestAdvJobsNotBeforeGate(t *testing.T) {
	ctx := context.Background()
	_, dbPath, keyPath := tadvPaths(t)
	st, err := Open(dbPath, keyPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	future := time.Now().Add(2 * time.Hour)
	past := time.Now().Add(-2 * time.Hour)

	futureID, err := st.EnqueueJob(ctx, "deploy", json.RawMessage(`{"a":1}`), &future)
	if err != nil {
		t.Fatalf("EnqueueJob future: %v", err)
	}
	// Chỉ có job tương lai → không claim được.
	if job, err := st.ClaimJob(ctx, nil); !errors.Is(err, ErrNoJob) {
		t.Fatalf("ClaimJob khi chỉ có job tương lai → (%+v, %v), MUỐN ErrNoJob", job, err)
	}

	pastID, err := st.EnqueueJob(ctx, "deploy", nil, &past)
	if err != nil {
		t.Fatalf("EnqueueJob past: %v", err)
	}
	job, err := st.ClaimJob(ctx, nil)
	if err != nil {
		t.Fatalf("ClaimJob job quá hạn: %v", err)
	}
	if job.ID != pastID {
		t.Errorf("claim job id %d, muốn %d (job đến hạn)", job.ID, pastID)
	}
	if job.State != "running" {
		t.Errorf("job.State = %q, muốn running", job.State)
	}
	// Job tương lai vẫn không claim được.
	if _, err := st.ClaimJob(ctx, nil); !errors.Is(err, ErrNoJob) {
		t.Errorf("job tương lai id %d bị claim sớm", futureID)
	}

	// Định dạng cột not_before phải là RFC3339 giây UTC fixed-width.
	raw := tadvRawDB(t, dbPath)
	rows, err := raw.Query(`SELECT id, not_before FROM jobs WHERE not_before IS NOT NULL`)
	if err != nil {
		t.Fatalf("query not_before: %v", err)
	}
	defer rows.Close()
	re := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
	n := 0
	for rows.Next() {
		var id int64
		var nb string
		if err := rows.Scan(&id, &nb); err != nil {
			t.Fatalf("scan: %v", err)
		}
		n++
		if !re.MatchString(nb) {
			t.Errorf("job %d: not_before = %q KHÔNG phải RFC3339 giây UTC (spec §6.4 — Nano gây flaky)", id, nb)
		}
	}
	if n == 0 {
		t.Fatal("không có row not_before nào để kiểm — test vô nghĩa")
	}
}

// TesterJobsKindFilter: ClaimJob với kinds lọc sai kind → ErrNoJob;
// đúng kind → claim được đúng job đó.
func TestAdvJobsKindFilter(t *testing.T) {
	ctx := context.Background()
	st, _ := tadvOpen(t)

	deployID, err := st.EnqueueJob(ctx, "deploy", nil, nil)
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}

	if job, err := st.ClaimJob(ctx, []string{"backup"}); !errors.Is(err, ErrNoJob) {
		t.Errorf("ClaimJob(kinds=[backup]) khi chỉ có job deploy → (%+v, %v), MUỐN ErrNoJob", job, err)
	}
	if job, err := st.ClaimJob(ctx, []string{"backup", "restore", "gc"}); !errors.Is(err, ErrNoJob) {
		t.Errorf("ClaimJob(3 kind không khớp) → (%+v, %v), MUỐN ErrNoJob", job, err)
	}
	job, err := st.ClaimJob(ctx, []string{"backup", "deploy"})
	if err != nil {
		t.Fatalf("ClaimJob(kinds có deploy): %v", err)
	}
	if job.ID != deployID || job.Kind != "deploy" {
		t.Errorf("claim = id %d kind %q, muốn id %d kind deploy", job.ID, job.Kind, deployID)
	}
}

// TesterJobsFailFiveTimesBecomesFailed: FailJob đủ MaxJobAttempts → state=failed
// và KHÔNG bao giờ claim lại được nữa (không loop vô hạn).
func TestAdvJobsFailFiveTimesBecomesFailed(t *testing.T) {
	ctx := context.Background()
	_, dbPath, keyPath := tadvPaths(t)
	st, err := Open(dbPath, keyPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	id, err := st.EnqueueJob(ctx, "deploy", nil, nil)
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}

	raw := tadvRawDB(t, dbPath)
	readJob := func() (string, int) {
		t.Helper()
		var state string
		var attempt int
		if err := raw.QueryRow(`SELECT state, attempt FROM jobs WHERE id = ?`, id).Scan(&state, &attempt); err != nil {
			t.Fatalf("đọc job: %v", err)
		}
		return state, attempt
	}

	for i := 1; i <= MaxJobAttempts; i++ {
		job, err := st.ClaimJob(ctx, nil)
		if err != nil {
			t.Fatalf("lần %d: ClaimJob: %v", i, err)
		}
		if job.ID != id {
			t.Fatalf("lần %d: claim id %d, muốn %d", i, job.ID, id)
		}
		// retryAfter = 0 để claim lại được ngay ở vòng sau.
		if err := st.FailJob(ctx, id, fmt.Sprintf("loi lan %d", i), 0); err != nil {
			t.Fatalf("lần %d: FailJob: %v", i, err)
		}
		state, attempt := readJob()
		if attempt != i {
			t.Errorf("sau fail lần %d: attempt = %d, muốn %d", i, attempt, i)
		}
		wantState := "queued"
		if i >= MaxJobAttempts {
			wantState = "failed"
		}
		if state != wantState {
			t.Errorf("sau fail lần %d: state = %q, muốn %q", i, state, wantState)
		}
	}

	// Đã 'failed' → không được claim lại, dù thử nhiều lần.
	for i := 0; i < 3; i++ {
		if job, err := st.ClaimJob(ctx, nil); !errors.Is(err, ErrNoJob) {
			t.Fatalf("job đã failed vẫn claim lại được: (%+v, %v) — vòng lặp vô hạn", job, err)
		}
	}

	var lastErr string
	if err := raw.QueryRow(`SELECT last_error FROM jobs WHERE id = ?`, id).Scan(&lastErr); err != nil {
		t.Fatalf("đọc last_error: %v", err)
	}
	if !strings.Contains(lastErr, "loi lan 5") {
		t.Errorf("last_error = %q, muốn chứa lỗi lần cuối", lastErr)
	}
}

// ---------------------------------------------------------------------------
// Concurrency (không cần -race: kiểm bất biến logic, không kiểm data race)
// ---------------------------------------------------------------------------

// TesterConcurrentClaimNoDoubleClaim: 8 goroutine cùng ClaimJob trên 5 job →
// tổng claim thành công đúng 5, không job nào bị claim 2 lần.
func TestAdvConcurrentClaimNoDoubleClaim(t *testing.T) {
	ctx := context.Background()
	st, _ := tadvOpen(t)

	const nJobs, nWorkers = 5, 8
	for i := 0; i < nJobs; i++ {
		if _, err := st.EnqueueJob(ctx, "deploy", nil, nil); err != nil {
			t.Fatalf("EnqueueJob %d: %v", i, err)
		}
	}

	var (
		mu      sync.Mutex
		claimed []int64
		otherEr []error
	)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < nWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for {
				job, err := st.ClaimJob(ctx, nil)
				if errors.Is(err, ErrNoJob) {
					return
				}
				if err != nil {
					mu.Lock()
					otherEr = append(otherEr, err)
					mu.Unlock()
					return
				}
				mu.Lock()
				claimed = append(claimed, job.ID)
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(otherEr) > 0 {
		t.Errorf("ClaimJob trả lỗi lạ khi chạy song song: %v", otherEr)
	}
	if len(claimed) != nJobs {
		t.Errorf("tổng claim thành công = %d, MUỐN đúng %d", len(claimed), nJobs)
	}
	seen := map[int64]int{}
	for _, id := range claimed {
		seen[id]++
	}
	for id, c := range seen {
		if c != 1 {
			t.Errorf("job %d bị claim %d lần — MẤT tính atomic (ST-05)", id, c)
		}
	}
	if len(seen) != nJobs {
		t.Errorf("số job DISTINCT được claim = %d, muốn %d", len(seen), nJobs)
	}
}

// TesterConcurrentUpdateDesiredNoLostUpdate: 4 goroutine UpdateDesired song song
// trên cùng app (desired_rev khởi đầu 1) → rev cuối phải đúng 5 và 4 rev trả về
// phải phân biệt {2,3,4,5} — không mất update, không trùng rev.
func TestAdvConcurrentUpdateDesiredNoLostUpdate(t *testing.T) {
	ctx := context.Background()
	st, _ := tadvOpen(t)
	tadvCreateApp(t, st, "app-conc-rev")

	const nWriters = 4
	revs := make([]int64, nWriters)
	errs := make([]error, nWriters)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < nWriters; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			desired := json.RawMessage(fmt.Sprintf(`{"image":"traefik/whoami:v1.10","env":{"W":"%d"}}`, i))
			revs[i], errs[i] = st.UpdateDesired(ctx, "app-conc-rev", desired)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("writer %d: UpdateDesired: %v", i, err)
		}
	}
	seen := map[int64]int{}
	for _, r := range revs {
		seen[r]++
	}
	for r, c := range seen {
		if c != 1 {
			t.Errorf("rev %d bị trả %d lần — LOST UPDATE (ST-02)", r, c)
		}
	}
	for want := int64(2); want <= 1+nWriters; want++ {
		if seen[want] != 1 {
			t.Errorf("thiếu rev %d trong tập rev trả về %v", want, revs)
		}
	}
	app, err := st.GetApp(ctx, "app-conc-rev")
	if err != nil {
		t.Fatalf("GetApp: %v", err)
	}
	if app.DesiredRev != 1+nWriters {
		t.Errorf("desired_rev cuối = %d, MUỐN %d (1 + %d lần update)", app.DesiredRev, 1+nWriters, nWriters)
	}
}

// ---------------------------------------------------------------------------
// Migration — idempotent + nâng cấp DB M0 cũ
// ---------------------------------------------------------------------------

// TesterMigrateFromM0DBAndIdempotent: dựng DB "M0 cũ" bằng cách chạy CHỈ 0001
// (+ user_version=1), rồi migrate đầy đủ → user_version = migration mới nhất,
// dữ liệu M0 còn nguyên. Sau đó Open 3 lần liên tiếp → idempotent, không lỗi,
// version giữ nguyên.
func TestAdvMigrateFromM0DBAndIdempotent(t *testing.T) {
	ctx := context.Background()
	_, dbPath, keyPath := tadvPaths(t)

	// --- dựng DB M0: chỉ migration 0001 ---
	raw := tadvRawDB(t, dbPath)
	ddl, err := migrationsFS.ReadFile("migrations/0001_init.sql")
	if err != nil {
		t.Fatalf("đọc 0001: %v", err)
	}
	if _, err := raw.Exec(string(ddl)); err != nil {
		t.Fatalf("exec 0001: %v", err)
	}
	if _, err := raw.Exec(`PRAGMA user_version = 1`); err != nil {
		t.Fatalf("set user_version=1: %v", err)
	}
	// Dữ liệu M0 có sẵn phải sống sót qua migration.
	if _, err := raw.Exec(
		`INSERT INTO apps (id, slug, desired, desired_rev, applied_rev, created_at, updated_at)
		 VALUES ('m0-app','m0-app','{"image":"traefik/whoami:v1.10"}',1,0,?,?)`,
		time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert app M0: %v", err)
	}
	var v int
	if err := raw.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != 1 {
		t.Fatalf("DB M0 dựng sai: user_version=%d err=%v", v, err)
	}

	// --- Open (chạy migrate đầy đủ) 3 lần liên tiếp ---
	for i := 1; i <= 3; i++ {
		st, err := Open(dbPath, keyPath)
		if err != nil {
			t.Fatalf("Open lần %d trên DB M0: %v", i, err)
		}
		var uv int
		if err := raw.QueryRow(`PRAGMA user_version`).Scan(&uv); err != nil {
			t.Fatalf("đọc user_version lần %d: %v", i, err)
		}
		// Kỳ vọng = số file migration (helper latestVersion ở sqlite_test.go),
		// không phải hằng số cứng — thêm migration mới không làm test này lỗi thời.
		if want := latestVersion(t); uv != want {
			t.Errorf("sau Open lần %d: user_version = %d, MUỐN %d", i, uv, want)
		}
		// App M0 cũ phải còn nguyên.
		app, err := st.GetApp(ctx, "m0-app")
		if err != nil {
			t.Fatalf("lần %d: app M0 mất sau migration: %v", i, err)
		}
		if app.DesiredRev != 1 {
			t.Errorf("lần %d: app M0 desired_rev = %d, muốn 1", i, app.DesiredRev)
		}
		// Bảng/cột mới của 0002 phải dùng được.
		if err := st.PutSecret(ctx, fmt.Sprintf("tester/mig/%d", i), []byte("v")); err != nil {
			t.Errorf("lần %d: PutSecret sau migrate: %v", i, err)
		}
		jobID, err := st.EnqueueJob(ctx, "deploy", nil, nil)
		if err != nil {
			t.Fatalf("lần %d: EnqueueJob: %v", i, err)
		}
		if err := st.FailJob(ctx, jobID, "kiem tra cot last_error", time.Hour); err != nil {
			t.Errorf("lần %d: FailJob (cột last_error): %v", i, err)
		}
		st.Close()
	}

	// Cột 0002 tồn tại thật.
	for _, col := range []string{"result", "last_error"} {
		var cnt int
		if err := raw.QueryRow(
			`SELECT COUNT(*) FROM pragma_table_info('jobs') WHERE name = ?`, col).Scan(&cnt); err != nil {
			t.Fatalf("pragma_table_info: %v", err)
		}
		if cnt != 1 {
			t.Errorf("bảng jobs thiếu cột %q sau migration 0002", col)
		}
	}
}
