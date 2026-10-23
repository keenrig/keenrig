package store

// Test đối kháng vòng 2 — AGENT TESTER. Không sửa code sản phẩm, chỉ ép
// store vào các đường biên mà conformance suite không chạm tới:
// ST-01 (guard rev), ST-03 (secret không plaintext + chống giả mạo ciphertext),
// keystore mất master.key, jobs retry/kind filter, cạm bẫy §6.4 (not_before
// RFC3339 giây), và concurrency đếm được (máy chấm không có cgo → không -race).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func advR2Open(t *testing.T) (*SQLite, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st, dir
}

func advR2CreateApp(t *testing.T, st *SQLite, id, slug string) *App {
	t.Helper()
	app := &App{ID: id, Slug: slug, Desired: json.RawMessage(`{"image":"nginx:1"}`)}
	if err := st.CreateApp(context.Background(), app); err != nil {
		t.Fatalf("CreateApp(%s): %v", id, err)
	}
	return app
}

// ---------- ST-01: guard applied_rev ----------

// TestAdvR2SetStatusGuards ép SetStatus qua mọi biên của appliedRev và
// UpdateDesired trên id không tồn tại. Bất biến PHẢI giữ: applied_rev không
// bao giờ vượt desired_rev.
func TestAdvR2SetStatusGuards(t *testing.T) {
	st, _ := advR2Open(t)
	ctx := context.Background()
	advR2CreateApp(t, st, "app-1", "hello") // desired_rev = 1

	status := json.RawMessage(`{"state":"running"}`)

	// appliedRev = desired_rev → OK.
	if err := st.SetStatus(ctx, "app-1", status, 1); err != nil {
		t.Fatalf("SetStatus applied=1 (== desired): %v", err)
	}
	// appliedRev > desired_rev → ErrConflict, không ghi gì.
	for _, bad := range []int64{2, 3, 1 << 40} {
		if err := st.SetStatus(ctx, "app-1", status, bad); !errors.Is(err, ErrConflict) {
			t.Errorf("SetStatus applied=%d > desired=1: muốn ErrConflict, nhận %v", bad, err)
		}
		if got := advR2Get(t, st, "app-1").AppliedRev; got != 1 {
			t.Fatalf("applied_rev bị ghi = %d sau conflict, muốn giữ 1", got)
		}
	}

	// appliedRev = 0 → hợp lệ (app chưa apply lần nào).
	if err := st.SetStatus(ctx, "app-1", status, 0); err != nil {
		t.Errorf("SetStatus applied=0: muốn nil, nhận %v", err)
	}

	// appliedRev ÂM: guard hiện tại là `desired_rev >= appliedRev` nên số âm
	// LỌT. Ghi nhận hành vi thực tế + chốt bất biến applied <= desired.
	errNeg := st.SetStatus(ctx, "app-1", status, -5)
	appNeg := advR2Get(t, st, "app-1")
	t.Logf("QUAN SÁT: SetStatus(applied=-5) trả %v, applied_rev sau đó = %d", errNeg, appNeg.AppliedRev)
	if appNeg.AppliedRev > appNeg.DesiredRev {
		t.Errorf("BẤT BIẾN VỠ: applied_rev %d > desired_rev %d", appNeg.AppliedRev, appNeg.DesiredRev)
	}
	if errNeg == nil && appNeg.AppliedRev < 0 {
		t.Logf("LỖ HỔNG (minor): applied_rev âm được chấp nhận — app rơi lại vào " +
			"ListAppsNeedingReconcile vĩnh viễn; nên chặn appliedRev < 0")
	}

	// SetStatus / UpdateDesired trên id không tồn tại → ErrNotFound.
	if err := st.SetStatus(ctx, "khong-ton-tai", status, 0); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetStatus id lạ: muốn ErrNotFound, nhận %v", err)
	}
	if _, err := st.UpdateDesired(ctx, "khong-ton-tai", json.RawMessage(`{}`)); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateDesired id lạ: muốn ErrNotFound, nhận %v", err)
	}
}

func advR2Get(t *testing.T, st *SQLite, id string) *App {
	t.Helper()
	app, err := st.GetApp(context.Background(), id)
	if err != nil {
		t.Fatalf("GetApp(%s): %v", id, err)
	}
	return app
}

// ---------- ST-03 nghiêm ngặt ----------

// TestAdvR2SecretsNeverPlaintextMulti: NHIỀU secret khác nhau, sau Close thì
// KHÔNG plaintext nào xuất hiện trong bất kỳ file platform.db* nào.
func TestAdvR2SecretsNeverPlaintextMulti(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "platform.db")
	st, err := Open(dbPath, filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()

	secrets := map[string]string{
		"db/password":     "PLAINTEXT-ALPHA-9c1e4b",
		"oidc/client":     "PLAINTEXT-BRAVO-77f0aa",
		"smtp/pass":       "PLAINTEXT-CHARLIE-0d3e",
		"app/long/binary": string(bytes.Repeat([]byte("PLAINTEXT-DELTA-"), 40)),
		"app/empty":       "",
	}
	for ref, pt := range secrets {
		if err := st.PutSecret(ctx, ref, []byte(pt)); err != nil {
			t.Fatalf("PutSecret(%s): %v", ref, err)
		}
	}
	// Ghi đè để chắc bản cũ cũng không rơi ra WAL dạng thô.
	if err := st.PutSecret(ctx, "db/password", []byte("PLAINTEXT-ECHO-rotated")); err != nil {
		t.Fatalf("PutSecret rotate: %v", err)
	}
	secrets["db/password-rotated"] = "PLAINTEXT-ECHO-rotated"

	if err := st.Close(); err != nil { // checkpoint WAL
		t.Fatalf("Close: %v", err)
	}

	files, err := filepath.Glob(dbPath + "*")
	if err != nil || len(files) == 0 {
		t.Fatalf("Glob platform.db* = (%v, %v), muốn ≥1 file", files, err)
	}
	t.Logf("quét %d file: %v", len(files), files)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", f, err)
		}
		for ref, pt := range secrets {
			if pt == "" {
				continue
			}
			if bytes.Contains(raw, []byte(pt)) {
				t.Errorf("ST-03 VỠ: %s chứa plaintext của secret %q", f, ref)
			}
		}
	}
}

// TestAdvR2TamperedCiphertext: sửa 1 byte ciphertext trong DB → GetSecret
// PHẢI trả error (GCM auth), tuyệt đối không panic và không trả dữ liệu rác.
func TestAdvR2TamperedCiphertext(t *testing.T) {
	st, _ := advR2Open(t)
	ctx := context.Background()

	const pt = "top-secret-value-42"
	if err := st.PutSecret(ctx, "tamper/me", []byte(pt)); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	var blob []byte
	if err := st.db.QueryRowContext(ctx,
		`SELECT ciphertext FROM secrets WHERE ref = ?`, "tamper/me").Scan(&blob); err != nil {
		t.Fatalf("đọc ciphertext: %v", err)
	}
	if len(blob) < 13 {
		t.Fatalf("blob quá ngắn (%d byte) — sai format nonce||ct", len(blob))
	}

	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"lật 1 byte trong ciphertext", func(b []byte) []byte {
			c := append([]byte(nil), b...)
			c[len(c)-1] ^= 0x01
			return c
		}},
		{"lật 1 byte trong nonce", func(b []byte) []byte {
			c := append([]byte(nil), b...)
			c[0] ^= 0xFF
			return c
		}},
		{"cắt cụt ngắn hơn nonce", func(b []byte) []byte { return b[:5] }},
		{"blob rỗng", func(b []byte) []byte { return []byte{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC khi giải mã blob bị giả mạo: %v", r)
				}
			}()
			if _, err := st.db.ExecContext(ctx,
				`UPDATE secrets SET ciphertext = ? WHERE ref = ?`, tc.mutate(blob), "tamper/me"); err != nil {
				t.Fatalf("UPDATE ciphertext: %v", err)
			}
			got, err := st.GetSecret(ctx, "tamper/me")
			if err == nil {
				t.Fatalf("GetSecret sau khi giả mạo: muốn error, nhận plaintext %q", got)
			}
			if len(got) != 0 {
				t.Errorf("GetSecret lỗi nhưng vẫn trả %d byte rác: %q", len(got), got)
			}
			if bytes.Contains(got, []byte(pt)) {
				t.Errorf("trả về dữ liệu giải mã dù auth fail")
			}
			t.Logf("OK — error: %v", err)
		})
	}
}

// TestAdvR2MasterKeyLost: xoá master.key rồi Open lại → key MỚI được sinh,
// secret cũ phải lỗi TỬ TẾ (error, không panic, không rác).
func TestAdvR2MasterKeyLost(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "platform.db")
	keyPath := filepath.Join(dir, "master.key")
	ctx := context.Background()

	st, err := Open(dbPath, keyPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st.PutSecret(ctx, "lost/key", []byte("value-before-key-loss")); err != nil {
		t.Fatalf("PutSecret: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("xoá master.key: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PANIC sau khi mất master.key: %v", r)
		}
	}()

	st2, err := Open(dbPath, keyPath)
	if err != nil {
		t.Logf("QUAN SÁT: Open sau khi mất master.key trả lỗi: %v", err)
		return
	}
	defer st2.Close()

	info, statErr := os.Stat(keyPath)
	t.Logf("QUAN SÁT: Open THÀNH CÔNG và tự sinh master.key mới (%v byte, err=%v) — "+
		"secret cũ trở thành rác không giải mã được", info.Size(), statErr)

	got, err := st2.GetSecret(ctx, "lost/key")
	if err == nil {
		t.Fatalf("GetSecret với key mới: muốn error, nhận %q", got)
	}
	if len(got) != 0 {
		t.Errorf("GetSecret lỗi nhưng trả %d byte rác", len(got))
	}
	t.Logf("OK — GetSecret lỗi tử tế: %v", err)

	// Store vẫn dùng được cho secret MỚI (không hỏng vĩnh viễn).
	if err := st2.PutSecret(ctx, "lost/key", []byte("value-after")); err != nil {
		t.Errorf("PutSecret sau khi thay key: %v", err)
	}
	if v, err := st2.GetSecret(ctx, "lost/key"); err != nil || string(v) != "value-after" {
		t.Errorf("GetSecret sau ghi đè = (%q, %v), muốn value-after", v, err)
	}
}

// ---------- Jobs ----------

// TestAdvR2JobsAdversarial: kind filter sai, cạn attempt, id lạ, notBefore tương lai.
func TestAdvR2JobsAdversarial(t *testing.T) {
	st, _ := advR2Open(t)
	ctx := context.Background()

	if _, err := st.EnqueueJob(ctx, "deploy", json.RawMessage(`{"a":1}`), nil); err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}

	// kinds lọc sai → ErrNoJob (job vẫn còn queued, không bị đụng).
	for _, kinds := range [][]string{{"backup"}, {"backup", "restore"}, {""}} {
		if _, err := st.ClaimJob(ctx, kinds); !errors.Is(err, ErrNoJob) {
			t.Errorf("ClaimJob(%v): muốn ErrNoJob, nhận %v", kinds, err)
		}
	}
	job, err := st.ClaimJob(ctx, []string{"backup", "deploy"})
	if err != nil || job.Kind != "deploy" {
		t.Fatalf("ClaimJob(kind đúng nằm trong list) = (%+v, %v)", job, err)
	}

	// CompleteJob / FailJob id lạ → ErrNotFound.
	if err := st.CompleteJob(ctx, 999999, json.RawMessage(`{}`)); !errors.Is(err, ErrNotFound) {
		t.Errorf("CompleteJob id lạ: muốn ErrNotFound, nhận %v", err)
	}
	if err := st.FailJob(ctx, 999999, "x", 0); !errors.Is(err, ErrNotFound) {
		t.Errorf("FailJob id lạ: muốn ErrNotFound, nhận %v", err)
	}

	// Cạn attempt: FailJob liên tiếp (KHÔNG claim lại giữa chừng) đủ
	// MaxJobAttempts → state=failed, không bao giờ claim lại được nữa.
	deadID, err := st.EnqueueJob(ctx, "doomed", nil, nil)
	if err != nil {
		t.Fatalf("EnqueueJob doomed: %v", err)
	}
	if _, err := st.ClaimJob(ctx, []string{"doomed"}); err != nil {
		t.Fatalf("ClaimJob doomed: %v", err)
	}
	for i := 0; i < MaxJobAttempts; i++ {
		if err := st.FailJob(ctx, deadID, fmt.Sprintf("fail %d", i), 0); err != nil {
			t.Fatalf("FailJob #%d: %v", i, err)
		}
	}
	var state string
	var attempt int
	if err := st.db.QueryRowContext(ctx,
		`SELECT state, attempt FROM jobs WHERE id = ?`, deadID).Scan(&state, &attempt); err != nil {
		t.Fatalf("đọc job: %v", err)
	}
	if state != "failed" {
		t.Errorf("sau %d lần fail state = %q, muốn failed", MaxJobAttempts, state)
	}
	if attempt < MaxJobAttempts {
		t.Errorf("attempt = %d, muốn ≥ %d", attempt, MaxJobAttempts)
	}
	for i := 0; i < 3; i++ {
		if _, err := st.ClaimJob(ctx, []string{"doomed"}); !errors.Is(err, ErrNoJob) {
			t.Fatalf("job failed vẫn claim lại được (lần %d): %v", i, err)
		}
	}

	// notBefore tương lai 5s → claim ngay = ErrNoJob.
	future := time.Now().Add(5 * time.Second)
	if _, err := st.EnqueueJob(ctx, "later", nil, &future); err != nil {
		t.Fatalf("EnqueueJob later: %v", err)
	}
	if _, err := st.ClaimJob(ctx, []string{"later"}); !errors.Is(err, ErrNoJob) {
		t.Errorf("ClaimJob notBefore +5s: muốn ErrNoJob, nhận %v", err)
	}
}

// TestAdvR2NotBeforeSubSecond — cạm bẫy §6.4: not_before chỉ có độ phân giải
// GIÂY. Kiểm 2 tính chất:
//  1. AN TOÀN (bắt buộc): job đã quá hạn KHÔNG BAO GIỜ bị bỏ sót, và thứ tự
//     claim theo id.
//  2. Độ lệch: notBefore được Truncate XUỐNG giây nên job có thể chạy SỚM
//     tối đa 1 giây. Test chốt trần 1s và ghi lại độ sớm thực đo.
func TestAdvR2NotBeforeSubSecond(t *testing.T) {
	st, _ := advR2Open(t)
	ctx := context.Background()

	// (1) Nhiều job quá hạn với offset mili-giây quanh mốc giây → phải claim
	// hết, đúng thứ tự id, không sót.
	base := time.Now()
	var want []int64
	for i, off := range []time.Duration{
		-2500 * time.Millisecond, -2001 * time.Millisecond, -2000 * time.Millisecond,
		-1999 * time.Millisecond, -1500 * time.Millisecond, -1001 * time.Millisecond,
	} {
		nb := base.Add(off)
		id, err := st.EnqueueJob(ctx, "edge", json.RawMessage(fmt.Sprintf(`{"i":%d}`, i)), &nb)
		if err != nil {
			t.Fatalf("EnqueueJob edge #%d: %v", i, err)
		}
		want = append(want, id)
	}
	for i, wantID := range want {
		job, err := st.ClaimJob(ctx, []string{"edge"})
		if err != nil {
			t.Fatalf("job quá hạn #%d (id %d) BỊ SÓT: %v", i, wantID, err)
		}
		if job.ID != wantID {
			t.Errorf("thứ tự claim #%d = id %d, muốn %d (ORDER BY id)", i, job.ID, wantID)
		}
	}
	if _, err := st.ClaimJob(ctx, []string{"edge"}); !errors.Is(err, ErrNoJob) {
		t.Errorf("claim thừa: muốn ErrNoJob, nhận %v", err)
	}

	// (2) Đo độ sớm: canh ngay SAU mốc giây rồi hẹn +900ms — với Truncate
	// xuống giây, not_before rơi về giây HIỆN TẠI nên job claim được NGAY.
	// (Canh mốc để kết quả tất định, không phụ thuộc lúc chạy test.)
	now := time.Now()
	time.Sleep(now.Truncate(time.Second).Add(time.Second + 10*time.Millisecond).Sub(now))
	sched := time.Now().Add(900 * time.Millisecond)
	if _, err := st.EnqueueJob(ctx, "early", nil, &sched); err != nil {
		t.Fatalf("EnqueueJob early: %v", err)
	}
	claimAt := time.Now()
	job, err := st.ClaimJob(ctx, []string{"early"})
	switch {
	case errors.Is(err, ErrNoJob):
		t.Logf("OK — job hẹn +900ms chưa claim được ngay")
	case err != nil:
		t.Fatalf("ClaimJob early: %v", err)
	default:
		early := sched.Sub(claimAt)
		t.Logf("QUAN SÁT (LỖI minor §6.4): job id %d hẹn %s nhưng claim được SỚM %s "+
			"— formatSecond() Truncate XUỐNG giây (sqlite.go:63); retryAfter dưới 1s "+
			"của FailJob cũng vô hiệu. Nên dùng làm tròn LÊN để không chạy sớm.",
			job.ID, sched.Format(time.RFC3339Nano), early)
		if early > time.Second {
			t.Errorf("chạy sớm %s — vượt trần 1 giây của độ phân giải RFC3339 giây", early)
		}
	}

	// (3) not_before lưu đúng RFC3339 GIÂY (fixed width) — sai là ClaimJob flaky.
	rows, err := st.db.QueryContext(ctx, `SELECT not_before FROM jobs WHERE not_before IS NOT NULL`)
	if err != nil {
		t.Fatalf("query not_before: %v", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var nb string
		if err := rows.Scan(&nb); err != nil {
			t.Fatal(err)
		}
		if _, perr := time.Parse(time.RFC3339, nb); perr != nil {
			t.Errorf("not_before %q không parse được RFC3339: %v", nb, perr)
		}
		if len(nb) != len("2006-01-02T15:04:05Z") {
			t.Errorf("not_before %q dài %d — KHÔNG fixed-width, so sánh chuỗi <= sẽ sai", nb, len(nb))
		}
		n++
	}
	if n == 0 {
		t.Error("không có row not_before nào để kiểm format")
	}
}

// ---------- Concurrency (đếm được, không cần -race) ----------

// TestAdvR2ConcurrentUpdateAndClaim: 8 goroutine cùng UpdateDesired + ClaimJob.
// Bất biến: không mất update (rev là hoán vị 2..N+1, không trùng) và mỗi job
// bị claim ĐÚNG 1 lần.
func TestAdvR2ConcurrentUpdateAndClaim(t *testing.T) {
	st, _ := advR2Open(t)
	ctx := context.Background()
	advR2CreateApp(t, st, "app-cc", "cc") // desired_rev = 1

	const workers, jobsPerWorker = 8, 4
	const nJobs = workers * jobsPerWorker

	jobIDs := map[int64]bool{}
	for i := 0; i < nJobs; i++ {
		id, err := st.EnqueueJob(ctx, "cc", nil, nil)
		if err != nil {
			t.Fatalf("EnqueueJob #%d: %v", i, err)
		}
		jobIDs[id] = true
	}

	var (
		mu      sync.Mutex
		revs    []int64
		claimed []int64
		errs    []error
	)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < jobsPerWorker; i++ {
				rev, err := st.UpdateDesired(ctx, "app-cc",
					json.RawMessage(fmt.Sprintf(`{"image":"v%d-%d"}`, w, i)))
				mu.Lock()
				if err != nil {
					errs = append(errs, fmt.Errorf("UpdateDesired w%d i%d: %w", w, i, err))
				} else {
					revs = append(revs, rev)
				}
				mu.Unlock()

				job, err := st.ClaimJob(ctx, []string{"cc"})
				mu.Lock()
				switch {
				case errors.Is(err, ErrNoJob):
				case err != nil:
					errs = append(errs, fmt.Errorf("ClaimJob w%d i%d: %w", w, i, err))
				default:
					claimed = append(claimed, job.ID)
				}
				mu.Unlock()
			}
		}(w)
	}
	close(start)
	wg.Wait()

	for _, e := range errs {
		t.Errorf("lỗi trong goroutine: %v", e)
	}

	// Không mất update: N lần UpdateDesired → N rev PHÂN BIỆT, desired_rev cuối = 1+N.
	seenRev := map[int64]bool{}
	for _, r := range revs {
		if seenRev[r] {
			t.Errorf("rev %d bị trả 2 lần — MẤT UPDATE (lost update)", r)
		}
		seenRev[r] = true
	}
	if len(revs) != workers*jobsPerWorker {
		t.Fatalf("chỉ %d/%d lần UpdateDesired thành công", len(revs), workers*jobsPerWorker)
	}
	final := advR2Get(t, st, "app-cc")
	if want := int64(1 + workers*jobsPerWorker); final.DesiredRev != want {
		t.Errorf("desired_rev cuối = %d, muốn %d (không được mất update nào)", final.DesiredRev, want)
	}

	// Không claim đôi: mỗi job đúng 1 lần, tổng = nJobs.
	count := map[int64]int{}
	for _, id := range claimed {
		count[id]++
	}
	for id, c := range count {
		if c != 1 {
			t.Errorf("job %d bị claim %d lần — CLAIM ĐÔI", id, c)
		}
	}
	if len(claimed) != nJobs {
		t.Errorf("tổng claim = %d, muốn %d", len(claimed), nJobs)
	}
	if len(count) != nJobs {
		t.Errorf("số job phân biệt đã claim = %d, muốn %d", len(count), nJobs)
	}
	for id := range jobIDs {
		if count[id] != 1 {
			t.Errorf("job %d claim %d lần, muốn 1", id, count[id])
		}
	}
}
