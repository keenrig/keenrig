package jobs_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/jobs"
	"github.com/keenrig/keenrig/keenrig-node/internal/locks"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

func openStore(t *testing.T) store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func fastOpts(owner string) jobs.Options {
	return jobs.Options{
		Owner:        owner,
		Poll:         20 * time.Millisecond,
		RetryAfter:   20 * time.Millisecond,
		ReclaimEvery: 50 * time.Millisecond,
		Visibility:   2 * time.Second,
	}
}

func runWorker(t *testing.T, w *jobs.Worker) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := w.Run(ctx); err != nil {
			t.Errorf("Run trả lỗi: %v", err)
		}
	}()
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("worker không thoát")
		}
	}
	t.Cleanup(stop)
	return stop
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("quá %s vẫn chưa: %s", timeout, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRunsJobAndRecordsResult(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	w := jobs.New(st, fastOpts("w1"))

	var gotArgs string
	w.Register("test", func(_ context.Context, job *store.Job, p jobs.Progress) (json.RawMessage, error) {
		gotArgs = string(job.Args)
		p.Set(50, "đang làm")
		return json.RawMessage(`{"ok":true}`), nil
	})

	id, err := w.Enqueue(ctx, "test", map[string]string{"a": "1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	runWorker(t, w)

	waitFor(t, 5*time.Second, "job xong", func() bool {
		return hasEvent(t, st, "job.completed")
	})
	if gotArgs != `{"a":"1"}` {
		t.Errorf("args = %q", gotArgs)
	}
	// Job xong phải ở state done, percent 100, có result và finished_at.
	job := jobByID(t, st, id)
	if job.State != "done" || job.Percent != 100 || string(job.Result) != `{"ok":true}` {
		t.Errorf("job = %+v", job)
	}
	if job.FinishedAt == nil {
		t.Error("thiếu finished_at — janitor sẽ không dọn được job cũ")
	}
}

// Tiến độ phải ĐỌC ĐƯỢC trong lúc job còn chạy. Không có nó thì "đang chạy" và
// "đã treo" nhìn giống hệt nhau.
func TestProgressVisibleWhileRunning(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	w := jobs.New(st, fastOpts("w1"))

	release := make(chan struct{})
	var id int64
	w.Register("slow", func(_ context.Context, job *store.Job, p jobs.Progress) (json.RawMessage, error) {
		p.Set(42, "đang nén dữ liệu")
		<-release
		return nil, nil
	})

	var err error
	id, err = w.Enqueue(ctx, "slow", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	runWorker(t, w)

	waitFor(t, 5*time.Second, "tiến độ hiện ra khi job CÒN chạy", func() bool {
		j := jobByID(t, st, id)
		return j.State == "running" && j.Percent == 42 && j.Message == "đang nén dữ liệu"
	})
	close(release)
}

// Handler lỗi → job retry, và cạn lượt thì sang failed (không lặp vô hạn).
func TestRetryThenFail(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	w := jobs.New(st, fastOpts("w1"))

	var mu sync.Mutex
	calls := 0
	w.Register("flaky", func(context.Context, *store.Job, jobs.Progress) (json.RawMessage, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return nil, errors.New("hỏng")
	})

	id, err := w.Enqueue(ctx, "flaky", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	runWorker(t, w)

	waitFor(t, 10*time.Second, "job sang failed sau khi cạn lượt", func() bool {
		return jobByID(t, st, id).State == "failed"
	})
	mu.Lock()
	got := calls
	mu.Unlock()
	if got != store.MaxJobAttempts {
		t.Errorf("chạy %d lần, muốn đúng %d (MaxJobAttempts)", got, store.MaxJobAttempts)
	}
	if !hasEvent(t, st, "job.failed") {
		t.Error("thiếu event job.failed")
	}
}

// Handler PANIC không được giết tiến trình — mất box nghĩa là mất luôn control
// API và đường chẩn đoán.
func TestPanicIsContained(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	w := jobs.New(st, fastOpts("w1"))

	w.Register("boom", func(context.Context, *store.Job, jobs.Progress) (json.RawMessage, error) {
		panic("nổ")
	})
	done := make(chan struct{}, 1)
	w.Register("sau", func(context.Context, *store.Job, jobs.Progress) (json.RawMessage, error) {
		done <- struct{}{}
		return nil, nil
	})

	if _, err := w.Enqueue(ctx, "boom", nil, nil); err != nil {
		t.Fatal(err)
	}
	runWorker(t, w)

	if _, err := w.Enqueue(ctx, "sau", nil, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("worker chết sau panic — job kế tiếp không chạy")
	}
}

// Kind không có handler phải FAIL NGAY, không quay lại hàng đợi mãi mãi.
func TestUnknownKindFailsFast(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	w := jobs.New(st, fastOpts("w1"))

	id, err := w.Enqueue(ctx, "không-ai-nhận", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	runWorker(t, w)

	waitFor(t, 10*time.Second, "job kind lạ sang failed", func() bool {
		return jobByID(t, st, id).State == "failed"
	})
	if msg := jobByID(t, st, id).LastError; msg == "" {
		t.Error("không ghi lý do")
	}
}

// Job mồ côi của worker chết được thu hồi NGAY lúc worker mới khởi động —
// không đợi tick, vì đúng lúc vừa restart mới là lúc có job mồ côi.
func TestReclaimsOrphanOnStartup(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()

	if _, err := st.EnqueueJob(ctx, "test", nil, nil); err != nil {
		t.Fatal(err)
	}
	// Worker "chết": claim với hạn 1 giây rồi không bao giờ kết thúc.
	if _, err := st.ClaimJobAs(ctx, nil, "worker-đã-chết", time.Second); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2100 * time.Millisecond) // để lease hết hạn

	w := jobs.New(st, jobs.Options{
		Owner: "w2", Poll: 20 * time.Millisecond,
		ReclaimEvery: time.Hour, // nhịp DÀI: nếu thu hồi chỉ chạy theo tick thì test này đỏ
		Visibility:   time.Minute,
	})
	ran := make(chan struct{}, 1)
	w.Register("test", func(context.Context, *store.Job, jobs.Progress) (json.RawMessage, error) {
		ran <- struct{}{}
		return nil, nil
	})
	runWorker(t, w)

	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("job mồ côi không được thu hồi lúc khởi động")
	}
}

// Khoá mà handler quên nhả phải được dọn sau khi job kết thúc — và LOG lại,
// vì đó là bằng chứng một đường thoát của handler thiếu Release.
func TestLeakedLocksCleanedAfterJob(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	w := jobs.New(st, fastOpts("w1"))

	w.Register("rò-khoá", func(ctx context.Context, job *store.Job, _ jobs.Progress) (json.RawMessage, error) {
		m := locks.New(st, w.LockHolder(job), time.Hour)
		if err := m.Acquire(ctx, locks.FullBackup, "cố tình quên nhả"); err != nil {
			return nil, err
		}
		return nil, nil // KHÔNG nhả
	})

	if _, err := w.Enqueue(ctx, "rò-khoá", nil, nil); err != nil {
		t.Fatal(err)
	}
	runWorker(t, w)

	waitFor(t, 5*time.Second, "job xong", func() bool { return hasEvent(t, st, "job.completed") })
	waitFor(t, 5*time.Second, "khoá bị rò được dọn", func() bool {
		held, err := st.ListLocks(ctx)
		return err == nil && len(held) == 0
	})
}

// Nhiều job xếp hàng phải chạy hết trong MỘT nhịp poll, không phải mỗi nhịp
// một job — 100 job với poll 2s sẽ mất 200 giây chỉ để bắt đầu cái cuối.
func TestDrainsQueueInOneTick(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	w := jobs.New(st, jobs.Options{
		Owner: "w1", Poll: 2 * time.Second, // nhịp DÀI có chủ đích
		ReclaimEvery: time.Hour, Visibility: time.Minute,
	})

	var mu sync.Mutex
	done := 0
	w.Register("test", func(context.Context, *store.Job, jobs.Progress) (json.RawMessage, error) {
		mu.Lock()
		done++
		mu.Unlock()
		return nil, nil
	})
	for i := 0; i < 5; i++ {
		if _, err := w.Enqueue(ctx, "test", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	runWorker(t, w)

	// 5 job trong ~1 nhịp poll (2s). Nếu mỗi nhịp một job thì cần 10s.
	waitFor(t, 5*time.Second, "cả 5 job chạy xong", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return done == 5
	})
}

// --- helper ---------------------------------------------------------------------

func jobByID(t *testing.T, st store.Store, id int64) *store.Job {
	t.Helper()
	j, err := st.GetJob(t.Context(), id)
	if err != nil {
		t.Fatalf("GetJob(%d): %v", id, err)
	}
	return j
}

func hasEvent(t *testing.T, st store.Store, action string) bool {
	t.Helper()
	evs, err := st.ListEvents(context.Background(), 200)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	for _, e := range evs {
		if e.Action == action {
			return true
		}
	}
	return false
}
