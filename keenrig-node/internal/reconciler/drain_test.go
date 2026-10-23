package reconciler

// Test T9b phía vòng lặp — drain/resume mà ota dựa vào để thay bin an toàn.

import (
	"context"
	"testing"
	"time"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
)

// Drain xong thì vòng lặp KHÔNG được chạm runtime nữa, kể cả khi có app mới.
func TestDrainStopsWork(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	createApp(t, st, "app-dr1", "traefik/whoami:v1.10")

	r := New(st, fake, proxyOpts())
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "hội tụ trước khi drain", func() bool {
		app := getApp(t, st, "app-dr1")
		return app.AppliedRev == app.DesiredRev
	})

	n, err := r.Drain(context.Background(), 5*time.Second)
	if err != nil || n != 0 {
		t.Fatalf("Drain = (%d, %v), muốn (0, nil)", n, err)
	}
	if !r.Paused() {
		t.Fatal("Drain xong mà Paused() vẫn false")
	}

	before := fake.applyCount()
	createApp(t, st, "app-dr2", "traefik/whoami:v1.10")
	time.Sleep(300 * time.Millisecond)
	if got := fake.applyCount(); got != before {
		t.Errorf("vòng lặp vẫn Apply sau khi drain: %d → %d", before, got)
	}
	if app := getApp(t, st, "app-dr2"); app.AppliedRev != 0 {
		t.Errorf("applied_rev = %d sau khi drain, muốn 0", app.AppliedRev)
	}

	// Resume → hội tụ trở lại.
	r.Resume()
	if r.Paused() {
		t.Fatal("Resume xong mà Paused() vẫn true")
	}
	waitFor(t, 5*time.Second, "hội tụ lại sau resume", func() bool {
		app := getApp(t, st, "app-dr2")
		return app.AppliedRev == app.DesiredRev
	})
}

// Drain phải ĐỢI việc đang chạy dở, không cắt ngang. Đây là toàn bộ lý do nó
// tồn tại: thay bin giữa một lần Apply để lại container rev mới đã dựng mà rev
// cũ chưa gỡ.
func TestDrainWaitsForInFlight(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	createApp(t, st, "app-dr3", "traefik/whoami:v1.10")

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	fake.setApplyFn(func(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return runtime.Observed{Phase: contracts.AppStateRunning, Health: contracts.HealthUnknown}, nil
	})

	r := New(st, fake, proxyOpts())
	_, stop := runReconciler(t, r)
	defer stop()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("không vào được Apply")
	}

	// Timeout ngắn trong lúc Apply còn treo → phải báo CÒN việc dở.
	n, err := r.Drain(context.Background(), 300*time.Millisecond)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if n == 0 {
		t.Error("Drain báo sạch trong khi Apply vẫn đang chạy — ota sẽ thay bin giữa một lần deploy")
	}

	close(release)
	// Apply xong → drain lần nữa phải sạch.
	waitFor(t, 5*time.Second, "drain sạch sau khi Apply xong", func() bool {
		n, err := r.Drain(context.Background(), 200*time.Millisecond)
		return err == nil && n == 0
	})
}

// Drain/Resume idempotent — ota retry là chuyện bình thường.
func TestDrainResumeIdempotent(t *testing.T) {
	st := openStore(t)
	r := New(st, newFakeRuntime(), proxyOpts())
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if n, err := r.Drain(ctx, time.Second); err != nil || n != 0 {
			t.Fatalf("Drain lần %d = (%d, %v)", i, n, err)
		}
		if !r.Paused() {
			t.Fatalf("Paused() false sau Drain lần %d", i)
		}
	}
	for i := 0; i < 3; i++ {
		r.Resume()
		if r.Paused() {
			t.Fatalf("Paused() true sau Resume lần %d", i)
		}
	}
}

// Đang drain thì cũng KHÔNG được giành lease: box sắp bị thay bin mà lại đi
// giành quyền lái Docker là đúng thứ drain sinh ra để chặn.
func TestDrainedBoxDoesNotHoldLease(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	r := New(st, newFakeRuntime(), proxyOpts())

	if _, err := r.Drain(ctx, time.Second); err != nil {
		t.Fatal(err)
	}
	_, stop := runReconciler(t, r)
	defer stop()

	time.Sleep(300 * time.Millisecond)
	if _, err := st.GetLease(ctx, "reconciler"); err == nil {
		t.Error("box đang drain vẫn giành lease")
	}
}
