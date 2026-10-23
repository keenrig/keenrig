package reconciler

// Test đối kháng vòng 2 — AGENT TESTER. Ép reconciler vào các đường lỗi mà
// reconciler_test.go không chạm: desired JSON HỎNG, rt.Apply PANIC, store
// SetStatus lỗi vĩnh viễn, 1 app lỗi mãi làm nghẽn app khác, ctx cancel giữa
// lúc Apply đang block.
//
// Helper/type ở file này đều có tiền tố advR2* để KHÔNG đụng helper của
// reconciler_test.go (fakeRuntime/openStore/waitFor/...) — file này tự chứa.

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/resources"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
	"github.com/keenrig/keenrig/keenrig-node/internal/supervise"
)

// ---------- runtime giả, tự chứa ----------

type advRuntime struct {
	mu      sync.Mutex
	applies map[string]int // appID → số lần Apply
	applyFn func(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error)
}

func newAdvRuntime() *advRuntime { return &advRuntime{applies: map[string]int{}} }

func (f *advRuntime) setApplyFn(fn func(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applyFn = fn
}

func (f *advRuntime) count(appID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applies[appID]
}

func (f *advRuntime) Apply(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
	f.mu.Lock()
	f.applies[spec.ID]++
	fn := f.applyFn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, spec) // fn có thể panic — đó là chủ đích của test
	}
	return runtime.Observed{
		Phase:        contracts.AppStateRunning,
		Health:       contracts.HealthUnknown,
		ContainerIDs: []string{"adv-" + spec.ID},
	}, nil
}

func (f *advRuntime) Status(ctx context.Context, appID string) (runtime.Observed, error) {
	return runtime.Observed{Phase: contracts.AppStateRunning, Health: contracts.HealthUnknown}, nil
}

func (f *advRuntime) Remove(ctx context.Context, appID string) error { return nil }

func (f *advRuntime) ResourceCaps(context.Context) (resources.Caps, error) {
	return resources.Caps{}, nil
}

var _ runtime.Runtime = (*advRuntime)(nil)

// ---------- helper tự chứa ----------

func advR2Store(t *testing.T) store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// advR2App tạo app với desired THÔ (cho phép nhét JSON hỏng).
func advR2App(t *testing.T, st store.Store, id string, desired string) {
	t.Helper()
	app := &store.App{ID: id, Slug: id, Desired: json.RawMessage(desired)}
	if err := st.CreateApp(context.Background(), app); err != nil {
		t.Fatalf("CreateApp(%s): %v", id, err)
	}
}

func advR2Wait(t *testing.T, timeout time.Duration, what string, cond func() bool) {
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

func advR2Get(t *testing.T, st store.Store, id string) (*store.App, contracts.AppStatus) {
	t.Helper()
	app, err := st.GetApp(context.Background(), id)
	if err != nil {
		t.Fatalf("GetApp(%s): %v", id, err)
	}
	var s contracts.AppStatus
	if len(app.Status) > 0 {
		if err := json.Unmarshal(app.Status, &s); err != nil {
			t.Fatalf("unmarshal status %q: %v", app.Status, err)
		}
	}
	return app, s
}

func advR2HasEvent(t *testing.T, st store.Store, action, subject string) bool {
	t.Helper()
	evs, err := st.ListEvents(context.Background(), 500)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	for _, e := range evs {
		if e.Action == action && e.Subject == subject {
			return true
		}
	}
	return false
}

// advR2Run chạy Run trong goroutine, trả stop() đợi thoát sạch.
func advR2Run(t *testing.T, r *Reconciler) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := r.Run(ctx); err != nil {
			t.Errorf("Run trả lỗi: %v", err)
		}
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(20 * time.Second):
				t.Error("Run KHÔNG thoát sau khi cancel ctx")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

// ---------- (1) desired JSON hỏng ----------

// TestAdvR2BadDesiredJSONIsolated: app có desired KHÔNG parse được →
// reconciler không panic, ghi status error + event + backoff; app LÀNH bên
// cạnh vẫn hội tụ bình thường (lỗi 1 app không nghẽn app khác).
func TestAdvR2BadDesiredJSONIsolated(t *testing.T) {
	st := advR2Store(t)
	fake := newAdvRuntime()

	// desired hỏng đủ kiểu: cụt, không phải object, sai type field.
	advR2App(t, st, "app-broken", `{"image": `)
	advR2App(t, st, "app-notobj", `["array","khong-phai-object"]`)
	advR2App(t, st, "app-badtype", `{"image": 12345}`)
	advR2App(t, st, "app-good", `{"image":"traefik/whoami:v1.10"}`)

	r := New(st, fake, Options{
		Interval:        10 * time.Millisecond,
		RefreshInterval: time.Hour,
		BackoffBase:     20 * time.Millisecond,
		BackoffCap:      80 * time.Millisecond,
	})
	advR2Run(t, r)

	// App lành PHẢI hội tụ dù 3 app hỏng đứng TRƯỚC nó theo created_at.
	advR2Wait(t, 15*time.Second, "app-good hội tụ", func() bool {
		app, _ := advR2Get(t, st, "app-good")
		return app.AppliedRev == 1
	})
	if _, s := advR2Get(t, st, "app-good"); s.State != contracts.AppStateRunning {
		t.Errorf("app-good state = %q, muốn running", s.State)
	}

	for _, bad := range []string{"app-broken", "app-notobj", "app-badtype"} {
		app, s := advR2Get(t, st, bad)
		if app.AppliedRev != 0 {
			t.Errorf("%s applied_rev = %d, muốn giữ 0 (desired không parse được)", bad, app.AppliedRev)
		}
		if s.State != contracts.AppStateError {
			t.Errorf("%s state = %q, muốn error", bad, s.State)
		}
		if s.Message == "" {
			t.Errorf("%s status.message rỗng — mất nguyên nhân lỗi", bad)
		}
		if !advR2HasEvent(t, st, "app.reconcile_failed", bad) {
			t.Errorf("%s thiếu event app.reconcile_failed", bad)
		}
		// Không được gọi Apply với desired hỏng.
		if n := fake.count(bad); n != 0 {
			t.Errorf("%s: Apply bị gọi %d lần dù desired không parse được", bad, n)
		}
	}

	// Backoff phải chặn hot-loop trên app hỏng: đo trong 400ms.
	before := advR2CountFailEvents(t, st, "app-broken")
	time.Sleep(400 * time.Millisecond)
	after := advR2CountFailEvents(t, st, "app-broken")
	// Base 20ms cap 80ms → tối đa ~400/80 + vài lần đầu ≈ 10.
	if n := after - before; n > 12 {
		t.Errorf("app-broken thất bại %d lần trong 400ms — HOT LOOP, backoff không hiệu lực", n)
	} else {
		t.Logf("OK — backoff chặn: %d lần fail trong 400ms", n)
	}
}

func advR2CountFailEvents(t *testing.T, st store.Store, subject string) int {
	t.Helper()
	evs, err := st.ListEvents(context.Background(), 5000)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	n := 0
	for _, e := range evs {
		if e.Action == "app.reconcile_failed" && e.Subject == subject {
			n++
		}
	}
	return n
}

// ---------- (2) rt.Apply PANIC ----------

// TestAdvR2ApplyPanicEscapesReconciler: chứng minh reconciler TỰ NÓ không
// recover — panic từ rt.Apply thoát thẳng ra khỏi reconcileTick. Gọi
// reconcileTick trực tiếp (cùng package) để quan sát an toàn, không cần
// goroutine (panic trong goroutine sẽ giết cả test binary).
func TestAdvR2ApplyPanicEscapesReconciler(t *testing.T) {
	st := advR2Store(t)
	fake := newAdvRuntime()
	fake.setApplyFn(func(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
		panic("driver bùm giữa Apply")
	})
	advR2App(t, st, "app-panic", `{"image":"traefik/whoami:v1.10"}`)

	r := New(st, fake, Options{Interval: 10 * time.Millisecond, RefreshInterval: time.Hour})

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		r.reconcileTick(context.Background())
	}()

	if recovered == nil {
		t.Log("QUAN SÁT: reconciler TỰ recover panic của rt.Apply")
		return
	}
	t.Logf("QUAN SÁT (thiết kế hiện tại): panic THOÁT khỏi reconcileTick (%v) — "+
		"reconciler không có recover per-app; chỉ supervise.Go ở main chặn được. "+
		"Hệ quả: 1 app làm driver panic sẽ giết CẢ vòng lặp, mọi app khác ngừng "+
		"reconcile tới khi supervisor restart (mất backoff in-memory).", recovered)
}

// TestAdvR2PanicContainedBySupervisor: đúng như main.go bọc — supervise.Go
// PHẢI nuốt panic, restart reconciler, và hệ thống vẫn hội tụ. Tiến trình test
// sống sót là bằng chứng luật §2.1.1 có hiệu lực end-to-end.
func TestAdvR2PanicContainedBySupervisor(t *testing.T) {
	st := advR2Store(t)
	fake := newAdvRuntime()

	var panics atomic.Int32
	fake.setApplyFn(func(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
		if panics.Add(1) <= 2 {
			panic("driver bùm lần " + string(rune('0'+panics.Load())))
		}
		return runtime.Observed{
			Phase:        contracts.AppStateRunning,
			Health:       contracts.HealthUnknown,
			ContainerIDs: []string{"adv-" + spec.ID},
		}, nil
	})
	advR2App(t, st, "app-sup", `{"image":"traefik/whoami:v1.10"}`)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var restarts atomic.Int32
	r := New(st, fake, Options{Interval: 10 * time.Millisecond, RefreshInterval: time.Hour})
	supervise.Go(ctx, "reconciler", r.Run, supervise.Options{
		BackoffBase: 10 * time.Millisecond,
		BackoffCap:  50 * time.Millisecond,
		OnRestart: func(name string, cause error, next time.Duration) {
			restarts.Add(1)
		},
	})

	advR2Wait(t, 20*time.Second, "hội tụ sau 2 lần panic", func() bool {
		app, err := st.GetApp(context.Background(), "app-sup")
		return err == nil && app.AppliedRev == 1
	})
	if n := restarts.Load(); n < 2 {
		t.Errorf("OnRestart gọi %d lần, muốn ≥2 (2 panic)", n)
	}
	if _, s := advR2Get(t, st, "app-sup"); s.State != contracts.AppStateRunning {
		t.Errorf("state = %q, muốn running", s.State)
	}
	t.Logf("OK — supervise nuốt %d panic, tiến trình sống, app hội tụ", restarts.Load())
}

// ---------- (3) 1 app lỗi mãi không được nghẽn app khác ----------

// TestAdvR2PermanentFailureDoesNotBlockPeer: app-fail lỗi vĩnh viễn (Apply trả
// error mãi) → app-ok vẫn hội tụ và vẫn được refresh; app-fail không hot-loop.
func TestAdvR2PermanentFailureDoesNotBlockPeer(t *testing.T) {
	st := advR2Store(t)
	fake := newAdvRuntime()
	errBoom := errors.New("driver hỏng vĩnh viễn")
	fake.setApplyFn(func(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
		if spec.ID == "app-fail" {
			return runtime.Observed{Phase: contracts.AppStateError}, errBoom
		}
		return runtime.Observed{
			Phase:        contracts.AppStateRunning,
			Health:       contracts.HealthUnknown,
			ContainerIDs: []string{"adv-" + spec.ID},
		}, nil
	})

	advR2App(t, st, "app-fail", `{"image":"traefik/whoami:v1.10"}`) // tạo TRƯỚC → đứng đầu ORDER BY created_at
	time.Sleep(5 * time.Millisecond)
	advR2App(t, st, "app-ok", `{"image":"traefik/whoami:v1.10"}`)

	r := New(st, fake, Options{
		Interval:        10 * time.Millisecond,
		RefreshInterval: time.Hour,
		BackoffBase:     50 * time.Millisecond,
		BackoffCap:      200 * time.Millisecond,
	})
	advR2Run(t, r)

	advR2Wait(t, 15*time.Second, "app-ok hội tụ dù app-fail lỗi mãi", func() bool {
		app, _ := advR2Get(t, st, "app-ok")
		return app.AppliedRev == 1
	})

	// app-ok đã hội tụ → không được Apply lại nữa (ra khỏi ListAppsNeedingReconcile).
	okBefore := fake.count("app-ok")
	failBefore := fake.count("app-fail")
	time.Sleep(500 * time.Millisecond)
	okAfter := fake.count("app-ok")
	failAfter := fake.count("app-fail")

	if okAfter != okBefore {
		t.Errorf("app-ok đã hội tụ nhưng vẫn bị Apply thêm %d lần", okAfter-okBefore)
	}
	// Backoff 50→100→200(cap) trong 500ms → ≤ ~6 lần.
	if n := failAfter - failBefore; n > 8 {
		t.Errorf("app-fail Apply %d lần trong 500ms — HOT LOOP (backoff không hiệu lực)", n)
	} else {
		t.Logf("OK — app-fail retry %d lần trong 500ms (backoff mũ có hiệu lực)", n)
	}

	appFail, sFail := advR2Get(t, st, "app-fail")
	if appFail.AppliedRev != 0 {
		t.Errorf("app-fail applied_rev = %d, muốn 0", appFail.AppliedRev)
	}
	if sFail.State != contracts.AppStateError || sFail.Message == "" {
		t.Errorf("app-fail status = %+v, muốn error kèm message", sFail)
	}
}

// ---------- (4) SetStatus lỗi vĩnh viễn ----------

// advFailingSetStatus nhúng store thật nhưng SetStatus luôn lỗi.
type advFailingSetStatus struct {
	store.Store
	calls atomic.Int32
}

func (s *advFailingSetStatus) SetStatus(ctx context.Context, id string, status json.RawMessage, appliedRev int64) error {
	s.calls.Add(1)
	return errors.New("store giả lập: disk full")
}

// TestAdvR2SetStatusErrorDoesNotStall: SetStatus lỗi vĩnh viễn KHÔNG được làm
// kẹt vòng lặp (Run vẫn tick, vẫn thoát sạch khi cancel). Đồng thời ghi nhận
// tần suất Apply — app không bao giờ rời ListAppsNeedingReconcile nên bị Apply
// lại mỗi tick, KHÔNG có backoff (vì Apply thành công).
func TestAdvR2SetStatusErrorDoesNotStall(t *testing.T) {
	real := advR2Store(t)
	st := &advFailingSetStatus{Store: real}
	fake := newAdvRuntime()
	advR2App(t, st, "app-nostatus", `{"image":"traefik/whoami:v1.10"}`)

	r := New(st, fake, Options{Interval: 20 * time.Millisecond, RefreshInterval: time.Hour})
	stop := advR2Run(t, r)

	advR2Wait(t, 10*time.Second, "reconciler vẫn chạy dù SetStatus lỗi", func() bool {
		return fake.count("app-nostatus") >= 3
	})

	n0 := fake.count("app-nostatus")
	time.Sleep(300 * time.Millisecond)
	n1 := fake.count("app-nostatus")
	t.Logf("QUAN SÁT: SetStatus lỗi vĩnh viễn → Apply %d lần trong 300ms (tick 20ms). "+
		"Vòng lặp KHÔNG kẹt (đạt yêu cầu §3.1) nhưng cũng KHÔNG có backoff vì Apply "+
		"thành công — app kẹt trong ListAppsNeedingReconcile và bị Apply lại mỗi tick. "+
		"Với Interval mặc định 1s = 1 lần gọi driver/giây vô hạn.", n1-n0)
	if n1 == n0 {
		t.Errorf("Apply không được gọi thêm trong 300ms — vòng lặp bị KẸT")
	}

	// applied_rev không đổi (SetStatus lỗi), nhưng không được panic/corrupt.
	app, err := real.GetApp(context.Background(), "app-nostatus")
	if err != nil {
		t.Fatalf("GetApp: %v", err)
	}
	if app.AppliedRev != 0 {
		t.Errorf("applied_rev = %d, muốn 0 (SetStatus luôn lỗi)", app.AppliedRev)
	}
	// Event vẫn ghi được (đường AppendEvent độc lập SetStatus).
	if !advR2HasEvent(t, real, "app.reconciled", "app-nostatus") {
		t.Log("QUAN SÁT: không có event app.reconciled — chấp nhận được")
	}

	stop() // phải thoát sạch, không treo
}

// ---------- (5) ctx cancel giữa lúc Apply đang block ----------

// TestAdvR2CancelWhileApplyBlocked: Apply block tới khi ctx done → Run phải
// trả nil và thoát NHANH, không rò goroutine, không kẹt.
func TestAdvR2CancelWhileApplyBlocked(t *testing.T) {
	st := advR2Store(t)
	fake := newAdvRuntime()
	entered := make(chan struct{}, 1)
	fake.setApplyFn(func(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-ctx.Done() // block tới cancel
		return runtime.Observed{Phase: contracts.AppStateError}, ctx.Err()
	})
	advR2App(t, st, "app-block", `{"image":"traefik/whoami:v1.10"}`)

	r := New(st, fake, Options{Interval: 10 * time.Millisecond, RefreshInterval: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("Apply không được gọi")
	}

	t0 := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run trả %v, muốn nil khi ctx done", err)
		}
		t.Logf("OK — Run thoát sau %s kể từ cancel", time.Since(t0))
	case <-time.After(10 * time.Second):
		t.Fatal("Run KHÔNG thoát sau khi cancel ctx (kẹt trong Apply/SetStatus)")
	}
}
