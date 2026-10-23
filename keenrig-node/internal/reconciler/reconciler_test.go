package reconciler

// Unit test T6 — store SQLite thật + fakeRuntime (không cần Docker).
// Interval/backoff cỡ chục ms + poll-with-deadline, không sleep cứng dài.
// Helper dùng chung với integration_test.go: openStore / createApp / getApp /
// appStatus / hasEvent / waitFor / runReconciler.

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/resources"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// ---------- fakeRuntime ----------

// fakeRuntime thay được applyFn, đếm số lần Apply/Status, và giữ state
// ensure-style (map appID → spec đã apply) để kiểm chứng "không nhân đôi".
type fakeRuntime struct {
	mu       sync.Mutex
	applies  int
	statuses int
	state    map[string]runtime.AppSpec
	// eps — endpoint của lần Apply gần nhất, để Status mặc định trả về CÙNG
	// một sự thật với Apply (driver docker thật cũng vậy: cả hai đọc từ
	// container đang chạy). Fake mà Status luôn trả rỗng sẽ khiến nhịp refresh
	// xoá sạch endpoint vừa ghi — một hành vi không driver nào có.
	eps      map[string][]runtime.Endpoint
	applyFn  func(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error)
	statusFn func(ctx context.Context, appID string) (runtime.Observed, error)
}

func (f *fakeRuntime) setStatusFn(fn func(ctx context.Context, appID string) (runtime.Observed, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statusFn = fn
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{state: map[string]runtime.AppSpec{}, eps: map[string][]runtime.Endpoint{}}
}

func (f *fakeRuntime) setApplyFn(fn func(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applyFn = fn
}

func (f *fakeRuntime) applyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applies
}

func (f *fakeRuntime) statusCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.statuses
}

func (f *fakeRuntime) trackedApps() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.state)
}

// appliedRev trả rev của lần Apply thành công gần nhất cho app (0 nếu chưa có).
func (f *fakeRuntime) appliedRev(appID string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state[appID].DesiredRev
}

func (f *fakeRuntime) Apply(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
	f.mu.Lock()
	f.applies++
	fn := f.applyFn
	f.mu.Unlock()

	if fn != nil {
		obs, err := fn(ctx, spec)
		if err != nil {
			return obs, err
		}
		f.mu.Lock()
		f.state[spec.ID] = spec // ensure-style: ghi đè, gọi lại cùng spec là no-op
		f.eps[spec.ID] = obs.Endpoints
		f.mu.Unlock()
		return obs, nil
	}

	obs := runtime.Observed{
		Phase:        contracts.AppStateRunning,
		Health:       contracts.HealthUnknown,
		ContainerIDs: []string{"fake-" + spec.ID},
		Endpoints:    []runtime.Endpoint{{Host: "10.0.0.1", Port: 80}},
	}
	f.mu.Lock()
	f.state[spec.ID] = spec
	f.eps[spec.ID] = obs.Endpoints
	f.mu.Unlock()
	return obs, nil
}

func (f *fakeRuntime) Status(ctx context.Context, appID string) (runtime.Observed, error) {
	f.mu.Lock()
	f.statuses++
	fn := f.statusFn
	f.mu.Unlock()
	// Gọi fn NGOÀI lock (như Apply): fn tự do đụng lại fake mà không deadlock.
	if fn != nil {
		return fn(ctx, appID)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.state[appID]; !ok {
		return runtime.Observed{Phase: contracts.AppStateStopped, Health: contracts.HealthUnknown}, nil
	}
	return runtime.Observed{
		Phase:        contracts.AppStateRunning,
		Health:       contracts.HealthUnknown,
		ContainerIDs: []string{"fake-" + appID},
		Endpoints:    f.eps[appID],
	}, nil
}

func (f *fakeRuntime) Remove(ctx context.Context, appID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.state, appID)
	delete(f.eps, appID)
	return nil
}

// ResourceCaps — fake không thực thi hạn mức nào, và nói đúng như vậy.
//
// Khai một tập rỗng chứ không khai `ByDriver("docker")`: reconciler không được
// phép có hành vi khác nhau tuỳ vào việc runtime đỡ hạn mức nào, và một fake
// khai năng lực nó không có sẽ che mất chỗ nào đó phụ thuộc điều ngược lại.
func (f *fakeRuntime) ResourceCaps(context.Context) (resources.Caps, error) {
	return resources.Caps{}, nil
}

var _ runtime.Runtime = (*fakeRuntime)(nil)

// ---------- helper ----------

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

func createApp(t *testing.T, st store.Store, id, image string) *store.App {
	t.Helper()
	desired, err := json.Marshal(contracts.DesiredApp{Image: image})
	if err != nil {
		t.Fatal(err)
	}
	app := &store.App{ID: id, Slug: id, Desired: desired}
	if err := st.CreateApp(context.Background(), app); err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
	return app
}

// waitFor poll cond mỗi 10ms tới deadline; hết giờ → t.Fatal kèm what.
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

func getApp(t *testing.T, st store.Store, id string) *store.App {
	t.Helper()
	app, err := st.GetApp(context.Background(), id)
	if err != nil {
		t.Fatalf("GetApp: %v", err)
	}
	return app
}

// appStatus giải mã cột status của app thành contracts.AppStatus.
func appStatus(t *testing.T, st store.Store, id string) (*store.App, contracts.AppStatus) {
	t.Helper()
	app := getApp(t, st, id)
	var s contracts.AppStatus
	if len(app.Status) == 0 {
		return app, s
	}
	if err := json.Unmarshal(app.Status, &s); err != nil {
		t.Fatalf("unmarshal status %q: %v", app.Status, err)
	}
	return app, s
}

func hasEvent(t *testing.T, st store.Store, action, subject string) bool {
	t.Helper()
	evs, err := st.ListEvents(context.Background(), 200)
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

// runReconciler chạy Run trong goroutine; trả ctx và stop() (cancel + đợi
// thoát sạch). stop() idempotent, cũng được gọi tự động lúc cleanup.
func runReconciler(t *testing.T, r *Reconciler) (context.Context, func()) {
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
			case <-time.After(30 * time.Second):
				t.Error("Run không thoát sau khi cancel ctx")
			}
		})
	}
	t.Cleanup(stop)
	return ctx, stop
}

// ---------- RC-01 ----------

// TestReconcileConverges: app mới → applied_rev bắt kịp desired_rev, status
// running, có event app.reconciled; UpdateDesired → hội tụ tiếp rev 2.
func TestReconcileConverges(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	createApp(t, st, "app-conv", "traefik/whoami:v1.10")

	r := New(st, fake, Options{Interval: 10 * time.Millisecond, RefreshInterval: 20 * time.Millisecond})
	runReconciler(t, r)

	waitFor(t, 10*time.Second, "hội tụ rev 1", func() bool {
		return getApp(t, st, "app-conv").AppliedRev == 1
	})

	_, s := appStatus(t, st, "app-conv")
	if s.State != contracts.AppStateRunning {
		t.Errorf("state = %q, muốn %q", s.State, contracts.AppStateRunning)
	}
	if s.AppliedRev != 1 || s.DesiredRev != 1 {
		t.Errorf("status rev = applied %d/desired %d, muốn 1/1", s.AppliedRev, s.DesiredRev)
	}
	if !hasEvent(t, st, "app.reconciled", "app-conv") {
		t.Error("thiếu event app.reconciled")
	}
	if got := fake.appliedRev("app-conv"); got != 1 {
		t.Errorf("runtime thấy rev %d, muốn 1", got)
	}

	// Đổi desired → rev 2, phải hội tụ tiếp.
	desired, err := json.Marshal(contracts.DesiredApp{
		Image: "traefik/whoami:v1.10",
		Env:   map[string]string{"WHOAMI_NAME": "v2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rev, err := st.UpdateDesired(context.Background(), "app-conv", desired)
	if err != nil {
		t.Fatalf("UpdateDesired: %v", err)
	}
	if rev != 2 {
		t.Fatalf("UpdateDesired trả rev %d, muốn 2", rev)
	}

	waitFor(t, 10*time.Second, "hội tụ rev 2", func() bool {
		return getApp(t, st, "app-conv").AppliedRev == 2
	})
	if got := fake.appliedRev("app-conv"); got != 2 {
		t.Errorf("runtime thấy rev %d, muốn 2", got)
	}
	if _, s := appStatus(t, st, "app-conv"); s.State != contracts.AppStateRunning {
		t.Errorf("sau rev 2 state = %q, muốn running", s.State)
	}
}

// ---------- RC-02 ----------

// TestBackoffNoHotLoop: Apply lỗi mãi thì reconciler KHÔNG quay hot-loop —
// số lần Apply bị chặn bởi backoff mũ. Sửa applyFn thành OK → hội tụ lại.
func TestBackoffNoHotLoop(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	fake.setApplyFn(func(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
		return runtime.Observed{Phase: contracts.AppStateError}, context.DeadlineExceeded
	})
	createApp(t, st, "app-backoff", "traefik/whoami:v1.10")

	r := New(st, fake, Options{
		Interval:        10 * time.Millisecond,
		RefreshInterval: time.Hour, // tắt refresh tick cho khỏi nhiễu
		BackoffBase:     50 * time.Millisecond,
		BackoffCap:      200 * time.Millisecond,
	})
	runReconciler(t, r)

	// Đợi lần Apply đầu tiên để chắc reconciler đã chạy.
	waitFor(t, 10*time.Second, "Apply lần đầu", func() bool { return fake.applyCount() >= 1 })

	time.Sleep(600 * time.Millisecond)
	// Backoff 50,100,200,200,... → trong ~600ms tối đa ~6 lần (không phải ~60
	// như khi tick 10ms chạy tự do).
	if n := fake.applyCount(); n > 6 {
		t.Errorf("sau ~600ms có %d lần Apply — hot loop, backoff không hiệu lực (muốn ≤ 6)", n)
	}

	app := getApp(t, st, "app-backoff")
	if app.AppliedRev != 0 {
		t.Errorf("applied_rev = %d, muốn giữ 0 khi Apply lỗi", app.AppliedRev)
	}
	if _, s := appStatus(t, st, "app-backoff"); s.State != contracts.AppStateError {
		t.Errorf("state = %q, muốn error", s.State)
	}
	if !hasEvent(t, st, "app.reconcile_failed", "app-backoff") {
		t.Error("thiếu event app.reconcile_failed")
	}

	// Hết lỗi → phải hội tụ (backoff cap 200ms nên không chờ lâu).
	fake.setApplyFn(nil)
	waitFor(t, 10*time.Second, "hội tụ sau khi hết lỗi", func() bool {
		return getApp(t, st, "app-backoff").AppliedRev == 1
	})
	if _, s := appStatus(t, st, "app-backoff"); s.State != contracts.AppStateRunning {
		t.Errorf("state sau hồi phục = %q, muốn running", s.State)
	}
}

// ---------- RC-03 ----------

// TestCrashRecovery: reconciler bị cắt giữa lúc Apply (ctx cancel) → instance
// mới trên cùng store vẫn hội tụ, runtime không bị nhân đôi tài nguyên
// (state ensure-style vẫn đúng 1 entry).
func TestCrashRecovery(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	createApp(t, st, "app-crash", "traefik/whoami:v1.10")

	entered := make(chan struct{}, 1)
	// Instance 1: Apply block tới khi ctx bị cancel (deploy đang dở).
	fake.setApplyFn(func(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return runtime.Observed{Phase: contracts.AppStateError}, ctx.Err()
	})

	r1 := New(st, fake, Options{Interval: 10 * time.Millisecond, RefreshInterval: time.Hour})
	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		if err := r1.Run(ctx1); err != nil {
			t.Errorf("instance 1 Run trả lỗi: %v", err)
		}
	}()

	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		cancel1()
		t.Fatal("instance 1 không kịp vào Apply")
	}

	// "Crash": cancel ctx — backoff in-memory mất theo instance.
	cancel1()
	select {
	case <-done1:
	case <-time.After(30 * time.Second):
		t.Fatal("instance 1 không thoát sau cancel")
	}

	if app := getApp(t, st, "app-crash"); app.AppliedRev != 0 {
		t.Fatalf("applied_rev = %d, muốn 0 (Apply chưa xong)", app.AppliedRev)
	}

	// Instance 2 trên CÙNG store, Apply lành → phải hội tụ.
	fake.setApplyFn(nil)
	r2 := New(st, fake, Options{Interval: 10 * time.Millisecond, RefreshInterval: time.Hour})
	runReconciler(t, r2)

	waitFor(t, 10*time.Second, "instance 2 hội tụ", func() bool {
		return getApp(t, st, "app-crash").AppliedRev == 1
	})
	if _, s := appStatus(t, st, "app-crash"); s.State != contracts.AppStateRunning {
		t.Errorf("state = %q, muốn running", s.State)
	}
	if n := fake.trackedApps(); n != 1 {
		t.Errorf("runtime giữ %d app, muốn đúng 1 (không nhân đôi)", n)
	}
}

// ---------- panic per-app ----------

// TestPanicPerAppIsContained: rt.Apply PANIC với một app → panic được recover
// và quy về lỗi CỦA APP ĐÓ (status error + event app.reconcile_panicked +
// backoff), app khác trong CÙNG tick vẫn hội tụ, reconcileTick không panic ra
// ngoài. Lỗi vẫn được trả về để supervisor (§2.1.1) tái tạo module.
func TestPanicPerAppIsContained(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()

	var mu sync.Mutex
	applies := map[string]int{}
	count := func(id string) int {
		mu.Lock()
		defer mu.Unlock()
		return applies[id]
	}
	fake.setApplyFn(func(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
		mu.Lock()
		applies[spec.ID]++
		mu.Unlock()
		if spec.ID == "app-panic" {
			panic("driver bùm giữa Apply")
		}
		return runtime.Observed{
			Phase:        contracts.AppStateRunning,
			Health:       contracts.HealthUnknown,
			ContainerIDs: []string{"fake-" + spec.ID},
		}, nil
	})

	createApp(t, st, "app-panic", "traefik/whoami:v1.10") // tạo TRƯỚC → đứng đầu ORDER BY created_at
	time.Sleep(5 * time.Millisecond)
	createApp(t, st, "app-ok", "traefik/whoami:v1.10")

	r := New(st, fake, Options{
		Interval:        10 * time.Millisecond,
		RefreshInterval: time.Hour,
		BackoffBase:     200 * time.Millisecond,
		BackoffCap:      200 * time.Millisecond,
	})
	ctx := context.Background()

	// Tick 1: app-panic bùm nhưng KHÔNG được cắt ngang tick.
	err := r.reconcileTick(ctx)
	if err == nil {
		t.Error("reconcileTick nuốt im lặng panic — supervisor không bao giờ biết driver đã hỏng")
	}
	if app := getApp(t, st, "app-ok"); app.AppliedRev != 1 {
		t.Errorf("app-ok applied_rev = %d, muốn 1 — panic của app khác đã giết vòng lặp", app.AppliedRev)
	}
	if app, s := appStatus(t, st, "app-panic"); app.AppliedRev != 0 || s.State != contracts.AppStateError {
		t.Errorf("app-panic = applied_rev %d / state %q, muốn 0 / error", app.AppliedRev, s.State)
	} else if s.Message == "" {
		t.Error("app-panic status.message rỗng — mất nguyên nhân panic")
	}
	if !hasEvent(t, st, "app.reconcile_panicked", "app-panic") {
		t.Error("thiếu event app.reconcile_panicked")
	}

	// Tick 2 ngay sau đó: app-panic đang trong cửa sổ backoff → không Apply lại;
	// app-ok đã hội tụ nên cũng không bị đụng.
	if err := r.reconcileTick(ctx); err != nil {
		t.Errorf("tick 2 trả lỗi %v — app-panic phải bị backoff bỏ qua", err)
	}
	if n := count("app-panic"); n != 1 {
		t.Errorf("app-panic bị Apply %d lần — backoff sau panic không hiệu lực", n)
	}

	// Hết backoff + driver lành → hội tụ bình thường, backoff được xoá.
	fake.setApplyFn(nil)
	time.Sleep(250 * time.Millisecond)
	if err := r.reconcileTick(ctx); err != nil {
		t.Fatalf("tick 3: %v", err)
	}
	if app := getApp(t, st, "app-panic"); app.AppliedRev != 1 {
		t.Errorf("app-panic applied_rev = %d sau khi driver lành, muốn 1", app.AppliedRev)
	}
	if _, ok := r.backoff["app-panic"]; ok {
		t.Error("backoff của app-panic chưa được xoá sau khi hội tụ")
	}
}

// TestRefreshUpdatesStatus: app ĐÃ hội tụ vẫn được refresh tick gọi Status để
// cập nhật status/health (nền RC-04).
func TestRefreshUpdatesStatus(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	createApp(t, st, "app-refresh", "traefik/whoami:v1.10")

	r := New(st, fake, Options{Interval: 10 * time.Millisecond, RefreshInterval: 20 * time.Millisecond})
	runReconciler(t, r)

	waitFor(t, 10*time.Second, "hội tụ", func() bool {
		return getApp(t, st, "app-refresh").AppliedRev == 1
	})
	waitFor(t, 10*time.Second, "refresh tick gọi Status", func() bool {
		return fake.statusCount() > 0
	})
	if _, s := appStatus(t, st, "app-refresh"); s.State != contracts.AppStateRunning {
		t.Errorf("state sau refresh = %q, muốn running", s.State)
	}
}

// --- privops: dọn thư mục dữ liệu ở pha 2 của xoá ---------------------------------

// fakePriv ghi lại lời gọi, và tuỳ chọn trả lỗi.
type fakePriv struct {
	mu      sync.Mutex
	removed []string
	err     error
}

func (f *fakePriv) RemoveAppData(_ context.Context, appID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, appID)
	return f.err
}

func (f *fakePriv) list() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.removed...)
}

// markDeleted tạo app rồi đánh dấu xoá — bối cảnh chung của ba test dưới.
func markDeleted(t *testing.T, st store.Store, id string) {
	t.Helper()
	ctx := context.Background()
	app := &store.App{ID: id, Slug: id, Desired: json.RawMessage(`{"image":"nginx:1"}`)}
	if err := st.CreateApp(ctx, app); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteApp(ctx, id); err != nil {
		t.Fatal(err)
	}
}

// waitPurged đợi row biến mất hẳn (pha 2 xong).
func waitPurged(t *testing.T, st store.Store, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pending, err := st.ListAppsPendingDelete(context.Background())
		if err == nil && len(pending) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	pending, _ := st.ListAppsPendingDelete(context.Background())
	t.Fatalf("quá %s app vẫn kẹt ở trạng thái đang xoá: %+v — slug bị giữ mãi", timeout, pending)
}

// Thư mục dữ liệu phải được dọn khi app bị xoá — nếu không nó là rác vĩnh viễn
// mà không còn row nào nhắc rằng nó thuộc về ai.
func TestDeleteRemovesAppData(t *testing.T) {
	st := openStore(t)
	priv := &fakePriv{}
	markDeleted(t, st, "app-du-lieu")

	r := New(st, newFakeRuntime(), Options{Interval: 20 * time.Millisecond, Holder: "box-priv"}).
		WithPrivOps(priv)
	_, stop := runReconciler(t, r)
	defer stop()

	waitPurged(t, st, 5*time.Second)
	if got := priv.list(); len(got) != 1 || got[0] != "app-du-lieu" {
		t.Fatalf("RemoveAppData được gọi với %v, muốn [app-du-lieu]", got)
	}
}

// Dọn dữ liệu THẤT BẠI không được chặn Purge.
//
// Dữ liệu sót lại là rác tốn đĩa. Một app kẹt mãi ở "đang xoá" thì tệ hơn: nó
// giữ luôn slug, và người dùng không tạo lại được app cùng tên.
func TestDataCleanupFailureDoesNotBlockPurge(t *testing.T) {
	st := openStore(t)
	priv := &fakePriv{err: errors.New("sudoers chưa cài")}
	markDeleted(t, st, "app-loi-don")

	r := New(st, newFakeRuntime(), Options{Interval: 20 * time.Millisecond, Holder: "box-priv"}).
		WithPrivOps(priv)
	_, stop := runReconciler(t, r)
	defer stop()

	waitPurged(t, st, 5*time.Second)
	// Nhưng phải để lại VẾT: rác trên đĩa mà không ai biết là rác không dọn được.
	if !hasEvent(t, st, "app.data_cleanup_failed", "app-loi-don") {
		t.Error("không có event app.data_cleanup_failed — rác trên đĩa hoàn toàn im lặng")
	}
}

// priv nil (dev, test, sudoers chưa cài) KHÔNG được làm hỏng luồng xoá.
func TestDeleteWorksWithoutPrivOps(t *testing.T) {
	st := openStore(t)
	markDeleted(t, st, "app-khong-priv")

	// KHÔNG gọi WithPrivOps.
	r := New(st, newFakeRuntime(), Options{Interval: 20 * time.Millisecond, Holder: "box-priv"})
	_, stop := runReconciler(t, r)
	defer stop()

	waitPurged(t, st, 5*time.Second)
}

// lastSpec trả AppSpec của lần Apply gần nhất cho app — để test khẳng định
// những gì THẬT SỰ tới runtime, không chỉ những gì ta nghĩ đã truyền.
func (f *fakeRuntime) lastSpec(appID string) (runtime.AppSpec, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	spec, ok := f.state[appID]
	return spec, ok
}
