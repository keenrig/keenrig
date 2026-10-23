package reconciler

// Test T6b — lease reconciler (LS-01/LS-02) và thu hồi job quá hạn (LS-03).
// Dùng store SQLite thật + fakeRuntime; TTL cỡ giây để test không phải chờ lâu.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/runtime"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// leaseOpts — nhịp nhanh + TTL ngắn, vẫn giữ đúng bất đẳng thức TTL > renew +
// thời gian Apply lâu nhất (fakeRuntime Apply gần như tức thời).
func leaseOpts(holder string, ttl time.Duration) Options {
	return Options{
		Interval:        20 * time.Millisecond,
		RefreshInterval: 50 * time.Millisecond,
		BackoffBase:     20 * time.Millisecond,
		BackoffCap:      100 * time.Millisecond,
		Holder:          holder,
		LeaseTTL:        ttl,
	}
}

// LS-01 — hai reconciler cùng một store, cùng một "dockerd": chỉ MỘT được apply.
//
// Đây là bài kiểm quan trọng nhất của T6b. Trước khi có lease, cả hai cùng thấy
// app lệch rev và cùng gọi Apply — fakeRuntime sẽ đếm được nhiều hơn 1 lần cho
// cùng một rev.
func TestLeaseOnlyOneReconcilerApplies(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	createApp(t, st, "app-ls1", "traefik/whoami:v1.10")

	// applyLog ghi lại (appID, rev) MỖI lần Apply được gọi — kể cả lần trùng.
	var (
		mu       sync.Mutex
		applyLog []int64
	)
	fake.setApplyFn(func(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
		mu.Lock()
		applyLog = append(applyLog, spec.DesiredRev)
		mu.Unlock()
		// Apply chậm một chút để hai reconciler có cửa sổ chồng lên nhau thật.
		time.Sleep(30 * time.Millisecond)
		return runtime.Observed{Phase: "running", Health: "unknown"}, nil
	})

	a := New(st, fake, leaseOpts("box-A", 2*time.Second))
	b := New(st, fake, leaseOpts("box-B", 2*time.Second))
	_, stopA := runReconciler(t, a)
	_, stopB := runReconciler(t, b)

	waitFor(t, 5*time.Second, "app hội tụ", func() bool {
		app := getApp(t, st, "app-ls1")
		return app.AppliedRev == app.DesiredRev
	})
	// Để cả hai chạy thêm vài chục tick — nếu lease hỏng, kẻ thua sẽ apply chèn vào đây.
	time.Sleep(500 * time.Millisecond)
	stopA()
	stopB()

	mu.Lock()
	defer mu.Unlock()
	if len(applyLog) != 1 {
		t.Fatalf("Apply được gọi %d lần (%v), muốn đúng 1 — hai reconciler cùng lái runtime", len(applyLog), applyLog)
	}

	// Đúng một trong hai giữ lease, và có event lease.acquired.
	if !hasEvent(t, st, "lease.acquired", store.LeaseReconciler) {
		t.Error("thiếu event lease.acquired")
	}
}

// LS-02 — chủ nhả lease lúc dừng sạch thì box kia vào việc NGAY, không phải chờ
// hết TTL. Đây chính là cửa sổ OTA: box cũ drain xong, box mới tiếp quản.
func TestLeaseHandoverOnCleanShutdown(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()

	// TTL dài hẳn: nếu handover phải chờ hết hạn thì test này sẽ timeout —
	// tức là đúng thứ ta muốn bắt.
	a := New(st, fake, leaseOpts("box-A", 60*time.Second))
	_, stopA := runReconciler(t, a)

	createApp(t, st, "app-ls2a", "traefik/whoami:v1.10")
	waitFor(t, 5*time.Second, "box-A hội tụ app đầu", func() bool {
		app := getApp(t, st, "app-ls2a")
		return app.AppliedRev == app.DesiredRev
	})

	l, err := st.GetLease(context.Background(), store.LeaseReconciler)
	if err != nil || l.Holder != "box-A" {
		t.Fatalf("GetLease = (%+v, %v), muốn box-A", l, err)
	}

	stopA() // dừng sạch → releaseLease

	if _, err := st.GetLease(context.Background(), store.LeaseReconciler); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("sau khi box-A dừng sạch, lease vẫn còn (%v) — box mới sẽ phải chờ hết TTL", err)
	}

	b := New(st, fake, leaseOpts("box-B", 60*time.Second))
	_, stopB := runReconciler(t, b)
	defer stopB()

	createApp(t, st, "app-ls2b", "traefik/whoami:v1.10")
	waitFor(t, 5*time.Second, "box-B tiếp quản và hội tụ app thứ hai", func() bool {
		app := getApp(t, st, "app-ls2b")
		return app.AppliedRev == app.DesiredRev
	})
}

// LS-02 (nhánh chủ CHẾT, không nhả): box kia phải chờ hết TTL rồi mới nhận, và
// KHÔNG có khoảng nào hai bên cùng làm việc.
func TestLeaseHandoverAfterTTLExpiry(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()

	// Giả lập box-A chết: giành lease trực tiếp qua store rồi không bao giờ gia hạn.
	dead, err := st.AcquireLease(ctx, store.LeaseReconciler, "box-A-đã-chết", 2*time.Second)
	if err != nil {
		t.Fatalf("AcquireLease giả lập: %v", err)
	}

	fake := newFakeRuntime()
	createApp(t, st, "app-ls3", "traefik/whoami:v1.10")
	b := New(st, fake, leaseOpts("box-B", 5*time.Second))
	_, stop := runReconciler(t, b)
	defer stop()

	// Trong lúc lease của box-A còn hạn, box-B phải ĐỨNG IM.
	time.Sleep(700 * time.Millisecond)
	if n := fake.applyCount(); n != 0 {
		t.Fatalf("box-B đã Apply %d lần khi lease còn thuộc box-A", n)
	}
	if app := getApp(t, st, "app-ls3"); app.AppliedRev != 0 {
		t.Fatalf("applied_rev = %d khi chưa có lease, muốn 0", app.AppliedRev)
	}

	// Sau khi lease hết hạn, box-B nhận và hội tụ.
	waitFor(t, 10*time.Second, "box-B nhận lease sau TTL và hội tụ", func() bool {
		app := getApp(t, st, "app-ls3")
		return app.AppliedRev == app.DesiredRev
	})

	got, err := st.GetLease(ctx, store.LeaseReconciler)
	if err != nil {
		t.Fatalf("GetLease: %v", err)
	}
	if got.Holder != "box-B" {
		t.Errorf("holder = %q, muốn box-B", got.Holder)
	}
	// Đổi chủ phải để lại dấu trên fencing token.
	if got.Token <= dead.Token {
		t.Errorf("token = %d, muốn > %d (đổi chủ phải tăng token)", got.Token, dead.Token)
	}
}

// Mất lease giữa chừng (box khác cướp được vì mình treo quá lâu) → dừng chạm
// runtime, ghi event lease.lost. Không được chết, không được làm supervisor
// recycle module: box thua cuộc phải nằm im chờ.
func TestLeaseLostStopsTouchingRuntime(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	fake := newFakeRuntime()
	createApp(t, st, "app-ls4", "traefik/whoami:v1.10")

	r := New(st, fake, leaseOpts("box-A", 2*time.Second))
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "box-A hội tụ", func() bool {
		app := getApp(t, st, "app-ls4")
		return app.AppliedRev == app.DesiredRev
	})

	// Cướp lease bằng cách xoá rồi giành lại dưới tên khác — mô phỏng đúng cảnh
	// box-A treo lâu, lease hết hạn và box-B hợp pháp nhận.
	l, err := st.GetLease(ctx, store.LeaseReconciler)
	if err != nil {
		t.Fatalf("GetLease: %v", err)
	}
	if err := st.ReleaseLease(ctx, store.LeaseReconciler, l.Holder, l.Token); err != nil {
		t.Fatalf("ReleaseLease: %v", err)
	}
	if _, err := st.AcquireLease(ctx, store.LeaseReconciler, "box-B", time.Minute); err != nil {
		t.Fatalf("box-B giành lease: %v", err)
	}

	waitFor(t, 5*time.Second, "box-A phát hiện mất lease", func() bool {
		return hasEvent(t, st, "lease.lost", store.LeaseReconciler)
	})

	// Từ giờ box-A không được chạm runtime nữa: tạo app mới, nó phải nằm im.
	before := fake.applyCount()
	createApp(t, st, "app-ls4b", "traefik/whoami:v1.10")
	time.Sleep(500 * time.Millisecond)
	if got := fake.applyCount(); got != before {
		t.Errorf("box-A vẫn Apply sau khi mất lease: %d → %d", before, got)
	}
	if app := getApp(t, st, "app-ls4b"); app.AppliedRev != 0 {
		t.Errorf("applied_rev = %d, muốn 0 — box-A không được reconcile khi mất lease", app.AppliedRev)
	}

	// Lease vẫn thuộc box-B: box-A KHÔNG được cướp lại.
	if got, err := st.GetLease(ctx, store.LeaseReconciler); err != nil || got.Holder != "box-B" {
		t.Errorf("GetLease = (%+v, %v), muốn giữ nguyên box-B", got, err)
	}
}

// LS-03 ở tầng vòng lặp: reconciler giữ lease thu hồi job của worker đã chết.
func TestReclaimExpiredJobsInLoop(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	fake := newFakeRuntime()

	if _, err := st.EnqueueJob(ctx, "backup", nil, nil); err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}
	// Worker claim với hạn 1 giây rồi "chết".
	if _, err := st.ClaimJobAs(ctx, nil, "worker-đã-chết", time.Second); err != nil {
		t.Fatalf("ClaimJobAs: %v", err)
	}

	r := New(st, fake, leaseOpts("box-A", 10*time.Second))
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 10*time.Second, "job quá hạn được thu hồi", func() bool {
		return hasEvent(t, st, "jobs.reclaimed", "")
	})

	job, err := st.ClaimJobAs(ctx, nil, "worker-mới", time.Minute)
	if err != nil {
		t.Fatalf("ClaimJobAs sau thu hồi: %v", err)
	}
	if job.Attempt != 0 {
		t.Errorf("Attempt = %d, muốn 0 — thu hồi không phải một lần thất bại", job.Attempt)
	}
}

// LeaseDisabled là cửa hậu cho test đơn vị: phải thật sự bỏ qua lease, và
// KHÔNG được để lại lease trong DB (nếu không, test khác dùng chung DB sẽ tắc).
func TestLeaseDisabledSkipsLease(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	createApp(t, st, "app-ls5", "traefik/whoami:v1.10")

	opts := leaseOpts("box-A", time.Second)
	opts.LeaseDisabled = true
	r := New(st, fake, opts)
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "hội tụ khi tắt lease", func() bool {
		app := getApp(t, st, "app-ls5")
		return app.AppliedRev == app.DesiredRev
	})
	if _, err := st.GetLease(context.Background(), store.LeaseReconciler); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("LeaseDisabled nhưng vẫn ghi lease vào DB: %v", err)
	}
}
