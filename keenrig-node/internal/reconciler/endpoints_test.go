package reconciler

// Test T6c — reconciler ghi runtime.Observed.Endpoints vào store.

import (
	"context"
	"testing"
	"time"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/runtime"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

func epOpts() Options {
	return Options{
		Interval:        20 * time.Millisecond,
		RefreshInterval: 40 * time.Millisecond,
		BackoffBase:     20 * time.Millisecond,
		BackoffCap:      100 * time.Millisecond,
		Holder:          "box-ep",
		LeaseTTL:        30 * time.Second,
	}
}

func storeEndpoints(t *testing.T, st store.Store, id string) []store.Endpoint {
	t.Helper()
	return getApp(t, st, id).Endpoints
}

// Sau khi hội tụ, endpoint của mọi replica phải nằm trong store — đây là thứ
// T8 đọc để dựng upstream cho gateway.
func TestEndpointsWrittenAfterApply(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	createApp(t, st, "app-ep1", "traefik/whoami:v1.10")

	fake.setApplyFn(func(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
		return runtime.Observed{
			Phase:  contracts.AppStateRunning,
			Health: contracts.HealthUnknown,
			Endpoints: []runtime.Endpoint{
				{Host: "172.20.0.2", Port: 8080},
				{Host: "172.20.0.3", Port: 8080},
			},
		}, nil
	})

	r := New(st, fake, epOpts())
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "endpoint được ghi vào store", func() bool {
		return len(storeEndpoints(t, st, "app-ep1")) == 2
	})
	eps := storeEndpoints(t, st, "app-ep1")
	if eps[0] != (store.Endpoint{Host: "172.20.0.2", Port: 8080}) ||
		eps[1] != (store.Endpoint{Host: "172.20.0.3", Port: 8080}) {
		t.Fatalf("endpoint = %+v", eps)
	}
}

// Scale xuống phải LÀM MẤT endpoint thừa. Đây là chỗ dễ hỏng nhất: giữ lại
// upstream của replica đã chết nghĩa là gateway vẫn cân tải sang container
// không còn tồn tại, và người dùng thấy 502 ngắt quãng.
func TestEndpointsReplacedWholesale(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	createApp(t, st, "app-ep2", "traefik/whoami:v1.10")

	current := []runtime.Endpoint{
		{Host: "172.20.0.2", Port: 80},
		{Host: "172.20.0.3", Port: 80},
		{Host: "172.20.0.4", Port: 80},
	}
	fake.setApplyFn(func(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
		return runtime.Observed{Phase: contracts.AppStateRunning, Health: contracts.HealthUnknown, Endpoints: current}, nil
	})

	r := New(st, fake, epOpts())
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "3 endpoint ban đầu", func() bool {
		return len(storeEndpoints(t, st, "app-ep2")) == 3
	})

	// Scale 3 → 1: đổi desired để vòng hội tụ chạy lại.
	current = current[:1]
	if _, err := st.UpdateDesired(context.Background(), "app-ep2",
		[]byte(`{"image":"traefik/whoami:v1.10","resources":{"replicas":1}}`)); err != nil {
		t.Fatalf("UpdateDesired: %v", err)
	}

	waitFor(t, 5*time.Second, "endpoint thu về còn 1", func() bool {
		return len(storeEndpoints(t, st, "app-ep2")) == 1
	})
	if eps := storeEndpoints(t, st, "app-ep2"); eps[0].Host != "172.20.0.2" {
		t.Errorf("endpoint còn lại = %+v, muốn 172.20.0.2", eps)
	}
}

// Container tự restart đổi IP mà desired_rev KHÔNG đổi → vòng hội tụ không
// chạy lại. Nhịp refresh phải bắt được, nếu không gateway giữ upstream chết.
func TestEndpointsRefreshedWithoutRevChange(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	createApp(t, st, "app-ep3", "traefik/whoami:v1.10")

	fake.setApplyFn(func(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
		return runtime.Observed{
			Phase: contracts.AppStateRunning, Health: contracts.HealthUnknown,
			Endpoints: []runtime.Endpoint{{Host: "172.20.0.2", Port: 80}},
		}, nil
	})
	fake.setStatusFn(func(ctx context.Context, appID string) (runtime.Observed, error) {
		// IP mới sau khi container restart.
		return runtime.Observed{
			Phase: contracts.AppStateRunning, Health: contracts.HealthUnknown,
			Endpoints: []runtime.Endpoint{{Host: "172.20.0.9", Port: 80}},
		}, nil
	})

	r := New(st, fake, epOpts())
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "refresh cập nhật IP mới", func() bool {
		eps := storeEndpoints(t, st, "app-ep3")
		return len(eps) == 1 && eps[0].Host == "172.20.0.9"
	})

	app := getApp(t, st, "app-ep3")
	if app.DesiredRev != app.AppliedRev {
		t.Errorf("rev đã đổi (%d/%d) — test này phải chứng minh refresh chạy KHI rev không đổi",
			app.DesiredRev, app.AppliedRev)
	}
}

// Endpoint rác (thiếu host hoặc port ≤ 0) không được đẩy sang gateway.
func TestEndpointsDropInvalid(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	createApp(t, st, "app-ep4", "traefik/whoami:v1.10")

	fake.setApplyFn(func(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
		return runtime.Observed{
			Phase: contracts.AppStateRunning, Health: contracts.HealthUnknown,
			Endpoints: []runtime.Endpoint{
				{Host: "", Port: 80},          // thiếu host
				{Host: "172.20.0.5", Port: 0}, // thiếu port
				{Host: "172.20.0.6", Port: 80},
			},
		}, nil
	})

	r := New(st, fake, epOpts())
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "chỉ endpoint hợp lệ được ghi", func() bool {
		return len(storeEndpoints(t, st, "app-ep4")) == 1
	})
	if eps := storeEndpoints(t, st, "app-ep4"); eps[0].Host != "172.20.0.6" {
		t.Errorf("endpoint = %+v, muốn chỉ 172.20.0.6:80", eps)
	}
}
