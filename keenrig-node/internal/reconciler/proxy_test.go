package reconciler

// Test T8 phía vòng hội tụ: store (app_domains + apps.endpoints) → proxy.Apply.

import (
	"context"
	"sync"
	"testing"
	"time"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/proxy"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/runtime"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// fakeProxy ghi lại mọi lần Apply.
type fakeProxy struct {
	mu      sync.Mutex
	applies [][]proxy.Site
	err     error
}

func (f *fakeProxy) Name() string { return "fake" }

func (f *fakeProxy) Capabilities(context.Context) (proxy.Caps, error) {
	return proxy.Caps{proxy.CapACME: true, proxy.CapLoadBalance: true}, nil
}

func (f *fakeProxy) Apply(_ context.Context, desired []proxy.Site) (proxy.Report, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies = append(f.applies, append([]proxy.Site(nil), desired...))
	if f.err != nil {
		return proxy.Report{}, f.err
	}
	rep := proxy.Report{}
	for _, s := range desired {
		rep.Applied = append(rep.Applied, s.FQDN)
	}
	return rep, nil
}

func (f *fakeProxy) Status(context.Context) ([]proxy.Site, error) { return nil, nil }

func (f *fakeProxy) last() []proxy.Site {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.applies) == 0 {
		return nil
	}
	return f.applies[len(f.applies)-1]
}

func (f *fakeProxy) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applies)
}

var _ proxy.Controller = (*fakeProxy)(nil)

func proxyOpts() Options {
	return Options{
		Interval:        20 * time.Millisecond,
		RefreshInterval: 40 * time.Millisecond,
		BackoffBase:     20 * time.Millisecond,
		BackoffCap:      100 * time.Millisecond,
		Holder:          "box-px",
		LeaseTTL:        30 * time.Second,
	}
}

func addDomain(t *testing.T, st store.Store, appID, fqdn string, primary bool) {
	t.Helper()
	if err := st.AddDomain(context.Background(), &store.Domain{AppID: appID, FQDN: fqdn, IsPrimary: primary}); err != nil {
		t.Fatalf("AddDomain %s: %v", fqdn, err)
	}
}

func withEndpoints(fake *fakeRuntime, eps ...runtime.Endpoint) {
	fake.setApplyFn(func(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
		return runtime.Observed{Phase: contracts.AppStateRunning, Health: contracts.HealthUnknown, Endpoints: eps}, nil
	})
}

// PX-01 — app hội tụ xong thì route được đẩy sang gateway, upstream đúng endpoint.
func TestProxyGetsSiteAfterConverge(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	px := &fakeProxy{}
	createApp(t, st, "app-px1", "traefik/whoami:v1.10")
	addDomain(t, st, "app-px1", "a.keenrig.com", true)
	withEndpoints(fake, runtime.Endpoint{Host: "172.20.0.2", Port: 8080})

	r := New(st, fake, proxyOpts()).WithProxy(px)
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "site được đẩy sang gateway", func() bool {
		sites := px.last()
		return len(sites) == 1 && sites[0].FQDN == "a.keenrig.com"
	})
	s := px.last()[0]
	if len(s.Upstreams) != 1 || s.Upstreams[0].Host != "172.20.0.2" || s.Upstreams[0].Port != 8080 {
		t.Errorf("Upstreams = %+v", s.Upstreams)
	}
	if s.AppID != "app-px1" {
		t.Errorf("AppID = %q — thiếu nó thì driver không gắn được nhãn chủ sở hữu", s.AppID)
	}
	if s.TLS.Mode != proxy.TLSACMEByGateway {
		t.Errorf("TLS.Mode = %q, muốn acme_by_gateway", s.TLS.Mode)
	}
}

// App CHƯA có endpoint (chưa deploy xong / mọi replica chết) thì domain của nó
// KHÔNG được đẩy sang gateway: site không upstream cho 502, còn không có site
// thì catch-all trả 404 — 404 nói đúng sự thật hơn.
func TestProxySkipsAppWithoutEndpoints(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	px := &fakeProxy{}
	createApp(t, st, "app-px2", "traefik/whoami:v1.10")
	addDomain(t, st, "app-px2", "b.keenrig.com", true)
	// Apply thành công nhưng KHÔNG trả endpoint nào.
	withEndpoints(fake)

	r := New(st, fake, proxyOpts()).WithProxy(px)
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "có ít nhất một lần Apply", func() bool { return px.count() > 0 })
	time.Sleep(200 * time.Millisecond)
	for _, sites := range px.applies {
		for _, s := range sites {
			if s.FQDN == "b.keenrig.com" {
				t.Fatalf("đẩy site không upstream sang gateway: %+v", s)
			}
		}
	}
}

// Xoá app → route phải biến mất khỏi gateway (CASCADE + level-triggered).
func TestProxyRemovesSiteAfterAppDeleted(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	fake := newFakeRuntime()
	px := &fakeProxy{}
	createApp(t, st, "app-px3", "traefik/whoami:v1.10")
	addDomain(t, st, "app-px3", "c.keenrig.com", true)
	withEndpoints(fake, runtime.Endpoint{Host: "172.20.0.5", Port: 80})

	r := New(st, fake, proxyOpts()).WithProxy(px)
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "site lên gateway", func() bool { return len(px.last()) == 1 })

	if err := st.DeleteApp(ctx, "app-px3"); err != nil {
		t.Fatalf("DeleteApp: %v", err)
	}
	waitFor(t, 5*time.Second, "site rời gateway sau khi xoá app", func() bool {
		return len(px.last()) == 0
	})
	// Và vẫn phải GỌI Apply với tập rỗng — không gọi thì route mồ côi ở lại vĩnh viễn.
	if px.count() < 2 {
		t.Errorf("chỉ có %d lần Apply — phải có lần gọi với tập rỗng", px.count())
	}
}

// Không có gì đổi thì KHÔNG gọi lại Apply: mỗi lần Apply là một lời gọi mạng +
// ghi cấu hình gateway, gọi mỗi tick sẽ làm log gateway ngập và che lần đổi thật.
func TestProxyNoRedundantApply(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	px := &fakeProxy{}
	createApp(t, st, "app-px4", "traefik/whoami:v1.10")
	addDomain(t, st, "app-px4", "d.keenrig.com", true)
	withEndpoints(fake, runtime.Endpoint{Host: "172.20.0.7", Port: 80})

	r := New(st, fake, proxyOpts()).WithProxy(px)
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "site lên gateway", func() bool { return len(px.last()) == 1 })
	n := px.count()
	// Nhịp refresh 40ms → khoảng 10 lượt trong 400ms. Không có gì đổi nên
	// KHÔNG được có thêm lần Apply nào.
	time.Sleep(400 * time.Millisecond)
	if got := px.count(); got != n {
		t.Errorf("Apply chạy thêm %d lần dù không có gì đổi", got-n)
	}
}

// Apply lỗi → lần sau phải THỬ LẠI chính tập đó (không cache tập lỗi).
func TestProxyRetriesAfterApplyError(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	px := &fakeProxy{err: context.DeadlineExceeded}
	createApp(t, st, "app-px5", "traefik/whoami:v1.10")
	addDomain(t, st, "app-px5", "e.keenrig.com", true)
	withEndpoints(fake, runtime.Endpoint{Host: "172.20.0.8", Port: 80})

	r := New(st, fake, proxyOpts()).WithProxy(px)
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "Apply được gọi lại sau lỗi", func() bool { return px.count() >= 3 })
	if !hasEvent(t, st, "proxy.apply_failed", "") {
		t.Error("thiếu event proxy.apply_failed")
	}

	// Hết lỗi → hội tụ và ghi event thành công.
	px.mu.Lock()
	px.err = nil
	px.mu.Unlock()
	waitFor(t, 5*time.Second, "Apply thành công sau khi gateway lành", func() bool {
		return hasEvent(t, st, "proxy.applied", "")
	})
}

// Không cấu hình gateway (proxy == nil) thì box vẫn phải chạy bình thường.
func TestProxyNilStillConverges(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	createApp(t, st, "app-px6", "traefik/whoami:v1.10")
	addDomain(t, st, "app-px6", "f.keenrig.com", true)

	r := New(st, fake, proxyOpts()) // KHÔNG WithProxy
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "app vẫn hội tụ khi chưa có gateway", func() bool {
		app := getApp(t, st, "app-px6")
		return app.AppliedRev == app.DesiredRev
	})
}
