package reconciler

// Admin của CHÍNH box phải có site riêng theo tên miền gốc do cloud cấp —
// không có matcher tên thì gateway không xin chứng chỉ, và `https://admin.<env>`
// nhận TLS alert 80 trên mọi máy có IP công khai (đo được 2026-10-02, case 1).

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/proxy"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/runtime"
)

var adminUp = proxy.Upstream{Host: "127.0.0.1", Port: 8080}

func siteByFQDN(sites []proxy.Site, fqdn string) *proxy.Site {
	for i := range sites {
		if sites[i].FQDN == fqdn {
			return &sites[i]
		}
	}
	return nil
}

// Máy vừa cài, CHƯA có app nào: Admin vẫn phải lên gateway với ACME.
func TestPlatformAdminSiteWithoutAnyApp(t *testing.T) {
	st := openStore(t)
	px := &fakeProxy{}
	r := New(st, newFakeRuntime(), proxyOpts()).WithProxy(px).
		WithPlatformHosts(adminUp, func(context.Context) []string {
			return []string{"e1.iot.keenrig.com", "admin.e1.iot.keenrig.com"}
		})
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "site Admin được đẩy sang gateway", func() bool {
		return siteByFQDN(px.last(), "admin.e1.iot.keenrig.com") != nil
	})
	s := siteByFQDN(px.last(), "admin.e1.iot.keenrig.com")
	if len(s.Upstreams) != 1 || s.Upstreams[0] != adminUp {
		t.Errorf("Upstreams = %+v, muốn đúng upstream Admin", s.Upstreams)
	}
	if s.TLS.Mode != proxy.TLSACMEByGateway {
		t.Errorf("TLS.Mode = %q — không ACME thì không có chứng chỉ thật", s.TLS.Mode)
	}
	if s.AppID != PlatformSiteOwner {
		t.Errorf("AppID = %q, muốn %q", s.AppID, PlatformSiteOwner)
	}
	if siteByFQDN(px.last(), "e1.iot.keenrig.com") == nil {
		t.Error("tên gốc của env không lên gateway — link env trên Console sẽ chết TLS")
	}
}

// Tên miền gốc đổi (cloud cấp lại) → tick sau route đổi theo, không restart.
func TestPlatformHostsFollowTheCloud(t *testing.T) {
	st := openStore(t)
	px := &fakeProxy{}
	var mu sync.Mutex
	host := "admin.old.iot.keenrig.com"
	r := New(st, newFakeRuntime(), proxyOpts()).WithProxy(px).
		WithPlatformHosts(adminUp, func(context.Context) []string {
			mu.Lock()
			defer mu.Unlock()
			return []string{host}
		})
	_, stop := runReconciler(t, r)
	defer stop()
	waitFor(t, 5*time.Second, "tên cũ", func() bool { return siteByFQDN(px.last(), "admin.old.iot.keenrig.com") != nil })
	mu.Lock()
	host = "admin.new.iot.keenrig.com"
	mu.Unlock()
	waitFor(t, 5*time.Second, "tên mới thay tên cũ", func() bool {
		l := px.last()
		return siteByFQDN(l, "admin.new.iot.keenrig.com") != nil && siteByFQDN(l, "admin.old.iot.keenrig.com") == nil
	})
}

// App đã giữ một tên thì app thắng — không đẩy hai site cùng FQDN.
func TestPlatformHostYieldsToAnApp(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	px := &fakeProxy{}
	createApp(t, st, "app-root", "traefik/whoami:v1.10")
	addDomain(t, st, "app-root", "e1.iot.keenrig.com", true)
	withEndpoints(fake, runtime.Endpoint{Host: "172.20.0.9", Port: 80})
	r := New(st, fake, proxyOpts()).WithProxy(px).
		WithPlatformHosts(adminUp, func(context.Context) []string {
			return []string{"e1.iot.keenrig.com", "admin.e1.iot.keenrig.com"}
		})
	_, stop := runReconciler(t, r)
	defer stop()
	waitFor(t, 5*time.Second, "app + admin", func() bool {
		l := px.last()
		return siteByFQDN(l, "admin.e1.iot.keenrig.com") != nil && siteByFQDN(l, "e1.iot.keenrig.com") != nil
	})
	n := 0
	for _, s := range px.last() {
		if s.FQDN == "e1.iot.keenrig.com" {
			n++
			if s.AppID != "app-root" {
				t.Errorf("tên của app bị Admin chiếm: AppID = %q", s.AppID)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d site cùng FQDN e1.iot.keenrig.com, muốn 1", n)
	}
}
