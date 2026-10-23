package reconciler

// Test T9 phía vòng hội tụ — PX-02 "hai đường theo năng lực gateway".

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/certs"
	"github.com/keenrig/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig/keenrig/keenrig-node/internal/proxy"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
)

// noACMEProxy — gateway kiểu nginx: định tuyến được nhưng KHÔNG tự xin cert.
type noACMEProxy struct{ fakeProxy }

func (p *noACMEProxy) Capabilities(context.Context) (proxy.Caps, error) {
	return proxy.Caps{proxy.CapCertUpload: true, proxy.CapLoadBalance: true}, nil
}

type countingIssuer struct {
	mu    sync.Mutex
	calls []string
	fail  map[string]bool
}

func (c *countingIssuer) Name() string { return "đếm" }

func (c *countingIssuer) Issue(_ context.Context, fqdn string) (certs.Bundle, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, fqdn)
	if c.fail[fqdn] {
		return certs.Bundle{}, errors.New("DNS chưa trỏ")
	}
	return certs.Bundle{
		FQDN:     fqdn,
		CertPEM:  []byte("cert"),
		KeyPEM:   []byte("key"),
		NotAfter: time.Now().Add(90 * 24 * time.Hour),
	}, nil
}

func (c *countingIssuer) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.calls)
}

// Gateway CÓ CapACME (caddy) → module certs không được chạy một dòng nào, và
// site đi đường acme_by_gateway.
func TestGatewayWithACMESkipsCertModule(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	px := &fakeProxy{} // Capabilities mặc định có CapACME
	iss := &countingIssuer{}
	createApp(t, st, "app-tls1", "traefik/whoami:v1.10")
	addDomain(t, st, "app-tls1", "a.keenrig.com", true)
	withEndpoints(fake, runtime.Endpoint{Host: "10.0.0.1", Port: 80})

	m := certs.New(st, paths.New(t.TempDir()), iss, certs.Options{})
	r := New(st, fake, proxyOpts()).WithProxy(px).WithCerts(m)
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "site lên gateway", func() bool { return len(px.last()) == 1 })
	if got := px.last()[0].TLS.Mode; got != proxy.TLSACMEByGateway {
		t.Errorf("TLS.Mode = %q, muốn acme_by_gateway", got)
	}
	time.Sleep(200 * time.Millisecond)
	if iss.count() != 0 {
		t.Errorf("gateway tự xin được cert mà ta vẫn gọi CA %d lần", iss.count())
	}
}

// Gateway KHÔNG có CapACME (nginx) → phải xin cert TRƯỚC, rồi site đi đường
// cert_upload với CertRef đã điền.
func TestGatewayWithoutACMEIssuesCerts(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	px := &noACMEProxy{}
	iss := &countingIssuer{}
	createApp(t, st, "app-tls2", "traefik/whoami:v1.10")
	addDomain(t, st, "app-tls2", "b.keenrig.com", true)
	withEndpoints(fake, runtime.Endpoint{Host: "10.0.0.2", Port: 80})

	m := certs.New(st, paths.New(t.TempDir()), iss, certs.Options{})
	r := New(st, fake, proxyOpts()).WithProxy(px).WithCerts(m)
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "site lên gateway kèm cert", func() bool {
		sites := px.last()
		return len(sites) == 1 && sites[0].TLS.Mode == proxy.TLSProvided
	})
	s := px.last()[0]
	if s.TLS.CertRef == "" {
		t.Error("TLSProvided mà không có CertRef — gateway sẽ không biết đọc cert ở đâu")
	}
	if iss.count() == 0 {
		t.Error("gateway không có ACME mà ta cũng không xin cert")
	}

	// cert_ref phải được ghi ngược vào app_domains để UI và lần chạy sau thấy.
	ds, err := st.ListDomains(context.Background(), "app-tls2")
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 1 || ds[0].CertRef == "" {
		t.Errorf("app_domains.cert_ref chưa được ghi: %+v", ds)
	}
}

// Domain chưa xin được cert KHÔNG được đẩy lên gateway: với nginx, thiếu một
// file cert làm cả tập cấu hình bị từ chối, tức là một domain sai DNS đánh sập
// mọi site còn lại.
func TestDomainWithoutCertIsNotPushed(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	px := &noACMEProxy{}
	iss := &countingIssuer{fail: map[string]bool{"xau.keenrig.com": true}}

	createApp(t, st, "app-tot", "traefik/whoami:v1.10")
	addDomain(t, st, "app-tot", "tot.keenrig.com", true)
	createApp(t, st, "app-xau", "traefik/whoami:v1.10")
	addDomain(t, st, "app-xau", "xau.keenrig.com", true)
	withEndpoints(fake, runtime.Endpoint{Host: "10.0.0.3", Port: 80})

	m := certs.New(st, paths.New(t.TempDir()), iss, certs.Options{})
	r := New(st, fake, proxyOpts()).WithProxy(px).WithCerts(m)
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "domain lành lên gateway", func() bool {
		for _, s := range px.last() {
			if s.FQDN == "tot.keenrig.com" {
				return true
			}
		}
		return false
	})
	for _, s := range px.last() {
		if s.FQDN == "xau.keenrig.com" {
			t.Fatalf("đẩy site chưa có cert lên gateway: %+v", s)
		}
	}
}

// Gateway không có ACME và cũng KHÔNG có issuer → không site nào lên gateway,
// nhưng box vẫn sống và app vẫn hội tụ.
func TestNoACMENoIssuerStillRuns(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	px := &noACMEProxy{}
	createApp(t, st, "app-tls4", "traefik/whoami:v1.10")
	addDomain(t, st, "app-tls4", "d.keenrig.com", true)
	withEndpoints(fake, runtime.Endpoint{Host: "10.0.0.4", Port: 80})

	r := New(st, fake, proxyOpts()).WithProxy(px) // KHÔNG WithCerts
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "app vẫn hội tụ", func() bool {
		app := getApp(t, st, "app-tls4")
		return app.AppliedRev == app.DesiredRev
	})
	waitFor(t, 5*time.Second, "có gọi Apply", func() bool { return px.count() > 0 })
	if sites := px.last(); len(sites) != 0 {
		t.Errorf("đẩy %d site lên gateway dù không có cách nào lấy cert: %+v", len(sites), sites)
	}
}
