package apps_test

import (
	"context"
	"strings"
	"testing"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/apps"
	"github.com/keenrig/keenrig/keenrig-node/internal/domains"
)

// Release v0.3.8: app chạy ở địa chỉ tạm, tên miền riêng sẵn sàng thì app tự
// dời sang. Tên khách tự gắn (ngoài tên gốc cũ) không bị đụng.
func TestRebaseDomainsMovesAppsUnderTheOldParent(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	svc := apps.New(st, domains.New(st), apps.Options{GatewayCaps: gatewayCaps(t, "caddy")})
	img := "ghcr.io/acme/web@sha256:" + strings.Repeat("a", 64)
	const tmp = "shop.acme.keenrig.com"

	wp, err := svc.Create(ctx, apps.CreateInput{Slug: "wp", Desired: desiredJSON(t, contracts.DesiredApp{
		Image: img, Domains: []string{tmp, "blog.khachtu.vn"},
	})})
	if err != nil {
		t.Fatal(err)
	}
	n8n, err := svc.Create(ctx, apps.CreateInput{Slug: "n8n", Desired: desiredJSON(t, contracts.DesiredApp{
		Image: img, Domains: []string{"n8n." + tmp},
	})})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ { // lần hai: idempotent
		if err := svc.RebaseDomains(ctx, tmp, "cuahangacme.com"); err != nil {
			t.Fatalf("RebaseDomains #%d: %v", i+1, err)
		}
	}

	want := map[string][]string{
		wp.ID:  {"cuahangacme.com", "blog.khachtu.vn"},
		n8n.ID: {"n8n.cuahangacme.com"},
	}
	for id, names := range want {
		ds, err := svc.Domains(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, d := range ds {
			got[d.FQDN] = true
		}
		for _, n := range names {
			if !got[n] {
				t.Errorf("app %s thiếu %s, có %v", id, n, got)
			}
		}
		if len(ds) != len(names) {
			t.Errorf("app %s có %d tên, muốn %d: %v", id, len(ds), len(names), got)
		}
	}
	a, err := svc.Get(ctx, wp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(a.Desired), tmp) {
		t.Errorf("desired vẫn giữ địa chỉ tạm: %s", a.Desired)
	}
	if !strings.Contains(string(a.Desired), `"cuahangacme.com"`) {
		t.Errorf("tên chính không còn đứng đầu: %s", a.Desired)
	}
}
