package apps_test

// Gate license ở admission (M5) — đi qua CHÍNH đường Create/AddDomain/
// UpdateDesired, trên store SQLite thật và một license ký Ed25519 THẬT.
//
// # Vì sao không dựng license.State bằng tay
//
// Một `&license.State{Features: …}` viết tay khẳng định "nếu state nói 1 app thì
// app thứ hai bị chặn" — đúng nhưng vô dụng, vì nó không nói gì về việc một
// license THẬT có cho ra state đó không. Nên bậc trả phí ở đây đi qua
// license.Verify với chữ ký thật, và sàn starter đi qua license.Load với file
// không tồn tại — đúng hai đường mà main.go dùng.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/apps"
	"github.com/keenrig/keenrig/keenrig-node/internal/domains"
	"github.com/keenrig/keenrig/keenrig-node/internal/license"
)

// starterState — đúng đường main.go đi khi chưa có file license.
func starterState(t *testing.T) func() *license.State {
	t.Helper()
	path := filepath.Join(t.TempDir(), "license.json")
	return func() *license.State {
		st, err := license.Load(path, nil, time.Now())
		if err != nil {
			t.Fatalf("Load(file không tồn tại): %v", err)
		}
		return st
	}
}

// signedState — license ký Ed25519 thật, verify thật, rồi mới thành State.
func signedState(t *testing.T, f contracts.Features) func() *license.State {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	payload, err := json.Marshal(contracts.LicensePayload{
		LicenseID: "lic-t", InstanceID: "inst-t", EnvID: "env-t",
		Features: f, IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour), GraceDays: 14,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(contracts.LicenseEnvelope{
		V: contracts.LicenseEnvelopeV, KeyID: "active",
		Payload:   base64.RawURLEncoding.EncodeToString(payload),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload)),
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := license.Verify(raw, license.Keys{"active": pub}, now)
	if err != nil {
		t.Fatalf("Verify license tự ký: %v", err)
	}
	return func() *license.State { return st }
}

func licensedService(t *testing.T, state func() *license.State) *apps.Service {
	t.Helper()
	st := openStore(t)
	return apps.New(st, domains.New(st), apps.Options{License: state})
}

func plainDesired(doms ...string) contracts.DesiredApp {
	return contracts.DesiredApp{
		Image:   "ghcr.io/acme/web@sha256:" + strings.Repeat("a", 64),
		Domains: doms,
	}
}

// starterSlugs — đủ slug để lấp đầy sàn starter, mỗi slug một domain riêng.
func starterSlugs() []string {
	out := make([]string, contracts.StarterMaxApps)
	for i := range out {
		out[i] = fmt.Sprintf("app%d", i+1)
	}
	return out
}

func TestStarterFloorAllowsItsLimitAndBlocksTheNextApp(t *testing.T) {
	ctx := context.Background()
	svc := licensedService(t, starterState(t))

	for i, slug := range starterSlugs() {
		if _, err := svc.Create(ctx, apps.CreateInput{
			Slug: slug, Desired: desiredJSON(t, plainDesired()),
		}); err != nil {
			t.Fatalf("app thứ %d của starter phải qua: %v", i+1, err)
		}
	}
	_, err := svc.Create(ctx, apps.CreateInput{
		Slug: "over", Desired: desiredJSON(t, plainDesired()),
	})
	if !errors.Is(err, apps.ErrLicense) {
		t.Fatalf("= %v, muốn ErrLicense — starter là %d app", err, contracts.StarterMaxApps)
	}
	// Thông báo phải nói TRẦN và HIỆN TRẠNG — người dùng cần biết mình đang
	// đứng ở đâu, không phải chỉ "không được".
	if !strings.Contains(err.Error(), fmt.Sprintf("%d app", contracts.StarterMaxApps)) {
		t.Errorf("thông báo không nói trần: %v", err)
	}
}

func TestStarterFloorBlocksTheDomainPastItsLimit(t *testing.T) {
	ctx := context.Background()
	svc := licensedService(t, starterState(t))

	doms := make([]string, contracts.StarterMaxDomains)
	for i := range doms {
		doms[i] = fmt.Sprintf("d%d.tld", i+1)
	}
	app, err := svc.Create(ctx, apps.CreateInput{
		Slug: "shop", Desired: desiredJSON(t, plainDesired(doms...)),
	})
	if err != nil {
		t.Fatalf("%d domain là đúng hạn mức starter: %v", contracts.StarterMaxDomains, err)
	}
	if _, err := svc.AddDomain(ctx, app.ID, "extra.tld", false); !errors.Is(err, apps.ErrLicense) {
		t.Fatalf("= %v, muốn ErrLicense — starter là %d domain", err, contracts.StarterMaxDomains)
	}
}

// Create bị chặn vì domain phải chặn TRƯỚC khi app được ghi: một app "nửa vời"
// nằm lại trong DB là thứ người dùng phải tự dọn.
func TestABlockedCreateLeavesNoOrphanApp(t *testing.T) {
	ctx := context.Background()
	svc := licensedService(t, starterState(t))

	doms := make([]string, contracts.StarterMaxDomains+1)
	for i := range doms {
		doms[i] = fmt.Sprintf("g%d.tld", i+1)
	}
	_, err := svc.Create(ctx, apps.CreateInput{
		Slug: "greedy", Desired: desiredJSON(t, plainDesired(doms...)),
	})
	if !errors.Is(err, apps.ErrLicense) {
		t.Fatalf("= %v, muốn ErrLicense — %d domain vượt trần starter", err, len(doms))
	}
	list, err := svc.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("app bị từ chối vẫn nằm lại trong DB: %v", list)
	}
}

func TestASignedStandardLicenseLiftsTheLimits(t *testing.T) {
	ctx := context.Background()
	// standard: docker · 1 node · app/domain không giới hạn (0 = vô hạn, schema v2).
	svc := licensedService(t, signedState(t, contracts.Features{
		Plan: "standard", Runtime: "docker", MaxNodes: 1,
	}))

	for i, slug := range []string{"one", "two", "three"} {
		if _, err := svc.Create(ctx, apps.CreateInput{
			Slug: slug, Desired: desiredJSON(t, plainDesired(slug+".tld")),
		}); err != nil {
			t.Fatalf("app thứ %d với license standard: %v", i+1, err)
		}
	}
}

func TestUpdateDesiredCannotSmuggleADomainPastTheLicense(t *testing.T) {
	ctx := context.Background()
	svc := licensedService(t, starterState(t))

	app, err := svc.Create(ctx, apps.CreateInput{
		Slug: "shop", Desired: desiredJSON(t, plainDesired("shop.tld")),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Thay domain (1 → 1): tổng không tăng, phải qua.
	if _, err := svc.UpdateDesired(ctx, app.ID,
		desiredJSON(t, plainDesired("renamed.tld"))); err != nil {
		t.Fatalf("đổi domain không tăng tổng mà bị chặn: %v", err)
	}
	// Thêm domain tới đúng trần: phải qua. Vượt trần một domain: phải chặn.
	full := []string{"renamed.tld"}
	for i := 1; i < contracts.StarterMaxDomains; i++ {
		full = append(full, fmt.Sprintf("more%d.tld", i))
	}
	if _, err := svc.UpdateDesired(ctx, app.ID, desiredJSON(t, plainDesired(full...))); err != nil {
		t.Fatalf("update tới đúng trần %d domain mà bị chặn: %v", contracts.StarterMaxDomains, err)
	}
	if _, err := svc.UpdateDesired(ctx, app.ID,
		desiredJSON(t, plainDesired(append(full, "extra.tld")...))); !errors.Is(err, apps.ErrLicense) {
		t.Fatalf("= %v, muốn ErrLicense — update là đường thêm domain vượt trần", err)
	}
}
