package apps_test

// PR-08 — *"Admission: site bật WAF trên `nginx` bị từ chối lúc TẠO APP; đổi
// `nginx-owasp` thì cho qua."*
//
// # Vì sao test này đi qua apps.Create thật, không gọi proxy.Check
//
// `proxy.Check` đã có test riêng từ M1 (`proxy/driver/all/all_test.go`) và nó
// xanh suốt — trong khi nhánh WAF chưa bao giờ chạy trong đường thật, vì
// `apps` dựng `proxy.Site` với `Policy` để trống. Chỗ hỏng là ĐƯỜNG NỐI, nên test
// phải đi qua đường nối: `Create` → `validateDesired` → admission.
//
// # Vì sao năng lực lấy từ driver THẬT, không phải Caps viết tay
//
// Một `proxy.Caps{}` viết tay trong test khẳng định "nếu gateway không có waf thì
// bị từ chối" — điều đó đúng nhưng vô dụng, vì nó không nói gì về việc nginx CÓ
// waf hay không. Mở driver thật bằng `proxy.Open` và hỏi `Capabilities` khiến test
// đỏ nếu ai đó thêm `CapWAF` vào nginx thường.

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/apps"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/domains"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/proxy"
	_ "github.com/keenrig-platform/keenrig/keenrig-node/internal/proxy/driver/all"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/proxy/driver/nginx"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

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

// gatewayCaps hỏi năng lực của driver THẬT — kể cả driver TỪ CHỐI MỞ.
//
// Từ 2026-08-12 `nginx`/`nginx-owasp` từ chối `proxy.Open` cho tới khi Apply có
// thật (xem proxy/driver/nginx). Nhưng admission phải tiếp tục được canh trên
// năng lực của chúng: ngày Apply có thật, luật "WAF chỉ qua được trên
// nginx-owasp" phải vẫn đúng y nguyên, và nó không được ngừng canh chỉ vì driver
// tạm thời không phục vụ được.
func gatewayCaps(t *testing.T, name string) proxy.Caps {
	t.Helper()
	cfg := proxy.Config{Layout: paths.New(filepath.Join(t.TempDir(), "keenrig"))}
	c, err := proxy.Open(context.Background(), name, cfg)
	if errors.Is(err, proxy.ErrNotImplemented) {
		var nerr error
		if c, nerr = nginx.New(cfg, nginx.Options{WAF: name == "nginx-owasp"}); nerr != nil {
			t.Fatalf("dựng %s: %v", name, nerr)
		}
	} else if err != nil {
		t.Fatalf("proxy.Open(%s): %v", name, err)
	}
	caps, err := c.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities(%s): %v", name, err)
	}
	return caps
}

func serviceOn(t *testing.T, gateway string) *apps.Service {
	t.Helper()
	st := openStore(t)
	return apps.New(st, domains.New(st), apps.Options{GatewayCaps: gatewayCaps(t, gateway)})
}

func desiredJSON(t *testing.T, d contracts.DesiredApp) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func wafDesired(domains ...string) contracts.DesiredApp {
	return contracts.DesiredApp{
		Image:   "ghcr.io/acme/web@sha256:" + strings.Repeat("a", 64),
		Domains: domains,
		Policy:  &contracts.Policy{WAF: &contracts.WAF{Ruleset: "owasp-crs"}},
	}
}

// PR-08, cả hai nửa của một câu.
func TestWAFAdmission(t *testing.T) {
	ctx := context.Background()

	t.Run("nginx thường từ chối", func(t *testing.T) {
		_, err := serviceOn(t, "nginx").Create(ctx, apps.CreateInput{
			Slug: "shop", Desired: desiredJSON(t, wafDesired("shop.tld")),
		})
		if !errors.Is(err, apps.ErrUnsupported) {
			t.Fatalf("= %v, muốn ErrUnsupported", err)
		}
		// Thông báo phải nói TÊN NĂNG LỰC. Một lỗi 400 chỉ nói "không hỗ trợ cấu
		// hình này" buộc người dùng phải đoán trong sáu trường của policy.
		if !strings.Contains(err.Error(), "waf") {
			t.Errorf("thông báo không nói năng lực nào thiếu: %v", err)
		}
	})

	t.Run("nginx-owasp cho qua", func(t *testing.T) {
		app, err := serviceOn(t, "nginx-owasp").Create(ctx, apps.CreateInput{
			Slug: "shop", Desired: desiredJSON(t, wafDesired("shop.tld")),
		})
		if err != nil {
			t.Fatalf("nginx-owasp phải cho qua: %v", err)
		}
		if app.ID == "" {
			t.Error("app được tạo nhưng không có id")
		}
	})

	// caddy là gateway MẶC ĐỊNH, nên nửa này quyết định trải nghiệm thật của phần
	// lớn người cài. caddy chỉ có WAF khi build kèm plugin coraza, và driver không
	// khai CapWAF — nên WAF phải bị từ chối, không phải "được nhận rồi im lặng".
	t.Run("caddy từ chối", func(t *testing.T) {
		_, err := serviceOn(t, "caddy").Create(ctx, apps.CreateInput{
			Slug: "shop", Desired: desiredJSON(t, wafDesired("shop.tld")),
		})
		if !errors.Is(err, apps.ErrUnsupported) {
			t.Fatalf("= %v, muốn ErrUnsupported", err)
		}
	})
}

// Chính sách bị kiểm dù app CHƯA có domain nào.
//
// Chính sách thuộc về APP, không thuộc một tên miền. Nhận nó khi chưa có domain
// nghĩa là lưu một ý định không bao giờ thực thi được — và với WAF thì "được
// nhận" tự nó là thiệt hại, vì người vận hành tin site đang được bảo vệ.
func TestPolicyCheckedEvenWithoutDomains(t *testing.T) {
	_, err := serviceOn(t, "nginx").Create(context.Background(), apps.CreateInput{
		Slug: "khong-domain", Desired: desiredJSON(t, wafDesired()),
	})
	if !errors.Is(err, apps.ErrUnsupported) {
		t.Fatalf("= %v, muốn ErrUnsupported — app không domain vẫn phải bị kiểm", err)
	}
}

// UpdateDesired cũng phải bị kiểm, không chỉ Create.
//
// Bật WAF sau khi app đã chạy là đường tự nhiên hơn cả: người ta tạo app trước,
// nghĩ tới bảo mật sau. Nếu chỉ Create kiểm thì đường phổ biến nhất lại là đường
// không được canh.
func TestUpdateDesiredAlsoChecksPolicy(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	svc := apps.New(st, domains.New(st),
		apps.Options{GatewayCaps: gatewayCaps(t, "nginx")})

	plain := contracts.DesiredApp{Image: "ghcr.io/acme/web@sha256:" + strings.Repeat("a", 64)}
	app, err := svc.Create(ctx, apps.CreateInput{Slug: "sau-moi-bat", Desired: desiredJSON(t, plain)})
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.UpdateDesired(ctx, app.ID, desiredJSON(t, wafDesired()))
	if !errors.Is(err, apps.ErrUnsupported) {
		t.Fatalf("= %v, muốn ErrUnsupported", err)
	}

	// Và desired trong store phải KHÔNG đổi: một PATCH bị từ chối mà vẫn ghi
	// nghĩa là reconciler sẽ đi deploy thứ người dùng vừa nhận lỗi 400 cho.
	got, err := st.GetApp(ctx, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	var after contracts.DesiredApp
	if err := json.Unmarshal(got.Desired, &after); err != nil {
		t.Fatal(err)
	}
	if after.Policy != nil {
		t.Errorf("PATCH bị từ chối nhưng policy đã vào store: %+v", after.Policy)
	}
}

// Chính sách nào gateway ĐỠ ĐƯỢC thì phải đi qua — nếu không thì admission chỉ là
// một cách nói "không" cho mọi thứ.
//
// nginx khai rate_limit, ip_filter, body_limit, forward_auth; caddy khai
// ip_filter và body_limit. Test lấy năng lực từ driver thật nên nó theo sự thật
// chứ không theo bảng viết tay ở đây.
func TestSupportedPolicyPasses(t *testing.T) {
	ctx := context.Background()
	img := "ghcr.io/acme/web@sha256:" + strings.Repeat("a", 64)

	cases := []struct {
		gateway string
		policy  *contracts.Policy
	}{
		{"caddy", &contracts.Policy{IPDeny: []string{"203.0.113.7"}}},
		{"caddy", &contracts.Policy{BodyLimitMB: 25}},
		{"nginx", &contracts.Policy{RateLimit: &contracts.RateLimit{RequestsPerMinute: 600}}},
		{"nginx", &contracts.Policy{ForwardAuth: &contracts.ForwardAuth{URL: "https://auth.tld/v"}}},
		{"nginx-owasp", &contracts.Policy{
			WAF:       &contracts.WAF{Ruleset: "owasp-crs"},
			RateLimit: &contracts.RateLimit{RequestsPerMinute: 60},
		}},
	}

	for _, c := range cases {
		t.Run(c.gateway, func(t *testing.T) {
			d := contracts.DesiredApp{Image: img, Policy: c.policy}
			if _, err := serviceOn(t, c.gateway).Create(ctx,
				apps.CreateInput{Slug: "hop-le", Desired: desiredJSON(t, d)}); err != nil {
				t.Errorf("%s phải cho qua %+v: %v", c.gateway, c.policy, err)
			}
		})
	}
}

// Không khai policy thì admission không được chặn gì.
//
// Đường này là đường của gần như mọi app. Một bug làm `PolicyFrom(nil)` cần một
// năng lực nào đó sẽ làm KHÔNG TẠO ĐƯỢC APP NÀO — và đó là loại lỗi phải có test
// riêng, không phải để lộ ra ở e2e.
func TestNoPolicyIsAlwaysAdmitted(t *testing.T) {
	d := contracts.DesiredApp{Image: "ghcr.io/acme/web@sha256:" + strings.Repeat("a", 64)}
	for _, gw := range []string{"caddy", "nginx", "nginx-owasp"} {
		if _, err := serviceOn(t, gw).Create(context.Background(),
			apps.CreateInput{Slug: "tron", Desired: desiredJSON(t, d)}); err != nil {
			t.Errorf("%s: app không có policy vẫn bị chặn: %v", gw, err)
		}
	}
}

// Năng lực CHƯA BIẾT (proxy chưa mở được) → bỏ qua admission, không từ chối.
//
// Gateway hỏng không được biến thành "không tạo được app": người vận hành mất
// luôn đường sửa. Đây là lựa chọn có chủ đích và nó nằm ở godoc Options.GatewayCaps.
func TestUnknownCapsSkipsAdmission(t *testing.T) {
	st := openStore(t)
	svc := apps.New(st, domains.New(st), apps.Options{}) // GatewayCaps nil
	if _, err := svc.Create(context.Background(), apps.CreateInput{
		Slug: "chua-biet", Desired: desiredJSON(t, wafDesired()),
	}); err != nil {
		t.Fatalf("caps nil phải bỏ qua admission: %v", err)
	}
}
