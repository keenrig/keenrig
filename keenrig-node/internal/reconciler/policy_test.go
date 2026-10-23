package reconciler

// PR-08, nửa sau: chính sách trong `desired.policy` phải TỚI ĐƯỢC gateway.
//
// Admission ở tầng `apps` quyết định chính sách có được NHẬN hay không; đây kiểm
// nó có được CHUYỂN XUỐNG hay không. Hai chuyện đó hỏng độc lập với nhau, và
// hỏng ở đây tệ hơn: người dùng thấy app tạo thành công với WAF bật, còn gateway
// thì không bao giờ nghe nói tới nó.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/proxy"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// createAppWithDesired tạo app với desired đầy đủ (createApp chỉ đặt image).
func createAppWithDesired(t *testing.T, st store.Store, id string, d contracts.DesiredApp) {
	t.Helper()
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateApp(context.Background(),
		&store.App{ID: id, Slug: id, Desired: raw}); err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
}

func TestPolicyFromDesiredReachesGateway(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	px := &fakeProxy{}

	block := false
	createAppWithDesired(t, st, "app-pol", contracts.DesiredApp{
		Image: "traefik/whoami:v1.10",
		Policy: &contracts.Policy{
			WAF:         &contracts.WAF{Ruleset: "owasp-crs", Block: &block},
			RateLimit:   &contracts.RateLimit{RequestsPerMinute: 600, Burst: 50},
			IPDeny:      []string{"203.0.113.7"},
			BodyLimitMB: 25,
			ForwardAuth: &contracts.ForwardAuth{URL: "https://auth.tld/v", CopyHeaders: []string{"X-User"}},
		},
	})
	addDomain(t, st, "app-pol", "pol.keenrig.com", true)
	withEndpoints(fake, runtime.Endpoint{Host: "172.20.0.9", Port: 8080})

	r := New(st, fake, proxyOpts()).WithProxy(px)
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "site được đẩy sang gateway", func() bool {
		return len(px.last()) == 1
	})

	p := px.last()[0].Policy
	switch {
	case p.WAF == nil || p.WAF.Ruleset != "owasp-crs":
		t.Errorf("WAF = %+v", p.WAF)
	case p.WAF.Block:
		// `"block": false` phải sống sót qua cả hai chặng chuyển đổi. Mất nó
		// nghĩa là một WAF người dùng cố ý để detect-only bỗng chặn thật, và cách
		// họ phát hiện là traffic hợp lệ bị 403.
		t.Error(`"block": false bị mất trên đường xuống gateway`)
	case p.RateLimit == nil || p.RateLimit.RequestsPerMinute != 600 || p.RateLimit.Burst != 50:
		t.Errorf("RateLimit = %+v", p.RateLimit)
	case len(p.IPDeny) != 1 || p.IPDeny[0] != "203.0.113.7":
		t.Errorf("IPDeny = %v", p.IPDeny)
	case p.BodyLimitMB != 25:
		t.Errorf("BodyLimitMB = %d", p.BodyLimitMB)
	case p.ForwardAuth == nil || p.ForwardAuth.URL != "https://auth.tld/v":
		t.Errorf("ForwardAuth = %+v", p.ForwardAuth)
	}

	// ForceHTTPS là quyết định của PLATFORM, không phải của người dùng: hợp đồng
	// không có trường để tắt nó, nên nó phải bật cho mọi site kể cả site khai
	// policy đầy đủ.
	if !p.ForceHTTPS {
		t.Error("ForceHTTPS bị mất khi app có policy riêng")
	}
}

// App KHÔNG khai policy vẫn phải có ForceHTTPS.
//
// Đây là đường của gần như mọi app. Một lỗi làm `PolicyFrom(nil)` trả zero value
// sẽ tắt HTTPS bắt buộc cho toàn hệ thống mà không có gì trong log nói ra.
func TestNoPolicyStillForcesHTTPS(t *testing.T) {
	st := openStore(t)
	fake := newFakeRuntime()
	px := &fakeProxy{}
	createApp(t, st, "app-tron", "traefik/whoami:v1.10")
	addDomain(t, st, "app-tron", "tron.keenrig.com", true)
	withEndpoints(fake, runtime.Endpoint{Host: "172.20.0.10", Port: 8080})

	r := New(st, fake, proxyOpts()).WithProxy(px)
	_, stop := runReconciler(t, r)
	defer stop()

	waitFor(t, 5*time.Second, "site được đẩy sang gateway", func() bool {
		return len(px.last()) == 1
	})
	if got := px.last()[0].Policy; !got.ForceHTTPS || got.WAF != nil {
		t.Errorf("Policy = %+v, muốn chỉ ForceHTTPS", got)
	}
}

// desired KHÔNG parse được thì site vẫn lên, với chính sách mặc định.
//
// Bỏ site ở đây nghĩa là một app đang chạy bình thường bỗng mất route vì một
// trường không liên quan tới định tuyến. Mất route là mất dịch vụ.
func TestBrokenDesiredStillGetsDefaultPolicy(t *testing.T) {
	got := policyOf(&store.App{ID: "x", Desired: json.RawMessage(`{ khong phai json`)})
	if !got.ForceHTTPS {
		t.Errorf("desired hỏng → %+v, muốn chính sách mặc định", got)
	}
	if got.WAF != nil || got.RateLimit != nil || got.ForwardAuth != nil {
		t.Errorf("desired hỏng nhưng sinh ra chính sách có nội dung: %+v", got)
	}
}

// PolicyFrom phải SAO CHÉP slice, không dùng chung với desired đã giải mã.
//
// desired được giải mã một lần rồi truyền đi nhiều chỗ; một driver sắp xếp lại
// tại chỗ sẽ sửa luôn thứ caller đang giữ. Đây đúng là loại lỗi không test nào
// bắt được cho tới khi có driver thứ hai.
func TestPolicyFromCopiesSlices(t *testing.T) {
	src := &contracts.Policy{IPAllow: []string{"10.0.0.0/8"}, IPDeny: []string{"1.2.3.4"}}
	got := proxy.PolicyFrom(src)
	got.IPAllow[0] = "SUA"
	got.IPDeny[0] = "SUA"
	if src.IPAllow[0] != "10.0.0.0/8" || src.IPDeny[0] != "1.2.3.4" {
		t.Errorf("sửa Policy trả về làm đổi desired gốc: %+v", src)
	}
}
