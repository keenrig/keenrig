package caddy

// PR-05 — "Năng lực khai báo phải đúng sự thật".
//
// # Vì sao test này tồn tại
//
// Ở T8 driver khai `CapRateLimit: true` trong khi Caddy KHÔNG có rate limit
// dựng sẵn. Hậu quả không phải một lỗi ồn ào: admission cho qua, người dùng
// tưởng app được bảo vệ, và cấu hình bị bỏ rơi IM LẶNG. Đọc lại code không bắt
// được — chỉ có một test đối chiếu "khai gì" với "sinh ra gì" mới bắt được.
//
// Nguyên tắc test: với MỖI năng lực driver khai, dựng một site CẦN đúng năng
// lực đó rồi khẳng định cấu hình sinh ra có dấu vết của nó. Không có dấu vết =
// khai suông.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/proxy"
)

// siteFor dựng một site CẦN đúng năng lực cap. Trả ok=false cho năng lực không
// biểu diễn được bằng một Site (chúng được kiểm bằng cách khác, xem bên dưới).
func siteFor(cap proxy.Capability) (proxy.Site, bool) {
	s := proxy.Site{FQDN: "a.example.com", AppID: "app-1",
		Upstreams: []proxy.Upstream{{Host: "10.0.0.1", Port: 80}},
		TLS:       proxy.TLS{Mode: proxy.TLSACMEByGateway},
	}
	switch cap {
	case proxy.CapACME:
		return s, true
	case proxy.CapCertUpload:
		s.TLS = proxy.TLS{Mode: proxy.TLSProvided, CertRef: "certs/a.example.com"}
		return s, true
	case proxy.CapTLSPassthru:
		s.TLS = proxy.TLS{Mode: proxy.TLSPassthrough}
		return s, true
	case proxy.CapLoadBalance:
		s.Upstreams = append(s.Upstreams, proxy.Upstream{Host: "10.0.0.2", Port: 80})
		return s, true
	case proxy.CapRateLimit:
		s.Policy.RateLimit = &proxy.RateLimit{RequestsPerMinute: 60, Burst: 10}
		return s, true
	case proxy.CapForwardAuth:
		s.Policy.ForwardAuth = &proxy.ForwardAuth{URL: "http://127.0.0.1:9000/auth"}
		return s, true
	case proxy.CapWAF:
		s.Policy.WAF = &proxy.WAF{Ruleset: "owasp-crs", Block: true}
		return s, true
	case proxy.CapBodyLimit:
		s.Policy.BodyLimitMB = 25
		return s, true
	case proxy.CapIPFilter:
		s.Policy.IPAllow = []string{"10.0.0.0/8"}
		return s, true
	}
	return proxy.Site{}, false
}

// PR-05 — mỗi năng lực KHAI phải sinh ra cấu hình THẬT.
//
// Năng lực nào không biểu diễn được qua một Site (CapWildcardTLS, CapWebSocket,
// CapAtomicApply, CapObserve, CapIPFilter) được liệt kê tường minh dưới đây
// kèm cách nó ĐƯỢC kiểm ở chỗ khác — danh sách miễn trừ phải viết ra, vì một
// danh sách ngầm là chỗ để lén thêm năng lực khai suông.
func TestDeclaredCapabilitiesProduceRealConfig(t *testing.T) {
	// Miễn trừ, kèm LÝ DO và nơi kiểm thay thế.
	exempt := map[proxy.Capability]string{
		// Kiểm riêng ở TestStreamingIsNotBuffered (PX-06): điều kiện thật
		// không phải một handler mà là flush_interval = -1.
		proxy.CapWebSocket: "kiểm ở TestStreamingIsNotBuffered",
		// Là tính chất của cert, không phải của route. Cert do Caddy tự xin
		// (CapACME) nên không có cấu hình riêng ta sinh ra.
		proxy.CapWildcardTLS: "thuộc tính cert, không phải route",
		// Là tính chất của admin API (PATCH cả mảng bị từ chối nguyên khối),
		// kiểm ở TestApplyIsAtomic / TestApplyRejectsBadArray.
		proxy.CapAtomicApply: "kiểm ở tầng admin API, không ở route",
		// Kiểm ở TestStatusReturnsManagedOnly: Status đọc từ cấu hình đang chạy.
		proxy.CapObserve: "kiểm ở TestStatusReturnsManagedOnly",
	}

	d, _ := newTestDriver(t)
	caps, err := d.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	for cap, on := range caps {
		if !on {
			continue
		}
		if why, ok := exempt[cap]; ok {
			t.Logf("miễn trừ %q: %s", cap, why)
			continue
		}
		s, ok := siteFor(cap)
		if !ok {
			t.Errorf("driver khai năng lực %q nhưng test không dựng được site cần nó — "+
				"hoặc bổ sung vào siteFor, hoặc thêm vào danh sách miễn trừ kèm lý do", cap)
			continue
		}
		rt, err := buildRoute(s)
		if err != nil {
			t.Errorf("khai %q nhưng buildRoute lỗi: %v", cap, err)
			continue
		}
		raw, err := json.Marshal(rt)
		if err != nil {
			t.Fatal(err)
		}
		if !capVisibleIn(cap, string(raw)) {
			t.Errorf("driver khai %q nhưng cấu hình sinh ra không có dấu vết nào của nó.\n"+
				"Đây đúng là kiểu hỏng PR-05 sinh ra để chặn: admission cho qua, "+
				"người dùng tưởng được bảo vệ, cấu hình bị bỏ rơi im lặng.\nroute = %s", cap, raw)
		}
	}
}

// capVisibleIn — dấu vết tối thiểu của một năng lực trong route JSON.
func capVisibleIn(cap proxy.Capability, cfg string) bool {
	switch cap {
	case proxy.CapACME:
		// Caddy tự xin cert cho host trong matcher — dấu vết là chính matcher.
		return strings.Contains(cfg, `"host"`)
	case proxy.CapCertUpload:
		return strings.Contains(cfg, "tls") || strings.Contains(cfg, "cert")
	case proxy.CapTLSPassthru:
		return strings.Contains(cfg, "tls") || strings.Contains(cfg, "passthrough")
	case proxy.CapLoadBalance:
		return strings.Contains(cfg, "load_balancing")
	case proxy.CapRateLimit:
		return strings.Contains(cfg, "rate_limit")
	case proxy.CapForwardAuth:
		return strings.Contains(cfg, "forward_auth") || strings.Contains(cfg, "authentication")
	case proxy.CapWAF:
		return strings.Contains(cfg, "waf") || strings.Contains(cfg, "coraza")
	case proxy.CapBodyLimit:
		return strings.Contains(cfg, "max_size") || strings.Contains(cfg, "request_body")
	case proxy.CapIPFilter:
		return strings.Contains(cfg, "remote_ip")
	}
	return false
}

// PX-10 — "Admin API của gateway KHÔNG mở TCP mặc định; mở ra phải là hành
// động tường minh".
//
// Admin API của Caddy không có xác thực: ai gọi được là đổi được toàn bộ định
// tuyến của mọi app. Mặc định TCP nghĩa là mọi tiến trình trên máy — kể cả một
// container app bị chiếm — đều đổi được routing.
func TestAdminEndpointDefaultsToUnixSocket(t *testing.T) {
	layout := paths.New(t.TempDir())

	d, err := New(proxy.Config{Layout: layout}) // DSN RỖNG = mặc định
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !strings.HasPrefix(d.adminURL, schemeUnix) {
		t.Fatalf("endpoint mặc định = %q, PHẢI là unix socket (%q).\n"+
			"Admin API của Caddy không có xác thực — mặc định TCP là mở toàn bộ "+
			"định tuyến cho mọi tiến trình trên máy.", d.adminURL, schemeUnix)
	}
	// Và nó phải nằm trong RunDir, không phải một chỗ tuỳ ý.
	if !strings.Contains(strings.ReplaceAll(d.adminURL, "\\", "/"),
		strings.ReplaceAll(layout.RunDir(), "\\", "/")) {
		t.Errorf("socket %q không nằm dưới RunDir %q", d.adminURL, layout.RunDir())
	}
}

// Mở TCP vẫn PHẢI được: người vận hành chạy Caddy trong container cần nó. Điều
// quan trọng là đó là lựa chọn họ GÕ RA, không phải thứ họ thừa hưởng.
func TestAdminOverTCPIsExplicitAndAllowed(t *testing.T) {
	d, err := New(proxy.Config{Layout: paths.New(t.TempDir()), DSN: "http://127.0.0.1:2019"})
	if err != nil {
		t.Fatalf("New với DSN TCP tường minh bị từ chối: %v", err)
	}
	if d.adminURL != "http://127.0.0.1:2019" {
		t.Errorf("adminURL = %q", d.adminURL)
	}
}

// PX-06 — "WebSocket (terminal) + SSE (logs) passthrough ổn định ≥30 phút".
//
// # Phạm vi test này, nói thẳng
//
// Phần "≥30 phút" cần một Caddy thật và một kết nối thật; nó thuộc e2e. Cái
// test này kiểm điều kiện CẦN mà nếu thiếu thì 30 phút kia không bao giờ đạt
// được: response KHÔNG được đệm.
//
// Caddy mặc định gom bộ đệm response. Với SSE, hệ quả là log "streaming" hiện
// ra thành từng cục sau vài phút — app chạy đúng, gateway không báo lỗi, và
// triệu chứng duy nhất là "tính năng xem log hơi lạ". Đó là kiểu hỏng không ai
// truy được về cấu hình gateway.
func TestStreamingIsNotBuffered(t *testing.T) {
	rt, err := buildRoute(proxy.Site{
		FQDN: "a.example.com", AppID: "app-1",
		Upstreams: []proxy.Upstream{{Host: "10.0.0.1", Port: 80}},
		TLS:       proxy.TLS{Mode: proxy.TLSACMEByGateway},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(rt)
	if err != nil {
		t.Fatal(err)
	}

	var got struct {
		Handle []struct {
			Handler       string `json:"handler"`
			FlushInterval *int   `json:"flush_interval"`
		} `json:"handle"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}

	found := false
	for _, h := range got.Handle {
		if h.Handler != "reverse_proxy" {
			continue
		}
		found = true
		if h.FlushInterval == nil {
			t.Fatalf("reverse_proxy KHÔNG khai flush_interval — Caddy sẽ đệm "+
				"response và SSE (log) không bao giờ stream tới trình duyệt.\nroute = %s", raw)
		}
		if *h.FlushInterval != -1 {
			t.Errorf("flush_interval = %d, muốn -1 (đẩy ngay, không đệm)", *h.FlushInterval)
		}
	}
	if !found {
		t.Fatalf("không có handler reverse_proxy nào: %s", raw)
	}
}

// Catch-all cũng chuyển tiếp về Admin UI, mà Admin UI CŨNG có SSE (job
// progress) — nên nó cần đúng một thứ.
func TestCatchAllToAdminAlsoUnbuffered(t *testing.T) {
	rt, err := buildCatchAll(proxy.Upstream{Host: "127.0.0.1", Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(rt)
	if !strings.Contains(string(raw), `"flush_interval":-1`) {
		t.Errorf("catch-all về Admin UI bị đệm — tiến độ job sẽ không hiện realtime: %s", raw)
	}
}
