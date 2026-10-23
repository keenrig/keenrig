package caddy

// Conformance trên CADDY THẬT.
//
// # Vì sao bộ test này phải tồn tại riêng
//
// apply_test.go đối chiếu với một admin API GIẢ. Nó chứng minh ta gửi đúng
// hình dạng JSON, và KHÔNG chứng minh Caddy hiểu được JSON đó. Ba lỗi ở driver
// swarm (T13) đều thuộc loại thứ hai: chỉ lộ ra khi chạy trên nền tảng thật.
//
// Đây cũng là chỗ duy nhất trả lời được câu hỏi đang treo của PX-03: cấu hình
// TLS tự ký cho truy cập bằng IP có làm hỏng đường ACME của tên miền thật
// không. Đoán câu đó rồi ship là cách làm mọi tên miền của người dùng rơi sang
// cert tự ký.
//
// # Cách chạy
//
// Cấu hình bằng JSON chứ không phải Caddyfile: Caddyfile cần xuống dòng và
// tab, mà chúng phải sống sót qua nhiều tầng escape — một dấu sai chỗ làm
// Caddy lên với cấu hình rỗng và test đỏ ở chỗ trông y hệt lỗi driver.
//
//	docker run -d --name keenrig-caddy-test \
//	  --add-host host.docker.internal:host-gateway \
//	  -p 127.0.0.1:2019:2019 -p 127.0.0.1:8880:80 -p 127.0.0.1:8443:443 \
//	  caddy:2.8-alpine \
//	  sh -c 'echo "{\"admin\":{\"listen\":\"0.0.0.0:2019\"}}" > /tmp/caddy.json && caddy run --config /tmp/caddy.json'
//
//	KEENRIG_CADDY_ADMIN=http://127.0.0.1:2019 \
//	  go test ./keenrig-node/internal/proxy/driver/caddy/... -run TestRealCaddy -v
//
// --add-host là bắt buộc: upstream trong test là một httptest.Server chạy trên
// MÁY, còn Caddy chạy trong container — "127.0.0.1" của nó không phải của ta.
//
// Không đặt biến → SKIP. Cùng quy ước với conformance swarm/k8s: test hạ tầng
// KHÔNG được làm đỏ CI của người không có hạ tầng đó, nhưng cũng không được
// biến mất im lặng — nên nó SKIP có lý do, không phải bị bỏ qua.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/proxy"
)

const envRealAdmin = "KEENRIG_CADDY_ADMIN"

// realDriver mở driver trỏ vào Caddy thật, hoặc SKIP.
func realDriver(t *testing.T) *Driver {
	t.Helper()
	addr := strings.TrimSpace(os.Getenv(envRealAdmin))
	if addr == "" {
		t.Skipf("cần %s trỏ vào admin API của một Caddy đang chạy (xem godoc real_test.go)", envRealAdmin)
	}
	return realDriverWithAdmin(t, addr, proxy.Upstream{})
}

func realDriverWithAdmin(t *testing.T, adminAPI string, adminUI proxy.Upstream) *Driver {
	t.Helper()
	d, err := New(proxy.Config{
		Layout: paths.New(t.TempDir()), DSN: adminAPI, Admin: adminUI,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Dọn sạch sau mỗi test: Caddy này dùng chung giữa các test, và route sót
	// lại sẽ làm test sau đỏ vì lý do không liên quan tới nó.
	t.Cleanup(func() {
		if _, err := d.Apply(context.Background(), nil); err != nil {
			t.Logf("dọn route: %v", err)
		}
	})
	return d
}

// upstreamOf dựng một HTTP server thật rồi trả địa chỉ Caddy gọi tới được.
//
// Caddy chạy TRONG container nên "127.0.0.1" của nó không phải của ta —
// host.docker.internal là cầu nối, và nếu không phân giải được thì test SKIP
// thay vì đỏ: đó là giới hạn môi trường, không phải lỗi sản phẩm.
func upstreamOf(t *testing.T, h http.Handler) (proxy.Upstream, string) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)

	host := os.Getenv("KEENRIG_CADDY_HOST_GATEWAY")
	if host == "" {
		host = "host.docker.internal"
	}
	return proxy.Upstream{Host: host, Port: port}, srv.URL
}

// gatewayURL — cổng 80 của Caddy nhìn từ máy chạy test.
func gatewayURL(t *testing.T) string {
	t.Helper()
	if v := strings.TrimSpace(os.Getenv("KEENRIG_CADDY_HTTP")); v != "" {
		return v
	}
	return "http://127.0.0.1:8880"
}

// getWithHost gọi gateway với header Host cho trước.
//
// Đây là tương đương của một dòng trong /etc/hosts, và tốt hơn ở hai điểm:
// nó không đụng vào cấu hình máy của người chạy test, và nó nói rõ NGAY TRONG
// TEST rằng tên miền đó là giả.
func getWithHost(t *testing.T, base, host, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET %s (Host: %s): %v", base+path, host, err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n])
}

// --- PR-01/PR-04: Caddy THẬT chấp nhận cấu hình ta sinh ----------------------------

// Đây là khẳng định mà admin API giả KHÔNG bao giờ đưa ra được: Caddy nhận
// config, nạp nó, và request đi tới đúng upstream.
func TestRealCaddyRoutesToUpstream(t *testing.T) {
	d := realDriver(t)
	ctx := context.Background()

	up, _ := upstreamOf(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "app trả lời, Host=%s", r.Host)
	}))

	// TLSOff: test này đo ĐỊNH TUYẾN qua cổng 80. Site có TLS giờ bị đẩy sang
	// https (http-to-https) và tên *.example.test không xin được cert — phần đó
	// đo riêng ở TestRealCaddyRedirectsPlainHTTPToHTTPS.
	const fqdn = "app-thu.example.test"
	rep, err := d.Apply(ctx, []proxy.Site{{
		FQDN: fqdn, AppID: "app-1", Upstreams: []proxy.Upstream{up},
		TLS: proxy.TLS{Mode: proxy.TLSOff},
	}})
	if err != nil {
		t.Fatalf("Caddy THẬT từ chối cấu hình ta sinh: %v", err)
	}
	if len(rep.Applied) != 1 {
		t.Fatalf("Applied = %v", rep.Applied)
	}

	code, body := getWithHost(t, gatewayURL(t), fqdn, "/")
	if code != 200 {
		t.Fatalf("qua gateway = %d: %s", code, body)
	}
	if !strings.Contains(body, "app trả lời") {
		t.Errorf("body = %q — request không tới được upstream", body)
	}
	// Host phải được GIỮ NGUYÊN: nhiều app sinh URL tuyệt đối từ Host, và ghi
	// đè nó thành địa chỉ container sẽ làm mọi liên kết trong app trỏ sai chỗ.
	if !strings.Contains(body, fqdn) {
		t.Errorf("Host tới upstream = %q, muốn giữ nguyên %q", body, fqdn)
	}
}

// PR-01 — Apply lại cùng tập khi đã hội tụ là no-op, trên Caddy THẬT.
func TestRealCaddyApplyIdempotent(t *testing.T) {
	d := realDriver(t)
	ctx := context.Background()
	up, _ := upstreamOf(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))

	sites := []proxy.Site{{
		FQDN: "idem.example.test", AppID: "app-1", Upstreams: []proxy.Upstream{up},
		TLS: proxy.TLS{Mode: proxy.TLSACMEByGateway},
	}}
	for i := 0; i < 3; i++ {
		if _, err := d.Apply(ctx, sites); err != nil {
			t.Fatalf("Apply lần %d: %v", i+1, err)
		}
	}
	got, err := d.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("sau 3 lần Apply có %d site, muốn 1: %+v", len(got), got)
	}
}

// PR-02 — route do người vận hành thêm TAY phải còn nguyên sau Apply.
// Trên Caddy thật, vì đây là chỗ khác biệt giữa "quản lý gateway" và "chiếm gateway".
func TestRealCaddyKeepsForeignRoutes(t *testing.T) {
	d := realDriver(t)
	ctx := context.Background()

	// Người vận hành thêm một route tay qua admin API.
	foreign := `[{"@id":"route-cua-nguoi-van-hanh","match":[{"host":["tay.example.test"]}],` +
		`"handle":[{"handler":"static_response","status_code":418,"body":"tôi là ấm trà"}],"terminal":true}]`
	if err := d.ensureServer(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := d.admin.do(ctx, http.MethodPatch, routesPath, json.RawMessage(foreign)); err != nil {
		t.Fatalf("thêm route tay: %v", err)
	}

	up, _ := upstreamOf(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	rep, err := d.Apply(ctx, []proxy.Site{{
		FQDN: "cua-ta.example.test", AppID: "app-1", Upstreams: []proxy.Upstream{up},
		TLS: proxy.TLS{Mode: proxy.TLSOff},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Ignored) != 1 || !strings.Contains(rep.Ignored[0], "route-cua-nguoi-van-hanh") {
		t.Errorf("Ignored = %v — driver phải BÁO rằng nó cố tình không đụng", rep.Ignored)
	}

	// Và route đó vẫn PHỤC VỤ.
	if code, body := getWithHost(t, gatewayURL(t), "tay.example.test", "/"); code != 418 {
		t.Errorf("route tay = %d (%s), muốn 418 — driver đã xoá cấu hình của người vận hành", code, body)
	}
}

// PR-03 — level-triggered: site vắng mặt trong desired bị GỠ THẬT khỏi Caddy.
func TestRealCaddyLevelTriggered(t *testing.T) {
	d := realDriver(t)
	ctx := context.Background()
	up, _ := upstreamOf(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))

	site := func(fqdn string) proxy.Site {
		return proxy.Site{FQDN: fqdn, AppID: "app-" + fqdn,
			Upstreams: []proxy.Upstream{up}, TLS: proxy.TLS{Mode: proxy.TLSOff}}
	}
	if _, err := d.Apply(ctx, []proxy.Site{site("a.example.test"), site("b.example.test")}); err != nil {
		t.Fatal(err)
	}
	if code, _ := getWithHost(t, gatewayURL(t), "b.example.test", "/"); code != 204 {
		t.Fatalf("b chưa lên: %d", code)
	}

	// Chỉ còn a trong desired → b phải biến mất.
	rep, err := d.Apply(ctx, []proxy.Site{site("a.example.test")})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 1 || rep.Removed[0] != "b.example.test" {
		t.Errorf("Removed = %v", rep.Removed)
	}
	if code, _ := getWithHost(t, gatewayURL(t), "a.example.test", "/"); code != 204 {
		t.Errorf("a bị gỡ nhầm: %d", code)
	}
	// b không còn route TLSOff riêng → qua HTTP nó rơi vào http-to-https (308),
	// không còn tới upstream (204) nữa.
	if code, _ := redirectOf(t, gatewayURL(t), "b.example.test"); code != http.StatusPermanentRedirect {
		t.Errorf("b vẫn phục vụ sau khi bị gỡ: %d, muốn 308 (rơi xuống chuyển hướng)", code)
	}
}

// --- PX-03: đây là câu hỏi đang treo -----------------------------------------------

// PX-03 — truy cập KHÔNG kèm tên miền (gõ thẳng IP) phải tới Admin UI.
//
// Trên Caddy thật, request tới IP đến với Host = "127.0.0.1:8880", không khớp
// matcher nào, nên nó rơi vào catch-all. Đây là kịch bản của một máy VỪA CÀI.
func TestRealCaddyCatchAllServesAdmin(t *testing.T) {
	addr := strings.TrimSpace(os.Getenv(envRealAdmin))
	if addr == "" {
		t.Skipf("cần %s", envRealAdmin)
	}
	adminUI, _ := upstreamOf(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "Keenrig Admin")
	}))
	// SelfIPs 127.0.0.1: vào Admin bằng IP phải đi HTTPS (cert tự ký), vì HTTP
	// trần giờ luôn bị đẩy sang https — trang đăng nhập không bao giờ cleartext.
	d, err := New(proxy.Config{
		Layout: paths.New(t.TempDir()), DSN: addr, Admin: adminUI, SelfIPs: []string{selfIP()},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Apply(context.Background(), nil) })
	ctx := context.Background()

	appUp, _ := upstreamOf(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "APP CỦA NGƯỜI DÙNG")
	}))
	if _, err := d.Apply(ctx, []proxy.Site{{
		FQDN: "app.example.test", AppID: "app-1", Upstreams: []proxy.Upstream{appUp},
		TLS: proxy.TLS{Mode: proxy.TLSOff},
	}}); err != nil {
		t.Fatal(err)
	}

	// Gõ thẳng IP qua HTTP → 308 sang https, KHÔNG phải trang đăng nhập trần.
	if code, loc := redirectOf(t, gatewayURL(t), ""); code != http.StatusPermanentRedirect || !strings.HasPrefix(loc, "https://") {
		t.Fatalf("vào bằng IP qua HTTP = %d → %q, muốn 308 → https", code, loc)
	}
	// Tên miền lạ trỏ về máy (DNS wildcard) cũng vậy.
	if code, loc := redirectOf(t, gatewayURL(t), "ten-mien-la.example.test"); code != http.StatusPermanentRedirect ||
		loc != "https://ten-mien-la.example.test/" {
		t.Errorf("tên miền lạ qua HTTP = %d → %q, muốn 308 → https://ten-mien-la.example.test/", code, loc)
	}

	// Qua HTTPS bằng IP: Admin UI (PX-03), và KHÔNG rơi vào app (PX-09).
	//
	// Caddy chọn cert tự ký theo địa chỉ CỤC BỘ của kết nối (trình duyệt không
	// gửi SNI cho IP). Sau NAT của Docker, địa chỉ đó là IP container chứ không
	// phải 127.0.0.1 — nên phép đo này chỉ chạy khi người chạy khai đúng IP mà
	// Caddy nhìn thấy (KEENRIG_CADDY_SELF_IP, vd Caddy chạy --network host).
	// Đã đo trên VPS thật 2026-10-03: https://<IP> → 200 Admin, cert tự ký.
	t.Run("https bằng IP", func(t *testing.T) {
		if strings.TrimSpace(os.Getenv("KEENRIG_CADDY_SELF_IP")) == "" {
			t.Skip("cần KEENRIG_CADDY_SELF_IP = địa chỉ cục bộ Caddy thấy (Docker NAT đổi nó)")
		}
		body := getHTTPSInsecure(t, httpsURL(t), "")
		if !strings.Contains(body, "Keenrig Admin") {
			t.Errorf("vào bằng IP qua HTTPS trả %q, muốn Admin UI (PX-03)", body)
		}
		if strings.Contains(body, "APP CỦA NGƯỜI DÙNG") {
			t.Fatal("vào bằng IP rơi vào APP — ai biết IP là vào được app không cần domain (PX-09)")
		}
	})
	// Site khai TLSOff vẫn phục vụ qua HTTP: lựa chọn tường minh không bị đè.
	if _, body := getWithHost(t, gatewayURL(t), "app.example.test", "/"); !strings.Contains(body, "APP CỦA NGƯỜI DÙNG") {
		t.Errorf("site TLSOff trả %q, muốn app", body)
	}
}

// Trang đăng nhập và mọi site có TLS KHÔNG được phục vụ qua HTTP trần — Google
// cảnh báo "trình duyệt sẽ hiện pop-up khi người dùng nhập mật khẩu đã lưu"
// cho cả keenrig.com vì http://admin.<env>, http://<bất-kỳ>.<env> và http://<IP>
// đều trả form đăng nhập không mã hoá (đo 2026-10-03).
func TestRealCaddyRedirectsPlainHTTPToHTTPS(t *testing.T) {
	d := realDriver(t)
	up, _ := upstreamOf(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "KHÔNG ĐƯỢC THẤY QUA HTTP")
	}))
	if _, err := d.Apply(context.Background(), []proxy.Site{{
		FQDN: "admin.e1.example.test", AppID: "keenrig-admin", Upstreams: []proxy.Upstream{up},
		TLS: proxy.TLS{Mode: proxy.TLSACMEByGateway},
	}}); err != nil {
		t.Fatal(err)
	}
	code, loc := redirectOf(t, gatewayURL(t)+"/login?next=%2Fapps", "admin.e1.example.test")
	if code != http.StatusPermanentRedirect {
		t.Fatalf("HTTP tới site có TLS = %d, muốn 308", code)
	}
	if loc != "https://admin.e1.example.test/login?next=%2Fapps" {
		t.Errorf("Location = %q — phải giữ nguyên host + đường dẫn + query", loc)
	}
}

// selfIP — IP mà Caddy thấy là địa chỉ cục bộ (xem subtest "https bằng IP").
func selfIP() string {
	if v := strings.TrimSpace(os.Getenv("KEENRIG_CADDY_SELF_IP")); v != "" {
		return v
	}
	return "127.0.0.1"
}

// redirectOf gửi GET KHÔNG đi theo chuyển hướng, trả mã + Location.
func redirectOf(t *testing.T, url, host string) (int, string) {
	t.Helper()
	if !strings.Contains(strings.TrimPrefix(url, "http://"), "/") {
		url += "/"
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	c := &http.Client{Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s (Host: %s): %v", url, host, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

// httpsURL — cổng 443 của Caddy nhìn từ máy chạy test.
func httpsURL(t *testing.T) string {
	t.Helper()
	if v := strings.TrimSpace(os.Getenv("KEENRIG_CADDY_HTTPS")); v != "" {
		return strings.Replace(v, "http://", "https://", 1)
	}
	return "https://127.0.0.1:8443"
}

// getHTTPSInsecure — HTTPS với cert tự ký (chỉ dùng cho IP), SNI = serverName.
func getHTTPSInsecure(t *testing.T, base, serverName string) string {
	t.Helper()
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: serverName}} //nolint:gosec // cert tự ký cho IP là chủ đích của PX-03
	var body string
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := (&http.Client{Timeout: 5 * time.Second, Transport: tr}).Get(base + "/")
		if err == nil {
			buf := make([]byte, 4096)
			n, _ := resp.Body.Read(buf)
			resp.Body.Close()
			body = string(buf[:n])
			return body
		}
		// Caddy cấp cert tự ký BẤT ĐỒNG BỘ sau Apply; chờ một nhịp.
		if time.Now().After(deadline) {
			t.Fatalf("HTTPS %s: %v", base, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// PX-06 — SSE đi qua gateway KHÔNG bị đệm.
//
// Đây là điều kiện mà chỉ Caddy thật trả lời được: `flush_interval: -1` có
// thật sự làm Caddy đẩy từng chunk không. Test gửi một sự kiện, chờ, rồi gửi
// tiếp — nếu bị đệm thì sự kiện đầu tiên không tới trước sự kiện thứ hai.
func TestRealCaddyDoesNotBufferSSE(t *testing.T) {
	d := realDriver(t)
	ctx := context.Background()

	released := make(chan struct{})
	up, _ := upstreamOf(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fmt.Fprint(w, "data: su-kien-dau-tien\n\n")
		w.(http.Flusher).Flush()
		<-released // giữ kết nối mở
		fmt.Fprint(w, "data: su-kien-thu-hai\n\n")
		w.(http.Flusher).Flush()
	}))
	defer close(released)

	const fqdn = "sse.example.test"
	if _, err := d.Apply(ctx, []proxy.Site{{
		FQDN: fqdn, AppID: "app-sse", Upstreams: []proxy.Upstream{up},
		TLS: proxy.TLS{Mode: proxy.TLSOff},
	}}); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, gatewayURL(t)+"/", nil)
	req.Host = fqdn
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("mở SSE: %v", err)
	}
	defer resp.Body.Close()

	// Sự kiện đầu tiên phải tới NGAY, trong khi upstream vẫn đang giữ kết nối.
	// Bị đệm thì lời gọi Read này treo tới khi upstream đóng — và đó chính là
	// "log streaming hiện thành từng cục sau vài phút".
	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 256)
		n, _ := resp.Body.Read(buf)
		done <- string(buf[:n])
	}()

	select {
	case got := <-done:
		if !strings.Contains(got, "su-kien-dau-tien") {
			t.Errorf("chunk đầu = %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("3 giây chưa nhận được sự kiện đầu tiên — Caddy đang ĐỆM response.\n" +
			"Đây đúng là triệu chứng PX-06: app chạy đúng, gateway không báo lỗi, " +
			"và log 'streaming' chỉ hiện ra khi kết nối đóng.")
	}
}

// --- PX-03 phần TLS: câu hỏi đã treo từ T15, giờ trả lời được ------------------------

// Cổng 443 KHÔNG được phục vụ HTTP trần.
//
// Đây là một lỗi THẬT đã đo được: Automatic HTTPS của Caddy suy ra "cổng này
// cần TLS" từ host matcher trong route. Trên máy chưa có tên miền nào thì route
// duy nhất là catch-all, mà catch-all không có matcher — nên Caddy phục vụ HTTP
// trần ở :443. Toàn bộ bề mặt quản trị nằm trên cleartext, không có log nào nói.
func TestRealCaddyPort443IsNotCleartext(t *testing.T) {
	d := realDriver(t)
	ctx := context.Background()
	if _, err := d.Apply(ctx, nil); err != nil {
		t.Fatal(err)
	}

	httpsBase := strings.TrimSpace(os.Getenv("KEENRIG_CADDY_HTTPS"))
	if httpsBase == "" {
		httpsBase = "http://127.0.0.1:8443"
	}
	req, _ := http.NewRequest(http.MethodGet, httpsBase+"/", nil)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return // cổng từ chối nói HTTP trần — đúng như mong đợi
	}
	defer resp.Body.Close()

	// 400 KHÔNG phải thất bại: đó chính là câu trả lời của một cổng ĐANG bật
	// TLS khi nhận HTTP trần ("Client sent an HTTP request to an HTTPS server").
	// Nói cách khác, 400 là BẰNG CHỨNG TLS đã bật.
	//
	// Thất bại là khi cổng phục vụ BÌNH THƯỜNG trên cleartext — lúc đó catch-all
	// trả Admin UI qua HTTP không mã hoá và không ai nhận ra.
	if resp.StatusCode == http.StatusBadRequest {
		return
	}
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	t.Fatalf("cổng 443 phục vụ HTTP TRẦN: %d %q — trên máy chưa có tên miền, "+
		"toàn bộ bề mặt quản trị nằm trên cleartext", resp.StatusCode, string(buf[:n]))
}

// PX-03 — cert tự ký cho IP, và tên miền KHÔNG bị kéo theo.
//
// Hai khẳng định trong một test có chủ đích: chúng là hai vế của cùng một đánh
// đổi. Cấu hình cho IP nhận cert tự ký mà làm tên miền thật cũng nhận cert tự
// ký thì đó là hỏng nặng hơn nhiều so với việc chưa có HTTPS trên IP — và đó
// chính là lý do phần này bị hoãn cho tới khi có Caddy thật.
func TestRealCaddySelfSignedForIPOnly(t *testing.T) {
	addr := strings.TrimSpace(os.Getenv(envRealAdmin))
	if addr == "" {
		t.Skipf("cần %s", envRealAdmin)
	}
	// 127.0.0.1 vì đó là địa chỉ test gọi tới được. Trên máy thật, main truyền
	// các IP không phải loopback.
	d, err := New(proxy.Config{
		Layout: paths.New(t.TempDir()), DSN: addr, SelfIPs: []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Apply(context.Background(), nil) })
	ctx := context.Background()

	rep, err := d.Apply(ctx, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(rep.Warnings) > 0 {
		t.Fatalf("cấu hình TLS tự ký thất bại: %v", rep.Warnings)
	}

	// 1. Caddy đã cấp cert cho IP và policy dùng issuer `internal`.
	var pol []map[string]any
	if err := d.admin.getJSON(ctx, tlsPoliciesPath, &pol); err != nil {
		t.Fatalf("đọc policies: %v", err)
	}
	var mine map[string]any
	for _, p := range pol {
		if p["@id"] == selfTLSPolicyID {
			mine = p
		}
	}
	if mine == nil {
		t.Fatalf("không tìm thấy policy %q trong %+v", selfTLSPolicyID, pol)
	}
	subs, _ := mine["subjects"].([]any)
	if len(subs) != 1 || subs[0] != "127.0.0.1" {
		t.Errorf("subjects = %v — policy PHẢI hẹp, không được bắt tất cả", subs)
	}

	// 2. Tên miền thật KHÔNG rơi vào policy này. Đây là vế phải đúng.
	for _, p := range pol {
		if p["@id"] == selfTLSPolicyID {
			continue
		}
		if _, has := p["subjects"]; !has {
			t.Errorf("có policy KHÔNG có subjects (%+v) — nó khớp mọi tên miền", p)
		}
	}

	// 3. automate chứa IP, và Caddy thật sự cấp cert.
	var automate []string
	if err := d.admin.getJSON(ctx, tlsAutomatePath, &automate); err != nil {
		t.Fatalf("đọc automate: %v — thiếu nó thì Caddy KHÔNG cấp cert nào cả", err)
	}
	found := false
	for _, n := range automate {
		if n == "127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("automate = %v, thiếu 127.0.0.1", automate)
	}

	// 4. Apply LẠI không nhân bản policy (idempotent).
	if _, err := d.Apply(ctx, nil); err != nil {
		t.Fatal(err)
	}
	var pol2 []map[string]any
	_ = d.admin.getJSON(ctx, tlsPoliciesPath, &pol2)
	n := 0
	for _, p := range pol2 {
		if p["@id"] == selfTLSPolicyID {
			n++
		}
	}
	if n != 1 {
		t.Errorf("sau 2 lần Apply có %d policy của ta, muốn 1", n)
	}
}

// Policy của người vận hành phải còn nguyên — cùng nguyên tắc với route.
func TestRealCaddyKeepsForeignTLSPolicy(t *testing.T) {
	addr := strings.TrimSpace(os.Getenv(envRealAdmin))
	if addr == "" {
		t.Skipf("cần %s", envRealAdmin)
	}
	d, err := New(proxy.Config{
		Layout: paths.New(t.TempDir()), DSN: addr, SelfIPs: []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t.Cleanup(func() {
		_ = d.setBranch(ctx, "/config/apps/tls/automation", map[string]any{"policies": []any{}})
		_, _ = d.Apply(ctx, nil)
	})

	if err := d.ensureServer(ctx); err != nil {
		t.Fatal(err)
	}
	// Người vận hành đặt một policy riêng cho tên miền của họ.
	foreign := map[string]any{"policies": []map[string]any{{
		"@id": "policy-cua-nguoi-van-hanh", "subjects": []string{"cua-toi.example.test"},
		"issuers": []map[string]any{{"module": "internal"}},
	}}}
	// setBranch chứ không PUT trần: nhánh automation có thể đã tồn tại từ test
	// trước, và PUT sẽ 409 — test đỏ vì bối cảnh, không vì sản phẩm.
	if err := d.setBranch(ctx, "/config/apps/tls/automation", foreign); err != nil {
		t.Fatal(err)
	}

	if _, err := d.Apply(ctx, nil); err != nil {
		t.Fatal(err)
	}

	var pol []map[string]any
	if err := d.admin.getJSON(ctx, tlsPoliciesPath, &pol); err != nil {
		t.Fatal(err)
	}
	var keptForeign, hasMine bool
	for _, p := range pol {
		switch p["@id"] {
		case "policy-cua-nguoi-van-hanh":
			keptForeign = true
		case selfTLSPolicyID:
			hasMine = true
		}
	}
	if !keptForeign {
		t.Errorf("policy của người vận hành BỊ XOÁ: %+v", pol)
	}
	if !hasMine {
		t.Errorf("policy của ta không được thêm: %+v", pol)
	}
	// Của ta phải ở ĐẦU: Caddy dùng policy khớp đầu tiên.
	if len(pol) > 0 && pol[0]["@id"] != selfTLSPolicyID {
		t.Errorf("policy của ta không ở đầu mảng: %+v", pol)
	}
}
