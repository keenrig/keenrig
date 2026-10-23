package caddy

// Test T8 — Apply/Status đối chiếu một admin API GIẢ.
//
// Phạm vi nói thẳng: đây kiểm HỢP ĐỒNG giữa driver và admin API của Caddy
// (đường dẫn, method, hình dạng JSON, và quan trọng nhất là driver KHÔNG đụng
// vào route của người khác). Nó KHÔNG chứng minh Caddy thật hiểu config ta gửi
// — chỉ e2e với Caddy thật mới trả lời được (T12).

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig/keenrig/keenrig-node/internal/proxy"
)

// fakeAdmin — admin API tối giản: giữ mảng routes trong bộ nhớ.
type fakeAdmin struct {
	routes  []json.RawMessage
	hasSrv  bool
	patches int
	puts    []string
}

func (f *fakeAdmin) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == routesPath:
			if !f.hasSrv {
				http.Error(w, "unknown object path", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(f.routes)
		case r.Method == http.MethodPatch && r.URL.Path == routesPath:
			f.patches++
			body, _ := io.ReadAll(r.Body)
			var next []json.RawMessage
			if err := json.Unmarshal(body, &next); err != nil {
				http.Error(w, "routes phải là mảng: "+err.Error(), http.StatusBadRequest)
				return
			}
			f.routes = next
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut:
			f.puts = append(f.puts, r.URL.Path)
			if strings.HasSuffix(r.URL.Path, "/servers/"+serverName) {
				f.hasSrv = true
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "không hỗ trợ: "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	})
}

func newTestDriver(t *testing.T) (*Driver, *fakeAdmin) {
	t.Helper()
	return newTestDriverWithAdmin(t, proxy.Upstream{})
}

// newTestDriverWithAdmin — driver biết Admin UI ở đâu (PX-03). Mặc định của
// newTestDriver là KHÔNG biết, để mọi test cũ vẫn kiểm đúng nhánh 404.
func newTestDriverWithAdmin(t *testing.T, admin proxy.Upstream) (*Driver, *fakeAdmin) {
	t.Helper()
	fake := &fakeAdmin{}
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)

	d, err := New(proxy.Config{Layout: paths.New(t.TempDir()), DSN: srv.URL, Admin: admin})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, fake
}

func site(fqdn string, ups ...proxy.Upstream) proxy.Site {
	return proxy.Site{
		FQDN:      fqdn,
		AppID:     "app-" + fqdn,
		Upstreams: ups,
		TLS:       proxy.TLS{Mode: proxy.TLSACMEByGateway},
	}
}

func routeIDs(t *testing.T, raws []json.RawMessage) []string {
	t.Helper()
	out := make([]string, 0, len(raws))
	for _, raw := range raws {
		var probe struct {
			ID string `json:"@id"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			t.Fatalf("route không parse được: %v", err)
		}
		out = append(out, probe.ID)
	}
	return out
}

// PX-01 — site được đẩy sang gateway, có upstream đúng.
func TestApplyCreatesRoutes(t *testing.T) {
	d, fake := newTestDriver(t)
	ctx := context.Background()

	rep, err := d.Apply(ctx, []proxy.Site{
		site("b.example.com", proxy.Upstream{Host: "172.20.0.3", Port: 80}),
		site("a.example.com", proxy.Upstream{Host: "172.20.0.2", Port: 8080}),
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Chưa có server → driver phải dựng khung, KHÔNG được gọi POST /load.
	if len(fake.puts) == 0 {
		t.Error("không dựng khung server")
	}
	if len(rep.Applied) != 2 {
		t.Fatalf("Applied = %v, muốn 2", rep.Applied)
	}

	ids := routeIDs(t, fake.routes)
	want := []string{httpsRedirectID, siteRouteID("a.example.com"), siteRouteID("b.example.com"), catchAllID}
	if len(ids) != len(want) {
		t.Fatalf("routes = %v, muốn %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("routes = %v, muốn %v (thứ tự: site theo fqdn, catch-all CUỐI)", ids, want)
		}
	}

	// Upstream đúng dạng host:port.
	var rt struct {
		Match  []map[string]any `json:"match"`
		Handle []struct {
			Handler   string              `json:"handler"`
			Upstreams []map[string]string `json:"upstreams"`
		} `json:"handle"`
		Terminal bool `json:"terminal"`
	}
	// routes[0] là http-to-https; site a.example.com đứng ngay sau.
	if err := json.Unmarshal(fake.routes[1], &rt); err != nil {
		t.Fatal(err)
	}
	if !rt.Terminal {
		t.Error("route site phải terminal — không thì catch-all nuốt mất request đã có chủ")
	}
	last := rt.Handle[len(rt.Handle)-1]
	if last.Handler != "reverse_proxy" || last.Upstreams[0]["dial"] != "172.20.0.2:8080" {
		t.Errorf("handler cuối = %+v, muốn reverse_proxy tới 172.20.0.2:8080", last)
	}
}

// PR — LEVEL-TRIGGERED: site vắng mặt phải bị gỡ.
func TestApplyIsLevelTriggered(t *testing.T) {
	d, fake := newTestDriver(t)
	ctx := context.Background()

	if _, err := d.Apply(ctx, []proxy.Site{
		site("a.example.com", proxy.Upstream{Host: "10.0.0.1", Port: 80}),
		site("b.example.com", proxy.Upstream{Host: "10.0.0.2", Port: 80}),
	}); err != nil {
		t.Fatal(err)
	}

	rep, err := d.Apply(ctx, []proxy.Site{site("a.example.com", proxy.Upstream{Host: "10.0.0.1", Port: 80})})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Removed) != 1 || rep.Removed[0] != "b.example.com" {
		t.Errorf("Removed = %v, muốn [b.example.com]", rep.Removed)
	}
	ids := routeIDs(t, fake.routes)
	for _, id := range ids {
		if id == siteRouteID("b.example.com") {
			t.Fatalf("route của site đã gỡ vẫn còn: %v", ids)
		}
	}

	// desired RỖNG = gỡ hết site của platform (nhưng giữ catch-all).
	if _, err := d.Apply(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if ids := routeIDs(t, fake.routes); len(ids) != 2 || ids[0] != httpsRedirectID || ids[1] != catchAllID {
		t.Errorf("sau Apply rỗng còn %v, muốn chỉ http-to-https + catch-all", ids)
	}
}

// PR — route KHÔNG mang nhãn platform phải được giữ NGUYÊN VĂN và liệt kê
// trong Ignored. Đây là ranh giới giữa "quản lý gateway" và "chiếm gateway".
func TestApplyPreservesForeignRoutes(t *testing.T) {
	d, fake := newTestDriver(t)
	ctx := context.Background()
	fake.hasSrv = true
	foreignWithID := json.RawMessage(`{"@id":"của-tôi","match":[{"host":["tay.example.com"]}],"handle":[{"handler":"static_response","status_code":200}],"trường_lạ":{"giữ":"nguyên"}}`)
	foreignNoID := json.RawMessage(`{"match":[{"path":["/dev/*"]}],"handle":[{"handler":"static_response","status_code":418}]}`)
	fake.routes = []json.RawMessage{foreignWithID, foreignNoID}

	rep, err := d.Apply(ctx, []proxy.Site{site("a.example.com", proxy.Upstream{Host: "10.0.0.1", Port: 80})})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Ignored) != 2 {
		t.Errorf("Ignored = %v, muốn 2 route lạ", rep.Ignored)
	}

	// Route lạ vẫn còn, và còn NGUYÊN VĂN — kể cả trường driver không hiểu.
	var foundWithID, foundNoID bool
	for _, raw := range fake.routes {
		if string(raw) == string(foreignWithID) {
			foundWithID = true
		}
		if string(raw) == string(foreignNoID) {
			foundNoID = true
		}
	}
	if !foundWithID {
		t.Error("route lạ có @id bị sửa/mất — trường không khai trong struct phải sống sót")
	}
	if !foundNoID {
		t.Error("route lạ không @id bị mất")
	}
	// …và chúng đứng TRƯỚC route của ta.
	ids := routeIDs(t, fake.routes)
	if ids[0] != "của-tôi" {
		t.Errorf("thứ tự = %v, muốn route lạ đứng trước", ids)
	}
}

// Apply lặp lại với cùng tập site phải sinh CÙNG một mảng JSON — nếu không,
// mỗi tick refresh sẽ ghi lại cấu hình gateway dù chẳng có gì đổi.
func TestApplyDeterministic(t *testing.T) {
	d, fake := newTestDriver(t)
	ctx := context.Background()
	sites := []proxy.Site{
		site("b.example.com", proxy.Upstream{Host: "10.0.0.2", Port: 80}),
		site("a.example.com", proxy.Upstream{Host: "10.0.0.3", Port: 80}, proxy.Upstream{Host: "10.0.0.1", Port: 80}),
	}

	if _, err := d.Apply(ctx, sites); err != nil {
		t.Fatal(err)
	}
	first, err := json.Marshal(fake.routes)
	if err != nil {
		t.Fatal(err)
	}

	// Đảo thứ tự đầu vào: kết quả phải y hệt.
	if _, err := d.Apply(ctx, []proxy.Site{sites[1], sites[0]}); err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(fake.routes)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Errorf("Apply không tất định:\n#1 %s\n#2 %s", first, second)
	}
}

// PX-03 — nhiều replica thành nhiều upstream trên CÙNG một site.
func TestApplyLoadBalancesReplicas(t *testing.T) {
	d, fake := newTestDriver(t)
	if _, err := d.Apply(context.Background(), []proxy.Site{
		site("a.example.com",
			proxy.Upstream{Host: "10.0.0.1", Port: 80},
			proxy.Upstream{Host: "10.0.0.2", Port: 80},
			proxy.Upstream{Host: "10.0.0.3", Port: 80}),
	}); err != nil {
		t.Fatal(err)
	}
	var rt struct {
		Handle []struct {
			Handler       string              `json:"handler"`
			Upstreams     []map[string]string `json:"upstreams"`
			LoadBalancing map[string]any      `json:"load_balancing"`
		} `json:"handle"`
	}
	// routes[0] là http-to-https; site đứng ngay sau.
	if err := json.Unmarshal(fake.routes[1], &rt); err != nil {
		t.Fatal(err)
	}
	rp := rt.Handle[len(rt.Handle)-1]
	if len(rp.Upstreams) != 3 {
		t.Fatalf("upstreams = %v, muốn 3", rp.Upstreams)
	}
	if rp.LoadBalancing == nil {
		t.Error("nhiều upstream mà không khai load_balancing")
	}
}

// catchAll đọc route cuối cùng và khẳng định nó đúng là catch-all.
func catchAll(t *testing.T, fake *fakeAdmin) struct {
	Match  []map[string]any `json:"match"`
	Handle []struct {
		Handler   string `json:"handler"`
		Status    int    `json:"status_code"`
		Upstreams []struct {
			Dial string `json:"dial"`
		} `json:"upstreams"`
	} `json:"handle"`
} {
	t.Helper()
	var rt struct {
		Match  []map[string]any `json:"match"`
		Handle []struct {
			Handler   string `json:"handler"`
			Status    int    `json:"status_code"`
			Upstreams []struct {
				Dial string `json:"dial"`
			} `json:"upstreams"`
		} `json:"handle"`
	}
	ids := routeIDs(t, fake.routes)
	if len(ids) == 0 || ids[len(ids)-1] != catchAllID {
		t.Fatalf("catch-all không ở cuối: %v", ids)
	}
	if err := json.Unmarshal(fake.routes[len(fake.routes)-1], &rt); err != nil {
		t.Fatal(err)
	}
	if len(rt.Match) != 0 {
		t.Error("catch-all có matcher — nó phải khớp MỌI thứ chưa có chủ")
	}
	return rt
}

// PX-09 — chưa cấu hình Admin UI thì catch-all trả 404, KHÔNG rơi vào app đầu
// tiên. Đây là nhánh phòng thủ: thà không phục vụ gì còn hơn phục vụ nhầm app.
func TestCatchAllIsLastAnd404WhenNoAdmin(t *testing.T) {
	d, fake := newTestDriver(t)
	if _, err := d.Apply(context.Background(), []proxy.Site{
		site("a.example.com", proxy.Upstream{Host: "10.0.0.1", Port: 80}),
	}); err != nil {
		t.Fatal(err)
	}
	rt := catchAll(t, fake)
	if rt.Handle[0].Handler != "static_response" || rt.Handle[0].Status != 404 {
		t.Errorf("catch-all = %+v, muốn static_response 404", rt.Handle[0])
	}
}

// PX-03 — "Truy cập bằng IP (catch-all) → admin UI, không bắt buộc domain".
//
// Đây là điều kiện để một máy VỪA CÀI dùng được: chưa có tên miền nào, và bắt
// buộc có domain mới vào được Admin nghĩa là không có cách nào cấu hình cái
// domain đầu tiên. Đồng thời PX-09 vẫn phải giữ: catch-all đi tới Admin UI,
// KHÔNG tới app của người dùng.
func TestCatchAllGoesToAdminUI(t *testing.T) {
	admin := proxy.Upstream{Host: "127.0.0.1", Port: 8080}
	d, fake := newTestDriverWithAdmin(t, admin)
	if _, err := d.Apply(context.Background(), []proxy.Site{
		site("a.example.com", proxy.Upstream{Host: "10.0.0.1", Port: 80}),
	}); err != nil {
		t.Fatal(err)
	}
	rt := catchAll(t, fake)
	if rt.Handle[0].Handler != "reverse_proxy" {
		t.Fatalf("catch-all = %q, muốn reverse_proxy về Admin UI", rt.Handle[0].Handler)
	}
	if len(rt.Handle[0].Upstreams) != 1 || rt.Handle[0].Upstreams[0].Dial != "127.0.0.1:8080" {
		t.Errorf("upstream = %+v, muốn 127.0.0.1:8080", rt.Handle[0].Upstreams)
	}
	// PX-09 vẫn phải đúng: đích là Admin UI, không phải app 10.0.0.1:80.
	if rt.Handle[0].Upstreams[0].Dial == "10.0.0.1:80" {
		t.Error("catch-all trỏ vào APP — ai biết IP là vào được app không cần domain")
	}
}

// Status KHÔNG được coi catch-all là một site của platform, dù nó giờ đã là
// một reverse_proxy trông y hệt site thật. Nhầm ở đây thì reconciler thấy một
// "site lạ" mỗi vòng và cố gỡ nó mãi.
func TestCatchAllNotReportedAsSite(t *testing.T) {
	d, fake := newTestDriverWithAdmin(t, proxy.Upstream{Host: "127.0.0.1", Port: 8080})
	ctx := context.Background()
	if _, err := d.Apply(ctx, []proxy.Site{
		site("a.example.com", proxy.Upstream{Host: "10.0.0.1", Port: 80}),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := d.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].FQDN != "a.example.com" {
		t.Fatalf("Status = %+v, muốn đúng 1 site (catch-all không phải site)", got)
	}
	_ = fake
}

// Status đọc lại từ cấu hình ĐANG chạy, chỉ trả site của platform.
func TestStatusReturnsManagedOnly(t *testing.T) {
	d, fake := newTestDriver(t)
	ctx := context.Background()
	fake.hasSrv = true
	fake.routes = []json.RawMessage{json.RawMessage(`{"@id":"tay","handle":[]}`)}

	if _, err := d.Apply(ctx, []proxy.Site{
		site("a.example.com", proxy.Upstream{Host: "10.0.0.1", Port: 8080}),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := d.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("Status = %+v, muốn đúng 1 site của platform (không kể route tay, không kể catch-all)", got)
	}
	if got[0].FQDN != "a.example.com" {
		t.Errorf("FQDN = %q", got[0].FQDN)
	}
	if len(got[0].Upstreams) != 1 || got[0].Upstreams[0].Host != "10.0.0.1" || got[0].Upstreams[0].Port != 8080 {
		t.Errorf("Upstreams = %+v", got[0].Upstreams)
	}
}

// Site không có upstream là lỗi lập trình của caller, không phải cấu hình hợp
// lệ: gateway sẽ trả 502 cho mọi request. Từ chối sớm.
func TestApplyRejectsSiteWithoutUpstream(t *testing.T) {
	d, _ := newTestDriver(t)
	if _, err := d.Apply(context.Background(), []proxy.Site{site("a.example.com")}); err == nil {
		t.Error("Apply nhận site không upstream")
	}
}

// Lỗi từ admin API phải nổi lên kèm nguyên văn thông báo của Caddy — nuốt đi
// là vứt manh mối duy nhất về chỗ config sai.
func TestApplySurfacesAdminError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode([]json.RawMessage{})
			return
		}
		http.Error(w, "loading app module http: cụ thể chỗ sai", http.StatusBadRequest)
	}))
	defer srv.Close()

	d, err := New(proxy.Config{Layout: paths.New(t.TempDir()), DSN: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Apply(context.Background(), []proxy.Site{site("a.example.com", proxy.Upstream{Host: "10.0.0.1", Port: 80})})
	if err == nil {
		t.Fatal("Apply nuốt lỗi admin API")
	}
	if !strings.Contains(err.Error(), "cụ thể chỗ sai") {
		t.Errorf("lỗi mất nguyên văn của Caddy: %v", err)
	}
}

// Năng lực khai báo phải TRUNG THỰC: Caddy không có rate limit dựng sẵn, và ta
// không kiểm chứng được plugin, nên không được khai có.
func TestCapabilitiesHonest(t *testing.T) {
	d, _ := newTestDriver(t)
	caps, err := d.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if caps.Has(proxy.CapRateLimit) {
		t.Error("khai CapRateLimit nhưng Caddy cần plugin caddy-ratelimit — không kiểm chứng được thì không được khai")
	}
	if caps.Has(proxy.CapWAF) {
		t.Error("khai CapWAF nhưng cần plugin coraza")
	}
	for _, c := range []proxy.Capability{proxy.CapACME, proxy.CapLoadBalance, proxy.CapAtomicApply, proxy.CapObserve} {
		if !caps.Has(c) {
			t.Errorf("thiếu %q — Caddy có thật", c)
		}
	}
}
