package caddy

// Trang đăng nhập Admin (catch-all) và mọi site KHÔNG được phục vụ qua HTTP
// trần. Đo được 2026-10-03: http://admin.<env>, http://<bất-kỳ>.<env> và
// http://<IP> đều trả form đăng nhập không mã hoá → Google cảnh báo "trình
// duyệt sẽ hiện pop-up khi người dùng nhập mật khẩu đã lưu" cho cả site.

import (
	"encoding/json"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/proxy"
)

func TestPlainHTTPIsRedirectedBeforeAnySiteOrTheAdminLogin(t *testing.T) {
	d, fake := newTestDriver(t)
	if _, err := d.Apply(t.Context(), []proxy.Site{site("a.example.com", proxy.Upstream{Host: "10.0.0.1", Port: 80})}); err != nil {
		t.Fatal(err)
	}
	ids := routeIDs(t, fake.routes)
	rd, site0, ca := -1, -1, -1
	for i, id := range ids {
		switch id {
		case httpsRedirectID:
			rd = i
		case siteRouteID("a.example.com"):
			site0 = i
		case catchAllID:
			ca = i
		}
	}
	if rd < 0 || rd > site0 || rd > ca {
		t.Fatalf("routes = %v — http-to-https phải đứng TRƯỚC mọi site và catch-all", ids)
	}

	var r struct {
		Match []struct {
			Host     []string `json:"host"`
			Protocol string   `json:"protocol"`
			Not      []struct {
				Host     []string `json:"host"`
				RemoteIP struct {
					Ranges []string `json:"ranges"`
				} `json:"remote_ip"`
			} `json:"not"`
		} `json:"match"`
		Handle []struct {
			Handler    string              `json:"handler"`
			StatusCode int                 `json:"status_code"`
			Headers    map[string][]string `json:"headers"`
		} `json:"handle"`
		Terminal bool `json:"terminal"`
	}
	if err := json.Unmarshal(fake.routes[rd], &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Match) != 1 || r.Match[0].Protocol != "http" || len(r.Match[0].Host) != 0 {
		t.Errorf("match = %+v — phải khớp MỌI host qua protocol http, không riêng tên nào", r.Match)
	}
	// Ngoại lệ loopback: get.sh kiểm tra cổng 80 bằng http://127.0.0.1/healthz,
	// và loopback không có cert tự ký — chuyển nó sang https là handshake hỏng
	// (đo 2026-10-14). Miễn trừ phải đòi CẢ Host lẫn nguồn là loopback, trong
	// MỘT bộ matcher (AND), không phải hai bộ (OR).
	if len(r.Match) == 1 {
		n := r.Match[0].Not
		if len(n) != 1 {
			t.Fatalf("not = %+v — muốn đúng một bộ matcher (Host VÀ nguồn loopback)", n)
		}
		if !contains(n[0].Host, "127.0.0.1") || !contains(n[0].RemoteIP.Ranges, "127.0.0.0/8") {
			t.Errorf("not = %+v — phải miễn Host 127.0.0.1 từ nguồn 127.0.0.0/8", n[0])
		}
		if contains(n[0].RemoteIP.Ranges, "0.0.0.0/0") || len(n[0].RemoteIP.Ranges) == 0 {
			t.Errorf("not.remote_ip = %v — miễn trừ không được mở cho nguồn ngoài loopback", n[0].RemoteIP.Ranges)
		}
	}
	if len(r.Handle) != 1 || r.Handle[0].StatusCode != 308 ||
		len(r.Handle[0].Headers["Location"]) != 1 ||
		r.Handle[0].Headers["Location"][0] != "https://{http.request.host}{http.request.uri}" {
		t.Errorf("handle = %+v, muốn 308 → https://{host}{uri}", r.Handle)
	}
	if !r.Terminal {
		t.Error("không terminal — request trần rơi tiếp xuống site/catch-all")
	}
	// Route chuyển hướng KHÔNG phải một site: Status/Removed không được coi nó là FQDN.
	if fqdnFromID(httpsRedirectID) != "" {
		t.Error("http-to-https bị đọc như một site")
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
