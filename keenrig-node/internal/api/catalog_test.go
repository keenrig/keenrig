package api_test

// Test UI-01 ở tầng HTTP — "wizard owner → cài app từ catalog → app sống".
//
// Phần "app sống" và phép đo <60s cần Docker thật; nó nằm ở keenrig-tests/e2e.
// Ở đây kiểm phần mà chỉ tầng HTTP hỏng được: route có gắn không, scope có áp
// không, và quan trọng nhất — app tạo ra có GHIM DIGEST không.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/api"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/apps"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/authz"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/catalog"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/domains"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

func newCatalogServer(t *testing.T) (*httptest.Server, store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cat, errs := catalog.LoadBuiltin()
	for _, e := range errs {
		t.Fatalf("danh mục nhúng hỏng: %v", e)
	}

	auth := fakeAuth{
		tokAdmin:  {authz.ScopeAdmin},
		tokReader: {authz.ScopeAppsRead},
	}
	h := api.New(apps.New(st, domains.New(st), apps.Options{}), st, auth, api.WithCatalog(cat))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, st
}

func TestCatalogList(t *testing.T) {
	srv, _ := newCatalogServer(t)

	code, body := do(t, srv, "GET", "/api/v1/catalog", tokAdmin, nil)
	if code != 200 {
		t.Fatalf("GET /catalog = %d: %s", code, body)
	}
	var got struct {
		Apps []struct {
			ID         string `json:"id"`
			Title      string `json:"title"`
			DisplayRef string `json:"display_ref"`
			ImageRef   string `json:"image_ref"`
			HTTPPort   int    `json:"http_port"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Apps) == 0 {
		t.Fatal("danh mục rỗng — màn hình cài app sẽ không có gì để chọn")
	}
	for _, a := range got.Apps {
		if a.ID == "" || a.Title == "" || a.HTTPPort == 0 {
			t.Errorf("entry thiếu trường: %+v", a)
		}
		// Hai ref, hai mục đích. UI hiện display_ref, image_ref có đó cho ai
		// muốn kiểm chứng thứ thật sự sẽ chạy.
		if !strings.Contains(a.ImageRef, "@sha256:") {
			t.Errorf("%s: image_ref %q không ghim digest", a.ID, a.ImageRef)
		}
		if strings.Contains(a.DisplayRef, "@sha256:") {
			t.Errorf("%s: display_ref %q mang digest — người dùng cần đọc được nó", a.ID, a.DisplayRef)
		}
	}
}

// Cài với thân RỖNG phải được: "cài với mặc định" là lời gọi ngắn nhất, và nó
// là đường mà nút một-cú-bấm trong UI đi qua.
func TestInstallWithDefaults(t *testing.T) {
	srv, _ := newCatalogServer(t)

	code, body := do(t, srv, "POST", "/api/v1/catalog/nginx/install", tokAdmin, nil)
	if code != 201 {
		t.Fatalf("POST install = %d: %s", code, body)
	}
	var app store.App
	if err := json.Unmarshal(body, &app); err != nil {
		t.Fatal(err)
	}
	if app.Slug != "nginx" {
		t.Errorf("slug = %q, muốn id trong danh mục", app.Slug)
	}
	if app.DesiredRev != 1 {
		t.Errorf("DesiredRev = %d", app.DesiredRev)
	}

	// ĐÂY là khẳng định quan trọng nhất của cả file: app đã tạo phải ghim
	// digest. Nếu phép dịch manifest→desired để lọt tag thì app sẽ âm thầm
	// đổi image ở lần pull sau, và không có gì trong hệ thống ghi lại điều đó.
	var d contracts.DesiredApp
	if err := json.Unmarshal(app.Desired, &d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Image, "@sha256:") {
		t.Fatalf("desired.Image = %q — cài từ danh mục KHÔNG ghim digest", d.Image)
	}
	if d.HTTPPort != 80 {
		t.Errorf("HTTPPort = %d", d.HTTPPort)
	}
}

func TestInstallWithOptions(t *testing.T) {
	srv, st := newCatalogServer(t)

	code, body := do(t, srv, "POST", "/api/v1/catalog/nginx/install", tokAdmin, map[string]any{
		"slug":      "trang-chu",
		"domains":   []string{"trangchu.example.com"},
		"env":       map[string]string{"TZ": "Asia/Ho_Chi_Minh"},
		"memory_mb": 256,
	})
	if code != 201 {
		t.Fatalf("POST install = %d: %s", code, body)
	}
	var app store.App
	_ = json.Unmarshal(body, &app)
	if app.Slug != "trang-chu" {
		t.Errorf("slug = %q", app.Slug)
	}

	var d contracts.DesiredApp
	_ = json.Unmarshal(app.Desired, &d)
	if d.Env["TZ"] != "Asia/Ho_Chi_Minh" {
		t.Errorf("Env = %v", d.Env)
	}
	if d.Resources == nil || d.Resources.MemoryMB != 256 {
		t.Errorf("Resources = %+v", d.Resources)
	}

	// Domain phải được gắn THẬT, không chỉ nằm trong desired: gateway đọc từ
	// bảng app_domains, không đọc desired.
	doms, err := st.ListDomains(t.Context(), app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(doms) != 1 || doms[0].FQDN != "trangchu.example.com" {
		t.Errorf("domain = %+v — app cài xong không có đường vào từ ngoài", doms)
	}
}

// Cài hai lần cùng slug → 409, không phải 500 và không phải hai app trùng tên.
func TestInstallTwiceConflicts(t *testing.T) {
	srv, _ := newCatalogServer(t)
	if code, body := do(t, srv, "POST", "/api/v1/catalog/nginx/install", tokAdmin, nil); code != 201 {
		t.Fatalf("lần 1 = %d: %s", code, body)
	}
	if code, body := do(t, srv, "POST", "/api/v1/catalog/nginx/install", tokAdmin, nil); code != 409 {
		t.Errorf("lần 2 = %d, muốn 409: %s", code, body)
	}
	// Nhưng đặt slug khác thì cài được bản thứ hai — đó là lý do slug tồn tại.
	if code, body := do(t, srv, "POST", "/api/v1/catalog/nginx/install", tokAdmin,
		map[string]any{"slug": "nginx-thu-hai"}); code != 201 {
		t.Errorf("bản thứ hai với slug khác = %d: %s", code, body)
	}
}

func TestCatalogUnknownID(t *testing.T) {
	srv, _ := newCatalogServer(t)
	for _, path := range []string{
		"/api/v1/catalog/khong-co",
		"/api/v1/catalog/khong-co/install",
	} {
		method := "GET"
		if strings.HasSuffix(path, "/install") {
			method = "POST"
		}
		if code, body := do(t, srv, method, path, tokAdmin, nil); code != 404 {
			t.Errorf("%s %s = %d, muốn 404: %s", method, path, code, body)
		}
	}
}

// Đọc danh mục cần apps:read; CÀI cần apps:write. Trộn hai thứ nghĩa là một
// token chỉ-đọc cài được app.
func TestCatalogScopes(t *testing.T) {
	srv, _ := newCatalogServer(t)

	if code, _ := do(t, srv, "GET", "/api/v1/catalog", tokReader, nil); code != 200 {
		t.Errorf("token apps:read không đọc được danh mục: %d", code)
	}
	if code, _ := do(t, srv, "POST", "/api/v1/catalog/nginx/install", tokReader, nil); code != 403 {
		t.Errorf("token CHỈ ĐỌC cài được app: %d", code)
	}
	if code, _ := do(t, srv, "GET", "/api/v1/catalog", "", nil); code != 401 {
		t.Errorf("không xác thực vẫn đọc được danh mục: %d", code)
	}
}

// Không cắm danh mục → route KHÔNG tồn tại (404), không phải trả danh sách
// rỗng (200). "Chưa cấu hình" và "hết app" là hai chuyện khác nhau, và UI phải
// hiện hai màn hình khác nhau.
func TestCatalogRoutesAbsentWhenNotConfigured(t *testing.T) {
	srv, _ := newTestServer(t) // dựng KHÔNG có WithCatalog
	if code, _ := do(t, srv, "GET", "/api/v1/catalog", tokAdmin, nil); code != 404 {
		t.Errorf("GET /catalog khi chưa cắm danh mục = %d, muốn 404", code)
	}
}

// Tải trọng đối kháng qua {id} của catalog — cùng bộ với SEC-03.
func TestCatalogIDInjection(t *testing.T) {
	srv, _ := newCatalogServer(t)
	for group, list := range payloads {
		for _, p := range list {
			enc := url.PathEscape(p)
			code, body := do(t, srv, "POST", "/api/v1/catalog/"+enc+"/install", tokAdmin, nil)
			assertCleanResponse(t, group+" catalog id", p, code, body)
		}
	}
}

// getRaw như do() nhưng giữ lại header — icon là file, và test phải kiểm được
// Content-Type, không chỉ mã trạng thái.
func getRaw(t *testing.T, srv *httptest.Server, path, token string) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest("GET", srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, buf.Bytes()
}

// TestCatalogIcon — mỗi manifest khai "icon" thì file đó PHẢI tải được.
//
// Trước khi có route này, danh mục khai `"icon": "nginx.svg"` còn UI in thẳng
// chuỗi đó ra thẻ icon. Test đi từ chính danh sách catalog chứ không hardcode
// "nginx.svg": thêm app mới mà quên bỏ icon vào binary thì test này đỏ.
func TestCatalogIcon(t *testing.T) {
	srv, _ := newCatalogServer(t)

	code, body := do(t, srv, "GET", "/api/v1/catalog", tokAdmin, nil)
	if code != 200 {
		t.Fatalf("GET /catalog = %d: %s", code, body)
	}
	var list struct {
		Apps []struct {
			ID   string `json:"id"`
			Icon string `json:"icon"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}

	checked := 0
	for _, a := range list.Apps {
		if a.Icon == "" {
			continue // icon là tuỳ chọn; thiếu thì UI dùng chữ cái đầu
		}
		checked++
		code, hdr, data := getRaw(t, srv, "/api/v1/catalog/icons/"+a.Icon, tokAdmin)
		if code != 200 {
			t.Errorf("app %q khai icon %q nhưng GET icon = %d", a.ID, a.Icon, code)
			continue
		}
		if len(data) == 0 {
			t.Errorf("icon %q rỗng", a.Icon)
		}
		if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "image/") {
			t.Errorf("icon %q Content-Type = %q, muốn image/*", a.Icon, ct)
		}
		if hdr.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("icon %q thiếu nosniff — SVG chạy được script", a.Icon)
		}
	}
	if checked == 0 {
		t.Fatal("không manifest nào khai icon — test này không kiểm được gì")
	}
}

// TestCatalogIconRejects — icon không được biến thành lỗ đọc file tuỳ ý, và
// không được lộ ra ngoài phiên đăng nhập.
func TestCatalogIconRejects(t *testing.T) {
	srv, _ := newCatalogServer(t)

	t.Run("khong co icon do", func(t *testing.T) {
		code, _, _ := getRaw(t, srv, "/api/v1/catalog/icons/khong-ton-tai.svg", tokAdmin)
		if code != 404 {
			t.Fatalf("icon lạ = %d, muốn 404", code)
		}
	})

	t.Run("duyet thu muc", func(t *testing.T) {
		// Không khẳng định "phải khác 200": net/http chuẩn hoá ".." ngay ở
		// client, nên "/catalog/icons/.." rời máy dưới dạng "/catalog" và trúng
		// route danh sách — 200, nhưng handler icon chưa từng chạy. Điều thật
		// sự phải giữ là: KHÔNG tên xấu nào lấy được một file ra.
		//
		// %2e%2e%2f giải mã thành "../" sau khi qua chuẩn hoá, nên đó mới là
		// đường thực sự chạm tới PathValue.
		for _, bad := range []string{"..", "%2e%2e", "%2e%2e%2fmanifests%2fnginx.json", "%2fetc%2fpasswd"} {
			code, hdr, body := getRaw(t, srv, "/api/v1/catalog/icons/"+bad, tokAdmin)
			if code == 200 && strings.HasPrefix(hdr.Get("Content-Type"), "image/") {
				t.Errorf("icon %q trả một file ảnh — đọc được thứ ngoài icons/: %d bytes", bad, len(body))
			}
		}
	})

	t.Run("khong token", func(t *testing.T) {
		code, _, _ := getRaw(t, srv, "/api/v1/catalog/icons/nginx.svg", "")
		if code != 401 {
			t.Fatalf("icon không token = %d, muốn 401", code)
		}
	})
}

// Thẻ catalog phải biết app nào đã cài — không thì Whoami mời "Install" trên
// box đã chạy whoami, và gói 1-app trả lỗi hạn mức trông như hỏng. Cài dưới
// slug KHÁC id để chắc đối chiếu đi theo image chứ không theo tên.
func TestCatalogListMarksInstalled(t *testing.T) {
	srv, _ := newCatalogServer(t)

	code, body := do(t, srv, "POST", "/api/v1/catalog/whoami/install", tokAdmin, map[string]any{"slug": "diag"})
	if code != 201 {
		t.Fatalf("POST install = %d: %s", code, body)
	}
	var app store.App
	if err := json.Unmarshal(body, &app); err != nil {
		t.Fatal(err)
	}

	code, body = do(t, srv, "GET", "/api/v1/catalog", tokReader, nil)
	if code != 200 {
		t.Fatalf("GET /catalog = %d: %s", code, body)
	}
	var got struct {
		Apps []struct {
			ID        string            `json:"id"`
			Installed []json.RawMessage `json:"installed"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"installed":[]`) {
		t.Error("mục chưa cài phải mang installed: [] chứ không null/thiếu")
	}
	for _, a := range got.Apps {
		switch {
		case a.ID == "whoami":
			if len(a.Installed) != 1 {
				t.Fatalf("whoami.installed = %s, muốn đúng 1", a.Installed)
			}
			var ref struct{ ID, Slug string }
			json.Unmarshal(a.Installed[0], &ref)
			if ref.ID != app.ID || ref.Slug != "diag" {
				t.Errorf("whoami.installed[0] = %+v, muốn {%s diag}", ref, app.ID)
			}
		case len(a.Installed) != 0:
			t.Errorf("%s bị đánh dấu đã cài: %s", a.ID, a.Installed)
		}
	}
}

func TestImageRepo(t *testing.T) {
	for in, want := range map[string]string{
		"docker.io/traefik/whoami@sha256:abc": "docker.io/traefik/whoami",
		"nginx:1.27":                          "nginx",
		"registry:5000/app":                   "registry:5000/app",
		"registry:5000/app:v1@sha256:abc":     "registry:5000/app",
	} {
		if got := api.ImageRepoForTest(in); got != want {
			t.Errorf("imageRepo(%q) = %q, muốn %q", in, got, want)
		}
	}
}
