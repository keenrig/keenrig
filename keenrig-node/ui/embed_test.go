package ui_test

// Test T11 — asset Admin nhúng trong binary và cách phục vụ SPA (UI-01).

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/ui"
)

func requireBuilt(t *testing.T) {
	t.Helper()
	if !ui.Available() {
		t.Skip("chưa build UI (chạy `npm ci && npm run build` trong keenrig-node/ui)")
	}
}

func TestSPAServesIndexAndAssets(t *testing.T) {
	requireBuilt(t)
	h := ui.Handler()

	// "/" trả index.html.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET / = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "<div id=\"app\">") {
		t.Errorf("index.html không như mong đợi: %s", w.Body.String())
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		// index.html cache được nghĩa là người dùng giữ mãi bản UI cũ sau update.
		t.Errorf("index.html Cache-Control = %q, muốn no-cache", cc)
	}

	// Đường dẫn client-side route KHÔNG có file thật vẫn trả index.html.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/apps", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<div id=\"app\">") {
		t.Errorf("GET /apps = %d — SPA phải fallback về index.html", w.Code)
	}

	// Asset có hash trong tên → cache vĩnh viễn.
	sub, err := ui.FS()
	if err != nil {
		t.Fatal(err)
	}
	var asset string
	_ = fs.WalkDir(sub, "assets", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && asset == "" {
			asset = p
		}
		return nil
	})
	if asset == "" {
		t.Fatal("không tìm thấy asset nào trong dist/assets")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/"+asset, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /%s = %d", asset, w.Code)
	}
	if !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Errorf("asset có hash phải cache immutable, nhận %q", w.Header().Get("Cache-Control"))
	}
}

// Asset THIẾU phải 404, KHÔNG fallback về index.html: trả HTML cho một file .js
// làm trình duyệt báo "Unexpected token '<'" — thông báo chẳng liên quan gì tới
// nguyên nhân thật.
func TestMissingAssetIs404(t *testing.T) {
	requireBuilt(t)
	w := httptest.NewRecorder()
	ui.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/assets/không-có-thật.js", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("asset thiếu = %d, muốn 404 (body: %.80s)", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	ui.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/favicon.ico", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("/favicon.ico = %d, muốn 404 (body: %.80s)", w.Code, w.Body.String())
	}
}

// Favicon Keenrig phải nằm trong bản build: thiếu nó, trình duyệt hiện favicon
// cũ đã cache cho host — trên VPS tái sử dụng là logo của phần mềm khác.
func TestFaviconEmbedded(t *testing.T) {
	requireBuilt(t)
	w := httptest.NewRecorder()
	ui.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/favicon.svg", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `aria-label="Keenrig"`) {
		t.Errorf("/favicon.svg = %d (body: %.80s)", w.Code, w.Body.String())
	}
}

// Hai ngôn ngữ phải có ĐÚNG cùng tập khoá. Thiếu khoá ở một bên nghĩa là người
// dùng thấy chuỗi lạ (hoặc chính tên khoá) ngay giữa giao diện.
//
// Phép kiểm này SỐNG SÓT qua việc bỏ gate `UI-08` (2026-09-02). Cái bị bỏ là luật
// "tiếng Việt là locale gốc" — Admin UI giờ mặc định tiếng Anh. Cái KHÔNG bị bỏ là
// "cả hai ngôn ngữ phủ 100%": đổi mặc định mà để một bản dịch teo dần thì người
// bấm sang tiếng Việt nhận một giao diện lẫn hai thứ tiếng, và `fallbackLocale`
// giờ là `en` nên khoá thiếu ở vi im lặng hiện tiếng Anh thay vì lỗi thấy được.
func TestLocaleKeysMatch(t *testing.T) {
	vi := loadLocale(t, "vi.json")
	en := loadLocale(t, "en.json")

	viKeys := flatten(vi, "")
	enKeys := flatten(en, "")
	for k := range viKeys {
		if _, ok := enKeys[k]; !ok {
			t.Errorf("en thiếu khoá %q", k)
		}
	}
	for k := range enKeys {
		if _, ok := viKeys[k]; !ok {
			t.Errorf("vi thiếu khoá %q", k)
		}
	}
	if len(viKeys) == 0 {
		t.Fatal("không đọc được khoá nào — test này vô nghĩa nếu file rỗng")
	}
	// Không chuỗi nào được để rỗng: chuỗi rỗng hiện ra như một khoảng trắng và
	// không ai phát hiện cho tới khi người dùng hỏi nút này là nút gì.
	for k, v := range viKeys {
		if strings.TrimSpace(v) == "" {
			t.Errorf("vi.%s rỗng", k)
		}
	}
	for k, v := range enKeys {
		if strings.TrimSpace(v) == "" {
			t.Errorf("en.%s rỗng", k)
		}
	}
}

func loadLocale(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("src", "i18n", name))
	if err != nil {
		t.Fatalf("đọc %s: %v", name, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return m
}

func flatten(m map[string]any, prefix string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch t := v.(type) {
		case map[string]any:
			for ik, iv := range flatten(t, key) {
				out[ik] = iv
			}
		case string:
			out[key] = t
		}
	}
	return out
}

// Nguồn UI phải gọi API qua client dùng chung, không fetch rải rác: một chỗ
// fetch riêng là một chỗ quên xử lý 401 và quên credentials same-origin.
func TestNoStrayFetchCalls(t *testing.T) {
	var offenders []string
	err := filepath.Walk("src", func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if filepath.Base(p) == "client.js" {
			return nil
		}
		ext := filepath.Ext(p)
		if ext != ".vue" && ext != ".js" {
			return nil
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(raw), "fetch(") {
			offenders = append(offenders, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("gọi fetch() ngoài api/client.js: %v", offenders)
	}
}
