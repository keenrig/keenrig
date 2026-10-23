package httpd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

func openTestStore(t *testing.T) *store.SQLite {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	return st
}

func TestHealthzReadyz(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	s := New(st, ":0")
	ts := httptest.NewServer(s.srv.Handler)
	defer ts.Close()

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, muốn 200", path, resp.StatusCode)
		}
	}

	resp, err := http.Post(ts.URL+"/healthz", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /healthz = %d, muốn 405", resp.StatusCode)
	}
}

// Store đóng (Ping fail) → healthz phải trả 503, không panic.
func TestHealthzStoreClosed(t *testing.T) {
	st := openTestStore(t)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s := New(st, ":0")
	ts := httptest.NewServer(s.srv.Handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("GET /healthz với store đóng = %d, muốn 503", resp.StatusCode)
	}
}

// Đường của OIDC phải trả JSON kể cả khi IdP CHƯA bật.
//
// # Đây là một lỗi đo được trên box thật
//
// Bản đầu chỉ đăng ký hai đường đó khi provider được cắm. Chạy box thật (có SPA
// nhúng trong binary) mà không khai `KEENRIG_OIDC_ISSUER`, rồi gọi discovery:
//
//	HTTP 200 · Content-Type: text/html · thân là index.html của Admin UI
//
// SPA nhận "/" nên nó nuốt mọi đường không ai nhận. Một Relying Party gặp đúng
// thứ tệ nhất — mã thành công, thân là HTML — và lỗi hiện ra ở phía app dưới
// dạng "unexpected token < in JSON", không nhắc gì tới box.
func TestOIDCPathsAnswerJSONWhenDisabled(t *testing.T) {
	st := openTestStore(t)
	defer st.Close()

	// SPA giả ở "/" — đúng hình dạng của một binary đã `npm run build`.
	spa := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html><html>Admin UI</html>"))
	})
	s := New(st, ":0", WithUI(spa))
	ts := httptest.NewServer(s.srv.Handler)
	defer ts.Close()

	for _, path := range []string{OIDCDiscoveryPath, OIDCPathPrefix + "jwks.json"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Errorf("GET %s = 200 khi IdP chưa bật — SPA đã nuốt đường này: %s", path, body)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
			t.Errorf("GET %s trả Content-Type %q, phải là JSON", path, ct)
		}
		// Thông báo phải nói TÊN BIẾN phải đặt: người vận hành đọc lỗi này là
		// người phải sửa nó.
		if !strings.Contains(string(body), "KEENRIG_OIDC_ISSUER") {
			t.Errorf("GET %s không nói biến nào phải đặt: %s", path, body)
		}
	}

	// Và SPA vẫn phải nhận mọi đường KHÁC — bản vá không được cướp thêm gì.
	resp, err := http.Get(ts.URL + "/apps")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /apps = %d — bản vá lấy mất đường của SPA", resp.StatusCode)
	}
}
