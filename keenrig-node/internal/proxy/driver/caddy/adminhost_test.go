package caddy

// Host của request admin qua unix socket phải lọt `admin.origins` mà
// caddy-bootstrap.sh ghi. Hai đầu nằm ở hai module (driver Go, script cài) và
// lệch nhau là lỗi IM LẶNG: Caddy chạy, :443 mở, mọi Apply nhận 403 "host not
// allowed" và không route nào vào. Đo được trên VPS thật 2026-10-02 (case 1),
// khi driver còn gửi Host `caddy-admin`.

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Đầu script: origins mà bootstrap ghi phải chứa đúng Host driver gửi.
func TestBootstrapOriginsAllowTheDriverHost(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..",
		"keenrig-node-installer", "scripts", "caddy-bootstrap.sh"))
	if err != nil {
		t.Fatalf("đọc caddy-bootstrap.sh: %v", err)
	}
	m := regexp.MustCompile(`"origins":\s*\[([^\]]*)\]`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("caddy-bootstrap.sh không khai admin.origins — Caddy sẽ dùng mặc định, không khớp gì cả")
	}
	if !strings.Contains(string(m[1]), `"`+adminHost+`"`) {
		t.Errorf("admin.origins = [%s] không chứa %q — mọi Apply sẽ nhận 403", m[1], adminHost)
	}
}

// Đầu driver: request qua socket THẬT mang Host = adminHost. Server ở đây làm
// đúng phép kiểm của Caddy với origins ["localhost"].
func TestAdminOverUnixSocketSendsAnAllowedHost(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "caddy-admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix socket không dùng được ở đây: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "localhost" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"host not allowed: ` + r.Host + `"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	c := newAdminClient(schemeUnix + sock)
	if _, err := c.do(t.Context(), http.MethodGet, "/config/apps", nil); err != nil {
		t.Fatalf("admin qua socket bị từ chối: %v", err)
	}
}
