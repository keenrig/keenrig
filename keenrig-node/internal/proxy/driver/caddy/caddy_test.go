package caddy

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/proxy"
)

func cfg(dsn string) proxy.Config {
	return proxy.Config{Layout: paths.New(filepath.Join("srv", "keenrig")), DSN: dsn}
}

// Mặc định phải là unix socket dưới RunDir, KHÔNG phải TCP: admin API của Caddy
// không có xác thực, nên mở ra mạng phải là hành động tường minh.
func TestMacDinhLaUnixSocketTrongRunDir(t *testing.T) {
	d, err := New(cfg(""))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !strings.HasPrefix(d.adminURL, schemeUnix) {
		t.Errorf("adminURL = %q — mặc định phải là unix socket", d.adminURL)
	}
	if !strings.Contains(d.adminURL, adminSock) {
		t.Errorf("adminURL = %q — thiếu %s", d.adminURL, adminSock)
	}
	if strings.Contains(d.adminURL, `\`) {
		t.Errorf("adminURL = %q — endpoint là URL, không được chứa dấu phân cách Windows", d.adminURL)
	}
}

func TestDSNGhiDeEndpoint(t *testing.T) {
	d, err := New(cfg("http://127.0.0.1:2019"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if d.adminURL != "http://127.0.0.1:2019" {
		t.Errorf("adminURL = %q", d.adminURL)
	}
}

func TestEndpointSaiThiBaoLoiKemCuPhap(t *testing.T) {
	for _, dsn := range []string{
		"127.0.0.1:2019",  // thiếu scheme
		"tcp://host:2019", // scheme không hỗ trợ
		"unix/",           // thiếu đường dẫn socket
	} {
		_, err := New(cfg(dsn))
		if !errors.Is(err, proxy.ErrBadConfig) {
			t.Fatalf("New(%q) err = %v, muốn ErrBadConfig", dsn, err)
		}
		// Thông báo lỗi của sản phẩm là TIẾNG ANH (quyết định 2026-08-10);
		// thông báo của test thì vẫn tiếng Việt — hai đối tượng đọc khác nhau.
		if !strings.Contains(err.Error(), "syntax:") {
			t.Errorf("thông báo lỗi cho %q không nêu cú pháp đúng: %s", dsn, err)
		}
	}
}

// Đường dẫn trên đĩa đến từ paths.Layout, KHÔNG từ env — bố cục là hợp đồng
// (docs/FILESYSTEM.md), không phải nút vặn.
func TestDuongDanLayTuLayoutKhongTuDSN(t *testing.T) {
	l := paths.New(filepath.Join("srv", "keenrig"))
	d, err := New(proxy.Config{Layout: l, DSN: "http://127.0.0.1:2019"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if d.certDir != l.ProxyCerts() {
		t.Errorf("certDir = %q, muốn %q", d.certDir, l.ProxyCerts())
	}
}
