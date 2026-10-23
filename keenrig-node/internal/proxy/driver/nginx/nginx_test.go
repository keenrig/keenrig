package nginx

import (
	"errors"
	"strings"
	"testing"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/proxy"
)

func TestParseDSN(t *testing.T) {
	cases := []struct {
		name       string
		dsn        string
		wantReload string
		wantTest   string
	}{
		{"rỗng → mặc định", "", defaultReloadCmd, defaultTestCmd},
		{"chỉ khoảng trắng", "   ", defaultReloadCmd, defaultTestCmd},
		{"một vế", "systemctl reload nginx", "systemctl reload nginx", defaultTestCmd},
		{"hai vế", "docker exec gw nginx -s reload ;; docker exec gw nginx -t",
			"docker exec gw nginx -s reload", "docker exec gw nginx -t"},
		{"hai vế không khoảng trắng", "a;;b", "a", "b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reload, test, err := parseDSN(c.dsn)
			if err != nil {
				t.Fatalf("parseDSN(%q): %v", c.dsn, err)
			}
			if reload != c.wantReload {
				t.Errorf("reload = %q, muốn %q", reload, c.wantReload)
			}
			if test != c.wantTest {
				t.Errorf("test = %q, muốn %q", test, c.wantTest)
			}
		})
	}
}

// DSN sai phải nổ lúc MỞ driver, kèm cú pháp đúng — người vận hành gõ sai env
// lúc 2 giờ sáng cần biết phải sửa thành gì, không chỉ biết là mình sai.
func TestParseDSNSaiThiBaoLoiKemCuPhap(t *testing.T) {
	for _, dsn := range []string{
		";; nginx -t",        // thiếu vế reload
		"nginx -s reload ;;", // thiếu vế test
		"a ;; b ;; c",        // quá hai vế
	} {
		_, _, err := parseDSN(dsn)
		if !errors.Is(err, proxy.ErrBadConfig) {
			t.Fatalf("parseDSN(%q) err = %v, muốn ErrBadConfig", dsn, err)
		}
		// Sản phẩm báo lỗi bằng tiếng Anh (quyết định 2026-08-10).
		if !strings.Contains(err.Error(), "reload command") {
			t.Errorf("thông báo lỗi cho %q không nêu cú pháp đúng: %s", dsn, err)
		}
	}
}

func TestNewTraLoiKhiDSNSai(t *testing.T) {
	if _, err := New(proxy.Config{DSN: "a ;; b ;; c"}, Options{}); !errors.Is(err, proxy.ErrBadConfig) {
		t.Fatalf("New err = %v, muốn ErrBadConfig", err)
	}
}

// Lệnh kiểm tra KHÔNG suy ra được từ lệnh reload — đây là lý do vế thứ hai tồn
// tại. Chạy nginx trong container thì cả hai đều phải bọc docker exec.
func TestLenhKiemTraKhongSuyRaTuLenhReload(t *testing.T) {
	d, err := New(proxy.Config{DSN: "docker exec gw nginx -s reload ;; docker exec gw nginx -t"}, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !strings.HasPrefix(d.testCmd, "docker exec") {
		t.Errorf("testCmd = %q — reload chạy trong container mà test lại chạy ngoài host", d.testCmd)
	}
}
