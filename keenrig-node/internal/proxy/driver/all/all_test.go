package all_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig/keenrig/keenrig-node/internal/proxy"
	_ "github.com/keenrig/keenrig/keenrig-node/internal/proxy/driver/all"
	"github.com/keenrig/keenrig/keenrig-node/internal/proxy/driver/nginx"
)

func cfg() proxy.Config {
	return proxy.Config{Layout: paths.New(filepath.Join("srv", "keenrig"))}
}

// controllerFor dựng Controller cho MỌI driver, kể cả driver TỪ CHỐI MỞ.
//
// Từ 2026-08-12 `nginx`/`nginx-owasp` từ chối `proxy.Open` cho tới khi
// Apply/Status có thật — đó là luật, canh ở TestDriverKhongPhucVuDuocThiTuChoiMo.
// Nhưng NĂNG LỰC của chúng vẫn phải được canh tiếp: tầng admission dựa vào sự
// KHÁC BIỆT năng lực giữa ba driver, và sự khác biệt đó không được phép trôi chỉ
// vì driver tạm thời chưa phục vụ được. Ngày Apply có thật, những khẳng định
// dưới đây phải vẫn đúng y nguyên.
func controllerFor(t *testing.T, name string) proxy.Controller {
	t.Helper()
	ctl, err := proxy.Open(context.Background(), name, cfg())
	switch {
	case err == nil:
		return ctl
	case !errors.Is(err, proxy.ErrNotImplemented):
		t.Fatalf("Open(%s): %v", name, err)
	}
	// Driver chưa phục vụ được: dựng thẳng để đọc năng lực.
	var d proxy.Controller
	var nerr error
	switch name {
	case "nginx":
		d, nerr = nginx.New(cfg(), nginx.Options{})
	case "nginx-owasp":
		d, nerr = nginx.New(cfg(), nginx.Options{WAF: true})
	default:
		t.Fatalf("driver %q từ chối mở mà test này không biết cách dựng nó", name)
	}
	if nerr != nil {
		t.Fatalf("dựng %s: %v", name, nerr)
	}
	return d
}

func capsOf(t *testing.T, name string) proxy.Caps {
	t.Helper()
	caps, err := controllerFor(t, name).Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities(%s): %v", name, err)
	}
	return caps
}

func TestBaDriverDaDangKy(t *testing.T) {
	got := strings.Join(proxy.Registered(), ",")
	if want := "caddy,nginx,nginx-owasp"; got != want {
		t.Errorf("Registered() = %q, muốn %q", got, want)
	}
}

func TestMacDinhLaCaddy(t *testing.T) {
	// Không đặt biến môi trường.
	name := proxy.DriverFromEnv(func(string) (string, bool) { return "", false })
	if name != "caddy" {
		t.Fatalf("driver mặc định = %q, muốn caddy", name)
	}
	c, err := proxy.Open(context.Background(), name, cfg())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if c.Name() != "caddy" {
		t.Errorf("Name() = %q", c.Name())
	}
}

func TestEnvChonDungTenDriver(t *testing.T) {
	cases := []struct{ env, want string }{
		{"nginx", "nginx"},
		{"nginx-owasp", "nginx-owasp"},
		{"  caddy  ", "caddy"}, // khoảng trắng thừa trong env là chuyện thường
		{"", "caddy"},          // đặt nhưng để rỗng → về mặc định
	}
	for _, c := range cases {
		name := proxy.DriverFromEnv(func(k string) (string, bool) {
			if k == proxy.EnvDriver {
				return c.env, true
			}
			return "", false
		})
		if name != c.want {
			t.Errorf("KEENRIG_PROXY=%q → %q, muốn %q", c.env, name, c.want)
		}
	}
}

// Driver KHÔNG phục vụ được thì TỪ CHỐI MỞ — không phải mở xong rồi lỗi lúc Apply.
//
// Đây là luật của chính package proxy (PR-06/07: cấu hình gateway sai thì lỗi nổ
// LÚC MỞ), áp cho một dạng "sai" khác: driver không định tuyến được gì.
//
// Đo được TRƯỚC khi vá, trên box thật không có app nào: `KEENRIG_PROXY=nginx`
// làm box khởi động bình thường, log `proxy=nginx`, API trả 200 — không tín hiệu
// nào. Và cứ 15 giây reconciler lại ghi một event `proxy.apply_failed` vào
// platform.db: 3 event rác trong 50 giây, ngang với 3 event THẬT. Retention 90
// ngày → ~518.000 dòng cùng một lỗi trong audit log.
func TestDriverKhongPhucVuDuocThiTuChoiMo(t *testing.T) {
	for _, name := range []string{"nginx", "nginx-owasp"} {
		t.Run(name, func(t *testing.T) {
			_, err := proxy.Open(context.Background(), name, cfg())
			if !errors.Is(err, proxy.ErrNotImplemented) {
				t.Fatalf("Open(%s) = %v, muốn ErrNotImplemented", name, err)
			}
			// Thông báo phải chỉ đường ra, không chỉ nói "chưa xong": người vận
			// hành đang cần một gateway CHẠY ĐƯỢC ngay bây giờ.
			if !strings.Contains(err.Error(), proxy.DefaultDriver) {
				t.Errorf("thông báo không chỉ sang %q: %v", proxy.DefaultDriver, err)
			}
		})
	}
}

// Và lỗi đó phải KHÁC lỗi gõ sai tên: hai chuyện dẫn tới hai hành động khác nhau
// — sửa chính tả, hay đổi driver và chờ.
func TestChuaXongKhacGoSaiTen(t *testing.T) {
	_, notReady := proxy.Open(context.Background(), "nginx", cfg())
	_, typo := proxy.Open(context.Background(), "nginz", cfg())
	if errors.Is(notReady, proxy.ErrUnknownDriver) {
		t.Error("driver chưa xong bị báo như gõ sai tên")
	}
	if errors.Is(typo, proxy.ErrNotImplemented) {
		t.Error("gõ sai tên bị báo như driver chưa xong")
	}
}

// Gõ sai tên biến môi trường là lỗi phổ biến nhất — thông báo phải liệt kê tên
// hợp lệ chứ không chỉ nói "không tìm thấy".
func TestTenSaiBaoLoiKemDanhSach(t *testing.T) {
	_, err := proxy.Open(context.Background(), "nginz", cfg())
	if !errors.Is(err, proxy.ErrUnknownDriver) {
		t.Fatalf("err = %v, muốn ErrUnknownDriver", err)
	}
	for _, name := range proxy.Registered() {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("thông báo lỗi thiếu %q: %s", name, err)
		}
	}
}

// Khác biệt năng lực giữa 3 driver là điểm cả thiết kế dựa vào — nếu nó sai thì
// tầng admission cho qua thứ gateway không làm được.
func TestKhacBietNangLucGiuaBaDriver(t *testing.T) {
	caps := map[string]proxy.Caps{}
	for _, name := range proxy.Registered() {
		caps[name] = capsOf(t, name)
	}

	// Chỉ caddy tự xin cert; nginx buộc platform phải cấp.
	if !caps["caddy"].Has(proxy.CapACME) {
		t.Error("caddy phải có acme")
	}
	for _, n := range []string{"nginx", "nginx-owasp"} {
		if caps[n].Has(proxy.CapACME) {
			t.Errorf("%s không được khai có acme — nginx không tự xin cert", n)
		}
		if !caps[n].Has(proxy.CapCertUpload) {
			t.Errorf("%s phải nhận được cert do platform cấp", n)
		}
	}

	// WAF: chỉ biến thể owasp.
	if caps["nginx"].Has(proxy.CapWAF) {
		t.Error("nginx thường không được khai có waf")
	}
	if !caps["nginx-owasp"].Has(proxy.CapWAF) {
		t.Error("nginx-owasp phải có waf")
	}

	// Ngoài WAF, hai biến thể nginx phải giống hệt nhau — bằng chứng chúng là
	// MỘT driver hai hồ sơ, không phải hai bản cài đặt song song sẽ trôi xa nhau.
	for cap := range caps["nginx"] {
		if !caps["nginx-owasp"].Has(cap) {
			t.Errorf("nginx-owasp thiếu %q mà nginx có", cap)
		}
	}
	for cap := range caps["nginx-owasp"] {
		if cap == proxy.CapWAF {
			continue
		}
		if !caps["nginx"].Has(cap) {
			t.Errorf("nginx thiếu %q mà nginx-owasp có", cap)
		}
	}

	// Chỉ caddy quan sát được cấu hình đang chạy và áp nguyên khối.
	for _, cap := range []proxy.Capability{proxy.CapObserve, proxy.CapAtomicApply} {
		if !caps["caddy"].Has(cap) {
			t.Errorf("caddy phải có %q", cap)
		}
		if caps["nginx"].Has(cap) {
			t.Errorf("nginx không được khai có %q", cap)
		}
	}
}

// Tầng admission phải từ chối site cần WAF khi đang chạy nginx thường, và cho
// qua khi đổi sang nginx-owasp. Đây là toàn bộ lý do Capabilities tồn tại.
func TestAdmissionTuChoiWAFTrenNginxThuong(t *testing.T) {
	site := proxy.Site{
		FQDN:   "shop.tld",
		AppID:  "app-1",
		TLS:    proxy.TLS{Mode: proxy.TLSProvided, CertRef: "shop.tld"},
		Policy: proxy.Policy{WAF: &proxy.WAF{Ruleset: "owasp-crs", Block: true}},
	}

	bad := proxy.Check([]proxy.Site{site}, capsOf(t, "nginx"))
	if len(bad) != 1 || bad[0].Cap != proxy.CapWAF {
		t.Fatalf("nginx thường phải từ chối đúng 1 lý do waf, nhận %v", bad)
	}
	if ok := proxy.Check([]proxy.Site{site}, capsOf(t, "nginx-owasp")); len(ok) != 0 {
		t.Errorf("nginx-owasp phải cho qua, nhận %v", ok)
	}
}

// Đúng HAI biến môi trường, không hơn.
func TestChiHaiBienMoiTruong(t *testing.T) {
	env := map[string]string{
		proxy.EnvDriver: "caddy",
		proxy.EnvConfig: "http://127.0.0.1:2019",
	}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	ctl, err := proxy.OpenFromEnv(context.Background(), paths.New("srv"), proxy.Upstream{}, nil, lookup)
	if err != nil {
		t.Fatalf("OpenFromEnv: %v", err)
	}
	if ctl.Name() != "caddy" {
		t.Errorf("Name() = %q", ctl.Name())
	}

	c := proxy.ConfigFromEnv(paths.New("srv"), proxy.Upstream{}, nil, lookup)
	if c.DSN != "http://127.0.0.1:2019" {
		t.Errorf("DSN = %q", c.DSN)
	}
}

func TestDSNRongThiDungMacDinhCuaDriver(t *testing.T) {
	lookup := func(string) (string, bool) { return "", false }
	for _, name := range proxy.Registered() {
		_, err := proxy.Open(context.Background(), name, proxy.ConfigFromEnv(paths.New("srv"), proxy.Upstream{}, nil, lookup))
		// ErrNotImplemented là câu trả lời HỢP LỆ ở đây: nó nói "driver chưa
		// phục vụ được", không phải "DSN rỗng sai". Cái test này canh là DSN
		// rỗng KHÔNG bị coi là cấu hình sai.
		if err != nil && !errors.Is(err, proxy.ErrNotImplemented) {
			t.Errorf("Open(%s) với DSN rỗng phải dùng mặc định, nhận: %v", name, err)
		}
	}
}

// DSN sai cú pháp phải nổ lúc MỞ driver, không đợi tới Apply.
func TestDSNSaiNoLucMo(t *testing.T) {
	_, err := proxy.Open(context.Background(), "caddy",
		proxy.Config{Layout: paths.New("srv"), DSN: "tcp://host:2019"})
	if !errors.Is(err, proxy.ErrBadConfig) {
		t.Fatalf("err = %v, muốn ErrBadConfig", err)
	}
}

func TestDSNOr(t *testing.T) {
	if got := (proxy.Config{DSN: "  x  "}).DSNOr("def"); got != "x" {
		t.Errorf("DSNOr = %q, muốn x (đã cắt khoảng trắng)", got)
	}
	if got := (proxy.Config{DSN: "   "}).DSNOr("def"); got != "def" {
		t.Errorf("DSN toàn khoảng trắng phải rơi về mặc định, nhận %q", got)
	}
	if got := (proxy.Config{}).DSNOr("def"); got != "def" {
		t.Errorf("DSNOr = %q, muốn def", got)
	}
}

// implemented — driver đã có Apply/Status thật (T8 làm caddy trước vì nó là
// DefaultDriver). Danh sách này PHẢI thu hẹp dần; khi rỗng thì xoá luôn
// TestChuaHienThucThiBaoLoiRo bên dưới.
var implemented = map[string]bool{"caddy": true}

// Driver đã đăng ký nhưng CHƯA hiện thực phải TỪ CHỐI MỞ.
//
// Bản trước của test này chỉ đòi Apply trả ErrNotImplemented — tức là chấp nhận
// một driver mở được nhưng không định tuyến gì. Đo trên box thật cho thấy cái
// giá của việc chấp nhận đó: một cơn bão event 15 giây một lần vào audit log.
// Luật giờ chặt hơn, và nó khớp với PR-06/07.
func TestChuaHienThucThiTuChoiMo(t *testing.T) {
	ctx := context.Background()
	for _, name := range proxy.Registered() {
		if implemented[name] {
			continue
		}
		if _, err := proxy.Open(ctx, name, cfg()); !errors.Is(err, proxy.ErrNotImplemented) {
			t.Errorf("Open(%s) = %v, muốn ErrNotImplemented", name, err)
		}
		// Và bản thân driver vẫn phải nói thẳng khi bị gọi trực tiếp — dựng
		// được nhưng không làm được là hai chuyện khác nhau.
		c := controllerFor(t, name)
		if _, err := c.Apply(ctx, nil); !errors.Is(err, proxy.ErrNotImplemented) {
			t.Errorf("%s Apply err = %v, muốn ErrNotImplemented", name, err)
		}
		if _, err := c.Status(ctx); !errors.Is(err, proxy.ErrNotImplemented) {
			t.Errorf("%s Status err = %v, muốn ErrNotImplemented", name, err)
		}
	}
}

// Driver ĐÃ hiện thực thì không được còn trả ErrNotImplemented — nếu không,
// danh sách `implemented` ở trên sẽ nói dối mà chẳng ai biết.
func TestDaHienThucThiKhongConNotImplemented(t *testing.T) {
	ctx := context.Background()
	for name := range implemented {
		c, err := proxy.Open(ctx, name, cfg())
		if err != nil {
			t.Fatalf("Open(%s): %v", name, err)
		}
		// Không có gateway thật ở đây nên Apply sẽ lỗi KẾT NỐI — điều đó đúng
		// và đủ: cái ta khẳng định là lỗi KHÔNG PHẢI ErrNotImplemented.
		if _, err := c.Apply(ctx, nil); errors.Is(err, proxy.ErrNotImplemented) {
			t.Errorf("%s vẫn trả ErrNotImplemented dù đã có trong danh sách implemented", name)
		}
	}
}
