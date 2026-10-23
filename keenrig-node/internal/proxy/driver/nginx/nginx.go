// Package nginx — driver proxy.Controller trên nginx.
//
// Đăng ký HAI tên từ MỘT package:
//
//	nginx         nginx thường
//	nginx-owasp   nginx + ModSecurity nạp OWASP Core Rule Set
//
// Chúng KHÔNG phải hai driver. Toàn bộ đường render config, validate và reload
// giống hệt nhau; khác biệt duy nhất là có nạp module WAF hay không, và điều
// đó chỉ đổi hai thứ: tập Capabilities trả về, và mấy chỉ thị modsecurity
// trong template. Tách thành hai package là nhân đôi phần khó (render + reload)
// để khỏi lặp phần dễ (một cờ bool).
//
// # Cú pháp KEENRIG_PROXY_CONFIG
//
//	<reload command>
//	<reload command> ;; <test command>
//
// Ví dụ:
//
//	KEENRIG_PROXY_CONFIG="nginx -s reload"                              (mặc định)
//	KEENRIG_PROXY_CONFIG="systemctl reload nginx"
//	KEENRIG_PROXY_CONFIG="docker exec gw nginx -s reload ;; docker exec gw nginx -t"
//
// Vế thứ hai tồn tại vì lệnh kiểm tra KHÔNG suy ra được từ lệnh reload: chạy
// nginx trong container thì cả hai đều phải bọc `docker exec`, còn dùng
// systemctl thì `nginx -t` vẫn gọi thẳng nhị phân. Đoán sai chỗ này nghĩa là
// reload một config chưa từng được validate.
//
// Đường dẫn (sites dir, cert dir) KHÔNG nằm trong DSN — chúng đến từ
// paths.Layout, xem docs/FILESYSTEM.md.
package nginx

import (
	"context"
	"fmt"
	"strings"

	"github.com/keenrig/keenrig/keenrig-node/internal/proxy"
)

// Tên driver đã đăng ký.
const (
	NameNginx = "nginx"
	NameOWASP = "nginx-owasp"
)

// Mặc định + dấu tách hai vế của DSN.
const (
	dsnSep            = ";;"
	defaultReloadCmd  = "nginx -s reload"
	defaultTestCmd    = "nginx -t"
	dsnUsage          = `syntax: "<reload command>" or "<reload command> ;; <test command>"`
	sitesFilePrefix   = "keenrig-" // mọi file .conf sinh ra mang tiền tố này
	modsecRulesetName = "owasp-crs"
)

// Hai biến thể nginx đăng ký tên nhưng KHAI LÀ CHƯA PHỤC VỤ ĐƯỢC, cho tới khi
// Apply/Status có thật.
//
// # Vì sao chặn ở cửa mở chứ không để nó chạy rồi lỗi lúc Apply
//
// Đó là luật của chính package proxy (PR-06/07): cấu hình gateway sai thì lỗi
// nổ LÚC MỞ, không đợi người dùng deploy app đầu tiên. Một driver không định
// tuyến được gì cũng là "sai" theo đúng nghĩa đó.
//
// Đo được TRƯỚC khi vá, trên box thật không có app nào: `KEENRIG_PROXY=nginx`
// làm box khởi động BÌNH THƯỜNG, log `proxy=nginx`, API trả 200 — không một tín
// hiệu nào. Rồi cứ mỗi 15 giây (nhịp refresh), reconciler gọi Apply, nhận
// ErrNotImplemented và ghi MỘT event `proxy.apply_failed` vào platform.db.
// Đếm thật: 3 event rác trong 50 giây, ngang với 3 event THẬT (box.start,
// lease.acquired, job.completed). Với retention 90 ngày của housekeep, đó là
// ~518.000 dòng cùng một lỗi — audit log, thứ `events/doc.go` gọi là "bằng
// chứng bất biến", bị nhấn chìm.
//
// New() vẫn dùng được: phần phân tích DSN và render config đã có thật và có
// test riêng. Thứ thiếu là Apply/Status, và đó mới là thứ chặn.
func init() {
	const why = "cannot route anything yet (Apply and Status are stubs)"
	proxy.RegisterUnavailable(NameNginx, why)
	proxy.RegisterUnavailable(NameOWASP, why)
}

type Options struct {
	// WAF bật ModSecurity + OWASP CRS. Chỉ đặt true khi nhị phân nginx THẬT SỰ
	// có module — khai báo CapWAF mà module chưa nạp là nói dối tầng admission,
	// và người dùng sẽ tưởng app của họ đang được bảo vệ.
	WAF bool
}

// Driver hiện thực proxy.Controller bằng cách render file config rồi reload.
type Driver struct {
	opts Options

	// sitesDir là thư mục file .conf sinh ra. Đây là CACHE DẪN XUẤT của bảng
	// route trong store, không phải nguồn sự thật: xoá đi thì lần Apply sau
	// dựng lại đủ. Mọi file trong đây mang tiền tố keenrig- để Apply không bao
	// giờ đụng vhost do người vận hành tự đặt.
	sitesDir string
	certDir  string

	reloadCmd string
	testCmd   string
}

var _ proxy.Controller = (*Driver)(nil)

func New(cfg proxy.Config, opts Options) (*Driver, error) {
	reload, test, err := parseDSN(cfg.DSN)
	if err != nil {
		return nil, err
	}
	return &Driver{
		opts:      opts,
		sitesDir:  cfg.Layout.ProxySites(),
		certDir:   cfg.Layout.ProxyCerts(),
		reloadCmd: reload,
		testCmd:   test,
	}, nil
}

// parseDSN tách "<reload> ;; <test>". DSN rỗng → cả hai lấy mặc định.
//
// Kiểm ngay tại đây chứ không đợi tới Apply: cấu hình gateway sai phải nổ lúc
// khởi động, không phải lúc người dùng deploy app đầu tiên.
func parseDSN(dsn string) (reload, test string, err error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return defaultReloadCmd, defaultTestCmd, nil
	}

	before, after, hasSep := strings.Cut(dsn, dsnSep)
	reload = strings.TrimSpace(before)
	test = strings.TrimSpace(after)

	if reload == "" {
		return "", "", fmt.Errorf("%w: %s: the reload command is empty — %s", proxy.ErrBadConfig, NameNginx, dsnUsage)
	}
	if hasSep {
		if test == "" {
			return "", "", fmt.Errorf("%w: %s: %q is present but the test command is empty — %s",
				proxy.ErrBadConfig, NameNginx, dsnSep, dsnUsage)
		}
		if strings.Contains(test, dsnSep) {
			return "", "", fmt.Errorf("%w: %s: %q appears more than once — %s",
				proxy.ErrBadConfig, NameNginx, dsnSep, dsnUsage)
		}
	} else {
		test = defaultTestCmd
	}
	return reload, test, nil
}

func (d *Driver) Name() string {
	if d.opts.WAF {
		return NameOWASP
	}
	return NameNginx
}

// Capabilities — khác biệt so với caddy nằm ở ba dòng vắng mặt, và cả ba đều
// là sự thật kỹ thuật chứ không phải lựa chọn:
//
//   - KHÔNG có CapACME: nginx không tự xin cert, platform phải cấp
//     (CapCertUpload). Đó là lý do module certs vẫn phải chạy khi đổi sang nginx.
//   - KHÔNG có CapAtomicApply: `nginx -t` giữ được config ĐANG PHỤC VỤ khi
//     render hỏng, nhưng file trên đĩa thì recorded dở. Reconciler không được
//     tin "Apply lỗi = chưa có gì đổi".
//   - KHÔNG có CapObserve: đọc lại file do chính mình ghi không phải là quan
//     sát cấu hình đang chạy. Muốn biết nginx thực sự đang phục vụ gì thì phải
//     hỏi nginx, mà nginx không có API để hỏi.
func (d *Driver) Capabilities(ctx context.Context) (proxy.Caps, error) {
	c := proxy.Caps{
		proxy.CapCertUpload:  true,
		proxy.CapWildcardTLS: true,
		proxy.CapTLSPassthru: true,
		proxy.CapLoadBalance: true,
		proxy.CapWebSocket:   true,
		proxy.CapRateLimit:   true,
		proxy.CapIPFilter:    true,
		proxy.CapForwardAuth: true,
		proxy.CapBodyLimit:   true,
	}
	if d.opts.WAF {
		c[proxy.CapWAF] = true
	}
	return c, nil
}

func (d *Driver) Apply(ctx context.Context, desired []proxy.Site) (proxy.Report, error) {
	return proxy.Report{}, fmt.Errorf("%w: %s Apply", proxy.ErrNotImplemented, d.Name())
}

func (d *Driver) Status(ctx context.Context) ([]proxy.Site, error) {
	return nil, fmt.Errorf("%w: %s Status", proxy.ErrNotImplemented, d.Name())
}
