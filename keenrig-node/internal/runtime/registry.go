package runtime

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/keenrig/keenrig/keenrig-node/internal/paths"
)

// Chọn nơi chạy app bằng ĐÚNG HAI biến môi trường — cùng mô hình với seam
// proxy và với database/sql: Open(driverName, dataSourceName).
//
//	KEENRIG_RUNTIME=docker|swarm|k8s     mặc định docker
//	KEENRIG_RUNTIME_CONFIG=<dsn>         ngữ nghĩa do DRIVER quy định
//
// Hai biến chứ không phải một họ biến, vì mỗi lần chạy chỉ có ĐÚNG MỘT driver
// hoạt động; một họ KEENRIG_RUNTIME_* sẽ luôn có phần lớn giá trị vô nghĩa với
// driver đang chọn, và người vận hành không có cách nào biết cái nào đang được đọc.
const (
	EnvDriver     = "KEENRIG_RUNTIME"
	EnvConfig     = "KEENRIG_RUNTIME_CONFIG"
	DefaultDriver = "docker"
)

// Tên driver — hằng số để không rải chuỗi khắp nơi (gõ sai tên driver nghĩa là
// im lặng rơi về mặc định, một lỗi rất khó thấy).
const (
	DriverDocker = "docker"
	DriverSwarm  = "swarm"
	DriverK8s    = "k8s"
)

var (
	ErrUnknownDriver = errors.New("runtime: no such driver")
	// ErrBadConfig — DSN sai cú pháp. Driver PHẢI kiểm lúc mở, không đợi tới
	// Apply: cấu hình sai thì lỗi phải nổ lúc khởi động, không phải lúc người
	// dùng deploy app đầu tiên.
	ErrBadConfig = errors.New("runtime: invalid driver configuration")
	// ErrNotLicensed — driver hợp lệ nhưng bậc license hiện tại không cho dùng.
	ErrNotLicensed = errors.New("runtime: the licence tier does not allow this driver")
)

// Config — thứ mọi driver nhận khi được mở.
type Config struct {
	// Layout quyết định mọi đường dẫn trên đĩa. Driver KHÔNG nhận đường dẫn từ
	// nơi khác — cùng lý do với proxy.Config.
	Layout paths.Layout
	// DSN là nội dung KEENRIG_RUNTIME_CONFIG, truyền nguyên văn. Core không
	// phân tích chuỗi này; mỗi driver tự định nghĩa cú pháp và tự kiểm.
	DSN string
	// Namespace/tiền tố tài nguyên. Rỗng → driver tự chọn mặc định.
	Namespace string
}

// DSNOr trả DSN đã cắt khoảng trắng, hoặc def khi không đặt.
func (c Config) DSNOr(def string) string {
	if s := strings.TrimSpace(c.DSN); s != "" {
		return s
	}
	return def
}

// Factory dựng một Runtime. Nhận ctx vì driver phải bắt tay với nền tảng ngay
// lúc mở (docker ping, swarm kiểm node có phải manager không, k8s gọi /version)
// — chính chỗ đó quyết định lỗi cấu hình có nổ sớm hay không.
type Factory func(ctx context.Context, cfg Config) (Runtime, error)

var (
	mu       sync.RWMutex
	registry = map[string]Factory{}
)

// Register gắn driver vào registry; gọi từ init() của package driver.
//
// Panic khi trùng tên hoặc tên rỗng: đây là lỗi lúc dựng chương trình, phải nổ
// ngay khi khởi động chứ không được biến thành lỗi runtime lúc 2 giờ sáng.
func Register(name string, f Factory) {
	if name == "" {
		panic("runtime: Register called with an empty name")
	}
	if f == nil {
		panic("runtime: Register(" + name + ") with a nil factory")
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[name]; dup {
		panic("runtime: Register called twice for name " + name)
	}
	registry[name] = f
}

// Registered trả tên mọi driver đã biên dịch vào binary, đã sắp xếp.
func Registered() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// LicenseGate quyết định một driver có được dùng ở bậc license hiện tại không.
//
// Đây là SEAM, chưa phải cơ chế: `internal/license` thuộc M5. Mặc định
// AllowAll — nghĩa là swarm/k8s hiện chạy được mà không cần license, đúng như
// quyết định recorded nhận khi kéo hai driver này lên M1. Khi M5 tới, chỉ việc
// cắm một Gate đọc `features.runtime` từ license đã verify; KHÔNG phải sửa chỗ
// gọi nào.
type LicenseGate func(driver string) error

// AllowAll — gate mặc định.
func AllowAll(string) error { return nil }

// RequireFeature dựng gate từ giá trị features.runtime của license.
//
// docker luôn được phép (bậc miễn phí); swarm/k8s chỉ khi license khai đúng tên
// đó. Không có "cao hơn thì bao hàm thấp hơn" ngoài docker: license swarm KHÔNG
// mở k8s, vì đó là hai bậc giá khác nhau.
func RequireFeature(feature string) LicenseGate {
	return func(driver string) error {
		if driver == DriverDocker || driver == feature {
			return nil
		}
		return fmt.Errorf("%w: licence covers %q, %q was requested", ErrNotLicensed, feature, driver)
	}
}

// Open dựng driver theo tên. name rỗng → DefaultDriver. gate nil → AllowAll.
func Open(ctx context.Context, name string, cfg Config, gate LicenseGate) (Runtime, error) {
	if name == "" {
		name = DefaultDriver
	}
	if gate == nil {
		gate = AllowAll
	}
	mu.RLock()
	f, ok := registry[name]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %q (available: %s)", ErrUnknownDriver, name, strings.Join(Registered(), ", "))
	}
	// Kiểm license TRƯỚC khi mở: mở rồi mới từ chối nghĩa là đã kết nối tới
	// cluster của khách, và với k8s thì đó là một lời gọi mạng có thể treo lâu.
	if err := gate(name); err != nil {
		return nil, err
	}
	return f(ctx, cfg)
}

// DriverFromEnv đọc tên driver. lookup thường là os.LookupEnv; nhận tham số để
// test không phải đụng môi trường tiến trình.
func DriverFromEnv(lookup func(string) (string, bool)) string {
	if v := env(lookup, EnvDriver); v != "" {
		return v
	}
	return DefaultDriver
}

// ConfigFromEnv dựng Config từ layout + KEENRIG_RUNTIME_CONFIG.
func ConfigFromEnv(layout paths.Layout, lookup func(string) (string, bool)) Config {
	return Config{Layout: layout, DSN: env(lookup, EnvConfig)}
}

// OpenFromEnv là đường tắt cho main.
func OpenFromEnv(ctx context.Context, layout paths.Layout, lookup func(string) (string, bool), gate LicenseGate) (Runtime, error) {
	return Open(ctx, DriverFromEnv(lookup), ConfigFromEnv(layout, lookup), gate)
}

func env(lookup func(string) (string, bool), key string) string {
	if lookup == nil {
		return ""
	}
	v, ok := lookup(key)
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}
