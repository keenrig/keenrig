package proxy

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/paths"
)

// Chọn gateway bằng ĐÚNG HAI biến môi trường (quy tắc scale-ready #2 — 12-factor):
//
//	KEENRIG_PROXY=caddy|nginx|nginx-owasp     mặc định caddy
//	KEENRIG_PROXY_CONFIG=<dsn>                ngữ nghĩa do DRIVER quy định
//
// Hai biến, không phải một họ biến, vì mỗi lần chạy chỉ có ĐÚNG MỘT driver
// hoạt động — một họ KEENRIG_PROXY_* sẽ luôn có phần lớn giá trị vô nghĩa với
// driver đang chọn, và người vận hành không có cách nào biết cái nào đang được
// đọc. Đây chính là mô hình database/sql: Open(driverName, dataSourceName).
//
// Cái KHÔNG đi qua env: bố cục thư mục. sites dir và cert dir luôn lấy từ
// paths.Layout. Chúng là HỢP ĐỒNG (docs/FILESYSTEM.md), không phải nút vặn —
// cho env ghi đè là tạo ra hai nguồn sự thật cho vị trí file, đúng thứ mà
// package paths sinh ra để dẹp.
const (
	EnvDriver     = "KEENRIG_PROXY"
	EnvConfig     = "KEENRIG_PROXY_CONFIG"
	DefaultDriver = "caddy"
)

var (
	// ErrUnknownDriver — tên driver không có trong registry. Kèm danh sách tên
	// hợp lệ vì lỗi này gần như luôn là gõ sai biến môi trường.
	ErrUnknownDriver = errors.New("proxy: no such driver")
	// ErrBadConfig — DSN sai cú pháp với driver đang chọn. Driver PHẢI kiểm
	// lúc mở, không đợi tới Apply: sai cấu hình gateway thì lỗi phải nổ lúc
	// khởi động, không phải lúc người dùng deploy app đầu tiên.
	ErrBadConfig = errors.New("proxy: invalid driver configuration")
	// ErrNotImplemented — driver đã đăng ký và khai báo được Capabilities
	// nhưng chưa hiện thực Apply/Status. Trả lỗi rõ ràng thay vì im lặng
	// không làm gì: một gateway "thành công" mà không định tuyến gì cả là
	// kiểu hỏng khó phát hiện nhất.
	ErrNotImplemented = errors.New("proxy: driver not implemented")
)

// Config — thứ mọi driver nhận khi được mở.
type Config struct {
	// Layout quyết định mọi đường dẫn trên đĩa. Driver KHÔNG được nhận đường
	// dẫn từ nơi khác.
	Layout paths.Layout

	// DSN là nội dung KEENRIG_PROXY_CONFIG, truyền nguyên văn. Core không phân
	// tích chuỗi này — mỗi driver tự định nghĩa cú pháp và tự kiểm, nên thêm
	// driver thứ tư với cú pháp riêng không phải sửa gì ở đây.
	//
	// Giá phải trả, nói thẳng: gõ sai DSN thì core không bắt được, driver phải
	// tự trả ErrBadConfig kèm ví dụ đúng. Đổi lại là không có họ biến env mọc
	// vô hạn theo số driver.
	DSN string

	// Admin — nơi Admin UI của keenrig-box đang nghe (PX-03).
	//
	// Ở Config chứ KHÔNG ở DSN vì đây không phải cú pháp riêng của driver: mọi
	// gateway đều cần trả lời cùng một câu hỏi "request không khớp domain nào
	// thì đi đâu", và câu trả lời luôn là Admin UI. Cùng lý lẽ với Layout —
	// nó là HỢP ĐỒNG giữa box và gateway, không phải nút vặn.
	//
	// Zero value = chưa cấu hình → driver phải trả 404 cho catch-all. KHÔNG
	// được đoán một cổng mặc định: đoán sai thì catch-all proxy vào một cổng
	// lạ trên máy, và đó là một lỗ chuyển tiếp yêu cầu chứ không phải một
	// tính năng.
	Admin Upstream

	// SelfIPs — địa chỉ IP của CHÍNH máy này, để gateway cấp chứng chỉ tự ký
	// cho truy cập bằng IP (PX-03).
	//
	// Ở Config chứ không ở DSN, cùng lý lẽ với Admin: mọi gateway đều cần trả
	// lời "ai gõ thẳng IP thì nhận cert nào", và câu hỏi đó không phải cú pháp
	// riêng của driver.
	//
	// RỖNG nghĩa là CHƯA BIẾT, không phải "không có IP nào" — driver phải để
	// nguyên cấu hình TLS thay vì xoá. Không đọc được danh sách interface là
	// một sự cố tạm thời; xoá cert vì nó là biến sự cố tạm thành mất HTTPS.
	SelfIPs []string
}

// DSNOr trả DSN đã cắt khoảng trắng, hoặc def khi không đặt.
func (c Config) DSNOr(def string) string {
	if s := strings.TrimSpace(c.DSN); s != "" {
		return s
	}
	return def
}

// Factory dựng một Controller. Nhận ctx vì driver có thể phải bắt tay với
// gateway ngay lúc mở (caddy ping admin API, nginx kiểm nhị phân đã nạp module
// ModSecurity chưa) — chính chỗ đó quyết định Capabilities trả về gì.
type Factory func(ctx context.Context, cfg Config) (Controller, error)

var (
	mu       sync.RWMutex
	registry = map[string]Factory{}
	// unavailable — driver ĐÃ đăng ký tên nhưng chưa phục vụ được, kèm lý do.
	unavailable = map[string]string{}
)

// RegisterUnavailable đăng ký một driver CÓ TÊN nhưng CHƯA phục vụ được.
//
// # Vì sao là một khái niệm riêng, không phải một factory trả lỗi
//
// Vì có hai câu hỏi khác nhau, hỏi ở hai thời điểm khác nhau:
//
//	"mở nó ra được không?"        → Open, cần nói chuyện với gateway
//	"chọn nó có vô nghĩa không?"  → biết được NGAY, không cần nói chuyện với ai
//
// Câu thứ hai phải trả lời được TRƯỚC khi dựng supervisor. Lỗi "driver chưa
// hiện thực" là VĨNH VIỄN trong binary này — không lần thử lại nào làm nó khác
// đi — nên để supervisor retry với nó chỉ tạo ra một vòng lặp log. Đối lập với
// "gateway chưa lên", vốn là tạm thời và ĐÁNG retry. Cùng sự phân biệt mà
// `ErrInfraNotReady` đã dựng ở tầng addon: chưa-xong ≠ hỏng.
//
// # Vì sao vẫn giữ TÊN trong registry
//
// Bỏ hẳn thì `KEENRIG_PROXY=nginx` trả ErrUnknownDriver — cùng lỗi với gõ sai
// tên. Hai chuyện đó dẫn tới hai hành động khác nhau: sửa chính tả, hay đổi
// driver và chờ. Giữ tên để nói được câu thứ hai.
func RegisterUnavailable(name, reason string) {
	if strings.TrimSpace(reason) == "" {
		panic("proxy: RegisterUnavailable(" + name + ") without a reason")
	}
	Register(name, func(context.Context, Config) (Controller, error) {
		// Không bao giờ tới đây: Open chặn trước. Giữ để registry vẫn là một
		// map duy nhất, và để một lời gọi trực tiếp factory cũng không lọt.
		return nil, unavailableErr(name)
	})
	mu.Lock()
	defer mu.Unlock()
	unavailable[name] = reason
}

// Available trả nil nếu driver tên name phục vụ được, ngược lại là lý do.
//
// KHÔNG nói chuyện với gateway — nó chỉ trả lời "chọn cái này có vô nghĩa
// không". main gọi nó trước khi dựng supervisor.
func Available(name string) error {
	if name == "" {
		name = DefaultDriver
	}
	mu.RLock()
	_, known := registry[name]
	reason := unavailable[name]
	mu.RUnlock()
	if !known {
		return fmt.Errorf("%w: %q (available: %s)", ErrUnknownDriver, name, strings.Join(Registered(), ", "))
	}
	if reason != "" {
		return unavailableErr(name)
	}
	return nil
}

func unavailableErr(name string) error {
	mu.RLock()
	reason := unavailable[name]
	mu.RUnlock()
	return fmt.Errorf("%w: %s %s — set %s=%s until it is finished",
		ErrNotImplemented, name, reason, EnvDriver, DefaultDriver)
}

// Register gắn một driver vào registry. Gọi từ init() của package driver.
//
// Panic khi trùng tên hoặc tên rỗng: đây là lỗi lập trình lúc dựng chương
// trình, phải nổ ngay khi khởi động chứ không được biến thành lỗi runtime mà
// người vận hành gặp lúc 2 giờ sáng.
func Register(name string, f Factory) {
	if name == "" {
		panic("proxy: Register called with an empty name")
	}
	if f == nil {
		panic("proxy: Register(" + name + ") with a nil factory")
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[name]; dup {
		panic("proxy: Register called twice for name " + name)
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

// Open dựng driver theo tên. name rỗng → DefaultDriver.
func Open(ctx context.Context, name string, cfg Config) (Controller, error) {
	if name == "" {
		name = DefaultDriver
	}
	// Chặn TRƯỚC khi gọi factory: driver chưa phục vụ được thì không có lý do
	// nào để nói chuyện với gateway, và câu trả lời không phụ thuộc môi trường.
	if err := Available(name); err != nil {
		return nil, err
	}
	mu.RLock()
	f := registry[name]
	mu.RUnlock()
	return f(ctx, cfg)
}

// env đọc một biến qua lookup, trả "" khi lookup nil hoặc biến không đặt.
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

// DriverFromEnv đọc tên driver. lookup thường là os.LookupEnv; nhận tham số
// để test không phải đụng môi trường tiến trình. Đặt nhưng để rỗng cũng coi
// như không đặt — env rỗng gần như luôn là lỗi script, không phải ý định.
func DriverFromEnv(lookup func(string) (string, bool)) string {
	if v := env(lookup, EnvDriver); v != "" {
		return v
	}
	return DefaultDriver
}

// ConfigFromEnv dựng Config từ layout + KEENRIG_PROXY_CONFIG.
//
// admin KHÔNG đọc từ env: nó phải là ĐÚNG địa chỉ box đang nghe, và box biết
// điều đó từ cờ --http của chính mình. Cho env đặt riêng là tạo ra cơ hội để
// hai giá trị lệch nhau — và lúc lệch thì catch-all chuyển tiếp vào một cổng
// không phải Admin UI, tức là biến một tính năng thành một lỗ.
func ConfigFromEnv(layout paths.Layout, admin Upstream, selfIPs []string, lookup func(string) (string, bool)) Config {
	return Config{Layout: layout, DSN: env(lookup, EnvConfig), Admin: admin, SelfIPs: selfIPs}
}

// OpenFromEnv là đường tắt cho main: đọc cả hai biến rồi mở driver.
//
//	ctl, err := proxy.OpenFromEnv(ctx, layout, admin, selfIPs, os.LookupEnv)
func OpenFromEnv(ctx context.Context, layout paths.Layout, admin Upstream, selfIPs []string, lookup func(string) (string, bool)) (Controller, error) {
	return Open(ctx, DriverFromEnv(lookup), ConfigFromEnv(layout, admin, selfIPs, lookup))
}
