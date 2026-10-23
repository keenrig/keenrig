// Package proxy — trừu tượng hoá gateway đứng trước app (Caddy, nginx,
// Nginx Proxy Manager, BunkerWeb, Cloudflare/WAF…).
//
// # Vì sao cần trừu tượng thay vì chọn một cái
//
// Các gateway khác nhau ở BA trục, không phải một:
//
//	Mô hình cấu hình  API (Caddy, NPM, Cloudflare) ↔ file + reload (nginx)
//	Sở hữu chứng chỉ  gateway tự xin ACME (Caddy, NPM, Cloudflare) ↔ platform phải cấp (nginx)
//	Sở hữu trạng thái gateway có DB + UI riêng, người thật sửa được (NPM, Cloudflare)
//	                  ↔ cấu hình hoàn toàn do ta sinh (Caddy, nginx)
//
// Chọn cứng một cái là khoá luôn cả ba trục. Interface này để trục nào cũng
// đổi được bằng driver, giống cách runtime.Runtime tách docker khỏi reconciler.
//
// # Ba nguyên tắc thiết kế
//
//  1. LEVEL-TRIGGERED. Apply nhận TOÀN BỘ tập site mong muốn, không nhận delta.
//     Site vắng mặt trong desired nghĩa là phải xoá. Nhờ vậy drift tự lành và
//     driver không cần nhớ lịch sử. Hệ quả bắt buộc: xem nguyên tắc 2.
//
//  2. DANH TÍNH LÀ NHÃN, KHÔNG PHẢI FQDN. Apply chỉ được đụng site do platform
//     quản lý (mang OwnerKey/ManagedKey). Trên NPM hay Cloudflare còn có site
//     do người thật tạo tay — xoá nhầm chúng là sự cố không hoàn tác được.
//     Đây đúng là bài học đã trả giá ở driver docker với label keenrig.com.id.
//
//  3. NĂNG LỰC PHẢI KHAI BÁO, KHÔNG ĐƯỢC IM LẶNG. Gateway nào cũng thiếu thứ
//     gì đó (NPM không có WAF; nginx không tự xin cert; Cloudflare không nói
//     chuyện được với upstream nội bộ). Driver phải công bố Caps để tầng apps
//     TỪ CHỐI NGAY LÚC TẠO APP, thay vì để người dùng phát hiện tính năng im
//     lặng biến mất sau khi deploy xong.
//
// # Xếp tầng
//
// WAF/CDN thường đứng TRƯỚC proxy nội bộ chứ không thay thế nó. Đó là một
// Controller tổng hợp nhiều lớp: mỗi lớp nhận phần Site nó đỡ được, Caps là
// hợp của các lớp. Chuỗi là driver, không phải khái niệm mới trong interface.
package proxy

import (
	"context"
	"fmt"
	"sort"
)

// Nhãn ghi vào cấu hình gateway để nhận diện thứ do platform quản lý.
// Cách ghi tuỳ driver: Caddy dùng @id trong JSON config, nginx dùng tiền tố
// tên file, NPM dùng trường meta, Cloudflare dùng description của ruleset.
const (
	ManagedKey = "keenrig.managed"
	OwnerKey   = "keenrig.com.id"
)

// Capability — một tính năng gateway CÓ THỂ có. Driver công bố tập mình đỡ được.
type Capability string

const (
	CapACME        Capability = "acme"         // gateway tự xin/gia hạn cert
	CapCertUpload  Capability = "cert_upload"  // nhận cert do platform cấp
	CapWildcardTLS Capability = "wildcard_tls" // cert wildcard
	CapTLSPassthru Capability = "tls_passthru" // chuyển tiếp TLS không giải mã
	CapLoadBalance Capability = "load_balance" // nhiều upstream cho một site
	CapWebSocket   Capability = "websocket"
	CapRateLimit   Capability = "rate_limit"
	CapIPFilter    Capability = "ip_filter"    // allow/deny theo IP
	CapForwardAuth Capability = "forward_auth" // auth_request / forward_auth
	CapWAF         Capability = "waf"
	CapBodyLimit   Capability = "body_limit"
	CapAtomicApply Capability = "atomic_apply" // áp nguyên khối; hỏng thì KHÔNG đổi gì
	CapObserve     Capability = "observe"      // đọc lại được cấu hình đang chạy
)

// Caps — tập năng lực của một driver.
type Caps map[Capability]bool

func (c Caps) Has(x Capability) bool { return c[x] }

// Union — dùng khi xếp tầng: lớp biên đỡ WAF, lớp gốc đỡ upstream nội bộ.
func Union(all ...Caps) Caps {
	out := Caps{}
	for _, c := range all {
		for k, v := range c {
			if v {
				out[k] = true
			}
		}
	}
	return out
}

// TLSMode — AI chịu trách nhiệm về chứng chỉ. Đây là trục khác biệt lớn nhất
// giữa các gateway nên nó là trường tường minh, không phải suy đoán.
type TLSMode string

const (
	TLSOff           TLSMode = "off"
	TLSACMEByGateway TLSMode = "acme_by_gateway" // Caddy, NPM, Cloudflare
	TLSProvided      TLSMode = "provided"        // nginx: platform xin rồi cấp cert
	TLSPassthrough   TLSMode = "passthrough"
)

type TLS struct {
	Mode TLSMode
	// CertRef chỉ có nghĩa khi Mode = TLSProvided: khoá tra cứu cert trong
	// store.Secrets hoặc tên file dưới paths.ProxyCerts().
	CertRef string
}

type Upstream struct {
	Host   string
	Port   int
	Weight int // 0 = đều nhau
}

type RateLimit struct {
	RequestsPerMinute int
	Burst             int
}

type WAF struct {
	Ruleset string // vd "owasp-crs"
	Block   bool   // false = chỉ ghi nhận (detect-only)
}

type ForwardAuth struct {
	URL             string
	CopyHeaders     []string
	AllowedFailures int
}

// Policy — thứ KHÔNG phải định tuyến. Tách khỏi phần route có chủ đích: gộp
// chung sẽ dẫn tới cùng sai lầm với "compose là runtime" — nhét một khái niệm
// vào chỗ nó không thuộc về.
type Policy struct {
	ForceHTTPS  bool
	HSTSMaxAge  int
	BodyLimitMB int
	RateLimit   *RateLimit
	IPAllow     []string
	IPDeny      []string
	ForwardAuth *ForwardAuth
	WAF         *WAF
	SetHeaders  map[string]string
}

// Site — ý định định tuyến cho MỘT tên miền.
type Site struct {
	FQDN      string
	AppID     string // chủ sở hữu; ghi vào OwnerKey
	Upstreams []Upstream
	TLS       TLS
	Policy    Policy
}

// Requires suy ra tập năng lực site này CẦN. Đây là cơ sở để từ chối sớm ở
// tầng apps thay vì để lỗi lộ ra lúc Apply.
func (s Site) Requires() Caps {
	need := Caps{}
	switch s.TLS.Mode {
	case TLSACMEByGateway:
		need[CapACME] = true
	case TLSProvided:
		need[CapCertUpload] = true
	case TLSPassthrough:
		need[CapTLSPassthru] = true
	}
	if len(s.Upstreams) > 1 {
		need[CapLoadBalance] = true
	}
	if s.Policy.RateLimit != nil {
		need[CapRateLimit] = true
	}
	if len(s.Policy.IPAllow) > 0 || len(s.Policy.IPDeny) > 0 {
		need[CapIPFilter] = true
	}
	if s.Policy.ForwardAuth != nil {
		need[CapForwardAuth] = true
	}
	if s.Policy.WAF != nil {
		need[CapWAF] = true
	}
	if s.Policy.BodyLimitMB > 0 {
		need[CapBodyLimit] = true
	}
	return need
}

// Unsupported — một yêu cầu cụ thể mà gateway hiện tại không đỡ được.
type Unsupported struct {
	FQDN string
	Cap  Capability
}

func (u Unsupported) Error() string {
	return fmt.Sprintf("proxy: %s requires capability %q which the gateway lacks", u.FQDN, u.Cap)
}

// Check đối chiếu tập site với năng lực driver. Kết quả sắp xếp ổn định để
// thông báo lỗi không đổi thứ tự giữa các lần chạy.
//
// Gọi Check ở tầng admission (apps.Validate) chứ KHÔNG phải lúc Apply: người
// dùng cần biết "gateway này không có WAF" ngay khi bấm tạo app, không phải
// sau khi container đã chạy và họ tưởng đã được bảo vệ.
func Check(sites []Site, have Caps) []Unsupported {
	var out []Unsupported
	for _, s := range sites {
		for cap, needed := range s.Requires() {
			if needed && !have.Has(cap) {
				out = append(out, Unsupported{FQDN: s.FQDN, Cap: cap})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FQDN != out[j].FQDN {
			return out[i].FQDN < out[j].FQDN
		}
		return out[i].Cap < out[j].Cap
	})
	return out
}

// Report — kết quả một lần Apply.
type Report struct {
	// Applied là FQDN đã đưa về đúng trạng thái mong muốn.
	Applied []string
	// Removed là site do platform quản lý đã bị gỡ vì vắng mặt trong desired.
	Removed []string
	// Ignored là site TỒN TẠI trên gateway nhưng KHÔNG mang nhãn của platform.
	// Driver phải liệt kê chứ không được im lặng bỏ qua: đây là bằng chứng cho
	// người vận hành thấy driver đã cố tình không đụng vào cấu hình của họ.
	Ignored []string
	// Warnings là việc phụ KHÔNG làm được, trong khi Apply vẫn thành công.
	//
	// Có trường này để driver khỏi phải chọn giữa hai điều tệ: nuốt lỗi (người
	// vận hành không bao giờ biết) hoặc trả error (một việc phụ hỏng làm huỷ cả
	// một lần Apply đã đưa định tuyến vào đúng trạng thái).
	Warnings []string
}

// Controller — hợp đồng driver gateway.
//
//   - Apply đưa gateway về đúng tập desired và IDEMPOTENT: gọi lại với cùng
//     tập khi đã hội tụ là no-op. Chỉ được thêm/sửa/xoá site mang nhãn của
//     platform; site lạ phải để nguyên và báo trong Report.Ignored.
//     Apply LEVEL-TRIGGERED: desired rỗng nghĩa là gỡ hết site do platform
//     quản lý — caller luôn phải dựng desired từ store, đừng bao giờ truyền
//     danh sách rỗng vì "chưa kịp tải xong".
//   - Status READ-ONLY, chỉ trả site do platform quản lý. Reconciler dùng nó
//     để phát hiện drift — cần thiết với NPM/Cloudflare vì người thật sửa được
//     qua UI của chúng.
//   - Capabilities có thể phải hỏi gateway (phiên bản khác nhau, module khác
//     nhau) nên trả error và nhận ctx.
type Controller interface {
	Name() string
	Capabilities(ctx context.Context) (Caps, error)
	Apply(ctx context.Context, desired []Site) (Report, error)
	Status(ctx context.Context) ([]Site, error)
}
