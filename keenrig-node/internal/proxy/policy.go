package proxy

// Phép chuyển từ chính sách trong HỢP ĐỒNG (`desired.policy`) sang chính sách
// trong SEAM (`proxy.Policy`), và phép hỏi "gateway này thiếu năng lực nào".
//
// # Vì sao phép chuyển nằm ở đây, không ở apps hay reconciler
//
// Cả hai đều cần nó, và mỗi bên tự chuyển là hai bản sao lệch nhau được. Lệch
// theo hướng nào cũng tệ nhưng có một hướng tệ hơn hẳn: admission chuyển ĐỦ
// trường trong khi reconciler chuyển THIẾU — lúc đó app được nhận vì gateway có
// năng lực, rồi site lên gateway mà không mang chính sách, và người vận hành
// không có gì để nhìn thấy sự khác biệt. Chính sách an ninh không được phép có
// hai định nghĩa.
//
// # Vì sao hai type gần giống nhau vẫn phải là hai type
//
// `contracts.Policy` là những gì người dùng ĐƯỢC PHÉP nói; `proxy.Policy` là
// những gì driver ĐƯỢC PHÉP làm. Cái thứ hai rộng hơn — nó có `ForceHTTPS`,
// `HSTSMaxAge`, `SetHeaders` mà hợp đồng cố ý không mở ra. Gộp làm một sẽ hoặc
// bắt hợp đồng phải mở những trường không năng lực nào canh, hoặc bắt driver mất
// những trường platform tự quyết. Hai chuyện đó khác nhau, nên hai type.

import (
	"sort"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
)

// PolicyFrom chuyển chính sách trong desired sang chính sách của seam.
//
// nil (app không khai `policy`) vẫn trả về một Policy có nghĩa, không phải zero
// value: `ForceHTTPS` là quyết định của PLATFORM, không phải của người dùng. Nó
// bật cho mọi site và hợp đồng không có trường để tắt — đó là lý do nó được đặt
// ở đây thay vì đọc từ desired.
func PolicyFrom(p *contracts.Policy) Policy {
	out := Policy{ForceHTTPS: true}
	if p == nil {
		return out
	}
	if p.WAF != nil {
		out.WAF = &WAF{Ruleset: p.WAF.Ruleset, Block: p.WAF.Blocking()}
	}
	if p.RateLimit != nil {
		out.RateLimit = &RateLimit{
			RequestsPerMinute: p.RateLimit.RequestsPerMinute,
			Burst:             p.RateLimit.Burst,
		}
	}
	if p.ForwardAuth != nil {
		out.ForwardAuth = &ForwardAuth{
			URL:             p.ForwardAuth.URL,
			CopyHeaders:     append([]string(nil), p.ForwardAuth.CopyHeaders...),
			AllowedFailures: p.ForwardAuth.AllowedFailures,
		}
	}
	// Sao chép slice chứ không dùng chung: desired được giải mã một lần rồi truyền
	// đi nhiều chỗ, và một driver sắp xếp lại tại chỗ sẽ sửa luôn thứ caller đang
	// giữ. Đây đúng là loại lỗi mà không test nào bắt được cho tới khi có driver
	// thứ hai.
	out.IPAllow = append([]string(nil), p.IPAllow...)
	out.IPDeny = append([]string(nil), p.IPDeny...)
	out.BodyLimitMB = p.BodyLimitMB
	return out
}

// TLSModeFor trả đường TLS mà platform SẼ DÙNG với gateway có tập năng lực này.
//
// # Vì sao đây là một hàm, không phải một hằng số ở mỗi chỗ gọi
//
// Đường TLS không phải lựa chọn cấu hình — nó là hệ quả của năng lực gateway.
// caddy có `CapACME` nên nó tự xin cert; nginx không có nên platform phải xin rồi
// cấp xuống (`CapCertUpload`). Cùng một luật đó phải được dùng ở CẢ HAI nơi:
// admission (`apps`) và vòng hội tụ (`reconciler.gatewayHasACME`).
//
// Lỗi đã xảy ra khi không có hàm này: `apps` đặt cứng `TLSACMEByGateway`, nên
// `Site.Requires()` đòi `CapACME`, và MỌI app có domain đều bị từ chối trên
// nginx — trong khi reconciler thì hoàn toàn xử lý được nginx bằng đường
// `TLSProvided`. Admission nghiêm hơn thực tế là một loại lỗi khó thấy: không có
// gì hỏng, chỉ là không tạo được app, và thông báo nói về "năng lực acme" — thứ
// người dùng không hề yêu cầu.
//
// `have` là nil (chưa biết năng lực) → `TLSACMEByGateway`, giá trị lạc quan. Nó
// chỉ dùng cho admission, và ở đó caps nil đã có nghĩa là bỏ qua kiểm.
func TLSModeFor(have Caps) TLSMode {
	if have == nil || have.Has(CapACME) {
		return TLSACMEByGateway
	}
	return TLSProvided
}

// MissingCaps trả năng lực mà chính sách CẦN nhưng gateway KHÔNG có, đã sắp xếp.
//
// Khác `Check` ở một điểm quyết định: nó KHÔNG cần một FQDN. Một app bật WAF
// nhưng chưa gắn domain vẫn phải bị từ chối — nhận nó nghĩa là lưu một ý định
// không bao giờ thực thi được, và người dùng chỉ phát hiện lúc thêm domain, nếu
// lúc đó có ai kiểm.
//
// `have` là nil nghĩa là CHƯA BIẾT năng lực (proxy chưa mở được). Trả rỗng chứ
// không trả "thiếu tất cả": gateway hỏng không được biến thành "không tạo được
// app". Cùng lý lẽ với Options.GatewayCaps ở tầng apps.
func MissingCaps(p Policy, have Caps) []Capability {
	if have == nil {
		return nil
	}
	var out []Capability
	for cap, needed := range (Site{Policy: p}).Requires() {
		if needed && !have.Has(cap) {
			out = append(out, cap)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
