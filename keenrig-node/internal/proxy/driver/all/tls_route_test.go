package all_test

// Admission không được NGHIÊM HƠN THỰC TẾ.
//
// # Lỗi thật mà test này canh
//
// `apps.checkGatewaySupports` từng đặt cứng `TLSACMEByGateway`, nên
// `Site.Requires()` đòi `CapACME` và MỌI app có domain đều bị từ chối trên nginx —
// trong khi reconciler xử lý nginx bình thường bằng đường `TLSProvided` (platform
// xin cert rồi cấp xuống). Không có gì hỏng, chỉ là không tạo được app, và thông
// báo nói về "năng lực acme" — thứ người dùng không hề yêu cầu.
//
// Đây là package duy nhất thấy được MỌI driver đã đăng ký, nên khẳng định "với
// mọi gateway, đường TLS ta chọn là đường gateway đó đỡ được" chỉ phát biểu được
// ở đây. Thêm driver thứ tư mà nó không lo được cert bằng cách nào cả → đỏ tại
// đây, không phải ở máy người dùng.

import (
	"context"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/proxy"
	_ "github.com/keenrig/keenrig/keenrig-node/internal/proxy/driver/all"
)

func TestTLSRouteWorksForEveryDriver(t *testing.T) {
	ctx := context.Background()
	names := proxy.Registered()
	if len(names) == 0 {
		t.Fatal("không driver nào đăng ký — test này vô nghĩa")
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			// controllerFor chứ không proxy.Open: driver chưa phục vụ được thì
			// từ chối mở, nhưng NĂNG LỰC của nó vẫn phải đúng — ngày Apply có
			// thật, đường TLS ta chọn hôm nay phải vẫn là đường nó đỡ được.
			caps := capsOf(t, name)
			_ = ctx

			mode := proxy.TLSModeFor(caps)
			if mode == proxy.TLSOff {
				t.Fatalf("TLSModeFor trả %q — không gateway nào được phục vụ HTTP trần", mode)
			}

			site := proxy.Site{FQDN: "a.tld", AppID: "app-1", TLS: proxy.TLS{Mode: mode}}
			if bad := proxy.Check([]proxy.Site{site}, caps); len(bad) != 0 {
				t.Errorf("đường TLS ta chọn (%q) lại bị chính gateway từ chối: %v\n"+
					"→ admission nghiêm hơn thực tế: app có domain sẽ không tạo được trên %s",
					mode, bad, name)
			}
		})
	}
}

// Và luật chọn đường TLS phải là MỘT luật, không phải hai bản sao.
//
// `reconciler.gatewayHasACME` quyết định "gateway tự lo cert hay ta lo"; nếu nó
// và `TLSModeFor` lệch nhau thì admission nhận một đường mà vòng hội tụ đi đường
// khác — và cert được xin (hoặc không được xin) trái với thứ đã được kiểm.
func TestTLSModeForFollowsACMECapability(t *testing.T) {
	cases := []struct {
		name string
		caps proxy.Caps
		want proxy.TLSMode
	}{
		{"có acme", proxy.Caps{proxy.CapACME: true}, proxy.TLSACMEByGateway},
		{"không acme", proxy.Caps{proxy.CapCertUpload: true}, proxy.TLSProvided},
		// nil = CHƯA BIẾT năng lực. Trả giá trị lạc quan; ở tầng admission thì
		// caps nil đã có nghĩa là bỏ qua kiểm, nên giá trị này không dùng để
		// từ chối ai.
		{"chưa biết", nil, proxy.TLSACMEByGateway},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := proxy.TLSModeFor(c.caps); got != c.want {
				t.Errorf("= %q, muốn %q", got, c.want)
			}
		})
	}
}
