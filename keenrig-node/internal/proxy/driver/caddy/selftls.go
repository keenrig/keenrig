package caddy

// PX-03, phần TLS — chứng chỉ TỰ KÝ cho truy cập bằng ĐỊA CHỈ IP.
//
// # Ba mảnh, và thiếu mảnh nào cũng hỏng theo một kiểu khác nhau
//
// Cả ba đo được trên Caddy THẬT (real_test.go), không phải suy luận:
//
//	tls_connection_policies       Thiếu → cổng 443 phục vụ HTTP TRẦN.
//	                              Không phải "handshake lỗi" mà là: `curl
//	                              http://ip:443/` trả về Admin UI bình thường,
//	                              còn `https://` thì hỏng. Trên một máy chưa có
//	                              tên miền nào, đó là toàn bộ bề mặt quản trị
//	                              nằm trên cleartext.
//	certificates.automate         Thiếu → Caddy KHÔNG cấp cert nào cả. Policy
//	                              chỉ nói "cấp bằng cách nào", automate mới nói
//	                              "hãy cấp cho tên này".
//	automation.policies + subjects Thiếu → Caddy thử ACME cho một địa chỉ IP,
//	                              Let's Encrypt từ chối ("Domain name does not
//	                              end with a valid public suffix"), và nó retry
//	                              mãi.
//
// # Vì sao subjects TƯỜNG MINH chứ không phải policy bắt-tất-cả
//
// Một policy KHÔNG có `subjects` khớp MỌI tên. Đặt nó với issuer `internal`
// nghĩa là mọi tên miền thật của người dùng cũng nhận cert tự ký — trình duyệt
// đỏ trên toàn bộ instance. Đó là hỏng nặng hơn nhiều so với việc chưa có
// HTTPS khi gõ IP, và là lý do phần này bị hoãn cho tới khi có Caddy thật để
// kiểm chứng.
//
// Liệt kê IP tường minh thì policy chỉ khớp đúng những địa chỉ đó; mọi tên
// miền rơi xuống policy mặc định của Caddy và đi ACME như cũ. Đã kiểm: trong
// lúc policy này có hiệu lực, một tên miền khác vẫn gọi ACME bình thường.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"sort"

	"github.com/keenrig/keenrig/keenrig-node/internal/proxy"
)

const (
	// selfTLSPolicyID — @id của policy do platform quản lý. Cùng nguyên tắc với
	// route: nhận diện bằng NHÃN, không bằng vị trí trong mảng.
	selfTLSPolicyID = proxy.ManagedKey + "/self-signed-ip"

	tlsPoliciesPath = "/config/apps/tls/automation/policies"
	tlsAutomatePath = "/config/apps/tls/certificates/automate"
)

// ensureSelfSignedTLS cấu hình cert tự ký cho các địa chỉ IP của chính máy.
//
// Gọi mỗi lần Apply, không phải một lần lúc mở: địa chỉ IP đổi (DHCP, gắn thêm
// card, đổi VPC). Cấu hình một lần lúc khởi động nghĩa là sau lần đổi IP đầu
// tiên, người vận hành mất đường vào bằng HTTPS và không có gì nói cho họ biết.
//
// ips rỗng → KHÔNG đụng gì. Không phải "xoá hết": một danh sách rỗng vì không
// đọc được interface là chuyện khác hẳn với "máy này không có IP nào".
func (d *Driver) ensureSelfSignedTLS(ctx context.Context, ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	if err := d.putAutomateList(ctx, ips); err != nil {
		return err
	}
	return d.putSelfTLSPolicy(ctx, ips)
}

// putAutomateList ghi danh sách tên Caddy phải tự cấp cert.
//
// # Cái gì là của ta trong danh sách này
//
// `automate` là một mảng chuỗi TRẦN — không có @id để gắn nhãn. Quy tắc phân
// định: mọi phần tử là ĐỊA CHỈ IP là của ta, mọi phần tử còn lại là của người
// vận hành và ta không đụng.
//
// Quy tắc này đứng vững vì một lý do cụ thể: không CA công khai nào cấp cert
// cho địa chỉ IP qua ACME, nên một người vận hành sẽ không bao giờ tự tay đặt
// IP vào đây. Nếu một ngày điều đó đổi, quy tắc này phải đổi theo — và đó là
// lý do nó được viết ra ở đây thay vì ngầm hiểu.
func (d *Driver) putAutomateList(ctx context.Context, ips []string) error {
	var current []string
	if err := d.admin.getJSON(ctx, tlsAutomatePath, &current); err != nil {
		// Chưa có nhánh nào — bình thường trên một Caddy sạch.
		current = nil
	}

	next := make([]string, 0, len(current)+len(ips))
	for _, name := range current {
		if _, err := netip.ParseAddr(name); err == nil {
			continue // IP cũ của ta; sẽ được thay bằng danh sách hiện tại
		}
		next = append(next, name) // của người vận hành — giữ nguyên
	}
	next = append(next, ips...)
	sort.Strings(next)

	return d.setBranch(ctx, "/config/apps/tls/certificates", map[string]any{"automate": next})
}

// setBranch ghi một nhánh config, dù nhánh đó ĐÃ CÓ hay CHƯA.
//
// Admin API của Caddy dùng hai động từ khác nhau cho hai trường hợp, và chọn
// sai thì hỏng ở đúng lần chạy THỨ HAI:
//
//	PUT    tạo mới; nhánh đã tồn tại → 409 "key already exists"
//	PATCH  thay thế; nhánh chưa tồn tại → lỗi "unknown object"
//
// Apply chạy mỗi vòng reconcile, nên lần đầu cần PUT và mọi lần sau cần PATCH.
// Chỉ dùng PUT là cấu hình đóng băng ở giá trị đầu tiên — IP đổi thì cert
// không bao giờ được cấp lại, và không có gì đỏ để báo.
//
// Thử PATCH trước rồi mới PUT: sau lần chạy đầu tiên thì PATCH luôn là đường
// đúng, nên thứ tự này tiết kiệm một lời gọi thừa ở mọi vòng còn lại.
func (d *Driver) setBranch(ctx context.Context, path string, body any) error {
	if _, err := d.admin.do(ctx, http.MethodPatch, path, body); err == nil {
		return nil
	}
	_, err := d.admin.do(ctx, http.MethodPut, path, body)
	return err
}

// putSelfTLSPolicy chèn policy internal-issuer, giữ nguyên policy của người khác.
//
// Cùng thuật toán với Apply cho routes: đọc, giữ cái không mang @id của ta,
// thêm cái của ta, ghi lại cả mảng.
//
// Policy của ta đặt ĐẦU mảng: Caddy dùng policy KHỚP ĐẦU TIÊN, và policy của
// ta có subjects hẹp nên đặt đầu không cướp gì của ai — nhưng đặt CUỐI thì một
// policy bắt-tất-cả của người vận hành sẽ khớp IP trước và đẩy nó sang ACME.
func (d *Driver) putSelfTLSPolicy(ctx context.Context, ips []string) error {
	var current []json.RawMessage
	if err := d.admin.getJSON(ctx, tlsPoliciesPath, &current); err != nil {
		current = nil
	}

	kept := make([]json.RawMessage, 0, len(current))
	for _, raw := range current {
		var probe struct {
			ID string `json:"@id"`
		}
		if err := json.Unmarshal(raw, &probe); err == nil && probe.ID == selfTLSPolicyID {
			continue // của ta — sinh lại
		}
		kept = append(kept, raw)
	}

	mine, err := json.Marshal(map[string]any{
		"@id":      selfTLSPolicyID,
		"subjects": ips,
		"issuers":  []map[string]any{{"module": "internal"}},
	})
	if err != nil {
		return err
	}

	next := append([]json.RawMessage{json.RawMessage(mine)}, kept...)
	return d.setBranch(ctx, "/config/apps/tls/automation", map[string]any{"policies": next})
}
