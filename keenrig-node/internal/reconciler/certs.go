package reconciler

import (
	"context"
	"log"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/certs"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/proxy"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// T9 — hai đường TLS, chọn theo NĂNG LỰC gateway (PX-02).
//
// Đây là chỗ nguyên tắc 3 của seam proxy ("năng lực phải khai báo") sinh ra
// giá trị thật: cùng một tập domain, cùng một vòng lặp, nhưng caddy thì ta
// không làm gì cả còn nginx thì ta phải chạy trọn một quy trình ACME. Không có
// Capabilities(), chỗ này sẽ phải hỏi "driver tên là gì" — và thêm driver thứ
// tư là phải sửa lại vòng lặp.

// WithCerts gắn manager cấp chứng chỉ. Không gắn thì gateway PHẢI có CapACME,
// nếu không sẽ không site nào lên được (và có log nói rõ vì sao).
func (r *Reconciler) WithCerts(m *certs.Manager) *Reconciler {
	r.certs = m
	return r
}

// capsTTL — hỏi lại năng lực gateway sau ngần này.
//
// Không hỏi mỗi tick: Capabilities có thể là một lời gọi mạng tới gateway.
// Cũng không cache vĩnh viễn: gateway được nâng cấp (nginx thêm module, caddy
// build lại kèm plugin) mà không ai restart box, và ta muốn nhận ra điều đó
// trong vài phút chứ không phải sau lần restart kế tiếp.
const capsTTL = 5 * time.Minute

// gatewayHasACME — gateway tự lo được chứng chỉ hay không.
//
// Hỏi lỗi thì trả TRUE (giả định gateway tự lo). Chọn hướng này có chủ đích:
// đoán sai theo hướng "gateway tự lo" khiến ta không xin cert — site vẫn lên
// gateway và caddy vẫn tự xử lý; đoán sai theo hướng ngược lại sẽ chạy cả một
// quy trình ACME thừa và, tệ hơn, chặn mọi site cho tới khi cert có.
func (r *Reconciler) gatewayHasACME(ctx context.Context) bool {
	if r.proxy == nil {
		return true
	}
	now := time.Now()
	if r.caps != nil && now.Before(r.capsAt.Add(capsTTL)) {
		return r.caps.Has(proxy.CapACME)
	}
	caps, err := r.proxy.Capabilities(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("reconciler: querying gateway capabilities failed (%v) — assuming the gateway handles certificates itself", err)
		}
		return true
	}
	r.caps, r.capsAt = caps, now
	return caps.Has(proxy.CapACME)
}

// ensureCerts xin/gia hạn cert cho mọi domain, trả map fqdn → cert_ref cho
// những cái ĐÃ sẵn sàng.
//
// Domain hỏng không kéo domain khác: với nginx, một file cert thiếu làm `nginx -t`
// từ chối CẢ tập cấu hình, tức là một domain sai DNS sẽ đánh sập toàn bộ site
// trên máy. Vì vậy site chưa có cert bị loại khỏi desired chứ không đẩy kèm.
func (r *Reconciler) ensureCerts(ctx context.Context, doms []*store.Domain) map[string]string {
	if !r.certs.HasIssuer() {
		if len(doms) > 0 {
			r.warnNoIssuer()
		}
		return map[string]string{}
	}
	fqdns := make([]string, 0, len(doms))
	for _, d := range doms {
		fqdns = append(fqdns, d.FQDN)
	}
	refs, err := r.certs.Ensure(ctx, fqdns)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("reconciler: issuing certificate: %v", err)
		}
		return map[string]string{}
	}
	if len(refs) < len(fqdns) {
		log.Printf("reconciler: %d/%d domains have certificates — the rest are not on the gateway yet",
			len(refs), len(fqdns))
	}
	return refs
}

// warnNoIssuer log tối đa mỗi capsTTL: đây là cấu hình sai kéo dài, không phải
// sự cố thoáng qua, nên nhắc đều đặn nhưng đừng làm ngập log.
func (r *Reconciler) warnNoIssuer() {
	now := time.Now()
	if now.Before(r.noIssuerWarnAt.Add(capsTTL)) {
		return
	}
	r.noIssuerWarnAt = now
	log.Printf("reconciler: gateway lacks capability %q and no issuer is configured — "+
		"no site will be pushed to the gateway. Set KEENRIG_ACME_* or use the caddy gateway.",
		proxy.CapACME)
}
