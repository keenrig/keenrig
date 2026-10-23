package reconciler

import (
	"context"
	"encoding/json"
	"log"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/health"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/runtime"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// Probe HTTP bổ sung cho health của Docker.
//
// Docker chỉ trả health khi IMAGE khai HEALTHCHECK, mà phần lớn image công khai
// thì không — với chúng, "Running" và "đã treo, không trả lời request nào" nhìn
// giống hệt nhau. Probe lấp đúng khoảng đó.
//
// Chỉ chạy ở nhịp REFRESH, không chạy ở tick hội tụ: probe là lời gọi mạng tới
// từng replica, và làm nó mỗi giây sẽ tự tạo tải lên chính app mình đang theo dõi.

// WithHealth bật probe HTTP. Không gắn thì reconciler giữ nguyên hành vi cũ
// (chỉ đọc health của Docker).
func (r *Reconciler) WithHealth(m *health.Monitor) *Reconciler {
	r.health = m
	return r
}

// applyHealthProbe ghi đè obs.Health bằng kết quả probe (đã giảm rung).
//
// Ghi đè có điều kiện: chỉ khi Docker nói "unknown". Image CÓ khai HEALTHCHECK
// thì tác giả image biết rõ hơn ta thế nào là khoẻ — ta không được lấn.
func (r *Reconciler) applyHealthProbe(ctx context.Context, app *store.App, obs *runtime.Observed) {
	if r.health == nil || obs.Health != contracts.HealthUnknown {
		return
	}
	eps := make([]health.Endpoint, 0, len(obs.Endpoints))
	for _, e := range obs.Endpoints {
		eps = append(eps, health.Endpoint{Host: e.Host, Port: e.Port})
	}

	res := r.health.Check(ctx, health.Target{AppID: app.ID, Endpoints: eps})
	if res.Health == contracts.HealthUnknown {
		return // chưa kết luận được (chưa đủ ngưỡng, hoặc no endpoint yet)
	}
	obs.Health = res.Health
	if res.Health != contracts.HealthHealthy && res.Message != "" && obs.Message == "" {
		obs.Message = res.Message
	}

	// Chuyển trạng thái mới là thứ đáng ghi event; probe chạy mỗi 15 giây và
	// ghi event mỗi lần sẽ nhấn chìm audit log.
	if prev := r.lastHealth[app.ID]; prev != res.Health {
		r.lastHealth[app.ID] = res.Health
		action := "app.healthy"
		if res.Health != contracts.HealthHealthy {
			action = "app.unhealthy"
		}
		data, _ := json.Marshal(map[string]any{
			"ready": res.Ready, "total": res.Total, "message": res.Message,
		})
		if err := r.st.AppendEvent(ctx, action, "health", app.ID, data); err != nil && ctx.Err() == nil {
			log.Printf("reconciler: ghi event %s: %v", action, err)
		}
	}
}

// forgetHealth xoá trí nhớ probe của app đã bị purge — không có nó thì map
// phình theo số app từng tồn tại trên instance.
func (r *Reconciler) forgetHealth(appID string) {
	if r.health != nil {
		r.health.Forget(appID)
	}
	delete(r.lastHealth, appID)
}
