package metrics_test

import (
	"strings"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/metrics"
)

// Ba số liệu BẮT BUỘC của keenrig-box phải có mặt, đúng TÊN và đúng KIỂU.
//
// # Vì sao khoá cả tên
//
// Tên metric là hợp đồng công khai: nó nằm trong dashboard, trong luật alert,
// trong recording rule. Đổi tên là làm mọi thứ đó im lặng ngừng khớp — không
// lỗi, không cảnh báo, chỉ là biểu đồ phẳng và alert không bao giờ bắn. Đây là
// hạt giống của OB-01 ("tên metric ổn định, test snapshot").
//
// # Vì sao ba cái này chứ không phải ba cái khác
//
// Mỗi cái canh một vòng lặp trước đây chạy hoàn toàn trong bóng tối, và cái giá
// của bóng tối đã đo được: driver `nginx` chọn được nhưng không định tuyến gì,
// mỗi 15 giây ghi một event lỗi vào platform.db, không ai thấy trong nhiều
// tháng. `keenrig_proxy_apply_total{result="error"}` tăng đều sẽ tự nói ra ngay
// từ phút đầu.
func TestBaSoLieuBatBuocCoMat(t *testing.T) {
	r := metrics.NewRegistry()
	r.SetReconcilerLeaseAge(42)
	r.SetJobsQueueLag(3.5)
	r.SetProxyApply("caddy", metrics.ProxyApplyOK)
	r.SetProxyApply("caddy", metrics.ProxyApplyError)
	r.SetProxyApply("nginx", metrics.ProxyApplyError)

	out := r.Gather()
	for _, want := range []string{
		"# TYPE keenrig_reconciler_lease_age_seconds gauge",
		"keenrig_reconciler_lease_age_seconds 42",
		"# TYPE keenrig_jobs_queue_lag_seconds gauge",
		"keenrig_jobs_queue_lag_seconds 3.5",
		"# TYPE keenrig_proxy_apply_total counter",
		`keenrig_proxy_apply_total{driver="caddy",result="error"} 1`,
		`keenrig_proxy_apply_total{driver="caddy",result="ok"} 1`,
		`keenrig_proxy_apply_total{driver="nginx",result="error"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("thiếu dòng:\n  %s\ntrong:\n%s", want, out)
		}
	}
}

// Nhãn `driver` phải TÁCH được các driver ra.
//
// Một fleet chạy lẫn caddy và nginx mà gộp tỉ lệ lỗi chung sẽ che mất việc MỘT
// driver hỏng hoàn toàn: 50% lỗi trông như "hơi nhiều lỗi", trong khi thực tế
// là một nửa số máy không định tuyến gì cả.
func TestProxyApplyTachTheoDriver(t *testing.T) {
	r := metrics.NewRegistry()
	for range 3 {
		r.SetProxyApply("nginx", metrics.ProxyApplyError)
	}
	r.SetProxyApply("caddy", metrics.ProxyApplyOK)

	out := r.Gather()
	if !strings.Contains(out, `keenrig_proxy_apply_total{driver="nginx",result="error"} 3`) {
		t.Errorf("không cộng dồn theo driver:\n%s", out)
	}
	if !strings.Contains(out, `keenrig_proxy_apply_total{driver="caddy",result="ok"} 1`) {
		t.Errorf("driver kia bị gộp vào:\n%s", out)
	}
}

// Gauge phải XUỐNG được, không chỉ lên.
//
// Cụ thể: mất lease → tuổi về 0; hàng đợi rỗng → độ trễ về 0. Nếu chúng chỉ
// tăng thì một đỉnh cũ nằm mãi trên biểu đồ và trông như sự cố đang tiếp diễn —
// đúng loại cảnh báo giả mà người ta học cách phớt lờ.
func TestGaugeVeKhongDuoc(t *testing.T) {
	r := metrics.NewRegistry()
	r.SetReconcilerLeaseAge(120)
	r.SetJobsQueueLag(9)
	r.SetReconcilerLeaseAge(0)
	r.SetJobsQueueLag(0)

	out := r.Gather()
	for _, want := range []string{
		"keenrig_reconciler_lease_age_seconds 0",
		"keenrig_jobs_queue_lag_seconds 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("gauge không về 0 được — thiếu %q trong:\n%s", want, out)
		}
	}
}
