package runtime_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/reconciler"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/runtime"
	_ "github.com/keenrig-platform/keenrig/keenrig-node/internal/runtime/driver/all"
)

// Cả ba driver phải có mặt trong binary — nếu không, `KEENRIG_RUNTIME=k8s` sẽ
// lỗi "driver không tồn tại" trên máy khách và không ai hiểu vì sao.
func TestAllDriversRegistered(t *testing.T) {
	got := runtime.Registered()
	want := map[string]bool{
		runtime.DriverDocker: false,
		runtime.DriverSwarm:  false,
		runtime.DriverK8s:    false,
	}
	for _, n := range got {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for n, found := range want {
		if !found {
			t.Errorf("driver %q chưa đăng ký (có: %v)", n, got)
		}
	}
}

func TestDriverFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	cases := map[string]string{
		"":       runtime.DefaultDriver,
		"  ":     runtime.DefaultDriver, // đặt nhưng rỗng ~ lỗi script, không phải ý định
		"swarm":  runtime.DriverSwarm,
		" k8s  ": runtime.DriverK8s,
	}
	for in, want := range cases {
		m := map[string]string{}
		if in != "" {
			m[runtime.EnvDriver] = in
		}
		if got := runtime.DriverFromEnv(env(m)); got != want {
			t.Errorf("DriverFromEnv(%q) = %q, muốn %q", in, got, want)
		}
	}
	if got := runtime.DriverFromEnv(nil); got != runtime.DefaultDriver {
		t.Errorf("lookup nil = %q", got)
	}
}

// Tên driver sai phải LIỆT KÊ tên hợp lệ — lỗi này gần như luôn là gõ nhầm env.
func TestUnknownDriverListsValidNames(t *testing.T) {
	_, err := runtime.Open(context.Background(), "kubernets", runtime.Config{}, nil)
	if !errors.Is(err, runtime.ErrUnknownDriver) {
		t.Fatalf("err = %v, muốn ErrUnknownDriver", err)
	}
	for _, n := range []string{"docker", "swarm", "k8s"} {
		if !strings.Contains(err.Error(), n) {
			t.Errorf("thông báo lỗi không liệt kê %q: %v", n, err)
		}
	}
}

// Gate license chặn TRƯỚC khi mở driver: mở rồi mới từ chối nghĩa là đã kết
// nối tới cluster của khách, và với k8s đó là một lời gọi mạng có thể treo lâu.
func TestLicenseGateBlocksBeforeOpen(t *testing.T) {
	gate := runtime.RequireFeature(runtime.DriverDocker)

	// docker luôn được phép (bậc miễn phí).
	if err := gate(runtime.DriverDocker); err != nil {
		t.Errorf("gate chặn docker: %v", err)
	}
	for _, paid := range []string{runtime.DriverSwarm, runtime.DriverK8s} {
		if err := gate(paid); !errors.Is(err, runtime.ErrNotLicensed) {
			t.Errorf("gate cho qua %q với license docker: %v", paid, err)
		}
	}

	// License swarm KHÔNG mở k8s — hai bậc giá khác nhau.
	swarmGate := runtime.RequireFeature(runtime.DriverSwarm)
	if err := swarmGate(runtime.DriverSwarm); err != nil {
		t.Errorf("license swarm chặn swarm: %v", err)
	}
	if err := swarmGate(runtime.DriverK8s); !errors.Is(err, runtime.ErrNotLicensed) {
		t.Error("license swarm lại mở được k8s")
	}

	// Open phải trả ErrNotLicensed mà KHÔNG chạm tới nền tảng: driver k8s không
	// có cluster ở đây, nên nếu nó được mở thật thì lỗi sẽ là lỗi kết nối.
	_, err := runtime.Open(context.Background(), runtime.DriverK8s, runtime.Config{}, gate)
	if !errors.Is(err, runtime.ErrNotLicensed) {
		t.Errorf("Open = %v, muốn ErrNotLicensed (chặn trước khi kết nối)", err)
	}
}

// AllowAll là mặc định hiện tại (swarm/k8s kéo lên M1 trước khi có license M5).
// Test này CỐ Ý ghi nhận trạng thái đó để khi M5 tới, đổi mặc định sẽ làm test
// đỏ và buộc người sửa phải đọc lại quyết định.
func TestDefaultGateAllowsPaidDrivers(t *testing.T) {
	for _, n := range runtime.Registered() {
		if err := runtime.AllowAll(n); err != nil {
			t.Errorf("AllowAll chặn %q: %v", n, err)
		}
	}
}

// Ngân sách timeout: LeaseTTL của reconciler phải phủ được driver CHẬM NHẤT.
//
// Bất đẳng thức: LeaseTTL > LeaseTTL/3 + maxApply  ⟺  LeaseTTL > 1.5 × maxApply.
// Vỡ nó nghĩa là lease hết hạn giữa lúc Apply đang chạy, box khác giành được,
// và ta có đúng hai chủ cùng lái một cluster — thứ lease sinh ra để chặn.
func TestApplyTimeoutsWithinBudget(t *testing.T) {
	maxDriver := runtime.DockerApplyTimeout
	for _, d := range []time.Duration{runtime.SwarmApplyTimeout, runtime.K8sApplyTimeout} {
		if d > maxDriver {
			maxDriver = d
		}
	}
	if runtime.MaxApplyTimeout != maxDriver {
		t.Errorf("MaxApplyTimeout = %s nhưng driver chậm nhất là %s — hai giá trị phải khớp",
			runtime.MaxApplyTimeout, maxDriver)
	}

	renewEvery := reconciler.DefaultLeaseTTL / 3
	if reconciler.DefaultLeaseTTL <= renewEvery+runtime.MaxApplyTimeout {
		t.Errorf("LeaseTTL %s <= renew %s + maxApply %s — lease sẽ hết hạn giữa lúc Apply chạy",
			reconciler.DefaultLeaseTTL, renewEvery, runtime.MaxApplyTimeout)
	}
}
