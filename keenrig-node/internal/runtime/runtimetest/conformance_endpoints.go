package runtimetest

// Conformance T6c — Observed.Endpoints. Driver nào cũng phải trả địa chỉ mà
// gateway nối tới được, nếu không T8 không có gì để đẩy sang proxy.

import (
	"net"
	"strconv"
	"testing"
	"time"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/runtime"
)

// RunEndpointConformance — gọi từ RunConformance; tách file cho dễ đọc.
func RunEndpointConformance(t *testing.T, h Harness) {
	t.Run("EndpointsAfterApply", func(t *testing.T) { testEndpointsAfterApply(t, h) })
	t.Run("EndpointsPerReplica", func(t *testing.T) { testEndpointsPerReplica(t, h) })
	t.Run("EndpointsExplicitPort", func(t *testing.T) { testEndpointsExplicitPort(t, h) })
	t.Run("EndpointsGoneAfterRemove", func(t *testing.T) { testEndpointsGoneAfterRemove(t, h) })
}

// assertUsableEndpoint — endpoint phải là host:port THẬT SỰ dùng được, không
// phải chuỗi rỗng hay cổng 0. Kiểm ở tầng conformance vì đây là hợp đồng của
// interface, không phải chi tiết của driver docker.
func assertUsableEndpoint(t *testing.T, ep runtime.Endpoint) {
	t.Helper()
	if ep.Host == "" {
		t.Errorf("endpoint thiếu Host: %+v", ep)
	}
	if net.ParseIP(ep.Host) == nil {
		t.Errorf("Host %q không phải IP — gateway nối bằng IP nội bộ, không phải tên", ep.Host)
	}
	if ep.Port <= 0 || ep.Port > 65535 {
		t.Errorf("Port %d ngoài khoảng hợp lệ", ep.Port)
	}
	if _, _, err := net.SplitHostPort(net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))); err != nil {
		t.Errorf("endpoint %+v không ghép được thành host:port: %v", ep, err)
	}
}

func testEndpointsAfterApply(t *testing.T, h Harness) {
	rt := h.Factory(t)
	ctx := testCtx(t)
	spec := randomSpec(t)
	cleanupApp(t, rt, spec.ID)

	obs, err := rt.Apply(ctx, spec)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(obs.Endpoints) != 1 {
		t.Fatalf("Apply trả %d endpoint, muốn 1: %+v", len(obs.Endpoints), obs.Endpoints)
	}
	assertUsableEndpoint(t, obs.Endpoints[0])

	// Status phải trả CÙNG endpoint với Apply. Hai nguồn lệch nhau nghĩa là
	// gateway sẽ thấy upstream nhảy qua lại giữa hai giá trị theo nhịp refresh.
	st, err := rt.Status(ctx, spec.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(st.Endpoints) != 1 || st.Endpoints[0] != obs.Endpoints[0] {
		t.Errorf("Status trả %+v, Apply trả %+v — phải khớp", st.Endpoints, obs.Endpoints)
	}
}

func testEndpointsPerReplica(t *testing.T, h Harness) {
	rt := h.Factory(t)
	ctx := testCtx(t)
	spec := randomSpec(t)
	spec.Desired.Resources = &contracts.Resources{Replicas: 2}
	cleanupApp(t, rt, spec.ID)

	obs, err := rt.Apply(ctx, spec)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(obs.Endpoints) != 2 {
		t.Fatalf("2 replica → %d endpoint: %+v", len(obs.Endpoints), obs.Endpoints)
	}
	if obs.Endpoints[0] == obs.Endpoints[1] {
		t.Errorf("hai replica cùng endpoint %+v — LB sẽ dồn hết tải vào một container", obs.Endpoints[0])
	}
	for _, ep := range obs.Endpoints {
		assertUsableEndpoint(t, ep)
	}

	// Thu về 1 replica: endpoint thừa phải biến mất, nếu không gateway giữ
	// upstream trỏ vào container đã bị xoá.
	spec.DesiredRev = 2
	spec.Desired.Resources = &contracts.Resources{Replicas: 1}
	obs, err = rt.Apply(ctx, spec)
	if err != nil {
		t.Fatalf("Apply scale-down: %v", err)
	}
	if len(obs.Endpoints) != 1 {
		t.Errorf("sau scale-down còn %d endpoint: %+v", len(obs.Endpoints), obs.Endpoints)
	}
}

// desired.http_port phải THẮNG cổng suy từ EXPOSE của image.
func testEndpointsExplicitPort(t *testing.T, h Harness) {
	rt := h.Factory(t)
	ctx := testCtx(t)
	spec := randomSpec(t)
	spec.Desired.HTTPPort = 9999 // khác hẳn cổng whoami EXPOSE (80)
	cleanupApp(t, rt, spec.ID)

	obs, err := rt.Apply(ctx, spec)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(obs.Endpoints) != 1 || obs.Endpoints[0].Port != 9999 {
		t.Fatalf("endpoint = %+v, muốn cổng 9999 theo desired.http_port", obs.Endpoints)
	}
	// Và Status — vốn KHÔNG nhận AppSpec — vẫn phải ra 9999. Đây chính là lý do
	// cổng được đóng vào container lúc tạo thay vì suy lại mỗi lần đọc.
	st, err := rt.Status(ctx, spec.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(st.Endpoints) != 1 || st.Endpoints[0].Port != 9999 {
		t.Errorf("Status trả %+v, muốn cổng 9999 — cổng phải sống trên container, không suy lại từ image", st.Endpoints)
	}
}

func testEndpointsGoneAfterRemove(t *testing.T, h Harness) {
	rt := h.Factory(t)
	ctx := testCtx(t)
	spec := randomSpec(t)

	if _, err := rt.Apply(ctx, spec); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := rt.Remove(ctx, spec.ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	waitFor(t, 30*time.Second, "endpoint biến mất sau Remove", func() bool {
		st, err := rt.Status(ctx, spec.ID)
		return err == nil && len(st.Endpoints) == 0
	})
}
