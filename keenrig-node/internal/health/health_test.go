package health_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/health"
)

// srv dựng một app giả trả status theo biến điều khiển.
func srv(t *testing.T, status *int) health.Endpoint {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(*status)
	}))
	t.Cleanup(s.Close)
	return endpointOf(t, s.URL)
}

func endpointOf(t *testing.T, rawURL string) health.Endpoint {
	t.Helper()
	hostport := strings.TrimPrefix(rawURL, "http://")
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return health.Endpoint{Host: host, Port: port}
}

// deadEndpoint — cổng không ai nghe.
func deadEndpoint(t *testing.T) health.Endpoint {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ep := endpointOf(t, "http://"+ln.Addr().String())
	ln.Close() // đóng ngay → cổng chết
	return ep
}

// Quy tắc 3: chỉ 5xx là hỏng. 2xx/3xx/4xx đều tính là app đang sống.
func TestOnly5xxIsUnhealthy(t *testing.T) {
	cases := map[int]string{
		200: contracts.HealthHealthy,
		204: contracts.HealthHealthy,
		301: contracts.HealthHealthy,
		401: contracts.HealthHealthy, // app có xác thực vẫn là app đang chạy
		404: contracts.HealthHealthy,
		429: contracts.HealthHealthy,
		500: contracts.HealthUnhealthy,
		502: contracts.HealthUnhealthy,
		503: contracts.HealthUnhealthy,
	}
	for status, want := range cases {
		code := status
		ep := srv(t, &code)
		m := health.New(health.Options{UnhealthyAfter: 0, Timeout: 2 * time.Second})
		res := m.Check(context.Background(), health.Target{AppID: "a" + strconv.Itoa(status), Endpoints: []health.Endpoint{ep}})
		if res.Raw != want {
			t.Errorf("HTTP %d → raw %q, muốn %q", status, res.Raw, want)
		}
	}
}

// Quy tắc 1a: khoẻ lại được ghi nhận NGAY (UI phải hiện "đang chạy" tức thì).
func TestHealthyIsImmediate(t *testing.T) {
	code := 500
	ep := srv(t, &code)
	clock := time.Now()
	m := health.New(health.Options{
		UnhealthyAfter: time.Hour,
		Now:            func() time.Time { return clock },
	})
	ctx := context.Background()
	tgt := health.Target{AppID: "app-1", Endpoints: []health.Endpoint{ep}}

	// Hỏng nhưng chưa đủ ngưỡng → chưa kết luận unhealthy.
	if res := m.Check(ctx, tgt); res.Health == contracts.HealthUnhealthy {
		t.Fatalf("kết luận unhealthy ngay lần đầu: %+v", res)
	}
	// Đủ ngưỡng → unhealthy.
	clock = clock.Add(2 * time.Hour)
	if res := m.Check(ctx, tgt); res.Health != contracts.HealthUnhealthy {
		t.Fatalf("sau ngưỡng vẫn chưa unhealthy: %+v", res)
	}
	// Khoẻ lại → NGAY, không chờ ngưỡng nào.
	code = 200
	if res := m.Check(ctx, tgt); res.Health != contracts.HealthHealthy {
		t.Errorf("khoẻ lại không được ghi nhận ngay: %+v", res)
	}
}

// Quy tắc 1b: một lần hỏng thoáng qua KHÔNG được đổi trạng thái. Đây là lý do
// package tồn tại — không có nó, mỗi lần container restart là một cảnh báo.
func TestTransientFailureDoesNotFlip(t *testing.T) {
	code := 200
	ep := srv(t, &code)
	clock := time.Now()
	m := health.New(health.Options{
		UnhealthyAfter: 5 * time.Minute,
		Now:            func() time.Time { return clock },
	})
	ctx := context.Background()
	tgt := health.Target{AppID: "app-1", Endpoints: []health.Endpoint{ep}}

	if res := m.Check(ctx, tgt); res.Health != contracts.HealthHealthy {
		t.Fatalf("khởi đầu = %+v", res)
	}

	// Hỏng 30 giây rồi khoẻ lại: trạng thái công bố phải GIỮ NGUYÊN healthy.
	code = 503
	clock = clock.Add(30 * time.Second)
	res := m.Check(ctx, tgt)
	if res.Health != contracts.HealthHealthy {
		t.Errorf("hỏng thoáng qua đã lật trạng thái: %+v", res)
	}
	if res.Raw != contracts.HealthUnhealthy {
		t.Errorf("Raw phải phản ánh sự thật thô: %+v", res)
	}
	if res.UnhealthySince.IsZero() {
		t.Error("không ghi mốc bắt đầu hỏng — không có nó thì không đếm được ngưỡng")
	}

	code = 200
	clock = clock.Add(10 * time.Second)
	if res := m.Check(ctx, tgt); res.Health != contracts.HealthHealthy || !res.UnhealthySince.IsZero() {
		t.Errorf("khoẻ lại không xoá mốc hỏng: %+v", res)
	}
}

// Quy tắc 2: mốc hỏng bị KẸP về thời điểm khởi động tiến trình.
//
// Không kẹp thì một box tắt qua đêm vừa bật lên đã kết luận mọi app hỏng suốt
// 8 tiếng và bắn cảnh báo hàng loạt — trong khi chưa probe lần nào.
func TestUnhealthySinceClampedToStart(t *testing.T) {
	code := 503
	ep := srv(t, &code)
	start := time.Now()
	clock := start
	m := health.New(health.Options{
		UnhealthyAfter: 10 * time.Minute,
		Now:            func() time.Time { return clock },
	})
	ctx := context.Background()
	tgt := health.Target{AppID: "app-1", Endpoints: []health.Endpoint{ep}}

	// Ngay sau khi khởi động: hỏng nhưng CHƯA đủ ngưỡng.
	clock = start.Add(time.Second)
	res := m.Check(ctx, tgt)
	if res.Health == contracts.HealthUnhealthy {
		t.Fatalf("kết luận unhealthy 1 giây sau khi khởi động: %+v", res)
	}
	if res.UnhealthySince.Before(start) {
		t.Errorf("mốc hỏng %v nằm TRƯỚC mốc khởi động %v — chưa kẹp", res.UnhealthySince, start)
	}
}

// Một phần replica chết: báo unhealthy nhưng vẫn cho biết còn mấy cái sống.
func TestPartialReplicasDegraded(t *testing.T) {
	code := 200
	alive := srv(t, &code)
	dead := deadEndpoint(t)

	m := health.New(health.Options{UnhealthyAfter: 0, Timeout: time.Second})
	res := m.Check(context.Background(), health.Target{
		AppID:     "app-1",
		Endpoints: []health.Endpoint{alive, dead},
	})
	if res.Ready != 1 || res.Total != 2 {
		t.Fatalf("Ready/Total = %d/%d, muốn 1/2", res.Ready, res.Total)
	}
	if !res.Degraded() {
		t.Error("Degraded() = false trong khi 1/2 replica chết")
	}
	if !strings.Contains(res.Message, "1/2") {
		t.Errorf("thông báo không nói rõ mấy replica sống: %q", res.Message)
	}
}

// App chưa có endpoint (đang deploy) → unknown, KHÔNG phải unhealthy.
// Kết luận hỏng ở đây sẽ báo động giả cho mọi app vừa được tạo.
func TestNoEndpointsIsUnknown(t *testing.T) {
	m := health.New(health.Options{UnhealthyAfter: 0})
	res := m.Check(context.Background(), health.Target{AppID: "app-1"})
	if res.Raw != contracts.HealthUnknown {
		t.Errorf("raw = %q, muốn unknown", res.Raw)
	}
	if res.Health == contracts.HealthUnhealthy {
		t.Errorf("app chưa có endpoint bị kết luận unhealthy: %+v", res)
	}
}

// Endpoint chết (không ai nghe) là hỏng, và thông báo phải đọc được.
func TestDeadEndpoint(t *testing.T) {
	m := health.New(health.Options{UnhealthyAfter: 0, Timeout: time.Second})
	res := m.Check(context.Background(), health.Target{
		AppID: "app-1", Endpoints: []health.Endpoint{deadEndpoint(t)},
	})
	if res.Raw != contracts.HealthUnhealthy {
		t.Errorf("raw = %q", res.Raw)
	}
	if res.Message == "" {
		t.Error("không có thông báo lý do")
	}
}

// Path tuỳ chỉnh phải được dùng, và path thiếu "/" đầu vẫn phải chạy.
func TestCustomPath(t *testing.T) {
	var got string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Path
		w.WriteHeader(200)
	}))
	defer s.Close()

	m := health.New(health.Options{UnhealthyAfter: 0})
	ep := endpointOf(t, s.URL)
	m.Check(context.Background(), health.Target{AppID: "a", Endpoints: []health.Endpoint{ep}, Path: "healthz"})
	if got != "/healthz" {
		t.Errorf("path = %q, muốn /healthz (thiếu dấu / đầu phải được thêm)", got)
	}
}

// Forget xoá trí nhớ — không có nó thì map phình theo số app từng tồn tại.
func TestForget(t *testing.T) {
	code := 503
	ep := srv(t, &code)
	clock := time.Now()
	m := health.New(health.Options{UnhealthyAfter: time.Minute, Now: func() time.Time { return clock }})
	ctx := context.Background()
	tgt := health.Target{AppID: "app-1", Endpoints: []health.Endpoint{ep}}

	m.Check(ctx, tgt)
	clock = clock.Add(2 * time.Minute)
	if res := m.Check(ctx, tgt); res.Health != contracts.HealthUnhealthy {
		t.Fatalf("chưa unhealthy: %+v", res)
	}

	m.Forget("app-1")
	// Sau khi quên, đồng hồ đếm bắt đầu lại → chưa kết luận unhealthy ngay.
	if res := m.Check(ctx, tgt); res.Health == contracts.HealthUnhealthy {
		t.Errorf("Forget không xoá trí nhớ: %+v", res)
	}
}
