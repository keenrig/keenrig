// Package health — theo dõi sức khoẻ app bằng probe HTTP, có GIẢM RUNG.
//
// # Vì sao không dùng thẳng HEALTHCHECK của Docker
//
// Ta đã đọc health từ Docker (`runtime.Observed.Health`), nhưng nó chỉ có khi
// IMAGE khai HEALTHCHECK — phần lớn image công khai thì không. Với chúng, app
// "Running" và app "đã treo, không trả lời request nào" nhìn giống hệt nhau.
// Probe HTTP là thứ duy nhất phân biệt được.
//
// # Ba quy tắc
//
//  1. CHUYỂN TRẠNG THÁI BẤT ĐỐI XỨNG. Một probe thành công là đủ bằng chứng
//     app đang sống, nên ghi nhận ngay. Một probe thất bại thì chưa đủ — chỉ
//     ghi nhận khi thất bại kéo dài LIÊN TỤC quá UnhealthyAfter. Không có sự bất đối xứng này, một lần timeout thoáng qua
//     sẽ bắn cảnh báo, và người vận hành học cách phớt lờ cảnh báo.
//
//  2. KHÔNG TÍNH THỜI GIAN BOX KHÔNG QUAN SÁT. Mốc "hỏng từ bao giờ" không
//     bao giờ được sớm hơn lúc tiến trình này bắt đầu chạy. Không kẹp thì một box tắt
//     qua đêm sẽ vừa bật lên đã kết luận mọi app hỏng suốt 8 tiếng và bắn cảnh
//     báo hàng loạt — trong khi thật ra chưa probe lần nào.
//
//  3. CHỈ LỖI PHÍA SERVER MỚI LÀ HỎNG. Mã dưới 500 nghĩa là app đã nhận và xử
//     lý request: một app trả 401 ở "/" vẫn đang phục vụ bình thường, và coi
//     nó là hỏng sẽ báo động giả cho mọi app có xác thực.
//
// # Ranh giới
//
// Package này KHÔNG ghi store và KHÔNG gọi runtime — nó nhận một danh sách
// mục tiêu và trả kết quả. Reconciler là nơi duy nhất ghi trạng thái app, và
// giữ nguyên điều đó có nghĩa health monitor không cần lease riêng.
package health

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
)

// Target — một app cần probe.
type Target struct {
	AppID string
	// Endpoints — địa chỉ replica; probe TỪNG cái. App 3 replica mà 1 chết thì
	// gateway phải biết chính xác cái nào, không phải "app này hơi có vấn đề".
	Endpoints []Endpoint
	// Path — đường dẫn probe. Rỗng → "/".
	Path string
}

type Endpoint struct {
	Host string
	Port int
}

func (e Endpoint) addr() string { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }

// Result — kết quả probe một app.
type Result struct {
	AppID string
	// Health — contracts.Health*. Đây là giá trị SAU khi giảm rung.
	Health string
	// Raw — kết quả probe thô lần này, TRƯỚC giảm rung. Có nó để phân biệt
	// "vừa hỏng, đang chờ ngưỡng" với "vẫn khoẻ" khi đọc log.
	Raw string
	// Ready/Total — số endpoint trả lời được.
	Ready int
	Total int
	// Message — lý do khi không khoẻ.
	Message string
	// UnhealthySince — mốc bắt đầu hỏng liên tục (zero nếu đang khoẻ).
	UnhealthySince time.Time
}

// Degraded — có endpoint chết nhưng chưa phải toàn bộ.
func (r Result) Degraded() bool { return r.Ready > 0 && r.Ready < r.Total }

type Options struct {
	// UnhealthyAfter — hỏng liên tục quá lâu này mới coi là unhealthy.
	//
	// Không chọn quá dài vì vòng reconcile của ta nhanh và người dùng
	// self-host mong biết sớm; vẫn đủ dài để nuốt một lần restart container
	// hoặc một đợt GC dài.
	UnhealthyAfter time.Duration
	// Timeout cho MỘT lần probe.
	Timeout time.Duration
	// Now để test tua thời gian.
	Now func() time.Time
}

const (
	DefaultUnhealthyAfter = 2 * time.Minute
	DefaultTimeout        = 5 * time.Second
	// maxProbeBody — đọc rồi vứt, chỉ để tái dùng kết nối. App trả 4GB ở "/"
	// không được biến probe thành một cuộc tấn công vào chính ta.
	maxProbeBody = 4 << 10
)

// state — trí nhớ giảm rung cho một app.
type state struct {
	health         string
	unhealthySince time.Time
}

type Monitor struct {
	opts Options
	http *http.Client
	// startedAt — mốc khởi động tiến trình, dùng để KẸP unhealthySince (quy tắc 2).
	startedAt time.Time

	mu    sync.Mutex
	state map[string]*state
}

func New(opts Options) *Monitor {
	if opts.UnhealthyAfter <= 0 {
		opts.UnhealthyAfter = DefaultUnhealthyAfter
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Monitor{
		opts:      opts,
		startedAt: opts.Now(),
		state:     map[string]*state{},
		http: &http.Client{
			Timeout: opts.Timeout,
			// KHÔNG theo redirect: 302 tới trang đăng nhập là dấu hiệu app
			// SỐNG. Theo nó chỉ tốn thêm một vòng và có thể đi ra ngoài Internet.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Forget xoá trí nhớ của một app (gọi khi app bị xoá) để map không phình mãi.
func (m *Monitor) Forget(appID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.state, appID)
}

// Check probe MỘT app và trả kết quả đã giảm rung.
func (m *Monitor) Check(ctx context.Context, t Target) Result {
	now := m.opts.Now()
	res := Result{AppID: t.AppID, Total: len(t.Endpoints)}

	if len(t.Endpoints) == 0 {
		// Không có endpoint thì KHÔNG kết luận gì: app có thể đang deploy.
		// Kết luận "hỏng" ở đây sẽ báo động giả cho mọi app vừa được tạo.
		res.Raw = contracts.HealthUnknown
		res.Health = m.apply(t.AppID, contracts.HealthUnknown, now)
		res.Message = "no endpoint yet"
		return res
	}

	var firstErr string
	for _, ep := range t.Endpoints {
		if err := m.probe(ctx, ep, t.Path); err != nil {
			if firstErr == "" {
				firstErr = fmt.Sprintf("%s: %s", ep.addr(), err)
			}
			continue
		}
		res.Ready++
	}

	switch {
	case res.Ready == res.Total:
		res.Raw = contracts.HealthHealthy
	case res.Ready > 0:
		// Một phần replica chết: app VẪN phục vụ được. Gọi nó là unhealthy sẽ
		// làm mất phân biệt giữa "chậm" và "chết hẳn"; ta báo unhealthy nhưng
		// giữ Ready/Total để tầng trên quyết định.
		res.Raw = contracts.HealthUnhealthy
		res.Message = fmt.Sprintf("%d/%d replicas responded; %s", res.Ready, res.Total, firstErr)
	default:
		res.Raw = contracts.HealthUnhealthy
		res.Message = firstErr
	}

	res.Health = m.apply(t.AppID, res.Raw, now)
	m.mu.Lock()
	if s := m.state[t.AppID]; s != nil {
		res.UnhealthySince = s.unhealthySince
	}
	m.mu.Unlock()
	return res
}

// apply — GIẢM RUNG. Đây là toàn bộ giá trị của package.
//
// khoẻ  → ghi nhận ngay.
// hỏng  → giữ nguyên trạng thái cũ cho tới khi hỏng liên tục quá UnhealthyAfter.
func (m *Monitor) apply(appID, raw string, now time.Time) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	s := m.state[appID]
	if s == nil {
		s = &state{health: contracts.HealthUnknown}
		m.state[appID] = s
	}

	if raw == contracts.HealthHealthy {
		s.health = contracts.HealthHealthy
		s.unhealthySince = time.Time{}
		return s.health
	}

	if s.unhealthySince.IsZero() {
		s.unhealthySince = now
	}
	// Quy tắc 2: khoảng thời gian trước khi tiến trình này chạy là khoảng ta
	// KHÔNG quan sát gì, nên không được cộng vào thời gian hỏng.
	if s.unhealthySince.Before(m.startedAt) {
		s.unhealthySince = m.startedAt
	}

	if now.Sub(s.unhealthySince) >= m.opts.UnhealthyAfter {
		s.health = raw
	}
	// Chưa đủ ngưỡng → GIỮ giá trị cũ. Đây chính là chỗ nuốt rung.
	return s.health
}

// probe gọi HTTP một endpoint.
//
// 5xx mới là hỏng (quy tắc 3). Lỗi kết nối/timeout cũng là hỏng — khác hẳn với
// "trả 401": một cái là không ai nghe, cái kia là có người nghe và từ chối.
func (m *Monitor) probe(ctx context.Context, ep Endpoint, path string) error {
	if path == "" {
		path = "/"
	}
	if path[0] != '/' {
		path = "/" + path
	}
	ctx, cancel := context.WithTimeout(ctx, m.opts.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ep.addr()+path, nil)
	if err != nil {
		return err
	}
	// Gửi User-Agent riêng để log truy cập của app phân biệt được probe với
	// người dùng thật, và để WAF chặn request thiếu UA không làm probe hỏng oan.
	req.Header.Set("User-Agent", "Keenrig-HealthCheck/1")

	resp, err := m.http.Do(req)
	if err != nil {
		return netError(err)
	}
	defer resp.Body.Close()
	// Đọc một ít rồi vứt để kết nối tái dùng được; không đọc thì mỗi lần probe
	// mở một TCP mới và app thấy hàng nghìn kết nối TIME_WAIT.
	_, _ = io.CopyN(io.Discard, resp.Body, maxProbeBody)

	if resp.StatusCode >= 500 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// netError rút gọn lỗi mạng thành câu người đọc hiểu được.
func netError(err error) error {
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return errors.New("timed out")
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return fmt.Errorf("could not connect (%s)", opErr.Op)
	}
	return err
}
