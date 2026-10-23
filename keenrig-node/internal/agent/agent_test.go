package agent_test

// AG-04 · AG-08 · AG-09 và nửa phía INSTANCE của AG-01/02/03.
//
// # Cloud ở đây là một httptest.Server, và đó là lựa chọn có lý do
//
// Nửa phía cloud đã được kiểm trên PostgreSQL thật ở `keenrig-cloud`. Cái còn
// lại phải chứng minh là HÀNH VI CỦA AGENT khi cloud cư xử theo từng kiểu: trả
// 429, chết hẳn, sống lại, gửi lệnh. Dựng một cloud thật rồi ép nó chết đúng
// lúc là dựng một thứ khó điều khiển hơn nhiều so với thứ đang được kiểm.
//
// Ranh giới giữa hai bên là HTTP, và cả hai phía đều được kiểm trên đúng ranh
// giới đó — không bên nào giả lập bên kia bằng một interface Go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/agent"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
)

// --- chính sách poll -------------------------------------------------------------

// AG-03 phía agent — tôn trọng `next_poll_ms` TUYỆT ĐỐI.
func TestPolicyRespectsServerInterval(t *testing.T) {
	p := agent.NewPolicy(rand.New(rand.NewSource(1)))
	for _, ms := range []int{2000, 30000, 5000} {
		got := p.Next(agent.Outcome{OK: true, NextPollMS: ms})
		want := time.Duration(ms) * time.Millisecond
		if !within(got, want, agent.JitterFrac) {
			t.Errorf("next_poll_ms=%d → chờ %s, muốn quanh %s (±%.0f%%)",
				ms, got, want, agent.JitterFrac*100)
		}
	}
	// Server không nói gì → nhịp mặc định.
	if got := p.Next(agent.Outcome{OK: true}); !within(got, agent.DefaultInterval, agent.JitterFrac) {
		t.Errorf("không có next_poll_ms → %s, muốn quanh %s", got, agent.DefaultInterval)
	}
}

// Sàn nằm ở PHÍA AGENT.
//
// Server nói `next_poll_ms: 1` vì một lỗi cấu hình sẽ biến fleet thành một cuộc
// tấn công vào chính nó. Agent là nơi chịu hậu quả và là nơi không sửa được từ
// xa, nên sàn phải ở đây.
func TestPolicyRefusesAbsurdlyFastIntervals(t *testing.T) {
	p := agent.NewPolicy(rand.New(rand.NewSource(2)))
	for _, ms := range []int{1, 10, 100} {
		if got := p.Next(agent.Outcome{OK: true, NextPollMS: ms}); got < agent.MinInterval {
			t.Errorf("next_poll_ms=%d → %s, dưới sàn %s", ms, got, agent.MinInterval)
		}
	}
	// Và trần: một server nói 10 giờ cũng không làm agent biến mất.
	if got := p.Next(agent.Outcome{OK: true, NextPollMS: 36_000_000}); got > agent.MaxBackoff {
		t.Errorf("next_poll_ms rất lớn → %s, vượt trần %s", got, agent.MaxBackoff)
	}
}

// AG-04 — 429 + Retry-After: tôn trọng con số server đưa, backoff có trần 5'.
func TestPolicyBacksOffAndCapsAtFiveMinutes(t *testing.T) {
	p := agent.NewPolicy(rand.New(rand.NewSource(3)))

	// Retry-After thắng mọi thứ khác: server đang nói THẲNG là chờ bao lâu.
	got := p.Next(agent.Outcome{Err: agent.ErrRateLimited, RetryAfter: 7 * time.Second})
	if !within(got, 7*time.Second, agent.JitterFrac) {
		t.Errorf("Retry-After 7s → %s", got)
	}

	// Lỗi liên tiếp → backoff mũ, và ĐỨNG YÊN ở trần.
	p = agent.NewPolicy(rand.New(rand.NewSource(4)))
	var last time.Duration
	for i := range 20 {
		d := p.Next(agent.Outcome{Err: errors.New("cloud chết")})
		if d > agent.MaxBackoff {
			t.Fatalf("vòng %d: chờ %s, vượt trần %s", i, d, agent.MaxBackoff)
		}
		last = d
	}
	if !within(last, agent.MaxBackoff, agent.JitterFrac) {
		t.Errorf("sau 20 lần lỗi, chờ %s — muốn đã chạm trần %s", last, agent.MaxBackoff)
	}
	// Thành công một lần là RESET. Không reset thì một trục trặc mạng thoáng
	// qua để agent chậm 5 phút trong nhiều giờ sau đó.
	if d := p.Next(agent.Outcome{OK: true, NextPollMS: 30000}); !within(d, 30*time.Second, agent.JitterFrac) {
		t.Errorf("sau khi hồi phục vẫn chờ %s — backoff không reset", d)
	}
	if p.Fails() != 0 {
		t.Errorf("Fails() = %d sau khi thành công", p.Fails())
	}
}

// JITTER phải có THẬT, ở mọi nhánh.
//
// 10k agent khởi động lại cùng lúc sau một sự cố sẽ gọi lên cùng một giây nếu
// không có jitter — cloud vừa sống lại đã bị đạp xuống. Đây chính là nửa
// "không thundering herd" của AG-04.
func TestJitterSpreadsAgentsApart(t *testing.T) {
	// MỘT nguồn ngẫu nhiên dùng chung cho 200 agent, không phải 200 nguồn gieo
	// bằng 200 hạt giống liên tiếp.
	//
	// Đây là bài học của chính bộ test này. Bản đầu gieo `rand.NewSource(0..199)`
	// và chỉ ra ~100 giá trị khác nhau trong 200 — nhìn như sản phẩm thiếu
	// jitter. Thật ra `rand.NewSource` cho những giá trị ĐẦU tương quan với nhau
	// khi hạt giống gần nhau; đổi sang hạt giống rải thưa vẫn thế.
	//
	// Mô hình đúng của thực tế là 200 TIẾN TRÌNH, mỗi cái gieo từ một nguồn
	// entropy tử tế — tức là 200 lần rút từ một dòng tốt. Một khung test mô hình
	// sai hiện thực sẽ tố cáo sản phẩm về một lỗi của chính nó.
	src := rand.New(rand.NewSource(20260814))

	for _, tc := range []struct {
		name string
		out  agent.Outcome
	}{
		{"thành công", agent.Outcome{OK: true, NextPollMS: 30000}},
		{"lỗi", agent.Outcome{Err: errors.New("cloud chết")}},
		{"429", agent.Outcome{Err: agent.ErrRateLimited, RetryAfter: 2 * time.Second}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := map[time.Duration]int{}
			for range 200 {
				seen[agent.NewPolicy(src).Next(tc.out)]++
			}
			if len(seen) < 190 {
				t.Fatalf("200 agent chỉ cho %d khoảng chờ khác nhau — chúng sẽ gọi lên "+
					"thành từng đợt, và cloud vừa sống lại đã bị đạp xuống", len(seen))
			}
		})
	}
}

// --- vòng lặp trên HTTP thật ---------------------------------------------------------

// fakeCloud — control plane điều khiển được, đếm được.
type fakeCloud struct {
	mu       sync.Mutex
	syncs    int
	down     bool
	rate429  bool
	commands []agent.Command
	results  []agent.CommandResult
	lastReq  agent.SyncRequest
	// parent/mode — tên miền cloud đã chọn cho env; rỗng = chưa chọn, và
	// phản hồi KHÔNG mang trường (omitempty), đúng như cloud thật.
	parent, mode string
}

func (f *fakeCloud) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/v1/sync", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.syncs++

		if f.down {
			http.Error(w, "cloud đang chết", http.StatusBadGateway)
			return
		}
		if f.rate429 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
			return
		}
		var req agent.SyncRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.lastReq = req
		f.results = append(f.results, req.CommandResults...)

		cmds := f.commands
		f.commands = nil
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(agent.SyncResponse{
			Commands: cmds, NextPollMS: 30000,
			ParentDomain: f.parent, DomainMode: f.mode,
		})
	})
	return mux
}

func (f *fakeCloud) snapshot() (syncs int, results []agent.CommandResult, last agent.SyncRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.syncs, append([]agent.CommandResult(nil), f.results...), f.lastReq
}

func (f *fakeCloud) set(fn func(*fakeCloud)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// fakeNode — node API của box.
type fakeNode struct {
	apps json.RawMessage
	err  error
}

func (n *fakeNode) AppStatuses(context.Context) (json.RawMessage, error) { return n.apps, n.err }

// recordingExec ghi lại lệnh đã chạy, và hỏng theo yêu cầu.
type recordingExec struct {
	mu   sync.Mutex
	ran  []agent.Command
	fail map[string]error
}

func (e *recordingExec) Execute(_ context.Context, c agent.Command) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ran = append(e.ran, c)
	return e.fail[c.Kind]
}

func (e *recordingExec) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.ran)
}

// runLoop chạy vòng lặp với đồng hồ GIẢ: mọi Sleep trả về ngay, nên test kiểm
// được hàng chục vòng trong micro-giây thay vì chờ thật.
func runLoop(t *testing.T, f *fakeCloud, opts agent.Options, rounds int) (*agent.Loop, []time.Duration, []string) {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)

	var waits []time.Duration
	var logs []string
	var mu sync.Mutex
	ctx, cancel := context.WithCancel(context.Background())

	opts.Sleep = func(_ context.Context, d time.Duration) {
		mu.Lock()
		waits = append(waits, d)
		n := len(waits)
		mu.Unlock()
		if n >= rounds {
			cancel()
		}
	}
	opts.Log = func(format string, args ...any) {
		mu.Lock()
		logs = append(logs, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	if opts.Policy == nil {
		opts.Policy = agent.NewPolicy(rand.New(rand.NewSource(7)))
	}

	l := agent.NewLoop(agent.NewClient(srv.URL, "khoa-test", 5*time.Second), opts)
	_ = l.Run(ctx)
	mu.Lock()
	defer mu.Unlock()
	return l, append([]time.Duration(nil), waits...), append([]string(nil), logs...)
}

// AG-01/02 phía agent — nhận lệnh → thực thi → báo kết quả ở lần sync SAU.
func TestLoopExecutesCommandsAndReportsNextRound(t *testing.T) {
	f := &fakeCloud{commands: []agent.Command{
		{ID: "cmd-1", IdempotencyKey: "k1", Kind: "notice", Payload: json.RawMessage(`{}`)},
	}}
	exec := &recordingExec{}
	runLoop(t, f, agent.Options{
		EnvID: "env-1", Version: "0.1.0",
		Node: &fakeNode{apps: json.RawMessage(`[{"app_id":"a","state":"running"}]`)},
		Exec: exec,
	}, 3)

	if exec.count() != 1 {
		t.Fatalf("thực thi %d lệnh, muốn 1", exec.count())
	}
	_, results, last := f.snapshot()
	if len(results) != 1 || results[0].ID != "cmd-1" || !results[0].OK {
		t.Fatalf("kết quả báo lên = %+v", results)
	}
	// Và trạng thái app đi lên NGUYÊN VĂN từ node API (ND-01).
	if !strings.Contains(string(last.AppStatuses), `"app_id":"a"`) {
		t.Errorf("app_statuses = %s", last.AppStatuses)
	}
}

// Lệnh THẤT BẠI vẫn được báo lên, kèm lý do (CON-14).
func TestFailedCommandIsReportedWithItsReason(t *testing.T) {
	f := &fakeCloud{commands: []agent.Command{
		{ID: "cmd-x", Kind: "install_cert", Payload: json.RawMessage(`{}`)},
	}}
	exec := &recordingExec{fail: map[string]error{"install_cert": errors.New("cổng 80 đang bận")}}
	runLoop(t, f, agent.Options{EnvID: "env-1", Exec: exec}, 3)

	_, results, _ := f.snapshot()
	if len(results) != 1 || results[0].OK {
		t.Fatalf("kết quả = %+v, muốn một lệnh thất bại", results)
	}
	if results[0].Error != "cổng 80 đang bận" {
		t.Errorf("lý do = %q — mất lý do là mất khả năng sửa", results[0].Error)
	}
}

// Kết quả lệnh KHÔNG được rơi mất khi lần sync sau thất bại.
//
// Mất một kết quả nghĩa là lệnh treo ở `delivered` mãi mãi trên Console, và
// người dùng nhìn thấy "đang chạy" cho một việc đã xong từ lâu.
func TestCommandResultSurvivesAFailedSync(t *testing.T) {
	f := &fakeCloud{commands: []agent.Command{{ID: "cmd-9", Kind: "notice", Payload: json.RawMessage(`{}`)}}}
	exec := &recordingExec{}

	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	l := agent.NewLoop(agent.NewClient(srv.URL, "k", 5*time.Second), agent.Options{
		EnvID: "env-1", Exec: exec,
		Log:   func(string, ...any) {},
		Sleep: func(context.Context, time.Duration) {},
	})

	ctx, cancel := context.WithCancel(context.Background())
	rounds := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = l.Run(ctx)
	}()
	// Vòng 1 nhận lệnh; ngay sau đó cloud chết vài vòng; rồi sống lại.
	for range 40 {
		time.Sleep(time.Millisecond)
		s, _, _ := f.snapshot()
		if s >= 1 && rounds == 0 {
			rounds = 1
			f.set(func(c *fakeCloud) { c.down = true })
		}
		if s >= 4 && rounds == 1 {
			rounds = 2
			f.set(func(c *fakeCloud) { c.down = false })
		}
		if _, res, _ := f.snapshot(); len(res) > 0 {
			break
		}
	}
	cancel()
	<-done

	_, results, _ := f.snapshot()
	if len(results) == 0 {
		t.Fatal("kết quả lệnh RƠI MẤT khi cloud chết giữa chừng — lệnh sẽ treo ở " +
			"`delivered` mãi mãi trên Console")
	}
	if results[0].ID != "cmd-9" {
		t.Errorf("kết quả = %+v", results)
	}
}

// AG-08 — cắt cloud thì agent KHÔNG chết, KHÔNG spam log.
//
// Bảy ngày ở nhịp backoff 5 phút là ~2000 vòng. Test chạy 200 vòng và đòi số
// dòng log KHÔNG tỉ lệ với số vòng: một chuỗi lỗi lặp lại chỉ đáng một dòng.
func TestLoopSurvivesLongCloudOutageWithoutLogSpam(t *testing.T) {
	f := &fakeCloud{down: true}
	_, waits, logs := runLoop(t, f, agent.Options{EnvID: "env-1"}, 200)

	if len(waits) < 200 {
		t.Fatalf("vòng lặp DỪNG sau %d vòng khi cloud chết — agent thoát là mất "+
			"luôn đường quan sát instance đó", len(waits))
	}
	if len(logs) > 5 {
		t.Errorf("%d dòng log cho 200 vòng cùng một lỗi — 7 ngày mất cloud sẽ lấp "+
			"mất mọi thứ khác trên máy:\n%s", len(logs), strings.Join(logs[:5], "\n"))
	}
	if len(logs) == 0 {
		t.Error("mất cloud mà KHÔNG có dòng log nào — im lặng cũng là một cách hỏng")
	}
	// Và nó phải chạm trần 5 phút chứ không chờ lâu hơn.
	if max := maxWait(waits); max > agent.MaxBackoff {
		t.Errorf("khoảng chờ lớn nhất %s, vượt trần %s", max, agent.MaxBackoff)
	}
}

// AG-09 — cloud sống lại thì agent tự về, không cần can thiệp, và NÓI RA.
func TestLoopReconnectsAndSaysSo(t *testing.T) {
	f := &fakeCloud{down: true}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	var logs []string
	var mu sync.Mutex
	ctx, cancel := context.WithCancel(context.Background())
	round := 0
	l := agent.NewLoop(agent.NewClient(srv.URL, "k", 5*time.Second), agent.Options{
		EnvID:  "env-1",
		Policy: agent.NewPolicy(rand.New(rand.NewSource(11))),
		Log: func(format string, args ...any) {
			mu.Lock()
			logs = append(logs, fmt.Sprintf(format, args...))
			mu.Unlock()
		},
		Sleep: func(context.Context, time.Duration) {
			round++
			if round == 5 {
				f.set(func(c *fakeCloud) { c.down = false }) // cloud sống lại
			}
			if round >= 10 {
				cancel()
			}
		},
	})
	_ = l.Run(ctx)

	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "reconnected") {
		t.Fatalf("cloud sống lại mà không có dòng nào đánh dấu — không ai biết sự cố "+
			"kéo dài bao lâu:\n%s", joined)
	}
	if s, _, _ := f.snapshot(); s < 6 {
		t.Errorf("chỉ gọi %d lần — agent không tự quay lại", s)
	}
}

// AG-04 phía agent — 429 kèm Retry-After được TÔN TRỌNG, không phải bỏ qua.
func TestLoopHonoursRetryAfter(t *testing.T) {
	f := &fakeCloud{rate429: true}
	_, waits, _ := runLoop(t, f, agent.Options{
		EnvID:  "env-1",
		Policy: agent.NewPolicy(rand.New(rand.NewSource(13))),
	}, 5)

	for i, w := range waits {
		if !within(w, 2*time.Second, agent.JitterFrac) {
			t.Errorf("vòng %d: chờ %s, muốn quanh 2s (Retry-After của server)", i, w)
		}
	}
}

// Box khởi động lại KHÔNG được làm agent im bặt.
//
// Không đọc được trạng thái app là ca thường ngày. Bỏ nguyên vòng sync vì thế
// nghĩa là Console thấy env "mất kết nối" mỗi lần box restart — một cảnh báo
// giả mà người vận hành sẽ học cách phớt lờ.
func TestHeartbeatContinuesWhenTheBoxIsDown(t *testing.T) {
	f := &fakeCloud{}
	node := &fakeNode{err: errors.New("dial unix box.sock: connect: connection refused")}
	runLoop(t, f, agent.Options{EnvID: "env-1", Version: "0.1.0", Node: node}, 3)

	syncs, _, last := f.snapshot()
	if syncs < 3 {
		t.Fatalf("chỉ sync %d lần khi box chết — heartbeat đã bị chặn", syncs)
	}
	if last.Heartbeat.TS == "" {
		t.Error("heartbeat rỗng")
	}
	if len(last.AppStatuses) != 0 {
		t.Errorf("app_statuses = %s, muốn rỗng khi không đọc được", last.AppStatuses)
	}
}

// OB-05 phía vòng poll — metrics đi cùng chuyến heartbeat, và "không đo được"
// nghĩa là VẮNG trên dây, không phải một object số 0.
func TestMetricsRideAlongWithHeartbeat(t *testing.T) {
	f := &fakeCloud{}
	cpu := 34.0
	total := 4096.0
	runLoop(t, f, agent.Options{
		EnvID: "env-1", Version: "0.1.0",
		Metrics: func() *contracts.MetricsSummary {
			return &contracts.MetricsSummary{CPUPct: &cpu, MemTotalMB: &total}
		},
	}, 2)

	_, _, last := f.snapshot()
	if len(last.MetricsSummary) == 0 {
		t.Fatal("sync không mang metrics_summary dù collector có số")
	}
	var m contracts.MetricsSummary
	if err := json.Unmarshal(last.MetricsSummary, &m); err != nil {
		t.Fatalf("metrics_summary không phải JSON hợp lệ: %v", err)
	}
	if m.CPUPct == nil || *m.CPUPct != 34 {
		t.Errorf("cpu_pct = %v, muốn 34", m.CPUPct)
	}
	if m.DiskUsedGB != nil {
		t.Error("trường không đo phải VẮNG — disk_used_gb lại có mặt")
	}
}

func TestNoMetricsMeansNoMetricsField(t *testing.T) {
	f := &fakeCloud{}
	runLoop(t, f, agent.Options{
		EnvID: "env-1", Version: "0.1.0",
		// Collector trả nil — máy vừa boot, chưa có mẫu thứ hai để đo tốc độ.
		Metrics: func() *contracts.MetricsSummary { return nil },
	}, 2)

	_, _, last := f.snapshot()
	if len(last.MetricsSummary) != 0 {
		t.Fatalf("không đo được thì trường phải VẮNG, nhận %s", last.MetricsSummary)
	}
}

// --- tên miền gốc đi cloud → agent → box -----------------------------------------------
//
// Tên miền của một môi trường là QUYẾT ĐỊNH CỦA CLOUD (luật chủ dự án
// 2026-09-07); agent chỉ chuyển nó xuống box qua `PUT /node/v1/parent-domain`.
// Bốn điều vòng lặp phải giữ: giao MỘT lần cho một giá trị (cloud gửi nó mỗi
// nhịp), giao lại khi giá trị ĐỔI, thử lại khi box từ chối mà không spam log, và
// KHÔNG gọi gì khi cloud chưa chọn tên.

// recordingDomainSink — box giả ở ranh giới interface, ghi lại từng lần giao.
type recordingDomainSink struct {
	mu    sync.Mutex
	calls []string // "parent|mode"
}

func (s *recordingDomainSink) SetParentDomain(_ context.Context, parent, mode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, parent+"|"+mode)
	return nil
}

func (s *recordingDomainSink) got() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// Cloud gửi cùng tên ở MỌI nhịp; box chỉ nhận MỘT lần. Không có bộ nhớ "đã
// giao" thì mỗi 30 giây là một lần ghi ba khoá settings cho cùng một giá trị.
func TestParentDomainIsDeliveredOnceForTheSameValue(t *testing.T) {
	f := &fakeCloud{parent: "demo.acme.keenrig.com", mode: "keenrig"}
	sink := &recordingDomainSink{}
	_, _, logs := runLoop(t, f, agent.Options{EnvID: "env-1", Domain: sink}, 3)

	if syncs, _, _ := f.snapshot(); syncs < 3 {
		t.Fatalf("chỉ sync %d lần — khung test không chạy đủ vòng", syncs)
	}
	if got := sink.got(); len(got) != 1 || got[0] != "demo.acme.keenrig.com|keenrig" {
		t.Fatalf("box nhận %v qua 3 nhịp sync, muốn đúng MỘT lần %q", got, "demo.acme.keenrig.com|keenrig")
	}
	n := 0
	for _, l := range logs {
		if strings.Contains(l, "delivered") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d dòng log 'delivered' cho một lần giao:\n%s", n, strings.Join(logs, "\n"))
	}
}

// Đổi tên ở Console → box nhận tên mới ở nhịp kế; tên cũ không được giao lại.
func TestParentDomainIsRedeliveredWhenItChanges(t *testing.T) {
	f := &fakeCloud{parent: "old.iot.keenrig.com", mode: "keenrig"}
	sink := &recordingDomainSink{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	round := 0
	l := agent.NewLoop(agent.NewClient(srv.URL, "k", 5*time.Second), agent.Options{
		EnvID:  "env-1",
		Domain: sink,
		Policy: agent.NewPolicy(rand.New(rand.NewSource(17))),
		Log:    func(string, ...any) {},
		Sleep: func(context.Context, time.Duration) {
			round++
			if round == 2 {
				f.set(func(c *fakeCloud) { c.parent, c.mode = "shop.example.com", "custom" })
			}
			if round >= 5 {
				cancel()
			}
		},
	})
	_ = l.Run(ctx)

	want := []string{"old.iot.keenrig.com|keenrig", "shop.example.com|custom"}
	got := sink.got()
	if len(got) != len(want) {
		t.Fatalf("box nhận %v, muốn %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("lần giao %d = %q, muốn %q", i, got[i], want[i])
		}
	}
}

// Box từ chối (500) → thử lại ở MỖI nhịp, nhưng log đúng MỘT dòng cho cùng một
// lý do — và lý do của box đi NGUYÊN VĂN vào dòng đó. Đi qua NodeClient thật
// để đo cả đường PUT /node/v1/parent-domain, không chỉ interface.
func TestParentDomainIsRetriedWithoutLogSpamWhenTheBoxRefuses(t *testing.T) {
	var (
		mu    sync.Mutex
		hits  int
		paths []string
	)
	box := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"settings table is read-only"}`))
	}))
	defer box.Close()

	f := &fakeCloud{parent: "demo.acme.keenrig.com", mode: "keenrig"}
	_, _, logs := runLoop(t, f, agent.Options{
		EnvID:  "env-1",
		Domain: agent.NewNodeClient(box.URL, time.Second),
	}, 5)

	mu.Lock()
	defer mu.Unlock()
	if hits != 5 {
		t.Fatalf("box bị gọi %d lần qua 5 nhịp — từ chối phải được thử lại ở mỗi nhịp, "+
			"và chỉ khi 200 mới được nhớ là đã giao", hits)
	}
	if paths[0] != "PUT /node/v1/parent-domain" {
		t.Errorf("gọi %q, hợp đồng node.yaml nói PUT /node/v1/parent-domain", paths[0])
	}
	var refused []string
	for _, l := range logs {
		if strings.Contains(l, "refused the parent domain") {
			refused = append(refused, l)
		}
	}
	if len(refused) != 1 {
		t.Fatalf("%d dòng log cho 5 lần cùng một lý do từ chối — phải gộp còn một:\n%s",
			len(refused), strings.Join(logs, "\n"))
	}
	if !strings.Contains(refused[0], "settings table is read-only") {
		t.Errorf("lý do của box không đi nguyên văn vào log: %s", refused[0])
	}
	// Và sync KHÔNG bị kéo theo: box hỏng không làm Console thấy env mất kết nối.
	if syncs, _, _ := f.snapshot(); syncs < 5 {
		t.Errorf("chỉ sync %d lần — box từ chối tên miền đã chặn heartbeat", syncs)
	}
}

// Cloud chưa chọn tên miền → agent KHÔNG gõ cửa box, và nhất là không xoá gì.
func TestNoParentDomainMeansTheSinkIsNeverCalled(t *testing.T) {
	f := &fakeCloud{}
	sink := &recordingDomainSink{}
	runLoop(t, f, agent.Options{EnvID: "env-1", Domain: sink}, 3)
	if got := sink.got(); len(got) != 0 {
		t.Fatalf("cloud không gửi parent_domain mà box vẫn nhận %v — một tên rỗng đi xuống "+
			"là một tên local bị xoá", got)
	}
}

// NodeClient nói đúng hợp đồng node.yaml: PUT /node/v1/parent-domain, thân mang
// parent_domain + mode.
func TestNodeClientPutsTheParentDomainWhereTheContractSays(t *testing.T) {
	var (
		gotPath string
		gotBody map[string]string
	)
	box := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.Method + " " + r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"stored"}`))
	}))
	defer box.Close()

	if err := agent.NewNodeClient(box.URL, time.Second).
		SetParentDomain(context.Background(), "demo.acme.keenrig.com", "keenrig"); err != nil {
		t.Fatalf("SetParentDomain: %v", err)
	}
	if gotPath != "PUT /node/v1/parent-domain" {
		t.Errorf("gọi %q, hợp đồng node.yaml nói PUT /node/v1/parent-domain", gotPath)
	}
	if gotBody["parent_domain"] != "demo.acme.keenrig.com" || gotBody["mode"] != "keenrig" {
		t.Errorf("thân request = %v", gotBody)
	}
}

// --- trạng thái pair (AD-12): agent báo cho box SAU sync thành công, có tiết chế ---

// recordingCloudLinkSink — box giả ở ranh giới interface, ghi lại từng báo cáo.
type recordingCloudLinkSink struct {
	mu    sync.Mutex
	calls []cloudLinkReport
}

type cloudLinkReport struct {
	url, env string
	at       time.Time
}

func (s *recordingCloudLinkSink) SetCloudLink(_ context.Context, cloudURL, envID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, cloudLinkReport{cloudURL, envID, at})
	return nil
}

func (s *recordingCloudLinkSink) got() []cloudLinkReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]cloudLinkReport(nil), s.calls...)
}

// Một sync thành công → box nhận đúng MỘT báo cáo mang CloudURL/EnvID và một
// mốc "vừa rồi" — đây là dữ kiện Admin UI thiếu suốt tới 2026-09-19.
func TestCloudLinkIsReportedAfterASuccessfulSync(t *testing.T) {
	f := &fakeCloud{}
	sink := &recordingCloudLinkSink{}
	before := time.Now()
	_, _, logs := runLoop(t, f, agent.Options{
		EnvID: "env-1", CloudLink: sink, CloudURL: "https://keenrig.com",
	}, 1)

	got := sink.got()
	if len(got) != 1 {
		t.Fatalf("box nhận %d báo cáo sau một sync thành công, muốn đúng 1: %+v", len(got), got)
	}
	if got[0].url != "https://keenrig.com" || got[0].env != "env-1" {
		t.Errorf("báo cáo = %+v, muốn https://keenrig.com / env-1", got[0])
	}
	if got[0].at.Before(before.Add(-time.Second)) || got[0].at.After(time.Now().Add(time.Second)) {
		t.Errorf("mốc last_sync_at = %s, không phải 'vừa rồi' (%s)", got[0].at, before)
	}
	n := 0
	for _, l := range logs {
		if strings.Contains(l, "cloud link state delivered") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d dòng log 'delivered' cho lần báo đầu, muốn 1:\n%s", n, strings.Join(logs, "\n"))
	}
}

// Ba nhịp sync nhanh liên tiếp → vẫn MỘT báo cáo: tiết chế theo CloudLinkEvery
// với đồng hồ tiêm vào. Không có nó thì mỗi 30 giây là ba khoá settings được
// ghi lại cho cùng một sự thật.
func TestCloudLinkIsThrottled(t *testing.T) {
	f := &fakeCloud{}
	sink := &recordingCloudLinkSink{}
	clock := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	runLoop(t, f, agent.Options{
		EnvID: "env-1", CloudLink: sink, CloudURL: "https://keenrig.com",
		// Mỗi lần hỏi giờ tiến 5 giây: ba vòng ≪ một phút.
		Now: func() time.Time { clock = clock.Add(5 * time.Second); return clock },
	}, 3)
	if syncs, _, _ := f.snapshot(); syncs < 3 {
		t.Fatalf("chỉ sync %d lần — khung test không chạy đủ vòng", syncs)
	}
	if got := sink.got(); len(got) != 1 {
		t.Fatalf("box nhận %d báo cáo qua 3 nhịp trong vài giây, muốn 1 (tiết chế %s): %+v",
			len(got), agent.DefaultCloudLinkEvery, got)
	}

	// Và khi đồng hồ vượt nhịp thì báo lại — mốc trên Admin UI phải tươi.
	sink2 := &recordingCloudLinkSink{}
	clock2 := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	runLoop(t, &fakeCloud{}, agent.Options{
		EnvID: "env-1", CloudLink: sink2, CloudURL: "https://keenrig.com",
		Now: func() time.Time { clock2 = clock2.Add(40 * time.Second); return clock2 },
	}, 3)
	if got := sink2.got(); len(got) < 2 {
		t.Fatalf("đồng hồ tiến 40 s mỗi lần hỏi qua 3 nhịp mà box chỉ nhận %d báo cáo — mốc last sync sẽ cũ mãi", len(got))
	}
}

// Cloud chết → KHÔNG báo gì: mốc chỉ đi sau thành công, vì nó là bằng chứng
// cloud vừa trả lời. Báo cả khi hỏng thì box không bao giờ tính ra `stale`.
func TestCloudLinkIsNotReportedWhenSyncFails(t *testing.T) {
	f := &fakeCloud{down: true}
	sink := &recordingCloudLinkSink{}
	runLoop(t, f, agent.Options{
		EnvID: "env-1", CloudLink: sink, CloudURL: "https://keenrig.com",
	}, 4)
	if got := sink.got(); len(got) != 0 {
		t.Fatalf("cloud chết mà box vẫn nhận %d báo cáo pair — Admin UI sẽ vẽ synced trên máy đã mất cloud", len(got))
	}
}

// Box từ chối (500) → thử lại ở mỗi nhịp thành công, log đúng MỘT dòng cho
// cùng lý do (nguyên văn), và sync KHÔNG bị kéo theo. Đi qua NodeClient thật
// để đo cả đường PUT /node/v1/cloud-link.
func TestCloudLinkIsRetriedWithoutLogSpamWhenTheBoxRefuses(t *testing.T) {
	var (
		mu    sync.Mutex
		hits  int
		paths []string
	)
	box := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"settings table is read-only"}`))
	}))
	defer box.Close()

	f := &fakeCloud{}
	_, _, logs := runLoop(t, f, agent.Options{
		EnvID: "env-1", CloudURL: "https://keenrig.com",
		CloudLink: agent.NewNodeClient(box.URL, time.Second),
	}, 5)

	mu.Lock()
	defer mu.Unlock()
	if hits != 5 {
		t.Fatalf("box bị gọi %d lần qua 5 nhịp — từ chối phải được thử lại ở mỗi nhịp, "+
			"và chỉ khi 2xx mới được nhớ là đã báo", hits)
	}
	if paths[0] != "PUT /node/v1/cloud-link" {
		t.Errorf("gọi %q, hợp đồng node.yaml nói PUT /node/v1/cloud-link", paths[0])
	}
	var refused []string
	for _, l := range logs {
		if strings.Contains(l, "refused the cloud link") {
			refused = append(refused, l)
		}
	}
	if len(refused) != 1 {
		t.Fatalf("%d dòng log cho 5 lần cùng một lý do từ chối — phải gộp còn một:\n%s",
			len(refused), strings.Join(logs, "\n"))
	}
	if !strings.Contains(refused[0], "settings table is read-only") {
		t.Errorf("lý do của box không đi nguyên văn vào log: %s", refused[0])
	}
	if syncs, _, _ := f.snapshot(); syncs < 5 {
		t.Errorf("chỉ sync %d lần — box từ chối trạng thái pair đã chặn heartbeat", syncs)
	}
}

// NodeClient nói đúng hợp đồng node.yaml: PUT /node/v1/cloud-link, thân mang
// cloud_url + env_id + last_sync_at (RFC3339).
func TestNodeClientPutsTheCloudLinkWhereTheContractSays(t *testing.T) {
	var (
		gotPath string
		gotBody map[string]string
	)
	box := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.Method + " " + r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"stored"}`))
	}))
	defer box.Close()

	at := time.Date(2026, 9, 19, 3, 4, 5, 0, time.FixedZone("ICT", 7*3600))
	if err := agent.NewNodeClient(box.URL, time.Second).
		SetCloudLink(context.Background(), "https://keenrig.com", "env_01J8ZK", at); err != nil {
		t.Fatalf("SetCloudLink: %v", err)
	}
	if gotPath != "PUT /node/v1/cloud-link" {
		t.Errorf("gọi %q, hợp đồng node.yaml nói PUT /node/v1/cloud-link", gotPath)
	}
	if gotBody["cloud_url"] != "https://keenrig.com" || gotBody["env_id"] != "env_01J8ZK" ||
		gotBody["last_sync_at"] != "2026-09-18T20:04:05Z" {
		t.Errorf("thân request = %v, muốn ba trường đúng tên hợp đồng, mốc RFC3339 UTC", gotBody)
	}
}

// --- tiện ích ------------------------------------------------------------------------

func within(got, want time.Duration, frac float64) bool {
	lo := time.Duration(float64(want) * (1 - frac - 0.01))
	hi := time.Duration(float64(want) * (1 + frac + 0.01))
	return got >= lo && got <= hi
}

func maxWait(ds []time.Duration) time.Duration {
	var m time.Duration
	for _, d := range ds {
		if d > m {
			m = d
		}
	}
	return m
}
