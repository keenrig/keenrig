package agent_test

// Vòng gia hạn license (M5): cloud ký → agent đưa thư → box verify+ghi.
// Agent là NGƯỜI ĐƯA THƯ: mọi test ở đây canh hai điều — byte đi nguyên văn,
// và nhịp hỏi không biến thành spam.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/agent"
)

// licenseCloud — control plane giả có CẢ sync lẫn license.
type licenseCloud struct {
	mu       sync.Mutex
	syncs    int
	licenses int
	status   int // 0 → 200
	body     []byte
}

func (f *licenseCloud) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/v1/sync", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.syncs++
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(agent.SyncResponse{NextPollMS: 30000})
	})
	mux.HandleFunc("GET /agent/v1/license", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.licenses++
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if f.status != 0 {
			w.WriteHeader(f.status)
			_, _ = w.Write([]byte(`{"error":"no_signer"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(f.body)
	})
	return mux
}

func (f *licenseCloud) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.licenses
}

// recordingSink — box giả phía sau node API.
type recordingSink struct {
	mu  sync.Mutex
	got [][]byte
	err error
}

func (s *recordingSink) InstallLicense(_ context.Context, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, append([]byte(nil), raw...))
	return s.err
}

func (s *recordingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

// envelope mẫu — nội dung không quan trọng với agent (nó không mở phong bì).
var sampleEnvelope = []byte(`{"v":1,"key_id":"active","payload":"eyJwbGFuIjoicHJvIn0","signature":"c2ln"}`)

// tickingNow — đồng hồ giả tiến `step` mỗi lần được hỏi. Cadence KHÔNG được
// kiểm bằng đồng hồ thật: Windows cấp time.Now theo tick ~0.5ms, hai vòng lặp
// nhanh nằm gọn trong một tick cho hiệu số 0 và test thành trò tung xu.
func tickingNow(step time.Duration) func() time.Time {
	var mu sync.Mutex
	t0 := time.Unix(1_700_000_000, 0)
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		t0 = t0.Add(step)
		return t0
	}
}

// Nhịp mặc định 12h: trong N vòng sync liên tiếp (đồng hồ tiến 1 giây mỗi lần
// hỏi), license chỉ được hỏi MỘT lần, và byte tới sink nguyên văn.
func TestLicenseIsFetchedOncePerCadenceNotOncePerSync(t *testing.T) {
	f := &licenseCloud{body: sampleEnvelope}
	sink := &recordingSink{}

	rounds := 0
	var cancel context.CancelFunc
	ctx, c := context.WithCancel(context.Background())
	cancel = c
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	l := agent.NewLoop(agent.NewClient(srv.URL, "khoa-test", 5*time.Second), agent.Options{
		EnvID: "env-1", Version: "0.1.0",
		License: sink,
		Now:     tickingNow(time.Second),
		Policy:  agent.NewPolicy(rand.New(rand.NewSource(7))),
		Log:     func(string, ...any) {},
		Sleep: func(_ context.Context, _ time.Duration) {
			rounds++
			if rounds >= 5 {
				cancel()
			}
		},
	})
	_ = l.Run(ctx)

	if got := f.count(); got != 1 {
		t.Fatalf("license bị hỏi %d lần trong 5 vòng sync — nhịp 12h thành spam", got)
	}
	if sink.count() != 1 {
		t.Fatalf("sink nhận %d lần, muốn 1", sink.count())
	}
	sink.mu.Lock()
	raw := sink.got[0]
	sink.mu.Unlock()
	if string(raw) != string(sampleEnvelope) {
		t.Fatalf("byte tới box khác nguyên văn:\n  gửi: %s\n  nhận: %s", sampleEnvelope, raw)
	}
}

// LicenseEvery dương rất nhỏ → mỗi vòng một lần hỏi: nhịp là THAM SỐ, không
// phải hằng chôn trong code.
func TestLicenseCadenceIsConfigurable(t *testing.T) {
	f := &licenseCloud{body: sampleEnvelope}
	sink := &recordingSink{}

	rounds := 0
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	l := agent.NewLoop(agent.NewClient(srv.URL, "khoa-test", 5*time.Second), agent.Options{
		EnvID: "env-1", Version: "0.1.0",
		License: sink,
		// Mỗi lần hỏi Now đồng hồ tiến 1 giờ — vượt nhịp 30 phút ở mọi vòng.
		Now:          tickingNow(time.Hour),
		LicenseEvery: 30 * time.Minute,
		Policy:       agent.NewPolicy(rand.New(rand.NewSource(7))),
		Log:          func(string, ...any) {},
		Sleep: func(_ context.Context, _ time.Duration) {
			rounds++
			if rounds >= 4 {
				cancel()
			}
		},
	})
	_ = l.Run(ctx)

	f.mu.Lock()
	syncs := f.syncs
	f.mu.Unlock()
	if got := f.count(); got < 3 {
		t.Fatalf("license chỉ được hỏi %d lần trong %d vòng sync với nhịp 30 phút và đồng hồ tiến 1h/lần hỏi", got, syncs)
	}
}

// Cloud không phát license (503, bản self-hosted) là trạng thái THIẾT KẾ:
// không log, không đưa gì cho box.
func TestACloudWithoutASignerStaysQuiet(t *testing.T) {
	f := &licenseCloud{status: http.StatusServiceUnavailable}
	sink := &recordingSink{}

	rounds := 0
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	var logs []string
	var mu sync.Mutex
	l := agent.NewLoop(agent.NewClient(srv.URL, "khoa-test", 5*time.Second), agent.Options{
		EnvID: "env-1", Version: "0.1.0",
		License: sink,
		Policy:  agent.NewPolicy(rand.New(rand.NewSource(7))),
		Log: func(format string, args ...any) {
			mu.Lock()
			logs = append(logs, fmt.Sprintf(format, args...))
			mu.Unlock()
		},
		Sleep: func(_ context.Context, _ time.Duration) {
			rounds++
			if rounds >= 3 {
				cancel()
			}
		},
	})
	_ = l.Run(ctx)

	if sink.count() != 0 {
		t.Fatalf("box nhận %d license từ một cloud không phát license", sink.count())
	}
	mu.Lock()
	defer mu.Unlock()
	for _, line := range logs {
		t.Errorf("log thừa cho một trạng thái thiết kế: %s", line)
	}
}

// Client.License — phân loại phản hồi thành lỗi ĐÚNG loại.
func TestClientLicenseClassifiesResponses(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		want   error
	}{
		"503 → không phát license": {http.StatusServiceUnavailable, agent.ErrNoLicenseSigner},
		"401 → khoá bị thu hồi":    {http.StatusUnauthorized, agent.ErrUnauthorized},
		"429 → rate limit":         {http.StatusTooManyRequests, agent.ErrRateLimited},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(srv.Close)
			_, err := agent.NewClient(srv.URL, "k", time.Second).License(context.Background())
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, muốn %v", err, tc.want)
			}
		})
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer khoa-that" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write(sampleEnvelope)
	}))
	t.Cleanup(srv.Close)
	raw, err := agent.NewClient(srv.URL, "khoa-that", time.Second).License(context.Background())
	if err != nil || string(raw) != string(sampleEnvelope) {
		t.Fatalf("raw=%s err=%v — byte phải về nguyên văn và kèm Bearer", raw, err)
	}
}

// NodeClient.InstallLicense — lý do từ chối của box đi NGUYÊN VĂN vào lỗi.
func TestNodeClientCarriesTheBoxRefusalVerbatim(t *testing.T) {
	var got []byte
	box := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/node/v1/license" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		got, _ = io.ReadAll(r.Body)
		if string(got) == "rác" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"license: chữ ký không hợp lệ"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"installed"}`))
	}))
	t.Cleanup(box.Close)

	nc := agent.NewNodeClient(box.URL, time.Second)
	if err := nc.InstallLicense(context.Background(), sampleEnvelope); err != nil {
		t.Fatalf("giao license hợp lệ: %v", err)
	}
	if string(got) != string(sampleEnvelope) {
		t.Fatalf("box nhận byte khác nguyên văn: %s", got)
	}
	err := nc.InstallLicense(context.Background(), []byte("rác"))
	if err == nil || !strings.Contains(err.Error(), "chữ ký không hợp lệ") {
		t.Fatalf("lỗi không mang lý do của box: %v", err)
	}
}
