package nodeapi_test

// Test T9b — node API. Gate: ND-01 (shape app_statuses), ND-02 (log là stream,
// không endpoint nào trả đường dẫn file), ND-03 (Idempotency-Key), drain/resume.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/instance"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/metrics"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/nodeapi"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

type fakeLifecycle struct {
	mu       sync.Mutex
	inFlight int
	drains   int
	resumes  int
	err      error
}

func (f *fakeLifecycle) Drain(context.Context, time.Duration) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.drains++
	return f.inFlight, f.err
}

func (f *fakeLifecycle) Resume() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resumes++
}

func newServer(t *testing.T, lc nodeapi.Lifecycle) (*httptest.Server, store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	reg := metrics.NewRegistry()
	reg.SetProcessInfo("keenrig-box", "0.0.1-test")
	h := nodeapi.New(nodeapi.Options{
		Store:     st,
		Lifecycle: lc,
		Version:   nodeapi.Version{Process: "keenrig-box", Version: "0.0.1-test"},
		Metrics:   reg,
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, st
}

func req(t *testing.T, srv *httptest.Server, method, path string, body any, headers map[string]string) (int, []byte) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	r, err := http.NewRequest(method, srv.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, buf.Bytes()
}

// Luật 7 — 3 endpoint bắt buộc, và phơi ở CẢ hai chỗ (gốc cho systemd/probe,
// dưới prefix cho client theo hợp đồng).
func TestHealthEndpointsBothPaths(t *testing.T) {
	srv, _ := newServer(t, nil)
	for _, p := range []string{"/healthz", "/readyz", "/metrics", "/version",
		"/node/v1/healthz", "/node/v1/readyz", "/node/v1/metrics", "/node/v1/version"} {
		if code, body := req(t, srv, "GET", p, nil, nil); code != http.StatusOK {
			t.Errorf("GET %s = %d: %s", p, code, body)
		}
	}
}

// /healthz KHÔNG được phụ thuộc store: store hỏng thì systemd sẽ giết tiến
// trình, mà giết đi cũng không sửa được store — chỉ mất luôn node API và mất
// đường chẩn đoán. /readyz mới là chỗ chạm store.
func TestHealthzIndependentOfStore(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	h := nodeapi.New(nodeapi.Options{Store: st, Version: nodeapi.Version{Process: "box"}})
	srv := httptest.NewServer(h)
	defer srv.Close()

	st.Close() // store chết

	if code, _ := req(t, srv, "GET", "/healthz", nil, nil); code != http.StatusOK {
		t.Errorf("healthz = %d khi store chết, muốn vẫn 200", code)
	}
	if code, _ := req(t, srv, "GET", "/readyz", nil, nil); code != http.StatusServiceUnavailable {
		t.Errorf("readyz = %d khi store chết, muốn 503", code)
	}
}

// ND-01 — shape app_statuses khớp sync.schema.json#/$defs/AppStatus.
func TestListAppsShape(t *testing.T) {
	srv, st := newServer(t, nil)
	ctx := context.Background()

	app := &store.App{ID: "app-1", Slug: "hello", Desired: json.RawMessage(`{"image":"nginx:1"}`)}
	if err := st.CreateApp(ctx, app); err != nil {
		t.Fatal(err)
	}

	code, body := req(t, srv, "GET", "/node/v1/apps", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("= %d: %s", code, body)
	}
	var got []map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	// App chưa reconcile vẫn phải xuất hiện: bỏ qua sẽ làm app mới tạo biến mất
	// khỏi báo cáo lên cloud cho tới lần reconcile đầu tiên.
	if len(got) != 1 {
		t.Fatalf("= %v, muốn 1 app kể cả khi chưa có status", got)
	}
	for _, f := range []string{"app_id", "state"} {
		if _, ok := got[0][f]; !ok {
			t.Errorf("thiếu trường bắt buộc %q của AppStatus: %v", f, got[0])
		}
	}

	// Sau khi có status thật thì trả nguyên status đó.
	if err := st.SetStatus(ctx, "app-1", json.RawMessage(`{"app_id":"app-1","state":"running","health":"healthy"}`), 1); err != nil {
		t.Fatal(err)
	}
	_, body = req(t, srv, "GET", "/node/v1/apps", nil, nil)
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got[0]["state"] != "running" || got[0]["health"] != "healthy" {
		t.Errorf("status = %v", got[0])
	}
}

// ND-02 — log là STREAM qua HTTP. Chưa nối thì 501; TUYỆT ĐỐI không trả đường
// dẫn file, vì trả path là khoá cứng agent vào cùng máy với box vĩnh viễn.
func TestLogsNeverReturnFilePath(t *testing.T) {
	srv, _ := newServer(t, nil)
	code, body := req(t, srv, "GET", "/node/v1/apps/app-1/logs", nil, nil)
	if code != http.StatusNotImplemented {
		t.Errorf("= %d, muốn 501 khi chưa nối streamer", code)
	}
	for _, bad := range []string{"/var/lib/keenrig", "node", ".log", `C:\`} {
		if strings.Contains(string(body), bad) {
			t.Errorf("body có vẻ trả đường dẫn file (%q): %s", bad, body)
		}
	}
}

// ND-03 — Idempotency-Key trùng → 409 và KHÔNG sinh event thứ hai.
func TestAppendEventIdempotency(t *testing.T) {
	srv, st := newServer(t, nil)
	ctx := context.Background()
	ev := map[string]any{"action": "ota.update_started", "actor": "keenrig-ota"}
	hdr := map[string]string{"Idempotency-Key": "11111111-1111-1111-1111-111111111111"}

	if code, body := req(t, srv, "POST", "/node/v1/events", ev, hdr); code != http.StatusAccepted {
		t.Fatalf("lần 1 = %d: %s", code, body)
	}
	if code, _ := req(t, srv, "POST", "/node/v1/events", ev, hdr); code != http.StatusConflict {
		t.Errorf("lần 2 cùng key = %d, muốn 409", code)
	}

	evs, err := st.ListEvents(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range evs {
		if e.Action == "ota.update_started" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("có %d event, muốn đúng 1 — retry không được sinh bản trùng", n)
	}

	// Key khác → event mới.
	hdr2 := map[string]string{"Idempotency-Key": "22222222-2222-2222-2222-222222222222"}
	if code, _ := req(t, srv, "POST", "/node/v1/events", ev, hdr2); code != http.StatusAccepted {
		t.Errorf("key khác phải ghi được")
	}
	// Thiếu key → 400. Key là BẮT BUỘC vì client sẽ retry.
	if code, _ := req(t, srv, "POST", "/node/v1/events", ev, nil); code != http.StatusBadRequest {
		t.Errorf("thiếu Idempotency-Key phải 400")
	}
	// Thiếu action/actor → 400.
	if code, _ := req(t, srv, "POST", "/node/v1/events", map[string]any{"action": "x"},
		map[string]string{"Idempotency-Key": "33333333-3333-3333-3333-333333333333"}); code != http.StatusBadRequest {
		t.Errorf("thiếu actor phải 400")
	}
}

// Drain sạch → 200; còn việc dở → 503 (ota PHẢI huỷ update).
func TestDrainResume(t *testing.T) {
	lc := &fakeLifecycle{}
	srv, _ := newServer(t, lc)

	code, body := req(t, srv, "POST", "/node/v1/drain", map[string]any{"timeout_s": 5}, nil)
	if code != http.StatusOK {
		t.Fatalf("drain sạch = %d: %s", code, body)
	}
	var okBody struct {
		InFlight int `json:"in_flight"`
	}
	if err := json.Unmarshal(body, &okBody); err != nil || okBody.InFlight != 0 {
		t.Errorf("body = %s", body)
	}

	lc.inFlight = 2
	code, body = req(t, srv, "POST", "/node/v1/drain", nil, nil)
	if code != http.StatusServiceUnavailable {
		t.Errorf("còn việc dở = %d, muốn 503 — 200 sẽ mời ota thay bin giữa một lần deploy", code)
	}
	if !strings.Contains(string(body), "in_flight") {
		t.Errorf("503 không nói còn bao nhiêu việc: %s", body)
	}

	if code, _ := req(t, srv, "POST", "/node/v1/resume", nil, nil); code != http.StatusOK {
		t.Errorf("resume = %d", code)
	}
	if lc.resumes != 1 {
		t.Errorf("Resume gọi %d lần", lc.resumes)
	}
}

// Không có vòng lặp nào để drain (box chạy --reconcile=false) → 503 rõ ràng,
// không phải 200 giả vờ đã drain.
func TestDrainWithoutLifecycle(t *testing.T) {
	srv, _ := newServer(t, nil)
	if code, _ := req(t, srv, "POST", "/node/v1/drain", nil, nil); code != http.StatusServiceUnavailable {
		t.Errorf("= %d, muốn 503", code)
	}
}

// /metrics phải parse được: có # HELP/# TYPE, không lặp TYPE cho cùng tên.
func TestMetricsFormat(t *testing.T) {
	srv, _ := newServer(t, nil)
	code, body := req(t, srv, "GET", "/metrics", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("= %d", code)
	}
	text := string(body)
	if !strings.Contains(text, "keenrig_build_info") || !strings.Contains(text, "keenrig_uptime_seconds") {
		t.Errorf("thiếu metric bắt buộc:\n%s", text)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "# TYPE ") {
			continue
		}
		name := strings.Fields(line)[2]
		if seen[name] {
			t.Errorf("# TYPE lặp cho %q — Prometheus sẽ từ chối cả trang", name)
		}
		seen[name] = true
	}
}

// Method sai không được rơi vào handler khác (ServeMux của Go 1.22+ khớp cả
// method, nhưng ta khẳng định điều đó chứ không giả định).
func TestMethodMismatch(t *testing.T) {
	srv, _ := newServer(t, &fakeLifecycle{})
	if code, _ := req(t, srv, "POST", "/node/v1/apps", nil, nil); code == http.StatusOK {
		t.Error("POST /apps trả 200 — route chỉ nhận GET")
	}
	if code, _ := req(t, srv, "GET", "/node/v1/drain", nil, nil); code == http.StatusOK {
		t.Error("GET /drain trả 200 — route chỉ nhận POST")
	}
}

// Lỗi từ Lifecycle.Drain phải thành 503, không phải 200.
func TestDrainError(t *testing.T) {
	lc := &fakeLifecycle{err: errors.New("ctx huỷ")}
	srv, _ := newServer(t, lc)
	if code, _ := req(t, srv, "POST", "/node/v1/drain", nil, nil); code != http.StatusServiceUnavailable {
		t.Errorf("= %d, muốn 503", code)
	}
}

// ND-01 — hình dạng `/node/v1/apps` khớp `sync.schema.json`, và khớp theo nghĩa
// AGENT KHÔNG PHẢI MAP LẠI.
//
// # Vì sao không kiểm tên trường, mà nhét thẳng vào một SyncRequest
//
// Bản trước của test này (`TestListAppsShape`) kiểm sự CÓ MẶT của hai tên
// trường. Nó xanh kể cả khi `state` mang một giá trị ngoài enum, kể cả khi
// `desired_rev` là chuỗi thay vì số, kể cả khi có thêm một trường mà schema
// không biết. Ba thứ đó đều làm agent hỏng ở phía kia — và không cái nào đỏ ở
// đây.
//
// Cái gate thật sự đòi là *"agent không phải map lại"*. Cách chứng minh đúng
// nghĩa đen của câu đó: lấy phản hồi, nhét NGUYÊN VẸN vào `app_statuses` của
// một SyncRequest, rồi chạy CHÍNH bộ validator của contracts lên nó. Qua được
// tức là agent chuyển tiếp thẳng lên cloud mà không phải đụng vào.
func TestListAppsIsDirectlyUsableAsSyncPayload(t *testing.T) {
	srv, st := newServer(t, nil)
	ctx := context.Background()

	// Hai app: một chưa reconcile lần nào, một đã có status thật. Cả hai đều
	// phải đi thẳng lên cloud được.
	for _, a := range []*store.App{
		{ID: "app-1", Slug: "hello", Desired: json.RawMessage(`{"image":"nginx:1"}`)},
		{ID: "app-2", Slug: "shop", Desired: json.RawMessage(`{"image":"ghost:5"}`)},
	} {
		if err := st.CreateApp(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SetStatus(ctx, "app-2",
		json.RawMessage(`{"app_id":"app-2","slug":"shop","state":"running","health":"healthy","applied_rev":3}`), 1); err != nil {
		t.Fatal(err)
	}

	code, body := req(t, srv, "GET", "/node/v1/apps", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("= %d: %s", code, body)
	}

	// Nhét NGUYÊN VẸN vào một SyncRequest tối thiểu hợp lệ.
	payload := []byte(`{
		"env_id": "env-1",
		"version": "0.1.0",
		"heartbeat": {"ts": "2026-08-14T00:00:00Z"},
		"app_statuses": ` + string(body) + `
	}`)
	if err := contracts.ValidateSyncRequest(payload); err != nil {
		t.Fatalf("phản hồi /node/v1/apps KHÔNG dùng thẳng được làm app_statuses:\n%v\n\n%s",
			err, body)
	}
}

// --- PUT /parent-domain: tên miền gốc do cloud cấp đi vào box qua đây, và CHỈ qua đây ---

// recordingDomainSink ghi lại từng lần giao — kiểm route mà không cần store.
type recordingDomainSink struct {
	mu    sync.Mutex
	calls [][2]string
}

func (s *recordingDomainSink) SetParentDomain(_ context.Context, parent, mode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, [2]string{parent, mode})
	return nil
}

func newServerWithDomain(t *testing.T, sink nodeapi.ParentDomainSink) *httptest.Server {
	t.Helper()
	h := nodeapi.New(nodeapi.Options{
		Domain:  sink,
		Version: nodeapi.Version{Process: "keenrig-box", Version: "0.0.1-test"},
		Metrics: metrics.NewRegistry(),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// Chưa cắm sink → 501 kèm lý do, KHÔNG phải 200: nhận rồi vứt đi làm agent nhớ
// "đã giao" và không bao giờ gửi lại.
func TestParentDomainNotWiredIs501(t *testing.T) {
	srv, _ := newServer(t, nil)
	code, body := req(t, srv, "PUT", "/node/v1/parent-domain",
		map[string]string{"parent_domain": "demo.acme.keenrig.com", "mode": "keenrig"}, nil)
	if code != http.StatusNotImplemented {
		t.Fatalf("= %d: %s, muốn 501 khi box không nhận tên miền qua node API", code, body)
	}
	if !strings.Contains(string(body), "does not accept a parent domain") {
		t.Errorf("501 không nói lý do: %s", body)
	}
}

// Sink THẬT (internal/instance): tên hỏng bị chặn ở 400 với lý do nguyên văn,
// tên hợp lệ được cất kèm nguồn = cloud.
func TestParentDomainValidatesAndStores(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := newServerWithDomain(t, instance.New(st))

	for _, bad := range []string{"*.iot.keenrig.com", "", "a..b", "nodots"} {
		code, body := req(t, srv, "PUT", "/node/v1/parent-domain",
			map[string]string{"parent_domain": bad, "mode": "keenrig"}, nil)
		if code != http.StatusBadRequest {
			t.Errorf("parent_domain=%q → %d: %s, muốn 400", bad, code, body)
		}
		if !strings.Contains(string(body), "invalid") {
			t.Errorf("parent_domain=%q: 400 không mang lý do: %s", bad, body)
		}
	}
	// Mode ngoài enum cũng là 400: hợp đồng nói keenrig|custom.
	if code, _ := req(t, srv, "PUT", "/node/v1/parent-domain",
		map[string]string{"parent_domain": "x.example.com", "mode": "magic"}, nil); code != http.StatusBadRequest {
		t.Errorf("mode lạ → %d, muốn 400", code)
	}
	// Thân không phải JSON → 400.
	r, _ := http.NewRequest("PUT", srv.URL+"/node/v1/parent-domain", strings.NewReader("not json"))
	if resp, err := srv.Client().Do(r); err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Errorf("thân hỏng → %v/%v, muốn 400", resp, err)
	}
	// Không có gì lọt vào store sau chuỗi từ chối trên.
	if v, err := st.GetSetting(context.Background(), instance.SettingParentDomain); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("store đã có parent_domain=%q sau toàn những request bị từ chối (err=%v)", v, err)
	}

	code, body := req(t, srv, "PUT", "/node/v1/parent-domain",
		map[string]string{"parent_domain": "Demo.ACME.keenrig.com.", "mode": "keenrig"}, nil)
	if code != http.StatusOK {
		t.Fatalf("= %d: %s", code, body)
	}
	if !strings.Contains(string(body), `"stored"`) {
		t.Errorf("body = %s", body)
	}
	info, err := instance.New(st).Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Chuẩn hoá: chữ thường, bỏ dấu chấm cuối — cùng luật với FQDN của app.
	if info.ParentDomain != "demo.acme.keenrig.com" || info.Source != instance.SourceCloud || info.Mode != "keenrig" {
		t.Errorf("Info = %+v, muốn demo.acme.keenrig.com / cloud / keenrig", info)
	}
}

// Sink giả: route chuyển ĐÚNG hai trường, nguyên văn, không thêm không bớt.
func TestParentDomainRouteForwardsBothFields(t *testing.T) {
	sink := &recordingDomainSink{}
	srv := newServerWithDomain(t, sink)
	if code, body := req(t, srv, "PUT", "/node/v1/parent-domain",
		map[string]string{"parent_domain": "shop.example.com", "mode": "custom"}, nil); code != http.StatusOK {
		t.Fatalf("= %d: %s", code, body)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.calls) != 1 || sink.calls[0] != [2]string{"shop.example.com", "custom"} {
		t.Errorf("sink nhận %v, muốn [[shop.example.com custom]]", sink.calls)
	}
}

// --- PUT /cloud-link: trạng thái pair đi vào box từ AGENT, và chỉ từ agent (AD-12) ---

// cloudLinkCall — một báo cáo sink giả nhận được.
type cloudLinkCall struct {
	url, env string
	at       time.Time
}

// recordingCloudLinkSink ghi lại từng báo cáo — kiểm route mà không cần store.
type recordingCloudLinkSink struct {
	mu    sync.Mutex
	calls []cloudLinkCall
}

func (s *recordingCloudLinkSink) SetCloudLink(_ context.Context, cloudURL, envID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, cloudLinkCall{cloudURL, envID, at})
	return nil
}

func newServerWithCloudLink(t *testing.T, sink nodeapi.CloudLinkSink) *httptest.Server {
	t.Helper()
	h := nodeapi.New(nodeapi.Options{
		CloudLink: sink,
		Version:   nodeapi.Version{Process: "keenrig-box", Version: "0.0.1-test"},
		Metrics:   metrics.NewRegistry(),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// Chưa cắm sink → 501 kèm lý do, KHÔNG phải 200: nhận rồi vứt đi thì Admin UI
// vẫn "chưa pair" mà agent tưởng đã báo xong.
func TestCloudLinkNotWiredIs501(t *testing.T) {
	srv, _ := newServer(t, nil)
	code, body := req(t, srv, "PUT", "/node/v1/cloud-link",
		map[string]string{"cloud_url": "https://keenrig.com", "env_id": "env-1",
			"last_sync_at": "2026-09-19T10:00:00Z"}, nil)
	if code != http.StatusNotImplemented {
		t.Fatalf("= %d: %s, muốn 501 khi box không nhận trạng thái pair qua node API", code, body)
	}
	if !strings.Contains(string(body), "does not accept the cloud link") {
		t.Errorf("501 không nói lý do: %s", body)
	}
}

// Sink THẬT (internal/instance): thân hỏng / URL hỏng / mốc hỏng bị chặn ở 400
// với lý do nguyên văn và không chạm store; báo cáo hợp lệ được cất.
func TestCloudLinkValidatesAndStores(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := newServerWithCloudLink(t, instance.New(st))

	for name, bad := range map[string]map[string]string{
		"url không scheme":  {"cloud_url": "keenrig.com", "env_id": "env-1", "last_sync_at": "2026-09-19T10:00:00Z"},
		"url ftp":           {"cloud_url": "ftp://keenrig.com", "env_id": "env-1", "last_sync_at": "2026-09-19T10:00:00Z"},
		"env rỗng":          {"cloud_url": "https://keenrig.com", "env_id": "", "last_sync_at": "2026-09-19T10:00:00Z"},
		"mốc vắng":          {"cloud_url": "https://keenrig.com", "env_id": "env-1"},
		"mốc không RFC3339": {"cloud_url": "https://keenrig.com", "env_id": "env-1", "last_sync_at": "hôm qua"},
	} {
		code, body := req(t, srv, "PUT", "/node/v1/cloud-link", bad, nil)
		if code != http.StatusBadRequest {
			t.Errorf("%s → %d: %s, muốn 400", name, code, body)
		}
		if !strings.Contains(string(body), "error") {
			t.Errorf("%s: 400 không mang lý do: %s", name, body)
		}
	}
	r, _ := http.NewRequest("PUT", srv.URL+"/node/v1/cloud-link", strings.NewReader("not json"))
	if resp, err := srv.Client().Do(r); err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Errorf("thân hỏng → %v/%v, muốn 400", resp, err)
	}
	if v, err := st.GetSetting(context.Background(), instance.SettingCloudLinkURL); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("store đã có cloud_link_url=%q sau toàn request bị từ chối (err=%v)", v, err)
	}

	code, body := req(t, srv, "PUT", "/node/v1/cloud-link",
		map[string]string{"cloud_url": "https://keenrig.com", "env_id": "env-1",
			"last_sync_at": "2026-09-19T10:00:00Z"}, nil)
	if code != http.StatusOK {
		t.Fatalf("= %d: %s", code, body)
	}
	if !strings.Contains(string(body), `"stored"`) {
		t.Errorf("body = %s", body)
	}
	now := time.Date(2026, 9, 19, 10, 0, 30, 0, time.UTC)
	info, err := instance.New(st).CloudLink(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Paired || info.State != instance.StateSynced || info.CloudURL != "https://keenrig.com" || info.EnvID != "env-1" {
		t.Errorf("CloudLink = %+v, muốn paired/synced với https://keenrig.com / env-1", info)
	}
}

// Sink giả: route chuyển ĐÚNG ba trường, mốc đã parse, không thêm không bớt.
func TestCloudLinkRouteForwardsAllThreeFields(t *testing.T) {
	sink := &recordingCloudLinkSink{}
	srv := newServerWithCloudLink(t, sink)
	if code, body := req(t, srv, "PUT", "/node/v1/cloud-link",
		map[string]string{"cloud_url": "http://127.0.0.1:8080", "env_id": "env_01J8ZK",
			"last_sync_at": "2026-09-19T03:04:05+07:00"}, nil); code != http.StatusOK {
		t.Fatalf("= %d: %s", code, body)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	want := time.Date(2026, 9, 18, 20, 4, 5, 0, time.UTC)
	if len(sink.calls) != 1 || sink.calls[0].url != "http://127.0.0.1:8080" ||
		sink.calls[0].env != "env_01J8ZK" || !sink.calls[0].at.Equal(want) {
		t.Errorf("sink nhận %+v, muốn [http://127.0.0.1:8080 env_01J8ZK %s]", sink.calls, want)
	}
}

type fakeAppInstaller struct {
	created bool
	err     error
	got     []string
}

func (f *fakeAppInstaller) InstallCatalogApp(_ context.Context, id, slug string, domains []string) (string, bool, error) {
	f.got = append([]string{id, slug}, domains...)
	return "app-1", f.created, f.err
}

func newServerWithApps(t *testing.T, a nodeapi.AppInstaller) *httptest.Server {
	t.Helper()
	h := nodeapi.New(nodeapi.Options{Apps: a, Metrics: metrics.NewRegistry()})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// Chưa cắm installer → 501 kèm lý do: nhận rồi vứt đi làm Console báo "xong".
func TestInstallAppNotWiredIs501(t *testing.T) {
	srv, _ := newServer(t, nil)
	code, body := req(t, srv, "POST", "/node/v1/apps/install", map[string]string{"catalog_id": "whoami"}, nil)
	if code != http.StatusNotImplemented || !strings.Contains(string(body), "does not accept app installs") {
		t.Fatalf("= %d %s, muốn 501 kèm lý do", code, body)
	}
}

// 201 vừa tạo, 200 đã có (lệnh giao lại), 422 kèm lý do nguyên văn khi hỏng.
func TestInstallAppForwardsAndMapsOutcome(t *testing.T) {
	f := &fakeAppInstaller{created: true}
	srv := newServerWithApps(t, f)
	body := map[string]any{"catalog_id": "whoami", "slug": "whoami", "domains": []string{"whoami.e.iot.keenrig.com"}}

	if code, b := req(t, srv, "POST", "/node/v1/apps/install", body, nil); code != http.StatusCreated {
		t.Fatalf("tạo mới = %d %s, muốn 201", code, b)
	}
	if strings.Join(f.got, ",") != "whoami,whoami,whoami.e.iot.keenrig.com" {
		t.Errorf("installer nhận %v", f.got)
	}
	f.created = false
	if code, b := req(t, srv, "POST", "/node/v1/apps/install", body, nil); code != http.StatusOK {
		t.Fatalf("giao lại = %d %s, muốn 200", code, b)
	}
	f.err = errors.New("app quota reached")
	if code, b := req(t, srv, "POST", "/node/v1/apps/install", body, nil); code != http.StatusUnprocessableEntity ||
		!strings.Contains(string(b), "app quota reached") {
		t.Fatalf("hỏng = %d %s, muốn 422 kèm lý do", code, b)
	}
	if code, _ := req(t, srv, "POST", "/node/v1/apps/install", map[string]string{}, nil); code != http.StatusBadRequest {
		t.Fatalf("thiếu catalog_id = %d, muốn 400", code)
	}
}
