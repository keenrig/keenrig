package agent_test

// Test executor của agent — nửa phía INSTANCE của CON-13/CON-14.
//
// Lỗi đo được ngoài đời (TC-UI-01 bước 10): mọi lệnh từ Console đều về
// `failed` kèm *"this agent has no executor wired up for command kind …"* —
// agent nhận lệnh nhưng không có gì để thực thi nó. Test dưới đây canh đúng
// hai điều làm câu đó biến mất: kind biết làm thì LÀM, kind chưa biết thì
// thất bại KÈM TÊN nó.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/agent"
)

type ticketSink struct {
	mu      sync.Mutex
	hash    string
	expires time.Time
	calls   int
	err     error
}

func (s *ticketSink) AcceptAdminTicket(_ context.Context, hash string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.hash, s.expires = hash, expiresAt
	return s.err
}

const testHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func mintCommand(t *testing.T, expiresAt string) agent.Command {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"token_hash": testHash})
	if err != nil {
		t.Fatal(err)
	}
	return agent.Command{
		ID: "cmd-1", Kind: contracts.CommandKindMintAdminToken,
		Payload: payload, ExpiresAt: expiresAt,
	}
}

func TestExecMintsAdminTokenThroughTheNodeAPI(t *testing.T) {
	sink := &ticketSink{}
	exp := time.Now().Add(9 * time.Minute).UTC().Truncate(time.Second)

	if err := agent.NewExec(sink).Execute(t.Context(), mintCommand(t, exp.Format(time.RFC3339))); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if sink.calls != 1 {
		t.Fatalf("node API được gọi %d lần, muốn 1", sink.calls)
	}
	if sink.hash != testHash {
		t.Errorf("hash giao cho box = %q, muốn %q", sink.hash, testHash)
	}
	// Hạn phải là hạn của HÀNG LỆNH, không phải một con số agent tự đặt: hai
	// sự thật về hạn của một bí mật thì cái rộng hơn luôn thắng.
	if !sink.expires.Equal(exp) {
		t.Errorf("hạn giao cho box = %s, muốn %s (hạn của chính lệnh)", sink.expires, exp)
	}
}

// Kind chưa hiện thực phải nói TÊN nó ra — đó là toàn bộ giá trị của CON-14.
func TestExecNamesTheKindItCannotRun(t *testing.T) {
	err := agent.NewExec(&ticketSink{}).Execute(t.Context(),
		agent.Command{ID: "cmd-2", Kind: contracts.CommandKindResizePlan, Payload: json.RawMessage(`{}`)})
	if err == nil {
		t.Fatal("kind chưa hiện thực mà Execute trả nil — lệnh sẽ báo THÀNH CÔNG cho việc không ai làm")
	}
	if !strings.Contains(err.Error(), contracts.CommandKindResizePlan) {
		t.Errorf("lý do %q không nhắc tên kind — người dùng đọc câu này trên Console", err)
	}
}

func TestExecRefusesAMintCommandWithoutHash(t *testing.T) {
	sink := &ticketSink{}
	err := agent.NewExec(sink).Execute(t.Context(), agent.Command{
		ID: "cmd-3", Kind: contracts.CommandKindMintAdminToken, Payload: json.RawMessage(`{}`),
	})
	if err == nil {
		t.Fatal("payload không có token_hash mà vẫn OK — Console sẽ báo đã cấp phiên cho một vé không tồn tại")
	}
	if sink.calls != 0 {
		t.Errorf("đã gọi node API %d lần với payload rỗng", sink.calls)
	}
}

// Box chưa lên là ca HỢP LỆ (ND-06): lệnh thất bại kèm lý do, agent sống tiếp.
func TestExecReportsTheBoxRefusal(t *testing.T) {
	box := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte(`{"error":"this instance has no login enabled"}`))
	}))
	defer box.Close()

	err := agent.NewExec(agent.NewNodeClient(box.URL, time.Second)).
		Execute(t.Context(), mintCommand(t, ""))
	if err == nil {
		t.Fatal("box từ chối mà Execute trả nil")
	}
	if !strings.Contains(err.Error(), "no login enabled") {
		t.Errorf("lý do của box không đi tiếp lên Console: %v", err)
	}
}

// NodeClient nói đúng hợp đồng node.yaml: POST /node/v1/admin-tickets, thân
// mang token_hash. Một lần đổi path ở đây là một nút "Mở Admin ↗" chết.
func TestNodeClientPostsTheTicketWhereTheContractSaysToo(t *testing.T) {
	var (
		gotPath string
		gotBody map[string]string
	)
	box := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.Method + " " + r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer box.Close()

	exp := time.Now().Add(time.Minute).UTC().Truncate(time.Second)
	if err := agent.NewNodeClient(box.URL, time.Second).
		AcceptAdminTicket(t.Context(), testHash, exp); err != nil {
		t.Fatalf("AcceptAdminTicket: %v", err)
	}
	if gotPath != "POST /node/v1/admin-tickets" {
		t.Errorf("gọi %q, hợp đồng node.yaml nói POST /node/v1/admin-tickets", gotPath)
	}
	if gotBody["token_hash"] != testHash {
		t.Errorf("thân request = %v, thiếu token_hash", gotBody)
	}
	if gotBody["expires_at"] != exp.Format(time.RFC3339) {
		t.Errorf("expires_at = %q, muốn %q", gotBody["expires_at"], exp.Format(time.RFC3339))
	}
}

// CON-09 nửa phía instance: `app.install` từ Console phải tới được box, đúng
// path hợp đồng, mang đúng id catalog + slug + FQDN do CLOUD ghép. Trước bản vá
// lệnh này rơi vào default và Console hiện "does not implement … app.install".
func TestExecInstallsAppThroughTheNodeAPI(t *testing.T) {
	var (
		gotPath string
		gotBody struct {
			CatalogID string   `json:"catalog_id"`
			Slug      string   `json:"slug"`
			Domains   []string `json:"domains"`
		}
	)
	box := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.Method + " " + r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
	}))
	defer box.Close()

	err := agent.NewExec(agent.NewNodeClient(box.URL, time.Second)).Execute(t.Context(), agent.Command{
		ID:      "c-1",
		Kind:    contracts.CommandKindAppInstall,
		Payload: json.RawMessage(`{"app_id":"whoami","subdomain":"whoami","fqdn":"whoami.case1.iot.keenrig.com"}`),
	})
	if err != nil {
		t.Fatalf("app.install: %v", err)
	}
	if gotPath != "POST /node/v1/apps/install" {
		t.Errorf("gọi %q, muốn POST /node/v1/apps/install", gotPath)
	}
	if gotBody.CatalogID != "whoami" || gotBody.Slug != "whoami" ||
		len(gotBody.Domains) != 1 || gotBody.Domains[0] != "whoami.case1.iot.keenrig.com" {
		t.Errorf("thân lệnh cài sai: %+v", gotBody)
	}
}

// Box từ chối (quota, license…) → lệnh failed KÈM lý do nguyên văn của box.
func TestExecInstallCarriesTheBoxReason(t *testing.T) {
	box := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"app quota reached: 1 of 1"}`))
	}))
	defer box.Close()

	err := agent.NewExec(agent.NewNodeClient(box.URL, time.Second)).Execute(t.Context(), agent.Command{
		ID: "c-2", Kind: contracts.CommandKindAppInstall,
		Payload: json.RawMessage(`{"app_id":"nginx","subdomain":"web","fqdn":"web.x.iot.keenrig.com"}`),
	})
	if err == nil || !strings.Contains(err.Error(), "app quota reached") {
		t.Fatalf("muốn lỗi mang lý do của box, được %v", err)
	}
}

// Payload thiếu app_id bị chặn TRƯỚC khi chạm box.
func TestExecInstallRejectsEmptyAppID(t *testing.T) {
	called := false
	box := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true }))
	defer box.Close()
	err := agent.NewExec(agent.NewNodeClient(box.URL, time.Second)).Execute(t.Context(), agent.Command{
		ID: "c-3", Kind: contracts.CommandKindAppInstall, Payload: json.RawMessage(`{"subdomain":"web"}`),
	})
	if err == nil || called {
		t.Fatalf("payload không có app_id: err=%v, box called=%v", err, called)
	}
}
