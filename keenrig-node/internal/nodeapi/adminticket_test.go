package nodeapi_test

// POST /node/v1/admin-tickets — cửa agent giao vé "Mở Admin ↗" cho box (CON-13).

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/metrics"
	"github.com/keenrig/keenrig/keenrig-node/internal/nodeapi"
)

type fakeTickets struct {
	mu      sync.Mutex
	hash    string
	expires time.Time
	calls   int
	err     error
}

func (f *fakeTickets) AcceptAdminTicket(hash string, expiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.hash, f.expires = hash, expiresAt
	return f.err
}

func ticketServer(t *testing.T, tk nodeapi.AdminTickets) *httptest.Server {
	t.Helper()
	h := nodeapi.New(nodeapi.Options{
		AdminTickets: tk,
		Version:      nodeapi.Version{Process: "keenrig-box", Version: "0.0.1-test"},
		Metrics:      metrics.NewRegistry(),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

const ticketHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestAdminTicketRouteHandsTheHashToIdentity(t *testing.T) {
	tk := &fakeTickets{}
	srv := ticketServer(t, tk)
	exp := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)

	code, body := req(t, srv, "POST", "/node/v1/admin-tickets", map[string]string{
		"token_hash": ticketHash,
		"expires_at": exp.Format(time.RFC3339),
	}, nil)
	if code != 202 {
		t.Fatalf("POST admin-tickets = %d (%s), muốn 202", code, body)
	}
	if tk.calls != 1 || tk.hash != ticketHash {
		t.Fatalf("identity nhận %d lần, hash %q", tk.calls, tk.hash)
	}
	if !tk.expires.Equal(exp) {
		t.Errorf("hạn = %s, muốn %s", tk.expires, exp)
	}
}

// Chưa bật đăng nhập: 501 KÈM LÝ DO, không phải 200. Nhận vé rồi vứt đi sẽ làm
// Console báo "đã cấp phiên" cho một phiên không bao giờ mở được.
func TestAdminTicketRouteSaysWhenLoginIsOff(t *testing.T) {
	srv := ticketServer(t, nil)
	code, body := req(t, srv, "POST", "/node/v1/admin-tickets",
		map[string]string{"token_hash": ticketHash}, nil)
	if code != 501 {
		t.Fatalf("không có identity mà = %d (%s), muốn 501", code, body)
	}
	if !strings.Contains(string(body), "login") {
		t.Errorf("lý do %q không nói ra thứ còn thiếu", body)
	}
}

// Lý do từ chối phải đi NGUYÊN VĂN ra ngoài: nó là thứ duy nhất người dùng đọc
// được trên Console khi lệnh về failed (CON-14).
func TestAdminTicketRouteForwardsTheReason(t *testing.T) {
	tk := &fakeTickets{err: context.DeadlineExceeded}
	srv := ticketServer(t, tk)
	code, body := req(t, srv, "POST", "/node/v1/admin-tickets",
		map[string]string{"token_hash": ticketHash}, nil)
	if code != 400 {
		t.Fatalf("= %d, muốn 400", code)
	}
	if !strings.Contains(string(body), context.DeadlineExceeded.Error()) {
		t.Errorf("thân %q nuốt mất lý do của identity", body)
	}
}

// Hạn lệch định dạng KHÔNG được biến thành một nút bấm hỏng: bên nhận tự kẹp
// về trần 10 phút của mình, nên vé vẫn hợp lệ.
func TestAdminTicketRouteToleratesABadExpiry(t *testing.T) {
	tk := &fakeTickets{}
	srv := ticketServer(t, tk)
	code, body := req(t, srv, "POST", "/node/v1/admin-tickets", map[string]string{
		"token_hash": ticketHash, "expires_at": "hôm-nào-đó",
	}, nil)
	if code != 202 {
		t.Fatalf("= %d (%s), muốn 202", code, body)
	}
	if !tk.expires.IsZero() {
		t.Errorf("hạn không đọc được mà thành %s — muốn để bên nhận tự kẹp", tk.expires)
	}
}
