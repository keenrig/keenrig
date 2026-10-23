package api_test

// POST /_keenrig/admin-session — cửa trình duyệt trình vé "Mở Admin ↗" (CON-13).
//
// Đây là đường DUY NHẤT ngoài /auth/{setup,login} nhận được request chưa đăng
// nhập, nên mọi luật của nó đều phải có test: vé không đi trong URL, POST chứ
// không phải link, đúng một lần, và cookie phiên phải thật sự được đặt.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/api"
	"github.com/keenrig/keenrig/keenrig-node/internal/apps"
	"github.com/keenrig/keenrig/keenrig-node/internal/domains"
	"github.com/keenrig/keenrig/keenrig-node/internal/httpd"
	"github.com/keenrig/keenrig/keenrig-node/internal/identity"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

func sha256Hex(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// newHandoffServer dựng đúng hai thứ cửa này cần: một api.Server có identity,
// và (tuỳ ca) một chủ instance để phiên có chỗ mà mở.
func newHandoffServer(t *testing.T, withOwner bool) (*httptest.Server, *identity.Service, store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	ident := identity.New(st, identity.Options{})
	if withOwner {
		if _, err := ident.CreateOwner(t.Context(), "alice", "mật-khẩu-đủ-dài-12"); err != nil {
			t.Fatalf("CreateOwner: %v", err)
		}
	}
	srv := api.New(apps.New(st, domains.New(st), apps.Options{}), st, ident, api.WithIdentity(ident))
	ts := httptest.NewServer(srv.AdminSessionHandler())
	t.Cleanup(ts.Close)
	return ts, ident, st
}

// postForm gửi vé đúng cách trình duyệt gửi: form POST, Accept text/html, và
// KHÔNG đi theo redirect (để đọc được Set-Cookie của chính lần trả lời này).
func postForm(t *testing.T, ts *httptest.Server, ticket string) *http.Response {
	t.Helper()
	body := url.Values{api.AdminSessionField: {ticket}}.Encode()
	req, err := http.NewRequest("POST", ts.URL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	c := ts.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

func TestHandoffTurnsATicketIntoASessionCookie(t *testing.T) {
	ts, ident, st := newHandoffServer(t, true)
	const ticket = "vé-từ-console"
	if err := ident.AcceptAdminTicket(sha256Hex(ticket), time.Time{}); err != nil {
		t.Fatal(err)
	}

	res := postForm(t, ts, ticket)
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("= %d, muốn 303 — trình duyệt phải được đưa sang GET, không lặp lại POST kèm vé đã tiêu",
			res.StatusCode)
	}
	var session string
	for _, c := range res.Cookies() {
		if strings.Contains(c.Name, "keenrig_session") {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("không có cookie phiên — người dùng rơi thẳng vào màn đăng nhập, đúng thứ CON-13 muốn tránh")
	}
	// Cookie phải là một phiên THẬT trong store, không phải một chuỗi trang trí.
	if _, err := st.GetSession(t.Context(), sha256Hex(session)); err != nil {
		t.Errorf("cookie không tra được trong store: %v", err)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q — một lần chuyển tay có bí mật không được nằm lại trong cache",
			res.Header.Get("Cache-Control"))
	}

	// MỘT LẦN: vé thứ hai chết, và câu trả lời không nói nó từng tồn tại.
	again := postForm(t, ts, ticket)
	if again.StatusCode != http.StatusUnauthorized {
		t.Errorf("đổi lại lần hai = %d, muốn 401 — một vé mở được hai phiên", again.StatusCode)
	}
}

// Vé trong URL bị TỪ CHỐI, không phải im lặng chấp nhận: query string nằm lại
// trong access log của mọi proxy trên đường đi và trong header Referer kế tiếp.
func TestHandoffRefusesATicketInTheURL(t *testing.T) {
	ts, ident, _ := newHandoffServer(t, true)
	const ticket = "vé-trong-url"
	if err := ident.AcceptAdminTicket(sha256Hex(ticket), time.Time{}); err != nil {
		t.Fatal(err)
	}

	for _, k := range []string{api.AdminSessionField, "ticket", "token", "t"} {
		res, err := ts.Client().Post(ts.URL+"?"+k+"="+url.QueryEscape(ticket),
			"application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("?%s=… = %d, muốn 400", k, res.StatusCode)
		}
	}
	// Và vé vẫn còn nguyên: một request viết sai không được tiêu mất vé của
	// người dùng.
	if n := ident.PendingAdminTickets(); n != 1 {
		t.Errorf("còn %d vé sau mấy lần gọi sai, muốn 1", n)
	}
}

// GET phải trả JSON nói rõ luật, KHÔNG được rơi xuống SPA hay 404 trần: người
// dùng bấm nhầm một link phải đọc được vì sao nó không chạy.
func TestHandoffIsNotALink(t *testing.T) {
	ts, _, _ := newHandoffServer(t, true)
	res, err := ts.Client().Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, muốn 405", res.StatusCode)
	}
	if res.Header.Get("Allow") != "POST" {
		t.Errorf("Allow = %q, muốn POST", res.Header.Get("Allow"))
	}
}

// Client không phải trình duyệt: JSON vào, JSON ra (token trong thân, như
// /auth/login) — không có redirect nào để một script phải đoán.
func TestHandoffAnswersScriptsWithJSON(t *testing.T) {
	ts, ident, _ := newHandoffServer(t, true)
	const ticket = "vé-cho-script"
	if err := ident.AcceptAdminTicket(sha256Hex(ticket), time.Time{}); err != nil {
		t.Fatal(err)
	}
	res, err := ts.Client().Post(ts.URL, "application/json",
		strings.NewReader(`{"ticket":"`+ticket+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("= %d, muốn 200", res.StatusCode)
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil || body.Token == "" {
		t.Fatalf("thân không mang token: %v", err)
	}
}

// Hai hằng số, hai package, MỘT đường — và một đường thứ ba nằm ở cloud
// (`consoleapi/wizard.go` in ra `handoff.url`). httpd không import api được
// (Luật 9 giữ chiều phụ thuộc), nên bản sao là cái giá; test này là thứ làm nó
// không trôi. Chuỗi trần ở đây có chủ đích: nó phải khớp CHỮ mà cloud in ra.
func TestAdminSessionPathIsTheSameEverywhere(t *testing.T) {
	const contract = "/_keenrig/admin-session"
	if api.AdminSessionPath != contract {
		t.Errorf("api.AdminSessionPath = %q, hợp đồng với Console là %q", api.AdminSessionPath, contract)
	}
	if httpd.AdminSessionPath != contract {
		t.Errorf("httpd.AdminSessionPath = %q, hợp đồng với Console là %q", httpd.AdminSessionPath, contract)
	}
	if api.AdminSessionField != "keenrig_admin_ticket" {
		t.Errorf("tên trường = %q — Console gửi keenrig_admin_ticket", api.AdminSessionField)
	}
}

// Chưa thiết lập instance — người dùng mở Admin LẦN ĐẦU từ Console.
//
// Trình duyệt: 303 về `/`, nơi Admin UI vẽ form tạo chủ. Trước đây nhánh này
// ném JSON 409 vào trang và người dùng kẹt lại (đo trên VPS thật 2026-10-02):
// mã setup chỉ nằm trong journalctl, không ai đi từ Console nhìn thấy nó.
// KHÔNG có cookie phiên: chưa có chủ thì chưa có ai để mở phiên cho.
//
// Script: vẫn 409 kèm câu nói ra thứ CÒN THIẾU là bước tạo chủ.
func TestHandoffSaysWhenThereIsNoOwnerYet(t *testing.T) {
	ts, ident, _ := newHandoffServer(t, false)
	const ticket = "vé-vào-máy-trống"
	if err := ident.AcceptAdminTicket(sha256Hex(ticket), time.Time{}); err != nil {
		t.Fatal(err)
	}
	res := postForm(t, ts, ticket)
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/" {
		t.Fatalf("trình duyệt = %d → %q, muốn 303 → / (màn tạo chủ)", res.StatusCode, res.Header.Get("Location"))
	}
	for _, c := range res.Cookies() {
		if strings.Contains(c.Name, "keenrig_session") && c.Value != "" {
			t.Errorf("mở phiên trên máy chưa có chủ: cookie %s", c.Name)
		}
	}

	const ticket2 = "vé-thứ-hai"
	if err := ident.AcceptAdminTicket(sha256Hex(ticket2), time.Time{}); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", ts.URL, strings.NewReader(`{"`+api.AdminSessionField+`":"`+ticket2+`"}`))
	req.Header.Set("Content-Type", "application/json")
	jr, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer jr.Body.Close()
	if jr.StatusCode != http.StatusConflict {
		t.Fatalf("script = %d, muốn 409", jr.StatusCode)
	}
}
