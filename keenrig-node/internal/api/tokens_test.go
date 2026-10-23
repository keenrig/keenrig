package api_test

// Test ID-04 ở tầng HTTP — vòng đời ĐẦY ĐỦ của một token qua đúng những lời gọi
// mà một script CI thật sẽ dùng: tạo → gọi API bằng nó → thu hồi → bị chặn.
//
// Các test ở internal/identity đã phủ luật nghiệp vụ. Ở đây kiểm thứ chỉ hỏng
// tại tầng ghép nối: route có được gắn không, mã trạng thái có đúng không, và
// token trần có lọt ra ở một chỗ nào KHÁC ngoài lần trả về duy nhất không.

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/api"
	"github.com/keenrig/keenrig/keenrig-node/internal/apps"
	"github.com/keenrig/keenrig/keenrig-node/internal/domains"
	"github.com/keenrig/keenrig/keenrig-node/internal/identity"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// newTokenServer dựng server với identity THẬT (không phải fakeAuth) — token
// chỉ có nghĩa khi cả đường xác thực là thật.
func newTokenServer(t *testing.T) (*httptest.Server, *identity.Service, store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	ident := identity.New(st, identity.Options{})
	if _, err := ident.CreateOwner(t.Context(), "alice", "mật-khẩu-đủ-dài-12"); err != nil {
		t.Fatalf("CreateOwner: %v", err)
	}
	h := api.New(apps.New(st, domains.New(st), apps.Options{}), st, ident, api.WithIdentity(ident))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, ident, st
}

// ownerSession đăng nhập và trả token phiên để gọi các route quản trị.
func ownerSession(t *testing.T, ident *identity.Service) string {
	t.Helper()
	tok, _, err := ident.Login(t.Context(), identity.LoginInput{
		Username: "alice", Password: "mật-khẩu-đủ-dài-12",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	return tok
}

func TestTokenAPIFullLifecycle(t *testing.T) {
	srv, ident, _ := newTokenServer(t)
	sess := ownerSession(t, ident)

	// --- tạo
	code, body := do(t, srv, "POST", "/api/v1/tokens", sess, map[string]any{
		"name": "CI deploy", "scopes": []string{"apps:read", "apps:write"},
	})
	if code != 201 {
		t.Fatalf("POST /tokens = %d: %s", code, body)
	}
	var created struct {
		Token string `json:"token"`
		Meta  struct {
			ID string `json:"id"`
		} `json:"meta"`
		Warning string `json:"warning"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.Token == "" || created.Meta.ID == "" {
		t.Fatalf("thiếu token hoặc id: %s", body)
	}
	if created.Warning == "" {
		t.Error("không cảnh báo rằng token chỉ hiện một lần — người dùng sẽ không lưu lại")
	}

	// --- dùng
	if code, body := do(t, srv, "GET", "/api/v1/apps", created.Token, nil); code != 200 {
		t.Fatalf("gọi API bằng token = %d: %s", code, body)
	}
	// Scope hẹp phải được ÁP THẬT: token này không có events:read.
	if code, _ := do(t, srv, "GET", "/api/v1/events", created.Token, nil); code != 403 {
		t.Errorf("token không có events:read đọc được /events: %d", code)
	}

	// --- liệt kê: KHÔNG được lộ token trần hay hash
	code, body = do(t, srv, "GET", "/api/v1/tokens", sess, nil)
	if code != 200 {
		t.Fatalf("GET /tokens = %d: %s", code, body)
	}
	if strings.Contains(string(body), created.Token) {
		t.Fatal("GET /tokens trả lại token TRẦN — token phải chỉ hiện đúng một lần")
	}
	if strings.Contains(string(body), "token_hash") {
		t.Error("GET /tokens lộ token_hash")
	}
	if !strings.Contains(string(body), created.Meta.ID) {
		t.Errorf("GET /tokens thiếu id để thu hồi: %s", body)
	}

	// --- thu hồi
	if code, body := do(t, srv, "DELETE", "/api/v1/tokens/"+created.Meta.ID, sess, nil); code != 204 {
		t.Fatalf("DELETE /tokens/{id} = %d: %s", code, body)
	}
	if code, _ := do(t, srv, "GET", "/api/v1/apps", created.Token, nil); code != 401 {
		t.Errorf("token đã thu hồi vẫn gọi được API: %d", code)
	}
	if code, _ := do(t, srv, "DELETE", "/api/v1/tokens/"+created.Meta.ID, sess, nil); code != 404 {
		t.Errorf("thu hồi lần hai = %d, muốn 404", code)
	}
}

// Yêu cầu sai trả 400 kèm MÃ máy đọc được — UI phải hiện được lỗi cụ thể chứ
// không phải "có gì đó sai".
func TestTokenAPIBadRequests(t *testing.T) {
	srv, ident, _ := newTokenServer(t)
	sess := ownerSession(t, ident)

	cases := []struct {
		name string
		body map[string]any
		code string
	}{
		{"cidr hỏng", map[string]any{"allowed_ip_cidrs": []string{"10.0.0.0/33"}}, "bad_cidr"},
		{"ttl vượt trần", map[string]any{"expires_in_days": 400}, "ttl_too_long"},
		// Gõ nhầm một chữ. Chủ instance có `admin` nên luật bao hàm nói CÓ với
		// mọi chuỗi — chỉ có bảng scope mới bắt được cái này.
		{"scope gõ nhầm", map[string]any{"scopes": []string{"apps:writes"}}, "unknown_scope"},
		{"scope bịa", map[string]any{"scopes": []string{"nuke:everything"}}, "unknown_scope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := do(t, srv, "POST", "/api/v1/tokens", sess, tc.body)
			if code != 400 {
				t.Fatalf("= %d, muốn 400: %s", code, body)
			}
			var e struct {
				Code string `json:"code"`
			}
			_ = json.Unmarshal(body, &e)
			if e.Code != tc.code {
				t.Errorf("code = %q, muốn %q: %s", e.Code, tc.code, body)
			}
		})
	}
}

// Token hẹp KHÔNG tự phát được token mới. Không có ràng buộc này thì giới hạn
// scope chỉ là gợi ý: kẻ cầm token `apps:read` phát cho mình một cái rộng hơn.
func TestNarrowTokenCannotMintTokens(t *testing.T) {
	srv, ident, _ := newTokenServer(t)
	sess := ownerSession(t, ident)
	code, body := do(t, srv, "POST", "/api/v1/tokens", sess, map[string]any{
		"scopes": []string{"apps:read"},
	})
	if code != 201 {
		t.Fatalf("tạo token hẹp = %d: %s", code, body)
	}
	var created struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(body, &created)

	if code, _ := do(t, srv, "POST", "/api/v1/tokens", created.Token, map[string]any{}); code != 403 {
		t.Errorf("token apps:read phát được token mới: %d", code)
	}
	if code, _ := do(t, srv, "GET", "/api/v1/tokens", created.Token, nil); code != 403 {
		t.Errorf("token apps:read đọc được danh sách token: %d", code)
	}
}

// Không đăng nhập → 401 ở cả ba route, không phải 404 hay 500.
func TestTokenRoutesRequireAuth(t *testing.T) {
	srv, _, _ := newTokenServer(t)
	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/v1/tokens"},
		{"POST", "/api/v1/tokens"},
		{"DELETE", "/api/v1/tokens/bất-kỳ"},
	} {
		if code, body := do(t, srv, tc.method, tc.path, "", nil); code != 401 {
			t.Errorf("%s %s không xác thực = %d, muốn 401: %s", tc.method, tc.path, code, body)
		}
	}
}
