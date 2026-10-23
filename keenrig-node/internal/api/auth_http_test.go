package api_test

// Năm route auth CHƯA từng có test HTTP: logout, password, totp/{enroll,
// confirm,disable}. Luật nghiệp vụ đã phủ ở internal/identity — ở đây kiểm
// thứ chỉ hỏng tại tầng ghép nối: route có gắn không, mã trạng thái đúng
// không, cookie có bị xoá không, và MÃ LỖI máy đọc được (totp_required /
// totp_invalid) có đi ra đúng hình dạng mà LoginView.vue đang rẽ nhánh không.
//
// Phát hiện bằng rà soát phủ route→test (2026-08-16): mọi route khác của
// /api/v1 đều có ít nhất một test gọi thẳng, riêng nhánh auth-flow thì chỉ
// service được test — một lỗi đăng ký route (đổi path, quên WithIdentity) sẽ
// xanh toàn bộ test cũ và chết ngoài production.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/identity"
)

// --- POST /auth/logout ---------------------------------------------------------------

func TestLogoutKillsTheSessionAndIsIdempotent(t *testing.T) {
	srv, ident, _ := newTokenServer(t)
	sess := ownerSession(t, ident)

	// Phiên sống: /auth/me trả 200.
	if code, _ := do(t, srv, "GET", "/api/v1/auth/me", sess, nil); code != 200 {
		t.Fatalf("me trước logout = %d", code)
	}

	// Logout bằng bearer — 204 và PHẢI kèm lệnh xoá cookie: UI không đọc được
	// cookie HttpOnly nên chỉ server mới dọn được nó.
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+sess)
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d, muốn 204", res.StatusCode)
	}
	cleared := false
	for _, c := range res.Cookies() {
		if strings.Contains(c.Name, "keenrig_session") && (c.MaxAge < 0 || c.Value == "") {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout không gửi Set-Cookie xoá phiên — trình duyệt sẽ tiếp tục gửi token đã chết")
	}

	// Token cũ phải CHẾT ngay, không phải chờ hết hạn.
	if code, _ := do(t, srv, "GET", "/api/v1/auth/me", sess, nil); code != 401 {
		t.Errorf("me sau logout = %d, muốn 401 — phiên chưa bị thu hồi", code)
	}

	// Idempotent: logout lần nữa (không phiên) vẫn 204 — "bạn chưa đăng nhập"
	// là một nhánh vô nghĩa mà UI sẽ phải xử lý.
	req2, _ := http.NewRequest("POST", srv.URL+"/api/v1/auth/logout", nil)
	res2, err := srv.Client().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	res2.Body.Close()
	if res2.StatusCode != http.StatusNoContent {
		t.Errorf("logout lần hai = %d, muốn 204", res2.StatusCode)
	}
}

// --- POST /auth/password --------------------------------------------------------------

func TestChangePasswordOverHTTPRevokesEverySession(t *testing.T) {
	srv, ident, _ := newTokenServer(t)
	sessA := ownerSession(t, ident)
	sessB := ownerSession(t, ident) // phiên thứ hai — tab khác / máy khác

	// Mật khẩu cũ SAI → 401, không đổi gì.
	if code, _ := do(t, srv, "POST", "/api/v1/auth/password", sessA, map[string]string{
		"old_password": "sai-toét", "new_password": "mật-khẩu-mới-dài-hơn-nữa",
	}); code != 401 {
		t.Fatalf("đổi bằng mật khẩu cũ sai = %d, muốn 401", code)
	}

	// Đổi đúng → 200, và MỌI phiên chết — kể cả phiên B không tham gia đổi:
	// người đổi mật khẩu vì nghi bị chiếm phiên cần đúng hành vi này.
	if code, body := do(t, srv, "POST", "/api/v1/auth/password", sessA, map[string]string{
		"old_password": "mật-khẩu-đủ-dài-12", "new_password": "mật-khẩu-mới-dài-hơn-nữa",
	}); code != 200 {
		t.Fatalf("đổi mật khẩu = %d: %s", code, body)
	}
	for name, s := range map[string]string{"A (phiên tự đổi)": sessA, "B (phiên khác)": sessB} {
		if code, _ := do(t, srv, "GET", "/api/v1/auth/me", s, nil); code != 401 {
			t.Errorf("phiên %s còn sống sau đổi mật khẩu (= %d)", name, code)
		}
	}

	// Mật khẩu mới dùng được, mật khẩu cũ thì không.
	if code, _ := do(t, srv, "POST", "/api/v1/auth/login", "", map[string]string{
		"username": "vincent", "password": "mật-khẩu-đủ-dài-12",
	}); code != 401 {
		t.Errorf("mật khẩu cũ vẫn đăng nhập được (= %d)", code)
	}
	if code, body := do(t, srv, "POST", "/api/v1/auth/login", "", map[string]string{
		"username": "vincent", "password": "mật-khẩu-mới-dài-hơn-nữa",
	}); code != 200 {
		t.Errorf("mật khẩu mới không đăng nhập được (= %d): %s", code, body)
	}
}

// --- POST /auth/totp/{enroll,confirm,disable} ------------------------------------------

func TestTOTPLifecycleOverHTTP(t *testing.T) {
	srv, ident, _ := newTokenServer(t)
	sess := ownerSession(t, ident)
	login := func(totp string) (int, []byte) {
		body := map[string]string{"username": "vincent", "password": "mật-khẩu-đủ-dài-12"}
		if totp != "" {
			body["totp"] = totp
		}
		return do(t, srv, "POST", "/api/v1/auth/login", "", body)
	}

	// Enroll: trả otpauth:// URI (KHÔNG phải ảnh QR — secret không đi qua
	// thêm tầng nào). Chưa confirm thì login vẫn KHÔNG đòi mã.
	code, body := do(t, srv, "POST", "/api/v1/auth/totp/enroll", sess, map[string]string{})
	if code != 200 {
		t.Fatalf("enroll = %d: %s", code, body)
	}
	var enr struct {
		URI string `json:"otpauth_uri"`
	}
	if err := json.Unmarshal(body, &enr); err != nil || !strings.HasPrefix(enr.URI, "otpauth://") {
		t.Fatalf("enroll không trả otpauth URI: %s", body)
	}
	if code, _ := login(""); code != 200 {
		t.Fatalf("login sau enroll-chưa-confirm = %d — TOTP đã bật TRƯỚC khi người dùng xác nhận quét QR", code)
	}

	// Confirm bằng mã tính từ CHÍNH secret trong URI — đúng việc app xác thực làm.
	secret := secretFromURI(t, enr.URI)
	okCode, err := identity.TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code, body := do(t, srv, "POST", "/api/v1/auth/totp/confirm", sess, map[string]string{"code": okCode}); code != 200 {
		t.Fatalf("confirm = %d: %s", code, body)
	}

	// Giờ login THIẾU mã phải trả đúng MÃ MÁY ĐỌC ĐƯỢC totp_required — chuỗi
	// mà LoginView.vue rẽ nhánh; đổi nó là làm câm màn hình nhập mã.
	code, body = login("")
	if code != 401 {
		t.Fatalf("login thiếu mã = %d, muốn 401", code)
	}
	var e struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &e)
	if e.Code != "totp_required" {
		t.Errorf("mã lỗi = %q, muốn totp_required", e.Code)
	}
	if code, body = login("000000"); code != 401 {
		t.Fatalf("login mã sai = %d, muốn 401", code)
	} else {
		_ = json.Unmarshal(body, &e)
		if e.Code != "totp_invalid" {
			t.Errorf("mã lỗi khi sai mã = %q, muốn totp_invalid", e.Code)
		}
	}
	freshCode, _ := identity.TOTPCode(secret, time.Now())
	code, body = login(freshCode)
	if code != 200 {
		t.Fatalf("login kèm mã đúng = %d: %s", code, body)
	}
	var logged struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(body, &logged)

	// Disable đòi MẬT KHẨU (không phải mã): kẻ cầm được phiên nhưng không có
	// mật khẩu không được quyền tắt lớp bảo vệ thứ hai.
	if code, _ := do(t, srv, "POST", "/api/v1/auth/totp/disable", logged.Token, map[string]string{"password": "sai"}); code != 401 {
		t.Errorf("disable bằng mật khẩu sai = %d, muốn 401", code)
	}
	if code, body := do(t, srv, "POST", "/api/v1/auth/totp/disable", logged.Token, map[string]string{"password": "mật-khẩu-đủ-dài-12"}); code != 200 {
		t.Fatalf("disable = %d: %s", code, body)
	}
	if code, _ := login(""); code != 200 {
		t.Errorf("login sau disable vẫn đòi mã (= %d)", code)
	}
}

// secretFromURI bóc secret= khỏi otpauth URI.
func secretFromURI(t *testing.T, uri string) string {
	t.Helper()
	i := strings.Index(uri, "secret=")
	if i < 0 {
		t.Fatalf("URI không có secret: %s", uri)
	}
	s := uri[i+len("secret="):]
	if j := strings.IndexByte(s, '&'); j >= 0 {
		s = s[:j]
	}
	return s
}
