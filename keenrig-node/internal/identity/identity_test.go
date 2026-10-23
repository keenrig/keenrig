package identity_test

// Test T10 — ID-03 (rate-limit + lockout, TOTP đúng/sai), ID-05 (cookie
// HttpOnly/SameSite/Secure, logout revoke THẬT).

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/authz"
	"github.com/keenrig/keenrig/keenrig-node/internal/identity"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

const goodPass = "mật-khẩu-đủ-dài-12"

func setup(t *testing.T, opts identity.Options) (*identity.Service, store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return identity.New(st, opts), st
}

func mustOwner(t *testing.T, s *identity.Service) *store.User {
	t.Helper()
	u, err := s.CreateOwner(context.Background(), "alice", goodPass)
	if err != nil {
		t.Fatalf("CreateOwner: %v", err)
	}
	return u
}

func TestSetupOwnerOnce(t *testing.T) {
	s, _ := setup(t, identity.Options{})
	ctx := context.Background()

	if need, err := s.NeedsSetup(ctx); err != nil || !need {
		t.Fatalf("NeedsSetup = (%v, %v), muốn true", need, err)
	}
	mustOwner(t, s)
	if need, err := s.NeedsSetup(ctx); err != nil || need {
		t.Errorf("NeedsSetup sau khi tạo chủ = %v", need)
	}
	// Chủ thứ hai qua luồng thiết lập → từ chối. Không từ chối là để bất kỳ ai
	// chạm được API tự phong mình làm quản trị.
	if _, err := s.CreateOwner(ctx, "kẻ-khác", goodPass); !errors.Is(err, identity.ErrSetupDone) {
		t.Errorf("CreateOwner lần 2 = %v, muốn ErrSetupDone", err)
	}
}

func TestPasswordPolicyAndHash(t *testing.T) {
	if _, err := identity.HashPassword("ngắn"); err == nil {
		t.Error("nhận mật khẩu ngắn hơn tối thiểu")
	}
	h, err := identity.HashPassword(goodPass)
	if err != nil {
		t.Fatal(err)
	}
	// Hash phải MANG THEO tham số: không có chúng thì nâng chi phí băm sau này
	// sẽ làm mọi hash cũ không xác thực được nữa.
	for _, want := range []string{"$argon2id$", "m=", "t=", "p="} {
		if !strings.Contains(h, want) {
			t.Errorf("hash thiếu %q: %s", want, h)
		}
	}
	if strings.Contains(h, goodPass) {
		t.Error("hash chứa mật khẩu trần")
	}
	// Cùng mật khẩu, hai lần băm phải khác nhau (salt ngẫu nhiên).
	h2, _ := identity.HashPassword(goodPass)
	if h == h2 {
		t.Error("hai lần băm cho cùng kết quả — salt không ngẫu nhiên")
	}
	if err := identity.VerifyPassword(h, goodPass); err != nil {
		t.Errorf("Verify mật khẩu đúng: %v", err)
	}
	if err := identity.VerifyPassword(h, goodPass+"x"); !errors.Is(err, identity.ErrBadPassword) {
		t.Errorf("Verify mật khẩu sai = %v", err)
	}
	for _, bad := range []string{"", "không-phải-hash", "$argon2id$v=19$m=1$abc"} {
		if err := identity.VerifyPassword(bad, goodPass); err == nil {
			t.Errorf("Verify với hash rác %q lại thành công", bad)
		}
	}
}

// ID-03 — lockout sau N lần sai, và mở lại sau khi hết cửa sổ khoá.
func TestLockoutAfterFailures(t *testing.T) {
	s, _ := setup(t, identity.Options{})
	ctx := context.Background()
	mustOwner(t, s)

	in := identity.LoginInput{Username: "alice", Password: "sai-mật-khẩu-rồi", IP: "10.0.0.1"}
	for i := 0; i < identity.MaxLoginFailures; i++ {
		if _, _, err := s.Login(ctx, in); !errors.Is(err, identity.ErrInvalidCredentials) {
			t.Fatalf("lần %d = %v, muốn ErrInvalidCredentials", i+1, err)
		}
	}
	// Chạm ngưỡng → khoá, và mật khẩu ĐÚNG cũng không vào được.
	if _, _, err := s.Login(ctx, identity.LoginInput{
		Username: "alice", Password: goodPass, IP: "10.0.0.1",
	}); !errors.Is(err, identity.ErrLocked) {
		t.Fatalf("sau %d lần sai, mật khẩu đúng = %v, muốn ErrLocked", identity.MaxLoginFailures, err)
	}
}

// Tên đăng nhập KHÔNG tồn tại cũng phải bị đếm — không đếm là để kẻ dò tên thử
// vô hạn miễn là gõ sai tên.
func TestUnknownUserAlsoCounted(t *testing.T) {
	s, st := setup(t, identity.Options{})
	ctx := context.Background()
	mustOwner(t, s)

	for i := 0; i < identity.MaxLoginFailures; i++ {
		if _, _, err := s.Login(ctx, identity.LoginInput{
			Username: "không-tồn-tại", Password: "x", IP: "10.0.0.9",
		}); !errors.Is(err, identity.ErrInvalidCredentials) {
			t.Fatalf("= %v", err)
		}
	}
	// IP đó nay bị khoá, kể cả khi đổi sang tên đúng.
	if _, _, err := s.Login(ctx, identity.LoginInput{
		Username: "alice", Password: goodPass, IP: "10.0.0.9",
	}); !errors.Is(err, identity.ErrLocked) {
		t.Errorf("IP đã dò %d lần vẫn vào được: %v", identity.MaxLoginFailures, err)
	}
	if la, err := st.GetLoginAttempts(ctx, "ip:10.0.0.9"); err != nil || la.Failures < identity.MaxLoginFailures {
		t.Errorf("bộ đếm theo IP = %+v (%v)", la, err)
	}
}

// Đăng nhập ĐÚNG phải xoá lịch sử thử sai, nếu không vài lần gõ nhầm rải rác
// trong ngày sẽ cộng dồn thành khoá tài khoản.
func TestSuccessClearsFailures(t *testing.T) {
	s, st := setup(t, identity.Options{})
	ctx := context.Background()
	mustOwner(t, s)

	for i := 0; i < identity.MaxLoginFailures-1; i++ {
		_, _, _ = s.Login(ctx, identity.LoginInput{Username: "alice", Password: "sai", IP: "10.0.0.2"})
	}
	if _, _, err := s.Login(ctx, identity.LoginInput{Username: "alice", Password: goodPass, IP: "10.0.0.2"}); err != nil {
		t.Fatalf("đăng nhập đúng: %v", err)
	}
	if _, err := st.GetLoginAttempts(ctx, "user:alice"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("lịch sử thử sai chưa được xoá: %v", err)
	}
}

// ID-05 — logout thu hồi THẬT: token cũ không dùng lại được.
func TestSessionLifecycle(t *testing.T) {
	s, _ := setup(t, identity.Options{})
	ctx := context.Background()
	u := mustOwner(t, s)

	token, sess, err := s.Login(ctx, identity.LoginInput{Username: "alice", Password: goodPass, IP: "10.0.0.3"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if token == "" || sess.UserID != u.ID {
		t.Fatalf("phiên = %+v", sess)
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	p, err := s.Authenticate(r)
	if err != nil || p.Subject != u.ID {
		t.Fatalf("Authenticate = (%+v, %v)", p, err)
	}
	if !p.Has(authz.ScopeAdmin) {
		t.Error("chủ instance không có scope admin")
	}

	if err := s.Logout(ctx, token); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := s.Authenticate(r); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Error("token vẫn dùng được sau logout — thu hồi không thật")
	}
	// Logout hai lần không phải lỗi.
	if err := s.Logout(ctx, token); err != nil {
		t.Errorf("Logout lần 2: %v", err)
	}
}

// Phiên hết hạn coi như không tồn tại.
func TestSessionExpiry(t *testing.T) {
	clock := time.Now()
	s, _ := setup(t, identity.Options{SessionTTL: time.Second, Now: func() time.Time { return clock }})
	ctx := context.Background()
	mustOwner(t, s)

	token, _, err := s.Login(ctx, identity.LoginInput{Username: "alice", Password: goodPass})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	if _, err := s.Authenticate(r); err != nil {
		t.Fatalf("ngay sau login: %v", err)
	}

	time.Sleep(2100 * time.Millisecond) // cột expires_at có độ phân giải giây
	if _, err := s.Authenticate(r); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Error("phiên hết hạn vẫn dùng được")
	}
}

// ID-05 — cờ cookie. Tiền tố __Host- là ràng buộc do TRÌNH DUYỆT thực thi, nên
// nó không thay được bằng bất cứ kiểm tra nào phía server.
func TestSessionCookieFlags(t *testing.T) {
	for _, secure := range []bool{true, false} {
		s, _ := setup(t, identity.Options{Secure: secure})
		w := httptest.NewRecorder()
		s.SetSessionCookie(w, "tok", time.Now().Add(time.Hour))

		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("secure=%v: %d cookie", secure, len(cookies))
		}
		c := cookies[0]
		if !c.HttpOnly {
			t.Errorf("secure=%v: thiếu HttpOnly — một lỗ XSS thành mất phiên ngay", secure)
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Errorf("secure=%v: SameSite = %v, muốn Lax", secure, c.SameSite)
		}
		if c.Path != "/" {
			t.Errorf("secure=%v: Path = %q", secure, c.Path)
		}
		if c.Secure != secure {
			t.Errorf("secure=%v: cờ Secure = %v", secure, c.Secure)
		}
		wantName := identity.SessionCookieInsecure
		if secure {
			wantName = identity.SessionCookie
			if !strings.HasPrefix(c.Name, "__Host-") {
				t.Errorf("chạy HTTPS mà cookie không có tiền tố __Host-: %q", c.Name)
			}
		}
		if c.Name != wantName {
			t.Errorf("secure=%v: tên cookie = %q, muốn %q", secure, c.Name, wantName)
		}
	}
}

// ID-03 — TOTP: đăng ký hai bước, mã đúng/sai, và bắt buộc khi đã bật.
func TestTOTPFlow(t *testing.T) {
	s, st := setup(t, identity.Options{})
	ctx := context.Background()
	u := mustOwner(t, s)

	uri, err := s.EnrollTOTP(ctx, u.ID)
	if err != nil {
		t.Fatalf("EnrollTOTP: %v", err)
	}
	if !strings.HasPrefix(uri, "otpauth://totp/") || !strings.Contains(uri, "secret=") {
		t.Fatalf("URI = %q", uri)
	}

	// Chưa xác nhận thì CHƯA bật — người dùng có thể chưa kịp quét QR.
	got, err := st.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TOTPEnabled {
		t.Error("bật TOTP ngay khi đăng ký — người chưa quét QR sẽ bị khoá ra ngoài")
	}
	if _, _, err := s.Login(ctx, identity.LoginInput{Username: "alice", Password: goodPass}); err != nil {
		t.Errorf("chưa xác nhận TOTP mà login đã cần mã: %v", err)
	}

	secret := secretFromURI(t, uri)
	if err := s.ConfirmTOTP(ctx, u.ID, "000000"); !errors.Is(err, identity.ErrTOTPInvalid) {
		t.Errorf("xác nhận bằng mã sai = %v", err)
	}
	code, err := identity.TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmTOTP(ctx, u.ID, code); err != nil {
		t.Fatalf("ConfirmTOTP: %v", err)
	}

	// Đã bật → thiếu mã là ErrTOTPRequired, KHÔNG phải sai mật khẩu.
	_, _, err = s.Login(ctx, identity.LoginInput{Username: "alice", Password: goodPass})
	if !errors.Is(err, identity.ErrTOTPRequired) {
		t.Errorf("thiếu mã = %v, muốn ErrTOTPRequired", err)
	}
	// Thiếu mã KHÔNG được tính là thử sai, nếu không UI hỏi mã theo hai bước
	// sẽ tự khoá tài khoản người dùng.
	if la, err := st.GetLoginAttempts(ctx, "user:alice"); err == nil && la.Failures > 0 {
		t.Errorf("thiếu mã TOTP bị tính là thử sai: %+v", la)
	}

	if _, _, err := s.Login(ctx, identity.LoginInput{
		Username: "alice", Password: goodPass, TOTPCode: "000000",
	}); !errors.Is(err, identity.ErrTOTPInvalid) {
		t.Errorf("mã sai = %v", err)
	}
	code, _ = identity.TOTPCode(secret, time.Now())
	if _, _, err := s.Login(ctx, identity.LoginInput{
		Username: "alice", Password: goodPass, TOTPCode: code,
	}); err != nil {
		t.Errorf("mã đúng vẫn không vào được: %v", err)
	}

	// Tắt TOTP phải cần MẬT KHẨU: tắt lớp thứ hai chỉ bằng một phiên đang mở
	// biến mọi lỗ chiếm phiên thành chiếm tài khoản vĩnh viễn.
	if err := s.DisableTOTP(ctx, u.ID, "sai-mật-khẩu"); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Errorf("tắt TOTP bằng mật khẩu sai = %v", err)
	}
	if err := s.DisableTOTP(ctx, u.ID, goodPass); err != nil {
		t.Errorf("DisableTOTP: %v", err)
	}
}

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

// TOTP chấp nhận lệch ±1 bước (đồng hồ điện thoại lệch vài giây là bình
// thường) nhưng KHÔNG chấp nhận lệch xa hơn.
func TestTOTPSkewWindow(t *testing.T) {
	secret, err := identity.NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		code, err := identity.TOTPCode(secret, now.Add(d))
		if err != nil {
			t.Fatal(err)
		}
		if !identity.VerifyTOTP(secret, code, now) {
			t.Errorf("lệch %s bị từ chối — cửa sổ ±1 bước phải chấp nhận", d)
		}
	}
	for _, d := range []time.Duration{-90 * time.Second, 90 * time.Second} {
		code, _ := identity.TOTPCode(secret, now.Add(d))
		if identity.VerifyTOTP(secret, code, now) {
			t.Errorf("lệch %s vẫn được chấp nhận — cửa sổ quá rộng", d)
		}
	}
	// Mã rác không được lọt.
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if identity.VerifyTOTP(secret, bad, now) {
			t.Errorf("mã rác %q được chấp nhận", bad)
		}
	}
}

// Đổi mật khẩu phải THU HỒI mọi phiên — nếu không, đổi mật khẩu vì nghi bị
// chiếm phiên chẳng giải quyết được gì.
func TestChangePasswordRevokesSessions(t *testing.T) {
	s, _ := setup(t, identity.Options{})
	ctx := context.Background()
	u := mustOwner(t, s)

	token, _, err := s.Login(ctx, identity.LoginInput{Username: "alice", Password: goodPass})
	if err != nil {
		t.Fatal(err)
	}
	newPass := "mật-khẩu-mới-dài-hơn"
	if err := s.ChangePassword(ctx, u.ID, "sai", newPass); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Errorf("đổi bằng mật khẩu cũ sai = %v", err)
	}
	if err := s.ChangePassword(ctx, u.ID, goodPass, newPass); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	if _, err := s.Authenticate(r); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Error("phiên cũ còn sống sau khi đổi mật khẩu")
	}
	if _, _, err := s.Login(ctx, identity.LoginInput{Username: "alice", Password: newPass}); err != nil {
		t.Errorf("mật khẩu mới không dùng được: %v", err)
	}
}

// User bị vô hiệu → phiên đang mở hết giá trị NGAY, không đợi hết hạn.
func TestDisabledUserSessionDies(t *testing.T) {
	s, st := setup(t, identity.Options{})
	ctx := context.Background()
	u := mustOwner(t, s)

	token, _, err := s.Login(ctx, identity.LoginInput{Username: "alice", Password: goodPass})
	if err != nil {
		t.Fatal(err)
	}
	u.Disabled = true
	if err := st.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	if _, err := s.Authenticate(r); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Error("phiên của user đã vô hiệu vẫn dùng được")
	}
}

// Tên đăng nhập không phân biệt hoa thường — hai tài khoản chỉ khác hoa thường
// là một cái bẫy giả mạo.
func TestUsernameCaseInsensitive(t *testing.T) {
	s, _ := setup(t, identity.Options{})
	ctx := context.Background()
	mustOwner(t, s)

	if _, _, err := s.Login(ctx, identity.LoginInput{Username: "AliCe", Password: goodPass}); err != nil {
		t.Errorf("đăng nhập bằng tên khác hoa thường: %v", err)
	}
}

// ClientIP KHÔNG được tin X-Forwarded-For: header đó do client đặt, dùng nó
// cho rate-limit là tặng luôn cách vượt rate-limit.
func TestClientIPIgnoresForwardedFor(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.10:34567"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := identity.ClientIP(r); got != "192.0.2.10" {
		t.Errorf("ClientIP = %q, muốn 192.0.2.10 (không tin X-Forwarded-For)", got)
	}
}

// Reset (cứu hộ khi quên mật khẩu): không cần mật khẩu cũ, gỡ lockout cả theo
// IP lẫn theo user, mở lại tài khoản bị vô hiệu và thu hồi phiên cũ.
func TestResetPasswordRecoversLockedOutOwner(t *testing.T) {
	s, st := setup(t, identity.Options{})
	ctx := context.Background()
	u := mustOwner(t, s)

	token, _, err := s.Login(ctx, identity.LoginInput{Username: "alice", Password: goodPass, IP: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	bad := identity.LoginInput{Username: "alice", Password: "quên-mất-rồi-nhé", IP: "10.0.0.1"}
	for i := 0; i < identity.MaxLoginFailures; i++ {
		_, _, _ = s.Login(ctx, bad)
	}
	u.Disabled = true
	if err := st.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}

	newPass := "mật-khẩu-sau-khi-reset"
	if _, err := s.ResetPassword(ctx, "ALICE", newPass, false); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	if _, err := s.Authenticate(r); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Error("phiên cũ còn sống sau khi reset")
	}
	if _, _, err := s.Login(ctx, identity.LoginInput{Username: "alice", Password: newPass, IP: "10.0.0.1"}); err != nil {
		t.Errorf("mật khẩu mới không dùng được từ IP vừa bị khoá: %v", err)
	}
	if _, err := s.ResetPassword(ctx, "không-có-ai", newPass, false); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("reset user không tồn tại = %v, muốn ErrNotFound", err)
	}
	if _, err := s.ResetPassword(ctx, "alice", "ngắn", false); err == nil {
		t.Error("reset chấp nhận mật khẩu dưới 12 ký tự")
	}
}
