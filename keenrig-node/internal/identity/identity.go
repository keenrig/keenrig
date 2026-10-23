// Package identity — "anh là ai": tài khoản, mật khẩu, TOTP, phiên đăng nhập,
// rate-limit và lockout (ID-03..05).
//
// Tách khỏi authz ("anh được làm gì") có chủ đích: thêm một nhà cung cấp đăng
// nhập không được kéo theo việc viết lại bảng quyền, và thêm một endpoint mới
// không được đụng tới luồng đăng nhập. Package này CUNG CẤP một
// authz.Authenticator, chứ không tự áp scope.
//
// # Rate-limit nằm ở đây, không ở gateway
//
// Không đặt ở reverse proxy vì ta phải chạy với caddy/nginx/NPM, và năng lực
// rate-limit của ba cái đó khác nhau (xem
// proxy.Capabilities). Bảo vệ đăng nhập không được phụ thuộc gateway đang chọn.
//
// # Bộ đếm nằm trong DB, không nằm trong bộ nhớ
//
// Bộ nhớ mất sau mỗi lần restart, và kẻ tấn công chỉ cần làm box restart (hoặc
// đợi một lần OTA) là xoá sạch lịch sử thử sai.
package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/authz"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

var (
	// ErrInvalidCredentials — sai tên HOẶC sai mật khẩu HOẶC user bị vô hiệu.
	// MỘT lỗi cho cả ba: phân biệt là cho phép dò xem tài khoản nào tồn tại.
	ErrInvalidCredentials = errors.New("identity: wrong username or password")
	// ErrLocked — đang trong cửa sổ khoá.
	ErrLocked = errors.New("identity: temporarily locked out after too many failed attempts")
	// ErrTOTPRequired — đúng mật khẩu nhưng thiếu mã TOTP.
	ErrTOTPRequired = errors.New("identity: a two-factor code is required")
	// ErrTOTPInvalid — mã TOTP sai.
	ErrTOTPInvalid = errors.New("identity: the two-factor code is incorrect")
	// ErrSetupDone — đã có chủ; không cho tạo chủ thứ hai qua luồng thiết lập.
	ErrSetupDone = errors.New("identity: this instance already has an owner")
)

const (
	// MaxLoginFailures / LockoutFor — ngưỡng khoá (ID-03).
	//
	// 5 lần rồi khoá 15 phút: đủ rộng cho người gõ nhầm vài lần, đủ chặt để
	// một cuộc dò từ điển tụt xuống ~480 lần thử/ngày cho mỗi tên đăng nhập.
	MaxLoginFailures = 5
	LockoutFor       = 15 * time.Minute

	// SessionTTL — hạn phiên.
	SessionTTL = 12 * time.Hour
	// SessionCookie — tên cookie phiên.
	//
	// Tiền tố __Host- là một ràng buộc do TRÌNH DUYỆT thực thi: cookie bắt
	// buộc Secure, Path=/, KHÔNG Domain — nghĩa là một subdomain bị chiếm cũng
	// không đặt được cookie này cho ta. Đây là lớp phòng thủ mà server không tự
	// bảo đảm được.
	SessionCookie = "__Host-keenrig_session"
	// SessionCookieInsecure — bản không có tiền tố, dùng khi chạy HTTP (dev).
	// Trình duyệt TỪ CHỐI cookie __Host- trên http://, nên dev sẽ không đăng
	// nhập được nếu không có đường này.
	SessionCookieInsecure = "keenrig_session"

	sessionTokenLen = 32
	totpIssuer      = "Keenrig"
)

type Options struct {
	// Secure = true khi phục vụ qua HTTPS. Quyết định tên cookie và cờ Secure.
	Secure bool
	// SessionTTL; zero → SessionTTL mặc định.
	SessionTTL time.Duration
	// Now để test tua thời gian.
	Now func() time.Time
}

type Service struct {
	st   store.Store
	opts Options
	// tickets — vé "Mở Admin ↗" đang chờ, giữ trong BỘ NHỚ (xem adminticket.go).
	tickets adminTickets
}

func New(st store.Store, opts Options) *Service {
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = SessionTTL
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Service{st: st, opts: opts}
}

// CookieName — tên cookie đang dùng.
func (s *Service) CookieName() string {
	if s.opts.Secure {
		return SessionCookie
	}
	return SessionCookieInsecure
}

// --- thiết lập lần đầu ----------------------------------------------------------

// NeedsSetup — instance chưa có chủ.
func (s *Service) NeedsSetup(ctx context.Context) (bool, error) {
	n, err := s.st.CountUsers(ctx)
	return n == 0, err
}

// CreateOwner tạo chủ instance. CHỈ chạy được khi chưa có user nào.
//
// Kiểm "chưa có ai" rồi INSERT có một cửa sổ; UNIQUE(lower(username)) không
// đóng được nó vì hai tên khác nhau vẫn qua. Chấp nhận ở đây vì luồng này chạy
// đúng một lần trên một máy vừa cài, trước khi có ai biết địa chỉ — và ta vẫn
// kiểm lại sau INSERT để không im lặng tạo chủ thứ hai.
func (s *Service) CreateOwner(ctx context.Context, username, password string) (*store.User, error) {
	if done, err := s.setupDone(ctx); err != nil || done {
		if err != nil {
			return nil, err
		}
		return nil, ErrSetupDone
	}
	u, err := s.createUser(ctx, username, password, []authz.Scope{authz.ScopeAdmin})
	if err != nil {
		return nil, err
	}
	if n, cerr := s.st.CountUsers(ctx); cerr == nil && n > 1 {
		// Có kẻ chen ngang: gỡ tài khoản vừa tạo bằng cách vô hiệu hoá nó.
		u.Disabled = true
		_ = s.st.UpdateUser(ctx, u)
		return nil, ErrSetupDone
	}
	s.event(ctx, "identity.owner_created", u.ID, map[string]any{"username": u.Username})
	return u, nil
}

func (s *Service) setupDone(ctx context.Context) (bool, error) {
	n, err := s.st.CountUsers(ctx)
	return n > 0, err
}

func (s *Service) createUser(ctx context.Context, username, password string, scopes []authz.Scope) (*store.User, error) {
	name := strings.TrimSpace(username)
	if name == "" {
		return nil, errors.New("identity: empty username")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	strs := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		strs = append(strs, string(sc))
	}
	u := &store.User{ID: newID(), Username: name, PasswordHash: hash, Scopes: strs}
	if err := s.st.CreateUser(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// --- đăng nhập ------------------------------------------------------------------

// LoginInput — thứ handler thu được từ request.
type LoginInput struct {
	Username  string
	Password  string
	TOTPCode  string
	IP        string
	UserAgent string
}

// Login xác thực rồi mở phiên. Trả token TRẦN (chỉ lần này) + phiên.
//
// Thứ tự có chủ đích: kiểm khoá TRƯỚC khi băm mật khẩu. argon2 cố tình tốn
// 64MB và vài chục ms, nên băm trước rồi mới kiểm khoá sẽ biến chính cơ chế
// chống dò thành một kênh tự DoS.
func (s *Service) Login(ctx context.Context, in LoginInput) (string, *store.Session, error) {
	now := s.opts.Now()
	keys := lockKeys(in.Username, in.IP)
	for _, k := range keys {
		if locked, err := s.isLocked(ctx, k, now); err != nil {
			return "", nil, err
		} else if locked {
			return "", nil, ErrLocked
		}
	}

	u, err := s.st.GetUserByName(ctx, in.Username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Vẫn ĐẾM lần thử sai cho tên không tồn tại: không đếm là để kẻ dò
			// tên đăng nhập thử vô hạn miễn là gõ sai tên.
			s.recordFailure(ctx, keys)
			return "", nil, ErrInvalidCredentials
		}
		return "", nil, err
	}
	if u.Disabled {
		s.recordFailure(ctx, keys)
		return "", nil, ErrInvalidCredentials
	}
	if err := VerifyPassword(u.PasswordHash, in.Password); err != nil {
		s.recordFailure(ctx, keys)
		s.event(ctx, "identity.login_failed", u.ID, map[string]any{"ip": in.IP, "reason": "password"})
		return "", nil, ErrInvalidCredentials
	}

	if u.TOTPEnabled {
		if in.TOTPCode == "" {
			// KHÔNG tính là thất bại: người dùng đã chứng minh biết mật khẩu,
			// và tính là thất bại sẽ khoá tài khoản của chính họ mỗi lần UI
			// hỏi mã theo hai bước.
			return "", nil, ErrTOTPRequired
		}
		secret, err := s.totpSecret(ctx, u)
		if err != nil {
			return "", nil, err
		}
		if !VerifyTOTP(secret, in.TOTPCode, now) {
			s.recordFailure(ctx, keys)
			s.event(ctx, "identity.login_failed", u.ID, map[string]any{"ip": in.IP, "reason": "totp"})
			return "", nil, ErrTOTPInvalid
		}
	}

	for _, k := range keys {
		_ = s.st.ClearLoginFailures(ctx, k)
	}

	token, sess, err := s.openSession(ctx, u, in.IP, in.UserAgent)
	if err != nil {
		return "", nil, err
	}
	s.event(ctx, "identity.login", u.ID, map[string]any{"ip": in.IP})
	return token, sess, nil
}

// lockKeys — khoá theo CẢ tên đăng nhập lẫn IP.
//
// Chỉ theo tên: một kẻ tấn công khoá được tài khoản người khác chỉ bằng cách
// gõ sai (DoS). Chỉ theo IP: dò phân tán qua nhiều IP đi lọt. Hai khoá song
// song, chạm cái nào cũng chặn.
func lockKeys(username, ip string) []string {
	keys := []string{"user:" + strings.ToLower(strings.TrimSpace(username))}
	if ip != "" {
		keys = append(keys, "ip:"+ip)
	}
	return keys
}

func (s *Service) isLocked(ctx context.Context, key string, now time.Time) (bool, error) {
	la, err := s.st.GetLoginAttempts(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return la.Locked(now), nil
}

func (s *Service) recordFailure(ctx context.Context, keys []string) {
	for _, k := range keys {
		la, err := s.st.RecordLoginFailure(ctx, k, MaxLoginFailures, LockoutFor)
		if err == nil && la != nil && la.Failures == MaxLoginFailures {
			s.event(ctx, "identity.locked", k, map[string]any{"failures": la.Failures})
		}
	}
}

// --- phiên -----------------------------------------------------------------------

// hashToken băm token phiên trước khi lưu.
//
// SHA-256 trần (không argon2): token là 256 bit ngẫu nhiên mật mã, không phải
// mật khẩu người chọn, nên không có gì để dò từ điển. Băm chậm ở đây chỉ làm
// MỌI request tốn 50ms.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Service) openSession(ctx context.Context, u *store.User, ip, ua string) (string, *store.Session, error) {
	raw := make([]byte, sessionTokenLen)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sess := &store.Session{
		TokenHash: hashToken(token),
		UserID:    u.ID,
		ExpiresAt: s.opts.Now().Add(s.opts.SessionTTL),
		UserAgent: truncate(ua, 200),
		IP:        ip,
	}
	if err := s.st.CreateSession(ctx, sess); err != nil {
		return "", nil, err
	}
	return token, sess, nil
}

// Logout thu hồi THẬT phiên (ID-05).
func (s *Service) Logout(ctx context.Context, token string) error {
	err := s.st.DeleteSession(ctx, hashToken(token))
	if errors.Is(err, store.ErrNotFound) {
		return nil // logout hai lần không phải lỗi
	}
	return err
}

// Authenticate — cài authz.Authenticator. Ưu tiên cookie, rồi tới bearer token.
//
// Nhận cả hai vì cùng một API phục vụ hai loại client: trình duyệt (cookie, có
// CSRF) và script/CLI (bearer, không có cookie nên không có CSRF).
//
// API token (ID-04) được PHÂN LUỒNG BẰNG TIỀN TỐ chứ không phải bằng cách thử
// lần lượt hai bảng: thử lần lượt thì mỗi request sai token tốn hai lần truy
// vấn, và tệ hơn là thời gian trả lời khác nhau giữa "token phiên sai" và
// "token API sai" — một kênh phụ nhỏ nhưng miễn phí để đóng.
func (s *Service) Authenticate(r *http.Request) (authz.Principal, error) {
	token := ""
	if c, err := r.Cookie(s.CookieName()); err == nil {
		token = c.Value
	}
	if token == "" {
		token = authz.BearerToken(r)
	}
	if token == "" {
		return authz.Principal{}, authz.ErrUnauthenticated
	}

	ctx := r.Context()
	if strings.HasPrefix(token, TokenPrefix) {
		return s.authenticateToken(ctx, token, ClientIP(r))
	}

	sess, err := s.st.GetSession(ctx, hashToken(token))
	if err != nil {
		return authz.Principal{}, authz.ErrUnauthenticated
	}
	u, err := s.st.GetUser(ctx, sess.UserID)
	if err != nil || u.Disabled {
		// User bị vô hiệu giữa phiên → phiên hết giá trị NGAY, không đợi hết
		// hạn. Vô hiệu hoá một tài khoản mà phiên của nó còn sống 12 tiếng thì
		// việc vô hiệu hoá gần như vô nghĩa.
		return authz.Principal{}, authz.ErrUnauthenticated
	}
	scopes := make([]authz.Scope, 0, len(u.Scopes))
	for _, sc := range u.Scopes {
		scopes = append(scopes, authz.Scope(sc))
	}
	return authz.Principal{Subject: u.ID, Scopes: scopes}, nil
}

// SetSessionCookie ghi cookie phiên.
//
// HttpOnly: JavaScript không đọc được — một lỗ XSS không biến ngay thành mất
// phiên. SameSite=Lax: chặn CSRF cho mọi request đổi trạng thái (POST/PATCH/
// DELETE đều không kèm cookie khi đến từ site khác) mà vẫn giữ được trải
// nghiệm bấm link từ email.
func (s *Service) SetSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.CookieName(),
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.opts.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie xoá cookie phía trình duyệt.
func (s *Service) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.CookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.opts.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// --- TOTP -------------------------------------------------------------------------

// EnrollTOTP sinh secret mới và trả URI để hiện QR. CHƯA bật — phải xác nhận
// bằng một mã đúng qua ConfirmTOTP.
//
// Hai bước có lý do: bật ngay sau khi sinh secret sẽ khoá người dùng ra ngoài
// nếu họ chưa kịp quét QR hoặc app của họ lệch giờ.
func (s *Service) EnrollTOTP(ctx context.Context, userID string) (string, error) {
	u, err := s.st.GetUser(ctx, userID)
	if err != nil {
		return "", err
	}
	secret, err := NewTOTPSecret()
	if err != nil {
		return "", err
	}
	ref := "totp/" + u.ID
	if err := s.st.PutSecret(ctx, ref, []byte(secret)); err != nil {
		return "", err
	}
	u.TOTPRef = ref
	u.TOTPEnabled = false
	if err := s.st.UpdateUser(ctx, u); err != nil {
		return "", err
	}
	return TOTPURI(totpIssuer, u.Username, secret), nil
}

// ConfirmTOTP bật 2FA sau khi người dùng nhập đúng một mã.
func (s *Service) ConfirmTOTP(ctx context.Context, userID, code string) error {
	u, err := s.st.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if u.TOTPRef == "" {
		return errors.New("identity: TOTP is not enrolled")
	}
	secret, err := s.totpSecret(ctx, u)
	if err != nil {
		return err
	}
	if !VerifyTOTP(secret, code, s.opts.Now()) {
		return ErrTOTPInvalid
	}
	u.TOTPEnabled = true
	if err := s.st.UpdateUser(ctx, u); err != nil {
		return err
	}
	s.event(ctx, "identity.totp_enabled", u.ID, nil)
	return nil
}

// DisableTOTP tắt 2FA. Yêu cầu MẬT KHẨU: tắt lớp bảo vệ thứ hai chỉ bằng một
// phiên đang mở là biến mọi lỗ chiếm phiên thành chiếm tài khoản vĩnh viễn.
func (s *Service) DisableTOTP(ctx context.Context, userID, password string) error {
	u, err := s.st.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if err := VerifyPassword(u.PasswordHash, password); err != nil {
		return ErrInvalidCredentials
	}
	if u.TOTPRef != "" {
		_ = s.st.DeleteSecret(ctx, u.TOTPRef)
	}
	u.TOTPRef = ""
	u.TOTPEnabled = false
	if err := s.st.UpdateUser(ctx, u); err != nil {
		return err
	}
	s.event(ctx, "identity.totp_disabled", u.ID, nil)
	return nil
}

func (s *Service) totpSecret(ctx context.Context, u *store.User) (string, error) {
	if u.TOTPRef == "" {
		return "", errors.New("identity: the user has no TOTP secret")
	}
	raw, err := s.st.GetSecret(ctx, u.TOTPRef)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// ChangePassword đổi mật khẩu và THU HỒI mọi phiên khác.
//
// Không thu hồi thì đổi mật khẩu vì nghi bị chiếm phiên chẳng giải quyết được
// gì — kẻ chiếm vẫn giữ nguyên phiên cũ.
func (s *Service) ChangePassword(ctx context.Context, userID, oldPass, newPass string) error {
	u, err := s.st.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if err := VerifyPassword(u.PasswordHash, oldPass); err != nil {
		return ErrInvalidCredentials
	}
	hash, err := HashPassword(newPass)
	if err != nil {
		return err
	}
	u.PasswordHash = hash
	if err := s.st.UpdateUser(ctx, u); err != nil {
		return err
	}
	if _, err := s.st.DeleteUserSessions(ctx, u.ID); err != nil {
		return err
	}
	s.event(ctx, "identity.password_changed", u.ID, nil)
	return nil
}

// ResetPassword đặt mật khẩu mới KHÔNG cần mật khẩu cũ — đường cứu hộ cho chủ
// instance quên mật khẩu, chỉ gọi từ `keenrig-box reset-password` (root trên
// máy). Không có route HTTP nào dẫn tới đây: ai gọi được hàm này đã đọc được
// platform.db và master.key rồi, nên nó không mở thêm quyền gì.
//
// Ngoài mật khẩu, nó gỡ luôn những thứ khiến người vừa reset vẫn không vào
// được: tài khoản bị vô hiệu, lockout do thử sai (cả theo IP), và — khi
// disableTOTP — 2FA của một thiết bị đã mất. Mọi phiên cũ bị thu hồi như
// ChangePassword.
func (s *Service) ResetPassword(ctx context.Context, username, newPass string, disableTOTP bool) (*store.User, error) {
	u, err := s.st.GetUserByName(ctx, strings.TrimSpace(username))
	if err != nil {
		return nil, err
	}
	hash, err := HashPassword(newPass)
	if err != nil {
		return nil, err
	}
	u.PasswordHash = hash
	u.Disabled = false
	if disableTOTP {
		u.TOTPEnabled = false
	}
	if err := s.st.UpdateUser(ctx, u); err != nil {
		return nil, err
	}
	if _, err := s.st.DeleteUserSessions(ctx, u.ID); err != nil {
		return nil, err
	}
	if _, err := s.st.ClearAllLoginFailures(ctx); err != nil {
		return nil, err
	}
	s.event(ctx, "identity.password_reset", u.ID, map[string]any{"totp_disabled": disableTOTP})
	return u, nil
}

// --- tiện ích ------------------------------------------------------------------------

// ClientIP lấy IP người gọi.
//
// KHÔNG tin X-Forwarded-For: header đó do client đặt và ai cũng giả được, nên
// dùng nó cho rate-limit là tặng luôn cách vượt rate-limit. Gateway đứng trước
// ta là tiến trình cùng máy nên RemoteAddr là địa chỉ thật của kết nối tới
// gateway hoặc tới ta; khi nào có reverse proxy đáng tin ở tầng ngoài thì mới
// thêm danh sách proxy tin cậy — không sớm hơn.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("identity: crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:])
}

func (s *Service) event(ctx context.Context, action, subject string, data map[string]any) {
	var raw json.RawMessage
	if data != nil {
		raw, _ = json.Marshal(data)
	}
	_ = s.st.AppendEvent(ctx, action, "identity", subject, raw)
}
