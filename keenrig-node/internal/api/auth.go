package api

import (
	"errors"
	"net/http"

	"github.com/keenrig/keenrig/keenrig-node/internal/authz"
	"github.com/keenrig/keenrig/keenrig-node/internal/identity"
)

// Route xác thực (T10).
//
// # Vì sao chúng KHÔNG đi qua Guard
//
// /auth/setup và /auth/login là hai endpoint duy nhất phải gọi được khi CHƯA
// đăng nhập — bắt chúng qua Guard là khoá vĩnh viễn mọi người ra ngoài. Bù lại,
// chúng được bảo vệ bằng thứ khác: setup chỉ chạy khi chưa có user nào, login
// có rate-limit + lockout.
//
// Mọi route auth CÒN LẠI vẫn qua Guard như bình thường.

func (s *Server) authRoutes() {
	s.mux.HandleFunc("GET /api/v1/auth/setup", s.setupStatus)
	s.mux.HandleFunc("POST /api/v1/auth/setup", s.createOwner)
	s.mux.HandleFunc("POST /api/v1/auth/login", s.login)
	s.mux.HandleFunc("POST /api/v1/auth/logout", s.logout)

	// Các route dưới đây cần đã đăng nhập. Dùng scope hẹp nhất còn ý nghĩa:
	// mọi người dùng đăng nhập được đều phải tự xem và tự sửa được tài khoản
	// của mình, kể cả khi họ không có quyền gì trên app.
	s.mux.Handle("GET /api/v1/auth/me", s.guard.Require(authz.ScopeAppsRead, http.HandlerFunc(s.me)))
	s.mux.Handle("POST /api/v1/auth/totp/enroll", s.guard.Require(authz.ScopeAppsRead, http.HandlerFunc(s.totpEnroll)))
	s.mux.Handle("POST /api/v1/auth/totp/confirm", s.guard.Require(authz.ScopeAppsRead, http.HandlerFunc(s.totpConfirm)))
	s.mux.Handle("POST /api/v1/auth/totp/disable", s.guard.Require(authz.ScopeAppsRead, http.HandlerFunc(s.totpDisable)))
	s.mux.Handle("POST /api/v1/auth/password", s.guard.Require(authz.ScopeAppsRead, http.HandlerFunc(s.changePassword)))
}

func (s *Server) setupStatus(w http.ResponseWriter, r *http.Request) {
	if s.ident == nil {
		writeJSON(w, http.StatusOK, map[string]bool{"needs_setup": false})
		return
	}
	need, err := s.ident.NeedsSetup(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"needs_setup": need})
}

func (s *Server) createOwner(w http.ResponseWriter, r *http.Request) {
	if s.ident == nil {
		writeJSON(w, http.StatusNotImplemented, errBody{"login is not enabled"})
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	u, err := s.ident.CreateOwner(r.Context(), body.Username, body.Password)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.ident == nil {
		writeJSON(w, http.StatusNotImplemented, errBody{"login is not enabled"})
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if !decode(w, r, &body) {
		return
	}
	token, sess, err := s.ident.Login(r.Context(), identity.LoginInput{
		Username:  body.Username,
		Password:  body.Password,
		TOTPCode:  body.TOTP,
		IP:        identity.ClientIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	s.ident.SetSessionCookie(w, token, sess.ExpiresAt)
	// Trả token TRONG BODY nữa: client không phải trình duyệt (CLI, script)
	// không dùng cookie được. Đây là lần DUY NHẤT token trần xuất hiện — store
	// chỉ giữ hash.
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_at": sess.ExpiresAt,
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if s.ident == nil {
		writeJSON(w, http.StatusNotImplemented, errBody{"login is not enabled"})
		return
	}
	token := authz.BearerToken(r)
	if c, err := r.Cookie(s.ident.CookieName()); err == nil && c.Value != "" {
		token = c.Value
	}
	if token != "" {
		if err := s.ident.Logout(r.Context(), token); err != nil {
			writeErr(w, err)
			return
		}
	}
	s.ident.ClearSessionCookie(w)
	// 204 kể cả khi không có phiên: logout là thao tác idempotent, và báo lỗi
	// "bạn chưa đăng nhập" chỉ làm UI phải xử lý một nhánh vô nghĩa.
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.FromContext(r.Context())
	if !ok {
		writeErr(w, authz.ErrUnauthenticated)
		return
	}
	u, err := s.st.GetUser(r.Context(), p.Subject)
	if err != nil {
		// Principal không phải user thật (bootstrap token) — trả thông tin tối
		// thiểu thay vì 404: client chỉ cần biết mình là ai và có scope gì.
		writeJSON(w, http.StatusOK, map[string]any{"id": p.Subject, "scopes": p.Scopes})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": u.ID, "username": u.Username, "scopes": p.Scopes, "totp_enabled": u.TOTPEnabled,
	})
}

func (s *Server) totpEnroll(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.FromContext(r.Context())
	if !ok || s.ident == nil {
		writeErr(w, authz.ErrUnauthenticated)
		return
	}
	uri, err := s.ident.EnrollTOTP(r.Context(), p.Subject)
	if err != nil {
		writeErr(w, err)
		return
	}
	// Trả URI otpauth:// để UI dựng QR phía client. KHÔNG trả ảnh QR sinh sẵn:
	// secret khi đó đi qua thêm một tầng và nằm lại trong cache ảnh.
	writeJSON(w, http.StatusOK, map[string]string{"otpauth_uri": uri})
}

func (s *Server) totpConfirm(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.FromContext(r.Context())
	if !ok || s.ident == nil {
		writeErr(w, authz.ErrUnauthenticated)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := s.ident.ConfirmTOTP(r.Context(), p.Subject, body.Code); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"totp_enabled": true})
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.FromContext(r.Context())
	if !ok || s.ident == nil {
		writeErr(w, authz.ErrUnauthenticated)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := s.ident.DisableTOTP(r.Context(), p.Subject, body.Password); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"totp_enabled": false})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.FromContext(r.Context())
	if !ok || s.ident == nil {
		writeErr(w, authz.ErrUnauthenticated)
		return
	}
	var body struct {
		Old string `json:"old_password"`
		New string `json:"new_password"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := s.ident.ChangePassword(r.Context(), p.Subject, body.Old, body.New); err != nil {
		writeErr(w, err)
		return
	}
	// Mọi phiên (kể cả phiên hiện tại) đã bị thu hồi — xoá cookie để UI không
	// tiếp tục gửi một token đã chết.
	s.ident.ClearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "password changed, all sessions revoked"})
}

// writeAuthErr — phần bổ sung của bảng dịch lỗi cho T10.
func writeAuthErr(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, identity.ErrInvalidCredentials):
		writeJSON(w, http.StatusUnauthorized, errBody{"wrong username or password"})
	case errors.Is(err, identity.ErrTOTPRequired):
		// 401 kèm mã lỗi máy đọc được: UI phải phân biệt "sai mật khẩu" với
		// "đúng mật khẩu, giờ nhập mã" để hiện đúng màn hình.
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "a two-factor code is required", "code": "totp_required",
		})
	case errors.Is(err, identity.ErrTOTPInvalid):
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "the two-factor code is incorrect", "code": "totp_invalid",
		})
	case errors.Is(err, identity.ErrLocked):
		// 429 chứ không 401: nói đúng rằng vấn đề là TẦN SUẤT, để client biết
		// chờ chứ không thử tiếp.
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "temporarily locked out after too many failed attempts", "code": "locked",
		})
	case errors.Is(err, identity.ErrSetupDone):
		writeJSON(w, http.StatusConflict, errBody{"this instance already has an owner"})
	default:
		return false
	}
	return true
}
