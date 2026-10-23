package api

// Route quản lý API token (ID-04).
//
// # Vì sao một token KHÔNG tự quản được token
//
// Ba route dưới đây yêu cầu ScopeAdmin, không phải scope hẹp như /auth/me. Lý
// do: nếu token `apps:read` tự phát được token mới thì giới hạn scope chỉ còn
// là gợi ý — kẻ cầm token hẹp phát cho mình một cái khác và cứ thế. Ranh giới
// "ai được phát bí mật mới" phải nằm cao hơn ranh giới "ai được đọc danh sách
// app".
//
// Hệ quả có chủ đích: token thường không tự thu hồi được chính nó. Đường thu
// hồi là đăng nhập bằng trình duyệt — và đó đúng là điều ta muốn khi nghi một
// token bị lộ.

import (
	"errors"
	"net/http"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/authz"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/identity"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

func (s *Server) tokenRoutes() {
	s.mux.Handle("GET /api/v1/tokens", s.guard.Require(authz.ScopeAdmin, http.HandlerFunc(s.listTokens)))
	s.mux.Handle("POST /api/v1/tokens", s.guard.Require(authz.ScopeAdmin, http.HandlerFunc(s.createToken)))
	s.mux.Handle("DELETE /api/v1/tokens/{id}", s.guard.Require(authz.ScopeAdmin, http.HandlerFunc(s.revokeToken)))
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.FromContext(r.Context())
	if !ok || s.ident == nil {
		writeErr(w, authz.ErrUnauthenticated)
		return
	}
	toks, err := s.ident.ListTokens(r.Context(), p.Subject)
	if err != nil {
		writeErr(w, err)
		return
	}
	// store.APIToken có `json:"-"` trên TokenHash nên hash KHÔNG ra ngoài. Trả
	// thẳng struct thay vì tự dựng map: một trường mới thêm sau này sẽ tự xuất
	// hiện, và nếu nó là bí mật thì tag `-` là chỗ duy nhất phải nhớ.
	if toks == nil {
		toks = []*store.APIToken{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": toks})
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.FromContext(r.Context())
	if !ok || s.ident == nil {
		writeErr(w, authz.ErrUnauthenticated)
		return
	}
	var body struct {
		Name string `json:"name"`
		// Scopes rỗng → kế thừa toàn bộ quyền của người tạo.
		Scopes []string `json:"scopes"`
		// ExpiresInDays; 0 → mặc định.
		ExpiresInDays int `json:"expires_in_days"`
		// AllowedIPCIDRs rỗng → mọi IP.
		AllowedIPCIDRs []string `json:"allowed_ip_cidrs"`
	}
	if !decode(w, r, &body) {
		return
	}

	in := identity.NewTokenInput{
		Name:           body.Name,
		Scopes:         authz.ScopesFromStrings(body.Scopes),
		TTL:            time.Duration(body.ExpiresInDays) * 24 * time.Hour,
		AllowedIPCIDRs: body.AllowedIPCIDRs,
	}
	raw, tok, err := s.ident.CreateToken(r.Context(), p.Subject, in)
	if err != nil {
		writeErr(w, err)
		return
	}
	// `token` chỉ xuất hiện ở ĐÂY, đúng một lần trong đời. Không có đường API
	// nào đọc lại được — mất thì thu hồi và phát cái mới.
	writeJSON(w, http.StatusCreated, map[string]any{
		"token": raw,
		"meta":  tok,
		"warning": "this token is shown exactly once — save it now, " +
			"there is no way to retrieve it again",
	})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.FromContext(r.Context())
	if !ok || s.ident == nil {
		writeErr(w, authz.ErrUnauthenticated)
		return
	}
	if err := s.ident.RevokeToken(r.Context(), p.Subject, r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeTokenErr — phần bổ sung của bảng dịch lỗi cho ID-04.
//
// Cả ba lỗi đều là 400: chúng nói rằng YÊU CẦU sai, không phải người gọi thiếu
// quyền. Trả 403 cho ErrScopeEscalation sẽ gợi ý sai rằng "xin admin ở chỗ nào
// đó rồi thử lại" — trong khi điều đúng là xin ít quyền hơn.
func writeTokenErr(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, identity.ErrUnknownScope):
		// Kèm luôn danh sách scope hợp lệ: lỗi gõ nhầm mà không nói tên đúng là
		// gì thì người dùng phải đi tra tài liệu, và họ sẽ đoán thay vì tra.
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": err.Error(), "code": "unknown_scope", "valid_scopes": authz.AllScopes(),
		})
	case errors.Is(err, identity.ErrScopeEscalation):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": err.Error(), "code": "scope_escalation",
		})
	case errors.Is(err, identity.ErrTTLTooLong):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": err.Error(), "code": "ttl_too_long",
		})
	case errors.Is(err, identity.ErrBadCIDR):
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": err.Error(), "code": "bad_cidr",
		})
	default:
		return false
	}
	return true
}
