package oidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/authz"
)

// Đường dẫn CỐ ĐỊNH của giao thức.
//
// `/.well-known/openid-configuration` do chuẩn quy định, không đổi được. Ba cái
// còn lại thì tự chọn, nhưng chúng được công bố trong discovery nên RP không
// bao giờ phải đoán — và vì thế chúng KHÔNG nằm dưới `/api/v1`: `/api/v1` là
// hợp đồng của Admin UI và có quyền đổi version, còn địa chỉ IdP mà đổi thì mọi
// app đã cấu hình sẽ hỏng cùng lúc.
const (
	DiscoveryPath = "/.well-known/openid-configuration"
	JWKSPath      = "/oidc/jwks.json"
	AuthorizePath = "/oidc/authorize"
	TokenPath     = "/oidc/token"
	UserInfoPath  = "/oidc/userinfo"
)

// Handler dựng http.Handler cho toàn bộ endpoint OIDC.
//
// auth là cách package này biết NGƯỜI DÙNG NÀO đang gõ /authorize — nó chính là
// `identity.Service`. Nhận qua interface `authz.Authenticator` chứ không import
// identity: package identity đã import store và authz, và một vòng import ngược
// lại sẽ buộc phải tách kiểu ra một package thứ ba chỉ để phá vòng.
func (p *Provider) Handler(auth authz.Authenticator) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+DiscoveryPath, p.discovery)
	mux.HandleFunc("GET "+JWKSPath, p.serveJWKS)
	mux.HandleFunc("GET "+AuthorizePath, func(w http.ResponseWriter, r *http.Request) {
		p.authorize(w, r, auth)
	})
	mux.HandleFunc("POST "+TokenPath, p.token)
	mux.HandleFunc("GET "+UserInfoPath, p.userinfo)
	mux.HandleFunc("POST "+UserInfoPath, p.userinfo)
	return mux
}

// discovery — bản tự mô tả mà RP đọc để tự cấu hình.
//
// Công bố ĐÚNG những gì hiện thực làm được, không phải những gì đẹp: khai
// `email` trong scopes_supported khi bảng users không có email nghĩa là RP cấu
// hình xong, chạy được, rồi người dùng đầu tiên đăng nhập vào một tài khoản
// không có email và app đó hỏng theo cách riêng của nó.
func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.opts.Issuer,
		"authorization_endpoint":                p.opts.Issuer + AuthorizePath,
		"token_endpoint":                        p.opts.Issuer + TokenPath,
		"userinfo_endpoint":                     p.opts.Issuer + UserInfoPath,
		"jwks_uri":                              p.opts.Issuer + JWKSPath,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{SigningAlg},
		"scopes_supported":                      supportedScopes,
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "preferred_username"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
	})
}

func (p *Provider) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	// Cache được: JWKS đổi chỉ khi xoay khoá, và RP tải nó ở MỌI lần xác minh
	// token nếu ta không nói gì. 5 phút đủ ngắn để một lần xoay khoá lan ra
	// nhanh, đủ dài để không thành một lời gọi mỗi request.
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, p.jwks())
}

// authorize — bước một: người dùng đồng ý (ngầm) và nhận mã.
//
// # Hai loại lỗi, hai cách trả về khác nhau
//
// Lỗi về CLIENT hoặc REDIRECT_URI được trả thẳng ra trang, KHÔNG chuyển hướng:
// lúc đó ta chưa biết URI kia có thật là của client không, và chuyển hướng tới
// một URI chưa xác minh là tự biến mình thành open redirect.
//
// Mọi lỗi CÒN LẠI được chuyển hướng về redirect_uri kèm `?error=`, đúng như
// chuẩn — RP cần thấy lỗi ở đúng chỗ nó đang đợi, không phải ở một trang lạ.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request, auth authz.Authenticator) {
	q := r.URL.Query()
	// Client được bỏ qua ở đây nhưng vẫn được ParseAuthRequest trả về: màn hình
	// đồng ý (nếu có, xem giới hạn 3 ở godoc package) cần TÊN app để hiện cho
	// người dùng, và lúc đó nó lấy từ đúng chỗ này.
	req, _, err := p.ParseAuthRequest(r.Context(), q)
	switch {
	case errors.Is(err, ErrUnknownClient):
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	case errors.Is(err, ErrBadRedirectURI):
		http.Error(w, "redirect_uri does not match a registered URI for this client", http.StatusBadRequest)
		return
	}
	if err != nil {
		redirectError(w, r, req, errorCode(err), err.Error())
		return
	}

	// Ai đang gõ? Chưa đăng nhập → đẩy sang trang đăng nhập của Admin UI, mang
	// theo đường quay lại. KHÔNG tự dựng form: hai form đăng nhập là hai bộ
	// rate-limit, lockout và TOTP phải giữ đồng bộ bằng tay.
	pr, err := auth.Authenticate(r)
	if err != nil {
		to := p.opts.LoginPath + "?return_to=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, to, http.StatusFound)
		return
	}

	// auth_time: bản này chưa mang được mốc đăng nhập thật ra khỏi phiên, nên
	// dùng thời điểm hiện tại và NÓI RA điều đó thay vì giả vờ chính xác.
	// Hệ quả: `max_age` của RP sẽ không bao giờ ép đăng nhập lại.
	code, err := p.IssueCode(r.Context(), req, pr.Subject, p.opts.Now())
	if err != nil {
		redirectError(w, r, req, "server_error", err.Error())
		return
	}

	to, err := url.Parse(req.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	v := to.Query()
	v.Set("code", code)
	if req.State != "" {
		v.Set("state", req.State)
	}
	to.RawQuery = v.Encode()
	http.Redirect(w, r, to.String(), http.StatusFound)
}

// redirectError chuyển hướng lỗi về RP theo đúng hình dạng chuẩn.
func redirectError(w http.ResponseWriter, r *http.Request, req *AuthRequest, code, desc string) {
	if req == nil || req.RedirectURI == "" {
		http.Error(w, desc, http.StatusBadRequest)
		return
	}
	to, err := url.Parse(req.RedirectURI)
	if err != nil {
		http.Error(w, desc, http.StatusBadRequest)
		return
	}
	v := to.Query()
	v.Set("error", code)
	v.Set("error_description", desc)
	if req.State != "" {
		v.Set("state", req.State)
	}
	to.RawQuery = v.Encode()
	http.Redirect(w, r, to.String(), http.StatusFound)
}

// token — bước hai: đổi mã lấy token.
func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthErr(w, http.StatusBadRequest, "invalid_request", "the request body is not a valid form")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		writeOAuthErr(w, http.StatusBadRequest, "unsupported_grant_type",
			"only authorization_code is supported")
		return
	}

	req := TokenRequest{
		Code:         r.PostForm.Get("code"),
		ClientID:     r.PostForm.Get("client_id"),
		ClientSecret: r.PostForm.Get("client_secret"),
		RedirectURI:  r.PostForm.Get("redirect_uri"),
		CodeVerifier: r.PostForm.Get("code_verifier"),
	}
	// HTTP Basic là cách xác thực client mà chuẩn đòi MỌI IdP phải nhận, và
	// nhiều thư viện RP chỉ dùng nó. Không nhận nó nghĩa là những RP đó không
	// đăng nhập được, với thông báo "invalid client" không nhắc gì tới header.
	if id, secret, ok := r.BasicAuth(); ok {
		req.ClientID, req.ClientSecret = id, secret
	}

	tok, err := p.Exchange(r.Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidClientAuth):
			// 401 + WWW-Authenticate: đây là lỗi XÁC THỰC CLIENT, khác hẳn lỗi
			// về mã. Trộn hai thứ vào 400 làm người tích hợp đi sửa nhầm chỗ.
			w.Header().Set("WWW-Authenticate", `Basic realm="oidc"`)
			writeOAuthErr(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		case errors.Is(err, ErrUserDisabled):
			writeOAuthErr(w, http.StatusBadRequest, "invalid_grant", "the account is disabled")
		case errors.Is(err, ErrInvalidGrant):
			writeOAuthErr(w, http.StatusBadRequest, "invalid_grant",
				"the authorization code is invalid, expired, already used, or does not match this request")
		default:
			writeOAuthErr(w, http.StatusInternalServerError, "server_error", "could not issue tokens")
		}
		return
	}

	// Token KHÔNG được nằm lại trong bất kỳ cache nào trên đường về.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, tok)
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	token := bearer(r)
	if token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oidc"`)
		writeOAuthErr(w, http.StatusUnauthorized, "invalid_token", "a bearer access token is required")
		return
	}
	claims, err := p.UserInfo(r.Context(), token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oidc", error="invalid_token"`)
		writeOAuthErr(w, http.StatusUnauthorized, "invalid_token", "the access token is invalid or expired")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, claims)
}

// bearer đọc access token từ header Authorization.
//
// CHỈ từ header: chuẩn cho phép cả query `?access_token=`, và chỗ đó là nơi
// token đi vào log truy cập của mọi proxy trên đường.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, ErrPKCERequired):
		return "invalid_request"
	case errors.Is(err, ErrInvalidRequest):
		return "invalid_request"
	default:
		return "server_error"
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeOAuthErr(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}
