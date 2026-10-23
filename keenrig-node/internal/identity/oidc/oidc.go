// Package oidc — Keenrig là NHÀ CUNG CẤP danh tính OpenID Connect (ID-01).
//
// # Chiều của luồng quyết định mọi thứ còn lại
//
// App cài trên nền tảng — Grafana, Nextcloud, một dashboard nội bộ — đăng nhập
// BẰNG tài khoản Keenrig. Ta giữ khoá ký, cấp mã uỷ quyền, phát hành token.
// Ta KHÔNG lưu token của Google; đó là chiều ngược lại và là một tính năng khác.
//
// Hệ quả không dễ chịu, và nó phải được nói ra: một lỗi ở package này không làm
// hỏng một app, nó làm hỏng ĐĂNG NHẬP CỦA MỌI APP — và tệ hơn, nó có thể cho
// một app mạo danh người dùng ở app khác.
//
// # Bốn quyết định thu hẹp bề mặt tấn công, mỗi cái bỏ đi một tính năng
//
//	CHỈ authorization code    Không implicit, không password grant. Implicit trả
//	                          token qua thanh địa chỉ — nó nằm lại trong lịch sử
//	                          duyệt, trong Referer, trong log của proxy. Password
//	                          grant thì bắt app cầm mật khẩu Keenrig của người
//	                          dùng, tức là phá bỏ toàn bộ lý do có SSO.
//	PKCE BẮT BUỘC, chỉ S256   Chuẩn chỉ đòi PKCE cho client công khai. Ở đây nó
//	                          bắt buộc cho MỌI client: một mã uỷ quyền bị đọc
//	                          trộm (log proxy, Referer) là vô dụng nếu không có
//	                          verifier. `plain` bị từ chối — nó là PKCE trên
//	                          giấy, vì challenge chính là verifier.
//	redirect_uri KHỚP TUYỆT ĐỐI  Không wildcard, không so tiền tố. Cho phép
//	                          `https://app.example.com/*` nghĩa là một open
//	                          redirect bất kỳ trên chính domain đó trở thành
//	                          đường lấy mã uỷ quyền của người dùng.
//	KHÔNG dynamic registration Client do nền tảng cấp lúc cài app. Đăng ký động
//	                          nghĩa là bất kỳ ai gọi được endpoint đều tự tạo
//	                          được client — và trên một box tự lưu trữ thì "bất
//	                          kỳ ai" gồm cả mọi app đang chạy trên chính máy đó.
//
// # Ba giới hạn của bản này, nói thẳng chứ không giấu trong code
//
//  1. KHÔNG có refresh token. Access token sống 1 giờ, hết hạn thì RP đẩy người
//     dùng qua /authorize lại — với phiên Keenrig còn sống thì đó là một lần
//     chuyển hướng không ai thấy. Đổi lại, không có một bí mật dài hạn thứ hai
//     phải lưu, phải xoay, phải thu hồi.
//  2. KHÔNG có scope `email`: bảng `users` chưa có cột email. Discovery công bố
//     đúng những scope hỗ trợ, để RP phát hiện lúc CẤU HÌNH chứ không phải lúc
//     người dùng đầu tiên đăng nhập.
//  3. KHÔNG có màn hình đồng ý (consent). App được người quản trị cài lên chính
//     box này; hỏi người dùng có đồng ý cho app đó biết tên mình không là một
//     nghi thức mà ai cũng bấm qua. Khi nào có người dùng được MỜI vào (chứ
//     không phải chủ box) thì câu trả lời có thể khác — và lúc đó nó là một
//     quyết định mới, không phải một dòng bị bỏ quên.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

var (
	// ErrUnknownClient — client_id không tồn tại.
	ErrUnknownClient = errors.New("oidc: unknown client")
	// ErrBadRedirectURI — redirect_uri không nằm trong danh sách đã đăng ký.
	//
	// Tách riêng vì nó là lỗi DUY NHẤT không được phép chuyển hướng về: nếu URI
	// sai mà ta vẫn redirect kèm `?error=`, ta vừa trở thành open redirect cho
	// chính kẻ gửi URI đó.
	ErrBadRedirectURI = errors.New("oidc: redirect_uri does not match a registered URI")
	// ErrInvalidRequest — thiếu tham số bắt buộc hoặc giá trị không hợp lệ.
	ErrInvalidRequest = errors.New("oidc: invalid request")
	// ErrPKCERequired — thiếu code_challenge, hoặc method không phải S256.
	ErrPKCERequired = errors.New("oidc: a S256 code_challenge is required")
	// ErrInvalidGrant — mã uỷ quyền sai, đã dùng, đã hết hạn, hoặc không khớp.
	//
	// MỘT lỗi cho cả bốn, có chủ đích: phân biệt là nói cho kẻ đang thử biết nó
	// sai ở đâu. Đây cũng đúng tên lỗi mà RFC 6749 quy định.
	ErrInvalidGrant = errors.New("oidc: invalid or expired authorization code")
	// ErrInvalidClientAuth — sai client_secret.
	ErrInvalidClientAuth = errors.New("oidc: client authentication failed")
	// ErrInvalidToken / ErrTokenExpired — access token hỏng hoặc hết hạn.
	ErrInvalidToken = errors.New("oidc: invalid access token")
	ErrTokenExpired = errors.New("oidc: the access token has expired")
	// ErrUserDisabled — tài khoản bị vô hiệu SAU khi token được cấp.
	ErrUserDisabled = errors.New("oidc: the account is disabled")
)

const (
	// CodeTTL — mã uỷ quyền sống bao lâu.
	//
	// 60 giây. Chuẩn khuyến nghị "tối đa 10 phút"; 10 phút là khoảng thời gian
	// một mã bị đọc trộm còn dùng được, mà quãng đường thật của nó chỉ là một
	// lần chuyển hướng trình duyệt cộng một lời gọi HTTP từ máy chủ RP.
	CodeTTL = 60 * time.Second
	// AccessTokenTTL / IDTokenTTL — hạn của token.
	AccessTokenTTL = time.Hour
	IDTokenTTL     = time.Hour

	// signingKeyRef — khoá tra cứu khoá ký trong bảng secrets.
	signingKeyRef = "oidc/signing-key"
	// clientSecretRef — tiền tố khoá tra cứu client secret.
	clientSecretPrefix = "oidc/client/"

	// ScopeOpenID là scope bắt buộc của mọi yêu cầu OIDC.
	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
)

// supportedScopes — công bố ở discovery. Xem giới hạn (2) ở godoc package.
var supportedScopes = []string{ScopeOpenID, ScopeProfile}

// Options cấu hình Provider.
type Options struct {
	// Issuer — URL gốc của IdP, ví dụ https://box.example.com.
	//
	// Nó đi vào claim `iss` của mọi token và vào discovery, nên RP so khớp CHÍNH
	// XÁC chuỗi này. Sai một dấu `/` ở cuối là mọi RP từ chối mọi token, với
	// thông báo lỗi không nhắc gì tới dấu gạch chéo.
	Issuer string
	// LoginPath — nơi đẩy người dùng chưa đăng nhập tới.
	//
	// Mặc định "/login". Trang đó thuộc Admin UI, không thuộc package này: một
	// IdP tự dựng form đăng nhập riêng nghĩa là có HAI form đăng nhập phải giữ
	// đồng bộ về rate-limit, lockout và TOTP.
	LoginPath string
	// Now để test tua thời gian.
	Now func() time.Time
}

// Provider — nhà cung cấp OIDC.
type Provider struct {
	st   store.Store
	opts Options

	mu sync.RWMutex
	// keys — khoá ký. Phần tử ĐẦU là khoá đang dùng để ký; phần còn lại chỉ để
	// xác minh token đã phát hành trước khi xoay khoá.
	keys []*signingKey
}

// New dựng Provider, nạp (hoặc sinh) khoá ký.
//
// Khoá nằm trong bảng secrets, tức là được mã hoá bằng master.key và đi theo
// bản sao lưu. Sinh mới mỗi lần khởi động sẽ làm MỌI token đang lưu hành chết
// sau mỗi lần restart hoặc mỗi lần OTA — người dùng bị đá ra khỏi mọi app vì
// một lần cập nhật.
func New(ctx context.Context, st store.Store, opts Options) (*Provider, error) {
	if opts.Issuer == "" {
		return nil, errors.New("oidc: an issuer URL is required")
	}
	opts.Issuer = strings.TrimSuffix(opts.Issuer, "/")
	if opts.LoginPath == "" {
		opts.LoginPath = "/login"
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	p := &Provider{st: st, opts: opts}

	raw, err := st.GetSecret(ctx, signingKeyRef)
	switch {
	case err == nil:
		k, perr := parseKey(raw)
		if perr != nil {
			return nil, perr
		}
		p.keys = []*signingKey{k}
	case errors.Is(err, store.ErrNotFound):
		k, gerr := newSigningKey()
		if gerr != nil {
			return nil, gerr
		}
		pem, merr := marshalKey(k.key)
		if merr != nil {
			return nil, merr
		}
		if serr := st.PutSecret(ctx, signingKeyRef, pem); serr != nil {
			return nil, serr
		}
		p.keys = []*signingKey{k}
	default:
		return nil, err
	}
	return p, nil
}

// Issuer trả URL gốc đang dùng.
func (p *Provider) Issuer() string { return p.opts.Issuer }

// --- client -----------------------------------------------------------------------

// RegisterClient cấp một client mới và trả về secret TRẦN — chỉ lần này.
//
// Secret được lưu ở bảng secrets (sau master.key), không ở cột nào của
// oidc_clients. Trả trần đúng một lần là cùng luật với API token và session:
// caller phải tiêm nó vào app ngay, hoặc mất và phải cấp lại.
func (p *Provider) RegisterClient(ctx context.Context, clientID, appID, name string, redirectURIs []string) (string, error) {
	if clientID == "" {
		return "", fmt.Errorf("%w: empty client_id", ErrInvalidRequest)
	}
	if len(redirectURIs) == 0 {
		return "", fmt.Errorf("%w: at least one redirect_uri is required", ErrInvalidRequest)
	}
	for _, u := range redirectURIs {
		if err := checkRedirectURI(u); err != nil {
			return "", err
		}
	}
	secret, err := randomString(32)
	if err != nil {
		return "", err
	}
	ref := clientSecretPrefix + clientID
	if err := p.st.PutSecret(ctx, ref, []byte(secret)); err != nil {
		return "", err
	}
	c := &store.OIDCClient{
		ClientID: clientID, AppID: appID, Name: name,
		SecretRef: ref, RedirectURIs: redirectURIs,
	}
	if err := p.st.PutOIDCClient(ctx, c); err != nil {
		_ = p.st.DeleteSecret(ctx, ref)
		return "", err
	}
	return secret, nil
}

// checkRedirectURI — luật cho URI được đăng ký.
//
// Ba phép kiểm, mỗi cái vì một cách một RP tự mở cửa cho mình:
//
//	tuyệt đối        URI tương đối không xác định được đích, và so khớp chuỗi
//	                 với nó thì mọi thứ đều "khớp".
//	không fragment   Fragment KHÔNG bao giờ được gửi lên server, nên một URI
//	                 đăng ký có `#...` sẽ không bao giờ khớp — im lặng.
//	không wildcard   Xem godoc package.
func checkRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: redirect_uri %q is not a URL", ErrInvalidRequest, raw)
	}
	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("%w: redirect_uri %q must be absolute", ErrInvalidRequest, raw)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("%w: redirect_uri %q must not contain a fragment", ErrInvalidRequest, raw)
	}
	if strings.Contains(raw, "*") {
		return fmt.Errorf("%w: redirect_uri %q must not contain a wildcard", ErrInvalidRequest, raw)
	}
	return nil
}

// --- /authorize ---------------------------------------------------------------------

// AuthRequest — tham số đã được kiểm của một yêu cầu uỷ quyền.
type AuthRequest struct {
	ClientID      string
	RedirectURI   string
	Scope         string
	State         string
	Nonce         string
	CodeChallenge string
}

// ParseAuthRequest kiểm tham số /authorize TRƯỚC khi đụng tới người dùng.
//
// Thứ tự trong hàm này là một phần của thiết kế: client và redirect_uri được
// kiểm ĐẦU TIÊN, vì mọi lỗi sau đó được báo bằng cách chuyển hướng VỀ
// redirect_uri — và chỉ được phép làm thế khi đã biết URI đó là của client thật.
func (p *Provider) ParseAuthRequest(ctx context.Context, q url.Values) (*AuthRequest, *store.OIDCClient, error) {
	clientID := q.Get("client_id")
	c, err := p.st.GetOIDCClient(ctx, clientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, ErrUnknownClient
	}
	if err != nil {
		return nil, nil, err
	}

	redirectURI := q.Get("redirect_uri")
	if !matchRedirectURI(c.RedirectURIs, redirectURI) {
		return nil, nil, ErrBadRedirectURI
	}

	req := &AuthRequest{
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       q.Get("scope"),
		State:       q.Get("state"),
		Nonce:       q.Get("nonce"),
	}
	if q.Get("response_type") != "code" {
		return req, c, fmt.Errorf("%w: only response_type=code is supported", ErrInvalidRequest)
	}
	if !hasScope(req.Scope, ScopeOpenID) {
		return req, c, fmt.Errorf("%w: the openid scope is required", ErrInvalidRequest)
	}
	// PKCE: bắt buộc, và chỉ S256. Xem godoc package.
	if m := q.Get("code_challenge_method"); m != "S256" {
		return req, c, fmt.Errorf("%w: code_challenge_method=%q", ErrPKCERequired, m)
	}
	req.CodeChallenge = q.Get("code_challenge")
	if req.CodeChallenge == "" {
		return req, c, ErrPKCERequired
	}
	return req, c, nil
}

// matchRedirectURI — so khớp CHÍNH XÁC từng ký tự.
//
// Không chuẩn hoá, không bỏ qua dấu `/` cuối, không phân giải `..`. Mọi phép
// "khoan dung" ở đây đều mở ra một cách để hai URI khác nhau cùng khớp, và bên
// hưởng lợi từ điều đó không phải người vận hành.
func matchRedirectURI(registered []string, got string) bool {
	if got == "" {
		return false
	}
	for _, r := range registered {
		if r == got {
			return true
		}
	}
	return false
}

// IssueCode cấp mã uỷ quyền cho một người dùng ĐÃ đăng nhập.
//
// Trả về mã TRẦN; store chỉ giữ hash của nó.
func (p *Provider) IssueCode(ctx context.Context, req *AuthRequest, userID string, authTime time.Time) (string, error) {
	code, err := randomString(32)
	if err != nil {
		return "", err
	}
	now := p.opts.Now()
	rec := &store.OIDCCode{
		CodeHash:      hashCode(code),
		ClientID:      req.ClientID,
		UserID:        userID,
		RedirectURI:   req.RedirectURI,
		Scope:         req.Scope,
		Nonce:         req.Nonce,
		CodeChallenge: req.CodeChallenge,
		AuthTime:      authTime,
		ExpiresAt:     now.Add(CodeTTL),
	}
	if err := p.st.CreateOIDCCode(ctx, rec); err != nil {
		return "", err
	}
	return code, nil
}

// --- /token -------------------------------------------------------------------------

// TokenRequest — tham số của lần đổi mã lấy token.
type TokenRequest struct {
	Code         string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	CodeVerifier string
}

// Tokens — thứ trả về ở /token.
type Tokens struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope,omitempty"`
}

// Exchange đổi mã uỷ quyền lấy token.
//
// Thứ tự các phép kiểm ở đây quan trọng, và nó ngược với trực giác: mã được
// TIÊU THỤ (xoá) TRƯỚC khi kiểm client_secret, redirect_uri hay PKCE.
//
// Lý do: nếu kiểm trước rồi mới xoá, một kẻ có mã nhưng thiếu verifier sẽ thử
// được vô hạn lần — mỗi lần sai không tiêu thụ gì cả. Tiêu thụ trước nghĩa là
// MỘT lần thử sai đốt luôn mã, đúng như RFC 6749 §4.1.2 yêu cầu.
func (p *Provider) Exchange(ctx context.Context, req TokenRequest) (*Tokens, error) {
	if req.Code == "" {
		return nil, ErrInvalidGrant
	}
	rec, err := p.st.ConsumeOIDCCode(ctx, hashCode(req.Code))
	if errors.Is(err, store.ErrNotFound) {
		// Mã không tồn tại, đã dùng, hoặc đã hết hạn — MỘT câu trả lời cho cả ba.
		return nil, ErrInvalidGrant
	}
	if err != nil {
		return nil, err
	}

	c, err := p.st.GetOIDCClient(ctx, rec.ClientID)
	if err != nil {
		return nil, ErrInvalidGrant
	}
	if req.ClientID != "" && req.ClientID != rec.ClientID {
		return nil, ErrInvalidGrant
	}
	if err := p.checkClientSecret(ctx, c, req.ClientSecret); err != nil {
		return nil, err
	}
	// redirect_uri phải khớp CHÍNH URI mã đã được cấp cho (RFC 6749 §4.1.3).
	if req.RedirectURI != rec.RedirectURI {
		return nil, ErrInvalidGrant
	}
	if !verifyPKCE(rec.CodeChallenge, req.CodeVerifier) {
		return nil, ErrInvalidGrant
	}

	u, err := p.st.GetUser(ctx, rec.UserID)
	if err != nil {
		return nil, ErrInvalidGrant
	}
	if u.Disabled {
		// Tài khoản bị vô hiệu GIỮA lúc mã còn sống. Cùng luật với phiên đăng
		// nhập: vô hiệu hoá phải có tác dụng ngay, không đợi hết hạn.
		return nil, ErrUserDisabled
	}
	return p.issueTokens(rec, u)
}

func (p *Provider) checkClientSecret(ctx context.Context, c *store.OIDCClient, got string) error {
	want, err := p.st.GetSecret(ctx, c.SecretRef)
	if err != nil {
		return ErrInvalidClientAuth
	}
	if !constantTimeEqual(string(want), got) {
		return ErrInvalidClientAuth
	}
	return nil
}

func (p *Provider) issueTokens(rec *store.OIDCCode, u *store.User) (*Tokens, error) {
	p.mu.RLock()
	key := p.keys[0]
	p.mu.RUnlock()

	now := p.opts.Now()
	base := map[string]any{
		"iss": p.opts.Issuer,
		"sub": u.ID,
		"aud": rec.ClientID,
		"iat": now.Unix(),
	}

	idClaims := map[string]any{}
	for k, v := range base {
		idClaims[k] = v
	}
	idClaims["exp"] = now.Add(IDTokenTTL).Unix()
	idClaims["auth_time"] = rec.AuthTime.Unix()
	if rec.Nonce != "" {
		idClaims["nonce"] = rec.Nonce
	}
	if hasScope(rec.Scope, ScopeProfile) {
		idClaims["preferred_username"] = u.Username
		idClaims["name"] = u.Username
	}
	idToken, err := key.sign(idClaims)
	if err != nil {
		return nil, err
	}

	acClaims := map[string]any{}
	for k, v := range base {
		acClaims[k] = v
	}
	acClaims["exp"] = now.Add(AccessTokenTTL).Unix()
	acClaims["scope"] = rec.Scope
	// `typ` phân biệt access token với ID token khi cả hai cùng ký bằng một khoá.
	// Thiếu nó thì một ID token dùng làm access token được — và ID token thì RP
	// nào cũng có trong tay.
	acClaims["typ"] = "at+jwt"
	accessToken, err := key.sign(acClaims)
	if err != nil {
		return nil, err
	}

	return &Tokens{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(AccessTokenTTL.Seconds()),
		IDToken:     idToken,
		Scope:       rec.Scope,
	}, nil
}

// --- /userinfo ------------------------------------------------------------------------

// UserInfo trả claim của chủ access token.
//
// Nó đọc LẠI user từ store thay vì tin claim trong token, và đó là chỗ việc vô
// hiệu hoá một tài khoản có tác dụng trước khi token hết hạn — bù cho việc
// access token là JWT nên không thu hồi được trực tiếp.
func (p *Provider) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	claims, err := p.verify(accessToken, p.opts.Now())
	if err != nil {
		return nil, err
	}
	if typ, _ := claims["typ"].(string); typ != "at+jwt" {
		// Một ID token bị dùng làm access token. Nó ký hợp lệ, hạn còn, và nếu
		// không kiểm `typ` thì nó qua được — trong khi ID token là thứ RP đưa
		// cho trình duyệt.
		return nil, ErrInvalidToken
	}
	sub, _ := claims["sub"].(string)
	u, err := p.st.GetUser(ctx, sub)
	if err != nil {
		return nil, ErrInvalidToken
	}
	if u.Disabled {
		return nil, ErrUserDisabled
	}
	out := map[string]any{"sub": u.ID}
	if scope, _ := claims["scope"].(string); hasScope(scope, ScopeProfile) {
		out["preferred_username"] = u.Username
		out["name"] = u.Username
	}
	return out, nil
}

// --- tiện ích --------------------------------------------------------------------------

// verifyPKCE kiểm verifier khớp challenge S256.
func verifyPKCE(challenge, verifier string) bool {
	if challenge == "" || verifier == "" {
		return false
	}
	// Độ dài verifier theo RFC 7636 §4.1. Quá ngắn là đoán được; quá dài là một
	// cách bắt ta băm dữ liệu tuỳ ý.
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return constantTimeEqual(challenge, base64.RawURLEncoding.EncodeToString(sum[:]))
}

// constantTimeEqual so sánh không phụ thuộc vị trí khác nhau đầu tiên.
//
// So bằng `==` trên một bí mật để lộ độ dài tiền tố đúng qua thời gian trả lời.
// Trên mạng thật kênh này rất ồn, nhưng nó miễn phí để đóng và client_secret là
// thứ đáng đóng.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hasScope — scope là chuỗi ngăn cách bằng KHOẢNG TRẮNG (RFC 6749), không phải
// dấu phẩy. Tách sai làm "openid profile" thành một scope tên là cả cụm đó.
func hasScope(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}
