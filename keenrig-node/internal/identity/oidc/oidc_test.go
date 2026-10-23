package oidc_test

// ID-01 — luồng OIDC ĐẦY ĐỦ trên HTTP thật, SQLite thật, khoá RSA thật.
//
// # Vì sao không có fake ở đây
//
// Cái phải chứng minh không phải "ta gọi đúng thứ tự các hàm của mình" mà là
// "một Relying Party THẬT đăng nhập được". RP thật làm ba việc mà một fake sẽ
// không bao giờ làm: nó đọc `/.well-known/openid-configuration` để tự cấu hình,
// nó tải `/jwks.json` rồi TỰ xác minh chữ ký ID token, và nó gửi form
// `application/x-www-form-urlencoded` chứ không gửi JSON.
//
// Nên bộ test này tự đóng vai RP: nó tự xác minh chữ ký bằng khoá lấy từ JWKS,
// bằng code KHÔNG dùng lại một dòng nào của package oidc. Đó là cách duy nhất
// bắt được lớp lỗi "kid trong token khác kid trong JWKS" — lỗi mà cả hai phía
// của package đều thấy hợp lệ khi tự soi mình.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/httpd"
	"github.com/keenrig/keenrig/keenrig-node/internal/identity"
	"github.com/keenrig/keenrig/keenrig-node/internal/identity/oidc"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

const (
	ownerPass = "mật-khẩu-đủ-dài-12"
	clientID  = "app-grafana"
	// redirectURI — URI của RP. Được đăng ký nguyên văn và so khớp nguyên văn.
	redirectURI = "https://grafana.example.com/login/generic_oauth"
)

// rig — một IdP đang chạy, kèm một người dùng đã đăng nhập và một client đã cấp.
type rig struct {
	t        *testing.T
	st       store.Store
	ident    *identity.Service
	prov     *oidc.Provider
	srv      *httptest.Server
	owner    *store.User
	secret   string
	sessTok  string
	cookieNm string
}

func newRig(t *testing.T, opts oidc.Options) *rig {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Secure:false → cookie không có tiền tố __Host-, vì httptest phục vụ HTTP
	// trần và trình duyệt (cũng như http.Client) từ chối __Host- trên http://.
	ident := identity.New(st, identity.Options{Secure: false})
	owner, err := ident.CreateOwner(context.Background(), "alice", ownerPass)
	if err != nil {
		t.Fatalf("CreateOwner: %v", err)
	}
	tok, _, err := ident.Login(context.Background(), identity.LoginInput{
		Username: "alice", Password: ownerPass,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// Issuer phải là địa chỉ THẬT của server test: nó đi vào claim `iss`, và
	// phần xác minh phía RP dưới đây so khớp chính xác chuỗi đó.
	srv := httptest.NewUnstartedServer(nil)
	if opts.Issuer == "" {
		opts.Issuer = "http://" + srv.Listener.Addr().String()
	}
	prov, err := oidc.New(context.Background(), st, opts)
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	srv.Config.Handler = prov.Handler(ident)
	srv.Start()
	t.Cleanup(srv.Close)

	secret, err := prov.RegisterClient(context.Background(), clientID, "", "Grafana", []string{redirectURI})
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	return &rig{
		t: t, st: st, ident: ident, prov: prov, srv: srv,
		owner: owner, secret: secret, sessTok: tok, cookieNm: ident.CookieName(),
	}
}

// client — http.Client KHÔNG tự đi theo redirect.
//
// Bắt buộc: toàn bộ giao thức nằm trong header `Location`, và một client tự đi
// theo sẽ biến bước quan trọng nhất thành một lời gọi tới grafana.example.com —
// một host không tồn tại.
func (r *rig) client() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// authorize gọi /authorize kèm cookie phiên và trả về response thô.
func (r *rig) authorize(q url.Values, withSession bool) *http.Response {
	r.t.Helper()
	req, err := http.NewRequest(http.MethodGet, r.srv.URL+oidc.AuthorizePath+"?"+q.Encode(), nil)
	if err != nil {
		r.t.Fatal(err)
	}
	if withSession {
		req.AddCookie(&http.Cookie{Name: r.cookieNm, Value: r.sessTok})
	}
	res, err := r.client().Do(req)
	if err != nil {
		r.t.Fatalf("GET /authorize: %v", err)
	}
	return res
}

// authQuery — tham số /authorize hợp lệ cho một verifier cho trước.
func authQuery(verifier, state, nonce string) url.Values {
	sum := sha256.Sum256([]byte(verifier))
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
}

// newVerifier — code_verifier đúng luật RFC 7636 (43–128 ký tự).
func newVerifier(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b) // 43 ký tự
}

// getCode đi qua /authorize và bóc `code` ra khỏi Location.
func (r *rig) getCode(q url.Values) string {
	r.t.Helper()
	res := r.authorize(q, true)
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(res.Body)
		r.t.Fatalf("/authorize = %d, muốn 302\n%s", res.StatusCode, body)
	}
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		r.t.Fatal(err)
	}
	if e := loc.Query().Get("error"); e != "" {
		r.t.Fatalf("/authorize trả lỗi %q: %s", e, loc.Query().Get("error_description"))
	}
	code := loc.Query().Get("code")
	if code == "" {
		r.t.Fatalf("Location không có code: %s", loc)
	}
	return code
}

// exchange POST /token bằng form, đúng như một RP thật.
func (r *rig) exchange(form url.Values) (*http.Response, map[string]any) {
	r.t.Helper()
	res, err := r.client().PostForm(r.srv.URL+oidc.TokenPath, form)
	if err != nil {
		r.t.Fatalf("POST /token: %v", err)
	}
	defer res.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	return res, body
}

func tokenForm(code, verifier, secret string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"client_secret": {secret},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
}

// --- vòng đầy đủ ------------------------------------------------------------------

// Gate ID-01: app SSO login → token → userinfo, trên một IdP đang chạy thật.
func TestFullSSOFlow(t *testing.T) {
	r := newRig(t, oidc.Options{})
	verifier := newVerifier(t)

	// RP tự cấu hình từ discovery — đúng như một RP thật làm.
	disco := r.getJSON(oidc.DiscoveryPath)
	if disco["issuer"] != r.prov.Issuer() {
		t.Errorf("issuer trong discovery = %v, muốn %s", disco["issuer"], r.prov.Issuer())
	}
	for _, k := range []string{"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"} {
		if s, _ := disco[k].(string); !strings.HasPrefix(s, r.prov.Issuer()) {
			t.Errorf("discovery.%s = %v — không nằm dưới issuer", k, disco[k])
		}
	}

	q := authQuery(verifier, "state-cua-rp", "nonce-cua-rp")
	code := r.getCode(q)

	res, body := r.exchange(tokenForm(code, verifier, r.secret))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST /token = %d: %v", res.StatusCode, body)
	}
	// Token KHÔNG được nằm lại trong cache nào trên đường về.
	if cc := res.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, phải có no-store", cc)
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", body["token_type"])
	}

	idToken, _ := body["id_token"].(string)
	if idToken == "" {
		t.Fatal("không có id_token")
	}
	// XÁC MINH ĐỘC LẬP: chữ ký kiểm bằng khoá lấy từ JWKS, không dùng một dòng
	// nào của package oidc. Đây là chỗ bắt được lỗi kid lệch.
	claims := r.verifyWithJWKS(t, idToken)
	if claims["sub"] != r.owner.ID {
		t.Errorf("sub = %v, muốn %s", claims["sub"], r.owner.ID)
	}
	if claims["aud"] != clientID {
		t.Errorf("aud = %v, muốn %s", claims["aud"], clientID)
	}
	if claims["nonce"] != "nonce-cua-rp" {
		t.Errorf("nonce = %v — RP không kiểm được ID token này trả lời yêu cầu nào", claims["nonce"])
	}
	if claims["iss"] != r.prov.Issuer() {
		t.Errorf("iss = %v, muốn %s", claims["iss"], r.prov.Issuer())
	}
	if _, ok := claims["auth_time"]; !ok {
		t.Error("thiếu auth_time — RP không dùng được max_age")
	}
	if claims["preferred_username"] != "alice" {
		t.Errorf("preferred_username = %v (scope profile đã xin)", claims["preferred_username"])
	}

	// /userinfo bằng access token.
	access, _ := body["access_token"].(string)
	info := r.getJSONAuth(t, oidc.UserInfoPath, access)
	if info["sub"] != r.owner.ID {
		t.Errorf("userinfo.sub = %v, muốn %s", info["sub"], r.owner.ID)
	}
	if info["preferred_username"] != "alice" {
		t.Errorf("userinfo.preferred_username = %v", info["preferred_username"])
	}
}

// state phải đi NGUYÊN VẸN về RP — nó là lớp chống CSRF của chính RP.
func TestStateIsReturnedUnchanged(t *testing.T) {
	r := newRig(t, oidc.Options{})
	const state = "một state có ký tự lạ &=?#/ và dấu tiếng Việt"
	q := authQuery(newVerifier(t), state, "n")
	res := r.authorize(q, true)
	defer res.Body.Close()
	loc, _ := url.Parse(res.Header.Get("Location"))
	if got := loc.Query().Get("state"); got != state {
		t.Errorf("state trả về = %q, muốn %q", got, state)
	}
}

// --- các ca PHẢI ĐỎ --------------------------------------------------------------

// Mã uỷ quyền dùng ĐÚNG MỘT LẦN — và lần hai phải chết kể cả khi mọi tham số
// khác đều đúng.
func TestCodeIsSingleUse(t *testing.T) {
	r := newRig(t, oidc.Options{})
	verifier := newVerifier(t)
	code := r.getCode(authQuery(verifier, "s", "n"))

	if res, body := r.exchange(tokenForm(code, verifier, r.secret)); res.StatusCode != http.StatusOK {
		t.Fatalf("lần đầu phải thành công: %d %v", res.StatusCode, body)
	}
	res, body := r.exchange(tokenForm(code, verifier, r.secret))
	if res.StatusCode == http.StatusOK {
		t.Fatal("mã uỷ quyền dùng được LẦN THỨ HAI — một mã bị đọc trộm là một " +
			"phiên đăng nhập mạo danh")
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v, muốn invalid_grant", body["error"])
	}
}

// Một lần thử SAI cũng phải ĐỐT mã.
//
// Đây là điều RFC 6749 §4.1.2 đòi và là chỗ dễ làm ngược: kiểm trước rồi mới
// xoá nghĩa là kẻ có mã nhưng thiếu verifier thử được vô hạn lần.
func TestFailedAttemptStillBurnsTheCode(t *testing.T) {
	r := newRig(t, oidc.Options{})
	verifier := newVerifier(t)
	code := r.getCode(authQuery(verifier, "s", "n"))

	// Sai verifier.
	if res, _ := r.exchange(tokenForm(code, newVerifier(t), r.secret)); res.StatusCode == http.StatusOK {
		t.Fatal("verifier sai mà vẫn cấp token")
	}
	// Giờ thử lại với verifier ĐÚNG — phải vẫn chết, vì mã đã bị đốt.
	res, body := r.exchange(tokenForm(code, verifier, r.secret))
	if res.StatusCode == http.StatusOK {
		t.Fatal("một lần thử sai KHÔNG đốt mã — kẻ có mã thử verifier được vô hạn lần")
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v, muốn invalid_grant", body["error"])
	}
}

// PKCE BẮT BUỘC, và chỉ S256.
func TestPKCEIsMandatoryAndS256Only(t *testing.T) {
	r := newRig(t, oidc.Options{})
	verifier := newVerifier(t)

	cases := map[string]func(url.Values){
		"thiếu hẳn": func(q url.Values) {
			q.Del("code_challenge")
			q.Del("code_challenge_method")
		},
		"thiếu challenge":    func(q url.Values) { q.Del("code_challenge") },
		"method plain":       func(q url.Values) { q.Set("code_challenge_method", "plain") },
		"method rỗng":        func(q url.Values) { q.Set("code_challenge_method", "") },
		"method lạ":          func(q url.Values) { q.Set("code_challenge_method", "S512") },
		"response_type lạ":   func(q url.Values) { q.Set("response_type", "token") },
		"thiếu scope openid": func(q url.Values) { q.Set("scope", "profile") },
	}
	for name, mangle := range cases {
		t.Run(name, func(t *testing.T) {
			q := authQuery(verifier, "s", "n")
			mangle(q)
			res := r.authorize(q, true)
			defer res.Body.Close()
			// Lỗi loại này ĐƯỢC chuyển hướng về RP kèm ?error= (client và
			// redirect_uri đã xác minh xong), nhưng KHÔNG được kèm code.
			loc, _ := url.Parse(res.Header.Get("Location"))
			if loc != nil && loc.Query().Get("code") != "" {
				t.Fatalf("vẫn cấp mã: %s", loc)
			}
			if res.StatusCode == http.StatusFound && loc.Query().Get("error") == "" {
				t.Fatalf("chuyển hướng mà không có error: %s", loc)
			}
		})
	}
}

// redirect_uri phải khớp TUYỆT ĐỐI, và mọi biến tấu gần giống đều bị từ chối.
func TestRedirectURIMustMatchExactly(t *testing.T) {
	r := newRig(t, oidc.Options{})
	verifier := newVerifier(t)

	for _, bad := range []string{
		redirectURI + "/",    // thêm dấu gạch chéo
		redirectURI + "?x=1", // thêm query
		strings.Replace(redirectURI, "https", "http", 1),           // hạ cấp giao thức
		"https://grafana.example.com.evil.tld/login/generic_oauth", // hậu tố
		"https://evil.tld/login/generic_oauth",
		"", // thiếu hẳn
	} {
		q := authQuery(verifier, "s", "n")
		q.Set("redirect_uri", bad)
		res := r.authorize(q, true)
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()

		// KHÔNG được chuyển hướng: lúc này URI chưa được xác minh, và chuyển
		// hướng tới nó là tự biến mình thành open redirect cho kẻ vừa gửi nó.
		if res.StatusCode == http.StatusFound {
			t.Errorf("redirect_uri %q bị từ chối bằng cách CHUYỂN HƯỚNG tới %q — "+
				"đó chính là open redirect", bad, res.Header.Get("Location"))
			continue
		}
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("redirect_uri %q → %d (%s), muốn 400", bad, res.StatusCode, body)
		}
	}
}

// client_id lạ cũng phải chết TẠI CHỖ, không chuyển hướng.
func TestUnknownClientIsRefusedInPlace(t *testing.T) {
	r := newRig(t, oidc.Options{})
	q := authQuery(newVerifier(t), "s", "n")
	q.Set("client_id", "app-khong-ton-tai")
	res := r.authorize(q, true)
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("client lạ → %d, muốn 400 (và tuyệt đối không chuyển hướng)", res.StatusCode)
	}
}

// redirect_uri ở bước ĐỔI TOKEN phải khớp URI mà mã đã được cấp cho.
func TestRedirectURIIsRecheckedAtToken(t *testing.T) {
	r := newRig(t, oidc.Options{})
	verifier := newVerifier(t)
	code := r.getCode(authQuery(verifier, "s", "n"))

	form := tokenForm(code, verifier, r.secret)
	form.Set("redirect_uri", "https://evil.tld/cb")
	res, body := r.exchange(form)
	if res.StatusCode == http.StatusOK {
		t.Fatal("đổi được token với redirect_uri KHÁC lúc cấp mã (RFC 6749 §4.1.3)")
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v", body["error"])
	}
}

// Sai client_secret → 401 invalid_client, KHÔNG phải 400 invalid_grant.
func TestWrongClientSecret(t *testing.T) {
	r := newRig(t, oidc.Options{})
	verifier := newVerifier(t)
	code := r.getCode(authQuery(verifier, "s", "n"))

	res, body := r.exchange(tokenForm(code, verifier, "sai-be-bet"))
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("= %d %v, muốn 401", res.StatusCode, body)
	}
	if body["error"] != "invalid_client" {
		t.Errorf("error = %v, muốn invalid_client — trộn với invalid_grant làm "+
			"người tích hợp đi sửa nhầm chỗ", body["error"])
	}
	if res.Header.Get("WWW-Authenticate") == "" {
		t.Error("thiếu WWW-Authenticate")
	}
}

// HTTP Basic là cách xác thực client mà chuẩn đòi mọi IdP phải nhận.
func TestClientSecretBasicWorks(t *testing.T) {
	r := newRig(t, oidc.Options{})
	verifier := newVerifier(t)
	code := r.getCode(authQuery(verifier, "s", "n"))

	form := tokenForm(code, verifier, "")
	form.Del("client_secret")
	req, err := http.NewRequest(http.MethodPost, r.srv.URL+oidc.TokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, r.secret)
	res, err := r.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("client_secret_basic = %d: %s", res.StatusCode, b)
	}
}

// Mã HẾT HẠN không đổi được token — kiểm bằng cách tua đồng hồ của Provider về
// quá khứ để mã sinh ra đã chết ngay lúc tạo.
func TestExpiredCodeIsRejected(t *testing.T) {
	past := time.Now().Add(-10 * time.Minute)
	r := newRig(t, oidc.Options{Now: func() time.Time { return past }})
	verifier := newVerifier(t)
	code := r.getCode(authQuery(verifier, "s", "n"))

	res, body := r.exchange(tokenForm(code, verifier, r.secret))
	if res.StatusCode == http.StatusOK {
		t.Fatalf("mã đã hết hạn %s mà vẫn đổi được token", oidc.CodeTTL)
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %v", body["error"])
	}
}

// Chưa đăng nhập → đẩy sang trang đăng nhập, mang theo đường quay lại.
func TestUnauthenticatedIsSentToLogin(t *testing.T) {
	r := newRig(t, oidc.Options{LoginPath: "/dang-nhap"})
	res := r.authorize(authQuery(newVerifier(t), "s", "n"), false)
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("= %d, muốn 302 về trang đăng nhập", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.HasPrefix(loc, "/dang-nhap?") {
		t.Fatalf("Location = %q, muốn /dang-nhap?…", loc)
	}
	// return_to phải giữ NGUYÊN yêu cầu uỷ quyền, nếu không thì sau khi đăng
	// nhập người dùng rơi vào trang chủ và luồng SSO đứt giữa đường.
	back, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	rt := back.Query().Get("return_to")
	if !strings.Contains(rt, "client_id="+clientID) || !strings.Contains(rt, "code_challenge") {
		t.Errorf("return_to mất tham số: %q", rt)
	}
}

// --- token: các cách giả mạo phải chết ------------------------------------------

// ID token KHÔNG dùng được làm access token.
//
// Cả hai ký bằng cùng một khoá và cùng hợp lệ về chữ ký. Khác biệt duy nhất là
// claim `typ` — và ID token là thứ RP đưa cho trình duyệt, nên nếu nó qua được
// /userinfo thì mọi RP vô tình trở thành đường phát tán quyền đọc userinfo.
func TestIDTokenIsNotAnAccessToken(t *testing.T) {
	r := newRig(t, oidc.Options{})
	verifier := newVerifier(t)
	code := r.getCode(authQuery(verifier, "s", "n"))
	_, body := r.exchange(tokenForm(code, verifier, r.secret))
	idToken, _ := body["id_token"].(string)

	res := r.rawAuth(t, oidc.UserInfoPath, idToken)
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		t.Fatal("ID token dùng được làm access token ở /userinfo")
	}
}

// `alg: none` và đổi RS256 → HS256 là hai cách giả mạo JWT kinh điển.
//
// Cả hai chỉ thành công khi bên xác minh ĐỌC `alg` từ header rồi chọn thuật
// toán theo nó. Test này chứng minh ta không làm thế.
func TestForgedAlgorithmsAreRejected(t *testing.T) {
	r := newRig(t, oidc.Options{})
	verifier := newVerifier(t)
	code := r.getCode(authQuery(verifier, "s", "n"))
	_, body := r.exchange(tokenForm(code, verifier, r.secret))
	access, _ := body["access_token"].(string)

	parts := strings.Split(access, ".")
	if len(parts) != 3 {
		t.Fatalf("access token không phải JWS compact: %q", access)
	}
	payload := parts[1]

	// alg: none — không chữ ký.
	none := b64json(t, map[string]string{"alg": "none", "typ": "JWT"}) + "." + payload + "."
	// alg: HS256 ký bằng chuỗi rỗng (kẻ tấn công sẽ ký bằng khoá công khai lấy
	// từ JWKS; ở đây chỉ cần chứng minh nhánh HS256 không tồn tại).
	hs := b64json(t, map[string]string{"alg": "HS256", "typ": "JWT"}) + "." + payload + "." + parts[2]
	// Đổi payload, giữ chữ ký cũ.
	tampered := parts[0] + "." + b64json(t, map[string]any{
		"iss": r.prov.Issuer(), "sub": "ke-tan-cong", "aud": clientID,
		"exp": time.Now().Add(time.Hour).Unix(), "typ": "at+jwt", "scope": "openid profile",
	}) + "." + parts[2]

	for name, tok := range map[string]string{
		"alg:none":    none,
		"alg:HS256":   hs,
		"đổi payload": tampered,
		"cắt chữ ký":  parts[0] + "." + parts[1] + ".",
		"rác":         "khong-phai-jwt",
	} {
		t.Run(name, func(t *testing.T) {
			res := r.rawAuth(t, oidc.UserInfoPath, tok)
			defer res.Body.Close()
			if res.StatusCode == http.StatusOK {
				b, _ := io.ReadAll(res.Body)
				t.Fatalf("token giả mạo (%s) ĐƯỢC CHẤP NHẬN: %s", name, b)
			}
		})
	}
}

// Vô hiệu hoá tài khoản phải có tác dụng NGAY, không đợi access token hết hạn.
//
// Access token là JWT nên không thu hồi trực tiếp được. Bù lại, /userinfo đọc
// LẠI user từ store — và đây là test khoá lại lý lẽ đó.
func TestDisablingUserKillsAccessImmediately(t *testing.T) {
	r := newRig(t, oidc.Options{})
	verifier := newVerifier(t)
	code := r.getCode(authQuery(verifier, "s", "n"))
	_, body := r.exchange(tokenForm(code, verifier, r.secret))
	access, _ := body["access_token"].(string)

	if info := r.getJSONAuth(t, oidc.UserInfoPath, access); info["sub"] != r.owner.ID {
		t.Fatalf("trước khi vô hiệu hoá đã không đọc được userinfo: %v", info)
	}

	u, err := r.st.GetUser(context.Background(), r.owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	u.Disabled = true
	if err := r.st.UpdateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}

	res := r.rawAuth(t, oidc.UserInfoPath, access)
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		t.Fatal("tài khoản đã bị vô hiệu mà access token vẫn đọc được userinfo — " +
			"vô hiệu hoá không có tác dụng trong tối đa một giờ")
	}
}

// --- khoá ký -----------------------------------------------------------------------

// Khoá ký phải SỐNG SÓT qua lần khởi động lại.
//
// Sinh khoá mới mỗi lần New nghĩa là mọi token đang lưu hành chết sau mỗi lần
// restart hoặc mỗi lần OTA — người dùng bị đá ra khỏi mọi app vì một lần cập nhật.
func TestSigningKeySurvivesRestart(t *testing.T) {
	r := newRig(t, oidc.Options{})
	first := r.getJSON(oidc.JWKSPath)

	// Provider MỚI trên CÙNG store — đúng như tiến trình box khởi động lại.
	again, err := oidc.New(context.Background(), r.st, oidc.Options{Issuer: r.prov.Issuer()})
	if err != nil {
		t.Fatal(err)
	}
	srv2 := httptest.NewServer(again.Handler(r.ident))
	defer srv2.Close()

	res, err := http.Get(srv2.URL + oidc.JWKSPath)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var second map[string]any
	if err := json.NewDecoder(res.Body).Decode(&second); err != nil {
		t.Fatal(err)
	}
	if kidOf(t, first) != kidOf(t, second) {
		t.Fatalf("kid đổi sau khi khởi động lại: %s → %s.\n"+
			"Mọi token đang lưu hành vừa chết vì một lần restart.",
			kidOf(t, first), kidOf(t, second))
	}
}

// Discovery không được HỨA thứ không có.
//
// `email` là ca cụ thể: bảng users chưa có cột email. Khai nó trong
// scopes_supported nghĩa là RP cấu hình xong, chạy được, rồi người dùng đầu
// tiên đăng nhập và app đó hỏng theo cách riêng của nó.
func TestDiscoveryDoesNotPromiseWhatIsMissing(t *testing.T) {
	r := newRig(t, oidc.Options{})
	disco := r.getJSON(oidc.DiscoveryPath)

	scopes := toStrings(disco["scopes_supported"])
	for _, s := range scopes {
		if s == "email" {
			t.Error("discovery khai scope email trong khi bảng users không có cột email")
		}
	}
	if len(scopes) == 0 {
		t.Error("scopes_supported rỗng")
	}
	// Chỉ S256 — công bố `plain` là mời RP dùng PKCE trên giấy.
	if m := toStrings(disco["code_challenge_methods_supported"]); len(m) != 1 || m[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v, muốn đúng [S256]", m)
	}
	// Chỉ authorization_code — implicit trả token qua thanh địa chỉ.
	if g := toStrings(disco["grant_types_supported"]); len(g) != 1 || g[0] != "authorization_code" {
		t.Errorf("grant_types_supported = %v", g)
	}
	if rt := toStrings(disco["response_types_supported"]); len(rt) != 1 || rt[0] != "code" {
		t.Errorf("response_types_supported = %v", rt)
	}
}

// Client secret KHÔNG được nằm trong bảng oidc_clients.
//
// Cùng luật với AppAddon.ConfigRef và User.TOTPRef: cột chỉ giữ khoá tra cứu,
// bí mật nằm sau master.key.
func TestClientSecretIsNotStoredInTheClientRow(t *testing.T) {
	r := newRig(t, oidc.Options{})
	c, err := r.st.GetOIDCClient(context.Background(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c.SecretRef, r.secret) {
		t.Fatal("secret_ref CHỨA chính secret")
	}
	blob, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), r.secret) {
		t.Fatalf("secret lọt vào JSON của bản ghi client: %s", blob)
	}
	// Và nó phải đọc lại được qua bảng secrets (tức là đã được mã hoá ở đó).
	raw, err := r.st.GetSecret(context.Background(), c.SecretRef)
	if err != nil {
		t.Fatalf("secret không nằm trong bảng secrets: %v", err)
	}
	if string(raw) != r.secret {
		t.Error("secret trong bảng secrets khác secret đã trả về")
	}
}

// redirect_uri NGUY HIỂM bị từ chối ngay lúc ĐĂNG KÝ, không phải lúc dùng.
func TestRegisterClientRejectsDangerousRedirectURIs(t *testing.T) {
	r := newRig(t, oidc.Options{})
	ctx := context.Background()
	for _, bad := range []string{
		"https://app.example.com/*",    // wildcard
		"/login/callback",              // tương đối
		"app.example.com/cb",           // không có scheme
		"https://app.example.com/cb#x", // fragment
		"",
	} {
		if _, err := r.prov.RegisterClient(ctx, "c-"+bad, "", "x", []string{bad}); err == nil {
			t.Errorf("redirect_uri %q được đăng ký", bad)
		}
	}
	if _, err := r.prov.RegisterClient(ctx, "c-empty", "", "x", nil); err == nil {
		t.Error("client KHÔNG có redirect_uri nào được đăng ký")
	}
}

// --- helper: phía RP, không dùng code của package oidc -----------------------------

func (r *rig) getJSON(path string) map[string]any {
	r.t.Helper()
	res, err := http.Get(r.srv.URL + path)
	if err != nil {
		r.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		r.t.Fatalf("GET %s: %v", path, err)
	}
	return out
}

func (r *rig) rawAuth(t *testing.T, path, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, r.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := r.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func (r *rig) getJSONAuth(t *testing.T, path, token string) map[string]any {
	t.Helper()
	res := r.rawAuth(t, path, token)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("GET %s = %d: %s", path, res.StatusCode, b)
	}
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// verifyWithJWKS xác minh ID token bằng khoá lấy từ /jwks.json.
//
// Đây là ĐOẠN CODE CỦA RP, viết lại từ đầu bằng stdlib: nó không gọi hàm nào
// của package oidc. Nếu package công bố một kid khác với kid nó ký, hoặc mã hoá
// modulus/số mũ sai, thì chỉ chỗ này bắt được — cả hai phía của package đều
// thấy nhau hợp lệ.
func (r *rig) verifyWithJWKS(t *testing.T, token string) map[string]any {
	t.Helper()
	jwks := r.getJSON(oidc.JWKSPath)

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("không phải JWS compact: %q", token)
	}
	var head struct{ Alg, Kid string }
	mustB64JSON(t, parts[0], &head)
	if head.Alg != "RS256" {
		t.Fatalf("alg = %q, RP chỉ chấp nhận RS256", head.Alg)
	}

	pub := findKey(t, jwks, head.Kid)
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("chữ ký ID token KHÔNG khớp khoá trong JWKS: %v", err)
	}

	var claims map[string]any
	mustB64JSON(t, parts[1], &claims)
	if exp, ok := claims["exp"].(float64); !ok || time.Now().Unix() >= int64(exp) {
		t.Fatalf("ID token đã hết hạn hoặc thiếu exp: %v", claims["exp"])
	}
	return claims
}

// findKey dựng *rsa.PublicKey từ một entry JWKS.
func findKey(t *testing.T, jwks map[string]any, kid string) *rsa.PublicKey {
	t.Helper()
	list, _ := jwks["keys"].([]any)
	if len(list) == 0 {
		t.Fatal("JWKS rỗng")
	}
	for _, item := range list {
		m, _ := item.(map[string]any)
		if m["kid"] != kid {
			continue
		}
		if m["kty"] != "RSA" || m["alg"] != "RS256" || m["use"] != "sig" {
			t.Errorf("JWKS entry thiếu metadata: %v", m)
		}
		n := decodeB64Int(t, m["n"])
		e := decodeB64Int(t, m["e"])
		return &rsa.PublicKey{N: n, E: int(e.Int64())}
	}
	t.Fatalf("JWKS không có kid %q — token ký bằng một khoá KHÔNG được công bố", kid)
	return nil
}

func decodeB64Int(t *testing.T, v any) *big.Int {
	t.Helper()
	s, _ := v.(string)
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("giá trị JWKS %q không phải base64url: %v", s, err)
	}
	return new(big.Int).SetBytes(raw)
}

func mustB64JSON(t *testing.T, seg string, out any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("segment không phải base64url: %v", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("segment không phải JSON: %v", err)
	}
}

func b64json(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func kidOf(t *testing.T, jwks map[string]any) string {
	t.Helper()
	list, _ := jwks["keys"].([]any)
	if len(list) == 0 {
		t.Fatal("JWKS rỗng")
	}
	m, _ := list[0].(map[string]any)
	kid, _ := m["kid"].(string)
	if kid == "" {
		t.Fatal("JWKS entry không có kid — RP không chọn được khoá nào để xác minh")
	}
	return kid
}

func toStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Đường của OIDC bị VIẾT HAI LẦN — ở đây và trong httpd — vì luật §2.1 cấm httpd
// import package này. Test này là thứ duy nhất phát hiện hai bên lệch nhau.
//
// Lệch thì hỏng IM LẶNG: httpd đăng ký một đường, Provider phục vụ một đường
// khác, và SPA ở "/" nhận nốt phần còn lại — RP nhận HTTP 200 kèm HTML. Đã xảy
// ra thật, xem TestOIDCPathsAnswerJSONWhenDisabled ở package httpd.
func TestPathsMatchWhatHTTPDRegisters(t *testing.T) {
	if oidc.DiscoveryPath != httpd.OIDCDiscoveryPath {
		t.Errorf("discovery: oidc=%q httpd=%q", oidc.DiscoveryPath, httpd.OIDCDiscoveryPath)
	}
	for _, p := range []string{oidc.JWKSPath, oidc.AuthorizePath, oidc.TokenPath, oidc.UserInfoPath} {
		if !strings.HasPrefix(p, httpd.OIDCPathPrefix) {
			t.Errorf("%q không nằm dưới %q mà httpd đăng ký", p, httpd.OIDCPathPrefix)
		}
	}
}
