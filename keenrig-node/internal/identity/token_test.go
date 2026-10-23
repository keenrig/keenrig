package identity_test

// Test ID-04 — "Token: expiry, revoke, allowed_ip_cidrs chặn đúng IP".
//
// Ba tính chất trong tên testcase là ba đường thất bại KHÁC NHAU, nên mỗi cái
// một test: hết hạn (thời gian), thu hồi (hành động của người vận hành), sai IP
// (vị trí người gọi). Gộp lại thành một test "token xấu bị chặn" sẽ vẫn xanh
// khi hai trong ba đường hỏng.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/authz"
	"github.com/keenrig/keenrig/keenrig-node/internal/identity"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// authAs gọi Authenticate với một request mang bearer token từ IP cho trước.
//
// net.JoinHostPort chứ không phải ip+":port": IPv6 phải có ngoặc vuông, và
// "2001:db8::1:54321" là một chuỗi net.SplitHostPort không đọc được — test sẽ
// đỏ vì harness sai chứ không vì sản phẩm sai. Server HTTP thật luôn đặt
// RemoteAddr đúng dạng này.
func authAs(t *testing.T, s *identity.Service, token, ip string) (authz.Principal, error) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/apps", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.RemoteAddr = net.JoinHostPort(ip, "54321")
	return s.Authenticate(r)
}

func TestTokenAuthenticatesAndCarriesScopes(t *testing.T) {
	s, _ := setup(t, identity.Options{})
	ctx := context.Background()
	u := mustOwner(t, s)

	raw, tok, err := s.CreateToken(ctx, u.ID, identity.NewTokenInput{
		Name:   "CI deploy",
		Scopes: []authz.Scope{authz.ScopeAppsRead, authz.ScopeAppsWrite},
	})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if !strings.HasPrefix(raw, identity.TokenPrefix) {
		t.Errorf("token %q thiếu tiền tố %q — trình quét bí mật sẽ không bắt được nó", raw, identity.TokenPrefix)
	}

	p, err := authAs(t, s, raw, "203.0.113.9")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Subject != u.ID {
		t.Errorf("Subject = %q, muốn %q", p.Subject, u.ID)
	}
	if p.TokenID != tok.ID {
		t.Errorf("TokenID = %q, muốn %q — không có nó thì log không nói được token NÀO bị lộ", p.TokenID, tok.ID)
	}
	if !p.Has(authz.ScopeAppsWrite) {
		t.Errorf("thiếu scope apps:write: %v", p.Scopes)
	}
	// Chủ instance có `admin`, nhưng token này KHÔNG xin admin — nên nó không
	// được có. Đây chính là điểm của việc phát token hẹp.
	if p.Has(authz.ScopeEventsRead) {
		t.Errorf("token hẹp lại mang quyền không xin: %v", p.Scopes)
	}
}

// Token trần chỉ trả về ĐÚNG MỘT LẦN. Store chỉ giữ hash.
func TestTokenPlaintextNeverStored(t *testing.T) {
	s, st := setup(t, identity.Options{})
	ctx := context.Background()
	u := mustOwner(t, s)

	raw, _, err := s.CreateToken(ctx, u.ID, identity.NewTokenInput{})
	if err != nil {
		t.Fatal(err)
	}
	list, err := st.ListAPITokens(ctx, u.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListAPITokens = %d, %v", len(list), err)
	}
	if list[0].TokenHash == raw {
		t.Fatal("store giữ token TRẦN — ai đọc được một bản backup là gọi được API")
	}
	// Và không lọt vào event.
	evs, _ := st.ListEvents(ctx, 50)
	for _, e := range evs {
		if strings.Contains(string(e.Data), raw) {
			t.Fatalf("token trần lọt vào event %q (SEC-04)", e.Action)
		}
	}
}

// --- expiry ---------------------------------------------------------------------

func TestTokenExpires(t *testing.T) {
	clock := time.Now()
	s, _ := setup(t, identity.Options{Now: func() time.Time { return clock }})
	ctx := context.Background()
	u := mustOwner(t, s)

	// Test này ngủ THẬT vì store lọc hạn bằng chuỗi thời gian của chính nó,
	// không qua Options.Now — tua clock ở đây sẽ không đổi gì và test thành ra
	// chứng minh một điều khác với điều nó nói.
	//
	// Ngủ bao lâu là SỐ HỌC, không phải phỏng đoán. expires_at được làm tròn
	// LÊN giây (§0.5) nên nó ≤ now+TTL+1; so sánh dùng nowSecond() bị làm tròn
	// XUỐNG nên nó ≥ now+sleep−1. Cần now+sleep−1 ≥ now+TTL+1, tức:
	//
	//	sleep ≥ TTL + 2
	//
	// Với TTL 1s thì 3.1s là biên an toàn nhỏ nhất. Chọn 2.1s (số trực giác
	// "TTL cộng chút") sẽ đỏ ngẫu nhiên tuỳ vào phần lẻ của giây lúc chạy.
	const ttl = time.Second
	raw, _, err := s.CreateToken(ctx, u.ID, identity.NewTokenInput{TTL: ttl})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authAs(t, s, raw, "203.0.113.9"); err != nil {
		t.Fatalf("token còn hạn bị từ chối: %v", err)
	}

	time.Sleep(ttl + 2100*time.Millisecond)
	if _, err := authAs(t, s, raw, "203.0.113.9"); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Errorf("token hết hạn vẫn vào được: err = %v", err)
	}
}

func TestTokenTTLDefaultAndCeiling(t *testing.T) {
	clock := time.Now()
	s, _ := setup(t, identity.Options{Now: func() time.Time { return clock }})
	ctx := context.Background()
	u := mustOwner(t, s)

	_, tok, err := s.CreateToken(ctx, u.ID, identity.NewTokenInput{}) // TTL bỏ trống
	if err != nil {
		t.Fatal(err)
	}
	want := clock.Add(identity.DefaultTokenTTL)
	if d := tok.ExpiresAt.Sub(want); d > time.Second || d < -time.Second {
		t.Errorf("hạn mặc định = %v, muốn ~%v", tok.ExpiresAt, want)
	}

	// Vượt trần phải bị TỪ CHỐI, không phải bị cắt xuống im lặng: cắt im lặng
	// thì người dùng tin token sống 5 năm và ngạc nhiên vào năm sau.
	if _, _, err := s.CreateToken(ctx, u.ID, identity.NewTokenInput{
		TTL: identity.MaxTokenTTL + time.Hour,
	}); !errors.Is(err, identity.ErrTTLTooLong) {
		t.Errorf("TTL vượt trần = %v, muốn ErrTTLTooLong", err)
	}
}

// --- revoke ---------------------------------------------------------------------

func TestTokenRevokeIsImmediate(t *testing.T) {
	s, _ := setup(t, identity.Options{})
	ctx := context.Background()
	u := mustOwner(t, s)

	raw, tok, err := s.CreateToken(ctx, u.ID, identity.NewTokenInput{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authAs(t, s, raw, "203.0.113.9"); err != nil {
		t.Fatalf("token mới bị từ chối: %v", err)
	}

	if err := s.RevokeToken(ctx, u.ID, tok.ID); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	// NGAY lập tức, không có cửa sổ ân hạn: thu hồi vì nghi bị lộ mà còn hiệu
	// lực thêm vài phút thì thu hồi gần như vô nghĩa.
	if _, err := authAs(t, s, raw, "203.0.113.9"); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Errorf("token đã thu hồi vẫn vào được: err = %v", err)
	}
	if err := s.RevokeToken(ctx, u.ID, tok.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("thu hồi lần hai = %v, muốn ErrNotFound", err)
	}
}

// Đổi mật khẩu giết mọi PHIÊN nhưng KHÔNG giết token — nếu không thì mọi script
// CI của người vận hành hỏng mỗi lần họ đổi mật khẩu, và họ sẽ ngừng đổi.
func TestPasswordChangeKeepsTokensKillsSessions(t *testing.T) {
	s, _ := setup(t, identity.Options{})
	ctx := context.Background()
	u := mustOwner(t, s)

	sessToken, _, err := s.Login(ctx, identity.LoginInput{Username: "alice", Password: goodPass})
	if err != nil {
		t.Fatal(err)
	}
	apiToken, _, err := s.CreateToken(ctx, u.ID, identity.NewTokenInput{})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.ChangePassword(ctx, u.ID, goodPass, "mật-khẩu-mới-đủ-dài"); err != nil {
		t.Fatal(err)
	}

	if _, err := authAs(t, s, sessToken, "203.0.113.9"); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Errorf("phiên sống sót qua lần đổi mật khẩu: %v", err)
	}
	if _, err := authAs(t, s, apiToken, "203.0.113.9"); err != nil {
		t.Errorf("token API chết theo mật khẩu — CI của người vận hành sẽ đỏ: %v", err)
	}
}

// --- allowed_ip_cidrs -------------------------------------------------------------

func TestTokenIPRestriction(t *testing.T) {
	s, st := setup(t, identity.Options{})
	ctx := context.Background()
	u := mustOwner(t, s)

	raw, _, err := s.CreateToken(ctx, u.ID, identity.NewTokenInput{
		// Trộn CIDR, IP trần và IPv6 — cả ba dạng người vận hành thật sự gõ.
		AllowedIPCIDRs: []string{"10.0.0.0/8", "203.0.113.7", "2001:db8::/32"},
	})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	allowed := []string{"10.1.2.3", "10.255.255.255", "203.0.113.7", "2001:db8::1"}
	for _, ip := range allowed {
		if _, err := authAs(t, s, raw, ip); err != nil {
			t.Errorf("IP %s trong dải cho phép bị chặn: %v", ip, err)
		}
	}
	denied := []string{"11.0.0.1", "203.0.113.8", "2001:db9::1", "127.0.0.1"}
	for _, ip := range denied {
		if _, err := authAs(t, s, raw, ip); !errors.Is(err, authz.ErrUnauthenticated) {
			t.Errorf("IP %s ngoài dải vẫn vào được: err = %v", ip, err)
		}
	}

	// Lần bị chặn phải để lại VẾT có token_id — "có ai đó gọi sai IP" thì không
	// hành động được, "token tok-X bị dùng từ 11.0.0.1" thì có.
	evs, _ := st.ListEvents(ctx, 100)
	found := false
	for _, e := range evs {
		if e.Action == "identity.token_ip_denied" && strings.Contains(string(e.Data), "11.0.0.1") {
			found = true
		}
	}
	if !found {
		t.Error("không có event identity.token_ip_denied — người vận hành không thấy gì")
	}
}

// Danh sách rỗng = MỌI IP. Mặc định-cấm sẽ làm mọi token vừa tạo đều chết và
// người dùng học cách điền 0.0.0.0/0 — biến tính năng thành nghi thức.
func TestTokenNoIPRestrictionAllowsAll(t *testing.T) {
	s, _ := setup(t, identity.Options{})
	ctx := context.Background()
	u := mustOwner(t, s)

	raw, _, err := s.CreateToken(ctx, u.ID, identity.NewTokenInput{})
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"127.0.0.1", "8.8.8.8", "2001:db8::1"} {
		if _, err := authAs(t, s, raw, ip); err != nil {
			t.Errorf("IP %s bị chặn dù token không giới hạn IP: %v", ip, err)
		}
	}
}

// CIDR sai cú pháp bị bắt LÚC TẠO. Bắt lúc dùng nghĩa là dải gõ nhầm âm thầm
// thành "chặn tất cả", và người vận hành phát hiện lúc 3 giờ sáng.
func TestBadCIDRRejectedAtCreate(t *testing.T) {
	s, _ := setup(t, identity.Options{})
	ctx := context.Background()
	u := mustOwner(t, s)

	bad := []string{"10.0.0.0/33", "không-phải-ip", "10.0.0.0/8/8", "10.0.0.1,10.0.0.2", "/24"}
	for _, c := range bad {
		if _, _, err := s.CreateToken(ctx, u.ID, identity.NewTokenInput{
			AllowedIPCIDRs: []string{c},
		}); !errors.Is(err, identity.ErrBadCIDR) {
			t.Errorf("CIDR %q được chấp nhận (err = %v)", c, err)
		}
	}
}

// --- scope là tập con ---------------------------------------------------------------

// Đây là tính chất an ninh cốt lõi của ID-04: token không bao giờ rộng hơn
// người tạo. Không có nó thì một user quyền hẹp tự cấp cho mình token admin —
// leo thang quyền bằng chính tính năng dùng để giới hạn quyền.
func TestTokenCannotEscalateScope(t *testing.T) {
	s, st := setup(t, identity.Options{})
	ctx := context.Background()
	mustOwner(t, s) // chủ, có admin

	narrow := &store.User{
		ID: "u-narrow", Username: "reader", PasswordHash: "x",
		Scopes: []string{string(authz.ScopeAppsRead)},
	}
	if err := st.CreateUser(ctx, narrow); err != nil {
		t.Fatal(err)
	}

	for _, want := range []authz.Scope{authz.ScopeAdmin, authz.ScopeAppsWrite, authz.ScopeDomainsWrite} {
		if _, _, err := s.CreateToken(ctx, narrow.ID, identity.NewTokenInput{
			Scopes: []authz.Scope{want},
		}); !errors.Is(err, identity.ErrScopeEscalation) {
			t.Errorf("user apps:read phát được token %q: err = %v", want, err)
		}
	}
	// Nhưng scope mình CÓ thì được.
	if _, _, err := s.CreateToken(ctx, narrow.ID, identity.NewTokenInput{
		Scopes: []authz.Scope{authz.ScopeAppsRead},
	}); err != nil {
		t.Errorf("user apps:read không phát được token apps:read: %v", err)
	}
}

// Chủ instance chỉ mang đúng scope `admin`, nhưng `admin` BAO HÀM mọi scope —
// nên họ phải phát được token hẹp. Nếu so chuỗi thay vì dùng luật bao hàm thì
// người duy nhất cần phát token hẹp lại là người không phát được.
func TestAdminCanMintNarrowToken(t *testing.T) {
	s, _ := setup(t, identity.Options{})
	ctx := context.Background()
	u := mustOwner(t, s)

	raw, _, err := s.CreateToken(ctx, u.ID, identity.NewTokenInput{
		Scopes: []authz.Scope{authz.ScopeAppsRead},
	})
	if err != nil {
		t.Fatalf("chủ instance không phát được token hẹp: %v", err)
	}
	p, err := authAs(t, s, raw, "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if p.Has(authz.ScopeAdmin) {
		t.Error("token hẹp lại mang quyền admin — mọi giới hạn scope là vô nghĩa")
	}
	if !p.Has(authz.ScopeAppsRead) {
		t.Errorf("thiếu scope đã xin: %v", p.Scopes)
	}
}

// Hạ quyền user phải hạ luôn quyền token đã phát. Không có điều này thì việc
// hạ quyền một tài khoản gần như vô nghĩa — token cũ vẫn giữ quyền cũ.
func TestUserDowngradeShrinksToken(t *testing.T) {
	s, st := setup(t, identity.Options{})
	ctx := context.Background()
	u := mustOwner(t, s)

	raw, _, err := s.CreateToken(ctx, u.ID, identity.NewTokenInput{
		Scopes: []authz.Scope{authz.ScopeAppsRead, authz.ScopeAppsWrite},
	})
	if err != nil {
		t.Fatal(err)
	}

	u.Scopes = []string{string(authz.ScopeAppsRead)} // hạ quyền
	if err := st.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}

	p, err := authAs(t, s, raw, "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if p.Has(authz.ScopeAppsWrite) {
		t.Errorf("token giữ quyền đã bị gỡ khỏi user: %v", p.Scopes)
	}
	if !p.Has(authz.ScopeAppsRead) {
		t.Errorf("token mất luôn quyền vẫn còn: %v", p.Scopes)
	}
}

// User bị vô hiệu → token của họ chết ngay, không đợi hết hạn.
func TestDisabledUserTokenRejected(t *testing.T) {
	s, st := setup(t, identity.Options{})
	ctx := context.Background()
	u := mustOwner(t, s)

	raw, _, err := s.CreateToken(ctx, u.ID, identity.NewTokenInput{})
	if err != nil {
		t.Fatal(err)
	}
	u.Disabled = true
	if err := st.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := authAs(t, s, raw, "203.0.113.9"); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Errorf("token của user bị vô hiệu vẫn vào được: %v", err)
	}
}

// Token API và cookie phiên KHÔNG lẫn nhau: dán token API vào cookie phiên
// không được coi là đăng nhập, và ngược lại.
func TestTokenAndSessionDoNotCrossOver(t *testing.T) {
	s, _ := setup(t, identity.Options{})
	ctx := context.Background()
	u := mustOwner(t, s)

	sessToken, _, err := s.Login(ctx, identity.LoginInput{Username: "alice", Password: goodPass})
	if err != nil {
		t.Fatal(err)
	}
	apiToken, _, err := s.CreateToken(ctx, u.ID, identity.NewTokenInput{})
	if err != nil {
		t.Fatal(err)
	}

	// Token API bị băm rồi tra bảng sessions → không khớp. Ngược lại, token
	// phiên không có tiền tố nên không bao giờ tới đường api_tokens.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/apps", nil)
	r.AddCookie(&http.Cookie{Name: s.CookieName(), Value: apiToken})
	r.RemoteAddr = net.JoinHostPort("203.0.113.9", "1")
	if p, err := s.Authenticate(r); err == nil {
		// Chấp nhận được: token API trong cookie vẫn là token API hợp lệ. Điều
		// PHẢI đúng là nó không được biến thành một phiên trình duyệt (TokenID
		// còn nguyên) — nếu không thì mất dấu vết token trong log.
		if p.TokenID == "" {
			t.Error("token API trong cookie bị coi là phiên — mất dấu vết token")
		}
	}

	if p, err := authAs(t, s, sessToken, "203.0.113.9"); err != nil {
		t.Errorf("token phiên qua bearer bị từ chối: %v", err)
	} else if p.TokenID != "" {
		t.Errorf("phiên lại mang TokenID %q", p.TokenID)
	}
}
