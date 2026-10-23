// Package authz — SCOPE và cổng kiểm quyền cho control API (ID-02).
//
// Tách khỏi identity (T10) có chủ đích: identity trả lời "anh là ai", authz trả
// lời "anh được làm gì". Hai câu hỏi đó đổi theo hai nhịp khác nhau — thêm một
// nhà cung cấp đăng nhập không được kéo theo việc viết lại bảng quyền, và thêm
// một endpoint mới không được đụng tới luồng đăng nhập.
//
// Vì vậy package này KHÔNG biết mật khẩu, session hay TOTP. Nó chỉ nhận một
// Authenticator (do main cắm vào) và áp scope.
//
// Hai thứ CÒN NỢ, ghi ở đây để không rơi:
//   - Rate-limit + lockout đăng nhập thuộc về gói này (T10), KHÔNG đẩy xuống
//     gateway: ta phải chạy được với caddy/nginx/NPM nên không được phụ thuộc
//     năng lực gateway.
//   - Trên node API (box.sock) xác thực bằng PEER CREDENTIAL của unix socket
//     chứ không phải token (ND-04, T9b) — cùng package, hai cơ chế, và cả hai
//     đều phải áp scope qua Guard.
//
// Scope enforcement là THẬT: tuyệt đối không stub principal có ['*'].
package authz

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// Scope — quyền trên một nhóm tài nguyên. Chuỗi chứ không phải bitmask: scope
// đi vào token và log, nên nó phải đọc được bằng mắt khi soát sự cố.
type Scope string

const (
	ScopeAppsRead     Scope = "apps:read"
	ScopeAppsWrite    Scope = "apps:write"
	ScopeDomainsRead  Scope = "domains:read"
	ScopeDomainsWrite Scope = "domains:write"
	ScopeEventsRead   Scope = "events:read"
	// ScopeAdmin bao hàm mọi scope khác. Có nó để chủ instance không phải liệt
	// kê lại toàn bộ bảng quyền mỗi lần ta thêm một nhóm tài nguyên mới.
	ScopeAdmin Scope = "admin"
)

// AllScopes — dùng cho kiểm tra cấu hình và cho UI hiển thị.
func AllScopes() []Scope {
	return []Scope{ScopeAppsRead, ScopeAppsWrite, ScopeDomainsRead, ScopeDomainsWrite, ScopeEventsRead, ScopeAdmin}
}

// IsKnownScope — tên này có nằm trong bảng quyền không.
//
// Cần ở ĐẦU VÀO (lúc phát token), không phải lúc kiểm quyền. Lúc kiểm quyền,
// một scope lạ tự nhiên không khớp gì nên vô hại. Nhưng lúc phát token thì
// chấp nhận nó im lặng là một cái bẫy: người vận hành gõ "apps:writes", nhận
// 201, và phát hiện token không làm được gì vào lúc job CI đỏ lúc 3 giờ sáng —
// với một thông báo lỗi không hề nhắc tới chữ "scope".
func IsKnownScope(s Scope) bool {
	for _, known := range AllScopes() {
		if s == known {
			return true
		}
	}
	return false
}

var (
	// ErrUnauthenticated — không có/ sai thông tin xác thực → 401.
	ErrUnauthenticated = errors.New("authz: not authenticated")
	// ErrForbidden — đã xác thực nhưng thiếu scope → 403.
	//
	// Phân biệt 401/403 không phải chuyện thẩm mỹ: 401 bảo client đi đăng nhập
	// lại, 403 bảo nó đừng thử nữa. Gộp thành một sẽ khiến UI quay vòng đăng
	// nhập vô hạn khi người dùng chỉ đơn giản là insufficient permissions.
	ErrForbidden = errors.New("authz: insufficient permissions")
)

// Principal — chủ thể đã xác thực.
type Principal struct {
	Subject string
	Scopes  []Scope
	// TokenID — id API token đã dùng, rỗng khi vào bằng phiên trình duyệt.
	// Có nó để log sự cố trả lời được "token nào đã làm việc này", chứ không
	// dừng ở "user nào" — một user có thể có mười token và chỉ một cái bị lộ.
	TokenID string
}

// Has — ScopeAdmin bao hàm tất cả.
func (p Principal) Has(want Scope) bool { return Grants(p.Scopes, want) }

// Grants — LUẬT BAO HÀM, và là chỗ DUY NHẤT định nghĩa nó.
//
// Có hàm riêng vì luật này bị cần ở ngoài vòng request: identity phải biết một
// user `admin` có được phát token `apps:read` không (có — hẹp hơn thì luôn
// được). Nếu identity tự so chuỗi thì chủ instance, vốn chỉ mang đúng scope
// `admin`, sẽ không tạo nổi một token hẹp — và tính năng giới hạn quyền hoá ra
// chỉ dùng được bởi người không cần tới nó.
func Grants(have []Scope, want Scope) bool {
	for _, s := range have {
		if s == want || s == ScopeAdmin {
			return true
		}
	}
	return false
}

// ScopesFromStrings chuyển dạng lưu trong store sang kiểu Scope.
//
// KHÔNG lọc tên lạ: một scope không còn được nhận ra phải đi tiếp tới Grants
// và thất bại ở đó, chứ không biến mất im lặng ở đây — biến mất im lặng nghĩa
// là gỡ một scope khỏi code sẽ âm thầm NỚI quyền của mọi token đang mang nó.
func ScopesFromStrings(in []string) []Scope {
	out := make([]Scope, 0, len(in))
	for _, s := range in {
		out = append(out, Scope(s))
	}
	return out
}

type ctxKey struct{}

// WithPrincipal / FromContext — truyền principal qua ctx.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext trả principal; ok=false nghĩa là request CHƯA qua middleware.
//
// Handler phải coi ok=false là lỗi lập trình chứ không phải "khách vãng lai":
// nhầm hai thứ đó là cách một endpoint lọt ra ngoài vòng kiểm quyền mà không ai
// nhận ra cho tới lúc bị khai thác.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

// Authenticator — seam sang identity (T10). Trả ErrUnauthenticated khi không
// nhận diện được; lỗi khác coi là lỗi hệ thống (500).
type Authenticator interface {
	Authenticate(r *http.Request) (Principal, error)
}

// AuthenticatorFunc để main cắm hàm thay vì phải khai một kiểu.
type AuthenticatorFunc func(r *http.Request) (Principal, error)

func (f AuthenticatorFunc) Authenticate(r *http.Request) (Principal, error) { return f(r) }

// Any thử lần lượt nhiều Authenticator, nhận cái đầu tiên thành công.
//
// Dùng cho giai đoạn chuyển tiếp: khi instance CHƯA có chủ, cả session lẫn
// bootstrap token đều phải dùng được, vì bootstrap token là cách duy nhất để
// chạy luồng thiết lập lần đầu từ CLI.
//
// Lỗi trả về là lỗi của cái CUỐI CÙNG, nhưng ErrUnauthenticated được ưu tiên
// giữ: một authenticator hỏng vì store không được phép biến "chưa đăng nhập"
// thành 500 và làm UI hiển thị sự cố thay vì màn hình đăng nhập.
func Any(auths ...Authenticator) Authenticator {
	return AuthenticatorFunc(func(r *http.Request) (Principal, error) {
		var lastErr error = ErrUnauthenticated
		for _, a := range auths {
			p, err := a.Authenticate(r)
			if err == nil {
				return p, nil
			}
			if !errors.Is(err, ErrUnauthenticated) {
				lastErr = err
			}
		}
		return Principal{}, lastErr
	})
}

// BearerToken lấy token từ header Authorization; "" nếu không có.
func BearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// Guard bọc Authenticator và sinh middleware theo scope.
type Guard struct {
	auth Authenticator
	// OnError để caller quyết cách trả lỗi (JSON của package api).
	OnError func(w http.ResponseWriter, r *http.Request, err error)
}

func NewGuard(auth Authenticator, onError func(http.ResponseWriter, *http.Request, error)) *Guard {
	return &Guard{auth: auth, OnError: onError}
}

// Require trả middleware yêu cầu scope.
//
// Xác thực chạy TRONG middleware chứ không phải ở một middleware riêng phía
// trước: gộp lại thì không thể tồn tại một route đã xác thực mà quên áp scope —
// muốn gắn handler vào Guard là buộc phải nêu scope.
func (g *Guard) Require(scope Scope, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := g.auth.Authenticate(r)
		if err != nil {
			g.fail(w, r, err)
			return
		}
		if !p.Has(scope) {
			g.fail(w, r, ErrForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// RequireFunc — dạng tiện cho handler func.
func (g *Guard) RequireFunc(scope Scope, next http.HandlerFunc) http.Handler {
	return g.Require(scope, next)
}

func (g *Guard) fail(w http.ResponseWriter, r *http.Request, err error) {
	if g.OnError != nil {
		g.OnError(w, r, err)
		return
	}
	code := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrUnauthenticated):
		code = http.StatusUnauthorized
	case errors.Is(err, ErrForbidden):
		code = http.StatusForbidden
	}
	http.Error(w, http.StatusText(code), code)
}
