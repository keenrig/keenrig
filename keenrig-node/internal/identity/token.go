package identity

// API token (ID-04) — bí mật dài hạn cho script, CI và CLI.
//
// # Ba ràng buộc, mỗi cái đóng một lỗ cụ thể
//
//  1. HẠN BẮT BUỘC. Không tồn tại token vô hạn. Một token rò vào git history
//     mà không hết hạn là một cánh cửa mở suốt đời instance; có hạn thì cánh
//     cửa tự đóng kể cả khi không ai phát hiện ra vụ rò.
//
//  2. SCOPE LÀ TẬP CON. Token không bao giờ mang quyền rộng hơn người tạo ra
//     nó tại thời điểm tạo. Không có ràng buộc này thì một user quyền hẹp tự
//     cấp cho mình một token `admin` — leo thang quyền bằng đúng tính năng
//     dùng để giới hạn quyền.
//
//  3. GIỚI HẠN IP LÀ TUỲ CHỌN, MẶC ĐỊNH MỞ. Rỗng = mọi IP. Mặc định-cấm nghe
//     an toàn hơn nhưng làm mọi token vừa tạo đều chết, và người dùng sẽ học
//     cách điền 0.0.0.0/0 — biến tính năng thành nghi thức.
//
// # Token bị chặn IP trả ErrInvalidToken, không phải một lỗi riêng
//
// Người gọi đã cầm token thì việc nói cho họ biết "token đúng nhưng sai IP"
// không lộ thêm gì. Ta vẫn gộp làm một vì tầng trên chỉ cần biết "không cho
// vào", còn lý do thật thì ghi vào event — nơi người vận hành đọc, chứ không
// phải nơi kẻ tấn công đọc.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/authz"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

var (
	// ErrInvalidToken — token không tồn tại, đã hết hạn, đã thu hồi, hoặc gọi
	// từ IP không được phép.
	ErrInvalidToken = errors.New("identity: invalid token")
	// ErrScopeEscalation — xin scope rộng hơn quyền của chính mình.
	ErrScopeEscalation = errors.New("identity: a token may not request broader scopes than its creator holds")
	// ErrUnknownScope — tên scope không có trong bảng quyền (thường là gõ nhầm).
	//
	// Tách khỏi ErrScopeEscalation vì hai lỗi này cần hai hành động khác nhau:
	// escalation nghĩa là "xin ít quyền hơn", unknown nghĩa là "gõ lại cho
	// đúng". Gộp làm một sẽ khiến người gõ nhầm đi tìm quyền admin.
	ErrUnknownScope = errors.New("identity: no such scope")
	// ErrBadCIDR — dải IP sai cú pháp.
	ErrBadCIDR = errors.New("identity: invalid IP range")
	// ErrTTLTooLong — hạn vượt trần.
	ErrTTLTooLong = fmt.Errorf("identity: the token lifetime exceeds the %s cap", MaxTokenTTL)
)

const (
	// TokenPrefix — tiền tố nhận dạng.
	//
	// Có nó vì hai lý do thực dụng: (a) trình quét bí mật (gitleaks, GitHub
	// secret scanning) cần một mẫu ổn định để bắt token lọt vào commit; (b)
	// Authenticate phân luồng được phiên/token bằng tiền tố, khỏi phải tra hai
	// bảng cho mỗi request.
	TokenPrefix = "spu_"

	// DefaultTokenTTL / MaxTokenTTL — hạn mặc định và trần.
	//
	// 90 ngày đủ dài để không phiền người dùng mỗi quý, đủ ngắn để một token
	// bị bỏ quên tự chết trong vòng một mùa. Trần 1 năm là ranh giới cứng:
	// muốn lâu hơn thì phải quay lại tạo mới, và lần quay lại đó chính là dịp
	// nhìn lại xem token còn cần không.
	DefaultTokenTTL = 90 * 24 * time.Hour
	MaxTokenTTL     = 365 * 24 * time.Hour

	tokenSecretLen = 32
	maxTokenName   = 100
)

// NewTokenInput — thứ handler thu được từ request.
type NewTokenInput struct {
	Name string
	// Scopes — quyền của token. Rỗng → kế thừa TOÀN BỘ quyền của user.
	Scopes []authz.Scope
	// TTL — hạn. <= 0 → DefaultTokenTTL. > MaxTokenTTL → ErrTTLTooLong.
	TTL time.Duration
	// AllowedIPCIDRs — dải được phép; rỗng = mọi IP. Chấp nhận cả IP trần
	// ("203.0.113.7") lẫn CIDR ("203.0.113.0/24") — bắt người vận hành nhớ
	// viết "/32" chỉ tạo ra lỗi gõ nhầm, không tạo ra an toàn.
	AllowedIPCIDRs []string
}

// CreateToken sinh token cho user và trả giá trị TRẦN — chỉ lần này, và không
// bao giờ lấy lại được. Store chỉ giữ hash.
func (s *Service) CreateToken(ctx context.Context, userID string, in NewTokenInput) (string, *store.APIToken, error) {
	u, err := s.st.GetUser(ctx, userID)
	if err != nil {
		return "", nil, err
	}
	if u.Disabled {
		return "", nil, ErrInvalidCredentials
	}

	scopes, err := resolveScopes(u.Scopes, in.Scopes)
	if err != nil {
		return "", nil, err
	}

	ttl := in.TTL
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	if ttl > MaxTokenTTL {
		return "", nil, ErrTTLTooLong
	}

	cidrs, err := normalizeCIDRs(in.AllowedIPCIDRs)
	if err != nil {
		return "", nil, err
	}

	raw := make([]byte, tokenSecretLen)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token := TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)

	t := &store.APIToken{
		TokenHash:      hashToken(token),
		ID:             newID(),
		UserID:         u.ID,
		Name:           truncate(strings.TrimSpace(in.Name), maxTokenName),
		Scopes:         scopes,
		ExpiresAt:      s.opts.Now().Add(ttl),
		AllowedIPCIDRs: cidrs,
	}
	if err := s.st.CreateAPIToken(ctx, t); err != nil {
		return "", nil, err
	}
	// Event KHÔNG mang token lẫn hash — chỉ id, tên và quyền (SEC-04).
	s.event(ctx, "identity.token_created", u.ID, map[string]any{
		"token_id": t.ID, "name": t.Name, "scopes": t.Scopes, "expires_at": t.ExpiresAt,
	})
	return token, t, nil
}

// resolveScopes ép quy tắc TẬP CON. want rỗng → kế thừa toàn bộ quyền của user.
//
// Luật bao hàm lấy từ authz.Grants — KHÔNG so chuỗi tại chỗ. Tự so chuỗi ở đây
// thì một chủ instance (chỉ mang scope `admin`) sẽ bị từ chối khi xin token
// `apps:read`, tức là người duy nhất cần phát token hẹp lại không phát được.
func resolveScopes(userScopes []string, want []authz.Scope) ([]string, error) {
	have := authz.ScopesFromStrings(userScopes)
	if len(want) == 0 {
		out := make([]string, len(userScopes))
		copy(out, userScopes)
		return out, nil
	}
	out := make([]string, 0, len(want))
	for _, sc := range want {
		// Kiểm "có tồn tại" TRƯỚC "có được phép": chủ instance mang `admin` nên
		// Grants nói CÓ với mọi chuỗi, kể cả chuỗi gõ nhầm. Đảo hai bước này
		// thì "apps:writes" được cấp thành công và token im lặng không có quyền.
		if !authz.IsKnownScope(sc) {
			return nil, fmt.Errorf("%w: %q", ErrUnknownScope, sc)
		}
		if !authz.Grants(have, sc) {
			return nil, fmt.Errorf("%w: %q", ErrScopeEscalation, sc)
		}
		out = append(out, string(sc))
	}
	return out, nil
}

// normalizeCIDRs kiểm cú pháp NGAY LÚC TẠO.
//
// Kiểm lúc dùng thay vì lúc tạo nghĩa là một dải gõ sai âm thầm biến thành
// "chặn tất cả", và người vận hành phát hiện ra vào lúc job CI của họ đỏ lúc
// 3 giờ sáng chứ không phải lúc họ bấm nút tạo.
func normalizeCIDRs(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if strings.Contains(v, ",") {
			// CSV là định dạng lưu; nhận nó ở đây sẽ tạo một phần tử chứa dấu
			// phẩy và phá vỡ vòng lặp so khớp một cách im lặng.
			return nil, fmt.Errorf("%w: %q contains a comma", ErrBadCIDR, v)
		}
		p, err := parseCIDROrIP(v)
		if err != nil {
			return nil, fmt.Errorf("%w: %q", ErrBadCIDR, v)
		}
		out = append(out, p.String())
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// parseCIDROrIP nhận cả "10.0.0.0/8" lẫn "10.0.0.1" (thành /32, /128).
func parseCIDROrIP(v string) (netip.Prefix, error) {
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return netip.Prefix{}, err
		}
		// Masked() để "10.0.0.5/8" được lưu thành "10.0.0.0/8" — giữ nguyên
		// dạng người gõ sẽ làm hai dải giống hệt nhau trông khác nhau trong UI.
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()), nil
}

// ipAllowed — rỗng = mọi IP.
//
// IP không phân giải được trả FALSE khi có danh sách: không biết người gọi ở
// đâu thì không thể khẳng định họ ở trong dải, và "không biết" phải nghiêng về
// từ chối ở đúng chỗ này.
func ipAllowed(cidrs []string, ip string) bool {
	if len(cidrs) == 0 {
		return true
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			continue // dải hỏng trong DB: bỏ qua, không mở toang
		}
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ListTokens trả token của user, gồm cả token đã hết hạn.
func (s *Service) ListTokens(ctx context.Context, userID string) ([]*store.APIToken, error) {
	return s.st.ListAPITokens(ctx, userID)
}

// RevokeToken thu hồi THẬT (xoá row). Thu hồi hai lần không phải lỗi.
func (s *Service) RevokeToken(ctx context.Context, userID, tokenID string) error {
	err := s.st.DeleteAPIToken(ctx, userID, tokenID)
	if errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err != nil {
		return err
	}
	s.event(ctx, "identity.token_revoked", userID, map[string]any{"token_id": tokenID})
	return nil
}

// authenticateToken xác thực một bearer token API.
//
// Thứ tự kiểm có chủ đích: hạn (đã lọc trong SQL) → user còn sống → IP. Kiểm
// IP CUỐI để event ghi được token_id — biết "token nào bị dùng sai chỗ" mới là
// thông tin hành động được, chứ "có ai đó gọi sai IP" thì không.
func (s *Service) authenticateToken(ctx context.Context, token, ip string) (authz.Principal, error) {
	t, err := s.st.GetAPIToken(ctx, hashToken(token))
	if err != nil {
		return authz.Principal{}, authz.ErrUnauthenticated
	}
	u, err := s.st.GetUser(ctx, t.UserID)
	if err != nil || u.Disabled {
		return authz.Principal{}, authz.ErrUnauthenticated
	}
	if !ipAllowed(t.AllowedIPCIDRs, ip) {
		s.event(ctx, "identity.token_ip_denied", t.UserID, map[string]any{
			"token_id": t.ID, "ip": ip,
		})
		return authz.Principal{}, authz.ErrUnauthenticated
	}

	// GIAO của scope token và scope user HIỆN TẠI — hai lần lọc, không phải một.
	//
	// Chỉ lấy scope token: hạ quyền một user không hạ được token họ đã phát, nên
	// việc hạ quyền gần như vô nghĩa. Chỉ lấy scope user: nâng quyền user âm
	// thầm nâng luôn mọi token cũ, kể cả cái đã cố ý phát hẹp cho một script.
	userScopes := authz.ScopesFromStrings(u.Scopes)
	scopes := make([]authz.Scope, 0, len(t.Scopes))
	for _, sc := range t.Scopes {
		if authz.Grants(userScopes, authz.Scope(sc)) {
			scopes = append(scopes, authz.Scope(sc))
		}
	}

	// Lỗi ghi vết KHÔNG chặn request: nó là dữ liệu chẩn đoán, và để một lần
	// UPDATE hỏng làm gãy xác thực là tự tạo ra sự cố từ chỗ không cần thiết.
	_ = s.st.TouchAPIToken(ctx, t.TokenHash, ip)

	return authz.Principal{Subject: t.UserID, Scopes: scopes, TokenID: t.ID}, nil
}
