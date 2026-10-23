package identity

// adminticket.go — nửa phía INSTANCE của "Mở Admin ↗" (`CON-13`).
//
// # Đường đi của một vé
//
//	Console  POST /console/v1/envs/{id}/admin-sessions
//	         → cloud sinh vé TRẦN, đặt HASH vào payload lệnh `mint_admin_token`
//	agent    nhận lệnh ở lần sync kế → POST /node/v1/admin-tickets {token_hash}
//	box      giữ hash trong BỘ NHỚ tới khi hết hạn  ← file này
//	trình duyệt POST https://admin.<domain>/_keenrig/admin-session {ticket}
//	         → box băm vé, so với hash đang giữ, mở phiên cho CHỦ instance
//
// Vé trần không bao giờ chạm tới đĩa ở cả hai đầu, và ở đầu này ngay cả HASH
// cũng không: nó sống trong RAM, tối đa 10 phút.
//
// # Vì sao KHÔNG lưu xuống platform.db
//
// Vé có hạn 10 phút và cloud mới là nguồn sự thật — box restart giữa chừng thì
// người dùng bấm lại "Mở Admin ↗" và cloud phát vé mới. Đổi lấy điều đó là:
// không thêm bảng, không thêm migration, và một hash phiên đăng nhập không nằm
// lại trong mọi bản backup của instance. Một bảng bền cho thứ sống 10 phút là
// một bảng phải nhớ dọn.

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

var (
	// ErrAdminTicketRejected — vé không tồn tại, đã dùng, hoặc hết hạn.
	//
	// MỘT lỗi cho cả ba, cùng lý lẽ với ErrInvalidCredentials: phân biệt được
	// "hết hạn" với "chưa từng tồn tại" là cho một kẻ dò biết vé nào từng có
	// thật.
	ErrAdminTicketRejected = errors.New("identity: this admin ticket is not valid")
	// ErrNoOwner — instance chưa có chủ nên chưa có ai để mở phiên.
	//
	// Tách riêng vì nó KHÔNG phải lỗi của vé: người vận hành phải được biết
	// rằng thứ còn thiếu là bước thiết lập lần đầu, không phải cái vé.
	ErrNoOwner = errors.New("identity: this instance has no owner yet — finish the first-run setup")
)

const (
	// AdminTicketTTL — hạn tối đa box chấp nhận giữ một vé (`SEC-06`).
	//
	// Cloud gửi kèm hạn của chính nó; box kẹp xuống con số này. Không kẹp thì
	// một control plane bị chiếm có thể đặt một vé sống một năm trên MỌI
	// instance, và không ai trên máy nhìn thấy điều đó.
	AdminTicketTTL = 10 * time.Minute
	// maxAdminTickets — trần số vé đang chờ.
	//
	// Cửa này gọi được từ node API, tức từ bất kỳ tiến trình nào mở được
	// socket. Không có trần thì một vòng lặp hỏng ở phía agent làm đầy bộ nhớ
	// box — và box hết bộ nhớ là mọi app trên máy đi cùng.
	maxAdminTickets = 32
	// adminTicketHashLen — sha256 hex.
	adminTicketHashLen = 64
)

type adminTicket struct {
	hash      string
	expiresAt time.Time
}

// adminTickets — kho vé trong bộ nhớ. Zero value dùng được ngay.
type adminTickets struct {
	mu   sync.Mutex
	list []adminTicket
}

// AcceptAdminTicket ghi nhận một vé do control plane phát.
//
// Idempotent theo hash: agent retry một lệnh đã thực thi (mất kết quả giữa
// đường là chuyện thường) không được biến thành hai vé — và cũng không được
// báo lỗi, vì lúc đó lệnh sẽ đứng ở `failed` trên Console cho một việc đã xong.
func (s *Service) AcceptAdminTicket(hash string, expiresAt time.Time) error {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if !isHex(hash, adminTicketHashLen) {
		return errors.New("identity: an admin ticket hash must be 64 hex characters (sha256)")
	}
	now := s.opts.Now()
	// Kẹp hạn: quá dài cắt về trần, quá khứ/không khai → trần luôn.
	max := now.Add(AdminTicketTTL)
	if expiresAt.IsZero() || expiresAt.After(max) || !expiresAt.After(now) {
		expiresAt = max
	}

	s.tickets.mu.Lock()
	defer s.tickets.mu.Unlock()
	s.tickets.sweep(now)
	for i, t := range s.tickets.list {
		if t.hash == hash {
			s.tickets.list[i].expiresAt = expiresAt
			return nil
		}
	}
	if len(s.tickets.list) >= maxAdminTickets {
		return errors.New("identity: too many admin tickets are pending on this instance")
	}
	s.tickets.list = append(s.tickets.list, adminTicket{hash: hash, expiresAt: expiresAt})
	return nil
}

// RedeemAdminTicket đổi vé TRẦN lấy một phiên của chủ instance. MỘT LẦN.
//
// Vé bị gỡ khỏi kho TRƯỚC khi phiên được mở, và trong cùng một lần giữ khoá:
// đọc rồi mới xoá để lại một cửa sổ, và cửa sổ đó là hai phiên đăng nhập từ
// một vé — đúng thứ "một lần" phải chặn.
//
// Hệ quả có chủ đích: nếu mở phiên hỏng (DB lỗi) thì vé cũng mất, và người dùng
// phải xin vé mới. Đó là hướng hỏng an toàn hơn so với giữ vé lại.
func (s *Service) RedeemAdminTicket(ctx context.Context, ticket, ip, ua string) (string, *store.Session, error) {
	ticket = strings.TrimSpace(ticket)
	if ticket == "" {
		return "", nil, ErrAdminTicketRejected
	}
	if !s.tickets.take(hashToken(ticket), s.opts.Now()) {
		return "", nil, ErrAdminTicketRejected
	}
	u, err := s.st.OwnerUser(ctx)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", nil, ErrNoOwner
		}
		return "", nil, err
	}
	token, sess, err := s.openSession(ctx, u, ip, ua)
	if err != nil {
		return "", nil, err
	}
	// Nhật ký: một phiên mở ra mà KHÔNG có ai gõ mật khẩu trên máy này phải để
	// lại dấu vết, nếu không thì "Mở Admin ↗" là một cửa sau không nhìn thấy
	// được từ chính instance.
	s.event(ctx, "identity.admin_session_minted", u.ID, map[string]any{"ip": ip})
	return token, sess, nil
}

// PendingAdminTickets — số vé còn hiệu lực. Dùng cho test và chẩn đoán.
func (s *Service) PendingAdminTickets() int {
	s.tickets.mu.Lock()
	defer s.tickets.mu.Unlock()
	s.tickets.sweep(s.opts.Now())
	return len(s.tickets.list)
}

// take gỡ vé khỏi kho và cho biết nó có hiệu lực hay không.
func (a *adminTickets) take(hash string, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sweep(now)
	for i, t := range a.list {
		if subtleEqual(t.hash, hash) {
			a.list = append(a.list[:i], a.list[i+1:]...)
			return true
		}
	}
	return false
}

// sweep bỏ vé hết hạn. Chỗ gọi PHẢI đang giữ khoá.
//
// Dọn trên đường ghi/đọc thay vì bằng một goroutine hẹn giờ: một goroutine nữa
// là một thứ nữa có thể chết im lặng, và kho này bị chạm tới đủ thường xuyên.
func (a *adminTickets) sweep(now time.Time) {
	keep := a.list[:0]
	for _, t := range a.list {
		if t.expiresAt.After(now) {
			keep = append(keep, t)
		}
	}
	a.list = keep
}

// subtleEqual so hai chuỗi hex trong thời gian KHÔNG phụ thuộc nội dung.
//
// So bằng `==` trả lời sớm ở byte đầu khác nhau. Ở đây thứ đem so là hash của
// một vé, nên kênh phụ đó hẹp — nhưng nó miễn phí để đóng, và lần sau ai đó
// copy đoạn này sang chỗ so bí mật thật thì đã đúng sẵn.
func subtleEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
