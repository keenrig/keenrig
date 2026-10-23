package identity_test

// Test CON-13 phía instance: vé "Mở Admin ↗" đổi được ĐÚNG MỘT LẦN, hết hạn
// đúng trần SEC-06, và không đổi được khi instance chưa có chủ.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/identity"
)

func hashOf(ticket string) string {
	sum := sha256.Sum256([]byte(ticket))
	return hex.EncodeToString(sum[:])
}

func TestAdminTicketOpensExactlyOneSession(t *testing.T) {
	s, st := setup(t, identity.Options{})
	owner := mustOwner(t, s)

	const ticket = "vé-một-lần"
	if err := s.AcceptAdminTicket(hashOf(ticket), time.Time{}); err != nil {
		t.Fatalf("AcceptAdminTicket: %v", err)
	}

	tok, sess, err := s.RedeemAdminTicket(t.Context(), ticket, "10.0.0.9", "curl/8")
	if err != nil {
		t.Fatalf("RedeemAdminTicket: %v", err)
	}
	if sess.UserID != owner.ID {
		t.Errorf("phiên mở cho %q, muốn chủ instance %q", sess.UserID, owner.ID)
	}
	// Phiên phải DÙNG ĐƯỢC thật, không chỉ tồn tại trong bộ nhớ.
	if _, err := st.GetSession(t.Context(), hashOf(tok)); err != nil {
		t.Errorf("token trả về không tra được trong store: %v", err)
	}

	// Lần thứ hai với CÙNG vé phải chết — "một lần" là toàn bộ giá trị của vé.
	if _, _, err := s.RedeemAdminTicket(t.Context(), ticket, "10.0.0.9", "curl/8"); !errors.Is(err, identity.ErrAdminTicketRejected) {
		t.Errorf("đổi lần hai = %v, muốn ErrAdminTicketRejected — một vé mở được hai phiên", err)
	}
	if n := s.PendingAdminTickets(); n != 0 {
		t.Errorf("còn %d vé trong kho sau khi đổi, muốn 0", n)
	}
}

// Vé bịa, vé của instance khác, vé gõ nhầm — cùng MỘT câu trả lời.
func TestAdminTicketRejectsWhatItNeverIssued(t *testing.T) {
	s, _ := setup(t, identity.Options{})
	mustOwner(t, s)
	if err := s.AcceptAdminTicket(hashOf("vé-thật"), time.Time{}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "vé-giả", "vé-thật-hơn", hashOf("vé-thật")} {
		if _, _, err := s.RedeemAdminTicket(t.Context(), bad, "", ""); !errors.Is(err, identity.ErrAdminTicketRejected) {
			t.Errorf("vé %q = %v, muốn ErrAdminTicketRejected", bad, err)
		}
	}
	// Và những lần trượt đó KHÔNG được tiêu mất vé thật: nếu có, ai cũng vô
	// hiệu hoá được nút "Mở Admin ↗" của người khác bằng một request rác.
	if _, _, err := s.RedeemAdminTicket(t.Context(), "vé-thật", "", ""); err != nil {
		t.Errorf("vé thật chết sau mấy lần đoán sai: %v", err)
	}
}

// SEC-06: 10 phút là TRẦN, kể cả khi control plane khai xa hơn.
func TestAdminTicketExpiryIsCappedAndEnforced(t *testing.T) {
	clock := time.Now()
	s, _ := setup(t, identity.Options{Now: func() time.Time { return clock }})
	mustOwner(t, s)

	// Cloud khai hạn một năm — box phải kẹp về trần của chính nó.
	if err := s.AcceptAdminTicket(hashOf("vé"), clock.Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(identity.AdminTicketTTL + time.Second)
	if _, _, err := s.RedeemAdminTicket(t.Context(), "vé", "", ""); !errors.Is(err, identity.ErrAdminTicketRejected) {
		t.Fatalf("vé sống quá %s = %v — trần SEC-06 không được ép", identity.AdminTicketTTL, err)
	}
	if n := s.PendingAdminTickets(); n != 0 {
		t.Errorf("vé hết hạn còn nằm lại trong kho (%d)", n)
	}
}

// Instance chưa thiết lập: lỗi phải nói ra thứ CÒN THIẾU là bước tạo chủ, chứ
// không đổ cho cái vé — người vận hành sẽ đi tìm nhầm chỗ.
func TestAdminTicketNeedsAnOwner(t *testing.T) {
	s, _ := setup(t, identity.Options{})
	if err := s.AcceptAdminTicket(hashOf("vé"), time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RedeemAdminTicket(t.Context(), "vé", "", ""); !errors.Is(err, identity.ErrNoOwner) {
		t.Fatalf("chưa có chủ mà = %v, muốn ErrNoOwner", err)
	}
}

func TestAcceptAdminTicketGuardsTheVault(t *testing.T) {
	s, _ := setup(t, identity.Options{})

	// Hash sai hình dạng bị chặn ở cửa: một chuỗi tuỳ ý lọt vào kho là một ô
	// nhớ mà không vé nào đổi được, tức rác sống 10 phút.
	for _, bad := range []string{"", "khôngphảihex", hashOf("x")[:63], hashOf("x") + "0"} {
		if err := s.AcceptAdminTicket(bad, time.Time{}); err == nil {
			t.Errorf("nhận hash %q — muốn từ chối", bad)
		}
	}

	// Idempotent theo hash: agent retry một lệnh đã giao KHÔNG tạo vé thứ hai
	// và KHÔNG báo lỗi (lệnh sẽ đứng failed cho việc đã xong).
	for i := 0; i < 3; i++ {
		if err := s.AcceptAdminTicket(hashOf("vé"), time.Time{}); err != nil {
			t.Fatalf("retry lần %d: %v", i, err)
		}
	}
	if n := s.PendingAdminTickets(); n != 1 {
		t.Errorf("ba lần giao cùng một vé thành %d vé, muốn 1", n)
	}

	// Trần: node API gọi được từ mọi tiến trình mở được socket, nên kho phải
	// có đáy — box hết bộ nhớ là mọi app trên máy đi cùng.
	var lastErr error
	for i := 0; i < 200; i++ {
		lastErr = s.AcceptAdminTicket(hashOf(string(rune('a'+i%26))+time.Duration(i).String()), time.Time{})
		if lastErr != nil {
			break
		}
	}
	if lastErr == nil {
		t.Errorf("nhận %d vé mà không chạm trần nào", s.PendingAdminTickets())
	}
}
