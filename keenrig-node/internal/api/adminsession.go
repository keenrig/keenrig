package api

// adminsession.go — cửa nhận vé "Mở Admin ↗" của trình duyệt (`CON-13`).
//
// Đường này KHÔNG nằm dưới `/api/v1`: nó không phải hợp đồng cho client script
// mà là một lần chuyển tay giữa hai trang web (Console → Admin UI), và nó là
// đường DUY NHẤT trên box nhận được request khi chưa đăng nhập ngoài
// `/auth/setup` + `/auth/login`. Đặt nó ở `/_keenrig/` để không lẫn với API và
// không bị SPA ở "/" nuốt mất.
//
// Nó KHÔNG đi qua Guard, cũng vì lẽ đó — chính cái vé là thứ xác thực. Bù lại:
// vé chỉ dùng được một lần, sống tối đa 10 phút, và phải khớp một hash mà cloud
// đã giao xuống qua hàng lệnh.

import (
	"errors"
	"net/http"
	"strings"

	"github.com/keenrig/keenrig/keenrig-node/internal/identity"
)

// AdminSessionPath — đường mà cloud in ra trong `handoff.url` (xem
// `consoleapi/wizard.go`). Hai bên phải khớp nhau từng ký tự.
const AdminSessionPath = "/_keenrig/admin-session"

// AdminSessionField — tên trường mang vé, cả ở form lẫn ở JSON.
const AdminSessionField = "keenrig_admin_ticket"

// AdminSessionHandler trả handler cho AdminSessionPath, để main gắn vào httpd.
//
// Trả handler thay vì tự đăng ký vào mux của `/api/v1`: httpd là nơi biết cây
// đường dẫn gốc, và package này không được biết nó nằm sau tiền tố nào.
func (s *Server) AdminSessionHandler() http.Handler {
	return http.HandlerFunc(s.adminSession)
}

func (s *Server) adminSession(w http.ResponseWriter, r *http.Request) {
	// Vé là bí mật: không cache, và không rò qua Referer khi trình duyệt rời
	// trang. Đặt TRƯỚC mọi nhánh trả lời, kể cả nhánh lỗi.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed,
			errBody{"a one-time admin ticket is redeemed with POST, never with a link"})
		return
	}
	// Vé trong URL bị TỪ CHỐI, không phải im lặng chấp nhận.
	//
	// Query string nằm lại trong access log của mọi proxy trên đường đi, trong
	// lịch sử trình duyệt, và trong header Referer của request kế tiếp. Cloud
	// đã chặn ở đầu kia (`redeemAdminSession`); chặn lại ở đây vì một client
	// viết sai không được phép làm rò vé của mọi người dùng chỉ vì nó gọi
	// thẳng instance.
	for _, k := range []string{AdminSessionField, "ticket", "token", "t"} {
		if r.URL.Query().Get(k) != "" {
			writeJSON(w, http.StatusBadRequest,
				errBody{"a one-time admin ticket must never travel in a URL: send it in the request body"})
			return
		}
	}
	if s.ident == nil {
		writeJSON(w, http.StatusNotImplemented, errBody{"login is not enabled"})
		return
	}

	ticket, ok := adminTicketFrom(w, r)
	if !ok {
		return
	}
	token, sess, err := s.ident.RedeemAdminTicket(r.Context(), ticket,
		identity.ClientIP(r), r.UserAgent())
	switch {
	case errors.Is(err, identity.ErrAdminTicketRejected):
		// 401 kèm MỘT câu cho cả "bịa", "đã dùng" và "hết hạn": phân biệt được
		// ba ca đó là cho một kẻ dò biết vé nào từng tồn tại.
		writeJSON(w, http.StatusUnauthorized,
			errBody{"this admin ticket is not valid any more — open the environment in the Console and try again"})
		return
	case errors.Is(err, identity.ErrNoOwner):
		// Box vừa cài, chưa có chủ: đây là lần ĐẦU TIÊN người dùng mở Admin, và
		// họ tới từ Console — đường duy nhất họ có. Trình duyệt được đưa thẳng
		// tới màn tạo chủ của Admin UI (`/` vẽ form setup khi needs_setup).
		// Trước đây nhánh này ném JSON 409 vào trang: người dùng thấy một dòng
		// lỗi thô và không có lối đi tiếp, vì mã setup chỉ nằm trong journalctl
		// của máy — đo được trên VPS thật 2026-10-02 (case 1, bước Open Admin).
		if wantsHTML(r) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		writeJSON(w, http.StatusConflict, errBody{err.Error()})
		return
	case err != nil:
		writeErr(w, err)
		return
	}
	s.ident.SetSessionCookie(w, token, sess.ExpiresAt)

	// Trình duyệt đi tới đây bằng một form POST và mong đợi một TRANG, không
	// phải JSON. 303 (không phải 302) để lần đi tiếp là GET: giữ POST rồi
	// chuyển hướng sẽ gửi lại chính cái vé đã tiêu tới đường mới.
	if wantsHTML(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// Client không phải trình duyệt vẫn dùng được đường này: token trong thân,
	// đúng như /auth/login. Đây là lần DUY NHẤT nó xuất hiện.
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_at": sess.ExpiresAt,
	})
}

// adminTicketFrom bóc vé từ form hoặc từ JSON.
//
// Hai định dạng vì hai loại client: trình duyệt gửi form (đó là cách duy nhất
// để POST sang origin khác mà không cần CORS), script gửi JSON.
func adminTicketFrom(w http.ResponseWriter, r *http.Request) (string, bool) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(ct, "multipart/form-data") {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, errBody{"invalid form body"})
			return "", false
		}
		// PostForm, không phải Form: Form trộn cả query string vào, và trộn vào
		// đây sẽ vô hiệu hoá chính phép chặn "vé không đi trong URL" ở trên.
		v := strings.TrimSpace(r.PostForm.Get(AdminSessionField))
		if v == "" {
			v = strings.TrimSpace(r.PostForm.Get("ticket"))
		}
		if v == "" {
			writeJSON(w, http.StatusBadRequest, errBody{"a ticket is required"})
			return "", false
		}
		return v, true
	}

	var body struct {
		Ticket  string `json:"ticket"`
		Handoff string `json:"keenrig_admin_ticket"`
	}
	if !decode(w, r, &body) {
		return "", false
	}
	v := strings.TrimSpace(body.Handoff)
	if v == "" {
		v = strings.TrimSpace(body.Ticket)
	}
	if v == "" {
		writeJSON(w, http.StatusBadRequest, errBody{"a ticket is required"})
		return "", false
	}
	return v, true
}

// wantsHTML — client này là một trình duyệt đang điều hướng hay một script.
func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}
