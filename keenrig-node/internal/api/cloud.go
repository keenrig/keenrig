package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/instance"
	"github.com/keenrig/keenrig/keenrig-node/internal/privops"
)

// cloudLink — GET /api/v1/cloud: trạng thái pair với Keenrig Cloud, NHƯ AGENT
// BÁO VỀ (AD-12).
//
// # Vì sao đòi đăng nhập, khác /instance
//
// /instance trả tên miền gốc — thứ người mở trang đã đọc được từ thanh địa
// chỉ. Đường này trả URL control plane và định danh môi trường: hai thứ không
// hiện ở đâu ngoài agent.env, và đủ để một người lạ biết máy này thuộc cloud
// nào, môi trường nào. Scope `apps:read` — cùng scope với danh sách app: ai
// được nhìn app đang chạy thì được biết máy có đang được quản từ xa hay không;
// không cần tới admin vì đây là đọc, không phải đổi.
//
// # Vì sao CHỈ có GET
//
// Pairing là việc của agent (join token trong lệnh cài từ Console). Box không
// có đường đặt trạng thái này từ Admin UI — nó chỉ vẽ lại điều agent đã báo
// qua node API `PUT /cloud-link`. Một nút "Pair" ở đây mà không có agent phía
// sau là một nút nói dối.
func (s *Server) cloudLink(w http.ResponseWriter, r *http.Request) {
	if s.inst == nil {
		writeJSON(w, http.StatusNotImplemented, errBody{"the cloud link state is not wired up on this box"})
		return
	}
	info, err := s.inst.CloudLink(r.Context(), time.Now())
	if err != nil {
		writeErr(w, err)
		return
	}
	last := ""
	if !info.LastSyncAt.IsZero() {
		last = info.LastSyncAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"paired":       info.Paired,
		"cloud_url":    info.CloudURL,
		"env_id":       info.EnvID,
		"last_sync_at": last,
		"state":        info.State,
	})
}

// WithInstance cắm Config của instance để /cloud đọc được trạng thái pair.
// Không cắm → 501 "not wired", để Admin UI phân biệt "box cũ" với "chưa pair".
func WithInstance(cfg *instance.Config) Option {
	return func(s *Server) { s.inst = cfg }
}

// Pairer ghép node với Console bằng join token, trả env id — privops.Ops.Pair
// trong main. Kiểu hàm chứ không phải *privops.Ops: tầng ① chỉ cần MỘT việc,
// và test cắm được một hàm giả mà không cần sudo.
type Pairer func(ctx context.Context, token string) (string, error)

// WithPairer bật POST /cloud/pair. Không cắm → 501, để Admin UI biết box này
// chưa nhận token từ UI và chỉ đường còn lại (lệnh --join).
func WithPairer(p Pairer) Option {
	return func(s *Server) { s.pair = p }
}

// cloudPair — POST /api/v1/cloud/pair {"token": "..."}: ghép một máy ĐÃ CÀI
// standalone với Console, ngay từ Admin UI.
//
// # Vì sao giờ có đường này (trước đây: "chỉ có GET")
//
// Người cài bằng `curl … | sudo sh` không có join token lúc cài; muốn quản từ
// Console về sau thì trước đây phải SSH vào và chạy lại installer. Box vẫn KHÔNG
// tự đặt trạng thái pair: nó nhờ pair.sh (root) đổi token lấy khoá agent rồi
// restart agent, và trạng thái hiện lên đây khi agent sync lần đầu — đúng con
// đường GET ở trên đã đọc. Không có nút nào nói dối.
//
// Scope admin: pair là trao quyền điều khiển máy cho một control plane.
func (s *Server) cloudPair(w http.ResponseWriter, r *http.Request) {
	if s.pair == nil {
		writeJSON(w, http.StatusNotImplemented, errBody{"this box cannot pair from the Admin UI - run the install command from the Console with --join"})
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &body) {
		return
	}
	envID, err := s.pair(r.Context(), strings.TrimSpace(body.Token))
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, map[string]string{"env_id": envID})
	case errors.Is(err, privops.ErrInvalidArg):
		writeJSON(w, http.StatusBadRequest, errBody{"this is not a join token - copy the token shown in the Console"})
	case errors.Is(err, privops.ErrUnavailable):
		writeJSON(w, http.StatusNotImplemented, errBody{"pairing is not installed on this box yet - run the install command from the Console with --join"})
	default:
		// Thông điệp của pair.sh viết cho NGƯỜI DÙNG ("token hết hạn, phát
		// token mới"), nên đưa nó lên — bỏ tiền tố nội bộ "privops: pair.sh: ".
		msg := strings.TrimPrefix(err.Error(), "privops: "+privops.ScriptPair+": ")
		writeJSON(w, http.StatusBadGateway, errBody{msg})
	}
}
