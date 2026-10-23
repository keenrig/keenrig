package api

import (
	"net/http"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/authz"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/importer"
)

// POST /api/v1/import/compose — dịch một file compose thành desired NHÁP.
//
// Endpoint này KHÔNG tạo app. Nó trả bản nháp kèm danh sách thứ không dịch được
// để UI hiện ra cho người dùng đọc, rồi họ mới bấm tạo qua POST /apps như bình
// thường. Tự tạo luôn sẽ bỏ qua đúng bước mà cả package importer sinh ra để
// bảo vệ: người dùng nhìn thấy cái gì bị bỏ trước khi nó chạy.
//
// Scope là apps:write chứ không phải apps:read: tuy không ghi gì, nó nhận đầu
// vào không tin cậy và tiêu CPU parse. Người chỉ có quyền đọc không cần nó.
func (s *Server) importCompose(w http.ResponseWriter, r *http.Request) {
	raw, ok := readRawBody(w, r)
	if !ok {
		return
	}
	res, err := importer.Import(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{err.Error()})
		return
	}
	// Có mục bị TỪ CHỐI vì an ninh → 422, không phải 200 kèm cảnh báo.
	//
	// 200 sẽ khiến UI hiện bản nháp "gần đúng" và người dùng bấm tạo, rồi
	// admission từ chối ở bước sau với một thông báo khác. Nói "không" một lần,
	// ngay tại chỗ người dùng còn đang nhìn file của họ.
	if bad := res.Rejected(); len(bad) > 0 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":    "the compose file contains declarations that are not allowed on the platform",
			"code":     "compose_rejected",
			"rejected": bad,
			"result":   res,
		})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// readRawBody đọc body THÔ (compose là YAML, không phải JSON).
func readRawBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	raw, err := readAll(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{"request body could not be read: " + err.Error()})
		return nil, false
	}
	if len(raw) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody{"request body is empty"})
		return nil, false
	}
	return raw, true
}

func (s *Server) importRoutes() {
	s.mux.Handle("POST /api/v1/import/compose",
		s.guard.Require(authz.ScopeAppsWrite, http.HandlerFunc(s.importCompose)))
}
