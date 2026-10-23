// Package api — control API `/api/v1` cho Admin UI: adapter MỎNG giữa HTTP và
// tầng service.
//
// Ràng buộc: package này KHÔNG chứa business rule. Validate desired, sinh slug,
// quota, chống domain trùng đều nằm ở `apps`/`domains`; ở đây chỉ decode/encode,
// map lỗi sang HTTP status và áp `authz`. Lý do thực dụng: node API và (sau này)
// agent phải chạy được cùng luật mà không đi qua HTTP handler này — luật nằm
// trong handler là luật không dùng lại được.
//
// LUẬT 9 (V2-DELTA §3): tầng ① của box — httpd + api — KHÔNG được import
// reconciler/runtime/addons. Tầng ① chết thì ota mất drain/resume, tức mất
// đường sửa lỗi cuối cùng. CI verify bằng `go list -deps` (xem
// api_arch_test.go), không phải bằng lời hứa trong comment này.
//
// Hợp đồng: contracts/openapi/instance.yaml.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/apps"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/authz"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/catalog"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/domains"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/identity"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/instance"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// maxBodyBytes — chặn body khổng lồ trước khi nó thành rác trong bộ nhớ.
// desired của một app là vài KB; 1MB đã rộng gấp trăm lần nhu cầu thật.
const maxBodyBytes = 1 << 20

type Server struct {
	apps  *apps.Service
	st    store.Store
	ident *identity.Service
	guard *authz.Guard
	mux   *http.ServeMux
	// cat — danh mục app. nil = chưa cắm; route /catalog KHÔNG tồn tại thay vì
	// trả danh sách rỗng. Rỗng và chưa-bật là hai chuyện khác nhau, và trộn
	// chúng lại làm UI không phân biệt được "chưa cấu hình" với "hết app".
	cat *catalog.Catalog
	// inst — Config của instance, cho /cloud đọc trạng thái pair agent đã báo.
	// nil = chưa cắm: route trả 501 nói rõ, KHÔNG trả "standalone" — binary cũ
	// và máy chưa pair là hai chuyện khác nhau, và UI phải vẽ khác nhau.
	inst *instance.Config
	// pair — ghép với Console từ Admin UI (WithPairer). nil → 501.
	pair Pairer
}

// New dựng handler cho /api/v1. auth do main cắm vào.
func New(svc *apps.Service, st store.Store, auth authz.Authenticator, opts ...Option) *Server {
	s := &Server{apps: svc, st: st}
	for _, o := range opts {
		o(s)
	}
	s.guard = authz.NewGuard(auth, func(w http.ResponseWriter, _ *http.Request, err error) {
		writeErr(w, err)
	})
	s.routes()
	return s
}

// Option cấu hình Server.
type Option func(*Server)

// WithIdentity bật các route /auth (T10). Không gắn thì chúng trả 501 —
// endpoint tồn tại nhưng nói rõ là chưa bật, thay vì 404 để client đoán mò.
func WithIdentity(id *identity.Service) Option {
	return func(s *Server) { s.ident = id }
}

// WithCatalog bật các route /catalog (UI-01).
func WithCatalog(c *catalog.Catalog) Option {
	return func(s *Server) { s.cat = c }
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// routes — mọi route đi qua guard.Require(scope). Không có đường nào gắn
// handler trực tiếp vào mux: quên scope phải là chuyện KHÔNG viết ra được, chứ
// không phải chuyện phải nhớ.
func (s *Server) routes() {
	s.mux = http.NewServeMux()
	h := func(pattern string, scope authz.Scope, fn http.HandlerFunc) {
		s.mux.Handle(pattern, s.guard.Require(scope, fn))
	}

	// Không có guard: xem godoc của instanceInfo.
	s.mux.HandleFunc("GET /api/v1/instance", s.instanceInfo)

	h("GET /api/v1/apps", authz.ScopeAppsRead, s.listApps)
	h("POST /api/v1/apps", authz.ScopeAppsWrite, s.createApp)
	h("GET /api/v1/apps/{id}", authz.ScopeAppsRead, s.getApp)
	h("DELETE /api/v1/apps/{id}", authz.ScopeAppsWrite, s.deleteApp)
	h("PATCH /api/v1/apps/{id}/desired", authz.ScopeAppsWrite, s.updateDesired)
	h("GET /api/v1/apps/{id}/domains", authz.ScopeDomainsRead, s.listDomains)
	h("POST /api/v1/apps/{id}/domains", authz.ScopeDomainsWrite, s.addDomain)
	h("DELETE /api/v1/domains/{fqdn}", authz.ScopeDomainsWrite, s.removeDomain)
	h("GET /api/v1/events", authz.ScopeEventsRead, s.listEvents)
	// CÓ guard, khác /instance: xem godoc của cloudLink.
	h("GET /api/v1/cloud", authz.ScopeAppsRead, s.cloudLink)
	h("POST /api/v1/cloud/pair", authz.ScopeAdmin, s.cloudPair)

	s.authRoutes()
	s.tokenRoutes()
	s.catalogRoutes()
	s.importRoutes()
}

// --- handler ------------------------------------------------------------------

func (s *Server) listApps(w http.ResponseWriter, r *http.Request) {
	list, err := s.apps.List(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	// Trả mảng RỖNG chứ không phải null khi chưa có app: client JS phân biệt
	// hai thứ đó, và `null.map(...)` là lỗi runtime ở phía UI.
	if list == nil {
		list = []*store.App{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) createApp(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Slug    string          `json:"slug"`
		Desired json.RawMessage `json:"desired"`
	}
	if !decode(w, r, &body) {
		return
	}
	app, err := s.apps.Create(r.Context(), apps.CreateInput{Slug: body.Slug, Desired: body.Desired})
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Location", "/api/v1/apps/"+app.ID)
	writeJSON(w, http.StatusCreated, app)
}

func (s *Server) getApp(w http.ResponseWriter, r *http.Request) {
	app, err := s.apps.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, app)
}

// deleteApp trả 202, KHÔNG phải 204.
//
// 204 nghĩa là "đã xong, không có gì để nói thêm" — sai sự thật ở đây: lúc
// response về, row mới chỉ được đánh dấu deleted_at, còn container thì reconciler
// dọn ở tick sau. Trả 204 sẽ khiến UI báo "đã xoá" trong khi app vẫn đang phục vụ.
func (s *Server) deleteApp(w http.ResponseWriter, r *http.Request) {
	if err := s.apps.Delete(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "deleting"})
}

func (s *Server) updateDesired(w http.ResponseWriter, r *http.Request) {
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	rev, err := s.apps.UpdateDesired(r.Context(), r.PathValue("id"), raw)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"desired_rev": rev})
}

func (s *Server) listDomains(w http.ResponseWriter, r *http.Request) {
	ds, err := s.apps.Domains(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	if ds == nil {
		ds = []*store.Domain{}
	}
	writeJSON(w, http.StatusOK, ds)
}

func (s *Server) addDomain(w http.ResponseWriter, r *http.Request) {
	var body struct {
		FQDN    string `json:"fqdn"`
		Primary bool   `json:"is_primary"`
	}
	if !decode(w, r, &body) {
		return
	}
	d, err := s.apps.AddDomain(r.Context(), r.PathValue("id"), body.FQDN, body.Primary)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, d)
}

func (s *Server) removeDomain(w http.ResponseWriter, r *http.Request) {
	if err := s.apps.RemoveDomain(r.Context(), r.PathValue("fqdn")); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	evs, err := s.st.ListEvents(r.Context(), eventLimit(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	if evs == nil {
		evs = []*store.Event{}
	}
	writeJSON(w, http.StatusOK, evs)
}

// --- helper -------------------------------------------------------------------

const (
	defaultEventLimit = 100
	maxEventLimit     = 500
)

func eventLimit(r *http.Request) int {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return defaultEventLimit
	}
	n := 0
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return defaultEventLimit // tham số rác → mặc định, không phải 400
		}
		n = n*10 + int(v[i]-'0')
		if n > maxEventLimit {
			return maxEventLimit
		}
	}
	if n <= 0 {
		return defaultEventLimit
	}
	return n
}

// readAll đọc body thô có giới hạn kích thước.
func readAll(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
}

func readBody(w http.ResponseWriter, r *http.Request) (json.RawMessage, bool) {
	raw, err := readAll(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{"request body could not be read: " + err.Error()})
		return nil, false
	}
	if !json.Valid(raw) {
		writeJSON(w, http.StatusBadRequest, errBody{"request body is not valid JSON"})
		return nil, false
	}
	return raw, true
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	raw, ok := readBody(w, r)
	if !ok {
		return false
	}
	if err := json.Unmarshal(raw, v); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{"request body has the wrong shape: " + err.Error()})
		return false
	}
	return true
}

type errBody struct {
	Error string `json:"error"`
}

// conflictBody — 409 kèm LOẠI xung đột.
//
// Ba nguyên nhân rất khác nhau cùng trả 409: tên đã có app khác dùng, hết hạn
// mức phần cứng, và chạm trần của license. Không có trường `code` thì giao diện
// chỉ còn mã trạng thái để đoán — và nó đã đoán sai: một người dùng chạm trần
// "1 app" của bậc starter nhận câu *"slug hoặc domain đã được app khác dùng"*,
// vừa sai vừa dẫn họ đi sửa nhầm chỗ (đổi tên mãi mà không bao giờ qua được).
//
// Kiểu riêng thay vì thêm trường vào errBody: errBody được dựng bằng literal
// KHÔNG tên ở hàng chục chỗ, và thêm một trường sẽ làm tất cả không biên dịch.
type conflictBody struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr — bảng dịch DUY NHẤT từ lỗi tầng service sang HTTP status.
//
// Tập trung một chỗ để không có endpoint nào lệch: một handler trả 500 cho
// domain trùng trong khi handler khác trả 409 là kiểu bất nhất mà client không
// có cách nào lập trình quanh.
func writeErr(w http.ResponseWriter, err error) {
	// Lỗi xác thực có bảng riêng (auth.go) vì chúng cần mã lỗi máy đọc được.
	if writeAuthErr(w, err) {
		return
	}
	if writeTokenErr(w, err) {
		return
	}
	if writeCatalogErr(w, err) {
		return
	}
	switch {
	case errors.Is(err, authz.ErrUnauthenticated):
		writeJSON(w, http.StatusUnauthorized, errBody{"not authenticated"})
	case errors.Is(err, authz.ErrForbidden):
		writeJSON(w, http.StatusForbidden, errBody{"insufficient permissions"})
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errBody{"not found"})
	case errors.Is(err, apps.ErrLicense):
		writeJSON(w, http.StatusConflict, conflictBody{err.Error(), "license_limit"})
	case errors.Is(err, apps.ErrQuota):
		writeJSON(w, http.StatusConflict, conflictBody{err.Error(), "quota"})
	case errors.Is(err, store.ErrConflict):
		writeJSON(w, http.StatusConflict, conflictBody{err.Error(), "conflict"})
	case errors.Is(err, apps.ErrInvalidSlug),
		errors.Is(err, apps.ErrInvalidDesired),
		errors.Is(err, apps.ErrUnsupported),
		errors.Is(err, domains.ErrInvalidFQDN):
		writeJSON(w, http.StatusBadRequest, errBody{err.Error()})
	default:
		// KHÔNG lộ err.Error() ra ngoài ở nhánh này: lỗi chưa phân loại thường
		// mang chi tiết nội bộ (đường dẫn file, câu SQL).
		writeJSON(w, http.StatusInternalServerError, errBody{"internal error"})
	}
}
