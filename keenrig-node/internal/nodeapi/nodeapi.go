// Package nodeapi — server của node API (`contracts/openapi/node.yaml`), hợp
// đồng giữa 4 tiến trình TRÊN CÙNG một instance.
//
// # Vì sao tồn tại
//
// SQLite không chịu được nhiều tiến trình cùng ghi. Box sở hữu độc quyền
// platform.db; agent và ota lấy dữ liệu qua API này, KHÔNG mở file DB và KHÔNG
// đọc thẳng file log (ND-05, ND-02).
//
// # Độc lập transport
//
// Nấc 0 chạy trên unix socket; nấc cao hơn cùng hợp đồng này trên TCP + mTLS,
// khác host. Vì vậy API không được giả định client ở cùng máy: log là STREAM
// qua HTTP chứ không phải một endpoint trả đường dẫn file. Ràng buộc đó có test
// canh (xem nodeapi_test.go).
//
// # Luật 9
//
// Đây là tầng ① cùng với httpd/api: KHÔNG import reconciler/runtime. Những
// việc cần chúng (drain, resume, log) đi qua interface do main cắm vào. Tầng ①
// chết thì ota mất drain/resume, tức mất đường sửa lỗi cuối cùng.
package nodeapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/metrics"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// Lifecycle — thứ ota cần điều khiển để thay bin an toàn.
//
// Interface chứ không phải *reconciler.Reconciler: nodeapi không được import
// reconciler (Luật 9), và nhờ vậy test chạy được mà không cần dựng cả vòng lặp.
type Lifecycle interface {
	// Drain ngừng nhận việc mới và đợi việc đang chạy xong.
	// Trả số việc CÒN chạy dở lúc hết timeout (0 = drain sạch).
	Drain(ctx context.Context, timeout time.Duration) (inFlight int, err error)
	// Resume nhận việc trở lại. Idempotent.
	Resume()
}

// LogStreamer — stream log của một app qua HTTP.
//
// nil nghĩa là chưa nối (M1): endpoint trả 501 chứ KHÔNG trả đường dẫn file.
// Trả đường dẫn là cách dễ nhất để phá vỡ tính độc lập transport, và một khi
// client đã dựa vào đó thì không gỡ ra được nữa.
type LogStreamer interface {
	StreamLogs(ctx context.Context, appID string, tail int, w io.Writer) error
}

// AdminTickets — nơi box giữ vé "Mở Admin ↗" (`CON-13`).
//
// Interface chứ không phải *identity.Service, cùng lý lẽ với Lifecycle: nodeapi
// không cần biết vé được kiểm ra sao, và test không phải dựng cả tầng identity
// để kiểm một route.
//
// nil = chưa cắm (instance chạy không có đăng nhập): endpoint trả 501 kèm lý
// do, KHÔNG trả 200. Nhận vé rồi vứt đi sẽ làm Console báo "đã cấp phiên" cho
// một phiên không bao giờ mở được.
type AdminTickets interface {
	// AcceptAdminTicket ghi nhận HASH của một vé, có hạn. Idempotent theo hash.
	AcceptAdminTicket(hash string, expiresAt time.Time) error
}

// LicenseInstaller — nơi box nhận license mới do agent kéo từ cloud về (M5).
//
// Interface cùng lý lẽ với AdminTickets: nodeapi không cần biết license được
// verify và ghi ra sao (đó là việc của internal/license phía box), và test kiểm
// route này không phải dựng khoá Ed25519 nào.
//
// nil = box này không nhận license qua node API: endpoint trả 501 kèm lý do,
// KHÔNG trả 200 — nhận rồi vứt đi sẽ làm agent tưởng license đã có hiệu lực.
type LicenseInstaller interface {
	// InstallLicense verify RỒI mới ghi. Lỗi trả về NGUYÊN VĂN cho agent — "chữ
	// ký sai" và "không ghi được đĩa" là hai việc phải sửa khác nhau.
	InstallLicense(raw []byte) error
}

// ParentDomainSink — nơi box nhận tên miền gốc do control plane cấp cho môi
// trường, qua agent.
//
// Cùng lý lẽ với LicenseInstaller: nodeapi không cần biết tên miền được chuẩn
// hoá và cất ra sao (internal/instance), và test kiểm route này không phải dựng
// store. Đây là con đường DUY NHẤT một tên miền gốc đi vào box từ bên ngoài —
// control API `/api/v1` (Admin UI) không có đường ghi, theo luật chủ dự án
// 2026-09-07: tên miền do cloud quyết định, box chỉ nhận.
//
// nil = box này không nhận tên miền qua node API: endpoint trả 501 kèm lý do,
// KHÔNG trả 200 — nhận rồi vứt đi sẽ làm agent nhớ "đã giao" và không bao giờ
// gửi lại.
type ParentDomainSink interface {
	// SetParentDomain chuẩn hoá RỒI mới ghi. Lỗi trả về NGUYÊN VĂN cho agent.
	SetParentDomain(ctx context.Context, parent, mode string) error
}

// CloudLinkSink — nơi box nhận trạng thái pair với control plane, từ agent.
//
// Agent là tiến trình DUY NHẤT biết máy này đã pair (nó đọc agent.env và là
// bên nói chuyện với cloud); box chỉ ghi lại để Admin UI hiển thị. Cùng lý lẽ
// với ParentDomainSink: nodeapi không cần biết giá trị được cất ra sao
// (internal/instance), và test kiểm route này không phải dựng store.
//
// nil = box này không nhận trạng thái pair qua node API: endpoint trả 501 kèm
// lý do, KHÔNG trả 200 — nhận rồi vứt đi thì Admin UI vẫn "chưa pair" mà agent
// tưởng đã báo xong.
type CloudLinkSink interface {
	// SetCloudLink kiểm RỒI mới ghi. Lỗi trả về NGUYÊN VĂN cho agent.
	SetCloudLink(ctx context.Context, cloudURL, envID string, lastSync time.Time) error
}

// AppInstaller — nơi box nhận lệnh "cài app từ catalog" do Console xếp hàng,
// qua agent (`CON-09`, kind `app.install`).
//
// Đi qua ĐÚNG đường mà Admin UI dùng (`POST /api/v1/catalog/{id}/install`):
// manifest → desired → apps.Create, với đủ quota, admission và gắn domain. Một
// đường cài riêng cho cloud sẽ là đường thứ hai bỏ qua mấy chốt đó.
//
// nil = box này không nhận lệnh cài qua node API: endpoint trả 501 kèm lý do,
// KHÔNG trả 200 — nhận rồi vứt đi sẽ làm Console báo "xong" cho một app không
// bao giờ chạy.
type AppInstaller interface {
	// InstallCatalogApp cài app `catalogID` dưới tên `slug`, gắn `domains`.
	// IDEMPOTENT theo slug: agent giao lại một lệnh đã chạy (mất ack, khởi
	// động lại) phải nhận về app đã có, không phải lỗi trùng tên — nếu không
	// lần cài thứ hai của cùng một lệnh biến một lệnh thành công thành failed.
	InstallCatalogApp(ctx context.Context, catalogID, slug string, domains []string) (appID string, created bool, err error)
}

// Version — thông tin bản dựng, do main truyền vào (ldflags).
type Version struct {
	Process string `json:"process"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

type Options struct {
	Store        store.Store
	Lifecycle    Lifecycle
	Logs         LogStreamer
	AdminTickets AdminTickets
	License      LicenseInstaller
	Domain       ParentDomainSink
	CloudLink    CloudLinkSink
	Apps         AppInstaller
	Version      Version
	Metrics      *metrics.Registry
}

type Server struct {
	opts Options
	mux  *http.ServeMux
}

const prefix = "/node/v1"

func New(opts Options) *Server {
	if opts.Metrics == nil {
		opts.Metrics = metrics.Default
	}
	s := &Server{opts: opts}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) routes() {
	s.mux = http.NewServeMux()
	// /healthz, /readyz, /metrics phơi ở CẢ hai chỗ: dưới prefix cho client
	// theo hợp đồng, và ở gốc cho systemd/probe vốn không biết prefix.
	for _, p := range []string{"", prefix} {
		s.mux.HandleFunc("GET "+p+"/healthz", s.healthz)
		s.mux.HandleFunc("GET "+p+"/readyz", s.readyz)
		s.mux.Handle("GET "+p+"/metrics", s.metricsHandler())
		s.mux.HandleFunc("GET "+p+"/version", s.version)
	}
	s.mux.HandleFunc("GET "+prefix+"/apps", s.listApps)
	s.mux.HandleFunc("GET "+prefix+"/apps/{id}/logs", s.appLogs)
	s.mux.HandleFunc("POST "+prefix+"/events", s.appendEvent)
	s.mux.HandleFunc("POST "+prefix+"/drain", s.drain)
	s.mux.HandleFunc("POST "+prefix+"/resume", s.resume)
	s.mux.HandleFunc("POST "+prefix+"/admin-tickets", s.acceptAdminTicket)
	s.mux.HandleFunc("PUT "+prefix+"/license", s.installLicense)
	s.mux.HandleFunc("PUT "+prefix+"/parent-domain", s.setParentDomain)
	s.mux.HandleFunc("PUT "+prefix+"/cloud-link", s.setCloudLink)
	s.mux.HandleFunc("POST "+prefix+"/apps/install", s.installApp)
}

// healthz — TIẾN TRÌNH còn sống chưa. Không chạm store: /healthz phụ thuộc
// store nghĩa là store hỏng thì systemd giết tiến trình, mà giết đi cũng không
// sửa được store — chỉ mất luôn node API và mất đường chẩn đoán.
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, statusBody{Status: "ok"})
}

// readyz — SẴN SÀNG PHỤC VỤ chưa. Ở đây mới chạm store, vì không đọc được DB
// thì mọi endpoint có dữ liệu đều vô nghĩa.
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if s.opts.Store == nil {
		writeJSON(w, http.StatusOK, statusBody{Status: "ok", Detail: "no store"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.opts.Store.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, statusBody{Status: "unavailable", Detail: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, statusBody{Status: "ok"})
}

func (s *Server) metricsHandler() http.Handler {
	h := s.opts.Metrics.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Cập nhật uptime NGAY TRƯỚC khi phơi: tính sẵn theo tick sẽ cho giá
		// trị cũ tới một nhịp, và uptime cũ là thứ vô dụng.
		s.opts.Metrics.SetUptime(s.opts.Version.Process)
		h.ServeHTTP(w, r)
	})
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.opts.Version)
}

// listApps — ND-01. Shape khớp sync.schema.json#/$defs/AppStatus vì agent đẩy
// thẳng nó lên cloud; đổi shape ở đây là làm hỏng hợp đồng với cloud.
func (s *Server) listApps(w http.ResponseWriter, r *http.Request) {
	if s.opts.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"no store yet"})
		return
	}
	apps, err := s.opts.Store.ListApps(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody{"could not read the app list"})
		return
	}
	out := make([]json.RawMessage, 0, len(apps))
	for _, a := range apps {
		if len(a.Status) > 0 {
			// Bổ sung `slug` và `domains` vào status của reconciler.
			//
			// Reconciler ghi trạng thái CHẠY (state/health/rev) — nó không biết
			// gì về tên miền. Nhưng cloud cần đúng những tên đó để xin chứng
			// chỉ, và suy bằng `<slug>.<parent>` chỉ đúng với quy ước mặc định:
			// một app đặt domain tuỳ chỉnh sẽ im lặng không bao giờ có cert.
			//
			// Làm giàu ở đây thay vì bắt reconciler ghi kèm: hai thứ có nhịp
			// đổi khác nhau — trạng thái đổi mỗi vài giây, tên miền đổi khi
			// người dùng sửa — và ghép chúng vào một lần ghi là để lộ một cửa
			// sổ mà tên miền mới chưa được báo lên.
			out = append(out, s.withAppIdentity(r, a))
			continue
		}
		// App chưa có status: dựng bản tối thiểu thay vì bỏ qua. Bỏ qua sẽ làm
		// app mới tạo biến mất khỏi báo cáo lên cloud cho tới lần reconcile đầu.
		//
		// Bản tối thiểu vẫn phải mang `domains`: app kẹt trước lần reconcile
		// đầu (kéo image hỏng, chưa tới lượt) là đúng ca cloud cần tên miền để
		// xin cert sẵn — thiếu nó thì app không bao giờ có cert, và triệu chứng
		// là bắt tay TLS hỏng thay vì một trang lỗi.
		m := map[string]any{
			"app_id": a.ID, "slug": a.Slug, "state": "unknown",
			"desired_rev": a.DesiredRev, "applied_rev": a.AppliedRev,
		}
		s.addDomains(r, a.ID, m)
		raw, _ := json.Marshal(m)
		out = append(out, raw)
	}
	writeJSON(w, http.StatusOK, out)
}

// withAppIdentity chèn `slug` + `domains` vào status, không đụng gì khác.
//
// Không phân tích được status (không phải JSON object) thì trả NGUYÊN VĂN: mất
// hai trường bổ sung còn hơn làm hỏng báo cáo trạng thái của cả fleet.
func (s *Server) withAppIdentity(r *http.Request, a *store.App) json.RawMessage {
	var m map[string]any
	if err := json.Unmarshal(a.Status, &m); err != nil || m == nil {
		return a.Status
	}
	m["slug"] = a.Slug
	s.addDomains(r, a.ID, m)
	raw, err := json.Marshal(m)
	if err != nil {
		return a.Status
	}
	return raw
}

// addDomains gắn `domains` của app vào m; đọc lỗi hoặc không có tên nào thì để
// nguyên — thiếu trường còn hơn báo một danh sách sai.
func (s *Server) addDomains(r *http.Request, appID string, m map[string]any) {
	doms, err := s.opts.Store.ListDomains(r.Context(), appID)
	if err != nil || len(doms) == 0 {
		return
	}
	names := make([]string, 0, len(doms))
	for _, d := range doms {
		names = append(names, d.FQDN)
	}
	m["domains"] = names
}

// appLogs — ND-02. Stream qua HTTP; KHÔNG endpoint nào trả đường dẫn file.
func (s *Server) appLogs(w http.ResponseWriter, r *http.Request) {
	if s.opts.Logs == nil {
		writeJSON(w, http.StatusNotImplemented, errBody{"log streaming is not wired up yet (M3)"})
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := s.opts.Logs.StreamLogs(r.Context(), r.PathValue("id"), tailParam(r), w); err != nil && r.Context().Err() == nil {
		// Header đã gửi rồi nên không đổi status được nữa; ghi lỗi vào chính
		// stream là cách duy nhất còn lại để client biết nó bị cắt.
		_, _ = w.Write([]byte("\n[log stream error: " + err.Error() + "]\n"))
	}
}

const defaultTail = 200

func tailParam(r *http.Request) int {
	v := r.URL.Query().Get("tail")
	n := 0
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return defaultTail
		}
		n = n*10 + int(v[i]-'0')
		if n > 10000 {
			return 10000
		}
	}
	if n <= 0 {
		return defaultTail
	}
	return n
}

// appendEvent — ND-03. Idempotency-Key BẮT BUỘC vì client sẽ retry.
//
// Key trùng trả 409 và KHÔNG sinh event thứ hai. 409 ở đây nghĩa là "recorded
// rồi" — client coi như thành công, đúng như mô tả trong node.yaml.
func (s *Server) appendEvent(w http.ResponseWriter, r *http.Request) {
	if s.opts.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"no store yet"})
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		writeJSON(w, http.StatusBadRequest, errBody{"Idempotency-Key is missing"})
		return
	}
	var body struct {
		Action  string          `json:"action"`
		Actor   string          `json:"actor"`
		Subject string          `json:"subject"`
		Data    json.RawMessage `json:"data"`
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil || json.Unmarshal(raw, &body) != nil {
		writeJSON(w, http.StatusBadRequest, errBody{"invalid request body"})
		return
	}
	if body.Action == "" || body.Actor == "" {
		writeJSON(w, http.StatusBadRequest, errBody{"action or actor is missing"})
		return
	}

	// Dùng bảng settings làm sổ idempotency: SetSetting là upsert nên phải đọc
	// trước. Cửa sổ giữa đọc và ghi tồn tại, nhưng client của node API là
	// agent/ota — mỗi loại một tiến trình, không gọi song song cùng một key.
	// Khi có nhiều client hơn thì đổi sang một bảng có UNIQUE thật.
	idemKey := "idem/node/" + key
	if _, err := s.opts.Store.GetSetting(r.Context(), idemKey); err == nil {
		writeJSON(w, http.StatusConflict, statusBody{Status: "recorded", Detail: "Idempotency-Key already used"})
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusInternalServerError, errBody{"could not read the idempotency ledger"})
		return
	}

	if err := s.opts.Store.AppendEvent(r.Context(), body.Action, body.Actor, body.Subject, body.Data); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody{"could not append the event"})
		return
	}
	// Ghi sổ SAU khi ghi event: ngược lại thì event mất mà key đã tiêu, và lần
	// retry sẽ bị từ chối vĩnh viễn. Ghi sổ lỗi thì tệ nhất là một event trùng
	// khi client retry — hỏng nhẹ hơn nhiều so với mất hẳn.
	if err := s.opts.Store.SetSetting(r.Context(), idemKey, time.Now().UTC().Format(time.RFC3339)); err != nil {
		writeJSON(w, http.StatusAccepted, statusBody{Status: "recorded", Detail: "could not write the idempotency ledger"})
		return
	}
	writeJSON(w, http.StatusAccepted, statusBody{Status: "recorded"})
}

const defaultDrainTimeout = 60 * time.Second

// drain — ota gọi TRƯỚC khi thay bin/.
//
// Còn việc chạy dở lúc hết timeout → 503, và hợp đồng nói rõ: ota PHẢI huỷ
// update, không được thay bin. Trả 200 kèm in_flight > 0 sẽ mời ota thay bin
// giữa một lần deploy dở dang.
func (s *Server) drain(w http.ResponseWriter, r *http.Request) {
	if s.opts.Lifecycle == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"there is no loop to drain"})
		return
	}
	timeout := defaultDrainTimeout
	var body struct {
		TimeoutS int `json:"timeout_s"`
	}
	if raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16)); err == nil && len(raw) > 0 {
		if json.Unmarshal(raw, &body) == nil && body.TimeoutS > 0 {
			timeout = time.Duration(body.TimeoutS) * time.Second
		}
	}

	inFlight, err := s.opts.Lifecycle.Drain(r.Context(), timeout)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{err.Error()})
		return
	}
	if inFlight > 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"in_flight": inFlight,
			"error":     "the timeout elapsed with work still running — bin/ must NOT be replaced",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"in_flight": 0})
}

func (s *Server) resume(w http.ResponseWriter, _ *http.Request) {
	if s.opts.Lifecycle == nil {
		writeJSON(w, http.StatusServiceUnavailable, errBody{"there is no loop to resume"})
		return
	}
	s.opts.Lifecycle.Resume()
	writeJSON(w, http.StatusOK, statusBody{Status: "ok"})
}

// acceptAdminTicket — CON-13, phía nhận của lệnh `mint_admin_token`.
//
// Agent gọi đường này sau khi cloud giao lệnh; thân request chỉ có HASH của vé
// (sha256 hex) và hạn. Vé TRẦN không đi qua đây — nó đi thẳng từ Console tới
// trình duyệt và chỉ xuất hiện ở `/_keenrig/admin-session`.
//
// Trả 202 chứ không 201: box không tạo ra tài nguyên nào có địa chỉ, nó chỉ ghi
// nhận một vé sẽ được trình lên sau (hoặc không bao giờ).
func (s *Server) acceptAdminTicket(w http.ResponseWriter, r *http.Request) {
	if s.opts.AdminTickets == nil {
		writeJSON(w, http.StatusNotImplemented,
			errBody{"this instance has no login enabled, so an admin session cannot be minted"})
		return
	}
	var body struct {
		TokenHash string `json:"token_hash"`
		ExpiresAt string `json:"expires_at"`
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil || json.Unmarshal(raw, &body) != nil {
		writeJSON(w, http.StatusBadRequest, errBody{"invalid request body"})
		return
	}
	var expires time.Time
	if body.ExpiresAt != "" {
		// Hạn không đọc được KHÔNG phải lý do từ chối vé: bên nhận tự kẹp về
		// trần của mình (identity.AdminTicketTTL), và một vé sống 10 phút vẫn
		// đúng luật SEC-06. Từ chối ở đây chỉ biến một chuỗi lệch định dạng
		// thành một nút bấm hỏng.
		if t, perr := time.Parse(time.RFC3339, body.ExpiresAt); perr == nil {
			expires = t
		}
	}
	if err := s.opts.AdminTickets.AcceptAdminTicket(body.TokenHash, expires); err != nil {
		// Lý do đi NGUYÊN VĂN lên Console qua kết quả lệnh (CON-14): "vé hỏng"
		// và "quá nhiều vé đang chờ" là hai việc phải sửa khác nhau.
		writeJSON(w, http.StatusBadRequest, errBody{err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, statusBody{Status: "accepted"})
}

// installLicense — phía nhận của vòng gia hạn license (M5).
//
// PUT chứ không POST: license là MỘT tài nguyên được thay thế trọn vẹn, không
// phải một dòng được thêm vào. Thân request là NGUYÊN VĂN phong bì JSON cloud
// trả về từ `/agent/v1/license` — agent không parse, không dựng lại, cùng kỷ
// luật nguyên-văn với app_statuses (ND-01): một lần parse-rồi-dựng-lại là một
// chỗ chữ ký ngừng khớp.
func (s *Server) installLicense(w http.ResponseWriter, r *http.Request) {
	if s.opts.License == nil {
		writeJSON(w, http.StatusNotImplemented,
			errBody{"this box does not accept licenses over the node API"})
		return
	}
	// 256KB là hơn 100 lần cỡ một phong bì thật — đủ rộng cho payload lớn dần,
	// đủ hẹp để một agent hỏng không nhét nổi một file GB vào instance/.
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
	if err != nil || len(raw) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody{"invalid request body"})
		return
	}
	if err := s.opts.License.InstallLicense(raw); err != nil {
		// Lý do NGUYÊN VĂN cho agent: nó là dòng log duy nhất người vận hành
		// có khi license không vào.
		writeJSON(w, http.StatusBadRequest, errBody{err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, statusBody{Status: "installed"})
}

// setParentDomain — phía nhận của `parent_domain` trong phản hồi sync.
//
// PUT vì cùng lý lẽ với license: tên miền gốc là MỘT giá trị được thay thế trọn
// vẹn, idempotent theo nội dung — agent gửi lại cùng tên là vô hại. Thân request
// mang tên nguyên văn từ cloud; box chuẩn hoá và từ chối ở sink, lý do đi
// nguyên văn về agent (dòng log duy nhất người vận hành có).
func (s *Server) setParentDomain(w http.ResponseWriter, r *http.Request) {
	if s.opts.Domain == nil {
		writeJSON(w, http.StatusNotImplemented,
			errBody{"this box does not accept a parent domain over the node API"})
		return
	}
	var body struct {
		ParentDomain string `json:"parent_domain"`
		Mode         string `json:"mode"`
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil || json.Unmarshal(raw, &body) != nil {
		writeJSON(w, http.StatusBadRequest, errBody{"invalid request body"})
		return
	}
	if err := s.opts.Domain.SetParentDomain(r.Context(), body.ParentDomain, body.Mode); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, statusBody{Status: "stored"})
}

// setCloudLink — phía nhận của báo cáo "tôi đã pair" từ agent (AD-12).
//
// PUT cùng lý lẽ với parent-domain: trạng thái pair là MỘT giá trị thay thế
// trọn vẹn, idempotent theo nội dung — agent gửi lại mỗi phút là vô hại. Mốc
// `last_sync_at` đi qua đúng định dạng RFC3339 của hợp đồng; mốc không đọc
// được là 400 chứ không phải "coi như bây giờ": box tự bịa thời gian sẽ vẽ
// synced trên một máy mà agent đang gửi rác.
func (s *Server) setCloudLink(w http.ResponseWriter, r *http.Request) {
	if s.opts.CloudLink == nil {
		writeJSON(w, http.StatusNotImplemented,
			errBody{"this box does not accept the cloud link state over the node API"})
		return
	}
	var body struct {
		CloudURL   string `json:"cloud_url"`
		EnvID      string `json:"env_id"`
		LastSyncAt string `json:"last_sync_at"`
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil || json.Unmarshal(raw, &body) != nil {
		writeJSON(w, http.StatusBadRequest, errBody{"invalid request body"})
		return
	}
	at, err := time.Parse(time.RFC3339, body.LastSyncAt)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{"last_sync_at must be an RFC3339 timestamp"})
		return
	}
	if err := s.opts.CloudLink.SetCloudLink(r.Context(), body.CloudURL, body.EnvID, at); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, statusBody{Status: "stored"})
}

// installApp — phía nhận của lệnh `app.install` từ agent.
//
// 201 khi vừa tạo, 200 khi app cùng slug đã có (giao lại lệnh). Trả ngay khi
// app vào store, không đợi container chạy — cùng lý lẽ với installFromCatalog
// của control API: kéo image có thể mất vài phút, và tiến độ thật đi lên
// Console qua `app_statuses` của nhịp sync, không qua kết quả lệnh này.
func (s *Server) installApp(w http.ResponseWriter, r *http.Request) {
	if s.opts.Apps == nil {
		writeJSON(w, http.StatusNotImplemented,
			errBody{"this box does not accept app installs over the node API"})
		return
	}
	var body struct {
		CatalogID string   `json:"catalog_id"`
		Slug      string   `json:"slug"`
		Domains   []string `json:"domains"`
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil || json.Unmarshal(raw, &body) != nil || body.CatalogID == "" {
		writeJSON(w, http.StatusBadRequest, errBody{"invalid request body: catalog_id is required"})
		return
	}
	id, created, err := s.opts.Apps.InstallCatalogApp(r.Context(), body.CatalogID, body.Slug, body.Domains)
	if err != nil {
		// Lý do NGUYÊN VĂN: nó đi lên Console thành dòng lỗi của lệnh (CON-14).
		writeJSON(w, http.StatusUnprocessableEntity, errBody{err.Error()})
		return
	}
	code := http.StatusOK
	if created {
		code = http.StatusCreated
	}
	writeJSON(w, code, map[string]any{"app_id": id, "created": created})
}

type statusBody struct {
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type errBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
