// Package httpd — HTTP surface của keenrig-box: node API + control API + serve SPA.
//
// LUẬT FAULT-ISOLATION (§2.1): package này CHỈ được import internal/store và stdlib.
// Tuyệt đối không import reconciler/runtime/agent/... — lỗi hay deadlock ở subsystem
// khác không được phép kéo sập health endpoint.
package httpd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

type Server struct {
	st  store.Store
	srv *http.Server
}

// Option cấu hình Server lúc dựng.
type Option func(*options)

type options struct {
	api          http.Handler
	ui           http.Handler
	adminSession http.Handler
	oidc         http.Handler
	metrics      http.Handler
}

// WithAPI gắn control API vào /api/v1/.
//
// Nhận http.Handler chứ KHÔNG import package api: đó là cách duy nhất để httpd
// giữ được luật §2.1 (chỉ phụ thuộc store + stdlib) mà vẫn phục vụ được API.
// main là nơi biết cả hai và nối chúng lại — nếu httpd tự import api thì
// `go list -deps httpd` sẽ kéo theo apps → proxy, và /healthz không còn độc lập
// với các subsystem nữa.
func WithAPI(h http.Handler) Option {
	return func(o *options) { o.api = h }
}

// WithUI gắn SPA Admin vào "/".
//
// Cũng nhận http.Handler như WithAPI và cùng lý do: httpd không được import
// package ui (nó sẽ kéo theo embed của toàn bộ asset vào đồ thị phụ thuộc của
// tầng ①). main biết cả hai và nối chúng.
func WithUI(h http.Handler) Option {
	return func(o *options) { o.ui = h }
}

// Đường của OIDC, viết TRẦN ở đây chứ không import từ package oidc.
//
// Luật §2.1 cấm httpd import ngoài store + stdlib, và hai chuỗi này là hằng số
// của GIAO THỨC — `/.well-known/openid-configuration` do chuẩn quy định và
// không bao giờ đổi được. Đổi lại, chúng bị trùng lặp với package oidc, nên có
// một test ở phía oidc so hai bên với nhau để phát hiện lệch.
const (
	OIDCPathPrefix    = "/oidc/"
	OIDCDiscoveryPath = "/.well-known/openid-configuration"
)

// oidcNotEnabled — trả lời khi chưa cấu hình IdP.
//
// 501 + JSON + TÊN BIẾN phải đặt. Cùng quy ước với các route /auth khi identity
// chưa cắm: endpoint TỒN TẠI và nói rõ là chưa bật, thay vì để client đoán mò
// giữa "gõ sai đường" và "chưa cấu hình".
func oidcNotEnabled(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": "the OpenID Connect provider is not enabled on this instance",
		"hint":  "set KEENRIG_OIDC_ISSUER to the public URL of this box and restart",
	})
}

// WithMetrics phơi `/metrics` trên CỔNG HTTP của box (ND-07, Luật 7).
//
// # Vì sao cần dòng này, và nó là một lỗ ĐO ĐƯỢC chứ không phải phòng xa
//
// Box vẫn luôn có `/metrics` — nhưng chỉ trên NODE API, và node API nghe trên
// một unix socket. Prometheus không scrape được unix socket. Nên trên một máy
// thật, số liệu của tiến trình quan trọng nhất là thứ không ai lấy được.
//
// Tệ hơn: gọi `/metrics` trên cổng HTTP của box KHÔNG trả 404 — SPA nhận "/"
// nên nó trả HTTP 200 kèm `index.html`. Một cấu hình Prometheus trỏ vào đó sẽ
// báo "up" và không có metric nào, mãi mãi. Đo được bằng e2e chạy ba binary
// thật; hai binary kia (agent, ota) không có SPA nên chúng đúng từ đầu.
//
// Nhận http.Handler như WithAPI và cùng lý do (Luật §2.1): httpd chỉ được import
// store + stdlib.
func WithMetrics(h http.Handler) Option {
	return func(o *options) { o.metrics = h }
}

// WithOIDC gắn nhà cung cấp OpenID Connect (ID-01).
//
// Cùng lý do với WithAPI — nhận http.Handler để httpd không import identity.
//
// Nó được gắn ở ĐƯỜNG RIÊNG chứ không dưới /api/v1: `/api/v1` là hợp đồng của
// Admin UI và có quyền lên version, còn địa chỉ của một IdP mà đổi thì mọi app
// đã cấu hình SSO hỏng cùng một lúc, và người vận hành phải đi sửa từng cái.
func WithOIDC(h http.Handler) Option {
	return func(o *options) { o.oidc = h }
}

// AdminSessionPath — cửa nhận vé "Mở Admin ↗" của Console (`CON-13`).
//
// Hằng số nằm ở đây chứ không lấy từ package api, cùng lý do với WithAPI: httpd
// không import api. Giá của bản sao là một test canh hai hằng số bằng nhau —
// rẻ hơn một chiều phụ thuộc ngược.
const AdminSessionPath = "/_keenrig/admin-session"

// WithAdminSession gắn cửa nhận vé SSO.
//
// Nhận http.Handler như WithAPI và cùng lý do. Đăng ký KHÔNG kèm method: gắn
// riêng "POST" sẽ để mọi GET rơi xuống SPA ở "/", và người dùng bấm nhầm một
// link sẽ nhận về index.html thay vì câu "vé không đi trong URL" — đúng cái bẫy
// đã đo được ở đường OIDC (xem New bên dưới).
func WithAdminSession(h http.Handler) Option {
	return func(o *options) { o.adminSession = h }
}

func New(st store.Store, addr string, opts ...Option) *Server {
	var o options
	for _, fn := range opts {
		fn(&o)
	}
	s := &Server{st: st}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	if o.api != nil {
		mux.Handle("/api/v1/", o.api)
	}
	// Hai đường của OIDC được đăng ký LUÔN LUÔN, kể cả khi provider chưa bật.
	//
	// # Đây là một lỗi ĐO ĐƯỢC trên box thật, không phải phòng xa
	//
	// Bản đầu chỉ đăng ký khi `o.oidc != nil`. Chạy box thật với SPA nhúng trong
	// binary và KHÔNG khai issuer, rồi gọi `/.well-known/openid-configuration`:
	//
	//	HTTP 200, Content-Type text/html, nội dung là index.html của Admin UI
	//
	// Vì SPA nhận "/" nên nó nuốt mọi đường không ai nhận. Một Relying Party gặp
	// đúng thứ tệ nhất: mã thành công, thân là HTML, và lỗi hiện ra dưới dạng
	// "unexpected token < in JSON" ở phía app — không nhắc gì tới việc IdP chưa
	// được bật trên box.
	//
	// Đăng ký luôn, và khi chưa bật thì trả 501 kèm TÊN BIẾN phải đặt.
	if o.adminSession != nil {
		mux.Handle(AdminSessionPath, o.adminSession)
	}
	if o.metrics != nil {
		mux.Handle("GET /metrics", o.metrics)
	}
	if o.oidc != nil {
		mux.Handle(OIDCPathPrefix, o.oidc)
		mux.Handle(OIDCDiscoveryPath, o.oidc)
	} else {
		mux.HandleFunc(OIDCPathPrefix, oidcNotEnabled)
		mux.HandleFunc(OIDCDiscoveryPath, oidcNotEnabled)
	}
	// UI đăng ký CUỐI và ở "/" — pattern cụ thể hơn (/healthz, /api/v1/) luôn
	// thắng trong ServeMux, nên SPA không nuốt mất API.
	if o.ui != nil {
		mux.Handle("/", o.ui)
	}
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s
}

// Start block cho tới khi server dừng; Shutdown chủ động trả về nil.
func (s *Server) Start() error {
	err := s.srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.st.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	// role-readiness thật ở M6
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
