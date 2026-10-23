// Package caddy — driver proxy.Controller trên Caddy, qua admin API.
//
// Đây là driver MẶC ĐỊNH (proxy.DefaultDriver). Lý do không phải hiệu năng —
// ở quy mô một instance thì chênh lệch throughput với nginx không đo được — mà
// là mô hình cấu hình: Caddy nhận config qua lời gọi HTTP, cùng hình dạng với
// runtime.Apply. Không template, không render file, không reload, và do đó
// không có nguồn sự thật thứ hai cho routing nằm trên đĩa.
//
// # Cú pháp KEENRIG_PROXY_CONFIG
//
// Endpoint admin API. Bỏ trống là dùng unix socket dưới paths.RunDir():
//
//	KEENRIG_PROXY_CONFIG="unix//var/lib/keenrig/node/run/caddy-admin.sock"   (mặc định)
//	KEENRIG_PROXY_CONFIG="http://127.0.0.1:2019"
//
// Chỉ nhận hai scheme trên. Admin API của Caddy KHÔNG có xác thực — ai gọi
// được là đổi được toàn bộ định tuyến — nên mặc định là unix socket, và mở ra
// TCP phải là hành động tường minh của người vận hành, không phải giá trị
// mặc định họ vô tình thừa hưởng.
package caddy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/keenrig/keenrig/keenrig-node/internal/proxy"
)

const Name = "caddy"

// Tiền tố endpoint hợp lệ. "unix/" là cách Caddy viết socket trong URL admin.
const (
	schemeUnix  = "unix/"
	schemeHTTP  = "http://"
	schemeHTTPS = "https://"
	dsnUsage    = `syntax: "unix/<socket path>" or "http://host:port"`
	adminSock   = "caddy-admin.sock"
)

func init() {
	proxy.Register(Name, func(ctx context.Context, cfg proxy.Config) (proxy.Controller, error) {
		return New(cfg)
	})
}

type Driver struct {
	// adminURL — endpoint admin API của Caddy.
	adminURL string
	admin    *adminClient
	// configID — tiền tố @id trong JSON config, mang nhãn proxy.ManagedKey.
	// Apply chỉ đụng route mang tiền tố này; route do người vận hành thêm tay
	// được giữ nguyên và liệt kê trong Report.Ignored.
	configID string
	certDir  string
	// adminUI — nơi Admin UI của box đang nghe; đích của catch-all (PX-03).
	// Zero value → catch-all trả 404.
	adminUI proxy.Upstream
	// selfIPs — địa chỉ của chính máy, để cấp cert tự ký (PX-03). Xem selftls.go.
	selfIPs []string
}

var _ proxy.Controller = (*Driver)(nil)

func New(cfg proxy.Config) (*Driver, error) {
	addr := cfg.DSNOr(schemeUnix + filepath.ToSlash(filepath.Join(cfg.Layout.RunDir(), adminSock)))
	if err := checkAdminURL(addr); err != nil {
		return nil, err
	}
	return &Driver{
		adminURL: addr,
		admin:    newAdminClient(addr),
		configID: proxy.ManagedKey,
		certDir:  cfg.Layout.ProxyCerts(),
		adminUI:  cfg.Admin,
		selfIPs:  cfg.SelfIPs,
	}, nil
}

// checkAdminURL kiểm lúc mở, không đợi tới Apply: endpoint sai thì lỗi phải nổ
// lúc khởi động chứ không phải lúc người dùng deploy app đầu tiên.
func checkAdminURL(addr string) error {
	switch {
	case strings.HasPrefix(addr, schemeUnix):
		if strings.TrimPrefix(addr, schemeUnix) == "" {
			return fmt.Errorf("%w: %s: missing socket path after %q — %s",
				proxy.ErrBadConfig, Name, schemeUnix, dsnUsage)
		}
		return nil
	case strings.HasPrefix(addr, schemeHTTP), strings.HasPrefix(addr, schemeHTTPS):
		return nil
	default:
		return fmt.Errorf("%w: %s: unrecognised endpoint %q — %s",
			proxy.ErrBadConfig, Name, addr, dsnUsage)
	}
}

func (d *Driver) Name() string { return Name }

// Capabilities — CapACME là khác biệt đáng giá nhất so với nginx: Caddy tự xin
// và tự gia hạn cert, nên toàn bộ module ACME phía platform không cần chạy.
// CapObserve có thật vì `GET /config/` trả về cấu hình ĐANG chạy, không phải
// bản sao ta tự ghi. CapAtomicApply cũng có thật: POST config sai bị từ chối
// nguyên khối, cấu hình đang phục vụ không đổi.
//
// CapWAF để ngỏ: Caddy chỉ có WAF khi build kèm plugin coraza. Driver phải hỏi
// admin API xem module đã nạp chưa rồi mới được khai báo — vì thế hàm này trả
// error và nhận ctx thay vì là hằng số.
//
// CapRateLimit để ngỏ, và đây là một SỬA LỖI: Caddy KHÔNG có rate limit dựng
// sẵn (cần plugin caddy-ratelimit), mà admin API lại không có endpoint liệt kê
// module đã nạp nên ta không kiểm chứng được.
//
// # Bốn năng lực nữa đã bị GỠ, và lý do giống hệt
//
// TestDeclaredCapabilitiesProduceRealConfig (PR-05) đối chiếu "khai gì" với
// "sinh ra gì" và bắt được bốn dòng khai suông nữa. Cả bốn đều có cùng triệu
// chứng: admission cho qua, cấu hình bị bỏ rơi im lặng, người dùng tưởng đã
// được bảo vệ.
//
//	cert_upload   certDir được lưu vào Driver nhưng KHÔNG BAO GIỜ được đọc;
//	              cert do platform cấp không bao giờ tới Caddy. Caddy tự xin
//	              được (CapACME) nên đường này chưa từng chạy — và chính vì
//	              chưa từng chạy nên không ai phát hiện.
//	tls_passthru  cần app `layer4`, một plugin không có trong bản Caddy chuẩn.
//	forward_auth  buildRoute không sinh handler `forward_auth` nào.
//	body_limit    ĐÃ hiện thực bên dưới (handler request_body) nên nó ở lại.
//
// Gỡ chứ không phải hiện thực vội: một năng lực khai đúng nhưng chưa có thì
// người dùng bị từ chối ở bước TẠO APP với lý do rõ ràng. Một năng lực khai
// sai thì họ deploy xong mới phát hiện — nếu phát hiện được.
func (d *Driver) Capabilities(ctx context.Context) (proxy.Caps, error) {
	return proxy.Caps{
		proxy.CapACME:        true,
		proxy.CapWildcardTLS: true,
		proxy.CapLoadBalance: true,
		proxy.CapWebSocket:   true,
		proxy.CapIPFilter:    true,
		proxy.CapBodyLimit:   true,
		proxy.CapAtomicApply: true,
		proxy.CapObserve:     true,
	}, nil
}

// Apply — LEVEL-TRIGGERED: desired là TOÀN BỘ tập site platform quản lý.
//
// Thuật toán, và vì sao từng bước:
//
//  1. Đọc mảng routes đang chạy. Chưa có server "keenrig" → dựng khung.
//  2. Giữ NGUYÊN VĂN mọi route không mang @id của ta → Report.Ignored. Đây là
//     điều khác biệt giữa "quản lý gateway" và "chiếm gateway".
//  3. Sinh lại toàn bộ route của ta từ desired. Site vắng mặt biến mất — đó
//     chính là ngữ nghĩa level-triggered, và là cách drift tự lành.
//  4. Ghi một lần bằng PATCH cả mảng. Caddy áp nguyên khối (CapAtomicApply):
//     mảng sai bị từ chối và cấu hình đang phục vụ không đổi.
//
// Route của ta xếp TRƯỚC catch-all và sau route lạ: route lạ do người vận hành
// đặt có chủ đích (chuyển hướng, chặn) nên phải được quyền chạy trước.
func (d *Driver) Apply(ctx context.Context, desired []proxy.Site) (proxy.Report, error) {
	var report proxy.Report

	current, err := d.currentRoutes(ctx)
	if err != nil {
		return report, err
	}

	kept := make([]json.RawMessage, 0, len(current))
	for _, r := range current {
		if isManagedID(r.id) {
			continue // route của ta — sinh lại từ desired
		}
		kept = append(kept, r.raw)
		report.Ignored = append(report.Ignored, describeForeign(r))
	}

	next := append([]json.RawMessage(nil), kept...)
	// Thứ tự route của ta: site TLSOff → HTTP→HTTPS → site còn lại → catch-all.
	//
	// Chuyển hướng đứng trước mọi site có TLS và trước catch-all (trang đăng
	// nhập Admin): không request trần nào tới được chúng — xem buildHTTPSRedirect.
	// Site khai TLSOff là lựa chọn TƯỜNG MINH "chỉ HTTP" nên được xếp TRƯỚC
	// chuyển hướng; đẩy nó sang https là làm hỏng đúng thứ người ta yêu cầu.
	ordered, nOff := tlsOffFirst(sortedSites(desired))
	rd, err := buildHTTPSRedirect()
	if err != nil {
		return report, err
	}
	rdRaw, err := json.Marshal(rd)
	if err != nil {
		return report, err
	}
	for i, s := range ordered {
		if i == nOff {
			next = append(next, rdRaw)
		}
		rt, err := buildRoute(s)
		if err != nil {
			return report, err
		}
		raw, err := json.Marshal(rt)
		if err != nil {
			return report, err
		}
		next = append(next, raw)
		report.Applied = append(report.Applied, s.FQDN)
	}
	if nOff == len(ordered) {
		// Không có site TLS nào (kể cả tập rỗng): chuyển hướng vẫn phải đứng
		// trước catch-all, nếu không trang đăng nhập Admin lại đi qua HTTP trần.
		next = append(next, rdRaw)
	}
	// Catch-all luôn ở CUỐI: nó khớp mọi thứ, đứng trước là nuốt hết.
	ca, err := buildCatchAll(d.adminUI)
	if err != nil {
		return report, err
	}
	caRaw, err := json.Marshal(ca)
	if err != nil {
		return report, err
	}
	next = append(next, caRaw)

	// Site do ta quản lý mà không còn trong desired = đã bị gỡ.
	want := make(map[string]bool, len(desired))
	for _, s := range desired {
		want[s.FQDN] = true
	}
	for _, r := range current {
		if fqdn := fqdnFromID(r.id); fqdn != "" && !want[fqdn] {
			report.Removed = append(report.Removed, fqdn)
		}
	}

	if err := d.putRoutes(ctx, next); err != nil {
		return report, err
	}
	// Cert tự ký cho truy cập bằng IP (PX-03). Chạy SAU khi route đã vào: lỗi ở
	// đây KHÔNG được huỷ một lần Apply đã thành công — định tuyến chạy được mà
	// thiếu HTTPS trên IP còn hơn là không định tuyến gì.
	if err := d.ensureSelfSignedTLS(ctx, d.selfIPs); err != nil {
		report.Warnings = append(report.Warnings,
			"could not configure a self-signed certificate for access by IP: "+err.Error())
	}
	return report, nil
}

// Status — READ-ONLY, chỉ trả site do platform quản lý.
//
// Đọc từ cấu hình ĐANG CHẠY của Caddy chứ không phải từ bản sao trong bộ nhớ
// (CapObserve). Đó là cách duy nhất phát hiện drift khi có người sửa tay.
func (d *Driver) Status(ctx context.Context) ([]proxy.Site, error) {
	current, err := d.currentRoutes(ctx)
	if err != nil {
		return nil, err
	}
	var out []proxy.Site
	for _, r := range current {
		fqdn := fqdnFromID(r.id)
		if fqdn == "" {
			continue
		}
		s, err := siteFromRoute(fqdn, r.raw)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FQDN < out[j].FQDN })
	return out, nil
}

// currentRoutes đọc mảng routes của server keenrig; chưa có thì dựng khung rồi
// trả mảng rỗng.
func (d *Driver) currentRoutes(ctx context.Context) ([]rawRoute, error) {
	var raw json.RawMessage
	err := d.admin.getJSON(ctx, routesPath, &raw)
	if err == nil {
		return parseRoutes(raw)
	}
	// Chưa có server: dựng khung rồi coi như chưa có route nào. Không phân biệt
	// được 404 "chưa có" với lỗi thật qua chuỗi lỗi, nên thử dựng khung — dựng
	// khung cũng lỗi thì mới báo lên, kèm cả hai nguyên nhân.
	if ensureErr := d.ensureServer(ctx); ensureErr != nil {
		return nil, fmt.Errorf("%w (while reading the previous routes: %v)", ensureErr, err)
	}
	return nil, nil
}

// ensureServer dựng apps.http.servers.keenrig nếu chưa có.
//
// Dùng PUT theo từng nhánh thay vì POST /load: /load THAY TOÀN BỘ config, tức
// là xoá sạch mọi thứ người vận hành đã cấu hình. Với một driver có nguyên tắc
// "không đụng thứ không phải của mình", /load là lệnh không bao giờ được gọi.
func (d *Driver) ensureServer(ctx context.Context) error {
	for _, step := range []struct {
		path string
		body any
	}{
		{"/config/apps", map[string]any{}},
		{"/config/apps/http", map[string]any{}},
		{"/config/apps/http/servers", map[string]any{}},
		{"/config/apps/http/servers/" + serverName, map[string]any{
			"listen": []string{":80", ":443"},
			"routes": []any{},
			// tls_connection_policies BẮT BUỘC — đây là một lỗi đã đo được
			// trên Caddy thật, không phải phòng xa.
			//
			// Automatic HTTPS của Caddy suy ra "cổng này cần TLS" từ các host
			// matcher trong route. Trên một máy CHƯA CÓ TÊN MIỀN NÀO thì route
			// duy nhất là catch-all, mà catch-all không có matcher — nên Caddy
			// kết luận :443 không cần TLS và phục vụ HTTP TRẦN ở đó.
			//
			// Triệu chứng không giống lỗi cấu hình: `https://ip/` hỏng bắt tay,
			// còn `http://ip:443/` trả về Admin UI bình thường. Tức là toàn bộ
			// bề mặt quản trị của một máy vừa cài nằm trên cleartext, và không
			// có dòng log nào nói điều đó.
			//
			// Policy RỖNG `{}` = áp cho mọi kết nối, để Caddy tự chọn cert.
			"tls_connection_policies": []map[string]any{{}},
		}},
	} {
		// PUT là idempotent theo nghĩa ta cần: nhánh đã có thì Caddy trả lỗi,
		// và ta bỏ qua — kiểm "đã có chưa" rồi mới ghi sẽ mở ra cửa sổ đúng
		// giữa hai bước.
		if _, err := d.admin.do(ctx, http.MethodPut, step.path, step.body); err != nil {
			if !alreadyExists(err) {
				return err
			}
		}
	}
	return nil
}

// alreadyExists nhận diện lỗi "nhánh đã tồn tại" của Caddy.
func alreadyExists(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "already exists") || strings.Contains(s, "conflict")
}

func (d *Driver) putRoutes(ctx context.Context, routes []json.RawMessage) error {
	_, err := d.admin.do(ctx, http.MethodPatch, routesPath, routes)
	return err
}

const routesPath = "/config/apps/http/servers/" + serverName + "/routes"

// describeForeign mô tả route KHÔNG thuộc platform để đưa vào Report.Ignored.
// Có @id thì dùng @id; không có thì cắt ngắn JSON — người vận hành cần nhận ra
// route nào đang được giữ nguyên, kể cả khi nó không đặt tên.
func describeForeign(r rawRoute) string {
	if r.id != "" {
		return r.id
	}
	s := string(r.raw)
	const max = 120
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// siteFromRoute dựng lại Site (một phần) từ route đọc về — đủ để so drift.
func siteFromRoute(fqdn string, raw json.RawMessage) (proxy.Site, error) {
	s := proxy.Site{FQDN: fqdn, TLS: proxy.TLS{Mode: proxy.TLSACMEByGateway}}
	var rt struct {
		Handle []struct {
			Handler   string `json:"handler"`
			Upstreams []struct {
				Dial string `json:"dial"`
			} `json:"upstreams"`
		} `json:"handle"`
	}
	if err := json.Unmarshal(raw, &rt); err != nil {
		return s, fmt.Errorf("caddy: route %s could not be decoded: %w", fqdn, err)
	}
	for _, h := range rt.Handle {
		if h.Handler != "reverse_proxy" {
			continue
		}
		for _, u := range h.Upstreams {
			host, portStr, err := net.SplitHostPort(u.Dial)
			if err != nil {
				continue
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				continue
			}
			s.Upstreams = append(s.Upstreams, proxy.Upstream{Host: host, Port: port})
		}
	}
	return s, nil
}

// tlsOffFirst xếp site TLSOff lên đầu (giữ thứ tự ổn định trong mỗi nhóm) và
// trả số site TLSOff — vị trí chèn route HTTP→HTTPS.
func tlsOffFirst(sites []proxy.Site) ([]proxy.Site, int) {
	out := make([]proxy.Site, 0, len(sites))
	for _, s := range sites {
		if s.TLS.Mode == proxy.TLSOff {
			out = append(out, s)
		}
	}
	n := len(out)
	for _, s := range sites {
		if s.TLS.Mode != proxy.TLSOff {
			out = append(out, s)
		}
	}
	return out, n
}
