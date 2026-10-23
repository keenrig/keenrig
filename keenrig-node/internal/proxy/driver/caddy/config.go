package caddy

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/proxy"
)

// Dịch proxy.Site → route JSON của Caddy.
//
// # Danh tính là @id, không phải vị trí trong mảng
//
// Caddy giữ routes trong một MẢNG có thứ tự. Nếu ta nhận diện route của mình
// bằng chỉ số thì mọi thao tác của người vận hành (thêm một route thủ công ở
// đầu mảng) sẽ làm ta sửa nhầm route của họ. `@id` là định danh Caddy hỗ trợ
// sẵn và bền qua sắp xếp lại — đúng nguyên tắc 2 của seam proxy.
const (
	// serverName — tên server HTTP trong config Caddy do platform quản lý.
	serverName = "keenrig"
	// idPrefix — tiền tố @id của mọi route ta tạo.
	idPrefix = proxy.ManagedKey + "/"
	// catchAllID — route bắt mọi request KHÔNG khớp domain nào (PX-09).
	catchAllID = proxy.ManagedKey + "/catch-all"
	// httpsRedirectID — route đẩy mọi request HTTP trần sang HTTPS.
	httpsRedirectID = proxy.ManagedKey + "/http-to-https"
)

// route — chỉ khai những trường ta thực sự ghi. Phần còn lại của route do
// người vận hành tạo được giữ nguyên dưới dạng json.RawMessage (xem serverRoutes),
// nên khai thiếu trường ở đây KHÔNG làm mất cấu hình của họ.
type route struct {
	ID       string            `json:"@id,omitempty"`
	Match    []matcher         `json:"match,omitempty"`
	Handle   []json.RawMessage `json:"handle,omitempty"`
	Terminal bool              `json:"terminal,omitempty"`
}

type matcher struct {
	Host     []string `json:"host,omitempty"`
	Protocol string   `json:"protocol,omitempty"`
	RemoteIP *remIP   `json:"remote_ip,omitempty"`
	// Not — các bộ matcher phủ định: khớp khi KHÔNG bộ nào khớp (Caddy `not`).
	Not []matcher `json:"not,omitempty"`
}

// Loopback — dùng để miễn chuyển hướng cho request NỘI BỘ (xem buildHTTPSRedirect).
var (
	loopbackHosts  = []string{"127.0.0.1", "localhost", "::1"}
	loopbackRanges = []string{"127.0.0.0/8", "::1/128"}
)

type remIP struct {
	Ranges []string `json:"ranges,omitempty"`
	Forbid bool     `json:"forbidden,omitempty"`
}

// siteRouteID — @id của route phục vụ một FQDN.
func siteRouteID(fqdn string) string { return idPrefix + fqdn }

// isManagedID cho biết @id có thuộc platform không.
func isManagedID(id string) bool { return strings.HasPrefix(id, idPrefix) }

// fqdnFromID lấy lại FQDN từ @id ("" nếu không phải route site của ta).
func fqdnFromID(id string) string {
	if !isManagedID(id) || id == catchAllID || id == httpsRedirectID {
		return ""
	}
	return strings.TrimPrefix(id, idPrefix)
}

// buildRoute dịch một Site thành route Caddy.
//
// Thứ tự handler CÓ NGHĨA và không đổi chỗ được: chặn IP → giới hạn body →
// đặt header → reverse_proxy. Đưa reverse_proxy lên trước là gửi request tới
// app rồi mới nghĩ đến chuyện có nên chặn nó không.
func buildRoute(s proxy.Site) (route, error) {
	if len(s.Upstreams) == 0 {
		return route{}, fmt.Errorf("caddy: site %s has no upstream", s.FQDN)
	}
	m := matcher{Host: []string{s.FQDN}}
	if len(s.Policy.IPDeny) > 0 {
		m.RemoteIP = &remIP{Ranges: s.Policy.IPDeny, Forbid: true}
	} else if len(s.Policy.IPAllow) > 0 {
		m.RemoteIP = &remIP{Ranges: s.Policy.IPAllow}
	}

	var handlers []json.RawMessage
	if s.Policy.BodyLimitMB > 0 {
		h, err := jsonRaw(map[string]any{
			"handler":  "request_body",
			"max_size": int64(s.Policy.BodyLimitMB) << 20,
		})
		if err != nil {
			return route{}, err
		}
		handlers = append(handlers, h)
	}
	if len(s.Policy.SetHeaders) > 0 {
		set := map[string][]string{}
		for k, v := range s.Policy.SetHeaders {
			set[k] = []string{v}
		}
		h, err := jsonRaw(map[string]any{
			"handler":  "headers",
			"response": map[string]any{"set": set},
		})
		if err != nil {
			return route{}, err
		}
		handlers = append(handlers, h)
	}

	ups := make([]map[string]string, 0, len(s.Upstreams))
	for _, u := range s.Upstreams {
		ups = append(ups, map[string]string{"dial": net.JoinHostPort(u.Host, strconv.Itoa(u.Port))})
	}
	rp := map[string]any{
		"handler":   "reverse_proxy",
		"upstreams": ups,
		// PX-06 — WebSocket (terminal) và SSE (logs) đi qua được.
		//
		// flush_interval = -1 nghĩa là ĐẨY NGAY, không gom bộ đệm. Không có nó,
		// Caddy gom response và SSE chỉ tới trình duyệt khi bộ đệm đầy hoặc
		// kết nối đóng — tức là log "streaming" hiện ra thành từng cục sau vài
		// phút, hoặc không hiện gì cho tới khi người dùng đóng tab.
		//
		// Triệu chứng này KHÔNG giống một lỗi cấu hình: app chạy đúng, gateway
		// không báo lỗi, và mọi request thường đều bình thường. Chỉ có tính
		// năng xem log là "hơi lạ". Đó là lý do nó phải nằm ở đây, có tên, và
		// có test canh.
		//
		// WebSocket thì reverse_proxy của Caddy tự nâng cấp — không cần khai
		// thêm, nhưng flush_interval = -1 cũng là điều kiện để nó không bị
		// đệm ở chiều ngược lại.
		"flush_interval": -1,
	}
	if len(ups) > 1 {
		// least_conn thay vì round_robin: replica của cùng một app không đồng
		// đều về thời gian xử lý (một cái đang pull ảnh, một cái đang GC), và
		// round_robin sẽ đều đặn nhồi request vào cái đang chậm.
		rp["load_balancing"] = map[string]any{"selection_policy": map[string]any{"policy": "least_conn"}}
	}
	h, err := jsonRaw(rp)
	if err != nil {
		return route{}, err
	}
	handlers = append(handlers, h)

	return route{
		ID:    siteRouteID(s.FQDN),
		Match: []matcher{m},
		// terminal: khớp host rồi thì dừng, không rơi xuống route sau — nếu
		// không, catch-all sẽ nuốt mọi request đã có chủ.
		Handle:   handlers,
		Terminal: true,
	}, nil
}

// buildCatchAll — PX-03 + PX-09: request tới thẳng IP máy chủ (hoặc một domain
// lạ trỏ về đây) đi ĐÂU.
//
// Hai ràng buộc phải thoả cùng lúc, và chúng kéo về hai hướng:
//
//	PX-09  KHÔNG được rơi vào app đầu tiên trong danh sách. Nếu không thì ai
//	       biết IP là truy cập được app bất kỳ mà chẳng cần biết tên miền —
//	       vô hiệu hoá mọi giới hạn theo domain.
//	PX-03  PHẢI vào được Admin UI bằng IP. Một máy vừa cài chưa có tên miền
//	       nào; bắt buộc có domain mới vào được Admin nghĩa là người dùng
//	       không có cách nào cấu hình cái domain đầu tiên.
//
// Chuyển tiếp về Admin UI thoả cả hai: nó KHÔNG phải app của người dùng (nên
// PX-09 giữ nguyên), và nó là màn hình duy nhất có ý nghĩa khi chưa có gì được
// cấu hình. Bản trước trả 404 — thoả PX-09 nhưng làm PX-03 bất khả thi, và đó
// là chỗ tôi đọc ngược spec.
//
// admin zero value → quay về 404. Không đoán "chắc là 127.0.0.1:8080": đoán
// sai thì catch-all chuyển tiếp yêu cầu vào một cổng lạ nào đó trên máy.
func buildCatchAll(admin proxy.Upstream) (route, error) {
	var body map[string]any
	if admin.Host == "" || admin.Port == 0 {
		body = map[string]any{
			"handler":     "static_response",
			"status_code": 404,
			"body":        "404 — no site matches this domain\n",
		}
	} else {
		body = map[string]any{
			"handler": "reverse_proxy",
			"upstreams": []map[string]any{
				{"dial": net.JoinHostPort(admin.Host, strconv.Itoa(admin.Port))},
			},
			// Cùng lý do với route app (PX-06): Admin UI cũng dùng SSE cho
			// tiến độ job. Thiếu dòng này thì thanh tiến độ đứng im tới lúc
			// job xong — và "đang chạy" lại nhìn giống hệt "đã treo", đúng thứ
			// internal/jobs sinh ra để dẹp.
			"flush_interval": -1,
		}
	}
	h, err := jsonRaw(body)
	if err != nil {
		return route{}, err
	}
	return route{ID: catchAllID, Handle: []json.RawMessage{h}, Terminal: true}, nil
}

// buildHTTPSRedirect — MỌI request HTTP trần → 308 sang https cùng host + URI.
//
// # Vì sao Caddy không tự làm việc này ở đây
//
// Server `keenrig` nghe CẢ :80 lẫn :443 trong MỘT server. Chuyển hướng tự động
// của Caddy chỉ áp khi :80 KHÔNG thuộc một server do người dùng khai — nên mọi
// route (Admin lẫn app) phục vụ được qua HTTP trần. Đo được 2026-10-03:
// `http://admin.<env>`, `http://<tên-bất-kỳ>.<env>` (DNS wildcard) và
// `http://<IP>` đều trả trang đăng nhập Keenrig Admin không mã hoá, và Google
// báo "trình duyệt sẽ cảnh báo khi người dùng nhập mật khẩu đã lưu" cho site.
//
// Thử thách ACME HTTP-01 KHÔNG bị chặn: Caddy trả `/.well-known/acme-challenge`
// ở tầng server, trước khi duyệt route. IP thì sang https với chứng chỉ tự ký
// (policy self-signed-ip) — PX-03 vẫn giữ: vào Admin bằng IP, có mã hoá.
//
// # Ngoại lệ duy nhất: request nội bộ gửi tới loopback
//
// Loopback CỐ Ý không có cert tự ký (selftls.go chỉ lấy IP không phải loopback),
// nên chuyển `http://127.0.0.1/` sang https là đẩy nó tới một handshake chắc
// chắn hỏng. Đo được 2026-10-14 trên Ubuntu 26.04 (Contabo): get.sh kiểm tra
// cổng 80 bằng `curl -L http://127.0.0.1/healthz`, nhận 308 → TLS "internal
// error", và báo "port 80 does not reach it" trên một máy đang chạy tốt.
//
// Miễn trừ khi CẢ HAI cùng là loopback — Host VÀ địa chỉ nguồn. Chỉ xét Host thì
// ai ngoài Internet gửi `Host: 127.0.0.1` cũng lấy được trang đăng nhập qua
// HTTP trần; chỉ xét nguồn thì một request nội bộ tới tên miền thật lại thoát
// khỏi HTTPS. Request từ chính máy thì không đi qua mạng nào để bị nghe lén.
func buildHTTPSRedirect() (route, error) {
	h, err := jsonRaw(map[string]any{
		"handler":     "static_response",
		"status_code": 308,
		"headers": map[string][]string{
			"Location": {"https://{http.request.host}{http.request.uri}"},
		},
	})
	if err != nil {
		return route{}, err
	}
	return route{
		ID:       httpsRedirectID,
		Match: []matcher{{
			Protocol: "http",
			Not: []matcher{{
				Host:     loopbackHosts,
				RemoteIP: &remIP{Ranges: loopbackRanges},
			}},
		}},
		Handle:   []json.RawMessage{h},
		Terminal: true,
	}, nil
}

func jsonRaw(v any) (json.RawMessage, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(raw), nil
}

// rawRoute — route đọc về từ Caddy, giữ NGUYÊN VĂN.
//
// Giữ nguyên văn là điều kiện để không phá cấu hình của người vận hành: nếu ta
// unmarshal vào struct `route` rồi marshal lại, mọi trường ta chưa khai (group,
// error handlers, matcher lạ…) sẽ bốc hơi trong lần Apply đầu tiên.
type rawRoute struct {
	raw json.RawMessage
	id  string
}

func parseRoutes(raw json.RawMessage) ([]rawRoute, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("caddy: routes is not an array: %w", err)
	}
	out := make([]rawRoute, 0, len(items))
	for _, it := range items {
		var probe struct {
			ID string `json:"@id"`
		}
		// Route không parse được @id vẫn phải giữ: nó là cấu hình của người
		// khác, và ta không có quyền vứt thứ mình không hiểu.
		_ = json.Unmarshal(it, &probe)
		out = append(out, rawRoute{raw: it, id: probe.ID})
	}
	return out, nil
}

// sortedSites trả bản sao đã sắp xếp theo FQDN.
//
// Thứ tự ổn định để hai lần Apply với cùng tập site sinh ra CÙNG một mảng JSON.
// Không có nó, mảng routes đổi thứ tự mỗi lần và Caddy ghi lại config mỗi tick
// dù chẳng có gì thay đổi — Apply hết idempotent theo nghĩa quan sát được.
func sortedSites(sites []proxy.Site) []proxy.Site {
	out := append([]proxy.Site(nil), sites...)
	sort.Slice(out, func(i, j int) bool { return out[i].FQDN < out[j].FQDN })
	return out
}
