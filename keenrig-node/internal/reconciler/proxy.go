package reconciler

import (
	"context"
	"encoding/json"
	"log"
	"reflect"
	"sort"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/metrics"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/proxy"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// T8 — đẩy định tuyến sang gateway.
//
// # Vì sao việc này nằm trong reconciler
//
// proxy.Apply là LEVEL-TRIGGERED: nó nhận toàn bộ tập site và xoá thứ vắng mặt.
// Hai tiến trình cùng gọi nó với hai ảnh chụp khác nhau sẽ luân phiên xoá site
// của nhau. Reconciler là nơi DUY NHẤT giữ lease (T6b), nên đặt ở đây là cách
// rẻ nhất để có đúng một người ghi — không cần thêm lease thứ hai.
//
// # Vì sao dựng desired từ STORE chứ không từ sự kiện
//
// Mọi thứ cần đều đã nằm trong platform.db: app_domains cho tên miền,
// apps.endpoints cho upstream. Dựng lại từ đầu mỗi lần nghĩa là drift tự lành —
// ai đó sửa tay trên gateway thì tick sau ghi đè. Đi theo delta sẽ phải nhớ
// lịch sử, và trí nhớ đó mất sau mỗi lần restart.

// syncProxy dựng tập site mong muốn từ store rồi gọi proxy.Apply.
//
// Bỏ qua khi không có controller (chưa cấu hình gateway) — box vẫn phải chạy
// được để người dùng vào Admin sửa cấu hình.
func (r *Reconciler) syncProxy(ctx context.Context) {
	if r.proxy == nil {
		return
	}
	sites, err := r.desiredSites(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("reconciler: building desired proxy state: %v", err)
		}
		return
	}

	// Bỏ qua khi KHÔNG có gì đổi: Apply là một lời gọi mạng + ghi cấu hình
	// gateway. Gọi mỗi tick refresh dù không đổi gì sẽ làm log gateway ngập và
	// che mất lần đổi thật.
	if r.lastSites != nil && reflect.DeepEqual(r.lastSites, sites) {
		return
	}

	report, err := r.proxy.Apply(ctx, sites)
	if err != nil {
		metrics.Default.SetProxyApply(r.proxy.Name(), metrics.ProxyApplyError)
		if ctx.Err() == nil {
			log.Printf("reconciler: proxy.Apply: %v", err)
		}
		// KHÔNG cache khi lỗi — lần sau phải thử lại chính tập này.
		r.lastSites = nil
		data, _ := json.Marshal(map[string]any{"error": err.Error(), "sites": len(sites)})
		if aerr := r.st.AppendEvent(ctx, "proxy.apply_failed", "reconciler", "", data); aerr != nil && ctx.Err() == nil {
			log.Printf("reconciler: appending event proxy.apply_failed: %v", aerr)
		}
		return
	}
	metrics.Default.SetProxyApply(r.proxy.Name(), metrics.ProxyApplyOK)
	r.lastSites = sites

	data, _ := json.Marshal(map[string]any{
		"applied": report.Applied,
		"removed": report.Removed,
		"ignored": len(report.Ignored),
	})
	if err := r.st.AppendEvent(ctx, "proxy.applied", "reconciler", "", data); err != nil && ctx.Err() == nil {
		log.Printf("reconciler: appending event proxy.applied: %v", err)
	}
	if len(report.Ignored) > 0 {
		// Log chứ không im lặng: người vận hành cần thấy driver đang CỐ TÌNH
		// không đụng vào cấu hình của họ, chứ không phải đoán xem nó có đụng không.
		log.Printf("reconciler: proxy left %d non-platform route(s) untouched: %v",
			len(report.Ignored), report.Ignored)
	}
}

// desiredSites dựng []proxy.Site từ app_domains + apps.endpoints.
//
// App KHÔNG có endpoint nào (chưa deploy xong, hoặc mọi replica đã chết) thì
// domain của nó bị BỎ QUA, không phải đưa vào với danh sách upstream rỗng: một
// site không upstream trên gateway trả 502, còn không có site thì rơi vào
// catch-all và trả 404. 404 nói đúng sự thật hơn — chưa có gì phục vụ ở đây.
func (r *Reconciler) desiredSites(ctx context.Context) ([]proxy.Site, error) {
	doms, err := r.st.ListAllDomains(ctx)
	if err != nil {
		return nil, err
	}
	platform := r.platformHostList(ctx, doms)
	if len(doms) == 0 && len(platform) == 0 {
		// Tập RỖNG chứ không phải nil, và vẫn gọi Apply: đó là cách gỡ site
		// cuối cùng khi người dùng xoá app cuối. Trả sớm ở đây sẽ để lại route
		// mồ côi vĩnh viễn trên gateway.
		return []proxy.Site{}, nil
	}

	apps, err := r.st.ListApps(ctx)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]*store.App, len(apps))
	for _, a := range apps {
		byID[a.ID] = a
	}

	// T9 — chọn đường TLS theo NĂNG LỰC gateway, không theo cấu hình riêng.
	// caddy có CapACME → nó tự xin, module certs rảnh. nginx không có → ta phải
	// xin trước và cấp xuống, và site nào chưa có cert thì KHÔNG được lên
	// gateway (nginx từ chối nạp cả tập cấu hình nếu thiếu một file cert).
	gatewayACME := r.gatewayHasACME(ctx)
	certRefs := map[string]string{}
	if !gatewayACME {
		want := doms
		for _, h := range platform {
			want = append(want, &store.Domain{FQDN: h})
		}
		certRefs = r.ensureCerts(ctx, want)
	}

	sites := make([]proxy.Site, 0, len(doms)+len(platform))
	for _, h := range platform {
		tlsCfg := proxy.TLS{Mode: proxy.TLSACMEByGateway}
		if !gatewayACME {
			ref, ok := certRefs[h]
			if !ok {
				continue
			}
			tlsCfg = proxy.TLS{Mode: proxy.TLSProvided, CertRef: ref}
		}
		sites = append(sites, proxy.Site{
			FQDN:      h,
			AppID:     PlatformSiteOwner,
			Upstreams: []proxy.Upstream{r.platformUp},
			TLS:       tlsCfg,
			Policy:    proxy.PolicyFrom(nil),
		})
	}
	for _, d := range doms {
		app := byID[d.AppID]
		if app == nil || len(app.Endpoints) == 0 {
			continue
		}
		tlsCfg := proxy.TLS{Mode: proxy.TLSACMEByGateway, CertRef: d.CertRef}
		if !gatewayACME {
			ref, ok := certRefs[d.FQDN]
			if !ok {
				continue // chưa có cert — bỏ site này lần này, tick sau thử lại
			}
			tlsCfg = proxy.TLS{Mode: proxy.TLSProvided, CertRef: ref}
		}
		ups := make([]proxy.Upstream, 0, len(app.Endpoints))
		for _, e := range app.Endpoints {
			ups = append(ups, proxy.Upstream{Host: e.Host, Port: e.Port})
		}
		sort.Slice(ups, func(i, j int) bool {
			if ups[i].Host != ups[j].Host {
				return ups[i].Host < ups[j].Host
			}
			return ups[i].Port < ups[j].Port
		})
		sites = append(sites, proxy.Site{
			FQDN:      d.FQDN,
			AppID:     d.AppID,
			Upstreams: ups,
			TLS:       tlsCfg,
			Policy:    policyOf(app),
		})
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].FQDN < sites[j].FQDN })
	return sites, nil
}

// PlatformSiteOwner — chủ sở hữu ghi vào OwnerKey cho site của CHÍNH box
// (Admin), để phân biệt với site của app khi đọc lại trạng thái gateway.
const PlatformSiteOwner = "keenrig-admin"

// PlatformHosts trả tên miền của CHÍNH box — `<parent>` và `admin.<parent>`.
type PlatformHosts func(ctx context.Context) []string

// WithPlatformHosts — định tuyến Admin của box qua tên miền thật, có TLS thật.
//
// # Vì sao cần, khi đã có catch-all
//
// Catch-all đưa MỌI host lạ về Admin, nhưng nó không có matcher tên nên Caddy
// không biết xin chứng chỉ cho tên nào: trình duyệt gửi SNI `admin.<env>` và
// nhận TLS alert 80, vì trong kho chỉ có chứng chỉ tự ký cho IP. Đo được trên
// VPS công khai thật 2026-10-02 (case 1): DNS đúng, :443 mở, Admin không mở
// được. Trước đó chỉ máy sau NAT chạy được, vì TLS do forwarder của cloud lo.
//
// Tên do CLOUD cấp (luật 2026-09-07) nên đọc lại mỗi lần dựng desired: tên
// đổi thì tick kế tiếp đổi route, không cần restart.
func (r *Reconciler) WithPlatformHosts(up proxy.Upstream, f PlatformHosts) *Reconciler {
	r.platformUp = up
	r.platformHosts = f
	return r
}

// platformHostList — tên của box, trừ tên nào đã có app giữ (app thắng: người
// dùng chủ động gắn tên đó cho app của họ).
func (r *Reconciler) platformHostList(ctx context.Context, doms []*store.Domain) []string {
	if r.platformHosts == nil || r.platformUp.Port == 0 {
		return nil
	}
	taken := make(map[string]bool, len(doms))
	for _, d := range doms {
		taken[d.FQDN] = true
	}
	var out []string
	for _, h := range r.platformHosts(ctx) {
		if h != "" && !taken[h] {
			out = append(out, h)
		}
	}
	return out
}

// policyOf đọc `desired.policy` của app và dựng chính sách cho site (PR-08).
//
// # desired không parse được thì KHÔNG bỏ site
//
// Trả về chính sách mặc định và đi tiếp, chứ không `continue`. Lý lẽ: một desired
// hỏng đã bị `reconcileApp` đánh dấu app lỗi ở chỗ khác — bỏ luôn site ở đây
// nghĩa là app đang chạy bình thường bỗng mất route vì một trường không liên quan
// tới định tuyến. Mất route là mất dịch vụ; mất chính sách là mất một lớp bảo vệ
// mà admission đã kiểm trước đó.
//
// Đây KHÔNG phải chỗ kiểm năng lực gateway. Chuyện đó xảy ra ở
// `apps.checkGatewaySupportsPolicy`, lúc tạo app, khi người dùng còn sửa được.
// Tới đây thì chính sách đã được nhận, và việc của reconciler là chuyển nó xuống
// nguyên vẹn.
func policyOf(app *store.App) proxy.Policy {
	var d contracts.DesiredApp
	if err := json.Unmarshal(app.Desired, &d); err != nil {
		return proxy.PolicyFrom(nil)
	}
	return proxy.PolicyFrom(d.Policy)
}
