package proxy

import (
	"strings"
	"testing"
)

func TestTLSModeQuyetDinhNangLucCanThiet(t *testing.T) {
	cases := []struct {
		mode TLSMode
		want Capability
	}{
		{TLSACMEByGateway, CapACME},
		{TLSProvided, CapCertUpload},
		{TLSPassthrough, CapTLSPassthru},
	}
	for _, c := range cases {
		got := Site{FQDN: "a.tld", TLS: TLS{Mode: c.mode}}.Requires()
		if !got.Has(c.want) {
			t.Errorf("TLS mode %q phải cần %q, Requires() = %v", c.mode, c.want, got)
		}
	}
	if got := (Site{FQDN: "a.tld", TLS: TLS{Mode: TLSOff}}).Requires(); len(got) != 0 {
		t.Errorf("TLS off không cần năng lực nào, nhận %v", got)
	}
}

func TestRequiresBaoPhuMoiTruongPolicy(t *testing.T) {
	s := Site{
		FQDN: "a.tld",
		TLS:  TLS{Mode: TLSACMEByGateway},
		Upstreams: []Upstream{
			{Host: "10.0.0.1", Port: 80},
			{Host: "10.0.0.2", Port: 80},
		},
		Policy: Policy{
			RateLimit:   &RateLimit{RequestsPerMinute: 600},
			IPDeny:      []string{"1.2.3.4"},
			ForwardAuth: &ForwardAuth{URL: "http://box/authz"},
			WAF:         &WAF{Ruleset: "owasp-crs", Block: true},
			BodyLimitMB: 50,
		},
	}
	for _, want := range []Capability{
		CapACME, CapLoadBalance, CapRateLimit, CapIPFilter,
		CapForwardAuth, CapWAF, CapBodyLimit,
	} {
		if !s.Requires().Has(want) {
			t.Errorf("thiếu %q trong Requires()", want)
		}
	}
}

func TestMotUpstreamKhongCanLoadBalance(t *testing.T) {
	s := Site{FQDN: "a.tld", Upstreams: []Upstream{{Host: "10.0.0.1", Port: 80}}}
	if s.Requires().Has(CapLoadBalance) {
		t.Error("một upstream mà vẫn đòi load_balance")
	}
}

// Đây là bất biến trung tâm: KHÔNG được im lặng bỏ qua tính năng gateway không
// đỡ được. Người dùng bật WAF trên gateway không có WAF phải bị từ chối, chứ
// không phải chạy tiếp mà tưởng mình đã được bảo vệ.
func TestCheckKhongImLangBoQuaTinhNangThieu(t *testing.T) {
	// NPM: có ACME, không có WAF, không có rate limit.
	npm := Caps{CapACME: true, CapCertUpload: true, CapWebSocket: true}

	sites := []Site{
		{FQDN: "b.tld", TLS: TLS{Mode: TLSACMEByGateway}, Policy: Policy{WAF: &WAF{Ruleset: "owasp-crs"}}},
		{FQDN: "a.tld", TLS: TLS{Mode: TLSACMEByGateway}, Policy: Policy{RateLimit: &RateLimit{RequestsPerMinute: 60}}},
	}

	got := Check(sites, npm)
	if len(got) != 2 {
		t.Fatalf("muốn 2 mục không đỡ được, nhận %d: %v", len(got), got)
	}
	// Sắp xếp ổn định: a.tld trước b.tld.
	if got[0].FQDN != "a.tld" || got[0].Cap != CapRateLimit {
		t.Errorf("mục đầu = %+v, muốn a.tld/rate_limit", got[0])
	}
	if got[1].FQDN != "b.tld" || got[1].Cap != CapWAF {
		t.Errorf("mục hai = %+v, muốn b.tld/waf", got[1])
	}
	if msg := got[1].Error(); !strings.Contains(msg, "b.tld") || !strings.Contains(msg, "waf") {
		t.Errorf("thông báo lỗi không nêu rõ site và năng lực: %q", msg)
	}
}

func TestCheckSachKhiDuNangLuc(t *testing.T) {
	caddy := Caps{
		CapACME: true, CapLoadBalance: true, CapWebSocket: true,
		CapRateLimit: true, CapForwardAuth: true, CapWAF: true,
		CapBodyLimit: true, CapIPFilter: true, CapAtomicApply: true, CapObserve: true,
	}
	s := Site{
		FQDN:      "a.tld",
		TLS:       TLS{Mode: TLSACMEByGateway},
		Upstreams: []Upstream{{Host: "10.0.0.1", Port: 80}, {Host: "10.0.0.2", Port: 80}},
		Policy:    Policy{WAF: &WAF{Ruleset: "owasp-crs"}, RateLimit: &RateLimit{RequestsPerMinute: 60}},
	}
	if got := Check([]Site{s}, caddy); len(got) != 0 {
		t.Errorf("đủ năng lực mà vẫn báo thiếu: %v", got)
	}
}

// Xếp tầng: Cloudflare ở biên đỡ WAF, Caddy ở gốc đỡ upstream nội bộ. Hợp của
// hai lớp mới đủ phục vụ site — đó là lý do Union tồn tại.
func TestUnionChoPhepXepTangWAFTruocProxy(t *testing.T) {
	edge := Caps{CapWAF: true, CapRateLimit: true, CapACME: true}
	origin := Caps{CapLoadBalance: true, CapForwardAuth: true, CapObserve: true}

	s := Site{
		FQDN:      "a.tld",
		TLS:       TLS{Mode: TLSACMEByGateway},
		Upstreams: []Upstream{{Host: "10.0.0.1", Port: 80}, {Host: "10.0.0.2", Port: 80}},
		Policy:    Policy{WAF: &WAF{Ruleset: "owasp-crs"}, ForwardAuth: &ForwardAuth{URL: "http://box/authz"}},
	}

	if got := Check([]Site{s}, edge); len(got) == 0 {
		t.Error("chỉ lớp biên thì phải thiếu load_balance/forward_auth")
	}
	if got := Check([]Site{s}, origin); len(got) == 0 {
		t.Error("chỉ lớp gốc thì phải thiếu waf/acme")
	}
	if got := Check([]Site{s}, Union(edge, origin)); len(got) != 0 {
		t.Errorf("hợp hai lớp phải đủ, còn thiếu: %v", got)
	}
}

func TestUnionBoQuaGiaTriFalse(t *testing.T) {
	u := Union(Caps{CapWAF: false}, Caps{CapACME: true})
	if u.Has(CapWAF) {
		t.Error("Union giữ lại năng lực đánh dấu false")
	}
	if !u.Has(CapACME) {
		t.Error("Union đánh rơi năng lực true")
	}
}
