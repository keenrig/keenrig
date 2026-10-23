package contracts_test

// `policy` trong desired.schema.json (PR-08).
//
// Mỗi trường ở đây tương ứng MỘT proxy.Capability, và tầng admission dùng chúng
// để từ chối lúc tạo app. Nên schema phải chặt ở đúng những chỗ mà một giá trị
// "hợp lệ về hình dạng nhưng vô nghĩa" sẽ đi qua admission rồi không làm gì.

import (
	"encoding/json"
	"testing"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
)

func TestValidateDesiredPolicy(t *testing.T) {
	const img = `"image": "nginx@sha256:abc"`

	cases := []struct {
		name string
		doc  string
		ok   bool
	}{
		{"policy đủ trường", `{` + img + `, "policy": {
			"waf": {"ruleset": "owasp-crs", "block": true},
			"rate_limit": {"requests_per_minute": 600, "burst": 50},
			"ip_allow": ["10.0.0.0/8"],
			"body_limit_mb": 25,
			"forward_auth": {"url": "https://auth.tld/verify",
			                 "copy_headers": ["X-User"], "allowed_failures": 1}
		}}`, true},
		{"policy rỗng", `{` + img + `, "policy": {}}`, true},
		{"waf chỉ có ruleset", `{` + img + `, "policy": {"waf": {"ruleset": "owasp-crs"}}}`, true},
		{"waf detect-only", `{` + img + `, "policy": {"waf": {"ruleset": "owasp-crs", "block": false}}}`, true},
		{"chỉ ip_deny", `{` + img + `, "policy": {"ip_deny": ["203.0.113.7"]}}`, true},

		// ruleset là enum, không phải chuỗi tự do: tên gõ sai sẽ được nhận rồi
		// không nạp được bộ luật nào, và site chạy KHÔNG có WAF trong khi người
		// dùng tin là có.
		{"ruleset ngoài enum", `{` + img + `, "policy": {"waf": {"ruleset": "owasp"}}}`, false},
		{"ruleset rỗng", `{` + img + `, "policy": {"waf": {"ruleset": ""}}}`, false},
		{"waf thiếu ruleset", `{` + img + `, "policy": {"waf": {"block": true}}}`, false},
		{"waf trường lạ", `{` + img + `, "policy": {"waf": {"ruleset": "owasp-crs", "paranoia": 2}}}`, false},

		// Mảng IP RỖNG khớp không gì cả, nhưng vẫn làm site cần năng lực
		// ip_filter — tức là bị từ chối ở admission mà không ai hiểu vì sao.
		{"ip_allow rỗng", `{` + img + `, "policy": {"ip_allow": []}}`, false},
		{"ip_allow phần tử rỗng", `{` + img + `, "policy": {"ip_allow": [""]}}`, false},
		{"ip_deny trùng phần tử", `{` + img + `, "policy": {"ip_deny": ["1.2.3.4", "1.2.3.4"]}}`, false},

		{"body_limit_mb = 0", `{` + img + `, "policy": {"body_limit_mb": 0}}`, false},
		{"body_limit_mb âm", `{` + img + `, "policy": {"body_limit_mb": -1}}`, false},
		{"rate_limit thiếu rpm", `{` + img + `, "policy": {"rate_limit": {"burst": 10}}}`, false},
		{"rate_limit rpm = 0", `{` + img + `, "policy": {"rate_limit": {"requests_per_minute": 0}}}`, false},
		{"forward_auth thiếu url", `{` + img + `, "policy": {"forward_auth": {"copy_headers": ["X-U"]}}}`, false},
		{"forward_auth url không phải URI", `{` + img + `, "policy": {"forward_auth": {"url": "không phải uri"}}}`, false},

		// Trường bị CỐ Ý bỏ ra khỏi hợp đồng: không có năng lực nào canh chúng,
		// nên chúng sẽ im lặng không có tác dụng. Nhận chúng là hứa một thứ
		// không ai thực thi.
		{"force_https không thuộc hợp đồng", `{` + img + `, "policy": {"force_https": true}}`, false},
		{"set_headers không thuộc hợp đồng", `{` + img + `, "policy": {"set_headers": {"X": "1"}}}`, false},
		{"policy trường lạ", `{` + img + `, "policy": {"bogus": 1}}`, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := contracts.ValidateDesired([]byte(c.doc))
			if c.ok && err != nil {
				t.Fatalf("muốn hợp lệ, nhận: %v", err)
			}
			if !c.ok && err == nil {
				t.Fatal("muốn lỗi, nhận hợp lệ")
			}
		})
	}
}

// Type Go và schema phải đọc được CÙNG tài liệu.
//
// Test này bắt lỗi lệch thẻ json — thứ schema không bắt được vì schema chỉ thấy
// byte, còn `json.Unmarshal` thì bỏ qua trường nó không biết một cách im lặng.
// Hệ quả nếu lệch: desired đi qua admission (schema thấy `policy.waf`) rồi
// `DesiredApp.Policy` là nil, và WAF biến mất không dấu vết.
func TestPolicyRoundTripsThroughGoTypes(t *testing.T) {
	const doc = `{
		"image": "nginx@sha256:abc",
		"policy": {
			"waf": {"ruleset": "owasp-crs", "block": false},
			"rate_limit": {"requests_per_minute": 600, "burst": 50},
			"ip_allow": ["10.0.0.0/8"],
			"ip_deny": ["203.0.113.7"],
			"body_limit_mb": 25,
			"forward_auth": {"url": "https://auth.tld/verify",
			                 "copy_headers": ["X-User"], "allowed_failures": 1}
		}
	}`
	if err := contracts.ValidateDesired([]byte(doc)); err != nil {
		t.Fatalf("tài liệu mẫu không hợp lệ: %v", err)
	}

	var d contracts.DesiredApp
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatal(err)
	}
	if d.Policy == nil {
		t.Fatal("policy biến mất khi unmarshal — thẻ json lệch khỏi schema")
	}
	p := d.Policy
	switch {
	case p.WAF == nil || p.WAF.Ruleset != "owasp-crs":
		t.Errorf("waf = %+v", p.WAF)
	case p.WAF.Blocking():
		t.Error(`"block": false bị mất — Blocking() phải trả false`)
	case p.RateLimit == nil || p.RateLimit.RequestsPerMinute != 600 || p.RateLimit.Burst != 50:
		t.Errorf("rate_limit = %+v", p.RateLimit)
	case len(p.IPAllow) != 1 || len(p.IPDeny) != 1:
		t.Errorf("ip_allow = %v, ip_deny = %v", p.IPAllow, p.IPDeny)
	case p.BodyLimitMB != 25:
		t.Errorf("body_limit_mb = %d", p.BodyLimitMB)
	case p.ForwardAuth == nil || p.ForwardAuth.URL != "https://auth.tld/verify":
		t.Errorf("forward_auth = %+v", p.ForwardAuth)
	}

	// Và chiều ngược lại: marshal ra phải VẪN hợp lệ. Một thẻ json thiếu
	// `omitempty` sẽ ghi ra `"ip_allow": null` — thứ schema từ chối, và chỗ vỡ là
	// UpdateDesired của người dùng chứ không phải test nào.
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.ValidateDesired(raw); err != nil {
		t.Errorf("marshal lại không còn hợp lệ: %v\n%s", err, raw)
	}
}

// Không đặt `block` thì mặc định là CHẶN.
//
// Mặc định ngược lại là một WAF chỉ ghi nhận mà người vận hành tin đang chặn —
// tệ hơn không có WAF, vì nó tạo ra cảm giác an toàn sai.
func TestWAFBlockDefaultsToTrue(t *testing.T) {
	var d contracts.DesiredApp
	err := json.Unmarshal([]byte(`{"image":"x","policy":{"waf":{"ruleset":"owasp-crs"}}}`), &d)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Policy.WAF.Blocking() {
		t.Error("không đặt block → phải CHẶN")
	}
}
