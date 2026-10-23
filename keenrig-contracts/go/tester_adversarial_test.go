// tester_adversarial_test.go — test đối kháng do Agent Tester thêm (vòng nghiệm thu M0).
// Mục đích: kiểm chứng độc lập từng ràng buộc trong bảng T1.1–T1.4 của M0-SPEC.md,
// đặc biệt các nhánh mà validate_test.go của Coder chưa chạm tới
// (minLength, uniqueItems, format assertion uuid/hostname, pattern, min/max biên).
package contracts

import "testing"

func TestAdversarialDesired(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{"minimal hợp lệ chỉ image", `{"image":"nginx"}`, false},
		{"image rỗng (minLength 1)", `{"image":""}`, true},
		{"domains trùng nhau (uniqueItems)", `{"image":"nginx","domains":["a.example.com","a.example.com"]}`, true},
		{"domains hostname sai format", `{"image":"nginx","domains":["not_a_host!name"]}`, true},
		{"replicas 0 (minimum 1)", `{"image":"x","resources":{"replicas":0}}`, true},
		{"field lạ top-level (additionalProperties)", `{"image":"x","foo":1}`, true},
		{"env value là số", `{"image":"x","env":{"PORT":8080}}`, true},
		{"resources.memory_mb 63 (min 64)", `{"image":"x","resources":{"memory_mb":63}}`, true},
		{"resources.cpu = 0 (exclusiveMinimum)", `{"image":"x","resources":{"cpu":0}}`, true},
		{"autoscale thiếu enabled (required)", `{"image":"x","autoscale":{"cpu_high":50}}`, true},
		{"autoscale.cpu_high 101 (max 100)", `{"image":"x","autoscale":{"enabled":true,"cpu_high":101}}`, true},
		{"addons field lạ trong postgres", `{"image":"x","addons":{"postgres":{"enabled":true,"size":"big"}}}`, true},
		{"đầy đủ hợp lệ", `{"image":"nginx:1@sha256:abc","domains":["a.example.com","b.example.com"],"env":{"A":"1"},"addons":{"postgres":{"enabled":true},"redis":{"enabled":false}},"resources":{"memory_mb":64,"cpu":0.5,"replicas":1},"sso":{"enabled":true},"backup":{"enabled":true,"schedule":"@daily"},"autoscale":{"enabled":true,"cpu_high":80,"max_replicas":3}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDesired([]byte(tc.json))
			if (err != nil) != tc.wantErr {
				t.Fatalf("wantErr=%v got err=%v", tc.wantErr, err)
			}
		})
	}
}

func TestAdversarialSync(t *testing.T) {
	validReq := `{"env_id":"e1","version":"0.1.0","heartbeat":{"ts":"2026-08-05T00:00:00Z","uptime_s":10}}`
	validCmd := `{"id":"c1","idempotency_key":"3fa85f64-5717-4562-b3fc-2c963f66afa6","kind":"notice","payload":{}}`

	reqCases := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{"request hợp lệ tối thiểu", validReq, false},
		{"thiếu heartbeat", `{"env_id":"e1","version":"0.1.0"}`, true},
		{"heartbeat thiếu ts", `{"env_id":"e1","version":"0.1.0","heartbeat":{"uptime_s":1}}`, true},
		{"heartbeat.ts sai date-time", `{"env_id":"e1","version":"0.1.0","heartbeat":{"ts":"hôm-qua"}}`, true},
		{"host_role lạ", `{"env_id":"e1","version":"0.1.0","host_role":"observer","heartbeat":{"ts":"2026-08-05T00:00:00Z"}}`, true},
		{"field lạ top-level", `{"env_id":"e1","version":"0.1.0","heartbeat":{"ts":"2026-08-05T00:00:00Z"},"extra":true}`, true},
		{"app_statuses state lạ", `{"env_id":"e1","version":"0.1.0","heartbeat":{"ts":"2026-08-05T00:00:00Z"},"app_statuses":[{"app_id":"a","state":"exploded"}]}`, true},
	}
	for _, tc := range reqCases {
		t.Run("req/"+tc.name, func(t *testing.T) {
			err := ValidateSyncRequest([]byte(tc.json))
			if (err != nil) != tc.wantErr {
				t.Fatalf("wantErr=%v got err=%v", tc.wantErr, err)
			}
		})
	}

	respCases := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{"response hợp lệ", `{"commands":[` + validCmd + `],"next_poll_ms":500}`, false},
		{"commands rỗng hợp lệ", `{"commands":[]}`, false},
		{"kind rm_rf ngoài enum", `{"commands":[{"id":"c1","idempotency_key":"3fa85f64-5717-4562-b3fc-2c963f66afa6","kind":"rm_rf","payload":{}}]}`, true},
		{"idempotency_key không phải uuid (format assertion)", `{"commands":[{"id":"c1","idempotency_key":"not-a-uuid","kind":"notice","payload":{}}]}`, true},
		{"command thiếu payload", `{"commands":[{"id":"c1","idempotency_key":"3fa85f64-5717-4562-b3fc-2c963f66afa6","kind":"notice"}]}`, true},
		{"next_poll_ms 100 (min 500)", `{"commands":[],"next_poll_ms":100}`, true},
		{"thiếu commands (required)", `{"next_poll_ms":1000}`, true},
	}
	for _, tc := range respCases {
		t.Run("resp/"+tc.name, func(t *testing.T) {
			err := ValidateSyncResponse([]byte(tc.json))
			if (err != nil) != tc.wantErr {
				t.Fatalf("wantErr=%v got err=%v", tc.wantErr, err)
			}
		})
	}
}

func TestAdversarialManifest(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{"hợp lệ tối thiểu", `{"id":"my-app","version":"1.2.3","image":"repo/app@sha256:deadbeef","httpPort":8080}`, false},
		{"image không có @sha256:", `{"id":"my-app","version":"1.2.3","image":"repo/app:latest","httpPort":8080}`, true},
		{"id viết hoa (pattern)", `{"id":"MyApp","version":"1.2.3","image":"repo/app@sha256:deadbeef","httpPort":8080}`, true},
		{"id 1 ký tự (pattern cần ≥2)", `{"id":"a","version":"1.2.3","image":"repo/app@sha256:deadbeef","httpPort":8080}`, true},
		{"httpPort 70000 (max 65535)", `{"id":"my-app","version":"1.2.3","image":"repo/app@sha256:deadbeef","httpPort":70000}`, true},
		{"httpPort 0 (min 1)", `{"id":"my-app","version":"1.2.3","image":"repo/app@sha256:deadbeef","httpPort":0}`, true},
		{"version không semver", `{"id":"my-app","version":"v1","image":"repo/app@sha256:deadbeef","httpPort":8080}`, true},
		{"field lạ", `{"id":"my-app","version":"1.2.3","image":"repo/app@sha256:deadbeef","httpPort":8080,"port":80}`, true},
		{"healthcheck interval_s 0", `{"id":"my-app","version":"1.2.3","image":"repo/app@sha256:deadbeef","httpPort":8080,"healthcheck":{"interval_s":0}}`, true},
		{"addons cross-file $ref hợp lệ", `{"id":"my-app","version":"1.2.3","image":"repo/app@sha256:deadbeef","httpPort":8080,"addons":{"redis":{"enabled":true}}}`, false},
		{"addons cross-file $ref sai shape", `{"id":"my-app","version":"1.2.3","image":"repo/app@sha256:deadbeef","httpPort":8080,"addons":{"redis":{}}}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateManifest([]byte(tc.json))
			if (err != nil) != tc.wantErr {
				t.Fatalf("wantErr=%v got err=%v", tc.wantErr, err)
			}
		})
	}
}

func TestAdversarialLicense(t *testing.T) {
	base := `"license_id":"l1","instance_id":"i1","issued_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z"`
	cases := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{"hợp lệ", `{` + base + `,"features":{"runtime":"docker","max_nodes":1,"ha_t1":false},"grace_days":14}`, false},
		{"grace_days -1 (min 0)", `{` + base + `,"features":{"runtime":"docker"},"grace_days":-1}`, true},
		{"runtime podman ngoài enum", `{` + base + `,"features":{"runtime":"podman"},"grace_days":14}`, true},
		{"features thiếu runtime", `{` + base + `,"features":{"max_nodes":2},"grace_days":14}`, true},
		{"features field lạ", `{` + base + `,"features":{"runtime":"k8s","gpu":true},"grace_days":14}`, true},
		{"thiếu grace_days (required)", `{` + base + `,"features":{"runtime":"docker"}}`, true},
		{"expires_at sai date-time", `{"license_id":"l1","instance_id":"i1","issued_at":"2026-01-01T00:00:00Z","expires_at":"sang-năm","features":{"runtime":"docker"},"grace_days":14}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateLicense([]byte(tc.json))
			if (err != nil) != tc.wantErr {
				t.Fatalf("wantErr=%v got err=%v", tc.wantErr, err)
			}
		})
	}
}
