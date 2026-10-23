package contracts

import "testing"

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		fn      func([]byte) error
		data    string
		wantErr bool
	}{
		{
			name: "desired hợp lệ đầy đủ",
			fn:   ValidateDesired,
			data: `{
				"image": "ghcr.io/acme/web:1.2.3",
				"domains": ["app.example.com"],
				"env": {"LOG_LEVEL": "debug"},
				"addons": {"postgres": {"enabled": true}, "redis": {"enabled": false}},
				"resources": {"memory_mb": 256, "cpu": 0.5, "replicas": 2},
				"sso": {"enabled": true},
				"backup": {"enabled": true, "schedule": "0 3 * * *"},
				"autoscale": {"enabled": true, "cpu_high": 80, "max_replicas": 4}
			}`,
		},
		{
			name:    "desired thiếu image",
			fn:      ValidateDesired,
			data:    `{"domains": ["app.example.com"]}`,
			wantErr: true,
		},
		{
			name:    "desired field lạ",
			fn:      ValidateDesired,
			data:    `{"image": "nginx:1", "bogus": true}`,
			wantErr: true,
		},
		{
			name:    "desired replicas 0",
			fn:      ValidateDesired,
			data:    `{"image": "nginx:1", "resources": {"replicas": 0}}`,
			wantErr: true,
		},
		{
			name: "sync request hợp lệ",
			fn:   ValidateSyncRequest,
			data: `{
				"env_id": "env-1",
				"host_role": "solo",
				"version": "0.1.0",
				"heartbeat": {"ts": "2026-08-05T00:00:00Z", "uptime_s": 42},
				"app_statuses": [{"app_id": "a1", "state": "running", "health": "healthy"}],
				"command_results": [{"id": "c1", "ok": true}]
			}`,
		},
		{
			name:    "sync request thiếu env_id",
			fn:      ValidateSyncRequest,
			data:    `{"version": "0.1.0", "heartbeat": {"ts": "2026-08-05T00:00:00Z"}}`,
			wantErr: true,
		},
		{
			name: "sync response hợp lệ",
			fn:   ValidateSyncResponse,
			data: `{
				"commands": [{
					"id": "c1",
					"idempotency_key": "0e8dcf0e-6cf3-4f0c-9c88-9d9c4c6c1a2b",
					"kind": "notice",
					"payload": {"message": "hi"}
				}],
				"next_poll_ms": 1000
			}`,
		},
		{
			name: "sync response command kind lạ",
			fn:   ValidateSyncResponse,
			data: `{
				"commands": [{
					"id": "c1",
					"idempotency_key": "0e8dcf0e-6cf3-4f0c-9c88-9d9c4c6c1a2b",
					"kind": "self_destruct",
					"payload": {}
				}]
			}`,
			wantErr: true,
		},
		{
			name: "manifest hợp lệ",
			fn:   ValidateManifest,
			data: `{
				"id": "gitea",
				"version": "1.22.0",
				"title": "Gitea",
				"image": "ghcr.io/acme/gitea@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"httpPort": 3000,
				"addons": {"postgres": {"enabled": true}},
				"healthcheck": {"path": "/", "interval_s": 10, "timeout_s": 3},
				"scalable": false
			}`,
		},
		{
			name:    "manifest image thiếu digest",
			fn:      ValidateManifest,
			data:    `{"id": "gitea", "version": "1.22.0", "image": "ghcr.io/acme/gitea:latest", "httpPort": 3000}`,
			wantErr: true,
		},
		{
			name: "license hợp lệ",
			fn:   ValidateLicense,
			data: `{
				"license_id": "lic-1",
				"instance_id": "inst-1",
				"env_id": "env-1",
				"features": {"runtime": "docker", "max_nodes": 1, "ha_t1": false},
				"issued_at": "2026-08-05T00:00:00Z",
				"expires_at": "2027-08-05T00:00:00Z",
				"grace_days": 14
			}`,
		},
		{
			name: "license thiếu features",
			fn:   ValidateLicense,
			data: `{
				"license_id": "lic-1",
				"instance_id": "inst-1",
				"issued_at": "2026-08-05T00:00:00Z",
				"expires_at": "2027-08-05T00:00:00Z",
				"grace_days": 14
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn([]byte(tt.data))
			if tt.wantErr && err == nil {
				t.Fatal("muốn lỗi validate nhưng nhận nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("không muốn lỗi nhưng nhận: %v", err)
			}
		})
	}
}
