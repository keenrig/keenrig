package contracts_test

import (
	"strings"
	"testing"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
)

func TestValidateAddonConfig(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		ok   bool
	}{
		{"tối thiểu hợp lệ", `{
			"app_id": "7f3a9c1e-0000-4000-8000-000000000001",
			"addon": "postgres",
			"env": {"KEENRIG_POSTGRES_URL": "postgres://u:p@postgres:5432/db"}
		}`, true},
		{"đủ trường", `{
			"app_id": "a1",
			"addon": "redis",
			"env": {"KEENRIG_REDIS_URL": "redis://redis:6379", "KEENRIG_REDIS_HOST": "redis"},
			"secret_ref": "app/a1/redis",
			"provisioned_at": "2026-08-08T10:00:00Z"
		}`, true},

		{"addon lạ", `{"app_id":"a1","addon":"mongodb","env":{"KEENRIG_X":"1"}}`, false},
		{"env sai namespace", `{"app_id":"a1","addon":"redis","env":{"REDIS_URL":"redis://x"}}`, false},
		{"env chữ thường", `{"app_id":"a1","addon":"redis","env":{"keenrig_redis_url":"x"}}`, false},
		{"env rỗng", `{"app_id":"a1","addon":"redis","env":{}}`, false},
		{"env giá trị không phải string", `{"app_id":"a1","addon":"redis","env":{"KEENRIG_PORT":6379}}`, false},
		{"thiếu app_id", `{"addon":"redis","env":{"KEENRIG_REDIS_URL":"x"}}`, false},
		{"thừa trường", `{"app_id":"a1","addon":"redis","env":{"KEENRIG_REDIS_URL":"x"},"password":"lộ"}`, false},
		{"provisioned_at sai format", `{"app_id":"a1","addon":"redis","env":{"KEENRIG_REDIS_URL":"x"},"provisioned_at":"hôm qua"}`, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := contracts.ValidateAddonConfig([]byte(c.doc))
			if c.ok && err != nil {
				t.Fatalf("muốn hợp lệ, nhận lỗi: %v", err)
			}
			if !c.ok && err == nil {
				t.Fatal("muốn lỗi, nhận hợp lệ")
			}
		})
	}
}

func TestValidateInfra(t *testing.T) {
	const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	cases := []struct {
		name string
		doc  string
		ok   bool
	}{
		{"hợp lệ", `{
			"infra_version": 1,
			"images": {
				"postgres-shared": {"repository":"ghcr.io/keenrig/postgres-shared","tag":"16.4","digest":"` + digest + `"},
				"redis": {"repository":"ghcr.io/keenrig/redis","tag":"7.4","digest":"` + digest + `"}
			}
		}`, true},

		{"thiếu digest", `{"infra_version":1,"images":{"redis":{"repository":"r","tag":"7"}}}`, false},
		{"digest không phải sha256", `{"infra_version":1,"images":{"redis":{"repository":"r","tag":"7","digest":"latest"}}}`, false},
		{"digest thiếu ký tự", `{"infra_version":1,"images":{"redis":{"repository":"r","tag":"7","digest":"sha256:abc"}}}`, false},
		{"digest chữ hoa", `{"infra_version":1,"images":{"redis":{"repository":"r","tag":"7","digest":"sha256:` + strings.ToUpper(digest[7:]) + `"}}}`, false},
		{"images rỗng", `{"infra_version":1,"images":{}}`, false},
		{"infra_version = 0", `{"infra_version":0,"images":{"redis":{"repository":"r","tag":"7","digest":"` + digest + `"}}}`, false},
		{"tên image chữ hoa", `{"infra_version":1,"images":{"Redis":{"repository":"r","tag":"7","digest":"` + digest + `"}}}`, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := contracts.ValidateInfra([]byte(c.doc))
			if c.ok && err != nil {
				t.Fatalf("muốn hợp lệ, nhận lỗi: %v", err)
			}
			if !c.ok && err == nil {
				t.Fatal("muốn lỗi, nhận hợp lệ")
			}
		})
	}
}
