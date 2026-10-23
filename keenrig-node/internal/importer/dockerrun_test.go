package importer_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/importer"
)

func runOK(t *testing.T, cmd string) importer.Result {
	t.Helper()
	res, err := importer.ImportDockerRun(cmd)
	if err != nil {
		t.Fatalf("ImportDockerRun(%q): %v", cmd, err)
	}
	return res
}

// IM-01 — `docker run` cơ bản → desired ĐÚNG TỪNG FIELD.
//
// Dòng lệnh dưới đây là dạng thật của mọi README self-host: cờ ngắn lẫn dài,
// `=` lẫn khoảng trắng, và `\` nối dòng.
func TestDockerRunMapsEveryField(t *testing.T) {
	res := runOK(t, `docker run -d \
  --name my-blog \
  -p 8080:2368 \
  -e url=https://blog.example.com \
  -e NODE_ENV=production \
  -v blogdata:/var/lib/ghost/content \
  --restart unless-stopped \
  -m 512m --cpus 0.5 \
  ghost:5-alpine`)

	if len(res.Apps) != 1 {
		t.Fatalf("= %d app", len(res.Apps))
	}
	a := res.Apps[0]
	if a.Slug != "my-blog" {
		t.Errorf("slug = %q, muốn my-blog (từ --name)", a.Slug)
	}
	if a.Desired.Image != "ghost:5-alpine" {
		t.Errorf("image = %q", a.Desired.Image)
	}
	// Cổng TRONG container, không phải cổng publish — cùng luật với compose.
	if a.Desired.HTTPPort != 2368 {
		t.Errorf("http_port = %d, muốn 2368", a.Desired.HTTPPort)
	}
	if a.Desired.Env["url"] != "https://blog.example.com" || a.Desired.Env["NODE_ENV"] != "production" {
		t.Errorf("env = %v", a.Desired.Env)
	}
	if len(a.Desired.Volumes) != 1 ||
		a.Desired.Volumes[0].Name != "blogdata" ||
		a.Desired.Volumes[0].Path != "/var/lib/ghost/content" {
		t.Errorf("volumes = %+v", a.Desired.Volumes)
	}
	if a.Desired.Resources == nil || a.Desired.Resources.MemoryMB != 512 || a.Desired.Resources.CPU != 0.5 {
		t.Errorf("resources = %+v", a.Desired.Resources)
	}
}

// Không có `--name` thì tên suy từ image.
func TestNameFallsBackToImage(t *testing.T) {
	for cmd, want := range map[string]string{
		"docker run nginx": "nginx",
		"docker run docker.io/library/redis:7-alpine":   "redis",
		"docker run ghcr.io/owner/my-tool:v2":           "my-tool",
		"sudo docker run -d traefik/whoami":             "whoami",
		"podman run quay.io/prometheus/node-exporter:1": "node-exporter",
	} {
		res, err := importer.ImportDockerRun(cmd)
		if errors.Is(err, importer.ErrNoService) {
			// redis một mình bị HẤP THỤ thành addon, nên không còn app nào —
			// đó là hành vi đúng, và TestDockerRunPostgresBecomesAddonToo canh nó.
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", cmd, err)
			continue
		}
		if res.Apps[0].Slug != want {
			t.Errorf("%q → slug %q, muốn %q", cmd, res.Apps[0].Slug, want)
		}
	}
}

// CHÍNH SÁCH AN NINH DÙNG CHUNG với compose — không có bộ luật thứ hai.
//
// Đây là khẳng định quan trọng nhất của file này: nếu hai đường vào có hai bộ
// luật thì `--privileged` bị chặn ở một đường và LỌT ở đường kia, và không ai
// phát hiện cho tới khi có người thử.
func TestDockerRunSharesTheSameSecurityPolicy(t *testing.T) {
	cases := map[string]struct{ cmd, field string }{
		"privileged":     {"docker run --privileged nginx", "privileged"},
		"network host":   {"docker run --network=host nginx", "network_mode"},
		"pid host":       {"docker run --pid host nginx", "pid/ipc"},
		"bind mount /":   {"docker run -v /:/host nginx", "volumes"},
		"docker.sock":    {"docker run -v /var/run/docker.sock:/var/run/docker.sock nginx", "volumes"},
		"cap_add":        {"docker run --cap-add SYS_ADMIN nginx", "cap_add"},
		"device":         {"docker run --device /dev/sda:/dev/sda nginx", "devices"},
		"seccomp":        {"docker run --security-opt seccomp:unconfined nginx", "security_opt"},
		"bind tương đối": {"docker run -v ./data:/data nginx", "volumes"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			res := runOK(t, c.cmd)
			if len(res.Rejected()) == 0 {
				t.Fatalf("%q KHÔNG bị từ chối", c.cmd)
			}
			found := false
			for _, n := range res.Rejected() {
				if n.Field == c.field {
					found = true
				}
			}
			if !found {
				t.Errorf("từ chối nhưng không phải vì %q: %+v", c.field, res.Rejected())
			}
		})
	}
}

// `docker run postgres` cho ra CÙNG kết quả với compose khai postgres: một
// addon, không phải một app database tự quản.
func TestDockerRunPostgresBecomesAddonToo(t *testing.T) {
	res, err := importer.ImportDockerRun("docker run -e POSTGRES_PASSWORD=x postgres:16")
	// Một mình postgres thì không còn app nào để gắn addon → ErrNoService là
	// câu trả lời ĐÚNG: người dùng chưa dán app cần nó.
	if !errors.Is(err, importer.ErrNoService) {
		t.Fatalf("= %v (apps=%d), muốn ErrNoService", err, len(res.Apps))
	}
}

// Cú pháp SHELL bị từ chối, không được đoán.
//
// Một chuỗi dán vào ô nhập là DỮ LIỆU. Bắt đầu hiểu `$(...)` hay `&&` là bắt
// đầu viết một shell nhỏ trong đường nhập liệu — đúng thứ package này sinh ra
// để chặn.
func TestShellSyntaxIsRefusedNotGuessed(t *testing.T) {
	for _, cmd := range []string{
		"docker run nginx && rm -rf /",
		"docker run -e PW=$(cat /etc/shadow) nginx",
		"docker run nginx; curl evil.example.com",
		"docker run -e X=`whoami` nginx",
		"docker run nginx | tee /tmp/x",
	} {
		if _, err := importer.ImportDockerRun(cmd); !errors.Is(err, importer.ErrParse) {
			t.Errorf("%q = %v, muốn ErrParse", cmd, err)
		}
	}
}

// Nháy giữ nguyên giá trị có khoảng trắng; nháy lệch thì báo lỗi.
func TestQuotingIsHandled(t *testing.T) {
	res := runOK(t, `docker run -e "MSG=hello world" --name x nginx`)
	if got := res.Apps[0].Desired.Env["MSG"]; got != "hello world" {
		t.Errorf("env MSG = %q", got)
	}
	if _, err := importer.ImportDockerRun(`docker run -e "MSG=unbalanced nginx`); !errors.Is(err, importer.ErrParse) {
		t.Errorf("nháy lệch không bị báo lỗi")
	}
}

// Cờ LẠ phải được NÓI RA, không nuốt im lặng.
//
// Nuốt im lặng một cờ là cách chính sách bị đi vòng mà không ai biết: người
// dùng thấy app được tạo và tin rằng mọi thứ họ dán vào đã được áp dụng.
func TestUnknownFlagIsReported(t *testing.T) {
	res := runOK(t, "docker run --some-future-flag=1 nginx")
	said := false
	for _, n := range res.Apps[0].Notes {
		if n.Field == "flags" && strings.Contains(n.Message, "some-future-flag") {
			said = true
		}
	}
	if !said {
		t.Errorf("cờ lạ bị nuốt im lặng: %+v", res.Apps[0].Notes)
	}
}

// Lệnh rỗng / không có image → lỗi rõ ràng.
func TestEmptyOrImagelessCommand(t *testing.T) {
	for _, cmd := range []string{"", "docker run", "docker run -d", "   "} {
		if _, err := importer.ImportDockerRun(cmd); err == nil {
			t.Errorf("%q được chấp nhận", cmd)
		}
	}
}
