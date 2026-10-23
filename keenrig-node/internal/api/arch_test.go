package api_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestLayer1DoesNotImportSubsystems — LUẬT 9 (V2-DELTA §3) kiểm bằng máy.
//
// Tầng ① của box (httpd + api) không được phụ thuộc reconciler/runtime/addons.
// Nếu nó phụ thuộc, một deadlock hay panic trong vòng reconcile sẽ kéo sập luôn
// /healthz và node API — tức là ota mất drain/resume, mất đường sửa lỗi cuối
// cùng đúng lúc cần nhất.
//
// Kiểm bằng `go list -deps` chứ không bằng lời hứa trong comment: comment không
// đỏ khi ai đó thêm import.
func TestLayer1DoesNotImportSubsystems(t *testing.T) {
	const prefix = "github.com/keenrig-platform/keenrig/keenrig-node/internal/"
	banned := []string{"reconciler", "runtime", "addons", "supervise"}

	for _, pkg := range []string{"api", "httpd", "nodeapi"} {
		out, err := exec.Command("go", "list", "-deps", prefix+pkg).Output()
		if err != nil {
			t.Fatalf("go list -deps %s: %v", pkg, err)
		}
		for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			dep = strings.TrimSpace(dep)
			if !strings.HasPrefix(dep, prefix) {
				continue
			}
			name := strings.TrimPrefix(dep, prefix)
			for _, b := range banned {
				if name == b || strings.HasPrefix(name, b+"/") {
					t.Errorf("%s phụ thuộc %s — vi phạm Luật 9 (tầng ① phải sống khi subsystem chết)", pkg, dep)
				}
			}
		}
	}
}
