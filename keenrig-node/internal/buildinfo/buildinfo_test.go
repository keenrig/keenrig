package buildinfo_test

// Test này BUILD ba binary thật với `-X`, rồi chạy `--version`. Đọc biến
// trong cùng tiến trình test thì không chứng minh được gì: lỗi mà nó phải bắt
// là một binary quay lại hằng số tự gõ — khi đó `-X` bị bỏ qua trong IM LẶNG
// và chỉ binary đã build mới lộ ra.
//
// BẪY: `go test` KHÔNG biết test này phụ thuộc cmd/ (nó build qua exec), nên
// sửa cmd/ rồi chạy lại vẫn ra "(cached)" xanh. Kiểm thay đổi ở cmd/ bằng
// `go test -count=1 ./internal/buildinfo/`.

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/buildinfo"
)

func TestLDFlagReachesEveryBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("build 3 binary — bỏ qua với -short")
	}
	const want = "9.8.7-ldflag"
	dir := t.TempDir()
	for _, name := range []string{"keenrig-box", "keenrig-agent", "keenrig-ota"} {
		t.Run(name, func(t *testing.T) {
			bin := filepath.Join(dir, name)
			if runtime.GOOS == "windows" {
				bin += ".exe"
			}
			build := exec.Command("go", "build", "-o", bin,
				"-ldflags", "-X "+buildinfo.LDFlag+"="+want, "../../cmd/"+name)
			if out, err := build.CombinedOutput(); err != nil {
				t.Fatalf("go build %s: %v\n%s", name, err, out)
			}
			out, err := exec.Command(bin, "--version").CombinedOutput()
			if err != nil {
				t.Fatalf("%s --version: %v\n%s", name, err, out)
			}
			if got := strings.TrimSpace(string(out)); got != name+" "+want {
				t.Errorf("%s --version = %q, muốn %q — binary không đọc buildinfo.Version", name, got, name+" "+want)
			}
		})
	}
}
