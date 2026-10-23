//go:build linux

package docker

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/runtime"
)

// nonRootImage — image nhỏ có `USER 101` sẵn trong image, giống tình huống của
// n8n (`USER node`) nhưng không phải kéo nửa GB mỗi lần chạy test.
const nonRootImage = "nginxinc/nginx-unprivileged:1.27-alpine"

// ownerBase — thư mục gốc cho test. Mặc định t.TempDir(); KEENRIG_TEST_BASE
// dùng khi chạy go test TRONG một container nói chuyện với daemon qua socket:
// lúc đó đường dẫn bind mount được daemon hiểu theo filesystem của MÁY CHỦ, nên
// nó phải trùng ở cả hai phía.
func ownerBase(t *testing.T) string {
	if b := os.Getenv("KEENRIG_TEST_BASE"); b != "" {
		dir, err := os.MkdirTemp(b, "owner-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		return dir
	}
	return t.TempDir()
}

func ownerOf(t *testing.T, p string) (int, int) {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return int(st.Uid), int(st.Gid)
}

// App chạy bằng user thường phải nhận một thư mục volume nó GHI ĐƯỢC.
//
// Trước thay đổi này thư mục thuộc root:root 0755 và n8n chết ngay với
// `EACCES: permission denied, open '/home/node/.n8n/config'`.
func TestNonRootAppOwnsItsFreshVolume(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("cần root để chown thật — đường box KHÔNG root (EPERM → sudo) được phủ bởi TestGiveVolumeFallsBackToPrivopsOnEPERM")
	}
	base := ownerBase(t)
	d := newDriverAt(t, base)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	const appID = "33333333-2222-4333-8444-555555555555"
	spec := runtime.AppSpec{
		ID: appID, Slug: "khong-root", DesiredRev: 1,
		Desired: contracts.DesiredApp{
			Image:    nonRootImage,
			HTTPPort: 8080,
			Volumes: []contracts.VolumeMount{
				{Name: "data", Path: "/data"},
				{Name: "cau-hinh", Path: "/cfg", ReadOnly: true},
			},
		},
	}
	t.Cleanup(func() { _ = d.Remove(context.Background(), appID) })
	if _, err := d.Apply(ctx, spec); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	layout := paths.New(base)
	data, _ := layout.AppVolume(appID, "data")
	if uid, gid := ownerOf(t, data); uid != 101 || gid != 101 {
		t.Errorf("volume data thuộc %d:%d, muốn 101:101 (USER của image) — app không ghi được", uid, gid)
	}
	// Chỉ đọc → app không ghi vào đó, nền tảng giữ quyền.
	cfg, _ := layout.AppVolume(appID, "cau-hinh")
	if uid, _ := ownerOf(t, cfg); uid != 0 {
		t.Errorf("volume chỉ đọc bị đổi chủ sang %d", uid)
	}
}

// Thư mục ĐÃ có dữ liệu thì không được đụng: quyền của nó là thứ người vận
// hành (hoặc một lần restore) đã sắp đặt.
func TestVolumeWithDataKeepsItsOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("cần root để chown thật — đường box KHÔNG root (EPERM → sudo) được phủ bởi TestGiveVolumeFallsBackToPrivopsOnEPERM")
	}
	base := ownerBase(t)
	d := newDriverAt(t, base)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	const appID = "44444444-2222-4333-8444-555555555555"
	data, err := paths.New(base).AppVolume(appID, "data")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "da-restore.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	spec := runtime.AppSpec{
		ID: appID, Slug: "co-du-lieu", DesiredRev: 1,
		Desired: contracts.DesiredApp{
			Image:    nonRootImage,
			HTTPPort: 8080,
			Volumes:  []contracts.VolumeMount{{Name: "data", Path: "/data"}},
		},
	}
	t.Cleanup(func() { _ = d.Remove(context.Background(), appID) })
	if _, err := d.Apply(ctx, spec); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if uid, _ := ownerOf(t, data); uid != 0 {
		t.Errorf("thư mục đã có dữ liệu bị đổi chủ sang %d", uid)
	}
}
