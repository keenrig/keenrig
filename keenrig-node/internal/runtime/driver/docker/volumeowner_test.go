package docker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
)

// /etc/passwd và /etc/group chép nguyên từ n8n 2.41.6 (rút gọn) — app đã làm
// lộ lỗ này. Dòng hỏng và dòng chú thích là để chắc trình đọc không ngã vì chúng.
const (
	passwdFixture = `root:x:0:0:root:/root:/bin/sh
# chú thích
hỏng:x
node:x:1000:1000:node:/home/node:/bin/sh
nobody:x:65534:65534:nobody:/:/sbin/nologin
`
	groupFixture = `root:x:0:root
node:x:1000:node
docker:x:999:
`
)

func TestResolveUser(t *testing.T) {
	cases := []struct {
		spec     string
		uid, gid int
	}{
		{"node", 1000, 1000},       // n8n: tên → gid chính trong passwd
		{"1000", 1000, 1000},       // số có trong passwd → vẫn lấy gid chính
		{"4242", 4242, 0},          // số KHÔNG có trong passwd → gid 0 (luật Docker)
		{"node:docker", 1000, 999}, // group theo tên
		{"node:55", 1000, 55},      // group theo số
		{"65534:65534", 65534, 65534},
	}
	for _, c := range cases {
		uid, gid, err := resolveUser(c.spec, passwdFixture, groupFixture)
		if err != nil {
			t.Errorf("%q: %v", c.spec, err)
			continue
		}
		if uid != c.uid || gid != c.gid {
			t.Errorf("%q = %d:%d, muốn %d:%d", c.spec, uid, gid, c.uid, c.gid)
		}
	}
}

// Tên không có trong image phải là LỖI. Đoán (ví dụ "coi như root") nghĩa là
// app nhận một thư mục nó không ghi được và chết với EACCES — đúng cái lỗi mà
// file này sinh ra để chặn — chỉ là khó truy hơn.
func TestResolveUserUnknownName(t *testing.T) {
	for _, spec := range []string{"khong-co", "node:khong-co", "-1"} {
		if _, _, err := resolveUser(spec, passwdFixture, groupFixture); err == nil {
			t.Errorf("%q được chấp nhận", spec)
		}
	}
	// Image không có /etc/passwd (distroless): uid số vẫn phải chạy được.
	if uid, gid, err := resolveUser("65532", "", ""); err != nil || uid != 65532 || gid != 0 {
		t.Errorf("distroless 65532 = %d:%d, %v", uid, gid, err)
	}
}

// Box thật chạy bằng user keenrig, KHÔNG có CAP_CHOWN: os.Chown sang uid 1000
// luôn EPERM. Trước khi có fallback, đó chính là lý do n8n trên VPS kẹt
// restart với EACCES dù adoptVolumeOwnership đã có trong binary.
func TestGiveVolumeFallsBackToPrivopsOnEPERM(t *testing.T) {
	eperm := func(string, int, int) error {
		return &os.PathError{Op: "chown", Path: "x", Err: syscall.EPERM}
	}
	var got []string
	d := &Driver{
		chown: eperm,
		chownVolume: func(_ context.Context, appID, volume string, uid, gid int) error {
			got = append(got, fmt.Sprintf("%s/%s %d:%d", appID, volume, uid, gid))
			return nil
		},
	}
	if err := d.giveVolume(context.Background(), "app-1", "data", "/h", 1000, 1000); err != nil {
		t.Fatalf("giveVolume = %v, muốn nil nhờ fallback", err)
	}
	if len(got) != 1 || got[0] != "app-1/data 1000:1000" {
		t.Fatalf("fallback calls = %v", got)
	}

	// Fallback cũng hỏng (script cũ chưa có chown-volume) → lỗi phải nói rõ cả hai.
	d.chownVolume = func(context.Context, string, string, int, int) error {
		return errors.New("invalid action: chown-volume")
	}
	err := d.giveVolume(context.Background(), "app-1", "data", "/h", 1000, 1000)
	if err == nil || !strings.Contains(err.Error(), "chown-volume") || !strings.Contains(err.Error(), "chown") {
		t.Fatalf("giveVolume = %v, muốn lỗi nêu cả EPERM lẫn fallback", err)
	}

	// Không có fallback → không im lặng.
	d.chownVolume = nil
	if err := d.giveVolume(context.Background(), "app-1", "data", "/h", 1000, 1000); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("giveVolume không fallback = %v, muốn ErrPermission", err)
	}
}

// os.Chown thành công (box chạy bằng root) → KHÔNG gọi sudo.
func TestGiveVolumeSkipsPrivopsWhenChownWorks(t *testing.T) {
	called := false
	d := &Driver{
		chown:       func(string, int, int) error { return nil },
		chownVolume: func(context.Context, string, string, int, int) error { called = true; return nil },
	}
	if err := d.giveVolume(context.Background(), "app-1", "data", "/h", 1000, 1000); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("gọi sudo dù os.Chown đã thành công")
	}
}
