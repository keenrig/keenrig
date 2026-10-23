package dir_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/backup/target"
	"github.com/keenrig/keenrig/keenrig-node/internal/backup/target/driver/dir"
	"github.com/keenrig/keenrig/keenrig-node/internal/backup/target/targettest"
)

func TestDirConformance(t *testing.T) {
	targettest.RunConformance(t, func(t *testing.T) target.Target {
		d, err := dir.New(t.TempDir())
		if err != nil {
			t.Fatalf("dir.New: %v", err)
		}
		return d
	})
}

func newDir(t *testing.T) (*dir.Driver, string) {
	t.Helper()
	root := t.TempDir()
	d, err := dir.New(root)
	if err != nil {
		t.Fatalf("dir.New: %v", err)
	}
	return d, root
}

// DSN sai phải nổ lúc MỞ, không lúc Put.
//
// Một thư mục sao lưu không ghi được chỉ lộ ra lúc snapshot đầu tiên chạy theo
// lịch — tức là lúc không ai ngồi xem log.
func TestBadDSNFailsAtOpen(t *testing.T) {
	for _, dsn := range []string{"", "   ", "tuong-doi/khong-tuyet-doi"} {
		if _, err := dir.New(dsn); !errors.Is(err, target.ErrBadConfig) {
			t.Errorf("dir.New(%q) = %v, muốn ErrBadConfig", dsn, err)
		}
	}
}

// Thư mục sao lưu phải là 0700.
//
// Nó chứa toàn bộ dữ liệu instance. 0755 nghĩa là mọi user trên máy đọc được
// lịch sử đầy đủ của mọi app.
func TestRootIs0700(t *testing.T) {
	if os.Getenv("GOOS") == "windows" || filepath.Separator == '\\' {
		t.Skip("quyền POSIX không có nghĩa trên Windows")
	}
	_, root := newDir(t)
	st, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Errorf("mode = %o, muốn 700", st.Mode().Perm())
	}
}

// DSN không ở dạng chuẩn vẫn phải ghi được.
//
// Regression đã đo trên máy thật: `KEENRIG_BACKUP_CONFIG` có dấu '/' cuối, hoặc
// dùng '/' xuôi trên Windows, làm MỌI lần Put thất bại với thông báo
// *"invalid key: … escapes the backup directory"* — tức là đổ lỗi cho key trong
// khi thứ sai là một ký tự thừa trong cấu hình. Không test nào cũ bắt được vì
// tất cả đều dựng root bằng `t.TempDir()`, luôn ở dạng chuẩn.
//
// Ba dạng dưới đây là ba cách người ta gõ thật: dấu '/' cuối (copy từ shell),
// './' ở giữa (nối chuỗi), và '/' xuôi trên Windows (copy từ tài liệu).
func TestNonCanonicalRootStillWrites(t *testing.T) {
	base := t.TempDir()
	variants := map[string]string{
		"dấu / ở cuối": base + string(os.PathSeparator),
		"có ./ ở giữa": filepath.Join(base, "x", "..") + string(os.PathSeparator) + ".",
		"dấu / xuôi":   filepath.ToSlash(base),
	}
	for name, root := range variants {
		t.Run(name, func(t *testing.T) {
			d, err := dir.New(root)
			if err != nil {
				t.Fatalf("dir.New(%q): %v", root, err)
			}
			const key = "snapshots/2026-08-12T05-17-57Z/instance.tgz"
			if err := d.Put(context.Background(), key, strings.NewReader("noi dung"), 8); err != nil {
				t.Fatalf("Put: %v", err)
			}
			rc, err := d.Get(context.Background(), key)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			defer rc.Close()
			b, _ := io.ReadAll(rc)
			if string(b) != "noi dung" {
				t.Errorf("= %q", b)
			}
		})
	}
}

// Key độc hại KHÔNG được ghi ra ngoài thư mục sao lưu.
//
// Đây là khẳng định chỉ nói được ở tầng driver dir: suite conformance kiểm rằng
// key xấu bị TỪ CHỐI, còn test này kiểm rằng nếu nó có lọt thì cũng không ra được
// ngoài. Hai lớp, vì lớp trên có thể bị nới ra sau này.
func TestKeyCannotEscapeRoot(t *testing.T) {
	d, root := newDir(t)
	outside := filepath.Dir(root)
	before, _ := os.ReadDir(outside)

	for _, k := range []string{"../thoat", "a/../../thoat", "/etc/passwd", "..\\thoat"} {
		_ = d.Put(context.Background(), k, strings.NewReader("x"), 1)
	}

	after, _ := os.ReadDir(outside)
	if len(after) != len(before) {
		t.Errorf("thư mục cha đổi từ %d thành %d entry — key đã thoát ra ngoài",
			len(before), len(after))
	}
}

// Put bị NGẮT không được để lại object.
//
// Ghi trực tiếp vào file đích để lại một archive cụt mà List vẫn kể tên và Size
// vẫn có số — bản sao lưu đó đi qua mọi lần kiểm và chỉ hỏng lúc restore.
func TestInterruptedPutLeavesNothing(t *testing.T) {
	d, root := newDir(t)

	// Reader trả lỗi giữa đường: mô phỏng đúng ca đọc file bị cắt bớt.
	r := io.MultiReader(strings.NewReader("phan-dau-"), &failingReader{})
	if err := d.Put(context.Background(), "snap/a.tgz", r, 100); err == nil {
		t.Fatal("Put với reader lỗi lại thành công")
	}

	objs, err := d.List(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 0 {
		t.Errorf("còn lại object sau khi Put lỗi: %+v", objs)
	}
	// Và không được để lại file tạm.
	ents, _ := os.ReadDir(filepath.Join(root, "snap"))
	for _, e := range ents {
		t.Errorf("còn rác trong thư mục: %q", e.Name())
	}
}

type failingReader struct{}

func (*failingReader) Read([]byte) (int, error) {
	return 0, errors.New("đĩa hỏng giữa lúc đọc")
}

// File tạm của một Put đang chạy KHÔNG được xuất hiện trong List.
//
// Nếu nó xuất hiện, retention đếm nó như một bản sao lưu và sẽ xoá một bản THẬT
// để giữ đúng KeepLast.
func TestTempFileNotListed(t *testing.T) {
	d, root := newDir(t)
	if err := os.WriteFile(filepath.Join(root, ".put-dang-do.tmp"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	objs, err := d.List(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 0 {
		t.Errorf("List kể tên file tạm: %+v", objs)
	}
}

// Delete dọn luôn thư mục cha rỗng.
//
// Không dọn thì sau vài tháng retention, cây còn lại là hàng nghìn thư mục ngày
// rỗng mà List phải đi bộ hết mỗi lần.
func TestDeleteRemovesEmptyParents(t *testing.T) {
	d, root := newDir(t)
	ctx := context.Background()
	if err := d.Put(ctx, "a/b/c/x.tgz", strings.NewReader("x"), 1); err != nil {
		t.Fatal(err)
	}
	if err := d.Delete(ctx, "a/b/c/x.tgz"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "a")); !os.IsNotExist(err) {
		t.Errorf("thư mục a/ còn lại sau khi xoá object cuối cùng: %v", err)
	}
	// Nhưng thư mục GỐC phải còn: xoá nó đi thì lần Put sau tạo lại với quyền
	// mặc định của process umask, không phải 0700.
	if _, err := os.Stat(root); err != nil {
		t.Errorf("thư mục gốc bị xoá: %v", err)
	}
}

// Thư mục cha CÒN object khác thì không được xoá.
func TestDeleteKeepsNonEmptyParents(t *testing.T) {
	d, root := newDir(t)
	ctx := context.Background()
	for _, k := range []string{"a/x.tgz", "a/y.tgz"} {
		if err := d.Put(ctx, k, strings.NewReader("x"), 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Delete(ctx, "a/x.tgz"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "a", "y.tgz")); err != nil {
		t.Errorf("xoá x.tgz làm mất y.tgz: %v", err)
	}
}

// Đăng ký vào registry và mở được qua env.
func TestOpenFromEnv(t *testing.T) {
	root := t.TempDir()
	env := map[string]string{
		target.EnvDriver: dir.Name,
		target.EnvConfig: root,
	}
	tg, err := target.OpenFromEnv(context.Background(), func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	})
	if err != nil {
		t.Fatalf("OpenFromEnv: %v", err)
	}
	if tg.Name() != dir.Name {
		t.Errorf("Name = %q", tg.Name())
	}
}

// KHÔNG đặt biến → ErrNotConfigured, lỗi RIÊNG.
//
// "Chưa bật sao lưu" là trạng thái hợp lệ của instance; "gõ sai tên driver" là
// lỗi cấu hình. Hai thứ dẫn tới hai hành động khác nhau của người vận hành.
func TestNoTargetConfigured(t *testing.T) {
	_, err := target.OpenFromEnv(context.Background(), func(string) (string, bool) {
		return "", false
	})
	if !errors.Is(err, target.ErrNotConfigured) {
		t.Errorf("= %v, muốn ErrNotConfigured", err)
	}
}
