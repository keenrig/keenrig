package paths_test

// Test di trú bố cục cũ → mới.
//
// Đây là test canh cho kiểu hỏng IM LẶNG: đổi tên thư mục mà không di trú thì
// box lên bình thường, /healthz trả 200, và mọi app của người dùng biến mất.
// Không có gì đỏ để báo — nên phải có test này.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/paths"
)

func writeAt(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("đọc %s: %v", path, err)
	}
	return string(b)
}

// Bố cục cũ đầy đủ → đổi tên hết, NỘI DUNG còn nguyên.
func TestMigrateRenamesAllThree(t *testing.T) {
	base := t.TempDir()
	l := paths.New(base)

	writeAt(t, filepath.Join(base, "instancedata", "platform.db"), "DB CỦA TÔI")
	writeAt(t, filepath.Join(base, "instancedata", "master.key"), "KHOÁ")
	writeAt(t, filepath.Join(base, "platformdata", "proxy", "caddy.json"), "{}")
	writeAt(t, filepath.Join(base, "appsdata", "app-1", "data.txt"), "DỮ LIỆU NGƯỜI DÙNG")

	done, err := l.MigrateLegacyLayout()
	if err != nil {
		t.Fatalf("MigrateLegacyLayout: %v", err)
	}
	if len(done) != 3 {
		t.Fatalf("đổi tên %d thư mục, muốn 3: %v", len(done), done)
	}

	// Nội dung phải NGUYÊN VẸN — đây mới là điều cần chứng minh, không phải
	// "thư mục mới tồn tại".
	if got := mustRead(t, l.DB()); got != "DB CỦA TÔI" {
		t.Errorf("platform.db = %q", got)
	}
	if got := mustRead(t, l.MasterKey()); got != "KHOÁ" {
		t.Errorf("master.key = %q", got)
	}
	if got := mustRead(t, filepath.Join(l.NodeData(), "proxy", "caddy.json")); got != "{}" {
		t.Errorf("caddy.json = %q", got)
	}
	appData, err := l.AppData("app-1")
	if err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, filepath.Join(appData, "data.txt")); got != "DỮ LIỆU NGƯỜI DÙNG" {
		t.Errorf("dữ liệu app = %q", got)
	}

	// Tên cũ phải BIẾN MẤT: còn lại nghĩa là lần khởi động sau sẽ thấy "cả hai
	// cùng tồn tại" và từ chối.
	for _, old := range []string{"instancedata", "platformdata", "appsdata"} {
		if _, err := os.Stat(filepath.Join(base, old)); err == nil {
			t.Errorf("%s vẫn còn sau khi di trú", old)
		}
	}
}

// Bản cài MỚI (không có tên cũ) → không làm gì, không lỗi.
func TestMigrateIsNoOpOnFreshInstall(t *testing.T) {
	l := paths.New(t.TempDir())
	if err := l.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	done, err := l.MigrateLegacyLayout()
	if err != nil {
		t.Fatalf("bản cài mới bị coi là cần di trú: %v", err)
	}
	if len(done) != 0 {
		t.Errorf("đổi tên %v trên một bản cài mới", done)
	}
}

// Gọi lại lần hai là no-op — box restart nhiều lần, và mỗi lần đều gọi.
func TestMigrateIsIdempotent(t *testing.T) {
	base := t.TempDir()
	l := paths.New(base)
	writeAt(t, filepath.Join(base, "appsdata", "app-1", "x"), "x")

	if _, err := l.MigrateLegacyLayout(); err != nil {
		t.Fatal(err)
	}
	done, err := l.MigrateLegacyLayout()
	if err != nil {
		t.Fatalf("lần hai lỗi: %v", err)
	}
	if len(done) != 0 {
		t.Errorf("lần hai vẫn đổi tên %v", done)
	}
}

// CẢ HAI cùng tồn tại → DỪNG, không trộn.
//
// Trộn hai cây thư mục là đoán, và đoán sai ở đây là mất dữ liệu người dùng.
// Từ chối và bắt người vận hành quyết định là câu trả lời đúng.
func TestMigrateRefusesWhenBothExist(t *testing.T) {
	base := t.TempDir()
	l := paths.New(base)

	writeAt(t, filepath.Join(base, "appsdata", "app-1", "cu.txt"), "CŨ")
	writeAt(t, filepath.Join(base, "apps", "app-1", "moi.txt"), "MỚI")

	_, err := l.MigrateLegacyLayout()
	if !errors.Is(err, paths.ErrLayoutConflict) {
		t.Fatalf("err = %v, muốn ErrLayoutConflict", err)
	}
	// Và KHÔNG được đụng vào cái nào.
	if got := mustRead(t, filepath.Join(base, "appsdata", "app-1", "cu.txt")); got != "CŨ" {
		t.Errorf("dữ liệu cũ bị đụng: %q", got)
	}
	if got := mustRead(t, filepath.Join(base, "apps", "app-1", "moi.txt")); got != "MỚI" {
		t.Errorf("dữ liệu mới bị đụng: %q", got)
	}
}

// instance đi ĐẦU: nếu quá trình dừng giữa chừng, thứ đã sang tên mới phải là
// platform.db chứ không phải thư mục log.
func TestMigrateOrderPutsInstanceFirst(t *testing.T) {
	base := t.TempDir()
	l := paths.New(base)
	writeAt(t, filepath.Join(base, "instancedata", "platform.db"), "db")
	writeAt(t, filepath.Join(base, "platformdata", "logs", "x.log"), "log")
	writeAt(t, filepath.Join(base, "appsdata", "app-1", "x"), "x")

	done, err := l.MigrateLegacyLayout()
	if err != nil {
		t.Fatal(err)
	}
	if len(done) == 0 || done[0] != "instancedata → instance" {
		t.Errorf("thứ tự = %v, muốn instancedata đi đầu", done)
	}
}

// Một thư mục cũ, hai cái kia đã ở tên mới — tình huống của một lần di trú
// từng dừng giữa chừng, và nó phải chạy tiếp được.
func TestMigratePartialResumes(t *testing.T) {
	base := t.TempDir()
	l := paths.New(base)
	writeAt(t, filepath.Join(base, "instance", "platform.db"), "db")  // đã xong
	writeAt(t, filepath.Join(base, "appsdata", "app-1", "x"), "data") // chưa

	done, err := l.MigrateLegacyLayout()
	if err != nil {
		t.Fatalf("không chạy tiếp được sau lần dừng giữa chừng: %v", err)
	}
	if len(done) != 1 || done[0] != "appsdata → apps" {
		t.Errorf("done = %v", done)
	}
	if got := mustRead(t, filepath.Join(base, "apps", "app-1", "x")); got != "data" {
		t.Errorf("dữ liệu = %q", got)
	}
}
