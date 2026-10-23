package store_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// Khẳng định của DRIVER, không thuộc conformance: bản sao MỞ LẠI ĐƯỢC và nội
// dung đúng thời điểm chụp.
//
// Suite chung cố ý không nói câu này — nó không được biết bản sao là file
// SQLite. Cùng cách `targettest` để phần "key không thoát khỏi thư mục" cho
// driver/dir tự kiểm.

func openStore(t *testing.T, dir string) (*store.SQLite, string) {
	t.Helper()
	key := filepath.Join(dir, "master.key")
	st, err := store.Open(filepath.Join(dir, "platform.db"), key)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st, key
}

func newApp(id, slug string) *store.App {
	return &store.App{ID: id, Slug: slug, Desired: json.RawMessage(`{"image":"nginx:1"}`)}
}

// Bản sao là ẢNH CHỤP MỘT THỜI ĐIỂM: có thứ đã commit trước đó, KHÔNG có thứ
// ghi sau đó.
//
// Nếu nó có cả dữ liệu ghi sau, nghĩa là ta đang chép một file đang sống chứ
// không chụp — và lúc đó không có gì bảo đảm nó nhất quán.
func TestSnapshotIsPointInTime(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, keyPath := openStore(t, dir)

	const before = "33333333-3333-4333-8333-333333333333"
	const after = "44444444-4444-4444-8444-444444444444"
	if err := st.CreateApp(ctx, newApp(before, "co-truoc-khi-chup")); err != nil {
		t.Fatal(err)
	}

	snap := filepath.Join(t.TempDir(), "chup.db")
	if err := st.SnapshotTo(ctx, snap); err != nil {
		t.Fatalf("SnapshotTo: %v", err)
	}

	if err := st.CreateApp(ctx, newApp(after, "ghi-sau-khi-chup")); err != nil {
		t.Fatal(err)
	}

	// Mở lại bản sao bằng CHÍNH master.key của instance gốc — xem test dưới về
	// lý do đó không phải chi tiết phụ.
	copied, err := store.Open(snap, keyPath)
	if err != nil {
		t.Fatalf("bản sao không mở được: %v", err)
	}
	defer copied.Close()

	if _, err := copied.GetApp(ctx, before); err != nil {
		t.Errorf("mất app đã commit TRƯỚC khi chụp: %v", err)
	}
	if _, err := copied.GetApp(ctx, after); err == nil {
		t.Error("bản sao có app ghi SAU khi chụp — đây là bản chép file đang sống, không phải ảnh chụp")
	}
}

// Bản sao KHÔNG tự đọc được secret nếu thiếu master.key — và đó chính là lý do
// `master.key` phải nằm trong snapshot (chốt 2026-08-12).
//
// Test này khoá lại lý lẽ của quyết định đó: nếu ngày nào có người bỏ master.key
// ra khỏi snapshot vì "an toàn hơn", đây là chỗ nói cho họ biết cái giá — mọi
// secret của mọi app thành rác không giải mã được, và điều đó chỉ lộ ra lúc
// rebuild T0.
func TestSnapshotSecretsNeedTheSameMasterKey(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, keyPath := openStore(t, dir)

	const ref, plain = "app/shop/db-password", "mat-khau-that"
	if err := st.PutSecret(ctx, ref, []byte(plain)); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(t.TempDir(), "chup.db")
	if err := st.SnapshotTo(ctx, snap); err != nil {
		t.Fatal(err)
	}

	// Đúng khoá → đọc lại được nguyên văn.
	same, err := store.Open(snap, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := same.GetSecret(ctx, ref)
	same.Close()
	if err != nil || string(got) != plain {
		t.Fatalf("với ĐÚNG master.key: %q, %v — muốn %q", got, err, plain)
	}

	// Khoá khác (mô phỏng: restore lên máy mới, master.key tự sinh mới) → secret
	// thành rác. Không phải "sai mật khẩu", mà là mất hẳn.
	otherKey := filepath.Join(t.TempDir(), "master.key")
	other, err := store.Open(snap, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.GetSecret(ctx, ref); err == nil {
		t.Error("giải mã được secret bằng master.key KHÁC — keystore không thật sự khoá gì cả")
	}
}

// Chụp vào thư mục chưa tồn tại thì tự tạo, và chụp được nhiều lần ra nhiều
// tên khác nhau (retention giữ nhiều bản).
func TestSnapshotCreatesParentDirs(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, _ := openStore(t, dir)

	base := t.TempDir()
	for _, name := range []string{"2026/08/12/a.db", "2026/08/13/b.db"} {
		dst := filepath.Join(base, filepath.FromSlash(name))
		if err := st.SnapshotTo(ctx, dst); err != nil {
			t.Fatalf("SnapshotTo(%s): %v", name, err)
		}
		if fi, err := os.Stat(dst); err != nil || fi.Size() == 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
}
