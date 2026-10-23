package storetest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// Ba khẳng định về SnapshotTo, phát biểu ở tầng KHÔNG biết driver.
//
// Suite này không nói "phải là file SQLite", không mở lại bản sao, không đọc
// header. Nó chỉ nói ba điều đúng với mọi implementation: bản sao là MỘT file
// tự đủ, nó không ghi đè, và nó chụp được trong lúc đang có người ghi. Phần
// "mở lại và dữ liệu đúng" là khẳng định của driver — nằm ở sqlite_test.go,
// cùng cách targettest để phần đường-dẫn-trên-đĩa cho driver/dir.

// Bản sao phải là MỘT file tự đủ.
//
// Đây là khẳng định quan trọng nhất và cũng dễ trượt nhất: SQLite ở chế độ WAL
// giữ dữ liệu ở hai nơi, nên một hiện thực chép file chính rồi coi là xong sẽ
// tạo ra bản sao THIẾU những giao dịch chưa checkpoint — mở lên vẫn chạy, chỉ
// quên vài phút cuối. Nếu bên cạnh bản sao còn `-wal` hoặc `-shm` thì nó không
// tự đủ: nhét mỗi file chính vào archive là mất phần còn lại.
func testSnapshotTo(t *testing.T, st store.Store) {
	ctx := context.Background()
	mustCreate(t, st, "11111111-1111-4111-8111-111111111111", "truoc-khi-chup")

	dst := filepath.Join(t.TempDir(), "snap", "platform.db")
	if err := st.SnapshotTo(ctx, dst); err != nil {
		t.Fatalf("SnapshotTo: %v", err)
	}

	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("bản sao không tồn tại: %v", err)
	}
	if fi.Size() == 0 {
		t.Error("bản sao 0 byte — không phân biệt được với một lần ghi hỏng")
	}
	for _, sidecar := range []string{dst + "-wal", dst + "-shm", dst + "-journal"} {
		if _, err := os.Stat(sidecar); err == nil {
			t.Errorf("còn %s bên cạnh bản sao — bản sao KHÔNG tự đủ, nhét mỗi file chính vào archive là mất dữ liệu",
				filepath.Base(sidecar))
		}
	}

	// Store gốc vẫn phải dùng được sau khi chụp. Một lần sao lưu làm hỏng
	// instance đang chạy là cái giá không ai chấp nhận cho việc sao lưu.
	if err := st.Ping(ctx); err != nil {
		t.Errorf("store gốc hỏng sau khi chụp: %v", err)
	}
	if _, err := st.ListApps(ctx); err != nil {
		t.Errorf("đọc store gốc sau khi chụp: %v", err)
	}
}

// Đích đã tồn tại → LỖI, và file cũ KHÔNG được đụng tới.
//
// Ghi đè im lặng ở đây là cách một bản sao lưu tốt bị thay bằng một bản mới
// hỏng: lần chụp thứ hai lỗi giữa chừng, và bản đầy đủ của hôm qua đã bị xoá
// mất từ trước đó.
func testSnapshotNoOverwrite(t *testing.T, st store.Store) {
	ctx := context.Background()
	dir := t.TempDir()
	dst := filepath.Join(dir, "da-co.db")
	const oldBody = "ban sao lưu cũ, đừng đụng vào"
	if err := os.WriteFile(dst, []byte(oldBody), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := st.SnapshotTo(ctx, dst); err == nil {
		t.Error("chụp đè lên file đã có lại thành công")
	}
	b, err := os.ReadFile(dst)
	if err != nil || string(b) != oldBody {
		t.Errorf("file cũ bị sửa: %q (%v)", b, err)
	}

	// Đường dẫn rỗng cũng phải là lỗi, không phải ghi vào thư mục làm việc.
	if err := st.SnapshotTo(ctx, "  "); err == nil {
		t.Error("đích rỗng lại được chấp nhận")
	}
}

// Chụp được TRONG LÚC đang có người ghi.
//
// Sao lưu theo lịch chạy trên một instance đang phục vụ — đó là điều kiện bình
// thường, không phải ca hiếm. Một hiện thực đòi khoá độc quyền sẽ hoặc thất bại
// ở đây, hoặc chặn đường ghi đủ lâu để reconciler timeout. Cả hai đều biến sao
// lưu tự động thành thứ phải tắt đi.
func testSnapshotDuringWrites(t *testing.T, st store.Store) {
	ctx := context.Background()
	dst := filepath.Join(t.TempDir(), "trong-luc-ghi.db")

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var writeErr error
	var mu sync.Mutex

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			app := &store.App{
				ID:      fmt.Sprintf("22222222-2222-4222-8222-%012d", i),
				Slug:    fmt.Sprintf("ghi-lien-tuc-%d", i),
				Desired: json.RawMessage(`{"image":"nginx:1"}`),
			}
			if err := st.CreateApp(ctx, app); err != nil {
				mu.Lock()
				writeErr = err
				mu.Unlock()
				return
			}
		}
	}()

	err := st.SnapshotTo(ctx, dst)
	close(stop)
	wg.Wait()

	if err != nil {
		t.Fatalf("chụp trong lúc đang ghi: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if writeErr != nil {
		t.Errorf("đường GHI bị hỏng vì một lần chụp: %v — sao lưu không được chặn đường phục vụ", writeErr)
	}
	if fi, serr := os.Stat(dst); serr != nil || fi.Size() == 0 {
		t.Errorf("bản sao lưu không dùng được: %v", serr)
	}
}
