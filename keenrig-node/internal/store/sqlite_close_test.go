package store_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// TestCloseCheckpointsWAL — sau Close, platform.db-wal phải rỗng (hoặc biến mất).
//
// Vì sao đáng một test riêng: đây là điều kiện để "copy file platform.db" là
// một bản backup ĐÚNG. Bỏ lại -wal có commit chưa checkpoint thì bản backup mở
// lên vẫn chạy, chỉ thiếu vài giao dịch cuối — hỏng im lặng, kiểu tệ nhất.
// Cùng lý do đó áp cho cửa sổ OTA, khi box cũ tắt và box mới mở lại cùng file.
func TestCloseCheckpointsWAL(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "platform.db")
	st, err := store.Open(dbPath, filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	ctx := context.Background()
	// Ghi đủ để WAL chắc chắn có nội dung chưa checkpoint.
	for i := 0; i < 50; i++ {
		if err := st.AppendEvent(ctx, "test.write", "tester", "", json.RawMessage(`{"i":1}`)); err != nil {
			t.Fatalf("AppendEvent: %v", err)
		}
	}
	if fi, err := os.Stat(dbPath + "-wal"); err != nil || fi.Size() == 0 {
		t.Skipf("môi trường không tạo -wal có nội dung (err=%v) — test không có gì để khẳng định", err)
	}

	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fi, err := os.Stat(dbPath + "-wal")
	if os.IsNotExist(err) {
		return // -wal bị xoá hẳn: cũng đạt
	}
	if err != nil {
		t.Fatalf("Stat -wal sau Close: %v", err)
	}
	if fi.Size() != 0 {
		t.Errorf("-wal còn %d byte sau Close, muốn 0 — copy platform.db sẽ mất commit cuối", fi.Size())
	}

	// Mở lại phải thấy đủ dữ liệu (checkpoint không được làm mất gì).
	st2, err := store.Open(dbPath, filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("Open lần 2: %v", err)
	}
	defer st2.Close()
	evs, err := st2.ListEvents(ctx, 100)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(evs) != 50 {
		t.Errorf("sau checkpoint còn %d event, muốn 50", len(evs))
	}
}
