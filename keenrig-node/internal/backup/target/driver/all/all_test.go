package all_test

// Package DUY NHẤT thấy được mọi driver đã nạp, nên khẳng định về TẬP driver chỉ
// phát biểu được ở đây.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/backup/target"
	_ "github.com/keenrig/keenrig/keenrig-node/internal/backup/target/driver/all"
)

func TestRegisteredDrivers(t *testing.T) {
	got := strings.Join(target.Registered(), ",")
	if got != "dir,s3" {
		t.Errorf("Registered() = %q, muốn \"dir,s3\"", got)
	}
}

// Tên driver gõ sai → lỗi LIỆT KÊ tên hợp lệ.
//
// Lỗi này gần như luôn là gõ sai biến môi trường, nên thông báo phải trả lời luôn
// câu hỏi tiếp theo của người vận hành.
func TestUnknownDriverListsValidNames(t *testing.T) {
	_, err := target.Open(context.Background(), "s3x", target.Config{})
	if !errors.Is(err, target.ErrUnknownDriver) {
		t.Fatalf("= %v, muốn ErrUnknownDriver", err)
	}
	for _, name := range target.Registered() {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("thông báo không liệt kê %q: %v", name, err)
		}
	}
}

// KHÔNG cấu hình gì → ErrNotConfigured, KHÔNG phải một target mặc định.
//
// Đây là điểm khác proxy có chủ đích: một gateway mặc định sai thì thấy ngay (site
// không lên), còn một target mặc định sai thì im lặng ghi bản sao lưu vào đĩa cục
// bộ của chính máy sắp chết.
func TestNoDefaultTarget(t *testing.T) {
	if _, err := target.Open(context.Background(), "", target.Config{}); !errors.Is(err, target.ErrNotConfigured) {
		t.Errorf("= %v, muốn ErrNotConfigured", err)
	}
}

// Mọi driver phải TỪ CHỐI DSN rỗng, không phải đoán một giá trị mặc định.
//
// Chạy vòng trên registry chứ không viết tay hai ca: driver thứ ba thêm vào sẽ tự
// động bị kiểm.
func TestEveryDriverRefusesEmptyDSN(t *testing.T) {
	for _, name := range target.Registered() {
		t.Run(name, func(t *testing.T) {
			_, err := target.Open(context.Background(), name, target.Config{DSN: ""})
			if !errors.Is(err, target.ErrBadConfig) {
				t.Errorf("Open(%q, DSN rỗng) = %v, muốn ErrBadConfig", name, err)
			}
		})
	}
}
