package all_test

// PR-05 xuyên driver — "im lặng không làm gì" là kiểu hỏng tệ nhất.
//
// Test theo từng driver (vd caps_test.go của caddy) kiểm được rằng năng lực
// khai báo sinh ra cấu hình thật. Cái nó KHÔNG kiểm được là một driver mới trả
// về `Report{}, nil` mà chẳng làm gì — mọi thứ trông xanh, reconciler ghi
// "proxy.applied", và không có request nào tới được app.
//
// Test này canh đúng chỗ đó: Apply phải hoặc LÀM THẬT, hoặc nói thẳng
// ErrNotImplemented. Không có đường thứ ba.

import (
	"context"
	"errors"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig/keenrig/keenrig-node/internal/proxy"
	_ "github.com/keenrig/keenrig/keenrig-node/internal/proxy/driver/all"
)

// Luật, phát biểu ở dạng chặt nhất: MỘT driver mở được thì nó PHẢI định tuyến
// được. Không có đường thứ ba.
//
// Bản trước của test này chấp nhận đường thứ ba — mở được, rồi Apply trả
// ErrNotImplemented — và chỉ `t.Logf` một dòng cảnh báo. Dòng đó không ai đọc,
// và cái giá đã đo được trên box thật: chọn `nginx` làm reconciler ghi một
// event `proxy.apply_failed` vào platform.db mỗi 15 giây, ~518.000 dòng sau 90
// ngày retention, nhấn chìm chính cái audit log đáng ra là bằng chứng.
//
// Nên `t.Logf` đổi thành `t.Fatalf`: driver chưa xong phải bị chặn TỪ CỬA MỞ.
func TestUnimplementedDriversSaySo(t *testing.T) {
	ctx := context.Background()
	for _, name := range proxy.Registered() {
		t.Run(name, func(t *testing.T) {
			ctl, err := proxy.Open(ctx, name, proxy.Config{Layout: paths.New(t.TempDir())})
			if errors.Is(err, proxy.ErrNotImplemented) {
				// Đây là câu trả lời ĐÚNG cho một driver chưa xong.
				return
			}
			if err != nil {
				t.Fatalf("Open(%s): %v", name, err)
			}

			// desired RỖNG là lời gọi vô hại nhất có thể: level-triggered nên
			// nó nghĩa "gỡ hết site của platform". Driver nào cũng phải trả lời
			// được câu này.
			_, applyErr := ctl.Apply(ctx, nil)

			caps, capErr := ctl.Capabilities(ctx)
			if capErr != nil {
				t.Fatalf("Capabilities(%s): %v", name, capErr)
			}

			if errors.Is(applyErr, proxy.ErrNotImplemented) {
				t.Fatalf("driver %q MỞ ĐƯỢC nhưng Apply trả ErrNotImplemented (khai %d năng lực).\n"+
					"Đó là hình dạng đã gây ra cơn bão event 15 giây/lần: người vận hành chọn được\n"+
					"một gateway không định tuyến gì. Driver chưa xong phải từ chối ngay ở proxy.Open.",
					name, len(caps))
			}
			if applyErr != nil {
				// Lỗi thật (không có gateway để nói chuyện trong môi trường test)
				// cũng chấp nhận được — điều bị cấm là thành công giả.
				t.Logf("driver %q: Apply lỗi thật: %v", name, applyErr)
				return
			}
			// Apply "thành công" mà driver không khai năng lực nào là dấu hiệu
			// của một no-op đội lốt.
			if len(caps) == 0 {
				t.Errorf("driver %q: Apply trả nil error nhưng không khai năng lực nào — "+
					"đây là hình dạng của một no-op im lặng", name)
			}
		})
	}
}

// Driver mặc định KHÔNG được là driver chưa hiện thực. Người không đặt
// KEENRIG_PROXY phải có định tuyến chạy được, không phải một lỗi mỗi vòng.
func TestDefaultDriverIsImplemented(t *testing.T) {
	ctx := context.Background()
	ctl, err := proxy.Open(ctx, proxy.DefaultDriver, proxy.Config{Layout: paths.New(t.TempDir())})
	if err != nil {
		t.Fatalf("Open(%s): %v", proxy.DefaultDriver, err)
	}
	if _, err := ctl.Apply(ctx, nil); errors.Is(err, proxy.ErrNotImplemented) {
		t.Fatalf("driver MẶC ĐỊNH %q chưa hiện thực Apply", proxy.DefaultDriver)
	}
	// Lỗi kết nối là bình thường ở đây (không có Caddy thật) — điều cần khẳng
	// định chỉ là nó KHÔNG phải ErrNotImplemented.
}
