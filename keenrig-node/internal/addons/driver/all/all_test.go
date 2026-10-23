package all

// Đây là package DUY NHẤT thấy được cả registry đã nạp lẫn danh sách khai báo —
// `addons` không import driver (sẽ thành vòng), và driver không import nhau. Nên
// khẳng định "mọi addon đã khai đều có driver" chỉ phát biểu được ở đây.

import (
	"testing"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/addons"
)

// AllKinds là thứ schema, API và UI dùng để nói "hệ thống hỗ trợ addon nào".
// Registered là thứ thực sự có code. Lệch nhau nghĩa là ta quảng cáo một addon
// mà lúc hội tụ trả ErrUnknownAddon — lỗi rơi xuống người dùng ở bước cuối, sau
// khi họ đã tạo app và chờ.
func TestEveryDeclaredKindHasDriver(t *testing.T) {
	have := map[addons.Kind]bool{}
	for _, k := range addons.Registered() {
		have[k] = true
	}
	for _, k := range addons.AllKinds() {
		if !have[k] {
			t.Errorf("AllKinds khai %q nhưng không driver nào Register nó — "+
				"thiếu một dòng import trong package all", k)
		}
	}
	for k := range have {
		found := false
		for _, d := range addons.AllKinds() {
			if d == k {
				found = true
			}
		}
		if !found {
			t.Errorf("driver %q đã Register nhưng không có trong AllKinds — "+
				"nó sẽ không bao giờ được bật qua API", k)
		}
	}
}
