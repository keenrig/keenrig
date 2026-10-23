package runtime

import "time"

// MaxApplyTimeout — thời gian block lâu nhất của một Apply, tính trên DRIVER
// CHẬM NHẤT đã biên dịch vào binary.
//
// Vì sao khai ở đây chứ không để mỗi driver tự giữ: reconciler phải chọn
// LeaseTTL thoả `LeaseTTL > LeaseTTL/3 + maxApply`, mà nó KHÔNG biết driver nào
// sẽ được chọn lúc chạy (env quyết định, và người vận hành đổi env rồi restart
// là chuyện bình thường). Lấy theo driver chậm nhất là cách duy nhất đúng cho
// mọi cấu hình.
//
// Con số này và timeout thật của từng driver được canh bằng test
// TestApplyTimeoutsWithinBudget — sửa một chỗ mà quên chỗ kia sẽ đỏ.
const MaxApplyTimeout = 180 * time.Second

// Timeout thật của từng driver, khai tập trung để test đối chiếu được.
//
// Driver vẫn dùng hằng số riêng của nó (đọc code driver không phải nhảy sang
// file này); bảng dưới đây là bản sao CÓ TEST CANH, không phải nguồn sự thật
// thứ hai lặng lẽ trôi khỏi bản gốc.
const (
	DockerApplyTimeout = 60 * time.Second
	SwarmApplyTimeout  = 120 * time.Second
	K8sApplyTimeout    = 180 * time.Second
)
