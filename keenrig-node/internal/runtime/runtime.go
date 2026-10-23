// Package runtime — trừu tượng hoá tầng chạy app (docker hôm nay, swarm/k8s sau).
// Reconciler chỉ nói chuyện qua interface này, không biết driver cụ thể.
package runtime

import (
	"context"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/resources"
)

// AppSpec — trạng thái mong muốn của 1 app, đủ để driver hiện thực hoá.
type AppSpec struct {
	ID         string
	Slug       string
	Desired    contracts.DesiredApp
	DesiredRev int64
}

// Endpoint — một replica ĐANG CHẠY, ở dạng gateway nối tới được.
//
// Host là địa chỉ trong mạng nội bộ của instance (IP container trên network
// keenrig0), KHÔNG phải địa chỉ công khai: chỉ gateway đứng cùng máy mới dùng
// được. Đó là ý đồ — app không bao giờ lộ cổng ra host.
type Endpoint struct {
	Host string
	Port int
}

// Observed — trạng thái driver quan sát được sau Apply/Status.
type Observed struct {
	Phase        string // contracts.AppState*
	Health       string // contracts.Health*
	Message      string
	ContainerIDs []string
	// Endpoints — địa chỉ các replica đang Running, THEO ĐÚNG thứ tự replica idx.
	//
	// Chỉ chứa replica Running: một container Created/Exited không phục vụ được
	// request, đưa nó vào danh sách upstream là chủ động gửi lưu lượng vào chỗ
	// chết. Vì vậy len(Endpoints) có thể NHỎ HƠN len(ContainerIDs).
	//
	// Đây là điều kiện tiên quyết của T8: không có nó thì box biết app đã chạy
	// nhưng không biết bảo gateway trỏ đi đâu.
	Endpoints []Endpoint
}

// Runtime — hợp đồng driver:
//
//   - Apply đưa app về đúng AppSpec và BLOCK tới khi trạng thái ổn định
//     (mọi replica của rev mới Running) hoặc lỗi/ctx hết hạn. Apply phải
//     IDEMPOTENT: gọi lại với cùng spec khi đã hội tụ là no-op và trả cùng
//     kết quả; gọi lại sau khi bị ngắt giữa chừng phải tiếp tục hội tụ,
//     không nhân đôi tài nguyên.
//   - Status là READ-ONLY: chỉ quan sát, tuyệt đối không sửa trạng thái.
//   - Remove xoá mọi tài nguyên của app; IDEMPOTENT: app không tồn tại → nil.
//   - ResourceCaps trả hạn mức driver THỰC THI ĐƯỢC trên host này.
type Runtime interface {
	Apply(ctx context.Context, spec AppSpec) (Observed, error)
	Status(ctx context.Context, appID string) (Observed, error)
	Remove(ctx context.Context, appID string) error

	// ResourceCaps — hạn mức phần cứng driver thực thi được TRÊN HOST NÀY.
	//
	// # Vì sao nó nằm trong interface chứ không là interface tuỳ chọn
	//
	// Một `interface{ ResourceCaps(...) }` kiểm bằng type assertion nghĩa là
	// driver quên hiện thực sẽ rơi về nhánh mặc định trong im lặng — và nhánh
	// mặc định chỉ có hai lựa chọn, cả hai đều sai: "đỡ tất" (app chạy không
	// giới hạn mà không ai biết) hoặc "không đỡ gì" (mọi hạn mức bị từ chối).
	// Đặt trong interface làm việc quên trở thành lỗi BIÊN DỊCH. Cùng lý lẽ với
	// `api.routes`: quên scope phải là chuyện không viết ra được.
	//
	// # Vì sao có ctx, và vì sao trả lỗi
	//
	// Câu trả lời phụ thuộc HOST, không chỉ phụ thuộc driver: cùng một Docker
	// Engine, quota lớp ghi có trên overlay2/xfs+pquota và không có trên
	// snapshotter overlayfs. Biết được điều đó phải hỏi daemon, và hỏi daemon
	// thì treo được — nên có ctx. Nền tảng chưa trả lời được thì trả lỗi, KHÔNG
	// trả một tập rỗng: rỗng nghĩa là "đã hỏi, không đỡ gì", còn lỗi nghĩa là
	// "chưa biết", và tầng trên xử lý hai thứ đó khác nhau.
	ResourceCaps(ctx context.Context) (resources.Caps, error)
}
