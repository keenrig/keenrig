package swarm

// Hạn mức phần cứng trên swarm — và bốn thứ swarm KHÔNG làm được.
//
// # Vì sao bốn thứ đó vắng mặt vì API, không vì "chưa làm"
//
//	swarm.Limit                = { NanoCPUs, MemoryBytes, Pids }
//	swarm.ResourceRequirements = { Limits, Reservations, SwapBytes, ... }
//	swarm.ContainerSpec        = { ..., Sysctls, Ulimits, CapabilityAdd }
//
// Không có trường nào cho cpu shares, blkio throttle, storage quota hay shm —
// `docker service create` cũng không có cờ tương ứng. Đó là lý do
// `resources.ByDriver("swarm")` không khai bốn năng lực đó, và vì sao một app
// khai `io_write_mbps` bị TỪ CHỐI lúc tạo trên swarm thay vì được nhận rồi chạy
// không throttle. Ranh giới này được canh bằng test đối chiếu bảng năng lực với
// thứ buildSpec thật sự sinh ra.

import (
	"context"

	"github.com/moby/moby/api/types/container"
	swarmapi "github.com/moby/moby/api/types/swarm"

	"github.com/keenrig/keenrig/keenrig-node/internal/resources"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
)

// ResourceCaps — swarm không có cờ nào phụ thuộc host cho phần này: những gì
// ContainerSpec/Limit chứa được thì mọi manager đều nhận. Nên nó trả đúng bảng
// tĩnh, và trả THẲNG bảng đó (không dựng lại bằng tay) để hai nguồn sự thật
// không thể lệch nhau.
//
// Ngoại lệ đáng nói: swap. Kernel của NODE có thể không có swap accounting, và
// manager không biết điều đó thay cho node. Khai CapMemorySwap ở đây là lạc quan
// một cách có ý thức — swarm nhận SwapBytes và task sẽ nổ trên node không đỡ,
// tức là hỏng TO TIẾNG trên node đó chứ không im lặng mất trần.
func (d *Driver) ResourceCaps(_ context.Context) (resources.Caps, error) {
	return resources.ByDriver(Name), nil
}

// resourcesOf dịch `desired.resources` → swarm.ResourceRequirements.
//
// Trả nil khi không có hạn mức nào: swarm phân biệt "không khai" với "khai 0", và
// một ResourceRequirements rỗng làm mọi lần Apply trông như một thay đổi spec
// (swarm so sánh spec để quyết định có rolling update hay không).
func resourcesOf(spec runtime.AppSpec) *swarmapi.ResourceRequirements {
	r := spec.Desired.Resources
	if r == nil {
		return nil
	}
	lim := &swarmapi.Limit{}
	if r.MemoryMB > 0 {
		lim.MemoryBytes = int64(r.MemoryMB) << 20
	}
	if r.CPU > 0 {
		lim.NanoCPUs = int64(r.CPU * 1e9)
	}
	if r.PidsLimit > 0 {
		lim.Pids = int64(r.PidsLimit)
	}
	empty := *lim == swarmapi.Limit{}
	if empty && r.MemorySwapMB == 0 {
		return nil
	}
	out := &swarmapi.ResourceRequirements{}
	if !empty {
		out.Limits = lim
	}
	if r.MemorySwapMB > 0 {
		// SwapBytes ở swarm là TỔNG mem+swap, cùng ngữ nghĩa với hợp đồng và
		// với `--memory-swap` của Docker — không có phép trừ nào ở đây.
		swap := int64(r.MemorySwapMB) << 20
		out.SwapBytes = &swap
	}
	return out
}

func ulimitsOf(spec runtime.AppSpec) []*container.Ulimit {
	r := spec.Desired.Resources
	if r == nil {
		return nil
	}
	out := make([]*container.Ulimit, 0, len(r.Ulimits))
	for _, u := range r.Ulimits {
		out = append(out, &container.Ulimit{Name: u.Name, Soft: u.Soft, Hard: u.HardOr()})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
