package k8s

// Hạn mức phần cứng trên Kubernetes — ba thứ map được, năm thứ không.
//
// Pod chỉ khai được `resources.limits` với memory / cpu / ephemeral-storage.
// Năm thông số còn lại vắng mặt, và mỗi thứ vắng vì một lý do KHÁC NHAU — không
// lý do nào là "chưa viết code":
//
//   - cpu_shares: k8s có `requests.cpu`, và nó thật sự thành cpu.weight trên
//     node. Nhưng requests còn quyết định pod được XẾP lên node nào và app thuộc
//     hạng QoS nào (Guaranteed/Burstable). Map cpu_shares vào đó là lặng lẽ đổi
//     luôn hai thứ người dùng không hề yêu cầu.
//   - pids_limit: `podPidsLimit` là cấu hình của KUBELET, một giá trị cho mọi pod
//     trên node. Không có đường khai theo app.
//   - io_read/write: không tồn tại trong resource model của k8s.
//   - ulimits: cần securityContext/sysctl ở tầng pod, và sysctl thì bị allowlist
//     của kubelet chặn — không phải hạn mức của container.
//   - shm_size: chỉ làm được bằng mẹo `emptyDir{medium: Memory}` mount vào
//     /dev/shm, và mẹo đó ĂN vào chính trần memory của pod. Một trường "tăng shm"
//     mà lặng lẽ trừ vào RAM khả dụng là thông tin sai.
//
// `ephemeral-storage` LÀ tương đương thật của disk_mb: kubelet đo dung lượng lớp
// ghi + emptyDir và EVICT pod khi vượt. Nó cưỡng chế bằng cách trục xuất chứ
// không bằng ENOSPC như quota của xfs — khác cơ chế, nhưng cùng lời hứa: app
// không ghi quá phần của mình mà không có hậu quả.

import (
	"context"
	"strconv"

	"github.com/keenrig/keenrig/keenrig-node/internal/resources"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
)

// ResourceCaps trả thẳng bảng tĩnh: những gì `resources.limits` chứa được thì
// mọi cluster đều nhận, không có cờ nào phụ thuộc node ở tầng này.
//
// (Trần ephemeral-storage cần feature gate LocalStorageCapacityIsolation, bật
// mặc định từ k8s 1.25 — thấp hơn phiên bản tối thiểu driver này nói chuyện được.)
func (d *Driver) ResourceCaps(_ context.Context) (resources.Caps, error) {
	return resources.ByDriver(Name), nil
}

func resourcesOf(spec runtime.AppSpec) *resourceReqs {
	r := spec.Desired.Resources
	if r == nil {
		return nil
	}
	lim := map[string]string{}
	if r.MemoryMB > 0 {
		lim["memory"] = strconv.Itoa(r.MemoryMB) + "Mi"
	}
	if r.CPU > 0 {
		// milliCPU: Kubernetes nhận "500m". Nhân 1000 rồi làm tròn để
		// 0.5 CPU không thành "0.5" (hợp lệ nhưng khó đọc trong kubectl).
		lim["cpu"] = strconv.Itoa(int(r.CPU*1000+0.5)) + "m"
	}
	if r.DiskMB > 0 {
		lim["ephemeral-storage"] = strconv.Itoa(r.DiskMB) + "Mi"
	}
	if len(lim) == 0 {
		return nil
	}
	return &resourceReqs{Limits: lim}
}
