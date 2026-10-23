package docker

// Dò xem HOST NÀY thực thi được hạn mức nào, và thiết bị block nào đỡ lớp ghi
// của container.
//
// # Bài học đứng sau cả file này
//
// Đo trên Docker 29.4.3, cgroup v2, snapshotter overlayfs:
//
//	docker run --rm --storage-opt size=64m busybox \
//	  sh -c 'df -m /; dd if=/dev/zero of=/big bs=1M count=128'
//	→ df: 1031018 MB khả dụng.  dd: 134217728 bytes copied.  Exit 0.
//
// Docker NHẬN cờ quota, KHÔNG đỡ được nó, và KHÔNG nói gì. Đó là lý do năng lực
// không được suy từ "Docker có chấp nhận tham số không" — câu hỏi đó trả lời
// "có" ở đúng nơi nó phải trả lời "không". Nó phải suy từ storage driver và
// filesystem đỡ bên dưới.
//
// # Vì sao dò một lần lúc mở driver, không dò mỗi lần Apply
//
// Câu trả lời chỉ đổi khi người vận hành đổi storage driver hoặc kernel — cả hai
// đều đòi restart dockerd, mà restart dockerd làm driver này bị dựng lại. Dò mỗi
// Apply là một lời gọi /info cho mỗi app mỗi 15 giây, không đổi lấy được gì.

import (
	"context"
	"fmt"
	"strings"

	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/client"

	"github.com/keenrig/keenrig/keenrig-node/internal/resources"
)

// storageDriversWithQuota — storage driver thực thi được quota lớp ghi.
//
// overlay2 CÓ ĐIỀU KIỆN (xem quotaSupported): nó chỉ có quota khi filesystem đỡ
// bên dưới là xfs bật pquota. Ba cái còn lại có quota tự thân.
var storageDriversWithQuota = map[string]bool{
	"btrfs":         true,
	"zfs":           true,
	"devicemapper":  true,
	"windowsfilter": true,
}

// ResourceCaps — hạn mức driver thực thi được TRÊN HOST NÀY.
//
// Docker Engine trả lời phần lớn câu này trong /info: MemoryLimit, SwapLimit,
// CPUShares, CPUCfsQuota, PidsLimit là cờ daemon tự dò từ kernel, không phải
// hằng số biên dịch. Ta dùng chúng thay vì đoán, vì kernel thiếu swap accounting
// là chuyện thật và rất phổ biến (Debian/Ubuntu mặc định TẮT, phải thêm
// `swapaccount=1` vào cmdline).
func (d *Driver) ResourceCaps(ctx context.Context) (resources.Caps, error) {
	info, err := d.cli.Info(ctx, client.InfoOptions{})
	if err != nil {
		return nil, fmt.Errorf("docker: querying daemon info for resource capabilities: %w", err)
	}
	return capsFromInfo(info.Info, d.ioDev()), nil
}

// capsFromInfo tách khỏi ResourceCaps để test được mọi hình dạng host mà không
// cần một host như thế: kernel không có swap accounting, storage driver không có
// quota, cgroup v1 — ba thứ không thể dựng cùng lúc trên một máy.
func capsFromInfo(info system.Info, dev string) resources.Caps {
	caps := resources.Caps{
		// Ulimits và shm là RLIMIT/tmpfs, không phải cgroup controller: chúng
		// không phụ thuộc cấu hình cgroup của host. Replicas là chuyện của
		// driver (tạo N container), không phải của kernel.
		resources.CapUlimits:  true,
		resources.CapShmSize:  true,
		resources.CapReplicas: true,
	}
	set := func(c resources.Capability, on bool) {
		if on {
			caps[c] = true
		}
	}
	set(resources.CapMemory, info.MemoryLimit)
	// SwapLimit=false là host KHÔNG có swap accounting. Docker chỉ CẢNH BÁO
	// trong trường hợp đó rồi chạy tiếp không giới hạn swap — nên nếu ta khai
	// năng lực này, app sẽ được nhận với một trần swap không tồn tại.
	set(resources.CapMemorySwap, info.MemoryLimit && info.SwapLimit)
	set(resources.CapCPUQuota, info.CPUCfsQuota)
	set(resources.CapCPUShares, info.CPUShares)
	set(resources.CapPids, info.PidsLimit)
	set(resources.CapDiskQuota, quotaSupported(info))
	// Không tra ra thiết bị block thì io.max không có chỗ để ghi vào —
	// resourcesOf cũng bỏ hai trường io khi dev rỗng. Hai chỗ phải khớp.
	set(resources.CapIOBps, dev != "")
	set(resources.CapIOIOPS, dev != "")
	return caps
}

// quotaSupported — storage driver hiện tại có thực thi `--storage-opt size` không.
//
// overlay2 cần "Backing Filesystem: xfs". Docker báo nó trong DriverStatus, và
// ta đọc chính chỗ đó thay vì stat filesystem: daemon có thể ở máy khác (DOCKER_HOST
// qua TCP), và lúc đó filesystem của TIẾN TRÌNH NÀY không liên quan gì tới nơi
// container thật sự chạy.
//
// Snapshotter containerd (DriverStatus chỉ có driver-type=io.containerd.snapshotter.v1)
// KHÔNG có quota theo container — đó chính là host đã đo được ở godoc đầu file.
func quotaSupported(info system.Info) bool {
	if storageDriversWithQuota[info.Driver] {
		return true
	}
	if info.Driver != "overlay2" {
		return false
	}
	for _, kv := range info.DriverStatus {
		if len(kv) == 2 && kv[0] == "Backing Filesystem" && kv[1] == "xfs" {
			// xfs không bật pquota thì overlay2 báo lỗi TO TIẾNG lúc create
			// ("--storage-opt is supported only for overlay over xfs with
			// 'pquota' mount option") — khác hẳn kiểu im lặng của snapshotter,
			// nên phần còn lại của điều kiện này an toàn để lạc quan.
			return true
		}
	}
	return false
}

// EnvIODevice — thiết bị block mà trần io áp lên.
//
// # Vì sao đây là biến người vận hành khai, không phải thứ ta tự dò
//
// cgroup io.max nhận theo THIẾT BỊ, nên phải biết thiết bị nào đỡ lớp ghi của
// container. Tra nó tự động đòi đọc /proc/mounts TRÊN MÁY DAEMON — không làm
// được qua Docker API, và daemon có thể ở máy khác (DOCKER_HOST qua TCP), lúc đó
// filesystem của tiến trình này không liên quan gì tới nơi container chạy. Đường
// còn lại là chạy một container privileged mỗi lần mở driver: một container đặc
// quyền để trả lời một câu hỏi cấu hình, cái giá sai hoàn toàn.
//
// Nên luật là: khai tường minh, và KHÔNG khai thì trần io không được cấp năng
// lực — app đòi nó bị từ chối lúc tạo, với thông báo nói đúng biến cần đặt. Lựa
// chọn ở đây là giữa "im lặng không throttle gì" và "nói thẳng là chưa cấu
// hình"; im lặng chính là thứ package resources tồn tại để loại bỏ.
const EnvIODevice = "KEENRIG_IO_DEVICE"

// ioDev trả thiết bị hợp lệ để throttle, hoặc "" khi chưa khai/khai sai.
//
// Trả "" thay vì lỗi có chủ đích: không có thiết bị KHÔNG phải hỏng, nó chỉ
// nghĩa là không đặt được trần io. Trả lỗi sẽ làm cả ResourceCaps thất bại — tức
// là một host chưa khai thiết bị mất luôn admission cho memory và cpu.
func (d *Driver) ioDev() string {
	dev := strings.TrimSpace(d.ioDevice)
	// Chỉ nhận đường dẫn dưới /dev. Docker cũng từ chối phần còn lại, nhưng nó
	// từ chối lúc ContainerCreate — sau khi app đã tồn tại và đã có desired_rev.
	if !strings.HasPrefix(dev, "/dev/") {
		return ""
	}
	return dev
}
