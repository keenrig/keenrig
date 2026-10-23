// Package resources — hạn mức phần cứng của app: thông số nào CẦN năng lực nào,
// runtime nào THỰC THI được năng lực nào, và luật kiểm mà JSON Schema không nói được.
//
// # Vì sao package này tồn tại thay vì để mỗi driver tự lo
//
// Vì kiểu hỏng ở tầng hạn mức là IM LẶNG, và nó đã đo được trên Docker thật
// (29.4.3, cgroup v2, snapshotter overlayfs):
//
//	docker run --storage-opt size=64m busybox \
//	  sh -c 'dd if=/dev/zero of=/big bs=1M count=128'
//	→ 134217728 bytes copied.  df báo 1 TB. Không một dòng lỗi nào.
//
// Docker nhận cờ quota, không đỡ được nó, và không nói gì. Một hiện thực ngây
// thơ sẽ mở `disk_mb` trong API, chuyển thẳng xuống Docker, không thấy lỗi, và
// người vận hành tin rằng app đã bị chặn. Đó là hình dạng tệ nhất: không có gì
// hỏng để lần ra, chỉ có một lời hứa không được giữ.
//
// Nên luật ở đây giống hệt luật của seam proxy (PR-08): mỗi trường hạn mức ứng
// với một Capability, và app đòi một năng lực runtime đang chạy KHÔNG có thì bị
// từ chối LÚC TẠO, chứ không phải được nhận rồi im lặng chạy không giới hạn.
//
// # Vì sao nó là package riêng, không nằm trong internal/runtime
//
// `internal/api` bị Luật 9 (V2-DELTA §3) cấm phụ thuộc `internal/runtime`, và
// `api` → `apps` → admission thì phải biết về năng lực. Đặt Capability trong
// `runtime` sẽ làm `TestLayer1DoesNotImportSubsystems` đỏ. Package này là LÁ:
// nó chỉ import contracts.
package resources

import (
	"fmt"
	"sort"
	"strings"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
)

// Capability — một hạn mức mà nền tảng CÓ THỂ thực thi. Driver công bố tập mình
// thực thi được; app đòi thứ ngoài tập đó bị từ chối lúc tạo.
type Capability string

const (
	CapMemory     Capability = "memory"      // cgroup memory.max
	CapMemorySwap Capability = "memory_swap" // memory.swap.max — cần kernel bật swap accounting
	CapCPUQuota   Capability = "cpu_quota"   // cpu.max — trần cứng
	CapCPUShares  Capability = "cpu_shares"  // cpu.weight — trọng số tương đối
	CapPids       Capability = "pids"        // pids.max
	CapDiskQuota  Capability = "disk_quota"  // quota lớp ghi; xem godoc package
	CapIOBps      Capability = "io_bps"      // io.max rbps/wbps
	CapIOIOPS     Capability = "io_iops"     // io.max riops/wiops
	CapUlimits    Capability = "ulimits"     // RLIMIT_* theo process
	CapShmSize    Capability = "shm_size"    // kích thước /dev/shm
	CapReplicas   Capability = "replicas"    // chạy nhiều bản
)

// All — mọi năng lực, theo thứ tự ổn định. Dùng cho test và cho thông báo lỗi.
func All() []Capability {
	return []Capability{
		CapMemory, CapMemorySwap, CapCPUQuota, CapCPUShares, CapPids,
		CapDiskQuota, CapIOBps, CapIOIOPS, CapUlimits, CapShmSize, CapReplicas,
	}
}

// Caps — tập năng lực của một runtime.
type Caps map[Capability]bool

func (c Caps) Has(x Capability) bool { return c[x] }

// Names trả tên đã sắp xếp — để thông báo lỗi và log ổn định giữa hai lần chạy.
func Names(cs []Capability) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, string(c))
	}
	sort.Strings(out)
	return out
}

// Requires trả tập năng lực mà một khai báo `desired.resources` CẦN.
//
// Chỉ trường ĐƯỢC ĐẶT mới sinh yêu cầu: một app không khai `io_write_mbps` phải
// chạy được trên runtime không đỡ throttle. Nếu không thì mọi app trên k8s đều
// bị từ chối vì một năng lực chẳng ai yêu cầu — đúng lỗi mà `proxy.TLSModeFor`
// đã phải sửa (admission nghiêm hơn thực tế).
//
// `replicas: 1` KHÔNG sinh yêu cầu CapReplicas: một bản là mặc định, mọi runtime
// làm được.
func Requires(r *contracts.Resources) Caps {
	need := Caps{}
	if r == nil {
		return need
	}
	set := func(c Capability, on bool) {
		if on {
			need[c] = true
		}
	}
	set(CapMemory, r.MemoryMB > 0)
	set(CapMemorySwap, r.MemorySwapMB > 0)
	set(CapCPUQuota, r.CPU > 0)
	set(CapCPUShares, r.CPUShares > 0)
	set(CapPids, r.PidsLimit > 0)
	set(CapDiskQuota, r.DiskMB > 0)
	set(CapIOBps, r.IOReadMBps > 0 || r.IOWriteMBps > 0)
	set(CapIOIOPS, r.IOReadIOPS > 0 || r.IOWriteIOPS > 0)
	set(CapUlimits, len(r.Ulimits) > 0)
	set(CapShmSize, r.ShmSizeMB > 0)
	set(CapReplicas, r.Replicas > 1)
	return need
}

// MissingCaps trả năng lực app CẦN nhưng runtime KHÔNG có, đã sắp xếp.
//
// `have` là nil nghĩa là CHƯA BIẾT năng lực (chưa dò được nền tảng) → trả rỗng.
// Cùng lý lẽ với `proxy.MissingCaps`: nền tảng chưa trả lời được không được biến
// thành "không tạo được app". Chỗ bù cho sự lạc quan đó là tầng Apply — driver
// phải từ chối TO TIẾNG khi thực sự áp không được (xem Enforce).
func MissingCaps(r *contracts.Resources, have Caps) []Capability {
	if have == nil {
		return nil
	}
	var out []Capability
	for c, needed := range Requires(r) {
		if needed && !have.Has(c) {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ErrUnenforceable — hạn mức không áp được trên nền tảng này.
//
// Driver trả lỗi này từ Apply thay vì áp một phần rồi báo thành công. Đó là
// nửa còn lại của luật ở godoc package: admission có thể lạc quan (caps nil),
// nhưng đường thực thi thì KHÔNG được im lặng bỏ qua bao giờ.
type ErrUnenforceable struct {
	Missing []Capability
	Runtime string
}

func (e *ErrUnenforceable) Error() string {
	return fmt.Sprintf("resources: runtime %q cannot enforce %s — "+
		"the app would run WITHOUT that limit, so it is refused instead",
		e.Runtime, strings.Join(Names(e.Missing), ", "))
}

// Enforce kiểm trước khi áp: thiếu năng lực → ErrUnenforceable.
//
// Gọi từ driver, không phải từ admission. Hai chỗ kiểm không phải trùng lặp:
// admission chạy trên năng lực THEO THIẾT KẾ của driver (biết được mà không cần
// nói chuyện với nền tảng), còn chỗ này chạy trên năng lực ĐO ĐƯỢC của host —
// và khoảng cách giữa hai thứ đó chính là chỗ `--storage-opt` lọt qua.
func Enforce(r *contracts.Resources, have Caps, runtimeName string) error {
	missing := MissingCaps(r, have)
	if len(missing) == 0 {
		return nil
	}
	return &ErrUnenforceable{Missing: missing, Runtime: runtimeName}
}

// --- luật kiểm mà JSON Schema không nói được ----------------------------------

// ErrInvalid — hạn mức tự mâu thuẫn. Tách khỏi lỗi schema vì nó là quan hệ GIỮA
// hai trường, thứ JSON Schema draft 2020-12 không so sánh được.
type ErrInvalid struct{ Reason string }

func (e *ErrInvalid) Error() string { return "resources: " + e.Reason }

// Validate canh ba quan hệ giữa các trường.
//
// # Vì sao không để driver tự phát hiện
//
// Driver PHÁT HIỆN được: Docker từ chối `--memory-swap` nhỏ hơn `--memory`. Nhưng
// nó phát hiện lúc Apply — sau khi app đã được tạo, đã có desired_rev, và người
// bấm nút đã đi làm việc khác. Thông báo lúc đó nằm trong event log dưới dạng
// lỗi driver, không phải một 400 chỉ đúng vào trường sai.
func Validate(r *contracts.Resources) error {
	if r == nil {
		return nil
	}
	// swap là TỔNG mem+swap, nên nhỏ hơn mem là vô nghĩa — và Docker từ chối nó.
	if r.MemorySwapMB > 0 && r.MemoryMB > 0 && r.MemorySwapMB < r.MemoryMB {
		return &ErrInvalid{Reason: fmt.Sprintf(
			"memory_swap_mb (%d) is the TOTAL of memory+swap, so it cannot be below memory_mb (%d)",
			r.MemorySwapMB, r.MemoryMB)}
	}
	// swap không có ý nghĩa nếu không có trần memory: cgroup chỉ đặt được
	// memory.swap.max cùng với memory.max.
	if r.MemorySwapMB > 0 && r.MemoryMB == 0 {
		return &ErrInvalid{Reason: "memory_swap_mb needs memory_mb: a swap ceiling without a memory ceiling caps nothing"}
	}
	seen := make(map[string]bool, len(r.Ulimits))
	for _, u := range r.Ulimits {
		if seen[u.Name] {
			// Hai dòng cùng tên: Docker lấy dòng CUỐI, im lặng. Người dùng thấy
			// dòng đầu trong desired và tin nó đang có tác dụng.
			return &ErrInvalid{Reason: fmt.Sprintf("ulimit %q is declared twice; only the last one would take effect", u.Name)}
		}
		seen[u.Name] = true
		if u.Hard != 0 && u.Hard < u.Soft {
			return &ErrInvalid{Reason: fmt.Sprintf(
				"ulimit %q has hard (%d) below soft (%d)", u.Name, u.Hard, u.Soft)}
		}
	}
	return nil
}
