package resources_test

// RS-01..RS-04 — luật của tầng hạn mức, kiểm ở nơi rẻ nhất.
//
// Test đắt nhất của bộ này (docker thật, đọc cgroup) nằm ở
// runtime/driver/docker/reslimits_test.go. File này canh thứ test đó KHÔNG canh
// được: rằng danh sách trường và danh sách năng lực không bao giờ lệch nhau.

import (
	"reflect"
	"strings"
	"testing"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/resources"
)

// fieldCap — mỗi trường của contracts.Resources ứng với năng lực nào, và giá trị
// nào là "đã đặt". Bảng này là ĐẶC TẢ, không phải bản sao của code.
var fieldCap = map[string]struct {
	cap resources.Capability
	set func(*contracts.Resources)
}{
	"MemoryMB":     {resources.CapMemory, func(r *contracts.Resources) { r.MemoryMB = 128 }},
	"MemorySwapMB": {resources.CapMemorySwap, func(r *contracts.Resources) { r.MemorySwapMB = 256 }},
	"CPU":          {resources.CapCPUQuota, func(r *contracts.Resources) { r.CPU = 0.5 }},
	"CPUShares":    {resources.CapCPUShares, func(r *contracts.Resources) { r.CPUShares = 512 }},
	"PidsLimit":    {resources.CapPids, func(r *contracts.Resources) { r.PidsLimit = 100 }},
	"DiskMB":       {resources.CapDiskQuota, func(r *contracts.Resources) { r.DiskMB = 512 }},
	"IOReadMBps":   {resources.CapIOBps, func(r *contracts.Resources) { r.IOReadMBps = 10 }},
	"IOWriteMBps":  {resources.CapIOBps, func(r *contracts.Resources) { r.IOWriteMBps = 10 }},
	"IOReadIOPS":   {resources.CapIOIOPS, func(r *contracts.Resources) { r.IOReadIOPS = 500 }},
	"IOWriteIOPS":  {resources.CapIOIOPS, func(r *contracts.Resources) { r.IOWriteIOPS = 500 }},
	"Ulimits": {resources.CapUlimits, func(r *contracts.Resources) {
		r.Ulimits = []contracts.Ulimit{{Name: "nofile", Soft: 1024, Hard: 2048}}
	}},
	"ShmSizeMB": {resources.CapShmSize, func(r *contracts.Resources) { r.ShmSizeMB = 128 }},
	"Replicas":  {resources.CapReplicas, func(r *contracts.Resources) { r.Replicas = 2 }},
}

// RS-01 — MỌI trường của contracts.Resources phải có một năng lực canh nó.
//
// # Vì sao test này tồn tại, và vì sao nó dùng reflection
//
// Vì kiểu hỏng nguy hiểm nhất ở tầng này không phải một phép dịch sai — nó là
// một trường ĐƯỢC THÊM VÀO HỢP ĐỒNG mà không ai nối dây. Lúc đó: schema nhận
// trường, người dùng khai nó, `Requires` không đòi năng lực nào, admission cho
// qua, driver không đọc nó, và app chạy KHÔNG có hạn mức đó. Không một test viết
// tay nào đỏ, vì test viết tay chỉ kiểm những trường tác giả nhớ tới.
//
// Reflection đổi chuyện đó thành lỗi bắt buộc: thêm `NetworkMBps` vào struct mà
// quên mọi thứ khác thì test này đỏ ngay, với đúng tên trường trong thông báo.
func TestMoiTruongDeuCoNangLucCanh(t *testing.T) {
	rt := reflect.TypeOf(contracts.Resources{})
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		spec, known := fieldCap[name]
		if !known {
			t.Errorf("contracts.Resources.%s KHÔNG có năng lực nào canh nó.\n"+
				"Thêm trường vào hợp đồng mà không nối dây nghĩa là người dùng khai được\n"+
				"một hạn mức rồi app chạy không có hạn mức đó — không có gì đỏ để lần ra.\n"+
				"Sửa: thêm một Capability trong internal/resources, map nó trong Requires,\n"+
				"áp nó trong driver, rồi khai nó ở bảng fieldCap của test này.", name)
			continue
		}
		var r contracts.Resources
		spec.set(&r)
		need := resources.Requires(&r)
		if !need.Has(spec.cap) {
			t.Errorf("đặt %s nhưng Requires() không đòi %q (đòi %v)", name, spec.cap, need)
		}
		// Và nó KHÔNG được đòi thứ gì khác: một trường kéo theo năng lực lạ sẽ
		// làm app bị từ chối vì thứ nó không yêu cầu (lỗi TLSModeFor đã phải sửa).
		for c := range need {
			if c != spec.cap {
				t.Errorf("đặt %s làm Requires() đòi thêm %q — admission sẽ nghiêm hơn thực tế", name, c)
			}
		}
	}
}

// RS-01b — mọi Capability phải được ÍT NHẤT một trường dùng tới.
//
// Chiều ngược lại của test trên. Một năng lực không trường nào đòi là năng lực
// driver phải khai và test phải canh mà không bảo vệ được gì — nó chỉ làm ma
// trận năng lực trông đầy đủ hơn thực tế.
func TestMoiNangLucDeuCoTruongDung(t *testing.T) {
	used := map[resources.Capability]bool{}
	for _, spec := range fieldCap {
		used[spec.cap] = true
	}
	for _, c := range resources.All() {
		if !used[c] {
			t.Errorf("năng lực %q không trường nào của desired.resources đòi tới — nó canh cái gì?", c)
		}
	}
}

// RS-02 — không khai gì thì không đòi gì.
//
// Đây là nửa dễ quên của admission: nếu `Requires` đòi năng lực cho trường KHÔNG
// đặt, mọi app trên k8s sẽ bị từ chối vì `io_bps` — một năng lực chẳng ai yêu cầu.
func TestKhongKhaiThiKhongDoi(t *testing.T) {
	for _, r := range []*contracts.Resources{nil, {}, {Replicas: 1}} {
		if need := resources.Requires(r); len(need) != 0 {
			t.Errorf("Requires(%+v) = %v, muốn rỗng", r, need)
		}
		// Và không runtime nào bị coi là thiếu năng lực cho một app như thế.
		for _, drv := range []string{"docker", "swarm", "k8s"} {
			if m := resources.MissingCaps(r, resources.ByDriver(drv)); len(m) != 0 {
				t.Errorf("app không khai hạn mức bị %s từ chối vì %v", drv, m)
			}
		}
	}
}

// RS-03 — caps nil nghĩa là CHƯA BIẾT, không phải "không đỡ gì".
//
// Nếu nil bị hiểu là rỗng thì một box chưa dò được nền tảng sẽ từ chối mọi app
// có hạn mức — nền tảng chưa trả lời được biến thành không tạo được app.
func TestCapsNilKhongTuChoiGi(t *testing.T) {
	full := &contracts.Resources{MemoryMB: 128, CPU: 1, DiskMB: 512, IOWriteMBps: 10}
	if m := resources.MissingCaps(full, nil); m != nil {
		t.Errorf("MissingCaps(caps=nil) = %v, muốn nil (chưa biết ≠ không đỡ)", m)
	}
	if err := resources.Enforce(full, nil, "docker"); err != nil {
		t.Errorf("Enforce với caps nil = %v, muốn nil", err)
	}
}

// RS-04 — ma trận năng lực phải nói ĐÚNG giới hạn của từng API.
//
// Đây là những khẳng định kiểm được bằng tài liệu API, và chúng là thứ giữ cho
// `ByDriver` không trôi thành "khai cho đủ": swarm.Limit chỉ có
// {NanoCPUs, MemoryBytes, Pids}, và pod chỉ khai được memory/cpu/ephemeral-storage.
func TestMaTranNangLucDungVoiTungAPI(t *testing.T) {
	cases := []struct {
		driver string
		cap    resources.Capability
		want   bool
		why    string
	}{
		{"swarm", resources.CapIOBps, false, "swarm không có trường blkio nào"},
		{"swarm", resources.CapIOIOPS, false, "swarm không có trường blkio nào"},
		{"swarm", resources.CapDiskQuota, false, "swarm không nhận --storage-opt"},
		{"swarm", resources.CapCPUShares, false, "swarm.Limit không có CPUShares"},
		{"swarm", resources.CapShmSize, false, "swarm.ContainerSpec không có ShmSize"},
		{"swarm", resources.CapPids, true, "swarm.Limit CÓ Pids"},
		{"swarm", resources.CapUlimits, true, "swarm.ContainerSpec CÓ Ulimits"},
		{"swarm", resources.CapMemorySwap, true, "ResourceRequirements CÓ SwapBytes"},

		{"k8s", resources.CapDiskQuota, true, "limits.ephemeral-storage là tương đương thật"},
		{"k8s", resources.CapPids, false, "podPidsLimit là cấu hình kubelet, không theo app"},
		{"k8s", resources.CapUlimits, false, "pod không khai RLIMIT theo container"},
		{"k8s", resources.CapIOBps, false, "resource model của k8s không có io"},
		{"k8s", resources.CapShmSize, false, "chỉ làm được bằng mẹo emptyDir, và nó ăn vào trần memory"},
		{"k8s", resources.CapMemorySwap, false, "swap của k8s là chuyện cấp node"},

		{"docker", resources.CapIOBps, true, "HostConfig có BlkioDeviceReadBps/WriteBps"},
		{"docker", resources.CapShmSize, true, "HostConfig có ShmSize"},
	}
	for _, c := range cases {
		if got := resources.ByDriver(c.driver).Has(c.cap); got != c.want {
			t.Errorf("ByDriver(%q).Has(%q) = %v, muốn %v — %s", c.driver, c.cap, got, c.want, c.why)
		}
	}

	// Driver lạ → nil (chưa biết), KHÔNG phải rỗng: xem godoc ByDriver.
	if caps := resources.ByDriver("nomad"); caps != nil {
		t.Errorf("ByDriver(driver lạ) = %v, muốn nil", caps)
	}
}

// RS-05 — luật GIỮA các trường, thứ JSON Schema không so sánh được.
func TestValidateQuanHeGiuaCacTruong(t *testing.T) {
	cases := []struct {
		name    string
		r       contracts.Resources
		wantErr string // chuỗi con phải có trong thông báo; "" = phải hợp lệ
	}{
		{
			name:    "swap dưới memory",
			r:       contracts.Resources{MemoryMB: 512, MemorySwapMB: 256},
			wantErr: "TOTAL",
		},
		{
			name:    "swap bằng memory là hợp lệ (nghĩa là TẮT swap)",
			r:       contracts.Resources{MemoryMB: 512, MemorySwapMB: 512},
			wantErr: "",
		},
		{
			name:    "swap không có memory",
			r:       contracts.Resources{MemorySwapMB: 512},
			wantErr: "needs memory_mb",
		},
		{
			name: "ulimit hard dưới soft",
			r: contracts.Resources{Ulimits: []contracts.Ulimit{
				{Name: "nofile", Soft: 4096, Hard: 1024},
			}},
			wantErr: "below soft",
		},
		{
			name: "ulimit hard không đặt = bằng soft, hợp lệ",
			r: contracts.Resources{Ulimits: []contracts.Ulimit{
				{Name: "nofile", Soft: 4096},
			}},
			wantErr: "",
		},
		{
			name: "ulimit trùng tên",
			r: contracts.Resources{Ulimits: []contracts.Ulimit{
				{Name: "nofile", Soft: 1024}, {Name: "nofile", Soft: 4096},
			}},
			wantErr: "twice",
		},
		{
			name:    "core=0 hợp lệ — tắt core dump là ý định thật",
			r:       contracts.Resources{Ulimits: []contracts.Ulimit{{Name: "core", Soft: 0, Hard: 0}}},
			wantErr: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := resources.Validate(&c.r)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate = %v, muốn nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate = nil, muốn lỗi chứa %q", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("thông báo %q không chứa %q", err, c.wantErr)
			}
		})
	}
	if err := resources.Validate(nil); err != nil {
		t.Errorf("Validate(nil) = %v, muốn nil", err)
	}
}

// RS-06 — HardOr: 0 nghĩa là "bằng soft", không phải "vô hạn".
//
// Ranh giới này quan trọng vì hai cách hiểu cho ra hành vi ĐỐI NGƯỢC: một cái
// giữ nguyên hạn mức, cái kia vô hiệu hoá nó hoàn toàn.
func TestHardOrKhongPhaiVoHan(t *testing.T) {
	if got := (contracts.Ulimit{Name: "nofile", Soft: 1024}).HardOr(); got != 1024 {
		t.Errorf("HardOr() với hard=0 = %d, muốn 1024 (bằng soft)", got)
	}
	if got := (contracts.Ulimit{Name: "nofile", Soft: 1024, Hard: 4096}).HardOr(); got != 4096 {
		t.Errorf("HardOr() = %d, muốn 4096", got)
	}
}

// RS-07 — thông báo của ErrUnenforceable phải nói ĐỦ để sửa được.
//
// Nó là thứ duy nhất người vận hành nhìn thấy khi app vào trạng thái error, nên
// nó phải chứa cả tên runtime và tên năng lực thiếu.
func TestThongBaoTuChoiNoiDuNangLucVaRuntime(t *testing.T) {
	r := &contracts.Resources{MemoryMB: 128, DiskMB: 512, IOWriteMBps: 10}
	err := resources.Enforce(r, resources.Caps{resources.CapMemory: true}, "docker")
	if err == nil {
		t.Fatal("Enforce = nil dù thiếu disk_quota và io_bps")
	}
	for _, want := range []string{"docker", "disk_quota", "io_bps"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("thông báo không nói %q: %v", want, err)
		}
	}
	// KHÔNG được nói tới năng lực đã có.
	if strings.Contains(err.Error(), "memory,") || strings.Contains(err.Error(), " memory ") {
		t.Errorf("thông báo nói tới memory dù host có năng lực đó: %v", err)
	}
}
