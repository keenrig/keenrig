package swarm

// RT-17 — hạn mức trên swarm: map đúng thứ API có, TỪ CHỐI thứ nó không có.
//
// Không cần cluster: `buildSpec` là hàm thuần, và nó là chỗ duy nhất quyết định
// hạn mức nào tới được task. Test cần cluster thật nằm ở swarm_test.go.

import (
	"context"
	"errors"
	"strings"
	"testing"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/resources"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
)

func specWith(r *contracts.Resources) runtime.AppSpec {
	return runtime.AppSpec{
		ID: "app-1", Slug: "shop", DesiredRev: 1,
		Desired: contracts.DesiredApp{Image: "nginx:1.27", Resources: r},
	}
}

func TestSwarmMapDungThuNoDoDuoc(t *testing.T) {
	spec := specWith(&contracts.Resources{
		MemoryMB: 512, MemorySwapMB: 1024, CPU: 1.5, PidsLimit: 200,
		Ulimits:  []contracts.Ulimit{{Name: "nofile", Soft: 1024, Hard: 4096}},
		Replicas: 3,
	})
	svc := buildSpec(spec, 8080)

	res := svc.TaskTemplate.Resources
	if res == nil || res.Limits == nil {
		t.Fatal("Resources.Limits nil — không hạn mức nào tới được task")
	}
	if res.Limits.MemoryBytes != 512<<20 {
		t.Errorf("MemoryBytes = %d, muốn %d", res.Limits.MemoryBytes, int64(512)<<20)
	}
	if res.Limits.NanoCPUs != 15e8 {
		t.Errorf("NanoCPUs = %d, muốn 15e8 (1.5 CPU)", res.Limits.NanoCPUs)
	}
	if res.Limits.Pids != 200 {
		t.Errorf("Pids = %d, muốn 200", res.Limits.Pids)
	}
	// SwapBytes là TỔNG mem+swap, y hệt hợp đồng — không có phép trừ nào.
	if res.SwapBytes == nil || *res.SwapBytes != 1024<<20 {
		t.Errorf("SwapBytes = %v, muốn %d (TỔNG mem+swap)", res.SwapBytes, int64(1024)<<20)
	}

	ul := svc.TaskTemplate.ContainerSpec.Ulimits
	if len(ul) != 1 || ul[0].Name != "nofile" || ul[0].Soft != 1024 || ul[0].Hard != 4096 {
		t.Errorf("Ulimits = %+v, muốn nofile 1024:4096", ul)
	}
}

// Không khai hạn mức → Resources phải là nil, KHÔNG phải struct rỗng.
//
// swarm so sánh spec để quyết định có rolling update hay không; một
// ResourceRequirements rỗng làm mọi lần Apply trông như một thay đổi, tức là
// app bị khởi động lại mỗi 15 giây mà không ai đổi gì.
func TestSwarmKhongKhaiThiNil(t *testing.T) {
	if res := buildSpec(specWith(nil), 8080).TaskTemplate.Resources; res != nil {
		t.Errorf("Resources = %+v với desired không khai hạn mức, muốn nil", res)
	}
	if res := buildSpec(specWith(&contracts.Resources{Replicas: 2}), 8080).TaskTemplate.Resources; res != nil {
		t.Errorf("Resources = %+v khi chỉ khai replicas, muốn nil (replicas không phải hạn mức tài nguyên)", res)
	}
}

// Bốn thông số swarm KHÔNG có chỗ khai phải bị từ chối ở Apply, không im lặng bỏ.
//
// Test này gọi resources.Enforce với đúng bảng năng lực mà Apply dùng, thay vì
// dựng một cluster: chỗ cần canh là QUYẾT ĐỊNH từ chối, và nó nằm trong bảng.
func TestSwarmTuChoiThuKhongCoChoKhai(t *testing.T) {
	cases := []struct {
		field string
		r     contracts.Resources
		cap   string
	}{
		{"disk_mb", contracts.Resources{DiskMB: 512}, "disk_quota"},
		{"io_write_mbps", contracts.Resources{IOWriteMBps: 10}, "io_bps"},
		{"io_read_iops", contracts.Resources{IOReadIOPS: 500}, "io_iops"},
		{"cpu_shares", contracts.Resources{CPUShares: 512}, "cpu_shares"},
		{"shm_size_mb", contracts.Resources{ShmSizeMB: 256}, "shm_size"},
	}
	for _, c := range cases {
		t.Run(c.field, func(t *testing.T) {
			err := resources.Enforce(&c.r, resources.ByDriver(Name), Name)
			if err == nil {
				t.Fatalf("swarm NHẬN %s dù API không có chỗ khai — app sẽ chạy không có hạn mức đó", c.field)
			}
			var unenf *resources.ErrUnenforceable
			if !errors.As(err, &unenf) {
				t.Fatalf("lỗi = %v, muốn *resources.ErrUnenforceable", err)
			}
			if !strings.Contains(err.Error(), c.cap) {
				t.Errorf("thông báo không nói năng lực %q: %v", c.cap, err)
			}
		})
	}

	// Và thứ swarm LÀM ĐƯỢC phải qua.
	ok := &contracts.Resources{MemoryMB: 512, MemorySwapMB: 1024, CPU: 1, PidsLimit: 100,
		Ulimits: []contracts.Ulimit{{Name: "nofile", Soft: 1024}}, Replicas: 2}
	if err := resources.Enforce(ok, resources.ByDriver(Name), Name); err != nil {
		t.Errorf("swarm từ chối hạn mức nó làm được: %v", err)
	}
}

// ResourceCaps phải trả THẲNG bảng tĩnh — hai nguồn sự thật thì lệch được.
func TestSwarmResourceCapsKhopBangTinh(t *testing.T) {
	caps, err := (&Driver{}).ResourceCaps(context.Background())
	if err != nil {
		t.Fatalf("ResourceCaps: %v", err)
	}
	want := resources.ByDriver(Name)
	for _, c := range resources.All() {
		if caps.Has(c) != want.Has(c) {
			t.Errorf("năng lực %q: driver khai %v, bảng tĩnh %v", c, caps.Has(c), want.Has(c))
		}
	}
}
