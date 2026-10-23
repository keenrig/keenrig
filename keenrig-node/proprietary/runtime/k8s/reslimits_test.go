package k8s

// RT-18 — hạn mức trên Kubernetes: ba thứ map được, năm thứ bị từ chối.
//
// `buildDeployment` là hàm thuần nên không cần cluster. Điều đáng canh nhất ở
// đây là `disk_mb` → `ephemeral-storage`: nó là thông số DUY NHẤT mà k8s thực thi
// bằng cơ chế khác hẳn docker (kubelet EVICT pod thay vì ENOSPC), và cũng là
// thông số dễ bị bỏ quên nhất vì tên hai bên không giống nhau.

import (
	"context"
	"errors"
	"strings"
	"testing"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/resources"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
)

func specWithRes(r *contracts.Resources) runtime.AppSpec {
	return runtime.AppSpec{
		ID: "app-1", Slug: "shop", DesiredRev: 1,
		Desired: contracts.DesiredApp{Image: "nginx:1.27", Resources: r},
	}
}

func limitsOf(t *testing.T, r *contracts.Resources) map[string]string {
	t.Helper()
	dep := buildDeployment(specWithRes(r), "keenrig")
	c := dep.Spec.Template.Spec.Containers[0]
	if c.Resources == nil {
		return nil
	}
	return c.Resources.Limits
}

func TestK8sMapMemoryCPUEphemeralStorage(t *testing.T) {
	lim := limitsOf(t, &contracts.Resources{MemoryMB: 512, CPU: 0.5, DiskMB: 2048, Replicas: 2})
	if lim["memory"] != "512Mi" {
		t.Errorf("limits.memory = %q, muốn 512Mi", lim["memory"])
	}
	if lim["cpu"] != "500m" {
		t.Errorf("limits.cpu = %q, muốn 500m", lim["cpu"])
	}
	if lim["ephemeral-storage"] != "2048Mi" {
		t.Errorf("limits.ephemeral-storage = %q, muốn 2048Mi — disk_mb là trần lớp ghi, "+
			"và ephemeral-storage là tương đương thật của nó trên k8s", lim["ephemeral-storage"])
	}
	// Không có trường lạ: một key k8s không hiểu làm API server từ chối cả
	// Deployment, và lỗi đó nổ lúc Apply chứ không lúc tạo app.
	for k := range lim {
		switch k {
		case "memory", "cpu", "ephemeral-storage":
		default:
			t.Errorf("limits có key lạ %q — API server sẽ từ chối cả Deployment", k)
		}
	}
}

func TestK8sKhongKhaiThiNil(t *testing.T) {
	if lim := limitsOf(t, nil); lim != nil {
		t.Errorf("limits = %v với desired không khai hạn mức, muốn nil", lim)
	}
	if lim := limitsOf(t, &contracts.Resources{Replicas: 3}); lim != nil {
		t.Errorf("limits = %v khi chỉ khai replicas, muốn nil", lim)
	}
}

// Năm thông số pod không khai được phải bị từ chối — mỗi thứ một lý do, xem
// godoc reslimits.go.
func TestK8sTuChoiThuPodKhongKhaiDuoc(t *testing.T) {
	cases := []struct {
		field string
		r     contracts.Resources
		cap   string
	}{
		{"cpu_shares", contracts.Resources{CPUShares: 512}, "cpu_shares"},
		{"pids_limit", contracts.Resources{PidsLimit: 200}, "pids"},
		{"io_write_mbps", contracts.Resources{IOWriteMBps: 10}, "io_bps"},
		{"ulimits", contracts.Resources{Ulimits: []contracts.Ulimit{{Name: "nofile", Soft: 1024}}}, "ulimits"},
		{"shm_size_mb", contracts.Resources{ShmSizeMB: 256}, "shm_size"},
		{"memory_swap_mb", contracts.Resources{MemoryMB: 512, MemorySwapMB: 1024}, "memory_swap"},
	}
	for _, c := range cases {
		t.Run(c.field, func(t *testing.T) {
			err := resources.Enforce(&c.r, resources.ByDriver(Name), Name)
			if err == nil {
				t.Fatalf("k8s NHẬN %s dù pod không khai được — app sẽ chạy không có hạn mức đó", c.field)
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

	ok := &contracts.Resources{MemoryMB: 512, CPU: 1, DiskMB: 1024, Replicas: 2}
	if err := resources.Enforce(ok, resources.ByDriver(Name), Name); err != nil {
		t.Errorf("k8s từ chối hạn mức nó làm được: %v", err)
	}
}

func TestK8sResourceCapsKhopBangTinh(t *testing.T) {
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
