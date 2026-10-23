package apps_test

// RS-10..RS-13 — admission cho `desired.resources`, đi qua `apps.Create` THẬT.
//
// # Vì sao test này không gọi resources.MissingCaps
//
// `MissingCaps` đã có test riêng (internal/resources) và nó xanh. Cái nó không
// chứng minh được là admission CÓ GỌI nó — và đó đúng là chỗ đã hỏng một lần
// trong lịch sử repo này: `proxy.Check` xanh suốt từ M1 trong khi nhánh WAF chưa
// bao giờ chạy trên đường thật, vì `apps` dựng `proxy.Site` với `Policy` để
// trống (xem godoc admission_test.go). Nên test phải đi qua đúng đường nối:
// `Create` → `validateDesired` → admission.
//
// # Vì sao năng lực lấy từ resources.ByDriver, không viết tay
//
// Một `Caps{}` viết tay khẳng định "nếu runtime không đỡ io thì bị từ chối" —
// đúng nhưng vô dụng, vì nó không nói gì về việc swarm CÓ đỡ io hay không. Lấy
// từ bảng thật làm test đỏ nếu ai đó thêm `CapIOBps` vào swarm.

import (
	"context"
	"errors"
	"strings"
	"testing"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/apps"
	"github.com/keenrig/keenrig/keenrig-node/internal/domains"
	"github.com/keenrig/keenrig/keenrig-node/internal/resources"
)

// serviceOnRuntime dựng service với năng lực của MỘT driver runtime thật.
func serviceOnRuntime(t *testing.T, driver string) *apps.Service {
	t.Helper()
	st := openStore(t)
	return apps.New(st, domains.New(st), apps.Options{ResourceCaps: resources.ByDriver(driver)})
}

func resDesired(r *contracts.Resources) contracts.DesiredApp {
	return contracts.DesiredApp{
		Image:     "ghcr.io/acme/web@sha256:" + strings.Repeat("a", 64),
		Resources: r,
	}
}

// RS-10 — cùng một desired: docker nhận, swarm/k8s từ chối.
//
// Đây là hình dạng đầy đủ nhất của luật, và nó là bản sao có chủ đích của PR-08
// ("WAF trên nginx bị từ chối, đổi nginx-owasp thì cho qua").
func TestResourceAdmissionTheoRuntime(t *testing.T) {
	ctx := context.Background()
	// io throttle: docker có (HostConfig.BlkioDevice*), swarm/k8s không có chỗ khai.
	d := resDesired(&contracts.Resources{MemoryMB: 512, IOWriteMBps: 20})

	t.Run("docker cho qua", func(t *testing.T) {
		app, err := serviceOnRuntime(t, "docker").Create(ctx, apps.CreateInput{
			Slug: "shop", Desired: desiredJSON(t, d),
		})
		if err != nil {
			t.Fatalf("docker từ chối hạn mức nó thực thi được: %v", err)
		}
		if app.ID == "" {
			t.Error("app tạo ra không có ID")
		}
	})

	for _, drv := range []string{"swarm", "k8s"} {
		t.Run(drv+" từ chối", func(t *testing.T) {
			_, err := serviceOnRuntime(t, drv).Create(ctx, apps.CreateInput{
				Slug: "shop", Desired: desiredJSON(t, d),
			})
			if !errors.Is(err, apps.ErrUnsupported) {
				t.Fatalf("= %v, muốn ErrUnsupported — %s không throttle được io, "+
					"nhận app nghĩa là lưu một ý định không bao giờ thực thi", err, drv)
			}
			// Thông báo phải nói TÊN NĂNG LỰC: người dùng có mười một trường
			// trong desired.resources, một lỗi "không hỗ trợ" buộc họ đoán.
			if !strings.Contains(err.Error(), "io_bps") {
				t.Errorf("thông báo không nói năng lực nào thiếu: %v", err)
			}
		})
	}
}

// RS-11 — caps nil (chưa dò được nền tảng) KHÔNG được biến thành "không tạo được app".
//
// Nửa còn lại của sự lạc quan này là `resources.Enforce` ở tầng Apply; test
// RT-15 canh nửa đó.
func TestCapsChuaBietThiVanTaoDuocApp(t *testing.T) {
	st := openStore(t)
	svc := apps.New(st, domains.New(st), apps.Options{}) // ResourceCaps không đặt
	_, err := svc.Create(context.Background(), apps.CreateInput{
		Slug:    "shop",
		Desired: desiredJSON(t, resDesired(&contracts.Resources{MemoryMB: 512, DiskMB: 1024, IOWriteMBps: 20})),
	})
	if err != nil {
		t.Fatalf("app bị từ chối khi chưa biết năng lực runtime: %v — "+
			"nền tảng chưa trả lời được không được thành 'không tạo được app'", err)
	}
}

// RS-12 — luật GIỮA các trường trả 400 (ErrInvalidDesired), không phải 400 kiểu
// "không hỗ trợ".
//
// Phân biệt này quan trọng vì hai lỗi đòi hai hành động khác nhau: một cái sửa
// desired, cái kia đổi runtime.
func TestQuanHeGiuaCacTruongBiChanOAdmission(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		r    contracts.Resources
		want string
	}{
		{"swap dưới memory", contracts.Resources{MemoryMB: 512, MemorySwapMB: 256}, "TOTAL"},
		{"swap không có memory", contracts.Resources{MemorySwapMB: 512}, "needs memory_mb"},
		{"ulimit hard dưới soft", contracts.Resources{
			Ulimits: []contracts.Ulimit{{Name: "nofile", Soft: 4096, Hard: 1024}},
		}, "below soft"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := serviceOnRuntime(t, "docker").Create(ctx, apps.CreateInput{
				Slug: "shop", Desired: desiredJSON(t, resDesired(&c.r)),
			})
			if !errors.Is(err, apps.ErrInvalidDesired) {
				t.Fatalf("= %v, muốn ErrInvalidDesired", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("thông báo không nói lý do (%q): %v", c.want, err)
			}
		})
	}
}

// RS-13 — UpdateDesired cũng phải qua admission, không chỉ Create.
//
// Nếu chỉ Create được canh thì người dùng tạo app không hạn mức rồi PATCH thêm
// `io_write_mbps` là xong — một đường vòng quanh toàn bộ tầng admission.
func TestUpdateDesiredCungQuaAdmission(t *testing.T) {
	ctx := context.Background()
	svc := serviceOnRuntime(t, "k8s")
	app, err := svc.Create(ctx, apps.CreateInput{
		Slug: "shop", Desired: desiredJSON(t, resDesired(&contracts.Resources{MemoryMB: 512})),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err = svc.UpdateDesired(ctx, app.ID,
		desiredJSON(t, resDesired(&contracts.Resources{MemoryMB: 512, PidsLimit: 200})))
	if !errors.Is(err, apps.ErrUnsupported) {
		t.Fatalf("PATCH thêm pids_limit trên k8s = %v, muốn ErrUnsupported — "+
			"nếu không thì admission bị đi vòng qua bằng một lần update", err)
	}
	if !strings.Contains(err.Error(), "pids") {
		t.Errorf("thông báo không nói năng lực nào thiếu: %v", err)
	}
}
