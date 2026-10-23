package docker

// RT-11..RT-15 — hạn mức phần cứng, kiểm trên Docker THẬT.
//
// # Vì sao inspect HostConfig là chưa đủ
//
// `ContainerInspect` trả lại đúng thứ ta vừa gửi đi. Nó chứng minh phép dịch
// `desired.resources` → HostConfig không mất trường nào — có giá trị, nhưng nó
// KHÔNG chứng minh kernel làm gì với những con số đó. Ba loại lỗi sống sót qua
// một test chỉ-inspect:
//
//   - sai đơn vị: `Memory = 64` (byte) thay vì `64<<20` inspect vẫn ra 64, và
//     "khớp kỳ vọng 64" nếu kỳ vọng cũng sai cùng chiều.
//   - sai ngữ nghĩa: `MemorySwap` là TỔNG mem+swap, không phải riêng swap. Hiểu
//     sai thì hạn swap lệch đúng một phép trừ, và không ai nhìn thấy.
//   - bị nhận rồi bỏ: `--storage-opt size` trên snapshotter overlayfs (đo được:
//     nhận, không lỗi, ghi 128 MB vào hạn 64 MB thành công).
//
// Nên bộ này có HAI tầng: tầng một inspect qua driver, tầng hai đọc
// /sys/fs/cgroup TỪ TRONG một container dựng bằng CHÍNH phép dịch đó. Tầng hai
// là tầng nói được câu "kernel đã nhận".

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/client"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/resources"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
)

// probeImage — cần một image CÓ SHELL để đọc /sys/fs/cgroup. testImage
// (traefik/whoami) là binary tĩnh trên scratch, không có shell nào để gọi.
const probeImage = "busybox:1.37"

// fullLimits — một khai báo dùng MỌI thông số, với giá trị chọn để phép dịch sai
// là nhìn thấy được.
//
// # Vì sao swap là 192, không phải 128
//
// Đây là một cái bẫy đã bắt được bằng cách phá code: bản đầu dùng
// memory 64 / swap 128, và khi xoá hẳn dòng gán MemorySwap thì test vẫn XANH.
// Lý do là Docker TỰ đặt swap = 2 × memory khi không khai — đo được:
//
//	docker run --memory=64m busybox cat /sys/fs/cgroup/memory.swap.max
//	→ 67108864   (tức tổng mem+swap = 128 MiB, đúng bằng kỳ vọng cũ)
//
// Nghĩa là kỳ vọng cũ trùng khít MẶC ĐỊNH của Docker, nên nó không phân biệt
// được "code áp đúng" với "code không áp gì". 192 = 3 × memory nằm ngoài mọi
// mặc định, nên chỉ có một cách để nó đúng.
//
// Các giá trị còn lại chọn theo cùng nguyên tắc:
//   - cpu 0.5: không phải số nguyên, nên nhân/chia sai lộ ra ngay.
//   - shm 128 ≠ mặc định 64 của Docker, nên "không áp gì" cũng đỏ.
//   - ulimit core soft=0 hard=0: canh chỗ "0 nghĩa là không đặt" ăn mất trường.
func fullLimits() *contracts.Resources {
	return &contracts.Resources{
		MemoryMB:     64,
		MemorySwapMB: 192,
		CPU:          0.5,
		CPUShares:    512,
		PidsLimit:    100,
		ShmSizeMB:    128,
		Ulimits: []contracts.Ulimit{
			{Name: "nofile", Soft: 1024, Hard: 2048},
			{Name: "core", Soft: 0},
		},
		Replicas: 1,
	}
}

// RT-11 — mọi thông số app khai phải có mặt trong HostConfig thật.
//
// Đi qua driver.Apply, không gọi resourcesOf trực tiếp: chỗ hỏng thường là ĐƯỜNG
// NỐI (createStart quên gọi applyHostLimits), và một test gọi thẳng hàm dịch sẽ
// xanh suốt trong khi không hạn mức nào tới được container. Cùng lý lẽ với
// admission_test.go của PR-08.
func TestResourceLimitsVaoHostConfigThat(t *testing.T) {
	d := newDriver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	spec := testSpec(t)
	spec.Desired.Resources = fullLimits()
	skipUnlessEnforceable(t, d, spec.Desired.Resources)
	cleanupApp(t, d, spec.ID)

	obs, err := d.Apply(ctx, spec)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(obs.ContainerIDs) != 1 {
		t.Fatalf("muốn 1 container, nhận %v", obs.ContainerIDs)
	}
	ins, err := d.cli.ContainerInspect(ctx, obs.ContainerIDs[0], client.ContainerInspectOptions{})
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	hc := ins.Container.HostConfig
	if hc == nil {
		t.Fatal("HostConfig nil")
	}

	if hc.Memory != 64<<20 {
		t.Errorf("Memory = %d, muốn %d (64 MiB)", hc.Memory, int64(64)<<20)
	}
	// 192, không phải 128: xem godoc fullLimits — 128 trùng mặc định 2×memory
	// của Docker, nên nó không phân biệt được "áp đúng" với "không áp gì".
	if hc.MemorySwap != 192<<20 {
		t.Errorf("MemorySwap = %d, muốn %d (192 MiB TỔNG mem+swap)", hc.MemorySwap, int64(192)<<20)
	}
	if hc.NanoCPUs != 5e8 {
		t.Errorf("NanoCPUs = %d, muốn 5e8 (0.5 CPU)", hc.NanoCPUs)
	}
	if hc.CPUShares != 512 {
		t.Errorf("CPUShares = %d, muốn 512", hc.CPUShares)
	}
	if hc.PidsLimit == nil || *hc.PidsLimit != 100 {
		t.Errorf("PidsLimit = %v, muốn 100", hc.PidsLimit)
	}
	if hc.ShmSize != 128<<20 {
		t.Errorf("ShmSize = %d, muốn %d (128 MiB)", hc.ShmSize, int64(128)<<20)
	}
	if hc.RestartPolicy.Name != container.RestartPolicyUnlessStopped {
		t.Errorf("RestartPolicy = %q, muốn unless-stopped", hc.RestartPolicy.Name)
	}

	// Ulimits: cả hai dòng, đúng soft/hard. `core` có Soft=0 Hard=0 — nó phải
	// đi tới container, không bị "0 nghĩa là không đặt" ăn mất.
	got := map[string][2]int64{}
	for _, u := range hc.Ulimits {
		got[u.Name] = [2]int64{u.Soft, u.Hard}
	}
	if v, ok := got["nofile"]; !ok || v != [2]int64{1024, 2048} {
		t.Errorf("ulimit nofile = %v (có=%v), muốn soft 1024 hard 2048", v, ok)
	}
	if v, ok := got["core"]; !ok || v != [2]int64{0, 0} {
		t.Errorf("ulimit core = %v (có=%v), muốn soft 0 hard 0 — hard=0 phải nghĩa là bằng soft, "+
			"không phải 'không đặt'", v, ok)
	}
}

// RT-12 — KERNEL đã nhận, không chỉ API đồng ý.
//
// Đọc /sys/fs/cgroup từ trong một container dựng bằng CHÍNH `resourcesOf` +
// `applyHostLimits` mà đường thật dùng. Đây là tầng duy nhất phát hiện được sai
// đơn vị và sai ngữ nghĩa (xem godoc đầu file).
//
// Giá trị đối chiếu đã đo tay trên Docker 29.4.3 / cgroup v2:
//
//	--memory=64m --memory-swap=128m → memory.max=67108864, memory.swap.max=67108864
//	--cpus=0.5                      → cpu.max="50000 100000"
//	--pids-limit=100                → pids.max=100
func TestKernelThucSuNhanHanMuc(t *testing.T) {
	d := newDriver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if v := cgroupVersion(t, d); v != "2" {
		t.Skipf("host dùng cgroup v%s — kỳ vọng trong test này viết cho cgroup v2", v)
	}

	spec := testSpec(t)
	spec.Desired.Resources = fullLimits()
	skipUnlessEnforceable(t, d, spec.Desired.Resources)

	out := runProbe(ctx, t, d, spec, []string{"sh", "-c",
		"cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.swap.max " +
			"/sys/fs/cgroup/cpu.max /sys/fs/cgroup/pids.max; ulimit -n; " +
			"awk '$2==\"/dev/shm\"{print $3}' /proc/self/mounts >/dev/null; " +
			"df -m /dev/shm | awk 'NR==2{print $2}'"})
	lines := nonEmptyLines(out)
	if len(lines) < 6 {
		t.Fatalf("probe trả %d dòng, muốn 6:\n%s", len(lines), out)
	}

	// memory.max — sai đơn vị (64 thay vì 64 MiB) đỏ ở đây.
	if lines[0] != strconv.Itoa(64<<20) {
		t.Errorf("memory.max = %s, muốn %d — kernel KHÔNG nhận trần RAM 64 MiB", lines[0], 64<<20)
	}
	// memory.swap.max = tổng - mem = 192-64 = 128 MiB.
	//
	// Dòng này canh HAI thứ cùng lúc:
	//   - hiểu sai ngữ nghĩa: nếu ta coi memory_swap_mb là "riêng swap" thì
	//     kernel nhận 192 MiB và dòng này đỏ.
	//   - không áp gì: mặc định của Docker là swap = 2×memory → 64 MiB, cũng đỏ.
	// Với kỳ vọng cũ (swap 128) thì trường hợp thứ hai XANH — xem godoc fullLimits.
	if lines[1] != strconv.Itoa(128<<20) {
		t.Errorf("memory.swap.max = %s, muốn %d.\n"+
			"memory_swap_mb là TỔNG mem+swap (192), nên phần swap kernel nhận là 192-64 = 128 MiB.\n"+
			"Nhận %d MiB nghĩa là Docker đang dùng mặc định 2×memory, tức là trần swap KHÔNG được áp.",
			lines[1], 128<<20, 64)
	}
	// cpu.max = "quota period". 0.5 CPU → quota/period = 0.5.
	if got := lines[2]; got != "50000 100000" {
		q, p, ok := parseCPUMax(got)
		if !ok || q*2 != p {
			t.Errorf("cpu.max = %q, muốn tỉ lệ 0.5 (vd \"50000 100000\")", got)
		}
	}
	if lines[3] != "100" {
		t.Errorf("pids.max = %s, muốn 100 — không có phòng tuyến fork bomb", lines[3])
	}
	if lines[4] != "1024" {
		t.Errorf("ulimit -n trong container = %s, muốn 1024", lines[4])
	}
	// /dev/shm phải là 128 MB, KHÔNG phải mặc định 64 của Docker.
	if shm, err := strconv.Atoi(lines[5]); err != nil || shm < 120 || shm > 136 {
		t.Errorf("/dev/shm = %s MB (lỗi=%v), muốn ~128 — mặc định 64 nghĩa là ShmSize không tới container",
			lines[5], err)
	}
}

// RT-13 — cpu_shares: hợp đồng chỉ hứa THỨ TỰ, và thứ tự đó phải đúng thật.
//
// # Vì sao không khoá một con số
//
// Đo tay: `--cpu-shares=512` cho `cpu.weight=59` trên host này, trong khi công
// thức của runc (`1 + (shares-2)*9999/262142`) cho 20. Phép quy đổi khác nhau
// giữa runc và systemd, nên khoá một con số tuyệt đối là viết một test đỏ trên
// máy người khác vì một lý do không liên quan tới code này.
//
// Thứ hợp đồng hứa được — và người dùng thật sự cần — là: shares lớn hơn thì
// phần CPU lớn hơn. Test đó vẫn có răng: nó đỏ nếu ai đó nối cpu_shares vào một
// trường không phải trọng số, hoặc đảo chiều phép quy đổi.
func TestCPUSharesGiuDungThuTu(t *testing.T) {
	d := newDriver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if v := cgroupVersion(t, d); v != "2" {
		t.Skipf("host dùng cgroup v%s — test này đọc cpu.weight của cgroup v2", v)
	}
	if caps, err := d.ResourceCaps(ctx); err == nil && !caps.Has(resources.CapCPUShares) {
		t.Skip("host không đỡ cpu shares")
	}

	weight := func(shares int) int {
		t.Helper()
		spec := testSpec(t)
		spec.Desired.Resources = &contracts.Resources{CPUShares: shares}
		out := runProbe(ctx, t, d, spec, []string{"cat", "/sys/fs/cgroup/cpu.weight"})
		lines := nonEmptyLines(out)
		if len(lines) == 0 {
			t.Fatalf("không đọc được cpu.weight (shares=%d)", shares)
		}
		w, err := strconv.Atoi(lines[0])
		if err != nil {
			t.Fatalf("cpu.weight = %q: %v", lines[0], err)
		}
		return w
	}

	low, high := weight(256), weight(2048)
	if low >= high {
		t.Errorf("cpu_shares 256 → cpu.weight %d và 2048 → %d: trọng số KHÔNG tăng theo shares.\n"+
			"Hợp đồng chỉ hứa thứ tự, và đây là chỗ thứ tự đó phải đúng.", low, high)
	} else {
		t.Logf("thứ tự đúng: shares 256 → weight %d, shares 2048 → weight %d", low, high)
	}
}

// RT-14 — disk quota: HAI CHIỀU, vì đây là chỗ Docker im lặng.
//
// Luật: năng lực ta khai và sự thật của host phải TRÙNG. Cả hai hướng lệch đều
// là lỗi thật, và mỗi hướng hỏng theo một kiểu khác nhau:
//
//   - khai CÓ mà quota không cắn → ta hứa một hạn mức không tồn tại. Đúng lỗi đã
//     đo được trên snapshotter overlayfs: `--storage-opt size=64m` được nhận, dd
//     ghi 128 MB thành công, df báo cả 1 TB.
//   - khai KHÔNG mà quota có cắn → ta từ chối `disk_mb` trên một host thực thi
//     được nó. Không nguy hiểm, nhưng là một tính năng bị lấy đi trong im lặng.
//
// Test này ĐO chứ không tin: nó ghi quá hạn và xem có bị chặn.
func TestDiskQuotaKhaiDungSuThat(t *testing.T) {
	d := newDriver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	caps, err := d.ResourceCaps(ctx)
	if err != nil {
		t.Fatalf("ResourceCaps: %v", err)
	}
	claimed := caps.Has(resources.CapDiskQuota)

	// Ghi 128 MB vào một container khai hạn 64 MB. Quota thật → dd thất bại.
	spec := testSpec(t)
	spec.Desired.Resources = &contracts.Resources{DiskMB: 64}
	out, runErr := runProbeAllowFail(ctx, t, d, spec, []string{"sh", "-c",
		"dd if=/dev/zero of=/big bs=1M count=128 2>&1; echo EXIT=$?"})
	enforced := runErr != nil || !strings.Contains(out, "EXIT=0")

	t.Logf("storage driver khai disk_quota=%v; ghi 128MB vào hạn 64MB bị chặn=%v\nprobe:\n%s",
		claimed, enforced, strings.TrimSpace(out))

	switch {
	case claimed && !enforced:
		t.Errorf("năng lực khai CÓ disk_quota nhưng ghi 128 MB vào hạn 64 MB THÀNH CÔNG.\n"+
			"Đây đúng là kiểu hỏng im lặng mà package resources tồn tại để chặn: người vận hành\n"+
			"thấy disk_mb trong desired, API trả 201, và app ghi bao nhiêu cũng được.\n"+
			"Sửa quotaSupported() trong reslimits.go cho khớp storage driver thật.\nprobe:\n%s", out)
	case !claimed && enforced:
		t.Errorf("năng lực khai KHÔNG đỡ disk_quota nhưng host THỰC SỰ chặn được.\n"+
			"quotaSupported() quá nghiêm: nó đang lấy đi một hạn mức host làm được,\n"+
			"và app khai disk_mb bị từ chối lúc tạo mà không có lý do thật.\nprobe:\n%s", out)
	default:
		t.Logf("OK — năng lực khai khớp sự thật đo được")
	}
}

// RT-15 — hạn mức không thực thi nổi phải bị TỪ CHỐI, không được áp một nửa.
//
// Dựng một driver có caps thiếu đúng một năng lực rồi Apply. Trước khi có
// resources.Enforce, đường này chạy tới ContainerCreate và Docker vui vẻ nhận —
// app lên "running" mà không có hạn mức người dùng khai.
func TestApplyTuChoiHanMucKhongThucThiNoi(t *testing.T) {
	d := newDriver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	spec := testSpec(t)
	spec.Desired.Resources = &contracts.Resources{MemoryMB: 64, DiskMB: 512}

	// Host này đỡ memory nhưng (giả lập) không đỡ quota lớp ghi.
	d.caps = resources.Caps{resources.CapMemory: true}
	obs, err := d.Apply(ctx, spec)
	if err == nil {
		cleanupApp(t, d, spec.ID)
		t.Fatal("Apply THÀNH CÔNG dù host không thực thi được disk_mb — app chạy không có hạn mức đó")
	}
	var unenf *resources.ErrUnenforceable
	if !errors.As(err, &unenf) {
		t.Fatalf("Apply = %v, muốn *resources.ErrUnenforceable", err)
	}
	if !strings.Contains(err.Error(), "disk_quota") {
		t.Errorf("thông báo không nói năng lực nào thiếu: %v", err)
	}
	if obs.Phase != contracts.AppStateError {
		t.Errorf("Observed.Phase = %q, muốn error", obs.Phase)
	}
	// Và KHÔNG được tạo container nào: từ chối phải là từ chối, không phải
	// "tạo rồi báo lỗi".
	if items := listByLabel(t, rawClient(t), spec.ID); len(items) != 0 {
		t.Errorf("Apply bị từ chối nhưng vẫn tạo %d container", len(items))
	}
}

// RT-16 — dò năng lực phải đọc cờ THẬT của daemon, không đoán.
//
// Kiểm bằng capsFromInfo trên các hình dạng host không thể dựng cùng lúc trên
// một máy: kernel thiếu swap accounting (Debian/Ubuntu mặc định TẮT), storage
// driver không quota, thiếu thiết bị io.
func TestCapsFromInfoDocCoThatCuaDaemon(t *testing.T) {
	full := system.Info{
		MemoryLimit: true, SwapLimit: true, CPUCfsQuota: true,
		CPUShares: true, PidsLimit: true,
		Driver: "overlay2", DriverStatus: [][2]string{{"Backing Filesystem", "xfs"}},
	}

	t.Run("host đầy đủ + thiết bị io", func(t *testing.T) {
		caps := capsFromInfo(full, "/dev/sda")
		for _, c := range resources.All() {
			if !caps.Has(c) {
				t.Errorf("thiếu %q trên một host đỡ mọi thứ", c)
			}
		}
	})

	t.Run("kernel không có swap accounting", func(t *testing.T) {
		info := full
		info.SwapLimit = false
		caps := capsFromInfo(info, "/dev/sda")
		if caps.Has(resources.CapMemorySwap) {
			t.Error("khai memory_swap trên kernel không có swap accounting — " +
				"Docker chỉ CẢNH BÁO rồi chạy tiếp không giới hạn swap, nên app sẽ có một trần không tồn tại")
		}
		if !caps.Has(resources.CapMemory) {
			t.Error("mất luôn năng lực memory — swap và memory là hai cờ khác nhau")
		}
	})

	t.Run("snapshotter overlayfs không có quota", func(t *testing.T) {
		// Chính hình dạng đã đo được: Docker Desktop / containerd snapshotter.
		info := full
		info.Driver = "overlayfs"
		info.DriverStatus = [][2]string{{"driver-type", "io.containerd.snapshotter.v1"}}
		if capsFromInfo(info, "/dev/sda").Has(resources.CapDiskQuota) {
			t.Error("khai disk_quota trên snapshotter overlayfs — đo được: cờ được nhận, không lỗi, " +
				"và container ghi 128 MB vào hạn 64 MB bình thường")
		}
	})

	t.Run("overlay2 trên ext4 không có quota", func(t *testing.T) {
		info := full
		info.DriverStatus = [][2]string{{"Backing Filesystem", "extfs"}}
		if capsFromInfo(info, "").Has(resources.CapDiskQuota) {
			t.Error("khai disk_quota cho overlay2 trên extfs — quota cần xfs bật pquota")
		}
	})

	t.Run("btrfs có quota tự thân", func(t *testing.T) {
		info := full
		info.Driver = "btrfs"
		info.DriverStatus = nil
		if !capsFromInfo(info, "").Has(resources.CapDiskQuota) {
			t.Error("btrfs có quota theo subvolume, phải được khai")
		}
	})

	t.Run("không có thiết bị io", func(t *testing.T) {
		caps := capsFromInfo(full, "")
		if caps.Has(resources.CapIOBps) || caps.Has(resources.CapIOIOPS) {
			t.Error("khai trần io khi không biết thiết bị nào — io.max nhận THEO thiết bị, " +
				"nên resourcesOf sẽ bỏ hai trường đó và hạn mức biến mất trong im lặng")
		}
	})
}

// RT-16b — hai chỗ quyết định về thiết bị io phải NHẤT QUÁN.
//
// `capsFromInfo` khai năng lực io theo việc có thiết bị hay không; `resourcesOf`
// bỏ hai trường io khi không có thiết bị. Lệch nhau nghĩa là: khai có năng lực,
// admission cho qua, rồi phép dịch bỏ trường — hạn mức mất trong im lặng.
func TestNangLucIOKhopVoiPhepDich(t *testing.T) {
	spec := runtime.AppSpec{Desired: contracts.DesiredApp{
		Resources: &contracts.Resources{IOWriteMBps: 10, IOReadIOPS: 500},
	}}
	for _, dev := range []string{"", "/dev/sda"} {
		claimed := capsFromInfo(system.Info{}, dev).Has(resources.CapIOBps)
		res := resourcesOf(spec, dev)
		mapped := len(res.BlkioDeviceWriteBps) > 0
		if claimed != mapped {
			t.Errorf("dev=%q: khai năng lực io_bps=%v nhưng phép dịch áp=%v — hai chỗ lệch nhau",
				dev, claimed, mapped)
		}
	}
	// Và khi có thiết bị, giá trị phải đúng đơn vị: MB/s → byte/s.
	res := resourcesOf(spec, "/dev/sda")
	if len(res.BlkioDeviceWriteBps) != 1 || res.BlkioDeviceWriteBps[0].Rate != 10<<20 {
		t.Errorf("io_write_mbps=10 → %v, muốn rate %d byte/s", res.BlkioDeviceWriteBps, 10<<20)
	}
	if len(res.BlkioDeviceReadIOps) != 1 || res.BlkioDeviceReadIOps[0].Rate != 500 {
		t.Errorf("io_read_iops=500 → %v, muốn rate 500 (KHÔNG nhân với 1 MiB)", res.BlkioDeviceReadIOps)
	}
}

// --- helper -------------------------------------------------------------------

// skipUnlessEnforceable skip khi host này không thực thi được hạn mức trong r.
//
// Skip THAY VÌ fail, nhưng skip có LÝ DO IN RA: một dòng "skip vì thiếu
// pids" nói được rằng test không chạy, còn một test xanh không nói gì.
func skipUnlessEnforceable(t *testing.T, d *Driver, r *contracts.Resources) {
	t.Helper()
	caps, err := d.ResourceCaps(context.Background())
	if err != nil {
		t.Fatalf("ResourceCaps: %v", err)
	}
	if missing := resources.MissingCaps(r, caps); len(missing) > 0 {
		t.Skipf("host không thực thi được %v — skip", resources.Names(missing))
	}
}

func cgroupVersion(t *testing.T, d *Driver) string {
	t.Helper()
	res, err := d.cli.Info(context.Background(), client.InfoOptions{})
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if v := res.Info.CgroupVersion; v != "" {
		return v
	}
	return "1"
}

// runProbe dựng MỘT container chạy tới khi xong, bằng chính phép dịch hạn mức của
// đường thật, rồi trả về stdout của nó.
//
// # Vì sao không dùng driver.Apply
//
// Apply block tới khi container Running và ổn định; một container `cat` rồi thoát
// không bao giờ đạt trạng thái đó. Nên ta gọi ContainerCreate trực tiếp — nhưng
// HostConfig thì dựng bằng `resourcesOf` + `applyHostLimits`, đúng hai hàm mà
// createStart dùng. Nếu ai đó sửa phép dịch, test này đổi theo; nếu ai đó thêm
// một hạn mức mà quên gọi applyHostLimits ở đường thật thì RT-11 đỏ.
func runProbe(ctx context.Context, t *testing.T, d *Driver, spec runtime.AppSpec, cmd []string) string {
	t.Helper()
	out, err := runProbeAllowFail(ctx, t, d, spec, cmd)
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, out)
	}
	return out
}

func runProbeAllowFail(ctx context.Context, t *testing.T, d *Driver, spec runtime.AppSpec, cmd []string) (string, error) {
	t.Helper()
	if err := d.ensureImage(ctx, probeImage); err != nil {
		t.Fatalf("pull %s: %v", probeImage, err)
	}
	hostCfg := &container.HostConfig{Resources: resourcesOf(spec, d.ioDev())}
	applyHostLimits(hostCfg, spec)

	created, err := d.cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config:     &container.Config{Image: probeImage, Cmd: cmd},
		HostConfig: hostCfg,
		NetworkingConfig: &network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{networkName: {}},
		},
	})
	if err != nil {
		return "", fmt.Errorf("ContainerCreate: %w", err)
	}
	id := created.ID
	defer func() {
		_, _ = d.cli.ContainerRemove(context.Background(), id, client.ContainerRemoveOptions{Force: true})
	}()

	// ContainerWait TRƯỚC Start, đúng thứ tự moby khuyến nghị: gọi sau Start là
	// một cửa sổ đua mà container ngắn (probe chỉ `cat` rồi thoát) thắng thường
	// xuyên — lúc đó wait treo tới hết ctx thay vì trả exit code.
	wait := d.cli.ContainerWait(ctx, id, client.ContainerWaitOptions{
		Condition: container.WaitConditionNextExit,
	})
	if _, err := d.cli.ContainerStart(ctx, id, client.ContainerStartOptions{}); err != nil {
		return "", fmt.Errorf("ContainerStart: %w", err)
	}
	select {
	case werr := <-wait.Error:
		return "", fmt.Errorf("ContainerWait: %w", werr)
	case <-wait.Result:
	case <-ctx.Done():
		return "", fmt.Errorf("probe không thoát: %w", ctx.Err())
	}
	logs, err := d.cli.ContainerLogs(ctx, id, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return "", fmt.Errorf("ContainerLogs: %w", err)
	}
	defer logs.Close()
	raw, err := io.ReadAll(logs)
	if err != nil {
		return "", fmt.Errorf("đọc log: %w", err)
	}
	return stripDockerLogFraming(raw), nil
}

// stripDockerLogFraming bỏ 8 byte header của giao thức multiplexed log.
//
// Container không có TTY nên mỗi frame log mang header
// [stream(1) 0 0 0 size(4)]; đọc thô sẽ dính byte điều khiển vào đầu dòng và
// mọi phép so sánh chuỗi sau đó sai một cách khó hiểu.
func stripDockerLogFraming(raw []byte) string {
	var sb strings.Builder
	for len(raw) >= 8 {
		size := int(raw[4])<<24 | int(raw[5])<<16 | int(raw[6])<<8 | int(raw[7])
		if size < 0 || 8+size > len(raw) {
			break
		}
		sb.Write(raw[8 : 8+size])
		raw = raw[8+size:]
	}
	if sb.Len() == 0 {
		return string(raw) // stream có TTY: không có framing
	}
	return sb.String()
}

func nonEmptyLines(s string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			out = append(out, line)
		}
	}
	return out
}

func parseCPUMax(s string) (quota, period int, ok bool) {
	parts := strings.Fields(s)
	if len(parts) != 2 {
		return 0, 0, false
	}
	q, err1 := strconv.Atoi(parts[0])
	p, err2 := strconv.Atoi(parts[1])
	return q, p, err1 == nil && err2 == nil
}
