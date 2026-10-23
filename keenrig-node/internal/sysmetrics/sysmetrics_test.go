package sysmetrics

// OB-05 — mỗi ràng buộc trung thực một ca, và mỗi ca dựng đúng tình huống mà
// con số nói dối sẽ có hình dạng hợp lệ:
//
//   - container 4 GB trên host 32 GB: đọc meminfo là báo thừa 28 GB
//   - nguồn đo hỏng: trả 0 là biến "không biết" thành "đang rảnh"
//   - veth cộng vào: instance không khách vẫn báo hàng GB
//
// Cây /proc, /sys/fs/cgroup là THẬT về hình dạng (đúng format từng file) nhưng
// dựng trong t.TempDir() — package đọc qua root tiêm được nên bộ này chạy trên
// mọi OS, kể cả máy dev Windows.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
)

// tree ghi một cây file giả; key là đường dẫn tương đối kiểu slash.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const memHost32G = "MemTotal:       33554432 kB\nMemFree:         4194304 kB\nMemAvailable:   16777216 kB\n"

// Ràng buộc 1 — TRONG container phải báo trần cgroup, không phải RAM host.
func TestMemoryPrefersCgroupCeilingOverHostMeminfo(t *testing.T) {
	root := tree(t, map[string]string{
		"proc/meminfo":                 memHost32G,     // host: 32 GB
		"sys/fs/cgroup/memory.max":     "4294967296\n", // trần container: 4 GB
		"sys/fs/cgroup/memory.current": "2254857830\n", // ~2150 MB đang dùng
	})
	c := New("", WithRoot(root), WithDiskUsage(nil))
	m := c.Collect()
	if m == nil || m.MemTotalMB == nil || m.MemUsedMB == nil {
		t.Fatalf("muốn có RAM, nhận %+v", m)
	}
	if *m.MemTotalMB != 4096 {
		t.Fatalf("tổng RAM phải là TRẦN CGROUP 4096 MB, nhận %v — đây chính là ca "+
			"'còn 3.5 GB trống' ngay trước OOM kill", *m.MemTotalMB)
	}
	if got := *m.MemUsedMB; got < 2149 || got > 2151 {
		t.Fatalf("mem_used_mb = %v, muốn ~2150", got)
	}
}

// memory.max = "max" nghĩa là KHÔNG có trần → meminfo là câu trả lời đúng.
func TestMemoryFallsBackToMeminfoWhenNoCeiling(t *testing.T) {
	root := tree(t, map[string]string{
		"proc/meminfo":                 memHost32G,
		"sys/fs/cgroup/memory.max":     "max\n",
		"sys/fs/cgroup/memory.current": "123\n",
	})
	m := New("", WithRoot(root), WithDiskUsage(nil)).Collect()
	if m == nil || m.MemTotalMB == nil {
		t.Fatal("muốn có RAM từ meminfo")
	}
	if *m.MemTotalMB != 32768 {
		t.Fatalf("mem_total_mb = %v, muốn 32768", *m.MemTotalMB)
	}
	// used = total − available = (33554432 − 16777216) kB = 16384 MB
	if *m.MemUsedMB != 16384 {
		t.Fatalf("mem_used_mb = %v, muốn 16384", *m.MemUsedMB)
	}
}

// Ràng buộc 2 — không đo được thì VẮNG trường, không phải 0. Ba tình huống:
// meminfo thiếu MemAvailable, /proc/stat không đọc được, lần đo CPU đầu tiên.
func TestAbsentNotZero(t *testing.T) {
	t.Run("meminfo thiếu MemAvailable", func(t *testing.T) {
		root := tree(t, map[string]string{
			"proc/meminfo": "MemTotal: 1024 kB\nMemFree: 512 kB\n",
		})
		m := New("", WithRoot(root), WithDiskUsage(nil)).Collect()
		if m != nil && (m.MemUsedMB != nil || m.MemTotalMB != nil) {
			t.Fatalf("RAM phải VẮNG khi thiếu MemAvailable (MemFree không phải nó), nhận %+v", m)
		}
	})

	t.Run("không có nguồn nào", func(t *testing.T) {
		m := New("", WithRoot(t.TempDir()), WithDiskUsage(nil)).Collect()
		if m != nil {
			t.Fatalf("không đo được gì thì summary phải là nil, nhận %+v", m)
		}
	})

	t.Run("CPU lần đo đầu — counter cộng dồn chưa có gì để so", func(t *testing.T) {
		root := tree(t, map[string]string{
			"proc/stat": "cpu  100 0 100 800 0 0 0 0\n",
		})
		m := New("", WithRoot(root), WithDiskUsage(nil)).Collect()
		if m != nil && m.CPUPct != nil {
			t.Fatalf("cpu_pct lần đầu phải VẮNG, nhận %v", *m.CPUPct)
		}
	})
}

// CPU host: hai mẫu /proc/stat cách nhau, pct = Δbusy/Δtotal.
func TestCPUFromProcStatDelta(t *testing.T) {
	root := tree(t, map[string]string{
		"proc/stat": "cpu  100 0 100 800 0 0 0 0\n", // busy 200, total 1000
	})
	now := time.Unix(1000, 0)
	c := New("", WithRoot(root), WithDiskUsage(nil), WithNow(func() time.Time { return now }))
	c.Collect() // mồi mẫu đầu

	// +30 giây: busy tăng 340, total tăng 1000 → 34%.
	if err := os.WriteFile(filepath.Join(root, "proc", "stat"),
		[]byte("cpu  300 0 240 1460 0 0 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Second)
	m := c.Collect()
	if m == nil || m.CPUPct == nil {
		t.Fatal("muốn có cpu_pct ở lần đo thứ hai")
	}
	if *m.CPUPct != 34 {
		t.Fatalf("cpu_pct = %v, muốn 34", *m.CPUPct)
	}
}

// Ràng buộc 1, phiên bản CPU: có quota cgroup thì đo so với QUOTA — /proc/stat
// trong container là CPU của host.
func TestCPUPrefersCgroupQuota(t *testing.T) {
	root := tree(t, map[string]string{
		"proc/stat":              "cpu  100 0 100 800 0 0 0 0\n",
		"sys/fs/cgroup/cpu.max":  "200000 100000\n", // 2 CPU
		"sys/fs/cgroup/cpu.stat": "usage_usec 1000000\nuser_usec 0\nsystem_usec 0\n",
	})
	now := time.Unix(2000, 0)
	c := New("", WithRoot(root), WithDiskUsage(nil), WithNow(func() time.Time { return now }))
	c.Collect()

	// +10s, dùng thêm 5_000_000 usec trên quota 2 CPU (được phép 20_000_000) → 25%.
	if err := os.WriteFile(filepath.Join(root, "sys", "fs", "cgroup", "cpu.stat"),
		[]byte("usage_usec 6000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Second)
	m := c.Collect()
	if m == nil || m.CPUPct == nil {
		t.Fatal("muốn có cpu_pct từ cgroup")
	}
	if *m.CPUPct != 25 {
		t.Fatalf("cpu_pct = %v, muốn 25 (so với quota, không phải so với host)", *m.CPUPct)
	}
}

// Ràng buộc 3 — veth/br-/docker0/keenrig0/lo không được cộng vào network.
func TestNetworkExcludesVirtualInterfaces(t *testing.T) {
	header := "Inter-|   Receive                                                |  Transmit\n" +
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
	dev1 := header +
		"    lo:  999999    100    0    0    0     0          0         0   999999    100    0    0    0     0       0          0\n" +
		"  eth0:  100000    100    0    0    0     0          0         0    50000     50    0    0    0     0       0          0\n" +
		"vethab12:  777777    77    0    0    0     0          0         0   777777    77    0    0    0     0       0          0\n" +
		"br-99aa:  888888    88    0    0    0     0          0         0   888888    88    0    0    0     0       0          0\n" +
		"docker0:  555555    55    0    0    0     0          0         0   555555    55    0    0    0     0       0          0\n" +
		"keenrig0:  444444    44    0    0    0     0          0         0   444444    44    0    0    0     0       0          0\n"
	// +10 giây: eth0 nhận thêm 125000 byte (=100 kbps), gửi thêm 25000 (=20 kbps);
	// các interface ảo tăng VŨ BÃO — đúng hình dạng lưu lượng gateway→app.
	dev2 := header +
		"    lo: 9999999   1000    0    0    0     0          0         0  9999999   1000    0    0    0     0       0          0\n" +
		"  eth0:  225000    200    0    0    0     0          0         0    75000    100    0    0    0     0       0          0\n" +
		"vethab12: 99777777  777    0    0    0     0          0         0 99777777  777    0    0    0     0       0          0\n" +
		"br-99aa: 99888888  888    0    0    0     0          0         0 99888888  888    0    0    0     0       0          0\n" +
		"docker0: 99555555  555    0    0    0     0          0         0 99555555  555    0    0    0     0       0          0\n" +
		"keenrig0: 99444444  444    0    0    0     0          0         0 99444444  444    0    0    0     0       0          0\n"

	root := tree(t, map[string]string{"proc/net/dev": dev1})
	now := time.Unix(3000, 0)
	c := New("", WithRoot(root), WithDiskUsage(nil), WithNow(func() time.Time { return now }))
	c.Collect()

	if err := os.WriteFile(filepath.Join(root, "proc", "net", "dev"), []byte(dev2), 0o644); err != nil {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Second)
	m := c.Collect()
	if m == nil || m.NetRxKbps == nil || m.NetTxKbps == nil {
		t.Fatal("muốn có số network ở lần đo thứ hai")
	}
	if *m.NetRxKbps != 100 || *m.NetTxKbps != 20 {
		t.Fatalf("rx/tx = %v/%v kbps, muốn 100/20 — interface ảo đã bị cộng vào", *m.NetRxKbps, *m.NetTxKbps)
	}
}

// Đĩa qua hàm tiêm: 18/80 GB — đúng ô Disk của wireframe S4.
func TestDiskFromInjectedStatfs(t *testing.T) {
	c := New("/data", WithRoot(t.TempDir()), WithDiskUsage(func(path string) (uint64, uint64, error) {
		if path != "/data" {
			t.Fatalf("đo sai chỗ: %s", path)
		}
		return 18 << 30, 80 << 30, nil
	}))
	m := c.Collect()
	if m == nil || m.DiskUsedGB == nil || m.DiskTotalGB == nil {
		t.Fatal("muốn có số đĩa")
	}
	if *m.DiskUsedGB != 18 || *m.DiskTotalGB != 80 {
		t.Fatalf("disk = %v/%v GB, muốn 18/80", *m.DiskUsedGB, *m.DiskTotalGB)
	}
}

// Đầu ra của Collect phải HỢP LỆ theo chính schema OB-06 — hai gate này là một
// hợp đồng nhìn từ hai phía, và đây là mối nối giữa chúng.
func TestCollectOutputSatisfiesSchema(t *testing.T) {
	root := tree(t, map[string]string{
		"proc/meminfo":                 memHost32G,
		"sys/fs/cgroup/memory.max":     "4294967296\n",
		"sys/fs/cgroup/memory.current": "2254857830\n",
	})
	m := New("", WithRoot(root), WithDiskUsage(func(string) (uint64, uint64, error) {
		return 18 << 30, 80 << 30, nil
	})).Collect()
	if m == nil {
		t.Fatal("muốn có summary")
	}
	doc, err := jsonMarshalSyncRequest(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.ValidateSyncRequest(doc); err != nil {
		t.Fatalf("đầu ra của Collect không qua được schema OB-06: %v\n%s", err, doc)
	}
}

// jsonMarshalSyncRequest bọc summary vào một SyncRequest tối thiểu — validator
// chỉ có cửa vào ở tầng đó, đúng như trên dây.
func jsonMarshalSyncRequest(m *contracts.MetricsSummary) ([]byte, error) {
	return json.Marshal(contracts.SyncRequest{
		EnvID:          "e1",
		Version:        "0.0.0-test",
		Heartbeat:      contracts.Heartbeat{TS: time.Unix(0, 0).UTC()},
		MetricsSummary: m,
	})
}
