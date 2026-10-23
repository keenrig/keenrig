// Package sysmetrics — số đo tài nguyên VPS cho `metrics_summary` (OB-05).
//
// # Ba ràng buộc trung thực, mỗi cái chặn một lời nói dối có hình dạng hợp lệ
//
//  1. Chạy TRONG container thì báo TRẦN CGROUP, không phải RAM host —
//     `/proc/meminfo` trong container vẫn hiện RAM của host, nên đọc thẳng nó
//     sẽ báo "còn 3.5 GB trống" đúng lúc box sắp bị OOM kill. Ở đây cgroup v2
//     được hỏi TRƯỚC, meminfo chỉ là đường lui khi không có trần.
//  2. Không đo được thì VẮNG TRƯỜNG, không trả 0 — "0% CPU" và "không đo được
//     CPU" phải là hai màn hình khác nhau. Mọi trường của kết quả là con trỏ,
//     và mọi nhánh lỗi của package này kết thúc bằng nil, không bằng zero.
//  3. Interface ảo của Docker (veth*, br-*, docker0, keenrig0) KHÔNG cộng vào
//     network của VPS — mỗi request gateway→app đi qua veth một lần nữa, cộng
//     cả vào thì một instance không có khách vẫn báo hàng GB.
//
// # Vì sao CPU/network cần HAI lần gọi
//
// Cả hai là counter cộng dồn: một lần đọc chỉ cho "tổng từ lúc boot", không cho
// tốc độ. Collect giữ mẫu trước trong bộ nhớ và trả nil ở lần gọi đầu — đúng
// ràng buộc 2: chưa có gì để so thì nói "chưa đo được", không bịa một số từ
// tổng cộng dồn.
//
// Mọi đường đọc đều đi qua Root (mặc định "/") nên test dựng cây /proc,
// /sys/fs/cgroup giả trong t.TempDir() và chạy được trên mọi OS; chỉ statfs
// (đĩa) là syscall thật, tách ra sau build tag và tiêm được qua DiskUsage.
package sysmetrics

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
)

// Collector gom số đo. Zero value KHÔNG dùng được — tạo bằng New.
type Collector struct {
	root string
	// dataPath — mount point cần đo dung lượng (nơi platform.db + volume sống).
	dataPath string
	// diskUsage tiêm được: statfs thật trên Linux, lỗi "unsupported" nơi khác.
	diskUsage func(path string) (used, total uint64, err error)
	now       func() time.Time

	mu      sync.Mutex
	prevCPU *cpuSample
	prevNet *netSample
}

// Option chỉnh Collector lúc tạo — test dùng để trỏ root vào cây giả.
type Option func(*Collector)

// WithRoot trỏ mọi đường đọc /proc, /sys vào một cây khác (test).
func WithRoot(root string) Option { return func(c *Collector) { c.root = root } }

// WithDiskUsage thay hàm đo đĩa (test, hoặc OS không có statfs).
func WithDiskUsage(f func(string) (uint64, uint64, error)) Option {
	return func(c *Collector) { c.diskUsage = f }
}

// WithNow thay đồng hồ (test tua thời gian cho phép đo tốc độ).
func WithNow(f func() time.Time) Option { return func(c *Collector) { c.now = f } }

// New tạo Collector đo máy thật: root "/", đĩa đo tại dataPath bằng statfs.
func New(dataPath string, opts ...Option) *Collector {
	c := &Collector{
		root:      "/",
		dataPath:  dataPath,
		diskUsage: statfsUsage,
		now:       time.Now,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Collect trả số đo hiện tại. KHÔNG BAO GIỜ trả lỗi: từng phân hệ hỏng thì
// trường tương ứng vắng (ràng buộc 2), heartbeat không được chặn vì một con số.
// Trả nil khi không đo được gì cả — chỗ gọi bỏ hẳn metrics_summary khỏi sync.
func (c *Collector) Collect() *contracts.MetricsSummary {
	c.mu.Lock()
	defer c.mu.Unlock()

	m := &contracts.MetricsSummary{}
	got := false

	if used, total, ok := c.memory(); ok {
		m.MemUsedMB, m.MemTotalMB, got = &used, &total, true
	}
	if pct, ok := c.cpu(); ok {
		m.CPUPct, got = &pct, true
	}
	if rx, tx, ok := c.network(); ok {
		m.NetRxKbps, m.NetTxKbps, got = &rx, &tx, true
	}
	if c.diskUsage != nil && c.dataPath != "" {
		if used, total, err := c.diskUsage(c.dataPath); err == nil && total > 0 {
			u, t := float64(used)/(1<<30), float64(total)/(1<<30)
			m.DiskUsedGB, m.DiskTotalGB, got = &u, &t, true
		}
	}

	if !got {
		return nil
	}
	return m
}

// --- memory -----------------------------------------------------------------------

// memory — cgroup v2 trước, meminfo là đường lui (ràng buộc 1).
func (c *Collector) memory() (usedMB, totalMB float64, ok bool) {
	// Trần cgroup v2: memory.max là "max" nghĩa là KHÔNG có trần → hỏi host.
	maxRaw, err1 := c.read("sys/fs/cgroup/memory.max")
	curRaw, err2 := c.read("sys/fs/cgroup/memory.current")
	if err1 == nil && err2 == nil {
		maxS := strings.TrimSpace(string(maxRaw))
		if maxS != "max" {
			limit, errA := strconv.ParseUint(maxS, 10, 64)
			cur, errB := strconv.ParseUint(strings.TrimSpace(string(curRaw)), 10, 64)
			if errA == nil && errB == nil && limit > 0 {
				return float64(cur) / (1 << 20), float64(limit) / (1 << 20), true
			}
		}
	}

	// /proc/meminfo — đơn vị kB. Thiếu MemAvailable thì KHÔNG suy ra từ
	// MemFree: MemFree không tính page cache, số "đang dùng" sẽ phóng đại và
	// người vận hành sẽ nâng cấp RAM cho một máy không thiếu RAM.
	raw, err := c.read("proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	var totalKB, availKB uint64
	var haveTotal, haveAvail bool
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			if v, err := strconv.ParseUint(f[1], 10, 64); err == nil {
				totalKB, haveTotal = v, true
			}
		case "MemAvailable:":
			if v, err := strconv.ParseUint(f[1], 10, 64); err == nil {
				availKB, haveAvail = v, true
			}
		}
	}
	if !haveTotal || !haveAvail || totalKB == 0 || availKB > totalKB {
		return 0, 0, false
	}
	return float64(totalKB-availKB) / 1024, float64(totalKB) / 1024, true
}

// --- cpu --------------------------------------------------------------------------

type cpuSample struct {
	at time.Time
	// cgroup: usage_usec cộng dồn. host: busy/total jiffy cộng dồn.
	cgUsageUsec uint64
	fromCgroup  bool
	busy, total uint64
	quotaPerSec float64 // usec CPU được phép mỗi giây thật (quota/period × 1e6)
}

// cpu — tỉ lệ dùng so với TRẦN: có quota cgroup thì so với quota, không thì so
// với toàn bộ CPU host. Lần gọi đầu (chưa có mẫu trước) → không đo được.
func (c *Collector) cpu() (pct float64, ok bool) {
	cur, ok := c.cpuSampleNow()
	if !ok {
		return 0, false
	}
	prev := c.prevCPU
	c.prevCPU = cur
	if prev == nil || prev.fromCgroup != cur.fromCgroup {
		return 0, false
	}

	if cur.fromCgroup {
		dt := cur.at.Sub(prev.at).Seconds()
		if dt <= 0 || cur.cgUsageUsec < prev.cgUsageUsec {
			return 0, false
		}
		allowed := cur.quotaPerSec * dt
		if allowed <= 0 {
			return 0, false
		}
		return clampPct(float64(cur.cgUsageUsec-prev.cgUsageUsec) / allowed * 100), true
	}

	dTotal := cur.total - prev.total
	if cur.total < prev.total || dTotal == 0 || cur.busy < prev.busy {
		return 0, false
	}
	return clampPct(float64(cur.busy-prev.busy) / float64(dTotal) * 100), true
}

func (c *Collector) cpuSampleNow() (*cpuSample, bool) {
	// cgroup v2 có quota (cpu.max không phải "max ...") → nguồn sự thật là
	// cpu.stat: /proc/stat trong container vẫn là CPU của HOST (ràng buộc 1,
	// phiên bản CPU).
	if maxRaw, err := c.read("sys/fs/cgroup/cpu.max"); err == nil {
		f := strings.Fields(string(maxRaw))
		if len(f) == 2 && f[0] != "max" {
			quota, errA := strconv.ParseFloat(f[0], 64)
			period, errB := strconv.ParseFloat(f[1], 64)
			if errA == nil && errB == nil && quota > 0 && period > 0 {
				if statRaw, err := c.read("sys/fs/cgroup/cpu.stat"); err == nil {
					for _, line := range strings.Split(string(statRaw), "\n") {
						ff := strings.Fields(line)
						if len(ff) == 2 && ff[0] == "usage_usec" {
							if v, err := strconv.ParseUint(ff[1], 10, 64); err == nil {
								return &cpuSample{
									at: c.now(), fromCgroup: true,
									cgUsageUsec: v,
									quotaPerSec: quota / period * 1e6,
								}, true
							}
						}
					}
				}
			}
		}
	}

	raw, err := c.read("proc/stat")
	if err != nil {
		return nil, false
	}
	line, _, _ := strings.Cut(string(raw), "\n")
	f := strings.Fields(line)
	// "cpu  user nice system idle iowait irq softirq steal ..."
	if len(f) < 8 || f[0] != "cpu" {
		return nil, false
	}
	var vals []uint64
	for _, s := range f[1:] {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, false
		}
		vals = append(vals, v)
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	// busy = total − idle − iowait: iowait là "đang chờ đĩa", tính nó vào CPU
	// thì một máy nghẽn I/O hiện 100% CPU và người ta đi tối ưu nhầm thứ.
	busy := total - vals[3] - vals[4]
	return &cpuSample{at: c.now(), busy: busy, total: total}, true
}

// --- network ----------------------------------------------------------------------

type netSample struct {
	at     time.Time
	rx, tx uint64
}

// virtualIface — ràng buộc 3: đếm những interface này là đếm lại chính lưu
// lượng đã đếm trên interface thật.
func virtualIface(name string) bool {
	if name == "lo" || name == "docker0" || name == "keenrig0" {
		return true
	}
	return strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "br-")
}

func (c *Collector) network() (rxKbps, txKbps float64, ok bool) {
	raw, err := c.read("proc/net/dev")
	if err != nil {
		return 0, 0, false
	}
	var rx, tx uint64
	var seen bool
	for _, line := range strings.Split(string(raw), "\n") {
		name, rest, found := strings.Cut(line, ":")
		if !found {
			continue // hai dòng header không có ':'
		}
		name = strings.TrimSpace(name)
		if virtualIface(name) {
			continue
		}
		f := strings.Fields(rest)
		// cột 1 = rx_bytes, cột 9 = tx_bytes (man 5 proc)
		if len(f) < 9 {
			continue
		}
		r, errA := strconv.ParseUint(f[0], 10, 64)
		t, errB := strconv.ParseUint(f[8], 10, 64)
		if errA != nil || errB != nil {
			continue
		}
		rx += r
		tx += t
		seen = true
	}
	if !seen {
		return 0, 0, false
	}

	cur := &netSample{at: c.now(), rx: rx, tx: tx}
	prev := c.prevNet
	c.prevNet = cur
	if prev == nil {
		return 0, 0, false
	}
	dt := cur.at.Sub(prev.at).Seconds()
	// Counter tụt (interface bị tạo lại) → bỏ lượt này, KHÔNG báo số âm.
	if dt <= 0 || cur.rx < prev.rx || cur.tx < prev.tx {
		return 0, 0, false
	}
	// kbps = kilobit/giây: byte × 8 ÷ 1000 ÷ giây.
	return float64(cur.rx-prev.rx) * 8 / 1000 / dt,
		float64(cur.tx-prev.tx) * 8 / 1000 / dt, true
}

// --- tiện ích ----------------------------------------------------------------------

func (c *Collector) read(rel string) ([]byte, error) {
	return os.ReadFile(filepath.Join(c.root, rel))
}

func clampPct(v float64) float64 {
	// Trên 100 xảy ra thật: jiffy không atomic giữa các CPU, quota burst. Schema
	// từ chối >100, và "100%" là câu trả lời đúng của mọi giá trị vượt trần.
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
