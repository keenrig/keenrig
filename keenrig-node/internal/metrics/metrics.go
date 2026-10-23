// Package metrics — registry số liệu tối giản, phơi theo định dạng text của
// Prometheus.
//
// # Vì sao tự viết thay vì dùng client_golang
//
// Ba binary của instance phải phơi /metrics (Luật 7). client_golang kéo theo
// một cây phụ thuộc lớn hơn cả phần còn lại của keenrig-agent, và ta chỉ cần
// counter/gauge với vài nhãn. Định dạng phơi ra là hợp đồng công khai và rất
// ổn định, nên tự sinh không phải rủi ro. Khi cần histogram/exemplar thì đổi
// sang thư viện thật — chỗ gọi (Inc/Set) giữ nguyên.
//
// An toàn cho goroutine: mọi thao tác đều dưới một mutex. Số liệu ghi thưa
// (mỗi tick), đọc còn thưa hơn (mỗi lần scrape), nên tranh chấp không đáng kể
// và một mutex đơn giản đúng hơn là sharding.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kind — loại metric, đi vào dòng # TYPE.
type Kind string

const (
	KindCounter Kind = "counter"
	KindGauge   Kind = "gauge"
)

type key struct {
	name   string
	labels string // đã tuần tự hoá, sắp xếp — xem labelKey
}

type series struct {
	kind   Kind
	help   string
	labels map[string]string
	value  float64
}

type Registry struct {
	mu   sync.Mutex
	data map[key]*series
}

func NewRegistry() *Registry { return &Registry{data: map[key]*series{}} }

// Default — registry dùng chung cho một tiến trình.
var Default = NewRegistry()

// labelKey tuần tự hoá nhãn theo thứ tự tên.
//
// Sắp xếp là bắt buộc: map trong Go duyệt ngẫu nhiên, nên không sắp thì cùng
// một tập nhãn sẽ cho hai key khác nhau và metric bị tách làm hai series.
func labelKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	names := make([]string, 0, len(labels))
	for k := range labels {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(n)
		b.WriteByte('=')
		b.WriteString(escapeLabel(labels[n]))
	}
	return b.String()
}

// escapeLabel thoát ký tự theo đúng quy tắc phơi của Prometheus.
//
// Không thoát là mở đường cho INJECTION vào chính định dạng phơi: giá trị nhãn
// đến từ tên app hay thông báo lỗi, và một dấu " hay xuống dòng trong đó sẽ
// làm hỏng toàn bộ phần còn lại của trang /metrics.
func escapeLabel(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(v)
}

func (r *Registry) get(name string, kind Kind, help string, labels map[string]string) *series {
	k := key{name: name, labels: labelKey(labels)}
	s := r.data[k]
	if s == nil {
		cp := make(map[string]string, len(labels))
		for lk, lv := range labels {
			cp[lk] = lv
		}
		s = &series{kind: kind, help: help, labels: cp}
		r.data[k] = s
	}
	return s
}

// Inc cộng delta vào counter.
//
// Từ chối delta âm im lặng: counter giảm sẽ làm mọi hàm rate() ở phía
// Prometheus hiểu là "counter reset" và sinh ra một đỉnh giả khổng lồ.
func (r *Registry) Inc(name, help string, labels map[string]string, delta float64) {
	if delta < 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.get(name, KindCounter, help, labels).value += delta
}

// Set đặt giá trị gauge.
func (r *Registry) Set(name, help string, labels map[string]string, v float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.get(name, KindGauge, help, labels).value = v
}

// Gather sinh nội dung /metrics.
//
// Gom theo TÊN và chỉ in # HELP/# TYPE một lần cho mỗi tên — lặp lại là vi
// phạm định dạng phơi và Prometheus sẽ từ chối cả trang.
func (r *Registry) Gather() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	byName := map[string][]*series{}
	names := make([]string, 0, len(r.data))
	for k, s := range r.data {
		if _, seen := byName[k.name]; !seen {
			names = append(names, k.name)
		}
		byName[k.name] = append(byName[k.name], s)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		list := byName[name]
		if list[0].help != "" {
			fmt.Fprintf(&b, "# HELP %s %s\n", name, strings.ReplaceAll(list[0].help, "\n", " "))
		}
		fmt.Fprintf(&b, "# TYPE %s %s\n", name, list[0].kind)
		// Thứ tự ổn định giữa các lần scrape để diff đọc được bằng mắt.
		sort.Slice(list, func(i, j int) bool { return labelKey(list[i].labels) < labelKey(list[j].labels) })
		for _, s := range list {
			b.WriteString(name)
			if len(s.labels) > 0 {
				b.WriteByte('{')
				lnames := make([]string, 0, len(s.labels))
				for k := range s.labels {
					lnames = append(lnames, k)
				}
				sort.Strings(lnames)
				for i, ln := range lnames {
					if i > 0 {
						b.WriteByte(',')
					}
					b.WriteString(ln)
					b.WriteString(`="`)
					b.WriteString(escapeLabel(s.labels[ln]))
					b.WriteByte('"')
				}
				b.WriteByte('}')
			}
			b.WriteByte(' ')
			b.WriteString(formatFloat(s.value))
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// formatFloat in số theo cách Prometheus đọc được: 'g' đủ ngắn mà không mất
// thông tin, và số nguyên không bị in thành 1e+06.
func formatFloat(v float64) string {
	if v == float64(int64(v)) && v < 1e15 && v > -1e15 {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// Handler phơi /metrics.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(r.Gather()))
	})
}

// --- số liệu chung cho mọi tiến trình ------------------------------------------

var startedAt = time.Now()

// SetProcessInfo ghi các metric mà MỌI tiến trình phải có.
//
// keenrig_build_info dùng mẫu "info metric": giá trị luôn 1, thông tin nằm ở
// nhãn. Nhờ vậy version đổi không tạo ra một chuỗi thời gian gãy, và join được
// với metric khác trong PromQL.
func (r *Registry) SetProcessInfo(process, version string) {
	r.Set("keenrig_build_info", "Build information; the value is always 1, read the labels.",
		map[string]string{"process": process, "version": version}, 1)
}

// SetUptime cập nhật thời gian sống. Gọi lúc scrape để giá trị luôn tươi.
func (r *Registry) SetUptime(process string) {
	r.Set("keenrig_uptime_seconds", "Seconds since the process started.",
		map[string]string{"process": process}, time.Since(startedAt).Seconds())
}

// --- ba số liệu BẮT BUỘC của keenrig-box ----------------------------------------
//
// Ba thứ dưới đây không phải "metric nào cũng được": chúng là ba thứ mà KHÔNG CÓ
// thì sự cố chỉ nhìn thấy sau khi khách báo. Mỗi cái canh một vòng lặp đã tồn
// tại nhưng trước đây chạy hoàn toàn trong bóng tối.
//
// Đã trả giá đúng một lần vì thiếu chúng: driver `nginx` chọn được nhưng không
// định tuyến gì, và mỗi 15 giây lại ghi một event lỗi vào platform.db. Không ai
// thấy trong nhiều tháng. Nếu SetProxyApply đã tồn tại,
// `keenrig_proxy_apply_total{result="error"}` tăng đều sẽ tự nói ra ngay từ
// phút đầu.

// SetReconcilerLeaseAge — số giây tiến trình NÀY đã giữ lease reconciler.
//
// 0 nghĩa là không giữ. Đây là chỉ báo trung tâm của cả vòng hội tụ: không ai
// giữ lease thì KHÔNG app nào được deploy, và ngoài chỉ số này thì triệu chứng
// duy nhất là "app cứ ở trạng thái chờ" — thứ trông giống hệt một app đang kéo
// image chậm.
//
// Cảnh báo dựng trên nó không phải "quá cao" mà là **quay về 0 rồi lên lại liên
// tục**: đó là hai box đang tranh lease của nhau.
func (r *Registry) SetReconcilerLeaseAge(seconds float64) {
	r.Set("keenrig_reconciler_lease_age_seconds",
		"Seconds this process has held the reconciler lease; 0 when it holds none.",
		nil, seconds)
}

// SetJobsQueueLag — số giây job vừa nhận đã phải CHỜ trước khi được nhận.
//
// Đo trên job vừa claim chứ không phải "job cũ nhất đang chờ", có chủ đích: cái
// sau cần một câu truy vấn riêng mỗi tick trên đường nóng. Cái này lấy được
// miễn phí từ chính lần claim, và nó trả lời đúng câu người vận hành hỏi —
// "hàng đợi có đang tụt lại không".
//
// Hệ quả phải biết khi đọc biểu đồ: khi hàng đợi RỖNG, giá trị được đặt về 0
// chứ không giữ số cũ. Không làm thế thì một đỉnh cũ sẽ nằm mãi trên biểu đồ và
// trông như sự cố đang tiếp diễn.
func (r *Registry) SetJobsQueueLag(seconds float64) {
	r.Set("keenrig_jobs_queue_lag_seconds",
		"Seconds the most recently claimed job waited in the queue; 0 when the queue is empty.",
		nil, seconds)
}

// Kết quả một lần proxy.Apply, dùng làm nhãn `result`.
const (
	ProxyApplyOK    = "ok"
	ProxyApplyError = "error"
)

// SetProxyApply đếm kết quả Apply THEO DRIVER.
//
// Nhãn `driver` là phần quan trọng: một fleet chạy lẫn caddy và nginx thì tỉ lệ
// lỗi gộp chung sẽ che mất việc MỘT driver hỏng hoàn toàn.
func (r *Registry) SetProxyApply(driver, result string) {
	r.Inc("keenrig_proxy_apply_total",
		"Total proxy Apply calls by driver and result.",
		map[string]string{"driver": driver, "result": result}, 1)
}
