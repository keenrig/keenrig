// Package jobs — worker tiêu thụ hàng đợi việc nền trong SQLite.
//
// # Vì sao gói này tồn tại (và vì sao nó là nợ M1, không phải M2)
//
// `store` đã có EnqueueJob/ClaimJobAs/ReclaimExpired + lease từ T6b, nhưng
// KHÔNG AI tiêu thụ hàng đợi. Mọi thứ dựa vào nó — backup, gia hạn cert, import,
// dọn dẹp — đều không chạy được. SOURCE-CODE §2 xếp `internal/jobs` ở phase M1
// đúng vì lý do đó.
//
// # Hai nguyên tắc
//
//  1. TIẾN ĐỘ LÀ BẮT BUỘC, không phải trang trí. Một job chạy 20 phút mà API
//     chỉ trả "running" thì "đang chạy" và "đã treo" nhìn giống hệt nhau, và
//     người dùng sẽ bấm lại. `SetProgress` là toàn bộ khác biệt giữa hai
//     trạng thái đó.
//
//  2. PHÁT HIỆN CRASH KHI KHỞI ĐỘNG. Job state='running' mà lease đã hết hạn
//     là job mồ côi do tiến trình chết giữa chừng — `store.ReclaimExpired` đưa
//     nó về queued. Chạy MỘT LẦN ngay lúc worker khởi động, không đợi tick
//     đầu, vì đúng lúc vừa restart mới là lúc có job mồ côi.
//
// # Ranh giới
//
// Worker KHÔNG giành lease riêng. Nó chạy trong cùng tiến trình box và mọi
// thao tác nguy hiểm bên trong handler phải tự giành `locks` — lease của
// reconciler bảo vệ vòng hội tụ, `locks` bảo vệ thao tác hữu hạn. Ép worker
// giành lease reconciler sẽ dừng hẳn vòng hội tụ trong suốt mỗi lần backup.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"runtime/debug"
	"sync"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/metrics"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// Kind — tên loại job. Hằng số để không rải chuỗi: gõ sai kind nghĩa là job
// nằm mãi trong hàng đợi mà không handler nào nhận.
const (
	KindBackup    = "backup"
	KindRenewCert = "renew_cert"
	KindImport    = "import"
	KindPurgeApp  = "purge_app"
	KindHousekeep = "housekeep"
)

// Handler xử lý một job. Trả result (có thể nil) hoặc lỗi.
//
// Nhận Progress để báo tiến độ; job không báo tiến độ vẫn hợp lệ, nhưng job
// chạy lâu mà im lặng là thứ người dùng không phân biệt được với treo.
type Handler func(ctx context.Context, job *store.Job, p Progress) (json.RawMessage, error)

// Progress — kênh báo tiến độ về store.
type Progress interface {
	// Set ghi phần trăm (0..100) và một dòng mô tả việc đang làm.
	Set(percent int, message string)
}

type progressFn func(percent int, message string)

func (f progressFn) Set(percent int, message string) { f(percent, message) }

type Options struct {
	// Owner — định danh worker, ghi vào lease_owner. Rỗng → tự sinh.
	Owner string
	// Poll — nhịp hỏi hàng đợi khi rỗng. Zero → 2s.
	//
	// Không dùng nhịp 1s như reconciler: hàng đợi rỗng là trạng thái BÌNH
	// THƯỜNG, và một câu UPDATE mỗi giây suốt đời chỉ để not found gì là
	// tiếng ồn thường trực trên SQLite.
	Poll time.Duration
	// Visibility — hạn giữ job. Zero → store.DefaultJobLease.
	Visibility time.Duration
	// Kinds — chỉ nhận các kind này. Rỗng = mọi kind.
	Kinds []string
	// RetryAfter — chờ bao lâu trước khi thử lại job lỗi. Zero → 30s.
	RetryAfter time.Duration
	// ReclaimEvery — nhịp thu hồi job của worker đã chết. Zero → 1 phút.
	ReclaimEvery time.Duration
}

const (
	defaultPoll         = 2 * time.Second
	defaultRetryAfter   = 30 * time.Second
	defaultReclaimEvery = time.Minute
)

type Worker struct {
	st       store.Store
	opts     Options
	mu       sync.RWMutex
	handlers map[string]Handler
}

func New(st store.Store, opts Options) *Worker {
	if opts.Poll <= 0 {
		opts.Poll = defaultPoll
	}
	if opts.RetryAfter <= 0 {
		opts.RetryAfter = defaultRetryAfter
	}
	if opts.ReclaimEvery <= 0 {
		opts.ReclaimEvery = defaultReclaimEvery
	}
	if opts.Visibility <= 0 {
		opts.Visibility = store.DefaultJobLease
	}
	if opts.Owner == "" {
		opts.Owner = fmt.Sprintf("worker/%d", time.Now().UnixNano())
	}
	return &Worker{st: st, opts: opts, handlers: map[string]Handler{}}
}

func (w *Worker) Owner() string { return w.opts.Owner }

// Register gắn handler cho một kind.
//
// Panic khi trùng: đây là lỗi lúc dựng chương trình. Handler thứ hai ghi đè im
// lặng nghĩa là một nửa số job chạy sai logic và không ai biết.
func (w *Worker) Register(kind string, h Handler) {
	if kind == "" || h == nil {
		panic("jobs: Register requires a non-empty kind and handler")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, dup := w.handlers[kind]; dup {
		panic("jobs: Register called twice for kind " + kind)
	}
	w.handlers[kind] = h
}

func (w *Worker) handlerFor(kind string) Handler {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.handlers[kind]
}

// Enqueue thêm việc vào hàng đợi.
func (w *Worker) Enqueue(ctx context.Context, kind string, args any, notBefore *time.Time) (int64, error) {
	var raw json.RawMessage
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			return 0, err
		}
		raw = b
	}
	return w.st.EnqueueJob(ctx, kind, raw, notBefore)
}

// Run chạy vòng lặp worker tới khi ctx done. Trả nil khi dừng sạch.
//
// KHÔNG trả lỗi khi một job hỏng: job hỏng là chuyện bình thường và đã có
// backoff + attempt. Trả lỗi lên supervisor sẽ recycle worker mỗi lần một job
// lỗi, và mất luôn nhịp poll đang chạy.
func (w *Worker) Run(ctx context.Context) error {
	// Thu hồi NGAY lúc khởi động, không đợi tick: đúng lúc vừa restart mới là
	// lúc có job mồ côi do lần chạy trước chết giữa chừng.
	w.reclaim(ctx)

	poll := time.NewTicker(w.opts.Poll)
	defer poll.Stop()
	reclaim := time.NewTicker(w.opts.ReclaimEvery)
	defer reclaim.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-reclaim.C:
			w.reclaim(ctx)
		case <-poll.C:
			// Chạy hết hàng đợi rồi mới ngủ: nhận đúng một job mỗi nhịp poll
			// nghĩa là 100 job xếp hàng cần 200 giây chỉ để bắt đầu cái cuối.
			for ctx.Err() == nil && w.runOne(ctx) {
			}
		}
	}
}

// runOne nhận và chạy MỘT job. Trả true nếu có job được xử lý.
func (w *Worker) runOne(ctx context.Context) bool {
	job, err := w.st.ClaimJobAs(ctx, w.opts.Kinds, w.opts.Owner, w.opts.Visibility)
	if errors.Is(err, store.ErrNoJob) {
		// Hàng đợi rỗng → độ trễ VỀ 0, không giữ số cũ. Giữ lại thì một đỉnh cũ
		// nằm mãi trên biểu đồ và trông như sự cố đang tiếp diễn.
		metrics.Default.SetJobsQueueLag(0)
		return false
	}
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("jobs: claiming job: %v", err)
		}
		return false
	}

	// Độ trễ hàng đợi = job này đã CHỜ bao lâu trước khi tới lượt. NotBefore là
	// lúc nó đủ điều kiện chạy (job hẹn giờ và job retry đều đặt trường này),
	// nên nó đúng hơn CreatedAt: một job hẹn chạy sau một giờ không phải là một
	// giờ tụt hậu.
	if job.NotBefore != nil {
		if lag := time.Since(*job.NotBefore).Seconds(); lag > 0 {
			metrics.Default.SetJobsQueueLag(lag)
		} else {
			metrics.Default.SetJobsQueueLag(0)
		}
	}

	h := w.handlerFor(job.Kind)
	if h == nil {
		// Không có handler: FAIL NGAY thay vì để job quay lại hàng đợi mãi mãi.
		// Job kind lạ thường là bản box cũ gặp job do bản mới tạo — và một job
		// lặp vô hạn tốn nhiều hơn một job thất bại có ghi lý do.
		w.fail(ctx, job, fmt.Errorf("no handler for kind %q", job.Kind))
		return true
	}

	w.run(ctx, job, h)
	return true
}

// run chạy handler, bọc panic, và LUÔN kết thúc job theo đúng một đường.
func (w *Worker) run(ctx context.Context, job *store.Job, h Handler) {
	prog := progressFn(func(percent int, message string) {
		if err := w.st.SetJobProgress(ctx, job.ID, w.opts.Owner, percent, message); err != nil &&
			!errors.Is(err, store.ErrNotFound) && ctx.Err() == nil {
			// ErrNotFound ở đây nghĩa là job đã bị thu hồi khỏi tay ta (lease
			// hết hạn) — bỏ qua, không phải lỗi đáng báo.
			log.Printf("jobs: writing progress for job %d: %v", job.ID, err)
		}
	})

	result, err := runGuarded(job, h, ctx, prog)

	// Lưới an toàn: job đã kết thúc thì không được còn giữ khoá nào. Có nhả
	// được gì ở đây thì ghi log để người viết handler thấy mà sửa.
	if n, rerr := w.st.ReleaseLocksByHolder(ctx, w.lockHolder(job)); rerr == nil && n > 0 {
		log.Printf("jobs: job %d (%s) left %d lock(s) held — cleaned up", job.ID, job.Kind, n)
	}

	if err != nil {
		w.fail(ctx, job, err)
		return
	}
	if cerr := w.st.CompleteJob(ctx, job.ID, result); cerr != nil && ctx.Err() == nil {
		log.Printf("jobs: completing job %d: %v", job.ID, cerr)
	}
	w.event(ctx, "job.completed", job, nil)
}

// LockHolder — định danh dùng khi handler giành locks. Xuất ra để handler dùng
// ĐÚNG chuỗi này; dùng chuỗi khác thì ReleaseLocksByHolder ở trên không dọn được.
func (w *Worker) LockHolder(job *store.Job) string { return w.lockHolder(job) }

func (w *Worker) lockHolder(job *store.Job) string {
	return fmt.Sprintf("%s/job-%d", w.opts.Owner, job.ID)
}

// runGuarded biến panic của handler thành error.
//
// Không có nó, một handler panic sẽ giết cả tiến trình box — mất luôn control
// API và node API, tức là mất đường chẩn đoán đúng lúc cần nhất.
func runGuarded(job *store.Job, h Handler, ctx context.Context, p Progress) (result json.RawMessage, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("jobs: PANIC in job %d (%s): %v\n%s", job.ID, job.Kind, rec, debug.Stack())
			err = fmt.Errorf("panic: %v", rec)
		}
	}()
	return h(ctx, job, p)
}

func (w *Worker) fail(ctx context.Context, job *store.Job, cause error) {
	if err := w.st.FailJob(ctx, job.ID, cause.Error(), w.opts.RetryAfter); err != nil && ctx.Err() == nil {
		log.Printf("jobs: marking job %d as failed: %v", job.ID, err)
	}
	// attempt+1 vì job trong tay ta là ảnh chụp TRƯỚC khi FailJob tăng bộ đếm.
	last := job.Attempt+1 >= store.MaxJobAttempts
	log.Printf("jobs: job %d (%s) failed (attempt %d/%d%s): %v",
		job.ID, job.Kind, job.Attempt+1, store.MaxJobAttempts, map[bool]string{true: ", NO attempts left"}[last], cause)
	w.event(ctx, "job.failed", job, map[string]any{
		"error": cause.Error(), "attempt": job.Attempt + 1, "final": last,
	})
}

// reclaim thu hồi job của worker đã chết.
func (w *Worker) reclaim(ctx context.Context) {
	n, err := w.st.ReclaimExpired(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("jobs: reclaiming expired jobs: %v", err)
		}
		return
	}
	if n > 0 {
		log.Printf("jobs: reclaimed %d job(s) from a dead worker", n)
		data, _ := json.Marshal(map[string]int{"count": n})
		_ = w.st.AppendEvent(ctx, "jobs.reclaimed", "worker", "", data)
	}
}

func (w *Worker) event(ctx context.Context, action string, job *store.Job, extra map[string]any) {
	payload := map[string]any{"kind": job.Kind, "job_id": job.ID}
	for k, v := range extra {
		payload[k] = v
	}
	data, _ := json.Marshal(payload)
	if err := w.st.AppendEvent(ctx, action, "worker", fmt.Sprint(job.ID), data); err != nil && ctx.Err() == nil {
		log.Printf("jobs: appending event %s: %v", action, err)
	}
}
