package reconciler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/metrics"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// # Vì sao reconciler phải giành lease — và vì sao NGAY BÂY GIỜ
//
// Trước V2-DELTA chỉ có một tiến trình nên "một reconciler" là hệ quả tự nhiên
// của kiến trúc. Không còn đúng nữa: cửa sổ OTA (drain box cũ → khởi động box
// mới) làm hai tiến trình box chồng nhau vài giây. Hai reconciler cùng lái MỘT
// dockerd thì cả hai cùng thấy app lệch rev, cùng gọi Apply, cùng dựng container
// thay thế cho nhau. Đây là hỏng thật, không phải phòng xa cho nấc 1.
//
// # Số học của TTL — đọc trước khi chỉnh bất kỳ hằng số nào dưới đây
//
// Renew chạy trong CHÍNH goroutine Run, không phải goroutine riêng. Cố ý: một
// goroutine renew chạy song song sẽ gia hạn lease đều đặn ngay cả khi vòng lặp
// chính đã treo cứng trong driver — tức là quảng cáo "tôi còn sống" trong khi
// việc thực tế không tiến triển, đúng thứ lease sinh ra để phát hiện.
//
// Giá phải trả: một lần Apply block sẽ hoãn luôn lần renew kế tiếp. Nên TTL
// phải thoả:
//
//	LeaseTTL  >  renewEvery + thời_gian_block_lâu_nhất_của_một_Apply
//	          >  LeaseTTL/3 + maxApply
//	⟺ LeaseTTL >  1.5 × maxApply
//
// maxApply là của DRIVER CHẬM NHẤT đã biên dịch vào binary, không phải của
// driver đang chạy — người vận hành đổi KEENRIG_RUNTIME mà không restart với
// TTL khác là chuyện bình thường:
//
//	docker waitRunningTimeout  60s
//	swarm  waitRunningTimeout 120s   ← chậm nhất
//	k8s    waitReadyTimeout   180s   ← chậm nhất sau khi thêm k8s
//
//	LeaseTTL 300s > 100s (renew) + 180s (k8s) = 280s, dư 20s biên.
//
// AI ĐỔI TIMEOUT CỦA BẤT KỲ DRIVER NÀO PHẢI ĐỔI CẢ SỐ NÀY — bất đẳng thức vỡ
// thì lease hết hạn giữa lúc Apply đang chạy, box khác nhảy vào, và ta có đúng
// hai chủ mà lease được dựng để chặn. Có test canh: TestLeaseTTLCoversSlowestDriver.
const (
	// DefaultLeaseTTL — hạn của lease reconciler.
	DefaultLeaseTTL = 300 * time.Second
	// leaseRenewFraction — gia hạn khi đã tiêu hết 1/N hạn.
	leaseRenewFraction = 3
	// leaseSafetyFraction — biên an toàn trước hạn (TTL/N). Còn ít hơn biên này
	// thì coi như KHÔNG giữ lease nữa, dù đồng hồ nói vẫn còn: đồng hồ hai máy
	// lệch nhau, và ta thà bỏ một tick còn hơn chạm dockerd lúc không chắc.
	leaseSafetyFraction = 6
)

// DefaultHolder sinh định danh tiến trình cho lease: hostname + pid.
//
// Phải phân biệt được hai TIẾN TRÌNH trên CÙNG máy (đó chính là cửa sổ OTA),
// nên chỉ hostname là không đủ. Hostname lỗi → dùng "unknown", vẫn còn pid để
// phân biệt.
func DefaultHolder() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	return fmt.Sprintf("%s/%d", host, os.Getpid())
}

// leaseState — lease đang giữ, chỉ đọc/ghi từ goroutine Run.
type leaseState struct {
	lease    *store.Lease
	renewAt  time.Time
	lastWarn time.Time
	// heldSince — lúc tiến trình NÀY giành được lease lần này. Không lấy từ
	// store.Lease được: bản ghi đó chỉ có ExpiresAt, và nó được ghi lại mỗi lần
	// gia hạn nên không nói được đã giữ bao lâu.
	heldSince time.Time
}

func (r *Reconciler) leaseTTL() time.Duration {
	if r.opts.LeaseTTL > 0 {
		return r.opts.LeaseTTL
	}
	return DefaultLeaseTTL
}

// holdsLease — CÓ ĐƯỢC PHÉP chạm runtime lúc now không.
//
// Không chỉ là "lease chưa hết hạn": phải còn hơn biên an toàn. Chạy tick khi
// lease còn 1 giây nghĩa là Apply sẽ chạy phần lớn thời gian trong lúc box khác
// đã hợp pháp giành được lease.
func (ls *leaseState) holdsLease(now time.Time, ttl time.Duration) bool {
	if ls.lease == nil {
		return false
	}
	return now.Add(ttl / leaseSafetyFraction).Before(ls.lease.ExpiresAt)
}

// ensureLease giành/gia hạn lease. Trả true khi được phép chạm runtime.
//
// Mọi đường thất bại đều trả false và KHÔNG trả lỗi lên Run: mất lease không
// phải sự cố của tiến trình này — đó là trạng thái bình thường của box thua
// cuộc trong cửa sổ OTA. Nó phải nằm im chờ, không được chết và cũng không
// được làm supervisor recycle module.
func (r *Reconciler) ensureLease(ctx context.Context) bool {
	now := time.Now()
	ttl := r.leaseTTL()

	if r.ls.lease != nil {
		if now.Before(r.ls.renewAt) {
			r.reportLeaseAge(now)
			return r.ls.holdsLease(now, ttl)
		}
		got, err := r.st.RenewLease(ctx, store.LeaseReconciler,
			r.holder(), r.ls.lease.Token, ttl)
		if err == nil {
			r.ls.lease = got
			r.ls.renewAt = now.Add(ttl / leaseRenewFraction)
			// heldSince GIỮ NGUYÊN: gia hạn không phải giành lại. Đặt lại ở đây
			// sẽ làm tuổi lease luôn ~0 và mất hẳn tín hiệu "hai box tranh nhau".
			r.reportLeaseAge(now)
			return true
		}
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
			// Lease đã sang tay người khác (hoặc bị xoá). Buông NGAY, đừng thử
			// giành lại trong cùng lượt: chủ mới vừa nhận thì mình cướp lại chỉ
			// tạo ra cảnh hai bên tranh nhau mỗi tick.
			r.dropLease(ctx, err)
			return false
		}
		// Lỗi store thoáng qua: giữ lease cũ nếu vẫn còn dư biên an toàn, hết
		// biên thì dừng — không đoán mò khi không đọc được sổ sách.
		if ctx.Err() == nil {
			log.Printf("reconciler: renewing the lease failed: %v", err)
		}
		return r.ls.holdsLease(now, ttl)
	}

	got, err := r.st.AcquireLease(ctx, store.LeaseReconciler, r.holder(), ttl)
	if err != nil {
		if !errors.Is(err, store.ErrConflict) && ctx.Err() == nil {
			log.Printf("reconciler: acquiring the lease failed: %v", err)
		} else if errors.Is(err, store.ErrConflict) {
			r.warnLeaseHeld(ctx, now)
		}
		return false
	}
	r.ls.lease = got
	r.ls.renewAt = now.Add(ttl / leaseRenewFraction)
	r.ls.heldSince = now
	r.reportLeaseAge(now)
	r.appendLeaseEvent(ctx, "lease.acquired", got.Token, "")
	log.Printf("reconciler: lease acquired (holder=%s token=%d)", got.Holder, got.Token)
	return true
}

// warnLeaseHeld log "box khác đang giữ lease" tối đa mỗi leaseWarnEvery — nếu
// không, box thua cuộc sẽ đổ log mỗi tick (1s) suốt thời gian chờ.
const leaseWarnEvery = time.Minute

func (r *Reconciler) warnLeaseHeld(ctx context.Context, now time.Time) {
	if now.Sub(r.ls.lastWarn) < leaseWarnEvery {
		return
	}
	r.ls.lastWarn = now
	holder := "?"
	if l, err := r.st.GetLease(ctx, store.LeaseReconciler); err == nil {
		holder = l.Holder
	}
	log.Printf("reconciler: standing by — lease is held by %s", holder)
}

// dropLease buông lease đang giữ trong bộ nhớ (KHÔNG gọi ReleaseLease: lease đã
// là của người khác, xoá đi là cướp mất của chủ mới).
func (r *Reconciler) dropLease(ctx context.Context, cause error) {
	token := int64(0)
	if r.ls.lease != nil {
		token = r.ls.lease.Token
	}
	r.ls.lease = nil
	r.ls.renewAt = time.Time{}
	r.ls.heldSince = time.Time{}
	// Về 0 NGAY khi mất lease. Giữ số cũ sẽ vẽ ra một đường tuổi lease tăng đều
	// trong khi thực tế không ai đang lái vòng hội tụ.
	r.reportLeaseAge(time.Now())
	msg := ""
	if cause != nil {
		msg = cause.Error()
	}
	r.appendLeaseEvent(ctx, "lease.lost", token, msg)
	log.Printf("reconciler: LOST the lease (token=%d): %v — no longer touching the runtime", token, cause)
}

// releaseLease nhả lease lúc dừng sạch. Đây là phần có giá trị vận hành lớn
// nhất của cả cơ chế: box cũ nhả ngay khi drain xong nên box mới vào việc trong
// một tick, thay vì cả hệ thống đứng im chờ hết TTL 120 giây.
//
// Nhận ctx RIÊNG (không phải ctx đã bị huỷ của Run) — nhả lease là việc phải
// làm ĐÚNG LÚC đang tắt, mà ctx của Run lúc đó đã done.
func (r *Reconciler) releaseLease(ctx context.Context) {
	if r.ls.lease == nil {
		return
	}
	l := r.ls.lease
	r.ls.lease = nil
	if err := r.st.ReleaseLease(ctx, store.LeaseReconciler, l.Holder, l.Token); err != nil {
		if !errors.Is(err, store.ErrConflict) && !errors.Is(err, store.ErrNotFound) {
			log.Printf("reconciler: releasing the lease failed: %v", err)
		}
		return
	}
	r.appendLeaseEvent(ctx, "lease.released", l.Token, "")
	log.Printf("reconciler: lease released (token=%d)", l.Token)
}

func (r *Reconciler) holder() string {
	if r.opts.Holder != "" {
		return r.opts.Holder
	}
	return r.defaultHolder
}

func (r *Reconciler) appendLeaseEvent(ctx context.Context, action string, token int64, errMsg string) {
	payload := map[string]any{"holder": r.holder(), "token": token}
	if errMsg != "" {
		payload["error"] = errMsg
	}
	data, _ := json.Marshal(payload)
	if err := r.st.AppendEvent(ctx, action, "reconciler", store.LeaseReconciler, data); err != nil && ctx.Err() == nil {
		log.Printf("reconciler: appending event %s: %v", action, err)
	}
}

// reclaimJobs — LS-03 ở tầng vòng lặp: đưa job của worker đã chết về queued.
//
// Đặt ở reconciler vì nó là thứ DUY NHẤT giữ lease, nên chỉ có một tiến trình
// gọi. Chạy theo nhịp refresh (15s) chứ không theo nhịp tick (1s): đây là một
// câu UPDATE mở transaction ghi, chạy mỗi giây là tiếng ồn thường trực trên
// SQLite mà không đổi lại được gì — worker chết muộn 15 giây không ai chết.
//
// Chuyển về jobs.Worker khi T7 có worker thật.
func (r *Reconciler) reclaimJobs(ctx context.Context) {
	n, err := r.st.ReclaimExpired(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("reconciler: reclaiming expired jobs: %v", err)
		}
		return
	}
	if n > 0 {
		data, _ := json.Marshal(map[string]int{"count": n})
		if err := r.st.AppendEvent(ctx, "jobs.reclaimed", "reconciler", "", data); err != nil && ctx.Err() == nil {
			log.Printf("reconciler: appending event jobs.reclaimed: %v", err)
		}
		log.Printf("reconciler: reclaimed %d job(s) whose lease had expired", n)
	}
}

// reportLeaseAge phơi tuổi lease ra /metrics.
//
// Đặt ở đây chứ không ở chỗ gọi: mọi đường ra/vào của lease đều đi qua file này,
// nên một đường quên cập nhật là một đường vẽ sai biểu đồ.
func (r *Reconciler) reportLeaseAge(now time.Time) {
	if r.ls.heldSince.IsZero() {
		metrics.Default.SetReconcilerLeaseAge(0)
		return
	}
	metrics.Default.SetReconcilerLeaseAge(now.Sub(r.ls.heldSince).Seconds())
}
