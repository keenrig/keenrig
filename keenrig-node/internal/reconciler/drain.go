package reconciler

import (
	"context"
	"log"
	"sync/atomic"
	"time"
)

// T9b — drain/resume cho ota.
//
// # Vì sao cần
//
// ota thay nguyên khối bin/. Cắt ngang giữa một lần Apply nghĩa là container
// rev mới đã dựng nhưng rev cũ chưa gỡ, hoặc ngược lại — và bản box mới khởi
// động sẽ thấy một trạng thái nó không tạo ra. Drain đưa vòng lặp về mốc yên
// tĩnh trước khi ai đó đụng vào đĩa.
//
// # Vì sao dùng atomic chứ không mutex
//
// Drain được gọi từ goroutine của node API, còn cờ được ĐỌC trong vòng lặp
// Run. Đây là hai goroutine thật sự, nên cần đồng bộ. Mutex sẽ buộc vòng lặp
// khoá/mở mỗi tick chỉ để đọc một bit; atomic.Bool nói đúng ý định và không có
// khả năng quên mở khoá trên một đường lỗi.

// drainState — cờ tạm dừng + số việc đang chạy dở.
type drainState struct {
	paused   atomic.Bool
	inFlight atomic.Int32
}

// Paused cho biết vòng lặp có đang tạm dừng không.
func (r *Reconciler) Paused() bool { return r.drain.paused.Load() }

// Drain ngừng nhận việc mới rồi đợi việc đang chạy xong (Lifecycle của nodeapi).
//
// Trả số việc CÒN dở lúc hết timeout. 0 nghĩa là an toàn để thay bin; khác 0
// thì ota PHẢI huỷ update — hợp đồng node.yaml nói rõ như vậy.
//
// Idempotent: gọi lại khi đã drain trả về ngay.
func (r *Reconciler) Drain(ctx context.Context, timeout time.Duration) (int, error) {
	// Đặt cờ TRƯỚC khi đợi. Đảo thứ tự thì trong lúc đợi vòng lặp vẫn nhận
	// việc mới và ta đợi mãi một hàng đợi tự nạp lại.
	first := r.drain.paused.CompareAndSwap(false, true)
	if first {
		log.Printf("reconciler: DRAIN — no longer accepting new work")
	}

	deadline := time.Now().Add(timeout)
	const poll = 50 * time.Millisecond
	for {
		if n := int(r.drain.inFlight.Load()); n == 0 {
			if first {
				log.Printf("reconciler: drained cleanly")
			}
			return 0, nil
		}
		if time.Now().After(deadline) {
			n := int(r.drain.inFlight.Load())
			log.Printf("reconciler: %s elapsed with %d task(s) still running — NOT safe to replace bin/", timeout, n)
			return n, nil
		}
		select {
		case <-ctx.Done():
			return int(r.drain.inFlight.Load()), ctx.Err()
		case <-time.After(poll):
		}
	}
}

// Resume nhận việc trở lại. Idempotent.
//
// ota gọi khi huỷ update giữa chừng. KHÔNG tự động resume theo thời gian: một
// box tự bỏ trạng thái drain trong lúc ota đang thay file là đúng thứ drain
// sinh ra để chặn. Nếu ota chết giữa chừng thì box khởi động lại sẽ tự về
// trạng thái không drain, vì cờ này chỉ nằm trong bộ nhớ.
func (r *Reconciler) Resume() {
	if r.drain.paused.CompareAndSwap(true, false) {
		log.Printf("reconciler: RESUME — accepting work again")
	}
}

// enterWork/leaveWork đánh dấu một đơn vị việc chạm runtime.
func (r *Reconciler) enterWork() { r.drain.inFlight.Add(1) }
func (r *Reconciler) leaveWork() { r.drain.inFlight.Add(-1) }
