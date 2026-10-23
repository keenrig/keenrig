// Package supervise — chạy module nền trong goroutine được giám sát
// (luật SOURCE-CODE §2.1.1): panic/lỗi không được kéo sập process,
// module chết thì restart với backoff.
package supervise

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"
)

type Options struct {
	BackoffBase time.Duration // zero → 1s
	BackoffCap  time.Duration // zero → 60s
	// OnRestart được gọi TRƯỚC mỗi lần restart: name module, nguyên nhân
	// (error trả về hoặc panic kèm stack), và thời gian chờ sắp tới.
	OnRestart func(name string, cause error, next time.Duration)
}

// Go chạy fn trong goroutine giám sát:
//   - fn panic (recover, cause kèm debug.Stack) hoặc trả error ≠ nil →
//     OnRestart + ngủ backoff (huỷ được bởi ctx) + chạy lại;
//   - fn trả nil → coi như kết thúc sạch, dừng hẳn;
//   - fn chạy sống ≥ BackoffCap trước khi chết → reset backoff về Base;
//   - ctx done → thoát (kể cả đang giữa giấc ngủ backoff).
//
// Trả channel done, ĐÓNG khi goroutine giám sát đã thoát hẳn. Caller nào có
// tài nguyên dùng chung với fn (vd store.Close) PHẢI đợi channel này sau khi
// cancel ctx, nếu không fn có thể còn đang chạy dở trên tài nguyên đã đóng.
// Bỏ qua giá trị trả về là hợp lệ nếu không cần đợi.
func Go(ctx context.Context, name string, fn func(ctx context.Context) error, opts Options) <-chan struct{} {
	base := opts.BackoffBase
	if base <= 0 {
		base = time.Second
	}
	maxBackoff := opts.BackoffCap
	if maxBackoff <= 0 {
		maxBackoff = 60 * time.Second
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		backoff := base
		for {
			if ctx.Err() != nil {
				return
			}
			started := time.Now()
			err := runOnce(ctx, fn)
			if err == nil {
				return // kết thúc sạch
			}
			if ctx.Err() != nil {
				return // đang shutdown — lỗi do ctx, không restart
			}
			if time.Since(started) >= maxBackoff {
				backoff = base // sống đủ lâu → coi như đã hồi phục, reset backoff
			}
			if opts.OnRestart != nil {
				opts.OnRestart(name, err, backoff)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}()
	return done
}

// runOnce chạy fn và biến panic thành error (kèm stack) thay vì sập process.
func runOnce(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v\n%s", r, debug.Stack())
		}
	}()
	return fn(ctx)
}
