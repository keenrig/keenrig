package supervise

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func waitFor(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout %s đợi: %s", timeout, desc)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Panic 2 lần → OnRestart đúng 2 lần với cause chứa panic, test vẫn sống.
func TestPanicRestarts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu     sync.Mutex
		causes []error
	)
	var runs atomic.Int32
	done := make(chan struct{})

	Go(ctx, "boomer", func(ctx context.Context) error {
		n := runs.Add(1)
		if n <= 2 {
			panic(fmt.Sprintf("bùm lần %d", n))
		}
		close(done)
		return nil
	}, Options{
		BackoffBase: 10 * time.Millisecond,
		BackoffCap:  50 * time.Millisecond,
		OnRestart: func(name string, cause error, next time.Duration) {
			mu.Lock()
			causes = append(causes, cause)
			mu.Unlock()
		},
	})

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: fn không được chạy lại sau panic")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(causes) != 2 {
		t.Fatalf("OnRestart gọi %d lần, muốn 2", len(causes))
	}
	for i, c := range causes {
		if c == nil {
			t.Fatalf("cause #%d nil", i)
		}
		if !strings.Contains(c.Error(), "panic") || !strings.Contains(c.Error(), "goroutine") {
			t.Errorf("cause #%d = %.80q..., muốn chứa panic + stack", i, c.Error())
		}
	}
	if got := runs.Load(); got != 3 {
		t.Errorf("fn chạy %d lần, muốn 3 (2 panic + 1 sạch)", got)
	}
}

// fn trả nil → kết thúc sạch, không restart.
func TestCleanExitNoRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var runs, restarts atomic.Int32
	Go(ctx, "oneshot", func(ctx context.Context) error {
		runs.Add(1)
		return nil
	}, Options{
		BackoffBase: 5 * time.Millisecond,
		OnRestart:   func(string, error, time.Duration) { restarts.Add(1) },
	})

	waitFor(t, 2*time.Second, "fn chạy lần đầu", func() bool { return runs.Load() == 1 })
	time.Sleep(50 * time.Millisecond) // đủ nhiều chu kỳ backoff 5ms — không được chạy lại
	if got := runs.Load(); got != 1 {
		t.Errorf("fn chạy %d lần, muốn đúng 1", got)
	}
	if got := restarts.Load(); got != 0 {
		t.Errorf("OnRestart gọi %d lần, muốn 0", got)
	}
}

// BUG-3: Go trả channel done, chỉ ĐÓNG khi goroutine giám sát đã thoát hẳn —
// caller đợi được trước khi đóng tài nguyên dùng chung (vd store).
func TestGoDoneChannel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	release := make(chan struct{})
	var finished atomic.Bool
	done := Go(ctx, "slow", func(ctx context.Context) error {
		<-release
		time.Sleep(20 * time.Millisecond) // mô phỏng SetStatus sau khi Apply xong
		finished.Store(true)
		return nil
	}, Options{BackoffBase: 5 * time.Millisecond})

	// fn còn đang chạy → done PHẢI chưa đóng.
	select {
	case <-done:
		t.Fatal("done đóng trong khi fn còn đang chạy")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("done không đóng sau khi fn kết thúc")
	}
	if !finished.Load() {
		t.Error("done đóng TRƯỚC khi fn chạy xong — đợi kiểu này không chặn được race đóng store")
	}
}

// done cũng phải đóng khi thoát vì ctx bị cancel giữa giấc ngủ backoff.
func TestGoDoneClosesOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := Go(ctx, "failer", func(ctx context.Context) error {
		return errors.New("lỗi cố định")
	}, Options{BackoffBase: 10 * time.Second})

	time.Sleep(50 * time.Millisecond) // để nó vào giấc ngủ backoff dài
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("done không đóng sau khi cancel ctx giữa backoff")
	}
}

// Cancel ctx khi đang ngủ backoff dài → thoát nhanh, không chạy lại.
func TestCancelDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var runs, restarts atomic.Int32
	Go(ctx, "failer", func(ctx context.Context) error {
		runs.Add(1)
		return errors.New("lỗi cố định")
	}, Options{
		BackoffBase: 10 * time.Second, // ngủ RẤT dài — chỉ cancel mới cắt được
		OnRestart:   func(string, error, time.Duration) { restarts.Add(1) },
	})

	waitFor(t, 2*time.Second, "vào backoff sleep (OnRestart lần 1)", func() bool { return restarts.Load() == 1 })
	start := time.Now()
	cancel()
	time.Sleep(100 * time.Millisecond) // cho goroutine cơ hội chạy lại nếu có bug
	if got := runs.Load(); got != 1 {
		t.Errorf("fn chạy %d lần sau cancel, muốn đúng 1 (không restart)", got)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("thoát mất %s — backoff sleep không bị cắt bởi ctx", elapsed)
	}
}
