package main

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/jobs"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// Dọn dẹp định kỳ — chạy như MỘT job thay vì nhiều cron riêng.
//
// Vì sao gộp: mỗi việc dưới đây là một câu DELETE mất mili-giây, và tách thành
// năm lịch riêng chỉ tạo ra năm chỗ để quên. Ta chưa có scheduler nên gộp là
// lựa chọn đơn giản đúng.
//
// Audit log giữ 90 ngày: đủ phủ một quý để tra sự cố, mà bảng vẫn nhỏ.
const (
	housekeepEvery   = time.Hour
	eventRetention   = 90 * 24 * time.Hour
	jobRetention     = 7 * 24 * time.Hour
	housekeepJobKind = jobs.KindHousekeep
)

// registerHousekeep gắn handler dọn dẹp.
func registerHousekeep(w *jobs.Worker, st store.Store) {
	w.Register(housekeepJobKind, func(ctx context.Context, _ *store.Job, p jobs.Progress) (json.RawMessage, error) {
		now := time.Now()
		counts := map[string]int{}

		p.Set(20, "prune expired login sessions")
		if n, err := st.PurgeExpiredSessions(ctx); err == nil {
			counts["sessions"] = n
		} else {
			return nil, err
		}

		p.Set(30, "prune expired API tokens")
		if n, err := st.PurgeExpiredAPITokens(ctx); err == nil {
			counts["api_tokens"] = n
		} else {
			return nil, err
		}

		p.Set(40, "prune expired locks")
		if n, err := st.PurgeExpiredLocks(ctx); err == nil {
			counts["locks"] = n
		} else {
			return nil, err
		}

		p.Set(60, "prune finished jobs")
		if n, err := st.PurgeFinishedJobs(ctx, now.Add(-jobRetention)); err == nil {
			counts["jobs"] = n
		} else {
			return nil, err
		}

		// Audit log dọn CUỐI: nếu một bước trên lỗi, ta muốn giữ nguyên audit
		// để còn lần theo được chuyện gì đã xảy ra.
		p.Set(80, "prune old audit log entries")
		if n, err := st.PurgeEvents(ctx, now.Add(-eventRetention)); err == nil {
			counts["events"] = n
		} else {
			return nil, err
		}

		p.Set(100, "xong")
		return json.Marshal(counts)
	})
}

// scheduleHousekeep xếp lịch dọn dẹp theo nhịp cố định.
//
// Chưa dùng cron thật: một nhịp cố định đủ cho mọi việc ở đây (không việc nào
// cần chạy "lúc 2 giờ sáng"). Khi có việc cần giờ cụ thể — backup hằng đêm —
// thì mới thêm scheduler, và lúc đó nó là một package riêng.
func scheduleHousekeep(ctx context.Context, w *jobs.Worker) {
	// Chạy một lần ngay lúc khởi động: box vừa restart thường là box vừa chạy
	// một lần OTA, và đó đúng là lúc có nhiều rác nhất.
	if _, err := w.Enqueue(ctx, housekeepJobKind, nil, nil); err != nil {
		log.Printf("keenrig-box: scheduling housekeeping: %v", err)
	}

	go func() {
		t := time.NewTicker(housekeepEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := w.Enqueue(ctx, housekeepJobKind, nil, nil); err != nil && ctx.Err() == nil {
					log.Printf("keenrig-box: scheduling housekeeping: %v", err)
				}
			}
		}
	}()
}
