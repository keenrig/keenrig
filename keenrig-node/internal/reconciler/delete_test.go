package reconciler

// Regression BUG-2 (vòng 2b): trước khi sửa, store.DeleteApp xoá thẳng row và
// KHÔNG code path nào gọi runtime.Remove → container mồ côi vĩnh viễn.
// Nay xoá 2 pha: DeleteApp đánh dấu deleted_at → reconciler Remove + PurgeApp.
// Dùng lại helper itg* trong integration_test.go (cùng package).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// TestDeleteAppRemovesContainers — e2e Docker thật: CreateApp → reconciler dựng
// container → DeleteApp → reconciler dọn → 0 container theo label + row bị purge.
func TestDeleteAppRemovesContainers(t *testing.T) {
	drv := itgDriver(t) // skip nếu không có Docker
	cli := itgRawClient(t)
	st := itgOpenStore(t)
	ctx := context.Background()

	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	appID := "whoami-del-" + hex.EncodeToString(b)
	t.Cleanup(func() { // lưới an toàn nếu test fail giữa chừng
		c, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		drv.Remove(c, appID)
	})

	app := &store.App{ID: appID, Slug: appID, Desired: itgDesired(t, nil)}
	if err := st.CreateApp(ctx, app); err != nil {
		t.Fatalf("CreateApp: %v", err)
	}

	itgRun(t, New(st, drv, Options{Interval: 50 * time.Millisecond, RefreshInterval: time.Hour}))

	itgWaitFor(t, 3*time.Minute, "hội tụ rev 1 + container Running", func() bool {
		a, s := itgStatus(t, st, appID)
		if a.AppliedRev != 1 || s.State != contracts.AppStateRunning {
			return false
		}
		items := itgListByLabel(t, cli, appID)
		return len(items) == 1 && items[0].State == container.StateRunning
	})

	// --- Xoá app: pha 1 chỉ đánh dấu, container CHƯA bị dọn ngay ---
	if err := st.DeleteApp(ctx, appID); err != nil {
		t.Fatalf("DeleteApp: %v", err)
	}
	if _, err := st.GetApp(ctx, appID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetApp ngay sau DeleteApp: muốn ErrNotFound (app biến mất với API), nhận %v", err)
	}

	// --- Pha 2: reconciler dọn container rồi purge row ---
	itgWaitFor(t, 3*time.Minute, "reconciler dọn container + purge row", func() bool {
		if len(itgListByLabel(t, cli, appID)) != 0 {
			return false
		}
		pending, err := st.ListAppsPendingDelete(ctx)
		if err != nil {
			t.Fatalf("ListAppsPendingDelete: %v", err)
		}
		return len(pending) == 0
	})

	assertFullyPurged(t, st, appID)
}

// assertFullyPurged — sau khi reconciler dọn xong: không còn app trong store và
// slug đã được giải phóng (row bị DELETE thật, không chỉ đánh dấu).
func assertFullyPurged(t *testing.T, st store.Store, appID string) {
	t.Helper()
	ctx := context.Background()

	if apps, err := st.ListApps(ctx); err != nil || len(apps) != 0 {
		t.Errorf("ListApps sau xoá = (%d app, %v), muốn rỗng", len(apps), err)
	}
	reuse := &store.App{ID: appID + "-v2", Slug: appID, Desired: itgDesired(t, nil)}
	if err := st.CreateApp(ctx, reuse); err != nil {
		t.Errorf("CreateApp dùng lại slug sau khi purge: %v (row chưa được xoá thật?)", err)
	} else if err := st.DeleteApp(ctx, reuse.ID); err != nil {
		t.Errorf("dọn app phụ: %v", err)
	}
	if !hasEvent(t, st, "app.deleted", appID) {
		t.Errorf("thiếu event app.deleted cho %s", appID)
	}
}

// removeFailRuntime — Remove luôn lỗi, để kiểm chứng reconciler KHÔNG purge row
// khi chưa dọn được container (an toàn khi crash / dockerd hỏng).
type removeFailRuntime struct {
	runtime.Runtime
	calls int
}

func (r *removeFailRuntime) Remove(context.Context, string) error {
	r.calls++
	return errors.New("dockerd giả vờ hỏng")
}

// TestDeleteAppKeepsRowWhenRemoveFails — Remove lỗi → row PHẢI còn pending-delete
// (thử lại tick sau), có event app.delete_failed, và KHÔNG bị purge.
func TestDeleteAppKeepsRowWhenRemoveFails(t *testing.T) {
	st := openStore(t) // helper của reconciler_test.go — không cần Docker
	ctx := context.Background()

	app := createApp(t, st, "app-del-fail", "traefik/whoami:v1.10")
	rt := &removeFailRuntime{Runtime: newFakeRuntime()}
	r := New(st, rt, Options{Interval: 10 * time.Millisecond, RefreshInterval: time.Hour,
		BackoffBase: time.Millisecond, BackoffCap: 5 * time.Millisecond})

	if err := st.DeleteApp(ctx, app.ID); err != nil {
		t.Fatalf("DeleteApp: %v", err)
	}

	_, stop := runReconciler(t, r)
	waitFor(t, 5*time.Second, "event app.delete_failed", func() bool {
		return hasEvent(t, st, "app.delete_failed", app.ID)
	})
	stop()

	pending, err := st.ListAppsPendingDelete(ctx)
	if err != nil {
		t.Fatalf("ListAppsPendingDelete: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != app.ID {
		t.Errorf("Remove lỗi nhưng row đã bị purge (pending=%d) — container sẽ thành mồ côi", len(pending))
	}
	if rt.calls == 0 {
		t.Error("reconciler không gọi runtime.Remove khi app bị xoá")
	}
}
