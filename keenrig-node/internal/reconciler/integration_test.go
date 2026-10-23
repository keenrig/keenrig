package reconciler

// Integration T6 — reconciler + driver docker THẬT (không fake).
// Docker không chạy → t.Skip (không Fail).
//
// File này cố ý TỰ CHỨA helper (tên có tiền tố itg*) để không phụ thuộc
// helper của reconciler_test.go.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/runtime/driver/docker"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// itgLabelAppID lặp lại const của package docker (unexported bên đó) — kiểm
// chứng bằng client thô, độc lập driver.
const itgLabelAppID = "keenrig.com.id"

const itgImage = "traefik/whoami:v1.10"

func itgDriver(t *testing.T) *docker.Driver {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d, err := docker.New(ctx)
	if err != nil {
		t.Skipf("Docker không khả dụng — skip: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func itgRawClient(t *testing.T) *client.Client {
	t.Helper()
	cli, err := client.New(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("raw client: %v", err)
	}
	t.Cleanup(func() { cli.Close() })
	return cli
}

func itgOpenStore(t *testing.T) store.Store {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// itgStatus trả app + status đã giải mã.
func itgStatus(t *testing.T, st store.Store, id string) (*store.App, contracts.AppStatus) {
	t.Helper()
	app, err := st.GetApp(context.Background(), id)
	if err != nil {
		t.Fatalf("GetApp: %v", err)
	}
	var s contracts.AppStatus
	if len(app.Status) > 0 {
		if err := json.Unmarshal(app.Status, &s); err != nil {
			t.Fatalf("unmarshal status %q: %v", app.Status, err)
		}
	}
	return app, s
}

func itgWaitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("quá %s vẫn chưa: %s", timeout, what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// itgRun chạy Run trong goroutine, trả stop() đợi thoát sạch (gọi nhiều lần OK).
func itgRun(t *testing.T, r *Reconciler) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := r.Run(ctx); err != nil {
			t.Errorf("Run trả lỗi: %v", err)
		}
	}()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("Run không thoát sau khi cancel ctx")
		}
	}
	t.Cleanup(stop)
	return stop
}

func itgListByLabel(t *testing.T, cli *client.Client, appID string) []container.Summary {
	t.Helper()
	res, err := cli.ContainerList(context.Background(), client.ContainerListOptions{
		All:     true,
		Filters: make(client.Filters).Add("label", itgLabelAppID+"="+appID),
	})
	if err != nil {
		t.Fatalf("ContainerList theo label: %v", err)
	}
	return res.Items
}

func itgDesired(t *testing.T, env map[string]string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(contracts.DesiredApp{Image: itgImage, Env: env})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RC-01..03 e2e: hội tụ thật trên Docker; cắt reconciler giữa lúc rolling rev 2
// → instance MỚI hội tụ tiếp, không để lại container thừa.
func TestEndToEndDocker(t *testing.T) {
	drv := itgDriver(t)
	cli := itgRawClient(t)
	st := itgOpenStore(t)

	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	appID := "whoami-" + hex.EncodeToString(b)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := drv.Remove(ctx, appID); err != nil {
			t.Errorf("cleanup Remove(%s): %v", appID, err)
		}
	})

	app := &store.App{ID: appID, Slug: appID, Desired: itgDesired(t, map[string]string{"WHOAMI_NAME": "rev1"})}
	if err := st.CreateApp(context.Background(), app); err != nil {
		t.Fatalf("CreateApp: %v", err)
	}

	opts := Options{Interval: 50 * time.Millisecond, RefreshInterval: time.Hour}
	stop1 := itgRun(t, New(st, drv, opts))

	// Hội tụ rev 1: store ghi applied_rev=1 VÀ container thật đang Running.
	itgWaitFor(t, 3*time.Minute, "hội tụ rev 1 + container Running", func() bool {
		a, s := itgStatus(t, st, appID)
		if a.AppliedRev != 1 || s.State != contracts.AppStateRunning {
			return false
		}
		items := itgListByLabel(t, cli, appID)
		return len(items) == 1 && items[0].State == container.StateRunning
	})

	// Rev 2: đổi env → rolling. Cắt reconciler giữa chừng (~200ms).
	rev, err := st.UpdateDesired(context.Background(), appID, itgDesired(t, map[string]string{"WHOAMI_NAME": "rev2"}))
	if err != nil {
		t.Fatalf("UpdateDesired: %v", err)
	}
	if rev != 2 {
		t.Fatalf("UpdateDesired trả rev %d, muốn 2", rev)
	}
	time.Sleep(200 * time.Millisecond)
	stop1()

	// Instance MỚI trên cùng store phải hội tụ nốt rev 2.
	itgRun(t, New(st, drv, opts))

	itgWaitFor(t, 3*time.Minute, "hội tụ rev 2 sau khi cắt ngang", func() bool {
		a, s := itgStatus(t, st, appID)
		return a.AppliedRev == 2 && a.DesiredRev == 2 && s.State == contracts.AppStateRunning
	})

	// Không nhân đôi: đúng 1 container, đang chạy (rev cũ đã bị dọn).
	items := itgListByLabel(t, cli, appID)
	if len(items) != 1 {
		var names []string
		for _, c := range items {
			names = append(names, c.Names...)
		}
		t.Fatalf("tổng container theo label = %d %v, muốn đúng 1 (rev cũ phải bị dọn)", len(items), names)
	}
	if items[0].State != container.StateRunning {
		t.Errorf("container state = %s, muốn running", items[0].State)
	}
}
