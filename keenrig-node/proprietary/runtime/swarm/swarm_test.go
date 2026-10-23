package swarm_test

// Conformance driver swarm trên Docker Swarm THẬT.
//
// Node phải là manager. Test tự SKIP nếu không, kèm hướng dẫn — chứ không tự ý
// `docker swarm init`: bật swarm mode là thay đổi trạng thái daemon của người
// chạy test, và một test không được phép làm điều đó sau lưng họ.
//
//	docker swarm init
//	go test ./keenrig-node/proprietary/runtime/swarm/
//
// CI đặt KEENRIG_TEST_SWARM=1 sau khi đã init trong bước setup.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/moby/moby/client"

	"github.com/keenrig/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime/runtimetest"
	"github.com/keenrig/keenrig/keenrig-node/proprietary/runtime/swarm"
)

func requireSwarmManager(t *testing.T) {
	t.Helper()
	cli, err := client.New(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Skipf("không có Docker: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := cli.Info(ctx, client.InfoOptions{})
	if err != nil {
		t.Skipf("không hỏi được daemon: %v", err)
	}
	if !res.Info.Swarm.ControlAvailable {
		t.Skipf("node không phải swarm manager (trạng thái %q) — chạy `docker swarm init` rồi thử lại",
			res.Info.Swarm.LocalNodeState)
	}
}

func newDriver(t *testing.T) runtime.Runtime {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d, err := swarm.New(ctx, runtime.Config{Layout: paths.New(t.TempDir())})
	if err != nil {
		t.Fatalf("mở driver swarm: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestSwarmConformance(t *testing.T) {
	requireSwarmManager(t)
	runtimetest.RunConformance(t, runtimetest.Harness{
		Factory: func(t *testing.T) runtime.Runtime { return newDriver(t) },
		// KillReplica bỏ trống: giết một task swarm bằng đường ngoài driver
		// nghĩa là `docker rm` container của task, và swarm dựng lại gần như
		// tức thì — test sẽ đo được điều gì tuỳ nhịp, tức là flaky. Trường hợp
		// "một replica chết" ở swarm do chính swarm xử lý, không phải bởi ta.
	})
}

// Node KHÔNG phải manager thì New phải từ chối NGAY với thông báo nói rõ phải
// làm gì — không đợi tới Apply, lúc đó người dùng đã tưởng cấu hình xong xuôi.
func TestRejectsNonManager(t *testing.T) {
	if os.Getenv("KEENRIG_TEST_SWARM_NONMANAGER") == "" {
		t.Skip("cần một daemon KHÔNG ở swarm mode; đặt KEENRIG_TEST_SWARM_NONMANAGER=1 kèm DOCKER_HOST trỏ tới nó")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := swarm.New(ctx, runtime.Config{Layout: paths.New(t.TempDir())}); err == nil {
		t.Fatal("New chấp nhận một node không phải manager")
	}
}
