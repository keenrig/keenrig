package k8s_test

// Conformance driver k8s trên cluster THẬT.
//
// PHẠM VI ĐÃ KIỂM CHỨNG — đọc trước khi tin driver này:
//
// Máy phát triển làm ra driver này KHÔNG có cluster, nên toàn bộ file này CHƯA
// từng chạy xanh. Phần đã kiểm là dịch AppSpec → manifest và đọc trạng thái pod
// (manifest_test.go, 8 test). Phần CHƯA kiểm là mọi lời gọi tới API server:
// đường dẫn resource, mã lỗi, optimistic locking bằng resourceVersion.
//
// Chạy khi có cluster:
//
//	KUBECONFIG=~/.kube/config go test ./keenrig-node/proprietary/runtime/k8s/
//
// Cluster phải có namespace `keenrig` (hoặc đặt KEENRIG_K8S_NAMESPACE) và
// ServiceAccount đủ quyền trên deployments/services/pods.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime/runtimetest"
	"github.com/keenrig/keenrig/keenrig-node/proprietary/runtime/k8s"
)

func requireCluster(t *testing.T) {
	t.Helper()
	if os.Getenv("KUBECONFIG") == "" && os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		t.Skip("không có cluster: đặt KUBECONFIG hoặc chạy trong pod")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := k8s.New(ctx, runtime.Config{Layout: paths.New(t.TempDir())}); err != nil {
		t.Skipf("không mở được driver k8s: %v", err)
	}
}

func TestK8sConformance(t *testing.T) {
	requireCluster(t)
	runtimetest.RunConformance(t, runtimetest.Harness{
		Factory: func(t *testing.T) runtime.Runtime {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			d, err := k8s.New(ctx, runtime.Config{Layout: paths.New(t.TempDir())})
			if err != nil {
				t.Fatalf("mở driver k8s: %v", err)
			}
			return d
		},
		// KillReplica bỏ trống: xoá một pod thì Deployment dựng lại gần như tức
		// thì, nên test sẽ đo được gì tuỳ nhịp — flaky. "Một replica chết" ở
		// k8s do chính kube-controller xử lý, không phải bởi ta.
	})
}
