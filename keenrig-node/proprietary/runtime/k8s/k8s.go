// Package k8s — driver runtime.Runtime trên Kubernetes.
//
// # Ánh xạ khái niệm
//
//	app          → Deployment (+ Service ClusterIP)
//	replica      → Pod
//	desired_rev  → label keenrig.com.rev + annotation trigger rolling
//	Endpoints    → PodIP của các pod Ready
//
// # Ba quyết định đáng ghi
//
//  1. DEPLOYMENT, không phải StatefulSet. App web ở M1 là stateless; dữ liệu
//     người dùng nằm ở addon (M2). Chọn StatefulSet cho mọi app sẽ áp đặt danh
//     tính ổn định và PVC per-pod cho những app không cần, và làm scale chậm đi
//     đáng kể. Addon stateful sẽ cần StatefulSet — đó là việc riêng, chưa POC
//     (V1 §11.8 ghi rõ đây là phần khó nhất của bậc trả phí).
//
//  2. Trả PodIP, KHÔNG trả ClusterIP của Service. Cùng lập luận với driver
//     swarm (VIP): hợp đồng Endpoints là "địa chỉ từng replica", và qua một VIP
//     thì gateway mất khả năng loại đúng một pod hỏng. Service vẫn được tạo, vì
//     app gọi nhau trong cluster cần một tên DNS ổn định — nhưng gateway thì
//     nối thẳng pod.
//
//     Giá phải trả, nói thẳng: gateway PHẢI ở trên mạng pod (chạy trong cluster,
//     hoặc node có route tới CNI). Với BYO cluster mà gateway đứng ngoài, cấu
//     hình này không chạy — lúc đó phải chuyển sang Ingress, và đó là việc của
//     M7 chứ không phải một cờ ẩn ở đây.
//
//  3. Update bằng PUT có resourceVersion, không PATCH. resourceVersion là
//     optimistic locking của Kubernetes; bỏ qua nó là ghi đè mất thay đổi của
//     người khác — cùng lý do driver swarm phải truyền Version.Index.
//
// # Phạm vi đã kiểm chứng
//
// Phần dịch AppSpec → manifest có test đơn vị đầy đủ. Phần nói chuyện với API
// server CHƯA chạy trên cluster thật (máy phát triển không có cluster);
// conformance sẽ tự chạy khi KUBECONFIG trỏ tới một cluster và SKIP khi không.
// Điều này được ghi ở đây thay vì để người đọc tự đoán.
package k8s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/resources"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
)

const (
	// Name — tên driver trong registry.
	Name = "k8s"

	labelManaged = "keenrig.managed"
	labelAppID   = "keenrig.com.id"
	labelAppSlug = "keenrig.com.slug"
	labelRev     = "keenrig.com.rev"
	labelPort    = "keenrig.com.port"

	// waitReadyTimeout — k8s có thể phải kéo image, chờ scheduler, chờ readiness
	// probe. Rộng hơn swarm.
	//
	// PHẢI khớp runtime.K8sApplyTimeout và nằm trong ngân sách LeaseTTL của
	// reconciler — có test canh (TestApplyTimeoutsWithinBudget).
	waitReadyTimeout = 180 * time.Second
	pollInterval     = 1 * time.Second
)

func init() {
	runtime.Register(Name, func(ctx context.Context, cfg runtime.Config) (runtime.Runtime, error) {
		return New(ctx, cfg)
	})
}

type Driver struct {
	c *restClient
}

var _ runtime.Runtime = (*Driver)(nil)

// New mở driver.
//
// Thứ tự tìm cấu hình: DSN → KUBECONFIG → in-cluster → ~/.kube/config.
// In-cluster đứng TRƯỚC ~/.kube/config có chủ đích: khi keenrig-box chạy như
// một pod, một file kubeconfig sót lại trong image không được phép thắng danh
// tính ServiceAccount thật của pod.
func New(ctx context.Context, cfg runtime.Config) (*Driver, error) {
	c, err := openClient(cfg)
	if err != nil {
		return nil, err
	}
	if ns := strings.TrimSpace(cfg.Namespace); ns != "" {
		c.namespace = ns
	} else if ns := os.Getenv(defaultNamespaceEnv); ns != "" {
		c.namespace = ns
	}
	// Bắt tay NGAY: kubeconfig sai hay thiếu quyền phải nổ lúc khởi động, không
	// phải lúc người dùng deploy app đầu tiên.
	if err := c.ping(ctx); err != nil {
		return nil, err
	}
	return &Driver{c: c}, nil
}

func openClient(cfg runtime.Config) (*restClient, error) {
	if dsn := cfg.DSNOr(""); dsn != "" {
		return newKubeconfigClient(dsn)
	}
	if kc := os.Getenv("KUBECONFIG"); kc != "" {
		// KUBECONFIG có thể là danh sách ngăn cách bởi dấu phân cách của HĐH.
		// Ta chỉ đọc mục ĐẦU TIÊN và nói rõ, thay vì merge sai lặng lẽ.
		parts := filepath.SplitList(kc)
		return newKubeconfigClient(parts[0])
	}
	if c, err := newInClusterClient(); err == nil {
		return c, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("%w: no kubeconfig found (set KEENRIG_RUNTIME_CONFIG or KUBECONFIG)", runtime.ErrBadConfig)
	}
	p := filepath.Join(home, ".kube", "config")
	if _, err := os.Stat(p); err != nil {
		return nil, fmt.Errorf("%w: no kubeconfig found (set KEENRIG_RUNTIME_CONFIG or KUBECONFIG)", runtime.ErrBadConfig)
	}
	return newKubeconfigClient(p)
}

// Namespace đang dùng (test và log cần biết).
func (d *Driver) Namespace() string { return d.c.namespace }

// --- đường dẫn API ---------------------------------------------------------------

func (d *Driver) deploymentsPath() string {
	return "/apis/apps/v1/namespaces/" + d.c.namespace + "/deployments"
}

func (d *Driver) servicesPath() string {
	return "/api/v1/namespaces/" + d.c.namespace + "/services"
}

func (d *Driver) podsPath(appID string) string {
	return "/api/v1/namespaces/" + d.c.namespace + "/pods?labelSelector=" +
		labelAppID + "%3D" + appID
}

// --- Runtime ----------------------------------------------------------------------

func (d *Driver) Apply(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
	// Xem godoc swarm.Apply về vì sao đây không phải trùng lặp với admission.
	if err := resources.Enforce(spec.Desired.Resources, resources.ByDriver(Name), Name); err != nil {
		return errObserved(err), err
	}
	dep := buildDeployment(spec, d.c.namespace)
	name := resourceName(spec.ID, spec.Slug)

	// Deployment: tạo mới, hoặc PUT đè kèm resourceVersion hiện tại.
	var cur deployment
	err := d.c.get(ctx, d.deploymentsPath()+"/"+name, &cur)
	switch {
	case err == nil:
		if owner := cur.Metadata.Labels[labelAppID]; owner != spec.ID {
			// Danh tính là LABEL, không phải tên — bài học BUG-1 của driver
			// docker. Tên trùng mà chủ khác thì KHÔNG đè.
			e := fmt.Errorf("k8s: deployment %q belongs to another app (app.id=%s)", name, owner)
			return errObserved(e), e
		}
		dep.Metadata.ResourceVersion = cur.Metadata.ResourceVersion
		if err := d.c.put(ctx, d.deploymentsPath()+"/"+name, dep, nil); err != nil {
			return errObserved(err), err
		}
	case isNotFound(err):
		if cerr := d.c.post(ctx, d.deploymentsPath(), dep, nil); cerr != nil && !isConflict(cerr) {
			return errObserved(cerr), cerr
		}
	default:
		return errObserved(err), err
	}

	// Service: chỉ tạo, không cập nhật mỗi lần — ClusterIP là bất biến và PUT
	// lại sẽ chỉ tạo ra lỗi. Đổi cổng thì xoá rồi tạo lại (hiếm, và có event).
	svc := buildService(spec, d.c.namespace)
	if err := d.c.post(ctx, d.servicesPath(), svc, nil); err != nil && !isConflict(err) {
		return errObserved(err), err
	}

	return d.waitReady(ctx, spec)
}

// waitReady đợi HỘI TỤ: đúng `want` pod Ready, và TẤT CẢ ở rev mới.
//
// Điều kiện này copy nguyên từ driver swarm, nơi conformance trên cluster THẬT
// đã dạy hai điều (xem swarm.waitRunning):
//
//   - `>=` là sai: với maxSurge=1, giữa lúc rolling có want+1 pod Ready và pod
//     rev cũ vẫn phục vụ. `>=` cho qua ngay, Apply trả về "thành công" trong
//     khi rev mới chưa lên đủ, và Status ngay sau đó đếm ra want+1.
//   - Chỉ đếm số lượng cũng sai: đúng lúc pod cũ vừa bị xoá và pod mới chưa
//     Ready, số lượng có thể khớp trong khi cái còn lại vẫn là rev CŨ.
//
// Gộp lại: hội tụ = đúng số lượng VÀ không còn dấu vết rev cũ.
func (d *Driver) waitReady(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
	want := replicasOf(spec)
	rev := strconv.FormatInt(spec.DesiredRev, 10)
	deadline := time.Now().Add(waitReadyTimeout)

	for {
		if err := ctx.Err(); err != nil {
			return errObserved(err), err
		}
		pods, err := d.listPods(ctx, spec.ID)
		if err != nil {
			return errObserved(err), err
		}

		ready, err := readyPods(pods)
		if err != nil {
			return errObserved(err), err
		}
		if len(ready) == want && allAtRev(ready, rev) {
			return d.observe(spec, ready), nil
		}
		if time.Now().After(deadline) {
			e := fmt.Errorf("k8s: timed out after %s — %d/%d pods Ready, desired rev %s",
				waitReadyTimeout, len(ready), want, rev)
			return errObserved(e), e
		}
		select {
		case <-ctx.Done():
			return errObserved(ctx.Err()), ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// readyPods lọc pod ĐANG PHỤC VỤ; lỗi nếu có pod hỏng theo kiểu không tự khỏi.
//
// KHÔNG lọc theo rev — cùng lý do với swarm.currentRunning: pod rev cũ vẫn nhận
// request trong lúc rolling, và bỏ chúng khỏi Observed sẽ khiến reconciler đẩy
// một tập endpoint rỗng sang gateway. Đó là downtime do chính ta gây ra, đúng
// giữa lúc deploy.
func readyPods(pods []pod) ([]pod, error) {
	var ready []pod
	for _, p := range pods {
		// Pod hỏng vì lý do KHÔNG tự khỏi (image sai tên, thiếu quyền pull) →
		// lỗi ngay, đừng bắt người dùng nhìn màn hình 3 phút để nhận "timeout".
		if reason := terminalFailure(p); reason != "" {
			return nil, fmt.Errorf("k8s: pod %s failed to start: %s", p.Metadata.Name, reason)
		}
		if podReady(p) {
			ready = append(ready, p)
		}
	}
	return ready, nil
}

func allAtRev(pods []pod, rev string) bool {
	for _, p := range pods {
		if p.Metadata.Labels[labelRev] != rev {
			return false
		}
	}
	return true
}

func (d *Driver) Status(ctx context.Context, appID string) (runtime.Observed, error) {
	pods, err := d.listPods(ctx, appID)
	if err != nil {
		return runtime.Observed{Phase: contracts.AppStateUnknown, Health: contracts.HealthUnknown, Message: err.Error()}, err
	}
	if len(pods) == 0 {
		return runtime.Observed{Phase: contracts.AppStateStopped, Health: contracts.HealthUnknown, Message: "no pods"}, nil
	}

	// Status không có AppSpec → cổng đọc từ LABEL trên pod, đúng như hai driver kia.
	port := contracts.DefaultHTTPPort
	if p := portFromLabels(pods[0].Metadata.Labels); p > 0 {
		port = p
	}
	specForObserve := runtime.AppSpec{Desired: contracts.DesiredApp{HTTPPort: port}}

	// Status báo cáo CÁI GÌ ĐANG PHỤC VỤ (không lọc rev — xem readyPods).
	ready, failErr := readyPods(pods)

	obs := d.observe(specForObserve, ready)
	switch {
	case failErr != nil:
		// Status là READ-ONLY và KHÔNG trả error cho "app đang hỏng": app hỏng
		// là trạng thái hợp lệ để báo cáo, không phải lỗi khi quan sát.
		obs.Phase = contracts.AppStateError
		obs.Message = failErr.Error()
	case len(ready) == 0:
		obs.Phase = contracts.AppStateDeploying
		obs.Message = fmt.Sprintf("0/%d pod Ready", len(pods))
	case len(ready) < len(pods):
		obs.Phase = contracts.AppStateDeploying
		obs.Message = fmt.Sprintf("%d/%d pod Ready", len(ready), len(pods))
	}
	return obs, nil
}

// Remove xoá Deployment + Service. IDEMPOTENT.
func (d *Driver) Remove(ctx context.Context, appID string) error {
	// Không biết slug ở đây nên phải tìm qua label rồi xoá theo tên thật —
	// đoán tên từ appID là cách để sót tài nguyên khi slug đã đổi.
	deps, err := d.listDeployments(ctx, appID)
	if err != nil {
		return err
	}
	for _, dep := range deps {
		if err := d.c.delete(ctx, d.deploymentsPath()+"/"+dep.Metadata.Name); err != nil {
			return err
		}
		if err := d.c.delete(ctx, d.servicesPath()+"/"+dep.Metadata.Name); err != nil {
			return err
		}
	}
	return nil
}

func (d *Driver) observe(spec runtime.AppSpec, ready []pod) runtime.Observed {
	// Thứ tự ổn định theo tên pod — nếu không, tập endpoint "đổi" mỗi tick và
	// reconciler đẩy lại cấu hình gateway vô ích.
	sort.Slice(ready, func(i, j int) bool { return ready[i].Metadata.Name < ready[j].Metadata.Name })

	port := portOf(spec)
	obs := runtime.Observed{Phase: contracts.AppStateRunning, Health: contracts.HealthUnknown}
	for _, p := range ready {
		obs.ContainerIDs = append(obs.ContainerIDs, p.Metadata.Name)
		if p.Status.PodIP != "" {
			obs.Endpoints = append(obs.Endpoints, runtime.Endpoint{Host: p.Status.PodIP, Port: port})
		}
	}
	return obs
}

func (d *Driver) listPods(ctx context.Context, appID string) ([]pod, error) {
	var list podList
	if err := d.c.get(ctx, d.podsPath(appID), &list); err != nil {
		return nil, err
	}
	// Pod đang bị xoá vẫn xuất hiện trong list cho tới khi biến mất hẳn; đưa
	// chúng vào tập endpoint là gửi request tới thứ sắp chết.
	out := make([]pod, 0, len(list.Items))
	for _, p := range list.Items {
		if p.Metadata.DeletionTimestamp != "" {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func (d *Driver) listDeployments(ctx context.Context, appID string) ([]deployment, error) {
	var list deploymentList
	path := d.deploymentsPath() + "?labelSelector=" + labelAppID + "%3D" + appID
	if err := d.c.get(ctx, path, &list); err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return list.Items, nil
}

func errObserved(err error) runtime.Observed {
	return runtime.Observed{
		Phase:   contracts.AppStateError,
		Health:  contracts.HealthUnknown,
		Message: err.Error(),
	}
}
