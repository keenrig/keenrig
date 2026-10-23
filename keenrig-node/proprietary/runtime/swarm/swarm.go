// Package swarm — driver runtime.Runtime trên Docker Swarm mode.
//
// # Khác biệt nền tảng so với driver docker
//
// docker: box quản lý N CONTAINER, tự đặt tên, tự rolling, tự đợi Running.
// swarm: box quản lý MỘT SERVICE, và swarm lo phần còn lại — số replica, đặt
// task lên node nào, rolling update, restart khi task chết.
//
// Hệ quả cụ thể, không phải chi tiết trang trí:
//
//  1. TÊN KHÔNG MANG REV. Tên container ở driver docker có `-r<rev>` để hai rev
//     đồng tồn tại lúc rolling (RT-03). Ở swarm, rolling là việc của swarm và
//     nó cập nhật service TẠI CHỖ; thêm rev vào tên nghĩa là mỗi lần deploy tạo
//     một service mới và swarm không còn biết đó là cùng một app để rolling.
//     Rev vẫn được ghi, nhưng vào LABEL.
//
//  2. Apply là CREATE-hoặc-UPDATE, không phải "dựng mới rồi gỡ cũ". Update cần
//     `Version.Index` của service hiện tại — đó là optimistic locking của
//     swarm, và bỏ qua nó là ghi đè mất thay đổi của người khác.
//
//  3. MẠNG PHẢI LÀ OVERLAY. Bridge chỉ tồn tại trên một node. Tên mạng khác
//     driver docker có chủ đích: `runtime migrate swarm` (V1 §6.1) cần hai mạng
//     cùng tồn tại trong cửa sổ chuyển, và tên mạng là duy nhất trên mỗi daemon.
//
// # Endpoint: IP từng task, không phải VIP của service
//
// Swarm cấp cho service một VIP và tự cân tải. Trả VIP thì đơn giản hơn — một
// upstream duy nhất — nhưng ta CỐ TÌNH không làm vậy:
//
//   - Hợp đồng `Observed.Endpoints` là "địa chỉ các replica đang chạy". Trả VIP
//     làm len(Endpoints) luôn bằng 1 bất kể replica, và conformance
//     EndpointsPerReplica mất hết ý nghĩa với driver này.
//   - Gateway mất khả năng đánh dấu MỘT replica hỏng: qua VIP nó chỉ thấy
//     "service", nên một task lỗi vẫn nhận request cho tới khi swarm phát hiện.
//
// Giá phải trả: gateway phải nối được vào overlay (mạng để `Attachable: true`),
// và tập IP đổi mỗi lần swarm dời task. Đổi lại là cân tải và health thật ở
// tầng gateway. Đây là đánh đổi có chủ đích, không phải bỏ sót.
package swarm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	swarmapi "github.com/moby/moby/api/types/swarm"
	"github.com/moby/moby/client"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/resources"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/runtime"
)

const (
	// Name — tên driver trong registry.
	Name = "swarm"

	// networkName — overlay attachable. KHÁC `keenrig0` của driver docker: tên
	// mạng là duy nhất trên mỗi daemon, và `runtime migrate swarm` cần cả hai
	// tồn tại trong cửa sổ chuyển đổi.
	networkName = "keenrig-swarm0"

	labelManaged = "keenrig.managed"
	labelAppID   = "keenrig.com.id"
	labelAppSlug = "keenrig.com.slug"
	labelRev     = "keenrig.com.rev"
	labelPort    = "keenrig.com.port"

	// waitRunningTimeout — swarm phải kéo image trên (có thể) nhiều node rồi
	// mới chạy task, nên rộng hơn driver docker.
	//
	// AI ĐỔI SỐ NÀY PHẢI ĐỌC reconciler/lease.go: bất đẳng thức
	// LeaseTTL > renewEvery + Apply-lâu-nhất phải còn đúng. 120s > 40s + 120s
	// là SAI — vì vậy reconciler.DefaultLeaseTTL đã được nâng cùng lúc.
	waitRunningTimeout = 120 * time.Second
	pollInterval       = 500 * time.Millisecond
)

func init() {
	runtime.Register(Name, func(ctx context.Context, cfg runtime.Config) (runtime.Runtime, error) {
		return New(ctx, cfg)
	})
}

// Driver implement runtime.Runtime trên Swarm.
type Driver struct {
	cli *client.Client
}

var _ runtime.Runtime = (*Driver)(nil)

// New kết nối daemon và KIỂM node có phải MANAGER không.
//
// Kiểm ngay lúc mở, không đợi Apply: mọi lời gọi service API trên một worker
// đều lỗi, và lỗi đó lộ ra lúc người dùng deploy app đầu tiên thì đã quá muộn
// để nói "anh cài nhầm vai trò node".
func New(ctx context.Context, cfg runtime.Config) (*Driver, error) {
	opts := []client.Opt{client.FromEnv, client.WithAPIVersionNegotiation()}
	if host := cfg.DSNOr(""); host != "" {
		opts = append(opts, client.WithHost(host))
	}
	cli, err := client.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("swarm: creating the client: %w", err)
	}
	res, err := cli.Info(ctx, client.InfoOptions{})
	if err != nil {
		cli.Close()
		return nil, fmt.Errorf("swarm: querying the daemon: %w", err)
	}
	if !res.Info.Swarm.ControlAvailable {
		cli.Close()
		return nil, fmt.Errorf("%w: this node is not a swarm manager (state %q) — "+
			"run `docker swarm init` or point KEENRIG_RUNTIME_CONFIG at a manager",
			runtime.ErrBadConfig, res.Info.Swarm.LocalNodeState)
	}
	d := &Driver{cli: cli}
	if err := d.ensureNetwork(ctx); err != nil {
		cli.Close()
		return nil, err
	}
	return d, nil
}

func (d *Driver) Close() error { return d.cli.Close() }

// ensureNetwork tạo overlay attachable nếu chưa có.
//
// Attachable là bắt buộc, không phải tuỳ chọn: gateway chạy như một container
// thường (không phải swarm service) và chỉ nối được vào overlay khi mạng cho
// phép attach. Thiếu cờ này thì app chạy nhưng không ai vào được.
func (d *Driver) ensureNetwork(ctx context.Context) error {
	res, err := d.cli.NetworkList(ctx, client.NetworkListOptions{
		Filters: make(client.Filters).Add("name", networkName),
	})
	if err != nil {
		return fmt.Errorf("swarm: list network: %w", err)
	}
	for _, n := range res.Items {
		if n.Name == networkName { // filter khớp chuỗi con — so sánh exact
			return nil
		}
	}
	_, err = d.cli.NetworkCreate(ctx, networkName, client.NetworkCreateOptions{
		Driver:     "overlay",
		Attachable: true,
		Labels:     map[string]string{labelManaged: "true"},
	})
	if err != nil && !cerrdefs.IsConflict(err) {
		return fmt.Errorf("swarm: creating overlay %s: %w", networkName, err)
	}
	return nil
}

// appIDShort — 8 hex đầu của SHA-256(app.id); cùng lý do với driver docker.
func appIDShort(appID string) string {
	sum := sha256.Sum256([]byte(appID))
	return hex.EncodeToString(sum[:4])
}

// serviceName — KHÔNG mang rev (xem godoc package).
func serviceName(appID, slug string) string {
	return fmt.Sprintf("su-%s-%s", slug, appIDShort(appID))
}

func replicasOf(spec runtime.AppSpec) uint64 {
	if spec.Desired.Resources == nil || spec.Desired.Resources.Replicas < 1 {
		return 1
	}
	return uint64(spec.Desired.Resources.Replicas)
}

func portOf(spec runtime.AppSpec) int {
	if spec.Desired.HTTPPort > 0 {
		return spec.Desired.HTTPPort
	}
	return contracts.DefaultHTTPPort
}

func envList(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out
}

func labelsFor(spec runtime.AppSpec, port int) map[string]string {
	return map[string]string{
		labelManaged: "true",
		labelAppID:   spec.ID,
		labelAppSlug: spec.Slug,
		labelRev:     strconv.FormatInt(spec.DesiredRev, 10),
		labelPort:    strconv.Itoa(port),
	}
}

// buildSpec dịch AppSpec → swarm.ServiceSpec.
func buildSpec(spec runtime.AppSpec, port int) swarmapi.ServiceSpec {
	replicas := replicasOf(spec)
	labels := labelsFor(spec, port)

	res := resourcesOf(spec)
	ulimits := ulimitsOf(spec)

	return swarmapi.ServiceSpec{
		Annotations: swarmapi.Annotations{
			Name:   serviceName(spec.ID, spec.Slug),
			Labels: labels,
		},
		TaskTemplate: swarmapi.TaskSpec{
			ContainerSpec: &swarmapi.ContainerSpec{
				Image:   spec.Desired.Image,
				Env:     envList(spec.Desired.Env),
				Labels:  labels, // cả trên task để `docker ps` cũng thấy chủ sở hữu
				Ulimits: ulimits,
			},
			Resources: res,
			RestartPolicy: &swarmapi.RestartPolicy{
				Condition: swarmapi.RestartPolicyConditionAny,
			},
			Networks: []swarmapi.NetworkAttachmentConfig{{Target: networkName}},
		},
		Mode: swarmapi.ServiceMode{
			Replicated: &swarmapi.ReplicatedService{Replicas: &replicas},
		},
		// START-FIRST, không phải mặc định stop-first.
		//
		// Mặc định của swarm là DỪNG task cũ rồi mới khởi động task mới — với
		// replicas=1 đó là downtime thật, và conformance RollingByRev bắt được
		// đúng điều đó. Driver docker làm new-trước-old (RT-03); hợp đồng
		// runtime.Runtime là như nhau cho mọi driver, nên swarm phải theo.
		//
		// Giá phải trả: trong cửa sổ rolling có replicas+1 task, tức là tốn thêm
		// tài nguyên bằng một replica. Đó là cái giá đúng để đổi lấy không downtime.
		//
		// FailureAction=pause: task mới fail thì DỪNG rollout và giữ nguyên bản
		// cũ đang phục vụ. `continue` sẽ thay tiếp cho tới khi không còn replica
		// lành nào — biến một image hỏng thành một sự cố toàn phần.
		UpdateConfig: &swarmapi.UpdateConfig{
			Parallelism:   1,
			Order:         swarmapi.UpdateOrderStartFirst,
			FailureAction: swarmapi.UpdateFailureActionPause,
		},
		// KHÔNG khai EndpointSpec/PublishedPort: app không được publish ra host.
		// Gateway nối vào overlay; publish ra host sẽ mở app ra ngoài vòng kiểm
		// soát của gateway (bỏ qua TLS, WAF, rate limit) — cùng lý do với driver docker.
	}
}

// findService tìm service của app theo LABEL (không theo tên).
//
// Theo label vì tên có thể trùng khi slug được dùng lại; đây đúng là bài học
// BUG-1 của driver docker, áp sang đây trước khi nó kịp xảy ra lần nữa.
func (d *Driver) findService(ctx context.Context, appID string) (*swarmapi.Service, error) {
	res, err := d.cli.ServiceList(ctx, client.ServiceListOptions{
		Filters: make(client.Filters).Add("label", labelAppID+"="+appID),
	})
	if err != nil {
		return nil, fmt.Errorf("swarm: list service app=%s: %w", appID, err)
	}
	if len(res.Items) == 0 {
		return nil, nil
	}
	if len(res.Items) > 1 {
		// Không tự dọn: nhiều service cùng app.id là dấu hiệu ai đó tạo tay
		// hoặc một lần migrate hỏng. Xoá bớt có thể xoá đúng cái đang phục vụ.
		names := make([]string, 0, len(res.Items))
		for _, s := range res.Items {
			names = append(names, s.Spec.Name)
		}
		return nil, fmt.Errorf("swarm: app %s has %d services (%s) — manual cleanup required",
			appID, len(res.Items), strings.Join(names, ", "))
	}
	return &res.Items[0], nil
}

// Apply — create-hoặc-update rồi ĐỢI đủ replica Running.
func (d *Driver) Apply(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
	// Hạn mức swarm không có chỗ khai → TỪ CHỐI. Không trùng lặp với admission:
	// admission bỏ qua khi chưa biết năng lực (caps nil), còn ở đây thì luôn
	// biết. Đây là chỗ duy nhất đảm bảo không có đường nào áp thiếu trong im lặng.
	if err := resources.Enforce(spec.Desired.Resources, resources.ByDriver(Name), Name); err != nil {
		return errObserved(err), err
	}
	port := portOf(spec)
	desired := buildSpec(spec, port)

	cur, err := d.findService(ctx, spec.ID)
	if err != nil {
		return errObserved(err), err
	}

	var serviceID string
	switch {
	case cur == nil:
		res, cerr := d.cli.ServiceCreate(ctx, client.ServiceCreateOptions{Spec: desired})
		if cerr != nil {
			return errObserved(cerr), fmt.Errorf("swarm: creating the service: %w", cerr)
		}
		serviceID = res.ID
	default:
		serviceID = cur.ID
		// Version.Index là optimistic lock của swarm. Truyền version cũ →
		// swarm từ chối; bỏ qua nó thì không có API nào để bỏ qua — bắt buộc.
		_, uerr := d.cli.ServiceUpdate(ctx, serviceID, client.ServiceUpdateOptions{
			Version: cur.Version,
			Spec:    desired,
		})
		if uerr != nil {
			return errObserved(uerr), fmt.Errorf("swarm: updating the service: %w", uerr)
		}
	}

	obs, err := d.waitRunning(ctx, serviceID, spec, int(replicasOf(spec)))
	if err != nil {
		return obs, err
	}
	return obs, nil
}

// taskRev đọc rev từ label trên TASK (không phải trên service).
//
// Label service đổi ngay khi ServiceUpdate trả về; label task chỉ đổi khi swarm
// đã thực sự tạo task mới. Đó chính là thứ phân biệt "đã ra lệnh" với "đã hội tụ".
func taskRev(t swarmapi.Task) string {
	if t.Spec.ContainerSpec == nil {
		return ""
	}
	return t.Spec.ContainerSpec.Labels[labelRev]
}

// waitRunning đợi HỘI TỤ: đúng `want` task đang chạy, và TẤT CẢ ở rev mới.
//
// Điều kiện gồm hai vế, và cả hai đều do test dạy ra:
//
//  1. `len(running) == want`, không phải `>=`. Ngay sau ServiceUpdate, task rev
//     CŨ vẫn Running (start-first còn cố tình giữ nó lại), nên `>=` cho qua
//     ngay và Apply báo thành công trước khi rollout bắt đầu. Khi thu replica
//     2→1 cũng vậy: cả hai task còn Running vài trăm ms đầu.
//
//  2. TẤT CẢ phải ở rev mới. Nếu chỉ đếm số lượng thì trong cửa sổ start-first
//     (1 cũ + 1 mới = 2 ≠ 1) ta vẫn chờ đúng, nhưng lúc swarm vừa gỡ task cũ và
//     chưa kịp báo, số lượng về 1 trong khi cái còn lại có thể vẫn là task CŨ.
//
// Gộp lại: hội tụ = "đúng số lượng, và không còn dấu vết rev cũ". Đó cũng là
// điều kiện để Status ngay sau Apply trả về đúng `want` container.
//
// Task Failed/Rejected → LỖI NGAY kèm thông báo của swarm: image sai tên hay
// thiếu quyền pull fail ngay, và bắt người dùng nhìn màn hình 2 phút để nhận
// một dòng "timeout" là vô ích.
func (d *Driver) waitRunning(ctx context.Context, serviceID string, spec runtime.AppSpec, want int) (runtime.Observed, error) {
	rev := strconv.FormatInt(spec.DesiredRev, 10)
	deadline := time.Now().Add(waitRunningTimeout)
	for {
		if err := ctx.Err(); err != nil {
			return errObserved(err), err
		}
		tasks, err := d.tasksOf(ctx, serviceID)
		if err != nil {
			return errObserved(err), err
		}

		running, err := currentRunning(tasks)
		if err != nil {
			return errObserved(err), err
		}
		if len(running) == want && allAtRev(running, rev) {
			return d.observe(spec, running), nil
		}
		if time.Now().After(deadline) {
			err := fmt.Errorf("swarm: timed out after %s — %d/%d tasks Running, desired rev %s",
				waitRunningTimeout, len(running), want, rev)
			return errObserved(err), err
		}
		select {
		case <-ctx.Done():
			return errObserved(ctx.Err()), ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// currentRunning lọc task ĐANG PHỤC VỤ; lỗi nếu có task hỏng hẳn.
//
// KHÔNG lọc theo rev, và đây là điểm quan trọng nhất của cả file:
//
// Trong lúc rolling, task rev cũ VẪN đang nhận request. Lọc chúng ra khỏi
// Observed nghĩa là reconciler ghi một tập endpoint rỗng, đẩy sang gateway, và
// gateway gỡ hết upstream — downtime THẬT, do chính ta gây ra, đúng giữa lúc
// deploy. Conformance RollingByRev bắt được điều đó ("có downtime trong lúc
// rolling") và nó nói đúng.
//
// Rev chỉ dùng để trả lời câu hỏi KHÁC — "đã hội tụ chưa" — và câu đó thuộc về
// waitRunning, không thuộc về "cái gì đang phục vụ".
func currentRunning(tasks []swarmapi.Task) ([]swarmapi.Task, error) {
	var running []swarmapi.Task
	for _, t := range tasks {
		// Task swarm không còn muốn chạy: đang bị thay hoặc bị thu. Nó vẫn có
		// thể đang phục vụ nốt, nhưng đưa vào danh sách upstream là gửi request
		// tới thứ sắp bị gỡ.
		if t.DesiredState != swarmapi.TaskStateRunning {
			continue
		}
		switch t.Status.State {
		case swarmapi.TaskStateRunning:
			running = append(running, t)
		case swarmapi.TaskStateFailed, swarmapi.TaskStateRejected:
			return nil, fmt.Errorf("swarm: task %s %s: %s", shortID(t.ID), t.Status.State, t.Status.Err)
		}
	}
	return running, nil
}

func allAtRev(tasks []swarmapi.Task, rev string) bool {
	for _, t := range tasks {
		if taskRev(t) != rev {
			return false
		}
	}
	return true
}

func (d *Driver) tasksOf(ctx context.Context, serviceID string) ([]swarmapi.Task, error) {
	res, err := d.cli.TaskList(ctx, client.TaskListOptions{
		Filters: make(client.Filters).Add("service", serviceID),
	})
	if err != nil {
		return nil, fmt.Errorf("swarm: list task: %w", err)
	}
	return res.Items, nil
}

// observe dựng Observed từ tập task đang chạy.
func (d *Driver) observe(spec runtime.AppSpec, running []swarmapi.Task) runtime.Observed {
	// Sắp theo Slot để thứ tự ổn định giữa hai lần gọi — nếu không, tập
	// endpoint "đổi" mỗi tick và reconciler sẽ đẩy lại cấu hình gateway vô ích.
	sort.Slice(running, func(i, j int) bool {
		if running[i].Slot != running[j].Slot {
			return running[i].Slot < running[j].Slot
		}
		return running[i].ID < running[j].ID
	})

	port := portOf(spec)
	obs := runtime.Observed{Phase: contracts.AppStateRunning, Health: contracts.HealthUnknown}
	for _, t := range running {
		obs.ContainerIDs = append(obs.ContainerIDs, t.ID)
		if ip := taskIP(t); ip != "" {
			obs.Endpoints = append(obs.Endpoints, runtime.Endpoint{Host: ip, Port: port})
		}
	}
	return obs
}

// taskIP lấy IP của task TRÊN MẠNG CỦA MÌNH.
//
// Chỉ đọc đúng overlay của platform: task có thể được attach thêm mạng khác, và
// IP trên mạng đó gateway không tới được — cùng cạm bẫy đã xử ở driver docker.
// Địa chỉ trả về dạng CIDR ("10.0.1.5/24") nên phải cắt mask.
func taskIP(t swarmapi.Task) string {
	for _, na := range t.NetworksAttachments {
		if na.Network.Spec.Name != networkName {
			continue
		}
		for _, addr := range na.Addresses {
			if addr.IsValid() && addr.Addr().Is4() {
				return addr.Addr().String()
			}
		}
	}
	return ""
}

// Status — READ-ONLY.
func (d *Driver) Status(ctx context.Context, appID string) (runtime.Observed, error) {
	svc, err := d.findService(ctx, appID)
	if err != nil {
		return runtime.Observed{Phase: contracts.AppStateUnknown, Health: contracts.HealthUnknown, Message: err.Error()}, err
	}
	if svc == nil {
		return runtime.Observed{
			Phase: contracts.AppStateStopped, Health: contracts.HealthUnknown, Message: "no service",
		}, nil
	}

	tasks, err := d.tasksOf(ctx, svc.ID)
	if err != nil {
		return runtime.Observed{Phase: contracts.AppStateUnknown, Health: contracts.HealthUnknown, Message: err.Error()}, err
	}

	// Status KHÔNG có AppSpec — cổng đọc từ LABEL trên service, đúng như driver
	// docker đọc label trên container. Đó là lý do label tồn tại.
	port := portFromLabels(svc.Spec.Labels)
	specForObserve := runtime.AppSpec{Desired: contracts.DesiredApp{HTTPPort: port}}

	// Status báo cáo CÁI GÌ ĐANG PHỤC VỤ, không phải "đã hội tụ chưa" — xem
	// godoc currentRunning. Rev chỉ dùng để đặt phase deploying/running.
	rev := svc.Spec.Labels[labelRev]
	running, failErr := currentRunning(tasks)

	want := 1
	if svc.Spec.Mode.Replicated != nil && svc.Spec.Mode.Replicated.Replicas != nil {
		want = int(*svc.Spec.Mode.Replicated.Replicas)
	}

	obs := d.observe(specForObserve, running)
	switch {
	case failErr != nil:
		// Status là READ-ONLY và KHÔNG trả error cho "app đang hỏng": app hỏng
		// là một trạng thái hợp lệ để báo cáo, không phải lỗi khi quan sát.
		obs.Phase = contracts.AppStateError
		obs.Message = failErr.Error()
	case want == 0 || len(running) == 0:
		obs.Phase = contracts.AppStateStopped
	case len(running) != want || !allAtRev(running, rev):
		// Đang rolling hoặc đang scale: KHÔNG phải lỗi, và endpoint vẫn được
		// trả về đầy đủ để gateway giữ nguyên lưu lượng.
		obs.Phase = contracts.AppStateDeploying
		obs.Message = fmt.Sprintf("%d/%d replicas, desired rev %s", len(running), want, rev)
	}
	return obs, nil
}

func portFromLabels(labels map[string]string) int {
	n, err := strconv.Atoi(labels[labelPort])
	if err != nil || n <= 0 || n > 65535 {
		return contracts.DefaultHTTPPort
	}
	return n
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// Remove xoá service; IDEMPOTENT. KHÔNG xoá overlay (dùng chung).
func (d *Driver) Remove(ctx context.Context, appID string) error {
	svc, err := d.findService(ctx, appID)
	if err != nil {
		return err
	}
	if svc == nil {
		return nil
	}
	if _, err := d.cli.ServiceRemove(ctx, svc.ID, client.ServiceRemoveOptions{}); err != nil {
		if cerrdefs.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("swarm: removing service %s: %w", svc.Spec.Name, err)
	}
	return nil
}

func errObserved(err error) runtime.Observed {
	return runtime.Observed{
		Phase:   contracts.AppStateError,
		Health:  contracts.HealthUnknown,
		Message: err.Error(),
	}
}
