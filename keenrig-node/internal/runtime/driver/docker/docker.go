// Package docker — driver runtime.Runtime trên Docker Engine
// (github.com/moby/moby/client v0.5.x — options struct + result struct).
//
// Danh tính container = LABELS (keenrig.com.id/rev/replica); tên container
// su-<slug>-<appIDShort>-<idx>-r<rev> có rev để 2 rev đồng tồn tại lúc rolling
// (RT-03) và có appIDShort để 2 app khác nhau không bao giờ tranh cùng một tên.
package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/blkiodev"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
	mountpkg "github.com/moby/moby/api/types/mount"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/privops"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/resources"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/runtime"
)

const (
	networkName  = "keenrig0"
	labelManaged = "keenrig.managed"
	labelAppID   = "keenrig.com.id"
	labelAppSlug = "keenrig.com.slug"
	labelRev     = "keenrig.com.rev"
	labelReplica = "keenrig.com.replica"
	// labelPort — cổng app nghe bên trong container, đã giải lúc Apply.
	// Xem endpoints.go: Status không có AppSpec nên cổng phải sống trên container.
	labelPort = "keenrig.com.port"

	waitRunningTimeout = 60 * time.Second
	stopTimeoutSec     = 10
	pollInterval       = 250 * time.Millisecond
)

// Driver implement runtime.Runtime trên Docker Engine.
type Driver struct {
	cli    *client.Client
	layout paths.Layout
	// ioDevice — thiết bị block cho trần io, đọc từ EnvIODevice lúc mở. Xem
	// godoc EnvIODevice: nó không tự dò được, và không khai thì trần io không
	// được cấp năng lực thay vì được nhận rồi bỏ qua.
	ioDevice string
	// caps — năng lực ĐO ĐƯỢC của host, dò một lần lúc mở driver.
	//
	// Cache có chủ đích: câu trả lời chỉ đổi khi đổi storage driver hoặc kernel,
	// và cả hai đòi restart dockerd — thứ làm driver này bị dựng lại. Dò mỗi
	// Apply là một lời gọi /info cho mỗi app mỗi 15 giây mà không đổi lấy gì.
	caps resources.Caps
	// chownVolume — đường đặc quyền (sudo appdata.sh chown-volume) cho
	// adoptVolumeOwnership khi os.Chown bị EPERM, tức là mọi box thật: box
	// chạy bằng user keenrig, không có CAP_CHOWN. nil → không có fallback.
	chownVolume func(ctx context.Context, appID, volume string, uid, gid int) error
	// chown — nil → os.Chown. Chỉ test ghi đè, để giả EPERM mà không cần root.
	chown func(name string, uid, gid int) error
}

var _ runtime.Runtime = (*Driver)(nil)

// New kết nối Docker Engine (FromEnv: npipe mặc định trên Windows, unix socket
// trên Linux), Ping kiểm tra daemon sống và đảm bảo network bridge keenrig0.
// New dựng driver KHÔNG có Layout — chỉ dùng cho test không đụng tới volume.
// Đường thật đi qua NewWithLayout.
func New(ctx context.Context) (*Driver, error) {
	return NewWithLayout(ctx, paths.New(""))
}

// NewWithLayout kết nối Docker Engine và neo mọi đường dẫn trên đĩa vào layout.
func NewWithLayout(ctx context.Context, layout paths.Layout) (*Driver, error) {
	cli, err := client.New(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("docker: creating the client: %w", err)
	}
	if _, err := cli.Ping(ctx, client.PingOptions{}); err != nil {
		cli.Close()
		return nil, fmt.Errorf("docker: ping daemon: %w", err)
	}
	d := &Driver{
		cli:         cli,
		layout:      layout,
		ioDevice:    os.Getenv(EnvIODevice),
		chownVolume: privops.NewFromBase(layout.Base()).ChownAppVolume,
	}
	if err := d.ensureNetwork(ctx); err != nil {
		cli.Close()
		return nil, err
	}
	// Dò năng lực hạn mức NGAY lúc mở, và lỗi dò KHÔNG làm việc mở thất bại:
	// nil caps nghĩa là "chưa biết", và Apply xử lý nó bằng cách áp như cũ thay
	// vì từ chối mọi app. Ngược lại sẽ biến một /info tạm hỏng thành mất khả
	// năng deploy hoàn toàn.
	if caps, cerr := d.ResourceCaps(ctx); cerr == nil {
		d.caps = caps
	}
	return d, nil
}

func (d *Driver) Close() error { return d.cli.Close() }

func (d *Driver) ensureNetwork(ctx context.Context) error {
	res, err := d.cli.NetworkList(ctx, client.NetworkListOptions{
		Filters: make(client.Filters).Add("name", networkName),
	})
	if err != nil {
		return fmt.Errorf("docker: list network: %w", err)
	}
	for _, n := range res.Items {
		if n.Name == networkName { // filter "name" match substring — so sánh exact
			return nil
		}
	}
	_, err = d.cli.NetworkCreate(ctx, networkName, client.NetworkCreateOptions{
		Driver: "bridge",
		Labels: map[string]string{labelManaged: "true"},
	})
	if err != nil && !cerrdefs.IsConflict(err) { // conflict = race tạo trùng — network đã có
		return fmt.Errorf("docker: creating network %s: %w", networkName, err)
	}
	return nil
}

// appIDShort — 8 ký tự hex đầu của SHA-256(app.id). Rút gọn để tên container
// vẫn đọc được; SHA-256 (không phải cắt thẳng app.id) để mọi dạng app.id —
// kể cả có ký tự Docker không nhận trong tên — đều cho hậu tố hợp lệ.
func appIDShort(appID string) string {
	sum := sha256.Sum256([]byte(appID))
	return hex.EncodeToString(sum[:4])
}

// containerName — tên deterministic của 1 replica.
//
// Tên PHẢI mang định danh app (appIDShort) chứ không chỉ slug: slug được tái
// dùng sau khi app cũ bị xoá, nên 2 app khác app.id có thể trùng slug + trùng
// rev; nếu tên chỉ dựa vào slug thì cả hai sinh CÙNG một tên và app thứ hai
// không bao giờ deploy được (kẹt lỗi "tên bị chiếm" vĩnh viễn). rev nằm trong
// tên vì RT-03 cần 2 rev đồng tồn tại lúc rolling.
func containerName(appID, slug string, idx int, rev int64) string {
	return fmt.Sprintf("su-%s-%s-%d-r%d", slug, appIDShort(appID), idx, rev)
}

func appLabels(spec runtime.AppSpec, idx, port int) map[string]string {
	return map[string]string{
		labelManaged: "true",
		labelAppID:   spec.ID,
		labelAppSlug: spec.Slug,
		labelRev:     strconv.FormatInt(spec.DesiredRev, 10),
		labelReplica: strconv.Itoa(idx),
		labelPort:    strconv.Itoa(port),
	}
}

// envList map → []string "K=V" sort theo key (ổn định giữa các lần Apply).
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

func replicasOf(spec runtime.AppSpec) int {
	if spec.Desired.Resources == nil || spec.Desired.Resources.Replicas < 1 {
		return 1
	}
	return spec.Desired.Resources.Replicas
}

// resourcesOf dịch `desired.resources` → container.Resources.
//
// # Vì sao mỗi trường có một `if > 0` chứ không gán thẳng
//
// 0 trong container.Resources không phải "0", nó là "không đặt". Gán thẳng
// `res.PidsLimit = &r.PidsLimit` với PidsLimit=0 nghĩa là nói với kernel
// "pids.max = 0" — không process nào chạy được. Ranh giới giữa "người dùng không
// khai" và "người dùng khai 0" phải được giữ ở ĐÚNG chỗ này.
//
// # Vì sao io throttle cần `dev`
//
// cgroup io.max nhận theo THIẾT BỊ (`8:0 wbps=...`), không có dạng "mọi thiết
// bị". Docker nhận đường dẫn block device và tự tra major:minor. Không biết
// thiết bị nào đỡ lớp ghi của container thì không đặt được trần nào — nên `dev`
// rỗng làm hai trường io bị BỎ, và đó là lý do ResourceCaps không khai CapIOBps
// khi dò không ra thiết bị. Hai chỗ đó phải nhất quán, nếu không ta lại có đúng
// thứ package resources tồn tại để chặn: một hạn mức được nhận rồi bỏ qua.
func resourcesOf(spec runtime.AppSpec, dev string) container.Resources {
	var res container.Resources
	r := spec.Desired.Resources
	if r == nil {
		return res
	}
	if r.MemoryMB > 0 {
		res.Memory = int64(r.MemoryMB) << 20
	}
	// MemorySwap là TỔNG mem+swap — cùng ngữ nghĩa với hợp đồng, nên không có
	// phép cộng/trừ nào ở đây. Đo được trên cgroup v2: --memory=64m
	// --memory-swap=128m → memory.max=67108864 và memory.swap.max=67108864,
	// tức kernel nhận phần swap = tổng - mem. Docker làm phép trừ đó, ta không.
	if r.MemorySwapMB > 0 {
		res.MemorySwap = int64(r.MemorySwapMB) << 20
	}
	if r.CPU > 0 {
		res.NanoCPUs = int64(r.CPU * 1e9)
	}
	if r.CPUShares > 0 {
		res.CPUShares = int64(r.CPUShares)
	}
	if r.PidsLimit > 0 {
		limit := int64(r.PidsLimit)
		res.PidsLimit = &limit
	}
	for _, u := range r.Ulimits {
		res.Ulimits = append(res.Ulimits, &container.Ulimit{
			Name: u.Name, Soft: u.Soft, Hard: u.HardOr(),
		})
	}
	applyIOLimits(&res, r, dev)
	return res
}

func applyIOLimits(res *container.Resources, r *contracts.Resources, dev string) {
	if dev == "" {
		return
	}
	throttle := func(rate uint64) []*blkiodev.ThrottleDevice {
		return []*blkiodev.ThrottleDevice{{Path: dev, Rate: rate}}
	}
	if r.IOReadMBps > 0 {
		res.BlkioDeviceReadBps = throttle(uint64(r.IOReadMBps) << 20)
	}
	if r.IOWriteMBps > 0 {
		res.BlkioDeviceWriteBps = throttle(uint64(r.IOWriteMBps) << 20)
	}
	if r.IOReadIOPS > 0 {
		res.BlkioDeviceReadIOps = throttle(uint64(r.IOReadIOPS))
	}
	if r.IOWriteIOPS > 0 {
		res.BlkioDeviceWriteIOps = throttle(uint64(r.IOWriteIOPS))
	}
}

// hostConfigExtras — hai hạn mức KHÔNG nằm trong container.Resources mà nằm
// thẳng trên HostConfig. Chúng ở đây thay vì lẫn vào resourcesOf để chữ ký của
// resourcesOf tiếp tục nói đúng nó trả về cái gì.
func applyHostLimits(hc *container.HostConfig, spec runtime.AppSpec) {
	r := spec.Desired.Resources
	if r == nil {
		return
	}
	if r.ShmSizeMB > 0 {
		hc.ShmSize = int64(r.ShmSizeMB) << 20
	}
	if r.DiskMB > 0 {
		// `size` là tên option của mọi storage driver có quota (overlay2/xfs,
		// btrfs, zfs). Chỉ đặt khi ResourceCaps đã khai CapDiskQuota — Apply
		// chặn trước, xem godoc ResourceCaps về việc cờ này bị NHẬN trong im
		// lặng ở nơi không đỡ nó.
		hc.StorageOpt = map[string]string{"size": strconv.Itoa(r.DiskMB) + "m"}
	}
}

func (d *Driver) listByAppID(ctx context.Context, appID string) ([]container.Summary, error) {
	res, err := d.cli.ContainerList(ctx, client.ContainerListOptions{
		All:     true,
		Filters: make(client.Filters).Add("label", labelAppID+"="+appID),
	})
	if err != nil {
		return nil, fmt.Errorf("docker: list container app=%s: %w", appID, err)
	}
	return res.Items, nil
}

func errObserved(err error) runtime.Observed {
	return runtime.Observed{
		Phase:   contracts.AppStateError,
		Health:  contracts.HealthUnknown,
		Message: err.Error(),
	}
}

func healthFromSummary(c container.Summary) string {
	if c.Health == nil {
		return contracts.HealthUnknown // image không có HEALTHCHECK
	}
	switch c.Health.Status {
	case container.Healthy:
		return contracts.HealthHealthy
	case container.Unhealthy:
		return contracts.HealthUnhealthy
	default: // none / starting
		return contracts.HealthUnknown
	}
}

func healthFromState(st *container.State) string {
	if st == nil || st.Health == nil {
		return contracts.HealthUnknown // image không có HEALTHCHECK
	}
	switch st.Health.Status {
	case container.Healthy:
		return contracts.HealthHealthy
	case container.Unhealthy:
		return contracts.HealthUnhealthy
	default:
		return contracts.HealthUnknown
	}
}

// aggregateHealth gộp health nhiều replica: có unhealthy → unhealthy;
// tất cả healthy → healthy; còn lại (kể cả không healthcheck) → unknown.
func aggregateHealth(healths []string) string {
	if len(healths) == 0 {
		return contracts.HealthUnknown
	}
	allHealthy := true
	for _, h := range healths {
		switch h {
		case contracts.HealthUnhealthy:
			return contracts.HealthUnhealthy
		case contracts.HealthHealthy:
		default:
			allHealthy = false
		}
	}
	if allHealthy {
		return contracts.HealthHealthy
	}
	return contracts.HealthUnknown
}

// ownerAppID đọc label keenrig.com.id của container đã Inspect ("" nếu container
// không mang label — container lạ do người dùng tự đặt tên trùng).
func ownerAppID(ins container.InspectResponse) string {
	if ins.Config == nil {
		return ""
	}
	return ins.Config.Labels[labelAppID]
}

// errNameTaken — tên container đã bị tài nguyên KHÔNG thuộc quyền quản lý của
// app này chiếm (§0.11: danh tính thật = labels, không phải tên). Xảy ra khi
// slug được dùng lại sau khi app cũ bị xoá mà container chưa được dọn, hoặc khi
// người vận hành tự tạo container trùng tên. Driver KHÔNG adopt và KHÔNG xoá
// container của người khác — trả lỗi để reconciler backoff và người vận hành thấy.
func errNameTaken(name, otherID string) error {
	if otherID == "" {
		otherID = "<no keenrig.com.id label>"
	}
	return fmt.Errorf("docker: container name %q is already taken by another app (app.id=%s)", name, otherID)
}

func displayName(c container.Summary) string {
	if len(c.Names) > 0 {
		return strings.TrimPrefix(c.Names[0], "/")
	}
	if len(c.ID) >= 12 {
		return c.ID[:12]
	}
	return c.ID
}

// Apply đưa app về đúng spec. Thuật toán idempotent, new-trước-old:
//
//  1. Tính replicas (nil/0 → 1) và env sorted.
//  2. List ALL theo label app.id → tách current (đúng rev + idx < replicas)
//     và stale (khác rev hoặc idx thừa).
//  3. Fast-path: đủ current Running + không stale → trả kết quả, KHÔNG đụng
//     Docker thêm — Apply lặp lại khi đã hội tụ là no-op.
//  4. Ensure image; pull lỗi → return error, KHÔNG đụng container cũ.
//  5. Ensure từng replica rev mới theo TÊN (tên chứa rev nên rev cũ vẫn chạy
//     song song — bị ngắt giữa chừng thì lần Apply sau adopt lại phần đã tạo).
//     Adopt CHỈ khi label keenrig.com.id khớp spec.ID; tên bị app khác chiếm →
//     lỗi (bất biến: ContainerIDs trả về không bao giờ chứa container của app khác).
//  6. Đợi TẤT CẢ rev mới Running (poll, deadline VÀ ctx); lỗi/timeout →
//     trả lỗi, GIỮ NGUYÊN rev cũ.
//  7. Rev mới ổn định rồi mới Stop+Remove stale.
func (d *Driver) Apply(ctx context.Context, spec runtime.AppSpec) (runtime.Observed, error) {
	// Hạn mức host không thực thi nổi → TỪ CHỐI, không áp một phần rồi báo
	// thành công. Đây là nửa thứ hai của luật ở godoc internal/resources:
	// admission chặn sai-thiết-kế (biết trước, không cần mạng), chỗ này chặn
	// sai-máy — khoảng cách giữa hai thứ đó chính là chỗ `--storage-opt size`
	// lọt qua trên snapshotter overlayfs.
	if err := resources.Enforce(spec.Desired.Resources, d.caps, Name); err != nil {
		return errObserved(err), err
	}
	replicas := replicasOf(spec)
	revStr := strconv.FormatInt(spec.DesiredRev, 10)

	listed, err := d.listByAppID(ctx, spec.ID)
	if err != nil {
		return errObserved(err), err
	}
	current := make(map[int]container.Summary, replicas)
	var stale []container.Summary
	for _, c := range listed {
		idx, idxErr := strconv.Atoi(c.Labels[labelReplica])
		if c.Labels[labelRev] != revStr || idxErr != nil || idx < 0 || idx >= replicas {
			stale = append(stale, c)
			continue
		}
		if _, dup := current[idx]; dup {
			stale = append(stale, c)
			continue
		}
		current[idx] = c
	}

	// Fast-path (idempotency): trạng thái đã đúng hoàn toàn → no-op.
	if len(stale) == 0 && len(current) == replicas {
		ids := make([]string, 0, replicas)
		healths := make([]string, 0, replicas)
		eps := make([]runtime.Endpoint, 0, replicas)
		converged := true
		for idx := 0; idx < replicas; idx++ {
			c := current[idx]
			if c.State != container.StateRunning {
				converged = false
				break
			}
			ids = append(ids, c.ID)
			healths = append(healths, healthFromSummary(c))
			if ep, ok := endpointFromSummary(c, spec.Desired.HTTPPort); ok {
				eps = append(eps, ep)
			}
		}
		if converged {
			return runtime.Observed{
				Phase:        contracts.AppStateRunning,
				Health:       aggregateHealth(healths),
				ContainerIDs: ids,
				Endpoints:    eps,
			}, nil
		}
	}

	if err := d.ensureImage(ctx, spec.Desired.Image); err != nil {
		return errObserved(err), err
	}

	// Giải cổng SAU ensureImage (cần image có mặt để đọc EXPOSE) và MỘT lần cho
	// cả app, rồi đóng vào label từng replica — xem endpoints.go.
	port := d.resolvePort(ctx, spec)

	env := envList(spec.Desired.Env)
	ids := make([]string, replicas)
	for idx := 0; idx < replicas; idx++ {
		id, err := d.ensureReplica(ctx, spec, idx, env, port)
		if err != nil {
			return errObserved(err), err
		}
		ids[idx] = id
	}

	healths, eps, err := d.waitRunning(ctx, spec, ids)
	if err != nil {
		obs := errObserved(err)
		obs.ContainerIDs = ids
		return obs, err
	}

	for _, c := range stale {
		if err := d.stopRemove(ctx, c.ID); err != nil {
			obs := errObserved(err)
			obs.ContainerIDs = ids
			return obs, err
		}
	}

	return runtime.Observed{
		Phase:        contracts.AppStateRunning,
		Health:       aggregateHealth(healths),
		ContainerIDs: ids, // theo thứ tự idx 0..replicas-1
		Endpoints:    eps,
	}, nil
}

// ensureImage: Inspect → NotFound → Pull + Wait (bắt buộc đợi xong) + Close.
func (d *Driver) ensureImage(ctx context.Context, ref string) error {
	_, err := d.cli.ImageInspect(ctx, ref)
	if err == nil {
		return nil
	}
	if !cerrdefs.IsNotFound(err) {
		return fmt.Errorf("docker: inspect image %s: %w", ref, err)
	}
	resp, err := d.cli.ImagePull(ctx, ref, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("docker: pull image %s: %w", ref, err)
	}
	defer resp.Close()
	if err := resp.Wait(ctx); err != nil {
		return fmt.Errorf("docker: pull image %s: %w", ref, err)
	}
	return nil
}

// ensureReplica đảm bảo container tên su-<slug>-<appIDShort>-<idx>-r<rev> tồn tại và đã Start.
// Idempotent theo tên: Running → giữ nguyên; Created/Exited → Start lại
// (Start lỗi → remove + create mới); chưa có → Create+Start; Create đụng 409
// trùng tên (race với Apply trước bị ngắt) → inspect + adopt.
//
// Danh tính = LABEL, không phải tên (§0.11): mỗi lần Inspect-theo-tên PHẢI
// kiểm keenrig.com.id == spec.ID trước khi adopt. Lệch/thiếu label → lỗi
// (không adopt, không xoá của app khác).
func (d *Driver) ensureReplica(ctx context.Context, spec runtime.AppSpec, idx int, env []string, port int) (string, error) {
	name := containerName(spec.ID, spec.Slug, idx, spec.DesiredRev)

	ins, err := d.cli.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	switch {
	case err == nil:
		if owner := ownerAppID(ins.Container); owner != spec.ID {
			return "", errNameTaken(name, owner)
		}
		id := ins.Container.ID
		if st := ins.Container.State; st != nil && st.Status == container.StateRunning {
			return id, nil
		}
		if _, serr := d.cli.ContainerStart(ctx, id, client.ContainerStartOptions{}); serr == nil {
			return id, nil
		}
		// Start lỗi (container hỏng) → remove rồi tạo lại từ đầu.
		if _, rerr := d.cli.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: true}); rerr != nil && !cerrdefs.IsNotFound(rerr) {
			return "", fmt.Errorf("docker: removing broken container %s: %w", name, rerr)
		}
	case !cerrdefs.IsNotFound(err):
		return "", fmt.Errorf("docker: inspect %s: %w", name, err)
	}

	return d.createStart(ctx, spec, idx, name, env, port)
}

func (d *Driver) createStart(ctx context.Context, spec runtime.AppSpec, idx int, name string, env []string, port int) (string, error) {
	mounts, err := d.mountsFor(spec)
	if err != nil {
		return "", err
	}
	hostCfg := &container.HostConfig{
		RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
		Resources:     resourcesOf(spec, d.ioDev()),
		Mounts:        mounts,
	}
	applyHostLimits(hostCfg, spec)
	res, cerr := d.cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: name,
		Config: &container.Config{
			Image:  spec.Desired.Image,
			Env:    env,
			Labels: appLabels(spec, idx, port),
		},
		HostConfig: hostCfg,
		NetworkingConfig: &network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{networkName: {}},
		},
	})
	if cerr != nil {
		if !cerrdefs.IsConflict(cerr) {
			return "", fmt.Errorf("docker: create %s: %w", name, cerr)
		}
		// 409 trùng tên: lần Apply trước bị ngắt sau khi create → adopt,
		// NHƯNG chỉ khi label app.id khớp (§0.11 — danh tính = label).
		ins, ierr := d.cli.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
		if ierr != nil {
			return "", fmt.Errorf("docker: create %s conflicted and the follow-up inspect failed: %w", name, ierr)
		}
		if owner := ownerAppID(ins.Container); owner != spec.ID {
			return "", errNameTaken(name, owner)
		}
		id := ins.Container.ID
		if st := ins.Container.State; st != nil && st.Status == container.StateRunning {
			return id, nil
		}
		// Lần Apply bị ngắt có thể đã dừng giữa create và chown.
		if err := d.adoptVolumeOwnership(ctx, id, spec); err != nil {
			return "", err
		}
		if _, serr := d.cli.ContainerStart(ctx, id, client.ContainerStartOptions{}); serr != nil {
			return "", fmt.Errorf("docker: start container adopt %s: %w", name, serr)
		}
		return id, nil
	}
	// Sau create (mới biết chắc user của container), trước start (app chưa kịp
	// ghi gì) — xem volumeowner.go.
	if err := d.adoptVolumeOwnership(ctx, res.ID, spec); err != nil {
		return "", err
	}
	if _, err := d.cli.ContainerStart(ctx, res.ID, client.ContainerStartOptions{}); err != nil {
		return "", fmt.Errorf("docker: start %s: %w", name, err)
	}
	return res.ID, nil
}

// waitRunning block tới khi TẤT CẢ ids Running (poll pollInterval, deadline
// waitRunningTimeout VÀ tôn trọng ctx). Container Exited/Dead giữa chừng →
// lỗi kèm exit code. Trả health VÀ endpoint từng container (theo thứ tự ids).
//
// Endpoint dựng ở ĐÂY chứ không phải một vòng inspect riêng sau đó: lần
// inspect cuối của vòng đợi đã có đúng thứ cần (State + NetworkSettings +
// Config.ExposedPorts), và IP chỉ có nghĩa khi container đang Running — hỏi
// lại sau là mở thêm một cửa sổ để nó kịp chết giữa hai lần hỏi.
func (d *Driver) waitRunning(ctx context.Context, spec runtime.AppSpec, ids []string) ([]string, []runtime.Endpoint, error) {
	deadline := time.Now().Add(waitRunningTimeout)
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		healths := make([]string, 0, len(ids))
		eps := make([]runtime.Endpoint, 0, len(ids))
		allRunning := true
		for _, id := range ids {
			ins, err := d.cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
			if err != nil {
				return nil, nil, fmt.Errorf("docker: inspect while waiting for running: %w", err)
			}
			st := ins.Container.State
			if st == nil {
				allRunning = false
				break
			}
			switch st.Status {
			case container.StateRunning:
				healths = append(healths, healthFromState(st))
				if ep, ok := endpointFromInspect(ins.Container, spec.Desired.HTTPPort); ok {
					eps = append(eps, ep)
				}
			case container.StateExited, container.StateDead:
				return nil, nil, fmt.Errorf("docker: container %s exited (exit code %d) while waiting for running",
					strings.TrimPrefix(ins.Container.Name, "/"), st.ExitCode)
			default: // created / restarting / paused → đợi tiếp
				allRunning = false
			}
			if !allRunning {
				break
			}
		}
		if allRunning {
			return healths, eps, nil
		}
		if time.Now().After(deadline) {
			return nil, nil, fmt.Errorf("docker: timed out after %s waiting for the container to be Running", waitRunningTimeout)
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// Status — READ-ONLY, quan sát qua labels:
// 0 container → stopped; có Exited(code≠0)/Dead/Restarting → error (kèm tên +
// exit code); tất cả Running → running; có Created → deploying; tất cả
// Exited(0) → stopped.
func (d *Driver) Status(ctx context.Context, appID string) (runtime.Observed, error) {
	listed, err := d.listByAppID(ctx, appID)
	if err != nil {
		return runtime.Observed{Phase: contracts.AppStateUnknown, Health: contracts.HealthUnknown, Message: err.Error()}, err
	}
	if len(listed) == 0 {
		return runtime.Observed{
			Phase:   contracts.AppStateStopped,
			Health:  contracts.HealthUnknown,
			Message: "no containers",
		}, nil
	}

	sort.Slice(listed, func(i, j int) bool { return displayName(listed[i]) < displayName(listed[j]) })

	var (
		ids                             []string
		healths                         []string
		errMsgs                         []string
		eps                             []runtime.Endpoint
		nRunning, nCreated, nExitedZero int
	)
	for _, c := range listed {
		ids = append(ids, c.ID)
		switch c.State {
		case container.StateRunning:
			nRunning++
			healths = append(healths, healthFromSummary(c))
			// Status không có AppSpec: cổng đọc từ label do Apply đóng vào.
			// Không có label (container của bản box cũ) → DefaultHTTPPort.
			if ep, ok := endpointFromSummary(c, 0); ok {
				eps = append(eps, ep)
			}
		case container.StateCreated:
			nCreated++
		case container.StateExited:
			ins, ierr := d.cli.ContainerInspect(ctx, c.ID, client.ContainerInspectOptions{})
			switch {
			case cerrdefs.IsNotFound(ierr):
				// container vừa bị xoá giữa list và inspect — bỏ qua
			case ierr != nil:
				return runtime.Observed{Phase: contracts.AppStateUnknown, Health: contracts.HealthUnknown, Message: ierr.Error()}, ierr
			case ins.Container.State != nil && ins.Container.State.ExitCode != 0:
				errMsgs = append(errMsgs, fmt.Sprintf("%s exited (exit code %d)", displayName(c), ins.Container.State.ExitCode))
			default:
				nExitedZero++
			}
		default: // dead / restarting / paused / removing
			errMsgs = append(errMsgs, fmt.Sprintf("%s %s", displayName(c), c.State))
		}
	}

	obs := runtime.Observed{Health: contracts.HealthUnknown, ContainerIDs: ids, Endpoints: eps}
	if nRunning > 0 {
		obs.Health = aggregateHealth(healths)
	}
	switch {
	case len(errMsgs) > 0:
		obs.Phase = contracts.AppStateError
		obs.Message = strings.Join(errMsgs, "; ")
	case nRunning == len(listed):
		obs.Phase = contracts.AppStateRunning
	case nCreated > 0:
		obs.Phase = contracts.AppStateDeploying
	case nRunning == 0 && nExitedZero > 0:
		obs.Phase = contracts.AppStateStopped
	default:
		obs.Phase = contracts.AppStateDeploying
		obs.Message = "partially running"
	}
	return obs, nil
}

// Remove xoá mọi container của app theo label (Stop rồi Remove Force;
// NotFound → bỏ qua). KHÔNG xoá network keenrig0 (dùng chung). Idempotent:
// không còn gì để xoá → nil.
func (d *Driver) Remove(ctx context.Context, appID string) error {
	listed, err := d.listByAppID(ctx, appID)
	if err != nil {
		return err
	}
	for _, c := range listed {
		if err := d.stopRemove(ctx, c.ID); err != nil {
			return err
		}
	}
	return nil
}

func (d *Driver) stopRemove(ctx context.Context, id string) error {
	sec := stopTimeoutSec
	if _, err := d.cli.ContainerStop(ctx, id, client.ContainerStopOptions{Timeout: &sec}); err != nil && !cerrdefs.IsNotFound(err) {
		return fmt.Errorf("docker: stop %s: %w", id, err)
	}
	if _, err := d.cli.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: true}); err != nil && !cerrdefs.IsNotFound(err) {
		return fmt.Errorf("docker: remove %s: %w", id, err)
	}
	return nil
}

// mountsFor map `desired.volumes` → bind mount THẬT trên máy chủ.
//
// # Ba việc, và việc thứ ba là việc dễ quên nhất
//
//  1. tên volume → đường dẫn máy chủ, QUA paths.AppVolume (lớp kiểm thứ hai)
//  2. tạo thư mục nếu chưa có — Docker sẽ tự tạo, nhưng với quyền của DAEMON
//     (root:root 0755), còn ta muốn quyền của mình và biết chắc nó tồn tại
//     TRƯỚC khi container chạy
//  3. dùng `mountpkg.TypeBind` với `CreateMountpoint`, KHÔNG dùng named volume
//     của Docker
//
// Việc thứ ba là quyết định, không phải chi tiết: named volume của Docker nằm
// trong `/var/lib/docker/volumes/`, tức là NGOÀI `<base>` — và toàn bộ cơ chế
// sao lưu của dự án này gom theo `<base>`. Dùng named volume nghĩa là dữ liệu
// app nằm ngoài tầm với của `keenrig-box backup`, và điều đó chỉ lộ ra lúc
// restore. Bind mount vào `apps/<id>/volumes/<name>` thì được sao lưu MIỄN PHÍ
// bởi phần đã có.
func (d *Driver) mountsFor(spec runtime.AppSpec) ([]mountpkg.Mount, error) {
	if len(spec.Desired.Volumes) == 0 {
		return nil, nil
	}
	out := make([]mountpkg.Mount, 0, len(spec.Desired.Volumes))
	for _, v := range spec.Desired.Volumes {
		host, err := d.layout.AppVolume(spec.ID, v.Name)
		if err != nil {
			return nil, fmt.Errorf("docker: volume %q of app %s: %w", v.Name, spec.ID, err)
		}
		if err := os.MkdirAll(host, 0o755); err != nil {
			return nil, fmt.Errorf("docker: creating volume directory %s: %w", host, err)
		}
		out = append(out, mountpkg.Mount{
			Type:     mountpkg.TypeBind,
			Source:   host,
			Target:   v.Path,
			ReadOnly: v.ReadOnly,
			BindOptions: &mountpkg.BindOptions{
				// Thư mục vừa được tạo ở trên, nhưng cờ này là lưới an toàn cho
				// ca đua: nếu có ai xoá nó giữa hai dòng, Docker tạo lại thay vì
				// từ chối khởi động app.
				CreateMountpoint: true,
			},
		})
	}
	return out, nil
}
