// Package infradocker — `addons.InfraRuntime` trên Docker Engine.
//
// # Vì sao KHÔNG nằm trong runtime/driver/docker
//
// Nó dựng container, giống driver runtime — nhưng container hạ tầng và container
// app khác nhau ở ba điểm khiến gộp chung là sai:
//
//	danh tính   app: label keenrig.com.id (nhiều replica, có rev, rolling)
//	            hạ tầng: MỘT container theo TÊN, không rev, không rolling
//	vòng đời    app: level-triggered theo desired của người dùng
//	            hạ tầng: chỉ dựng lại khi INFRA_VERSION bump
//	ai gỡ       app: reconciler khi người dùng xoá app
//	            hạ tầng: driver addon, khi app CUỐI CÙNG dùng nó bị xoá
//
// Gộp lại nghĩa là `runtime.Apply` phải phân biệt hai loại, và mọi driver
// runtime tương lai (swarm, k8s) phải hiểu cả hai. Tách ra thì thêm addon không
// đụng gì tới đường app.
//
// Nhãn `keenrig.infra` phân định rõ: reconciler chỉ đụng container mang
// `keenrig.com.id`, nên nó không bao giờ gỡ nhầm container hạ tầng — và ngược lại.
package infradocker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/addons"
)

const (
	// networkName — CÙNG network với container app. Bắt buộc: app phải phân giải
	// được tên container hạ tầng qua DNS nội bộ của Docker.
	networkName = "keenrig0"

	labelManaged = "keenrig.managed"
	// labelInfra — nhãn phân định container HẠ TẦNG với container APP.
	//
	// Reconciler chỉ đụng container mang `keenrig.com.id`; nhờ nhãn này, một
	// container postgres không bao giờ bị hiểu là "app mồ côi cần dọn".
	labelInfra = "keenrig.infra"
	// labelInfraVersion — bump INFRA_VERSION là tín hiệu DUY NHẤT bắt dựng lại.
	labelInfraVersion = "keenrig.infra.version"

	namePrefix = "su-infra-"

	startTimeout = 60 * time.Second
	pollInterval = 250 * time.Millisecond
)

type Runtime struct {
	cli *client.Client
}

var _ addons.InfraRuntime = (*Runtime)(nil)

// New mở client Docker từ môi trường.
func New() (*Runtime, error) {
	cli, err := client.New(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("infradocker: opening the client: %w", err)
	}
	return &Runtime{cli: cli}, nil
}

// NewWithClient để test cắm client riêng.
func NewWithClient(cli *client.Client) *Runtime { return &Runtime{cli: cli} }

func (r *Runtime) Close() error { return r.cli.Close() }

// Ping hỏi daemon còn sống không.
//
// # Vì sao cần hàm này chứ không dò chuỗi lỗi
//
// `client.New` KHÔNG kết nối — nó chỉ dựng client. Lỗi kết nối lộ ra ở lời gọi
// đầu tiên, và test muốn SKIP (chứ không FAIL) khi không có Docker phải phân
// biệt "daemon không chạy" với "driver hỏng".
//
// Bản đầu dò chuỗi `"cannot connect"` trong thông báo lỗi. Thông báo thật là
// `"failed to connect to the docker API at …"` — nên phép dò không khớp, và cả
// bộ test ĐỎ ở nơi đáng ra chỉ SKIP. Dò chuỗi lỗi của thư viện khác là thứ
// hỏng đúng vào lúc thư viện đó sửa câu chữ.
func (r *Runtime) Ping(ctx context.Context) error {
	if _, err := r.cli.Ping(ctx, client.PingOptions{}); err != nil {
		return fmt.Errorf("infradocker: the daemon did not respond: %w", err)
	}
	return nil
}

func containerName(name string) string { return namePrefix + name }

// EnsureInfra dựng container hạ tầng, hoặc xác nhận nó đã chạy. Idempotent.
//
// Ready ở đây nghĩa là CONTAINER ĐANG CHẠY — không phải "service nhận kết nối".
// Phân biệt đó có chủ đích: "postgres nhận kết nối chưa" là câu chỉ driver
// postgres trả lời được (`pg_isready`), và nhồi nó vào đây nghĩa là runtime phải
// biết cách kiểm sẵn sàng của mọi addon sẽ có trong tương lai.
func (r *Runtime) EnsureInfra(ctx context.Context, spec addons.InfraSpec) (addons.InfraStatus, error) {
	if err := r.ensureNetwork(ctx); err != nil {
		return addons.InfraStatus{}, err
	}
	name := containerName(spec.Name)

	ins, err := r.cli.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	switch {
	case err == nil:
		got := ins.Container.Config.Labels[labelInfraVersion]
		want := strconv.Itoa(spec.InfraVersion)
		if got != want {
			// INFRA_VERSION đổi → dựng lại. Đây là ĐƯỜNG DUY NHẤT container hạ
			// tầng bị thay: không có nó thì nâng cấp image là hệ quả ngẫu nhiên
			// của việc một tag bị đẩy lại.
			if _, rerr := r.cli.ContainerRemove(ctx, ins.Container.ID,
				client.ContainerRemoveOptions{Force: true}); rerr != nil && !cerrdefs.IsNotFound(rerr) {
				return addons.InfraStatus{}, fmt.Errorf("infradocker: removing %s in order to recreate it: %w", name, rerr)
			}
			break
		}
		if st := ins.Container.State; st != nil && st.Status == container.StateRunning {
			return r.statusOf(ctx, spec, name)
		}
		if _, serr := r.cli.ContainerStart(ctx, ins.Container.ID, client.ContainerStartOptions{}); serr == nil {
			return r.waitRunning(ctx, spec, name)
		}
		// Start lỗi → container hỏng, dựng lại.
		if _, rerr := r.cli.ContainerRemove(ctx, ins.Container.ID,
			client.ContainerRemoveOptions{Force: true}); rerr != nil && !cerrdefs.IsNotFound(rerr) {
			return addons.InfraStatus{}, fmt.Errorf("infradocker: removing broken %s: %w", name, rerr)
		}
	case !cerrdefs.IsNotFound(err):
		return addons.InfraStatus{}, fmt.Errorf("infradocker: inspect %s: %w", name, err)
	}

	if err := r.create(ctx, spec, name); err != nil {
		return addons.InfraStatus{}, err
	}
	return r.waitRunning(ctx, spec, name)
}

func (r *Runtime) create(ctx context.Context, spec addons.InfraSpec, name string) error {
	env := make([]string, 0, len(spec.Env))
	for k, v := range spec.Env {
		env = append(env, k+"="+v)
	}
	sort.Strings(env) // thứ tự ổn định để diff container dễ đọc

	var mounts []mount.Mount
	if spec.DataDir != "" {
		mounts = append(mounts, mount.Mount{
			Type: mount.TypeBind, Source: spec.DataDir, Target: dataTarget(spec.Name),
		})
	}

	if err := r.pull(ctx, spec.Image.Ref()); err != nil {
		return err
	}

	_, err := r.cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: name,
		Config: &container.Config{
			Image: spec.Image.Ref(),
			Cmd:   spec.Cmd,
			Env:   env,
			Labels: map[string]string{
				labelManaged:      "true",
				labelInfra:        spec.Name,
				labelInfraVersion: strconv.Itoa(spec.InfraVersion),
			},
		},
		HostConfig: &container.HostConfig{
			// unless-stopped: container hạ tầng phải lên lại sau khi máy reboot,
			// TRƯỚC khi box kịp gọi EnsureInfra. Không có nó thì mọi app đều
			// thấy "addon chưa sẵn sàng" trong vài chục giây đầu sau reboot.
			RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
			Mounts:        mounts,
		},
		NetworkingConfig: &network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{
				// Alias = tên logic (vd "postgres"), KHÔNG phải tên container.
				// App kết nối tới "postgres", và nhờ alias nó không cần biết
				// tiền tố su-infra-.
				networkName: {Aliases: []string{spec.Name}},
			},
		},
	})
	if err != nil && !cerrdefs.IsConflict(err) {
		return fmt.Errorf("infradocker: create %s: %w", name, err)
	}
	if _, err := r.cli.ContainerStart(ctx, name, client.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("infradocker: start %s: %w", name, err)
	}
	return nil
}

// dataTarget — điểm mount trong container, theo quy ước của từng image.
//
// Bảng cứng chứ không tham số: nó là sự thật của IMAGE, không phải lựa chọn của
// ta. Đặt vào InfraSpec sẽ mời gọi mỗi chỗ gọi tự đoán một giá trị.
func dataTarget(name string) string {
	switch name {
	case "postgres":
		return "/var/lib/postgresql/data"
	default:
		// redis và phần còn lại: /data là quy ước của gần như mọi image chính thống.
		return "/data"
	}
}

func (r *Runtime) pull(ctx context.Context, ref string) error {
	rc, err := r.cli.ImagePull(ctx, ref, client.ImagePullOptions{})
	if err != nil {
		// Image đã có sẵn thì pull lỗi cũng không sao — create sẽ cho biết.
		return nil //nolint:nilerr // xem chú thích trên
	}
	defer rc.Close()
	_, _ = io.Copy(io.Discard, rc) // phải đọc hết, nếu không pull bị hủy giữa đường
	return nil
}

func (r *Runtime) ensureNetwork(ctx context.Context) error {
	res, err := r.cli.NetworkList(ctx, client.NetworkListOptions{
		Filters: make(client.Filters).Add("name", networkName),
	})
	if err != nil {
		return fmt.Errorf("infradocker: list network: %w", err)
	}
	for _, n := range res.Items {
		if n.Name == networkName { // filter "name" khớp chuỗi con — so sánh exact
			return nil
		}
	}
	if _, err := r.cli.NetworkCreate(ctx, networkName, client.NetworkCreateOptions{
		Driver: "bridge",
		Labels: map[string]string{labelManaged: "true"},
	}); err != nil && !cerrdefs.IsConflict(err) {
		return fmt.Errorf("infradocker: creating network %s: %w", networkName, err)
	}
	return nil
}

func (r *Runtime) waitRunning(ctx context.Context, spec addons.InfraSpec, name string) (addons.InfraStatus, error) {
	deadline := time.Now().Add(startTimeout)
	for {
		st, err := r.statusOf(ctx, spec, name)
		if err == nil && st.Ready {
			return st, nil
		}
		if time.Now().After(deadline) {
			msg := "timed out waiting for the container to come up"
			if err != nil {
				msg = err.Error()
			} else if st.Message != "" {
				msg = st.Message
			}
			return addons.InfraStatus{Message: msg}, nil
		}
		select {
		case <-ctx.Done():
			return addons.InfraStatus{Message: ctx.Err().Error()}, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

func (r *Runtime) statusOf(ctx context.Context, spec addons.InfraSpec, name string) (addons.InfraStatus, error) {
	ins, err := r.cli.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if err != nil {
		return addons.InfraStatus{Message: "the container does not exist yet"}, err
	}
	st := ins.Container.State
	if st == nil || st.Status != container.StateRunning {
		status := "unknown"
		if st != nil {
			status = string(st.Status)
		}
		return addons.InfraStatus{Message: "the container is in state " + status}, nil
	}
	// Host = ALIAS trên network, không phải IP.
	//
	// IP container đổi mỗi lần dựng lại; một URL kết nối mang IP sẽ thành sai
	// sau lần restart đầu tiên, và app chỉ phát hiện lúc mất kết nối. DNS nội bộ
	// của Docker phân giải alias, nên tên là thứ ổn định.
	return addons.InfraStatus{Host: spec.Name, Port: spec.Port, Ready: true}, nil
}

// RemoveInfra gỡ container hạ tầng. Idempotent.
func (r *Runtime) RemoveInfra(ctx context.Context, name string) error {
	_, err := r.cli.ContainerRemove(ctx, containerName(name),
		client.ContainerRemoveOptions{Force: true, RemoveVolumes: false})
	if err != nil && !cerrdefs.IsNotFound(err) {
		return fmt.Errorf("infradocker: removing %s: %w", name, err)
	}
	return nil
}

// Exec chạy lệnh trong container hạ tầng.
//
// Stdin được đẩy vào rồi ĐÓNG: `psql` đọc tới EOF, và không đóng nghĩa là nó
// chờ mãi — triệu chứng là "thao tác addon treo", không phải một lỗi.
func (r *Runtime) Exec(ctx context.Context, spec addons.ExecSpec) (addons.ExecResult, error) {
	name := containerName(spec.Name)

	env := make([]string, 0, len(spec.Env))
	for k, v := range spec.Env {
		env = append(env, k+"="+v)
	}
	sort.Strings(env)

	created, err := r.cli.ExecCreate(ctx, name, client.ExecCreateOptions{
		Cmd:          spec.Cmd,
		Env:          env,
		AttachStdin:  len(spec.Stdin) > 0,
		AttachStdout: true,
		AttachStderr: true,
		// TTY = false có chủ đích: chỉ khi KHÔNG có TTY thì Docker ghép
		// stdout/stderr với header 8 byte, và chỉ khi có header thì ta tách được
		// hai luồng. Bật TTY nghĩa là stderr lẫn vào stdout — với `pg_dump -Fc`
		// thì một dòng cảnh báo làm bản dump hỏng theo cách chỉ lộ ra lúc restore.
		TTY: false,
	})
	if err != nil {
		return addons.ExecResult{}, fmt.Errorf("infradocker: exec create on %s: %w", name, err)
	}

	att, err := r.cli.ExecAttach(ctx, created.ID, client.ExecAttachOptions{})
	if err != nil {
		return addons.ExecResult{}, fmt.Errorf("infradocker: exec attach: %w", err)
	}
	defer att.Close()

	if len(spec.Stdin) > 0 {
		if _, err := att.Conn.Write(spec.Stdin); err != nil {
			return addons.ExecResult{}, fmt.Errorf("infradocker: ghi stdin: %w", err)
		}
		// CloseWrite chứ không Close: đóng cả kết nối sẽ mất luôn stdout.
		if cw, ok := att.Conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}

	var stdout, stderr bytes.Buffer
	if err := demux(att.Reader, &stdout, &stderr); err != nil {
		return addons.ExecResult{}, fmt.Errorf("infradocker: reading the exec output: %w", err)
	}

	insp, err := r.cli.ExecInspect(ctx, created.ID, client.ExecInspectOptions{})
	if err != nil {
		return addons.ExecResult{}, fmt.Errorf("infradocker: exec inspect: %w", err)
	}
	return addons.ExecResult{
		Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: insp.ExitCode,
	}, nil
}

// demux tách stdout/stderr khỏi luồng ghép của Docker.
//
// Docker ghép hai luồng vào một kết nối với header 8 byte mỗi khung
// (stream, 0,0,0, size uint32 big-endian). Đọc thẳng mà không tách nghĩa là
// stdout của ta lẫn cả header nhị phân — và với `pg_dump -Fc` thì bản dump hỏng
// theo cách chỉ lộ ra lúc restore.
func demux(r io.Reader, stdout, stderr io.Writer) error {
	header := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return err
		}
		size := int64(header[4])<<24 | int64(header[5])<<16 | int64(header[6])<<8 | int64(header[7])
		dst := stdout
		if header[0] == 2 {
			dst = stderr
		}
		if _, err := io.CopyN(dst, r, size); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// InfraName trả tên container hạ tầng — cho test và cho lệnh chẩn đoán.
func InfraName(name string) string { return containerName(name) }

// IsManaged cho biết một tên container có phải hạ tầng của platform.
func IsManaged(name string) bool { return strings.HasPrefix(name, namePrefix) }
