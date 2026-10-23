package docker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime"
	"github.com/keenrig/keenrig/keenrig-node/internal/runtime/runtimetest"
	"github.com/moby/moby/client"
)

// Gate CHƯA CÓ TÊN trong đặc tả: *app ghi file → cập nhật app → file còn nguyên*.
//
// Rà soát trước M3 không bắt được lỗ này, và nó là lỗ lớn nhất còn lại: không
// testcase nào trong bộ đặc tả kiểm thử phủ chuyện lưu trữ file cho
// app. `IM-01` có nhắc `named volume`, nhưng nó bảo parser đọc volume VÀO
// `desired` — mà `desired` trước hôm nay không có trường đó, nên nó map vào hư
// không.
//
// Chạy trên Docker THẬT. Tự SKIP khi không có Docker, có lý do.

func newDriverAt(t *testing.T, base string) *Driver {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d, err := NewWithLayout(ctx, paths.New(base))
	if err != nil {
		t.Skipf("Docker không khả dụng — skip: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// Khẳng định trung tâm: dữ liệu app SỐNG QUA một lần đổi revision.
//
// Vòng đời container là "vứt cái cũ, dựng cái mới từ image gốc" — nên nếu không
// có volume, mọi thứ app ghi đều biến mất ở lần cập nhật đầu tiên. Đó chính là
// trạng thái của nền tảng TRƯỚC hôm nay, và không có gì đỏ để nhìn thấy.
func TestAppDataSurvivesRedeploy(t *testing.T) {
	base := t.TempDir()
	d := newDriverAt(t, base)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	const appID = "11111111-2222-4333-8444-555555555555"
	spec := runtime.AppSpec{
		ID: appID, Slug: "ghi-file", DesiredRev: 1,
		Desired: contracts.DesiredApp{
			Image:   runtimetest.TestImage,
			Volumes: []contracts.VolumeMount{{Name: "data", Path: "/data"}},
			Env:     map[string]string{"KEEP": "1"},
		},
	}
	t.Cleanup(func() { _ = d.Remove(context.Background(), appID) })
	if _, err := d.Apply(ctx, spec); err != nil {
		t.Fatalf("Apply rev 1: %v", err)
	}

	// Ghi vào ĐÚNG thư mục máy chủ mà volume trỏ tới — đó là thứ app sẽ thấy.
	hostDir, err := paths.New(base).AppVolume(appID, "data")
	if err != nil {
		t.Fatal(err)
	}
	if fi, serr := os.Stat(hostDir); serr != nil || !fi.IsDir() {
		t.Fatalf("thư mục volume KHÔNG được tạo lúc Apply: %v", serr)
	}
	const body = "bai viet cua nguoi dung"
	if err := os.WriteFile(filepath.Join(hostDir, "noi-dung.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	// Container của rev 1 phải ĐANG nối vào đúng thư mục đó.
	srcRev1 := mountSourceOf(t, appID, "/data")
	if srcRev1 != hostDir {
		t.Fatalf("rev 1 nối vào %q, muốn %q", srcRev1, hostDir)
	}

	// CẬP NHẬT app: đổi revision → container mới hoàn toàn.
	spec.DesiredRev = 2
	spec.Desired.Env["KEEP"] = "2"
	if _, err := d.Apply(ctx, spec); err != nil {
		t.Fatalf("Apply rev 2: %v", err)
	}

	// Hai khẳng định, và khẳng định THỨ HAI mới là khẳng định thật.
	//
	// Chỉ đọc lại file trên máy chủ là một test tự lừa mình: thư mục đó không ai
	// xoá, nên nó "sống sót" kể cả khi container mới KHÔNG hề được nối vào —
	// tức là kể cả khi app mất sạch dữ liệu. Đã kiểm: bỏ dòng dựng mount ra thì
	// phép đọc file vẫn xanh. Phép so nguồn mount thì đỏ.
	got, err := os.ReadFile(filepath.Join(hostDir, "noi-dung.txt"))
	if err != nil || string(got) != body {
		t.Fatalf("dữ liệu MẤT sau khi đổi revision: %q, %v", got, err)
	}
	if src := mountSourceOf(t, appID, "/data"); src != hostDir {
		t.Fatalf("container rev 2 nối vào %q, muốn %q — app mới KHÔNG thấy dữ liệu cũ", src, hostDir)
	}
}

// mountSourceOf trả đường dẫn máy chủ mà container ĐANG CHẠY của app nối vào
// target, đọc từ `docker inspect`.
//
// Hỏi Docker chứ không đọc lại cấu trúc ta vừa dựng: một test đọc lại chính đầu
// vào của mình thì không chứng minh Docker đã nhận nó.
func mountSourceOf(t *testing.T, appID, target string) string {
	t.Helper()
	cli := rawClient(t)
	items := listByLabel(t, cli, appID)
	if len(items) == 0 {
		t.Fatalf("không có container nào cho app %s", appID)
	}
	ins, err := cli.ContainerInspect(context.Background(), items[0].ID, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ins.Container.Mounts {
		if m.Destination == target {
			return m.Source
		}
	}
	return ""
}

// Mount phải THẬT SỰ tới được bên trong container, và đúng đường dẫn đã khai.
//
// Kiểm bằng `docker inspect` chứ không bằng cờ ta tự đặt: một test đọc lại chính
// cấu trúc mình vừa dựng thì không chứng minh Docker đã nhận nó.
func TestVolumeReachesTheContainer(t *testing.T) {
	base := t.TempDir()
	d := newDriverAt(t, base)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	const appID = "22222222-2222-4333-8444-555555555555"
	spec := runtime.AppSpec{
		ID: appID, Slug: "mount-that", DesiredRev: 1,
		Desired: contracts.DesiredApp{
			Image: runtimetest.TestImage,
			Volumes: []contracts.VolumeMount{
				{Name: "uploads", Path: "/var/uploads"},
				{Name: "chi-doc", Path: "/etc/app-config", ReadOnly: true},
			},
		},
	}
	t.Cleanup(func() { _ = d.Remove(context.Background(), appID) })
	if _, err := d.Apply(ctx, spec); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	cli := rawClient(t)
	items := listByLabel(t, cli, appID)
	if len(items) == 0 {
		t.Fatal("không có container nào")
	}
	ins, err := cli.ContainerInspect(ctx, items[0].ID, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}

	byTarget := map[string]struct {
		src string
		rw  bool
	}{}
	for _, m := range ins.Container.Mounts {
		byTarget[m.Destination] = struct {
			src string
			rw  bool
		}{m.Source, m.RW}
	}

	up, ok := byTarget["/var/uploads"]
	if !ok {
		t.Fatalf("Docker KHÔNG nhận mount /var/uploads; có: %v", byTarget)
	}
	// Nguồn phải nằm dưới apps/<id>/volumes/ — không phải trong
	// /var/lib/docker/volumes, vì chỗ đó nằm NGOÀI <base> và sẽ không được
	// `keenrig-box backup` gom.
	wantPrefix, _ := paths.New(base).AppVolumesDir(appID)
	if !strings.HasPrefix(up.src, wantPrefix) {
		t.Errorf("nguồn mount = %q, muốn nằm dưới %q — ngoài <base> thì backup không gom được", up.src, wantPrefix)
	}
	if !up.rw {
		t.Error("volume mặc định phải ghi được")
	}
	if ro, ok := byTarget["/etc/app-config"]; !ok {
		t.Error("thiếu mount chỉ-đọc")
	} else if ro.rw {
		t.Error("read_only:true nhưng Docker nhận là ghi được")
	}
}

// App KHÔNG khai volume thì không có mount nào — không tự bịa ra thư mục.
func TestNoVolumesMeansNoMounts(t *testing.T) {
	base := t.TempDir()
	d := newDriverAt(t, base)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	const appID = "33333333-2222-4333-8444-555555555555"
	spec := runtime.AppSpec{
		ID: appID, Slug: "khong-volume", DesiredRev: 1,
		Desired: contracts.DesiredApp{Image: runtimetest.TestImage},
	}
	t.Cleanup(func() { _ = d.Remove(context.Background(), appID) })
	if _, err := d.Apply(ctx, spec); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	cli := rawClient(t)
	items := listByLabel(t, cli, appID)
	ins, err := cli.ContainerInspect(ctx, items[0].ID, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(ins.Container.Mounts); n != 0 {
		t.Errorf("app không khai volume mà có %d mount: %v", n, ins.Container.Mounts)
	}
}

// Tên volume độc hại KHÔNG được thoát khỏi thư mục của app — kiểm ở tầng driver,
// không dựa vào schema đã chặn ở tầng trên.
//
// Hai lớp, vì luật ở tầng trên có thể bị nới ra sau này và đường đi tới đây có
// nhiều nguồn (desired của người dùng, importer, API tương lai).
func TestMaliciousVolumeNameCannotEscape(t *testing.T) {
	base := t.TempDir()
	d := newDriverAt(t, base)

	for _, name := range []string{"..", "../../instance", "a/b", `a\b`, "", "."} {
		_, err := d.mountsFor(runtime.AppSpec{
			ID: "44444444-2222-4333-8444-555555555555",
			Desired: contracts.DesiredApp{
				Image:   runtimetest.TestImage,
				Volumes: []contracts.VolumeMount{{Name: name, Path: "/d"}},
			},
		})
		if err == nil {
			t.Errorf("tên volume %q được chấp nhận — nó đi thẳng vào đường dẫn máy chủ", name)
		}
	}
}

// SEC-05 nửa thứ nhất: container app KHÔNG BAO GIỜ có `docker.sock`.
//
// # Vì sao khẳng định này phải nằm ở ĐÂY, cạnh code dựng mount
//
// Trước khi có `volumes`, câu này đúng một cách tầm thường: driver không dựng
// mount nào cả. Đúng-vì-chưa-có-tính-năng là loại đúng biến mất im lặng — và nó
// biến mất ĐÚNG LÚC ai đó thêm mount thứ hai mà không nghĩ tới.
//
// Một container có `/var/run/docker.sock` là một container ĐIỀU KHIỂN ĐƯỢC
// DOCKER: nó tạo được container mới với `--privileged`, mount được `/` của máy
// chủ, đọc được `instance/master.key`. Cách ly ở mọi tầng khác trở thành vô
// nghĩa. Đây không phải leo thang đặc quyền — đây là trao thẳng máy chủ.
func TestAppContainerNeverGetsDockerSocket(t *testing.T) {
	base := t.TempDir()
	d := newDriverAt(t, base)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	const appID = "55555555-2222-4333-8444-555555555555"
	// App CỐ TÌNH xin: tên volume hợp lệ, nhưng đường dẫn đích là chính socket.
	// Đích nằm phía CONTAINER nên schema không cấm — cái cấm nó là nguồn mount
	// luôn nằm dưới apps/<id>/volumes/, không bao giờ là socket thật.
	spec := runtime.AppSpec{
		ID: appID, Slug: "xin-socket", DesiredRev: 1,
		Desired: contracts.DesiredApp{
			Image: runtimetest.TestImage,
			Volumes: []contracts.VolumeMount{
				{Name: "sock", Path: "/var/run/docker.sock"},
				{Name: "data", Path: "/data"},
			},
		},
	}
	t.Cleanup(func() { _ = d.Remove(context.Background(), appID) })
	if _, err := d.Apply(ctx, spec); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	cli := rawClient(t)
	items := listByLabel(t, cli, appID)
	ins, err := cli.ContainerInspect(ctx, items[0].ID, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	volumesDir, _ := paths.New(base).AppVolumesDir(appID)
	for _, m := range ins.Container.Mounts {
		// NGUỒN là thứ quyết định. Một app đặt tên ĐÍCH là "/var/run/docker.sock"
		// chỉ tự làm hỏng chính nó — nó nhận một THƯ MỤC RỖNG ở đó, không phải
		// socket của daemon.
		low := strings.ToLower(m.Source)
		if strings.Contains(low, "docker.sock") || strings.Contains(low, "docker_engine") {
			t.Fatalf("container app được mount THẲNG socket của Docker: %s → %s", m.Source, m.Destination)
		}
		if !strings.HasPrefix(m.Source, volumesDir) {
			t.Errorf("mount nguồn %q nằm NGOÀI %q — mọi mount của app phải bị nhốt trong đó",
				m.Source, volumesDir)
		}
	}
}

// Bất biến tổng quát hơn, và không cần daemon: MỌI mount sinh ra đều nằm dưới
// `apps/<id>/volumes/`, bất kể app khai gì.
//
// Test trên kể tên `docker.sock`; test này thì không kể tên gì cả. Một danh sách
// cấm (docker.sock, /etc, /root…) luôn thiếu một mục; một bất biến thì không.
func TestEveryMountSourceStaysInsideTheAppDirectory(t *testing.T) {
	base := t.TempDir()
	d := &Driver{layout: paths.New(base)} // phép kiểm này không đụng daemon
	const appID = "66666666-2222-4333-8444-555555555555"

	mounts, err := d.mountsFor(runtime.AppSpec{
		ID: appID,
		Desired: contracts.DesiredApp{
			Image: runtimetest.TestImage,
			Volumes: []contracts.VolumeMount{
				{Name: "a", Path: "/var/run/docker.sock"},
				{Name: "b", Path: "/etc"},
				{Name: "c", Path: "/root/.ssh"},
			},
		},
	})
	if err != nil {
		t.Fatalf("mountsFor: %v", err)
	}
	volumesDir, _ := paths.New(base).AppVolumesDir(appID)
	for _, m := range mounts {
		if !strings.HasPrefix(m.Source, volumesDir) {
			t.Errorf("nguồn %q thoát khỏi %q", m.Source, volumesDir)
		}
	}
	if len(mounts) != 3 {
		t.Errorf("có %d mount, muốn 3 — mọi khai báo hợp lệ đều phải được dựng", len(mounts))
	}
}
