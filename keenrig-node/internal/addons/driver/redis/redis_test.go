package redis

// Conformance AD-01..04 + BK-01/05 trên REDIS THẬT trong Docker.
//
// # Đây là phép thử thật cho seam
//
// Driver này có kiến trúc NGƯỢC postgres: một container mỗi app, `Teardown` gỡ
// hẳn container. Nó chạy ĐÚNG bộ `addontest.RunConformance` mà postgres chạy,
// KHÔNG có cờ nào, KHÔNG có subtest nào bị bỏ.
//
// Nếu suite phải sửa để driver này pass thì suite đang phát biểu khẳng định ở
// tầng sai — và đó là thông tin quan trọng hơn cả việc driver có pass hay không.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/addons"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/addons/addontest"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/addons/infradocker"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// infraJSONPath — CÙNG file mà bản phát hành ship. Viết cứng digest trong test
// nghĩa là test xanh trong khi bản ship dùng image khác.
const infraJSONPath = "../../../../addon-images/infra.json"

type infraFile struct {
	InfraVersion int                           `json:"infra_version"`
	Images       map[string]addons.PinnedImage `json:"images"`
}

// appsUsed — app id mà conformance dùng. Phải dọn container của TỪNG cái, vì
// mỗi app có container riêng (khác postgres: một container cho tất cả).
var appsUsed = []string{"conf-app-a", "conf-app-b"}

// sharedBase — thư mục dữ liệu dùng chung cả binary test.
//
// Cùng lý do như ở driver postgres: bind mount cố định lúc container được TẠO,
// nên cấp một t.TempDir() mới cho mỗi subtest sẽ làm container mount một thư mục
// đã bị xoá. Với redis thì mỗi app có thư mục con riêng dưới base này.
var sharedBase string

func TestMain(m *testing.M) {
	d, err := os.MkdirTemp("", "keenrig-redis-conformance-")
	if err != nil {
		panic(err)
	}
	sharedBase = d
	cleanupInfra()
	code := m.Run()
	cleanupInfra()
	_ = os.RemoveAll(sharedBase)
	os.Exit(code)
}

func cleanupInfra() {
	rt, err := infradocker.New()
	if err != nil {
		return
	}
	defer func() { _ = rt.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if rt.Ping(ctx) != nil {
		return
	}
	for _, app := range appsUsed {
		_ = rt.RemoveInfra(ctx, infraName(app))
	}
}

func loadInfra(t *testing.T) infraFile {
	t.Helper()
	raw, err := os.ReadFile(infraJSONPath)
	if err != nil {
		t.Fatalf("đọc %s: %v", infraJSONPath, err)
	}
	var f infraFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func newDriver(t *testing.T) addons.Addon {
	t.Helper()
	if os.Getenv("KEENRIG_SKIP_DOCKER") != "" {
		t.Skip("KEENRIG_SKIP_DOCKER đặt — bỏ qua test cần Docker")
	}
	rt, err := infradocker.New()
	if err != nil {
		t.Skipf("không mở được Docker: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rt.Ping(ctx); err != nil {
		t.Skipf("Docker daemon không chạy: %v", err)
	}

	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "platform.db"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	f := loadInfra(t)
	d, err := New(addons.Config{
		Layout:       paths.New(sharedBase),
		Store:        st,
		Runtime:      rt,
		InfraVersion: f.InfraVersion,
		Images:       f.Images,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Dọn container + thư mục dữ liệu sau MỖI subtest.
	//
	// Bắt buộc vì store là mới mỗi subtest nhưng container thì không: một
	// container sót lại chạy với mật khẩu của store CŨ, và subtest sau không nói
	// chuyện được với nó — triệu chứng là "NOAUTH" ở một chỗ trông như lỗi driver.
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		for _, app := range appsUsed {
			_ = rt.RemoveInfra(c, infraName(app))
			if p, err := paths.New(sharedBase).AddonData(infraName(app)); err == nil {
				_ = os.RemoveAll(p)
			}
		}
	})
	return d
}

func TestRedisConformance(t *testing.T) {
	if testing.Short() {
		t.Skip("bỏ qua ở chế độ -short (cần Docker)")
	}
	addontest.RunConformance(t, newDriver)
}

// --- test riêng: những điều conformance KHÔNG kiểm được ------------------------------

// Mật khẩu KHÔNG được nằm trong Cmd hay Env của container.
//
// `docker inspect` hiện cả hai, và nó chạy được bởi bất kỳ ai trong nhóm docker.
// Đây là lý do redis đọc mật khẩu từ file cấu hình trong thư mục dữ liệu.
func TestPasswordNotInContainerConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("cần Docker")
	}
	d := newDriver(t).(*Driver)
	ctx := t.Context()
	const app = "conf-app-a"

	c, err := d.Setup(ctx, app)
	if err != nil {
		t.Fatal(err)
	}
	pw := c.Env["KEENRIG_REDIS_PASSWORD"]
	if pw == "" {
		t.Fatal("không có KEENRIG_REDIS_PASSWORD")
	}

	// Đọc lại cấu hình container qua chính đường mà `docker inspect` dùng.
	res, err := d.cfg.Runtime.Exec(ctx, addons.ExecSpec{
		Name: infraName(app),
		// /proc/1/cmdline là đối số của tiến trình redis-server — tương đương
		// phần Cmd mà docker inspect hiện.
		Cmd: []string{"cat", "/proc/1/cmdline"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.Stdout), pw) {
		t.Error("mật khẩu nằm trong đối số của redis-server — `docker inspect` và " +
			"`ps` trong container đều hiện nó")
	}

	res, err = d.cfg.Runtime.Exec(ctx, addons.ExecSpec{
		Name: infraName(app), Cmd: []string{"env"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.Stdout), pw) {
		t.Error("mật khẩu nằm trong env của container — `docker inspect` hiện nó")
	}
}

// Không có mật khẩu thì KHÔNG vào được.
//
// Nếu `requirepass` không có tác dụng thì mọi container trên network keenrig0
// đọc/ghi được redis của app khác, chỉ cần biết tên. Với redis, cách ly ở tầng
// tiến trình là toàn bộ cơ chế — và nó chỉ có nghĩa khi có mật khẩu.
func TestRequirePassIsEnforced(t *testing.T) {
	if testing.Short() {
		t.Skip("cần Docker")
	}
	d := newDriver(t).(*Driver)
	ctx := t.Context()
	const app = "conf-app-a"

	if _, err := d.Setup(ctx, app); err != nil {
		t.Fatal(err)
	}
	// redis-cli KHÔNG có REDISCLI_AUTH.
	res, err := d.cfg.Runtime.Exec(ctx, addons.ExecSpec{
		Name: infraName(app), Cmd: []string{"redis-cli", "GET", "bat-ky"},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := strings.ToUpper(string(res.Stdout) + string(res.Stderr))
	if !strings.Contains(out, "NOAUTH") && !strings.Contains(out, "AUTH") {
		t.Errorf("truy cập KHÔNG mật khẩu không bị từ chối: %q", out)
	}
}

// Backup → Restore phải giữ được KHOÁ THẬT, không chỉ "không lỗi".
//
// Đây là chỗ redis khác postgres về bản chất: redis chỉ nạp RDB LÚC KHỞI ĐỘNG.
// Ghi file vào một redis đang chạy không có tác dụng gì — và lần SAVE tiếp theo
// sẽ ghi đè đúng file vừa đặt. Test này bắt được nếu Restore quên khởi động lại.
func TestBackupRestoreKeepsKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("cần Docker")
	}
	d := newDriver(t).(*Driver)
	ctx := t.Context()
	const app = "conf-app-a"

	c, err := d.Setup(ctx, app)
	if err != nil {
		t.Fatal(err)
	}
	pw := c.Env["KEENRIG_REDIS_PASSWORD"]

	if res, err := d.redisCLI(ctx, app, pw, "SET", "ghi-chu", "du-lieu-quan-trong"); err != nil || !res.OK() {
		t.Fatalf("SET: %v %s", err, res.Stderr)
	}

	dir := t.TempDir()
	if err := d.Backup(ctx, app, dir); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// Xoá khoá rồi restore — nếu Restore không thật sự nạp lại thì khoá vẫn mất.
	if res, err := d.redisCLI(ctx, app, pw, "DEL", "ghi-chu"); err != nil || !res.OK() {
		t.Fatalf("DEL: %v %s", err, res.Stderr)
	}
	if err := d.Restore(ctx, app, dir); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	res, err := d.redisCLI(ctx, app, pw, "GET", "ghi-chu")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "du-lieu-quan-trong" {
		t.Errorf("sau Restore đọc được %q, muốn %q — RDB nạp được nhưng dữ liệu "+
			"không quay lại (redis chỉ nạp RDB lúc KHỞI ĐỘNG)", got, "du-lieu-quan-trong")
	}
}

// Hai app có HAI container riêng — đây là điểm khác postgres, và là lý do redis
// chọn kiến trúc này: cách ly ở tầng TIẾN TRÌNH.
func TestEachAppGetsOwnContainer(t *testing.T) {
	if testing.Short() {
		t.Skip("cần Docker")
	}
	d := newDriver(t).(*Driver)
	ctx := t.Context()

	ca, err := d.Setup(ctx, "conf-app-a")
	if err != nil {
		t.Fatal(err)
	}
	cb, err := d.Setup(ctx, "conf-app-b")
	if err != nil {
		t.Fatal(err)
	}
	// HOST khác nhau: postgres dùng chung nên host giống nhau; ở đây mỗi app có
	// alias DNS riêng.
	if ca.Env["KEENRIG_REDIS_HOST"] == cb.Env["KEENRIG_REDIS_HOST"] {
		t.Errorf("hai app trỏ vào CÙNG host %q — không phải container riêng",
			ca.Env["KEENRIG_REDIS_HOST"])
	}

	// Và một app KHÔNG FLUSHALL được dữ liệu của app kia — vì nó ở tiến trình khác.
	pwA := ca.Env["KEENRIG_REDIS_PASSWORD"]
	pwB := cb.Env["KEENRIG_REDIS_PASSWORD"]
	if _, err := d.redisCLI(ctx, "conf-app-b", pwB, "SET", "cua-b", "con-nguyen"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.redisCLI(ctx, "conf-app-a", pwA, "FLUSHALL"); err != nil {
		t.Fatal(err)
	}
	res, err := d.redisCLI(ctx, "conf-app-b", pwB, "GET", "cua-b")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "con-nguyen" {
		t.Errorf("FLUSHALL của app A xoá dữ liệu app B (đọc được %q).\n"+
			"Đây chính là lý do redis KHÔNG dùng chung container: FLUSHALL không "+
			"cần quyền gì đặc biệt.", got)
	}
}
