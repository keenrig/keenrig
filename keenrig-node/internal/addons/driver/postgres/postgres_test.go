package postgres

// Conformance AD-01..04 + BK-01/05 trên POSTGRESQL THẬT trong Docker.
//
// # Vì sao không có bản test với fake
//
// Một fake InfraRuntime chỉ chứng minh ta gọi đúng thứ tự các method của chính
// mình. Nó KHÔNG chứng minh `psql` chấp nhận câu SQL ta sinh, không chứng minh
// `REVOKE ALL ON SCHEMA public` có tác dụng, và không chứng minh `pg_restore`
// đọc được bản dump của `pg_dump -Fc`. Cả ba đều là chỗ đã hỏng thật ở các
// driver khác (swarm, caddy) — và cả ba chỉ lộ ra trên nền tảng thật.
//
// Tự SKIP khi không có Docker. Skip có lý do, không phải biến mất im lặng.

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

// infraJSON — CÙNG file mà bản phát hành ship. Đọc nó thay vì viết cứng digest
// trong test: viết cứng nghĩa là test xanh trong khi bản ship dùng image khác.
const infraJSONPath = "../../../../addon-images/infra.json"

type infraFile struct {
	InfraVersion int                           `json:"infra_version"`
	Images       map[string]addons.PinnedImage `json:"images"`
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
	if f.InfraVersion < 1 || len(f.Images) == 0 {
		t.Fatalf("infra.json không hợp lệ: %+v", f)
	}
	return f
}

// newDriver dựng driver trỏ vào Docker THẬT, hoặc SKIP.
//
// Mỗi lần gọi dùng MỘT store tươi nhưng CHUNG container postgres: dựng lại
// container cho mỗi subtest sẽ mất ~10 giây mỗi lần và suite thành vô dụng.
// Đổi lại, mỗi subtest phải tự dọn — xem cleanup bên dưới.
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

	// Kiểm Docker CÒN SỐNG bằng Ping, KHÔNG bằng cách dò chuỗi lỗi.
	//
	// client.New không kết nối — lỗi lộ ra ở lời gọi đầu tiên. Bản đầu của test
	// này dò chuỗi "cannot connect" trong thông báo lỗi, nhưng thông báo thật là
	// "failed to connect to the docker API at …" — nên phép dò không khớp và cả
	// bộ test ĐỎ ở nơi đáng ra chỉ SKIP.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rt.Ping(ctx); err != nil {
		t.Skipf("Docker daemon không chạy: %v", err)
	}

	// Store TƯƠI mỗi subtest (nó rẻ), nhưng LAYOUT — tức thư mục dữ liệu
	// postgres — DÙNG CHUNG cả binary test. Xem sharedBase.
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

	// Dọn DB/role của các app dùng trong suite. BẮT BUỘC vì container dùng
	// chung giữa subtest: một role sót lại làm subtest sau thấy "đã setup rồi"
	// và kiểm sai thứ.
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, app := range []string{"conf-app-a", "conf-app-b"} {
			_, _ = d.psql(c, "DROP DATABASE IF EXISTS "+dbName(app)+";\nDROP ROLE IF EXISTS "+roleName(app)+";\n")
		}
	})
	return d
}

// sharedBase — thư mục dữ liệu postgres DÙNG CHUNG cho cả binary test.
//
// # Vì sao không dùng t.TempDir() mỗi subtest
//
// Container postgres dùng chung giữa các subtest (dựng lại mỗi lần mất ~45 giây
// vì initdb, suite sẽ thành vô dụng). Nhưng bind mount được cố định lúc container
// được TẠO. Cấp một t.TempDir() mới cho mỗi subtest nghĩa là subtest thứ hai
// truyền một thư mục khác trong khi container vẫn mount thư mục CŨ — và thư mục
// cũ đã bị t.Cleanup xoá.
//
// Kết quả đo được: `FATAL: could not open file "global/pg_filenode.map"`. Đây là
// lỗi HARNESS, không phải sản phẩm — nhưng nó chỉ lộ ra khi chạy trên PostgreSQL
// thật, và thông báo lỗi không hề nhắc tới bind mount.
var sharedBase string

func TestMain(m *testing.M) {
	d, err := os.MkdirTemp("", "keenrig-pg-conformance-")
	if err != nil {
		panic(err)
	}
	sharedBase = d

	// Container SẠCH trước khi chạy: một container còn sót từ lần chạy trước
	// mount một thư mục đã bị xoá, và mọi subtest sẽ đỏ vì lý do không liên quan
	// tới lần chạy này.
	removeInfra()
	code := m.Run()
	removeInfra()
	_ = os.RemoveAll(sharedBase)
	os.Exit(code)
}

// removeInfra gỡ container postgres. Bỏ qua lỗi: không có Docker thì mọi test
// đã SKIP, và ở đây báo lỗi chỉ làm nhiễu.
func removeInfra() {
	rt, err := infradocker.New()
	if err != nil {
		return
	}
	defer func() { _ = rt.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if rt.Ping(ctx) != nil {
		return
	}
	_ = rt.RemoveInfra(ctx, "postgres")
}

func TestPostgresConformance(t *testing.T) {
	if testing.Short() {
		t.Skip("bỏ qua ở chế độ -short (cần Docker)")
	}
	addontest.RunConformance(t, newDriver)
}

// --- test riêng của driver: những điều conformance KHÔNG kiểm được ------------------

// Cách ly Ở TẦNG SQL là toàn bộ giá trị của postgres dùng chung — và nó là chỗ
// dễ tưởng đã có mà thật ra không.
//
// PostgreSQL < 15 cấp cho MỌI role quyền CREATE trên schema `public` của MỌI
// database. Không REVOKE thì "database riêng cho từng app" chỉ là tên gọi: app A
// tạo được bảng trong DB của app B, đọc được dữ liệu ở đó.
func TestSchemaPublicIsLockedDown(t *testing.T) {
	if testing.Short() {
		t.Skip("cần Docker")
	}
	d := newDriver(t).(*Driver)
	ctx := t.Context()

	ca, err := d.Setup(ctx, "conf-app-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Setup(ctx, "conf-app-b"); err != nil {
		t.Fatal(err)
	}
	_ = ca

	// Role của app A thử tạo bảng trong DB của app B.
	res, err := d.cfg.Runtime.Exec(ctx, addons.ExecSpec{
		Name: infraName,
		Cmd: []string{"psql", "-v", "ON_ERROR_STOP=1", "-q",
			"-U", roleName("conf-app-a"), "-d", dbName("conf-app-b")},
		Stdin: []byte("CREATE TABLE xam_nhap(x int);\n"),
		Env:   map[string]string{"PGPASSWORD": credPassword(t, d, "conf-app-a")},
	})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if res.OK() {
		t.Fatal("app A TẠO ĐƯỢC BẢNG trong database của app B.\n" +
			"Cách ly ở tầng SQL không có tác dụng — với postgres dùng chung thì\n" +
			"đó là toàn bộ cơ chế cách ly giữa các app (BK-05).")
	}
	// Và lý do từ chối phải là QUYỀN, không phải "database không tồn tại" —
	// nếu là cái sau thì test này đang chứng minh nhầm thứ.
	low := strings.ToLower(string(res.Stderr))
	if !strings.Contains(low, "permission denied") && !strings.Contains(low, "must be owner") {
		t.Errorf("bị từ chối nhưng KHÔNG vì quyền: %s", res.Stderr)
	}
}

// pg_dump → pg_restore phải giữ được DỮ LIỆU THẬT, không chỉ "không lỗi".
//
// Conformance chỉ kiểm Backup sinh ra file và Restore không lỗi — nó không biết
// addon lưu gì. Chỉ test riêng của driver kiểm được rằng một hàng ghi vào trước
// backup còn nguyên sau restore.
func TestBackupRestoreKeepsRows(t *testing.T) {
	if testing.Short() {
		t.Skip("cần Docker")
	}
	d := newDriver(t).(*Driver)
	ctx := t.Context()
	const app = "conf-app-a"

	if _, err := d.Setup(ctx, app); err != nil {
		t.Fatal(err)
	}
	pw := credPassword(t, d, app)

	exec := func(sql string) addons.ExecResult {
		t.Helper()
		res, err := d.cfg.Runtime.Exec(ctx, addons.ExecSpec{
			Name: infraName,
			Cmd: []string{"psql", "-v", "ON_ERROR_STOP=1", "-t", "-A", "-q", "-h", "127.0.0.1",
				"-U", roleName(app), "-d", dbName(app)},
			Stdin: []byte(sql),
			Env:   map[string]string{"PGPASSWORD": pw},
		})
		if err != nil {
			t.Fatalf("exec: %v", err)
		}
		return res
	}

	if res := exec("CREATE TABLE ghi_chu(noi_dung text);\nINSERT INTO ghi_chu VALUES ('du lieu quan trong');\n"); !res.OK() {
		t.Fatalf("tạo dữ liệu mẫu: %s", res.Stderr)
	}

	dir := t.TempDir()
	if err := d.Backup(ctx, app, dir); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// Xoá dữ liệu rồi restore — nếu Restore không thật sự nạp thì bảng vẫn trống.
	if res := exec("DROP TABLE ghi_chu;\n"); !res.OK() {
		t.Fatalf("xoá bảng: %s", res.Stderr)
	}
	if err := d.Restore(ctx, app, dir); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	res := exec("SELECT noi_dung FROM ghi_chu;\n")
	if !res.OK() {
		t.Fatalf("đọc lại sau restore: %s", res.Stderr)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "du lieu quan trong" {
		t.Errorf("sau restore đọc được %q, muốn %q — bản dump nạp được nhưng "+
			"DỮ LIỆU không quay lại", got, "du lieu quan trong")
	}
}

// Dump phải là NHỊ PHÂN đúng định dạng custom của pg_dump.
//
// Đây là test canh cho một lỗi cụ thể: Docker ghép stdout/stderr với header
// 8 byte mỗi khung. Đọc thẳng luồng đó mà không tách nghĩa là bản dump lẫn
// header nhị phân — `pg_dump` vẫn trả mã 0, file vẫn có kích thước, và lỗi chỉ
// lộ ra vào lúc người dùng cần restore.
func TestDumpIsNotCorruptedByStreamMultiplexing(t *testing.T) {
	if testing.Short() {
		t.Skip("cần Docker")
	}
	d := newDriver(t).(*Driver)
	ctx := t.Context()
	const app = "conf-app-a"

	if _, err := d.Setup(ctx, app); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := d.Backup(ctx, app, dir); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(filepath.Join(dir, dumpFile))
	if err != nil {
		t.Fatal(err)
	}
	// Định dạng custom của pg_dump bắt đầu bằng "PGDMP".
	if len(blob) < 5 || string(blob[:5]) != "PGDMP" {
		t.Fatalf("dump không bắt đầu bằng \"PGDMP\" (5 byte đầu: %q).\n"+
			"Gần như chắc chắn là luồng ghép của Docker chưa được tách — header\n"+
			"8 byte lọt vào đầu file.", blob[:min(5, len(blob))])
	}
}

func credPassword(t *testing.T, d *Driver, appID string) string {
	t.Helper()
	c, err := d.credsOf(t.Context(), appID)
	if err != nil {
		t.Fatal(err)
	}
	return c.Password
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
