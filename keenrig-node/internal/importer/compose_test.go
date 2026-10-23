package importer_test

// Test importer. Trọng tâm là CHÍNH SÁCH AN NINH: mỗi mục bị từ chối ở đây là
// một đường leo thang ra khỏi container, và một lỗ ở đây biến "dán compose vào
// ô nhập" thành "chiếm máy chủ".

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/importer"
)

func importOK(t *testing.T, yaml string) importer.Result {
	t.Helper()
	res, err := importer.Import([]byte(yaml))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	return res
}

func findApp(t *testing.T, res importer.Result, slug string) importer.App {
	t.Helper()
	for _, a := range res.Apps {
		if a.Slug == slug {
			return a
		}
	}
	t.Fatalf("không thấy app %q trong %d app", slug, len(res.Apps))
	return importer.App{}
}

func rejectedFields(a importer.App) []string {
	var out []string
	for _, n := range a.Notes {
		if n.Severity == importer.SeverityRejected {
			out = append(out, n.Field)
		}
	}
	return out
}

func hasField(fields []string, want string) bool {
	for _, f := range fields {
		if f == want {
			return true
		}
	}
	return false
}

func TestBasicService(t *testing.T) {
	res := importOK(t, `
services:
  web:
    image: nginx:1.27
    ports: ["8080:80"]
    environment:
      FOO: bar
      NUM: 42
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: "0.5"
          memory: 512m
`)
	if len(res.Apps) != 1 {
		t.Fatalf("= %d app", len(res.Apps))
	}
	a := res.Apps[0]
	if a.Slug != "web" {
		t.Errorf("slug = %q", a.Slug)
	}
	if a.Desired.Image != "nginx:1.27" {
		t.Errorf("image = %q", a.Desired.Image)
	}
	// Cổng TRONG container, không phải cổng publish.
	if a.Desired.HTTPPort != 80 {
		t.Errorf("http_port = %d, muốn 80 (cổng trong container)", a.Desired.HTTPPort)
	}
	if a.Desired.Env["FOO"] != "bar" || a.Desired.Env["NUM"] != "42" {
		t.Errorf("env = %v", a.Desired.Env)
	}
	if a.Desired.Resources == nil || a.Desired.Resources.Replicas != 3 ||
		a.Desired.Resources.MemoryMB != 512 || a.Desired.Resources.CPU != 0.5 {
		t.Errorf("resources = %+v", a.Desired.Resources)
	}
	// Publish ra host bị bỏ → phải NÓI RA, không im lặng.
	var told bool
	for _, n := range a.Notes {
		if n.Field == "ports" {
			told = true
		}
	}
	if !told {
		t.Error("bỏ cổng publish mà không ghi chú")
	}
}

// Mỗi mục ở đây là một đường thoát container. Không cái nào được lọt.
func TestSecurityPolicyRejects(t *testing.T) {
	cases := map[string]struct {
		yaml  string
		field string
	}{
		"privileged": {`
services:
  x:
    image: nginx
    privileged: true
`, "privileged"},
		"network_mode host": {`
services:
  x:
    image: nginx
    network_mode: host
`, "network_mode"},
		"pid host": {`
services:
  x:
    image: nginx
    pid: host
`, "pid/ipc"},
		"bind mount tuyệt đối": {`
services:
  x:
    image: nginx
    volumes:
      - /:/host
`, "volumes"},
		"bind mount tương đối": {`
services:
  x:
    image: nginx
    volumes:
      - ./data:/data
`, "volumes"},
		"bind mount dạng object": {`
services:
  x:
    image: nginx
    volumes:
      - type: bind
        source: /etc
        target: /etc
`, "volumes"},
		"cap_add": {`
services:
  x:
    image: nginx
    cap_add: [SYS_ADMIN]
`, "cap_add"},
		"devices": {`
services:
  x:
    image: nginx
    devices:
      - /dev/sda:/dev/sda
`, "devices"},
		"seccomp unconfined": {`
services:
  x:
    image: nginx
    security_opt:
      - seccomp:unconfined
`, "security_opt"},
		"build từ Dockerfile": {`
services:
  x:
    build: .
`, "build"},
	}

	for name, c := range cases {
		res := importOK(t, c.yaml)
		a := findApp(t, res, "x")
		fields := rejectedFields(a)
		if !hasField(fields, c.field) {
			t.Errorf("%s: KHÔNG bị từ chối (rejected fields = %v)", name, fields)
		}
		if len(res.Rejected()) == 0 {
			t.Errorf("%s: Result.Rejected() rỗng", name)
		}
	}
}

// Named volume KHÁC bind mount: nó không chạm filesystem host, nên chỉ bị bỏ
// (dropped) chứ không bị từ chối. Nhầm hai thứ này làm mọi compose có volume
// đều không nhập được.
func TestNamedVolumeIsImportedNotDropped(t *testing.T) {
	// Image KHÔNG phải database: từ IM-02, một service `postgres:16` bị HẤP THỤ
	// thành addon và không còn là app — nên dùng nó ở đây sẽ kiểm nhầm thứ.
	res := importOK(t, `
services:
  files:
    image: myapp:1
    volumes:
      - appdata:/var/lib/app
volumes:
  appdata:
`)
	a := findApp(t, res, "files")
	if f := rejectedFields(a); len(f) != 0 {
		t.Errorf("named volume bị từ chối: %v", f)
	}
	// Bản trước của test này khẳng định volume bị BỎ, và nó đúng với hành vi lúc
	// đó. Nhưng hành vi đó là hệ quả của một lỗ: `desired` chưa có trường
	// `volumes`, nên `IM-01` — vốn đòi parser đọc named volume VÀO desired — map
	// vào hư không. Giờ trường đã có, và luật đảo lại.
	if len(a.Desired.Volumes) != 1 {
		t.Fatalf("named volume KHÔNG vào desired: %+v", a.Desired.Volumes)
	}
	if v := a.Desired.Volumes[0]; v.Name != "appdata" || v.Path != "/var/lib/app" {
		t.Errorf("= %+v", v)
	}
}

// Env dạng list "K=V" cũng phải nhận; biến không có giá trị bị bỏ VÀ được nói ra.
func TestEnvListForm(t *testing.T) {
	res := importOK(t, `
services:
  x:
    image: nginx
    environment:
      - A=1
      - B=2
      - FROM_SHELL
`)
	a := findApp(t, res, "x")
	if a.Desired.Env["A"] != "1" || a.Desired.Env["B"] != "2" {
		t.Errorf("env = %v", a.Desired.Env)
	}
	if _, has := a.Desired.Env["FROM_SHELL"]; has {
		t.Error("biến không có giá trị lại được nhập — platform không có shell của người dùng để lấy giá trị")
	}
	var told bool
	for _, n := range a.Notes {
		if n.Field == "environment" {
			told = true
		}
	}
	if !told {
		t.Error("bỏ biến môi trường mà không ghi chú")
	}
}

func TestPortForms(t *testing.T) {
	cases := map[string]int{
		`ports: ["80"]`:                            80,
		`ports: ["8080:3000"]`:                     3000,
		`ports: ["127.0.0.1:8080:3000"]`:           3000,
		`ports: ["3000/tcp"]`:                      3000,
		`expose: ["9000"]`:                         9000,
		`ports: [{target: 5000, published: 8080}]`: 5000,
	}
	for portYAML, want := range cases {
		res := importOK(t, "services:\n  x:\n    image: nginx\n    "+portYAML+"\n")
		a := findApp(t, res, "x")
		if a.Desired.HTTPPort != want {
			t.Errorf("%s → http_port %d, muốn %d", portYAML, a.Desired.HTTPPort, want)
		}
	}
}

// Nhiều service → nhiều app, thứ tự TẤT ĐỊNH (map YAML duyệt ngẫu nhiên).
func TestMultipleServicesStableOrder(t *testing.T) {
	yaml := `
services:
  web:
    image: nginx
  worker:
    image: busybox
  api:
    image: golang
`
	first := importOK(t, yaml)
	if len(first.Apps) != 3 {
		t.Fatalf("= %d app", len(first.Apps))
	}
	want := []string{"api", "web", "worker"}
	for i, a := range first.Apps {
		if a.Slug != want[i] {
			t.Fatalf("thứ tự = %v, muốn %v", []string{first.Apps[0].Slug, first.Apps[1].Slug, first.Apps[2].Slug}, want)
		}
	}
	for i := 0; i < 5; i++ {
		again := importOK(t, yaml)
		for j := range again.Apps {
			if again.Apps[j].Slug != first.Apps[j].Slug {
				t.Fatal("thứ tự đổi giữa hai lần import")
			}
		}
	}
}

func TestSlugify(t *testing.T) {
	res := importOK(t, `
services:
  My_App.Web 1:
    image: nginx
`)
	if len(res.Apps) != 1 {
		t.Fatal("= 0 app")
	}
	slug := res.Apps[0].Slug
	for i := 0; i < len(slug); i++ {
		c := slug[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			t.Fatalf("slug %q chứa ký tự không hợp lệ %q", slug, string(c))
		}
	}
	if strings.HasPrefix(slug, "-") || strings.HasSuffix(slug, "-") {
		t.Errorf("slug %q bắt đầu/kết thúc bằng dấu gạch", slug)
	}
}

func TestErrors(t *testing.T) {
	if _, err := importer.Import([]byte("không: [phải: yaml hợp lệ")); !errors.Is(err, importer.ErrParse) {
		t.Errorf("YAML hỏng = %v, muốn ErrParse", err)
	}
	if _, err := importer.Import([]byte("version: '3'\n")); !errors.Is(err, importer.ErrNoService) {
		t.Errorf("không service = %v, muốn ErrNoService", err)
	}
}

// Thứ không dịch được PHẢI được nói ra — im lặng bỏ qua nghĩa là app chạy khác
// hẳn compose và người dùng chỉ phát hiện sau vài ngày.
func TestUntranslatableAreReported(t *testing.T) {
	res := importOK(t, `
services:
  x:
    image: nginx
    command: ["sleep", "1"]
    entrypoint: /bin/sh
    depends_on: [db]
    healthcheck:
      test: ["CMD", "true"]
    restart: on-failure
  db:
    image: postgres:16
`)
	a := findApp(t, res, "x")
	got := map[string]bool{}
	for _, n := range a.Notes {
		got[n.Field] = true
	}
	for _, want := range []string{"command", "entrypoint", "depends_on", "healthcheck", "restart"} {
		if !got[want] {
			t.Errorf("không ghi chú việc bỏ %q", want)
		}
	}
}

func TestMemoryParsing(t *testing.T) {
	cases := map[string]int{"512m": 512, "1g": 1024, "1024mb": 1024, "2gb": 2048}
	for in, want := range cases {
		res := importOK(t, "services:\n  x:\n    image: nginx\n    deploy:\n      resources:\n        limits:\n          memory: "+in+"\n")
		a := findApp(t, res, "x")
		if a.Desired.Resources == nil || a.Desired.Resources.MemoryMB != want {
			t.Errorf("memory %q → %+v, muốn %dMB", in, a.Desired.Resources, want)
		}
	}
}

// IM-01 phần `named volume`: từ hôm nay nó map vào `desired.volumes` THẬT.
//
// Trước đây gate này map vào hư không — `IM-01` đòi parser đọc named volume vào
// desired, nhưng desired KHÔNG có trường đó, nên importer chỉ ghi một dòng
// "volumes dropped" rồi vứt đi.
func TestNamedVolumeBecomesDesiredVolume(t *testing.T) {
	res := importOK(t, `
services:
  web:
    image: nginx
    volumes:
      - uploads:/var/www/uploads
      - cache:/var/cache:ro
`)
	a := findApp(t, res, "web")
	if len(a.Desired.Volumes) != 2 {
		t.Fatalf("có %d volume, muốn 2: %+v", len(a.Desired.Volumes), a.Desired.Volumes)
	}
	if a.Desired.Volumes[0].Name != "uploads" || a.Desired.Volumes[0].Path != "/var/www/uploads" {
		t.Errorf("volume 1 = %+v", a.Desired.Volumes[0])
	}
	if !a.Desired.Volumes[1].ReadOnly {
		t.Error("`:ro` không thành read_only")
	}
}

// Bind mount vẫn phải bị TỪ CHỐI — nó đọc/ghi được filesystem máy chủ.
//
// Đây là ranh giới không được nới ra khi thêm named volume: hai thứ trông giống
// nhau trong cú pháp compose nhưng khác nhau hoàn toàn về hậu quả.
func TestBindMountStillRejectedAfterVolumeSupport(t *testing.T) {
	for _, y := range []string{
		"services:\n  x:\n    image: nginx\n    volumes:\n      - /:/host\n",
		"services:\n  x:\n    image: nginx\n    volumes:\n      - ./data:/data\n",
		"services:\n  x:\n    image: nginx\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
	} {
		res, err := importer.Import([]byte(y))
		if err != nil {
			continue
		}
		rejected := false
		for _, a := range res.Apps {
			for _, n := range a.Notes {
				if n.Severity == importer.SeverityRejected && n.Field == "volumes" {
					rejected = true
				}
			}
		}
		if !rejected {
			t.Errorf("bind mount KHÔNG bị từ chối:\n%s", y)
		}
	}
}

// Tên volume bị chuẩn hoá thì phải NÓI RA — một cái tên đổi im lặng là một cái
// tên người ta đi tìm mà không thấy.
func TestRenamedVolumeIsReported(t *testing.T) {
	res := importOK(t, `
services:
  web:
    image: nginx
    volumes:
      - myApp_Data:/data
`)
	a := findApp(t, res, "web")
	if len(a.Desired.Volumes) != 1 || a.Desired.Volumes[0].Name != "myapp-data" {
		t.Fatalf("tên sau chuẩn hoá = %+v", a.Desired.Volumes)
	}
	said := false
	for _, n := range a.Notes {
		if n.Field == "volumes" && strings.Contains(n.Message, "renamed") {
			said = true
		}
	}
	if !said {
		t.Errorf("đổi tên volume mà không nói ra: %+v", a.Notes)
	}
}

// Volume ẩn danh (`- /data`, không có tên) không neo được — phải bỏ CÓ LÝ DO.
func TestAnonymousVolumeIsReportedNotSilentlyDropped(t *testing.T) {
	res := importOK(t, `
services:
  web:
    image: nginx
    volumes:
      - somedata
`)
	a := findApp(t, res, "web")
	if len(a.Desired.Volumes) != 0 {
		t.Errorf("volume ẩn danh lại được nhận: %+v", a.Desired.Volumes)
	}
	said := false
	for _, n := range a.Notes {
		if n.Field == "volumes" {
			said = true
		}
	}
	if !said {
		t.Error("bỏ volume ẩn danh mà không nói lý do")
	}
}

// IM-07 — YAML bomb / file quá lớn / lồng quá sâu phải bị TỪ CHỐI trong thời
// gian chặn, không được làm tiến trình chết.
//
// Ô nhập compose là bề mặt tấn công có thật: bất kỳ ai đăng nhập được Admin đều
// dán được vào đó. Và `keenrig-box` là MỘT tiến trình — làm nó chết nghĩa là
// mất control plane, không phải mất một request.

func TestFileTooLargeRejected(t *testing.T) {
	big := append([]byte("services:\n  x:\n    image: nginx\n    environment:\n      A: \""),
		bytes.Repeat([]byte("x"), importer.MaxComposeBytes)...)
	big = append(big, '"')
	_, err := importer.Import(big)
	if !errors.Is(err, importer.ErrTooLarge) {
		t.Fatalf("= %v, muốn ErrTooLarge", err)
	}
}

// Lồng sâu: tràn ngăn xếp trong Go KHÔNG bắt được bằng recover — nó giết cả
// tiến trình. Nên phép đo phải chặn TRƯỚC khi bộ giải mã đi xuống.
func TestDeeplyNestedRejectedNotCrash(t *testing.T) {
	depth := importer.MaxComposeDepth * 4
	var b bytes.Buffer
	b.WriteString("services:\n  x:\n    image: nginx\n    environment:\n      DEEP: ")
	b.WriteString(strings.Repeat("[", depth))
	b.WriteString(strings.Repeat("]", depth))
	b.WriteString("\n")

	done := make(chan error, 1)
	go func() { _, err := importer.Import(b.Bytes()); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, importer.ErrTooLarge) && !errors.Is(err, importer.ErrParse) {
			t.Fatalf("= %v, muốn ErrTooLarge hoặc ErrParse", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Import không trả về trong 10 giây — parser bị treo trên input lồng sâu")
	}
}

// "Billion laughs": vài KB alias lồng nhau nở ra hàng tỉ node.
//
// # Điều ĐO ĐƯỢC, khác với điều tôi đoán lúc đầu
//
// Bản đầu của test này khẳng định MỌI bomb đều bị từ chối. Chạy thật thì:
//
//	alias nằm TRONG services  → yaml.v3 tự từ chối: "document contains
//	                            excessive aliasing", 0ms
//	alias ở khoá KHÔNG được   → được chấp nhận trong 1ms, và điều đó ĐÚNG:
//	giải mã vào struct          alias không bao giờ được nở ra, nên không có
//	                            gì để tấn công
//
// Nên khẳng định đúng không phải "mọi bomb bị từ chối" mà là "bomb CHẠM TỚI bộ
// giải mã bị từ chối nhanh". Viết cái đầu là viết một điều sai — và nó sẽ đỏ
// vào ngày ai đó sửa cho đúng.
func TestYAMLBombReachingTheDecoderIsRejectedQuickly(t *testing.T) {
	bomb := `
x: &a ["x","x","x","x","x","x","x","x","x"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
services:
  x:
    image: nginx
    environment: [*f,*f,*f,*f,*f,*f,*f,*f,*f]
`
	start := time.Now()
	done := make(chan error, 1)
	go func() { _, err := importer.Import([]byte(bomb)); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("YAML bomb chạm tới bộ giải mã lại được chấp nhận")
		}
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("từ chối được nhưng mất %s — quá lâu để gọi là 'thời gian chặn'", d)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Import không trả về — YAML bomb làm treo parser")
	}
}

// Và bomb KHÔNG chạm tới bộ giải mã thì vô hại — nhưng phải vô hại NHANH.
//
// Không khẳng định nó bị từ chối: alias ở một khoá không ai đọc thì không bao
// giờ nở ra. Thứ cần canh là thời gian, để ngày nào ai đó bắt importer đọc
// thêm khoá lạ thì test này đỏ trước khi người dùng gặp.
func TestBombInUnreadKeysStaysCheap(t *testing.T) {
	bomb := `
a: &a ["x","x","x","x","x","x","x","x","x"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: [*f,*f,*f,*f,*f,*f,*f,*f,*f]
services:
  x:
    image: nginx
`
	start := time.Now()
	done := make(chan error, 1)
	go func() { _, err := importer.Import([]byte(bomb)); done <- err }()
	select {
	case <-done:
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("mất %s cho một file vài KB — alias đang bị nở ra ở đâu đó", d)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Import không trả về")
	}
}

// File bình thường KHÔNG được bị giới hạn chặn nhầm.
func TestNormalFileWellUnderLimits(t *testing.T) {
	var b strings.Builder
	b.WriteString("services:\n")
	for i := range 30 {
		fmt.Fprintf(&b, "  svc%02d:\n    image: nginx:1.27\n    environment:\n      A: \"1\"\n      B: \"2\"\n", i)
	}
	res, err := importer.Import([]byte(b.String()))
	if err != nil {
		t.Fatalf("file 30 service bị từ chối: %v", err)
	}
	if len(res.Apps) != 30 {
		t.Errorf("= %d app, muốn 30", len(res.Apps))
	}
}

// Regression IM-06: service có tên không còn ký tự dùng được sau chuẩn hoá.
//
// Fuzz tìm ra sau 2 giây với input `services:\n  $:\n …`. Slug rỗng đi thẳng
// vào tên container `su-<slug>-<appIDShort>-<idx>-r<rev>`, và nó lọt qua
// importer im lặng — chỉ hỏng ở tầng runtime, nơi thông báo lỗi không còn nhắc
// gì tới compose.
func TestServiceNameWithNoUsableCharsIsRejected(t *testing.T) {
	for _, name := range []string{"$", "!!!", "***", "   ", "@#%"} {
		res, err := importer.Import([]byte("services:\n  \"" + name + "\":\n    image: nginx\n"))
		if err != nil {
			continue // từ chối ở tầng parse cũng được
		}
		if len(res.Apps) == 0 {
			continue
		}
		a := res.Apps[0]
		if a.Slug == "" && len(rejectedFields(a)) == 0 {
			t.Errorf("service %q → slug rỗng mà KHÔNG bị từ chối", name)
		}
		if a.Slug == "" && !hasField(rejectedFields(a), "service") {
			t.Errorf("service %q bị từ chối nhưng không nói vì tên: %v", name, rejectedFields(a))
		}
	}
}

// IM-03 — `docker.sock` phải bị TỪ CHỐI kèm GIẢI THÍCH RÕ, không gộp vào thông
// báo bind mount chung.
//
// Gate nói "REJECT + giải thích rõ". Trước đây nó chỉ dính gián tiếp qua luật
// bind-mount-tuyệt-đối, và thông báo là một dòng chung chung về volume — người
// dùng không biết vì sao ĐÚNG thứ này bị chặn, mà đây lại là mục phổ biến nhất
// trong compose thật (watchtower, portainer, traefik).
func TestDockerSocketRejectedWithItsOwnExplanation(t *testing.T) {
	paths := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/var/run/docker.sock:ro",
		"//./pipe/docker_engine",
		"/run/user/1000/docker.sock", // rootless
		"/run/containerd/containerd.sock",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			src := strings.TrimSuffix(p, ":ro")
			res := importOK(t, "services:\n  x:\n    image: nginx\n    volumes:\n      - \""+src+":/var/run/docker.sock\"\n")
			a := findApp(t, res, "x")
			if !hasField(rejectedFields(a), "volumes") {
				t.Fatalf("%s KHÔNG bị từ chối", p)
			}
			var msg string
			for _, n := range a.Notes {
				if n.Severity == importer.SeverityRejected && n.Field == "volumes" {
					msg = n.Message
				}
			}
			// Thông báo phải nói ĐÚNG mối nguy, không phải một câu chung về volume.
			for _, want := range []string{"Docker socket", "privileged", "master key"} {
				if !strings.Contains(msg, want) {
					t.Errorf("thông báo thiếu %q — người dùng không biết vì sao đúng thứ này bị chặn:\n%s", want, msg)
				}
			}
		})
	}
}

// Bind mount thường vẫn giữ thông báo CŨ — hai mối nguy khác bậc thì hai câu
// khác nhau.
func TestOrdinaryBindMountKeepsItsOwnMessage(t *testing.T) {
	res := importOK(t, "services:\n  x:\n    image: nginx\n    volumes:\n      - /etc:/etc\n")
	a := findApp(t, res, "x")
	for _, n := range a.Notes {
		if n.Severity == importer.SeverityRejected && n.Field == "volumes" {
			if strings.Contains(n.Message, "Docker socket") {
				t.Errorf("bind mount thường bị gán thông báo của docker.sock: %s", n.Message)
			}
			return
		}
	}
	t.Error("bind mount /etc không bị từ chối")
}

// IM-02 — compose web+postgres → MỘT app + addon managed.
//
// Đây là hình dạng phổ biến nhất của compose thật, và là con đường mà app
// stateful vào được nền tảng.
func TestWebPlusPostgresBecomesOneAppWithAddon(t *testing.T) {
	res := importOK(t, `
services:
  web:
    image: myapp:1
    depends_on: [db]
    environment:
      DATABASE_URL: postgres://u:p@db:5432/mydb
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_PASSWORD: secret
`)
	if len(res.Apps) != 1 {
		slugs := make([]string, len(res.Apps))
		for i, a := range res.Apps {
			slugs[i] = a.Slug
		}
		t.Fatalf("= %d app (%v), muốn 1 — service postgres phải bị HẤP THỤ thành addon", len(res.Apps), slugs)
	}
	a := res.Apps[0]
	if a.Slug != "web" {
		t.Fatalf("app còn lại = %q", a.Slug)
	}
	if a.Desired.Addons == nil || a.Desired.Addons.Postgres == nil || !a.Desired.Addons.Postgres.Enabled {
		t.Fatalf("addon postgres KHÔNG được bật: %+v", a.Desired.Addons)
	}
	// Và phải NÓI RA rằng connection string viết tay giờ đã sai — app vẫn trỏ
	// vào một service không còn tồn tại.
	said := false
	for _, n := range a.Notes {
		if n.Field == "addons" && strings.Contains(n.Message, "KEENRIG_POSTGRES_URL") {
			said = true
		}
	}
	if !said {
		t.Errorf("không cảnh báo rằng DATABASE_URL viết tay đã trỏ sai: %+v", a.Notes)
	}
}

// Redis cũng vậy.
func TestRedisIsAbsorbedToo(t *testing.T) {
	res := importOK(t, `
services:
  app:
    image: myapp:1
    depends_on: [cache]
  cache:
    image: redis:7-alpine
`)
	if len(res.Apps) != 1 {
		t.Fatalf("= %d app, muốn 1", len(res.Apps))
	}
	if r := res.Apps[0].Desired.Addons; r == nil || r.Redis == nil || !r.Redis.Enabled {
		t.Fatalf("addon redis không bật: %+v", r)
	}
}

// Không có depends_on nhưng chỉ còn ĐÚNG MỘT app → vẫn gán được.
func TestSingleAppGetsAddonWithoutDependsOn(t *testing.T) {
	res := importOK(t, `
services:
  web:
    image: myapp:1
  db:
    image: postgres:16
`)
	if len(res.Apps) != 1 {
		t.Fatalf("= %d app", len(res.Apps))
	}
	if p := res.Apps[0].Desired.Addons; p == nil || p.Postgres == nil {
		t.Fatal("app duy nhất không được gán addon")
	}
}

// NHIỀU app mà không ai khai depends_on → KHÔNG đoán, và nói rõ vì sao.
//
// Đoán sai nghĩa là một app chạy mà không có DB, và triệu chứng nằm trong log
// của app chứ không của nền tảng.
func TestAmbiguousOwnershipIsNotGuessed(t *testing.T) {
	res := importOK(t, `
services:
  web:
    image: myapp:1
  worker:
    image: myworker:1
  db:
    image: postgres:16
`)
	if len(res.Apps) != 2 {
		t.Fatalf("= %d app, muốn 2", len(res.Apps))
	}
	for _, a := range res.Apps {
		if a.Desired.Addons != nil {
			t.Errorf("app %q bị ĐOÁN gán addon", a.Slug)
		}
	}
	said := false
	for _, n := range res.Notes {
		if n.Field == "addons" && strings.Contains(n.Message, "by hand") {
			said = true
		}
	}
	if !said {
		t.Errorf("không nói vì sao addon không được gán: %+v", res.Notes)
	}
}

// Image của BÊN THỨ BA không được hấp thụ — nó có thể đã sửa cấu hình, thêm
// extension, đổi cách khởi tạo.
func TestThirdPartyDatabaseImageIsNotAbsorbed(t *testing.T) {
	res := importOK(t, `
services:
  web:
    image: myapp:1
  db:
    image: mycompany/postgres-with-extensions:16
`)
	if len(res.Apps) != 2 {
		t.Fatalf("= %d app, muốn 2 — image bên thứ ba phải thành app thường", len(res.Apps))
	}
}

// Database mà nền tảng CHƯA có addon (MySQL, Mongo) → từ chối kèm lý do, không
// im lặng biến thành một app database tự quản.
func TestUnsupportedDatabaseIsRefusedWithReason(t *testing.T) {
	for _, img := range []string{"mysql:8", "mariadb:11", "mongo:7"} {
		res, err := importer.Import([]byte("services:\n  web:\n    image: myapp:1\n  db:\n    image: " + img + "\n"))
		if err != nil {
			continue
		}
		found := false
		for _, n := range res.Rejected() {
			if strings.Contains(n.Message, "no addon for it yet") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: không bị từ chối kèm lý do; notes=%+v", img, res.Rejected())
		}
	}
}
