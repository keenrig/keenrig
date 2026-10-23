// Package importer — dịch định dạng ĐẦU VÀO KHÔNG TIN CẬY sang `desired`.
//
// # Vì sao compose ở đây chứ không phải là một runtime driver
//
// Bằng chứng nằm trong chính hợp đồng: `license.schema.json` khai
// `features.runtime: enum [docker, swarm, k8s]` — không có compose. Lý do sâu
// hơn tên gọi: docker/swarm/k8s là NƠI APP CHẠY; compose là MỘT TỆP NGƯỜI DÙNG
// ĐƯA VÀO.
//
// Khác biệt đó là khác biệt an ninh, không phải phân loại cho gọn. Một
// docker-compose.yml có thể khai `privileged: true`, `volumes: /:/host`,
// `network_mode: host`, `cap_add: SYS_ADMIN`. Chạy thẳng nó nghĩa là giao root
// máy chủ cho bất kỳ ai dán được một file YAML vào ô nhập. Đường đúng là
//
//	compose → parse → desired NHÁP → admission (apps.Validate) → runtime
//
// và bước "admission" chính là thứ biến mất nếu compose trở thành driver.
//
// # Kết quả là BẢN NHÁP, không phải bản cuối
//
// Import không bao giờ tự deploy. Nó trả về `Result` gồm desired đã dịch được
// VÀ danh sách thứ KHÔNG dịch được, để người dùng đọc rồi mới bấm tạo. Im lặng
// bỏ qua một `volumes:` nghĩa là app chạy nhưng mất dữ liệu, và người dùng chỉ
// phát hiện sau vài ngày.
package importer

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
)

var (
	// ErrParse — YAML hỏng hoặc không phải compose.
	ErrParse = errors.New("importer: the compose file could not be parsed")
	// ErrRejected — compose khai thứ chính sách an ninh CẤM.
	ErrRejected = errors.New("importer: the compose file was rejected for security reasons")
	// ErrNoService — không có service nào để nhập.
	ErrNoService = errors.New("importer: the compose file has no services")
	// ErrTooLarge — file vượt giới hạn kích thước hoặc độ sâu (IM-07).
	//
	// Lỗi RIÊNG, không gộp vào ErrParse: "cú pháp sai" thì người dùng sửa file,
	// còn "quá lớn" thì họ cần biết giới hạn là bao nhiêu. Hai câu dẫn tới hai
	// hành động khác nhau.
	ErrTooLarge = errors.New("importer: the compose file exceeds a safety limit")
)

// Severity — mức của một ghi chú khi dịch.
type Severity string

const (
	// SeverityRejected — CHẶN việc nhập. Không có cách nào an toàn để dịch.
	SeverityRejected Severity = "rejected"
	// SeverityDropped — bỏ qua một khai báo; app vẫn chạy nhưng KHÁC compose.
	SeverityDropped Severity = "dropped"
	// SeverityInfo — dịch được nhưng người dùng nên biết.
	SeverityInfo Severity = "info"
)

// Note — một điều đã xảy ra khi dịch. Đây là phần quan trọng nhất của kết quả:
// nó là thứ người dùng đọc trước khi bấm tạo app.
type Note struct {
	Severity Severity `json:"severity"`
	Service  string   `json:"service,omitempty"`
	Field    string   `json:"field,omitempty"`
	Message  string   `json:"message"`
}

// App — một service trong compose đã dịch thành desired nháp.
type App struct {
	// Slug gợi ý, lấy từ tên service. apps.NormalizeSlug vẫn là nơi quyết định
	// cuối cùng — ở đây chỉ là gợi ý cho UI điền sẵn.
	Slug    string               `json:"slug"`
	Desired contracts.DesiredApp `json:"desired"`
	Notes   []Note               `json:"notes,omitempty"`

	// composeName — tên service NGUYÊN VĂN trong file. Không xuất ra JSON: nó
	// chỉ dùng nội bộ để nối `depends_on` với app, vì `Slug` đã bị chuẩn hoá và
	// hai tên khác nhau có thể cho cùng một slug.
	composeName string
}

// Result — kết quả một lần nhập.
type Result struct {
	Apps  []App  `json:"apps"`
	Notes []Note `json:"notes,omitempty"`
}

// Rejected trả các ghi chú mức rejected (gộp cả cấp file lẫn cấp app).
func (r Result) Rejected() []Note {
	var out []Note
	for _, n := range r.Notes {
		if n.Severity == SeverityRejected {
			out = append(out, n)
		}
	}
	for _, a := range r.Apps {
		for _, n := range a.Notes {
			if n.Severity == SeverityRejected {
				out = append(out, n)
			}
		}
	}
	return out
}

// --- hình dạng compose (chỉ trường ta đọc) --------------------------------------

type composeFile struct {
	Version  string                    `yaml:"version"`
	Services map[string]composeService `yaml:"services"`
	Volumes  map[string]any            `yaml:"volumes"`
	Networks map[string]any            `yaml:"networks"`
}

type composeService struct {
	Image       string `yaml:"image"`
	Build       any    `yaml:"build"`
	Environment any    `yaml:"environment"` // map HOẶC list "K=V"
	Ports       []any  `yaml:"ports"`
	Expose      []any  `yaml:"expose"`
	Volumes     []any  `yaml:"volumes"`
	DependsOn   any    `yaml:"depends_on"`
	// Deploy dùng KIỂU CÓ TÊN (không phải struct ẩn danh) để đường vào
	// `docker run` dựng được cùng cấu trúc — hai đường vào phải đổ vào MỘT bộ
	// luật, nếu không thì `--privileged` chặn ở một đường và lọt ở đường kia.
	Deploy      *composeDeploy `yaml:"deploy"`
	Restart     string         `yaml:"restart"`
	Command     any            `yaml:"command"`
	Entrypoint  any            `yaml:"entrypoint"`
	NetworkMode string         `yaml:"network_mode"`
	Privileged  bool           `yaml:"privileged"`
	CapAdd      []string       `yaml:"cap_add"`
	Devices     []any          `yaml:"devices"`
	PID         string         `yaml:"pid"`
	IPC         string         `yaml:"ipc"`
	UsernsMode  string         `yaml:"userns_mode"`
	SecurityOpt []string       `yaml:"security_opt"`
	Sysctls     any            `yaml:"sysctls"`
	Labels      any            `yaml:"labels"`
	Healthcheck any            `yaml:"healthcheck"`
}

// Giới hạn an toàn cho parser (IM-07). Mỗi con số vì một cách một file YAML
// "hợp lệ" làm tiến trình chết.
const (
	// MaxComposeBytes — 1 MiB. File compose thật lớn nhất trong corpus công khai
	// dưới 100 KB; một file 50 MB không phải cấu hình mà là tấn công.
	MaxComposeBytes = 1 << 20
	// MaxComposeDepth — 32 tầng lồng nhau. Compose sâu nhất thực tế khoảng 6
	// tầng (services → tên → deploy → resources → limits → giá trị).
	//
	// Vì sao cần: YAML cho phép lồng vô hạn, và bộ giải mã đệ quy theo cấu trúc.
	// Một file vài KB toàn dấu `[` sẽ làm nổ ngăn xếp — và tràn ngăn xếp trong
	// Go KHÔNG bắt được bằng recover: nó giết cả tiến trình. Với `keenrig-box`
	// đó là cả control plane, vì một người dùng dán nhầm một file vào ô nhập.
	MaxComposeDepth = 32
	// MaxComposeNodes — trần số node sau khi giải mã, chống "YAML bomb" kiểu
	// billion-laughs: vài KB alias lồng nhau nở ra hàng tỉ node trong RAM.
	MaxComposeNodes = 200_000
)

// Import dịch nội dung một file compose.
func Import(raw []byte) (Result, error) {
	if len(raw) > MaxComposeBytes {
		return Result{}, fmt.Errorf("%w: %d bytes, the maximum is %d", ErrTooLarge, len(raw), MaxComposeBytes)
	}
	// Giải mã HAI LẦN có chủ đích: lần đầu vào yaml.Node để đo độ sâu và số node
	// TRƯỚC khi dựng struct. Đo trên struct đã dựng là đo sau khi RAM đã bị ăn.
	var probe yaml.Node
	if err := yaml.Unmarshal(raw, &probe); err != nil {
		return Result{}, fmt.Errorf("%w: %s", ErrParse, err)
	}
	if err := checkShape(&probe); err != nil {
		return Result{}, err
	}

	var f composeFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return Result{}, fmt.Errorf("%w: %s", ErrParse, err)
	}
	if len(f.Services) == 0 {
		return Result{}, ErrNoService
	}

	var res Result
	if len(f.Volumes) > 0 {
		res.Notes = append(res.Notes, Note{
			Severity: SeverityInfo, Field: "volumes",
			Message: fmt.Sprintf("the top-level `volumes:` block (%d entry) only declares names; driver/size options there are ignored — each service's `name:/path` is what becomes a platform volume",
				len(f.Volumes)),
		})
	}
	if len(f.Networks) > 0 {
		res.Notes = append(res.Notes, Note{
			Severity: SeverityInfo, Field: "networks",
			Message: "hand-declared networks are ignored — every app runs on the platform network and reaches others by name",
		})
	}

	// Thứ tự tất định: map YAML duyệt ngẫu nhiên, và một kết quả import đổi thứ
	// tự mỗi lần chạy sẽ làm người dùng tưởng có gì đó thay đổi.
	names := make([]string, 0, len(f.Services))
	for n := range f.Services {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		res.Apps = append(res.Apps, convert(name, f.Services[name]))
	}

	// IM-02: hấp thụ service-database thành addon managed. Làm SAU khi đã dựng
	// mọi app, vì nó cần biết app nào phụ thuộc app nào.
	apps, addonNotes := absorbAddons(res.Apps, f.Services, dependsOnMap(f.Services))
	res.Apps = apps
	res.Notes = append(res.Notes, addonNotes...)
	if len(res.Apps) == 0 {
		return res, ErrNoService
	}
	return res, nil
}

// convert dịch MỘT service.
func convert(name string, s composeService) App {
	app := App{Slug: slugify(name), composeName: name}
	var notes []Note
	add := func(sev Severity, field, msg string) {
		notes = append(notes, Note{Severity: sev, Service: name, Field: field, Message: msg})
	}

	// Tên không còn ký tự nào dùng được sau khi chuẩn hoá → TỪ CHỐI, không tự
	// bịa một cái tên.
	//
	// Tìm ra bằng FUZZ (IM-06) sau 2 giây, không phải bằng đọc code: một service
	// tên `$` cho ra slug RỖNG. Slug đi thẳng vào tên container
	// (`su-<slug>-<appIDShort>-<idx>-r<rev>`), nên một slug rỗng tạo ra tên
	// container dị dạng — và nó lọt qua importer im lặng, chỉ hỏng ở tầng
	// runtime nơi thông báo lỗi không còn nhắc gì tới compose.
	//
	// Tự đặt tên thay (`app-1`) thì hai service cùng cho ra tên đó, và người
	// dùng không có cách nào biết cái nào là cái nào.
	if app.Slug == "" {
		add(SeverityRejected, "service",
			"the service name has no usable characters after normalisation (only [a-z0-9-] survive) — rename it in the compose file")
	}

	// --- chính sách an ninh: từ chối, không "cố dịch cho bằng được" -----------
	//
	// Mỗi mục dưới đây đều là một đường leo thang ra khỏi container. Không có
	// cách nào dịch chúng sang desired "an toàn hơn một chút" — hoặc cho phép
	// hoàn toàn, hoặc từ chối. Ta từ chối, và nói rõ vì sao.
	if s.Privileged {
		add(SeverityRejected, "privileged", "privileged: true gives the container full control of the host — equivalent to root outside the container")
	}
	if s.NetworkMode == "host" {
		add(SeverityRejected, "network_mode", "network_mode: host bypasses all network isolation and lets the container take the platform's ports")
	}
	if s.PID == "host" || s.IPC == "host" {
		add(SeverityRejected, "pid/ipc", "pid/ipc: host allows inspecting and signalling every process on the host")
	}
	if len(s.Devices) > 0 {
		add(SeverityRejected, "devices", "attaching host devices to a container is not supported")
	}
	for _, c := range s.CapAdd {
		add(SeverityRejected, "cap_add", "cap_add: "+c+" grants extra kernel capabilities — not supported")
	}
	for _, o := range s.SecurityOpt {
		// seccomp/apparmor unconfined = tắt lớp phòng thủ cuối cùng của container.
		if strings.Contains(o, "unconfined") {
			add(SeverityRejected, "security_opt", "security_opt "+o+" disables seccomp/apparmor")
		}
	}
	for _, v := range s.Volumes {
		src := bindSource(v)
		if src == "" {
			continue
		}
		// IM-03: `docker.sock` phải được gọi ĐÚNG TÊN, không gộp vào thông báo
		// bind mount chung.
		//
		// Vì sao đáng một nhánh riêng: mọi bind mount đều nguy hiểm, nhưng
		// docker.sock nguy hiểm theo một BẬC khác. Nó không phải "đọc/ghi được
		// filesystem máy chủ" — nó là ĐIỀU KHIỂN ĐƯỢC DOCKER: container đó tạo
		// được container mới với --privileged, mount `/`, và đọc
		// `instance/master.key`. Mọi tầng cách ly khác thành vô nghĩa.
		//
		// Và nó là mục PHỔ BIẾN NHẤT trong compose thật (watchtower, portainer,
		// traefik, mọi thứ "auto-discovery"), nên người dùng sẽ gặp nó nhiều
		// nhất — họ cần biết vì sao đúng thứ này bị chặn, chứ không phải một
		// dòng chung chung về volume.
		if isDockerSocket(src) {
			add(SeverityRejected, "volumes",
				"mounting the Docker socket ("+src+") is never allowed: a container with it can create "+
					"privileged containers, mount the host filesystem and read the instance master key — "+
					"it is equivalent to giving the app root on the machine. Apps that need container "+
					"discovery cannot run on this platform")
			continue
		}
		add(SeverityRejected, "volumes",
			"bind mount from the host ("+src+") is not supported — it can read and write the host's filesystem")
	}

	// --- image ---------------------------------------------------------------
	switch {
	case s.Image != "":
		app.Desired.Image = s.Image
	case s.Build != nil:
		add(SeverityRejected, "build",
			"the service builds an image from a Dockerfile (build:) — the platform only runs prebuilt images; build and push first")
	default:
		add(SeverityRejected, "image", "the service declares no image")
	}

	// --- cổng ----------------------------------------------------------------
	//
	// Chỉ lấy cổng TRONG container. Phần "publish ra host" bị bỏ có chủ đích:
	// app không bao giờ được publish thẳng ra host — gateway là đường vào duy
	// nhất, và publish sẽ đi vòng qua TLS/WAF/rate-limit.
	if p, note := firstContainerPort(s); p > 0 {
		app.Desired.HTTPPort = p
		if note != "" {
			add(SeverityInfo, "ports", note)
		}
	}

	// --- env -----------------------------------------------------------------
	if env, dropped := parseEnv(s.Environment); len(env) > 0 || dropped > 0 {
		app.Desired.Env = env
		if dropped > 0 {
			add(SeverityDropped, "environment",
				fmt.Sprintf("%d environment variable(s) without a value (bare `KEY` taken from the shell) were dropped — declare values explicitly", dropped))
		}
	}

	// --- replicas / tài nguyên -----------------------------------------------
	if s.Deploy != nil {
		res := &contracts.Resources{}
		has := false
		if s.Deploy.Replicas != nil && *s.Deploy.Replicas > 0 {
			res.Replicas = *s.Deploy.Replicas
			has = true
		}
		if l := s.Deploy.Resources; l != nil && l.Limits != nil {
			if mb := parseMemoryMB(l.Limits.Memory); mb > 0 {
				res.MemoryMB = mb
				has = true
			}
			if c, err := strconv.ParseFloat(strings.TrimSpace(l.Limits.CPUs), 64); err == nil && c > 0 {
				res.CPU = c
				has = true
			}
		}
		if has {
			app.Desired.Resources = res
		}
	}

	// --- thứ KHÔNG dịch được, phải nói ra -------------------------------------
	if s.Command != nil {
		add(SeverityDropped, "command", "command: dropped — desired has no field for overriding the run command yet")
	}
	if s.Entrypoint != nil {
		add(SeverityDropped, "entrypoint", "entrypoint: dropped")
	}
	if s.DependsOn != nil {
		add(SeverityInfo, "depends_on",
			"depends_on dropped — the reconciler converges each app independently, so an app must tolerate its dependencies not being ready")
	}
	if s.Healthcheck != nil {
		add(SeverityInfo, "healthcheck", "compose's healthcheck dropped — the platform uses the image's own HEALTHCHECK")
	}
	if len(s.Volumes) > 0 && !hasRejected(notes) {
		vols, skipped := namedVolumes(s.Volumes)
		if len(vols) > 0 {
			if verr := contracts.ValidateVolumes(vols); verr != nil {
				add(SeverityRejected, "volumes", verr.Error())
			} else {
				app.Desired.Volumes = vols
			}
		}
		for _, sk := range skipped {
			add(SeverityDropped, "volumes", sk)
		}
	}
	if s.Restart != "" && s.Restart != "always" && s.Restart != "unless-stopped" {
		add(SeverityInfo, "restart",
			"restart: "+s.Restart+" dropped — the platform always restarts apps and converges to desired")
	}

	app.Notes = notes
	return app
}

func hasRejected(notes []Note) bool {
	for _, n := range notes {
		if n.Severity == SeverityRejected {
			return true
		}
	}
	return false
}

// bindSource trả đường dẫn host của một bind mount ("" nếu không phải).
//
// Nhận cả hai cú pháp compose: chuỗi ngắn "host:container" và dạng object
// {type: bind, source: ...}. Bỏ sót một dạng nghĩa là chính sách an ninh có lỗ.
// namedVolumes dịch named volume của compose → desired.volumes.
//
// # Vì sao CHỈ named volume, không phải mọi volume
//
// Bind mount (`/data:/data`) đã bị TỪ CHỐI ở trên vì nó đọc/ghi được filesystem
// của máy chủ. Named volume thì ngược lại: nó chỉ là một CÁI TÊN, và nền tảng
// tự quyết định tên đó nằm ở đâu trên đĩa — `apps/<id>/volumes/<name>`. Đúng
// hình dạng mà `desired.volumes` cần.
//
// # Tên bị chuẩn hoá, và điều đó phải được NÓI RA
//
// Compose cho phép `myApp_Data`; schema chỉ nhận `^[a-z0-9][a-z0-9-]*[a-z0-9]$`.
// Ta chuẩn hoá thay vì từ chối — nhưng một cái tên bị đổi im lặng là một cái tên
// người ta sẽ đi tìm mà không thấy, nên mọi lần đổi đều thành một Note.
func namedVolumes(raw []any) (vols []contracts.VolumeMount, skipped []string) {
	for _, v := range raw {
		name, path, ro, ok := splitNamedVolume(v)
		if !ok {
			skipped = append(skipped, fmt.Sprintf("volume %v was not imported — only `name:/path` named volumes map onto the platform", v))
			continue
		}
		slug := slugify(name)
		if slug == "" {
			skipped = append(skipped, fmt.Sprintf("volume %q has no usable name after normalisation", name))
			continue
		}
		if slug != name {
			skipped = append(skipped, fmt.Sprintf("volume %q was renamed to %q — the platform only allows [a-z0-9-]", name, slug))
		}
		vols = append(vols, contracts.VolumeMount{Name: slug, Path: path, ReadOnly: ro})
	}
	return vols, skipped
}

// splitNamedVolume đọc `name:/path[:ro]` hoặc dạng long syntax.
func splitNamedVolume(v any) (name, path string, readOnly, ok bool) {
	switch t := v.(type) {
	case string:
		parts := strings.Split(t, ":")
		if len(parts) < 2 {
			return "", "", false, false // volume ẩn danh: không có tên để neo
		}
		name, path = parts[0], parts[1]
		if len(parts) > 2 && parts[2] == "ro" {
			readOnly = true
		}
	case map[string]any:
		if ty := fmt.Sprint(t["type"]); ty != "volume" && t["type"] != nil {
			return "", "", false, false
		}
		name, path = fmt.Sprint(t["source"]), fmt.Sprint(t["target"])
		readOnly = fmt.Sprint(t["read_only"]) == "true"
	default:
		return "", "", false, false
	}
	if name == "" || name == "<nil>" || !strings.HasPrefix(path, "/") {
		return "", "", false, false
	}
	return name, path, readOnly, true
}

// isDockerSocket nhận diện socket của Docker ở MỌI dạng người ta hay viết.
//
// Không so bằng một chuỗi cố định: đường dẫn thật khác nhau theo hệ điều hành và
// cách cài (rootless Docker để socket dưới $XDG_RUNTIME_DIR, Docker Desktop trên
// Windows dùng named pipe). Một danh sách một mục sẽ bỏ lọt đúng những cấu hình
// mà người dùng thật đang chạy.
func isDockerSocket(p string) bool {
	low := strings.ToLower(strings.TrimSpace(p))
	low = strings.ReplaceAll(low, "\\", "/")
	switch {
	case strings.HasSuffix(low, "/docker.sock"), low == "docker.sock":
		return true
	case strings.Contains(low, "docker_engine"): // named pipe trên Windows
		return true
	case strings.HasSuffix(low, "/containerd.sock"), strings.HasSuffix(low, "/crio.sock"):
		// Cùng bậc nguy hiểm: nói chuyện thẳng với runtime bên dưới.
		return true
	}
	return false
}

func bindSource(v any) string {
	switch t := v.(type) {
	case string:
		parts := strings.Split(t, ":")
		if len(parts) < 2 {
			return "" // volume ẩn danh
		}
		src := parts[0]
		// Named volume là một tên, không phải đường dẫn. Bind bắt đầu bằng
		// "/", "./", "../", "~" hoặc một ổ đĩa Windows.
		if strings.HasPrefix(src, "/") || strings.HasPrefix(src, ".") || strings.HasPrefix(src, "~") ||
			(len(src) > 1 && src[1] == ':') {
			return src
		}
		return ""
	case map[string]any:
		if fmt.Sprint(t["type"]) == "bind" {
			return fmt.Sprint(t["source"])
		}
	}
	return ""
}

// firstContainerPort lấy cổng TRONG container từ ports/expose.
func firstContainerPort(s composeService) (int, string) {
	for _, p := range s.Ports {
		if cp, published := parsePort(p); cp > 0 {
			note := ""
			if published {
				note = "ports published to the host were dropped — apps receive traffic only through the gateway"
			}
			return cp, note
		}
	}
	for _, e := range s.Expose {
		if cp, _ := parsePort(e); cp > 0 {
			return cp, ""
		}
	}
	return 0, ""
}

// parsePort trả (cổng container, có publish ra host không).
func parsePort(v any) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, false
	case string:
		s := strings.TrimSuffix(strings.TrimSuffix(t, "/tcp"), "/udp")
		parts := strings.Split(s, ":")
		// "8080" | "80:8080" | "127.0.0.1:80:8080"
		last := parts[len(parts)-1]
		if i := strings.Index(last, "-"); i >= 0 {
			last = last[:i] // dải cổng → lấy đầu dải
		}
		n, err := strconv.Atoi(last)
		if err != nil || n <= 0 || n > 65535 {
			return 0, false
		}
		return n, len(parts) > 1
	case map[string]any:
		if tgt, ok := t["target"]; ok {
			n, err := strconv.Atoi(fmt.Sprint(tgt))
			if err == nil {
				_, published := t["published"]
				return n, published
			}
		}
	}
	return 0, false
}

// parseEnv nhận cả hai cú pháp compose: map và list "K=V".
// Trả thêm số biến bị bỏ vì không có giá trị (dạng `KEY` lấy từ shell của người
// chạy — một nguồn giá trị mà platform không có và không nên đoán).
func parseEnv(v any) (map[string]string, int) {
	out := map[string]string{}
	dropped := 0
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if val == nil {
				dropped++
				continue
			}
			out[k] = fmt.Sprint(val)
		}
	case []any:
		for _, item := range t {
			s := fmt.Sprint(item)
			k, val, ok := strings.Cut(s, "=")
			if !ok {
				dropped++
				continue
			}
			out[k] = val
		}
	}
	if len(out) == 0 {
		return nil, dropped
	}
	return out, dropped
}

// parseMemoryMB đọc "512m", "1g", "1073741824" → MB.
func parseMemoryMB(s string) int {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0
	}
	mult := 1
	switch {
	case strings.HasSuffix(s, "g"), strings.HasSuffix(s, "gb"):
		mult, s = 1024, strings.TrimRight(s, "gb")
	case strings.HasSuffix(s, "m"), strings.HasSuffix(s, "mb"):
		mult, s = 1, strings.TrimRight(s, "mb")
	case strings.HasSuffix(s, "k"), strings.HasSuffix(s, "kb"):
		n, err := strconv.Atoi(strings.TrimRight(s, "kb"))
		if err != nil {
			return 0
		}
		return n / 1024
	default:
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0
		}
		return int(n / (1 << 20))
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n * mult
}

// slugify biến tên service compose thành gợi ý slug.
//
// Chỉ là GỢI Ý: apps.NormalizeSlug mới là nơi quyết định, và nó có quyền từ
// chối. Hai nơi cùng "chuẩn hoá" là hai nơi có thể lệch nhau — vì vậy ở đây ta
// làm tối thiểu và để tầng service phán quyết.
func slugify(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.' || r == ' ':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// checkShape đo độ sâu và số node của cây YAML đã giải mã.
//
// Đi bằng NGĂN XẾP TỰ QUẢN chứ không đệ quy: một hàm đệ quy để đo độ sâu sẽ
// chính nó tràn ngăn xếp trên đúng cái file nó định từ chối. Đây là loại lỗi
// chỉ lộ ra khi có người thử tấn công thật.
func checkShape(root *yaml.Node) error {
	type frame struct {
		n     *yaml.Node
		depth int
	}
	stack := []frame{{root, 1}}
	nodes := 0
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		nodes++
		if nodes > MaxComposeNodes {
			return fmt.Errorf("%w: more than %d nodes after expansion (anchors/aliases?)", ErrTooLarge, MaxComposeNodes)
		}
		if f.depth > MaxComposeDepth {
			return fmt.Errorf("%w: nesting deeper than %d levels", ErrTooLarge, MaxComposeDepth)
		}
		for _, c := range f.n.Content {
			stack = append(stack, frame{c, f.depth + 1})
		}
	}
	return nil
}

// dependsOnMap đọc `depends_on` ở cả hai dạng compose cho phép: danh sách tên,
// hoặc map tên → điều kiện.
func dependsOnMap(services map[string]composeService) map[string][]string {
	out := make(map[string][]string, len(services))
	for name, s := range services {
		switch t := s.DependsOn.(type) {
		case []any:
			for _, v := range t {
				out[name] = append(out[name], fmt.Sprint(v))
			}
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			out[name] = keys
		}
	}
	return out
}
