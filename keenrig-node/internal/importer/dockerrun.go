package importer

import (
	"fmt"
	"strings"
)

// IM-01 — dịch một dòng `docker run` sang desired nháp.
//
// # Vì sao đường vào thứ hai này đáng có
//
// Compose là thứ người ta LƯU; `docker run` là thứ người ta DÁN. Mọi trang
// README của một app self-host mở đầu bằng đúng một dòng `docker run -d …`, và
// đó là thứ nằm trong clipboard của người dùng lúc họ mở Admin.
//
// # Nó dùng CHUNG toàn bộ chính sách an ninh với compose
//
// Không có bộ luật thứ hai: hàm này dịch cờ dòng lệnh sang cùng `composeService`
// rồi gọi chính `convert`. Nếu tách ra hai bộ luật thì `--privileged` bị chặn ở
// một đường và lọt ở đường kia — và không ai phát hiện cho tới khi có người thử.
// Đây là lý do file này ngắn: phần khó đã có sẵn.
//
// # Phân tích dòng lệnh, không phải shell
//
// Nó KHÔNG chạy shell, không nội suy biến, không hiểu `$(...)` hay `&&`. Một
// chuỗi dán vào là DỮ LIỆU, không phải lệnh — và biến nó thành lệnh là đúng cái
// lỗ mà cả package này sinh ra để chặn.

// ImportDockerRun dịch một dòng `docker run`.
//
// Nhận cả dạng nhiều dòng có `\` ở cuối — đó là dạng mọi README dùng.
func ImportDockerRun(cmd string) (Result, error) {
	if len(cmd) > MaxComposeBytes {
		return Result{}, fmt.Errorf("%w: %d bytes, the maximum is %d", ErrTooLarge, len(cmd), MaxComposeBytes)
	}
	args, err := splitCommandLine(cmd)
	if err != nil {
		return Result{}, err
	}
	// Bỏ tiền tố `docker run` / `podman run` / `sudo docker run`.
	args = trimRunPrefix(args)
	if len(args) == 0 {
		return Result{}, fmt.Errorf("%w: nothing after `docker run`", ErrParse)
	}

	svc, name, notes, err := parseRunFlags(args)
	if err != nil {
		return Result{}, err
	}
	if svc.Image == "" {
		return Result{}, fmt.Errorf("%w: no image in the command", ErrParse)
	}
	if name == "" {
		name = imageBaseName(svc.Image)
	}

	app := convert(name, svc)
	app.Notes = append(app.Notes, notes...)
	res := Result{Apps: []App{app}}

	// Dùng CHUNG bước hấp thụ addon với compose — một dòng `docker run postgres`
	// phải cho ra cùng kết quả với một compose khai đúng thứ đó.
	apps, addonNotes := absorbAddons(res.Apps, map[string]composeService{name: svc}, nil)
	res.Apps = apps
	res.Notes = append(res.Notes, addonNotes...)
	if len(res.Apps) == 0 {
		return res, ErrNoService
	}
	return res, nil
}

// trimRunPrefix bỏ `sudo`, `docker`, `podman`, `run` ở đầu.
func trimRunPrefix(args []string) []string {
	for len(args) > 0 {
		switch strings.ToLower(args[0]) {
		case "sudo", "docker", "podman", "run", "container", "create":
			args = args[1:]
			continue
		}
		break
	}
	return args
}

// parseRunFlags đọc cờ và trả về một composeService tương đương.
//
// Cờ KHÔNG hiểu được thì báo — không bỏ qua im lặng. Một `--network=host` bị
// nuốt sẽ thành một app chạy với chính sách khác hẳn thứ người dùng dán vào.
func parseRunFlags(args []string) (composeService, string, []Note, error) {
	var s composeService
	var name string
	var notes []Note
	env := map[string]string{}

	note := func(sev Severity, field, msg string) {
		notes = append(notes, Note{Severity: sev, Field: field, Message: msg})
	}

	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			break // hết cờ → tới image
		}
		flag, val, hasVal := splitFlag(a)
		// Cờ cần giá trị mà giá trị nằm ở đối số KẾ TIẾP.
		needsValue := map[string]bool{
			"-e": true, "--env": true, "-p": true, "--publish": true,
			"-v": true, "--volume": true, "--mount": true, "--name": true,
			"--restart": true, "--memory": true, "-m": true, "--cpus": true,
			"--network": true, "--net": true, "--cap-add": true, "--device": true,
			"--security-opt": true, "--pid": true, "--ipc": true, "--userns": true,
			"--expose": true, "--label": true, "-l": true, "--entrypoint": true,
			"-u": true, "--user": true, "--workdir": true, "-w": true,
			"--health-cmd": true, "--sysctl": true, "--env-file": true,
		}
		if !hasVal && needsValue[flag] && i+1 < len(args) {
			i++
			val, hasVal = args[i], true
		}

		switch flag {
		case "-d", "--detach", "-i", "--interactive", "-t", "--tty", "--rm", "--init":
			// Không có nghĩa với một nền tảng hội tụ: app luôn chạy nền và luôn
			// được khởi động lại. Không cần nói ra — chúng vô hại.
		case "-e", "--env":
			if k, v, ok := strings.Cut(val, "="); ok {
				env[k] = v
			} else {
				note(SeverityDropped, "environment",
					"`-e "+val+"` takes its value from the shell that would run the command — the platform has no such shell, so declare the value explicitly")
			}
		case "--env-file":
			note(SeverityDropped, "environment", "`--env-file "+val+"` refers to a file that only exists on your machine")
		case "-p", "--publish":
			s.Ports = append(s.Ports, val)
		case "--expose":
			s.Expose = append(s.Expose, val)
		case "-v", "--volume", "--mount":
			s.Volumes = append(s.Volumes, val)
		case "--name":
			name = val
		case "--restart":
			s.Restart = val
		case "-m", "--memory":
			s.Deploy = ensureDeploy(s.Deploy)
			s.Deploy.Resources.Limits.Memory = val
		case "--cpus":
			s.Deploy = ensureDeploy(s.Deploy)
			s.Deploy.Resources.Limits.CPUs = val
		case "--network", "--net":
			s.NetworkMode = val
		case "--privileged":
			s.Privileged = true
		case "--cap-add":
			s.CapAdd = append(s.CapAdd, val)
		case "--device":
			s.Devices = append(s.Devices, val)
		case "--security-opt":
			s.SecurityOpt = append(s.SecurityOpt, val)
		case "--pid":
			s.PID = val
		case "--ipc":
			s.IPC = val
		case "--userns":
			s.UsernsMode = val
		case "--entrypoint":
			s.Entrypoint = val
		case "-l", "--label", "-u", "--user", "-w", "--workdir", "--health-cmd", "--sysctl":
			note(SeverityDropped, strings.TrimLeft(flag, "-"),
				"`"+flag+"` is not translated — desired has no field for it")
		default:
			// Cờ LẠ: nói ra. Nuốt im lặng một cờ an ninh là cách chính sách bị
			// đi vòng mà không ai biết.
			note(SeverityDropped, "flags", "unrecognised flag `"+flag+"` was ignored")
		}
	}

	if i < len(args) {
		s.Image = args[i]
		i++
	}
	if i < len(args) {
		// Mọi thứ sau image là lệnh ghi đè. `convert` đã có nhánh nói ra việc
		// desired chưa có chỗ cho nó.
		s.Command = args[i:]
	}
	if len(env) > 0 {
		s.Environment = toAnyMap(env)
	}
	return s, name, notes, nil
}

func toAnyMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func ensureDeploy(d *composeDeploy) *composeDeploy {
	if d == nil {
		d = &composeDeploy{}
	}
	if d.Resources == nil {
		d.Resources = &composeResources{}
	}
	if d.Resources.Limits == nil {
		d.Resources.Limits = &composeLimits{}
	}
	return d
}

// splitFlag tách `--key=value` thành ("--key", "value", true).
func splitFlag(a string) (flag, val string, hasVal bool) {
	if k, v, ok := strings.Cut(a, "="); ok {
		return k, v, true
	}
	return a, "", false
}

// imageBaseName lấy tên gợi ý từ image khi không có `--name`.
func imageBaseName(image string) string {
	repo := image
	if i := strings.IndexByte(repo, '@'); i >= 0 {
		repo = repo[:i]
	}
	if i := strings.LastIndexByte(repo, ':'); i >= 0 && !strings.Contains(repo[i:], "/") {
		repo = repo[:i]
	}
	if i := strings.LastIndexByte(repo, '/'); i >= 0 {
		repo = repo[i+1:]
	}
	return repo
}

// splitCommandLine tách một dòng lệnh thành đối số.
//
// Hiểu nháy đơn, nháy kép, dấu `\` nối dòng — đủ cho thứ người ta chép từ
// README. KHÔNG hiểu `$(...)`, backtick, `&&`, `|`, `;`: chúng là cú pháp SHELL,
// và một chuỗi dán vào ô nhập phải được đối xử như DỮ LIỆU. Gặp chúng thì báo
// lỗi thay vì đoán — đoán ở đây là bắt đầu viết một shell nhỏ, và một shell nhỏ
// trong đường nhập liệu là đúng thứ package này sinh ra để chặn.
func splitCommandLine(s string) ([]string, error) {
	if i := strings.IndexAny(s, "`;|&"); i >= 0 {
		return nil, fmt.Errorf("%w: the command contains shell syntax (%q) — paste a single `docker run`, not a shell script",
			ErrParse, string(s[i]))
	}
	if strings.Contains(s, "$(") {
		return nil, fmt.Errorf("%w: the command substitutes a shell expression `$(...)` — the platform has no shell to run it in", ErrParse)
	}

	var args []string
	var cur strings.Builder
	var quote rune
	flush := func() {
		if cur.Len() > 0 {
			args = append(args, cur.String())
			cur.Reset()
		}
	}
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
				continue
			}
			cur.WriteRune(r)
		case r == '\'' || r == '"':
			quote = r
		case r == '\\':
			// `\` cuối dòng là nối dòng; ở giữa dòng là thoát ký tự kế.
			if i+1 < len(runes) && (runes[i+1] == '\n' || runes[i+1] == '\r') {
				i++
				continue
			}
			if i+1 < len(runes) {
				i++
				cur.WriteRune(runes[i])
			}
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("%w: unbalanced quote", ErrParse)
	}
	flush()
	return args, nil
}

// Kiểu phụ để `-m`/`--cpus` dựng được cấu trúc deploy giống compose.
type (
	composeLimits struct {
		CPUs   string `yaml:"cpus"`
		Memory string `yaml:"memory"`
	}
	composeResources struct {
		Limits *composeLimits `yaml:"limits"`
	}
	composeDeploy struct {
		Replicas  *int              `yaml:"replicas"`
		Resources *composeResources `yaml:"resources"`
	}
)
