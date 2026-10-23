// Package privops — thao tác cần quyền root, gọi qua `sudo <script>`.
//
// # Vì sao box KHÔNG chạy bằng root
//
// Box mở một control API ra mạng. Chạy nó bằng root nghĩa là mọi lỗ trong API
// đó — một path traversal, một injection, một lỗi phân tích JSON — đều thành
// quyền root trên máy. Chạy bằng user riêng thì cùng lỗ đó chỉ đọc/ghi được
// những gì user đó đọc/ghi được.
//
// # Vì sao là SCRIPT chứ không phải gọi thẳng systemctl/rm từ Go
//
// Lý do cụ thể: sudoers KHÔNG kiểm được đối số. `NOPASSWD: /bin/systemctl` là
// quyền restart mọi dịch vụ, kể cả sshd. Một script với danh sách trắng bên
// trong biến bề mặt đặc quyền từ "mọi thứ systemctl làm được" thành "đúng bốn
// dịch vụ này".
//
// Hệ quả phải chấp nhận: mỗi thao tác đặc quyền là MỘT tiến trình mới, tốn
// vài mili-giây. Không thao tác nào ở đây nằm trong đường nóng, nên giá đó rẻ.
//
// # Bề mặt đặc quyền là DANH SÁCH DƯỚI ĐÂY
//
// Mỗi hàm exported ở package này là một khả năng mà một lỗ trong control API
// có thể với tới. Thêm một hàm là mở rộng bề mặt đó — nên nó phải đi kèm sửa
// sudoers, và sửa sudoers là một lần review.
package privops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrUnavailable — không gọi được script (chưa cài, thiếu sudo, sai quyền).
	//
	// TÁCH khỏi lỗi thực thi có chủ đích: "chưa cài đặt xong" và "thao tác thất
	// bại" dẫn người vận hành tới hai chỗ khác nhau, và gộp chúng lại sẽ khiến
	// họ đi tìm lỗi trong app khi vấn đề nằm ở sudoers.
	ErrUnavailable = errors.New("privops: privileged operation is not available")
	// ErrInvalidArg — đối số không qua được kiểm ở phía Go.
	ErrInvalidArg = errors.New("privops: invalid argument")
)

// appIDRe — cùng luật với script. Kiểm ở CẢ HAI phía có chủ đích: phía Go bắt
// lỗi sớm và cho thông báo tốt hơn; phía script là hàng rào thật, vì nó vẫn
// đứng vững khi ai đó gọi script từ chỗ khác.
var appIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$`)

// defaultTimeout — mọi thao tác ở đây là cục bộ và nhanh.
//
// 30 giây vì `appdata.sh remove` phải xoá một cây thư mục có thể lớn. Không có
// timeout thì một script treo giữ luôn goroutine gọi nó, và với reconciler thì
// đó là cả vòng hội tụ đứng im.
const defaultTimeout = 30 * time.Second

// Runner thực thi một thao tác đặc quyền. Interface để test không phải có
// sudo, và để một bản cài đặt tương lai (helper qua unix socket) thay được
// mà không đụng chỗ gọi.
type Runner interface {
	Run(ctx context.Context, script string, args ...string) (string, error)
}

// Ops — mặt tiền của package. Zero value KHÔNG dùng được; luôn tạo bằng New.
type Ops struct {
	run Runner
}

func New(r Runner) *Ops { return &Ops{run: r} }

// NewFromBase dựng Ops chạy script dưới <base>/scripts qua sudo.
func NewFromBase(base string) *Ops {
	return New(&SudoRunner{Dir: filepath.Join(base, "scripts"), Base: base})
}

// --- runner thật ------------------------------------------------------------------

// SudoRunner gọi `sudo -n <dir>/<script> <args...>`.
type SudoRunner struct {
	// Dir — thư mục chứa script. Phải khớp đường dẫn TUYỆT ĐỐI trong sudoers:
	// sudo so khớp theo đường dẫn, nên lệch một ký tự là "password required".
	Dir string
	// Base — giá trị KEENRIG_BASE truyền cho script.
	Base string
	// Timeout; 0 → defaultTimeout.
	Timeout time.Duration
}

func (s *SudoRunner) Run(ctx context.Context, script string, args ...string) (string, error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	path := filepath.Join(s.Dir, script)
	// -n: KHÔNG BAO GIỜ hỏi mật khẩu. Thiếu cờ này thì một dòng sudoers sai sẽ
	// làm sudo chờ nhập mật khẩu trên một stdin không có ai gõ — script treo
	// tới hết timeout, và triệu chứng là "thao tác chậm" chứ không phải
	// "cấu hình sudo sai".
	cmd := exec.CommandContext(ctx, "sudo", append([]string{"-n", path}, args...)...)
	cmd.Env = append(os.Environ(), "KEENRIG_BASE="+s.Base)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		// Phân biệt "không gọi được" với "gọi được nhưng thất bại".
		if isUnavailable(err, msg) {
			return "", fmt.Errorf("%w: %s: %s", ErrUnavailable, script, msg)
		}
		return "", fmt.Errorf("privops: %s: %s", script, msg)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func isUnavailable(err error, stderr string) bool {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return true // sudo không tồn tại, hoặc không exec được
	}
	low := strings.ToLower(stderr)
	for _, s := range []string{
		"a password is required", "no such file", "command not found",
		"is not allowed to execute", "not in the sudoers file",
		// NoNewPrivs trên tiến trình box — xem NoNewPrivs(). sudo và sudo-rs
		// báo khác nhau, nên khớp cả hai.
		"no new privileges", "effective uid is not 0",
	} {
		if strings.Contains(low, s) {
			return true
		}
	}
	return false
}

// --- thao tác --------------------------------------------------------------------

// Available kiểm MỘT script gọi được không, bằng cờ --check (không tác dụng phụ).
//
// Có hàm này để box báo NGAY LÚC KHỞI ĐỘNG rằng sudoers chưa đúng, thay vì để
// người vận hành phát hiện lúc bấm nút xoá app và không có gì xảy ra.
func (o *Ops) Available(ctx context.Context, script string) error {
	_, err := o.run.Run(ctx, script, "--check")
	return err
}

// NoNewPrivs báo tiến trình này có mang cờ no_new_privs không (Linux; nơi
// khác luôn false). Cờ đó làm nhân bỏ qua bit setuid của sudo, nên MỌI script
// ở đây hỏng cùng lúc.
//
// Có hàm riêng thay vì để AvailableAll tự lộ ra, vì nguyên nhân nằm ở chỗ
// không ai nghĩ tới: systemd NGẦM bật cờ này cho unit có User= không phải root
// mà dùng tuỳ chọn seccomp (RestrictSUIDSGID=, ProtectKernelModules=, ...).
// Unit không có chữ NoNewPrivileges nào — chỉ /proc/self/status nói thật. Đo
// trên VPS 2026-10-14: n8n kẹt restart với EACCES vì chown-volume không chạy.
func NoNewPrivs() bool {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	return noNewPrivsIn(string(b))
}

func noNewPrivsIn(status string) bool {
	for _, line := range strings.Split(status, "\n") {
		if v, ok := strings.CutPrefix(line, "NoNewPrivs:"); ok {
			return strings.TrimSpace(v) == "1"
		}
	}
	return false
}

// AvailableAll kiểm toàn bộ bộ script; trả danh sách cái hỏng.
func (o *Ops) AvailableAll(ctx context.Context) map[string]error {
	out := map[string]error{}
	for _, s := range AllScripts() {
		if err := o.Available(ctx, s); err != nil {
			out[s] = err
		}
	}
	return out
}

// AllScripts — bề mặt đặc quyền, liệt kê một chỗ. Phải khớp sudoers/keenrig.
func AllScripts() []string {
	return []string{
		ScriptCaddyBootstrap, ScriptNginxBootstrap, ScriptNginxCtl,
		ScriptRestartService, ScriptAppData, ScriptDU, ScriptReboot, ScriptPair,
	}
}

const (
	ScriptCaddyBootstrap = "caddy-bootstrap.sh"
	ScriptNginxBootstrap = "nginx-bootstrap.sh"
	ScriptNginxCtl       = "nginx-ctl.sh"
	ScriptRestartService = "restartservice.sh"
	ScriptAppData        = "appdata.sh"
	ScriptDU             = "du.sh"
	ScriptReboot         = "reboot.sh"
	ScriptPair           = "pair.sh"
)

// joinTokenRe — hình dạng join token Console phát ra (NewPairingToken: 32 byte
// hex). Kiểm cả ở đây lẫn trong pair.sh: ở đây để trả 400 rõ ràng thay vì một
// lần gọi sudo vô ích, ở script vì sudoers không kiểm được đối số.
var joinTokenRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Pair ghép node với Keenrig Console bằng join token, trả env id. Dùng cho máy
// cài standalone rồi mới muốn quản từ Console — cùng việc `get.sh --join`.
func (o *Ops) Pair(ctx context.Context, token string) (string, error) {
	if !joinTokenRe.MatchString(token) {
		return "", fmt.Errorf("%w: join token must be the 64-character token from the Console", ErrInvalidArg)
	}
	return o.run.Run(ctx, ScriptPair, token)
}

// Service — dịch vụ restart được. Kiểu riêng chứ không phải string: một hằng
// số sai chính tả khi đó là lỗi biên dịch, không phải lỗi lúc chạy.
type Service string

const (
	ServiceCaddy  Service = "caddy"
	ServiceNginx  Service = "nginx"
	ServiceDocker Service = "docker"
	ServiceBox    Service = "box"
	ServiceAgent  Service = "agent"
)

// RestartService nạp lại / khởi động lại một dịch vụ.
func (o *Ops) RestartService(ctx context.Context, svc Service) error {
	_, err := o.run.Run(ctx, ScriptRestartService, string(svc))
	return err
}

// BootstrapNginx dựng cấu hình gốc cho nginx rồi khởi động nó.
//
// waf=true bật ModSecurity + OWASP CRS. Script TỪ CHỐI nếu module chưa nạp —
// khai CapWAF mà module không có là nói dối tầng admission, và người dùng sẽ
// tưởng app của họ đang được bảo vệ.
func (o *Ops) BootstrapNginx(ctx context.Context, waf bool) error {
	args := []string{}
	if waf {
		args = append(args, "--waf")
	}
	_, err := o.run.Run(ctx, ScriptNginxBootstrap, args...)
	return err
}

// BootstrapCaddy dựng cấu hình gốc cho Caddy rồi khởi động nó.
//
// Idempotent: gọi lại trên một máy đã chạy sẽ ghi lại cấu hình gốc và reload.
// Cấu hình gốc KHÔNG chứa route nào, nên nó không xoá gì của driver — driver
// đẩy lại toàn bộ ở vòng reconcile kế tiếp (level-triggered).
func (o *Ops) BootstrapCaddy(ctx context.Context) error {
	_, err := o.run.Run(ctx, ScriptCaddyBootstrap)
	return err
}

// CreateAppData tạo data directory cho app, trả đường dẫn.
func (o *Ops) CreateAppData(ctx context.Context, appID string) (string, error) {
	if !appIDRe.MatchString(appID) {
		return "", fmt.Errorf("%w: app-id %q", ErrInvalidArg, appID)
	}
	return o.run.Run(ctx, ScriptAppData, "create", appID)
}

// ChownAppData đổi chủ data directory sang uid:gid mà container chạy dưới.
func (o *Ops) ChownAppData(ctx context.Context, appID string, uid, gid int) error {
	if !appIDRe.MatchString(appID) {
		return fmt.Errorf("%w: app-id %q", ErrInvalidArg, appID)
	}
	if uid < 0 || gid < 0 {
		return fmt.Errorf("%w: negative uid/gid", ErrInvalidArg)
	}
	// uid 0 = root. Cho phép nhưng KHÔNG im lặng: một app chạy dưới root với
	// data directory thuộc root là chuyện có thật (nhiều image chính thống
	// làm vậy), nhưng nó phải là lựa chọn nhìn thấy được chứ không phải mặc
	// định người ta rơi vào.
	_, err := o.run.Run(ctx, ScriptAppData, "chown", appID,
		strconv.Itoa(uid)+":"+strconv.Itoa(gid))
	return err
}

// volumeNameRe — cùng luật với VolumeMount.Name (keenrig-contracts) và với
// appdata.sh chown-volume.
var volumeNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)

// ChownAppVolume đổi chủ ĐÚNG MỘT thư mục volume còn rỗng
// (`apps/<id>/volumes/<name>`, không đệ quy) sang uid:gid của container.
//
// Khác ChownAppData: cái đó đổi cả cây apps/<id>, sau đó box (user keenrig)
// không tạo thêm được thư mục volume nào. Docker driver gọi cái này khi
// os.Chown của chính nó bị EPERM — tức là mọi box thật, vì box không có
// CAP_CHOWN.
func (o *Ops) ChownAppVolume(ctx context.Context, appID, volume string, uid, gid int) error {
	if !appIDRe.MatchString(appID) {
		return fmt.Errorf("%w: app-id %q", ErrInvalidArg, appID)
	}
	if !volumeNameRe.MatchString(volume) {
		return fmt.Errorf("%w: volume %q", ErrInvalidArg, volume)
	}
	if uid < 0 || gid < 0 {
		return fmt.Errorf("%w: negative uid/gid", ErrInvalidArg)
	}
	_, err := o.run.Run(ctx, ScriptAppData, "chown-volume", appID, volume,
		strconv.Itoa(uid)+":"+strconv.Itoa(gid))
	return err
}

// RemoveAppData xoá data directory. Idempotent — không có cũng trả nil.
//
// Gọi từ pha 2 của xoá app (sau runtime.Remove, trước PurgeApp). Gọi sớm hơn
// là xoá dữ liệu khi container còn đang ghi vào nó.
func (o *Ops) RemoveAppData(ctx context.Context, appID string) error {
	if !appIDRe.MatchString(appID) {
		return fmt.Errorf("%w: app-id %q", ErrInvalidArg, appID)
	}
	_, err := o.run.Run(ctx, ScriptAppData, "remove", appID)
	return err
}

// DiskUsage trả dung lượng data directory của app, tính bằng BYTE.
func (o *Ops) DiskUsage(ctx context.Context, appID string) (int64, error) {
	if !appIDRe.MatchString(appID) {
		return 0, fmt.Errorf("%w: app-id %q", ErrInvalidArg, appID)
	}
	out, err := o.run.Run(ctx, ScriptDU, appID)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("privops: du returned %q, which is not a number: %w", out, err)
	}
	return n, nil
}

// Reboot khởi động lại máy.
func (o *Ops) Reboot(ctx context.Context) error {
	_, err := o.run.Run(ctx, ScriptReboot)
	return err
}
