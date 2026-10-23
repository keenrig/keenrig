// Package addons — seam #3 `addons.Addon`: cấp phát service dữ liệu cho app và
// tiêm credential vào container.
//
// # Hai hình dạng, MỘT interface — và đó là ràng buộc quan trọng nhất ở đây
//
// Hai addon đầu tiên có kiến trúc NGƯỢC nhau:
//
//	postgres  MỘT container dùng chung cho mọi app. Setup tạo DB + user riêng
//	          BÊN TRONG nó. Teardown xoá DB + user, container vẫn chạy vì app
//	          khác đang dùng.
//	redis     MỘT container CHO MỖI app. Setup dựng container, Teardown xoá
//	          hẳn nó. Không có gì dùng chung.
//
// Interface phải đúng cho cả hai mà không rò rỉ chi tiết của cái nào. Cụ thể:
// nó KHÔNG có method nào tên `CreateDatabase`, và KHÔNG có method nào tên
// `StartContainer`. Cả hai đều là chi tiết của một hình dạng, và đặt vào
// interface là ép hình dạng kia phải giả vờ.
//
// Hệ quả đo được: `Teardown` của postgres phải không làm app khác gãy (AD-04),
// còn `Teardown` của redis thì được phép xoá cả container. Conformance suite
// kiểm CÙNG MỘT khẳng định trên cả hai — "sau Teardown, app này mất dữ liệu,
// app khác thì không" — và mỗi driver tự chọn cách thoả.
//
// # Vì sao `Env` là method, không phải một trường dữ liệu
//
// Credential nằm trong bảng `secrets` (mã hoá AES-256-GCM), không nằm trong
// `app_addons`. `Env` đọc secret ra rồi dựng bộ biến. Nếu nó là dữ liệu tĩnh
// trả về từ `Setup` thì mật khẩu phải đi qua thêm một chặng và nằm lại trong
// bất cứ chỗ nào caller lưu kết quả — kể cả log.
//
// # Namespace KEENRIG_ là HỢP ĐỒNG CÔNG KHAI
//
// `addon.schema.json` ép `^KEENRIG_[A-Z0-9_]+$`. Đổi tên một biến là breaking
// change với MỌI image app đang chạy, không phải refactor nội bộ. Validate ở
// tầng này chứ không tin driver: một driver mới đặt sai tên biến sẽ làm app của
// người dùng mất kết nối DB, và triệu chứng nằm trong log của app chứ không
// trong log của ta.
package addons

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/keenrig/keenrig/keenrig-node/internal/paths"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// Kind — addon đã đăng ký. Phải khớp enum trong addon.schema.json.
type Kind string

const (
	KindPostgres Kind = "postgres"
	KindRedis    Kind = "redis"
)

// AllKinds — dùng cho validate và cho UI. Thứ tự ổn định.
func AllKinds() []Kind { return []Kind{KindPostgres, KindRedis} }

var (
	// ErrUnknownAddon — kind không có driver.
	ErrUnknownAddon = errors.New("addons: no such addon")
	// ErrNotProvisioned — chưa Setup mà đã gọi Env/Backup/Restore.
	ErrNotProvisioned = errors.New("addons: this addon is not provisioned for the app")
	// ErrBadEnvName — tên biến môi trường vi phạm namespace KEENRIG_.
	//
	// Lỗi RIÊNG có chủ đích: nó không phải "cấu hình sai" mà là "driver vi phạm
	// hợp đồng công khai", và hai thứ đó dẫn tới hai hành động khác nhau.
	ErrBadEnvName = errors.New("addons: the environment variable name violates the KEENRIG_ namespace")
	// ErrInfraNotReady — service hạ tầng chưa lên (container chưa chạy).
	//
	// Tách khỏi lỗi thật: reconciler phải BACKOFF chứ không đánh dấu app lỗi.
	// Postgres mất 2–3 giây để nhận kết nối đầu tiên; coi đó là lỗi nghĩa là
	// mọi app đầu tiên trên một máy mới đều vào trạng thái error.
	ErrInfraNotReady = errors.New("addons: the infrastructure service is not ready")
)

// envNameRe — CÙNG mẫu với addon.schema.json. Trùng lặp có chủ đích: schema
// canh dữ liệu đi qua API, hàm này canh dữ liệu do driver tự sinh — và driver
// không đi qua API.
var envNameRe = regexp.MustCompile(`^KEENRIG_[A-Z0-9_]+$`)

// Config — thứ mọi driver nhận khi được mở. Cùng mô hình runtime/proxy.
type Config struct {
	// Layout quyết định data directory addon. Driver KHÔNG nhận đường dẫn từ
	// nơi khác — dữ liệu addon phải ở node/addons/<tên>/ (FILESYSTEM.md).
	Layout paths.Layout
	// Store để lưu credential (mã hoá) và bản ghi app_addons.
	Store store.Store
	// Runtime để dựng container hạ tầng. Driver KHÔNG tự gọi Docker: nếu nó gọi
	// thẳng thì đổi sang swarm/k8s là viết lại từng driver addon.
	Runtime InfraRuntime
	// InfraVersion — bump nó là TÍN HIỆU DUY NHẤT bắt dựng lại container addon.
	// Không có tín hiệu tường minh thì
	// nâng cấp hạ tầng thành hệ quả ngẫu nhiên của một tag bị đẩy lại.
	InfraVersion int
	// Images — image hạ tầng đã PIN DIGEST, khoá theo tên addon.
	Images map[string]PinnedImage
}

// PinnedImage — khớp infra.schema.json.
type PinnedImage struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Digest     string `json:"digest"`
}

// Ref trả tham chiếu DÙNG ĐỂ CHẠY: repository@digest. Không kèm tag — cùng lý
// do với catalog.Manifest.ImageRef.
func (p PinnedImage) Ref() string { return p.Repository + "@" + p.Digest }

// InfraRuntime — phần runtime mà driver addon cần. Interface HẸP thay vì nhận
// thẳng runtime.Runtime: driver addon chỉ được dựng/gỡ container hạ tầng của
// chính nó, không được đụng container app của người dùng.
type InfraRuntime interface {
	// EnsureInfra dựng (hoặc xác nhận đã có) một container hạ tầng và trả địa
	// chỉ nội bộ để kết nối tới. Idempotent.
	EnsureInfra(ctx context.Context, spec InfraSpec) (InfraStatus, error)
	// RemoveInfra gỡ container hạ tầng. Idempotent — không có cũng trả nil.
	RemoveInfra(ctx context.Context, name string) error
	// Exec chạy một lệnh BÊN TRONG container hạ tầng.
	//
	// # Vì sao driver addon dùng Exec thay vì nối TCP tới DB
	//
	// Hai lý do, và lý do thứ hai mới là lý do quyết định:
	//
	//  1. Không thêm dependency: chạy DDL qua `psql -c` khỏi cần một driver
	//     PostgreSQL trong go.mod, và khỏi cần box tới được IP container.
	//  2. `Backup` CẦN `pg_dump` — một NHỊ PHÂN, chỉ có sẵn trong image postgres.
	//     Ta không muốn bắt máy chủ cài postgres-client. Nên Exec là bắt buộc
	//     dù sao; và khi đã có nó, dùng TCP cho DDL nghĩa là hai cơ chế song
	//     song cho cùng một việc — hai chỗ để hỏng, hai chỗ để cấu hình sai.
	//
	// Exec có ở cả ba runtime (docker exec · swarm · k8s exec), nên lựa chọn này
	// không khoá ta vào Docker.
	Exec(ctx context.Context, spec ExecSpec) (ExecResult, error)
}

// ExecSpec — lệnh chạy trong container hạ tầng.
type ExecSpec struct {
	// Name — container hạ tầng.
	Name string
	Cmd  []string
	// Stdin — dữ liệu đưa vào lệnh.
	//
	// BÍ MẬT PHẢI ĐI QUA ĐÂY, KHÔNG QUA Cmd. Đối số dòng lệnh hiện trong
	// `ps` của MỌI tiến trình trong container — kể cả tiến trình của app khác
	// nếu container đó dùng chung. Một `psql -c "… PASSWORD 'abc'"` là mật khẩu
	// nằm trong process list cho tới khi lệnh kết thúc.
	Stdin []byte
	// Env cho lệnh (vd PGPASSWORD).
	Env map[string]string
}

// ExecResult — kết quả Exec. ExitCode ≠ 0 KHÔNG phải error của Exec: lệnh chạy
// được nhưng trả mã lỗi là thông tin, và driver cần đọc stderr để biết vì sao.
type ExecResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// OK — lệnh chạy xong với mã 0.
func (r ExecResult) OK() bool { return r.ExitCode == 0 }

// Err dựng lỗi đọc được từ kết quả thất bại.
func (r ExecResult) Err(what string) error {
	msg := strings.TrimSpace(string(r.Stderr))
	if msg == "" {
		msg = strings.TrimSpace(string(r.Stdout))
	}
	if msg == "" {
		msg = fmt.Sprintf("exit code %d, no output", r.ExitCode)
	}
	return fmt.Errorf("addons: %s: %s", what, msg)
}

// InfraSpec — container hạ tầng cần dựng.
type InfraSpec struct {
	// Name — định danh container hạ tầng, ví dụ "postgres" hoặc "redis-app-1".
	Name  string
	Image PinnedImage
	// Cmd ghi đè entrypoint args của image. Rỗng = dùng mặc định của image.
	//
	// Cần cho redis: nó nhận cấu hình qua đối số hoặc file, không qua env như
	// postgres. Nhưng ĐỪNG truyền bí mật qua đây — `docker inspect` hiện toàn
	// bộ Cmd, và với container dùng chung thì `ps` bên trong cũng hiện. Cách
	// đúng: ghi một file cấu hình vào DataDir (box sở hữu thư mục đó) rồi trỏ
	// Cmd vào file.
	Cmd []string
	Env map[string]string
	// DataDir trên máy chủ, mount vào container. Rỗng = không có dữ liệu bền.
	DataDir string
	// Port container nghe bên trong.
	Port int
	// InfraVersion đi kèm để runtime biết phải dựng lại khi nó đổi.
	InfraVersion int
}

// InfraStatus — kết quả EnsureInfra.
type InfraStatus struct {
	// Host/Port là địa chỉ NỘI BỘ để app kết nối tới.
	Host string
	Port int
	// Ready = container đang chạy VÀ nhận kết nối. false → ErrInfraNotReady.
	Ready bool
	// Message giải thích khi chưa ready.
	Message string
}

// Creds — credential cấp cho MỘT app trên MỘT addon.
//
// Đây là thứ Setup trả về. Nó KHÔNG được lưu nguyên vào app_addons: phần nhạy
// cảm đi vào bảng secrets, app_addons chỉ giữ khoá tra cứu.
type Creds struct {
	// Env — biến tiêm vào container app. Tên PHẢI khớp ^KEENRIG_[A-Z0-9_]+$.
	Env map[string]string
	// SecretRef — khoá tra cứu trong store.Secrets. Rỗng nghĩa là addon này
	// không có gì nhạy cảm (chưa có ca nào, nhưng interface không cấm).
	SecretRef string
}

// Addon — hợp đồng driver addon. Năm method, đúng như AD-01.
//
//   - Setup IDEMPOTENT: gọi lại cho cùng app KHÔNG tạo DB/user trùng và trả về
//     credential ĐÃ CÓ, không sinh mật khẩu mới (AD-02). Sinh mật khẩu mới ở
//     lần gọi thứ hai nghĩa là container app đang chạy với mật khẩu cũ mất kết
//     nối, và không có gì trong hệ thống nói ra điều đó.
//   - Teardown dọn phần của app NÀY. App khác dùng chung service không được
//     ảnh hưởng (AD-04). Idempotent.
//   - Env đọc credential đã cấp. Chưa Setup → ErrNotProvisioned.
//   - Backup/Restore làm việc trên MỘT app, không phải cả service — restore
//     một app không được cuốn theo dữ liệu app khác.
type Addon interface {
	Kind() Kind
	// Setup cấp phát cho app. Idempotent.
	Setup(ctx context.Context, appID string) (Creds, error)
	// Teardown dọn phần của app này. Idempotent.
	Teardown(ctx context.Context, appID string) error
	// Env trả bộ biến môi trường để tiêm vào container app.
	Env(ctx context.Context, appID string) (map[string]string, error)
	// Backup ghi dump dữ liệu của app ra dir. dir do caller tạo sẵn.
	Backup(ctx context.Context, appID, dir string) error
	// Restore nạp dump từ dir. GHI ĐÈ dữ liệu hiện có của app đó.
	Restore(ctx context.Context, appID, dir string) error
}

// ValidateEnv ép hợp đồng namespace. Gọi ở TẦNG NÀY, không tin driver.
//
// Một driver mới đặt sai tên biến sẽ làm app của người dùng mất kết nối DB, và
// triệu chứng nằm trong log của APP chứ không trong log của ta — nên nó phải
// bị chặn trước khi rời khỏi package này.
func ValidateEnv(env map[string]string) error {
	if len(env) == 0 {
		return fmt.Errorf("%w: the variable set is empty", ErrBadEnvName)
	}
	names := make([]string, 0, len(env))
	for k := range env {
		names = append(names, k)
	}
	sort.Strings(names) // lỗi báo ra phải ổn định giữa các lần chạy
	for _, k := range names {
		if !envNameRe.MatchString(k) {
			return fmt.Errorf("%w: %q", ErrBadEnvName, k)
		}
		if strings.ContainsRune(env[k], 0) {
			// NUL bị cắt cụt ở tầng syscall: giá trị ta đặt và giá trị app nhận
			// sẽ khác nhau, và không có lỗi nào được sinh ra.
			return fmt.Errorf("addons: the value of %s contains a NUL byte", k)
		}
	}
	return nil
}

// --- registry -----------------------------------------------------------------
//
// Cùng mô hình runtime/proxy: driver tự Register trong init(), core không biết
// tên cụ thể nào. Nhờ vậy thêm addon thứ ba không phải sửa file này.

// Factory dựng một Addon. Nhận ctx vì driver có thể phải bắt tay với service
// hạ tầng ngay lúc mở.
type Factory func(ctx context.Context, cfg Config) (Addon, error)

var (
	mu       sync.RWMutex
	registry = map[Kind]Factory{}
)

// Register gắn driver vào registry. Panic khi trùng tên hoặc tên rỗng: đây là
// lỗi lập trình lúc dựng chương trình, phải nổ lúc khởi động.
func Register(k Kind, f Factory) {
	if k == "" {
		panic("addons: Register called with an empty kind")
	}
	if f == nil {
		panic("addons: Register(" + string(k) + ") with a nil factory")
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[k]; dup {
		panic("addons: Register called twice for kind " + string(k))
	}
	registry[k] = f
}

// Registered trả kind của mọi driver đã biên dịch vào binary, đã sắp xếp.
func Registered() []Kind {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Kind, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Open dựng driver theo kind.
func Open(ctx context.Context, k Kind, cfg Config) (Addon, error) {
	mu.RLock()
	f, ok := registry[k]
	mu.RUnlock()
	if !ok {
		names := make([]string, 0, len(Registered()))
		for _, r := range Registered() {
			names = append(names, string(r))
		}
		return nil, fmt.Errorf("%w: %q (available: %s)", ErrUnknownAddon, k, strings.Join(names, ", "))
	}
	return f(ctx, cfg)
}
