// Package contracts chứa type Go tương ứng các JSON schema trong contracts/jsonschema.
package contracts

import (
	"encoding/json"
	"time"
)

// CommandKind — khớp enum kind trong sync.schema.json#/$defs/Command.
const (
	CommandKindSetDNSResult   = "set_dns_result"
	CommandKindInstallCert    = "install_cert"
	CommandKindRotateLicense  = "rotate_license"
	CommandKindNotice         = "notice"
	CommandKindMintAdminToken = "mint_admin_token"
	CommandKindPromote        = "promote"
	CommandKindOfferUpdate    = "offer_update"
	CommandKindFlipDNSConfirm = "flip_dns_confirm"
	CommandKindResizePlan     = "resize_plan"
	// CommandKindAppInstall — Console cài một app từ catalog (CON-09). Dấu
	// chấm là cố ý: nó mở họ app.* (xem $comment của enum trong schema).
	CommandKindAppInstall = "app.install"
)

// HostRole — khớp enum host_role trong sync.schema.json#/$defs/SyncRequest.
const (
	HostRolePrimary = "primary"
	HostRoleStandby = "standby"
	HostRoleSolo    = "solo"
)

// Runtime — khớp enum features.runtime trong license.schema.json.
const (
	RuntimeDocker = "docker"
	RuntimeSwarm  = "swarm"
	RuntimeK8s    = "k8s"
)

// AppState — khớp enum state trong sync.schema.json#/$defs/AppStatus.
const (
	AppStateDeploying = "deploying"
	AppStateRunning   = "running"
	AppStateStopped   = "stopped"
	AppStateError     = "error"
	AppStateUnknown   = "unknown"
)

// DefaultHTTPPort — cổng dùng khi desired không đặt http_port và image cũng
// không EXPOSE cổng nào. 80 là quy ước của phần lớn image web; đoán sai thì
// gateway trả 502 ngay lần request đầu, dễ thấy hơn nhiều so với việc không
// tạo endpoint nào (app "chạy" mà không ai vào được, không có manh mối).
const DefaultHTTPPort = 80

// Health — khớp enum health trong sync.schema.json#/$defs/AppStatus.
const (
	HealthHealthy   = "healthy"
	HealthUnhealthy = "unhealthy"
	HealthUnknown   = "unknown"
)

type DesiredApp struct {
	Image string `json:"image"`
	// HTTPPort — cổng app nghe BÊN TRONG container (gateway nối tới
	// <ip-container>:<http_port>). 0 = không đặt: platform suy từ EXPOSE của
	// image, không suy được thì DefaultHTTPPort.
	HTTPPort int               `json:"http_port,omitempty"`
	Domains  []string          `json:"domains,omitempty"`
	Env      map[string]string `json:"env,omitempty"`
	// Volumes — thư mục BỀN, mount vào container.
	//
	// Không khai = app KHÔNG giữ được file nào qua lần cập nhật: mỗi lần deploy
	// dựng một container MỚI từ image gốc, và mọi thứ ghi trong lớp ghi của
	// container cũ biến mất cùng nó.
	//
	// Đây là kênh lưu trữ thứ hai, tách khỏi `Addons` có chủ đích: file thô
	// (ảnh, kho git, tài liệu tải lên) thuộc về thư mục, còn bản ghi có cấu
	// trúc (bài viết, tài khoản) thuộc về database. Nhét ảnh 5 MB vào database
	// làm nó phình và chậm; lưu bình luận thành 10.000 file .txt làm mọi truy
	// vấn thành một lần quét thư mục.
	Volumes []VolumeMount `json:"volumes,omitempty"`
	Addons  *Addons       `json:"addons,omitempty"`
	// Policy — chính sách ở tầng BIÊN, gateway thực thi. Mỗi trường ứng với một
	// proxy.Capability và bị admission từ chối lúc tạo app nếu gateway đang chạy
	// không có năng lực đó (PR-08).
	Policy    *Policy    `json:"policy,omitempty"`
	Resources *Resources `json:"resources,omitempty"`
	SSO       *SSO       `json:"sso,omitempty"`
	Backup    *Backup    `json:"backup,omitempty"`
	Autoscale *Autoscale `json:"autoscale,omitempty"`
}

// VolumeMount — một thư mục bền của app.
//
// # Vì sao có `Name` chứ không chỉ `Path`
//
// Phía máy chủ neo theo `Name`, không theo `Path`. Nhờ vậy app đổi đường dẫn
// giữa hai phiên bản (ví dụ `/data` → `/var/lib/app`) mà dữ liệu KHÔNG mất —
// chỉ cần giữ nguyên `Name`. Nếu neo theo `Path` thì một lần đổi đường dẫn
// trong image sẽ trông y hệt một lần mất sạch dữ liệu, và người dùng không có
// cách nào phân biệt.
//
// Đây cũng là lý do `Name` là RANH GIỚI AN NINH còn `Path` thì không: `Name`
// trở thành một đoạn đường dẫn THẬT dưới `apps/<id>/volumes/`, nên một giá trị
// như `../../instance` sẽ mount thẳng thư mục chứa master.key vào container của
// app. `Path` thì chỉ có nghĩa BÊN TRONG container — nó không chạm tới máy chủ.
type VolumeMount struct {
	// Name — tên thư mục phía máy chủ. Chỉ [a-z0-9-], không bắt đầu/kết thúc
	// bằng '-'.
	Name string `json:"name"`
	// Path — đường dẫn TUYỆT ĐỐI bên trong container.
	Path string `json:"path"`
	// ReadOnly — mount chỉ đọc. Dùng cho dữ liệu nền tảng bơm xuống mà app
	// không được sửa.
	ReadOnly bool `json:"read_only,omitempty"`
}

// Policy — khớp desired.schema.json #/$defs/Policy.
//
// Danh sách này CỐ Ý ngắn hơn thứ một gateway làm được: chỉ trường nào có một
// năng lực canh mới được đưa vào. Trường không có năng lực canh sẽ im lặng không
// có tác dụng trên gateway không đỡ nó — và im lặng là điều tệ nhất ở tầng chính
// sách an ninh, vì người vận hành tin là mình đang được bảo vệ.
type Policy struct {
	WAF         *WAF         `json:"waf,omitempty"`
	RateLimit   *RateLimit   `json:"rate_limit,omitempty"`
	IPAllow     []string     `json:"ip_allow,omitempty"`
	IPDeny      []string     `json:"ip_deny,omitempty"`
	BodyLimitMB int          `json:"body_limit_mb,omitempty"`
	ForwardAuth *ForwardAuth `json:"forward_auth,omitempty"`
}

// WAF — Block là *bool, không phải bool, và đó là điều duy nhất đáng chú ý ở đây.
//
// Mặc định của schema là true. Với `bool` thường thì "người dùng không đặt" và
// "người dùng đặt false" cho ra CÙNG giá trị zero, nên không có cách nào áp mặc
// định true mà không ghi đè lựa chọn tường minh của người dùng — tức là một WAF
// người ta cố tình để chế độ chỉ-ghi-nhận sẽ tự bật chặn.
type WAF struct {
	Ruleset string `json:"ruleset"`
	Block   *bool  `json:"block,omitempty"`
}

// Blocking — mặc định true khi không đặt (xem godoc WAF).
func (w WAF) Blocking() bool { return w.Block == nil || *w.Block }

type RateLimit struct {
	RequestsPerMinute int `json:"requests_per_minute"`
	Burst             int `json:"burst,omitempty"`
}

type ForwardAuth struct {
	URL             string   `json:"url"`
	CopyHeaders     []string `json:"copy_headers,omitempty"`
	AllowedFailures int      `json:"allowed_failures,omitempty"`
}

type Addons struct {
	Postgres *AddonSpec `json:"postgres,omitempty"`
	Redis    *AddonSpec `json:"redis,omitempty"`
}

type AddonSpec struct {
	Enabled bool `json:"enabled"`
}

// Resources — phần cứng app được phép dùng.
//
// # Vì sao danh sách này ngắn hơn thứ Docker làm được
//
// Cùng luật với `Policy`: trường nào KHÔNG có năng lực canh thì không được đưa
// vào. Với tài nguyên, luật đó không phải sự tinh tế — nó là bài học đo được.
// Docker NHẬN `--storage-opt size=64m` trên storage driver không đỡ quota,
// không trả lỗi, rồi container ghi 128 MB vào "hạn 64 MB" một cách bình thường.
// Một trường được nhận mà không thực thi tệ hơn một trường không có: người vận
// hành tin là app đã bị chặn.
//
// Vì vậy mỗi trường ở đây ứng với một `resources.Capability`, và bị TỪ CHỐI lúc
// tạo app nếu runtime đang chạy không thực thi được nó (xem `internal/resources`).
//
// # Vì sao KHÔNG có băng thông mạng và cpuset
//
// Băng thông mạng: Docker/swarm/k8s đều không có chỗ khai; muốn có phải tự nặn
// `tc qdisc` trên veth của container, và một trường trông như giới hạn nhưng chỉ
// có tác dụng trên một trong ba runtime là đúng cái bẫy đoạn trên nói tới.
// `cpuset_cpus`: đó là quyết định XẾP CHỖ, không phải hạn mức — nó không chặn
// app dùng quá phần của mình, chỉ đổi chỗ app chạy.
type Resources struct {
	// MemoryMB — RAM tối đa (cgroup memory.max).
	MemoryMB int `json:"memory_mb,omitempty"`
	// MemorySwapMB — TỔNG memory+swap, không phải riêng swap. Đây là ngữ nghĩa
	// của Docker (`--memory-swap`) và ta giữ nguyên chứ không "dịch cho dễ
	// hiểu": một trường tên `swap_mb` nghĩa là "riêng swap" sẽ lệch đúng một
	// phép trừ so với thứ kernel nhận, và lệch đó không có cách nào nhìn thấy.
	//
	// Không đặt = app swap KHÔNG GIỚI HẠN. `memory_mb` một mình không chặn được
	// một app 512 MB làm cả box thrashing; nó chỉ chặn RAM thường trú.
	MemorySwapMB int `json:"memory_swap_mb,omitempty"`
	// CPU — trần CỨNG, tính theo số core (0.5 = nửa core). cgroup cpu.max.
	CPU float64 `json:"cpu,omitempty"`
	// CPUShares — trọng số TƯƠNG ĐỐI khi CPU tranh chấp; mặc định 1024.
	//
	// Khác `CPU` ở chỗ nó KHÔNG chặn: app một mình trên box rảnh vẫn dùng hết
	// core. Trần cứng 0.5 CPU trên một box 4 core đang rảnh là bỏ không 87% máy
	// — nên hai trường này cùng tồn tại có chủ đích, không phải trùng nhau.
	//
	// Con số TUYỆT ĐỐI mà kernel thấy phụ thuộc host (cgroup v2 quy đổi shares
	// → cpu.weight, và phép quy đổi khác nhau giữa runc/systemd: 512 shares đo
	// được là weight 59 trên một máy, 20 theo công thức runc). Vì vậy hợp đồng
	// chỉ hứa THỨ TỰ: shares lớn hơn thì phần CPU lớn hơn.
	CPUShares int `json:"cpu_shares,omitempty"`
	// PidsLimit — số process/thread tối đa (cgroup pids.max). Đây là phòng
	// tuyến chống fork bomb, KHÔNG phải ulimit nproc: nproc của Docker tính
	// theo UID và đếm chung mọi container cùng UID, nên nó vừa rò rỉ qua ranh
	// giới app vừa không chặn được đúng thứ cần chặn.
	PidsLimit int `json:"pids_limit,omitempty"`
	// DiskMB — trần lớp ghi của container (KHÔNG tính volume bền).
	//
	// Chỉ thực thi được trên storage driver có quota (overlay2 trên xfs bật
	// pquota, btrfs, zfs). Ở nơi khác nó bị TỪ CHỐI lúc tạo app — xem godoc
	// type này về `--storage-opt` bị nhận trong im lặng.
	DiskMB int `json:"disk_mb,omitempty"`
	// IOReadMBps/IOWriteMBps — trần băng thông đĩa, MB/s (cgroup io.max rbps/wbps).
	IOReadMBps  int `json:"io_read_mbps,omitempty"`
	IOWriteMBps int `json:"io_write_mbps,omitempty"`
	// IOReadIOPS/IOWriteIOPS — trần số phép vào/ra mỗi giây (io.max riops/wiops).
	// Tách khỏi băng thông vì hai kiểu hỏng khác nhau: một app ghi log 200 MB/s
	// và một app fsync 50.000 lần/giây đều giết đĩa, nhưng chỉ một trong hai bị
	// trần MB/s chặn.
	IOReadIOPS  int `json:"io_read_iops,omitempty"`
	IOWriteIOPS int `json:"io_write_iops,omitempty"`
	// Ulimits — giới hạn theo process. Cần cho CẢ HAI hướng: chặn app xài cạn
	// file descriptor của host, và NÂNG hạn mặc định cho app thật sự cần
	// (postgres, node) — nên nó không phải "chỉ để siết".
	Ulimits []Ulimit `json:"ulimits,omitempty"`
	// ShmSizeMB — kích thước /dev/shm. Mặc định của Docker là 64 MB và đó là
	// nguyên nhân một loạt app chết không rõ lý do (Chromium, PostgreSQL với
	// parallel query): chúng không báo "thiếu shm", chúng chỉ crash.
	ShmSizeMB int `json:"shm_size_mb,omitempty"`
	Replicas  int `json:"replicas,omitempty"`
}

// Ulimit — một hạn mức theo process, ngữ nghĩa y hệt `docker run --ulimit`.
//
// Soft là hạn đang áp, Hard là trần mà process được tự nâng Soft tới. Hard = 0
// nghĩa là "bằng Soft" — không phải "không giới hạn": một hợp đồng mà 0 nghĩa là
// vô hạn sẽ biến mọi ulimit khai thiếu Hard thành ulimit bị vô hiệu.
type Ulimit struct {
	Name string `json:"name"`
	Soft int64  `json:"soft"`
	Hard int64  `json:"hard,omitempty"`
}

// HardOr trả Hard, hoặc Soft khi Hard không đặt (xem godoc Ulimit).
func (u Ulimit) HardOr() int64 {
	if u.Hard == 0 {
		return u.Soft
	}
	return u.Hard
}

type SSO struct {
	Enabled bool `json:"enabled"`
}

type Backup struct {
	Enabled  bool   `json:"enabled"`
	Schedule string `json:"schedule,omitempty"`
}

type Autoscale struct {
	Enabled     bool `json:"enabled"`
	CPUHigh     int  `json:"cpu_high,omitempty"`
	MaxReplicas int  `json:"max_replicas,omitempty"`
}

type AppStatus struct {
	AppID      string `json:"app_id"`
	Slug       string `json:"slug,omitempty"`
	State      string `json:"state"`
	DesiredRev int64  `json:"desired_rev,omitempty"`
	AppliedRev int64  `json:"applied_rev,omitempty"`
	Health     string `json:"health,omitempty"`
	Message    string `json:"message,omitempty"`
}

type Heartbeat struct {
	TS      time.Time `json:"ts"`
	UptimeS int64     `json:"uptime_s,omitempty"`
}

type SyncRequest struct {
	EnvID            string          `json:"env_id"`
	HostRole         string          `json:"host_role,omitempty"`
	Version          string          `json:"version"`
	Heartbeat        Heartbeat       `json:"heartbeat"`
	ReplLagSeconds   float64         `json:"repl_lag_seconds,omitempty"`
	AppStatuses      []AppStatus     `json:"app_statuses,omitempty"`
	MetricsSummary   *MetricsSummary `json:"metrics_summary,omitempty"`
	CommandResults   []CommandResult `json:"command_results,omitempty"`
	CertFingerprints []string        `json:"cert_fingerprints,omitempty"`
}

// MetricsSummary — khớp `sync.schema.json#/$defs/MetricsSummary` (OB-06).
//
// Mọi trường là CON TRỎ, và đó là nội dung của OB-05(2): "không đo được" phải
// truyền được qua JSON, mà số 0 thì không phân biệt nổi "CPU đang rảnh" với
// "CPU không đọc được". Con trỏ nil + omitempty = trường VẮNG trên dây, đúng
// như schema cho phép (không trường nào required).
//
// Đơn vị nằm trong tên trường — _pct, _mb, _gb, _kbps — vì đơn vị để trong tài
// liệu là đơn vị sẽ bị đọc sai: ba ô CPU/RAM/Disk của Console từng vẽ từ những
// cái tên UI tự đoán trước khi có $defs này.
type MetricsSummary struct {
	CPUPct       *float64 `json:"cpu_pct,omitempty"`
	MemUsedMB    *float64 `json:"mem_used_mb,omitempty"`
	MemTotalMB   *float64 `json:"mem_total_mb,omitempty"`
	DiskUsedGB   *float64 `json:"disk_used_gb,omitempty"`
	DiskTotalGB  *float64 `json:"disk_total_gb,omitempty"`
	NetRxKbps    *float64 `json:"net_rx_kbps,omitempty"`
	NetTxKbps    *float64 `json:"net_tx_kbps,omitempty"`
	LastBackupAt *string  `json:"last_backup_at,omitempty"`
	LastBackupOK *bool    `json:"last_backup_ok,omitempty"`
}

type Command struct {
	ID             string          `json:"id"`
	IdempotencyKey string          `json:"idempotency_key"`
	Kind           string          `json:"kind"`
	Payload        json.RawMessage `json:"payload"`
	Sig            string          `json:"sig,omitempty"`
	ExpiresAt      *time.Time      `json:"expires_at,omitempty"`
}

type CommandResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type SyncResponse struct {
	Commands   []Command `json:"commands"`
	NextPollMS int       `json:"next_poll_ms,omitempty"`
	// ParentDomain/DomainMode — tên miền gốc CLOUD đã chọn cho môi trường
	// (2026-09-07). Trạng thái, không phải sự kiện: đi kèm mọi nhịp sync để box
	// tự chữa mà không cần backfill; box chỉ nhận, không đặt lại.
	ParentDomain string `json:"parent_domain,omitempty"`
	DomainMode   string `json:"domain_mode,omitempty"`
}

type LicensePayload struct {
	LicenseID  string    `json:"license_id"`
	InstanceID string    `json:"instance_id"`
	EnvID      string    `json:"env_id,omitempty"`
	Features   Features  `json:"features"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	GraceDays  int       `json:"grace_days"`
}

// Features — bốn con số + cờ HA + tên bậc, khớp license.schema.json v2.
//
// 0 ở các trường Max* nghĩa là KHÔNG GIỚI HẠN. Instance thi hành theo SỐ, không
// theo tên bậc — `Plan` chỉ để UI và log nói được tên, nên thêm bậc mới không
// cần binary mới ở máy khách.
type Features struct {
	Plan       string `json:"plan,omitempty"`
	Runtime    string `json:"runtime"`
	MaxNodes   int    `json:"max_nodes,omitempty"`
	MaxApps    int    `json:"max_apps,omitempty"`
	MaxDomains int    `json:"max_domains,omitempty"`
	HAT1       bool   `json:"ha_t1"`
}

type Manifest struct {
	ID          string       `json:"id"`
	Version     string       `json:"version"`
	Title       string       `json:"title,omitempty"`
	Description string       `json:"description,omitempty"`
	Image       string       `json:"image"`
	HTTPPort    int          `json:"httpPort"`
	Addons      *Addons      `json:"addons,omitempty"`
	Healthcheck *Healthcheck `json:"healthcheck,omitempty"`
	NeedsTags   []string     `json:"needs_tags,omitempty"`
	Scalable    bool         `json:"scalable,omitempty"`
}

type Healthcheck struct {
	Path      string `json:"path,omitempty"`
	IntervalS int    `json:"interval_s,omitempty"`
	TimeoutS  int    `json:"timeout_s,omitempty"`
}
