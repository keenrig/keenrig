// Package store — persistence layer của keenrig-box trên SQLite (box sở hữu độc quyền — V2-DELTA Luật 5).
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: conflict")
	ErrNoJob    = errors.New("store: no job available")
)

// MaxJobAttempts — job fail đủ số lần này thì chuyển hẳn sang state 'failed'.
const MaxJobAttempts = 5

// DefaultJobLease — visibility timeout mặc định của ClaimJob (LS-03). Đủ dài
// cho job nặng nhất hiện có (backup, pull image) mà vẫn đủ ngắn để worker chết
// không giam job quá lâu.
const DefaultJobLease = 5 * time.Minute

// LeaseReconciler — tên lease của vòng lặp reconcile. Hằng số chứ không phải
// chuỗi rải rác: gõ sai tên lease nghĩa là hai tiến trình giành hai lease khác
// nhau và cùng tưởng mình là chủ.
const LeaseReconciler = "reconciler"

// Endpoint — một địa chỉ replica đang chạy, do reconciler ghi sau Apply.
type Endpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type App struct {
	ID         string          `json:"id"`
	Slug       string          `json:"slug"`
	Desired    json.RawMessage `json:"desired"`
	DesiredRev int64           `json:"desired_rev"`
	AppliedRev int64           `json:"applied_rev"`
	Status     json.RawMessage `json:"status,omitempty"`
	// Endpoints là DẪN XUẤT từ runtime — chỉ reconciler ghi, phần còn lại đọc.
	Endpoints []Endpoint `json:"endpoints,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Domain — một FQDN trỏ về app. UNIQUE(fqdn) enforce ở tầng DB (migration 0004).
type Domain struct {
	AppID     string    `json:"app_id"`
	FQDN      string    `json:"fqdn"`
	IsPrimary bool      `json:"is_primary"`
	CertRef   string    `json:"cert_ref,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// AppAddon — addon đã cấp cho app. ConfigRef là khoá tra cứu vào secrets,
// KHÔNG phải credential.
type AppAddon struct {
	AppID     string    `json:"app_id"`
	Addon     string    `json:"addon"`
	State     string    `json:"state"`
	ConfigRef string    `json:"config_ref,omitempty"`
	LastError string    `json:"last_error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// State hợp lệ của AppAddon.
const (
	AddonPending = "pending"
	AddonReady   = "ready"
	AddonError   = "error"
)

// Lease — quyền độc quyền có thời hạn trên một tên.
//
// Token là FENCING TOKEN: tăng đơn điệu mỗi lần lease đổi chủ, KHÔNG tăng khi
// gia hạn. Chủ bị treo (GC pause, ổ đĩa nghẽn) rồi tỉnh dậy vẫn tin mình giữ
// lease — chỉ token mới phân biệt được nó với chủ hiện tại, vì so sánh
// expires_at cần một giả định về đồng hồ mà ta không có quyền đặt ra.
type Lease struct {
	Name      string    `json:"name"`
	Holder    string    `json:"holder"`
	Token     int64     `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Expired cho biết lease đã quá hạn theo đồng hồ của tiến trình gọi.
func (l Lease) Expired(now time.Time) bool { return !now.Before(l.ExpiresAt) }

// User — tài khoản đăng nhập Admin (T10).
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	// PasswordHash là chuỗi argon2id MANG THEO tham số băm, không phải hash trần.
	PasswordHash string   `json:"-"`
	Scopes       []string `json:"scopes"`
	// TOTPRef trỏ vào bảng secrets; secret TOTP không bao giờ nằm ở bảng users.
	TOTPRef     string    `json:"-"`
	TOTPEnabled bool      `json:"totp_enabled"`
	Disabled    bool      `json:"disabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Session — phiên đăng nhập. TokenHash chứ không phải token: store không bao
// giờ thấy token trần.
type Session struct {
	TokenHash string    `json:"-"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	UserAgent string    `json:"user_agent,omitempty"`
	IP        string    `json:"ip,omitempty"`
}

// Lock — khoá trên một TÊN THAO TÁC, có chủ và có hạn.
//
// Khác Lease: Lease trả lời "ai được làm việc liên tục" (một reconciler, gia
// hạn mãi); Lock trả lời "thao tác A và B có chạy cùng lúc được không" (hữu
// hạn, có ma trận tương thích ở internal/locks).
type Lock struct {
	Name       string    `json:"name"`
	Holder     string    `json:"holder"`
	Reason     string    `json:"reason,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
	AcquiredAt time.Time `json:"acquired_at"`
}

// Expired cho biết khoá đã quá hạn theo đồng hồ của tiến trình gọi.
func (l Lock) Expired(now time.Time) bool { return !now.Before(l.ExpiresAt) }

// APIToken — token gọi API cho script/CI (ID-04).
//
// Khác Session ở vòng đời, không ở hình dạng: phiên ngắn và chết khi đổi mật
// khẩu; token dài, do người dùng đặt hạn, và SỐNG SÓT qua lần đổi mật khẩu.
type APIToken struct {
	// TokenHash — SHA-256 của token trần. Store không bao giờ thấy token trần.
	TokenHash string `json:"-"`
	// ID — khoá công khai để thu hồi; an toàn để hiện lên UI và dán vào ticket.
	ID     string   `json:"id"`
	UserID string   `json:"user_id"`
	Name   string   `json:"name,omitempty"`
	Scopes []string `json:"scopes"`
	// ExpiresAt luôn có giá trị: không tồn tại token vô hạn.
	ExpiresAt time.Time `json:"expires_at"`
	// AllowedIPCIDRs rỗng = mọi IP.
	AllowedIPCIDRs []string   `json:"allowed_ip_cidrs,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP     string     `json:"last_used_ip,omitempty"`
}

// OIDCClient — một app được phép cho người dùng đăng nhập bằng tài khoản
// Keenrig (ID-01).
//
// SecretRef là khoá tra cứu vào bảng secrets, KHÔNG phải secret — cùng luật với
// AppAddon.ConfigRef và User.TOTPRef.
type OIDCClient struct {
	ClientID string `json:"client_id"`
	// AppID rỗng = client cấp bằng tay cho một dịch vụ ngoài box.
	AppID     string `json:"app_id,omitempty"`
	Name      string `json:"name,omitempty"`
	SecretRef string `json:"-"`
	// RedirectURIs so khớp CHÍNH XÁC. Không wildcard, không so tiền tố.
	RedirectURIs []string  `json:"redirect_uris"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// OIDCCode — mã uỷ quyền, sống vài chục giây và dùng ĐÚNG MỘT LẦN.
type OIDCCode struct {
	CodeHash    string `json:"-"`
	ClientID    string `json:"client_id"`
	UserID      string `json:"user_id"`
	RedirectURI string `json:"redirect_uri"`
	Scope       string `json:"scope,omitempty"`
	Nonce       string `json:"nonce,omitempty"`
	// CodeChallenge là PKCE S256 đã mã hoá base64url. Luôn có giá trị.
	CodeChallenge string `json:"-"`
	// AuthTime là lúc người dùng THẬT SỰ đăng nhập, không phải lúc cấp mã.
	AuthTime  time.Time `json:"auth_time"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// LoginAttempts — bộ đếm thử sai cho rate-limit/lockout (ID-03).
type LoginAttempts struct {
	Key         string     `json:"key"`
	Failures    int        `json:"failures"`
	FirstFail   time.Time  `json:"first_fail"`
	LastFail    time.Time  `json:"last_fail"`
	LockedUntil *time.Time `json:"locked_until,omitempty"`
}

// Locked cho biết đang trong cửa sổ khoá.
func (l LoginAttempts) Locked(now time.Time) bool {
	return l.LockedUntil != nil && now.Before(*l.LockedUntil)
}

type Job struct {
	ID        int64           `json:"id"`
	Kind      string          `json:"kind"`
	Args      json.RawMessage `json:"args,omitempty"`
	State     string          `json:"state"`
	Attempt   int             `json:"attempt"`
	NotBefore *time.Time      `json:"not_before,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	LastError string          `json:"last_error,omitempty"`
	// LeaseUntil/LeaseOwner chỉ có nghĩa khi State = 'running'.
	LeaseUntil *time.Time `json:"lease_until,omitempty"`
	LeaseOwner string     `json:"lease_owner,omitempty"`
	// Percent/Message — tiến độ cho UI. Không có chúng thì "đang chạy" và
	// "đã treo" nhìn giống hệt nhau và người dùng sẽ bấm lại.
	Percent int    `json:"percent"`
	Message string `json:"message,omitempty"`
	// FinishedAt chỉ đặt khi job HẾT đường thử lại (done, hoặc failed sau khi
	// cạn attempt) — janitor dùng nó để dọn theo tuổi.
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

type Event struct {
	ID        int64           `json:"id"`
	Action    string          `json:"action"`
	Actor     string          `json:"actor,omitempty"`
	Subject   string          `json:"subject,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

type Store interface {
	Ping(ctx context.Context) error
	Close() error

	// SnapshotTo ghi một bản sao NHẤT QUÁN của database ra dst (dst phải chưa
	// tồn tại). Bản sao là MỘT file tự đủ, không kèm `-wal`/`-shm`.
	//
	// Nằm trong interface chứ không phải một method riêng của SQLite: đây là
	// bước đầu của mọi lần sao lưu instance (BK-02), nên một implementation
	// thứ hai không có nó là một implementation không sao lưu được — và điều đó
	// phải là lỗi lúc BIÊN DỊCH, không phải một dòng log lúc 3 giờ sáng.
	SnapshotTo(ctx context.Context, dst string) error

	CreateApp(ctx context.Context, app *App) error // desired_rev=1
	// GetApp — app đã đánh dấu xoá coi như không tồn tại (ErrNotFound).
	GetApp(ctx context.Context, id string) (*App, error)
	// ListApps KHÔNG trả app đang chờ xoá.
	ListApps(ctx context.Context) ([]*App, error)
	// ListAppsNeedingReconcile trả các app có desired_rev > applied_rev, ORDER BY created_at.
	// KHÔNG trả app đang chờ xoá (đừng vừa dựng vừa xoá).
	ListAppsNeedingReconcile(ctx context.Context) ([]*App, error)
	// ListAppsPendingDelete trả các app đã đánh dấu xoá mà chưa purge,
	// ORDER BY deleted_at — reconciler gọi runtime.Remove rồi PurgeApp.
	ListAppsPendingDelete(ctx context.Context) ([]*App, error)
	UpdateDesired(ctx context.Context, id string, desired json.RawMessage) (int64, error)
	// SetStatus enforce appliedRev <= desired_rev hiện tại; vi phạm → ErrConflict.
	SetStatus(ctx context.Context, id string, status json.RawMessage, appliedRev int64) error
	// DeleteApp là pha 1 của xoá 2 pha: đánh dấu deleted_at, KHÔNG xoá row.
	// App biến mất khỏi Get/List ngay, nhưng slug vẫn bị giữ tới khi PurgeApp
	// — chính điều đó chặn app mới dùng lại slug khi container cũ chưa dọn.
	DeleteApp(ctx context.Context, id string) error
	// PurgeApp là pha 2: DELETE row thật. Chỉ gọi sau khi runtime.Remove xong.
	// ON DELETE CASCADE dọn luôn app_domains + app_addons của app.
	PurgeApp(ctx context.Context, id string) error
	// SetEndpoints thay NGUYÊN KHỐI tập endpoint của app (level-triggered).
	// eps rỗng/nil → xoá sạch. Chỉ reconciler được gọi.
	SetEndpoints(ctx context.Context, id string, eps []Endpoint) error

	// AddDomain gắn FQDN vào app. FQDN đã có chủ (kể cả app khác) → ErrConflict;
	// app không tồn tại/đang chờ xoá → ErrNotFound. Đặt is_primary khi app đã có
	// domain chính khác cũng là ErrConflict.
	AddDomain(ctx context.Context, d *Domain) error
	// ListDomains trả domain của một app, ORDER BY is_primary DESC, fqdn.
	ListDomains(ctx context.Context, appID string) ([]*Domain, error)
	// ListAllDomains trả domain của MỌI app còn sống (bỏ app đang chờ xoá),
	// ORDER BY fqdn — đây là nguồn dựng desired cho proxy.Apply.
	ListAllDomains(ctx context.Context) ([]*Domain, error)
	// DeleteDomain gỡ FQDN; không có → ErrNotFound.
	DeleteDomain(ctx context.Context, fqdn string) error
	// SetDomainCertRef ghi khoá tra cứu cert cho FQDN (đường TLSProvided).
	SetDomainCertRef(ctx context.Context, fqdn, certRef string) error

	// PutAppAddon upsert bản ghi addon của app.
	PutAppAddon(ctx context.Context, a *AppAddon) error
	// ListAppAddons trả addon của một app, ORDER BY addon.
	ListAppAddons(ctx context.Context, appID string) ([]*AppAddon, error)
	// DeleteAppAddon gỡ addon khỏi app; không có → ErrNotFound.
	DeleteAppAddon(ctx context.Context, appID, addon string) error

	// AcquireLease giành lease trên name trong ttl.
	//
	// Thành công khi: chưa ai giữ · lease đã quá hạn · holder chính là mình
	// (gia hạn). Người khác đang giữ và CHƯA quá hạn → ErrConflict.
	// Token tăng khi đổi chủ, giữ nguyên khi gia hạn.
	AcquireLease(ctx context.Context, name, holder string, ttl time.Duration) (*Lease, error)
	// RenewLease gia hạn lease mình đang giữ. Sai holder HOẶC sai token →
	// ErrConflict, kể cả khi lease chưa quá hạn: sai token nghĩa là lease đã
	// đổi chủ ít nhất một lần kể từ lúc mình giành được.
	RenewLease(ctx context.Context, name, holder string, token int64, ttl time.Duration) (*Lease, error)
	// ReleaseLease nhả sớm; sai holder/token → ErrConflict, không có → ErrNotFound.
	ReleaseLease(ctx context.Context, name, holder string, token int64) error
	// GetLease đọc lease hiện tại (READ-ONLY, kể cả khi đã quá hạn).
	GetLease(ctx context.Context, name string) (*Lease, error)

	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string) error

	// PutSecret mã hoá plaintext và upsert theo ref.
	PutSecret(ctx context.Context, ref string, plaintext []byte) error
	// GetSecret giải mã; không có → ErrNotFound.
	GetSecret(ctx context.Context, ref string) ([]byte, error)
	// DeleteSecret xoá; 0 row → ErrNotFound.
	DeleteSecret(ctx context.Context, ref string) error

	// EnqueueJob thêm job queued; notBefore nil = chạy được ngay.
	//
	// not_before có ĐỘ PHÂN GIẢI GIÂY (§0.5 — RFC3339 giây để so sánh chuỗi):
	// notBefore được làm tròn LÊN giây, nên job chạy muộn hơn mốc hẹn tối đa
	// 1 giây và KHÔNG BAO GIỜ sớm hơn. Đừng trông đợi lịch dưới giây.
	EnqueueJob(ctx context.Context, kind string, args json.RawMessage, notBefore *time.Time) (int64, error)
	// ClaimJob claim atomic 1 job queued đến hạn (kinds rỗng = mọi kind); hết job → (nil, ErrNoJob).
	// Tương đương ClaimJobAs với owner rỗng và visibility = DefaultJobLease.
	ClaimJob(ctx context.Context, kinds []string) (*Job, error)
	// ClaimJobAs như ClaimJob nhưng ghi kèm chủ và HẠN GIỮ (visibility timeout).
	//
	// Không có hạn giữ thì worker chết = job kẹt 'running' vĩnh viễn, vì không
	// ai còn cầm id để gọi FailJob. visibility <= 0 → DefaultJobLease.
	ClaimJobAs(ctx context.Context, kinds []string, owner string, visibility time.Duration) (*Job, error)
	// ReclaimExpired đưa job 'running' quá hạn giữ về 'queued' (LS-03), trả số
	// job đã thu hồi. Job không có lease_until (do bản box cũ claim trước khi
	// migrate) KHÔNG bị đụng — không cướp job mà mình không biết hạn.
	//
	// Thu hồi KHÔNG tăng attempt: job chưa được chạy xong lần nào, tính là một
	// lần thất bại sẽ đẩy job tới 'failed' chỉ vì worker bị kill.
	ReclaimExpired(ctx context.Context) (int, error)
	CompleteJob(ctx context.Context, id int64, result json.RawMessage) error
	// FailJob tăng attempt; đủ MaxJobAttempts → 'failed', chưa → về 'queued' với not_before=now+retryAfter.
	//
	// ĐỘ PHÂN GIẢI GIÂY: retryAfter được làm tròn LÊN giây — retryAfter dưới 1s
	// không tạo được độ trễ dưới giây (dùng 0 nếu muốn claim lại ngay).
	// Job không bao giờ chạy sớm hơn now+retryAfter, chỉ có thể muộn tối đa 1s.
	FailJob(ctx context.Context, id int64, errMsg string, retryAfter time.Duration) error

	// --- identity (T10) ---
	// CreateUser; username trùng (không phân biệt hoa thường) → ErrConflict.
	CreateUser(ctx context.Context, u *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	// GetUserByName tra KHÔNG phân biệt hoa thường.
	GetUserByName(ctx context.Context, username string) (*User, error)
	// CountUsers để biết this instance already has an owner chưa (luồng thiết lập lần đầu).
	CountUsers(ctx context.Context) (int, error)
	// OwnerUser trả chủ instance (user còn hiệu lực, có scope admin, cũ nhất);
	// chưa có ai → ErrNotFound. Phiên SSO của Console (CON-13) mở dưới tên tài
	// khoản này.
	OwnerUser(ctx context.Context) (*User, error)
	UpdateUser(ctx context.Context, u *User) error

	// CreateSession lưu HASH token; store không bao giờ thấy token trần.
	CreateSession(ctx context.Context, s *Session) error
	// GetSession chỉ trả phiên CÒN HẠN (lọc trong SQL).
	GetSession(ctx context.Context, tokenHash string) (*Session, error)
	// DeleteSession — logout, xoá THẬT khỏi bảng.
	DeleteSession(ctx context.Context, tokenHash string) error
	DeleteUserSessions(ctx context.Context, userID string) (int, error)
	PurgeExpiredSessions(ctx context.Context) (int, error)
	TouchSession(ctx context.Context, tokenHash string) error

	// --- API token (ID-04) ---
	// CreateAPIToken lưu HASH token; user không tồn tại → ErrNotFound.
	CreateAPIToken(ctx context.Context, t *APIToken) error
	// GetAPIToken trả token CÒN HẠN theo hash; hết hạn coi như không tồn tại
	// (lọc trong SQL, cùng lý do với GetSession).
	GetAPIToken(ctx context.Context, tokenHash string) (*APIToken, error)
	// ListAPITokens trả token của một user KỂ CẢ đã hết hạn, ORDER BY created_at
	// DESC — người vận hành phải thấy được token chết để dọn, và thấy được nó
	// đã chết chứ không phải nó biến mất.
	ListAPITokens(ctx context.Context, userID string) ([]*APIToken, error)
	// DeleteAPIToken thu hồi theo ID công khai. Xoá THẬT; không có → ErrNotFound.
	DeleteAPIToken(ctx context.Context, userID, id string) error
	// TouchAPIToken ghi mốc + IP dùng gần nhất. Lỗi ở đây KHÔNG được chặn
	// request — nó là dữ liệu chẩn đoán, không phải điều kiện xác thực.
	TouchAPIToken(ctx context.Context, tokenHash, ip string) error
	PurgeExpiredAPITokens(ctx context.Context) (int, error)

	// --- OIDC provider (ID-01) ---
	// PutOIDCClient upsert client theo client_id.
	PutOIDCClient(ctx context.Context, c *OIDCClient) error
	GetOIDCClient(ctx context.Context, clientID string) (*OIDCClient, error)
	// ListOIDCClients trả mọi client, ORDER BY client_id.
	ListOIDCClients(ctx context.Context) ([]*OIDCClient, error)
	// DeleteOIDCClient thu hồi quyền SSO; không có → ErrNotFound.
	DeleteOIDCClient(ctx context.Context, clientID string) error

	// CreateOIDCCode lưu HASH của mã; client không tồn tại → ErrNotFound.
	CreateOIDCCode(ctx context.Context, c *OIDCCode) error
	// ConsumeOIDCCode lấy VÀ XOÁ mã trong MỘT câu lệnh nguyên khối.
	//
	// Đây là khẳng định quan trọng nhất của cả bảng: dùng lại một mã phải là
	// điều KHÔNG THỂ, không phải điều được kiểm ở tầng trên. Đọc-rồi-xoá thành
	// hai bước để lại một cửa sổ, và một kẻ đọc trộm được mã chỉ cần chạy song
	// song với chính người dùng để lọt qua cửa sổ đó.
	//
	// Mã đã hết hạn coi như không tồn tại (lọc trong SQL), NHƯNG vẫn bị xoá —
	// nếu không thì bảng đầy rác mà không ai dọn.
	ConsumeOIDCCode(ctx context.Context, codeHash string) (*OIDCCode, error)
	PurgeExpiredOIDCCodes(ctx context.Context) (int, error)

	// RecordLoginFailure tăng bộ đếm và khoá khi chạm threshold (một câu UPSERT).
	RecordLoginFailure(ctx context.Context, key string, threshold int, lockFor time.Duration) (*LoginAttempts, error)
	GetLoginAttempts(ctx context.Context, key string) (*LoginAttempts, error)
	ClearLoginFailures(ctx context.Context, key string) error
	// ClearAllLoginFailures — chỉ dùng cho `keenrig-box reset-password`: người
	// quên mật khẩu thường đã tự khoá IP của mình bằng các lần thử sai.
	ClearAllLoginFailures(ctx context.Context) (int, error)

	// --- locks: khoá thao tác (xem package locks) ---
	// AcquireLock giành/gia hạn khoá; người khác đang giữ và CHƯA hết hạn → ErrConflict.
	AcquireLock(ctx context.Context, name, holder, reason string, ttl time.Duration) (*Lock, error)
	// ReleaseLock nhả; sai holder → ErrConflict, không có → ErrNotFound.
	ReleaseLock(ctx context.Context, name, holder string) error
	// ReleaseLocksByHolder nhả MỌI khoá của một chủ — dọn sau job quên nhả.
	ReleaseLocksByHolder(ctx context.Context, holder string) (int, error)
	// ListLocks trả khoá CÒN HẠN, ORDER BY name.
	ListLocks(ctx context.Context) ([]*Lock, error)
	PurgeExpiredLocks(ctx context.Context) (int, error)

	// GetJob / ListJobs — đường đọc cho API "job của tôi tới đâu rồi".
	GetJob(ctx context.Context, id int64) (*Job, error)
	ListJobs(ctx context.Context, kinds []string, limit int) ([]*Job, error)
	// SetJobProgress cập nhật tiến độ; chỉ job 'running' và ĐÚNG chủ lease.
	SetJobProgress(ctx context.Context, id int64, owner string, percent int, message string) error
	// PurgeFinishedJobs / PurgeEvents — dọn định kỳ để bảng không phình vô hạn.
	PurgeFinishedJobs(ctx context.Context, before time.Time) (int, error)
	PurgeEvents(ctx context.Context, before time.Time) (int, error)

	AppendEvent(ctx context.Context, action, actor, subject string, data json.RawMessage) error
	// ListEvents trả tối đa limit event mới nhất, ORDER BY id DESC.
	ListEvents(ctx context.Context, limit int) ([]*Event, error)
}
