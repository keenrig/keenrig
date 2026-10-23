// Package catalog — danh mục app cài được bằng một cú bấm (UI-01).
//
// # Manifest là ĐẦU VÀO KHÔNG TIN CẬY
//
// Cùng lập luận với internal/importer: manifest đến từ một catalog ngoài, có
// thể là catalog cộng đồng, có thể là catalog riêng của người dùng. Nó KHÔNG
// phải cấu hình do ta viết.
//
// Nhưng cách phòng thủ ở đây khác importer, và khác một cách quan trọng:
// compose là một ngôn ngữ ĐỦ MẠNH để diễn đạt `privileged: true`, bind mount
// và `cap_add`, nên importer phải liệt kê và từ chối từng cấu trúc nguy hiểm —
// một danh sách đen, và danh sách đen nào cũng có lỗ.
//
// Manifest ở đây là định dạng của CHÍNH TA, và nó cố tình KHÔNG CÓ cách nào
// diễn đạt những thứ đó. Không có trường `privileged`, không có `volumes`,
// không có `cap_add`, không có `network_mode`. Thêm một trường mới là một
// quyết định có ý thức, không phải một thứ lọt qua vì ta quên chặn.
//
// Đó là lý do struct dưới đây dùng DisallowUnknownFields: một trường lạ trong
// manifest phải là LỖI, không phải thứ bị bỏ qua im lặng. Bỏ qua im lặng nghĩa
// là một catalog độc hại thêm `"privileged": true` và không ai thấy gì cả —
// kể cả khi hôm nay ta không đọc trường đó, ngày mai ai đó có thể đọc.
//
// # Vì sao KHÔNG ghim image theo digest ở đây
//
// contracts.ValidateDesired bắt buộc image phải có `@sha256:` (xem
// tester_adversarial_test.go). Manifest catalog thì khai tag người đọc được
// (`nginx:1.27-alpine`) VÀ digest. Tag để hiển thị, digest để chạy — chuyển
// đổi xảy ra ở ToDesired. Nếu chỉ có tag thì "cài lại app này" tháng sau sẽ
// cho ra một image khác mà không ai biết.
package catalog

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
)

var (
	// ErrInvalidManifest — manifest sai cú pháp hoặc vi phạm chính sách.
	ErrInvalidManifest = errors.New("catalog: invalid manifest")
	// ErrNotFound — không có app nào mang id này trong danh mục.
	ErrNotFound = errors.New("catalog: no such app in the catalog")
)

const (
	// MaxManifestBytes — trần cho MỘT manifest. Catalog là nguồn ngoài; không
	// có trần thì một file 2GB làm cạn RAM của box.
	MaxManifestBytes = 64 << 10
	// MaxEnvVars / MaxEnvValueLen — trần cho biến môi trường.
	MaxEnvVars     = 50
	MaxEnvValueLen = 4096
	maxTitleLen    = 100
	maxDescLen     = 2000
)

// idRe — id app trong danh mục. Chữ thường, số, gạch ngang; bắt đầu bằng chữ.
//
// Hẹp có chủ đích: id này đi vào tên container, tên data directory và đường
// dẫn URL. Một id chứa `/` hoặc `..` là một lỗ path traversal ở ba chỗ cùng lúc.
var idRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}[a-z0-9]$`)

// volumeNameRe — khớp desired.schema.json #/$defs/VolumeMount/name.
var volumeNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$`)

// envNameRe — tên biến môi trường kiểu POSIX.
var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

const maxVolumes = 8

// digestRe — chỉ nhận sha256 hex đủ 64 ký tự.
var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// repoRe — phần repository của image ref (không gồm tag/digest).
//
// Cho phép host, cổng, và nhiều đoạn path. KHÔNG cho khoảng trắng, dấu nháy
// hay ký tự shell — image ref đi vào lời gọi API của runtime, và một ref chứa
// ký tự lạ là thứ ta không muốn phải suy nghĩ về sau này.
var repoRe = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)

// Manifest — mô tả một app cài được.
type Manifest struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// TitleVI — tên hiển thị tiếng Việt khi khác bản chuẩn (vd "Caddy (trang
	// tĩnh)" so với "Caddy (static)"). Thường bỏ trống: tên sản phẩm không dịch.
	TitleVI     string `json:"title_vi,omitempty"`
	Description string `json:"description,omitempty"`
	// DescriptionVI — bản tiếng Việt của Description. `description` là bản
	// chuẩn bằng tiếng Anh (mặc định của sản phẩm); UI chọn theo ngôn ngữ người
	// dùng và rơi về `description` khi thiếu. Trước 2026-10-07 mỗi manifest chỉ
	// có MỘT ngôn ngữ tuỳ người viết, nên Admin tiếng Anh hiện mô tả tiếng Việt
	// và ngược lại.
	DescriptionVI string `json:"description_vi,omitempty"`
	// Version là phiên bản của APP (hiển thị), không phải của manifest.
	Version string `json:"version"`
	// Repository + Digest tách rời có chủ đích, xem godoc package.
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Digest     string `json:"digest"`
	// HTTPPort — cổng app nghe BÊN TRONG container.
	HTTPPort int `json:"http_port"`
	// Env — biến mặc định. Người dùng ghi đè được lúc cài.
	Env map[string]string `json:"env,omitempty"`
	// OriginEnv — tên biến môi trường nhận URL công khai của app
	// ("https://<domain đầu tiên>") lúc cài.
	//
	// Có vì nhiều app (Activepieces, n8n…) phải biết chính URL của mình để dựng
	// link webhook và link trong email, mà URL đó chỉ có lúc người dùng chọn
	// domain — manifest viết trước không biết được. Không có trường này thì mỗi
	// người cài phải tự gõ lại đúng domain vừa chọn vào một ô env, và gõ lệch
	// một ký tự là webhook chết im lặng.
	//
	// Chỉ là TÊN biến, không phải mẫu chuỗi: một ngôn ngữ template trong manifest
	// là thứ phải nghĩ về injection, một tên biến thì không.
	OriginEnv string `json:"origin_env,omitempty"`
	// SecretEnv — tên các biến nhận một bí mật NGẪU NHIÊN RIÊNG cho mỗi lần cài
	// (32 byte, hex) — trừ khi người dùng tự đưa giá trị.
	//
	// Có vì một bí mật viết thẳng vào `env` của manifest là CÙNG MỘT bí mật cho
	// mọi bản cài trên đời: ai đọc danh mục công khai là ký được JWT cho mọi
	// Activepieces cài từ nó. Sinh lúc cài rồi nằm trong desired (store) nên ổn
	// định qua các lần deploy lại — sinh lại mỗi lần deploy sẽ đăng xuất mọi
	// người và làm hỏng mọi thứ đã ký bằng khoá cũ.
	SecretEnv []string `json:"secret_env,omitempty"`
	// Volumes — thư mục bền, chuyển thẳng sang DesiredApp.Volumes.
	//
	// KHÔNG phải bind mount: phía máy chủ neo theo Name dưới apps/<id>/volumes/,
	// manifest không chọn được đường dẫn máy chủ nào. Thiếu trường này thì mọi
	// app có dữ liệu (database nhúng, file tải lên) mất sạch ở lần cập nhật đầu.
	Volumes []contracts.VolumeMount `json:"volumes,omitempty"`
	// MinMemoryMB — hạn dưới; dùng làm giá trị mặc định cho Resources.
	MinMemoryMB int `json:"min_memory_mb,omitempty"`
	// HealthcheckPath — đường dẫn probe. Rỗng → "/".
	HealthcheckPath string `json:"healthcheck_path,omitempty"`
	// Tags để lọc trong UI.
	Tags []string `json:"tags,omitempty"`
	// Icon — tên file dưới keenrig-catalog/icons/. Chỉ tên file, KHÔNG đường dẫn.
	Icon string `json:"icon,omitempty"`
	// Website/Source để người dùng biết mình đang cài gì của ai.
	Website string `json:"website,omitempty"`
	Source  string `json:"source,omitempty"`
}

// Parse đọc MỘT manifest và kiểm chính sách.
//
// DisallowUnknownFields: trường lạ là LỖI. Xem godoc package — bỏ qua im lặng
// là cách một trường nguy hiểm lọt vào mà không ai thấy.
func Parse(r io.Reader) (*Manifest, error) {
	dec := json.NewDecoder(io.LimitReader(r, MaxManifestBytes+1))
	dec.DisallowUnknownFields()

	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	// Còn dữ liệu sau object đầu tiên = hai document nối nhau, hoặc rác ở đuôi.
	// Chấp nhận nó nghĩa là hai người đọc khác nhau có thể thấy hai nội dung
	// khác nhau từ cùng một file.
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after the manifest", ErrInvalidManifest)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	if !idRe.MatchString(m.ID) {
		return fmt.Errorf("%w: id %q — must be lowercase letters/digits/hyphens, 3–40 characters, "+
			"starting with a letter (the id ends up in container names and URL paths)", ErrInvalidManifest, m.ID)
	}
	if t := strings.TrimSpace(m.Title); t == "" || len(t) > maxTitleLen {
		return fmt.Errorf("%w: title is empty or longer than %d characters", ErrInvalidManifest, maxTitleLen)
	}
	if len(m.Description) > maxDescLen {
		return fmt.Errorf("%w: description is longer than %d characters", ErrInvalidManifest, maxDescLen)
	}
	if len(m.TitleVI) > maxTitleLen {
		return fmt.Errorf("%w: title_vi is longer than %d characters", ErrInvalidManifest, maxTitleLen)
	}
	if len(m.DescriptionVI) > maxDescLen {
		return fmt.Errorf("%w: description_vi is longer than %d characters", ErrInvalidManifest, maxDescLen)
	}
	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("%w: version is missing", ErrInvalidManifest)
	}
	if !repoRe.MatchString(m.Repository) {
		return fmt.Errorf("%w: repository %q contains a disallowed character", ErrInvalidManifest, m.Repository)
	}
	if !digestRe.MatchString(m.Digest) {
		return fmt.Errorf("%w: digest %q — must be sha256:<64 hex>. "+
			"Without a digest, 'reinstall this app' next month yields a different image",
			ErrInvalidManifest, m.Digest)
	}
	if m.HTTPPort < 1 || m.HTTPPort > 65535 {
		return fmt.Errorf("%w: http_port %d is outside 1–65535", ErrInvalidManifest, m.HTTPPort)
	}
	if err := m.validateEnv(); err != nil {
		return err
	}
	if m.OriginEnv != "" && !envNameRe.MatchString(m.OriginEnv) {
		return fmt.Errorf("%w: origin_env %q is not a valid environment variable name", ErrInvalidManifest, m.OriginEnv)
	}
	if err := m.validateVolumes(); err != nil {
		return err
	}
	if err := m.validateSecretEnv(); err != nil {
		return err
	}
	if strings.ContainsAny(m.Icon, `/\`) || strings.Contains(m.Icon, "..") {
		// Icon đi vào một đường dẫn file. Cho phép "/" hay ".." ở đây là mở
		// đường đọc file tuỳ ý trên máy chủ.
		return fmt.Errorf("%w: icon %q must be a FILE NAME, not a path",
			ErrInvalidManifest, m.Icon)
	}
	for _, u := range []string{m.Website, m.Source} {
		if u != "" && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
			// Chặn javascript: và data: — hai thứ này biến một liên kết trong
			// Admin UI thành một đường thực thi mã trong phiên của quản trị viên.
			return fmt.Errorf("%w: url %q must start with http:// or https://",
				ErrInvalidManifest, u)
		}
	}
	return nil
}

// validateVolumes — Name là RANH GIỚI AN NINH (nó thành một đoạn đường dẫn thật
// trên máy chủ), nên kiểm ngay lúc nạp danh mục chứ không đợi tới lúc cài: một
// manifest có `../../instance` phải biến mất khỏi danh mục, không phải nằm đó
// mời người ta bấm rồi mới bị từ chối.
func (m *Manifest) validateVolumes() error {
	if len(m.Volumes) > maxVolumes {
		return fmt.Errorf("%w: %d volumes, the maximum is %d", ErrInvalidManifest, len(m.Volumes), maxVolumes)
	}
	for _, v := range m.Volumes {
		if !volumeNameRe.MatchString(v.Name) {
			return fmt.Errorf("%w: volume name %q — must be lowercase letters/digits/hyphens, 2–32 characters",
				ErrInvalidManifest, v.Name)
		}
	}
	if err := contracts.ValidateVolumes(m.Volumes); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	return nil
}

func (m *Manifest) validateSecretEnv() error {
	if len(m.SecretEnv) > MaxEnvVars {
		return fmt.Errorf("%w: %d secret_env entries, the maximum is %d", ErrInvalidManifest, len(m.SecretEnv), MaxEnvVars)
	}
	for _, k := range m.SecretEnv {
		if !envNameRe.MatchString(k) {
			return fmt.Errorf("%w: secret_env %q is not a valid environment variable name", ErrInvalidManifest, k)
		}
		if _, clash := m.Env[k]; clash {
			// Hai nguồn cho một biến: người đọc manifest sẽ tưởng giá trị
			// trong env là thứ chạy, trong khi thứ chạy là bí mật ngẫu nhiên.
			return fmt.Errorf("%w: %s is in both env and secret_env", ErrInvalidManifest, k)
		}
	}
	return nil
}

func (m *Manifest) validateEnv() error {
	if len(m.Env) > MaxEnvVars {
		return fmt.Errorf("%w: %d environment variables, the maximum is %d", ErrInvalidManifest, len(m.Env), MaxEnvVars)
	}
	for k, v := range m.Env {
		if k == "" || strings.ContainsAny(k, "= \t\n\r\x00") {
			return fmt.Errorf("%w: invalid environment variable name %q", ErrInvalidManifest, k)
		}
		if len(v) > MaxEnvValueLen {
			return fmt.Errorf("%w: the value of %s is longer than %d bytes", ErrInvalidManifest, k, MaxEnvValueLen)
		}
		if strings.ContainsRune(v, 0) {
			// NUL trong biến môi trường bị cắt cụt ở tầng syscall — giá trị
			// người dùng thấy và giá trị app nhận sẽ khác nhau.
			return fmt.Errorf("%w: the value of %s contains a NUL byte", ErrInvalidManifest, k)
		}
	}
	return nil
}

// ImageRef trả tham chiếu image DÙNG ĐỂ CHẠY: repository@digest.
//
// KHÔNG kèm tag: `repo:tag@digest` là hợp lệ với Docker nhưng tag trong đó chỉ
// là trang trí — digest mới quyết định. Giữ tag lại chỉ tạo ảo giác rằng đổi
// tag sẽ đổi thứ đang chạy.
func (m *Manifest) ImageRef() string { return m.Repository + "@" + m.Digest }

// DisplayRef — thứ hiện cho người đọc: repository:tag.
func (m *Manifest) DisplayRef() string {
	if m.Tag == "" {
		return m.Repository
	}
	return m.Repository + ":" + m.Tag
}

// InstallOptions — lựa chọn của người dùng lúc bấm cài.
type InstallOptions struct {
	// Domains — FQDN gắn cho app. Rỗng cũng cài được: app chạy, chỉ chưa có
	// đường vào từ ngoài. Bắt buộc domain ở đây sẽ chặn đúng người dùng chưa
	// có tên miền — tức là người vừa cài xong máy.
	Domains []string
	// Env — ghi đè/bổ sung lên Env của manifest.
	Env map[string]string
	// MemoryMB — 0 nghĩa là dùng MinMemoryMB của manifest.
	MemoryMB int
}

// ToDesired dịch manifest + lựa chọn người dùng thành desired spec.
//
// Đây là chỗ DUY NHẤT manifest biến thành thứ chạy được, nên nó cũng là chỗ
// duy nhất phải nhớ ghim digest.
func (m *Manifest) ToDesired(opt InstallOptions) (contracts.DesiredApp, error) {
	d := contracts.DesiredApp{
		Image:    m.ImageRef(),
		HTTPPort: m.HTTPPort,
		Domains:  opt.Domains,
	}

	if len(m.Volumes) > 0 {
		// Chép, không dùng chung slice: desired đi vào store và có thể bị sửa;
		// manifest thì dùng chung cho mọi lần cài.
		d.Volumes = append([]contracts.VolumeMount(nil), m.Volumes...)
	}

	env, err := m.buildEnv(opt)
	if err != nil {
		return d, err
	}
	d.Env = env
	// Kiểm lại env SAU khi trộn: phần ghi đè của người dùng chưa đi qua
	// validate của manifest.
	merged := &Manifest{Env: d.Env}
	if err := merged.validateEnv(); err != nil {
		return d, err
	}

	mem := opt.MemoryMB
	if mem == 0 {
		mem = m.MinMemoryMB
	}
	if mem > 0 {
		d.Resources = &contracts.Resources{MemoryMB: mem}
	}
	return d, nil
}

// buildEnv trộn bốn nguồn env theo thứ tự: env của manifest, bí mật sinh lúc
// cài, URL gốc, rồi ghi đè của người dùng CUỐI — người dùng luôn thắng. Ngược
// lại thì một manifest đặt được biến mà người dùng không gỡ nổi, kể cả khi họ
// đứng sau một proxy khác và URL thật khác URL ta đoán.
func (m *Manifest) buildEnv(opt InstallOptions) (map[string]string, error) {
	origin := m.OriginEnv != "" && len(opt.Domains) > 0
	if len(m.Env) == 0 && len(opt.Env) == 0 && len(m.SecretEnv) == 0 && !origin {
		return nil, nil
	}
	env := make(map[string]string, len(m.Env)+len(opt.Env)+len(m.SecretEnv)+1)
	for k, v := range m.Env {
		env[k] = v
	}
	for _, k := range m.SecretEnv {
		if _, given := opt.Env[k]; given {
			continue // người dùng thắng — vd. khôi phục bản cài cũ với khoá cũ
		}
		s, err := randomSecret()
		if err != nil {
			// KHÔNG lùi về một giá trị cố định: thà không cài được còn hơn
			// cài với một bí mật đoán được.
			return nil, fmt.Errorf("catalog: generating %s: %w", k, err)
		}
		env[k] = s
	}
	if origin {
		// https là đoán mặc định (gateway xin chứng chỉ ACME cho domain của
		// app); ai chạy http thuần thì ghi đè biến này lúc cài.
		env[m.OriginEnv] = "https://" + opt.Domains[0]
	}
	for k, v := range opt.Env {
		env[k] = v
	}
	return env, nil
}

// randomSecret — 32 byte từ crypto/rand, mã hex (64 ký tự): an toàn trong env,
// trong URL và trong mọi trình phân tích .env.
func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// --- danh mục -------------------------------------------------------------------

// Catalog — tập manifest đã xác minh, tra theo id.
type Catalog struct {
	byID map[string]*Manifest
}

func New() *Catalog { return &Catalog{byID: map[string]*Manifest{}} }

// Add nạp một manifest. id trùng → lỗi: hai app cùng id nghĩa là một trong hai
// sẽ im lặng biến mất, và không có cách nào đoán được cái nào.
func (c *Catalog) Add(m *Manifest) error {
	if _, dup := c.byID[m.ID]; dup {
		return fmt.Errorf("%w: id %q appears twice", ErrInvalidManifest, m.ID)
	}
	c.byID[m.ID] = m
	return nil
}

func (c *Catalog) Get(id string) (*Manifest, error) {
	m, ok := c.byID[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	return m, nil
}

// List trả danh mục đã sắp theo title — thứ tự ỔN ĐỊNH giữa các lần gọi.
// Map iteration order của Go là ngẫu nhiên, và một danh sách nhảy loạn mỗi lần
// tải lại trang là lỗi UI mà không ai truy được về nguyên nhân.
func (c *Catalog) List() []*Manifest {
	out := make([]*Manifest, 0, len(c.byID))
	for _, m := range c.byID {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Title != out[j].Title {
			return out[i].Title < out[j].Title
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (c *Catalog) Len() int { return len(c.byID) }
