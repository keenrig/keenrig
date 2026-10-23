// Package apps — tầng service của app: nơi DUY NHẤT giữ luật nghiệp vụ.
//
// # Vì sao validate nằm ở đây chứ không ở store hay reconciler
//
// store cố ý không validate (nó là persistence), reconciler cũng không (nó chỉ
// hội tụ thứ đã được chấp nhận). Hệ quả trước T7: một desired rỗng `{}` đi
// thẳng xuống Docker và nổ ở tầng driver, nơi thông báo lỗi không còn nói được
// gì cho người bấm nút. Chặn ở admission là chặn đúng chỗ người dùng còn sửa được.
//
// # Vì sao năng lực gateway cũng kiểm ở đây
//
// proxy.Check gọi lúc TẠO app, không phải lúc Apply (V2-DELTA §5.2 nguyên tắc
// 3). Người bật WAF trên một gateway không có WAF phải bị từ chối khi bấm tạo,
// chứ không phải deploy xong rồi tưởng mình đang được bảo vệ.
package apps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	"github.com/keenrig/keenrig/keenrig-node/internal/domains"
	"github.com/keenrig/keenrig/keenrig-node/internal/license"
	"github.com/keenrig/keenrig/keenrig-node/internal/proxy"
	"github.com/keenrig/keenrig/keenrig-node/internal/resources"
	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

var (
	// ErrInvalidSlug / ErrInvalidDesired → 400.
	ErrInvalidSlug    = errors.New("apps: invalid slug")
	ErrInvalidDesired = errors.New("apps: invalid desired state")
	// ErrQuota → 409: đã chạm trần số app của bậc đang dùng.
	ErrQuota = errors.New("apps: the app limit has been reached")
	// ErrLicense → 409: license hiện tại không cho THÊM app/domain nữa. Cùng
	// lớp với ErrQuota — xung đột với trạng thái hiện có, không phải request
	// sai — và cùng luật "chặn thao tác mới, không đụng thứ đang chạy".
	ErrLicense = errors.New("apps: the licensed limit has been reached")
	// ErrUnsupported → 400: gateway hiện tại không đỡ được thứ desired yêu cầu.
	ErrUnsupported = errors.New("apps: the gateway does not support this configuration")
)

const (
	MaxSlugLen = 40
	// DefaultMaxApps — trần mặc định khi Options.MaxApps không đặt. Có trần
	// ngay từ M1 vì bậc trả phí sẽ nới nó; thêm trần vào một hệ đã chạy không
	// trần thì mọi instance hiện có đều thành vi phạm.
	DefaultMaxApps = 50
)

// IDGenerator sinh app id. Tách ra để test cố định được id.
type IDGenerator func() string

type Options struct {
	MaxApps int
	NewID   IDGenerator
	// GatewayCaps — năng lực gateway đang chạy, dùng cho admission. nil nghĩa
	// là CHƯA biết (proxy chưa mở được): khi đó bỏ qua bước kiểm thay vì từ
	// chối mọi thứ — gateway hỏng không được biến thành "không tạo được app".
	GatewayCaps proxy.Caps
	// ResourceCaps — hạn mức phần cứng runtime đang chạy THỰC THI ĐƯỢC.
	//
	// nil nghĩa là chưa biết → bỏ qua kiểm, cùng lý lẽ với GatewayCaps. Sự lạc
	// quan đó an toàn vì nó không phải chỗ canh duy nhất: driver còn từ chối
	// TO TIẾNG lúc Apply (`resources.Enforce`). Hai tầng khác nhau ở chất lượng
	// thông báo, không ở việc có chặn hay không — admission cho một 400 chỉ
	// đúng vào trường sai, Apply cho một app ở trạng thái error.
	ResourceCaps resources.Caps
	// License — trạng thái license HIỆN TẠI, hỏi mỗi lần admission chứ không
	// giữ lại: license được agent thay trên đĩa trong lúc box chạy, và một bản
	// cache là một bản đã cũ. nil nghĩa là bản build này không gate theo
	// license (test, dev) — KHÔNG phải "không giới hạn cho khách": main.go
	// luôn cắm nó.
	License func() *license.State
}

type Service struct {
	st   store.Store
	dom  *domains.Service
	opts Options
}

func New(st store.Store, dom *domains.Service, opts Options) *Service {
	if opts.MaxApps <= 0 {
		opts.MaxApps = DefaultMaxApps
	}
	if opts.NewID == nil {
		opts.NewID = newUUIDv4
	}
	return &Service{st: st, dom: dom, opts: opts}
}

// CreateInput — thứ API nhận từ client.
type CreateInput struct {
	Slug    string
	Desired json.RawMessage
}

// Create — admission đầy đủ rồi mới ghi.
//
// Thứ tự có chủ đích: validate (rẻ, không đụng DB) → quota → tạo app → gắn
// domain. Domain gắn SAU khi app tồn tại vì app_domains có khoá ngoại; đổi lại,
// domain trùng làm request lỗi khi app đã được tạo. Ta dọn lại bằng cách xoá
// app vừa tạo — xem cleanupOnDomainFailure.
func (s *Service) Create(ctx context.Context, in CreateInput) (*store.App, error) {
	slug, err := NormalizeSlug(in.Slug)
	if err != nil {
		return nil, err
	}
	desired, err := s.validateDesired(in.Desired)
	if err != nil {
		return nil, err
	}
	if err := s.checkQuota(ctx); err != nil {
		return nil, err
	}
	if err := s.checkDomainLicense(ctx, len(desired.Domains)); err != nil {
		return nil, err
	}

	app := &store.App{ID: s.opts.NewID(), Slug: slug, Desired: in.Desired}
	if err := s.st.CreateApp(ctx, app); err != nil {
		return nil, err
	}
	if err := s.dom.Sync(ctx, app.ID, desired.Domains); err != nil {
		s.cleanupOnDomainFailure(ctx, app.ID)
		return nil, err
	}
	s.event(ctx, "app.created", app.ID, map[string]any{"slug": slug})
	return app, nil
}

// CreateFromDesired tạo app từ một DesiredApp đã dựng sẵn (UI-01, cài từ
// danh mục).
//
// Đi qua ĐÚNG đường Create, không phải một đường tắt: nếu không thì cài từ
// danh mục sẽ bỏ qua kiểm quota, kiểm năng lực gateway và admission — và ba
// thứ đó là ba chỗ duy nhất chặn được một app hỏng trước khi nó chạm runtime.
//
// Hàm này chỉ làm một việc: tuần tự hoá desired rồi gọi Create. Có nó để chỗ
// gọi không phải tự json.Marshal, vì một chỗ tự marshal là một chỗ có thể quên
// một trường.
func (s *Service) CreateFromDesired(ctx context.Context, slug string, d contracts.DesiredApp) (*store.App, error) {
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidDesired, err)
	}
	return s.Create(ctx, CreateInput{Slug: slug, Desired: raw})
}

// cleanupOnDomainFailure — app vừa tạo nhưng gắn domain hỏng thì app đó không
// bao giờ dùng được. Xoá nó đi (đi qua đúng đường xoá 2 pha) để người dùng
// không phải dọn tay một app "nửa vời", và để slug được trả lại.
func (s *Service) cleanupOnDomainFailure(ctx context.Context, appID string) {
	if err := s.st.DeleteApp(ctx, appID); err != nil && !errors.Is(err, store.ErrNotFound) {
		// Không nuốt: app rác còn lại là thứ người vận hành cần biết.
		s.event(ctx, "app.create_cleanup_failed", appID, map[string]any{"error": err.Error()})
	}
}

func (s *Service) Get(ctx context.Context, id string) (*store.App, error) {
	return s.st.GetApp(ctx, id)
}

func (s *Service) List(ctx context.Context) ([]*store.App, error) {
	return s.st.ListApps(ctx)
}

// UpdateDesired thay toàn bộ desired (PATCH gửi cả tập, không phải delta) và
// đồng bộ lại domain theo desired.domains.
func (s *Service) UpdateDesired(ctx context.Context, id string, raw json.RawMessage) (int64, error) {
	desired, err := s.validateDesired(raw)
	if err != nil {
		return 0, err
	}
	// Update thay CẢ TẬP domain nên có thể làm tổng domain tăng: gate license
	// trên phần tăng ròng. Giảm hay giữ nguyên thì qua — luật "chặn thao tác
	// mới, không đụng thứ đang có" áp cho cả update.
	if cur, err := s.st.ListDomains(ctx, id); err != nil {
		return 0, err
	} else if err := s.checkDomainLicense(ctx, len(desired.Domains)-len(cur)); err != nil {
		return 0, err
	}
	// Đồng bộ domain TRƯỚC khi bump rev: domain trùng làm request hỏng, mà rev
	// đã bump thì reconciler sẽ đi deploy một desired người dùng tưởng đã bị từ chối.
	if err := s.dom.Sync(ctx, id, desired.Domains); err != nil {
		return 0, err
	}
	rev, err := s.st.UpdateDesired(ctx, id, raw)
	if err != nil {
		return 0, err
	}
	s.event(ctx, "app.desired_updated", id, map[string]any{"rev": rev})
	return rev, nil
}

// Delete — pha 1 của xoá 2 pha. Trả về NGAY, container do reconciler dọn.
// Đó là lý do API trả 202 chứ không phải 204: lúc response về, app đã biến mất
// khỏi mọi truy vấn nhưng tài nguyên thì chưa.
func (s *Service) Delete(ctx context.Context, id string) error {
	if err := s.st.DeleteApp(ctx, id); err != nil {
		return err
	}
	s.event(ctx, "app.delete_requested", id, nil)
	return nil
}

func (s *Service) Domains(ctx context.Context, appID string) ([]*store.Domain, error) {
	if _, err := s.st.GetApp(ctx, appID); err != nil {
		return nil, err // app lạ → 404, không phải danh sách rỗng
	}
	return s.dom.List(ctx, appID)
}

// AddDomain gắn thêm domain ngoài đường desired (dùng cho màn Domains của Admin).
func (s *Service) AddDomain(ctx context.Context, appID, fqdn string, primary bool) (*store.Domain, error) {
	if err := s.checkGatewaySupports(fqdn); err != nil {
		return nil, err
	}
	if err := s.checkDomainLicense(ctx, 1); err != nil {
		return nil, err
	}
	return s.dom.Add(ctx, appID, fqdn, primary)
}

func (s *Service) RemoveDomain(ctx context.Context, fqdn string) error {
	return s.dom.Remove(ctx, fqdn)
}

// --- admission ---------------------------------------------------------------

// validateDesired kiểm theo JSON Schema rồi giải mã.
//
// Kiểm bằng SCHEMA chứ không phải bằng json.Unmarshal vào struct: Unmarshal bỏ
// qua trường lạ và nhận kiểu sai một cách im lặng, nên `{"image": 123}` hay
// `{"imagee": "x"}` đều lọt. Schema có additionalProperties:false nên bắt được
// cả lỗi gõ nhầm tên trường — thứ người dùng gặp nhiều nhất.
func (s *Service) validateDesired(raw json.RawMessage) (contracts.DesiredApp, error) {
	var d contracts.DesiredApp
	if len(raw) == 0 {
		return d, fmt.Errorf("%w: empty", ErrInvalidDesired)
	}
	if err := contracts.ValidateDesired(raw); err != nil {
		return d, fmt.Errorf("%w: %s", ErrInvalidDesired, err)
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return d, fmt.Errorf("%w: %s", ErrInvalidDesired, err)
	}
	// Chính sách kiểm TRƯỚC domain, và kiểm KHÔNG PHỤ THUỘC domain: xem godoc
	// checkGatewaySupportsPolicy.
	if err := s.checkGatewaySupportsPolicy(d.Policy); err != nil {
		return d, err
	}
	// Hạn mức: luật GIỮA các trường trước (rẻ, không cần biết năng lực), rồi
	// mới tới năng lực runtime. Thứ tự đó cho thông báo tốt hơn: một desired vừa
	// tự mâu thuẫn vừa đòi năng lực thiếu thì lỗi đáng nói trước là cái người
	// dùng sửa được mà không cần đổi runtime.
	if err := resources.Validate(d.Resources); err != nil {
		return d, fmt.Errorf("%w: %s", ErrInvalidDesired, err)
	}
	if err := s.checkRuntimeSupportsResources(d.Resources); err != nil {
		return d, err
	}
	for _, fqdn := range d.Domains {
		if err := s.checkGatewaySupports(fqdn); err != nil {
			return d, err
		}
	}
	return d, nil
}

// checkGatewaySupportsPolicy — admission cho `desired.policy` (PR-08).
//
// # Vì sao đây là một hàm riêng, không gộp vào vòng lặp domain
//
// Chính sách thuộc về APP, không thuộc về một tên miền. Gộp vào vòng lặp trên
// nghĩa là một app bật WAF mà CHƯA gắn domain sẽ được nhận — rồi ta lưu một ý
// định không bao giờ thực thi được, và người dùng chỉ phát hiện lúc thêm domain,
// nếu lúc đó có ai kiểm. Với WAF thì "được nhận" tự nó là thiệt hại: người vận
// hành tin site đang được bảo vệ.
//
// # Thông báo lỗi nói tên NĂNG LỰC, không nói FQDN
//
// `proxy.Unsupported.Error()` in ra FQDN, nhưng ở đây có thể không có FQDN nào để
// in. Một thông báo `proxy: "" cần năng lực "waf"` là thông báo tệ hơn không có.
func (s *Service) checkGatewaySupportsPolicy(p *contracts.Policy) error {
	if s.opts.GatewayCaps == nil {
		return nil // chưa biết năng lực — xem godoc Options.GatewayCaps
	}
	missing := proxy.MissingCaps(proxy.PolicyFrom(p), s.opts.GatewayCaps)
	if len(missing) == 0 {
		return nil
	}
	names := make([]string, 0, len(missing))
	for _, c := range missing {
		names = append(names, string(c))
	}
	return fmt.Errorf("%w: the running gateway lacks capability %s — "+
		"switch gateway or remove the corresponding policy from desired.policy",
		ErrUnsupported, strings.Join(names, ", "))
}

// checkRuntimeSupportsResources — admission cho `desired.resources`.
//
// # Vì sao phải chặn ở đây thay vì để runtime tự bỏ qua
//
// Vì runtime KHÔNG bỏ qua một cách nhìn thấy được. Đo trên Docker 29.4.3 với
// snapshotter overlayfs: `--storage-opt size=64m` được nhận, không trả lỗi, và
// container ghi 128 MB vào "hạn 64 MB" bình thường. Nếu admission cho qua thì
// người vận hành có một app khai `disk_mb: 64` trong desired, một API trả 201,
// và không có gì trên hệ thống nói rằng hạn đó không tồn tại.
//
// # Vì sao thông báo nói TÊN NĂNG LỰC và tên runtime
//
// Người dùng sửa được hai thứ: bỏ trường đó, hoặc đổi runtime. Một lỗi
// "cấu hình tài nguyên không được hỗ trợ" không nói được nên bỏ trường nào trong
// mười một trường, cũng không nói đổi sang đâu thì được.
func (s *Service) checkRuntimeSupportsResources(r *contracts.Resources) error {
	missing := resources.MissingCaps(r, s.opts.ResourceCaps)
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("%w: the running runtime cannot enforce %s — "+
		"remove the corresponding field from desired.resources, or switch to a runtime that enforces it",
		ErrUnsupported, strings.Join(resources.Names(missing), ", "))
}

// checkGatewaySupports — admission cho MỘT tên miền: gateway lo được chứng chỉ
// cho nó bằng đường nào.
//
// # Đường TLS phải SUY RA từ năng lực, không được đặt cứng
//
// Bản đầu đặt cứng `TLSACMEByGateway`, nên `Site.Requires()` đòi `CapACME` và MỌI
// app có domain đều bị từ chối trên nginx — trong khi reconciler xử lý nginx bình
// thường bằng đường `TLSProvided` (platform xin cert rồi cấp xuống). Admission
// nghiêm hơn thực tế là loại lỗi khó thấy: không có gì hỏng, chỉ là không tạo
// được app, và thông báo nói về "năng lực acme" — thứ người dùng không hề yêu cầu.
//
// `proxy.TLSModeFor` giữ luật đó ở MỘT chỗ, dùng chung với
// `reconciler.gatewayHasACME`.
func (s *Service) checkGatewaySupports(fqdn string) error {
	if s.opts.GatewayCaps == nil {
		return nil // chưa biết năng lực — xem godoc Options.GatewayCaps
	}
	norm, err := domains.Normalize(fqdn)
	if err != nil {
		return err
	}
	site := proxy.Site{FQDN: norm, TLS: proxy.TLS{Mode: proxy.TLSModeFor(s.opts.GatewayCaps)}}
	bad := proxy.Check([]proxy.Site{site}, s.opts.GatewayCaps)
	if len(bad) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(bad))
	for _, u := range bad {
		msgs = append(msgs, u.Error())
	}
	return fmt.Errorf("%w: %s", ErrUnsupported, strings.Join(msgs, "; "))
}

func (s *Service) checkQuota(ctx context.Context) error {
	apps, err := s.st.ListApps(ctx)
	if err != nil {
		return err
	}
	if len(apps) >= s.opts.MaxApps {
		return fmt.Errorf("%w: %d/%d", ErrQuota, len(apps), s.opts.MaxApps)
	}
	if s.opts.License != nil {
		if err := s.opts.License().CanAddApp(len(apps)); err != nil {
			return fmt.Errorf("%w: %v", ErrLicense, err)
		}
	}
	return nil
}

// checkDomainLicense — license có cho thêm `adding` domain nữa không, tính trên
// tổng domain của MỌI app (trần của bậc là trần của máy, không phải của app).
func (s *Service) checkDomainLicense(ctx context.Context, adding int) error {
	if s.opts.License == nil || adding <= 0 {
		return nil
	}
	existing, err := s.st.ListAllDomains(ctx)
	if err != nil {
		return err
	}
	// CanAddDomain hỏi "thêm MỘT khi đang có current" — thêm N domain một lượt
	// tương đương thêm một khi đang có current+N-1.
	if err := s.opts.License().CanAddDomain(len(existing) + adding - 1); err != nil {
		return fmt.Errorf("%w: %v", ErrLicense, err)
	}
	return nil
}

// NormalizeSlug — chữ thường, [a-z0-9-], không bắt đầu/kết thúc bằng '-'.
//
// Slug đi vào TÊN CONTAINER (su-<slug>-…) nên nó phải là thứ Docker nhận, và
// phải chặn được ký tự đường dẫn: cùng lý do paths.AppData từ chối "..".
func NormalizeSlug(slug string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(slug))
	if s == "" {
		return "", fmt.Errorf("%w: empty", ErrInvalidSlug)
	}
	if len(s) > MaxSlugLen {
		return "", fmt.Errorf("%w: %d characters long, the maximum is %d", ErrInvalidSlug, len(s), MaxSlugLen)
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return "", fmt.Errorf("%w: %q starts or ends with a hyphen", ErrInvalidSlug, s)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return "", fmt.Errorf("%w: %q contains the invalid character %q", ErrInvalidSlug, s, string(c))
		}
	}
	return s, nil
}

func (s *Service) event(ctx context.Context, action, subject string, data map[string]any) {
	var raw json.RawMessage
	if data != nil {
		raw, _ = json.Marshal(data)
	}
	// Lỗi ghi audit không được làm hỏng thao tác đã thành công; nó nổi lên qua
	// log của store nếu có.
	_ = s.st.AppendEvent(ctx, action, "api", subject, raw)
}
