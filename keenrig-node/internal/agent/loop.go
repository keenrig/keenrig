package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
)

// Vòng lặp poll — trái tim của agent, và là chỗ cam kết "cắt cloud không sao"
// được giữ hay bị phá.
//
// # AG-08 là một khẳng định về thứ KHÔNG xảy ra
//
// Cắt cloud bảy ngày thì mọi chức năng local phải nguyên vẹn: *không degrade,
// không log spam*. Nghĩa là vòng lặp này, khi cloud chết, phải:
//
//	KHÔNG chết          agent thoát là mất luôn đường quan sát instance đó, và
//	                    systemd dựng lại nó thành một vòng restart vô nghĩa.
//	KHÔNG đụng gì local box vẫn reconcile, app vẫn chạy. Agent không có quyền
//	                    nào trên chúng — nó chỉ đọc qua node API.
//	KHÔNG spam log      mỗi lần thất bại một dòng, ở nhịp backoff, là 7 ngày ×
//	                    288 dòng = vừa đủ để đọc. Log mỗi giây là 600k dòng và
//	                    nó lấp mất mọi thứ khác trên máy.
//
// Ba điều đó không phải "cố gắng" — chúng là cấu trúc của hàm Run bên dưới.

// NodeAPI — thứ agent đọc từ box. Interface chứ không phải client cụ thể: test
// không cần dựng cả một box để kiểm vòng lặp.
type NodeAPI interface {
	// AppStatuses trả nguyên văn phản hồi `/node/v1/apps`.
	//
	// NGUYÊN VĂN, không parse rồi dựng lại: `ND-01` nói *"agent không phải map
	// lại"*, và cách chắc chắn nhất để đúng câu đó là không đụng vào nó. Một
	// lần parse-rồi-dựng-lại là một chỗ để trường mới bị đánh rơi im lặng.
	AppStatuses(ctx context.Context) (json.RawMessage, error)
}

// Executor thực thi một lệnh từ cloud.
//
// Trả về lỗi = lệnh thất bại, và lý do đi thẳng lên Console (CON-14). Không có
// đường nào để "thất bại im lặng".
type Executor interface {
	Execute(ctx context.Context, cmd Command) error
}

// LicenseSink — nơi giao license mới kéo về từ cloud (box, qua node API).
type LicenseSink interface {
	InstallLicense(ctx context.Context, raw []byte) error
}

// DomainSink — nơi giao tên miền gốc cloud đã chọn cho môi trường (box, qua
// node API).
//
// Tên miền của một môi trường là QUYẾT ĐỊNH CỦA CLOUD (luật chủ dự án
// 2026-09-07); agent chỉ chuyển nó xuống, box chỉ hiển thị. Interface để test
// vòng lặp không phải dựng box.
type DomainSink interface {
	SetParentDomain(ctx context.Context, parent, mode string) error
}

// CloudLinkSink — nơi agent báo "tôi đã pair, và vừa sync được" (box, qua
// node API).
//
// Agent là tiến trình DUY NHẤT biết máy này đã pair: nó đọc KEENRIG_CLOUD_URL
// + KEENRIG_ENV_ID và là bên nói chuyện với cloud. Box serve Admin UI nhưng
// không có dòng nào của những thứ đó — nên tới 2026-09-19 màn Cloud Link viết
// cứng "chưa pair" trên một máy đang sync mỗi 30 giây. Interface để test vòng
// lặp không phải dựng box.
type CloudLinkSink interface {
	SetCloudLink(ctx context.Context, cloudURL, envID string, lastSync time.Time) error
}

// DefaultCloudLinkEvery — nhịp báo trạng thái pair cho box, SAU một sync thành
// công. Một phút = hai nhịp sync: đủ mịn để mốc "last sync" trên Admin UI
// không bao giờ cũ quá 90 giây khi mọi thứ ổn, đủ thưa để không ghi ba khoá
// settings mỗi 30 giây cho cùng một sự thật.
const DefaultCloudLinkEvery = time.Minute

// DefaultLicenseEvery — nhịp hỏi license. 12 giờ trên TTL 30 ngày + 14 ngày
// grace nghĩa là ~60 cơ hội gia hạn trước khi một license đang dùng hết hiệu
// lực — trượt vài lượt vì mạng không là gì cả, và cloud không bị mọi instance
// hỏi license mỗi nhịp sync.
const DefaultLicenseEvery = 12 * time.Hour

// Options cấu hình vòng lặp.
type Options struct {
	EnvID   string
	Version string
	Node    NodeAPI
	Exec    Executor
	// Metrics — nguồn `metrics_summary` (OB-05). nil hoặc trả nil → sync đi
	// KHÔNG kèm metrics: "không đo được" là trường vắng, không phải số 0.
	Metrics func() *contracts.MetricsSummary
	// Log nil → log.Printf. Test thay để đếm dòng.
	Log func(string, ...any)
	// Now để test tua thời gian.
	Now func() time.Time
	// Sleep để test chạy nhanh; nil → time.After thật.
	Sleep func(ctx context.Context, d time.Duration)
	// Policy nil → NewPolicy(nil).
	Policy *Policy
	// License — nơi giao license kéo từ cloud về (box). nil = agent này không
	// lo license; cloud không phát license (503) cũng là một trạng thái yên
	// lặng, không phải lỗi.
	License LicenseSink
	// LicenseEvery — nhịp hỏi license; 0 → DefaultLicenseEvery.
	LicenseEvery time.Duration
	// Domain — nơi giao `parent_domain` từ phản hồi sync (box). nil = agent
	// này không đưa tên miền xuống.
	Domain DomainSink
	// CloudLink — nơi báo trạng thái pair (box). nil = agent này không báo.
	CloudLink CloudLinkSink
	// CloudURL — gốc control plane đang poll, đi kèm báo cáo pair để Admin UI
	// vẽ link "Console". Rỗng → không báo (không có gì để chỉ tới).
	CloudURL string
	// CloudLinkEvery — nhịp báo; 0 → DefaultCloudLinkEvery.
	CloudLinkEvery time.Duration
}

// Loop — vòng poll.
type Loop struct {
	c     *Client
	opts  Options
	start time.Time
	// pending — kết quả lệnh CHƯA báo được lên cloud.
	//
	// Nó tồn tại vì lệnh được thực thi ngay sau khi nhận, còn kết quả chỉ báo
	// được ở lần sync SAU. Nếu lần sync sau thất bại thì kết quả phải ở lại đây
	// chứ không được bỏ — mất một kết quả là lệnh treo ở `delivered` mãi mãi
	// trên Console, và người dùng nhìn thấy "đang chạy" cho việc đã xong.
	pending []CommandResult
	// lastLicense — lần hỏi license gần nhất (kể cả lần trượt: xem
	// maybeRenewLicense vì sao không retry dồn).
	lastLicense time.Time
	// deliveredParent/deliveredMode — tên miền đã giao THÀNH CÔNG cho box lần
	// gần nhất. Cloud gửi nó ở mọi nhịp; đây là bộ nhớ để không gõ cửa box mỗi
	// 30 giây với cùng một giá trị. Giao hỏng thì không ghi, nên nhịp sau thử
	// lại.
	deliveredParent, deliveredMode string
	// lastDomainErr — lỗi giao tên miền gần nhất, để log GỘP như log sync: một
	// box từ chối cùng một câu ở mỗi nhịp chỉ đáng một dòng.
	lastDomainErr string
	// lastCloudLink — lần báo trạng thái pair THÀNH CÔNG gần nhất. Báo hỏng
	// thì không ghi, nên nhịp sync thành công kế thử lại ngay — box đang khởi
	// động lại là ca thường ngày, và Admin UI không nên đợi thêm một phút.
	lastCloudLink time.Time
	// lastCloudLinkErr — lỗi báo gần nhất, để log GỘP như lastDomainErr.
	lastCloudLinkErr string
}

func NewLoop(c *Client, opts Options) *Loop {
	if opts.Log == nil {
		opts.Log = log.Printf
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Sleep == nil {
		opts.Sleep = sleepCtx
	}
	if opts.Policy == nil {
		opts.Policy = NewPolicy(nil)
	}
	return &Loop{c: c, opts: opts, start: opts.Now()}
}

// Run chạy tới khi ctx bị huỷ. KHÔNG BAO GIỜ trả về vì lỗi cloud.
//
// Chữ "không bao giờ" ở trên là nghĩa đen: mọi lỗi đều biến thành một khoảng
// chờ. Lối ra duy nhất là ctx.Done(). Đó là hình dạng mà `AG-08` đòi hỏi, và
// một `return err` ở giữa hàm này sẽ phá nó mà không có gì đỏ ở tầng biên dịch.
func (l *Loop) Run(ctx context.Context) error {
	var lastErr string
	for {
		out := l.once(ctx)

		// Log GỘP: một chuỗi lỗi lặp lại chỉ in dòng đầu và dòng khi nó đổi.
		// Không có nó thì bảy ngày mất cloud là bảy ngày log cùng một câu.
		if out.Err != nil {
			if msg := out.Err.Error(); msg != lastErr {
				l.opts.Log("agent: sync failed (%d in a row), backing off: %v",
					l.opts.Policy.Fails(), out.Err)
				lastErr = msg
			}
		} else if lastErr != "" {
			// AG-09: nói ra lúc QUAY LẠI. Một sự cố kết thúc mà không có dòng
			// nào đánh dấu thì không ai biết nó kéo dài bao lâu.
			l.opts.Log("agent: reconnected to the control plane after %d failed attempts",
				l.opts.Policy.Fails())
			lastErr = ""
		}

		wait := l.opts.Policy.Next(out)
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		l.opts.Sleep(ctx, wait)
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

// once chạy đúng một vòng: gom trạng thái → sync → thực thi lệnh.
func (l *Loop) once(ctx context.Context) Outcome {
	req := SyncRequest{
		EnvID:   l.opts.EnvID,
		Version: l.opts.Version,
		Heartbeat: Heartbeat{
			TS:      l.opts.Now().UTC().Format(time.RFC3339),
			UptimeS: int(l.opts.Now().Sub(l.start).Seconds()),
		},
		CommandResults: l.pending,
	}

	// Không đọc được trạng thái app KHÔNG được chặn heartbeat.
	//
	// Box đang khởi động lại là ca thường ngày. Bỏ nguyên vòng sync vì thế
	// nghĩa là Console thấy env "mất kết nối" mỗi lần box restart — một cảnh
	// báo giả mà người vận hành sẽ học cách phớt lờ.
	if l.opts.Node != nil {
		if apps, err := l.opts.Node.AppStatuses(ctx); err == nil {
			req.AppStatuses = apps
		} else {
			l.opts.Log("agent: could not read app statuses from the box (%v) — "+
				"sending the heartbeat without them", err)
		}
	}

	// Số đo tài nguyên đi CÙNG chuyến với heartbeat — và cũng như app_statuses,
	// không có nó thì heartbeat vẫn đi. Marshal hỏng ở đây chỉ có thể là lỗi
	// lập trình (type contracts thuần dữ liệu), nhưng kể cả thế thì câu trả
	// lời đúng vẫn là "gửi thiếu một trường", không phải "bỏ nguyên vòng sync".
	if l.opts.Metrics != nil {
		if m := l.opts.Metrics(); m != nil {
			if raw, err := json.Marshal(m); err == nil {
				req.MetricsSummary = raw
			}
		}
	}

	res, out := l.c.Sync(ctx, req)
	if out.Err != nil || res == nil {
		return out
	}
	// Sync thành công → cloud đã nhận kết quả cũ, giờ mới được quên chúng.
	l.pending = nil

	for _, cmd := range res.Commands {
		l.pending = append(l.pending, l.run(ctx, cmd))
	}

	// Gia hạn license đi SAU một sync thành công: cloud vừa trả lời được thì
	// mới đáng hỏi tiếp, và lúc cloud chết vòng lặp này không sinh thêm một
	// dòng lỗi thứ hai cho cùng một sự cố.
	l.maybeRenewLicense(ctx)
	l.deliverParentDomain(ctx, res)
	l.reportCloudLink(ctx)
	return out
}

// reportCloudLink nói với box "tôi đã pair, và vừa sync được lúc này" — CHỈ
// sau một sync thành công, lần đầu ngay và rồi nhiều nhất một lần mỗi
// CloudLinkEvery.
//
// Chỉ sau thành công là phần quan trọng nhất: mốc gửi đi là bằng chứng cloud
// vừa trả lời, không phải "agent vừa thử". Nhờ đó box tính được `stale` khi
// mốc cũ quá 5 phút (instance.StaleAfter) mà không cần agent gửi thêm một cờ
// "tôi đang hỏng" — cờ mà một agent đã chết không bao giờ gửi được.
//
// Không bao giờ làm sync thất bại, không bao giờ chặn: box từ chối → một dòng
// log gộp, nhịp sau thử lại. Heartbeat đã lên và lệnh đã chạy; Admin UI thiếu
// một pill không phải lý do để Console thấy env "mất kết nối".
func (l *Loop) reportCloudLink(ctx context.Context) {
	if l.opts.CloudLink == nil || l.opts.CloudURL == "" {
		return
	}
	every := l.opts.CloudLinkEvery
	if every <= 0 {
		every = DefaultCloudLinkEvery
	}
	now := l.opts.Now()
	if !l.lastCloudLink.IsZero() && now.Sub(l.lastCloudLink) < every {
		return
	}
	if err := l.opts.CloudLink.SetCloudLink(ctx, l.opts.CloudURL, l.opts.EnvID, now); err != nil {
		if msg := err.Error(); msg != l.lastCloudLinkErr {
			l.opts.Log("agent: the box refused the cloud link state (will retry next sync): %v", err)
			l.lastCloudLinkErr = msg
		}
		return
	}
	if l.lastCloudLink.IsZero() {
		// Nói ra đúng một lần lúc Admin UI bắt đầu thấy sự thật; các lần sau là
		// cùng một sự thật được làm tươi, không đáng một dòng.
		l.opts.Log("agent: cloud link state delivered to the box (%s, environment %s)",
			l.opts.CloudURL, l.opts.EnvID)
	}
	l.lastCloudLink = now
	l.lastCloudLinkErr = ""
}

// deliverParentDomain đưa tên miền gốc từ phản hồi sync xuống box, khi nó ĐỔI.
//
// Không bao giờ làm sync thất bại: heartbeat đã lên, lệnh đã chạy — một box
// tạm không nhận tên miền không phải lý do để Console thấy env "mất kết nối".
// Giao hỏng thì giữ nguyên bộ nhớ "chưa giao" và nhịp sau thử lại; lỗi lặp lại
// chỉ log một dòng.
//
// Cloud KHÔNG gửi `parent_domain` → không làm gì, và nhất là KHÔNG xoá giá trị
// local của box. Vắng trường chỉ có nghĩa là cloud chưa chọn tên miền cho môi
// trường này (wizard chưa tới bước đó, hoặc env tạo qua API trần) — và một box
// standalone khai `--domain` rồi pair sau phải giữ được tên của nó cho tới khi
// cloud thật sự có gì để nói.
func (l *Loop) deliverParentDomain(ctx context.Context, res *SyncResponse) {
	if l.opts.Domain == nil || res.ParentDomain == "" {
		return
	}
	if res.ParentDomain == l.deliveredParent && res.DomainMode == l.deliveredMode {
		return
	}
	if err := l.opts.Domain.SetParentDomain(ctx, res.ParentDomain, res.DomainMode); err != nil {
		if msg := err.Error(); msg != l.lastDomainErr {
			l.opts.Log("agent: the box refused the parent domain %s (will retry next sync): %v",
				res.ParentDomain, err)
			l.lastDomainErr = msg
		}
		return
	}
	l.deliveredParent, l.deliveredMode = res.ParentDomain, res.DomainMode
	l.lastDomainErr = ""
	l.opts.Log("agent: parent domain %s (%s) delivered to the box", res.ParentDomain, res.DomainMode)
}

// maybeRenewLicense hỏi license mới theo nhịp LicenseEvery và giao cho box.
//
// Đánh dấu thời điểm TRƯỚC khi hỏi, kể cả khi hỏng: TTL 30 ngày trên nhịp 12
// giờ nghĩa là trượt một lượt rồi đợi lượt sau vẫn còn ~60 cơ hội — đổi lại
// không có đường nào retry dồn dập lên cloud, và log lỗi nhiều nhất một dòng
// mỗi nhịp thay vì mỗi lần sync.
func (l *Loop) maybeRenewLicense(ctx context.Context) {
	if l.opts.License == nil {
		return
	}
	every := l.opts.LicenseEvery
	if every <= 0 {
		every = DefaultLicenseEvery
	}
	now := l.opts.Now()
	if !l.lastLicense.IsZero() && now.Sub(l.lastLicense) < every {
		return
	}
	l.lastLicense = now

	raw, err := l.c.License(ctx)
	if errors.Is(err, ErrNoLicenseSigner) {
		// Cloud không phát license (self-hosted): giữ nguyên hiện trạng, im
		// lặng — đây là trạng thái thiết kế, không phải sự cố.
		return
	}
	if err != nil {
		l.opts.Log("agent: could not fetch the license (next try in %s): %v", every, err)
		return
	}
	if err := l.opts.License.InstallLicense(ctx, raw); err != nil {
		l.opts.Log("agent: the box refused the license: %v", err)
	}
}

// run thực thi một lệnh và dựng kết quả.
//
// Lệnh KHÔNG có executor được báo `failed` kèm lý do, không phải bỏ qua im
// lặng: một lệnh biến mất khỏi Console là một lệnh người dùng đợi mãi.
func (l *Loop) run(ctx context.Context, cmd Command) CommandResult {
	if l.opts.Exec == nil {
		return CommandResult{ID: cmd.ID, OK: false,
			Error: "this agent has no executor wired up for command kind " + cmd.Kind}
	}
	if err := l.opts.Exec.Execute(ctx, cmd); err != nil {
		l.opts.Log("agent: command %s (%s) failed: %v", cmd.ID, cmd.Kind, err)
		return CommandResult{ID: cmd.ID, OK: false, Error: err.Error()}
	}
	return CommandResult{ID: cmd.ID, OK: true}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
