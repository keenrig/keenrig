package instance

// cloudlink.go — trạng thái pair với control plane, NHƯ AGENT BÁO VỀ.
//
// # Vì sao box không tự biết mình đã pair
//
// Pairing thuộc keenrig-agent: nó đọc KEENRIG_CLOUD_URL + KEENRIG_ENV_ID từ
// /etc/keenrig/agent.env và là tiến trình duy nhất nói chuyện với cloud. Box
// serve Admin UI nhưng không có dòng nào của những thứ đó — nên cho tới
// 2026-09-19 màn Cloud Link viết cứng "chưa pair" trên một máy đang sync mỗi
// 30 giây. Cách sửa KHÔNG phải cho box đọc file của agent (Luật 5/6: mỗi tiến
// trình một mặt phẳng ghi) mà là cho agent BÁO qua node API, cùng đường với
// parent_domain — và box chỉ ghi lại.
//
// # Vì sao có `stale`
//
// AG-08 nói cắt cloud bảy ngày thì app vẫn chạy — nhưng "vẫn chạy" không có
// nghĩa là "giấu". Agent chỉ báo SAU một sync thành công, nên mốc gần nhất cũ
// hơn StaleAfter chính là bằng chứng agent không chạm được cloud (hoặc agent
// chết). Pill xanh cũ trên một máy đã mất cloud năm ngày là một lời nói dối,
// và người vận hành cần thấy nó ở đúng màn họ sẽ mở khi Console kêu "mất kết
// nối".

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Khoá trong bảng `settings`. Cả ba vắng = chưa từng pair (hoặc agent chưa báo).
const (
	SettingCloudLinkURL        = "cloud_link_url"
	SettingCloudLinkEnvID      = "cloud_link_env_id"
	SettingCloudLinkLastSyncAt = "cloud_link_last_sync_at"
)

// StaleAfter — quá khoảng này kể từ lần sync thành công gần nhất thì trạng
// thái là `stale`. 5 phút = 10 nhịp sync mặc định (30 s) và bằng trần backoff
// của agent (MaxBackoff): một agent khoẻ đang backoff vẫn quay lại trong cửa
// sổ này, còn quá nó là mất cloud thật. AG-08: mất cloud phải được nói ra ở
// Admin UI, không phải giấu — app vẫn chạy là chuyện khác với "mọi thứ ổn".
const StaleAfter = 5 * time.Minute

// Trạng thái pair mà Admin UI vẽ. Khớp enum `state` của CloudLink trong
// instance.yaml.
const (
	StateStandalone = "standalone"
	StateSynced     = "synced"
	StateStale      = "stale"
)

// ErrInvalidCloudLink — báo cáo pair không dùng được: URL không http(s)/không
// host, env_id rỗng, hoặc mốc thời gian zero. Chỗ gọi map về 400 bằng một
// errors.Is; lý do cụ thể nằm sau dấu hai chấm để agent log nguyên văn.
var ErrInvalidCloudLink = errors.New("instance: invalid cloud link")

// CloudLinkInfo — thứ GET /api/v1/cloud trả về.
type CloudLinkInfo struct {
	// Paired = có URL được ghi. false ⇔ State == StateStandalone.
	Paired bool
	// CloudURL — gốc control plane agent poll. Rỗng khi chưa pair.
	CloudURL string
	// EnvID — định danh môi trường trên cloud. Rỗng khi chưa pair.
	EnvID string
	// LastSyncAt — lần sync THÀNH CÔNG gần nhất agent báo; zero khi chưa pair.
	LastSyncAt time.Time
	// State — StateStandalone | StateSynced | StateStale.
	State string
}

// SetCloudLink ghi báo cáo pair của agent. Khớp nodeapi.CloudLinkSink.
//
// Kiểm ở box dù agent đã đọc giá trị từ env của chính nó: đây là thứ Admin UI
// sẽ vẽ thành một link bấm được ("Console URL"), và một chuỗi không phải URL
// lọt vào đây thành một link hỏng không ai lần ra. Idempotent theo giá trị.
func (c *Config) SetCloudLink(ctx context.Context, cloudURL, envID string, lastSync time.Time) error {
	cloudURL = strings.TrimSpace(cloudURL)
	u, err := url.Parse(cloudURL)
	if err != nil {
		return fmt.Errorf("%w: cloud_url %q does not parse: %v", ErrInvalidCloudLink, cloudURL, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%w: cloud_url %q must be an http(s) URL with a host", ErrInvalidCloudLink, cloudURL)
	}
	if strings.TrimSpace(envID) == "" {
		return fmt.Errorf("%w: env_id is empty", ErrInvalidCloudLink)
	}
	if lastSync.IsZero() {
		return fmt.Errorf("%w: last_sync_at is missing", ErrInvalidCloudLink)
	}
	// Mốc thời gian ghi TRƯỚC, URL ghi SAU. Ba lần ghi không cùng transaction
	// (store không phơi tx cho settings); Paired được suy từ URL, nên nếu chết
	// giữa chừng thì tệ nhất là "chưa pair" thêm một nhịp — agent báo lại sau
	// CloudLinkEvery — chứ không có cửa sổ nào "đã pair" mà thiếu mốc.
	if err := c.st.SetSetting(ctx, SettingCloudLinkLastSyncAt, lastSync.UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if err := c.st.SetSetting(ctx, SettingCloudLinkEnvID, strings.TrimSpace(envID)); err != nil {
		return err
	}
	return c.st.SetSetting(ctx, SettingCloudLinkURL, cloudURL)
}

// CloudLink đọc ba khoá và tính State theo `now`. Khoá vắng là standalone,
// KHÔNG phải lỗi — một máy chưa từng pair là ca thường ngày.
//
// `now` là tham số chứ không phải time.Now() để test đặt đúng mốc 5 phút hai
// bên biên mà không phải ngủ.
func (c *Config) CloudLink(ctx context.Context, now time.Time) (CloudLinkInfo, error) {
	var info CloudLinkInfo
	var err error
	if info.CloudURL, err = c.get(ctx, SettingCloudLinkURL); err != nil {
		return CloudLinkInfo{}, err
	}
	if info.CloudURL == "" {
		return CloudLinkInfo{State: StateStandalone}, nil
	}
	if info.EnvID, err = c.get(ctx, SettingCloudLinkEnvID); err != nil {
		return CloudLinkInfo{}, err
	}
	raw, err := c.get(ctx, SettingCloudLinkLastSyncAt)
	if err != nil {
		return CloudLinkInfo{}, err
	}
	// Mốc không đọc được (ai đó sửa tay bảng settings) → coi như rất cũ: thà
	// báo stale giả còn hơn synced giả — stale có lệnh chẩn đoán đi kèm, synced
	// thì không ai nhìn lại.
	info.LastSyncAt, _ = time.Parse(time.RFC3339, raw)
	info.Paired = true
	if !info.LastSyncAt.IsZero() && now.Sub(info.LastSyncAt) <= StaleAfter {
		info.State = StateSynced
	} else {
		info.State = StateStale
	}
	return info, nil
}
