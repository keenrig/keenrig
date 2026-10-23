// Package instance — danh tính của instance: tên miền gốc, và NGUỒN của nó.
//
// # Vì sao có một package cho một giá trị
//
// Tên miền gốc (`<app>.<parent>`, `admin.<parent>`) có HAI nguồn có thể ghi
// vào cùng một khoá `settings.parent_domain`, và chúng không ngang hàng:
//
//	cloud   keenrig-cloud chọn tên cho môi trường (vd. demo.acme.keenrig.com,
//	        domain_mode=keenrig) và đưa xuống qua agent → node API. Đây là
//	        QUYẾT ĐỊNH CỦA CLOUD — luật chủ dự án 2026-09-07: "chỉ cho phép thực
//	        hiện bởi keenrig-cloud; keenrig-admin là nơi nhận thông tin thôi".
//	local   `get.sh --domain` ghi KEENRIG_DOMAIN vào unit; box đọc lúc khởi
//	        động. Đây là đường STANDALONE — máy không pair với cloud nào.
//
// Cloud THẮNG. Một box đã pair và đã nhận tên từ cloud không được để một biến
// môi trường cũ trong unit đè lại ở lần restart kế — người dùng đổi tên ở
// Console, restart box, và thấy tên cũ quay về là một lỗi không ai lần ra được
// từ Admin UI. Luật đó sống ở đây, một chỗ, thay vì rải ở main.go và nodeapi.
//
// Không có đường nào từ control API `/api/v1` (Admin UI) đặt được giá trị này
// — api chỉ gọi Info. Test phía api canh điều đó bằng cách gõ PUT/POST/PATCH/
// DELETE vào `/api/v1/instance` và đòi không-2xx.
package instance

import (
	"context"
	"errors"
	"fmt"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/domains"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/store"
)

// Khoá trong bảng `settings`.
const (
	// SettingParentDomain — tên miền gốc của instance. Định nghĩa CHÍNH ở đây;
	// api.SettingParentDomain là bí danh để chỗ đọc cũ không đổi.
	SettingParentDomain = "parent_domain"
	// SettingParentDomainSource — SourceCloud hoặc SourceLocal. Vắng = box cũ
	// đã ghi tên miền trước khi có khái niệm nguồn, hoặc chưa có tên miền.
	SettingParentDomainSource = "parent_domain_source"
	// SettingParentDomainMode — "keenrig" | "custom", chỉ có nghĩa khi nguồn
	// là cloud; local không biết mode nên để rỗng.
	SettingParentDomainMode = "parent_domain_mode"
)

// Nguồn của tên miền gốc.
const (
	SourceCloud = "cloud"
	SourceLocal = "local"
)

// Mode — khớp enum `domain_mode` của sync.schema.json và
// store.DomainModeKeenrig/DomainModeCustom phía cloud.
const (
	ModeKeenrig = "keenrig"
	ModeCustom  = "custom"
)

// ErrInvalidDomain — tên miền không dùng được làm tên gốc: rỗng, wildcard, nhãn
// rỗng, ký tự lạ, hoặc mode ngoài enum. Bọc domains.ErrInvalidFQDN khi lỗi đến
// từ cú pháp, để chỗ gọi map về 400 bằng một errors.Is.
var ErrInvalidDomain = errors.New("instance: invalid parent domain")

// Config — cửa duy nhất đọc/ghi tên miền gốc của instance.
type Config struct {
	st store.Store

	// OnParentChanged — gọi khi cloud ĐỔI tên miền gốc đang có (không gọi lần
	// đầu gán). box gắn apps.Service.RebaseDomains vào đây để app đang chạy ở
	// địa chỉ tạm tự dời sang tên miền riêng (release v0.3.8).
	OnParentChanged func(ctx context.Context, oldParent, newParent string) error
}

// New dựng Config trên store của box.
func New(st store.Store) *Config { return &Config{st: st} }

// Info — thứ Admin UI (và log khởi động) cần biết.
type Info struct {
	// ParentDomain rỗng = chưa có tên miền: một box vào bằng IP là hợp lệ.
	ParentDomain string
	// Source — SourceCloud | SourceLocal | "" (chưa có, hoặc box cũ chưa ghi nguồn).
	Source string
	// Mode — ModeKeenrig | ModeCustom | "" (không biết).
	Mode string
}

// Info đọc ba khoá; khoá vắng là "", KHÔNG phải lỗi.
func (c *Config) Info(ctx context.Context) (Info, error) {
	var info Info
	var err error
	if info.ParentDomain, err = c.get(ctx, SettingParentDomain); err != nil {
		return Info{}, err
	}
	if info.Source, err = c.get(ctx, SettingParentDomainSource); err != nil {
		return Info{}, err
	}
	if info.Mode, err = c.get(ctx, SettingParentDomainMode); err != nil {
		return Info{}, err
	}
	// Tên miền vắng thì nguồn/mode còn sót lại cũng vô nghĩa — trả sạch để UI
	// không vẽ pill "Keenrig Cloud" cạnh một ô trống.
	if info.ParentDomain == "" {
		return Info{}, nil
	}
	return info, nil
}

// SetFromCloud ghi tên miền cloud đã chọn, kèm nguồn = cloud.
//
// Chuẩn hoá bằng đúng luật FQDN của app (domains.Normalize): chữ thường, bỏ dấu
// chấm cuối, từ chối wildcard/nhãn rỗng/ký tự lạ. Cloud đã kiểm ở phía nó,
// nhưng box là nơi giá trị này thành `<app>.<parent>` — một tên hỏng lọt vào
// đây sinh ra N tên app hỏng, nên box kiểm lại thay vì tin.
//
// Idempotent theo giá trị: agent gửi lại cùng tên là ghi lại cùng ba khoá.
func (c *Config) SetFromCloud(ctx context.Context, parent, mode string) error {
	fqdn, err := domains.Normalize(parent)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidDomain, err)
	}
	switch mode {
	case "", ModeKeenrig, ModeCustom:
	default:
		return fmt.Errorf("%w: unknown domain mode %q (want %q or %q)",
			ErrInvalidDomain, mode, ModeKeenrig, ModeCustom)
	}
	// Dời app TRƯỚC khi ghi tên mới: hỏng giữa chừng thì box trả lỗi, agent
	// không nhớ "đã giao", và lần sync sau vẫn thấy tên cũ → dời tiếp phần còn
	// lại (RebaseDomains idempotent). Ghi trước rồi mới dời thì lần sau tên đã
	// bằng nhau và app bị bỏ lại ở địa chỉ cũ mãi.
	if c.OnParentChanged != nil {
		old, err := c.get(ctx, SettingParentDomain)
		if err != nil {
			return err
		}
		if old != "" && old != fqdn {
			if err := c.OnParentChanged(ctx, old, fqdn); err != nil {
				return fmt.Errorf("instance: moving apps from %s to %s: %w", old, fqdn, err)
			}
		}
	}
	// Tên miền ghi TRƯỚC, nguồn ghi SAU. Ba lần ghi không cùng transaction
	// (store không phơi tx cho settings); nếu chết giữa chừng thì tệ nhất là
	// tên cloud mang nguồn cũ — và nhịp sync kế của agent ghi lại đủ ba khoá,
	// vì agent chỉ nhớ "đã giao" khi box trả 200.
	if err := c.st.SetSetting(ctx, SettingParentDomain, fqdn); err != nil {
		return err
	}
	if err := c.st.SetSetting(ctx, SettingParentDomainMode, mode); err != nil {
		return err
	}
	return c.st.SetSetting(ctx, SettingParentDomainSource, SourceCloud)
}

// SetParentDomain — khớp nodeapi.ParentDomainSink. Node API là đường của
// agent, và agent chỉ mang giá trị từ cloud, nên hai tên này là một việc.
func (c *Config) SetParentDomain(ctx context.Context, parent, mode string) error {
	return c.SetFromCloud(ctx, parent, mode)
}

// ApplyLocal áp giá trị KEENRIG_DOMAIN lúc khởi động — theo luật cloud thắng.
//
// Trả (false, nil) khi nguồn hiện tại là cloud: biến môi trường bị bỏ qua, và
// chỗ gọi nên nói ra điều đó trong log để người sửa unit hiểu vì sao tên không
// đổi. Ngược lại ghi giá trị + nguồn = local và xoá mode (local không biết
// mode). Ghi ở MỖI lần khởi động, không chỉ lần đầu, để đổi `--domain` trên
// một box standalone chỉ cần sửa unit rồi restart.
//
// envValue rỗng → (false, nil): không có gì để áp, và không xoá gì.
func (c *Config) ApplyLocal(ctx context.Context, envValue string) (applied bool, err error) {
	if envValue == "" {
		return false, nil
	}
	fqdn, err := domains.Normalize(envValue)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrInvalidDomain, err)
	}
	src, err := c.get(ctx, SettingParentDomainSource)
	if err != nil {
		return false, err
	}
	if src == SourceCloud {
		return false, nil
	}
	if err := c.st.SetSetting(ctx, SettingParentDomain, fqdn); err != nil {
		return false, err
	}
	if err := c.st.SetSetting(ctx, SettingParentDomainMode, ""); err != nil {
		return false, err
	}
	if err := c.st.SetSetting(ctx, SettingParentDomainSource, SourceLocal); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Config) get(ctx context.Context, key string) (string, error) {
	v, err := c.st.GetSetting(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	return v, err
}
