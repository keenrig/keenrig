package addons

// Provisioner — mặt tiền mà reconciler dùng: mở driver theo kind, dùng lại.
//
// # Vì sao cần một tầng nữa thay vì reconciler tự gọi Open
//
// `Open` dựng một driver mới mỗi lần gọi. Với postgres, mỗi driver mới sẽ gọi
// `EnsureInfra` — tức là một lần inspect container cho MỖI app trong MỖI vòng
// hội tụ. Ở 50 app với nhịp 1 giây, đó là 50 lời gọi Docker mỗi giây cho một
// container không đổi.
//
// Provisioner mở MỘT LẦN cho mỗi kind rồi dùng lại. Driver phải an toàn khi gọi
// đồng thời — cả hai driver hiện tại đều không giữ state nào ngoài `cfg`, nên
// điều đó đúng, và `var _ = ...` bên dưới không kiểm được nó. Nếu một driver
// tương lai cần cache thì nó phải tự khoá.

import (
	"context"
	"fmt"
	"sync"
)

type Provisioner struct {
	cfg Config

	mu     sync.Mutex
	opened map[Kind]Addon
}

func NewProvisioner(cfg Config) *Provisioner {
	return &Provisioner{cfg: cfg, opened: map[Kind]Addon{}}
}

// get mở driver (hoặc trả bản đã mở).
func (p *Provisioner) get(ctx context.Context, k Kind) (Addon, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if a, ok := p.opened[k]; ok {
		return a, nil
	}
	a, err := Open(ctx, k, p.cfg)
	if err != nil {
		return nil, err
	}
	p.opened[k] = a
	return a, nil
}

// Setup cấp phát và trả bộ biến môi trường.
func (p *Provisioner) Setup(ctx context.Context, k Kind, appID string) (map[string]string, error) {
	a, err := p.get(ctx, k)
	if err != nil {
		return nil, err
	}
	c, err := a.Setup(ctx, appID)
	if err != nil {
		return nil, err
	}
	// Kiểm LẠI ở đây dù driver đã kiểm: đây là ranh giới cuối trước khi bộ biến
	// đi vào container app. Một driver thứ ba viết sai tên biến sẽ bị chặn ở đây
	// thay vì làm app của người dùng mất kết nối.
	//
	// Hai lớp, không phải một, vì chúng bắt hai loại lỗi khác nhau:
	//   ValidateEnv     tên biến + byte NUL (schema KHÔNG diễn đạt được NUL —
	//                   nó là chuỗi JSON hợp lệ, chỉ bị cắt cụt ở tầng syscall).
	//   Record.Validate enum addon + additionalProperties:false + secret_ref
	//                   khác rỗng — những thứ regex tên biến không nhìn thấy.
	if err := ValidateEnv(c.Env); err != nil {
		return nil, fmt.Errorf("addon %s: %w", k, err)
	}
	if err := c.Record(k, appID).Validate(); err != nil {
		return nil, err
	}
	return c.Env, nil
}

// Teardown dọn phần của app này.
func (p *Provisioner) Teardown(ctx context.Context, k Kind, appID string) error {
	a, err := p.get(ctx, k)
	if err != nil {
		return err
	}
	return a.Teardown(ctx, appID)
}

// Backup/Restore — đường cho internal/backup (BK-01) dùng ở bước sau.
func (p *Provisioner) Backup(ctx context.Context, k Kind, appID, dir string) error {
	a, err := p.get(ctx, k)
	if err != nil {
		return err
	}
	return a.Backup(ctx, appID, dir)
}

func (p *Provisioner) Restore(ctx context.Context, k Kind, appID, dir string) error {
	a, err := p.get(ctx, k)
	if err != nil {
		return err
	}
	return a.Restore(ctx, appID, dir)
}

// PITR trả năng lực khôi phục theo thời điểm của một kind, hoặc nil.
//
// Trả nil KHÔNG phải lỗi: redis không có WAL liên tục, và đó là câu trả lời đúng
// cho redis chứ không phải một thiếu sót cần báo. Caller phải phân biệt được
// "addon này không làm được" với "addon này hỏng", nên hai ca đó đi bằng hai
// đường trả về khác nhau.
func (p *Provisioner) PITR(ctx context.Context, k Kind) (PITR, error) {
	a, err := p.get(ctx, k)
	if err != nil {
		return nil, err
	}
	return PITROf(a), nil
}
