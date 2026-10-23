// Package locks — khoá theo TÊN THAO TÁC, kèm ma trận tương thích.
//
// # Vấn đề nó giải, và vì sao lease không giải được
//
// `store.Lease` trả lời "ai được lái Docker" — một reconciler duy nhất, gia hạn
// mãi mãi. Nó KHÔNG trả lời được câu thứ hai: "backup có được chạy trong lúc
// đang cập nhật box không?". Ép câu thứ hai vào lease nghĩa là backup phải
// giành lease của reconciler, tức là dừng hẳn vòng hội tụ suốt cả lần backup.
//
// Hai câu hỏi, hai cơ chế:
//
//	lease  — quyền LÀM VIỆC LIÊN TỤC, đúng một chủ, gia hạn vô hạn
//	lock   — quyền CHẠY MỘT THAO TÁC HỮU HẠN, nhiều loại, có ma trận tương thích
//
// # Vì sao có ma trận tương thích
//
// Điểm cốt lõi không phải bản thân việc khoá, mà là danh sách "cái gì xung
// khắc cái gì" phải được viết ra một chỗ và kiểm bằng máy — chứ không nằm rải
// rác trong từng thao tác dưới dạng "nhớ kiểm trước khi chạy".
//
// Lưu trữ: mỗi khoá là một HÀNG, khoá chính là tên thao tác. Giành khoá là
// đúng một câu `INSERT … ON CONFLICT … WHERE` — SQLite tự bảo đảm chỉ một bên
// thắng, nên tầng này không phải tự làm phân xử nào.
package locks

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/store"
)

// Tên thao tác. Tên có dấu "/" là tên theo PHẠM VI: "<phạm vi>/<id app>", để
// hai app khác nhau chạy song song được mà vẫn xung khắc đúng chỗ cần.
const (
	// BoxUpdate — thay bin/ (OTA). Xung khắc với gần như mọi thứ.
	BoxUpdate = "ota"
	// FullBackup — backup toàn instance.
	FullBackup = "backup-all"
	// AppTaskPrefix — thao tác dài trên một app (cài, đổi cấu hình lớn, khôi phục).
	AppTaskPrefix = "app-op/"
	// AppBackupPrefix — backup của MỘT app.
	AppBackupPrefix = "app-backup/"
	// RuntimeMigrate — đổi driver runtime (docker → swarm/k8s).
	RuntimeMigrate = "runtime-switch"
)

// AppTask / AppBackup dựng tên khoá cho một app.
func AppTask(appID string) string   { return AppTaskPrefix + appID }
func AppBackup(appID string) string { return AppBackupPrefix + appID }

var (
	// ErrBusy — có thao tác xung khắc đang chạy. Thông báo kèm TÊN thao tác
	// đang chặn: "hệ thống bận" là câu vô dụng, "đang cập nhật box" thì người
	// vận hành biết phải chờ bao lâu.
	ErrBusy = errors.New("locks: a conflicting operation is in progress")
	// ErrNotHeld — nhả khoá mình không giữ.
	ErrNotHeld = errors.New("locks: the lock is not held by you")
)

// DefaultTTL — hạn mặc định của một khoá.
//
// Đây là HÀNG RÀO CUỐI cho trường hợp tiến trình giữ khoá chết, không phải cơ
// chế chính (chủ phải tự nhả). 30 phút đủ dài cho một lần backup lớn mà vẫn đủ
// ngắn để một lần crash không khoá tính năng backup tới hết ngày.
const DefaultTTL = 30 * time.Minute

// conflictsWith trả về danh sách LOẠI thao tác mà `want` không chạy cùng được.
//
// Bảng này là NƠI DUY NHẤT định nghĩa xung khắc. Thêm một loại thao tác mới mà
// quên khai ở đây thì nó chạy song song với mọi thứ — vì vậy có test đối xứng
// canh (TestMatrixIsSymmetric).
func conflictsWith(want string) []string {
	switch {
	case want == BoxUpdate:
		// Thay bin/ trong lúc một app đang cài dở, hoặc trong lúc đang backup,
		// để lại một trạng thái không ai tạo ra: binary mới đọc dữ liệu do
		// binary cũ ghi dở.
		return []string{BoxUpdate, FullBackup, AppTaskPrefix, AppBackupPrefix, RuntimeMigrate}

	case want == RuntimeMigrate:
		// Đổi nền tảng chạy app — mọi thứ khác phải đứng yên.
		return []string{BoxUpdate, FullBackup, AppTaskPrefix, AppBackupPrefix, RuntimeMigrate}

	case want == FullBackup:
		// Backup toàn instance đọc trạng thái của MỌI app; một app đang cài dở
		// sẽ vào bản backup ở trạng thái nửa vời.
		return []string{BoxUpdate, FullBackup, AppTaskPrefix, RuntimeMigrate}

	case strings.HasPrefix(want, AppTaskPrefix):
		// Thao tác trên app: chặn bởi update/migrate/full-backup, và bởi CHÍNH
		// NÓ (cùng app). Hai app khác nhau chạy song song được — đó là lý do
		// khoá mang id app chứ không phải một khoá "apps" chung.
		return []string{BoxUpdate, FullBackup, RuntimeMigrate, want}

	case strings.HasPrefix(want, AppBackupPrefix):
		// Backup MỘT app chạy song song với thao tác app khác được; chỉ xung
		// khắc với update box và với chính nó.
		return []string{BoxUpdate, RuntimeMigrate, want}

	default:
		// Khoá lạ: xung khắc với chính nó. Mặc định CHẶT — một tên gõ sai không
		// được biến thành một thao tác chạy song song với mọi thứ.
		return []string{want}
	}
}

// matches cho biết một khoá ĐANG GIỮ có khớp mẫu xung khắc không.
// Mẫu kết thúc bằng "/" là cả một phạm vi (khớp mọi app), còn lại khớp đúng tên.
func matches(held, pattern string) bool {
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(held, pattern)
	}
	return held == pattern
}

// Manager cấp và nhả khoá.
type Manager struct {
	st     store.Store
	holder string
	ttl    time.Duration
}

// New dựng manager. holder nên là định danh tiến trình + job (vd
// "box-1/job-42") để ReleaseAll dọn đúng phạm vi.
func New(st store.Store, holder string, ttl time.Duration) *Manager {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Manager{st: st, holder: holder, ttl: ttl}
}

func (m *Manager) Holder() string { return m.holder }

// Acquire giành khoá sau khi kiểm ma trận.
//
// Hai bước — kiểm ma trận rồi mới INSERT — nên có một cửa sổ hẹp giữa chúng.
// Cửa sổ đó KHÔNG nguy hiểm ở đây vì bước INSERT vẫn nguyên tử trên chính tên
// khoá: hai thao tác CÙNG LOẠI không bao giờ cùng thắng. Chỉ hai thao tác KHÁC
// loại xung khắc nhau mới có thể cùng lọt, và cả hai đường đó đều đi qua
// reconciler vốn đơn luồng. Ghi rõ giới hạn thay vì giả vờ là nó tuyệt đối.
func (m *Manager) Acquire(ctx context.Context, name, reason string) error {
	held, err := m.st.ListLocks(ctx)
	if err != nil {
		return err
	}
	for _, pattern := range conflictsWith(name) {
		for _, h := range held {
			if h.Holder == m.holder && h.Name == name {
				continue // khoá của chính mình → gia hạn, không phải xung khắc
			}
			if matches(h.Name, pattern) {
				return fmt.Errorf("%w: %q is running (holder %s%s)", ErrBusy, h.Name, h.Holder, reasonSuffix(h.Reason))
			}
		}
	}

	if _, err := m.st.AcquireLock(ctx, name, m.holder, reason, m.ttl); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("%w: %q was just taken by someone else", ErrBusy, name)
		}
		return err
	}
	return nil
}

func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return ": " + reason
}

// Release nhả một khoá.
func (m *Manager) Release(ctx context.Context, name string) error {
	err := m.st.ReleaseLock(ctx, name, m.holder)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil // nhả hai lần không phải lỗi
	case errors.Is(err, store.ErrConflict):
		return fmt.Errorf("%w: %q", ErrNotHeld, name)
	}
	return err
}

// ReleaseAll nhả mọi khoá của chủ này; nếu có gì để nhả thì GHI LOG.
//
// Worker gọi hàm này sau mỗi job như một lưới an toàn. Bình thường nó không
// có gì để làm — WithLock đã tự nhả. Khi nó nhả được khoá nào thì đó là tín
// hiệu cần sửa code, nên phải để lại dấu vết trong log thay vì lặng lẽ dọn.
func (m *Manager) ReleaseAll(ctx context.Context) {
	n, err := m.st.ReleaseLocksByHolder(ctx, m.holder)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("locks: releasing locks held by %s: %v", m.holder, err)
		}
		return
	}
	if n > 0 {
		log.Printf("locks: %s left %d lock(s) held — cleaned up, but this is a bug in the job's exit path", m.holder, n)
	}
}

// WithLock chạy fn dưới khoá, luôn nhả kể cả khi fn panic.
//
// Đây là API NÊN DÙNG: defer bảo đảm nhả trên mọi đường thoát. Với
// Acquire/Release viết tay, chỉ cần một `return` sớm là khoá nằm đó tới hết TTL.
func (m *Manager) WithLock(ctx context.Context, name, reason string, fn func(context.Context) error) error {
	if err := m.Acquire(ctx, name, reason); err != nil {
		return err
	}
	defer func() {
		// ctx có thể đã bị huỷ khi fn trả về; nhả khoá bằng ctx riêng, nếu
		// không thì khoá kẹt tới hết TTL đúng vào lúc tắt máy.
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.Release(releaseCtx, name); err != nil {
			log.Printf("locks: releasing %q: %v", name, err)
		}
	}()
	return fn(ctx)
}

// Blocking trả danh sách khoá đang chặn một thao tác (rỗng = chạy được ngay).
// Dùng cho API "vì sao tôi không backup được".
func (m *Manager) Blocking(ctx context.Context, name string) ([]*store.Lock, error) {
	held, err := m.st.ListLocks(ctx)
	if err != nil {
		return nil, err
	}
	var out []*store.Lock
	seen := map[string]bool{}
	for _, pattern := range conflictsWith(name) {
		for _, h := range held {
			if h.Holder == m.holder && h.Name == name {
				continue
			}
			if matches(h.Name, pattern) && !seen[h.Name] {
				seen[h.Name] = true
				out = append(out, h)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
