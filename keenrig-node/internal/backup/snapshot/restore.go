package snapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/backup/crypt"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/backup/format"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/backup/target"
	"github.com/keenrig-platform/keenrig/keenrig-node/internal/paths"
)

// ErrInstanceNotEmpty — đích restore đã có dữ liệu.
//
// Lỗi RIÊNG vì nó dẫn tới một hành động rất khác mọi lỗi khác: người vận hành
// phải tự quyết định xoá cái đang có. Không có cờ `--force` ở tầng này — xem
// godoc Restore.
var ErrInstanceNotEmpty = errors.New("snapshot: the instance already has data")

// List trả mọi snapshot HOÀN CHỈNH trên Target, mới nhất trước.
//
// "Hoàn chỉnh" = có manifest. Một lần chạy bị ngắt để lại vài object mồ côi;
// kể tên chúng như một bản sao lưu là mời người ta restore từ một bản không đủ.
func List(ctx context.Context, tg target.Target) ([]*Manifest, error) {
	objs, err := tg.List(ctx, Prefix)
	if err != nil {
		return nil, err
	}
	var out []*Manifest
	for _, o := range objs {
		if !strings.HasSuffix(o.Key, "/"+ManifestName) {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(o.Key, Prefix), "/"+ManifestName)
		m, err := Load(ctx, tg, id)
		if err != nil {
			// Một manifest hỏng KHÔNG được làm cả lần liệt kê thất bại: người
			// vận hành cần thấy những bản còn lành, nhất là lúc đang đi tìm bản
			// để cứu.
			continue
		}
		out = append(out, m)
	}
	// ID sinh theo thời gian và sắp chuỗi trùng sắp thời gian (xem NewID), nên
	// đảo ngược thứ tự key là ra "mới nhất trước".
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// Load đọc manifest của một snapshot.
func Load(ctx context.Context, tg target.Target, id string) (*Manifest, error) {
	rc, err := tg.Get(ctx, ManifestKey(id))
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	// Giới hạn đọc: manifest là dữ liệu từ nơi lưu trữ, và một object 2 GB mang
	// tên manifest.json sẽ ăn hết RAM của tiến trình restore.
	body, err := io.ReadAll(io.LimitReader(rc, 8<<20))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("snapshot: reading manifest %s: %w", id, err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// RestoreOptions — mọi thứ Restore cần.
type RestoreOptions struct {
	Layout paths.Layout
	Target target.Target
	// Format — nil thì Restore tự mở driver theo tên ghi trong manifest. Truyền
	// vào chỉ để test dùng driver dựng sẵn.
	Format     format.Format
	Passphrase string
	// ID — rỗng thì lấy snapshot mới nhất.
	ID string
	// OnlyApps — rỗng thì khôi phục tất cả. Có giá trị thì CHỈ những app đó, và
	// phần `instance` bị BỎ QUA: ca "app này hỏng, lấy lại bản hôm qua" không
	// được phép ghi đè platform.db của cả máy.
	OnlyApps []string
	// AddonRestore — nil thì dump addon được giải nén ra đĩa nhưng KHÔNG nạp
	// vào addon. Việc đó được nói ra, không im lặng.
	AddonRestore func(ctx context.Context, appID, dir string) error
	Log          func(format string, args ...any)
}

// Restore khôi phục từ một snapshot.
//
// # Từ chối khi instance đã có dữ liệu — và không có cờ ép
//
// Restore lên một instance đang chạy là cách mất dữ liệu nhanh nhất còn tồn tại
// trong hệ thống này: nó ghi đè platform.db (toàn bộ app, user, secret) bằng
// một bản cũ, trong khi container vẫn đang chạy và vẫn đang ghi vào cây dữ liệu
// mà ta vừa thay dưới chân chúng.
//
// Không có `--force`, có chủ đích. Một cờ như thế biến "không thể làm nhầm"
// thành "chỉ cần gõ thêm sáu ký tự", và nó sẽ được gõ lúc 3 giờ sáng bởi người
// đang hoảng. Muốn restore đè thì phải tự xoá thư mục trước — một hành động
// tường minh, có thể nhìn thấy trong lịch sử shell, và không thể làm nhầm.
//
// # Xác thực băm TRONG LÚC giải nén, không phải sau
//
// Băm được tính trên chính luồng plaintext đang chảy vào bộ giải nén, nên nó
// không phải đọc lại lần hai. Nhưng nó chỉ đối chiếu được ở CUỐI luồng — nghĩa
// là dữ liệu sai đã kịp ra đĩa trước khi ta biết. Đó là đánh đổi có ý thức:
// lớp `crypt` đã xác thực từng chunk 64 KiB TRƯỚC khi nhả ra, nên băm ở đây bắt
// một loại lỗi khác hẳn — Target trả đúng số byte của một object KHÁC.
func Restore(ctx context.Context, opts RestoreOptions) (*Manifest, error) {
	logf := opts.Log
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if opts.Target == nil {
		return nil, errors.New("snapshot: no backup target")
	}

	man, err := resolve(ctx, opts)
	if err != nil {
		return nil, err
	}
	f := opts.Format
	if f == nil {
		if f, err = format.Open(man.Format); err != nil {
			return nil, err
		}
	}
	if f.Name() != man.Format {
		return nil, fmt.Errorf("snapshot: manifest was packed by %q but %q was supplied", man.Format, f.Name())
	}

	parts, err := selectParts(man, opts.OnlyApps)
	if err != nil {
		return nil, err
	}

	// Kiểm passphrase TRƯỚC khi tải bất cứ thứ gì lớn: sai passphrase phải lộ ra
	// sau vài chục byte, không phải sau mười phút tải về. Xem crypt.CheckPassphrase.
	if man.Encrypted {
		if err := checkPassphrase(ctx, opts.Target, parts[0].Key, opts.Passphrase); err != nil {
			return nil, err
		}
	}

	for _, p := range parts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		dest, err := destinationFor(opts.Layout, p)
		if err != nil {
			return nil, err
		}
		if err := restorePart(ctx, opts, f, p, dest, man.Encrypted, logf); err != nil {
			return nil, err
		}
	}
	logf("restore: snapshot %s restored: %d parts", man.ID, len(parts))
	return man, nil
}

func resolve(ctx context.Context, opts RestoreOptions) (*Manifest, error) {
	if strings.TrimSpace(opts.ID) != "" {
		return Load(ctx, opts.Target, opts.ID)
	}
	all, err := List(ctx, opts.Target)
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("%w: no complete snapshot found under %q", target.ErrNotFound, Prefix)
	}
	return all[0], nil
}

// selectParts chọn phần sẽ khôi phục, và ép luật "chọn app thì KHÔNG đụng
// instance".
func selectParts(man *Manifest, onlyApps []string) ([]Part, error) {
	if len(onlyApps) == 0 {
		return man.Parts, nil
	}
	want := map[string]bool{}
	for _, a := range onlyApps {
		want[a] = true
	}
	var out []Part
	for _, p := range man.Parts {
		if p.Kind != KindInstance && want[p.AppID] {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("snapshot %s has no data for the requested app(s)", man.ID)
	}
	return out, nil
}

func checkPassphrase(ctx context.Context, tg target.Target, key, passphrase string) error {
	rc, err := tg.Get(ctx, key)
	if err != nil {
		return err
	}
	defer rc.Close()
	return crypt.CheckPassphrase(io.LimitReader(rc, crypt.PrefixLen), passphrase)
}

// destinationFor map một phần → thư mục đích trên đĩa.
func destinationFor(l paths.Layout, p Part) (string, error) {
	switch p.Kind {
	case KindInstance:
		return l.Instance(), nil
	case KindApp:
		return l.AppData(p.AppID)
	case KindAddon:
		// Dump addon KHÔNG đi thẳng vào cây dữ liệu: nó là đầu vào của
		// `addons.Addon.Restore`, và chỗ đúng cho nó là vùng làm việc tạm.
		dir, err := l.AppData(p.AppID)
		if err != nil {
			return "", err
		}
		return filepath.Join(filepath.Dir(dir), ".restore-addons-"+p.AppID), nil
	default:
		return "", fmt.Errorf("snapshot: unknown part kind %q", p.Kind)
	}
}

func restorePart(ctx context.Context, opts RestoreOptions, f format.Format, p Part, dest string, encrypted bool, logf func(string, ...any)) error {
	// Lớp phòng thủ thứ nhất, ở tầng NÀY: đích phải trống. format.Unpack cũng
	// kiểm, nhưng lỗi ở đây gọi đúng tên chuyện đang xảy ra — "instance đã có
	// dữ liệu" — thay vì "thư mục không rỗng".
	if err := ensureRestorable(dest); err != nil {
		return err
	}

	rc, err := opts.Target.Get(ctx, p.Key)
	if err != nil {
		return err
	}
	defer rc.Close()

	// Nhánh theo cờ trong MANIFEST, không theo việc caller có truyền passphrase
	// hay không: cái sau để một archive đã mã hoá bị đọc như archive trần khi
	// người ta quên đặt biến, và lỗi hiện ra sẽ là "không phải gzip" — nói sai
	// hoàn toàn chuyện đang xảy ra.
	var plain io.Reader = rc
	if encrypted {
		if plain, err = crypt.Unwrap(rc, opts.Passphrase); err != nil {
			return err
		}
	}

	sum := sha256.New()
	stats, err := f.Unpack(ctx, io.TeeReader(plain, sum), dest)
	if err != nil {
		return fmt.Errorf("snapshot: restoring %s: %w", p.Key, err)
	}
	if got := hex.EncodeToString(sum.Sum(nil)); got != p.PlainSHA256 {
		return fmt.Errorf("%w: %s (manifest %s, restored %s)", ErrDigestMismatch, p.Key, p.PlainSHA256, got)
	}
	logf("restore: %s -> %s (%d files)", p.Key, dest, stats.Files)

	if p.Kind == KindAddon && opts.AddonRestore != nil {
		if err := opts.AddonRestore(ctx, p.AppID, dest); err != nil {
			return fmt.Errorf("snapshot: loading the addon dump for app %s: %w", p.AppID, err)
		}
		// Dump đã vào addon rồi thì không để lại bản trần trên đĩa: nó chứa dữ
		// liệu app ở dạng không mã hoá.
		_ = os.RemoveAll(dest)
	} else if p.Kind == KindAddon {
		logf("restore: addon dump for app %s left at %s — no addon loader was supplied, load it manually", p.AppID, dest)
	}
	return nil
}

// ensureRestorable từ chối một đích đã có dữ liệu.
func ensureRestorable(dest string) error {
	ents, err := os.ReadDir(dest)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(ents) == 0 {
		return nil
	}
	names := make([]string, 0, 3)
	for i, e := range ents {
		if i == 3 {
			names = append(names, "…")
			break
		}
		names = append(names, e.Name())
	}
	return fmt.Errorf("%w: %s still contains %d entries (%s) — remove it yourself before restoring, there is no force flag",
		ErrInstanceNotEmpty, dest, len(ents), strings.Join(names, ", "))
}
