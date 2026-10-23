// Package dir — target trên filesystem cục bộ hoặc mount (NFS/SMB).
//
//	KEENRIG_BACKUP_TARGET=dir
//	KEENRIG_BACKUP_CONFIG=/mnt/nas/keenrig-backup
//
// # Đây cũng là driver cho NAS, và đó là một lựa chọn có điều kiện
//
// Một share SMB/NFS đã mount là một thư mục với Go, nên driver này phục vụ luôn
// ca NAS của BT-01 mà không cần code riêng. Cái phải nói thẳng: tính NGUYÊN KHỐI
// của `Put` ở đây dựa vào `os.Rename` cùng filesystem là nguyên tử. Điều đó đúng
// trên ext4/xfs/APFS/NTFS; trên CIFS thì phụ thuộc server và tuỳ chọn mount, và
// không có cách nào để driver tự kiểm. Nên với NAS, khẳng định đúng là "không tệ
// hơn cách ghi trực tiếp", không phải "nguyên tử".
//
// # Vì sao KHÔNG cảnh báo khi target nằm trên cùng đĩa với dữ liệu
//
// Vì driver không biết được. `/mnt/backup` có thể là bind mount của `/`, hoặc là
// một NAS. Chỗ đúng để cảnh báo là tầng cấu hình instance, nơi có cả hai đường
// dẫn để so — và nó thuộc BK-02.
package dir

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/backup/target"
)

// Name — tên driver.
const Name = "dir"

func init() { target.Register(Name, open) }

type Driver struct{ root string }

func open(_ context.Context, cfg Config) (target.Target, error) {
	return New(cfg.DSN)
}

// Config alias để init không phụ thuộc thứ tự khai báo.
type Config = target.Config

// New dựng driver với thư mục gốc là root.
//
// Kiểm NGAY tại đây, không đợi Put: một thư mục sao lưu không ghi được chỉ lộ ra
// lúc snapshot đầu tiên chạy theo lịch — tức là lúc không ai ngồi xem log.
func New(root string) (*Driver, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("%w: %s needs a path, e.g. KEENRIG_BACKUP_CONFIG=/mnt/nas/keenrig",
			target.ErrBadConfig, Name)
	}
	if !filepath.IsAbs(root) {
		// Đường dẫn tương đối phụ thuộc thư mục làm việc của tiến trình, và
		// keenrig-box chạy từ systemd với WorkingDirectory không hiển nhiên.
		return nil, fmt.Errorf("%w: %s needs an ABSOLUTE path, got %q",
			target.ErrBadConfig, Name, root)
	}
	// CHUẨN HOÁ root — và đây không phải dọn dẹp cho gọn.
	//
	// `path` kiểm thoát-thư-mục bằng cách so tiền tố giữa `filepath.Join(root,
	// key)` và `root + separator`. Join tự Clean vế trái nhưng KHÔNG chạm vào
	// root, nên chỉ cần root khác dạng chuẩn một chút là phép so tiền tố hỏng:
	//
	//	/mnt/backup/          → so với "/mnt/backup//" → KHÔNG khớp
	//	C:/nas/backup         → Join ra "C:\nas\backup\..." → KHÔNG khớp
	//
	// Hậu quả không phải một cảnh báo nhỏ mà là MỌI thao tác ghi thất bại, với
	// thông báo đổ lỗi cho key: *"invalid key: … escapes the backup directory"*.
	// Người vận hành đọc dòng đó sẽ đi tìm lỗi ở tên key, trong khi thứ sai là
	// một dấu '/' thừa ở cuối biến môi trường.
	//
	// Tìm ra bằng cách chạy `keenrig-box backup` thật với DSN có dấu '/' xuôi
	// trên Windows — không phải bằng đọc code, và không test nào của BT-01 bắt
	// được vì tất cả đều dựng root bằng `t.TempDir()` (luôn ở dạng chuẩn).
	root = filepath.Clean(root)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("%w: creating %s: %s", target.ErrBadConfig, root, err)
	}
	// 0700 vì bản sao lưu chứa toàn bộ dữ liệu instance — kể cả bảng secrets đã
	// mã hoá và, ở BK-02, cả khoá. Một thư mục 0755 làm mọi user trên máy đọc
	// được lịch sử đầy đủ của mọi app.
	if err := os.Chmod(root, 0o700); err != nil && !errors.Is(err, fs.ErrPermission) {
		return nil, fmt.Errorf("%w: chmod 0700 %s: %s", target.ErrBadConfig, root, err)
	}
	probe := filepath.Join(root, ".keenrig-write-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return nil, fmt.Errorf("%w: %s is not writable: %s", target.ErrBadConfig, root, err)
	}
	_ = os.Remove(probe)
	return &Driver{root: root}, nil
}

func (d *Driver) Name() string { return Name }

// path map key → đường dẫn, SAU khi đã kiểm key.
//
// Kiểm rồi mới join, và join rồi kiểm lại lần nữa bằng tiền tố: ValidateKey đã
// chặn `..`, nhưng lớp thứ hai là thứ bắt được nếu luật ở tầng trên bị nới ra sau
// này. Cùng mô hình bốn lớp của `appdata.sh`.
func (d *Driver) path(key string) (string, error) {
	if err := target.ValidateKey(key); err != nil {
		return "", err
	}
	p := filepath.Join(d.root, filepath.FromSlash(key))
	if p != d.root && !strings.HasPrefix(p, d.root+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: %q escapes the backup directory", target.ErrBadKey, key)
	}
	return p, nil
}

// Put ghi ra file tạm rồi RENAME.
//
// Ghi trực tiếp vào file đích nghĩa là một lần ngắt (mất điện, OOM kill, ctx hết
// hạn) để lại một archive cụt mà `List` vẫn kể tên và `Size` vẫn có số. Bản sao
// lưu đó đi qua mọi lần kiểm và chỉ hỏng lúc giải nén để restore — đúng lúc không
// còn lựa chọn nào khác.
func (d *Driver) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	p, err := d.path(key)
	if err != nil {
		return err
	}
	if size < 0 {
		return fmt.Errorf("target: %s: negative size (%d)", Name, size)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(p), ".put-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Dọn file tạm ở MỌI đường thoát. Không có nó thì mỗi lần Put lỗi để lại một
	// file .tmp, và thư mục sao lưu đầy dần bằng rác mà không ai nhìn.
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, fs.ErrPermission) {
		return err
	}
	n, err := io.Copy(tmp, io.LimitReader(r, size))
	if err != nil {
		return fmt.Errorf("target: %s: writing %s: %w", Name, key, err)
	}
	// size là HỢP ĐỒNG, không phải gợi ý: caller lấy nó từ os.Stat, và file có
	// thể đã bị cắt bớt giữa lúc đọc. Ghi ít hơn đã hứa rồi rename là tạo ra một
	// bản sao lưu cụt mang đúng tên bản đầy đủ.
	if n != size {
		return fmt.Errorf("target: %s: %s declared %d bytes but %d were read", Name, key, size, n)
	}
	// fsync TRƯỚC rename: rename nguyên tử chỉ bảo đảm "thấy tên cũ hoặc tên
	// mới", không bảo đảm nội dung đã xuống đĩa. Mất điện ngay sau rename có thể
	// để lại một file đúng tên với nội dung rỗng.
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err // ngắt trước khi công bố: file tạm sẽ bị defer dọn
	}
	return os.Rename(tmpName, p)
}

func (d *Driver) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	p, err := d.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", target.ErrNotFound, key)
	}
	if err != nil {
		return nil, err
	}
	// Thư mục mở được bằng os.Open nhưng đọc ra lỗi ở giữa đường. Bắt tại đây để
	// caller nhận ErrNotFound thay vì một reader hỏng.
	st, serr := f.Stat()
	if serr != nil || st.IsDir() {
		f.Close()
		return nil, fmt.Errorf("%w: %s", target.ErrNotFound, key)
	}
	return f, nil
}

// List đi bộ cây thư mục và lọc theo TIỀN TỐ CHUỖI của key.
//
// Tiền tố chuỗi, không phải tên thư mục: `List("snap/a")` phải khớp `snap/a.tgz`.
// Đó là ngữ nghĩa của S3, và hai driver hiểu prefix khác nhau sẽ làm cùng một
// lệnh retention xoá hai tập khác nhau tuỳ nơi lưu.
func (d *Driver) List(ctx context.Context, prefix string) ([]target.Object, error) {
	if err := target.ValidatePrefix(prefix); err != nil {
		return nil, err
	}
	var out []target.Object
	err := filepath.WalkDir(d.root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			// Một thư mục con không đọc được không được làm cả lần liệt kê thất
			// bại... NGOẠI TRỪ khi đó là chính thư mục gốc. Xem godoc dưới.
			if p == d.root {
				return err
			}
			return nil
		}
		if e.IsDir() || ctx.Err() != nil {
			return ctx.Err()
		}
		rel, rerr := filepath.Rel(d.root, p)
		if rerr != nil {
			return nil
		}
		key := filepath.ToSlash(rel)
		// File tạm của Put đang dở KHÔNG được kể tên: nó không phải object, và
		// retention sẽ đếm nó như một bản sao lưu.
		if strings.HasPrefix(filepath.Base(key), ".put-") || filepath.Base(key) == ".keenrig-write-probe" {
			return nil
		}
		if !strings.HasPrefix(key, prefix) {
			return nil
		}
		info, ierr := e.Info()
		if ierr != nil {
			return nil
		}
		out = append(out, target.Object{Key: key, Size: info.Size(), ModTime: info.ModTime()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// Delete xoá file. Không có → nil (idempotent).
//
// Xoá luôn thư mục cha nếu nó trở thành rỗng: không dọn thì sau vài tháng
// retention, cây thư mục còn lại là hàng nghìn thư mục ngày rỗng, và `List` phải
// đi bộ hết chúng mỗi lần.
func (d *Driver) Delete(ctx context.Context, key string) error {
	p, err := d.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for cur := filepath.Dir(p); cur != d.root && strings.HasPrefix(cur, d.root); cur = filepath.Dir(cur) {
		// os.Remove trên thư mục CHỈ thành công khi nó rỗng — nên đây vừa là
		// phép kiểm vừa là phép xoá, không có cửa sổ giữa hai bước.
		if err := os.Remove(cur); err != nil {
			return nil
		}
	}
	return nil
}
