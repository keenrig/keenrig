// Package tgz — format tar + gzip. Driver đầu tiên của seam `backup.Format`.
//
//	KEENRIG_BACKUP_FORMAT=tgz     (mặc định)
//
// # Vì sao tgz là driver đầu tiên chứ không phải restic
//
// Vì restore phải làm được KHI KHÔNG CÒN GÌ. Một VPS trắng, một file archive, và
// `tar xzf` có sẵn trong mọi bản Linux từ hai mươi năm nay. Nếu keenrig-box không
// khởi động được thì người vận hành vẫn lấy được dữ liệu ra bằng tay. Một format
// chỉ đọc được bằng chính công cụ đang hỏng là một bản sao lưu có điều kiện.
//
// Cái đánh đổi phải nói thẳng: KHÔNG dedup, KHÔNG tăng dần. Mỗi snapshot là toàn
// bộ cây, nén lại từ đầu. Với một instance vài GB thì chấp nhận được; với hàng
// trăm GB thì không, và đó là lúc driver thứ hai có lý do tồn tại.
//
// # Hard link không được giữ
//
// Hai tên trỏ cùng một inode ra hai file độc lập sau restore. Đó là hao dung
// lượng, không phải mất dữ liệu — và phát hiện hard link cần syscall riêng theo
// hệ điều hành. Ghi ở đây để không ai tưởng nó đã được xử lý.
//
// # Archive tất định
//
// Cùng một cây → cùng một byte. gzip header không mang thời gian đóng gói, và
// [filepath.WalkDir] đi theo thứ tự từ điển. Nhờ vậy "bản sao lưu này có khác bản
// trước không" trả lời được bằng một phép so sánh băm, không cần giải nén.
package tgz

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/keenrig/keenrig/keenrig-node/internal/backup/format"
)

// Name — tên driver. Giá trị này được ghi vào metadata snapshot; đổi nó là làm
// mọi snapshot cũ mở không được.
const Name = "tgz"

func init() { format.Register(Name, func() format.Format { return New() }) }

// Driver không mang state — mọi thứ nằm trong tham số của Pack/Unpack. Nhờ vậy
// một instance dùng được đồng thời cho nhiều snapshot.
type Driver struct{}

// New dựng driver.
func New() *Driver { return &Driver{} }

func (*Driver) Name() string { return Name }

// dirPerm — quyền tạm cho thư mục TRONG lúc giải nén.
//
// Không dùng mode thật ngay: một thư mục 0500 trong archive làm mọi entry con
// ghi không được. Mode thật được đặt lại ở cuối, sau khi con đã đủ.
const dirPerm fs.FileMode = 0o700

// --- Pack --------------------------------------------------------------------------

// Pack đi bộ cây và ghi tar.gz vào w.
func (d *Driver) Pack(ctx context.Context, dir string, w io.Writer) (format.Stats, error) {
	var st format.Stats

	root, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return st, err
	}
	fi, err := os.Stat(root)
	if err != nil || !fi.IsDir() {
		return st, fmt.Errorf("%w: %s", format.ErrNoSource, dir)
	}

	zw := gzip.NewWriter(w)
	// Header gzip mang tên file và thời gian đóng gói theo mặc định. Xoá cả hai:
	// chúng làm hai lần đóng gói cùng một cây ra hai chuỗi byte khác nhau, và mất
	// tính tất định là mất luôn cách so sánh snapshot bằng băm.
	zw.Name, zw.ModTime = "", time.Time{}
	tw := tar.NewWriter(zw)

	walkErr := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			// Thư mục gốc không đọc được là hỏng thật; một entry con không đọc
			// được thì ghi lại và đi tiếp — bản sao lưu thiếu một file có tên còn
			// hơn không có bản sao lưu nào.
			if p == root {
				return err
			}
			st.Skipped = append(st.Skipped, format.Skip{Path: relOf(root, p), Reason: err.Error()})
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return d.packEntry(root, p, e, tw, &st)
	})
	if walkErr != nil {
		return st, walkErr
	}

	// Đóng THEO THỨ TỰ và kiểm CẢ HAI lỗi: tar.Close ghi hai block kết thúc, gzip
	// .Close ghi CRC và độ dài. Bỏ qua lỗi ở đây là ghi ra một archive mà mọi
	// công cụ đọc được 99% rồi báo "unexpected EOF" — đúng lúc restore.
	if err := tw.Close(); err != nil {
		return st, err
	}
	if err := zw.Close(); err != nil {
		return st, err
	}
	return st, nil
}

func (d *Driver) packEntry(root, p string, e fs.DirEntry, tw *tar.Writer, st *format.Stats) error {
	rel := relOf(root, p)
	info, err := e.Info()
	if err != nil {
		if os.IsNotExist(err) {
			st.Skipped = append(st.Skipped, format.Skip{Path: rel, Reason: format.SkipVanished})
			return nil
		}
		return err
	}
	mode := info.Mode()

	switch {
	case mode.IsDir():
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		// Gốc đi vào archive với tên "." để mode của CHÍNH nó được giữ. `instance/`
		// là 0700 vì chứa master.key; restore ra 0755 là lộ khoá mà không có gì đỏ.
		hdr.Name = rel + "/"
		if rel == "." {
			hdr.Name = "./"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		st.Dirs++
		return nil

	case mode&fs.ModeSymlink != 0:
		// Đọc symlink NGUYÊN VĂN, kể cả khi nó trỏ ra ngoài cây. Đi xuyên qua nó
		// là chép nội dung ngoài cây vào bản sao lưu, và mất chính cái symlink —
		// restore ra một cây khác cây gốc. An toàn được bảo đảm ở chiều NGƯỢC
		// lại: Unpack không bao giờ ghi XUYÊN qua một symlink (EnsureRealParents).
		link, err := os.Readlink(p)
		if err != nil {
			if os.IsNotExist(err) {
				st.Skipped = append(st.Skipped, format.Skip{Path: rel, Reason: format.SkipVanished})
				return nil
			}
			return err
		}
		hdr, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		st.Symlinks++
		return nil

	case mode.IsRegular():
		return d.packFile(p, rel, tw, st)

	case mode&fs.ModeSocket != 0:
		st.Skipped = append(st.Skipped, format.Skip{Path: rel, Reason: format.SkipSocket})
		return nil

	case mode&(fs.ModeDevice|fs.ModeCharDevice|fs.ModeNamedPipe) != 0:
		st.Skipped = append(st.Skipped, format.Skip{Path: rel, Reason: format.SkipDevice})
		return nil

	default:
		st.Skipped = append(st.Skipped, format.Skip{Path: rel, Reason: format.SkipUnsupported})
		return nil
	}
}

// packFile MỞ TRƯỚC rồi mới stat qua chính handle đó.
//
// Thứ tự này không phải tuỳ tiện: size ghi vào header tar là một lời hứa nhị phân
// — ghi thiếu một byte so với lời hứa là hỏng cả archive từ chỗ đó trở đi. Stat từ
// lúc đi bộ cây tới lúc đọc có thể đã cũ; stat trên handle đã mở thì cửa sổ đó
// hẹp nhất có thể.
func (d *Driver) packFile(p, rel string, tw *tar.Writer, st *format.Stats) error {
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			st.Skipped = append(st.Skipped, format.Skip{Path: rel, Reason: format.SkipVanished})
			return nil
		}
		if errors.Is(err, fs.ErrPermission) {
			st.Skipped = append(st.Skipped, format.Skip{Path: rel, Reason: err.Error()})
			return nil
		}
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	hdr.Name = rel
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}

	// LimitReader để file ĐANG ĐƯỢC GHI THÊM (log của app) không tràn quá size đã
	// hứa. Ca ngược lại — file bị CẮT NGẮN giữa chừng — không vá được: header đã
	// ra khỏi tay, và đệm thêm số 0 cho đủ là ghi ra dữ liệu không có thật. Nên
	// nó là lỗi, và lỗi phải gọi đúng tên file.
	n, err := io.Copy(tw, io.LimitReader(f, info.Size()))
	if err != nil {
		return fmt.Errorf("tgz: reading %s: %w", rel, err)
	}
	if n != info.Size() {
		return fmt.Errorf("tgz: %s shrank while being read: declared %d bytes, got %d",
			rel, info.Size(), n)
	}
	st.Files++
	st.Bytes += n
	return nil
}

func relOf(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return filepath.ToSlash(p)
	}
	return filepath.ToSlash(rel)
}

// --- Unpack ------------------------------------------------------------------------

// pending — mode và mtime của một thư mục, để đặt lại SAU khi con đã đủ.
type pending struct {
	path  string
	mode  fs.FileMode
	mtime time.Time
}

// Unpack giải nén tar.gz từ r về dir.
func (d *Driver) Unpack(ctx context.Context, r io.Reader, dir string) (format.Stats, error) {
	var st format.Stats

	root, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return st, err
	}
	if err := format.EnsureEmptyDir(root, dirPerm); err != nil {
		return st, err
	}

	zr, err := gzip.NewReader(r)
	if err != nil {
		return st, fmt.Errorf("%w: %s", format.ErrBadArchive, err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	var dirs []pending
	for {
		if err := ctx.Err(); err != nil {
			return st, err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return st, fmt.Errorf("%w: %s", format.ErrBadArchive, err)
		}
		more, err := d.unpackEntry(root, hdr, tr, &st, &dirs)
		if err != nil {
			return st, err
		}
		dirs = more
	}

	// Đặt mode và mtime của thư mục SAU CÙNG, từ sâu ra nông.
	//
	// Hai lý do, cả hai đều làm hỏng theo cách im lặng nếu làm sớm: một thư mục
	// 0500 không nhận được entry con, và mtime của thư mục bị ghi đè mỗi lần tạo
	// một file bên trong nó.
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].path > dirs[j].path })
	for _, p := range dirs {
		if err := chmodIfMeaningful(p.path, p.mode); err != nil {
			return st, err
		}
		if !p.mtime.IsZero() {
			_ = os.Chtimes(p.path, p.mtime, p.mtime)
		}
	}
	return st, nil
}

func (d *Driver) unpackEntry(root string, hdr *tar.Header, tr *tar.Reader, st *format.Stats, dirs *[]pending) ([]pending, error) {
	list := *dirs

	// Gốc phải được hỏi TRƯỚC: "." là tên hợp lệ duy nhất mà ValidateEntryPath
	// từ chối.
	if format.IsRootEntry(hdr.Name) {
		list = append(list, pending{path: root, mode: hdr.FileInfo().Mode().Perm(), mtime: hdr.ModTime})
		chown(root, hdr)
		st.Dirs++
		return list, nil
	}

	p, err := format.SafeJoin(root, hdr.Name)
	if err != nil {
		return list, err
	}
	if err := format.EnsureRealParents(root, hdr.Name); err != nil {
		return list, err
	}
	// Và đích cũng không được là một symlink có sẵn: một entry THƯ MỤC trùng tên
	// với symlink do entry trước tạo ra sẽ làm chmod/chtimes ở cuối đi xuyên qua
	// nó và đổi quyền của thứ nằm ngoài cây restore.
	if err := format.EnsureNotASymlink(p); err != nil {
		return list, err
	}
	if err := os.MkdirAll(filepath.Dir(p), dirPerm); err != nil {
		return list, err
	}

	switch hdr.Typeflag {
	case tar.TypeDir:
		if err := os.MkdirAll(p, dirPerm); err != nil {
			return list, err
		}
		chown(p, hdr)
		list = append(list, pending{path: p, mode: hdr.FileInfo().Mode().Perm(), mtime: hdr.ModTime})
		st.Dirs++

	case tar.TypeReg:
		if err := d.writeFile(p, hdr, tr); err != nil {
			return list, err
		}
		st.Files++
		st.Bytes += hdr.Size

	case tar.TypeSymlink:
		// Tên của chính symlink đã được kiểm; ĐÍCH của nó thì không, có chủ đích.
		// Một symlink tuyệt đối (/etc/localtime) là dữ liệu thật của app và phải
		// sống lại y nguyên. Nó vô hại vì Unpack không bao giờ ghi xuyên qua một
		// symlink — EnsureRealParents chặn ở entry kế tiếp.
		if err := os.Symlink(hdr.Linkname, p); err != nil {
			return list, err
		}
		// Lchown, không Chown: Chown đi xuyên symlink và đổi chủ của thứ nó trỏ
		// tới — có thể là một file ngoài cây restore.
		if isRoot() {
			_ = os.Lchown(p, hdr.Uid, hdr.Gid)
		}
		// mtime của symlink bị bỏ qua: os.Chtimes đi xuyên qua nó, và Go không có
		// lutimes portable. Mất mtime của một symlink không làm hỏng app nào.
		st.Symlinks++

	default:
		// Archive lạ có thể mang device/fifo/hardlink. Không dựng lại, nhưng phải
		// KỂ TÊN: một restore thiếu thứ gì đó mà không nói là một restore người
		// vận hành tưởng là đủ.
		st.Skipped = append(st.Skipped, format.Skip{Path: hdr.Name, Reason: format.SkipUnsupported})
	}
	return list, nil
}

// writeFile tạo file bằng O_EXCL.
//
// O_EXCL là phép chặn, không phải phép vệ sinh: nếu đường dẫn đã tồn tại — kể cả
// dưới dạng symlink do một entry TRƯỚC trong cùng archive tạo ra — thì open thất
// bại thay vì ghi xuyên qua nó. Cùng cửa lỗ với EnsureRealParents, chặn từ hướng
// khác.
func (d *Driver) writeFile(p string, hdr *tar.Header, tr *tar.Reader) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, tr)
	if err != nil {
		f.Close()
		return fmt.Errorf("%w: writing %s: %s", format.ErrBadArchive, hdr.Name, err)
	}
	if n != hdr.Size {
		f.Close()
		return fmt.Errorf("%w: %s declared %d bytes, archive had %d",
			format.ErrBadArchive, hdr.Name, hdr.Size, n)
	}
	if err := f.Close(); err != nil {
		return err
	}
	chown(p, hdr)
	if err := chmodIfMeaningful(p, hdr.FileInfo().Mode().Perm()); err != nil {
		return err
	}
	if !hdr.ModTime.IsZero() {
		_ = os.Chtimes(p, hdr.ModTime, hdr.ModTime)
	}
	return nil
}

// chown chỉ chạy khi tiến trình là root.
//
// keenrig-box restore CHẠY bằng root, và ở đó chown là bắt buộc: dữ liệu app
// thuộc về uid của container, và một cây restore toàn quyền root làm app khởi
// động lên rồi báo permission denied. Khi KHÔNG phải root (test, dev) thì chown
// luôn thất bại — gọi rồi bỏ qua lỗi sẽ che mất ca thật, nên hỏi trước.
func chown(p string, hdr *tar.Header) {
	if !isRoot() {
		return
	}
	_ = os.Lchown(p, hdr.Uid, hdr.Gid)
}

func isRoot() bool { return os.Geteuid() == 0 }

// chmodIfMeaningful bỏ qua ErrPermission và bỏ qua luôn trên hệ không có quyền
// POSIX. Test chạy trên Windows trong khi sản phẩm chạy trên Linux; làm đỏ ở
// Windows vì một thứ Windows không có là dạy người ta bỏ qua màu đỏ.
func chmodIfMeaningful(p string, mode fs.FileMode) error {
	if mode == 0 {
		return nil
	}
	err := os.Chmod(p, mode)
	if err == nil || errors.Is(err, fs.ErrPermission) || errors.Is(err, errors.ErrUnsupported) {
		return nil
	}
	return err
}
