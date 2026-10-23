// Package format — seam #6 `backup.Format`: ĐÓNG GÓI thế nào.
//
// # Ranh giới: "đóng gói thế nào" tách khỏi "lưu ở đâu"
//
// Format chỉ biết cây thư mục ↔ stream. Nó KHÔNG biết dir hay s3, không biết
// snapshot gồm những gì, không biết key đặt tên ra sao. Seam #5 `backup.Target`
// lo phần đó. Gộp hai thứ lại thì đổi từ tgz sang restic phải sửa mọi driver
// target — và ngược lại.
//
// # Vì sao Format CÓ mặc định còn Target thì KHÔNG
//
// `target` từ chối đoán: một target mặc định sai im lặng ghi bản sao lưu vào đĩa
// của chính máy sắp chết, và không có gì hỏng để nhìn thấy. Format thì ngược lại
// — chọn sai chỉ đổi cách nén, dữ liệu vẫn đủ, và tên format được GHI VÀO
// metadata của snapshot nên restore đọc nó từ đó chứ không từ môi trường. Một
// biến môi trường đổi sau khi đã có snapshot cũ KHÔNG được làm những bản cũ đọc
// không ra.
//
//	KEENRIG_BACKUP_FORMAT=tgz    không đặt = tgz
//
// # Ba quyết định trong interface
//
//	Pack nhận đường dẫn, không nhận fs.FS   Bản sao lưu phải giữ mode, mtime,
//	                                        symlink và chủ sở hữu. fs.FS không
//	                                        mang được symlink (nó đi xuyên qua),
//	                                        và restore một cây mất symlink là
//	                                        restore một cây khác.
//	Stream, không phải "repo"                Target chỉ biết key → bytes. Một
//	                                        driver kiểu restic sẽ phải tự dựng
//	                                        repo của nó ở tầng khác; xem "Nợ
//	                                        đã biết" dưới đây.
//	Trả Stats, không chỉ error               Bỏ qua một socket là ĐÚNG, nhưng bỏ
//	                                        qua im lặng thì người vận hành không
//	                                        bao giờ biết bản sao lưu thiếu gì.
//	                                        Mọi thứ không vào được archive phải
//	                                        có tên trong Stats.Skipped.
//
// # Luật an ninh nằm ở TẦNG NÀY, không ở driver
//
// Giải nén là nơi cổ điển của lỗi zip-slip: một entry tên `../../etc/cron.d/x`
// ghi ra ngoài cây, và keenrig-box chạy bằng root. Ba lớp chặn — [ValidateEntryPath],
// [SafeJoin], [EnsureRealParents] — viết MỘT lần ở đây vì mọi driver đều cần, và
// một driver thứ hai quên một lớp là một lỗ mới. Cùng lý lẽ với
// `target.ValidateKey`.
//
// # Nợ đã biết, ghi thẳng
//
// Hình dạng "một cây thư mục → một stream" hợp với tgz và với mọi thứ nén-rồi-đẩy.
// Nó KHÔNG hợp với restic/borg: chúng quản một repo có dedup xuyên snapshot, và
// ép chúng phát ra một stream là vứt bỏ đúng cái làm chúng đáng dùng. Khi tới lúc
// đó, seam này sẽ phải mọc thêm một hình dạng thứ hai (`PackTo(repo)`), chứ không
// phải bẻ cong tgz. Ghi ở đây để lần sau không ai tưởng đã tính rồi.
package format

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// EnvFormat — biến chọn format cho snapshot MỚI. Không đặt → [Default].
const EnvFormat = "KEENRIG_BACKUP_FORMAT"

// Default — format dùng khi không ai nói gì.
const Default = "tgz"

var (
	// ErrUnknownDriver — tên format không có trong registry.
	//
	// Đây là lỗi của restore một snapshot cũ nhiều hơn là lỗi cấu hình: metadata
	// nói "restic" mà binary này chỉ có "tgz". Thông báo phải kể tên những cái CÓ.
	ErrUnknownDriver = errors.New("format: no such driver")
	// ErrBadArchive — stream không phải archive hợp lệ, hoặc cụt.
	//
	// Một archive cụt PHẢI thành lỗi. Giải nén được nửa cây rồi báo thành công là
	// cách restore "xong" mà mất một nửa dữ liệu.
	ErrBadArchive = errors.New("format: corrupt or unreadable archive")
	// ErrUnsafePath — entry trong archive trỏ ra ngoài cây đích.
	//
	// Lỗi AN NINH, không phải lỗi định dạng: nó nghĩa là có người dựng archive để
	// ghi vào chỗ khác. Giữ riêng để lọc được trong log.
	ErrUnsafePath = errors.New("format: archive entry escapes the destination")
	// ErrNotEmpty — thư mục đích đã có dữ liệu.
	//
	// Giải nén đè lên một cây đang có là trộn hai snapshot thành một cây không
	// thuộc về bản nào. Xem [EnsureEmptyDir].
	ErrNotEmpty = errors.New("format: destination directory is not empty")
	// ErrNoSource — thư mục nguồn không tồn tại hoặc không phải thư mục.
	ErrNoSource = errors.New("format: source is not a directory")
)

// Lý do một entry không vào được archive. Mỗi lý do là một thứ CÓ THẬT trong
// thư mục dữ liệu app, không phải giả định.
const (
	// SkipSocket — unix socket. Postgres, php-fpm, mọi thứ nói chuyện cục bộ đều
	// để lại một cái trong thư mục dữ liệu. Nó không mang state; tiến trình tạo
	// lại lúc khởi động.
	SkipSocket = "unix socket"
	// SkipDevice — device node hoặc fifo. Không tái tạo được nếu không có
	// quyền, và không mang dữ liệu.
	SkipDevice = "device or named pipe"
	// SkipVanished — file biến mất giữa lúc đi bộ cây và lúc mở.
	//
	// Đây là ca THƯỜNG, không phải ngoại lệ: log xoay vòng, file tạm bị dọn. Làm
	// hỏng cả bản sao lưu vì một file tạm là làm sao lưu thành thứ không tin được.
	SkipVanished = "vanished during backup"
	// SkipUnsupported — kiểu entry driver không dựng lại được.
	SkipUnsupported = "unsupported entry type"
)

// Skip — một thứ KHÔNG vào được archive, kèm lý do.
type Skip struct {
	Path   string // tương đối so với gốc cây
	Reason string
}

func (s Skip) String() string { return s.Path + " (" + s.Reason + ")" }

// Stats — thứ đã đi qua, để caller đối chiếu và ghi vào metadata snapshot.
type Stats struct {
	Files    int64
	Dirs     int64
	Symlinks int64
	// Bytes — tổng nội dung file thường, TRƯỚC khi nén. Không phải kích thước
	// archive: caller đo cái đó ở tầng Target.
	Bytes   int64
	Skipped []Skip
}

// Format — hợp đồng driver. Hai method, không hơn.
type Format interface {
	// Name trả tên driver (khớp tên đã Register). Tên này được ghi vào metadata
	// snapshot; đổi nó là làm mọi snapshot cũ mở không được.
	Name() string

	// Pack đóng gói cây tại dir thành một stream ghi vào w.
	//
	// Phải giữ: nội dung, mode, mtime, symlink (nguyên văn, KHÔNG đi xuyên qua),
	// thư mục rỗng, và mode của CHÍNH dir. Cái cuối không thừa: `instance/` là
	// 0700 vì nó chứa master.key, và restore ra 0755 là lộ khoá mà không có gì
	// đỏ để nhìn.
	//
	// KHÔNG đóng w — caller mở nó thì caller đóng nó.
	Pack(ctx context.Context, dir string, w io.Writer) (Stats, error)

	// Unpack giải nén stream r về dir.
	//
	// dir phải chưa tồn tại hoặc là thư mục RỖNG → ErrNotEmpty. Ràng buộc này là
	// lớp phòng thủ cuối trước khi restore ghi đè dữ liệu đang sống.
	//
	// Entry trỏ ra ngoài dir → ErrUnsafePath, và những gì đã ghi được giữ nguyên
	// tại chỗ: dọn dở một cây restore là cách mất thêm dữ liệu. Caller quyết định
	// xoá hay không.
	Unpack(ctx context.Context, r io.Reader, dir string) (Stats, error)
}

// --- luật đường dẫn trong archive ------------------------------------------------

// MaxEntryPathLen — giới hạn thực dụng. Tên dài hơn là dấu hiệu archive dựng tay,
// không phải cây thư mục thật.
const MaxEntryPathLen = 4096

// ValidateEntryPath ép luật cho tên entry. Đây là RANH GIỚI AN NINH.
//
// Tên trong archive luôn dùng '/', kể cả archive tạo trên Windows — đó là quy ước
// của tar và ta ép nó ở cả hai chiều.
//
// Luật, mỗi dòng vì một cách hỏng cụ thể:
//
//	rỗng                    → ghi đè chính thư mục đích
//	bắt đầu bằng '/'        → đường dẫn tuyệt đối: `/etc/cron.d/x` chạy bằng root
//	có segment '..'         → zip-slip cổ điển
//	có segment '.'          → hai tên cho cùng một file; kiểm trùng lặp nói sai
//	có segment rỗng ('//')  → cùng lý do
//	có '\'                  → là dấu phân cách trên Windows, nơi test chạy
//	có byte NUL             → bị cắt cụt ở tầng syscall: tên ta ghi ≠ tên ta tạo
func ValidateEntryPath(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: empty entry name", ErrUnsafePath)
	case len(name) > MaxEntryPathLen:
		return fmt.Errorf("%w: %d bytes long, the maximum is %d", ErrUnsafePath, len(name), MaxEntryPathLen)
	case strings.HasPrefix(name, "/"):
		return fmt.Errorf("%w: %q is absolute", ErrUnsafePath, name)
	case strings.ContainsRune(name, '\\'):
		return fmt.Errorf("%w: %q contains '\\'", ErrUnsafePath, name)
	case strings.ContainsRune(name, 0):
		return fmt.Errorf("%w: %q contains a NUL byte", ErrUnsafePath, name)
	}
	for _, seg := range strings.Split(strings.TrimSuffix(name, "/"), "/") {
		switch seg {
		case "":
			return fmt.Errorf("%w: %q has an empty segment", ErrUnsafePath, name)
		case ".", "..":
			return fmt.Errorf("%w: %q has segment %q", ErrUnsafePath, name, seg)
		}
	}
	return nil
}

// IsRootEntry nhận biết entry mô tả CHÍNH thư mục gốc.
//
// tar viết gốc là "./" hoặc "."; ta chấp nhận cả hai vì archive có thể tới từ một
// công cụ khác. Nó là ca DUY NHẤT mà [ValidateEntryPath] từ chối nhưng vẫn hợp lệ,
// nên nó phải được hỏi TRƯỚC.
func IsRootEntry(name string) bool {
	return name == "." || name == "./" || name == "/"
}

// SafeJoin map tên entry → đường dẫn tuyệt đối dưới root, SAU khi đã kiểm.
//
// Kiểm rồi mới join, và join rồi kiểm lại bằng tiền tố. Lớp thứ hai là thứ bắt
// được nếu luật ở tầng trên bị nới ra sau này — cùng mô hình `driver/dir.path`.
func SafeJoin(root, name string) (string, error) {
	if err := ValidateEntryPath(name); err != nil {
		return "", err
	}
	clean := path.Clean(strings.TrimSuffix(name, "/"))
	p := filepath.Join(root, filepath.FromSlash(clean))
	if p != root && !strings.HasPrefix(p, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: %q", ErrUnsafePath, name)
	}
	return p, nil
}

// EnsureRealParents kiểm rằng mọi thành phần cha của name dưới root là thư mục
// THẬT, không phải symlink.
//
// Đây là lớp mà [SafeJoin] một mình KHÔNG có, và là lỗ thật sự khó thấy: archive
// chứa `data -> /etc` rồi ngay sau đó `data/cron.d/x`. Cả hai tên đều sạch với
// mọi phép kiểm chuỗi, nhưng entry thứ hai ghi vào /etc vì thành phần cha là một
// symlink ta VỪA TỰ TẠO. Chuỗi không cứu được ở đây — chỉ lstat cứu được.
//
// Chỉ đi trên phần dưới root, và không lstat chính root: root là thứ caller chọn,
// có thể nằm sau một symlink hợp lệ (/var → /private/var trên macOS).
func EnsureRealParents(root, name string) error {
	clean := path.Clean(strings.TrimSuffix(name, "/"))
	segs := strings.Split(clean, "/")
	cur := root
	for _, seg := range segs[:max(len(segs)-1, 0)] {
		cur = filepath.Join(cur, seg)
		fi, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			// Chưa tạo tới đó — hợp lệ, driver sẽ MkdirAll. Không có gì để lừa.
			return nil
		}
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("%w: %q traverses %q, which is not a real directory",
				ErrUnsafePath, name, seg)
		}
	}
	return nil
}

// EnsureNotASymlink từ chối một đường dẫn đích đã tồn tại DƯỚI DẠNG symlink.
//
// Lớp thứ ba, và nó bịt một lỗ mà hai lớp kia không thấy: archive chứa
// `kho -> /etc` rồi một entry THƯ MỤC cũng tên `kho`. [EnsureRealParents] không
// bắt vì `kho` không phải cha của chính nó, [SafeJoin] không bắt vì tên sạch, và
// `os.MkdirAll` cũng không kêu — nó thấy một thư mục (qua symlink) và trả về nil.
// Hậu quả không phải ghi nhầm file mà là `chmod`/`chtimes` đi xuyên qua symlink
// và đổi quyền của /etc.
//
// Ba lớp khác nhau vì ba thứ khác nhau: SafeJoin lo TÊN, EnsureRealParents lo
// ĐƯỜNG ĐI, hàm này lo ĐÍCH.
func EnsureNotASymlink(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil // chưa tồn tại là bình thường
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s already exists as a symlink", ErrUnsafePath, p)
	}
	return nil
}

// EnsureEmptyDir chuẩn bị dir cho một lần giải nén: tạo nếu chưa có, và từ chối
// nếu đã có bất cứ thứ gì bên trong.
//
// perm chỉ áp dụng khi PHẢI tạo mới. Thư mục đã có giữ nguyên quyền của nó, và
// nếu archive mang mode của gốc thì driver sẽ đặt lại ở cuối.
func EnsureEmptyDir(dir string, perm os.FileMode) error {
	fi, err := os.Lstat(dir)
	switch {
	case os.IsNotExist(err):
		return os.MkdirAll(dir, perm)
	case err != nil:
		return err
	case !fi.IsDir():
		return fmt.Errorf("%w: %s is not a directory", ErrNotEmpty, dir)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(ents) != 0 {
		return fmt.Errorf("%w: %s has %d entries", ErrNotEmpty, dir, len(ents))
	}
	return nil
}

// --- registry --------------------------------------------------------------------

// Factory dựng một Format. KHÔNG nhận ctx và KHÔNG nhận cấu hình: khác Target,
// ở đây không có credential để kiểm và không có dịch vụ để bắt tay. Thêm tham số
// "phòng xa" là thêm một chỗ mọi driver phải bỏ qua.
type Factory func() Format

var (
	mu       sync.RWMutex
	registry = map[string]Factory{}
)

// Register gắn driver vào registry. Panic khi trùng/rỗng — lỗi lập trình lúc
// dựng chương trình, phải nổ lúc khởi động.
func Register(name string, f Factory) {
	if name == "" {
		panic("format: Register called with an empty name")
	}
	if f == nil {
		panic("format: Register(" + name + ") with a nil factory")
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[name]; dup {
		panic("format: Register called twice for name " + name)
	}
	registry[name] = f
}

// Registered trả tên mọi driver đã biên dịch vào binary, đã sắp xếp.
func Registered() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Open dựng driver theo tên. Tên rỗng → [Default].
func Open(name string) (Format, error) {
	if strings.TrimSpace(name) == "" {
		name = Default
	}
	mu.RLock()
	f, ok := registry[strings.TrimSpace(name)]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %q (available: %s)", ErrUnknownDriver, name, strings.Join(Registered(), ", "))
	}
	return f(), nil
}

// OpenFromEnv chọn format cho snapshot MỚI.
//
// Restore KHÔNG được đi qua đây: nó phải mở đúng format ghi trong metadata của
// snapshot. Đổi biến môi trường mà làm snapshot cũ đọc không ra là biến một thay
// đổi cấu hình thành mất dữ liệu.
func OpenFromEnv(lookup func(string) (string, bool)) (Format, error) {
	name := ""
	if lookup != nil {
		if v, ok := lookup(EnvFormat); ok {
			name = strings.TrimSpace(v)
		}
	}
	return Open(name)
}
