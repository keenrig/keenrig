// Package target — seam #5 `backup.Target`: NƠI đặt bytes của bản sao lưu.
//
// # Ranh giới: "lưu ở đâu" tách khỏi "đóng gói thế nào"
//
// Target chỉ biết key → bytes. Nó KHÔNG biết snapshot là gì, không biết tgz hay
// restic, không biết cái gì thuộc app nào. Seam #6 `backup.Format` lo phần đó.
// Gộp hai thứ lại thì thêm một target (SFTP, Backblaze) phải viết lại toàn bộ
// phần nén/dedup — và ngược lại, đổi từ tgz sang restic phải sửa mọi driver.
//
// # Bốn quyết định trong interface, mỗi cái vì một lý do đo được
//
//	Put nhận io.Reader + size    Snapshot của một instance là gigabyte. Nhận
//	                             []byte nghĩa là giữ cả bản sao lưu trong RAM
//	                             trên một VPS 2 vCPU. Nhưng size là BẮT BUỘC:
//	                             không có Content-Length thì Go dùng chunked
//	                             transfer-encoding, và S3 THẬT từ chối
//	                             (MissingContentLength). Caller luôn biết size
//	                             vì nguồn luôn là một file trên đĩa.
//	Không có Stat                List với prefix chính xác đã trả về Size và
//	                             ModTime. Một method nữa là một method nữa mà
//	                             mọi driver phải hiện thực đúng.
//	Delete IDEMPOTENT            Retention chạy lặp lại; "not found" ở lần
//	                             thứ hai không phải lỗi. Trả lỗi ở đó buộc
//	                             caller phải phân biệt hai loại thất bại mà nó
//	                             không quan tâm.
//	Get phân biệt ErrNotFound    Restore cần tách "chưa có bản sao lưu nào" khỏi
//	                             "mạng hỏng". Cái đầu là trạng thái BÌNH THƯỜNG
//	                             trên một instance mới.
//
// # Retention KHÔNG phải method của Target
//
// Nó là chính sách trên `List` + `Delete`, nên nó nằm ở `retention.go`, viết một
// lần, và conformance chạy nó trên MỌI target. Cho mỗi driver tự hiện thực
// retention là ba bản sao của cùng một logic xoá dữ liệu — nơi cuối cùng ta muốn
// có ba bản sao.
package target

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// Chọn nơi sao lưu bằng ĐÚNG HAI biến, cùng mô hình với KEENRIG_PROXY:
//
//	KEENRIG_BACKUP_TARGET=dir|s3     không đặt = KHÔNG có sao lưu
//	KEENRIG_BACKUP_CONFIG=<dsn>      ngữ nghĩa do driver quy định
//
// Không có giá trị mặc định, và đó là điểm khác proxy: một gateway mặc định sai
// thì thấy ngay (site không lên), còn một target mặc định sai thì im lặng ghi
// bản sao lưu vào đĩa cục bộ của chính máy sắp chết. Sao lưu nằm cùng chỗ với
// dữ liệu gốc không phải sao lưu.
const (
	EnvDriver = "KEENRIG_BACKUP_TARGET"
	EnvConfig = "KEENRIG_BACKUP_CONFIG"
)

var (
	// ErrUnknownDriver — tên driver không có trong registry.
	ErrUnknownDriver = errors.New("target: no such driver")
	// ErrBadConfig — DSN sai cú pháp. Driver PHẢI kiểm lúc mở: một target sai
	// cấu hình chỉ lộ ra lúc cần restore, tức là lúc muộn nhất có thể.
	ErrBadConfig = errors.New("target: invalid driver configuration")
	// ErrNotFound — key không tồn tại.
	ErrNotFound = errors.New("target: no such object")
	// ErrBadKey — key vi phạm luật đặt tên (xem ValidateKey).
	ErrBadKey = errors.New("target: invalid key")
	// ErrNotConfigured — chưa cấu hình target nào.
	//
	// Lỗi RIÊNG, không dùng ErrUnknownDriver: "chưa bật sao lưu" là một trạng
	// thái hợp lệ của instance, còn "gõ sai tên driver" là một lỗi cấu hình. Hai
	// thứ đó dẫn tới hai hành động khác nhau của người vận hành.
	ErrNotConfigured = errors.New("target: no backup destination configured")
)

// Object — một entry trong target.
type Object struct {
	Key     string
	Size    int64
	ModTime time.Time
}

// Target — hợp đồng driver. Bốn method, không hơn.
type Target interface {
	// Name trả tên driver (khớp tên đã Register).
	Name() string
	// Put ghi size byte từ r vào key. Ghi đè nếu key đã có.
	//
	// PHẢI NGUYÊN KHỐI theo nghĩa người đọc thấy được: một lần Put bị ngắt giữa
	// đường KHÔNG được để lại một object cụt mà List vẫn kể tên. Đó là cách một
	// bản sao lưu hỏng đi qua mọi lần kiểm tra cho tới lúc restore.
	Put(ctx context.Context, key string, r io.Reader, size int64) error
	// Get mở object để đọc. Caller PHẢI Close. Không có → ErrNotFound.
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	// List liệt kê object có key bắt đầu bằng prefix, SẮP XẾP theo key.
	//
	// Thứ tự ổn định là một phần hợp đồng: retention chọn bản để xoá, và một thứ
	// tự đổi giữa hai lần gọi làm nó xoá bản khác nhau mỗi lần.
	List(ctx context.Context, prefix string) ([]Object, error)
	// Delete xoá key. IDEMPOTENT — không có cũng trả nil.
	Delete(ctx context.Context, key string) error
}

// --- luật đặt key --------------------------------------------------------------

// MaxKeyLen — giới hạn của S3 là 1024 byte. Lấy thấp hơn để key còn chỗ cho tiền
// tố mà driver tự thêm.
const MaxKeyLen = 900

// ValidateKey ép luật đặt tên key. Đây là RANH GIỚI AN NINH, không phải kiểm tra
// hình thức.
//
// Driver `dir` map key thành đường dẫn dưới thư mục sao lưu. Một key `../../etc/x`
// ghi ra ngoài thư mục đó — cùng loại lỗ mà `paths.AppData` chặn bằng cách từ
// chối `..`. Kiểm ở TẦNG NÀY chứ không trong driver: mọi driver đều cần luật này,
// và một driver thứ tư quên kiểm là một lỗ mới.
//
// Luật, mỗi dòng vì một cách hỏng cụ thể:
//
//	rỗng                    → dir sẽ ghi vào chính thư mục sao lưu
//	bắt đầu bằng '/'        → đường dẫn tuyệt đối, thoát khỏi thư mục
//	có segment '..'         → thoát khỏi thư mục
//	có segment rỗng ('//')  → dir và s3 hiểu khác nhau, cùng key ra hai object
//	có '\'                  → là ký tự phân cách đường dẫn trên Windows
//	có byte NUL             → bị cắt cụt ở tầng syscall, key ta ghi ≠ key ta đọc
//	có ký tự điều khiển     → không in ra được, làm log và UI nói sai sự thật
func ValidateKey(key string) error {
	switch {
	case key == "":
		return fmt.Errorf("%w: empty", ErrBadKey)
	case len(key) > MaxKeyLen:
		return fmt.Errorf("%w: %d bytes long, the maximum is %d", ErrBadKey, len(key), MaxKeyLen)
	case strings.HasPrefix(key, "/"):
		return fmt.Errorf("%w: %q starts with '/'", ErrBadKey, key)
	case strings.HasSuffix(key, "/"):
		return fmt.Errorf("%w: %q ends with '/' — that is a prefix, not an object", ErrBadKey, key)
	case strings.ContainsRune(key, '\\'):
		return fmt.Errorf("%w: %q contains '\\'", ErrBadKey, key)
	}
	for _, r := range key {
		if r == 0 || r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %q contains a control character", ErrBadKey, key)
		}
	}
	for _, seg := range strings.Split(key, "/") {
		switch seg {
		case "":
			return fmt.Errorf("%w: %q has an empty segment", ErrBadKey, key)
		case ".", "..":
			return fmt.Errorf("%w: %q has segment %q", ErrBadKey, key, seg)
		}
	}
	return nil
}

// ValidatePrefix — prefix lỏng hơn key: nó ĐƯỢC kết thúc bằng '/' và ĐƯỢC rỗng
// (nghĩa là liệt kê tất cả). Nhưng nó vẫn không được thoát khỏi thư mục.
func ValidatePrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	if strings.HasPrefix(prefix, "/") || strings.ContainsRune(prefix, '\\') {
		return fmt.Errorf("%w: prefix %q", ErrBadKey, prefix)
	}
	for _, seg := range strings.Split(strings.TrimSuffix(prefix, "/"), "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("%w: prefix %q has segment %q", ErrBadKey, prefix, seg)
		}
	}
	return nil
}

// --- registry ------------------------------------------------------------------

// Config — thứ mọi driver nhận khi mở. Cùng mô hình proxy.Config: core KHÔNG
// phân tích DSN, mỗi driver tự định nghĩa cú pháp và tự kiểm.
type Config struct {
	DSN string
}

// Factory dựng một Target. Nhận ctx vì driver có thể phải bắt tay với dịch vụ
// lưu trữ ngay lúc mở — và nó PHẢI làm thế: một credential sai chỉ lộ ra lúc
// restore thì đã quá muộn.
type Factory func(ctx context.Context, cfg Config) (Target, error)

var (
	mu       sync.RWMutex
	registry = map[string]Factory{}
)

// Register gắn driver vào registry. Panic khi trùng/rỗng — lỗi lập trình lúc
// dựng chương trình, phải nổ lúc khởi động.
func Register(name string, f Factory) {
	if name == "" {
		panic("target: Register called with an empty name")
	}
	if f == nil {
		panic("target: Register(" + name + ") with a nil factory")
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[name]; dup {
		panic("target: Register called twice for name " + name)
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

// Open dựng driver theo tên. Tên rỗng → ErrNotConfigured (KHÔNG có mặc định).
func Open(ctx context.Context, name string, cfg Config) (Target, error) {
	if strings.TrimSpace(name) == "" {
		return nil, ErrNotConfigured
	}
	mu.RLock()
	f, ok := registry[name]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %q (available: %s)", ErrUnknownDriver, name, strings.Join(Registered(), ", "))
	}
	return f(ctx, cfg)
}

// OpenFromEnv đọc cả hai biến rồi mở driver.
//
// Không đặt KEENRIG_BACKUP_TARGET → ErrNotConfigured. Caller PHẢI xử lý riêng
// lỗi đó: box vẫn phải chạy được khi chưa cấu hình sao lưu, nhưng nó phải KÊU TO
// — một instance không có sao lưu là một instance một lần hỏng là mất hết.
func OpenFromEnv(ctx context.Context, lookup func(string) (string, bool)) (Target, error) {
	return Open(ctx, env(lookup, EnvDriver), Config{DSN: env(lookup, EnvConfig)})
}

func env(lookup func(string) (string, bool), key string) string {
	if lookup == nil {
		return ""
	}
	v, ok := lookup(key)
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}
