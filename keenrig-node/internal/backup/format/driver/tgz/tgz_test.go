package tgz_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keenrig/keenrig/keenrig-node/internal/backup/format"
	"github.com/keenrig/keenrig/keenrig-node/internal/backup/format/driver/tgz"
	"github.com/keenrig/keenrig/keenrig-node/internal/backup/format/formattest"
)

func TestTgzConformance(t *testing.T) {
	formattest.RunConformance(t, func(t *testing.T) format.Format { return tgz.New() })
}

// --- archive dựng TAY ------------------------------------------------------------
//
// Những phép kiểm dưới đây không nằm trong bộ conformance vì chúng phải dựng một
// archive ĐỘC HẠI, và dựng tay là việc riêng của từng định dạng. Cùng cách
// `targettest` để phần "key không thoát ra ngoài thư mục" cho `driver/dir` tự kiểm.

type item struct {
	name string
	body string
	link string // khác rỗng → symlink
	dir  bool
}

func craft(t *testing.T, items ...item) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, it := range items {
		hdr := &tar.Header{Name: it.name, Mode: 0o644, Size: int64(len(it.body))}
		switch {
		case it.dir:
			hdr.Typeflag, hdr.Mode, hdr.Size = tar.TypeDir, 0o755, 0
		case it.link != "":
			hdr.Typeflag, hdr.Linkname, hdr.Size = tar.TypeSymlink, it.link, 0
		default:
			hdr.Typeflag = tar.TypeReg
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(it.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Entry trỏ ra ngoài cây đích bị TỪ CHỐI, và không ghi được gì ra ngoài.
//
// keenrig-box restore chạy bằng root. Một entry `../../etc/cron.d/x` là thực thi
// mã tuỳ ý, không phải một file đặt sai chỗ. Archive tới từ Target — và Target có
// thể là một bucket S3 mà credential đã rò rỉ.
func TestEntryCannotEscapeDestination(t *testing.T) {
	for _, name := range []string{
		"../thoat.txt",
		"a/../../thoat.txt",
		"/etc/cron.d/thoat",
		"a/b/../../../thoat.txt",
	} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			dst := filepath.Join(parent, "restore")
			before, _ := os.ReadDir(parent)

			_, err := tgz.New().Unpack(t.Context(), bytes.NewReader(craft(t, item{name: name, body: "doc"})), dst)
			if !errors.Is(err, format.ErrUnsafePath) {
				t.Errorf("Unpack(%q) = %v, muốn ErrUnsafePath", name, err)
			}
			after, _ := os.ReadDir(parent)
			if len(after) != len(before)+1 { // +1 = chính thư mục đích
				t.Errorf("thư mục cha đổi từ %d thành %d entry — entry đã thoát ra ngoài",
					len(before), len(after))
			}
		})
	}
}

// Symlink làm THÀNH PHẦN CHA là lỗ mà mọi phép kiểm chuỗi bỏ sót.
//
// Archive chứa `kho -> <ngoài cây>` rồi ngay sau đó `kho/thoat.txt`. Cả hai tên
// đều sạch: không có `..`, không tuyệt đối, join xong vẫn nằm dưới thư mục đích.
// Nhưng entry thứ hai ghi ra ngoài, vì cha của nó là một symlink ta VỪA TỰ TẠO ở
// entry thứ nhất. Chỉ lstat bắt được, không phép kiểm chuỗi nào bắt được.
func TestSymlinkParentCannotBeTraversed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cần quyền riêng để tạo symlink")
	}
	outside := t.TempDir()
	dst := filepath.Join(t.TempDir(), "restore")

	arc := craft(t,
		item{name: "kho", link: outside},
		item{name: "kho/thoat.txt", body: "ghi xuyen qua symlink"},
	)
	_, err := tgz.New().Unpack(t.Context(), bytes.NewReader(arc), dst)
	if !errors.Is(err, format.ErrUnsafePath) {
		t.Errorf("= %v, muốn ErrUnsafePath", err)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Errorf("đã ghi %d entry ra ngoài cây đích qua symlink cha", len(ents))
	}
}

// Ghi ĐÈ lên một symlink đã tạo cũng không được đi xuyên qua nó.
//
// Biến thể của ca trên, chặn bằng cửa khác: O_EXCL. Archive chứa
// `bi-mat -> <file ngoài cây>` rồi `bi-mat` lần nữa dưới dạng file thường.
func TestWriteDoesNotFollowExistingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cần quyền riêng để tạo symlink")
	}
	outside := filepath.Join(t.TempDir(), "quan-trong.txt")
	if err := os.WriteFile(outside, []byte("noi dung goc"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "restore")

	arc := craft(t,
		item{name: "bi-mat", link: outside},
		item{name: "bi-mat", body: "GHI DE"},
	)
	if _, err := tgz.New().Unpack(t.Context(), bytes.NewReader(arc), dst); err == nil {
		t.Error("ghi đè lên một symlink lại thành công")
	}
	b, err := os.ReadFile(outside)
	if err != nil || string(b) != "noi dung goc" {
		t.Errorf("file ngoài cây bị ghi đè: %q, %v", b, err)
	}
}

// Entry THƯ MỤC trùng tên với một symlink vừa tạo không được đổi quyền của thứ
// nằm ngoài cây.
//
// Ca này lọt qua cả hai lớp kia và chỉ lộ ra khi đọc lại code: `EnsureRealParents`
// không kiểm vì `kho` không phải cha của chính nó, `SafeJoin` không kiểm vì tên
// sạch, và `os.MkdirAll` trả nil vì nó THẤY một thư mục — qua symlink. Thiệt hại
// không phải một file đặt sai chỗ mà là `chmod 0755` lên thư mục bên ngoài, ở
// cuối lần giải nén, khi mọi thứ trông như đã xong.
func TestDirEntryCannotChmodThroughSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cần quyền riêng để tạo symlink")
	}
	outside := t.TempDir()
	if err := os.Chmod(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "restore")

	arc := craft(t,
		item{name: "kho", link: outside},
		item{name: "kho/", dir: true}, // mode 0755 trong craft
	)
	if _, err := tgz.New().Unpack(t.Context(), bytes.NewReader(arc), dst); !errors.Is(err, format.ErrUnsafePath) {
		t.Errorf("= %v, muốn ErrUnsafePath", err)
	}
	fi, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Errorf("quyền của thư mục NGOÀI cây đổi thành %04o — chmod đã đi xuyên qua symlink", got)
	}
}

// Entry tên "." mô tả chính thư mục gốc — hợp lệ, và là ca DUY NHẤT mà
// ValidateEntryPath từ chối nhưng vẫn phải đi qua.
func TestRootEntryIsAccepted(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "restore")
	arc := craft(t,
		item{name: "./", dir: true},
		item{name: "a.txt", body: "x"},
	)
	st, err := tgz.New().Unpack(t.Context(), bytes.NewReader(arc), dst)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if st.Dirs != 1 || st.Files != 1 {
		t.Errorf("Stats = %+v, muốn 1 thư mục 1 file", st)
	}
}

// Kiểu entry không dựng lại được thì BỎ QUA CÓ TÊN, không làm hỏng cả lần restore.
func TestUnsupportedEntryTypeIsNamed(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, hdr := range []*tar.Header{
		{Name: "fifo", Typeflag: tar.TypeFifo, Mode: 0o600},
		{Name: "thuc.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2},
	} {
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte("ok")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "restore")
	st, err := tgz.New().Unpack(t.Context(), bytes.NewReader(buf.Bytes()), dst)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if len(st.Skipped) != 1 || st.Skipped[0].Path != "fifo" {
		t.Errorf("Skipped = %v, muốn đúng một entry \"fifo\"", st.Skipped)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "thuc.txt")); err != nil || string(b) != "ok" {
		t.Errorf("entry sau fifo không tới nơi: %q, %v", b, err)
	}
}

// Cùng một cây → cùng một chuỗi byte.
//
// gzip mặc định nhét thời gian đóng gói vào header, và điều đó làm hai lần chạy
// ra hai archive khác nhau dù dữ liệu y hệt. Mất tính tất định là mất cách trả
// lời "bản đêm nay có khác bản đêm qua không" bằng một phép so băm — tức là phải
// tải về và giải nén cả gigabyte để biết.
func TestOutputIsDeterministic(t *testing.T) {
	src := t.TempDir()
	for _, n := range []string{"a.txt", "b.txt"} {
		if err := os.WriteFile(filepath.Join(src, n), []byte("noi dung "+n), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var one, two bytes.Buffer
	f := tgz.New()
	if _, err := f.Pack(t.Context(), src, &one); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Pack(t.Context(), src, &two); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one.Bytes(), two.Bytes()) {
		t.Errorf("hai lần đóng gói cùng một cây ra %d và %d byte khác nhau",
			one.Len(), two.Len())
	}
}

// --- registry --------------------------------------------------------------------

// Không đặt biến → tgz. Khác Target, ở đây mặc định là AN TOÀN: chọn sai format
// chỉ đổi cách nén, còn chọn sai target thì ghi bản sao lưu vào đĩa của chính máy
// sắp chết.
func TestDefaultFormatIsTgz(t *testing.T) {
	f, err := format.OpenFromEnv(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("OpenFromEnv: %v", err)
	}
	if f.Name() != tgz.Name {
		t.Errorf("mặc định = %q, muốn %q", f.Name(), tgz.Name)
	}
}

func TestOpenFromEnv(t *testing.T) {
	f, err := format.OpenFromEnv(func(k string) (string, bool) {
		if k == format.EnvFormat {
			return " tgz ", true // khoảng trắng thừa từ file cấu hình là chuyện thường
		}
		return "", false
	})
	if err != nil {
		t.Fatalf("OpenFromEnv: %v", err)
	}
	if f.Name() != tgz.Name {
		t.Errorf("Name = %q", f.Name())
	}
}

// Tên lạ → ErrUnknownDriver, và thông báo phải KỂ TÊN những cái có.
//
// Ca thật của lỗi này không phải gõ sai biến môi trường mà là restore một snapshot
// cũ: metadata nói "restic" trong khi binary này chỉ có "tgz".
func TestUnknownFormat(t *testing.T) {
	_, err := format.Open("restic")
	if !errors.Is(err, format.ErrUnknownDriver) {
		t.Fatalf("= %v, muốn ErrUnknownDriver", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte(tgz.Name)) {
		t.Errorf("thông báo %q không kể tên format nào đang có", err)
	}
}

func TestRegistered(t *testing.T) {
	found := false
	for _, n := range format.Registered() {
		if n == tgz.Name {
			found = true
		}
	}
	if !found {
		t.Errorf("Registered() = %v, thiếu %q", format.Registered(), tgz.Name)
	}
}
