// Package formattest — bộ conformance cho `format.Format`.
//
// Mọi driver chạy CÙNG bộ này. Nếu một driver cần suite phải sửa để pass thì suite
// đang sai, không phải driver — đúng nguyên tắc đã dùng cho `storetest`,
// `runtimetest`, `addontest` và `targettest`.
//
// # Khẳng định được phát biểu ở tầng nào
//
// Suite này KHÔNG biết tar, gzip hay restic. Nó chỉ nói một câu: cây thư mục đi
// vào phải bằng cây thư mục đi ra. Nó không bao giờ nói "byte thứ 257 phải là
// 'ustar'" — điều đó đúng cho tgz và vô nghĩa với mọi format khác.
//
// Hệ quả: những phép kiểm cần DỰNG TAY một archive độc hại (entry `../../etc/x`,
// symlink cha) KHÔNG nằm ở đây, vì dựng tay là việc riêng của mỗi định dạng.
// Chúng nằm trong test của từng driver — cùng cách `targettest` để phần "key
// không thoát ra ngoài thư mục" cho `driver/dir` tự kiểm.
package formattest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/backup/format"
)

// Opener dựng một Format sạch cho mỗi subtest.
type Opener func(t *testing.T) format.Format

// RunConformance chạy toàn bộ suite.
func RunConformance(t *testing.T, open Opener) {
	t.Run("RoundTripPreservesTree", func(t *testing.T) { testRoundTrip(t, open(t)) })
	t.Run("EmptyDirsSurvive", func(t *testing.T) { testEmptyDirs(t, open(t)) })
	t.Run("EmptyTreeRoundTrips", func(t *testing.T) { testEmptyTree(t, open(t)) })
	t.Run("PreservesFileModes", func(t *testing.T) { testModes(t, open(t)) })
	t.Run("PreservesRootDirMode", func(t *testing.T) { testRootMode(t, open(t)) })
	t.Run("PreservesSymlinks", func(t *testing.T) { testSymlinks(t, open(t)) })
	t.Run("PreservesOwnershipAsRoot", func(t *testing.T) { testOwnership(t, open(t)) })
	t.Run("PreservesMTime", func(t *testing.T) { testMTime(t, open(t)) })
	t.Run("LargeFileIntegrity", func(t *testing.T) { testLargeFile(t, open(t)) })
	t.Run("AwkwardNames", func(t *testing.T) { testAwkwardNames(t, open(t)) })
	t.Run("UnpackRefusesNonEmptyDest", func(t *testing.T) { testRefusesNonEmpty(t, open(t)) })
	t.Run("UnpackCreatesMissingDest", func(t *testing.T) { testCreatesDest(t, open(t)) })
	t.Run("TruncatedArchiveIsError", func(t *testing.T) { testTruncated(t, open(t)) })
	t.Run("GarbageStreamIsError", func(t *testing.T) { testGarbage(t, open(t)) })
	t.Run("PackRefusesMissingSource", func(t *testing.T) { testMissingSource(t, open(t)) })
	t.Run("SocketIsSkippedWithReason", func(t *testing.T) { testSocketSkipped(t, open(t)) })
	t.Run("CancelledContextStopsPack", func(t *testing.T) { testCancel(t, open(t)) })
	t.Run("StatsDescribeTheTree", func(t *testing.T) { testStats(t, open(t)) })
}

// --- helper --------------------------------------------------------------------

// entry — một node trong cây mẫu. Kiểu suy ra từ trường nào được đặt.
type entry struct {
	path string // tương đối, luôn dùng '/'
	body string // file thường
	dir  bool
	link string // đích symlink
	mode fs.FileMode
}

func build(t *testing.T, root string, entries []entry) {
	t.Helper()
	for _, e := range entries {
		p := filepath.Join(root, filepath.FromSlash(e.path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		switch {
		case e.dir:
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
		case e.link != "":
			if err := os.Symlink(filepath.FromSlash(e.link), p); err != nil {
				t.Fatalf("symlink %s: %v", e.path, err)
			}
			continue // không chmod: mode của symlink không có nghĩa
		default:
			if err := os.WriteFile(p, []byte(e.body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if e.mode != 0 {
			if err := os.Chmod(p, e.mode); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// snap — ảnh chụp một cây để so sánh. Chỉ giữ thứ nói được ở tầng seam.
type snap struct {
	kind string // "dir" | "file" | "link"
	body string
	link string
	mode fs.FileMode
	mtim time.Time
}

func scan(t *testing.T, root string) map[string]snap {
	t.Helper()
	out := map[string]snap{}
	err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		info, err := e.Info()
		if err != nil {
			return err
		}
		s := snap{mode: info.Mode().Perm(), mtim: info.ModTime()}
		switch {
		case info.IsDir():
			s.kind = "dir"
		case info.Mode()&fs.ModeSymlink != 0:
			s.kind = "link"
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			s.link = filepath.ToSlash(target)
		default:
			s.kind = "file"
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			s.body = string(b)
		}
		out[rel] = s
		return nil
	})
	if err != nil {
		t.Fatalf("quét cây %s: %v", root, err)
	}
	return out
}

// roundTrip đóng gói src rồi giải nén ra một thư mục mới, trả đường dẫn đích.
func roundTrip(t *testing.T, f format.Format, src string) (string, format.Stats, format.Stats) {
	t.Helper()
	var buf bytes.Buffer
	packed, err := f.Pack(t.Context(), src, &buf)
	if err != nil {
		t.Fatalf("Pack(%s): %v", src, err)
	}
	dst := filepath.Join(t.TempDir(), "restore")
	unpacked, err := f.Unpack(t.Context(), bytes.NewReader(buf.Bytes()), dst)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	return dst, packed, unpacked
}

func keysOf(m map[string]snap) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func skipWithoutPosixPerms(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows không map quyền POSIX — khẳng định về mode phải chạy trên Linux (CI)")
	}
}

// --- test ----------------------------------------------------------------------

// Cây đi vào phải BẰNG cây đi ra: cùng tập tên, cùng kiểu, cùng nội dung.
func testRoundTrip(t *testing.T, f format.Format) {
	src := t.TempDir()
	build(t, src, []entry{
		{path: "instance/platform.db", body: "SQLite format 3\x00du lieu nhi phan\xff\xfe"},
		{path: "instance/master.key", body: "khoa-32-byte-gia-lap-0123456789ab"},
		{path: "apps/app-1/data/index.html", body: "<h1>xin chao</h1>"},
		{path: "apps/app-1/data/rong.txt", body: ""},
		{path: "apps/app-2/config.json", body: `{"a":1}`},
	})

	dst, _, _ := roundTrip(t, f, src)

	before, after := scan(t, src), scan(t, dst)
	if got, want := strings.Join(keysOf(after), ","), strings.Join(keysOf(before), ","); got != want {
		t.Fatalf("tập entry khác:\n có: %s\nmuốn: %s", got, want)
	}
	for k, b := range before {
		a := after[k]
		if a.kind != b.kind {
			t.Errorf("%s: kiểu = %s, muốn %s", k, a.kind, b.kind)
		}
		if a.body != b.body {
			t.Errorf("%s: nội dung đọc lại khác (%d vs %d byte)", k, len(a.body), len(b.body))
		}
	}
}

// Thư mục RỖNG phải sống sót.
//
// Nhiều app coi sự tồn tại của một thư mục là một phần cấu hình: thiếu
// `data/uploads/` thì app không tạo lại mà báo lỗi lúc người dùng tải file lên —
// tức là nhiều ngày sau khi restore được tuyên bố thành công.
func testEmptyDirs(t *testing.T, f format.Format) {
	src := t.TempDir()
	build(t, src, []entry{
		{path: "apps/app-1/data/uploads", dir: true},
		{path: "apps/app-1/data/cache/tmp", dir: true},
		{path: "apps/app-1/README", body: "x"},
	})

	dst, _, _ := roundTrip(t, f, src)

	for _, d := range []string{"apps/app-1/data/uploads", "apps/app-1/data/cache/tmp"} {
		fi, err := os.Stat(filepath.Join(dst, filepath.FromSlash(d)))
		if err != nil {
			t.Errorf("thư mục rỗng %s biến mất: %v", d, err)
			continue
		}
		if !fi.IsDir() {
			t.Errorf("%s không còn là thư mục", d)
		}
	}
}

// Cây rỗng phải cho ra một archive HỢP LỆ, không phải 0 byte.
//
// Ca này có thật: một instance vừa cài xong, chưa có app nào. Nếu format trả về
// stream rỗng thì target ghi một object 0 byte và lần restore sau báo hỏng — một
// lỗi giả ở đúng lúc người vận hành đang lo lắng nhất.
func testEmptyTree(t *testing.T, f format.Format) {
	src := t.TempDir()
	var buf bytes.Buffer
	if _, err := f.Pack(t.Context(), src, &buf); err != nil {
		t.Fatalf("Pack cây rỗng: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("archive của cây rỗng dài 0 byte — không phân biệt được với lỗi ghi")
	}
	dst := filepath.Join(t.TempDir(), "restore")
	if _, err := f.Unpack(t.Context(), bytes.NewReader(buf.Bytes()), dst); err != nil {
		t.Fatalf("Unpack cây rỗng: %v", err)
	}
	ents, err := os.ReadDir(dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Errorf("cây rỗng giải nén ra %d entry", len(ents))
	}
}

// Mode của file phải sống sót.
//
// `master.key` là 0600. Restore ra 0644 là lộ khoá chủ của cả instance cho mọi
// user trên máy — và không có gì đỏ, không có gì trong log, không có gì hỏng cho
// tới ngày có người đọc nó.
func testModes(t *testing.T, f format.Format) {
	skipWithoutPosixPerms(t)
	src := t.TempDir()
	build(t, src, []entry{
		{path: "instance/master.key", body: "k", mode: 0o600},
		{path: "instance", dir: true, mode: 0o700},
		{path: "bin/start.sh", body: "#!/bin/sh\n", mode: 0o755},
		{path: "apps/data/public.txt", body: "x", mode: 0o644},
	})

	dst, _, _ := roundTrip(t, f, src)

	for _, want := range []struct {
		path string
		mode fs.FileMode
	}{
		{"instance/master.key", 0o600},
		{"instance", 0o700},
		{"bin/start.sh", 0o755},
		{"apps/data/public.txt", 0o644},
	} {
		fi, err := os.Lstat(filepath.Join(dst, filepath.FromSlash(want.path)))
		if err != nil {
			t.Errorf("%s: %v", want.path, err)
			continue
		}
		if got := fi.Mode().Perm(); got != want.mode {
			t.Errorf("%s: mode = %04o, muốn %04o", want.path, got, want.mode)
		}
	}
}

// Mode của CHÍNH thư mục gốc phải sống sót.
//
// Tách khỏi test trên vì nó là ca dễ rơi nhất: gốc không phải "một entry trong
// cây", nên một hiện thực đi bộ từ trong ra sẽ không bao giờ ghi nó. Snapshot của
// `instance/` (0700) restore ra một thư mục 0755 là lộ toàn bộ nội dung bên trong.
func testRootMode(t *testing.T, f format.Format) {
	skipWithoutPosixPerms(t)
	src := t.TempDir()
	build(t, src, []entry{{path: "master.key", body: "k", mode: 0o600}})
	if err := os.Chmod(src, 0o700); err != nil {
		t.Fatal(err)
	}

	dst, _, _ := roundTrip(t, f, src)

	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Errorf("mode của thư mục gốc = %04o, muốn 0700", got)
	}
}

// Symlink phải sống lại LÀ symlink, với đúng đích.
//
// Đi xuyên qua nó lúc đóng gói làm hai việc sai cùng lúc: nhân đôi dữ liệu, và
// biến một liên kết thành một bản sao đông cứng — app ghi vào một bên, đọc ở bên
// kia, và dữ liệu tách đôi im lặng.
func testSymlinks(t *testing.T, f format.Format) {
	src := t.TempDir()
	if err := os.Symlink("that.txt", filepath.Join(src, "probe")); err != nil {
		t.Skipf("hệ này không tạo được symlink (%v) — trên Windows cần quyền riêng", err)
	}
	if err := os.Remove(filepath.Join(src, "probe")); err != nil {
		t.Fatal(err)
	}

	build(t, src, []entry{
		{path: "that.txt", body: "noi dung that"},
		{path: "kho", dir: true},
		{path: "lien-ket-file", link: "that.txt"},
		{path: "lien-ket-thu-muc", link: "kho"},
		{path: "sau/lien-ket-len", link: "../that.txt"},
		// Symlink TUYỆT ĐỐI: dữ liệu thật của app (vd /etc/localtime). Phải sống
		// lại nguyên văn — an toàn nằm ở chỗ Unpack không ghi XUYÊN qua symlink,
		// không phải ở chỗ từ chối lưu nó.
		{path: "lien-ket-tuyet-doi", link: "/etc/localtime"},
	})

	dst, _, _ := roundTrip(t, f, src)

	for _, c := range []struct{ path, want string }{
		{"lien-ket-file", "that.txt"},
		{"lien-ket-thu-muc", "kho"},
		{"sau/lien-ket-len", "../that.txt"},
		{"lien-ket-tuyet-doi", "/etc/localtime"},
	} {
		p := filepath.Join(dst, filepath.FromSlash(c.path))
		fi, err := os.Lstat(p)
		if err != nil {
			t.Errorf("%s: %v", c.path, err)
			continue
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			t.Errorf("%s: đã thành file thường — symlink bị đi xuyên qua lúc đóng gói", c.path)
			continue
		}
		got, err := os.Readlink(p)
		if err != nil {
			t.Errorf("Readlink %s: %v", c.path, err)
			continue
		}
		if filepath.ToSlash(got) != c.want {
			t.Errorf("%s → %q, muốn %q", c.path, got, c.want)
		}
	}
}

// uid/gid phải sống sót.
//
// Chạy được KHI VÀ CHỈ KHI là root — và đó chính là điều kiện của `keenrig-box
// restore` thật, nên đây không phải một ca hiếm mà là ca CHÍNH. Dữ liệu app thuộc
// về uid của tiến trình trong container; một cây restore toàn quyền root làm app
// khởi động lên rồi báo permission denied, và triệu chứng đó trông giống hệt
// "image hỏng" nên người ta đi tìm sai chỗ hàng giờ.
func testOwnership(t *testing.T, f format.Format) {
	if !isRoot() {
		t.Skip("chown cần root — ca này chạy trên CI Linux (hoặc trong container)")
	}
	const uid, gid = 1234, 5678
	src := t.TempDir()
	build(t, src, []entry{
		{path: "data/cua-app.txt", body: "x"},
		{path: "data", dir: true},
	})
	for _, p := range []string{"data/cua-app.txt", "data"} {
		if err := os.Chown(filepath.Join(src, filepath.FromSlash(p)), uid, gid); err != nil {
			t.Fatalf("chown %s: %v", p, err)
		}
	}

	dst, _, _ := roundTrip(t, f, src)

	for _, p := range []string{"data/cua-app.txt", "data"} {
		fi, err := os.Lstat(filepath.Join(dst, filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		gotUID, gotGID, ok := ownerOf(fi)
		if !ok {
			t.Skip("hệ này không cho đọc uid/gid")
		}
		if gotUID != uid || gotGID != gid {
			t.Errorf("%s: chủ sở hữu = %d:%d, muốn %d:%d", p, gotUID, gotGID, uid, gid)
		}
	}
}

// mtime phải sống sót, ít nhất tới giây.
//
// Không phải chi tiết trang trí: rsync, mọi cơ chế cache theo mtime, và chính
// phép so sánh "có gì đổi từ bản sao lưu trước" đều đọc nó. Restore đặt mọi file
// về "bây giờ" làm lần đồng bộ tiếp theo coi cả cây là mới.
func testMTime(t *testing.T, f format.Format) {
	src := t.TempDir()
	build(t, src, []entry{
		{path: "a/cu.txt", body: "x"},
		{path: "a", dir: true},
	})
	want := time.Date(2024, 3, 14, 15, 9, 26, 0, time.UTC)
	for _, p := range []string{"a/cu.txt", "a"} {
		if err := os.Chtimes(filepath.Join(src, filepath.FromSlash(p)), want, want); err != nil {
			t.Fatal(err)
		}
	}

	dst, _, _ := roundTrip(t, f, src)

	for _, p := range []string{"a/cu.txt", "a"} {
		fi, err := os.Lstat(filepath.Join(dst, filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		if diff := fi.ModTime().Sub(want); diff > time.Second || diff < -time.Second {
			t.Errorf("%s: mtime = %s, muốn %s (lệch %s)", p, fi.ModTime().UTC(), want, diff)
		}
	}
}

// 6 MiB nội dung KHÔNG lặp lại: một lần ghi thiếu hay lệch bị lộ ra, thay vì bị
// che bởi dữ liệu giống nhau. Cũng đủ lớn để vượt mọi buffer trên đường đi.
func testLargeFile(t *testing.T, f format.Format) {
	src := t.TempDir()
	const n = 6 << 20
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = byte(i*31 + i/251)
	}
	if err := os.WriteFile(filepath.Join(src, "lon.bin"), buf, 0o644); err != nil {
		t.Fatal(err)
	}

	dst, _, _ := roundTrip(t, f, src)

	got, err := os.ReadFile(filepath.Join(dst, "lon.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, buf) {
		t.Errorf("6 MiB đọc lại khác: %d byte, khớp tới byte %d", len(got), firstDiff(got, buf))
	}
}

func firstDiff(a, b []byte) int {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// Tên file "khó" phải đi qua nguyên vẹn.
//
// Dữ liệu app là dữ liệu của NGƯỜI DÙNG: file tải lên mang tên tiếng Việt có dấu,
// có khoảng trắng, có dấu ngoặc. Một format cắt xén tên làm restore đủ số byte
// nhưng thiếu đúng file người dùng đi tìm.
func testAwkwardNames(t *testing.T, f format.Format) {
	names := []string{
		"tài liệu quan trọng.pdf",
		"hoá đơn (bản sao).txt",
		"thư mục có dấu/tệp con.md",
		"dấu-gạch_và.chấm.tar.gz",
		"khoảng  trắng  đôi.txt",
	}
	src := t.TempDir()
	entries := make([]entry, 0, len(names))
	for i, n := range names {
		entries = append(entries, entry{path: n, body: fmt.Sprintf("noi dung %d", i)})
	}
	build(t, src, entries)

	dst, _, _ := roundTrip(t, f, src)

	for i, n := range names {
		b, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(n)))
		if err != nil {
			t.Errorf("%q: %v", n, err)
			continue
		}
		if want := fmt.Sprintf("noi dung %d", i); string(b) != want {
			t.Errorf("%q: nội dung = %q, muốn %q", n, b, want)
		}
	}
}

// Giải nén vào một thư mục ĐÃ CÓ DỮ LIỆU phải bị từ chối.
//
// Trộn hai snapshot cho ra một cây không thuộc về bản nào: file của bản cũ mà bản
// mới đã xoá vẫn còn đó, và app đọc được cả hai. Đây là lớp phòng thủ ở tầng
// format; lớp ở tầng lệnh `restore --from` là một lớp khác, và cả hai đều cần.
func testRefusesNonEmpty(t *testing.T, f format.Format) {
	src := t.TempDir()
	build(t, src, []entry{{path: "a.txt", body: "moi"}})
	var buf bytes.Buffer
	if _, err := f.Pack(t.Context(), src, &buf); err != nil {
		t.Fatal(err)
	}

	dst := t.TempDir()
	if err := os.WriteFile(filepath.Join(dst, "du-lieu-dang-song.db"), []byte("dung xoa toi"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := f.Unpack(t.Context(), bytes.NewReader(buf.Bytes()), dst)
	if !errors.Is(err, format.ErrNotEmpty) {
		t.Fatalf("Unpack vào thư mục có dữ liệu = %v, muốn ErrNotEmpty", err)
	}
	// Và không được đụng vào thứ đang có.
	b, err := os.ReadFile(filepath.Join(dst, "du-lieu-dang-song.db"))
	if err != nil || string(b) != "dung xoa toi" {
		t.Errorf("dữ liệu đang có bị sửa: %q, %v", b, err)
	}
}

// Thư mục đích CHƯA TỒN TẠI thì tạo — đó là ca bình thường của rebuild T0.
func testCreatesDest(t *testing.T, f format.Format) {
	src := t.TempDir()
	build(t, src, []entry{{path: "a/b.txt", body: "x"}})
	var buf bytes.Buffer
	if _, err := f.Pack(t.Context(), src, &buf); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "chua", "co", "gi")
	if _, err := f.Unpack(t.Context(), bytes.NewReader(buf.Bytes()), dst); err != nil {
		t.Fatalf("Unpack vào đường dẫn chưa tồn tại: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "a", "b.txt")); err != nil {
		t.Errorf("nội dung không tới nơi: %v", err)
	}
}

// Archive CỤT phải là LỖI.
//
// Đây là cách hỏng thật nhất của một bản sao lưu: đầy đĩa hay mất mạng giữa lúc
// đẩy lên. Nếu giải nén được nửa cây rồi báo thành công thì restore "xong" với
// một nửa dữ liệu, và không ai biết cho tới khi đi tìm nửa còn lại.
func testTruncated(t *testing.T, f format.Format) {
	src := t.TempDir()
	body := strings.Repeat("noi dung du dai de nen khong lam no bien mat\n", 40000)
	build(t, src, []entry{
		{path: "a.txt", body: body},
		{path: "b.txt", body: body},
	})
	var buf bytes.Buffer
	if _, err := f.Pack(t.Context(), src, &buf); err != nil {
		t.Fatal(err)
	}
	full := buf.Bytes()
	if len(full) < 64 {
		t.Fatalf("archive quá ngắn (%d byte) để cắt đôi có ý nghĩa", len(full))
	}

	dst := filepath.Join(t.TempDir(), "restore")
	_, err := f.Unpack(t.Context(), bytes.NewReader(full[:len(full)/2]), dst)
	if err == nil {
		t.Fatal("giải nén một archive cụt lại báo thành công")
	}
	if !errors.Is(err, format.ErrBadArchive) {
		t.Errorf("= %v, muốn ErrBadArchive (restore cần tách 'bản sao lưu hỏng' khỏi 'đĩa hỏng')", err)
	}
}

// Stream không phải archive → ErrBadArchive, không phải panic và không phải một
// cây rỗng "thành công".
func testGarbage(t *testing.T, f format.Format) {
	junk := bytes.Repeat([]byte("day khong phai archive"), 100)
	dst := filepath.Join(t.TempDir(), "restore")
	_, err := f.Unpack(t.Context(), bytes.NewReader(junk), dst)
	if !errors.Is(err, format.ErrBadArchive) {
		t.Errorf("= %v, muốn ErrBadArchive", err)
	}
}

// Nguồn không tồn tại → ErrNoSource, và KHÔNG ghi ra archive rỗng.
//
// Gõ sai một đường dẫn mà vẫn tạo được một bản sao lưu "hợp lệ" 0 file là cách
// một instance chạy hàng tháng với những bản sao lưu trống rỗng.
func testMissingSource(t *testing.T, f format.Format) {
	var buf bytes.Buffer
	_, err := f.Pack(t.Context(), filepath.Join(t.TempDir(), "khong-ton-tai"), &buf)
	if !errors.Is(err, format.ErrNoSource) {
		t.Errorf("= %v, muốn ErrNoSource", err)
	}

	// File thường cũng không phải cây thư mục.
	p := filepath.Join(t.TempDir(), "la-mot-file")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Pack(t.Context(), p, &buf); !errors.Is(err, format.ErrNoSource) {
		t.Errorf("Pack một file thường = %v, muốn ErrNoSource", err)
	}
}

// Unix socket trong cây phải được BỎ QUA CÓ TÊN, không làm hỏng cả bản sao lưu.
//
// Nó có thật trong mọi thư mục dữ liệu có postgres hay php-fpm. Hai cách sai đối
// xứng nhau: làm đỏ cả lần sao lưu vì một socket, hoặc bỏ qua im lặng để người
// vận hành không bao giờ biết bản sao lưu thiếu gì.
func testSocketSkipped(t *testing.T, f format.Format) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket trên filesystem không có ngữ nghĩa này trên Windows")
	}
	src := t.TempDir()
	build(t, src, []entry{{path: "data/thuc.txt", body: "giu lai"}})

	sock := filepath.Join(src, "data", ".s.PGSQL.5432")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("không tạo được unix socket ở đây: %v", err)
	}
	defer ln.Close()

	var buf bytes.Buffer
	st, err := f.Pack(t.Context(), src, &buf)
	if err != nil {
		t.Fatalf("Pack với một socket trong cây phải thành công, nhận: %v", err)
	}
	found := false
	for _, s := range st.Skipped {
		if strings.HasSuffix(s.Path, ".s.PGSQL.5432") {
			found = true
			if s.Reason == "" {
				t.Error("bỏ qua mà không nói lý do")
			}
		}
	}
	if !found {
		t.Errorf("socket bị bỏ qua IM LẶNG: Skipped = %v", st.Skipped)
	}

	dst := filepath.Join(t.TempDir(), "restore")
	if _, err := f.Unpack(t.Context(), bytes.NewReader(buf.Bytes()), dst); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if _, err := os.ReadFile(filepath.Join(dst, "data", "thuc.txt")); err != nil {
		t.Errorf("file thật cạnh socket không tới nơi: %v", err)
	}
}

// ctx đã huỷ → dừng, không chạy tiếp cho hết cây.
//
// Snapshot của một instance là gigabyte. Không tôn trọng ctx nghĩa là lệnh dừng
// dịch vụ phải chờ hết một lần đóng gói, và systemd bắn SIGKILL vào giữa chừng.
func testCancel(t *testing.T, f format.Format) {
	src := t.TempDir()
	entries := make([]entry, 0, 200)
	for i := range 200 {
		entries = append(entries, entry{
			path: fmt.Sprintf("d%02d/f%03d.txt", i%10, i),
			body: strings.Repeat("x", 4096),
		})
	}
	build(t, src, entries)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.Pack(ctx, src, io.Discard); !errors.Is(err, context.Canceled) {
		t.Errorf("Pack với ctx đã huỷ = %v, muốn context.Canceled", err)
	}
}

// Stats phải MÔ TẢ ĐÚNG cây, ở cả hai chiều.
//
// Nó không phải số trang trí: nó đi vào metadata snapshot, và là thứ duy nhất
// người vận hành có để trả lời "bản sao lưu đêm qua có đủ không" mà không phải
// giải nén cả gigabyte.
func testStats(t *testing.T, f format.Format) {
	src := t.TempDir()
	build(t, src, []entry{
		{path: "a", dir: true},
		{path: "a/1.txt", body: "12345"},   // 5
		{path: "a/2.txt", body: "1234567"}, // 7
		{path: "b/c/3.txt", body: "123"},   // 3
		{path: "b/rong", dir: true},
	})

	_, packed, unpacked := roundTrip(t, f, src)

	// gốc + a + b + b/c + b/rong = 5
	if packed.Dirs != 5 {
		t.Errorf("Pack Dirs = %d, muốn 5 (kể cả chính thư mục gốc)", packed.Dirs)
	}
	if packed.Files != 3 {
		t.Errorf("Pack Files = %d, muốn 3", packed.Files)
	}
	if packed.Bytes != 15 {
		t.Errorf("Pack Bytes = %d, muốn 15 (kích thước TRƯỚC khi nén)", packed.Bytes)
	}
	if unpacked.Files != packed.Files || unpacked.Dirs != packed.Dirs || unpacked.Bytes != packed.Bytes {
		t.Errorf("Unpack %+v ≠ Pack %+v — hai chiều không khớp thì con số nói dối", unpacked, packed)
	}
}
