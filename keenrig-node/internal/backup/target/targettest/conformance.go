// Package targettest — bộ conformance cho `target.Target` (BT-01).
//
// Mọi driver chạy CÙNG bộ này. Nếu một driver cần suite phải sửa để pass thì
// suite đang sai, không phải driver — đúng nguyên tắc đã dùng cho `storetest`,
// `runtimetest` và `addontest`.
//
// # Khẳng định được phát biểu ở tầng nào
//
// Suite này KHÔNG biết dir hay s3. Nó chỉ nói về key và bytes. Cụ thể nó không
// bao giờ nói "phải có file ở đường dẫn X" — điều đó đúng cho dir và vô nghĩa với
// s3. Chỗ duy nhất nói về đĩa là test riêng của driver dir.
package targettest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/keenrig-platform/keenrig/keenrig-node/internal/backup/target"
)

// Opener dựng một Target SẠCH cho mỗi subtest.
//
// Sạch là bắt buộc: hai subtest dùng chung một bucket sẽ thấy object của nhau, và
// khẳng định về List trở thành vô nghĩa. Driver s3 làm điều này bằng cách sinh
// prefix riêng mỗi lần.
type Opener func(t *testing.T) target.Target

// RunConformance chạy toàn bộ suite.
func RunConformance(t *testing.T, open Opener) {
	t.Run("PutGetRoundTrip", func(t *testing.T) { testRoundTrip(t, open(t)) })
	t.Run("PutOverwritesFully", func(t *testing.T) { testOverwrite(t, open(t)) })
	t.Run("GetMissingIsNotFound", func(t *testing.T) { testGetMissing(t, open(t)) })
	t.Run("ListByPrefixSorted", func(t *testing.T) { testList(t, open(t)) })
	t.Run("ListMissingPrefixIsEmpty", func(t *testing.T) { testListMissing(t, open(t)) })
	t.Run("DeleteIsIdempotent", func(t *testing.T) { testDeleteIdempotent(t, open(t)) })
	t.Run("BadKeyRejected", func(t *testing.T) { testBadKey(t, open(t)) })
	t.Run("NestedKeys", func(t *testing.T) { testNested(t, open(t)) })
	t.Run("EmptyObject", func(t *testing.T) { testEmpty(t, open(t)) })
	t.Run("LargeObject", func(t *testing.T) { testLarge(t, open(t)) })
	t.Run("SizeMismatchFails", func(t *testing.T) { testSizeMismatch(t, open(t)) })
	t.Run("RetentionKeepsNewest", func(t *testing.T) { testRetentionKeepLast(t, open(t)) })
	t.Run("RetentionZeroPolicyRefuses", func(t *testing.T) { testRetentionZero(t, open(t)) })
	t.Run("RetentionDryRunDeletesNothing", func(t *testing.T) { testRetentionDryRun(t, open(t)) })
}

// --- helper --------------------------------------------------------------------

func put(t *testing.T, tg target.Target, key, body string) {
	t.Helper()
	if err := tg.Put(t.Context(), key, strings.NewReader(body), int64(len(body))); err != nil {
		t.Fatalf("Put(%q): %v", key, err)
	}
}

func get(t *testing.T, tg target.Target, key string) string {
	t.Helper()
	rc, err := tg.Get(t.Context(), key)
	if err != nil {
		t.Fatalf("Get(%q): %v", key, err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("đọc %q: %v", key, err)
	}
	return string(b)
}

func keys(objs []target.Object) []string {
	out := make([]string, 0, len(objs))
	for _, o := range objs {
		out = append(out, o.Key)
	}
	return out
}

// --- test ----------------------------------------------------------------------

func testRoundTrip(t *testing.T, tg target.Target) {
	const body = "noi dung ban sao luu\n\x00\xff nhi phan"
	put(t, tg, "snap/2026-08-10.tgz", body)

	if got := get(t, tg, "snap/2026-08-10.tgz"); got != body {
		t.Errorf("đọc lại khác thứ đã ghi (%d vs %d byte)", len(got), len(body))
	}

	objs, err := tg.List(t.Context(), "snap/")
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 1 {
		t.Fatalf("List = %v, muốn 1 object", keys(objs))
	}
	// Size phải là size THẬT. Một target trả 0 làm retention theo dung lượng và
	// mọi hiển thị dung lượng nói sai, mà không có gì hỏng để lần ra.
	if objs[0].Size != int64(len(body)) {
		t.Errorf("Size = %d, muốn %d", objs[0].Size, len(body))
	}
	if objs[0].ModTime.IsZero() {
		t.Error("ModTime rỗng — retention theo tuổi sẽ coi mọi bản là cũ vô hạn")
	}
}

// Ghi đè phải thay TOÀN BỘ nội dung.
//
// Ghi đè một phần là cách một bản sao lưu hỏng đi qua mọi lần kiểm: List thấy
// đúng key, Size có thể đúng, và đuôi file là dữ liệu của bản cũ.
func testOverwrite(t *testing.T, tg target.Target) {
	put(t, tg, "a.bin", "dai-hon-nhieu-lan-so-voi-ban-sau")
	put(t, tg, "a.bin", "ngan")
	if got := get(t, tg, "a.bin"); got != "ngan" {
		t.Errorf("= %q — ghi đè để lại đuôi của bản cũ", got)
	}
	objs, _ := tg.List(t.Context(), "a.bin")
	if len(objs) == 1 && objs[0].Size != 4 {
		t.Errorf("Size sau ghi đè = %d, muốn 4", objs[0].Size)
	}
}

// Không có object → ErrNotFound, KHÔNG phải reader rỗng.
//
// Reader rỗng nghĩa là restore đọc được 0 byte rồi báo "khôi phục xong".
func testGetMissing(t *testing.T, tg target.Target) {
	rc, err := tg.Get(t.Context(), "khong/ton/tai.tgz")
	if err == nil {
		rc.Close()
		t.Fatal("Get key không tồn tại trả nil error")
	}
	if !errors.Is(err, target.ErrNotFound) {
		t.Errorf("= %v, muốn ErrNotFound (restore cần tách 'chưa có bản nào' khỏi 'mạng hỏng')", err)
	}
}

func testList(t *testing.T, tg target.Target) {
	for _, k := range []string{
		"snap/c.tgz", "snap/a.tgz", "snap/b.tgz",
		"wal/0001", "other.txt",
	} {
		put(t, tg, k, k)
	}

	objs, err := tg.List(t.Context(), "snap/")
	if err != nil {
		t.Fatal(err)
	}
	got := keys(objs)
	want := []string{"snap/a.tgz", "snap/b.tgz", "snap/c.tgz"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("List(\"snap/\") = %v, muốn %v (đã sắp xếp, và KHÔNG lẫn prefix khác)", got, want)
	}

	// prefix rỗng = tất cả.
	all, err := tg.List(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 {
		t.Errorf("List(\"\") = %v, muốn 5 object", keys(all))
	}

	// prefix KHÔNG kết thúc bằng '/' là tiền tố chuỗi, không phải tên thư mục —
	// s3 hành xử thế và dir phải theo, nếu không cùng một prefix cho hai kết quả
	// khác nhau tuỳ driver.
	part, err := tg.List(t.Context(), "snap/a")
	if err != nil {
		t.Fatal(err)
	}
	if len(part) != 1 || part[0].Key != "snap/a.tgz" {
		t.Errorf("List(\"snap/a\") = %v, muốn đúng snap/a.tgz", keys(part))
	}
}

// Prefix không có gì → slice rỗng và nil error, KHÔNG phải lỗi.
//
// Trên một instance mới chưa sao lưu lần nào, đây là đường chạy BÌNH THƯỜNG.
// Trả lỗi ở đó làm mọi lần khởi động đầu tiên có một dòng lỗi giả.
func testListMissing(t *testing.T, tg target.Target) {
	objs, err := tg.List(t.Context(), "chua/co/gi/")
	if err != nil {
		t.Fatalf("List prefix rỗng phải trả nil error, nhận %v", err)
	}
	if len(objs) != 0 {
		t.Errorf("= %v, muốn rỗng", keys(objs))
	}
}

func testDeleteIdempotent(t *testing.T, tg target.Target) {
	put(t, tg, "x.tgz", "noi dung")
	if err := tg.Delete(t.Context(), "x.tgz"); err != nil {
		t.Fatalf("Delete lần 1: %v", err)
	}
	// Lần 2 KHÔNG được lỗi: retention chạy lặp lại, và một object đã xoá không
	// phải sự cố.
	if err := tg.Delete(t.Context(), "x.tgz"); err != nil {
		t.Errorf("Delete lần 2: %v — phải idempotent", err)
	}
	if _, err := tg.Get(t.Context(), "x.tgz"); !errors.Is(err, target.ErrNotFound) {
		t.Errorf("sau Delete, Get = %v, muốn ErrNotFound", err)
	}
}

// Key vi phạm luật bị TỪ CHỐI ở mọi method, không chỉ Put.
//
// Đây là ranh giới an ninh: driver dir map key thành đường dẫn, nên `../` thoát
// khỏi thư mục sao lưu. Kiểm ở cả Get/Delete vì một key độc hại tới từ metadata
// snapshot cũng đi qua hai đường đó.
func testBadKey(t *testing.T, tg target.Target) {
	bad := []string{
		"", "/tuyet-doi", "../thoat-ra", "snap/../../etc/passwd",
		"snap//rong", "co\\backslash", "co\x00nul", "ket-thuc-bang-slash/",
	}
	for _, k := range bad {
		t.Run(fmt.Sprintf("%q", k), func(t *testing.T) {
			if err := tg.Put(t.Context(), k, strings.NewReader("x"), 1); err == nil {
				t.Error("Put nhận key xấu")
			}
			if _, err := tg.Get(t.Context(), k); err == nil {
				t.Error("Get nhận key xấu")
			}
			if err := tg.Delete(t.Context(), k); err == nil {
				t.Error("Delete nhận key xấu")
			}
		})
	}
}

func testNested(t *testing.T, tg target.Target) {
	const key = "instance/2026/08/10/platform.db.tgz"
	put(t, tg, key, "sau tang")
	if got := get(t, tg, key); got != "sau tang" {
		t.Errorf("= %q", got)
	}
	objs, _ := tg.List(t.Context(), "instance/2026/")
	if len(objs) != 1 || objs[0].Key != key {
		t.Errorf("List = %v, muốn %q", keys(objs), key)
	}
}

// Object 0 byte là object CÓ THẬT, không phải object vắng mặt.
//
// Nó xuất hiện thật: một app không có volume nào cho ra archive rỗng. Nếu target
// coi 0 byte là "không có" thì restore của app đó báo ErrNotFound và người dùng
// nghĩ bản sao lưu bị mất.
func testEmpty(t *testing.T, tg target.Target) {
	put(t, tg, "rong.tgz", "")
	if got := get(t, tg, "rong.tgz"); got != "" {
		t.Errorf("= %q, muốn rỗng", got)
	}
	objs, err := tg.List(t.Context(), "rong.tgz")
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 1 {
		t.Fatalf("List = %v — object 0 byte phải được kể tên", keys(objs))
	}
	if objs[0].Size != 0 {
		t.Errorf("Size = %d, muốn 0", objs[0].Size)
	}
}

// 5 MiB — đủ lớn để vượt buffer mặc định của mọi tầng trên đường đi, đủ nhỏ để
// test không chậm. Nội dung KHÔNG lặp lại để một lần ghi thiếu/lệch bị phát hiện,
// chứ không bị che bởi dữ liệu giống nhau.
func testLarge(t *testing.T, tg target.Target) {
	const n = 5 << 20
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = byte(i*31 + i/251)
	}
	if err := tg.Put(t.Context(), "lon.bin", bytes.NewReader(buf), int64(n)); err != nil {
		t.Fatalf("Put 5 MiB: %v", err)
	}
	rc, err := tg.Get(t.Context(), "lon.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, buf) {
		t.Errorf("5 MiB đọc lại khác: %d byte, khớp tới byte %d", len(got), firstDiff(got, buf))
	}
}

func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// size NÓI SAI so với dữ liệu thật phải là LỖI, không được ghi ra một object cụt.
//
// Đây là cách hỏng thật nhất trong cả package: caller lấy size từ os.Stat rồi file
// bị ghi thêm/cắt bớt giữa lúc đọc. Nếu target im lặng ghi những gì nó đọc được
// thì List báo một size, object mang một size khác, và không ai biết cho tới lúc
// giải nén.
func testSizeMismatch(t *testing.T, tg target.Target) {
	// Khai nhiều hơn thực tế.
	err := tg.Put(t.Context(), "thieu.bin", strings.NewReader("ngan"), 999)
	if err == nil {
		t.Error("Put với size lớn hơn dữ liệu thật lại thành công")
	}
	// Và không được để lại một object cụt.
	if objs, _ := tg.List(t.Context(), "thieu.bin"); len(objs) != 0 {
		t.Errorf("Put thất bại vẫn để lại object: %v", keys(objs))
	}

	// Khai ít hơn thực tế.
	err = tg.Put(t.Context(), "thua.bin", strings.NewReader("dai hon nhieu"), 4)
	if err == nil {
		if got := get(t, tg, "thua.bin"); len(got) != 4 {
			t.Errorf("size khai 4 nhưng ghi %d byte", len(got))
		}
	}
}

func testRetentionKeepLast(t *testing.T, tg target.Target) {
	// Ghi 5 bản, cách nhau về thời gian bằng cách ghi tuần tự rồi dùng ModTime
	// thật của target. Không giả lập ModTime: retention phải làm việc được với
	// ĐỘ PHÂN GIẢI THẬT của target, kể cả khi nó là 1 giây và nhiều bản có
	// ModTime bằng nhau.
	for _, k := range []string{"s/01", "s/02", "s/03", "s/04", "s/05"} {
		put(t, tg, k, k)
	}
	res, err := target.Prune(t.Context(), tg, "s/", target.Policy{KeepLast: 2}, time.Now(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Kept) != 2 || len(res.Deleted) != 3 {
		t.Fatalf("giữ %v, xoá %v — muốn giữ 2 xoá 3", res.Kept, res.Deleted)
	}
	if len(res.Failed) != 0 {
		t.Errorf("Failed = %v", res.Failed)
	}
	// Và thứ được giữ phải là hai key LỚN NHẤT: khi ModTime bằng nhau, key giảm
	// dần là tiêu chí phá hoà, nên kết quả vẫn xác định.
	after, err := tg.List(t.Context(), "s/")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(keys(after), ","); got != "s/04,s/05" {
		t.Errorf("còn lại %q, muốn \"s/04,s/05\" — retention không xác định", got)
	}
}

// Policy rỗng → LỖI và không xoá gì.
//
// Diễn giải "không cấu hình gì" thành "không giữ gì" là biến một dòng cấu hình
// thiếu thành mất toàn bộ lịch sử sao lưu.
func testRetentionZero(t *testing.T, tg target.Target) {
	put(t, tg, "s/01", "x")
	if _, err := target.Prune(t.Context(), tg, "s/", target.Policy{}, time.Now(), false); err == nil {
		t.Error("policy rỗng lại được chấp nhận")
	}
	if objs, _ := tg.List(t.Context(), "s/"); len(objs) != 1 {
		t.Errorf("policy rỗng vẫn xoá: còn %v", keys(objs))
	}
}

func testRetentionDryRun(t *testing.T, tg target.Target) {
	for _, k := range []string{"s/01", "s/02", "s/03"} {
		put(t, tg, k, k)
	}
	res, err := target.Prune(t.Context(), tg, "s/", target.Policy{KeepLast: 1}, time.Now(), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Deleted) != 2 {
		t.Errorf("dry-run báo xoá %v, muốn 2 key", res.Deleted)
	}
	if objs, _ := tg.List(t.Context(), "s/"); len(objs) != 3 {
		t.Errorf("dry-run ĐÃ XOÁ thật: còn %v", keys(objs))
	}
}
