package contracts_test

import (
	"errors"
	"strings"
	"testing"

	contracts "github.com/keenrig-platform/keenrig/keenrig-contracts/go"
)

// `volumes` là kênh lưu trữ file của app — và `name` của nó trở thành một đoạn
// ĐƯỜNG DẪN THẬT dưới `apps/<id>/volumes/`. Nên bộ test này chia làm hai phần
// rõ ràng: phần hình dạng do schema ép, phần quan hệ do ValidateVolumes ép.

func desiredWith(volumes string) []byte {
	return []byte(`{"image":"nginx:1","volumes":` + volumes + `}`)
}

// --- schema: hình dạng của MỘT volume ---------------------------------------------

func TestVolumeShapeAcceptedBySchema(t *testing.T) {
	ok := []string{
		`[{"name":"uploads","path":"/var/www/uploads"}]`,
		`[{"name":"data","path":"/data","read_only":true}]`,
		`[{"name":"a1","path":"/a"},{"name":"b2","path":"/b"}]`,
		`[]`,
	}
	for _, v := range ok {
		if err := contracts.ValidateDesired(desiredWith(v)); err != nil {
			t.Errorf("%s bị từ chối: %v", v, err)
		}
	}
}

// Tên volume là RANH GIỚI AN NINH: nó thành một đoạn đường dẫn thật trên máy
// chủ. `../../instance` sẽ mount thẳng thư mục chứa master.key vào container
// của app — tức là trao khoá giải mã mọi secret cho một image tuỳ ý.
func TestVolumeNameIsRejectedWhenItCouldEscape(t *testing.T) {
	bad := map[string]string{
		"thoát lên trên":     `[{"name":"..","path":"/d"}]`,
		"thoát nhiều tầng":   `[{"name":"../../instance","path":"/d"}]`,
		"có dấu phân cách":   `[{"name":"a/b","path":"/d"}]`,
		"backslash Windows":  `[{"name":"a\\b","path":"/d"}]`,
		"rỗng":               `[{"name":"","path":"/d"}]`,
		"chấm":               `[{"name":".","path":"/d"}]`,
		"chữ hoa":            `[{"name":"Uploads","path":"/d"}]`,
		"bắt đầu bằng gạch":  `[{"name":"-x","path":"/d"}]`,
		"kết thúc bằng gạch": `[{"name":"x-","path":"/d"}]`,
	}
	for name, v := range bad {
		t.Run(name, func(t *testing.T) {
			if err := contracts.ValidateDesired(desiredWith(v)); err == nil {
				t.Errorf("%s ĐƯỢC CHẤP NHẬN — tên volume đi thẳng vào đường dẫn máy chủ", v)
			}
		})
	}
}

// Thiếu trường, thừa trường, sai kiểu — schema phải bắt hết.
func TestVolumeMissingOrExtraFieldsRejected(t *testing.T) {
	bad := []string{
		`[{"name":"a"}]`,                                // thiếu path
		`[{"path":"/d"}]`,                               // thiếu name
		`[{"name":"a","path":"/d","mode":"rw"}]`,        // trường lạ
		`[{"name":"a","path":"/d","read_only":1}]` + ``, // sai kiểu
		`[{"name":"a","path":"relative"}]`,              // không tuyệt đối
		`[{"name":"a","path":"/"}]`,                     // quá ngắn (minLength 2)
		`"khong-phai-mang"`,
	}
	for _, v := range bad {
		if err := contracts.ValidateDesired(desiredWith(v)); err == nil {
			t.Errorf("%s được chấp nhận", v)
		}
	}
}

// Giới hạn số lượng: một app khai 10.000 volume sẽ tạo 10.000 thư mục.
func TestTooManyVolumesRejected(t *testing.T) {
	var b strings.Builder
	b.WriteString("[")
	for i := range 17 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"name":"v`)
		b.WriteByte(byte('a' + i%26))
		b.WriteString(`x","path":"/d`)
		b.WriteByte(byte('a' + i%26))
		b.WriteString(`"}`)
	}
	b.WriteString("]")
	if err := contracts.ValidateDesired(desiredWith(b.String())); err == nil {
		t.Error("17 volume được chấp nhận, maxItems là 16")
	}
}

// --- ValidateVolumes: quan hệ GIỮA các volume ------------------------------------

func TestValidateVolumesAcceptsSaneDeclarations(t *testing.T) {
	if err := contracts.ValidateVolumes([]contracts.VolumeMount{
		{Name: "uploads", Path: "/var/www/uploads"},
		{Name: "repos", Path: "/data/git", ReadOnly: true},
	}); err != nil {
		t.Fatalf("khai báo hợp lệ bị từ chối: %v", err)
	}
	if err := contracts.ValidateVolumes(nil); err != nil {
		t.Errorf("không khai volume nào phải hợp lệ: %v", err)
	}
}

// Trùng NAME → cùng một thư mục máy chủ, app thấy cùng dữ liệu ở hai chỗ mà
// không hiểu vì sao.
func TestDuplicateVolumeNameRejected(t *testing.T) {
	err := contracts.ValidateVolumes([]contracts.VolumeMount{
		{Name: "data", Path: "/a"},
		{Name: "data", Path: "/b"},
	})
	if !errors.Is(err, contracts.ErrBadVolume) {
		t.Fatalf("= %v, muốn ErrBadVolume", err)
	}
}

// Trùng PATH → Docker nhận cả hai rồi cái sau che cái trước. Dữ liệu ghi vào
// volume bị che nằm lại trên đĩa mà không ai đọc được nữa — mất dữ liệu im lặng.
func TestDuplicateVolumePathRejected(t *testing.T) {
	err := contracts.ValidateVolumes([]contracts.VolumeMount{
		{Name: "mot", Path: "/data"},
		{Name: "hai", Path: "/data"},
	})
	if !errors.Is(err, contracts.ErrBadVolume) {
		t.Fatalf("= %v, muốn ErrBadVolume", err)
	}
}

// Mount đè lên đường dẫn hệ thống của container.
//
// KHÔNG phải lỗ hổng máy chủ — phía máy chủ luôn nằm dưới apps/<id>/volumes/.
// Nhưng một app xin mount lên /proc là app cấu hình sai, và nói ra lúc TẠO rẻ
// hơn nhiều so với để nó khởi động rồi chết vì một lý do khó lần.
func TestMountingOverSystemPathsRejected(t *testing.T) {
	for _, p := range []string{"/", "/proc", "/proc/self", "/sys", "/sys/fs/cgroup", "/dev", "/dev/shm"} {
		err := contracts.ValidateVolumes([]contracts.VolumeMount{{Name: "x", Path: p}})
		if !errors.Is(err, contracts.ErrBadVolume) {
			t.Errorf("mount lên %q được chấp nhận: %v", p, err)
		}
	}
}

// Đường dẫn không ở dạng chuẩn nói một đằng làm một nẻo.
func TestNonCanonicalPathRejected(t *testing.T) {
	for _, p := range []string{"/data/../etc", "/data/", "/data/./x", "//data"} {
		err := contracts.ValidateVolumes([]contracts.VolumeMount{{Name: "x", Path: p}})
		if !errors.Is(err, contracts.ErrBadVolume) {
			t.Errorf("%q được chấp nhận — nó không ở dạng chuẩn", p)
		}
	}
}

// `name` neo phía máy chủ, `path` neo phía container — nên ĐỔI PATH giữa hai
// phiên bản app KHÔNG được coi là một khai báo khác.
//
// Đây là lý do tồn tại của `name`. Nếu phía máy chủ neo theo `path`, một lần
// app đổi `/data` → `/var/lib/app` sẽ trông y hệt một lần mất sạch dữ liệu, và
// người dùng không có cách nào phân biệt.
func TestSameNameDifferentPathIsAValidUpgrade(t *testing.T) {
	v1 := []contracts.VolumeMount{{Name: "data", Path: "/data"}}
	v2 := []contracts.VolumeMount{{Name: "data", Path: "/var/lib/app"}}
	for i, v := range [][]contracts.VolumeMount{v1, v2} {
		if err := contracts.ValidateVolumes(v); err != nil {
			t.Errorf("phiên bản %d bị từ chối: %v", i+1, err)
		}
	}
	if v1[0].Name != v2[0].Name {
		t.Fatal("test này chỉ có nghĩa khi hai bên cùng Name")
	}
}
