package contracts_test

// Schema của `desired.resources` — cửa đầu tiên, và cửa duy nhất bắt được lỗi
// GÕ SAI TÊN TRƯỜNG.
//
// # Vì sao kiểm bằng schema chứ không bằng Unmarshal
//
// `json.Unmarshal` bỏ qua trường lạ trong im lặng. Với hạn mức tài nguyên, hệ
// quả của sự im lặng đó rất cụ thể: `{"memory_gb": 2}` được nhận, app chạy KHÔNG
// có trần RAM, và trong desired có một dòng trông y như một hạn mức đang hiệu
// lực. `additionalProperties: false` là thứ duy nhất chặn được — nên nó có test
// riêng, không chỉ dựa vào việc nó đang có trong file.

import (
	"strings"
	"testing"

	contracts "github.com/keenrig/keenrig/keenrig-contracts/go"
	schemafs "github.com/keenrig/keenrig/keenrig-contracts/jsonschema"
)

func desiredWithResources(res string) []byte {
	return []byte(`{"image":"nginx:1.27","resources":` + res + `}`)
}

// schemaJSON đọc chính file schema đã NHÚNG, không đọc từ đĩa: đó là bản mà
// binary thật dùng, và là bản duy nhất đáng khẳng định điều gì về.
func schemaJSON() (string, error) {
	raw, err := schemafs.FS.ReadFile("desired.schema.json")
	return string(raw), err
}

func TestSchemaResourcesNhanCauHinhDay(t *testing.T) {
	// Mọi trường cùng lúc, giá trị hợp lệ — phải qua.
	full := `{
		"memory_mb": 512,
		"memory_swap_mb": 1024,
		"cpu": 0.5,
		"cpu_shares": 512,
		"pids_limit": 200,
		"disk_mb": 2048,
		"io_read_mbps": 50,
		"io_write_mbps": 20,
		"io_read_iops": 2000,
		"io_write_iops": 1000,
		"ulimits": [{"name":"nofile","soft":1024,"hard":4096}, {"name":"core","soft":0}],
		"shm_size_mb": 256,
		"replicas": 3
	}`
	if err := contracts.ValidateDesired(desiredWithResources(full)); err != nil {
		t.Fatalf("cấu hình hạn mức đầy đủ bị từ chối: %v", err)
	}
}

func TestSchemaResourcesTuChoiGiaTriXau(t *testing.T) {
	cases := []struct {
		name string
		res  string
	}{
		// Gõ sai tên trường — lý do additionalProperties:false tồn tại.
		{"tên trường lạ", `{"memory_gb": 2}`},
		{"gõ sai memory_mb", `{"memmory_mb": 512}`},
		{"ulimit sai tên trường", `{"ulimits":[{"name":"nofile","softt":1024}]}`},

		// Ranh giới dưới: một trần nhỏ hơn mức khởi động được là một app chết
		// ngay giây đầu với "hạn mức đã được đặt".
		{"memory_mb dưới 64", `{"memory_mb": 32}`},
		{"memory_mb = 0", `{"memory_mb": 0}`},
		{"cpu = 0", `{"cpu": 0}`},
		{"cpu âm", `{"cpu": -1}`},
		{"pids_limit dưới 8", `{"pids_limit": 1}`},
		{"replicas = 0", `{"replicas": 0}`},
		{"shm_size_mb = 0", `{"shm_size_mb": 0}`},
		{"io_read_mbps = 0", `{"io_read_mbps": 0}`},

		// cpu_shares ngoài khoảng Docker nhận: 1 bị daemon từ chối lúc create,
		// tức là lỗi nổ ở tầng driver nơi thông báo không còn nói được gì.
		{"cpu_shares dưới 2", `{"cpu_shares": 1}`},
		{"cpu_shares trên 262144", `{"cpu_shares": 300000}`},

		// Kiểu sai.
		{"memory_mb là chuỗi", `{"memory_mb": "512m"}`},
		{"memory_mb là số thực", `{"memory_mb": 512.5}`},
		{"ulimits không phải mảng", `{"ulimits": {"name":"nofile","soft":1}}`},

		// ulimit: name là enum có chủ đích.
		{"ulimit tên không có trong enum", `{"ulimits":[{"name":"nofiles","soft":1024}]}`},
		{"ulimit nproc bị loại có chủ đích", `{"ulimits":[{"name":"nproc","soft":100}]}`},
		{"ulimit thiếu soft", `{"ulimits":[{"name":"nofile"}]}`},
		{"ulimit soft âm", `{"ulimits":[{"name":"nofile","soft":-1}]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := contracts.ValidateDesired(desiredWithResources(c.res)); err == nil {
				t.Errorf("schema NHẬN %s — %s", c.name, c.res)
			}
		})
	}
}

// `nproc` không phải một sự bỏ sót: nó bị loại vì Linux tính RLIMIT_NPROC theo
// UID và đếm chung mọi container cùng UID. Test này khoá quyết định đó lại, để
// một lần "thêm cho đủ bộ" sau này phải đọc lý do trước.
func TestNprocBiLoaiCoChuDich(t *testing.T) {
	raw, err := schemaJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, `"nproc"`) {
		t.Error("nproc xuất hiện trong enum ulimit — xem godoc $defs/Ulimit: nó tính theo UID, " +
			"không chặn được đúng thứ cần chặn, và rò rỉ qua ranh giới app. Dùng pids_limit.")
	}
	// Và lý do phải được VIẾT RA trong schema, không chỉ nằm trong đầu ai đó.
	if !strings.Contains(raw, "pids_limit") {
		t.Error("schema không nói dùng gì thay cho nproc")
	}
}

// Hạn mức mặc định của replicas là 1, và schema phải cho phép app không khai gì.
func TestResourcesLaTuyChon(t *testing.T) {
	if err := contracts.ValidateDesired([]byte(`{"image":"nginx:1.27"}`)); err != nil {
		t.Fatalf("desired không có resources bị từ chối: %v", err)
	}
	if err := contracts.ValidateDesired(desiredWithResources(`{}`)); err != nil {
		t.Fatalf("resources rỗng bị từ chối: %v", err)
	}
}
