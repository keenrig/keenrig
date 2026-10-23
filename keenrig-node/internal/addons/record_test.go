package addons

// AD-03 ở tầng kiểu dữ liệu: bản ghi cấp phát khớp addon.schema.json, và danh
// sách addon trong code KHÔNG lệch khỏi enum trong schema.

import (
	"encoding/json"
	"strings"
	"testing"

	schemafs "github.com/keenrig/keenrig/keenrig-contracts/jsonschema"
)

func TestRecordValidate(t *testing.T) {
	ok := Creds{Env: map[string]string{"KEENRIG_POSTGRES_URL": "postgres://u:p@h:5432/d"}}

	cases := []struct {
		name string
		rec  Record
		ok   bool
	}{
		{"tối thiểu", ok.Record(KindPostgres, "app-1"), true},
		{"có secret_ref", Creds{Env: ok.Env, SecretRef: "app/app-1/postgres"}.
			Record(KindPostgres, "app-1"), true},

		{"kind không có trong enum", ok.Record(Kind("mysql"), "app-1"), false},
		{"kind rỗng", ok.Record(Kind(""), "app-1"), false},
		{"app_id rỗng", ok.Record(KindPostgres, ""), false},
		{"env nil", Creds{}.Record(KindRedis, "app-1"), false},
		{"env rỗng", Creds{Env: map[string]string{}}.Record(KindRedis, "app-1"), false},
		{"tên biến sai namespace", Creds{Env: map[string]string{"REDIS_URL": "x"}}.
			Record(KindRedis, "app-1"), false},
		{"tên biến chữ thường", Creds{Env: map[string]string{"keenrig_redis_url": "x"}}.
			Record(KindRedis, "app-1"), false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.rec.Validate()
			if c.ok && err != nil {
				t.Fatalf("muốn hợp lệ, nhận: %v", err)
			}
			if !c.ok && err == nil {
				t.Fatal("muốn lỗi, nhận hợp lệ")
			}
		})
	}
}

// secret_ref RỖNG phải biến mất khỏi JSON, không được ghi thành "".
//
// Schema đặt minLength:1 nên `"secret_ref": ""` bị từ chối — và đó là hành vi
// đúng: một con trỏ rỗng được ghi như thể nó trỏ tới đâu đó là tệ hơn không ghi.
// Chỗ duy nhất quyết định điều này là thẻ `omitempty`, và nó là thứ dễ mất nhất
// khi có người sửa struct.
func TestEmptySecretRefIsOmittedNotEmptyString(t *testing.T) {
	rec := Creds{Env: map[string]string{"KEENRIG_REDIS_URL": "redis://h:6379"}}.
		Record(KindRedis, "app-1")

	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret_ref") {
		t.Errorf("secret_ref rỗng vẫn được ghi ra: %s", raw)
	}
	if err := rec.Validate(); err != nil {
		t.Errorf("bản ghi không secret_ref phải hợp lệ: %v", err)
	}
}

// Bản ghi KHÔNG được mang trường nào ngoài bốn trường đã khai.
//
// `additionalProperties: false` là hàng rào chống rò rỉ credential: thêm một
// trường `password` vào Record là cách dễ nhất để mật khẩu rời khỏi bảng
// `secrets`. Test này khoá hình dạng bằng cách so danh sách khoá JSON thật với
// danh sách cho phép — nếu ai đó thêm trường thì đây đỏ trước khi schema đỏ, và
// thông báo nói rõ hơn.
func TestRecordHasNoExtraFields(t *testing.T) {
	rec := Creds{Env: map[string]string{"KEENRIG_REDIS_URL": "redis://h:6379"},
		SecretRef: "app/app-1/redis"}.Record(KindRedis, "app-1")

	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"app_id": true, "addon": true, "env": true, "secret_ref": true}
	for k := range m {
		if !allowed[k] {
			t.Errorf("Record mang trường %q — addon.schema.json đặt "+
				"additionalProperties:false, và trường lạ ở đây là đường rò credential", k)
		}
	}
}

// Danh sách addon trong code và enum trong schema phải TRÙNG KHỚP, hai chiều.
//
// Lệch theo chiều nào cũng hỏng, và hỏng khác nhau:
//
//	code có, schema không  →  Setup thành công nhưng bản ghi không validate được;
//	                          app vào trạng thái lỗi ở tick đầu, và thông báo nói
//	                          về JSON schema chứ không nói "thiếu driver".
//	schema có, code không  →  API nhận desired bật một addon không có driver;
//	                          Open trả ErrUnknownAddon lúc hội tụ, tức là lỗi rơi
//	                          xuống người dùng thay vì bị chặn lúc tạo app.
//
// Cả hai đều là lỗi lúc BUILD, nên chúng phải nổ ở CI, không ở máy khách.
func TestAllKindsMatchSchemaEnum(t *testing.T) {
	raw, err := schemafs.FS.ReadFile("addon.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Defs struct {
			AddonKind struct {
				Enum []string `json:"enum"`
			} `json:"AddonKind"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	inSchema := map[string]bool{}
	for _, e := range doc.Defs.AddonKind.Enum {
		inSchema[e] = true
	}
	if len(inSchema) == 0 {
		t.Fatal("không đọc được enum AddonKind — test này vô nghĩa nếu enum rỗng")
	}

	inCode := map[string]bool{}
	for _, k := range AllKinds() {
		inCode[string(k)] = true
		if !inSchema[string(k)] {
			t.Errorf("AllKinds có %q nhưng addon.schema.json không — mọi bản ghi của "+
				"addon này sẽ không validate được", k)
		}
	}
	for e := range inSchema {
		if !inCode[e] {
			t.Errorf("addon.schema.json có %q nhưng AllKinds không — API sẽ nhận một "+
				"addon không có driver", e)
		}
	}
}
