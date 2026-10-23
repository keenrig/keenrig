package addons

// Provisioner là ranh giới cuối trước khi bộ biến rời khỏi package này và đi vào
// container app. Hai test dưới đây canh hai lớp kiểm ở đó — không có chúng thì
// hàng rào tồn tại mà không ai biết nó còn hoạt động.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeAddon — driver tối thiểu, chỉ để đẩy một bộ Creds qua Provisioner.
type fakeAddon struct {
	kind  Kind
	creds Creds
}

func (f *fakeAddon) Kind() Kind                                   { return f.kind }
func (f *fakeAddon) Setup(context.Context, string) (Creds, error) { return f.creds, nil }
func (f *fakeAddon) Teardown(context.Context, string) error       { return nil }
func (f *fakeAddon) Env(context.Context, string) (map[string]string, error) {
	return f.creds.Env, nil
}
func (f *fakeAddon) Backup(context.Context, string, string) error  { return nil }
func (f *fakeAddon) Restore(context.Context, string, string) error { return nil }

// registerFake gắn một driver giả dưới tên riêng. Tên KHÔNG nằm trong AllKinds
// nên nó không lẫn vào test drift enum ở driver/all.
func registerFake(t *testing.T, kind Kind, creds Creds) {
	t.Helper()
	Register(kind, func(context.Context, Config) (Addon, error) {
		return &fakeAddon{kind: kind, creds: creds}, nil
	})
}

// Tên biến sai namespace bị chặn Ở ĐÂY, không lọt vào container.
//
// Một driver mới đặt tên biến sai làm app của người dùng mất kết nối DB, và
// triệu chứng nằm trong log của APP — nên nó phải chết ở ranh giới của ta.
func TestProvisionerRejectsBadEnvName(t *testing.T) {
	const kind = Kind("test-badenv")
	registerFake(t, kind, Creds{Env: map[string]string{"POSTGRES_URL": "x"}})

	_, err := NewProvisioner(Config{}).Setup(context.Background(), kind, "app-1")
	if !errors.Is(err, ErrBadEnvName) {
		t.Fatalf("= %v, muốn ErrBadEnvName", err)
	}
}

// Kind không nằm trong enum của addon.schema.json bị chặn ở đây.
//
// Đây là điều `ValidateEnv` KHÔNG thấy được: mọi tên biến đúng, giá trị đúng,
// nhưng bản ghi không hợp lệ vì hệ thống chưa công nhận addon này. Nếu không
// chặn, bản ghi sẽ được ghi vào DB rồi mới hỏng ở chỗ khác — lúc đó thứ sai đã
// bền vững.
func TestProvisionerRejectsKindOutsideSchemaEnum(t *testing.T) {
	const kind = Kind("test-notinschema")
	registerFake(t, kind, Creds{Env: map[string]string{"KEENRIG_TEST_URL": "x://h"}})

	_, err := NewProvisioner(Config{}).Setup(context.Background(), kind, "app-1")
	if err == nil {
		t.Fatal("addon ngoài enum vẫn cấp phát được")
	}
	if !strings.Contains(err.Error(), "addon.schema.json") {
		t.Errorf("lỗi không nói tới schema, người đọc log sẽ không biết vì sao: %v", err)
	}
}
